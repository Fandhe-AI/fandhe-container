//! userns helper の要求・応答のワイヤー形式（OS 非依存の純コード。REPAIR-2・REPAIR-5。#4795）。
//!
//! 親（`launcher`）と helper（`helper`）が制御用 socket（helper の fd 0）で交わす固定長の frame。
//! 生の `Vec<u8>` を手で組まず、[`encode_request`]（固定長の [`RequestFrame`]）/ [`decode_request_header`] /
//! [`RequestHead::mode`] / [`encode_response`] / [`decode_response`] だけを経由させる。長さは確保の前に上限検査する（無制限確保の DoS を防ぐ。coding-rust.md）。
//!
//! # 要求 frame（8 バイトの header ＋ 任意長の payload）
//! `[version = 1, mode tag, 0, 0, payload_len(u32 BE)]`。payload は [`MAX_REQUEST_PAYLOAD_BYTES`] 以下。
//! [`Mode::Inspect`]・[`Mode::StatTarget`] は payload 長 0 が必須。[`Mode::Remove`]（tag 4。H3。OCI-7・SEC-5・#4800）は
//! 固定 4 バイト `[target tag, 0, 0, 0]`（対象は [`RemoveTarget`] の固定 2 種だけで、パス・名前は受けない）。
//! helper は header を検査して期待の長さが決まってから、その長さだけを固定長バッファへ読む（確保しない）。
//!
//! # 展開要求（tag 3。OCI-1・OCI-2・SEC-5・#4847）
//! payload は固定部 48 バイトと、レイヤー 1〜[`MAX_EXTRACT_LAYERS`] 件の 76 バイトずつ（すべて BE）:
//! 固定部 = `[ownership tag（1 = ChownInUserNamespace のみ）, special bits tag（1 = Strip / 2 = PreserveIfChowned）,
//! layer_count(u16), work_ms(u32), u64 × 5（max_entries・max_total_bytes・max_input_bytes・max_tracked_paths・
//! max_uncompressed_bytes）]`、レイヤー = `[media 添字（[`fandhe_container_oci::layer::LAYER_MEDIA_TYPES`] の 1 起点）, 0, 0, 0,
//! size(u64), digest(32 バイト), diff_id(32 バイト)]`。パス・名前・id の写像は受けない（写像は helper が参加に使ったものを使う）。
//! 長さ・件数・各値の範囲は確保・読み取りの前に検査する。blob の fd は要求 frame の後に `SCM_RIGHTS` で 1 通にまとめて送る
//! （[`EXTRACT_FD_TOKEN`] の 1 バイトに添える。helper は参加の後に受ける）。
//!
//! # 応答 frame（固定 [`RESPONSE_LEN`] バイト）
//! `[version, status(0 = ok / 1 = error), mode tag（ok）または error tag（error）, flags, u32 BE × 7]`。
//! 未使用のスロットが 0 でない frame は拒否する。エラーの文言は固定語彙で、パス・errno・uid を含めない（REPAIR-4）。

use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::{
    DEFAULT_MAX_EXTRACTED_BYTES, DEFAULT_MAX_LAYER_ENTRIES, DEFAULT_MAX_TRACKED_PATHS,
    ExtractLimits,
};
use fandhe_container_oci::layer::{DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, LAYER_MEDIA_TYPES};
use fandhe_container_oci::reference::Digest;

/// ワイヤー形式の版。
pub const WIRE_VERSION: u8 = 1;
/// 要求 header の長さ。
pub const REQUEST_HEADER_LEN: usize = 8;
/// 要求 payload の上限。超える `payload_len` は payload を読む前・確保する前に拒否する。
pub const MAX_REQUEST_PAYLOAD_BYTES: usize = 16 * 1024;
/// 応答 frame の長さ。
pub const RESPONSE_LEN: usize = 32;

const TAG_INSPECT: u8 = 1;
const TAG_STAT_TARGET: u8 = 2;
/// Extract（#4847。OCI-1・OCI-2・SEC-5）。
const TAG_EXTRACT: u8 = 3;
/// Remove（H3。OCI-7・SEC-5・#4800）。
const TAG_REMOVE: u8 = 4;
/// Remove の payload 長（`[target tag, 0, 0, 0]`）。
const REMOVE_PAYLOAD_LEN: usize = 4;
/// 要求 frame の最大長（header + 固定長モードの最大 payload。Extract は別の型で持つ）。
const MAX_FRAME_LEN: usize = REQUEST_HEADER_LEN + REMOVE_PAYLOAD_LEN;
/// 1 回の展開で受け取るレイヤー（blob の fd）の上限。`SCM_MAX_FD`（253）以下で 1 通に収まり、実用上の層数（約 127）を超える。
pub const MAX_EXTRACT_LAYERS: usize = 128;
/// 展開要求の固定部の長さ。
const EXTRACT_FIXED_LEN: usize = 48;
/// 展開要求のレイヤー 1 件の長さ。
const EXTRACT_LAYER_LEN: usize = 76;
/// 展開要求の payload の最大長（固定部 + 上限件数）。[`MAX_REQUEST_PAYLOAD_BYTES`] 以下。
pub const MAX_EXTRACT_PAYLOAD_BYTES: usize =
    EXTRACT_FIXED_LEN + MAX_EXTRACT_LAYERS * EXTRACT_LAYER_LEN;
const _: () = assert!(MAX_EXTRACT_PAYLOAD_BYTES <= MAX_REQUEST_PAYLOAD_BYTES);
/// blob の fd を運ぶ 1 バイトの token（`SCM_RIGHTS` はデータ 1 バイト以上に添える）。
pub const EXTRACT_FD_TOKEN: u8 = 0x58;
/// 所有者の方針の tag（`OwnershipPolicy::ChownInUserNamespace` だけを受ける）。
const OWNERSHIP_CHOWN_IN_USERNS: u8 = 1;
/// 展開に見込む時間（ms）の範囲。
const WORK_MS_MAX: u32 = 600_000;

/// 応答の error tag（`ExtractFailed`。oci の分類はスロット 0）。
const TAG_ERR_EXTRACT_FAILED: u8 = 12;

/// oci の分類の固定表（応答のスロット 0。未知の分類は `Internal`）。
fn oci_class_tag(c: OciErrorCode) -> u32 {
    match c {
        OciErrorCode::InvalidArgument => 1,
        OciErrorCode::Unimplemented => 2,
        OciErrorCode::Unavailable => 3,
        OciErrorCode::Timeout => 4,
        OciErrorCode::PermissionDenied => 5,
        OciErrorCode::NotFound => 6,
        OciErrorCode::DataLoss => 7,
        OciErrorCode::ResourceExhausted => 8,
        OciErrorCode::FailedPrecondition => 9,
        OciErrorCode::AlreadyExists => 10,
        _ => 11,
    }
}

fn oci_class_from_tag(t: u32) -> Option<OciErrorCode> {
    Some(match t {
        1 => OciErrorCode::InvalidArgument,
        2 => OciErrorCode::Unimplemented,
        3 => OciErrorCode::Unavailable,
        4 => OciErrorCode::Timeout,
        5 => OciErrorCode::PermissionDenied,
        6 => OciErrorCode::NotFound,
        7 => OciErrorCode::DataLoss,
        8 => OciErrorCode::ResourceExhausted,
        9 => OciErrorCode::FailedPrecondition,
        10 => OciErrorCode::AlreadyExists,
        11 => OciErrorCode::Internal,
        _ => return None,
    })
}

const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;
const FLAG_JOINED: u8 = 1;

/// [`Mode::Remove`] が消す対象（固定 2 種。親ディレクトリは fd 1 で渡し、子の名前はこの tag で選ぶ。#4800）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoveTarget {
    /// bundle ディレクトリ直下の `rootfs`。
    BundleRootfs,
    /// pull ディレクトリ（`staging/<id>`）直下の `unpack`。
    PullUnpack,
}

impl RemoveTarget {
    fn tag(self) -> u8 {
        match self {
            Self::BundleRootfs => 1,
            Self::PullUnpack => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::BundleRootfs),
            2 => Some(Self::PullUnpack),
            _ => None,
        }
    }

    /// fd 1 の直下で消す子の固定名（oci の `unpack/`・cri の `rootfs/` の定数と一致させる）。
    pub fn child_name(self) -> &'static str {
        match self {
            Self::BundleRootfs => "rootfs",
            Self::PullUnpack => "unpack",
        }
    }
}

/// helper が実行する固定長のモード（展開は payload が可変長のため [`Request::Extract`] に分ける）。足すため `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// 参加後の状態（threads・dumpable・euid・egid・写像の行数）の報告。
    Inspect,
    /// 対象 fd（fd 1）の、名前空間の中から見た所有者と mode の報告。
    StatTarget,
    /// 対象 fd（fd 1。親ディレクトリ）の直下の固定名の木を、名前空間の中で消す（#4800）。
    Remove(RemoveTarget),
}

impl Mode {
    fn tag(self) -> u8 {
        match self {
            Mode::Inspect => TAG_INSPECT,
            Mode::StatTarget => TAG_STAT_TARGET,
            Mode::Remove(_) => TAG_REMOVE,
        }
    }
}

/// helper が返す失敗の固定語彙（ワイヤー tag と `as_str` を持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelperErrorCode {
    /// 要求の形式不正（version・reserved・未知の tag・payload 長の不整合・対象 fd の種別違い）。
    InvalidRequest,
    /// `payload_len` が上限超過。
    RequestTooLarge,
    /// 未対応の入力（レイヤーの mediaType が表に無い等。fail-closed）。
    Unimplemented,
    /// 参加の直前に単一スレッドでない。
    MultiThreaded,
    /// 範囲写像の権限モデルでない（subuid / subgid が無い・root 等）。
    NoSubordinateIds,
    /// user namespace への参加に失敗した。
    JoinFailed,
    /// non-dumpable でない。
    NotNonDumpable,
    /// 要求の受信が期限切れ。
    RequestTimeout,
    /// 削除の拒否（マウントをまたぐ・種別違い等の `FailedPrecondition`。symlink は辿らず unlink するだけで拒否ではない。#4800）。
    RemoveRefused,
    /// 削除の失敗（拒否以外。#4800）。
    RemoveFailed,
    /// 展開の失敗（blob の検証・展開本体。oci の分類を運ぶ。後続の呼び出し側は `PullError::from_extract` へ渡す。#4847）。
    ExtractFailed(OciErrorCode),
    /// 上記以外の内部エラー。
    Internal,
}

impl HelperErrorCode {
    fn tag(self) -> u8 {
        match self {
            Self::InvalidRequest => 1,
            Self::RequestTooLarge => 2,
            Self::Unimplemented => 3,
            Self::MultiThreaded => 4,
            Self::NoSubordinateIds => 5,
            Self::JoinFailed => 6,
            Self::NotNonDumpable => 7,
            Self::RequestTimeout => 8,
            Self::Internal => 9,
            Self::RemoveRefused => 10,
            Self::RemoveFailed => 11,
            Self::ExtractFailed(_) => TAG_ERR_EXTRACT_FAILED,
        }
    }

    /// 単体で復号できる tag だけ（`ExtractFailed` は分類をスロット 0 から読むため `decode_response` が扱う）。
    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::InvalidRequest,
            2 => Self::RequestTooLarge,
            3 => Self::Unimplemented,
            4 => Self::MultiThreaded,
            5 => Self::NoSubordinateIds,
            6 => Self::JoinFailed,
            7 => Self::NotNonDumpable,
            8 => Self::RequestTimeout,
            9 => Self::Internal,
            10 => Self::RemoveRefused,
            11 => Self::RemoveFailed,
            _ => return None,
        })
    }

    /// 固定語彙の名前（ログ・メッセージ用。REPAIR-4）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::RequestTooLarge => "request_too_large",
            Self::Unimplemented => "unimplemented",
            Self::MultiThreaded => "multi_threaded",
            Self::NoSubordinateIds => "no_subordinate_ids",
            Self::JoinFailed => "join_failed",
            Self::NotNonDumpable => "not_non_dumpable",
            Self::RequestTimeout => "request_timeout",
            Self::Internal => "internal",
            Self::RemoveRefused => "remove_refused",
            Self::RemoveFailed => "remove_failed",
            Self::ExtractFailed(_) => "extract_failed",
        }
    }

    /// 親側で core の `ErrorCode` へ写す。
    pub fn core_code(self) -> ErrorCode {
        match self {
            Self::InvalidRequest | Self::RequestTooLarge => ErrorCode::InvalidArgument,
            Self::Unimplemented => ErrorCode::Unimplemented,
            Self::MultiThreaded
            | Self::NoSubordinateIds
            | Self::NotNonDumpable
            | Self::RemoveRefused => ErrorCode::FailedPrecondition,
            Self::RequestTimeout => ErrorCode::Timeout,
            Self::JoinFailed | Self::RemoveFailed | Self::Internal => ErrorCode::Internal,
            Self::ExtractFailed(c) => match c {
                OciErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
                OciErrorCode::Unimplemented => ErrorCode::Unimplemented,
                OciErrorCode::Unavailable => ErrorCode::Unavailable,
                OciErrorCode::Timeout => ErrorCode::Timeout,
                OciErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
                OciErrorCode::NotFound => ErrorCode::NotFound,
                OciErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
                OciErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
                OciErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
                // DataLoss（digest・diff_id の不一致）は core に対応が無く Internal。未知の分類も Internal。
                _ => ErrorCode::Internal,
            },
        }
    }
}

/// [`Mode::Inspect`] の報告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectReport {
    /// user namespace へ参加したか（試験専用の `--no-join` では false）。
    pub joined: bool,
    /// `/proc/self/status` の `Threads:`。
    pub threads: u32,
    /// `PR_GET_DUMPABLE`。
    pub dumpable: u32,
    /// 実効 uid（名前空間の中から見た値）。
    pub euid: u32,
    /// 実効 gid。
    pub egid: u32,
    /// `/proc/self/uid_map` の行数。
    pub uid_map_rows: u32,
    /// `/proc/self/gid_map` の行数。
    pub gid_map_rows: u32,
}

/// [`Mode::StatTarget`] の報告（対象 fd を名前空間の中から見た値。unmapped は 65534）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatReport {
    /// 所有 uid。
    pub uid: u32,
    /// 所有 gid。
    pub gid: u32,
    /// `st_mode & 0o7777`。
    pub mode: u32,
}

/// 成功時の報告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Report {
    /// [`Mode::Inspect`] の結果。
    Inspect(InspectReport),
    /// [`Mode::StatTarget`] の結果。
    StatTarget(StatReport),
    /// [`Mode::Remove`] の結果（対象の木が無くなった。不在も成功）。
    Removed,
    /// 展開要求の結果。
    Extracted(ExtractReport),
}

/// 展開の報告（レイヤー数と処理したエントリ数の合計。パス・名前は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractReport {
    /// 展開したレイヤー数。
    pub layers: u32,
    /// 処理したエントリ数の合計（`u32` で飽和）。
    pub entries: u32,
}

/// [`ExtractRequest`] の特殊ビットの方針（`SpecialBitsPolicy` のうち、写像を伴わない 2 種だけを受ける）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractSpecialBits {
    /// 常に落とす。
    Strip,
    /// `chown` と読み戻しの後の所有者が写像と一致するものだけ保持する（`PreserveIfChowned`）。
    PreserveIfChowned,
}

impl ExtractSpecialBits {
    fn tag(self) -> u8 {
        match self {
            Self::Strip => 1,
            Self::PreserveIfChowned => 2,
        }
    }

    fn from_tag(t: u8) -> Option<Self> {
        match t {
            1 => Some(Self::Strip),
            2 => Some(Self::PreserveIfChowned),
            _ => None,
        }
    }
}

/// `sha256:<hex>` の digest を 32 バイトへ（wire は固定長で運ぶ。sha256 以外は `Digest` が作れない）。
fn digest_to_bytes(d: &Digest) -> Option<[u8; 32]> {
    let hex = d.as_str().strip_prefix("sha256:")?;
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn digest_from_bytes(b: &[u8]) -> Result<Digest, HelperErrorCode> {
    use std::fmt::Write as _;
    let mut s = String::from("sha256:");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    Digest::parse(&s).map_err(|_| HelperErrorCode::InvalidRequest)
}

/// 展開要求の 1 レイヤー（blob の fd は別に `SCM_RIGHTS` で渡し、ここは検証の期待値だけを持つ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractLayerSpec {
    /// [`LAYER_MEDIA_TYPES`] の 1 起点の添字（mediaType の文字列は送らない）。
    media_index: u8,
    size: u64,
    digest: Digest,
    diff_id: Digest,
}

impl ExtractLayerSpec {
    /// manifest の descriptor の値から作る。表に無い mediaType は `Unimplemented`（親が spawn の前に拒否する）。
    pub fn new(
        media_type: &str,
        size: u64,
        digest: Digest,
        diff_id: Digest,
    ) -> Result<Self, HelperErrorCode> {
        let idx = LAYER_MEDIA_TYPES
            .iter()
            .position(|e| e.media_type == media_type)
            .and_then(|i| u8::try_from(i + 1).ok())
            .ok_or(HelperErrorCode::Unimplemented)?;
        Self::from_parts(idx, size, digest, diff_id)
    }

    fn from_parts(
        media_index: u8,
        size: u64,
        digest: Digest,
        diff_id: Digest,
    ) -> Result<Self, HelperErrorCode> {
        let known = (1..=LAYER_MEDIA_TYPES.len()).contains(&usize::from(media_index));
        if !known || digest_to_bytes(&digest).is_none() || digest_to_bytes(&diff_id).is_none() {
            return Err(HelperErrorCode::InvalidRequest);
        }
        Ok(Self {
            media_index,
            size,
            digest,
            diff_id,
        })
    }

    /// mediaType（表の固定文字列）。
    pub fn media_type(&self) -> &'static str {
        LAYER_MEDIA_TYPES
            .get(usize::from(self.media_index).saturating_sub(1))
            .map_or("", |e| e.media_type)
    }

    /// manifest の descriptor の `size`。
    pub fn size(&self) -> u64 {
        self.size
    }

    /// blob の digest。
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// image config の `rootfs.diff_ids` の対応する要素。
    pub fn diff_id(&self) -> &Digest {
        &self.diff_id
    }
}

/// 展開要求（展開モード。所有者の方針は `ChownInUserNamespace` 固定で、写像は helper が参加に使ったものを使う）。
///
/// 制限値は 1 以上かつ oci の既定値以下に限る（親が上限を広げて helper に無制限の確保・書き込みをさせないため）。
/// 既定値より大きい上限が要るようになったら、wire の版を上げて足す。閉じ込めの祖先（`confined_in`）は未対応（#4801 の判断待ち）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRequest {
    special_bits: ExtractSpecialBits,
    work_ms: u32,
    limits: ExtractLimits,
    max_uncompressed_bytes: u64,
    layers: Vec<ExtractLayerSpec>,
}

impl ExtractRequest {
    /// 検証して作る。違反は `InvalidRequest`。`work_ms` は上限（600 秒）で始まり、[`Self::with_work`] で絞る。
    pub fn new(
        special_bits: ExtractSpecialBits,
        limits: ExtractLimits,
        max_uncompressed_bytes: u64,
        layers: Vec<ExtractLayerSpec>,
    ) -> Result<Self, HelperErrorCode> {
        Self::checked(
            special_bits,
            WORK_MS_MAX,
            limits,
            max_uncompressed_bytes,
            layers,
        )
    }

    fn checked(
        special_bits: ExtractSpecialBits,
        work_ms: u32,
        limits: ExtractLimits,
        max_uncompressed_bytes: u64,
        layers: Vec<ExtractLayerSpec>,
    ) -> Result<Self, HelperErrorCode> {
        let in_range = |v: u64, max: u64| (1..=max).contains(&v);
        let ok = !layers.is_empty()
            && layers.len() <= MAX_EXTRACT_LAYERS
            && (1..=WORK_MS_MAX).contains(&work_ms)
            && in_range(limits.max_entries, DEFAULT_MAX_LAYER_ENTRIES)
            && in_range(limits.max_total_bytes, DEFAULT_MAX_EXTRACTED_BYTES)
            && in_range(limits.max_input_bytes, DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES)
            && in_range(limits.max_tracked_paths, DEFAULT_MAX_TRACKED_PATHS)
            && in_range(max_uncompressed_bytes, DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES);
        if !ok {
            return Err(HelperErrorCode::InvalidRequest);
        }
        Ok(Self {
            special_bits,
            work_ms,
            limits,
            max_uncompressed_bytes,
            layers,
        })
    }

    /// helper が展開に使ってよい時間（1 ms 以上、600 秒以下に丸める。端数は切り上げ）を設定する。
    pub fn with_work(self, d: Duration) -> Result<Self, HelperErrorCode> {
        let ms = d.as_nanos().div_ceil(1_000_000);
        let ms = u32::try_from(ms).unwrap_or(u32::MAX).clamp(1, WORK_MS_MAX);
        Self::checked(
            self.special_bits,
            ms,
            self.limits,
            self.max_uncompressed_bytes,
            self.layers,
        )
    }

    /// 特殊ビットの方針。
    pub fn special_bits(&self) -> ExtractSpecialBits {
        self.special_bits
    }

    /// helper の展開期限（ms）。
    pub fn work_ms(&self) -> u32 {
        self.work_ms
    }

    /// 展開の上限。
    pub fn limits(&self) -> ExtractLimits {
        self.limits
    }

    /// gzip 展開後サイズの上限（レイヤーごと）。
    pub fn max_uncompressed_bytes(&self) -> u64 {
        self.max_uncompressed_bytes
    }

    /// レイヤー（重ねる順）。
    pub fn layers(&self) -> &[ExtractLayerSpec] {
        &self.layers
    }
}

/// 符号化済みの展開要求 frame（header + payload。長さは header + [`MAX_EXTRACT_PAYLOAD_BYTES`] 以下。encoder だけが作る）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRequestFrame(Vec<u8>);

impl ExtractRequestFrame {
    /// 書き込む bytes。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 展開要求を符号化する。
pub fn encode_extract_request(req: &ExtractRequest) -> ExtractRequestFrame {
    let payload_len = EXTRACT_FIXED_LEN + req.layers.len() * EXTRACT_LAYER_LEN;
    let mut v = Vec::with_capacity(REQUEST_HEADER_LEN + payload_len);
    v.extend_from_slice(&[WIRE_VERSION, TAG_EXTRACT, 0, 0]);
    v.extend_from_slice(&u32::try_from(payload_len).unwrap_or(0).to_be_bytes());
    v.push(OWNERSHIP_CHOWN_IN_USERNS);
    v.push(req.special_bits.tag());
    v.extend_from_slice(&u16::try_from(req.layers.len()).unwrap_or(0).to_be_bytes());
    v.extend_from_slice(&req.work_ms.to_be_bytes());
    for n in [
        req.limits.max_entries,
        req.limits.max_total_bytes,
        req.limits.max_input_bytes,
        req.limits.max_tracked_paths,
        req.max_uncompressed_bytes,
    ] {
        v.extend_from_slice(&n.to_be_bytes());
    }
    for l in &req.layers {
        v.extend_from_slice(&[l.media_index, 0, 0, 0]);
        v.extend_from_slice(&l.size.to_be_bytes());
        // 構築時に 32 バイトへ変換できることを検査済み。
        v.extend_from_slice(&digest_to_bytes(&l.digest).unwrap_or_default());
        v.extend_from_slice(&digest_to_bytes(&l.diff_id).unwrap_or_default());
    }
    ExtractRequestFrame(v)
}

fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at.checked_add(8)?)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_be_bytes)
}

/// 展開要求の payload を復号する（長さは [`decode_request_header`] が検査済みでも、ここでも検査する）。
pub fn decode_extract_payload(p: &[u8]) -> Result<ExtractRequest, HelperErrorCode> {
    let bad = HelperErrorCode::InvalidRequest;
    let n = extract_layer_count(p.len()).ok_or(bad)?;
    let fixed = p.get(..EXTRACT_FIXED_LEN).ok_or(bad)?;
    let (Some(&own), Some(&sb), Some(cnt), Some(work)) = (
        fixed.first(),
        fixed.get(1),
        fixed
            .get(2..4)
            .and_then(|s| <[u8; 2]>::try_from(s).ok())
            .map(u16::from_be_bytes),
        fixed
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes),
    ) else {
        return Err(bad);
    };
    if own != OWNERSHIP_CHOWN_IN_USERNS || usize::from(cnt) != n {
        return Err(bad);
    }
    let special = ExtractSpecialBits::from_tag(sb).ok_or(bad)?;
    let mut nums = [0u64; 5];
    for (i, o) in nums.iter_mut().enumerate() {
        *o = be_u64(fixed, 8 + i * 8).ok_or(bad)?;
    }
    let [e, t, i, tp, mu] = nums;
    let mut layers = Vec::with_capacity(n);
    let body = p.get(EXTRACT_FIXED_LEN..).ok_or(bad)?;
    for chunk in body.as_chunks::<EXTRACT_LAYER_LEN>().0 {
        let (Some(&media), Some(rsv), Some(size), Some(d), Some(di)) = (
            chunk.first(),
            chunk.get(1..4),
            be_u64(chunk, 4),
            chunk.get(12..44),
            chunk.get(44..76),
        ) else {
            return Err(bad);
        };
        if rsv != [0, 0, 0] {
            return Err(bad);
        }
        layers.push(ExtractLayerSpec::from_parts(
            media,
            size,
            digest_from_bytes(d)?,
            digest_from_bytes(di)?,
        )?);
    }
    ExtractRequest::checked(special, work, ExtractLimits::new(e, t, i, tp), mu, layers)
}

/// 展開要求の payload 長からレイヤー数を得る（`48 + n × 76`、1 ≤ n ≤ 128 だけ）。
fn extract_layer_count(payload_len: usize) -> Option<usize> {
    let body = payload_len.checked_sub(EXTRACT_FIXED_LEN)?;
    let n = body / EXTRACT_LAYER_LEN;
    (body % EXTRACT_LAYER_LEN == 0 && (1..=MAX_EXTRACT_LAYERS).contains(&n)).then_some(n)
}

/// 復号した要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// 固定長のモード。
    Mode(Mode),
    /// 展開要求（blob の fd は別に受ける）。
    Extract(ExtractRequest),
}
/// 符号化済みの要求 frame（固定長バッファ。生の `Vec<u8>` を組まない。REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFrame {
    buf: [u8; MAX_FRAME_LEN],
    len: usize,
}

impl RequestFrame {
    /// 書き込む bytes（header + payload）。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

/// 要求を符号化する。
pub fn encode_request(mode: Mode) -> RequestFrame {
    let mut buf = [0u8; MAX_FRAME_LEN];
    let payload_len = match mode {
        Mode::Remove(t) => {
            buf[REQUEST_HEADER_LEN] = t.tag();
            REMOVE_PAYLOAD_LEN
        }
        _ => 0,
    };
    buf[0] = WIRE_VERSION;
    buf[1] = mode.tag();
    // payload_len は 0 か 4（u32 に収まる）。
    buf[4..8].copy_from_slice(&u32::try_from(payload_len).unwrap_or(0).to_be_bytes());
    RequestFrame {
        buf,
        len: REQUEST_HEADER_LEN + payload_len,
    }
}

/// 検査済みの要求 header（読むべき payload の長さが決まっている）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHead {
    tag: u8,
    payload_len: usize,
}

impl RequestHead {
    /// 読むべき payload の長さ（高々 [`MAX_EXTRACT_PAYLOAD_BYTES`]。呼び出し側は固定長バッファへ読む）。
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// payload（長さは [`Self::payload_len`] と一致すること）から [`Request`] を得る。
    pub fn request(&self, payload: &[u8]) -> Result<Request, HelperErrorCode> {
        if payload.len() != self.payload_len {
            return Err(HelperErrorCode::InvalidRequest);
        }
        if self.tag == TAG_EXTRACT {
            return decode_extract_payload(payload).map(Request::Extract);
        }
        self.mode(payload).map(Request::Mode)
    }

    /// payload（長さは [`Self::payload_len`] と一致すること）から固定長の [`Mode`] を得る（展開要求は `InvalidRequest`）。
    pub fn mode(&self, payload: &[u8]) -> Result<Mode, HelperErrorCode> {
        if payload.len() != self.payload_len {
            return Err(HelperErrorCode::InvalidRequest);
        }
        match self.tag {
            TAG_INSPECT => Ok(Mode::Inspect),
            TAG_STAT_TARGET => Ok(Mode::StatTarget),
            TAG_REMOVE => match payload {
                [t, 0, 0, 0] => RemoveTarget::from_tag(*t)
                    .map(Mode::Remove)
                    .ok_or(HelperErrorCode::InvalidRequest),
                _ => Err(HelperErrorCode::InvalidRequest),
            },
            _ => Err(HelperErrorCode::InvalidRequest),
        }
    }
}

/// 要求 header を検査する。`payload_len` の上限検査は tag の検査より先（確保・読み取りの前）。
/// tag ごとの固定長（展開要求は `48 + n × 76`、1 ≤ n ≤ 128）と合わない長さは `InvalidRequest`。
pub fn decode_request_header(
    header: &[u8; REQUEST_HEADER_LEN],
) -> Result<RequestHead, HelperErrorCode> {
    let [version, tag, r0, r1, l0, l1, l2, l3] = *header;
    if version != WIRE_VERSION || r0 != 0 || r1 != 0 {
        return Err(HelperErrorCode::InvalidRequest);
    }
    let payload_len = u32::from_be_bytes([l0, l1, l2, l3]);
    let payload_len = match usize::try_from(payload_len) {
        Ok(n) if n <= MAX_REQUEST_PAYLOAD_BYTES => n,
        _ => return Err(HelperErrorCode::RequestTooLarge),
    };
    let want = match tag {
        TAG_INSPECT | TAG_STAT_TARGET => 0,
        TAG_REMOVE => REMOVE_PAYLOAD_LEN,
        TAG_EXTRACT => extract_layer_count(payload_len)
            .map(|_| payload_len)
            .ok_or(HelperErrorCode::InvalidRequest)?,
        _ => return Err(HelperErrorCode::InvalidRequest),
    };
    if payload_len != want {
        return Err(HelperErrorCode::InvalidRequest);
    }
    Ok(RequestHead { tag, payload_len })
}

/// 完全な要求 frame（header + payload）を復号する（試験・往復用。helper は 2 段で読む）。
pub fn decode_request(buf: &[u8]) -> Result<Request, HelperErrorCode> {
    let (header, payload) = buf
        .split_first_chunk::<REQUEST_HEADER_LEN>()
        .ok_or(HelperErrorCode::InvalidRequest)?;
    decode_request_header(header)?.request(payload)
}

fn put(frame: &mut [u8; RESPONSE_LEN], slot: usize, value: u32) {
    let at = 4 + slot * 4;
    if let Some(dst) = frame.get_mut(at..at + 4) {
        dst.copy_from_slice(&value.to_be_bytes());
    }
}

fn get(frame: &[u8; RESPONSE_LEN], slot: usize) -> u32 {
    let at = 4 + slot * 4;
    frame
        .get(at..at + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes)
}

/// 応答 frame を符号化する。
pub fn encode_response(result: &Result<Report, HelperErrorCode>) -> [u8; RESPONSE_LEN] {
    let mut f = [0u8; RESPONSE_LEN];
    f[0] = WIRE_VERSION;
    match result {
        Err(code) => {
            f[1] = STATUS_ERR;
            f[2] = code.tag();
            if let HelperErrorCode::ExtractFailed(c) = code {
                put(&mut f, 0, oci_class_tag(*c));
            }
        }
        Ok(Report::Inspect(r)) => {
            f[1] = STATUS_OK;
            f[2] = TAG_INSPECT;
            f[3] = if r.joined { FLAG_JOINED } else { 0 };
            for (i, v) in [
                r.threads,
                r.dumpable,
                r.euid,
                r.egid,
                r.uid_map_rows,
                r.gid_map_rows,
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut f, i, v);
            }
        }
        Ok(Report::StatTarget(r)) => {
            f[1] = STATUS_OK;
            f[2] = TAG_STAT_TARGET;
            for (i, v) in [r.uid, r.gid, r.mode].into_iter().enumerate() {
                put(&mut f, i, v);
            }
        }
        Ok(Report::Removed) => {
            f[1] = STATUS_OK;
            f[2] = TAG_REMOVE;
        }
        Ok(Report::Extracted(r)) => {
            f[1] = STATUS_OK;
            f[2] = TAG_EXTRACT;
            put(&mut f, 0, r.layers);
            put(&mut f, 1, r.entries);
        }
    }
    f
}

/// 応答 frame を検査して復号する。形式不正は `None`（呼び出し側が Protocol エラーにする）。
pub fn decode_response(buf: &[u8]) -> Option<Result<Report, HelperErrorCode>> {
    let f: &[u8; RESPONSE_LEN] = buf.try_into().ok()?;
    if f[0] != WIRE_VERSION {
        return None;
    }
    let used_slots;
    let out = match (f[1], f[2]) {
        (STATUS_ERR, tag) => {
            if f[3] != 0 {
                return None;
            }
            if tag == TAG_ERR_EXTRACT_FAILED {
                used_slots = 1;
                Err(HelperErrorCode::ExtractFailed(oci_class_from_tag(get(
                    f, 0,
                ))?))
            } else {
                used_slots = 0;
                Err(HelperErrorCode::from_tag(tag)?)
            }
        }
        (STATUS_OK, TAG_INSPECT) => {
            used_slots = 6;
            if f[3] & !FLAG_JOINED != 0 {
                return None;
            }
            Ok(Report::Inspect(InspectReport {
                joined: f[3] & FLAG_JOINED != 0,
                threads: get(f, 0),
                dumpable: get(f, 1),
                euid: get(f, 2),
                egid: get(f, 3),
                uid_map_rows: get(f, 4),
                gid_map_rows: get(f, 5),
            }))
        }
        (STATUS_OK, TAG_STAT_TARGET) => {
            used_slots = 3;
            if f[3] != 0 {
                return None;
            }
            Ok(Report::StatTarget(StatReport {
                uid: get(f, 0),
                gid: get(f, 1),
                mode: get(f, 2),
            }))
        }
        (STATUS_OK, TAG_REMOVE) => {
            used_slots = 0;
            if f[3] != 0 {
                return None;
            }
            Ok(Report::Removed)
        }
        (STATUS_OK, TAG_EXTRACT) => {
            used_slots = 2;
            if f[3] != 0 {
                return None;
            }
            Ok(Report::Extracted(ExtractReport {
                layers: get(f, 0),
                entries: get(f, 1),
            }))
        }
        _ => return None,
    };
    // 未使用のスロットは 0 でなければ拒否する。
    if (used_slots..7).any(|s| get(f, s) != 0) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, tag: u8, reserved: [u8; 2], len: u32) -> [u8; 8] {
        let l = len.to_be_bytes();
        [
            version,
            tag,
            reserved[0],
            reserved[1],
            l[0],
            l[1],
            l[2],
            l[3],
        ]
    }

    /// SEC-5・REPAIR-2・#4795: 要求 header の往復と、H1 の 2 モードの tag は 1 / 2。
    #[test]
    fn sec5_4795_request_roundtrip_and_tags() {
        assert_eq!(
            encode_request(Mode::Inspect).as_bytes(),
            &[1, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_request(Mode::StatTarget).as_bytes(),
            &[1, 2, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            decode_request(encode_request(Mode::Inspect).as_bytes()),
            Ok(Request::Mode(Mode::Inspect))
        );
        assert_eq!(
            decode_request(encode_request(Mode::StatTarget).as_bytes()),
            Ok(Request::Mode(Mode::StatTarget))
        );
    }

    /// SEC-5・OCI-7・REPAIR-2・#4800: Remove の要求は固定 12 バイトで、対象は tag 1 / 2 の具体値で往復する。
    #[test]
    fn sec5_4800_remove_request_roundtrip() {
        let root = encode_request(Mode::Remove(RemoveTarget::BundleRootfs));
        assert_eq!(root.as_bytes(), &[1, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0]);
        assert_eq!(
            decode_request(root.as_bytes()),
            Ok(Request::Mode(Mode::Remove(RemoveTarget::BundleRootfs)))
        );
        let unpack = encode_request(Mode::Remove(RemoveTarget::PullUnpack));
        assert_eq!(unpack.as_bytes(), &[1, 4, 0, 0, 0, 0, 0, 4, 2, 0, 0, 0]);
        assert_eq!(
            decode_request(unpack.as_bytes()),
            Ok(Request::Mode(Mode::Remove(RemoveTarget::PullUnpack)))
        );
        assert_eq!(RemoveTarget::BundleRootfs.child_name(), "rootfs");
        assert_eq!(RemoveTarget::PullUnpack.child_name(), "unpack");
        // header だけを先に検査すると、読むべき長さは 4。
        let head = decode_request_header(&[1, 4, 0, 0, 0, 0, 0, 4]).unwrap();
        assert_eq!(head.payload_len(), 4);
    }

    /// SEC-5・REPAIR-2・#4800: Remove の payload は厳密。長さ違い・未知の対象・予約バイト非 0 は `InvalidRequest`、
    /// 上限 + 1 は従来どおり `RequestTooLarge`、tag 3 は長さ 0 で `InvalidRequest`（展開要求は固定部が要る）。
    #[test]
    fn sec5_4800_remove_payload_is_strict() {
        for len in [0u32, 3, 5] {
            assert_eq!(
                decode_request_header(&header(1, 4, [0, 0], len)),
                Err(HelperErrorCode::InvalidRequest),
                "len {len}"
            );
        }
        for bad in [
            [0, 0, 0, 0],
            [3, 0, 0, 0],
            [1, 1, 0, 0],
            [2, 0, 1, 0],
            [1, 0, 0, 9],
        ] {
            let mut buf = header(1, 4, [0, 0], 4).to_vec();
            buf.extend_from_slice(&bad);
            assert_eq!(
                decode_request(&buf),
                Err(HelperErrorCode::InvalidRequest),
                "{bad:?}"
            );
        }
        // header と payload の長さの不一致（payload が付いていない）。
        assert_eq!(
            decode_request(&header(1, 4, [0, 0], 4)),
            Err(HelperErrorCode::InvalidRequest)
        );
        let too_big = u32::try_from(MAX_REQUEST_PAYLOAD_BYTES).unwrap() + 1;
        assert_eq!(
            decode_request_header(&header(1, 4, [0, 0], too_big)),
            Err(HelperErrorCode::RequestTooLarge)
        );
        assert_eq!(
            decode_request_header(&header(1, 3, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
    }

    /// SEC-5・#4800: Remove の応答 `Removed` は往復し、未使用スロットが非 0 の frame は拒否する。
    #[test]
    fn sec5_4800_removed_response_roundtrip() {
        let f = encode_response(&Ok(Report::Removed));
        assert_eq!(&f[..4], &[1, 0, 4, 0]);
        assert!(f[4..].iter().all(|b| *b == 0));
        assert_eq!(decode_response(&f), Some(Ok(Report::Removed)));
        let mut bad = f;
        bad[4] = 1;
        assert_eq!(decode_response(&bad), None);
        let mut bad = f;
        bad[3] = 1;
        assert_eq!(decode_response(&bad), None);
    }

    /// REPAIR-5・#4795: 上限ちょうどは tag の検査へ進み、上限 + 1 は tag を問わず `RequestTooLarge`（確保の前）。
    #[test]
    fn sec5_4795_payload_limit_is_checked_before_anything_else() {
        let max = u32::try_from(MAX_REQUEST_PAYLOAD_BYTES).unwrap();
        assert_eq!(MAX_REQUEST_PAYLOAD_BYTES, 16384);
        // 上限ちょうど: tag 1 は payload 非 0 で InvalidRequest（上限検査は通過している）。
        assert_eq!(
            decode_request(&header(1, 1, [0, 0], max)),
            Err(HelperErrorCode::InvalidRequest)
        );
        for tag in [1, 3, 4, 99] {
            assert_eq!(
                decode_request(&header(1, tag, [0, 0], max + 1)),
                Err(HelperErrorCode::RequestTooLarge)
            );
        }
        assert_eq!(
            decode_request(&header(1, 1, [0, 0], u32::MAX)),
            Err(HelperErrorCode::RequestTooLarge)
        );
    }

    /// REPAIR-2・#4795: version・reserved・未知の tag・長さ違いは `InvalidRequest`。tag 3 は長さ 0 で `InvalidRequest`（tag 4 は payload 必須）。
    #[test]
    fn sec5_4795_malformed_and_reserved_requests() {
        assert_eq!(
            decode_request(&header(2, 1, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 1, [1, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 1, [0, 1], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 0, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 5, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 2, [0, 0], 1)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 3, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&header(1, 4, [0, 0], 0)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request(&[1, 1, 0]),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(decode_request(&[]), Err(HelperErrorCode::InvalidRequest));
    }

    /// REPAIR-2・#4795: 応答 frame の往復（具体値）。
    #[test]
    fn sec5_4795_response_roundtrip() {
        let inspect = Report::Inspect(InspectReport {
            joined: true,
            threads: 1,
            dumpable: 0,
            euid: 0,
            egid: 0,
            uid_map_rows: 2,
            gid_map_rows: 3,
        });
        let f = encode_response(&Ok(inspect));
        assert_eq!(f.len(), 32);
        assert_eq!(&f[..4], &[1, 0, 1, 1]);
        assert_eq!(decode_response(&f), Some(Ok(inspect)));
        let stat = Report::StatTarget(StatReport {
            uid: 0,
            gid: 65534,
            mode: 0o700,
        });
        assert_eq!(decode_response(&encode_response(&Ok(stat))), Some(Ok(stat)));
        for code in [
            HelperErrorCode::InvalidRequest,
            HelperErrorCode::RequestTooLarge,
            HelperErrorCode::Unimplemented,
            HelperErrorCode::MultiThreaded,
            HelperErrorCode::NoSubordinateIds,
            HelperErrorCode::JoinFailed,
            HelperErrorCode::NotNonDumpable,
            HelperErrorCode::RequestTimeout,
            HelperErrorCode::RemoveRefused,
            HelperErrorCode::RemoveFailed,
            HelperErrorCode::ExtractFailed(OciErrorCode::DataLoss),
            HelperErrorCode::Internal,
        ] {
            assert_eq!(
                decode_response(&encode_response(&Err(code))),
                Some(Err(code))
            );
        }
    }

    /// REPAIR-2・#4795: 未使用スロット・未知のフラグ・版・長さの違う応答は拒否する。
    #[test]
    fn sec5_4795_malformed_responses_are_rejected() {
        let mut f = encode_response(&Ok(Report::StatTarget(StatReport {
            uid: 1,
            gid: 2,
            mode: 3,
        })));
        assert!(decode_response(&f).is_some());
        f[4 + 3 * 4 + 3] = 1; // スロット 3（未使用）
        assert_eq!(decode_response(&f), None);
        let mut f = encode_response(&Err(HelperErrorCode::Internal));
        f[3] = 1;
        assert_eq!(decode_response(&f), None);
        let mut f = encode_response(&Err(HelperErrorCode::Internal));
        f[0] = 2;
        assert_eq!(decode_response(&f), None);
        let mut f = encode_response(&Err(HelperErrorCode::Internal));
        f[2] = 0;
        assert_eq!(decode_response(&f), None);
        assert_eq!(decode_response(&[0u8; 31]), None);
        assert_eq!(decode_response(&[0u8; 33]), None);
    }

    /// REPAIR-4・#4795: エラー語彙の名前と core の `ErrorCode` への写像を固定する。
    #[test]
    fn sec5_4795_error_vocabulary_is_fixed() {
        let table = [
            (
                HelperErrorCode::InvalidRequest,
                "invalid_request",
                ErrorCode::InvalidArgument,
            ),
            (
                HelperErrorCode::RequestTooLarge,
                "request_too_large",
                ErrorCode::InvalidArgument,
            ),
            (
                HelperErrorCode::Unimplemented,
                "unimplemented",
                ErrorCode::Unimplemented,
            ),
            (
                HelperErrorCode::MultiThreaded,
                "multi_threaded",
                ErrorCode::FailedPrecondition,
            ),
            (
                HelperErrorCode::NoSubordinateIds,
                "no_subordinate_ids",
                ErrorCode::FailedPrecondition,
            ),
            (
                HelperErrorCode::JoinFailed,
                "join_failed",
                ErrorCode::Internal,
            ),
            (
                HelperErrorCode::NotNonDumpable,
                "not_non_dumpable",
                ErrorCode::FailedPrecondition,
            ),
            (
                HelperErrorCode::RequestTimeout,
                "request_timeout",
                ErrorCode::Timeout,
            ),
            (
                HelperErrorCode::RemoveRefused,
                "remove_refused",
                ErrorCode::FailedPrecondition,
            ),
            (
                HelperErrorCode::RemoveFailed,
                "remove_failed",
                ErrorCode::Internal,
            ),
            (HelperErrorCode::Internal, "internal", ErrorCode::Internal),
            (
                HelperErrorCode::ExtractFailed(OciErrorCode::DataLoss),
                "extract_failed",
                ErrorCode::Internal,
            ),
            (
                HelperErrorCode::ExtractFailed(OciErrorCode::Timeout),
                "extract_failed",
                ErrorCode::Timeout,
            ),
            (
                HelperErrorCode::ExtractFailed(OciErrorCode::ResourceExhausted),
                "extract_failed",
                ErrorCode::ResourceExhausted,
            ),
        ];
        for (code, name, core) in table {
            assert_eq!(code.as_str(), name);
            assert_eq!(code.core_code(), core);
        }
    }

    fn dg(c: char) -> Digest {
        Digest::parse(&format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn layer(media: &str) -> ExtractLayerSpec {
        ExtractLayerSpec::new(media, 1234, dg('a'), dg('b')).unwrap()
    }

    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

    fn req(n: usize) -> ExtractRequest {
        ExtractRequest::new(
            ExtractSpecialBits::PreserveIfChowned,
            ExtractLimits::default(),
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            (0..n).map(|_| layer(TAR)).collect(),
        )
        .unwrap()
        .with_work(Duration::from_millis(1500))
        .unwrap()
    }

    /// SEC-5・OCI-1・REPAIR-2・#4847: 1 層の展開要求の bytes を具体値で固定し、往復する。
    #[test]
    fn sec5_4847_extract_request_roundtrip_and_bytes() {
        let f = encode_extract_request(&req(1));
        let b = f.as_bytes();
        assert_eq!(b.len(), 8 + 48 + 76);
        // header: version 1・tag 3・payload 124 = 0x7c。
        assert_eq!(&b[..8], &[1, 3, 0, 0, 0, 0, 0, 0x7c]);
        // 固定部: ownership 1・special 2・layers 1・work 1500 ms = 0x5dc。
        assert_eq!(&b[8..16], &[1, 2, 0, 1, 0, 0, 0x05, 0xdc]);
        // レイヤー: media 添字 1・予約 0・size 1234 = 0x4d2・digest の先頭 0xaa・diff_id の先頭 0xbb。
        assert_eq!(&b[56..68], &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0xd2]);
        assert_eq!(b[68], 0xaa);
        assert_eq!(b[100], 0xbb);
        assert_eq!(decode_request(b), Ok(Request::Extract(req(1))));
        let head = decode_request_header(b[..8].try_into().unwrap()).unwrap();
        assert_eq!(head.payload_len(), 124);
        let r = req(1);
        assert_eq!(r.layers()[0].media_type(), TAR);
        assert_eq!(r.layers()[0].size(), 1234);
        assert_eq!(r.work_ms(), 1500);
    }

    /// REPAIR-5・#4847: 件数の上限（128 は受理、129 と 0 は拒否）と、header の長さの検査。
    #[test]
    fn sec5_4847_extract_layer_count_bounds() {
        assert_eq!(MAX_EXTRACT_PAYLOAD_BYTES, 48 + 128 * 76);
        assert_eq!(MAX_EXTRACT_PAYLOAD_BYTES, 9776);
        let f = encode_extract_request(&req(128));
        assert_eq!(f.as_bytes().len(), 8 + 9776);
        assert_eq!(decode_request(f.as_bytes()), Ok(Request::Extract(req(128))));
        // 129 層は構築できず、長さだけ 129 層の header も InvalidRequest（上限 16 KiB 以下のため RequestTooLarge ではない）。
        assert_eq!(
            ExtractRequest::new(
                ExtractSpecialBits::Strip,
                ExtractLimits::default(),
                1,
                (0..129).map(|_| layer(TAR)).collect()
            ),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            ExtractRequest::new(
                ExtractSpecialBits::Strip,
                ExtractLimits::default(),
                1,
                vec![]
            ),
            Err(HelperErrorCode::InvalidRequest)
        );
        for len in [0u32, 48, 48 + 75, 48 + 76 - 1, 48 + 76 + 1, 48 + 129 * 76] {
            assert_eq!(
                decode_request_header(&header(1, 3, [0, 0], len)),
                Err(HelperErrorCode::InvalidRequest),
                "len {len}"
            );
        }
        let max = u32::try_from(MAX_REQUEST_PAYLOAD_BYTES).unwrap();
        assert_eq!(
            decode_request_header(&header(1, 3, [0, 0], max + 1)),
            Err(HelperErrorCode::RequestTooLarge)
        );
        assert_eq!(
            decode_request_header(&header(1, 3, [0, 0], 124))
                .unwrap()
                .payload_len(),
            124
        );
        // 版 2・予約バイトは tag 3 でも InvalidRequest。
        assert_eq!(
            decode_request_header(&header(2, 3, [0, 0], 124)),
            Err(HelperErrorCode::InvalidRequest)
        );
        assert_eq!(
            decode_request_header(&header(1, 3, [0, 1], 124)),
            Err(HelperErrorCode::InvalidRequest)
        );
    }

    /// SEC-5・REPAIR-2・#4847: 壊れた payload（tag・予約・添字・件数不一致・制限値・work_ms）は `InvalidRequest`。
    #[test]
    fn sec5_4847_malformed_extract_payloads_are_rejected() {
        let good = encode_extract_request(&req(1)).as_bytes().to_vec();
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut mutate = |name, at: usize, v: &[u8]| {
            let mut b = good.clone();
            b[at..at + v.len()].copy_from_slice(v);
            cases.push((name, b));
        };
        mutate("ownership 0", 8, &[0]);
        mutate("ownership 2", 8, &[2]);
        mutate("special 0", 9, &[0]);
        mutate("special 3", 9, &[3]);
        mutate("count mismatch", 10, &[0, 2]);
        mutate("work 0", 12, &[0, 0, 0, 0]);
        mutate("work over", 12, &600_001u32.to_be_bytes());
        for (i, name) in ["entries", "total", "input", "tracked", "uncompressed"]
            .into_iter()
            .enumerate()
        {
            let at = 16 + i * 8;
            mutate(name, at, &0u64.to_be_bytes());
        }
        mutate(
            "entries over",
            16,
            &(DEFAULT_MAX_LAYER_ENTRIES + 1).to_be_bytes(),
        );
        mutate(
            "total over",
            24,
            &(DEFAULT_MAX_EXTRACTED_BYTES + 1).to_be_bytes(),
        );
        mutate(
            "tracked over",
            40,
            &(DEFAULT_MAX_TRACKED_PATHS + 1).to_be_bytes(),
        );
        mutate(
            "uncompressed over",
            48,
            &(DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES + 1).to_be_bytes(),
        );
        mutate("media 0", 56, &[0]);
        mutate("media 7", 56, &[7]);
        mutate("reserved", 57, &[1]);
        for (name, b) in &cases {
            assert_eq!(
                decode_request(b),
                Err(HelperErrorCode::InvalidRequest),
                "{name}"
            );
        }
        assert_eq!(decode_request(&good), Ok(Request::Extract(req(1))));
    }

    /// OCI-1・#4847: mediaType は表の 6 種すべてが添字で往復し、表に無い値は `Unimplemented`。
    #[test]
    fn sec5_4847_every_media_type_round_trips_and_unknown_is_unimplemented() {
        assert_eq!(LAYER_MEDIA_TYPES.len(), 6);
        for e in LAYER_MEDIA_TYPES {
            assert_eq!(layer(e.media_type).media_type(), e.media_type);
        }
        assert_eq!(
            ExtractLayerSpec::new(
                "application/vnd.oci.image.layer.v1.tar+zstd",
                1,
                dg('a'),
                dg('b')
            ),
            Err(HelperErrorCode::Unimplemented)
        );
    }

    /// SEC-5・#4847: 展開の結果の応答は往復し、未使用スロットが非 0 の frame は拒否する。
    #[test]
    fn sec5_4847_extracted_response_roundtrip() {
        let r = Report::Extracted(ExtractReport {
            layers: 3,
            entries: 70_000,
        });
        let f = encode_response(&Ok(r));
        assert_eq!(&f[..4], &[1, 0, 3, 0]);
        assert_eq!(&f[4..12], &[0, 0, 0, 3, 0, 1, 0x11, 0x70]);
        assert_eq!(decode_response(&f), Some(Ok(r)));
        let mut bad = f;
        bad[4 + 2 * 4 + 3] = 1;
        assert_eq!(decode_response(&bad), None);
        let mut bad = f;
        bad[3] = 1;
        assert_eq!(decode_response(&bad), None);
    }

    /// REPAIR-4・#4847: `ExtractFailed` は oci の全分類で往復し、スロット 0 が未知なら拒否・他の失敗でスロット 0 が非 0 なら拒否。
    #[test]
    fn sec5_4847_extract_failed_carries_the_oci_class() {
        for (code, tag) in [
            (OciErrorCode::InvalidArgument, 1u8),
            (OciErrorCode::Unimplemented, 2),
            (OciErrorCode::Unavailable, 3),
            (OciErrorCode::Timeout, 4),
            (OciErrorCode::PermissionDenied, 5),
            (OciErrorCode::NotFound, 6),
            (OciErrorCode::DataLoss, 7),
            (OciErrorCode::ResourceExhausted, 8),
            (OciErrorCode::FailedPrecondition, 9),
            (OciErrorCode::AlreadyExists, 10),
            (OciErrorCode::Internal, 11),
        ] {
            let e = Err(HelperErrorCode::ExtractFailed(code));
            let f = encode_response(&e);
            assert_eq!(&f[..4], &[1, 1, 12, 0]);
            assert_eq!(f[7], tag);
            assert_eq!(decode_response(&f), Some(e));
        }
        let mut f = encode_response(&Err(HelperErrorCode::ExtractFailed(OciErrorCode::Timeout)));
        f[7] = 0;
        assert_eq!(decode_response(&f), None);
        f[7] = 12;
        assert_eq!(decode_response(&f), None);
        let mut f = encode_response(&Err(HelperErrorCode::Internal));
        f[7] = 4;
        assert_eq!(decode_response(&f), None);
    }
}
