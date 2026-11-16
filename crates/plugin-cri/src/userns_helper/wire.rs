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
//! # 未実装のモード（REPAIR-3）
//! tag 3（Extract。H2。OCI-1・OCI-2・SEC-5）は予約だけで、デコードは [`HelperErrorCode::Unimplemented`] を返す。
//! 実装済みを装わない。
//!
//! # 応答 frame（固定 [`RESPONSE_LEN`] バイト）
//! `[version, status(0 = ok / 1 = error), mode tag（ok）または error tag（error）, flags, u32 BE × 7]`。
//! 未使用のスロットが 0 でない frame は拒否する。エラーの文言は固定語彙で、パス・errno・uid を含めない（REPAIR-4）。

use fandhe_container_core::traits::ErrorCode;

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
/// 予約（H2。Extract）。
const TAG_EXTRACT: u8 = 3;
/// Remove（H3。OCI-7・SEC-5・#4800）。
const TAG_REMOVE: u8 = 4;
/// Remove の payload 長（`[target tag, 0, 0, 0]`）。
const REMOVE_PAYLOAD_LEN: usize = 4;
/// 要求 frame の最大長（header + 現行モードの最大 payload）。
const MAX_FRAME_LEN: usize = REQUEST_HEADER_LEN + REMOVE_PAYLOAD_LEN;

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

/// helper が実行するモード。H2 で足すため `non_exhaustive`。
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
    /// 予約だけで未実装のモード。
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
        }
    }

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
    /// 読むべき payload の長さ（高々 4 バイト。呼び出し側は固定長バッファへ読む）。
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// payload（長さは [`Self::payload_len`] と一致すること）から [`Mode`] を得る。
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
/// tag 3（予約）は [`HelperErrorCode::Unimplemented`]、tag ごとの固定長と合わない長さは `InvalidRequest`。
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
        TAG_EXTRACT => return Err(HelperErrorCode::Unimplemented),
        _ => return Err(HelperErrorCode::InvalidRequest),
    };
    if payload_len != want {
        return Err(HelperErrorCode::InvalidRequest);
    }
    Ok(RequestHead { tag, payload_len })
}

/// 完全な要求 frame（header + payload）を復号する（試験・往復用。helper は 2 段で読む）。
pub fn decode_request(buf: &[u8]) -> Result<Mode, HelperErrorCode> {
    let (header, payload) = buf
        .split_first_chunk::<REQUEST_HEADER_LEN>()
        .ok_or(HelperErrorCode::InvalidRequest)?;
    decode_request_header(header)?.mode(payload)
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
            used_slots = 0;
            if f[3] != 0 {
                return None;
            }
            Err(HelperErrorCode::from_tag(tag)?)
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
            Ok(Mode::Inspect)
        );
        assert_eq!(
            decode_request(encode_request(Mode::StatTarget).as_bytes()),
            Ok(Mode::StatTarget)
        );
    }

    /// SEC-5・OCI-7・REPAIR-2・#4800: Remove の要求は固定 12 バイトで、対象は tag 1 / 2 の具体値で往復する。
    #[test]
    fn sec5_4800_remove_request_roundtrip() {
        let root = encode_request(Mode::Remove(RemoveTarget::BundleRootfs));
        assert_eq!(root.as_bytes(), &[1, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0]);
        assert_eq!(
            decode_request(root.as_bytes()),
            Ok(Mode::Remove(RemoveTarget::BundleRootfs))
        );
        let unpack = encode_request(Mode::Remove(RemoveTarget::PullUnpack));
        assert_eq!(unpack.as_bytes(), &[1, 4, 0, 0, 0, 0, 0, 4, 2, 0, 0, 0]);
        assert_eq!(
            decode_request(unpack.as_bytes()),
            Ok(Mode::Remove(RemoveTarget::PullUnpack))
        );
        assert_eq!(RemoveTarget::BundleRootfs.child_name(), "rootfs");
        assert_eq!(RemoveTarget::PullUnpack.child_name(), "unpack");
        // header だけを先に検査すると、読むべき長さは 4。
        let head = decode_request_header(&[1, 4, 0, 0, 0, 0, 0, 4]).unwrap();
        assert_eq!(head.payload_len(), 4);
    }

    /// SEC-5・REPAIR-2・#4800: Remove の payload は厳密。長さ違い・未知の対象・予約バイト非 0 は `InvalidRequest`、
    /// 上限 + 1 は従来どおり `RequestTooLarge`、tag 3 は `Unimplemented` のまま。
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
            Err(HelperErrorCode::Unimplemented)
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

    /// REPAIR-2・#4795: version・reserved・未知の tag・長さ違いは `InvalidRequest`。tag 3 は `Unimplemented`（tag 4 は payload 必須）。
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
            Err(HelperErrorCode::Unimplemented)
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
        ];
        for (code, name, core) in table {
            assert_eq!(code.as_str(), name);
            assert_eq!(code.core_code(), core);
        }
    }
}
