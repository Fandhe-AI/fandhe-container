//! sandbox・コンテナ記録 1 件分の符号化と厳密な復号（CRI-1・REPAIR-2・REPAIR-4・ERR-3。#2930）。
//!
//! `CriRuntimeService` の `SandboxRegistry` はプロセス内メモリにしか記録を持たないため、plugin-cri の再起動で
//! CRI 層の項目（config・状態・時刻・`resolved_image`・`applied_user`・`stop_signal` 等）が失われる。
//! 設計 `docs/design/cri-record-readoption.md`（#2902）の実装単位 R1 として、記録 1 件分のバイト列を作る
//! 符号化と、壊れた入力・改ざんされた入力を untrusted として拒否する復号を提供する。ファイルの置き場・排他・
//! fsync（R2 #2932）、registry との変換と書く / 消す時点（R4 #2933・R5 #2934）、起動時の再採用（R6 #2935 は実装済みで `readopt` が呼ぶ・
//! R7 #2936）は範囲外で、本モジュールは純粋な関数だけを持つ（ファイル I/O なし）。
//!
//! # 形式 v1
//!
//! 「固定ヘッダ（版の行＋キー順固定のスカラー項目、各行は LF 終端）」と、`config=<長さ>` の行に続く
//! 「長さちょうどの prost 符号化した `PodSandboxConfig` / `ContainerConfig`」から成る。ヘッダは ASCII の
//! キーと、LF 以外の制御文字を含まない UTF-8 の値で、`log_path` など非 ASCII を許す値があるため値は ASCII に
//! 限らない。`ContainerConfig.envs` は記録に書かない（秘密値を状態ルートへ残さない。符号化で消し、復号で非空を拒否）。
//! 版は完全一致のみを受ける。保持役の素性（R11）や `pod_netns`（R12）の鍵を足すときは `v2` とし、旧版の扱いは
//! それぞれの issue で決める。
//!
//! 復号は次のどれかに反する入力を、固定文言の `INVALID_ARGUMENT` で拒否する（メッセージに入力値・長さ・鍵名を
//! 載せない。REPAIR-4）: 版の完全一致・キー順固定・重複キーなし・未知キーなし・余分な行なし・CRLF なし・
//! 整数の正準形・列挙値の固定語彙・記録内 ID とファイル名由来 ID（`expect_id`）の一致・長さの一致。
//! 記録全体・行ごと・config の長さ上限は、確保（prost の復号・`Vec` の確保）の前に確認する。復号後に
//! `RunPodSandbox` / `CreateContainer` と同じ上限検証（`config_limits`）を通す。
//!
//! 呼び出し元になる予定: R2（バイト列の読み書き。上限は [`MAX_SANDBOX_RECORD_BYTES`] /
//! [`MAX_CONTAINER_RECORD_BYTES`]）・R4（sandbox の書く時点。実装済み）・R5（コンテナの書く時点。実装済み）・R6 / R7（起動時の再採用）。

use std::collections::HashSet;

use prost::Message;

use super::config_limits::MAX_CONFIG_ENCODED_BYTES;
use super::container::{ContainerState, validate_container_config};
use super::{
    ContainerRecord, InFlightKind, SUPPORTED_RUNTIME_HANDLERS, SandboxRecord, SandboxState,
    validate_sandbox_config,
};
use crate::adapter::RuntimeTerminationReason;
use crate::bundle::spec::{MAX_ADDITIONAL_GIDS, is_valid_image_reference, is_valid_image_tag};
use crate::bundle::{AppliedUser, ResolvedImage};
use crate::error::CriError;
use crate::image_service::MAX_IMAGE_FIELD_BYTES;
use crate::port_mapping::parse_port_mappings;
use crate::runtime::v1::{ContainerConfig, PodSandboxConfig, Signal};
use fandhe_container_core::traits::{CONTAINER_LOG_PATH_MAX_BYTES, ContainerLogPath};
use fandhe_container_oci::reference::Digest;

const SANDBOX_VERSION_LINE: &str = "fandhe-cri-sandbox-record v1";
const CONTAINER_VERSION_LINE: &str = "fandhe-cri-container-record v1";

/// 版の行・スカラー行の内容の上限（バイト。LF を含まない。最長は `pod_sandbox_id=` + 64 文字の 79）。
const LINE_MAX_SCALAR: usize = 96;
/// `user=` 行の内容の上限: キー 5 + uid(10) + ':' + gid(10) + ':' + 補助 gid（10 桁 + ',' を件数分）。
const LINE_MAX_USER: usize = 5 + 10 + 1 + 10 + 1 + MAX_ADDITIONAL_GIDS * 11;
/// `log_path=` 行の内容の上限。
const LINE_MAX_LOG_PATH: usize = 9 + CONTAINER_LOG_PATH_MAX_BYTES;
/// `image_id=` / `image_ref=` / `image_tag=` 行の内容の上限。
const LINE_MAX_IMAGE_FIELD: usize = 10 + MAX_IMAGE_FIELD_BYTES;

/// sandbox 記録のヘッダ部（`config=` 行を含む）の予算: 版・id・state・created_at・runtime_handler・pending・
/// network_owned・network_pending・config の 9 行（各 LF 込み）。
pub(super) const SANDBOX_HEADER_BUDGET: usize = 9 * (LINE_MAX_SCALAR + 1);
/// コンテナ記録のヘッダ部の予算。スカラー行 14（版・id・pod_sandbox_id・state・in_flight・created_at・
/// started_at・finished_at・exit_code・termination・stop_signal・config の 12 行と余裕 2）と
/// `user`・`log_path`・`image_id`・`image_ref`・`image_tag` の可変行（image_id は digest 文字列で 64 バイトを超える）。
pub(super) const CONTAINER_HEADER_BUDGET: usize = 14 * (LINE_MAX_SCALAR + 1)
    + (LINE_MAX_USER + 1)
    + (LINE_MAX_LOG_PATH + 1)
    + 3 * (LINE_MAX_IMAGE_FIELD + 1);

/// sandbox 記録 1 件の上限（バイト）。R2 は読み込みの前にこの値でファイル長を確認する。
pub(super) const MAX_SANDBOX_RECORD_BYTES: usize = SANDBOX_HEADER_BUDGET + MAX_CONFIG_ENCODED_BYTES;
/// コンテナ記録 1 件の上限（バイト）。
pub(super) const MAX_CONTAINER_RECORD_BYTES: usize =
    CONTAINER_HEADER_BUDGET + MAX_CONFIG_ENCODED_BYTES;

// 上限の計算が想定の範囲（数 MiB）に収まることの固定。
const _: () = assert!(MAX_SANDBOX_RECORD_BYTES < 1024 * 1024);
const _: () = assert!(MAX_CONTAINER_RECORD_BYTES < 4 * 1024 * 1024);
const _: () = assert!(MAX_CONTAINER_RECORD_BYTES > MAX_SANDBOX_RECORD_BYTES);

const SANDBOX_MALFORMED: &str = "sandbox record is malformed";
const CONTAINER_MALFORMED: &str = "container record is malformed";

/// sandbox 記録 1 件分の内容（registry の `SandboxRecord` からの変換は [`Self::from_registry`]。R4 #2933）。
#[derive(Debug, Clone, PartialEq)]
pub(super) struct SandboxRecordData {
    pub(super) id: String,
    pub(super) config: PodSandboxConfig,
    pub(super) state: SandboxState,
    pub(super) created_at_nanos: i64,
    pub(super) runtime_handler: &'static str,
    /// 作成の途中（確定前）を表す印。
    pub(super) pending: bool,
    pub(super) network_owned: bool,
    pub(super) network_pending: bool,
}

/// コンテナ記録 1 件分の内容（registry の `ContainerRecord` との変換は R5 #2934）。
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ContainerRecordData {
    pub(super) id: String,
    pub(super) pod_sandbox_id: String,
    pub(super) config: ContainerConfig,
    pub(super) state: ContainerState,
    /// 実行層を呼び出し中だった操作の種類（再採用の分岐に使う）。
    pub(super) in_flight: Option<InFlightKind>,
    pub(super) created_at_nanos: i64,
    pub(super) started_at_nanos: i64,
    pub(super) finished_at_nanos: i64,
    pub(super) exit_code: Option<i32>,
    pub(super) termination: Option<RuntimeTerminationReason>,
    pub(super) stop_signal: i32,
    pub(super) resolved_log_path: Option<ContainerLogPath>,
    pub(super) applied_user: Option<AppliedUser>,
    pub(super) resolved_image: Option<ResolvedImage>,
}

/// 復号した sandbox 記録と、数え直した config の保持量見積もり。
#[derive(Debug)]
pub(super) struct DecodedSandbox {
    pub(super) data: SandboxRecordData,
    pub(super) retained_bytes: usize,
}

/// 復号したコンテナ記録と、数え直した config の保持量見積もり。
///
/// `applied_user`・`resolved_image` の上乗せ分（`attach_prepared` と同じ計算）は含まない。R7 #2936 が足す。
// R4 / R5 / R6 / R7（#2933〜#2936）が呼ぶまでは本番の経路から呼ばれないスタブ（REPAIR-3）。呼び出しが入ったら外す。
#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct DecodedContainer {
    pub(super) data: ContainerRecordData,
    pub(super) retained_bytes: usize,
}

/// 内部の失敗（外へは固定文言の `INVALID_ARGUMENT` に写し、値を載せない）。
struct Bad;

type R<T> = Result<T, Bad>;

// ---------------------------------------------------------------------------
// 語彙
// ---------------------------------------------------------------------------

fn sandbox_state_token(s: SandboxState) -> &'static str {
    match s {
        SandboxState::Ready => "ready",
        SandboxState::NotReady => "notready",
    }
}

fn parse_sandbox_state(s: &str) -> R<SandboxState> {
    match s {
        "ready" => Ok(SandboxState::Ready),
        "notready" => Ok(SandboxState::NotReady),
        _ => Err(Bad),
    }
}

fn container_state_token(s: ContainerState) -> &'static str {
    match s {
        ContainerState::Created => "created",
        ContainerState::Running => "running",
        ContainerState::Exited => "exited",
        ContainerState::Unknown => "unknown",
    }
}

fn parse_container_state(s: &str) -> R<ContainerState> {
    match s {
        "created" => Ok(ContainerState::Created),
        "running" => Ok(ContainerState::Running),
        "exited" => Ok(ContainerState::Exited),
        "unknown" => Ok(ContainerState::Unknown),
        _ => Err(Bad),
    }
}

fn in_flight_token(k: Option<InFlightKind>) -> &'static str {
    match k {
        None => "-",
        Some(InFlightKind::Create) => "create",
        Some(InFlightKind::Start) => "start",
        Some(InFlightKind::Stop) => "stop",
        Some(InFlightKind::Remove) => "remove",
    }
}

fn parse_in_flight(s: &str) -> R<Option<InFlightKind>> {
    match s {
        "-" => Ok(None),
        "create" => Ok(Some(InFlightKind::Create)),
        "start" => Ok(Some(InFlightKind::Start)),
        "stop" => Ok(Some(InFlightKind::Stop)),
        "remove" => Ok(Some(InFlightKind::Remove)),
        _ => Err(Bad),
    }
}

fn termination_token(t: Option<RuntimeTerminationReason>) -> &'static str {
    match t {
        None => "-",
        Some(RuntimeTerminationReason::OomKilled) => "oom_killed",
    }
}

fn parse_termination(s: &str) -> R<Option<RuntimeTerminationReason>> {
    match s {
        "-" => Ok(None),
        "oom_killed" => Ok(Some(RuntimeTerminationReason::OomKilled)),
        _ => Err(Bad),
    }
}

fn bool_token(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

fn parse_bool(s: &str) -> R<bool> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Bad),
    }
}

// ---------------------------------------------------------------------------
// 正準形の整数・ID
// ---------------------------------------------------------------------------

/// 10 進の符号なし整数の正準形だけを受ける（数字のみ・先頭 0 なし〔`0` 自体は可〕・20 桁まで）。
fn parse_canonical_u64(s: &str) -> R<u64> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 20 || !b.iter().all(u8::is_ascii_digit) {
        return Err(Bad);
    }
    if b.len() > 1 && b.first() == Some(&b'0') {
        return Err(Bad);
    }
    s.parse::<u64>().map_err(|_| Bad)
}

/// 10 進の符号つき整数の正準形（先頭の `-` を 1 つだけ許す。`-0`・`+` は拒否）。
fn parse_canonical_i64(s: &str) -> R<i64> {
    match s.strip_prefix('-') {
        Some(rest) => {
            let v = parse_canonical_u64(rest)?;
            if v == 0 {
                return Err(Bad);
            }
            i64::try_from(-i128::from(v)).map_err(|_| Bad)
        }
        None => i64::try_from(parse_canonical_u64(s)?).map_err(|_| Bad),
    }
}

fn parse_u32(s: &str) -> R<u32> {
    u32::try_from(parse_canonical_u64(s)?).map_err(|_| Bad)
}

fn parse_i32(s: &str) -> R<i32> {
    i32::try_from(parse_canonical_i64(s)?).map_err(|_| Bad)
}

/// 正の i64（`created_at`）。
fn parse_i64_positive(s: &str) -> R<i64> {
    let v = parse_canonical_i64(s)?;
    if v > 0 { Ok(v) } else { Err(Bad) }
}

/// 0 以上の i64（`started_at`・`finished_at`）。
fn parse_i64_non_negative(s: &str) -> R<i64> {
    let v = parse_canonical_i64(s)?;
    if v >= 0 { Ok(v) } else { Err(Bad) }
}

/// `generate_id` の出力と同じ形（64 文字の小文字 16 進）か。
pub(super) fn is_record_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_record_id(s: &str) -> R<&str> {
    if is_record_id(s) { Ok(s) } else { Err(Bad) }
}

/// `-` を `None`、それ以外を `Some` にする（`-` 自体を値に持つ項目はない）。
fn dash_none(s: &str) -> Option<&str> {
    if s == "-" { None } else { Some(s) }
}

/// 値に載せてよい文字だけか（LF を含む制御文字を含まない）。
fn is_clean_value(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

// ---------------------------------------------------------------------------
// 行リーダー
// ---------------------------------------------------------------------------

/// ヘッダを 1 行ずつ読む。各行は LF 終端で、行の上限は読む前に確認する。
struct Lines<'a> {
    rest: &'a [u8],
}

impl<'a> Lines<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// 次の行（LF を除く）を返す。`max` バイト以内に LF が無ければ拒否。CR・制御文字・不正な UTF-8 も拒否。
    fn line(&mut self, max: usize) -> R<&'a str> {
        let limit = max.saturating_add(1).min(self.rest.len());
        let window = self.rest.get(..limit).ok_or(Bad)?;
        let end = window.iter().position(|b| *b == b'\n').ok_or(Bad)?;
        let (line, tail) = self.rest.split_at(end);
        let text = std::str::from_utf8(line).map_err(|_| Bad)?;
        if !is_clean_value(text) {
            return Err(Bad);
        }
        self.rest = tail.get(1..).ok_or(Bad)?;
        Ok(text)
    }

    /// 期待する鍵の行を読み、値を返す。
    fn key(&mut self, key: &str, max: usize) -> R<&'a str> {
        let line = self.line(max)?;
        let value = line.strip_prefix(key).ok_or(Bad)?;
        value.strip_prefix('=').ok_or(Bad)
    }

    /// 版の行の完全一致。
    fn version(&mut self, expected: &str) -> R<()> {
        if self.line(LINE_MAX_SCALAR)? == expected {
            Ok(())
        } else {
            Err(Bad)
        }
    }

    /// `config=<長さ>` の行を読み、残りがちょうどその長さであることを確かめて config 部を返す。
    /// prost の復号はこの後にだけ行う（長さを確認する前に確保しない）。
    fn config_payload(mut self) -> R<&'a [u8]> {
        let len = usize::try_from(parse_canonical_u64(self.key("config", LINE_MAX_SCALAR)?)?)
            .map_err(|_| Bad)?;
        if len > MAX_CONFIG_ENCODED_BYTES || self.rest.len() != len {
            return Err(Bad);
        }
        Ok(self.rest)
    }
}

// ---------------------------------------------------------------------------
// sandbox
// ---------------------------------------------------------------------------

impl SandboxRecordData {
    /// registry の記録 1 件から、ディスクへ書く内容を作る（`CriRuntimeService` が書く時点ごとにロック下で呼ぶ。
    /// R4 #2933）。`network_teardown`・`pod_netns`（R12）・`retained_bytes` は記録に載せない。
    pub(super) fn from_registry(id: &str, record: &SandboxRecord, pending: bool) -> Self {
        Self {
            id: id.to_owned(),
            config: record.config.clone(),
            state: record.state,
            created_at_nanos: record.created_at_nanos,
            runtime_handler: record.runtime_handler,
            pending,
            network_owned: record.network_owned,
            network_pending: record.network_pending,
        }
    }

    /// 記録のバイト列を作る。形式に載せられない値（ID の形式違反・未対応の handler・時刻の範囲外・
    /// config の符号化長超過）は `INTERNAL`（成功を装わない）。
    pub(super) fn encode(&self) -> Result<Vec<u8>, CriError> {
        let fail = || CriError::internal("sandbox record cannot be encoded");
        if !is_record_id(&self.id)
            || self.created_at_nanos <= 0
            || !SUPPORTED_RUNTIME_HANDLERS.contains(&self.runtime_handler)
        {
            return Err(fail());
        }
        if self.config.encoded_len() > MAX_CONFIG_ENCODED_BYTES {
            return Err(fail());
        }
        let payload = self.config.encode_to_vec();
        let header = format!(
            "{SANDBOX_VERSION_LINE}\nid={}\nstate={}\ncreated_at={}\nruntime_handler={}\npending={}\nnetwork_owned={}\nnetwork_pending={}\nconfig={}\n",
            self.id,
            sandbox_state_token(self.state),
            self.created_at_nanos,
            self.runtime_handler,
            bool_token(self.pending),
            bool_token(self.network_owned),
            bool_token(self.network_pending),
            payload.len(),
        );
        assemble(header, &payload, MAX_SANDBOX_RECORD_BYTES).ok_or_else(fail)
    }

    /// 記録のバイト列を厳密に復号する。`expect_id` は記録のファイル名由来の ID。
    /// どの違反も固定文言の `INVALID_ARGUMENT` で、入力値を含めない。
    pub(super) fn decode(bytes: &[u8], expect_id: &str) -> Result<DecodedSandbox, CriError> {
        let malformed = || CriError::invalid_argument(SANDBOX_MALFORMED);
        if bytes.len() > MAX_SANDBOX_RECORD_BYTES {
            return Err(malformed());
        }
        decode_sandbox(bytes, expect_id).map_err(|_| malformed())
    }
}

fn decode_sandbox(bytes: &[u8], expect_id: &str) -> R<DecodedSandbox> {
    let mut l = Lines::new(bytes);
    l.version(SANDBOX_VERSION_LINE)?;
    let id = parse_record_id(l.key("id", LINE_MAX_SCALAR)?)?;
    if id != expect_id {
        return Err(Bad);
    }
    let state = parse_sandbox_state(l.key("state", LINE_MAX_SCALAR)?)?;
    let created_at_nanos = parse_i64_positive(l.key("created_at", LINE_MAX_SCALAR)?)?;
    let handler = l.key("runtime_handler", LINE_MAX_SCALAR)?;
    let runtime_handler = SUPPORTED_RUNTIME_HANDLERS
        .iter()
        .copied()
        .find(|h| *h == handler)
        .ok_or(Bad)?;
    let pending = parse_bool(l.key("pending", LINE_MAX_SCALAR)?)?;
    let network_owned = parse_bool(l.key("network_owned", LINE_MAX_SCALAR)?)?;
    let network_pending = parse_bool(l.key("network_pending", LINE_MAX_SCALAR)?)?;
    let payload = l.config_payload()?;

    let config = PodSandboxConfig::decode(payload).map_err(|_| Bad)?;
    // 未知フィールド・重複フィールドの後勝ち・非正準な符号化（例: bool の 0x02）は、再符号化のバイト列と一致しない。
    // map は BTreeMap（build.rs）で符号化が決定的なため、長さではなくバイト完全一致で判定する。
    if config.encode_to_vec() != payload {
        return Err(Bad);
    }
    // RunPodSandbox と同じ検証（必須項目・config_limits の上限・port_mappings の値）。
    let bounded = validate_sandbox_config(config).map_err(|_| Bad)?;
    parse_port_mappings(bounded.port_mappings()).map_err(|_| Bad)?;
    let retained_bytes = bounded.retained_bytes();
    Ok(DecodedSandbox {
        data: SandboxRecordData {
            id: id.to_owned(),
            config: bounded.into_config(),
            state,
            created_at_nanos,
            runtime_handler,
            pending,
            network_owned,
            network_pending,
        },
        retained_bytes,
    })
}

/// ヘッダと config 部を連結する。全体が上限を超えるなら `None`。
fn assemble(header: String, payload: &[u8], max_total: usize) -> Option<Vec<u8>> {
    let total = header.len().checked_add(payload.len())?;
    if total > max_total {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

// ---------------------------------------------------------------------------
// コンテナ
// ---------------------------------------------------------------------------

fn encode_user(user: &AppliedUser) -> String {
    let gids: Vec<String> = user.additional_gids().iter().map(u32::to_string).collect();
    format!("{}:{}:{}", user.uid(), user.gid(), gids.join(","))
}

fn parse_user(s: &str) -> R<AppliedUser> {
    let mut parts = s.splitn(3, ':');
    let uid = parse_u32(parts.next().ok_or(Bad)?)?;
    let gid = parse_u32(parts.next().ok_or(Bad)?)?;
    let list = parts.next().ok_or(Bad)?;
    let mut gids: Vec<u32> = Vec::new();
    if !list.is_empty() {
        // 件数を区切りの数で確かめてから確保する。
        let count = list.bytes().filter(|b| *b == b',').count() + 1;
        if count > MAX_ADDITIONAL_GIDS {
            return Err(Bad);
        }
        gids.reserve_exact(count);
        let mut seen: HashSet<u32> = HashSet::with_capacity(count);
        for item in list.split(',') {
            let g = parse_u32(item)?;
            if g == u32::MAX || !seen.insert(g) {
                return Err(Bad);
            }
            gids.push(g);
        }
    }
    Ok(AppliedUser::new(uid, gid, gids))
}

/// `stop_signal` が CRI の `Signal` の定義済みの値で、`RUNTIME_DEFAULT` でないか。
fn is_concrete_signal(v: i32) -> bool {
    matches!(Signal::try_from(v), Ok(s) if s != Signal::RuntimeDefault)
}

impl ContainerRecordData {
    /// registry の記録 1 件から、ディスクへ書く内容を作る（`CriRuntimeService` が書く時点ごとに、ロック下で
    /// 複製した記録から呼ぶ。R5 #2934）。`retained_bytes`・`runtime_owned` は記録に載せない
    /// （再採用側が数え直す・core の状態から導く。R7 #2936）。`envs` は [`Self::encode`] が消す。
    pub(super) fn from_registry(
        id: &str,
        record: &ContainerRecord,
        in_flight: Option<InFlightKind>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            pod_sandbox_id: record.pod_sandbox_id.clone(),
            config: record.config.clone(),
            state: record.state,
            in_flight,
            created_at_nanos: record.created_at_nanos,
            started_at_nanos: record.started_at_nanos,
            finished_at_nanos: record.finished_at_nanos,
            exit_code: record.exit_code,
            termination: record.termination,
            stop_signal: record.stop_signal,
            resolved_log_path: record.resolved_log_path.clone(),
            applied_user: record.applied_user.clone(),
            resolved_image: record.resolved_image.clone(),
        }
    }

    /// 記録のバイト列を作る。`config.envs` は複製の側で消してから符号化する（呼び出し元の値は変えない）。
    /// 形式に載せられない値は `INTERNAL`（成功を装わない）。
    pub(super) fn encode(&self) -> Result<Vec<u8>, CriError> {
        let fail = || CriError::internal("container record cannot be encoded");
        if !is_record_id(&self.id)
            || !is_record_id(&self.pod_sandbox_id)
            || self.created_at_nanos <= 0
            || self.started_at_nanos < 0
            || self.finished_at_nanos < 0
            || !is_concrete_signal(self.stop_signal)
        {
            return Err(fail());
        }
        let image = match &self.resolved_image {
            None => ("-".to_owned(), "-".to_owned(), "-".to_owned()),
            Some(img) => (
                img.id_str().to_owned(),
                img.reference().unwrap_or("-").to_owned(),
                img.tag().unwrap_or("-").to_owned(),
            ),
        };
        let user = self
            .applied_user
            .as_ref()
            .map_or_else(|| "-".to_owned(), encode_user);
        let log_path = self
            .resolved_log_path
            .as_ref()
            .map_or("-", ContainerLogPath::as_str);
        let exit_code = self
            .exit_code
            .map_or_else(|| "-".to_owned(), |c| c.to_string());

        let mut config = self.config.clone();
        config.envs.clear();
        if config.encoded_len() > MAX_CONFIG_ENCODED_BYTES {
            return Err(fail());
        }
        let payload = config.encode_to_vec();
        let header = format!(
            "{CONTAINER_VERSION_LINE}\nid={}\npod_sandbox_id={}\nstate={}\nin_flight={}\ncreated_at={}\nstarted_at={}\nfinished_at={}\nexit_code={}\ntermination={}\nstop_signal={}\nlog_path={}\nuser={}\nimage_id={}\nimage_ref={}\nimage_tag={}\nconfig={}\n",
            self.id,
            self.pod_sandbox_id,
            container_state_token(self.state),
            in_flight_token(self.in_flight),
            self.created_at_nanos,
            self.started_at_nanos,
            self.finished_at_nanos,
            exit_code,
            termination_token(self.termination),
            self.stop_signal,
            log_path,
            user,
            image.0,
            image.1,
            image.2,
            payload.len(),
        );
        // 行の上限・制御文字は復号側と同じ規則で自己検査する（読めない記録を書かない）。
        if !header_lines_ok(&header) {
            return Err(fail());
        }
        assemble(header, &payload, MAX_CONTAINER_RECORD_BYTES).ok_or_else(fail)
    }

    /// 記録のバイト列を厳密に復号する。`expect_id` は記録のファイル名由来の ID。
    // R6 / R7（#2935・#2936）の起動時の再採用が呼ぶまでは本番の経路から呼ばれない（REPAIR-3）。
    #[allow(dead_code)]
    pub(super) fn decode(bytes: &[u8], expect_id: &str) -> Result<DecodedContainer, CriError> {
        let malformed = || CriError::invalid_argument(CONTAINER_MALFORMED);
        if bytes.len() > MAX_CONTAINER_RECORD_BYTES {
            return Err(malformed());
        }
        decode_container(bytes, expect_id).map_err(|_| malformed())
    }
}

/// 符号化したヘッダの各行が、復号側の行リーダーの規則（上限・制御文字なし）を満たすか。
fn header_lines_ok(header: &str) -> bool {
    header.split_terminator('\n').all(|line| {
        let max = if line.starts_with("user=") {
            LINE_MAX_USER
        } else if line.starts_with("log_path=") {
            LINE_MAX_LOG_PATH
        } else if line.starts_with("image_id=")
            || line.starts_with("image_ref=")
            || line.starts_with("image_tag=")
        {
            LINE_MAX_IMAGE_FIELD
        } else {
            LINE_MAX_SCALAR
        };
        line.len() <= max && is_clean_value(line)
    })
}

fn decode_container(bytes: &[u8], expect_id: &str) -> R<DecodedContainer> {
    let mut l = Lines::new(bytes);
    l.version(CONTAINER_VERSION_LINE)?;
    let id = parse_record_id(l.key("id", LINE_MAX_SCALAR)?)?;
    if id != expect_id {
        return Err(Bad);
    }
    let pod_sandbox_id = parse_record_id(l.key("pod_sandbox_id", LINE_MAX_SCALAR)?)?;
    let state = parse_container_state(l.key("state", LINE_MAX_SCALAR)?)?;
    let in_flight = parse_in_flight(l.key("in_flight", LINE_MAX_SCALAR)?)?;
    let created_at_nanos = parse_i64_positive(l.key("created_at", LINE_MAX_SCALAR)?)?;
    let started_at_nanos = parse_i64_non_negative(l.key("started_at", LINE_MAX_SCALAR)?)?;
    let finished_at_nanos = parse_i64_non_negative(l.key("finished_at", LINE_MAX_SCALAR)?)?;
    let exit_code = match dash_none(l.key("exit_code", LINE_MAX_SCALAR)?) {
        None => None,
        Some(v) => Some(parse_i32(v)?),
    };
    let termination = parse_termination(l.key("termination", LINE_MAX_SCALAR)?)?;
    let stop_signal = parse_i32(l.key("stop_signal", LINE_MAX_SCALAR)?)?;
    if !is_concrete_signal(stop_signal) {
        return Err(Bad);
    }
    let resolved_log_path = match dash_none(l.key("log_path", LINE_MAX_LOG_PATH)?) {
        None => None,
        Some(v) => Some(ContainerLogPath::new(v).map_err(|_| Bad)?),
    };
    let applied_user = match dash_none(l.key("user", LINE_MAX_USER)?) {
        None => None,
        Some(v) => Some(parse_user(v)?),
    };
    let image_id = dash_none(l.key("image_id", LINE_MAX_IMAGE_FIELD)?);
    let image_ref = dash_none(l.key("image_ref", LINE_MAX_IMAGE_FIELD)?);
    let image_tag = dash_none(l.key("image_tag", LINE_MAX_IMAGE_FIELD)?);
    let resolved_image = match image_id {
        None => {
            if image_ref.is_some() || image_tag.is_some() {
                return Err(Bad);
            }
            None
        }
        Some(raw) => {
            // ResolvedImage::new / with_tag は不正値を黙って落とすため、構築の前に同じ判定で拒否する。
            if image_ref.is_some_and(|r| !is_valid_image_reference(r))
                || image_tag.is_some_and(|t| !is_valid_image_tag(t))
            {
                return Err(Bad);
            }
            let digest = Digest::parse(raw).map_err(|_| Bad)?;
            Some(
                ResolvedImage::new(digest, image_ref.map(str::to_owned))
                    .with_tag(image_tag.map(str::to_owned)),
            )
        }
    };
    let payload = l.config_payload()?;

    let config = ContainerConfig::decode(payload).map_err(|_| Bad)?;
    if config.encode_to_vec() != payload || !config.envs.is_empty() {
        return Err(Bad);
    }
    // CreateContainer と同じ検証（必須項目・config_limits の上限）。
    let bounded = validate_container_config(config).map_err(|_| Bad)?;
    let retained_bytes = bounded.retained_bytes();
    Ok(DecodedContainer {
        data: ContainerRecordData {
            id: id.to_owned(),
            pod_sandbox_id: pod_sandbox_id.to_owned(),
            config: bounded.into_config(),
            state,
            in_flight,
            created_at_nanos,
            started_at_nanos,
            finished_at_nanos,
            exit_code,
            termination,
            stop_signal,
            resolved_log_path,
            applied_user,
            resolved_image,
        },
        retained_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;
    use crate::runtime::v1::{
        ContainerMetadata, DnsConfig, ImageSpec, KeyValue, Mount, PodSandboxMetadata, PortMapping,
    };

    fn id(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn sandbox_config() -> PodSandboxConfig {
        PodSandboxConfig {
            metadata: Some(PodSandboxMetadata {
                name: "pod".into(),
                uid: "uid-1".into(),
                namespace: "ns".into(),
                attempt: 2,
            }),
            hostname: "h".into(),
            labels: std::collections::BTreeMap::from([("app".to_owned(), "web".to_owned())]),
            annotations: std::collections::BTreeMap::from([("note".to_owned(), "x".to_owned())]),
            dns_config: Some(DnsConfig {
                servers: vec!["10.0.0.1".into()],
                searches: vec!["svc.local".into()],
                options: vec![],
            }),
            port_mappings: vec![PortMapping {
                protocol: 0,
                container_port: 80,
                host_port: 8080,
                host_ip: "192.0.2.10".into(),
            }],
            ..Default::default()
        }
    }

    fn sandbox_data() -> SandboxRecordData {
        SandboxRecordData {
            id: id('a'),
            config: sandbox_config(),
            state: SandboxState::NotReady,
            created_at_nanos: 1_700_000_000_123_456_789,
            runtime_handler: "",
            pending: true,
            network_owned: true,
            network_pending: false,
        }
    }

    fn container_config() -> ContainerConfig {
        ContainerConfig {
            metadata: Some(ContainerMetadata {
                name: "c".into(),
                attempt: 1,
            }),
            image: Some(ImageSpec {
                image: "busybox:1.36".into(),
                ..Default::default()
            }),
            command: vec!["/bin/sh".into()],
            args: vec!["-c".into(), "true".into()],
            envs: vec![KeyValue {
                key: "SECRET".into(),
                value: "v".into(),
            }],
            mounts: vec![Mount {
                container_path: "/data".into(),
                host_path: "/srv/data".into(),
                ..Default::default()
            }],
            labels: std::collections::BTreeMap::from([("k".to_owned(), "v".to_owned())]),
            annotations: std::collections::BTreeMap::from([("a".to_owned(), "b".to_owned())]),
            ..Default::default()
        }
    }

    fn digest() -> Digest {
        Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap()
    }

    fn container_data() -> ContainerRecordData {
        ContainerRecordData {
            id: id('b'),
            pod_sandbox_id: id('a'),
            config: container_config(),
            state: ContainerState::Exited,
            in_flight: Some(InFlightKind::Create),
            created_at_nanos: 1_700_000_000_000_000_001,
            started_at_nanos: 1_700_000_000_000_000_002,
            finished_at_nanos: 1_700_000_000_000_000_003,
            exit_code: Some(-137),
            termination: Some(RuntimeTerminationReason::OomKilled),
            stop_signal: Signal::Sigkill as i32,
            resolved_log_path: Some(
                ContainerLogPath::new("/var/log/pods/ns_p_uid/c/0.log").unwrap(),
            ),
            applied_user: Some(AppliedUser::new(1000, 1000, vec![2000, 3000])),
            resolved_image: Some(
                ResolvedImage::new(
                    digest(),
                    Some(format!("busybox@sha256:{}", "ab".repeat(32))),
                )
                .with_tag(Some("busybox:1.36".into())),
            ),
        }
    }

    fn min_container() -> ContainerRecordData {
        ContainerRecordData {
            in_flight: None,
            exit_code: None,
            termination: None,
            resolved_log_path: None,
            applied_user: None,
            resolved_image: None,
            ..container_data()
        }
    }

    fn assert_sandbox_rejected(bytes: &[u8], marker: &str) {
        let e = SandboxRecordData::decode(bytes, &id('a')).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), SANDBOX_MALFORMED);
        assert!(!e.message().contains(marker));
    }

    fn assert_container_rejected(bytes: &[u8]) {
        let e = ContainerRecordData::decode(bytes, &id('b')).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), CONTAINER_MALFORMED);
    }

    /// ヘッダ内の 1 つの置換を施したコンテナ記録を返す。
    fn container_with(from: &str, to: &str) -> Vec<u8> {
        let bytes = container_data().encode().unwrap();
        let text =
            String::from_utf8_lossy(&bytes[..bytes.len() - payload_len(&bytes)]).into_owned();
        assert!(text.contains(from), "fixture lacks {from:?}");
        let mut out = text.replacen(from, to, 1).into_bytes();
        out.extend_from_slice(&bytes[bytes.len() - payload_len(&bytes)..]);
        out
    }

    fn payload_len(bytes: &[u8]) -> usize {
        let text = String::from_utf8_lossy(bytes);
        let line = text.lines().find(|l| l.starts_with("config=")).unwrap();
        line["config=".len()..].parse().unwrap()
    }

    fn sandbox_with(from: &str, to: &str) -> Vec<u8> {
        let bytes = sandbox_data().encode().unwrap();
        let n = payload_len(&bytes);
        let head = String::from_utf8_lossy(&bytes[..bytes.len() - n]).into_owned();
        assert!(head.contains(from), "fixture lacks {from:?}");
        let mut out = head.replacen(from, to, 1).into_bytes();
        out.extend_from_slice(&bytes[bytes.len() - n..]);
        out
    }

    #[test]
    fn cri1_repair2_sandbox_roundtrip() {
        let data = sandbox_data();
        let bytes = data.encode().unwrap();
        let got = SandboxRecordData::decode(&bytes, &data.id).unwrap();
        assert_eq!(got.data, data);
        let expected = validate_sandbox_config(sandbox_config())
            .unwrap()
            .retained_bytes();
        assert_eq!(got.retained_bytes, expected);
    }

    #[test]
    fn cri1_repair2_sandbox_header_is_fixed_text() {
        let bytes = sandbox_data().encode().unwrap();
        let n = payload_len(&bytes);
        let head = std::str::from_utf8(&bytes[..bytes.len() - n]).unwrap();
        let expected = format!(
            "fandhe-cri-sandbox-record v1\nid={}\nstate=notready\ncreated_at=1700000000123456789\nruntime_handler=\npending=1\nnetwork_owned=1\nnetwork_pending=0\nconfig={n}\n",
            id('a')
        );
        assert_eq!(head, expected);
    }

    #[test]
    fn cri1_repair2_container_roundtrip_drops_envs() {
        let data = container_data();
        let bytes = data.encode().unwrap();
        assert!(!bytes.windows(6).any(|w| w == b"SECRET"));
        let got = ContainerRecordData::decode(&bytes, &data.id).unwrap();
        let mut expected = data.clone();
        expected.config.envs.clear();
        assert_eq!(got.data, expected);
        assert_eq!(got.data.exit_code, Some(-137));
        assert_eq!(got.data.stop_signal, Signal::Sigkill as i32);
        assert_eq!(
            got.data.applied_user.as_ref().unwrap().additional_gids(),
            &[2000, 3000]
        );
        let mut bounded = container_config();
        bounded.envs.clear();
        assert_eq!(
            got.retained_bytes,
            validate_container_config(bounded).unwrap().retained_bytes()
        );
        // 呼び出し元の値は変えない。
        assert_eq!(data.config.envs.len(), 1);
    }

    #[test]
    fn cri1_repair2_container_header_is_fixed_text() {
        let bytes = container_data().encode().unwrap();
        let n = payload_len(&bytes);
        let head = std::str::from_utf8(&bytes[..bytes.len() - n]).unwrap();
        let hex = "ab".repeat(32);
        let expected = format!(
            "fandhe-cri-container-record v1\nid={}\npod_sandbox_id={}\nstate=exited\nin_flight=create\ncreated_at=1700000000000000001\nstarted_at=1700000000000000002\nfinished_at=1700000000000000003\nexit_code=-137\ntermination=oom_killed\nstop_signal=13\nlog_path=/var/log/pods/ns_p_uid/c/0.log\nuser=1000:1000:2000,3000\nimage_id=sha256:{hex}\nimage_ref=busybox@sha256:{hex}\nimage_tag=busybox:1.36\nconfig={n}\n",
            id('b'),
            id('a'),
        );
        assert_eq!(head, expected);
    }

    #[test]
    fn cri1_repair2_container_minimal_forms_roundtrip() {
        let data = min_container();
        let bytes = data.encode().unwrap();
        let mut expected = data.clone();
        expected.config.envs.clear();
        assert_eq!(
            ContainerRecordData::decode(&bytes, &data.id).unwrap().data,
            expected
        );

        let mut no_groups = min_container();
        no_groups.applied_user = Some(AppliedUser::new(1000, 1000, vec![]));
        let bytes = no_groups.encode().unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\nuser=1000:1000:\n"));
        let got = ContainerRecordData::decode(&bytes, &no_groups.id).unwrap();
        assert_eq!(got.data.applied_user, no_groups.applied_user);

        let mut unicode = min_container();
        unicode.resolved_log_path =
            Some(ContainerLogPath::new("/var/log/pods/名前/c/0.log").unwrap());
        let bytes = unicode.encode().unwrap();
        let got = ContainerRecordData::decode(&bytes, &unicode.id).unwrap();
        assert_eq!(got.data.resolved_log_path, unicode.resolved_log_path);
    }

    #[test]
    fn cri1_repair2_sandbox_rejects_header_violations() {
        let secret = "SECRETMARK";
        for (from, to) in [
            ("record v1\n", "record v2\n"),
            ("record v1\n", "record v1 \n"),
            ("state=notready\n", "state=NOTREADY\n"),
            ("state=notready\n", "state=bogus\n"),
            ("pending=1\n", "pending=2\n"),
            ("created_at=1700000000123456789", "created_at=0"),
            ("created_at=1700000000123456789", "created_at=+5"),
            ("created_at=1700000000123456789", "created_at=01"),
            (
                "created_at=1700000000123456789",
                "created_at=99999999999999999999",
            ),
            ("runtime_handler=\n", "runtime_handler=kata\n"),
            ("pending=1\n", "pending=1\r\n"),
            ("pending=1\n", "pending=1\0\n"),
            ("pending=1\n", "pending=1\x07\n"),
            // 順序の入れ替え・重複・未知キー・欠落・余分な行
            (
                "state=notready\ncreated_at=",
                "created_at=1\nstate=notready\nx=",
            ),
            ("pending=1\n", "pending=1\npending=1\n"),
            ("pending=1\n", "pending=1\nextra=SECRETMARK\n"),
            ("pending=1\n", ""),
            ("config=", "extra=1\nconfig="),
        ] {
            assert_sandbox_rejected(&sandbox_with(from, to), secret);
        }
    }

    #[test]
    fn cri1_repair2_sandbox_rejects_id_mismatch_and_bad_ids() {
        let bytes = sandbox_data().encode().unwrap();
        assert!(SandboxRecordData::decode(&bytes, &id('c')).is_err());
        let a = id('a');
        for bad in [&a[..63], &a.to_uppercase()[..]] {
            let b = sandbox_with(&format!("id={a}"), &format!("id={bad}"));
            let e = SandboxRecordData::decode(&b, bad).unwrap_err();
            assert_eq!(e.message(), SANDBOX_MALFORMED);
        }
    }

    #[test]
    fn cri1_repair2_sandbox_rejects_length_violations() {
        let bytes = sandbox_data().encode().unwrap();
        let n = payload_len(&bytes);
        // 長さが実際より短い・長い・後ろに余分なバイト
        let short = sandbox_with(&format!("config={n}"), &format!("config={}", n - 1));
        assert_sandbox_rejected(&short, "SECRETMARK");
        let long = sandbox_with(&format!("config={n}"), &format!("config={}", n + 1));
        assert_sandbox_rejected(&long, "SECRETMARK");
        let mut extra = bytes.clone();
        extra.push(0);
        assert_sandbox_rejected(&extra, "SECRETMARK");
        // config の上限 + 1 は残りの長さ照合の前に拒否される。
        let over = sandbox_with(
            &format!("config={n}"),
            &format!("config={}", MAX_CONFIG_ENCODED_BYTES + 1),
        );
        assert_sandbox_rejected(&over, "SECRETMARK");
        // 記録全体の上限 + 1 は、中身を読む前に拒否される。
        let huge = vec![b'x'; MAX_SANDBOX_RECORD_BYTES + 1];
        let start = std::time::Instant::now();
        assert_sandbox_rejected(&huge, "SECRETMARK");
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        // LF の無い長い行
        let mut no_lf = SANDBOX_VERSION_LINE.as_bytes().to_vec();
        no_lf.extend(std::iter::repeat_n(b'x', 1000));
        assert_sandbox_rejected(&no_lf, "SECRETMARK");
        assert_sandbox_rejected(b"", "SECRETMARK");
    }

    #[test]
    fn cri1_repair2_container_rejects_noncanonical_bool_wire_value() {
        // 長さを変えない非正準表現（bool true の 0x01 を 0x02）も拒否する（バイト完全一致の判定）。
        let mut data = container_data();
        data.config.stdin = true;
        let mut bytes = data.encode().unwrap();
        let pos = bytes
            .windows(2)
            .rposition(|w| w == [0x60, 0x01])
            .expect("stdin field");
        bytes[pos + 1] = 0x02;
        assert_container_rejected(&bytes);
    }

    #[test]
    fn cri1_repair2_multi_label_config_roundtrips_and_dash_tag_is_not_kept() {
        let mut data = container_data();
        for i in 0..8 {
            data.config.labels.insert(format!("k{i}"), format!("v{i}"));
            data.config.annotations.insert(format!("a{i}"), "x".into());
        }
        let decoded = ContainerRecordData::decode(&data.encode().unwrap(), &id('b')).unwrap();
        assert_eq!(decoded.data.config.labels, data.config.labels);
        assert_eq!(decoded.data.config.annotations, data.config.annotations);
        // "-" はタグ無しのセンチネルと衝突するため、タグとして受けない。
        let img = ResolvedImage::new(digest(), None).with_tag(Some("-".into()));
        assert_eq!(img.tag(), None);
        assert!(!is_valid_image_tag("-"));
    }

    #[test]
    fn cri1_repair2_sandbox_rejects_bad_config_payload() {
        let good = sandbox_data().encode().unwrap();
        let n = payload_len(&good);
        let head_len = good.len() - n;

        // prost として壊れている
        let mut broken = good[..head_len].to_vec();
        broken.extend(std::iter::repeat_n(0xFFu8, n));
        assert_sandbox_rejected(&broken, "SECRETMARK");

        // 未知フィールド番号を足した config（encoded_len の不一致）
        let mut payload = good[head_len..].to_vec();
        payload.extend_from_slice(&[0xF8, 0x7F, 0x01]); // field 2047, varint 1
        let head = String::from_utf8(good[..head_len].to_vec())
            .unwrap()
            .replacen(
                &format!("config={n}"),
                &format!("config={}", payload.len()),
                1,
            );
        let mut unknown = head.into_bytes();
        unknown.extend_from_slice(&payload);
        assert_sandbox_rejected(&unknown, "SECRETMARK");

        // 再適用される検証: metadata なし・name 空・annotations の件数超過・port_mappings 不正
        let mut cases: Vec<PodSandboxConfig> = Vec::new();
        cases.push(PodSandboxConfig {
            metadata: None,
            ..sandbox_config()
        });
        let mut c = sandbox_config();
        c.metadata.as_mut().unwrap().name.clear();
        cases.push(c);
        let mut c = sandbox_config();
        for i in 0..=super::super::config_limits::MAX_CONFIG_COLLECTION_ENTRIES {
            c.annotations.insert(format!("k{i}"), "v".into());
        }
        cases.push(c);
        let mut c = sandbox_config();
        c.port_mappings[0].container_port = 0;
        c.port_mappings[0].host_port = 70_000;
        cases.push(c);
        for cfg in cases {
            let mut data = sandbox_data();
            data.config = cfg;
            if let Ok(bytes) = data.encode() {
                assert_sandbox_rejected(&bytes, "SECRETMARK");
            }
        }
    }

    #[test]
    fn cri1_repair2_sandbox_encode_refuses_unrecordable_values() {
        let mut d = sandbox_data();
        d.id = "short".into();
        assert_eq!(d.encode().unwrap_err().code(), CriErrorCode::Internal);
        let mut d = sandbox_data();
        d.created_at_nanos = 0;
        assert!(d.encode().is_err());
        let mut d = sandbox_data();
        d.runtime_handler = "kata";
        assert!(d.encode().is_err());
    }

    #[test]
    fn cri1_repair2_container_rejects_header_violations() {
        for (from, to) in [
            ("record v1\n", "record v2\n"),
            ("state=exited\n", "state=Exited\n"),
            ("state=exited\n", "state=gone\n"),
            ("in_flight=create\n", "in_flight=bogus\n"),
            ("termination=oom_killed\n", "termination=other\n"),
            ("exit_code=-137", "exit_code=-0"),
            ("exit_code=-137", "exit_code=+1"),
            ("exit_code=-137", "exit_code=2147483648"),
            ("exit_code=-137", "exit_code=-2147483649"),
            ("started_at=1700000000000000002", "started_at=-1"),
            ("created_at=1700000000000000001", "created_at=0"),
            ("stop_signal=13", "stop_signal=0"),
            ("stop_signal=13", "stop_signal=99999"),
            ("stop_signal=13", "stop_signal=09"),
            (
                "log_path=/var/log/pods/ns_p_uid/c/0.log",
                "log_path=var/log",
            ),
            (
                "log_path=/var/log/pods/ns_p_uid/c/0.log",
                "log_path=/var/../log",
            ),
            ("user=1000:1000:2000,3000", "user=1000:1000:2000,2000"),
            ("user=1000:1000:2000,3000", "user=1000:1000:4294967295"),
            ("user=1000:1000:2000,3000", "user=1000:1000"),
            ("user=1000:1000:2000,3000", "user=01000:1000:"),
            ("image_ref=busybox@", "image_ref=busybox#"),
            ("image_tag=busybox:1.36", "image_tag=busybox@x"),
            ("image_tag=busybox:1.36", "image_tag=\x01"),
            ("image_id=sha256:", "image_id=md5:"),
            ("pod_sandbox_id=", "pod_sandbox_id=Z"),
            ("pod_sandbox_id=", "unknown=1\npod_sandbox_id="),
            (
                "state=exited\nin_flight=create\n",
                "in_flight=create\nstate=exited\n",
            ),
            ("stop_signal=13\n", "stop_signal=13\r\n"),
        ] {
            assert_container_rejected(&container_with(from, to));
        }
    }

    #[test]
    fn cri1_repair2_container_rejects_image_dependencies() {
        let mut d = min_container();
        d.resolved_image = Some(ResolvedImage::new(digest(), None));
        let bytes = d.encode().unwrap();
        assert!(ContainerRecordData::decode(&bytes, &d.id).is_ok());
        // image_id が無いのに ref がある
        let text = String::from_utf8_lossy(&bytes).replacen(
            &format!("image_id=sha256:{}\nimage_ref=-", "ab".repeat(32)),
            "image_id=-\nimage_ref=a@b",
            1,
        );
        assert_container_rejected(text.as_bytes());
    }

    #[test]
    fn cri1_repair2_container_rejects_config_violations() {
        let good = container_data().encode().unwrap();
        let n = payload_len(&good);
        let head_len = good.len() - n;
        let rebuild = |payload: &[u8]| -> Vec<u8> {
            let head = String::from_utf8(good[..head_len].to_vec())
                .unwrap()
                .replacen(
                    &format!("config={n}"),
                    &format!("config={}", payload.len()),
                    1,
                );
            let mut out = head.into_bytes();
            out.extend_from_slice(payload);
            out
        };

        // envs が空でない config（作る側は必ず空にする）
        assert_container_rejected(&rebuild(&container_config().encode_to_vec()));
        // 未知フィールド
        let mut cfg = container_config();
        cfg.envs.clear();
        let mut p = cfg.encode_to_vec();
        p.extend_from_slice(&[0xF8, 0x7F, 0x01]);
        assert_container_rejected(&rebuild(&p));
        // 壊れた prost
        assert_container_rejected(&rebuild(&[0xFFu8; 16]));
        // 必須項目・上限の再適用
        let mut c = container_config();
        c.envs.clear();
        c.metadata = None;
        assert_container_rejected(&rebuild(&c.encode_to_vec()));
        let mut c = container_config();
        c.envs.clear();
        c.image = Some(ImageSpec::default());
        assert_container_rejected(&rebuild(&c.encode_to_vec()));
        let mut c = container_config();
        c.envs.clear();
        for i in 0..=super::super::config_limits::MAX_CONFIG_COLLECTION_ENTRIES {
            c.annotations.insert(format!("k{i}"), "v".into());
        }
        assert_container_rejected(&rebuild(&c.encode_to_vec()));
        // 上限
        let over = String::from_utf8(good[..head_len].to_vec())
            .unwrap()
            .replacen(
                &format!("config={n}"),
                &format!("config={}", MAX_CONFIG_ENCODED_BYTES + 1),
                1,
            );
        let mut b = over.into_bytes();
        b.extend_from_slice(&good[head_len..]);
        assert_container_rejected(&b);
        assert_container_rejected(&vec![b'x'; MAX_CONTAINER_RECORD_BYTES + 1]);
    }

    #[test]
    fn cri1_repair2_container_rejects_too_many_gids_before_allocating() {
        let list = (0..=MAX_ADDITIONAL_GIDS as u32)
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let text = String::from_utf8_lossy(&container_data().encode().unwrap()).into_owned();
        let _ = text;
        assert_container_rejected(&container_with(
            "user=1000:1000:2000,3000",
            &format!("user=1000:1000:{list}"),
        ));
    }

    #[test]
    fn cri1_repair2_container_encode_refuses_unrecordable_values() {
        let mut d = container_data();
        d.stop_signal = 0;
        assert_eq!(d.encode().unwrap_err().code(), CriErrorCode::Internal);
        let mut d = container_data();
        d.pod_sandbox_id = "x".into();
        assert!(d.encode().is_err());
        let mut d = container_data();
        d.started_at_nanos = -1;
        assert!(d.encode().is_err());
    }

    #[test]
    fn cri1_repair2_canonical_integers() {
        assert_eq!(parse_canonical_u64("0").ok(), Some(0));
        assert!(parse_canonical_u64("").is_err());
        assert!(parse_canonical_u64("00").is_err());
        assert!(parse_canonical_u64("1_0").is_err());
        assert!(parse_canonical_u64("123456789012345678901").is_err());
        assert_eq!(parse_canonical_i64("-5").ok(), Some(-5));
        assert!(parse_canonical_i64("-0").is_err());
        assert!(parse_canonical_i64("--1").is_err());
        assert!(parse_canonical_i64("9223372036854775808").is_err());
        assert_eq!(
            parse_canonical_i64("-9223372036854775808").ok(),
            Some(i64::MIN)
        );
    }
}
