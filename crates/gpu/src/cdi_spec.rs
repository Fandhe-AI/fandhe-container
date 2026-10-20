//! CDI spec（Container Device Interface）の YAML / JSON 読み込み基盤（TASK-126.1・GPU-1・MS-10）。
//!
//! NVIDIA Container Toolkit が生成する `/var/run/cdi/nvidia.yaml` 等を型付き構造体 [`CdiSpec`] へ
//! デシリアライズするだけの層で、`fandhe-container-gpu` の他モジュール（TASK-126.2 の集計、
//! TASK-126.3 の usr-merge パス正規化、TASK-127 以降の edits 適用）から入力として使われる。
//!
//! 責務境界（将来仕様。REPAIR-3）:
//! - 本モジュールは構文・型・未知フィールド・重複キー・資源上限の検査までを行う。
//!   `cdiVersion` / `kind` / `name` の形式検査、パスの絶対性、`hookName` の許可値などの意味検証は行わない
//!   （TASK-126.2 以降・TASK-127 の責務）。値は保持するだけで、パスやコマンドの組み立てはしない。
//! - `/var/run/cdi` の所有者・権限の検証、ディレクトリ走査、名前から spec への解決は後続タスクで扱う。解決済みの
//!   (spec, 名前) の列の集計は `cdi_edits::aggregate_container_edits_across_specs`（TASK-126.2・GPU-1）が担う。
//! - 未知フィールドは全構造体で拒否する（fail-closed）。将来の CDI 版で増えたフィールドを受けるには
//!   本モジュールの型を拡張する。
//!
//! 外部入力の扱い（`security.md`・`coding-rust.md`）: 入力バイト長を先に検証し、`serde-saphyr` の
//! `Budget` を明示して深さ・ノード数・エイリアス展開を締める。エラーの `message` と `Debug` 出力には
//! YAML の内容（とくに `env` の値。トークン等を含みうる）を載せない。

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};

/// 読み込みを許す CDI spec の最大バイト数（1 MiB）。実際の nvidia.yaml は数十 KiB 程度。
pub const CDI_SPEC_MAX_INPUT_BYTES: usize = 1024 * 1024;

/// YAML の最大ネスト深さ。CDI spec の実際の深さは 7 程度。
const CDI_SPEC_MAX_DEPTH: usize = 16;
/// YAML の最大ノード数。
const CDI_SPEC_MAX_NODES: usize = 100_000;
/// YAML パーサの最大イベント数。
const CDI_SPEC_MAX_EVENTS: usize = 400_000;
/// エイリアス・アンカーの上限。CDI spec は通常アンカーを使わないため小さく締める。
const CDI_SPEC_MAX_ALIASES: usize = 64;
/// `CdiSpecError` の `message` の最大バイト数。
const CDI_SPEC_ERROR_MESSAGE_MAX_BYTES: usize = 512;

/// `CdiSpecError` の機械可読な分類（ERR-1。文字列は他 crate の `code` と揃える）。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CdiSpecErrorCode {
    /// 構文・型・必須欠落・未知フィールド・重複キー。
    InvalidArgument,
    /// 入力サイズ・深さ・ノード数・エイリアス展開などの上限超過、または集計で要求したデバイス名の
    /// 件数・長さの上限超過。
    ResourceExhausted,
    /// spec ファイルが存在しない、または集計で指定したデバイスが spec に無い。
    NotFound,
    /// 上記以外（読み取り失敗など）。
    Internal,
}

impl CdiSpecErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::NotFound => "NOT_FOUND",
            Self::Internal => "INTERNAL",
        }
    }
}

/// CDI spec 読み込みのエラー（`code`・英語の `message`・任意の行列位置）。
///
/// `message` は固定文言と行・列だけで組み立て、入力 YAML の内容を含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiSpecError {
    code: CdiSpecErrorCode,
    message: String,
    line: Option<u64>,
    column: Option<u64>,
}

impl CdiSpecError {
    pub(crate) fn new(code: CdiSpecErrorCode, message: &str) -> Self {
        let mut sanitized: String = message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if sanitized.len() > CDI_SPEC_ERROR_MESSAGE_MAX_BYTES {
            let mut end = CDI_SPEC_ERROR_MESSAGE_MAX_BYTES;
            while !sanitized.is_char_boundary(end) {
                end -= 1;
            }
            sanitized.truncate(end);
        }
        Self {
            code,
            message: sanitized,
            line: None,
            column: None,
        }
    }

    fn with_location(mut self, line: u64, column: u64) -> Self {
        self.line = Some(line);
        self.column = Some(column);
        self
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> CdiSpecErrorCode {
        self.code
    }

    /// 英語のメッセージを返す（入力 YAML の内容は含まない）。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// 問題の行（1 始まり）。取得できない場合は `None`。
    pub fn line(&self) -> Option<u64> {
        self.line
    }

    /// 問題の列（1 始まり）。取得できない場合は `None`。
    pub fn column(&self) -> Option<u64> {
        self.column
    }
}

impl fmt::Display for CdiSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for CdiSpecError {}

/// 値を `Debug` に出さない環境変数リスト（`KEY=VALUE` 形式の文字列の配列）。
///
/// CDI の `env` はトークン等を含みうるため、ログやテスト失敗出力への漏洩を避けて件数だけを表示する。
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct EnvList(Vec<String>);

impl EnvList {
    /// 集計結果（`cdi_edits`。TASK-126.2）から `EnvList` を組み立てる。
    pub(crate) fn from_entries(entries: Vec<String>) -> Self {
        Self(entries)
    }

    /// `KEY=VALUE` 形式の文字列を順に返す。
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }

    /// 要素数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空かどうか。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for EnvList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvList(<{} entries redacted>)", self.0.len())
    }
}

/// CDI spec のトップレベル（CDI v0.7.0 のフィールド集合。GPU-1）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CdiSpec {
    /// `cdiVersion`（値の検証は TASK-126.2 以降）。
    pub cdi_version: String,
    /// `kind`（`vendor/class`。形式検査は TASK-126.2 以降）。
    pub kind: String,
    /// 任意の注釈。
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// デバイス定義。
    #[serde(default)]
    pub devices: Vec<CdiDevice>,
    /// 全デバイス共通の edits（集計は TASK-126.2）。
    #[serde(default)]
    pub container_edits: ContainerEdits,
}

/// CDI のデバイス 1 件。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CdiDevice {
    /// デバイス名（文字種の検証は TASK-126.2 以降）。
    pub name: String,
    /// 任意の注釈。
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// このデバイスに対する edits。
    pub container_edits: ContainerEdits,
}

/// OCI spec への編集内容（適用は TASK-127 以降。本層は保持のみ）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEdits {
    /// 環境変数（値は `Debug` に出ない）。
    #[serde(default)]
    pub env: EnvList,
    /// デバイスノード。
    #[serde(default)]
    pub device_nodes: Vec<DeviceNode>,
    /// フック。
    #[serde(default)]
    pub hooks: Vec<Hook>,
    /// マウント。
    #[serde(default)]
    pub mounts: Vec<Mount>,
    /// Intel RDT 設定。
    #[serde(default)]
    pub intel_rdt: Option<IntelRdt>,
    /// 追加 GID。
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

/// デバイスノード定義。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceNode {
    /// コンテナ内パス（絶対性の検証は TASK-127 以降）。
    pub path: String,
    /// ホスト側パス。
    #[serde(default)]
    pub host_path: Option<String>,
    /// ノード種別（`c` / `b` / `u` / `p`。許可値の検証は後続）。
    #[serde(default, rename = "type")]
    pub r#type: Option<String>,
    /// メジャー番号。
    #[serde(default)]
    pub major: Option<i64>,
    /// マイナー番号。
    #[serde(default)]
    pub minor: Option<i64>,
    /// ファイルモード。
    #[serde(default)]
    pub file_mode: Option<u32>,
    /// cgroup device の権限（`rwm` の部分集合）。
    #[serde(default)]
    pub permissions: Option<String>,
    /// 所有 UID。
    #[serde(default)]
    pub uid: Option<u32>,
    /// 所有 GID。
    #[serde(default)]
    pub gid: Option<u32>,
}

/// OCI フック定義。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hook {
    /// フック名（許可値の検証は後続）。
    pub hook_name: String,
    /// 実行ファイルのパス。
    pub path: String,
    /// 引数。
    #[serde(default)]
    pub args: Vec<String>,
    /// 環境変数（値は `Debug` に出ない）。
    #[serde(default)]
    pub env: EnvList,
    /// タイムアウト秒。
    #[serde(default)]
    pub timeout: Option<i64>,
}

/// マウント定義。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mount {
    /// ホスト側パス。
    pub host_path: String,
    /// コンテナ内パス。
    pub container_path: String,
    /// マウントオプション。
    #[serde(default)]
    pub options: Vec<String>,
    /// マウント種別。
    #[serde(default, rename = "type")]
    pub r#type: Option<String>,
}

/// Intel RDT 設定。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelRdt {
    /// `closID`。
    #[serde(default, rename = "closID")]
    pub clos_id: Option<String>,
    /// L3 キャッシュスキーマ。
    #[serde(default)]
    pub l3_cache_schema: Option<String>,
    /// メモリ帯域スキーマ。
    #[serde(default)]
    pub mem_bw_schema: Option<String>,
    /// CMT の有効化。
    #[serde(default, rename = "enableCMT")]
    pub enable_cmt: Option<bool>,
    /// MBM の有効化。
    #[serde(default, rename = "enableMBM")]
    pub enable_mbm: Option<bool>,
}

/// `serde-saphyr` のエラーを、入力内容を含まない固定文言の [`CdiSpecError`] へ写す。
fn classify(err: &serde_saphyr::Error) -> CdiSpecError {
    use serde_saphyr::Error as E;
    let (code, msg) = match err {
        E::Budget { .. }
        | E::AliasReplayLimitExceeded { .. }
        | E::AliasExpansionLimitExceeded { .. }
        | E::AliasReplayStackDepthExceeded { .. } => (
            CdiSpecErrorCode::ResourceExhausted,
            "CDI spec exceeds a parser resource limit",
        ),
        E::DuplicateMappingKey { .. } => (
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec has a duplicate mapping key",
        ),
        E::SerdeUnknownField { .. } => (
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec has an unknown field",
        ),
        E::SerdeMissingField { .. } => (
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec is missing a required field",
        ),
        E::SerdeInvalidType { .. } | E::SerdeInvalidValue { .. } | E::InvalidScalar { .. } => (
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec has a value of an unexpected type",
        ),
        _ => (
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec is not valid YAML or does not match the schema",
        ),
    };
    let e = CdiSpecError::new(code, msg);
    match err.location() {
        Some(loc) => e.with_location(loc.line(), loc.column()),
        None => e,
    }
}

/// YAML（または JSON）文字列から [`CdiSpec`] を読む。
///
/// 入力長が [`CDI_SPEC_MAX_INPUT_BYTES`] を超えれば `ResourceExhausted`。`Budget` を明示し、
/// 重複キー・マージキーは拒否する。パニックしない。
pub fn parse_cdi_spec(input: &str) -> Result<CdiSpec, CdiSpecError> {
    if input.len() > CDI_SPEC_MAX_INPUT_BYTES {
        return Err(CdiSpecError::new(
            CdiSpecErrorCode::ResourceExhausted,
            "CDI spec input is too large",
        ));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = CDI_SPEC_MAX_DEPTH;
    budget.max_nodes = CDI_SPEC_MAX_NODES;
    budget.max_events = CDI_SPEC_MAX_EVENTS;
    budget.max_aliases = CDI_SPEC_MAX_ALIASES;
    budget.max_anchors = CDI_SPEC_MAX_ALIASES;
    budget.max_documents = 1;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Error;
    // エラーにソース断片（env の値を含みうる）を付けさせない。
    options.with_snippet = false;
    options.emit_comments = false;
    serde_saphyr::from_str_with_options::<CdiSpec>(input, options).map_err(|e| classify(&e))
}

/// 読み込み 1 回の計測結果（REPAIR-4）。入力内容・パス・`env` の値は持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiSpecReadSample {
    /// 成功なら `None`、失敗なら分類。
    error_code: Option<CdiSpecErrorCode>,
    /// open から解析完了（または失敗）までの所要時間。
    latency: Duration,
}

impl CdiSpecReadSample {
    /// 成功したか。
    pub fn is_success(&self) -> bool {
        self.error_code.is_none()
    }

    /// 失敗時の分類（成功なら `None`）。
    pub fn error_code(&self) -> Option<CdiSpecErrorCode> {
        self.error_code
    }

    /// 所要時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// [`read_cdi_spec_file_with_recorder`] の計測先（REPAIR-4）。
///
/// 上位 crate が core の `OpRecorder` 等へ写すアダプタを実装する（gpu は core に依存しない）。
/// 成功・open 失敗・種別拒否・read 失敗・UTF-8 失敗・解析失敗のすべてで 1 回だけ呼ばれる。
pub trait CdiSpecReadRecorder {
    /// 1 回の読み込み結果を記録する。
    fn record(&self, sample: CdiSpecReadSample);
}

/// 何も記録しない記録先。
struct NoopRecorder;

impl CdiSpecReadRecorder for NoopRecorder {
    fn record(&self, _sample: CdiSpecReadSample) {}
}

/// 読み取り用 open のフラグ（`O_NONBLOCK | O_NOCTTY`）。`O_NONBLOCK` は FIFO の open 待ちによる無期限停止を避け、
/// `O_NOCTTY` は端末デバイスを指定されても制御端末を取得しないために付ける。
/// 値を確定できない Unix では `None` とし、open 前の `metadata` 検査だけで代える。
#[cfg(unix)]
const OPEN_FLAGS: Option<i32> = if cfg!(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
)) {
    // O_NONBLOCK 0o4000 | O_NOCTTY 0o400
    Some(0o4000 | 0o400)
} else if cfg!(any(target_os = "macos", target_os = "ios")) {
    // O_NONBLOCK 0x4 | O_NOCTTY 0x20000
    Some(0x4 | 0x20000)
} else if cfg!(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)) {
    // O_NONBLOCK 0x4 | O_NOCTTY 0x8000
    Some(0x4 | 0x8000)
} else {
    None
};

/// Linux の `O_PATH`（パスの固定だけを行い、デバイスドライバの open 処理を起こさない）。
/// 値が汎用定義（0o10000000）と一致するアーキテクチャに限る。
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )
))]
const O_PATH: i32 = 0o10000000;

fn not_regular_error() -> CdiSpecError {
    CdiSpecError::new(
        CdiSpecErrorCode::InvalidArgument,
        "CDI spec path is not a regular file",
    )
}

fn map_open_error(e: &std::io::Error) -> CdiSpecError {
    if e.kind() == std::io::ErrorKind::NotFound {
        CdiSpecError::new(CdiSpecErrorCode::NotFound, "CDI spec file not found")
    } else {
        CdiSpecError::new(CdiSpecErrorCode::Internal, "failed to open CDI spec file")
    }
}

fn stat_error() -> CdiSpecError {
    CdiSpecError::new(CdiSpecErrorCode::Internal, "failed to stat CDI spec file")
}

/// 固定済みハンドルの `/proc/self/fd/N` を読み取り用に開き直す。
///
/// 対象ファイルの存在判定とは無関係なため、失敗は `NotFound` にせず常に `Internal` とする
/// （`/proc` 欠落で実在する spec が不在扱いになり、呼び出し側が GPU 編集を飛ばすのを防ぐ。GPU-1）。
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )
))]
fn reopen_via_proc(proc_path: &Path) -> Result<std::fs::File, CdiSpecError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut reopen = std::fs::OpenOptions::new();
    reopen.read(true);
    if let Some(flag) = OPEN_FLAGS {
        reopen.custom_flags(flag);
    }
    reopen.open(proc_path).map_err(|_| {
        CdiSpecError::new(
            CdiSpecErrorCode::Internal,
            "failed to reopen pinned CDI spec file via /proc",
        )
    })
}

/// 通常ファイルだけを開く。FIFO・デバイス等は拒否する（open / read の無期限停止とドライバ副作用を防ぐ）。
///
/// Linux では `O_PATH` で対象を固定し（デバイスの open 処理は走らない）、`fstat` で通常ファイルと
/// 確認できた同じ対象だけを `/proc/self/fd/N` 経由で読み取り用に開き直す（パス差し替え競合を避ける。
/// GPU-1）。`/proc` が使えない環境では fail-closed で `Internal` を返す。
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )
))]
fn open_regular_file(path: &Path) -> Result<std::fs::File, CdiSpecError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut pin = std::fs::OpenOptions::new();
    pin.read(true).custom_flags(O_PATH);
    let pinned = pin.open(path).map_err(|e| map_open_error(&e))?;
    let pinned_meta = pinned.metadata().map_err(|_| stat_error())?;
    if !pinned_meta.is_file() {
        return Err(not_regular_error());
    }
    let proc_path = std::path::PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    let file = reopen_via_proc(&proc_path)?;
    let meta = file.metadata().map_err(|_| stat_error())?;
    if !meta.is_file() || meta.dev() != pinned_meta.dev() || meta.ino() != pinned_meta.ino() {
        return Err(not_regular_error());
    }
    Ok(file)
}

/// 通常ファイルだけを開く（Linux 以外・対象外アーキテクチャ）。
///
/// std だけでは非通常ファイルを開かずに固定する手段が無いため、open 前に `metadata`（symlink を
/// 辿る）で種別を確認し、開いた後にもハンドルの種別を検証する。検査と open の間のパス差し替えは
/// 残る（best effort。固定する薄いラッパーは後続課題）。
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )
)))]
fn open_regular_file(path: &Path) -> Result<std::fs::File, CdiSpecError> {
    if let Ok(meta) = std::fs::metadata(path)
        && !meta.is_file()
    {
        return Err(not_regular_error());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(flag) = OPEN_FLAGS {
            opts.custom_flags(flag);
        }
    }
    let file = opts.open(path).map_err(|e| map_open_error(&e))?;
    let meta = file.metadata().map_err(|_| stat_error())?;
    if !meta.is_file() {
        return Err(not_regular_error());
    }
    Ok(file)
}

/// ファイルから [`CdiSpec`] を読む（上限付き）。計測は行わない。
///
/// 通常ファイル以外（FIFO・デバイス等）は `InvalidArgument`。ディレクトリ走査・所有者検証は
/// 行わない（後続タスク）。計測が要る呼び出し側は [`read_cdi_spec_file_with_recorder`] を使う。
pub fn read_cdi_spec_file(path: &Path) -> Result<CdiSpec, CdiSpecError> {
    read_cdi_spec_file_with_recorder(path, &NoopRecorder)
}

/// [`read_cdi_spec_file`] に計測（REPAIR-4）を付けたもの。全経路で結果とレイテンシを 1 回記録する。
pub fn read_cdi_spec_file_with_recorder(
    path: &Path,
    recorder: &dyn CdiSpecReadRecorder,
) -> Result<CdiSpec, CdiSpecError> {
    let start = Instant::now();
    let result = read_cdi_spec_file_inner(path);
    recorder.record(CdiSpecReadSample {
        error_code: result.as_ref().err().map(CdiSpecError::code),
        latency: start.elapsed(),
    });
    result
}

fn read_cdi_spec_file_inner(path: &Path) -> Result<CdiSpec, CdiSpecError> {
    let file = open_regular_file(path)?;
    let mut buf = Vec::new();
    let limit = CDI_SPEC_MAX_INPUT_BYTES as u64 + 1;
    file.take(limit).read_to_end(&mut buf).map_err(|_| {
        CdiSpecError::new(CdiSpecErrorCode::Internal, "failed to read CDI spec file")
    })?;
    // UTF-8 変換より先に上限超過を判定する（上限 +1 バイトで切れた多バイト文字が
    // InvalidArgument に化けて分類契約と食い違うのを防ぐ）。
    if buf.len() > CDI_SPEC_MAX_INPUT_BYTES {
        return Err(CdiSpecError::new(
            CdiSpecErrorCode::ResourceExhausted,
            "CDI spec input exceeds the size limit",
        ));
    }
    let text = String::from_utf8(buf).map_err(|_| {
        CdiSpecError::new(
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec file is not valid UTF-8",
        )
    })?;
    parse_cdi_spec(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "DUMMY_SECRET_TOKEN_12345";

    fn sample() -> String {
        format!(
            r#"cdiVersion: "0.5.0"
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
          type: c
          major: 195
          minor: 0
          permissions: rw
  - name: all
    containerEdits:
      deviceNodes:
        - path: /dev/nvidiactl
containerEdits:
  env:
    - NVIDIA_VISIBLE_DEVICES=void
    - TOKEN={SECRET}
  hooks:
    - hookName: createContainer
      path: /usr/bin/nvidia-ctk
      args: [nvidia-ctk, hook, update-ldcache]
      env: ["X={SECRET}"]
  mounts:
    - hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.1
      containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.1
      options: [ro, nosuid, nodev, bind]
"#
        )
    }

    /// GPU-1: 正常な spec が具体値で読める。
    #[test]
    fn gpu1_parses_sample() {
        let s = parse_cdi_spec(&sample()).unwrap();
        assert_eq!(s.cdi_version, "0.5.0");
        assert_eq!(s.kind, "nvidia.com/gpu");
        assert_eq!(s.devices.len(), 2);
        assert_eq!(s.devices[0].name, "0");
        let n = &s.devices[0].container_edits.device_nodes[0];
        assert_eq!(n.path, "/dev/nvidia0");
        assert_eq!(n.r#type.as_deref(), Some("c"));
        assert_eq!(n.major, Some(195));
        assert_eq!(s.container_edits.env.len(), 2);
        assert_eq!(s.container_edits.hooks[0].hook_name, "createContainer");
        assert_eq!(s.container_edits.hooks[0].args.len(), 3);
        let m = &s.container_edits.mounts[0];
        assert_eq!(m.container_path, "/usr/lib/x86_64-linux-gnu/libcuda.so.1");
        assert_eq!(m.options, ["ro", "nosuid", "nodev", "bind"]);
    }

    /// GPU-1: devices 空・JSON 形式も読める。
    #[test]
    fn gpu1_minimal_and_json() {
        let s = parse_cdi_spec("cdiVersion: '0.5.0'\nkind: a.b/c\n").unwrap();
        assert!(s.devices.is_empty());
        let j = r#"{"cdiVersion":"0.5.0","kind":"a.b/c","containerEdits":{"env":["A=1"]}}"#;
        let s = parse_cdi_spec(j).unwrap();
        assert_eq!(s.container_edits.env.len(), 1);
    }

    fn code_of(input: &str) -> CdiSpecErrorCode {
        parse_cdi_spec(input).unwrap_err().code()
    }

    /// GPU-1: 未知フィールドは各階層で InvalidArgument。
    #[test]
    fn gpu1_rejects_unknown_fields() {
        let cases = [
            "cdiVersion: '1'\nkind: a/b\nbogus: 1\n",
            "cdiVersion: '1'\nkind: a/b\ndevices:\n  - name: x\n    bogus: 1\n    containerEdits: {}\n",
            "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  bogus: 1\n",
            "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  mounts:\n    - hostPath: /a\n      containerPath: /b\n      bogus: 1\n",
        ];
        for c in cases {
            assert_eq!(code_of(c), CdiSpecErrorCode::InvalidArgument, "{c}");
        }
    }

    /// GPU-1: 構文不正・型不一致・必須欠落・重複キー・空入力はエラー。
    #[test]
    fn gpu1_rejects_malformed() {
        let cases = [
            "",
            "kind: [unclosed\n",
            "cdiVersion: \"abc\nkind: x\n",
            "cdiVersion: '1'\n",
            "cdiVersion: '1'\nkind: a/b\ndevices:\n  - containerEdits: {}\n",
            "cdiVersion: '1'\nkind: a/b\ndevices:\n  - name: x\n",
            "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  deviceNodes:\n    - path: /d\n      major: x\n",
            "cdiVersion: '1'\nkind: a/b\nkind: c/d\n",
            "cdiVersion: '1'\nkind: a/b\nannotations:\n  <<: {}\n",
        ];
        for c in cases {
            let e = parse_cdi_spec(c).unwrap_err();
            assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{c}");
        }
    }

    /// GPU-1: 巨大入力・深いネスト・エイリアス爆発は資源上限エラーで panic しない。
    #[test]
    fn gpu1_resource_limits() {
        let big = format!(
            "cdiVersion: '1'\nkind: a/b\n# {}\n",
            "x".repeat(CDI_SPEC_MAX_INPUT_BYTES)
        );
        assert_eq!(code_of(&big), CdiSpecErrorCode::ResourceExhausted);

        // 構文的に完結し、スキーマにも適合する入力でノード数上限（CDI_SPEC_MAX_NODES）を超える。
        // 深さは未知フィールド・型不一致が先に検出されるため、別経路（ノード数・エイリアス）で上限を確認する。
        let mut many = String::from("cdiVersion: '1'\nkind: a/b\ndevices:\n");
        for _ in 0..30_000 {
            many.push_str("- {name: a, containerEdits: {}}\n");
        }
        assert!(many.len() <= CDI_SPEC_MAX_INPUT_BYTES);
        assert_eq!(code_of(&many), CdiSpecErrorCode::ResourceExhausted);

        // 構文的に完結し、スキーマにも適合する入力でエイリアス数上限（CDI_SPEC_MAX_ALIASES）を超える。
        let mut aliases = String::from("cdiVersion: '1'\nkind: a/b\nannotations:\n  k0: &a v\n");
        for i in 1..=(CDI_SPEC_MAX_ALIASES + 8) {
            aliases.push_str(&format!("  k{i}: *a\n"));
        }
        assert_eq!(code_of(&aliases), CdiSpecErrorCode::ResourceExhausted);
    }

    /// GPU-1: IntelRdt は CDI の綴り enableCMT / enableMBM を読む。
    #[test]
    fn gpu1_intel_rdt_field_names() {
        let y = "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  intelRdt:\n    closID: c1\n    enableCMT: true\n    enableMBM: false\n";
        let r = parse_cdi_spec(y)
            .unwrap()
            .container_edits
            .intel_rdt
            .unwrap();
        assert_eq!(r.clos_id.as_deref(), Some("c1"));
        assert_eq!(r.enable_cmt, Some(true));
        assert_eq!(r.enable_mbm, Some(false));
        let bad = "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  intelRdt:\n    enableCmt: true\n";
        assert_eq!(code_of(bad), CdiSpecErrorCode::InvalidArgument);
    }

    /// GPU-1: env の値はエラー message と Debug に出ない。
    #[test]
    fn gpu1_does_not_leak_env_values() {
        let s = parse_cdi_spec(&sample()).unwrap();
        assert!(!format!("{s:?}").contains(SECRET));

        let bad = format!(
            "cdiVersion: '1'\nkind: a/b\ncontainerEdits:\n  env: [\"T={SECRET}\"]\n  bogus: 1\n"
        );
        let e = parse_cdi_spec(&bad).unwrap_err();
        assert!(!e.message().contains(SECRET));
        assert!(!e.to_string().contains(SECRET));
        assert!(e.line().is_some());
    }

    /// 存在しないファイルは NotFound。
    #[test]
    fn read_missing_file_is_not_found() {
        let e = read_cdi_spec_file(Path::new("/nonexistent/fandhe/cdi.yaml")).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::NotFound);
    }

    /// GPU-1: `/proc` 再オープンの失敗は NotFound ではなく Internal（具体値）。
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "powerpc64",
            target_arch = "s390x"
        )
    ))]
    #[test]
    fn gpu1_proc_reopen_failure_is_internal_not_not_found() {
        let e = reopen_via_proc(Path::new("/nonexistent-proc/self/fd/3")).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::Internal);
        assert_eq!(
            e.message(),
            "failed to reopen pinned CDI spec file via /proc"
        );
    }

    /// GPU-1: 通常ファイルは読め、デバイス（直接・symlink 経由）は InvalidArgument で拒否する。
    #[cfg(unix)]
    #[test]
    fn gpu1_reads_regular_and_rejects_device_via_symlink() {
        let dir = std::env::temp_dir().join(format!("fandhe-cdi-spec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("spec.yaml");
        std::fs::write(&file, "cdiVersion: '0.5.0'\nkind: a.b/c\n").unwrap();
        let link_ok = dir.join("ok.yaml");
        let link_dev = dir.join("dev.yaml");
        std::os::unix::fs::symlink(&file, &link_ok).unwrap();
        std::os::unix::fs::symlink("/dev/null", &link_dev).unwrap();

        let ok = read_cdi_spec_file(&link_ok).unwrap();
        assert_eq!(ok.kind, "a.b/c");
        let e = read_cdi_spec_file(&link_dev).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
        let e = read_cdi_spec_file(Path::new("/dev/null")).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
