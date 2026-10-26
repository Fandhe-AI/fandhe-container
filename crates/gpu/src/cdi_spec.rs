//! CDI spec（Container Device Interface）の YAML / JSON 読み込み基盤（TASK-126.1・GPU-1・MS-10）。
//!
//! NVIDIA Container Toolkit が生成する `/var/run/cdi/nvidia.yaml` 等を型付き構造体 [`CdiSpec`] へ
//! デシリアライズするだけの層で、`fandhe-container-gpu` の他モジュール（TASK-126.2 の集計、
//! TASK-126.3 の usr-merge パス正規化、TASK-127 以降の edits 適用）から入力として使われる。
//!
//! フィールド集合は CDI v1.1.x のもの（GPU-1）。v1.1.0 で `containerEdits.netDevices` と `intelRdt` の
//! `schemata`・`enableMonitoring` が追加され、`enableCMT`・`enableMBM` が削除された。
//!
//! `cdiVersion` の検証（#2597・GPU-1・REPAIR-3）: 出典は cncf-tags/container-device-interface v1.1.1
//! `cb98bcf66dc68530012483bd56e33e14d815e167` の `specs-go/version.go`（L25-62 の既知の版、L64-81 `ValidateVersion`、
//! L92-95 `newVersion`、L110-118 `requiredVersion`、L131-256 各要件）・`specs-go/config.go` L67-73・`pkg/cdi/spec.go` の
//! `ParseSpec`（`KnownFields(true)`）・`SPEC.md` L20-42, L193。上流と判定を揃え、上流より厳しくも緩くもしない。
//! - 受ける版は 0.3.0・0.4.0・0.5.0・0.6.0・0.7.0・0.8.0・1.0.0・1.1.0 の 8 個だけ。先頭の `v` は 1 つだけ許し、
//!   外した後の文字列が完全一致するときだけ受ける（`01.1.0`・`1.1`・`1.1.0-rc1`・空文字は不一致）。0.1.0・0.2.0 は
//!   上流でも最小の版の既定（0.3.0）未満で必ず失敗するため拒否する。未知の版（1.1.1・1.2.0・2.0.0 など新しい版を含む）は
//!   `InvalidArgument`（fail-closed。`Unimplemented` は「有効だが未適用」の意味なので使わない）。
//! - フィールドごとの最小の版（新しい版から順に見て最初に当てはまったもの。宣言された版がそれより古ければ `InvalidArgument`）:
//!   1.1.0 = `intelRdt.schemata`（空の列も含む）・`intelRdt.enableMonitoring: true`・`netDevices` 非空 /
//!   0.7.0 = `intelRdt`・`additionalGids` 非空 / 0.6.0 = `annotations` 非空・`kind` の class に `.` /
//!   0.5.0 = デバイス名の先頭が数字・`deviceNodes[].hostPath` が空でない / 0.4.0 = `mounts[].type` が空でない /
//!   0.3.0 = 上記のどれにも当てはまらない場合。空文字・false は「無い」と同じ扱い（Go のゼロ値と同じ）。
//! - `intelRdt`: v1.1.0 の `schemata`・`enableMonitoring` を受ける。`enableCMT`・`enableMBM` は上流 v1.1.x の
//!   `IntelRdt` に無く、`ParseSpec` が宣言された版に関係なく未知フィールドとして拒否するため、本実装も
//!   `InvalidArgument`（`CDI spec has an unknown field`。行・列つき）で拒否する。v0.7.0 の旧い綴りを書いた spec は
//!   版に関係なく拒否される（REPAIR-3。版で分ける規則は上流に無いので採らない）。値（schemata の文字列）の意味は検証しない。
//!
//! netDevices（#2445・GPU-1・REPAIR-3）: ホストのネットワークインターフェースをコンテナの netns へ移す編集で、
//! 適用は net crate の責務でありまだ無い。そのため型付きで解析・検証した上で、1 件でもあれば
//! [`parse_cdi_spec`] が `Unimplemented` で spec 全体を拒否する（要求されないデバイスにだけあっても拒否する）。
//!
//! 責務境界（将来仕様。REPAIR-3）:
//! - 本モジュールは構文・型・未知フィールド・重複キー・資源上限の検査までを行う。
//!   `kind` / `name` の形式検査（最小の版の判定に要る分解だけは行う）、パスの絶対性、`hookName` の許可値などの意味検証は行わない
//!   （TASK-126.2 以降・TASK-127 の責務）。値は保持するだけで、パスやコマンドの組み立てはしない。
//! - `/var/run/cdi` の所有者・権限の検証、ディレクトリ走査、名前から spec への解決は後続タスクで扱う。解決済みの
//!   (spec, 名前) の列の集計は `cdi_edits::aggregate_container_edits_across_specs`（TASK-126.2・GPU-1）が担う。
//! - 未知フィールドは全構造体で拒否する（fail-closed）。将来の CDI 版で増えたフィールドを受けるには
//!   本モジュールの型を拡張する。
//!
//! 外部入力の扱い（`security.md`・`coding-rust.md`）: 入力バイト長を先に検証し、`serde-saphyr` の
//! `Budget` を明示して深さ・ノード数・エイリアス展開を締める。エラーの `message` と `Debug` 出力には
//! YAML の内容（とくに `env` の値。トークン等を含みうる）を載せない。

use std::collections::{BTreeMap, BTreeSet};
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
/// `#[non_exhaustive]` のため、他 crate の `match` は網羅にできない。`_` に吸収させず、[`CdiSpecErrorCode::ALL`] 由来の
/// `const` 表＋`find` と表外への明示の倒し先にし、試験で表の網羅を照合する（REPAIR-1・ERR-1）。
/// 文字列から戻すときは [`CdiSpecErrorCode::from_name`] の `None` を fail-closed で扱う。
///
/// core の `ErrorCode` への写像は持たせない: gpu はワークスペース内の crate に依存せず、消費側（edits の適用。
/// TASK-127 以降）がまだ無い。写像は消費側を作るときにその crate に `ALL` 由来の表で置く。
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
    /// 仕様上は有効だが本実装がまだ適用できない編集（現状は `netDevices`。#2445・REPAIR-3）。
    Unimplemented,
}

impl CdiSpecErrorCode {
    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら単体試験（`ordinal` の網羅 match と件数）が検出する。
    pub const ALL: [CdiSpecErrorCode; 5] = [
        CdiSpecErrorCode::InvalidArgument,
        CdiSpecErrorCode::ResourceExhausted,
        CdiSpecErrorCode::NotFound,
        CdiSpecErrorCode::Internal,
        CdiSpecErrorCode::Unimplemented,
    ];

    /// `as_str` の逆写像。完全一致だけを受ける（大文字小文字の畳み込み・空白の除去をしない）。
    ///
    /// 未知は `None` で、呼び出し側は固定文言で拒否する（fail-closed。既知の variant へ黙って
    /// 置き換えない）。現時点で製品経路の呼び出し元は無く、往復試験と将来の受信側のために置く。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }

    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::NotFound => "NOT_FOUND",
            Self::Internal => "INTERNAL",
            Self::Unimplemented => "UNIMPLEMENTED",
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

/// CDI spec のトップレベル（CDI v1.1.x のフィールド集合。GPU-1）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CdiSpec {
    /// `cdiVersion`（[`parse_cdi_spec`] が既知の版と、使っているフィールドに対する最小の版を検証する。モジュール doc 参照）。
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
    /// ネットワークデバイス（CDI v1.1.0 で追加。適用は未実装で、非空なら [`parse_cdi_spec`] と集計が
    /// `Unimplemented` で拒否する。#2445・GPU-1・REPAIR-3）。
    #[serde(default)]
    pub net_devices: Vec<NetDevice>,
}

/// ホストのインターフェースをコンテナの netns へ移す CDI v1.1.0 の編集 1 件。
///
/// 適用（netns への移動）は net crate の責務で未実装（#2445・REPAIR-3）。本層は名前を検証して保持するだけ。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetDevice {
    /// ホスト側のインターフェース名。
    pub host_interface_name: String,
    /// コンテナ内でのインターフェース名。
    pub name: String,
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

/// Intel RDT 設定（CDI v1.1.x のフィールド集合。GPU-1・REPAIR-3）。
///
/// v0.7.0 の `enableCMT`・`enableMBM` は v1.1.0 で削除された。上流 v1.1.x の `ParseSpec` は宣言された版に関係なく
/// 未知フィールドとして拒否するため、本実装も同じく `InvalidArgument`（unknown field）で拒否する
/// （版で分ける規則は上流に無いので採らない。出典は module doc）。
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
    /// スキーマ文字列の列（CDI v1.1.0 で追加。空の列でも 1.1.0 を要求する）。
    #[serde(default)]
    pub schemata: Option<Vec<String>>,
    /// モニタリングの有効化（CDI v1.1.0 で追加。`true` のとき 1.1.0 を要求する）。
    #[serde(default)]
    pub enable_monitoring: Option<bool>,
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
///
/// 構文の検査に続けて、次の順で検査する（#2445・#2597・GPU-1）。
/// 1. `cdiVersion` が既知の版でない、または使っているフィールドの最小の版（`netDevices` なら 1.1.0）より古ければ
///    `InvalidArgument`（モジュール doc 参照）
/// 2. 各 `containerEdits` の名前（15 バイト以下・`.` `..` `/` `:` 空白 NUL 不可。`fandhe-container-net` の
///    `IfName::new` と同じ規則）と、1 つの edits 内の `hostInterfaceName`・`name` の重複を検査し `InvalidArgument`
/// 3. 検査を通っても適用が未実装のため `Unimplemented`（spec 単位。REPAIR-3）
///
/// 2・3 は `netDevices` が 1 件以上あるときだけ行う。1・2 は逆シリアライズ後の検査のため、エラーの行・列は `None`。
/// `netDevices: []` は無いものと同じ扱い。
/// 適用（net crate）が実装されたら 3 を外し、公開 API から netDevices を返す（将来仕様）。
pub fn parse_cdi_spec(input: &str) -> Result<CdiSpec, CdiSpecError> {
    let spec = parse_cdi_spec_unchecked(input)?;
    reject_unapplied_edits(&spec)?;
    Ok(spec)
}

/// 構造・名前・版の検査までを行い、適用可否のゲートは掛けない解析（集計の内部試験用）。
pub(crate) fn parse_cdi_spec_unchecked(input: &str) -> Result<CdiSpec, CdiSpecError> {
    let spec = parse_structure(input)?;
    validate_cdi_version(&spec)?;
    validate_net_devices(&spec)?;
    Ok(spec)
}

/// 適用が未実装の編集（現状は `netDevices`）を含む spec を `Unimplemented` で拒否するゲート。
pub(crate) fn reject_unapplied_edits(spec: &CdiSpec) -> Result<(), CdiSpecError> {
    let any = !spec.container_edits.net_devices.is_empty()
        || spec
            .devices
            .iter()
            .any(|d| !d.container_edits.net_devices.is_empty());
    if any {
        return Err(net_devices_unimplemented());
    }
    Ok(())
}

/// `netDevices` が未適用であることを示す固定文言のエラー（parse と集計の両ゲートで共有する）。
pub(crate) fn net_devices_unimplemented() -> CdiSpecError {
    CdiSpecError::new(
        CdiSpecErrorCode::Unimplemented,
        "CDI netDevices edits are not supported yet",
    )
}

/// 受ける `cdiVersion` の最新（上流の `CurrentVersion`。GPU-1）。
pub const CDI_SPEC_LATEST_SUPPORTED_VERSION: &str = "1.1.0";

/// 受ける `cdiVersion`（GPU-1・REPAIR-3）。既知の版だけを表し、壊れた版・未知の版は作れない。
///
/// 上流 `specs-go/version.go` の既知の版のうち、最小の版の既定（0.3.0）未満の 0.1.0・0.2.0 を除いた 8 個。
/// `Ord` は版の新旧の順で、フィールドごとの最小の版との比較に使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CdiSpecVersion {
    V0_3_0,
    V0_4_0,
    V0_5_0,
    V0_6_0,
    V0_7_0,
    V0_8_0,
    V1_0_0,
    V1_1_0,
}

impl CdiSpecVersion {
    /// 先頭の `v` を 1 つだけ外し、既知の版の文字列との完全一致でのみ作る（上流 `newVersion` と同じ。数値解釈はしない）。
    pub(crate) fn from_raw(raw: &str) -> Option<Self> {
        let body = raw.strip_prefix('v').unwrap_or(raw);
        Some(match body {
            "0.3.0" => Self::V0_3_0,
            "0.4.0" => Self::V0_4_0,
            "0.5.0" => Self::V0_5_0,
            "0.6.0" => Self::V0_6_0,
            "0.7.0" => Self::V0_7_0,
            "0.8.0" => Self::V0_8_0,
            "1.0.0" => Self::V1_0_0,
            "1.1.0" => Self::V1_1_0,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::V0_3_0 => "0.3.0",
            Self::V0_4_0 => "0.4.0",
            Self::V0_5_0 => "0.5.0",
            Self::V0_6_0 => "0.6.0",
            Self::V0_7_0 => "0.7.0",
            Self::V0_8_0 => "0.8.0",
            Self::V1_0_0 => "1.0.0",
            Self::V1_1_0 => "1.1.0",
        }
    }
}

/// 全 `containerEdits`（トップレベル、続けて各デバイス）。
fn all_edits(spec: &CdiSpec) -> impl Iterator<Item = &ContainerEdits> + Clone {
    std::iter::once(&spec.container_edits).chain(spec.devices.iter().map(|d| &d.container_edits))
}

/// 使っているフィールドから求めた最小の版と、その理由（固定の語彙）。新しい版から順に見て最初に当てはまったもの
/// （上流 `requiredVersion`。`specs-go/version.go` L110-118、各要件は L131-256）。どれにも当てはまらなければ 0.3.0。
/// 空文字・false は「無い」と同じ扱い（Go のゼロ値と同じ）。
fn required_version(spec: &CdiSpec) -> (CdiSpecVersion, &'static str) {
    let edits = || all_edits(spec);
    // 1.1.0（L131-156）。
    if edits().any(|e| e.intel_rdt.as_ref().is_some_and(|r| r.schemata.is_some())) {
        return (CdiSpecVersion::V1_1_0, "intelRdt schemata");
    }
    if edits().any(|e| {
        e.intel_rdt
            .as_ref()
            .is_some_and(|r| r.enable_monitoring == Some(true))
    }) {
        return (CdiSpecVersion::V1_1_0, "intelRdt enableMonitoring");
    }
    if edits().any(|e| !e.net_devices.is_empty()) {
        return (CdiSpecVersion::V1_1_0, "netDevices");
    }
    // 1.0.0・0.8.0 は spec への変更が無い。
    // 0.7.0。
    if edits().any(|e| e.intel_rdt.is_some()) {
        return (CdiSpecVersion::V0_7_0, "intelRdt");
    }
    if edits().any(|e| !e.additional_gids.is_empty()) {
        return (CdiSpecVersion::V0_7_0, "additionalGids");
    }
    // 0.6.0。
    if !spec.annotations.is_empty() || spec.devices.iter().any(|d| !d.annotations.is_empty()) {
        return (CdiSpecVersion::V0_6_0, "annotations");
    }
    if spec
        .kind
        .split_once('/')
        .is_some_and(|(_, class)| class.contains('.'))
    {
        return (CdiSpecVersion::V0_6_0, "kind class containing '.'");
    }
    // 0.5.0。
    if spec
        .devices
        .iter()
        .any(|d| d.name.as_bytes().first().is_some_and(u8::is_ascii_digit))
    {
        return (CdiSpecVersion::V0_5_0, "device name starting with a digit");
    }
    if edits().any(|e| {
        e.device_nodes
            .iter()
            .any(|n| n.host_path.as_deref().is_some_and(|h| !h.is_empty()))
    }) {
        return (CdiSpecVersion::V0_5_0, "deviceNodes hostPath");
    }
    // 0.4.0。
    if edits().any(|e| {
        e.mounts
            .iter()
            .any(|m| m.r#type.as_deref().is_some_and(|t| !t.is_empty()))
    }) {
        return (CdiSpecVersion::V0_4_0, "mounts type");
    }
    (CdiSpecVersion::V0_3_0, "default")
}

/// `cdiVersion` を検証する（GPU-1・REPAIR-3）。未知の版・0.3.0 未満・使っているフィールドに対して古すぎる版は
/// `InvalidArgument`（fail-closed）。メッセージは固定文言で、入力の値を載せない。
///
/// `parse_cdi_spec` が呼ぶほか、parse を通らずに作られた [`CdiSpec`] に備えて `cdi_edits` の集計も呼ぶ。
pub(crate) fn validate_cdi_version(spec: &CdiSpec) -> Result<(), CdiSpecError> {
    let Some(declared) = CdiSpecVersion::from_raw(&spec.cdi_version) else {
        return Err(CdiSpecError::new(
            CdiSpecErrorCode::InvalidArgument,
            "CDI spec has an unsupported cdiVersion (supported: 0.3.0 to 1.1.0; earliest supported 0.3.0)",
        ));
    };
    let (required, feature) = required_version(spec);
    if declared < required {
        return Err(CdiSpecError::new(
            CdiSpecErrorCode::InvalidArgument,
            &format!(
                "CDI {feature} requires cdiVersion {} or later",
                required.as_str()
            ),
        ));
    }
    Ok(())
}

/// インターフェース名の検証。`fandhe-container-net` の `IfName::new`（カーネルの `dev_valid_name` 相当）と
/// 同じ規則で、変えるときは両方を揃える。net crate への依存は crate 境界を変えるため足さない。
/// ホストの altname（最大 127 バイト）は受けない（fail-closed。net crate での適用実装時に見直す）。
fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == ':' || c == '\0' || c.is_whitespace())
}

fn validate_net_devices(spec: &CdiSpec) -> Result<(), CdiSpecError> {
    for edits in all_edits(spec) {
        let mut hosts: BTreeSet<&str> = BTreeSet::new();
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for nd in &edits.net_devices {
            if !is_valid_interface_name(&nd.host_interface_name)
                || !is_valid_interface_name(&nd.name)
            {
                return Err(CdiSpecError::new(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI netDevices entry has an invalid interface name",
                ));
            }
            if !hosts.insert(nd.host_interface_name.as_str()) || !names.insert(nd.name.as_str()) {
                return Err(CdiSpecError::new(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI netDevices has a duplicate hostInterfaceName or name",
                ));
            }
        }
    }
    Ok(())
}

fn parse_structure(input: &str) -> Result<CdiSpec, CdiSpecError> {
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

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: CdiSpecErrorCode) -> usize {
        match code {
            CdiSpecErrorCode::InvalidArgument => 0,
            CdiSpecErrorCode::ResourceExhausted => 1,
            CdiSpecErrorCode::NotFound => 2,
            CdiSpecErrorCode::Internal => 3,
            CdiSpecErrorCode::Unimplemented => 4,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err1_cdispecerrorcode_all_covers_every_variant() {
        for (i, c) in CdiSpecErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(CdiSpecErrorCode::ALL.len(), 5);
        let set: std::collections::HashSet<_> = CdiSpecErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 5);
    }

    /// ERR-1: ワイヤーへ出す code 名は固定（変えると互換が壊れる）。`from_name` は完全一致の逆写像。
    #[test]
    fn err1_cdispecerrorcode_wire_names_are_fixed_and_roundtrip() {
        let table = [
            (CdiSpecErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (CdiSpecErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (CdiSpecErrorCode::NotFound, "NOT_FOUND"),
            (CdiSpecErrorCode::Internal, "INTERNAL"),
            (CdiSpecErrorCode::Unimplemented, "UNIMPLEMENTED"),
        ];
        assert_eq!(table.len(), CdiSpecErrorCode::ALL.len());
        for (i, (code, name)) in table.into_iter().enumerate() {
            assert_eq!(CdiSpecErrorCode::ALL[i], code);
            assert_eq!(code.as_str(), name);
            assert_eq!(CdiSpecErrorCode::from_name(name), Some(code));
        }
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(CdiSpecErrorCode::from_name(bad), None, "{bad:?}");
        }
    }

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
            "cdiVersion: '0.7.0'\nkind: a/b\nbogus: 1\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ndevices:\n  - name: x\n    bogus: 1\n    containerEdits: {}\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ncontainerEdits:\n  bogus: 1\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ncontainerEdits:\n  mounts:\n    - hostPath: /a\n      containerPath: /b\n      bogus: 1\n",
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
            "cdiVersion: '0.7.0'\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ndevices:\n  - containerEdits: {}\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ndevices:\n  - name: x\n",
            "cdiVersion: '0.7.0'\nkind: a/b\ncontainerEdits:\n  deviceNodes:\n    - path: /d\n      major: x\n",
            "cdiVersion: '0.7.0'\nkind: a/b\nkind: c/d\n",
            "cdiVersion: '0.7.0'\nkind: a/b\nannotations:\n  <<: {}\n",
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
            "cdiVersion: '0.7.0'\nkind: a/b\n# {}\n",
            "x".repeat(CDI_SPEC_MAX_INPUT_BYTES)
        );
        assert_eq!(code_of(&big), CdiSpecErrorCode::ResourceExhausted);

        // 構文的に完結し、スキーマにも適合する入力でノード数上限（CDI_SPEC_MAX_NODES）を超える。
        // 深さは未知フィールド・型不一致が先に検出されるため、別経路（ノード数・エイリアス）で上限を確認する。
        let mut many = String::from("cdiVersion: '0.7.0'\nkind: a/b\ndevices:\n");
        for _ in 0..30_000 {
            many.push_str("- {name: a, containerEdits: {}}\n");
        }
        assert!(many.len() <= CDI_SPEC_MAX_INPUT_BYTES);
        assert_eq!(code_of(&many), CdiSpecErrorCode::ResourceExhausted);

        // 構文的に完結し、スキーマにも適合する入力でエイリアス数上限（CDI_SPEC_MAX_ALIASES）を超える。
        let mut aliases =
            String::from("cdiVersion: '0.7.0'\nkind: a/b\nannotations:\n  k0: &a v\n");
        for i in 1..=(CDI_SPEC_MAX_ALIASES + 8) {
            aliases.push_str(&format!("  k{i}: *a\n"));
        }
        assert_eq!(code_of(&aliases), CdiSpecErrorCode::ResourceExhausted);
    }

    /// GPU-1・REPAIR-3: IntelRdt は v1.1.x の綴り schemata / enableMonitoring を読み、旧い enableCMT / enableMBM は
    /// 宣言された版に関係なく未知フィールドとして拒否する（上流 v1.1.x と同じ）。
    #[test]
    fn gpu1_intel_rdt_field_names() {
        let y = "cdiVersion: '1.1.0'\nkind: a/b\ncontainerEdits:\n  intelRdt:\n    closID: c1\n    schemata: [\"L3:0=f\"]\n    enableMonitoring: true\n";
        let r = parse_cdi_spec(y)
            .unwrap()
            .container_edits
            .intel_rdt
            .unwrap();
        assert_eq!(r.clos_id.as_deref(), Some("c1"));
        assert_eq!(r.schemata, Some(vec!["L3:0=f".to_string()]));
        assert_eq!(r.enable_monitoring, Some(true));
        for v in ["0.7.0", "1.1.0"] {
            for key in ["enableCMT", "enableMBM", "enableCmt", "enablemonitoring"] {
                let bad = format!(
                    "cdiVersion: '{v}'\nkind: a/b\ncontainerEdits:\n  intelRdt:\n    {key}: true\n"
                );
                let e = parse_cdi_spec(&bad).unwrap_err();
                assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{v} {key}");
                assert_eq!(e.message(), "CDI spec has an unknown field", "{v} {key}");
            }
        }
    }

    /// GPU-1: env の値はエラー message と Debug に出ない。
    #[test]
    fn gpu1_does_not_leak_env_values() {
        let s = parse_cdi_spec(&sample()).unwrap();
        assert!(!format!("{s:?}").contains(SECRET));

        let bad = format!(
            "cdiVersion: '0.7.0'\nkind: a/b\ncontainerEdits:\n  env: [\"T={SECRET}\"]\n  bogus: 1\n"
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

    // ---- netDevices（#2445・GPU-1・REPAIR-3） ----

    fn nd_spec(version: &str, top: &str, dev: &str) -> String {
        format!(
            "cdiVersion: \"{version}\"\nkind: v/c\ndevices:\n  - name: a\n    containerEdits:\n      netDevices: {dev}\ncontainerEdits:\n  netDevices: {top}\n"
        )
    }

    fn pair(h: &str, n: &str) -> String {
        format!("{{hostInterfaceName: \"{h}\", name: \"{n}\"}}")
    }

    #[test]
    fn gpu1_parses_net_devices_structure() {
        let y = nd_spec(
            "1.1.0",
            &format!("[{}]", pair("eth1", "net1")),
            &format!("[{}]", pair("eth2", "net2")),
        );
        let spec = parse_cdi_spec_unchecked(&y).unwrap();
        assert_eq!(spec.container_edits.net_devices.len(), 1);
        assert_eq!(
            spec.container_edits.net_devices[0].host_interface_name,
            "eth1"
        );
        assert_eq!(spec.container_edits.net_devices[0].name, "net1");
        let d = &spec.devices[0].container_edits.net_devices[0];
        assert_eq!(
            (d.host_interface_name.as_str(), d.name.as_str()),
            ("eth2", "net2")
        );
        let json = r#"{"cdiVersion":"1.1.0","kind":"v/c","containerEdits":{"netDevices":[{"hostInterfaceName":"eth1","name":"net1"}]}}"#;
        assert_eq!(
            parse_cdi_spec_unchecked(json)
                .unwrap()
                .container_edits
                .net_devices[0]
                .name,
            "net1"
        );
    }

    #[test]
    fn gpu1_net_device_schema_errors() {
        for dev in [
            "[{hostInterfaceName: eth1, name: n, bogus: 1}]",
            "[{hostInterfaceName: eth1}]",
            "[{name: n}]",
            "[{hostInterfaceName: 1, name: [x]}]",
        ] {
            let e = parse_cdi_spec_unchecked(&nd_spec("1.1.0", dev, "[]")).unwrap_err();
            assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{dev}");
        }
    }

    #[test]
    fn gpu1_net_device_name_validation() {
        let long16 = "a".repeat(16);
        let ok15 = "a".repeat(15);
        // YAML のダブルクォート内のエスケープ（\t・\0・全角空白）を含む。
        let bad = [
            "",
            long16.as_str(),
            ".",
            "..",
            "a/b",
            "a:b",
            "a b",
            "a\\tb",
            "a\\0b",
            "a\\u3000b",
        ];
        for b in bad {
            for (h, n) in [(b, "net1"), ("eth1", b)] {
                let y = nd_spec("1.1.0", &format!("[{}]", pair(h, n)), "[]");
                let e = parse_cdi_spec_unchecked(&y).unwrap_err();
                assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{b:?}");
                assert_eq!(
                    e.message(),
                    "CDI netDevices entry has an invalid interface name"
                );
            }
        }
        for good in [ok15.as_str(), "eth0", "net1"] {
            let y = nd_spec("1.1.0", &format!("[{}]", pair(good, good)), "[]");
            assert!(parse_cdi_spec_unchecked(&y).is_ok(), "{good}");
        }
    }

    #[test]
    fn gpu1_net_devices_duplicate_within_edits() {
        let dup_host = format!("[{}, {}]", pair("eth1", "a"), pair("eth1", "b"));
        let dup_exact = format!("[{}, {}]", pair("eth1", "a"), pair("eth1", "a"));
        let dup_name = format!("[{}, {}]", pair("eth1", "a"), pair("eth2", "a"));
        for top in [dup_host, dup_exact, dup_name] {
            let e = parse_cdi_spec_unchecked(&nd_spec("1.1.0", &top, "[]")).unwrap_err();
            assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
            assert_eq!(
                e.message(),
                "CDI netDevices has a duplicate hostInterfaceName or name"
            );
        }
        // 別の edits にまたがる重複はこの段では拒否しない（集計側の規則）。
        let y = nd_spec(
            "1.1.0",
            &format!("[{}]", pair("eth1", "a")),
            &format!("[{}]", pair("eth1", "b")),
        );
        assert!(parse_cdi_spec_unchecked(&y).is_ok());
    }

    #[test]
    fn repair3_parse_rejects_net_devices_unimplemented() {
        let y = nd_spec("1.1.0", &format!("[{}]", pair("eth1", "n")), "[]");
        let e = parse_cdi_spec(&y).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::Unimplemented);
        assert_eq!(e.code().as_str(), "UNIMPLEMENTED");
        assert_eq!(e.message(), "CDI netDevices edits are not supported yet");
        // 要求されないデバイスにだけあっても spec 単位で拒否する。
        let y = nd_spec("1.1.0", "[]", &format!("[{}]", pair("eth1", "n")));
        assert_eq!(
            parse_cdi_spec(&y).unwrap_err().code(),
            CdiSpecErrorCode::Unimplemented
        );
    }

    #[test]
    fn gpu1_empty_net_devices_is_absent() {
        assert!(parse_cdi_spec(&nd_spec("0.5.0", "[]", "[]")).is_ok());
    }

    #[test]
    fn gpu1_cdi_version_parsing() {
        use CdiSpecVersion as V;
        assert_eq!(V::from_raw("1.1.0"), Some(V::V1_1_0));
        assert_eq!(V::from_raw("v0.3.0"), Some(V::V0_3_0));
        for bad in [
            "",
            "abc",
            "1",
            "1.1",
            "1.1.0-rc1",
            "1.1.0+x",
            "vv1.1.0",
            "1.1.0.0",
            "01.1.0",
            "0.1.0",
            "0.2.0",
            "1.1.1",
            "1.2.0",
            "2.0.0",
        ] {
            assert_eq!(V::from_raw(bad), None, "{bad}");
        }
    }
}
