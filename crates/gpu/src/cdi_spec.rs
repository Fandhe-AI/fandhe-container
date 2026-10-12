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
//! - `/var/run/cdi` の所有者・権限の検証、ディレクトリ走査、複数 spec のマージは後続タスクで扱う。
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
    /// 入力サイズ・深さ・ノード数・エイリアス展開などの上限超過。
    ResourceExhausted,
    /// spec ファイルが存在しない。
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
    fn new(code: CdiSpecErrorCode, message: &str) -> Self {
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
    #[serde(default)]
    pub enable_cmt: Option<bool>,
    /// MBM の有効化。
    #[serde(default)]
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

/// ファイルから [`CdiSpec`] を読む（上限付き）。
///
/// ディレクトリ走査・所有者検証は行わない（後続タスク）。
pub fn read_cdi_spec_file(path: &Path) -> Result<CdiSpec, CdiSpecError> {
    let file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CdiSpecError::new(CdiSpecErrorCode::NotFound, "CDI spec file not found")
        } else {
            CdiSpecError::new(CdiSpecErrorCode::Internal, "failed to open CDI spec file")
        }
    })?;
    let mut buf = Vec::new();
    let limit = CDI_SPEC_MAX_INPUT_BYTES as u64 + 1;
    file.take(limit).read_to_end(&mut buf).map_err(|_| {
        CdiSpecError::new(CdiSpecErrorCode::Internal, "failed to read CDI spec file")
    })?;
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

        let deep = format!(
            "cdiVersion: '1'\nkind: a/b\nannotations: {}\n",
            "[".repeat(5000)
        );
        assert!(parse_cdi_spec(&deep).is_err());

        let mut bomb =
            String::from("cdiVersion: '1'\nkind: a/b\nx: &a0 [a, a, a, a, a, a, a, a, a]\n");
        for i in 1..12 {
            let p = i - 1;
            bomb.push_str(&format!(
                "x{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        assert!(parse_cdi_spec(&bomb).is_err());
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
}
