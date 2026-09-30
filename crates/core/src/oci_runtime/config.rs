//! OCI Runtime Spec の `config.json` の型定義と、外部入力として安全なパーサ（TASK-29.1.1・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! bundle の `config.json` を検証済みの [`OciConfig`] に変換する。TASK-29.2（create）が
//! `load_config(<bundle>/config.json)` を呼び、結果を `exec::Entrypoint` や rootfs / mount の
//! セットアップへ渡す想定（未実装。呼び出し側は後続 TASK）。`mounts[].destination` の rootfs 配下への
//! 正規化とトラバーサル拒否は TASK-29.1.2 の担当で、本モジュールは「未検証のパス値」として保持する
//! だけである。TASK-29.1.2 の検証を経ずに使ってはならない。
//!
//! # 型設計（REPAIR-2）
//!
//! - 2 層構成: 非公開の raw 層（`#[derive(Deserialize)]`）で JSON を受け、検証を通過した値だけを
//!   公開型に詰める。公開型のフィールドは非公開で、生成経路はパース関数のみ。
//! - OCI Runtime Spec の拡張性規則に従い、未知のプロパティはエラーにせず無視する。
//!   ただし重複キー・必須欠落・型不一致・未知の namespace type はエラーにする。
//!
//! # 未解釈のセクション（REPAIR-3）
//!
//! 次のセクションはパース時に無視しているだけで、適用済みではない（fail-open にならない扱いは
//! TASK-29.2 の計画で決める）: `process.capabilities`・`process.rlimits`・`process.noNewPrivileges`
//! （SEC-1・TASK-27.4.3 系）、`linux.seccomp`（CORE-5・TASK-38）、`linux.resources`
//! （CORE-3/4・TASK-32〜）、`linux.maskedPaths` / `readonlyPaths`、`hooks`、`annotations`。
//!
//! # 入力上限（DoS 防止）
//!
//! 読み込み前にバイト長を [`CONFIG_MAX_BYTES`] で制限し、デシリアライズ中は配列の件数と文字列の
//! 長さを上限超過の時点で中断する（上限を超える件数分のアロケーションをしない）。ネスト深さは
//! serde_json 既定の再帰上限（128）に任せる。
//!
//! # エラーの秘密情報非漏洩
//!
//! serde_json のエラー文字列は不正な入力値（例: `env` の値）をそのまま含むため、保持・出力しない。
//! [`OciConfigError`] は分類・位置（行・列）・固定文言・検証で判明した自前のフィールド名だけを持つ。

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

use crate::traits::ErrorCode;

/// `config.json` 全体の最大バイト長（4 MiB）。`args` / `env` の合計上限（1 MiB。
/// `exec::ENTRYPOINT_MAX_TOTAL_BYTES`）に JSON エスケープ分とその他フィールドの余裕を加えた値。
pub const CONFIG_MAX_BYTES: usize = 4 << 20;
/// `process.args` の最大件数（`exec::ENTRYPOINT_MAX_ARGS` と同値）。
pub const CONFIG_MAX_ARGS: usize = 4096;
/// `process.env` の最大件数（`exec::ENTRYPOINT_MAX_ENV` と同値）。
pub const CONFIG_MAX_ENV: usize = 4096;
/// `args` / `env` の 1 要素の最大バイト長（`exec::ENTRYPOINT_MAX_STRING_BYTES` と同値）。
pub const CONFIG_MAX_STRING_BYTES: usize = 131_072;
/// パス文字列の最大バイト長（`PATH_MAX` 相当）。
pub const CONFIG_MAX_PATH_BYTES: usize = 4096;
/// `mounts` の最大件数。
pub const CONFIG_MAX_MOUNTS: usize = 1024;
/// `mounts[].options` の最大件数。
pub const CONFIG_MAX_MOUNT_OPTIONS: usize = 64;
/// `process.user.additionalGids` の最大件数（`NGROUPS_MAX` 相当）。
pub const CONFIG_MAX_ADDITIONAL_GIDS: usize = 65_536;
/// `linux.namespaces` の最大件数（種別は 8 種のため余裕を持たせた値）。
pub const CONFIG_MAX_NAMESPACES: usize = 16;
/// `linux.uidMappings` / `gidMappings` の最大件数（カーネルの上限 340）。
pub const CONFIG_MAX_ID_MAPPINGS: usize = 340;
/// `ociVersion` の最大バイト長。
pub const CONFIG_MAX_OCI_VERSION_BYTES: usize = 64;
/// `hostname` の最大バイト長（`HOST_NAME_MAX` 相当）。
pub const CONFIG_MAX_HOSTNAME_BYTES: usize = 64;
/// マウント種別（`mounts[].type`）の最大バイト長。
const MOUNT_TYPE_MAX_BYTES: usize = 256;

/// 上限超過を serde のエラー文字列で運ぶための目印。`classify` 側で復元する。
const LIMIT_TAG: &str = "fandhe-limit";

// ---------------------------------------------------------------------------
// エラー型
// ---------------------------------------------------------------------------

/// [`OciConfigError`] の分類。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OciConfigErrorKind {
    /// JSON の構文エラー（再帰深さ超過を含む）。
    Syntax,
    /// 構文は正しいが、必須欠落・型不一致・未知の列挙値・重複キーがある。
    Data,
    /// JSON が途中で終わっている。
    Eof,
    /// 入力が [`CONFIG_MAX_BYTES`] を超える。
    TooLarge,
    /// 配列の件数または文字列の長さが上限を超える。
    LimitExceeded {
        /// 上限超過したフィールド（例: `process.args`）。
        field: String,
        /// 超えた上限値（件数またはバイト長）。
        limit: usize,
    },
    /// 値が意味的に不正（空・相対パス・非対応バージョン等）。
    Invalid {
        /// 不正なフィールド。
        field: &'static str,
    },
    /// ファイルの読み込みに失敗した。
    Io,
}

/// `config.json` の読み込み・検証エラー（ERR-1: 機械可読な `code` / `message`）。
///
/// 入力値は保持しない（モジュール doc の「秘密情報非漏洩」参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciConfigError {
    code: ErrorCode,
    kind: OciConfigErrorKind,
    line: Option<usize>,
    column: Option<usize>,
    message: String,
}

impl OciConfigError {
    fn new(code: ErrorCode, kind: OciConfigErrorKind, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            line: None,
            column: None,
            message: message.into(),
        }
    }

    fn invalid(field: &'static str) -> Self {
        Self::new(
            ErrorCode::InvalidArgument,
            OciConfigErrorKind::Invalid { field },
            format!("config.json has an invalid value for `{field}`"),
        )
    }

    fn from_json(err: &serde_json::Error) -> Self {
        use serde_json::error::Category;
        let (kind, message) = match err.classify() {
            Category::Syntax => (
                OciConfigErrorKind::Syntax,
                "config.json is not valid JSON".to_owned(),
            ),
            Category::Eof => (
                OciConfigErrorKind::Eof,
                "config.json ended unexpectedly".to_owned(),
            ),
            Category::Io => (
                OciConfigErrorKind::Io,
                "failed to read config.json".to_owned(),
            ),
            Category::Data => match parse_limit_marker(&err.to_string()) {
                Some((field, limit)) => {
                    let message = format!("config.json exceeds the limit of {limit} for `{field}`");
                    (OciConfigErrorKind::LimitExceeded { field, limit }, message)
                }
                None => (
                    OciConfigErrorKind::Data,
                    "config.json has a missing field, a type mismatch, or an invalid value"
                        .to_owned(),
                ),
            },
        };
        let mut out = Self::new(ErrorCode::InvalidArgument, kind, message);
        if err.line() > 0 {
            out.line = Some(err.line());
            out.column = Some(err.column());
        }
        out
    }

    fn from_io(err: &io::Error) -> Self {
        let code = match err.kind() {
            io::ErrorKind::NotFound => ErrorCode::NotFound,
            io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            _ => ErrorCode::Internal,
        };
        Self::new(code, OciConfigErrorKind::Io, "failed to read config.json")
    }

    fn too_large() -> Self {
        Self::new(
            ErrorCode::InvalidArgument,
            OciConfigErrorKind::TooLarge,
            format!("config.json exceeds {CONFIG_MAX_BYTES} bytes"),
        )
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// エラーの分類。
    pub fn kind(&self) -> &OciConfigErrorKind {
        &self.kind
    }

    /// JSON 上の行番号（1 始まり。JSON パーサ由来のエラーのみ）。
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// JSON 上の桁番号（1 始まり。JSON パーサ由来のエラーのみ）。
    pub fn column(&self) -> Option<usize> {
        self.column
    }

    /// 固定文言のメッセージ（入力値を含まない）。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for OciConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(f, " (line {line}, column {column})")?;
        }
        Ok(())
    }
}

impl Error for OciConfigError {}

/// serde のエラー文字列から上限超過の目印を取り出す。
fn parse_limit_marker(text: &str) -> Option<(String, usize)> {
    let rest = text.get(text.find(LIMIT_TAG)?.checked_add(LIMIT_TAG.len())?..)?;
    let mut parts = rest.strip_prefix('|')?.splitn(2, '|');
    let field = parts.next()?;
    let digits: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some((field.to_owned(), digits.parse().ok()?))
}

// ---------------------------------------------------------------------------
// 上限付きデシリアライズ
// ---------------------------------------------------------------------------

/// フィールドごとの上限を型で運ぶマーカー。
trait Limit {
    const FIELD: &'static str;
    const MAX: usize;
}

fn limit_error<L: Limit, E: de::Error>() -> E {
    E::custom(format_args!("{LIMIT_TAG}|{}|{}", L::FIELD, L::MAX))
}

macro_rules! limits {
    ($($name:ident => ($field:literal, $max:expr)),* $(,)?) => {$(
        struct $name;
        impl Limit for $name {
            const FIELD: &'static str = $field;
            const MAX: usize = $max;
        }
    )*};
}

limits! {
    OciVersionLimit => ("ociVersion", CONFIG_MAX_OCI_VERSION_BYTES),
    RootPathLimit => ("root.path", CONFIG_MAX_PATH_BYTES),
    ArgsLimit => ("process.args", CONFIG_MAX_ARGS),
    ArgLimit => ("process.args[]", CONFIG_MAX_STRING_BYTES),
    EnvLimit => ("process.env", CONFIG_MAX_ENV),
    EnvItemLimit => ("process.env[]", CONFIG_MAX_STRING_BYTES),
    CwdLimit => ("process.cwd", CONFIG_MAX_PATH_BYTES),
    GidsLimit => ("process.user.additionalGids", CONFIG_MAX_ADDITIONAL_GIDS),
    HostnameLimit => ("hostname", CONFIG_MAX_HOSTNAME_BYTES),
    MountsLimit => ("mounts", CONFIG_MAX_MOUNTS),
    MountDestLimit => ("mounts[].destination", CONFIG_MAX_PATH_BYTES),
    MountSourceLimit => ("mounts[].source", CONFIG_MAX_PATH_BYTES),
    MountTypeLimit => ("mounts[].type", MOUNT_TYPE_MAX_BYTES),
    MountOptionsLimit => ("mounts[].options", CONFIG_MAX_MOUNT_OPTIONS),
    MountOptionLimit => ("mounts[].options[]", CONFIG_MAX_PATH_BYTES),
    NamespacesLimit => ("linux.namespaces", CONFIG_MAX_NAMESPACES),
    NamespacePathLimit => ("linux.namespaces[].path", CONFIG_MAX_PATH_BYTES),
    UidMappingsLimit => ("linux.uidMappings", CONFIG_MAX_ID_MAPPINGS),
    GidMappingsLimit => ("linux.gidMappings", CONFIG_MAX_ID_MAPPINGS),
}

/// 件数上限付きの配列。`L::MAX` 件を超える要素を読んだ時点で中断する。
struct Bounded<T, L>(Vec<T>, PhantomData<L>);

impl<'de, T: Deserialize<'de>, L: Limit> Deserialize<'de> for Bounded<T, L> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor<T, L>(PhantomData<(T, L)>);

        impl<'de, T: Deserialize<'de>, L: Limit> Visitor<'de> for SeqVisitor<T, L> {
            type Value = Bounded<T, L>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // size_hint は使わない（入力由来の値で事前確保しない）。
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<T>()? {
                    if items.len() >= L::MAX {
                        return Err(limit_error::<L, A::Error>());
                    }
                    items.push(item);
                }
                Ok(Bounded(items, PhantomData))
            }
        }

        deserializer.deserialize_seq(SeqVisitor(PhantomData))
    }
}

/// バイト長上限付きの文字列。上限を超える文字列はコピー（確保）せずに拒否する。
struct BoundedStr<L>(String, PhantomData<L>);

impl<'de, L: Limit> Deserialize<'de> for BoundedStr<L> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrVisitor<L>(PhantomData<L>);

        impl<L: Limit> Visitor<'_> for StrVisitor<L> {
            type Value = BoundedStr<L>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() > L::MAX {
                    return Err(limit_error::<L, E>());
                }
                Ok(BoundedStr(v.to_owned(), PhantomData))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                if v.len() > L::MAX {
                    return Err(limit_error::<L, E>());
                }
                Ok(BoundedStr(v, PhantomData))
            }
        }

        deserializer.deserialize_str(StrVisitor(PhantomData))
    }
}

fn strings<L: Limit, I: Limit>(list: Option<Bounded<BoundedStr<I>, L>>) -> Vec<String> {
    list.map(|b| b.0.into_iter().map(|s| s.0).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// raw 層（非公開。JSON の形をそのまま受ける）
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    oci_version: BoundedStr<OciVersionLimit>,
    root: RawRoot,
    #[serde(default)]
    process: Option<RawProcess>,
    #[serde(default)]
    hostname: Option<BoundedStr<HostnameLimit>>,
    #[serde(default)]
    mounts: Option<Bounded<RawMount, MountsLimit>>,
    #[serde(default)]
    linux: Option<RawLinux>,
}

#[derive(Deserialize)]
struct RawRoot {
    path: BoundedStr<RootPathLimit>,
    #[serde(default)]
    readonly: bool,
}

#[derive(Deserialize)]
struct RawProcess {
    #[serde(default)]
    terminal: bool,
    user: RawUser,
    args: Bounded<BoundedStr<ArgLimit>, ArgsLimit>,
    #[serde(default)]
    env: Option<Bounded<BoundedStr<EnvItemLimit>, EnvLimit>>,
    cwd: BoundedStr<CwdLimit>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUser {
    uid: u32,
    gid: u32,
    #[serde(default)]
    additional_gids: Option<Bounded<u32, GidsLimit>>,
}

#[derive(Deserialize)]
struct RawMount {
    destination: BoundedStr<MountDestLimit>,
    #[serde(default, rename = "type")]
    fs_type: Option<BoundedStr<MountTypeLimit>>,
    #[serde(default)]
    source: Option<BoundedStr<MountSourceLimit>>,
    #[serde(default)]
    options: Option<Bounded<BoundedStr<MountOptionLimit>, MountOptionsLimit>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLinux {
    #[serde(default)]
    namespaces: Option<Bounded<RawNamespace, NamespacesLimit>>,
    #[serde(default)]
    uid_mappings: Option<Bounded<RawIdMapping, UidMappingsLimit>>,
    #[serde(default)]
    gid_mappings: Option<Bounded<RawIdMapping, GidMappingsLimit>>,
}

#[derive(Deserialize)]
struct RawNamespace {
    #[serde(rename = "type")]
    kind: NamespaceKind,
    #[serde(default)]
    path: Option<BoundedStr<NamespacePathLimit>>,
}

#[derive(Deserialize)]
struct RawIdMapping {
    #[serde(rename = "containerID")]
    container_id: u32,
    #[serde(rename = "hostID")]
    host_id: u32,
    size: u32,
}

// ---------------------------------------------------------------------------
// 公開型（検証済み）
// ---------------------------------------------------------------------------

/// 検証済みの OCI Runtime Spec バージョン（`1.x` 系のみ受理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciVersion(String);

impl OciVersion {
    fn parse(value: String) -> Result<Self, OciConfigError> {
        let valid = value.strip_prefix("1.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        });
        if valid {
            Ok(Self(value))
        } else {
            Err(OciConfigError::invalid("ociVersion"))
        }
    }

    /// バージョン文字列（例: `1.2.0`）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `root`（コンテナの rootfs）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciRoot {
    path: PathBuf,
    readonly: bool,
}

impl OciRoot {
    /// rootfs のパス（bundle からの相対または絶対。解決は create 側の責務）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// rootfs を読み取り専用にするか。
    pub fn readonly(&self) -> bool {
        self.readonly
    }
}

/// `process.user`。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciUser {
    uid: u32,
    gid: u32,
    additional_gids: Vec<u32>,
}

impl OciUser {
    /// コンテナ内の UID。
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// コンテナ内の GID。
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// 補助グループ ID。
    pub fn additional_gids(&self) -> &[u32] {
        &self.additional_gids
    }
}

/// `process`。`args` は 1 件以上、`cwd` は `/` 始まりであることを検証済み。
///
/// `env` の `KEY=VALUE` 形式・NUL 検査は `exec::Entrypoint::new` が担う（ここでは件数と長さのみ）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciProcess {
    terminal: bool,
    user: OciUser,
    args: Vec<String>,
    env: Vec<String>,
    cwd: PathBuf,
}

impl OciProcess {
    /// 端末を割り当てるか。
    pub fn terminal(&self) -> bool {
        self.terminal
    }

    /// 実行ユーザー。
    pub fn user(&self) -> &OciUser {
        &self.user
    }

    /// 実行するコマンドと引数（1 件以上）。
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// 環境変数（未検証の `KEY=VALUE` 文字列）。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// 作業ディレクトリ（コンテナ内の絶対パス）。
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }
}

/// `mounts[]` の 1 件。
///
/// `destination` は未検証のパス値で、rootfs 配下への正規化と `..` 等の拒否は TASK-29.1.2 で行う。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciMount {
    destination: PathBuf,
    fs_type: Option<String>,
    source: Option<PathBuf>,
    options: Vec<String>,
}

impl OciMount {
    /// マウント先（未検証。TASK-29.1.2 の検証を経て使うこと）。
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// ファイルシステム種別。
    pub fn fs_type(&self) -> Option<&str> {
        self.fs_type.as_deref()
    }

    /// マウント元。
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// マウントオプション。
    pub fn options(&self) -> &[String] {
        &self.options
    }
}

/// `linux.namespaces[].type`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NamespaceKind {
    /// PID namespace。
    Pid,
    /// ネットワーク namespace。
    Network,
    /// マウント namespace。
    Mount,
    /// IPC namespace。
    Ipc,
    /// UTS namespace。
    Uts,
    /// ユーザー namespace。
    User,
    /// cgroup namespace。
    Cgroup,
    /// 時刻 namespace。
    Time,
}

/// `linux.namespaces[]` の 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciNamespace {
    kind: NamespaceKind,
    path: Option<PathBuf>,
}

impl OciNamespace {
    /// namespace の種別。
    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }

    /// 既存 namespace に参加する場合のパス。
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// `linux.uidMappings` / `gidMappings` の 1 件。`size` は 1 以上を検証済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciIdMapping {
    container_id: u32,
    host_id: u32,
    size: u32,
}

impl OciIdMapping {
    /// コンテナ側の開始 ID。
    pub fn container_id(&self) -> u32 {
        self.container_id
    }

    /// ホスト側の開始 ID。
    pub fn host_id(&self) -> u32 {
        self.host_id
    }

    /// 範囲の長さ。
    pub fn size(&self) -> u32 {
        self.size
    }
}

/// 検証済みの `config.json`。生成経路は [`load_config`] / [`parse_config_bytes`] のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciConfig {
    oci_version: OciVersion,
    root: OciRoot,
    process: Option<OciProcess>,
    hostname: Option<String>,
    mounts: Vec<OciMount>,
    namespaces: Vec<OciNamespace>,
    uid_mappings: Vec<OciIdMapping>,
    gid_mappings: Vec<OciIdMapping>,
}

impl OciConfig {
    /// `ociVersion`。
    pub fn oci_version(&self) -> &OciVersion {
        &self.oci_version
    }

    /// `root`。
    pub fn root(&self) -> &OciRoot {
        &self.root
    }

    /// `process`（省略可。create 時に必須とするかは TASK-29.2 で判断する）。
    pub fn process(&self) -> Option<&OciProcess> {
        self.process.as_ref()
    }

    /// `hostname`（形式の検証は `exec::Hostname` 側で行う）。
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// `mounts`。
    pub fn mounts(&self) -> &[OciMount] {
        &self.mounts
    }

    /// `linux.namespaces`。
    pub fn namespaces(&self) -> &[OciNamespace] {
        &self.namespaces
    }

    /// `linux.uidMappings`。
    pub fn uid_mappings(&self) -> &[OciIdMapping] {
        &self.uid_mappings
    }

    /// `linux.gidMappings`。
    pub fn gid_mappings(&self) -> &[OciIdMapping] {
        &self.gid_mappings
    }
}

// ---------------------------------------------------------------------------
// 検証（raw 層 → 公開型）
// ---------------------------------------------------------------------------

/// パス文字列の共通検証（空・NUL を拒否）。
fn checked_path(value: String, field: &'static str) -> Result<PathBuf, OciConfigError> {
    if value.is_empty() || value.contains('\0') {
        return Err(OciConfigError::invalid(field));
    }
    Ok(PathBuf::from(value))
}

fn convert_mappings<L: Limit>(
    list: Option<Bounded<RawIdMapping, L>>,
    field: &'static str,
) -> Result<Vec<OciIdMapping>, OciConfigError> {
    list.map(|b| b.0)
        .unwrap_or_default()
        .into_iter()
        .map(|m| {
            if m.size == 0 {
                return Err(OciConfigError::invalid(field));
            }
            Ok(OciIdMapping {
                container_id: m.container_id,
                host_id: m.host_id,
                size: m.size,
            })
        })
        .collect()
}

fn convert_process(raw: RawProcess) -> Result<OciProcess, OciConfigError> {
    let args = strings(Some(raw.args));
    if args.is_empty() {
        return Err(OciConfigError::invalid("process.args"));
    }
    // コンテナ内パスは Linux 表記なので、ホスト OS の `is_absolute` ではなく先頭 `/` で判定する。
    if !raw.cwd.0.starts_with('/') {
        return Err(OciConfigError::invalid("process.cwd"));
    }
    let cwd = checked_path(raw.cwd.0, "process.cwd")?;
    Ok(OciProcess {
        terminal: raw.terminal,
        user: OciUser {
            uid: raw.user.uid,
            gid: raw.user.gid,
            additional_gids: raw.user.additional_gids.map(|b| b.0).unwrap_or_default(),
        },
        args,
        env: strings(raw.env),
        cwd,
    })
}

fn convert_mount(raw: RawMount) -> Result<OciMount, OciConfigError> {
    Ok(OciMount {
        destination: checked_path(raw.destination.0, "mounts[].destination")?,
        fs_type: raw.fs_type.map(|s| s.0),
        source: raw
            .source
            .map(|s| checked_path(s.0, "mounts[].source"))
            .transpose()?,
        options: strings(raw.options),
    })
}

impl RawConfig {
    fn validate(self) -> Result<OciConfig, OciConfigError> {
        let oci_version = OciVersion::parse(self.oci_version.0)?;
        let root = OciRoot {
            path: checked_path(self.root.path.0, "root.path")?,
            readonly: self.root.readonly,
        };
        let process = self.process.map(convert_process).transpose()?;
        let mounts = self
            .mounts
            .map(|b| b.0)
            .unwrap_or_default()
            .into_iter()
            .map(convert_mount)
            .collect::<Result<Vec<_>, _>>()?;

        let (mut namespaces, mut uid_mappings, mut gid_mappings) =
            (Vec::new(), Vec::new(), Vec::new());
        if let Some(linux) = self.linux {
            for ns in linux.namespaces.map(|b| b.0).unwrap_or_default() {
                namespaces.push(OciNamespace {
                    kind: ns.kind,
                    path: ns
                        .path
                        .map(|p| checked_path(p.0, "linux.namespaces[].path"))
                        .transpose()?,
                });
            }
            uid_mappings = convert_mappings(linux.uid_mappings, "linux.uidMappings")?;
            gid_mappings = convert_mappings(linux.gid_mappings, "linux.gidMappings")?;
        }

        Ok(OciConfig {
            oci_version,
            root,
            process,
            hostname: self.hostname.map(|h| h.0),
            mounts,
            namespaces,
            uid_mappings,
            gid_mappings,
        })
    }
}

// ---------------------------------------------------------------------------
// 公開関数
// ---------------------------------------------------------------------------

/// メモリ上の `config.json` をパースして検証する。
///
/// `bytes` が [`CONFIG_MAX_BYTES`] を超える場合は解析せず `TooLarge` を返す。
pub fn parse_config_bytes(bytes: &[u8]) -> Result<OciConfig, OciConfigError> {
    if bytes.len() > CONFIG_MAX_BYTES {
        return Err(OciConfigError::too_large());
    }
    let raw: RawConfig =
        serde_json::from_slice(bytes).map_err(|e| OciConfigError::from_json(&e))?;
    raw.validate()
}

/// ファイルから `config.json` を読み込んで検証する（TASK-29.2 の create が bundle から呼ぶ想定）。
///
/// サイズは `metadata` で先に拒否するが、それを信用せず読み込み量も [`CONFIG_MAX_BYTES`] + 1 で
/// 打ち切る（読み込み中にファイルが伸びる場合への対処）。
pub fn load_config(path: &Path) -> Result<OciConfig, OciConfigError> {
    let file = File::open(path).map_err(|e| OciConfigError::from_io(&e))?;
    let len = file
        .metadata()
        .map_err(|e| OciConfigError::from_io(&e))?
        .len();
    if len > CONFIG_MAX_BYTES as u64 {
        return Err(OciConfigError::too_large());
    }
    let capacity = usize::try_from(len).unwrap_or(0).min(CONFIG_MAX_BYTES);
    let mut buf = Vec::with_capacity(capacity);
    file.take(CONFIG_MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| OciConfigError::from_io(&e))?;
    parse_config_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn base() -> Value {
        json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": true},
            "process": {
                "terminal": false,
                "user": {"uid": 1000, "gid": 100, "additionalGids": [5, 6]},
                "args": ["/bin/sh", "-c", "true"],
                "env": ["PATH=/bin"],
                "cwd": "/work"
            },
            "hostname": "box",
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid"]}
            ],
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "network", "path": "/run/netns/a"}],
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
                "gidMappings": [{"containerID": 0, "hostID": 100, "size": 1}]
            }
        })
    }

    fn parse(v: &Value) -> Result<OciConfig, OciConfigError> {
        parse_config_bytes(&serde_json::to_vec(v).expect("serialize"))
    }

    fn err_of(v: &Value) -> OciConfigError {
        parse(v).expect_err("expected an error")
    }

    #[test]
    fn oci4_valid_config_is_parsed_with_concrete_values() {
        let cfg = parse(&base()).expect("valid");
        assert_eq!(cfg.oci_version().as_str(), "1.2.0");
        assert_eq!(cfg.root().path(), Path::new("rootfs"));
        assert!(cfg.root().readonly());
        let p = cfg.process().expect("process");
        assert_eq!(p.args(), ["/bin/sh", "-c", "true"]);
        assert_eq!(p.env(), ["PATH=/bin"]);
        assert_eq!(p.cwd(), Path::new("/work"));
        assert_eq!((p.user().uid(), p.user().gid()), (1000, 100));
        assert_eq!(p.user().additional_gids(), [5, 6]);
        assert_eq!(cfg.hostname(), Some("box"));
        assert_eq!(cfg.mounts().len(), 1);
        assert_eq!(cfg.mounts()[0].destination(), Path::new("/proc"));
        assert_eq!(cfg.mounts()[0].fs_type(), Some("proc"));
        assert_eq!(cfg.mounts()[0].options(), ["nosuid"]);
        assert_eq!(cfg.namespaces()[0].kind(), NamespaceKind::Pid);
        assert_eq!(cfg.namespaces()[1].path(), Some(Path::new("/run/netns/a")));
        assert_eq!(cfg.uid_mappings()[0].host_id(), 1000);
        assert_eq!(cfg.gid_mappings()[0].size(), 1);
    }

    #[test]
    fn oci4_minimal_config_without_optional_sections() {
        let cfg = parse(&json!({"ociVersion": "1.0.0", "root": {"path": "/r"}})).expect("valid");
        assert!(cfg.process().is_none());
        assert!(cfg.mounts().is_empty());
        assert!(!cfg.root().readonly());
    }

    #[test]
    fn oci4_missing_required_fields_are_data_errors() {
        let removals: [&[&str]; 6] = [
            &["ociVersion"],
            &["root", "path"],
            &["process", "args"],
            &["process", "cwd"],
            &["process", "user", "uid"],
            &["mounts", "0", "destination"],
        ];
        for path in removals {
            let mut v = base();
            let mut cur = &mut v;
            for key in &path[..path.len() - 1] {
                cur = match key.parse::<usize>() {
                    Ok(i) => &mut cur[i],
                    Err(_) => &mut cur[*key],
                };
            }
            cur.as_object_mut()
                .expect("object")
                .remove(path[path.len() - 1]);
            let e = err_of(&v);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{path:?}");
            assert_eq!(*e.kind(), OciConfigErrorKind::Data, "{path:?}");
        }
    }

    #[test]
    fn oci4_type_mismatch_is_data_error() {
        let mut v = base();
        v["process"]["user"]["uid"] = json!("1000");
        assert_eq!(*err_of(&v).kind(), OciConfigErrorKind::Data);
        let mut v = base();
        v["process"]["args"] = json!({"a": 1});
        assert_eq!(*err_of(&v).kind(), OciConfigErrorKind::Data);
        let mut v = base();
        v["process"]["user"]["uid"] = json!(-1);
        assert_eq!(*err_of(&v).kind(), OciConfigErrorKind::Data);
    }

    #[test]
    fn oci4_semantic_violations_are_invalid() {
        let mut v = base();
        v["process"]["args"] = json!([]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::Invalid {
                field: "process.args"
            }
        );
        let mut v = base();
        v["process"]["cwd"] = json!("work");
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::Invalid {
                field: "process.cwd"
            }
        );
        let mut v = base();
        v["root"]["path"] = json!("");
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::Invalid { field: "root.path" }
        );
        let mut v = base();
        v["mounts"][0]["destination"] = json!("");
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::Invalid {
                field: "mounts[].destination"
            }
        );
        let mut v = base();
        v["linux"]["uidMappings"][0]["size"] = json!(0);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::Invalid {
                field: "linux.uidMappings"
            }
        );
    }

    #[test]
    fn oci4_oci_version_must_be_1x() {
        for bad in ["2.0.0", "", "1.", "1.0 0"] {
            let mut v = base();
            v["ociVersion"] = json!(bad);
            assert_eq!(
                *err_of(&v).kind(),
                OciConfigErrorKind::Invalid {
                    field: "ociVersion"
                },
                "{bad:?}"
            );
        }
    }

    #[test]
    fn oci4_unknown_namespace_type_is_rejected() {
        let mut v = base();
        v["linux"]["namespaces"] = json!([{"type": "bogus"}]);
        assert_eq!(*err_of(&v).kind(), OciConfigErrorKind::Data);
    }

    #[test]
    fn oci4_unknown_fields_are_ignored() {
        let mut v = base();
        v["annotations"] = json!({"a": "b"});
        v["linux"]["seccomp"] = json!({"defaultAction": "SCMP_ACT_ERRNO"});
        v["process"]["capabilities"] = json!({"bounding": ["CAP_KILL"]});
        assert!(parse(&v).is_ok());
    }

    #[test]
    fn oci4_array_count_limits_at_boundary() {
        let mut v = base();
        v["process"]["args"] = json!(vec!["a"; CONFIG_MAX_ARGS]);
        assert_eq!(
            parse(&v)
                .expect("at limit")
                .process()
                .expect("p")
                .args()
                .len(),
            4096
        );
        v["process"]["args"] = json!(vec!["a"; CONFIG_MAX_ARGS + 1]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "process.args".to_owned(),
                limit: 4096
            }
        );

        let mut v = base();
        v["mounts"] = json!(vec![json!({"destination": "/a"}); CONFIG_MAX_MOUNTS + 1]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "mounts".to_owned(),
                limit: 1024
            }
        );

        let mut v = base();
        v["linux"]["namespaces"] = json!(vec![json!({"type": "pid"}); CONFIG_MAX_NAMESPACES + 1]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "linux.namespaces".to_owned(),
                limit: 16
            }
        );

        let mut v = base();
        v["linux"]["gidMappings"] = json!(vec![
            json!({"containerID": 0, "hostID": 0, "size": 1});
            CONFIG_MAX_ID_MAPPINGS + 1
        ]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "linux.gidMappings".to_owned(),
                limit: 340
            }
        );
    }

    #[test]
    fn oci4_string_length_limits() {
        let mut v = base();
        v["process"]["args"] = json!(["a".repeat(CONFIG_MAX_STRING_BYTES + 1)]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "process.args[]".to_owned(),
                limit: CONFIG_MAX_STRING_BYTES
            }
        );
        let mut v = base();
        v["hostname"] = json!("h".repeat(CONFIG_MAX_HOSTNAME_BYTES + 1));
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "hostname".to_owned(),
                limit: 64
            }
        );
        let mut v = base();
        v["process"]["cwd"] = json!(format!("/{}", "d".repeat(CONFIG_MAX_PATH_BYTES)));
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "process.cwd".to_owned(),
                limit: 4096
            }
        );
    }

    #[test]
    fn oci4_total_bytes_limit() {
        let big = vec![b' '; CONFIG_MAX_BYTES + 1];
        let e = parse_config_bytes(&big).expect_err("too large");
        assert_eq!(*e.kind(), OciConfigErrorKind::TooLarge);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn oci4_duplicate_key_is_rejected() {
        let text = br#"{"ociVersion":"1.0.0","ociVersion":"1.0.1","root":{"path":"r"}}"#;
        assert_eq!(
            *parse_config_bytes(text).expect_err("dup").kind(),
            OciConfigErrorKind::Data
        );
    }

    #[test]
    fn oci4_deep_nesting_is_bounded_without_panic() {
        let depth = 200;
        let nested = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        // 型付きフィールド内の深いネスト（型不一致）は深く辿る前に拒否される。
        let text = format!(
            r#"{{"ociVersion":"1.0.0","root":{{"path":"r"}},"process":{{"user":{{"uid":0,"gid":0}},"args":{nested},"cwd":"/"}}}}"#
        );
        let e = parse_config_bytes(text.as_bytes()).expect_err("deep");
        assert_eq!(*e.kind(), OciConfigErrorKind::Data);
        // 未知フィールドの読み飛ばしは反復処理でスタックを消費せず、コストは入力バイト上限で抑えられる。
        let text = format!(r#"{{"ociVersion":"1.0.0","root":{{"path":"r"}},"x":{nested}}}"#);
        assert!(parse_config_bytes(text.as_bytes()).is_ok());
    }

    #[test]
    fn oci4_syntax_errors_carry_position() {
        let e = parse_config_bytes(b"{\"ociVersion\": }").expect_err("syntax");
        assert_eq!(*e.kind(), OciConfigErrorKind::Syntax);
        assert_eq!((e.line(), e.column()), (Some(1), Some(16)));
        let e = parse_config_bytes(b"{\"ociVersion\":").expect_err("eof");
        assert_eq!(*e.kind(), OciConfigErrorKind::Eof);
        let e = parse_config_bytes(b"").expect_err("empty");
        assert_eq!(*e.kind(), OciConfigErrorKind::Eof);
    }

    #[test]
    fn oci4_error_does_not_leak_input_values() {
        let mut v = base();
        v["process"]["env"] = json!(["TOKEN=dummy-secret"]);
        v["process"]["user"]["uid"] = json!("dummy-secret");
        let e = err_of(&v);
        assert!(!e.to_string().contains("dummy-secret"));
        assert!(!format!("{e:?}").contains("dummy-secret"));
        let mut v = base();
        v["linux"]["namespaces"] = json!([{"type": "dummy-secret"}]);
        let e = err_of(&v);
        assert!(!e.to_string().contains("dummy-secret"));
        assert!(!format!("{e:?}").contains("dummy-secret"));
    }

    #[test]
    fn oci4_load_config_reads_file_and_reports_errors() {
        let dir = std::env::temp_dir().join(format!("fandhe-oci-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");

        let ok = dir.join("config.json");
        std::fs::write(&ok, serde_json::to_vec(&base()).expect("ser")).expect("write");
        assert_eq!(
            load_config(&ok).expect("load").oci_version().as_str(),
            "1.2.0"
        );

        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; CONFIG_MAX_BYTES + 1]).expect("write");
        assert_eq!(
            *load_config(&big).expect_err("big").kind(),
            OciConfigErrorKind::TooLarge
        );

        let missing = load_config(&dir.join("missing.json")).expect_err("missing");
        assert_eq!(missing.code(), ErrorCode::NotFound);
        assert_eq!(*missing.kind(), OciConfigErrorKind::Io);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `exec::Entrypoint` の上限との同値を照合し、片方だけ変更されるドリフトを防ぐ。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_limits_match_exec_entrypoint_limits() {
        use crate::exec::{ENTRYPOINT_MAX_ARGS, ENTRYPOINT_MAX_ENV, ENTRYPOINT_MAX_STRING_BYTES};
        assert_eq!(CONFIG_MAX_ARGS, ENTRYPOINT_MAX_ARGS);
        assert_eq!(CONFIG_MAX_ENV, ENTRYPOINT_MAX_ENV);
        assert_eq!(CONFIG_MAX_STRING_BYTES, ENTRYPOINT_MAX_STRING_BYTES);
    }
}
