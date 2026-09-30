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
//!   ただし既知フィールドの重複キー・必須欠落・型不一致・未知の namespace type はエラーにする。
//!   既知フィールドの省略はキーが無い場合に限り、キーがあって値が `null` のものは省略とみなさず
//!   型不一致（`Data`）として拒否する（OCI の JSON Schema に `null` を許すフィールドが無いため。
//!   根拠は `present` を参照）。object 型のフィールドに配列を書く位置指定（serde の derive が既定で
//!   受理する形）と、列挙値（namespace type）の型不一致も同様に `Data` として拒否する。
//!   未知プロパティ（読み飛ばす対象）内の重複キーは検出せず受理する（無視する値であり、
//!   解釈結果に影響しないため。既知フィールドの重複は serde の重複検出で拒否される）。
//!
//! # 未解釈のセクション（REPAIR-3）
//!
//! 次のセクションはパース時に無視しているだけで、適用済みではない（fail-open にならない扱いは
//! TASK-29.2 の計画で決める）: `process.capabilities`・`process.rlimits`・`process.noNewPrivileges`
//! （SEC-1・TASK-27.4.3 系）、`linux.seccomp`（CORE-5・TASK-38）、`linux.resources`
//! （CORE-3/4・TASK-32〜）、`linux.maskedPaths` / `readonlyPaths`、`mounts[].uidMappings` /
//! `gidMappings`（idmapped mount）、`hooks`、`annotations`。
//!
//! # 実行ファイルの検証
//!
//! `process.args` は 1 件以上であることだけを検証する。`args[0]` の空文字・実行可能性の検証は
//! `exec::Entrypoint` 側の担当（本モジュールでは行わない）。
//!
//! # 入力上限（DoS 防止）
//!
//! 読み込み前にバイト長を [`CONFIG_MAX_BYTES`] で制限し、デシリアライズ中は配列の件数と文字列の
//! 長さを上限超過の時点で中断する（上限を超えた要素は型として組み立てず、件数分のアロケーションを
//! しない。エスケープ展開用の serde_json の作業バッファは入力全体の上限で抑える）。ネスト深さは
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
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::traits::ErrorCode;

/// `config.json` 全体の最大バイト長（4 MiB）。`args` / `env` の合計上限（1 MiB。
/// `exec::ENTRYPOINT_MAX_TOTAL_BYTES`）に JSON エスケープ分とその他フィールドの余裕を加えた値。
/// 合計上限そのもの（実行パスを含む）は本モジュールでは検証せず、`exec::Entrypoint::new` が担う。
pub const CONFIG_MAX_BYTES: usize = 4 << 20;
/// `process.args` の最大件数（`exec::ENTRYPOINT_MAX_ARGS` と同値）。
pub const CONFIG_MAX_ARGS: usize = 4096;
/// `process.env` の最大件数（`exec::ENTRYPOINT_MAX_ENV` と同値）。
pub const CONFIG_MAX_ENV: usize = 4096;
/// `args` / `env` の 1 要素の最大バイト長（NUL 終端を含まない。131071）。
///
/// `exec::ENTRYPOINT_MAX_STRING_BYTES`（Linux の `MAX_ARG_STRLEN` = 131072）は NUL 終端を含めた
/// 上限なので、文字列長としてはその 1 バイト手前が上限になる。同値にすると上限ちょうどの要素が
/// パースを通っても `Entrypoint::new` で拒否されるため、NUL の 1 バイトを差し引いて揃える。
pub const CONFIG_MAX_STRING_BYTES: usize = 131_071;
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
                    (
                        OciConfigErrorKind::LimitExceeded {
                            field: field.to_owned(),
                            limit,
                        },
                        message,
                    )
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

    /// ファイル操作の失敗を分類する。
    ///
    /// 同じ入力に 3 OS で同じ `code` を返すため、途中の要素が通常ファイルのパス
    /// （`<file>/config.json`）は `NotFound` に揃える。Linux / macOS は `ENOTDIR`
    /// （`NotADirectory`）、Windows は `ERROR_PATH_NOT_FOUND`（`NotFound`）を返すため。
    fn from_io(err: &io::Error) -> Self {
        let code = match err.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => ErrorCode::NotFound,
            io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            _ => ErrorCode::Internal,
        };
        Self::new(code, OciConfigErrorKind::Io, "failed to read config.json")
    }

    /// 通常ファイルでない `config.json`（ディレクトリ・FIFO・デバイス等）。open 前の `stat` と
    /// open 後の `fstat` のどちらで判明しても、全 OS でこの 1 か所の分類
    /// （`InvalidArgument` / `Invalid { field: "config.json" }`）に揃える。
    fn not_regular_file() -> Self {
        Self::invalid("config.json")
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
///
/// 入力値由来の文字列（unknown variant / invalid type のメッセージ等）による偽装を防ぐため、
/// メッセージ全体が `LIMIT_TAG|<field>|<n>` の形で始まり、かつ `field` が既知の `LIMIT_TABLE` に
/// あるものだけを採用する。返す上限値は表側の値で、メッセージ中の数値は使わない。
fn parse_limit_marker(text: &str) -> Option<(&'static str, usize)> {
    let rest = text.strip_prefix(LIMIT_TAG)?.strip_prefix('|')?;
    let field = rest.split('|').next()?;
    LIMIT_TABLE
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(name, max)| (*name, *max))
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
    )*

        /// 既知の上限（フィールド名と上限値）。`parse_limit_marker` の照合表。
        const LIMIT_TABLE: &[(&str, usize)] = &[$(($field, $max)),*];
    };
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

/// 件数上限付きの配列。`L::MAX` 件を読んだ後に次の要素があれば、その要素を型 `T` として
/// デシリアライズ（確保）せずに中断する。
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
                loop {
                    if items.len() >= L::MAX {
                        // 上限に達したら次の要素は `IgnoredAny` で読み飛ばし（値を確保しない）、
                        // 有無だけで判定する。上限超過の要素を `T` として組み立てないため、その
                        // 要素が巨大な文字列・object でも確保は発生しない。
                        return match seq.next_element::<de::IgnoredAny>()? {
                            Some(_) => Err(limit_error::<L, A::Error>()),
                            None => Ok(Bounded(items, PhantomData)),
                        };
                    }
                    match seq.next_element::<T>()? {
                        Some(item) => items.push(item),
                        None => return Ok(Bounded(items, PhantomData)),
                    }
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor(PhantomData))
    }
}

/// バイト長上限付きの文字列。上限を超える文字列は `String` へコピー（確保）せずに拒否する。
///
/// エスケープを含まない文字列は入力バッファから借用して長さを判定する。エスケープを含む文字列は
/// serde_json が内部の作業バッファへ展開してから渡すため、その一時確保は判定より前に起きるが、
/// 大きさは入力全体の上限（[`CONFIG_MAX_BYTES`]）で抑えられ、作業バッファは再利用される。
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

/// 省略可能な既知フィールドを「省略」と「`null`」で区別して読む（OCI-4）。
///
/// `#[serde(default, deserialize_with = "present")]` と組み合わせ、キーが無い場合だけ `None` にする。
/// キーがある場合は `deserialize_option` を経由せず中身の型で直接読むため、`null` は中身の型
/// （object / array / string）に対する型不一致として serde_json が拒否し、`Data` エラーになる。
///
/// 根拠: OCI Runtime Spec の JSON Schema（`schema/config-schema.json`・`defs.json`・
/// `config-linux.json`・`defs-linux.json`）は、本パーサが解釈するフィールドのいずれにも `null` 型を
/// 許しておらず（object / array / string / boolean / uint32 のみ）、`null` が「省略」や「既定値」の
/// 意味を持つフィールドは無い。`null` を省略扱いすると、例えば `linux: null` の誤りが黙って
/// 「namespace・ID マッピング無し」に変わるため、fail-closed に拒否する。
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// JSON の object だけを受ける struct の読み込み（OCI-4）。
///
/// serde が derive した struct の実装は、serde_json では配列も「フィールドを宣言順に並べたもの」と
/// して受理する（例: `"root": ["rootfs", true]`・`"linux": []`）。OCI の JSON Schema でこれらは
/// `object` 型なので、map として読んでから中身を derive 実装へ渡し、配列・`null`・スカラーは
/// 型不一致（`Data`）として拒否する。重複キー検出・未知プロパティの無視・再帰上限は derive 実装と
/// serde_json の挙動のまま変わらない。raw 層の struct はトップレベルも含めて必ずこれで包む。
struct Obj<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Obj<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjVisitor<T> {
            type Value = Obj<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Obj)
            }
        }

        deserializer.deserialize_map(ObjVisitor(PhantomData))
    }
}

// ---------------------------------------------------------------------------
// raw 層（非公開。JSON の形をそのまま受ける）
//
// 省略可能な既知フィールドは必ず `#[serde(default, deserialize_with = "present")]` を付ける
// （`null` を省略として受理しないため）。`#[serde(default)] bool` は serde_json が `null` を
// 型不一致として拒否するため `present` を要しない。struct 型のフィールド・配列要素は `Obj` で包み
// （配列を struct として受理しないため）、列挙値は文字列として読む（`RawNamespaceKind`）。
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    oci_version: BoundedStr<OciVersionLimit>,
    root: Obj<RawRoot>,
    #[serde(default, deserialize_with = "present")]
    process: Option<Obj<RawProcess>>,
    #[serde(default, deserialize_with = "present")]
    hostname: Option<BoundedStr<HostnameLimit>>,
    #[serde(default, deserialize_with = "present")]
    mounts: Option<Bounded<Obj<RawMount>, MountsLimit>>,
    #[serde(default, deserialize_with = "present")]
    linux: Option<Obj<RawLinux>>,
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
    user: Obj<RawUser>,
    args: Bounded<BoundedStr<ArgLimit>, ArgsLimit>,
    #[serde(default, deserialize_with = "present")]
    env: Option<Bounded<BoundedStr<EnvItemLimit>, EnvLimit>>,
    cwd: BoundedStr<CwdLimit>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUser {
    uid: u32,
    gid: u32,
    #[serde(default, deserialize_with = "present")]
    additional_gids: Option<Bounded<u32, GidsLimit>>,
}

#[derive(Deserialize)]
struct RawMount {
    destination: BoundedStr<MountDestLimit>,
    #[serde(default, rename = "type", deserialize_with = "present")]
    fs_type: Option<BoundedStr<MountTypeLimit>>,
    #[serde(default, deserialize_with = "present")]
    source: Option<BoundedStr<MountSourceLimit>>,
    #[serde(default, deserialize_with = "present")]
    options: Option<Bounded<BoundedStr<MountOptionLimit>, MountOptionsLimit>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLinux {
    #[serde(default, deserialize_with = "present")]
    namespaces: Option<Bounded<Obj<RawNamespace>, NamespacesLimit>>,
    #[serde(default, deserialize_with = "present")]
    uid_mappings: Option<Bounded<Obj<RawIdMapping>, UidMappingsLimit>>,
    #[serde(default, deserialize_with = "present")]
    gid_mappings: Option<Bounded<Obj<RawIdMapping>, GidMappingsLimit>>,
}

#[derive(Deserialize)]
struct RawNamespace {
    #[serde(rename = "type")]
    kind: RawNamespaceKind,
    #[serde(default, deserialize_with = "present")]
    path: Option<BoundedStr<NamespacePathLimit>>,
}

/// OCI Runtime Spec が定める `linux.namespaces[].type` の値（OCI-4）。
const NAMESPACE_TYPES: &[&str] = &[
    "pid", "network", "mount", "ipc", "uts", "user", "cgroup", "time",
];

/// `linux.namespaces[].type` を文字列として読む。
///
/// derive した unit variant の enum は、serde_json では文字列以外（`null`・数値・配列等）を
/// `ExpectedSomeValue`（`Syntax`）に分類するため、構文は正しい JSON の型不一致が「構文エラー」に
/// なる。文字列として読めば型不一致は `invalid type`、未知の値は `unknown variant` となり、
/// どちらも他フィールドと同じ `Data` に揃う。文字列は借用で照合し、確保しない。
struct RawNamespaceKind(NamespaceKind);

impl<'de> Deserialize<'de> for RawNamespaceKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KindVisitor;

        impl Visitor<'_> for KindVisitor {
            type Value = RawNamespaceKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a namespace type string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let kind = match v {
                    "pid" => NamespaceKind::Pid,
                    "network" => NamespaceKind::Network,
                    "mount" => NamespaceKind::Mount,
                    "ipc" => NamespaceKind::Ipc,
                    "uts" => NamespaceKind::Uts,
                    "user" => NamespaceKind::User,
                    "cgroup" => NamespaceKind::Cgroup,
                    "time" => NamespaceKind::Time,
                    _ => return Err(E::unknown_variant(v, NAMESPACE_TYPES)),
                };
                Ok(RawNamespaceKind(kind))
            }
        }

        deserializer.deserialize_str(KindVisitor)
    }
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

/// SemVer 2.0.0 の識別子列（`.` 区切り・各要素は非空の `[0-9A-Za-z-]`）か判定する。
/// `numeric_no_leading_zero` が真なら、数字のみの要素の先頭ゼロを拒否する（pre-release 用）。
fn is_semver_identifiers(text: &str, numeric_no_leading_zero: bool) -> bool {
    !text.is_empty()
        && text.split('.').all(|id| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(numeric_no_leading_zero
                    && id.len() > 1
                    && id.starts_with('0')
                    && id.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// `1.MINOR.PATCH[-prerelease][+build]` の構文か判定する（OCI Runtime Spec の `ociVersion` は
/// SemVer 2.0.0。OCI-4）。`1.foo`・`1..2`・`1.0` 等は拒否する。
fn is_oci_1x_semver(value: &str) -> bool {
    let (rest, build) = match value.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (value, None),
    };
    if build.is_some_and(|b| !is_semver_identifiers(b, false)) {
        return false;
    }
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    if pre.is_some_and(|p| !is_semver_identifiers(p, true)) {
        return false;
    }
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let numeric = |t: &str| {
        !t.is_empty()
            && t.bytes().all(|b| b.is_ascii_digit())
            && (t.len() == 1 || !t.starts_with('0'))
    };
    major == "1" && numeric(minor) && numeric(patch)
}

/// 検証済みの OCI Runtime Spec バージョン（`1.x` 系のみ受理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciVersion(String);

impl OciVersion {
    fn parse(value: String) -> Result<Self, OciConfigError> {
        if is_oci_1x_semver(&value) {
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
/// `env` の `KEY=VALUE` 形式・NUL 検査と、実行パスを含む合計長の上限は `exec::Entrypoint::new` が
/// 担う（ここでは件数と 1 要素の長さのみ）。
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    list: Option<Bounded<Obj<RawIdMapping>, L>>,
    field: &'static str,
) -> Result<Vec<OciIdMapping>, OciConfigError> {
    list.map(|b| b.0)
        .unwrap_or_default()
        .into_iter()
        .map(|Obj(m)| {
            // 範囲の排他的終端（先頭 ID + size）が 2^32 以下であることを container 側・host 側の双方で
            // 検証する。u64 に広げて比較し、u32::MAX 単独の範囲（終端がちょうど 2^32）も受理する。
            let fits = |start: u32| u64::from(start) + u64::from(m.size) <= 1u64 << 32;
            if m.size == 0 || !fits(m.container_id) || !fits(m.host_id) {
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
            uid: raw.user.0.uid,
            gid: raw.user.0.gid,
            additional_gids: raw.user.0.additional_gids.map(|b| b.0).unwrap_or_default(),
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
            path: checked_path(self.root.0.path.0, "root.path")?,
            readonly: self.root.0.readonly,
        };
        let process = self.process.map(|Obj(p)| convert_process(p)).transpose()?;
        let mounts = self
            .mounts
            .map(|b| b.0)
            .unwrap_or_default()
            .into_iter()
            .map(|Obj(m)| convert_mount(m))
            .collect::<Result<Vec<_>, _>>()?;

        let (mut namespaces, mut uid_mappings, mut gid_mappings) =
            (Vec::new(), Vec::new(), Vec::new());
        if let Some(Obj(linux)) = self.linux {
            for Obj(ns) in linux.namespaces.map(|b| b.0).unwrap_or_default() {
                namespaces.push(OciNamespace {
                    kind: ns.kind.0,
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
    let Obj(raw) = serde_json::from_slice::<Obj<RawConfig>>(bytes)
        .map_err(|e| OciConfigError::from_json(&e))?;
    raw.validate()
}

/// `O_NONBLOCK`（`open(2)` フラグ）を値で持つ環境の条件。
///
/// Linux は `0o4000` を使うアーキテクチャ（x86 / x86_64 / arm / aarch64 / riscv / powerpc / s390x /
/// loongarch64）、BSD 系（macOS・iOS・FreeBSD・NetBSD・OpenBSD・DragonFly）は `0x4`。
/// mips・sparc 等は値が異なるためここに含めず、`O_NONBLOCK` 無しで開く（事前 `stat` のみで防ぐ）。
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;

/// 事前 `stat` で通常ファイルと確認済みのパスを開く（REPAIR-5）。
///
/// 種別の確認そのものは呼び出し側（[`load_config`]）が全 OS 共通で行う（open 前の `stat` と open 後の
/// `fstat`）。ここでは `O_NONBLOCK` を指定できる環境に限り非ブロッキングで開き、`stat` 後に FIFO へ
/// 差し替えられても `open` が戻るようにする（差し替えは open 後の `fstat` で検出する）。それ以外の
/// 環境（Windows・mips / sparc の Linux 等）は通常の open で、Windows には POSIX の FIFO が無く、
/// その他は `stat` 後の差し替えによる競合窓が残るが、事前 `stat` の fail-closed な拒否で通常経路の
/// 無期限ブロックは防ぐ。
fn open_checked_candidate(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86",
                target_arch = "x86_64",
                target_arch = "arm",
                target_arch = "aarch64",
                target_arch = "riscv32",
                target_arch = "riscv64",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "s390x",
                target_arch = "loongarch64"
            )
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NONBLOCK);
    }
    opts.open(path)
}

/// ファイルから `config.json` を読み込んで検証する（TASK-29.2 の create が bundle から呼ぶ想定）。
///
/// 通常ファイル以外（ディレクトリ・FIFO・デバイス等）は読み込みが無期限にブロックし得るため拒否する
/// （REPAIR-5）。種別は open 前の `stat`（全 OS。ブロックし得る open の前に拒否する）と open 後の
/// `fstat`（`stat` 後の差し替え対策）の 2 回確認し、どちらで判明しても同じエラー
/// （`InvalidArgument` / `Invalid { field: "config.json" }`）を返す（OS による種別の食い違いを作らない）。
/// サイズは `metadata` で先に拒否するが、それを信用せず読み込み量も [`CONFIG_MAX_BYTES`] + 1 で
/// 打ち切る（読み込み中にファイルが伸びる場合への対処）。
pub fn load_config(path: &Path) -> Result<OciConfig, OciConfigError> {
    let pre = std::fs::metadata(path).map_err(|e| OciConfigError::from_io(&e))?;
    if !pre.is_file() {
        return Err(OciConfigError::not_regular_file());
    }
    let file = open_checked_candidate(path).map_err(|e| OciConfigError::from_io(&e))?;
    let meta = file.metadata().map_err(|e| OciConfigError::from_io(&e))?;
    if !meta.is_file() {
        return Err(OciConfigError::not_regular_file());
    }
    let len = meta.len();
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

    /// `path`（キー名または配列の添字文字列の列）が指す値への可変参照。
    fn value_at<'a>(v: &'a mut Value, path: &[&str]) -> &'a mut Value {
        let mut cur = v;
        for key in path {
            cur = match key.parse::<usize>() {
                Ok(i) => &mut cur[i],
                Err(_) => &mut cur[*key],
            };
        }
        cur
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
    fn oci4_oci_version_accepts_semver_suffixes() {
        for ok in [
            "1.0.0",
            "1.2.0",
            "1.0.2-dev",
            "1.1.0-rc.1+build.5",
            "1.0.0+x",
        ] {
            let mut v = base();
            v["ociVersion"] = json!(ok);
            parse(&v).unwrap_or_else(|e| panic!("{ok:?}: {e:?}"));
        }
    }

    #[test]
    fn oci4_id_mapping_range_end_must_fit_u32() {
        for (field, key) in [
            ("linux.uidMappings", "uidMappings"),
            ("linux.gidMappings", "gidMappings"),
        ] {
            for m in [
                json!({"containerID": 4294967295u32, "hostID": 0, "size": 2}),
                json!({"containerID": 0, "hostID": 4294967295u32, "size": 2}),
            ] {
                let mut v = base();
                v["linux"][key] = json!([m]);
                assert_eq!(*err_of(&v).kind(), OciConfigErrorKind::Invalid { field },);
            }
            let mut v = base();
            v["linux"][key] = json!([{"containerID": 4294967294u32, "hostID": 0, "size": 1}]);
            parse(&v).expect("end fits");
        }
    }

    /// 書き手のいない FIFO でブロックせず、非通常ファイルとして拒否する（REPAIR-5・ERR-1）。
    /// Linux / macOS の双方で実行する（`mkfifo` の失敗は skip せずテスト失敗にする）。
    #[cfg(unix)]
    #[test]
    fn repair5_load_config_rejects_fifo_without_blocking() {
        let dir = std::env::temp_dir().join(format!("fandhe-oci-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fifo = dir.join("config.json");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status:?}");
        let e = load_config(&fifo).expect_err("fifo");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            *e.kind(),
            OciConfigErrorKind::Invalid {
                field: "config.json"
            }
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// 既知フィールドが存在して `null` の場合は省略とみなさず `Data` で拒否する（OCI-4）。
    /// 省略可能な既知フィールド 13 件・`bool` 2 件・必須フィールド・配列要素のすべてを照合する。
    #[test]
    fn oci4_null_in_known_fields_is_data_error() {
        const OPTIONAL: [&[&str]; 13] = [
            &["process"],
            &["hostname"],
            &["mounts"],
            &["linux"],
            &["process", "env"],
            &["process", "user", "additionalGids"],
            &["mounts", "0", "type"],
            &["mounts", "0", "source"],
            &["mounts", "0", "options"],
            &["linux", "namespaces"],
            &["linux", "uidMappings"],
            &["linux", "gidMappings"],
            &["linux", "namespaces", "1", "path"],
        ];
        const DEFAULT_BOOL: [&[&str]; 2] = [&["root", "readonly"], &["process", "terminal"]];
        const REQUIRED: [&[&str]; 12] = [
            &["ociVersion"],
            &["root"],
            &["root", "path"],
            &["process", "user"],
            &["process", "user", "uid"],
            &["process", "args"],
            &["process", "args", "0"],
            &["process", "cwd"],
            &["mounts", "0"],
            &["mounts", "0", "destination"],
            &["linux", "namespaces", "0", "type"],
            &["linux", "uidMappings", "0", "size"],
        ];
        for path in OPTIONAL.iter().chain(&DEFAULT_BOOL).chain(&REQUIRED) {
            let mut v = base();
            *value_at(&mut v, path) = Value::Null;
            let e = err_of(&v);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{path:?}");
            assert_eq!(*e.kind(), OciConfigErrorKind::Data, "{path:?}");
        }
        // 省略（キー自体が無い）は従来どおり受理する。
        for path in OPTIONAL.iter().chain(&DEFAULT_BOOL) {
            let mut v = base();
            let (last, parent) = path.split_last().expect("non-empty path");
            value_at(&mut v, parent)
                .as_object_mut()
                .expect("object")
                .remove(*last);
            parse(&v).unwrap_or_else(|e| panic!("{path:?}: {e:?}"));
        }
    }

    /// 非通常ファイル（ディレクトリ）は 3 OS で同じ分類になる（ERR-1・REPAIR-5）。
    #[test]
    fn err1_directory_config_is_invalid_on_all_os() {
        let dir = std::env::temp_dir().join(format!("fandhe-oci-dir-{}", std::process::id()));
        let target = dir.join("config.json");
        std::fs::create_dir_all(&target).expect("mkdir");
        let e = load_config(&target).expect_err("directory");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            *e.kind(),
            OciConfigErrorKind::Invalid {
                field: "config.json"
            }
        );
        assert_eq!(
            e.message(),
            "config.json has an invalid value for `config.json`"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// 途中の要素が通常ファイルのパス（`<file>/config.json`）は 3 OS で `NotFound` になる（ERR-1）。
    #[test]
    fn err1_path_through_regular_file_is_not_found_on_all_os() {
        let dir = std::env::temp_dir().join(format!("fandhe-oci-notdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("bundle");
        std::fs::write(&file, b"{}").expect("write");
        let e = load_config(&file.join("config.json")).expect_err("not a directory");
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert_eq!(*e.kind(), OciConfigErrorKind::Io);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn oci4_oci_version_must_be_1x() {
        for bad in [
            "2.0.0", "", "1.", "1.0 0", "1.foo", "1..2", "1.0", "1.0.", "1.0.0-", "1.0.0+",
            "1.0.x", "1.0.0-01",
        ] {
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

    /// object 型の既知フィールドに配列を書いても、宣言順の位置指定として受理しない（OCI-4）。
    #[test]
    fn oci4_array_in_place_of_object_is_data_error() {
        let cases: [(&[&str], Value); 7] = [
            (&["root"], json!(["rootfs", true])),
            (
                &["process"],
                json!([false, {"uid": 0, "gid": 0}, ["/bin/sh"], [], "/"]),
            ),
            (&["process", "user"], json!([0, 0])),
            (&["mounts", "0"], json!(["/proc"])),
            (&["linux"], json!([])),
            (&["linux", "namespaces", "0"], json!(["pid"])),
            (&["linux", "uidMappings", "0"], json!([0, 1000, 1])),
        ];
        for (path, wrong) in cases {
            let mut v = base();
            *value_at(&mut v, path) = wrong;
            let e = err_of(&v);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{path:?}");
            assert_eq!(*e.kind(), OciConfigErrorKind::Data, "{path:?}");
        }
        let e = parse_config_bytes(br#"["1.0.0", {"path": "r"}]"#).expect_err("top-level array");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(*e.kind(), OciConfigErrorKind::Data);
    }

    /// OCI Runtime Spec の namespace 種別 8 種を読み分ける（OCI-4）。
    #[test]
    fn oci4_all_namespace_types_are_parsed() {
        let expected = [
            ("pid", NamespaceKind::Pid),
            ("network", NamespaceKind::Network),
            ("mount", NamespaceKind::Mount),
            ("ipc", NamespaceKind::Ipc),
            ("uts", NamespaceKind::Uts),
            ("user", NamespaceKind::User),
            ("cgroup", NamespaceKind::Cgroup),
            ("time", NamespaceKind::Time),
        ];
        assert_eq!(NAMESPACE_TYPES.len(), expected.len());
        let mut v = base();
        v["linux"]["namespaces"] = Value::Array(
            expected
                .iter()
                .map(|(name, _)| json!({"type": name}))
                .collect(),
        );
        let cfg = parse(&v).expect("valid");
        let kinds: Vec<NamespaceKind> = cfg.namespaces().iter().map(OciNamespace::kind).collect();
        assert_eq!(kinds, expected.map(|(_, k)| k));
        for (name, _) in expected {
            assert!(NAMESPACE_TYPES.contains(&name), "{name}");
        }
    }

    /// 構文は正しい JSON の型不一致は、どの既知フィールドでも `Syntax` ではなく `Data` になる
    /// （OCI-4。`linux.namespaces[].type` のような列挙値も含む）。
    #[test]
    fn oci4_type_mismatch_in_every_known_field_is_data() {
        let cases: [(&[&str], Value); 23] = [
            (&["ociVersion"], json!(1)),
            (&["root"], json!("r")),
            (&["root", "path"], json!(1)),
            (&["root", "readonly"], json!("yes")),
            (&["process"], json!([])),
            (&["process", "terminal"], json!(0)),
            (&["process", "user"], json!(1)),
            (&["process", "user", "gid"], json!(true)),
            (&["process", "user", "additionalGids"], json!({})),
            (&["process", "args", "0"], json!(1)),
            (&["process", "env"], json!("PATH=/bin")),
            (&["process", "cwd"], json!([])),
            (&["hostname"], json!(1)),
            (&["mounts"], json!({})),
            (&["mounts", "0", "destination"], json!(1)),
            (&["mounts", "0", "type"], json!(1)),
            (&["mounts", "0", "source"], json!([])),
            (&["mounts", "0", "options"], json!("nosuid")),
            (&["linux"], json!([])),
            (&["linux", "namespaces", "0", "type"], json!(1)),
            (&["linux", "namespaces", "1", "path"], json!(1)),
            (&["linux", "uidMappings"], json!({})),
            (&["linux", "gidMappings", "0", "hostID"], json!("100")),
        ];
        for (path, wrong) in cases {
            let mut v = base();
            *value_at(&mut v, path) = wrong;
            let e = err_of(&v);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{path:?}");
            assert_eq!(*e.kind(), OciConfigErrorKind::Data, "{path:?}");
        }
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

    /// 上限件数を超えた要素は型として組み立てずに件数超過で拒否する（OCI-4）。
    /// 超過要素を型不一致の値・1 要素上限を超える文字列にしても、要素の検証（`Data`・
    /// `process.args[]`）ではなく件数超過（`process.args` / `mounts`）になることで、
    /// 超過要素をデシリアライズしていないことを照合する。
    #[test]
    fn oci4_element_beyond_count_limit_is_not_deserialized() {
        for extra in [json!(1), json!("a".repeat(CONFIG_MAX_STRING_BYTES + 1))] {
            let mut args = vec![json!("a"); CONFIG_MAX_ARGS];
            args.push(extra);
            let mut v = base();
            v["process"]["args"] = Value::Array(args);
            assert_eq!(
                *err_of(&v).kind(),
                OciConfigErrorKind::LimitExceeded {
                    field: "process.args".to_owned(),
                    limit: 4096
                }
            );
        }
        let mut mounts = vec![json!({"destination": "/a"}); CONFIG_MAX_MOUNTS];
        mounts.push(json!({"destination": null, "options": 7}));
        let mut v = base();
        v["mounts"] = Value::Array(mounts);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "mounts".to_owned(),
                limit: 1024
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
    fn oci4_duplicate_key_in_unknown_property_is_ignored() {
        let text = br#"{"ociVersion":"1.0.0","root":{"path":"r"},"x":1,"x":2}"#;
        assert!(parse_config_bytes(text).is_ok());
    }

    #[test]
    fn oci4_id_mapping_at_u32_max_is_accepted() {
        let text = br#"{"ociVersion":"1.0.0","root":{"path":"r"},"linux":{"uidMappings":[{"containerID":4294967295,"hostID":4294967295,"size":1}]}}"#;
        assert!(parse_config_bytes(text).is_ok());
        let bad = br#"{"ociVersion":"1.0.0","root":{"path":"r"},"linux":{"uidMappings":[{"containerID":4294967295,"hostID":0,"size":2}]}}"#;
        assert!(parse_config_bytes(bad).is_err());
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
    fn oci4_limit_marker_in_input_value_is_not_spoofed() {
        let mut v = base();
        v["linux"]["namespaces"] = json!([{"type": "fandhe-limit|X|7"}]);
        let e = err_of(&v);
        assert_eq!(*e.kind(), OciConfigErrorKind::Data);
        assert!(!e.to_string().contains("fandhe-limit"));
        assert!(!format!("{e:?}").contains("fandhe-limit"));
        assert_eq!(parse_limit_marker("fandhe-limit|X|7"), None);
        assert_eq!(
            parse_limit_marker("unknown variant `fandhe-limit|hostname|7`"),
            None
        );
        assert_eq!(
            parse_limit_marker("fandhe-limit|hostname|999"),
            Some(("hostname", CONFIG_MAX_HOSTNAME_BYTES))
        );
    }

    #[cfg(unix)]
    #[test]
    fn oci4_load_config_rejects_non_regular_file() {
        let e = load_config(Path::new("/dev/null")).expect_err("not a file");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            *e.kind(),
            OciConfigErrorKind::Invalid {
                field: "config.json"
            }
        );
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

    /// `args` / `env` の 1 要素は上限ちょうどを受理し、1 バイト超過を拒否する（OCI-4・CORE-2）。
    #[test]
    fn oci4_string_item_limit_boundary() {
        let arg = "a".repeat(CONFIG_MAX_STRING_BYTES);
        let env = format!("K={}", "v".repeat(CONFIG_MAX_STRING_BYTES - 2));
        let mut v = base();
        v["process"]["args"] = json!([arg]);
        v["process"]["env"] = json!([env]);
        let cfg = parse(&v).expect("at limit");
        let p = cfg.process().expect("process");
        assert_eq!(p.args()[0].len(), 131_071);
        assert_eq!(p.env()[0].len(), 131_071);

        let mut v = base();
        v["process"]["env"] = json!([format!("K={}", "v".repeat(CONFIG_MAX_STRING_BYTES - 1))]);
        assert_eq!(
            *err_of(&v).kind(),
            OciConfigErrorKind::LimitExceeded {
                field: "process.env[]".to_owned(),
                limit: 131_071
            }
        );
    }

    /// パーサが上限ちょうどで受理した `args` / `env` を `exec::Entrypoint::new` もそのまま受理する
    /// （パースを通った値が後段の 1 要素上限で拒否されない。CORE-2）。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_parsed_items_at_limit_are_accepted_by_entrypoint() {
        let mut v = base();
        v["process"]["args"] = json!(["a".repeat(CONFIG_MAX_STRING_BYTES)]);
        v["process"]["env"] = json!([format!("K={}", "v".repeat(CONFIG_MAX_STRING_BYTES - 2))]);
        let cfg = parse(&v).expect("at limit");
        let p = cfg.process().expect("process");
        let ep = crate::exec::Entrypoint::new("/bin/app", p.args(), p.env())
            .expect("entrypoint accepts parsed values at the limit");
        assert_eq!(ep.path(), Path::new("/bin/app"));
    }

    /// `exec::Entrypoint` の上限との対応を照合し、片方だけ変更されるドリフトを防ぐ
    /// （1 要素の上限は Entrypoint 側が NUL 込みのため、こちらは 1 バイト小さい）。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_limits_match_exec_entrypoint_limits() {
        use crate::exec::{ENTRYPOINT_MAX_ARGS, ENTRYPOINT_MAX_ENV, ENTRYPOINT_MAX_STRING_BYTES};
        assert_eq!(CONFIG_MAX_ARGS, ENTRYPOINT_MAX_ARGS);
        assert_eq!(CONFIG_MAX_ENV, ENTRYPOINT_MAX_ENV);
        assert_eq!(CONFIG_MAX_STRING_BYTES + 1, ENTRYPOINT_MAX_STRING_BYTES);
    }
}
