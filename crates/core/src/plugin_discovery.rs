//! 管理ディレクトリ・`PATH`（opt-in）からの plugin 候補探索（TASK-109.1・TASK-109.2・PLUG-4・PLUG-11・MS-3）。
//!
//! # 役割と呼び出し元
//!
//! core が plugin バイナリを発見・登録する機構（TASK-109）の最初の 1 片。既定の管理ディレクトリ
//! （system / user）を走査し、`fandhe-container-plugin-*` の命名規約に合うファイルを **候補**
//! として列挙するだけを担う。TASK-109.2（#254）で `PATH` 探索の opt-in と警告ログを加えた。
//! 後続のレジストリと同名候補の優先順位・登録（#255・TASK-109.3）、信頼性検証（TASK-122・PLUG-11）が
//! 本モジュールの戻り値を入力に使う。`fandhe-container-plugin`（境界機構）には依存しない。
//!
//! # 契約
//!
//! - 返す [`PluginCandidate`] は **未検証** である。所有者・権限ビット・許可済みハッシュの照合は
//!   行っておらず、このまま実行・登録してはならない（PLUG-11。検証は TASK-122）
//! - 走査から検証・登録までの間にファイルは差し替わり得る（TOCTOU）。登録側は検証時に
//!   再 stat・ハッシュ照合する前提で、本モジュールの結果を信頼の根拠にしない
//! - symlink は辿らず [`PluginFileKind::Symlink`] として記録する。実体への検証は TASK-122 の責務
//! - ファイルの中身は読まず、実行ビットも見ない
//! - `PATH` は既定で探索しない。環境変数 [`PATH_SEARCH_ENV`]`=1` または呼び出し側が渡す
//!   [`PathSearchPolicy::Enabled`] の opt-in があるときだけ探索し、`PATH` 上で見つけた候補 1 件
//!   ごとに警告ログ 1 行を出す（[`PathSearchWarning`]）。**`PATH` 上の名前一致のみでは登録しない**
//!   （`PluginDirKind::Path` の候補は未検証で、登録可否は TASK-122・#255 が決める）
//! - CLI フラグ（opt-in の CLI 側入口）の配線は CLI 実装（TASK-79）で行う。未実装（REPAIR-3）。
//!   CLI は `PathSearchPolicy::Enabled` を [`DiscoveryOptions`] 経由で渡す想定
//! - 探索先ディレクトリが存在しない場合はエラーにせず候補なしとする。それ以外の I/O エラーは
//!   握りつぶさず返す（fail-closed）
//! - system と user に同名があれば両方返す。優先順位・重複解決は #255 の責務
//!
//! # 対応 OS
//!
//! 既定探索先の定義は Linux のみ（system は `/usr/libexec/fandhe-container/plugins`、user は
//! XDG Base Directory の `<XDG_DATA_HOME>/fandhe-container/plugins`、未設定なら
//! `<HOME>/.local/share/fandhe-container/plugins`）。macOS / Windows の「相当」パスは spec で
//! 未確定のため空の探索先一覧を返す（エラーにしない。PLUG-11）。走査関数自体は 3 OS で動く。

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use crate::traits::{ErrorCode, TraitError};

/// plugin 実行ファイル名の接頭辞（PLUG-11 の命名規約）。
pub const PLUGIN_NAME_PREFIX: &str = "fandhe-container-plugin-";

/// 1 ディレクトリあたりの走査エントリ数の上限。超過は fail-closed で拒否する（無制限走査の防止）。
pub const MAX_SCANNED_ENTRIES_PER_DIR: usize = 4096;

/// `PATH` 探索時の 1 ディレクトリあたりの走査エントリ数の上限（`/usr/bin` 等は管理ディレクトリ用の
/// 上限を超え得るため別に設ける）。超過は fail-closed で拒否する。
pub const MAX_SCANNED_ENTRIES_PER_PATH_DIR: usize = 65536;

/// 探索全体（管理ディレクトリ + `PATH`）で保持する候補数の上限。超過は切り捨てず fail-closed で
/// 拒否する（多数のディレクトリに名前一致ファイルを置かれた場合の無制限なメモリ確保・警告複製を防ぐ）。
pub const MAX_TOTAL_CANDIDATES: usize = 4096;

/// `PATH` から採用するディレクトリ数の上限。超過は切り捨てず fail-closed で拒否する。
pub const MAX_PATH_SEARCH_DIRS: usize = 256;

/// `PATH` 探索を opt-in する環境変数名。値が厳密に `1` のときだけ有効（PLUG-11）。
pub const PATH_SEARCH_ENV: &str = "FANDHE_CONTAINER_PLUGIN_PATH_SEARCH";

/// `PATH` 候補の警告行 `code` フィールド値（機械可読。ERR 系の流儀）。
pub const PATH_WARNING_CODE: &str = "PLUGIN_PATH_CANDIDATE";

/// `PATH` 候補の警告行 `message` フィールド値（英語固定。名前一致のみでは登録しない旨を明記）。
pub const PATH_WARNING_MESSAGE: &str = "plugin candidate found via PATH search; a name match on PATH alone is not registered (trust verification required)";

/// plugin 名（接頭辞を除いた部分）の最大バイト数。
const MAX_PLUGIN_NAME_LEN: usize = 64;

/// 探索元の区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PluginDirKind {
    /// システム全体の管理ディレクトリ。
    System,
    /// ユーザー単位の管理ディレクトリ。
    User,
    /// `PATH` 由来（opt-in 時のみ）。未検証で、名前一致のみでは登録しない（PLUG-11・TASK-122）。
    Path,
}

/// `PATH` 探索の可否（bool を避け将来の拡張に備える）。既定は [`PathSearchPolicy::Disabled`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSearchPolicy {
    /// `PATH` を探索しない（既定）。
    #[default]
    Disabled,
    /// `PATH` を探索し、発見ごとに警告を出す。
    Enabled,
}

impl PathSearchPolicy {
    /// 環境変数値から方針を決める純粋関数。厳密に `1` のときだけ `Enabled`。
    /// 未設定・空・`0`・`true`・前後空白付き・非 UTF-8 などはすべて `Disabled`（fail-closed）。
    pub fn from_env_value(value: Option<&OsStr>) -> Self {
        if value == Some(OsStr::new("1")) {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    /// [`PATH_SEARCH_ENV`] を読んで方針を決める。
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var_os(PATH_SEARCH_ENV).as_deref())
    }
}

/// 探索対象ディレクトリ 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSearchDir {
    kind: PluginDirKind,
    path: PathBuf,
}

impl PluginSearchDir {
    /// 区分とパスから探索先を作る。
    pub fn new(kind: PluginDirKind, path: PathBuf) -> Self {
        Self { kind, path }
    }

    /// 探索元の区分を返す。
    pub fn kind(&self) -> PluginDirKind {
        self.kind
    }

    /// 探索先のパスを返す。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 候補ファイルの種別（`symlink_metadata` 相当。リンクは辿らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginFileKind {
    /// 通常ファイル。
    File,
    /// シンボリックリンク（リンク先は未解決・未検証）。
    Symlink,
}

/// 命名規約に合う plugin 候補（未検証。モジュール doc の契約を参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCandidate {
    name: String,
    path: PathBuf,
    origin: PluginDirKind,
    file_kind: PluginFileKind,
}

impl PluginCandidate {
    /// 接頭辞（と実行ファイル拡張子）を除いた plugin 名を返す。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 候補ファイルのパス（探索ディレクトリ + ファイル名）を返す。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 発見元の区分を返す。
    pub fn origin(&self) -> PluginDirKind {
        self.origin
    }

    /// 候補の種別を返す。
    pub fn file_kind(&self) -> PluginFileKind {
        self.file_kind
    }
}

/// ファイル名が命名規約に合えば plugin 名を返す純粋関数。
///
/// `exe_suffix` が空でなければ末尾から除去する（Windows の `.exe`。無ければ除外）。名前部分は
/// 1〜64 バイトの ASCII 英小文字・数字・ハイフンで、先頭と末尾がハイフンでないものに限る。
/// 区切り文字や `..` を含み得ないため、パス連結に使っても外へ出られない。
fn plugin_name_from_file_name<'a>(file_name: &'a str, exe_suffix: &str) -> Option<&'a str> {
    let stem = if exe_suffix.is_empty() {
        file_name
    } else {
        file_name.strip_suffix(exe_suffix)?
    };
    let name = stem.strip_prefix(PLUGIN_NAME_PREFIX)?;
    if name.is_empty() || name.len() > MAX_PLUGIN_NAME_LEN {
        return None;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return None;
    }
    let valid = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    valid.then_some(name)
}

/// 環境値から既定探索先を組み立てる純粋関数（`default_search_dirs` が環境値を渡す）。
///
/// 相対パスの環境値は採用しない（カレントディレクトリ依存の探索を作らない）。
#[cfg(target_os = "linux")]
fn resolve_default_dirs(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Vec<PluginSearchDir> {
    let mut dirs = vec![PluginSearchDir::new(
        PluginDirKind::System,
        Path::new("/usr/libexec")
            .join("fandhe-container")
            .join("plugins"),
    )];
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    let data_home =
        absolute(xdg_data_home).or_else(|| absolute(home).map(|h| h.join(".local").join("share")));
    if let Some(base) = data_home {
        dirs.push(PluginSearchDir::new(
            PluginDirKind::User,
            base.join("fandhe-container").join("plugins"),
        ));
    }
    dirs
}

/// 非 Linux では既定探索先が未確定のため空を返す（PLUG-11。モジュール doc 参照）。
#[cfg(not(target_os = "linux"))]
fn resolve_default_dirs(
    _xdg_data_home: Option<OsString>,
    _home: Option<OsString>,
) -> Vec<PluginSearchDir> {
    Vec::new()
}

/// 既定の管理ディレクトリ一覧（system → user の順）を返す。
pub fn default_search_dirs() -> Vec<PluginSearchDir> {
    resolve_default_dirs(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// 指定ディレクトリを走査して命名規約に合う候補を列挙する。
///
/// 結果は (origin: System → User, name 昇順) に整列する。存在しないディレクトリは候補なし。
/// それ以外の I/O エラー・走査上限・候補総数上限（[`MAX_TOTAL_CANDIDATES`]）超過は `Err`（fail-closed）。
///
/// `PluginDirKind::Path` の探索先は受け付けず `Err(InvalidArgument)`（PLUG-11。`PATH` 探索は
/// opt-in 経路の [`discover_with_options`] が内部で生成した探索先だけを走査する）。
pub fn discover_candidates(dirs: &[PluginSearchDir]) -> Result<Vec<PluginCandidate>, TraitError> {
    reject_path_kind(dirs)?;
    let mut found = Vec::new();
    for dir in dirs {
        scan_dir(dir, MAX_SCANNED_ENTRIES_PER_DIR, &mut found)?;
    }
    found.sort_by(|a, b| (a.origin, &a.name, &a.path).cmp(&(b.origin, &b.name, &b.path)));
    Ok(found)
}

/// 管理ディレクトリ引数に `PATH` 区分が混入していたら拒否する（PLUG-11。opt-in と警告の迂回防止）。
fn reject_path_kind(dirs: &[PluginSearchDir]) -> Result<(), TraitError> {
    if dirs.iter().any(|d| d.kind == PluginDirKind::Path) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "PATH-kind search directory is not accepted as a managed directory",
        ));
    }
    Ok(())
}

/// 既定の管理ディレクトリを走査する（`discover_candidates(&default_search_dirs())`）。
pub fn discover_default_candidates() -> Result<Vec<PluginCandidate>, TraitError> {
    discover_candidates(&default_search_dirs())
}

fn io_error(e: &std::io::Error, message: &'static str) -> TraitError {
    let code = if e.kind() == ErrorKind::PermissionDenied {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::Internal
    };
    TraitError::new(code, message)
}

/// `max_entries` は走査上限。`Path` 区分のときだけ「ディレクトリでない」要素も候補なしとして skip する
/// （`PATH` には通常ファイルが混ざり得る。管理ディレクトリの既存挙動は変えない）。
fn scan_dir(
    dir: &PluginSearchDir,
    max_entries: usize,
    out: &mut Vec<PluginCandidate>,
) -> Result<(), TraitError> {
    let entries = match fs::read_dir(dir.path()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) if e.kind() == ErrorKind::NotADirectory && dir.kind() == PluginDirKind::Path => {
            return Ok(());
        }
        Err(e) => return Err(io_error(&e, "failed to read plugin directory")),
    };
    for (scanned, entry) in entries.enumerate() {
        if scanned >= max_entries {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "too many entries in plugin directory",
            ));
        }
        let entry = entry.map_err(|e| io_error(&e, "failed to read plugin directory entry"))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name) = plugin_name_from_file_name(file_name, std::env::consts::EXE_SUFFIX) else {
            continue;
        };
        let file_type = entry
            .file_type()
            .map_err(|e| io_error(&e, "failed to read plugin entry type"))?;
        let file_kind = if file_type.is_symlink() {
            PluginFileKind::Symlink
        } else if file_type.is_file() {
            PluginFileKind::File
        } else {
            continue;
        };
        if out.len() >= MAX_TOTAL_CANDIDATES {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "too many plugin candidates",
            ));
        }
        out.push(PluginCandidate {
            name: name.to_owned(),
            path: dir.path().join(file_name),
            origin: dir.kind(),
            file_kind,
        });
    }
    Ok(())
}

/// `PATH` 値を探索先へ分割する純粋関数。空要素・相対パス（カレントディレクトリ依存）は採用せず、
/// 重複は初出のみ残す。採用数が [`MAX_PATH_SEARCH_DIRS`] を超えたら `Err`。`None` は空。
fn resolve_path_search_dirs(
    path_value: Option<&OsStr>,
) -> Result<Vec<PluginSearchDir>, TraitError> {
    let mut dirs: Vec<PluginSearchDir> = Vec::new();
    let Some(value) = path_value else {
        return Ok(dirs);
    };
    for p in std::env::split_paths(value) {
        if !p.is_absolute() || dirs.iter().any(|d| d.path == p) {
            continue;
        }
        if dirs.len() >= MAX_PATH_SEARCH_DIRS {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "too many directories in PATH",
            ));
        }
        dirs.push(PluginSearchDir::new(PluginDirKind::Path, p));
    }
    Ok(dirs)
}

/// 探索オプション（将来拡張できるよう構造体にする）。既定は `PATH` 探索なし。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiscoveryOptions {
    path_search: PathSearchPolicy,
}

impl DiscoveryOptions {
    /// 既定（`PATH` 探索なし）のオプションを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// `PATH` 探索の方針を設定する（CLI フラグ・環境変数の解決結果を渡す。配線は TASK-79）。
    pub fn with_path_search(mut self, policy: PathSearchPolicy) -> Self {
        self.path_search = policy;
        self
    }

    /// `PATH` 探索の方針を返す。
    pub fn path_search(&self) -> PathSearchPolicy {
        self.path_search
    }
}

/// `PATH` 上で見つかった候補 1 件に対する警告（名前一致のみでは登録しない旨を伝える）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSearchWarning {
    name: String,
    path: PathBuf,
}

impl PathSearchWarning {
    /// 候補の plugin 名を返す。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 候補のパスを返す。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// JSON Lines 1 行（末尾 `\n`）で書き出す。`serde_json` でエスケープするため、パスに改行や
    /// 制御文字があっても 1 行に収まる（ログ行の偽造防止）。
    pub fn write_line(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let line = serde_json::json!({
            "level": "warn",
            "code": PATH_WARNING_CODE,
            "message": PATH_WARNING_MESSAGE,
            "name": self.name,
            "path": self.path.to_string_lossy(),
        });
        serde_json::to_writer(&mut *out, &line).map_err(std::io::Error::from)?;
        out.write_all(b"\n")
    }
}

/// 探索結果（候補と `PATH` 警告）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    candidates: Vec<PluginCandidate>,
    path_warnings: Vec<PathSearchWarning>,
}

impl DiscoveryReport {
    /// 整列済みの候補（未検証）を返す。
    pub fn candidates(&self) -> &[PluginCandidate] {
        &self.candidates
    }

    /// `PATH` 由来の候補ごとの警告を返す（`Disabled` では常に空）。
    pub fn path_warnings(&self) -> &[PathSearchWarning] {
        &self.path_warnings
    }

    /// 候補だけを取り出す。
    pub fn into_candidates(self) -> Vec<PluginCandidate> {
        self.candidates
    }
}

/// 管理ディレクトリに加え、opt-in 時のみ `path_value`（`PATH` 環境変数値）も走査する。
///
/// `Disabled` では `path_value` を解釈も走査もしない。`Enabled` では `PATH` 由来の候補
/// （`origin == Path`）1 件につき警告を 1 件作る。名前一致のみでは登録しない（TASK-122・#255）。
pub fn discover_with_options(
    managed_dirs: &[PluginSearchDir],
    path_value: Option<&OsStr>,
    options: &DiscoveryOptions,
) -> Result<DiscoveryReport, TraitError> {
    reject_path_kind(managed_dirs)?;
    let mut found = Vec::new();
    for dir in managed_dirs {
        scan_dir(dir, MAX_SCANNED_ENTRIES_PER_DIR, &mut found)?;
    }
    if options.path_search == PathSearchPolicy::Enabled {
        for dir in resolve_path_search_dirs(path_value)? {
            scan_dir(&dir, MAX_SCANNED_ENTRIES_PER_PATH_DIR, &mut found)?;
        }
    }
    found.sort_by(|a, b| (a.origin, &a.name, &a.path).cmp(&(b.origin, &b.name, &b.path)));
    let path_warnings = found
        .iter()
        .filter(|c| c.origin == PluginDirKind::Path)
        .map(|c| PathSearchWarning {
            name: c.name.clone(),
            path: c.path.clone(),
        })
        .collect();
    Ok(DiscoveryReport {
        candidates: found,
        path_warnings,
    })
}

/// 明示オプションと環境変数値から実効の `PATH` 探索方針を決める純粋関数（PLUG-11）。
///
/// どちらか一方でも `Enabled` なら `Enabled`（opt-in の和。どちらも未指定なら `Disabled`）。
/// 環境変数側は [`PathSearchPolicy::from_env_value`] の厳密解釈（`1` のみ）に従う。
fn effective_path_search(
    options: &DiscoveryOptions,
    env_value: Option<&OsStr>,
) -> PathSearchPolicy {
    if options.path_search == PathSearchPolicy::Enabled
        || PathSearchPolicy::from_env_value(env_value) == PathSearchPolicy::Enabled
    {
        PathSearchPolicy::Enabled
    } else {
        PathSearchPolicy::Disabled
    }
}

/// 既定の管理ディレクトリと、実効方針が `Enabled` のときだけ `PATH` 環境変数を使って探索する。
///
/// 実効方針は `options` の明示指定と環境変数 [`PATH_SEARCH_ENV`]`=1` の opt-in の和
/// （[`effective_path_search`]）。`Disabled` では `PATH` 環境変数を読まない。
pub fn discover_default_with_options(
    options: &DiscoveryOptions,
) -> Result<DiscoveryReport, TraitError> {
    let env_value = std::env::var_os(PATH_SEARCH_ENV);
    discover_default_with_env(
        options,
        env_value.as_deref(),
        &default_search_dirs(),
        |dir_var| std::env::var_os(dir_var),
    )
}

/// 環境依存の入力（環境変数値・管理ディレクトリ・`PATH` 取得関数）を注入できる本体。
/// テストから実環境を変更せずに環境変数 opt-in の経路を検証するために分離している。
fn discover_default_with_env(
    options: &DiscoveryOptions,
    env_value: Option<&OsStr>,
    managed_dirs: &[PluginSearchDir],
    get_var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<DiscoveryReport, TraitError> {
    let effective =
        DiscoveryOptions::new().with_path_search(effective_path_search(options, env_value));
    let path_value = match effective.path_search {
        PathSearchPolicy::Enabled => get_var("PATH"),
        PathSearchPolicy::Disabled => None,
    };
    discover_with_options(managed_dirs, path_value.as_deref(), &effective)
}

/// `PATH` 警告を 1 件 1 行で書く。呼び出し側（CLI 等）が stderr を渡す（core は直接書かない）。
pub fn write_path_warnings(report: &DiscoveryReport, out: &mut dyn Write) -> std::io::Result<()> {
    report
        .path_warnings
        .iter()
        .try_for_each(|w| w.write_line(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plug11_name_filter_accepts_and_rejects() {
        let p = PLUGIN_NAME_PREFIX;
        fn f(n: &str) -> Option<&str> {
            plugin_name_from_file_name(n, "")
        }
        assert_eq!(f("fandhe-container-plugin-mcp"), Some("mcp"));
        assert_eq!(f("fandhe-container-plugin-cri-2"), Some("cri-2"));
        assert_eq!(f(p), None);
        assert_eq!(f("fandhe-container-pluginx"), None);
        assert_eq!(f("fandhe-container-plugin-MCP"), None);
        assert_eq!(f("fandhe-container-plugin-.."), None);
        assert_eq!(f("fandhe-container-plugin-a/b"), None);
        assert_eq!(f("fandhe-container-plugin-a\\b"), None);
        assert_eq!(f("fandhe-container-plugin--a"), None);
        assert_eq!(f("fandhe-container-plugin-a-"), None);
        assert_eq!(f("fandhe-container-plugin-a.b"), None);
        let long_ok = format!("{p}{}", "a".repeat(64));
        let long_ng = format!("{p}{}", "a".repeat(65));
        assert_eq!(f(&long_ok), Some("a".repeat(64).as_str()));
        assert_eq!(f(&long_ng), None);
        assert_eq!(
            plugin_name_from_file_name("fandhe-container-plugin-mcp.exe", ".exe"),
            Some("mcp")
        );
        assert_eq!(
            plugin_name_from_file_name("fandhe-container-plugin-mcp", ".exe"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    fn dirs_of(v: Vec<PluginSearchDir>) -> Vec<(PluginDirKind, PathBuf)> {
        v.into_iter().map(|d| (d.kind, d.path)).collect()
    }

    #[cfg(target_os = "linux")]
    fn system() -> (PluginDirKind, PathBuf) {
        (
            PluginDirKind::System,
            PathBuf::from("/usr/libexec/fandhe-container/plugins"),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_default_dirs_use_xdg_data_home() {
        let got = resolve_default_dirs(Some("/xdg".into()), Some("/home/u".into()));
        assert_eq!(
            dirs_of(got),
            vec![
                system(),
                (
                    PluginDirKind::User,
                    PathBuf::from("/xdg/fandhe-container/plugins")
                )
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_default_dirs_fall_back_to_home() {
        for xdg in [None, Some(OsString::new()), Some("relative".into())] {
            let got = resolve_default_dirs(xdg, Some("/home/u".into()));
            assert_eq!(
                dirs_of(got),
                vec![
                    system(),
                    (
                        PluginDirKind::User,
                        PathBuf::from("/home/u/.local/share/fandhe-container/plugins")
                    )
                ]
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_default_dirs_skip_user_when_env_unusable() {
        for home in [None, Some(OsString::new()), Some("rel".into())] {
            let got = resolve_default_dirs(None, home);
            assert_eq!(dirs_of(got), vec![system()]);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn plug11_default_dirs_are_empty_outside_linux() {
        assert!(resolve_default_dirs(Some("/xdg".into()), Some("/h".into())).is_empty());
    }

    #[test]
    fn plug11_env_opt_in_enables_path_search_in_default_api() {
        use std::ffi::OsString;
        let tmp = std::env::temp_dir().join(format!("fc-plug11-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let fixture = format!(
            "fandhe-container-plugin-envtest{}",
            std::env::consts::EXE_SUFFIX
        );
        std::fs::write(tmp.join(fixture), b"").unwrap();
        let path = OsString::from(tmp.as_os_str());
        let get = |k: &str| (k == "PATH").then(|| path.clone());
        let opts = DiscoveryOptions::default();

        // 環境変数 `1` なら明示オプションが Disabled でも PATH を探索する
        let r = discover_default_with_env(&opts, Some(OsStr::new("1")), &[], get).unwrap();
        assert_eq!(r.candidates().len(), 1);
        assert_eq!(r.path_warnings().len(), 1);
        // 未設定・`0` は探索しない（fail-closed）
        for v in [None, Some(OsStr::new("0")), Some(OsStr::new("true"))] {
            let r = discover_default_with_env(&opts, v, &[], get).unwrap();
            assert!(r.candidates().is_empty());
        }
        // 明示オプション Enabled は環境変数なしでも探索する
        let on = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
        let r = discover_default_with_env(&on, None, &[], get).unwrap();
        assert_eq!(r.candidates().len(), 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn plug11_path_search_policy_parses_only_exact_one() {
        for v in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some(" 1"),
            Some("1 "),
            Some("11"),
        ] {
            assert_eq!(
                PathSearchPolicy::from_env_value(v.map(OsStr::new)),
                PathSearchPolicy::Disabled,
                "{v:?}"
            );
        }
        assert_eq!(
            PathSearchPolicy::from_env_value(Some(OsStr::new("1"))),
            PathSearchPolicy::Enabled
        );
        assert_eq!(PathSearchPolicy::default(), PathSearchPolicy::Disabled);
    }

    #[test]
    fn plug11_path_dirs_skip_empty_and_relative_and_dedupe() {
        let a = std::env::temp_dir().join("fandhe-a");
        let b = std::env::temp_dir().join("fandhe-b");
        let joined = std::env::join_paths([
            a.clone(),
            PathBuf::new(),
            PathBuf::from("rel"),
            b.clone(),
            a.clone(),
        ])
        .unwrap();
        let got = resolve_path_search_dirs(Some(&joined)).unwrap();
        let got: Vec<_> = got.into_iter().map(|d| (d.kind, d.path)).collect();
        assert_eq!(
            got,
            vec![(PluginDirKind::Path, a), (PluginDirKind::Path, b)]
        );
        assert!(resolve_path_search_dirs(None).unwrap().is_empty());
    }

    #[test]
    fn plug11_path_dirs_reject_too_many_entries() {
        let base = std::env::temp_dir();
        let mk =
            |n: usize| std::env::join_paths((0..n).map(|i| base.join(format!("d{i}")))).unwrap();
        let ok = resolve_path_search_dirs(Some(&mk(256))).unwrap();
        assert_eq!(ok.len(), 256);
        let err = resolve_path_search_dirs(Some(&mk(257))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    }

    #[test]
    fn plug11_path_kind_dir_is_rejected_as_managed_dir() {
        let dirs = vec![PluginSearchDir::new(
            PluginDirKind::Path,
            std::env::temp_dir(),
        )];
        let err = discover_candidates(&dirs).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let err = discover_with_options(&dirs, None, &DiscoveryOptions::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn plug11_total_candidates_are_capped() {
        let root = std::env::temp_dir().join(format!("fandhe-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut out = Vec::new();
        let dir = PluginSearchDir::new(PluginDirKind::Path, root.clone());
        let ext = std::env::consts::EXE_SUFFIX;
        for i in 0..MAX_TOTAL_CANDIDATES + 1 {
            fs::write(root.join(format!("{PLUGIN_NAME_PREFIX}p{i}{ext}")), b"").unwrap();
        }
        // 総数上限を 1 超える数のファイルがある場合は fail-closed。
        let err = scan_dir(&dir, MAX_SCANNED_ENTRIES_PER_PATH_DIR, &mut out).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(out.len(), MAX_TOTAL_CANDIDATES);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn plug11_path_warning_is_single_line_and_states_no_registration() {
        let w = PathSearchWarning {
            name: "cri".to_owned(),
            path: PathBuf::from("/x\ny/fandhe-container-plugin-cri"),
        };
        let mut buf = Vec::new();
        w.write_line(&mut buf).unwrap();
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(buf.last(), Some(&b'\n'));
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["level"], "warn");
        assert_eq!(v["code"], "PLUGIN_PATH_CANDIDATE");
        assert_eq!(v["name"], "cri");
        assert!(v["message"].as_str().unwrap().contains("not registered"));
    }
}
