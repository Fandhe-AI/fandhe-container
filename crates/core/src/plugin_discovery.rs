//! 管理ディレクトリからの plugin 候補探索（TASK-109.1・PLUG-4・PLUG-11・MS-3）。
//!
//! # 役割と呼び出し元
//!
//! core が plugin バイナリを発見・登録する機構（TASK-109）の最初の 1 片。既定の管理ディレクトリ
//! （system / user）を走査し、`fandhe-container-plugin-*` の命名規約に合うファイルを **候補**
//! として列挙するだけを担う。後続の `PATH` 探索の opt-in（#254・TASK-109.2）、レジストリと
//! 同名候補の優先順位・登録（#255・TASK-109.3）、信頼性検証（TASK-122・PLUG-11）が本モジュールの
//! 戻り値を入力に使う。`fandhe-container-plugin`（境界機構）には依存しない。
//!
//! # 契約
//!
//! - 返す [`PluginCandidate`] は **未検証** である。所有者・権限ビット・許可済みハッシュの照合は
//!   行っておらず、このまま実行・登録してはならない（PLUG-11。検証は TASK-122）
//! - 走査から検証・登録までの間にファイルは差し替わり得る（TOCTOU）。登録側は検証時に
//!   再 stat・ハッシュ照合する前提で、本モジュールの結果を信頼の根拠にしない
//! - symlink は辿らず [`PluginFileKind::Symlink`] として記録する。実体への検証は TASK-122 の責務
//! - ファイルの中身は読まず、実行ビットも見ない。`PATH` は探索しない（opt-in は #254）
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

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::traits::{ErrorCode, TraitError};

/// plugin 実行ファイル名の接頭辞（PLUG-11 の命名規約）。
pub const PLUGIN_NAME_PREFIX: &str = "fandhe-container-plugin-";

/// 1 ディレクトリあたりの走査エントリ数の上限。超過は fail-closed で拒否する（無制限走査の防止）。
pub const MAX_SCANNED_ENTRIES_PER_DIR: usize = 4096;

/// plugin 名（接頭辞を除いた部分）の最大バイト数。
const MAX_PLUGIN_NAME_LEN: usize = 64;

/// 探索元の区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PluginDirKind {
    /// システム全体の管理ディレクトリ。
    System,
    /// ユーザー単位の管理ディレクトリ。
    User,
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
/// それ以外の I/O エラー・走査上限超過は `Err`（fail-closed）。
pub fn discover_candidates(dirs: &[PluginSearchDir]) -> Result<Vec<PluginCandidate>, TraitError> {
    let mut found = Vec::new();
    for dir in dirs {
        scan_dir(dir, &mut found)?;
    }
    found.sort_by(|a, b| (a.origin, &a.name, &a.path).cmp(&(b.origin, &b.name, &b.path)));
    Ok(found)
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

fn scan_dir(dir: &PluginSearchDir, out: &mut Vec<PluginCandidate>) -> Result<(), TraitError> {
    let entries = match fs::read_dir(dir.path()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error(&e, "failed to read plugin directory")),
    };
    for (scanned, entry) in entries.enumerate() {
        if scanned >= MAX_SCANNED_ENTRIES_PER_DIR {
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
        out.push(PluginCandidate {
            name: name.to_owned(),
            path: dir.path().join(file_name),
            origin: dir.kind(),
            file_kind,
        });
    }
    Ok(())
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
}
