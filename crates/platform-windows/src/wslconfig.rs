//! `.wslconfig`（ユーザープロファイル直下）の読み書き（TASK-67.2・#373・WIN-1・WIN-2・MS-5）。
//!
//! Windows で Linux コンテナを動かす主経路は WSL2 経由（WIN-1）で、既定の 9P はネイティブ比で約 9 倍遅い
//! ため、`.wslconfig` の `[wsl2]` セクションへ `virtiofs=true` を opt-in で追加して既定運用に含める（WIN-2）。
//! 本モジュールはその設定ファイル操作だけを単独の関心事として担う。呼び出し元は virtiofs の共有マウントと
//! 起動ロジック（TASK-67.4・#375）と 9P フォールバック判定（TASK-67.5・#376）で、読み取り API として
//! [`WslConfig::virtiofs_state`] を、書き込み API として [`enable_virtiofs_at`] を使う。
//!
//! 検証状況: キーの配置（`[wsl2]` の `virtiofs`）は Issue・spec の記述どおりで、Windows 実機での検証は
//! 未了（WIN-2 の再検証条件 1）。セクション名・キー名は [`WSL2_SECTION`]・[`VIRTIOFS_KEY`] に集約している。
//!
//! 設計方針:
//! - 行ベースのモデルで各行の原文（インデント・コメント・改行の種類）を保持し、変更対象の行以外は
//!   バイト単位で保つ。BOM の有無も保つ。
//! - 純粋なテキスト処理（[`WslConfig`]）とファイル I/O（[`load`]・[`enable_virtiofs_at`]）を分け、
//!   前者は全 OS でテストする。OS 固有なのは [`default_path`] の `%UserProfile%` 解決だけ。
//! - `.wslconfig` は untrusted 入力として扱い、`unwrap` / 添字を使わず、読み込みは [`MAX_WSLCONFIG_BYTES`]
//!   までに制限する。エラーの `message` に内容・パスを載せない（[`crate::error`]）。
//! - 書き込みは同一ディレクトリの一時ファイル → fsync → rename の原子的置換。シンボリックリンクは拒否する。
//!
//! パース規則: 入力は UTF-8（先頭 BOM は許容）。NUL は拒否。前後の空白を除いて判定し、空行・`#` / `;`
//! 始まりのコメント・`[name]`（閉じ括弧の後ろはコメントのみ可）・`key=value` を受理し、それ以外は
//! `INVALID_ARGUMENT`。セクション名とキー名は ASCII 大文字小文字を区別しない。値は trim して
//! `true` / `false`（大文字小文字不問）のみ真偽として扱い、行内コメントは解釈しない（値の一部になり
//! [`VirtiofsState::Other`] になる）。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{WinError, WinErrorCode};

/// virtiofs を設定するセクション名（WIN-2。実機検証は未了）。
pub const WSL2_SECTION: &str = "wsl2";
/// virtiofs を有効にするキー名（WIN-2。実機検証は未了）。
pub const VIRTIOFS_KEY: &str = "virtiofs";
/// `.wslconfig` として読み書きする最大バイト数（無制限確保による DoS の防止）。
pub const MAX_WSLCONFIG_BYTES: u64 = 64 * 1024;
/// 新規ファイル・改行のないファイルで使う改行。`.wslconfig` は Windows のユーザー設定ファイルで
/// 内部データファイル（LF 固定）の対象外のため、メモ帳等との整合を優先して CRLF とする。
const DEFAULT_EOL: &str = "\r\n";
const BOM: char = '\u{FEFF}';

/// `.wslconfig` の `[wsl2]` における `virtiofs` の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtiofsState {
    /// `true`（大文字小文字不問）。
    Enabled,
    /// `false`（大文字小文字不問）。
    Disabled,
    /// `[wsl2]` に `virtiofs` キーがない。
    Unset,
    /// `true` / `false` 以外の値。
    Other,
}

/// [`WslConfig::enable_virtiofs`] の結果（メモリ上の編集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtiofsEdit {
    /// キーを新規に追加した。
    Added,
    /// 既存のキーを `true` に更新した。`previous` は更新前の状態（`Disabled` の上書きを上位が警告できる）。
    Updated {
        /// 更新前の状態。
        previous: VirtiofsState,
    },
    /// すでに有効で、何も変更していない。
    AlreadyEnabled,
}

/// [`enable_virtiofs_at`] の結果（ファイル操作）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnableOutcome {
    /// ファイルがなかったため新規作成した。
    Created,
    /// キーを追加した。
    Added,
    /// 既存のキーを `true` に更新した。
    Updated {
        /// 更新前の状態。
        previous: VirtiofsState,
    },
    /// すでに有効で、ファイルへ一切書き込んでいない。
    AlreadyEnabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Blank,
    Comment,
    /// 小文字化したセクション名。
    Section(String),
    /// `section` は小文字化したセクション名（セクション前のグローバルは `None`）。`key` は小文字化済み。
    Key {
        section: Option<String>,
        key: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    /// 改行を除いた原文。
    body: String,
    /// 行末の改行（`"\r\n"`・`"\n"`、最終行で改行なしなら空）。
    eol: String,
    kind: Kind,
}

/// 解析済みの `.wslconfig`（行ごとの原文を保持する）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslConfig {
    bom: bool,
    lines: Vec<Line>,
}

fn err(code: WinErrorCode, message: impl Into<String>) -> WinError {
    WinError::new(code, message)
}

fn bad_line(n: usize, what: &str) -> WinError {
    err(WinErrorCode::InvalidArgument, format!("line {n}: {what}"))
}

fn is_comment_start(s: &str) -> bool {
    s.starts_with('#') || s.starts_with(';')
}

fn classify_value(value: &str) -> VirtiofsState {
    let v = value.trim();
    if v.eq_ignore_ascii_case("true") {
        VirtiofsState::Enabled
    } else if v.eq_ignore_ascii_case("false") {
        VirtiofsState::Disabled
    } else {
        VirtiofsState::Other
    }
}

fn is_virtiofs_key(kind: &Kind) -> Option<&str> {
    match kind {
        Kind::Key {
            section: Some(s),
            key,
            value,
        } if s == WSL2_SECTION && key == VIRTIOFS_KEY => Some(value.as_str()),
        _ => None,
    }
}

impl WslConfig {
    /// テキストを解析する（純関数）。構文エラーは行番号だけを含む `INVALID_ARGUMENT`、
    /// 上限超過は `RESOURCE_EXHAUSTED`。panic しない。
    pub fn parse(text: &str) -> Result<Self, WinError> {
        if text.len() as u64 > MAX_WSLCONFIG_BYTES {
            return Err(err(
                WinErrorCode::ResourceExhausted,
                format!("input exceeds {MAX_WSLCONFIG_BYTES} bytes"),
            ));
        }
        if text.contains('\0') {
            return Err(err(WinErrorCode::InvalidArgument, "input contains NUL"));
        }
        let (bom, text) = match text.strip_prefix(BOM) {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let mut lines = Vec::new();
        let mut section: Option<String> = None;
        for (i, chunk) in text.split_inclusive('\n').enumerate() {
            let n = i + 1;
            let (body, eol) = if let Some(b) = chunk.strip_suffix("\r\n") {
                (b, "\r\n")
            } else if let Some(b) = chunk.strip_suffix('\n') {
                (b, "\n")
            } else {
                (chunk, "")
            };
            let t = body.trim();
            let kind = if t.is_empty() {
                Kind::Blank
            } else if is_comment_start(t) {
                Kind::Comment
            } else if let Some(rest) = t.strip_prefix('[') {
                let (name, after) = rest
                    .split_once(']')
                    .ok_or_else(|| bad_line(n, "unterminated section header"))?;
                let name = name.trim();
                if name.is_empty() {
                    return Err(bad_line(n, "empty section name"));
                }
                let after = after.trim();
                if !after.is_empty() && !is_comment_start(after) {
                    return Err(bad_line(n, "unexpected text after section header"));
                }
                let name = name.to_ascii_lowercase();
                section = Some(name.clone());
                Kind::Section(name)
            } else if let Some((k, v)) = t.split_once('=') {
                let k = k.trim();
                if k.is_empty() {
                    return Err(bad_line(n, "empty key"));
                }
                Kind::Key {
                    section: section.clone(),
                    key: k.to_ascii_lowercase(),
                    value: v.trim().to_string(),
                }
            } else {
                return Err(bad_line(n, "expected key=value"));
            };
            lines.push(Line {
                body: body.to_string(),
                eol: eol.to_string(),
                kind,
            });
        }
        Ok(Self { bom, lines })
    }

    /// `[wsl2]` の `virtiofs` の状態を返す。複数ある場合は有効でない最初のものの状態（すべて有効なら `Enabled`）。
    pub fn virtiofs_state(&self) -> VirtiofsState {
        let mut found = false;
        for line in &self.lines {
            if let Some(v) = is_virtiofs_key(&line.kind) {
                found = true;
                let st = classify_value(v);
                if st != VirtiofsState::Enabled {
                    return st;
                }
            }
        }
        if found {
            VirtiofsState::Enabled
        } else {
            VirtiofsState::Unset
        }
    }

    /// 最初に見つかった改行の種類（なければ [`DEFAULT_EOL`]）。
    fn file_eol(&self) -> String {
        self.lines
            .iter()
            .find(|l| !l.eol.is_empty())
            .map(|l| l.eol.clone())
            .unwrap_or_else(|| DEFAULT_EOL.to_string())
    }

    fn new_key_line(eol: String, indent: &str) -> Line {
        Line {
            body: format!("{indent}{VIRTIOFS_KEY}=true"),
            eol,
            kind: Kind::Key {
                section: Some(WSL2_SECTION.to_string()),
                key: VIRTIOFS_KEY.to_string(),
                value: "true".to_string(),
            },
        }
    }

    /// `[wsl2]` に `virtiofs=true` を設定する（メモリ上のみ。純関数）。
    ///
    /// - `[wsl2]` 配下の一致キーが複数あれば、有効でないものをすべて `true` に書き換える（WSL 側の
    ///   どの出現が優先されても同じ結果になるようにするため）。元のインデントは保つが行内コメントは失われる。
    /// - 一致キーがなく `[wsl2]` がある場合は、最初の `[wsl2]` の最後の非空行の直後に挿入する。
    /// - `[wsl2]` がない場合は末尾へ追加する。
    /// - 改行は既存ファイルの最初の改行に合わせる（なければ CRLF）。
    pub fn enable_virtiofs(&mut self) -> VirtiofsEdit {
        let eol = self.file_eol();
        let matches: Vec<usize> = self
            .lines
            .iter()
            .enumerate()
            .filter(|(_, l)| is_virtiofs_key(&l.kind).is_some())
            .map(|(i, _)| i)
            .collect();
        if !matches.is_empty() {
            let mut previous = None;
            for i in matches {
                let Some(line) = self.lines.get_mut(i) else {
                    continue;
                };
                let st = is_virtiofs_key(&line.kind)
                    .map(classify_value)
                    .unwrap_or(VirtiofsState::Other);
                if st == VirtiofsState::Enabled {
                    continue;
                }
                previous.get_or_insert(st);
                let indent_len = line.body.len() - line.body.trim_start().len();
                let indent = line.body.get(..indent_len).unwrap_or("").to_string();
                let eol = std::mem::take(&mut line.eol);
                *line = Self::new_key_line(eol, &indent);
            }
            return match previous {
                Some(previous) => VirtiofsEdit::Updated { previous },
                None => VirtiofsEdit::AlreadyEnabled,
            };
        }

        let header = self
            .lines
            .iter()
            .position(|l| matches!(&l.kind, Kind::Section(s) if s == WSL2_SECTION));
        if let Some(h) = header {
            let end = self
                .lines
                .iter()
                .enumerate()
                .skip(h + 1)
                .find(|(_, l)| matches!(l.kind, Kind::Section(_)))
                .map_or(self.lines.len(), |(i, _)| i);
            let anchor = self
                .lines
                .iter()
                .enumerate()
                .take(end)
                .skip(h)
                .filter(|(_, l)| l.kind != Kind::Blank)
                .map(|(i, _)| i)
                .next_back()
                .unwrap_or(h);
            // 挿入位置の直後に行が続くなら改行付き。末尾（改行なしで終わるファイル）なら改行なしを保つ。
            let mut new_eol = eol.clone();
            if let Some(a) = self.lines.get_mut(anchor)
                && a.eol.is_empty()
            {
                a.eol = eol;
                new_eol = String::new();
            }
            self.lines
                .insert(anchor + 1, Self::new_key_line(new_eol, ""));
            return VirtiofsEdit::Added;
        }

        if let Some(last) = self.lines.last_mut()
            && last.eol.is_empty()
        {
            last.eol = eol.clone();
        }
        if self.lines.last().is_some_and(|l| l.kind != Kind::Blank) {
            self.lines.push(Line {
                body: String::new(),
                eol: eol.clone(),
                kind: Kind::Blank,
            });
        }
        self.lines.push(Line {
            body: format!("[{WSL2_SECTION}]"),
            eol: eol.clone(),
            kind: Kind::Section(WSL2_SECTION.to_string()),
        });
        self.lines.push(Self::new_key_line(eol, ""));
        VirtiofsEdit::Added
    }

    /// テキストへ戻す（純関数）。未変更の行は入力とバイト単位で一致する。
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.bom {
            out.push(BOM);
        }
        for l in &self.lines {
            out.push_str(&l.body);
            out.push_str(&l.eol);
        }
        out
    }
}

fn io_err(e: &std::io::Error, what: &str) -> WinError {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound => WinErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => WinErrorCode::PermissionDenied,
        _ => WinErrorCode::Internal,
    };
    err(code, what)
}

/// 事前に通常ファイルと確認したパスを開き、開いたハンドル自身を検証する。
///
/// パスの再解決による検査と使用の競合（TOCTOU）を避けるため、読み込みは必ずここで検証したハンドルから行う。
/// Windows はリパースポイントを辿らずに開き、ハンドルの属性がリンクでないことを確認する。unix は開いた後に
/// パスを `symlink_metadata` で引き直し、ハンドルと同一の inode（dev / ino）の通常ファイルであることを確認する
/// （検査後にリンクや別ファイルへ差し替えられていれば拒否する）。
fn open_verified(path: &Path) -> Result<std::fs::File, WinError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: リパースポイントを辿らず、リンク自体を開く。
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts
        .open(path)
        .map_err(|e| io_err(&e, "failed to open .wslconfig"))?;
    let handle_meta = file
        .metadata()
        .map_err(|e| io_err(&e, "failed to stat .wslconfig"))?;
    if handle_meta.file_type().is_symlink() || !handle_meta.is_file() {
        return Err(err(
            WinErrorCode::PermissionDenied,
            ".wslconfig is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let now =
            std::fs::symlink_metadata(path).map_err(|e| io_err(&e, "failed to stat .wslconfig"))?;
        if now.file_type().is_symlink()
            || now.dev() != handle_meta.dev()
            || now.ino() != handle_meta.ino()
        {
            return Err(err(
                WinErrorCode::PermissionDenied,
                ".wslconfig changed while it was being opened",
            ));
        }
    }
    Ok(file)
}

/// `.wslconfig` を読み込む。ファイルがなければ `Ok(None)`。
///
/// シンボリックリンク・通常ファイル以外は拒否し（fail-closed）、[`MAX_WSLCONFIG_BYTES`] を超えるものと
/// 非 UTF-8 は `Err`。
pub fn load(path: &Path) -> Result<Option<WslConfig>, WinError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(&e, "failed to stat .wslconfig")),
    };
    if meta.file_type().is_symlink() {
        return Err(err(
            WinErrorCode::PermissionDenied,
            ".wslconfig is a symbolic link",
        ));
    }
    if !meta.is_file() {
        return Err(err(
            WinErrorCode::InvalidArgument,
            ".wslconfig is not a regular file",
        ));
    }
    let file = open_verified(path)?;
    let mut buf = Vec::new();
    file.take(MAX_WSLCONFIG_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_err(&e, "failed to read .wslconfig"))?;
    if buf.len() as u64 > MAX_WSLCONFIG_BYTES {
        return Err(err(
            WinErrorCode::ResourceExhausted,
            format!(".wslconfig exceeds {MAX_WSLCONFIG_BYTES} bytes"),
        ));
    }
    let text = String::from_utf8(buf).map_err(|_| {
        err(
            WinErrorCode::InvalidArgument,
            ".wslconfig is not valid UTF-8",
        )
    })?;
    WslConfig::parse(&text).map(Some)
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 書き込みの意図。読み込み時点でのファイルの有無を呼び出し側から引き継ぐ。
#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    /// 読み込み時点でファイルが存在しなかった。宛先が現れていたら置換せず `Err`（排他的な新規作成）。
    CreateOnly,
    /// 読み込み時点でファイルが存在した。既存の内容を置き換える。
    Replace,
}

/// 同一ディレクトリに一意名の一時ファイルのパスを作る。
fn tmp_path(parent: &Path, tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    parent.join(format!(
        ".wslconfig.{tag}.{}.{}.{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        nanos
    ))
}

/// 一時ファイルを排他的に作り、`data` を書いて fsync する。失敗時は自分が作ったファイルを消す。
///
/// unix では作成時点から所有者のみ（0600）で作り、`perm_from` があればその権限へ揃えてから内容を書く。
/// 既定の作成権限（umask 次第で他ユーザー読み取り可）のまま書くと、`kernelCommandLine` 等の秘密情報が
/// 権限調整までの間だけ漏れうるため、書き込みより前に権限を確定させる。
fn write_new_file(
    tmp: &Path,
    data: &[u8],
    perm_from: Option<&Path>,
) -> Result<std::fs::File, WinError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(tmp)
        .map_err(|e| io_err(&e, "failed to create temporary file"))?;
    let result = (|| -> Result<(), WinError> {
        #[cfg(unix)]
        if let Some(src) = perm_from {
            // 宛先が消えていた場合のみ 0600 のまま続行する。それ以外の失敗は書き込み前に中止する。
            match std::fs::metadata(src) {
                Ok(m) => f
                    .set_permissions(m.permissions())
                    .map_err(|e| io_err(&e, "failed to copy file permissions"))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&e, "failed to copy file permissions")),
            }
        }
        #[cfg(not(unix))]
        let _ = perm_from;
        f.write_all(data)
            .and_then(|()| f.sync_all())
            .map_err(|e| io_err(&e, "failed to write temporary file"))
    })();
    match result {
        Ok(()) => Ok(f),
        Err(e) => {
            drop(f);
            let _ = std::fs::remove_file(tmp);
            Err(e)
        }
    }
}

/// `.wslconfig` を書き込む。`mode` により新規作成の排他性と既存置換の方式が変わる。
///
/// - [`WriteMode::CreateOnly`]: 一時ファイルへ書いて fsync した後、`hard_link` で宛先に公開する。
///   `hard_link` は宛先が存在すれば失敗する（既存を置換しない）ため、読み込みから公開までの間に
///   別プロセスが作った `.wslconfig` を上書きしない（`Err` を返し元のまま残す）。公開後に一時名を消す。
/// - [`WriteMode::Replace`]: 一時ファイル → fsync → rename で原子的に置き換える（全 OS 共通）。途中で
///   強制終了しても宛先は旧内容か新内容のどちらかで、欠損・混在しない。unix では既存の宛先の
///   パーミッションを書き込み前に一時ファイルへ引き継ぐ。Windows の rename は既存ファイルを置換し、
///   置換後の ACL は親ディレクトリから継承した既定になる（エディタの一時ファイル保存と同じ。
///   ACL の複製には Win32 API が必要で、依存追加はユーザー承認制のため行わない）。rename 成功後の
///   親ディレクトリ fsync（unix）に失敗した場合は置換済みのまま `Err` を返す。
///
/// 失敗時は自分が作った一時ファイルだけを削除する。読み込みから書き込みまでの間の他プロセスによる
/// 変更はロックしない（単一ユーザーのホーム配下の設定操作のため許容。新規作成の競合のみ上記で拒否する）。
fn write_atomic(path: &Path, data: &[u8], mode: WriteMode) -> Result<(), WinError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tmp_path(parent, "tmp");
    if mode == WriteMode::CreateOnly {
        drop(write_new_file(&tmp, data, None)?);
        let linked = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        return match linked {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(err(
                WinErrorCode::Internal,
                ".wslconfig was created concurrently; refusing to replace it",
            )),
            Err(e) => Err(io_err(&e, "failed to create .wslconfig")),
        };
    }
    drop(write_new_file(&tmp, data, Some(path))?);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(&e, "failed to replace .wslconfig"));
    }
    #[cfg(unix)]
    {
        // rename の反映先を永続化する。失敗しても内容は置換済みのため成功を装わずエラーにする。
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| io_err(&e, "failed to sync parent directory"))?;
    }
    Ok(())
}

/// `path` の `.wslconfig` に `virtiofs=true` を opt-in する（読み込み → 編集 → 原子的書き込み）。
///
/// ファイルがなければ新規作成（親ディレクトリは作らず、なければ `NOT_FOUND`）。すでに有効なら書き込まない。
/// `Err` のとき通常は元のファイルを変更しない。例外として unix で rename 後の親ディレクトリ fsync に
/// 失敗した場合は、置換済みのまま `Err` になりうる。TASK-67.4（#375）の起動ロジックから呼ばれる想定。
pub fn enable_virtiofs_at(path: &Path) -> Result<EnableOutcome, WinError> {
    let (mut cfg, existed) = match load(path)? {
        Some(c) => (c, true),
        None => (WslConfig::parse("")?, false),
    };
    let edit = cfg.enable_virtiofs();
    if edit == VirtiofsEdit::AlreadyEnabled {
        return Ok(EnableOutcome::AlreadyEnabled);
    }
    let text = cfg.render();
    if text.len() as u64 > MAX_WSLCONFIG_BYTES {
        return Err(err(
            WinErrorCode::ResourceExhausted,
            format!("result exceeds {MAX_WSLCONFIG_BYTES} bytes"),
        ));
    }
    let mode = if existed {
        WriteMode::Replace
    } else {
        WriteMode::CreateOnly
    };
    write_atomic(path, text.as_bytes(), mode)?;
    Ok(match edit {
        _ if !existed => EnableOutcome::Created,
        VirtiofsEdit::Updated { previous } => EnableOutcome::Updated { previous },
        _ => EnableOutcome::Added,
    })
}

/// 既定の `.wslconfig` のパス（`%UserProfile%\.wslconfig`）を返す。
///
/// Windows 以外では `UNIMPLEMENTED`（fail-closed）。`USERPROFILE` が未設定・空・相対パスなら `Err`。
#[cfg(windows)]
pub fn default_path() -> Result<PathBuf, WinError> {
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or_else(|| err(WinErrorCode::NotFound, "USERPROFILE is not set"))?;
    if base.as_os_str().is_empty() || !base.is_absolute() {
        return Err(err(
            WinErrorCode::InvalidArgument,
            "USERPROFILE is not an absolute path",
        ));
    }
    Ok(base.join(".wslconfig"))
}

/// 既定の `.wslconfig` のパス。Windows 以外では常に `UNIMPLEMENTED`（fail-closed）。
#[cfg(not(windows))]
pub fn default_path() -> Result<PathBuf, WinError> {
    Err(err(
        WinErrorCode::Unimplemented,
        "default .wslconfig path is only available on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enable(input: &str) -> (VirtiofsEdit, String) {
        let mut c = WslConfig::parse(input).expect("parse");
        let e = c.enable_virtiofs();
        (e, c.render())
    }

    /// WIN-2・TASK-67.2: 他セクション・他キー・コメント・空行を保ち 1 行だけ挿入する（AC1）。
    #[test]
    fn adds_key_preserving_everything_else() {
        let input = "# top\r\nglobal=1\r\n\r\n[experimental]\r\nsparseVhd=true\r\n\r\n[wsl2]\r\nmemory=4GB\r\n; note\r\n\r\n[boot]\r\nsystemd=true\r\n";
        let (e, out) = enable(input);
        assert_eq!(e, VirtiofsEdit::Added);
        assert_eq!(
            out,
            "# top\r\nglobal=1\r\n\r\n[experimental]\r\nsparseVhd=true\r\n\r\n[wsl2]\r\nmemory=4GB\r\n; note\r\nvirtiofs=true\r\n\r\n[boot]\r\nsystemd=true\r\n"
        );
    }

    /// WIN-2: 改行なしの末尾空白行があってもセクションが連結されない（レビュー指摘 P1）。
    #[test]
    fn appends_section_after_trailing_blank_without_eol() {
        let (e, out) = enable("[boot]\n   ");
        assert_eq!(e, VirtiofsEdit::Added);
        assert_eq!(out, "[boot]\n   \n[wsl2]\nvirtiofs=true\n");
    }

    /// WIN-2: `[wsl2]` がなければ末尾に区切りの空行つきで追加する（AC1）。
    #[test]
    fn appends_section_when_missing() {
        let (e, out) = enable("[boot]\nsystemd=true\n");
        assert_eq!(e, VirtiofsEdit::Added);
        assert_eq!(out, "[boot]\nsystemd=true\n\n[wsl2]\nvirtiofs=true\n");
        // 末尾改行なし。
        let (_, out) = enable("[boot]\nsystemd=true");
        assert_eq!(out, "[boot]\nsystemd=true\n\n[wsl2]\nvirtiofs=true\n");
    }

    /// WIN-2: 末尾改行のない `[wsl2]` 末尾への挿入は改行なしを保つ。
    #[test]
    fn insert_at_end_without_trailing_newline() {
        let (e, out) = enable("[wsl2]\nmemory=4GB");
        assert_eq!(e, VirtiofsEdit::Added);
        assert_eq!(out, "[wsl2]\nmemory=4GB\nvirtiofs=true");
    }

    /// WIN-2: 空の `[wsl2]` セクションへ挿入する。
    #[test]
    fn inserts_into_empty_section() {
        let (_, out) = enable("[wsl2]\n\n[boot]\n");
        assert_eq!(out, "[wsl2]\nvirtiofs=true\n\n[boot]\n");
    }

    /// WIN-2: `virtiofs=false` の更新。大文字小文字・インデントを許容し、previous で区別できる。
    #[test]
    fn updates_false_and_case_insensitive() {
        let (e, out) = enable("[WSL2]\n  VirtioFS = False\nmemory=1GB\n");
        assert_eq!(
            e,
            VirtiofsEdit::Updated {
                previous: VirtiofsState::Disabled
            }
        );
        assert_eq!(out, "[WSL2]\n  virtiofs=true\nmemory=1GB\n");
        let (e, _) = enable("[wsl2]\nvirtiofs=maybe\n");
        assert_eq!(
            e,
            VirtiofsEdit::Updated {
                previous: VirtiofsState::Other
            }
        );
    }

    /// WIN-2: 重複キー・重複セクションの `[wsl2]` 配下をすべて書き換える。他セクションの同名キーは触らない。
    #[test]
    fn rewrites_all_duplicates_in_wsl2_only() {
        let input =
            "[wsl2]\nvirtiofs=false\n[x]\nvirtiofs=false\n[wsl2]\nvirtiofs=0\nvirtiofs=true\n";
        let (e, out) = enable(input);
        assert_eq!(
            e,
            VirtiofsEdit::Updated {
                previous: VirtiofsState::Disabled
            }
        );
        assert_eq!(
            out,
            "[wsl2]\nvirtiofs=true\n[x]\nvirtiofs=false\n[wsl2]\nvirtiofs=true\nvirtiofs=true\n"
        );
    }

    /// WIN-2: 改行の種類と BOM を保つ。新規（空）入力は CRLF。
    #[test]
    fn keeps_eol_and_bom() {
        let (_, out) = enable("\u{FEFF}[boot]\nsystemd=true\n");
        assert_eq!(
            out,
            "\u{FEFF}[boot]\nsystemd=true\n\n[wsl2]\nvirtiofs=true\n"
        );
        let (_, out) = enable("");
        assert_eq!(out, "[wsl2]\r\nvirtiofs=true\r\n");
    }

    /// WIN-2: すでに有効なら変更せず、2 回目は AlreadyEnabled（冪等）。
    #[test]
    fn already_enabled_is_identity() {
        let input = "[wsl2]\r\nvirtiofs=TRUE # keep?\r\n";
        // 行内コメントは値の一部となり Other 扱い。
        let (e, _) = enable(input);
        assert!(matches!(e, VirtiofsEdit::Updated { .. }));
        let input = "[wsl2]\r\nvirtiofs = true\r\n";
        let (e, out) = enable(input);
        assert_eq!(e, VirtiofsEdit::AlreadyEnabled);
        assert_eq!(out, input);
        let mut c = WslConfig::parse("[boot]\n").expect("parse");
        assert_eq!(c.virtiofs_state(), VirtiofsState::Unset);
        assert_eq!(c.enable_virtiofs(), VirtiofsEdit::Added);
        assert_eq!(c.virtiofs_state(), VirtiofsState::Enabled);
        assert_eq!(c.enable_virtiofs(), VirtiofsEdit::AlreadyEnabled);
    }

    /// WIN-2・AC3: 構文エラーは INVALID_ARGUMENT で、message は行番号のみ（入力の断片を含まない）。
    #[test]
    fn parse_errors_report_line_only() {
        let cases = [
            ("[wsl2\n", "line 1: unterminated section header"),
            ("[]\n", "line 1: empty section name"),
            ("[a] junk\n", "line 1: unexpected text after section header"),
            ("[a]\nsecret_token\n", "line 2: expected key=value"),
            ("[a]\n=secret\n", "line 2: empty key"),
        ];
        for (input, msg) in cases {
            let e = WslConfig::parse(input).expect_err("must fail");
            assert_eq!(e.code(), WinErrorCode::InvalidArgument, "{input:?}");
            assert_eq!(e.message(), msg);
        }
        let e = WslConfig::parse("a=1\0\n").expect_err("nul");
        assert_eq!(e.code(), WinErrorCode::InvalidArgument);
        let big = "#".repeat(MAX_WSLCONFIG_BYTES as usize + 1);
        let e = WslConfig::parse(&big).expect_err("big");
        assert_eq!(e.code(), WinErrorCode::ResourceExhausted);
    }

    /// 値が空でも `]` 後ろのコメントでも受理する。
    #[test]
    fn accepts_comment_after_header_and_empty_value() {
        let c = WslConfig::parse("[wsl2] # c\nvirtiofs=\n").expect("parse");
        assert_eq!(c.virtiofs_state(), VirtiofsState::Other);
    }

    use std::path::PathBuf;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-wslconfig-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
        fn file(&self) -> PathBuf {
            self.0.join(".wslconfig")
        }
        fn entries(&self) -> Vec<String> {
            std::fs::read_dir(&self.0)
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// WIN-2: 新規作成モードで宛先が既に存在する（競合で現れた）場合は置換せず Err、一時ファイルも残さない。
    #[test]
    fn create_only_refuses_to_replace_existing_file() {
        let d = TmpDir::new("createrace");
        std::fs::write(d.file(), "[wsl2]\nmemory=4GB\n").expect("write");
        let e = write_atomic(
            &d.file(),
            b"[wsl2]\r\nvirtiofs=true\r\n",
            WriteMode::CreateOnly,
        )
        .expect_err("must refuse");
        assert_eq!(e.code(), WinErrorCode::Internal);
        assert_eq!(
            std::fs::read(d.file()).expect("read"),
            b"[wsl2]\nmemory=4GB\n"
        );
        assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
    }

    /// WIN-2・AC2: ファイルがなければ新規作成する。
    #[test]
    fn creates_missing_file() {
        let d = TmpDir::new("create");
        assert_eq!(enable_virtiofs_at(&d.file()), Ok(EnableOutcome::Created));
        assert_eq!(
            std::fs::read(d.file()).expect("read"),
            b"[wsl2]\r\nvirtiofs=true\r\n"
        );
        assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
    }

    /// WIN-2・AC1: 既存ファイルを更新し、一時ファイルが残らない。再実行は書き込まない。
    #[test]
    fn updates_existing_file_and_is_idempotent() {
        let d = TmpDir::new("update");
        std::fs::write(d.file(), "[wsl2]\nmemory=4GB\n").expect("write");
        assert_eq!(enable_virtiofs_at(&d.file()), Ok(EnableOutcome::Added));
        assert_eq!(
            std::fs::read(d.file()).expect("read"),
            b"[wsl2]\nmemory=4GB\nvirtiofs=true\n"
        );
        assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
        assert_eq!(
            enable_virtiofs_at(&d.file()),
            Ok(EnableOutcome::AlreadyEnabled)
        );
        assert_eq!(
            std::fs::read(d.file()).expect("read"),
            b"[wsl2]\nmemory=4GB\nvirtiofs=true\n"
        );
    }

    /// WIN-2・AC3: 不正・非 UTF-8・上限超えは Err で、元ファイルは無変更・一時ファイルなし。
    #[test]
    fn invalid_inputs_leave_file_untouched() {
        let cases: Vec<(Vec<u8>, WinErrorCode)> = vec![
            (b"[wsl2\nx=1\n".to_vec(), WinErrorCode::InvalidArgument),
            (vec![0xff, 0xfe, b'[', 0], WinErrorCode::InvalidArgument),
            (
                vec![b'#'; MAX_WSLCONFIG_BYTES as usize + 1],
                WinErrorCode::ResourceExhausted,
            ),
        ];
        for (bytes, code) in cases {
            let d = TmpDir::new("invalid");
            std::fs::write(d.file(), &bytes).expect("write");
            let e = enable_virtiofs_at(&d.file()).expect_err("must fail");
            assert_eq!(e.code(), code);
            assert_eq!(std::fs::read(d.file()).expect("read"), bytes);
            assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
        }
    }

    /// 結果が上限を超える場合は書き込まず RESOURCE_EXHAUSTED。
    #[test]
    fn result_over_limit_is_rejected() {
        let d = TmpDir::new("limit");
        let body = "#".repeat(MAX_WSLCONFIG_BYTES as usize - 4);
        std::fs::write(d.file(), &body).expect("write");
        let e = enable_virtiofs_at(&d.file()).expect_err("must fail");
        assert_eq!(e.code(), WinErrorCode::ResourceExhausted);
        assert_eq!(std::fs::read(d.file()).expect("read"), body.as_bytes());
    }

    /// 親ディレクトリがなければ NOT_FOUND（親は作らない）。
    #[test]
    fn missing_parent_is_not_found() {
        let d = TmpDir::new("noparent");
        let p = d.0.join("nope").join(".wslconfig");
        let e = enable_virtiofs_at(&p).expect_err("must fail");
        assert_eq!(e.code(), WinErrorCode::NotFound);
        assert!(!d.0.join("nope").exists());
    }

    /// 既存ファイルのパーミッションは置換後も引き継がれる（unix）。
    #[cfg(unix)]
    #[test]
    fn enable_virtiofs_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new("perm");
        std::fs::write(d.file(), "[wsl2]\nmemory=4GB\n").unwrap();
        std::fs::set_permissions(d.file(), std::fs::Permissions::from_mode(0o600)).unwrap();
        enable_virtiofs_at(&d.file()).unwrap();
        let mode = std::fs::metadata(d.file()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// WIN-2: 一時ファイルは作成時点から 0600 で、内容を書く前に権限が確定している（unix）。
    #[cfg(unix)]
    #[test]
    fn new_temp_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new("tmpmode");
        let tmp = d.0.join("t");
        drop(write_new_file(&tmp, b"secret", None).unwrap());
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// シンボリックリンクの `.wslconfig` は拒否しリンク先を変更しない。
    /// Windows ではシンボリックリンクの作成に特権が要るため unix に限定する。
    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected() {
        let d = TmpDir::new("symlink");
        let target = d.0.join("target");
        std::fs::write(&target, "[wsl2]\n").expect("write");
        std::os::unix::fs::symlink(&target, d.file()).expect("symlink");
        let e = enable_virtiofs_at(&d.file()).expect_err("must fail");
        assert_eq!(e.code(), WinErrorCode::PermissionDenied);
        assert_eq!(std::fs::read(&target).expect("read"), b"[wsl2]\n");
    }

    #[cfg(not(windows))]
    #[test]
    fn default_path_is_unimplemented_off_windows() {
        let e = default_path().expect_err("must fail");
        assert_eq!(e.code(), WinErrorCode::Unimplemented);
    }

    #[cfg(windows)]
    #[test]
    fn default_path_ends_with_wslconfig() {
        let p = default_path().expect("USERPROFILE");
        assert!(p.ends_with(".wslconfig"));
    }
}
