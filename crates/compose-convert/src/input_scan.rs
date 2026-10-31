//! 入力ディレクトリの走査と読み込み（TASK-151.5・#600・STACK-3・MS-12）。
//!
//! 変換器の入力段。bin（#602・TASK-151.7）が入力ディレクトリを渡して [`load_input_dir`] を呼び、
//! 返った本文を [`crate::compose_convert::parse_compose_yaml`] へ渡す。変換・出力は全件読めた後にだけ行う想定で、
//! 失敗時に部分結果を返さない（読めなかったファイルが黙って欠ける fail-open を作らない）。
//!
//! PoC-16 は `read_dir` の反復エラーだけを伝播し、mode 000 のファイルや切れた symlink は後段の
//! `read_to_string(..).expect(..)` で panic していた。本モジュールは検査と読み込みの全失敗を構造化エラーにし、
//! ERR-2 の対応表と同じ非 0 の終了コードへ写す（STACK-3）。
//!
//! # 契約
//!
//! - 走査は非再帰。拡張子が `yml` / `yaml`（小文字の完全一致。PoC と同じ）のエントリだけが候補で、他は読まず無視する。
//! - 候補は通常ファイルのみ許す。拡張子が yaml のディレクトリ・FIFO・デバイス・切れた symlink は黙ってスキップせず停止する。
//! - 1 件でも失敗したら即 `Err`。成功時はファイル名（`OsString`）の昇順で返す。
//! - エントリ数・候補件数・1 ファイルのバイト数・総バイト数に上限がある（超過は `ResourceExhausted`）。
//! - `message` は固定の英語文言で、ファイルの中身・OS のエラー詳細は載せない。パスは構造化フィールド `path` に分け、
//!   端末へ出す際のエスケープは bin（#602）の責務とする。
//!
//! # 残余（REPAIR-3）
//!
//! - 検査（`metadata`）と `open` の間に FIFO へすり替えられると読み込みが止まりうる（TOCTOU）。`O_NONBLOCK` は
//!   自前 FFI 定数が要り、この crate には `sys` が無いため入れない。入力ディレクトリは実行者自身のもので、
//!   すり替えられる者は入力も自由に書ける前提とする。
//! - 大文字拡張子（`.YAML`）は候補にしない。case-insensitive FS の扱い（IO-5）は現状維持。
//! - `file_id` の導出と `compose.yml` / `compose.yaml` の同名重複の検出は出力名の関心事で、#602 が担う。

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};

use crate::compose_convert::COMPOSE_MAX_INPUT_BYTES;

/// 走査するディレクトリエントリ総数の上限（候補以外も数える）。
pub const COMPOSE_MAX_DIR_ENTRIES: usize = 65_536;
/// 候補（`yml` / `yaml`）の件数の上限。
pub const COMPOSE_MAX_INPUT_FILES: usize = 1_024;
/// 全候補の合計バイト数の上限。
pub const COMPOSE_MAX_TOTAL_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// 読み込み済みの 1 入力ファイル。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeInput {
    path: PathBuf,
    text: String,
}

impl ComposeInput {
    /// 入力ディレクトリ配下のファイルパス。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// UTF-8 の本文（補間・パース前の生の値）。
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// エラー分類。値は ERR-1 の流儀の機械可読コード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComposeInputErrorCode {
    /// 入力の形が不正（ディレクトリでない・通常ファイルでない・UTF-8 でない）。
    InvalidArgument,
    /// 存在しない（切れた symlink を含む）。
    NotFound,
    /// 権限不足。
    PermissionDenied,
    /// 上限超過。
    ResourceExhausted,
    /// 上記以外の I/O 失敗。
    Internal,
}

impl ComposeInputErrorCode {
    /// 機械可読コード文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Internal => "INTERNAL",
        }
    }

    /// 終了コード。core の ERR-2 の対応表と同じ値を、core へ依存せずここで持つ。非 0 を型で保証する。
    pub fn exit_code(self) -> NonZeroU8 {
        let n = match self {
            Self::Internal => 1,
            Self::InvalidArgument => 2,
            Self::NotFound => 3,
            Self::PermissionDenied => 6,
            Self::ResourceExhausted => 10,
        };
        // 全て非 0 の定数。万一 0 でも 1 に倒す。
        NonZeroU8::new(n).unwrap_or(NonZeroU8::MIN)
    }
}

/// 走査・読み込みの構造化エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeInputError {
    /// 分類。
    pub code: ComposeInputErrorCode,
    /// 固定文言。
    pub message: &'static str,
    /// 対象のパス（取れた場合）。`Display` には含めない。
    pub path: Option<PathBuf>,
}

impl ComposeInputError {
    /// 終了コード。
    pub fn exit_code(&self) -> NonZeroU8 {
        self.code.exit_code()
    }
}

impl fmt::Display for ComposeInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ComposeInputError {}

fn err(
    code: ComposeInputErrorCode,
    message: &'static str,
    path: Option<&Path>,
) -> ComposeInputError {
    ComposeInputError {
        code,
        message,
        path: path.map(Path::to_path_buf),
    }
}

/// `io::ErrorKind` を分類へ写す。
fn code_for_io(kind: io::ErrorKind) -> ComposeInputErrorCode {
    match kind {
        io::ErrorKind::NotFound => ComposeInputErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ComposeInputErrorCode::PermissionDenied,
        _ => ComposeInputErrorCode::Internal,
    }
}

fn io_err(e: &io::Error, message: &'static str, path: &Path) -> ComposeInputError {
    err(code_for_io(e.kind()), message, Some(path))
}

fn is_candidate(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
    )
}

/// 入力ディレクトリ直下の `yml` / `yaml` を全件検査・読み込みして返す。1 件でも失敗したら `Err`。
pub fn load_input_dir(dir: &Path) -> Result<Vec<ComposeInput>, ComposeInputError> {
    let meta = fs::metadata(dir).map_err(|e| io_err(&e, "cannot access input directory", dir))?;
    if !meta.is_dir() {
        return Err(err(
            ComposeInputErrorCode::InvalidArgument,
            "input path is not a directory",
            Some(dir),
        ));
    }
    let rd = fs::read_dir(dir).map_err(|e| io_err(&e, "cannot read input directory", dir))?;

    let mut candidates: Vec<(OsString, PathBuf)> = Vec::new();
    let mut seen: usize = 0;
    for entry in rd {
        let entry = entry.map_err(|e| io_err(&e, "cannot read directory entry", dir))?;
        seen += 1;
        if seen > COMPOSE_MAX_DIR_ENTRIES {
            return Err(err(
                ComposeInputErrorCode::ResourceExhausted,
                "too many entries in input directory",
                Some(dir),
            ));
        }
        let path = entry.path();
        if !is_candidate(&path) {
            continue;
        }
        if candidates.len() >= COMPOSE_MAX_INPUT_FILES {
            return Err(err(
                ComposeInputErrorCode::ResourceExhausted,
                "too many input files",
                Some(dir),
            ));
        }
        candidates.push((entry.file_name(), path));
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    let mut total: usize = 0;
    let mut out = Vec::with_capacity(candidates.len());
    for (_, path) in candidates {
        let text = read_one(&path, &mut total)?;
        out.push(ComposeInput { path, text });
    }
    Ok(out)
}

/// 1 候補を検査して読む。`total` は読み込み済みの合計で、上限判定に使う。
fn read_one(path: &Path, total: &mut usize) -> Result<String, ComposeInputError> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let dangling = fs::symlink_metadata(path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            let msg = if dangling {
                "dangling or unresolvable symbolic link"
            } else {
                "cannot stat input file"
            };
            let code = if dangling && e.kind() != io::ErrorKind::PermissionDenied {
                ComposeInputErrorCode::NotFound
            } else {
                code_for_io(e.kind())
            };
            return Err(err(code, msg, Some(path)));
        }
    };
    if !meta.is_file() {
        return Err(err(
            ComposeInputErrorCode::InvalidArgument,
            "input entry is not a regular file",
            Some(path),
        ));
    }
    check_size(meta.len(), path)?;

    let file = fs::File::open(path).map_err(|e| io_err(&e, "cannot open input file", path))?;
    // 開いたハンドルで再確認する（検査後のすり替えの窓を狭める）。
    let opened = file
        .metadata()
        .map_err(|e| io_err(&e, "cannot stat input file", path))?;
    if !opened.is_file() {
        return Err(err(
            ComposeInputErrorCode::InvalidArgument,
            "input entry is not a regular file",
            Some(path),
        ));
    }
    let limit = (COMPOSE_MAX_INPUT_BYTES as u64).saturating_add(1);
    let mut buf = Vec::new();
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| io_err(&e, "cannot read input file", path))?;
    check_size(buf.len() as u64, path)?;

    *total = total.saturating_add(buf.len());
    if *total > COMPOSE_MAX_TOTAL_INPUT_BYTES {
        return Err(err(
            ComposeInputErrorCode::ResourceExhausted,
            "total input size exceeds limit",
            Some(path),
        ));
    }
    String::from_utf8(buf).map_err(|_| {
        err(
            ComposeInputErrorCode::InvalidArgument,
            "input file is not valid UTF-8",
            Some(path),
        )
    })
}

fn check_size(len: u64, path: &Path) -> Result<(), ComposeInputError> {
    if len > COMPOSE_MAX_INPUT_BYTES as u64 {
        return Err(err(
            ComposeInputErrorCode::ResourceExhausted,
            "input file exceeds size limit",
            Some(path),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// 一意な一時ディレクトリ。Drop で権限を戻して削除する。
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir()
                .join(format!("fc-compose-scan-{}-{n}-{t}", std::process::id()));
            fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn write(&self, name: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, data).expect("write");
            p
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(rd) = fs::read_dir(&self.0) {
                    for e in rd.flatten() {
                        let _ = fs::set_permissions(e.path(), fs::Permissions::from_mode(0o600));
                    }
                }
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// STACK-3: ディレクトリ名が yaml のエントリは黙ってスキップせず停止する（全 OS）。
    #[test]
    fn stack3_directory_named_yaml_is_rejected() {
        let s = Scratch::new();
        s.write("ok.yaml", b"services: {}\n");
        fs::create_dir(s.path().join("bad.yaml")).expect("mkdir");
        let e = load_input_dir(s.path()).expect_err("must fail");
        assert_eq!(e.code, ComposeInputErrorCode::InvalidArgument);
        assert_eq!(e.message, "input entry is not a regular file");
        assert_eq!(e.path, Some(s.path().join("bad.yaml")));
        assert_eq!(e.exit_code().get(), 2);
    }

    /// STACK-3: 切れた symlink は NOT_FOUND（終了コード 3）。
    #[cfg(unix)]
    #[test]
    fn stack3_dangling_symlink_is_rejected() {
        let s = Scratch::new();
        std::os::unix::fs::symlink(
            s.path().join("missing-target"),
            s.path().join("broken.yaml"),
        )
        .expect("symlink");
        let e = load_input_dir(s.path()).expect_err("must fail");
        assert_eq!(e.code, ComposeInputErrorCode::NotFound);
        assert_eq!(e.message, "dangling or unresolvable symbolic link");
        assert_eq!(e.exit_code().get(), 3);
    }

    /// STACK-3: 読めないファイルは PERMISSION_DENIED（終了コード 6）。
    /// 非 root 前提（root は DAC を越えて読める）。CI の platform-ci は非 root で走る。
    #[cfg(unix)]
    #[test]
    fn stack3_unreadable_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let p = s.write("secret.yaml", b"services: {}\n");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).expect("chmod");
        let e = load_input_dir(s.path()).expect_err("must fail (run as non-root)");
        assert_eq!(e.code, ComposeInputErrorCode::PermissionDenied);
        assert_eq!(e.exit_code().get(), 6);
    }

    /// `io::ErrorKind` の写し（root でも決定的）。
    #[test]
    fn io_kind_maps_to_code() {
        assert_eq!(
            code_for_io(io::ErrorKind::PermissionDenied),
            ComposeInputErrorCode::PermissionDenied
        );
        assert_eq!(
            code_for_io(io::ErrorKind::NotFound),
            ComposeInputErrorCode::NotFound
        );
        assert_eq!(
            code_for_io(io::ErrorKind::TimedOut),
            ComposeInputErrorCode::Internal
        );
    }

    /// ERR-2 の対応表の機械照合。全て非 0。
    #[test]
    fn exit_code_table() {
        use ComposeInputErrorCode as C;
        let t = [
            (C::Internal, 1, "INTERNAL"),
            (C::InvalidArgument, 2, "INVALID_ARGUMENT"),
            (C::NotFound, 3, "NOT_FOUND"),
            (C::PermissionDenied, 6, "PERMISSION_DENIED"),
            (C::ResourceExhausted, 10, "RESOURCE_EXHAUSTED"),
        ];
        for (c, n, s) in t {
            assert_eq!(c.exit_code().get(), n);
            assert_eq!(c.as_str(), s);
        }
    }

    #[test]
    fn missing_dir_is_not_found_and_file_is_invalid() {
        let s = Scratch::new();
        let e = load_input_dir(&s.path().join("nope")).expect_err("fail");
        assert_eq!(e.code, ComposeInputErrorCode::NotFound);
        let f = s.write("a.yaml", b"x: 1\n");
        let e = load_input_dir(&f).expect_err("fail");
        assert_eq!(e.code, ComposeInputErrorCode::InvalidArgument);
        assert_eq!(e.message, "input path is not a directory");
    }

    #[test]
    fn non_utf8_is_invalid_argument() {
        let s = Scratch::new();
        s.write("x.yaml", &[0xff, 0xfe, 0x00]);
        let e = load_input_dir(s.path()).expect_err("fail");
        assert_eq!(e.code, ComposeInputErrorCode::InvalidArgument);
        assert_eq!(e.message, "input file is not valid UTF-8");
    }

    #[test]
    fn size_limit_boundary() {
        let s = Scratch::new();
        s.write("ok.yaml", &vec![b'#'; COMPOSE_MAX_INPUT_BYTES]);
        assert_eq!(load_input_dir(s.path()).expect("at limit").len(), 1);
        s.write("big.yaml", &vec![b'#'; COMPOSE_MAX_INPUT_BYTES + 1]);
        let e = load_input_dir(s.path()).expect_err("over limit");
        assert_eq!(e.code, ComposeInputErrorCode::ResourceExhausted);
        assert_eq!(e.exit_code().get(), 10);
    }

    #[test]
    fn ok_sorted_and_ignores_other_entries() {
        let s = Scratch::new();
        s.write("b.yml", b"b: 1\n");
        s.write("a.yaml", b"a: 1\n");
        s.write("note.txt", b"x");
        fs::create_dir(s.path().join("sub")).expect("mkdir");
        let v = load_input_dir(s.path()).expect("ok");
        let names: Vec<_> = v
            .iter()
            .map(|i| i.path().file_name().map(|n| n.to_owned()))
            .collect();
        assert_eq!(
            names,
            vec![
                Some(OsString::from("a.yaml")),
                Some(OsString::from("b.yml"))
            ]
        );
        assert_eq!(v[0].text(), "a: 1\n");
        assert_eq!(v[1].text(), "b: 1\n");
    }

    /// 失敗時は部分結果を返さず、エラーに中身を載せない（SEC-1）。
    #[test]
    fn errors_do_not_leak_content() {
        let s = Scratch::new();
        s.write("a.yaml", b"environment: SECRET-SENTINEL-1\n");
        s.write("z.yaml", &[0xff, b'S', b'E', b'C', b'R', b'E', b'T']);
        let e = load_input_dir(s.path()).expect_err("fail");
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert_eq!(
            e.to_string(),
            "INVALID_ARGUMENT: input file is not valid UTF-8"
        );
    }
}
