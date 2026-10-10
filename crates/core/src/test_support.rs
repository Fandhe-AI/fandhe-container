//! テスト専用: 一時ディレクトリの排他作成ヘルパー（#1298・CORE-1・MS-2、TASK-27.4.1 の切り出し）。
//!
//! `core` の単体テスト（`exec::devices`・`exec::rootfs`・`sys` の各 `mod tests`）から使う。
//! 共有 `/tmp` では他ユーザーが同名のディレクトリや symlink を先置きできるため、
//! 予測できる固定名を「削除してから作り直す」方式では、意図しない場所を消したり辿ったりしうる
//! （`.claude/rules/security.md` の symlink・パストラバーサル方針）。
//! 本モジュールは非再帰の `mkdir`（既存名・symlink には `EEXIST`）で排他的に作り、
//! 衝突したら別名で再試行する。名前の乱数は推測を難しくする補助で、防御の本質は排他作成である。
//! `#[cfg(test)]` のみで OS 非依存にし、3 OS で未使用警告を出さないよう自己テストから使う。

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// 名前衝突時の再試行上限（無限ループ防止）。
const MAX_ATTEMPTS: usize = 16;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 排他的に作った一時ディレクトリ。drop 時に、自分が作ったこのパスだけを再帰削除する。
#[derive(Debug)]
pub(crate) struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    /// `temp_dir()`（正規化済み）直下に `fandhe-<label>-<pid>-<seq>-<rand>` を作る。
    /// `label` はテスト内の固定文字列で、パス区切りを含めない。
    pub(crate) fn new(label: &str) -> io::Result<Self> {
        debug_assert!(
            !label.contains(['/', '\\']),
            "label must be a single path component"
        );
        let parent = std::fs::canonicalize(std::env::temp_dir())?;
        let pid = std::process::id();
        let label = label.to_owned();
        let candidates = std::iter::repeat_with(move || {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            format!("fandhe-{label}-{pid}-{seq}-{:016x}", random_u64(seq))
        });
        create_unique_in(&parent, candidates, MAX_ATTEMPTS)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 実行中のカーネルの版が `major.minor` 以上か（`/proc/sys/kernel/osrelease`。Linux のみ。TASK-163 追補・#1531）。
///
/// `AT_EXECVE_CHECK`（6.14+）のようにカーネル版で結果が分かれる試験が、両方の分岐で具体値を照合するための
/// 独立した基準に使う（判定対象の syscall の結果からは導かない）。読めない・解釈できない版は panic する
/// （試験の前提が崩れたことを黙って片方の分岐に倒さない）。
#[cfg(target_os = "linux")]
pub(crate) fn kernel_at_least(major: u32, minor: u32) -> bool {
    let text =
        std::fs::read_to_string("/proc/sys/kernel/osrelease").expect("read the kernel release");
    let (got_major, got_minor) = parse_release(&text).expect("parse the kernel release");
    (got_major, got_minor) >= (major, minor)
}

/// 子プロセスの待ち時間の上限（REPAIR-5。超過したら kill して回収する）。
#[cfg(target_os = "linux")]
const CHILD_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `path` へ `content` を「子プロセス（`/bin/sh` の `cat`）」に書かせる（#1686・REPAIR-7・REPAIR-12）。
///
/// `exec::sealed_copy`・`sys` の `AT_EXECVE_CHECK` 系試験がフィクスチャ作成に使う。試験プロセス自身が
/// 書き込み用 fd を開くと、同じ libtest バイナリの他スレッドの `fork` がその複製を一瞬継承し、その間の
/// `execveat(AT_EXECVE_CHECK)` が `ETXTBSY` で不安定に失敗する。ここでは書き込み用 fd を子だけが持つため、
/// 試験プロセスの fd 表には対象 inode の書き込み用 fd が一度も現れず、他スレッドの fork も継承できない。
///
/// 契約: 返った時点で書き込んだ子は回収済みで、書き込み用 fd はどのプロセスにも残らない。mode は呼び出し側が
/// `set_permissions`（パス指定で fd を開かない）で付ける。子の失敗・期限超過・`/bin/sh` 不在は skip せずエラーにする。
/// パスは argv（`$1`）、内容は stdin の pipe で渡し、シェル文字列へ連結しない。
#[cfg(target_os = "linux")]
pub(crate) fn write_file_in_child(path: &Path, content: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new("/bin/sh")
        .args(["-c", r#"exec cat > "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("child stdin was not piped"))?;
    // 送信は別スレッドで行い、送信と終了待ちを同じ期限で保護する（REPAIR-5）。子が stdin を読まず pipe が
    // 満杯になっても、親は wait_bounded の期限で子を kill して回収し、pipe の閉鎖で送信スレッドも解放される。
    // `exec cat` によりシェルが cat 自身に置き換わるため、kill の対象が書き込み用 fd の保持者そのものになる。
    let (wait_result, write_result) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(content)
            // stdin はここで drop（EOF）
        });
        let wait_result = wait_bounded(&mut child, CHILD_WRITE_DEADLINE);
        let write_result = writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("writer thread panicked")));
        (wait_result, write_result)
    });
    let status = wait_result?;
    write_result?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "writer child exited with {status} for {}",
            path.display()
        )));
    }
    Ok(())
}

/// 期限付きの `try_wait`。超過したら kill し、有限の猶予で回収して `TimedOut` を返す（REPAIR-5）。
#[cfg(target_os = "linux")]
fn wait_bounded(
    child: &mut std::process::Child,
    deadline: std::time::Duration,
) -> io::Result<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= deadline {
            child.kill()?;
            let reap_start = std::time::Instant::now();
            while child.try_wait()?.is_none() {
                if reap_start.elapsed() >= std::time::Duration::from_secs(5) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "killed child was not reaped in time",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child did not exit before the deadline",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// 自プロセスが開いている fd のうち、指定 inode を指すものの数（アクセスモード別）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FdCounts {
    /// `O_WRONLY` または `O_RDWR` で開いている fd 数。
    pub(crate) writable: usize,
    /// `O_RDONLY` で開いている fd 数。
    pub(crate) read_only: usize,
}

/// `/proc/self/fd` を走査し、`(dev, ino)` を指す fd を書き込み用／読み取り専用に分けて数える（#1686）。
///
/// `write_file_in_child` の後に書き込み用 fd が残っていないことを具体値で照合するための独立した検査器。
/// 走査中に他スレッドが閉じた fd（`NotFound`）だけを読み飛ばし、それ以外の失敗・解釈不能はエラーにする。
#[cfg(target_os = "linux")]
pub(crate) fn open_fds_on(dev: u64, ino: u64) -> io::Result<FdCounts> {
    use std::os::unix::fs::MetadataExt as _;

    let mut counts = FdCounts {
        writable: 0,
        read_only: 0,
    };
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        let fd_path = Path::new("/proc/self/fd").join(&name);
        let meta = match std::fs::metadata(&fd_path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if meta.dev() != dev || meta.ino() != ino {
            continue;
        }
        let info = match std::fs::read_to_string(Path::new("/proc/self/fdinfo").join(&name)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
            .ok_or_else(|| io::Error::other("cannot parse flags in fdinfo"))?;
        if flags & 0o3 == 0 {
            counts.read_only += 1;
        } else {
            counts.writable += 1;
        }
    }
    Ok(counts)
}

/// `6.14.0-1-generic` 形式の先頭 2 要素を数値で返す（純関数）。
fn parse_release(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim().split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// 時刻と OS 乱数で初期化される `RandomState` から 64bit 値を作る（暗号強度は不要）。
fn random_u64(seq: u64) -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u64(seq);
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    h.finish()
}

/// `candidates` の名前を順に `parent` 直下へ非再帰で作る。`AlreadyExists` なら次の候補へ進み、
/// `max_attempts` 回で諦める。既存のディレクトリ・symlink（宛先なしを含む）は消さず辿らない。
/// 自己テストが衝突を決定的に起こせるよう、候補列を注入できる形にしてある。
fn create_unique_in(
    parent: &Path,
    candidates: impl Iterator<Item = String>,
    max_attempts: usize,
) -> io::Result<TestTempDir> {
    let mut last = None;
    for name in candidates.take(max_attempts) {
        let path = parent.join(name);
        let mut b = std::fs::DirBuilder::new();
        b.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        match b.create(&path) {
            Ok(()) => return Ok(TestTempDir { path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("failed to create temp dir {}: {e}", path.display()),
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "no free temp dir name after {max_attempts} attempts (last: {:?})",
            last.map(|e| e.to_string())
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-7・REPAIR-12・SEC-1・SUP-6・TASK-163 追補・#1686: 子で書いたフィクスチャは、作成後に自プロセスへ
    /// 書き込み用 fd を残さず（0 件）、内容が一致し、`AT_EXECVE_CHECK` の判定がカーネル版どおりになる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair12_issue1686_child_written_fixture_leaves_no_writable_fd() {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let tmp = TestTempDir::new("child-write").expect("temp dir");
        let path = tmp.path().join("script");
        let big = vec![0xA5u8; 64 * 1024 * 2 + 123];
        for content in [&b"#!/bin/sh\nexit 0\n"[..], &big[..]] {
            write_file_in_child(&path, content).expect("write in child");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let mut file = std::fs::File::open(&path).expect("open");
            let meta = file.metadata().expect("metadata");
            let mut got = Vec::new();
            file.read_to_end(&mut got).expect("read");
            assert_eq!(got, content);
            assert_eq!(
                open_fds_on(meta.dev(), meta.ino()).expect("count fds"),
                FdCounts {
                    writable: 0,
                    read_only: 1
                }
            );
            // 対照: 検査器が書き込み用 fd を実際に数えられること。
            let writer = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for write");
            assert_eq!(
                open_fds_on(meta.dev(), meta.ino()).expect("count fds"),
                FdCounts {
                    writable: 1,
                    read_only: 1
                }
            );
            drop(writer);
        }
    }

    fn names(v: &[&str]) -> impl Iterator<Item = String> {
        v.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// SEC-1・#1531: カーネル版の解釈（先頭 2 要素）の具体値。解釈できない版は `None`。
    #[test]
    fn sec1_task163_parse_release_reads_major_and_minor() {
        assert_eq!(parse_release("6.14.0-1-generic\n"), Some((6, 14)));
        assert_eq!(parse_release("7.0.0-34-generic"), Some((7, 0)));
        assert_eq!(parse_release("6.8-rc1"), Some((6, 8)));
        assert_eq!(parse_release("garbage"), None);
        assert_eq!(parse_release(""), None);
    }

    /// 先置きの名前を指す候補を先頭に流し、事前ディレクトリを消さず別名で作ることを照合する。
    #[test]
    fn core1_issue1298_preexisting_dir_is_kept_and_fresh_dir_is_used() {
        let outer = TestTempDir::new("excl-outer").expect("outer");
        let pre = outer.path().join("pre");
        std::fs::create_dir(&pre).expect("pre");
        std::fs::write(pre.join("marker"), b"keep").expect("marker");
        let fresh = create_unique_in(outer.path(), names(&["pre", "fresh"]), 4).expect("fresh");
        assert_eq!(fresh.path(), outer.path().join("fresh"));
        assert_eq!(std::fs::read_dir(fresh.path()).expect("rd").count(), 0);
        drop(fresh);
        assert_eq!(std::fs::read(pre.join("marker")).expect("marker"), b"keep");
        assert!(!outer.path().join("fresh").exists());
    }

    /// 先置き symlink（実在先・dangling）を辿らず、そのまま残すこと。
    #[cfg(unix)]
    #[test]
    fn core1_issue1298_preexisting_symlinks_are_not_followed() {
        let outer = TestTempDir::new("excl-link").expect("outer");
        let victim = outer.path().join("victim");
        std::fs::create_dir(&victim).expect("victim");
        std::fs::write(victim.join("marker"), b"keep").expect("marker");
        let missing = outer.path().join("missing");
        std::os::unix::fs::symlink(&victim, outer.path().join("l1")).expect("l1");
        std::os::unix::fs::symlink(&missing, outer.path().join("l2")).expect("l2");
        let fresh =
            create_unique_in(outer.path(), names(&["l1", "l2", "fresh"]), 4).expect("fresh");
        assert_eq!(fresh.path(), outer.path().join("fresh"));
        for l in ["l1", "l2"] {
            let m = std::fs::symlink_metadata(outer.path().join(l)).expect("meta");
            assert!(m.file_type().is_symlink(), "{l}");
        }
        assert_eq!(
            std::fs::read(victim.join("marker")).expect("marker"),
            b"keep"
        );
        assert_eq!(std::fs::read_dir(&victim).expect("rd").count(), 1);
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn core1_issue1298_mode_is_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = TestTempDir::new("excl-mode").expect("t");
        let mode = std::fs::metadata(t.path())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn core1_issue1298_retry_is_bounded() {
        let outer = TestTempDir::new("excl-bound").expect("outer");
        std::fs::create_dir(outer.path().join("a")).expect("a");
        let err = create_unique_in(outer.path(), std::iter::repeat("a".to_string()), 3)
            .expect_err("must give up");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(outer.path().join("a").is_dir());
    }

    #[test]
    fn core1_issue1298_same_label_yields_distinct_paths() {
        let a = TestTempDir::new("excl-uniq").expect("a");
        let b = TestTempDir::new("excl-uniq").expect("b");
        assert_ne!(a.path(), b.path());
        assert!(a.path().is_dir() && b.path().is_dir());
    }
}
