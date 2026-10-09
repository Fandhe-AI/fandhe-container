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
