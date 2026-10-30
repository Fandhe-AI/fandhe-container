//! oci の結合試験と、`#[path]` で取り込む他 crate の試験（#3375）が使う、残骸に強い一時ディレクトリの補助
//! （OCI-7・REPAIR-12・#3237・#3298・#3475）。
//!
//! 名前が pid だけの一時ディレクトリは、Windows の PID 再利用や panic で残った前回の残骸と衝突する。
//! 共有の `temp_dir()` 直下の予測できる名前を先に消して作り直す方式は、消してから作るまでの間に別ユーザーが
//! 同じ名前へ symlink を置くと、作成も chmod も以降の書き込みもその先へ向かう。そこで core の
//! `TestTempDir`（`crates/core/src/test_support.rs`）・`ScratchDir`（`crates/core/tests/support/scratch_root.rs`）・
//! net の `exclusive_dir` と方針を揃え、既存の名前は消さず・辿らず・chmod せず、非再帰の排他作成
//! （unix では作成時に mode 0700）で作る。名前が既にあれば連番と乱数を足した別名で再試行する（上限 16 回）。
//! core の `ScratchDir` そのものを使わないのは、あれが製品の `BundleLock` と systemd-tmpfiles の
//! 走査の競合（#2840）を避ける補助であり、oci の blob / store の試験は `BundleLock` に関わらないため。
//!
//! 不変条件: 返る `TestRoot` のパスは、引数の `p` と異なることがある（`p` が既にあるとき）。呼び出し元は
//! 必ず返り値のパスを使うこと。Drop が消すのは自分が排他作成したパスだけ。

use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// 再試行の上限（core の `MAX_ATTEMPTS` と同じ）。
const MAX_ATTEMPTS: usize = 16;

/// 排他作成した試験用ディレクトリ。Drop で再帰削除する（best-effort）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub struct TestRoot(PathBuf);

impl Deref for TestRoot {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TestRoot {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        // 自分が排他作成したパスだけを消す。試験本体が先に消していても NotFound は無視する。
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 暗号強度の要らない乱数（`RandomState` と時刻。core の `random_u64` と同じ作り）。
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}

/// 非再帰の排他作成（unix では作成時に mode 0700）。既存のパスには触れず `AlreadyExists` を返す。
fn mkdir_exclusive(p: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)
}

/// `parent` 直下で `candidates` を順に排他作成し、最初に成功したものを返す（上限 `max_attempts`）。
/// 既存の名前（ディレクトリ・symlink・宛先の無い symlink を含む）は消さず・辿らない。
/// `AlreadyExists` 以外のエラーはそのまま返す。上限超過は `AlreadyExists` を返す。
#[allow(dead_code)] // 上限の試験が使う。他の取り込み先は `test_root_at` だけを使うため
pub fn create_unique_at(
    parent: &Path,
    candidates: impl Iterator<Item = OsString>,
    max_attempts: usize,
) -> std::io::Result<TestRoot> {
    for name in candidates.take(max_attempts) {
        let p = parent.join(name);
        match mkdir_exclusive(&p) {
            Ok(()) => return Ok(TestRoot(p)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "no free name under {} after {max_attempts} attempts",
            parent.display()
        ),
    ))
}

/// `p` を第 1 候補に、先に消さず排他作成で空のディレクトリ（unix では 0700）を作る。
/// `p` が既にあれば同じ親の下に別名を作るため、返るパスは `p` と異なることがある（呼び出し元は返り値を使う）。
/// 親が無い・上限超過・`AlreadyExists` 以外のエラーは panic する（fail-closed）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn test_root_at(p: PathBuf) -> TestRoot {
    let parent = p.parent().expect("test root has a parent").to_path_buf();
    let base = p.file_name().expect("test root has a name").to_os_string();
    let first = std::iter::once(base.clone());
    let retries = std::iter::repeat_with(move || {
        let mut n = base.clone();
        n.push(format!(
            "-{}-{:016x}",
            SEQ.fetch_add(1, Ordering::Relaxed),
            random_u64()
        ));
        n
    });
    create_unique_at(&parent, first.chain(retries), MAX_ATTEMPTS)
        .unwrap_or_else(|e| panic!("mkdir test root {}: {e}", p.display()))
}

/// `temp_dir()/<prefix>-<pid>-<連番>-<tag>` を第 1 候補に試験用ディレクトリを排他作成する。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn test_root(prefix: &str, tag: &str) -> TestRoot {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    test_root_at(std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{tag}", std::process::id())))
}
