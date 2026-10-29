//! oci の結合試験が使う、残骸に強い一時ディレクトリの補助（OCI-7・REPAIR-12・#3237・#3298）。
//!
//! 名前が pid だけの一時ディレクトリは、Windows の PID 再利用や panic で残った前回の残骸と衝突する。
//! `image_management/inventory_persist.rs`（#3279）の `TestRoot` と同じ形で、
//! 名前にプロセス内連番を入れ、作成前に残骸を消し、Drop で後始末する。
//! core の `ScratchDir` を使わないのは、あれが製品の `BundleLock` と systemd-tmpfiles の
//! 走査の競合（#2840）を避ける補助であり、oci の blob / store の試験は `BundleLock` に関わらないため。
//!
//! 不変条件: 作成前の削除の対象は、この補助が組み立てた `temp_dir()` 配下の試験専用の名前だけ。
//! 削除に失敗したら残骸の上で試験を進めず panic する（fail-closed）。

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// 残骸を消して作った試験用ディレクトリ。Drop で再帰削除する（best-effort）。
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
        // 試験本体が先に消していても NotFound は無視する。
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 指定パスの残骸を消して空のディレクトリ（unix では 0700）として作り直す。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn test_root_at(p: PathBuf) -> TestRoot {
    match std::fs::remove_dir_all(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("stale test dir could not be removed: {}: {e}", p.display()),
    }
    std::fs::create_dir_all(&p).expect("mkdir test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    TestRoot(p)
}

/// `temp_dir()/<prefix>-<pid>-<連番>-<tag>` に試験用ディレクトリを作る。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn test_root(prefix: &str, tag: &str) -> TestRoot {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    test_root_at(std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{tag}", std::process::id())))
}
