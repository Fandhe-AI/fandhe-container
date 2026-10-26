//! 実機前提試験の一時領域の親ディレクトリ保護（#2840・#2887・CORE-5・REPAIR-12）。
//!
//! `std::env::temp_dir()` 直下に bundle を作り製品の `oci_runtime::{create,start,delete}` を通す試験が、
//! `systemd-tmpfiles-clean` の aging 走査（Ubuntu の `/tmp` は `D /tmp 1777 root root 30d`。走査中は
//! サブディレクトリごとに `flock(LOCK_EX|LOCK_NB)`）と、製品の待たない `BundleLock`（`try_lock`）の競合で
//! 間欠的に `container start is in progress in another process` で失敗するのを防ぐ。
//! tmpfiles は LOCK_EX を取れないディレクトリを丸ごと飛ばす（tmpfiles.d(5)）ので、排他作成した 0700 の
//! 親ディレクトリに共有 flock を試験終了まで持ち続け、bundle・作業ディレクトリを親の下へ置く。
//!
//! 不変条件: 本補助がロックするのは **親ディレクトリだけ**。製品がロックする bundle・rootfs・staging には
//! 触れない（子の inode のロックと親のロックは干渉しない）。fd は `File::open` の O_CLOEXEC で子へ継承されない。
//!
//! 取り込み方: core の試験は `#[path = "support/scratch_root.rs"]`、supervisor・cli の試験は
//! `#[path = "../../core/tests/support/scratch_root.rs"]` で同じファイルを取り込む（複製しない。保護条件の
//! 修正を 1 箇所に保つため。試験専用で製品コード・rlib には影響しない）。`remove_scratch_root` は作成した
//! プロセスでだけ削除する。成功行の照合を乱さないよう標準出力へは何も出さず、失敗は panic（英語）で表す。

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 親ディレクトリ・共有 flock を保持する fd・作成した pid。
static ROOT: OnceLock<(PathBuf, std::fs::File, u32)> = OnceLock::new();

/// 保護済みの親ディレクトリを返す。初回に `<prefix>-<pid>-<nanos>` を排他作成（既存パスは採用も削除もしない）して
/// 0700 にし、共有 flock を `deadline` まで再試行して取る。取れなければ panic（REPAIR-5）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なり、未使用の取り込み先があるため。
pub fn scratch_root(prefix: &str, deadline: Duration) -> &'static Path {
    let (dir, _guard, _pid) = ROOT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).expect("exclusively create scratch root");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod scratch root");
        let file = std::fs::File::open(&dir).expect("open scratch root");
        let start = Instant::now();
        while file.try_lock_shared().is_err() {
            assert!(
                start.elapsed() < deadline,
                "could not take a shared flock on the scratch root within the deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        (dir, file, std::process::id())
    });
    dir
}

/// 親ディレクトリを消す（best-effort。作成したプロセスでだけ削除し、fork・re-exec した子は何もしない）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なり、未使用の取り込み先があるため。
pub fn remove_scratch_root() {
    if let Some((dir, _, pid)) = ROOT.get()
        && *pid == std::process::id()
    {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// drop で `remove_scratch_root` を呼ぶガード（panic の unwind 経路用）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なり、未使用の取り込み先があるため。
pub struct ScratchRootCleanup;

impl Drop for ScratchRootCleanup {
    fn drop(&mut self) {
        remove_scratch_root();
    }
}
