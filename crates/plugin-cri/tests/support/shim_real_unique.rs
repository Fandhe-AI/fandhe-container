//! `shim_v2_*_real` の実機前提試験（`shim_v2_containerd_real.rs`・`shim_v2_kill_all_real.rs`・`shim_v2_exec_real.rs`）が、
//! 実行ごとに一意なコンテナ ID・namespace を作るための共有部品と、旧形式（pid だけ）の残骸が試験に影響しないことの確認用の
//! おとり（CRI-5・REPAIR-4・REPAIR-5・REPAIR-12・#4285）。
//!
//! 背景: 3 試験は CRI の記録を持たないので #4142 の gRPC の回収は当てはまらない。固定名の危険は、pid が再利用されたときに
//! `<XDG_RUNTIME_DIR>/fandhe-container-shim-state/<hash>/<namespace>/<id>` が前回の残骸と衝突することだけである（containerd は
//! 試験専用の私設、hash は address 由来で他は実行ごとに一意）。そこで ID・namespace に pid と時刻を入れて衝突を避ける。
//! 生きている supervisor の状態を消すおそれがあるため、状態ディレクトリの先頭での自動削除はしない。
//!
//! 呼び出し元: 3 試験が `#[path]` で取り込む。取り込む試験ごとに使う項目が異なる。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// 実行ごとに一意なタグ（pid と UNIX 時刻 ns の下位 32 bit の 16 進。文字種は `[0-9a-f]`）。同じ実行では同じ値を返す
/// （通常の後始末と watchdog の緊急回収が同じ ID を見るため）。
pub fn run_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}{:08x}", std::process::id(), nanos as u32)
    })
}

/// 旧形式（pid だけ）の残骸のおとり。`<XDG>/fandhe-container-shim-state/fc-test-decoy-<tag>/<ns>/<id>` を排他作成し、
/// Drop で自分が作ったパスだけを深い順に `remove_dir` する（既存のパスは辿らず、消さない）。
pub struct Decoy {
    created: Vec<PathBuf>,
}

impl Decoy {
    /// おとりを置く。`XDG_RUNTIME_DIR` が無い・排他作成に失敗したときは `Err`（既存のパスは消さない）。
    pub fn place(old_namespace: &str, old_id: &str) -> Result<Self, String> {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is not set")?;
        let mut d = Decoy {
            created: Vec::new(),
        };
        let root = xdg.join("fandhe-container-shim-state");
        if !root.is_dir() {
            d.make(&root)?;
        }
        let hash = root.join(format!("fc-test-decoy-{}", run_tag()));
        d.make(&hash)?;
        let ns = hash.join(old_namespace);
        d.make(&ns)?;
        d.make(&ns.join(old_id))?;
        Ok(d)
    }

    fn make(&mut self, p: &Path) -> Result<(), String> {
        // 本番 shim の状態ルート検査（private = 0700）と揃える。umask 022 の 0755 だと shim が拒否する。
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(p)
            .map_err(|e| format!("create decoy dir {}: {e}", p.display()))?;
        self.created.push(p.to_path_buf());
        Ok(())
    }
}

impl Drop for Decoy {
    fn drop(&mut self) {
        for p in self.created.iter().rev() {
            let _ = std::fs::remove_dir(p);
        }
    }
}

// ---- 既定の集合で走る自己照合（REPAIR-12。実機を使わない） ----

#[test]
fn shim_unique_4285_run_tag_is_stable_and_safe() {
    let a = run_tag();
    assert_eq!(a, run_tag());
    assert!(a.bytes().all(|b| b.is_ascii_hexdigit()), "{a}");
    assert!(a.starts_with(&std::process::id().to_string()));
    assert!(a.len() <= 16, "{a}");
}

#[test]
fn shim_unique_4285_decoy_creates_and_removes_only_its_own_paths() {
    let root = std::env::temp_dir().join(format!("fc4285-decoy-{}", run_tag()));
    std::fs::create_dir(&root).expect("create root");
    // XDG_RUNTIME_DIR を変えずに済むよう、同じ手順を手で再現して Drop の挙動を確かめる。
    let mut d = Decoy {
        created: Vec::new(),
    };
    let ns = root.join("ns");
    d.make(&ns).expect("make ns");
    d.make(&ns.join("id")).expect("make id");
    assert!(d.make(&ns).is_err(), "exclusive create must not reuse");
    assert!(ns.join("id").is_dir());
    drop(d);
    assert!(!ns.exists());
    assert!(root.is_dir());
    std::fs::remove_dir(&root).expect("remove root");
}
