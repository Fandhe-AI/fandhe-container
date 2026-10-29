//! platform-macos の実機・結合試験が共有する、std だけの補助関数（MAC-1・MAC-2・REPAIR-1・#3351）。
//!
//! スクラッチディレクトリ（`Scratch`）・環境変数のパス読み・失敗診断用の末尾切り出し・秒数の環境変数の解決を、
//! `vm_boot.rs`・`vm_cold_start.rs`・`virtiofs_io.rs`・`virtiofs_link.rs`・`virtiofs_harness.rs`（試験 target）の
//! 5 本が複製していたため 1 本にまとめる。片方だけ直して食い違うことを防ぐ（REPAIR-1）。
//!
//! `vm_cold_start.rs` は Windows を含む 3 OS でコンパイルされるため、本ファイルは std だけで書き、
//! ファイル自体に cfg を付けない（OS 固有の chmod は関数内の `cfg(unix)` で閉じる）。
//!
//! 取り込み規約: 取り込み側は `#[path = "support/common.rs"] mod common;` とトップレベルで宣言する
//! （`vm_guest.rs`・`virtiofs_harness.rs` が `super::common` を参照するため。守られなければコンパイルエラー）。
//! 各 `tests/*.rs` は別 crate なので、未使用の項目は取り込み側の `mod common;` に理由付きの
//! `allow(dead_code)` を付けて許容する（項目単位では付けない。他の取り込み側の検出を消さないため）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// スクラッチ名・fixture の nonce が衝突しないための通し番号。
pub static COUNTER: AtomicU64 = AtomicU64::new(0);

/// テストごとの新規ディレクトリ（unix では 0700）。`keep` が false なら `Drop` で削除する。
pub struct Scratch {
    pub dir: PathBuf,
    keep: bool,
}

impl Scratch {
    /// `CARGO_TARGET_TMPDIR` 配下に新規作成する。`create_dir` は既存に失敗するため、他のディレクトリを
    /// 再利用・削除しない。親に symlink を含めないよう canonicalize した基点を使う。
    pub fn new(tag: &str, keep: bool) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base).expect("create tmp base");
        let base = base.canonicalize().expect("canonicalize tmp base");
        for _ in 0..100 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
            if std::fs::create_dir(&dir).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod scratch dir");
                }
                return Self { dir, keep };
            }
        }
        panic!("could not create a fresh scratch directory");
    }

    /// 0600 のファイルを作る（unix のみ）。
    #[cfg(unix)]
    pub fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.dir.join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// 環境変数をパスとして読む。未設定なら `None`。
pub fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// 末尾 `max` バイトを（不正な UTF-8 は置換して）文字列にする。失敗時の診断出力用。
pub fn tail_lossy(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(bytes.get(start..).unwrap_or_default()).into_owned()
}

/// 秒数の環境変数を決める。未指定は既定値、範囲外・非数は拒否する（VM 起動前に拒否するため）。
pub fn resolve_secs(raw: Option<String>, default: u64, range: (u64, u64)) -> Result<u64, String> {
    match raw {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (range.0..=range.1).contains(n))
            .ok_or_else(|| {
                format!(
                    "seconds must be an integer in {}..={}, got {v:?}",
                    range.0, range.1
                )
            }),
    }
}
