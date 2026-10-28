//! virtiofs 実機試験の補助関数の共通化（MAC-1・REPAIR-1・#3099）。
//!
//! `virtiofs_io.rs`（IO-5・TASK-65.4）と `virtiofs_link.rs`（SEC-4・#1877）が、それぞれ複製していた
//! スクラッチディレクトリ・コンソールログの確定待ち・期限の解決をここへ 1 本にまとめる。
//! 片方だけ直して食い違うことを防ぐ（REPAIR-1）。
//!
//! 呼び出し元は `virtiofs_io.rs`・`virtiofs_link.rs` と、本モジュールの単体試験 `virtiofs_harness.rs` の 3 つ。
//! いずれも `#[path = "support/virtiofs_harness.rs"] mod harness;` で取り込む。
//!
//! `console_log::TRUNCATION_MARKER` と `std::os::unix` を使うため、取り込み側は unix 限定
//! （`#![cfg(unix)]` か `#![cfg(target_os = "macos")]`）にすること。ファイル自体には cfg を付けない
//! （`guest_markers.rs` と同じ流儀）。片方の試験だけが使う関数を足すときは、その関数にだけ理由付きの
//! `allow(dead_code)` を付ける。
//!
//! `Vm` を使う起動・待ちループや、untrusted なゲスト出力を扱う検証・観測は各試験に残す（共通化しない）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_platform_macos::console_log::TRUNCATION_MARKER;

/// VM 破棄後、コンソールログの書き出しスレッドが EOF で終わるのを待つ上限（REPAIR-5）。
pub const CONSOLE_LOG_SETTLE_TIMEOUT: Duration = Duration::from_secs(30);

/// スクラッチ名・fixture の nonce が衝突しないための通し番号。
pub static COUNTER: AtomicU64 = AtomicU64::new(0);

/// テストごとの新規ディレクトリ（0700）。`keep` が false なら `Drop` で削除する。
pub struct Scratch {
    pub dir: PathBuf,
    keep: bool,
}

impl Scratch {
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
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod scratch dir");
                return Self { dir, keep };
            }
        }
        panic!("could not create a fresh scratch directory");
    }

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

/// コンソールログが書き出しスレッドの上限（`MAX_CONSOLE_LOG_BYTES`）で打ち切られたか。
/// 区切り文は上限到達時に末尾へ 1 回だけ書かれ、以後ゲスト出力は破棄されるため、
/// 末尾が区切り文ならプローブ行の後続は観測できない。
pub fn log_truncated(bytes: &[u8]) -> bool {
    bytes.ends_with(TRUNCATION_MARKER)
}

/// コンソールログの書き出しスレッド（`console_log`）がログを閉じ終えるまで待つ。
///
/// 書き出しスレッドはログへの排他 advisory lock（unix では `flock(2)`）を EOF でファイルを閉じるまで
/// 保持する（`console_log` モジュールの「排他」）。EOF は VM と設定が解放され serial の書き込み端が
/// すべて閉じたときに来るため、`Vm` を破棄した後に lock を取れれば、ゲスト出力はすべてファイルへ
/// 反映済みで以後増えない。期限内に取れなければ不完全なログで判定しないよう `Err` を返す（fail-closed）。
pub fn wait_console_log_settled(path: &Path, timeout: Duration) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open console log: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            // 取得した lock は `file` の drop で解放される。
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("lock console log: {e}"));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "console log writer did not finish within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 実機試験の期限（秒）を解決する。未指定は 60 秒、指定は 1..=600 のみ受け付ける。
pub fn resolve_probe_timeout(raw: Option<String>) -> Result<Duration, String> {
    match raw {
        None => Ok(Duration::from_secs(60)),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=600).contains(n))
            .map(Duration::from_secs)
            .ok_or_else(|| {
                "FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS must be an integer in 1..=600"
                    .to_string()
            }),
    }
}
