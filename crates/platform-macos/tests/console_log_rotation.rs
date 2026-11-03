//! コンソールログの回転と削除の結合試験（MAC-1・REPAIR-4・REPAIR-12・#2138）。
//!
//! 公開 API（`VmConfigSpec::open_serial_console` / `remove_console_logs`）だけを使い、実 VM は要らない。
//! 書き出しスレッドへ書き込む手段は公開されないため、各起動の「前回のログ」は fixture として直接置き、
//! 起動（`open_serial_console`）による世代の送りと、使用中の拒否、全世代の削除を確認する。
//! 回転は unix 限定（`console_log` が unix 限定）のため、全体を unix に限る。

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fandhe_container_platform_macos::config::{
    ConsoleLogPath, DeviceConfigSpec, SerialConsoleSink, VmConfigSpec,
};

/// プロセスごとに作る使い捨てディレクトリ（0700。親ディレクトリ検査を通す）。
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fandhe-console-rot-{tag}-{}", std::process::id()));
        // 前回の残骸があれば消してから作る（REPAIR-12・#3375）。
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let dir = std::fs::canonicalize(&dir).expect("canonicalize");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// ログ先を持つ構成と現在のログのパスを返す。
fn spec_in(dir: &Dir) -> (VmConfigSpec, PathBuf) {
    let kernel = dir.0.join("vmlinux");
    let initrd = dir.0.join("initrd.img");
    std::fs::write(&kernel, b"dummy").expect("kernel");
    std::fs::write(&initrd, b"dummy").expect("initrd");
    let log = dir.0.join("console.log");
    let devices = DeviceConfigSpec::try_new(
        vec![],
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(&log).expect("log path"),
        )),
    )
    .expect("devices");
    let spec = VmConfigSpec::from_parts(&kernel, Some(&initrd), "console=hvc0")
        .expect("spec")
        .with_devices(devices)
        .expect("with devices");
    (spec, log)
}

fn put(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn generation(log: &Path, n: u32) -> PathBuf {
    ConsoleLogPath::try_new(log)
        .expect("log path")
        .generation_path(n)
}

/// 起動 1 回分: 開いて（回転）すぐ閉じる。書き出しスレッドの終了まで待つ。
fn boot(spec: &VmConfigSpec) {
    let sink = spec
        .open_serial_console()
        .expect("open")
        .expect("console sink");
    sink.finish(Duration::from_secs(10))
        .expect("writer thread finished");
}

/// MAC-1・REPAIR-4・#2138: 起動のたびに現在のログが `.1` → `.2` へ送られ、3 世代より古い内容は消える。
#[test]
fn generations_hold_previous_boots_in_order() {
    let dir = Dir::new("gens");
    let (spec, log) = spec_in(&dir);
    put(&log, b"boot1\n");
    boot(&spec);
    assert_eq!(std::fs::read(generation(&log, 1)).unwrap(), b"boot1\n");
    assert_eq!(std::fs::read(&log).unwrap(), b"");

    // 空のログは世代を消費しない。
    boot(&spec);
    assert_eq!(std::fs::read(generation(&log, 1)).unwrap(), b"boot1\n");
    assert!(!generation(&log, 2).exists());

    put(&log, b"boot2\n");
    boot(&spec);
    put(&log, b"boot3\n");
    boot(&spec);
    assert_eq!(std::fs::read(generation(&log, 1)).unwrap(), b"boot3\n");
    assert_eq!(std::fs::read(generation(&log, 2)).unwrap(), b"boot2\n");
    assert!(!dir.0.join("console.log.3").exists());
}

/// MAC-1・REPAIR-4・#2138: 使用中の間は 2 本目の起動も削除も何も動かさず `config.console_log_in_use` で拒否し、
/// 解放後は削除が現在のログ・全世代・排他用ファイルを消す。
#[test]
fn in_use_log_is_refused_then_removed_after_release() {
    let dir = Dir::new("inuse");
    let (spec, log) = spec_in(&dir);
    put(&log, b"old\n");
    let live = spec
        .open_serial_console()
        .expect("first open")
        .expect("console sink");
    assert_eq!(std::fs::read(generation(&log, 1)).unwrap(), b"old\n");

    assert_eq!(
        spec.open_serial_console().unwrap_err().code(),
        "config.console_log_in_use"
    );
    assert_eq!(
        spec.remove_console_logs().unwrap_err().code(),
        "config.console_log_in_use"
    );
    assert!(log.exists());
    assert_eq!(std::fs::read(generation(&log, 1)).unwrap(), b"old\n");

    live.finish(Duration::from_secs(10))
        .expect("writer thread finished");
    put(&generation(&log, 2), b"older\n");
    assert_eq!(spec.remove_console_logs().unwrap().removed, 3);
    assert!(!log.exists());
    assert!(!generation(&log, 1).exists());
    assert!(!generation(&log, 2).exists());
    assert!(!generation(&log, 0).exists());
    assert!(dir.0.exists());
    assert_eq!(spec.remove_console_logs().unwrap().removed, 0);
}

/// MAC-1・REPAIR-4・#2138: 世代の名前に不正なエントリ（symlink）があれば何も消さず何も動かさずに拒否する。
#[test]
fn bad_generation_entry_blocks_rotation_and_removal() {
    let dir = Dir::new("bad");
    let (spec, log) = spec_in(&dir);
    put(&log, b"old\n");
    let victim = dir.0.join("victim");
    put(&victim, b"keep\n");
    std::os::unix::fs::symlink(&victim, generation(&log, 2)).unwrap();
    assert_eq!(
        spec.open_serial_console().unwrap_err().code(),
        "config.console_log_is_symlink"
    );
    assert_eq!(
        spec.remove_console_logs().unwrap_err().code(),
        "config.console_log_is_symlink"
    );
    assert_eq!(std::fs::read(&log).unwrap(), b"old\n");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep\n");
}
