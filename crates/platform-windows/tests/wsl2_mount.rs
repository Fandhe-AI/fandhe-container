//! virtiofs 共有マウントの結合試験（TASK-67.4・#375。WIN-1・WIN-2・ERR-1・REPAIR-5・REPAIR-12）。
//!
//! 偽の `wsl.exe`（`tests/bin/fake_wsl.rs` のマウント系モード）を実際に子プロセスとして起動し、
//! `wsl2::test_support` 経由で公開 API と同じ処理（検出 → mount → mountinfo によるマウント ID・fstype の確認 →
//! 起動ステップ → 解除）を 3 OS で確かめる。実行器との接続（argv の受け渡し・呼び出しごとのタイムアウト・
//! 出力の解析）を通すことが目的で、ゲスト内スクリプトの振る舞いは模擬ゲストのユニットテスト
//! （`src/wsl2/mount.rs`）と実機確認（TASK-67.6・#377）の担当。
//! feature `wsl2-test-support` が必要（`cargo test -p fandhe-container-platform-windows --all-features`）。
//! feature なしでは本ファイル全体を外し、0 件の test target になる（Cargo.toml のコメント参照）。

#![cfg(feature = "wsl2-test-support")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use fandhe_container_platform_windows::wsl2::test_support::{
    launch_with_program, prepare_virtiofs_launch_with_program, release_virtiofs_launch_with_program,
};
use fandhe_container_platform_windows::wsl2::{
    DistroName, HostDir, LaunchRequest, MountName, PreparedMount, SharedMount, SharedTransport,
    Wsl2Error, Wsl2ErrorCode,
};
use fandhe_container_platform_windows::wslconfig::VirtiofsState;

const TIMEOUT: Duration = Duration::from_secs(10);

/// 偽 `wsl.exe` のマウント系モード（テストごとに別の状態ファイルを使うため 1 テスト 1 モード）。
const MODES: [&str; 4] = ["mount_ok", "mount_9p", "mount_launch", "mount_unset"];

/// モードごとの名前で偽 `wsl.exe` を置いたディレクトリ（`tests/wsl2_detect.rs` と同じ用意の仕方。
/// 状態ファイルが衝突しないよう別ディレクトリにする）。
fn fake_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let src = Path::new(env!("CARGO_BIN_EXE_fake_wsl"));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake_wsl_mount");
        std::fs::create_dir_all(&dir).unwrap();
        for mode in MODES {
            let dst = dir.join(format!("fake_wsl-{mode}{}", std::env::consts::EXE_SUFFIX));
            let _ = std::fs::remove_file(&dst);
            if std::fs::hard_link(src, &dst).is_err() {
                std::fs::copy(src, &dst).unwrap();
            }
        }
        dir
    })
}

/// モードの偽 `wsl.exe` を返し、状態ファイルを削除してマウント表を初期状態（`/` のみ）に戻す。
fn fresh_fake(mode: &str) -> PathBuf {
    assert!(MODES.contains(&mode), "unknown mode {mode}");
    let exe = fake_dir().join(format!("fake_wsl-{mode}{}", std::env::consts::EXE_SUFFIX));
    let _ = std::fs::remove_file(exe.with_extension("state"));
    exe
}

/// 状態ファイルに残っているマウント先の一覧（`/` を除く）。
fn mounted(exe: &Path) -> Vec<String> {
    std::fs::read_to_string(exe.with_extension("state"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .filter(|p| *p != "/")
        .map(str::to_string)
        .collect()
}

fn request() -> LaunchRequest {
    let m = |h: &str, n: &str, ro: bool| {
        SharedMount::new(HostDir::parse(h).unwrap(), MountName::parse(n).unwrap(), ro)
    };
    LaunchRequest::new(
        DistroName::parse("Ubuntu").unwrap(),
        vec![m("C:\\work", "work", false), m("D:\\data", "data", true)],
    )
    .unwrap()
}

/// WIN-2・REPAIR-12: 準備はマウント ID・読み取り専用の別を具体値で返し、解除で全マウントが外れる。
#[test]
fn prepare_then_release_through_fake_wsl() {
    let exe = fresh_fake("mount_ok");
    let p = prepare_virtiofs_launch_with_program(&exe, VirtiofsState::Enabled, &request(), TIMEOUT)
        .unwrap();
    assert_eq!(p.transport(), SharedTransport::Virtiofs);
    assert_eq!(p.distro().as_str(), "Ubuntu");
    let got: Vec<(&str, u32, bool)> = p
        .mounts()
        .iter()
        .map(|m: &PreparedMount| (m.guest_path.as_str(), m.mount_id, m.read_only))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/mnt/fandhe/work", 100, false),
            ("/mnt/fandhe/data", 101, true)
        ]
    );
    assert_eq!(mounted(&exe), ["/mnt/fandhe/work", "/mnt/fandhe/data"]);
    release_virtiofs_launch_with_program(&exe, &p, TIMEOUT).unwrap();
    assert!(mounted(&exe).is_empty());
}

/// WIN-2: 9P で成立したら FAILED_PRECONDITION で拒否し、作ったマウントを外してから返す。
#[test]
fn prepare_rejects_9p_and_rolls_back_through_fake_wsl() {
    let exe = fresh_fake("mount_9p");
    let e = prepare_virtiofs_launch_with_program(&exe, VirtiofsState::Enabled, &request(), TIMEOUT)
        .unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
    assert!(
        e.message().contains("not backed by virtiofs"),
        "{}",
        e.message()
    );
    assert!(mounted(&exe).is_empty());
}

/// WIN-2: `.wslconfig` で virtiofs が有効でなければ、ゲスト内のコマンドを一切実行しない。
#[test]
fn prepare_refuses_without_virtiofs_opt_in() {
    let exe = fresh_fake("mount_unset");
    let e = prepare_virtiofs_launch_with_program(&exe, VirtiofsState::Unset, &request(), TIMEOUT)
        .unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
    assert!(!exe.with_extension("state").exists());
}

/// AC2・REPAIR-5: 起動ステップが失敗したら準備済みマウントを外し、起動ステップのエラーを返す。
/// 成功時は起動ステップの戻り値を返し、マウントは呼び出し側の所有として残る。
#[test]
fn launch_rolls_back_when_start_fails_through_fake_wsl() {
    let exe = fresh_fake("mount_launch");
    let e = launch_with_program(&exe, VirtiofsState::Enabled, &request(), TIMEOUT, |p| {
        assert_eq!(p.mounts().len(), 2);
        Err::<(), _>(Wsl2Error::new(Wsl2ErrorCode::Internal, "start failed"))
    })
    .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Wsl2ErrorCode::Internal, "start failed")
    );
    assert!(mounted(&exe).is_empty());

    let n = launch_with_program(&exe, VirtiofsState::Enabled, &request(), TIMEOUT, |p| {
        Ok(p.mounts().len())
    })
    .unwrap();
    assert_eq!(n, 2);
    assert_eq!(mounted(&exe), ["/mnt/fandhe/work", "/mnt/fandhe/data"]);
}
