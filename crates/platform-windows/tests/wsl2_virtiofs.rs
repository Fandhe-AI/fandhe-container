//! WSL2 virtiofs 共有の Windows 固有検証と実機結合試験（TASK-67.6・#377。WIN-1・WIN-2・MS-5・REPAIR-12）。
//!
//! Windows でのみビルドする（他 OS は 0 件の test target。`tests/vm_boot.rs`〔platform-macos〕と同じ方式）。
//! feature `wsl2-test-support` は使わず公開 API だけを使うため、`make test-integration` の既定集合に入る。
//!
//! - 既定集合（3 件）: 実 Windows のパス規約（一時ディレクトリ・`canonicalize` の `\\?\` 形式・
//!   `USERPROFILE`）と `HostDir` / `wslconfig::default_path` の契約を具体値で固定する。windows-latest の
//!   runner に WSL があるかどうかで結果が変わらないよう、`detect` などの WSL 呼び出しは含めない。
//! - 実機前提（`#[ignore]` の 1 件）: 実 WSL2 ディストリに対し `detect` と
//!   `prepare_virtiofs_launch` / `release_virtiofs_launch` を通し、`mount -t drvfs` が virtiofs で成立すること・
//!   `nosuid,nodev,ro` が受理されること・9P フォールバック時の fstype を確かめる（`src/wsl2/mount.rs` の
//!   「実機未検証」の前提を確認する入口）。手順は AGENTS.md「実機前提テスト」節。
//!
//! 偽の `wsl.exe` による処理の通し確認は `tests/wsl2_mount.rs`（feature `wsl2-test-support`）の担当。
//! 実機テストは `.wslconfig` に書き込まない（`virtiofs=true` と `wsl --shutdown` は事前に人間が行う）。

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use fandhe_container_platform_windows::instrument::WinWarningCode;
use fandhe_container_platform_windows::wsl2::{
    DistroName, HostDir, LaunchRequest, MAX_WSL_TIMEOUT, MIN_WSL_TIMEOUT, MountName,
    PreparedLaunch, SharedMount, SharedTransport, Wsl2ErrorCode, detect, prepare_virtiofs_launch,
    release_virtiofs_launch,
};
use fandhe_container_platform_windows::wslconfig;

/// 一時ディレクトリを作り、Drop で削除するガード（panic 時も残さない）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fandhe-it-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// WIN-2: 実 Windows の一時ディレクトリ配下のサブディレクトリ（`C:\...\Temp\x` 形式）は共有元として受理される。
#[test]
fn win2_host_dir_accepts_real_windows_temp_subdir() {
    let sub = std::env::temp_dir().join(format!("fandhe-it-accept-{}", std::process::id()));
    let s = sub.to_str().expect("temp path is UTF-8");
    let parsed = HostDir::parse(s).expect("real temp subdir must be accepted");
    assert_eq!(parsed.as_str(), s);
}

/// WIN-2: `canonicalize` が返す `\\?\C:\...` 形式は、ドライブレター形式のみを許す方針どおり拒否される。
#[test]
fn win2_host_dir_rejects_canonicalized_verbatim_path() {
    let dir = TempDir::new("verbatim");
    let canon = std::fs::canonicalize(dir.path()).expect("canonicalize");
    let s = canon.to_str().expect("canonical path is UTF-8");
    assert!(
        s.starts_with(r"\\?\"),
        "canonicalize must return a verbatim path"
    );
    let e = HostDir::parse(s).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument);
    assert_eq!(
        e.message(),
        "host directory must be an absolute path starting with a drive letter, e.g. C:\\dir"
    );
}

/// WIN-2: 既定の `.wslconfig` は `%USERPROFILE%\.wslconfig`。
#[test]
fn win2_wslconfig_default_path_is_userprofile_wslconfig() {
    let profile = std::env::var_os("USERPROFILE").expect("USERPROFILE must be set on Windows");
    let expected = PathBuf::from(profile).join(".wslconfig");
    assert_eq!(wslconfig::default_path().expect("default path"), expected);
}

// ---- 実機前提テスト ----

const ENV_DISTRO: &str = "FANDHE_CONTAINER_WSL_DISTRO";
const ENV_TRANSPORT: &str = "FANDHE_CONTAINER_WSL_EXPECT_TRANSPORT";
const ENV_TIMEOUT: &str = "FANDHE_CONTAINER_TEST_TIMEOUT_SECS";

/// 実機の WSL ディストリに残したマウントを、テストが途中で panic しても best-effort で解除するガード。
struct ReleaseGuard {
    prepared: Option<PreparedLaunch>,
    timeout: Duration,
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        if let Some(p) = self.prepared.take() {
            let _ = release_virtiofs_launch(&p, self.timeout);
        }
    }
}

fn test_timeout() -> Duration {
    let secs = match std::env::var(ENV_TIMEOUT) {
        Ok(v) => v
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{ENV_TIMEOUT} must be an integer")),
        Err(_) => 60,
    };
    let t = Duration::from_secs(secs);
    assert!(
        (MIN_WSL_TIMEOUT..=MAX_WSL_TIMEOUT).contains(&t),
        "{ENV_TIMEOUT} is out of range"
    );
    t
}

/// WIN-1・WIN-2: 実 WSL2 での検出と、virtiofs（または 9P フォールバック）共有マウントの準備・解除。
#[test]
#[ignore = "requires real Windows with WSL2 and a WSL2 distribution (and .wslconfig virtiofs=true applied for the virtiofs expectation); see AGENTS.md"]
fn win1_win2_shared_mount_on_real_wsl2() {
    let timeout = test_timeout();
    let distro_name = std::env::var(ENV_DISTRO)
        .unwrap_or_else(|_| panic!("{ENV_DISTRO} must be set to a WSL2 distribution name"));
    let expect_virtiofs = match std::env::var(ENV_TRANSPORT).as_deref() {
        Err(_) | Ok("virtiofs") => true,
        Ok("9p") => false,
        Ok(_) => panic!("{ENV_TRANSPORT} must be 'virtiofs' or '9p'"),
    };

    // WIN-1: 指定ディストリが WSL2 として使えること。
    let status = detect(timeout).unwrap_or_else(|e| {
        panic!(
            "detect failed: code={} message={}",
            e.code().as_str(),
            e.message()
        )
    });
    let usable = status
        .distros
        .iter()
        .any(|d| d.name == distro_name && d.is_usable_wsl2());
    assert!(
        usable,
        "the specified distribution is not a usable WSL2 distribution"
    );

    // 共有元: 一時ディレクトリ配下の rw / ro 2 件に目印ファイルを置く。
    let tmp = TempDir::new("real-wsl2");
    let mut mounts = Vec::new();
    for (name, ro) in [("fc-it-rw", false), ("fc-it-ro", true)] {
        let dir = tmp.path().join(if ro { "ro" } else { "rw" });
        std::fs::create_dir_all(&dir).expect("create share dir");
        std::fs::write(dir.join("marker.txt"), b"fandhe-it").expect("write marker");
        let host = HostDir::parse(dir.to_str().expect("UTF-8 path")).expect("host dir");
        mounts.push(SharedMount::new(
            host,
            MountName::parse(name).expect("mount name"),
            ro,
        ));
    }
    let req = LaunchRequest::new(
        DistroName::parse(&distro_name).expect("distro name"),
        mounts,
    )
    .expect("launch request");

    let prepared = match prepare_virtiofs_launch(&req, timeout) {
        Ok(p) => p,
        Err(e) => {
            // 未解除のマウントが残っていれば回収する。
            let n = e.unreleased().map_or(0, |u| u.mounts().len());
            if let Some(u) = e.unreleased() {
                let _ = release_virtiofs_launch(u, timeout);
            }
            panic!(
                "prepare failed: code={} message={} unreleased={n}",
                e.code().as_str(),
                e.message()
            );
        }
    };
    let mut guard = ReleaseGuard {
        prepared: Some(prepared.clone()),
        timeout,
    };

    // WIN-2: 輸送方式・警告・ディストリ・マウント内容。
    let expected = if expect_virtiofs {
        SharedTransport::Virtiofs
    } else {
        SharedTransport::NineP
    };
    assert_eq!(prepared.transport(), Some(expected));
    match (expect_virtiofs, prepared.warning()) {
        (true, w) => assert!(w.is_none(), "unexpected warning for virtiofs"),
        (false, Some(w)) => assert!(
            matches!(
                w.code(),
                WinWarningCode::VirtiofsNotApplied | WinWarningCode::VirtiofsNotEnabled
            ),
            "unexpected warning code for 9P fallback"
        ),
        (false, None) => panic!("9P fallback must carry a warning"),
    }
    assert_eq!(prepared.distro().as_str(), distro_name);
    let got: Vec<(String, bool, bool)> = prepared
        .mounts()
        .iter()
        .map(|m| (m.guest_path.clone(), m.mount_id.is_some(), m.read_only))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/mnt/fandhe/fc-it-rw".to_string(), true, false),
            ("/mnt/fandhe/fc-it-ro".to_string(), true, true),
        ]
    );

    // 明示解除。成功したらガードは二重に解除しない。
    release_virtiofs_launch(&prepared, timeout).unwrap_or_else(|e| {
        panic!(
            "release failed: code={} message={} unreleased={}",
            e.code().as_str(),
            e.message(),
            e.unreleased().map_or(0, |u| u.mounts().len())
        )
    });
    guard.prepared = None;
}
