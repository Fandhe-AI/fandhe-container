//! `supervised` の直接経路の bin 検査の試験（CRI-6・SEC-1・PLUG-11・#4499）。実 systemd-run・supervisor は使わず、
//! 解決（`resolve`）と起動（`run`）を注入して、検査が spawn の前に効くことを具体値で照合する。

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::pod_holder::bin_fixture::{BinFixture, assert_untrusted};
use crate::pod_holder::{MSG_UNTRUSTED_EXE, current_euid};

fn direct(sup: &Path) -> Result<SupervisorLaunch, OciRuntimeError> {
    Ok(SupervisorLaunch::new(
        "/nonexistent/systemd-run".into(),
        sup.to_path_buf(),
        "/run/user/1".into(),
    ))
}

fn via_launcher(sup: &Path) -> Result<SupervisorLaunch, OciRuntimeError> {
    Ok(SupervisorLaunch::new_via_launcher(
        "/nonexistent/systemd-run".into(),
        "/nonexistent/launcher".into(),
        sup.to_path_buf(),
        "/run/user/1".into(),
    ))
}

fn fake_start_error() -> OciRuntimeError {
    OciRuntimeError::new(LifecycleOp::Start, ErrorCode::Internal, "fake run")
}

/// `start_checked` を回し、`(結果の code・message、run が呼ばれたか)` を返す。
fn drive(
    exe: &Path,
    euid: Result<u32, ()>,
    resolve: impl FnOnce(&Path) -> Result<SupervisorLaunch, OciRuntimeError>,
) -> (Result<NonZeroU32, OciRuntimeError>, bool) {
    let ran = AtomicBool::new(false);
    let (r, child) = start_checked(
        exe,
        || euid,
        resolve,
        |_| {
            ran.store(true, Ordering::SeqCst);
            (Err(fake_start_error()), None)
        },
    );
    assert!(child.is_none());
    (r, ran.load(Ordering::SeqCst))
}

fn expect_untrusted(r: Result<NonZeroU32, OciRuntimeError>, ran: bool) {
    let e = r.expect_err("rejected");
    assert_untrusted(e.code(), e.message());
    assert!(!ran, "must be rejected before spawning");
}

#[test]
fn cri6_plug11_4499_direct_start_rejects_foreign_owner() {
    let euid = current_euid().expect("euid");
    if euid == 0 {
        return;
    }
    let fx = BinFixture::new("sup-owner");
    fx.place_elf(0o755);
    let (r, ran) = drive(&fx.exe, Ok(euid + 1), |_| direct(&fx.sup));
    expect_untrusted(r, ran);
}

#[test]
fn cri6_plug11_4499_direct_start_rejects_group_writable_bin() {
    let euid = current_euid().expect("euid");
    let fx = BinFixture::new("sup-gw");
    fx.place_elf(0o775);
    let (r, ran) = drive(&fx.exe, Ok(euid), |_| direct(&fx.sup));
    expect_untrusted(r, ran);
}

#[test]
fn cri6_plug11_4499_direct_start_rejects_writable_ancestor() {
    let euid = current_euid().expect("euid");
    let fx = BinFixture::new("sup-anc");
    fx.place_elf(0o755);
    fx.set_dir_mode(0o775);
    let (r, ran) = drive(&fx.exe, Ok(euid), |_| direct(&fx.sup));
    expect_untrusted(r, ran);
}

#[test]
fn cri6_plug11_4499_direct_start_rejects_fifo_without_blocking() {
    let euid = current_euid().expect("euid");
    let fx = BinFixture::new("sup-fifo");
    fx.place_fifo();
    let (exe, sup) = (fx.exe.clone(), fx.sup.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(drive(&exe, Ok(euid), |_| direct(&sup)));
    });
    let (r, ran) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("did not block");
    expect_untrusted(r, ran);
}

/// 直接経路で条件を満たす bin は検査を通り、run に進む（祖先が通らない環境では要求しない）。
#[test]
fn cri6_plug11_4499_direct_start_runs_with_trusted_bin() {
    let euid = current_euid().expect("euid");
    let fx = BinFixture::new("sup-ok");
    fx.place_elf(0o755);
    let (r, ran) = drive(&fx.exe, Ok(euid), |_| direct(&fx.sup));
    let e = r.expect_err("fake run fails");
    if fx.ancestors_ok(euid) {
        assert!(ran);
        assert_eq!(e.message(), "fake run");
    } else {
        assert!(!ran);
        assert_eq!(e.message(), MSG_UNTRUSTED_EXE);
    }
}

/// ランチャー経由は従来どおり検査を足さない（0775 の bin でも run に進む。ランチャーが検証する）。
#[test]
fn cri6_plug11_4499_launcher_path_is_unchanged() {
    let fx = BinFixture::new("sup-launcher");
    fx.place_elf(0o775);
    let (r, ran) = drive(&fx.exe, Err(()), |_| via_launcher(&fx.sup));
    assert!(ran);
    assert_eq!(r.expect_err("fake").message(), "fake run");
}

/// resolve の失敗はそのまま返り、euid も run も評価しない（既存の優先順位を保つ）。
#[test]
fn cri6_plug11_4499_resolve_error_wins_over_bin_check() {
    let fx = BinFixture::new("sup-resolve");
    fx.place_elf(0o775);
    let (r, ran) = drive(&fx.exe, Err(()), |_| {
        Err(OciRuntimeError::new(
            LifecycleOp::Start,
            ErrorCode::Unimplemented,
            "rootful",
        ))
    });
    let e = r.expect_err("resolve error");
    assert_eq!(
        (e.code(), e.message()),
        (ErrorCode::Unimplemented, "rootful")
    );
    assert!(!ran);
}

#[test]
fn cri6_plug11_4499_unreadable_credentials_fail_closed() {
    let fx = BinFixture::new("sup-cred");
    fx.place_elf(0o755);
    let (r, ran) = drive(&fx.exe, Err(()), |_| direct(&fx.sup));
    let e = r.expect_err("rejected");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "cannot determine the plugin process credentials"
    );
    assert!(!ran);
}
