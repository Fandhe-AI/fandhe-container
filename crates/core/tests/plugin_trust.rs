//! plugin 所有者・モード検証の結合試験（TASK-122.1・PLUG-11・REPAIR-12）。
//!
//! 公開 API のみを使い、一時ディレクトリのモードは `set_permissions` で明示して umask に
//! 依存させない。所有者不一致の実ファイル試験は chown（root）が要るため作らず、判定論理は
//! `check_owner_and_mode` の単体テストで担保する。

use fandhe_container_core::plugin_trust::{PluginTrustErrorKind, check_owner_and_mode};

#[test]
fn plug11_task122_1_pure_check_is_reachable_from_public_api() {
    assert_eq!(check_owner_and_mode(0, 0o755, 1000), Ok(()));
    assert_eq!(
        check_owner_and_mode(1, 0o755, 1000),
        Err(PluginTrustErrorKind::UntrustedOwner)
    );
}

/// macOS（#1865）: `/tmp` は `/private/tmp` への symlink のため祖先の symlink として拒否する（PLUG-11・MAC-1）。
#[cfg(target_os = "macos")]
#[test]
fn plug11_1865_macos_rejects_symlinked_tmp() {
    use fandhe_container_core::plugin_trust::{TrustTarget, verify_plugin_dir};

    let err = verify_plugin_dir(std::path::Path::new("/tmp/fandhe-x")).expect_err("must reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), std::path::Path::new("/tmp"));
}

/// Windows 等は同等検証を持たない（ホストでは検証しない。#1415・#1539）ため、どのパスも fail-closed で拒否する（PLUG-11・REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn plug11_task122_1_windows_is_rejected_fail_closed() {
    use fandhe_container_core::plugin_trust::{TrustTarget, verify_plugin_dir};

    let dir = std::env::temp_dir();
    let err = verify_plugin_dir(&dir).expect_err("must reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::Unsupported);
    assert_eq!(err.target(), TrustTarget::Directory);
}
/// 許可一覧と sha256 型が公開 API から到達でき、3 OS で同じ結果になること（TASK-122.3・PLUG-11）。
#[test]
fn plug11_task122_3_allowlist_is_reachable_from_public_api() {
    use fandhe_container_core::plugin_trust::{AllowedPluginHashes, Sha256Digest};

    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let list = AllowedPluginHashes::parse(format!("{abc}  plugin-a\n").as_bytes()).expect("parse");
    let digest = Sha256Digest::from_hex(abc).expect("hex");
    assert!(list.contains(&digest));
    assert_eq!(list.len(), 1);
    assert!(AllowedPluginHashes::default().is_empty());
}

/// 検証方式の切替点が公開 API から到達でき、既定はハッシュ方式、署名は fail-closed で拒否されること
/// （TASK-122.4・PLUG-11）。
#[test]
fn plug11_task122_4_verification_method_is_reachable_from_public_api() {
    use fandhe_container_core::plugin_trust::{
        PluginVerificationMethod, PluginVerificationMethodKind,
    };

    assert_eq!(
        PluginVerificationMethod::default().kind(),
        PluginVerificationMethodKind::Sha256Allowlist
    );
    assert_eq!(
        PluginVerificationMethod::Signature.kind(),
        PluginVerificationMethodKind::Signature
    );
    let kind = PluginVerificationMethod::Signature
        .ensure_implemented()
        .expect_err("must reject");
    assert_eq!(kind, PluginTrustErrorKind::VerificationMethodNotImplemented);
    assert_eq!(
        PluginVerificationMethod::default().ensure_implemented(),
        Ok(())
    );
}
