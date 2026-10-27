//! `createContainer` フックの実行順序ゲートの公開 API 結合試験（TASK-127.3・GPU-2）。root 不要。
#![cfg(target_os = "linux")]

use fandhe_container_gpu::cdi_apply::CdiApplyErrorCode;
use fandhe_container_gpu::cdi_apply::hooks::verify_hook_stage;
use std::path::Path;

/// GPU-2: マウントポイントでない通常のディレクトリ（自己 bind 前）は FailedPrecondition。
#[test]
fn gpu2_unmounted_rootfs_is_rejected() {
    let dir = std::env::temp_dir().join(format!("fandhe-gpu-stage-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let canon = std::fs::canonicalize(&dir).unwrap();
    let r = verify_hook_stage(&canon);
    std::fs::remove_dir(&dir).unwrap();
    let err = r.unwrap_err();
    assert_eq!(err.code(), CdiApplyErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "rootfs is not self-bind mounted");
}

/// GPU-2: ホストの `/`（pivot 済み相当）は FailedPrecondition。
#[test]
fn gpu2_host_root_is_rejected() {
    let err = verify_hook_stage(Path::new("/")).unwrap_err();
    assert_eq!(err.code(), CdiApplyErrorCode::FailedPrecondition);
}

/// GPU-2: 相対パスは InvalidArgument。
#[test]
fn gpu2_relative_rootfs_is_rejected() {
    let err = verify_hook_stage(Path::new("relative/rootfs")).unwrap_err();
    assert_eq!(err.code(), CdiApplyErrorCode::InvalidArgument);
}
