//! `createContainer` フックの実行順序ゲートの公開 API 結合試験（TASK-127.3・GPU-2）。root 不要。
#![cfg(target_os = "linux")]

use fandhe_container_gpu::cdi_apply::CdiApplyErrorCode;
use fandhe_container_gpu::cdi_apply::hooks::verify_hook_stage;
use std::path::Path;

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

/// GPU-2: マウントポイントでない通常のディレクトリ（自己 bind 前）は FailedPrecondition。
#[test]
fn gpu2_unmounted_rootfs_is_rejected() {
    // 残骸があると排他作成が AlreadyExists になるため、連番・作成前削除・Drop の補助を使う（REPAIR-12・#3375）。
    let dir = test_root::test_root("fandhe-gpu-stage", "hooks");
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

/// GPU-2・REPAIR-12(#3375): 前回の残骸（同名のディレクトリと中身）が残っていても、補助が空に作り直し、
/// `gpu2_unmounted_rootfs_is_rejected` と同じ排他作成（`create_dir`）が通り、drop で消える。
#[test]
fn gpu2_repair12_test_root_clears_stale_residue() {
    let p = std::env::temp_dir().join(format!(
        "fandhe-gpu-stage-stale-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(p.join("old")).unwrap();
    std::fs::write(p.join("old").join("f"), b"x").unwrap();
    assert!(std::fs::create_dir(&p).is_err(), "residue must collide");
    {
        let root = test_root::test_root_at(p.clone());
        assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
        let canon = std::fs::canonicalize(&*root).unwrap();
        let err = verify_hook_stage(&canon).unwrap_err();
        assert_eq!(err.code(), CdiApplyErrorCode::FailedPrecondition);
    }
    assert!(!p.exists());
}
