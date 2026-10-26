//! CDI `deviceNodes` の作成の非特権の実試験（GPU-2・TASK-127.1）。
//!
//! 一時ディレクトリを `/dev` のルートに見立て、FIFO と whiteout（c 0:0。Linux 5.8 以降は
//! `CAP_MKNOD` なしで作れる）で、実際の `mknodat` 経路と「ホストと major/minor が一致」を照合する。
#![cfg(target_os = "linux")]

use fandhe_container_gpu::cdi_apply::{
    CdiApplyErrorCode, DeviceNodeKind, DeviceNodeStatus, create_device_nodes, resolve_device_nodes,
};
use fandhe_container_gpu::cdi_spec::DeviceNode;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fc-gpu-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 子プロセスを期限つきで待つ（REPAIR-5）。超過時は kill して wait で回収し、失敗として返す。
fn run_with_deadline(cmd: &mut std::process::Command, limit: Duration) -> bool {
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// REPAIR-5: 期限を超えた子プロセスは kill され、失敗として返る。
#[test]
fn run_with_deadline_kills_a_hung_child() {
    let start = Instant::now();
    let ok = run_with_deadline(
        std::process::Command::new("sleep").arg("60"),
        Duration::from_millis(200),
    );
    assert!(!ok);
    assert!(start.elapsed() < Duration::from_secs(10));
}

fn node(path: &str, ty: Option<&str>) -> DeviceNode {
    DeviceNode {
        path: path.to_owned(),
        host_path: None,
        r#type: ty.map(str::to_owned),
        major: None,
        minor: None,
        file_mode: None,
        permissions: None,
        uid: None,
        gid: None,
    }
}

/// GPU-2: FIFO を中間ディレクトリごと作り、mode が umask に削られず観測値と一致する。
#[test]
fn gpu2_fifo_creates_dirs_and_fixes_mode() {
    let d = tmp("fifo");
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[node("/dev/a/b/fifo0", Some("p"))]).unwrap();
    let rep = create_device_nodes(root.as_fd(), &resolved).unwrap();
    assert_eq!(rep.outcomes.len(), 1);
    let o = &rep.outcomes[0];
    assert_eq!(o.path, "a/b/fifo0");
    assert_eq!(o.kind, DeviceNodeKind::Fifo);
    assert_eq!(o.status, DeviceNodeStatus::Created);
    assert_eq!(o.observed_mode, 0o666);
    let md = std::fs::symlink_metadata(d.join("a/b/fifo0")).unwrap();
    assert!(md.file_type().is_fifo());
    assert_eq!(md.mode() & 0o7777, 0o666);
    // 2 回目は完全一致の既存として受ける。
    let rep2 = create_device_nodes(root.as_fd(), &resolved).unwrap();
    assert_eq!(rep2.outcomes[0].status, DeviceNodeStatus::AlreadyPresent);
    let _ = std::fs::remove_dir_all(&d);
}

/// GPU-2 受け入れ条件 1: ホスト役の whiteout を hostPath で指す path だけの指定が、
/// 同じ種別・rdev のノードとして作られる。
#[test]
fn gpu2_whiteout_matches_host_major_minor() {
    let host = tmp("wo-host");
    let dev = tmp("wo-dev");
    // ホスト役の whiteout を作る（CAP_MKNOD 不要）。作れない環境は skip せず原因を明示して失敗させる。
    let ok = run_with_deadline(
        std::process::Command::new("mknod")
            .arg(host.join("wo"))
            .args(["c", "0", "0"]),
        Duration::from_secs(10),
    );
    assert!(ok, "failed to create a whiteout device on the host side");
    let host_md = std::fs::symlink_metadata(host.join("wo")).unwrap();
    assert!(host_md.file_type().is_char_device());

    let mut n = node("/dev/wo", None);
    n.host_path = Some(host.join("wo").to_str().unwrap().to_owned());
    let resolved = resolve_device_nodes(&[n]).unwrap();
    assert_eq!(
        (resolved[0].kind(), resolved[0].major(), resolved[0].minor()),
        (DeviceNodeKind::Char, 0, 0)
    );
    let root = std::fs::File::open(&dev).unwrap();
    let rep = create_device_nodes(root.as_fd(), &resolved).unwrap();
    assert_eq!(
        (
            rep.outcomes[0].observed_major,
            rep.outcomes[0].observed_minor
        ),
        (0, 0)
    );
    let md = std::fs::symlink_metadata(dev.join("wo")).unwrap();
    assert!(md.file_type().is_char_device());
    assert_eq!(md.rdev(), host_md.rdev());
    let _ = std::fs::remove_dir_all(&host);
    let _ = std::fs::remove_dir_all(&dev);
}

/// GPU-2: 中間要素が symlink なら拒否し、外には何も作らない。
#[test]
fn gpu2_symlink_component_is_rejected() {
    let d = tmp("sl");
    let outside = tmp("sl-out");
    std::os::unix::fs::symlink(&outside, d.join("x")).unwrap();
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[node("/dev/x/fifo", Some("p"))]).unwrap();
    let e = create_device_nodes(root.as_fd(), &resolved).unwrap_err();
    assert_eq!(e.code(), CdiApplyErrorCode::FailedPrecondition);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&outside);
}

/// GPU-2: 末端に別内容の既存があれば拒否し、上書きしない。
#[test]
fn gpu2_existing_mismatch_is_rejected_without_overwrite() {
    let d = tmp("ex");
    std::fs::write(d.join("f"), b"keep").unwrap();
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[node("/dev/f", Some("p"))]).unwrap();
    let e = create_device_nodes(root.as_fd(), &resolved).unwrap_err();
    assert_eq!(e.code(), CdiApplyErrorCode::FailedPrecondition);
    assert_eq!(std::fs::read(d.join("f")).unwrap(), b"keep");
    let _ = std::fs::remove_dir_all(&d);
}

/// GPU-2: 2 件目が失敗したとき、1 件目と作ったディレクトリが消える。
#[test]
fn gpu2_failure_rolls_back_created_nodes_and_dirs() {
    let d = tmp("rb");
    std::fs::write(d.join("blocker"), b"x").unwrap();
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[
        node("/dev/sub/fifo0", Some("p")),
        node("/dev/blocker", Some("p")),
    ])
    .unwrap();
    assert!(create_device_nodes(root.as_fd(), &resolved).is_err());
    assert!(!d.join("sub").exists());
    assert!(d.join("blocker").exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// GPU-2: 自分の uid / gid への chown が通り、観測値と一致する。
#[test]
fn gpu2_owner_is_applied() {
    let d = tmp("own");
    let me = std::fs::metadata(&d).unwrap();
    let mut n = node("/dev/o", Some("p"));
    n.uid = Some(me.uid());
    n.gid = Some(me.gid());
    n.file_mode = Some(0o640);
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[n]).unwrap();
    let rep = create_device_nodes(root.as_fd(), &resolved).unwrap();
    assert_eq!(rep.outcomes[0].observed_mode, 0o640);
    let md = std::fs::symlink_metadata(d.join("o")).unwrap();
    assert_eq!((md.uid(), md.gid()), (me.uid(), me.gid()));
    let _ = std::fs::remove_dir_all(&d);
}
