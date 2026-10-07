//! `--shm-size` / `--tmpfs` 解析の受け入れ基準照合（SUP-12・TASK-169.2・#527・REPAIR-12）。
//! 公開 API のみを外部 crate 視点で使い、文字列から core の仕様型（mount data まで）への変換を具体値で確認する。
//! OS 非依存のため 3 OS で実行する。

use fandhe_container_supervisor::container_options::{MountOptions, ShmSize, TmpfsOption};

/// SUP-12: `--shm-size 64m --tmpfs /run:rw,noexec,nosuid,size=65536k` が指定どおりの mount data になる。
#[test]
fn sup12_shm_size_and_tmpfs_become_exact_mount_specs() {
    let opts = MountOptions::default()
        .with_shm_size(ShmSize::parse("64m").expect("shm"))
        .with_tmpfs(TmpfsOption::parse("/run:rw,noexec,nosuid,size=65536k").expect("tmpfs"))
        .expect("add tmpfs");
    let set = opts.to_tmpfs_set().expect("set");
    let got: Vec<(String, String, bool, bool)> = set
        .mounts()
        .iter()
        .map(|m| {
            (
                m.destination.as_str().to_owned(),
                m.data_string(),
                m.read_only,
                m.exec,
            )
        })
        .collect();
    let expected = ("mode=1777,size=67108864".to_owned(), false, false);
    assert_eq!(
        got,
        vec![
            (
                "/dev/shm".to_owned(),
                expected.0.clone(),
                expected.1,
                expected.2
            ),
            ("/run".to_owned(), expected.0, expected.1, expected.2),
        ]
    );
}

/// SUP-12: 分離を弱める指定（suid・dev）と予約先（/proc）は拒否される。
#[test]
fn sup12_unsafe_tmpfs_requests_are_rejected() {
    assert!(TmpfsOption::parse("/x:suid").is_err());
    assert!(TmpfsOption::parse("/x:dev").is_err());
    let opts = MountOptions::default()
        .with_tmpfs(TmpfsOption::parse("/proc/sys").expect("parse"))
        .expect("add tmpfs");
    assert!(opts.to_tmpfs_set().is_err());
}
