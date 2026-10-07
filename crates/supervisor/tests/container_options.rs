//! 起動オプション全種を 1 つの `ContainerOptions` へ同時指定したときの結合照合
//! （SUP-12・TASK-169.5.2・#856・MS-9・REPAIR-12）。
//!
//! 対象は ulimit（#526）・`--shm-size` / `--tmpfs`（#527）・`--ipc`（#528）・env / env ファイル（#529）・
//! label（#855）。公開 API だけで文字列入力から 1 つの設定を組み立て、各オプションが個別実装どおりの値で
//! 読めること・互いに干渉しないこと・`--ipc=host` と `--shm-size` の併用を拒否することを具体値で確認する。
//! root 不要で既定のテスト集合で動く。3 OS 共通の照合が本体で、Linux 限定部分は core の exec 入力と実ストア。
//!
//! 対象外（REPAIR-3）: secrets / configs の tmpfs 注入は未実装のため含めない（実装後に組み合わせを追加する）。
//! 実カーネルへの適用（`prlimit(2)`・`mount(2)`・`unshare(2)`）は個別の実機前提テスト
//! （`crates/core/tests/tmpfs_mount.rs` 等・`container_options_ipc.rs`）が担い、全オプション同時の
//! 実機適用は本番 `ProcessLauncher` の提供後の課題。

use fandhe_container_core::rlimits::RlimitKind;
use fandhe_container_core::traits::{ContainerId, ContainerStatus, CreateStateRequest, ErrorCode};
use fandhe_container_supervisor::container_options::env::{EnvFile, EnvSet, EnvVar};
use fandhe_container_supervisor::container_options::{
    ContainerOptions, IpcMode, Label, Labels, MountOptions, ShmSize, TmpfsOption, Ulimit,
};

fn ulimits() -> Vec<Ulimit> {
    ["nofile=1024:2048", "nproc=512", "core=0"]
        .iter()
        .map(|s| Ulimit::parse(s).unwrap())
        .collect()
}

fn mounts() -> MountOptions {
    MountOptions::default()
        .with_shm_size(ShmSize::parse("64m").unwrap())
        .with_tmpfs(TmpfsOption::parse("/run:rw,noexec,nosuid,size=65536k").unwrap())
        .unwrap()
        .with_tmpfs(TmpfsOption::parse("/scratch:ro").unwrap())
        .unwrap()
}

fn env() -> EnvSet {
    let base = [EnvVar::parse("PATH=/usr/bin").unwrap()];
    let file = EnvFile::parse("# c\nMODE=file\nNAME=dummy\n").unwrap();
    let cli = [EnvVar::parse("MODE=cli").unwrap()];
    EnvSet::resolve(&base, &[file], &cli).unwrap()
}

fn labels() -> Labels {
    Labels::resolve(
        ["app=web", "tier", "env=prod", "env=stg", "note=a=b"]
            .iter()
            .map(|s| Label::parse(s).unwrap())
            .collect(),
    )
    .unwrap()
}

/// 全オプションを同時指定した設定。
fn all_options() -> ContainerOptions {
    ContainerOptions::new()
        .with_ulimits(ulimits())
        .unwrap()
        .with_mounts(mounts())
        .with_ipc_mode(IpcMode::Shareable)
        .with_env(env())
        .with_labels(labels())
}

fn rlimits_of(o: &ContainerOptions) -> Vec<(RlimitKind, u64, u64)> {
    o.rlimits()
        .iter()
        .map(|r| (r.kind(), r.soft(), r.hard()))
        .collect()
}

fn tmpfs_of(o: &ContainerOptions) -> Vec<(String, String, bool, bool)> {
    o.tmpfs_set()
        .unwrap()
        .mounts()
        .iter()
        .map(|m| {
            (
                m.destination.as_str().to_string(),
                m.data_string(),
                m.read_only,
                m.exec,
            )
        })
        .collect()
}

fn label_pairs(o: &ContainerOptions) -> Vec<(&str, &str)> {
    o.labels().iter().collect()
}

/// AC: 全オプション同時指定でも各オプションが個別実装どおりの具体値で反映される。
#[test]
fn sup12_task169_5_2_all_options_reflected_together() {
    let o = all_options();
    assert_eq!(
        rlimits_of(&o),
        [
            (RlimitKind::Nofile, 1024, 2048),
            (RlimitKind::Nproc, 512, 512),
            (RlimitKind::Core, 0, 0)
        ]
    );
    let t = tmpfs_of(&o);
    assert_eq!(t.len(), 3);
    assert_eq!(
        t[0],
        (
            "/dev/shm".into(),
            "mode=1777,size=67108864".into(),
            false,
            false
        )
    );
    assert_eq!(
        t[1],
        (
            "/run".into(),
            "mode=1777,size=67108864".into(),
            false,
            false
        )
    );
    assert_eq!(t[2].0, "/scratch");
    assert!(t[2].2, "/scratch must be read-only");
    assert_eq!(o.ipc_mode(), IpcMode::Shareable);
    assert!(o.ipc_mode().is_shareable());
    assert!(!o.ipc_mode().shares_host_namespace());
    assert_eq!(
        o.env().to_env_strings(),
        ["PATH=/usr/bin", "MODE=cli", "NAME=dummy"]
    );
    assert_eq!(
        label_pairs(&o),
        [
            ("app", "web"),
            ("env", "stg"),
            ("note", "a=b"),
            ("tier", "")
        ]
    );
}

/// AC: 各オプションは他のオプションの指定に干渉されず、builder の適用順にも依存しない。
#[test]
fn sup12_task169_5_2_options_are_independent() {
    let all = all_options();
    assert_eq!(
        rlimits_of(&all),
        rlimits_of(&ContainerOptions::new().with_ulimits(ulimits()).unwrap())
    );
    assert_eq!(
        tmpfs_of(&all),
        tmpfs_of(&ContainerOptions::new().with_mounts(mounts()))
    );
    assert_eq!(
        all.env().to_env_strings(),
        ContainerOptions::new()
            .with_env(env())
            .env()
            .to_env_strings()
    );
    assert_eq!(
        label_pairs(&all),
        label_pairs(&ContainerOptions::new().with_labels(labels()))
    );
    let reversed = ContainerOptions::new()
        .with_labels(labels())
        .with_env(env())
        .with_ipc_mode(IpcMode::Shareable)
        .with_mounts(mounts())
        .with_ulimits(ulimits())
        .unwrap();
    assert_eq!(all, reversed);
}

/// AC: 全指定の設定から作る状態作成要求の annotations は label のみで、env・ulimit が混入しない。
#[test]
fn sup12_task169_5_2_label_reaches_create_request_with_other_options() {
    let o = all_options();
    let req = CreateStateRequest::new(
        ContainerStatus::created(ContainerId::new("web").unwrap(), None),
        std::env::temp_dir().join("fandhe-sup-options-bundle"),
    )
    .unwrap()
    .with_annotations(o.labels().annotations().clone());
    let got: Vec<(&str, &str)> = req.annotations().unwrap().iter().collect();
    assert_eq!(
        got,
        [
            ("app", "web"),
            ("env", "stg"),
            ("note", "a=b"),
            ("tier", "")
        ]
    );
}

/// AC: `--ipc=host` と `--shm-size` の併用は適用順によらず InvalidArgument で拒否し、他オプションは読める。
#[test]
fn sup12_task169_5_2_ipc_host_with_shm_size_is_rejected() {
    let a = all_options().with_ipc_mode(IpcMode::Host);
    let b = ContainerOptions::new()
        .with_ipc_mode(IpcMode::Host)
        .with_mounts(mounts());
    for o in [&a, &b] {
        let e = o.tmpfs_set().unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "--shm-size cannot be combined with --ipc=host");
    }
    assert_eq!(a.rlimits().len(), 3);
    assert_eq!(a.env().len(), 3);
    assert_eq!(a.labels().iter().count(), 4);
}

/// AC: `--ipc=host` と `--tmpfs /dev/shm` の併用は（`--shm-size` なしでも）InvalidArgument で拒否する。
#[test]
fn sup12_task169_5_2_ipc_host_with_tmpfs_dev_shm_is_rejected() {
    let o = ContainerOptions::new()
        .with_ipc_mode(IpcMode::Host)
        .with_mounts(
            MountOptions::default()
                .with_tmpfs(TmpfsOption::parse("/dev/shm:size=1m").unwrap())
                .unwrap(),
        );
    let e = o.tmpfs_set().unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        e.message(),
        "--tmpfs /dev/shm cannot be combined with --ipc=host"
    );
}

/// 境界: `--ipc=host` でも `--shm-size` を伴わない `--tmpfs` は受理される。
#[test]
fn sup12_task169_5_2_ipc_host_without_shm_size_is_accepted() {
    let o = ContainerOptions::new()
        .with_ipc_mode(IpcMode::Host)
        .with_mounts(
            MountOptions::default()
                .with_tmpfs(TmpfsOption::parse("/run").unwrap())
                .unwrap(),
        );
    let t = tmpfs_of(&o);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].0, "/run");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use fandhe_container_core::exec::{Entrypoint, Namespace, NamespaceSet, StagePipeline};
    use fandhe_container_core::traits::{ContainerId, ContainerStatus, CreateStateRequest};
    use fandhe_container_supervisor::container_options::IpcMode;
    use fandhe_container_supervisor::state::open_default_store;

    use super::all_options;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            // 既存パスは削除せず、未使用名が見つかるまで連番を進めて `create_dir`（既存なら失敗）で新規作成する。
            let p = loop {
                let n = COUNTER.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fandhe-sup-options-{}-{n}", std::process::id()));
                match fs::create_dir(&p) {
                    Ok(()) => break p,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create temp dir: {e}"),
                }
            };
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// AC: 全指定の設定が core の exec 入力（namespace 集合・rlimit ステージ・Entrypoint）へ渡せる。
    /// プロセスは起動せず namespace も作らない。
    #[test]
    fn sup12_task169_5_2_reaches_core_exec_inputs() {
        let o = all_options();
        let base = NamespaceSet::empty().with(Namespace::Uts);
        assert!(o.ipc_mode().apply_to(base).contains(Namespace::Ipc));
        assert!(!IpcMode::Host.apply_to(base).contains(Namespace::Ipc));
        assert!(
            StagePipeline::new()
                .with_rlimits(o.rlimits().clone())
                .is_ok()
        );
        o.env()
            .check_entrypoint_budget("/bin/true", &["true"])
            .unwrap();
        Entrypoint::new("/bin/true", ["true"], o.env().to_env_strings()).unwrap();
    }

    /// AC: 全オプション指定でも label が state.json の annotations へ具体値で永続化される。
    #[test]
    fn sup12_task169_5_2_labels_persist_with_all_options() {
        let t = TmpDir::new();
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let o = all_options();
        let req = CreateStateRequest::new(
            ContainerStatus::created(ContainerId::new("web").unwrap(), None),
            std::env::temp_dir().join("fandhe-sup-options-bundle"),
        )
        .unwrap()
        .with_annotations(o.labels().annotations().clone());
        store.create(&req).unwrap();
        let raw = fs::read_to_string(t.path().join("web").join("state.json")).unwrap();
        assert!(
            raw.contains(r#""annotations":{"app":"web","env":"stg","note":"a=b","tier":""}"#),
            "{raw}"
        );
    }
}
