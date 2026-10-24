//! 本番 launcher へ渡す起動オプション(SUP-12・CORE-5・SEC-1・#2625。TASK-169 追補)。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `ContainerOptions`(`--ipc`・`--shm-size`・`--tmpfs`・secrets / configs)で検証済みの指定を、
//! 依存の向き(supervisor → core)を守ったまま [`super::ProductionLauncherBuilder::launch_options`] へ渡すための
//! OS 非依存の型。supervisor の `ContainerOptions::launch_options` が作り、launcher が launch のたびに
//! (restart の再 launch を含む)同じ指定を fork 前に確定して pivot 前段へ渡す。
//!
//! | フィールド | 反映先 |
//! | ---- | ---- |
//! | `tmpfs` | pivot 前段の `mount_tmpfs`(`--ipc=host` 以外では `/dev/shm` を必ず含む) |
//! | `inject` | pivot 前段の `inject_files`(secrets / configs。空なら注入しない) |
//! | `ipc` | `Host` のときだけ IPC namespace を作らず、Landlock の暗黙マウントを `WithoutShm` にする |
//!
//! # 契約
//!
//! - core は supervisor の検証を信用せず、[`LaunchOptions::new`] で再検証する(builder の呼び出し順で迂回
//!   させない)。矛盾する組み合わせは `InvalidArgument` の固定文言で拒否する(fail-closed)。
//! - Landlock の暗黙マウントは受け取らず、実際に載せる tmpfs 集合から [`ImplicitDevMounts::for_tmpfs_set`] で
//!   導く(入力を 1 つに保ち、実マウントとルールの食い違いを作らない。CORE-5)。
//! - `Debug` は secret の内容を出さない(`InjectedContent` の `Debug` は長さだけを出す)。
//! - IPC 共有(`Host`)は launcher の起動オプションだけで許し、`config.json` からは外せない(`start` は
//!   IPC namespace を必須とする検査を維持する。SEC-1)。
//!
//! # 未実装・残余(REPAIR-3)
//!
//! - CLI / stack から supervisor への `ContainerOptions` の受け渡しは未結線(`run_main` は既定のまま)。
//! - 範囲写像の経路では ID 写像の holder が中間プロセスのメモリ(注入内容を含む)を継承する。露出の解消は #2628。

use crate::dev_mounts::ImplicitDevMounts;
use crate::injected_files::InjectedFileSet;
use crate::tmpfs::{DEV_SHM_PATH, TmpfsMountSet};
use crate::traits::types::{ErrorCode, TraitError};

/// コンテナの IPC namespace の扱い(SUP-12・SEC-1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LaunchIpcMode {
    /// コンテナ専用の IPC namespace と専用の `/dev/shm`(既定)。
    Private,
    /// ホストの IPC namespace を共有する(`--ipc=host`)。IPC namespace を作らず、`/dev/shm` を載せない。
    Host,
}

/// 検証済みの起動オプション(モジュール doc)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOptions {
    tmpfs: TmpfsMountSet,
    inject: InjectedFileSet,
    ipc: LaunchIpcMode,
}

fn invalid(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

impl LaunchOptions {
    /// 検証して作る。`Host` と `/dev/shm`、`Private` と `/dev/shm` の欠落、注入ディレクトリと tmpfs の重なりは
    /// `InvalidArgument` で拒否する。
    pub fn new(
        tmpfs: TmpfsMountSet,
        inject: InjectedFileSet,
        ipc: LaunchIpcMode,
    ) -> Result<Self, TraitError> {
        let has_shm = tmpfs
            .mounts()
            .iter()
            .any(|m| m.destination.as_str() == DEV_SHM_PATH);
        match ipc {
            LaunchIpcMode::Host if has_shm => {
                return Err(invalid(
                    "a /dev/shm mount cannot be combined with --ipc=host",
                ));
            }
            LaunchIpcMode::Private if !has_shm => {
                return Err(invalid("a private IPC namespace requires a /dev/shm mount"));
            }
            _ => {}
        }
        inject.check_against_tmpfs(&tmpfs)?;
        Ok(Self { tmpfs, inject, ipc })
    }

    /// 指定が無いときの値(既定の `/dev/shm` 64 MiB 1 件・注入なし・`Private`)。従来の launcher の動作と同じ。
    pub fn try_default() -> Result<Self, TraitError> {
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs.ensure_default_dev_shm().map_err(|e| {
            TraitError::new(e.code(), "failed to prepare the default /dev/shm mount")
        })?;
        Self::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
    }

    /// pivot 前段で載せる tmpfs の集合。
    pub fn tmpfs(&self) -> &TmpfsMountSet {
        &self.tmpfs
    }

    /// 注入するファイルの集合。
    pub fn inject(&self) -> &InjectedFileSet {
        &self.inject
    }

    /// IPC namespace の扱い。
    pub fn ipc(&self) -> LaunchIpcMode {
        self.ipc
    }

    /// Landlock の暗黙マウント(実際に載せる tmpfs の集合から導く。CORE-5)。
    pub fn implicit_dev_mounts(&self) -> ImplicitDevMounts {
        ImplicitDevMounts::for_tmpfs_set(&self.tmpfs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
    use crate::tmpfs::{TmpfsMountSpec, TmpfsSize};

    fn set_of(dests: &[&str]) -> TmpfsMountSet {
        let mut set = TmpfsMountSet::new();
        for d in dests {
            set.push(TmpfsMountSpec::new(d, None).expect("spec"))
                .expect("push");
        }
        set
    }

    fn secret(dest: &str, bytes: &[u8]) -> InjectedFileSet {
        let mut set = InjectedFileSet::new();
        set.push(
            InjectedFileSpec::new(
                dest,
                InjectedContent::from_bytes(bytes.to_vec()).expect("content"),
                InjectedFileMode::new(0o444).expect("mode"),
            )
            .expect("spec"),
        )
        .expect("push");
        set
    }

    /// SUP-12・CORE-5: 既定値は従来の launcher と同じ(`/dev/shm` 64 MiB 1 件・注入なし・Private・All)。
    #[test]
    fn sup12_core5_launch_options_default_matches_current() {
        let o = LaunchOptions::try_default().expect("default");
        let mounts = o.tmpfs().mounts();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].destination.as_str(), "/dev/shm");
        assert_eq!(mounts[0].data_string(), "mode=1777,size=67108864");
        assert!(o.inject().is_empty());
        assert_eq!(o.ipc(), LaunchIpcMode::Private);
        assert_eq!(o.implicit_dev_mounts(), ImplicitDevMounts::All);
    }

    /// SUP-12: Host と /dev/shm の組み合わせは拒否する。
    #[test]
    fn sup12_launch_options_rejects_host_ipc_with_dev_shm() {
        let mut set = TmpfsMountSet::new();
        set.push(
            TmpfsMountSpec::dev_shm(TmpfsSize::from_bytes(1 << 20).expect("size")).expect("shm"),
        )
        .expect("push");
        let err = LaunchOptions::new(set, InjectedFileSet::new(), LaunchIpcMode::Host)
            .expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "a /dev/shm mount cannot be combined with --ipc=host"
        );
    }

    /// SUP-12: Private で /dev/shm が無い組み合わせは拒否する(Landlock の All と実マウントの食い違い防止)。
    #[test]
    fn sup12_launch_options_rejects_private_without_dev_shm() {
        let err = LaunchOptions::new(
            set_of(&["/run"]),
            InjectedFileSet::new(),
            LaunchIpcMode::Private,
        )
        .expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "a private IPC namespace requires a /dev/shm mount"
        );
    }

    /// SUP-12: 注入ディレクトリと tmpfs の重なりは拒否する。
    #[test]
    fn sup12_launch_options_rejects_inject_overlapping_tmpfs() {
        let err = LaunchOptions::new(
            set_of(&["/run"]),
            secret("/run/secrets/db", b"x"),
            LaunchIpcMode::Host,
        )
        .expect_err("rejected");
        assert_eq!(
            err.message(),
            "injected file directory overlaps a tmpfs mount"
        );
    }

    /// CORE-5: Host は WithoutShm、/dev/shm と /run が別なら注入は通る。
    #[test]
    fn core5_host_ipc_uses_without_shm() {
        let o = LaunchOptions::new(
            set_of(&["/run"]),
            secret("/etc/token", b"x"),
            LaunchIpcMode::Host,
        )
        .expect("options");
        assert_eq!(o.implicit_dev_mounts(), ImplicitDevMounts::WithoutShm);
        assert_eq!(o.inject().files().len(), 1);
    }

    /// SEC-1: Debug に secret の内容が出ない。
    #[test]
    fn sec1_debug_does_not_leak_secret_content() {
        let o = LaunchOptions::new(
            set_of(&["/run"]),
            secret("/etc/token", b"TOPSECRETVALUE"),
            LaunchIpcMode::Host,
        )
        .expect("options");
        let text = format!("{o:?}");
        assert!(!text.contains("TOPSECRETVALUE"), "{text}");
        assert!(text.contains("<redacted 14 bytes>"), "{text}");
    }
}
