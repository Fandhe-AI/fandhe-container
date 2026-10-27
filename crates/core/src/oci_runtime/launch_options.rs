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
//! | `rlimits` | `--ulimit` の指定値。launcher が 16 種へ補完して `Rlimits` 段へ渡し、`state.json` にも記録する(#2713) |
//! | `env` | `--env` の上書き。`process.env` へ `KEY` 単位で重ねて entrypoint へ渡す(#2713) |
//! | `capability_drop` | `create --cap-drop`。config.json 由来の許可集合から除く(狭める方向のみ。launch の段と分離の記録へ同じ値を渡す。CLI-1・SEC-1・#2775) |
//! | `network` | start が予約前に config の network エントリと突き合わせ(D7。`network_mode.rs`)、launcher が spec と照合する。`Loopback` の実体は #3064 まで `Unimplemented`(NET-6・SEC-1・#3058) |
//! | `root_readonly` | `create --read-only`。config の `root.readonly` と OR(狭める方向のみ)。mount の RDONLY・Landlock の root 規則・分離の記録へ同じ実効値を渡す(CLI-1・SUP-12・CORE-5・SEC-1・#2828) |
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
//! - CLI から supervisor への受け渡しは状態ルート配下の 0600 の文書(`fandhe-container-supervisor` の
//!   `container_options::document`・#2713)で行う。stack の `up` からの結線は TASK-155 の後続。
//! - 範囲写像の経路では ID 写像の holder が中間プロセスのメモリを継承し dumpable になる。注入内容は
//!   `InjectedContent::from_file` の封印 memfd ならユーザー空間のメモリに載らず holder にも継承されない(#2628)。
//!   呼び出し元のメモリにある内容(`from_bytes`)は、launcher が範囲写像(`RootlessSubordinateIds`)との併用を
//!   起動前に拒否する。CLI → supervisor の結線では secret を fd で渡す必要がある(未設計)。

use crate::capabilities::CapabilitySet;
use crate::dev_mounts::ImplicitDevMounts;
use crate::injected_files::{InjectedFileSet, overlaps};
use crate::oci_runtime::config::{CONFIG_MAX_ENV, CONFIG_MAX_STRING_BYTES};
use crate::oci_runtime::network_mode::LaunchNetworkMode;
use crate::rlimits::Rlimits;
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
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchOptions {
    tmpfs: TmpfsMountSet,
    inject: InjectedFileSet,
    ipc: LaunchIpcMode,
    /// `--ulimit` で指定された種別だけ(未指定の種別は launcher が継承値で補う)。
    rlimits: Rlimits,
    /// `--env` の上書き(`KEY=VALUE`。`with_env` で検証済み)。
    env: Vec<String>,
    /// `--cap-drop` の集合(config.json 由来の許可集合から除く。空なら何もしない)。
    capability_drop: CapabilitySet,
    /// `--read-only`(true なら config の値によらず root を読み取り専用にする。false なら config に従う)。
    root_readonly: bool,
    /// network namespace の扱い(既定 `FromConfig`。NET-6・SEC-1・#3058)。
    network: LaunchNetworkMode,
}

/// `env` の値(秘密を含みうる)を出さず、件数だけを出す(SEC-1)。
impl std::fmt::Debug for LaunchOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchOptions")
            .field("tmpfs", &self.tmpfs)
            .field("inject", &self.inject)
            .field("ipc", &self.ipc)
            .field("rlimits", &self.rlimits)
            .field("env_count", &self.env.len())
            .field("capability_drop", &self.capability_drop)
            .field("root_readonly", &self.root_readonly)
            .field("network", &self.network)
            .finish()
    }
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
        // 注入は親ディレクトリに専用 tmpfs を載せる。Host IPC で `/dev/shm` を含む位置へ載せると、
        // ホストの共有を private な tmpfs で隠し、Landlock の WithoutShm も検査しない(SEC-1・CORE-5)。
        if ipc == LaunchIpcMode::Host
            && inject
                .files()
                .iter()
                .any(|f| overlaps(f.parent(), DEV_SHM_PATH))
        {
            return Err(invalid(
                "an injected file under /dev/shm cannot be combined with --ipc=host",
            ));
        }
        Ok(Self {
            tmpfs,
            inject,
            ipc,
            rlimits: Rlimits::default(),
            env: Vec::new(),
            capability_drop: CapabilitySet::empty(),
            root_readonly: false,
            network: LaunchNetworkMode::FromConfig,
        })
    }

    /// `--ulimit` の指定を持たせる(種別の重複は [`Rlimits`] が構築時に拒否済み。#2713)。
    #[must_use]
    pub fn with_rlimits(mut self, rlimits: Rlimits) -> Self {
        self.rlimits = rlimits;
        self
    }

    /// `--cap-drop` の集合を持たせる(CLI-1・SEC-1)。型が [`CapabilitySet`] なので不正な名前は表せず、
    /// 許可集合は狭まる方向にしか変わらない(add の経路は無い)。
    #[must_use]
    pub fn with_capability_drop(mut self, drop: CapabilitySet) -> Self {
        self.capability_drop = drop;
        self
    }

    /// `--read-only` を持たせる(CLI-1・SUP-12・#2828)。true は config の `root.readonly` と OR で効き、
    /// `readonly:true` の config を書き込み可能に戻す経路は無い(false は「config に従う」)。
    #[must_use]
    pub fn with_root_readonly(mut self, root_readonly: bool) -> Self {
        self.root_readonly = root_readonly;
        self
    }

    /// network namespace の扱いを持たせる(NET-6・SEC-1・#3058)。config との突き合わせは start が予約前に行い、
    /// `Host` は起動オプションだけで選べる(config.json からは選べない)。
    #[must_use]
    pub fn with_network(mut self, network: LaunchNetworkMode) -> Self {
        self.network = network;
        self
    }

    /// `--env` の上書きを持たせる。core は supervisor の検証を信用せず、件数・長さ・形式(`KEY=VALUE`・キー非空・
    /// NUL なし)を再検証する(fail-closed。値は文言に含めない。SEC-1・#2713)。
    pub fn with_env(mut self, env: Vec<String>) -> Result<Self, TraitError> {
        if env.len() > CONFIG_MAX_ENV {
            return Err(invalid("too many environment overrides"));
        }
        for entry in &env {
            let valid = entry.len() <= CONFIG_MAX_STRING_BYTES
                && !entry.contains('\0')
                && entry.split_once('=').is_some_and(|(k, _)| !k.is_empty());
            if !valid {
                return Err(invalid("an environment override is malformed"));
            }
        }
        self.env = env;
        Ok(self)
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

    /// `--ulimit` で指定された rlimit(指定した種別だけ)。
    pub fn rlimits(&self) -> &Rlimits {
        &self.rlimits
    }

    /// `--read-only` が指定されたか(config の値との OR は launcher が取る)。
    pub fn root_readonly(&self) -> bool {
        self.root_readonly
    }

    /// network namespace の扱い。
    pub fn network(&self) -> LaunchNetworkMode {
        self.network
    }

    /// `--cap-drop` で除く capability の集合。
    pub fn capability_drop(&self) -> CapabilitySet {
        self.capability_drop
    }

    /// `process.env`(`base`)へ上書きを重ねた env。既存のキーはその位置で値を置き換え、新しいキーは末尾へ足す
    /// (`--env` の後勝ち・初出位置の保持。`base` 側に同じキーが複数あれば最初の位置を置き換え、残りは落とす)。
    pub fn merged_env(&self, base: &[String]) -> Vec<String> {
        // キー部分(`=` より前。`=` が無ければ全体)。スライスの添字は使わない。
        fn key_of(s: &str) -> &str {
            s.split_once('=').map_or(s, |(k, _)| k)
        }
        let mut out: Vec<String> = base.to_vec();
        for over in &self.env {
            let k = key_of(over);
            match out.iter().position(|e| key_of(e) == k) {
                Some(i) => {
                    if let Some(slot) = out.get_mut(i) {
                        *slot = over.clone();
                    }
                    // 同じキーの後続の重複は落とす(先頭の位置に 1 つだけ残す)。
                    let mut seen = false;
                    out.retain(|e| {
                        if key_of(e) == k {
                            let keep = !seen;
                            seen = true;
                            keep
                        } else {
                            true
                        }
                    });
                }
                None => out.push(over.clone()),
            }
        }
        out
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

    /// NET-6(#3058): network の既定は `FromConfig`、`with_network` で往復し、`Debug` に出る。
    #[test]
    fn net6_network_mode_defaults_to_from_config_and_round_trips() {
        let opts = LaunchOptions::try_default().expect("default");
        assert_eq!(opts.network(), LaunchNetworkMode::FromConfig);
        let opts = opts.with_network(LaunchNetworkMode::Host);
        assert_eq!(opts.network(), LaunchNetworkMode::Host);
        assert!(format!("{opts:?}").contains("network: Host"));
    }

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

    /// SUP-12・#2713: env の上書きは既存キーの位置を保ち、新しいキーは末尾へ足す。
    #[test]
    fn sup12_launch_options_env_merge() {
        let o = LaunchOptions::try_default()
            .expect("default")
            .with_env(vec!["A=2".into(), "B=3".into()])
            .expect("env");
        let base = vec!["PATH=/bin".to_owned(), "A=1".to_owned()];
        assert_eq!(o.merged_env(&base), vec!["PATH=/bin", "A=2", "B=3"]);
        assert_eq!(
            LaunchOptions::try_default().expect("d").merged_env(&base),
            base
        );
    }

    /// SUP-12・#2713: 不正な env の上書きは固定文言で拒否する(値を含めない)。
    #[test]
    fn sup12_launch_options_with_env_rejects_malformed() {
        for bad in ["NOEQ", "=v", "A=\0"] {
            let err = LaunchOptions::try_default()
                .expect("d")
                .with_env(vec![bad.to_owned()])
                .expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(err.message(), "an environment override is malformed");
        }
        let many = vec!["A=1".to_owned(); CONFIG_MAX_ENV + 1];
        let err = LaunchOptions::try_default()
            .expect("d")
            .with_env(many)
            .expect_err("rejected");
        assert_eq!(err.message(), "too many environment overrides");
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

    /// SEC-1・CORE-5: Host IPC と /dev/shm 配下(親が /dev/shm)の注入は拒否する(ホストの共有を隠すため)。
    #[test]
    fn sec1_launch_options_rejects_host_ipc_with_inject_under_dev_shm() {
        let err = LaunchOptions::new(
            set_of(&["/run"]),
            secret("/dev/shm/token", b"x"),
            LaunchIpcMode::Host,
        )
        .expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "an injected file under /dev/shm cannot be combined with --ipc=host"
        );
        // Private では /dev/shm の tmpfs と重なるため別の文言で拒否される。
        let err = LaunchOptions::new(
            set_of(&["/dev/shm"]),
            secret("/dev/shm/a/token", b"x"),
            LaunchIpcMode::Private,
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

    /// SEC-1: Debug に env の値が出ない(件数だけ)。
    #[test]
    fn sec1_debug_does_not_leak_env_values() {
        let o = LaunchOptions::new(
            set_of(&["/run"]),
            secret("/etc/token", b"x"),
            LaunchIpcMode::Host,
        )
        .expect("options")
        .with_env(vec!["API_KEY=ENVSECRETVALUE".to_string()])
        .expect("env");
        let text = format!("{o:?}");
        assert!(!text.contains("ENVSECRETVALUE"), "{text}");
        assert!(!text.contains("API_KEY"), "{text}");
        assert!(text.contains("env_count: 1"), "{text}");
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
