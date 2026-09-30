//! start が起動を委ねる境界（`ProcessLauncher`。TASK-29.3・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! `start.rs` の [`start`](super::start) は検証済みの [`LaunchSpec`] を組み立て、実際のプロセス起動を
//! [`ProcessLauncher`] へ委ねる。`ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、
//! create が `StateStore` を依存注入で受けるのと同様に、起動も依存注入とした。
//!
//! # 本番実装が未提供である理由（REPAIR-3: 実装済みを装わない）
//!
//! TASK-27 の exec フロー（`exec::spawn_container`）は「分離済み・シングルスレッド・使い捨て」の
//! 親プロセスを要求し、さらに制限ステージ（capability 削減・seccomp・Landlock。TASK-37〜39）の
//! 証跡が無い限り exec を拒否する（SEC-1・CORE-5）。任意の文脈から呼ばれる `start` はこれを
//! 保証できないため、fork した中間プロセスでの `isolate` → `spawn_container` と pid 返却・子の回収
//! を行う本番 launcher は後続 sub-issue（TASK-29 / TASK-157 系）で提供する。現時点で本 crate に
//! launcher 実装は無く、実プロセスの起動は行われない。

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::config::NamespaceKind;
use crate::traits::TraitError;

/// launcher へ渡す、検証済みの起動仕様。
///
/// 構築は `start` のみ（`pub(super)`）で、config パーサの上限（`CONFIG_MAX_*`）検証と
/// `validate_bundle` の rootfs 検査を通った値だけを持つ。`args` は 1 件以上・先頭は絶対パス。
/// シェルを介さず配列のまま渡すこと（インジェクション防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchSpec {
    rootfs: PathBuf,
    args: Vec<String>,
    env: Vec<String>,
    hostname: Option<String>,
    namespaces: Vec<NamespaceKind>,
}

impl LaunchSpec {
    pub(super) fn new(
        rootfs: PathBuf,
        args: Vec<String>,
        env: Vec<String>,
        hostname: Option<String>,
        namespaces: Vec<NamespaceKind>,
    ) -> Self {
        Self {
            rootfs,
            args,
            env,
            hostname,
            namespaces,
        }
    }

    /// 検査済みの rootfs の絶対パス。
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    /// `process.args`（そのまま。先頭は実行ファイルの絶対パス）。
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// `process.env`（`KEY=VALUE` 形式のままの文字列）。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// `hostname`（UTS namespace 内で設定する値）。
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// 新規作成する namespace（未対応の種別は `start` が拒否済み）。
    pub fn namespaces(&self) -> &[NamespaceKind] {
        &self.namespaces
    }
}

/// 起動済みプロセスへのハンドル。
pub trait LaunchedProcess: Send {
    /// 起動したコンテナプロセスの pid。
    fn pid(&self) -> NonZeroU32;

    /// 状態の記録に失敗したときの後始末として、プロセスを終了させる。
    ///
    /// 待ちには必ず上限時間 `timeout` を設け、超過時は `ErrorCode::Timeout` を返す（REPAIR-5）。
    fn terminate(&self, timeout: Duration) -> Result<(), TraitError>;
}

/// [`LaunchSpec`] からコンテナプロセスを起動する境界。
///
/// # 契約
///
/// - 起動確認（子からの通知待ち等）には必ず上限時間を設け、超過時は `ErrorCode::Timeout`（REPAIR-5）
/// - exec フローの fail-closed（制限証跡なしの exec 拒否。SEC-1・CORE-5）を回避しない
/// - 失敗時にプロセスを残さない
///
/// 本番実装は本 crate に未提供（モジュール doc 参照）。
pub trait ProcessLauncher: Send + Sync {
    /// プロセスを起動し、ハンドルを返す。
    fn launch(&self, spec: &LaunchSpec) -> Result<Box<dyn LaunchedProcess>, TraitError>;
}
