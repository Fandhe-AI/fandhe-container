//! supervisor の制御チャネル（コンテナごとの UDS。SUP-1・SEC-1・CORE-1・PLUG-12・REPAIR-2・REPAIR-5・
//! TASK-157 追補・#2058・SUP-9・#2162）。
//!
//! # なぜ存在するか
//!
//! `stop`・`kill` は `state.json` の pid へ生の `kill(2)` を送らない（pid 再利用で無関係なプロセスを止めない。
//! SEC-1・CORE-1）。送信できるのは、起動ハンドル（`LaunchedProcess`）を持つ supervisor だけで、CLI から
//! supervisor へ依頼を届ける経路が要る。常駐デーモンは持たない（CORE-1）ので、コンテナごとの supervisor が
//! 自分の UDS を開き、CLI が接続して依頼する。
//!
//! # 構成
//!
//! | モジュール | 役割 |
//! | ---------- | ---- |
//! | `protocol` | 固定長 frame（Hello・SignalRequest・StopRequest・CancelRestartRequest・ExecHandoverRequest・Response）と理由コード。全 OS |
//! | `target` | 起動ハンドルの包み（`ControlledProcess`）と共有状態（`SignalSlot`。exec 用に起動時 pidfd の複製も保持する）。全 OS |
//! | `listener` | 置き場所の検証・bind・削除（Linux） |
//! | `server` | accept ループ・接続元の検証・期限（Linux） |
//! | `client` | CLI が使う入口 `ControlSignaler`（core の `ProcessSignaler` を実装）と `ControlRestartCanceller`（非 Linux は `Unimplemented`）、Linux のみ `ControlExecHandover`（CLI の `exec` 用に起動時 pidfd の複製を `SCM_RIGHTS` で受け取る。#2626） |
//!
//! # exec 用 pidfd の受け渡し（SUP-6・SEC-1・#2626）
//!
//! CLI の `exec` は `run_command_with_pidfd` に起動時の pidfd を要する（記録 pid からの `pidfd_open` は pid 再利用に弱く、
//! 本番では使わない）。pidfd を持つのは supervisor の監視スレッドだけなので、ExecHandoverRequest（kind 6）で複製を
//! `SCM_RIGHTS` の fd 1 本として返す。`Active` で記録 pid が一致するときだけ渡し（拒否には fd を添えない）、複製は
//! `Exited`・`Empty` へ遷移したら落とす。受け取った CLI は fd を信用せず、`identify_pid1_with_pidfd` が記録 pid との
//! 一致を確かめる。信頼境界は他の要求と同じ（同じ uid・コンテナごとの 0600 のソケット・`SO_PEERCRED` の照合）。
//! 判断記録は `docs/design/exec-pidfd-handover.md`。
//!
//! # 寿命
//!
//! 作成は supervisor の入口（`start_entry`）が `Running` を受け取った直後、`run_supervised` の前。単一スレッドを
//! 要する launch（手順 8）より後なので制約に触れない。削除は `run_supervised` が返った後（RAII）。作成に
//! 失敗したら、停止できないコンテナを残さないよう停止を要求する（fail-closed）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - CLI の `kill` への結線（`stop` は `stop_delete::production_stop_signaler` で結線済み。#2059・#2162。`kill` は #1902 が
//!   `ControlSignaler::new`〔stop の意図を立てない kind 2〕を使う。`kill` が意図を立てるかは #1902 の判断）
//! - 明示 stop の意図は StopRequest（kind 4。稼働中）か CancelRestartRequest（kind 5。バックオフ・再 launch 中。#2440）が
//!   `StopToken::mark_explicit_stop` で立て、restart の判定が読む（SUP-9・#2162）。supervisor の寿命の中では `always`・
//!   `unless-stopped` を含む全ポリシーで、stop 後は再起動しない。明示 stop は `restart` ループが state.json の `Stopped` の記録へ
//!   「明示 stop 済み」（トレイト契約 14）として残す。記録に失敗したら再起動せず非 0 で終わる（fail-closed）。取り消しの `Ok` は
//!   「この supervisor は再起動しない」の意味で、記録の成否は応答に含まれない（失敗は supervisor のログと終了コードで見える）。
//!   終了から記録までの間に supervisor が死んだ場合も記録は残らず、その後の re-adopt では `unless-stopped` が起こし得る。
//!   re-adopt 本体（`restart::evaluate_resume` を呼ぶ側）は未実装（#514・SUP-8）
//! - restart の再 launch を単一スレッドで行う再構成（#2043）では、制御チャネルのスレッドも止める対象になる
//!   （停止の口は `ControlServer::shutdown` に用意済み）
//! - 異常終了で残った `supervisor.sock` は、core の `StateStore::delete`（`FileStateStore`）が `<id>/` を開いた fd を
//!   起点に種別（ソケット）と所有者（実効 UID）を検証してから消す（#2174・OCI-6・SUP-1）。ソケット以外・他 UID 所有の
//!   同名は消さず `<id>/` を残す。`purge_corrupted` は触れない
//! - `start` の OK 報告は制御チャネルの作成より前に送信済みのため、作成に失敗した場合は報告を取り消せない。
//!   停止を要求し、supervisor の終了コードを非 0 にして `Stopped` を記録する（報告の順序の再構成は別 issue）

pub mod client;
pub mod protocol;
pub mod target;

#[cfg(target_os = "linux")]
pub mod listener;
#[cfg(target_os = "linux")]
pub mod observe;
#[cfg(target_os = "linux")]
pub mod server;

#[cfg(target_os = "linux")]
pub use client::ControlExecHandover;
pub use client::{CancelOutcome, ControlRestartCanceller, ControlSignaler};

/// 状態ルートを公開しないストア用の fail-closed の signaler。常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// [`production_signaler`]・[`production_stop_signaler`] が `host_state_root()` の無いストアに対してだけ返す。
/// 送らないことで `state.json` の pid への縮退を防ぐ（SEC-1・CORE-1）。
pub struct UnavailableSignaler;

impl fandhe_container_core::oci_runtime::ProcessSignaler for UnavailableSignaler {
    fn signal(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _pid: std::num::NonZeroU32,
        _signal: fandhe_container_core::traits::Signal,
        _deadline: std::time::Instant,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "process signaler is not available yet",
        ))
    }
}

/// 本番の signaler（stop の意図を記録させない版。`kill` 用。#2059・#1902。CLI-1・SEC-1・CORE-1）。
///
/// CLI の `kill` 系の注入点と plugin-cri の `kill` が呼ぶ。`<host_state_root>/<id>/supervisor.sock` の supervisor へ依頼する
/// [`ControlSignaler`] を返し、到達できなければ構造化エラーで失敗する。`state.json` の pid へ `kill(2)` する縮退は持たない。
/// ルートに `host_state_root()` を使うのは、supervisor のログルートと揃い、cfg を呼び出し側に持ち込まないため。
/// supervisor の bind 側（`args.root`）との違いは親の symlink の解決だけで、`<root>/<id>` は同じディレクトリを指す。
pub fn production_signaler(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn fandhe_container_core::oci_runtime::ProcessSignaler> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlSignaler::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableSignaler),
    }
}

/// 本番の `stop` 用 signaler（SUP-9・#2162）。[`production_signaler`] と同じ到達先・縮退なしの規則だが、
/// `ControlSignaler::for_stop` で StopRequest を送り、supervisor に明示 stop の意図を記録させてから SIGTERM を渡す。
/// 意図を記録できない supervisor（書き先なし・古い版）には送らず、構造化エラーで失敗する（fail-closed）。
pub fn production_stop_signaler(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn fandhe_container_core::oci_runtime::ProcessSignaler> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlSignaler::for_stop(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableSignaler),
    }
}

/// バックオフ中・再 launch 中の stop で、supervisor の保留中の再起動を取り消す注入点（SUP-9・SUP-3・#2440）。
///
/// CLI の `stop`（`Stopped` の記録に対する分岐）が呼ぶ。本番は [`ControlRestartCanceller`]、CLI の試験は差し替える。
pub trait PendingRestartCanceller: Send + Sync {
    /// `deadline` までに取り消しを依頼し、結果を返す。シグナルは送らない。
    fn cancel(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        deadline: std::time::Instant,
    ) -> Result<CancelOutcome, fandhe_container_core::traits::TraitError>;
}

/// 状態ルートを公開しないストア用の fail-closed の canceller。常に `Unimplemented` で失敗する（REPAIR-3）。
pub struct UnavailableRestartCanceller;

impl PendingRestartCanceller for UnavailableRestartCanceller {
    fn cancel(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _deadline: std::time::Instant,
    ) -> Result<CancelOutcome, fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "restart canceller is not available yet",
        ))
    }
}

/// 本番の canceller（`stop` が `Stopped` の記録に当たったとき用。SUP-9・SUP-3・#2440）。
/// [`production_stop_signaler`] と同じ到達先の規則で、`host_state_root()` の無いストアには fail-closed の実装を返す。
pub fn production_restart_canceller(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn PendingRestartCanceller> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlRestartCanceller::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableRestartCanceller),
    }
}

/// 稼働中コンテナの起動時 pidfd の複製を取得する注入点（CLI の `exec` 用。SUP-6・SEC-1・CLI-1・#2626）。Linux のみ。
///
/// 本番は [`ControlExecHandover`]（supervisor の制御チャネルの ExecHandoverRequest）、CLI の試験は差し替える。
/// 取得した fd を信用しない: 呼び出し側が `exec::identify_pid1_with_pidfd`（`run_command_with_pidfd`）で記録 pid との一致を
/// 確かめる。`state.json` の pid からの `pidfd_open` への縮退は持たない（pid 再利用。SEC-1）。
#[cfg(target_os = "linux")]
pub trait ExecPidfdSource: Send + Sync {
    /// `deadline` までに、`pid`（記録上の pid1）の起動時 pidfd の複製を受け取る。supervisor に届かない・保持していない・
    /// pid 不一致・古い版の supervisor などは構造化エラー（fd は渡らない）。
    fn obtain(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        pid: std::num::NonZeroU32,
        deadline: std::time::Instant,
    ) -> Result<std::os::fd::OwnedFd, fandhe_container_core::traits::TraitError>;
}

/// 状態ルートを公開しないストア用の fail-closed の取得元。常に `Unimplemented` で失敗する（REPAIR-3）。
#[cfg(target_os = "linux")]
pub struct UnavailableExecPidfdSource;

#[cfg(target_os = "linux")]
impl ExecPidfdSource for UnavailableExecPidfdSource {
    fn obtain(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _pid: std::num::NonZeroU32,
        _deadline: std::time::Instant,
    ) -> Result<std::os::fd::OwnedFd, fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "exec pidfd source is not available yet",
        ))
    }
}

/// 本番の exec 用 pidfd 取得元。[`production_stop_signaler`] と同じ到達先の規則で、`host_state_root()` の無いストアには
/// fail-closed の実装を返す（縮退しない。SEC-1・CORE-1）。
#[cfg(target_os = "linux")]
pub fn production_exec_pidfd_source(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn ExecPidfdSource> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlExecHandover::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableExecPidfdSource),
    }
}

/// 構造化ログを stderr に 1 行出す（値は固定語彙だけ。入力値・uid・パス・errno は載せない。REPAIR-4）。
///
/// 待たない出力経路（`stderr_sink`）へ渡すだけで、キューが満杯なら捨てる（REPAIR-5）。
#[cfg(target_os = "linux")]
pub(crate) fn log_control_event(event: &'static str, reason: Option<&'static str>) {
    let reason = reason.unwrap_or("");
    let line =
        format!("{{\"component\":\"supervisor\",\"event\":\"{event}\",\"reason\":\"{reason}\"}}\n");
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

#[cfg(target_os = "linux")]
pub use install::{ControlHandle, install};

#[cfg(target_os = "linux")]
mod install {
    use std::path::Path;
    use std::sync::Arc;

    use fandhe_container_core::audit_log::AuditSink;
    use fandhe_container_core::oci_runtime::exit_code_for;
    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

    use super::listener::{ControlListener, effective_uid};
    use super::observe::ControlObserver;
    use super::server::{ControlServer, ServeConfig};
    use super::target::{ControlledProcess, ControlledRelauncher, SignalSlot};
    use crate::run::StopToken;
    use crate::start_entry::Running;

    /// 制御チャネルの後始末（`Drop` でサーバスレッドを止め、その後にソケットを消す）。
    ///
    /// フィールドの宣言順がそのまま drop 順で、サーバを先に止めてから listener の `Drop` が最終名を消す。
    /// 作成に失敗していたら [`Self::failure`] が構造化エラーを返す。
    #[must_use = "dropping the handle stops the control channel"]
    pub struct ControlHandle {
        _server: Option<ControlServer>,
        _listener: Option<ControlListener>,
        failure: Option<TraitError>,
    }

    impl ControlHandle {
        /// 作成の失敗（機械可読な code と message。入力値を含まない）。成功なら `None`。
        pub fn failure(&self) -> Option<&TraitError> {
            self.failure.as_ref()
        }

        /// `run_supervised` の終了コードへ作成の失敗を反映する（失敗していて `code` が 0 なら非 0 にする）。
        ///
        /// 失敗時は停止を要求済みで、回収に成功すると `run_supervised` は 0 を返す。それを正常終了として
        /// 報告しない（SUP-1・REPAIR-4）。
        pub fn exit_code(&self, code: u8) -> u8 {
            match (&self.failure, code) {
                (Some(e), 0) => exit_code_for(e.code()).get(),
                _ => code,
            }
        }
    }

    fn failed_handle(error: TraitError) -> ControlHandle {
        // 機械可読な固定語彙の 1 行（code は列挙名。message は固定文言）。
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"control_channel_failed\",\"code\":\"{}\",\"message\":\"{}\"}}\n",
            error.code().as_str(),
            error.message()
        );
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
        ControlHandle {
            _server: None,
            _listener: None,
            failure: Some(error),
        }
    }

    /// `running` の起動ハンドルと relauncher を制御チャネルに結線し、サーバを起動する。
    ///
    /// bind・サーバスレッドの生成に失敗したら、構造化エラーを [`ControlHandle::failure`] に載せ、`stop` に
    /// 停止を要求する（停止できないコンテナを残さない。fail-closed）。呼び出し元は `run_supervised` の前に呼び、
    /// 返った [`ControlHandle`] を `run_supervised` が返るまで保持し、終了コードを [`ControlHandle::exit_code`]
    /// に通す。`audit` は認証境界の拒否（別 uid 等）の記録先（SEC-4）。
    pub fn install(
        state_root: &Path,
        id: &ContainerId,
        running: Running,
        stop: &StopToken,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> (Running, ControlHandle) {
        let bound = effective_uid()
            .and_then(|uid| ControlListener::bind_as(state_root, id, uid).map(|l| (uid, l)));
        let (uid, listener) = match bound {
            Ok(v) => v,
            Err(e) => {
                stop.request_stop();
                return (running, failed_handle(e));
            }
        };
        let slot = SignalSlot::with_stop_intent(stop.clone());
        let Running {
            process,
            relauncher,
            instance,
            logs,
            seccomp,
        } = running;
        let running = Running {
            process: Box::new(ControlledProcess::new(process, slot.clone())),
            relauncher: Arc::new(ControlledRelauncher::new(relauncher, slot.clone())),
            instance,
            logs,
            seccomp,
        };
        let observer = Arc::new(ControlObserver::new(audit, Some(id.clone())));
        let server = listener
            .try_clone_listener()
            .and_then(|l| ControlServer::spawn(l, slot, uid, ServeConfig::default(), observer));
        match server {
            Ok(s) => (
                running,
                ControlHandle {
                    _server: Some(s),
                    _listener: Some(listener),
                    failure: None,
                },
            ),
            Err(_) => {
                stop.request_stop();
                let mut handle = failed_handle(TraitError::new(
                    ErrorCode::Internal,
                    "failed to start the control channel server",
                ));
                handle._listener = Some(listener);
                (running, handle)
            }
        }
    }
}
