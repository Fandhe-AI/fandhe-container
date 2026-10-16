//! supervisor の制御チャネル（コンテナごとの UDS。SUP-1・SEC-1・CORE-1・PLUG-12・REPAIR-2・REPAIR-5・
//! TASK-157 追補・#2058）。
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
//! | `protocol` | 固定長 frame（Hello・SignalRequest・Response）と理由コード。全 OS |
//! | `target` | 起動ハンドルの包み（`ControlledProcess`）と共有状態（`SignalSlot`）。全 OS |
//! | `listener` | 置き場所の検証・bind・削除（Linux） |
//! | `server` | accept ループ・接続元の検証・期限（Linux） |
//! | `client` | CLI が使う入口 `ControlSignaler`（core の `ProcessSignaler` を実装。非 Linux は `Unimplemented`） |
//!
//! # 寿命
//!
//! 作成は supervisor の入口（`start_entry`）が `Running` を受け取った直後、`run_supervised` の前。単一スレッドを
//! 要する launch（手順 8）より後なので制約に触れない。削除は `run_supervised` が返った後（RAII）。作成に
//! 失敗したら、停止できないコンテナを残さないよう停止を要求する（fail-closed）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - CLI の `stop`・`kill` への結線（`UnavailableSignaler` から `ControlSignaler` への差し替え。#1544 の段 C・#1902）
//! - 明示的な stop の意図の伝達（SUP-9・#1545）: CLI の stop による SIGTERM の終了は、今は通常の終了として
//!   restart ポリシーの評価に入る。protocol の kind を拡張して `StopToken` を立てる op を足すのは別 issue
//! - restart の再 launch を単一スレッドで行う再構成（#2043）では、制御チャネルのスレッドも止める対象になる
//!   （停止の口は `ControlServer::shutdown` に用意済み）
//! - 異常終了で残った `supervisor.sock` のために、core の `delete` が `<id>/` を残す件（core 側で掃除対象に加えるかは
//!   別 issue で判断する）
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

pub use client::ControlSignaler;

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
        let slot = SignalSlot::new();
        let Running {
            process,
            relauncher,
            instance,
            logs,
        } = running;
        let running = Running {
            process: Box::new(ControlledProcess::new(process, slot.clone())),
            relauncher: Arc::new(ControlledRelauncher::new(relauncher, slot.clone())),
            instance,
            logs,
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
