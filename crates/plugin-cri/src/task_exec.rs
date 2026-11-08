//! shim v2 の `TaskExecLauncher` の本番実装（CRI-5・CRI-1・SEC-1・SUP-6・PLUG-1・REPAIR-3・REPAIR-5・#4148・TASK-62.7）。
//!
//! 呼び出し元: shim の `TaskService`（cri の `shim_v2::task_service`）が `Start(exec_id)` で `ShimExecLauncher::launch` を呼び、
//! 返る `TaskExecProcess` を登録簿（`ExecRegistry`）が保持して `State` / `Kill` / `Wait` / `Delete`（`exec_id` つき）に使う。
//! 差し込み（`registry_in` から `TaskService::with_exec_launcher`）は #4149、実機前提試験は #4150 の範囲で、本モジュールは
//! 部品と単体試験までを担う。cri に実装を置かず supervisor 依存も足さないのは PLUG-1 のため
//! （設計は `docs/design/shim-v2-production-binary.md`「Exec の橋渡し」案 A）。
//!
//! # 方式
//! #3761 の stream-exec helper（`streaming::exec_launcher` の同期の中核: `HelperSpawner`・`HelperGuard`・`Shared`）を再利用する。
//! Exec ごとに supervisor を `stream-exec` で起動して単一スレッドの helper にし、stdio は 3 本とも `/dev/null`（mask 0）で、
//! `Started` を待ってから専用スレッドで `Result` を待つ。コマンドは helper が supervisor の既存の exec 入口（namespace・cgroup・
//! capability・NNP・Landlock・seccomp の段）を通して実行するため、本モジュールは分離を広げない（SEC-1）。
//!
//! # 契約
//! - env・cwd（`/` 以外）・user は黙って捨てず `UNIMPLEMENTED`（helper が受けないため）。`argv[0]` が絶対パスでなければ `INVALID_ARGUMENT`。
//! - 存在しないコンテナは `NOT_FOUND`、Running でない・pid が無いコンテナは `FAILED_PRECONDITION`、状態ストアの失敗は `UNAVAILABLE`。
//! - シグナルは SIGKILL だけ（helper の kill）。init へは送らない。SIGKILL 以外は `UNIMPLEMENTED`。
//! - ハンドルの drop は helper を止めない（追跡一覧が強参照を持つ）。止めるのは `ShimExecLauncher::shutdown_all`・SIGKILL・期限切れ。
//! - 待ちはすべて有界（handover・`Started`・セッション + 余裕）。panic しない。エラー文は固定の英文で argv・ID・パスを含めない。
//!
//! # 未実装・簡易実装・残余（REPAIR-3）
//! - 消滅の確認: kill した exec・期限切れの exec・`Started` の後に `Failed` になった exec は、exec 子 cgroup の回収を plugin-cri
//!   から観測できない（`ExecGuardPool` は supervisor の中。`Started` は payload 0 バイトで cgroup 名を運ばない）。そのため
//!   `Exited` にせず「未確認」（`status()` が `UNAVAILABLE` の "exec termination is not confirmed"）を保ち、Wait は失敗し Delete は
//!   除去を拒む（fail-closed）。確認の差し込み口は `ExecExtinctionProbe`。本番の `UnconfirmedExtinctionProbe` は常に `Unknown`
//!   で、supervisor 側の wire 拡張（`Started` へ cgroup 名を載せる等。8 バイトの payload を超えるため version 変更）が入るまでの暫定。
//!   帰結として、これらの登録はコンテナ削除の purge まで残り、コンテナあたりの exec の枠を消費する。
//! - `pid()` は `None`（helper がコマンドの pid を返さない）。State の pid は 0 になる。
//! - SIGKILL 以外のシグナル（helper の Signal frame）・env・cwd・user の受け入れは後続。

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::sync::Arc;

    use fandhe_container_core::traits::ContainerId;
    use fandhe_container_cri::error::CriError;
    use fandhe_container_cri::shim_v2::{
        ExecId, ExecProcessSpec, TaskExecLauncher, TaskExecProcess,
    };

    /// 非 Linux の起動役。exec は Linux の supervisor helper に依存するため常に `UNIMPLEMENTED`（REPAIR-3）。
    #[derive(Debug, Default)]
    pub struct ShimExecLauncher;

    impl ShimExecLauncher {
        /// 非対応の起動役を作る。
        pub fn unsupported() -> Self {
            Self
        }
    }

    impl TaskExecLauncher for ShimExecLauncher {
        fn launch(
            &self,
            _container: &ContainerId,
            _exec_id: &ExecId,
            _spec: &ExecProcessSpec,
        ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
            Err(CriError::unimplemented(
                "exec is not supported on this platform",
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use fandhe_container_cri::error::CriErrorCode;
        use fandhe_container_cri::shim_v2::exec::PROCESS_TYPE_URL;
        use fandhe_container_cri::shim_v2::task_api::Any;

        use super::*;

        /// CRI-5・REPAIR-3: 非 Linux の launch は `UNIMPLEMENTED`。
        #[test]
        fn cri5_4148_non_linux_launch_is_unimplemented() {
            let any = Any {
                type_url: PROCESS_TYPE_URL.into(),
                value: br#"{"cwd":"/","args":["/bin/true"]}"#.to_vec(),
            };
            let spec = fandhe_container_cri::shim_v2::exec::parse_process_spec(&any).expect("spec");
            let id = ContainerId::new("c1").expect("id");
            let exec = ExecId::new("e1").expect("exec id");
            let err = ShimExecLauncher::unsupported()
                .launch(&id, &exec, &spec)
                .err()
                .expect("err");
            assert_eq!(err.code(), CriErrorCode::Unimplemented);
            assert_eq!(err.message(), "exec is not supported on this platform");
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use unsupported::ShimExecLauncher;
