//! shim v2 の `TaskExecLauncher` の本番実装（CRI-5・CRI-1・SEC-1・SUP-6・PLUG-1・REPAIR-3・REPAIR-5・#4148・TASK-62.7）。
//!
//! 呼び出し元: shim の `TaskService`（cri の `shim_v2::task_service`）が `Start(exec_id)` で `ShimExecLauncher::launch` を呼び、
//! 返る `TaskExecProcess` を登録簿（`ExecRegistry`）が保持して `State` / `Kill` / `Wait` / `Delete`（`exec_id` つき）に使う。
//! 差し込み（`shim::registry_parts_in` から v2・v3 の `TaskService::with_exec_launcher`。停止時は登録簿の drop で `shutdown_all`）は
//! #4149 で済み、実機前提試験は #4150 の範囲で、本モジュールは部品と単体試験までを担う。cri に実装を置かず supervisor 依存も足さないのは PLUG-1 のため
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
//! - 登録時のインスタンス識別子 `expected_instance` を、pid を決めるのと同じ状態読み取りで `instance_matches` により照合し、
//!   不一致（値が違う・片側だけ `None`）は helper を起動せず `FAILED_PRECONDITION`（`MSG_EXEC_INSTANCE_CHANGED`）。照合は Running・pid の確認より前（#4323）。
//! - シグナルは SIGKILL（helper の kill）と、許可リスト（SIGHUP・SIGINT・SIGQUIT・SIGUSR1・SIGUSR2・SIGTERM。#4282）の `Signal` frame。init へは送らない。許可外は `UNIMPLEMENTED`。
//! - ハンドルの drop は helper を止めない（追跡一覧が強参照を持つ）。止めるのは `ShimExecLauncher::shutdown_all`・SIGKILL・期限切れ。
//! - 待ちはすべて有界（handover・`Started`・セッション + 余裕）。panic しない。エラー文は固定の英文で argv・ID・パスを含めない。
//!
//! # 未実装・簡易実装・残余（REPAIR-3）
//! - 消滅の確認（#4221 で実装）: kill した exec・期限切れの exec・`Started` の後に `Failed` になった exec は、いったん「未確認」
//!   （`status()` が `UNAVAILABLE` の "exec termination is not confirmed"）になり、本番の `CgroupExtinctionProbe` が `Started` で通知された
//!   exec 子 cgroup（stream-exec wire v2 で名前を運ぶ）の **不在** を読み取り専用で確かめられたときだけ `Exited`（コード無し）へ進む。
//!   Wait は未確認の間 `extinction_grace`（既定 10 秒）だけ刻みごとに確かめ、Delete は確認できた exec の登録だけ除去する。確認できない
//!   （材料が無い・照合に失敗・cgroup がまだ残る）間は fail-closed のまま `UNAVAILABLE` で、登録は purge まで残る。wire の版が合わない
//!   旧い supervisor とは `Started` に至らず launch が失敗する（exec は始まらず、確認済みとも扱わない）。残余: 名前は helper の pid と
//!   連番で、helper の回収後に別の helper が同じ名前を作りうる（probe は読むだけで kill しないため、起きるのは「まだある」と見える
//!   安全側の誤りだけ）。コンテナ内から cgroupfs に書けない前提（`exec::cgroup_join` の doc と同じ）に依存する。
//! - `pid()` は launch が `Spawned`（コマンドのホスト側 pid。#4316）を最長 `ExecBudgets::spawned` まで待つため通常は実 pid（#4318）。
//!   届かない経路（`Spawned` 無しの `Result`・予算切れ）は `None` で、Start 応答・TaskExecStarted・State の pid は 0 になる。
//!   計数（#4379・REPAIR-4）: 予算切れの回は `shim_exec_pid_unreported`、登録時のインスタンスとの不一致の拒否は
//!   `shim_exec_instance_changed` を共有記録器へ数える（`Spawned` 無しの終了・ほかの拒否は数えない）。発生ごとに `{"event":"<操作名>","elapsed_ms":N}` の JSON 1 行を
//!   stderr の有界 sink へ出す（満杯なら捨て、exec は待たない）。集計の書き出しは起動時の走査の後（回収 1 件以上）と serve の終了時（`shim::serve_end`。#4408）の 2 時点で、定期出力は #4228 の出力方式と合わせて後続。
//! - 許可リスト外のシグナル・env・cwd・user の受け入れは後続（許可リストの SIGKILL 以外は helper の `Signal` frame で対応済み。#4282）。

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
            _expected_instance: Option<u64>,
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
                .launch(&id, &exec, &spec, None)
                .err()
                .expect("err");
            assert_eq!(err.code(), CriErrorCode::Unimplemented);
            assert_eq!(err.message(), "exec is not supported on this platform");
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use unsupported::ShimExecLauncher;
