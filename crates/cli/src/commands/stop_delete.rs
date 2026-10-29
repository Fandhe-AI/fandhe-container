//! `stop` / `delete` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.2・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_stop`] / [`run_delete`] を呼ぶ。実処理は core の
//! `oci_runtime::kill` / `oci_runtime::delete`（OCI-6・CORE-2・TASK-30）へ委ね、ID の文字種検証も
//! core の型（`ContainerId`）を唯一の判定とする。状態ルートの解決・状態ストアの組み立ては
//! `create_start::production_runtime` を共用する。
//!
//! 設計判断（fail-closed）:
//! - `stop` は core の `kill` に写像する。シグナルは既定 `SIGTERM`、`--signal <名前|番号>`(Docker の表記。core の
//!   `Signal::parse_notation` で解釈。CRI と共有する語彙。不正値・範囲外は `INVALID_ARGUMENT`。CLI-1・ERR-1・#2775)で
//!   上書きできる。core に stop（猶予 → SIGKILL）は無い(#1545)。残余(REPAIR-3): `SIGSTOP`・`SIGCONT`・`SIGCHLD`・`SIGWINCH`
//!   など終了させないシグナルでも明示 stop の意図は記録され、後の自然終了で再起動されない。
//! - 本番の [`ProcessSignaler`] は [`production_stop_signaler`] が返す supervisor の `ControlSignaler`
//!   （`<state_root>/<id>/supervisor.sock` の制御チャネル。#2059）で、supervisor が保持する起動ハンドルへ
//!   シグナルを渡す。supervisor に届かない・期限切れ・接続元の検証で拒否・pid 不一致のときは ERR-2 の構造化エラー
//!   （UNAVAILABLE・TIMEOUT・PERMISSION_DENIED・FAILED_PRECONDITION）で失敗する。`state.json` の pid へ生の
//!   `kill(2)` は送らない（PID 再利用で無関係なプロセスを止めない。縮退しない。SEC-1・CORE-1）。
//! - `delete` の cgroup 削除は Linux では `DetectedCgroupRemover`（`cgroups::DelegatedCgroup` の遅延検出。
//!   #1314 の 3-ii）が担う。cgroup 配置が記録されたレコードに出会った場合だけ検出し、検出の失敗・削除の失敗は
//!   cgroup も状態記録も残したまま構造化エラーで失敗する（fail-closed。OCI-6・CORE-3・SEC-1）。検出したスコープと
//!   記録のスコープが食い違う場合は、#2060 のオーナー決定（2026-10-16・案 B。#1314 の 3-ii の delete の行を変更）
//!   により、core の `delete` が記録された配置を `remove_recorded` へ渡し、`cgroups::RecordedCgroupScope`
//!   が記録のスコープを fd 起点で検証つきに開いてコンテナ cgroup を消す（#2096）。検証に失敗すれば何も消さず
//!   記録を残す。非 Linux では `UnavailableCgroupRemover` が `Unimplemented` で失敗する。
//!
//! `delete` は core の delete が成功したとき、`DeleteResponse::image_rootfs` が `Kept { code }`（core が作ったイメージ由来
//! rootfs を消せずに残した。OCI-7・#2633）なら、`code` / `message` の 1 行 JSON の警告を stderr に出す（終了コードは 0 のまま。
//! bundle のパス・errno は含めない）。消せた・既に無かった・記録が無いときの stderr は空。
//!
//! `delete` は core の delete が成功した後に、supervisor の構造化ログ（`<root>/@supervisor-logs/<id>.log*`）を best effort で
//! 消す（`remove_supervisor_log`。失敗は握り、成功時の stderr は空のまま。#2067・REPAIR-4・ERR-2）。
//!
//! 続けてコンテナログ（`<root>/@container-logs/<id>.log*`・ロックファイル）も消す（`remove_container_log`。#2446・SUP-7・CLI-1）。
//! 消せなかった（supervisor 生存中でロックが取れない・期限切れ等）ときも delete は成功のまま（状態は削除済みで、再試行は
//! `NOT_FOUND` になり回復できないため。残りは 1 ID あたり世代数 × 上限に収まり、次の start で世代として回る）、
//! `code` / `message` の 1 行 JSON の警告を stderr に出す。消せたとき（0 件を含む）の stderr は空（ERR-2）。
//! 削除は supervisor ログ → コンテナログの直列。どちらも `stop` 直後の閉鎖の窓（supervisor の drain とプロセス終了）を
//! `FailedPrecondition` の間だけ待つが、待ちの期限（`CONTAINER_LOG_LOCK_WAIT` の 10 秒）は 2 つのログで共有する。
//! 1 回の試行は 5 秒が上限で、最悪 10 + 5 + 5 = 20 秒（#2698・#2892・REPAIR-5）。
//! 結果は `DeleteResponse` の `supervisor_log` / `container_log` 欄に載せ、警告は欄の `kept()` から出す（#2698・#2633）。
//! 窓を超えて残ったログは、同じ ID の `create` が core を呼ぶ前に回収する（`create_start::reclaim_stale_container_log`）。
//! ID を再利用しない場合の残りは手動で消す（`docs/setup/container-log-recovery.md`）。
//!
//! 状態ルートが無ければ `production_runtime` の状態ストアを開く段階で親の下に 0700 で作る（親は作らない）。
//! list / logs と同じ判断で、読み取り専用 open は足さない（理由は `list_logs` の module doc。#1607 E2）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - `delete` は core の `delete_releasing_image_ref` で OCI-7 のイメージ参照を外す（#2315）。ストアは create が状態記録の
//!   annotations（`io.fandhe.container.image-root`）に残した root を使い、`--image-root` は任意（#2499。判断表は
//!   [`delete_with_recorded_image_root`]）。ストアは core に入る前に開き、開けない・記録と食い違うときは状態を消さずに失敗する。
//!   記録の root を消したり移したりしたコンテナは delete できない。元のパスにストアを戻すか、同じパスに空の 0700 ディレクトリを
//!   作れば delete は通る（参照が無ければ解除は空振り）。逃げ道（`--force` 等）の要否は未決。解除に失敗した場合は
//!   `DeleteResponse::image_ref` の `Kept` と stderr の警告で伝え、終了コードは 0 のまま。照合（#2495）は、記録を持たない
//!   古いコンテナや core 到達後に失敗した解除の残りを後追いで回収する役（同じ ID の `create --image-root` の core 呼び出し前、
//!   または `image rm` が使用中で拒否したとき。`ref_reconcile` の module doc）。
//! - stop の失敗 JSON の `op` は `kill` になる（core に `LifecycleOp::Stop` が無いため。core 到達前の失敗も
//!   `kill` に揃える）。猶予待ち → SIGKILL・Stopped への遷移確認は TASK-157 の範囲。
//! - stop の SIGTERM は意図つき（StopRequest）で送る。supervisor は意図を記録してから送るので、stop による終了は
//!   `always`・`on-failure`・`unless-stopped` でも再起動されない（SUP-9・SUP-3・#2162）。意図を記録できない supervisor
//!   （書き先なし・古い版）にはシグナルを送らず、構造化エラーで失敗する（fail-closed）。「明示 stop 済み」は supervisor が
//!   state.json の `Stopped` の記録へ残す（#2440・トレイト契約 14）。
//! - 記録が `Stopped` のとき（終了を検知した後のバックオフ・再 launch 中かもしれない）は、[`stop_or_cancel_restart`] が
//!   core の `kill`（`Stopped` を `FailedPrecondition` で拒否する）の前に、supervisor の制御チャネルへ保留中の再起動の取り消しを
//!   依頼する（#2440・SUP-9・SUP-3）。取り消せたら成功。届く supervisor が無ければ従来どおり core の `kill` に任せて
//!   `container is not running` で失敗する。取り消しの時点で新しいプロセスが動いていたら、期限内に記録を読み直して通常の stop を
//!   やり直す。
//! - stop の猶予後の SIGKILL と Stopped への遷移確認（#1545。同じ stop 用 signaler を使う。意図は一度立てば残るので 2 回目は
//!   無害）は未実装。
//! - `kill <id> [<signal>]`（#1902・CLI-1）はシグナルを 1 回送るだけで、終了を待たず状態も変えない（OCI Runtime の `kill` と同じ）。
//!   core の `kill` を [`production_signaler`]（`ControlSignaler::new`・kind 2）で呼び、`stop` と違って明示 stop の意図は立てない
//!   （`stop_or_cancel_restart` の分岐も通らない）。記録が `Stopped` なら core の規則どおり `FAILED_PRECONDITION` になる。
//!   シグナルの語彙は `stop --signal`（Docker の語彙）と異なり spec の CLI-1 の固定表（`kill_signal` module）。
//!   残余: moby の `kill` は SIGKILL か StopSignal と一致するとき再起動を止めるが、本実装は止めない
//!   （`always`・`unless-stopped`・`on-failure` では `kill <id> KILL` の後に再起動されうる）。Docker 互換にするかはオーナー判断待ち。
//! - `delete` が最初に照合する委譲スコープは CLI 自身の cgroup から検出したもの。start 時に supervisor が記録した
//!   スコープと一致すれば従来の経路、食い違えば記録のスコープを直接開く経路（#2096）で消す。検出自体の失敗は
//!   記録の経路へ回さず失敗させる（壊れた環境で使わない安全側の判断）。#2133 で再検討し、挙動を変えず維持した:
//!   検出の失敗まで記録の経路へ回すには core の `delete` の契約（`scope()?`）を変える必要があり、#2060 のオーナー決定
//!   （案 B）は「検出は成功したがスコープが食い違う」場合だけを対象にしている。技術的には `remove_recorded` は
//!   `RecordedCgroupScope::open` が委譲（所有者・`cgroup.type`）を独立に検証し直すため、検出の失敗を回しても検証が抜ける
//!   わけではない。なお、通常のログインセッション（SSH・TTY ログイン。`session-N.scope` が root 所有）から `delete` すると
//!   検出が失敗し、cgroup の配置を記録したコンテナは消せない（`doctor` の `CGROUP_NOT_DELEGATED` で事前に確かめられる。#2158）。回避策は委譲されたスコープの中で実行すること
//!   （`systemd-run --user --scope -p Delegate=yes -- fandhe-container delete <id>`。検出が成功し、スコープの不一致から
//!   記録の経路へ入る）。検出の失敗を記録の経路へ回すかはオーナー判断待ち（core の契約の変更になる）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。非 Linux では `production_runtime` が
//!   `plugin_backend` を呼び、現状は必ず fail-closed で失敗する（起動と RPC は #1869 の設計〔docs/design/plugin-backend-wiring.md。承認と実装 issue の起票は #2232〕・TASK-125）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    ContainerCgroupRemover, KillTimeout, LifecycleOp, OciRuntimeError, ProcessSignaler, delete,
    delete_releasing_image_ref, kill,
};
use fandhe_container_core::traits::{
    CleanupOutcome, CleanupTarget, ContainerId, ContainerState, ContainerStatus, DeleteRequest,
    DeleteResponse, ErrorCode, GetStateRequest, KillRequest, Signal, StateStore, TraitError,
};
// 試験が `use super::*` 経由で使う型（本番の経路では使わない）。
#[cfg(all(test, target_os = "linux"))]
use fandhe_container_core::oci_runtime::CgroupRemoval;
#[cfg(test)]
use fandhe_container_core::traits::{CgroupPlacement, CgroupScope, StateRevision};

use super::CliExit;
use super::args::{DeleteArgs, GlobalArgs, KillArgs, StopArgs};
use super::create_start::{
    OP_LOG_ENV, export_ops, production_runtime, record_pre_core_failure, require_local_backend,
};
use super::image::open_image_store_for_lifecycle;
use super::image_refs::{
    IMAGE_ROOT_ANNOTATION, StoreImageRefs, fail, legacy_scope, ref_key, state_scope,
};
use super::kill_signal::parse_kill_signal;
use fandhe_container_oci::image_management::{ContainerRefId, ContainerRefRelease, ImageStore};

// 本番の signaler・cgroup remover は supervisor crate にある（plugin-cri の `kill`・`stop`・`delete` と共有するため
// CLI の private 実装から移した。#2434・REPAIR-1）。`production_signaler` は `kill` コマンド（#1902）が使う。
#[cfg(all(test, not(target_os = "linux")))]
use fandhe_container_supervisor::cgroup_remover::UnavailableCgroupRemover;
use fandhe_container_supervisor::cgroup_remover::production_cgroup_remover;
#[cfg(all(test, target_os = "linux"))]
use fandhe_container_supervisor::cgroup_remover::{DetectedCgroupRemover, detect_error};
#[cfg(test)]
use fandhe_container_supervisor::control::UnavailableSignaler;
use fandhe_container_supervisor::control::{
    CancelOutcome, PendingRestartCanceller, production_restart_canceller, production_signaler,
    production_stop_signaler,
};
use fandhe_container_supervisor::logs::{CONTAINER_LOG_LOCK_WAIT, CONTAINER_LOG_REMOVE_TIMEOUT};
use fandhe_container_supervisor::supervisor_log::{
    SUPERVISOR_LOG_REMOVE_TIMEOUT, run_log_removal_bounded,
};

/// ID とシグナルを core の型で検証し、kill 要求を作る(`--signal` 未指定は `SIGTERM`)。
///
/// シグナルの解釈は core の `Signal::parse_notation`(CRI と共有する語彙)に委ね、不正値は `INVALID_ARGUMENT`
/// (固定文言・値を含めない)。状態ルートを開く前に終わるので、非 Linux でも同じ結果になる。
fn build_stop_request(args: &StopArgs) -> Result<KillRequest, TraitError> {
    let signal = match args.signal.as_deref() {
        Some(text) => Signal::parse_notation(text)?,
        None => Signal::SIGTERM,
    };
    Ok(KillRequest::new(
        ContainerId::new(args.id.as_str())?,
        signal,
    ))
}

/// ID とシグナルを検証し、`kill` の要求を作る（`<signal>` 省略は `SIGTERM`。CLI-1・#1902）。
///
/// シグナルは `kill_signal::parse_kill_signal`（spec の固定表）で解釈し、不正値は固定文言の `INVALID_ARGUMENT`。
/// 状態ルートを開く前に終わるので、非 Linux でも同じ結果になる。
fn build_kill_request(args: &KillArgs) -> Result<KillRequest, TraitError> {
    let signal = match args.signal.as_deref() {
        Some(text) => parse_kill_signal(text)?,
        None => Signal::SIGTERM,
    };
    Ok(KillRequest::new(
        ContainerId::new(args.id.as_str())?,
        signal,
    ))
}

fn build_delete_request(args: &DeleteArgs) -> Result<DeleteRequest, TraitError> {
    Ok(DeleteRequest::new(ContainerId::new(args.id.as_str())?).with_force(args.force))
}

/// 構築済みの要求で core の `kill` を呼ぶ（テストで signaler を差し替える入口）。
pub(super) fn stop_container(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    signaler: &Arc<dyn ProcessSignaler>,
    req: &KillRequest,
    timeout: &KillTimeout,
) -> Result<ContainerStatus, OciRuntimeError> {
    kill(store, recorder, signaler, req, timeout)
}

/// `stop` の本体。記録が `Stopped` なら保留中の再起動の取り消しを試し、それ以外は core の `kill`（SIGTERM）へ進む
/// （SUP-9・SUP-3・#2440。モジュール doc 参照）。op は従来どおり `kill` で記録する（取り消しの経路も含む）。
pub(super) fn stop_or_cancel_restart(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    signaler: &Arc<dyn ProcessSignaler>,
    canceller: &dyn PendingRestartCanceller,
    req: &KillRequest,
    timeout: &KillTimeout,
) -> Result<(), OciRuntimeError> {
    let stopped = store
        .get(&GetStateRequest::new(req.id().clone()))
        .is_ok_and(|rec| rec.status().state() == ContainerState::Stopped);
    if !stopped {
        return stop_container(store, recorder, signaler, req, timeout).map(drop);
    }
    let started = Instant::now();
    let deadline = started + timeout.get();
    match cancel_until(store, canceller, req.id(), deadline) {
        // 取り消せた、または取り消しの試行自体が失敗した: ここで終わる。op `kill` として記録する。
        Ok(CancelFlow::Cancelled) => {
            record_kill(recorder, true, started);
            Ok(())
        }
        Err(e) => {
            record_kill(recorder, false, started);
            Err(OciRuntimeError::from_trait_error(LifecycleOp::Kill, e))
        }
        // 届く supervisor が無い、または新しいプロセスが動いている: 通常の stop（従来の挙動と失敗）へ。
        Ok(CancelFlow::Fallback) => {
            stop_container(store, recorder, signaler, req, timeout).map(drop)
        }
    }
}

/// 取り消しの試行の結果。
enum CancelFlow {
    /// 保留中の再起動を取り消した。
    Cancelled,
    /// 取り消せない（届く supervisor が無い・記録が `Stopped` でなくなった）。通常の `kill` へ進む。
    Fallback,
}

/// op `kill` の結果を記録する（記録できなくても stop の結果は変えない）。
fn record_kill(recorder: &OpRecorder, success: bool, started: Instant) {
    if let Ok(name) = OpName::new("kill") {
        let outcome = if success {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
}

/// 記録が `Stopped` の間、`deadline` まで取り消しを依頼する。
///
/// 取り消しの時点で新しいプロセスが動いていた（`ContainerRunning`）ときは、記録を読み直して様子を見る:
/// `Running` なら通常の stop に任せ（`Fallback`）、また `Stopped` ならもう一度取り消す。期限に達したら `Timeout`。
fn cancel_until(
    store: &dyn StateStore,
    canceller: &dyn PendingRestartCanceller,
    id: &ContainerId,
    deadline: Instant,
) -> Result<CancelFlow, TraitError> {
    loop {
        match canceller.cancel(id, deadline)? {
            CancelOutcome::Cancelled => return Ok(CancelFlow::Cancelled),
            CancelOutcome::ContainerRunning => {
                let rec = store.get(&GetStateRequest::new(id.clone()))?;
                if rec.status().state() != ContainerState::Stopped {
                    return Ok(CancelFlow::Fallback);
                }
                if Instant::now() >= deadline {
                    return Err(TraitError::new(
                        ErrorCode::Timeout,
                        "the restart cancellation did not complete within the timeout",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return Ok(CancelFlow::Fallback),
        }
    }
}

/// 構築済みの要求で core の `delete` を呼ぶ。
pub(super) fn delete_container(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
) -> Result<DeleteResponse, OciRuntimeError> {
    delete(store, recorder, cgroups, req)
}

/// [`delete_container`] に、OCI-7 のイメージ参照の解除を後置したもの（#2315）。
///
/// 解除の失敗は戻り値に影響させず、core が操作名 `image_ref_release` で記録する。
pub(super) fn delete_container_releasing_image_ref(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    images: &ImageStore,
    scope: &str,
    req: &DeleteRequest,
) -> Result<DeleteResponse, OciRuntimeError> {
    let refs = StoreImageRefs::new(images, scope);
    delete_releasing_image_ref(store, recorder, cgroups, &refs, req)
}

/// 本番入口の `stop`。成功時は何も出力しない（OCI の kill 互換）。
pub(super) fn run_stop(global: &GlobalArgs, args: &StopArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "kill", started, || {
        build_stop_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Kill, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let signaler = production_stop_signaler(rt.store.as_ref());
    let canceller = production_restart_canceller(rt.store.as_ref());
    let result = stop_or_cancel_restart(
        rt.store.as_ref(),
        &rt.recorder,
        &signaler,
        canceller.as_ref(),
        &req,
        &KillTimeout::default(),
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `kill`（CLI-1・#1902）。成功時は何も出力しない。意図は立てず、猶予待ちも再起動の取り消しもしない。
pub(super) fn run_kill(global: &GlobalArgs, args: &KillArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "kill", started, || {
        build_kill_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Kill, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let signaler = production_signaler(rt.store.as_ref());
    let result = stop_container(
        rt.store.as_ref(),
        &rt.recorder,
        &signaler,
        &req,
        &KillTimeout::default(),
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `delete`。成功時は何も出力しない（OCI の delete 互換）。
pub(super) fn run_delete(global: &GlobalArgs, args: &DeleteArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "delete", started, || {
        // ストアを開けなければ core に入る前に失敗させ、状態だけが消えて参照を外す手段を失う経路を作らない（fail-closed）。
        let req = build_delete_request(args)?;
        let images = args
            .image_root
            .as_deref()
            .map(|root| {
                // 非 Linux はローカルストアを開かず、バックエンド（plugin）解決の拒否へそのまま渡す（OCI-7・CLI-1）。
                require_local_backend(global)?;
                open_image_store_for_lifecycle(root)
            })
            .transpose()?;
        Ok((req, images))
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Delete, e));
    let (rt, (req, images)) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let remover = production_cgroup_remover();
    let legacy = state_scope(rt.store.as_ref())
        .ok()
        .and_then(|cur| legacy_scope(global.root.clone(), &cur));
    let result = delete_with_recorded_image_root(
        rt.store.as_ref(),
        &rt.recorder,
        &remover,
        images.as_ref(),
        legacy.as_deref(),
        &req,
        started,
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(resp) => {
            let resp = finish_delete(rt.store.as_ref(), &req, resp, CONTAINER_LOG_LOCK_WAIT);
            for warning in cleanup_warnings(&resp) {
                emit_warning_bounded(warning, write_warning_to_stderr, WARNING_WRITE_TIMEOUT);
            }
            remove_container_options(rt.store.as_ref(), &req);
            remove_etc_files_after_delete(rt.store.as_ref(), &req);
            remove_pasta_leftovers_after_delete(rt.store.as_ref(), &req);
            CliExit::Success
        }
        Err(e) => CliExit::Runtime(e),
    }
}

const MSG_IMAGE_ROOT_MISMATCH: &str = "image root does not match the image root recorded at create";
const MSG_RECORDED_IMAGE_ROOT_INVALID: &str = "the recorded image root is invalid";

/// create 時に記録したイメージストア root（[`IMAGE_ROOT_ANNOTATION`]）と `--image-root` から、解除に使うストアを決めて
/// delete する（#2499・OCI-7・OCI-5・CLI-1）。
///
/// 判断表（`get` で読んだ記録の有無 × `explicit`）:
/// - 記録あり・`explicit` なし: 記録の root を `ImageStore::open`（所有者・権限・祖先・symlink の検査）で開き、開いた `root()` が
///   記録と一致すれば解除つきで delete する。開けない・食い違う・絶対パスでないときは core に入らず失敗し、状態も参照も残す。
/// - 記録あり・`explicit` あり: `explicit.root()` が記録と一致すれば解除つき、違えば `FAILED_PRECONDITION`（状態も参照も残す）。
/// - 記録なし・`explicit` あり: 従来どおり `explicit` で解除つき（記録を持たない古いコンテナとの互換）。
/// - 記録なし（`get` が NOT_FOUND）・`explicit` なし: 従来どおり通常の delete（core が同じ NOT_FOUND を返す）。
/// - `get` がそれ以外で失敗: 状態も参照も残して core に入る前に失敗する（REPAIR-4）。
///
/// 記録の値は信頼しない入力として扱う。`get` から core の delete までの間に別の delete と同じ ID の再 create が
/// 割り込むと新しいコンテナの参照が残りうるが、余分に持つ安全側で、次の同じ ID の create（契機 A）が回収する。
/// 参照の解除結果は `DeleteResponse::image_ref` に載る（失敗は `Kept` で、警告になる）。
/// 判断で core に入る前に失敗した場合は `delete` の失敗として 1 回記録する（REPAIR-4）。`started` はその所要時間の起点。
pub(super) fn delete_with_recorded_image_root(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    explicit: Option<&ImageStore>,
    legacy_scope: Option<&str>,
    req: &DeleteRequest,
    started: Instant,
) -> Result<DeleteResponse, OciRuntimeError> {
    // 記録が無い（NOT_FOUND）ときだけ「記録なし」として core に任せる。ロック競合の Timeout 等の読み取り失敗を
    // 「記録なし」に畳むと、参照を解除せず状態だけを消してしまうため、core に入る前に失敗させる（OCI-7・REPAIR-4）。
    let recorded = match store.get(&GetStateRequest::new(req.id().clone())) {
        Ok(r) => r
            .annotations()
            .get(IMAGE_ROOT_ANNOTATION)
            .map(str::to_owned),
        Err(e) if e.code() == ErrorCode::NotFound => None,
        Err(e) => return Err(pre_core_delete_failure(recorder, started, e)),
    };
    let opened;
    let images = match decide_release_store(recorded.as_deref(), explicit) {
        Ok(ReleaseStore::Explicit(i)) => Some(i),
        Ok(ReleaseStore::Open(root)) => match open_image_store_for_lifecycle(&root) {
            Ok(i) if i.root() == root.as_path() => {
                opened = i;
                Some(&opened)
            }
            Ok(_) => {
                return Err(pre_core_delete_failure(
                    recorder,
                    started,
                    TraitError::new(ErrorCode::FailedPrecondition, MSG_IMAGE_ROOT_MISMATCH),
                ));
            }
            Err(e) => return Err(pre_core_delete_failure(recorder, started, e)),
        },
        Ok(ReleaseStore::None) => None,
        Err(e) => return Err(pre_core_delete_failure(recorder, started, e)),
    };
    match images {
        Some(images) => {
            let scope = match state_scope(store) {
                Ok(s) => s,
                Err(e) => return Err(pre_core_delete_failure(recorder, started, e)),
            };
            let result =
                delete_container_releasing_image_ref(store, recorder, cgroups, images, &scope, req);
            // 旧 scope のキーで残った参照も外す（旧版で作ったコンテナの互換。コンテナは消えた後なので無条件に外してよく、
            // 旧 scope のキーは新規に作られない）。結果は応答へ反映し、失敗は `Kept` として警告と計測に渡す（REPAIR-4）。
            match (result, legacy_scope) {
                (Ok(resp), Some(legacy)) => {
                    let merged = merge_legacy_outcome(
                        resp.image_ref(),
                        release_legacy_ref(images, recorder, legacy, req.id()),
                    );
                    Ok(resp.with_image_ref(merged))
                }
                (result, _) => result,
            }
        }
        None => delete_container(store, recorder, cgroups, req),
    }
}

/// 旧 scope の解除を記録する操作名（core の `image_ref_release` と同じ）。
const LEGACY_REF_RELEASE_OP_NAME: &str = "image_ref_release";

/// 旧 scope の参照キー 1 件を外した結果（#2499・OCI-7・REPAIR-4）。
///
/// core の現行 scope の解除と同じ操作名 `image_ref_release` で、成否と所要時間を `recorder` に記録する
/// （旧 scope にだけ参照が残る場合、core の解除は `AlreadyAbsent` で終わるため、この経路の失敗は
/// ここで計測しないと観測できない）。キーを作れない失敗も 1 回の失敗として記録する。
fn release_legacy_ref(
    images: &ImageStore,
    recorder: &OpRecorder,
    legacy_scope: &str,
    id: &ContainerId,
) -> CleanupOutcome {
    let started = Instant::now();
    let name = OpName::new(LEGACY_REF_RELEASE_OP_NAME).ok();
    let record = |ok: bool| {
        if let Some(name) = &name {
            let outcome = if ok {
                OpOutcome::Success
            } else {
                OpOutcome::Failure
            };
            let _ = recorder.record(name, outcome, started.elapsed());
        }
    };
    let key = match ContainerRefId::new(&ref_key(legacy_scope, id.as_str())) {
        Ok(k) => k,
        Err(_) => {
            record(false);
            return CleanupOutcome::Kept {
                code: ErrorCode::Internal,
            };
        }
    };
    match images.release_container_ref(&key) {
        Ok(r) => {
            record(true);
            match r {
                ContainerRefRelease::Released(_) => CleanupOutcome::Removed,
                _ => CleanupOutcome::AlreadyAbsent,
            }
        }
        Err(e) => {
            record(false);
            CleanupOutcome::Kept {
                code: fail(e).code(),
            }
        }
    }
}

/// 現行 scope の解除結果と旧 scope の解除結果を 1 つにまとめる。失敗（`Kept`）を最優先し、
/// 次に実際に外した（`Removed`）を採り、それ以外は現行 scope の結果を保つ。
fn merge_legacy_outcome(current: CleanupOutcome, legacy: CleanupOutcome) -> CleanupOutcome {
    match (current, legacy) {
        (CleanupOutcome::Kept { code }, _) | (_, CleanupOutcome::Kept { code }) => {
            CleanupOutcome::Kept { code }
        }
        (CleanupOutcome::NotApplicable, _) => CleanupOutcome::NotApplicable,
        (_, CleanupOutcome::Removed) => CleanupOutcome::Removed,
        (c, _) => c,
    }
}

/// 解除に使うイメージストアの決め方（[`decide_release_store`] の結果）。
enum ReleaseStore<'a> {
    /// 利用者が渡して開いた済みのストア（記録と一致を確認済み、または記録なし）。
    Explicit(&'a ImageStore),
    /// 記録の root を開く（開いた後に `root()` と記録の一致を確かめる）。
    Open(std::path::PathBuf),
    /// 解除しない（イメージつきでないコンテナ）。
    None,
}

/// 記録の値と `--image-root` から解除に使うストアを決める（ストアに触れない純関数）。
fn decide_release_store<'a>(
    recorded: Option<&str>,
    explicit: Option<&'a ImageStore>,
) -> Result<ReleaseStore<'a>, TraitError> {
    let Some(recorded) = recorded else {
        return Ok(explicit.map_or(ReleaseStore::None, ReleaseStore::Explicit));
    };
    let root = std::path::Path::new(recorded);
    if recorded.is_empty() || !root.is_absolute() {
        return Err(TraitError::new(
            ErrorCode::Internal,
            MSG_RECORDED_IMAGE_ROOT_INVALID,
        ));
    }
    match explicit {
        Some(e) if e.root() == root => Ok(ReleaseStore::Explicit(e)),
        Some(_) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_IMAGE_ROOT_MISMATCH,
        )),
        None => Ok(ReleaseStore::Open(root.to_path_buf())),
    }
}

/// core に入る前の delete の失敗を 1 回記録して `OciRuntimeError` にする（REPAIR-4）。
fn pre_core_delete_failure(
    recorder: &OpRecorder,
    started: Instant,
    e: TraitError,
) -> OciRuntimeError {
    record_pre_core_failure(recorder, "delete", started);
    OciRuntimeError::from_trait_error(LifecycleOp::Delete, e)
}

/// イメージ由来 rootfs を残した場合の警告（stderr に 1 行の JSON。ERR-1・OCI-7・#2633）。
///
/// パス・errno・ID は含めず、`code` で理由を見分ける。残った木は手動で消す（`docs/design/image-rootfs-lifetime.md`）。
fn image_rootfs_removal_warning(code: ErrorCode) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"image rootfs removal failed; leftover rootfs may remain\"}}",
        code.as_str()
    )
}

/// イメージ参照の解除に失敗した場合の警告（stderr に 1 行の JSON。ERR-1・OCI-7・#2499）。
///
/// パス・ID・errno は含めない。参照が残ったイメージは使用中のままになりうる（回収は次の同じ ID の create か `image rm`）。
fn image_ref_release_warning(code: ErrorCode) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"image reference release failed; the image may stay in use\"}}",
        code.as_str()
    )
}

/// 期限切れの警告（stderr に 1 行の JSON。`code` / `message` は ERR-1 の形）。
fn log_removal_timeout_warning() -> &'static str {
    "{\"level\":\"warn\",\"code\":\"TIMEOUT\",\"message\":\"supervisor log removal did not finish within the deadline; leftover logs may remain\"}"
}

/// core の `delete` が成功した後の後始末（supervisor ログ → コンテナログ）を行い、結果を `DeleteResponse` の
/// `supervisor_log` / `container_log` 欄に載せて返す（#2698・CLI-1・SUP-7・#2633）。`image_rootfs` は core の値のまま。
///
/// `run_delete` から呼ばれる。警告の出力は呼び出し元が [`cleanup_warnings`] で行う。`lock_wait` はログのロック解放を
/// 待つ上限（本番は [`CONTAINER_LOG_LOCK_WAIT`]。試験は短い値を渡す）。この期限は supervisor ログとコンテナログで
/// 共有し、コンテナログには supervisor ログの待ちの残りを渡す（独立に待つと最悪 30 秒になるため。#2892・REPAIR-5）。
///
/// CLI には `delete` 全体の期限が無く、各段は必ず 1 回試す。このため `Kept { Timeout }` は常に「試して期限切れになった」ことを
/// 表し、plugin-cri の警告行にある `existence: unverified`（試さなかった段）に当たる区別は要らない（#3260・REPAIR-4）。
fn finish_delete(
    store: &dyn StateStore,
    req: &DeleteRequest,
    resp: DeleteResponse,
    lock_wait: Duration,
) -> DeleteResponse {
    let wait = lock_wait.min(CONTAINER_LOG_LOCK_WAIT);
    let deadline = Instant::now() + wait;
    let sup = remove_supervisor_log(store, req, wait);
    let remaining = deadline.saturating_duration_since(Instant::now());
    resp.with_supervisor_log(sup)
        .with_container_log(remove_container_log(store, req, remaining))
}

/// 残った後始末の警告行（固定の順序: rootfs → supervisor ログ → コンテナログ → イメージ参照）。消せた・対象外は含まない。
fn cleanup_warnings(resp: &DeleteResponse) -> Vec<String> {
    resp.kept()
        .filter_map(|(target, code)| match target {
            CleanupTarget::ImageRootfs => Some(image_rootfs_removal_warning(code)),
            CleanupTarget::SupervisorLog => Some(supervisor_log_removal_warning(code)),
            CleanupTarget::ContainerLog => Some(container_log_removal_warning(code)),
            CleanupTarget::ImageRef => Some(image_ref_release_warning(code)),
            // 将来追加される対象は、警告の文言が決まるまで出さない（`DeleteResponse` の欄には残る）。
            _ => None,
        })
        .collect()
}

/// core の `delete` が成功した後に、supervisor の構造化ログ（`<root>/@supervisor-logs/<id>.log*`）を best effort で消す
/// （#2067・REPAIR-4）。削除は作業スレッドで 1 回あたり [`SUPERVISOR_LOG_REMOVE_TIMEOUT`] まで待つ（REPAIR-5）。
///
/// `stop` 直後は supervisor が drain の間ロックを持つため、`FailedPrecondition` の間は `lock_wait` まで試し直す（#2892・SUP-7）。
/// 再作成済みの ID は guard で見送る。失敗しても delete の結果は変えない。期限切れは `Kept { Timeout }`、枠の満杯は
/// `Kept { ResourceExhausted }`、待ち切れなければ `Kept { FailedPrecondition }`、状態ルートが無ければ `NotApplicable`。
/// core の delete より前には消さない（delete が失敗したとき稼働中のログを消さないため）。
fn remove_supervisor_log(
    store: &dyn StateStore,
    req: &DeleteRequest,
    lock_wait: Duration,
) -> CleanupOutcome {
    let Some(root) = store.host_state_root() else {
        return CleanupOutcome::NotApplicable;
    };
    let guard_root = root.to_path_buf();
    let guard_id = req.id().clone();
    match fandhe_container_supervisor::supervisor_log::remove_guarded_bounded_waiting(
        root,
        req.id(),
        lock_wait,
        SUPERVISOR_LOG_REMOVE_TIMEOUT,
        Arc::new(move || id_is_still_deleted(&guard_root, &guard_id)),
    ) {
        // guard が偽（同じ ID が再作成済み）の 0 件成功は `Removed` と報告しない（#3143・SUP-7）。
        Ok(removed) if removed.guard_declined() => CleanupOutcome::Superseded,
        Ok(_) => CleanupOutcome::Removed,
        Err(e) => CleanupOutcome::Kept { code: e.code() },
    }
}

/// 起動オプション文書の削除の失敗の警告(stderr に 1 行の JSON。ERR-1)。パス・errno・内容は含めない。
pub(super) fn options_removal_warning(e: &TraitError) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"container options file removal failed; a leftover file may remain\"}}",
        e.code().as_str()
    )
}

/// core の `delete` が成功した後に、起動オプション文書(`<root>/@container-options/<id>`。#2713・SUP-12)を消す。
///
/// ログの削除と同じく、失敗しても delete の結果は変えず警告を 1 行だけ出す。ID 単位のロックを取った上で、同じ ID が
/// 再作成されていないことを確かめてから消す(並行 `create` の新しいインスタンスの文書を消さない。`id_is_still_deleted`)。
/// ロック取得・削除は作業スレッドで期限つきに待つ(REPAIR-5)。期限切れの作業スレッドは CLI の終了で消え、
/// 文書が残っても次の同 ID の `create` が(ロックと状態の不在確認の下で)掃除する。
fn remove_container_options(store: &dyn StateStore, req: &DeleteRequest) {
    use fandhe_container_supervisor::container_options::store as options_store;
    let Some(root) = store.host_state_root() else {
        return;
    };
    let guard_root = root.to_path_buf();
    let guard_id = req.id().clone();
    // 本体は plugin-cri の create / delete と共有する（#2760・REPAIR-1）。
    let result = options_store::remove_stale_bounded(
        root,
        req.id(),
        move || id_is_still_deleted(&guard_root, &guard_id),
        options_store::OPTIONS_LOCK_WAIT,
        options_store::OPTIONS_REMOVE_TIMEOUT,
    );
    if let Err(e) = result {
        emit_warning_bounded(
            options_removal_warning(&e),
            write_warning_to_stderr,
            WARNING_WRITE_TIMEOUT,
        );
    }
}

/// 管理ルートの `/etc/hosts`・`/etc/resolv.conf` の削除(`<root>/@container-etc/<id>`)の期限(REPAIR-5)。
pub(super) const ETC_FILES_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

/// 管理ルートの生成物の削除失敗の警告(stderr に 1 行の JSON。ERR-1)。パス・errno・ID は含めない。
pub(super) fn etc_files_removal_warning(code: ErrorCode) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"container etc files removal failed; leftover files may remain\"}}",
        code.as_str()
    )
}

/// core の `delete` が成功した後に、管理ルートの生成物(`<root>/@container-etc/<id>`。NET-12・#1872)を消す。
///
/// 起動オプション文書の削除と同じく、失敗・期限切れでも delete の結果は変えず警告を 1 行だけ出す。再作成済みの ID は
/// 作業スレッド内で ID ロックを取った後の再確認(`remove_etc_files_locked`)で見送り、新しいインスタンスの生成物を
/// 消さない。呼び出し元スレッドには状態ストアの I/O を置かず、削除も再確認も期限つきに待つ(REPAIR-5・#3357)。
/// 並行の create / start が同じ ID のロックを長く持つ場合は、見送るだけでも警告が出うる。
/// 期限切れの作業スレッドは CLI の終了で消え、残った生成物は次の start の `remove` → `create` で回収される。
fn remove_etc_files_after_delete(store: &dyn StateStore, req: &DeleteRequest) {
    // 生成は Linux だけ(非 Linux の `remove_etc_files` は UNIMPLEMENTED のため、毎回警告を出さないよう呼ばない)。
    if !cfg!(target_os = "linux") {
        return;
    }
    let Some(root) = store.host_state_root() else {
        return;
    };
    let root = root.to_path_buf();
    let id = req.id().clone();
    // 不在の再確認は ID ロックの下(`remove_etc_files_locked`)の作業スレッドで行う。ここで同期のストア open を
    // しない(止まった状態ルートで delete が戻らなくならないよう、全体を期限つきの待ちに収める。REPAIR-5・#3357)。
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(remove_etc_files_locked(&root, &id));
    });
    let code = match rx.recv_timeout(ETC_FILES_REMOVE_TIMEOUT) {
        Ok(Ok(_)) => return,
        Ok(Err(e)) => e.code(),
        Err(_) => ErrorCode::Timeout,
    };
    emit_warning_bounded(
        etc_files_removal_warning(code),
        write_warning_to_stderr,
        WARNING_WRITE_TIMEOUT,
    );
}

/// pasta の置き場所の削除失敗の警告(stderr に 1 行の JSON。ERR-1)。パス・errno・ID は含めない。
pub(super) fn pasta_removal_warning(code: ErrorCode) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"pasta run directory removal failed; leftover files may remain\"}}",
        code.as_str()
    )
}

/// ID 単位のロック(`remove_etc_files_locked` と同じ `@container-options/@locks/<id>`)を保持したまま、不在の再確認から
/// pasta の置き場所(`@pasta/<id>`)の削除までを直列化する(#1940・NET-9)。
///
/// 起動前の 1 回の不在確認だけでは、worker の実行までに同じ ID が `create` / start されて新インスタンスの
/// `@pasta/<id>/pid` とディレクトリを消し、pasta の準備完了判定を壊す競合が残る。ロックを取ってから再確認し、
/// 再作成済みなら見送る。削除したときだけロックファイルを回収する。
fn remove_pasta_leftovers_locked(
    root: &std::path::Path,
    id: &ContainerId,
) -> Result<(), fandhe_container_core::traits::types::TraitError> {
    use fandhe_container_supervisor::container_options::store as options_store;
    let lock = options_store::acquire_lock(root, id, ETC_FILES_LOCK_WAIT)?;
    if !id_is_still_deleted(root, id) {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    let result = fandhe_container_supervisor::pasta_attach::remove_pasta_leftovers(root, id);
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), fandhe_container_core::traits::types::TraitError> = Ok(());
    if result.is_ok() && id_is_still_deleted(root, id) {
        lock.remove_lock_file();
    }
    result
}

/// core の `delete` が成功した後に、pasta の置き場所の残骸(`<root>/@pasta/<id>`。NET-9・#1940)を消す。
///
/// 通常は supervisor がコンテナの終了時に消す。supervisor が異常終了して残った PID ファイルだけを消し、記録の pid での
/// プロセスの探索・kill はしない(pid の再利用で無関係なプロセスを撃たないため。12.10)。失敗・期限切れでも delete の結果は
/// 変えず警告を 1 行だけ出す。再作成済みの ID は見送る。Linux 以外は pasta 構成が無いので何もしない。
fn remove_pasta_leftovers_after_delete(store: &dyn StateStore, req: &DeleteRequest) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let Some(root) = store.host_state_root() else {
        return;
    };
    let root = root.to_path_buf();
    let id = req.id().clone();
    // 不在の再確認は ID ロックの下(`remove_pasta_leftovers_locked`)の作業スレッドで行う。ここで同期のストア open を
    // しない(止まった状態ルートで delete が戻らなくならないよう、全体を期限つきの待ちに収める。REPAIR-5)。
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(remove_pasta_leftovers_locked(&root, &id));
    });
    let code = match rx.recv_timeout(ETC_FILES_REMOVE_TIMEOUT) {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e.code(),
        Err(_) => ErrorCode::Timeout,
    };
    emit_warning_bounded(
        pasta_removal_warning(code),
        write_warning_to_stderr,
        WARNING_WRITE_TIMEOUT,
    );
}

/// ID 単位のロック(`create` が起動オプション文書の書き込みで取るものと同じ `@container-options/@locks/<id>`)を
/// 保持したまま、不在確認から削除までを直列化する(#1872・NET-12)。
///
/// ロックなしでは「確認 → 並行 `create` の再作成と生成 → 削除」の順で新インスタンスの生成物を消す競合が残る。
/// 生成側(`create` / start)は同じロックの下で作るため、ここで保持中は新しい生成が割り込まない。
/// 削除したときだけロックファイルを回収する(再作成済みで見送ったときは触らない)。
fn remove_etc_files_locked(
    root: &std::path::Path,
    id: &ContainerId,
) -> Result<
    fandhe_container_core::etc_files::EtcRemoveOutcome,
    fandhe_container_core::traits::types::TraitError,
> {
    use fandhe_container_supervisor::container_options::store as options_store;
    let lock = options_store::acquire_lock(root, id, ETC_FILES_LOCK_WAIT)?;
    let outcome = remove_etc_files_if_still_deleted(
        root,
        id,
        fandhe_container_core::etc_files::remove_etc_files,
    );
    if outcome.is_ok() && id_is_still_deleted(root, id) {
        lock.remove_lock_file();
    }
    outcome
}

/// 管理ルートの生成物の削除で ID 単位のロックを待つ上限(`ETC_FILES_REMOVE_TIMEOUT` より短くする。REPAIR-5)。
const ETC_FILES_LOCK_WAIT: Duration = Duration::from_secs(3);

/// 削除直前に ID が再作成されていないことを再確認して `remove` を呼ぶ(options の cleanup と同じ形。#1872・NET-12)。
/// 再作成された新インスタンスの `@container-etc/<id>` を消さない。呼び出し元(`remove_etc_files_locked`)が ID ロックを
/// 保持した状態で呼ぶ、唯一の不在確認である(#3357)。
fn remove_etc_files_if_still_deleted(
    root: &std::path::Path,
    id: &ContainerId,
    remove: impl FnOnce(
        &std::path::Path,
        &ContainerId,
    ) -> Result<
        fandhe_container_core::etc_files::EtcRemoveOutcome,
        fandhe_container_core::traits::types::TraitError,
    >,
) -> Result<
    fandhe_container_core::etc_files::EtcRemoveOutcome,
    fandhe_container_core::traits::types::TraitError,
> {
    if !id_is_still_deleted(root, id) {
        return Ok(fandhe_container_core::etc_files::EtcRemoveOutcome::NotPresent);
    }
    remove(root, id)
}

/// supervisor ログ削除の警告。期限切れは専用文言、それ以外（ロック保持・権限エラー等）は `code` つきの失敗文言（REPAIR-4）。
fn supervisor_log_removal_warning(code: ErrorCode) -> String {
    if code == ErrorCode::Timeout {
        return log_removal_timeout_warning().to_string();
    }
    // 待ち切れなかった（FailedPrecondition）ときだけ reason を足す。語彙はコンテナログと同じ（#2892・REPAIR-4）。
    let reason = fandhe_container_supervisor::logs::container_log_removal_reason(code)
        .map(|r| format!(",\"reason\":\"{r}\""))
        .unwrap_or_default();
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\"{reason},\"message\":\"supervisor log removal failed; leftover logs may remain\"}}",
        code.as_str()
    )
}

/// コンテナログ削除失敗の警告（stderr に 1 行の JSON。ERR-1）。パス・errno・ID・内容は含めない。
/// 期限切れ（`TIMEOUT`）も同じ文言で、`code` で見分ける。待ちを使い切っても sink が閉じなかった失敗
/// （`FAILED_PRECONDITION`）だけは `reason: "sink_open_after_wait"` を足して、他の失敗と区別する（#2760・REPAIR-4。
/// 閉じた語彙は supervisor の `container_log_removal_reason`）。
fn container_log_removal_warning(code: ErrorCode) -> String {
    let reason = fandhe_container_supervisor::logs::container_log_removal_reason(code)
        .map(|r| format!(",\"reason\":\"{r}\""))
        .unwrap_or_default();
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\"{reason},\"message\":\"container log removal failed; leftover logs may remain\"}}",
        code.as_str()
    )
}

/// core の `delete` が成功した後に、コンテナログ（`<root>/@container-logs/<id>.log*`）を消す（#2446・#2698・SUP-7・CLI-1）。
///
/// supervisor は `Stopped` を記録した後で hub を drain してから sink のロックを手放すため、`stop` 直後の delete では
/// ロックが取れない窓がある。plugin-cri と同じく `FailedPrecondition` の間は `lock_wait` まで待つ
/// （1 回の試行の上限は [`CONTAINER_LOG_REMOVE_TIMEOUT`]）。再作成済みの ID は guard で見送る。
/// 残ったログは同じ ID の `create` で回収する（`create_start::reclaim_stale_container_log`）。
fn remove_container_log(
    store: &dyn StateStore,
    req: &DeleteRequest,
    lock_wait: Duration,
) -> CleanupOutcome {
    let Some(root) = store.host_state_root() else {
        return CleanupOutcome::NotApplicable;
    };
    let guard_root = root.to_path_buf();
    let guard_id = req.id().clone();
    match fandhe_container_supervisor::logs::remove_container_logs_guarded_bounded_waiting(
        root,
        req.id(),
        lock_wait.min(CONTAINER_LOG_LOCK_WAIT),
        CONTAINER_LOG_REMOVE_TIMEOUT,
        Arc::new(move || id_is_still_deleted(&guard_root, &guard_id)),
    ) {
        // guard が偽（同じ ID が再作成済み）の 0 件成功は `Removed` と報告しない（#3143・SUP-7）。
        Ok(removed) if removed.guard_declined() => CleanupOutcome::Superseded,
        Ok(_) => CleanupOutcome::Removed,
        Err(e) => CleanupOutcome::Kept { code: e.code() },
    }
}

/// 状態ストアに `id` が無い（delete 後に再作成されていない）ときだけ `true`（#2446・SUP-7。同じ ID の再作成との排他）。
///
/// supervisor のログ削除がロックを取った後（同じ ID の sink が開けない状態）で評価される。再作成済みなら削除を
/// 見送り、新しいインスタンスのログを消さない。ストアを開けない・NotFound 以外の失敗は fail-closed で `false`。
pub(super) fn id_is_still_deleted(
    root: &std::path::Path,
    id: &fandhe_container_core::traits::ContainerId,
) -> bool {
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    let Ok(root) = StateRoot::from_override(root.to_path_buf()) else {
        return false;
    };
    let Ok(store) = FileStateStore::open(root) else {
        return false;
    };
    matches!(
        store.get(&GetStateRequest::new(id.clone())),
        Err(e) if e.code() == fandhe_container_core::traits::ErrorCode::NotFound
    )
}

/// 警告の書き出しを待つ上限（`main.rs` の `DEFERRED_REPORT_TIMEOUT` と同じ値）。
pub(super) const WARNING_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// 本番の警告出力。`eprintln!` は書き込み失敗で panic するため使わず、エラーは捨てる（delete の成功を保つ）。
pub(super) fn write_warning_to_stderr(line: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr();
    let _ = err.write_all(line.as_bytes());
    let _ = err.write_all(b"\n");
}

/// 警告 1 行を `write` で作業スレッドから出し、`timeout` までだけ待つ（REPAIR-5）。
///
/// stderr が満杯の pipe / socket だと書き込みは無期限に止まり得るため、呼び出し元スレッドでは書かない。
/// 期限切れ・書き込み側の panic・スレッド起動失敗のいずれでも何も伝播せず戻り、delete の結果は変えない
/// （`main.rs` の `report_deferred` と同じ流儀。止まった書き込みのスレッドは置き去りにする）。
pub(super) fn emit_warning_bounded(
    line: String,
    write: impl FnOnce(&str) + Send + 'static,
    timeout: Duration,
) {
    let _ = run_log_removal_bounded(move || write(&line), timeout);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_supervisor::supervisor_log::LogRemoval;

    /// #2894・ERR-1: 起動オプション文書の削除警告は、枠の満杯（RESOURCE_EXHAUSTED）と期限切れ（TIMEOUT）で code が分かれる。
    #[test]
    fn err1_2894_options_removal_warning_distinguishes_busy_from_timeout() {
        assert_eq!(
            options_removal_warning(&TraitError::new(ErrorCode::ResourceExhausted, "x")),
            "{\"level\":\"warn\",\"code\":\"RESOURCE_EXHAUSTED\",\"message\":\"container options file removal failed; a leftover file may remain\"}"
        );
        assert_eq!(
            options_removal_warning(&TraitError::new(ErrorCode::Timeout, "x")),
            "{\"level\":\"warn\",\"code\":\"TIMEOUT\",\"message\":\"container options file removal failed; a leftover file may remain\"}"
        );
    }

    /// REPAIR-4: 失敗コードの supervisor ログ警告は code つきの 1 行 JSON。
    #[test]
    fn repair4_supervisor_log_failure_warning_carries_code() {
        assert_eq!(
            supervisor_log_removal_warning(ErrorCode::Internal),
            "{\"level\":\"warn\",\"code\":\"INTERNAL\",\"message\":\"supervisor log removal failed; leftover logs may remain\"}"
        );
        assert_eq!(
            supervisor_log_removal_warning(ErrorCode::Timeout),
            log_removal_timeout_warning()
        );
        assert!(!log_removal_timeout_warning().contains("existence"));
        assert_eq!(
            supervisor_log_removal_warning(ErrorCode::FailedPrecondition),
            "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"supervisor log removal failed; leftover logs may remain\"}"
        );
    }

    /// SUP-12(#2713): delete の後、状態の無い ID の起動オプション文書を消す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup12_delete_removes_options_document() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
        use fandhe_container_supervisor::container_options::store;
        let dir = std::env::temp_dir().join(format!("fc-cli-del-opt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        let root = StateRoot::from_override(dir.join("state")).expect("root");
        let fs_store = FileStateStore::open(root).expect("open");
        let state_root = fs_store.host_state_root().expect("root").to_path_buf();
        let id = ContainerId::new("c1").expect("id");
        let doc = ContainerOptionsDocument::new(vec![], vec!["A=1".into()], None, None, vec![])
            .expect("doc");
        store::write_new(&state_root, &id, &doc).expect("write");
        remove_container_options(&fs_store, &DeleteRequest::new(id.clone()));
        assert!(!store::options_path(&state_root, &id).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-9(#1940): delete の後に pasta の置き場所の残骸(`@pasta/<id>`)が消え、他の ID は残る。残骸が無くても成功する。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_delete_removes_pasta_leftovers_and_keeps_other_ids() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = std::env::temp_dir().join(format!("fc-cli-del-pasta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        let root = StateRoot::from_override(dir.join("state")).expect("root");
        let fs_store = FileStateStore::open(root).expect("open");
        let state_root = fs_store.host_state_root().expect("root").to_path_buf();
        let (a, b) = (
            ContainerId::new("c1").expect("id"),
            ContainerId::new("c2").expect("id"),
        );
        // 残骸が無いときも成功(警告も出さない)。
        remove_pasta_leftovers_after_delete(&fs_store, &DeleteRequest::new(a.clone()));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(state_root.join("@pasta"))
            .expect("pasta dir");
        for id in [&a, &b] {
            let run = state_root.join("@pasta").join(id.as_str());
            builder.create(&run).expect("run dir");
            std::fs::write(run.join("pid"), "123\n").expect("pid");
        }
        remove_pasta_leftovers_after_delete(&fs_store, &DeleteRequest::new(a.clone()));
        assert!(!state_root.join("@pasta").join("c1").exists());
        assert!(state_root.join("@pasta").join("c2").exists());
        assert_eq!(
            pasta_removal_warning(ErrorCode::Timeout),
            r#"{"level":"warn","code":"TIMEOUT","message":"pasta run directory removal failed; leftover files may remain"}"#
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-9(#1940): pasta の残骸の削除は ID 単位のロックの下で再確認し、ロックを他者が持つ間は消さず、
    /// 再作成済みの ID は見送る(新インスタンスの `@pasta/<id>` を巻き込まない)。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_pasta_leftover_removal_is_serialized_with_recreation() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_supervisor::container_options::store as options_store;
        use std::os::unix::fs::DirBuilderExt as _;
        let dir =
            std::env::temp_dir().join(format!("fc-cli-del-pasta-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        let root = StateRoot::from_override(dir.join("state")).expect("root");
        let fs_store = FileStateStore::open(root).expect("open");
        let state_root = fs_store.host_state_root().expect("root").to_path_buf();
        let a = ContainerId::new("c1").expect("id");
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(state_root.join("@pasta"))
            .expect("pasta dir");
        let run = state_root.join("@pasta").join("c1");
        builder.create(&run).expect("run dir");
        // ロックを他者(create 側)が持つ間は消さずに失敗する。
        let held =
            options_store::acquire_lock(&state_root, &a, Duration::from_secs(1)).expect("lock");
        assert!(remove_pasta_leftovers_locked(&state_root, &a).is_err());
        assert!(run.exists());
        drop(held);
        // 解放後は(不在なので)消せる。
        remove_pasta_leftovers_locked(&state_root, &a).expect("removed");
        assert!(!run.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-12(#1872): delete の後に管理ルートの生成物(`@container-etc/<id>`)が消え、他の ID は残る。
    /// 再作成済み(状態にある)ID は見送る。警告文言は固定。
    #[cfg(target_os = "linux")]
    #[test]
    fn net12_delete_removes_etc_files_and_keeps_recreated_or_other_ids() {
        use fandhe_container_core::etc_files::{
            EtcFileKind, EtcFileSelection, create_etc_files, etc_dir,
        };
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        let dir = std::env::temp_dir().join(format!("fc-cli-del-etc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        let root = StateRoot::from_override(dir.join("state")).expect("root");
        let fs_store = FileStateStore::open(root).expect("open");
        let state_root = fs_store.host_state_root().expect("root").to_path_buf();
        let sel = EtcFileSelection::default()
            .with(EtcFileKind::Hosts)
            .with(EtcFileKind::ResolvConf);
        let (a, b) = (
            ContainerId::new("c1").expect("id"),
            ContainerId::new("c2").expect("id"),
        );
        create_etc_files(&state_root, &a, sel).expect("create c1");
        create_etc_files(&state_root, &b, sel).expect("create c2");
        remove_etc_files_after_delete(&fs_store, &DeleteRequest::new(a.clone()));
        assert!(!etc_dir(&state_root, &a).exists(), "deleted id is removed");
        assert!(etc_dir(&state_root, &b).exists(), "other ids are kept");
        assert_eq!(
            etc_files_removal_warning(ErrorCode::FailedPrecondition),
            r#"{"level":"warn","code":"FAILED_PRECONDITION","message":"container etc files removal failed; leftover files may remain"}"#
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REPAIR-5: 警告の書き込みが止まっても期限で戻り、書き込みが panic しても呼び出し元へ伝播しない。
    #[test]
    fn repair5_warning_write_is_bounded_and_panic_safe() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        emit_warning_bounded(
            "w".to_string(),
            move |_| {
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
            },
            Duration::from_millis(100),
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(release_tx);

        emit_warning_bounded(
            "w".to_string(),
            |_| panic!("injected write failure"),
            Duration::from_secs(10),
        );
    }

    /// REPAIR-5・REPAIR-4: ログ削除が止まっても期限で戻り、`TimedOut` になる。期限内に終われば `Finished`。
    #[test]
    fn repair5_log_removal_is_bounded_by_deadline() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let out = run_log_removal_bounded(
            move || {
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
            },
            Duration::from_millis(100),
        );
        assert_eq!(out, LogRemoval::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(release_tx);

        let out = run_log_removal_bounded(|| {}, Duration::from_secs(10));
        assert_eq!(out, LogRemoval::Finished);
    }

    /// ERR-1: 期限切れの警告は `code` / `message` を持つ 1 行の JSON。
    #[test]
    fn err1_log_removal_timeout_warning_is_single_line_json() {
        let w = log_removal_timeout_warning();
        assert!(!w.contains('\n'));
        assert!(w.contains("\"code\":\"TIMEOUT\""));
        assert!(w.contains("\"message\":\"supervisor log removal did not finish"));
    }

    /// ERR-1・#2446: コンテナログ削除失敗の警告は改行なしの 1 行 JSON で、code ごとに完全一致し、パスを含まない。
    #[test]
    fn err1_container_log_removal_warning_is_single_line_json() {
        let w = container_log_removal_warning(ErrorCode::FailedPrecondition);
        assert_eq!(
            w,
            "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"container log removal failed; leftover logs may remain\"}"
        );
        let w = container_log_removal_warning(ErrorCode::Timeout);
        // 試して期限切れになった行は常にこの形で、`existence` を持たない（#3260）。
        assert_eq!(
            w,
            "{\"level\":\"warn\",\"code\":\"TIMEOUT\",\"message\":\"container log removal failed; leftover logs may remain\"}"
        );
        assert!(!w.contains("existence") && !w.contains('\n') && !w.contains('/'));
    }

    /// ERR-1・OCI-7・#2633: rootfs の警告は code ごとに完全一致する 1 行 JSON で、`cleanup_warnings` は残した欄だけを
    /// 固定の順序（rootfs → supervisor ログ → コンテナログ）で出す（#2698）。
    #[test]
    fn err1_cleanup_warnings_cover_only_kept_targets_in_order() {
        let w = image_rootfs_removal_warning(ErrorCode::FailedPrecondition);
        assert_eq!(
            w,
            "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"message\":\"image rootfs removal failed; leftover rootfs may remain\"}"
        );
        let quiet = DeleteResponse::new()
            .with_supervisor_log(CleanupOutcome::Removed)
            .with_container_log(CleanupOutcome::AlreadyAbsent);
        assert!(cleanup_warnings(&quiet).is_empty());
        let all = DeleteResponse::new()
            .with_image_rootfs(CleanupOutcome::Kept {
                code: ErrorCode::Unimplemented,
            })
            .with_supervisor_log(CleanupOutcome::Kept {
                code: ErrorCode::Timeout,
            })
            .with_container_log(CleanupOutcome::Kept {
                code: ErrorCode::FailedPrecondition,
            });
        let lines = cleanup_warnings(&all);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"code\":\"UNIMPLEMENTED\"") && lines[0].contains("rootfs"));
        assert_eq!(lines[1], log_removal_timeout_warning());
        assert!(
            lines[2].contains("\"code\":\"FAILED_PRECONDITION\"")
                && lines[2].contains("container log")
        );
    }

    /// REPAIR-4・OCI-7・#2499: 旧 scope の解除の失敗は応答を `Kept` にする（`AlreadyAbsent` に埋もれさせない）。
    #[test]
    fn repair4_legacy_release_outcome_is_merged_into_response() {
        let kept = CleanupOutcome::Kept {
            code: ErrorCode::Timeout,
        };
        assert_eq!(
            merge_legacy_outcome(CleanupOutcome::AlreadyAbsent, kept),
            kept
        );
        assert_eq!(merge_legacy_outcome(CleanupOutcome::Removed, kept), kept);
        assert_eq!(
            merge_legacy_outcome(CleanupOutcome::AlreadyAbsent, CleanupOutcome::Removed),
            CleanupOutcome::Removed
        );
        assert_eq!(
            merge_legacy_outcome(CleanupOutcome::Removed, CleanupOutcome::AlreadyAbsent),
            CleanupOutcome::Removed
        );
        assert_eq!(
            merge_legacy_outcome(CleanupOutcome::NotApplicable, CleanupOutcome::Removed),
            CleanupOutcome::NotApplicable
        );
    }

    /// ERR-1・OCI-7・#2499: イメージ参照の解除の失敗は完全一致する 1 行 JSON の警告になり、rootfs の後ろに並ぶ。
    #[test]
    fn err1_image_ref_release_warning_is_exact_and_last() {
        let resp = DeleteResponse::new()
            .with_image_ref(CleanupOutcome::Kept {
                code: ErrorCode::Internal,
            })
            .with_image_rootfs(CleanupOutcome::Kept {
                code: ErrorCode::Timeout,
            });
        let lines = cleanup_warnings(&resp);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("image rootfs removal failed"));
        assert_eq!(
            lines[1],
            "{\"level\":\"warn\",\"code\":\"INTERNAL\",\"message\":\"image reference release failed; the image may stay in use\"}"
        );
    }

    /// REPAIR-5・#2698・#2892: CLI の delete の後始末は、待ち（2 つのログで共有）+ supervisor ログの最後の試行 +
    /// コンテナログの最後の試行で 20 秒に収まる。
    #[test]
    fn repair5_cli_delete_cleanup_budget_fits_20s() {
        let total =
            CONTAINER_LOG_LOCK_WAIT + SUPERVISOR_LOG_REMOVE_TIMEOUT + CONTAINER_LOG_REMOVE_TIMEOUT;
        assert_eq!(total, Duration::from_secs(20));
    }

    fn stop_args(id: &str) -> StopArgs {
        StopArgs {
            id: id.into(),
            signal: None,
        }
    }

    fn delete_args(id: &str, force: bool) -> DeleteArgs {
        DeleteArgs {
            id: id.into(),
            force,
            image_root: None,
        }
    }

    /// ERR-2: 不正な ID 文字は INVALID_ARGUMENT（2）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_stop_request(&stop_args(id)).expect_err("stop");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_delete_request(&delete_args(id, false)).expect_err("delete");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1・ERR-1・#2775: `--signal` は Docker 表記を解釈して kill 要求に載せ、不正値は固定文言の `INVALID_ARGUMENT`。
    #[test]
    fn cli1_build_stop_request_parses_signal() {
        for (text, want) in [("SIGKILL", 9), ("kill", 9), ("10", 10), ("RTMIN+1", 35)] {
            let args = StopArgs {
                id: "c1".into(),
                signal: Some(text.into()),
            };
            let k = build_stop_request(&args).expect("stop");
            assert_eq!(k.signal().as_u8(), want, "{text}");
        }
        for text in ["", "0", "32", "65", "BOGUS", "SIGNAL_SIGTERM"] {
            let args = StopArgs {
                id: "c1".into(),
                signal: Some(text.into()),
            };
            let e = build_stop_request(&args).expect_err("must be rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{text}");
            assert_eq!(e.message(), "signal is invalid", "{text}");
        }
    }

    fn kill_args(id: &str, signal: Option<&str>) -> KillArgs {
        KillArgs {
            id: id.into(),
            signal: signal.map(str::to_owned),
        }
    }

    /// CLI-1・#1902: `kill` の省略は SIGTERM（15）、指定は `kill_signal` の語彙で番号に解く。
    #[test]
    fn cli1_build_kill_request_defaults_to_sigterm() {
        for (signal, want) in [
            (None, 15),
            (Some("KILL"), 9),
            (Some("10"), 10),
            (Some("33"), 33),
        ] {
            let k = build_kill_request(&kill_args("c1", signal)).expect("kill");
            assert_eq!(k.id().as_str(), "c1");
            assert_eq!(k.signal().as_u8(), want, "{signal:?}");
        }
    }

    /// ERR-1・ERR-2・#1902: 不正な ID・シグナルは core の型 / 固定文言の `INVALID_ARGUMENT`。
    #[test]
    fn err2_build_kill_request_rejects_invalid_id_and_signal() {
        let e = build_kill_request(&kill_args("a/b", None)).expect_err("id");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        for text in ["", "BOGUS", "term", "RTMIN"] {
            let e = build_kill_request(&kill_args("c1", Some(text))).expect_err("signal");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{text}");
            assert_eq!(e.message(), "signal is invalid", "{text}");
        }
    }

    /// CLI-1: stop は SIGTERM（15）の kill 要求、delete は force を素通しする。
    #[test]
    fn cli1_build_requests_keep_values() {
        let k = build_stop_request(&stop_args("c1")).expect("stop");
        assert_eq!(k.id().as_str(), "c1");
        assert_eq!(k.signal().as_u8(), 15);
        for force in [false, true] {
            let d = build_delete_request(&delete_args("c1", force)).expect("delete");
            assert_eq!(d.id().as_str(), "c1");
            assert_eq!(d.force(), force);
        }
    }

    /// REPAIR-3: 状態ルート無しのストア用 signaler は fail-closed の Unimplemented（非 Linux は cgroup remover も）。
    #[test]
    fn repair3_unavailable_signaler_and_remover_fail_closed() {
        let id = ContainerId::new("c1").expect("id");
        let pid = std::num::NonZeroU32::new(4242).expect("pid");
        let e = UnavailableSignaler
            .signal(&id, pid, Signal::SIGTERM, Instant::now())
            .expect_err("signal");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        #[cfg(not(target_os = "linux"))]
        {
            use fandhe_container_supervisor::control::ControlSignaler;
            let e = ControlSignaler::new(std::path::PathBuf::from("root"))
                .signal(&id, pid, Signal::SIGTERM, Instant::now())
                .expect_err("control signal");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            let e = UnavailableCgroupRemover.scope().expect_err("scope");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            let e = UnavailableCgroupRemover
                .remove(&id, StateRevision::from_raw(1))
                .expect_err("remove");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            let placement = CgroupPlacement::new(
                CgroupScope::new("/user.slice/x.scope").expect("scope"),
                StateRevision::from_raw(1),
            );
            let e = UnavailableCgroupRemover
                .remove_recorded(&id, &placement, &OpRecorder::new())
                .expect_err("remove_recorded");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use fandhe_container_core::observability::OpName;
        use fandhe_container_core::oci_runtime::{
            LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create, start,
        };
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_core::traits::{ContainerState, CreateRequest, GetStateRequest};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(
            PathBuf,
            #[allow(dead_code)] crate::scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
        );

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let scratch = crate::scratch_root::ScratchDir::new(
                    "fc-cli-sd",
                    std::time::Duration::from_secs(10),
                );
                let p = scratch.path().join(format!("{tag}-{n}"));
                std::fs::create_dir(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p, scratch)
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn state_root(base: &TmpDir) -> PathBuf {
            base.0.join("state")
        }

        fn store(base: &TmpDir) -> FileStateStore {
            let root = StateRoot::from_override(state_root(base)).expect("root");
            FileStateStore::open(root).expect("open")
        }

        fn id(s: &str) -> ContainerId {
            ContainerId::new(s).expect("id")
        }

        fn do_create(base: &TmpDir, store: &FileStateStore, rec: &OpRecorder, name: &str) {
            let req = CreateRequest::new(id(name), make_bundle(base)).expect("req");
            create(store, rec, &req).expect("create");
        }

        struct FakeProcess;

        impl LaunchedProcess for FakeProcess {
            fn pid(&self) -> std::num::NonZeroU32 {
                std::num::NonZeroU32::new(4242).expect("nonzero")
            }
            fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
                Ok(None)
            }
            fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }

        struct FakeLauncher;

        impl ProcessLauncher for FakeLauncher {
            fn launch(
                &self,
                _spec: &LaunchSpec,
                _timeout: Duration,
            ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                Ok(Box::new(FakeProcess))
            }
        }

        /// Running（pid 4242）まで進める。戻り値のハンドルは呼び出し元がテスト終了まで保持する。
        fn do_start(
            store: &FileStateStore,
            rec: &OpRecorder,
            name: &str,
        ) -> fandhe_container_core::oci_runtime::StartedContainer {
            let launcher: Arc<dyn ProcessLauncher> = Arc::new(FakeLauncher);
            start(
                store,
                rec,
                &launcher,
                &fandhe_container_core::traits::StartRequest::new(id(name)),
                &StartTimeouts::default(),
            )
            .expect("start")
        }

        /// 呼び出しを記録する signaler。
        #[derive(Default)]
        struct RecordingSignaler(Mutex<Vec<(String, u32, u8)>>);

        impl ProcessSignaler for RecordingSignaler {
            fn signal(
                &self,
                id: &ContainerId,
                pid: std::num::NonZeroU32,
                signal: Signal,
                _deadline: Instant,
            ) -> Result<(), TraitError> {
                self.0.lock().expect("lock").push((
                    id.as_str().to_string(),
                    pid.get(),
                    signal.as_u8(),
                ));
                Ok(())
            }
        }

        fn stop_with(
            store: &FileStateStore,
            rec: &OpRecorder,
            signaler: Arc<dyn ProcessSignaler>,
            name: &str,
        ) -> Result<ContainerStatus, OciRuntimeError> {
            let req = build_stop_request(&stop_args(name)).expect("req");
            stop_container(store, rec, &signaler, &req, &KillTimeout::default())
        }

        fn delete_with(
            store: &FileStateStore,
            rec: &OpRecorder,
            name: &str,
            force: bool,
        ) -> Result<DeleteResponse, OciRuntimeError> {
            let req = build_delete_request(&delete_args(name, force)).expect("req");
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            delete_container(store, rec, &remover, &req)
        }

        const FAKE_SCOPE: &str = "/user.slice/x.scope";

        /// フェイクの cgroup。`scope` は既定で記録と同じ値を返し、呼び出しの種別と instance を記録する。
        struct FakeCgroup {
            scope: &'static str,
            remove_error: Mutex<Option<TraitError>>,
            calls: Mutex<Vec<(&'static str, u64)>>,
            /// `remove_recorded` に渡された記録のスコープ。
            recorded_scopes: Mutex<Vec<String>>,
        }

        impl Default for FakeCgroup {
            fn default() -> Self {
                Self {
                    scope: FAKE_SCOPE,
                    remove_error: Mutex::new(None),
                    calls: Mutex::new(Vec::new()),
                    recorded_scopes: Mutex::new(Vec::new()),
                }
            }
        }

        impl FakeCgroup {
            fn finish(
                &self,
                kind: &'static str,
                instance: StateRevision,
            ) -> Result<CgroupRemoval, TraitError> {
                self.calls
                    .lock()
                    .expect("lock")
                    .push((kind, instance.value()));
                match self.remove_error.lock().expect("lock").take() {
                    Some(e) => Err(e),
                    None => Ok(CgroupRemoval::Removed),
                }
            }
        }

        impl ContainerCgroupRemover for FakeCgroup {
            fn scope(&self) -> Result<CgroupScope, TraitError> {
                CgroupScope::new(self.scope)
            }
            fn remove(
                &self,
                _id: &ContainerId,
                instance: StateRevision,
            ) -> Result<CgroupRemoval, TraitError> {
                self.finish("remove", instance)
            }
            fn remove_with_recorder(
                &self,
                _id: &ContainerId,
                instance: StateRevision,
                _recorder: &OpRecorder,
            ) -> Result<CgroupRemoval, TraitError> {
                self.finish("remove_with_recorder", instance)
            }
            fn remove_recorded(
                &self,
                _id: &ContainerId,
                placement: &CgroupPlacement,
                _recorder: &OpRecorder,
            ) -> Result<CgroupRemoval, TraitError> {
                self.recorded_scopes
                    .lock()
                    .expect("lock")
                    .push(placement.scope().as_str().to_owned());
                self.finish("remove_recorded", placement.instance())
            }
        }

        /// テストから内側のフェイクを観測するための共有ラッパー。
        struct SharedCgroup(Arc<FakeCgroup>);

        impl ContainerCgroupRemover for SharedCgroup {
            fn scope(&self) -> Result<CgroupScope, TraitError> {
                self.0.scope()
            }
            fn remove(
                &self,
                id: &ContainerId,
                instance: StateRevision,
            ) -> Result<CgroupRemoval, TraitError> {
                self.0.remove(id, instance)
            }
            fn remove_with_recorder(
                &self,
                id: &ContainerId,
                instance: StateRevision,
                recorder: &OpRecorder,
            ) -> Result<CgroupRemoval, TraitError> {
                self.0.remove_with_recorder(id, instance, recorder)
            }
            fn remove_recorded(
                &self,
                id: &ContainerId,
                placement: &CgroupPlacement,
                recorder: &OpRecorder,
            ) -> Result<CgroupRemoval, TraitError> {
                self.0.remove_recorded(id, placement, recorder)
            }
        }

        /// cgroup 配置つきの Created レコード（失敗した start の後に残る形）を作る。
        fn create_placed(base: &TmpDir, store: &FileStateStore, name: &str) -> StateRevision {
            use fandhe_container_core::traits::CreateStateRequest;
            let req = CreateStateRequest::new(
                ContainerStatus::created(id(name), None),
                make_bundle(base),
            )
            .expect("req")
            .with_cgroup_scope(CgroupScope::new(FAKE_SCOPE).expect("scope"));
            store.create(&req).expect("create").revision()
        }

        fn log_names(base: &TmpDir) -> Vec<String> {
            let dir = state_root(base).join("@container-logs");
            match std::fs::read_dir(dir) {
                Ok(rd) => rd
                    .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
                    .collect(),
                Err(_) => Vec::new(),
            }
        }

        /// `@container-logs`（0700）に `name` の sink を開いて 1 行書く。
        fn open_sink(
            base: &TmpDir,
            name: &str,
        ) -> fandhe_container_supervisor::logs::RotatingFileSink {
            use fandhe_container_supervisor::logs::{
                RotatingFileSink, container_log_rotation_config,
            };
            use std::os::unix::fs::PermissionsExt;
            let root = state_root(base);
            let dir = root.join("@container-logs");
            std::fs::create_dir_all(&dir).expect("dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            RotatingFileSink::open(&dir, &id(name), container_log_rotation_config()).expect("sink")
        }

        fn delete_req(name: &str) -> DeleteRequest {
            DeleteRequest::new(id(name))
        }

        /// SUP-7・CLI-1・#2698: sink が窓の間だけ生きていても、delete は閉鎖を待ってログとロックを消し、欄に載せる。
        #[test]
        fn sup7_cli1_delete_waits_for_sink_close_in_window() {
            let base = TmpDir::new("waitwin");
            let st = store(&base);
            let sink = open_sink(&base, "w1");
            let h = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(sink);
            });
            let resp = finish_delete(
                &st,
                &delete_req("w1"),
                DeleteResponse::new(),
                Duration::from_secs(3),
            );
            h.join().expect("join");
            assert_eq!(resp.container_log(), CleanupOutcome::Removed);
            assert_eq!(resp.supervisor_log(), CleanupOutcome::Removed);
            assert!(log_names(&base).is_empty(), "{:?}", log_names(&base));
            assert!(cleanup_warnings(&resp).is_empty());
        }

        /// SUP-7・REPAIR-5・#2698: sink が待ちより長く生きるときはログを残し、Kept{FailedPrecondition} と警告 1 行になる。
        #[test]
        fn sup7_repair5_delete_keeps_logs_when_sink_outlives_wait() {
            let base = TmpDir::new("keep");
            let st = store(&base);
            let _sink = open_sink(&base, "k1");
            let t = Instant::now();
            let resp = finish_delete(
                &st,
                &delete_req("k1"),
                DeleteResponse::new(),
                Duration::from_millis(100),
            );
            assert!(t.elapsed() < Duration::from_secs(5));
            assert_eq!(
                resp.container_log(),
                CleanupOutcome::Kept {
                    code: ErrorCode::FailedPrecondition
                }
            );
            assert!(!log_names(&base).is_empty());
            let w = cleanup_warnings(&resp);
            assert_eq!(w.len(), 1);
            assert_eq!(
                w[0],
                "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"container log removal failed; leftover logs may remain\"}"
            );
        }

        fn supervisor_log_names(base: &TmpDir) -> Vec<String> {
            let dir = state_root(base).join("@supervisor-logs");
            match std::fs::read_dir(dir) {
                Ok(rd) => rd
                    .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
                    .collect(),
                Err(_) => Vec::new(),
            }
        }

        /// SUP-7・CLI-1・#2892: supervisor がロックを手放す（drain 後）のを待ってから消し、警告は出ない。
        #[test]
        fn sup7_cli1_delete_waits_for_supervisor_log_release() {
            let base = TmpDir::new("supwait");
            let st = store(&base);
            let w =
                fandhe_container_supervisor::supervisor_log::open(&state_root(&base), &id("s1"))
                    .expect("supervisor log");
            let h = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(w);
            });
            let resp = finish_delete(
                &st,
                &delete_req("s1"),
                DeleteResponse::new(),
                Duration::from_secs(3),
            );
            h.join().expect("join");
            assert_eq!(resp.supervisor_log(), CleanupOutcome::Removed);
            assert_eq!(resp.container_log(), CleanupOutcome::Removed);
            assert!(supervisor_log_names(&base).is_empty());
            assert!(cleanup_warnings(&resp).is_empty());
        }

        /// SUP-7・REPAIR-5・#2892: ロックが待ちより長く続くと、supervisor ログを残し FAILED_PRECONDITION の警告 1 行になる。
        #[test]
        fn sup7_repair5_delete_keeps_supervisor_log_when_lock_outlives_wait() {
            let base = TmpDir::new("supkeep");
            let st = store(&base);
            let _w =
                fandhe_container_supervisor::supervisor_log::open(&state_root(&base), &id("s2"))
                    .expect("supervisor log");
            let t = Instant::now();
            let resp = finish_delete(
                &st,
                &delete_req("s2"),
                DeleteResponse::new(),
                Duration::from_millis(100),
            );
            assert!(t.elapsed() < Duration::from_secs(5));
            assert_eq!(
                resp.supervisor_log(),
                CleanupOutcome::Kept {
                    code: ErrorCode::FailedPrecondition
                }
            );
            let mut names = supervisor_log_names(&base);
            names.sort();
            assert_eq!(names, ["s2.log", "s2.log.lock"]);
            let w = cleanup_warnings(&resp);
            assert_eq!(w.len(), 1);
            assert_eq!(
                w[0],
                "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"supervisor log removal failed; leftover logs may remain\"}"
            );
        }

        /// REPAIR-5・#2892: 待ちの期限は 2 つのログで共有する。両方が塞がっていても 1 回分の待ち + 試行で終わる。
        #[test]
        fn repair5_delete_shares_wait_between_both_logs() {
            let base = TmpDir::new("share");
            let st = store(&base);
            let _w =
                fandhe_container_supervisor::supervisor_log::open(&state_root(&base), &id("s3"))
                    .expect("supervisor log");
            let _sink = open_sink(&base, "s3");
            let t = Instant::now();
            let resp = finish_delete(
                &st,
                &delete_req("s3"),
                DeleteResponse::new(),
                Duration::from_millis(300),
            );
            let elapsed = t.elapsed();
            // 独立に待つなら 600ms 以上かかる。共有なら 300ms 強で、どちらも待ち切れずに残る。
            assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
            assert!(elapsed < Duration::from_millis(590), "{elapsed:?}");
            let kept = CleanupOutcome::Kept {
                code: ErrorCode::FailedPrecondition,
            };
            assert_eq!(resp.supervisor_log(), kept);
            assert_eq!(resp.container_log(), kept);
        }

        /// SUP-7・#2892: 待つ間に同じ ID が再作成されていても、新しいインスタンスの supervisor ログは消さない。
        #[test]
        fn sup7_delete_does_not_remove_recreated_instance_supervisor_log() {
            let base = TmpDir::new("suprecreated");
            let st = store(&base);
            drop(
                fandhe_container_supervisor::supervisor_log::open(&state_root(&base), &id("s4"))
                    .expect("supervisor log"),
            );
            create_placed(&base, &st, "s4");
            let resp = finish_delete(
                &st,
                &delete_req("s4"),
                DeleteResponse::new(),
                Duration::from_millis(50),
            );
            assert_eq!(resp.supervisor_log(), CleanupOutcome::Superseded);
            assert!(supervisor_log_names(&base).contains(&"s4.log".to_string()));
        }

        /// CLI-1・#2698: ログが無くても Removed（0 件で成功）、core の image_rootfs は保たれ、状態ルートが無いストアは NotApplicable。
        #[test]
        fn cli1_delete_response_carries_cleanup_outcomes() {
            let base = TmpDir::new("outcomes");
            let st = store(&base);
            let core = DeleteResponse::new().with_image_rootfs(CleanupOutcome::Removed);
            let resp = finish_delete(&st, &delete_req("o1"), core, Duration::from_millis(50));
            assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
            assert_eq!(resp.supervisor_log(), CleanupOutcome::Removed);
            assert_eq!(resp.container_log(), CleanupOutcome::Removed);
        }

        /// SUP-7・#2698・#3143: 同じ ID が再作成済み（guard が false）ならログは消さず `Superseded` で返す（`Removed` と報告しない）。
        #[test]
        fn sup7_delete_does_not_remove_recreated_instance_logs() {
            let base = TmpDir::new("recreated2");
            let st = store(&base);
            drop(open_sink(&base, "r1"));
            create_placed(&base, &st, "r1");
            let resp = finish_delete(
                &st,
                &delete_req("r1"),
                DeleteResponse::new(),
                Duration::from_millis(50),
            );
            assert_eq!(resp.container_log(), CleanupOutcome::Superseded);
            assert!(!log_names(&base).is_empty());
        }

        /// SUP-7・#2446: コンテナログ削除の確認は、同じ ID が再作成されていたら `false`（削除を見送る）、
        /// 無ければ `true`、記録が壊れていて判定できなければ fail-closed で `false`。
        #[test]
        fn sup7_id_is_still_deleted_reflects_recreation() {
            let base = TmpDir::new("recreated");
            let store = store(&base);
            let root = state_root(&base);
            assert!(id_is_still_deleted(&root, &id("c1")));
            create_placed(&base, &store, "c1");
            assert!(!id_is_still_deleted(&root, &id("c1")));
            assert!(id_is_still_deleted(&root, &id("c2")));
            std::fs::write(root.join("c1").join("state.json"), "{").expect("corrupt");
            assert!(!id_is_still_deleted(&root, &id("c1")));
        }

        /// NET-12・#1872: worker の直前で再作成済みと分かれば remover を呼ばない(新インスタンスの生成物を消さない)。
        #[test]
        fn net12_etc_files_removal_skipped_when_recreated_before_worker() {
            let base = TmpDir::new("etc-recreated");
            let store = store(&base);
            let root = state_root(&base);
            create_placed(&base, &store, "e1");
            let called = std::cell::Cell::new(false);
            let r = remove_etc_files_if_still_deleted(&root, &id("e1"), |_, _| {
                called.set(true);
                Ok(fandhe_container_core::etc_files::EtcRemoveOutcome::Removed)
            });
            assert_eq!(
                r.expect("ok"),
                fandhe_container_core::etc_files::EtcRemoveOutcome::NotPresent
            );
            assert!(!called.get());
            let r = remove_etc_files_if_still_deleted(&root, &id("e2"), |_, _| {
                called.set(true);
                Ok(fandhe_container_core::etc_files::EtcRemoveOutcome::Removed)
            });
            assert_eq!(
                r.expect("ok"),
                fandhe_container_core::etc_files::EtcRemoveOutcome::Removed
            );
            assert!(called.get());
        }

        /// NET-12・REPAIR-5・#3357: 公開の入口でも、再作成済み(状態に記録がある)ID の生成物は残り、記録の無い ID の生成物は消える。
        #[test]
        fn net12_repair5_delete_keeps_etc_files_of_recreated_id() {
            use fandhe_container_core::etc_files::{
                EtcFileKind, EtcFileSelection, create_etc_files, etc_dir,
            };
            let base = TmpDir::new("etc-delete-recreated");
            let store = store(&base);
            let root = state_root(&base);
            let sel = EtcFileSelection::default().with(EtcFileKind::Hosts);
            create_etc_files(&root, &id("e1"), sel).expect("create e1");
            create_etc_files(&root, &id("e2"), sel).expect("create e2");
            create_placed(&base, &store, "e1");
            remove_etc_files_after_delete(&store, &DeleteRequest::new(id("e1")));
            remove_etc_files_after_delete(&store, &DeleteRequest::new(id("e2")));
            assert!(etc_dir(&root, &id("e1")).exists(), "recreated id is kept");
            assert!(!etc_dir(&root, &id("e2")).exists(), "deleted id is removed");
        }

        /// NET-12・REPAIR-5・#3357: 生成物の削除は ID ロックの下で直列化され、他者が持つ間は消さず `TIMEOUT` で失敗し、
        /// 解放後は消せる。
        #[test]
        fn net12_etc_files_removal_is_serialized_with_recreation() {
            use fandhe_container_core::etc_files::{
                EtcFileKind, EtcFileSelection, EtcRemoveOutcome, create_etc_files, etc_dir,
            };
            use fandhe_container_supervisor::container_options::store as options_store;
            let base = TmpDir::new("etc-lock");
            let _store = store(&base); // 状態ルートを作る
            let root = state_root(&base);
            let a = id("e1");
            create_etc_files(
                &root,
                &a,
                EtcFileSelection::default().with(EtcFileKind::Hosts),
            )
            .expect("create");
            let held =
                options_store::acquire_lock(&root, &a, Duration::from_secs(1)).expect("lock");
            let err = remove_etc_files_locked(&root, &a).expect_err("locked");
            assert_eq!(err.code(), ErrorCode::Timeout);
            assert!(etc_dir(&root, &a).exists());
            drop(held);
            assert_eq!(
                remove_etc_files_locked(&root, &a).expect("removed"),
                EtcRemoveOutcome::Removed
            );
            assert!(!etc_dir(&root, &a).exists());
        }

        /// 検出の呼び出し回数を数えつつ `fake` を返す remover を作る。
        fn counted(
            fake: &Arc<FakeCgroup>,
            detects: &Arc<AtomicUsize>,
        ) -> DetectedCgroupRemover<
            SharedCgroup,
            impl Fn() -> Result<SharedCgroup, TraitError> + Send + Sync,
        > {
            let (fake, detects) = (fake.clone(), detects.clone());
            DetectedCgroupRemover::new(move || {
                detects.fetch_add(1, Ordering::SeqCst);
                Ok(SharedCgroup(fake.clone()))
            })
        }

        /// OCI-6: 配置の無いレコードの delete は検出せずに成功し、状態記録が消える。
        #[test]
        fn oci6_delete_without_placement_does_not_detect() {
            let base = TmpDir::new("del-noplace");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            let detects = Arc::new(AtomicUsize::new(0));
            let fake = Arc::new(FakeCgroup::default());
            let remover = counted(&fake, &detects);
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_container(&st, &rec, &remover, &req).expect("delete");
            assert_eq!(detects.load(Ordering::SeqCst), 0);
            assert!(fake.calls.lock().expect("lock").is_empty());
            let e = st.get(&GetStateRequest::new(id("c1"))).expect_err("gone");
            assert_eq!(e.code(), ErrorCode::NotFound);
        }

        /// OCI-6・CORE-3: 配置つきレコードは検出 1 回・remove_with_recorder 1 回で削除される。
        #[test]
        fn oci6_delete_with_placement_detects_once_and_removes() {
            let base = TmpDir::new("del-place");
            let st = store(&base);
            let rev = create_placed(&base, &st, "c1");
            let detects = Arc::new(AtomicUsize::new(0));
            let fake = Arc::new(FakeCgroup::default());
            let remover = counted(&fake, &detects);
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_container(&st, &OpRecorder::new(), &remover, &req).expect("delete");
            assert_eq!(detects.load(Ordering::SeqCst), 1);
            assert_eq!(
                *fake.calls.lock().expect("lock"),
                vec![("remove_with_recorder", rev.value())]
            );
            let e = st.get(&GetStateRequest::new(id("c1"))).expect_err("gone");
            assert_eq!(e.code(), ErrorCode::NotFound);
        }

        /// OCI-6・CORE-3（#2096・#2060 案 B）: 記録とスコープが異なれば、記録の配置（スコープ・instance）で
        /// `remove_recorded` が 1 回だけ呼ばれ、`remove*` は呼ばれずに状態記録が消える。
        #[test]
        fn oci6_delete_scope_mismatch_removes_via_recorded_scope() {
            let base = TmpDir::new("del-mismatch");
            let st = store(&base);
            let rev = create_placed(&base, &st, "c1");
            let fake = Arc::new(FakeCgroup {
                scope: "/user.slice/other.scope",
                ..FakeCgroup::default()
            });
            let detects = Arc::new(AtomicUsize::new(0));
            let remover = counted(&fake, &detects);
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_container(&st, &OpRecorder::new(), &remover, &req).expect("delete");
            assert_eq!(
                *fake.calls.lock().expect("lock"),
                vec![("remove_recorded", rev.value())]
            );
            assert_eq!(
                *fake.recorded_scopes.lock().expect("lock"),
                vec![FAKE_SCOPE.to_owned()]
            );
            let e = st.get(&GetStateRequest::new(id("c1"))).expect_err("gone");
            assert_eq!(e.code(), ErrorCode::NotFound);
        }

        /// SEC-1（#2096）: 記録の経路が失敗したら同じ code（FAILED_PRECONDITION・exit 5）で失敗し、記録を残す。
        #[test]
        fn sec1_delete_recorded_scope_failure_keeps_record() {
            let base = TmpDir::new("del-mismatch-fail");
            let st = store(&base);
            create_placed(&base, &st, "c1");
            let fake = Arc::new(FakeCgroup {
                scope: "/user.slice/other.scope",
                ..FakeCgroup::default()
            });
            *fake.remove_error.lock().expect("lock") = Some(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container cgroup is not empty or changed; retry",
            ));
            let detects = Arc::new(AtomicUsize::new(0));
            let remover = counted(&fake, &detects);
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            let e =
                delete_container(&st, &OpRecorder::new(), &remover, &req).expect_err("recorded");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            assert_eq!(fake.calls.lock().expect("lock").len(), 1);
            st.get(&GetStateRequest::new(id("c1"))).expect("kept");
        }

        /// SEC-1: 検出の失敗は固定文言の PERMISSION_DENIED で失敗し、記録を残す。
        #[test]
        fn sec1_delete_detect_failure_is_fail_closed() {
            let base = TmpDir::new("del-detect-fail");
            let st = store(&base);
            create_placed(&base, &st, "c1");
            let remover = DetectedCgroupRemover::new(|| -> Result<FakeCgroup, TraitError> {
                Err(detect_error(ErrorCode::PermissionDenied))
            });
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            let e = delete_container(&st, &OpRecorder::new(), &remover, &req).expect_err("denied");
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
            assert_eq!(e.exit_code().get(), 6);
            st.get(&GetStateRequest::new(id("c1"))).expect("kept");
        }

        /// OCI-6: remove の失敗（プロセスが残っている等）は同じ code で失敗し、記録を残す。
        #[test]
        fn oci6_delete_remove_failure_keeps_record() {
            let base = TmpDir::new("del-remove-fail");
            let st = store(&base);
            create_placed(&base, &st, "c1");
            let fake = Arc::new(FakeCgroup::default());
            *fake.remove_error.lock().expect("lock") = Some(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container cgroup still has processes",
            ));
            let detects = Arc::new(AtomicUsize::new(0));
            let remover = counted(&fake, &detects);
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            let e = delete_container(&st, &OpRecorder::new(), &remover, &req).expect_err("remove");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            st.get(&GetStateRequest::new(id("c1"))).expect("kept");
        }

        /// REPAIR-4: remove_with_recorder は内側の remove_with_recorder へ転送される（remove は呼ばれない）。
        #[test]
        fn repair4_remover_forwards_recorder() {
            let fake = Arc::new(FakeCgroup::default());
            let detects = Arc::new(AtomicUsize::new(0));
            let remover = counted(&fake, &detects);
            let r = remover
                .remove_with_recorder(&id("c1"), StateRevision::from_raw(7), &OpRecorder::new())
                .expect("remove");
            assert_eq!(r, CgroupRemoval::Removed);
            assert_eq!(
                *fake.calls.lock().expect("lock"),
                vec![("remove_with_recorder", 7)]
            );
            remover.scope().expect("scope");
            assert_eq!(detects.load(Ordering::SeqCst), 1);
            let placement = CgroupPlacement::new(
                CgroupScope::new("/user.slice/y.scope").expect("scope"),
                StateRevision::from_raw(9),
            );
            remover
                .remove_recorded(&id("c1"), &placement, &OpRecorder::new())
                .expect("remove_recorded");
            assert_eq!(
                *fake.calls.lock().expect("lock"),
                vec![("remove_with_recorder", 7), ("remove_recorded", 9)]
            );
        }

        /// CLI-1: 検出失敗のエラーは code を保ち、文言は固定。
        #[test]
        fn cli1_detect_error_maps_code_only() {
            for code in [
                ErrorCode::PermissionDenied,
                ErrorCode::FailedPrecondition,
                ErrorCode::Internal,
            ] {
                let e = detect_error(code);
                assert_eq!(e.code(), code);
                assert_eq!(e.message(), "failed to detect the delegated cgroup");
            }
        }

        /// ERR-2: 未 create の ID の stop は NOT_FOUND（3・op=kill）で signaler を呼ばない。
        #[test]
        fn err2_stop_unknown_id_is_not_found() {
            let base = TmpDir::new("stop-nf");
            let st = store(&base);
            let sig = Arc::new(RecordingSignaler::default());
            let e = stop_with(&st, &OpRecorder::new(), sig.clone(), "nope").expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(e.op(), LifecycleOp::Kill);
            assert!(sig.0.lock().expect("lock").is_empty());
        }

        /// ERR-2: Created（pid なし）の stop は FAILED_PRECONDITION（5）で signaler を呼ばない。
        #[test]
        fn err2_stop_created_is_failed_precondition() {
            let base = TmpDir::new("stop-created");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            let sig = Arc::new(RecordingSignaler::default());
            let e = stop_with(&st, &rec, sig.clone(), "c1").expect_err("fp");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            assert!(sig.0.lock().expect("lock").is_empty());
        }

        /// CLI-1・OCI-6: Running の stop は core の kill 経由で signaler に SIGTERM（15）が 1 回届く。
        #[test]
        fn cli1_stop_calls_core_and_signals_sigterm() {
            let base = TmpDir::new("stop-ok");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-stop-ok");
            let _handle = do_start(&st, &rec, "sd-stop-ok");
            let sig = Arc::new(RecordingSignaler::default());
            let status = stop_with(&st, &rec, sig.clone(), "sd-stop-ok").expect("stop");
            assert_eq!(status.state(), ContainerState::Running);
            assert_eq!(
                *sig.0.lock().expect("lock"),
                vec![("sd-stop-ok".to_string(), 4242, 15)]
            );
        }

        fn kill_with(
            store: &FileStateStore,
            rec: &OpRecorder,
            signaler: Arc<dyn ProcessSignaler>,
            name: &str,
            signal: Option<&str>,
        ) -> Result<ContainerStatus, OciRuntimeError> {
            let req = build_kill_request(&kill_args(name, signal)).expect("req");
            stop_container(store, rec, &signaler, &req, &KillTimeout::default())
        }

        /// CLI-1・#1902: kill は指定番号を 1 回だけ送り、終了を待たず状態も変えない（Running のまま・pid 不変）。
        #[test]
        fn cli1_kill_signals_requested_number_once() {
            for (signal, want) in [
                (None, 15),
                (Some("KILL"), 9),
                (Some("SIGUSR1"), 10),
                (Some("10"), 10),
            ] {
                let base = TmpDir::new("kill-ok");
                let st = store(&base);
                let rec = OpRecorder::new();
                do_create(&base, &st, &rec, "sd-kill-ok");
                let _handle = do_start(&st, &rec, "sd-kill-ok");
                let sig = Arc::new(RecordingSignaler::default());
                let status = kill_with(&st, &rec, sig.clone(), "sd-kill-ok", signal).expect("kill");
                assert_eq!(status.state(), ContainerState::Running);
                assert_eq!(
                    *sig.0.lock().expect("lock"),
                    vec![("sd-kill-ok".to_string(), 4242, want)],
                    "{signal:?}"
                );
                let got = st
                    .get(&GetStateRequest::new(id("sd-kill-ok")))
                    .expect("get");
                assert_eq!(got.status().state(), ContainerState::Running);
                assert_eq!(got.status().pid(), std::num::NonZeroU32::new(4242));
            }
        }

        /// ERR-2・#1902: 未作成は NOT_FOUND（3）、Created は FAILED_PRECONDITION（5）で、signaler は呼ばれない。
        #[test]
        fn err2_kill_unknown_and_created_do_not_signal() {
            let base = TmpDir::new("kill-pre");
            let st = store(&base);
            let rec = OpRecorder::new();
            let sig = Arc::new(RecordingSignaler::default());
            let e = kill_with(&st, &rec, sig.clone(), "none", None).expect_err("nf");
            assert_eq!((e.code(), e.exit_code().get()), (ErrorCode::NotFound, 3));
            assert_eq!(e.op(), LifecycleOp::Kill);
            do_create(&base, &st, &rec, "c1");
            let e = kill_with(&st, &rec, sig.clone(), "c1", None).expect_err("fp");
            assert_eq!(e.exit_code().get(), 5);
            assert!(sig.0.lock().expect("lock").is_empty());
        }

        /// SEC-1・ERR-2・#1902: 本番 signaler（意図なし）は supervisor が無ければ UNAVAILABLE（9）で、
        /// pid へ縮退せず状態は Running のまま。
        #[test]
        fn sec1_kill_with_production_signaler_without_supervisor_is_unavailable() {
            let base = TmpDir::new("kill-unavail");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-kill-unavail");
            let _handle = do_start(&st, &rec, "sd-kill-unavail");
            let e = kill_with(&st, &rec, production_signaler(&st), "sd-kill-unavail", None)
                .expect_err("unavailable");
            assert_eq!(e.code(), ErrorCode::Unavailable);
            assert_eq!(e.exit_code().get(), 9);
            assert_eq!(e.op(), LifecycleOp::Kill);
            let got = st
                .get(&GetStateRequest::new(id("sd-kill-unavail")))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Running);
        }

        /// SEC-1・ERR-2: 本番 signaler は supervisor のソケットが無ければ UNAVAILABLE（9・op=kill）で失敗し、
        /// pid へ縮退せず状態は Running のまま。
        #[test]
        fn sec1_stop_with_production_signaler_without_supervisor_is_unavailable() {
            let base = TmpDir::new("stop-unavail");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-stop-unavail");
            let _handle = do_start(&st, &rec, "sd-stop-unavail");
            let e = stop_with(&st, &rec, production_stop_signaler(&st), "sd-stop-unavail")
                .expect_err("unavailable");
            assert_eq!(e.code(), ErrorCode::Unavailable);
            assert_eq!(e.exit_code().get(), 9);
            assert_eq!(e.op(), LifecycleOp::Kill);
            let got = st
                .get(&GetStateRequest::new(id("sd-stop-unavail")))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Running);
            assert_eq!(got.status().pid(), std::num::NonZeroU32::new(4242));
        }

        /// REPAIR-3: 状態ルートを公開しないストアでは UNIMPLEMENTED（8）で fail-closed。
        #[test]
        fn repair3_production_signaler_without_host_root_is_unimplemented() {
            struct NoRoot(FileStateStore);
            impl StateStore for NoRoot {
                fn create(
                    &self,
                    r: &fandhe_container_core::traits::CreateStateRequest,
                ) -> Result<fandhe_container_core::traits::StateRecord, TraitError>
                {
                    self.0.create(r)
                }
                fn update(
                    &self,
                    r: &fandhe_container_core::traits::UpdateStateRequest,
                ) -> Result<fandhe_container_core::traits::StateRecord, TraitError>
                {
                    self.0.update(r)
                }
                fn get(
                    &self,
                    r: &GetStateRequest,
                ) -> Result<fandhe_container_core::traits::StateRecord, TraitError>
                {
                    self.0.get(r)
                }
                fn list(
                    &self,
                    r: &fandhe_container_core::traits::ListStateRequest,
                ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
                    self.0.list(r)
                }
                fn delete(
                    &self,
                    r: &fandhe_container_core::traits::DeleteStateRequest,
                ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError>
                {
                    self.0.delete(r)
                }
            }
            let base = TmpDir::new("stop-noroot");
            let st = NoRoot(store(&base));
            let e = production_signaler(&st)
                .signal(
                    &id("c1"),
                    std::num::NonZeroU32::new(4242).expect("pid"),
                    Signal::SIGTERM,
                    Instant::now(),
                )
                .expect_err("unimpl");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
        }

        /// ERR-2・REPAIR-5: 応答しない相手には期限で TIMEOUT（7・op=kill）になる。
        #[test]
        fn err2_stop_with_silent_supervisor_times_out() {
            let base = TmpDir::new("stop-timeout");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-stop-timeout");
            let _handle = do_start(&st, &rec, "sd-stop-timeout");
            let sock = state_root(&base)
                .join("sd-stop-timeout")
                .join("supervisor.sock");
            let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
            // 接続が来なくても有限時間で終わるよう、non-blocking の accept を絶対期限まで再試行する
            // （REPAIR-5。worker が接続前に Timeout になっても join が戻らなくならない）。
            listener.set_nonblocking(true).expect("nonblocking");
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let accept_deadline = Instant::now() + Duration::from_secs(5);
                let mut conn = None;
                while Instant::now() < accept_deadline {
                    match listener.accept() {
                        Ok(c) => {
                            conn = Some(c);
                            break;
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
                // 呼び出し側の検証が終わるまで無応答のまま接続を保持する（有限の上限つき）。
                let _ = done_rx.recv_timeout(Duration::from_secs(5));
                drop(conn);
            });
            let req = build_stop_request(&stop_args("sd-stop-timeout")).expect("req");
            let t0 = Instant::now();
            let e = stop_container(
                &st,
                &rec,
                &production_stop_signaler(&st),
                &req,
                &KillTimeout::new(Duration::from_millis(300)).expect("timeout"),
            )
            .expect_err("timeout");
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert_eq!(e.exit_code().get(), 7);
            assert_eq!(e.op(), LifecycleOp::Kill);
            assert!(t0.elapsed() < Duration::from_secs(2));
            let _ = done_tx.send(());
            t.join().expect("join");
        }

        /// CLI-1・OCI-6: Created の delete は core を呼んで状態記録を消す。
        #[test]
        fn cli1_delete_calls_core_and_removes_state() {
            let base = TmpDir::new("del-ok");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            assert!(state_root(&base).join("c1").join("state.json").exists());
            delete_with(&st, &rec, "c1", false).expect("delete");
            let e = st
                .get(&GetStateRequest::new(id("c1")))
                .expect_err("removed");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert!(!state_root(&base).join("c1").join("state.json").exists());
        }

        /// ERR-2: 二重 delete の 2 回目は NOT_FOUND（3・op=delete）。
        #[test]
        fn err2_delete_twice_is_not_found() {
            let base = TmpDir::new("del-twice");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            delete_with(&st, &rec, "c1", false).expect("first");
            let e = delete_with(&st, &rec, "c1", false).expect_err("second");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(e.op(), LifecycleOp::Delete);
        }

        /// ERR-2: Running の delete は 5、force でも 8 で、いずれもレコードが残る。
        #[test]
        fn err2_delete_running_is_refused_and_keeps_record() {
            let base = TmpDir::new("del-running");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-del-running");
            let _handle = do_start(&st, &rec, "sd-del-running");
            let e = delete_with(&st, &rec, "sd-del-running", false).expect_err("plain");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            let e = delete_with(&st, &rec, "sd-del-running", true).expect_err("force");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            let got = st
                .get(&GetStateRequest::new(id("sd-del-running")))
                .expect("kept");
            assert_eq!(got.status().state(), ContainerState::Running);
        }

        /// REPAIR-4: stop / delete は同じ recorder に操作名 kill / delete で成功・失敗件数が記録される。
        #[test]
        fn repair4_stop_delete_are_recorded() {
            let base = TmpDir::new("rec");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            let sig: Arc<dyn ProcessSignaler> = Arc::new(RecordingSignaler::default());
            let _ = stop_with(&st, &rec, sig.clone(), "c1");
            let _ = stop_with(&st, &rec, sig, "nope");
            delete_with(&st, &rec, "c1", false).expect("delete");
            let _ = delete_with(&st, &rec, "c1", false);
            let kill_op = rec
                .snapshot_op(&OpName::new("kill").expect("name"))
                .expect("kill");
            assert_eq!((kill_op.success(), kill_op.failure()), (0, 2));
            let del_op = rec
                .snapshot_op(&OpName::new("delete").expect("name"))
                .expect("delete");
            assert_eq!((del_op.success(), del_op.failure()), (1, 1));
        }

        const REF_MANIFEST: &str =
            "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

        fn scope_of(base: &TmpDir) -> String {
            crate::commands::image_refs::state_scope(&store(base)).expect("scope")
        }

        fn ref_digest() -> fandhe_container_core::oci_runtime::ImageManifestDigest {
            fandhe_container_core::oci_runtime::ImageManifestDigest::new(REF_MANIFEST)
                .expect("manifest")
        }

        /// 在庫の有無を選べるイメージストア（在庫は未永続化のため、同じインスタンスを使い回す）。
        fn images_store(
            base: &TmpDir,
            seed: bool,
        ) -> fandhe_container_oci::image_management::ImageStore {
            use fandhe_container_oci::image_management::{ImageStore, ManifestComposition};
            use fandhe_container_oci::reference::Digest;
            let root = base.0.join("images");
            std::fs::create_dir_all(&root).expect("images");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            let images = ImageStore::open(&root).expect("open");
            if seed {
                images
                    .lock()
                    .expect("lock")
                    .register_manifest(
                        Digest::parse(REF_MANIFEST).expect("digest"),
                        ManifestComposition::new(
                            Digest::parse(
                                "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
                            )
                            .expect("config"),
                            vec![],
                        )
                        .expect("comp"),
                    )
                    .expect("register manifest");
            }
            images
        }

        fn container_refs(
            images: &fandhe_container_oci::image_management::ImageStore,
        ) -> Vec<String> {
            use fandhe_container_oci::reference::Digest;
            images
                .lock()
                .expect("lock")
                .manifest_references(&Digest::parse(REF_MANIFEST).expect("digest"))
                .containers
                .iter()
                .map(|c| c.as_str().to_string())
                .collect()
        }

        fn runtime_with(st: FileStateStore) -> crate::commands::create_start::Runtime {
            crate::commands::create_start::Runtime {
                audit: Box::new(
                    fandhe_container_core::audit_log::FileAuditSink::in_state_store(&st),
                ),
                store: Box::new(st),
                recorder: OpRecorder::new(),
            }
        }

        fn create_image(
            base: &TmpDir,
            rt: &crate::commands::create_start::Runtime,
            images: fandhe_container_oci::image_management::ImageStore,
            name: &str,
        ) -> Result<crate::commands::create_start::CreateImage, OciRuntimeError> {
            use crate::commands::create_start::{
                CreateImage, create_container_with_image_reclaiming as create_container_with_image,
            };
            let image = CreateImage {
                store: images,
                manifest: ref_digest(),
                scope: scope_of(base),
                legacy_scope: None,
            };
            let req = CreateRequest::new(id(name), make_bundle(base)).expect("req");
            create_container_with_image(rt, &image, &req).map(|_| image)
        }

        /// OCI-7・#2315: イメージつき create の後は参照が 1 件、`--image-root` つき delete の後は 0 件。
        #[test]
        fn oci7_create_then_delete_with_image_root_releases_reference() {
            let base = TmpDir::new("img-flow");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            assert_eq!(
                container_refs(&image.store),
                vec![format!("{}.c1", scope_of(&base))]
            );
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_container_releasing_image_ref(
                rt.store.as_ref(),
                &rt.recorder,
                &remover,
                &image.store,
                &image.scope,
                &req,
            )
            .expect("delete");
            assert_eq!(container_refs(&image.store), Vec::<String>::new());
        }

        /// 解除つき delete を、記録の root を使う本番と同じ入口で呼ぶ。
        fn delete_recorded(
            rt: &crate::commands::create_start::Runtime,
            explicit: Option<&fandhe_container_oci::image_management::ImageStore>,
            name: &str,
        ) -> Result<DeleteResponse, OciRuntimeError> {
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            let req = build_delete_request(&delete_args(name, false)).expect("req");
            delete_with_recorded_image_root(
                rt.store.as_ref(),
                &rt.recorder,
                &remover,
                explicit,
                None,
                &req,
                Instant::now(),
            )
        }

        /// 別インスタンスで開き直したストアから見た参照（永続化された状態）。
        fn persisted_refs(base: &TmpDir) -> Vec<String> {
            let fresh =
                fandhe_container_oci::image_management::ImageStore::open(&base.0.join("images"))
                    .expect("reopen");
            container_refs(&fresh)
        }

        /// OCI-7・OCI-5・CLI-1・#2499（条件 1）: create が状態記録へ残したストア root で、`--image-root` なしの delete が
        /// 参照を解除する（状態だけが消えて参照が残る経路を作らない）。
        #[test]
        fn oci7_delete_without_image_root_releases_recorded_reference() {
            let base = TmpDir::new("img-keep");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let recorded = rt
                .store
                .get(&GetStateRequest::new(id("c1")))
                .expect("record")
                .annotations()
                .get(IMAGE_ROOT_ANNOTATION)
                .map(str::to_owned);
            let canonical = std::fs::canonicalize(base.0.join("images")).expect("canonical");
            assert_eq!(recorded.as_deref(), canonical.to_str());
            assert_eq!(
                container_refs(&image.store),
                vec![format!("{}.c1", scope_of(&base))]
            );
            let resp = delete_recorded(&rt, None, "c1").expect("delete");
            assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
            assert_eq!(
                rt.store
                    .get(&GetStateRequest::new(id("c1")))
                    .expect_err("gone")
                    .code(),
                ErrorCode::NotFound
            );
            assert_eq!(persisted_refs(&base), Vec::<String>::new());
        }

        /// 読み取りだけが Timeout で失敗する状態ストア（ロック競合の模擬）。
        struct GetTimeoutStore(FileStateStore);

        impl StateStore for GetTimeoutStore {
            fn create(
                &self,
                r: &fandhe_container_core::traits::CreateStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                self.0.create(r)
            }
            fn update(
                &self,
                r: &fandhe_container_core::traits::UpdateStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                self.0.update(r)
            }
            fn get(
                &self,
                _r: &GetStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Timeout, "lock timeout"))
            }
            fn list(
                &self,
                r: &fandhe_container_core::traits::ListStateRequest,
            ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
                self.0.list(r)
            }
            fn delete(
                &self,
                r: &fandhe_container_core::traits::DeleteStateRequest,
            ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError>
            {
                self.0.delete(r)
            }
            fn host_state_root(&self) -> Option<&std::path::Path> {
                self.0.host_state_root()
            }
        }

        /// OCI-7・REPAIR-4・#2499: 記録の読み取りが Timeout で失敗したら、状態も参照も残して core に入る前に失敗する。
        #[test]
        fn oci7_delete_fails_closed_when_record_read_times_out() {
            let base = TmpDir::new("img-get-timeout");
            let rt = runtime_with(store(&base));
            create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let wrapped = GetTimeoutStore(store(&base));
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            let err = delete_with_recorded_image_root(
                &wrapped,
                &OpRecorder::new(),
                &remover,
                None,
                None,
                &req,
                Instant::now(),
            )
            .expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::Timeout);
            assert!(store(&base).get(&GetStateRequest::new(id("c1"))).is_ok());
            assert_eq!(persisted_refs(&base).len(), 1);
        }

        /// OCI-7・#2499: 旧 scope のキーで残った参照も、delete が新 scope の解除に続けて外す。
        #[test]
        fn oci7_delete_releases_reference_under_legacy_scope() {
            let base = TmpDir::new("img-legacy-scope");
            let rt = runtime_with(store(&base));
            let legacy = "0123456789abcdef0123456789abcdef";
            let image = crate::commands::create_start::CreateImage {
                store: images_store(&base, true),
                manifest: ref_digest(),
                scope: legacy.to_owned(),
                legacy_scope: None,
            };
            let req = CreateRequest::new(id("c1"), make_bundle(&base)).expect("req");
            crate::commands::create_start::create_container_with_image_reclaiming(
                &rt, &image, &req,
            )
            .expect("create");
            assert_eq!(container_refs(&image.store), vec![format!("{legacy}.c1")]);
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            let dreq = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_with_recorded_image_root(
                rt.store.as_ref(),
                &rt.recorder,
                &remover,
                None,
                Some(legacy),
                &dreq,
                Instant::now(),
            )
            .expect("delete");
            assert_eq!(persisted_refs(&base), Vec::<String>::new());
            // REPAIR-4: 旧 scope の解除も `image_ref_release` として計測される（現行 scope の登録が無いので core 側の記録は無く、この 1 件）。
            let stats = rt
                .recorder
                .snapshot_op(&OpName::new("image_ref_release").expect("name"))
                .expect("recorded");
            assert_eq!((stats.success(), stats.failure()), (1, 0));
        }

        /// OCI-7・#2499（条件 2）: 記録で解除した delete の後は、同じ ID・同じ digest の再 create が成功する。
        #[test]
        fn oci7_recreate_after_delete_without_image_root_succeeds() {
            let base = TmpDir::new("img-recreate");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            delete_recorded(&rt, None, "c1").expect("delete");
            recreate(&rt, &image, &base, "c1").expect("recreate");
            assert_eq!(
                persisted_refs(&base),
                vec![format!("{}.c1", scope_of(&base))]
            );
        }

        /// OCI-7・#2499（条件 3）: 記録と違うストアを `--image-root` に渡した delete は `FAILED_PRECONDITION` で拒否し、
        /// 状態も参照も残す。記録と同じストアなら成功する。
        #[test]
        fn oci7_delete_with_other_image_root_is_rejected() {
            use fandhe_container_oci::image_management::ImageStore;
            let base = TmpDir::new("img-other-image-root");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let other = base.0.join("images-b");
            std::fs::create_dir_all(&other).expect("mkdir");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            let store_b = ImageStore::open(&other).expect("open b");
            let e = delete_recorded(&rt, Some(&store_b), "c1").expect_err("mismatch");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            assert!(rt.store.get(&GetStateRequest::new(id("c1"))).is_ok());
            assert_eq!(
                persisted_refs(&base),
                vec![format!("{}.c1", scope_of(&base))]
            );
            let resp = delete_recorded(&rt, Some(&image.store), "c1").expect("same root");
            assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
            assert_eq!(persisted_refs(&base), Vec::<String>::new());
        }

        /// OCI-7・#2499（条件 4）: 在庫が空で `@container-refs.json` だけが残るストア（別プロセスが永続化した状態）でも、
        /// 記録の root から開き直して参照を解除できる。
        #[test]
        fn oci7_delete_releases_reference_persisted_without_inventory() {
            let base = TmpDir::new("img-no-inventory");
            let rt = runtime_with(store(&base));
            let _image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let inventory = base.0.join("images").join("@image-inventory.json");
            let _ = std::fs::remove_file(&inventory);
            assert!(!inventory.exists());
            let resp = delete_recorded(&rt, None, "c1").expect("delete");
            assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
            // 開き直したストアで、登録そのものが無いこと（在庫に依らない確認）。
            use fandhe_container_oci::image_management::ContainerRefId;
            let fresh =
                fandhe_container_oci::image_management::ImageStore::open(&base.0.join("images"))
                    .expect("reopen");
            let key = ContainerRefId::new(&crate::commands::image_refs::ref_key(
                &scope_of(&base),
                "c1",
            ))
            .expect("key");
            assert_eq!(
                fresh.container_ref_registration(&key).expect("lookup"),
                None
            );
        }

        /// OCI-7・#2499: 記録を持たない（イメージ無し・古い）コンテナは従来どおり。`--image-root` なしは通常の delete で
        /// `image_ref` は対象外、ありなら解除を試みる（登録が無ければ `AlreadyAbsent`）。
        #[test]
        fn oci7_delete_without_record_keeps_legacy_behavior() {
            let base = TmpDir::new("img-legacy");
            let rt = runtime_with(store(&base));
            do_create(&base, &store(&base), &OpRecorder::new(), "c1");
            do_create(&base, &store(&base), &OpRecorder::new(), "c2");
            let resp = delete_recorded(&rt, None, "c1").expect("plain");
            assert_eq!(resp.image_ref(), CleanupOutcome::NotApplicable);
            let images = images_store(&base, true);
            let resp = delete_recorded(&rt, Some(&images), "c2").expect("explicit");
            assert_eq!(resp.image_ref(), CleanupOutcome::AlreadyAbsent);
        }

        /// OCI-7・#2499: 記録の値は信頼しない。絶対パスでない値は `INTERNAL`、存在しない root は `NOT_FOUND` で拒否し、
        /// どちらも状態を残す。
        #[test]
        fn oci7_delete_rejects_invalid_recorded_image_root() {
            use fandhe_container_core::traits::{Annotations, CreateStateRequest};
            let base = TmpDir::new("img-bad-record");
            let rt = runtime_with(store(&base));
            let missing = base.0.join("no-such-images");
            for (name, value, code) in [
                ("c1", "relative/path".to_string(), ErrorCode::Internal),
                (
                    "c2",
                    missing.to_string_lossy().into_owned(),
                    ErrorCode::NotFound,
                ),
            ] {
                let status = ContainerStatus::created(id(name), None);
                let req = CreateStateRequest::new(status, make_bundle(&base))
                    .expect("req")
                    .with_annotations(
                        Annotations::new([(IMAGE_ROOT_ANNOTATION.to_string(), value)])
                            .expect("ann"),
                    );
                rt.store.create(&req).expect("create state");
                let e = delete_recorded(&rt, None, name).expect_err("rejected");
                assert_eq!(e.code(), code, "{name}");
                assert!(rt.store.get(&GetStateRequest::new(id(name))).is_ok());
            }
        }

        /// OCI-7・#2315: 別の状態ルートの同名コンテナの `--image-root` つき delete は、状態ルート A の参照を外さない。
        #[test]
        fn oci7_delete_from_other_state_root_keeps_reference() {
            let base = TmpDir::new("img-other-root");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let root_b = StateRoot::from_override(base.0.join("state-b")).expect("root b");
            let store_b = FileStateStore::open(root_b.clone()).expect("open b");
            do_create(&base, &store_b, &OpRecorder::new(), "c1");
            let remover = DetectedCgroupRemover::new(|| Ok(FakeCgroup::default()));
            let req = build_delete_request(&delete_args("c1", false)).expect("req");
            delete_container_releasing_image_ref(
                &store_b,
                &OpRecorder::new(),
                &remover,
                &image.store,
                &crate::commands::image_refs::state_scope(&store_b).expect("scope b"),
                &req,
            )
            .expect("delete in b");
            assert_eq!(
                container_refs(&image.store),
                vec![format!("{}.c1", scope_of(&base))]
            );
        }

        fn ref_generation(
            images: &fandhe_container_oci::image_management::ImageStore,
            base: &TmpDir,
            name: &str,
        ) -> Option<u64> {
            use fandhe_container_oci::image_management::ContainerRefId;
            let key =
                ContainerRefId::new(&crate::commands::image_refs::ref_key(&scope_of(base), name))
                    .expect("key");
            let unbound = {
                let guard = images.lock().expect("lock");
                guard
                    .unbound_containers()
                    .find(|(k, _, _)| **k == key)
                    .map(|(_, g, _)| g.as_raw())
            };
            unbound.or_else(|| {
                images
                    .container_ref_registration(&key)
                    .expect("registration")
                    .map(|g| g.as_raw())
            })
        }

        fn register_unbound(
            images: &fandhe_container_oci::image_management::ImageStore,
            base: &TmpDir,
            name: &str,
        ) {
            use fandhe_container_oci::image_management::ContainerRefId;
            use fandhe_container_oci::reference::Digest;
            let key =
                ContainerRefId::new(&crate::commands::image_refs::ref_key(&scope_of(base), name))
                    .expect("key");
            images
                .register_container_ref(&key, &Digest::parse(REF_MANIFEST).expect("digest"))
                .expect("register");
        }

        fn recreate(
            rt: &crate::commands::create_start::Runtime,
            image: &crate::commands::create_start::CreateImage,
            base: &TmpDir,
            name: &str,
        ) -> Result<fandhe_container_core::traits::StateRecord, OciRuntimeError> {
            let req = CreateRequest::new(id(name), make_bundle(base)).expect("req");
            crate::commands::create_start::create_container_with_image_reclaiming(rt, image, &req)
        }

        fn image_of(
            base: &TmpDir,
            images: fandhe_container_oci::image_management::ImageStore,
        ) -> crate::commands::create_start::CreateImage {
            crate::commands::create_start::CreateImage {
                store: images,
                manifest: ref_digest(),
                scope: scope_of(base),
                legacy_scope: None,
            }
        }

        /// OCI-7・#2495: `--image-root` なしの delete が残した確定済み参照は、同じ ID の再 create の前に回収され、
        /// 再 create が成功する（世代は旧 +1）。
        #[test]
        fn oci7_create_reclaims_ref_left_by_delete_without_image_root() {
            let base = TmpDir::new("img-reclaim-bound");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            let old = ref_generation(&image.store, &base, "c1").expect("bound");
            delete_with(&store(&base), &OpRecorder::new(), "c1", false).expect("delete");
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old));
            recreate(&rt, &image, &base, "c1").expect("recreate");
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old + 1));
            assert_eq!(
                container_refs(&image.store),
                vec![format!("{}.c1", scope_of(&base))]
            );
        }

        /// OCI-7・#2495: register 後のクラッシュ（状態なし・未確定参照）の後でも、同じ ID の再 create が成功する。
        #[test]
        fn oci7_recreate_after_crash_after_register() {
            let base = TmpDir::new("img-crash-register");
            let rt = runtime_with(store(&base));
            let images = images_store(&base, true);
            register_unbound(&images, &base, "c1");
            let old = ref_generation(&images, &base, "c1").expect("unbound");
            let image = image_of(&base, images);
            recreate(&rt, &image, &base, "c1").expect("recreate");
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old + 1));
        }

        /// OCI-7・#2495: bind 失敗後（状態あり・参照は未確定）は ALREADY_EXISTS で塞がれるが、状態の削除後は回収されて
        /// 再 create が成功する（恒久的に塞がない）。状態が残る間は参照も触れない。
        #[test]
        fn oci7_present_unbound_does_not_block_forever() {
            let base = TmpDir::new("img-bind-fail");
            let rt = runtime_with(store(&base));
            let images = images_store(&base, true);
            register_unbound(&images, &base, "c1");
            let old = ref_generation(&images, &base, "c1").expect("unbound");
            do_create(&base, &store(&base), &OpRecorder::new(), "c1");
            let image = image_of(&base, images);
            let e = recreate(&rt, &image, &base, "c1").expect_err("present");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old));
            delete_with(&store(&base), &OpRecorder::new(), "c1", false).expect("delete");
            recreate(&rt, &image, &base, "c1").expect("recreate");
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old + 1));
        }

        /// OCI-7・#2495: 別プロセス相当（別インスタンス）が create ゲートの共有を保持している間は未確定参照を回収せず、
        /// 終わった後の再試行は成功する。
        #[test]
        fn oci7_unbound_ref_kept_while_create_in_progress() {
            use fandhe_container_oci::image_management::ImageStore;
            let base = TmpDir::new("img-in-progress");
            let rt = runtime_with(store(&base));
            let images = images_store(&base, true).with_timeout(Duration::from_millis(100));
            register_unbound(&images, &base, "c1");
            let old = ref_generation(&images, &base, "c1").expect("unbound");
            let holder = ImageStore::open(&base.0.join("images")).expect("holder");
            let pass = holder.enter_container_create().expect("pass");
            let image = image_of(&base, images);
            let e = recreate(&rt, &image, &base, "c1").expect_err("in progress");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old));
            drop(pass);
            recreate(&rt, &image, &base, "c1").expect("recreate");
            assert_eq!(ref_generation(&image.store, &base, "c1"), Some(old + 1));
        }

        /// OCI-7・#2315: 在庫に無い manifest の create は NOT_FOUND で、状態も参照も残らない
        /// （本番の現行値。在庫の永続化は #2380 で済みだが、在庫を埋める cri の pull は #2539 で配線済みで、本番の `PullImage` へも #2592 で届く。pull していない root では空）。
        #[test]
        fn oci7_create_with_empty_inventory_is_not_found() {
            let base = TmpDir::new("img-empty");
            let rt = runtime_with(store(&base));
            let images = images_store(&base, false);
            let e = create_image(&base, &rt, images, "c1").err().expect("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(
                rt.store
                    .get(&GetStateRequest::new(id("c1")))
                    .expect_err("none")
                    .code(),
                ErrorCode::NotFound
            );
        }
    }
}
