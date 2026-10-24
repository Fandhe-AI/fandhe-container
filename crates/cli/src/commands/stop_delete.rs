//! `stop` / `delete` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.2・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_stop`] / [`run_delete`] を呼ぶ。実処理は core の
//! `oci_runtime::kill` / `oci_runtime::delete`（OCI-6・CORE-2・TASK-30）へ委ね、ID の文字種検証も
//! core の型（`ContainerId`）を唯一の判定とする。状態ルートの解決・状態ストアの組み立ては
//! `create_start::production_runtime` を共用する。
//!
//! 設計判断（fail-closed）:
//! - `stop` は core の `kill` に `SIGTERM` で写像する。core に stop（猶予 → SIGKILL）は無い。
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
//! 削除は supervisor ログ → コンテナログの直列で、各 5 秒が上限（最悪 10 秒）。
//!
//! 状態ルートが無ければ `production_runtime` の状態ストアを開く段階で親の下に 0700 で作る（親は作らない）。
//! list / logs と同じ判断で、読み取り専用 open は足さない（理由は `list_logs` の module doc。#1607 E2）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - `delete --image-root <abs>` は core の `delete_releasing_image_ref` で OCI-7 のイメージ参照を外す（#2315）。ストアは core に入る前に
//!   開き、開けなければ状態を消さずに失敗する。`--image-root` を省いた delete では確定済みの参照が残り、回収は次の契機で行う
//!   （同じ ID の `create --image-root` の core 呼び出し前、または `image rm` が使用中で拒否したとき。`ref_reconcile` の module doc・#2495。
//!   安全側でデータは消えない）。
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
//!   無害）、`kill` コマンド（#1902。[`production_signaler`] を使い、意図は立てない）は未実装。
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
//!   `plugin_backend` を呼び、現状は必ず fail-closed で失敗する（起動と RPC は #1869 の設計〔docs/design/plugin-backend-wiring.md。承認待ち・実装 issue は未起票〕・TASK-125）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    ContainerCgroupRemover, KillTimeout, LifecycleOp, OciRuntimeError, ProcessSignaler, delete,
    delete_releasing_image_ref, kill,
};
use fandhe_container_core::traits::{
    CleanupOutcome, ContainerId, ContainerState, ContainerStatus, DeleteRequest, DeleteResponse,
    ErrorCode, GetStateRequest, KillRequest, Signal, StateStore, TraitError,
};
// 試験が `use super::*` 経由で使う型（本番の経路では使わない）。
#[cfg(all(test, target_os = "linux"))]
use fandhe_container_core::oci_runtime::CgroupRemoval;
#[cfg(test)]
use fandhe_container_core::traits::{CgroupPlacement, CgroupScope, StateRevision};

use super::CliExit;
use super::args::{DeleteArgs, GlobalArgs, StopArgs};
use super::create_start::{OP_LOG_ENV, export_ops, production_runtime, require_local_backend};
use super::image::open_image_store_for_lifecycle;
use super::image_refs::{StoreImageRefs, state_scope};
use fandhe_container_oci::image_management::ImageStore;

// 本番の signaler・cgroup remover は supervisor crate にある（plugin-cri の `kill`・`stop`・`delete` と共有するため
// CLI の private 実装から移した。#2434・REPAIR-1）。`production_signaler` は `kill` コマンド（#1902）が入るまで試験だけが使う。
#[cfg(all(test, not(target_os = "linux")))]
use fandhe_container_supervisor::cgroup_remover::UnavailableCgroupRemover;
use fandhe_container_supervisor::cgroup_remover::production_cgroup_remover;
#[cfg(all(test, target_os = "linux"))]
use fandhe_container_supervisor::cgroup_remover::{DetectedCgroupRemover, detect_error};
#[cfg(test)]
use fandhe_container_supervisor::control::UnavailableSignaler;
#[cfg(all(test, target_os = "linux"))]
use fandhe_container_supervisor::control::production_signaler;
use fandhe_container_supervisor::control::{
    CancelOutcome, PendingRestartCanceller, production_restart_canceller, production_stop_signaler,
};
use fandhe_container_supervisor::supervisor_log::{
    LogRemoval, SUPERVISOR_LOG_REMOVE_TIMEOUT, run_log_removal_bounded,
};

/// ID を core の型で検証し、`SIGTERM` の kill 要求を作る。
fn build_stop_request(args: &StopArgs) -> Result<KillRequest, TraitError> {
    Ok(KillRequest::new(
        ContainerId::new(args.id.as_str())?,
        Signal::SIGTERM,
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
                let store = open_image_store_for_lifecycle(root)?;
                // 参照キーに状態ルートを含め、別の状態ルートの同名コンテナの参照を外さない（OCI-7）。
                let scope = state_scope(&fandhe_container_core::state_store::StateRoot::resolve(
                    global.root.clone(),
                )?);
                Ok::<_, TraitError>((store, scope))
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
    let result = match &images {
        Some((images, scope)) => delete_container_releasing_image_ref(
            rt.store.as_ref(),
            &rt.recorder,
            &remover,
            images,
            scope,
            &req,
        ),
        None => delete_container(rt.store.as_ref(), &rt.recorder, &remover, &req),
    };
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(resp) => {
            if let Some(warning) = image_rootfs_removal_warning(resp.image_rootfs()) {
                emit_warning_bounded(warning, write_warning_to_stderr, WARNING_WRITE_TIMEOUT);
            }
            remove_supervisor_log(rt.store.as_ref(), &req);
            remove_container_log(rt.store.as_ref(), &req);
            CliExit::Success
        }
        Err(e) => CliExit::Runtime(e),
    }
}

/// イメージ由来 rootfs を残した場合の警告（stderr に 1 行の JSON。ERR-1・OCI-7・#2633）。
///
/// `Kept` のときだけ `Some`。パス・errno・ID は含めず、`code` で理由を見分ける。残った木は手動で消す
/// （`docs/design/image-rootfs-lifetime.md`）。
fn image_rootfs_removal_warning(outcome: CleanupOutcome) -> Option<String> {
    match outcome {
        CleanupOutcome::Kept { code } => Some(format!(
            "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"image rootfs removal failed; leftover rootfs may remain\"}}",
            code.as_str()
        )),
        _ => None,
    }
}

/// 期限切れの警告（stderr に 1 行の JSON。`code` / `message` は ERR-1 の形）。
fn log_removal_timeout_warning() -> &'static str {
    "{\"level\":\"warn\",\"code\":\"TIMEOUT\",\"message\":\"supervisor log removal did not finish within the deadline; leftover logs may remain\"}"
}

/// core の `delete` が成功した後に、supervisor の構造化ログ（`<root>/@supervisor-logs/<id>.log*`）を best effort で消す
/// （#2067・REPAIR-4）。削除は作業スレッドで [`SUPERVISOR_LOG_REMOVE_TIMEOUT`] まで待つ（REPAIR-5）。
///
/// 失敗しても delete の結果は変えず、成功時の stderr は空（ERR-2）。期限切れのときも delete は成功のまま
/// （状態の削除は完了済みで、ログは残っても次の start で世代として回るため）、警告を 1 行だけ stderr に出す。
/// supervisor が生存中でロックを取れない等で消せなかった分は、1 ID あたり世代数 × 上限（3 MiB）に収まる。
/// core の delete より前には消さない（delete が失敗したとき稼働中のログを消さないため）。
fn remove_supervisor_log(store: &dyn StateStore, req: &DeleteRequest) {
    let Some(root) = store.host_state_root() else {
        return;
    };
    let outcome = fandhe_container_supervisor::supervisor_log::remove_bounded(
        root,
        req.id(),
        SUPERVISOR_LOG_REMOVE_TIMEOUT,
    );
    if outcome == LogRemoval::TimedOut {
        emit_warning_bounded(
            log_removal_timeout_warning().to_string(),
            write_warning_to_stderr,
            WARNING_WRITE_TIMEOUT,
        );
    }
}

/// コンテナログ削除の失敗の警告（stderr に 1 行の JSON。ERR-1）。パス・errno・内容は含めない。
/// 期限切れ（`TIMEOUT`）も同じ文言で、`code` で見分ける。
fn container_log_removal_warning(e: &TraitError) -> String {
    format!(
        "{{\"level\":\"warn\",\"code\":\"{}\",\"message\":\"container log removal failed; leftover logs may remain\"}}",
        e.code().as_str()
    )
}

/// core の `delete` が成功した後に、コンテナログ（`<root>/@container-logs/<id>.log*`）を消す（#2446・SUP-7・CLI-1）。
///
/// 失敗しても delete の結果は変えず、警告を 1 行だけ stderr に出す（理由はモジュール doc）。core の delete より前には
/// 呼ばない（delete が失敗したとき稼働中のコンテナのログを消さないため）。
fn remove_container_log(store: &dyn StateStore, req: &DeleteRequest) {
    let Some(root) = store.host_state_root() else {
        return;
    };
    let guard_root = root.to_path_buf();
    let guard_id = req.id().clone();
    if let Err(e) = fandhe_container_supervisor::logs::remove_container_logs_guarded_bounded(
        root,
        req.id(),
        fandhe_container_supervisor::logs::CONTAINER_LOG_REMOVE_TIMEOUT,
        move || id_is_still_deleted(&guard_root, &guard_id),
    ) {
        emit_warning_bounded(
            container_log_removal_warning(&e),
            write_warning_to_stderr,
            WARNING_WRITE_TIMEOUT,
        );
    }
}

/// 状態ストアに `id` が無い（delete 後に再作成されていない）ときだけ `true`（#2446・SUP-7。同じ ID の再作成との排他）。
///
/// supervisor のログ削除がロックを取った後（同じ ID の sink が開けない状態）で評価される。再作成済みなら削除を
/// 見送り、新しいインスタンスのログを消さない。ストアを開けない・NotFound 以外の失敗は fail-closed で `false`。
fn id_is_still_deleted(
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
const WARNING_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// 本番の警告出力。`eprintln!` は書き込み失敗で panic するため使わず、エラーは捨てる（delete の成功を保つ）。
fn write_warning_to_stderr(line: &str) {
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
fn emit_warning_bounded(
    line: String,
    write: impl FnOnce(&str) + Send + 'static,
    timeout: Duration,
) {
    let _ = run_log_removal_bounded(move || write(&line), timeout);
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let w = container_log_removal_warning(&TraitError::new(
            ErrorCode::FailedPrecondition,
            "/secret/path",
        ));
        assert_eq!(
            w,
            "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"message\":\"container log removal failed; leftover logs may remain\"}"
        );
        let w = container_log_removal_warning(&TraitError::new(ErrorCode::Timeout, "x"));
        assert!(w.contains("\"code\":\"TIMEOUT\"") && !w.contains('\n') && !w.contains('/'));
    }

    /// ERR-1・OCI-7・#2633: rootfs を残したときだけ、code ごとに完全一致する 1 行 JSON の警告を作る。
    #[test]
    fn err1_image_rootfs_removal_warning_is_single_line_json() {
        let w = image_rootfs_removal_warning(CleanupOutcome::Kept {
            code: ErrorCode::FailedPrecondition,
        })
        .expect("kept warns");
        assert_eq!(
            w,
            "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"message\":\"image rootfs removal failed; leftover rootfs may remain\"}"
        );
        let w = image_rootfs_removal_warning(CleanupOutcome::Kept {
            code: ErrorCode::Unimplemented,
        })
        .expect("kept warns");
        assert!(w.contains("\"code\":\"UNIMPLEMENTED\"") && !w.contains('\n'));
        for quiet in [
            CleanupOutcome::Removed,
            CleanupOutcome::AlreadyAbsent,
            CleanupOutcome::NotApplicable,
        ] {
            assert_eq!(image_rootfs_removal_warning(quiet), None);
        }
    }

    fn stop_args(id: &str) -> StopArgs {
        StopArgs { id: id.into() }
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
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-cli-sd-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
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
            crate::commands::image_refs::state_scope(
                &StateRoot::from_override(state_root(base)).expect("root"),
            )
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

        /// OCI-7・#2315: `--image-root` なしの delete は確定済みの参照を残す（安全側。回収は照合を待つ）。
        #[test]
        fn oci7_delete_without_image_root_keeps_reference() {
            let base = TmpDir::new("img-keep");
            let rt = runtime_with(store(&base));
            let image = create_image(&base, &rt, images_store(&base, true), "c1").expect("create");
            delete_with(&store(&base), &OpRecorder::new(), "c1", false).expect("delete");
            assert_eq!(
                container_refs(&image.store),
                vec![format!("{}.c1", scope_of(&base))]
            );
            let gone = rt
                .store
                .get(&GetStateRequest::new(id("c1")))
                .expect_err("gone");
            assert_eq!(gone.code(), ErrorCode::NotFound);
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
                &crate::commands::image_refs::state_scope(&root_b),
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
        /// （本番の現行値。在庫の永続化は #2380 で済みだが、本番で在庫を埋める経路が未実装）。
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
