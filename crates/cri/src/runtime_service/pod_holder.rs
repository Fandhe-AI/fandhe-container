//! pod の namespace の保持役（`PodNamespaceHolderProvider`）を sandbox のライフサイクルへ組み込む段
//! （#2871・CRI-2・CORE-3・REPAIR-5。設計は `docs/design/pod-namespace-holder.md`、実装単位 H4）。
//!
//! 役割: `runtime_service` の `RunPodSandbox`（起動）・`StopPodSandbox` / `RemovePodSandbox`（解放）・
//! `PodSandboxStatus` / `ListPodSandbox` / `CreateContainer`（死活の反映）から呼ばれ、provider の呼び出しを
//! 期限つきの worker で行い、結果を `SandboxRecord` の `pod_holder` / `holder_*` へロック下で確定する。
//! network の `set_up` / `tear_down` の段（`SetUpSettlement`・`NetworkTearDownGuard`）と同じ形にそろえてある。
//!
//! 契約: provider の呼び出しはレジストリのロックを保ったまま行わない。保持役の pid は sandbox 記録の
//! メモリ上にだけ置く（記録ファイルへの永続化と素性の照合は R11〔#2940〕）。
//!
//! **未実装・簡易実装（REPAIR-3）**: 本番の provider は H6〔#2877〕。pid から namespace のパスを作って
//! bundle へ渡す配線は H5〔#2876〕で `reserve_container` に実装済み。ここは注入点と記録の保持、解放の冪等・再試行、死活の反映まで。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::adapter::{PodHolderLiveness, PodHolderRequest, PodNamespaceHolderProvider};
use crate::error::CriError;

use super::{
    CriRuntimeService, OpDeadline, SandboxRegistry, SandboxState, SetUpSettlement, run_bounded,
    step_within,
};

/// provider の `spawn` / `release` の契約上の上限（`ready_timeout` / `timeout`）に足す外側の余裕。
/// provider が契約どおり先に戻る前提で、外側の待ちは契約違反（ハング）に対する歯止めにすぎない（REPAIR-5）。
const HOLDER_OUTER_SLACK: Duration = Duration::from_millis(500);

/// `spawn_pod_holder` の失敗。`clear` が真なら保持役は残っていないと確かめられた（呼び出し側は予約を
/// 巻き戻して sandbox を登録しない）。偽なら保持役が残りうる・まだ起動中で、記録を NotReady で残す。
pub(super) struct HolderSpawnFailure {
    pub(super) err: CriError,
    pub(super) clear: bool,
}

/// `spawn` の worker が正常に確定できないまま終わった（panic・起動されないままの破棄）とき、
/// `holder_pending` を解除する guard。worker が走った後の異常終了は保持役が残りうる印（`holder_owned`・
/// NotReady）へ倒し、走らなかったなら資源は無いので印を付けない（`NetworkSetUpGuard` と同じ形）。
struct HolderSpawnGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
    ran: Arc<AtomicBool>,
    /// worker が結果の確定まで正常に終えたら真（以後の `holder_pending` は呼び出し側の受領が解除する）。
    settled: bool,
}

impl Drop for HolderSpawnGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
            && record.holder_pending
        {
            record.holder_pending = false;
            if self.ran.load(Ordering::SeqCst) {
                record.holder_owned = true;
                record.state = SandboxState::NotReady;
            }
        }
    }
}

/// `release` の worker が終わるまで `holder_release` を保つ guard（期限超過で RPC が先に返っても、
/// worker の終了〔panic 含む〕で解除される。重複起動の拒否。REPAIR-5）。
struct HolderReleaseGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
}

impl Drop for HolderReleaseGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
        {
            record.holder_release = false;
        }
    }
}

/// `spawn_pod_holder` の future が起動待ちの途中で破棄されたとき、settlement を放棄する guard。
/// 放棄しないと切り離された worker が後から成功して Ready を公開し、確定版の記録なしに CreateContainer が通る
/// （CRI-2 の fail-closed 違反）。放棄後の成功は `pod_holder`・`holder_owned` だけ記録し NotReady に保つ。
///
/// worker が既に確定していた（結果の受領前に future が破棄された）場合は、worker が `holder_pending` を
/// 保ったままのため、ここで解除して NotReady へ倒す（解除しないと Stop・Remove が永久に拒否される。
/// 保持役は `holder_owned` で追跡済みなので Stop・Remove が解放できる）。受領後は `disarm` する。
struct SettlementAbandonOnDrop {
    settlement: Arc<SetUpSettlement>,
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
    armed: bool,
}

impl Drop for SettlementAbandonOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // 放棄に勝てば worker が後で `holder_pending` を解除する。負けた（worker が確定済み）なら自分で解除する。
        if !self.settlement.abandon()
            && let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
            && record.holder_pending
        {
            record.holder_pending = false;
            record.state = SandboxState::NotReady;
        }
    }
}

/// 保持役の起動後〜確定版の記録の書き込みが終わるまでの間に RunPodSandbox の future が破棄されたとき、
/// Ready を公開したままにせず NotReady へ戻す guard（確定版が書けていない sandbox に CreateContainer を
/// 通さない。CRI-2 の fail-closed・REPAIR-5）。成功したら `disarm` する。
pub(super) struct ReadyRevertOnDrop {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
    armed: bool,
}

impl ReadyRevertOnDrop {
    pub(super) fn new(registry: Arc<Mutex<SandboxRegistry>>, id: &str) -> Self {
        Self {
            registry,
            id: id.to_owned(),
            armed: true,
        }
    }

    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ReadyRevertOnDrop {
    fn drop(&mut self) {
        if self.armed
            && let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
            && record.state == SandboxState::Ready
        {
            record.state = SandboxState::NotReady;
        }
    }
}

impl CriRuntimeService {
    /// 保持役を起動して記録へ確定する（`RunPodSandbox` から、write-ahead の後に呼ぶ）。
    ///
    /// worker で `provider.spawn` を呼び、`runtime_timeout`（+ 余裕）で打ち切る。成功は worker がロック下で
    /// `pod_holder`・`holder_owned` を確定し、`publish_ready` なら結果の受領後に呼び出し側が Ready にする（network を伴う経路は
    /// `set_up` が Ready にするので偽）。外側の期限超過で呼び出し側が先に手放した（provider の契約違反）場合、
    /// 遅れて成功した保持役は記録にだけ残す（NotReady のまま `holder_owned`。Stop・Remove が解放する）。
    /// 動いている資源が無いと確かめられたときだけ `clear`（登録しない）にする fail-closed。
    pub(super) async fn spawn_pod_holder(
        &self,
        provider: &Arc<dyn PodNamespaceHolderProvider>,
        id: &str,
        publish_ready: bool,
    ) -> Result<(), HolderSpawnFailure> {
        let unavailable = |err: CriError| HolderSpawnFailure { err, clear: false };
        let config =
            {
                let mut registry = self.registry.lock().map_err(|_| {
                    unavailable(CriError::internal("sandbox registry is unavailable"))
                })?;
                let record = registry.records.get_mut(id).ok_or_else(|| {
                    unavailable(CriError::internal("sandbox record is unavailable"))
                })?;
                // 予約時に立てた印を保つ（保持役の起動から結果の受領までの間、Stop・Remove を拒否する）。
                record.holder_pending = true;
                record.config.clone()
            };
        let ran = Arc::new(AtomicBool::new(false));
        let guard = HolderSpawnGuard {
            registry: Arc::clone(&self.registry),
            id: id.to_owned(),
            ran: Arc::clone(&ran),
            settled: false,
        };
        let settlement = Arc::new(SetUpSettlement::new());
        let worker_settlement = Arc::clone(&settlement);
        let mut abandon_on_drop = SettlementAbandonOnDrop {
            settlement: Arc::clone(&settlement),
            registry: Arc::clone(&self.registry),
            id: id.to_owned(),
            armed: true,
        };
        let worker_provider = Arc::clone(provider);
        let worker_registry = Arc::clone(&self.registry);
        let worker_id = id.to_owned();
        let worker_ran = Arc::clone(&ran);
        let ready_timeout = self.runtime_timeout;
        let result = run_bounded(self.runtime_timeout + HOLDER_OUTER_SLACK, move || {
            let mut guard = guard;
            worker_ran.store(true, Ordering::SeqCst);
            let result =
                worker_provider.spawn(&PodHolderRequest::new(&worker_id, &config, ready_timeout));
            if let Ok(mut registry) = worker_registry.lock()
                && let Some(record) = registry.records.get_mut(&worker_id)
            {
                // 手放しとの競合の決着だけを取る。Ready は worker では公開しない（結果の受領前に呼び出し側が
                // 破棄されても Ready が残らないよう、呼び出し側が受領と同じ同期区間で公開する）。
                let settled = worker_settlement.settle_by_worker();
                if let Ok(holder) = &result {
                    record.pod_holder = Some(*holder);
                    record.holder_owned = true;
                } else if let Err(e) = &result
                    && e.resource_retained()
                {
                    // 回収を確認できない子が provider に残る。記録を残して Stop・Remove の `release` に再試行させる。
                    record.holder_owned = true;
                }
                // 成功を呼び出し側が受領できる（確定に勝った）間は `holder_pending` を保ち、受領と同じ同期区間で
                // 呼び出し側が解除する（解除と Ready 公開の間に Stop が解放できる窓を作らない）。
                // 失敗・手放し後の完了では worker が解除する（手放し後は NotReady のまま `holder_owned` で追跡）。
                if result.is_err() || !settled {
                    record.holder_pending = false;
                    if !settled {
                        record.state = SandboxState::NotReady;
                    }
                }
                guard.settled = true;
            }
            result
        })
        .await
        .and_then(|r| r.map(|_| ()));
        // 以降は await を挟まない（future の破棄で guard が走る窓を作らない）。
        abandon_on_drop.armed = false;
        let Err(err) = result else {
            // 結果を受領した。保持役の起動中の印を外し、同じ同期区間で Ready を公開する。
            if let Ok(mut registry) = self.registry.lock()
                && let Some(record) = registry.records.get_mut(id)
            {
                record.holder_pending = false;
                if publish_ready && record.pod_holder.is_some() && record.holder_owned {
                    record.state = SandboxState::Ready;
                }
            }
            return Ok(());
        };
        // 期限超過の判定から記録を取るまでの間に worker が成功を確定していたら成功として扱う
        // （手放しに勝てなかった場合。Ready を公開したまま失敗を返す食い違いを作らない）。
        let abandoned = settlement.abandon();
        let Ok(mut registry) = self.registry.lock() else {
            return Err(unavailable(err));
        };
        let Some(record) = registry.records.get_mut(id) else {
            return Err(unavailable(err));
        };
        if !abandoned && record.pod_holder.is_some() && record.holder_owned {
            // 通常の成功経路と同じく、ここでも印を外して Ready を公開する（worker は Ready を公開しないため、
            // 省くと network なしの RunPodSandbox が成功しても NotReady のまま残り CreateContainer が拒否される。CRI-2）。
            record.holder_pending = false;
            if publish_ready {
                record.state = SandboxState::Ready;
            }
            return Ok(());
        }
        let clear = !record.holder_owned && !record.holder_pending;
        Err(HolderSpawnFailure { err, clear })
    }

    /// 保持役の解放を `Run` の巻き戻しとして行う。残りうるなら偽（呼び出し側は記録を残して Stop・Remove に任せる）。
    pub(super) async fn rollback_pod_holder(&self, id: &str) -> bool {
        self.release_pod_holder(id, None).await.is_ok()
    }

    /// 資源が残りうる保持役を解放し、成功したら記録の印を外す（Stop・Remove から呼ぶ。冪等）。
    ///
    /// 注入が無い・印が無い場合は何もしない（2 回目の Stop は `release` を呼ばない）。起動中・解放中は
    /// `FAILED_PRECONDITION`。失敗・期限超過では `holder_owned` を残し、再試行できる。
    pub(super) async fn release_pod_holder(
        &self,
        sandbox_id: &str,
        deadline: Option<&OpDeadline>,
    ) -> Result<(), CriError> {
        let Some(provider) = &self.pod_holder else {
            return Ok(());
        };
        let timeout = step_within(deadline, self.runtime_timeout)?;
        let guard = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let Some(record) = registry.records.get_mut(sandbox_id) else {
                return Ok(());
            };
            if record.holder_pending || record.holder_release {
                return Err(CriError::failed_precondition(
                    "sandbox holder startup or release is in progress",
                ));
            }
            if !record.holder_owned {
                return Ok(());
            }
            record.holder_release = true;
            HolderReleaseGuard {
                registry: Arc::clone(&self.registry),
                id: sandbox_id.to_owned(),
            }
        };
        let provider = Arc::clone(provider);
        let registry = Arc::clone(&self.registry);
        let id = sandbox_id.to_owned();
        // 共有期限がある（Remove 等）ときは外側の待ちを残り期限ぴったりで頭打ちにし、provider へは
        // 余裕分（残りの半分を上限）を引いた猶予を渡して契約どおり先に戻れるようにする（#3142・REPAIR-5）。
        // 期限が無いとき（Stop 単独の内部呼び出し等）は従来どおり外側に余裕を足す。
        let (provider_timeout, outer) = if deadline.is_some() {
            (timeout - HOLDER_OUTER_SLACK.min(timeout / 2), timeout)
        } else {
            (timeout, timeout + HOLDER_OUTER_SLACK)
        };
        run_bounded(outer, move || {
            let _guard = guard;
            let result = provider.release(&id, provider_timeout);
            if result.is_ok()
                && let Ok(mut registry) = registry.lock()
                && let Some(record) = registry.records.get_mut(&id)
            {
                record.holder_owned = false;
                record.pod_holder = None;
            }
            result
        })
        .await
        .and_then(|r| r)
    }

    /// 保持役の起動・解放の最中、または provider 未注入のまま解放待ちの記録なら `FAILED_PRECONDITION`
    /// （Stop・Remove の入口の検査。未知 ID・空 ID は何もしない。CRI-2 の fail-closed）。
    pub(super) fn ensure_holder_operable(&self, id: &str) -> Result<(), CriError> {
        if id.is_empty() {
            return Ok(());
        }
        let registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let Some(record) = registry.records.get(id) else {
            return Ok(());
        };
        if record.holder_pending || record.holder_release {
            return Err(CriError::failed_precondition(
                "sandbox holder startup or release is in progress",
            ));
        }
        if self.pod_holder.is_none() && record.holder_owned {
            return Err(CriError::failed_precondition(
                "sandbox holder cannot be released without a holder provider",
            ));
        }
        Ok(())
    }

    /// Ready の sandbox の保持役の死活を照会し、死んだ・判定不能なものを NotReady にする（一方向。Ready へは戻さない）。
    ///
    /// provider の呼び出しはロックの外で行う（`liveness` はブロックしない契約。件数は `max_sandboxes` で有界）。
    /// 書き戻すのは、照会した時点と同じ pid の記録だけ（照会の間に解放・再作成された記録を巻き込まない）。
    /// 判定不能（`Err`）も fail-closed に NotReady へ倒す。
    pub(super) fn reconcile_holders(&self, only: Option<&str>) {
        let Some(provider) = &self.pod_holder else {
            return;
        };
        let candidates: Vec<_> = match self.registry.lock() {
            Ok(registry) => registry
                .records
                .iter()
                .filter(|(id, r)| {
                    only.is_none_or(|o| o == id.as_str())
                        && r.state == SandboxState::Ready
                        && r.holder_owned
                        && !r.holder_release
                })
                .filter_map(|(id, r)| r.pod_holder.map(|h| (id.clone(), h)))
                .collect(),
            Err(_) => return,
        };
        let down: Vec<_> = candidates
            .into_iter()
            .filter(|(id, _)| !matches!(provider.liveness(id), Ok(PodHolderLiveness::Alive)))
            .collect();
        if down.is_empty() {
            return;
        }
        if let Ok(mut registry) = self.registry.lock() {
            for (id, holder) in down {
                if let Some(record) = registry.records.get_mut(&id)
                    && record.pod_holder == Some(holder)
                    && record.state == SandboxState::Ready
                {
                    record.state = SandboxState::NotReady;
                }
            }
        }
    }
}
