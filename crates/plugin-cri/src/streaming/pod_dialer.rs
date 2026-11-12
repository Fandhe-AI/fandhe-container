//! POD ネットワークの pod 向け `PortForwardDialer` の本番実装 `PodNetnsDialer`（Linux のみ。CRI-6・NET-3・SEC-1・REPAIR-5・
//! TASK-63.4・#4484。設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」）。
//!
//! 呼び出し元: cri の `PortForwardHandler` が `spawn_blocking` 上で `dial` を呼ぶ。`streaming::ProductionPortForward::pod_network` が
//! 保持役がある構成（Linux・非 root）だけで結線し（#4486。`supports_pod_network` は真）、保持役が無い構成は結線されず POD の PortForward は
//! RPC 時に `UNIMPLEMENTED` のまま。実 helper を通す実機の段 F は `tests/cri_exec_real.rs` で照合済み（#4487）。
//! NODE の target は `NodeLoopbackDialer` へ委ねる。
//!
//! # 手順（POD。順序は変えない）
//! 1. 入力検査（port 0・timeout 0 は `INVALID_ARGUMENT`）。保持一覧を掃除し、満杯なら `RESOURCE_EXHAUSTED`（ns も開かない）。
//! 2. 予算の検査。入口の締切から「後始末の予約 + connect の余裕」を引いて足りなければ、helper を起動せず `TIMEOUT`。
//! 3. 保持役の user / net namespace の fd を、**自 sandbox の ID だけ**で開く（`PodNamespaceSource`。要求・URL・記録の pid は
//!    使わない。#2776）。無い・死んでいる・記録と合わない場合は `UNAVAILABLE` で、host の loopback へは縮退しない。
//! 4. 保持役の net / user が plugin-cri 自身のものでないことを、helper の起動**前**に確かめる（PR #4497 の security-auditor の
//!    指摘への対応。net 側の `NetnsDialFds::new` と `wait_response` にも同じ検査があるが、spawn 前に断る別の層）。
//! 5. `netns-dial` helper を呼び出しスレッドで起動し（PDEATHSIG が起動スレッドに結びつくため。別スレッドへ渡さない）、
//!    要求と fd 2 本を送り、応答を期限つきで受けて検証する（検証は `NetnsDialChannel::wait_response`）。
//! 6. channel を閉じて helper を `SIGKILL` つきで回収する（成功時も失敗時も）。回収できない helper は保持一覧に入れる。
//!
//! # 期限（REPAIR-5。すべて入口の締切 `now + timeout` から導く。cri の外側の `timeout` を内側の合計が超えない）
//! 締切の末尾に `KILL_REAP_RESERVE`（helper の自然終了待ち + SIGKILL 後の回収待ち）を確保し、応答待ちはその手前までとする。
//! helper の connect 期限はさらに `CONNECT_MARGIN` 手前に置く（helper 側の `TimedOut` が親側の待ちより先に届くように）。
//! 定数はすべて暫定値のまま承認された（#4116 の項目 11・2026-11-12）。
//!
//! # 後始末と上限（REPAIR-5）
//! helper は `DialHelper` の RAII ガードで必ず回収を試みる。`SIGKILL` の後も回収できない helper は `retained` に保持し、
//! `MAX_RETAINED_DIAL_HELPERS` 件に達したら新しい dial を `RESOURCE_EXHAUSTED` で断る。
//! 保持一覧は dial の入口・各 dial の出口（`DialHelper::finish`）・一覧へ入れる直前（`retain`）・dialer の drop で、
//! 非ブロッキングの `try_wait` により掃除する（回収済みの子は数え直しで外れる。#4525）。
//!
//! # 観測（CRI-6・REPAIR-4・REPAIR-5・#4546。操作名と reason は暫定で、語彙の確定は #4116 の項目 3）
//! 回収できず保持した・保持数が上限を超えた・満杯で拒否した、の 3 つを [`PodDialTelemetry`] が共有 `OpRecorder` の件数と、
//! 累計が 2 のべき乗の時だけの構造化行で出す。記録は保持一覧の lock の外で行い（`retain` はガードを落としてから記録する）、
//! `OpRecorder::record` と `LineSink::submit`（`try_send`）だけを使う。行に pid・port・パス・errno は入れない。
//!
//! # 残余
//! - 保持数の上限は dial の入口で検査するため、並行する dial が同時に回収に失敗すると一時的に上限を超えうる。入れる側は
//!   断ると `Child` を落として追えない zombie を作るため断らない。超過は 8 + (`max_inflight_dials` − 1) で有界
//!   （既定 32 なら 39、許容範囲の最大 256 なら 263。#4525）。この超過は許容と判断済みで、入口の検査に並行数を含めない（#4116 の項目 11・2026-11-12）。
//! - 掃除は dial の入口・出口と drop だけで、定期の掃除は採らない（常駐スレッドを増やさない。CORE-7〜9）。dial が来ない間は、
//!   `SIGKILL` の後に遅れて終了した子が zombie のまま残りうる（件数は上記の上限内。pid の枠とわずかなカーネルメモリを占め、
//!   次の dial か plugin-cri の終了で解消する）。drop の時点でまだ終了していない子は回収されない（#4525）。
//! - StopPodSandbox と並行した dial は、fd を開いた後に保持役が解放されても helper が既に開いた fd の ns へ入る窓が残る
//!   （最大でも dial の期限で有界）。
//! - エラーは固定の英文で、port・pid・パス・errno を含めない（REPAIR-4）。

use std::net::TcpStream;
use std::num::NonZeroU16;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::port_forward::{
    PortForwardDialer, PortForwardNetwork, PortForwardTarget,
};
use fandhe_container_net::netns_dial::{
    ConnectTimeout, DialErrorCode, DialRequest, MAX_CONNECT_TIMEOUT_MS, MAX_RESPONSE_TIMEOUT,
    NETNS_DIAL_SUBCOMMAND, NetnsDialChannel, NetnsDialFailure, NetnsDialFds, NsId as NetNsId,
};

use super::NodeLoopbackDialer;
use crate::pod_holder::{PodNamespaceFds, ProductionPodHolder, open_supervisor_beside};
use crate::telemetry::LineSink;

/// 回収できず保持する helper の上限（暫定値のまま承認。#4116 の項目 11）。
pub const MAX_RETAINED_DIAL_HELPERS: usize = 8;
/// 応答（または channel の EOF）の後に helper が自分で終わるのを待つ時間（暫定値のまま承認。#4116 の項目 11）。
pub const HELPER_EXIT_WAIT: Duration = Duration::from_millis(200);
/// `SIGKILL` の後に回収を待つ時間（暫定値のまま承認。#4116 の項目 11）。
pub const HELPER_REAP_WAIT: Duration = Duration::from_millis(800);
/// 締切の末尾に確保する後始末の予約（[`HELPER_EXIT_WAIT`] + [`HELPER_REAP_WAIT`]）。
pub const KILL_REAP_RESERVE: Duration = Duration::from_millis(1000);
/// helper の connect 期限を応答待ちより手前に置く余裕（暫定値のまま承認。#4116 の項目 11）。
pub const CONNECT_MARGIN: Duration = Duration::from_millis(500);
const REAP_POLL: Duration = Duration::from_millis(10);

const MSG_PORT_RANGE: &str = "port forward port is out of range";
const MSG_TIMEOUT_RANGE: &str = "port forward dial timeout is out of range";
const MSG_TIMEOUT_POSITIVE: &str = "port forward dial timeout must be positive";
const MSG_RETAINED_FULL: &str = "too many netns-dial helpers are retained";
const MSG_TIMED_OUT: &str = "port forward dial timed out";
const MSG_NS_LOOKUP_FAILED: &str = "pod network namespace lookup failed";
const MSG_NS_UNAVAILABLE: &str = "pod network namespace is not available";
const MSG_NS_NOT_ISOLATED: &str = "pod network namespace is not isolated from the plugin";
const MSG_HELPER_START: &str = "failed to start the netns-dial helper";
const MSG_DIAL_FAILED: &str = "port forward dial failed";
const MSG_POD_DIAL_FAILED: &str = "port forward pod network dial failed";
const MSG_POD_DIAL_INTERNAL: &str = "port forward pod network dial failed internally";

/// 保持役の namespace の fd を sandbox ID から開く口（本番は [`ProductionPodHolder`]。試験で差し替える）。
pub trait PodNamespaceSource: Send + Sync + 'static {
    /// `sandbox_id` の保持役の user / net namespace を開く。無い・死んでいる・記録と合わない場合は `Unavailable`。
    fn open_pod_namespaces(&self, sandbox_id: &str) -> Result<PodNamespaceFds, TraitError>;
}

impl PodNamespaceSource for ProductionPodHolder {
    fn open_pod_namespaces(&self, sandbox_id: &str) -> Result<PodNamespaceFds, TraitError> {
        ProductionPodHolder::open_pod_namespaces(self, sandbox_id)
    }
}

/// `netns-dial` helper の起動口（本番は [`SupervisorNetnsDialSpawner`]。試験で偽の helper を差す）。
///
/// 呼び出したスレッドでブロッキングに起動する（helper の PDEATHSIG は起動スレッドに結びつくため、別スレッドへ渡さない）。
pub trait NetnsDialSpawner: Send + Sync + 'static {
    /// `channel_end` を helper の stdin にして起動する。
    fn spawn(&self, channel_end: OwnedFd) -> Result<Child, CriError>;
}

/// helper の Command を固定の形（argv は `netns-dial` の 1 個、環境変数なし、cwd は `/`、stdin は channel の端、
/// stdout・stderr は捨てる）にする。可変値を載せない（SEC-1・PLUG-11）。
fn configure_netns_dial(cmd: &mut Command, channel_end: OwnedFd) {
    cmd.arg(NETNS_DIAL_SUBCOMMAND)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(channel_end))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

/// 本番の spawner。plugin-cri の隣の supervisor の bin を検査した fd 経由で `netns-dial` として起動する。
#[derive(Debug, Default, Clone, Copy)]
pub struct SupervisorNetnsDialSpawner;

impl NetnsDialSpawner for SupervisorNetnsDialSpawner {
    fn spawn(&self, channel_end: OwnedFd) -> Result<Child, CriError> {
        let exe = open_supervisor_beside().map_err(|_| CriError::unavailable(MSG_HELPER_START))?;
        let mut cmd = exe.command();
        configure_netns_dial(&mut cmd, channel_end);
        let child = cmd
            .spawn()
            .map_err(|_| CriError::unavailable(MSG_HELPER_START))?;
        // 親が持つ子側の端の複製を閉じる（残ると helper の EOF 検知が成り立たない）。検証済み fd のガードは spawn 後に不要。
        drop(cmd);
        drop(exe);
        Ok(child)
    }
}

#[derive(Debug, Clone, Copy)]
struct DialTimings {
    exit_wait: Duration,
    reap_wait: Duration,
    margin: Duration,
}

impl DialTimings {
    const fn production() -> Self {
        Self {
            exit_wait: HELPER_EXIT_WAIT,
            reap_wait: HELPER_REAP_WAIT,
            margin: CONNECT_MARGIN,
        }
    }

    fn reserve(&self) -> Duration {
        self.exit_wait.saturating_add(self.reap_wait)
    }
}

/// 回収できず保持した helper の操作名（暫定。#4116 の項目 3）。
pub const OP_PF_HELPER_RETAINED: &str = "cri.port_forward.helper_retained";
/// 保持数が [`MAX_RETAINED_DIAL_HELPERS`] を超えた操作名（暫定）。
pub const OP_PF_RETAINED_OVER_LIMIT: &str = "cri.port_forward.retained_over_limit";
/// 満杯で dial を断った操作名（暫定）。
pub const OP_PF_RETAINED_FULL: &str = "cri.port_forward.retained_full";
/// 異常行の `event` 名。
pub const PF_EVENT_NAME: &str = "cri_port_forward_helper";
/// 回収できず保持した理由（固定語彙）。
pub const REASON_HELPER_UNREAPED: &str = "helper_unreaped";
/// 保持数が上限を超えた理由。
pub const REASON_RETAINED_OVER_LIMIT: &str = "retained_over_limit";
/// 満杯で拒否した理由。
pub const REASON_RETAINED_FULL: &str = "retained_full";

/// 回収できない helper の保持・上限超過・満杯の拒否を telemetry へ出す口（CRI-6・REPAIR-4・REPAIR-5・#4546）。
///
/// 呼び出し元は [`PodNetnsDialer`] の `retain` と `dial_pod` の入口だけ。`main.rs` が共有 `OpRecorder` と
/// `telemetry::stderr_sink()` で組み立てて `ProductionPortForward::pod_network` へ渡す。件数は `OpRecorder`、
/// 異常行は出来事ごとの累計が 2 のべき乗の時だけ（共有 sink の監査行を押し出さない間引き。SEC-4）。
/// ブロックせず I/O もしない。行には `&'static str` と累計 `u64` だけを埋める（pid・port・パス・errno は出さない）。
pub struct PodDialTelemetry {
    recorder: Arc<OpRecorder>,
    sink: LineSink,
    retained: OpName,
    over_limit: OpName,
    full: OpName,
    retained_total: AtomicU64,
    over_limit_total: AtomicU64,
    full_total: AtomicU64,
}

impl PodDialTelemetry {
    /// 操作名を検証して作る。失敗は呼び出し側（`main.rs`）が起動中止にする（観測なしで動き続けない）。
    pub fn new(recorder: Arc<OpRecorder>, sink: LineSink) -> Result<Self, TraitError> {
        Ok(Self {
            recorder,
            sink,
            retained: OpName::new(OP_PF_HELPER_RETAINED)?,
            over_limit: OpName::new(OP_PF_RETAINED_OVER_LIMIT)?,
            full: OpName::new(OP_PF_RETAINED_FULL)?,
            retained_total: AtomicU64::new(0),
            over_limit_total: AtomicU64::new(0),
            full_total: AtomicU64::new(0),
        })
    }

    fn note(&self, name: &OpName, total: &AtomicU64, op: &'static str, reason: &'static str) {
        // record の失敗（名前数の上限など）は記録器側の dropped_records に計上されるため無視する。
        let _ = self
            .recorder
            .record(name, OpOutcome::Failure, Duration::ZERO);
        let n = total.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if n.is_power_of_two() {
            self.sink.submit(format!(
                "{{\"event\":\"{PF_EVENT_NAME}\",\"op\":\"{op}\",\"outcome\":\"error\",\"reason\":\"{reason}\",\"count\":{n}}}"
            ));
        }
    }

    fn helper_retained(&self) {
        self.note(
            &self.retained,
            &self.retained_total,
            OP_PF_HELPER_RETAINED,
            REASON_HELPER_UNREAPED,
        );
    }

    fn retained_over_limit(&self) {
        self.note(
            &self.over_limit,
            &self.over_limit_total,
            OP_PF_RETAINED_OVER_LIMIT,
            REASON_RETAINED_OVER_LIMIT,
        );
    }

    fn retained_full(&self) {
        self.note(
            &self.full,
            &self.full_total,
            OP_PF_RETAINED_FULL,
            REASON_RETAINED_FULL,
        );
    }
}

/// POD ネットワークの pod の PortForward 用 dialer。
pub struct PodNetnsDialer {
    node: NodeLoopbackDialer,
    source: Arc<dyn PodNamespaceSource>,
    spawner: Arc<dyn NetnsDialSpawner>,
    retained: Mutex<Vec<Child>>,
    timings: DialTimings,
    /// 保持・上限超過・満杯の観測（`None` は観測なし。試験用の `with_spawner` の既定）。
    telemetry: Option<PodDialTelemetry>,
}

impl std::fmt::Debug for PodNetnsDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodNetnsDialer").finish_non_exhaustive()
    }
}

impl PodNetnsDialer {
    /// 本番の dialer（helper は plugin-cri の隣の supervisor の bin）。
    pub fn new(source: Arc<dyn PodNamespaceSource>, telemetry: PodDialTelemetry) -> Self {
        Self::with_spawner(source, Arc::new(SupervisorNetnsDialSpawner)).with_telemetry(telemetry)
    }

    /// 観測の口を付ける（本番は [`Self::new`]。試験は `with_spawner` の後に付ける）。
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: PodDialTelemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// 起動口を差し替えた dialer（試験用の入口。本番の結線は [`Self::new`]）。
    pub fn with_spawner(
        source: Arc<dyn PodNamespaceSource>,
        spawner: Arc<dyn NetnsDialSpawner>,
    ) -> Self {
        Self {
            node: NodeLoopbackDialer::new(),
            source,
            spawner,
            retained: Mutex::new(Vec::new()),
            timings: DialTimings::production(),
            telemetry: None,
        }
    }

    #[cfg(test)]
    fn push_retained_for_test(&self, child: Child) {
        self.lock_retained().push(child);
    }

    #[cfg(test)]
    fn retained_len_for_test(&self) -> usize {
        self.lock_retained().len()
    }

    fn lock_retained(&self) -> std::sync::MutexGuard<'_, Vec<Child>> {
        self.retained.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 回収できた helper を一覧から外し、残りの件数を返す。
    fn sweep_retained(&self) -> usize {
        let mut r = self.lock_retained();
        Self::sweep_locked(&mut r);
        r.len()
    }

    /// ロック済みの一覧から、終了（回収）済みの子を外す。`try_wait` のみで待たない。
    fn sweep_locked(v: &mut Vec<Child>) {
        v.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }

    /// 回収できなかった helper を保持一覧へ入れる。入れる前に掃除して数え直す。
    /// 上限を超えても断らない（`Child` を落とすと追えない zombie が残るため。超過は並行 dial 数で有界。#4525）。
    fn retain(&self, child: Child) {
        let mut r = self.lock_retained();
        Self::sweep_locked(&mut r);
        r.push(child);
        let len = r.len();
        // 記録は lock の外で行う（I/O は無いが、保持一覧の lock を長く持たない。#4546）。
        drop(r);
        if let Some(t) = &self.telemetry {
            t.helper_retained();
            if len > MAX_RETAINED_DIAL_HELPERS {
                t.retained_over_limit();
            }
        }
    }

    fn dial_pod(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        // Instant で表現できない巨大な timeout（`Duration::MAX` 等）は panic させず拒否する（REPAIR-5）。
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err(CriError::invalid_argument(MSG_TIMEOUT_RANGE));
        };
        let Some(port) = NonZeroU16::new(port) else {
            return Err(CriError::invalid_argument(MSG_PORT_RANGE));
        };
        if timeout.is_zero() {
            return Err(CriError::invalid_argument(MSG_TIMEOUT_POSITIVE));
        }
        if self.sweep_retained() >= MAX_RETAINED_DIAL_HELPERS {
            if let Some(t) = &self.telemetry {
                t.retained_full();
            }
            return Err(CriError::resource_exhausted(MSG_RETAINED_FULL));
        }
        let t = &self.timings;
        let tail = t.reserve().saturating_add(t.margin);
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget < tail.saturating_add(Duration::from_millis(1)) {
            return Err(CriError::timeout(MSG_TIMED_OUT));
        }

        // 自 sandbox の保持役の fd だけを使う（要求・URL・記録の pid は使わない）。
        let ns = self
            .source
            .open_pod_namespaces(target.pod_sandbox_id())
            .map_err(|e| match e.code() {
                ErrorCode::Internal => CriError::internal(MSG_NS_LOOKUP_FAILED),
                _ => CriError::unavailable(MSG_NS_UNAVAILABLE),
            })?;
        // helper の起動前に、plugin-cri 自身の net / user でないことを確かめる（stat の失敗も fail-closed）。
        let (rec_net, rec_user) = (ns.net_id(), ns.user_id());
        match (own_ns_id("net"), own_ns_id("user")) {
            (Some(n), Some(u))
                if n != (rec_net.dev, rec_net.ino) && u != (rec_user.dev, rec_user.ino) => {}
            _ => return Err(CriError::unavailable(MSG_NS_NOT_ISOLATED)),
        }
        // 期待値は READY の記録から作る（送る fd から導出しない）。
        let expected = NetNsId::new(rec_net.dev, rec_net.ino);
        let (user_fd, net_fd) = ns.into_fds();
        let fds = NetnsDialFds::new(user_fd, net_fd)
            .map_err(|_| CriError::unavailable(MSG_NS_UNAVAILABLE))?;
        if fds.net_id() != expected {
            return Err(CriError::unavailable(MSG_NS_UNAVAILABLE));
        }

        // helper の connect 期限（締切から後始末の予約と余裕を引く）。
        let remain = deadline.saturating_duration_since(Instant::now());
        let connect = remain
            .saturating_sub(tail)
            .min(Duration::from_millis(u64::from(MAX_CONNECT_TIMEOUT_MS)));
        let Ok(connect) = ConnectTimeout::from_duration(connect) else {
            return Err(CriError::timeout(MSG_TIMED_OUT));
        };

        let (channel, child_end) =
            NetnsDialChannel::pair().map_err(|_| CriError::unavailable(MSG_HELPER_START))?;
        let child = self.spawner.spawn(child_end)?;
        let mut helper = DialHelper::new(self, child);
        let sent = channel
            .send_request(DialRequest::new(port, connect), fds)
            .map_err(|_| CriError::unavailable(MSG_HELPER_START))?;
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(t.reserve())
            .min(MAX_RESPONSE_TIMEOUT);
        if wait.is_zero() {
            return Err(CriError::timeout(MSG_TIMED_OUT));
        }
        let result = channel.wait_response(&sent, expected, wait);
        // EOF を届けてから回収する（成功時も失敗時も）。
        drop(channel);
        helper.finish();
        result.map_err(|e| map_failure(e.failure()))
    }
}

/// `/proc/self/ns/<name>` の (dev, ino)。取れなければ `None`。
fn own_ns_id(name: &str) -> Option<(u64, u64)> {
    std::fs::metadata(format!("/proc/self/ns/{name}"))
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// `wait_response` の失敗を固定文の CRI エラーへ写す（port・pid・パス・errno を含めない。REPAIR-4）。
fn map_failure(f: NetnsDialFailure) -> CriError {
    match f {
        NetnsDialFailure::TimedOut | NetnsDialFailure::Helper(DialErrorCode::TimedOut) => {
            CriError::timeout(MSG_TIMED_OUT)
        }
        NetnsDialFailure::Helper(DialErrorCode::Refused | DialErrorCode::Unreachable) => {
            CriError::unavailable(MSG_DIAL_FAILED)
        }
        NetnsDialFailure::Helper(DialErrorCode::JoinFailed | DialErrorCode::IdentityMismatch)
        | NetnsDialFailure::HelperExited
        | NetnsDialFailure::Protocol
        | NetnsDialFailure::OwnNetns
        | NetnsDialFailure::Rejected(_) => CriError::unavailable(MSG_POD_DIAL_FAILED),
        _ => CriError::internal(MSG_POD_DIAL_INTERNAL),
    }
}

/// 起動した helper の RAII ガード。`finish` か drop で、自然終了待ち → `SIGKILL` → 回収待ちの順に後始末し、
/// 回収できなければ Child を落とさず dialer の保持一覧へ移す（REPAIR-5）。
struct DialHelper<'a> {
    owner: &'a PodNetnsDialer,
    child: Option<Child>,
}

impl<'a> DialHelper<'a> {
    fn new(owner: &'a PodNetnsDialer, child: Child) -> Self {
        Self {
            owner,
            child: Some(child),
        }
    }

    fn finish(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let t = &self.owner.timings;
        if wait_exit(&mut child, t.exit_wait) {
            self.owner.sweep_retained();
            return;
        }
        let _ = child.kill();
        if wait_exit(&mut child, t.reap_wait) {
            self.owner.sweep_retained();
            return;
        }
        // 入れる側で掃除するため、出口の掃除はこの分岐では不要。
        self.owner.retain(child);
    }
}

impl Drop for DialHelper<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// `within` の間 `try_wait` で終了（回収）を待つ。回収できたら true。
fn wait_exit(child: &mut Child, within: Duration) -> bool {
    // 加算できない（巨大な）待ちは、表現できる最大の先の時刻として扱い panic させない。
    let now0 = Instant::now();
    let end = now0
        .checked_add(within)
        .or_else(|| now0.checked_add(Duration::from_secs(86_400 * 365)))
        .unwrap_or(now0);
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        let now = Instant::now();
        if now >= end {
            return false;
        }
        std::thread::sleep(REAP_POLL.min(end - now));
    }
}

impl Drop for PodNetnsDialer {
    fn drop(&mut self) {
        // 保持中の helper へ SIGKILL を送るだけで待たない（プロセス終了時の後始末）。
        // 既に終了した子は非ブロッキングで回収する（待たない。#4525）。
        let mut r = self.lock_retained();
        for c in r.iter_mut() {
            let _ = c.kill();
        }
        Self::sweep_locked(&mut r);
    }
}

impl PortForwardDialer for PodNetnsDialer {
    fn dial(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        if target.network() == PortForwardNetwork::Pod {
            self.dial_pod(target, port, timeout)
        } else {
            self.node.dial(target, port, timeout)
        }
    }

    fn supports_pod_network(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
