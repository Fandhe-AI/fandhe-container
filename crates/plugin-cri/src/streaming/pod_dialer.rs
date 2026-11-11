//! POD ネットワークの pod 向け `PortForwardDialer` の本番実装 `PodNetnsDialer`（Linux のみ。CRI-6・NET-3・SEC-1・REPAIR-5・
//! TASK-63.4・#4484。設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」）。
//!
//! 呼び出し元: cri の `PortForwardHandler` が `spawn_blocking` 上で `dial` を呼ぶ。`production_stream_dispatcher` への結線と
//! `supports_pod_network` の有効化は #4486、実 helper を通す実機の段 F は #4487（本 issue は dialer 本体まで。結線されるまで
//! POD の pod の PortForward は RPC 時に `UNIMPLEMENTED` のまま）。NODE の target は `NodeLoopbackDialer` へ委ねる。
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
//! 定数はすべて暫定値で、オーナー確認（#4116）の対象。承認済みの値ではない。
//!
//! # 後始末と上限（REPAIR-5）
//! helper は `DialHelper` の RAII ガードで必ず回収を試みる。`SIGKILL` の後も回収できない helper は `retained` に保持し、
//! `MAX_RETAINED_DIAL_HELPERS` 件に達したら新しい dial を `RESOURCE_EXHAUSTED` で断る。
//!
//! # 残余
//! - 保持数の上限は dial の入口で検査するため、並行する dial が同時に回収に失敗すると一時的に上限を超えうる。超過は並行数
//!   （cri の `max_inflight_dials`）で有界。
//! - StopPodSandbox と並行した dial は、fd を開いた後に保持役が解放されても helper が既に開いた fd の ns へ入る窓が残る
//!   （最大でも dial の期限で有界）。
//! - エラーは固定の英文で、port・pid・パス・errno を含めない（REPAIR-4）。

use std::net::TcpStream;
use std::num::NonZeroU16;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

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

/// 回収できず保持する helper の上限（暫定値。#4116 の確認待ち）。
pub const MAX_RETAINED_DIAL_HELPERS: usize = 8;
/// 応答（または channel の EOF）の後に helper が自分で終わるのを待つ時間（暫定値。#4116）。
pub const HELPER_EXIT_WAIT: Duration = Duration::from_millis(200);
/// `SIGKILL` の後に回収を待つ時間（暫定値。#4116）。
pub const HELPER_REAP_WAIT: Duration = Duration::from_millis(800);
/// 締切の末尾に確保する後始末の予約（[`HELPER_EXIT_WAIT`] + [`HELPER_REAP_WAIT`]）。
pub const KILL_REAP_RESERVE: Duration = Duration::from_millis(1000);
/// helper の connect 期限を応答待ちより手前に置く余裕（暫定値。#4116）。
pub const CONNECT_MARGIN: Duration = Duration::from_millis(500);
const REAP_POLL: Duration = Duration::from_millis(10);

const MSG_PORT_RANGE: &str = "port forward port is out of range";
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

/// POD ネットワークの pod の PortForward 用 dialer。
pub struct PodNetnsDialer {
    node: NodeLoopbackDialer,
    source: Arc<dyn PodNamespaceSource>,
    spawner: Arc<dyn NetnsDialSpawner>,
    retained: Mutex<Vec<Child>>,
    timings: DialTimings,
}

impl std::fmt::Debug for PodNetnsDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodNetnsDialer").finish_non_exhaustive()
    }
}

impl PodNetnsDialer {
    /// 本番の dialer（helper は plugin-cri の隣の supervisor の bin）。
    pub fn new(source: Arc<dyn PodNamespaceSource>) -> Self {
        Self::with_spawner(source, Arc::new(SupervisorNetnsDialSpawner))
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
        r.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        r.len()
    }

    fn dial_pod(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        let deadline = Instant::now() + timeout;
        let Some(port) = NonZeroU16::new(port) else {
            return Err(CriError::invalid_argument(MSG_PORT_RANGE));
        };
        if timeout.is_zero() {
            return Err(CriError::invalid_argument(MSG_TIMEOUT_POSITIVE));
        }
        if self.sweep_retained() >= MAX_RETAINED_DIAL_HELPERS {
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
            return;
        }
        let _ = child.kill();
        if wait_exit(&mut child, t.reap_wait) {
            return;
        }
        self.owner.lock_retained().push(child);
    }
}

impl Drop for DialHelper<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// `within` の間 `try_wait` で終了（回収）を待つ。回収できたら true。
fn wait_exit(child: &mut Child, within: Duration) -> bool {
    let end = Instant::now() + within;
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
        for c in self.lock_retained().iter_mut() {
            let _ = c.kill();
        }
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
