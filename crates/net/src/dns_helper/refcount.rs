//! DNS ヘルパーの参照カウント管理とオンデマンド起動・終了（NET-7・TASK-144.1・#329・MS-8）。
//!
//! # 役割と呼び出し文脈
//! ネットワークへの参加・離脱ごとに参照カウントを増減し、0→1 でヘルパーを 1 回だけ起動、1→0 で終了して
//! 常駐コストを 0 にする。将来の統一 CLI / supervisor（TASK-79・TASK-157）が、コンテナ接続
//! （`network::attach_container`）の後に [`DnsHelperRefCounts::join`]、切断・停止・supervisor からの終了通知で
//! [`DnsHelperRefCounts::leave`] を呼ぶ。起動・停止の実体は [`DnsHelperLauncher`] に分離し、本番は
//! [`ProcessLauncher`]（`spawn_dns_helper` / `DnsHelperProcess::stop_checked` の薄いラッパー）、ユニットテストは偽実装を使う。
//!
//! # 設計
//! - カウントは裸の整数でなく [`EndpointId`] の集合で持つ。参加・離脱の再送や重複通知が冪等になり、
//!   カウントが負になる状態を表現できない（REPAIR-2）
//! - 起動・停止はロックを保持したまま呼ぶ。同時 join でも起動はちょうど 1 回になり、1→0 直後の再参加で
//!   旧ヘルパーの回収前に新ヘルパーが同じアドレスへ bind する競合が起きない。保持時間は ready / reap の期限
//!   （最大 10 秒。REPAIR-5）で上限が決まる。トレードオフとして、あるネットワークの起動中は他ネットワークの
//!   join / leave も待たされる（ネットワークごとのロックへの細分化は将来課題）
//! - 起動失敗は何も記録しない（fail-closed。次の join で再試行）
//! - 停止失敗（回収期限切れ）では、メンバーが空の「停止中」エントリとハンドルを保持する。旧プロセスの終了を
//!   確認できるまで次の join / leave は停止を再試行し、成功してから（join なら）新ヘルパーを起動する（同一アドレスへの二重 bind を
//!   防ぐ）。再試行も失敗すればエラーを返し、起動しない。エントリが破棄されればハンドルの `Drop` が回収する
//! - join のたびに稼働中ヘルパーの生死を確認し、異常終了していれば同じアドレス（port 0 指定時は確定済みの実ポート）で
//!   再起動する。生死を確認できない場合は再起動せず、旧ハンドルを停止・回収できてから再起動する。復旧はメンバー上限判定
//!   より先に行う（[`JoinOutcome::Restarted`]）。再起動に失敗すればエラーを返し、死んだエントリは残して次の join で再試行する。
//!   `is_running` / `bound_addr` は死んだヘルパーを稼働中として報告しない
//! - 起動・停止の成否と所要時間は [`NetOpRecorder`] へ記録する（REPAIR-4。`NetOpKind::DnsHelperStart` / `DnsHelperStop`）
//! - ネットワーク数・参加数は上限つき（DoS 対策）。エラー文言にネットワーク名・endpoint・アドレス・pid を含めない
//!
//! # 未実装（REPAIR-3）
//! - プロセスをまたぐ参照カウントの永続化（CORE-1 により CLI 起動ごとに別プロセスのため、最終的にはファイルと
//!   ロック等での共有が要る。本モジュールはプロセス内の排他制御まで）
//! - supervisor（TASK-157）からの終了通知・異常終了の push 通知の配線（現状は join 時の生死確認のみ）
//! - `DnsRegistry` の登録・削除との連動、SIGTERM による正常終了

use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use super::{
    DnsHelperProcess, DnsListenAddr, MAX_REGISTRY_ENTRIES, check_timeout, spawn_dns_helper,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};
use crate::network::{EndpointId, NetworkName};

/// 同時に管理するネットワーク数の上限（無制限確保の防止）。
pub const MAX_TRACKED_NETWORKS: usize = 1024;

/// ヘルパーの起動・停止の抽象（NET-7）。本番は [`ProcessLauncher`]、テストは偽実装。
pub trait DnsHelperLauncher: Send + Sync {
    /// 起動したヘルパーを表すハンドル。
    type Handle: Send;
    /// ヘルパーを起動し、準備完了までを待つ（期限つき）。
    fn start(&self, listen: DnsListenAddr) -> Result<Self::Handle, NetError>;
    /// ヘルパーを停止して回収する（期限つき）。失敗時はハンドルを保持したまま返し、再試行できる。
    fn stop(&self, handle: &mut Self::Handle) -> Result<(), NetError>;
    /// ヘルパーがまだ動いているか（異常終了の検知用）。生死を確認できない場合は `Err`（死亡扱いにしない）。
    fn is_alive(&self, handle: &mut Self::Handle) -> Result<bool, NetError>;
    /// ハンドルが報告する実際の待受アドレス（port 0 指定時の確定ポートの取得用）。
    fn bound_addr(&self, handle: &Self::Handle) -> SocketAddrV4;
}

/// 実プロセスを起動する本番ランチャー（`spawn_dns_helper` / `DnsHelperProcess::stop_checked`）。
#[derive(Debug, Clone)]
pub struct ProcessLauncher {
    program: PathBuf,
    ready_timeout: Duration,
    reap_timeout: Duration,
}

impl ProcessLauncher {
    /// `program` は絶対パスに限る。各期限は 0 より大きく 10 秒以下（REPAIR-5）。
    pub fn new(
        program: PathBuf,
        ready_timeout: Duration,
        reap_timeout: Duration,
    ) -> Result<Self, NetError> {
        if !program.is_absolute() {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "helper program path must be absolute",
            ));
        }
        check_timeout(ready_timeout)?;
        check_timeout(reap_timeout)?;
        Ok(Self {
            program,
            ready_timeout,
            reap_timeout,
        })
    }
}

impl DnsHelperLauncher for ProcessLauncher {
    type Handle = DnsHelperProcess;

    fn start(&self, listen: DnsListenAddr) -> Result<Self::Handle, NetError> {
        spawn_dns_helper(&self.program, listen, self.ready_timeout)
    }

    fn stop(&self, handle: &mut Self::Handle) -> Result<(), NetError> {
        handle.stop_checked(self.reap_timeout)
    }

    fn is_alive(&self, handle: &mut Self::Handle) -> Result<bool, NetError> {
        handle.is_alive()
    }

    fn bound_addr(&self, handle: &Self::Handle) -> SocketAddrV4 {
        handle.listen_addr()
    }
}

/// [`DnsHelperRefCounts::join`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinOutcome {
    /// 0→1 でヘルパーを起動した。
    Started,
    /// 異常終了していたヘルパーを同じアドレスで再起動して参加した。
    Restarted {
        /// 参加後の人数。
        members: usize,
    },
    /// 既存のヘルパーに参加した（起動なし）。
    Joined {
        /// 参加後の人数。
        members: usize,
    },
    /// すでに参加済み（何もしない）。
    AlreadyMember {
        /// 現在の人数。
        members: usize,
    },
}

/// [`DnsHelperRefCounts::leave`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaveOutcome {
    /// 1→0 でヘルパーを停止した。
    Stopped,
    /// まだ参加者が残っている（停止なし）。
    Remaining {
        /// 離脱後の人数。
        members: usize,
    },
    /// 未参加（終了通知の重複に冪等。エラーにしない）。
    NotMember,
}

struct NetworkEntry<H> {
    listen: DnsListenAddr,
    members: HashSet<EndpointId>,
    helper: H,
    /// 最後の leave で停止に失敗し、旧プロセスの回収待ちである（members は空）。
    stopping: bool,
}

/// ネットワークごとの参照カウント（参加 endpoint の集合）とヘルパーの自動起動・終了。
pub struct DnsHelperRefCounts<L: DnsHelperLauncher> {
    launcher: L,
    state: Mutex<HashMap<NetworkName, NetworkEntry<L::Handle>>>,
    recorder: Arc<dyn NetOpRecorder>,
    max_members: usize,
    max_networks: usize,
}

impl<L: DnsHelperLauncher> DnsHelperRefCounts<L> {
    /// 既定の上限（[`MAX_REGISTRY_ENTRIES`]・[`MAX_TRACKED_NETWORKS`]）・計測なしで作る。
    pub fn new(launcher: L) -> Self {
        Self::with_recorder(launcher, Arc::new(NoopNetOpRecorder))
    }

    /// 既定の上限で、起動・停止の計測先を指定して作る（REPAIR-4）。
    pub fn with_recorder(launcher: L, recorder: Arc<dyn NetOpRecorder>) -> Self {
        Self::with_limits_and_recorder(
            launcher,
            MAX_REGISTRY_ENTRIES,
            MAX_TRACKED_NETWORKS,
            recorder,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_limits(launcher: L, max_members: usize, max_networks: usize) -> Self {
        Self::with_limits_and_recorder(
            launcher,
            max_members,
            max_networks,
            Arc::new(NoopNetOpRecorder),
        )
    }

    pub(crate) fn with_limits_and_recorder(
        launcher: L,
        max_members: usize,
        max_networks: usize,
        recorder: Arc<dyn NetOpRecorder>,
    ) -> Self {
        Self {
            launcher,
            state: Mutex::new(HashMap::new()),
            recorder,
            max_members,
            max_networks,
        }
    }

    /// poison は回復する: 起動・停止の呼び出しは map の変更の前後で区切られており、panic しても map は整合している。
    fn lock(&self) -> MutexGuard<'_, HashMap<NetworkName, NetworkEntry<L::Handle>>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn start_helper(&self, listen: DnsListenAddr) -> Result<L::Handle, NetError> {
        record_net_op(self.recorder.as_ref(), NetOpKind::DnsHelperStart, || {
            self.launcher.start(listen)
        })
    }

    fn stop_helper(&self, handle: &mut L::Handle) -> Result<(), NetError> {
        record_net_op(self.recorder.as_ref(), NetOpKind::DnsHelperStop, || {
            self.launcher.stop(handle)
        })
    }

    /// ネットワークへ参加する。0→1 のときだけヘルパーを起動する（失敗時は何も記録しない）。
    ///
    /// 稼働中ヘルパーが異常終了していれば同じアドレスで再起動する。直前の停止が回収待ちなら、旧プロセスの
    /// 終了を確認できるまで起動しない。
    pub fn join(
        &self,
        network: &NetworkName,
        listen: DnsListenAddr,
        endpoint: &EndpointId,
    ) -> Result<JoinOutcome, NetError> {
        let mut map = self.lock();
        let mut reaped = false;
        if let Some(entry) = map.get_mut(network) {
            if entry.listen != listen {
                return Err(NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "listen address differs from the running helper",
                ));
            }
            if entry.stopping {
                // 旧プロセスの終了を確認してから新規起動する（失敗ならエントリを残して返す）。
                self.stop_helper(&mut entry.helper)?;
                reaped = true;
            } else {
                // 生死不明（try_wait 失敗）のときは再起動しない: 旧プロセスが生きていれば同一アドレスへ二重 bind になる。
                // まず旧ハンドルを停止・回収し、確認できた場合だけ（死亡扱いで）再起動へ進む。
                let alive = match self.launcher.is_alive(&mut entry.helper) {
                    Ok(alive) => alive,
                    Err(_) => {
                        self.stop_helper(&mut entry.helper)?;
                        false
                    }
                };
                let is_member = entry.members.contains(endpoint);
                if alive && is_member {
                    return Ok(JoinOutcome::AlreadyMember {
                        members: entry.members.len(),
                    });
                }
                if !alive {
                    // 異常終了を検知: 復旧を上限判定より先に行う（上限超過の拒否で死んだヘルパーが放置されない）。
                    // port 0 指定でも既存参加者の bound_addr を保つため、旧ヘルパーが確定させた実ポートで再起動する。
                    // 失敗時は死んだエントリを残す（次の join で再試行）。
                    let bound = self.launcher.bound_addr(&entry.helper);
                    let relisten = DnsListenAddr::new(*bound.ip(), bound.port())?;
                    entry.helper = self.start_helper(relisten)?;
                }
                if !is_member && entry.members.len() >= self.max_members {
                    return Err(NetError::new(
                        NetErrorCode::ResourceExhausted,
                        "too many members in the network",
                    ));
                }
                entry.members.insert(endpoint.clone());
                let members = entry.members.len();
                return Ok(if alive {
                    JoinOutcome::Joined { members }
                } else {
                    JoinOutcome::Restarted { members }
                });
            }
        }
        if reaped {
            map.remove(network);
        }
        if map.len() >= self.max_networks {
            return Err(NetError::new(
                NetErrorCode::ResourceExhausted,
                "too many tracked networks",
            ));
        }
        // ロック保持のまま起動する: 同時 join でも起動は 1 回だけ。
        let helper = self.start_helper(listen)?;
        let mut members = HashSet::new();
        members.insert(endpoint.clone());
        map.insert(
            network.clone(),
            NetworkEntry {
                listen,
                members,
                helper,
                stopping: false,
            },
        );
        Ok(JoinOutcome::Started)
    }

    /// ネットワークから離脱する。1→0 のときヘルパーを停止する。未参加は [`LeaveOutcome::NotMember`]。
    ///
    /// 停止に失敗した場合はメンバーシップは解除済みのままエラーを返し、ハンドルは「停止中」として保持される
    /// （次の join が旧プロセスの終了を確認してから起動する）。
    pub fn leave(
        &self,
        network: &NetworkName,
        endpoint: &EndpointId,
    ) -> Result<LeaveOutcome, NetError> {
        let mut map = self.lock();
        let Some(entry) = map.get_mut(network) else {
            return Ok(LeaveOutcome::NotMember);
        };
        if entry.stopping {
            // 前回の停止が回収待ち: leave でも回収を再試行できる（join を待たずに解放する）。
            self.stop_helper(&mut entry.helper)?;
            map.remove(network);
            return Ok(LeaveOutcome::Stopped);
        }
        if !entry.members.remove(endpoint) {
            return Ok(LeaveOutcome::NotMember);
        }
        if !entry.members.is_empty() {
            return Ok(LeaveOutcome::Remaining {
                members: entry.members.len(),
            });
        }
        // ロック保持のまま停止する: 回収完了前に再 join が同じアドレスへ bind する競合を防ぐ。
        match self.stop_helper(&mut entry.helper) {
            Ok(()) => {
                map.remove(network);
                Ok(LeaveOutcome::Stopped)
            }
            Err(e) => {
                entry.stopping = true;
                Err(e)
            }
        }
    }

    /// 現在の参加人数（未起動は 0）。
    pub fn members(&self, network: &NetworkName) -> usize {
        self.lock().get(network).map_or(0, |e| e.members.len())
    }

    /// ヘルパーが起動中か（停止中・異常終了済みは false）。
    pub fn is_running(&self, network: &NetworkName) -> bool {
        self.lock()
            .get_mut(network)
            .is_some_and(|e| !e.stopping && self.launcher.is_alive(&mut e.helper) == Ok(true))
    }

    /// 起動中ヘルパーの実際の待受アドレス（停止中・異常終了済みは `None`）。
    pub fn bound_addr(&self, network: &NetworkName) -> Option<SocketAddrV4> {
        self.lock().get_mut(network).and_then(|e| {
            (!e.stopping && self.launcher.is_alive(&mut e.helper) == Ok(true))
                .then(|| self.launcher.bound_addr(&e.helper))
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::NetOpOutcome;
    use crate::instrument::testing::Collect;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Fake {
        starts: AtomicUsize,
        stops: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        fail_start: AtomicBool,
        fail_stop: AtomicBool,
        slow: AtomicBool,
        unknown: AtomicBool,
        dead: Mutex<HashSet<usize>>,
    }

    impl Fake {
        fn enter(&self) {
            let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(n, Ordering::SeqCst);
            if self.slow.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        fn exit(&self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl DnsHelperLauncher for Fake {
        type Handle = (SocketAddrV4, usize);
        fn start(&self, listen: DnsListenAddr) -> Result<(SocketAddrV4, usize), NetError> {
            self.enter();
            self.starts.fetch_add(1, Ordering::SeqCst);
            let r = if self.fail_start.load(Ordering::SeqCst) {
                Err(NetError::new(NetErrorCode::Internal, "fake start failure"))
            } else {
                Ok((listen.socket_addr(), self.starts.load(Ordering::SeqCst)))
            };
            self.exit();
            r
        }
        fn is_alive(&self, h: &mut (SocketAddrV4, usize)) -> Result<bool, NetError> {
            if self.unknown.load(Ordering::SeqCst) {
                return Err(NetError::new(
                    NetErrorCode::Internal,
                    "fake liveness unknown",
                ));
            }
            Ok(!self.dead.lock().expect("lock").contains(&h.1))
        }
        fn stop(&self, _h: &mut (SocketAddrV4, usize)) -> Result<(), NetError> {
            self.enter();
            self.stops.fetch_add(1, Ordering::SeqCst);
            let r = if self.fail_stop.load(Ordering::SeqCst) {
                Err(NetError::new(NetErrorCode::Timeout, "fake stop failure"))
            } else {
                Ok(())
            };
            self.exit();
            r
        }
        fn bound_addr(&self, h: &(SocketAddrV4, usize)) -> SocketAddrV4 {
            h.0
        }
    }

    fn net(n: &str) -> NetworkName {
        NetworkName::new(n).expect("network name")
    }
    fn ep(n: &str) -> EndpointId {
        EndpointId::new(n).expect("endpoint id")
    }
    fn addr(port: u16) -> DnsListenAddr {
        DnsListenAddr::new(Ipv4Addr::new(10, 88, 0, 1), port).expect("addr")
    }
    fn n(v: &AtomicUsize) -> usize {
        v.load(Ordering::SeqCst)
    }

    /// NET-7: 0→1 で起動がちょうど 1 回。
    #[test]
    fn net7_first_join_starts_helper_once() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        let out = rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        assert_eq!(out, JoinOutcome::Started);
        assert_eq!(n(&rc.launcher.starts), 1);
        assert_eq!(rc.members(&net("a")), 1);
        assert!(rc.is_running(&net("a")));
        assert_eq!(rc.bound_addr(&net("a")), Some(addr(53).socket_addr()));
    }

    /// NET-7: 2 人目の参加では再起動しない。
    #[test]
    fn net7_second_join_does_not_restart() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        let out = rc.join(&net("a"), addr(53), &ep("c2")).expect("join");
        assert_eq!(out, JoinOutcome::Joined { members: 2 });
        assert_eq!(n(&rc.launcher.starts), 1);
    }

    /// NET-7: 1→0 で停止が 1 回。
    #[test]
    fn net7_last_leave_stops_helper() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.join(&net("a"), addr(53), &ep("c2")).expect("join");
        assert_eq!(
            rc.leave(&net("a"), &ep("c1")).expect("leave"),
            LeaveOutcome::Remaining { members: 1 }
        );
        assert_eq!(n(&rc.launcher.stops), 0);
        assert_eq!(
            rc.leave(&net("a"), &ep("c2")).expect("leave"),
            LeaveOutcome::Stopped
        );
        assert_eq!(n(&rc.launcher.stops), 1);
        assert!(!rc.is_running(&net("a")));
    }

    /// NET-7: 重複 join / 未参加 leave は冪等。
    #[test]
    fn net7_duplicate_join_and_leave_are_idempotent() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        assert_eq!(
            rc.leave(&net("a"), &ep("c1")).expect("leave"),
            LeaveOutcome::NotMember
        );
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c1")).expect("join"),
            JoinOutcome::AlreadyMember { members: 1 }
        );
        assert_eq!(
            rc.leave(&net("a"), &ep("zz")).expect("leave"),
            LeaveOutcome::NotMember
        );
        assert_eq!((n(&rc.launcher.starts), n(&rc.launcher.stops)), (1, 0));
    }

    /// NET-7: 起動失敗はカウント 0 のまま、次の join で再試行。
    #[test]
    fn net7_start_failure_keeps_count_zero_and_retries() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.launcher.fail_start.store(true, Ordering::SeqCst);
        let e = rc.join(&net("a"), addr(53), &ep("c1")).expect_err("fail");
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(rc.members(&net("a")), 0);
        assert!(!rc.is_running(&net("a")));
        rc.launcher.fail_start.store(false, Ordering::SeqCst);
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c1")).expect("join"),
            JoinOutcome::Started
        );
        assert_eq!(n(&rc.launcher.starts), 2);
    }

    /// NET-7: 停止失敗ではメンバーシップは解除済みでエラーを返し、旧プロセスの終了確認まで再起動しない。
    #[test]
    fn net7_stop_failure_blocks_restart_until_reaped() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.fail_stop.store(true, Ordering::SeqCst);
        let e = rc.leave(&net("a"), &ep("c1")).expect_err("fail");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(rc.members(&net("a")), 0);
        assert!(!rc.is_running(&net("a")));
        // 回収できないうちは再参加しても新ヘルパーを起動しない。
        let e = rc
            .join(&net("a"), addr(53), &ep("c1"))
            .expect_err("blocked");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(n(&rc.launcher.starts), 1);
        // leave も回収を再試行する（失敗中はエラー）。
        rc.leave(&net("a"), &ep("c1")).expect_err("retry fails");
        // 回収できたら起動する。
        rc.launcher.fail_stop.store(false, Ordering::SeqCst);
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c1")).expect("join"),
            JoinOutcome::Started
        );
        assert_eq!(n(&rc.launcher.starts), 2);
        assert_eq!(n(&rc.launcher.stops), 4);
        assert!(rc.is_running(&net("a")));
    }

    /// NET-7: 異常終了したヘルパーは稼働中扱いされず、join で再起動される。
    #[test]
    fn net7_crashed_helper_is_restarted_on_join() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.dead.lock().expect("lock").insert(1);
        assert!(!rc.is_running(&net("a")));
        assert_eq!(rc.bound_addr(&net("a")), None);
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c2")).expect("join"),
            JoinOutcome::Restarted { members: 2 }
        );
        assert_eq!(n(&rc.launcher.starts), 2);
        assert!(rc.is_running(&net("a")));
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c1")).expect("join"),
            JoinOutcome::AlreadyMember { members: 2 }
        );
    }

    /// NET-7: 異常終了後の再起動に失敗したらエラーを返し、次の join で再試行する。
    #[test]
    fn net7_crashed_helper_restart_failure_retries() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.dead.lock().expect("lock").insert(1);
        rc.launcher.fail_start.store(true, Ordering::SeqCst);
        let e = rc.join(&net("a"), addr(53), &ep("c1")).expect_err("fail");
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert!(!rc.is_running(&net("a")));
        rc.launcher.fail_start.store(false, Ordering::SeqCst);
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c1")).expect("join"),
            JoinOutcome::Restarted { members: 1 }
        );
    }

    /// NET-7: 生死不明（try_wait 失敗）では停止・回収に失敗する間は再起動しない。
    #[test]
    fn net7_unknown_liveness_stops_before_restart() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.unknown.store(true, Ordering::SeqCst);
        rc.launcher.fail_stop.store(true, Ordering::SeqCst);
        rc.join(&net("a"), addr(53), &ep("c2"))
            .expect_err("stop fails");
        assert_eq!((n(&rc.launcher.starts), n(&rc.launcher.stops)), (1, 1));
        assert_eq!(rc.members(&net("a")), 1);
        rc.launcher.fail_stop.store(false, Ordering::SeqCst);
        assert_eq!(
            rc.join(&net("a"), addr(53), &ep("c2")).expect("join"),
            JoinOutcome::Restarted { members: 2 }
        );
        assert_eq!((n(&rc.launcher.starts), n(&rc.launcher.stops)), (2, 2));
    }

    /// NET-7: port 0 のヘルパー再起動は確定済みの実ポートで行い、bound_addr を変えない。
    #[test]
    fn net7_restart_keeps_bound_port() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(0), &ep("c1")).expect("join");
        rc.launcher.dead.lock().expect("lock").insert(1);
        let before = rc.launcher.bound_addr(&(addr(5353).socket_addr(), 0));
        assert_eq!(before.port(), 5353);
        // Fake は与えられた listen をそのまま bound とするため、再起動後も元ポート（0）に固定される。
        rc.join(&net("a"), addr(0), &ep("c1")).expect("join");
        assert_eq!(rc.bound_addr(&net("a")), Some(addr(0).socket_addr()));
    }

    /// NET-7: 停止回収待ちのとき leave で回収を再試行できる。
    #[test]
    fn net7_leave_retries_pending_stop() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.fail_stop.store(true, Ordering::SeqCst);
        rc.leave(&net("a"), &ep("c1")).expect_err("fail");
        rc.leave(&net("a"), &ep("c1")).expect_err("still failing");
        rc.launcher.fail_stop.store(false, Ordering::SeqCst);
        assert_eq!(
            rc.leave(&net("a"), &ep("c1")).expect("leave"),
            LeaveOutcome::Stopped
        );
        assert_eq!(
            rc.leave(&net("a"), &ep("c1")).expect("leave"),
            LeaveOutcome::NotMember
        );
        assert_eq!(n(&rc.launcher.stops), 3);
    }

    /// NET-7: メンバー上限で拒否される join でも、死んだヘルパーは復旧される。
    #[test]
    fn net7_dead_helper_restarted_even_when_member_limit_rejects() {
        let rc = DnsHelperRefCounts::with_limits(Fake::default(), 1, 4);
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.dead.lock().expect("lock").insert(1);
        let e = rc.join(&net("a"), addr(53), &ep("c2")).expect_err("limit");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(n(&rc.launcher.starts), 2);
        assert!(rc.is_running(&net("a")));
        assert_eq!(rc.members(&net("a")), 1);
    }

    /// REPAIR-4: 起動・停止の成功 / 失敗が記録される。
    #[test]
    fn repair4_start_and_stop_are_recorded() {
        let c = Arc::new(Collect::default());
        let rc = DnsHelperRefCounts::with_recorder(Fake::default(), c.clone());
        rc.launcher.fail_start.store(true, Ordering::SeqCst);
        rc.join(&net("a"), addr(53), &ep("c1")).expect_err("fail");
        rc.launcher.fail_start.store(false, Ordering::SeqCst);
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.launcher.fail_stop.store(true, Ordering::SeqCst);
        rc.leave(&net("a"), &ep("c1")).expect_err("fail");
        rc.launcher.fail_stop.store(false, Ordering::SeqCst);
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.leave(&net("a"), &ep("c1")).expect("leave");
        assert_eq!(
            c.kinds(),
            vec![
                (NetOpKind::DnsHelperStart, NetOpOutcome::Failure),
                (NetOpKind::DnsHelperStart, NetOpOutcome::Success),
                (NetOpKind::DnsHelperStop, NetOpOutcome::Failure),
                (NetOpKind::DnsHelperStop, NetOpOutcome::Success),
                (NetOpKind::DnsHelperStart, NetOpOutcome::Success),
                (NetOpKind::DnsHelperStop, NetOpOutcome::Success),
            ]
        );
    }

    /// NET-7: 0→1→0→1 で起動 2 回・停止 1 回。
    #[test]
    fn net7_rejoin_after_stop_restarts() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.leave(&net("a"), &ep("c1")).expect("leave");
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        assert_eq!((n(&rc.launcher.starts), n(&rc.launcher.stops)), (2, 1));
    }

    /// NET-7: 待受アドレス違いは FailedPrecondition。
    #[test]
    fn net7_listen_mismatch_rejected() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        let e = rc
            .join(&net("a"), addr(5353), &ep("c2"))
            .expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(rc.members(&net("a")), 1);
    }

    /// NET-7: ネットワークは互いに独立。
    #[test]
    fn net7_networks_are_independent() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.join(&net("b"), addr(53), &ep("c1")).expect("join");
        assert_eq!(n(&rc.launcher.starts), 2);
        rc.leave(&net("a"), &ep("c1")).expect("leave");
        assert!(!rc.is_running(&net("a")));
        assert!(rc.is_running(&net("b")));
        assert_eq!(n(&rc.launcher.stops), 1);
    }

    /// NET-7: 人数・ネットワーク数の上限。
    #[test]
    fn net7_member_limit_and_network_limit() {
        let rc = DnsHelperRefCounts::with_limits(Fake::default(), 2, 1);
        rc.join(&net("a"), addr(53), &ep("c1")).expect("join");
        rc.join(&net("a"), addr(53), &ep("c2")).expect("join");
        let e = rc.join(&net("a"), addr(53), &ep("c3")).expect_err("limit");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        let e = rc.join(&net("b"), addr(53), &ep("c1")).expect_err("limit");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(n(&rc.launcher.starts), 1);
    }

    /// NET-7: 同時 join / leave でも起動・停止はちょうど 1 回で、重なって実行されない。
    #[test]
    fn net7_concurrent_join_leave_is_consistent() {
        const N: usize = 16;
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.launcher.slow.store(true, Ordering::SeqCst);
        let eps: Vec<EndpointId> = (0..N).map(|i| ep(&format!("c{i}"))).collect();
        let a = net("a");
        for round in 1..=5 {
            let started = AtomicUsize::new(0);
            std::thread::scope(|s| {
                for e in &eps {
                    s.spawn(|| {
                        if rc.join(&a, addr(53), e).expect("join") == JoinOutcome::Started {
                            started.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            });
            assert_eq!(n(&started), 1);
            assert_eq!(n(&rc.launcher.starts), round);
            assert_eq!(rc.members(&a), N);
            let stopped = AtomicUsize::new(0);
            std::thread::scope(|s| {
                for e in &eps {
                    s.spawn(|| {
                        if rc.leave(&a, e).expect("leave") == LeaveOutcome::Stopped {
                            stopped.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            });
            assert_eq!(n(&stopped), 1);
            assert_eq!(n(&rc.launcher.stops), round);
            assert!(!rc.is_running(&a));
        }
        assert_eq!(n(&rc.launcher.max_active), 1);
    }

    /// NET-7: 同一 endpoint の同時 join は起動 1 回・AlreadyMember 15 件。
    #[test]
    fn net7_concurrent_same_endpoint_join() {
        let rc = DnsHelperRefCounts::new(Fake::default());
        rc.launcher.slow.store(true, Ordering::SeqCst);
        let already = AtomicUsize::new(0);
        let (a, e) = (net("a"), ep("c1"));
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    if let JoinOutcome::AlreadyMember { .. } =
                        rc.join(&a, addr(53), &e).expect("join")
                    {
                        already.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(n(&rc.launcher.starts), 1);
        assert_eq!(rc.members(&a), 1);
        assert_eq!(n(&already), 15);
    }

    /// NET-7: ProcessLauncher の入力検証。
    #[test]
    fn net7_process_launcher_validates_input() {
        let abs = std::env::current_exe().expect("exe");
        let ok = Duration::from_secs(1);
        for r in [
            ProcessLauncher::new(PathBuf::from("relative"), ok, ok),
            ProcessLauncher::new(abs.clone(), Duration::ZERO, ok),
            ProcessLauncher::new(abs.clone(), ok, Duration::from_secs(11)),
        ] {
            assert_eq!(
                r.expect_err("invalid").code(),
                NetErrorCode::InvalidArgument
            );
        }
        assert!(ProcessLauncher::new(abs, ok, ok).is_ok());
    }
}
