//! net 操作の計装連携点（REPAIR-4・NET-11・TASK-136.2.1）。
//!
//! `NETLINK_ROUTE` ソケットの open / send / recv（`crate::netlink_route::NetlinkRouteSocket`）が、
//! 1 回の操作ごとの結果（成功 / 失敗）と所要時間を記録先へ渡すための境界。集計（成功・失敗件数と
//! レイテンシ分布）と構造化ログへの出力は core の `OpRecorder` が担うが、net は core に依存しない
//! ため、本モジュールが net 内の型だけで完結するトレイトを定義する（`fandhe-container-io` の
//! `instrument` モジュールと同じ形）。core の記録器への接続は、`docs/architecture.md` の「計装アダプタの配置」の原則
//! （net の操作を本番で呼び、`OpRecorder` を持つ crate に置く newtype アダプタ）に従う。
//! アダプタは `sample.kind().as_str()` を core の `OpName::new` へ、`sample.outcome()` / `sample.latency()` を `OpRecorder::record` へ写す。
//!
//! OS 非依存（型とトレイトのみ）で、Linux 以外でもアダプタをビルドできる。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 後続の操作（address / route 送信ラッパー等。#301）の種別は、送信ラッパーと一緒に
//!   [`NetOpKind`] へ追加する
//!
//! # 機微情報
//!
//! [`NetOpSample`] は種別・結果・レイテンシのみを持ち、メッセージ内容・アドレス・エラー文言は
//! 持たせない（`.claude/rules/security.md`）。

use std::time::{Duration, Instant};

/// 計装対象の net 操作の種別（REPAIR-4）。
///
/// [`NetOpKind::as_str`] は core の `OpName` 規則（`[A-Za-z0-9._-]`・64 バイト以下）に収まる
/// 固定文字列を返す契約を持つ。net は core の定数を import できないため規則を重複して持ち、
/// テストで固定する。閉じた enum なので自由入力の文字列がログのキーに入る経路はない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetOpKind {
    /// `NETLINK_ROUTE` ソケットの open と bind。
    NetlinkOpen,
    /// netlink メッセージ 1 件の送信（送信前検証での拒否を含む）。
    NetlinkSend,
    /// netlink データグラム 1 件の受信（期限までの待機時間を含む。時間切れは失敗）。
    NetlinkRecv,
    /// 要求 1 件の往復（送信 → seq 一致の応答 / ACK 待ち。TASK-136.2.2・#844）。内側の send / recv も
    /// 従来どおり個別に記録される。
    NetlinkRequest,
    /// link 作成要求 1 件（`RTM_NEWLINK`。`NetlinkRouteSocket::create_link`。TASK-136.3.2・#846）。
    /// 内側の request / send / recv も個別に記録される。
    LinkCreate,
    /// link 設定要求 1 件（`RTM_SETLINK`。`NetlinkRouteSocket::set_link`。TASK-136.3.2・#846）。
    LinkSet,
    /// link 削除要求 1 件（`RTM_DELLINK`。`NetlinkRouteSocket::delete_link`。TASK-139.1・#314）。
    LinkDelete,
    /// nf_tables バッチ 1 件の送信と ACK / エラー判定（`NetlinkNetfilterSocket::send_batch`。
    /// TASK-137.3・#306）。内側の send / recv も従来どおり個別に記録される。
    NftBatch,
    /// DNS ヘルパーの起動と準備完了待ち（`DnsHelperRefCounts::join`。TASK-144.1・#329・NET-7）。
    DnsHelperStart,
    /// DNS ヘルパーの停止と回収（`DnsHelperRefCounts::leave` / 再参加時の停止再試行。TASK-144.1・#329・NET-7）。
    DnsHelperStop,
    /// `--add-host` の hosts ファイル追記 1 件（`add_host_dns::apply_add_hosts_with_recorder`。
    /// 検証から追記・fsync までを含む。TASK-185.2・#345・NET-12）。
    AddHostsApply,
    /// host / none モードの `--dns` 反映（検証 + `resolv.conf` 原子的書き込み。`add_host_dns::resolv_conf`。
    /// TASK-185.4・#347・NET-12）。
    /// 軽量運用（`StaticHosts`）の `etc_hosts::apply_static_dns` でも使う（TASK-146.2・#336・NET-8）。
    DnsResolvConfWrite,
    /// 軽量運用（DNS ヘルパーなし）のサービス名 hosts 静的注入（検証 + 追記。
    /// `etc_hosts::inject_service_hosts_with_recorder`。TASK-146.1・#334・NET-8）。
    StaticHostsInject,
    /// pasta の起動と準備完了待ち（`pasta::process::spawn_pasta_with_recorder`。NET-9・#1938）。
    PastaStart,
    /// pasta の停止と回収（`PastaProcess::stop_with_recorder`。NET-9・#1938）。
    PastaStop,
    /// ネットワーク定義ストアの open（`NetworkStore::open`。NET-6・#3059）。
    NetworkStoreOpen,
    /// ネットワーク定義の作成（`NetworkStore::create`。ロック待ちを含む）。
    NetworkStoreCreate,
    /// ネットワーク定義の取得（`NetworkStore::get`）。
    NetworkStoreGet,
    /// ネットワーク定義の一覧（`NetworkStore::list`）。
    NetworkStoreList,
    /// ネットワーク定義の削除（`NetworkStore::remove`）。
    NetworkStoreRemove,
    /// メンバー記録・意図記録の書き込み（`NetworkLockGuard::write_member_intent` / `commit_member`。NET-1・#3067）。
    NetworkStoreMemberWrite,
    /// メンバー記録・意図記録の削除（`NetworkLockGuard::remove_member` / `remove_member_intent`。NET-1・#3067）。
    NetworkStoreMemberRemove,
    /// `realized`・`realized.intent` の書き込み（NET-1・#3067）。
    NetworkStoreRealizedWrite,
    /// `realized`・`realized.intent` の削除（NET-1・#3067）。
    NetworkStoreRealizedRemove,
    /// 記録からの IPAM の組み直し（`NetworkLockGuard::rebuild_ipam`。NET-1・#3067）。
    NetworkStoreIpamRebuild,
    /// 回収待ちの請求書の書き込み・削除（`pending-reclaim/`。NET-1・REPAIR-4・#3067）。
    NetworkStoreReclaimWrite,
    /// DNS ヘルパーの記録（`dns-helper`・`dns-helper.intent`）の書き込み（NET-5・NET-7・REPAIR-4・#3070）。
    NetworkStoreDnsHelperWrite,
    /// DNS ヘルパーの記録の削除（NET-5・NET-7・REPAIR-4・#3070）。
    NetworkStoreDnsHelperRemove,
    /// 起動窓の意図記録の回収（`recover_dns_helper_intent`。NET-5・NET-7・REPAIR-4・#3070）。
    DnsHelperRecover,
    /// 記録だけからのメンバー 1 件の切り離し全体（検証拒否・回収・記録の削除を含む。
    /// `detach_member_recorded_with`。NET-1・NET-6・REPAIR-4・#3347）。
    MemberDetachRecorded,
    /// ホストの再起動（boot ID の違い）をまたぐ記録だけからの切り離し全体
    /// （`detach_member_after_reboot_with`。NET-1・NET-3・REPAIR-4・#3412）。
    MemberDetachAfterReboot,
}

impl NetOpKind {
    /// core の `OpName` へ渡す安定した操作名。
    pub fn as_str(self) -> &'static str {
        match self {
            NetOpKind::NetlinkOpen => "netlink.open",
            NetOpKind::NetlinkSend => "netlink.send",
            NetOpKind::NetlinkRecv => "netlink.recv",
            NetOpKind::NetlinkRequest => "netlink.request",
            NetOpKind::LinkCreate => "netlink.link.create",
            NetOpKind::LinkSet => "netlink.link.set",
            NetOpKind::LinkDelete => "netlink.link.delete",
            NetOpKind::NftBatch => "nftables.batch",
            NetOpKind::DnsHelperStart => "dns.helper.start",
            NetOpKind::DnsHelperStop => "dns.helper.stop",
            NetOpKind::AddHostsApply => "hosts.add_host.apply",
            NetOpKind::DnsResolvConfWrite => "dns.resolv_conf.write",
            NetOpKind::StaticHostsInject => "hosts.static.inject",
            NetOpKind::PastaStart => "pasta.start",
            NetOpKind::PastaStop => "pasta.stop",
            NetOpKind::NetworkStoreOpen => "network.store.open",
            NetOpKind::NetworkStoreCreate => "network.store.create",
            NetOpKind::NetworkStoreGet => "network.store.get",
            NetOpKind::NetworkStoreList => "network.store.list",
            NetOpKind::NetworkStoreRemove => "network.store.remove",
            NetOpKind::NetworkStoreMemberWrite => "network.store.member_write",
            NetOpKind::NetworkStoreMemberRemove => "network.store.member_remove",
            NetOpKind::NetworkStoreRealizedWrite => "network.store.realized_write",
            NetOpKind::NetworkStoreRealizedRemove => "network.store.realized_remove",
            NetOpKind::NetworkStoreIpamRebuild => "network.store.ipam_rebuild",
            NetOpKind::NetworkStoreReclaimWrite => "network.store.reclaim_write",
            NetOpKind::NetworkStoreDnsHelperWrite => "network.store.dns_helper_write",
            NetOpKind::NetworkStoreDnsHelperRemove => "network.store.dns_helper_remove",
            NetOpKind::DnsHelperRecover => "dns.helper.recover",
            NetOpKind::MemberDetachRecorded => "network.member.detach_recorded",
            NetOpKind::MemberDetachAfterReboot => "network.member.detach_after_reboot",
        }
    }
}

/// 操作の結果区分（真偽値ではなく将来拡張できる型。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetOpOutcome {
    /// 成功。
    Success,
    /// 失敗（エラー・時間切れ・早期 return・panic を含む）。
    Failure,
}

impl NetOpOutcome {
    /// `Result` から結果区分を導く（中身は参照しない）。
    pub fn from_result<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => NetOpOutcome::Success,
            Err(_) => NetOpOutcome::Failure,
        }
    }
}

/// 1 回の操作の計測結果（固定サイズの値型。ヒープ確保なし）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetOpSample {
    kind: NetOpKind,
    outcome: NetOpOutcome,
    latency: Duration,
}

impl NetOpSample {
    /// サンプルを作る。
    pub fn new(kind: NetOpKind, outcome: NetOpOutcome, latency: Duration) -> Self {
        Self {
            kind,
            outcome,
            latency,
        }
    }

    /// 操作の種別。
    pub fn kind(&self) -> NetOpKind {
        self.kind
    }

    /// 操作の結果区分。
    pub fn outcome(&self) -> NetOpOutcome {
        self.outcome
    }

    /// 操作に要した時間。
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

/// net の計測結果を受け取る記録先（REPAIR-4）。
///
/// 契約: 送受信経路から呼ばれるため、有界時間で戻ること（I/O・相手応答待ち・無期限の
/// ロック待ちをしない。O(1) の短い有界ロックは許容。REPAIR-5）。panic しないこと。
/// 戻り値を `()` にしているのは、計測の失敗で本来の操作結果を変えないため。
/// `dyn NetOpRecorder` として `Arc` 共有できる。
pub trait NetOpRecorder: Send + Sync {
    /// 1 件の計測結果を記録する。
    fn record_net_op(&self, sample: &NetOpSample);
}

/// 計測しない場合に明示的に渡す既定実装。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopNetOpRecorder;

impl NetOpRecorder for NoopNetOpRecorder {
    fn record_net_op(&self, _sample: &NetOpSample) {}
}

/// 計測中の操作を表すガード。
///
/// [`finish_with`](Self::finish_with) で結果を確定する。未確定のまま Drop された場合
/// （早期 return・`?`・panic の巻き戻し）は `Failure` として記録する（fail-closed）。
#[must_use = "drop without finishing records a failure"]
pub struct NetOpTimer<'a> {
    recorder: &'a dyn NetOpRecorder,
    kind: NetOpKind,
    started: Instant,
    done: bool,
}

impl<'a> NetOpTimer<'a> {
    /// 計測を開始する。
    pub fn start(recorder: &'a dyn NetOpRecorder, kind: NetOpKind) -> Self {
        Self {
            recorder,
            kind,
            started: Instant::now(),
            done: false,
        }
    }

    fn emit(&mut self, outcome: NetOpOutcome) {
        if self.done {
            return;
        }
        self.done = true;
        let sample = NetOpSample::new(self.kind, outcome, self.started.elapsed());
        self.recorder.record_net_op(&sample);
    }

    /// `Result` に応じて確定する。
    pub fn finish_with<T, E>(mut self, result: &Result<T, E>) {
        self.emit(NetOpOutcome::from_result(result));
    }
}

impl Drop for NetOpTimer<'_> {
    fn drop(&mut self) {
        self.emit(NetOpOutcome::Failure);
    }
}

/// クロージャを計測して結果をそのまま返すヘルパー（panic 時もガードが Failure を記録する）。
pub fn record_net_op<T, E>(
    recorder: &dyn NetOpRecorder,
    kind: NetOpKind,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let timer = NetOpTimer::start(recorder, kind);
    let result = f();
    timer.finish_with(&result);
    result
}

#[cfg(test)]
pub(crate) mod testing {
    //! 記録内容を照合するための試験用記録先。
    use super::*;
    use std::sync::Mutex;

    /// 受け取ったサンプルを順に保持する。
    #[derive(Default)]
    pub(crate) struct Collect(Mutex<Vec<NetOpSample>>);

    impl NetOpRecorder for Collect {
        fn record_net_op(&self, s: &NetOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*s);
            }
        }
    }

    impl Collect {
        /// これまでに記録されたサンプル。
        pub(crate) fn items(&self) -> Vec<NetOpSample> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }

        /// (種別, 結果) の列。
        pub(crate) fn kinds(&self) -> Vec<(NetOpKind, NetOpOutcome)> {
            self.items()
                .iter()
                .map(|s| (s.kind(), s.outcome()))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Collect;
    use super::*;
    use std::sync::Arc;

    const ALL_KINDS: [NetOpKind; 31] = [
        NetOpKind::NetlinkOpen,
        NetOpKind::NetlinkSend,
        NetOpKind::NetlinkRecv,
        NetOpKind::NetlinkRequest,
        NetOpKind::LinkCreate,
        NetOpKind::LinkSet,
        NetOpKind::LinkDelete,
        NetOpKind::NftBatch,
        NetOpKind::DnsHelperStart,
        NetOpKind::DnsHelperStop,
        NetOpKind::AddHostsApply,
        NetOpKind::DnsResolvConfWrite,
        NetOpKind::StaticHostsInject,
        NetOpKind::PastaStart,
        NetOpKind::PastaStop,
        NetOpKind::NetworkStoreOpen,
        NetOpKind::NetworkStoreCreate,
        NetOpKind::NetworkStoreGet,
        NetOpKind::NetworkStoreList,
        NetOpKind::NetworkStoreRemove,
        NetOpKind::NetworkStoreMemberWrite,
        NetOpKind::NetworkStoreMemberRemove,
        NetOpKind::NetworkStoreRealizedWrite,
        NetOpKind::NetworkStoreRealizedRemove,
        NetOpKind::NetworkStoreIpamRebuild,
        NetOpKind::NetworkStoreReclaimWrite,
        NetOpKind::NetworkStoreDnsHelperWrite,
        NetOpKind::NetworkStoreDnsHelperRemove,
        NetOpKind::DnsHelperRecover,
        NetOpKind::MemberDetachRecorded,
        NetOpKind::MemberDetachAfterReboot,
    ];

    /// REPAIR-4: 操作名は安定した固定文字列。
    #[test]
    fn repair4_net_op_kind_as_str_is_stable() {
        assert_eq!(NetOpKind::NetlinkOpen.as_str(), "netlink.open");
        assert_eq!(NetOpKind::NetlinkSend.as_str(), "netlink.send");
        assert_eq!(NetOpKind::NetlinkRecv.as_str(), "netlink.recv");
        assert_eq!(NetOpKind::NetlinkRequest.as_str(), "netlink.request");
        assert_eq!(NetOpKind::LinkCreate.as_str(), "netlink.link.create");
        assert_eq!(NetOpKind::LinkSet.as_str(), "netlink.link.set");
        assert_eq!(NetOpKind::LinkDelete.as_str(), "netlink.link.delete");
        assert_eq!(NetOpKind::NftBatch.as_str(), "nftables.batch");
        assert_eq!(NetOpKind::DnsHelperStart.as_str(), "dns.helper.start");
        assert_eq!(NetOpKind::DnsHelperStop.as_str(), "dns.helper.stop");
        assert_eq!(NetOpKind::AddHostsApply.as_str(), "hosts.add_host.apply");
        assert_eq!(
            NetOpKind::DnsResolvConfWrite.as_str(),
            "dns.resolv_conf.write"
        );
        assert_eq!(NetOpKind::StaticHostsInject.as_str(), "hosts.static.inject");
        assert_eq!(
            NetOpKind::NetworkStoreMemberWrite.as_str(),
            "network.store.member_write"
        );
        assert_eq!(
            NetOpKind::NetworkStoreMemberRemove.as_str(),
            "network.store.member_remove"
        );
        assert_eq!(
            NetOpKind::NetworkStoreRealizedWrite.as_str(),
            "network.store.realized_write"
        );
        assert_eq!(
            NetOpKind::NetworkStoreRealizedRemove.as_str(),
            "network.store.realized_remove"
        );
        assert_eq!(
            NetOpKind::NetworkStoreIpamRebuild.as_str(),
            "network.store.ipam_rebuild"
        );
        assert_eq!(
            NetOpKind::NetworkStoreReclaimWrite.as_str(),
            "network.store.reclaim_write"
        );
        assert_eq!(
            NetOpKind::NetworkStoreDnsHelperWrite.as_str(),
            "network.store.dns_helper_write"
        );
        assert_eq!(
            NetOpKind::NetworkStoreDnsHelperRemove.as_str(),
            "network.store.dns_helper_remove"
        );
        assert_eq!(NetOpKind::DnsHelperRecover.as_str(), "dns.helper.recover");
        assert_eq!(
            NetOpKind::MemberDetachRecorded.as_str(),
            "network.member.detach_recorded"
        );
        assert_eq!(
            NetOpKind::MemberDetachAfterReboot.as_str(),
            "network.member.detach_after_reboot"
        );
        assert_eq!(NetOpKind::PastaStart.as_str(), "pasta.start");
        assert_eq!(NetOpKind::PastaStop.as_str(), "pasta.stop");
    }

    /// REPAIR-4: 操作名は core の `OpName::new` と同じ規則に収まる（net は core に依存できないため
    /// 重複して固定する）。
    #[test]
    fn repair4_net_op_kind_names_fit_core_op_name_contract() {
        for kind in ALL_KINDS {
            let s = kind.as_str();
            assert!(!s.is_empty() && s.len() <= 64);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            );
        }
    }

    /// REPAIR-4: 成功・失敗がそれぞれ 1 件ずつ、結果を変えずに記録される。
    #[test]
    fn repair4_record_net_op_counts_success_and_failure() {
        let c = Collect::default();
        let ok: Result<u32, ()> = record_net_op(&c, NetOpKind::NetlinkSend, || Ok(7));
        assert_eq!(ok, Ok(7));
        let err: Result<u32, &str> = record_net_op(&c, NetOpKind::NetlinkRecv, || Err("x"));
        assert_eq!(err, Err("x"));
        assert_eq!(
            c.kinds(),
            vec![
                (NetOpKind::NetlinkSend, NetOpOutcome::Success),
                (NetOpKind::NetlinkRecv, NetOpOutcome::Failure),
            ]
        );
    }

    /// REPAIR-4: レイテンシは操作に要した実時間を含む。
    #[test]
    fn repair4_record_net_op_measures_latency() {
        let c = Collect::default();
        let _: Result<(), ()> = record_net_op(&c, NetOpKind::NetlinkRecv, || {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        });
        let items = c.items();
        assert_eq!(items.len(), 1);
        let latency = items.first().map(NetOpSample::latency).expect("one sample");
        assert!(latency >= Duration::from_millis(20));
        assert!(latency < Duration::from_secs(5));
    }

    /// REPAIR-4: 未確定のまま Drop されたガードは Failure を 1 件記録する（fail-closed）。
    #[test]
    fn repair4_net_op_timer_drop_records_failure() {
        let c = Collect::default();
        {
            let _t = NetOpTimer::start(&c, NetOpKind::NetlinkOpen);
        }
        assert_eq!(
            c.kinds(),
            vec![(NetOpKind::NetlinkOpen, NetOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: panic で巻き戻っても Failure が 1 件だけ記録される。
    #[test]
    fn repair4_record_net_op_records_failure_on_panic() {
        let c = Collect::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ()> = record_net_op(&c, NetOpKind::NetlinkSend, || panic!("boom"));
        }));
        assert!(r.is_err());
        assert_eq!(
            c.kinds(),
            vec![(NetOpKind::NetlinkSend, NetOpOutcome::Failure)]
        );
    }

    /// REPAIR-4: 記録先は `Arc<dyn NetOpRecorder>` として共有でき、Send + Sync。
    #[test]
    fn repair4_net_op_recorder_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopNetOpRecorder>();
        assert_send_sync::<dyn NetOpRecorder>();
        let r: Arc<dyn NetOpRecorder> = Arc::new(NoopNetOpRecorder);
        let sample = NetOpSample::new(
            NetOpKind::NetlinkOpen,
            NetOpOutcome::Success,
            Duration::from_millis(3),
        );
        r.record_net_op(&sample);
        assert_eq!(sample.kind(), NetOpKind::NetlinkOpen);
        assert_eq!(sample.outcome(), NetOpOutcome::Success);
        assert_eq!(sample.latency(), Duration::from_millis(3));
    }
}
