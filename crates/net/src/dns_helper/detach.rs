//! DNS ヘルパーを親から切り離して起動し、記録（pid・開始時刻・boot id）で照合して pidfd 経由で停止する
//! （NET-5・NET-7・REPAIR-3・REPAIR-5・SEC-1・#3070。設計は `docs/design/network-wiring.md` の D11・D14・D15）。
//!
//! # 役割と呼び出し文脈
//! CORE-1 により、ヘルパーの起動（最初の attach）と停止（最後の detach）は別のプロセスで起きる。今の
//! `spawn_dns_helper` は `Child` を握った起動元の寿命に縛られ、`Drop` で止めるため、プロセスをまたいで停止できない
//! （試験専用として残す）。本モジュールは CLI・supervisor・`NetworkPlugin` の実装が、ネットワークの排他ロック
//! （`NetworkLockGuard`）を持ったまま呼ぶ入口を持つ。
//! - 起動 `spawn_detached_dns_helper`（Linux）: 段 1 が `setsid` して段 2（ヘルパー本体）を起動して即終了する二重 fork 相当
//! - 停止 `stop_recorded_dns_helper`（Linux）: 記録 → pidfd 取得 → 照合 → 停止要求 → 期限 → pidfd へ SIGKILL
//! - 起動窓の回収 `recover_dns_helper_intent`（Linux）: 意図記録が残っているときの nonce 照合による停止（D14 (iv)）
//! - 純粋な部分（停止の段の並び [`run_stop_sequence`]・参照カウントの遷移 [`helper_transition`]）は OS 非依存
//!
//! # 起動の手順（D14 (i)〜(iii)）
//! 1. `dns-helper.intent`（ネットワーク名・nonce・待受アドレス）を fsync して書く
//! 2. `program --dns-helper-detach --listen A --nonce N`（段 1）を起動する。段 1 は `setsid` して
//!    `/proc/self/exe --dns-helper-stage2 ...`（段 2）を起動し、待たずに終了する（段 2 は init か subreaper の子になる）
//! 3. 段 2 は自分の識別行 `IDENT <pid> <start> <boot> <nonce>` を stdout へ送り、stdin の `ACK` を
//!    [`DNS_HELPER_ACK_TIMEOUT`]（2 秒。D15）まで待つ。期限内に ack が無ければ bind せずに自分で終了する
//!    （起動元が記録の前に死んでも gateway:53 を握った孤児が残らない）
//! 4. 起動元は識別行を nonce・boot id・pidfd 上の開始時刻で照合し、意図記録へ同一性（pid・開始時刻・boot id）を
//!    原子的に追記し（#3344）、`dns-helper` を fsync して書いてから ack を返す
//! 5. 段 2 が bind して `READY <addr>` を返したら、意図記録を消す
//!
//! # 停止の手順（D11）
//! 記録の pid で `pidfd_open` を先に行い、その後で開始時刻と boot id を照合する（照合と操作の間の pid の再利用で
//! 別のプロセスに触れない）。一致しなければ何も送らず、記録を古いものとして消す。一致すれば、停止要求（制御 UDS は
//! #3071。未接続の間は [`NoStopRequest`] が [`RequestOutcome::Unavailable`] を返し、猶予の待ちを飛ばす）→
//! [`DNS_HELPER_STOP_GRACE`] の待機 → pidfd へ SIGKILL → [`DNS_HELPER_KILL_REAP_TIMEOUT`] の待機の順に進める。
//! pid 番号へもシグナルを送らない。`pidfd_open` が使えないカーネル（Linux 5.3 未満）は記録を残して `Unimplemented`。
//!
//! # 未実装（REPAIR-3）
//! - 停止要求（制御 UDS の `Reload`/`Stop`）は #3071。いまは要求できないため SIGKILL の段へ進む
//! - 参照カウントはメンバー記録 `members/*` の件数を正とする（#3067）。配線は #3067・#3074 で、本モジュールは
//!   遷移の判定 [`helper_transition`] だけを持つ
//! - 起動窓の回収の候補 pid（`net-helpers` の cgroup の `cgroup.procs`）は #3074 の呼び出し側が渡す。cgroup の
//!   列挙は本モジュールでは行わない。子は ack の期限（2 秒）で自分から終了するため、通常はこの経路に入る前に
//!   消えている（入るのは、ack を受けた後で起動元が記録を確定する前に死んだ場合）
//! - 回収前に終了したゾンビは cmdline が空で、cgroup v2 では `cgroup.procs` にも現れない。識別行の照合後に意図記録へ
//!   追記した同一性（#3344）があれば、回収は候補の列挙に依らずその同一性で pidfd を取って照合し、停止または
//!   `waitid` で回収する。SPAWN 行も識別行も得られず pid が分からない窓は帰属できない（段 2 は ack の期限で終了する）
//! - 呼び出し元が child subreaper のとき、切り離した孫は呼び出し元の子になる。停止後に `waitid(P_PIDFD, WNOHANG)`
//!   で回収する。cgroup の配置（`net-helpers`）は #3074

use std::time::Duration;

use crate::error::{NetError, NetErrorCode};

use super::record::DnsHelperRecord;

/// 起動時の ack の待ち（D15 の DNS の ack）。段 2 が ack を待つ期限であり、起動元が識別行を待つ期限でもある。
pub const DNS_HELPER_ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// 停止要求を送った後、ヘルパーが自分で終わるのを待つ猶予。D15 に値の明記が無いため ack と同じ 2 秒とする
/// （`check_timeout` の範囲 0 < t ≤ 10 秒に収まる）。
pub const DNS_HELPER_STOP_GRACE: Duration = Duration::from_secs(2);
/// SIGKILL を送った後、pidfd の可読化（終了）を待つ期限（`REAP_TIMEOUT_DEFAULT` と同じ 2 秒）。
pub const DNS_HELPER_KILL_REAP_TIMEOUT: Duration = Duration::from_secs(2);
/// 起動窓の回収（`recover_dns_helper_intent`）全体の期限。候補の走査が超えたら意図記録を残して `Timeout`。
pub const DNS_HELPER_RECOVER_TIMEOUT: Duration = Duration::from_secs(30);
/// 段 1 の終了を待つ上限。
pub const DNS_HELPER_STAGE1_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
/// 識別行の最大バイト数。
pub const IDENT_LINE_MAX: usize = 128;
/// 起動窓の回収で調べる候補 pid の最大数（無制限の走査の防止）。
pub const MAX_RECOVERY_CANDIDATES: usize = 4096;

/// 段 1 を指す起動引数。
pub const ARG_DETACH: &str = "--dns-helper-detach";
/// 段 2 を指す起動引数。
pub const ARG_STAGE2: &str = "--dns-helper-stage2";
/// nonce を渡す起動引数。
pub const ARG_NONCE: &str = "--nonce";

#[cfg(target_os = "linux")]
const IDENT_PREFIX: &str = "IDENT ";

/// 段 1 が段 2 の pid を起動元へ知らせる行の接頭辞（`SPAWN <pid>`）。
#[cfg(target_os = "linux")]
const SPAWN_PREFIX: &str = "SPAWN ";
#[cfg(target_os = "linux")]
const ACK: &[u8; 4] = b"ACK\n";

/// メンバー記録の件数の変化に対するヘルパーの遷移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelperTransition {
    /// 0 → 1。起動する。
    Start,
    /// 1 → 0。停止する。
    Stop,
    /// それ以外。何もしない。
    Keep,
}

/// ネットワークのロックの下で数えたメンバー記録（`members/*`。#3067）の前後の件数から、ヘルパーの遷移を決める。
/// 参照カウントは件数の変更ではなく記録の件数が正で、プロセスをまたいで一致する（CORE-1・NET-7）。
pub fn helper_transition(members_before: usize, members_after: usize) -> HelperTransition {
    match (members_before, members_after) {
        (0, a) if a >= 1 => HelperTransition::Start,
        (b, 0) if b >= 1 => HelperTransition::Stop,
        _ => HelperTransition::Keep,
    }
}

/// 停止要求の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestOutcome {
    /// 要求を送った（猶予の間、ヘルパーの自発的な終了を待つ）。
    Sent,
    /// 要求できない（猶予の待ちを飛ばして SIGKILL の段へ進む）。
    Unavailable,
}

/// 停止要求の送り手（制御 UDS。#3071）。pid 番号へも pidfd 経由でもシグナルを送らない（D11）。
pub trait DnsHelperStopRequest {
    /// 記録のヘルパーへ停止を要求する。
    fn request(&self, record: &DnsHelperRecord) -> RequestOutcome;
}

/// 制御 UDS（#3071）が未接続の間の既定。要求を送ったふりをせず `Unavailable` を返す（REPAIR-3）。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStopRequest;

impl DnsHelperStopRequest for NoStopRequest {
    fn request(&self, _record: &DnsHelperRecord) -> RequestOutcome {
        RequestOutcome::Unavailable
    }
}

/// 停止の段の駆動に必要なプロセス操作（本番は pidfd、試験は偽実装で呼び出しの列を照合する）。
pub trait HelperProcessOps {
    /// 停止を要求する。
    fn request(&mut self) -> RequestOutcome;
    /// 終了を `timeout` まで待つ。終了していれば true。
    fn wait_exit(&mut self, timeout: Duration) -> Result<bool, NetError>;
    /// 強制終了させる（既に終了していれば成功）。
    fn kill(&mut self) -> Result<(), NetError>;
}

/// 停止がどの段で終わったか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopStage {
    /// 停止要求の後、猶予内に自分で終了した。
    StoppedOnRequest,
    /// SIGKILL で終了した。
    Killed,
}

/// 停止の段の並び（要求 → 猶予 → SIGKILL → 待機）を駆動する。SIGKILL の後も終了しなければ `Timeout`
/// （呼び出し側は記録を残し、次の操作で再試行できる）。
pub fn run_stop_sequence(
    ops: &mut dyn HelperProcessOps,
    grace: Duration,
    kill_wait: Duration,
) -> Result<StopStage, NetError> {
    if ops.request() == RequestOutcome::Sent && ops.wait_exit(grace)? {
        return Ok(StopStage::StoppedOnRequest);
    }
    ops.kill()?;
    if ops.wait_exit(kill_wait)? {
        Ok(StopStage::Killed)
    } else {
        Err(NetError::new(
            NetErrorCode::Timeout,
            "dns helper did not exit before the deadline",
        ))
    }
}

/// 記録による停止の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopOutcome {
    /// 記録が無かった。
    NoRecord,
    /// 記録のプロセスは既に無かった（記録は消した）。
    AlreadyGone,
    /// pid は別のプロセスに再利用されていた（何も送らず記録を消した）。
    StaleRecord,
    /// 停止要求で自分から終了した。
    StoppedOnRequest,
    /// SIGKILL で止めた。
    Killed,
}

#[cfg(target_os = "linux")]
mod os;
#[cfg(target_os = "linux")]
pub use os::{
    DetachedDnsHelper, IntentRecovery, recover_dns_helper_intent, spawn_detached_dns_helper,
    stop_recorded_dns_helper,
};
#[cfg(target_os = "linux")]
pub(crate) use os::{run_stage1, run_stage2_handshake};

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Request,
        Wait(Duration),
        Kill,
    }

    struct Fake {
        calls: Vec<Call>,
        request: RequestOutcome,
        exits_at: Vec<bool>,
    }

    impl Fake {
        fn new(request: RequestOutcome, exits_at: &[bool]) -> Self {
            let mut e = exits_at.to_vec();
            e.reverse();
            Self {
                calls: Vec::new(),
                request,
                exits_at: e,
            }
        }
    }

    impl HelperProcessOps for Fake {
        fn request(&mut self) -> RequestOutcome {
            self.calls.push(Call::Request);
            self.request
        }
        fn wait_exit(&mut self, timeout: Duration) -> Result<bool, NetError> {
            self.calls.push(Call::Wait(timeout));
            Ok(self.exits_at.pop().unwrap_or(false))
        }
        fn kill(&mut self) -> Result<(), NetError> {
            self.calls.push(Call::Kill);
            Ok(())
        }
    }

    const G: Duration = DNS_HELPER_STOP_GRACE;
    const K: Duration = DNS_HELPER_KILL_REAP_TIMEOUT;

    /// D15・REPAIR-5・#3070: 期限は 2 秒の具体値。
    #[test]
    fn net7_3070_timeout_constants() {
        assert_eq!(DNS_HELPER_ACK_TIMEOUT, Duration::from_secs(2));
        assert_eq!(DNS_HELPER_STOP_GRACE, Duration::from_secs(2));
        assert_eq!(DNS_HELPER_KILL_REAP_TIMEOUT, Duration::from_secs(2));
        assert_eq!(DNS_HELPER_STAGE1_EXIT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(IDENT_LINE_MAX, 128);
    }

    /// D11・#3070: 要求が通り猶予内に終了したら SIGKILL を送らない。
    #[test]
    fn net7_3070_sequence_stops_on_request_without_kill() {
        let mut f = Fake::new(RequestOutcome::Sent, &[true]);
        assert_eq!(
            run_stop_sequence(&mut f, G, K).expect("seq"),
            StopStage::StoppedOnRequest
        );
        assert_eq!(f.calls, vec![Call::Request, Call::Wait(G)]);
    }

    /// D11・#3070: 要求の後も終了しなければ、猶予の後に SIGKILL を送って待つ（要求 → 期限 → SIGKILL の順）。
    #[test]
    fn net7_3070_sequence_request_then_grace_then_kill() {
        let mut f = Fake::new(RequestOutcome::Sent, &[false, true]);
        assert_eq!(
            run_stop_sequence(&mut f, G, K).expect("seq"),
            StopStage::Killed
        );
        assert_eq!(
            f.calls,
            vec![Call::Request, Call::Wait(G), Call::Kill, Call::Wait(K)]
        );
    }

    /// D11・REPAIR-3・#3070: 要求できない間は猶予の待ちを飛ばして SIGKILL の段へ進む。
    #[test]
    fn net7_3070_sequence_without_request_skips_grace() {
        let mut f = Fake::new(RequestOutcome::Unavailable, &[true]);
        assert_eq!(
            run_stop_sequence(&mut f, G, K).expect("seq"),
            StopStage::Killed
        );
        assert_eq!(f.calls, vec![Call::Request, Call::Kill, Call::Wait(K)]);
    }

    /// REPAIR-5・#3070: SIGKILL の後も終了しなければ `Timeout`。
    #[test]
    fn net7_3070_sequence_times_out_after_kill() {
        let mut f = Fake::new(RequestOutcome::Unavailable, &[false]);
        let e = run_stop_sequence(&mut f, G, K).expect_err("timeout");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(f.calls, vec![Call::Request, Call::Kill, Call::Wait(K)]);
    }

    /// NET-7・#3070: 参照カウントの遷移は件数の前後で決まる。
    #[test]
    fn net7_3070_helper_transition_table() {
        use HelperTransition::{Keep, Start, Stop};
        for (before, after, want) in [
            (0, 1, Start),
            (1, 2, Keep),
            (2, 1, Keep),
            (1, 0, Stop),
            (0, 0, Keep),
            (2, 0, Stop),
            (0, 3, Start),
            (3, 3, Keep),
        ] {
            assert_eq!(helper_transition(before, after), want, "{before}->{after}");
        }
    }
}
