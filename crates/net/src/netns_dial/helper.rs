//! `netns-dial` helper プロセスの本体（Linux のみ。CRI-6・NET-3・SEC-1・REPAIR-5・#4479）。手順と契約は親モジュール
//! `crate::netns_dial` の `//!` を参照。supervisor の bin の main が第 1 引数 `netns-dial` で `run_netns_dial_main`
//! へ振り分けて呼ぶ（振り分けは #4482）。
//!
//! 単一スレッドで同期的に動く（`setns(CLONE_NEWUSER)` が多スレッドで `EINVAL` になるため。`kernel/user_namespace.c` の
//! `userns_install` が `thread_group_empty` を要求する）。待ちは `poll(2)` と `TcpStream::connect_timeout`（スレッドを
//! 作らない）だけ。stderr は null の契約のため何も書かず、診断は固定語彙の応答 frame だけで返す。
//! unsafe は持たず、syscall は `crate::sys::holder` の安全なラッパーだけを使う。
//!
//! holder（`crate::netns_holder`）との差: (1) 診断を stderr に出さない、(2) dumpable を起動直後に 0 にし、参加後と
//! 特権の破棄の後にも 0 であることを確かめる（窓は exec から最初の `PR_SET_DUMPABLE` までに縮む。#4558）、
//! (3) 副作用の前に argv を検査し、継承 fd の整理は stdin の素性確認の後に行う。親の照合・期限つき受信・ns の識別の取得の本体は
//! `crate::netns_helper` と共有し（REPAIR-1・#4510）、ここは固定語彙 `DialErrorCode` への写像だけを持つ。
//!
//! # 失敗から固定語彙への対応（Agent が安全側に倒して記録した判断。オーナーの承認は得ていない）
//! | 段 | 失敗 | 応答 | 終了コード |
//! | -- | ---- | ---- | ---------- |
//! | argv | 引数が空でない | なし | 2 |
//! | 起動直後の non-dumpable | prctl の失敗・値が 0 でない | なし（素性を確かめる前なので書かない） | 1 |
//! | stdin / peer | seqpacket でない・親が作成者でない | なし（素性の知れない相手へ書かない） | 1 |
//! | 準備 | `close_range` の失敗 | `JoinFailed` | 1 |
//! | 受信 | 期限切れ・EOF・切り詰め・decode 失敗・kind 違い・fd が 2 本でない | `InvalidRequest` | 1 |
//! | 前検査 | 2 本が同一 fs 上の別の ns でない | `InvalidRequest` | 1 |
//! | 参加 | `setns` の失敗・`/proc/self/ns` を開けない・参加後に dumpable が 0 でない | `JoinFailed` | 1 |
//! | 照合 | 参加後の (dev, ino) が受けた fd と違う | `IdentityMismatch` | 1 |
//! | 特権の破棄 | capset・NNP・PDEATHSIG・non-dumpable の失敗 | `JoinFailed` | 1 |
//! | connect | `127.0.0.1` と `::1` の両方が失敗。IPv4 の理由を返す。どちらかが期限切れ、または IPv4 の後に残りが 0 なら `TimedOut`（未知は fail-closed で `Unreachable`） | `Refused` / `TimedOut` / `Unreachable` | 1 |
//! | 応答 | `Connected` + fd 1 本を送れた | `Connected` | 0 |
//!
//! connect は固定の 2 宛先を順に試す（#4572。containerd の `sandbox_portforward_linux.go` が `tcp4` の後に `tcp6` を
//! 試すのに合わせた。オーナーが決めたのは「IPv4 で失敗したら `::1` でつなぎ直す・宛先は 2 つに固定・期限は延ばさない」
//! まで）。両方失敗したときの理由の選び方（IPv4 の理由を返し、期限切れは `TimedOut` で区別する）は Agent が安全側に
//! 倒して記録した判断で、オーナーの承認は得ていない。要求の期限 C は `Deadline` 1 つで共有し、IPv6 には残り時間だけを渡す。
//!
//! 受信の期限切れを `TimedOut` にしないのは、`TimedOut` を connect の期限切れ専用にして、親側（#4480）が
//! 区別できるようにするため。

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::process::ExitCode;
use std::time::Duration;

use super::REQUEST_RECV_TIMEOUT;
use super::frame::{
    DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame, FRAME_LEN,
};
use crate::netns_helper as helper;
use crate::sys::Deadline;
use crate::sys::holder as sysh;

/// 受けた 2 本または参加後の ns の識別（`fstat` / `/proc/self/ns` の dev・ino）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NsPair {
    pub user: (u64, u64),
    pub net: (u64, u64),
}

/// 参加後の識別が受けた fd の識別と一致するかを照合する（純関数）。不一致は `IdentityMismatch`。
pub(super) fn check_joined_identity(
    received: NsPair,
    observed: NsPair,
) -> Result<(), DialErrorCode> {
    if received == observed {
        Ok(())
    } else {
        Err(DialErrorCode::IdentityMismatch)
    }
}

/// argv の検査（純関数）。可変値は argv に載せないため、非空は終了コード 2。
pub(super) fn check_args(mut args: impl Iterator<Item = OsString>) -> Result<(), u8> {
    if args.next().is_none() {
        Ok(())
    } else {
        Err(2)
    }
}

const ETIMEDOUT: i32 = 110;
const ECONNREFUSED: i32 = 111;

/// connect の失敗を固定語彙に分類する（純関数）。`ErrorKind` を優先し、補助で errno を見る。未知は `Unreachable`。
pub(super) fn classify_connect_error(e: &io::Error) -> DialErrorCode {
    use io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => DialErrorCode::Refused,
        K::TimedOut | K::WouldBlock => DialErrorCode::TimedOut,
        _ => match e.raw_os_error() {
            Some(n) if n == ETIMEDOUT => DialErrorCode::TimedOut,
            Some(n) if n == ECONNREFUSED => DialErrorCode::Refused,
            _ => DialErrorCode::Unreachable,
        },
    }
}

/// 参加と特権の破棄の継ぎ目。本番は [`RealJoiner`]。不可逆な操作（setns・capset・NNP・non-dumpable）を
/// libtest の試験バイナリで実行しないために分ける（実プロセスの経路は結合試験 `netns_dial_process`、実 namespace への
/// 参加は実機前提の `netns_dial_userns` が担う）。
pub(super) trait Joiner {
    /// `setns(user)` → `setns(net)` の順に参加し、参加後の識別を `received` と照合し、fd を閉じる。
    fn join(&mut self, user: OwnedFd, net: OwnedFd, received: NsPair) -> Result<(), DialErrorCode>;
    /// capability を空にし、NNP・PDEATHSIG の再武装・non-dumpable を確かめる。
    fn harden(&mut self) -> Result<(), DialErrorCode>;
}

/// 本番の [`Joiner`]。試験専用の入口（`test_support`、feature `netns-dial-test-support`）が包んで 3 時点の
/// dumpable を記録するため `pub(super)` にしている。
pub(super) struct RealJoiner;

fn identity_of(file: &File) -> Result<(u64, u64), DialErrorCode> {
    helper::fd_identity(file).map_err(|_| DialErrorCode::InvalidRequest)
}

fn observed_identity(ns: helper::JoinedNs) -> Result<(u64, u64), DialErrorCode> {
    helper::self_ns_identity(ns).map_err(|_| DialErrorCode::JoinFailed)
}

impl Joiner for RealJoiner {
    fn join(&mut self, user: OwnedFd, net: OwnedFd, received: NsPair) -> Result<(), DialErrorCode> {
        sysh::join_namespace(user.as_fd(), sysh::CLONE_NEWUSER)
            .map_err(|_| DialErrorCode::JoinFailed)?;
        sysh::join_namespace(net.as_fd(), sysh::CLONE_NEWNET)
            .map_err(|_| DialErrorCode::JoinFailed)?;
        let observed = NsPair {
            user: observed_identity(helper::JoinedNs::User)?,
            net: observed_identity(helper::JoinedNs::Net)?,
        };
        check_joined_identity(received, observed)?;
        // 起動直後に 0 にした dumpable が、参加（`commit_creds`）で `suid_dumpable` へ戻っていないことを確かめる。
        // 現在受ける構成（rootless・保持役が同じ euid で作った userns）では戻らない（v6.12 `kernel/cred.c`
        // `commit_creds` は euid 等の変更か `!cred_cap_issubset` のときだけ戻す）。戻ったら想定外なので fail-closed。
        match sysh::get_dumpable() {
            Ok(0) => {}
            _ => return Err(DialErrorCode::JoinFailed),
        }
        drop(user);
        drop(net);
        Ok(())
    }

    fn harden(&mut self) -> Result<(), DialErrorCode> {
        sysh::drop_all_capabilities().map_err(|_| DialErrorCode::JoinFailed)?;
        sysh::set_no_new_privs().map_err(|_| DialErrorCode::JoinFailed)?;
        // 資格情報が変わった後でも PDEATHSIG が効いていることを設定し直して確かめる。
        sysh::set_pdeathsig_sigkill().map_err(|_| DialErrorCode::JoinFailed)?;
        match sysh::get_pdeathsig() {
            Ok(s) if s == sysh::PR_SIGKILL => {}
            _ => return Err(DialErrorCode::JoinFailed),
        }
        // holder（pasta が /proc を開ける前提で dumpable）と違い、dial helper は同じ uid からの観測を塞ぐ。
        // 起動直後に設定済みだが、capset の後の最後の層として設定し直して確かめる。
        sysh::set_non_dumpable().map_err(|_| DialErrorCode::JoinFailed)?;
        match sysh::get_dumpable() {
            Ok(0) => Ok(()),
            _ => Err(DialErrorCode::JoinFailed),
        }
    }
}

/// `serve` の結果（試験で具体値を照合するための型。終了コードへは `exit_code` で写す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// `Connected` と fd 1 本を送れた。
    Connected,
    /// `Error(code)` を送れた。
    Responded(DialErrorCode),
    /// 応答を送れなかった（相手が閉じた等）。`None` は `Connected` を送ろうとした場合。
    SendFailed(Option<DialErrorCode>),
}

impl Outcome {
    fn exit_code(self) -> ExitCode {
        match self {
            Outcome::Connected => ExitCode::SUCCESS,
            _ => ExitCode::from(1),
        }
    }
}

/// 期限つきで要求 1 通と fd 2 本を受ける。拒否はすべて `InvalidRequest`（受信の期限切れを含む）。
fn receive_request(
    fd: BorrowedFd<'_>,
    deadline: &Deadline,
) -> Result<(DialRequest, OwnedFd, OwnedFd), DialErrorCode> {
    let mut buf = [0u8; FRAME_LEN];
    // 受信の失敗は期限切れを含めてすべて `InvalidRequest`（`TimedOut` は connect 専用）。
    let got = helper::recv_before_deadline(fd, deadline, &mut buf, sysh::MAX_FDS)
        .map_err(|_| DialErrorCode::InvalidRequest)?;
    if got.ctrl_truncated || got.data_truncated {
        return Err(DialErrorCode::InvalidRequest);
    }
    let req = DialRequestFrame::decode(buf.get(..got.len).unwrap_or(&[]))
        .map_err(|_| DialErrorCode::InvalidRequest)?;
    let mut it = got.fds.into_iter();
    let (Some(user), Some(net), None) = (it.next(), it.next(), it.next()) else {
        return Err(DialErrorCode::InvalidRequest);
    };
    Ok((req, user, net))
}

/// helper が試す宛先（固定。要求から組み立てない）。順序が優先順位で、IPv4 を先に試す。
const LOOPBACK_ADDRS: [std::net::IpAddr; 2] = [
    std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
    std::net::IpAddr::V6(Ipv6Addr::LOCALHOST),
];

/// つなぎ直しの判断（純関数。接続と残り時間を注入して試験する。#4572）。
///
/// 1. `127.0.0.1:port` へ `remaining()` の期間で接続し、成功ならそれを返す。
/// 2. 失敗が期限切れなら `TimedOut` を返し、IPv6 は試さない。
/// 3. 改めて `remaining()` を読み、0 なら `TimedOut`（`TcpStream::connect_timeout` は 0 の期間を `InvalidInput` で
///    拒否し、それが `Unreachable` に化けるため分ける）。
/// 4. 残り時間で `[::1]:port` へ接続し、成功ならそれを返す。失敗が期限切れなら `TimedOut`、それ以外は IPv4 の理由。
///
/// 合計の待ちは `remaining()` が基づく期限 C を超えない（延ばさない）。
fn dial_loopback_with<T>(
    port: u16,
    mut connect: impl FnMut(SocketAddr, Duration) -> io::Result<T>,
    mut remaining: impl FnMut() -> Duration,
) -> Result<T, DialErrorCode> {
    let [first, second] = LOOPBACK_ADDRS;
    let first_err = match connect(SocketAddr::new(first, port), remaining()) {
        Ok(v) => return Ok(v),
        Err(e) => classify_connect_error(&e),
    };
    if first_err == DialErrorCode::TimedOut {
        return Err(DialErrorCode::TimedOut);
    }
    let left = remaining();
    if left.is_zero() {
        return Err(DialErrorCode::TimedOut);
    }
    match connect(SocketAddr::new(second, port), left) {
        Ok(v) => Ok(v),
        Err(e) if classify_connect_error(&e) == DialErrorCode::TimedOut => {
            Err(DialErrorCode::TimedOut)
        }
        Err(_) => Err(first_err),
    }
}

/// 宛先は `127.0.0.1`、失敗したら `::1` の固定（[`dial_loopback_with`]）。スレッドを作らず、期限は要求の値
/// （上限 10 秒）を IPv4 の試行の直前から数える `Deadline` 1 つで両方の試行が共有する。
fn connect_loopback(req: &DialRequest) -> Result<TcpStream, DialErrorCode> {
    let deadline = Deadline::after(req.connect_timeout().as_duration());
    dial_loopback_with(
        req.port().get(),
        |addr, timeout| TcpStream::connect_timeout(&addr, timeout),
        || deadline.remaining(),
    )
}

fn respond_error(fd: BorrowedFd<'_>, code: DialErrorCode) -> Outcome {
    let frame = DialResponseFrame::encode(DialResponse::Error(code));
    match sysh::send_with_fds(fd, frame.as_bytes(), &[], true) {
        Ok(_) => Outcome::Responded(code),
        Err(_) => Outcome::SendFailed(Some(code)),
    }
}

/// 受信から応答までの本体（stdin の確認と継承 fd の整理は呼び出し側 `run`）。試験が `Joiner` を差し替えて駆動する。
pub(super) fn serve(
    fd: BorrowedFd<'_>,
    recv_timeout: Duration,
    joiner: &mut impl Joiner,
) -> Outcome {
    let (req, user_fd, net_fd) = match receive_request(fd, &Deadline::after(recv_timeout)) {
        Ok(v) => v,
        Err(code) => return respond_error(fd, code),
    };
    let user = File::from(user_fd);
    let net = File::from(net_fd);
    let (Ok(u), Ok(n)) = (identity_of(&user), identity_of(&net)) else {
        return respond_error(fd, DialErrorCode::InvalidRequest);
    };
    if u.0 != n.0 || u.1 == n.1 {
        return respond_error(fd, DialErrorCode::InvalidRequest);
    }
    if let Err(code) = joiner.join(user.into(), net.into(), NsPair { user: u, net: n }) {
        return respond_error(fd, code);
    }
    if let Err(code) = joiner.harden() {
        return respond_error(fd, code);
    }
    let stream = match connect_loopback(&req) {
        Ok(s) => s,
        Err(code) => return respond_error(fd, code),
    };
    let frame = DialResponseFrame::encode(DialResponse::Connected);
    match sysh::send_one_fd(fd, frame.as_bytes(), stream.as_fd(), true) {
        Ok(_) => Outcome::Connected,
        Err(_) => Outcome::SendFailed(None),
    }
}

/// `run_netns_dial_main` の本体（`crate::netns_dial` から委譲される）。終了コードは `Connected` を送れたら 0、
/// それ以外の失敗は 1、argv の誤りは 2。
pub(super) fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    run_with(args, &mut RealJoiner)
}

/// [`run`] の本体。`joiner` を差し替えられるのは試験専用の入口（`test_support`）が 3 時点の dumpable を記録するため
/// （本番は常に [`RealJoiner`]）。dumpable は argv の検査の直後、副作用（PDEATHSIG・stdin の確認・参加）の前に 0 にする。
/// exec で dumpable は戻るので親側から先に設定することはできず、窓は exec からここまで（#4558・SEC-1）。
pub(super) fn run_with(args: impl Iterator<Item = OsString>, joiner: &mut impl Joiner) -> ExitCode {
    if let Err(c) = check_args(args) {
        return ExitCode::from(c);
    }
    // 素性を確かめる前なので失敗しても応答は書かない。
    if sysh::set_non_dumpable().is_err() || !matches!(sysh::get_dumpable(), Ok(0)) {
        return ExitCode::from(1);
    }
    if sysh::set_pdeathsig_sigkill().is_err() {
        return ExitCode::from(1);
    }
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    // 応答先が seqpacket でなければ書けない。親が作成者でなければ素性の知れない相手なので書かない。
    match sysh::socket_type(fd) {
        Ok(t) if t == sysh::SOCK_SEQPACKET => {}
        _ => return ExitCode::from(1),
    }
    if helper::check_parent_is_creator(fd).is_err() {
        return ExitCode::from(1);
    }
    if sysh::close_inherited_fds().is_err() {
        return respond_error(fd, DialErrorCode::JoinFailed).exit_code();
    }
    serve(fd, REQUEST_RECV_TIMEOUT, joiner).exit_code()
}

#[cfg(test)]
mod tests {
    //! `RealJoiner`（setns・capset・NNP・non-dumpable）は不可逆でプロセス全体に効くため、ここでは呼ばない。
    //! 実際の setns の成功経路は実機前提試験 `netns_dial_userns` が担う。`run` も `close_range` が
    //! 試験ハーネスの fd を閉じるため呼ばない（argv の検査だけ `check_args` で試験する）。
    use super::*;
    use crate::netns_dial::frame::ConnectTimeout;
    use std::net::TcpListener;
    use std::num::NonZeroU16;
    use std::time::Instant;

    struct FakeJoiner {
        join_result: Result<(), DialErrorCode>,
        harden_result: Result<(), DialErrorCode>,
        joined: bool,
        hardened: bool,
    }

    impl FakeJoiner {
        fn ok() -> Self {
            Self {
                join_result: Ok(()),
                harden_result: Ok(()),
                joined: false,
                hardened: false,
            }
        }
    }

    impl Joiner for FakeJoiner {
        fn join(&mut self, _: OwnedFd, _: OwnedFd, _: NsPair) -> Result<(), DialErrorCode> {
            self.joined = true;
            self.join_result
        }
        fn harden(&mut self) -> Result<(), DialErrorCode> {
            self.hardened = true;
            self.harden_result
        }
    }

    fn req_frame(port: u16) -> DialRequestFrame {
        DialRequestFrame::encode(DialRequest::new(
            NonZeroU16::new(port).unwrap(),
            ConnectTimeout::new(1000).unwrap(),
        ))
    }

    /// 識別の異なる 2 本の fd（同一 fs 上の別 inode）。
    fn two_fds() -> (File, File) {
        (
            File::open("/dev/null").unwrap(),
            File::open("/dev/zero").unwrap(),
        )
    }

    fn recv_resp(parent: BorrowedFd<'_>) -> (DialResponse, Vec<OwnedFd>) {
        let mut buf = [0u8; FRAME_LEN];
        let r = sysh::recv_with_fds(parent, &mut buf, sysh::MAX_FDS).unwrap();
        assert!(!r.ctrl_truncated);
        (DialResponseFrame::decode(&buf[..r.len]).unwrap(), r.fds)
    }

    /// 要求を送って `serve` を同スレッドで駆動する（応答は seqpacket のバッファに残るので送り→serve→受けの順でよい）。
    fn drive(
        data: &[u8],
        fds: &[BorrowedFd<'_>],
        joiner: &mut FakeJoiner,
    ) -> (Outcome, DialResponse, Vec<OwnedFd>) {
        let (parent, child) = sysh::socketpair_seqpacket().unwrap();
        sysh::send_with_fds(parent.as_fd(), data, fds, false).unwrap();
        let out = serve(child.as_fd(), Duration::from_secs(2), joiner);
        let (resp, got) = recv_resp(parent.as_fd());
        (out, resp, got)
    }

    /// CRI-6・REPAIR-5: 受信の期限切れは InvalidRequest（TimedOut ではない）で、joiner に触れない。
    #[test]
    fn cri6_4479_recv_deadline_returns_invalid_request() {
        let (parent, child) = sysh::socketpair_seqpacket().unwrap();
        let mut j = FakeJoiner::ok();
        let t = Instant::now();
        let out = serve(child.as_fd(), Duration::from_millis(100), &mut j);
        let el = t.elapsed();
        assert_eq!(out, Outcome::Responded(DialErrorCode::InvalidRequest));
        assert!(
            el >= Duration::from_millis(100) && el < Duration::from_secs(2),
            "{el:?}"
        );
        let (resp, fds) = recv_resp(parent.as_fd());
        assert_eq!(resp, DialResponse::Error(DialErrorCode::InvalidRequest));
        assert_eq!(fds.len(), 0);
        assert!(!j.joined && !j.hardened);
    }

    /// CRI-6・SEC-1: fd が 0・1・3 本のときは InvalidRequest。
    #[test]
    fn sec1_4479_wrong_fd_count_is_invalid_request() {
        let (a, b) = two_fds();
        let c = File::open("/dev/random").unwrap();
        let frame = req_frame(9);
        let cases: [Vec<BorrowedFd<'_>>; 3] = [
            vec![],
            vec![a.as_fd()],
            vec![a.as_fd(), b.as_fd(), c.as_fd()],
        ];
        for fds in &cases {
            let mut j = FakeJoiner::ok();
            let (out, resp, got) = drive(frame.as_bytes(), fds, &mut j);
            assert_eq!(
                out,
                Outcome::Responded(DialErrorCode::InvalidRequest),
                "{}",
                fds.len()
            );
            assert_eq!(resp, DialResponse::Error(DialErrorCode::InvalidRequest));
            assert_eq!(got.len(), 0);
            assert!(!j.joined);
        }
    }

    /// CRI-6: 長さ違い・応答の kind の frame は InvalidRequest。
    #[test]
    fn cri6_4479_bad_frames_are_invalid_request() {
        let (a, b) = two_fds();
        let resp_bytes = DialResponseFrame::encode(DialResponse::Connected);
        let inputs: [&[u8]; 2] = [&[1, 2, 3], resp_bytes.as_bytes()];
        for data in inputs {
            let mut j = FakeJoiner::ok();
            let (out, resp, _) = drive(data, &[a.as_fd(), b.as_fd()], &mut j);
            assert_eq!(out, Outcome::Responded(DialErrorCode::InvalidRequest));
            assert_eq!(resp, DialResponse::Error(DialErrorCode::InvalidRequest));
            assert!(!j.joined);
        }
    }

    /// SEC-1: 同じ fd を 2 本（同一 ino）は前検査で拒否。
    #[test]
    fn sec1_4479_same_inode_is_rejected_before_join() {
        let (a, _) = two_fds();
        let frame = req_frame(9);
        let mut j = FakeJoiner::ok();
        let (out, resp, _) = drive(frame.as_bytes(), &[a.as_fd(), a.as_fd()], &mut j);
        assert_eq!(out, Outcome::Responded(DialErrorCode::InvalidRequest));
        assert_eq!(resp, DialResponse::Error(DialErrorCode::InvalidRequest));
        assert!(!j.joined);
    }

    /// SEC-1: joiner の素性不一致・参加失敗・特権破棄失敗はそのまま固定語彙で返り、後続（connect）へ進まない。
    #[test]
    fn sec1_4479_join_and_harden_failures_are_reported() {
        let (a, b) = two_fds();
        let frame = req_frame(9);
        let mut j = FakeJoiner::ok();
        j.join_result = Err(DialErrorCode::IdentityMismatch);
        let (out, resp, _) = drive(frame.as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Responded(DialErrorCode::IdentityMismatch));
        assert_eq!(resp, DialResponse::Error(DialErrorCode::IdentityMismatch));
        assert!(!j.hardened);

        let mut j = FakeJoiner::ok();
        j.harden_result = Err(DialErrorCode::JoinFailed);
        let (out, resp, _) = drive(frame.as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Responded(DialErrorCode::JoinFailed));
        assert_eq!(resp, DialResponse::Error(DialErrorCode::JoinFailed));
    }

    /// SEC-1: 参加後の識別の照合（具体値）。
    #[test]
    fn sec1_4479_check_joined_identity_compares_both() {
        let r = NsPair {
            user: (1, 10),
            net: (1, 20),
        };
        assert_eq!(check_joined_identity(r, r), Ok(()));
        let u = NsPair {
            user: (1, 11),
            net: (1, 20),
        };
        let n = NsPair {
            user: (1, 10),
            net: (2, 20),
        };
        assert_eq!(
            check_joined_identity(r, u),
            Err(DialErrorCode::IdentityMismatch)
        );
        assert_eq!(
            check_joined_identity(r, n),
            Err(DialErrorCode::IdentityMismatch)
        );
    }

    /// CRI-6: 誰も listen していない port への connect は Refused。
    #[test]
    fn cri6_4479_connect_refused() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let (a, b) = two_fds();
        let mut j = FakeJoiner::ok();
        let (out, resp, got) = drive(req_frame(port).as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Responded(DialErrorCode::Refused));
        assert_eq!(resp, DialResponse::Error(DialErrorCode::Refused));
        assert_eq!(got.len(), 0);
        assert!(j.joined && j.hardened);
    }

    /// 偽の接続と時計で `dial_loopback_with` を駆動する。呼び出しの記録（宛先と期間）を返す。
    fn drive_dial(
        results: Vec<io::Result<()>>,
        remaining: Vec<Duration>,
    ) -> (Result<(), DialErrorCode>, Vec<(SocketAddr, Duration)>) {
        let mut calls = Vec::new();
        let mut res = results.into_iter();
        let mut rem = remaining.into_iter();
        let out = dial_loopback_with(
            8080,
            |a, t| {
                calls.push((a, t));
                res.next().expect("unexpected extra connect")
            },
            || rem.next().expect("unexpected extra remaining"),
        );
        (out, calls)
    }

    fn v4() -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }
    fn v6() -> SocketAddr {
        "[::1]:8080".parse().unwrap()
    }
    fn refused() -> io::Error {
        io::Error::from(io::ErrorKind::ConnectionRefused)
    }
    fn unreachable_err() -> io::Error {
        io::Error::from(io::ErrorKind::NetworkUnreachable)
    }
    fn timed_out() -> io::Error {
        io::Error::from(io::ErrorKind::TimedOut)
    }

    /// CRI-6・NET-3・#4572: IPv4 が成功したら IPv6 を呼ばない。
    #[test]
    fn cri6_net3_4572_ipv4_success_does_not_try_ipv6() {
        let c = Duration::from_millis(1000);
        let (out, calls) = drive_dial(vec![Ok(())], vec![c]);
        assert_eq!(out, Ok(()));
        assert_eq!(calls, vec![(v4(), c)]);
    }

    /// CRI-6・NET-3・#4572: IPv4 が Refused で IPv6 が成功なら 2 回目は `[::1]` で、残り時間だけを渡す。
    #[test]
    fn cri6_net3_4572_ipv4_refused_then_ipv6_success_uses_remaining() {
        let c = Duration::from_millis(1000);
        let left = Duration::from_millis(990);
        let (out, calls) = drive_dial(vec![Err(refused()), Ok(())], vec![c, left]);
        assert_eq!(out, Ok(()));
        assert_eq!(calls, vec![(v4(), c), (v6(), left)]);
        assert!(calls[1].1 <= c);
        assert_eq!(v6().ip().to_string(), "::1");
    }

    /// REPAIR-5・#4572: IPv4 の期限切れは IPv6 を試さず `TimedOut`。
    #[test]
    fn cri6_net3_4572_ipv4_timeout_does_not_try_ipv6() {
        let c = Duration::from_millis(1000);
        let (out, calls) = drive_dial(vec![Err(timed_out())], vec![c]);
        assert_eq!(out, Err(DialErrorCode::TimedOut));
        assert_eq!(calls, vec![(v4(), c)]);
    }

    /// REPAIR-5・#4572: IPv4 が Refused でも残りが 0 なら IPv6 を試さず `TimedOut`（0 の期間を connect へ渡さない）。
    #[test]
    fn cri6_net3_4572_zero_remaining_skips_ipv6() {
        let c = Duration::from_millis(1000);
        let (out, calls) = drive_dial(vec![Err(refused())], vec![c, Duration::ZERO]);
        assert_eq!(out, Err(DialErrorCode::TimedOut));
        assert_eq!(calls, vec![(v4(), c)]);
    }

    /// CRI-6・#4572: 両方失敗したときは IPv4 の理由。どちらかが期限切れなら `TimedOut`。
    #[test]
    fn cri6_net3_4572_both_fail_returns_ipv4_reason_or_timeout() {
        let t = Duration::from_millis(500);
        let cases = [
            (refused(), refused(), DialErrorCode::Refused),
            (unreachable_err(), refused(), DialErrorCode::Unreachable),
            (refused(), unreachable_err(), DialErrorCode::Refused),
            (refused(), timed_out(), DialErrorCode::TimedOut),
        ];
        for (a, b, want) in cases {
            let (out, calls) = drive_dial(vec![Err(a), Err(b)], vec![t, t]);
            assert_eq!(out, Err(want));
            assert_eq!(calls.len(), 2);
        }
    }

    /// `::1` と同じ番号の IPv4 listener を drop 済みにして `[::1]` だけで待ち受ける（番号の揺れを数回やり直す）。
    fn ipv6_only_listener() -> TcpListener {
        for _ in 0..20 {
            let v4l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = v4l.local_addr().unwrap().port();
            if let Ok(l) = TcpListener::bind(("::1", p)) {
                drop(v4l);
                return l;
            }
        }
        panic!("could not bind an IPv6-only loopback listener");
    }

    /// CRI-6・NET-3・#4572: `::1` だけで待ち受ける listener へつなぎ直して Connected（実ソケット）。
    #[test]
    fn cri6_net3_4572_falls_back_to_ipv6_loopback() {
        let l = ipv6_only_listener();
        let port = l.local_addr().unwrap().port();
        let (a, b) = two_fds();
        let mut j = FakeJoiner::ok();
        let (out, resp, got) = drive(req_frame(port).as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Connected);
        assert_eq!(resp, DialResponse::Connected);
        assert_eq!(got.len(), 1);
        let s = TcpStream::from(got.into_iter().next().unwrap());
        assert_eq!(s.peer_addr().unwrap().to_string(), format!("[::1]:{port}"));
        assert_eq!(s.local_addr().unwrap().ip().to_string(), "::1");
        let (_acc, peer) = l.accept().unwrap();
        assert_eq!(peer, s.local_addr().unwrap());
    }

    /// CRI-6・#4572: 両方で待ち受けるときは IPv4 を優先する。
    #[test]
    fn cri6_net3_4572_prefers_ipv4_when_both_listen() {
        let (v4l, v6l) = (0..20)
            .find_map(|_| {
                let v4l = TcpListener::bind("127.0.0.1:0").unwrap();
                let p = v4l.local_addr().unwrap().port();
                TcpListener::bind(("::1", p)).ok().map(|v6l| (v4l, v6l))
            })
            .expect("bind both");
        let port = v4l.local_addr().unwrap().port();
        let (a, b) = two_fds();
        let mut j = FakeJoiner::ok();
        let (out, _, got) = drive(req_frame(port).as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Connected);
        let s = TcpStream::from(got.into_iter().next().unwrap());
        assert_eq!(
            s.peer_addr().unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        v4l.accept().unwrap();
        drop(v6l);
    }

    /// CRI-6・NET-3: 成功時は Connected と接続済み fd がちょうど 1 本。
    #[test]
    fn cri6_4479_connect_success_returns_one_connected_fd() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (a, b) = two_fds();
        let mut j = FakeJoiner::ok();
        let (out, resp, got) = drive(req_frame(port).as_bytes(), &[a.as_fd(), b.as_fd()], &mut j);
        assert_eq!(out, Outcome::Connected);
        assert_eq!(resp, DialResponse::Connected);
        assert_eq!(got.len(), 1);
        let s = TcpStream::from(got.into_iter().next().unwrap());
        assert_eq!(
            s.peer_addr().unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        assert!(s.local_addr().unwrap().ip().is_loopback());
        let (_acc, peer) = l.accept().unwrap();
        assert_eq!(peer, s.local_addr().unwrap());
    }

    /// CRI-6: connect エラーの分類（具体値）。
    #[test]
    fn cri6_4479_classify_connect_error() {
        use io::ErrorKind as K;
        let k = |k: K| classify_connect_error(&io::Error::from(k));
        assert_eq!(k(K::ConnectionRefused), DialErrorCode::Refused);
        assert_eq!(k(K::TimedOut), DialErrorCode::TimedOut);
        assert_eq!(k(K::WouldBlock), DialErrorCode::TimedOut);
        assert_eq!(k(K::NetworkUnreachable), DialErrorCode::Unreachable);
        assert_eq!(k(K::HostUnreachable), DialErrorCode::Unreachable);
        assert_eq!(k(K::AddrNotAvailable), DialErrorCode::Unreachable);
        assert_eq!(k(K::Other), DialErrorCode::Unreachable);
        assert_eq!(
            classify_connect_error(&io::Error::from_raw_os_error(ETIMEDOUT)),
            DialErrorCode::TimedOut
        );
    }

    /// REPAIR-5: 親が閉じていても panic せず SendFailed。
    #[test]
    fn cri6_4479_closed_peer_is_send_failed() {
        let (parent, child) = sysh::socketpair_seqpacket().unwrap();
        drop(parent);
        let mut j = FakeJoiner::ok();
        let out = serve(child.as_fd(), Duration::from_millis(100), &mut j);
        assert_eq!(
            out,
            Outcome::SendFailed(Some(DialErrorCode::InvalidRequest))
        );
    }

    /// SEC-1: argv は空だけを受ける（非空は 2）。
    #[test]
    fn sec1_4479_args_must_be_empty() {
        assert_eq!(check_args(std::iter::empty()), Ok(()));
        assert_eq!(check_args([OsString::from("x")].into_iter()), Err(2));
    }
}
