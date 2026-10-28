//! entrypoint の exec 直前の同期点と、network namespace の素性（dev, ino）の照合
//! （NET-6・SEC-1・SEC-4・REPAIR-2・REPAIR-5。#3206。方式は `docs/design/network-wiring.md` D8）。
//!
//! # 役割と呼び出し文脈
//!
//! `network_mode=host`（供給元は supervisor の netns のまま）と `loopback`・`attachable`（新しい netns）の起動で、PID 1 が
//! 実際にいる network namespace が指定どおりかを、exec の前に呼び出しプロセス C が確かめる。呼び出し元は
//! `launch_intermediate::launch_via_intermediate`（C 側の [`receive_and_verify`]）と、その中の PID 1
//! （子側の [`NetnsSyncSender::hand_over_current_netns`]）だけ。
//!
//! 本番の supervisor は `PR_SET_DUMPABLE=0` で、exec 前の子もそれを継承する。このため C が procfs で子の
//! `/proc/<pid>/ns/net` を開く方式は使えない（non-dumpable のプロセスの ns リンクは `CAP_SYS_PTRACE` 無しに開けない）。
//! dumpable を 1 に戻す・`CAP_SYS_PTRACE` を足すことはせず、**子が自分の `/proc/thread-self/ns/net` を開いて
//! `SCM_RIGHTS` で C へ渡す**。C は受け取った fd を種別・形式と (dev, ino) で検証する。
//!
//! # 流れ
//!
//! ```text
//! C : 基準(baseline)として自分の netns の (dev, ino) を fork の前に取る → socketpair を作る → fork
//! PID 1 : 開始ゲート通過後・pivot と資格情報の切り替え(StagePipeline の CapabilityDrop)より前に、
//!         自分の netns を O_RDONLY|O_CLOEXEC で開いて送り、C の ACK を期限つきで待つ。ACK が無ければ exec しない
//! C : 受信 → 検証 → 期待(Host: 基準と同じ / Loopback・Attachable: 基準と異なる)と照合
//!     → (Attachable のみ)user namespace が C 自身と異なることを照合 → 呼び出し側のフック(`NetnsAttachHook`)を呼ぶ
//!     → 合格(Attachable はフックが Ok かつ期限内)なら ACK、不合格なら PID 1 を kill
//! ```
//!
//! # Attachable(rootless の pasta 構成。NET-9・CORE-6・#1939)
//!
//! 子は netns と user namespace の fd を**この順で 2 本**、1 通の `SCM_RIGHTS` で渡す。C は種別(`net:` / `user:`)を位置ごとに
//! 検証し、フックへ所有権ごと渡す。フックが失敗・期限切れ・不正のときは ACK を送らず PID 1 を kill して回収する。
//! フックは C の単一スレッドの区間で呼ばれる(契約は `oci_runtime::NetnsAttachHook`)。
//!
//! # ワイヤー形式（REPAIR-2。AF_UNIX `SOCK_SEQPACKET` の socketpair。パスを持たない。listener 用とは別）
//!
//! | 方向 | 内容 |
//! | ---- | ---- |
//! | 子 → C | 本文 1 バイト `N`（[`TOKEN_NETNS`]）＋ `SCM_RIGHTS` の fd 1 本(Attachable は netns・user namespace の 2 本をこの順で）。受信側の `SO_PASSCRED` で送信元の pid が付く |
//! | 子 → C（失敗時） | `E` ＋ コード 1 バイト（fd 無し。netns を開けなかったときの best-effort の通知） |
//! | C → 子 | 本文 1 バイト `A`。検証の完了。子はこれを待ってから exec に進む |
//!
//! 受信側は期待する fd の種別の列（`[Net]` か `[Net, User]`）を取る。
//!
//! # 受信側の検証（fail-closed。拒否した fd は `OwnedFd` の drop で閉じる）
//!
//! 切り詰め（`MSG_TRUNC` / `MSG_CTRUNC`）が無い・本文がちょうど `N`・fd がちょうど期待の本数・送信元 pid が C が起動した
//! PID 1 と一致・各 fd が close-on-exec・`fstatfs` が nsfs・`readlink(/proc/self/fd/N)` が位置ごとの期待の種別
//! （`net:[<st_ino>]` / `user:[<st_ino>]`）。
//! すべて満たしたときだけ (dev, ino) を取り出し、モードの期待と比べる。
//!
//! # 信頼の前提（pid だけを照合する根拠。`seccomp_listener` と同じ）
//!
//! 子の端を持つのは C が fork した PID 1 だけで、端は `SOCK_CLOEXEC`、送信は exec 前の 1 回だけである。pid 照合は配線の
//! 取り違えへの照合であり、悪意ある送信者への認証ではない（`seccomp_listener` の「信頼の前提」を参照）。
//!
//! # 時間上限（REPAIR-5）
//!
//! 子の ACK 待ちは [`NETNS_SYNC_ACK_TIMEOUT`]、C の受信は launch の単一期限の残りまで。EOF（相手の死）・期限切れ・
//! `A` 以外の本文では、子は exec せずに終了する。
//!
//! # 範囲と残余（REPAIR-3）
//!
//! - 同期点を通すのは `LaunchNetworkMode::Loopback`・`Attachable`・`Host` の起動だけ。`FromConfig`（CRI の経路）は通さない
//!   （pod の netns への join〔#2838〕が入るときに見直す）
//! - `network_mode=host` の構造化ログと、net crate の `HostNetns` を使う結線は #1873。pasta 構成のフックの実装
//!   （holder の保持と pasta の起動）は #1940
//! - user namespace と netns の所有関係は C では照合しない（`NS_GET_USERNS` の ioctl は新しい `unsafe`）。holder の
//!   `setns(user)` → `setns(net)` が組の違いを `EPERM` / `EINVAL` で fail-closed にする
//! - 基準は launch の入口で C 自身の netns から取る。C は `Threads: 1` の supervisor で、start の入口から launch までの間に
//!   `setns` / `unshare(CLONE_NEWNET)` をしないため、D8 の「supervisor が start の入口で取る基準」と同じ値になる

use std::fs::File;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, Instant};

use super::seccomp_listener::{ACK, TOKEN_FAILURE, wait_readable};
use super::{ExecError, IsolationStage, ViolationReason};
use crate::oci_runtime::{AttachableNamespaces, NetnsAttachHook};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

/// 子が自分の netns を送るときの本文（1 バイト）。
pub(super) const TOKEN_NETNS: u8 = b'N';
/// 子が C の ACK を待つ上限（C は検証直後に返すため通常は即時。開始ゲートと同じ値。REPAIR-5）。
pub(super) const NETNS_SYNC_ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// 自スレッドの netns を指すリンク。PID 1 は単一スレッドだが、`/proc/self` ではなくスレッド単位で引く。
const NETNS_LINK: &str = "/proc/thread-self/ns/net";
/// 自スレッドの user namespace を指すリンク(Attachable の 2 本目と、C 自身の基準の取得)。
const USERNS_LINK: &str = "/proc/thread-self/ns/user";
const STAGE: IsolationStage = IsolationStage::NetnsVerify;

/// network namespace の素性（`fstat` の st_dev と st_ino）。同じ netns なら同じ値になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetnsIdentity {
    dev: u64,
    ino: u64,
}

impl NetnsIdentity {
    /// 試験用: 値を直接指定する（拒否の場面で基準を差し替えるため）。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(crate) fn from_parts_for_test(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }
}

/// モードごとの期待（基準との関係）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetnsExpectation {
    /// 基準（supervisor の netns）と同じ（`network_mode=host`）。
    SameAsBaseline,
    /// 基準と異なる（`network_mode=loopback`・`attachable`。新しい netns）。
    DiffersFromBaseline,
}

/// 子が C へ渡す fd の組(NET-9・#1939)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetnsHandover {
    /// netns の 1 本だけ(Host・Loopback)。
    NetOnly,
    /// netns と user namespace の 2 本をこの順で(Attachable。rootless の pasta 構成)。
    NetAndUser,
}

/// fd の種別(位置ごとの検証)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NsKind {
    Net,
    User,
}

impl NsKind {
    /// `/proc/self/fd/N` の readlink の接頭辞。
    fn link_prefix(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::User => "user",
        }
    }

    fn not_that_kind(self) -> &'static str {
        match self {
            Self::Net => "the received fd is not a network namespace",
            Self::User => "the received fd is not a user namespace",
        }
    }
}

impl NetnsHandover {
    /// 子が送る fd の種別の列(送る順)。
    pub(crate) fn kinds(self) -> &'static [NsKind] {
        match self {
            Self::NetOnly => &[NsKind::Net],
            Self::NetAndUser => &[NsKind::Net, NsKind::User],
        }
    }
}

/// 同期点を通す起動の要求（`IntermediateSpec` に載る）。`baseline` が `None` なら launch の入口で C が自分の netns から取る。
#[derive(Debug, Clone, Copy)]
pub(crate) struct NetnsSyncRequest {
    pub(crate) expectation: NetnsExpectation,
    pub(crate) baseline: Option<NetnsIdentity>,
    /// 子が渡す fd の組。`NetAndUser` の起動はフックが要る(launch の入口が欠落を拒否する)。
    pub(crate) handover: NetnsHandover,
}

/// Attachable の C 側の追加の照合と、呼び出し側のフック。
pub(crate) struct AttachCheck<'a> {
    /// C 自身の user namespace の素性(受け取った 2 本目がこれと異なること)。
    pub(crate) user_baseline: NetnsIdentity,
    pub(crate) hook: &'a dyn NetnsAttachHook,
}

/// 基準が確定した、C が照合に使う値。
pub(crate) struct NetnsCheck<'a> {
    pub(crate) expectation: NetnsExpectation,
    pub(crate) baseline: NetnsIdentity,
    /// `Some` なら 2 本版(Attachable)。
    pub(crate) attach: Option<AttachCheck<'a>>,
}

impl NetnsCheck<'_> {
    fn kinds(&self) -> &'static [NsKind] {
        if self.attach.is_some() {
            NetnsHandover::NetAndUser.kinds()
        } else {
            NetnsHandover::NetOnly.kinds()
        }
    }
}

/// 期待との照合（純粋な判定）。
pub(crate) fn judge(
    expectation: NetnsExpectation,
    baseline: NetnsIdentity,
    observed: NetnsIdentity,
) -> bool {
    match expectation {
        NetnsExpectation::SameAsBaseline => observed == baseline,
        NetnsExpectation::DiffersFromBaseline => observed != baseline,
    }
}

/// C の失敗の結果。`reason` が `Some` なら分離の前提が崩れた拒否として監査に記録する（SEC-4）。
/// `None` は系のエラー（EOF・期限切れ・errno）で、既存の方針どおり記録しない。
#[derive(Debug)]
pub(super) struct NetnsSyncFailure {
    pub(super) error: ExecError,
    pub(super) reason: Option<ViolationReason>,
}

impl NetnsSyncFailure {
    fn violation(reason: ViolationReason) -> Box<Self> {
        Box::new(Self {
            error: ExecError::from_violation(reason, None),
            reason: Some(reason),
        })
    }

    fn system(error: ExecError) -> Box<Self> {
        Box::new(Self {
            error,
            reason: None,
        })
    }
}

/// 開いた ns の fd を検証して、素性と fd を返す。`fd` は検証に失敗すれば drop で閉じる。
fn verify_ns_fd(fd: OwnedFd, kind: NsKind) -> Result<(NetnsIdentity, OwnedFd), &'static str> {
    match sys::seccomp_notify::fd_is_cloexec(fd.as_fd()) {
        Ok(true) => {}
        _ => return Err("the received fd is not close-on-exec"),
    }
    match sys::fs_type(fd.as_fd()) {
        Ok(t) if t == sys::NSFS_MAGIC => {}
        _ => return Err("the received fd is not a namespace file"),
    }
    let raw = fd.as_raw_fd();
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|_| "the received fd could not be inspected")?;
    let link = std::fs::read_link(format!("/proc/self/fd/{raw}")).ok();
    let expected = format!("{}:[{}]", kind.link_prefix(), meta.ino());
    if link.as_deref().and_then(|p| p.to_str()) != Some(expected.as_str()) {
        return Err(kind.not_that_kind());
    }
    Ok((
        NetnsIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        },
        OwnedFd::from(file),
    ))
}

/// 自スレッドのリンクを開いて素性を取る(基準の取得と、子の送信が共有する検査)。
fn capture_identity(
    link: &str,
    kind: NsKind,
    what: &'static str,
) -> Result<NetnsIdentity, ExecError> {
    let file = File::open(link).map_err(|e| ExecError::from_io(&e, STAGE, what))?;
    verify_ns_fd(OwnedFd::from(file), kind)
        .map(|(identity, _fd)| identity)
        .map_err(|why| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                format!("the baseline namespace is unusable: {why}"),
            )
        })
}

/// 自スレッドの netns を開いて素性を取る（基準の取得と、子の送信が共有する検査）。
pub(crate) fn capture_baseline() -> Result<NetnsIdentity, ExecError> {
    capture_identity(
        NETNS_LINK,
        NsKind::Net,
        "open the current network namespace",
    )
}

/// 自スレッドの user namespace の素性を取る(Attachable で、受け取った 2 本目が C 自身のものでないことの照合に使う)。
pub(crate) fn capture_user_baseline() -> Result<NetnsIdentity, ExecError> {
    capture_identity(USERNS_LINK, NsKind::User, "open the current user namespace")
}

/// 受信した 1 通の検証（純粋な判定。fd は `received` の drop で閉じる）。受理なら受け取った順の素性と fd を返す。
fn validate_netns_handoff(
    received: sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
    kinds: &[NsKind],
) -> Result<Vec<(NetnsIdentity, OwnedFd)>, &'static str> {
    let sys::seccomp_notify::ReceivedFd {
        payload,
        fds,
        creds,
        truncated,
    } = received;
    if truncated {
        return Err("the network namespace message was truncated");
    }
    if payload.as_slice() != [TOKEN_NETNS] {
        return Err("the network namespace message had an unexpected payload");
    }
    if fds.len() != kinds.len() {
        return Err("the network namespace message did not carry the expected number of fds");
    }
    let Some(creds) = creds else {
        return Err("the network namespace message carried no sender credentials");
    };
    if u32::try_from(creds.pid).ok() != Some(expected_pid) {
        return Err("the network namespace message came from an unexpected process");
    }
    let mut out = Vec::with_capacity(fds.len());
    for (fd, kind) in fds.into_iter().zip(kinds.iter().copied()) {
        out.push(verify_ns_fd(fd, kind)?);
    }
    Ok(out)
}

/// 失敗の通知（`E` + コード 1 バイト）の復元。通知でなければ `None`。
fn decode_failure(
    received: &sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
) -> Option<ExecError> {
    if received.payload.first() != Some(&TOKEN_FAILURE)
        || !received.fds.is_empty()
        || received.truncated
        || received.payload.len() != 2
    {
        return None;
    }
    let from_expected = received
        .creds
        .as_ref()
        .is_some_and(|c| u32::try_from(c.pid).ok() == Some(expected_pid));
    if !from_expected {
        return None;
    }
    let code = match received.payload.get(1).copied() {
        Some(b'F') => ErrorCode::FailedPrecondition,
        Some(b'P') => ErrorCode::PermissionDenied,
        Some(b'U') => ErrorCode::Unimplemented,
        Some(b'T') => ErrorCode::Timeout,
        _ => ErrorCode::Internal,
    };
    Some(ExecError::new(
        code,
        STAGE,
        "the container init could not open its network namespace",
    ))
}

/// 新しい socketpair（C の端、子の端）。C の端には `SO_PASSCRED` を設定済みで、どちらも fd 3 以上。
pub(super) fn netns_socketpair() -> Result<(OwnedFd, OwnedFd), ExecError> {
    super::seccomp_listener::listener_socketpair()
}

/// 受信 → 形式の検証までの結果(fd の所有権を含む)。
struct Handoff {
    identities: Vec<NetnsIdentity>,
    fds: Vec<OwnedFd>,
}

/// 子の送信を期限つきで受け取り、形式を検証する(ACK は送らない)。形式違反は記録の対象(`reason` あり)。
fn receive_handoff(
    sock: BorrowedFd<'_>,
    expected_pid: u32,
    kinds: &[NsKind],
    deadline: Instant,
) -> Result<Handoff, Box<NetnsSyncFailure>> {
    let received = loop {
        match wait_readable(sock, deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(NetnsSyncFailure::system(ExecError::new(
                    ErrorCode::Timeout,
                    STAGE,
                    "the network namespace was not delivered in time",
                )));
            }
            Err(e) => {
                return Err(NetnsSyncFailure::system(ExecError::from_sys(
                    e,
                    STAGE,
                    "wait for the network namespace",
                )));
            }
        }
        match sys::seccomp_notify::recv_fd_with_creds(sock) {
            Err(SysError::Os(e)) if e == sys::EAGAIN => {}
            Ok(r) => break r,
            Err(e) => {
                return Err(NetnsSyncFailure::system(ExecError::from_sys(
                    e,
                    STAGE,
                    "receive of the network namespace",
                )));
            }
        }
    };
    if received.payload.is_empty() && received.fds.is_empty() {
        return Err(NetnsSyncFailure::system(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "the sender closed before delivering the network namespace",
        )));
    }
    if let Some(e) = decode_failure(&received, expected_pid) {
        return Err(NetnsSyncFailure::system(e));
    }
    let verified = validate_netns_handoff(received, expected_pid, kinds)
        .map_err(|_| NetnsSyncFailure::violation(ViolationReason::NetnsHandoffInvalid))?;
    let (identities, fds) = verified.into_iter().unzip();
    Ok(Handoff { identities, fds })
}

/// C → 子の ACK を送る(検証・準備の完了)。
fn send_ack(sock: BorrowedFd<'_>) -> Result<(), Box<NetnsSyncFailure>> {
    sys::send_nonblocking_unix(sock, &[ACK])
        .map(|_| ())
        .map_err(|e| {
            NetnsSyncFailure::system(ExecError::from_sys(e, STAGE, "send of the netns ACK"))
        })
}

/// C 側: 子の netns(Attachable は netns と user namespace)を受け取って検証し、期待と照合して合格なら ACK を返す。
///
/// `expected_pid` は C が起動した PID 1 の pid、`deadline` までに届かなければ `Timeout`。Attachable(`check.attach`)は
/// 2 本目の user namespace が C 自身と異なることを照合し、フックを呼んで、Ok かつ期限内のときだけ ACK を送る。
/// 失敗は [`NetnsSyncFailure`]（`reason` ありは監査に記録する拒否）。呼び出し側が PID 1 を回収する。
pub(super) fn receive_and_verify(
    sock: BorrowedFd<'_>,
    expected_pid: u32,
    check: &NetnsCheck<'_>,
    deadline: Instant,
) -> Result<(), Box<NetnsSyncFailure>> {
    let Handoff { identities, fds } = receive_handoff(sock, expected_pid, check.kinds(), deadline)?;
    let mut ids = identities.iter().copied();
    let Some(observed) = ids.next() else {
        return Err(NetnsSyncFailure::violation(
            ViolationReason::NetnsHandoffInvalid,
        ));
    };
    if !judge(check.expectation, check.baseline, observed) {
        return Err(NetnsSyncFailure::violation(
            ViolationReason::NetnsIdentityMismatch,
        ));
    }
    if let Some(attach) = &check.attach {
        let Some(user_observed) = ids.next() else {
            return Err(NetnsSyncFailure::violation(
                ViolationReason::NetnsHandoffInvalid,
            ));
        };
        // 子が C と同じ user namespace にいる(新しい user namespace を作っていない)なら、holder が別の資格で
        // 参加できない構成を黙って通すことになるため拒否する(SEC-5)。
        if user_observed == attach.user_baseline {
            return Err(NetnsSyncFailure::violation(
                ViolationReason::NetnsIdentityMismatch,
            ));
        }
        let mut fds = fds.into_iter();
        let (Some(net), Some(user)) = (fds.next(), fds.next()) else {
            return Err(NetnsSyncFailure::violation(
                ViolationReason::NetnsHandoffInvalid,
            ));
        };
        // フックの失敗は系のエラー(監査しない。pasta の失敗の分類と記録は呼び出し側〔#1940〕)。message は固定の英文。
        if let Err(e) = attach
            .hook
            .attach(AttachableNamespaces::new(net, user), deadline)
        {
            return Err(NetnsSyncFailure::system(ExecError::new(
                e.code(),
                IsolationStage::NetnsAttach,
                "the network attach hook failed",
            )));
        }
        // 期限を越えたフックは Ok でも失敗(合図の前に期限を確かめ直す。REPAIR-5)。
        if Instant::now() >= deadline {
            return Err(NetnsSyncFailure::system(ExecError::new(
                ErrorCode::Timeout,
                IsolationStage::NetnsAttach,
                "the network attach hook did not finish in time",
            )));
        }
    }
    send_ack(sock)
}

/// 子（PID 1）側の送信口。socketpair の子の端を所有する。
#[derive(Debug)]
pub(super) struct NetnsSyncSender(OwnedFd);

impl NetnsSyncSender {
    pub(super) fn new(child_end: OwnedFd) -> Self {
        Self(child_end)
    }

    /// netns を開けなかったことを `E` + コード 1 バイトで知らせる（best-effort。送れなくても失敗は変わらない）。
    fn report_failure(&self, error: &ExecError) {
        let code = match error.code {
            ErrorCode::FailedPrecondition => b'F',
            ErrorCode::PermissionDenied => b'P',
            ErrorCode::Unimplemented => b'U',
            ErrorCode::Timeout => b'T',
            _ => b'I',
        };
        let _ = sys::send_nonblocking_unix(self.0.as_fd(), &[TOKEN_FAILURE, code]);
    }

    /// 自分の netns(`NetAndUser` は続けて user namespace)を開いて C へこの順で送り、自分の fd を閉じ、C の ACK を
    /// `timeout` まで待つ。どれかが失敗したら exec に進ませない（呼び出し側は `EXIT_SETUP_FAILED` で終了する）。
    pub(super) fn hand_over(
        self,
        handover: NetnsHandover,
        timeout: Duration,
    ) -> Result<(), ExecError> {
        let mut files = Vec::with_capacity(2);
        for kind in handover.kinds() {
            let (link, what) = match kind {
                NsKind::Net => (NETNS_LINK, "open the current network namespace"),
                NsKind::User => (USERNS_LINK, "open the current user namespace"),
            };
            match File::open(link) {
                Ok(f) => files.push(f),
                Err(e) => {
                    let error = ExecError::from_io(&e, STAGE, what);
                    self.report_failure(&error);
                    return Err(error);
                }
            }
        }
        let borrowed: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
        sys::seccomp_notify::send_fds_with_token(self.0.as_fd(), TOKEN_NETNS, &borrowed)
            .map_err(|e| ExecError::from_sys(e, STAGE, "send of the network namespace"))?;
        // 手元の fd を閉じる（workload が持たないように）。
        drop(borrowed);
        drop(files);
        let deadline = Instant::now() + timeout;
        match wait_readable(self.0.as_fd(), deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ExecError::new(
                    ErrorCode::Timeout,
                    STAGE,
                    "the launcher did not acknowledge the network namespace in time",
                ));
            }
            Err(e) => return Err(ExecError::from_sys(e, STAGE, "wait for the netns ACK")),
        }
        let mut buf = [0u8; 2];
        let n = sys::seccomp_notify::recv_nowait(self.0.as_fd(), &mut buf)
            .map_err(|e| ExecError::from_sys(e, STAGE, "receive of the netns ACK"))?;
        if n == 1 && buf.first() == Some(&ACK) {
            Ok(())
        } else {
            Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "the launcher rejected or dropped the network namespace",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::seccomp_notify::{ReceivedFd, Ucred};
    use std::io::Read as _;

    fn me() -> u32 {
        std::process::id()
    }

    fn msg(payload: &[u8], fds: Vec<OwnedFd>, pid: Option<u32>, truncated: bool) -> ReceivedFd {
        ReceivedFd {
            payload: payload.to_vec(),
            fds,
            creds: pid.map(|p| Ucred {
                pid: i32::try_from(p).unwrap(),
                uid: 0,
                gid: 0,
            }),
            truncated,
        }
    }

    fn open_ns(kind: &str) -> OwnedFd {
        OwnedFd::from(File::open(format!("/proc/thread-self/ns/{kind}")).unwrap())
    }

    fn own_identity() -> NetnsIdentity {
        capture_baseline().expect("own netns")
    }

    /// NET-6・SEC-1: 自分の netns を送った受け渡しは受理され、基準と同じ素性になる。
    #[test]
    fn net6_sec1_3206_validate_accepts_own_netns() {
        let got = validate_netns_handoff(
            msg(b"N", vec![open_ns("net")], Some(me()), false),
            me(),
            &[NsKind::Net],
        )
        .unwrap();
        let identities: Vec<_> = got.into_iter().map(|(i, _fd)| i).collect();
        assert_eq!(identities, vec![own_identity()]);
    }

    /// NET-6・SEC-1: 期待との照合の表（Host は同じ、Loopback は異なる）。
    #[test]
    fn net6_sec1_3206_judge_table() {
        let a = NetnsIdentity { dev: 4, ino: 100 };
        let b = NetnsIdentity { dev: 4, ino: 200 };
        assert!(judge(NetnsExpectation::SameAsBaseline, a, a));
        assert!(!judge(NetnsExpectation::SameAsBaseline, a, b));
        assert!(judge(NetnsExpectation::DiffersFromBaseline, a, b));
        assert!(!judge(NetnsExpectation::DiffersFromBaseline, a, a));
        // dev だけ違っても別の素性。
        let c = NetnsIdentity { dev: 5, ino: 100 };
        assert!(!judge(NetnsExpectation::SameAsBaseline, a, c));
    }

    /// SEC-1・SEC-4: 形式違反の表。理由語を具体値で照合する。
    #[test]
    fn sec1_3206_validate_rejects_every_malformed_message() {
        let p = std::io::pipe().unwrap();
        let cases: Vec<(&str, ReceivedFd)> = vec![
            (
                "the network namespace message was truncated",
                msg(b"N", vec![open_ns("net")], Some(me()), true),
            ),
            (
                "the network namespace message had an unexpected payload",
                msg(b"X", vec![open_ns("net")], Some(me()), false),
            ),
            (
                "the network namespace message had an unexpected payload",
                msg(b"NN", vec![open_ns("net")], Some(me()), false),
            ),
            (
                "the network namespace message did not carry the expected number of fds",
                msg(b"N", vec![], Some(me()), false),
            ),
            (
                "the network namespace message did not carry the expected number of fds",
                msg(
                    b"N",
                    vec![open_ns("net"), open_ns("net")],
                    Some(me()),
                    false,
                ),
            ),
            (
                "the network namespace message carried no sender credentials",
                msg(b"N", vec![open_ns("net")], None, false),
            ),
            (
                "the network namespace message came from an unexpected process",
                msg(b"N", vec![open_ns("net")], Some(me() + 1), false),
            ),
            (
                "the received fd is not a namespace file",
                msg(
                    b"N",
                    vec![OwnedFd::from(File::open("/dev/null").unwrap())],
                    Some(me()),
                    false,
                ),
            ),
            (
                "the received fd is not a namespace file",
                msg(b"N", vec![OwnedFd::from(p.0)], Some(me()), false),
            ),
            (
                "the received fd is not a network namespace",
                msg(b"N", vec![open_ns("user")], Some(me()), false),
            ),
        ];
        for (why, m) in cases {
            assert_eq!(
                validate_netns_handoff(m, me(), &[NsKind::Net]).unwrap_err(),
                why
            );
        }
    }

    /// SEC-1・REPAIR-5: 期待の本数を超えた fd は拒否され、受け取った fd はすべて閉じられる。
    #[test]
    fn sec1_3206_rejected_message_closes_every_received_fd() {
        let (mut r, w) = std::io::pipe().unwrap();
        let extra = OwnedFd::from(w.try_clone().unwrap());
        drop(w);
        let m = msg(b"N", vec![open_ns("net"), extra], Some(me()), false);
        assert!(validate_netns_handoff(m, me(), &[NsKind::Net]).is_err());
        // 書き込み端が全て閉じていれば EOF（0 バイト）になる。
        let mut buf = [0u8; 1];
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    /// NET-9(#1939): 期待が (net, user) のとき、この順の 2 本を受理し、素性は各 ns のものと一致する。
    #[test]
    fn net9_1939_validate_accepts_net_then_user() {
        let got = validate_netns_handoff(
            msg(
                b"N",
                vec![open_ns("net"), open_ns("user")],
                Some(me()),
                false,
            ),
            me(),
            NetnsHandover::NetAndUser.kinds(),
        )
        .unwrap();
        let identities: Vec<_> = got.into_iter().map(|(i, _fd)| i).collect();
        assert_eq!(
            identities,
            vec![own_identity(), capture_user_baseline().unwrap()]
        );
    }

    /// NET-9・SEC-1(#1939): 2 本の期待に対する逆順・1 本・同種 2 本・3 本は固定文言で拒否する。
    #[test]
    fn net9_sec1_1939_validate_rejects_wrong_order_and_count() {
        let kinds = NetnsHandover::NetAndUser.kinds();
        let cases: Vec<(&str, ReceivedFd)> = vec![
            (
                "the received fd is not a network namespace",
                msg(
                    b"N",
                    vec![open_ns("user"), open_ns("net")],
                    Some(me()),
                    false,
                ),
            ),
            (
                "the network namespace message did not carry the expected number of fds",
                msg(b"N", vec![open_ns("net")], Some(me()), false),
            ),
            (
                "the received fd is not a user namespace",
                msg(
                    b"N",
                    vec![open_ns("net"), open_ns("net")],
                    Some(me()),
                    false,
                ),
            ),
            (
                "the network namespace message did not carry the expected number of fds",
                msg(
                    b"N",
                    vec![open_ns("net"), open_ns("user"), open_ns("user")],
                    Some(me()),
                    false,
                ),
            ),
        ];
        for (why, m) in cases {
            assert_eq!(validate_netns_handoff(m, me(), kinds).unwrap_err(), why);
        }
        // 1 本の期待に 2 本が来ても拒否する。
        let m = msg(
            b"N",
            vec![open_ns("net"), open_ns("user")],
            Some(me()),
            false,
        );
        assert_eq!(
            validate_netns_handoff(m, me(), &[NsKind::Net]).unwrap_err(),
            "the network namespace message did not carry the expected number of fds"
        );
    }

    fn run_pair(
        check: NetnsCheck,
        child_timeout: Duration,
    ) -> (Result<(), Box<NetnsSyncFailure>>, Result<(), ExecError>) {
        let (parent, child) = netns_socketpair().unwrap();
        let t = std::thread::spawn(move || {
            NetnsSyncSender::new(child).hand_over(NetnsHandover::NetOnly, child_timeout)
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let parent_result = receive_and_verify(parent.as_fd(), me(), &check, deadline);
        drop(parent);
        (parent_result, t.join().unwrap())
    }

    /// NET-6: Host 相当（基準と同じ）の受け渡しは合格し、子は ACK を受ける。
    #[test]
    fn net6_3206_same_as_baseline_roundtrip_acks() {
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let (parent, child) = run_pair(check, Duration::from_secs(10));
        assert!(parent.is_ok());
        assert!(child.is_ok());
    }

    /// NET-6・SEC-1・SEC-4: Host 相当で基準と違えば `netns_identity_mismatch`（FailedPrecondition・段 `netns_verify`）。
    /// 子は ACK を受けず失敗する（exec に進まない）。
    #[test]
    fn net6_sec1_sec4_3206_mismatch_is_rejected_and_child_does_not_proceed() {
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: NetnsIdentity { dev: 0, ino: 0 },
            attach: None,
        };
        let (parent, child) = run_pair(check, Duration::from_secs(10));
        let f = parent.unwrap_err();
        assert_eq!(f.reason, Some(ViolationReason::NetnsIdentityMismatch));
        assert_eq!(f.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(f.error.stage, IsolationStage::NetnsVerify);
        assert!(child.is_err());
    }

    /// NET-6・SEC-1: Loopback 相当で基準と同じ素性（新しい netns になっていない）なら拒否する。
    #[test]
    fn net6_sec1_3206_loopback_expectation_rejects_the_baseline_itself() {
        let check = NetnsCheck {
            expectation: NetnsExpectation::DiffersFromBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let (parent, child) = run_pair(check, Duration::from_secs(10));
        let f = parent.unwrap_err();
        assert_eq!(f.reason, Some(ViolationReason::NetnsIdentityMismatch));
        assert!(child.is_err());
    }

    /// REPAIR-5: 親が死んだ（端が閉じた）とき、子は EOF で失敗する（exec に進まない）。
    #[test]
    fn repair5_3206_child_fails_on_parent_eof() {
        let (parent, child) = netns_socketpair().unwrap();
        drop(parent);
        let e = NetnsSyncSender::new(child)
            .hand_over(NetnsHandover::NetOnly, Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(e.stage, IsolationStage::NetnsVerify);
    }

    /// REPAIR-5: ACK が来なければ子は期限で `Timeout` になる。
    #[test]
    fn repair5_3206_child_times_out_without_ack() {
        let (_parent, child) = netns_socketpair().unwrap();
        let started = Instant::now();
        let e = NetnsSyncSender::new(child)
            .hand_over(NetnsHandover::NetOnly, Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);
        assert_eq!(e.stage, IsolationStage::NetnsVerify);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// REPAIR-5: `A` 以外の本文は ACK として受けない。
    #[test]
    fn sec1_3206_child_rejects_a_non_ack_reply() {
        let (parent, child) = netns_socketpair().unwrap();
        let t = std::thread::spawn(move || {
            NetnsSyncSender::new(child).hand_over(NetnsHandover::NetOnly, Duration::from_secs(5))
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(wait_readable(parent.as_fd(), deadline).unwrap());
        let _ = sys::seccomp_notify::recv_fd_with_creds(parent.as_fd()).unwrap();
        sys::send_nonblocking_unix(parent.as_fd(), b"Z").unwrap();
        let e = t.join().unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
    }

    /// REPAIR-5: 子が何も送らないまま期限が来たら C は `Timeout`（記録しない系のエラー）。
    #[test]
    fn repair5_3206_parent_times_out_when_nothing_arrives() {
        let (parent, _child) = netns_socketpair().unwrap();
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let f = receive_and_verify(
            parent.as_fd(),
            me(),
            &check,
            Instant::now() + Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(f.error.code, ErrorCode::Timeout);
        assert_eq!(f.reason, None);
    }

    /// 子が送る前に終わった（EOF）なら C は記録しない系の `FailedPrecondition`。
    #[test]
    fn net6_3206_parent_sees_eof_when_child_end_closes() {
        let (parent, child) = netns_socketpair().unwrap();
        drop(child);
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let f = receive_and_verify(
            parent.as_fd(),
            me(),
            &check,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(f.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(f.reason, None);
    }

    /// 子の `E` 通知はコードを保って復元され、記録の対象にならない。
    #[test]
    fn net6_3206_failure_notice_keeps_the_code_and_is_not_audited() {
        let (parent, child) = netns_socketpair().unwrap();
        sys::send_nonblocking_unix(child.as_fd(), &[TOKEN_FAILURE, b'P']).unwrap();
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let f = receive_and_verify(
            parent.as_fd(),
            me(),
            &check,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(f.error.code, ErrorCode::PermissionDenied);
        assert_eq!(f.reason, None);
    }

    /// 形式違反（別の種類の ns）は `netns_handoff_invalid` として記録の対象になる。
    #[test]
    fn sec1_sec4_3206_wrong_namespace_kind_is_a_recorded_handoff_violation() {
        let (parent, child) = netns_socketpair().unwrap();
        sys::seccomp_notify::send_fd_with_token(
            child.as_fd(),
            TOKEN_NETNS,
            open_ns("user").as_fd(),
        )
        .unwrap();
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: None,
        };
        let f = receive_and_verify(
            parent.as_fd(),
            me(),
            &check,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(f.reason, Some(ViolationReason::NetnsHandoffInvalid));
        assert_eq!(f.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(f.error.stage, IsolationStage::NetnsVerify);
    }

    /// フックの記録(呼び出し回数と受け取った fd の素性)。
    struct RecordingHook {
        calls: std::sync::Mutex<Vec<(NetnsIdentity, NetnsIdentity)>>,
        result: Result<(), ErrorCode>,
        delay: Duration,
    }

    impl RecordingHook {
        fn new(result: Result<(), ErrorCode>) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                result,
                delay: Duration::ZERO,
            }
        }
    }

    impl NetnsAttachHook for RecordingHook {
        fn attach(
            &self,
            namespaces: AttachableNamespaces,
            _deadline: Instant,
        ) -> Result<(), crate::traits::types::TraitError> {
            let (user_fd, net_fd) = namespaces.into_parts();
            let (net, _net_fd) = verify_ns_fd(net_fd, NsKind::Net).unwrap();
            let (user, _user_fd) = verify_ns_fd(user_fd, NsKind::User).unwrap();
            self.calls.lock().unwrap().push((net, user));
            std::thread::sleep(self.delay);
            self.result
                .map_err(|code| crate::traits::types::TraitError::new(code, "hook detail"))
        }
    }

    fn attach_pair(
        hook: &RecordingHook,
        user_baseline: NetnsIdentity,
        deadline: Duration,
    ) -> (Result<(), Box<NetnsSyncFailure>>, Result<(), ExecError>) {
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: Some(AttachCheck {
                user_baseline,
                hook,
            }),
        };
        let (parent, child) = netns_socketpair().unwrap();
        let t = std::thread::spawn(move || {
            NetnsSyncSender::new(child)
                .hand_over(NetnsHandover::NetAndUser, Duration::from_secs(10))
        });
        let parent_result =
            receive_and_verify(parent.as_fd(), me(), &check, Instant::now() + deadline);
        drop(parent);
        (parent_result, t.join().unwrap())
    }

    fn fake_user() -> NetnsIdentity {
        NetnsIdentity { dev: 0, ino: 0 }
    }

    /// NET-9・CORE-6(#1939): 2 本版は net → user の順に届き、フックが 1 回だけ呼ばれ、Ok なら子が ACK を受ける。
    #[test]
    fn net9_1939_attach_roundtrip_calls_hook_once_then_acks() {
        let hook = RecordingHook::new(Ok(()));
        let (parent, child) = attach_pair(&hook, fake_user(), Duration::from_secs(10));
        assert!(parent.is_ok());
        assert!(child.is_ok());
        let calls = hook.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (own_identity(), capture_user_baseline().unwrap()));
    }

    /// NET-9・SEC-5(#1939): 子の user namespace が C と同じなら拒否し、フックは呼ばれず子は ACK を受けない。
    #[test]
    fn net9_sec5_1939_same_user_namespace_is_rejected_without_calling_the_hook() {
        let hook = RecordingHook::new(Ok(()));
        let (parent, child) = attach_pair(
            &hook,
            capture_user_baseline().unwrap(),
            Duration::from_secs(10),
        );
        let f = parent.unwrap_err();
        assert_eq!(f.reason, Some(ViolationReason::NetnsIdentityMismatch));
        assert!(child.is_err());
        assert!(hook.calls.lock().unwrap().is_empty());
    }

    /// NET-9・REPAIR-5(#1939): フックの失敗は code を保ち、段 `NetnsAttach`・固定文言で、監査の対象にしない。子は ACK を受けない。
    #[test]
    fn net9_repair5_1939_hook_failure_keeps_code_and_withholds_ack() {
        let hook = RecordingHook::new(Err(ErrorCode::Unavailable));
        let (parent, child) = attach_pair(&hook, fake_user(), Duration::from_secs(10));
        let f = parent.unwrap_err();
        assert_eq!(f.error.code, ErrorCode::Unavailable);
        assert_eq!(f.error.stage, IsolationStage::NetnsAttach);
        assert_eq!(f.reason, None);
        assert!(!format!("{}", f.error).contains("hook detail"));
        assert!(child.is_err());
        assert_eq!(hook.calls.lock().unwrap().len(), 1);
    }

    /// NET-9・REPAIR-5(#1939): フックが Ok でも期限を越えていれば `Timeout`(段 `NetnsAttach`)で失敗し、ACK を送らない。
    #[test]
    fn net9_repair5_1939_hook_past_the_deadline_fails_with_timeout() {
        let mut hook = RecordingHook::new(Ok(()));
        hook.delay = Duration::from_millis(400);
        let (parent, child) = attach_pair(&hook, fake_user(), Duration::from_millis(200));
        let f = parent.unwrap_err();
        assert_eq!(f.error.code, ErrorCode::Timeout);
        assert_eq!(f.error.stage, IsolationStage::NetnsAttach);
        assert_eq!(f.reason, None);
        assert!(child.is_err());
    }

    /// NET-9・SEC-1(#1939): 2 本の期待に対して子が 1 本しか送らなければ `netns_handoff_invalid` で、フックは呼ばれない。
    #[test]
    fn net9_sec1_1939_single_fd_sender_is_a_handoff_violation() {
        let hook = RecordingHook::new(Ok(()));
        let check = NetnsCheck {
            expectation: NetnsExpectation::SameAsBaseline,
            baseline: own_identity(),
            attach: Some(AttachCheck {
                user_baseline: fake_user(),
                hook: &hook,
            }),
        };
        let (parent, child) = netns_socketpair().unwrap();
        sys::seccomp_notify::send_fd_with_token(child.as_fd(), TOKEN_NETNS, open_ns("net").as_fd())
            .unwrap();
        let f = receive_and_verify(
            parent.as_fd(),
            me(),
            &check,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(f.reason, Some(ViolationReason::NetnsHandoffInvalid));
        assert!(hook.calls.lock().unwrap().is_empty());
    }

    /// REPAIR-5(#1939): 親が死んだ(端が閉じた)とき、2 本版の子も EOF で失敗する。
    #[test]
    fn net9_repair5_1939_two_fd_child_fails_on_parent_eof() {
        let (parent, child) = netns_socketpair().unwrap();
        drop(parent);
        let e = NetnsSyncSender::new(child)
            .hand_over(NetnsHandover::NetAndUser, Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(e.stage, IsolationStage::NetnsVerify);
    }

    /// REPAIR-5(#1939): 2 本版の子は、期限内に ACK が無ければ `Timeout`、`A` 以外の本文は拒否する。
    #[test]
    fn net9_repair5_1939_two_fd_child_times_out_and_rejects_non_ack() {
        let (_parent, child) = netns_socketpair().unwrap();
        let e = NetnsSyncSender::new(child)
            .hand_over(NetnsHandover::NetAndUser, Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);

        let (parent, child) = netns_socketpair().unwrap();
        let t = std::thread::spawn(move || {
            NetnsSyncSender::new(child).hand_over(NetnsHandover::NetAndUser, Duration::from_secs(5))
        });
        assert!(wait_readable(parent.as_fd(), Instant::now() + Duration::from_secs(5)).unwrap());
        let got = sys::seccomp_notify::recv_fd_with_creds(parent.as_fd()).unwrap();
        assert_eq!(got.fds.len(), 2);
        sys::send_nonblocking_unix(parent.as_fd(), b"Z").unwrap();
        assert_eq!(
            t.join().unwrap().unwrap_err().code,
            ErrorCode::FailedPrecondition
        );
    }
}
