//! seccomp の listener fd の受け渡し（SEC-4・TASK-41 追補・#2024。監査配送 2/6。方式は
//! `docs/design/audit-delivery.md`）。
//!
//! # 役割と呼び出し文脈
//!
//! コンテナの PID 1（または exec の worker）が seccomp の最終段で `NEW_LISTENER` 付きで filter を載せ、得た
//! listener fd を起動側（supervisor 側のプロセス C）へ socketpair の `SCM_RIGHTS` で渡す。
//! `exec/seccomp.rs` の `apply_default_seccomp_with_listener` が [`ListenerSender::hand_over`] を呼び、
//! `exec/launch_intermediate.rs` の launch 経路（と exec の経路）が [`receive_listener`] で受け取る。
//! 受け取った [`SeccompListener`] は `LaunchedProcess::take_seccomp_listener` で supervisor へ渡る。
//! 通知を読んで応答するループ（PID 変換・`record_seccomp_denial_for`・`EPERM` 応答）は supervisor の
//! `seccomp_notify`（#2025）が担い、本モジュールは取得・受け渡しと、通知の読み書きの安全 API（[`SeccompListener::wait`]・
//! `receive`・`is_pending`・`deny_eperm`）を担う。**filter の既定は ERRNO 版**（`USER_NOTIF` を返さない）で、listener を
//! 保持するだけならコンテナの挙動は変わらない。exec の経路（SUP-6・#2385）では worker が同じ手順で渡し、起動側 C は worker を fork した
//! exec 専用の親（[`ExecListenerReceiver`]）になる。exec の親は worker の終了を待つ前に受信し（相互待ちを避ける）、届け方は親が fork 前に決める
//! （exec の本番経路は `USER_NOTIF`、応答者は supervisor の `exec::run_in_worker_with`。9.4・#2544）。`ProductionLauncherBuilder::seccomp_errno_delivery(UserNotif)` で opt-in した
//! launcher（supervisor の start 経路だけ）では ERRNO 側の 40 件が通知になり、応答者がいる前提になる
//! （`audit-delivery.md` 9 章の案 3）。通知の引数・命令ポインタは公開せず、応答は `-EPERM` の 1 種類だけ（TOCTOU の余地を
//! 型で無くす）。
//!
//! # ワイヤー形式（REPAIR-2。AF_UNIX `SOCK_SEQPACKET` の socketpair。パスを持たない）
//!
//! | 方向 | 内容 |
//! | ---- | ---- |
//! | 子 → C | 本文 1 バイト `L`（[`TOKEN_LISTENER`]）＋ `SCM_RIGHTS` の fd 1 本（listener）。受信側の `SO_PASSCRED` により送信元の pid が付く |
//! | C → 子 | 本文 1 バイト `A`（[`ACK`]）。受領と検証の完了。子はこれを待ってから exec に進む |
//!
//! # 受信側の検証（PLUG-12 と同じ系統。fail-closed）
//!
//! `SO_PEERCRED` は socketpair では作成者（C 自身）を両端で返すため検証の根拠にならず使わない。代わりに次をすべて
//! 満たすときだけ受理し、満たさなければ受け取った fd をすべて閉じて拒否する。
//!
//! - 切り詰め（`MSG_TRUNC` / `MSG_CTRUNC`）が無い・本文がちょうど `L` 1 バイト
//! - `SCM_RIGHTS` の fd がちょうど 1 本
//! - `SCM_CREDENTIALS` の pid が、C が起動した子（PID 1 または worker）の pid と一致する（pid は C の PID namespace へ
//!   カーネルが変換する）。uid は照合しない（下の「信頼の前提」）
//! - fd が close-on-exec（`MSG_CMSG_CLOEXEC`）で、種別が `anon_inode:seccomp notify`
//!
//! # 信頼の前提（pid のみ照合し uid を照合しない根拠。SEC-4・REPAIR-5・#2372）
//!
//! - 実際の境界は socketpair の子の端の保持である。子の端を持つのは C が fork した子（launch は PID 1、exec は
//!   worker）だけで、端は `SOCK_CLOEXEC`、子は送信して ACK を受けた後に閉じ、workload（execve 後）へは渡らない
//! - 送信は exec 前の、こちらのコードだけが走っている子が 1 回だけ行う。pid 照合はこの前提の下での配線の取り違え
//!   （別の子・別の socketpair）への照合であり、悪意ある送信者への認証ではない
//! - uid を照合しない理由: C が受け取る uid は C の user namespace へ写された値で、権限モデル（単一 ID 写像・
//!   範囲写像）と送信時点で子が uid を切り替え済みかの両方に依存し、固定の期待値を導けない。また、新しい user
//!   namespace 内で capability を持つ PID 1 は `SCM_CREDENTIALS` の値を明示指定できうるため、uid を足しても
//!   送信者の偽装に対する強さは増えない。条件は Linux v6.12（タグ commit `adc218676eef…`。2026-10-26 に原文で
//!   確認。#2498）`net/core/scm.c` の `scm_check_creds`（L47–66）にある:
//!   pid は自分の tgid 以外を、その PID namespace を所有する user namespace の `CAP_SYS_ADMIN` で指定できる。
//!   uid は uid / euid / suid 以外を `CAP_SETUID`、gid は `CAP_SETGID`（いずれも自分の user namespace）で指定できる。
//!   指定した pid は `__scm_send`（`SCM_CREDENTIALS` の case は L180–200）が送信側の名前空間から `find_get_pid`
//!   で引くため、実在する pid に限る（無ければ `ESRCH`）。つまり pid 照合は偽装を防がない
//! - 受信できる fd は `MAX_RECV_FDS`（制御バッファの容量で実際に制限）までで、受信は `MSG_DONTWAIT`
//! - PID namespace をまたぐ pid の変換の実機確認は `production_launcher` のシナリオ A で行い、結果は #1621 に記録する
//!   （人間担当）
//!
//! # 漏れの防止（分離）
//!
//! listener を workload（execve 後）が持つと、自分の通知に自分で応答して拒否を回避できる。listener はカーネルが
//! `O_CLOEXEC` で作り、子は送信後に自分の fd を閉じ、socket も `SOCK_CLOEXEC` で、ACK の後に閉じる。
//!
//! # 制約
//!
//! - ワークロードが自分で `NEW_LISTENER` 付きの filter を載せる、または祖先の filter が既に listener を持つ環境では
//!   `EBUSY` になる。後者の launch は `FailedPrecondition`（段 `Seccomp`）で失敗する（fail-closed）
//! - Linux 5.0 未満は対象外

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{ContainerChild, ExecError, IsolationStage};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

/// listener を送るときの本文（1 バイト）。
pub(crate) const TOKEN_LISTENER: u8 = b'L';
/// listener を渡す前の適用失敗を知らせる本文の先頭(`E` + コード 1 バイト。fd は伴わない。受信の本文上限は 8 バイト。SEC-4・#2024)。
pub(crate) const TOKEN_FAILURE: u8 = b'E';
/// 受領の確認応答の本文（1 バイト）。
pub(crate) const ACK: u8 = b'A';
/// 子が ACK を待つ上限（C は受信直後に返すため通常は即時。launch の開始ゲートと同じ値。REPAIR-5）。
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// listener fd の種別（`/proc/self/fd/N` の readlink）。
const NOTIFY_FD_KIND: &str = "anon_inode:seccomp notify";

/// seccomp の listener fd（通知の受信側）。supervisor が監視の間保持する。
///
/// 検証付きの受信でしか作れない（公開コンストラクタを持たない）。`Clone` を持たず、drop で閉じる。閉じると
/// カーネルは `USER_NOTIF` 側の待機中の syscall を `ENOSYS` にする。
#[derive(Debug)]
pub struct SeccompListener(OwnedFd, AtomicBool);

impl SeccompListener {
    /// fd の借用(種別の確認・試験用)。通知の読み書きは下の安全 API を使う。
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// 通知の到着か、filter の利用者の消滅(`Closed`)を最大 `timeout` 待つ。`EINTR` は `Idle`(呼び出し側のループが
    /// 停止フラグを見て再試行する)。supervisor の listener スレッドが呼ぶ(SEC-4・#2025)。
    pub fn wait(&self, timeout: Duration) -> Result<ListenerReadiness, ExecError> {
        let ms = i32::try_from(timeout.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX);
        sys::seccomp_notify::poll_listener(self.0.as_fd(), ms)
            .map(|p| match p {
                sys::seccomp_notify::ListenerPoll::Idle => ListenerReadiness::Idle,
                sys::seccomp_notify::ListenerPoll::Readable => ListenerReadiness::Readable,
                sys::seccomp_notify::ListenerPoll::Closed => ListenerReadiness::Closed,
            })
            .map_err(|e| {
                ExecError::from_sys(e, IsolationStage::Seccomp, "poll of the seccomp listener")
            })
    }

    /// 通知を 1 件受信する。対象が既に消えていれば `None`。[`Self::wait`] が `Readable` を返した直後に呼ぶ。
    ///
    /// 返す [`SeccompNotification`] は記録に要る値(通知 ID・PID・syscall 番号・arch)だけを持つ。引数と命令ポインタは
    /// 公開しない(ポインタ先を許可の判断に使うと TOCTOU になるため。応答は常に `-EPERM` の 1 種類)。
    ///
    /// `SECCOMP_IOCTL_NOTIF_RECV` は `O_NONBLOCK` を見ず、カーネル内の要求セマフォで待つ。待機は「通知が無いのに RECV
    /// を呼んだ」ときにだけ起き、`wait` が `Readable` を返した直後の単独の読み手では起きない(通知が取り消されても
    /// セマフォは先に up 済みで、RECV は `ENOENT` で戻る。Linux v6.12 `seccomp_notify_recv`)。無期限待機の唯一の経路は
    /// 複数の読み手が同じ fd を競うことなので、同時の受信を 1 本に限り、2 本目は待たずに `None` を返す(REPAIR-5)。
    /// `EINTR` も再試行せず `None` で戻し、呼び出し側のループが停止要求を確かめてから再び `wait` する。
    pub fn receive(&self) -> Result<Option<SeccompNotification>, ExecError> {
        if self.1.swap(true, Ordering::AcqRel) {
            return Ok(None);
        }
        // 排他の中で到着を確かめ直す。別の読み手が同じ通知を先に消費していれば未到着になり、RECV に進まない
        // (古い `Readable` を根拠に RECV すると次の通知まで無期限に止まる。REPAIR-5)。
        let result = match sys::seccomp_notify::poll_listener(self.0.as_fd(), 0) {
            Ok(sys::seccomp_notify::ListenerPoll::Readable) => {
                sys::seccomp_notify::notif_recv(self.0.as_fd())
            }
            Ok(_) => {
                self.1.store(false, Ordering::Release);
                return Ok(None);
            }
            Err(e) => {
                self.1.store(false, Ordering::Release);
                return Err(ExecError::from_sys(
                    e,
                    IsolationStage::Seccomp,
                    "re-poll of the seccomp listener",
                ));
            }
        };
        self.1.store(false, Ordering::Release);
        result
            .map(|n| {
                n.map(|n| SeccompNotification {
                    id: NotificationId(n.id),
                    pid_in_listener_ns: n.pid,
                    nr: n.nr,
                    arch: n.arch,
                })
            })
            .map_err(|e| {
                ExecError::from_sys(
                    e,
                    IsolationStage::Seccomp,
                    "receive of a seccomp notification",
                )
            })
    }

    /// 通知 `id` がまだ応答待ちか(`ID_VALID`)。`/proc` の読み取りの後に呼び、pid の再利用や対象の終了で別プロセスの
    /// 情報を記録しないことを確かめる cookie 検証。
    pub fn is_pending(&self, id: NotificationId) -> Result<bool, ExecError> {
        sys::seccomp_notify::notif_id_valid(self.0.as_fd(), id.0).map_err(|e| {
            ExecError::from_sys(
                e,
                IsolationStage::Seccomp,
                "validate of a seccomp notification id",
            )
        })
    }

    /// 通知 `id` へ `-EPERM` で応答する(拒否を許可に覆す応答は持たない)。対象が既に消えていれば
    /// [`DenyOutcome::TargetGone`]。
    pub fn deny_eperm(&self, id: NotificationId) -> Result<DenyOutcome, ExecError> {
        sys::seccomp_notify::notif_send_eperm(self.0.as_fd(), id.0)
            .map(|sent| {
                if sent {
                    DenyOutcome::Sent
                } else {
                    DenyOutcome::TargetGone
                }
            })
            .map_err(|e| {
                ExecError::from_sys(
                    e,
                    IsolationStage::Seccomp,
                    "response to a seccomp notification",
                )
            })
    }
}

/// [`SeccompListener::wait`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenerReadiness {
    /// 時間切れ(通知なし)。
    Idle,
    /// 未処理の通知がある。
    Readable,
    /// filter の利用者がいなくなった(コンテナの全プロセスが終了した)。以後通知は来ない。
    Closed,
}

/// 通知の識別子(カーネルが採番する cookie)。値を作れるのは受信だけ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationId(u64);

/// 受信した通知のうち記録に要る値。引数・命令ポインタは持たない(TOCTOU の余地を型で無くす。SEC-4・#2025)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompNotification {
    id: NotificationId,
    pid_in_listener_ns: u32,
    nr: i32,
    arch: u32,
}

impl SeccompNotification {
    /// 応答に使う識別子。
    pub fn id(&self) -> NotificationId {
        self.id
    }
    /// 対象スレッドの TID。**listener(受信側)の PID namespace** の値で、記録にはそのまま使えない
    /// (`AuditPid` は対象自身の PID namespace の値。`/proc/<値>/status` の `NSpid` で変換する)。
    pub fn pid_in_listener_ns(&self) -> u32 {
        self.pid_in_listener_ns
    }
    /// 拒否された syscall 番号(`seccomp_data.nr`)。
    pub fn nr(&self) -> i32 {
        self.nr
    }
    /// `seccomp_data.arch`(`AUDIT_ARCH_*`)。
    pub fn arch(&self) -> u32 {
        self.arch
    }
}

/// [`SeccompListener::deny_eperm`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyOutcome {
    /// `-EPERM` を返した。
    Sent,
    /// 応答の前に対象が消えていた(`ENOENT`)。
    TargetGone,
}

/// 子（PID 1 / worker）側の送信口。socketpair の子の端を所有する。
#[derive(Debug)]
pub(crate) struct ListenerSender(OwnedFd, crate::seccomp::ErrnoDelivery);

impl ListenerSender {
    pub(crate) fn new(child_end: OwnedFd) -> Self {
        Self(child_end, crate::seccomp::ErrnoDelivery::Errno)
    }

    /// 載せる filter の ERRNO 側の届け方を設定する(既定 `Errno`。`UserNotif` は listener に応答する者がいる
    /// 本番 launcher の opt-in だけ。SEC-4・#2025)。
    pub(crate) fn with_delivery(mut self, delivery: crate::seccomp::ErrnoDelivery) -> Self {
        self.1 = delivery;
        self
    }

    /// 設定済みの届け方。
    pub(crate) fn delivery(&self) -> crate::seccomp::ErrnoDelivery {
        self.1
    }

    /// listener を得る前の適用失敗(`EBUSY` 等)を `E` + コード 1 バイト(`F` FailedPrecondition・`P` PermissionDenied・
    /// `U` Unimplemented・`T` Timeout・その他 `I`)の 1 通で C へ知らせる(ベストエフォート。SEC-4・#2024)。
    ///
    /// 運ぶのは `ErrorCode` の分類 1 バイトだけ(メッセージ・errno は運ばない)。C は [`receive_listener`] で段 `Seccomp` の
    /// 同じコードの失敗に復元し、EOF 由来の `Internal` に潰れない。送れなくても(C が既に閉じた等)失敗は変わらない。
    pub(crate) fn report_failure(&self, error: &ExecError) {
        let code = match error.code {
            ErrorCode::FailedPrecondition => b'F',
            ErrorCode::PermissionDenied => b'P',
            ErrorCode::Unimplemented => b'U',
            ErrorCode::Timeout => b'T',
            _ => b'I',
        };
        let _ = sys::send_nonblocking_unix(self.0.as_fd(), &[TOKEN_FAILURE, code]);
    }

    /// `listener` を C へ送り、自分の fd を閉じ、C の ACK を期限つきで待つ。どれかが失敗したら exec に進ませない
    /// （段 `Seccomp` の `ExecError`）。
    pub(crate) fn hand_over(self, listener: OwnedFd, timeout: Duration) -> Result<(), ExecError> {
        const STAGE: IsolationStage = IsolationStage::Seccomp;
        sys::seccomp_notify::send_fd_with_token(self.0.as_fd(), TOKEN_LISTENER, listener.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "send of the seccomp listener"))?;
        // 手元の listener を閉じる（workload が持たないように）。
        drop(listener);
        let deadline = Instant::now() + timeout;
        match wait_readable(self.0.as_fd(), deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ExecError::new(
                    ErrorCode::Timeout,
                    STAGE,
                    "the launcher did not acknowledge the seccomp listener in time",
                ));
            }
            Err(e) => return Err(ExecError::from_sys(e, STAGE, "wait for the listener ACK")),
        }
        let mut buf = [0u8; 2];
        let n = sys::seccomp_notify::recv_nowait(self.0.as_fd(), &mut buf)
            .map_err(|e| ExecError::from_sys(e, STAGE, "receive of the listener ACK"))?;
        if n == 1 && buf.first() == Some(&ACK) {
            Ok(())
        } else {
            Err(ExecError::new(
                ErrorCode::Internal,
                STAGE,
                "the launcher rejected or dropped the seccomp listener",
            ))
        }
    }
}

/// `deadline` まで `fd` が読み取り可能になるのを待つ（`EINTR` は残り時間で再試行）。時間切れは `false`。
fn wait_readable(fd: BorrowedFd<'_>, deadline: Instant) -> Result<bool, SysError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let ms = i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX);
        match sys::poll_readable(fd, ms) {
            Ok(true) => return Ok(true),
            Ok(false) => {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
            Err(SysError::Os(e)) if e == sys::EINTR => {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// 受信した 1 通の検証（純粋な判定。fd は `received` の drop で閉じる）。受理なら listener を返し、拒否なら
/// 固定の理由語を返す。
fn validate(
    received: sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
) -> Result<OwnedFd, &'static str> {
    let sys::seccomp_notify::ReceivedFd {
        payload,
        mut fds,
        creds,
        truncated,
    } = received;
    if payload.is_empty() && fds.is_empty() {
        return Err(SENDER_CLOSED_MESSAGE);
    }
    if truncated {
        return Err("the listener message was truncated");
    }
    if payload.as_slice() != [TOKEN_LISTENER] {
        return Err("the listener message had an unexpected payload");
    }
    if fds.len() != 1 {
        return Err("the listener message did not carry exactly one fd");
    }
    let Some(creds) = creds else {
        return Err("the listener message carried no sender credentials");
    };
    if u32::try_from(creds.pid).ok() != Some(expected_pid) {
        return Err("the listener message came from an unexpected process");
    }
    let Some(fd) = fds.pop() else {
        return Err("the listener message did not carry exactly one fd");
    };
    match sys::seccomp_notify::fd_is_cloexec(fd.as_fd()) {
        Ok(true) => {}
        _ => return Err("the received fd is not close-on-exec"),
    }
    let kind = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok();
    if kind.as_deref().and_then(|p| p.to_str()) != Some(NOTIFY_FD_KIND) {
        return Err("the received fd is not a seccomp notification fd");
    }
    Ok(fd)
}

/// 適用失敗の通知(`E` + コード 1 バイト。fd 無し・送信元が期待の pid)なら、段 `Seccomp` の同じコードの `ExecError` に復元する。
/// 許可リスト外の語は `Internal`。通知でなければ `None`(通常の検証へ進む)。
fn decode_failure(
    received: &sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
) -> Option<ExecError> {
    if received.payload.first() != Some(&TOKEN_FAILURE) || !received.fds.is_empty() {
        return None;
    }
    let from_expected = received
        .creds
        .as_ref()
        .is_some_and(|c| u32::try_from(c.pid).ok() == Some(expected_pid));
    if received.truncated || !from_expected {
        return None;
    }
    if received.payload.len() != 2 {
        return None;
    }
    let (code, message) = match received.payload.get(1).copied() {
        Some(b'F') => (
            ErrorCode::FailedPrecondition,
            "seccomp listener unavailable: an ancestor filter already has a listener, or the process state forbids it",
        ),
        Some(b'P') => (
            ErrorCode::PermissionDenied,
            "the container init was denied while applying the seccomp filter",
        ),
        Some(b'U') => (
            ErrorCode::Unimplemented,
            "the seccomp filter is not supported on this target",
        ),
        Some(b'T') => (
            ErrorCode::Timeout,
            "the container init timed out while applying the seccomp filter",
        ),
        _ => (
            ErrorCode::Internal,
            "the container init failed to apply the seccomp filter",
        ),
    };
    Some(ExecError::new(code, IsolationStage::Seccomp, message))
}

/// 子の端と対になる C の端から listener を受け取って検証し、ACK を返す。
///
/// `expected_pid` は C が起動した子（launch は PID 1、exec は worker）の pid。`deadline` までに届かなければ
/// `Timeout`、EOF（子が送る前に死んだ）・検証の不一致は `Internal`（段 `Seccomp`）。呼び出し側が子を回収する。
pub(crate) fn receive_listener(
    sock: BorrowedFd<'_>,
    expected_pid: u32,
    deadline: Instant,
) -> Result<SeccompListener, ExecError> {
    receive_listener_classified(sock, expected_pid, deadline).map_err(|failure| match failure {
        ReceiveFailure::SenderClosed => ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            SENDER_CLOSED_MESSAGE,
        ),
        ReceiveFailure::Failed(e) => e,
    })
}

/// 何も届かないまま送り手が閉じたときの文言（launch 側の `Internal` と exec 側の判別で同じ値を使う）。
const SENDER_CLOSED_MESSAGE: &str = "the sender closed before delivering the seccomp listener";

/// [`receive_listener_classified`] の失敗。EOF（送り手が seccomp より前で失敗して終わった通常の経路）と、
/// それ以外の拒否・期限切れを区別する（exec の親は前者では worker の結果を採る。SUP-6・#2385）。
enum ReceiveFailure {
    /// 本文も fd も無いまま EOF になった。
    SenderClosed,
    /// 検証の不一致・切り詰め・期限切れ・syscall 失敗・`E` 通知の復元（段 `Seccomp`）。
    Failed(ExecError),
}

/// [`receive_listener`] の本体。EOF を [`ReceiveFailure::SenderClosed`] として区別して返す。
fn receive_listener_classified(
    sock: BorrowedFd<'_>,
    expected_pid: u32,
    deadline: Instant,
) -> Result<SeccompListener, ReceiveFailure> {
    const STAGE: IsolationStage = IsolationStage::Seccomp;
    let failed = |e: ExecError| ReceiveFailure::Failed(e);
    // 受信は `MSG_DONTWAIT`。poll の見かけ上の起床で `EAGAIN` になれば、同じ `deadline` までで待ち直す
    // （各周回の `wait_readable` が期限を見るため無期限にならない。REPAIR-5・#2372）。
    let received = loop {
        match wait_readable(sock, deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(failed(ExecError::new(
                    ErrorCode::Timeout,
                    STAGE,
                    "the seccomp listener was not delivered in time",
                )));
            }
            Err(e) => {
                return Err(failed(ExecError::from_sys(
                    e,
                    STAGE,
                    "wait for the seccomp listener",
                )));
            }
        }
        match sys::seccomp_notify::recv_fd_with_creds(sock) {
            Err(SysError::Os(e)) if e == sys::EAGAIN => {}
            other => {
                break other.map_err(|e| {
                    failed(ExecError::from_sys(
                        e,
                        STAGE,
                        "receive of the seccomp listener",
                    ))
                })?;
            }
        }
    };
    if let Some(e) = decode_failure(&received, expected_pid) {
        return Err(failed(e));
    }
    if received.payload.is_empty() && received.fds.is_empty() {
        return Err(ReceiveFailure::SenderClosed);
    }
    let fd = validate(received, expected_pid)
        .map_err(|why| failed(ExecError::new(ErrorCode::Internal, STAGE, why)))?;
    // 設定の失敗で ACK を返さない(子が exec へ進んだまま listener だけ捨てられるのを防ぐ。fail-closed)。
    ack_after_nonblocking(
        || {
            sys::seccomp_notify::set_nonblocking(fd.as_fd())
                .map_err(|e| ExecError::from_sys(e, STAGE, "set the seccomp listener non-blocking"))
        },
        || {
            sys::send_nonblocking_unix(sock, &[ACK])
                .map(|_| ())
                .map_err(|e| ExecError::from_sys(e, STAGE, "send of the listener ACK"))
        },
    )
    .map_err(failed)?;
    Ok(SeccompListener(fd, AtomicBool::new(false)))
}

/// listener の後処理(`set_nonblocking`)を先に行い、成功したときだけ ACK を送る。順序を試験で固定するため分離している。
fn ack_after_nonblocking<S, A>(set_nonblocking: S, ack: A) -> Result<(), ExecError>
where
    S: FnOnce() -> Result<(), ExecError>,
    A: FnOnce() -> Result<(), ExecError>,
{
    set_nonblocking()?;
    ack()
}

/// 新しい socketpair（C の端、子の端）。C の端には `SO_PASSCRED` を設定済み（送信の前に必要）。
/// どちらも fd 3 以上へ置く（子の標準入出力の付け替えで潰されないように）。
pub(crate) fn listener_socketpair() -> Result<(OwnedFd, OwnedFd), ExecError> {
    const STAGE: IsolationStage = IsolationStage::Spawn;
    let (parent_end, child_end) = sys::seccomp_notify::unix_seqpacket_pair()
        .map_err(|e| ExecError::from_sys(e, STAGE, "create the listener socketpair"))?;
    sys::seccomp_notify::set_passcred(parent_end.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "enable SO_PASSCRED"))?;
    Ok((
        super::process::keep_above_stdio(parent_end)?,
        super::process::keep_above_stdio(child_end)?,
    ))
}

/// exec の worker（`spawn_exec_worker_with_listener` の子）側の送信口（SEC-4・SUP-6・#2385）。
///
/// `ExecRestrictions::with_seccomp_listener` へ渡すと、`reapply_restrictions` の最後（seccomp の段）が
/// `NEW_LISTENER` 付きで filter を載せ、得た listener を exec の親（[`ExecListenerReceiver`]）へ渡して ACK を待つ。
/// 構築できるのは core だけ（`spawn_exec_worker_with_listener` が worker へ渡す）で、`Clone` を持たない。
/// filter の届け方（`ERRNO` か `USER_NOTIF` か）は exec の親が fork の **前** に決めて持たせる（`delivery`）。
/// `USER_NOTIF` なら拒否ごとに通知が生じ、応答者は exec の親（supervisor の `exec::run_in_worker_with`。
/// `docs/design/audit-delivery.md` 9.4・#2544）。`Errno` のままなら通知は生じない。
#[derive(Debug)]
pub struct ExecListenerSender {
    inner: ListenerSender,
    ack_deadline: Option<Instant>,
}

impl ExecListenerSender {
    fn new(child_end: OwnedFd, delivery: crate::seccomp::ErrnoDelivery) -> Self {
        Self {
            inner: ListenerSender::new(child_end).with_delivery(delivery),
            ack_deadline: None,
        }
    }

    /// filter の届け方（親が fork 前に決めた値）。
    #[must_use]
    pub fn delivery(&self) -> crate::seccomp::ErrnoDelivery {
        self.inner.delivery()
    }

    /// ACK 待ちの絶対期限を設定する（実際の待ちは `ACK_TIMEOUT` と残り時間の短い方。REPAIR-5）。
    #[must_use]
    pub fn with_ack_deadline(mut self, at: Instant) -> Self {
        self.ack_deadline = Some(at);
        self
    }

    /// 送り手と、ACK を待つ上限。
    pub(crate) fn into_parts(self) -> (ListenerSender, Duration) {
        let timeout = match self.ack_deadline {
            Some(at) => at
                .saturating_duration_since(Instant::now())
                .min(ACK_TIMEOUT),
            None => ACK_TIMEOUT,
        };
        (self.inner, timeout)
    }
}

/// exec の親プロセス側の受信口（SEC-4・SUP-6・#2385）。worker の fork の前に作った socketpair の親の端を所有する。
#[derive(Debug)]
pub struct ExecListenerReceiver(OwnedFd);

/// [`ExecListenerReceiver::receive`] の結果。
#[derive(Debug)]
#[non_exhaustive]
pub enum ListenerReceipt {
    /// 検証済みの listener を受け取り、ACK を返した。呼び出し側は worker の回収が済むまで保持する。
    Received(SeccompListener),
    /// 何も届かないまま worker 側が閉じた。worker が seccomp の段より前で失敗して終わった通常の経路で、
    /// 呼び出し側は worker の結果（失敗の理由）を採る。worker が成功を返したなら ACK 無しで進んだことになるため拒否する。
    SenderClosed,
    /// 検証の不一致・切り詰め・送信元の不一致・worker からの失敗通知（`EBUSY` 等）。段 `Seccomp`。
    Rejected(ExecError),
    /// 期限までに届かなかった。段 `Seccomp`・`Timeout`。
    TimedOut(ExecError),
}

impl ExecListenerReceiver {
    /// listener を期限つきで受信・検証して ACK を返す。`self` を消費するため、成否によらず親の端は閉じ、
    /// worker の ACK 待ちには HUP が届く。`worker` は `spawn_exec_worker_with_listener` が返した子で、送信元の pid の照合に使う。
    ///
    /// worker の終了を待つ **前** に呼ぶこと（worker は ACK を待つため、先に終了を待つと相互待ちになる）。
    pub fn receive(self, worker: &ContainerChild, deadline: Instant) -> ListenerReceipt {
        match receive_listener_classified(self.0.as_fd(), worker.pid(), deadline) {
            Ok(listener) => ListenerReceipt::Received(listener),
            Err(ReceiveFailure::SenderClosed) => ListenerReceipt::SenderClosed,
            Err(ReceiveFailure::Failed(e)) if e.code == ErrorCode::Timeout => {
                ListenerReceipt::TimedOut(e)
            }
            Err(ReceiveFailure::Failed(e)) => ListenerReceipt::Rejected(e),
        }
    }
}

/// 新しい socketpair を作り、`(親の端, 子の端の送信口)` を返す（`exec_command` の worker 用）。
pub(crate) fn exec_listener_pair() -> Result<(ExecListenerReceiver, OwnedFd), ExecError> {
    let (parent_end, child_end) = listener_socketpair()?;
    Ok((ExecListenerReceiver(parent_end), child_end))
}

impl ExecListenerReceiver {
    /// 親の端の fd 番号（worker が継承した複製を閉じるために使う）。
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

/// 子の端から送信口を作る（`exec_command` の worker 内で呼ぶ）。
pub(crate) fn exec_sender_from(
    child_end: OwnedFd,
    delivery: crate::seccomp::ErrnoDelivery,
) -> ExecListenerSender {
    ExecListenerSender::new(child_end, delivery)
}

/// 試験専用: 呼び出しプロセスが今開いている socket fd の識別子（`/proc/self/fd` の `socket:[inode]`）を返す（SEC-4・SUP-6・#2385・#2603）。
///
/// 試験の親が worker の fork（受け渡し用 socketpair の作成）より前に採り、[`apply_exec_seccomp_listener_for_test`] の
/// 基準にする。起動元から継承した socket（stdio が socket の実行器など）は受け渡しと無関係なので、基準に含めて数えない。
/// `exec-test-support` feature の下のみ。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn open_socket_ids_for_test() -> Result<Vec<String>, ExecError> {
    let dir = std::fs::read_dir("/proc/self/fd").map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            "failed to list the open fds",
        )
    })?;
    // `read_dir` 自身の fd も走査するが、それは socket ではない。
    let mut ids: Vec<String> = dir
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter_map(|t| t.to_str().map(str::to_owned))
        .filter(|s| s.starts_with("socket:["))
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// 試験専用: worker の中で本番と同じ seccomp の listener 付き適用（NNP → `NEW_LISTENER` 付き filter → 送信 → ACK 待ち）を行い、
/// 受け渡しの後に開いている socket fd のうち `baseline` に無いものの数を返す（SEC-4・SUP-6・#2385・#2603。
/// supervisor の結合試験 `exec_seccomp_listener`）。
///
/// `baseline` は試験の親が fork の前に [`open_socket_ids_for_test`] で採った集合。数は 0 でなければならない（子の端は送信で
/// 消費され、継承した親の端は worker の開始時に閉じ済みのため。残っていれば listener の受け渡しに使った socket が worker に
/// 漏れている）。親は基準の socket を開いたままなので inode は再利用されず、基準との差は受け渡しのために作った socket だけに
/// なる。起動元から継承した socket を数えると実行環境で結果が変わる（#2603）。**呼び出しプロセスに seccomp の filter が不可逆に
/// 載る**ため、使い捨ての worker 専用。`exec-test-support` feature の下のみ。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn apply_exec_seccomp_listener_for_test(
    sender: ExecListenerSender,
    baseline: &[String],
) -> Result<usize, ExecError> {
    super::no_new_privs::apply_no_new_privs()?;
    let (sender, timeout) = sender.into_parts();
    super::seccomp::apply_default_seccomp_with_listener_threads(
        sender,
        timeout,
        &mut super::ThreadCountSource::ProcSelf,
    )?;
    Ok(open_socket_ids_for_test()?
        .iter()
        .filter(|id| !baseline.contains(id))
        .count())
}

/// 試験専用: listener ではない fd（pipe の読み端）を、本番の `hand_over` と同じ経路で親へ送る（親の検証が拒否することと、
/// 拒否で worker の ACK 待ちが期限より前に終わることの確認用。SEC-4・SUP-6・#2385）。常に `Err` を返せば期待どおり
/// （親が拒否して閉じた）で、`Ok` は親が ACK を返した（検証の欠陥）。`exec-test-support` feature の下のみ。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn hand_over_non_listener_for_test(sender: ExecListenerSender) -> Result<(), ExecError> {
    let (sender, timeout) = sender.into_parts();
    let (reader, _writer) = std::io::pipe().map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            "failed to create a pipe",
        )
    })?;
    sender.hand_over(OwnedFd::from(reader), timeout)
}

/// [`UserNotifProbe::call_kcmp`] が応答を待つ上限。
#[cfg(any(test, feature = "exec-test-support"))]
const KCMP_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// [`UserNotifProbe`] の Drop がスレッドの終了を待つ上限。
#[cfg(any(test, feature = "exec-test-support"))]
const PROBE_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// USER_NOTIF 版の filter を載せた使い捨てスレッド(試験専用。SEC-4・#2025)。
///
/// 本番の filter 適用は PID 1 で単一スレッドを要するため、試験では適用を **専用スレッド 1 本** に閉じ込める
/// (filter は呼び出しスレッドだけに効く)。`NEW_LISTENER` で得た listener は [`Self::take_listener`] で取り出し、
/// 応答者(supervisor のループ)に渡す。`kcmp`(ERRNO 側の禁止 syscall)は [`Self::call_kcmp`] でこのスレッドから呼ぶ。
/// 呼び出し元: `fandhe-container-supervisor` の結合試験 `seccomp_notify_audit`(`exec-test-support`)と本 crate の単体試験。
#[cfg(any(test, feature = "exec-test-support"))]
#[doc(hidden)]
pub struct UserNotifProbe {
    listener: Option<SeccompListener>,
    tid: u32,
    commands: Option<std::sync::mpsc::Sender<std::sync::mpsc::Sender<Option<i32>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(test, feature = "exec-test-support"))]
impl UserNotifProbe {
    /// listener を 1 回だけ取り出す。
    pub fn take_listener(&mut self) -> Option<SeccompListener> {
        self.listener.take()
    }

    /// プローブスレッドの TID(自身の PID namespace での値。記録の `pid` の期待値)。
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// プローブスレッドで `kcmp(自 pid, 自 pid, KCMP_VM)` を呼び、成功なら `None`、失敗ならその errno を返す。
    /// 応答が無い間は呼び出しがブロックする(試験が期限で別途見張る)。
    pub fn call_kcmp(&self) -> Option<i32> {
        let (tx, rx) = std::sync::mpsc::channel();
        let sent = self.commands.as_ref().is_some_and(|c| c.send(tx).is_ok());
        if !sent {
            return Some(-1);
        }
        // 応答者がいないと kcmp は止まり続けるので、有限時間で諦める（REPAIR-5）。
        rx.recv_timeout(KCMP_REPLY_TIMEOUT).unwrap_or(Some(-1))
    }
}

#[cfg(any(test, feature = "exec-test-support"))]
impl Drop for UserNotifProbe {
    fn drop(&mut self) {
        self.commands.take();
        // プローブスレッドが応答待ちで止まっていても無期限に待たない。期限内に終わらなければ放置する（REPAIR-5）。
        if let Some(t) = self.thread.take() {
            let end = std::time::Instant::now() + PROBE_JOIN_TIMEOUT;
            while !t.is_finished() && std::time::Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }
}

/// 呼び出しスレッドで `kcmp(自 pid, 自 pid, KCMP_VM)`(ERRNO 側の禁止 syscall)を発行し、成功なら `None`、失敗ならその errno を
/// 返す(試験専用)。`unsafe` を持たない結合試験のコンテナ内プローブが、本番の filter の拒否を観測するために使う
/// (`supervisor_bin_real` の PID 1 のプローブ。SEC-4・#2025)。
#[cfg(any(test, feature = "exec-test-support"))]
#[doc(hidden)]
pub fn kcmp_self_errno_for_test() -> Option<i32> {
    match sys::kcmp_self_probe() {
        Ok(()) => None,
        Err(sys::SysError::Os(n)) => Some(n),
        Err(_) => Some(-1),
    }
}

/// [`UserNotifProbe`] を作る(試験専用)。`NO_NEW_PRIVS` を立て、`UserNotif` 版の filter を `NEW_LISTENER` 付きで載せる。
/// 祖先に listener がある環境などで失敗したら理由を `Err` で返す。
#[cfg(any(test, feature = "exec-test-support"))]
#[doc(hidden)]
pub fn user_notif_probe_for_test() -> Result<UserNotifProbe, String> {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(OwnedFd, u32), String>>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<mpsc::Sender<Option<i32>>>();
    let thread = std::thread::Builder::new()
        .name("user-notif-probe".into())
        .spawn(move || {
            let setup = || -> Result<(OwnedFd, u32), String> {
                sys::set_no_new_privs().map_err(|e| format!("no_new_privs: {e:?}"))?;
                let program = crate::seccomp::build_filter_for_target_arch_with(
                    crate::seccomp::ErrnoDelivery::UserNotif,
                )
                .map_err(|e| e.to_string())?;
                let fd = sys::seccomp_notify::seccomp_set_filter_new_listener(&program)
                    .map_err(|e| format!("new listener: {e:?}"))?;
                // `/proc/thread-self` は "<tgid>/task/<tid>" へのリンク(gettid の syscall 番号を増やさない)。
                let link = std::fs::read_link("/proc/thread-self").map_err(|e| e.to_string())?;
                let tid = link
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.parse::<u32>().ok())
                    .ok_or("unparsable /proc/thread-self")?;
                Ok((fd, tid))
            };
            let ok = setup();
            let failed = ok.is_err();
            let _ = ready_tx.send(ok);
            if failed {
                return;
            }
            while let Ok(reply) = cmd_rx.recv() {
                let r = match sys::kcmp_self_probe() {
                    Ok(()) => None,
                    Err(sys::SysError::Os(n)) => Some(n),
                    Err(_) => Some(-1),
                };
                let _ = reply.send(r);
            }
        })
        .map_err(|e| e.to_string())?;
    let (fd, tid) = ready_rx.recv().map_err(|e| e.to_string())??;
    sys::seccomp_notify::set_nonblocking(fd.as_fd()).map_err(|e| format!("nonblock: {e:?}"))?;
    Ok(UserNotifProbe {
        listener: Some(SeccompListener(fd, AtomicBool::new(false))),
        tid,
        commands: Some(cmd_tx),
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sys::seccomp_notify::{ReceivedFd, Ucred};

    /// SEC-4・REPAIR-5: 非ブロック化が先で ACK が後。非ブロック化が失敗したら ACK を送らず、そのエラーを返す。
    #[test]
    fn sec4_2025_ack_is_sent_only_after_nonblocking_succeeds() {
        use std::cell::RefCell;
        let order = RefCell::new(Vec::new());
        ack_after_nonblocking(
            || {
                order.borrow_mut().push("nonblock");
                Ok(())
            },
            || {
                order.borrow_mut().push("ack");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(order.into_inner(), ["nonblock", "ack"]);

        let acked = RefCell::new(false);
        let err = ack_after_nonblocking(
            || {
                Err(ExecError::new(
                    ErrorCode::Internal,
                    IsolationStage::Seccomp,
                    "nonblock failed",
                ))
            },
            || {
                *acked.borrow_mut() = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert!(!acked.into_inner());
    }

    fn me() -> u32 {
        std::process::id()
    }

    fn pipe_fd() -> OwnedFd {
        let (r, _w) = std::io::pipe().unwrap();
        OwnedFd::from(r)
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

    /// 実 listener を使い捨てスレッドで作る（filter の適用はスレッド単位。通知は生じない ERRNO 版）。
    fn real_listener() -> OwnedFd {
        std::thread::spawn(|| {
            assert_eq!(sys::set_no_new_privs(), Ok(()));
            let p = crate::seccomp::build_filter_for_target_arch().unwrap();
            sys::seccomp_notify::seccomp_set_filter_new_listener(&p).unwrap()
        })
        .join()
        .unwrap()
    }

    /// SEC-4: 拒否する条件の表（理由語を具体値で照合する）。
    #[test]
    fn sec4_validate_rejects_every_malformed_message() {
        let cases: Vec<(&str, ReceivedFd, &str)> = vec![
            (
                "eof",
                msg(b"", vec![], None, false),
                "the sender closed before delivering the seccomp listener",
            ),
            (
                "truncated",
                msg(b"L", vec![pipe_fd()], Some(me()), true),
                "the listener message was truncated",
            ),
            (
                "token",
                msg(b"X", vec![pipe_fd()], Some(me()), false),
                "the listener message had an unexpected payload",
            ),
            (
                "no fd",
                msg(b"L", vec![], Some(me()), false),
                "the listener message did not carry exactly one fd",
            ),
            (
                "two fds",
                msg(b"L", vec![pipe_fd(), pipe_fd()], Some(me()), false),
                "the listener message did not carry exactly one fd",
            ),
            (
                "no creds",
                msg(b"L", vec![pipe_fd()], None, false),
                "the listener message carried no sender credentials",
            ),
            (
                "pid mismatch",
                msg(b"L", vec![pipe_fd()], Some(me() + 1), false),
                "the listener message came from an unexpected process",
            ),
            (
                "wrong kind",
                msg(b"L", vec![pipe_fd()], Some(me()), false),
                "the received fd is not a seccomp notification fd",
            ),
        ];
        for (name, m, why) in cases {
            assert_eq!(validate(m, me()).unwrap_err(), why, "{name}");
        }
    }

    /// SEC-4: 正しい listener は受理される（種別・close-on-exec・pid の照合を通る）。
    #[test]
    fn sec4_validate_accepts_a_real_listener() {
        let l = real_listener();
        let fd = validate(msg(b"L", vec![l], Some(me()), false), me()).unwrap();
        let kind = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
    }

    /// SEC-4: socketpair 越しの送受信と ACK の往復（同一プロセス内。送信元 pid は自分）。
    #[test]
    fn sec4_handover_and_receive_roundtrip_with_ack() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let l = real_listener();
        let sender = ListenerSender::new(child_end);
        let t = std::thread::spawn(move || sender.hand_over(l, Duration::from_secs(10)));
        let got = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        t.join().unwrap().unwrap();
        let kind =
            std::fs::read_link(format!("/proc/self/fd/{}", got.as_fd().as_raw_fd())).unwrap();
        assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
    }

    /// REPAIR-5・SEC-4: 子が送らずに閉じると、C は期限まで待たずに EOF を拒否として観測する。
    #[test]
    fn sec4_receive_sees_eof_immediately_when_the_child_end_closes() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        drop(child_end);
        let started = Instant::now();
        let e = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(
            e.message,
            "the sender closed before delivering the seccomp listener"
        );
    }

    /// REPAIR-5: 届かないまま期限が切れると `Timeout`。
    #[test]
    fn sec4_receive_times_out_when_nothing_arrives() {
        let (parent_end, _child_end) = listener_socketpair().unwrap();
        let e = receive_listener(
            parent_end.as_fd(),
            me(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);
    }

    /// SEC-4: ACK が届かないまま C が閉じると、子の `hand_over` は失敗する（exec に進ませない）。
    #[test]
    fn sec4_handover_fails_when_the_launcher_closes_without_ack() {
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let l = real_listener();
        let sender = ListenerSender::new(child_end);
        let t = std::thread::spawn(move || sender.hand_over(l, Duration::from_secs(10)));
        // 送信を待ってから ACK せずに閉じる。
        assert_eq!(
            wait_readable(parent_end.as_fd(), Instant::now() + Duration::from_secs(10)),
            Ok(true)
        );
        drop(parent_end);
        let e = t.join().unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Seccomp);
    }

    /// SEC-4・#2024(issue コメントの要求): ACK の後に execve したプロセス(workload 相当)へ、listener fd も受け渡しに
    /// 使った socket も継承されない。`ls -l /proc/self/fd` の出力を具体的に照合する。
    #[test]
    fn sec4_2024_listener_and_socket_are_not_inherited_across_execve() {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        let (parent_end, child_end) = listener_socketpair().unwrap();
        let socket_name =
            std::fs::read_link(format!("/proc/self/fd/{}", child_end.as_raw_fd())).unwrap();
        let socket_name = socket_name.to_str().unwrap().to_string();
        assert!(socket_name.starts_with("socket:["), "{socket_name}");
        let (mut out_r, out_w) = std::io::pipe().unwrap();
        let pid = sys::fork_single_threaded_with(
            || true,
            move || {
                if sys::set_no_new_privs().is_err() {
                    return 9;
                }
                let Ok(p) = crate::seccomp::build_filter_for_target_arch() else {
                    return 8;
                };
                let Ok(listener) = sys::seccomp_notify::seccomp_set_filter_new_listener(&p) else {
                    return 10;
                };
                if ListenerSender::new(child_end)
                    .hand_over(listener, Duration::from_secs(20))
                    .is_err()
                {
                    return 11;
                }
                let err = std::process::Command::new("/bin/ls")
                    .args(["-l", "/proc/self/fd"])
                    .stdout(out_w)
                    .exec();
                let _ = err;
                127
            },
            1,
        )
        .unwrap();
        let child = super::super::process::ContainerChild::spawned(pid);
        // `child_end` と `out_w` は子へ move 済み(親の複製は fork 後に閉じる扱い)。ここでの `out_r` 以外の端は無い。
        let got = receive_listener(
            parent_end.as_fd(),
            pid,
            Instant::now() + Duration::from_secs(20),
        );
        assert!(got.is_ok(), "{got:?}");
        let mut listing = String::new();
        // 子が exec した ls の終了(= 書き込み側の全 close)まで読む。ハング防止に期限を付ける。
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match wait_readable(out_r.as_fd(), deadline) {
                Ok(true) => {}
                other => panic!("probe output did not arrive: {other:?}"),
            }
            let mut buf = [0u8; 4096];
            let n = out_r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            listing.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert_eq!(
            child.wait_for_exit(Duration::from_secs(10)).unwrap(),
            Some(super::super::process::ChildExit::Exited(0)),
            "{listing}"
        );
        assert!(listing.contains("-> pipe:["), "control: {listing}");
        assert!(!listing.contains("seccomp notify"), "{listing}");
        assert!(!listing.contains(&socket_name), "{listing}");
    }

    /// SEC-4(#2025): USER_NOTIF 版の filter では ERRNO 側の syscall が通知になり、応答者が `-EPERM` を返すと
    /// 対象は `EPERM`(1) を観測する。通知の中身(nr・arch・TID)は具体値で、引数は公開されない。
    #[test]
    fn sec4_2025_user_notif_is_answered_with_eperm_and_reports_values() {
        let mut probe = user_notif_probe_for_test().unwrap();
        let listener = probe.take_listener().unwrap();
        let tid = probe.tid();
        let responder = std::thread::spawn(move || {
            assert_eq!(
                listener.wait(Duration::from_secs(10)).unwrap(),
                ListenerReadiness::Readable
            );
            let n = listener.receive().unwrap().expect("a notification");
            assert!(listener.is_pending(n.id()).unwrap());
            // 受信側の PID namespace と対象は同じなので TID が一致する(テストは入れ子の namespace を使わない)。
            assert_eq!(n.pid_in_listener_ns(), tid);
            assert_eq!((n.nr(), n.arch()), (kcmp_nr(), audit_arch()));
            assert_eq!(listener.deny_eperm(n.id()).unwrap(), DenyOutcome::Sent);
            // 応答済みの ID は無効になり、二重応答は対象なし扱いにならず失敗する(EINPROGRESS)か TargetGone。
            assert!(!listener.is_pending(n.id()).unwrap());
            listener
        });
        assert_eq!(probe.call_kcmp(), Some(1));
        let listener = responder.join().unwrap();
        assert_eq!(
            listener.wait(Duration::from_millis(50)).unwrap(),
            ListenerReadiness::Idle
        );
        // 応答者(listener)が消えると、拒否は ENOSYS のまま保たれる(許可に倒れない)。
        drop(listener);
        assert_eq!(probe.call_kcmp(), Some(38));
    }

    /// REPAIR-5・SEC-4(#2025): 通知が消費済み(古い `Readable`)の状態で `receive` を呼んでも、RECV に進まず
    /// すぐ `None` を返す(次の通知まで無期限に止まらない)。2 本目の読み手が排他を得た時点の状況を再現する。
    #[test]
    fn repair5_receive_without_pending_notification_returns_none_promptly() {
        let mut probe = user_notif_probe_for_test().unwrap();
        let listener = probe.take_listener().unwrap();
        let started = Instant::now();
        assert!(listener.receive().unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
        // 排他フラグが戻っている(続けて呼べる)。
        assert!(listener.receive().unwrap().is_none());
    }

    fn kcmp_nr() -> i32 {
        #[cfg(target_arch = "x86_64")]
        {
            312
        }
        #[cfg(target_arch = "aarch64")]
        {
            272
        }
    }

    fn audit_arch() -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            0xC000_003E
        }
        #[cfg(target_arch = "aarch64")]
        {
            0xC000_00B7
        }
    }

    /// SEC-4(#2025): 送り手の届け方の既定は ERRNO で、`UserNotif` は明示した場合だけ(誤って応答者のいない構成にしない)。
    #[test]
    fn sec4_2025_sender_delivery_defaults_to_errno() {
        let (_p, c) = listener_socketpair().unwrap();
        let sender = ListenerSender::new(c);
        assert_eq!(sender.delivery(), crate::seccomp::ErrnoDelivery::Errno);
        assert_eq!(
            sender
                .with_delivery(crate::seccomp::ErrnoDelivery::UserNotif)
                .delivery(),
            crate::seccomp::ErrnoDelivery::UserNotif
        );
        assert_eq!(
            crate::exec::StagePipeline::new().seccomp_delivery(),
            crate::seccomp::ErrnoDelivery::Errno
        );
    }

    // ---- exec の受け渡し（SEC-4・SUP-6・#2385）。worker の代役を同一プロセス内のスレッドで立てる。----
    //
    // libtest は多スレッドで走るため、`fork` を伴う代役は単一スレッド検査（`Threads: 1`）を満たせない。検査を迂回して
    // fork すると、子が他スレッドの握るロックを継承して停止したり、並行する試験の fd を継承して EOF 検出が遅れたりする。
    // そのため fork せず、受け渡しの送信側（worker の役）をスレッドで動かす。送信元 pid の照合（SO_PEERCRED）は
    // 自プロセスの pid と一致する。fork を伴う実プロセスの経路は supervisor の結合試験 `exec_seccomp_listener`
    // （`harness = false`）が検証する。

    /// 代役の worker。`pid` は自プロセスのもので、`join` が終了コード（`body` の戻り値）を返す。
    struct WorkerStandIn {
        child: ContainerChild,
        handle: std::thread::JoinHandle<i32>,
    }

    impl WorkerStandIn {
        /// スレッドの終了を待って `body` の戻り値を返す（panic は -1）。
        fn join(self) -> i32 {
            self.handle.join().unwrap_or(-1)
        }
    }

    /// 代役の worker を起動し、`(親の受信口, 代役)` を返す。`body` は子の送信口を受けて終了コードを返す。
    fn fork_worker_stand_in(
        body: impl FnOnce(ExecListenerSender) -> i32 + Send + 'static,
    ) -> (ExecListenerReceiver, WorkerStandIn) {
        let (receiver, child_end) = exec_listener_pair().unwrap();
        let handle = std::thread::spawn(move || {
            body(exec_sender_from(
                child_end,
                crate::seccomp::ErrnoDelivery::Errno,
            ))
        });
        (
            receiver,
            WorkerStandIn {
                child: ContainerChild::spawned(std::process::id()),
                handle,
            },
        )
    }

    /// 子の中で実 listener を作る（NNP を立て、ERRNO 版の filter を `NEW_LISTENER` 付きで載せる）。
    fn child_listener() -> Option<OwnedFd> {
        sys::set_no_new_privs().ok()?;
        let p = crate::seccomp::build_filter_for_target_arch().ok()?;
        sys::seccomp_notify::seccomp_set_filter_new_listener(&p).ok()
    }

    /// SEC-4・SUP-6（#2385）: 実 listener を受け取って検証し、worker は ACK を受けて 0 で終わる。
    #[test]
    fn sec4_sup6_2385_exec_receiver_gets_a_verified_listener() {
        let (receiver, stand_in) = fork_worker_stand_in(|sender| {
            let Some(listener) = child_listener() else {
                return 10;
            };
            let (sender, timeout) = sender
                .with_ack_deadline(Instant::now() + Duration::from_secs(20))
                .into_parts();
            match sender.hand_over(listener, timeout) {
                Ok(()) => 0,
                Err(_) => 11,
            }
        });
        match receiver.receive(&stand_in.child, Instant::now() + Duration::from_secs(20)) {
            ListenerReceipt::Received(l) => {
                let kind =
                    std::fs::read_link(format!("/proc/self/fd/{}", l.as_fd().as_raw_fd())).unwrap();
                assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
            }
            other => panic!("unexpected receipt: {other:?}"),
        }
        assert_eq!(stand_in.join(), 0);
    }

    /// SEC-4・SUP-6（#2385）: worker が何も送らずに終わると `SenderClosed`（期限を待たない）。
    #[test]
    fn sec4_sup6_2385_exec_receiver_reports_sender_closed() {
        let (receiver, stand_in) = fork_worker_stand_in(|sender| {
            drop(sender);
            0
        });
        let started = Instant::now();
        let receipt = receiver.receive(&stand_in.child, Instant::now() + Duration::from_secs(30));
        assert!(
            matches!(receipt, ListenerReceipt::SenderClosed),
            "{receipt:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(stand_in.join(), 0);
    }

    /// SEC-4・SUP-6（#2385）: listener でない fd は `Rejected`（段 `Seccomp`）。親が閉じると worker の ACK 待ちは
    /// HUP で期限より前に終わる。
    #[test]
    fn sec4_sup6_2385_exec_receiver_rejects_a_non_listener_fd() {
        let (receiver, stand_in) = fork_worker_stand_in(|sender| {
            let (sender, _) = sender.into_parts();
            let (r, _w) = std::io::pipe().unwrap();
            let fd = OwnedFd::from(r);
            // 本物の `hand_over` と同じ経路で送り、ACK 待ちが HUP で終わること（60 秒を待たない）を確かめる。
            match sender.hand_over(fd, Duration::from_secs(20)) {
                Err(_) => 0,
                Ok(()) => 12,
            }
        });
        let started = Instant::now();
        match receiver.receive(&stand_in.child, Instant::now() + Duration::from_secs(20)) {
            ListenerReceipt::Rejected(e) => {
                assert_eq!(e.stage, IsolationStage::Seccomp);
                assert_eq!(e.code, ErrorCode::Internal);
                assert_eq!(
                    e.message,
                    "the received fd is not a seccomp notification fd"
                );
            }
            other => panic!("unexpected receipt: {other:?}"),
        }
        assert_eq!(stand_in.join(), 0);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// REPAIR-5・SEC-4（#2385）: 何も届かず眠る worker は期限で `TimedOut`（段 `Seccomp`・`Timeout`）。
    #[test]
    fn sec4_sup6_2385_exec_receiver_times_out() {
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (receiver, stand_in) = fork_worker_stand_in(move |sender| {
            let _keep = sender;
            let _ = released.recv_timeout(Duration::from_secs(30));
            0
        });
        let receipt =
            receiver.receive(&stand_in.child, Instant::now() + Duration::from_millis(150));
        match receipt {
            ListenerReceipt::TimedOut(e) => {
                assert_eq!(e.code, ErrorCode::Timeout);
                assert_eq!(e.stage, IsolationStage::Seccomp);
            }
            other => panic!("unexpected receipt: {other:?}"),
        }
        release.send(()).unwrap();
        assert_eq!(stand_in.join(), 0);
    }

    /// REPAIR-5（#2385）: ACK 待ちの上限は、全体の期限が近ければその残り（`ACK_TIMEOUT` を超えない）。
    #[test]
    fn sec4_sup6_2385_ack_wait_is_capped_by_the_deadline() {
        let (_r, c) = exec_listener_pair().unwrap();
        let (_, t) = exec_sender_from(c, crate::seccomp::ErrnoDelivery::Errno).into_parts();
        assert_eq!(t, ACK_TIMEOUT);
        let (_r, c) = exec_listener_pair().unwrap();
        let (_, t) = exec_sender_from(c, crate::seccomp::ErrnoDelivery::Errno)
            .with_ack_deadline(Instant::now() + Duration::from_secs(2))
            .into_parts();
        assert!(t <= Duration::from_secs(2), "{t:?}");
        let (_r, c) = exec_listener_pair().unwrap();
        let (_, t) = exec_sender_from(c, crate::seccomp::ErrnoDelivery::Errno)
            .with_ack_deadline(Instant::now() + Duration::from_secs(3600))
            .into_parts();
        assert_eq!(t, ACK_TIMEOUT);
    }

    /// SEC-4・SUP-6・#2544: exec の送信口の届け方は親が fork 前に決めた値のまま持ち上がる（`Errno` と `UserNotif` を取り違えない）。
    #[test]
    fn sec4_sup6_2544_exec_sender_carries_the_delivery_chosen_by_the_parent() {
        use crate::seccomp::ErrnoDelivery;
        for delivery in [ErrnoDelivery::Errno, ErrnoDelivery::UserNotif] {
            let (_r, c) = exec_listener_pair().unwrap();
            let sender = exec_sender_from(c, delivery);
            assert_eq!(sender.delivery(), delivery);
            assert_eq!(sender.into_parts().0.delivery(), delivery);
        }
    }
}
