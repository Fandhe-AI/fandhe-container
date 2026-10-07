//! カーネル監査サブシステム（NETLINK_AUDIT）へのフォールバック経路（SEC-4・TASK-41.5.2・#840）。
//!
//! # 役割
//!
//! 主経路（`AuditFileWriter`。TASK-41.5.1・#839）が失敗したときに、同じ [`AuditRecord`] を
//! カーネル監査（auditd 等が読む監査ログ）へユーザー空間監査メッセージとして送る代替経路を提供する。
//! [`AuditFallback`] の実装で、`write_with_fallback` が主経路の失敗時にだけ 1 回呼ぶ。
//!
//! # 方式
//!
//! `record_fallback` の呼び出しごとに `socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT)` を開き、
//! `nlmsghdr`（`NLM_F_REQUEST|NLM_F_ACK`）＋ key=value ペイロードを 1 データグラムでカーネルへ送り、
//! カーネルの ACK（`NLMSG_ERROR`）を [`KERNEL_AUDIT_ACK_TIMEOUT`] を上限に待って閉じる（稀な経路のため
//! 常駐 fd を持たない）。メッセージ型は `AUDIT_TRUSTED_APP`（1121。auditd の libaudit が定義する
//! 信頼済みアプリ向けの自由形式テキスト。カーネルは `AUDIT_FIRST_USER_MSG..=AUDIT_LAST_USER_MSG`
//! の範囲のユーザーメッセージとして受理する）。`AUDIT_USER_AVC`（1107）は SELinux AVC 用の別扱い
//! （カーネルが `audit_enabled` 無効でも処理する等）のため採らない。
//!
//! # 契約・エラー分類（`AuditWriteError` の kind と `ErrorCode`）
//!
//! | 契機 | kind | コード |
//! | ---- | ---- | ------ |
//! | socket 作成不可・初期 user namespace 外（ACK が `ECONNREFUSED`）・rootless | `KernelAuditUnavailable` | `UNAVAILABLE` |
//! | ACK が `EPERM`（`CAP_AUDIT_WRITE` 無し） | `KernelAuditPermissionDenied` | `PERMISSION_DENIED` |
//! | 期限内に一致する ACK が来ない | `KernelAuditTimeout` | `TIMEOUT` |
//! | 上記以外の errno の ACK | `KernelAuditRejected` | `INTERNAL` |
//! | 送受信の I/O 失敗・ACK の形式不正 | `KernelAuditIo` | `INTERNAL` |
//! | 非 Linux・対応外アーキテクチャ・ペイロード過大 | `Unsupported` / `LineTooLong` | `UNIMPLEMENTED` / `INTERNAL` |
//!
//! - `Unimplemented` は「未実装」、`Unavailable` は「実装はあるが環境上到達できない」の区別
//! - ACK は untrusted として扱い、`get()`・`try_into()` だけで解析する。送信元 `nl_pid == 0`（カーネル）・
//!   `nlmsg_seq` 一致のものだけを受理し、他は破棄して締め切りまでに限り再受信する（上限回数あり）
//! - ペイロードの値は英数字・`.`・`-`・`?` と hex のみ。カーネルが `msg='…'` で囲むため、`'`・空白・改行・
//!   NUL を含みうるパスは生バイト列を大文字 hex にして出す（auditd の untrusted string の慣例。ログ注入対策）
//! - `audit_enabled` が無効なカーネルでも ACK は 0（成功）で返るため、「ACK 成功 = 監査ログへ必ず出た」
//!   ではなく「カーネルが受理した」を意味する
//! - 両経路が失敗したときの扱いは [`AuditWriteFailure`](super::AuditWriteFailure) の rustdoc を参照
//!
//! # 未実装（REPAIR-3）
//!
//! 常時の二重記録（tee）によるクラッシュ・改ざん時の記録保持、Linux 6.15+ の Landlock カーネル側監査
//! （`AUDIT_LANDLOCK_*`）によるワークロード拒否の捕捉、supervisor / CLI への配線は後続タスク。

use std::time::{Duration, Instant};

use super::file_writer::{AuditFallback, AuditWriteError, AuditWriteErrorKind as Kind};
use super::{AuditEvent, AuditPath, AuditRecord};

/// ACK を待つ上限時間（REPAIR-5: 無期限に待たない）。
pub const KERNEL_AUDIT_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// 一致しない（他者・古い seq の）メッセージを破棄して再受信する回数の上限。
const MAX_ACK_ATTEMPTS: usize = 8;
/// ACK 受信バッファ長。`nlmsghdr`（16）＋ `nlmsgerr.error`（4）＋元ヘッダ（16）に足りる固定長
/// （超過分はカーネルが切り捨てる）。
const ACK_BUF_LEN: usize = 64;

/// `AUDIT_TRUSTED_APP`（auditd の libaudit が定義するユーザー空間監査メッセージ型）。
const AUDIT_TRUSTED_APP: u16 = 1121;
/// `AUDIT_MESSAGE_TEXT_MAX`（include/uapi/linux/audit.h）。カーネルが 1 メッセージに載せる本文の上限。
const AUDIT_MESSAGE_TEXT_MAX: usize = 8560;
/// `NLM_F_REQUEST`・`NLM_F_ACK`（include/uapi/linux/netlink.h）。
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
/// `NLMSG_ERROR`（ACK も同じ型で返る）。
const NLMSG_ERROR: u16 = 0x2;
/// `nlmsghdr` の長さ。
const NLMSG_HDRLEN: usize = 16;
/// `nlmsgerr.error` までの最小メッセージ長。
const NLMSG_ACK_MIN_LEN: usize = NLMSG_HDRLEN + 4;

/// `EPERM`・`ECONNREFUSED`（ACK の `error` は負の errno）。ACK の解釈用で、syscall の定数ではないため
/// `sys` に依存せず値を持つ（Linux の全アーキテクチャで同値: include/uapi/asm-generic/errno*.h）。
const ERRNO_EPERM: i32 = 1;
const ERRNO_ECONNREFUSED: i32 = 111;

/// `struct nlmsghdr`（固定長 16 バイト。バイト順はホスト順）。壊れた長さを手で組まないための型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NlMsgHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

impl NlMsgHdr {
    fn to_bytes(self) -> [u8; NLMSG_HDRLEN] {
        let mut out = [0u8; NLMSG_HDRLEN];
        let parts: [&[u8]; 5] = [
            &self.len.to_ne_bytes(),
            &self.ty.to_ne_bytes(),
            &self.flags.to_ne_bytes(),
            &self.seq.to_ne_bytes(),
            &self.pid.to_ne_bytes(),
        ];
        let mut at = 0usize;
        for part in parts {
            if let Some(dst) = out.get_mut(at..at + part.len()) {
                dst.copy_from_slice(part);
            }
            at += part.len();
        }
        out
    }
}

/// カーネル監査へ送る 1 データグラム（ヘッダ＋ペイロード＋4 バイト境界までのパディング）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditNetlinkFrame {
    bytes: Vec<u8>,
    seq: u32,
}

impl AuditNetlinkFrame {
    /// `payload` を `seq` 付きのフレームにする。長さは `payload` から計算し、上限超過は拒否する。
    fn new(seq: u32, payload: &[u8]) -> Result<Self, AuditWriteError> {
        let too_long = || AuditWriteError::new(Kind::LineTooLong);
        if payload.len() > AUDIT_MESSAGE_TEXT_MAX {
            return Err(too_long());
        }
        // AUDIT_TRUSTED_APP ではカーネルが本文の最終バイトを NUL で上書きするため、libaudit と同じく
        // 末尾 NUL を含めた strlen+1 を `nlmsg_len` に入れる（含めないと最後のフィールドが欠ける）。
        let total = NLMSG_HDRLEN
            .checked_add(payload.len())
            .and_then(|t| t.checked_add(1))
            .ok_or_else(too_long)?;
        let hdr = NlMsgHdr {
            len: u32::try_from(total).map_err(|_| too_long())?,
            ty: AUDIT_TRUSTED_APP,
            flags: NLM_F_REQUEST | NLM_F_ACK,
            seq,
            pid: 0,
        };
        let padded = total.checked_add(3).ok_or_else(too_long)? & !3usize;
        let mut bytes = Vec::with_capacity(padded);
        bytes.extend_from_slice(&hdr.to_bytes());
        bytes.extend_from_slice(payload);
        // 末尾 NUL と 4 バイト境界までのパディング（ゼロ埋め）。
        bytes.resize(padded, 0);
        Ok(Self { bytes, seq })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// 生バイト列を大文字 hex にして `out` へ追記する。
fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
}

/// パス関連 3 項目（`path`・`path_truncated`・`path_original_len`）を追記する。
fn push_path_fields(out: &mut String, path: Option<&AuditPath>) {
    match path {
        Some(p) => {
            out.push_str(" path=");
            push_hex(out, p.as_path().as_os_str().as_encoded_bytes());
            out.push_str(if p.is_truncated() {
                " path_truncated=1"
            } else {
                " path_truncated=0"
            });
            out.push_str(&format!(" path_original_len={}", p.original_len()));
        }
        None => out.push_str(" path=? path_truncated=? path_original_len=?"),
    }
}

/// レコードをカーネル監査向けの key=value 本文へエンコードする（REPAIR-2・ログ注入対策）。
///
/// `pid` はレコード側（違反したプロセス）の PID で、送信者の PID はカーネルが別に付ける。
/// 本文が [`AUDIT_MESSAGE_TEXT_MAX`] を超える場合は切り詰めず `LineTooLong` で拒否する。
fn encode_payload(record: &AuditRecord) -> Result<String, AuditWriteError> {
    let ts = record.timestamp().as_unix_duration();
    let mut out = format!(
        "op=fandhe-audit layer={} ts={}.{:09} pid={}",
        record.event().layer().as_str(),
        ts.as_secs(),
        ts.subsec_nanos(),
        record.pid().get(),
    );
    match record.syscall() {
        Some(nr) => out.push_str(&format!(" syscall={}", nr.get())),
        None => out.push_str(" syscall=?"),
    }
    match record.seccomp_arch() {
        Some(arch) => out.push_str(&format!(" arch={:x}", arch.get())),
        None => out.push_str(" arch=?"),
    }
    let path = match record.event() {
        AuditEvent::Seccomp { .. } | AuditEvent::ExecTarget { .. } => None,
        AuditEvent::Landlock { path, .. } => Some(path),
        AuditEvent::Mount { path } => path.as_ref(),
        AuditEvent::PluginTrust { path, .. } => Some(path),
    };
    push_path_fields(&mut out, path);
    // plugin 信頼検証と exec 対象のみ末尾に理由を追記する（他レイヤーの本文は従来と同一）。
    if let Some(reason) = record.reason() {
        out.push_str(" reason=");
        out.push_str(reason.as_str());
    }
    if out.len() > AUDIT_MESSAGE_TEXT_MAX {
        return Err(AuditWriteError::new(Kind::LineTooLong));
    }
    Ok(out)
}

/// ACK 1 通の判定結果。
#[derive(Debug, PartialEq, Eq)]
enum AckVerdict {
    /// 自分宛ての ACK ではない（カーネル以外の送信元・seq 不一致）。破棄して再受信する。
    Skip,
    /// 自分宛ての ACK。`error` は `nlmsgerr.error`（0 = 成功、負 = -errno）。
    Ack { error: i32 },
    /// 形式不正（短すぎる・型が `NLMSG_ERROR` でない・長さ矛盾）。
    Malformed,
}

/// 受信データグラムを ACK として解析する。外部入力のため添字は使わず `get()`・`try_into()` だけで読む。
fn parse_ack(data: &[u8], src_nl_pid: u32, expected_seq: u32) -> AckVerdict {
    if src_nl_pid != 0 {
        return AckVerdict::Skip;
    }
    let u32_at = |at: usize| -> Option<u32> {
        let end = at.checked_add(4)?;
        data.get(at..end)?.try_into().ok().map(u32::from_ne_bytes)
    };
    let u16_at = |at: usize| -> Option<u16> {
        let end = at.checked_add(2)?;
        data.get(at..end)?.try_into().ok().map(u16::from_ne_bytes)
    };
    let (Some(len), Some(ty), Some(seq)) = (u32_at(0), u16_at(4), u32_at(8)) else {
        return AckVerdict::Malformed;
    };
    if seq != expected_seq {
        return AckVerdict::Skip;
    }
    // カーネルは元メッセージ全体を ACK に載せて返す（`nlmsg_len` は受信バッファより大きくなりうる）。
    // 先頭 20 バイトしか読まないため、上限は検査せず下限だけ見る（`data` が 20 バイト未満なら下で失敗）。
    let len_ok = usize::try_from(len).is_ok_and(|l| l >= NLMSG_ACK_MIN_LEN);
    if ty != NLMSG_ERROR || !len_ok {
        return AckVerdict::Malformed;
    }
    match u32_at(NLMSG_HDRLEN) {
        Some(raw) => AckVerdict::Ack {
            error: i32::from_ne_bytes(raw.to_ne_bytes()),
        },
        None => AckVerdict::Malformed,
    }
}

/// ACK の `error` を [`Result`] へ写す（0 = 成功。負の errno を kind に分類する）。
fn ack_error_to_result(error: i32) -> Result<(), AuditWriteError> {
    if error == 0 {
        return Ok(());
    }
    // 正の値は ACK として不正。負の値は -errno として分類する。
    let kind = match error.checked_neg() {
        _ if error > 0 => Kind::KernelAuditIo,
        Some(ERRNO_EPERM) => Kind::KernelAuditPermissionDenied,
        Some(ERRNO_ECONNREFUSED) => Kind::KernelAuditUnavailable,
        _ => Kind::KernelAuditRejected,
    };
    Err(AuditWriteError::new(kind))
}

/// netlink 送受信の差し込み点。本番は `sys` のラッパー、テストはモックに差し替える。
pub(crate) trait AuditNetlinkTransport {
    /// フレーム全体を 1 データグラムでカーネルへ送る（未接続なら接続を開く）。
    fn send(&mut self, frame: &[u8]) -> Result<(), Kind>;
    /// 最大 `timeout` 待って 1 データグラムを受信する。`Ok(None)` は時間切れ。`(受信長, 送信元 nl_pid)`。
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<Option<(usize, u32)>, Kind>;
    /// 接続を閉じる（次の `send` で開き直す）。
    fn close(&mut self);
}

/// `sys` のラッパーを使う本番のトランスポート（Linux）。
#[cfg(target_os = "linux")]
#[derive(Default)]
struct SystemTransport {
    fd: Option<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl SystemTransport {
    fn map_socket_error(e: crate::sys::SysError) -> Kind {
        use crate::sys::{EACCES, EAFNOSUPPORT, EPERM, EPROTONOSUPPORT, SysError};
        match e {
            SysError::Unsupported => Kind::Unsupported,
            // audit 非搭載・seccomp 等で netlink を作れない環境は「到達できない」。
            SysError::Os(n) if [EPROTONOSUPPORT, EAFNOSUPPORT, EACCES, EPERM].contains(&n) => {
                Kind::KernelAuditUnavailable
            }
            _ => Kind::KernelAuditIo,
        }
    }
}

#[cfg(target_os = "linux")]
impl AuditNetlinkTransport for SystemTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), Kind> {
        use crate::sys::{self, ECONNREFUSED, SysError};
        use std::os::fd::AsFd as _;
        if self.fd.is_none() {
            self.fd = Some(sys::netlink_audit_socket().map_err(Self::map_socket_error)?);
        }
        let Some(fd) = self.fd.as_ref() else {
            return Err(Kind::KernelAuditIo);
        };
        match sys::netlink_send_to_kernel(fd.as_fd(), frame) {
            Ok(n) if n == frame.len() => Ok(()),
            Ok(_) => Err(Kind::KernelAuditIo),
            Err(SysError::Os(ECONNREFUSED)) => Err(Kind::KernelAuditUnavailable),
            Err(SysError::Unsupported) => Err(Kind::Unsupported),
            Err(_) => Err(Kind::KernelAuditIo),
        }
    }

    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<Option<(usize, u32)>, Kind> {
        use crate::sys::{self, EINTR, SysError};
        use std::os::fd::AsFd as _;
        let Some(fd) = self.fd.as_ref() else {
            return Err(Kind::KernelAuditIo);
        };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // 切り上げ（0 ms で空回りしない）。i32 に収まらない値は上限へ丸める。
            let ms = i32::try_from(remaining.as_millis().saturating_add(1)).unwrap_or(i32::MAX);
            match sys::poll_readable(fd.as_fd(), ms) {
                Ok(true) => match sys::netlink_recv(fd.as_fd(), buf) {
                    Ok(r) => return Ok(Some(r)),
                    Err(SysError::Os(EINTR)) => {}
                    Err(_) => return Err(Kind::KernelAuditIo),
                },
                Ok(false) => return Ok(None),
                Err(SysError::Os(EINTR)) => {}
                Err(_) => return Err(Kind::KernelAuditIo),
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn close(&mut self) {
        self.fd = None;
    }
}

/// 非 Linux ではカーネル監査に到達できない（fail-closed。`Unsupported`）。
#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct UnsupportedTransport;

#[cfg(not(target_os = "linux"))]
impl AuditNetlinkTransport for UnsupportedTransport {
    fn send(&mut self, _frame: &[u8]) -> Result<(), Kind> {
        Err(Kind::Unsupported)
    }

    fn recv(&mut self, _buf: &mut [u8], _timeout: Duration) -> Result<Option<(usize, u32)>, Kind> {
        Err(Kind::Unsupported)
    }

    fn close(&mut self) {}
}

/// カーネル監査サブシステムへのフォールバック（[`AuditFallback`] の本番実装。TASK-41.5.2・#840）。
///
/// `write_with_fallback` に `&mut` で渡す。送信ごとに接続を開閉するため状態は seq 番号だけを持つ。
/// 特権の取得・昇格は行わず、`CAP_AUDIT_WRITE` が無ければ `PermissionDenied` を返すだけ。
pub struct KernelAuditFallback {
    transport: Box<dyn AuditNetlinkTransport>,
    ack_timeout: Duration,
    seq: u32,
}

impl std::fmt::Debug for KernelAuditFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelAuditFallback")
            .field("ack_timeout", &self.ack_timeout)
            .finish_non_exhaustive()
    }
}

impl Default for KernelAuditFallback {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelAuditFallback {
    /// 本番のトランスポート（Linux は NETLINK_AUDIT。他 OS は常に `Unsupported`）で構築する。
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        let transport: Box<dyn AuditNetlinkTransport> = Box::<SystemTransport>::default();
        #[cfg(not(target_os = "linux"))]
        let transport: Box<dyn AuditNetlinkTransport> = Box::<UnsupportedTransport>::default();
        Self::with_transport(transport, KERNEL_AUDIT_ACK_TIMEOUT)
    }

    /// トランスポートと ACK 待ち上限を差し替えて構築する（テスト用の差し込み点）。
    pub(crate) fn with_transport(
        transport: Box<dyn AuditNetlinkTransport>,
        ack_timeout: Duration,
    ) -> Self {
        Self {
            transport,
            ack_timeout,
            seq: 0,
        }
    }

    /// 送信して ACK を待つ。接続の後始末は呼び出し側（`record_fallback`）が行う。
    fn exchange(&mut self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        let payload = encode_payload(record)?;
        self.seq = self.seq.wrapping_add(1);
        let frame = AuditNetlinkFrame::new(self.seq, payload.as_bytes())?;
        self.transport
            .send(frame.as_bytes())
            .map_err(AuditWriteError::new)?;
        let deadline = Instant::now() + self.ack_timeout;
        for _ in 0..MAX_ACK_ATTEMPTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let mut buf = [0u8; ACK_BUF_LEN];
            let received = self
                .transport
                .recv(&mut buf, remaining)
                .map_err(AuditWriteError::new)?;
            let Some((n, src)) = received else {
                break;
            };
            let data = buf.get(..n.min(ACK_BUF_LEN)).unwrap_or_default();
            match parse_ack(data, src, frame.seq) {
                AckVerdict::Skip => {}
                AckVerdict::Ack { error } => return ack_error_to_result(error),
                AckVerdict::Malformed => return Err(AuditWriteError::new(Kind::KernelAuditIo)),
            }
        }
        Err(AuditWriteError::new(Kind::KernelAuditTimeout))
    }
}

impl AuditFallback for KernelAuditFallback {
    fn record_fallback(
        &mut self,
        record: &AuditRecord,
        _primary: &AuditWriteError,
    ) -> Result<(), AuditWriteError> {
        let result = self.exchange(record);
        self.transport.close();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{
        AuditFileWriter, AuditPid, AuditSyscallArch, AuditSyscallNr, AuditTimestamp,
        AuditWriteFailure, AuditWriteOutcome, write_with_fallback,
    };
    use crate::traits::ErrorCode;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    fn rec(event: AuditEvent) -> AuditRecord {
        AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(1234).unwrap(),
            event,
        )
    }

    fn seccomp() -> AuditRecord {
        rec(AuditEvent::Seccomp {
            syscall: AuditSyscallNr::new(272).unwrap(),
            arch: AuditSyscallArch::from_raw(0xC000_003E),
        })
    }

    #[test]
    fn sec4_task41_5_2_frame_bytes_are_exact() {
        let f = AuditNetlinkFrame::new(7, b"abcde").unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(&22u32.to_ne_bytes()); // 16 + 5 + 末尾 NUL（パディングは長さに含めない）
        want.extend_from_slice(&1121u16.to_ne_bytes());
        want.extend_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
        want.extend_from_slice(&7u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(b"abcde\0\0\0");
        assert_eq!(f.as_bytes(), want.as_slice());
        assert_eq!(f.as_bytes().len(), 24);
    }

    #[test]
    fn sec4_task41_5_2_frame_rejects_oversized_payload() {
        let ok = vec![b'a'; AUDIT_MESSAGE_TEXT_MAX];
        assert!(AuditNetlinkFrame::new(1, &ok).is_ok());
        let big = vec![b'a'; AUDIT_MESSAGE_TEXT_MAX + 1];
        assert_eq!(
            AuditNetlinkFrame::new(1, &big).unwrap_err().kind(),
            Kind::LineTooLong
        );
    }

    #[test]
    fn sec4_task41_5_2_payload_seccomp() {
        assert_eq!(
            encode_payload(&seccomp()).unwrap(),
            "op=fandhe-audit layer=seccomp ts=1700000000.000000005 pid=1234 syscall=272 \
             arch=c000003e path=? path_truncated=? path_original_len=?"
        );
    }

    #[test]
    fn sec4_task41_5_2_payload_landlock_hexes_hostile_path() {
        let r = rec(AuditEvent::Landlock {
            path: AuditPath::new("/a b'\n\0"),
            syscall: Some(AuditSyscallNr::new(2).unwrap()),
        });
        assert_eq!(
            encode_payload(&r).unwrap(),
            "op=fandhe-audit layer=landlock ts=1700000000.000000005 pid=1234 syscall=2 \
             arch=? path=2F612062270A00 path_truncated=0 path_original_len=7"
        );
    }

    #[test]
    fn plug11_task122_5_payload_plugin_trust_appends_reason() {
        let r = rec(AuditEvent::PluginTrust {
            path: AuditPath::new("/p"),
            reason: crate::audit_log::AuditReason::new("untrusted_owner"),
        });
        assert_eq!(
            encode_payload(&r).unwrap(),
            "op=fandhe-audit layer=plugin_trust ts=1700000000.000000005 pid=1234 syscall=? arch=? \
             path=2F70 path_truncated=0 path_original_len=2 reason=untrusted_owner"
        );
    }

    #[test]
    fn sec4_sup6_task163_payload_exec_target_without_path() {
        let r = rec(AuditEvent::ExecTarget {
            reason: crate::audit_log::AuditReason::new("exec_target_cgroup_mismatch"),
        });
        assert_eq!(
            encode_payload(&r).unwrap(),
            "op=fandhe-audit layer=exec_target ts=1700000000.000000005 pid=1234 syscall=? arch=? \
             path=? path_truncated=? path_original_len=? reason=exec_target_cgroup_mismatch"
        );
    }

    #[test]
    fn sec4_task41_5_2_payload_mount_without_path() {
        let r = rec(AuditEvent::Mount { path: None });
        assert_eq!(
            encode_payload(&r).unwrap(),
            "op=fandhe-audit layer=mount ts=1700000000.000000005 pid=1234 syscall=? arch=? \
             path=? path_truncated=? path_original_len=?"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sec4_task41_5_2_payload_non_utf8_path_is_raw_hex() {
        use std::os::unix::ffi::OsStrExt as _;
        let p = AuditPath::new(std::ffi::OsStr::from_bytes(b"/x\xff\xfe"));
        let r = rec(AuditEvent::Mount { path: Some(p) });
        assert!(
            encode_payload(&r)
                .unwrap()
                .ends_with("path=2F78FFFE path_truncated=0 path_original_len=4")
        );
    }

    #[test]
    fn sec4_task41_5_2_payload_max_path_fits_in_message_limit() {
        let r = rec(AuditEvent::Mount {
            path: Some(AuditPath::new(&"a".repeat(4096))),
        });
        let text = encode_payload(&r).unwrap();
        assert_eq!(text.len(), PAYLOAD_LEN_FOR_4096_BYTE_PATH);
        assert!(text.len() <= AUDIT_MESSAGE_TEXT_MAX);
        // 上限超過で切り詰められたパスも同じ上限に収まる。
        let long = rec(AuditEvent::Mount {
            path: Some(AuditPath::new(&"a".repeat(10_000))),
        });
        let t = encode_payload(&long).unwrap();
        assert!(t.ends_with("path_truncated=1 path_original_len=10000"));
        assert!(t.len() <= AUDIT_MESSAGE_TEXT_MAX);
    }

    /// 4096 バイトのパス（hex 8192 文字）を含む Mount レコードの本文長。
    const PAYLOAD_LEN_FOR_4096_BYTE_PATH: usize = 8315;

    fn ack_bytes(seq: u32, ty: u16, error: i32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&36u32.to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&0u16.to_ne_bytes());
        v.extend_from_slice(&seq.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&error.to_ne_bytes());
        v.resize(36, 0);
        v
    }

    #[test]
    fn sec4_task41_5_2_parse_ack_variants() {
        assert_eq!(
            parse_ack(&ack_bytes(3, 2, 0), 0, 3),
            AckVerdict::Ack { error: 0 }
        );
        assert_eq!(
            parse_ack(&ack_bytes(3, 2, -1), 0, 3),
            AckVerdict::Ack { error: -1 }
        );
        // 送信元がカーネルでない・seq 不一致は破棄。
        assert_eq!(parse_ack(&ack_bytes(3, 2, 0), 99, 3), AckVerdict::Skip);
        assert_eq!(parse_ack(&ack_bytes(4, 2, 0), 0, 3), AckVerdict::Skip);
        // 実カーネルの ACK は元メッセージ全体を含み `nlmsg_len` が受信バッファ（64）を超える。
        let mut echoed = ack_bytes(3, 2, -1);
        echoed
            .get_mut(..4)
            .unwrap()
            .copy_from_slice(&168u32.to_ne_bytes());
        assert_eq!(parse_ack(&echoed, 0, 3), AckVerdict::Ack { error: -1 });
        // 短すぎる・型不一致・長さ矛盾は形式不正。
        let mut tiny = ack_bytes(3, 2, 0);
        tiny.get_mut(..4)
            .unwrap()
            .copy_from_slice(&19u32.to_ne_bytes());
        assert_eq!(parse_ack(&tiny, 0, 3), AckVerdict::Malformed);
        assert_eq!(parse_ack(&[0u8; 7], 0, 3), AckVerdict::Malformed);
        assert_eq!(parse_ack(&ack_bytes(3, 3, 0), 0, 3), AckVerdict::Malformed);
        let short = ack_bytes(3, 2, 0);
        assert_eq!(
            parse_ack(short.get(..18).unwrap(), 0, 3),
            AckVerdict::Malformed
        );
    }

    #[test]
    fn sec4_task41_5_2_ack_error_mapping() {
        assert_eq!(ack_error_to_result(0), Ok(()));
        let k = |e| ack_error_to_result(e).unwrap_err().kind();
        assert_eq!(k(-1), Kind::KernelAuditPermissionDenied);
        assert_eq!(k(-111), Kind::KernelAuditUnavailable);
        assert_eq!(k(-22), Kind::KernelAuditRejected);
        assert_eq!(k(5), Kind::KernelAuditIo);
    }

    #[test]
    fn sec4_task41_5_2_error_codes_and_tokens() {
        let cases = [
            (
                Kind::KernelAuditUnavailable,
                ErrorCode::Unavailable,
                "kernel_audit_unavailable",
            ),
            (
                Kind::KernelAuditPermissionDenied,
                ErrorCode::PermissionDenied,
                "kernel_audit_permission_denied",
            ),
            (
                Kind::KernelAuditTimeout,
                ErrorCode::Timeout,
                "kernel_audit_timeout",
            ),
            (
                Kind::KernelAuditRejected,
                ErrorCode::Internal,
                "kernel_audit_rejected",
            ),
            (Kind::KernelAuditIo, ErrorCode::Internal, "kernel_audit_io"),
        ];
        for (kind, code, token) in cases {
            let e = AuditWriteError::new(kind);
            assert_eq!(e.error_code(), code);
            assert_eq!(kind.as_str(), token);
            assert!(!e.message().is_empty());
        }
    }

    /// モックが返す 1 回分の受信結果。
    type MockReply = Result<Option<(Vec<u8>, u32)>, Kind>;

    /// モックの共有状態（送信フレーム・受信の台本・close 回数）。
    #[derive(Default)]
    struct MockState {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<MockReply>,
        send_result: Option<Kind>,
        closes: usize,
    }

    struct Mock(Rc<RefCell<MockState>>);

    impl AuditNetlinkTransport for Mock {
        fn send(&mut self, frame: &[u8]) -> Result<(), Kind> {
            let mut s = self.0.borrow_mut();
            s.sent.push(frame.to_vec());
            s.send_result.map_or(Ok(()), Err)
        }
        fn recv(&mut self, buf: &mut [u8], _t: Duration) -> Result<Option<(usize, u32)>, Kind> {
            match self.0.borrow_mut().replies.pop_front() {
                None => Ok(None),
                Some(Err(k)) => Err(k),
                Some(Ok(None)) => Ok(None),
                Some(Ok(Some((data, src)))) => {
                    let n = data.len().min(buf.len());
                    buf.get_mut(..n)
                        .unwrap()
                        .copy_from_slice(data.get(..n).unwrap());
                    Ok(Some((n, src)))
                }
            }
        }
        fn close(&mut self) {
            self.0.borrow_mut().closes += 1;
        }
    }

    fn fallback_with(state: &Rc<RefCell<MockState>>) -> KernelAuditFallback {
        KernelAuditFallback::with_transport(
            Box::new(Mock(Rc::clone(state))),
            Duration::from_millis(200),
        )
    }

    fn primary_err() -> AuditWriteError {
        AuditWriteError::new(Kind::Write)
    }

    #[test]
    fn sec4_task41_5_2_fallback_success_sends_expected_frame() {
        let state = Rc::new(RefCell::new(MockState::default()));
        state
            .borrow_mut()
            .replies
            .push_back(Ok(Some((ack_bytes(1, 2, 0), 0))));
        let mut fb = fallback_with(&state);
        assert_eq!(fb.record_fallback(&seccomp(), &primary_err()), Ok(()));
        let s = state.borrow();
        assert_eq!(s.closes, 1);
        let payload = encode_payload(&seccomp()).unwrap();
        let want = AuditNetlinkFrame::new(1, payload.as_bytes()).unwrap();
        assert_eq!(s.sent, vec![want.as_bytes().to_vec()]);
    }

    #[test]
    fn sec4_task41_5_2_fallback_skips_foreign_acks_then_succeeds() {
        let state = Rc::new(RefCell::new(MockState::default()));
        {
            let mut s = state.borrow_mut();
            s.replies.push_back(Ok(Some((ack_bytes(1, 2, 0), 4242)))); // カーネル以外
            s.replies.push_back(Ok(Some((ack_bytes(9, 2, 0), 0)))); // seq 違い
            s.replies.push_back(Ok(Some((ack_bytes(1, 2, 0), 0))));
        }
        let mut fb = fallback_with(&state);
        assert_eq!(fb.record_fallback(&seccomp(), &primary_err()), Ok(()));
    }

    #[test]
    fn sec4_task41_5_2_fallback_error_paths() {
        let run = |setup: &dyn Fn(&mut MockState)| {
            let state = Rc::new(RefCell::new(MockState::default()));
            setup(&mut state.borrow_mut());
            let mut fb = fallback_with(&state);
            let r = fb.record_fallback(&seccomp(), &primary_err());
            assert_eq!(state.borrow().closes, 1);
            r.unwrap_err().kind()
        };
        let ack = |e: i32| {
            move |s: &mut MockState| s.replies.push_back(Ok(Some((ack_bytes(1, 2, e), 0))))
        };
        assert_eq!(run(&ack(-1)), Kind::KernelAuditPermissionDenied);
        assert_eq!(run(&ack(-111)), Kind::KernelAuditUnavailable);
        assert_eq!(run(&ack(-13)), Kind::KernelAuditRejected);
        // ACK なし（時間切れ）。
        assert_eq!(run(&|_| {}), Kind::KernelAuditTimeout);
        // 他者の ACK だけが続くと上限回数 / 締め切りで時間切れ。
        assert_eq!(
            run(&|s| {
                for _ in 0..20 {
                    s.replies.push_back(Ok(Some((ack_bytes(1, 2, 0), 7))));
                }
            }),
            Kind::KernelAuditTimeout
        );
        // 形式不正。
        assert_eq!(
            run(&|s| s.replies.push_back(Ok(Some((vec![1, 2, 3], 0))))),
            Kind::KernelAuditIo
        );
        // 送信失敗・受信失敗。
        assert_eq!(
            run(&|s| s.send_result = Some(Kind::KernelAuditUnavailable)),
            Kind::KernelAuditUnavailable
        );
        assert_eq!(
            run(&|s| s.replies.push_back(Err(Kind::KernelAuditIo))),
            Kind::KernelAuditIo
        );
    }

    #[test]
    fn sec4_task41_5_2_seq_increments_per_record() {
        let state = Rc::new(RefCell::new(MockState::default()));
        let mut fb = fallback_with(&state);
        for seq in [1u32, 2] {
            state
                .borrow_mut()
                .replies
                .push_back(Ok(Some((ack_bytes(seq, 2, 0), 0))));
            assert_eq!(fb.record_fallback(&seccomp(), &primary_err()), Ok(()));
        }
        assert_eq!(state.borrow().sent.len(), 2);
    }

    fn failing_primary() -> AuditFileWriter {
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        AuditFileWriter::from_file_unchecked(f)
    }

    #[test]
    fn sec4_task41_5_2_primary_failure_uses_kernel_fallback() {
        let state = Rc::new(RefCell::new(MockState::default()));
        state
            .borrow_mut()
            .replies
            .push_back(Ok(Some((ack_bytes(1, 2, 0), 0))));
        let mut fb = fallback_with(&state);
        let out = write_with_fallback(&mut failing_primary(), &mut fb, &seccomp()).unwrap();
        assert_eq!(
            out,
            AuditWriteOutcome::Fallback {
                primary_error: AuditWriteError::new(Kind::Write)
            }
        );
    }

    #[test]
    fn sec4_task41_5_2_both_paths_fail_structured_line() {
        let state = Rc::new(RefCell::new(MockState::default()));
        state.borrow_mut().send_result = Some(Kind::KernelAuditUnavailable);
        let mut fb = fallback_with(&state);
        let failure: AuditWriteFailure =
            write_with_fallback(&mut failing_primary(), &mut fb, &seccomp()).unwrap_err();
        assert_eq!(failure.error_code(), ErrorCode::Internal);
        assert_eq!(failure.primary().kind(), Kind::Write);
        assert_eq!(failure.fallback().kind(), Kind::KernelAuditUnavailable);
        let mut out = Vec::new();
        failure.write_json_line(&mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"write\",\
             \"primary_code\":\"INTERNAL\",\"fallback\":\"kernel_audit_unavailable\",\
             \"fallback_code\":\"UNAVAILABLE\"}\n"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec4_task41_5_2_non_linux_is_unsupported() {
        let mut fb = KernelAuditFallback::new();
        let e = fb.record_fallback(&seccomp(), &primary_err()).unwrap_err();
        assert_eq!(e.kind(), Kind::Unsupported);
        assert_eq!(e.error_code(), ErrorCode::Unimplemented);
    }
}
