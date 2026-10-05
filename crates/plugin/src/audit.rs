//! peer 認証で拒否した接続の監査イベント（PLUG-12・SEC-4・TASK-124.5・#1388・MS-3）。
//!
//! `transport` の UDS accept / connect が peer credential（Linux は `SO_PEERCRED`、macOS は
//! `getpeereid`）の照合で接続を拒否したとき、拒否 1 件につき [`PeerAuthRejection`] を 1 件、
//! [`PeerAuthObserver`] へ同期通知する。呼び出し側へ返すエラー（UID 値を含まない固定文言）は変えず、
//! 運用者向けの詳細（拒否理由・期待 UID・観測 peer UID・socket パス）はこのイベントにのみ載せる。
//!
//! # 方式（`crates/io` の `ServerObserver` / `JsonLinesServerObserver` に揃える。A4）
//! 観測フック trait・`#[non_exhaustive]` イベント・有界メモリの JSON Lines バッファ（あふれは集約）・
//! `drain_lines` を `fandhe-container-io` と同じ語彙で再現する。io crate への依存や共有 crate は
//! 作らない（依存・crate 境界の変更になるため。共有型が必要になった場合は設計判断として別途扱う）。
//!
//! # 契約
//! - 通知は拒否判定の後に行い、戻り値を持たないため判定・返却エラーに影響しない（fail-closed 維持）。
//! - 拒否した stream は通知より前に drop 済み（通知が遅くても拒否済み接続を保持しない）。
//! - フックはブロックする I/O をしない（REPAIR-5）。イベントを黙って捨てない（SEC-4）。
//!
//! # 未実装（REPAIR-3）
//! [`JsonLinesPeerAuthObserver`] は一時的なメモリバッファで、永続的な SEC-4 監査ログではない。
//! core 側 proxy（TASK-114）が `crates/core` の監査ログへ配線する責務で、本 crate では未実装。
//! 観測フックを渡さない `UdsListener::accept` / `UdsStream::connect` は、専用の書き込みスレッドへ
//! 有界キューで渡して stderr へ JSON Lines を出す（下記「既定出力の契約」）。
//!
//! # 既定出力の契約（REPAIR-5・SEC-4）
//! 既定の `StderrPeerAuthObserver` は呼び出し側スレッドで stderr に書かず、有界キュー（
//! [`DEFAULT_AUDIT_QUEUE_CAPACITY`] 件）へ `try_send` するだけなので、stderr の読み手が停滞しても
//! accept / connect は待たされない（ブロックしない）。
//! - キューが満杯・書き込みスレッドを起動できない場合は、捨てずに件数を数え、次に書き込みに成功した
//!   時点で集約行（`peer_auth_rejections_coalesced`）として出す。
//! - stderr への書き込みが失敗した場合（閉じている・書けない）は失われた件数を
//!   [`default_audit_write_failures`] へ数え、黙って消えない（呼び出し側が監視できる）。
//! - 書き込みスレッドの出力は非同期のため、直後にプロセスが終了すると未出力の行は失われ得る。
//!   確実に回収したい運用では、呼び出し側が [`JsonLinesPeerAuthObserver`] 等を渡す。

use crate::error::PluginErrorCode;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, OnceLock};

/// 監査枠の最大行数（`crates/io` の監査枠と同値）。
pub const PEER_AUTH_AUDIT_LOG_CAPACITY: usize = 256;
/// 監査枠の最大バイト数（`crates/io` の監査枠と同値）。
pub const MAX_PEER_AUTH_AUDIT_LOG_BUFFER_BYTES: usize = 128 * 1024;

/// 既定出力の書き込みキューの最大件数。
pub const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 256;

/// 既定出力の有界・非ブロッキング sink（専用スレッドが `Write` へ書く）。
struct AuditSink {
    tx: Option<SyncSender<String>>,
    /// キュー満杯・スレッド不在で未出力の件数（次の書き込み成功時に集約行へ）。
    pending_dropped: Arc<AtomicU64>,
    /// 書き込み失敗で失われた件数の累計。
    write_failures: Arc<AtomicU64>,
}

impl AuditSink {
    fn spawn<W: Write + Send + 'static>(mut out: W, capacity: usize) -> Self {
        let pending_dropped = Arc::new(AtomicU64::new(0));
        let write_failures = Arc::new(AtomicU64::new(0));
        let (tx, rx) = sync_channel::<String>(capacity);
        let (pd, wf) = (Arc::clone(&pending_dropped), Arc::clone(&write_failures));
        let spawned = std::thread::Builder::new()
            .name("peer-auth-audit".into())
            .spawn(move || {
                for line in rx {
                    let dropped = pd.swap(0, Ordering::AcqRel);
                    if dropped > 0 {
                        let agg = format!(
                            "{{\"event\":\"plugin_peer_auth\",\"outcome\":\"error\",\"reason\":\"peer_auth_rejections_coalesced\",\"count\":{dropped}}}"
                        );
                        if writeln!(out, "{agg}").is_err() {
                            wf.fetch_add(dropped, Ordering::AcqRel);
                        }
                    }
                    if writeln!(out, "{line}")
                        .and_then(|()| out.flush())
                        .is_err()
                    {
                        wf.fetch_add(1, Ordering::AcqRel);
                    }
                }
            });
        Self {
            tx: spawned.ok().map(|_| tx),
            pending_dropped,
            write_failures,
        }
    }

    /// ブロックせずキューへ積む。積めなければ件数に合算する（捨てたことを黙らせない）。
    fn submit(&self, line: String) {
        let sent = match &self.tx {
            Some(tx) => !matches!(
                tx.try_send(line),
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_))
            ),
            None => false,
        };
        if !sent {
            self.pending_dropped.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn default_sink() -> &'static AuditSink {
    static SINK: OnceLock<AuditSink> = OnceLock::new();
    SINK.get_or_init(|| AuditSink::spawn(std::io::stderr(), DEFAULT_AUDIT_QUEUE_CAPACITY))
}

/// 既定出力で stderr への書き込みに失敗し、失われた拒否イベントの累計件数（SEC-4）。
pub fn default_audit_write_failures() -> u64 {
    default_sink().write_failures.load(Ordering::Acquire)
}

/// 拒否が起きた側（accept = core の listener、connect = plugin の client）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthOp {
    /// `UdsListener::accept` / `accept_peer_pid`。
    Accept,
    /// `UdsStream::connect`。
    Connect,
}

impl PeerAuthOp {
    /// JSON の `op` 値。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Connect => "connect",
        }
    }
}

/// 拒否理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthRejectReason {
    /// peer の実効 UID が期待 UID と不一致。
    UidMismatch,
    /// peer の UID を取得できなかった（fail-closed）。
    PeerUidUnavailable,
    /// peer の pid が期待 pid と不一致（都度起動モードの子限定。PLUG-7）。
    PidMismatch,
    /// peer の pid を取得できなかった（fail-closed）。
    PeerPidUnavailable,
}

impl PeerAuthRejectReason {
    /// JSON の `reason` 値。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UidMismatch => "peer_uid_mismatch",
            Self::PeerUidUnavailable => "peer_uid_unavailable",
            Self::PidMismatch => "peer_pid_mismatch",
            Self::PeerPidUnavailable => "peer_pid_unavailable",
        }
    }
}

/// 拒否 1 件の監査イベント。借用は通知中のみ有効。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerAuthRejection<'a> {
    /// 拒否した側。
    pub op: PeerAuthOp,
    /// 拒否理由。
    pub reason: PeerAuthRejectReason,
    /// 呼び出し側へ返したエラーのコード。
    pub code: PluginErrorCode,
    /// 期待した UID（accept は listener の euid、connect は自 euid）。
    pub expected_uid: u32,
    /// 観測した peer UID。取得できた場合のみ。
    pub peer_uid: Option<u32>,
    /// 期待した pid（pid 系の理由のときのみ）。
    pub expected_pid: Option<u32>,
    /// 観測した peer pid（pid 系の理由で取得できた場合のみ）。
    pub peer_pid: Option<u32>,
    /// 対象 socket のパス。
    pub socket_path: &'a Path,
}

#[derive(Serialize)]
struct EventLine<'a> {
    event: &'static str,
    op: &'static str,
    outcome: &'static str,
    reason: &'static str,
    code: &'static str,
    expected_uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_pid: Option<u32>,
    socket_path: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    socket_path_lossy: bool,
}

impl PeerAuthRejection<'_> {
    /// 1 行の JSON（改行を含まない）へ符号化する。キー順は固定。
    ///
    /// socket パスは untrusted（connect はパスを呼び出し側が指定する）なため serde_json で
    /// エスケープし、1 行 1 イベントを保つ。非 UTF-8 は置換し `socket_path_lossy` を付ける。
    pub fn to_json_line(&self) -> String {
        let lossy_path = self.socket_path.to_string_lossy();
        let lossy = self.socket_path.to_str().is_none();
        let line = EventLine {
            event: "plugin_peer_auth",
            op: self.op.as_str(),
            outcome: "error",
            reason: self.reason.as_str(),
            code: self.code.as_str(),
            expected_uid: self.expected_uid,
            peer_uid: self.peer_uid,
            expected_pid: self.expected_pid,
            peer_pid: self.peer_pid,
            socket_path: &lossy_path,
            socket_path_lossy: lossy,
        };
        // 文字列・数値のみの struct は符号化に失敗しない。万一でも固定の代替行で 1 行を保つ。
        serde_json::to_string(&line).unwrap_or_else(|_| {
            String::from(
                "{\"event\":\"plugin_peer_auth\",\"outcome\":\"error\",\"reason\":\"encode_failed\"}",
            )
        })
    }
}

/// 拒否イベントの受け手（io の `ServerObserver` 相当）。
///
/// 契約: ブロックする I/O をしない（REPAIR-5）。イベントを黙って捨てない（SEC-4）。戻り値が無く、
/// 拒否の判定や呼び出し側へ返すエラーには影響しない。
pub trait PeerAuthObserver: Send {
    /// 拒否 1 件ごとに同期的に呼ばれる。
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>);
}

/// 観測しない場合に呼び出し元が明示的に渡す受け手。暗黙の既定にはならない。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPeerAuthObserver;

impl PeerAuthObserver for NoopPeerAuthObserver {
    fn on_rejection(&mut self, _event: &PeerAuthRejection<'_>) {}
}

/// 観測フックを渡さない公開入口（`accept` / `connect`）の既定: stderr へ JSON Lines を 1 行出す。
/// 呼び出し側ではブロックしない（有界キュー経由）。契約はモジュール doc を参照。
#[derive(Debug, Default)]
pub(crate) struct StderrPeerAuthObserver;

impl PeerAuthObserver for StderrPeerAuthObserver {
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>) {
        default_sink().submit(event.to_json_line());
    }
}

/// 有界メモリへ JSON Lines を積む受け手（io の `JsonLinesServerObserver` 相当）。
///
/// 上限は [`PEER_AUTH_AUDIT_LOG_CAPACITY`] 行・[`MAX_PEER_AUTH_AUDIT_LOG_BUFFER_BYTES`] バイト。満杯後の
/// 拒否は捨てず集約レコード（件数・最後の `peer_uid`）へ合算し、[`Self::drain_lines`] の末尾に
/// 集約行 1 行として返す。永続的な SEC-4 監査ログではない（モジュール doc の未実装を参照。REPAIR-3）。
#[derive(Debug, Default)]
pub struct JsonLinesPeerAuthObserver {
    lines: Vec<String>,
    bytes: usize,
    coalesced: u64,
    last_peer_uid: Option<u32>,
}

impl JsonLinesPeerAuthObserver {
    /// 空のバッファを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 積まれている通常行の数（集約分を含まない）。
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// 通常行も集約も無ければ true。
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.coalesced == 0
    }

    /// あふれて集約した拒否の件数。
    pub fn coalesced_rejections(&self) -> u64 {
        self.coalesced
    }

    /// 積まれた行を届いた順に取り出す。集約があれば末尾に集約行を 1 行足し、バッファを空にする。
    pub fn drain_lines(&mut self) -> Vec<String> {
        #[derive(Serialize)]
        struct Coalesced {
            event: &'static str,
            outcome: &'static str,
            reason: &'static str,
            count: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            last_peer_uid: Option<u32>,
        }
        let mut out = std::mem::take(&mut self.lines);
        self.bytes = 0;
        if self.coalesced > 0 {
            let line = Coalesced {
                event: "plugin_peer_auth",
                outcome: "error",
                reason: "peer_auth_rejections_coalesced",
                count: self.coalesced,
                last_peer_uid: self.last_peer_uid,
            };
            out.push(serde_json::to_string(&line).unwrap_or_default());
            self.coalesced = 0;
            self.last_peer_uid = None;
        }
        out
    }
}

impl PeerAuthObserver for JsonLinesPeerAuthObserver {
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>) {
        let line = event.to_json_line();
        let fits = self.lines.len() < PEER_AUTH_AUDIT_LOG_CAPACITY
            && self.bytes.saturating_add(line.len()) <= MAX_PEER_AUTH_AUDIT_LOG_BUFFER_BYTES;
        if fits {
            self.bytes += line.len();
            self.lines.push(line);
        } else {
            self.coalesced = self.coalesced.saturating_add(1);
            self.last_peer_uid = event.peer_uid;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(
        reason: PeerAuthRejectReason,
        peer_uid: Option<u32>,
        p: &'a Path,
    ) -> PeerAuthRejection<'a> {
        PeerAuthRejection {
            op: PeerAuthOp::Accept,
            reason,
            code: PluginErrorCode::PermissionDenied,
            expected_uid: 1001,
            peer_uid,
            expected_pid: None,
            peer_pid: None,
            socket_path: p,
        }
    }

    /// PLUG-12・SEC-4: UID 不一致の行は完全一致で固定する。
    #[test]
    fn plug12_sec4_uid_mismatch_line_is_exact() {
        let p = Path::new("/run/user/1000/fandhe-container/a.sock");
        let line = ev(PeerAuthRejectReason::UidMismatch, Some(1000), p).to_json_line();
        assert_eq!(
            line,
            "{\"event\":\"plugin_peer_auth\",\"op\":\"accept\",\"outcome\":\"error\",\"reason\":\"peer_uid_mismatch\",\"code\":\"PERMISSION_DENIED\",\"expected_uid\":1001,\"peer_uid\":1000,\"socket_path\":\"/run/user/1000/fandhe-container/a.sock\"}"
        );
    }

    /// PLUG-12・SEC-4: 取得失敗の行には peer_uid キーが無い。
    #[test]
    fn plug12_sec4_unavailable_line_has_no_peer_uid() {
        let p = Path::new("/x.sock");
        let line = ev(PeerAuthRejectReason::PeerUidUnavailable, None, p).to_json_line();
        assert!(!line.contains("\"peer_uid\""), "{line}");
        assert!(
            line.contains("\"reason\":\"peer_uid_unavailable\""),
            "{line}"
        );
    }

    /// PLUG-12・SEC-4: pid 不一致の行は expected_pid / peer_pid を持つ。
    #[test]
    fn plug12_sec4_pid_mismatch_line_has_pids() {
        let p = Path::new("/x.sock");
        let mut e = ev(PeerAuthRejectReason::PidMismatch, Some(1001), p);
        e.expected_pid = Some(42);
        e.peer_pid = Some(7);
        let line = e.to_json_line();
        assert!(
            line.contains("\"expected_pid\":42,\"peer_pid\":7"),
            "{line}"
        );
    }

    /// SEC-4: 引用符・改行・制御文字を含むパスでも 1 行の妥当な JSON で往復する。
    #[test]
    fn plug12_sec4_hostile_socket_path_stays_single_line() {
        let raw = "/tmp/a\"b\\c\nd\u{1}e.sock";
        let line = ev(PeerAuthRejectReason::UidMismatch, Some(1), Path::new(raw)).to_json_line();
        assert!(!line.contains('\n') && !line.contains('\r'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["socket_path"], raw);
    }

    /// SEC-4: 非 UTF-8 パスは置換され socket_path_lossy が付く。
    #[cfg(unix)]
    #[test]
    fn plug12_sec4_non_utf8_path_sets_lossy_flag() {
        use std::os::unix::ffi::OsStrExt;
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff.sock"));
        let line = ev(PeerAuthRejectReason::UidMismatch, Some(1), &p).to_json_line();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["socket_path_lossy"], true);
    }

    struct Blocked(std::sync::mpsc::Receiver<()>);
    impl Write for Blocked {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// REPAIR-5: 出力先が停滞しても submit は待たず、あふれた分は件数に合算される。
    #[test]
    fn repair5_stalled_writer_does_not_block_submit() {
        let (_gate, rx) = std::sync::mpsc::channel::<()>();
        let sink = AuditSink::spawn(Blocked(rx), 2);
        let start = std::time::Instant::now();
        for i in 0..50 {
            sink.submit(format!("line{i}"));
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        // 書き込みスレッドが 1 件を保持し、キュー 2 件を除いた残りが集約対象になる。
        assert!(sink.pending_dropped.load(Ordering::Acquire) >= 40);
    }

    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// SEC-4: 書き込み失敗は黙って消えず失敗件数に計上される。
    #[test]
    fn sec4_write_failure_is_counted() {
        let sink = AuditSink::spawn(Failing, 8);
        sink.submit("a".into());
        sink.submit("b".into());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while sink.write_failures.load(Ordering::Acquire) < 2 {
            assert!(std::time::Instant::now() < deadline, "failures not counted");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(sink.write_failures.load(Ordering::Acquire), 2);
    }

    /// SEC-4: 容量超過は捨てず集約行 1 行（count = 超過件数）になる。
    #[test]
    fn plug12_sec4_overflow_coalesces_into_one_line() {
        let p = Path::new("/x.sock");
        let mut o = JsonLinesPeerAuthObserver::new();
        for _ in 0..(PEER_AUTH_AUDIT_LOG_CAPACITY + 5) {
            o.on_rejection(&ev(PeerAuthRejectReason::UidMismatch, Some(9), p));
        }
        assert_eq!(o.len(), PEER_AUTH_AUDIT_LOG_CAPACITY);
        assert_eq!(o.coalesced_rejections(), 5);
        let lines = o.drain_lines();
        assert_eq!(lines.len(), PEER_AUTH_AUDIT_LOG_CAPACITY + 1);
        assert_eq!(
            lines.last().unwrap(),
            "{\"event\":\"plugin_peer_auth\",\"outcome\":\"error\",\"reason\":\"peer_auth_rejections_coalesced\",\"count\":5,\"last_peer_uid\":9}"
        );
        assert!(o.is_empty());
    }
}
