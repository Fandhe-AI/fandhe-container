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
//! - キューが満杯の場合は、捨てずに件数を数え、書き込みスレッドが定期的（次の行の到着を待たない）に
//!   集約行（`peer_auth_rejections_coalesced`）として出す。出力待ちの件数は
//!   [`default_audit_pending_dropped`] で観測できる。この件数は集約行の書き込み中も残し、書き込みの
//!   完了（または失敗の計上）後に初めて減らす（書き込み途中を「出力済み」と数えない）。
//! - 書き込みスレッドを起動できなかった場合・停止した場合（受信側 Disconnected・スレッドの異常終了）は
//!   出力経路が無いため、拒否件数・未出力の集約件数・キュー残存分を直接
//!   [`default_audit_write_failures`] へ計上する。
//! - 件数の移し替えは「移し先へ足してから移し元を減らす」順に行う（移し替え中の区間は回収中として数える）。
//!   [`flush_default_audit`] が true を返すのは、すべての拒否が出力済みか失敗計上済みになった後に限る。
//! - stderr への書き込みが失敗した場合（閉じている・書けない）は失われた件数を
//!   [`default_audit_write_failures`] へ数え、黙って消えない（呼び出し側が監視できる）。
//! - 拒否の通知ごとに、出力完了を最大 50ms（有界）待ってから戻る。通常は即時に完了するため、
//!   拒否直後にプロセスが終了しても行は失われない。stderr が停滞している場合は待機が期限で
//!   打ち切られ、未出力分は書き込みスレッドが後続で出力する（終了直前に確実に回収したい運用は
//!   [`flush_default_audit`] を呼ぶか、[`JsonLinesPeerAuthObserver`] 等を渡す）。

use crate::error::PluginErrorCode;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, OnceLock};

/// 監査枠の最大行数（`crates/io` の監査枠と同値）。
pub const PEER_AUTH_AUDIT_LOG_CAPACITY: usize = 256;
/// 監査枠の最大バイト数（`crates/io` の監査枠と同値）。
pub const MAX_PEER_AUTH_AUDIT_LOG_BUFFER_BYTES: usize = 128 * 1024;

/// 既定出力の書き込みキューの最大件数。
pub const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 256;

/// 既定 observer が拒否ごとに出力完了を待つ上限（REPAIR-5。停滞時もこの時間で戻る）。
const DEFAULT_AUDIT_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

/// 書き込みスレッドが未出力の集約件数を定期的に回収する間隔（次の行の到着に依存しない）。
const AGGREGATE_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// 未出力の集約件数があれば集約行として書く。書けなければ件数を失敗累計へ移す（SEC-4）。
///
/// 書き込みスレッドだけが呼ぶ。`pending` は書き込みの完了（または失敗の計上）後に、書いた件数だけ
/// 減らす。先に 0 へ戻すと、集約行がまだ出力されていない間に `AuditSink::flush` が「未出力 0 件」と
/// 判定してしまう（終了直前の flush 後にプロセスが終了すると拒否記録が失われる）。書き込み中に
/// `submit` が足した件数は減算後も残り、次回の集約行になる。
fn emit_aggregate<W: Write>(out: &mut W, pending: &AtomicU64, failures: &AtomicU64) {
    let dropped = pending.load(Ordering::Acquire);
    if dropped == 0 {
        return;
    }
    let agg = format!(
        "{{\"event\":\"plugin_peer_auth\",\"outcome\":\"error\",\"reason\":\"peer_auth_rejections_coalesced\",\"count\":{dropped}}}"
    );
    if writeln!(out, "{agg}").and_then(|()| out.flush()).is_err() {
        failures.fetch_add(dropped, Ordering::AcqRel);
    }
    saturating_sub(pending, dropped);
}

/// 既定出力の有界・非ブロッキング sink（専用スレッドが `Write` へ書く）。
struct AuditSink {
    tx: Option<SyncSender<String>>,
    /// キュー満杯・スレッド不在で未出力の件数（次の書き込み成功時に集約行へ）。
    pending_dropped: Arc<AtomicU64>,
    /// 書き込み失敗で失われた件数の累計。
    write_failures: Arc<AtomicU64>,
    /// キューに積まれ、書き込みスレッドが出力を終えていない件数（スレッド停止時に失敗として回収し、
    /// `flush` が出力完了の判定に使う）。
    queued: Arc<AtomicU64>,
    /// `queued`・`pending_dropped` を失敗累計へ移し替えている最中の回収処理の数。移し元を 0 へ戻して
    /// から失敗累計へ足すまでの区間を `flush` が「完了」と誤認しないために数える。
    reclaiming: Arc<AtomicU64>,
}

/// 0 未満にならないよう `n` 減らす（停止時の回収で 0 へ戻された後の減算に備える）。
fn saturating_sub(counter: &AtomicU64, n: u64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
        Some(v.saturating_sub(n))
    });
}

/// 出力する主体が居なくなった件数（キュー残存分・未出力の集約件数）を失敗累計へ移す（SEC-4）。
///
/// 書き込みスレッドの停止後に `submit`（受信側 Disconnected）とスレッド終了時の後始末から呼ばれる。
/// 各カウンタは `swap(0)` で取り出すため、並行して呼ばれても同じ件数を二重には計上しない。
fn reclaim_lost(
    queued: &AtomicU64,
    pending: &AtomicU64,
    failures: &AtomicU64,
    reclaiming: &AtomicU64,
) {
    reclaiming.fetch_add(1, Ordering::AcqRel);
    let lost = queued
        .swap(0, Ordering::AcqRel)
        .saturating_add(pending.swap(0, Ordering::AcqRel));
    failures.fetch_add(lost, Ordering::AcqRel);
    saturating_sub(reclaiming, 1);
}

/// 書き込みスレッドの終了時（出力先の `Write` の panic による異常終了を含む）に、出力されずに残った
/// 件数を失敗累計へ移す後始末。後続の `submit` が無くても件数が失われない（SEC-4）。
struct ReclaimOnExit {
    queued: Arc<AtomicU64>,
    pending: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
    reclaiming: Arc<AtomicU64>,
}

impl Drop for ReclaimOnExit {
    fn drop(&mut self) {
        reclaim_lost(
            &self.queued,
            &self.pending,
            &self.failures,
            &self.reclaiming,
        );
    }
}

impl AuditSink {
    fn spawn<W: Write + Send + 'static>(mut out: W, capacity: usize) -> Self {
        let pending_dropped = Arc::new(AtomicU64::new(0));
        let write_failures = Arc::new(AtomicU64::new(0));
        let (tx, rx) = sync_channel::<String>(capacity);
        let queued = Arc::new(AtomicU64::new(0));
        let reclaiming = Arc::new(AtomicU64::new(0));
        let (pd, wf, qd) = (
            Arc::clone(&pending_dropped),
            Arc::clone(&write_failures),
            Arc::clone(&queued),
        );
        let on_exit = ReclaimOnExit {
            queued: Arc::clone(&queued),
            pending: Arc::clone(&pending_dropped),
            failures: Arc::clone(&write_failures),
            reclaiming: Arc::clone(&reclaiming),
        };
        let spawned = std::thread::Builder::new()
            .name("peer-auth-audit".into())
            .spawn(move || {
                // 宣言の逆順に drop されるため、受信側（`rx`）を閉じた後に後始末が走る。閉じる前に
                // 積めた行は `queued` に数えられており、閉じた後の `submit` は Disconnected として
                // 自分で回収するので、どちらの順でも件数は失敗累計へ移る。
                let _on_exit = on_exit;
                let rx = rx;
                loop {
                    match rx.recv_timeout(AGGREGATE_FLUSH_INTERVAL) {
                        Ok(line) => {
                            emit_aggregate(&mut out, &pd, &wf);
                            if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
                                wf.fetch_add(1, Ordering::AcqRel);
                            }
                            // 書き込み完了後に減らす（`flush` が「未出力 0 件」を判定できるように）。
                            saturating_sub(&qd, 1);
                        }
                        // 次の行を待たずに未出力の集約件数を回収する（SEC-4。送信側が
                        // あふれ後に拒否を受けなくても件数が出力される）。
                        Err(RecvTimeoutError::Timeout) => emit_aggregate(&mut out, &pd, &wf),
                        Err(RecvTimeoutError::Disconnected) => {
                            emit_aggregate(&mut out, &pd, &wf);
                            break;
                        }
                    }
                }
            });
        Self {
            tx: spawned.ok().map(|_| tx),
            pending_dropped,
            write_failures,
            queued,
            reclaiming,
        }
    }

    /// 出力も失敗計上も済んでいない件数が無ければ true。
    ///
    /// 読む順序は件数の移し替えの順序と対にしている（順序を変えると移し替え中の件数を見落とす）:
    /// - `submit` の満杯時は `pending_dropped` へ足してから `queued` を減らすので、`queued` を先に読む。
    /// - 回収（`reclaim_lost`）は `reclaiming` を足してから `queued`・`pending_dropped` を 0 へ戻すので、
    ///   `reclaiming` を最後に読む。
    fn is_settled(&self) -> bool {
        self.queued.load(Ordering::Acquire) == 0
            && self.pending_dropped.load(Ordering::Acquire) == 0
            && self.reclaiming.load(Ordering::Acquire) == 0
    }

    /// 積まれた行と集約件数が出力されるまで、最大 `timeout` だけ待つ（SEC-4・REPAIR-5）。
    /// 出力が済んだ（または出力経路が無く失敗計上済みの）場合は true、期限切れは false。
    /// 集約行・通常行の書き込み中は未完了として扱う（書き込みの完了か失敗の計上を待つ）。
    fn flush(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // スレッド不在のときは `submit` が同期的に失敗累計へ計上済み。
            if self.tx.is_none() || self.is_settled() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// ブロックせずキューへ積む。積めなければ件数に合算する（捨てたことを黙らせない）。
    ///
    /// - `Full`: 書き込みスレッドが生きているので `pending_dropped` へ積み、集約行で出す。
    /// - `Disconnected` / スレッド不在: 集約行を出す主体が居ないため、この 1 件に加えて
    ///   未出力の集約件数・キュー残存分も `write_failures` へ直接計上する（SEC-4）。
    fn submit(&self, line: String) {
        let Some(tx) = &self.tx else {
            self.write_failures.fetch_add(1, Ordering::AcqRel);
            return;
        };
        // 送信前に積む（受信側の減算が先行して 0 未満にならないように）。
        self.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // 集約側へ足してから減らす（逆順だと、この 1 件がどちらにも数えられていない瞬間に
                // 並行する `flush` が「未出力 0 件」と判定し得る）。
                self.pending_dropped.fetch_add(1, Ordering::AcqRel);
                saturating_sub(&self.queued, 1);
            }
            Err(TrySendError::Disconnected(_)) => {
                // queued には今回の 1 件も含まれる。
                reclaim_lost(
                    &self.queued,
                    &self.pending_dropped,
                    &self.write_failures,
                    &self.reclaiming,
                );
            }
        }
    }
}

fn default_sink() -> &'static AuditSink {
    static SINK: OnceLock<AuditSink> = OnceLock::new();
    SINK.get_or_init(|| AuditSink::spawn(std::io::stderr(), DEFAULT_AUDIT_QUEUE_CAPACITY))
}

/// 既定出力の未出力イベントを最大 `timeout` だけ待って回収する（SEC-4・REPAIR-5）。
///
/// プロセス終了直前（都度起動モードの終了経路等）に呼ぶと、非同期の書き込みスレッドに積まれた
/// 拒否イベントが失われない。期限内に出力できれば true、期限切れは false（有界。無限には待たない）。
pub fn flush_default_audit(timeout: std::time::Duration) -> bool {
    default_sink().flush(timeout)
}

/// 既定出力で stderr への書き込みに失敗し、失われた拒否イベントの累計件数（SEC-4）。
pub fn default_audit_write_failures() -> u64 {
    default_sink().write_failures.load(Ordering::Acquire)
}

/// 既定出力でキューあふれのため未出力のまま保留中の拒否件数（SEC-4）。
/// 書き込みスレッドが定期回収して集約行にするまでの観測用で、stderr 停滞中は増え続ける。
pub fn default_audit_pending_dropped() -> u64 {
    default_sink().pending_dropped.load(Ordering::Acquire)
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
        let sink = default_sink();
        sink.submit(event.to_json_line());
        // 拒否の直後にプロセスが終了しても行が失われないよう、有界で出力完了を待つ（SEC-4）。
        // 拒否は稀な経路で、通常は即時に完了する。stderr 停滞時も最大 DEFAULT_AUDIT_FLUSH_TIMEOUT で戻る。
        let _ = sink.flush(DEFAULT_AUDIT_FLUSH_TIMEOUT);
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

    struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// SEC-4: あふれ件数は後続の拒否が無くても定期回収で集約行として出力される。
    #[test]
    fn sec4_pending_dropped_is_emitted_without_next_line() {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = AuditSink::spawn(Shared(Arc::clone(&buf)), 1);
        sink.submit("first".into());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !String::from_utf8_lossy(&buf.lock().unwrap()).contains("first") {
            assert!(std::time::Instant::now() < deadline, "line not written");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // 書き込みスレッドが受信待ちの状態でのあふれ記録（後続の行は来ない）。
        sink.pending_dropped.fetch_add(3, Ordering::AcqRel);
        while !String::from_utf8_lossy(&buf.lock().unwrap()).contains("\"count\":3") {
            assert!(
                std::time::Instant::now() < deadline,
                "aggregate not emitted"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(sink.pending_dropped.load(Ordering::Acquire), 0);
    }

    /// SEC-4: flush は出力完了まで待ち、完了後は行が書かれている。停滞時は期限で false を返す。
    #[test]
    fn sec4_flush_waits_for_written_line_and_is_bounded() {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = AuditSink::spawn(Shared(Arc::clone(&buf)), 4);
        sink.submit("last".into());
        assert!(sink.flush(std::time::Duration::from_secs(5)));
        assert_eq!(String::from_utf8_lossy(&buf.lock().unwrap()), "last\n");

        let (_gate, rx) = std::sync::mpsc::channel::<()>();
        let stalled = AuditSink::spawn(Blocked(rx), 4);
        stalled.submit("x".into());
        let start = std::time::Instant::now();
        assert!(!stalled.flush(std::time::Duration::from_millis(30)));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    /// SEC-4: 書き込みスレッド不在のときは件数が失敗累計へ計上される。
    #[test]
    fn sec4_spawn_failure_counts_as_write_failure() {
        let sink = AuditSink {
            tx: None,
            pending_dropped: Arc::new(AtomicU64::new(0)),
            write_failures: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicU64::new(0)),
            reclaiming: Arc::new(AtomicU64::new(0)),
        };
        sink.submit("x".into());
        sink.submit("y".into());
        assert_eq!(sink.write_failures.load(Ordering::Acquire), 2);
        assert_eq!(sink.pending_dropped.load(Ordering::Acquire), 0);
    }

    /// SEC-4: 受信側停止（Disconnected）後の拒否は、今回分・未出力の集約件数・キュー残存分を
    /// すべて失敗累計へ計上する。
    #[test]
    fn sec4_disconnected_receiver_counts_all_as_write_failures() {
        let (tx, rx) = sync_channel::<String>(4);
        let sink = AuditSink {
            tx: Some(tx),
            pending_dropped: Arc::new(AtomicU64::new(3)),
            write_failures: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicU64::new(0)),
            reclaiming: Arc::new(AtomicU64::new(0)),
        };
        sink.submit("a".into());
        sink.submit("b".into());
        drop(rx);
        sink.submit("c".into());
        // 残存 2 件 + 今回 1 件 + 未出力の集約 3 件
        assert_eq!(sink.write_failures.load(Ordering::Acquire), 6);
        assert_eq!(sink.pending_dropped.load(Ordering::Acquire), 0);
        sink.submit("d".into());
        assert_eq!(sink.write_failures.load(Ordering::Acquire), 7);
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
