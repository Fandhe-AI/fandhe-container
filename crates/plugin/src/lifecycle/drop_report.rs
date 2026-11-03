//! `ChildGuard` の `Drop` 経路で書けなかった後始末の失敗記録を、終了時にホストが出せるよう延期して保持する
//! 固定長の表（#1673・REPAIR-4・REPAIR-5・PLUG-7）。
//!
//! `Drop` は `Result` を返せず、stderr への書き込みがブロックしないと保証できるのは Linux（x86_64 / aarch64）の
//! AF_UNIX socket だけである（`crate::sys::write_nonblocking`）。それ以外（macOS・端末・通常ファイル・pipe・
//! 書き込みが途中までで終わった場合とそれ以後のすべての記録・別スレッドが即時に書いている最中の記録）の記録は、確保も I/O もロックもせず atomic の CAS だけでこの表へ積む。
//! ホスト（CLI の `main`）は終了時に [`take_pending_child_cleanup_failures`] で取り出し、期限付きで待つ別スレッドから
//! stderr へ 1 行ずつ出す（main は stderr へ書かない。REPAIR-5）。取り出した記録は表から消え、各記録はちょうど
//! 1 回だけ返る。ホストがスレッドを起動できないときの縮退出力には、ブロックしないと保証できる場合にだけ 1 回書く
//! [`write_stderr_nonblocking`] を使う。
//!
//! 記録に載せるのは固定文字列と pid の整数だけで、plugin 由来の文字列は載せない（ログ行の偽装を防ぐ）。
//!
//! 契約の限界（REPAIR-3）:
//! - `push` と並行して取り出しが走った場合、その時点で積まれた記録だけを返す（後の記録は次回の取り出しで返る）
//! - SIGKILL・abort・`signals` のシグナル再送出による終了と、取り出しを呼ばないホスト（core の plugin proxy は
//!   #1869 の設計〔docs/design/plugin-backend-wiring.md。承認と実装 issue の起票は #2232〕・TASK-114 で配線予定）では、延期した記録は残らない

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// プロセス全体の延期表の容量。溢れた分は件数だけ数える。
pub const DROP_REPORT_CAPACITY: usize = 64;

/// `ChildGuard` の `Drop` 経路で後始末に失敗したときの記録（#1605・PLUG-7・REPAIR-4）。
///
/// 値は固定文字列と整数のみで、plugin 由来の untrusted な文字列は載せない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildCleanupFailure {
    /// 直接の子は回収したが、グループ宛て SIGKILL が許容外のエラーで失敗し、孫が残り得る。
    GroupKillFailed,
    /// 直接の子を回収できなかった（孤児の可能性）。保持中の pid を載せる。
    Unreaped { pid: Option<u32> },
}

const TAG_SHIFT: u32 = 32;
const TAG_GROUP_KILL_FAILED: u64 = 1;
const TAG_UNREAPED_NO_PID: u64 = 2;
const TAG_UNREAPED_PID: u64 = 3;

impl ChildCleanupFailure {
    /// 構造化ログの 1 行（改行なし。キーは `audit` の `event` / `op` / `outcome` / `reason` の流儀に揃える）。
    pub fn to_json_line(self) -> String {
        match self {
            Self::GroupKillFailed => "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"group_kill_failed\"}".to_string(),
            Self::Unreaped { pid: Some(pid) } => format!(
                "{{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\",\"pid\":{pid}}}"
            ),
            Self::Unreaped { pid: None } => "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\"}".to_string(),
        }
    }

    /// 表の 1 要素へ符号化する（0 は空きのため返さない）。
    fn encode(self) -> u64 {
        match self {
            Self::GroupKillFailed => TAG_GROUP_KILL_FAILED << TAG_SHIFT,
            Self::Unreaped { pid: None } => TAG_UNREAPED_NO_PID << TAG_SHIFT,
            Self::Unreaped { pid: Some(pid) } => (TAG_UNREAPED_PID << TAG_SHIFT) | u64::from(pid),
        }
    }

    /// 表の 1 要素を復号する。不明なタグは `None`（壊れた値を表現しない。REPAIR-2）。
    fn decode(v: u64) -> Option<Self> {
        let low = u32::try_from(v & u64::from(u32::MAX)).ok()?;
        match v >> TAG_SHIFT {
            TAG_GROUP_KILL_FAILED => Some(Self::GroupKillFailed),
            TAG_UNREAPED_NO_PID => Some(Self::Unreaped { pid: None }),
            TAG_UNREAPED_PID => Some(Self::Unreaped { pid: Some(low) }),
            _ => None,
        }
    }
}

/// 延期記録の lock-free な固定長表。`Drop`・unwinding の中から呼んでよい（確保も I/O もロックもしない）。
pub(crate) struct DropReportTable {
    slots: &'static [AtomicU64],
    dropped: AtomicU64,
    partial_write_seen: AtomicBool,
    /// 即時書き込みを実行中のスレッドがあるとき真（同時に 1 つだけ。並行する即時書き込みの交錯を防ぐ）。
    /// 即時書き込みは unix だけのため、非 unix では持たない。
    #[cfg(unix)]
    immediate_writer: AtomicBool,
    /// 即時書き込みが途中までで終わったことが一度でもあれば真で、以後は取り出し後も含め即時に書かない。
    /// 断片の後ろに次の記録が連結して不正な行になるのを防ぐ（以後の記録はすべて延期表へ回す）。
    #[cfg(unix)]
    immediate_disabled: AtomicBool,
}

impl DropReportTable {
    /// 静的な要素列の上に表を作る（`signal_forward::Registry::over` と同じ流儀）。
    pub(crate) const fn over(slots: &'static [AtomicU64]) -> Self {
        Self {
            slots,
            dropped: AtomicU64::new(0),
            partial_write_seen: AtomicBool::new(false),
            #[cfg(unix)]
            immediate_writer: AtomicBool::new(false),
            #[cfg(unix)]
            immediate_disabled: AtomicBool::new(false),
        }
    }

    /// 記録を積む。空きが無ければ溢れた件数を数える（飽和）。
    pub(crate) fn push(&self, failure: ChildCleanupFailure) {
        let encoded = failure.encode();
        for slot in self.slots {
            if slot
                .compare_exchange(0, encoded, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
        // `fetch_update` は新しい toolchain で非推奨（`try_update` へ改名）のため、版差を避けて CAS ループで書く。
        let mut cur = self.dropped.load(Ordering::Relaxed);
        while let Some(next) = cur.checked_add(1) {
            match self
                .dropped
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(now) => cur = now,
            }
        }
    }

    /// 即時書き込みが途中までで終わった印を立て（取り出し時に先頭へ改行を足す）、以後の即時書き込みを止める。
    #[cfg(unix)]
    pub(crate) fn mark_partial_write(&self) {
        self.immediate_disabled.store(true, Ordering::Release);
        self.partial_write_seen.store(true, Ordering::Release);
    }

    /// 即時書き込みの権利を取る。他のスレッドが書いている最中か、過去に途中までの書き込みがあれば `None`
    /// （呼び出し側は延期表へ積む）。待たない（CAS 1 回）。
    #[cfg(unix)]
    fn try_begin_immediate(&self) -> Option<ImmediateWriter<'_>> {
        if self.immediate_disabled.load(Ordering::Acquire) {
            return None;
        }
        self.immediate_writer
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .ok()?;
        // 権利を取る間に別スレッドが途中までの書き込みを記録していれば書かない。
        if self.immediate_disabled.load(Ordering::Acquire) {
            self.immediate_writer.store(false, Ordering::Release);
            return None;
        }
        Some(ImmediateWriter { table: self })
    }

    /// 積まれた記録を取り出す。各記録はちょうど 1 回だけ返る。
    pub(crate) fn take(&self) -> PendingChildCleanup {
        let mut failures = Vec::new();
        for slot in self.slots {
            let v = slot.swap(0, Ordering::AcqRel);
            if v != 0
                && let Some(f) = ChildCleanupFailure::decode(v)
            {
                failures.push(f);
            }
        }
        PendingChildCleanup {
            failures,
            dropped: self.dropped.swap(0, Ordering::AcqRel),
            partial_write_seen: self.partial_write_seen.swap(false, Ordering::AcqRel),
        }
    }
}

/// 即時書き込みの権利（破棄で手放す。unwinding 中でも確実に戻すため RAII にする）。
#[cfg(unix)]
struct ImmediateWriter<'a> {
    table: &'a DropReportTable,
}

#[cfg(unix)]
impl Drop for ImmediateWriter<'_> {
    fn drop(&mut self) {
        self.table.immediate_writer.store(false, Ordering::Release);
    }
}

/// [`take_pending_child_cleanup_failures`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChildCleanup {
    failures: Vec<ChildCleanupFailure>,
    dropped: u64,
    partial_write_seen: bool,
}

impl PendingChildCleanup {
    /// 取り出した記録（積まれた順ではなく表の位置順）。
    pub fn failures(&self) -> &[ChildCleanupFailure] {
        &self.failures
    }

    /// 表が満杯で記録できなかった件数。
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// 即時書き込みが途中で切れた印を取り出して消す。真のとき、呼び出し元は次の出力（コマンド結果の行等）の前に
    /// 改行を 1 つ出して断片を分離する。消すので [`Self::write_json_lines`] は先頭の改行を重ねて出さない。
    pub fn take_partial_write_mark(&mut self) -> bool {
        std::mem::take(&mut self.partial_write_seen)
    }

    /// 出すものが無いとき真。記録が無くても断片分離の印が残っていれば偽（分離用の改行を出す必要がある）。
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty() && self.dropped == 0 && !self.partial_write_seen
    }

    /// `Drop` 時と同じ固定書式で 1 行ずつ書く。即時書き込みが途中で切れた断片が後続の行と連結しないよう、
    /// 印が立っていれば先頭に改行を 1 つ出す。溢れた分は固定の 1 行で件数を出す。
    pub fn write_json_lines(&self, out: &mut dyn Write) -> io::Result<()> {
        // 部分書き込みの印と記録の push の間に並行して取り出された場合、記録が空で印だけが残る。印は表から
        // 消えているため、ここで改行を出さないと次回の記録が断片へ連結する（REPAIR-4）。
        if self.partial_write_seen {
            out.write_all(b"\n")?;
        }
        for f in &self.failures {
            writeln!(out, "{}", f.to_json_line())?;
        }
        if self.dropped > 0 {
            writeln!(
                out,
                "{{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"records_dropped\",\"count\":{}}}",
                self.dropped
            )?;
        }
        Ok(())
    }
}

static GLOBAL_SLOTS: [AtomicU64; DROP_REPORT_CAPACITY] =
    [const { AtomicU64::new(0) }; DROP_REPORT_CAPACITY];

/// プロセス全体の延期表。
pub(crate) static GLOBAL_TABLE: DropReportTable = DropReportTable::over(&GLOBAL_SLOTS);

/// `Drop` 経路で即時に書けなかった後始末の失敗記録を取り出す。ホストは終了時（コマンド結果の出力後）に
/// 呼び、[`PendingChildCleanup::write_json_lines`] で stderr へ出す。stderr の書き込みはブロックし得るため、
/// ホストは期限付きで待つ別スレッドから書く（CLI の `main`。#1673・REPAIR-4・REPAIR-5）。
pub fn take_pending_child_cleanup_failures() -> PendingChildCleanup {
    GLOBAL_TABLE.take()
}

/// stderr へ、ブロックしないと保証できる場合にだけ `buf` を 1 回書く（#1673・REPAIR-5）。書いたバイト数を返す。
///
/// ホストが期限付きの出力スレッドを起動できなかったとき（EAGAIN 等）の縮退出力に使う。呼び出し元のスレッドで
/// 呼んでも、どの OS でも無期限に待たない:
/// - Linux（x86_64 / aarch64）で stderr が AF_UNIX socket: `send(MSG_DONTWAIT | MSG_NOSIGNAL)` を 1 回だけ行う
///   （`crate::sys::write_nonblocking`。送信バッファが満杯なら `WouldBlock` で即座に戻る。一部だけ書けた場合も
///   再試行しない）
/// - それ以外（pipe・端末・通常ファイル・キャラクタデバイス・TCP 等の socket、macOS を含むその他の unix、Windows）:
///   共有 fd の状態（`O_NONBLOCK`・`SO_SNDTIMEO` 等）を変えずに待たない手段が無いため、書かずに `Unsupported` を返す
///   （fail-closed。出力は失われる）
pub fn write_stderr_nonblocking(buf: &[u8]) -> io::Result<usize> {
    #[cfg(unix)]
    {
        crate::sys::write_nonblocking(&io::stderr(), buf)
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// `Drop` の記録 1 件を、書けるなら即時に（Linux の AF_UNIX socket）、書けなければ延期表へ積む。
/// ブロックし得る操作は含まない（REPAIR-5）。
///
/// 即時書き込みは同時に 1 スレッドだけが行い（他は延期）、一度でも途中までで終わったら以後の記録は
/// すべて延期表へ回す（断片の後ろに次の行が連結しない。断片の分離はホストが終了時に改行 1 つで行う）。
/// 本 crate の外から同じ stderr へ並行して書く書き込みとの交錯は防げない（契約の限界。REPAIR-3）。
#[cfg(unix)]
pub(crate) fn record_drop_failure(
    fd: &impl std::os::unix::io::AsFd,
    table: &DropReportTable,
    failure: ChildCleanupFailure,
) {
    if let Some(_writer) = table.try_begin_immediate() {
        let mut line = failure.to_json_line();
        line.push('\n');
        match crate::sys::write_nonblocking(fd, line.as_bytes()) {
            Ok(n) if n == line.len() => return,
            Ok(n) if n > 0 => table.mark_partial_write(),
            _ => {}
        }
    }
    table.push(failure);
}

/// 非 unix ではブロックしない書き込み手段を持たないため、常に延期表へ積む。
#[cfg(not(unix))]
pub(crate) fn record_drop_failure(
    _fd: &io::Stderr,
    table: &DropReportTable,
    failure: ChildCleanupFailure,
) {
    table.push(failure);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaked_table(n: usize) -> &'static DropReportTable {
        let slots: &'static [AtomicU64] = Box::leak(
            (0..n)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(DropReportTable::over(slots)))
    }

    fn render(p: &PendingChildCleanup) -> String {
        let mut out = Vec::new();
        p.write_json_lines(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// REPAIR-4・#1673: 積んだ記録が各 1 回だけ返り、2 回目は空。
    #[test]
    fn repair4_drop_report_take_returns_each_record_once() {
        let t = leaked_table(8);
        t.push(ChildCleanupFailure::GroupKillFailed);
        t.push(ChildCleanupFailure::Unreaped { pid: Some(1234) });
        t.push(ChildCleanupFailure::Unreaped { pid: None });
        let p = t.take();
        assert_eq!(
            p.failures(),
            &[
                ChildCleanupFailure::GroupKillFailed,
                ChildCleanupFailure::Unreaped { pid: Some(1234) },
                ChildCleanupFailure::Unreaped { pid: None },
            ]
        );
        assert_eq!(
            render(&p),
            "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"group_kill_failed\"}\n\
             {\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\",\"pid\":1234}\n\
             {\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\"}\n"
        );
        let again = t.take();
        assert_eq!(again.failures().len(), 0);
        assert_eq!(again.dropped(), 0);
        assert!(again.is_empty());
        assert_eq!(render(&again), "");
    }

    /// REPAIR-4・REPAIR-5・#1673: 容量を超えた分は件数だけ数える。
    #[test]
    fn repair4_drop_report_overflow_counts_dropped() {
        let t = leaked_table(4);
        for _ in 0..5 {
            t.push(ChildCleanupFailure::GroupKillFailed);
        }
        let p = t.take();
        assert_eq!(p.failures().len(), 4);
        assert_eq!(p.dropped(), 1);
        assert!(render(&p).ends_with(
            "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"records_dropped\",\"count\":1}\n"
        ));
    }

    /// REPAIR-4・#1673: 並行 push の総数が積んだ件数と溢れた件数の和に一致する。
    #[test]
    fn repair4_drop_report_concurrent_push_total() {
        let t = leaked_table(16);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        t.push(ChildCleanupFailure::Unreaped { pid: Some(7) });
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let p = t.take();
        assert_eq!(p.failures().len(), 16);
        assert_eq!(p.dropped(), 24);
    }

    /// REPAIR-4・#1673: 途中まで書いた印があれば出力の先頭が改行になり、印は取り出しで消える。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_report_partial_write_prefixes_newline() {
        let t = leaked_table(2);
        t.mark_partial_write();
        t.push(ChildCleanupFailure::GroupKillFailed);
        let out = render(&t.take());
        assert!(out.starts_with("\n{\"event\""));
        t.push(ChildCleanupFailure::GroupKillFailed);
        assert!(render(&t.take()).starts_with("{\"event\""));
    }

    /// REPAIR-4・#1673: 記録が空で印だけを取り出した場合も分離用の改行を 1 つ出す（部分書き込みの印と push の間に
    /// 並行して取り出された場合。次回の記録が断片へ連結しない）。
    #[cfg(unix)]
    #[test]
    fn repair4_partial_mark_without_records_still_emits_separator() {
        let t = leaked_table(2);
        t.mark_partial_write();
        let p = t.take();
        assert!(p.failures().is_empty());
        assert!(!p.is_empty());
        assert_eq!(render(&p), "\n");
        t.push(ChildCleanupFailure::GroupKillFailed);
        assert_eq!(
            render(&t.take()),
            format!("{}\n", ChildCleanupFailure::GroupKillFailed.to_json_line())
        );
    }

    /// #1673: 印を呼び出し側が取り出すと 1 回だけ真で、以後の出力は先頭の改行を重ねない。
    #[cfg(unix)]
    #[test]
    fn partial_write_mark_taken_once_and_not_repeated() {
        let t = leaked_table(2);
        t.mark_partial_write();
        t.push(ChildCleanupFailure::GroupKillFailed);
        let mut p = t.take();
        assert!(p.take_partial_write_mark());
        assert!(!p.take_partial_write_mark());
        assert!(render(&p).starts_with("{\"event\""));
    }

    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn read_available(b: &std::os::unix::net::UnixStream) -> Vec<u8> {
        use std::io::Read;
        b.set_nonblocking(true).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match (&*b).read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read failed: {e}"),
            }
        }
        out
    }

    /// REPAIR-4・REPAIR-5・#1673: 途中までの即時書き込みが一度あれば、書ける socket でも以後の記録は即時に
    /// 書かず延期表へ回す（断片の後ろに全文の行が連結しない）。取り出し後も即時書き込みへ戻らない。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_after_partial_write_all_records_are_deferred() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        let t = leaked_table(4);
        t.mark_partial_write();
        record_drop_failure(&a, t, ChildCleanupFailure::GroupKillFailed);
        assert_eq!(read_available(&b), b"");
        let mut p = t.take();
        assert!(p.take_partial_write_mark());
        assert_eq!(p.failures(), &[ChildCleanupFailure::GroupKillFailed]);
        record_drop_failure(&a, t, ChildCleanupFailure::Unreaped { pid: Some(5) });
        assert_eq!(read_available(&b), b"");
        assert_eq!(
            t.take().failures(),
            &[ChildCleanupFailure::Unreaped { pid: Some(5) }]
        );
    }

    /// REPAIR-4・#1673: 別スレッドが即時に書いている最中の記録は延期し、権利が戻れば即時に全文を書く。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_concurrent_immediate_writer_defers_record() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        let t = leaked_table(4);
        let held = t.try_begin_immediate().unwrap();
        assert!(t.try_begin_immediate().is_none());
        record_drop_failure(&a, t, ChildCleanupFailure::GroupKillFailed);
        assert_eq!(read_available(&b), b"");
        assert_eq!(t.take().failures(), &[ChildCleanupFailure::GroupKillFailed]);
        drop(held);
        record_drop_failure(&a, t, ChildCleanupFailure::GroupKillFailed);
        let mut expected = ChildCleanupFailure::GroupKillFailed
            .to_json_line()
            .into_bytes();
        expected.push(b'\n');
        assert_eq!(read_available(&b), expected);
        assert!(t.take().is_empty());
    }

    /// REPAIR-2・#1673: 不明なタグは捨て、pid は往復する。
    #[test]
    fn repair2_drop_report_unknown_tag_is_discarded() {
        assert_eq!(ChildCleanupFailure::decode(9 << 32), None);
        let f = ChildCleanupFailure::Unreaped {
            pid: Some(u32::MAX),
        };
        assert_eq!(ChildCleanupFailure::decode(f.encode()), Some(f));
    }
}
