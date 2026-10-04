//! シリアルコンソール出力のホスト側書き出し（追記量の上限つき）（MAC-1・TASK-64.3）。
//!
//! 背景: `VZFileHandleSerialPortAttachment` にログファイルの fd を直接渡すと、VZ がゲストの出力を
//! 無制限に追記し、ゲストがホストのディスクを枯渇させ得る（#1366 の security-auditor 事後レビュー P1-3）。
//! VZ 側にも macOS にもファイル単位の追記上限を設ける手段がない（`RLIMIT_FSIZE` はプロセス全体に効き
//! `SIGXFSZ` を伴う）ため、pipe を挟む。
//!
//! 構成: [`ConsoleLogSink::spawn`] が pipe を作り、読み出し端と検証・open 済みのログファイルを専用スレッドへ
//! 渡す。スレッドは [`copy_capped`] でゲスト出力をファイル長が上限に達するまで書き出し、超えたら区切り文
//! [`TRUNCATION_MARKER`] を 1 回だけ書いて以降を読み捨てる。書き込み端は `config::build_vz_configuration`
//! が `NSFileHandle` に包んで VZ へ渡す（macOS）。
//!
//! - 可観測性（REPAIR-4）: 上限到達・ログへの書き込み失敗・pipe の読み出し失敗は、書き出しスレッドが
//!   stderr へ構造化ログ（1 行 1 JSON。[`event_log_line`]）として各 1 回出す。VZ へ渡した後は
//!   [`ConsoleLogSink`] の結果を受け取れないため、これが呼び出し側（plugin プロセスの stderr を集める側）
//!   から欠落を検知する経路になる。
//! - 上限到達後・ログへの書き込み失敗（ディスク満杯等）後も EOF まで読み続ける（読むのを止めると pipe が
//!   詰まり、ゲストの `console=hvc0` 出力が停滞するため）。
//! - スレッドの寿命: EOF は書き込み端がすべて閉じたとき（VZ が設定・VM を解放し、ヘルパープロセスが複製した
//!   fd を手放したとき）に来る。それまでスレッドは残る（VM 1 台につき 1 本）。呼び出し側は join しない
//!   （VM が生きている間は終わらないため、join するとハングする）。結果は [`ConsoleLogSink::finish`] で
//!   期限付きで受け取れる（VZ へ渡す前に閉じる場合のみ。REPAIR-5）。
//! - 排他: 上限は open 時のファイル長から数えるため、書き出し中はログファイルに排他の advisory lock
//!   （`File::try_lock`。unix では `flock(2)`）を保持する。同じログを別の VM（本 crate の別の書き出し）が
//!   使おうとすると [`SpawnError::InUse`] で拒否し、複数の書き出しが上限をそれぞれ使い切ることを防ぐ。lock は
//!   書き出しスレッドがファイルを閉じる（EOF で終了する）まで保持される。lock に従わない外部プロセスの追記は対象外。
//! - モード: 新規作成は 0600。既存ファイルは group / other が読み書きできるモードなら `config` の open が
//!   拒否する（出力の漏えいと、他者の追記・切り詰めで上限を維持できないことを防ぐ）。
//!
//! 上限値 [`MAX_CONSOLE_LOG_BYTES`] は spec に規定がなく暫定値である（下記 doc 参照）。

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// コンソールログのゲスト出力の上限（バイト。ファイル長で数える）。
///
/// ファイル長がこの値に達するまでゲスト出力をそのまま書き、超える出力が来たら区切り文を 1 回だけ足して
/// 以降を捨てる。上限内に収まる出力は 1 バイトも失わない。ファイル長は
/// `max(open 時の長さ, MAX_CONSOLE_LOG_BYTES + TRUNCATION_MARKER.len())` を超えない（open 時に既に上限以上なら
/// 何も書かず区切り文も重ねないため、再起動を繰り返しても増えない）。総量上限のため、起動ごとに新しい出力を
/// 残したい呼び出し側はログのローテーション・削除を自分で行う。
///
/// 暫定値: spec にコンソールログの上限の規定はない。コンテナログの保持量として計画されている
/// 1 MiB × 3 世代（SUP-7・TASK-164）の合計に揃えた。ゲストのブートログ（数十〜数百 KiB）を十分に収める。
pub const MAX_CONSOLE_LOG_BYTES: u64 = 3 * 1024 * 1024;

/// 上限を超えたときにログへ 1 回だけ書く区切り文（プログラム出力のため英語）。
pub const TRUNCATION_MARKER: &[u8] =
    b"\n[fandhe-container] console log size limit reached; further guest output is discarded\n";

/// 読み出しバッファ（固定長。ゲストの出力量に依らずアロケーションしない）。
const COPY_BUFFER_BYTES: usize = 8 * 1024;

/// 書き出しスレッドのスタック（固定長バッファ 8 KiB を含めても十分で、VM ごとの常駐消費を抑える。CORE-7）。
const WRITER_THREAD_STACK_BYTES: usize = 64 * 1024;

/// 書き出しスレッドの名前（固定文字列）。
const WRITER_THREAD_NAME: &str = "fandhe-console-log";

/// 書き出しの結果（診断用。将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsoleLogOutcome {
    /// ログへ書いたゲスト出力のバイト数（区切り文を含まない）。
    pub written_bytes: u64,
    /// 上限超過・書き込み失敗で読み捨てたバイト数。
    pub discarded_bytes: u64,
    /// 上限を超える出力が来たか。
    pub limit_reached: bool,
    /// 区切り文を書いたか（上限超過時に 1 回。open 時に既に上限以上なら書かない）。
    pub marker_written: bool,
    /// ログへの書き込みが最初に失敗したときの種別（以後は読み捨てる）。
    pub write_error: Option<ErrorKind>,
    /// pipe の読み出しが失敗して終了したときの種別（EOF なら `None`）。
    pub read_error: Option<ErrorKind>,
}

/// 書き出し中に 1 回ずつ報告する出来事（構造化ログの材料。[`event_log_line`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleLogEvent {
    /// 上限を超える出力が来た（`written_bytes` はそれまでに書いたゲスト出力のバイト数）。
    LimitReached { written_bytes: u64 },
    /// ログへの書き込みに失敗した（以後は読み捨てる）。
    WriteFailed { kind: ErrorKind },
    /// pipe の読み出しに失敗して書き出しを終えた。
    ReadFailed { kind: ErrorKind },
}

/// 出来事を 1 行の JSON にする（`component` / `operation` / `result` / `code` は固定文字列）。
///
/// `kind` は `ErrorKind` の variant 名（ASCII 英数字のみ）で、エスケープは不要。vm.rs の停止失敗ログと同じ
/// 1 行 1 JSON の形式に揃える（REPAIR-4）。
pub(crate) fn event_log_line(event: ConsoleLogEvent) -> String {
    const PREFIX: &str = "{\"component\":\"platform-macos.console_log\",\"operation\":\"write\"";
    match event {
        ConsoleLogEvent::LimitReached { written_bytes } => format!(
            "{PREFIX},\"result\":\"truncated\",\"code\":\"console_log.limit_reached\",\"limit_bytes\":{MAX_CONSOLE_LOG_BYTES},\"written_bytes\":{written_bytes}}}"
        ),
        ConsoleLogEvent::WriteFailed { kind } => format!(
            "{PREFIX},\"result\":\"error\",\"code\":\"console_log.write_failed\",\"kind\":\"{kind:?}\"}}"
        ),
        ConsoleLogEvent::ReadFailed { kind } => format!(
            "{PREFIX},\"result\":\"error\",\"code\":\"console_log.read_failed\",\"kind\":\"{kind:?}\"}}"
        ),
    }
}

/// 出来事を stderr へ 1 行で出す。stderr への書き込み失敗（EPIPE 等）では panic しない（`eprintln!` を使わない）。
fn report_to_stderr(event: ConsoleLogEvent) {
    let _ = writeln!(std::io::stderr().lock(), "{}", event_log_line(event));
}

/// open 時のファイル長から決める書き出し計画。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapPlan {
    /// 書いてよいゲスト出力のバイト数（ファイル長が上限に達するまで）。
    pub(crate) guest_budget: u64,
    /// 上限超過時に区切り文を書くか（open 時に既に上限以上なら書かない）。
    pub(crate) marker_allowed: bool,
}

impl CapPlan {
    /// 上限 `cap` と既存長 `existing_len` から計画を立てる。
    pub(crate) fn new(cap: u64, existing_len: u64) -> CapPlan {
        CapPlan {
            guest_budget: cap.saturating_sub(existing_len),
            marker_allowed: existing_len < cap,
        }
    }
}

/// `src` を EOF まで読み、`plan` の範囲だけ `dst` へ書く（超過分・書き込み失敗後は読み捨てる）。
///
/// 上限到達・書き込み失敗・読み出し失敗はそれぞれ最初の 1 回だけ `report` へ渡す。panic しない。
/// `Interrupted` の読み出しは再試行し、その他の読み出し失敗で終了する。
pub(crate) fn copy_capped<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    plan: CapPlan,
    report: &mut dyn FnMut(ConsoleLogEvent),
) -> ConsoleLogOutcome {
    let mut buf = [0u8; COPY_BUFFER_BYTES];
    let mut out = ConsoleLogOutcome::default();
    let mut remaining = plan.guest_budget;
    let mut accepting = true;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                out.read_error = Some(e.kind());
                break;
            }
        };
        // `Read` の契約上 n <= buf.len() だが、契約違反の実装でも添字で panic させない。
        let Some(chunk) = buf.get(..n) else {
            out.read_error = Some(ErrorKind::InvalidData);
            break;
        };
        let chunk_len = len_u64(chunk);
        if !accepting {
            out.discarded_bytes = out.discarded_bytes.saturating_add(chunk_len);
            continue;
        }
        let take = usize::try_from(remaining).map_or(chunk.len(), |r| r.min(chunk.len()));
        let (head, tail) = chunk.split_at_checked(take).unwrap_or((chunk, &[]));
        let (done, err) = write_counted(&mut dst, head);
        out.written_bytes = out.written_bytes.saturating_add(done);
        remaining = remaining.saturating_sub(done);
        if let Some(kind) = err {
            // 書けた分は written、残り（head の未書き込み分と tail）は discarded に数える。
            record_write_error(&mut out, kind, report);
            out.discarded_bytes = out
                .discarded_bytes
                .saturating_add(chunk_len.saturating_sub(done));
            accepting = false;
            continue;
        }
        if !tail.is_empty() {
            accepting = false;
            out.limit_reached = true;
            out.discarded_bytes = out.discarded_bytes.saturating_add(len_u64(tail));
            report(ConsoleLogEvent::LimitReached {
                written_bytes: out.written_bytes,
            });
            if plan.marker_allowed {
                match write_counted(&mut dst, TRUNCATION_MARKER) {
                    (_, None) => out.marker_written = true,
                    (_, Some(kind)) => record_write_error(&mut out, kind, report),
                }
            }
        }
    }
    if let Some(kind) = out.read_error {
        report(ConsoleLogEvent::ReadFailed { kind });
    }
    out
}

/// `buf` を書けるだけ書き、書けたバイト数と（あれば）失敗の種別を返す。
///
/// `write_all` は途中まで書いた後に失敗すると書けたバイト数を返さないため、集計を実際のログと一致させる
/// ために自前で進める。`Interrupted` は再試行し、`Ok(0)` は `WriteZero` として失敗にする。
fn write_counted<W: Write>(dst: &mut W, buf: &[u8]) -> (u64, Option<ErrorKind>) {
    let mut rest = buf;
    let mut done = 0u64;
    while !rest.is_empty() {
        match dst.write(rest) {
            Ok(0) => return (done, Some(ErrorKind::WriteZero)),
            Ok(n) => {
                // `Write` の契約上 n <= rest.len() だが、契約違反の実装でも添字で panic させない。
                let Some(next) = rest.get(n..) else {
                    return (done, Some(ErrorKind::InvalidData));
                };
                done = done.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                rest = next;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return (done, Some(e.kind())),
        }
    }
    (done, None)
}

/// 最初の書き込み失敗だけを記録・報告する。
fn record_write_error(
    out: &mut ConsoleLogOutcome,
    kind: ErrorKind,
    report: &mut dyn FnMut(ConsoleLogEvent),
) {
    if out.write_error.is_none() {
        out.write_error = Some(kind);
        report(ConsoleLogEvent::WriteFailed { kind });
    }
}

fn len_u64(b: &[u8]) -> u64 {
    u64::try_from(b.len()).unwrap_or(u64::MAX)
}

/// 上限つきで書き出されるコンソールログの入口（pipe の書き込み端と書き出しスレッドの結果）。
///
/// 生のログファイルは保持せず公開もしないため、上限を迂回して追記する経路はない。
#[derive(Debug)]
pub struct ConsoleLogSink {
    writer: std::io::PipeWriter,
    outcome: Receiver<ConsoleLogOutcome>,
}

/// [`ConsoleLogSink::spawn`] の失敗要因。呼び出し側 `config` が `ConfigError` へ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnError {
    /// 同じログファイルを別の書き出しが使用中（排他 lock を取れない）。
    InUse,
    /// lock・ファイル長の取得・pipe 作成・スレッド起動の失敗。
    Io(ErrorKind),
}

impl From<std::io::Error> for SpawnError {
    fn from(e: std::io::Error) -> Self {
        SpawnError::Io(e.kind())
    }
}

impl ConsoleLogSink {
    /// `file`（検証・追記 open 済み）の排他 lock を取り、pipe を作り、ゲスト出力をファイル長 `cap` まで書き出す
    /// スレッドを起動する。
    ///
    /// lock を取ってからファイル長を読むため、上限の計算は他の書き出しと競合しない。失敗時は `file`（と lock）・
    /// pipe を drop で閉じる。書き出し中の出来事（上限到達・書き込み / 読み出し失敗）は stderr の構造化ログで報告する。
    pub(crate) fn spawn(file: File, cap: u64) -> Result<ConsoleLogSink, SpawnError> {
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(SpawnError::InUse),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        let plan = CapPlan::new(cap, file.metadata()?.len());
        let (reader, writer) = std::io::pipe()?;
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(WRITER_THREAD_NAME.to_string())
            .stack_size(WRITER_THREAD_STACK_BYTES)
            .spawn(move || {
                let outcome = copy_capped(reader, file, plan, &mut report_to_stderr);
                // 受け手が既に無い（VZ へ渡して取っ手を手放した）なら結果は捨てる（出来事は報告済み）。
                let _ = tx.send(outcome);
            })?;
        Ok(ConsoleLogSink {
            writer,
            outcome: rx,
        })
    }

    /// 書き込み端を閉じ、書き出しスレッドの結果を最大 `timeout` 待って返す（期限切れは `None`。REPAIR-5）。
    ///
    /// VZ へ渡さずに閉じる場合の後始末と結果確認に使う。
    pub fn finish(self, timeout: Duration) -> Option<ConsoleLogOutcome> {
        drop(self.writer);
        self.outcome.recv_timeout(timeout).ok()
    }

    /// テスト用: 書き込み端へ書く（VZ の代わり）。
    #[cfg(test)]
    pub(crate) fn writer(&mut self) -> &mut std::io::PipeWriter {
        &mut self.writer
    }

    /// 書き込み端の fd を取り出す（`NSFileHandle` へ所有を移すため）。書き出しスレッドは切り離され、
    /// VZ が書き込み端を手放した時点の EOF で終了する。以後の出来事は stderr の構造化ログでだけ観測できる。
    #[cfg(target_os = "macos")]
    pub(crate) fn into_write_fd(self) -> std::os::fd::OwnedFd {
        self.writer.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER_LEN: u64 = TRUNCATION_MARKER.len() as u64;

    /// テスト用: 出来事を集める。
    fn copy_collect<R: Read, W: Write>(
        src: R,
        dst: W,
        plan: CapPlan,
    ) -> (ConsoleLogOutcome, Vec<ConsoleLogEvent>) {
        let mut events = Vec::new();
        let out = copy_capped(src, dst, plan, &mut |e| events.push(e));
        (out, events)
    }

    /// MAC-1・TASK-64.3: 計画は既存長に応じて予算を減らし、区切り文の分は予約しない。
    #[test]
    fn cap_plan_uses_full_room() {
        assert_eq!(MARKER_LEN, 86);
        assert_eq!(
            CapPlan::new(1000, 0),
            CapPlan {
                guest_budget: 1000,
                marker_allowed: true
            }
        );
        assert_eq!(
            CapPlan::new(1000, 990),
            CapPlan {
                guest_budget: 10,
                marker_allowed: true
            }
        );
        assert_eq!(
            CapPlan::new(1000, 1000),
            CapPlan {
                guest_budget: 0,
                marker_allowed: false
            }
        );
        assert_eq!(
            CapPlan::new(1000, 5000),
            CapPlan {
                guest_budget: 0,
                marker_allowed: false
            }
        );
    }

    /// MAC-1・TASK-64.3: 上限内の出力はすべて書き、区切り文も出来事も出さない。
    #[test]
    fn copy_within_budget_writes_everything() {
        let mut dst = Vec::new();
        let (out, events) = copy_collect(&b"hello\n"[..], &mut dst, CapPlan::new(1000, 0));
        assert_eq!(dst, b"hello\n");
        assert_eq!(
            out,
            ConsoleLogOutcome {
                written_bytes: 6,
                ..ConsoleLogOutcome::default()
            }
        );
        assert!(events.is_empty());
    }

    /// MAC-1・TASK-64.3: 上限ちょうどの出力は末尾まで失わない（区切り文の分を予約して捨てない）。
    #[test]
    fn copy_exactly_budget_keeps_tail() {
        let src = vec![b'q'; 1000];
        let mut dst = Vec::new();
        let (out, events) = copy_collect(&src[..], &mut dst, CapPlan::new(1000, 0));
        assert_eq!(dst, src);
        assert_eq!(out.written_bytes, 1000);
        assert!(!out.limit_reached);
        assert!(events.is_empty());
    }

    /// MAC-1・TASK-64.3: 残りが区切り文より短くても、残り分は書いてから区切り文を足す。
    #[test]
    fn copy_small_room_writes_rest_then_marker() {
        let mut dst = Vec::new();
        let (out, events) = copy_collect(
            &b"0123456789ABCDEFGHIJ"[..],
            &mut dst,
            CapPlan::new(1000, 990),
        );
        let mut expected = b"0123456789".to_vec();
        expected.extend_from_slice(TRUNCATION_MARKER);
        assert_eq!(dst, expected);
        assert_eq!(out.written_bytes, 10);
        assert_eq!(out.discarded_bytes, 10);
        assert!(out.marker_written);
        assert_eq!(
            events,
            vec![ConsoleLogEvent::LimitReached { written_bytes: 10 }]
        );
    }

    /// MAC-1・TASK-64.3: 上限を超えた分は捨て、区切り文と出来事を 1 回だけ出し、EOF まで読み続ける。
    #[test]
    fn copy_over_budget_truncates_and_marks_once() {
        let src = vec![b'x'; 20_000];
        let mut dst = Vec::new();
        let (out, events) = copy_collect(&src[..], &mut dst, CapPlan::new(100, 0));
        let mut expected = vec![b'x'; 100];
        expected.extend_from_slice(TRUNCATION_MARKER);
        assert_eq!(dst, expected);
        assert_eq!(
            out,
            ConsoleLogOutcome {
                written_bytes: 100,
                discarded_bytes: 19_900,
                limit_reached: true,
                marker_written: true,
                ..ConsoleLogOutcome::default()
            }
        );
        assert_eq!(
            events,
            vec![ConsoleLogEvent::LimitReached { written_bytes: 100 }]
        );
    }

    /// MAC-1・TASK-64.3: open 時点で満杯なら何も書かず区切り文も重ねないが、上限到達は報告する。
    #[test]
    fn copy_into_full_file_discards_without_marker() {
        let mut dst = Vec::new();
        let (out, events) = copy_collect(&b"late output"[..], &mut dst, CapPlan::new(1000, 1000));
        assert!(dst.is_empty());
        assert_eq!(
            out,
            ConsoleLogOutcome {
                discarded_bytes: 11,
                limit_reached: true,
                ..ConsoleLogOutcome::default()
            }
        );
        assert_eq!(
            events,
            vec![ConsoleLogEvent::LimitReached { written_bytes: 0 }]
        );
    }

    /// 書き込みが常に失敗する出力先（ディスク満杯の模擬）。
    struct FullDisk;

    impl Write for FullDisk {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(ErrorKind::StorageFull))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// MAC-1・TASK-64.3: 書き込み失敗後は読み捨てに倒して EOF まで読み続け、失敗を 1 回だけ報告する。
    #[test]
    fn copy_after_write_error_keeps_draining() {
        let src = vec![b'y'; 3 * COPY_BUFFER_BYTES];
        let (out, events) = copy_collect(&src[..], FullDisk, CapPlan::new(1 << 20, 0));
        assert_eq!(
            out,
            ConsoleLogOutcome {
                discarded_bytes: 3 * COPY_BUFFER_BYTES as u64,
                write_error: Some(ErrorKind::StorageFull),
                ..ConsoleLogOutcome::default()
            }
        );
        assert_eq!(
            events,
            vec![ConsoleLogEvent::WriteFailed {
                kind: ErrorKind::StorageFull
            }]
        );
    }

    /// 先頭 `capacity` バイトだけ受け付け、以後は失敗する出力先（途中でディスクが満杯になる模擬）。
    struct PartialDisk {
        data: Vec<u8>,
        capacity: usize,
    }

    impl Write for PartialDisk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let room = self.capacity - self.data.len();
            if room == 0 {
                return Err(std::io::Error::from(ErrorKind::StorageFull));
            }
            let n = room.min(buf.len());
            self.data.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// MAC-1・TASK-64.3: 途中まで書けた後の失敗では、書けた分を written、残りを discarded に数える
    /// （集計を実際のログと一致させる）。
    #[test]
    fn copy_counts_partial_write_before_failure() {
        let src = vec![b'p'; 1000];
        let mut dst = PartialDisk {
            data: Vec::new(),
            capacity: 300,
        };
        let (out, events) = copy_collect(&src[..], &mut dst, CapPlan::new(1 << 20, 0));
        assert_eq!(dst.data.len(), 300);
        assert_eq!(
            out,
            ConsoleLogOutcome {
                written_bytes: 300,
                discarded_bytes: 700,
                write_error: Some(ErrorKind::StorageFull),
                ..ConsoleLogOutcome::default()
            }
        );
        assert_eq!(
            events,
            vec![ConsoleLogEvent::WriteFailed {
                kind: ErrorKind::StorageFull
            }]
        );
    }

    /// MAC-1・TASK-64.3: 区切り文の途中で失敗したら区切り文は書けていない扱いにし、失敗を報告する。
    #[test]
    fn copy_reports_marker_write_failure() {
        let src = [b'm'; 200];
        let mut dst = PartialDisk {
            data: Vec::new(),
            capacity: 110,
        };
        let (out, events) = copy_collect(&src[..], &mut dst, CapPlan::new(100, 0));
        assert_eq!(out.written_bytes, 100);
        assert_eq!(out.discarded_bytes, 100);
        assert!(out.limit_reached);
        assert!(!out.marker_written);
        assert_eq!(out.write_error, Some(ErrorKind::StorageFull));
        assert_eq!(
            events,
            vec![
                ConsoleLogEvent::LimitReached { written_bytes: 100 },
                ConsoleLogEvent::WriteFailed {
                    kind: ErrorKind::StorageFull
                },
            ]
        );
    }

    /// 1 回目は `Interrupted`、以後は内側へ委ねる読み出し元。
    struct InterruptOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptOnce<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::Error::from(ErrorKind::Interrupted));
            }
            self.inner.read(buf)
        }
    }

    /// MAC-1・TASK-64.3: `Interrupted` は再試行し、データを失わない。
    #[test]
    fn copy_retries_interrupted_read() {
        let src = InterruptOnce {
            inner: &b"boot ok\n"[..],
            interrupted: false,
        };
        let mut dst = Vec::new();
        let (out, events) = copy_collect(src, &mut dst, CapPlan::new(1000, 0));
        assert_eq!(dst, b"boot ok\n");
        assert_eq!(out.written_bytes, 8);
        assert_eq!(out.read_error, None);
        assert!(events.is_empty());
    }

    /// 常に失敗する読み出し元。
    struct BrokenPipe;

    impl Read for BrokenPipe {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    /// MAC-1・TASK-64.3: 読み出し失敗で終了し、その旨を報告する。
    #[test]
    fn copy_reports_read_failure() {
        let (out, events) = copy_collect(BrokenPipe, Vec::new(), CapPlan::new(1000, 0));
        assert_eq!(out.read_error, Some(ErrorKind::BrokenPipe));
        assert_eq!(
            events,
            vec![ConsoleLogEvent::ReadFailed {
                kind: ErrorKind::BrokenPipe
            }]
        );
    }

    /// MAC-1・TASK-64.3・REPAIR-4: 構造化ログは 1 行 1 JSON で、機械可読な code を持つ。
    #[test]
    fn event_log_lines_are_stable() {
        assert_eq!(
            event_log_line(ConsoleLogEvent::LimitReached { written_bytes: 42 }),
            "{\"component\":\"platform-macos.console_log\",\"operation\":\"write\",\"result\":\"truncated\",\"code\":\"console_log.limit_reached\",\"limit_bytes\":3145728,\"written_bytes\":42}"
        );
        assert_eq!(
            event_log_line(ConsoleLogEvent::WriteFailed {
                kind: ErrorKind::StorageFull
            }),
            "{\"component\":\"platform-macos.console_log\",\"operation\":\"write\",\"result\":\"error\",\"code\":\"console_log.write_failed\",\"kind\":\"StorageFull\"}"
        );
        assert_eq!(
            event_log_line(ConsoleLogEvent::ReadFailed {
                kind: ErrorKind::BrokenPipe
            }),
            "{\"component\":\"platform-macos.console_log\",\"operation\":\"write\",\"result\":\"error\",\"code\":\"console_log.read_failed\",\"kind\":\"BrokenPipe\"}"
        );
    }

    /// テスト用一時ファイル（終了時に削除）。
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(tag: &str, content: &[u8]) -> Self {
            let p = std::env::temp_dir()
                .join(format!("fandhe-macos-console-{tag}-{}", std::process::id()));
            std::fs::write(&p, content).expect("write fixture");
            Self(p)
        }

        fn append_handle(&self) -> File {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&self.0)
                .expect("open fixture")
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    const WAIT: Duration = Duration::from_secs(10);

    /// MAC-1・TASK-64.3: pipe 経由の出力は既存内容の後ろへ追記され、閉じると結果が返る。
    #[test]
    fn sink_appends_through_pipe() {
        let t = TempFile::new("append", b"previous\n");
        let mut sink = ConsoleLogSink::spawn(t.append_handle(), 1000).unwrap();
        sink.writer().write_all(b"guest boot\n").unwrap();
        let out = sink.finish(WAIT).expect("writer thread finished");
        assert_eq!(out.written_bytes, 11);
        assert!(!out.limit_reached);
        assert_eq!(std::fs::read(&t.0).unwrap(), b"previous\nguest boot\n");
    }

    /// MAC-1・TASK-64.3: 本番の上限 `MAX_CONSOLE_LOG_BYTES` を超える出力でも、ファイル長は上限＋区切り文で
    /// 止まる（ホストのディスク枯渇の防止。#1366 の P1-3）。
    #[test]
    fn sink_stops_at_production_cap() {
        let t = TempFile::new("cap", b"");
        let mut sink = ConsoleLogSink::spawn(t.append_handle(), MAX_CONSOLE_LOG_BYTES).unwrap();
        let chunk = vec![b'z'; 64 * 1024];
        let total = MAX_CONSOLE_LOG_BYTES + 256 * 1024;
        let mut sent = 0u64;
        while sent < total {
            sink.writer().write_all(&chunk).unwrap();
            sent += chunk.len() as u64;
        }
        let out = sink.finish(WAIT).expect("writer thread finished");
        let data = std::fs::read(&t.0).unwrap();
        assert_eq!(data.len() as u64, MAX_CONSOLE_LOG_BYTES + MARKER_LEN);
        assert!(data.ends_with(TRUNCATION_MARKER));
        assert_eq!(out.written_bytes, MAX_CONSOLE_LOG_BYTES);
        assert_eq!(out.discarded_bytes, total - MAX_CONSOLE_LOG_BYTES);
        assert!(out.limit_reached);
        assert!(out.marker_written);
    }

    /// MAC-1・TASK-64.3: 書き出し中の同じログへの 2 つ目の書き出しは `InUse` で拒否し（上限の二重使用を防ぐ）、
    /// 1 つ目が閉じた後は再び使える。
    #[test]
    fn sink_rejects_concurrent_writer_on_same_log() {
        let t = TempFile::new("lock", b"");
        let mut first = ConsoleLogSink::spawn(t.append_handle(), 1000).unwrap();
        assert_eq!(
            ConsoleLogSink::spawn(t.append_handle(), 1000).err(),
            Some(SpawnError::InUse)
        );
        first.writer().write_all(b"one\n").unwrap();
        first.finish(WAIT).expect("writer thread finished");
        let second = ConsoleLogSink::spawn(t.append_handle(), 1000).unwrap();
        second.finish(WAIT).expect("writer thread finished");
        assert_eq!(std::fs::read(&t.0).unwrap(), b"one\n");
    }

    /// MAC-1・TASK-64.3: 既に上限に達したファイルへは追記しない（再起動の繰り返しでも総量が増えない）。
    #[test]
    fn sink_does_not_grow_full_file() {
        let t = TempFile::new("full", &[b'a'; 200]);
        let mut sink = ConsoleLogSink::spawn(t.append_handle(), 200).unwrap();
        sink.writer().write_all(b"more output").unwrap();
        let out = sink.finish(WAIT).expect("writer thread finished");
        assert_eq!(std::fs::metadata(&t.0).unwrap().len(), 200);
        assert_eq!(out.discarded_bytes, 11);
        assert!(!out.marker_written);
    }
}
