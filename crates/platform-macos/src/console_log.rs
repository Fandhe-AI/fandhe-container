//! シリアルコンソール出力のホスト側書き出し（追記量の上限つき）（MAC-1・TASK-64.3）。
//!
//! 背景: `VZFileHandleSerialPortAttachment` にログファイルの fd を直接渡すと、VZ がゲストの出力を
//! 無制限に追記し、ゲストがホストのディスクを枯渇させ得る（#1366 の security-auditor 事後レビュー P1-3）。
//! VZ 側にも macOS にもファイル単位の追記上限を設ける手段がない（`RLIMIT_FSIZE` はプロセス全体に効き
//! `SIGXFSZ` を伴う）ため、pipe を挟む。
//!
//! 構成: [`ConsoleLogSink::spawn`] が pipe を作り、読み出し端と検証・open 済みのログファイルを専用スレッドへ
//! 渡す。スレッドは [`copy_capped`] でファイル総量が上限に達するまで書き出し、達したら区切り文
//! [`TRUNCATION_MARKER`] を 1 回だけ書いて以降を読み捨てる。書き込み端は `config::build_vz_configuration`
//! が `NSFileHandle` に包んで VZ へ渡す（macOS）。
//!
//! - 上限到達後・ログへの書き込み失敗（ディスク満杯等）後も EOF まで読み続ける（読むのを止めると pipe が
//!   詰まり、ゲストの `console=hvc0` 出力が停滞するため）。
//! - スレッドの寿命: EOF は書き込み端がすべて閉じたとき（VZ が設定・VM を解放し、ヘルパープロセスが複製した
//!   fd を手放したとき）に来る。それまでスレッドは残る（VM 1 台につき 1 本）。呼び出し側は join しない
//!   （VM が生きている間は終わらないため、join するとハングする）。結果は [`ConsoleLogSink::finish`] で
//!   期限付きで受け取れる（VZ へ渡す前に閉じる場合のみ。REPAIR-5）。
//! - 前提: 1 つのログファイルへ同時に書くのは 1 台の VM だけ（上限は open 時のファイル長から数える）。
//!
//! 上限値 [`MAX_CONSOLE_LOG_BYTES`] は spec に規定がなく暫定値である（下記 doc 参照）。

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// コンソールログファイルの総量上限（バイト。区切り文を含む）。
///
/// 暫定値: spec にコンソールログの上限の規定はない。コンテナログの保持量として計画されている
/// 1 MiB × 3 世代（SUP-7・TASK-164）の合計に揃えた。ゲストのブートログ（数十〜数百 KiB）を十分に収め、
/// 再起動を繰り返してもファイル総量はこれを超えない。既存ファイルが既に上限以上なら追記しない。
pub const MAX_CONSOLE_LOG_BYTES: u64 = 3 * 1024 * 1024;

/// 上限到達時にログへ 1 回だけ書く区切り文（プログラム出力のため英語）。
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
    /// 上限に達したか。
    pub limit_reached: bool,
    /// 区切り文を書いたか（上限到達時に 1 回。open 時点で区切り文の余地がなければ書かない）。
    pub marker_written: bool,
    /// ログへの書き込みが最初に失敗したときの種別（以後は読み捨てる）。
    pub write_error: Option<ErrorKind>,
    /// pipe の読み出しが失敗して終了したときの種別（EOF なら `None`）。
    pub read_error: Option<ErrorKind>,
}

/// open 時のファイル長から決める書き出し計画。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapPlan {
    /// 書いてよいゲスト出力のバイト数。
    pub(crate) guest_budget: u64,
    /// 区切り文を書く余地があるか。
    pub(crate) marker_room: bool,
}

impl CapPlan {
    /// 総量上限 `cap` と既存長 `existing_len` から計画を立てる。区切り文の分を先に確保し、
    /// ファイル総量が `max(existing_len, cap)` を超えないようにする。
    pub(crate) fn new(cap: u64, existing_len: u64) -> CapPlan {
        let marker_len = u64::try_from(TRUNCATION_MARKER.len()).unwrap_or(u64::MAX);
        let room = cap.saturating_sub(existing_len);
        CapPlan {
            guest_budget: room.saturating_sub(marker_len),
            marker_room: room >= marker_len,
        }
    }
}

/// `src` を EOF まで読み、`plan` の範囲だけ `dst` へ書く（超過分・書き込み失敗後は読み捨てる）。
///
/// panic しない。`Interrupted` の読み出しは再試行し、その他の読み出し失敗で終了する。
pub(crate) fn copy_capped<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    plan: CapPlan,
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
        if let Err(e) = dst.write_all(head) {
            out.write_error = Some(e.kind());
            out.discarded_bytes = out.discarded_bytes.saturating_add(chunk_len);
            accepting = false;
            continue;
        }
        out.written_bytes = out.written_bytes.saturating_add(len_u64(head));
        remaining = remaining.saturating_sub(len_u64(head));
        if !tail.is_empty() {
            accepting = false;
            out.limit_reached = true;
            out.discarded_bytes = out.discarded_bytes.saturating_add(len_u64(tail));
            if plan.marker_room {
                match dst.write_all(TRUNCATION_MARKER) {
                    Ok(()) => out.marker_written = true,
                    Err(e) => out.write_error = Some(e.kind()),
                }
            }
        }
    }
    out
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

impl ConsoleLogSink {
    /// pipe を作り、`file`（検証・追記 open 済み）へ総量 `cap` まで書き出すスレッドを起動する。
    ///
    /// 失敗（ファイル長の取得・pipe 作成・スレッド起動）は `io::Error` で返し、その場合 `file` と pipe は drop で閉じる。
    pub(crate) fn spawn(file: File, cap: u64) -> std::io::Result<ConsoleLogSink> {
        let plan = CapPlan::new(cap, file.metadata()?.len());
        let (reader, writer) = std::io::pipe()?;
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(WRITER_THREAD_NAME.to_string())
            .stack_size(WRITER_THREAD_STACK_BYTES)
            .spawn(move || {
                let outcome = copy_capped(reader, file, plan);
                // 受け手が既に無い（VZ へ渡して取っ手を手放した）なら結果は捨てる。
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

    /// 書き込み端の fd を取り出す（`NSFileHandle` へ所有を移すため）。書き出しスレッドは切り離され、
    /// VZ が書き込み端を手放した時点の EOF で終了する。
    #[cfg(target_os = "macos")]
    pub(crate) fn into_write_fd(self) -> std::os::fd::OwnedFd {
        self.writer.into()
    }
}
