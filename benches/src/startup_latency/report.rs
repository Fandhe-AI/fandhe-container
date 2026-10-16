//! supervisor の結果チャネル（stdout の pipe）から 1 行を読み、分類する（TASK-190・REPAIR-5・REPAIR-3）。
//!
//! 復号は supervisor 側の契約 `StartReport::decode` だけで行い、独自の解析を持たない。読み取りスレッドが行を読み終えた
//! 直後の時刻を一緒に送るため、チャネルの待ち時間は計測区間に入らない。

use fandhe_container_supervisor::start_contract::{MAX_REPORT_LEN, StartReport};
use std::io::{BufRead as _, BufReader, Read};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Instant;

/// 結果 1 行の分類。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    /// `FCSUP1 OK <pid>`。`at` は行を読み終えた時刻。
    Started { pid: u32, at: Instant },
    /// `FCSUP1 ERR ...`。
    Failed { code: &'static str, exit_code: u8 },
    /// 期限内に届かなかった。
    Timeout,
    /// 行が無いまま閉じた。
    Eof,
    /// 復号できない・改行なしで打ち切られた。
    Invalid,
}

/// 読み取りスレッドを起こし、`(読んだ行, 読み終えた時刻)` を 1 回だけ送るチャネルを返す。
/// 読む量は `MAX_REPORT_LEN` で打ち切る（無制限確保の防止）。
pub fn spawn_report_reader<R: Read + Send + 'static>(reader: R) -> Receiver<(Vec<u8>, Instant)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = Vec::new();
        let mut limited = BufReader::new(reader.take(MAX_REPORT_LEN as u64));
        let _ = limited.read_until(b'\n', &mut line);
        let at = Instant::now();
        let _ = tx.send((line, at));
    });
    rx
}

/// 受信結果を分類する。
pub fn classify(received: Result<(Vec<u8>, Instant), RecvTimeoutError>) -> ReportOutcome {
    let (line, at) = match received {
        Ok(v) => v,
        Err(RecvTimeoutError::Timeout) => return ReportOutcome::Timeout,
        Err(RecvTimeoutError::Disconnected) => return ReportOutcome::Eof,
    };
    if line.is_empty() {
        return ReportOutcome::Eof;
    }
    match StartReport::decode(&line) {
        Ok(StartReport::Started { pid }) => ReportOutcome::Started { pid: pid.get(), at },
        Ok(StartReport::Failed {
            code, exit_code, ..
        }) => ReportOutcome::Failed {
            code: code.as_str(),
            exit_code: exit_code.get(),
        },
        // `StartReport` は non_exhaustive。未知の種別も成功扱いにしない。
        Ok(_) | Err(_) => ReportOutcome::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    fn read(bytes: &[u8]) -> ReportOutcome {
        let rx = spawn_report_reader(Cursor::new(bytes.to_vec()));
        classify(rx.recv_timeout(Duration::from_secs(5)))
    }

    #[test]
    fn ok_line_is_started() {
        assert!(matches!(
            read(b"FCSUP1 OK 4242\n"),
            ReportOutcome::Started { pid: 4242, .. }
        ));
    }

    #[test]
    fn err_line_is_failed_with_code() {
        let exit = fandhe_container_core::oci_runtime::exit_code_for(
            fandhe_container_core::traits::ErrorCode::FailedPrecondition,
        )
        .get();
        let line = format!("FCSUP1 ERR FAILED_PRECONDITION {exit} msg\n");
        assert_eq!(
            read(line.as_bytes()),
            ReportOutcome::Failed {
                code: "FAILED_PRECONDITION",
                exit_code: exit
            }
        );
    }

    #[test]
    fn err_line_with_mismatched_exit_code_is_invalid() {
        assert_eq!(
            read(b"FCSUP1 ERR FAILED_PRECONDITION 200 msg\n"),
            ReportOutcome::Invalid
        );
    }

    #[test]
    fn zero_bytes_is_eof() {
        assert_eq!(read(b""), ReportOutcome::Eof);
    }

    #[test]
    fn missing_newline_is_invalid() {
        assert_eq!(read(b"FCSUP1 OK 42"), ReportOutcome::Invalid);
    }

    #[test]
    fn over_long_line_is_invalid() {
        let mut long = b"FCSUP1 ERR INTERNAL 1 ".to_vec();
        long.resize(641, b'x');
        long.push(b'\n');
        assert_eq!(read(&long), ReportOutcome::Invalid);
    }

    /// 読みがブロックしたままなら期限で Timeout になる（REPAIR-5）。
    #[test]
    fn blocked_reader_times_out() {
        struct Blocked;
        impl Read for Blocked {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(500));
                Ok(0)
            }
        }
        let rx = spawn_report_reader(Blocked);
        assert_eq!(
            classify(rx.recv_timeout(Duration::from_millis(50))),
            ReportOutcome::Timeout
        );
    }

    #[test]
    fn disconnected_channel_is_eof() {
        assert_eq!(
            classify(Err(RecvTimeoutError::Disconnected)),
            ReportOutcome::Eof
        );
    }
}
