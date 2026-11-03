//! `kill <id> [<signal>]` のシグナル指定の解釈（CLI-1・TASK-79 追補・#1902）。
//!
//! `commands::stop_delete::build_kill_request` が呼ぶ純粋関数だけを置く（ファイルにも環境にも触れず、3 OS で同じ結果になる）。
//!
//! # `stop --signal` との語彙の違い
//!
//! `stop --signal` と CRI の StopSignal は core の `Signal::parse_notation`（Docker の語彙）を使う。`kill` は spec の CLI-1 が
//! 定める厳密な語彙を使うため、別の解釈をここに置く。
//!
//! - 省略は呼び出し側が `SIGTERM`（15）にする。空文字は既定値扱いにせず拒否する（runc は空を既定値として扱う）。
//! - 10 進の番号は、範囲（1〜64）の判定を core の `Signal::new` だけに任せる（範囲外の固定文言は core のもの）。32・33 も受ける（`parse_notation` は拒否する）。
//! - 名前は x86_64 と aarch64 で番号が同じ標準の 31 個の固定表だけを受ける。`TERM` と `SIGTERM` の両形を受け、
//!   大文字小文字は区別する（runc は大文字にしてから照合する）。`RTMIN`・`RTMAX±n`・別名（`IOT`・`CLD`・`POLL`）は拒否する。
//!
//! # 一次情報
//!
//! - runc `kill.go`（v1.5.2・commit `b622a5992f0ba88fda05f2fd037d151b4fc5cc88`）: 空なら SIGTERM、`strconv.Atoi` で読めれば番号として使い、
//!   読めなければ大文字にして `SIG` を補い `unix.SignalNum` で引く。
//! - golang.org/x/sys `unix/zerrors_linux_amd64.go` と `zerrors_linux_arm64.go`（commit `908ab5927565d7c3b733cd0a13e22bd2228bc1bd`）の
//!   `signalList`: 1〜31 の 31 個で、2 アーキテクチャで一致する。下の表はこれと同じ。
//!
//! 表は core の private な名前表と二重になるため、試験で `Signal::parse_notation` と番号が一致することを機械照合する
//! （REPAIR-1・REPAIR-12）。

use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

/// 入力の上限バイト数（`Signal::parse_notation` と同じ）。
const MAX_SIGNAL_TEXT_LEN: usize = 64;

/// 標準シグナルの固定表（`SIG` を外した名前と番号。x86_64 と aarch64 で同じ）。
const STANDARD_SIGNALS: [(&str, u8); 31] = [
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("ILL", 4),
    ("TRAP", 5),
    ("ABRT", 6),
    ("BUS", 7),
    ("FPE", 8),
    ("KILL", 9),
    ("USR1", 10),
    ("SEGV", 11),
    ("USR2", 12),
    ("PIPE", 13),
    ("ALRM", 14),
    ("TERM", 15),
    ("STKFLT", 16),
    ("CHLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
    ("URG", 23),
    ("XCPU", 24),
    ("XFSZ", 25),
    ("VTALRM", 26),
    ("PROF", 27),
    ("WINCH", 28),
    ("IO", 29),
    ("PWR", 30),
    ("SYS", 31),
];

/// 不正な指定の固定エラー（入力値は含めない。`stop --signal` と同じ文言）。
fn invalid() -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, "signal is invalid")
}

/// `kill` のシグナル指定を解釈する。
///
/// 数字だけなら番号（範囲は `Signal::new` が判定）、それ以外は `SIG` を 1 回だけ外した名前を固定表と完全一致で照合する。
pub(super) fn parse_kill_signal(text: &str) -> Result<Signal, TraitError> {
    if text.is_empty() || text.len() > MAX_SIGNAL_TEXT_LEN || !text.is_ascii() {
        return Err(invalid());
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        let n: u8 = text.parse().map_err(|_| invalid())?;
        return Signal::new(n);
    }
    let name = text.strip_prefix("SIG").unwrap_or(text);
    match STANDARD_SIGNALS.iter().find(|(n, _)| *n == name) {
        Some((_, num)) => Signal::new(*num),
        None => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(text: &str) -> Option<u8> {
        parse_kill_signal(text).ok().map(|s| s.as_u8())
    }

    /// CLI-1: 標準の名前（両形）と 1〜64 の番号を受ける。
    #[test]
    fn cli1_kill_signal_accepts_standard_names_and_numbers() {
        for (text, want) in [
            ("TERM", 15),
            ("SIGTERM", 15),
            ("KILL", 9),
            ("SIGKILL", 9),
            ("HUP", 1),
            ("SYS", 31),
            ("SIGUSR1", 10),
            ("1", 1),
            ("32", 32),
            ("33", 33),
            ("64", 64),
            ("010", 10),
        ] {
            assert_eq!(num(text), Some(want), "{text}");
        }
    }

    /// CLI-1・ERR-1: 不正な指定は固定文言の `INVALID_ARGUMENT`。
    #[test]
    fn cli1_kill_signal_rejects_invalid() {
        let long = "A".repeat(65);
        for text in [
            "",
            "0",
            "65",
            "256",
            "99999999999",
            "+9",
            "-1",
            " 9",
            "9 ",
            " TERM",
            "term",
            "SIGterm",
            "SIG",
            "SIGSIGTERM",
            "RTMIN",
            "RTMIN+1",
            "SIGRTMAX",
            "IOT",
            "CLD",
            "POLL",
            "BOGUS",
            "ＴＥＲＭ",
            long.as_str(),
        ] {
            let e = parse_kill_signal(text).expect_err(text);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{text}");
            // 範囲外の番号（0・65）は core の `Signal::new` の固定文言、それ以外は本 module の固定文言。
            let range = text == "0" || text == "65";
            let want = if range {
                "signal number must be in 1..=64"
            } else {
                "signal is invalid"
            };
            assert_eq!(e.message(), want, "{text}");
        }
    }

    /// REPAIR-12: 表は core の `parse_notation` と番号が一致し、1〜31 を重複なく埋める。
    #[test]
    fn repair12_kill_signal_table_matches_core_notation() {
        assert_eq!(STANDARD_SIGNALS.len(), 31);
        for (i, (name, n)) in STANDARD_SIGNALS.iter().enumerate() {
            assert_eq!(usize::from(*n), i + 1, "{name}");
            let bare = Signal::parse_notation(name).ok().map(|s| s.as_u8());
            let prefixed = Signal::parse_notation(&format!("SIG{name}"))
                .ok()
                .map(|s| s.as_u8());
            assert_eq!(bare, Some(*n), "{name}");
            assert_eq!(prefixed, Some(*n), "SIG{name}");
        }
    }
}
