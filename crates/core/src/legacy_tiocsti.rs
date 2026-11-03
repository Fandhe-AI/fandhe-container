//! `dev.tty.legacy_tiocsti` の観測と警告ログ（TASK-29 追補・`CORE-5`・`SEC-1`・`REPAIR-4`・#1658 の案 A・#1739）。
//!
//! # 役割
//!
//! `TIOCSTI` は端末の入力キューへ 1 文字ずつ注入できる ioctl で、制御端末を共有するプロセスの間で入力を
//! 偽装できてしまう。本リポのコンテナは、(1) `setsid` で制御端末を持たない、(2) ホストの端末 fd を渡さない、
//! (3) コンテナ専用の独立した devpts を持つ、(4) 既定の capability に `CAP_SYS_ADMIN` を含まない、という
//! 4 つの前提のもとで、`TIOCSTI` が届くのをコンテナ自身の pty だけに限っている。この前提が崩れたときに
//! 運用者が危険度を見積もれるよう、起動時にカーネルの sysctl を読んで、有効なら警告を 1 行出す。
//!
//! #1658 のオーナー判断（2026-10-11）は「案 A（本モジュール）＋案 C（端末機能の実装時に前提を確かめ直す）」で、
//! seccomp で ioctl を request 単位で拒否する案 B は採らない（`seccomp` の引数を読まない拒否リストの契約を
//! 変えないため）。本モジュールは観測だけを行い、結果で起動の可否・seccomp・capability・Landlock を変えない。
//!
//! # 結果の区別と出力
//!
//! 5 つの場合を [`LegacyTiocsti`] で区別する。警告を出すのは `1`（[`LegacyTiocsti::Enabled`]）のときだけで、
//! 他の 4 つは出力せず戻り値で区別できる。
//!
//! - `Absent`: sysctl のファイルが無い。**安全という意味ではない**: 6.2 未満のカーネルでは `TIOCSTI` が
//!   無条件で使える。無音にするのは #1739 のスコープによる。6.2 以降で `CONFIG_LEGACY_TIOCSTI=n` のときに
//!   ファイルが存在するかは確認していないため断定しない（どちらでも「sysctl で制御できない」として扱う）
//! - `Disabled`・`Enabled`: 内容が `0`・`1`
//! - `Unexpected`: 上記以外・空・読み取り上限の超過
//! - `ReadFailed`: `NotFound` 以外の I/O 失敗
//!
//! procfs の内容は外部入力として扱う。読み取りは固定の上限で打ち切り、上限を超えたら解釈しない。ログの 1 行は
//! 固定の本体を共通ログ型 [`LogLine`]（level `warn`。`ERR-4`・#3117）で組んだもので、procfs の内容・パス・
//! errno 文字列を含めない（ログ行の偽装を防ぐ。`REPAIR-4`）。出力のバイト列は移行前の固定文字列と同一。
//!
//! # 呼び出し元
//!
//! `exec::spawn_container_with_stages`（`spawn_container` を含む従来経路。結合試験専用・`exec-test-support`）と、本番 launcher の入口
//! `exec::spawn_container_via_intermediate`（#2008）が、fork に成功した後、親の側で 1 回呼ぶ。
//! 出力は core の診断ログの共通経路（`exec::emit_diagnostic_line_to`。AF_UNIX の socket 以外へは書かず、満杯でも
//! 待たない。REPAIR-5）で、`exec::report_legacy_tiocsti_to` が行い、結果を `exec::LegacyTiocstiReport` で返す。
//! 本モジュールは OS 非依存の観測と固定 1 行の生成だけを持ち、出力はしない。
//! supervisor は start の成功後に同じ [`read_host`] と [`warning_line`] で自分のログ（`@supervisor-logs`）へも
//! 1 行残す（stderr が AF_UNIX の socket でない構成では上の出力が捨てられるため。#2008）。`/proc/sys/dev/tty/legacy_tiocsti` はグローバルな値で、
//! 親の user namespace から読んでも子と同じ値になる。非 Linux では常に `Absent` になり、呼び出し元は無い。

use std::io::{self, Read};
use std::path::Path;
use std::sync::OnceLock;

use serde::Serialize;

use crate::logging::{LogEvent, LogLevel, LogLine, encode_json_line};

/// 読む sysctl のパス。固定で、利用者の入力は入らない。
pub const LEGACY_TIOCSTI_PATH: &str = "/proc/sys/dev/tty/legacy_tiocsti";

/// sysctl 名（ログ用の固定語彙）。
pub const SYSCTL_NAME: &str = "dev.tty.legacy_tiocsti";

/// 読み取りの上限（バイト）。正しい内容は `0\n`・`1\n` の 2 バイトで、これを超える内容は解釈しない。
pub const LEGACY_TIOCSTI_READ_CAP: usize = 16;

/// 観測結果。`Enabled` 以外は警告を出さない（戻り値で区別する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LegacyTiocsti {
    /// ファイルが無い（6.2 未満のカーネル等）。安全という意味ではない。
    Absent,
    /// 内容が `0`（旧来の `TIOCSTI` を制限している）。
    Disabled,
    /// 内容が `1`（警告の対象）。
    Enabled,
    /// 上記以外の内容・空・読み取り上限の超過。
    Unexpected,
    /// `NotFound` 以外の I/O 失敗。OS 由来の文字列は持たず、種別だけを持つ。
    ReadFailed {
        /// 失敗の種別。
        kind: io::ErrorKind,
    },
}

impl LegacyTiocsti {
    /// 固定語彙の名前を返す（診断・将来のログ用）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Unexpected => "unexpected",
            Self::ReadFailed { .. } => "read_failed",
        }
    }
}

/// 内容（バイト列）を解釈する純粋関数。長さを先に確かめ、末尾の LF を 1 個だけ外して `0`・`1` と比較する。
pub fn parse(content: &[u8]) -> LegacyTiocsti {
    if content.len() > LEGACY_TIOCSTI_READ_CAP {
        return LegacyTiocsti::Unexpected;
    }
    let body = content.strip_suffix(b"\n").unwrap_or(content);
    if body == b"0" {
        LegacyTiocsti::Disabled
    } else if body == b"1" {
        LegacyTiocsti::Enabled
    } else {
        LegacyTiocsti::Unexpected
    }
}

/// 読み取り結果を分類する純粋関数。`NotFound` は `Absent`、他の失敗は `ReadFailed`。
pub fn classify(read: io::Result<&[u8]>) -> LegacyTiocsti {
    match read {
        Ok(bytes) => parse(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => LegacyTiocsti::Absent,
        Err(e) => LegacyTiocsti::ReadFailed { kind: e.kind() },
    }
}

/// `path` を上限つきで読んで分類する。上限 + 1 バイトまで読み、超過は `parse` が `Unexpected` にする
/// （切り詰めた内容を解釈しない）。パスは定数か試験の一時ファイルだけで、利用者の入力は入らない。
pub fn read_from(path: &Path) -> LegacyTiocsti {
    let result = std::fs::File::open(path).and_then(|file| {
        let mut buf = Vec::with_capacity(LEGACY_TIOCSTI_READ_CAP + 1);
        file.take(LEGACY_TIOCSTI_READ_CAP as u64 + 1)
            .read_to_end(&mut buf)?;
        Ok(buf)
    });
    match result {
        Ok(buf) => classify(Ok(&buf)),
        Err(e) => classify(Err(e)),
    }
}

/// ホストの sysctl を読む。非 Linux では `/proc` が無く常に `Absent` になる。
pub fn read_host() -> LegacyTiocsti {
    read_from(Path::new(LEGACY_TIOCSTI_PATH))
}

/// 警告行の本体（`level`・`event` は封筒 [`LogLine`] が持つため含めない。予約キーの重複は試験で検出する）。
/// フィールドの宣言順が出力のキー順になる。
#[derive(Serialize)]
struct LegacyTiocstiWarning {
    sysctl: &'static str,
    value: u32,
}

/// 警告行の本体。定数だけで、外部入力は入らない。
const WARNING_BODY: LegacyTiocstiWarning = LegacyTiocstiWarning {
    sysctl: SYSCTL_NAME,
    value: 1,
};

/// 警告行のイベント名。規則に合わなければ const 評価でコンパイルが失敗し、実行時には panic しない。
const WARNING_EVENT: LogEvent = match LogEvent::from_static("legacy_tiocsti_enabled") {
    Some(e) => e,
    None => panic!("invalid log event name"),
};

/// 共通ログ型で警告行（末尾の LF を除く）を組む。符号化できなければ `None`
/// （本体は定数のため通らない。通れば厳密 JSON の試験が失敗して検出する）。
fn encode_warning_line() -> Option<String> {
    let line = LogLine::new(WARNING_EVENT, &WARNING_BODY).with_level(LogLevel::Warn);
    let bytes = encode_json_line(&line).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    text.strip_suffix('\n').map(str::to_owned)
}

/// `Enabled` のときの固定の 1 行（改行を含まない。改行は呼び出し元が付ける）。他の状態では `None`。
///
/// 共通ログ型 [`LogLine`]（level `warn`）で初回だけ組み、以降は同じ文字列を返す（ERR-4・#3117）。
/// 初回の確保を伴うため、fork した子の中では呼ばない（呼び出し元は fork 成功後の親の側か、
/// supervisor の start 成功後）。
pub fn warning_line(state: LegacyTiocsti) -> Option<&'static str> {
    match state {
        LegacyTiocsti::Enabled => {
            static LINE: OnceLock<Option<String>> = OnceLock::new();
            LINE.get_or_init(encode_warning_line).as_deref()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestTempDir;

    const LINE: &str = "{\"level\":\"warn\",\"event\":\"legacy_tiocsti_enabled\",\"sysctl\":\"dev.tty.legacy_tiocsti\",\"value\":1}";

    #[test]
    fn core5_sec1_1739_parse_enabled_and_disabled() {
        assert_eq!(parse(b"1\n"), LegacyTiocsti::Enabled);
        assert_eq!(parse(b"1"), LegacyTiocsti::Enabled);
        assert_eq!(parse(b"0\n"), LegacyTiocsti::Disabled);
        assert_eq!(parse(b"0"), LegacyTiocsti::Disabled);
    }

    #[test]
    fn core5_sec1_1739_parse_unexpected() {
        for c in [
            &b"2\n"[..],
            b"",
            b"\n",
            b" 1\n",
            b"1\n\n",
            b"01\n",
            b"\xff\n",
        ] {
            assert_eq!(parse(c), LegacyTiocsti::Unexpected, "{c:?}");
        }
        let over = vec![b'1'; LEGACY_TIOCSTI_READ_CAP + 1];
        assert_eq!(parse(&over), LegacyTiocsti::Unexpected);
    }

    #[test]
    fn core5_sec1_1739_classify_errors() {
        assert_eq!(
            classify(Err(io::Error::from(io::ErrorKind::NotFound))),
            LegacyTiocsti::Absent
        );
        assert_eq!(
            classify(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            LegacyTiocsti::ReadFailed {
                kind: io::ErrorKind::PermissionDenied
            }
        );
        assert_eq!(classify(Ok(b"1\n")), LegacyTiocsti::Enabled);
    }

    #[test]
    fn core5_sec1_1739_read_from_files() {
        let dir = TestTempDir::new("legacy-tiocsti").unwrap();
        let cases: [(&str, &[u8], LegacyTiocsti); 4] = [
            ("one", b"1\n", LegacyTiocsti::Enabled),
            ("zero", b"0\n", LegacyTiocsti::Disabled),
            ("junk", b"x\n", LegacyTiocsti::Unexpected),
            ("long", &[b'1'; 32], LegacyTiocsti::Unexpected),
        ];
        for (name, content, expected) in cases {
            let p = dir.path().join(name);
            std::fs::write(&p, content).unwrap();
            assert_eq!(read_from(&p), expected, "{name}");
        }
        assert_eq!(
            read_from(&dir.path().join("missing")),
            LegacyTiocsti::Absent
        );
        match read_from(dir.path()) {
            LegacyTiocsti::ReadFailed { kind } => assert_ne!(kind, io::ErrorKind::NotFound),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn core5_sec1_1739_warning_line_exact_json() {
        let line = warning_line(LegacyTiocsti::Enabled).unwrap();
        assert_eq!(line, LINE);
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert_eq!(obj["level"], "warn");
        assert_eq!(obj["event"], "legacy_tiocsti_enabled");
        assert_eq!(obj["sysctl"], SYSCTL_NAME);
        assert_eq!(obj["value"], 1);
        assert!(!line.contains('\n') && !line.contains('\r'));
    }

    #[test]
    fn core5_sec1_1739_other_states_have_no_line() {
        for s in [
            LegacyTiocsti::Absent,
            LegacyTiocsti::Disabled,
            LegacyTiocsti::Unexpected,
            LegacyTiocsti::ReadFailed {
                kind: io::ErrorKind::PermissionDenied,
            },
        ] {
            assert_eq!(warning_line(s), None, "{s:?}");
        }
    }

    #[test]
    fn err4_3117_warning_body_has_no_reserved_keys() {
        let v = serde_json::to_value(WARNING_BODY).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["sysctl", "value"]);
        assert!(!obj.contains_key("level") && !obj.contains_key("event"));
    }

    #[test]
    fn err4_3117_warning_line_built_via_log_line() {
        assert_eq!(WARNING_EVENT.as_str(), "legacy_tiocsti_enabled");
        let line = warning_line(LegacyTiocsti::Enabled).unwrap();
        let expected = encode_json_line(
            &LogLine::new(WARNING_EVENT, &WARNING_BODY).with_level(LogLevel::Warn),
        )
        .unwrap();
        assert_eq!(format!("{line}\n").into_bytes(), expected);
        assert_eq!(warning_line(LegacyTiocsti::Enabled), Some(line));
    }

    #[test]
    fn core5_sec1_1739_as_str_vocabulary() {
        assert_eq!(LegacyTiocsti::Absent.as_str(), "absent");
        assert_eq!(LegacyTiocsti::Disabled.as_str(), "disabled");
        assert_eq!(LegacyTiocsti::Enabled.as_str(), "enabled");
        assert_eq!(LegacyTiocsti::Unexpected.as_str(), "unexpected");
        assert_eq!(
            LegacyTiocsti::ReadFailed {
                kind: io::ErrorKind::Other
            }
            .as_str(),
            "read_failed"
        );
    }
}
