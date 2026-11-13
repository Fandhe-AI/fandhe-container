//! core の書き出し口の出力を「1 行 1 JSON」の共有検査器で横断照合する（ERR-4・#3122）。
//!
//! TASK-98 の受け入れ条件 2（#653）「journald / syslog へ転送できる形式であることを確かめる試験」の
//! 照合先。監査（`audit`・`audit_write_failure`）・可観測性（`op_stats`・`op_stats_meta`）・警告
//! （`legacy_tiocsti_enabled`・`plugin_path_candidate`）・エラー（`oci_runtime_error`）の各書き出し口が
//! バッファへ書いた行を、plugin 配下の共有検査器（`crates/plugin/tests/support/json_lines_contract.rs`）で
//! 検査する。io・plugin は core へ依存できない（#3114 (f)）ため、同じ検査器を取り込んで形式を保つ。
//!
//! # 対象と除外
//!
//! - #3114 (b) で対象の書き出し口はすべて `event` を持つため、`event` なしで除外する行は無い。
//! - 対象外: cli の stdout のデータ出力（ログ行ではない）、3 系統の外の他 crate の行。
//! - `legacy_tiocsti_enabled` は `exec` が Linux 専用のため、全 OS で `warning_line` に呼び出し元の契約どおり
//!   LF を足した形を照合する（socket への送出自体は exec の試験の責務）。
//! - 監査は `encode_json_line`（`write_record` が書くのと同じ符号化）の出力を照合する。

#[path = "../../../plugin/tests/support/json_lines_contract.rs"]
mod json_lines_contract;

use json_lines_contract::{
    HOSTILE_TEXT, JOURNALD_LINE_MAX_DEFAULT, LineFacts, SHARED_MAX_LOG_LINE_BYTES, Violation,
    check_body, check_stream,
};

use super::MAX_LOG_LINE_BYTES;
use crate::audit_log::{
    AuditEvent, AuditFileWriter, AuditPath, AuditPid, AuditRecord, AuditTimestamp, NoAuditFallback,
    encode_json_line, write_with_fallback,
};
use crate::observability::{MAX_TRACKED_OPS, OpName, OpOutcome, OpRecorder};
use crate::oci_runtime::{LifecycleOp, OciRuntimeError};
use crate::plugin_discovery::PathSearchWarning;
use crate::traits::{ContainerId, ErrorCode, TraitError};
use std::path::PathBuf;
use std::time::Duration;

/// 表示を乱す文字が空白へ置換された `HOSTILE_TEXT` の具体値。
const HOSTILE_SANITIZED: &str = "a b c d e [31mf g h i j k l m\"n\\oあ";

fn stream(bytes: &[u8]) -> Vec<LineFacts> {
    check_stream(bytes, MAX_LOG_LINE_BYTES).expect("contract")
}

fn audit_bytes(path: &str, cid: Option<&str>) -> Vec<u8> {
    let mut r = AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
        AuditPid::new(7).unwrap(),
        AuditEvent::Landlock {
            path: AuditPath::new(path),
            syscall: None,
        },
    );
    if let Some(c) = cid {
        r = r.with_container_id(ContainerId::new(c).unwrap());
    }
    encode_json_line(&r).expect("encode")
}

/// ERR-4・#3122: 検査器は serde_json と同じ判定をする（差分照合）。
#[test]
fn err4_3122_checker_agrees_with_serde_json() {
    let accept: &[&str] = &[
        "{\"event\":\"x\"}\n",
        "{\"level\":\"warn\",\"event\":\"x\",\"a\":[1,-0,1e5,2.5E-3,null,true,{\"k\":\"\\u00e9\\ud83d\\ude00\"}]}\n",
        "{\"event\":\"x\",\"s\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"}\n",
    ];
    for l in accept {
        assert!(check_stream(l.as_bytes(), 4096).is_ok(), "accept {l:?}");
        assert!(serde_json::from_str::<serde_json::Value>(l.trim_end()).is_ok());
    }
    // 検査器が拒否するもの。JSON として読めない行は serde_json も拒否する。
    let not_json: &[&str] = &[
        "{\"event\":\"x\",\"s\":\"\\x\"}\n",
        "{\"event\":\"x\",\"s\":\"\\ud800\"}\n",
        "{\"event\":\"x\",\"s\":\"\\udc00\"}\n",
        "{\"event\":\"x\",\"n\":01}\n",
        "{\"event\":\"x\",\"n\":1.}\n",
        "{\"event\":\"x\",\"n\":+1}\n",
        "{\"event\":\"x\",}\n",
        "{\"event\":\"x\"\n",
        "{\"event\":\"x\",\"s\":\"a\u{1}b\"}\n",
        "{'event':'x'}\n",
    ];
    for l in not_json {
        assert!(
            matches!(
                check_stream(l.as_bytes(), 4096),
                Err(Violation::NotJson { .. })
            ),
            "reject {l:?}: {:?}",
            check_stream(l.as_bytes(), 4096)
        );
        assert!(serde_json::from_str::<serde_json::Value>(l.trim_end()).is_err());
    }
    let deep = format!(
        "{{\"event\":\"x\",\"a\":{}1{}}}\n",
        "[".repeat(40),
        "]".repeat(40)
    );
    assert!(matches!(
        check_stream(deep.as_bytes(), 4096),
        Err(Violation::NotJson { .. })
    ));
    // 構造の契約違反（JSON としては読めるものを含む）。
    let cases: &[(&str, Violation)] = &[
        ("", Violation::Empty),
        ("{\"event\":\"x\"}", Violation::MissingTrailingLf),
        ("{\"event\":\"x\"}\n\n", Violation::EmptyLine(1)),
        ("{\"event\":\"x\"}\r\n", Violation::CarriageReturn(0)),
        ("[1]\n", Violation::NotObject(0)),
        ("\"s\"\n", Violation::NotObject(0)),
        (
            "{\"event\":\"x\"}{\"event\":\"y\"}\n",
            Violation::TrailingData(0),
        ),
        (
            " {\"event\":\"x\"}\n",
            Violation::NotJson { line: 0, offset: 0 },
        ),
        ("{\"event\":\"x\"} \n", Violation::TrailingData(0)),
        (
            "{\"event\":\"x\",\"event\":\"y\"}\n",
            Violation::DuplicateKey(0),
        ),
        ("{\"a\":1}\n", Violation::MissingEvent(0)),
        ("{\"event\":1}\n", Violation::EventNotString(0)),
        ("{\"event\":\"Bad Name\"}\n", Violation::BadEventName(0)),
        ("{\"event\":\"\"}\n", Violation::BadEventName(0)),
        ("{\"a\":1,\"event\":\"x\"}\n", Violation::BadKeyOrder(0)),
        (
            "{\"event\":\"x\",\"level\":\"warn\"}\n",
            Violation::BadKeyOrder(0),
        ),
        (
            "{\"level\":\"loud\",\"event\":\"x\"}\n",
            Violation::BadLevel(0),
        ),
        ("{\"level\":1,\"event\":\"x\"}\n", Violation::BadLevel(0)),
        ("{\"level\":null,\"event\":\"x\"}\n", Violation::BadLevel(0)),
        ("{\"event\":\"x\",\"level\":1}\n", Violation::BadLevel(0)),
        ("{\"event\":\"x\",\"level\":null}\n", Violation::BadLevel(0)),
        (
            "{\"event\":\"x\",\"k\":\"\u{3042}\"}\n",
            Violation::TooLong { line: 0, len: 23 },
        ),
    ];
    for (i, (input, want)) in cases.iter().enumerate() {
        let max = if i == cases.len() - 1 { 22 } else { 4096 };
        assert_eq!(
            check_stream(input.as_bytes(), max).unwrap_err(),
            *want,
            "case {input:?}"
        );
    }
    assert_eq!(
        check_stream(b"{\"event\":\"x\"}\xff\n", 4096).unwrap_err(),
        Violation::NotUtf8(0)
    );
    assert_eq!(
        check_body("{\"event\":\"x\"}\n", 4096).unwrap_err(),
        Violation::EmbeddedLf
    );
    // LF を生で含む偽装は 2 行に分かれ、2 行目が契約違反になる。
    assert_eq!(
        check_stream(b"{\"event\":\"x\",\"m\":\"a\nb\"}\n", 4096).unwrap_err(),
        Violation::NotJson {
            line: 0,
            offset: 19
        }
    );
}

/// ERR-4・#3122: 定数の一致と、デコード後の往復。
#[test]
fn err4_3122_checker_constants_and_roundtrip() {
    assert_eq!(SHARED_MAX_LOG_LINE_BYTES, MAX_LOG_LINE_BYTES);
    const { assert!(MAX_LOG_LINE_BYTES < JOURNALD_LINE_MAX_DEFAULT) };
    let v = serde_json::json!({ "event": "x", "m": HOSTILE_TEXT });
    let line = format!("{v}\n");
    let facts = stream(line.as_bytes());
    assert_eq!(facts[0].str_of("m"), Some(HOSTILE_TEXT));
}

/// ERR-4・#3122: OCI エラー行。敵対的な message は空白へ置換され、`truncated` は出ない。
#[test]
fn err4_3122_oci_runtime_error_hostile_and_max() {
    let mut buf = Vec::new();
    OciRuntimeError::new(
        LifecycleOp::Create,
        ErrorCode::InvalidArgument,
        HOSTILE_TEXT,
    )
    .write_json_line(&mut buf)
    .unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.level.as_deref(), Some("error"));
    assert_eq!(f.event, "oci_runtime_error");
    assert_eq!(f.keys_vec(), ["level", "event", "op", "code", "message"]);
    assert_eq!(f.str_of("message"), Some(HOSTILE_SANITIZED));

    // 引用符だけの 4096 バイト: エスケープで約 2 倍になっても 1 行に収まり、切り詰めない。
    let mut buf = Vec::new();
    OciRuntimeError::new(LifecycleOp::Start, ErrorCode::Internal, "\"".repeat(4096))
        .write_json_line(&mut buf)
        .unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.str_of("message").map(str::len), Some(4096));
    assert_eq!(f.bool_of("truncated"), None);
    assert!(buf.len() < 9 * 1024);

    let mut buf = Vec::new();
    OciRuntimeError::new(LifecycleOp::Kill, ErrorCode::Internal, "a".repeat(4097))
        .write_json_line(&mut buf)
        .unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.str_of("message").map(str::len), Some(4096));
    assert_eq!(f.bool_of("truncated"), Some(true));

    let mut buf = Vec::new();
    OciRuntimeError::from_trait_error(
        LifecycleOp::Delete,
        TraitError::new(ErrorCode::Internal, "\n".repeat(9000)),
    )
    .write_json_line(&mut buf)
    .unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.bool_of("truncated"), Some(true));
    assert!(f.str_of("message").unwrap().chars().all(|c| c == ' '));
}

/// ERR-4・#3122: 監査行。最悪ケース（制御文字だけの最大長パス）でも 1 行に収まり、値は往復する。
#[test]
fn err4_3122_audit_worst_case_and_hostile_path() {
    let cid = "c".repeat(255);
    let path = "\u{1}".repeat(4096);
    let bytes = audit_bytes(&path, Some(&cid));
    let f = &stream(&bytes)[0];
    assert_eq!(f.event, "audit");
    assert_eq!(f.level, None);
    assert_eq!(f.str_of("path"), Some(path.as_str()));
    assert_eq!(f.bool_of("path_truncated"), Some(false));
    assert_eq!(f.str_of("container_id"), Some(cid.as_str()));
    assert!(bytes.len() <= MAX_LOG_LINE_BYTES);

    let long = "a".repeat(5000);
    let bytes = audit_bytes(&long, None);
    let f = &stream(&bytes)[0];
    assert_eq!(f.bool_of("path_truncated"), Some(true));
    assert_eq!(f.str_of("path").map(str::len), Some(4096));

    // 監査は置換せずエスケープだけで、値は元のまま往復する。
    let bytes = audit_bytes(&format!("/{HOSTILE_TEXT}"), None);
    let f = &stream(&bytes)[0];
    assert_eq!(f.str_of("path"), Some(format!("/{HOSTILE_TEXT}").as_str()));
    assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);

    // 複数レコードの追記は行数どおり。
    let mut all = audit_bytes("/a", None);
    all.extend(audit_bytes("/b", Some("x")));
    assert_eq!(stream(&all).len(), 2);
}

/// ERR-4・#3122: 両経路失敗の行は固定トークンだけで、キー順が固定。
#[test]
fn err4_3122_audit_write_failure_line() {
    let mut w = AuditFileWriter::from_file_unchecked(
        std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap(),
    );
    let rec = AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
        AuditPid::new(7).unwrap(),
        AuditEvent::Mount {
            path: None,
            reason: None,
        },
    );
    let failure = write_with_fallback(&mut w, &mut NoAuditFallback, &rec).unwrap_err();
    let mut buf = Vec::new();
    failure.write_json_line(&mut buf).unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.event, "audit_write_failure");
    assert_eq!(
        f.keys_vec(),
        [
            "event",
            "code",
            "primary",
            "primary_code",
            "fallback",
            "fallback_code"
        ]
    );
    assert_eq!(f.str_of("code"), Some("INTERNAL"));
}

/// ERR-4・#3122: op_stats は上限種類数でも全行が契約を満たし、敵対的な名前は作れない。
#[test]
fn err4_3122_op_stats_all_ops() {
    assert_eq!(
        OpName::new(HOSTILE_TEXT).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    let r = OpRecorder::new();
    for i in 0..MAX_TRACKED_OPS {
        let name = OpName::new(format!("{i:02}{}", "o".repeat(62))).unwrap();
        r.record(&name, OpOutcome::Success, Duration::from_millis(1))
            .unwrap();
    }
    let mut buf = Vec::new();
    r.export_json_lines(Some(&mut buf)).unwrap();
    let facts = stream(&buf);
    assert_eq!(facts.len(), MAX_TRACKED_OPS + 1);
    assert!(
        facts[..MAX_TRACKED_OPS]
            .iter()
            .all(|f| f.event == "op_stats")
    );
    assert_eq!(facts[MAX_TRACKED_OPS].event, "op_stats_meta");
}

/// ERR-4・#3122: legacy_tiocsti の警告行。
#[test]
fn err4_3122_legacy_tiocsti_line() {
    let line = crate::legacy_tiocsti::warning_line(crate::legacy_tiocsti::LegacyTiocsti::Enabled)
        .expect("line");
    let bytes = format!("{line}\n").into_bytes();
    let f = &stream(&bytes)[0];
    assert_eq!(f.level.as_deref(), Some("warn"));
    assert_eq!(f.event, "legacy_tiocsti_enabled");
    assert_eq!(f.str_of("sysctl"), Some("dev.tty.legacy_tiocsti"));
}

/// ERR-4・REPAIR-4・#2245: 中断された start の回復結果の行は共有検査器を通り、level `info`・
/// 本体は `outcome` の固定語彙だけ（キー順 `level, event, outcome`）。
#[test]
fn err4_2245_interrupted_start_recovered_line() {
    use crate::oci_runtime::{NoProcessEvidence, RecordedCgroupOutcome, RecoveredStart};
    use crate::traits::{ContainerStatus, StateRecord, StateRevision};
    let rec = StateRecord::new(
        ContainerStatus::created(ContainerId::new("web").unwrap(), None),
        std::env::temp_dir().join("b"),
        StateRevision::from_raw(1),
    )
    .unwrap();
    let bytes = RecoveredStart::for_test(
        rec,
        NoProcessEvidence::RecordedCgroup(RecordedCgroupOutcome::Killed),
    )
    .encode_log_line()
    .unwrap();
    let f = &stream(&bytes)[0];
    assert_eq!(f.level.as_deref(), Some("info"));
    assert_eq!(f.event, "interrupted_start_recovered");
    assert_eq!(f.str_of("outcome"), Some("killed"));
}

/// ERR-4・#3122: PATH 警告は敵対的・最大長のパスでも 1 行で、警告が先・エラーが最終行（#3114 (d)）。
#[test]
fn err4_3122_path_warning_hostile_and_ordering() {
    let hostile = PathBuf::from(format!("/{HOSTILE_TEXT}{}", "a".repeat(5000)));
    let mut buf = Vec::new();
    PathSearchWarning::for_test("cri", hostile)
        .write_line(&mut buf)
        .unwrap();
    let f = &stream(&buf)[0];
    assert_eq!(f.bool_of("truncated"), Some(true));
    let p = f.str_of("path").unwrap();
    assert_eq!(p.len(), 4096);
    assert!(p.starts_with(&format!("/{HOSTILE_SANITIZED}")));

    let worst = PathBuf::from(format!("/{}", "\"\\".repeat(2047)));
    let mut buf = Vec::new();
    PathSearchWarning::for_test("cri", worst)
        .write_line(&mut buf)
        .unwrap();
    assert!(buf.len() < MAX_LOG_LINE_BYTES);
    stream(&buf);

    // 連続した stderr を模す: 警告 2 行 → エラー行。
    let mut buf = Vec::new();
    PathSearchWarning::for_test("a", PathBuf::from("/x"))
        .write_line(&mut buf)
        .unwrap();
    PathSearchWarning::for_test("b", PathBuf::from("/y"))
        .write_line(&mut buf)
        .unwrap();
    OciRuntimeError::new(LifecycleOp::Create, ErrorCode::NotFound, "gone")
        .write_json_line(&mut buf)
        .unwrap();
    let facts = stream(&buf);
    let events: Vec<&str> = facts.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(
        events,
        [
            "plugin_path_candidate",
            "plugin_path_candidate",
            "oci_runtime_error"
        ]
    );
}
