//! plugin の構造化ログ行を「1 行 1 JSON」の共有検査器で横断照合する（ERR-4・#3122）。
//!
//! TASK-98 の受け入れ条件 2（#653）の照合先のうち plugin 分。plugin は core より下の層で core の
//! 共通ログ型を使えない（#3114 の判断 (f)）ため、core・cli・io と同じ検査器
//! （`tests/support/json_lines_contract.rs`。本 crate と同じ `MIT OR Apache-2.0`）を取り込んで形式を保つ。
//!
//! 対象: `plugin_peer_auth`（拒否 1 行・集約行）・`plugin_child_cleanup`・`grpc_op_stats`（`grpc` feature）。
//! 最大長の入力: `socket_path` は呼び出し元が bind / connect 済みの `sockaddr_un` に縛られる
//! （Linux 108・macOS 104 バイト）ため、その上限内の最大長で見る。`to_json_line` 自体には型としての
//! 上限が無い（製品コードの観察事項。本試験は検査器を緩めず、上限内で 1 行 1 JSON を確かめる）。

use crate::ChildCleanupFailure;
use crate::audit::{
    JsonLinesPeerAuthObserver, PeerAuthObserver, PeerAuthOp, PeerAuthRejectReason,
    PeerAuthRejection,
};
use crate::error::PluginErrorCode;
use std::path::Path;

#[path = "../tests/support/json_lines_contract.rs"]
mod json_lines_contract;
use json_lines_contract::{HOSTILE_TEXT, SHARED_MAX_LOG_LINE_BYTES, check_body, check_stream};

fn rejection(path: &Path) -> PeerAuthRejection<'_> {
    PeerAuthRejection {
        op: PeerAuthOp::Accept,
        reason: PeerAuthRejectReason::UidMismatch,
        code: PluginErrorCode::PermissionDenied,
        expected_uid: 1000,
        peer_uid: Some(1001),
        expected_pid: None,
        peer_pid: None,
        consecutive_rejections: Some(3),
        backoff_ms: Some(200),
        socket_path: path,
    }
}

/// ERR-4・#3122: 拒否行は敵対的・最大長の socket パスでも 1 行 1 JSON で、パスは往復する。
#[test]
fn err4_3122_peer_auth_line_hostile_and_max_path() {
    let hostile = format!("/{HOSTILE_TEXT}");
    let line = rejection(Path::new(&hostile)).to_json_line();
    let f = check_body(&line, SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.event, "plugin_peer_auth");
    assert_eq!(f.level, None);
    assert_eq!(f.str_of("socket_path"), Some(hostile.as_str()));
    assert_eq!(f.str_of("reason"), Some("peer_uid_mismatch"));

    let max = format!("/{}", "\u{1}".repeat(107));
    let line = rejection(Path::new(&max)).to_json_line();
    let f = check_body(&line, SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.str_of("socket_path"), Some(max.as_str()));
    assert!(line.len() < SHARED_MAX_LOG_LINE_BYTES);
}

/// ERR-4・#3122: 非 UTF-8 のパスは置換され `socket_path_lossy` が付く。
#[cfg(unix)]
#[test]
fn err4_3122_peer_auth_line_non_utf8_path_is_lossy() {
    use std::os::unix::ffi::OsStrExt;
    let p = Path::new(std::ffi::OsStr::from_bytes(b"/a\xffb\n"));
    let line = rejection(p).to_json_line();
    let f = check_body(&line, SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.bool_of("socket_path_lossy"), Some(true));
    assert_eq!(f.str_of("socket_path"), Some("/a\u{fffd}b\n"));
}

/// ERR-4・#3122: 受け手の `drain_lines` の全行（容量超過の集約行を含む）が契約を満たす。
#[test]
fn err4_3122_peer_auth_observer_lines_including_coalesced() {
    let mut o = JsonLinesPeerAuthObserver::new();
    let hostile = format!("/{HOSTILE_TEXT}");
    for _ in 0..10_000 {
        o.on_rejection(&rejection(Path::new(&hostile)));
        if o.coalesced_rejections() > 0 {
            break;
        }
    }
    assert!(o.coalesced_rejections() > 0, "capacity must be exceeded");
    let lines = o.drain_lines();
    let (last, rest) = lines.split_last().unwrap();
    for l in rest {
        assert_eq!(
            check_body(l, SHARED_MAX_LOG_LINE_BYTES).unwrap().event,
            "plugin_peer_auth"
        );
    }
    let f = check_body(last, SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.str_of("reason"), Some("peer_auth_rejections_coalesced"));
}

/// ERR-4・#3122: 子の後始末失敗の行。
#[test]
fn err4_3122_child_cleanup_lines() {
    for (failure, reason) in [
        (ChildCleanupFailure::GroupKillFailed, "group_kill_failed"),
        (ChildCleanupFailure::Unreaped { pid: None }, "unreaped"),
        (
            ChildCleanupFailure::Unreaped {
                pid: Some(u32::MAX),
            },
            "unreaped",
        ),
    ] {
        let line = failure.to_json_line();
        let f = check_body(&line, SHARED_MAX_LOG_LINE_BYTES).unwrap();
        assert_eq!(f.event, "plugin_child_cleanup");
        assert_eq!(f.str_of("reason"), Some(reason));
    }
}

/// ERR-4・#3122: gRPC の操作統計（LF 終端の複数行）。
#[cfg(feature = "grpc")]
#[test]
fn err4_3122_grpc_op_stats_lines() {
    let mut buf = Vec::new();
    crate::grpc::export_stats_json_lines(&mut buf).unwrap();
    let facts = check_stream(&buf, SHARED_MAX_LOG_LINE_BYTES).unwrap();
    let ops: Vec<_> = facts.iter().map(|f| f.str_of("op").unwrap()).collect();
    assert_eq!(ops, ["serve", "connect", "call"]);
    assert!(facts.iter().all(|f| f.event == "grpc_op_stats"));
}

/// ERR-4・#3122: 複数の拒否行を LF で連結した出力（書き出し先の形）が全体として契約を満たす。
#[test]
fn err4_3122_concatenated_output_is_valid_stream() {
    let mut out = String::new();
    for p in ["/a", "/b\n/c", "/d\"e"] {
        out.push_str(&rejection(Path::new(p)).to_json_line());
        out.push('\n');
    }
    assert_eq!(
        check_stream(out.as_bytes(), SHARED_MAX_LOG_LINE_BYTES)
            .unwrap()
            .len(),
        3
    );
}
