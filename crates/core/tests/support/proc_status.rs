//! 期限切れの診断として、生きている子の `/proc/<pid>/status` の要点を失敗メッセージへ載せる共有ヘルパー。
//!
//! 各テストバイナリが `#[path = "support/proc_status.rs"] mod proc_status;` で取り込む（`temp_rootfs.rs` と同じ形）。
//! 呼び出し元は SIGSYS で死ぬ子を待つ試験（`seccomp_enforcement`・`seccomp_kill_audit`・`seccomp`・
//! `escape_suite`・`production_launcher`）の期限切れ分岐で、子を kill する前に呼ぶ。製品コードからは使われない。
//!
//! 背景: SIGSYS の既定動作は core dump で、`core_pattern` がパイプ形式（apport 等）だと helper が終わるまで
//! 子を回収できず、並列の試験の `wait` が期限切れになる（#2538・#2629。REPAIR-4・REPAIR-5・REPAIR-12）。
//! `CoreDumping: 1` なら、この遅延が原因と一目で判別できる。
//! 子が non-dumpable でも `status` は 0444 のため親から読める。

use std::fs::File;
use std::io::Read as _;

/// `/proc/<pid>/status` を読む上限（外部入力の上限規約）。
const MAX_STATUS_BYTES: u64 = 64 * 1024;

/// `State:` と `CoreDumping:` の行を ` | ` で連結して返す。読めなければ `<unavailable>`。
#[allow(dead_code)]
pub fn excerpt(pid: u32) -> String {
    let mut text = String::new();
    let read = File::open(format!("/proc/{pid}/status"))
        .and_then(|f| f.take(MAX_STATUS_BYTES).read_to_string(&mut text));
    if read.is_err() {
        return "<unavailable>".to_string();
    }
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("State:") || l.starts_with("CoreDumping:"))
        .collect();
    if lines.is_empty() {
        "<unavailable>".to_string()
    } else {
        format!("/proc/{pid}/status: {}", lines.join(" | "))
    }
}
