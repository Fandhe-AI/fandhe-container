//! rootless 系の実機前提テストが、シナリオの終了後に呼び出しプロセスの子を残していないことを fail-closed で
//! 照合する共有部品（CORE-1・CORE-2・REPAIR-5・REPAIR-1。#2436）。
//!
//! 各テストが `#[path = "support/leftover_children.rs"] mod leftover_children;` で取り込む
//! （`temp_rootfs.rs`・`real_entry.rs` と同じ形。`tests/support/` は cargo の自動検出の対象外）。
//! 呼び出し元は `rootless`・`rootless_file_owner`・`rootless_uid_mapping`（本番 launcher が呼び出し側を child
//! subreaper にするため、再親付けされた PID 1・holder・mapper が見える）と `rootless_launch`（dispatcher が自分で
//! `ChildSubreaper::enable` を呼ぶ）。製品コードからは使われない。
//!
//! # 契約
//! - [`children_of_self`] は `/proc/self/task/*/children` を読む。読めなければ panic（検証せずに成功しない）
//! - [`assert_no_leftover_children`] は `limit` までポーリングし、空になれば戻る（待ちは必ず期限つき。REPAIR-5）。
//!   期限を過ぎて残っていれば、残りを kill・回収してから pid の一覧つきで panic する。実機にプロセスを残さない
//! - 回収対象の pid は自プロセスの子の一覧（カーネルが提供する値）から得る。子は回収するまで pid が再利用されない
//!   ため、別プロセスへの取り違えは起きない。状態に記録された pid や外部入力の pid には送らない（SEC-1）

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{ChildSubreaper, ContainerChild};

/// 残った子を kill した後に回収を待つ上限。
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// 呼び出しプロセスの子（全スレッド分）の pid 一覧。読めなければ panic（fail-closed）。
pub fn children_of_self() -> Vec<u32> {
    let mut out = Vec::new();
    let tasks = std::fs::read_dir("/proc/self/task").expect("read /proc/self/task");
    for t in tasks {
        let t = t.expect("task entry");
        let path = t.path().join("children");
        // スレッドは列挙の途中で終わりうる。消えたスレッドだけを許容し、その他の失敗は panic にする。
        let s = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => panic!("read {}: {e}", path.display()),
        };
        for tok in s.split_whitespace() {
            out.push(
                tok.parse::<u32>()
                    .unwrap_or_else(|e| panic!("child pid {tok:?}: {e}")),
            );
        }
    }
    out
}

/// 呼び出しプロセスの子が `limit` 以内に 0 件になることを照合する。残りがあれば kill・回収した上で、
/// pid を含めて panic する。`what` は失敗メッセージの文脈（例: "after the lifecycle scenario finished"）。
pub fn assert_no_leftover_children(limit: Duration, what: &str) {
    let deadline = Instant::now() + limit;
    loop {
        if children_of_self().is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let left = children_of_self();
    // 冪等。再親付けされた孫を pid 指定で回収できるようにする（呼び出し側が未設定でも安全側に倒す）。
    let proof = ChildSubreaper::enable().expect("enable child subreaper for cleanup");
    let mut failed = Vec::new();
    for pid in &left {
        let Some(pid) = NonZeroU32::new(*pid) else {
            continue;
        };
        let child = ContainerChild::adopt_reparented(pid, &proof);
        if let Err(e) = child.kill_and_reap(REAP_TIMEOUT) {
            failed.push(format!("{pid}: {e:?}"));
        }
    }
    panic!("no child may remain {what}: {left:?} (cleanup failures: {failed:?})");
}
