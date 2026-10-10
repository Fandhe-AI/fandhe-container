//! 違反理由の一覧とソースの突き合わせ（単体テスト専用。SEC-4・SUP-6・SEC-1・REPAIR-12・#1533）。
//!
//! # 役割
//!
//! 監査ログへ届く経路ごとの違反理由の一覧（exec の子の `process::EXEC_CHILD_VIOLATIONS`・exec の worker の
//! `ViolationReason::EXEC_WORKER_REASONS`）が、その経路のソースが実際に作る理由と一致することを固定する。
//! 一覧の足し忘れは「違反を拒否したのに記録されない」（SEC-4 違反）につながるため、ソースから
//! `ViolationReason::<名前>` を抽出して機械的に照合する。`#[cfg(test)]` の下だけでコンパイルする。
//!
//! # worker の経路（`EXEC_WORKER_REASONS`）
//!
//! supervisor の `exec::run_command` が core の `spawn_exec_worker` で fork する worker は、対象の特定
//! （`setns.rs`）・cgroup 参加（`cgroup_join.rs`）・制限の準備と再適用（`reapply.rs` と、そこから呼ぶ
//! `landlock.rs`・`rlimits.rs`・`capabilities.rs`・`no_new_privs.rs`・`seccomp.rs`・`entrypoint_mode.rs`）・
//! コマンド環境（`container_env.rs`）・コマンドの fork（`exec_command.rs` の親側）を行う。これらが作る違反は
//! `err` 行で親へ運ばれ、親が層 `exec_target` / `mount` に 1 件ずつ記録する。exec の子（fork 後・`execve` 前。
//! `process.rs`・`interpreter.rs`・`sealed_copy.rs`）の違反は `ok` 行の `SetupFailed` で運ばれ、層 `entrypoint` に
//! 記録される（`EXEC_CHILD_VIOLATIONS`）。照合の限界: worker が別ファイルの違反生成ヘルパを呼ぶように
//! なったら、そのファイルを照合対象に加えること（`rootfs.rs`・`inject.rs`・`tmpfs.rs` は launch の経路の違反を
//! 多数作るため `exec/` 全体は走査しない）。

use std::collections::BTreeSet;

use super::ViolationReason;

/// `ViolationReason::<Name>` の `Name` を集めた集合（経路のソースからの違反理由の抽出。#1533）。
///
/// `mod tests` 以降・コメント行・`EXEC_CHILD_VIOLATIONS` 自身の定義は数えない。拾いすぎは「失敗して判断を
/// 迫る」側に倒れるため許容する。
pub(super) fn violation_names(src: &str) -> BTreeSet<String> {
    let body = src
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .unwrap_or(src);
    let mut kept = String::new();
    let mut in_list = false;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub(super) const EXEC_CHILD_VIOLATIONS") {
            in_list = true;
        }
        if in_list {
            if trimmed.starts_with("];") {
                in_list = false;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    const PREFIX: &str = "ViolationReason::";
    kept.match_indices(PREFIX)
        .filter_map(|(at, _)| {
            let rest = kept.get(at + PREFIX.len()..)?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// 抽出した名前と一覧の差分 `(missing, stale)`。`missing` はコードにあって一覧に無い名前、`stale` は逆。
pub(super) fn violation_list_gaps(
    found: &BTreeSet<String>,
    list: &[ViolationReason],
) -> (Vec<String>, Vec<String>) {
    let listed: BTreeSet<String> = list.iter().map(|r| format!("{r:?}")).collect();
    (
        found.difference(&listed).cloned().collect(),
        listed.difference(found).cloned().collect(),
    )
}

/// worker の経路のソース（ファイル名と内容）。モジュール doc「worker の経路」の一覧と同じ。
const WORKER_PATH_SOURCES: [(&str, &str); 11] = [
    ("setns.rs", include_str!("setns.rs")),
    ("cgroup_join.rs", include_str!("cgroup_join.rs")),
    ("reapply.rs", include_str!("reapply.rs")),
    ("landlock.rs", include_str!("landlock.rs")),
    ("rlimits.rs", include_str!("rlimits.rs")),
    ("capabilities.rs", include_str!("capabilities.rs")),
    ("no_new_privs.rs", include_str!("no_new_privs.rs")),
    ("seccomp.rs", include_str!("seccomp.rs")),
    ("entrypoint_mode.rs", include_str!("entrypoint_mode.rs")),
    ("container_env.rs", include_str!("container_env.rs")),
    ("exec_command.rs", include_str!("exec_command.rs")),
];

/// SEC-4・SUP-6・SEC-1・REPAIR-12: worker の経路のソースが作る違反理由と `EXEC_WORKER_REASONS` が一致し、
/// その全理由が監査イベントに写る（記録される）。`execve` 前の子の経路（`EXEC_CHILD_VIOLATIONS`）とは
/// 交わらない（同じ違反が `err` 行と `ok` 行の両方で運ばれて二重に記録されることはない）。
#[test]
fn sec4_sup6_exec_worker_reasons_match_worker_path_sources() {
    let mut found = BTreeSet::new();
    for (name, src) in WORKER_PATH_SOURCES {
        let names = violation_names(src);
        if name == "setns.rs" || name == "cgroup_join.rs" || name == "reapply.rs" {
            assert!(!names.is_empty(), "{name} must produce worker violations");
        }
        found.extend(names);
    }
    let (missing, stale) = violation_list_gaps(&found, &ViolationReason::EXEC_WORKER_REASONS);
    assert!(
        missing.is_empty(),
        "worker-path violations missing from EXEC_WORKER_REASONS: {missing:?}"
    );
    assert!(
        stale.is_empty(),
        "EXEC_WORKER_REASONS entries not produced by worker-path sources: {stale:?}"
    );
    assert_eq!(found.len(), 11);
    for r in ViolationReason::EXEC_WORKER_REASONS {
        assert!(
            r.exec_worker_audit_event().is_some(),
            "{r:?} is not audited"
        );
        assert!(
            !super::process::exec_child_violation_reasons().contains(&r),
            "{r:?} is carried by both the err and ok lines"
        );
    }
}

/// worker の経路の照合が実際に失敗を報告する根拠: `rootfs_is_host_root` を一覧から外すと `missing` に出る
/// （#1614 の事後監査で見つかった記録漏れと同じ形。SEC-4）。
#[test]
fn sec4_sup6_exec_worker_scan_detects_omission() {
    let found = violation_names(include_str!("reapply.rs"));
    assert!(found.contains("RootfsIsHostRoot"), "{found:?}");
    let (missing, stale) = violation_list_gaps(&found, &ViolationReason::EXEC_TARGET_REASONS);
    assert_eq!(missing, ["RootfsIsHostRoot"]);
    assert!(!stale.is_empty());
}
