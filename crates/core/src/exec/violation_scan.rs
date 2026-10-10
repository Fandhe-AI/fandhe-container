//! 違反理由の一覧とソースの突き合わせ（単体テスト専用。SEC-4・SUP-6・SEC-1・REPAIR-12・#1533）。
//!
//! # 役割
//!
//! 監査ログへ届く経路ごとの違反理由の一覧（exec の子の `process::EXEC_CHILD_VIOLATIONS`）が、その経路の
//! ソースが実際に作る理由と一致することを固定する。
//! 一覧の足し忘れは「違反を拒否したのに記録されない」（SEC-4 違反）につながるため、ソースから
//! `ViolationReason::<名前>` を抽出して機械的に照合する。`#[cfg(test)]` の下だけでコンパイルする。
//!
//! # 照合の限界
//!
//! 対象のファイルは呼び出し側のテストが列挙する（exec の子は `process.rs`・`interpreter.rs`・`sealed_copy.rs`）。
//! 経路が別ファイルの違反生成ヘルパを呼ぶようになったら、そのファイルを照合対象に加えること。

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
