#![cfg(target_os = "macos")]
//! objc2 / Virtualization.framework の FFI 呼び出しを包む薄いラッパーの置き場（MAC-1・TASK-64.1）。
//!
//! 上位モジュールへは安全な API だけを公開し、`unsafe fn` を本モジュールの外へ公開しない。
//! `unsafe` を置く場合は `// SAFETY:` で不変条件を明記し、`.claude/rules/coding-rust.md` の
//! 事前承認（#4）の条件（security-auditor 観点のレビュー・PR 本文の unsafe 一覧）を満たすこと。
//!
//! 現状は空で、ラッパー本体は TASK-64.2〜64.5 で実装する（REPAIR-3: 実装済みを装わない）。
