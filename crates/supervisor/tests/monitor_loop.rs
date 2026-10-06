//! 監視ループ基本実装の受け入れ照合テスト（TASK-157.4・#238・TASK-157.5・#239・SUP-1・SUP-3・CORE-1・D-19・REPAIR-12）。
//!
//! 文字列照合であり構文解析ではない（tests/skeleton.rs・state_store_wiring.rs と同じ手法）。

/// AC2: 監視ループは 1 呼び出し 1 コンテナで、グローバル状態・unsafe・記録 pid への直接操作を持たない。
#[test]
fn sup1_task157_4_run_rs_has_no_global_state_or_raw_pid_access() {
    const RUN_RS: &str = include_str!("../src/run.rs");
    let body = RUN_RS.split("#[cfg(test)]").next().unwrap_or(RUN_RS);
    // コメント行（//! ・ ///）は禁止語を説明に使うため除外する。
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "\nstatic ",
        "\npub static ",
        "thread_local",
        "OnceLock",
        "LazyLock",
        "unsafe",
        "kill(",
        "waitpid",
        "/proc",
        "cfg(target_os",
    ] {
        assert!(!code.contains(banned), "run.rs must not contain {banned}");
    }
}

/// AC2: 依存は core への path 依存のみ（新規依存・中央デーモン用の仕組みを持たない）。
#[test]
fn sup1_task157_4_manifest_has_only_core_dependency() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    let deps = MANIFEST.split("[dependencies]").nth(1).unwrap_or("");
    // `[dependencies]` 節のみを対象にする（後続の `[[test]]` 等のテーブルは依存ではない）。
    let entries: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(entries, ["fandhe-container-core = { path = \"../core\" }"]);
}

/// TASK-157.5 AC2: 未実装の restart ポリシー詳細が将来仕様と ID 付きで doc に明記されている。
#[test]
fn sup1_task157_5_run_rs_documents_unimplemented_restart_policy() {
    const RUN_RS: &str = include_str!("../src/run.rs");
    let body = RUN_RS.split("#[cfg(test)]").next().unwrap_or(RUN_RS);
    for needle in [
        "SUP-3",
        "TASK-157.5",
        "未実装",
        "on-failure",
        "always",
        "unless-stopped",
        "バックオフ",
    ] {
        assert!(body.contains(needle), "run.rs docs must mention {needle}");
    }
}

/// TASK-157.5 AC1: 異常終了時の restart_count 更新は最新レコードからの飽和加算で行う。
#[test]
fn sup1_task157_5_run_rs_updates_restart_count_with_saturation() {
    const RUN_RS: &str = include_str!("../src/run.rs");
    let body = RUN_RS.split("#[cfg(test)]").next().unwrap_or(RUN_RS);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(code.contains("restart_count().saturating_add(1)"));
    assert!(!code.contains("restart_count() + 1"));
}
