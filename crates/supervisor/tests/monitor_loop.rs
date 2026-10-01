//! 監視ループ基本実装の受け入れ照合テスト（TASK-157.4・#238・SUP-1・CORE-1・D-19・REPAIR-12）。
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
    let entries: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(entries, ["fandhe-container-core = { path = \"../core\" }"]);
}
