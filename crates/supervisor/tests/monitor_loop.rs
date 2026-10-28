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

/// AC2: 依存は workspace 内の path 依存（core と、#3065 で足した net の一方向）のみ。外部クレート・中央デーモン用の仕組みを持たない。
/// core は `default-features = false` で引く。supervisor は core の plugin 境界基盤を使わず、既定 feature のままだと
/// CLI など依存元の実行ファイルで feature 統合により core の `plugin` が再有効化され、PLUG-3・CORE-7 の
/// 実行ファイル計測（#3204）が成り立たないため。
#[test]
fn sup1_task157_4_manifest_has_only_workspace_path_dependencies() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    let deps = MANIFEST.split("[dependencies]").nth(1).unwrap_or("");
    // `[dependencies]` 節のみを対象にする（後続の `[[test]]` 等のテーブルは依存ではない）。
    let entries: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(
        entries,
        [
            "fandhe-container-core = { path = \"../core\", default-features = false }",
            "fandhe-container-net = { path = \"../net\" }",
        ]
    );
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

/// TASK-159.3 AC1: `restart_count` の加算は再 launch 成功時（restart.rs）だけが最新レコードからの飽和加算で行い、
/// 終了記録（run.rs）は加算しない。
#[test]
fn sup3_task159_3_restart_count_is_incremented_only_on_relaunch() {
    fn code_of(src: &str) -> String {
        let body = src.split("#[cfg(test)]").next().unwrap_or(src);
        body.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    let run_rs = code_of(include_str!("../src/run.rs"));
    let restart_rs = code_of(include_str!("../src/restart.rs"));
    assert!(restart_rs.contains("restart_count().saturating_add(1)"));
    assert!(!restart_rs.contains("restart_count() + 1"));
    assert!(!run_rs.contains("saturating_add"));
    assert!(!run_rs.contains("restart_count() + 1"));
    assert!(!run_rs.contains("is_abnormal_exit"));
}
