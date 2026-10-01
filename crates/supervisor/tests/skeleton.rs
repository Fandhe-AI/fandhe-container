//! crate 雛形の受け入れ基準を機械照合するテスト（TASK-157.1・#235・SUP-1・REPAIR-12）。
//!
//! 基準 1: workspace のビルド対象に含まれること。本テストは members から外れると実行されないため、登録の回帰検出は workspace 外の `make check-workspace-manifest`（`cargo metadata --no-deps` の `manifest_path` 照合。CI の rust-ci 系ジョブからも実行）が担う。
//! 基準 2: `license` が crate 直書きでなく `[workspace.package]` の継承であること。
//! マニフェストの照合は文字列一致であり、TOML の構文解析ではない（依存ゼロ方針のため）。

const CRATE_MANIFEST: &str = include_str!("../Cargo.toml");
const ROOT_MANIFEST: &str = include_str!("../../../Cargo.toml");

/// TASK-157.1: crate 名が確定名であること。
#[test]
fn task_157_1_crate_name() {
    assert_eq!(env!("CARGO_PKG_NAME"), "fandhe-container-supervisor");
}

/// TASK-157.1: 継承解決後の実効ライセンスが Apache-2.0 であること。
#[test]
fn task_157_1_effective_license_is_apache_2_0() {
    assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
}

/// TASK-157.1: ライセンスは workspace 継承で、crate 側に直書きがないこと。
#[test]
fn task_157_1_license_is_inherited_from_workspace() {
    assert!(
        CRATE_MANIFEST.contains("license.workspace = true"),
        "crate manifest must inherit license via `license.workspace = true`"
    );
    assert!(
        !CRATE_MANIFEST.contains("license = \""),
        "crate manifest must not hardcode `license = \"...\"`"
    );
    assert!(
        ROOT_MANIFEST.contains("license = \"Apache-2.0\""),
        "root [workspace.package] must set license = \"Apache-2.0\""
    );
}

/// TASK-157.1: ルート workspace の members に含まれること。
#[test]
fn task_157_1_listed_in_workspace_members() {
    assert!(
        ROOT_MANIFEST.contains("\"crates/supervisor\""),
        "root workspace members must include \"crates/supervisor\""
    );
}
