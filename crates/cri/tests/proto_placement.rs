//! cri-api の `.proto` 配置の受け入れ基準を機械照合するテスト（TASK-56.2・#424・CRI-3・REPAIR-12）。
//!
//! 基準: 配置した `.proto` のライセンスと出典（バージョン・コミットハッシュ）が README に記録されていること。
//! バイト長・行数は無改変の近似検出であり、sha256 の検証は README 記載の `sha256sum` 手順で行う（依存ゼロ方針のため自前実装しない）。

const API_PROTO: &str = include_str!("../proto/api.proto");
const README: &str = include_str!("../proto/README.md");

/// TASK-56.2: upstream v0.37.1 と同じバイト長・行数であること（無改変の近似検出）。
#[test]
fn task_56_2_proto_matches_upstream_size() {
    assert_eq!(API_PROTO.len(), 102158);
    assert_eq!(API_PROTO.lines().count(), 2395);
}

/// TASK-56.2: proto3 構文とパッケージ宣言があること。
#[test]
fn task_56_2_proto_syntax_and_package() {
    assert!(API_PROTO.contains("syntax = \"proto3\";"));
    assert!(API_PROTO.contains("package runtime.v1;"));
}

/// TASK-56.2: gogoproto 拡張・import を含まないこと（CRI-3 の wire 互換形式の前提）。
#[test]
fn task_56_2_proto_has_no_gogoproto_or_import() {
    assert!(!API_PROTO.contains("gogoproto"));
    assert!(!API_PROTO.lines().any(|l| l.starts_with("import ")));
}

/// TASK-56.2: CRI の 2 サービスが定義されていること。
#[test]
fn task_56_2_proto_defines_cri_services() {
    assert!(API_PROTO.contains("service RuntimeService {"));
    assert!(API_PROTO.contains("service ImageService {"));
}

/// TASK-56.2: Apache-2.0 ヘッダと著作権表記が保持されていること。
#[test]
fn task_56_2_proto_keeps_license_header() {
    assert!(API_PROTO.contains("Licensed under the Apache License, Version 2.0"));
    assert!(API_PROTO.contains("The Kubernetes Authors"));
}

/// TASK-56.2: README に出典（バージョン・コミット・ハッシュ・パス）とライセンスが記録されていること。
#[test]
fn task_56_2_readme_records_provenance_and_license() {
    for needle in [
        "v0.37.1",
        "d279f3cbb9d18b653d5fab12e187589914329c77",
        "381aab5cf67425b3c90ab016489de661ccb83ed9f21204066dc5df83b9b83360",
        "pkg/apis/runtime/v1/api.proto",
        "Apache-2.0",
    ] {
        assert!(README.contains(needle), "README must record: {needle}");
    }
}
