//! `fandhe-container-io` 公開 API（`CaseCollisionSet` / `check_case_collisions`）の
//! 結合試験（TASK-19.1・IO-5・REPAIR-12・#99）。
//!
//! `src/fs_normalize.rs` のユニットテストは crate 内部から検証するが、本ファイルは
//! `fandhe-container-io` の外部利用者（#100 が想定するサーバー側の書き込み経路）と
//! 同じ経路（`pub use` された公開 API のみ）で、衝突検出・非衝突・不正パス拒否を
//! 機械照合する（AGENTS.md「新機能追加時に更新すべきテスト一覧」）。
//!
//! 衝突検出はワイヤー上のゲスト相対パス文字列、パス長検証（TASK-20.1・#102）は
//! ホストの `Path` を扱う。いずれも実ファイルシステムには触れず、3 OS の CI で
//! 同じ結果になる（モジュール doc「入力表現がゲスト相対パスの `&str` である理由」参照）。

use std::path::PathBuf;

use fandhe_container_io::{
    CaseCollisionSet, IoErrorCode, check_case_collisions, check_host_path_length,
};

/// IO-5・TASK-21.1: 公開 API 経由でも NFC/NFD の別表記を衝突として検出し、
/// 親が違えば衝突しない。
#[test]
fn io5_public_api_detects_nfc_nfd_collision() {
    let mut set = CaseCollisionSet::new();
    set.try_insert("caf\u{e9}/a.txt").expect("first insert");
    let err = set
        .try_insert("cafe\u{301}/b.txt")
        .expect_err("NFD ancestor must collide with NFC ancestor");
    assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    set.try_insert("x/\u{e9}").expect("different parent");
    set.try_insert("y/e\u{301}").expect("different parent");
    assert_eq!(set.len(), 3);
}

/// IO-5: 公開 API 経由でも大文字小文字だけの衝突を検出できる。
#[test]
fn io5_public_api_detects_case_collision() {
    let mut set = CaseCollisionSet::new();
    set.try_insert("Reports/Q1.csv")
        .expect("first insert must succeed");

    let err = set
        .try_insert("reports/q1.csv")
        .expect_err("case-only collision must be rejected via the public API");
    assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
}

/// IO-5: 公開 API 経由で、衝突しないバッチはすべて受理される。
#[test]
fn io5_public_api_accepts_non_colliding_batch() {
    check_case_collisions(["a.txt", "b.txt", "dir/c.txt", "dir/sub/d.txt"])
        .expect("non-colliding batch must be accepted via the public API");
}

/// IO-5: 公開 API 経由で、不正な形式のゲスト相対パスは `InvalidArgument` で
/// 拒否される。
#[test]
fn io5_public_api_rejects_malformed_path() {
    let err = check_case_collisions(["ok.txt", "/absolute/path"])
        .expect_err("absolute path must be rejected via the public API");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// IO-5: 公開 API 経由でも深さの異なる衝突（ファイル `"a"` とディレクトリ
/// `"A"` 配下の `"A/b"`）を検出する。
#[test]
fn io5_public_api_detects_collision_across_depths() {
    let err = check_case_collisions(["a", "A/b"])
        .expect_err("file and case-differing directory must collide via the public API");
    assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    assert_eq!(
        err.message(),
        "case-insensitive path collision: \"A/b\" conflicts with existing \"a\" \
         (components \"A\" and \"a\" differ only by case)"
    );
}

/// IO-5・TASK-20.1: 公開 API 経由で 260 は許容・261 は `InvalidArgument`。
#[test]
fn io5_public_api_host_path_length_boundary() {
    let base = PathBuf::from("a".repeat(100));
    let ok = check_host_path_length(&base.join("b".repeat(159))).expect("260 is ok");
    assert_eq!(ok.units(), 260);
    let err = check_host_path_length(&base.join("b".repeat(160))).expect_err("261");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}
