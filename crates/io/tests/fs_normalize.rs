//! `fandhe-container-io` 公開 API（`CaseCollisionSet` / `check_case_collisions`）の
//! 結合試験（TASK-19.1・IO-5・REPAIR-12・#99）。
//!
//! `src/fs_normalize.rs` のユニットテストは crate 内部から検証するが、本ファイルは
//! `fandhe-container-io` の外部利用者（#100 が想定するサーバー側の書き込み経路）と
//! 同じ経路（`pub use` された公開 API のみ）で、衝突検出・非衝突・不正パス拒否を
//! 機械照合する（AGENTS.md「新機能追加時に更新すべきテスト一覧」）。
//!
//! `std::path` や実ファイルシステムには触れない。ここで扱うのはワイヤー上の
//! ゲスト相対パス文字列であり、3 OS の CI で同じ結果になる必要があるため
//! （モジュール doc「入力表現がゲスト相対パスの `&str` である理由」参照）。

use fandhe_container_io::{CaseCollisionSet, IoErrorCode, check_case_collisions};

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
