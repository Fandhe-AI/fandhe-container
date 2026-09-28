//! FS 正規化層の雛形: 大文字小文字だけで衝突するゲスト相対パスの検出
//! （TASK-19.1・IO-5・#99）。
//!
//! # 役割
//! APFS（macOS）と NTFS（Windows）はデフォルトで大文字小文字を区別しないが、
//! ゲスト（Linux・ext4）は区別する。この差異があるホスト共有環境で、ゲストが
//! `Foo.txt` と `foo.txt` を別ファイルとして作成すると、ホスト側では同じ
//! ファイルとして扱われ、後から作成した方が先の内容を黙って上書きする
//! （データ損失）。本モジュールは、その組み合わせを**ゲスト側で検出**して
//! 構造化エラーを返す純粋関数・小さな状態型を提供する。
//!
//! # 呼び出し文脈
//! 本 sub-issue（#99）はこの検出ロジック単体の実装に留まる。実際の
//! サーバーの書き込み経路（`crates/io/src/server.rs` / `crates/io/src/writeback.rs`）
//! への組み込みは兄弟 sub-issue #100（TASK-19.2）が担う。現行の
//! [`crate::payload::RequestEnvelope`] にはファイルパスを表すフィールドがまだ
//! 無いため、本モジュールは現時点でどこからも呼ばれていない（REPAIR-3:
//! 実装済みを装わない）。
//!
//! # 畳み込み方式と、これが近似であること（REPAIR-3）
//! 大文字小文字の畳み込みは `char::to_lowercase()` を各文字へ適用する方式
//! （[`CaseFoldKey`] 参照）で、Unicode の単純な case folding の近似に過ぎない。
//! APFS の `casefold` 正規化表・NTFS の upcase table と厳密に一致することは
//! 主張しない。方式は「衝突の見逃しよりも過検出を選ぶ」よう選んでいる:
//! 見逃しはホスト側での黙った上書き（データ損失）に直結するが、過検出は
//! ゲストに見えるエラーで済むため。既知の非衝突（`ß` と `SS` など）は
//! テストで境界を固定する。APFS / NTFS の実際の case folding 表との厳密な
//! 一致・非 UTF-8 ファイル名の扱いは TASK-21（Unicode 正規化。方針は人間が
//! 判断する）以降のスコープ。
//!
//! # 入力表現がゲスト相対パスの `&str` である理由
//! 入力はワイヤープロトコル上のゲスト（Linux）側 `/` 区切り相対パス表現であり、
//! ホスト OS のファイルシステムパスではない。`std::path::Path` はホストの
//! パス区切り文字に従う（Windows ホストでは `\`）ため、ここで使うと
//! ゲスト表現を誤って解釈してしまう。coding-rust.md の「パスは `PathBuf` /
//! `Path::join` で組み立てる」はホスト上のファイルシステムパスの組み立てを
//! 指すものであり、ワイヤー上のゲスト相対パス文字列という別の対象には
//! 適用されない。
//!
//! # 検証の位置づけ（多層防御の 1 枚）
//! [`validate_guest_relative_path`] は先頭 `/`・`.`・`..`・空コンポーネント・
//! NUL を拒否するが、これはパストラバーサルを主目的として防ぐ層ではない。
//! rootfs 配下への閉じ込めを保証する本来の検証は、サーバー側の書き込み経路
//! （#100 以降）の責務であり、本モジュールの検証はそれとは独立に、同一表記
//! ゆれ（`a//B` と `a/b` など）で衝突検出をすり抜けさせないための入力正規化に
//! すぎない。
//!
//! # スコープ外（後続タスクへの引き継ぎ）
//! - サーバーの書き込み経路への組み込み・結合試験 → #100（TASK-19.2）
//! - パス長 260 超の検出 → TASK-20
//! - NFC / NFD の Unicode 正規化方針 → TASK-21
//! - APFS / NTFS の実際の case folding 表との厳密な一致・非 UTF-8 ファイル名の
//!   扱い → TASK-21 以降

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::error::{IoError, IoErrorCode};

/// [`quote_for_message`] がエラーメッセージへ埋め込む 1 パスあたりの最大文字数
/// （公開定数。呼び出し側がメッセージ全体の見積もりに使えるようにする）。
///
/// ゲスト由来の任意長パスをそのままログ・エラーメッセージへ載せると、巨大な
/// メッセージによる資源浪費（security.md「不安全な設計」観点）につながる
/// ため、char 境界で切り詰める。
pub const MAX_COLLISION_MESSAGE_PATH_CHARS: usize = 128;

/// 大文字小文字だけで衝突するかどうかを判定するための畳み込み済みキー
/// （非公開 newtype）。
///
/// `/` 区切りの各コンポーネントに `char::to_lowercase()` を適用して
/// 畳み込む。`str::to_lowercase()`（文字列全体への一括変換）ではなく
/// 文字ごとの `char::to_lowercase()` を使う理由は、`str::to_lowercase()` が
/// 語末のギリシャ文字シグマ（Σ）をコンテキスト依存で `ς`（語末形）に
/// 変換する規則を持ち、`"ΣΣ"` と `"σσ"` が異なる畳み込み結果になって
/// 衝突を見逃しうるため（`io5_final_sigma_folds_consistently` で回帰確認）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CaseFoldKey(Vec<String>);

impl CaseFoldKey {
    fn fold(components: &[&str]) -> Self {
        let folded = components
            .iter()
            .map(|component| component.chars().flat_map(char::to_lowercase).collect())
            .collect();
        Self(folded)
    }
}

/// ゲスト相対パスの形式を検証する（[`CaseCollisionSet::try_insert`] の入口）。
///
/// 次のいずれかに該当する場合は [`IoErrorCode::InvalidArgument`] を返す:
/// - 空文字列
/// - 先頭が `/`（絶対パス表現）
/// - 空コンポーネントを含む（連続する `/`・先頭または末尾の `/`）
/// - `.` または `..` のコンポーネントを含む
/// - NUL 文字（`\0`）を含む
///
/// これらを個別に拒否するのは、`a//B` のような表記ゆれが `a/b` と同じ
/// コンポーネント列に畳み込まれて衝突検出をすり抜けることを防ぐため
/// （多層防御の 1 枚であり、パストラバーサル防止の本体はサーバー側の責務。
/// モジュール doc「検証の位置づけ」参照）。
fn validate_guest_relative_path(path: &str) -> Result<Vec<&str>, IoError> {
    if path.is_empty() {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "guest relative path must not be empty",
        ));
    }
    if path.contains('\0') {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "guest relative path must not contain a NUL byte",
        ));
    }
    if path.starts_with('/') {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "guest relative path must not be absolute (must not start with '/')",
        ));
    }

    let components: Vec<&str> = path.split('/').collect();
    for component in &components {
        if component.is_empty() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "guest relative path must not contain an empty component (repeated or \
                 trailing '/')",
            ));
        }
        if *component == "." || *component == ".." {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "guest relative path must not contain '.' or '..' components",
            ));
        }
    }

    Ok(components)
}

/// エラーメッセージへ埋め込むためにパスを衛生化する（改行・制御文字による
/// ログ注入の防止・巨大メッセージの防止。security.md「インジェクション」観点）。
///
/// `{:?}`（`Debug` によるエスケープ）でパスを整形したうえで、char 境界で
/// [`MAX_COLLISION_MESSAGE_PATH_CHARS`] 文字までに切り詰める。切り詰めた
/// 場合は末尾に `...` を付ける。添字アクセス（`[]`）ではなく `chars().take`
/// を使い、マルチバイト文字の境界を壊さない。
fn quote_for_message(path: &str) -> String {
    let mut truncated: String = path
        .chars()
        .take(MAX_COLLISION_MESSAGE_PATH_CHARS)
        .collect();
    let was_truncated = path.chars().count() > MAX_COLLISION_MESSAGE_PATH_CHARS;
    if was_truncated {
        truncated.push_str("...");
    }
    format!("{truncated:?}")
}

/// 大文字小文字だけで衝突するパスを検出する状態つきの索引（TASK-19.1・IO-5）。
///
/// # 契約
/// - [`Self::try_insert`] は検証・畳み込み・照合を経て、初出のパスまたは完全に
///   同一のパスを `Ok(())` で受理し、大文字小文字の違いだけで既存パスと衝突
///   する場合は [`IoErrorCode::AlreadyExists`] を返す。
/// - `Send` / `Sync` は自動導出される（内部可変性を持たない `HashMap` のみの
///   フィールドのため）。複数スレッドで共有する場合は呼び出し側で同期する。
/// - アロケーション量は挿入したパスの長さに比例する定数倍に収まり、宣言された
///   件数から事前確保しない（`HashMap::new()` で逐次拡張する。coding-rust.md
///   「長さ・件数を上限検証してからアロケーションに使う」への対応。件数上限
///   〔バッチ上限等〕は呼び出し側の責務）。
#[derive(Debug, Default)]
pub struct CaseCollisionSet {
    seen: HashMap<CaseFoldKey, String>,
}

impl CaseCollisionSet {
    /// 空の索引を作る。
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// 索引に登録済みのパス件数を返す。
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 索引が空かどうかを返す。
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// `path` を検証・畳み込みしたうえで索引へ登録する。
    ///
    /// # 挙動
    /// 1. [`validate_guest_relative_path`] で形式を検証する（不正なら
    ///    [`IoErrorCode::InvalidArgument`]）
    /// 2. [`CaseFoldKey::fold`] で畳み込みキーを作る
    /// 3. 索引に同じキーが無ければ登録して `Ok(())`
    /// 4. 同じキーの既存エントリと `path` が完全一致するなら `Ok(())`
    ///    （同一バッチ内で同じファイルへ複数回書き込むのは正常な処理のため。
    ///    大文字小文字だけが違う場合に限りエラーにする）
    /// 5. 既存エントリと `path` が大文字小文字の違いだけで異なるなら
    ///    [`IoErrorCode::AlreadyExists`] を返す。`message` には両方のパスを
    ///    [`quote_for_message`] で衛生化して含める（生のパスをそのまま
    ///    埋め込まない）
    pub fn try_insert(&mut self, path: &str) -> Result<(), IoError> {
        let components = validate_guest_relative_path(path)?;
        let key = CaseFoldKey::fold(&components);

        match self.seen.entry(key) {
            Entry::Vacant(vacant) => {
                vacant.insert(path.to_string());
                Ok(())
            }
            Entry::Occupied(occupied) => {
                if occupied.get() == path {
                    Ok(())
                } else {
                    Err(IoError::new(
                        IoErrorCode::AlreadyExists,
                        format!(
                            "case-insensitive path collision: {} conflicts with existing {} \
                             (paths differ only by case)",
                            quote_for_message(path),
                            quote_for_message(occupied.get()),
                        ),
                    ))
                }
            }
        }
    }
}

/// [`CaseCollisionSet`] を使い捨てで使う便利関数（IO-5）。
///
/// `paths` を順に [`CaseCollisionSet::try_insert`] へ渡し、最初に検出した
/// エラー（形式不正の [`IoErrorCode::InvalidArgument`]、または大文字小文字の
/// 衝突の [`IoErrorCode::AlreadyExists`]）で打ち切って返す。すべて受理された
/// 場合は `Ok(())`。
pub fn check_case_collisions<'a, I>(paths: I) -> Result<(), IoError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut set = CaseCollisionSet::new();
    for path in paths {
        set.try_insert(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IO-5: 大文字小文字だけが違う 2 パスは `AlreadyExists` として検出され、
    /// message に両方のパスが含まれる。
    #[test]
    fn io5_detects_case_only_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("Foo.txt")
            .expect("first insert must succeed");

        let err = set
            .try_insert("foo.txt")
            .expect_err("case-only collision must be rejected");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
        assert!(err.message().contains("Foo.txt"));
        assert!(err.message().contains("foo.txt"));
    }

    /// IO-5: まったく同じパスを複数回挿入しても衝突扱いにしない
    /// （同一バッチ内での同一ファイルへの複数回書き込みは正常な処理）。
    #[test]
    fn io5_identical_path_is_not_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("foo.txt")
            .expect("first insert must succeed");
        set.try_insert("foo.txt")
            .expect("identical path must not be treated as a collision");
        assert_eq!(set.len(), 1);
    }

    /// IO-5: 名前が異なるパスは衝突しない。
    #[test]
    fn io5_different_names_do_not_collide() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("foo.txt").expect("insert must succeed");
        set.try_insert("bar.txt").expect("insert must succeed");
        assert_eq!(set.len(), 2);
    }

    /// IO-5: 文字数（畳み込み後の長さ）が異なるパスは衝突しない。
    #[test]
    fn io5_different_length_does_not_collide() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("Foo.txt").expect("insert must succeed");
        set.try_insert("foo.tx").expect("insert must succeed");
        assert_eq!(set.len(), 2);
    }

    /// IO-5: 親ディレクトリのコンポーネントの大文字小文字違いも衝突として
    /// 検出する。
    #[test]
    fn io5_detects_collision_in_parent_component() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("dir/Foo")
            .expect("first insert must succeed");

        let err = set
            .try_insert("DIR/foo")
            .expect_err("collision in parent component must be rejected");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: 親ディレクトリが異なれば、末端の名前が大文字小文字だけ違っても
    /// 衝突しない。
    #[test]
    fn io5_same_name_in_different_dirs_does_not_collide() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("a/Foo").expect("insert must succeed");
        set.try_insert("b/foo").expect("insert must succeed");
        assert_eq!(set.len(), 2);
    }

    /// IO-5: ASCII 以外の大文字小文字違い（ラテン文字の分音記号付き）も検出する。
    #[test]
    fn io5_detects_non_ascii_case_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("É.txt").expect("first insert must succeed");

        let err = set
            .try_insert("é.txt")
            .expect_err("non-ASCII case collision must be rejected");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: `str::to_lowercase()` への退行検出。語末のギリシャ文字シグマの
    /// コンテキスト依存変換規則があると `"ΣΣ"` と `"σσ"` が異なる畳み込み結果に
    /// なり衝突を見逃すため、char ごとの `to_lowercase` を使うことで一貫して
    /// 検出できることを固定する。
    #[test]
    fn io5_final_sigma_folds_consistently() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("ΣΣ").expect("first insert must succeed");

        let err = set
            .try_insert("σσ")
            .expect_err("sigma case collision must be rejected regardless of final-sigma rules");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: `ß` と `SS` は本方式の近似では衝突として検出しない（既知の非衝突。
    /// モジュール doc「畳み込み方式と、これが近似であること」で明示済みの境界を
    /// 固定する）。
    #[test]
    fn io5_sharp_s_is_documented_non_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("ß.txt").expect("insert must succeed");
        set.try_insert("SS.txt")
            .expect("ß vs SS is a documented non-collision under this approximation");
        assert_eq!(set.len(), 2);
    }

    /// IO-5: 不正な形式のパスはすべて `InvalidArgument` で拒否される。
    #[test]
    fn io5_rejects_malformed_paths() {
        let malformed = ["", "/abs", "a//b", "a/", "./a", "a/../b", "a\0b"];
        for path in malformed {
            let mut set = CaseCollisionSet::new();
            let err = set
                .try_insert(path)
                .expect_err(&format!("malformed path {path:?} must be rejected"));
            assert_eq!(
                err.code(),
                IoErrorCode::InvalidArgument,
                "path {path:?} must be rejected as InvalidArgument"
            );
        }
    }

    /// IO-5・security.md「インジェクション」観点: message は制御文字を
    /// エスケープし、長いパスは char 境界で切り詰められる。
    #[test]
    fn io5_message_escapes_control_chars_and_truncates() {
        let mut set = CaseCollisionSet::new();
        let with_newline = "line1\nline2.txt";
        set.try_insert(with_newline).expect("insert must succeed");
        let err = set
            .try_insert("LINE1\nLINE2.txt")
            .expect_err("collision must be detected even with control characters");
        assert!(
            !err.message().contains('\n'),
            "message must not contain a raw newline: {:?}",
            err.message()
        );

        let long_component = "A".repeat(200);
        let mut set = CaseCollisionSet::new();
        set.try_insert(&long_component)
            .expect("insert must succeed");
        let err = set
            .try_insert(&long_component.to_lowercase())
            .expect_err("collision must be detected for a long path");
        assert!(
            err.message().contains("..."),
            "message must indicate truncation for a long path: {:?}",
            err.message()
        );
    }

    /// IO-5: `check_case_collisions` はバッチ全体を照合し、最初に検出した
    /// 衝突（この場合は 2 番目の `"b"` と 3 番目の `"b"`。1・4 番目の `"a"` は
    /// 完全一致で衝突にならない）で打ち切って返す。
    #[test]
    fn io5_check_case_collisions_returns_first_collision() {
        let err = check_case_collisions(["a", "B", "b", "A"])
            .expect_err("first case-only collision must be returned");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().contains('B'));
        assert!(err.message().contains('b'));
    }

    /// IO-5: `check_case_collisions` は衝突が無ければ `Ok(())`。
    #[test]
    fn io5_check_case_collisions_accepts_non_colliding_batch() {
        check_case_collisions(["a", "b", "dir/c"]).expect("non-colliding batch must be accepted");
    }

    /// IO-5: `CaseCollisionSet` / `AdmittedHeader` と同じ契約
    /// （`recv_limits.rs` の前例）で `Send` を確認する。
    #[test]
    fn io5_case_collision_set_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CaseCollisionSet>();
    }
}
