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
//! サーバーのファイル作成経路は [`crate::guest_files::GuestFileCreator::create_file`]
//! （TASK-19.2・#100）が [`CaseCollisionSet`] を呼び出して衝突を検査する。
//! 現行の [`crate::payload::RequestEnvelope`] にはファイルパスを表すフィールドが
//! まだ無く、ワイヤー上の作成要求からの呼び出しは未実装（REPAIR-3: 実装済みを
//! 装わない。詳細は `guest_files` のモジュール doc）。
//!
//! # 衝突判定の単位: パスの全祖先プレフィックス
//! ホスト上では、パス `A/b` を作ると中間ディレクトリ `A` も実体として存在する。
//! そのため衝突はパス全体ではなく**各プレフィックス（祖先ディレクトリ・末端）
//! ごと**に判定する。[`CaseCollisionSet`] はゲスト相対パスを木（親ノード＋
//! 畳み込み済みコンポーネント）として登録し、同じ親の下で畳み込み結果が同じ
//! なのに元の表記が異なるコンポーネントを衝突とする。これにより、深さの
//! 異なる衝突（ファイル `a` とディレクトリ `A` 配下の `A/b` など。ホスト上では
//! 名前 `a` と `A` が同一実体になる）も検出する。
//!
//! 大文字小文字まで一致する「ファイル `a` とディレクトリ `a`（`a/b`）」の
//! 組み合わせは衝突として扱わない。これはホストとゲストで挙動が変わらない
//! 種別の不一致（ゲスト自身でも EEXIST / ENOTDIR 等になる）であり、IO-5 が
//! 扱う大文字小文字非区別に起因する黙った上書きではないため。
//!
//! # 畳み込み方式と、これが近似であること（REPAIR-3）
//! 大文字小文字の畳み込みは各文字へ lower → upper → lower を順に適用する方式
//! （[`fold_component`] 参照）で、Unicode の case folding の近似に過ぎない。
//! APFS の `casefold` 正規化表・NTFS の upcase table と厳密に一致することは
//! 主張しない。方式は「衝突の見逃しより過検出を選ぶ」よう選んでいる: 見逃しは
//! ホスト側での黙った上書き（データ損失）に直結するが、過検出はゲストに見える
//! エラーで済むため。この方針により `ß` は `"SS"`/`"ss"` と衝突検出される
//! （Unicode の simple case folding では非衝突だが、意図して過検出側に倒す）。
//!
//! # 未決事項: Unicode 正規化（NFC / NFD）
//! 本モジュールは Unicode 正規化を行わない。合成済み `é`（U+00E9）と分解形
//! `e` + U+0301 は別名として扱い、衝突として検出しない。APFS（正規化非区別）
//! と ext4（バイト列で区別）の差をどう扱うか（正規化を統一するか、差異を検出
//! してエラーにするか）は #103（TASK-21.h1・IO-5。担当は人間）で方針決定待ち
//! であり、本モジュールでは先取りしない。
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
//! （[`crate::guest_files`] のコンポーネント検証・祖先確認・`create_new`。#100）の
//! 責務であり、本モジュールの検証はそれとは独立に、同一表記
//! ゆれ（`a//B` と `a/b` など）で衝突検出をすり抜けさせないための入力正規化に
//! すぎない。
//!
//! # スコープ外（後続タスクへの引き継ぎ・既知の限界）
//! - サーバーのファイル作成経路への組み込み・結合試験 → #100（TASK-19.2。
//!   `guest_files` で実装済み。ワイヤー上の作成要求は未実装）
//! - パス長 260 超の検出 → TASK-20
//! - NFC / NFD の Unicode 正規化方針 → #103（TASK-21.h1）で決定後に TASK-21
//! - APFS / NTFS の実際の case folding 表との厳密な一致・非 UTF-8 ファイル名の
//!   扱い → TASK-21 以降
//! - Windows（Win32 API 経由）固有の名前の同一視（末尾の `.` / 空白の除去・
//!   8.3 短縮名・`CON` 等の予約デバイス名）は大文字小文字とは別種の差異であり、
//!   本モジュールは検出しない（担当タスク未確定）
//! - 削除・リネームは追跡しない。登録は追加のみのため、時系列上は解消済みの
//!   衝突（`Foo` を削除してから `foo` を作る等）も衝突として報告する
//!   （過検出側。方針どおり）

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

/// 木構造上のノード識別子（非公開）。[`ROOT_NODE`] が根（ゲスト相対パスの起点）。
type NodeId = usize;

/// 根ノードの識別子。実ノードには 1 以降を割り当てる。
const ROOT_NODE: NodeId = 0;

/// 1 コンポーネントを大文字小文字について畳み込む（IO-5）。
///
/// 各文字へ `to_lowercase` → `to_uppercase` → `to_lowercase` を順に適用する。
/// 2 段階（upper → lower）や lower のみでは見逃す衝突があるため 3 段階にしている:
/// - lower のみ: 語末シグマ `ς`（U+03C2）・long s `ſ`（U+017F）・ドットなし i
///   `ı`（U+0131）が自分自身に留まり、`σ`/`s`/`i` との衝突を見逃す
/// - upper → lower: 大文字の sharp s `ẞ`（U+1E9E）は `to_uppercase` で自分自身に
///   留まって `ß` へ畳み込まれる一方、`ß` 自身は `"SS"` 経由で `"ss"` に
///   畳み込まれるため、`ẞ` と `ß` の衝突を見逃す
///
/// lower → upper → lower は全 Unicode スカラー値について「文字を
/// `to_lowercase` / `to_uppercase` した結果と畳み込み結果が一致する」「畳み込みが
/// 冪等である」ことを `io5_fold_is_invariant_under_case_mapping_for_all_chars` で
/// 網羅的に固定している（std の Unicode テーブル更新時の退行も検出する）。
///
/// `str::to_lowercase()`（文字列全体への一括変換）を使わない理由は、それが
/// 語末シグマをコンテキスト依存で `ς` に変換する規則を持ち、`"ΣΣ"` と `"σσ"` が
/// 異なる畳み込み結果になって衝突を見逃しうるため（`io5_final_sigma_folds_consistently`
/// で固定）。文字ごとの変換はコンテキストを見ないためこの揺れが無い。
///
/// # 見逃しより過検出（既知のトレードオフ）
/// `ß`（U+00DF）は `"ss"` へ畳み込まれ、`"SS"` / `"ss"` と衝突として検出される
/// （Unicode simple case folding では非衝突）。モジュール doc の方針
/// 「見逃しよりも過検出を選ぶ」どおりの意図した挙動であり、
/// `io5_sharp_s_is_detected_as_collision` で固定する。
pub(crate) fn fold_component(component: &str) -> String {
    component
        .chars()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

/// 衝突判定の索引キー（非公開 newtype）: 親ノード＋畳み込み済みコンポーネント。
///
/// 親ノードを含めることで、同じディレクトリ内の同名（大文字小文字非区別）だけを
/// 同一視し、別ディレクトリの同名（`a/Foo` と `b/foo`）は区別する。パス全体を
/// キーにしない理由はモジュール doc「衝突判定の単位」参照。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CaseFoldKey {
    parent: NodeId,
    folded: String,
}

impl CaseFoldKey {
    fn new(parent: NodeId, component: &str) -> Self {
        Self {
            parent,
            folded: fold_component(component),
        }
    }
}

/// 索引に登録済みの 1 コンポーネント（木の 1 ノード）の情報。
#[derive(Debug)]
struct NodeEntry {
    /// このノード自身の識別子（子ノードの [`CaseFoldKey::parent`] になる）。
    id: NodeId,
    /// 最初に登録されたときの元の表記（大文字小文字を保ったコンポーネント）。
    original: String,
    /// このノードを新設したパスの [`CaseCollisionSet::origins`] 上の位置
    /// （衝突時のメッセージで既存パスとして示す）。
    introduced_by: usize,
    /// このノードで終わるパスが登録済みか（[`CaseCollisionSet::len`] の計数用）。
    is_path_end: bool,
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
pub(crate) fn quote_for_message(path: &str) -> String {
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

/// 衝突を表す構造化エラーを組み立てる。パス・コンポーネントはすべて
/// [`quote_for_message`] で衛生化してから埋め込む（生の値を埋め込まない）。
pub(crate) fn collision_error(
    path: &str,
    existing_path: &str,
    component: &str,
    existing_component: &str,
) -> IoError {
    IoError::new(
        IoErrorCode::AlreadyExists,
        format!(
            "case-insensitive path collision: {} conflicts with existing {} \
             (components {} and {} differ only by case)",
            quote_for_message(path),
            quote_for_message(existing_path),
            quote_for_message(component),
            quote_for_message(existing_component),
        ),
    )
}

/// 大文字小文字だけで衝突するパスを検出する状態つきの索引（TASK-19.1・IO-5）。
///
/// # 契約
/// - [`Self::try_insert`] は検証・畳み込み・照合を経て、既存のどのパスとも
///   衝突しないパス（初出・完全一致の再登録・大文字小文字まで一致する祖先を
///   共有するパス）を `Ok(())` で受理する。いずれかの祖先プレフィックスまたは
///   末端が、同じ親の下の既存コンポーネントと大文字小文字の違いだけで異なる
///   場合は [`IoErrorCode::AlreadyExists`] を返す（深さの異なる衝突を含む。
///   モジュール doc「衝突判定の単位」参照）。
/// - エラー時は索引を変更しない（衝突・形式不正のパスは登録されない）。
/// - `Send` / `Sync` は自動導出される（内部可変性を持たないフィールドのみの
///   ため）。複数スレッドで共有する場合は呼び出し側で同期する。
/// - アロケーション量は挿入したパスの長さに比例する定数倍に収まり（ノードは
///   コンポーネントごとに 1 つ、パス全文は新設ノードがあるときだけ 1 回保持）、
///   宣言された件数から事前確保しない（coding-rust.md「長さ・件数を上限検証
///   してからアロケーションに使う」への対応。件数・長さの上限〔バッチ上限等〕は
///   呼び出し側の責務）。木は `HashMap` 上の平坦な表現で持ち、再帰的な構造体を
///   作らないため、深いパスでも drop 時に再帰しない。
#[derive(Debug, Default)]
pub struct CaseCollisionSet {
    /// (親ノード, 畳み込み済みコンポーネント) → ノード情報。
    nodes: HashMap<CaseFoldKey, NodeEntry>,
    /// ノードを新設したパス（衝突メッセージで既存パスとして示す）。
    origins: Vec<String>,
    /// 登録済みの異なるパスの件数。
    path_count: usize,
}

impl CaseCollisionSet {
    /// 空の索引を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 索引に登録済みの（完全一致で重複しない）パス件数を返す。
    ///
    /// 祖先として暗黙に登録されたディレクトリは数えない（`"a/b"` だけを登録
    /// した場合は 1。その後 `"a"` を登録すると 2）。
    pub fn len(&self) -> usize {
        self.path_count
    }

    /// 索引が空かどうかを返す。
    pub fn is_empty(&self) -> bool {
        self.path_count == 0
    }

    /// `path` が（大文字小文字まで完全一致で）登録済みのパスかを返す（索引は変更
    /// しない。形式不正のパスは `false`）。
    ///
    /// 呼び出し側が「新規登録になる場合だけ件数上限を適用する」判定に使う
    /// （TASK-19.2・IO-5。`crate::guest_files` の索引上限。完全一致の再登録は
    /// [`Self::len`] を増やさないため上限の対象外）。
    pub fn contains(&self, path: &str) -> bool {
        let Ok(components) = validate_guest_relative_path(path) else {
            return false;
        };
        let mut parent = ROOT_NODE;
        let mut is_path_end = false;
        for component in &components {
            match self.nodes.get(&CaseFoldKey::new(parent, component)) {
                Some(entry) if entry.original == *component => {
                    parent = entry.id;
                    is_path_end = entry.is_path_end;
                }
                _ => return false,
            }
        }
        is_path_end
    }

    /// `path` を登録せずに、[`Self::try_insert`] が衝突で失敗するかだけを検査する
    /// （索引は変更しない。TASK-19.2・IO-5。ファイル作成の成功後に
    /// [`Self::try_insert`] で登録を確定する呼び出し側が、失敗した作成の登録を
    /// 索引へ残さないために使う）。
    ///
    /// 形式不正は [`IoErrorCode::InvalidArgument`]、大文字小文字だけが違う既存
    /// コンポーネントとの衝突は [`IoErrorCode::AlreadyExists`]（メッセージは
    /// [`Self::try_insert`] と同じ）。既存ノードが無い位置から下はすべて新設に
    /// なり衝突しえないため、そこで検査を打ち切る。
    pub fn check_insertable(&self, path: &str) -> Result<(), IoError> {
        let components = validate_guest_relative_path(path)?;
        let mut parent = ROOT_NODE;
        for component in &components {
            match self.nodes.get(&CaseFoldKey::new(parent, component)) {
                Some(entry) => {
                    if entry.original != *component {
                        let existing_path = self
                            .origins
                            .get(entry.introduced_by)
                            .map_or("", String::as_str);
                        return Err(collision_error(
                            path,
                            existing_path,
                            component,
                            &entry.original,
                        ));
                    }
                    parent = entry.id;
                }
                None => return Ok(()),
            }
        }
        Ok(())
    }

    /// `path` を検証・畳み込みしたうえで索引へ登録する。
    ///
    /// # 挙動
    /// 1. [`validate_guest_relative_path`] で形式を検証する（不正なら
    ///    [`IoErrorCode::InvalidArgument`]）
    /// 2. 根から順に各コンポーネントを [`CaseFoldKey`]（親ノード＋畳み込み結果）
    ///    で引く
    /// 3. 既存ノードがあり、元の表記も完全一致するならそのノードへ降りる
    ///    （同一ディレクトリの共有・同一ファイルへの複数回書き込みは正常な処理）
    /// 4. 既存ノードがあり、元の表記が大文字小文字の違いだけで異なるなら
    ///    [`IoErrorCode::AlreadyExists`] を返す。`message` には両方のパスと
    ///    衝突したコンポーネントを [`quote_for_message`] で衛生化して含める
    /// 5. 既存ノードが無ければ新設して降りる
    ///
    /// 4 のエラーは 5 の新設より前にしか起こらない（新設したノードには子が
    /// 無いため、以降のコンポーネントはすべて 5 になる）。したがってエラー時に
    /// 索引は変更されない。
    pub fn try_insert(&mut self, path: &str) -> Result<(), IoError> {
        let components = validate_guest_relative_path(path)?;
        let origin_index = self.origins.len();
        let last_depth = components.len().saturating_sub(1);
        let mut parent = ROOT_NODE;
        let mut created = false;

        for (depth, component) in components.iter().enumerate() {
            let is_last = depth == last_depth;
            // 実ノードの識別子は 1 以降（ROOT_NODE と重ならない）。ノードは
            // 削除しないため「現在の件数 + 1」は既存のどの識別子とも重ならない。
            // `HashMap` の件数は `isize::MAX` 未満に収まるため加算は溢れない。
            let next_id = self.nodes.len() + 1;

            match self.nodes.entry(CaseFoldKey::new(parent, component)) {
                Entry::Occupied(mut occupied) => {
                    let entry = occupied.get_mut();
                    if entry.original != *component {
                        let existing_path = self
                            .origins
                            .get(entry.introduced_by)
                            .map_or("", String::as_str);
                        return Err(collision_error(
                            path,
                            existing_path,
                            component,
                            &entry.original,
                        ));
                    }
                    if is_last && !entry.is_path_end {
                        entry.is_path_end = true;
                        self.path_count = self.path_count.saturating_add(1);
                    }
                    parent = entry.id;
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(NodeEntry {
                        id: next_id,
                        original: (*component).to_string(),
                        introduced_by: origin_index,
                        is_path_end: is_last,
                    });
                    if is_last {
                        self.path_count = self.path_count.saturating_add(1);
                    }
                    parent = next_id;
                    created = true;
                }
            }
        }

        if created {
            self.origins.push(path.to_string());
        }
        Ok(())
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

    /// IO-5: 深さの異なる衝突（ファイル `"a"` とディレクトリ `"A"` 配下の
    /// `"A/b"`）も検出する。ホスト上では `A/b` の作成に中間ディレクトリ `A` が
    /// 必要で、それが既存ファイル `a` と同一実体になるため。
    #[test]
    fn io5_detects_collision_between_file_and_case_differing_directory() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("a").expect("first insert must succeed");

        let err = set
            .try_insert("A/b")
            .expect_err("file \"a\" and directory \"A\" must be detected as a collision");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert_eq!(
            err.message(),
            "case-insensitive path collision: \"A/b\" conflicts with existing \"a\" \
             (components \"A\" and \"a\" differ only by case)"
        );
    }

    /// IO-5: 深さの異なる衝突は登録順が逆（ディレクトリ配下が先、ファイルが後）
    /// でも検出する。深い位置の祖先（`"x/Y/z"` の `"Y"` と `"x/y"`）も同様。
    #[test]
    fn io5_detects_collision_between_directory_and_case_differing_file() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("A/b").expect("first insert must succeed");
        let err = set
            .try_insert("a")
            .expect_err("directory \"A\" and file \"a\" must be detected as a collision");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert_eq!(
            err.message(),
            "case-insensitive path collision: \"a\" conflicts with existing \"A/b\" \
             (components \"a\" and \"A\" differ only by case)"
        );

        let mut set = CaseCollisionSet::new();
        set.try_insert("x/Y/z").expect("first insert must succeed");
        let err = set
            .try_insert("x/y")
            .expect_err("nested ancestor collision must be detected");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert_eq!(
            err.message(),
            "case-insensitive path collision: \"x/y\" conflicts with existing \"x/Y/z\" \
             (components \"y\" and \"Y\" differ only by case)"
        );
    }

    /// IO-5: 衝突として拒否したパスは索引に登録されない（エラー時に索引を
    /// 変更しない契約）。拒否後も既存の表記では引き続き受理され、拒否された
    /// 表記の配下に新しいノードが作られていないことを件数で確認する。
    #[test]
    fn io5_rejected_path_does_not_modify_index() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("a").expect("first insert must succeed");
        set.try_insert("A/b/c")
            .expect_err("collision must be rejected");
        assert_eq!(set.len(), 1);

        set.try_insert("a")
            .expect("existing spelling must still be accepted");
        assert_eq!(set.len(), 1);
        set.try_insert("b/c")
            .expect("unrelated path must be accepted after a rejection");
        assert_eq!(set.len(), 2);
    }

    /// IO-5: 大文字小文字まで一致する祖先の共有（`"dir/a"` と `"dir/b"`）や、
    /// 大文字小文字まで一致するファイルとディレクトリ（`"a"` と `"a/b"`）は
    /// 衝突として扱わない（後者はホストとゲストで挙動が変わらない種別の
    /// 不一致であり IO-5 の対象外。モジュール doc「衝突判定の単位」参照）。
    /// 祖先として暗黙に登録されたディレクトリは件数に数えない。
    #[test]
    fn io5_same_case_prefix_is_not_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("dir/a").expect("insert must succeed");
        set.try_insert("dir/b")
            .expect("shared same-case ancestor must be accepted");
        assert_eq!(set.len(), 2);

        set.try_insert("dir")
            .expect("same-case ancestor itself must be accepted");
        assert_eq!(set.len(), 3);

        let mut set = CaseCollisionSet::new();
        set.try_insert("a").expect("insert must succeed");
        set.try_insert("a/b")
            .expect("same-case file/directory pair is not a case collision");
        assert_eq!(set.len(), 2);
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
    /// なり衝突を見逃すため、char ごとの畳み込み（`fold_component`）で一貫して
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

    /// IO-5: 語末形 `ς`（U+03C2）単体と `σ`（U+03C3）も衝突として検出する。
    /// lower-only 畳み込み（`char::to_lowercase()` のみ）では `ς` が変化せず
    /// 見逃されるため、`fold_component` の多段畳み込みで検出できることを
    /// 固定する回帰テスト。
    #[test]
    fn io5_final_sigma_folds_consistently_both_directions() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("σ.txt").expect("first insert must succeed");

        let err = set
            .try_insert("ς.txt")
            .expect_err("final-sigma form must collide with sigma");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: ラテン文字の long s `ſ`（U+017F）は `s`/`S` と衝突として検出する。
    /// トルコ語系のドットなし i `ı`（U+0131）も `I` と衝突として検出する。
    /// いずれも lower-only 畳み込みでは自分自身に留まり見逃されるため、
    /// `fold_component` の多段畳み込みで検出できることを固定する回帰テスト。
    #[test]
    fn io5_long_s_and_dotless_i_fold_to_ascii() {
        let mut long_s_set = CaseCollisionSet::new();
        long_s_set
            .try_insert("S.txt")
            .expect("first insert must succeed");
        let err = long_s_set
            .try_insert("ſ.txt")
            .expect_err("long s must collide with S");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);

        let mut dotless_i_set = CaseCollisionSet::new();
        dotless_i_set
            .try_insert("I.txt")
            .expect("first insert must succeed");
        let err = dotless_i_set
            .try_insert("ı.txt")
            .expect_err("dotless i must collide with I");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: `ß` と `SS` は畳み込みで `"ss"` に揃い、衝突として検出される
    /// （Unicode の厳密な simple case folding では非衝突だが、本モジュールの方針
    /// 「見逃しよりも過検出を選ぶ」により意図して過検出側に倒す。モジュール
    /// doc・`fold_component` のドキュメント参照）。
    #[test]
    fn io5_sharp_s_is_detected_as_collision() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("ß.txt").expect("insert must succeed");
        let err = set
            .try_insert("SS.txt")
            .expect_err("ß vs SS must be detected as a collision");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: 大文字の sharp s `ẞ`（U+1E9E）と小文字 `ß`（U+00DF）・`"ss"` も
    /// 衝突として検出する。upper-then-lower の 2 段階では `ẞ` → `"ß"`、
    /// `ß` → `"ss"` と別々に畳み込まれて見逃すため、lower → upper → lower で
    /// 検出できることを固定する回帰テスト（`fold_component` 参照）。
    #[test]
    fn io5_capital_sharp_s_collides_with_sharp_s_and_ss() {
        assert_eq!(fold_component("ẞ"), "ss");
        assert_eq!(fold_component("ß"), "ss");

        let mut set = CaseCollisionSet::new();
        set.try_insert("ẞ.txt").expect("first insert must succeed");
        let err = set
            .try_insert("ß.txt")
            .expect_err("capital sharp s must collide with sharp s");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        let err = set
            .try_insert("ss.txt")
            .expect_err("capital sharp s must collide with ss");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
    }

    /// IO-5: 全 Unicode スカラー値について、`fold_component` が
    /// (1) 文字を `to_lowercase` した結果、(2) `to_uppercase` した結果と同じ
    /// 畳み込み結果を返し、(3) 冪等である（畳み込み結果を再度畳み込んでも
    /// 変わらない）ことを網羅的に確認する。std の Unicode テーブル更新や畳み込み
    /// 方式の変更で「大文字小文字の片側だけが別キーになる」見逃しが生じたら
    /// 失敗する（`ẞ` を見逃した upper-then-lower はこの検査で 1 件失敗する）。
    #[test]
    fn io5_fold_is_invariant_under_case_mapping_for_all_chars() {
        let mut violations = Vec::new();
        for c in (0u32..=0x10_FFFF).filter_map(char::from_u32) {
            let original = c.to_string();
            let lowered: String = c.to_lowercase().collect();
            let uppered: String = c.to_uppercase().collect();
            let folded = fold_component(&original);
            if fold_component(&lowered) != folded
                || fold_component(&uppered) != folded
                || fold_component(&folded) != folded
            {
                violations.push(format!("U+{:04X}", u32::from(c)));
            }
        }
        assert_eq!(violations, Vec::<String>::new());
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
        assert_eq!(
            err.message(),
            "case-insensitive path collision: \"b\" conflicts with existing \"B\" \
             (components \"b\" and \"B\" differ only by case)"
        );
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

    /// IO-5・TASK-19.2: `contains` は完全一致で登録済みのパスだけを `true` にする
    /// （祖先として暗黙に作られたノード・大小違い・形式不正は `false`）。
    #[test]
    fn io5_contains_matches_exact_registered_paths_only() {
        let mut set = CaseCollisionSet::new();
        set.try_insert("a/b").expect("insert");
        assert!(set.contains("a/b"));
        assert!(!set.contains("a"));
        assert!(!set.contains("A/b"));
        assert!(!set.contains("a/B"));
        assert!(!set.contains("a/b/c"));
        assert!(!set.contains("a//b"));
        set.try_insert("a").expect("insert ancestor as a path");
        assert!(set.contains("a"));
        assert_eq!(set.len(), 2);
    }
}
