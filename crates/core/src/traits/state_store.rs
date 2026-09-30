//! `StateStore` 拡張点トレイト（TASK-4.2・CRI-7・PLUG-1・OCI-5・MS-0）。
//!
//! コンテナ状態（[`ContainerStatus`]）の作成・更新・取得・一覧・削除を抽象化する。
//! `ContainerRuntime`（TASK-4.1）とは異なり、実装の既定はここ core 側に置く。
//! PLUG-1・CRI-7（オーナー決定 2026-09-26）・[crate-naming.md](../../../../docs/design/crate-naming.md)
//! 決定 6 による境界は次の通り。
//!
//! 1. トレイト定義は本 crate（core）に置く
//! 2. ファイルベースの既定実装も core に置く（TASK-31・OCI-5。
//!    `crate::state_store::FileStateStore` に実装済み〔TASK-31.1〕）。常駐デーモンを持たない CORE-1 と整合する
//! 3. 別実装（分散ストア等）は plugin として差し替えられる（TASK-107/114）。core 側の
//!    proxy が UDS RPC に変換して `Box<dyn StateStore>` として呼び出し側へ渡す
//! 4. supervisor は 2 つ目の実装を持たない（crate-naming.md 決定 6）
//!
//! # 契約
//! 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）
//! 2. 相手の応答を待つ処理（plugin RPC 等）は無期限に待たず、上限時間を超えたら
//!    [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の決定は
//!    proxy 実装（G8・TASK-107/114）の責務であり、本トレイトは契約のみを定める
//! 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn StateStore>` として複数スレッド
//!    から共有できることを前提にしてよい
//! 4. 書き込みは不可分にする（読み手は旧値か新値のどちらかだけを見て、途中状態を
//!    見ない）。実現手段（一時ファイルと rename 等）は実装側の責務とする
//! 5. 状態ファイルのパス（OCI-5 の `/run/fandhe-container/<id>/state.json` 等）は
//!    トレイトに出さない。実装の内部事情とし、分散ストアへ差し替えられるようにする
//! 6. plugin の信頼境界（PLUG-11・PLUG-12）はこのトレイトの外側、境界機構
//!    （`fandhe-container-plugin`）の責務。plugin 実装からの応答は untrusted として扱い、
//!    proxy 実装は [`StateList::records`] の件数が要求した [`ListStateRequest::page_size`]
//!    を超えていないか、[`StateListCursor`] の長さが [`MAX_CURSOR_LEN`] を超えていないか、
//!    [`TraitError::message`] の長さが上限内かを検証してからアロケーションする
//! 7. 状態レコードとエラーメッセージに秘密情報（レジストリ資格情報等）を含めない
//!    （security.md）
//!
//! メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。
//! `ContainerRuntime`（TASK-4.1）と同じく dyn 互換（object safety）を保つ。
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない。`StateRevision` による楽観的排他は特に、
//! #19 で確定させる想定。[`StateRevision`] の店舗（ストア）全体での単調採番方式・
//! [`ListStateRequest`] のページング契約は、PR #1076 への codex レビュー指摘
//! （P1 ×2）を受けた暫定対応であり、同じく #19 で確定させる。

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use super::container_runtime::ContainerStatus;
use super::types::{ContainerId, ErrorCode, TraitError};

/// コンテナ状態の作成・更新・取得・一覧・削除を抽象化する拡張点。
///
/// dyn 互換を保つため、メソッドは同期・非ジェネリックにする（`ContainerRuntime` と同じ
/// 方針。coding-rust.md・dependency-policy.md の依存最小方針により async ランタイムへの
/// 依存を追加しない）。
pub trait StateStore: Send + Sync {
    /// 新しいコンテナ状態を作成する（revision はストア全体で単調に採番された
    /// 未使用の値になる。新規ストアでの最初の 1 件は [`StateRevision::INITIAL`]
    /// になるが、それ以降の `create` はこれを返すとは限らない）。
    ///
    /// 前提: 同じ [`ContainerId`] のレコードが存在しないこと。存在する場合は
    /// [`ErrorCode::AlreadyExists`] を返す。`update`（upsert）にしない理由は、
    /// `ContainerRuntime::create` の二重作成検出をストア側で不可分に判定できるようにする
    /// ため。対応: OCI-5・CRI-7・ERR-2。
    ///
    /// # revision の再利用禁止（#19 codex レビュー P1 対応）
    /// 同じ [`ContainerId`] が削除後に再作成された場合でも、新しいレコードの revision は
    /// 過去にそのストアが発行したどの revision とも異なる値にする（etcd の
    /// `mod_revision` と同じ、ストア全体で単調増加するグローバル採番。line 93 参照）。
    /// `create` の度に [`StateRevision::INITIAL`] へ巻き戻すと、削除前の旧レコードを
    /// 読んだクライアントが保持する旧 revision が、たまたま同じ値になった新レコードに
    /// 対して `update`/`delete` を誤って成功させてしまう（楽観的排他の消失。
    /// 特に `delete` は新しい状態を誤って消す）。実装（TASK-31・G8）はこの採番位置を
    /// ストア再起動をまたいで永続化する必要がある。既存レコードの revision の
    /// 最大値から復元する方式は、削除済みレコードの revision を再発行してしまうため
    /// 不十分（別途ハイウォーターマークとして永続化する）。
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError>;

    /// 既存のコンテナ状態を更新する（楽観的排他）。
    ///
    /// 前提: 対象レコードが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// `req.expected_revision()` が現在の revision と一致しなければ
    /// [`ErrorCode::FailedPrecondition`] を返す（並行書き込みによる更新の消失を検出する）。
    /// 対応: OCI-5・CRI-7・ERR-2。
    ///
    /// 更新後の revision も `create` と同じストア全体の単調採番から払い出す
    /// （対象レコードの revision に単純に `+1` するのではない）。同一 ID を対象にした
    /// 単純な `+1` は、削除・再作成を挟んだ別レコードが過去に使った revision の値域へ
    /// 再突入し得るため、上記 `create` の再利用禁止契約を破ってしまう。
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError>;

    /// コンテナ状態を取得する。
    ///
    /// 前提: 対象レコードが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// 対応: OCI-5・CRI-7・ERR-2。
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError>;

    /// コンテナ状態を 1 ページ分一覧する。
    ///
    /// 返すレコード数は [`ListStateRequest::page_size`] を超えない。まだ残りがある場合は
    /// [`StateList::next_cursor`] に続きを取得するためのカーソルが入り、呼び出し側は
    /// それを次回の [`ListStateRequest`] に渡す。無制限に全件確保することを禁じ、件数の
    /// 上限をトレイト契約レベルで表現する（#19 codex レビュー P1 対応。
    /// coding-rust.md の「長さ・件数を上限検証してからアロケーションに使う」）。
    /// `req.cursor()` が不正・失効している場合は [`ErrorCode::InvalidArgument`] を返す。
    /// 対応: OCI-5・CRI-7。
    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError>;

    /// コンテナ状態を削除する（楽観的排他）。
    ///
    /// 前提: 対象レコードが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// `req.expected_revision()` が現在の revision と一致しなければ
    /// [`ErrorCode::FailedPrecondition`] を返す。`update` と同じ理由（読み取り後に
    /// 別の書き込みが状態を更新した場合、古い判断に基づく削除が新しい状態を消してしまう
    /// のを防ぐ）で、削除にも revision の照合を要求する。対応: OCI-5・CRI-7・ERR-2。
    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError>;
}

/// ストアが採番するレコードの世代番号（楽観的排他に使う）。
///
/// 呼び出し側は [`UpdateStateRequest`] の `expected_revision` として渡すだけで、値を
/// 組み立てない。TASK-157（CLI と supervisor の書き込み排他）や、将来の分散ストア
/// （etcd 等の mod_revision）に、トレイトのシグネチャを変えずに対応するために設ける。
///
/// 暫定仕様。#19（TASK-4.h1）の人間アーキテクチャレビューで確定させる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateRevision(u64);

impl StateRevision {
    /// 新規ストアが最初に払い出す revision。
    ///
    /// ストアの寿命全体で単調に増加するグローバル採番の起点であり、`create` の度に
    /// 割り当てられる値ではない（2 件目以降の `create`・`update` はこの値を返さない）。
    /// 詳細は [`StateStore::create`] の「revision の再利用禁止」を参照。
    pub const INITIAL: StateRevision = StateRevision(0);

    /// 次の revision を返す。`u64` の上限に達している場合は [`ErrorCode::Internal`] を返す
    /// （オーバーフローで revision が巻き戻り、楽観的排他の前提が崩れるのを防ぐ）。
    pub fn next(self) -> Result<Self, TraitError> {
        self.0
            .checked_add(1)
            .map(StateRevision)
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "state revision overflow"))
    }

    /// revision の値を返す。
    pub fn value(self) -> u64 {
        self.0
    }

    /// 生の `u64` 値から `StateRevision` を復元する。
    ///
    /// TASK-31 のファイルベース既定実装が `state.json` から revision を読み戻す場合や、
    /// plugin proxy がワイヤーフレームから revision を復元する場合に使う（`next()` を
    /// 繰り返し呼ぶ以外に構築手段がなかったための追加）。値の正当性（実際にストアが
    /// 発行した revision であること）は呼び出し側の責務とし、本メソッドは検証しない。
    ///
    /// 暫定仕様。#19（TASK-4.h1）の人間アーキテクチャレビューで確定させる。
    pub fn from_raw(value: u64) -> Self {
        StateRevision(value)
    }
}

/// コンテナ状態のレコード（[`StateStore`] が保持・返却する単位）。
///
/// 真偽値やフラットな文字列ではなく、将来の拡張に備えて構造化された型にする
/// （coding-rust.md）。supervisor が使う項目（`supervisor_pid`・`health`・
/// `restart_count`。crate-naming.md 決定 6・TASK-157）や Pod サンドボックス状態
/// （CRI 系）は、`#[non_exhaustive]` のもとで後続タスクが追加する想定。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateRecord {
    status: ContainerStatus,
    bundle: PathBuf,
    revision: StateRevision,
}

impl StateRecord {
    /// コンテナ状態・OCI bundle の絶対パス・revision からレコードを作る。
    ///
    /// `bundle` が絶対パスでない場合は [`ErrorCode::InvalidArgument`] を返す（fail-closed。
    /// `ContainerRuntime::CreateRequest::new` と同じ検証方針）。rootfs の外を指していないか
    /// 等の詳しい検証は実装側（TASK-31・G3）の責務であり、本トレイトは形式検証のみを行う。
    pub fn new(
        status: ContainerStatus,
        bundle: PathBuf,
        revision: StateRevision,
    ) -> Result<Self, TraitError> {
        if !bundle.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bundle path must be absolute",
            ));
        }
        Ok(Self {
            status,
            bundle,
            revision,
        })
    }

    /// 対象コンテナの ID を返す（`status().id()` への委譲）。
    pub fn id(&self) -> &ContainerId {
        self.status.id()
    }

    /// コンテナ状態を返す。
    pub fn status(&self) -> &ContainerStatus {
        &self.status
    }

    /// OCI bundle の絶対パスを返す。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    /// 現在の revision を返す。
    pub fn revision(&self) -> StateRevision {
        self.revision
    }
}

/// [`StateStore::create`] の要求。
///
/// revision は持たない（ストアがストア全体の単調採番から次の未使用値を割り当てる。
/// [`StateStore::create`] の「revision の再利用禁止」参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateStateRequest {
    status: ContainerStatus,
    bundle: PathBuf,
}

impl CreateStateRequest {
    /// コンテナ状態と OCI bundle の絶対パスから要求を作る。
    ///
    /// `bundle` が絶対パスでない場合は [`ErrorCode::InvalidArgument`] を返す。
    pub fn new(status: ContainerStatus, bundle: PathBuf) -> Result<Self, TraitError> {
        if !bundle.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bundle path must be absolute",
            ));
        }
        Ok(Self { status, bundle })
    }

    /// 対象コンテナの ID を返す（`status().id()` への委譲）。
    pub fn id(&self) -> &ContainerId {
        self.status.id()
    }

    /// 作成するコンテナ状態を返す。
    pub fn status(&self) -> &ContainerStatus {
        &self.status
    }

    /// OCI bundle の絶対パスを返す。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }
}

/// [`StateStore::update`] の要求。
///
/// bundle は作成後に変わらない前提のため含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateStateRequest {
    status: ContainerStatus,
    expected_revision: StateRevision,
}

impl UpdateStateRequest {
    /// 更新後のコンテナ状態と、更新前提となる revision から要求を作る。
    pub fn new(status: ContainerStatus, expected_revision: StateRevision) -> Self {
        Self {
            status,
            expected_revision,
        }
    }

    /// 対象コンテナの ID を返す（`status().id()` への委譲）。
    pub fn id(&self) -> &ContainerId {
        self.status.id()
    }

    /// 更新後のコンテナ状態を返す。
    pub fn status(&self) -> &ContainerStatus {
        &self.status
    }

    /// 更新前提となる revision を返す（楽観的排他）。
    pub fn expected_revision(&self) -> StateRevision {
        self.expected_revision
    }
}

/// [`StateStore::get`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GetStateRequest {
    id: ContainerId,
}

impl GetStateRequest {
    /// 対象コンテナの ID から要求を作る。
    pub fn new(id: ContainerId) -> Self {
        Self { id }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }
}

/// [`StateStore::delete`] の要求。
///
/// `update` と同じ楽観的排他を課すため `expected_revision` を持つ（#19 の P1 指摘対応。
/// revision を持たない旧仕様では、読み取り後に別の書き込みが状態を更新していても
/// 古い判断に基づく削除が成功し、新しい状態を消してしまっていた）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteStateRequest {
    id: ContainerId,
    expected_revision: StateRevision,
}

impl DeleteStateRequest {
    /// 対象コンテナの ID と、削除前提となる revision から要求を作る。
    pub fn new(id: ContainerId, expected_revision: StateRevision) -> Self {
        Self {
            id,
            expected_revision,
        }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 削除前提となる revision を返す（楽観的排他）。
    pub fn expected_revision(&self) -> StateRevision {
        self.expected_revision
    }
}

/// [`ListStateRequest::page_size`] に指定できる最大値（#19 codex レビュー P1 対応）。
///
/// plugin proxy 実装はこの値を上限として要求・応答を検証し、無制限なアロケーションを
/// 防ぐ（coding-rust.md「長さ・件数を上限検証してからアロケーションに使う」）。
/// 暫定値。#19（TASK-4.h1）のアーキテクチャレビューで確定させる。
pub const MAX_PAGE_SIZE: u32 = 1_000;

/// [`StateListCursor`] に許容する最大バイト長。
///
/// カーソルは実装（TASK-31 のファイルベース実装・plugin proxy）が発行する不透明な
/// トークンだが、plugin からの応答は untrusted な外部入力として扱い、
/// アロケーション前に長さを検証する（security.md・coding-rust.md）。
pub const MAX_CURSOR_LEN: usize = 4_096;

/// [`StateStore::list`] の要求。
///
/// 1 ページあたりの最大件数（[`MAX_PAGE_SIZE`] 以下）を必須で持たせることで、
/// 無制限な全件確保をトレイト契約レベルで防ぐ（#19 codex レビュー P1 対応）。
/// 将来の追加フィルタは新しいフィールドの追加で拡張する（`#[non_exhaustive]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListStateRequest {
    page_size: NonZeroU32,
    cursor: Option<StateListCursor>,
}

impl ListStateRequest {
    /// 1 ページあたりの最大件数から、カーソルなし（先頭ページ）の要求を作る。
    ///
    /// `page_size` が [`MAX_PAGE_SIZE`] を超える場合は [`ErrorCode::InvalidArgument`]
    /// を返す。
    pub fn new(page_size: NonZeroU32) -> Result<Self, TraitError> {
        if page_size.get() > MAX_PAGE_SIZE {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "page_size exceeds MAX_PAGE_SIZE",
            ));
        }
        Ok(Self {
            page_size,
            cursor: None,
        })
    }

    /// 前回の [`StateList::next_cursor`] を指定し、続きのページを要求する。
    pub fn with_cursor(mut self, cursor: StateListCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// 1 ページあたりの最大件数を返す。
    pub fn page_size(&self) -> NonZeroU32 {
        self.page_size
    }

    /// 続きのページを取得するためのカーソルを返す（先頭ページなら `None`）。
    pub fn cursor(&self) -> Option<&StateListCursor> {
        self.cursor.as_ref()
    }
}

/// [`StateStore::list`] のページ送りに使う不透明なカーソル。
///
/// 値の形式は実装の内部事情とし、トレイトはバイト長の上限（[`MAX_CURSOR_LEN`]）のみを
/// 規定する。plugin からの応答は untrusted な外部入力のため、`from_raw` は検証付きで
/// `Result` を返す（無検証の構築手段を公開しない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StateListCursor(String);

impl StateListCursor {
    /// 生のトークン文字列からカーソルを作る。[`MAX_CURSOR_LEN`] バイトを超える場合は
    /// [`ErrorCode::InvalidArgument`] を返す。
    pub fn from_raw(token: String) -> Result<Self, TraitError> {
        if token.len() > MAX_CURSOR_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "cursor exceeds MAX_CURSOR_LEN",
            ));
        }
        Ok(Self(token))
    }

    /// カーソルのトークン文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// [`StateStore::list`] の応答。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateList {
    records: Vec<StateRecord>,
    next_cursor: Option<StateListCursor>,
}

impl StateList {
    /// レコード一覧と、続きがある場合のカーソルから応答を作る。
    ///
    /// `next_cursor` が `Some` であることは「まだ残りがある」ことを意味し、`None` は
    /// このページが最後であることを意味する。
    pub fn new(records: Vec<StateRecord>, next_cursor: Option<StateListCursor>) -> Self {
        Self {
            records,
            next_cursor,
        }
    }

    /// レコード一覧への参照を返す（要求した [`ListStateRequest::page_size`] 以下）。
    pub fn records(&self) -> &[StateRecord] {
        &self.records
    }

    /// レコード一覧を所有権ごと取り出す。
    pub fn into_records(self) -> Vec<StateRecord> {
        self.records
    }

    /// 続きのページを取得するためのカーソルを返す（残りがなければ `None`）。
    pub fn next_cursor(&self) -> Option<&StateListCursor> {
        self.next_cursor.as_ref()
    }
}

/// [`StateStore::delete`] の応答。当面は空だが、将来の拡張に備えて構造体にする。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteStateResponse {}

impl DeleteStateResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::collections::{BinaryHeap, HashMap};
    use std::sync::{Arc, Mutex};

    /// [`StubStateStore::list`] の有界選択で使う比較用ラッパー。`StateRecord` 自体は
    /// 状態・revision も含むため `Ord` を持たず、id のみで全順序を与える。
    struct HeapEntry(StateRecord);

    impl PartialEq for HeapEntry {
        fn eq(&self, other: &Self) -> bool {
            self.0.id().as_str() == other.0.id().as_str()
        }
    }

    impl Eq for HeapEntry {}

    impl PartialOrd for HeapEntry {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for HeapEntry {
        fn cmp(&self, other: &Self) -> Ordering {
            self.0.id().as_str().cmp(other.0.id().as_str())
        }
    }

    /// テスト専用のインメモリスタブ実装。dyn 互換性とメソッドの契約を確認するためのみに
    /// 使い、ライブラリ側の既定実装（TASK-31・OCI-5）はここには置かない（REPAIR-3）。
    ///
    /// `next_revision` はストア全体で単調に増加する採番カウンタで、`create`・`update`
    /// の両方がここから revision を払い出す。削除・再作成を挟んでも同じ値を再発行しない
    /// ことで、#19 codex レビュー P1（PR #1076）の revision 再利用を防ぐ。
    struct StubStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        next_revision: Mutex<StateRevision>,
    }

    impl StubStateStore {
        fn new() -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                next_revision: Mutex::new(StateRevision::INITIAL),
            }
        }

        /// ストア全体で一意な revision を 1 つ払い出す。
        fn allocate_revision(&self) -> Result<StateRevision, TraitError> {
            let mut next = self.next_revision.lock().unwrap_or_else(|e| e.into_inner());
            let allocated = *next;
            *next = allocated.next()?;
            Ok(allocated)
        }
    }

    impl StateStore for StubStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "container state already exists",
                ));
            }
            let revision = self.allocate_revision()?;
            let record =
                StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let current = records
                .get(req.id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "container state not found"))?;
            if current.revision() != req.expected_revision() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            let bundle = current.bundle().to_path_buf();
            let next_revision = self.allocate_revision()?;
            let updated = StateRecord::new(req.status().clone(), bundle, next_revision)?;
            records.insert(req.id().clone(), updated.clone());
            Ok(updated)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "container state not found"))
        }

        fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());

            // カーソルが指定された場合は対応する id の存在だけを確認する。全件を
            // Vec に集めてソートすると、要求したページ 1 件分に対してもストア全体の
            // 件数に比例したメモリを確保してしまい、StateStore の「無制限に全件確保
            // しない」契約（本ファイル冒頭の契約コメント）と AGENTS.md のリソース上限
            // 規約に反する（PR #1076 codex レビュー P1 対応）。
            let after_id = match req.cursor() {
                Some(cursor) => {
                    let after_id = cursor.as_str().to_string();
                    let exists = records.keys().any(|id| id.as_str() == after_id);
                    if !exists {
                        return Err(TraitError::new(
                            ErrorCode::InvalidArgument,
                            "unknown list cursor",
                        ));
                    }
                    Some(after_id)
                }
                None => None,
            };

            // page_size は `ListStateRequest::new` が MAX_PAGE_SIZE 以下であることを
            // 検証済みのため、ここでの usize 変換は安全（32bit 環境でも u32 は usize に収まる）。
            let page_size = req.page_size().get() as usize;
            // ページに含み得る上限（page_size + 1。次ページの有無判定用に 1 件多く見る）
            // のみを保持する有界選択に留め、保持サイズをストア全体の件数に依存させない。
            let capacity = page_size.saturating_add(1);
            let mut heap: BinaryHeap<HeapEntry> = BinaryHeap::with_capacity(capacity.min(64));

            for record in records.values() {
                if let Some(after_id) = &after_id
                    && record.id().as_str() <= after_id.as_str()
                {
                    continue;
                }
                if heap.len() < capacity {
                    heap.push(HeapEntry(record.clone()));
                } else if let Some(top) = heap.peek()
                    && record.id().as_str() < top.0.id().as_str()
                {
                    heap.pop();
                    heap.push(HeapEntry(record.clone()));
                }
            }

            // `into_sorted_vec` は id 昇順（HeapEntry の Ord に従う）で最大 capacity 件を返す。
            let mut selected: Vec<StateRecord> = heap
                .into_sorted_vec()
                .into_iter()
                .map(|entry| entry.0)
                .collect();

            let has_next = selected.len() > page_size;
            if has_next {
                selected.truncate(page_size);
            }

            let next_cursor = if has_next {
                let last_id = selected
                    .last()
                    .map(|record| record.id().as_str().to_string())
                    .ok_or_else(|| {
                        TraitError::new(ErrorCode::Internal, "list pagination state inconsistent")
                    })?;
                Some(StateListCursor::from_raw(last_id)?)
            } else {
                None
            };

            Ok(StateList::new(selected, next_cursor))
        }

        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let current = records
                .get(req.id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "container state not found"))?;
            if current.revision() != req.expected_revision() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            records.remove(req.id());
            Ok(DeleteStateResponse::new())
        }
    }

    fn sample_id(name: &str) -> ContainerId {
        ContainerId::new(name).expect("valid id")
    }

    #[cfg(unix)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from("/run/x")
    }

    #[cfg(windows)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from(r"C:\x")
    }

    /// CRI-7: `StateStore` は dyn 互換で、`Box`/`Arc` に収めて create と get を呼べ、
    /// 返る id・state・revision が期待値と一致する。
    #[test]
    fn cri7_state_store_is_dyn_compatible() {
        let boxed: Box<dyn StateStore> = Box::new(StubStateStore::new());
        let id = sample_id("a");
        let status = ContainerStatus::created(id.clone(), None);
        let record = boxed
            .create(&CreateStateRequest::new(status, sample_bundle()).expect("valid bundle"))
            .expect("create succeeds");
        assert_eq!(record.id(), &id);
        assert_eq!(record.status().state().as_str(), "created");
        assert_eq!(record.revision(), StateRevision::INITIAL);

        let shared: Arc<dyn StateStore> = Arc::new(StubStateStore::new());
        let id2 = sample_id("b");
        let status2 = ContainerStatus::created(id2.clone(), None);
        shared
            .create(&CreateStateRequest::new(status2, sample_bundle()).expect("valid bundle"))
            .expect("create succeeds");
        let fetched = shared
            .get(&GetStateRequest::new(id2.clone()))
            .expect("get succeeds");
        assert_eq!(fetched.id(), &id2);
        assert_eq!(fetched.revision(), StateRevision::INITIAL);
    }

    /// OCI-5: 2 回目の create は `"ALREADY_EXISTS"` を返す。
    #[test]
    fn oci5_create_twice_returns_already_exists() {
        let store = StubStateStore::new();
        let id = sample_id("dup");
        let req =
            CreateStateRequest::new(ContainerStatus::created(id.clone(), None), sample_bundle())
                .expect("valid bundle");
        store.create(&req).expect("first create succeeds");

        let err = store.create(&req).expect_err("second create must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// OCI-5: 未登録の ID の get と delete が `"NOT_FOUND"` を返す。
    #[test]
    fn oci5_get_and_delete_missing_return_not_found() {
        let store = StubStateStore::new();
        let missing = sample_id("missing");

        let get_err = store
            .get(&GetStateRequest::new(missing.clone()))
            .expect_err("get must fail for missing id");
        assert_eq!(get_err.code().as_str(), "NOT_FOUND");

        let delete_err = store
            .delete(&DeleteStateRequest::new(missing, StateRevision::INITIAL))
            .expect_err("delete must fail for missing id");
        assert_eq!(delete_err.code().as_str(), "NOT_FOUND");
    }

    /// OCI-5: 古い revision での update が `"FAILED_PRECONDITION"` を返す。正しい
    /// revision なら成功し、revision が `INITIAL.next()` になり、state が `Running` になる。
    #[test]
    fn oci5_update_with_stale_revision_returns_failed_precondition() {
        let store = StubStateStore::new();
        let id = sample_id("c");
        let created = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("create succeeds");
        assert_eq!(created.revision(), StateRevision::INITIAL);

        let stale = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                StateRevision::INITIAL.next().expect("next revision"),
            ))
            .expect_err("stale revision must fail");
        assert_eq!(stale.code().as_str(), "FAILED_PRECONDITION");

        let updated = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                StateRevision::INITIAL,
            ))
            .expect("update succeeds with correct revision");
        assert_eq!(
            updated.revision(),
            StateRevision::INITIAL.next().expect("next revision")
        );
        assert_eq!(updated.status().state().as_str(), "running");
    }

    /// OCI-5: 2 件作成後の list が ID 集合 `{"a","b"}` を返し、1 件 delete した後は
    /// `{"b"}` を返す。
    #[test]
    fn oci5_list_returns_created_records() {
        let store = StubStateStore::new();
        let id_a = sample_id("a");
        let id_b = sample_id("b");
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id_a.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("create a succeeds");
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id_b.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("create b succeeds");

        let page_size = NonZeroU32::new(10).expect("nonzero");
        let listed = store
            .list(&ListStateRequest::new(page_size).expect("valid page size"))
            .expect("list succeeds");
        let mut ids: Vec<String> = listed
            .records()
            .iter()
            .map(|r| r.id().as_str().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);

        store
            .delete(&DeleteStateRequest::new(id_a, StateRevision::INITIAL))
            .expect("delete a succeeds");
        let listed_after = store
            .list(&ListStateRequest::new(page_size).expect("valid page size"))
            .expect("list succeeds");
        let ids_after: Vec<String> = listed_after
            .into_records()
            .into_iter()
            .map(|r| r.id().as_str().to_string())
            .collect();
        assert_eq!(ids_after, vec!["b".to_string()]);
    }

    /// OCI-5: 古い revision での delete が `"FAILED_PRECONDITION"` を返し、レコードは
    /// 削除されずに残る。正しい revision（更新後の最新値）なら削除に成功する（#19 P1 指摘:
    /// 削除にも update と同じ楽観的排他を課す）。
    #[test]
    fn oci5_delete_with_stale_revision_returns_failed_precondition() {
        let store = StubStateStore::new();
        let id = sample_id("d");
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("create succeeds");
        let updated = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                StateRevision::INITIAL,
            ))
            .expect("update succeeds");
        assert_eq!(
            updated.revision(),
            StateRevision::INITIAL.next().expect("next revision")
        );

        // 古い revision（INITIAL）での削除は現在の revision と一致しないため失敗する。
        let stale_err = store
            .delete(&DeleteStateRequest::new(id.clone(), StateRevision::INITIAL))
            .expect_err("stale revision delete must fail");
        assert_eq!(stale_err.code().as_str(), "FAILED_PRECONDITION");

        // レコードは削除されず残っているため get で取得できる。
        let still_present = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("record must still exist after failed delete");
        assert_eq!(still_present.revision(), updated.revision());

        // 正しい revision（最新値）を指定すれば削除に成功する。
        store
            .delete(&DeleteStateRequest::new(id.clone(), updated.revision()))
            .expect("delete succeeds with correct revision");
        let get_err = store
            .get(&GetStateRequest::new(id))
            .expect_err("record must be gone after delete");
        assert_eq!(get_err.code().as_str(), "NOT_FOUND");
    }

    /// CRI-7: `CreateStateRequest::new` と `StateRecord::new` が相対パスを
    /// `"INVALID_ARGUMENT"` で拒否し、絶対パスは受理する。
    #[test]
    fn cri7_state_requests_reject_relative_bundle() {
        let id = sample_id("rel");
        let status = ContainerStatus::created(id.clone(), None);

        let err = CreateStateRequest::new(status.clone(), PathBuf::from("relative"))
            .expect_err("relative path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
        assert!(CreateStateRequest::new(status.clone(), sample_bundle()).is_ok());

        let err2 = StateRecord::new(
            status.clone(),
            PathBuf::from("relative"),
            StateRevision::INITIAL,
        )
        .expect_err("relative path must be rejected");
        assert_eq!(err2.code().as_str(), "INVALID_ARGUMENT");
        assert!(StateRecord::new(status, sample_bundle(), StateRevision::INITIAL).is_ok());
    }

    /// `StateRevision::next` は `INITIAL` の次を +1 にし、`u64::MAX` からの
    /// `next()` は `"INTERNAL"` を返す（オーバーフロー検出）。
    #[test]
    fn cri7_state_revision_next_increments_and_detects_overflow() {
        let next = StateRevision::INITIAL.next().expect("next succeeds");
        assert_eq!(next.value(), 1);

        let max = StateRevision(u64::MAX);
        let err = max.next().expect_err("overflow must be rejected");
        assert_eq!(err.code().as_str(), "INTERNAL");
    }

    /// OCI-5: 削除後に同じ ID を再作成しても revision は再利用されないため、削除前の
    /// revision を保持していたクライアントの `update`/`delete` は新しいレコードに対して
    /// `"FAILED_PRECONDITION"` になる（#19 codex レビュー P1・PR #1076 対応。修正前は
    /// `create` が常に `StateRevision::INITIAL` へ巻き戻していたため、この `update`/
    /// `delete` が誤って成功し、`delete` の場合は新しい状態を消してしまっていた）。
    #[test]
    fn oci5_revision_not_reused_after_delete_and_recreate() {
        let store = StubStateStore::new();
        let id = sample_id("reuse");

        let created = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("create succeeds");
        let stale_revision = created.revision();

        store
            .delete(&DeleteStateRequest::new(id.clone(), stale_revision))
            .expect("delete succeeds");

        let recreated = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    sample_bundle(),
                )
                .expect("valid bundle"),
            )
            .expect("recreate succeeds");
        assert_ne!(recreated.revision(), stale_revision);

        let stale_update_err = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                stale_revision,
            ))
            .expect_err("stale revision update against recreated record must fail");
        assert_eq!(stale_update_err.code().as_str(), "FAILED_PRECONDITION");

        let stale_delete_err = store
            .delete(&DeleteStateRequest::new(id.clone(), stale_revision))
            .expect_err("stale revision delete against recreated record must fail");
        assert_eq!(stale_delete_err.code().as_str(), "FAILED_PRECONDITION");

        let still_present = store
            .get(&GetStateRequest::new(id))
            .expect("recreated record must still exist after stale requests are rejected");
        assert_eq!(still_present.revision(), recreated.revision());
    }

    /// OCI-5: `list` は `page_size` 以下の件数だけを返し、残りがあれば `next_cursor` で
    /// 続きのページを取得できる（#19 codex レビュー P1・PR #1076 対応）。
    #[test]
    fn oci5_list_pagination_respects_page_size() {
        let store = StubStateStore::new();
        for name in ["a", "b", "c"] {
            store
                .create(
                    &CreateStateRequest::new(
                        ContainerStatus::created(sample_id(name), None),
                        sample_bundle(),
                    )
                    .expect("valid bundle"),
                )
                .expect("create succeeds");
        }

        let page_size = NonZeroU32::new(2).expect("nonzero");
        let first_page = store
            .list(&ListStateRequest::new(page_size).expect("valid page size"))
            .expect("list succeeds");
        let first_ids: Vec<String> = first_page
            .records()
            .iter()
            .map(|r| r.id().as_str().to_string())
            .collect();
        assert_eq!(first_ids, vec!["a".to_string(), "b".to_string()]);
        let cursor = first_page
            .next_cursor()
            .cloned()
            .expect("more records remain after first page");

        let second_req = ListStateRequest::new(page_size)
            .expect("valid page size")
            .with_cursor(cursor);
        let second_page = store.list(&second_req).expect("list succeeds");
        assert!(second_page.next_cursor().is_none());
        let second_ids: Vec<String> = second_page
            .into_records()
            .into_iter()
            .map(|r| r.id().as_str().to_string())
            .collect();
        assert_eq!(second_ids, vec!["c".to_string()]);
    }

    /// OCI-5: `page_size` が `MAX_PAGE_SIZE` を超える `ListStateRequest::new` は
    /// `"INVALID_ARGUMENT"` を返し、`MAX_PAGE_SIZE` ちょうどは受理する（#19 codex レビュー
    /// P1・PR #1076 対応。無制限アロケーションの防止）。
    #[test]
    fn oci5_list_request_rejects_page_size_over_max() {
        let too_large = NonZeroU32::new(MAX_PAGE_SIZE + 1).expect("nonzero");
        let err =
            ListStateRequest::new(too_large).expect_err("oversized page_size must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let max_allowed = NonZeroU32::new(MAX_PAGE_SIZE).expect("nonzero");
        assert!(ListStateRequest::new(max_allowed).is_ok());
    }

    /// OCI-5: `StateListCursor::from_raw` は `MAX_CURSOR_LEN` を超えるトークンを
    /// `"INVALID_ARGUMENT"` で拒否し、上限ちょうどは受理する（plugin からの untrusted な
    /// 応答を検証してからアロケーションする契約。security.md・coding-rust.md）。
    #[test]
    fn oci5_state_list_cursor_rejects_oversized_token() {
        let too_long = "x".repeat(MAX_CURSOR_LEN + 1);
        let err =
            StateListCursor::from_raw(too_long).expect_err("oversized cursor must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let max_len = "x".repeat(MAX_CURSOR_LEN);
        assert!(StateListCursor::from_raw(max_len).is_ok());
    }
}
