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
//! 8. [`StateRecord::cgroup`]（コンテナ用 cgroup の配置 [`CgroupPlacement`]。TASK-30.3・OCI-6・CORE-3）は、
//!    `create` で [`CreateStateRequest::cgroup_scope`] が指定されたときだけ、そのスコープと **この create で
//!    割り当てた revision**（instance）の組として記録する。`update` では変更せずに引き継ぎ、`get` / `list` で
//!    返す。plugin 実装も同じく往復させる（落とすと delete が cgroup の削除を飛ばし、cgroup がリークする）。
//!    revision の再利用禁止（[`StateStore::create`]）により instance も再利用されず、instance を含む
//!    cgroup 名（`fc-<id>@<instance>`）は同じ ID の削除・再作成をまたいでも重ならない
//! 9. [`StateRecord::supervision`]（`supervisor_pid`・`health`・`restart_count`。supervisor〔TASK-157〕が
//!    使う項目。SUP-1）は、`create` で [`CreateStateRequest::with_supervision`] の指定があればその値、
//!    なければ既定値（PID なし・healthcheck 未設定・再起動 0 回）で記録する。`update` は
//!    [`UpdateStateRequest::with_supervision`] の指定があれば置き換え、なければ既存の値を引き継ぐ
//!    （CLI 側の status 更新で supervisor の項目を消さないため）。`get` / `list` で返す。plugin 実装も
//!    同じく往復させる。3 項目の相互関係や `status` との制約は本トレイトでは課さない（監視ループの仕様は
//!    supervisor 側のタスクで決める）
//! 10. [`StateRecord::annotations`]（コンテナの label。`--label` 相当。SUP-12・TASK-169.5.1）は、`create` で
//!     [`CreateStateRequest::with_annotations`] の指定があればその値、なければ空で記録し、`update` では
//!     変えずに引き継ぐ（[`UpdateStateRequest`] には持たせない。supervisor の status 更新で label を消さない。
//!     契約 8 と同じ形）。`get` / `list` で返す。plugin 実装も同じく往復させる。純粋なメタデータで、
//!     分離・権限・cgroup 等の判断には使わない
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

/// [`CgroupScope`] 全体の最大バイト数（Linux の `PATH_MAX`）。
pub const MAX_CGROUP_SCOPE_BYTES: usize = 4096;

/// [`CgroupScope`] の要素数の上限（`cgroups` モジュールの cgroup パス深さ上限と同じ）。
const MAX_CGROUP_SCOPE_DEPTH: usize = 64;

/// [`CgroupScope`] の 1 要素の最大バイト数（`NAME_MAX`）。
const MAX_CGROUP_SCOPE_COMPONENT_BYTES: usize = 255;

/// コンテナ用 cgroup を作った委譲スコープ（cgroup v2 の `/sys/fs/cgroup` 起点の絶対パス。TASK-30.3・OCI-6・CORE-3）。
///
/// コンテナ用子 cgroup（`<scope>/fc-<id>@<instance>`）の親を指す。正規形は Linux の
/// `cgroups::DelegatedCgroup::path()` と同じ文字列（ルートは `"/"`、それ以外は `"/a/b"`）で、
/// `oci_runtime::delete` は記録された値と削除側の委譲スコープを文字列の完全一致で照合し、
/// 一致しなければ cgroup にも状態記録にも触れない（別スコープで「cgroup 無し」を誤って確認して
/// 状態記録だけを消すことを防ぐ。fail-closed）。
///
/// 照合は文字列で行うため、記録した側と同じ cgroup 名前空間から見たパスであることが前提である
/// （名前空間が異なり文字列が食い違えば不一致として拒否される）。本型は形式（絶対パス・
/// 各要素が空 / `.` / `..` / NUL でない・要素長・深さ・全体長の上限）だけを検証し、実在は確かめない。
/// 3 OS でビルドする（状態記録は OS に依存しない。CLI-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupScope(String);

impl CgroupScope {
    /// 文字列から作る。形式が不正なら [`ErrorCode::InvalidArgument`]（値はメッセージに含めない）。
    pub fn new(path: &str) -> Result<Self, TraitError> {
        let invalid = || TraitError::new(ErrorCode::InvalidArgument, "invalid cgroup scope path");
        if path.len() > MAX_CGROUP_SCOPE_BYTES {
            return Err(invalid());
        }
        let rest = path.strip_prefix('/').ok_or_else(invalid)?;
        if !rest.is_empty() {
            let mut depth = 0usize;
            for comp in rest.split('/') {
                depth = depth.checked_add(1).ok_or_else(invalid)?;
                if depth > MAX_CGROUP_SCOPE_DEPTH
                    || comp.is_empty()
                    || comp == "."
                    || comp == ".."
                    || comp.len() > MAX_CGROUP_SCOPE_COMPONENT_BYTES
                    || comp.contains('\0')
                {
                    return Err(invalid());
                }
            }
        }
        Ok(Self(path.to_owned()))
    }

    /// 正規形の文字列（`"/"` または `"/a/b"`）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// コンテナ用 cgroup の配置（委譲スコープと instance の組。TASK-30.3・OCI-6・CORE-3）。
///
/// cgroup の実体は `<scope>/fc-<id>@<instance>`（Linux の `cgroups::CgroupName::for_instance`）。instance は
/// ストアがレコードの create で割り当てた revision で、ストア全体で再利用されない（[`StateStore::create`]）。
/// そのため同じ ID のコンテナが削除・再作成されても cgroup 名は重ならず、古いレコードを読んだ delete が
/// 再作成後のコンテナの cgroup を名前で消すことは構成上起きない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupPlacement {
    scope: CgroupScope,
    instance: StateRevision,
}

impl CgroupPlacement {
    /// スコープと instance（create で割り当てた revision）から作る。ストア実装が create で使う。
    pub fn new(scope: CgroupScope, instance: StateRevision) -> Self {
        Self { scope, instance }
    }

    /// コンテナ用 cgroup の親（委譲スコープ）。
    pub fn scope(&self) -> &CgroupScope {
        &self.scope
    }

    /// cgroup 名に埋め込む instance（create 時の revision）。
    pub fn instance(&self) -> StateRevision {
        self.instance
    }
}

/// healthcheck の結果（supervisor〔TASK-157〕が使う。SUP-1・SUP-4）。
///
/// 未知の値を表現できない enum で、STACK-2 の `depends_on` の `healthy` 条件が参照する文字列と
/// 対応する（[`Self::as_str`]）。healthcheck が未設定なら [`StateRecord::health`] は `None`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HealthStatus {
    /// 起動直後でまだ判定が出ていない（supervisor が使う。SUP-1・SUP-4）。
    Starting,
    /// healthcheck が成功している（supervisor が使う。SUP-1・SUP-4）。
    Healthy,
    /// healthcheck が失敗している（supervisor が使う。SUP-1・SUP-4）。
    Unhealthy,
}

impl HealthStatus {
    /// 状態ファイル・ログで使う固定の文字列表現を返す。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// [`Self::as_str`] の逆変換。未知の文字列（大文字小文字違いを含む）は `None`。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "starting" => Some(Self::Starting),
            "healthy" => Some(Self::Healthy),
            "unhealthy" => Some(Self::Unhealthy),
            _ => None,
        }
    }
}

/// supervisor（TASK-157）が使う監視状態の 3 項目（`supervisor_pid`・`health`・`restart_count`。SUP-1）。
///
/// [`StateRecord`] への設定・取得と、[`CreateStateRequest`] / [`UpdateStateRequest`] での受け渡しに使う。
/// `Default` は PID なし・healthcheck 未設定・再起動 0 回。3 項目間や `status` との制約は課さない
/// （監視ループの仕様は supervisor 側のタスクで決める）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SupervisionState {
    supervisor_pid: Option<NonZeroU32>,
    health: Option<HealthStatus>,
    restart_count: u32,
}

impl SupervisionState {
    /// 3 項目から作る。PID 0・負の再起動回数・未知の health は型で表現できない。
    pub fn new(
        supervisor_pid: Option<NonZeroU32>,
        health: Option<HealthStatus>,
        restart_count: u32,
    ) -> Self {
        Self {
            supervisor_pid,
            health,
            restart_count,
        }
    }

    /// 監視プロセス（supervisor）の PID。supervisor（TASK-157）が使う（SUP-1）。
    ///
    /// `None` は監視プロセスが付いていない（未起動・孤児化）。記録値であり PID は再利用され得るため、
    /// この値をそのままシグナル送信先・権限判断に使ってはならない（使う側で生存・同一性を検証する。
    /// SUP-5・SUP-8）。
    pub fn supervisor_pid(&self) -> Option<NonZeroU32> {
        self.supervisor_pid
    }

    /// healthcheck の結果。supervisor（TASK-157）が使う（SUP-1・SUP-4）。`None` は healthcheck 未設定。
    pub fn health(&self) -> Option<HealthStatus> {
        self.health
    }

    /// 再起動回数。supervisor（TASK-157）が使う（SUP-1）。既定は 0。
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }
}

/// [`Annotations`] の件数上限（SUP-12・TASK-169.5.1）。
pub const ANNOTATIONS_MAX_ENTRIES: usize = 64;
/// [`Annotations`] のキー 1 件の最大バイト数。
pub const ANNOTATION_MAX_KEY_BYTES: usize = 255;
/// [`Annotations`] の全キー・値の合計最大バイト数。
///
/// state.json 全体の上限（64 KiB）に対し、JSON エスケープで最悪 6 倍になっても収まる水準。
pub const ANNOTATIONS_MAX_TOTAL_BYTES: usize = 8 * 1024;

/// コンテナのメタデータ（label。OCI state の `annotations` に対応。SUP-12・TASK-169.5.1・MS-9）。
///
/// 文字列 → 文字列の順序付き map（出力順を決定的にするため `BTreeMap`）。件数・長さ・キー形式を
/// 構築時に検証し、壊れた値を表現させない。supervisor の `--label` 解析結果が
/// [`CreateStateRequest::with_annotations`] 経由で [`StateRecord`] に載り、`FileStateStore` が
/// `state.json` へ永続化する。純粋なメタデータで、分離・権限の判断には使わない。
/// 値は利用者入力だが秘密情報の置き場ではないため、`Debug` は伏せない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Annotations(std::collections::BTreeMap<String, String>);

impl Annotations {
    /// (key, value) の列から作る。同一キーは後勝ち。
    ///
    /// キーは空でなく `=`・NUL・制御文字を含まず、値は NUL を含まない。件数・キー長・合計長が
    /// 上限（[`ANNOTATIONS_MAX_ENTRIES`] 等）を超えると `InvalidArgument`（エラー文言に入力値を含めない）。
    pub fn new(entries: impl IntoIterator<Item = (String, String)>) -> Result<Self, TraitError> {
        let invalid = |m: &'static str| TraitError::new(ErrorCode::InvalidArgument, m);
        let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        // 現在の map の key+value 合計。挿入ごとに増減を反映し、巨大入力でも確保前に打ち切る。
        let mut total: usize = 0;
        for (key, value) in entries {
            if key.is_empty() || key.contains(['=', '\0']) || key.chars().any(char::is_control) {
                return Err(invalid("annotation key is invalid"));
            }
            if key.len() > ANNOTATION_MAX_KEY_BYTES {
                return Err(invalid("annotation key is too long"));
            }
            if value.contains('\0') {
                return Err(invalid("annotation value must not contain NUL"));
            }
            let old = map.get(&key).map_or(0, |v| key.len() + v.len());
            if old == 0 && map.len() >= ANNOTATIONS_MAX_ENTRIES {
                return Err(invalid("too many annotations"));
            }
            let next_total = total - old + key.len() + value.len();
            if next_total > ANNOTATIONS_MAX_TOTAL_BYTES {
                return Err(invalid("annotations are too large"));
            }
            total = next_total;
            map.insert(key, value);
        }
        Ok(Self(map))
    }

    /// 指定キーの値。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// キー昇順の (key, value) 列。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空かどうか。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// コンテナ状態のレコード（[`StateStore`] が保持・返却する単位）。
///
/// 真偽値やフラットな文字列ではなく、将来の拡張に備えて構造化された型にする
/// （coding-rust.md）。supervisor が使う項目（`supervisor_pid`・`health`・`restart_count`。
/// crate-naming.md 決定 6・TASK-157.2・SUP-1）は [`SupervisionState`] として追加済み。Pod サンドボックス状態
/// （CRI 系）は未追加で、`#[non_exhaustive]` のもとで後続タスクが追加する想定（REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateRecord {
    status: ContainerStatus,
    bundle: PathBuf,
    revision: StateRevision,
    cgroup: Option<CgroupPlacement>,
    /// 監視プロセスの PID。supervisor（TASK-157）が使う（SUP-1）。記録値で、PID 再利用があり得る。
    supervisor_pid: Option<NonZeroU32>,
    /// healthcheck の結果。supervisor（TASK-157）が使う（SUP-1・SUP-4）。`None` は未設定。
    health: Option<HealthStatus>,
    /// 再起動回数。supervisor（TASK-157）が使う（SUP-1）。
    restart_count: u32,
    /// コンテナの label（契約 10。SUP-12・TASK-169.5.1）。
    annotations: Annotations,
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
            cgroup: None,
            supervisor_pid: None,
            health: None,
            restart_count: 0,
            annotations: Annotations::default(),
        })
    }

    /// label を設定する（[`Self::annotations`]）。ストア実装が create・読み込みで使う。
    #[must_use]
    pub fn with_annotations(mut self, annotations: Annotations) -> Self {
        self.annotations = annotations;
        self
    }

    /// コンテナの label を返す（契約 10。SUP-12・TASK-169.5.1）。
    pub fn annotations(&self) -> &Annotations {
        &self.annotations
    }

    /// 監視状態（`supervisor_pid`・`health`・`restart_count`）を設定する（[`Self::supervision`]）。
    /// ストア実装が create・update・読み込みで使う。
    #[must_use]
    pub fn with_supervision(mut self, supervision: SupervisionState) -> Self {
        self.supervisor_pid = supervision.supervisor_pid();
        self.health = supervision.health();
        self.restart_count = supervision.restart_count();
        self
    }

    /// コンテナ用 cgroup の配置を設定する（[`Self::cgroup`]）。ストア実装が create・読み込みで使う。
    #[must_use]
    pub fn with_cgroup(mut self, cgroup: CgroupPlacement) -> Self {
        self.cgroup = Some(cgroup);
        self
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

    /// コンテナ用 cgroup の配置を返す（TASK-30.3・OCI-6）。
    ///
    /// `Some` なら、このコンテナの cgroup は `<scope>/fc-<id>@<instance>` にある（または削除済み）。`None` は
    /// 「このレコードのために cgroup を作っていない」ことを表し、`oci_runtime::delete` は cgroup に
    /// 触れない。cgroup を作る側（本番 launcher。TASK-29 / TASK-157 系で結線予定）は、create 時にスコープを
    /// 記録し（[`CreateStateRequest::with_cgroup_scope`]）、返された配置の名前で cgroup を作る契約である
    /// （`cgroups::DelegatedCgroup::prepare` の doc）。
    pub fn cgroup(&self) -> Option<&CgroupPlacement> {
        self.cgroup.as_ref()
    }

    /// 監視プロセスの PID を返す。supervisor（TASK-157）が使う（SUP-1）。
    ///
    /// 記録値であり PID は再利用され得るため、そのままシグナル送信先・権限判断に使わない
    /// （[`SupervisionState::supervisor_pid`]）。
    pub fn supervisor_pid(&self) -> Option<NonZeroU32> {
        self.supervisor_pid
    }

    /// healthcheck の結果を返す。supervisor（TASK-157）が使う（SUP-1・SUP-4）。`None` は未設定。
    pub fn health(&self) -> Option<HealthStatus> {
        self.health
    }

    /// 再起動回数を返す。supervisor（TASK-157）が使う（SUP-1）。
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// 監視状態の 3 項目をまとめて返す（SUP-1・TASK-157）。
    pub fn supervision(&self) -> SupervisionState {
        SupervisionState::new(self.supervisor_pid, self.health, self.restart_count)
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
    cgroup_scope: Option<CgroupScope>,
    supervision: Option<SupervisionState>,
    annotations: Option<Annotations>,
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
        Ok(Self {
            status,
            bundle,
            cgroup_scope: None,
            supervision: None,
            annotations: None,
        })
    }

    /// 記録する label を指定する（SUP-12・TASK-169.5.1。契約 10）。未指定なら空で作る。
    #[must_use]
    pub fn with_annotations(mut self, annotations: Annotations) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// 指定された label を返す（未指定なら `None`）。
    pub fn annotations(&self) -> Option<&Annotations> {
        self.annotations.as_ref()
    }

    /// 記録する監視状態を指定する（supervisor〔TASK-157〕が使う。SUP-1。契約 9）。未指定なら既定値で作る。
    #[must_use]
    pub fn with_supervision(mut self, supervision: SupervisionState) -> Self {
        self.supervision = Some(supervision);
        self
    }

    /// 指定された監視状態を返す（未指定なら `None`）。
    pub fn supervision(&self) -> Option<SupervisionState> {
        self.supervision
    }

    /// コンテナ用 cgroup を作る委譲スコープを記録する（[`StateRecord::cgroup`]）。
    ///
    /// ストアは create で割り当てた revision を instance として組にして記録する（契約 8）。cgroup を作る
    /// 呼び出し元は、作る前（`cgroups::DelegatedCgroup::prepare` の前）にこれで記録する。
    #[must_use]
    pub fn with_cgroup_scope(mut self, scope: CgroupScope) -> Self {
        self.cgroup_scope = Some(scope);
        self
    }

    /// 記録する委譲スコープを返す（未設定なら `None`）。
    pub fn cgroup_scope(&self) -> Option<&CgroupScope> {
        self.cgroup_scope.as_ref()
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
    supervision: Option<SupervisionState>,
}

impl UpdateStateRequest {
    /// 更新後のコンテナ状態と、更新前提となる revision から要求を作る。
    pub fn new(status: ContainerStatus, expected_revision: StateRevision) -> Self {
        Self {
            status,
            expected_revision,
            supervision: None,
        }
    }

    /// 更新後の監視状態を指定する（supervisor〔TASK-157〕が使う。SUP-1。契約 9）。
    /// 未指定の update は既存の値を引き継ぐ。
    #[must_use]
    pub fn with_supervision(mut self, supervision: SupervisionState) -> Self {
        self.supervision = Some(supervision);
        self
    }

    /// 指定された監視状態を返す（未指定なら `None`。その場合は既存の値を引き継ぐ）。
    pub fn supervision(&self) -> Option<SupervisionState> {
        self.supervision
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
            let mut record =
                StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
            // 契約 8: instance はこの create で割り当てた revision。
            if let Some(scope) = req.cgroup_scope() {
                record = record.with_cgroup(CgroupPlacement::new(scope.clone(), revision));
            }
            // 契約 9: 監視状態は指定があればその値、なければ既定値。
            if let Some(sup) = req.supervision() {
                record = record.with_supervision(sup);
            }
            // 契約 10: label は指定があればその値、なければ空。
            if let Some(a) = req.annotations() {
                record = record.with_annotations(a.clone());
            }
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
            let mut updated = StateRecord::new(req.status().clone(), bundle, next_revision)?;
            // 契約 8: cgroup の配置は update で変えずに引き継ぐ。
            if let Some(cgroup) = current.cgroup() {
                updated = updated.with_cgroup(cgroup.clone());
            }
            // 契約 9: 監視状態は指定があれば置き換え、なければ引き継ぐ。
            updated = updated.with_supervision(req.supervision().unwrap_or(current.supervision()));
            // 契約 10: label は update で変えずに引き継ぐ。
            updated = updated.with_annotations(current.annotations().clone());
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

    /// SUP-1・TASK-157.2: health の文字列表現と逆変換。未知・空・大文字は `None`。
    #[test]
    fn sup1_task157_2_health_status_as_str_and_parse() {
        let all = [
            (HealthStatus::Starting, "starting"),
            (HealthStatus::Healthy, "healthy"),
            (HealthStatus::Unhealthy, "unhealthy"),
        ];
        for (h, s) in all {
            assert_eq!(h.as_str(), s);
            assert_eq!(HealthStatus::parse(s), Some(h));
        }
        for bad in ["", "Healthy", "ok", "healthy "] {
            assert_eq!(HealthStatus::parse(bad), None, "{bad:?}");
        }
    }

    /// SUP-1・TASK-157.2: `StateRecord::new` 直後は既定値、`with_supervision` で指定値になる。
    #[test]
    fn sup1_task157_2_state_record_defaults_and_with_supervision() {
        let status = ContainerStatus::created(ContainerId::new("a").unwrap(), None);
        let bundle = std::env::temp_dir().join("b");
        let rec = StateRecord::new(status, bundle, StateRevision::INITIAL).unwrap();
        assert_eq!(rec.supervisor_pid(), None);
        assert_eq!(rec.health(), None);
        assert_eq!(rec.restart_count(), 0);
        assert_eq!(rec.supervision(), SupervisionState::default());
        let state = SupervisionState::new(NonZeroU32::new(4242), Some(HealthStatus::Healthy), 3);
        let rec = rec.with_supervision(state);
        assert_eq!(rec.supervisor_pid(), NonZeroU32::new(4242));
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.restart_count(), 3);
        assert_eq!(rec.supervision(), state);
    }

    /// SUP-1・TASK-157.2: create の指定・既定、update の置き換え・引き継ぎがストア越しに往復する（契約 9）。
    #[test]
    fn sup1_task157_2_supervision_round_trips_through_store() {
        let store = StubStateStore::new();
        let bundle = std::env::temp_dir().join("b");
        let id = |s: &str| ContainerId::new(s).unwrap();
        let plain =
            CreateStateRequest::new(ContainerStatus::created(id("p"), None), bundle.clone())
                .unwrap();
        assert_eq!(
            store.create(&plain).unwrap().supervision(),
            SupervisionState::default()
        );
        let first = SupervisionState::new(NonZeroU32::new(4242), Some(HealthStatus::Starting), 0);
        let req = CreateStateRequest::new(ContainerStatus::created(id("w"), None), bundle)
            .unwrap()
            .with_supervision(first);
        let created = store.create(&req).unwrap();
        assert_eq!(created.supervision(), first);
        let got = store.get(&GetStateRequest::new(id("w"))).unwrap();
        assert_eq!(got.supervision(), first);

        let second = SupervisionState::new(NonZeroU32::new(4243), Some(HealthStatus::Unhealthy), 7);
        let status = ContainerStatus::running(id("w"), None);
        let replaced = store
            .update(&UpdateStateRequest::new(status, got.revision()).with_supervision(second))
            .unwrap();
        assert_eq!(replaced.supervision(), second);
        let status = ContainerStatus::stopped(id("w"), Some(0));
        let kept = store
            .update(&UpdateStateRequest::new(status, replaced.revision()))
            .unwrap();
        assert_eq!(kept.supervision(), second);
        let listed = store
            .list(&ListStateRequest::new(NonZeroU32::new(10).unwrap()).unwrap())
            .unwrap();
        let w = listed
            .records()
            .iter()
            .find(|r| r.id() == &id("w"))
            .unwrap();
        assert_eq!(w.supervision(), second);
    }

    /// テスト用: `&str` ペア列を `(String, String)` 列へ変換する。
    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(k, x)| (k.to_string(), x.to_string()))
            .collect()
    }

    /// SUP-12・TASK-169.5.1: Annotations は妥当な入力を保持し、同一キーは後勝ち・キー昇順で返す。
    #[test]
    fn sup12_task169_5_1_annotations_accepts_valid_and_last_wins() {
        let a = Annotations::new(pairs(&[
            ("b", "2"),
            ("a", "1"),
            ("b", "3"),
            ("e", ""),
            ("日本", "語"),
        ]))
        .unwrap();
        assert_eq!(a.len(), 4);
        assert_eq!(
            a.iter().collect::<Vec<_>>(),
            [("a", "1"), ("b", "3"), ("e", ""), ("日本", "語")]
        );
        assert_eq!(a.get("b"), Some("3"));
        assert_eq!(a.get("zz"), None);
        assert!(Annotations::default().is_empty());
    }

    /// SUP-12・TASK-169.5.1: 空キー・`=`・NUL・制御文字・長さ・件数・合計の超過は InvalidArgument。
    #[test]
    fn sup12_task169_5_1_annotations_rejects_invalid() {
        for bad in [
            pairs(&[("", "v")]),
            pairs(&[("a=b", "v")]),
            pairs(&[("a\0", "v")]),
            pairs(&[("a\n", "v")]),
            pairs(&[("a", "v\0")]),
        ] {
            let e = Annotations::new(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
        let long_key = "k".repeat(ANNOTATION_MAX_KEY_BYTES + 1);
        assert!(Annotations::new(vec![(long_key, String::new())]).is_err());
        let ok_key = "k".repeat(ANNOTATION_MAX_KEY_BYTES);
        assert!(Annotations::new(vec![(ok_key, String::new())]).is_ok());
        let many = (0..=ANNOTATIONS_MAX_ENTRIES).map(|i| (format!("k{i}"), String::new()));
        assert!(Annotations::new(many).is_err());
        let exact = (0..ANNOTATIONS_MAX_ENTRIES).map(|i| (format!("k{i}"), String::new()));
        assert_eq!(
            Annotations::new(exact).unwrap().len(),
            ANNOTATIONS_MAX_ENTRIES
        );
        let big = vec![("a".to_string(), "v".repeat(ANNOTATIONS_MAX_TOTAL_BYTES))];
        assert!(Annotations::new(big).is_err());
        let fit = vec![("a".to_string(), "v".repeat(ANNOTATIONS_MAX_TOTAL_BYTES - 1))];
        assert!(Annotations::new(fit).is_ok());
        // 同一キーの上書きは合計を二重計上しない。
        let overwrite = vec![
            ("a".to_string(), "v".repeat(ANNOTATIONS_MAX_TOTAL_BYTES - 1)),
            ("a".to_string(), "v".repeat(ANNOTATIONS_MAX_TOTAL_BYTES - 1)),
        ];
        assert!(Annotations::new(overwrite).is_ok());
    }

    /// SUP-12・TASK-169.5.1: スタブストアでも契約 10（create で記録・update で引き継ぎ）が成り立つ。
    #[test]
    fn sup12_task169_5_1_annotations_round_trip_through_trait_store() {
        let store = StubStateStore::new();
        let labels = Annotations::new(pairs(&[("app", "web")])).unwrap();
        let id = ContainerId::new("web".to_string()).unwrap();
        let req = CreateStateRequest::new(
            ContainerStatus::created(id.clone(), None),
            std::env::temp_dir(),
        )
        .unwrap()
        .with_annotations(labels.clone());
        let rec = store.create(&req).unwrap();
        assert_eq!(rec.annotations(), &labels);
        let status = ContainerStatus::stopped(id, Some(0));
        let updated = store
            .update(&UpdateStateRequest::new(status, rec.revision()))
            .unwrap();
        assert_eq!(updated.annotations(), &labels);
    }

    /// TASK-30.3・OCI-6: `CgroupScope` はルート `/` と `/a/b` 形式だけを受理し、相対・空要素・`.`・`..`・
    /// NUL・要素長 / 深さ / 全体長の超過を `INVALID_ARGUMENT` で拒否する。
    #[test]
    fn oci6_task30_3_cgroup_scope_validation() {
        for ok in ["/", "/user.slice", "/user.slice/user-1000.slice/x.scope"] {
            assert_eq!(CgroupScope::new(ok).expect(ok).as_str(), ok);
        }
        let long_comp = format!("/{}", "a".repeat(256));
        let deep = "/a".repeat(65);
        let too_long = format!("/{}", vec!["b".repeat(200); 21].join("/"));
        let rejected = [
            "",
            "relative",
            "a/b",
            "//",
            "/a/",
            "/a//b",
            "/./a",
            "/a/..",
            "/a/../b",
            "/a\0b",
            long_comp.as_str(),
            deep.as_str(),
            too_long.as_str(),
        ];
        for bad in rejected {
            let err = CgroupScope::new(bad).expect_err(bad);
            assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
            assert_eq!(err.message(), "invalid cgroup scope path");
        }
        // 境界値: 要素長 255・深さ 64 は受理する。
        let max_comp = format!("/{}", "a".repeat(255));
        assert!(CgroupScope::new(&max_comp).is_ok());
        let max_depth = "/a".repeat(64);
        assert!(CgroupScope::new(&max_depth).is_ok());
    }

    /// TASK-30.3・OCI-6（契約 8）: create でスコープを指定すると、instance = create で割り当てた revision の
    /// 配置として記録され、get で返り、update でも変わらない。削除・再作成すると instance は変わる。
    /// 未指定のレコードは `None`。
    #[test]
    fn oci6_task30_3_cgroup_placement_round_trips_through_store() {
        let store = StubStateStore::new();
        let scope = CgroupScope::new("/user.slice/x.scope").expect("scope");
        let id = sample_id("scoped");
        let scoped_req = || {
            CreateStateRequest::new(ContainerStatus::created(id.clone(), None), sample_bundle())
                .expect("req")
                .with_cgroup_scope(scope.clone())
        };
        let created = store.create(&scoped_req()).expect("create");
        let placement = created.cgroup().expect("placement").clone();
        assert_eq!(placement.scope(), &scope);
        assert_eq!(placement.instance(), created.revision());
        assert_eq!(placement.instance(), StateRevision::INITIAL);
        let updated = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::stopped(id.clone(), Some(0)),
                created.revision(),
            ))
            .expect("update");
        assert_ne!(updated.revision(), created.revision());
        assert_eq!(updated.cgroup(), Some(&placement));
        let got = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(
            got.cgroup()
                .map(|c| (c.scope().as_str(), c.instance().value())),
            Some(("/user.slice/x.scope", 0))
        );

        store
            .delete(&DeleteStateRequest::new(id.clone(), updated.revision()))
            .expect("delete");
        let recreated = store.create(&scoped_req()).expect("recreate");
        let instance = recreated.cgroup().expect("placement").instance();
        assert_eq!(instance, recreated.revision());
        assert_ne!(instance, placement.instance());

        let plain = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(sample_id("plain"), None),
                    sample_bundle(),
                )
                .expect("req"),
            )
            .expect("create");
        assert_eq!(plain.cgroup(), None);
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
