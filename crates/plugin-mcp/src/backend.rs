//! `tools/call` の 2 ツール（`list_containers`・`start_container`）が呼ぶバックエンド（MCP-2。TASK-118.3・#466・MS-4）。
//!
//! [`crate::server::handle_message_with`] が `tools/call` を検証した後、ツールの意味の単位でこの
//! [`ToolBackend`] へ委ねる。プロトコル処理（JSON-RPC・引数検証・応答形状）と実行層の呼び出しを分け、
//! プロトコル側はフェイクで具体値検証でき、実行層側は差し替えられる。将来 UDS 経由で core 側へ委ねる
//! バックエンド（TASK-118.4・#467）や supervisor 起動の adapter（#1718）を差し込む枠でもある。
//! エラーは core の [`TraitError`] / [`ErrorCode`]（ERR-1）で返し、ERR-5 の表への写像は呼び出し側が持つ。
//!
//! # 本番実装 [`CoreBackend`]
//!
//! - `list_containers`: CLI の `list` と同じく core の `FileStateStore`（OCI-5・TASK-31）を呼び出しごとに開き、
//!   `StateStore::list` をページングして ID・状態・PID だけを返す。bundle・annotations は任意の UTF-8 を含み得る
//!   ため返さない（SEC-1）。件数・ページ数に上限を設ける（[`MAX_LIST_RECORDS`]・[`MAX_LIST_PAGES`]。REPAIR-5）。
//! - `start_container`: 未実装（REPAIR-3）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - `start_container` の本番起動: リポジトリに supervisor 経由の起動経路がまだ無い（CLI の `start` も
//!   `UNIMPLEMENTED` を返す）。将来は #1717 の起動契約に沿った supervisor 起動の adapter（#1718・
//!   TASK-157・CORE-1）へ差し替え、実際にコンテナを起動する（MCP-2）。それまでは状態ストアに触れずに
//!   `UNIMPLEMENTED` を返す（fail-closed。起動権の予約と取り消しで state.json の revision を進めない）。
//! - 状態ルートは既定の解決（root: `/run/fandhe-container`、rootless: `$XDG_RUNTIME_DIR/fandhe-container`）
//!   のみで、外部入力では指定させない。非 Linux では core が `Unimplemented` を返す（fail-closed）。

use std::num::NonZeroU32;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ErrorCode, ListStateRequest, StateStore, TraitError,
};
use serde::Serialize;

/// 1 回の応答に載せるコンテナ数の上限。超えたら `truncated: true` で打ち切る（1 応答行の大きさを抑える。REPAIR-5）。
pub const MAX_LIST_RECORDS: usize = 1_000;

/// 状態ストアへ 1 回に要求するページの大きさ（core の `MAX_PAGE_SIZE` 以下）。
pub const LIST_PAGE_SIZE: u32 = 100;

/// 走査するページ数の上限。不正なストアが `next_cursor` を返し続けても無期限に回らない（REPAIR-5）。
pub const MAX_LIST_PAGES: u32 = 100;

/// 一覧の 1 件。公開してよい項目（ID・状態・PID）だけを持つ。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerSummary {
    /// コンテナ ID（core が検証済みの文字種）。
    pub id: String,
    /// 状態の固定語（`creating` / `created` / `running` / `stopped`）。
    pub status: String,
    /// init の PID。無ければ `null`。
    pub pid: Option<u32>,
}

/// `list_containers` の結果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerList {
    /// コンテナ一覧（状態ストアの返す順）。
    pub containers: Vec<ContainerSummary>,
    /// 件数上限で打ち切ったとき `true`。
    pub truncated: bool,
}

/// `start_container` の結果（起動後の状態）。
pub type StartedSummary = ContainerSummary;

/// `tools/call` の実行層。実装は `Send + Sync` で、呼び出しごとに状態を読む（常駐状態を持たない。CORE-1）。
pub trait ToolBackend: Send + Sync {
    /// コンテナ一覧を返す。
    fn list_containers(&self) -> Result<ContainerList, TraitError>;
    /// `id` のコンテナを起動し、起動後の状態を返す。
    fn start_container(&self, id: &ContainerId) -> Result<StartedSummary, TraitError>;
}

/// 全操作が `UNIMPLEMENTED` を返すバックエンド。プロトコル処理だけを使う呼び出し（[`crate::server::handle_message`]）用。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBackend;

impl ToolBackend for UnavailableBackend {
    fn list_containers(&self) -> Result<ContainerList, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "backend is not configured",
        ))
    }

    fn start_container(&self, _id: &ContainerId) -> Result<StartedSummary, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "backend is not configured",
        ))
    }
}

/// core の状態ストアを直接読む本番バックエンド（上記モジュール doc を参照）。
#[derive(Debug, Clone)]
pub struct CoreBackend {
    /// `None` なら呼び出しごとに既定の状態ルートを解決する。
    root: Option<StateRoot>,
}

impl CoreBackend {
    /// 既定の状態ルートを使う本番構成。ルートは起動時ではなく呼び出しごとに解決・open する。
    pub fn production() -> Self {
        Self { root: None }
    }

    /// 状態ルートを指定する（結合試験用。外部入力からは指定させない）。
    #[doc(hidden)]
    pub fn with_root(root: StateRoot) -> Self {
        Self { root: Some(root) }
    }
}

impl ToolBackend for CoreBackend {
    fn list_containers(&self) -> Result<ContainerList, TraitError> {
        let root = match &self.root {
            Some(r) => r.clone(),
            None => StateRoot::resolve(None)?,
        };
        let store = FileStateStore::open(root)?;
        collect_list(&store)
    }

    fn start_container(&self, _id: &ContainerId) -> Result<StartedSummary, TraitError> {
        // 状態ストアに触れない（モジュール doc の REPAIR-3 を参照）。
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "container start via supervisor is not available yet",
        ))
    }
}

/// 状態ストアを上限付きで走査して一覧にする。
///
/// 件数が [`MAX_LIST_RECORDS`] に達して続きがあれば `truncated` で打ち切る。ページ数が
/// [`MAX_LIST_PAGES`] を超えて終わらなければ `INTERNAL`（不正なストア実装の検出）。
pub fn collect_list(store: &dyn StateStore) -> Result<ContainerList, TraitError> {
    let page_size = NonZeroU32::new(LIST_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let mut req = ListStateRequest::new(page_size)?;
    let mut containers: Vec<ContainerSummary> = Vec::new();
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        for record in page.records() {
            if containers.len() >= MAX_LIST_RECORDS {
                return Ok(ContainerList {
                    containers,
                    truncated: true,
                });
            }
            containers.push(ContainerSummary {
                id: record.id().as_str().to_owned(),
                status: record.status().state().as_str().to_owned(),
                pid: record.status().pid().map(NonZeroU32::get),
            });
        }
        match page.next_cursor() {
            Some(cursor) => req = req.with_cursor(cursor.clone()),
            None => {
                return Ok(ContainerList {
                    containers,
                    truncated: false,
                });
            }
        }
    }
    Err(TraitError::new(
        ErrorCode::Internal,
        "state listing did not terminate",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{StateList, StateListCursor, StateRecord};

    /// 固定のページ列を返すストア。`list` 以外は使わない。
    struct Pages {
        pages: Vec<StateList>,
        repeat_last: bool,
    }

    impl StateStore for Pages {
        fn create(
            &self,
            _req: &fandhe_container_core::traits::CreateStateRequest,
        ) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn get(
            &self,
            _req: &fandhe_container_core::traits::GetStateRequest,
        ) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn update(
            &self,
            _req: &fandhe_container_core::traits::UpdateStateRequest,
        ) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(
            &self,
            _req: &fandhe_container_core::traits::DeleteStateRequest,
        ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
            let idx = req
                .cursor()
                .and_then(|c| c.as_str().parse::<usize>().ok())
                .unwrap_or(0);
            let idx = if self.repeat_last {
                idx.min(self.pages.len() - 1)
            } else {
                idx
            };
            self.pages
                .get(idx)
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::Internal, "no page"))
        }
    }

    /// 一覧の試験用レコード。bundle は `StateRecord::new` の絶対パス検証を通すためだけの値で、読まない。
    /// `/b` のような Unix 形式は Windows ではドライブ等の接頭辞が無く絶対パスにならないため、
    /// 各 OS の一時ディレクトリの絶対パスを返す `temp_dir()` を使う（cli・supervisor の試験と同じ書き方）。
    fn record(n: usize) -> StateRecord {
        use fandhe_container_core::traits::ContainerStatus;
        let id = ContainerId::new(format!("c{n}")).unwrap();
        StateRecord::new(
            ContainerStatus::created(id, None),
            std::env::temp_dir().join("b"),
            fandhe_container_core::traits::StateRevision::from_raw(1),
        )
        .unwrap()
    }

    #[test]
    fn mcp2_collect_list_truncates_at_record_limit() {
        // 1 ページに MAX_LIST_RECORDS + 1 件を返す不正なストア。
        let records: Vec<StateRecord> = (0..=MAX_LIST_RECORDS).map(record).collect();
        let store = Pages {
            pages: vec![StateList::new(records, None)],
            repeat_last: false,
        };
        let list = collect_list(&store).unwrap();
        assert!(list.truncated);
        assert_eq!(list.containers.len(), MAX_LIST_RECORDS);
    }

    #[test]
    fn mcp2_collect_list_exact_limit_is_not_truncated() {
        let records: Vec<StateRecord> = (0..MAX_LIST_RECORDS).map(record).collect();
        let store = Pages {
            pages: vec![StateList::new(records, None)],
            repeat_last: false,
        };
        let list = collect_list(&store).unwrap();
        assert!(!list.truncated);
        assert_eq!(list.containers.len(), MAX_LIST_RECORDS);
    }

    #[test]
    fn mcp2_collect_list_bounds_pages_when_cursor_never_ends() {
        let cursor = StateListCursor::from_raw("0".to_owned()).unwrap();
        let store = Pages {
            pages: vec![StateList::new(vec![], Some(cursor))],
            repeat_last: true,
        };
        let err = collect_list(&store).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest, GetStateRequest};
    use std::num::NonZeroU32;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// 排他作成の一時ディレクトリ（0700）。drop で削除する。
    struct TempParent(PathBuf);

    impl TempParent {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            for n in 0..64u32 {
                let p = std::env::temp_dir()
                    .join(format!("fc-mcp-{label}-{}-{nanos}-{n}", std::process::id()));
                if std::fs::create_dir(&p).is_ok() {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(p);
                }
            }
            panic!("could not create a temp dir");
        }
    }

    impl Drop for TempParent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    /// MCP-2: 実際の状態ストアの内容が id・status・pid の具体値で返る。
    #[test]
    fn mcp2_core_backend_lists_real_store_records() {
        let parent = TempParent::new("list");
        let root = StateRoot::from_override(parent.0.join("state")).unwrap();
        let store = FileStateStore::open(root.clone()).unwrap();
        let bundle = PathBuf::from("/bundle");
        store
            .create(
                &CreateStateRequest::new(ContainerStatus::created(id("c2"), None), bundle.clone())
                    .unwrap(),
            )
            .unwrap();
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::running(id("c1"), NonZeroU32::new(42)),
                    bundle,
                )
                .unwrap(),
            )
            .unwrap();
        let list = CoreBackend::with_root(root).list_containers().unwrap();
        assert!(!list.truncated);
        assert_eq!(
            list.containers,
            vec![
                ContainerSummary {
                    id: "c1".into(),
                    status: "running".into(),
                    pid: Some(42)
                },
                ContainerSummary {
                    id: "c2".into(),
                    status: "created".into(),
                    pid: None
                },
            ]
        );
    }

    #[test]
    fn mcp2_core_backend_empty_store_lists_nothing() {
        let parent = TempParent::new("empty");
        let root = StateRoot::from_override(parent.0.join("state")).unwrap();
        let list = CoreBackend::with_root(root).list_containers().unwrap();
        assert_eq!(
            list,
            ContainerList {
                containers: vec![],
                truncated: false
            }
        );
    }

    /// REPAIR-3: start は未実装で、状態ストアの revision を進めない。
    #[test]
    fn mcp2_core_backend_start_is_unimplemented_and_leaves_state_untouched() {
        let parent = TempParent::new("start");
        let root = StateRoot::from_override(parent.0.join("state")).unwrap();
        let store = FileStateStore::open(root.clone()).unwrap();
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id("c1"), None),
                    PathBuf::from("/bundle"),
                )
                .unwrap(),
            )
            .unwrap();
        let before = store.get(&GetStateRequest::new(id("c1"))).unwrap();
        let err = CoreBackend::with_root(root)
            .start_container(&id("c1"))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        let after = store.get(&GetStateRequest::new(id("c1"))).unwrap();
        assert_eq!(before.revision(), after.revision());
        assert_eq!(after.status().state().as_str(), "created");
    }
}
