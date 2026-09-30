//! ファイルベース `StateStore` の結合試験（TASK-31.3・OCI-5・CRI-7）。
//!
//! 公開 API（`FileStateStore`・`StateRoot`・`StateStore`）だけを crate の外から呼び、
//! 別プロセスとの状態共有・ファイルロックによる排他・再起動（再 open）後の永続性・破損回復を
//! 具体値で確かめる。別プロセスはこのテストバイナリ自身を `--exact` で再実行して用意する
//! （追加依存なし）。子プロセスの待機には上限時間を設ける（REPAIR-5）。root 不要で 3 OS の
//! 既定のテスト集合で動く。

use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, ErrorCode,
    GetStateRequest, ListStateRequest, StateStore, UpdateStateRequest,
};

const ROOT_ENV: &str = "FANDHE_STATE_IT_ROOT";
const PREFIX_ENV: &str = "FANDHE_STATE_IT_PREFIX";
const CHILD_TEST: &str = "child_worker_creates_records";
const CHILDREN: u32 = 3;
const PER_CHILD: u32 = 8;
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// テスト用一時ディレクトリ（drop で削除）。
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("fandhe-state-it-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(root: &Path) -> FileStateStore {
    FileStateStore::open(StateRoot::from_override(root.to_path_buf()).unwrap()).unwrap()
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

fn bundle() -> PathBuf {
    std::env::temp_dir().join("fandhe-it-bundle")
}

fn create_req(id: &str) -> CreateStateRequest {
    CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle()).unwrap()
}

fn list_req(n: u32) -> ListStateRequest {
    ListStateRequest::new(NonZeroU32::new(n).unwrap()).unwrap()
}

/// 子プロセス側の本体。親が `ROOT_ENV` を渡したときだけ動き、単独実行では何もしない。
#[test]
fn child_worker_creates_records() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let prefix = std::env::var(PREFIX_ENV).unwrap();
    let store = open(Path::new(&root));
    for i in 0..PER_CHILD {
        let id = format!("{prefix}-{i}");
        let rec = store.create(&create_req(&id)).unwrap();
        // 状態遷移も行い、ロック下の read-modify-write を別プロセス間で競合させる。
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::creating(cid(&id)),
                rec.revision(),
            ))
            .unwrap();
    }
}

fn spawn_child(root: &Path, prefix: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, root)
        .env(PREFIX_ENV, prefix)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// 子プロセスを上限時間つきで待つ。超過したら kill して失敗させる（ハング検出。REPAIR-5）。
fn wait_with_deadline(mut child: Child) {
    let deadline = Instant::now() + CHILD_DEADLINE;
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "child exited with {status}");
                return;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not finish within the deadline");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// OCI-5: 複数の別プロセスが同じ状態ルートへ同時に書いても、ロックで直列化されて
/// 全レコードが残り、revision はストア全体で重複しない。
#[test]
fn oci5_processes_share_state_with_exclusive_locking() {
    let t = TmpDir::new("share");
    // 親が先に open して `@revision` を初期化しておく。
    let parent = open(t.path());
    let children: Vec<Child> = (0..CHILDREN)
        .map(|n| spawn_child(t.path(), &format!("c{n}")))
        .collect();
    // 親も同時に書く。
    for i in 0..PER_CHILD {
        parent.create(&create_req(&format!("p-{i}"))).unwrap();
    }
    for child in children {
        wait_with_deadline(child);
    }
    let page = parent.list(&list_req(1000)).unwrap();
    let total = (CHILDREN + 1) * PER_CHILD;
    assert_eq!(page.records().len() as u32, total);
    assert!(page.next_cursor().is_none());
    let mut revisions: Vec<u64> = page
        .records()
        .iter()
        .map(|r| r.revision().value())
        .collect();
    revisions.sort_unstable();
    revisions.dedup();
    assert_eq!(revisions.len() as u32, total, "revisions must be unique");
    // 子が更新した結果（creating）が親から見える。
    let rec = parent.get(&GetStateRequest::new(cid("c0-0"))).unwrap();
    assert_eq!(rec.status().state().as_str(), "creating");
}

/// OCI-5: ストアを閉じて開き直して（再起動相当）も状態が残り、削除済みの revision を再発行しない。
#[test]
fn oci5_state_survives_reopen_and_revision_is_not_reused() {
    let t = TmpDir::new("reopen");
    let first = {
        let store = open(t.path());
        let a = store.create(&create_req("a")).unwrap();
        store.create(&create_req("b")).unwrap();
        a
    };
    let store = open(t.path());
    let got = store.get(&GetStateRequest::new(cid("a"))).unwrap();
    assert_eq!(got, first);
    let b_rev = store
        .get(&GetStateRequest::new(cid("b")))
        .unwrap()
        .revision();
    store
        .delete(&DeleteStateRequest::new(cid("b"), b_rev))
        .unwrap();
    drop(store);
    let store = open(t.path());
    let c = store.create(&create_req("c")).unwrap();
    // a=0, b=1 を払い出し済み。b 削除・再 open 後も c は 2 になる。
    assert_eq!(c.revision().value(), 2);
    let ids: Vec<String> = store
        .list(&list_req(10))
        .unwrap()
        .records()
        .iter()
        .map(|r| r.id().as_str().to_owned())
        .collect();
    assert_eq!(ids, vec!["a".to_owned(), "c".to_owned()]);
}

/// OCI-5・CRI-7: 同じルートを開いた別インスタンス間で状態が見え、楽観的排他が効く
/// （古い revision での update は FAILED_PRECONDITION）。
#[test]
fn oci5_optimistic_concurrency_across_instances() {
    let t = TmpDir::new("occ");
    let a = open(t.path());
    let b = open(t.path());
    let rec = a.create(&create_req("web")).unwrap();
    let seen = b.get(&GetStateRequest::new(cid("web"))).unwrap();
    assert_eq!(seen, rec);
    let next = a
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(cid("web"), None),
            rec.revision(),
        ))
        .unwrap();
    let stale = b.update(&UpdateStateRequest::new(
        ContainerStatus::creating(cid("web")),
        rec.revision(),
    ));
    assert_eq!(stale.unwrap_err().code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        b.get(&GetStateRequest::new(cid("web"))).unwrap().revision(),
        next.revision()
    );
}

/// OCI-5: 破損レコードは find / purge で回復でき、健全なレコードと revision 採番に影響しない。
#[test]
fn oci5_corrupted_record_recovery_across_reopen() {
    let t = TmpDir::new("recover");
    {
        let store = open(t.path());
        store.create(&create_req("a")).unwrap();
        store.create(&create_req("b")).unwrap();
    }
    fs::write(t.path().join("a").join("state.json"), b"{broken").unwrap();
    let store = open(t.path());
    assert_eq!(
        store.list(&list_req(10)).unwrap_err().code(),
        ErrorCode::Internal
    );
    assert_eq!(store.find_corrupted().unwrap(), vec![cid("a")]);
    store.purge_corrupted(&cid("a")).unwrap();
    let page = store.list(&list_req(10)).unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(
        store.create(&create_req("c")).unwrap().revision().value(),
        2
    );
}

/// OCI-5: 権限不備のレコードは破損扱いせず、回復操作でも消さない（fail-closed）。
#[cfg(unix)]
#[test]
fn oci5_permission_error_record_is_never_purged() {
    use std::os::unix::fs::PermissionsExt;
    let t = TmpDir::new("permission");
    let store = open(t.path());
    store.create(&create_req("a")).unwrap();
    let dir = t.path().join("a");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        store.list(&list_req(10)).unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        store.find_corrupted().unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        store.purge_corrupted(&cid("a")).unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert!(dir.join("state.json").is_file());
}
