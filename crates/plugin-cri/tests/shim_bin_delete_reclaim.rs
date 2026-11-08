//! shim v2 起動バイナリの delete action の配線の結合試験（CRI-5・CRI-7・TASK-62.6・REPAIR-3・REPAIR-12・#4152）。
//!
//! 実バイナリ（`containerd-shim-fandhe-container-v2`）を containerd の呼び方（`-namespace`・`-address`・`-id`・`-bundle`・`delete`）で
//! 起動し、CLI → `production_delete` → 状態ルートの回収 → stdout の `DeleteResponse`（protobuf）の通しを具体値で照合する。
//! 状態ルートは `XDG_RUNTIME_DIR` 配下の既定の場所（非 root）に、本番と同じ `<base>-shim-state/<address のハッシュ>/<namespace>` の
//! 配置で記録を事前に作る。root・cgroup・実プロセスは要らず、既定のテスト集合で動く（Running の実プロセスの停止は
//! `reclaim_tests` の偽の実行層と実機前提の試験の範囲）。
#![cfg(target_os = "linux")]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, ExitTime, GetStateRequest, ListStateRequest,
    StateStore,
};

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const ADDRESS: &str = "/run/containerd/containerd.sock";
/// 回収済み・記録なしの冪等な応答の終了コード（`DELETE_EXIT_STATUS`）。
const IDEMPOTENT_EXIT: u64 = 137;

#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

/// 試験用の XDG_RUNTIME_DIR（短い /tmp 直下・0700。Drop で消す）。
struct Scratch {
    guard: test_root::TestRoot,
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let guard =
            test_root::test_root_at(PathBuf::from(format!("/tmp/fcd{}-{n}", std::process::id())));
        let root = guard.to_path_buf();
        Self { guard, root }
    }

    /// containerd の bundle の形（`<root>/b/default/<id>`）の実ディレクトリ。
    fn bundle(&self, id: &str) -> PathBuf {
        let b = self.root.join("b").join("default").join(id);
        std::fs::create_dir_all(&b).unwrap();
        b
    }

    /// 本番（`scoped_root_path`）と同じ式の状態ルート `<xdg>/fandhe-container-shim-state/<fnv1a(address)>/default`。
    fn scoped_root(&self) -> PathBuf {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in ADDRESS.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.guard
            .join("fandhe-container-shim-state")
            .join(format!("{h:016x}"))
            .join("default")
    }

    /// 記録用のストアを開く（階層は 0700 で 1 つずつ作る）。
    fn store(&self) -> FileStateStore {
        let path = self.scoped_root();
        let mut cur = self.root.clone();
        for part in path.strip_prefix(&self.root).unwrap().components() {
            cur.push(part);
            let _ = std::fs::DirBuilder::new().mode(0o700).create(&cur);
        }
        FileStateStore::open(StateRoot::from_override(path).unwrap()).unwrap()
    }

    fn seed(&self, store: &FileStateStore, status: ContainerStatus) {
        let bundle = self.bundle(status.id().as_str());
        store
            .create(&CreateStateRequest::new(status, bundle).unwrap())
            .unwrap();
    }

    /// delete を実バイナリで実行する（期限つき）。
    fn delete(&self, id: &str) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(["-namespace", "default", "-address", ADDRESS])
            .args(["-publish-binary", BIN, "-id", id, "-bundle"])
            .arg(self.bundle(id))
            .arg("delete")
            .env("XDG_RUNTIME_DIR", &self.root)
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", self.root.join("s"))
            .current_dir(&self.root)
            .stdin(Stdio::null());
        reap::output_within(&mut cmd, Duration::from_secs(30))
            .expect("shim delete must exit within the limit")
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

fn recorded(store: &FileStateStore, id: &str) -> bool {
    store.get(&GetStateRequest::new(cid(id))).is_ok()
}

/// 状態ルートの記録の id の一覧。
fn ids(store: &FileStateStore) -> Vec<String> {
    let mut v: Vec<String> = store
        .list(&ListStateRequest::new(std::num::NonZeroU32::new(100).unwrap()).unwrap())
        .unwrap()
        .records()
        .iter()
        .map(|r| r.status().id().as_str().to_owned())
        .collect();
    v.sort();
    v
}

/// protobuf の varint を 1 つ読む。
fn varint(b: &[u8], i: &mut usize) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    loop {
        let byte = b[*i];
        *i += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return v;
        }
        shift += 7;
    }
}

/// `DeleteResponse { pid = 1; exit_status = 2; exited_at = 3(Timestamp { seconds = 1; nanos = 2 }) }` の復号結果。
#[derive(Debug, PartialEq)]
struct Decoded {
    pid: u64,
    exit_status: u64,
    exited_at: Option<(u64, u64)>,
}

fn decode(buf: &[u8]) -> Decoded {
    let mut d = Decoded {
        pid: 0,
        exit_status: 0,
        exited_at: None,
    };
    let mut i = 0;
    while i < buf.len() {
        let tag = varint(buf, &mut i);
        match tag {
            0x08 => d.pid = varint(buf, &mut i),
            0x10 => d.exit_status = varint(buf, &mut i),
            0x1a => {
                let len = varint(buf, &mut i) as usize;
                let inner = &buf[i..i + len];
                i += len;
                let (mut j, mut secs, mut nanos) = (0, 0, 0);
                while j < inner.len() {
                    match varint(inner, &mut j) {
                        0x08 => secs = varint(inner, &mut j),
                        0x10 => nanos = varint(inner, &mut j),
                        t => panic!("unexpected timestamp tag {t:#x}"),
                    }
                }
                d.exited_at = Some((secs, nanos));
            }
            t => panic!("unexpected tag {t:#x}"),
        }
    }
    d
}

fn assert_success(out: &Output) {
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stderr, b"", "delete must not write to stderr");
}

/// CRI-5・TASK-62.6・#4152: Stopped で記録された終了コード・`exited_at` が stdout の DeleteResponse と一致し、
/// 記録が消え、他のコンテナの記録には触れない。再実行は固定の冪等な応答（137）で、記録は増減しない。
#[test]
fn cri5_4152_bin_delete_reclaims_stopped_record_with_recorded_exit_state() {
    let sc = Scratch::new();
    let store = sc.store();
    let at = ExitTime::from_unix_nanos(1_700_000_000_123_456_789).unwrap();
    sc.seed(
        &store,
        ContainerStatus::stopped_at(cid("stopped1"), Some(7), Some(at)),
    );
    sc.seed(&store, ContainerStatus::created(cid("other"), None));

    let out = sc.delete("stopped1");
    assert_success(&out);
    assert_eq!(
        decode(&out.stdout),
        Decoded {
            pid: 0,
            exit_status: 7,
            exited_at: Some((1_700_000_000, 123_456_789)),
        }
    );
    assert!(!recorded(&store, "stopped1"));
    assert_eq!(ids(&store), vec!["other".to_owned()]);

    // 再実行（回収済み）は固定の応答。終了状態は記録に依らず 137・exited_at あり。他の記録は残る。
    let again = sc.delete("stopped1");
    assert_success(&again);
    let d = decode(&again.stdout);
    assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    assert!(d.exited_at.is_some());
    assert_eq!(ids(&store), vec!["other".to_owned()]);
}

/// CRI-5・TASK-62.6・#4152: PID の無い Created は停止せず回収され、終了コード 0。2 回目は冪等な 137。
#[test]
fn cri5_4152_bin_delete_reclaims_pidless_created_then_is_idempotent() {
    let sc = Scratch::new();
    let store = sc.store();
    sc.seed(&store, ContainerStatus::created(cid("created1"), None));

    let out = sc.delete("created1");
    assert_success(&out);
    let d = decode(&out.stdout);
    assert_eq!((d.pid, d.exit_status), (0, 0));
    assert!(!recorded(&store, "created1"));
    assert_eq!(ids(&store), Vec::<String>::new());

    for _ in 0..2 {
        let again = sc.delete("created1");
        assert_success(&again);
        let d = decode(&again.stdout);
        assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    }
}

/// CRI-5・#4152: 状態ルートが無い（記録が一度も作られていない）delete も成功し、固定の 137 を返して状態ルートを作らない。
#[test]
fn cri5_4152_bin_delete_without_state_root_is_idempotent_and_creates_nothing() {
    let sc = Scratch::new();
    let out = sc.delete("nothing");
    assert_success(&out);
    let d = decode(&out.stdout);
    assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    assert!(!Path::new(&sc.scoped_root()).exists());
}
