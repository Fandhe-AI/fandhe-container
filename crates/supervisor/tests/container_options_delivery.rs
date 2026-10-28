//! CLI の create が保存した起動オプション文書と世代注釈を、supervisor の start 側が読んで検証済みの
//! 入力へ変換する境界の結合照合（SUP-12・CLI-1・SEC-1・NET-6・NET-12・#2713・#3065・REPAIR-12）。
//!
//! 実コンテナは起動しない。実ストア（`open_default_store`）の状態記録と実ファイルの文書を使い、
//! 保存（`store::write_new`）→ 読み取り（`store::read`）→ 世代照合（`select_document`）→ 変換
//! （`to_container_options`・`launch_env_for`）を通す。世代不一致と文書欠落の拒否を具体値で確認する。
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use fandhe_container_core::traits::{
    Annotations, ContainerId, ContainerStatus, CreateStateRequest, ErrorCode, GetStateRequest,
    StateRecord,
};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store::{
    GENERATION_ANNOTATION, launch_env_for, options_path, read, select_document, write_new,
};
use fandhe_container_supervisor::state::open_default_store;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 0700 の一時ディレクトリ（drop で削除）。
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let p = loop {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("fandhe-sup-delivery-{}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => break p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create temp dir: {e}"),
            }
        };
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
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

fn doc(generation: Option<&str>) -> ContainerOptionsDocument {
    let d = ContainerOptionsDocument::new(
        vec!["nofile=1024:2048".into()],
        vec!["TOKEN=dummy-value".into()],
        None,
        Some("64m".into()),
        vec!["/run:rw,noexec,size=65536k".into()],
    )
    .unwrap();
    match generation {
        Some(g) => d.with_generation(g.into()).unwrap(),
        None => d,
    }
}

/// 状態記録を作って読み戻す（`generation` が `Some` なら世代注釈を付ける）。
fn record(root: &Path, id: &ContainerId, generation: Option<&str>) -> StateRecord {
    let store = open_default_store(Some(root.to_path_buf())).unwrap();
    let mut req = CreateStateRequest::new(
        ContainerStatus::created(id.clone(), None),
        std::env::temp_dir().join("fandhe-sup-delivery-bundle"),
    )
    .unwrap();
    if let Some(g) = generation {
        let ann = Annotations::new([(GENERATION_ANNOTATION.to_owned(), g.to_owned())]).unwrap();
        req = req.with_annotations(ann);
    }
    store.create(&req).unwrap();
    store.get(&GetStateRequest::new(id.clone())).unwrap()
}

/// 世代が一致する文書は採用され、検証済みの `ContainerOptions` と launch の env に変換される。
#[test]
fn sup12_delivery_matching_generation_reaches_launch_inputs() {
    let t = TmpDir::new();
    let id = ContainerId::new("web").unwrap();
    let rec = record(t.path(), &id, Some("g1"));
    write_new(t.path(), &id, &doc(Some("g1"))).unwrap();
    let read_doc = read(t.path(), &id).unwrap();
    let picked = select_document(read_doc, Some("g1"))
        .unwrap()
        .expect("adopted");
    assert_eq!(picked.generation(), Some("g1"));
    assert_eq!(picked.env(), ["TOKEN=dummy-value".to_owned()]);
    assert_eq!(picked.ulimits(), ["nofile=1024:2048".to_owned()]);
    picked.to_container_options().unwrap();
    assert_eq!(
        launch_env_for(t.path(), &rec).unwrap(),
        vec!["TOKEN=dummy-value".to_owned()]
    );
}

/// 記録の世代と文書の世代が違うときは FailedPrecondition で拒否する（旧文書を新記録に当てない）。
#[test]
fn sup12_delivery_generation_mismatch_is_rejected() {
    let t = TmpDir::new();
    let id = ContainerId::new("web").unwrap();
    let rec = record(t.path(), &id, Some("new"));
    write_new(t.path(), &id, &doc(Some("old"))).unwrap();
    let e = launch_env_for(t.path(), &rec).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}

/// 記録が世代を持つのに文書が無いときは FailedPrecondition で拒否する（オプションを黙って落とさない）。
#[test]
fn sup12_delivery_missing_document_is_rejected() {
    let t = TmpDir::new();
    let id = ContainerId::new("web").unwrap();
    let rec = record(t.path(), &id, Some("g1"));
    assert!(!options_path(t.path(), &id).exists());
    let e = launch_env_for(t.path(), &rec).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}

/// 記録が世代を持たない（CLI 以外の経路で作られた）ときは、残った文書を採用せず既定値になる。
#[test]
fn sup12_delivery_record_without_generation_ignores_leftover_document() {
    let t = TmpDir::new();
    let id = ContainerId::new("web").unwrap();
    let rec = record(t.path(), &id, None);
    write_new(t.path(), &id, &doc(Some("stale"))).unwrap();
    assert_eq!(
        launch_env_for(t.path(), &rec).unwrap(),
        Vec::<String>::new()
    );
}
/// network 系を載せた文書(世代つき)。
fn net_doc(
    generation: &str,
    network: &str,
    add_hosts: &[&str],
    dns: &[&str],
) -> ContainerOptionsDocument {
    ContainerOptionsDocument::new(vec![], vec![], None, None, vec![])
        .unwrap()
        .with_network(
            Some(network.to_owned()),
            add_hosts.iter().map(|s| (*s).to_owned()).collect(),
            dns.iter().map(|s| (*s).to_owned()).collect(),
        )
        .unwrap()
        .with_generation(generation.to_owned())
        .unwrap()
}

/// 保存→読み取り→世代照合→`ContainerOptions`→`LaunchOptions` までを通した結果を返す。
fn deliver(
    d: &ContainerOptionsDocument,
) -> Result<
    fandhe_container_core::oci_runtime::LaunchOptions,
    fandhe_container_core::traits::TraitError,
> {
    let t = TmpDir::new();
    let id = ContainerId::new("web").unwrap();
    let _rec = record(t.path(), &id, Some("g1"));
    write_new(t.path(), &id, d).unwrap();
    let picked = select_document(read(t.path(), &id).unwrap(), Some("g1"))
        .unwrap()
        .expect("adopted");
    assert_eq!(picked.network(), d.network());
    picked.to_container_options()?.launch_options()
}

/// NET-6・SUP-12・#3065: `--network=host` / `none` は配送経路を通って core の `LaunchNetworkMode` になる。
#[test]
fn net6_delivery_network_host_and_none_reach_launch_options() {
    use fandhe_container_core::oci_runtime::LaunchNetworkMode;
    let host = deliver(&net_doc("g1", "host", &[], &[])).unwrap();
    assert_eq!(host.network(), LaunchNetworkMode::Host);
    let none = deliver(&net_doc("g1", "none", &[], &[])).unwrap();
    assert_eq!(none.network(), LaunchNetworkMode::Loopback);
}

/// NET-12・REPAIR-3: `--add-host` は反映経路が無いため、配送後の `launch_options` が Unimplemented で拒否する。
#[test]
fn net12_delivery_add_host_is_rejected_as_unimplemented() {
    let e = deliver(&net_doc("g1", "host", &["db:10.0.0.5"], &[])).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}

/// NET-12・REPAIR-3: `--dns` も同様に Unimplemented で拒否する。
#[test]
fn net12_delivery_dns_is_rejected_as_unimplemented() {
    let e = deliver(&net_doc("g1", "mynet", &[], &["8.8.8.8"])).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}

/// NET-6: ユーザー定義名のみ(add-host・dns なし)は結線前のため Unimplemented で拒否する。
#[test]
fn net6_delivery_named_network_is_rejected_as_unimplemented() {
    let e = deliver(&net_doc("g1", "mynet", &[], &[])).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}
