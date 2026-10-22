//! `system df` のコンテナ容量・staging・展開後サイズの合成の結合試験（OCI-7・TASK-183・#2222）。
//!
//! 実コンテナ領域の計測は core の `measure_container_usage` が担い、oci は結果を `ContainersUsage` として
//! 受けて `DiskUsage::with_containers` で合成する。この試験は oci と core の両方に依存する呼び出し側
//! （cri・将来の CLI アダプタ。#2221）の手順を再現し、具体値で照合する。
//!
//! 手順の契約: containers の計測は `ImageStoreGuard` の外で行い、ガードの内側では `disk_usage` と
//! 展開後サイズの計画の取得だけを行う。計画の計測もガードの外で行う。
//!
//! Linux 限定: `FileStateStore` は Linux でのみ使える（他 OS では `Unimplemented`）。他 OS では何もしない。

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use fandhe_container_core::container_usage::measure_container_usage;
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, StateStore as _,
};
use fandhe_container_oci::image_management::{
    ContainersUsage, ImageStore, ManifestComposition, ReferenceTable,
};
use fandhe_container_oci::reference::Digest;
use flate2::Compression;
use flate2::write::GzEncoder;

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-oci-sdf-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        // 状態ルートの祖先は group / others に書き込めてはいけない（umask に依らず 0700 にする）。
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).expect("write");
    e.finish().expect("finish")
}

/// OCI-7・TASK-183: FileStateStore → core の計測 → oci の合成で、各数値を具体値で照合する。
#[test]
fn oci7_system_df_composes_containers_staging_and_expanded() {
    let t = Tmp::new("compose");

    // 状態ストア（0700 の状態ルート）と 1 コンテナの bundle（config.json 込み）。
    let state_dir = t.0.join("state");
    fs::create_dir_all(&state_dir).expect("state dir");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let store =
        FileStateStore::open(StateRoot::from_override(state_dir).expect("root")).expect("open");
    let bundle = t.0.join("bundle");
    fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    let cfg = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#;
    fs::write(bundle.join("config.json"), cfg).expect("config");
    fs::write(bundle.join("rootfs").join("bin"), vec![0u8; 4000]).expect("bin");
    let id = ContainerId::new("sdf1").expect("id");
    store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(id, None), bundle.clone())
                .expect("req"),
        )
        .expect("create");

    // イメージ側: 圧縮済みレイヤー 1 つ（展開後 20000 バイト）、config 1 つ。ステージングに 123 バイト。
    let root = t.0.join("images");
    let blobs = root.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).expect("blobs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let layer = gz(&[9u8; 20_000]);
    fs::write(blobs.join("10".repeat(32)), &layer).expect("layer");
    fs::write(blobs.join("c1".repeat(32)), vec![0u8; 50]).expect("config blob");
    let pull = root.join("staging").join("p1");
    fs::create_dir_all(&pull).expect("staging");
    fs::write(pull.join("ee".repeat(32)), vec![0u8; 123]).expect("staged");
    let mut table = ReferenceTable::new();
    table
        .register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
        )
        .expect("manifest");
    let images = ImageStore::with_table(&root, table).expect("store");

    // 1) ガードの外で core を計測する。
    let cu = measure_container_usage(&store).expect("container usage");
    let containers = ContainersUsage::new(
        cu.count,
        cu.bytes,
        cu.missing_bundles,
        cu.unreadable_configs,
        cu.inaccessible_entries,
        cu.mount_points_skipped,
    );
    // 2) ガードの内側で df と計画だけ取る。
    let (df, plan) = {
        let guard = images.lock().expect("lock");
        (
            guard.disk_usage(&root).expect("df"),
            guard.expanded_size_plan(),
        )
    };
    // 3) ガードの外で展開後サイズを計測し、合成する。
    let expanded = plan.measure(&root).expect("measure");
    let usage = df.with_containers(containers).with_expanded(expanded);

    let compressed = layer.len() as u64 + 50;
    assert_eq!(usage.images.bytes, compressed);
    assert_eq!(usage.cache.bytes, compressed);
    assert_eq!(usage.staging.pulls, 1);
    assert_eq!(usage.staging.bytes, 123);
    let c = usage.containers.expect("containers measured");
    assert_eq!(c.count, 1);
    assert_eq!(c.bytes, 4000 + cfg.len() as u64);
    assert_eq!(c.missing_bundles, 0);
    let e = usage.expanded.expect("expanded measured");
    assert_eq!(e.expanded_bytes, 20_000);
    assert_eq!(e.measured_layers, 1);
    assert_eq!(e.unmeasured_layers, 0);
}
