//! 本番の `ProductionStartDeps` の手順 4b(`prepare_network` / `release_network`)と `ContainerOptions::launch_options`
//! の結線の結合試験(NET-6・NET-12・CORE-2・SEC-1・REPAIR-12・#1873)。
//!
//! # 役割
//!
//! CLI が受け渡した `network` / `add-host` / `dns` を持つ `ContainerOptions` を本番の `ProductionStartDeps` に載せ、
//! start の手順 4b が管理ルートへ生成する `/etc/hosts`・`/etc/resolv.conf` の内容と、launcher へ渡す
//! `LaunchOptions` の bind 対象・ネットワークモードが同じ選択で決まることを照合する。特権・実機は要らない
//! (既定の試験集合で動く)。launcher 自体の bind と netns の実機観測は core 側の `etc_files_mount` が担う。
//!
//! 照合する場面: CLI で省略したときの従来動作(生成なし)、`none`(add-host / dns の反映)、`host`(netns 基準の
//! 照合を通る)、準備の失敗時に何も残さないこと、後始末(`release_network` が生成物を消す・二重解放は無害)。

#![cfg(target_os = "linux")]

use std::path::PathBuf;

use fandhe_container_core::etc_files::{EtcFileKind, etc_dir, etc_file_path};
use fandhe_container_core::traits::ContainerId;
use fandhe_container_supervisor::container_options::ContainerOptions;
use fandhe_container_supervisor::container_options::network::NetworkOptions;
use fandhe_container_supervisor::start_entry::{ProductionStartDeps, StartDeps};

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let p = std::env::temp_dir().join(format!("fc-startnet-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("mkdir");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(p)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn options(network: Option<&str>, hosts: &[&str], dns: &[&str]) -> ContainerOptions {
    let h: Vec<String> = hosts.iter().map(|s| (*s).to_owned()).collect();
    let d: Vec<String> = dns.iter().map(|s| (*s).to_owned()).collect();
    let net = NetworkOptions::parse(network, &h, &d, &[]).expect("parse");
    ContainerOptions::new().with_network(net)
}

fn id() -> ContainerId {
    ContainerId::new("c1").expect("id")
}

/// NET-6: CLI で `--network` を省略した従来のコンテナ(文書に network が無い)は何も生成しない。
#[test]
fn net6_omitted_network_generates_nothing() {
    let root = Root::new("omitted");
    let o = ContainerOptions::new();
    assert!(o.launch_options().expect("launch").etc_files().is_empty());
    let mut deps = ProductionStartDeps::new(root.0.clone()).with_container_options(o);
    deps.prepare_network(&id()).expect("prepare");
    assert!(!etc_dir(&root.0, &id()).exists());
    assert_eq!(deps.network_log_mode(), None);
    deps.release_network().expect("release");
}

/// NET-6・NET-12: `none` + add-host + dns は hosts / resolv.conf を生成し、launcher へ同じ選択を渡し、
/// `release_network` で消える(二重解放は無害)。
#[test]
fn net12_none_mode_generates_and_releases() {
    let root = Root::new("none");
    let o = options(Some("none"), &["web:192.0.2.10"], &["127.0.0.1"]);
    let launch = o.launch_options().expect("launch");
    assert_eq!(
        launch.etc_files().kinds(),
        vec![EtcFileKind::Hosts, EtcFileKind::ResolvConf]
    );
    let mut deps = ProductionStartDeps::new(root.0.clone()).with_container_options(o);
    deps.prepare_network(&id()).expect("prepare");
    let hosts =
        std::fs::read_to_string(etc_file_path(&root.0, &id(), EtcFileKind::Hosts)).expect("hosts");
    assert!(hosts.ends_with("192.0.2.10\tweb\n"), "{hosts}");
    let resolv = std::fs::read_to_string(etc_file_path(&root.0, &id(), EtcFileKind::ResolvConf))
        .expect("resolv");
    assert!(resolv.ends_with("nameserver 127.0.0.1\n"), "{resolv}");
    assert_eq!(deps.network_log_mode(), None);
    deps.release_network().expect("release");
    assert!(!etc_dir(&root.0, &id()).exists());
    deps.release_network().expect("second release is harmless");
}

/// NET-6: `host` は netns の基準照合を通り、構造化ログのモードが `host` になる。add-host / dns が反映される。
#[test]
fn net6_host_mode_passes_baseline_and_generates() {
    let root = Root::new("host");
    let o = options(Some("host"), &["h:192.0.2.20"], &["192.0.2.53"]);
    let mut deps = ProductionStartDeps::new(root.0.clone()).with_container_options(o);
    deps.prepare_network(&id()).expect("prepare");
    assert_eq!(deps.network_log_mode(), Some("host"));
    let resolv = std::fs::read_to_string(etc_file_path(&root.0, &id(), EtcFileKind::ResolvConf))
        .expect("resolv");
    assert!(resolv.ends_with("nameserver 192.0.2.53\n"), "{resolv}");
    deps.release_network().expect("release");
    assert!(!etc_dir(&root.0, &id()).exists());
}

/// NET-12・SEC-1: 管理ルートに生成先を作れない(`@container-etc` が通常ファイル)ときは失敗し、何も残さない。
#[test]
fn net12_prepare_failure_leaves_nothing() {
    let root = Root::new("fail");
    std::fs::write(root.0.join("@container-etc"), b"x").expect("block");
    let o = options(Some("none"), &["a:192.0.2.1"], &[]);
    let mut deps = ProductionStartDeps::new(root.0.clone()).with_container_options(o);
    assert!(deps.prepare_network(&id()).is_err());
    assert!(!etc_dir(&root.0, &id()).exists());
    deps.release_network().expect("release");
}

/// NET-12・CORE-2・SEC-1・REPAIR-5(#3345): 並行する同じ ID の start で `claim_start` に負けた側は `prepare_network` を呼ばず、
/// 巻き戻し(`release_network`)が勝った側の生成物(`@container-etc/<id>`)を消さない。
///
/// start の手順 4b は所有ロック(`claim_start`)を握った後にだけ生成・削除する順序で、`release_network` は自分が作った分
/// (`etc_created`)だけを消す。この 2 点(`docs/design/network-wiring.md` D14)を、勝った側の生成物の inode と内容が
/// 負けた側の巻き戻しの前後で不変であることで照合する。実機の補強は cli の `network_modes_real`(running への 2 回目の start)。
#[test]
fn net12_core2_loser_release_keeps_winner_etc_files() {
    use std::os::unix::fs::MetadataExt as _;

    let root = Root::new("loser");
    let make = || {
        let o = options(Some("none"), &["web:192.0.2.10"], &["127.0.0.1"]);
        ProductionStartDeps::new(root.0.clone()).with_container_options(o)
    };
    let mut winner = make();
    winner.prepare_network(&id()).expect("winner prepare");
    let snapshot = || {
        [EtcFileKind::Hosts, EtcFileKind::ResolvConf].map(|k| {
            let p = etc_file_path(&root.0, &id(), k);
            let md = std::fs::metadata(&p).expect("stat");
            ((md.dev(), md.ino()), std::fs::read(&p).expect("read"))
        })
    };
    let before = snapshot();
    assert!(
        String::from_utf8_lossy(&before[0].1).ends_with("192.0.2.10\tweb\n"),
        "{:?}",
        before[0].1
    );

    // 負けた側: claim_start に負けるため prepare_network は呼ばれず、失敗の巻き戻しで release_network だけが呼ばれる。
    let mut loser = make();
    loser.release_network().expect("loser release");
    assert_eq!(
        snapshot(),
        before,
        "loser release touched the winner's files"
    );

    // 勝った側の release で初めて消える。
    winner.release_network().expect("winner release");
    assert!(!etc_dir(&root.0, &id()).exists());
}
