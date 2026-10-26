//! `NetsetupNetwork` + `LinuxNetsetup` の公開途中の失敗の巻き戻しと個別解除の実機結合試験
//! （NET-3・CRI-2・PLUG-1・#2904）。
//!
//! root（`CAP_NET_ADMIN`・`CAP_SYS_ADMIN`）・nf_tables・util-linux の `mount`・`nft` と、専用の net / mount
//! namespace が要る実機前提テストのため `#[ignore]` で既定の集合から分離する（CI の `platform-ci` には組み込まない。
//! 実機での実行は人間担当。`AGENTS.md`「実機前提テスト」）。ホストのネットワーク設定を変えないよう、初期の net
//! namespace で動いていたら panic で拒否する（前提を満たさなければ skip せず失敗にする）。
//!
//! 実行例: `sudo unshare --net --mount -- <テスト実行ファイル> --ignored --exact netsetup_unpublish_port_privileged`
//!
//! 照合する内容: 公開 2 件で DNAT が 4 本（各公開で prerouting と output の 2 本）→ 1 件を `unpublish_port` で
//! 2 本に減る → 解除した受け口を再公開できる → 重複した公開指定で `set_up_sandbox` が失敗すると、公開済みを個別に
//! 解除したうえで `delete_network` で専用テーブルごと消える（`rolled_back` が真）。

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use fandhe_container_core::traits::{
    ContainerId, DeleteNetworkRequest, IpCidr, NetworkName, NetworkPlugin, Protocol,
    PublishPortRequest, UnpublishPortRequest,
};
use fandhe_container_cri::port_mapping::{PodPortPublish, parse_port_mappings};
use fandhe_container_cri::runtime::v1::PortMapping as CriPortMapping;
use fandhe_container_plugin_cri::netsetup::{LinuxNetsetup, NetsetupNetwork};
use fandhe_container_plugin_cri::pod_network;

const SB: &str = "sandbox-2904";

fn ns_inode(path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {path}: {e}"))
        .ino()
}

fn run(program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// ruleset の中の、受け口 `host_port`（192.0.2.10）宛ての DNAT 行の本数。
fn dnat_lines(host_port: u16) -> usize {
    run("nft", &["list", "ruleset"])
        .lines()
        .filter(|l| {
            l.contains("dnat to") && l.contains("192.0.2.10") && l.contains(&host_port.to_string())
        })
        .count()
}

fn pod_publish(host_port: i32) -> PodPortPublish {
    parse_port_mappings(&[CriPortMapping {
        protocol: 0,
        container_port: 80,
        host_port,
        host_ip: "192.0.2.10".into(),
    }])
    .expect("valid")
    .remove(0)
}

/// NET-3・CRI-2・#2904: 実 nftables で個別解除と、公開途中の失敗の巻き戻しを通す。
#[test]
#[ignore = "requires root (CAP_NET_ADMIN/CAP_SYS_ADMIN), nf_tables, mount/nft and a private net+mount namespace: NET-3, CRI-2, #2904"]
fn netsetup_unpublish_port_privileged() {
    // ホストの net namespace を触らない（fail-closed）。
    assert_ne!(
        ns_inode("/proc/self/ns/net"),
        ns_inode("/proc/1/ns/net"),
        "refusing to run in the initial net namespace: use `unshare --net --mount`"
    );
    // pin の置き場は mount namespace の中の tmpfs に閉じる（host へ漏らさない）。
    run("mount", &["--make-rprivate", "/"]);
    let dir = std::env::temp_dir().join(format!("fandhe-2904-{}", std::process::id()));
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("mkdir");
    }
    let dir_str = dir.to_str().expect("utf8 path");
    run("mount", &["-t", "tmpfs", "tmpfs", dir_str]);
    let netns_dir = dir.join(".netns");

    let net = NetsetupNetwork::new(LinuxNetsetup::new(netns_dir));
    let subnet = IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).expect("subnet");
    let ports = [pod_publish(8080), pod_publish(8081)];
    pod_network::set_up_sandbox(&net, SB, subnet, &ports).expect("set up with two ports");
    assert_eq!(dnat_lines(8080), 2);
    assert_eq!(dnat_lines(8081), 2);

    let name = NetworkName::new(SB).expect("name");
    let container = ContainerId::new(SB).expect("id");
    let nz = |p: u16| std::num::NonZeroU16::new(p).expect("port");
    let unpublish = UnpublishPortRequest::new(
        name.clone(),
        container.clone(),
        nz(8080),
        nz(80),
        Protocol::Tcp,
    )
    .with_host_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    net.unpublish_port(&unpublish).expect("unpublish 8080");
    assert_eq!(dnat_lines(8080), 0);
    assert_eq!(dnat_lines(8081), 2);

    // 解除した受け口は再公開できる。
    net.publish_port(
        &PublishPortRequest::new(name.clone(), container, nz(8080), nz(80), Protocol::Tcp)
            .with_host_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
    )
    .expect("republish 8080");
    assert_eq!(dnat_lines(8080), 2);
    net.delete_network(&DeleteNetworkRequest::new(name))
        .expect("delete network");
    assert_eq!(dnat_lines(8080), 0);

    // 重複した公開指定で 2 件目が失敗しても、公開済みの 1 件を個別に解除し、テーブルごと消える。
    let dup = [pod_publish(8090), pod_publish(8090)];
    let f = pod_network::set_up_sandbox(&net, "sandbox-2904b", subnet, &dup).expect_err("dup");
    assert!(f.rolled_back, "rollback failed: {}", f.error);
    assert_eq!(dnat_lines(8090), 0);

    run("umount", &[dir_str]);
    std::fs::remove_dir(&dir).expect("cleanup");
}
