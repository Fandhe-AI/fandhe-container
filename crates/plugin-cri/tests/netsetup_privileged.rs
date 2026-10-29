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

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

/// 外部コマンド 1 回の期限（REPAIR-5）。超過したら子を kill して回収する。
const CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// 外部コマンドを期限つきで実行する。出力の収集も期限内に限る（REPAIR-5）。
///
/// 子孫が stdout / stderr を継承して残っても `read_to_end` の完了を待ち続けないよう、読み取りスレッドの結果は
/// チャネルの `recv_timeout` で受け、期限を超えたら読み取りを諦めてエラーにする（スレッドは切り離す）。
fn exec(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {program}: {e}"))?;
    let mut so = child.stdout.take().ok_or("stdout")?;
    let mut se = child.stderr.take().ok_or("stderr")?;
    let (tx_o, rx_o) = mpsc::channel();
    let (tx_e, rx_e) = mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        let _ = tx_o.send(b);
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        let _ = tx_e.send(b);
    });
    let deadline = Instant::now() + CMD_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(|e| format!("try_wait: {e}"))? {
            Some(st) => break st,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                // kill 後の回収も期限つきにする（回収できなければ諦める）。
                let reap_until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < reap_until {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                return Err(format!(
                    "{program} {args:?} timed out after {CMD_TIMEOUT:?}"
                ));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let left = |d: Instant| d.saturating_duration_since(Instant::now());
    let drain_until = Instant::now() + Duration::from_secs(5);
    let stdout = rx_o
        .recv_timeout(left(drain_until))
        .map_err(|_| format!("{program} {args:?}: stdout drain timed out"))?;
    let stderr = rx_e
        .recv_timeout(left(drain_until))
        .map_err(|_| format!("{program} {args:?}: stderr drain timed out"))?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn run(program: &str, args: &[&str]) -> String {
    let out = exec(program, args).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// root で作った一時ディレクトリの回収ガード。途中の失敗・panic でもアンマウントして削除する。
struct DirGuard(std::path::PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        if let Some(d) = self.0.to_str() {
            // マウントされていなければ失敗するだけなので結果は無視する（後始末は best effort）。
            let _ = exec("umount", &["-R", "-l", d]);
        }
        let _ = std::fs::remove_dir(&self.0);
    }
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
    // mount namespace も専用であることを確認する（共有のままだと伝播変更・マウントがホストへ及ぶ。SEC-1）。
    assert_ne!(
        ns_inode("/proc/self/ns/mnt"),
        ns_inode("/proc/1/ns/mnt"),
        "refusing to run in the initial mount namespace: use `unshare --net --mount`"
    );
    // pin の置き場は mount namespace の中の tmpfs に閉じる（host へ漏らさない）。
    run("mount", &["--make-rprivate", "/"]);
    // root が予測できる名前を再帰削除すると先取りされる余地があるため、既存のパスは消さず、
    // 排他作成（0700）で連番を進める（REPAIR-12・#3375）。後始末は下の DirGuard が行う。
    let dir = {
        use std::os::unix::fs::DirBuilderExt as _;
        (0..1000u32)
            .find_map(|n| {
                let p =
                    std::env::temp_dir().join(format!("fandhe-2904-{}-{n}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                    Ok(()) => Some(p),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(e) => panic!("mkdir: {e}"),
                }
            })
            .expect("too many stale test directories")
    };
    let _guard = DirGuard(dir.clone());
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
}
