//! TASK-186 の不正入力ケース (5)〜(12) のユニットテスト版（NET-12・TASK-185.5・ERR-1・REPAIR-12）。
//!
//! 実機実測（人間担当・TASK-186）の前段として、各不正入力が `INVALID_ARGUMENT`（ERR-1 形式）で拒否され、
//! 副作用先 3 つ（hosts ファイル・`resolv.conf`・DNS ヘルパーの上流マップ）が 1 バイトも変わらないことを
//! 機械照合する。成功ケース (1)〜(4) の実機実測と、ERR-1 の非ゼロ終了コード（CLI 層の責務。
//! `--add-host` / `--dns` の CLI 配線は未実装）は対象外。
//!
//! TASK-146.2（#336・NET-8）の軽量運用向け `--dns` 直接書き込み（`etc_hosts::apply_static_dns`）も本ファイルの
//! 既存ケースをそのまま再利用して照合する。本タスク固有の不正入力テストは新設しない。
//!
//! 不正系テストは `cfg` で絞らず 3 OS で実行する。`apply_add_hosts_with_recorder` は入力検証を
//! `append_add_hosts` の OS 分岐より前に行うため、不正入力はどの OS でも `INVALID_ARGUMENT` になりファイルに触れない。

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use super::resolv_conf::{DnsApplyOutcome, apply_dns};
use super::{HostName, InputViolation, apply_add_hosts, parse_ip_addr};
use crate::dns_helper::upstream::{DnsUpstreamMap, UpstreamSetOutcome};
use crate::error::{NetError, NetErrorCode};
use crate::etc_hosts::{NameResolution, StaticDnsOutcome, apply_static_dns};
use crate::instrument::NoopNetOpRecorder;
use crate::netlink_route::{IfIndex, IpPrefix};
use crate::network::{CreatedNetwork, NetworkName, NetworkResourceNames};
use crate::network_mode::NetworkMode;

const GW: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 1);
const SEED: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 2);
const TARGET: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 3);
const HOSTS_INIT: &str = "127.0.0.1\tlocalhost\n";
const RESOLV_INIT: &str = "nameserver 10.0.0.1\n";

/// 軽量運用（`StaticHosts`）のネットワーク。TASK-146.2 の入口へ渡すテスト専用の組み立て。
fn static_net() -> CreatedNetwork {
    let name = NetworkName::new("web").unwrap();
    let names = NetworkResourceNames::derive(&name).unwrap();
    CreatedNetwork {
        name,
        bridge: names.bridge().clone(),
        bridge_index: IfIndex::new(7).unwrap(),
        bridge_token: "fandhe-net:web:1:0:0".to_owned(),
        table: names.table().clone(),
        gateway: IpPrefix::new(IpAddr::V4(GW), 24).unwrap(),
        name_resolution: NameResolution::StaticHosts,
    }
}

/// ケースごとの副作用先 3 つ（hosts・resolv.conf・上流マップ）をまとめた fixture。
struct Sinks {
    root: PathBuf,
    hosts_root: PathBuf,
    resolv: PathBuf,
    upstream: DnsUpstreamMap,
}

impl Sinks {
    fn new(case: &str) -> Self {
        let root = std::env::temp_dir().join(format!("fc-net12-{case}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("hosts_dir")).unwrap();
        std::fs::create_dir_all(root.join("resolv_dir")).unwrap();
        // 管理ルートは symlink を含まない絶対パスで渡す契約のため正規化しておく。
        let hosts_root = std::fs::canonicalize(root.join("hosts_dir")).unwrap();
        std::fs::write(hosts_root.join("hosts"), HOSTS_INIT).unwrap();
        let resolv = root.join("resolv_dir").join("resolv.conf");
        std::fs::write(&resolv, RESOLV_INIT).unwrap();
        let upstream = DnsUpstreamMap::new();
        let seed: IpAddr = "192.0.2.53".parse().unwrap();
        upstream.set(SEED, GW, &[seed]).unwrap();
        Self {
            root,
            hosts_root,
            resolv,
            upstream,
        }
    }

    fn hosts(&self) -> String {
        std::fs::read_to_string(self.hosts_root.join("hosts")).unwrap()
    }

    /// 3 つの副作用先がすべて初期状態のままであることを照合する。
    fn assert_unchanged(&self) {
        assert_eq!(self.hosts(), HOSTS_INIT);
        assert_eq!(std::fs::read_to_string(&self.resolv).unwrap(), RESOLV_INIT);
        // tmp ファイルの残骸がないこと。
        let n = std::fs::read_dir(self.resolv.parent().unwrap())
            .unwrap()
            .count();
        assert_eq!(n, 1);
        let n = std::fs::read_dir(&self.hosts_root).unwrap().count();
        assert_eq!(n, 1);
        assert_eq!(self.upstream.len(), 1);
        let seeded: Vec<_> = self.upstream.lookup(SEED).unwrap().iter().collect();
        assert_eq!(seeded, vec!["192.0.2.53:53".parse().unwrap()]);
        assert!(self.upstream.lookup(TARGET).is_none());
    }

    /// `--add-host` に不正値を渡し、期待した違反で拒否されることを照合する。先頭の有効値も書かれない。
    fn try_add_host(&self, raw: &str, expected: InputViolation) {
        let r = apply_add_hosts(&self.hosts_root, Path::new("hosts"), ["ok:192.0.2.1", raw]);
        assert_err1(r, expected);
    }

    /// `--dns` に不正値を渡す。host / none 両モードと上流登録経路のすべてで同じ違反になる。
    fn try_dns(&self, raw: &str, expected: InputViolation) {
        for (mode, first) in [
            (NetworkMode::Host, "192.0.2.1"),
            (NetworkMode::None, "127.0.0.1"),
        ] {
            let r = apply_dns(mode, &[first, raw], &self.resolv, &NoopNetOpRecorder);
            assert_err1(r, expected);
        }
        // TASK-146.2（NET-8）: 軽量運用の bridge でも同じ違反で、ファイルに触れない。
        let r = apply_static_dns(
            &static_net(),
            &["192.0.2.1", raw],
            &self.resolv,
            &NoopNetOpRecorder,
        );
        assert_err1(r, expected);
        let r = register_raw_upstreams(&self.upstream, TARGET, GW, &["192.0.2.54", raw]);
        assert_err1(r, expected);
    }
}

impl Drop for Sinks {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// ERR-1 形式（`INVALID_ARGUMENT`・固定の英語メッセージ。入力をエコーしない）を具体値で照合する。
fn assert_err1<T: std::fmt::Debug>(r: Result<T, NetError>, expected: InputViolation) {
    let e = r.unwrap_err();
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    assert_eq!(e.code().as_str(), "INVALID_ARGUMENT");
    assert_eq!(e.message(), expected.message());
}

/// テスト専用: 生文字列を全件検証し、全件通ったときだけ上流マップへ登録する。
///
/// 本番に生文字列からマップへ登録する経路は未実装（`dns_helper::upstream` の module doc にある REPAIR-3）。
/// 本ヘルパーは「検証済み `IpAddr` しかマップに到達できない」という契約を固定するもので、本番配線の網羅ではない。
fn register_raw_upstreams(
    map: &DnsUpstreamMap,
    container: Ipv4Addr,
    gw: Ipv4Addr,
    raws: &[&str],
) -> Result<UpstreamSetOutcome, NetError> {
    let ips = raws
        .iter()
        .map(|s| parse_ip_addr(s))
        .collect::<Result<Vec<_>, _>>()?;
    map.set(container, gw, &ips)
}

fn a(n: usize) -> String {
    "a".repeat(n)
}

/// 陽性対照: 有効入力では副作用先が実際に変わる（「不変」アサーションが空振りでないことの保証）。
/// hosts の追記は Linux 限定（他 OS は `UNIMPLEMENTED`）。NET-12・TASK-185.5。
#[test]
fn net12_sinks_change_on_valid_input() {
    let s = Sinks::new("positive");
    let out = apply_dns(
        NetworkMode::Host,
        &["192.0.2.53"],
        &s.resolv,
        &NoopNetOpRecorder,
    )
    .unwrap();
    assert!(matches!(out, DnsApplyOutcome::Written { count: 1, .. }));
    assert_eq!(
        std::fs::read_to_string(&s.resolv).unwrap(),
        "# Generated by fandhe-container (NET-12)\nnameserver 192.0.2.53\n"
    );
    // TASK-146.2（NET-8）: 軽量運用の経路も同じ形式で書く。
    let out = apply_static_dns(
        &static_net(),
        &["192.0.2.53"],
        &s.resolv,
        &NoopNetOpRecorder,
    )
    .unwrap();
    assert!(matches!(
        out,
        StaticDnsOutcome::Applied(DnsApplyOutcome::Written { count: 1, .. })
    ));
    assert_eq!(
        std::fs::read_to_string(&s.resolv).unwrap(),
        "# Generated by fandhe-container (NET-12)\nnameserver 192.0.2.53\n"
    );
    let r = register_raw_upstreams(&s.upstream, TARGET, GW, &["192.0.2.54"]).unwrap();
    assert_eq!(r, UpstreamSetOutcome::Inserted);
    let got: Vec<_> = s.upstream.lookup(TARGET).unwrap().iter().collect();
    assert_eq!(got, vec!["192.0.2.54:53".parse().unwrap()]);

    let r = apply_add_hosts(&s.hosts_root, Path::new("hosts"), ["web:192.0.2.1"]);
    #[cfg(target_os = "linux")]
    {
        r.unwrap();
        assert_eq!(s.hosts(), "127.0.0.1\tlocalhost\n192.0.2.1\tweb\n");
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(r.unwrap_err().code(), NetErrorCode::Unimplemented);
        assert_eq!(s.hosts(), HOSTS_INIT);
    }
}

/// NET-12・TASK-185.5・TASK-186 (5): hostname 空値（`--dns` の空値も含む）。
#[test]
fn net12_case05_empty_hostname_rejected_without_side_effects() {
    let s = Sinks::new("c05");
    s.try_add_host(":192.0.2.1", InputViolation::EmptyHostname);
    s.try_dns("", InputViolation::NotIpAddress);
    s.assert_unchanged();
}

/// NET-12・TASK-185.5・TASK-186 (6): IP として解釈できない値。none モードでも loopback 違反にならない。
#[test]
fn net12_case06_non_ip_rejected_without_side_effects() {
    let s = Sinks::new("c06");
    for ip in [
        "999.1.1.1",
        "example.com",
        "host-gateway",
        "1.2.3.4/24",
        "[::1]",
        "fe80::1%eth0",
        "010.0.0.1",
        "",
    ] {
        s.try_add_host(&format!("web:{ip}"), InputViolation::NotIpAddress);
        s.try_dns(ip, InputViolation::NotIpAddress);
    }
    s.assert_unchanged();
}

/// NET-12・TASK-185.5・TASK-186 (7): 空白混入（hostname 側と IP 側の別経路）。
#[test]
fn net12_case07_whitespace_rejected_without_side_effects() {
    let s = Sinks::new("c07");
    let v = InputViolation::ControlOrWhitespace;
    s.try_add_host("my host:192.0.2.1", v);
    for ip in [
        " 192.0.2.1",
        "192.0.2.1 ",
        "192.0.2.1\u{3000}",
        "192.0.2.1\u{a0}",
    ] {
        s.try_add_host(&format!("web:{ip}"), v);
    }
    for ip in [" 192.0.2.1", "192.0.2.1 ", "192.0.2.1\u{3000}"] {
        s.try_dns(ip, v);
    }
    s.assert_unchanged();
}

/// NET-12・TASK-185.5・TASK-186 (8): ラベルの先頭 / 末尾ハイフン（`--dns` は IP のみで対象外）。
#[test]
fn net12_case08_label_hyphen_edge_rejected_without_side_effects() {
    let s = Sinks::new("c08");
    for h in ["-web", "web-", "a.-b.example", "a.b-.example", "a.example-"] {
        s.try_add_host(&format!("{h}:192.0.2.1"), InputViolation::LabelHyphenEdge);
    }
    s.assert_unchanged();
}

/// NET-12・TASK-185.5・TASK-186 (9): ラベル 64 文字は拒否。63 文字は受理（境界の正常系）。
#[test]
fn net12_case09_label_64_rejected_without_side_effects() {
    let s = Sinks::new("c09");
    let l = a(64);
    for h in [l.clone(), format!("{l}.example"), format!("x.{l}")] {
        s.try_add_host(&format!("{h}:192.0.2.1"), InputViolation::LabelLength);
    }
    s.assert_unchanged();
    assert!(HostName::parse(&a(63)).is_ok());
}

/// NET-12・TASK-185.5・TASK-186 (10): 総長 254 文字は拒否（`AddHostTooLong` ではない）。253 文字は受理。
#[test]
fn net12_case10_total_254_rejected_253_accepted() {
    let s = Sinks::new("c10");
    let h254 = format!("{}.{}.{}.{}", a(63), a(63), a(63), a(62));
    assert_eq!(h254.len(), 254);
    s.try_add_host(
        &format!("{h254}:192.0.2.1"),
        InputViolation::HostnameTooLong,
    );
    s.assert_unchanged();

    let h253 = format!("{}.{}.{}.{}", a(63), a(63), a(63), a(61));
    assert_eq!(h253.len(), 253);
    assert!(HostName::parse(&h253).is_ok());
    #[cfg(target_os = "linux")]
    {
        apply_add_hosts(
            &s.hosts_root,
            Path::new("hosts"),
            [format!("{h253}:192.0.2.1").as_str()],
        )
        .unwrap();
        assert_eq!(s.hosts(), format!("{HOSTS_INIT}192.0.2.1\t{h253}\n"));
    }
}

/// NET-12・TASK-185.5・TASK-186 (11): 改行（hosts / resolv.conf への行注入を含む）。
#[test]
fn net12_case11_newline_rejected_without_side_effects() {
    let s = Sinks::new("c11");
    let v = InputViolation::ControlOrWhitespace;
    for raw in [
        "web\n:192.0.2.1",
        "a\n1.2.3.4 evil:192.0.2.1",
        "web:192.0.2.1\n",
        "web:192.0.2.1\r\n",
        "web:192.0.2.1\n10.0.0.9 evil",
    ] {
        s.try_add_host(raw, v);
    }
    for raw in ["192.0.2.1\nnameserver 8.8.8.8", "192.0.2.1\r"] {
        s.try_dns(raw, v);
    }
    // none モード固有の注入（loopback 先頭）も拒否される。
    let r = apply_dns(
        NetworkMode::None,
        &["127.0.0.1\nnameserver 8.8.8.8"],
        &s.resolv,
        &NoopNetOpRecorder,
    );
    assert_err1(r, v);
    s.assert_unchanged();
}

/// NET-12・TASK-185.5・TASK-186 (12): 制御文字（タブ・NUL・ESC・DEL・C1）。
#[test]
fn net12_case12_control_char_rejected_without_side_effects() {
    let s = Sinks::new("c12");
    let v = InputViolation::ControlOrWhitespace;
    for raw in [
        "web\t:192.0.2.1",
        "we\0b:192.0.2.1",
        "we\x1bb:192.0.2.1",
        "we\x7fb:192.0.2.1",
        "we\u{85}b:192.0.2.1",
        "web:192.0.2.1\t",
        "web:192.0.2.1\0",
    ] {
        s.try_add_host(raw, v);
    }
    for raw in ["192.0.2.1\t", "\t192.0.2.1", "192.0.2.1\0", "192.0.2.1\x1b"] {
        s.try_dns(raw, v);
    }
    s.assert_unchanged();
}
