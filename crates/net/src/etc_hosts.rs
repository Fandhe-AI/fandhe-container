//! 軽量運用（DNS ヘルパーなし）のサービス名解決: コンテナ hosts ファイルへの静的注入と、
//! 名前解決方式の選択（NET-8・TASK-146.1・#334・MS-8。入力検証は NET-12・TASK-185.1 の契約を再利用）。
//!
//! # 役割
//! DNS ヘルパー（NET-5。参照カウントによるオンデマンド起動は NET-7・TASK-144）を起動せず、同じネットワークに
//! 参加しているコンテナの「名前 → IPv4 アドレス」一覧を、コンテナ起動時にそのコンテナの hosts ファイルへ
//! 書き込んでサービス名を解決する。方式は [`NameResolution`] で選び、ネットワーク作成時に
//! `NetworkCreateSpec::with_name_resolution` で指定する（`CreatedNetwork::name_resolution` へ引き継がれる）。
//!
//! # 呼び出し文脈
//! 1. `network::create_network`（`StaticHosts` を指定）
//! 2. `network::attach_container`（IPAM が各コンテナのアドレスを払い出す）
//! 3. `DnsHelperRefCounts::join_network`（`JoinOutcome::HelperDisabled` になりヘルパーは起動しない）
//! 4. コンテナ起動直前に [`inject_service_hosts`]（参加者全員の名前とアドレスを渡す）
//! 5. 同じく起動直前に `--dns` があれば [`apply_static_dns`]（runtime が用意した `resolv.conf` のパスへ
//!    `nameserver` を直接書く。NET-8・TASK-146.2・#336。指定サーバーへの到達確認は #337・TASK-146.3）
//!
//! hosts ファイルの生成とコンテナへの bind mount は runtime / core の責務で、本モジュールは管理ルート配下の
//! 既存の通常ファイルへ追記するだけ。書き込みは `--add-host`（NET-12・TASK-185.2）と同じ追記経路
//! （O_NOFOLLOW・nlink・所有者・mnt_id 照合・flock・巻き戻し）を共有し、新しい書き込み経路は持たない。
//! `--add-host` と同じファイルに追記するため、hosts の解決は最初に一致した行が勝つ点を踏まえ、
//! 追記の順序は runtime 側が決める。
//!
//! # 更新の範囲（参加・離脱）
//! - 書き込みは「コンテナ起動時の 1 回」で固定する。動的更新はしない
//! - 起動後に参加したコンテナは、起動済みコンテナの hosts に追加されない
//! - 離脱したコンテナの行は、他コンテナの再起動まで残る
//! - 追記専用のため、同じファイルへ再注入すると重複行が残る。新しく生成した hosts ファイルへ 1 回だけ呼ぶ
//! - 動的に追従させたい場合は DNS ヘルパー方式（NET-5・NET-7）を使う
//!
//! # 未実装（REPAIR-3）
//! - hosts の動的更新（参加・離脱の反映。担当 Issue 未確定）
//! - CLI `network create` への設定の配線（統一 CLI は TASK-79）と、名前解決方式のプロセスをまたぐ永続化
//!
//! 追記は Linux 限定（他 OS は `UNIMPLEMENTED`）。エラーの `message` は固定の英語文字列で入力値を含めない。

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::add_host_dns::resolv_conf::{DnsApplyOutcome, ResolvConfPlan};
use crate::add_host_dns::{AddHostEntry, HostName, append_hosts_lines, render_hosts_lines};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};
use crate::network::CreatedNetwork;

/// 静的注入の最大件数。1 行は IPv4 で最大約 271 バイトなので、上限件数でも約 272 KiB となり
/// hosts ファイルの上限（1 MiB）を下回る（無制限確保の防止）。
pub const MAX_STATIC_HOST_ENTRIES: usize = 1024;

/// ネットワークのサービス名解決方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum NameResolution {
    /// DNS ヘルパー（NET-5。参照カウントでオンデマンド起動する NET-7）。既定。
    #[default]
    DnsHelper,
    /// hosts ファイルへの静的注入（NET-8 の軽量運用。DNS ヘルパーを起動しない）。
    StaticHosts,
}

impl NameResolution {
    /// `"dns-helper"` / `"static-hosts"` のみ受け付ける（厳密一致）。違反は固定文言の `INVALID_ARGUMENT`。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        match s {
            "dns-helper" => Ok(Self::DnsHelper),
            "static-hosts" => Ok(Self::StaticHosts),
            _ => Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "invalid name resolution: expected dns-helper or static-hosts",
            )),
        }
    }

    /// 機械可読な識別子。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DnsHelper => "dns-helper",
            Self::StaticHosts => "static-hosts",
        }
    }

    /// DNS ヘルパー（参照カウントによる起動）を使う方式か。
    pub fn uses_dns_helper(&self) -> bool {
        matches!(self, Self::DnsHelper)
    }
}

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// `addr` が gateway のサブネット内の通常ホストアドレスか（gateway・ネットワーク・ブロードキャスト以外）。
fn is_usable_peer(gateway: Ipv4Addr, prefix_len: u8, addr: Ipv4Addr) -> bool {
    if prefix_len == 0 || prefix_len > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix_len));
    let (g, a) = (u32::from(gateway), u32::from(addr));
    let net = g & mask;
    let bcast = net | !mask;
    a & mask == net && a != net && a != bcast && a != g
}

/// 検証済みの静的注入エントリ表。不正な名前・アドレスを表現できず、hosts の行はこの型からのみ描画する
/// （行注入を型で防ぐ。REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHostsTable {
    entries: Vec<AddHostEntry>,
}

impl StaticHostsTable {
    /// `peers`（名前, アドレス）を検証して表にする。名前は RFC 1123（NET-12 の [`HostName`]）、
    /// アドレスはネットワークのサブネット内の IPv4 に限る。名前は大文字小文字を区別せず（glibc の `files`
    /// に合わせる）、同じ名前・同じアドレスは 1 件にまとめ、同じ名前で別アドレスは `ALREADY_EXISTS`。
    /// 件数は確保の前に [`MAX_STATIC_HOST_ENTRIES`] で検証する。失敗時に副作用は無い。
    /// 自分自身を含む参加者全員を渡すこと。出力は名前（小文字）の昇順で決定的。
    pub fn build<'a, I>(net: &CreatedNetwork, peers: I) -> Result<Self, NetError>
    where
        I: IntoIterator<Item = (&'a str, IpAddr)>,
    {
        let IpAddr::V4(gw) = net.gateway.addr() else {
            return Err(invalid("gateway must be an IPv4 address"));
        };
        let prefix = net.gateway.prefix_len();
        let mut map: BTreeMap<String, (HostName, Ipv4Addr)> = BTreeMap::new();
        let mut seen = 0usize;
        for (name, ip) in peers {
            seen += 1;
            if seen > MAX_STATIC_HOST_ENTRIES {
                return Err(invalid("too many static host entries"));
            }
            let host = HostName::parse(name)?;
            let IpAddr::V4(v4) = ip else {
                return Err(invalid("static host address must be IPv4"));
            };
            if !is_usable_peer(gw, prefix, v4) {
                return Err(invalid(
                    "static host address must be a host address in the network subnet",
                ));
            }
            let key = host.as_str().to_ascii_lowercase();
            match map.get(&key) {
                Some((_, prev)) if *prev == v4 => {}
                Some(_) => {
                    return Err(NetError::new(
                        NetErrorCode::AlreadyExists,
                        "static host name maps to different addresses",
                    ));
                }
                None => {
                    map.insert(key, (host, v4));
                }
            }
        }
        let entries = map
            .into_values()
            .map(|(h, ip)| AddHostEntry::from_parts(h, IpAddr::V4(ip)))
            .collect();
        Ok(Self { entries })
    }

    /// hosts 形式（`<ip>\t<name>\n` の列）へ描画する。
    pub fn render(&self) -> String {
        render_hosts_lines(&self.entries)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// [`inject_service_hosts`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StaticHostsOutcome {
    /// 追記した（空の表では何も開かず `entries: 0`）。
    Injected {
        /// 追記した件数。
        entries: usize,
    },
    /// ネットワークが DNS ヘルパー方式のため何もしなかった（ファイルに触れない）。
    NotApplicable,
}

/// 軽量運用のネットワークで、参加者のサービス名を hosts ファイルへ静的に追記する（NET-8・TASK-146.1）。
/// 計測しない呼び出し口。成否・所要時間を記録するには [`inject_service_hosts_with_recorder`]。
pub fn inject_service_hosts<'a, I>(
    net: &CreatedNetwork,
    managed_root: &Path,
    hosts_rel: &Path,
    peers: I,
) -> Result<StaticHostsOutcome, NetError>
where
    I: IntoIterator<Item = (&'a str, IpAddr)>,
{
    inject_service_hosts_with_recorder(net, managed_root, hosts_rel, peers, &NoopNetOpRecorder)
}

/// [`inject_service_hosts`] に計装（`NetOpKind::StaticHostsInject`。REPAIR-4）を付けた入口。
/// `DnsHelper` 方式では計測もせずファイルも開かず `NotApplicable`。`managed_root` / `hosts_rel` の
/// 契約は `add_host_dns::append_add_hosts` と同じ。検証が全件通るまでファイルを開かない。
pub fn inject_service_hosts_with_recorder<'a, I>(
    net: &CreatedNetwork,
    managed_root: &Path,
    hosts_rel: &Path,
    peers: I,
    recorder: &dyn NetOpRecorder,
) -> Result<StaticHostsOutcome, NetError>
where
    I: IntoIterator<Item = (&'a str, IpAddr)>,
{
    if net.name_resolution.uses_dns_helper() {
        return Ok(StaticHostsOutcome::NotApplicable);
    }
    record_net_op(recorder, NetOpKind::StaticHostsInject, || {
        let table = StaticHostsTable::build(net, peers)?;
        if table.is_empty() {
            return Ok(StaticHostsOutcome::Injected { entries: 0 });
        }
        append_hosts_lines(managed_root, hosts_rel, &table.render())?;
        Ok(StaticHostsOutcome::Injected {
            entries: table.len(),
        })
    })
}

/// [`apply_static_dns`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StaticDnsOutcome {
    /// 軽量運用のネットワークとして処理した（書き込み件数、または `--dns` 未指定）。
    Applied(DnsApplyOutcome),
    /// ネットワークが DNS ヘルパー方式のため何もしなかった（検証も書き込みもせずファイルに触れない）。
    /// この方式の `--dns` は上流転送（`dns_helper::upstream`。TASK-185.3）が扱う。
    NotApplicable,
}

/// 軽量運用のネットワークで、`--dns` の値をコンテナの `resolv.conf` の `nameserver` へ直接書く
/// （NET-8・TASK-146.2・#336。入力検証は NET-12 の `parse_ip_addr` を再利用）。
///
/// コンテナ起動前に呼ぶ。`resolv_path` は runtime が状態ディレクトリ配下に用意した `resolv.conf` のパスで、
/// `/etc/resolv.conf` への bind mount は core / oci の責務（rootfs 内のパスは組み立てない）。
/// 親ディレクトリは runtime 管理下の信頼できる場所であること。最終要素が symlink でも追従せず置換する。
///
/// - `DnsHelper` 方式: 何もせず [`StaticDnsOutcome::NotApplicable`]（計測もしない。ヘルパーを指す
///   nameserver を上書きしない）。
/// - 1 件でも不正（RFC 1123 外・IP 形式外・制御文字・件数超過）なら `INVALID_ARGUMENT`（ERR-1）で、
///   ファイルを開く前に拒否する（all-or-nothing）。
/// - 書き込み段階の `Err` は、rename 後の親ディレクトリ fsync 失敗では置換済みの可能性がある
///   （`apply_dns` と同じ契約）。
///
/// 検証 + 書き込み全体を 1 件として [`NetOpKind::DnsResolvConfWrite`] で記録する（REPAIR-4）。
pub fn apply_static_dns(
    net: &CreatedNetwork,
    dns: &[&str],
    resolv_path: &Path,
    recorder: &dyn NetOpRecorder,
) -> Result<StaticDnsOutcome, NetError> {
    if net.name_resolution.uses_dns_helper() {
        return Ok(StaticDnsOutcome::NotApplicable);
    }
    record_net_op(recorder, NetOpKind::DnsResolvConfWrite, || {
        match ResolvConfPlan::for_static_bridge(dns)? {
            None => Ok(StaticDnsOutcome::Applied(DnsApplyOutcome::NotRequested)),
            Some(plan) => {
                let persistence = plan.write_unrecorded(resolv_path)?;
                Ok(StaticDnsOutcome::Applied(DnsApplyOutcome::Written {
                    count: plan.nameservers().len(),
                    persistence,
                }))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::NetOpOutcome;
    use crate::instrument::testing::Collect;
    use crate::netlink_route::{IfIndex, IpPrefix};
    use crate::network::{NetworkName, NetworkResourceNames};

    fn net_with(res: NameResolution) -> CreatedNetwork {
        let name = NetworkName::new("web").unwrap();
        let names = NetworkResourceNames::derive(&name).unwrap();
        CreatedNetwork {
            name,
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: "fandhe-net:web:1:0:0".to_owned(),
            table: names.table().clone(),
            gateway: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).unwrap(),
            name_resolution: res,
        }
    }

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 89, 0, d))
    }

    fn build(peers: &[(&str, IpAddr)]) -> Result<StaticHostsTable, NetError> {
        StaticHostsTable::build(
            &net_with(NameResolution::StaticHosts),
            peers.iter().copied(),
        )
    }

    /// NET-8: parse / as_str の往復と不正値の拒否。
    #[test]
    fn net8_name_resolution_parse_roundtrip() {
        for r in [NameResolution::DnsHelper, NameResolution::StaticHosts] {
            assert_eq!(NameResolution::parse(r.as_str()).unwrap(), r);
        }
        assert_eq!(NameResolution::default(), NameResolution::DnsHelper);
        assert!(NameResolution::DnsHelper.uses_dns_helper());
        assert!(!NameResolution::StaticHosts.uses_dns_helper());
        for bad in ["", "Static-Hosts", "static-hosts ", "static_hosts"] {
            let e = NameResolution::parse(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    /// NET-8: 描画は名前の昇順で完全一致。
    #[test]
    fn net8_render_exact_bytes_sorted() {
        let t = build(&[("svc-b", ip(3)), ("svc-a", ip(2))]).unwrap();
        assert_eq!(t.render(), "10.89.0.2\tsvc-a\n10.89.0.3\tsvc-b\n");
        assert_eq!(t.len(), 2);
    }

    /// NET-8: 同名同アドレスは 1 件（大文字小文字違いを含む）、同名別アドレスは拒否。
    #[test]
    fn net8_duplicates() {
        assert_eq!(build(&[("a", ip(2)), ("a", ip(2))]).unwrap().len(), 1);
        let t = build(&[("Web", ip(2)), ("web", ip(2))]).unwrap();
        assert_eq!(t.render(), "10.89.0.2\tWeb\n");
        let e = build(&[("a", ip(2)), ("A", ip(3))]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
    }

    /// NET-12 再利用: 不正な名前は HostName と同じ違反メッセージの INVALID_ARGUMENT。
    #[test]
    fn net8_invalid_names_reuse_net12_contract() {
        for bad in ["a_b", "bad host", "a\nb", ""] {
            let got = build(&[(bad, ip(2))]).unwrap_err();
            let want = HostName::parse(bad).unwrap_err();
            assert_eq!(got.code(), NetErrorCode::InvalidArgument);
            assert_eq!(got.message(), want.message());
        }
    }

    /// NET-8: サブネット外・gateway・ネットワーク・ブロードキャスト・IPv6 は拒否。
    #[test]
    fn net8_rejects_bad_addresses() {
        let bad = [
            IpAddr::V4(Ipv4Addr::new(10, 90, 0, 2)),
            ip(1),
            ip(0),
            ip(255),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("::1".parse().unwrap()),
        ];
        for a in bad {
            let e = build(&[("a", a)]).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{a}");
        }
    }

    /// NET-8: 件数上限ちょうどは受理、+1 は拒否。最悪サイズは hosts 上限未満。
    #[test]
    fn net8_entry_limit_and_size() {
        let mut big = net_with(NameResolution::StaticHosts);
        big.gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 16).unwrap();
        let tail = format!(
            "{}.{}.{}.{}",
            "a".repeat(59),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let names: Vec<String> = (0..=MAX_STATIC_HOST_ENTRIES)
            .map(|i| format!("{i:04}{tail}"))
            .collect();
        assert_eq!(names[0].len(), 253);
        let peer = |i: usize| {
            let n = i + 2;
            IpAddr::V4(Ipv4Addr::new(10, 89, (n >> 8) as u8, (n & 0xff) as u8))
        };
        let ok = StaticHostsTable::build(
            &big,
            (0..MAX_STATIC_HOST_ENTRIES).map(|i| (names[i].as_str(), peer(i))),
        )
        .unwrap();
        assert_eq!(ok.len(), MAX_STATIC_HOST_ENTRIES);
        assert!(ok.render().len() < 1024 * 1024);
        let e = StaticHostsTable::build(
            &big,
            (0..=MAX_STATIC_HOST_ENTRIES).map(|i| (names[i].as_str(), peer(i))),
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-8: DnsHelper 方式ではファイルに触れず NotApplicable。
    #[test]
    fn net8_dns_helper_network_is_not_applicable() {
        let net = net_with(NameResolution::DnsHelper);
        let missing = std::env::temp_dir().join("fc-etc-hosts-missing-root");
        let out = inject_service_hosts(&net, &missing, Path::new("hosts"), [("a", ip(2))]).unwrap();
        assert_eq!(out, StaticHostsOutcome::NotApplicable);
    }

    /// NET-8: 空の peers は何も開かない。
    #[test]
    fn net8_empty_peers_do_not_open_file() {
        let net = net_with(NameResolution::StaticHosts);
        let missing = std::env::temp_dir().join("fc-etc-hosts-missing-root");
        let out = inject_service_hosts(&net, &missing, Path::new("hosts"), []).unwrap();
        assert_eq!(out, StaticHostsOutcome::Injected { entries: 0 });
    }

    /// NET-8: エラーメッセージに入力値を含めない。
    #[test]
    fn net8_error_does_not_echo_input() {
        let e = build(&[("secret_name", ip(2))]).unwrap_err();
        assert!(!e.message().contains("secret_name"));
    }

    /// REPAIR-4: 検証失敗は Failure として記録される。
    #[test]
    fn net8_records_failure_on_invalid() {
        let net = net_with(NameResolution::StaticHosts);
        let rec = Collect::default();
        let r = inject_service_hosts_with_recorder(
            &net,
            &std::env::temp_dir(),
            Path::new("hosts"),
            [("a_b", ip(2))],
            &rec,
        );
        assert!(r.is_err());
        assert_eq!(
            rec.kinds(),
            vec![(NetOpKind::StaticHostsInject, NetOpOutcome::Failure)]
        );
    }

    /// NET-8: 非 Linux は UNIMPLEMENTED（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn net8_unimplemented_outside_linux() {
        let net = net_with(NameResolution::StaticHosts);
        let e = inject_service_hosts(
            &net,
            &std::env::temp_dir(),
            Path::new("hosts"),
            [("a", ip(2))],
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Unimplemented);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        struct Tmp(std::path::PathBuf);
        impl Tmp {
            fn new(case: &str, content: &str) -> Self {
                let root = std::env::temp_dir()
                    .join(format!("fc-stathosts-{}-{case}", std::process::id()));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(&root).unwrap();
                let root = std::fs::canonicalize(&root).unwrap();
                std::fs::write(root.join("hosts"), content).unwrap();
                Self(root)
            }
            fn read(&self) -> String {
                std::fs::read_to_string(self.0.join("hosts")).unwrap()
            }
        }
        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// NET-8: 既存内容の後ろへ完全一致で追記され、成功が記録される。
        #[test]
        fn net8_injects_into_hosts() {
            let t = Tmp::new("inject", "127.0.0.1\tlocalhost\n");
            let net = net_with(NameResolution::StaticHosts);
            let rec = Collect::default();
            let out = inject_service_hosts_with_recorder(
                &net,
                &t.0,
                Path::new("hosts"),
                [("svc-b", ip(3)), ("svc-a", ip(2))],
                &rec,
            )
            .unwrap();
            assert_eq!(out, StaticHostsOutcome::Injected { entries: 2 });
            assert_eq!(
                t.read(),
                "127.0.0.1\tlocalhost\n10.89.0.2\tsvc-a\n10.89.0.3\tsvc-b\n"
            );
            assert_eq!(
                rec.kinds(),
                vec![(NetOpKind::StaticHostsInject, NetOpOutcome::Success)]
            );
        }

        /// NET-8: 検証失敗時はファイル不変。
        #[test]
        fn net8_invalid_leaves_file_unchanged() {
            let t = Tmp::new("unchanged", "127.0.0.1\tlocalhost\n");
            let net = net_with(NameResolution::StaticHosts);
            let e = inject_service_hosts(
                &net,
                &t.0,
                Path::new("hosts"),
                [("ok", ip(2)), ("a b", ip(3))],
            )
            .unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(t.read(), "127.0.0.1\tlocalhost\n");
        }

        /// NET-8: symlink の hosts は既存の追記経路が拒否する。
        #[test]
        fn net8_symlink_hosts_rejected() {
            let t = Tmp::new("symlink", "x\n");
            std::fs::write(t.0.join("real"), "y\n").unwrap();
            std::fs::remove_file(t.0.join("hosts")).unwrap();
            std::os::unix::fs::symlink(t.0.join("real"), t.0.join("hosts")).unwrap();
            let net = net_with(NameResolution::StaticHosts);
            let e =
                inject_service_hosts(&net, &t.0, Path::new("hosts"), [("a", ip(2))]).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(std::fs::read_to_string(t.0.join("real")).unwrap(), "y\n");
        }
    }

    /// TASK-146.2 のテスト用一時ディレクトリ（`resolv.conf` 用）。
    struct DnsDir(std::path::PathBuf);
    impl DnsDir {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("fc-static-dns-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self) -> std::path::PathBuf {
            self.0.join("resolv.conf")
        }
        fn entries(&self) -> usize {
            std::fs::read_dir(&self.0).unwrap().count()
        }
    }
    impl Drop for DnsDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    const EXPECTED_PERSIST: crate::add_host_dns::resolv_conf::PersistGuarantee =
        crate::add_host_dns::resolv_conf::PersistGuarantee::Durable;
    #[cfg(not(unix))]
    const EXPECTED_PERSIST: crate::add_host_dns::resolv_conf::PersistGuarantee =
        crate::add_host_dns::resolv_conf::PersistGuarantee::ContentOnly;

    const HDR: &str = "# Generated by fandhe-container (NET-12)\n";

    /// NET-8・TASK-146.2: 検証済みの値が入力順に `nameserver` として書かれ、既存ファイルは置換される。
    /// 不正入力のテストは TASK-185.5 / TASK-186 のケース（`net12_cases_tests`）を再利用し、ここでは新設しない。
    #[test]
    fn net8_static_dns_writes_nameservers() {
        let d = DnsDir::new("write");
        std::fs::write(d.file(), "old\n").unwrap();
        let net = net_with(NameResolution::StaticHosts);
        let out = apply_static_dns(
            &net,
            &["192.0.2.53", "2001:0db8::0053"],
            &d.file(),
            &NoopNetOpRecorder,
        )
        .unwrap();
        assert_eq!(
            out,
            StaticDnsOutcome::Applied(DnsApplyOutcome::Written {
                count: 2,
                persistence: EXPECTED_PERSIST
            })
        );
        assert_eq!(
            std::fs::read_to_string(d.file()).unwrap(),
            format!("{HDR}nameserver 192.0.2.53\nnameserver 2001:db8::53\n")
        );
        assert_eq!(d.entries(), 1);
    }

    /// NET-8: 軽量運用では loopback も受理する（NET-8 に追加制限は無い。到達性は #337）。
    #[test]
    fn net8_static_dns_accepts_loopback() {
        let d = DnsDir::new("loopback");
        let net = net_with(NameResolution::StaticHosts);
        apply_static_dns(&net, &["127.0.0.1", "::1"], &d.file(), &NoopNetOpRecorder).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.file()).unwrap(),
            format!("{HDR}nameserver 127.0.0.1\nnameserver ::1\n")
        );
    }

    /// NET-8・NET-12: DNS ヘルパー方式では何もせず、ファイルにも計測にも触れない。
    #[test]
    fn net8_static_dns_dns_helper_not_applicable() {
        let d = DnsDir::new("helper");
        std::fs::write(d.file(), "nameserver 10.89.0.1\n").unwrap();
        let net = net_with(NameResolution::DnsHelper);
        let rec = Collect::default();
        let out = apply_static_dns(&net, &["192.0.2.53"], &d.file(), &rec).unwrap();
        assert_eq!(out, StaticDnsOutcome::NotApplicable);
        assert_eq!(
            std::fs::read_to_string(d.file()).unwrap(),
            "nameserver 10.89.0.1\n"
        );
        assert_eq!(d.entries(), 1);
        assert!(rec.kinds().is_empty());
    }

    /// NET-8: `--dns` 未指定ならファイルを作らず変えない。
    #[test]
    fn net8_static_dns_empty_is_not_requested() {
        let d = DnsDir::new("empty");
        let net = net_with(NameResolution::StaticHosts);
        let out = apply_static_dns(&net, &[], &d.file(), &NoopNetOpRecorder).unwrap();
        assert_eq!(
            out,
            StaticDnsOutcome::Applied(DnsApplyOutcome::NotRequested)
        );
        assert_eq!(d.entries(), 0);
    }

    /// REPAIR-4: 成功時に `DnsResolvConfWrite` が 1 件だけ記録される。
    #[test]
    fn repair4_static_dns_records_once() {
        let d = DnsDir::new("record");
        let net = net_with(NameResolution::StaticHosts);
        let rec = Collect::default();
        apply_static_dns(&net, &["192.0.2.53"], &d.file(), &rec).unwrap();
        assert_eq!(
            rec.kinds(),
            vec![(NetOpKind::DnsResolvConfWrite, NetOpOutcome::Success)]
        );
    }
}
