//! コンテナのポート公開指定（検証済みの型）と DNAT ルールの expr 列（TASK-139.3・#316・NET-1・MS-8）。
//!
//! 呼び出し元は `crate::network::ContainerAttachSpec::with_port_publishes`（外部入力である CLI / TOML /
//! CRI 由来の公開指定を型へ落とす境界）と `crate::network::attach_container`（接続の最後に
//! ネットワーク専用 nft テーブルの `prerouting` / `output` へ投入）。ルールの形は PoC-15 と
//! TASK-138.3 / 138.4 の実機試験で実証済みのものを踏襲する。
//!
//! # ルールの形
//!
//! `ip daddr == host_addr && ip protocol == {6|17} && th dport == host_port` →
//! `dnat to container_addr:container_port`。dport だけでは照合しない。`prerouting` は bridge から
//! 出ていく転送通信も通るため、dport のみだとコンテナ発の外部宛て通信を横取りしてしまう。
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - `host_addr` は明示された非 loopback の unicast アドレスに限る。`0.0.0.0/8`（`0.0.0.0` の全アドレス公開は
//!   意図しない外部公開につながる）・`127.0.0.0/8`（loopback 宛ては `route_localnet` が必要）・
//!   `224.0.0.0/4`（multicast）・`240.0.0.0/4`（予約済み・broadcast を含む）は拒否する
//! - 同一 host アドレス・ポートの競合（コンテナ間・ネットワーク間）は [`PortRegistry`] で投入前に検出して
//!   拒否する（nft は同一ルールの重複を拒否しないため、後から入れたルールが機能しない）。レジストリは
//!   呼び出し側が所有し、複数ネットワークで 1 つを共有する。デーモンレス構成で別プロセスが公開した受け口とも
//!   競合を検出するには [`PortRegistry::with_shared_file`] を使う（排他ロック付きの共有ファイル。既定の
//!   [`PortRegistry::new`] はプロセス内のみ）。再起動後の復元と孤児エントリの回収は TASK-139.4 以降（REPAIR-3）
//! - IPv4 のみ（静的 IPAM が IPv4 のみのため）。公開の個別解除はルールハンドルの取得経路が無く未対応
//!   （ネットワーク削除時にテーブルごと解放する。TASK-139.4）

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{EndpointId, NetworkName};
use crate::error::{NetError, NetErrorCode};
use crate::nftables_rules::{
    NftCmp, NftDataValue, NftImmediate, NftNat, NftPayload, NftRegister, NftRuleExprs,
};

/// 1 コンテナあたりの公開指定の上限（バッチ長の上限 1 MiB に対して十分小さい値）。
pub const MAX_PORT_PUBLISHES: usize = 64;

// 呼び出し元（`network.rs` の Linux 限定 `publish_ports`）以外の OS では未使用になる。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const IPPROTO_TCP: u8 = 6;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const IPPROTO_UDP: u8 = 17;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 公開先として許可する IPv4 アドレスか。`0.0.0.0/8`（"this network"・未指定を含む）・`127.0.0.0/8`
/// （loopback）・`224.0.0.0/4`（multicast）・`240.0.0.0/4`（予約済み。`255.255.255.255` の broadcast を含む）
/// を拒否する。いずれも host のローカルアドレスにならず、DNAT ルールが意図せず他の通信に一致する
/// （または一致しない）ため。それ以外は許可する（`169.254.0.0/16` や TEST-NET も unicast として扱う）。
fn is_publishable_unicast(addr: Ipv4Addr) -> bool {
    let first = addr.octets()[0];
    !(first == 0 || first == 127 || first >= 224)
}

/// 公開するトランスポートプロトコル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortProtocol {
    /// TCP（IP プロトコル番号 6）。
    Tcp,
    /// UDP（IP プロトコル番号 17）。
    Udp,
}

impl PortProtocol {
    /// IP ヘッダーのプロトコル番号。
    // Linux 限定の呼び出し元のみが使う。他 OS の非 test ビルドでは未使用（単体テストは全 OS で使う）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

/// ポート公開 1 件（host の `host_addr:host_port` 宛ての通信をコンテナの `container_port` へ DNAT する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortPublish {
    protocol: PortProtocol,
    host_addr: Ipv4Addr,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
}

impl PortPublish {
    /// 検証して作る。ポート 0、および `host_addr` が公開先として許可する範囲（モジュール doc「契約」）の
    /// 外なら `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(
        protocol: PortProtocol,
        host_addr: Ipv4Addr,
        host_port: u16,
        container_port: u16,
    ) -> Result<Self, NetError> {
        if !is_publishable_unicast(host_addr) {
            return Err(invalid(
                "host address must be an explicit unicast non-loopback address",
            ));
        }
        let host_port = NonZeroU16::new(host_port).ok_or_else(|| invalid("host port is zero"))?;
        let container_port =
            NonZeroU16::new(container_port).ok_or_else(|| invalid("container port is zero"))?;
        Ok(Self {
            protocol,
            host_addr,
            host_port,
            container_port,
        })
    }

    /// プロトコル。
    pub fn protocol(&self) -> PortProtocol {
        self.protocol
    }

    /// 公開する host 側のアドレス。
    pub fn host_addr(&self) -> Ipv4Addr {
        self.host_addr
    }

    /// 公開する host 側のポート。
    pub fn host_port(&self) -> u16 {
        self.host_port.get()
    }

    /// 転送先のコンテナ側ポート。
    pub fn container_port(&self) -> u16 {
        self.container_port.get()
    }

    /// 同じ host 側の受け口（プロトコル・アドレス・ポート）かどうか。重複検出に使う。
    pub(crate) fn same_listener(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.host_addr == other.host_addr
            && self.host_port == other.host_port
    }

    /// `container` 宛ての DNAT ルールの expr 列を組み立てる（モジュール doc「ルールの形」）。
    // Linux 限定の `publish_ports` のみが使う。他 OS の非 test ビルドでは未使用。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn dnat_rule_exprs(&self, container: Ipv4Addr) -> Result<NftRuleExprs, NetError> {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let mut exprs = NftRuleExprs::new();
        exprs.push(NftPayload::ipv4_daddr(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&self.host_addr.octets())?)?.to_expr()?)?;
        exprs.push(NftPayload::ipv4_protocol(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&[self.protocol.number()])?)?.to_expr()?)?;
        exprs.push(NftPayload::transport_dport(r1)?.to_expr()?)?;
        exprs.push(
            NftCmp::eq(r1, NftDataValue::new(&self.host_port.get().to_be_bytes())?)?.to_expr()?,
        )?;
        exprs.push(NftImmediate::ipv4_addr(r1, container)?.to_expr()?)?;
        exprs.push(NftImmediate::port(r2, self.container_port.get())?.to_expr()?)?;
        exprs.push(NftNat::dnat_ipv4(r1, Some(r2))?.to_expr()?)?;
        Ok(exprs)
    }
}

/// 受け口の持ち主（ネットワークとエンドポイント）。
type ListenerOwner = (NetworkName, EndpointId);

/// 公開済みの受け口（プロトコル・host アドレス・host ポート）の予約表（NET-1・TASK-139.3・#316）。
///
/// `attach_container` が DNAT ルールを投入する前に受け口を予約し、既に誰かが公開している受け口なら
/// 接続を失敗させる。nft は同一ルールの重複を拒否せず、先に入ったルールが優先されて後のコンテナの公開が
/// 機能しないため。コンテナ間・ネットワーク間の競合を検出できるよう、呼び出し側が全ネットワークで 1 つを
/// 共有する。状態は呼び出し側が所有するメモリ上の値（常駐デーモンを持たない。CORE-1）で、永続化は
/// TASK-139.4 以降（REPAIR-3）。
///
/// # プロセス間の共有
///
/// [`PortRegistry::with_shared_file`] で作ると、予約の都度、共有ファイルを排他ロックして最新の内容を
/// 読み直し、競合検査と書き戻しを同じロックの中で行う。デーモンレス構成で別プロセスから接続した
/// コンテナとも競合を検出できる。ロックの待ちには期限を設ける（REPAIR-5）。ファイルは所有者のみ
/// 読み書き可（0600）で作り、symlink・通常ファイル以外・過大なファイル・壊れた内容は fail-closed で拒否する。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortRegistry {
    owners: HashMap<ListenerKey, ListenerOwner>,
    /// プロセス間で共有する予約ファイル（`None` ならプロセス内のみ）。
    shared: Option<PathBuf>,
}

type ListenerKey = (PortProtocol, Ipv4Addr, u16);

/// 共有ファイルの最大サイズ（無制限の読み込みを防ぐ）。
const MAX_SHARED_FILE_BYTES: u64 = 1024 * 1024;
/// 共有ファイルのロック待ちの期限。
const SHARED_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

fn shared_err(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::Internal, msg)
}

/// 共有ファイルを開いて排他ロックする（期限付き）。symlink・通常ファイル以外は拒否する。
fn open_locked(path: &std::path::Path) -> Result<File, NetError> {
    if let Ok(m) = std::fs::symlink_metadata(path)
        && !m.file_type().is_file()
    {
        return Err(shared_err("shared port registry is not a regular file"));
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .map_err(|_| shared_err("failed to open shared port registry"))?;
    let deadline = Instant::now() + SHARED_LOCK_TIMEOUT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out locking shared port registry",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(shared_err("failed to lock shared port registry"));
            }
        }
    }
}

fn parse_shared(file: &mut File) -> Result<HashMap<ListenerKey, ListenerOwner>, NetError> {
    let meta = file
        .metadata()
        .map_err(|_| shared_err("failed to stat shared port registry"))?;
    if meta.len() > MAX_SHARED_FILE_BYTES {
        return Err(shared_err("shared port registry is too large"));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|_| shared_err("failed to read shared port registry"))?;
    let corrupt = || shared_err("shared port registry is corrupt");
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut f = line.split(' ');
        let (Some(proto), Some(addr), Some(port), Some(net), Some(ep), None) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            return Err(corrupt());
        };
        let proto = match proto {
            "tcp" => PortProtocol::Tcp,
            "udp" => PortProtocol::Udp,
            _ => return Err(corrupt()),
        };
        let addr: Ipv4Addr = addr.parse().map_err(|_| corrupt())?;
        let port: u16 = port.parse().map_err(|_| corrupt())?;
        let owner = (
            NetworkName::new(net).map_err(|_| corrupt())?,
            EndpointId::new(ep).map_err(|_| corrupt())?,
        );
        map.insert((proto, addr, port), owner);
    }
    Ok(map)
}

fn write_shared(
    file: &mut File,
    map: &HashMap<ListenerKey, ListenerOwner>,
) -> Result<(), NetError> {
    let mut lines: Vec<String> = map
        .iter()
        .map(|((proto, addr, port), (n, e))| {
            let proto = match proto {
                PortProtocol::Tcp => "tcp",
                PortProtocol::Udp => "udp",
            };
            format!("{proto} {addr} {port} {} {}\n", n.as_str(), e.as_str())
        })
        .collect();
    lines.sort();
    let body = lines.concat();
    let werr = || shared_err("failed to write shared port registry");
    file.seek(SeekFrom::Start(0)).map_err(|_| werr())?;
    file.set_len(0).map_err(|_| werr())?;
    file.write_all(body.as_bytes()).map_err(|_| werr())?;
    file.sync_all().map_err(|_| werr())
}

impl PortRegistry {
    /// 空の予約表。
    pub fn new() -> Self {
        Self::default()
    }

    /// プロセス間で共有する予約ファイル `path` を使う予約表（構造体 doc「プロセス間の共有」）。
    /// ファイルが無ければ最初の予約時に作る。親ディレクトリは呼び出し側が所有者のみ書き込み可で用意すること。
    pub fn with_shared_file(path: PathBuf) -> Self {
        Self {
            owners: HashMap::new(),
            shared: Some(path),
        }
    }

    /// 予約済みの受け口の件数（共有ファイル使用時は、このプロセスが最後に読み書きした時点の件数）。
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// 予約が 1 件も無いか。
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    fn key(p: &PortPublish) -> (PortProtocol, Ipv4Addr, u16) {
        (p.protocol, p.host_addr, p.host_port.get())
    }

    /// `owner` として `ports` の受け口をすべて予約する。1 件でも既に予約済み（同じ持ち主を含む）なら
    /// 何も予約せず `AlreadyExists`（all-or-nothing）。`ports` 内の重複も `AlreadyExists`。
    pub(crate) fn reserve(
        &mut self,
        network: &NetworkName,
        endpoint: &EndpointId,
        ports: &[PortPublish],
    ) -> Result<(), NetError> {
        let conflict = || {
            NetError::new(
                NetErrorCode::AlreadyExists,
                "port listener is already published",
            )
        };
        // 共有ファイルは排他ロックの中で最新を読み直し、検査と書き戻しを同じロックで行う。
        let mut locked = match &self.shared {
            Some(path) => {
                let mut file = open_locked(path)?;
                self.owners = parse_shared(&mut file)?;
                Some(file)
            }
            None => None,
        };
        for (i, p) in ports.iter().enumerate() {
            if self.owners.contains_key(&Self::key(p))
                || ports.iter().skip(i + 1).any(|q| p.same_listener(q))
            {
                return Err(conflict());
            }
        }
        let mut next = self.owners.clone();
        for p in ports {
            next.insert(Self::key(p), (network.clone(), endpoint.clone()));
        }
        if let Some(file) = locked.as_mut() {
            write_shared(file, &next)?;
        }
        self.owners = next;
        Ok(())
    }

    /// `endpoint`（`network` 内）が持つ予約をすべて解放し、解放した件数を返す。
    ///
    /// DNAT ルールが残っている可能性がある間（結果不明のバッチ）は呼ばないこと。ネットワークの
    /// テーブルを削除して消えたことを確認した後（TASK-139.4）に呼ぶ。
    pub fn release(&mut self, network: &NetworkName, endpoint: &EndpointId) -> usize {
        let keep = |_: &ListenerKey, (n, e): &mut ListenerOwner| !(n == network && e == endpoint);
        if let Some(path) = &self.shared {
            // 共有ファイルから先に外す。失敗時は予約を残す（fail-closed。0 件を返す）。
            let Ok(mut file) = open_locked(path) else {
                return 0;
            };
            let Ok(mut map) = parse_shared(&mut file) else {
                return 0;
            };
            let before = map.len();
            map.retain(keep);
            if write_shared(&mut file, &map).is_err() {
                return 0;
            }
            let released = before - map.len();
            self.owners = map;
            return released;
        }
        let before = self.owners.len();
        self.owners.retain(keep);
        before - self.owners.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables_rules::NatType;

    fn a(x: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(x)
    }

    /// NET-1・TASK-139.3: 非 loopback の unicast は受理し、未指定・loopback・broadcast・multicast・
    /// ポート 0 は `InvalidArgument`。
    #[test]
    fn net1_port_publish_validation() {
        let ok = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8080, 80).unwrap();
        assert_eq!(ok.host_addr(), a([192, 0, 2, 10]));
        assert_eq!(ok.host_port(), 8080);
        assert_eq!(ok.container_port(), 80);
        for bad in [
            a([0, 0, 0, 0]),
            a([0, 0, 0, 1]),
            a([0, 255, 255, 255]),
            a([240, 0, 0, 1]),
            a([254, 255, 255, 255]),
            a([127, 0, 0, 1]),
            a([127, 255, 255, 254]),
            a([255, 255, 255, 255]),
            a([224, 0, 0, 1]),
        ] {
            let e = PortPublish::new(PortProtocol::Udp, bad, 8080, 80).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
        for (hp, cp) in [(0, 80), (8080, 0)] {
            let e = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), hp, cp).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    /// NET-1・TASK-139.3: expr 列の具体値（daddr・プロトコル番号・dport の big endian・転送先・nat 種別）。
    #[test]
    fn net1_dnat_exprs_have_expected_values() {
        for (proto, num) in [(PortProtocol::Tcp, 6u8), (PortProtocol::Udp, 17u8)] {
            let p = PortPublish::new(proto, a([192, 0, 2, 10]), 0x1f90, 80).unwrap();
            let exprs = p.dnat_rule_exprs(a([10, 89, 0, 2])).unwrap();
            let e = exprs.exprs();
            assert_eq!(e.len(), 9);
            let names: Vec<&str> = e.iter().map(|x| x.name().as_str()).collect();
            assert_eq!(
                names,
                [
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "immediate",
                    "immediate",
                    "nat"
                ]
            );
            assert_eq!(
                NftCmp::from_expr(&e[1]).unwrap().data().as_bytes(),
                [192, 0, 2, 10]
            );
            assert_eq!(NftCmp::from_expr(&e[3]).unwrap().data().as_bytes(), [num]);
            assert_eq!(
                NftCmp::from_expr(&e[5]).unwrap().data().as_bytes(),
                [0x1f, 0x90]
            );
            let nat = NftNat::from_expr(&e[8]).unwrap();
            assert_eq!(nat.nat_type(), NatType::Dnat);
        }
    }

    /// NET-1・TASK-139.3: 受け口の同一判定はプロトコル・アドレス・ポートの 3 つ組。
    #[test]
    fn net1_same_listener_compares_triple() {
        let t = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let u = PortPublish::new(PortProtocol::Udp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let t2 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 8080).unwrap();
        assert!(t.same_listener(&t2));
        assert!(!t.same_listener(&u));
    }

    /// NET-1・TASK-139.3: 受け口の予約は all-or-nothing で、別コンテナ・別ネットワークとの競合を拒否し、
    /// 解放後は再予約できる。
    #[test]
    fn net1_port_registry_detects_conflicts() {
        let web = NetworkName::new("web").unwrap();
        let db = NetworkName::new("db").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let p81 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 81, 80).unwrap();
        let udp80 = PortPublish::new(PortProtocol::Udp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let mut r = PortRegistry::new();
        r.reserve(&web, &c1, &[p80]).unwrap();
        // 同じネットワークの別コンテナ。p81 も予約されない（all-or-nothing）。
        let e = r.reserve(&web, &c2, &[p81, p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r.len(), 1);
        // 別ネットワークでも競合する。プロトコルが違えば別の受け口。
        assert_eq!(
            r.reserve(&db, &c2, &[p80]).unwrap_err().code(),
            NetErrorCode::AlreadyExists
        );
        r.reserve(&db, &c2, &[udp80]).unwrap();
        assert_eq!(r.len(), 2);
        // 指定内の重複。
        let e = r.reserve(&db, &c1, &[p81, p81]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r.release(&web, &c1), 1);
        r.reserve(&db, &c2, &[p80]).unwrap();
        assert_eq!(r.len(), 2);
    }

    /// NET-1・TASK-139.3: 共有ファイルの予約は別インスタンス（別プロセス相当）との競合を検出し、
    /// 解放は他方から見える。壊れた内容は fail-closed。
    #[test]
    fn net1_shared_registry_detects_cross_instance_conflicts() {
        let dir = std::env::temp_dir().join(format!("fc-portreg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ports.reg");
        let _ = std::fs::remove_file(&path);
        let web = NetworkName::new("web").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let mut r1 = PortRegistry::with_shared_file(path.clone());
        let mut r2 = PortRegistry::with_shared_file(path.clone());
        r1.reserve(&web, &c1, &[p80]).unwrap();
        let e = r2.reserve(&web, &c2, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r1.release(&web, &c1), 1);
        r2.reserve(&web, &c2, &[p80]).unwrap();
        assert_eq!(r2.len(), 1);
        std::fs::write(&path, "garbage\n").unwrap();
        let e = r1.reserve(&web, &c1, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
