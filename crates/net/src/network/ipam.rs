//! 1 ネットワーク内の静的 IPv4 アドレス払い出し（TASK-139.2.2・#848・NET-1・MS-8）。
//!
//! 親モジュール `network` のコンテナ接続処理（`attach_container`）が、netns 移動の後に
//! [`StaticIpam::allocate`] を呼んでコンテナ 1 つ分のアドレスを決める。常駐デーモンを持たない
//! 方針（CORE-1）のため、状態は呼び出し側が所有するメモリ上の値で、永続化と再起動後の復元
//! （[`StaticIpam::reserve`] で払い出し済みを戻す）は呼び出し側の責務。状態レジストリによる
//! 永続化は未実装で担当 Issue 未確定（REPAIR-3）。IPv6 は未対応（IPv4 のみ）。
//!
//! 接続処理は払い出しと同時に、その endpoint の netns pin 置き場（パスとディレクトリの識別子）を
//! `NetnsDirRecord` として記録する。ネットワーク削除（`network::delete_network`。TASK-139.4・NET-1）は、
//! 渡されていない endpoint の pin の残存を、呼び出し側が渡すパスではなくこの記録の置き場で確認する
//! （別の空ディレクトリを渡されて残存 pin を見落とし、生存 netns のアドレスを再払い出ししないため）。
//! [`StaticIpam::reserve`] で復元した払い出しには記録が無く、削除はその pin を判定不能として
//! アドレスを保持する（fail-closed。記録の永続化は IPAM 状態の永続化とともに未実装）。
//!
//! # 払い出し方針
//!
//! サブネットは gateway の [`IpPrefix`]（prefix 1〜30）から求め、`network+1 ..= broadcast-1` のうち
//! gateway を除いた最小の空きアドレスを払い出す（決定的）。network / broadcast / gateway は
//! 払い出さない。計算量は払い出し件数に比例し、prefix 依存の事前確保はしない。

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IpPrefix;

use super::{CreatedNetwork, EndpointId, NetworkName};

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 接続時の netns pin 置き場の記録（TASK-139.4・NET-1）。
///
/// `path` は接続時に渡した置き場の絶対パス、`dir_id` は接続処理が検査して開いたディレクトリの
/// 識別子 (st_dev, st_ino)。削除時は同じパスを開き直して識別子を照合し、一致しなければ
/// （差し替え・移動・消失）何も変更せずに拒否する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetnsDirRecord {
    path: PathBuf,
    dir_id: (u64, u64),
}

impl NetnsDirRecord {
    pub(crate) fn new(path: PathBuf, dir_id: (u64, u64)) -> Self {
        Self { path, dir_id }
    }

    /// 置き場のパス（接続時に渡したもの）。
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// 接続時に開いた置き場の識別子 (st_dev, st_ino)。読むのは Linux の削除実装とテストだけ。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn dir_id(&self) -> (u64, u64) {
        self.dir_id
    }
}

/// 1 ネットワーク分の静的 IPAM（OS 非依存）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticIpam {
    network: NetworkName,
    gateway: IpPrefix,
    /// ネットワークアドレス。
    base: u32,
    /// ブロードキャストアドレス。
    broadcast: u32,
    by_addr: BTreeMap<u32, EndpointId>,
    by_endpoint: HashMap<EndpointId, u32>,
    /// 接続処理が払い出しと同時に記録した netns pin 置き場（`reserve` で復元した払い出しには無い）。
    netns_dirs: HashMap<EndpointId, NetnsDirRecord>,
}

impl StaticIpam {
    /// gateway からサブネットを求めて作る。IPv4 以外・prefix 1〜30 以外・gateway が
    /// network / broadcast アドレスの場合は `InvalidArgument`。
    pub fn new(network: &NetworkName, gateway: IpPrefix) -> Result<Self, NetError> {
        let IpAddr::V4(gw) = gateway.addr() else {
            return Err(invalid("ipam supports ipv4 only"));
        };
        let len = u32::from(gateway.prefix_len());
        if !(1..=30).contains(&len) {
            return Err(invalid("ipam prefix length must be 1 to 30"));
        }
        let mask = u32::MAX
            .checked_shl(32 - len)
            .ok_or_else(|| invalid("ipam prefix length must be 1 to 30"))?;
        let gw = u32::from(gw);
        let base = gw & mask;
        let broadcast = base | !mask;
        if gw == base || gw == broadcast {
            return Err(invalid(
                "gateway must not be the network or broadcast address",
            ));
        }
        Ok(Self {
            network: network.clone(),
            gateway,
            base,
            broadcast,
            by_addr: BTreeMap::new(),
            by_endpoint: HashMap::new(),
            netns_dirs: HashMap::new(),
        })
    }

    /// 作成済みネットワークの IPAM を作る（[`StaticIpam::new`] の便宜版）。
    pub fn for_network(net: &CreatedNetwork) -> Result<Self, NetError> {
        Self::new(&net.name, net.gateway)
    }

    /// 対応するネットワーク名。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// gateway（prefix 長つき）。
    pub fn gateway(&self) -> IpPrefix {
        self.gateway
    }

    /// 払い出し済みの件数。
    pub fn allocated_count(&self) -> usize {
        self.by_endpoint.len()
    }

    /// エンドポイントに払い出し済みのアドレス。
    pub fn address_of(&self, endpoint: &EndpointId) -> Option<IpPrefix> {
        self.by_endpoint
            .get(endpoint)
            .and_then(|a| self.prefixed(*a))
    }

    /// 払い出し済みのエンドポイントとアドレスを、アドレスの昇順で返す。
    ///
    /// ネットワーク削除（`network::delete_network`。TASK-139.4・NET-1）が、呼び出し側から渡されていない
    /// 生存コンテナの有無を検査するために使う。
    pub fn endpoints(&self) -> impl Iterator<Item = (&EndpointId, IpPrefix)> {
        self.by_addr
            .iter()
            .filter_map(|(&a, e)| self.prefixed(a).map(|p| (e, p)))
    }

    /// 接続時に記録した netns pin 置き場（`delete_network` が残存 pin の確認に使う）。記録が無ければ `None`。
    pub(crate) fn netns_dir_of(&self, endpoint: &EndpointId) -> Option<&NetnsDirRecord> {
        self.netns_dirs.get(endpoint)
    }

    fn gateway_u32(&self) -> u32 {
        match self.gateway.addr() {
            IpAddr::V4(a) => u32::from(a),
            IpAddr::V6(_) => 0,
        }
    }

    fn prefixed(&self, addr: u32) -> Option<IpPrefix> {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(addr)), self.gateway.prefix_len()).ok()
    }

    /// 最小の空きアドレスを払い出す。払い出し済みの ID は `AlreadyExists`、
    /// 空きがなければ `ResourceExhausted`（状態は変わらない）。
    pub fn allocate(&mut self, endpoint: &EndpointId) -> Result<IpPrefix, NetError> {
        if self.by_endpoint.contains_key(endpoint) {
            return Err(NetError::new(
                NetErrorCode::AlreadyExists,
                "endpoint already has an address",
            ));
        }
        let exhausted = || NetError::new(NetErrorCode::ResourceExhausted, "address pool exhausted");
        // BTreeMap の昇順キーを複製せず直接歩いて最初の隙間を探す。gateway は by_addr に
        // 入らないため、候補との比較で読み飛ばす（追加メモリなし）。
        let gateway = self.gateway_u32();
        let mut candidate = self.base.checked_add(1).ok_or_else(exhausted)?;
        if candidate == gateway {
            candidate = candidate.checked_add(1).ok_or_else(exhausted)?;
        }
        for (&u, _) in self.by_addr.range(candidate..) {
            if u != candidate {
                break;
            }
            candidate = candidate.checked_add(1).ok_or_else(exhausted)?;
            if candidate == gateway {
                candidate = candidate.checked_add(1).ok_or_else(exhausted)?;
            }
        }
        if candidate >= self.broadcast {
            return Err(exhausted());
        }
        let prefixed = self.prefixed(candidate).ok_or_else(exhausted)?;
        self.by_addr.insert(candidate, endpoint.clone());
        self.by_endpoint.insert(endpoint.clone(), candidate);
        Ok(prefixed)
    }

    /// [`StaticIpam::allocate`] と同じく払い出し、その endpoint の netns pin 置き場 `dir` を記録する
    /// （接続処理 `attach_container` 専用）。払い出しに失敗したら何も記録しない。
    pub(crate) fn allocate_pinned(
        &mut self,
        endpoint: &EndpointId,
        dir: NetnsDirRecord,
    ) -> Result<IpPrefix, NetError> {
        let addr = self.allocate(endpoint)?;
        self.netns_dirs.insert(endpoint.clone(), dir);
        Ok(addr)
    }

    /// 永続化済みの払い出しを復元する。サブネット外・prefix 長の不一致・network / broadcast /
    /// gateway は `InvalidArgument`、使用中のアドレスや払い出し済みの ID は `AlreadyExists`。
    ///
    /// 復元した払い出しには netns pin 置き場の記録（`NetnsDirRecord`）が付かない。`delete_network` は
    /// その endpoint の pin の残存を判定できないため、アドレスを解放せず `Unknown` で報告する（TASK-139.4）。
    pub fn reserve(&mut self, endpoint: &EndpointId, addr: IpPrefix) -> Result<(), NetError> {
        let IpAddr::V4(a) = addr.addr() else {
            return Err(invalid("ipam supports ipv4 only"));
        };
        if addr.prefix_len() != self.gateway.prefix_len() {
            return Err(invalid("prefix length does not match the network"));
        }
        let a = u32::from(a);
        if a <= self.base || a >= self.broadcast {
            return Err(invalid("address is outside the allocatable range"));
        }
        if a == self.gateway_u32() {
            return Err(invalid("address is the gateway"));
        }
        if self.by_endpoint.contains_key(endpoint) || self.by_addr.contains_key(&a) {
            return Err(NetError::new(
                NetErrorCode::AlreadyExists,
                "address or endpoint already reserved",
            ));
        }
        self.by_addr.insert(a, endpoint.clone());
        self.by_endpoint.insert(endpoint.clone(), a);
        Ok(())
    }

    /// 払い出しを解放して、解放したアドレスを返す（netns pin 置き場の記録も消す）。未払い出しの ID は `NotFound`。
    pub fn release(&mut self, endpoint: &EndpointId) -> Result<IpPrefix, NetError> {
        let a = self
            .by_endpoint
            .remove(endpoint)
            .ok_or_else(|| NetError::new(NetErrorCode::NotFound, "endpoint has no address"))?;
        self.by_addr.remove(&a);
        self.netns_dirs.remove(endpoint);
        self.prefixed(a)
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "invalid stored address"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    fn p(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn ipam(gw: [u8; 4], len: u8) -> StaticIpam {
        StaticIpam::new(&NetworkName::new("web").unwrap(), p(gw, len)).unwrap()
    }

    /// NET-1・TASK-139.4: `endpoints` は払い出し済みを、アドレスの昇順で返す。
    #[test]
    fn net1_endpoints_lists_allocations_in_address_order() {
        let mut ip = ipam([10, 0, 0, 1], 24);
        ip.reserve(&eid("b"), p([10, 0, 0, 9], 24)).unwrap();
        ip.allocate(&eid("a")).unwrap();
        let got: Vec<(String, IpPrefix)> = ip
            .endpoints()
            .map(|(e, a)| (e.as_str().to_owned(), a))
            .collect();
        assert_eq!(
            got,
            vec![
                ("a".to_owned(), p([10, 0, 0, 2], 24)),
                ("b".to_owned(), p([10, 0, 0, 9], 24)),
            ]
        );
    }

    /// NET-1・TASK-139.4: `allocate_pinned` は払い出しと同時に pin 置き場を記録し、`release` で消す。
    /// `reserve` で復元した払い出しと、失敗した払い出しには記録が無い。
    #[test]
    fn net1_allocate_pinned_records_netns_dir_until_release() {
        let mut ip = ipam([10, 0, 0, 1], 24);
        let rec = NetnsDirRecord::new(PathBuf::from("/run/fc-netns"), (8, 9));
        assert_eq!(
            ip.allocate_pinned(&eid("a"), rec.clone()).unwrap(),
            p([10, 0, 0, 2], 24)
        );
        assert_eq!(ip.netns_dir_of(&eid("a")), Some(&rec));
        assert_eq!(
            ip.netns_dir_of(&eid("a")).map(|r| (r.path(), r.dir_id())),
            Some((Path::new("/run/fc-netns"), (8, 9)))
        );
        // 払い出し済みの ID への再払い出しは失敗し、既存の記録を書き換えない。
        let other = NetnsDirRecord::new(PathBuf::from("/tmp/other"), (1, 2));
        assert_eq!(
            ip.allocate_pinned(&eid("a"), other).unwrap_err().code(),
            NetErrorCode::AlreadyExists
        );
        assert_eq!(ip.netns_dir_of(&eid("a")), Some(&rec));
        ip.reserve(&eid("b"), p([10, 0, 0, 9], 24)).unwrap();
        assert_eq!(ip.netns_dir_of(&eid("b")), None);
        assert_eq!(ip.release(&eid("a")).unwrap(), p([10, 0, 0, 2], 24));
        assert_eq!(ip.netns_dir_of(&eid("a")), None);
    }

    /// NET-1: 連続して払い出すと重複せず最小の空きから順になる。
    #[test]
    fn net1_allocates_distinct_addresses() {
        let mut m = ipam([10, 89, 0, 1], 24);
        assert_eq!(m.allocate(&eid("a")).unwrap(), p([10, 89, 0, 2], 24));
        assert_eq!(m.allocate(&eid("b")).unwrap(), p([10, 89, 0, 3], 24));
        assert_eq!(m.address_of(&eid("a")), Some(p([10, 89, 0, 2], 24)));
        assert_eq!(m.allocated_count(), 2);
    }

    /// NET-1: gateway が .1 でなくても gateway を払い出さない。
    #[test]
    fn net1_skips_gateway() {
        let mut m = ipam([10, 89, 0, 2], 24);
        assert_eq!(m.allocate(&eid("a")).unwrap(), p([10, 89, 0, 1], 24));
        assert_eq!(m.allocate(&eid("b")).unwrap(), p([10, 89, 0, 3], 24));
    }

    /// NET-1・ERR-1: /30 は 1 件だけ払い出せ、2 件目は ResourceExhausted。
    #[test]
    fn net1_pool_exhausted() {
        let mut m = ipam([10, 0, 0, 1], 30);
        assert_eq!(m.allocate(&eid("a")).unwrap(), p([10, 0, 0, 2], 30));
        let e = m.allocate(&eid("b")).unwrap_err();
        assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
        assert_eq!(e.message(), "address pool exhausted");
        assert_eq!(m.allocated_count(), 1);
    }

    /// NET-1: 解放したアドレスが再利用される。
    #[test]
    fn net1_release_reuses_lowest() {
        let mut m = ipam([10, 89, 0, 1], 24);
        m.allocate(&eid("a")).unwrap();
        m.allocate(&eid("b")).unwrap();
        assert_eq!(m.release(&eid("a")).unwrap(), p([10, 89, 0, 2], 24));
        assert_eq!(m.allocate(&eid("c")).unwrap(), p([10, 89, 0, 2], 24));
    }

    /// NET-1: 二重払い出しは ALREADY_EXISTS、未払い出しの解放は NOT_FOUND。
    #[test]
    fn net1_duplicate_and_unknown() {
        let mut m = ipam([10, 89, 0, 1], 24);
        m.allocate(&eid("a")).unwrap();
        assert_eq!(
            m.allocate(&eid("a")).unwrap_err().code().as_str(),
            "ALREADY_EXISTS"
        );
        assert_eq!(
            m.release(&eid("zz")).unwrap_err().code().as_str(),
            "NOT_FOUND"
        );
    }

    /// NET-1: reserve の正常系と異常系。
    #[test]
    fn net1_reserve() {
        let mut m = ipam([10, 89, 0, 1], 24);
        m.reserve(&eid("a"), p([10, 89, 0, 5], 24)).unwrap();
        assert_eq!(m.allocate(&eid("b")).unwrap(), p([10, 89, 0, 2], 24));
        let code = |m: &mut StaticIpam, id: &str, a: IpPrefix| {
            m.reserve(&eid(id), a).unwrap_err().code().as_str()
        };
        assert_eq!(code(&mut m, "c", p([10, 90, 0, 5], 24)), "INVALID_ARGUMENT");
        assert_eq!(code(&mut m, "c", p([10, 89, 0, 1], 24)), "INVALID_ARGUMENT");
        assert_eq!(code(&mut m, "c", p([10, 89, 0, 0], 24)), "INVALID_ARGUMENT");
        assert_eq!(
            code(&mut m, "c", p([10, 89, 0, 255], 24)),
            "INVALID_ARGUMENT"
        );
        assert_eq!(code(&mut m, "c", p([10, 89, 0, 6], 16)), "INVALID_ARGUMENT");
        assert_eq!(code(&mut m, "c", p([10, 89, 0, 5], 24)), "ALREADY_EXISTS");
        assert_eq!(code(&mut m, "a", p([10, 89, 0, 9], 24)), "ALREADY_EXISTS");
    }

    /// NET-1: new の検証。
    #[test]
    fn net1_new_validation() {
        let n = NetworkName::new("web").unwrap();
        let v6 = IpPrefix::new(IpAddr::V6("fd00::1".parse().unwrap()), 64).unwrap();
        assert_eq!(
            StaticIpam::new(&n, v6).unwrap_err().code().as_str(),
            "INVALID_ARGUMENT"
        );
        for (a, len) in [
            ([10, 0, 0, 1], 0),
            ([10, 0, 0, 1], 31),
            ([10, 0, 0, 1], 32),
            ([10, 0, 0, 0], 24),
            ([10, 0, 0, 255], 24),
        ] {
            let e = StaticIpam::new(&n, p(a, len)).unwrap_err();
            assert_eq!(e.code().as_str(), "INVALID_ARGUMENT", "{a:?}/{len}");
        }
    }

    /// NET-1: 64 件が相異なり昇順に連続する。
    #[test]
    fn net1_many_unique_and_sequential() {
        let mut m = ipam([10, 89, 0, 1], 24);
        for i in 0..64u32 {
            let got = m.allocate(&eid(&format!("c{i}"))).unwrap();
            let expect = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 89, 0, 2)) + i);
            assert_eq!(got, IpPrefix::new(IpAddr::V4(expect), 24).unwrap());
        }
        assert_eq!(m.allocated_count(), 64);
    }
}
