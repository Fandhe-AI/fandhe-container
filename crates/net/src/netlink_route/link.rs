//! `RTM_NEWLINK` による bridge / veth ペアの作成メッセージ組み立て（TASK-136.3.1・#845・NET-11・MS-8）。
//!
//! `struct ifinfomsg` と `IFLA_*` 属性を `crate::netlink::NlMsgBuilder` で組み立てるだけの OS 非依存
//! モジュールで、ソケットも `unsafe` も持たない。呼び出し元（`NetlinkRouteSocket::create_link` /
//! `set_link`。Linux のみ。#846 TASK-136.3.2）は
//! `NetlinkRouteSocket::request(req.msg_type(), req.flags(), timeout, |b| req.encode(b))` の
//! `build` クロージャから [`LinkCreate::encode`] / [`LinkSet::encode`] を呼ぶ。
//! `NLM_F_REQUEST | NLM_F_ACK` は `request` が付与するため `flags()` には含めない。
//!
//! # ワイヤーレイアウト
//!
//! 文字列属性はすべて NUL 終端付き（libnl の `nla_put_string` と同じ）。
//!
//! ```text
//! bridge:
//!   nlmsghdr(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
//!   ifinfomsg(16B, すべて 0)
//!   IFLA_IFNAME = "br0\0"
//!   IFLA_LINKINFO (nested)
//!     IFLA_INFO_KIND = "bridge\0"
//!
//! veth:
//!   nlmsghdr / ifinfomsg / IFLA_IFNAME = "veth0\0"
//!   IFLA_LINKINFO (nested)
//!     IFLA_INFO_KIND = "veth\0"
//!     IFLA_INFO_DATA (nested)
//!       VETH_INFO_PEER (nested)
//!         ifinfomsg(16B, すべて 0)   <- peer 側は 2 つ目の ifinfomsg で始まる
//!         IFLA_IFNAME = "veth1\0"
//!
//! RTM_SETLINK（netns 移動）:
//!   nlmsghdr(RTM_SETLINK, flags = 0)
//!   ifinfomsg(index = ifindex か 0, flags = 0, change = 0)   <- 値入りフィールドはネイティブ順
//!   [IFLA_IFNAME = "veth0\0"]                                 <- 名前で指定するときだけ
//!   IFLA_NET_NS_PID = u32  または  IFLA_NET_NS_FD = u32
//!
//! RTM_SETLINK（up）:
//!   ifinfomsg(index, flags = IFF_UP, change = IFF_UP) + [IFLA_IFNAME]
//!
//! RTM_SETLINK（bridge へ接続。TASK-139.2.1）:
//!   ifinfomsg(index, flags = 0, change = 0) + [IFLA_IFNAME] + IFLA_MASTER = u32（bridge の ifindex）
//! ```
//!
//! # netns 移動と up の順序（カーネル挙動）
//!
//! 移動したデバイスは元の netns から消え、移動先では down になる。up は移動先 netns の中に
//! netlink ソケットを持つプロセスが別の `RTM_SETLINK` として送る（移動元のソケットからは届かない）。
//! bridge は `NETIF_F_NETNS_LOCAL` のため netns 間を移動できない（移動先 netns の中で作る）。
//!
//! # 信頼境界
//!
//! インターフェース名は [`IfName`] でカーネルの `dev_valid_name` 相当（1〜15 バイト・`.` / `..` 不可・
//! `/`・`:`・空白・NUL 不可）を満たすことを検証してからワイヤーに載せる（REPAIR-2）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - down 操作、MTU・MAC 等の追加属性、bridge のオプション（`IFLA_BR_*`）。
//!   bridge への接続（`IFLA_MASTER`）は `LinkSet::set_master`（TASK-139.2.1）、`RTM_DELLINK` は
//!   `LinkDelete` で実装済み（TASK-139.1）。改名（`IFLA_IFNAME`）は `LinkSet::rename`（RTM_SETLINK。
//!   ifindex 指定・down のうちに netns 内のソケットから送る。#3061）
//! - netns を作る・開く API（実機テストは外部コマンド `unshare(1)` と `/proc/<pid>/ns/net` を使う）

use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, BorrowedFd};

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLM_F_CREATE, NLM_F_ECHO, NLM_F_EXCL, NlMsgBuilder};
use crate::netlink_route::IfIndex;

/// リンクの新規作成（`linux/rtnetlink.h`）。
pub const RTM_NEWLINK: u16 = 16;
/// リンクの削除（`linux/rtnetlink.h`）。
pub const RTM_DELLINK: u16 = 17;
/// リンクの取得（`linux/rtnetlink.h`）。
pub const RTM_GETLINK: u16 = 18;
/// リンクの設定変更（`linux/rtnetlink.h`）。
pub const RTM_SETLINK: u16 = 19;
/// アドレスファミリ未指定（`linux/socket.h`）。
pub const AF_UNSPEC: u8 = 0;
/// `struct ifinfomsg` のバイト長（`linux/rtnetlink.h`）。
pub const IFINFOMSG_LEN: usize = 16;
/// インターフェース名属性（`linux/if_link.h`）。
pub const IFLA_IFNAME: u16 = 3;
/// インターフェースの別名属性（`linux/if_link.h` の `IFLA_IFALIAS`）。`RTM_SETLINK` で付けた所有トークンを
/// 後から読み戻して、同名の別 link に差し替わっていないかを確認するために使う（TASK-139.1）。
pub const IFLA_IFALIAS: u16 = 20;
/// 別名の最大長（NUL を含まない。`IFALIASZ` = 256 から NUL 分を引いた値）。
/// （出典: `include/uapi/linux/if.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で `IFALIASZ` = 256 を確認。libc 0.2.189 に無い）
pub const IFALIAS_MAX_LEN: usize = 255;
/// 移動先 netns を PID で指定する属性（`linux/if_link.h`）。
pub const IFLA_NET_NS_PID: u16 = 19;
/// 移動先 netns を ns ファイルの fd で指定する属性（`linux/if_link.h`）。
pub const IFLA_NET_NS_FD: u16 = 28;
/// リンクを up にするフラグ（`linux/if.h` の `IFF_UP`）。
pub const IFF_UP: u32 = 0x1;
/// 所属先の master（bridge）の ifindex を指す属性（`linux/if_link.h` の `IFLA_MASTER`。u32）。
pub const IFLA_MASTER: u16 = 10;
/// veth の peer の ifindex を指す属性（`linux/if_link.h` の `IFLA_LINK`。u32）。veth の
/// `ndo_get_iflink` は peer の ifindex を返すため、作成通知から peer 側の ifindex を取るのに使う
/// （Issue #3205・NET-1）。
pub const IFLA_LINK: u16 = 5;
/// `IFLA_LINK` が別 netns の link を指すときに付く netns ID の属性（`linux/if_link.h`）。作成通知に
/// 付いていれば `IFLA_LINK` の ifindex は別 netns のものになるため、拒否する（Issue #3205）。
pub const IFLA_LINK_NETNSID: u16 = 37;
/// リンク種別情報のネスト属性（`linux/if_link.h`）。
pub const IFLA_LINKINFO: u16 = 18;
/// リンク種別名（`bridge`・`veth` 等。`linux/if_link.h`）。
pub const IFLA_INFO_KIND: u16 = 1;
/// リンク種別固有データのネスト属性（`linux/if_link.h`）。
pub const IFLA_INFO_DATA: u16 = 2;
/// veth の peer 側を指定するネスト属性（`linux/veth.h`）。
/// （出典: `include/uapi/linux/veth.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const VETH_INFO_PEER: u16 = 1;
/// インターフェース名の最大長（NUL を含む。`linux/if.h`）。
pub const IFNAMSIZ: usize = 16;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 検証済みのインターフェース名（REPAIR-2: 不正な名前を表現できない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfName(String);

impl IfName {
    /// カーネルの `dev_valid_name` に合わせて検証する。違反は `InvalidArgument`（入力は載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(invalid("interface name length must be 1 to 15 bytes"));
        }
        if name == "." || name == ".." {
            return Err(invalid("interface name must not be . or .."));
        }
        if name
            .chars()
            .any(|c| c == '/' || c == ':' || c == '\0' || c.is_whitespace())
        {
            return Err(invalid("interface name contains a forbidden character"));
        }
        Ok(Self(name.to_owned()))
    }

    /// 名前を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// NUL 終端付きのワイヤー表現（最大 16 バイト）。
    fn to_nul_terminated(&self) -> Vec<u8> {
        nul_terminated(self.0.as_bytes())
    }
}

fn nul_terminated(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    v
}

/// 作成時の `ifinfomsg`（family = `AF_UNSPEC`、type・index・flags・change はすべて 0）。
///
/// レイアウトは `family:u8 | pad:u8 | type:u16 | index:i32 | flags:u32 | change:u32`。
/// 全フィールドが 0 のため、バイトオーダーの差は生じない。
fn ifinfomsg_for_create() -> [u8; IFINFOMSG_LEN] {
    [AF_UNSPEC; IFINFOMSG_LEN]
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Bridge { name: IfName },
    Veth { name: IfName, peer: IfName },
}

/// `RTM_NEWLINK` によるリンク作成要求（bridge / veth ペア）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCreate {
    kind: Kind,
    echo: bool,
}

impl LinkCreate {
    /// bridge を 1 本作る要求。
    ///
    /// 作成要求には `IFLA_IFALIAS`（所有トークン）を載せない。カーネルは作成時の
    /// `IFLA_IFALIAS` を黙って捨てる（torvalds/linux v7.0 の `net/core/rtnetlink.c` で `IFLA_IFALIAS` を
    /// 処理するのは `do_setlink` の `netif_set_alias` だけで、作成経路の `rtnl_newlink_create`・
    /// `rtnl_create_link` は読まない。Issue #1925）。所有は作成の ACK 後に [`LinkSet::set_alias`] で付ける。
    pub fn bridge(name: IfName) -> Self {
        Self {
            kind: Kind::Bridge { name },
            echo: false,
        }
    }

    /// 作成要求に `NLM_F_ECHO` を付け、カーネルが返す作成通知（`RTM_NEWLINK`）を `NetlinkReply::messages`
    /// に集める指定にする（Issue #1972・#3205・NET-1）。bridge と veth のどちらにも使える。
    ///
    /// 呼び出し元は通知を bridge なら [`decode_created_link`]、veth なら [`decode_created_veth`] で検証して
    /// 作成した link 自身の ifindex を得る（veth の peer は同じ通知の `IFLA_LINK` から取る）。名前での
    /// 引き直しをなくし、所有トークンを付ける相手を「自分が作った link」に固定するのが目的。
    /// 通知を返すのは Linux v6.2 以降（`rtnl_configure_link` が portid・`nlh` を受けて `NLM_F_ECHO` を
    /// 守る）。それより前のカーネルでは ACK だけが返るため、呼び出し側は通知なしを戻し経路で扱うこと。
    #[must_use]
    pub fn with_echo(mut self) -> Self {
        self.echo = true;
        self
    }

    /// veth ペア（`name` と `peer`）を作る要求。同名は `InvalidArgument`（fail-closed）。
    pub fn veth(name: IfName, peer: IfName) -> Result<Self, NetError> {
        if name == peer {
            return Err(invalid("veth name and peer name must differ"));
        }
        Ok(Self {
            kind: Kind::Veth { name, peer },
            echo: false,
        })
    }

    /// `nlmsg_type`（常に `RTM_NEWLINK`）。
    pub fn msg_type(&self) -> u16 {
        RTM_NEWLINK
    }

    /// `nlmsg_flags`（`NLM_F_CREATE | NLM_F_EXCL`。[`with_echo`](Self::with_echo) のときだけ `NLM_F_ECHO` も付く。
    /// REQUEST / ACK は `request` が付与する）。
    pub fn flags(&self) -> u16 {
        let base = NLM_F_CREATE | NLM_F_EXCL;
        if self.echo { base | NLM_F_ECHO } else { base }
    }

    /// nlmsghdr の後ろに続く `ifinfomsg` と属性を `b` へ書き込む。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let (name, kind, peer) = match &self.kind {
            Kind::Bridge { name } => (name, "bridge", None),
            Kind::Veth { name, peer } => (name, "veth", Some(peer)),
        };
        b.put_fixed(&ifinfomsg_for_create())?;
        b.put_attr(IFLA_IFNAME, &name.to_nul_terminated())?;
        b.put_nested(IFLA_LINKINFO, |b| {
            b.put_attr(IFLA_INFO_KIND, &nul_terminated(kind.as_bytes()))?;
            if let Some(peer) = peer {
                b.put_nested(IFLA_INFO_DATA, |b| {
                    b.put_nested(VETH_INFO_PEER, |b| {
                        b.put_fixed(&ifinfomsg_for_create())?;
                        b.put_attr(IFLA_IFNAME, &peer.to_nul_terminated())
                    })
                })?;
            }
            Ok(())
        })
    }
}

/// 値を指定した `ifinfomsg`。値入りフィールドはネイティブバイトオーダー（`to_ne_bytes`）。
fn ifinfomsg(index: i32, flags: u32, change: u32) -> [u8; IFINFOMSG_LEN] {
    let mut m = [AF_UNSPEC; IFINFOMSG_LEN];
    if let Some(d) = m.get_mut(4..8) {
        d.copy_from_slice(&index.to_ne_bytes());
    }
    if let Some(d) = m.get_mut(8..12) {
        d.copy_from_slice(&flags.to_ne_bytes());
    }
    if let Some(d) = m.get_mut(12..16) {
        d.copy_from_slice(&change.to_ne_bytes());
    }
    m
}

/// 検証済みの ifindex（正の値のみ。REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkIndex(i32);

impl LinkIndex {
    /// 1 以上を受け付ける。0 以下は `InvalidArgument`。
    pub fn new(index: i32) -> Result<Self, NetError> {
        if index <= 0 {
            return Err(invalid("link index must be positive"));
        }
        Ok(Self(index))
    }

    /// ifindex の値。
    pub fn get(self) -> i32 {
        self.0
    }
}

/// リンクの指定方法。`Name` は `ifi_index = 0` + `IFLA_IFNAME` でカーネルが引く。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRef {
    /// ifindex で指定する（`IFLA_IFNAME` は付けない）。
    Index(LinkIndex),
    /// 名前で指定する。
    Name(IfName),
}

/// 検証済みの PID（`1..=i32::MAX`）。呼び出し側の pid namespace で解釈される。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsPid(u32);

impl NetnsPid {
    /// 範囲外（0・`i32::MAX` 超）は `InvalidArgument`。
    pub fn new(pid: u32) -> Result<Self, NetError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(invalid("netns pid must be in 1..=i32::MAX"));
        }
        Ok(Self(pid))
    }

    /// PID の値。
    pub fn get(self) -> u32 {
        self.0
    }
}

/// netns を指す ns ファイル（`/proc/<pid>/ns/net` 等）の fd。借用の寿命の間だけ開いていればよい
/// （`request` は ACK まで同期で待つため）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsFd<'a> {
    raw: u32,
    _borrow: PhantomData<&'a ()>,
}

impl<'a> NetnsFd<'a> {
    /// 借用した fd から作る。負の fd は `InvalidArgument`。
    #[cfg(unix)]
    pub fn new(fd: BorrowedFd<'a>) -> Result<Self, NetError> {
        let raw =
            u32::try_from(fd.as_raw_fd()).map_err(|_| invalid("netns fd must not be negative"))?;
        Ok(Self {
            raw,
            _borrow: PhantomData,
        })
    }

    /// fd 番号。
    pub fn raw(&self) -> u32 {
        self.raw
    }

    #[cfg(test)]
    pub(crate) fn from_raw_for_test(raw: u32) -> Self {
        Self {
            raw,
            _borrow: PhantomData,
        }
    }
}

/// 移動先 netns の指定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsTarget<'a> {
    /// PID 指定（`IFLA_NET_NS_PID`）。
    Pid(NetnsPid),
    /// ns fd 指定（`IFLA_NET_NS_FD`）。
    Fd(NetnsFd<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetKind<'a> {
    MoveToNetns {
        link: LinkRef,
        target: NetnsTarget<'a>,
    },
    Up {
        link: LinkRef,
    },
    SetMaster {
        link: LinkRef,
        master: IfIndex,
    },
    SetAlias {
        link: LinkRef,
        alias: &'a str,
    },
    Rename {
        link: LinkIndex,
        name: IfName,
    },
}

/// `RTM_SETLINK` によるリンク設定要求（netns 移動・up）。
///
/// 送信は `NetlinkRouteSocket::set_link`（Linux のみ）。netns 移動後の up は移動先 netns の
/// ソケットから送ること（モジュール doc 参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSet<'a>(SetKind<'a>);

impl<'a> LinkSet<'a> {
    /// リンクを `target` の netns へ移動する要求。
    pub fn move_to_netns(link: LinkRef, target: NetnsTarget<'a>) -> Self {
        Self(SetKind::MoveToNetns { link, target })
    }

    /// リンクを up にする要求（`IFF_UP` のみ変更する）。
    pub fn up(link: LinkRef) -> Self {
        Self(SetKind::Up { link })
    }

    /// リンクを `master`（bridge の ifindex）へ接続する要求（`IFLA_MASTER`。TASK-139.2.1・NET-1）。
    /// `ifinfomsg` の flags / change は 0 で、up / down は変えない。
    pub fn set_master(link: LinkRef, master: IfIndex) -> Self {
        Self(SetKind::SetMaster { link, master })
    }

    /// リンクに `IFLA_IFALIAS`（所有トークン）を設定する要求（TASK-139.4・#317・NET-1）。カーネルは
    /// 作成時の `IFLA_IFALIAS` を反映しないため（[`LinkCreate::bridge`]）、bridge・veth とも作成の ACK 後に
    /// ifindex 指定でこの要求を送って所有を刻む。トークンは 1〜255 バイトの可視 ASCII のみ（NUL・空白・
    /// 制御文字は不可）で、違反は `InvalidArgument`。
    pub fn set_alias(link: LinkRef, alias: &'a str) -> Result<Self, NetError> {
        if alias.is_empty() || alias.len() > IFALIAS_MAX_LEN {
            return Err(invalid("link alias length must be 1 to 255 bytes"));
        }
        if !alias.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(invalid("link alias must be visible ASCII"));
        }
        Ok(Self(SetKind::SetAlias { link, alias }))
    }

    /// リンクの名前を `new_name` へ変える要求（`IFLA_IFNAME`。attach で netns 内の peer を `eth0` へ
    /// 改名する。NET-1・#3061・D11）。
    ///
    /// 対象は必ず ifindex で指定する。`do_setlink` は `ifi_index > 0` のときだけ `IFLA_IFNAME` を改名に使い、
    /// `ifi_index = 0` では対象の検索に使うため、名前指定では新しい名前で引いて `NotFound` になる。
    /// 対象が down のうちに、そのリンクがある netns のソケットから送ること（up 中の改名は `EBUSY`）。
    pub fn rename(link: LinkIndex, new_name: IfName) -> Self {
        Self(SetKind::Rename {
            link,
            name: new_name,
        })
    }

    /// `nlmsg_type`（常に `RTM_SETLINK`）。
    pub fn msg_type(&self) -> u16 {
        RTM_SETLINK
    }

    /// `nlmsg_flags`（0。REQUEST / ACK は `request` が付与する）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nlmsghdr の後ろに続く `ifinfomsg` と属性を `b` へ書き込む。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let (link, flags, change) = match &self.0 {
            SetKind::MoveToNetns { link, .. }
            | SetKind::SetMaster { link, .. }
            | SetKind::SetAlias { link, .. } => (link.clone(), 0, 0),
            SetKind::Up { link } => (link.clone(), IFF_UP, IFF_UP),
            SetKind::Rename { link, .. } => (LinkRef::Index(*link), 0, 0),
        };
        let (index, name) = match &link {
            LinkRef::Index(i) => (i.get(), None),
            LinkRef::Name(n) => (0, Some(n)),
        };
        b.put_fixed(&ifinfomsg(index, flags, change))?;
        if let Some(n) = name {
            b.put_attr(IFLA_IFNAME, &n.to_nul_terminated())?;
        }
        if let SetKind::MoveToNetns { target, .. } = &self.0 {
            match target {
                NetnsTarget::Pid(p) => b.put_attr(IFLA_NET_NS_PID, &p.get().to_ne_bytes())?,
                NetnsTarget::Fd(f) => b.put_attr(IFLA_NET_NS_FD, &f.raw().to_ne_bytes())?,
            }
        }
        if let SetKind::SetMaster { master, .. } = &self.0 {
            b.put_attr(IFLA_MASTER, &master.get().to_ne_bytes())?;
        }
        if let SetKind::SetAlias { alias, .. } = &self.0 {
            b.put_attr(IFLA_IFALIAS, &nul_terminated(alias.as_bytes()))?;
        }
        if let SetKind::Rename { name, .. } = &self.0 {
            b.put_attr(IFLA_IFNAME, &name.to_nul_terminated())?;
        }
        Ok(())
    }
}

/// `RTM_DELLINK` によるリンク削除要求（TASK-139.1・#314。ネットワーク作成の失敗時ロールバックと、
/// ネットワーク削除 `network::delete_network`（TASK-139.4）が使う）。
///
/// `LinkRef::Name` は `ifi_index = 0` + `IFLA_IFNAME` でカーネルが引く。bridge を削除すると
/// 付与済みの address も一緒に消える。送信は `NetlinkRouteSocket::delete_link`（Linux のみ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDelete(LinkRef);

impl LinkDelete {
    /// `link` を削除する要求。
    pub fn new(link: LinkRef) -> Self {
        Self(link)
    }

    /// `nlmsg_type`（常に `RTM_DELLINK`）。
    pub fn msg_type(&self) -> u16 {
        RTM_DELLINK
    }

    /// `nlmsg_flags`（0。REQUEST / ACK は `request` が付与する）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nlmsghdr の後ろに続く `ifinfomsg` と（名前指定のときだけ）`IFLA_IFNAME` を `b` へ書き込む。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let (index, name) = match &self.0 {
            LinkRef::Index(i) => (i.get(), None),
            LinkRef::Name(n) => (0, Some(n)),
        };
        b.put_fixed(&ifinfomsg(index, 0, 0))?;
        if let Some(n) = name {
            b.put_attr(IFLA_IFNAME, &n.to_nul_terminated())?;
        }
        Ok(())
    }
}

/// `RTM_NEWLINK` 応答のペイロードから `IFLA_IFNAME` を取り出す（無ければ `None`）。
///
/// 応答はカーネル由来の外部入力として属性走査で検証する。NUL 終端を除いた部分が UTF-8 でなければ
/// `DataLoss`（Issue #1972）。`IFLA_IFNAME` が重複した応答も `DataLoss`（どちらの名前を信じるかが曖昧に
/// なるため。カーネル応答は外部入力で、`decode_table_name` と同じ扱い。NET-1・#3258）。
pub fn decode_ifinfomsg_name(payload: &[u8]) -> Result<Option<String>, NetError> {
    let attrs = payload.get(IFINFOMSG_LEN..).ok_or_else(|| {
        NetError::new(
            NetErrorCode::DataLoss,
            "link reply is shorter than ifinfomsg",
        )
    })?;
    let mut found: Option<String> = None;
    for attr in crate::netlink::AttrIter::new(attrs) {
        let attr = attr?;
        if attr.attr_type() == IFLA_IFNAME {
            if found.is_some() {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    "duplicate IFLA_IFNAME attribute",
                ));
            }
            let raw = attr.payload();
            let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            let bytes = raw.get(..end).unwrap_or_default();
            let name = std::str::from_utf8(bytes).map_err(|_| {
                NetError::new(NetErrorCode::DataLoss, "IFLA_IFNAME is not valid UTF-8")
            })?;
            found = Some(name.to_owned());
        }
    }
    Ok(found)
}

/// `NLM_F_ECHO` 付きの bridge 作成要求に対する応答メッセージ（`(nlmsg_type, payload)`）から、作成した
/// link 自身の ifindex を取り出す（Issue #1972・NET-1）。
///
/// 呼び出し元は `NetlinkReply::messages` を写して渡す。`RTM_NEWLINK` 以外の型は無視する。判定:
///
/// - `RTM_NEWLINK` が 0 件 → `Ok(None)`（echo が返らなかった。v6.2 より前のカーネルなど。呼び出し側は
///   名前で引き直す戻し経路へ移る）
/// - ちょうど 1 件で、ifindex が正・`IFLA_IFNAME` が `expected` と一致・`IFLA_IFALIAS` が無いか空 →
///   `Ok(Some(ifindex))`
/// - 2 件以上・ペイロードの破損・名前の不一致・別名あり → `DataLoss`（カーネル応答は外部入力。通知は
///   rtnl ロックの中で作られるため、食い違いは正常系では起きない。何も言わずに戻し経路へ移らない）
pub fn decode_created_link<'a>(
    messages: impl IntoIterator<Item = (u16, &'a [u8])>,
    expected: &IfName,
) -> Result<Option<IfIndex>, NetError> {
    Ok(decode_created_payload(messages, expected)?.map(|(index, _)| index))
}

/// `NLM_F_ECHO` 付きの veth 作成要求に対する作成通知から取り出した、ペアの両端の ifindex
/// （Issue #3205・NET-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedVeth {
    host: IfIndex,
    peer: IfIndex,
}

impl CreatedVeth {
    /// 主側（`IFLA_IFNAME` の host 名）の ifindex。
    pub fn host(&self) -> IfIndex {
        self.host
    }

    /// peer 側の ifindex（通知の `IFLA_LINK`）。
    pub fn peer(&self) -> IfIndex {
        self.peer
    }
}

/// `NLM_F_ECHO` 付きの veth 作成要求に対する応答メッセージから、ペアの両端の ifindex を取り出す
/// （Issue #3205・NET-1）。
///
/// echo されるのは主側（`host`）の通知 1 件だけで、peer の ifindex は同じ通知の `IFLA_LINK` に載る
/// （veth の `ndo_get_iflink` が peer の ifindex を返す）。判定は [`decode_created_link`] と同じ
/// （0 件 → `Ok(None)`。2 件以上・破損・名前不一致・別名あり → `DataLoss`）に加えて、`IFLA_LINK` が
/// 4 バイトの正の値で自分の ifindex と異なること、`IFLA_LINK_NETNSID`（peer が別 netns にいる印）が
/// 無いことを要求し、満たさなければ `DataLoss`。
pub fn decode_created_veth<'a>(
    messages: impl IntoIterator<Item = (u16, &'a [u8])>,
    host: &IfName,
) -> Result<Option<CreatedVeth>, NetError> {
    let Some((host_index, payload)) = decode_created_payload(messages, host)? else {
        return Ok(None);
    };
    let (link, has_netnsid) = decode_ifinfomsg_link(payload)?;
    if has_netnsid {
        return Err(NetError::new(
            NetErrorCode::DataLoss,
            "veth creation notification points at a peer in another netns",
        ));
    }
    let peer = link.ok_or_else(|| {
        NetError::new(
            NetErrorCode::DataLoss,
            "veth creation notification has no IFLA_LINK",
        )
    })?;
    if peer == host_index {
        return Err(NetError::new(
            NetErrorCode::DataLoss,
            "veth creation notification has the same ifindex for both ends",
        ));
    }
    Ok(Some(CreatedVeth {
        host: host_index,
        peer,
    }))
}

/// 作成通知の共通検証。`RTM_NEWLINK` がちょうど 1 件で、ifindex が正・名前が `expected` と一致・別名なし
/// のとき、その ifindex とペイロードを返す。0 件は `Ok(None)`。
fn decode_created_payload<'a>(
    messages: impl IntoIterator<Item = (u16, &'a [u8])>,
    expected: &IfName,
) -> Result<Option<(IfIndex, &'a [u8])>, NetError> {
    let mut found: Option<&[u8]> = None;
    for (msg_type, payload) in messages {
        if msg_type != RTM_NEWLINK {
            continue;
        }
        if found.replace(payload).is_some() {
            return Err(NetError::new(
                NetErrorCode::DataLoss,
                "multiple link creation notifications in echo reply",
            ));
        }
    }
    let Some(payload) = found else {
        return Ok(None);
    };
    let index = decode_ifinfomsg_index(payload).map_err(|e| {
        NetError::new(
            NetErrorCode::DataLoss,
            format!("invalid echo reply: {}", e.message()),
        )
    })?;
    if decode_ifinfomsg_name(payload)?.as_deref() != Some(expected.as_str()) {
        return Err(NetError::new(
            NetErrorCode::DataLoss,
            "link creation notification names a different link",
        ));
    }
    if decode_ifinfomsg_alias(payload)?.is_some_and(|a| !a.is_empty()) {
        return Err(NetError::new(
            NetErrorCode::DataLoss,
            "link creation notification already has an alias",
        ));
    }
    Ok(Some((index, payload)))
}

/// `RTM_NEWLINK` 応答のペイロードから `IFLA_LINK`（veth なら peer の ifindex）と、`IFLA_LINK_NETNSID` の
/// 有無を取り出す。長さが 4 バイトでない `IFLA_LINK`・0 以下の値は `DataLoss`（Issue #3205）。
fn decode_ifinfomsg_link(payload: &[u8]) -> Result<(Option<IfIndex>, bool), NetError> {
    let attrs = payload.get(IFINFOMSG_LEN..).ok_or_else(|| {
        NetError::new(
            NetErrorCode::DataLoss,
            "link reply is shorter than ifinfomsg",
        )
    })?;
    let mut link = None;
    let mut has_netnsid = false;
    for attr in crate::netlink::AttrIter::new(attrs) {
        let attr = attr?;
        if attr.attr_type() == IFLA_LINK && link.is_none() {
            let raw = <[u8; 4]>::try_from(attr.payload()).map_err(|_| {
                NetError::new(NetErrorCode::DataLoss, "IFLA_LINK has an invalid length")
            })?;
            let index = IfIndex::new(u32::from_ne_bytes(raw)).map_err(|_| {
                NetError::new(NetErrorCode::DataLoss, "IFLA_LINK is not a valid ifindex")
            })?;
            link = Some(index);
        } else if attr.attr_type() == IFLA_LINK_NETNSID {
            has_netnsid = true;
        }
    }
    Ok((link, has_netnsid))
}

/// `RTM_NEWLINK` 応答のペイロードから `IFLA_IFALIAS` を取り出す（無ければ `None`）。
///
/// 応答はカーネル由来の外部入力として属性走査で検証する。NUL 終端を除いた UTF-8 文字列のみ返し、
/// 不正な属性列は `DataLoss`。UTF-8 でない別名は「別名なし」と区別するため、置換文字入りの非空文字列
/// （`from_utf8_lossy`）で返す。所有トークン（ASCII）とは一致せず、空でもないので、呼び出し側は
/// 所有者不明として扱い、上書きも削除もしない（Issue #1925・NET-1）。
/// `IFLA_IFALIAS` が重複した応答も `DataLoss`（どの別名を所有トークンとして信じるかが曖昧になるため。
/// カーネル応答は外部入力で、`decode_ifinfomsg_name`・`decode_table_name` と同じ扱い。NET-1・REPAIR-2・#3309）。
pub fn decode_ifinfomsg_alias(payload: &[u8]) -> Result<Option<String>, NetError> {
    let attrs = payload.get(IFINFOMSG_LEN..).ok_or_else(|| {
        NetError::new(
            NetErrorCode::DataLoss,
            "link reply is shorter than ifinfomsg",
        )
    })?;
    let mut found: Option<String> = None;
    for attr in crate::netlink::AttrIter::new(attrs) {
        let attr = attr?;
        if attr.attr_type() == IFLA_IFALIAS {
            if found.is_some() {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    "duplicate IFLA_IFALIAS attribute",
                ));
            }
            let raw = attr.payload();
            let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            let bytes = raw.get(..end).unwrap_or_default();
            found = Some(String::from_utf8_lossy(bytes).into_owned());
        }
    }
    Ok(found)
}

/// `RTM_NEWLINK` 応答のペイロードから `IFLA_MASTER`（所属先 bridge の ifindex）を取り出す（無ければ `None`）。
///
/// 応答はカーネル由来の外部入力として属性走査で検証する。長さが 4 バイトでない属性・0 以下の値は
/// `DataLoss`（TASK-139.4・#317）。
pub fn decode_ifinfomsg_master(payload: &[u8]) -> Result<Option<IfIndex>, NetError> {
    let attrs = payload.get(IFINFOMSG_LEN..).ok_or_else(|| {
        NetError::new(
            NetErrorCode::DataLoss,
            "link reply is shorter than ifinfomsg",
        )
    })?;
    for attr in crate::netlink::AttrIter::new(attrs) {
        let attr = attr?;
        if attr.attr_type() == IFLA_MASTER {
            let raw = <[u8; 4]>::try_from(attr.payload()).map_err(|_| {
                NetError::new(NetErrorCode::DataLoss, "IFLA_MASTER has an invalid length")
            })?;
            let index = IfIndex::new(u32::from_ne_bytes(raw)).map_err(|_| {
                NetError::new(NetErrorCode::DataLoss, "IFLA_MASTER is not a valid ifindex")
            })?;
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// `RTM_NEWLINK` 応答（`RTM_GETLINK` の返答）のペイロードから ifindex を取り出す。
///
/// 応答はカーネル由来の外部入力として扱い、添字アクセスを使わず長さ・値を検証する。
/// 短い payload は `DataLoss`、ifindex が 0 以下は `Internal`。
pub fn decode_ifinfomsg_index(payload: &[u8]) -> Result<IfIndex, NetError> {
    // ifinfomsg 全体（IFINFOMSG_LEN バイト）に満たない応答は、index が読めても破損とみなす。
    let raw = payload
        .get(..IFINFOMSG_LEN)
        .and_then(|full| full.get(4..8))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .ok_or_else(|| {
            NetError::new(
                NetErrorCode::DataLoss,
                "link reply is shorter than ifinfomsg",
            )
        })?;
    let index = i32::from_ne_bytes(raw);
    u32::try_from(index)
        .ok()
        .and_then(|i| IfIndex::new(i).ok())
        .ok_or_else(|| {
            NetError::new(
                NetErrorCode::Internal,
                "link reply has a non-positive index",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{AttrIter, NLA_F_NESTED, NLM_F_ACK, NLM_F_REQUEST, NlMsgIter};

    fn build(req: &LinkCreate) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), 0x1234, 0);
        req.encode(&mut b).unwrap();
        b.finish().unwrap()
    }

    fn link_payload(index: i32, name: Option<&[u8]>, alias: Option<&[u8]>) -> Vec<u8> {
        link_payload_ext(index, name, alias, &[])
    }

    /// `extra` は `(属性型, ペイロード)` を追加する（`IFLA_LINK`・`IFLA_LINK_NETNSID` 用）。
    fn link_payload_ext(
        index: i32,
        name: Option<&[u8]>,
        alias: Option<&[u8]>,
        extra: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(RTM_NEWLINK, 0, 1, 0);
        b.put_fixed(&ifinfomsg(index, 0, 0)).unwrap();
        if let Some(n) = name {
            b.put_attr(IFLA_IFNAME, n).unwrap();
        }
        if let Some(a) = alias {
            b.put_attr(IFLA_IFALIAS, a).unwrap();
        }
        for (t, p) in extra {
            b.put_attr(*t, p).unwrap();
        }
        let data = b.finish().unwrap();
        let msg = crate::netlink::NlMsgIter::new(&data)
            .next()
            .unwrap()
            .unwrap();
        msg.payload().to_vec()
    }

    fn name(s: &str) -> IfName {
        IfName::new(s).unwrap()
    }

    /// TASK-139.1: 名前指定の RTM_DELLINK は ifindex 0 + IFLA_IFNAME（NUL 終端）。
    #[test]
    fn task139_1_link_delete_by_name_bytes() {
        let req = LinkDelete::new(LinkRef::Name(name("br0")));
        assert_eq!(req.msg_type(), 17);
        assert_eq!(req.flags(), 0);
        let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), 7, 0);
        req.encode(&mut b).unwrap();
        let data = b.finish().unwrap();
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        assert_eq!(msg.header().msg_type(), 17);
        assert_eq!(msg.payload().get(..IFINFOMSG_LEN).unwrap(), &[0u8; 16]);
        let attrs: Vec<_> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap())
            .collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
        assert_eq!(attrs[0].payload(), b"br0\0");
    }

    /// TASK-139.1: index 指定の RTM_DELLINK は ifindex を持ち属性を付けない。
    #[test]
    fn task139_1_link_delete_by_index_bytes() {
        let req = LinkDelete::new(LinkRef::Index(LinkIndex::new(5).unwrap()));
        let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), 7, 0);
        req.encode(&mut b).unwrap();
        let data = b.finish().unwrap();
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        assert_eq!(msg.payload().len(), IFINFOMSG_LEN);
        assert_eq!(msg.payload().get(4..8).unwrap(), &5i32.to_ne_bytes());
    }

    /// TASK-139.1: 応答の ifindex 解釈（正常・短い・0・負）。
    #[test]
    fn task139_1_decode_ifinfomsg_index() {
        let mut p = [0u8; 16];
        p[4..8].copy_from_slice(&3i32.to_ne_bytes());
        assert_eq!(decode_ifinfomsg_index(&p).unwrap().get(), 3);
        assert_eq!(
            decode_ifinfomsg_index(&p[..7]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            decode_ifinfomsg_index(&p[..IFINFOMSG_LEN - 1])
                .unwrap_err()
                .code(),
            NetErrorCode::DataLoss
        );
        p[4..8].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(
            decode_ifinfomsg_index(&p).unwrap_err().code(),
            NetErrorCode::Internal
        );
        p[4..8].copy_from_slice(&(-1i32).to_ne_bytes());
        assert_eq!(
            decode_ifinfomsg_index(&p).unwrap_err().code(),
            NetErrorCode::Internal
        );
    }

    /// NET-11: bridge 作成は IFLA_IFNAME と IFLA_LINKINFO(KIND=bridge) だけを持つ。
    #[test]
    fn net11_bridge_create_has_ifname_and_linkinfo_kind_bridge() {
        let data = build(&LinkCreate::bridge(name("br0")));
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        let h = msg.header();
        assert_eq!(h.msg_type(), 16);
        assert_eq!(h.flags(), NLM_F_CREATE | NLM_F_EXCL);
        assert_eq!(msg.payload().get(..IFINFOMSG_LEN).unwrap(), &[0u8; 16]);
        let attrs: Vec<_> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap())
            .collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
        assert_eq!(attrs[0].payload(), b"br0\0");
        assert_eq!(attrs[1].attr_type(), IFLA_LINKINFO);
        assert!(attrs[1].is_nested());
        let kids: Vec<_> = attrs[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].attr_type(), IFLA_INFO_KIND);
        assert_eq!(kids[0].payload(), b"bridge\0");
    }

    /// Issue #1925: 非 UTF-8 の別名は「別名なし」ではなく非空の別名として復号する（NET-1）。
    #[test]
    fn net1_non_utf8_alias_is_not_decoded_as_absent() {
        let mut payload = vec![0u8; IFINFOMSG_LEN];
        let attr_len: u16 = 4 + 3;
        payload.extend_from_slice(&attr_len.to_ne_bytes());
        payload.extend_from_slice(&IFLA_IFALIAS.to_ne_bytes());
        payload.extend_from_slice(&[0xff, 0xfe, 0x00]);
        payload.push(0); // 4 バイト境界への padding
        let alias = decode_ifinfomsg_alias(&payload).unwrap().unwrap();
        assert_eq!(alias, "\u{fffd}\u{fffd}");
    }

    /// Issue #1925: bridge の作成要求は `IFLA_IFALIAS` を載せない（カーネルは作成時の別名を捨てるため）。
    /// 別名の応答側の復号は読み戻しで使うので維持する。
    #[test]
    fn net11_bridge_create_has_no_alias_attr() {
        let data = build(&LinkCreate::bridge(name("br0")));
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        let types: Vec<u16> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap().attr_type())
            .collect();
        assert_eq!(types, [IFLA_IFNAME, IFLA_LINKINFO]);
        assert_eq!(decode_ifinfomsg_alias(msg.payload()).unwrap(), None);
        assert_eq!(
            decode_ifinfomsg_alias(&[0u8; 4]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
    }

    /// TASK-139.4: 不正な別名は InvalidArgument（RTM_SETLINK 側の検証）。
    #[test]
    fn net11_alias_validation() {
        let link = || LinkRef::Index(LinkIndex::new(3).unwrap());
        for bad in [
            "".to_owned(),
            "a b".to_owned(),
            "a\0b".to_owned(),
            "x".repeat(256),
        ] {
            assert_eq!(
                LinkSet::set_alias(link(), &bad).unwrap_err().code(),
                NetErrorCode::InvalidArgument
            );
        }
        assert!(LinkSet::set_alias(link(), &"x".repeat(255)).is_ok());
    }

    /// NET-11: メッセージ全体のバイト列を期待値と完全一致で比べる。
    #[test]
    fn net11_bridge_create_golden_bytes() {
        let data = build(&LinkCreate::bridge(name("br0")));
        let mut e = Vec::new();
        // nlmsghdr: len = 16 + 16 + 8 (IFNAME) + 16 (LINKINFO: 4 + 11 + 1 pad) = 56
        e.extend_from_slice(&56u32.to_ne_bytes());
        e.extend_from_slice(&16u16.to_ne_bytes());
        e.extend_from_slice(&0x0600u16.to_ne_bytes());
        e.extend_from_slice(&0x1234u32.to_ne_bytes());
        e.extend_from_slice(&0u32.to_ne_bytes());
        e.extend_from_slice(&[0u8; 16]);
        e.extend_from_slice(&8u16.to_ne_bytes());
        e.extend_from_slice(&3u16.to_ne_bytes());
        e.extend_from_slice(b"br0\0");
        e.extend_from_slice(&16u16.to_ne_bytes());
        e.extend_from_slice(&(18u16 | NLA_F_NESTED).to_ne_bytes());
        e.extend_from_slice(&11u16.to_ne_bytes());
        e.extend_from_slice(&1u16.to_ne_bytes());
        e.extend_from_slice(b"bridge\0");
        e.push(0);
        assert_eq!(data, e);
    }

    /// NET-11: veth は INFO_DATA の中に VETH_INFO_PEER(ifinfomsg + IFNAME) を持つ。
    #[test]
    fn net11_veth_create_has_peer_in_info_data() {
        let data = build(&LinkCreate::veth(name("veth0"), name("veth1")).unwrap());
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        let attrs: Vec<_> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap())
            .collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
        assert_eq!(attrs[0].payload(), b"veth0\0");
        let info: Vec<_> = attrs[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].attr_type(), IFLA_INFO_KIND);
        assert_eq!(info[0].payload(), b"veth\0");
        assert_eq!(info[1].attr_type(), IFLA_INFO_DATA);
        assert!(info[1].is_nested());
        let data_kids: Vec<_> = info[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(data_kids.len(), 1);
        assert_eq!(data_kids[0].attr_type(), VETH_INFO_PEER);
        assert!(data_kids[0].is_nested());
        let peer = data_kids[0].payload();
        assert_eq!(peer.get(..IFINFOMSG_LEN).unwrap(), &[0u8; 16]);
        let rest = peer.get(IFINFOMSG_LEN..).unwrap();
        let a: Vec<_> = AttrIter::new(rest).map(|a| a.unwrap()).collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].attr_type(), IFLA_IFNAME);
        assert_eq!(a[0].payload(), b"veth1\0");
    }

    /// NET-11・REPAIR-2: 不正な名前を拒否し、境界値は受理する。
    #[test]
    fn net11_ifname_rejects_invalid() {
        for bad in [
            "",
            "0123456789abcdef",
            ".",
            "..",
            "a/b",
            "a:b",
            "a b",
            "a\0b",
            "a\u{3000}b",
            "a\tb",
        ] {
            let e = IfName::new(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad:?}");
        }
        assert_eq!(IfName::new("0123456789abcde").unwrap().as_str().len(), 15);
        assert_eq!(IfName::new("eth0").unwrap().as_str(), "eth0");
    }

    /// NET-11・REPAIR-2: ワイヤー表現は NUL 終端付きで最大 16 バイト。
    #[test]
    fn net11_ifname_wire_bytes_nul_terminated() {
        let w = name("0123456789abcde").to_nul_terminated();
        assert_eq!(w.len(), 16);
        assert_eq!(w.last(), Some(&0));
    }

    /// NET-11: 同名 veth は送る前に拒否する。
    #[test]
    fn net11_veth_rejects_same_peer_name() {
        let e = LinkCreate::veth(name("v0"), name("v0")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-11: flags は CREATE|EXCL のみ（REQUEST / ACK は request が付与）。
    #[test]
    fn net11_link_create_flags_exclude_request_ack() {
        let f = LinkCreate::bridge(name("br0")).flags();
        assert_eq!(f, 0x0600);
        assert_eq!(f & (NLM_F_REQUEST | NLM_F_ACK), 0);
    }

    fn build_set(req: &LinkSet<'_>) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), 0x1234, 0);
        req.encode(&mut b).unwrap();
        b.finish().unwrap()
    }

    fn set_attrs(data: &[u8]) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
        let mut it = NlMsgIter::new(data);
        let msg = it.next().unwrap().unwrap();
        let ifi = msg.payload().get(..IFINFOMSG_LEN).unwrap().to_vec();
        let attrs = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| {
                let a = a.unwrap();
                (a.attr_type(), a.payload().to_vec())
            })
            .collect();
        (ifi, attrs)
    }

    /// NET-11: netns 移動(PID 指定)のメッセージ全体を期待バイト列と完全一致で比べる。
    #[test]
    fn net11_setlink_move_by_pid_golden_bytes() {
        let req = LinkSet::move_to_netns(
            LinkRef::Name(name("veth1")),
            NetnsTarget::Pid(NetnsPid::new(4242).unwrap()),
        );
        let data = build_set(&req);
        let mut e = Vec::new();
        // len = 16 + 16 + 12 (IFNAME: 4 + 6 + 2 pad) + 8 (NET_NS_PID) = 52
        e.extend_from_slice(&52u32.to_ne_bytes());
        e.extend_from_slice(&19u16.to_ne_bytes());
        e.extend_from_slice(&0u16.to_ne_bytes());
        e.extend_from_slice(&0x1234u32.to_ne_bytes());
        e.extend_from_slice(&0u32.to_ne_bytes());
        e.extend_from_slice(&[0u8; 16]);
        e.extend_from_slice(&10u16.to_ne_bytes());
        e.extend_from_slice(&3u16.to_ne_bytes());
        e.extend_from_slice(b"veth1\0");
        e.extend_from_slice(&[0, 0]);
        e.extend_from_slice(&8u16.to_ne_bytes());
        e.extend_from_slice(&19u16.to_ne_bytes());
        e.extend_from_slice(&4242u32.to_ne_bytes());
        assert_eq!(data, e);
    }

    /// NET-11: FD 指定は IFLA_NET_NS_FD(28) を持ち、IFLA_NET_NS_PID を持たない。
    #[test]
    fn net11_setlink_move_by_fd_has_net_ns_fd_attr() {
        let req = LinkSet::move_to_netns(
            LinkRef::Name(name("veth1")),
            NetnsTarget::Fd(NetnsFd::from_raw_for_test(7)),
        );
        let (_, attrs) = set_attrs(&build_set(&req));
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], (IFLA_IFNAME, b"veth1\0".to_vec()));
        assert_eq!(attrs[1], (28, 7u32.to_ne_bytes().to_vec()));
        assert!(attrs.iter().all(|(t, _)| *t != IFLA_NET_NS_PID));
    }

    /// NET-11: ifindex 指定は ifi_index に入り IFLA_IFNAME を付けない。
    #[test]
    fn net11_setlink_move_by_index_sets_ifi_index_without_ifname() {
        let req = LinkSet::move_to_netns(
            LinkRef::Index(LinkIndex::new(5).unwrap()),
            NetnsTarget::Pid(NetnsPid::new(1).unwrap()),
        );
        let (ifi, attrs) = set_attrs(&build_set(&req));
        assert_eq!(ifi.get(4..8).unwrap(), &5i32.to_ne_bytes());
        assert_eq!(ifi.get(8..16).unwrap(), &[0u8; 8]);
        assert_eq!(attrs, vec![(19, 1u32.to_ne_bytes().to_vec())]);
    }

    /// NET-1・TASK-139.4: RTM_NEWLINK 応答の IFLA_MASTER を復号する。無ければ None、壊れた長さ・0 は DataLoss。
    #[test]
    fn net1_decode_master() {
        let mut p = vec![0u8; IFINFOMSG_LEN];
        assert_eq!(decode_ifinfomsg_master(&p).unwrap(), None);
        p.extend_from_slice(&8u16.to_ne_bytes());
        p.extend_from_slice(&10u16.to_ne_bytes());
        p.extend_from_slice(&7u32.to_ne_bytes());
        assert_eq!(
            decode_ifinfomsg_master(&p).unwrap(),
            Some(IfIndex::new(7).unwrap())
        );
        let mut zero = vec![0u8; IFINFOMSG_LEN];
        zero.extend_from_slice(&8u16.to_ne_bytes());
        zero.extend_from_slice(&10u16.to_ne_bytes());
        zero.extend_from_slice(&0u32.to_ne_bytes());
        assert_eq!(
            decode_ifinfomsg_master(&zero).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            decode_ifinfomsg_master(&[0u8; 3]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
    }

    /// NET-1・TASK-139.2.1: bridge 接続は ifi_index にポートの ifindex、IFLA_MASTER(10) に bridge の
    /// ifindex（u32 ネイティブ順）を載せ、flags / change は 0 のまま。メッセージ全体を完全一致で照合する。
    #[test]
    fn net1_setlink_set_master_golden_bytes() {
        let req = LinkSet::set_master(
            LinkRef::Index(LinkIndex::new(5).unwrap()),
            IfIndex::new(9).unwrap(),
        );
        let data = build_set(&req);
        let mut e = Vec::new();
        e.extend_from_slice(&40u32.to_ne_bytes()); // nlmsg_len = 16 + 16 + 8
        e.extend_from_slice(&RTM_SETLINK.to_ne_bytes());
        e.extend_from_slice(&0u16.to_ne_bytes()); // flags
        e.extend_from_slice(&0x1234u32.to_ne_bytes()); // seq
        e.extend_from_slice(&0u32.to_ne_bytes()); // pid
        e.extend_from_slice(&[0, 0]); // family + pad
        e.extend_from_slice(&0u16.to_ne_bytes()); // type
        e.extend_from_slice(&5i32.to_ne_bytes()); // ifi_index
        e.extend_from_slice(&0u32.to_ne_bytes()); // flags
        e.extend_from_slice(&0u32.to_ne_bytes()); // change
        e.extend_from_slice(&8u16.to_ne_bytes()); // rta_len
        e.extend_from_slice(&10u16.to_ne_bytes()); // IFLA_MASTER
        e.extend_from_slice(&9u32.to_ne_bytes());
        assert_eq!(data, e);
    }

    /// NET-1・TASK-139.2.1: 名前指定の bridge 接続は IFLA_IFNAME の後ろに IFLA_MASTER が続く。
    #[test]
    fn net1_setlink_set_master_by_name_orders_attrs() {
        let req = LinkSet::set_master(LinkRef::Name(name("veth0")), IfIndex::new(3).unwrap());
        let (ifi, attrs) = set_attrs(&build_set(&req));
        assert_eq!(ifi.get(4..16).unwrap(), &[0u8; 12]);
        assert_eq!(
            attrs,
            vec![
                (IFLA_IFNAME, b"veth0\0".to_vec()),
                (IFLA_MASTER, 3u32.to_ne_bytes().to_vec())
            ]
        );
    }

    /// NET-1・#3061: 改名は ifindex 指定で、IFLA_IFNAME が新しい名前の 1 件だけ載る（名前指定にしない）。
    #[test]
    fn net1_setlink_rename_encodes_single_ifname_by_index() {
        let req = LinkSet::rename(LinkIndex::new(5).unwrap(), name("eth0"));
        assert_eq!(req.msg_type(), RTM_SETLINK);
        assert_eq!(req.flags(), 0);
        let (ifi, attrs) = set_attrs(&build_set(&req));
        assert_eq!(ifi.get(4..8).unwrap(), &5i32.to_ne_bytes());
        assert_eq!(ifi.get(8..16).unwrap(), &[0u8; 8]);
        assert_eq!(attrs, vec![(IFLA_IFNAME, b"eth0\0".to_vec())]);
    }

    /// NET-1・TASK-139.4: veth の所有トークンは ifindex 指定の SETLINK で IFLA_IFALIAS に NUL 終端で載る。
    #[test]
    fn net1_setlink_set_alias_encodes_nul_terminated_alias() {
        let req = LinkSet::set_alias(
            LinkRef::Index(LinkIndex::new(5).unwrap()),
            "fandhe-net:web/ep/c1",
        )
        .unwrap();
        let (ifi, attrs) = set_attrs(&build_set(&req));
        assert_eq!(ifi.get(4..8).unwrap(), &5i32.to_ne_bytes());
        assert_eq!(
            attrs,
            vec![(IFLA_IFALIAS, b"fandhe-net:web/ep/c1\0".to_vec())]
        );
    }

    /// NET-1・TASK-139.4: 空・長すぎる・可視 ASCII 以外の別名は InvalidArgument。
    #[test]
    fn net1_setlink_set_alias_rejects_invalid_alias() {
        let link = || LinkRef::Name(name("veth0"));
        let long = "a".repeat(IFALIAS_MAX_LEN + 1);
        for bad in ["", "a b", "a\0b", long.as_str()] {
            let e = LinkSet::set_alias(link(), bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad:?}");
        }
    }

    /// NET-11: up は flags と change の両方に IFF_UP だけを立てる。
    #[test]
    fn net11_setlink_up_sets_iff_up_flag_and_change_mask() {
        let (ifi, attrs) = set_attrs(&build_set(&LinkSet::up(LinkRef::Name(name("br0")))));
        assert_eq!(ifi.get(4..8).unwrap(), &0i32.to_ne_bytes());
        assert_eq!(ifi.get(8..12).unwrap(), &1u32.to_ne_bytes());
        assert_eq!(ifi.get(12..16).unwrap(), &1u32.to_ne_bytes());
        assert_eq!(attrs, vec![(IFLA_IFNAME, b"br0\0".to_vec())]);
    }

    /// NET-11: up のメッセージ全体を期待バイト列と完全一致で比べる。
    #[test]
    fn net11_setlink_up_golden_bytes() {
        let data = build_set(&LinkSet::up(LinkRef::Index(LinkIndex::new(3).unwrap())));
        let mut e = Vec::new();
        e.extend_from_slice(&32u32.to_ne_bytes());
        e.extend_from_slice(&19u16.to_ne_bytes());
        e.extend_from_slice(&0u16.to_ne_bytes());
        e.extend_from_slice(&0x1234u32.to_ne_bytes());
        e.extend_from_slice(&0u32.to_ne_bytes());
        e.extend_from_slice(&[0, 0, 0, 0]);
        e.extend_from_slice(&3i32.to_ne_bytes());
        e.extend_from_slice(&1u32.to_ne_bytes());
        e.extend_from_slice(&1u32.to_ne_bytes());
        assert_eq!(data, e);
    }

    /// NET-11: RTM_SETLINK の flags は 0（CREATE / EXCL / REQUEST / ACK を含まない）。
    #[test]
    fn net11_setlink_flags_exclude_create_excl_request_ack() {
        let req = LinkSet::up(LinkRef::Name(name("br0")));
        assert_eq!(req.msg_type(), 19);
        assert_eq!(req.flags(), 0);
    }

    /// NET-11・REPAIR-2: PID と ifindex の範囲外を拒否し境界値は受理する。
    #[test]
    fn net11_netns_pid_and_link_index_validation() {
        for bad in [0u32, i32::MAX as u32 + 1, u32::MAX] {
            let e = NetnsPid::new(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
        assert_eq!(NetnsPid::new(1).unwrap().get(), 1);
        assert_eq!(
            NetnsPid::new(i32::MAX as u32).unwrap().get(),
            i32::MAX as u32
        );
        for bad in [0i32, -1, i32::MIN] {
            let e = LinkIndex::new(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
        assert_eq!(LinkIndex::new(1).unwrap().get(), 1);
        assert_eq!(LinkIndex::new(i32::MAX).unwrap().get(), i32::MAX);
    }

    /// NET-11: 借用した fd から作った NetnsFd の fd 番号は元の fd と一致する。
    #[cfg(unix)]
    #[test]
    fn net11_netns_fd_from_borrowed_fd() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let f = std::fs::File::open(env!("CARGO_MANIFEST_DIR").to_owned() + "/Cargo.toml").unwrap();
        let nfd = NetnsFd::new(f.as_fd()).unwrap();
        assert_eq!(nfd.raw(), f.as_raw_fd() as u32);
    }
    /// NET-1・Issue #1972: echo 指定は flags に NLM_F_ECHO だけを足し、既定（bridge・veth）は変えない。
    #[test]
    fn net1_with_echo_adds_only_echo_flag() {
        let echo = LinkCreate::bridge(name("br0")).with_echo();
        assert_eq!(echo.flags(), 0x0608);
        // veth（Issue #3205）も同じ flags になる。
        let veth_echo = LinkCreate::veth(name("fcvh0"), name("fcvp0"))
            .unwrap()
            .with_echo();
        assert_eq!(veth_echo.flags(), 0x0608);
        assert_eq!(echo.flags() & (NLM_F_REQUEST | NLM_F_ACK), 0);
        assert_eq!(LinkCreate::bridge(name("br0")).flags(), 0x0600);
        assert_eq!(
            LinkCreate::veth(name("a"), name("b")).unwrap().flags(),
            0x0600
        );
        // 属性構造は echo の有無で変わらない。
        let a = build(&echo);
        let mut b = build(&LinkCreate::bridge(name("br0")));
        // flags は nlmsghdr の 6..8 バイト目。差を揃えれば完全一致する。
        b.splice(6..8, a.get(6..8).unwrap().iter().copied());
        assert_eq!(a, b);
    }

    /// NET-1・Issue #1972: 作成通知の検証（0 件・正常・異常各種）。
    #[test]
    fn net1_decode_created_link_cases() {
        let br = name("fcbr0");
        let ok = link_payload(7, Some(b"fcbr0\0"), None);
        let empty_alias = link_payload(7, Some(b"fcbr0\0"), Some(b"\0"));
        let none: [(u16, &[u8]); 0] = [];
        assert_eq!(decode_created_link(none, &br).unwrap(), None);
        // RTM_NEWLINK 以外は無視する。
        assert_eq!(
            decode_created_link([(RTM_DELLINK, ok.as_slice())], &br).unwrap(),
            None
        );
        for p in [&ok, &empty_alias] {
            let got = decode_created_link([(RTM_NEWLINK, p.as_slice())], &br).unwrap();
            assert_eq!(got.map(|i| i.get()), Some(7));
        }
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("name mismatch", link_payload(7, Some(b"other\0"), None)),
            ("no name", link_payload(7, None, None)),
            ("alias", link_payload(7, Some(b"fcbr0\0"), Some(b"tok\0"))),
            ("index 0", link_payload(0, Some(b"fcbr0\0"), None)),
            ("non utf8", link_payload(7, Some(b"\xff\xfe\0"), None)),
            ("short", vec![0u8; 8]),
        ];
        for (label, p) in &bad {
            let e = decode_created_link([(RTM_NEWLINK, p.as_slice())], &br).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::DataLoss, "{label}");
        }
        let e = decode_created_link(
            [(RTM_NEWLINK, ok.as_slice()), (RTM_NEWLINK, ok.as_slice())],
            &br,
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::DataLoss);
    }

    /// NET-1・Issue #3205: veth の作成通知から host / peer の ifindex を取り出す。
    #[test]
    fn net1_decode_created_veth_cases() {
        let host = name("fcvh0");
        let link = |v: u32| v.to_ne_bytes();
        let ok = link_payload_ext(7, Some(b"fcvh0\0"), None, &[(IFLA_LINK, &link(8))]);
        let none: [(u16, &[u8]); 0] = [];
        assert_eq!(decode_created_veth(none, &host).unwrap(), None);
        assert_eq!(
            decode_created_veth([(RTM_DELLINK, ok.as_slice())], &host).unwrap(),
            None
        );
        let got = decode_created_veth([(RTM_NEWLINK, ok.as_slice())], &host)
            .unwrap()
            .unwrap();
        assert_eq!((got.host().get(), got.peer().get()), (7, 8));
        let bad: Vec<(&str, Vec<u8>)> = vec![
            (
                "name mismatch",
                link_payload_ext(7, Some(b"other\0"), None, &[(IFLA_LINK, &link(8))]),
            ),
            (
                "no name",
                link_payload_ext(7, None, None, &[(IFLA_LINK, &link(8))]),
            ),
            (
                "alias",
                link_payload_ext(
                    7,
                    Some(b"fcvh0\0"),
                    Some(b"tok\0"),
                    &[(IFLA_LINK, &link(8))],
                ),
            ),
            (
                "index 0",
                link_payload_ext(0, Some(b"fcvh0\0"), None, &[(IFLA_LINK, &link(8))]),
            ),
            ("no IFLA_LINK", link_payload(7, Some(b"fcvh0\0"), None)),
            (
                "IFLA_LINK length 3",
                link_payload_ext(7, Some(b"fcvh0\0"), None, &[(IFLA_LINK, &[1, 0, 0])]),
            ),
            (
                "IFLA_LINK zero",
                link_payload_ext(7, Some(b"fcvh0\0"), None, &[(IFLA_LINK, &link(0))]),
            ),
            (
                "IFLA_LINK same as self",
                link_payload_ext(7, Some(b"fcvh0\0"), None, &[(IFLA_LINK, &link(7))]),
            ),
            (
                "IFLA_LINK_NETNSID",
                link_payload_ext(
                    7,
                    Some(b"fcvh0\0"),
                    None,
                    &[(IFLA_LINK, &link(8)), (IFLA_LINK_NETNSID, &link(1))],
                ),
            ),
            ("short", vec![0u8; 8]),
        ];
        for (label, p) in &bad {
            let e = decode_created_veth([(RTM_NEWLINK, p.as_slice())], &host).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::DataLoss, "{label}");
        }
        let e = decode_created_veth(
            [(RTM_NEWLINK, ok.as_slice()), (RTM_NEWLINK, ok.as_slice())],
            &host,
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::DataLoss);
    }

    /// NET-1・#3258: `IFLA_IFNAME` が重複した応答は、値が同じでも違っても `DataLoss`（カーネル応答は外部入力）。
    #[test]
    fn net1_decode_ifinfomsg_name_rejects_duplicate() {
        for dup in [&b"br1\0"[..], &b"br0\0"[..]] {
            let p = link_payload_ext(3, Some(b"br0\0"), None, &[(IFLA_IFNAME, dup)]);
            let e = decode_ifinfomsg_name(&p).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::DataLoss);
            assert_eq!(e.message(), "duplicate IFLA_IFNAME attribute");
            let msgs = [(RTM_NEWLINK, p.as_slice())];
            assert_eq!(
                decode_created_link(msgs, &name("br0")).unwrap_err().code(),
                NetErrorCode::DataLoss
            );
        }
        let p = link_payload_ext(3, Some(b"br0\0"), None, &[]);
        assert_eq!(decode_ifinfomsg_name(&p).unwrap().as_deref(), Some("br0"));
    }

    /// NET-1・REPAIR-2・#3309: `IFLA_IFALIAS` が重複した応答は、値が同じでも違っても `DataLoss`。
    #[test]
    fn net1_decode_ifinfomsg_alias_rejects_duplicate() {
        let tok = &b"fandhe-net:web:tok\0"[..];
        for (first, second) in [
            (tok, tok),
            (tok, &b"other\0"[..]),
            (&b"\0"[..], tok),
            (tok, &b"\0"[..]),
            (&b"\0"[..], &b"\0"[..]),
        ] {
            let p = link_payload_ext(3, Some(b"br0\0"), Some(first), &[(IFLA_IFALIAS, second)]);
            let e = decode_ifinfomsg_alias(&p).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::DataLoss);
            assert_eq!(e.message(), "duplicate IFLA_IFALIAS attribute");
            let msgs = [(RTM_NEWLINK, p.as_slice())];
            assert_eq!(
                decode_created_link(msgs, &name("br0")).unwrap_err().code(),
                NetErrorCode::DataLoss
            );
        }
        let p = link_payload_ext(3, Some(b"br0\0"), Some(tok), &[]);
        assert_eq!(
            decode_ifinfomsg_alias(&p).unwrap().as_deref(),
            Some("fandhe-net:web:tok")
        );
        let p = link_payload_ext(3, Some(b"br0\0"), None, &[]);
        assert_eq!(decode_ifinfomsg_alias(&p).unwrap(), None);
    }

    /// NET-1・Issue #1972: `IFLA_IFNAME` の取り出し（NUL 終端・無し・非 UTF-8）。
    #[test]
    fn net1_decode_ifinfomsg_name_cases() {
        let p = link_payload(3, Some(b"br0\0"), None);
        assert_eq!(decode_ifinfomsg_name(&p).unwrap().as_deref(), Some("br0"));
        let p = link_payload(3, None, None);
        assert_eq!(decode_ifinfomsg_name(&p).unwrap(), None);
        let p = link_payload(3, Some(b"\xff\0"), None);
        assert_eq!(
            decode_ifinfomsg_name(&p).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
    }
}

/// rtnetlink の link 系定数の `libc` 照合（NET-1・MVM-4・REPAIR-12。#3102。方式は `docs/design/ffi-libc-check.md`）。
///
/// 宣言と同じく Linux の試験ビルド限定。`libc` に無い `VETH_INFO_PEER`・`IFALIAS_MAX_LEN` は定義の横に
/// 出典を書いた。
///
/// 対象外（黙って省かない）: link 名・別名の検証の方針値以外に、uapi でない定数は無い。
#[cfg(all(test, target_os = "linux"))]
mod libc_abi {
    use core::ffi::{c_int, c_ushort};
    use core::mem::size_of;

    const _: () = {
        libc_const_eq!(RTM_NEWLINK, u16, u16);
        libc_const_eq!(RTM_DELLINK, u16, u16);
        libc_const_eq!(RTM_GETLINK, u16, u16);
        libc_const_eq!(RTM_SETLINK, u16, u16);
        libc_const_eq!(AF_UNSPEC, u8, c_int);
        libc_const_eq!(IFLA_IFNAME, u16, c_ushort);
        libc_const_eq!(IFLA_IFALIAS, u16, c_ushort);
        libc_const_eq!(IFLA_NET_NS_PID, u16, c_ushort);
        libc_const_eq!(IFLA_NET_NS_FD, u16, c_ushort);
        libc_const_eq!(IFLA_MASTER, u16, c_ushort);
        libc_const_eq!(IFLA_LINK, u16, c_ushort);
        libc_const_eq!(IFLA_LINK_NETNSID, u16, c_ushort);
        libc_const_eq!(IFLA_LINKINFO, u16, c_ushort);
        libc_const_eq!(IFLA_INFO_KIND, u16, c_ushort);
        libc_const_eq!(IFLA_INFO_DATA, u16, c_ushort);
        libc_const_eq!(IFF_UP, u32, c_int);
        libc_const_eq!(IFNAMSIZ, usize, libc::size_t);
        assert!(super::IFINFOMSG_LEN == size_of::<libc::ifinfomsg>());
    };
}
