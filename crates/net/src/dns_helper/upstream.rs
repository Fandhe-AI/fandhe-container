//! ユーザー定義ネットワーク上の `--dns` 上流転送先マッピングと転送処理（NET-12・TASK-185.3・#346・MS-8）。
//!
//! # 役割と関係
//! - DNS ヘルパーのあるユーザー定義ネットワーク（NET-1・NET-5）では、コンテナの `resolv.conf` の nameserver は
//!   常に DNS ヘルパー（gateway:53）のままにし、`--dns` で指定された上流サーバーはヘルパーが肩代わりして
//!   コンテナ別に転送する（NET-12）。本モジュールはその「コンテナ別の転送先マッピング」（[`DnsUpstreamMap`]）、
//!   「期限つきの転送」（[`forward_query`]）、両者を [`RegistryHandler`] と合成する [`ForwardingHandler`] を持つ
//! - 上流アドレスの入力検証は `add_host_dns::parse_ip_addr`（TASK-185.1）が済ませた `IpAddr` を受け、
//!   [`UpstreamServer::new`] が種別ポリシーを足す。`resolv.conf` への反映は TASK-185.4（#347）の責務
//! - 登録側は `network::attach_container` が返す `AttachedContainer.address`（IPv4）をキーに
//!   [`DnsUpstreamMap::set`] を呼び、切断・停止で [`DnsUpstreamMap::remove`] を呼ぶ。`serve` は
//!   `QueryHandler::respond_from` で受けた送信元 IP をキーに引く（bridge 上の直接送信なので NAT は挟まらない）
//!
//! # 判定順（ForwardingHandler）
//! 1. QCLASS=IN でレジストリにある名前: 自前応答（A は answer、それ以外は NODATA）。qtype に関わらず転送しない
//!    （サービス名の権威を保つ）
//! 2. レジストリに無く、送信元が上流マッピング登録済み: そのコンテナの上流へ転送する
//! 3. レジストリに無く、送信元が未登録: REFUSED（オープンリゾルバにしない）
//!
//! # 安全性
//! - 転送は登録済みコンテナ宛てに限る。上流は loopback・unspecified・multicast・broadcast・link-local（IPv4 169.254.0.0/16〔メタデータ系アドレスを含む〕・IPv6 fe80::/10）を拒否する。
//!   これは NET-12 に規定の無い安全側の制限である（ヘルパーはホスト側 netns で動くため、`--dns 127.0.0.53` を許すと
//!   コンテナがホストローカルの UDP:53 サービスへ到達できてしまう）。ユーザー確認事項（未承認）
//! - 上流とのやりとりは試行ごとに新しいエフェメラルポートの UDP ソケットを `connect` し（送信元ポートの乱択と
//!   他送信元の応答のカーネル側での排除）、転送用に乱択した ID・QR・Opcode・QDCOUNT・質問バイト列の一致を確認した
//!   応答だけを受理する。ヘルパーはキャッシュを持たないため偽応答が持続しない。EDNS OPT は転送せず（ARCOUNT=0）、
//!   上流が 512 バイト超で返す経路を作らない。ログ・エラーには QNAME・パケット内容を載せない
//! - 待ちはすべて期限つき（試行 [`FORWARD_ATTEMPT_TIMEOUT`]・全体 [`FORWARD_TOTAL_DEADLINE`]。REPAIR-5）。全体期限は
//!   glibc の resolver 既定タイムアウト（5 秒）より短く、コンテナが先に SERVFAIL を受け取れる
//! - 転送応答にも自前応答と同じ増幅上限（要求長 + `MAX_RESPONSE_GROWTH`）を課す。送信元 IP は bridge 内で偽装され得て
//!   UDP では宛先を認証できないため、上限を超える上流応答は TC=1 の切り詰め応答（質問のみ）に置き換える。TCP 再試行が
//!   未対応のため、上限を超える応答（複数 RR・CNAME 連鎖等）は現状解決できない（TCP 対応は後続課題）
//! - 上流応答は質問の一致に加え、後続レコード（名前・圧縮ポインタ・RDLENGTH）が末尾ちょうどまで境界内で完結することを
//!   検証し、不正な応答は破棄する
//! - `DnsUpstreamMap::set` は gateway（ヘルパー自身）を上流に指定した登録を拒否する（自己転送で serve が塞がるため）
//!
//! # 未実装（REPAIR-3）
//! - プロセス外のヘルパープロセスへ上流マッピングを登録する経路は無い（`run_dns_helper_main` は NOTIMP のまま）。
//!   [`ForwardingHandler`] は同一プロセス内の登録側（テスト・将来の組み込み）からのみ到達できる
//! - `serve` は単一スレッドのため、転送中は同じネットワークの他クエリが最大 [`FORWARD_TOTAL_DEADLINE`] 待たされる
//!   （head-of-line blocking）。並列化は後続課題
//!   （追跡 Issue は未起票。out-of-scope-tracking 規約に従いユーザー承認後に起票し、番号をここへ追記する）
//! - TCP 再試行・EDNS0・上流応答の加工（TC=1 は素通し）は未対応

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::{
    DNS_PORT, DnsHeader, DnsRegistry, FLAG_QR, FLAG_RD, FLAG_TC, HEADER_LEN, HandlerOutcome,
    MAX_DATAGRAM_LEN, MAX_NAME_LEN, MAX_REGISTRY_ENTRIES, MAX_RESPONSE_GROWTH, MsgWriter,
    QCLASS_IN, QueryHandler, RCODE_SERVFAIL, RegistryHandler, ResponseBuf, normalize_qname,
    parse_question,
};
use crate::error::{NetError, NetErrorCode};

/// コンテナ 1 つあたりの上流の最大件数（resolv.conf の MAXNS に合わせた暫定値。spec に規定なし）。
pub const MAX_UPSTREAMS_PER_CONTAINER: usize = 3;
/// 上流 1 件あたりの応答待ち期限（暫定値。spec に規定なし）。
pub const FORWARD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// 転送全体の期限（暫定値）。glibc の既定 5 秒より短くする。
pub const FORWARD_TOTAL_DEADLINE: Duration = Duration::from_millis(2500);

fn invalid(msg: &str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

fn lock_poisoned<T>(r: Result<T, std::sync::PoisonError<T>>) -> T {
    // ポイズンしても中身は単純な map で整合性は壊れないため、回復して続行する。
    r.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 上流 DNS サーバー（ポートは 53 固定。unicast の非 loopback アドレスに限る）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamServer(SocketAddr);

impl UpstreamServer {
    /// 検証して作る。IPv4 射影 IPv6 は IPv4 に正規化したうえで判定する。種別の理由は module doc の「安全性」を参照
    /// （NET-12 の規定を超える安全側の制限）。
    pub fn new(ip: IpAddr) -> Result<Self, NetError> {
        let ip = ip.to_canonical();
        let bad = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_link_local()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if bad {
            return Err(invalid(
                "upstream DNS server must be a routable unicast address (not loopback, unspecified, multicast, broadcast or link-local)",
            ));
        }
        Ok(Self(SocketAddr::new(ip, DNS_PORT)))
    }

    /// 送信先ソケットアドレス（ポート 53）。
    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }
}

/// コンテナ 1 つ分の上流リスト（固定長・`Copy`。lookup のたびにヒープ確保しない）。登録順を保つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamList {
    servers: [Option<SocketAddr>; MAX_UPSTREAMS_PER_CONTAINER],
}

impl UpstreamList {
    fn from_addrs(addrs: &[SocketAddr]) -> Option<Self> {
        if addrs.is_empty() || addrs.len() > MAX_UPSTREAMS_PER_CONTAINER {
            return None;
        }
        let mut servers = [None; MAX_UPSTREAMS_PER_CONTAINER];
        for (slot, a) in servers.iter_mut().zip(addrs) {
            *slot = Some(*a);
        }
        Some(Self { servers })
    }

    /// 登録順の上流アドレス。
    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.servers.iter().flatten().copied()
    }
}

/// [`DnsUpstreamMap::set`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamSetOutcome {
    /// 新規に登録した。
    Inserted,
    /// 同じコンテナ・同じ上流で登録済み（再起動時の冪等性）。
    Unchanged,
}

/// [`DnsUpstreamMap::remove`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamRemoveOutcome {
    /// 削除した。
    Removed,
    /// 未登録（停止処理の冪等性のためエラーにしない）。
    NotFound,
}

/// コンテナ IPv4 → 上流リストのマッピング（NET-12）。`Arc` で `serve` 側と登録側が共有する。
/// コンテナ間で上流が混ざらないよう、キーは送信元 IP のみで引く。
#[derive(Debug, Default)]
pub struct DnsUpstreamMap {
    entries: RwLock<HashMap<Ipv4Addr, UpstreamList>>,
}

impl DnsUpstreamMap {
    /// 空のマップ。
    pub fn new() -> Self {
        Self::default()
    }

    /// コンテナの上流を登録する。空・上限超過・不正アドレスは、マップを変更する前に `InvalidArgument`。
    /// `gateway` はこのネットワークの DNS ヘルパー（gateway）の IPv4 で、上流に指定されていれば拒否する。
    /// 同キー・同値は `Unchanged`、別値は上書きせず `AlreadyExists`、件数上限は `ResourceExhausted`。
    pub fn set(
        &self,
        container: Ipv4Addr,
        gateway: Ipv4Addr,
        servers: &[IpAddr],
    ) -> Result<UpstreamSetOutcome, NetError> {
        if servers.is_empty() || servers.len() > MAX_UPSTREAMS_PER_CONTAINER {
            return Err(invalid("upstream DNS server count must be between 1 and 3"));
        }
        let mut addrs =
            [SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0); MAX_UPSTREAMS_PER_CONTAINER];
        for (slot, ip) in addrs.iter_mut().zip(servers) {
            let addr = UpstreamServer::new(*ip)?.socket_addr();
            // ヘルパー自身（gateway）への転送は自己ループで serve を塞ぐため拒否する。
            if addr.ip() == IpAddr::V4(gateway) {
                return Err(invalid(
                    "upstream DNS server must not be the DNS helper's own gateway address",
                ));
            }
            *slot = addr;
        }
        let list = UpstreamList::from_addrs(addrs.get(..servers.len()).unwrap_or(&[]))
            .ok_or_else(|| invalid("upstream DNS server count must be between 1 and 3"))?;
        self.insert_list(container, list)
    }

    fn insert_list(
        &self,
        container: Ipv4Addr,
        list: UpstreamList,
    ) -> Result<UpstreamSetOutcome, NetError> {
        let mut map = lock_poisoned(self.entries.write());
        match map.get(&container) {
            Some(cur) if *cur == list => return Ok(UpstreamSetOutcome::Unchanged),
            Some(_) => {
                return Err(NetError::new(
                    NetErrorCode::AlreadyExists,
                    "container already has a different upstream DNS configuration",
                ));
            }
            None => {}
        }
        if map.len() >= MAX_REGISTRY_ENTRIES {
            return Err(NetError::new(
                NetErrorCode::ResourceExhausted,
                "upstream DNS map is full",
            ));
        }
        map.insert(container, list);
        Ok(UpstreamSetOutcome::Inserted)
    }

    /// テスト専用: loopback・任意ポートの模擬上流を許して登録する（公開 API からは到達できない）。
    #[cfg(test)]
    fn set_unchecked_for_test(
        &self,
        container: Ipv4Addr,
        servers: &[SocketAddr],
    ) -> Result<UpstreamSetOutcome, NetError> {
        let list = UpstreamList::from_addrs(servers).ok_or_else(|| invalid("count"))?;
        self.insert_list(container, list)
    }

    /// 登録を削除する。
    pub fn remove(&self, container: Ipv4Addr) -> UpstreamRemoveOutcome {
        match lock_poisoned(self.entries.write()).remove(&container) {
            Some(_) => UpstreamRemoveOutcome::Removed,
            None => UpstreamRemoveOutcome::NotFound,
        }
    }

    /// 送信元 IP で引く。
    pub fn lookup(&self, peer: Ipv4Addr) -> Option<UpstreamList> {
        lock_poisoned(self.entries.read()).get(&peer).copied()
    }

    /// 登録件数。
    pub fn len(&self) -> usize {
        lock_poisoned(self.entries.read()).len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 転送の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardResult {
    /// 上流の応答を `out` に格納した（ID はクライアントの ID に戻し済み）。
    Forwarded,
    /// すべての上流が期限内に受理可能な応答を返さなかった。
    AllFailed,
}

/// 転送用の 16 ビット ID を `RandomState` の擬似乱数から作る（新規依存なし）。
fn random_id(counter: u64) -> u16 {
    let h = RandomState::new().hash_one(counter);
    u16::from_be_bytes([(h >> 8) as u8, h as u8])
}

/// 上流へ送るクエリを組む: ヘッダー + 質問のみ（ANCOUNT・NSCOUNT・ARCOUNT=0。EDNS OPT は転送しない）。RD は保持する。
/// 返すのは `(バッファ, 長さ)`。質問の範囲外・長すぎる入力は `None`。
fn build_forward_query(
    datagram: &[u8],
    q_end: usize,
    fwd_id: u16,
) -> Option<([u8; MAX_DATAGRAM_LEN], usize)> {
    let head = datagram.get(..q_end)?;
    let mut buf = [0u8; MAX_DATAGRAM_LEN];
    buf.get_mut(..q_end)?.copy_from_slice(head);
    buf.get_mut(0..2)?.copy_from_slice(&fwd_id.to_be_bytes());
    buf.get_mut(6..HEADER_LEN)?.fill(0);
    Some((buf, q_end))
}

/// 圧縮名を含む名前を `pos` から読み飛ばして次の位置を返す。ラベル長 63 超・予約ビット（0x40/0x80 単独）・
/// 範囲外・名前長 255 超・前方（自身以降）を指す圧縮ポインタは `None`（ポインタは追跡せず、位置の妥当性のみ検証する）。
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    let mut total = 0usize;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return pos.checked_add(1);
                }
                let step = usize::from(len).checked_add(1)?;
                total = total.checked_add(step)?;
                if total > MAX_NAME_LEN {
                    return None;
                }
                pos = pos.checked_add(step)?;
                msg.get(..pos)?;
            }
            0xC0 => {
                let lo = *msg.get(pos.checked_add(1)?)?;
                let target = usize::from(len & 0x3F) << 8 | usize::from(lo);
                // ヘッダーより後ろで、かつこのポインタより前だけを許す（ループ・前方参照の排除）。
                if target < HEADER_LEN || target >= pos {
                    return None;
                }
                return pos.checked_add(2);
            }
            _ => return None,
        }
    }
}

/// 質問の後ろに続く ANCOUNT + NSCOUNT + ARCOUNT 個のリソースレコードが、メッセージ末尾ちょうどで
/// 完結するか（名前・固定 10 バイト・RDLENGTH の境界）を検証する。
fn records_well_formed(reply: &[u8], mut pos: usize) -> bool {
    let count = |at: usize| -> usize {
        match reply.get(at..at + 2) {
            Some(&[a, b]) => usize::from(u16::from_be_bytes([a, b])),
            _ => 0,
        }
    };
    let total = count(6) + count(8) + count(10);
    for _ in 0..total {
        let Some(after_name) = skip_name(reply, pos) else {
            return false;
        };
        let Some(fixed) = reply.get(after_name..after_name.saturating_add(10)) else {
            return false;
        };
        let rdlen = match fixed.get(8..10) {
            Some(&[a, b]) => usize::from(u16::from_be_bytes([a, b])),
            _ => return false,
        };
        let end = after_name.saturating_add(10).saturating_add(rdlen);
        if end > reply.len() {
            return false;
        }
        pos = end;
    }
    pos == reply.len()
}

/// 上流応答の受理条件: 長さ 12〜512・QR=1・Opcode=0・転送 ID 一致・QDCOUNT=1・質問バイト列の完全一致・
/// 後続レコードが末尾まで境界内で完結していること（不正な応答はクライアントへ渡さず破棄する）。
fn validate_upstream_reply(reply: &[u8], fwd_id: u16, question: &[u8]) -> bool {
    if reply.len() < HEADER_LEN || reply.len() > MAX_DATAGRAM_LEN {
        return false;
    }
    let Ok(h) = DnsHeader::parse(reply) else {
        return false;
    };
    let q_end = HEADER_LEN.saturating_add(question.len());
    h.is_response()
        && h.opcode() == 0
        && h.id() == fwd_id
        && h.qdcount() == 1
        && reply.get(HEADER_LEN..q_end) == Some(question)
        && records_well_formed(reply, q_end)
}

/// 1 つの上流へ 1 試行する。受理した応答を `out` に格納して true を返す。
fn try_upstream(
    server: SocketAddr,
    query: &[u8],
    fwd_id: u16,
    question: &[u8],
    client_id: u16,
    deadline: Instant,
    out: &mut ResponseBuf,
) -> bool {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return false;
    };
    if sock.connect(server).is_err() || sock.send(query).is_err() {
        return false;
    }
    let mut buf = [0u8; MAX_DATAGRAM_LEN + 1];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || sock.set_read_timeout(Some(remaining)).is_err() {
            return false;
        }
        match sock.recv(&mut buf) {
            Ok(n) => {
                let reply = buf.get(..n).unwrap_or(&[]);
                if validate_upstream_reply(reply, fwd_id, question) {
                    // クライアントの ID に戻して他は素通しする。
                    let mut fixed = [0u8; MAX_DATAGRAM_LEN];
                    let Some(dst) = fixed.get_mut(..n) else {
                        return false;
                    };
                    dst.copy_from_slice(reply);
                    if let Some(id) = fixed.get_mut(0..2) {
                        id.copy_from_slice(&client_id.to_be_bytes());
                    }
                    return fixed.get(..n).is_some_and(|b| out.set(b));
                }
                // 条件を満たさない応答は捨てて期限まで待ち続ける。
            }
            Err(_) => return false,
        }
    }
}

/// 上流を登録順に試し、最初に受理できた応答を `out` に格納する。各試行は [`FORWARD_ATTEMPT_TIMEOUT`]、全体は
/// [`FORWARD_TOTAL_DEADLINE`] で打ち切る（REPAIR-5）。
fn forward_query(
    list: &UpstreamList,
    datagram: &[u8],
    q_end: usize,
    client_id: u16,
    counter: u64,
    out: &mut ResponseBuf,
) -> ForwardResult {
    let fwd_id = random_id(counter);
    let Some((query, qlen)) = build_forward_query(datagram, q_end, fwd_id) else {
        return ForwardResult::AllFailed;
    };
    let (Some(query), Some(question)) = (query.get(..qlen), query.get(HEADER_LEN..qlen)) else {
        return ForwardResult::AllFailed;
    };
    let start = Instant::now();
    let total = start + FORWARD_TOTAL_DEADLINE;
    for server in list.iter() {
        let now = Instant::now();
        if now >= total {
            break;
        }
        let deadline = (now + FORWARD_ATTEMPT_TIMEOUT).min(total);
        if try_upstream(server, query, fwd_id, question, client_id, deadline, out) {
            return ForwardResult::Forwarded;
        }
    }
    ForwardResult::AllFailed
}

/// 全上流が失敗したときの SERVFAIL 応答（質問をエコー、AA=0、ANCOUNT=0）。
fn build_servfail(
    header: &DnsHeader,
    datagram: &[u8],
    q_end: usize,
    out: &mut ResponseBuf,
) -> bool {
    let rd = if header.recursion_desired() {
        FLAG_RD
    } else {
        0
    };
    let id = header.id().to_be_bytes();
    let mut w = MsgWriter {
        buf: [0; MAX_DATAGRAM_LEN],
        len: 0,
    };
    let filled = (|| {
        w.put(&[
            id[0],
            id[1],
            FLAG_QR | rd,
            RCODE_SERVFAIL,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ])?;
        w.put(datagram.get(HEADER_LEN..q_end)?)
    })();
    filled.is_some() && w.buf.get(..w.len).is_some_and(|b| out.set(b))
}

/// 上流応答が増幅上限を超えるときの切り詰め応答（QR=1・TC=1・RCODE=NOERROR・質問のみ。長さは要求以下）。
fn build_truncated(
    header: &DnsHeader,
    datagram: &[u8],
    q_end: usize,
    out: &mut ResponseBuf,
) -> bool {
    let rd = if header.recursion_desired() {
        FLAG_RD
    } else {
        0
    };
    let id = header.id().to_be_bytes();
    let mut w = MsgWriter {
        buf: [0; MAX_DATAGRAM_LEN],
        len: 0,
    };
    let filled = (|| {
        w.put(&[
            id[0],
            id[1],
            FLAG_QR | FLAG_TC | rd,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ])?;
        w.put(datagram.get(HEADER_LEN..q_end)?)
    })();
    filled.is_some() && w.buf.get(..w.len).is_some_and(|b| out.set(b))
}

/// [`RegistryHandler`] と上流転送を合成するハンドラ（NET-12・TASK-185.3）。判定順は module doc を参照。
/// `respond`（送信元なし）は転送せず [`RegistryHandler`] と同じ挙動にする。
#[derive(Debug)]
pub struct ForwardingHandler {
    registry: Arc<DnsRegistry>,
    local: RegistryHandler,
    upstreams: Arc<DnsUpstreamMap>,
    counter: AtomicU64,
    forward_failed: AtomicU64,
}

impl ForwardingHandler {
    /// 共有レジストリと共有上流マップから作る。
    pub fn new(registry: Arc<DnsRegistry>, upstreams: Arc<DnsUpstreamMap>) -> Self {
        Self {
            local: RegistryHandler::new(Arc::clone(&registry)),
            registry,
            upstreams,
            counter: AtomicU64::new(0),
            forward_failed: AtomicU64::new(0),
        }
    }

    /// 全上流が失敗して SERVFAIL を返した回数（REPAIR-4）。
    pub fn forward_failed(&self) -> u64 {
        self.forward_failed.load(Ordering::Relaxed)
    }

    fn is_local_name(&self, datagram: &[u8]) -> bool {
        let Some(q) = parse_question(datagram) else {
            return false;
        };
        if q.qclass != QCLASS_IN {
            return false;
        }
        let mut norm = [0u8; MAX_NAME_LEN];
        normalize_qname(q.qname, &mut norm)
            .and_then(|n| self.registry.lookup(n))
            .is_some()
    }
}

impl QueryHandler for ForwardingHandler {
    fn respond(
        &self,
        header: &DnsHeader,
        datagram: &[u8],
        out: &mut ResponseBuf,
    ) -> HandlerOutcome {
        self.local.respond(header, datagram, out)
    }

    fn respond_from(
        &self,
        peer: SocketAddr,
        header: &DnsHeader,
        datagram: &[u8],
        out: &mut ResponseBuf,
    ) -> HandlerOutcome {
        let list = match peer.ip().to_canonical() {
            IpAddr::V4(ip) if !self.is_local_name(datagram) => self.upstreams.lookup(ip),
            _ => None,
        };
        let (Some(list), Some(q)) = (list, parse_question(datagram)) else {
            return self.local.respond(header, datagram, out);
        };
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        match forward_query(&list, datagram, q.end, header.id(), counter, out) {
            ForwardResult::Forwarded => {
                // 増幅反射の防止（NET-5）: 要求長 + MAX_RESPONSE_GROWTH を超える応答は、そのまま返さず
                // TC=1 の切り詰め応答（質問のみ。要求長以下）にする。送信元 IP は偽装され得るため、
                // 転送応答にも自前応答と同じ上限を課す。
                if out.as_bytes().len() <= datagram.len().saturating_add(MAX_RESPONSE_GROWTH) {
                    HandlerOutcome::RespondForwarded
                } else if build_truncated(header, datagram, q.end, out) {
                    HandlerOutcome::Respond
                } else {
                    HandlerOutcome::NoResponse
                }
            }
            ForwardResult::AllFailed => {
                self.forward_failed.fetch_add(1, Ordering::Relaxed);
                if build_servfail(header, datagram, q.end, out) {
                    HandlerOutcome::Respond
                } else {
                    HandlerOutcome::NoResponse
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_helper::{DnsHelperServer, DnsListenAddr, DnsName};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    const PEER1: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 2);
    const PEER2: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 3);
    const PEER3: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 4);
    const GW: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 1);

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 40000)
    }

    /// ヘッダー + 質問 1 件のクエリ（`name` は `\x08external\x07example\x00` 形式のラベル列）。
    fn query(id: u16, labels: &[u8], qtype: u16, arcount: u16) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0]);
        v.extend_from_slice(&arcount.to_be_bytes());
        v.extend_from_slice(labels);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&[0, 1]);
        if arcount > 0 {
            // EDNS OPT（ルート名・type 41・UDP 4096・RDLEN 0）。
            v.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        }
        v
    }

    const EXTERNAL: &[u8] = b"\x08external\x07example\x00";
    const SVC_A: &[u8] = b"\x05svc-a\x00";

    fn respond_from(
        h: &ForwardingHandler,
        peer: SocketAddr,
        pkt: &[u8],
    ) -> (HandlerOutcome, Vec<u8>) {
        let header = DnsHeader::parse(pkt).unwrap();
        let mut out = ResponseBuf::new();
        let o = h.respond_from(peer, &header, pkt, &mut out);
        (o, out.as_bytes().to_vec())
    }

    /// 模擬上流: 固定の A を `answers` 件返し、受信した QNAME（ラベル列）を記録する。
    struct MockUpstream {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl MockUpstream {
        fn start(a: Ipv4Addr, answers: usize, respond: bool) -> Self {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let addr = sock.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (s2, st2) = (Arc::clone(&seen), Arc::clone(&stop));
            let join = thread::spawn(move || {
                let mut buf = [0u8; 600];
                while !st2.load(Ordering::Relaxed) {
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let pkt = &buf[..n];
                    let q = parse_question(pkt).unwrap();
                    s2.lock().unwrap().push(q.qname.to_vec());
                    if !respond {
                        continue;
                    }
                    let mut r = pkt[..2].to_vec();
                    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, answers as u8, 0, 0, 0, 0]);
                    r.extend_from_slice(&pkt[HEADER_LEN..q.end]);
                    for _ in 0..answers {
                        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]);
                        r.extend_from_slice(&a.octets());
                    }
                    let _ = sock.send_to(&r, from);
                }
            });
            Self {
                addr,
                seen,
                stop,
                join: Some(join),
            }
        }

        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    fn handler_with(up: &[(Ipv4Addr, SocketAddr)]) -> (ForwardingHandler, Arc<DnsRegistry>) {
        let reg = Arc::new(DnsRegistry::new());
        let map = Arc::new(DnsUpstreamMap::new());
        for (peer, addr) in up {
            map.set_unchecked_for_test(*peer, &[*addr]).unwrap();
        }
        (ForwardingHandler::new(Arc::clone(&reg), map), reg)
    }

    fn answer_ip(reply: &[u8]) -> Ipv4Addr {
        let n = reply.len();
        Ipv4Addr::new(reply[n - 4], reply[n - 3], reply[n - 2], reply[n - 1])
    }

    /// NET-12: 上流ポリシー。
    #[test]
    fn upstream_policy() {
        assert_eq!(
            UpstreamServer::new(ip("192.0.2.53")).unwrap().socket_addr(),
            "192.0.2.53:53".parse().unwrap()
        );
        assert_eq!(
            UpstreamServer::new(ip("2001:db8::53"))
                .unwrap()
                .socket_addr(),
            "[2001:db8::53]:53".parse().unwrap()
        );
        for bad in [
            "127.0.0.1",
            "127.0.0.53",
            "::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "fe80::1",
            "169.254.169.254",
            "::ffff:127.0.0.1",
        ] {
            let e = UpstreamServer::new(ip(bad)).expect_err(bad);
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
    }

    /// NET-12: マップの意味論（冪等・衝突・削除・副作用前の拒否）。
    #[test]
    fn map_semantics() {
        let m = DnsUpstreamMap::new();
        let a = [ip("192.0.2.1")];
        assert_eq!(m.set(PEER1, GW, &a).unwrap(), UpstreamSetOutcome::Inserted);
        assert_eq!(m.set(PEER1, GW, &a).unwrap(), UpstreamSetOutcome::Unchanged);
        let e = m.set(PEER1, GW, &[ip("192.0.2.2")]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(m.len(), 1);
        assert_eq!(
            m.lookup(PEER1).unwrap().iter().collect::<Vec<_>>(),
            vec!["192.0.2.1:53".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(m.remove(PEER1), UpstreamRemoveOutcome::Removed);
        assert_eq!(m.remove(PEER1), UpstreamRemoveOutcome::NotFound);
        assert!(m.is_empty());

        assert_eq!(
            m.set(PEER2, GW, &[]).unwrap_err().code(),
            NetErrorCode::InvalidArgument
        );
        let four = [
            ip("192.0.2.1"),
            ip("192.0.2.2"),
            ip("192.0.2.3"),
            ip("192.0.2.4"),
        ];
        assert_eq!(
            m.set(PEER2, GW, &four).unwrap_err().code(),
            NetErrorCode::InvalidArgument
        );
        let mixed = [ip("192.0.2.1"), ip("127.0.0.1")];
        assert_eq!(
            m.set(PEER2, GW, &mixed).unwrap_err().code(),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(m.len(), 0);
    }

    /// NET-12: gateway（ヘルパー自身）を上流にする登録は拒否し、マップを変更しない。
    #[test]
    fn map_rejects_gateway_as_upstream() {
        let m = DnsUpstreamMap::new();
        let e = m.set(PEER1, GW, &[ip("10.215.0.1")]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let e = m
            .set(PEER1, GW, &[ip("192.0.2.1"), ip("::ffff:10.215.0.1")])
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert!(m.is_empty());
    }

    /// NET-12: 件数上限。
    #[test]
    fn map_capacity() {
        let m = DnsUpstreamMap::new();
        for i in 0..MAX_REGISTRY_ENTRIES {
            let n = u32::try_from(i).unwrap();
            let peer = Ipv4Addr::from(0x0a00_0000 + n);
            m.set(peer, GW, &[ip("192.0.2.1")]).unwrap();
        }
        let e = m
            .set(Ipv4Addr::new(11, 0, 0, 1), GW, &[ip("192.0.2.1")])
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    }

    /// NET-12: 転送クエリは ARCOUNT=0・質問までで、ID だけ差し替わる。
    #[test]
    fn forward_query_bytes() {
        let pkt = query(0x1234, EXTERNAL, 1, 1);
        let q = parse_question(&pkt).unwrap();
        let (buf, len) = build_forward_query(&pkt, q.end, 0xABCD).unwrap();
        let mut expect = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expect.extend_from_slice(EXTERNAL);
        expect.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(&buf[..len], expect.as_slice());
    }

    /// NET-12: 応答検証。
    #[test]
    fn reply_validation() {
        let question: Vec<u8> = [EXTERNAL, &[0, 1, 0, 1]].concat();
        let mk = |id: u16, flags: u8, qd: u8, q: &[u8]| {
            let mut v = id.to_be_bytes().to_vec();
            v.extend_from_slice(&[flags, 0x80, 0, qd, 0, 0, 0, 0, 0, 0]);
            v.extend_from_slice(q);
            v
        };
        assert!(validate_upstream_reply(
            &mk(7, 0x81, 1, &question),
            7,
            &question
        ));
        assert!(
            !validate_upstream_reply(&mk(7, 0x01, 1, &question), 7, &question),
            "QR=0"
        );
        assert!(
            !validate_upstream_reply(&mk(8, 0x81, 1, &question), 7, &question),
            "id"
        );
        assert!(
            !validate_upstream_reply(&mk(7, 0x81, 2, &question), 7, &question),
            "qdcount"
        );
        let other: Vec<u8> = [&b"\x05other\x00"[..], &[0, 1, 0, 1]].concat();
        assert!(
            !validate_upstream_reply(&mk(7, 0x81, 1, &other), 7, &question),
            "question"
        );
        assert!(!validate_upstream_reply(&[0; 11], 0, &question), "short");
        // レコード境界: ANCOUNT=1 で A RR が完結する応答は受理、RDLENGTH 超過・末尾余り・ポインタ不正・件数過大は拒否。
        let rr = |rdlen: u16, rdata: &[u8], name: &[u8]| {
            let mut v = mk(7, 0x81, 1, &question);
            v[7] = 1;
            v.extend_from_slice(name);
            v.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 5]);
            v.extend_from_slice(&rdlen.to_be_bytes());
            v.extend_from_slice(rdata);
            v
        };
        assert!(validate_upstream_reply(
            &rr(4, &[1, 2, 3, 4], &[0xC0, 0x0C]),
            7,
            &question
        ));
        assert!(
            !validate_upstream_reply(&rr(5, &[1, 2, 3, 4], &[0xC0, 0x0C]), 7, &question),
            "rdlength overrun"
        );
        assert!(
            !validate_upstream_reply(&rr(4, &[1, 2, 3, 4, 9], &[0xC0, 0x0C]), 7, &question),
            "trailing bytes"
        );
        assert!(
            !validate_upstream_reply(&rr(4, &[1, 2, 3, 4], &[0xC0, 0xFF]), 7, &question),
            "pointer out of range"
        );
        let own = u8::try_from(HEADER_LEN + question.len()).unwrap();
        assert!(
            !validate_upstream_reply(&rr(4, &[1, 2, 3, 4], &[0xC0, own]), 7, &question),
            "self pointer"
        );
        assert!(
            !validate_upstream_reply(&rr(4, &[1, 2, 3, 4], &[0x80, 0x0C]), 7, &question),
            "reserved label type"
        );
        let mut many = rr(4, &[1, 2, 3, 4], &[0xC0, 0x0C]);
        many[7] = 2;
        assert!(!validate_upstream_reply(&many, 7, &question), "count");
        let mut big = mk(7, 0x81, 1, &question);
        big.resize(513, 0);
        assert!(!validate_upstream_reply(&big, 7, &question), "oversized");
    }

    /// NET-12・REPAIR-5: 応答しない上流でも全体期限内に SERVFAIL（RCODE=2・AA=0・ANCOUNT=0）。
    #[test]
    fn unresponsive_upstream_yields_servfail_within_deadline() {
        let silent = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 1), 1, false);
        let (h, _) = handler_with(&[(PEER1, silent.addr)]);
        let pkt = query(0x4242, EXTERNAL, 1, 0);
        let t = Instant::now();
        let (o, r) = respond_from(&h, sa(PEER1), &pkt);
        assert!(t.elapsed() <= FORWARD_TOTAL_DEADLINE + Duration::from_millis(500));
        assert_eq!(o, HandlerOutcome::Respond);
        assert_eq!(&r[..2], &[0x42, 0x42]);
        assert_eq!(r[2] & 0x04, 0, "AA");
        assert_eq!(r[3] & 0x0F, 2, "RCODE");
        assert_eq!(&r[6..8], &[0, 0], "ANCOUNT");
        assert_eq!(silent.count(), 1);
        assert_eq!(h.forward_failed(), 1);
    }

    /// NET-12 受入基準 1: レジストリのサービス名は転送せず自前応答（AAAA は NODATA）。
    #[test]
    fn registry_names_stay_local() {
        let up = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 1), 1, true);
        let (h, reg) = handler_with(&[(PEER1, up.addr)]);
        reg.register(
            &DnsName::new("svc-a").unwrap(),
            Ipv4Addr::new(10, 215, 0, 9),
        )
        .unwrap();
        let (o, r) = respond_from(&h, sa(PEER1), &query(1, SVC_A, 1, 0));
        assert_eq!(o, HandlerOutcome::Respond);
        assert_eq!(r[2] & 0x04, 0x04, "AA");
        assert_eq!(answer_ip(&r), Ipv4Addr::new(10, 215, 0, 9));
        let (o, r) = respond_from(&h, sa(PEER1), &query(2, SVC_A, 28, 0));
        assert_eq!(o, HandlerOutcome::Respond);
        assert_eq!((r[3] & 0x0F, &r[6..8]), (0, &[0u8, 0][..]));
        assert_eq!(up.count(), 0);
    }

    /// NET-12 受入基準 2・3: 外部名は登録済みコンテナの上流へ転送され、コンテナ間で干渉しない。
    #[test]
    fn forwards_per_container_without_interference() {
        let u1 = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 1), 1, true);
        let u2 = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 2), 1, true);
        let (h, _) = handler_with(&[(PEER1, u1.addr), (PEER2, u2.addr)]);
        let (o, r) = respond_from(&h, sa(PEER1), &query(0x1111, EXTERNAL, 1, 0));
        assert_eq!(o, HandlerOutcome::RespondForwarded);
        assert_eq!(&r[..2], &[0x11, 0x11], "client id restored");
        assert_eq!(answer_ip(&r), Ipv4Addr::new(198, 51, 100, 1));
        let (o, r) = respond_from(&h, sa(PEER2), &query(0x2222, EXTERNAL, 1, 1));
        assert_eq!(o, HandlerOutcome::RespondForwarded);
        assert_eq!(answer_ip(&r), Ipv4Addr::new(198, 51, 100, 2));
        let (o, r) = respond_from(&h, sa(PEER3), &query(0x3333, EXTERNAL, 1, 0));
        assert_eq!(o, HandlerOutcome::Respond);
        assert_eq!(r[3] & 0x0F, 5, "REFUSED");
        assert_eq!((u1.count(), u2.count()), (1, 1));
        assert_eq!(u1.seen.lock().unwrap()[0], EXTERNAL);
    }

    /// NET-12・NET-5: serve 経由でも転送応答は要求長 + 16 以下に限られる。1 RR の応答は転送され統計に計上され、
    /// 上限を超える応答は TC=1 の切り詰め応答（質問のみ）に置き換わる。
    #[test]
    fn serve_keeps_amplification_limit_for_forwarded_responses() {
        let one = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 1), 1, true);
        let two = MockUpstream::start(Ipv4Addr::new(198, 51, 100, 2), 2, true);
        for (up, expect_tc) in [(&one, false), (&two, true)] {
            let (h, _) = handler_with(&[(Ipv4Addr::LOCALHOST, up.addr)]);
            let mut server =
                DnsHelperServer::bind(DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
            let addr = server.local_addr();
            let stop = Arc::new(AtomicBool::new(false));
            let st = Arc::clone(&stop);
            let join = thread::spawn(move || {
                server.serve(&h, &st).unwrap();
                server
            });
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let pkt = query(0x7777, EXTERNAL, 1, 0);
            client.send_to(&pkt, addr).unwrap();
            let mut buf = [0u8; 600];
            let (n, _) = client.recv_from(&mut buf).unwrap();
            assert!(n <= pkt.len() + MAX_RESPONSE_GROWTH, "reply {n} bytes");
            assert_eq!(&buf[..2], &[0x77, 0x77]);
            assert_eq!(buf[2] & 0x02 != 0, expect_tc, "TC");
            if expect_tc {
                assert_eq!(&buf[6..8], &[0, 0], "ANCOUNT");
                assert_eq!(n, pkt.len());
            }
            stop.store(true, Ordering::Relaxed);
            let server = join.join().unwrap();
            assert_eq!(server.stats().forwarded, u64::from(!expect_tc));
            assert_eq!(server.stats().suppressed, 0);
        }
    }
}
