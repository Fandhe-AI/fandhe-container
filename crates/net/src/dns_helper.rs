//! ネットワークごとの DNS ヘルパー: プロセス起動・UDP 待受基盤・不正パケットの破棄・A レコード応答
//! （NET-5・TASK-141.1・#321・TASK-141.2・#322・MS-8）。
//!
//! # 役割と関係
//! - ネットワーク（`network::create_network` が作る bridge）の gateway の IPv4:53 に UDP で待ち受ける
//!   ヘルパープロセスを 1 つ起動する基盤。質問セクションのパース（[`parse_question`]）、コンテナ名 → IPv4 の
//!   レジストリ（[`DnsRegistry`]）、A 応答・NXDOMAIN の組み立て（[`RegistryHandler`]）を持つ
//!   （TASK-141.2・#322）。上流 DNS への転送は TASK-185、参照カウントによるオンデマンド起動・終了と
//!   SIGTERM による正常終了は TASK-144 の責務
//! - 呼び出し側（将来の統一 CLI / 製品バイナリ。TASK-79）は [`spawn_dns_helper`] で自身または専用バイナリを
//!   `--listen <ipv4:port>` つきで起動し、ヘルパー側の `main` は [`run_dns_helper_main`] を呼ぶ
//!
//! # netns の解釈
//! 現行の bridge は `create_network` の呼び出し元の netns に作られる。ヘルパーは起動元の netns を継承し、
//! その bridge の gateway アドレスに bind する（PoC-15 も同じ配置）。ルーター専用 netns を新設して
//! ヘルパーを入れる読み方は crate 境界の設計変更になるため採らない。
//!
//! # レジストリの連携点
//! コンテナ接続（`network::attach_container` の `AttachedContainer.address` が IPv4 のとき）で
//! [`DnsRegistry::register`]、切断・停止で [`DnsRegistry::unregister`] を呼ぶ。
//!
//! # 未実装（REPAIR-3）
//! ヘルパープロセス（[`run_dns_helper_main`]）は空のレジストリで起動し、プロセス外から名前を登録する経路は
//! まだ無い（CORE-1 により起動・停止は別プロセスで起きるため、登録経路の設計は後続タスクで決める）。
//! このため現時点のヘルパープロセスは全名前に NXDOMAIN を返す。上流転送・TCP・AAAA・EDNS0 も未対応。
//! PLUG-1 における DNS ヘルパーの core / plugin 区分は検討中で、確定扱いにはしない。
//!
//! # 安全性
//! 受信バッファは固定長（513 バイト）で、512 バイト超は破棄する。外部入力の解析は `get` / `try_into` のみで
//! 添字アクセス・`unwrap` を使わない。ヘッダー不正のパケットには応答しない。応答は要求長 + [`MAX_RESPONSE_GROWTH`]
//! バイト以下に限り（増幅反射の防止）、ログ・統計にはパケットの内容を載せない。待受・準備完了待ち・回収はすべて期限つき（REPAIR-5）。

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::time::{Duration, Instant};

use crate::error::{NetError, NetErrorCode};
use crate::network::CreatedNetwork;

/// DNS の既定ポート。
pub const DNS_PORT: u16 = 53;
/// 受理する UDP DNS メッセージの最大長（RFC 1035。EDNS0 は対象外）。
pub const MAX_DATAGRAM_LEN: usize = 512;
/// DNS ヘッダーの固定長。
pub const HEADER_LEN: usize = 12;
/// 準備完了待ちの既定期限（AGENTS.md の推奨 5〜10 秒）。
pub const READY_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);
/// 子プロセス回収の既定期限。
pub const REAP_TIMEOUT_DEFAULT: Duration = Duration::from_secs(2);
/// 受信ループが停止フラグを確認する間隔。
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// 一時的な受信エラーが連続して許容される上限（超えたら受信ループを終了する。REPAIR-5）。
pub const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 100;
/// 期限引数の上限。
const TIMEOUT_MAX: Duration = Duration::from_secs(10);
/// 準備完了行の最大長。
const READY_LINE_MAX: usize = 64;
const READY_PREFIX: &str = "READY ";
const FLAG_QR: u8 = 0x80;
const FLAG_RD: u8 = 0x01;
const FLAG_AA: u8 = 0x04;
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
/// A レコード応答の TTL（秒）。コンテナの増減を反映しやすいよう短くする（PoC-15 と同値）。spec は TTL を規定しない。
pub const ANSWER_TTL_SECS: u32 = 5;
/// 応答が要求長を超えてよい上限（A RR 1 件: 圧縮ポインタ 2 + TYPE 2 + CLASS 2 + TTL 4 + RDLENGTH 2 + RDATA 4）。
/// 応答は「要求 + A RR 1 件」に限られ、最小クエリ（17 バイト）でも増幅率は 2 倍未満。待受は bridge gateway の
/// ユニキャストのみ（[`DnsListenAddr`]）で、外部インターフェースへは公開しない（NET-5）。
pub const MAX_RESPONSE_GROWTH: usize = 16;
/// レジストリの登録上限（1 ネットワークのコンテナ数として十分な値。無制限確保の防止）。
pub const MAX_REGISTRY_ENTRIES: usize = 4096;
/// 正規化済みドット連結名の最大長。
const MAX_NAME_LEN: usize = 253;

fn invalid(msg: &str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// `io::Error` を `NetError` の分類へ写す（OS 非依存。メッセージは OS のエラー文言のみで、パケット内容を含めない）。
fn map_io(context: &str, e: &io::Error) -> NetError {
    let code = match e.kind() {
        io::ErrorKind::PermissionDenied => NetErrorCode::PermissionDenied,
        io::ErrorKind::AddrInUse => NetErrorCode::AlreadyExists,
        io::ErrorKind::AddrNotAvailable => NetErrorCode::FailedPrecondition,
        io::ErrorKind::NotFound => NetErrorCode::NotFound,
        io::ErrorKind::TimedOut => NetErrorCode::Timeout,
        _ => NetErrorCode::Internal,
    };
    NetError::new(code, format!("{context}: {e}"))
}

/// 待受アドレス（unspecified・broadcast・multicast を拒否した IPv4 ユニキャスト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsListenAddr(SocketAddrV4);

impl DnsListenAddr {
    /// 検証して作る。外部インターフェースへ公開しないため `0.0.0.0` 等は拒否する。port 0 はテスト用に許可する。
    pub fn new(ip: Ipv4Addr, port: u16) -> Result<Self, NetError> {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return Err(invalid(
                "listen address must be a unicast IPv4 address (not unspecified, broadcast or multicast)",
            ));
        }
        Ok(Self(SocketAddrV4::new(ip, port)))
    }

    /// ネットワークの gateway（IPv4 に限る。fail-closed）の 53 番ポートを待受先にする。
    pub fn for_network(net: &CreatedNetwork) -> Result<Self, NetError> {
        match net.gateway.addr() {
            std::net::IpAddr::V4(ip) => Self::new(ip, DNS_PORT),
            std::net::IpAddr::V6(_) => Err(invalid("gateway must be an IPv4 address")),
        }
    }

    /// 待受先ソケットアドレス。
    pub fn socket_addr(&self) -> SocketAddrV4 {
        self.0
    }
}

impl fmt::Display for DnsListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// パケットの破棄理由（統計・ログのキー）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// 12 バイト未満。
    TooShort,
    /// 512 バイト超。
    Oversized,
    /// QR=1（応答パケットをクエリとして受けた）。
    NotQuery,
    /// Opcode が 0（標準クエリ）以外。
    UnsupportedOpcode,
    /// QDCOUNT が 1 以外。
    BadQuestionCount,
    /// 質問セクション（QNAME・QTYPE・QCLASS）が欠落・不正・データグラム境界を超えている。
    BadQuestion,
}

impl DropReason {
    /// 固定の識別文字列（パケット内容を含まない）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::Oversized => "oversized",
            Self::NotQuery => "not_query",
            Self::UnsupportedOpcode => "unsupported_opcode",
            Self::BadQuestionCount => "bad_question_count",
            Self::BadQuestion => "bad_question",
        }
    }
}

/// DNS ヘッダー（固定 12 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader([u8; HEADER_LEN]);

impl DnsHeader {
    /// 先頭 12 バイトを読む。不足なら `TooShort`。
    pub fn parse(datagram: &[u8]) -> Result<Self, DropReason> {
        let head = datagram.get(..HEADER_LEN).ok_or(DropReason::TooShort)?;
        let bytes: [u8; HEADER_LEN] = head.try_into().map_err(|_| DropReason::TooShort)?;
        Ok(Self(bytes))
    }

    fn byte(&self, i: usize) -> u8 {
        self.0.get(i).copied().unwrap_or(0)
    }

    /// 識別子。
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.byte(0), self.byte(1)])
    }

    /// QR ビット（true なら応答）。
    pub fn is_response(&self) -> bool {
        self.byte(2) & FLAG_QR != 0
    }

    /// Opcode（4 ビット）。
    pub fn opcode(&self) -> u8 {
        (self.byte(2) >> 3) & 0x0F
    }

    /// RD ビット。
    pub fn recursion_desired(&self) -> bool {
        self.byte(2) & FLAG_RD != 0
    }

    /// QDCOUNT。
    pub fn qdcount(&self) -> u16 {
        u16::from_be_bytes([self.byte(4), self.byte(5)])
    }
}

/// 受信データグラムの判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramVerdict {
    /// 処理対象のクエリ。
    Accept(DnsHeader),
    /// 破棄（応答しない）。
    Drop(DropReason),
}

/// データグラムを分類する純粋関数（NET-5）。長さ → ヘッダー → QR → Opcode → QDCOUNT → 質問セクション境界の順に検査する。
pub fn classify_datagram(datagram: &[u8]) -> DatagramVerdict {
    if datagram.len() > MAX_DATAGRAM_LEN {
        return DatagramVerdict::Drop(DropReason::Oversized);
    }
    let header = match DnsHeader::parse(datagram) {
        Ok(h) => h,
        Err(r) => return DatagramVerdict::Drop(r),
    };
    if header.is_response() {
        DatagramVerdict::Drop(DropReason::NotQuery)
    } else if header.opcode() != 0 {
        DatagramVerdict::Drop(DropReason::UnsupportedOpcode)
    } else if header.qdcount() != 1 {
        DatagramVerdict::Drop(DropReason::BadQuestionCount)
    } else if parse_question(datagram).is_none() {
        DatagramVerdict::Drop(DropReason::BadQuestion)
    } else {
        DatagramVerdict::Accept(header)
    }
}

/// パース済みの質問セクション（QNAME・QTYPE・QCLASS）。`serve` が検証した受信データグラムを借用する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQuestion<'a> {
    /// ラベル列（終端の長さ 0 を含む）。
    pub qname: &'a [u8],
    /// QTYPE（A=1 等）。
    pub qtype: u16,
    /// QCLASS（IN=1 等）。
    pub qclass: u16,
    /// QCLASS 直後のデータグラム内オフセット（質問セクションのエコー範囲 `HEADER_LEN..end`）。
    pub end: usize,
}

/// ヘッダー直後の質問 1 件を解析する。QNAME はラベル列（長さ 1〜63 + 本体）を長さ 0 で終端するもののみ受理し、
/// 圧縮ポインタ・拡張ラベル（上位 2 ビットが非 0）・全長 255 超・QTYPE / QCLASS の欠落は `None`。
/// `classify_datagram` の検証と同一経路（ドリフト防止）。添字アクセスは使わず `get` で境界を確認する（NET-5）。
pub fn parse_question(datagram: &[u8]) -> Option<DnsQuestion<'_>> {
    let body = datagram.get(HEADER_LEN..)?;
    let mut off = 0usize;
    let mut name_len = 0usize;
    loop {
        let len = usize::from(*body.get(off)?);
        if len == 0 {
            off = off.checked_add(1)?;
            break;
        }
        if len > 63 {
            return None;
        }
        let next = off.checked_add(1)?.checked_add(len)?;
        if next > body.len() {
            return None;
        }
        name_len = name_len.saturating_add(len + 1);
        if name_len > 254 {
            return None;
        }
        off = next;
    }
    let qname = body.get(..off)?;
    let tail = body.get(off..)?.get(..4)?;
    let qtype = u16::from_be_bytes([*tail.first()?, *tail.get(1)?]);
    let qclass = u16::from_be_bytes([*tail.get(2)?, *tail.get(3)?]);
    let end = HEADER_LEN.checked_add(off)?.checked_add(4)?;
    Some(DnsQuestion {
        qname,
        qtype,
        qclass,
        end,
    })
}
/// 応答バッファ（上限 512 バイトの固定長）。
#[derive(Debug)]
pub struct ResponseBuf {
    buf: [u8; MAX_DATAGRAM_LEN],
    len: usize,
}

impl ResponseBuf {
    fn new() -> Self {
        Self {
            buf: [0; MAX_DATAGRAM_LEN],
            len: 0,
        }
    }

    /// 内容を空にする。`serve` が各クエリのハンドラ呼び出し前に必ず呼ぶ（前回の応答が次の送信元へ漏れない）。
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// バイト列で置き換える。上限超過なら false（バッファは空になる）。
    pub fn set(&mut self, bytes: &[u8]) -> bool {
        self.len = 0;
        match self.buf.get_mut(..bytes.len()) {
            Some(dst) => {
                dst.copy_from_slice(bytes);
                self.len = bytes.len();
                true
            }
            None => false,
        }
    }

    /// 現在の内容。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

/// ハンドラの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerOutcome {
    /// `out` の内容を返信する。
    Respond,
    /// 返信しない。
    NoResponse,
}

/// 検証済みクエリの応答処理（本実装は [`RegistryHandler`]。TASK-141.2）。
pub trait QueryHandler {
    /// `header` は検証済み、`datagram` は受信全体（512 バイト以下）。
    fn respond(&self, header: &DnsHeader, datagram: &[u8], out: &mut ResponseBuf)
    -> HandlerOutcome;
}

/// 疎通確認用の最小ハンドラ: ID と RD をコピーし QR=1・RCODE=NOTIMP(4)・各カウント 0 の 12 バイトを返す。
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedHandler;

impl QueryHandler for NotImplementedHandler {
    fn respond(
        &self,
        header: &DnsHeader,
        _datagram: &[u8],
        out: &mut ResponseBuf,
    ) -> HandlerOutcome {
        let id = header.id().to_be_bytes();
        let rd = if header.recursion_desired() {
            FLAG_RD
        } else {
            0
        };
        let reply = [
            id[0],
            id[1],
            FLAG_QR | rd,
            RCODE_NOTIMP,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        if out.set(&reply) {
            HandlerOutcome::Respond
        } else {
            HandlerOutcome::NoResponse
        }
    }
}

/// コンテナ名として DNS に登録できる名前（RFC 1123 ホスト名規則: 英数字とハイフン、各ラベル 1〜63、
/// 先頭・末尾ハイフン不可、総長 253 以下）。小文字に正規化して保持する（NET-5・NET-12）。
///
/// 注意: Docker はコンテナ名に `_` を許すが、NET-12 の hostname 契約は許さないため拒否する。
/// `_` を含むコンテナ名の扱いは要判断（未決）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// 検証・正規化して作る。末尾ドット 1 個は除去する。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        let bad = || invalid("invalid DNS name (RFC 1123 hostname rules)");
        if trimmed.is_empty() || trimmed.len() > MAX_NAME_LEN {
            return Err(bad());
        }
        for label in trimmed.split('.') {
            let ok_len = (1..=63).contains(&label.len());
            let ok_chars = label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !ok_len || !ok_chars || label.starts_with('-') || label.ends_with('-') {
                return Err(bad());
            }
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// 正規化済み（小文字・末尾ドットなし）の名前。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// [`DnsRegistry::register`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegisterOutcome {
    /// 新規に登録した。
    Inserted,
    /// 同名・同アドレスで登録済み（コンテナ再起動時の冪等性）。
    Unchanged,
}

/// [`DnsRegistry::unregister`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnregisterOutcome {
    /// 削除した（削除前のアドレス）。
    Removed(Ipv4Addr),
    /// 未登録（停止処理の冪等性のためエラーにしない）。
    NotFound,
}

/// コンテナ名 → IPv4 アドレスのレジストリ（NET-5）。`Arc` で `serve` スレッドと登録側が共有する。
///
/// 登録側はコンテナ接続（`network::attach_container` が返すアドレスが IPv4 のとき）で [`register`](Self::register)、
/// 切断・停止で [`unregister`](Self::unregister) を呼ぶ。参照カウントと自動起動 / 終了は TASK-144（NET-7）、
/// 上流転送は TASK-185（NET-12）の責務。アドレスがサブネット内かの検証は行わない。
#[derive(Debug, Default)]
pub struct DnsRegistry {
    entries: RwLock<HashMap<String, Ipv4Addr>>,
}

impl DnsRegistry {
    /// 空のレジストリ。
    pub fn new() -> Self {
        Self::default()
    }

    /// 同名別アドレスは上書きせず `AlreadyExists`（名前の乗っ取りを隠さない）。上限超過は `ResourceExhausted`。
    pub fn register(&self, name: &DnsName, addr: Ipv4Addr) -> Result<RegisterOutcome, NetError> {
        // ポイズンしても中身は単純な map で整合性は壊れないため、回復して続行する。
        let mut map = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match map.get(name.as_str()) {
            Some(cur) if *cur == addr => return Ok(RegisterOutcome::Unchanged),
            Some(_) => {
                return Err(NetError::new(
                    NetErrorCode::AlreadyExists,
                    "DNS name is already registered with a different address",
                ));
            }
            None => {}
        }
        if map.len() >= MAX_REGISTRY_ENTRIES {
            return Err(NetError::new(
                NetErrorCode::ResourceExhausted,
                "DNS registry is full",
            ));
        }
        map.insert(name.as_str().to_owned(), addr);
        Ok(RegisterOutcome::Inserted)
    }

    /// 登録を削除する。未登録でもエラーにしない。
    pub fn unregister(&self, name: &DnsName) -> UnregisterOutcome {
        let mut map = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match map.remove(name.as_str()) {
            Some(a) => UnregisterOutcome::Removed(a),
            None => UnregisterOutcome::NotFound,
        }
    }

    /// 正規化済みの名前で引く。
    pub fn lookup(&self, normalized: &str) -> Option<Ipv4Addr> {
        let map = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(normalized).copied()
    }

    /// 登録件数。
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// QNAME を小文字のドット連結名へ正規化する（スタックバッファのみ）。許可文字（英数字・ハイフン）以外を含む
/// ラベル、ルート名、バッファ超過は `None`（どの登録名にも一致しない扱い。ラベル内の `.` による誤一致を防ぐ）。
fn normalize_qname<'b>(qname: &[u8], buf: &'b mut [u8; MAX_NAME_LEN]) -> Option<&'b str> {
    let mut rest = qname;
    let mut n = 0usize;
    loop {
        let (&len, tail) = rest.split_first()?;
        if len == 0 {
            break;
        }
        let label = tail.get(..usize::from(len))?;
        rest = tail.get(usize::from(len)..)?;
        if n > 0 {
            *buf.get_mut(n)? = b'.';
            n += 1;
        }
        for &b in label {
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                return None;
            }
            *buf.get_mut(n)? = b.to_ascii_lowercase();
            n += 1;
        }
    }
    if n == 0 {
        return None;
    }
    std::str::from_utf8(buf.get(..n)?).ok()
}

/// 固定長バッファへの追記ヘルパー（境界超過は `None`。添字アクセスを避ける）。
struct MsgWriter {
    buf: [u8; MAX_DATAGRAM_LEN],
    len: usize,
}

impl MsgWriter {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.len.checked_add(bytes.len())?;
        self.buf.get_mut(self.len..end)?.copy_from_slice(bytes);
        self.len = end;
        Some(())
    }
}

/// レジストリを引いて A 応答・NXDOMAIN 等を返すハンドラ（NET-5・TASK-141.2）。
///
/// 判定: QCLASS≠IN は REFUSED / 未登録は NXDOMAIN（AA=1）/ 登録済みの A は answer 1 件 / 登録済みの A 以外は
/// NODATA（NOERROR・answer 0。glibc が A と AAAA を並列に引くため NXDOMAIN にしない）。再帰は提供しない（RA=0）。
/// 要求の EDNS OPT はエコーしない（ARCOUNT=0）。
#[derive(Debug, Clone)]
pub struct RegistryHandler {
    registry: Arc<DnsRegistry>,
}

impl RegistryHandler {
    /// 共有レジストリを引くハンドラを作る。
    pub fn new(registry: Arc<DnsRegistry>) -> Self {
        Self { registry }
    }

    fn build(&self, header: &DnsHeader, datagram: &[u8], out: &mut ResponseBuf) -> Option<()> {
        let q = parse_question(datagram)?;
        let mut norm = [0u8; MAX_NAME_LEN];
        let (rcode, answer) = if q.qclass != QCLASS_IN {
            (RCODE_REFUSED, None)
        } else {
            let found = normalize_qname(q.qname, &mut norm).and_then(|n| self.registry.lookup(n));
            match found {
                None => (RCODE_NXDOMAIN, None),
                Some(ip) if q.qtype == QTYPE_A => (RCODE_NOERROR, Some(ip)),
                Some(_) => (RCODE_NOERROR, None),
            }
        };
        // REFUSED は権威を主張しないため AA を立てない。
        let aa = if rcode == RCODE_REFUSED { 0 } else { FLAG_AA };
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
        let ancount = u8::from(answer.is_some());
        w.put(&[
            id[0],
            id[1],
            FLAG_QR | aa | rd,
            rcode,
            0,
            1,
            0,
            ancount,
            0,
            0,
            0,
            0,
        ])?;
        w.put(datagram.get(HEADER_LEN..q.end)?)?;
        if let Some(ip) = answer {
            w.put(&[0xC0, 0x0C, 0, 1, 0, 1])?;
            w.put(&ANSWER_TTL_SECS.to_be_bytes())?;
            w.put(&[0, 4])?;
            w.put(&ip.octets())?;
        }
        out.set(w.buf.get(..w.len)?).then_some(())
    }
}

impl QueryHandler for RegistryHandler {
    fn respond(
        &self,
        header: &DnsHeader,
        datagram: &[u8],
        out: &mut ResponseBuf,
    ) -> HandlerOutcome {
        match self.build(header, datagram, out) {
            Some(()) => HandlerOutcome::Respond,
            None => HandlerOutcome::NoResponse,
        }
    }
}

/// 受信ループの統計（REPAIR-4）。パケット内容・送信元アドレスは持たない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsHelperStats {
    /// 受信したデータグラム数。
    pub received: u64,
    /// 応答を送った数。
    pub answered: u64,
    /// `TooShort` の破棄数。
    pub dropped_too_short: u64,
    /// `Oversized` の破棄数。
    pub dropped_oversized: u64,
    /// `NotQuery` の破棄数。
    pub dropped_not_query: u64,
    /// `UnsupportedOpcode` の破棄数。
    pub dropped_unsupported_opcode: u64,
    /// `BadQuestionCount` の破棄数。
    pub dropped_bad_question_count: u64,
    /// `BadQuestion` の破棄数。
    pub dropped_bad_question: u64,
    /// 送信失敗数。
    pub send_errors: u64,
    /// 受信失敗数（一時的なエラーとして継続）。
    pub recv_errors: u64,
    /// ハンドラの応答が要求長を超える等で抑止した数。
    pub suppressed: u64,
}

impl DnsHelperStats {
    /// 理由ごとの破棄数。
    pub fn dropped(&self, reason: DropReason) -> u64 {
        match reason {
            DropReason::TooShort => self.dropped_too_short,
            DropReason::Oversized => self.dropped_oversized,
            DropReason::NotQuery => self.dropped_not_query,
            DropReason::UnsupportedOpcode => self.dropped_unsupported_opcode,
            DropReason::BadQuestionCount => self.dropped_bad_question_count,
            DropReason::BadQuestion => self.dropped_bad_question,
        }
    }

    fn count_drop(&mut self, reason: DropReason) {
        let slot = match reason {
            DropReason::TooShort => &mut self.dropped_too_short,
            DropReason::Oversized => &mut self.dropped_oversized,
            DropReason::NotQuery => &mut self.dropped_not_query,
            DropReason::UnsupportedOpcode => &mut self.dropped_unsupported_opcode,
            DropReason::BadQuestionCount => &mut self.dropped_bad_question_count,
            DropReason::BadQuestion => &mut self.dropped_bad_question,
        };
        *slot = slot.saturating_add(1);
    }
}

/// `recv_from` のエラーが「データグラムがバッファに収まらない」（Linux / macOS の EMSGSIZE、Windows の
/// WSAEMSGSIZE）かを判定する。std は専用の `ErrorKind` を持たないため raw OS エラー番号で比較する。
fn is_msgsize(e: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    const MSGSIZE: i32 = 90;
    #[cfg(target_os = "macos")]
    const MSGSIZE: i32 = 40;
    #[cfg(windows)]
    const MSGSIZE: i32 = 10040;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    const MSGSIZE: i32 = -1;
    e.raw_os_error() == Some(MSGSIZE)
}

/// UDP 待受サーバー。ヘルパープロセスの本体で、テストからはスレッドでも動かせる。
#[derive(Debug)]
pub struct DnsHelperServer {
    socket: UdpSocket,
    local: SocketAddrV4,
    stats: DnsHelperStats,
}

impl DnsHelperServer {
    /// 待受先へ bind する。port 53 の bind は呼び出し側の権限（`CAP_NET_BIND_SERVICE` 等）に依存し、本 crate は昇格しない。
    pub fn bind(addr: DnsListenAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(addr.socket_addr()).map_err(|e| map_io("bind udp", &e))?;
        socket
            .set_read_timeout(Some(RECV_POLL_INTERVAL))
            .map_err(|e| map_io("set read timeout", &e))?;
        let local = match socket.local_addr().map_err(|e| map_io("local addr", &e))? {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => return Err(invalid("bound address is not IPv4")),
        };
        Ok(Self {
            socket,
            local,
            stats: DnsHelperStats::default(),
        })
    }

    /// 実際に bind したアドレス（port 0 指定時の確定 port を含む）。
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }

    /// 統計。
    pub fn stats(&self) -> &DnsHelperStats {
        &self.stats
    }

    /// `stop` が立つまで受信する。1 パケットごとの失敗では止まらない（NET-5）。停止確認は
    /// [`RECV_POLL_INTERVAL`] ごと（REPAIR-5）。パケットごとのヒープ確保はしない。
    ///
    /// 受信エラーは一時的なもの（割り込み・ICMP 由来の ConnectionReset 等）のみ再試行し、連続
    /// [`MAX_CONSECUTIVE_RECV_ERRORS`] 回を超えるか永続的なエラーなら受信ループを終了して `Err` を返す（REPAIR-5）。
    /// 各クエリのハンドラ呼び出し前に応答バッファを空にする。
    pub fn serve(&mut self, handler: &dyn QueryHandler, stop: &AtomicBool) -> Result<(), NetError> {
        let mut buf = [0u8; MAX_DATAGRAM_LEN + 1];
        let mut out = ResponseBuf::new();
        let mut consecutive_errors: u32 = 0;
        while !stop.load(Ordering::Relaxed) {
            let (n, peer) = match self.socket.recv_from(&mut buf) {
                Ok(v) => {
                    consecutive_errors = 0;
                    v
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                // バッファより大きいデータグラムを切り詰めず EMSGSIZE 系で返す OS では、
                // 致命扱いにせず Oversized として破棄して継続する（NET-5）。
                Err(e) if is_msgsize(&e) => {
                    self.stats.received = self.stats.received.saturating_add(1);
                    self.stats.count_drop(DropReason::Oversized);
                    continue;
                }
                Err(e) => {
                    self.stats.recv_errors = self.stats.recv_errors.saturating_add(1);
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    let transient = matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionAborted
                    );
                    if !transient || consecutive_errors > MAX_CONSECUTIVE_RECV_ERRORS {
                        return Err(map_io("recv udp", &e));
                    }
                    continue;
                }
            };
            self.stats.received = self.stats.received.saturating_add(1);
            let datagram = buf.get(..n).unwrap_or(&[]);
            let header = match classify_datagram(datagram) {
                DatagramVerdict::Accept(h) => h,
                DatagramVerdict::Drop(r) => {
                    self.stats.count_drop(r);
                    continue;
                }
            };
            out.clear();
            if handler.respond(&header, datagram, &mut out) != HandlerOutcome::Respond {
                continue;
            }
            // 増幅反射の防止: 応答は要求長 + A RR 1 件分以下に限る。
            if out.as_bytes().len() > n.saturating_add(MAX_RESPONSE_GROWTH) {
                self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                continue;
            }
            match self.socket.send_to(out.as_bytes(), peer) {
                Ok(_) => self.stats.answered = self.stats.answered.saturating_add(1),
                Err(_) => self.stats.send_errors = self.stats.send_errors.saturating_add(1),
            }
        }
        Ok(())
    }
}

/// ヘルパープロセスの入口（`--listen <ipv4:port>` のみ受理）。bind 後に stdout へ `READY <ip:port>` を 1 行だけ
/// 出し、以後 stdout には書かない（親が pipe を閉じても EPIPE で落ちないため）。失敗は stderr に英語 1 行
/// （code / message。ERR-1）を出して非ゼロで終了する（引数エラーは 2）。
pub fn run_dns_helper_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    fn fail_line(code: &str, message: &str) {
        let _ = writeln!(io::stderr(), "error code={code} message={message}");
    }
    let mut listen: Option<DnsListenAddr> = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        if arg != "--listen" || listen.is_some() {
            fail_line("INVALID_ARGUMENT", "unexpected or duplicate argument");
            return ExitCode::from(2);
        }
        let parsed = args
            .next()
            .and_then(|v| v.into_string().ok())
            .and_then(|s| s.parse::<SocketAddrV4>().ok())
            .and_then(|a| DnsListenAddr::new(*a.ip(), a.port()).ok());
        match parsed {
            Some(a) => listen = Some(a),
            None => {
                fail_line("INVALID_ARGUMENT", "invalid listen address");
                return ExitCode::from(2);
            }
        }
    }
    let Some(listen) = listen else {
        fail_line("INVALID_ARGUMENT", "missing --listen");
        return ExitCode::from(2);
    };
    let mut server = match DnsHelperServer::bind(listen) {
        Ok(s) => s,
        Err(e) => {
            fail_line(e.code().as_str(), e.message());
            return ExitCode::from(1);
        }
    };
    let mut stdout = io::stdout();
    if writeln!(stdout, "{READY_PREFIX}{}", server.local_addr())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        fail_line("INTERNAL", "cannot write readiness line");
        return ExitCode::from(1);
    }
    // 親が kill するまで動き続ける。正常終了（SIGTERM）は TASK-144 の責務。
    // プロセス外からの登録経路は未実装（REPAIR-3）のため、空のレジストリ = 全名前 NXDOMAIN。
    let stop = AtomicBool::new(false);
    let handler = RegistryHandler::new(Arc::new(DnsRegistry::new()));
    match server.serve(&handler, &stop) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            fail_line(e.code().as_str(), e.message());
            ExitCode::from(1)
        }
    }
}

/// 起動したヘルパープロセスのハンドル。`Drop` でも kill と回収を行う（ゾンビを残さない）。
#[derive(Debug)]
pub struct DnsHelperProcess {
    child: Option<Child>,
    listen: SocketAddrV4,
}

fn check_timeout(t: Duration) -> Result<(), NetError> {
    if t.is_zero() || t > TIMEOUT_MAX {
        return Err(invalid(
            "timeout must be greater than 0 and at most 10 seconds",
        ));
    }
    Ok(())
}

/// kill して期限内に回収する。回収できれば true。
fn kill_and_reap(child: &mut Child, timeout: Duration) -> bool {
    let _ = child.kill();
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return false,
        }
    }
}

/// kill して期限内に回収し、できなければ回収権をバックグラウンドの回収スレッドへ移す（ゾンビを残さない）。
/// 期限内に回収できたら true。kill 済みのため、回収スレッドの `wait` は子の終了後に必ず戻る。
fn kill_reap_or_detach(mut child: Child, timeout: Duration) -> bool {
    if kill_and_reap(&mut child, timeout) {
        return true;
    }
    // 回収権を捨てない: Child を破棄すると後から終了した子がゾンビになる。
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    false
}

impl DnsHelperProcess {
    /// プロセス ID。
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// ヘルパーが報告した待受アドレス。
    pub fn listen_addr(&self) -> SocketAddrV4 {
        self.listen
    }

    /// kill して期限内に回収する。期限内に回収できなければ `Timeout` を返すが、回収権は
    /// バックグラウンドの回収スレッドが引き継ぐため、子が後から終了してもゾンビは残らない。
    pub fn stop(mut self, reap_timeout: Duration) -> Result<(), NetError> {
        check_timeout(reap_timeout)?;
        let Some(child) = self.child.take() else {
            return Ok(());
        };
        if kill_reap_or_detach(child, reap_timeout) {
            Ok(())
        } else {
            Err(NetError::new(
                NetErrorCode::Timeout,
                "dns helper was not reaped before the deadline",
            ))
        }
    }
}

impl Drop for DnsHelperProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = kill_reap_or_detach(child, REAP_TIMEOUT_DEFAULT);
        }
    }
}

/// stdout から準備完了行を最大 [`READY_LINE_MAX`] バイト、改行まで読む。
fn read_ready_line(mut out: impl io::Read) -> Result<String, &'static str> {
    let mut line = Vec::with_capacity(READY_LINE_MAX);
    let mut byte = [0u8; 1];
    loop {
        match out.read(&mut byte) {
            Ok(0) => return Err("helper exited before readiness"),
            Ok(_) => {}
            Err(_) => return Err("cannot read readiness line"),
        }
        match byte.first().copied() {
            Some(b'\n') => break,
            Some(b) if line.len() < READY_LINE_MAX => line.push(b),
            _ => return Err("readiness line too long"),
        }
    }
    String::from_utf8(line).map_err(|_| "readiness line is not UTF-8")
}

fn parse_ready(line: &str, want: SocketAddrV4) -> Result<SocketAddrV4, NetError> {
    let bad = || NetError::new(NetErrorCode::FailedPrecondition, "malformed readiness line");
    let addr: SocketAddrV4 = line
        .strip_prefix(READY_PREFIX)
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    let port_ok = if want.port() == 0 {
        addr.port() != 0
    } else {
        addr.port() == want.port()
    };
    if addr.ip() != want.ip() || !port_ok {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "helper reported an unexpected listen address",
        ));
    }
    Ok(addr)
}

/// ヘルパーを起動し、準備完了行を `ready_timeout` 内に受理するまで待つ。
///
/// `program` は絶対パスに限る（PATH 探索をしない。PLUG-11 と同じ考え方）。シェルを経由せず、環境変数は
/// 引き継がない（Windows のみ Winsock 初期化に要る `SystemRoot`）。失敗時は kill と回収まで行う。
pub fn spawn_dns_helper(
    program: &Path,
    listen: DnsListenAddr,
    ready_timeout: Duration,
) -> Result<DnsHelperProcess, NetError> {
    check_timeout(ready_timeout)?;
    if !program.is_absolute() {
        return Err(invalid("helper program path must be absolute"));
    }
    let mut cmd = Command::new(program);
    cmd.arg("--listen")
        .arg(listen.to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd.spawn().map_err(|e| map_io("spawn dns helper", &e))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = kill_reap_or_detach(child, REAP_TIMEOUT_DEFAULT);
        return Err(NetError::new(
            NetErrorCode::Internal,
            "helper stdout unavailable",
        ));
    };
    let (tx, rx) = mpsc::channel();
    // kill で pipe の書き込み端が閉じれば read が戻る。失敗経路では kill 後にこのスレッドの終了も期限つきで確認する。
    let reader = std::thread::spawn(move || {
        let _ = tx.send(read_ready_line(stdout));
    });
    let result = match rx.recv_timeout(ready_timeout) {
        Ok(Ok(line)) => parse_ready(&line, listen.socket_addr()),
        Ok(Err(msg)) => Err(NetError::new(NetErrorCode::FailedPrecondition, msg)),
        Err(_) => Err(NetError::new(
            NetErrorCode::Timeout,
            "dns helper was not ready before the deadline",
        )),
    };
    match result {
        Ok(addr) => Ok(DnsHelperProcess {
            child: Some(child),
            listen: addr,
        }),
        Err(e) => {
            let reaped = kill_reap_or_detach(child, REAP_TIMEOUT_DEFAULT);
            // 読み取りスレッドの終了を期限つきで確認する。子孫プロセスが stdout を継承していると pipe が
            // 閉じず read が戻らない（std は pipe 読み取りを中断できない）ため、その場合は join せず
            // 切り離して Timeout で報告する（REPAIR-5。無期限にブロックしない）。
            let waited = rx.recv_timeout(REAP_TIMEOUT_DEFAULT);
            if !matches!(waited, Err(mpsc::RecvTimeoutError::Timeout)) || reader.is_finished() {
                let _ = reader.join();
                Err(e)
            } else {
                let tail = if reaped {
                    "readiness reader thread did not terminate before the deadline"
                } else {
                    "readiness reader thread and helper reaping did not finish before the deadline"
                };
                Err(NetError::new(NetErrorCode::Timeout, format!("{e}; {tail}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ヘッダー 12 バイト（ID・flags・QDCOUNT）を組む。
    fn hdr(id: u16, flags: u16, qd: u16) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&qd.to_be_bytes());
        v.extend_from_slice(&[0; 6]);
        v
    }

    /// ヘッダー + 質問 1 件（`example.com` A IN）のデータグラムを組む。
    fn query_pkt(id: u16, flags: u16) -> Vec<u8> {
        let mut v = hdr(id, flags, 1);
        v.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        v
    }

    /// NET-5: 破棄理由の表駆動。
    #[test]
    fn classify_drops_malformed() {
        let cases: Vec<(Vec<u8>, DropReason)> = vec![
            (vec![], DropReason::TooShort),
            (vec![0; 11], DropReason::TooShort),
            (hdr(1, 0x8100, 1), DropReason::NotQuery),
            (hdr(1, 0x1000, 1), DropReason::UnsupportedOpcode),
            (hdr(1, 0x0100, 0), DropReason::BadQuestionCount),
            (hdr(1, 0x0100, 2), DropReason::BadQuestionCount),
            // 質問セクション無し・途中切れ・圧縮ポインタ・63 超ラベルは BadQuestion。
            (hdr(1, 0x0100, 1), DropReason::BadQuestion),
            (
                query_pkt(1, 0x0100)[..query_pkt(1, 0x0100).len() - 1].to_vec(),
                DropReason::BadQuestion,
            ),
            (
                [hdr(1, 0x0100, 1), vec![0xC0, 0x0C, 0, 1, 0, 1]].concat(),
                DropReason::BadQuestion,
            ),
            (
                [
                    hdr(1, 0x0100, 1),
                    vec![64],
                    vec![b'a'; 64],
                    vec![0, 0, 1, 0, 1],
                ]
                .concat(),
                DropReason::BadQuestion,
            ),
            (vec![0; 513], DropReason::Oversized),
        ];
        for (pkt, want) in cases {
            assert_eq!(classify_datagram(&pkt), DatagramVerdict::Drop(want));
        }
        assert_eq!(DropReason::BadQuestionCount.as_str(), "bad_question_count");
    }

    /// NET-5: 正常ヘッダーは Accept で ID・QDCOUNT を読める。512 バイトちょうども受理する。
    #[test]
    fn classify_accepts_query() {
        let DatagramVerdict::Accept(h) = classify_datagram(&query_pkt(0x1234, 0x0100)) else {
            panic!("expected accept");
        };
        assert_eq!(h.id(), 0x1234);
        assert_eq!(h.qdcount(), 1);
        assert!(h.recursion_desired());
        assert_eq!(h.opcode(), 0);
        let mut big = query_pkt(7, 0);
        big.resize(512, 0);
        assert!(matches!(
            classify_datagram(&big),
            DatagramVerdict::Accept(_)
        ));
    }

    /// REPAIR-3: スタブ応答のバイト列（RD なし / あり）。
    #[test]
    fn stub_reply_bytes() {
        let mut out = ResponseBuf::new();
        for (flags, want) in [(0x0000u16, 0x80u8), (0x0100, 0x81)] {
            let pkt = hdr(0x1234, flags, 1);
            let h = DnsHeader::parse(&pkt).expect("header");
            assert_eq!(
                NotImplementedHandler.respond(&h, &pkt, &mut out),
                HandlerOutcome::Respond
            );
            assert_eq!(
                out.as_bytes(),
                &[0x12, 0x34, want, 0x04, 0, 0, 0, 0, 0, 0, 0, 0]
            );
        }
    }

    #[test]
    fn listen_addr_validation() {
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert_eq!(
                DnsListenAddr::new(ip, 53).expect_err("reject").code(),
                NetErrorCode::InvalidArgument
            );
        }
        let ok = DnsListenAddr::new(Ipv4Addr::new(10, 213, 0, 1), 53).expect("ok");
        assert_eq!(ok.to_string(), "10.213.0.1:53");
    }

    /// NET-5: EMSGSIZE 系のエラーは Oversized 扱い（致命ではない）と判定される。
    #[test]
    fn msgsize_error_is_recognized() {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        {
            #[cfg(target_os = "linux")]
            let code = 90;
            #[cfg(target_os = "macos")]
            let code = 40;
            #[cfg(windows)]
            let code = 10040;
            assert!(is_msgsize(&io::Error::from_raw_os_error(code)));
        }
        assert!(!is_msgsize(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }

    #[test]
    fn response_buf_limits() {
        let mut out = ResponseBuf::new();
        assert!(out.set(&[1; 512]));
        assert!(!out.set(&[1; 513]));
        assert!(out.as_bytes().is_empty());
    }

    #[test]
    fn main_rejects_bad_args() {
        let run = |a: &[&str]| run_dns_helper_main(a.iter().map(OsString::from));
        let two = ExitCode::from(2);
        assert_eq!(run(&["--bogus"]), two);
        assert_eq!(run(&[]), two);
        assert_eq!(run(&["--listen"]), two);
        assert_eq!(run(&["--listen", "nope"]), two);
        assert_eq!(run(&["--listen", "0.0.0.0:53"]), two);
        assert_eq!(
            run(&["--listen", "127.0.0.1:0", "--listen", "127.0.0.1:0"]),
            two
        );
    }

    #[test]
    fn spawn_rejects_relative_path_and_bad_timeout() {
        let l = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("addr");
        let e =
            spawn_dns_helper(Path::new("dns-helper"), l, READY_TIMEOUT_DEFAULT).expect_err("rel");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let abs = std::env::current_exe().expect("exe");
        let e = spawn_dns_helper(&abs, l, Duration::ZERO).expect_err("zero");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    #[test]
    fn ready_line_parsing() {
        let want = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        assert_eq!(
            parse_ready("READY 127.0.0.1:4000", want)
                .expect("ok")
                .port(),
            4000
        );
        assert!(parse_ready("READY 127.0.0.1:0", want).is_err());
        assert!(parse_ready("READY 127.0.0.2:4000", want).is_err());
        assert!(parse_ready("garbage", want).is_err());
        let fixed = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
        assert!(parse_ready("READY 127.0.0.1:54", fixed).is_err());
        assert_eq!(read_ready_line(&b"READY x\n"[..]), Ok("READY x".to_owned()));
        assert!(read_ready_line(&[b'a'; 100][..]).is_err());
        assert!(read_ready_line(&b"no newline"[..]).is_err());
    }

    /// 前回 `set` した内容を残したまま `Respond` だけ返すハンドラ（`serve` がバッファを空にすることの検証用）。
    struct ForgetfulHandler {
        calls: std::sync::atomic::AtomicU32,
    }

    impl QueryHandler for ForgetfulHandler {
        fn respond(&self, _h: &DnsHeader, _d: &[u8], out: &mut ResponseBuf) -> HandlerOutcome {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                assert!(out.set(&[1, 2, 3]));
                HandlerOutcome::NoResponse
            } else {
                assert!(
                    out.as_bytes().is_empty(),
                    "buffer must be cleared per query"
                );
                HandlerOutcome::Respond
            }
        }
    }

    /// NET-5: NoResponse 後の Respond でも前回の応答バイト列が漏れない。
    #[test]
    fn serve_clears_response_buffer_per_query() {
        let mut server =
            DnsHelperServer::bind(DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("addr"))
                .expect("bind");
        let target = server.local_addr();
        let stop = AtomicBool::new(false);
        let handler = ForgetfulHandler {
            calls: std::sync::atomic::AtomicU32::new(0),
        };
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        for _ in 0..2 {
            client.send_to(&query_pkt(7, 0x0100), target).expect("send");
        }
        std::thread::scope(|sc| {
            let th = sc.spawn(|| server.serve(&handler, &stop));
            let mut buf = [0u8; 600];
            let r = client.recv_from(&mut buf);
            stop.store(true, Ordering::Relaxed);
            assert!(th.join().expect("join").is_ok());
            // 2 件目は空応答（0 バイト）で返る。前回の [1,2,3] は出ない。
            assert_eq!(r.map(|(n, _)| n).ok(), Some(0));
        });
    }

    /// NET-5: ループバックの実ソケットで、不正パケットは無応答・正常クエリは応答、統計が具体値になる。
    #[test]
    fn serve_drops_malformed_and_answers_query() {
        let mut server =
            DnsHelperServer::bind(DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("addr"))
                .expect("bind");
        let target = server.local_addr();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let th = std::thread::spawn(move || {
            let r = server.serve(&NotImplementedHandler, &stop2);
            assert!(r.is_ok());
            server
        });
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let mut buf = [0u8; 600];
        let mut big = query_pkt(1, 0x0100);
        big.resize(513, 0);
        for pkt in [
            vec![0u8; 11],
            hdr(1, 0x8100, 1),
            hdr(1, 0x1000, 1),
            hdr(1, 0x0100, 0),
            hdr(1, 0x0100, 1),
            big,
        ] {
            client.send_to(&pkt, target).expect("send");
            let r = client.recv_from(&mut buf);
            assert!(r.is_err(), "malformed packet must not be answered");
        }
        client
            .send_to(&query_pkt(0xBEEF, 0x0100), target)
            .expect("send");
        let (n, _) = client.recv_from(&mut buf).expect("reply");
        assert_eq!(
            buf.get(..n),
            Some(&[0xBE, 0xEF, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0][..])
        );
        stop.store(true, Ordering::Relaxed);
        let server = th.join().expect("join");
        let s = server.stats();
        assert_eq!(s.received, 7);
        assert_eq!(s.answered, 1);
        assert_eq!(s.dropped(DropReason::TooShort), 1);
        assert_eq!(s.dropped(DropReason::NotQuery), 1);
        assert_eq!(s.dropped(DropReason::UnsupportedOpcode), 1);
        assert_eq!(s.dropped(DropReason::BadQuestionCount), 1);
        assert_eq!(s.dropped(DropReason::BadQuestion), 1);
        assert_eq!(s.dropped(DropReason::Oversized), 1);
    }

    // ---- TASK-141.2（#322）: 質問パース・レジストリ・A 応答 ----

    /// 任意の QNAME 文字列（ドット区切り）・QTYPE・QCLASS のクエリを組む。
    fn named_query(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut v = hdr(id, flags, 1);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            v.push(u8::try_from(label.len()).expect("label len"));
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        v
    }

    fn handler_with(entries: &[(&str, Ipv4Addr)]) -> (RegistryHandler, Arc<DnsRegistry>) {
        let reg = Arc::new(DnsRegistry::new());
        for (n, a) in entries {
            reg.register(&DnsName::new(n).expect("name"), *a)
                .expect("register");
        }
        (RegistryHandler::new(Arc::clone(&reg)), reg)
    }

    fn answer(h: &RegistryHandler, pkt: &[u8]) -> Vec<u8> {
        let DatagramVerdict::Accept(hd) = classify_datagram(pkt) else {
            panic!("expected accept");
        };
        let mut out = ResponseBuf::new();
        assert_eq!(h.respond(&hd, pkt, &mut out), HandlerOutcome::Respond);
        out.as_bytes().to_vec()
    }

    /// NET-5: 質問セクションの具体値（QNAME 範囲・QTYPE・QCLASS・end）。
    #[test]
    fn parse_question_values() {
        let pkt = query_pkt(1, 0x0100);
        let q = parse_question(&pkt).expect("question");
        assert_eq!(q.qname, b"\x07example\x03com\x00");
        assert_eq!((q.qtype, q.qclass, q.end), (1, 1, pkt.len()));
        // 質問の後ろの余剰（EDNS OPT 等）は end が質問末尾を指す。
        let mut with_opt = pkt.clone();
        with_opt.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_question(&with_opt).expect("q").end, pkt.len());
        assert!(parse_question(&hdr(1, 0, 1)).is_none());
        assert!(parse_question(&[]).is_none());
    }

    /// NET-5: DnsName の正規化と拒否。
    #[test]
    fn dns_name_validation() {
        assert_eq!(DnsName::new("web").expect("ok").as_str(), "web");
        assert_eq!(DnsName::new("Web.").expect("ok").as_str(), "web");
        assert_eq!(DnsName::new("db-1.svc").expect("ok").as_str(), "db-1.svc");
        let long_label = "a".repeat(64);
        let long_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
        ]
        .join(".");
        for bad in [
            "",
            ".",
            "-a",
            "a-",
            &long_label,
            &long_name,
            "a_b",
            "a b",
            "a\u{1}b",
            "a..b",
            "é",
        ] {
            assert_eq!(
                DnsName::new(bad).expect_err("reject").code(),
                NetErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
        assert!(DnsName::new(&"a".repeat(63)).is_ok());
    }

    /// NET-5: 登録・冪等・衝突・削除・上限。
    #[test]
    fn registry_lifecycle() {
        let reg = DnsRegistry::new();
        let web = DnsName::new("web").expect("name");
        let a1 = Ipv4Addr::new(10, 215, 0, 2);
        assert_eq!(reg.register(&web, a1), Ok(RegisterOutcome::Inserted));
        assert_eq!(reg.register(&web, a1), Ok(RegisterOutcome::Unchanged));
        let e = reg
            .register(&web, Ipv4Addr::new(10, 215, 0, 3))
            .expect_err("conflict");
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(reg.lookup("web"), Some(a1));
        assert_eq!(reg.unregister(&web), UnregisterOutcome::Removed(a1));
        assert_eq!(reg.unregister(&web), UnregisterOutcome::NotFound);
        assert!(reg.is_empty());
        for i in 0..MAX_REGISTRY_ENTRIES {
            let n = DnsName::new(&format!("c{i}")).expect("name");
            reg.register(&n, a1).expect("fill");
        }
        assert_eq!(reg.len(), MAX_REGISTRY_ENTRIES);
        let over = DnsName::new("over").expect("name");
        let e = reg.register(&over, a1).expect_err("full");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    }

    /// NET-5: 登録済み名の A 質問に正しいアドレスで応答する（全バイト列照合）。大文字小文字は無視。
    #[test]
    fn handler_answers_a_record() {
        let (h, _) = handler_with(&[("web", Ipv4Addr::new(10, 215, 0, 2))]);
        let pkt = named_query(0x1234, 0x0100, "WEB", 1, 1);
        let mut want = vec![0x12, 0x34, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        want.extend_from_slice(&pkt[HEADER_LEN..]);
        want.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 10, 215, 0, 2]);
        assert_eq!(answer(&h, &pkt), want);
        // RD=0 は RD を立てない。
        let pkt = named_query(1, 0, "web", 1, 1);
        assert_eq!(answer(&h, &pkt).get(2..4), Some(&[0x84, 0x00][..]));
    }

    /// NET-5: 未登録名は NXDOMAIN（AA=1・ANCOUNT=0・長さは要求と同じ）。
    #[test]
    fn handler_nxdomain_for_unknown() {
        let (h, _) = handler_with(&[("web", Ipv4Addr::new(10, 215, 0, 2))]);
        let pkt = named_query(7, 0x0100, "nope", 1, 1);
        let r = answer(&h, &pkt);
        assert_eq!(
            r.get(..12),
            Some(&[0, 7, 0x85, 3, 0, 1, 0, 0, 0, 0, 0, 0][..])
        );
        assert_eq!(r.len(), pkt.len());
    }

    /// NET-5: AAAA は NODATA、CH は REFUSED、ラベル内 `.` は誤一致しない、EDNS OPT はエコーしない。
    #[test]
    fn handler_edge_cases() {
        let (h, _) = handler_with(&[
            ("web", Ipv4Addr::new(10, 215, 0, 2)),
            ("web.x", Ipv4Addr::new(10, 215, 0, 3)),
        ]);
        let r = answer(&h, &named_query(1, 0x0100, "web", 28, 1));
        assert_eq!(
            r.get(..12),
            Some(&[0, 1, 0x85, 0, 0, 1, 0, 0, 0, 0, 0, 0][..])
        );
        let r = answer(&h, &named_query(1, 0x0100, "web", 1, 3));
        assert_eq!(r.get(2..4), Some(&[0x81, 5][..]));
        // 1 ラベル "web.x"（ラベル内に '.'）は 2 ラベル登録名 web.x に一致しない。
        let mut pkt = hdr(1, 0x0100, 1);
        pkt.extend_from_slice(b"\x05web.x\x00\x00\x01\x00\x01");
        assert_eq!(answer(&h, &pkt).get(3), Some(&3));
        let ok = named_query(1, 0x0100, "web.x", 1, 1);
        assert_eq!(answer(&h, &ok).get(3), Some(&0));
        // EDNS OPT 付き要求（ARCOUNT=1）でも応答は ARCOUNT=0 で OPT をエコーしない。
        let plain = named_query(1, 0x0100, "web", 1, 1);
        let mut edns = plain.clone();
        edns.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]);
        if let Some(b) = edns.get_mut(11) {
            *b = 1;
        }
        let r = answer(&h, &edns);
        assert_eq!(r.get(10..12), Some(&[0, 0][..]));
        assert_eq!(r.len(), plain.len() + 16);
    }

    /// NET-5: unregister（コンテナ停止）後は NXDOMAIN に変わる。
    #[test]
    fn handler_follows_unregister() {
        let (h, reg) = handler_with(&[("web", Ipv4Addr::new(10, 215, 0, 2))]);
        let pkt = named_query(1, 0x0100, "web", 1, 1);
        assert_eq!(answer(&h, &pkt).get(3), Some(&0));
        reg.unregister(&DnsName::new("web").expect("name"));
        assert_eq!(answer(&h, &pkt).get(3), Some(&3));
    }

    /// 固定長の応答を返すハンドラ（`serve` の増幅ガード境界の検証用）。
    struct FixedLenHandler(usize);

    impl QueryHandler for FixedLenHandler {
        fn respond(&self, _h: &DnsHeader, _d: &[u8], out: &mut ResponseBuf) -> HandlerOutcome {
            assert!(out.set(&vec![0u8; self.0]));
            HandlerOutcome::Respond
        }
    }

    /// NET-5: 応答が要求長 + 16 までは送信し、+17 は抑止（suppressed）する。
    #[test]
    fn serve_amplification_guard_boundary() {
        let pkt = query_pkt(1, 0x0100);
        for (extra, sent) in [
            (MAX_RESPONSE_GROWTH, true),
            (MAX_RESPONSE_GROWTH + 1, false),
        ] {
            let mut server =
                DnsHelperServer::bind(DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("addr"))
                    .expect("bind");
            let target = server.local_addr();
            let stop = AtomicBool::new(false);
            let handler = FixedLenHandler(pkt.len() + extra);
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
            client
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("timeout");
            client.send_to(&pkt, target).expect("send");
            std::thread::scope(|sc| {
                let th = sc.spawn(|| server.serve(&handler, &stop));
                let mut buf = [0u8; 600];
                let r = client.recv_from(&mut buf);
                stop.store(true, Ordering::Relaxed);
                assert!(th.join().expect("join").is_ok());
                assert_eq!(r.is_ok(), sent);
            });
            assert_eq!(server.stats().suppressed, u64::from(!sent));
        }
    }

    /// NET-5: 実ソケットで登録名の A 応答と未登録名の NXDOMAIN を受信バイト列で照合する。
    #[test]
    fn serve_registry_over_loopback() {
        let (h, _) = handler_with(&[("web", Ipv4Addr::new(10, 215, 0, 2))]);
        let mut server =
            DnsHelperServer::bind(DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("addr"))
                .expect("bind");
        let target = server.local_addr();
        let stop = AtomicBool::new(false);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        std::thread::scope(|sc| {
            let th = sc.spawn(|| server.serve(&h, &stop));
            let mut buf = [0u8; 600];
            let mut got = Vec::new();
            for name in ["web", "nope"] {
                let pkt = named_query(9, 0x0100, name, 1, 1);
                client.send_to(&pkt, target).expect("send");
                let (n, _) = client.recv_from(&mut buf).expect("reply");
                got.push(buf.get(..n).expect("len").to_vec());
            }
            stop.store(true, Ordering::Relaxed);
            assert!(th.join().expect("join").is_ok());
            assert_eq!(got[0].get(7), Some(&1));
            assert_eq!(got[0].get(got[0].len() - 4..), Some(&[10, 215, 0, 2][..]));
            assert_eq!(got[1].get(3), Some(&3));
        });
        assert_eq!(server.stats().answered, 2);
    }
}
