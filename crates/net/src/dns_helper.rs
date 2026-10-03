//! ネットワークごとの DNS ヘルパー: プロセス起動・UDP 待受基盤・不正パケットの破棄
//! （NET-5・TASK-141.1・#321・MS-8）。
//!
//! # 役割と関係
//! - ネットワーク（`network::create_network` が作る bridge）の gateway の IPv4:53 に UDP で待ち受ける
//!   ヘルパープロセスを 1 つ起動する基盤。クエリの意味解釈（QNAME / QTYPE のパース・レジストリ・A 応答・
//!   NXDOMAIN）は TASK-141.2（#322）が [`QueryHandler`] の実装を差し替えて担う。上流 DNS への転送は
//!   TASK-185、参照カウントによるオンデマンド起動・終了と SIGTERM による正常終了は TASK-144 の責務
//! - 呼び出し側（将来の統一 CLI / 製品バイナリ。TASK-79）は [`spawn_dns_helper`] で自身または専用バイナリを
//!   `--listen <ipv4:port>` つきで起動し、ヘルパー側の `main` は [`run_dns_helper_main`] を呼ぶ
//!
//! # netns の解釈
//! 現行の bridge は `create_network` の呼び出し元の netns に作られる。ヘルパーは起動元の netns を継承し、
//! その bridge の gateway アドレスに bind する（PoC-15 も同じ配置）。ルーター専用 netns を新設して
//! ヘルパーを入れる読み方は crate 境界の設計変更になるため採らない。
//!
//! # 未実装（REPAIR-3）
//! 既定の [`NotImplementedHandler`] は疎通確認用の仮実装で、ヘッダー検証を通ったクエリに RCODE=NOTIMP(4) の
//! 12 バイト応答を返すだけである。A レコード応答（NET-5 の本来の挙動）ではない。PLUG-1 における
//! DNS ヘルパーの core / plugin 区分は検討中で、確定扱いにはしない。
//!
//! # 安全性
//! 受信バッファは固定長（513 バイト）で、512 バイト超は破棄する。外部入力の解析は `get` / `try_into` のみで
//! 添字アクセス・`unwrap` を使わない。ヘッダー不正のパケットには応答しない。応答は要求長以下に限り
//! （増幅反射の防止）、ログ・統計にはパケットの内容を載せない。待受・準備完了待ち・回収はすべて期限つき（REPAIR-5）。

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
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
/// 期限引数の上限。
const TIMEOUT_MAX: Duration = Duration::from_secs(10);
/// 準備完了行の最大長。
const READY_LINE_MAX: usize = 64;
const READY_PREFIX: &str = "READY ";
const FLAG_QR: u8 = 0x80;
const FLAG_RD: u8 = 0x01;
const RCODE_NOTIMP: u8 = 4;

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

/// データグラムを分類する純粋関数（NET-5）。長さ → ヘッダー → QR → Opcode → QDCOUNT の順に検査する。
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
    } else {
        DatagramVerdict::Accept(header)
    }
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

/// 検証済みクエリの応答処理（TASK-141.2 が A 応答・NXDOMAIN の実装で差し替える差し替え点）。
pub trait QueryHandler {
    /// `header` は検証済み、`datagram` は受信全体（512 バイト以下）。
    fn respond(&self, header: &DnsHeader, datagram: &[u8], out: &mut ResponseBuf)
    -> HandlerOutcome;
}

/// 仮実装（REPAIR-3）: ID と RD をコピーし QR=1・RCODE=NOTIMP(4)・各カウント 0 の 12 バイトを返す。
/// NET-5 の A 応答ではなく、疎通確認用。
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
        }
    }

    fn count_drop(&mut self, reason: DropReason) {
        let slot = match reason {
            DropReason::TooShort => &mut self.dropped_too_short,
            DropReason::Oversized => &mut self.dropped_oversized,
            DropReason::NotQuery => &mut self.dropped_not_query,
            DropReason::UnsupportedOpcode => &mut self.dropped_unsupported_opcode,
            DropReason::BadQuestionCount => &mut self.dropped_bad_question_count,
        };
        *slot = slot.saturating_add(1);
    }
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
    pub fn serve(&mut self, handler: &dyn QueryHandler, stop: &AtomicBool) {
        let mut buf = [0u8; MAX_DATAGRAM_LEN + 1];
        let mut out = ResponseBuf::new();
        while !stop.load(Ordering::Relaxed) {
            let (n, peer) = match self.socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    self.stats.recv_errors = self.stats.recv_errors.saturating_add(1);
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
            if handler.respond(&header, datagram, &mut out) != HandlerOutcome::Respond {
                continue;
            }
            // 増幅反射の防止: 応答は要求長以下に限る。
            if out.as_bytes().len() > n {
                self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                continue;
            }
            match self.socket.send_to(out.as_bytes(), peer) {
                Ok(_) => self.stats.answered = self.stats.answered.saturating_add(1),
                Err(_) => self.stats.send_errors = self.stats.send_errors.saturating_add(1),
            }
        }
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
    let stop = AtomicBool::new(false);
    server.serve(&NotImplementedHandler, &stop);
    ExitCode::SUCCESS
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

impl DnsHelperProcess {
    /// プロセス ID。
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// ヘルパーが報告した待受アドレス。
    pub fn listen_addr(&self) -> SocketAddrV4 {
        self.listen
    }

    /// kill して期限内に回収する。期限内に回収できなければ `Timeout`。
    pub fn stop(mut self, reap_timeout: Duration) -> Result<(), NetError> {
        check_timeout(reap_timeout)?;
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if kill_and_reap(&mut child, reap_timeout) {
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
        if let Some(mut child) = self.child.take() {
            let _ = kill_and_reap(&mut child, REAP_TIMEOUT_DEFAULT);
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
        kill_and_reap(&mut child, REAP_TIMEOUT_DEFAULT);
        return Err(NetError::new(
            NetErrorCode::Internal,
            "helper stdout unavailable",
        ));
    };
    let (tx, rx) = mpsc::channel();
    // kill で pipe が閉じれば read が戻るため、スレッドは残らない。
    std::thread::spawn(move || {
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
            kill_and_reap(&mut child, REAP_TIMEOUT_DEFAULT);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// ヘッダー 12 バイト（ID・flags・QDCOUNT）を組む。
    fn hdr(id: u16, flags: u16, qd: u16) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&qd.to_be_bytes());
        v.extend_from_slice(&[0; 6]);
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
        let DatagramVerdict::Accept(h) = classify_datagram(&hdr(0x1234, 0x0100, 1)) else {
            panic!("expected accept");
        };
        assert_eq!(h.id(), 0x1234);
        assert_eq!(h.qdcount(), 1);
        assert!(h.recursion_desired());
        assert_eq!(h.opcode(), 0);
        let mut big = hdr(7, 0, 1);
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
            server.serve(&NotImplementedHandler, &stop2);
            server
        });
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let mut buf = [0u8; 600];
        let mut big = hdr(1, 0x0100, 1);
        big.resize(513, 0);
        for pkt in [
            vec![0u8; 11],
            hdr(1, 0x8100, 1),
            hdr(1, 0x1000, 1),
            hdr(1, 0x0100, 0),
            big,
        ] {
            client.send_to(&pkt, target).expect("send");
            let r = client.recv_from(&mut buf);
            assert!(r.is_err(), "malformed packet must not be answered");
        }
        client
            .send_to(&hdr(0xBEEF, 0x0100, 1), target)
            .expect("send");
        let (n, _) = client.recv_from(&mut buf).expect("reply");
        assert_eq!(
            buf.get(..n),
            Some(&[0xBE, 0xEF, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0][..])
        );
        stop.store(true, Ordering::Relaxed);
        let server = th.join().expect("join");
        let s = server.stats();
        assert_eq!(s.received, 6);
        assert_eq!(s.answered, 1);
        assert_eq!(s.dropped(DropReason::TooShort), 1);
        assert_eq!(s.dropped(DropReason::NotQuery), 1);
        assert_eq!(s.dropped(DropReason::UnsupportedOpcode), 1);
        assert_eq!(s.dropped(DropReason::BadQuestionCount), 1);
        assert_eq!(s.dropped(DropReason::Oversized), 1);
    }
}
