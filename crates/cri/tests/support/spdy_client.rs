//! ストリーミング試験用の client-go 相当のブロッキング SPDY クライアントと補助（CRI-6・SEC-1・REPAIR-5・REPAIR-12）。
//!
//! 取り込み元: `crates/cri/tests/streaming.rs`（偽 dialer での疎通）と
//! `crates/plugin-cri/tests/streaming_grpc.rs`（本番バイナリの NODE port-forward 往復。#3756）。後者は cri へ
//! 逆依存できないため `#[path]` で本ファイルを取り込む（core の `reap.rs` と同じ共有の流儀）。
//! std と `fandhe_container_cri::streaming::spdy` だけを使い、serde_json・tokio には依存しない
//! （plugin-cri の dev-dependencies を増やさないため）。読み書きは 5 秒で打ち切り、ハングしない（REPAIR-5）。

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use fandhe_container_cri::streaming::spdy::{Frame, FrameDecoder, FrameEncoder, Headers, StreamId};

/// 受けたバイトをそのまま返し、相手が書き込み側を閉じたら自分も閉じる echo サーバー。
#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
                let mut buf = [0u8; 4096];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if conn.write_all(buf.get(..n).unwrap_or_default()).is_err() {
                        return;
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// URL から `(authority, path)` を取り出す。
#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn split_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let at = rest.find('/').expect("path");
    (rest[..at].to_string(), rest[at..].to_string())
}

#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub struct Spdy {
    pub tcp: TcpStream,
    pub enc: FrameEncoder,
    pub dec: FrameDecoder,
    pub next_id: u32,
    pub data: HashMap<u32, Vec<u8>>,
    pub fin: HashSet<u32>,
    pub replies: HashSet<u32>,
    pub rsts: Vec<(u32, u32)>,
    pub pings: Vec<u32>,
    pub goaway: Option<u32>,
    pub eof: bool,
}

/// 応答のヘッダ部を 1 バイトずつ読む（後続の SPDY フレームを食わない）。
#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn read_head(tcp: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192, "response head is too long");
        assert_eq!(tcp.read(&mut byte).expect("read head"), 1, "closed early");
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn raw_connect(addr: SocketAddr) -> TcpStream {
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    tcp
}

/// Upgrade なしの素の `POST`。応答の先頭行を返す（404 などの照合用）。
#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn plain_post_status(addr: SocketAddr, path: &str) -> String {
    let mut tcp = raw_connect(addr);
    tcp.write_all(
        format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .expect("write");
    let head = read_head(&mut tcp);
    head.lines().next().unwrap_or_default().to_string()
}

#[allow(dead_code)] // 取り込み元によって使う項目が異なる
impl Spdy {
    /// client-go と同じ `POST` + Upgrade で接続し、101 と選ばれた版を確認する。
    pub fn connect(addr: SocketAddr, path: &str, versions: &[&str], expect: &str) -> Self {
        let mut tcp = raw_connect(addr);
        let mut raw = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n"
        );
        for v in versions {
            raw.push_str(&format!("X-Stream-Protocol-Version: {v}\r\n"));
        }
        raw.push_str("\r\n");
        tcp.write_all(raw.as_bytes()).expect("write request");
        let head = read_head(&mut tcp);
        assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("upgrade: spdy/3.1"), "{head}");
        assert!(
            lower.contains(&format!("x-stream-protocol-version: {expect}")),
            "{head}"
        );
        Self {
            tcp,
            enc: FrameEncoder::new(),
            dec: FrameDecoder::new(),
            next_id: 1,
            data: HashMap::new(),
            fin: HashSet::new(),
            replies: HashSet::new(),
            rsts: Vec::new(),
            pings: Vec::new(),
            goaway: None,
            eof: false,
        }
    }

    pub fn send(&mut self, frame: &Frame) {
        let mut out = Vec::new();
        self.enc.encode(frame, &mut out).expect("encode");
        self.tcp.write_all(&out).expect("send");
    }

    /// 次のフレームを 1 つ読んで蓄積する。読み取りの期限切れ（5 秒）は失敗にする。
    pub fn pump_one(&mut self) {
        assert!(!self.eof, "connection closed unexpectedly");
        let frame = loop {
            if let Some(frame) = self.dec.next_frame().expect("decode") {
                break Some(frame);
            }
            let mut buf = [0u8; 8192];
            match self.tcp.read(&mut buf) {
                Ok(0) => break None,
                Ok(n) => self.dec.extend(buf.get(..n).unwrap_or_default()),
                Err(e) => panic!("read failed (no frame within the deadline): {e}"),
            }
        };
        let Some(frame) = frame else {
            self.eof = true;
            return;
        };
        match frame {
            Frame::SynReply { stream_id, .. } => {
                self.replies.insert(stream_id.get());
            }
            Frame::RstStream { stream_id, status } => self.rsts.push((stream_id.get(), status)),
            Frame::Ping { id } => self.pings.push(id),
            Frame::GoAway { status, .. } => self.goaway = Some(status),
            Frame::Data {
                stream_id,
                fin,
                data,
            } => {
                self.data.entry(stream_id.get()).or_default().extend(data);
                if fin {
                    self.fin.insert(stream_id.get());
                }
            }
            _ => {}
        }
    }

    /// client-go の `CreateStream` 相当。SYN_STREAM を送り、その ID の SYN_REPLY を受けるまで次へ進まない。
    pub fn create_stream(&mut self, headers: &[(&str, &str)]) -> u32 {
        let id = self.next_id;
        self.next_id += 2;
        let mut h = Headers::new();
        for (k, v) in headers {
            h.push(k, v);
        }
        self.send(&Frame::SynStream {
            stream_id: StreamId::new(id).expect("id"),
            associated_to: 0,
            priority: 0,
            fin: false,
            unidirectional: false,
            headers: h,
        });
        while !self.replies.contains(&id) {
            assert!(
                !self.rsts.iter().any(|(rid, _)| *rid == id),
                "stream {id} was reset: {:?}",
                self.rsts
            );
            self.pump_one();
        }
        id
    }

    pub fn send_data(&mut self, id: u32, data: &[u8], fin: bool) {
        self.send(&Frame::Data {
            stream_id: StreamId::new(id).expect("id"),
            fin,
            data: data.to_vec(),
        });
    }

    /// 指定ストリームの FIN まで読み、そこまでの内容を返す。
    pub fn read_until_fin(&mut self, id: u32) -> Vec<u8> {
        while !self.fin.contains(&id) {
            self.pump_one();
        }
        self.data.get(&id).cloned().unwrap_or_default()
    }

    /// 指定ストリームに `want` バイト届くまで読む。
    pub fn read_at_least(&mut self, id: u32, want: usize) -> Vec<u8> {
        while self.data.get(&id).map_or(0, Vec::len) < want {
            self.pump_one();
        }
        self.data.get(&id).cloned().unwrap_or_default()
    }

    pub fn wait_goaway(&mut self) -> u32 {
        while self.goaway.is_none() {
            self.pump_one();
        }
        self.goaway.expect("goaway")
    }
}

/// 1 対の error / data を client-go と同じ手順で張る。error ストリームはクライアント側を直ちに閉じる。
#[allow(dead_code)] // 取り込み元によって使う項目が異なる
pub fn open_pf_pair(c: &mut Spdy, port: &str, request_id: &str) -> (u32, u32) {
    let error = c.create_stream(&[
        ("streamtype", "error"),
        ("port", port),
        ("requestid", request_id),
    ]);
    c.send_data(error, b"", true);
    let data = c.create_stream(&[
        ("streamtype", "data"),
        ("port", port),
        ("requestid", request_id),
    ]);
    (error, data)
}
