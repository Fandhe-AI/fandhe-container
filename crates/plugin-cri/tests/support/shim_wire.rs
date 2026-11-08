//! shim v2（ttrpc＋Task API）の試験用の手組みワイヤー補助（CRI-5・TASK-62.6・#3684）。
//!
//! 呼び出し元: plugin-cri の shim バイナリ試験（`shim_bin_*.rs`）が `#[path]` で共有する。prost を plugin-cri の依存に
//! 足さない（依存は承認制）ため、試験に要る最小限（要求の組み立てと応答の読み取り）だけを std で書く。
//! 外部入力（子プロセスの応答）の解析では `unwrap`・添字アクセスを使わず `Option` で返す。

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use fandhe_container_cri::shim_v2::{FrameHeader, HEADER_LEN, MessageType};

/// ttrpc の応答（status の code・message と payload）。status が無ければ成功。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resp {
    pub status: Option<(i32, String)>,
    pub payload: Vec<u8>,
}

/// `DeleteResponse` / `StateResponse` の試験が見る欄。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskFields {
    pub id: String,
    pub pid: u32,
    pub status: u32,
    pub exit_status: u32,
    pub has_exited_at: bool,
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// 長さ区切りの欄（string・bytes・message）。空は省略する（proto3 の既定値と同じ）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn put_len(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    put_varint(out, field << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// varint の欄。0 は省略する。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn put_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    if v == 0 {
        return;
    }
    put_varint(out, field << 3);
    put_varint(out, v);
}

/// `{ string id = 1; string exec_id = 2; }`（State・Delete・Wait・Start の要求）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn id_request(id: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_len(&mut b, 1, id.as_bytes());
    b
}

/// `{ string id = 1; string exec_id = 2; }`（exec_id つきの State・Start・Delete・Wait の要求。#4149）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn exec_id_request(id: &str, exec_id: &str) -> Vec<u8> {
    let mut b = id_request(id);
    put_len(&mut b, 2, exec_id.as_bytes());
    b
}

/// `ExecProcessRequest { id = 1; exec_id = 2; spec = 7 }`。spec は `Any { type_url = 1; value = 2 }` で、値は
/// OCI runtime-spec の `Process` の JSON（型 URL は cri の `PROCESS_TYPE_URL` と同じ。#4149）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn exec_request(id: &str, exec_id: &str, spec_json: &str) -> Vec<u8> {
    let mut any = Vec::new();
    put_len(
        &mut any,
        1,
        fandhe_container_cri::shim_v2::exec::PROCESS_TYPE_URL.as_bytes(),
    );
    put_len(&mut any, 2, spec_json.as_bytes());
    let mut b = exec_id_request(id, exec_id);
    put_len(&mut b, 7, &any);
    b
}

/// `KillRequest { id = 1; exec_id = 2; signal = 3; all = 4 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn kill_request(id: &str, signal: u32, all: bool) -> Vec<u8> {
    let mut b = id_request(id);
    put_uint(&mut b, 3, u64::from(signal));
    put_uint(&mut b, 4, u64::from(all));
    b
}

/// `ShutdownRequest { id = 1; now = 2 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn shutdown_request(id: &str, now: bool) -> Vec<u8> {
    let mut b = id_request(id);
    put_uint(&mut b, 2, u64::from(now));
    b
}

/// `CreateTaskRequest { id = 1; bundle = 2 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn create_request(id: &str, bundle: &str) -> Vec<u8> {
    let mut b = id_request(id);
    put_len(&mut b, 2, bundle.as_bytes());
    b
}

/// ttrpc の `Request { service = 1; method = 2; payload = 3 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn encode_request(service: &str, method: &str, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_len(&mut b, 1, service.as_bytes());
    put_len(&mut b, 2, method.as_bytes());
    put_len(&mut b, 3, payload);
    b
}

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for i in 0..10u32 {
        let b = *buf.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f).checked_shl(7 * i)?;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// 1 つの欄の値。
enum Val<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

/// 最上位の欄を順に走査する。切れた入力・未知のワイヤー型は `None`。
fn fields(buf: &[u8]) -> Option<Vec<(u64, Val<'_>)>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < buf.len() {
        let tag = varint(buf, &mut pos)?;
        match tag & 7 {
            0 => out.push((tag >> 3, Val::Int(varint(buf, &mut pos)?))),
            2 => {
                let len = usize::try_from(varint(buf, &mut pos)?).ok()?;
                let end = pos.checked_add(len)?;
                out.push((tag >> 3, Val::Bytes(buf.get(pos..end)?)));
                pos = end;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// ttrpc の応答 `Response { status = 1 { code = 1; message = 2 }; payload = 2 }` を読む。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn decode_response(buf: &[u8]) -> Option<Resp> {
    let mut resp = Resp::default();
    for (f, v) in fields(buf)? {
        match (f, v) {
            (1, Val::Bytes(b)) => {
                let (mut code, mut msg) = (0i32, String::new());
                for (g, w) in fields(b)? {
                    match (g, w) {
                        (1, Val::Int(c)) => code = c as i64 as i32,
                        (2, Val::Bytes(m)) => msg = String::from_utf8_lossy(m).into_owned(),
                        _ => {}
                    }
                }
                resp.status = Some((code, msg));
            }
            (2, Val::Bytes(b)) => resp.payload = b.to_vec(),
            _ => {}
        }
    }
    Some(resp)
}

/// `DeleteResponse { pid = 1; exit_status = 2; exited_at = 3 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn decode_delete_response(buf: &[u8]) -> Option<TaskFields> {
    let mut t = TaskFields::default();
    for (f, v) in fields(buf)? {
        match (f, v) {
            (1, Val::Int(n)) => t.pid = n as u32,
            (2, Val::Int(n)) => t.exit_status = n as u32,
            (3, Val::Bytes(_)) => t.has_exited_at = true,
            _ => {}
        }
    }
    Some(t)
}

/// `StateResponse { id = 1; pid = 3; status = 4; exit_status = 9; exited_at = 10 }`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn decode_state_response(buf: &[u8]) -> Option<TaskFields> {
    let mut t = TaskFields::default();
    for (f, v) in fields(buf)? {
        match (f, v) {
            (1, Val::Bytes(b)) => t.id = String::from_utf8_lossy(b).into_owned(),
            (3, Val::Int(n)) => t.pid = n as u32,
            (4, Val::Int(n)) => t.status = n as u32,
            (9, Val::Int(n)) => t.exit_status = n as u32,
            (10, Val::Bytes(_)) => t.has_exited_at = true,
            _ => {}
        }
    }
    Some(t)
}

/// 1 要求 1 接続で呼ぶ。応答は期限つきで読む（REPAIR-5）。失敗は理由つきの `Err`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn call_method(
    path: &Path,
    service: &str,
    method: &str,
    payload: &[u8],
) -> Result<Resp, String> {
    let mut s = UnixStream::connect(path).map_err(|e| format!("connect: {e}"))?;
    let t = Some(Duration::from_secs(15));
    s.set_read_timeout(t).map_err(|e| e.to_string())?;
    s.set_write_timeout(t).map_err(|e| e.to_string())?;
    let body = encode_request(service, method, payload);
    let h = FrameHeader::new(body.len() as u32, 1, MessageType::Request, 0)
        .map_err(|e| format!("header: {e:?}"))?;
    s.write_all(&h.to_bytes()).map_err(|e| e.to_string())?;
    s.write_all(&body).map_err(|e| e.to_string())?;
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb)
        .map_err(|e| format!("read header: {e}"))?;
    let h = FrameHeader::from_bytes(&hb).map_err(|e| format!("parse header: {e:?}"))?;
    let mut b = vec![0u8; h.length() as usize];
    s.read_exact(&mut b)
        .map_err(|e| format!("read body: {e}"))?;
    decode_response(&b).ok_or_else(|| "undecodable response".to_string())
}
