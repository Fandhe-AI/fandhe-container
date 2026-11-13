//! VM 保持役と起動役（CLI・plugin-macos アダプタ）の間の要求・応答の符号化（MAC-4・REPAIR-2）。
//!
//! 転送は `fandhe-container-plugin` の `Frame`（長さ接頭辞＋チェックサム）の payload に載せる。payload は固定長ヘッダ
//! （magic `FCVK`・version・kind・id 長）と任意長の ID だけで、`control::protocol` と同じく big-endian・型つきの
//! レコードとして組み立てる（生の `Vec<u8>` を手で組まない）。復号は `get`・`from_be_bytes` だけで行い、添字アクセスを
//! しない。ID は core の `ContainerId::new` で検証してから保持する（パス要素にはしないが、同じ語彙に揃える）。
//!
//! 呼び出し元は `vm_keeper::server`（復号して登録簿へ渡す）と `vm_keeper::client`（符号化して送る）。

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

/// payload の先頭 4 バイト。
pub const MAGIC: [u8; 4] = *b"FCVK";
/// 本実装が話す版。
pub const VERSION: u8 = 1;
/// ヘッダ長（magic 4 + version 1 + kind 1 + id 長 2）。
const REQUEST_HEADER_LEN: usize = 8;
/// ID の最大バイト数（`ContainerId` の上限と同値。長さを確かめてから切り出す）。
pub const ID_MAX_LEN: usize = 255;
/// 要求 payload の最大長。これを超える payload は復号せず拒否する。
pub const REQUEST_MAX_LEN: usize = REQUEST_HEADER_LEN + ID_MAX_LEN;
/// 応答 payload の長さ（固定）。
pub const RESPONSE_LEN: usize = 13;

const KIND_REGISTER: u8 = 1;
const KIND_UNREGISTER: u8 = 2;
const KIND_STATUS: u8 = 3;
const KIND_RESPONSE: u8 = 0x80;

fn invalid(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

/// 起動役から保持役への要求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// コンテナ 1 件を登録する（参照数 +1）。
    Register(ContainerId),
    /// コンテナ 1 件の登録を外す（参照数 -1）。
    Unregister(ContainerId),
    /// 参照数と保持役の pid を照会する。
    Status,
}

impl Request {
    /// payload へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let (kind, id): (u8, &[u8]) = match self {
            Self::Register(id) => (KIND_REGISTER, id.as_str().as_bytes()),
            Self::Unregister(id) => (KIND_UNREGISTER, id.as_str().as_bytes()),
            Self::Status => (KIND_STATUS, &[]),
        };
        let mut out = Vec::with_capacity(REQUEST_HEADER_LEN + id.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind);
        // `ContainerId` は 255 バイト以下のため u16 に収まる。
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        out
    }

    /// payload を復号する。magic・version・kind・長さ・ID の検証に失敗したら `InvalidArgument`（固定文言）。
    pub fn decode(bytes: &[u8]) -> Result<Self, TraitError> {
        if bytes.len() < REQUEST_HEADER_LEN || bytes.len() > REQUEST_MAX_LEN {
            return Err(invalid("vm keeper request has an invalid length"));
        }
        if bytes.get(..4) != Some(&MAGIC[..]) {
            return Err(invalid("vm keeper request has a bad magic"));
        }
        if bytes.get(4) != Some(&VERSION) {
            return Err(invalid("vm keeper request has an unsupported version"));
        }
        let kind = *bytes
            .get(5)
            .ok_or_else(|| invalid("vm keeper request is truncated"))?;
        let len_bytes: [u8; 2] = bytes
            .get(6..8)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("vm keeper request is truncated"))?;
        let id_len = usize::from(u16::from_be_bytes(len_bytes));
        if id_len > ID_MAX_LEN || bytes.len() != REQUEST_HEADER_LEN + id_len {
            return Err(invalid("vm keeper request has an inconsistent id length"));
        }
        let id_bytes = bytes
            .get(REQUEST_HEADER_LEN..)
            .ok_or_else(|| invalid("vm keeper request is truncated"))?;
        match kind {
            KIND_STATUS if id_len == 0 => Ok(Self::Status),
            KIND_REGISTER | KIND_UNREGISTER => {
                let text = std::str::from_utf8(id_bytes)
                    .map_err(|_| invalid("vm keeper request has a non-utf8 id"))?;
                let id = ContainerId::new(text)?;
                Ok(if kind == KIND_REGISTER {
                    Self::Register(id)
                } else {
                    Self::Unregister(id)
                })
            }
            _ => Err(invalid("vm keeper request has an unknown kind")),
        }
    }
}

/// 応答の結果分類（機械可読。`Ok` 以外は要求を適用していない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// 適用した。
    Ok,
    /// 同じ ID が既に登録済み。
    AlreadyRegistered,
    /// 登録の無い ID の解除。
    NotRegistered,
    /// 登録簿の上限に達している（正式な `RESOURCE_EXHAUSTED` の扱いは #2279）。
    CapacityExceeded,
    /// 終了を決定済みで新規の登録を受けない。
    ShuttingDown,
}

impl Reason {
    fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::AlreadyRegistered => 1,
            Self::NotRegistered => 2,
            Self::CapacityExceeded => 3,
            Self::ShuttingDown => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::AlreadyRegistered,
            2 => Self::NotRegistered,
            3 => Self::CapacityExceeded,
            4 => Self::ShuttingDown,
            _ => return None,
        })
    }
}

/// 保持役から起動役への応答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    /// 結果分類。
    pub reason: Reason,
    /// 要求の適用後の参照数。
    pub refcount: u16,
    /// 応答した保持役の pid（二重起動の拒否の検証で「勝った側」を見分ける）。
    pub keeper_pid: u32,
}

impl Response {
    /// payload へ符号化する（固定長 [`RESPONSE_LEN`]）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESPONSE_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(KIND_RESPONSE);
        out.push(self.reason.code());
        out.extend_from_slice(&self.refcount.to_be_bytes());
        out.extend_from_slice(&self.keeper_pid.to_be_bytes());
        out
    }

    /// payload を復号する。固定長・magic・version・kind・理由コードのいずれかが不正なら `InvalidArgument`。
    pub fn decode(bytes: &[u8]) -> Result<Self, TraitError> {
        if bytes.len() != RESPONSE_LEN {
            return Err(invalid("vm keeper response has an invalid length"));
        }
        if bytes.get(..4) != Some(&MAGIC[..])
            || bytes.get(4) != Some(&VERSION)
            || bytes.get(5) != Some(&KIND_RESPONSE)
        {
            return Err(invalid("vm keeper response has a bad header"));
        }
        let reason = bytes
            .get(6)
            .copied()
            .and_then(Reason::from_code)
            .ok_or_else(|| invalid("vm keeper response has an unknown reason"))?;
        let refcount = bytes
            .get(7..9)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or_else(|| invalid("vm keeper response is truncated"))?;
        let keeper_pid = bytes
            .get(9..13)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| invalid("vm keeper response is truncated"))?;
        Ok(Self {
            reason,
            refcount,
            keeper_pid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("valid id")
    }

    #[test]
    fn mac4_register_encodes_to_exact_bytes() {
        let bytes = Request::Register(id("ab")).encode();
        assert_eq!(bytes, b"FCVK\x01\x01\x00\x02ab".to_vec());
    }

    #[test]
    fn mac4_status_encodes_to_exact_bytes() {
        assert_eq!(Request::Status.encode(), b"FCVK\x01\x03\x00\x00".to_vec());
    }

    #[test]
    fn mac4_request_round_trips() {
        for req in [
            Request::Register(id("c-1.x_y")),
            Request::Unregister(id("c-1")),
            Request::Status,
        ] {
            assert_eq!(Request::decode(&req.encode()).expect("decode"), req);
        }
    }

    #[test]
    fn mac4_response_encodes_to_exact_bytes_and_round_trips() {
        let r = Response {
            reason: Reason::CapacityExceeded,
            refcount: 64,
            keeper_pid: 0x0102_0304,
        };
        assert_eq!(
            r.encode(),
            b"FCVK\x01\x80\x03\x00\x40\x01\x02\x03\x04".to_vec()
        );
        assert_eq!(Response::decode(&r.encode()).expect("decode"), r);
    }

    #[test]
    fn mac4_request_rejects_malformed_inputs() {
        let ok = Request::Register(id("ab")).encode();
        let mut bad_magic = ok.clone();
        bad_magic[0] = b'X';
        let mut bad_version = ok.clone();
        bad_version[4] = 2;
        let mut bad_kind = ok.clone();
        bad_kind[5] = 9;
        let mut long_len = ok.clone();
        long_len[7] = 3;
        let mut nul_id = ok.clone();
        nul_id[8] = 0;
        let mut status_with_id = b"FCVK\x01\x03\x00\x01".to_vec();
        status_with_id.extend_from_slice(b"a");
        let empty_id = b"FCVK\x01\x01\x00\x00".to_vec();
        let too_long = {
            let mut v = b"FCVK\x01\x01\x01\x00".to_vec();
            v.extend(std::iter::repeat_n(b'a', 256));
            v
        };
        let exactly_max = {
            let mut v = b"FCVK\x01\x01\x00\xff".to_vec();
            v.extend(std::iter::repeat_n(b'a', 255));
            v
        };
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("short", b"FCVK".to_vec()),
            ("magic", bad_magic),
            ("version", bad_version),
            ("kind", bad_kind),
            ("length", long_len),
            ("nul", nul_id),
            ("status-id", status_with_id),
            ("empty-id", empty_id),
            ("too-long", too_long),
        ] {
            let e = Request::decode(&bytes).expect_err(name);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{name}");
        }
        assert!(Request::decode(&exactly_max).is_ok());
    }

    #[test]
    fn mac4_response_rejects_malformed_inputs() {
        let ok = Response {
            reason: Reason::Ok,
            refcount: 1,
            keeper_pid: 7,
        }
        .encode();
        let mut bad_reason = ok.clone();
        bad_reason[6] = 200;
        let mut bad_kind = ok.clone();
        bad_kind[5] = 1;
        for bytes in [Vec::new(), ok[..12].to_vec(), bad_reason, bad_kind] {
            assert!(Response::decode(&bytes).is_err());
        }
    }
}
