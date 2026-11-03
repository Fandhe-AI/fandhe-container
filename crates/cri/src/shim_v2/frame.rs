//! ttrpc のフレームヘッダ（10 バイト。CRI-5・TASK-62.1・MS-7・REPAIR-2）。
//!
//! `length: u32`（ペイロードのみの長さ）・`stream_id: u32`・`type: u8`・`flags: u8`、整数はビッグエンディアン。
//! [`FrameHeader::from_bytes`] が長さの上限・type・type ごとのフラグを検証してから値を返すため、
//! 壊れたヘッダはこの型で表現できない。サーバーは検証済みの長さだけをアロケーションに使う。
//! I/O は行わない（読み書きは `server`）。

/// ヘッダの長さ（バイト）。
pub const HEADER_LEN: usize = 10;
/// ペイロード長の上限（4 MiB。ttrpc の `messageLengthMax`）。
pub const MAX_PAYLOAD_LEN: u32 = 4 << 20;

/// Request のフラグ: remote closed。
pub const FLAG_REMOTE_CLOSED: u8 = 0x01;
/// Request のフラグ: remote open（ストリーミング。本実装は拒否する）。
pub const FLAG_REMOTE_OPEN: u8 = 0x02;
/// Data のフラグ: no data。
pub const FLAG_NO_DATA: u8 = 0x04;

/// フレームの種別。未知の値は表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// クライアントからの要求（0x01）。
    Request,
    /// サーバーからの応答（0x02）。
    Response,
    /// ストリームのデータ（0x03）。unary では使わない。
    Data,
}

impl MessageType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Response),
            0x03 => Some(Self::Data),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Request => 0x01,
            Self::Response => 0x02,
            Self::Data => 0x03,
        }
    }

    /// type ごとに許すフラグのビット集合。
    fn allowed_flags(self) -> u8 {
        match self {
            Self::Request => FLAG_REMOTE_CLOSED | FLAG_REMOTE_OPEN,
            Self::Response => 0,
            Self::Data => FLAG_REMOTE_CLOSED | FLAG_NO_DATA,
        }
    }
}

/// ヘッダの検証エラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// ペイロード長が上限を超えた。
    PayloadTooLarge {
        /// ヘッダが申告した長さ。
        length: u32,
    },
    /// 未知の type。
    UnknownType(u8),
    /// type に対して許されないフラグ。
    InvalidFlags {
        /// type。
        message_type: MessageType,
        /// 受けたフラグ。
        flags: u8,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { length } => write!(f, "payload length {length} exceeds limit"),
            Self::UnknownType(t) => write!(f, "unknown message type {t:#04x}"),
            Self::InvalidFlags { flags, .. } => write!(f, "invalid flags {flags:#04x}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// 検証済みの 10 バイトヘッダ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    length: u32,
    stream_id: u32,
    message_type: MessageType,
    flags: u8,
}

impl FrameHeader {
    /// 組み立てる。長さの上限とフラグを検証する。
    pub fn new(
        length: u32,
        stream_id: u32,
        message_type: MessageType,
        flags: u8,
    ) -> Result<Self, FrameError> {
        if length > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge { length });
        }
        if flags & !message_type.allowed_flags() != 0 {
            return Err(FrameError::InvalidFlags {
                message_type,
                flags,
            });
        }
        Ok(Self {
            length,
            stream_id,
            message_type,
            flags,
        })
    }

    /// 10 バイトから復号する。上限超過・未知の type・不正なフラグは拒否する。
    pub fn from_bytes(b: &[u8; HEADER_LEN]) -> Result<Self, FrameError> {
        let [l0, l1, l2, l3, s0, s1, s2, s3, ty, flags] = *b;
        let length = u32::from_be_bytes([l0, l1, l2, l3]);
        let stream_id = u32::from_be_bytes([s0, s1, s2, s3]);
        if length > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge { length });
        }
        let message_type = MessageType::from_u8(ty).ok_or(FrameError::UnknownType(ty))?;
        Self::new(length, stream_id, message_type, flags)
    }

    /// 10 バイトへ符号化する。
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let [l0, l1, l2, l3] = self.length.to_be_bytes();
        let [s0, s1, s2, s3] = self.stream_id.to_be_bytes();
        [
            l0,
            l1,
            l2,
            l3,
            s0,
            s1,
            s2,
            s3,
            self.message_type.as_u8(),
            self.flags,
        ]
    }

    /// ペイロード長。
    pub fn length(&self) -> u32 {
        self.length
    }

    /// stream id。
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// 種別。
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// フラグ。
    pub fn flags(&self) -> u8 {
        self.flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-5: 具体的なバイト列での往復。
    #[test]
    fn cri5_header_roundtrip_concrete_bytes() {
        let bytes = [0, 0, 0, 5, 0, 0, 0, 1, 0x01, 0x00];
        let h = FrameHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h.length(), 5);
        assert_eq!(h.stream_id(), 1);
        assert_eq!(h.message_type(), MessageType::Request);
        assert_eq!(h.flags(), 0);
        assert_eq!(h.to_bytes(), bytes);
    }

    /// CRI-5: 上限ちょうどは通り、超過は確保の前に拒否する。
    #[test]
    fn cri5_length_limit() {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(&MAX_PAYLOAD_LEN.to_be_bytes());
        b[8] = 0x01;
        assert!(FrameHeader::from_bytes(&b).is_ok());
        b[..4].copy_from_slice(&(MAX_PAYLOAD_LEN + 1).to_be_bytes());
        assert_eq!(
            FrameHeader::from_bytes(&b),
            Err(FrameError::PayloadTooLarge {
                length: MAX_PAYLOAD_LEN + 1
            })
        );
    }

    /// CRI-5: 未知の type と許さないフラグを拒否する。
    #[test]
    fn cri5_rejects_unknown_type_and_flags() {
        for ty in [0x00u8, 0x04, 0xff] {
            let b = [0, 0, 0, 0, 0, 0, 0, 1, ty, 0];
            assert_eq!(
                FrameHeader::from_bytes(&b),
                Err(FrameError::UnknownType(ty))
            );
        }
        // Response はフラグ無し。Request は 0x04 を許さない。Data は remote open を許さない。
        for (ty, fl) in [(0x02u8, 0x01u8), (0x01, 0x04), (0x03, 0x02)] {
            let b = [0, 0, 0, 0, 0, 0, 0, 1, ty, fl];
            assert!(matches!(
                FrameHeader::from_bytes(&b),
                Err(FrameError::InvalidFlags { .. })
            ));
        }
    }
}
