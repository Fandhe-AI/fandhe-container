//! venus コマンドストリーム用の境界検査つき読み取りカーソル（GPU-6・TASK-172.2）。
//!
//! 出典の wire 規則（VK_EXT_command_serialization。venus-protocol v1.1.3）: リトルエンディアン、
//! 32bit 整列、64bit 件数、ポインタ配列は件数＋値列で末尾を 32bit にパディングする。
//! 将来、ring／コマンドストリーム実行（#765）や各コマンドの引数パーサ（TASK-177.x）が本カーソルで
//! ゲスト由来の untrusted バイト列を読む。借用のみで確保しない。全読み取りが `Result` を返し、
//! 添字アクセス・`unwrap` を使わない。

use super::error::VenusWireError;

/// 配列件数の上限（件）。件数を確保に使う前に必ず検証する（無制限確保による DoS 防止）。
/// 1 コマンドストリームが 1 MiB 級を超える配列を要求する実用ケースは骨格段階で想定せず、
/// 引数パーサ導入時（TASK-177.x）に各コマンドの実測で見直す。
pub const MAX_ARRAY_LEN: u64 = 1 << 20;

/// `&[u8]` 上の読み取りカーソル。
#[derive(Debug, Clone)]
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// 先頭からの読み取り済みバイト数。
    pub fn position(&self) -> usize {
        self.pos
    }

    /// 未読バイト数。
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VenusWireError> {
        let truncated = VenusWireError::Truncated {
            needed: n,
            remaining: self.remaining(),
        };
        let end = self.pos.checked_add(n).ok_or(truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(truncated)?;
        self.pos = end;
        Ok(s)
    }

    pub fn read_u32(&mut self) -> Result<u32, VenusWireError> {
        let raw = self.take(4)?;
        let arr: [u8; 4] = raw.try_into().map_err(|_| VenusWireError::Truncated {
            needed: 4,
            remaining: raw.len(),
        })?;
        Ok(u32::from_le_bytes(arr))
    }

    /// enum は `int32_t` として符号化される。
    pub fn read_i32(&mut self) -> Result<i32, VenusWireError> {
        self.read_u32().map(|v| v as i32)
    }

    /// 64bit 値（ハンドル ID・`size_t`・配列件数）。
    pub fn read_u64(&mut self) -> Result<u64, VenusWireError> {
        let raw = self.take(8)?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| VenusWireError::Truncated {
            needed: 8,
            remaining: raw.len(),
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    /// 64bit の件数を読み、`max` 超過と `usize` 変換失敗を拒否する。
    pub fn read_array_len(&mut self, max: u64) -> Result<usize, VenusWireError> {
        let n = self.read_u64()?;
        if n > max {
            return Err(VenusWireError::LengthExceeded { requested: n, max });
        }
        usize::try_from(n).map_err(|_| VenusWireError::LengthExceeded { requested: n, max })
    }

    /// `len` バイトの blob を借用で返し、消費量は 4 バイト境界へ切り上げる（パディングを読み飛ばす）。
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], VenusWireError> {
        let padded = len
            .checked_add(3)
            .map(|v| v & !3usize)
            .ok_or(VenusWireError::Misaligned { len })?;
        let chunk = self.take(padded)?;
        chunk.get(..len).ok_or(VenusWireError::Truncated {
            needed: len,
            remaining: chunk.len(),
        })
    }
}
