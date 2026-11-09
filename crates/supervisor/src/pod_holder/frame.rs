//! pod 保持役の READY / ERROR フレーム（固定 64 バイト。OS 非依存の純関数。CRI-2・SEC-5・REPAIR-2・REPAIR-5・#2874）。
//!
//! 保持役（`holder`）が stdout へ 1 回だけ書き、受信側（plugin-cri の起動処理〔H6・#2877〕と実機試験）が
//! [`PodHolderFrame::decode`] で解釈する。生の `Vec<u8>` を手で組まず、全欄を検証した型だけを通す。
//! 受信側は長さを [`FRAME_LEN`] に固定し、期限つきで読む（`client::read_ready`）ので、無制限確保も無期限待ちも無い。
//!
//! 形式（整数は LE）: magic 4・version 1・kind 1・reserved 2（0）・欄 A 8・user dev/ino 16・ipc dev/ino 16・net dev/ino 16。
//! READY の欄 A は pid、ERROR の欄 A はエラーコードのワイヤー値で、使わない欄は 0 にする。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};

/// フレームの長さ（バイト）。
pub const FRAME_LEN: usize = 64;

const MAGIC: [u8; 4] = *b"FCPH";
const VERSION: u8 = 1;
const KIND_READY: u8 = 1;
const KIND_ERROR: u8 = 2;

/// nsfs 上の namespace の素性（`st_dev`・`st_ino`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsId {
    /// `st_dev`。
    pub dev: u64,
    /// `st_ino`。
    pub ino: u64,
}

/// READY の内容（照合済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PodHolderReady {
    /// 保持役の pid（exec をまたいで不変）。
    pid: u32,
    /// pod の user namespace。
    user: NsId,
    /// pod の ipc namespace。
    ipc: NsId,
    /// pod の net namespace（`lo` は up）。
    net: NsId,
}

impl PodHolderReady {
    /// 検証つきで作る。pid は `1..=i32::MAX`、ino は非 0 で互いに異なり、dev は 3 つで一致すること（nsfs は 1 つの
    /// superblock）。満たさなければ `FailedPrecondition`。
    pub fn new(pid: u32, user: NsId, ipc: NsId, net: NsId) -> Result<Self, TraitError> {
        let pid_ok = (1..=i32::MAX as u32).contains(&pid);
        let ino_ok = user.ino != 0
            && ipc.ino != 0
            && net.ino != 0
            && user.ino != ipc.ino
            && user.ino != net.ino
            && ipc.ino != net.ino;
        let dev_ok = user.dev == ipc.dev && user.dev == net.dev;
        if !(pid_ok && ino_ok && dev_ok) {
            return Err(bad("pod holder READY contents are inconsistent"));
        }
        Ok(Self {
            pid,
            user,
            ipc,
            net,
        })
    }

    /// 保持役の pid（検証済み。フィールドは非公開で、`new` を通らない値は作れない。REPAIR-2）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// pod の user namespace。
    pub fn user(&self) -> NsId {
        self.user
    }

    /// pod の ipc namespace。
    pub fn ipc(&self) -> NsId {
        self.ipc
    }

    /// pod の net namespace。
    pub fn net(&self) -> NsId {
        self.net
    }
}

/// デコード結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodHolderMessage {
    /// 保持役が確立を終えた。
    Ready(PodHolderReady),
    /// 保持役が確立前に失敗した（理由は分類のみ）。
    Error(ErrorCode),
}

/// エンコード済みの固定長フレーム。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodHolderFrame([u8; FRAME_LEN]);

/// `ErrorCode` の固定のワイヤー値（宣言順に依存しない）。`non_exhaustive` の未知の variant は 6（Internal）。
pub(crate) fn code_to_wire(code: ErrorCode) -> u64 {
    match code {
        ErrorCode::InvalidArgument => 1,
        ErrorCode::NotFound => 2,
        ErrorCode::AlreadyExists => 3,
        ErrorCode::FailedPrecondition => 4,
        ErrorCode::Unimplemented => 5,
        ErrorCode::Internal => 6,
        ErrorCode::PermissionDenied => 7,
        ErrorCode::Timeout => 8,
        ErrorCode::Unavailable => 9,
        ErrorCode::ResourceExhausted => 10,
        _ => 6,
    }
}

pub(crate) fn code_from_wire(v: u64) -> Option<ErrorCode> {
    Some(match v {
        1 => ErrorCode::InvalidArgument,
        2 => ErrorCode::NotFound,
        3 => ErrorCode::AlreadyExists,
        4 => ErrorCode::FailedPrecondition,
        5 => ErrorCode::Unimplemented,
        6 => ErrorCode::Internal,
        7 => ErrorCode::PermissionDenied,
        8 => ErrorCode::Timeout,
        9 => ErrorCode::Unavailable,
        10 => ErrorCode::ResourceExhausted,
        _ => return None,
    })
}

fn bad(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, message)
}

fn put(buf: &mut [u8; FRAME_LEN], at: usize, v: u64) {
    if let Some(dst) = buf.get_mut(at..at + 8) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

fn get(buf: &[u8], at: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(at..at + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

impl PodHolderFrame {
    /// READY フレームを作る。
    pub fn ready(r: &PodHolderReady) -> Self {
        let mut f = Self::header(KIND_READY);
        put(&mut f.0, 8, u64::from(r.pid));
        put(&mut f.0, 16, r.user.dev);
        put(&mut f.0, 24, r.user.ino);
        put(&mut f.0, 32, r.ipc.dev);
        put(&mut f.0, 40, r.ipc.ino);
        put(&mut f.0, 48, r.net.dev);
        put(&mut f.0, 56, r.net.ino);
        f
    }

    /// ERROR フレームを作る（欄 A にコード、残りは 0）。
    pub fn error(code: ErrorCode) -> Self {
        let mut f = Self::header(KIND_ERROR);
        put(&mut f.0, 8, code_to_wire(code));
        f
    }

    fn header(kind: u8) -> Self {
        let mut buf = [0u8; FRAME_LEN];
        if let Some(h) = buf.get_mut(0..4) {
            h.copy_from_slice(&MAGIC);
        }
        if let Some(b) = buf.get_mut(4) {
            *b = VERSION;
        }
        if let Some(b) = buf.get_mut(5) {
            *b = kind;
        }
        Self(buf)
    }

    /// ワイヤーのバイト列。
    pub fn as_bytes(&self) -> &[u8; FRAME_LEN] {
        &self.0
    }

    /// 受信したバイト列を解釈する。長さ・magic・version・kind・reserved・各欄の整合を検証し、満たさなければ
    /// 固定文言の `FailedPrecondition`（受信内容を文言へ含めない）。
    pub fn decode(bytes: &[u8]) -> Result<PodHolderMessage, TraitError> {
        if bytes.len() != FRAME_LEN {
            return Err(bad("pod holder frame has an unexpected length"));
        }
        if bytes.get(0..4) != Some(&MAGIC[..]) || bytes.get(4) != Some(&VERSION) {
            return Err(bad("pod holder frame has an unknown header"));
        }
        if bytes.get(6..8) != Some(&[0u8, 0u8][..]) {
            return Err(bad("pod holder frame has a non-zero reserved field"));
        }
        let word = |at| get(bytes, at).ok_or_else(|| bad("pod holder frame is truncated"));
        match bytes.get(5).copied() {
            Some(KIND_READY) => {
                let pid = u32::try_from(word(8)?)
                    .map_err(|_| bad("pod holder READY contents are inconsistent"))?;
                let ns = |at| -> Result<NsId, TraitError> {
                    Ok(NsId {
                        dev: word(at)?,
                        ino: word(at + 8)?,
                    })
                };
                Ok(PodHolderMessage::Ready(PodHolderReady::new(
                    pid,
                    ns(16)?,
                    ns(32)?,
                    ns(48)?,
                )?))
            }
            Some(KIND_ERROR) => {
                for at in [16, 24, 32, 40, 48, 56] {
                    if word(at)? != 0 {
                        return Err(bad("pod holder ERROR frame has non-zero unused fields"));
                    }
                }
                let code = code_from_wire(word(8)?)
                    .ok_or_else(|| bad("pod holder ERROR frame has an unknown code"))?;
                Ok(PodHolderMessage::Error(code))
            }
            _ => Err(bad("pod holder frame has an unknown kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(ino: u64) -> NsId {
        NsId {
            dev: 4,
            ino: 0xF000_0000 + ino,
        }
    }

    fn sample() -> PodHolderReady {
        PodHolderReady::new(4242, ns(1), ns(2), ns(3)).unwrap()
    }

    /// CRI-2・SEC-5・#2874: READY の往復とワイヤーのレイアウト（具体値）。
    #[test]
    fn cri2_pod_holder_ready_roundtrip_and_layout() {
        let f = PodHolderFrame::ready(&sample());
        let b = f.as_bytes();
        assert_eq!(&b[0..4], b"FCPH");
        assert_eq!((b[4], b[5], b[6], b[7]), (1, 1, 0, 0));
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 4242);
        assert_eq!(
            u64::from_le_bytes(b[24..32].try_into().unwrap()),
            0xF000_0001
        );
        assert_eq!(
            PodHolderFrame::decode(b).unwrap(),
            PodHolderMessage::Ready(sample())
        );
    }

    /// ERROR の往復と、コード表が `ErrorCode::ALL` を全単射で覆うこと（variant 追加の検出）。
    #[test]
    fn cri2_pod_holder_error_roundtrip_and_code_table_is_bijective() {
        let mut seen = std::collections::BTreeSet::new();
        for code in ErrorCode::ALL {
            let wire = code_to_wire(code);
            assert!(seen.insert(wire), "duplicate wire value {wire}");
            assert_eq!(code_from_wire(wire), Some(code));
            let f = PodHolderFrame::error(code);
            assert_eq!(
                PodHolderFrame::decode(f.as_bytes()).unwrap(),
                PodHolderMessage::Error(code)
            );
        }
        assert_eq!(seen.len(), ErrorCode::ALL.len());
        assert_eq!(code_from_wire(0), None);
        assert_eq!(code_from_wire(11), None);
    }

    /// 壊れた入力は固定文言の FailedPrecondition で拒否する。
    #[test]
    fn cri2_pod_holder_decode_rejects_malformed_frames() {
        let good = *PodHolderFrame::ready(&sample()).as_bytes();
        assert!(PodHolderFrame::decode(&good[..63]).is_err());
        let mut long = good.to_vec();
        long.push(0);
        assert!(PodHolderFrame::decode(&long).is_err());
        let mutate = |at: usize, v: u8| {
            let mut b = good;
            b[at] = v;
            PodHolderFrame::decode(&b)
        };
        for (at, v) in [(0, b'X'), (4, 2), (5, 9), (6, 1), (7, 1)] {
            let e = mutate(at, v).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition, "at {at}");
        }
        // pid 0 / 範囲外、ino 0、重複 ino、dev 不一致。
        let set = |at: usize, v: u64| {
            let mut b = good;
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
            PodHolderFrame::decode(&b)
        };
        assert!(set(8, 0).is_err());
        assert!(set(8, u64::from(u32::MAX)).is_err());
        assert!(set(8, u64::MAX).is_err());
        assert!(set(24, 0).is_err());
        assert!(set(40, 0xF000_0001).is_err());
        assert!(set(32, 5).is_err());
        // ERROR: 使わない欄が非 0、未知コード。
        let mut e = *PodHolderFrame::error(ErrorCode::Timeout).as_bytes();
        e[16] = 1;
        assert!(PodHolderFrame::decode(&e).is_err());
        let mut e = *PodHolderFrame::error(ErrorCode::Timeout).as_bytes();
        e[8..16].copy_from_slice(&99u64.to_le_bytes());
        assert!(PodHolderFrame::decode(&e).is_err());
    }

    /// 文言は固定で、受信内容を含まない。
    #[test]
    fn cri2_pod_holder_decode_error_text_is_fixed() {
        let mut b = *PodHolderFrame::ready(&sample()).as_bytes();
        b[0] = b'Z';
        let e = PodHolderFrame::decode(&b).unwrap_err();
        assert_eq!(e.message(), "pod holder frame has an unknown header");
    }
}
