//! `KVM_RUN` の VM exit の型と、`kvm_run` 領域のバイト列からの復号（TASK-74.4.1・MVM-1。OS 非依存）。
//!
//! `device::VcpuFd::run_once` が `KVM_RUN` の戻り後に `decode_exit` を呼び、vCPU fd に mmap した
//! `kvm_run` 領域（`linux/kvm.h` の `struct kvm_run`）を [`VcpuExit`] へコピーして返す。OS 非依存にしてあるのは、
//! TASK-74.4.2（#883。`crate::dispatch` が exit を各デバイスモデルへ振り分ける）が KVM なしで単体テストできるようにするため。
//!
//! # 応答の書き戻し（TASK-74.4.2・MVM-1）
//! ゲストの読み出し（IN・MMIO read）は、次の `KVM_RUN` の前に応答値を `kvm_run` 領域へ書かないと完了しない。
//! `complete_io_in` / `complete_mmio_read` が領域の exit を読み直して種別・向き・長さを照合してから書く
//! （不一致は fail-closed）。呼び出しは `device::VcpuFd::handle_exit` が担う。
//!
//! # 未実装（REPAIR-3）
//! - vCPU の外部からの停止（TASK-75）
//!
//! # 外部入力としての検証
//! `kvm_run` 領域の内容はカーネル（と間接的にゲスト）が書いた値であり、各フィールドを検証してから使う
//! （coding-rust.md「エラーハンドリング」）。`size` は 1 / 2 / 4、`count` は 1 以上、`data_offset + size * count` は
//! 領域内、MMIO の `len` は 1..=8。違反は [`MicrovmErrorCode::Internal`] の `malformed KVM exit` で返す。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// `struct kvm_run` の `exit_reason` のオフセット（`linux/kvm.h`）。
pub(crate) const RUN_EXIT_REASON: usize = 8;
/// `struct kvm_run` の exit 情報 union の先頭オフセット（s390 以外）。
pub(crate) const RUN_UNION: usize = 32;
/// `kvm_run` 領域として最低限必要な大きさ（union の先頭 + 余裕）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const RUN_MIN_LEN: usize = RUN_UNION + 256;

const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_SHUTDOWN: u32 = 8;
const KVM_EXIT_FAIL_ENTRY: u32 = 9;
const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
const KVM_EXIT_IO_IN: u8 = 0;
const KVM_EXIT_IO_OUT: u8 = 1;

/// I/O ポートアクセスの向き。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// ゲストがポートから読む。応答値は `VcpuFd::handle_exit` が書き戻す（TASK-74.4.2）。
    In,
    /// ゲストがポートへ書く。
    Out,
}

/// `KVM_RUN` が戻った理由（VM exit）。
///
/// `#[non_exhaustive]` のため、他 crate の `match` は網羅にできない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VcpuExit {
    /// ポート I/O。`Out` のとき `data` はゲストが書いた `size * count` バイト。`In` のとき `data` は空
    /// （応答値は `VcpuFd::handle_exit` が書き戻す。TASK-74.4.2）。
    Io {
        direction: IoDirection,
        port: u16,
        size: u8,
        count: u32,
        data: Vec<u8>,
    },
    /// MMIO。`is_write` のとき `data[..len]` がゲストの書いた値。読み出しの応答は `VcpuFd::handle_exit` が書き戻す（TASK-74.4.2）。
    Mmio {
        phys_addr: u64,
        data: [u8; 8],
        len: u32,
        is_write: bool,
    },
    /// `HLT` 命令（in-kernel irqchip が無いためユーザー空間へ出る）。
    Hlt,
    /// ゲストのシャットダウン（トリプルフォールト等）。
    Shutdown,
    /// VM entry の失敗。
    FailEntry {
        hardware_entry_failure_reason: u64,
        cpu: u32,
    },
    /// KVM の内部エラー。
    InternalError { suberror: u32 },
    /// `KVM_RUN` がシグナル等で中断された（EINTR / EAGAIN。正常系。再実行できる）。
    Interrupted,
    /// 上記以外の exit（番号のみ保持。必要になれば型を足す）。
    Other { exit_reason: u32 },
}

/// `kvm_run` 領域の読み口。`KvmRunMap` が実装し、試験は `Vec<u8>` の実装を使う。
pub(crate) trait RunArea {
    /// 領域の長さ。
    fn len(&self) -> usize;
    /// `off..off + buf.len()` を `buf` へコピーする。範囲外は `Err`。
    fn copy_out(&self, off: usize, buf: &mut [u8]) -> Result<(), ()>;
}

/// `kvm_run` 領域の書き口（応答値の書き戻し用。TASK-74.4.2）。`KvmRunMap` が `&mut self` でだけ実装する。
pub(crate) trait RunAreaMut: RunArea {
    /// `buf` を `off..off + buf.len()` へコピーする。範囲外は `Err`。
    fn copy_in(&mut self, off: usize, buf: &[u8]) -> Result<(), ()>;
}

fn malformed(what: &str) -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Internal,
        format!("malformed KVM exit ({what})"),
    )
}

fn read_u8(a: &impl RunArea, off: usize) -> Result<u8, MicrovmError> {
    let mut b = [0u8; 1];
    a.copy_out(off, &mut b)
        .map_err(|()| malformed("out of range"))?;
    Ok(u8::from_ne_bytes(b))
}

fn read_u16(a: &impl RunArea, off: usize) -> Result<u16, MicrovmError> {
    let mut b = [0u8; 2];
    a.copy_out(off, &mut b)
        .map_err(|()| malformed("out of range"))?;
    Ok(u16::from_ne_bytes(b))
}

fn read_u32(a: &impl RunArea, off: usize) -> Result<u32, MicrovmError> {
    let mut b = [0u8; 4];
    a.copy_out(off, &mut b)
        .map_err(|()| malformed("out of range"))?;
    Ok(u32::from_ne_bytes(b))
}

fn read_u64(a: &impl RunArea, off: usize) -> Result<u64, MicrovmError> {
    let mut b = [0u8; 8];
    a.copy_out(off, &mut b)
        .map_err(|()| malformed("out of range"))?;
    Ok(u64::from_ne_bytes(b))
}

/// `kvm_run` 領域から exit を復号する。`KVM_RUN` が成功で戻った直後にだけ呼ぶ。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn decode_exit(area: &impl RunArea) -> Result<VcpuExit, MicrovmError> {
    let reason = read_u32(area, RUN_EXIT_REASON)?;
    match reason {
        KVM_EXIT_IO => decode_io(area),
        KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
        KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
        KVM_EXIT_MMIO => {
            let phys_addr = read_u64(area, RUN_UNION)?;
            let mut data = [0u8; 8];
            area.copy_out(RUN_UNION + 8, &mut data)
                .map_err(|()| malformed("out of range"))?;
            let len = read_u32(area, RUN_UNION + 16)?;
            let is_write = read_u8(area, RUN_UNION + 20)? != 0;
            if !(1..=8).contains(&len) {
                return Err(malformed("mmio len"));
            }
            Ok(VcpuExit::Mmio {
                phys_addr,
                data,
                len,
                is_write,
            })
        }
        KVM_EXIT_FAIL_ENTRY => Ok(VcpuExit::FailEntry {
            hardware_entry_failure_reason: read_u64(area, RUN_UNION)?,
            cpu: read_u32(area, RUN_UNION + 8)?,
        }),
        KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError {
            suberror: read_u32(area, RUN_UNION)?,
        }),
        other => Ok(VcpuExit::Other { exit_reason: other }),
    }
}

/// 検証済みの `KVM_EXIT_IO` ヘッダ。
struct IoHeader {
    direction: IoDirection,
    size: u8,
    port: u16,
    count: u32,
    /// 領域内のデータ位置。
    off: usize,
    /// `size * count`（領域内に収まることを検証済み）。
    total: usize,
}

/// `KVM_EXIT_IO` のヘッダを読んで検証する（`decode_io` と `complete_io_in` が共有する）。
fn read_io_header(area: &impl RunArea) -> Result<IoHeader, MicrovmError> {
    let dir = read_u8(area, RUN_UNION)?;
    let size = read_u8(area, RUN_UNION + 1)?;
    let port = read_u16(area, RUN_UNION + 2)?;
    let count = read_u32(area, RUN_UNION + 4)?;
    let data_offset = read_u64(area, RUN_UNION + 8)?;
    let direction = match dir {
        KVM_EXIT_IO_IN => IoDirection::In,
        KVM_EXIT_IO_OUT => IoDirection::Out,
        _ => return Err(malformed("io direction")),
    };
    if !matches!(size, 1 | 2 | 4) {
        return Err(malformed("io size"));
    }
    if count == 0 {
        return Err(malformed("io count"));
    }
    let total = usize::from(size)
        .checked_mul(usize::try_from(count).map_err(|_| malformed("io count"))?)
        .ok_or_else(|| malformed("io length"))?;
    let off = usize::try_from(data_offset).map_err(|_| malformed("io data_offset"))?;
    let end = off
        .checked_add(total)
        .ok_or_else(|| malformed("io data_offset"))?;
    if end > area.len() {
        return Err(malformed("io data_offset"));
    }
    Ok(IoHeader {
        direction,
        size,
        port,
        count,
        off,
        total,
    })
}

fn decode_io(area: &impl RunArea) -> Result<VcpuExit, MicrovmError> {
    let h = read_io_header(area)?;
    let data = match h.direction {
        IoDirection::In => Vec::new(),
        IoDirection::Out => {
            let mut v = vec![0u8; h.total];
            area.copy_out(h.off, &mut v)
                .map_err(|()| malformed("io data_offset"))?;
            v
        }
    };
    Ok(VcpuExit::Io {
        direction: h.direction,
        port: h.port,
        size: h.size,
        count: h.count,
        data,
    })
}

fn completion_mismatch(what: &str) -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Internal,
        format!("KVM exit completion mismatch ({what})"),
    )
}

/// ポート IN の応答 `data`（`size * count` バイト）を `kvm_run` 領域へ書き戻す。
///
/// 領域の exit が IN の `KVM_EXIT_IO` で、`data.len()` がヘッダの `size * count` と一致するときだけ書く
/// （それ以外は `Internal`。ゲストの誤動作でなくホスト側の呼び出しの矛盾）。`VcpuFd::handle_exit` が呼ぶ。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn complete_io_in(area: &mut impl RunAreaMut, data: &[u8]) -> Result<(), MicrovmError> {
    if read_u32(area, RUN_EXIT_REASON)? != KVM_EXIT_IO {
        return Err(completion_mismatch("exit reason"));
    }
    let h = read_io_header(area)?;
    if h.direction != IoDirection::In {
        return Err(completion_mismatch("io direction"));
    }
    if data.len() != h.total {
        return Err(completion_mismatch("io length"));
    }
    area.copy_in(h.off, data)
        .map_err(|()| completion_mismatch("io data_offset"))
}

/// MMIO 読み出しの応答 `data`（`len` バイト）を `kvm_run` 領域へ書き戻す（`VcpuFd::handle_exit` が呼ぶ）。
///
/// 領域の exit が読み出しの `KVM_EXIT_MMIO` で、`data.len()` が `len` と一致するときだけ書く。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn complete_mmio_read(
    area: &mut impl RunAreaMut,
    data: &[u8],
) -> Result<(), MicrovmError> {
    if read_u32(area, RUN_EXIT_REASON)? != KVM_EXIT_MMIO {
        return Err(completion_mismatch("exit reason"));
    }
    let len = read_u32(area, RUN_UNION + 16)?;
    if read_u8(area, RUN_UNION + 20)? != 0 {
        return Err(completion_mismatch("mmio direction"));
    }
    if !(1..=8).contains(&len) || usize::try_from(len).ok() != Some(data.len()) {
        return Err(completion_mismatch("mmio length"));
    }
    area.copy_in(RUN_UNION + 8, data)
        .map_err(|()| completion_mismatch("mmio data"))
}

/// 試験用の `Vec<u8>` 実装（`dispatch` の試験からも使う）。
#[cfg(test)]
pub(crate) mod test_support {
    use super::{RunArea, RunAreaMut};

    impl RunArea for Vec<u8> {
        fn len(&self) -> usize {
            Vec::len(self)
        }
        fn copy_out(&self, off: usize, buf: &mut [u8]) -> Result<(), ()> {
            let end = off.checked_add(buf.len()).ok_or(())?;
            let src = self.get(off..end).ok_or(())?;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    impl RunAreaMut for Vec<u8> {
        fn copy_in(&mut self, off: usize, buf: &[u8]) -> Result<(), ()> {
            let end = off.checked_add(buf.len()).ok_or(())?;
            let dst = self.get_mut(off..end).ok_or(())?;
            dst.copy_from_slice(buf);
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn area(reason: u32) -> Vec<u8> {
        let mut v = vec![0u8; 4096 + 64];
        v[RUN_EXIT_REASON..RUN_EXIT_REASON + 4].copy_from_slice(&reason.to_ne_bytes());
        v
    }

    fn put(v: &mut [u8], off: usize, b: &[u8]) {
        v[off..off + b.len()].copy_from_slice(b);
    }

    fn io_area(dir: u8, size: u8, port: u16, count: u32, data_offset: u64) -> Vec<u8> {
        let mut v = area(KVM_EXIT_IO);
        put(&mut v, RUN_UNION, &[dir, size]);
        put(&mut v, RUN_UNION + 2, &port.to_ne_bytes());
        put(&mut v, RUN_UNION + 4, &count.to_ne_bytes());
        put(&mut v, RUN_UNION + 8, &data_offset.to_ne_bytes());
        v
    }

    /// MVM-1: 実機で観測した `out 0x10, al`（al = 0x42）の exit。
    #[test]
    fn decodes_io_out_observed_on_real_kvm() {
        let mut v = io_area(1, 1, 0x10, 1, 4096);
        v[4096] = 0x42;
        assert_eq!(
            decode_exit(&v).unwrap(),
            VcpuExit::Io {
                direction: IoDirection::Out,
                port: 0x10,
                size: 1,
                count: 1,
                data: vec![0x42],
            }
        );
    }

    /// MVM-1: データ無しの IN exit を復号する。
    #[test]
    fn decodes_io_in_without_data() {
        let v = io_area(0, 4, 0x3f8, 2, 4096);
        assert_eq!(
            decode_exit(&v).unwrap(),
            VcpuExit::Io {
                direction: IoDirection::In,
                port: 0x3f8,
                size: 4,
                count: 2,
                data: vec![],
            }
        );
    }

    /// MVM-1: HLT・SHUTDOWN・未知の exit reason を復号する。
    #[test]
    fn decodes_hlt_shutdown_and_unknown() {
        assert_eq!(decode_exit(&area(KVM_EXIT_HLT)).unwrap(), VcpuExit::Hlt);
        assert_eq!(
            decode_exit(&area(KVM_EXIT_SHUTDOWN)).unwrap(),
            VcpuExit::Shutdown
        );
        assert_eq!(
            decode_exit(&area(24)).unwrap(),
            VcpuExit::Other { exit_reason: 24 }
        );
    }

    /// MVM-1: MMIO の read / write exit を復号する。
    #[test]
    fn decodes_mmio_write_and_read() {
        let mut v = area(KVM_EXIT_MMIO);
        put(&mut v, RUN_UNION, &0xd000_0000u64.to_ne_bytes());
        put(&mut v, RUN_UNION + 8, &[1, 2, 3, 4, 0, 0, 0, 0]);
        put(&mut v, RUN_UNION + 16, &4u32.to_ne_bytes());
        v[RUN_UNION + 20] = 1;
        assert_eq!(
            decode_exit(&v).unwrap(),
            VcpuExit::Mmio {
                phys_addr: 0xd000_0000,
                data: [1, 2, 3, 4, 0, 0, 0, 0],
                len: 4,
                is_write: true,
            }
        );
        v[RUN_UNION + 20] = 0;
        match decode_exit(&v).unwrap() {
            VcpuExit::Mmio { is_write, .. } => assert!(!is_write),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// MVM-1: FAIL_ENTRY・INTERNAL_ERROR の exit を復号する。
    #[test]
    fn decodes_fail_entry_and_internal_error() {
        let mut v = area(KVM_EXIT_FAIL_ENTRY);
        put(&mut v, RUN_UNION, &0x7u64.to_ne_bytes());
        put(&mut v, RUN_UNION + 8, &3u32.to_ne_bytes());
        assert_eq!(
            decode_exit(&v).unwrap(),
            VcpuExit::FailEntry {
                hardware_entry_failure_reason: 7,
                cpu: 3
            }
        );
        let mut v = area(KVM_EXIT_INTERNAL_ERROR);
        put(&mut v, RUN_UNION, &1u32.to_ne_bytes());
        assert_eq!(
            decode_exit(&v).unwrap(),
            VcpuExit::InternalError { suberror: 1 }
        );
    }

    /// MVM-1 / REPAIR-2: 不正な IO exit を拒否する。
    #[test]
    fn rejects_malformed_io() {
        let bad = [
            ("io size", io_area(1, 3, 0x10, 1, 4096)),
            ("io count", io_area(1, 1, 0x10, 0, 4096)),
            ("io direction", io_area(2, 1, 0x10, 1, 4096)),
            ("io data_offset", io_area(1, 4, 0x10, 1, u64::MAX)),
            ("io data_offset", io_area(1, 1, 0x10, 1, 4096 + 64)),
            ("io data_offset", io_area(1, 4, 0x10, u32::MAX, 4096)),
        ];
        for (what, v) in bad {
            let e = decode_exit(&v).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::Internal);
            assert_eq!(e.message(), format!("malformed KVM exit ({what})"));
        }
    }

    /// MVM-1 / REPAIR-2: 不正な MMIO 長を拒否する。
    #[test]
    fn rejects_malformed_mmio_len() {
        for len in [0u32, 9] {
            let mut v = area(KVM_EXIT_MMIO);
            put(&mut v, RUN_UNION + 16, &len.to_ne_bytes());
            let e = decode_exit(&v).unwrap_err();
            assert_eq!(e.message(), "malformed KVM exit (mmio len)");
        }
    }

    /// MVM-1 / REPAIR-2: 短すぎる kvm_run 領域を拒否する。
    #[test]
    fn rejects_too_short_area() {
        let e = decode_exit(&vec![0u8; 4]).unwrap_err();
        assert_eq!(e.message(), "malformed KVM exit (out of range)");
    }

    /// MVM-1・TASK-74.4.2: IN の応答が `data_offset` に `size * count` バイト書かれる。
    #[test]
    fn completes_io_in_response() {
        let mut v = io_area(0, 2, 0x10, 2, 4096);
        complete_io_in(&mut v, &[1, 2, 3, 4]).unwrap();
        assert_eq!(&v[4096..4100], &[1, 2, 3, 4]);
        assert_eq!(v[4100], 0);
    }

    /// MVM-1・TASK-74.4.2: MMIO read の応答が `RUN_UNION + 8` に `len` バイト書かれる。
    #[test]
    fn completes_mmio_read_response() {
        let mut v = area(KVM_EXIT_MMIO);
        put(&mut v, RUN_UNION + 16, &4u32.to_ne_bytes());
        complete_mmio_read(&mut v, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(
            &v[RUN_UNION + 8..RUN_UNION + 13],
            &[0xde, 0xad, 0xbe, 0xef, 0]
        );
    }

    /// MVM-1・TASK-74.4.2: 種別・向き・長さの不一致は書かずに拒否する（fail-closed）。
    #[test]
    fn rejects_mismatched_completion() {
        let msg = |e: MicrovmError| {
            assert_eq!(e.code(), MicrovmErrorCode::Internal);
            e.message().to_string()
        };
        // OUT への IN 応答。
        let mut v = io_area(1, 1, 0x10, 1, 4096);
        assert_eq!(
            msg(complete_io_in(&mut v, &[1]).unwrap_err()),
            "KVM exit completion mismatch (io direction)"
        );
        // 長さ不一致。
        let mut v = io_area(0, 2, 0x10, 1, 4096);
        assert_eq!(
            msg(complete_io_in(&mut v, &[1]).unwrap_err()),
            "KVM exit completion mismatch (io length)"
        );
        assert_eq!(v[4096], 0);
        // exit 種別の不一致。
        let mut v = area(KVM_EXIT_HLT);
        assert_eq!(
            msg(complete_io_in(&mut v, &[1]).unwrap_err()),
            "KVM exit completion mismatch (exit reason)"
        );
        assert_eq!(
            msg(complete_mmio_read(&mut v, &[1]).unwrap_err()),
            "KVM exit completion mismatch (exit reason)"
        );
        // 範囲外の data_offset は malformed のまま拒否される。
        let mut v = io_area(0, 1, 0x10, 1, u64::MAX);
        assert_eq!(
            msg(complete_io_in(&mut v, &[1]).unwrap_err()),
            "malformed KVM exit (io data_offset)"
        );
        // MMIO write への応答。
        let mut v = area(KVM_EXIT_MMIO);
        put(&mut v, RUN_UNION + 16, &1u32.to_ne_bytes());
        v[RUN_UNION + 20] = 1;
        assert_eq!(
            msg(complete_mmio_read(&mut v, &[1]).unwrap_err()),
            "KVM exit completion mismatch (mmio direction)"
        );
        // MMIO 長の不一致。
        v[RUN_UNION + 20] = 0;
        assert_eq!(
            msg(complete_mmio_read(&mut v, &[1, 2]).unwrap_err()),
            "KVM exit completion mismatch (mmio length)"
        );
    }
}
