//! VM exit（MMIO / ポート I/O）のデバイスモデルへの振り分け（TASK-74.4.2・MVM-1・MVM-4・MS-7。OS 非依存）。
//!
//! `device::VcpuFd::handle_exit` が `run_once` の戻り値（[`VcpuExit`]）を [`ExitDispatcher::dispatch`] へ渡し、
//! 登録済みの [`MmioDevice`]（virtio-mmio のトランスポートなど）または [`PortIoDevice`] へ相対オフセットで届ける。
//! ゲストの読み出し（IN・MMIO read）の応答は [`DispatchOutcome::read_response`] で取り出し、呼び出し側が
//! `kvm_run` 領域へ書き戻す（`crate::exit::complete_io_in` / `complete_mmio_read`）。OS 非依存にしてあるのは、
//! KVM なしで振り分けの規則を単体テストするため。`unsafe` は使わない。
//!
//! # 外部入力の扱い
//! アドレス・ポート・長さ・回数はゲストが間接的に決める非信頼入力。範囲検査は checked 演算と `get()` で行い、
//! 添字アクセス・`unwrap` を使わない。どのデバイスにも当たらないアクセス（空きポートの探査など）はゲストの
//! 正常動作なのでホストのエラーにせず、読み出しは全バイト `0xFF`、書き込みは捨てて
//! [`DispatchOutcome::Unhandled`] で返す（REPAIR-4 で呼び出し元が観測できる）。ホスト側の矛盾
//! （登録の誤り・MMIO / IO 以外の exit を渡す）は [`MicrovmError`]。
//!
//! # 未実装（REPAIR-3）
//! virtqueue の処理（TASK-74.2.2・74.3.1）・割り込み配送（TASK-74.2.3・74.3.2）は、
//! [`MmioAccess::Write`] の `QueueNotify` 等を受けた呼び出し元が後続 TASK で行う。PIO の具体デバイス
//! （シリアル等）も未実装。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::exit::{IoDirection, VcpuExit};
use crate::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome, VirtioDevice, VirtioMmioTransport};

/// 1 つの範囲表（MMIO / PIO それぞれ）に登録できるデバイス数の上限。
pub const MAX_BUS_DEVICES: usize = 32;
/// 1 回の PIO exit が扱う総バイト数（`size * count`）の上限。`decode_exit` が検証済みの `kvm_run` 領域の大きさ
/// （mmap サイズ）よりずっと小さく、不正な `VcpuExit` で巨大な応答バッファを確保させないための上限。
pub const MAX_PIO_TOTAL: usize = 1 << 20;
/// 未登録アクセスの読み出しで返すバイト値（空きバスは全ビット 1）。
const OPEN_BUS: u8 = 0xFF;

/// 登録したデバイスの識別子（登録順）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId(u32);

impl DeviceId {
    /// 登録順の番号（MMIO と PIO で別々に数える）。
    pub fn index(self) -> u32 {
        self.0
    }
}

/// MMIO 上のデバイスモデル。`offset` は登録した基底アドレスからの相対。
pub trait MmioDevice: Send {
    /// 読み出し。値は `data` へ書く（`data.len()` は 1〜8）。
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome;
    /// 書き込み。
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome;
}

impl<D: VirtioDevice + Send> MmioDevice for VirtioMmioTransport<D> {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        VirtioMmioTransport::read(self, offset, data)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        VirtioMmioTransport::write(self, offset, data)
    }
}

/// ポート I/O の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortIoOutcome {
    /// 処理した。
    Handled,
    /// 受け付けなかった（読み出しは呼び出し側が 0xFF 埋めにする）。
    Ignored,
}

/// ポート I/O 上のデバイスモデル。`offset` は登録した基底ポートからの相対。
/// `rep ins/outs` では同じポートに対し 1 要素ずつ `count` 回呼ばれる。
pub trait PortIoDevice: Send {
    /// 読み出し（`data.len()` は 1 / 2 / 4）。
    fn read(&mut self, offset: u16, data: &mut [u8]) -> PortIoOutcome;
    /// 書き込み（`data.len()` は 1 / 2 / 4）。
    fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome;
}

/// MMIO アクセスの結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmioAccess {
    /// 読み出し。応答は `data[..len]`。
    Read {
        outcome: MmioReadOutcome,
        data: [u8; 8],
        len: u32,
    },
    /// 書き込み。`QueueNotify` 等は呼び出し元が virtqueue 処理へつなげる。
    Write(MmioWriteOutcome),
}

/// どのデバイスにも当たらなかったアクセス（観測用。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnhandledAccess {
    Mmio {
        phys_addr: u64,
        len: u32,
        is_write: bool,
    },
    Pio {
        port: u16,
        size: u8,
        count: u32,
        direction: IoDirection,
    },
}

/// [`ExitDispatcher::dispatch`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DispatchOutcome {
    /// MMIO デバイスが処理した。
    Mmio {
        device: DeviceId,
        access: MmioAccess,
    },
    /// PIO デバイスが処理した。`response` は `In` のときだけ `size * count` バイト。
    Pio {
        device: DeviceId,
        direction: IoDirection,
        outcome: PortIoOutcome,
        response: Vec<u8>,
    },
    /// どのデバイスにも当たらなかった。読み出しの `response` は 0xFF 埋め、書き込みは空。
    Unhandled {
        access: UnhandledAccess,
        response: Vec<u8>,
    },
}

impl DispatchOutcome {
    /// ゲストの読み出しに返す応答バイト列。書き込みなら `None`。
    pub fn read_response(&self) -> Option<&[u8]> {
        match self {
            DispatchOutcome::Mmio {
                access: MmioAccess::Read { data, len, .. },
                ..
            } => data.get(..usize::try_from(*len).ok()?),
            DispatchOutcome::Mmio { .. } => None,
            DispatchOutcome::Pio { response, .. } | DispatchOutcome::Unhandled { response, .. } => {
                if response.is_empty() {
                    None
                } else {
                    Some(response)
                }
            }
        }
    }
}

struct Region<D: ?Sized> {
    base: u64,
    /// 排他的な終端（`base + len`）。
    end: u64,
    dev: Box<D>,
}

impl<D: ?Sized> Region<D> {
    /// `[start, start + len)` が全体としてこの範囲に収まるなら相対オフセットを返す。
    fn locate(&self, start: u64, len: u64) -> Option<u64> {
        let end = start.checked_add(len)?;
        if start >= self.base && end <= self.end {
            Some(start - self.base)
        } else {
            None
        }
    }
}

fn insert<D: ?Sized>(
    table: &mut Vec<Region<D>>,
    base: u64,
    end: u64,
    dev: Box<D>,
) -> Result<DeviceId, MicrovmError> {
    if table.len() >= MAX_BUS_DEVICES {
        return Err(MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            "too many devices registered",
        ));
    }
    if table.iter().any(|r| base < r.end && r.base < end) {
        return Err(MicrovmError::new(
            MicrovmErrorCode::AlreadyExists,
            "device range overlaps an existing registration",
        ));
    }
    let id = DeviceId(u32::try_from(table.len()).unwrap_or(u32::MAX));
    table.push(Region { base, end, dev });
    Ok(id)
}

/// MMIO・PIO の範囲表。exit を該当デバイスへ振り分ける。
#[derive(Default)]
pub struct ExitDispatcher {
    mmio: Vec<Region<dyn MmioDevice>>,
    pio: Vec<Region<dyn PortIoDevice>>,
}

impl std::fmt::Debug for ExitDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExitDispatcher")
            .field("mmio_devices", &self.mmio.len())
            .field("pio_devices", &self.pio.len())
            .finish()
    }
}

fn invalid(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

impl ExitDispatcher {
    /// 空の範囲表を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// MMIO デバイスを `[base, base + len)` に登録する。`len == 0`・桁あふれは `InvalidArgument`、
    /// 既存範囲との重なりは `AlreadyExists`、上限（[`MAX_BUS_DEVICES`]）超過は `ResourceExhausted`。
    pub fn register_mmio(
        &mut self,
        base: u64,
        len: u64,
        dev: Box<dyn MmioDevice>,
    ) -> Result<DeviceId, MicrovmError> {
        if len == 0 {
            return Err(invalid("device range length is zero"));
        }
        let end = base
            .checked_add(len)
            .ok_or_else(|| invalid("device range overflows"))?;
        insert(&mut self.mmio, base, end, dev)
    }

    /// PIO デバイスを `[base, base + len)` に登録する。エラーは [`ExitDispatcher::register_mmio`] と同じ。
    pub fn register_pio(
        &mut self,
        base: u16,
        len: u16,
        dev: Box<dyn PortIoDevice>,
    ) -> Result<DeviceId, MicrovmError> {
        if len == 0 {
            return Err(invalid("device range length is zero"));
        }
        let end = u32::from(base) + u32::from(len);
        if end > 0x1_0000 {
            return Err(invalid("device range overflows"));
        }
        insert(&mut self.pio, u64::from(base), u64::from(end), dev)
    }

    /// `exit` を該当デバイスへ振り分ける。`Io` / `Mmio` 以外は `InvalidArgument`（呼び出し側の誤用）。
    pub fn dispatch(&mut self, exit: &VcpuExit) -> Result<DispatchOutcome, MicrovmError> {
        match exit {
            VcpuExit::Mmio {
                phys_addr,
                data,
                len,
                is_write,
            } => self.dispatch_mmio(*phys_addr, data, *len, *is_write),
            VcpuExit::Io {
                direction,
                port,
                size,
                count,
                data,
            } => self.dispatch_pio(*direction, *port, *size, *count, data),
            _ => Err(invalid("exit is neither MMIO nor port I/O")),
        }
    }

    fn dispatch_mmio(
        &mut self,
        phys_addr: u64,
        data: &[u8; 8],
        len: u32,
        is_write: bool,
    ) -> Result<DispatchOutcome, MicrovmError> {
        let n = usize::try_from(len).map_err(|_| invalid("mmio length out of range"))?;
        if !(1..=8).contains(&n) {
            return Err(invalid("mmio length out of range"));
        }
        let hit = self
            .mmio
            .iter_mut()
            .enumerate()
            .find_map(|(i, r)| r.locate(phys_addr, u64::from(len)).map(|off| (i, off, r)));
        let Some((idx, off, region)) = hit else {
            return Ok(DispatchOutcome::Unhandled {
                access: UnhandledAccess::Mmio {
                    phys_addr,
                    len,
                    is_write,
                },
                response: if is_write {
                    Vec::new()
                } else {
                    vec![OPEN_BUS; n]
                },
            });
        };
        let device = DeviceId(u32::try_from(idx).unwrap_or(u32::MAX));
        let access = if is_write {
            let src = data
                .get(..n)
                .ok_or_else(|| invalid("mmio length out of range"))?;
            MmioAccess::Write(region.dev.write(off, src))
        } else {
            let mut buf = [0u8; 8];
            let dst = buf
                .get_mut(..n)
                .ok_or_else(|| invalid("mmio length out of range"))?;
            let outcome = region.dev.read(off, dst);
            MmioAccess::Read {
                outcome,
                data: buf,
                len,
            }
        };
        Ok(DispatchOutcome::Mmio { device, access })
    }

    fn dispatch_pio(
        &mut self,
        direction: IoDirection,
        port: u16,
        size: u8,
        count: u32,
        data: &[u8],
    ) -> Result<DispatchOutcome, MicrovmError> {
        let sz = usize::from(size);
        if !matches!(size, 1 | 2 | 4) || count == 0 {
            return Err(invalid("port I/O size or count out of range"));
        }
        let total = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(sz))
            .filter(|t| *t <= MAX_PIO_TOTAL)
            .ok_or_else(|| invalid("port I/O length out of range"))?;
        if direction == IoDirection::Out && data.len() != total {
            return Err(invalid("port I/O data length mismatch"));
        }
        let hit = self.pio.iter_mut().enumerate().find_map(|(i, r)| {
            r.locate(u64::from(port), u64::from(size))
                .map(|off| (i, off, r))
        });
        let Some((idx, off, region)) = hit else {
            return Ok(DispatchOutcome::Unhandled {
                access: UnhandledAccess::Pio {
                    port,
                    size,
                    count,
                    direction,
                },
                response: match direction {
                    IoDirection::In => vec![OPEN_BUS; total],
                    IoDirection::Out => Vec::new(),
                },
            });
        };
        let device = DeviceId(u32::try_from(idx).unwrap_or(u32::MAX));
        // 登録範囲は u16 ポート空間内なので、相対オフセットも u16 に収まる。
        let off = u16::try_from(off).map_err(|_| invalid("port offset out of range"))?;
        let mut outcome = PortIoOutcome::Handled;
        let mut response = Vec::new();
        match direction {
            IoDirection::In => {
                response = vec![0u8; total];
                for chunk in response.chunks_mut(sz) {
                    if region.dev.read(off, chunk) == PortIoOutcome::Ignored {
                        outcome = PortIoOutcome::Ignored;
                        chunk.fill(OPEN_BUS);
                    }
                }
            }
            IoDirection::Out => {
                for chunk in data.chunks(sz) {
                    if region.dev.write(off, chunk) == PortIoOutcome::Ignored {
                        outcome = PortIoOutcome::Ignored;
                    }
                }
            }
        }
        Ok(DispatchOutcome::Pio {
            device,
            direction,
            outcome,
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_mmio::{
        FeatureBits, IgnoredAccess, VirtioDevice, VirtioDeviceType,
        VirtioMmioTransport as Transport,
    };
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<String>>>;

    /// 読み出しで固定バイト列を返し、書き込みを記録する MMIO 試験デバイス。
    struct FakeMmio(Log);
    impl MmioDevice for FakeMmio {
        fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
            self.0
                .lock()
                .unwrap()
                .push(format!("r {offset} {}", data.len()));
            for (i, b) in data.iter_mut().enumerate() {
                *b = 0xA0 + u8::try_from(i).unwrap();
            }
            MmioReadOutcome::Handled
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
            self.0.lock().unwrap().push(format!("w {offset} {data:?}"));
            MmioWriteOutcome::Handled
        }
    }

    /// 呼び出しを記録し、読み出しでは呼び出し番号を返す PIO 試験デバイス。
    struct FakePio(Log, u8);
    impl PortIoDevice for FakePio {
        fn read(&mut self, offset: u16, data: &mut [u8]) -> PortIoOutcome {
            self.1 += 1;
            self.0
                .lock()
                .unwrap()
                .push(format!("in {offset} {}", data.len()));
            data.fill(self.1);
            PortIoOutcome::Handled
        }
        fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
            self.0
                .lock()
                .unwrap()
                .push(format!("out {offset} {data:?}"));
            PortIoOutcome::Handled
        }
    }

    fn mmio_exit(addr: u64, len: u32, is_write: bool, data: [u8; 8]) -> VcpuExit {
        VcpuExit::Mmio {
            phys_addr: addr,
            data,
            len,
            is_write,
        }
    }

    fn io_exit(direction: IoDirection, port: u16, size: u8, count: u32, data: Vec<u8>) -> VcpuExit {
        VcpuExit::Io {
            direction,
            port,
            size,
            count,
            data,
        }
    }

    fn new_log() -> Log {
        Arc::new(Mutex::new(Vec::new()))
    }

    /// MVM-1: 登録の検証（長さ 0・桁あふれ・重なり・上限）。境界が接する範囲は受理する。
    #[test]
    fn register_validates_ranges() {
        let mut d = ExitDispatcher::new();
        let log = new_log();
        let code = |r: Result<DeviceId, MicrovmError>| r.unwrap_err().code();
        assert_eq!(
            code(d.register_mmio(0x1000, 0, Box::new(FakeMmio(log.clone())))),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            code(d.register_mmio(u64::MAX, 2, Box::new(FakeMmio(log.clone())))),
            MicrovmErrorCode::InvalidArgument
        );
        d.register_mmio(0x1000, 0x100, Box::new(FakeMmio(log.clone())))
            .unwrap();
        assert_eq!(
            code(d.register_mmio(0x10ff, 0x10, Box::new(FakeMmio(log.clone())))),
            MicrovmErrorCode::AlreadyExists
        );
        // ちょうど接する範囲は重ならない。
        let id = d
            .register_mmio(0x1100, 0x100, Box::new(FakeMmio(log.clone())))
            .unwrap();
        assert_eq!(id.index(), 1);
        // PIO: 0xFFFF を含む範囲は受理、超える範囲は拒否。
        d.register_pio(0xFFF0, 0x10, Box::new(FakePio(log.clone(), 0)))
            .unwrap();
        assert_eq!(
            code(d.register_pio(0xFFF8, 0x10, Box::new(FakePio(log.clone(), 0)))),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            code(d.register_pio(0x10, 0, Box::new(FakePio(log.clone(), 0)))),
            MicrovmErrorCode::InvalidArgument
        );
        // 上限。
        let mut d = ExitDispatcher::new();
        for i in 0..MAX_BUS_DEVICES {
            d.register_pio(
                u16::try_from(i).unwrap(),
                1,
                Box::new(FakePio(log.clone(), 0)),
            )
            .unwrap();
        }
        assert_eq!(
            code(d.register_pio(0x100, 1, Box::new(FakePio(log.clone(), 0)))),
            MicrovmErrorCode::ResourceExhausted
        );
    }

    /// MVM-1: MMIO は基底からの相対オフセットで届き、読み出しの応答が返る。
    #[test]
    fn mmio_read_and_write_reach_device_with_relative_offset() {
        let log = new_log();
        let mut d = ExitDispatcher::new();
        let id = d
            .register_mmio(0xd000_0000, 0x200, Box::new(FakeMmio(log.clone())))
            .unwrap();
        let out = d
            .dispatch(&mmio_exit(0xd000_0010, 4, false, [0; 8]))
            .unwrap();
        assert_eq!(out.read_response(), Some(&[0xA0, 0xA1, 0xA2, 0xA3][..]));
        assert!(matches!(out, DispatchOutcome::Mmio { device, .. } if device == id));
        let out = d
            .dispatch(&mmio_exit(0xd000_0100, 2, true, [7, 8, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(out.read_response(), None);
        assert_eq!(
            out,
            DispatchOutcome::Mmio {
                device: id,
                access: MmioAccess::Write(MmioWriteOutcome::Handled)
            }
        );
        assert_eq!(*log.lock().unwrap(), vec!["r 16 4", "w 256 [7, 8]"]);
    }

    /// MVM-1: 未登録・範囲をまたぐ MMIO は Unhandled（読み出しは 0xFF、書き込みは捨てる）。
    #[test]
    fn mmio_outside_ranges_is_unhandled() {
        let log = new_log();
        let mut d = ExitDispatcher::new();
        d.register_mmio(0x1000, 0x10, Box::new(FakeMmio(log.clone())))
            .unwrap();
        for addr in [0x0fff, 0x100d, 0x2000, u64::MAX - 1] {
            let out = d.dispatch(&mmio_exit(addr, 4, false, [0; 8])).unwrap();
            assert_eq!(
                out,
                DispatchOutcome::Unhandled {
                    access: UnhandledAccess::Mmio {
                        phys_addr: addr,
                        len: 4,
                        is_write: false
                    },
                    response: vec![0xFF; 4]
                }
            );
        }
        let out = d.dispatch(&mmio_exit(0x2000, 1, true, [1; 8])).unwrap();
        assert_eq!(out.read_response(), None);
        assert!(log.lock().unwrap().is_empty());
    }

    /// 最小の virtio デバイス（キュー 1 本・設定空間なし）。
    struct NullVirtio;
    impl VirtioDevice for NullVirtio {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Block
        }
        fn device_features(&self) -> FeatureBits {
            FeatureBits::default()
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &[16]
        }
        fn read_config(&self, _offset: u64, data: &mut [u8]) {
            data.fill(0);
        }
        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
        fn activate(
            &mut self,
            _features: FeatureBits,
            _queues: &[crate::virtio_mmio::QueueConfig],
        ) -> Result<(), MicrovmError> {
            Ok(())
        }
        fn reset(&mut self) {}
    }

    /// MVM-1・TASK-74.2.1: virtio-mmio のトランスポートを登録して MAGIC を読み、QUEUE_NOTIFY の結果をそのまま受ける。
    #[test]
    fn virtio_transport_is_dispatchable() {
        let mut d = ExitDispatcher::new();
        let t = Transport::new(NullVirtio).unwrap();
        d.register_mmio(0xd000_0000, 0x200, Box::new(t)).unwrap();
        let out = d
            .dispatch(&mmio_exit(0xd000_0000, 4, false, [0; 8]))
            .unwrap();
        assert_eq!(out.read_response(), Some(&0x7472_6976u32.to_le_bytes()[..]));
        let out = d
            .dispatch(&mmio_exit(0xd000_0050, 4, true, [0; 8]))
            .unwrap();
        // DRIVER_OK 前の通知はトランスポートが無視する。その結果が加工されずに返る
        // （QueueNotify の返却はトランスポート側の試験が担保）。
        assert_eq!(
            out,
            DispatchOutcome::Mmio {
                device: DeviceId(0),
                access: MmioAccess::Write(MmioWriteOutcome::Ignored(
                    IgnoredAccess::WrongDeviceState
                ))
            }
        );
    }

    /// MVM-1: PIO の IN は size*count バイトの応答になり、rep では 1 要素ずつ同じオフセットで呼ばれる。
    #[test]
    fn pio_in_and_out_with_repeat() {
        let log = new_log();
        let mut d = ExitDispatcher::new();
        let id = d
            .register_pio(0x3f8, 8, Box::new(FakePio(log.clone(), 0)))
            .unwrap();
        let out = d
            .dispatch(&io_exit(IoDirection::In, 0x3fa, 2, 3, vec![]))
            .unwrap();
        assert_eq!(out.read_response(), Some(&[1, 1, 2, 2, 3, 3][..]));
        assert!(matches!(
            out,
            DispatchOutcome::Pio { device, outcome: PortIoOutcome::Handled, .. } if device == id
        ));
        let out = d
            .dispatch(&io_exit(IoDirection::Out, 0x3f8, 1, 2, vec![0x41, 0x42]))
            .unwrap();
        assert_eq!(out.read_response(), None);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["in 2 2", "in 2 2", "in 2 2", "out 0 [65]", "out 0 [66]"]
        );
    }

    /// MVM-1: 未登録ポート・範囲をまたぐアクセスは Unhandled（IN は 0xFF 埋め）。
    #[test]
    fn pio_outside_ranges_is_unhandled() {
        let log = new_log();
        let mut d = ExitDispatcher::new();
        d.register_pio(0x10, 2, Box::new(FakePio(log.clone(), 0)))
            .unwrap();
        // 0x11 から 4 バイトは範囲 [0x10, 0x12) をまたぐ。
        for (port, size) in [(0x11u16, 4u8), (0x20, 1), (0x0f, 2)] {
            let out = d
                .dispatch(&io_exit(IoDirection::In, port, size, 2, vec![]))
                .unwrap();
            assert_eq!(
                out,
                DispatchOutcome::Unhandled {
                    access: UnhandledAccess::Pio {
                        port,
                        size,
                        count: 2,
                        direction: IoDirection::In
                    },
                    response: vec![0xFF; usize::from(size) * 2]
                }
            );
        }
        let out = d
            .dispatch(&io_exit(IoDirection::Out, 0x20, 1, 1, vec![9]))
            .unwrap();
        assert_eq!(out.read_response(), None);
        assert!(log.lock().unwrap().is_empty());
    }

    /// MVM-1: Io / Mmio 以外の exit と、不正な形の Io は InvalidArgument（巨大確保もしない）。
    #[test]
    fn rejects_misuse() {
        let mut d = ExitDispatcher::new();
        for e in [
            VcpuExit::Hlt,
            VcpuExit::Interrupted,
            io_exit(IoDirection::In, 0x10, 3, 1, vec![]),
            io_exit(IoDirection::In, 0x10, 4, u32::MAX, vec![]),
            io_exit(IoDirection::Out, 0x10, 2, 2, vec![1]),
            mmio_exit(0x1000, 9, false, [0; 8]),
        ] {
            assert_eq!(
                d.dispatch(&e).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument,
                "{e:?}"
            );
        }
    }
}
