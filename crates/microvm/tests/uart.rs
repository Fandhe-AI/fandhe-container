//! UART のレジスタモデルを `ExitDispatcher` の PIO 経由で確かめる結合試験（#3739・MVM-1。KVM 不要）。
//! 製品の結線は `SerialConsole::port_device`（#3740）。ここでは `Arc<Mutex<..>>` で包んだ UART も COM1 に登録して確かめる。

use std::sync::{Arc, Mutex};

use fandhe_container_microvm::dispatch::{
    DispatchOutcome, ExitDispatcher, PortIoDevice, PortIoOutcome,
};
use fandhe_container_microvm::error::MicrovmError;
use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
use fandhe_container_microvm::interrupt::{IrqLevel, LevelInterruptLine};
use fandhe_container_microvm::uart::{COM1_BASE, SerialConsole, UART_PORT_LEN, Uart16550};

struct Shared(Arc<Mutex<Uart16550>>);

impl PortIoDevice for Shared {
    fn read(&mut self, offset: u16, data: &mut [u8]) -> PortIoOutcome {
        self.0.lock().unwrap().read(offset, data)
    }
    fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
        self.0.lock().unwrap().write(offset, data)
    }
}

#[test]
fn mvm1_uart_via_dispatcher() {
    let uart = Arc::new(Mutex::new(Uart16550::new()));
    let mut d = ExitDispatcher::new();
    d.register_pio(COM1_BASE, UART_PORT_LEN, Box::new(Shared(uart.clone())))
        .unwrap();

    let out = VcpuExit::Io {
        direction: IoDirection::Out,
        port: COM1_BASE,
        size: 1,
        count: 5,
        data: b"hello".to_vec(),
    };
    d.dispatch(&out).unwrap();
    assert_eq!(uart.lock().unwrap().take_output(), b"hello");

    let lsr = VcpuExit::Io {
        direction: IoDirection::In,
        port: COM1_BASE + 5,
        size: 1,
        count: 1,
        data: vec![],
    };
    match d.dispatch(&lsr).unwrap() {
        DispatchOutcome::Pio {
            response, outcome, ..
        } => {
            assert_eq!(response, vec![0x60]);
            assert_eq!(outcome, PortIoOutcome::Handled);
        }
        other => panic!("unexpected {other:?}"),
    }

    let wide = VcpuExit::Io {
        direction: IoDirection::In,
        port: COM1_BASE,
        size: 2,
        count: 1,
        data: vec![],
    };
    match d.dispatch(&wide).unwrap() {
        DispatchOutcome::Pio {
            response, outcome, ..
        } => {
            assert_eq!(response, vec![0xFF, 0xFF]);
            assert_eq!(outcome, PortIoOutcome::Ignored);
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn out_exit(data: &[u8]) -> VcpuExit {
    VcpuExit::Io {
        direction: IoDirection::Out,
        port: COM1_BASE,
        size: 1,
        count: data.len() as u32,
        data: data.to_vec(),
    }
}

/// MVM-1・#3740: `SerialConsole::port_device` を PIO に登録すると THR 出力がホスト側のバッファに届く。
#[test]
fn mvm1_3740_serial_console_port_device_routes_to_buffer() {
    let console = SerialConsole::new();
    let mut d = ExitDispatcher::new();
    d.register_pio(COM1_BASE, UART_PORT_LEN, console.port_device())
        .unwrap();
    d.dispatch(&out_exit(b"hello")).unwrap();
    assert_eq!(console.take_output().unwrap(), b"hello");
    assert_eq!(console.stats().unwrap().written_bytes, 5);
    assert!(console.take_output().unwrap().is_empty());

    let lsr = VcpuExit::Io {
        direction: IoDirection::In,
        port: COM1_BASE + 5,
        size: 1,
        count: 1,
        data: vec![],
    };
    match d.dispatch(&lsr).unwrap() {
        DispatchOutcome::Pio { response, .. } => assert_eq!(response, vec![0x60]),
        other => panic!("unexpected {other:?}"),
    }
}

/// MVM-1・#3740: clone は同じバッファを共有し、Debug は中身を出さない。
#[test]
fn mvm1_3740_serial_console_clone_shares_buffer() {
    let a = SerialConsole::new();
    let b = a.clone();
    let mut d = ExitDispatcher::new();
    d.register_pio(COM1_BASE, UART_PORT_LEN, b.port_device())
        .unwrap();
    d.dispatch(&out_exit(b"xy")).unwrap();
    assert_eq!(a.take_output().unwrap(), b"xy");
    assert!(b.take_output().unwrap().is_empty());
    assert_eq!(format!("{a:?}"), "SerialConsole { .. }");
}

#[derive(Debug, Default)]
struct RecordingLine(Mutex<Vec<IrqLevel>>);

impl LevelInterruptLine for RecordingLine {
    fn set_level(&self, level: IrqLevel) -> Result<(), MicrovmError> {
        self.0.lock().unwrap().push(level);
        Ok(())
    }
}

/// ExitDispatcher 経由の MMIO で 1 バイト読む / 書く。
fn mmio(d: &mut ExitDispatcher, base: u64, off: u64, write: Option<u8>) -> Option<u8> {
    let mut data = [0u8; 8];
    if let Some(v) = write {
        data[0] = v;
    }
    let exit = VcpuExit::Mmio {
        phys_addr: base + off,
        data,
        len: 1,
        is_write: write.is_some(),
    };
    let out = d.dispatch(&exit).unwrap();
    if write.is_some() {
        None
    } else {
        Some(out.read_response().unwrap()[0])
    }
}

/// MVM-5・MVM-1・REPAIR-12・#3893: 公開 API の push_input で入れた入力を、ディスパッチャ経由で
/// IIR・LSR・RBR として読め、受信割り込み線が立ち、読み切りで下がる（偽の線。実機不要）。
#[test]
fn mvm5_3893_push_input_via_dispatcher_raises_and_clears_line() {
    const BASE: u64 = 0x0900_0000;
    let console = SerialConsole::new();
    let line = Arc::new(RecordingLine::default());
    let mut d = ExitDispatcher::new();
    d.register_mmio(BASE, 8, console.mmio_device_with_irq(line.clone()))
        .unwrap();
    let calls = || line.0.lock().unwrap().clone();

    mmio(&mut d, BASE, 1, Some(0x01));
    assert!(calls().is_empty());
    assert_eq!(mmio(&mut d, BASE, 5, None), Some(0x60));

    let report = console.push_input(b"ok").unwrap();
    assert_eq!(report.accepted, 2);
    assert_eq!(calls(), vec![IrqLevel::High]);
    assert_eq!(mmio(&mut d, BASE, 2, None), Some(0x04));
    assert_eq!(mmio(&mut d, BASE, 5, None), Some(0x61));

    assert_eq!(mmio(&mut d, BASE, 0, None), Some(b'o'));
    assert_eq!(calls(), vec![IrqLevel::High]);
    assert_eq!(mmio(&mut d, BASE, 0, None), Some(b'k'));
    assert_eq!(calls(), vec![IrqLevel::High, IrqLevel::Low]);
    assert_eq!(mmio(&mut d, BASE, 5, None), Some(0x60));
    assert_eq!(mmio(&mut d, BASE, 2, None), Some(0x01));
    assert_eq!(console.stats().unwrap().input_read_bytes, 2);
}

/// PIO の 1 バイト In / Out を ExitDispatcher 経由で行う。
fn pio(d: &mut ExitDispatcher, off: u16, write: Option<u8>) -> Option<u8> {
    let exit = VcpuExit::Io {
        direction: if write.is_some() {
            IoDirection::Out
        } else {
            IoDirection::In
        },
        port: COM1_BASE + off,
        size: 1,
        count: 1,
        data: write.map(|v| vec![v]).unwrap_or_default(),
    };
    match d.dispatch(&exit).unwrap() {
        DispatchOutcome::Pio { response, .. } => response.first().copied(),
        other => panic!("unexpected {other:?}"),
    }
}

/// MVM-5・MVM-1・REPAIR-12・#3918: x86 の PIO（`port_device_with_irq`）でも THRE と受信データの線が
/// ディスパッチャ経由で立ち下がる（偽の線。実機不要）。
#[test]
fn mvm5_3918_pio_irq_line_via_dispatcher() {
    let console = SerialConsole::new();
    let line = Arc::new(RecordingLine::default());
    let mut d = ExitDispatcher::new();
    d.register_pio(
        COM1_BASE,
        UART_PORT_LEN,
        console.port_device_with_irq(line.clone()),
    )
    .unwrap();
    let calls = || line.0.lock().unwrap().clone();
    let (h, l) = (IrqLevel::High, IrqLevel::Low);

    pio(&mut d, 1, Some(0x02));
    assert_eq!(calls(), vec![h]);
    assert_eq!(pio(&mut d, 2, None), Some(0x02));
    assert_eq!(calls(), vec![h, l]);

    pio(&mut d, 1, Some(0x01));
    assert_eq!(console.push_input(b"ok").unwrap().accepted, 2);
    assert_eq!(calls(), vec![h, l, h]);
    assert_eq!(pio(&mut d, 2, None), Some(0x04));
    assert_eq!(pio(&mut d, 5, None), Some(0x61));
    assert_eq!(pio(&mut d, 0, None), Some(b'o'));
    assert_eq!(calls(), vec![h, l, h]);
    assert_eq!(pio(&mut d, 0, None), Some(b'k'));
    assert_eq!(calls(), vec![h, l, h, l]);
    assert_eq!(pio(&mut d, 2, None), Some(0x01));
}
