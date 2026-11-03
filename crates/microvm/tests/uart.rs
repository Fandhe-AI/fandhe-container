//! UART のレジスタモデルを `ExitDispatcher` の PIO 経由で確かめる結合試験（#3739・MVM-1。KVM 不要）。
//! 製品の結線は `SerialConsole::port_device`（#3740）。ここでは `Arc<Mutex<..>>` で包んだ UART も COM1 に登録して確かめる。

use std::sync::{Arc, Mutex};

use fandhe_container_microvm::dispatch::{
    DispatchOutcome, ExitDispatcher, PortIoDevice, PortIoOutcome,
};
use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
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
