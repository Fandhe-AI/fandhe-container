//! UART のレジスタモデルを `ExitDispatcher` の PIO 経由で確かめる結合試験（#3739・MVM-1。KVM 不要）。
//! #3740 の結線がそのまま使える雛形として、`Arc<Mutex<..>>` で包んだ UART を COM1 に登録する。

use std::sync::{Arc, Mutex};

use fandhe_container_microvm::dispatch::{
    DispatchOutcome, ExitDispatcher, PortIoDevice, PortIoOutcome,
};
use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
use fandhe_container_microvm::uart::{COM1_BASE, UART_PORT_LEN, Uart16550};

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
