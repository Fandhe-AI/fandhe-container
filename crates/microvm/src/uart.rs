//! 8250 / 16550 互換の最小 UART（COM1）のレジスタモデル（TASK-75.5・#3739・MVM-1・REPAIR-3。OS 非依存・`unsafe` なし）。
//!
//! ゲストカーネルのコンソール（`console=ttyS0`）の出力をホストが受け取るためのデバイスモデル。
//! `crate::dispatch::ExitDispatcher::register_pio` に `(COM1_BASE, UART_PORT_LEN, ..)` で登録される予定で、
//! 結線・ホストへの取り出し API の公開・実機前提試験は #3740 が担う。本モジュールはレジスタモデルと、
//! KVM 不要の単体試験までを受け持つ。
//!
//! # レジスタ
//! offset 0..8 の 8 ビットデバイス。THR / RBR・IER・IIR / FCR・LCR・MCR・LSR・MSR・SCR。LCR の DLAB（bit7）が
//! 立つと offset 0 / 1 は DLL / DLM に切り替わる。LSR は常に THRE | TEMT（0x60。DR=0）で、ゲストは
//! ポーリングで送信を進められる（Linux の 8250 コンソールの `wait_for_xmitr` 相当）。MSR は Linux の
//! `autoconfig()` が MCR=0x1A（ループバック）を書いて `MSR & 0xF0 == 0x90` を確かめるため、MCR を写す。
//! ループバック中の THR への書き込みはコンソール出力ではないので出力バッファへ送らず、数だけ数える。
//!
//! # 出力バッファ
//! THR への書き込みは上限（既定 [`MAX_OUTPUT_BYTES`]）つきのバッファへ溜める。溢れたら古いものから捨て、
//! 捨てた数を [`UartStats::dropped_bytes`] に数える（ゲストが無限に書いてもホストの確保は上限で頭打ち。CORE-7）。
//! [`Uart16550::take_output`] で取り出す。共有の持ち方（`Arc<Mutex<..>>` 等）は #3740 が決める。
//!
//! # 外部入力の扱い
//! offset・幅・値はゲストが決める非信頼入力。`offset >= 8` と 1 バイト以外の幅は `PortIoOutcome::Ignored`
//! （読み出しは dispatcher が 0xFF 埋め）。添字アクセス・`unwrap` は使わず、計数は saturating で行う。
//!
//! # 未実装（REPAIR-3）
//! - IRQ 4（[`COM1_IRQ`]）は出さない。IER は読み書きできるが割り込みは起こさず、IIR は常に「保留なし」。
//!   将来は IER.ETBEI と THR 空きによる THRE 割り込み（IIR=0x02）を、THR 書き込み・IER 書き込みで立て、
//!   IIR 読み出しと THR 書き込みで解除し、irqfd の GSI 4 へ結線する（MVM-1）。
//!   現状の制約: tty 層の割り込み駆動の送信（ユーザー空間から `/dev/ttyS0` への書き込み）は進まないことがある。
//! - ゲスト入力（RBR・DR・受信 FIFO）は対象外。RBR は常に 0。

use std::collections::VecDeque;

use crate::dispatch::{PortIoDevice, PortIoOutcome};
use crate::error::{MicrovmError, MicrovmErrorCode};

/// COM1 の基底ポート。
pub const COM1_BASE: u16 = 0x3f8;
/// UART が占めるポート数（offset 0..8）。
pub const UART_PORT_LEN: u16 = 8;
/// COM1 の IRQ 番号。本モジュールは割り込みを出さないため、将来仕様の記述用（#3740 以降）。
pub const COM1_IRQ: u32 = 4;
/// 出力バッファの上限バイト数（64 KiB）。
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

const LSR_THRE_TEMT: u8 = 0x60;
const LCR_DLAB: u8 = 0x80;
const MCR_LOOP: u8 = 0x10;
const MCR_MASK: u8 = 0x1F;
const IER_MASK: u8 = 0x0F;
const FCR_ENABLE: u8 = 0x01;
const IIR_NO_INT: u8 = 0x01;
const IIR_FIFO: u8 = 0xC0;
const MSR_DEFAULT: u8 = 0xB0;

/// UART の計数の写し。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UartStats {
    /// ゲストが THR に書いた総バイト数（ループバック中を除く）。
    pub written_bytes: u64,
    /// 現在バッファにあるバイト数。
    pub buffered_bytes: usize,
    /// 上限超過で古いものから捨てたバイト数。
    pub dropped_bytes: u64,
    /// ループバック中に THR へ書かれ、出力へ送らず捨てたバイト数。
    pub loopback_discarded: u64,
}

/// 8250 / 16550 互換の最小 UART のレジスタモデル。
#[derive(Debug, Clone)]
pub struct Uart16550 {
    dll: u8,
    dlm: u8,
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    fifo_enabled: bool,
    output: VecDeque<u8>,
    capacity: usize,
    written_bytes: u64,
    dropped_bytes: u64,
    loopback_discarded: u64,
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self::with_capacity_unchecked(MAX_OUTPUT_BYTES)
    }
}

impl Uart16550 {
    /// 上限 [`MAX_OUTPUT_BYTES`] の UART を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 出力バッファの上限を指定して作る。`1..=MAX_OUTPUT_BYTES` の外は `InvalidArgument`。
    pub fn with_output_capacity(capacity: usize) -> Result<Self, MicrovmError> {
        if capacity == 0 || capacity > MAX_OUTPUT_BYTES {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "uart output capacity out of range",
            ));
        }
        Ok(Self::with_capacity_unchecked(capacity))
    }

    fn with_capacity_unchecked(capacity: usize) -> Self {
        Self {
            dll: 0x0C,
            dlm: 0,
            ier: 0,
            lcr: 0x03,
            mcr: 0x08,
            scr: 0,
            fifo_enabled: false,
            output: VecDeque::new(),
            capacity,
            written_bytes: 0,
            dropped_bytes: 0,
            loopback_discarded: 0,
        }
    }

    /// バッファのバイト列を全部取り出して空にする（長さは上限で頭打ち）。
    pub fn take_output(&mut self) -> Vec<u8> {
        self.output.drain(..).collect()
    }

    /// 計数の写しを返す。
    pub fn stats(&self) -> UartStats {
        UartStats {
            written_bytes: self.written_bytes,
            buffered_bytes: self.output.len(),
            dropped_bytes: self.dropped_bytes,
            loopback_discarded: self.loopback_discarded,
        }
    }

    fn dlab(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    fn loopback(&self) -> bool {
        self.mcr & MCR_LOOP != 0
    }

    fn msr(&self) -> u8 {
        if !self.loopback() {
            return MSR_DEFAULT;
        }
        // ループバック: RTS→CTS、DTR→DSR、OUT1→RI、OUT2→DCD。
        let m = self.mcr;
        let mut v = 0;
        if m & 0x02 != 0 {
            v |= 0x10;
        }
        if m & 0x01 != 0 {
            v |= 0x20;
        }
        if m & 0x04 != 0 {
            v |= 0x40;
        }
        if m & 0x08 != 0 {
            v |= 0x80;
        }
        v
    }

    fn read_reg(&self, offset: u16) -> Option<u8> {
        let dlab = self.dlab();
        Some(match offset {
            0 if dlab => self.dll,
            0 => 0,
            1 if dlab => self.dlm,
            1 => self.ier,
            2 => {
                if self.fifo_enabled {
                    IIR_NO_INT | IIR_FIFO
                } else {
                    IIR_NO_INT
                }
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => LSR_THRE_TEMT,
            6 => self.msr(),
            7 => self.scr,
            _ => return None,
        })
    }

    fn write_reg(&mut self, offset: u16, value: u8) -> bool {
        let dlab = self.dlab();
        match offset {
            0 if dlab => self.dll = value,
            0 => self.push_output(value),
            1 if dlab => self.dlm = value,
            1 => self.ier = value & IER_MASK,
            2 => self.fifo_enabled = value & FCR_ENABLE != 0,
            3 => self.lcr = value,
            4 => self.mcr = value & MCR_MASK,
            5 | 6 => {}
            7 => self.scr = value,
            _ => return false,
        }
        true
    }

    fn push_output(&mut self, byte: u8) {
        if self.loopback() {
            self.loopback_discarded = self.loopback_discarded.saturating_add(1);
            return;
        }
        if self.output.len() >= self.capacity {
            self.output.pop_front();
            self.dropped_bytes = self.dropped_bytes.saturating_add(1);
        }
        self.output.push_back(byte);
        self.written_bytes = self.written_bytes.saturating_add(1);
    }
}

impl PortIoDevice for Uart16550 {
    fn read(&mut self, offset: u16, data: &mut [u8]) -> PortIoOutcome {
        match data {
            [slot] => match self.read_reg(offset) {
                Some(v) => {
                    *slot = v;
                    PortIoOutcome::Handled
                }
                None => PortIoOutcome::Ignored,
            },
            _ => PortIoOutcome::Ignored,
        }
    }

    fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
        match data {
            [b] if self.write_reg(offset, *b) => PortIoOutcome::Handled,
            _ => PortIoOutcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(u: &mut Uart16550, off: u16) -> u8 {
        let mut b = [0u8; 1];
        assert_eq!(u.read(off, &mut b), PortIoOutcome::Handled);
        b[0]
    }
    fn wr(u: &mut Uart16550, off: u16, v: u8) {
        assert_eq!(u.write(off, &[v]), PortIoOutcome::Handled);
    }

    #[test]
    fn mvm1_uart_lsr_reports_thre_and_temt() {
        let mut u = Uart16550::new();
        assert_eq!(rd(&mut u, 5), 0x60);
        wr(&mut u, 0, b'x');
        assert_eq!(rd(&mut u, 5), 0x60);
        assert_eq!(rd(&mut u, 2), 0x01);
    }

    #[test]
    fn mvm1_uart_lcr_dlab_switches_divisor_latch() {
        let mut u = Uart16550::new();
        wr(&mut u, 1, 0x05);
        wr(&mut u, 3, 0x83);
        wr(&mut u, 0, 0x01);
        wr(&mut u, 1, 0x00);
        assert_eq!(rd(&mut u, 0), 0x01);
        assert_eq!(rd(&mut u, 1), 0x00);
        assert_eq!(rd(&mut u, 3), 0x83);
        assert_eq!(u.stats().written_bytes, 0);
        wr(&mut u, 3, 0x03);
        assert_eq!(rd(&mut u, 3), 0x03);
        assert_eq!(rd(&mut u, 1), 0x05);
        wr(&mut u, 3, 0x83);
        assert_eq!(rd(&mut u, 0), 0x01);
    }

    #[test]
    fn mvm1_uart_ier_masks_upper_nibble() {
        let mut u = Uart16550::new();
        wr(&mut u, 1, 0xFF);
        assert_eq!(rd(&mut u, 1), 0x0F);
        wr(&mut u, 1, 0x00);
        assert_eq!(rd(&mut u, 1), 0x00);
    }

    #[test]
    fn mvm1_uart_scr_and_iir_fifo() {
        let mut u = Uart16550::new();
        wr(&mut u, 7, 0xA5);
        assert_eq!(rd(&mut u, 7), 0xA5);
        wr(&mut u, 2, 0x01);
        assert_eq!(rd(&mut u, 2), 0xC1);
        wr(&mut u, 2, 0x00);
        assert_eq!(rd(&mut u, 2), 0x01);
    }

    #[test]
    fn mvm1_uart_loopback_mirrors_mcr_into_msr() {
        let mut u = Uart16550::new();
        assert_eq!(rd(&mut u, 6), 0xB0);
        wr(&mut u, 4, 0x1A);
        assert_eq!(rd(&mut u, 6) & 0xF0, 0x90);
        wr(&mut u, 4, 0x1F);
        assert_eq!(rd(&mut u, 6) & 0xF0, 0xF0);
        wr(&mut u, 0, b'z');
        assert!(u.take_output().is_empty());
        assert_eq!(u.stats().loopback_discarded, 1);
    }

    #[test]
    fn mvm1_uart_rejects_wide_and_out_of_range_access() {
        let mut u = Uart16550::new();
        let mut two = [0u8; 2];
        let mut four = [0u8; 4];
        let mut one = [0u8; 1];
        assert_eq!(u.read(0, &mut two), PortIoOutcome::Ignored);
        assert_eq!(u.read(0, &mut four), PortIoOutcome::Ignored);
        assert_eq!(u.read(8, &mut one), PortIoOutcome::Ignored);
        assert_eq!(u.write(0, &[1, 2]), PortIoOutcome::Ignored);
        assert_eq!(u.write(0, &[1, 2, 3, 4]), PortIoOutcome::Ignored);
        assert_eq!(u.write(8, &[1]), PortIoOutcome::Ignored);
        assert_eq!(u.write(0, &[]), PortIoOutcome::Ignored);
        assert_eq!(u.stats(), UartStats::default());
    }

    #[test]
    fn mvm1_uart_output_overflow_drops_oldest() {
        let mut u = Uart16550::with_output_capacity(4).unwrap();
        for b in b"abcdefg" {
            wr(&mut u, 0, *b);
        }
        let s = u.stats();
        assert_eq!(
            (s.written_bytes, s.dropped_bytes, s.buffered_bytes),
            (7, 3, 4)
        );
        assert_eq!(u.take_output(), b"defg");
        assert_eq!(u.stats().buffered_bytes, 0);
        wr(&mut u, 0, b'h');
        assert_eq!(u.stats().dropped_bytes, 3);
    }

    #[test]
    fn mvm1_uart_capacity_bounds() {
        for bad in [0, MAX_OUTPUT_BYTES + 1] {
            let e = Uart16550::with_output_capacity(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        let mut u = Uart16550::new();
        for _ in 0..MAX_OUTPUT_BYTES + 2 {
            wr(&mut u, 0, b'a');
        }
        assert_eq!(u.stats().dropped_bytes, 2);
        assert_eq!(u.take_output().len(), MAX_OUTPUT_BYTES);
    }
}
