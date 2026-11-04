//! 8250 / 16550 互換の最小 UART（COM1）のレジスタモデル（TASK-75.5・#3739・MVM-1・REPAIR-3。OS 非依存・`unsafe` なし）。
//!
//! ゲストカーネルのコンソール（`console=ttyS0`）の出力をホストが受け取るためのデバイスモデル。
//! レジスタモデル（[`Uart16550`]）と、PIO バス・ホストで共有するハンドル（[`SerialConsole`]）を持つ。
//! arm64 ゲストは MMIO（FDT の `ns16550a`・`reg-shift = 0`・`reg-io-width = 1`）でも同じモデルを使う
//! ([`SerialConsole::mmio_device`]・割り込みつきは [`SerialConsole::mmio_device_with_irq`]。#3864・#3892・MVM-5)。
//! `microvm::DeviceBus`（Linux のみ）が [`SerialConsole::port_device`] を
//! `crate::dispatch::ExitDispatcher::register_pio` に `(COM1_BASE, UART_PORT_LEN, ..)` で常に登録し、
//! ホストは `microvm::MicroVm::serial_console` / `microvm::RunningMicroVm::serial_console`（macOS の MMIO 経路は `hvf::HvfMicroVm::serial_console`。#3882）で得た
//! [`SerialConsole`] から出力を取り出す（#3740）。実機前提試験は `tests/kvm_device.rs`。
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
//! [`Uart16550::take_output`] / [`SerialConsole::take_output`] で取り出す。共有は `Arc<Mutex<..>>`（[`SerialConsole`]）で、
//! vCPU スレッドが `MicroVm` を drop した後も clone したハンドルがバッファを保持する。バッファの中身はゲスト由来の
//! 非信頼バイト列なので、呼び出し元が表示・記録するときはエスケープすること（ログへは出さない。`Debug` にも出さない）。
//!
//! # 外部入力の扱い
//! offset・幅・値はゲストが決める非信頼入力。`offset >= 8` と 1 バイト以外の幅は `PortIoOutcome::Ignored`
//! （読み出しは dispatcher が 0xFF 埋め）。添字アクセス・`unwrap` は使わず、計数は saturating で行う。
//!
//! # THRE 割り込み（#3892・MVM-5・MVM-1）
//! 線が結線されている（[`SerialConsole::mmio_device_with_irq`]・x86 は [`SerialConsole::port_device_with_irq`] を呼んだ）
//! ときだけ有効で、線の無い経路（[`SerialConsole::port_device`]・[`SerialConsole::mmio_device`]）は従来どおり IIR が常に「保留なし」（0x01）を返す。
//! IER.ETBEI（bit1）が 1 で THRE 保留があるとき、IIR は 0x02（FIFO 有効時は 0xC2）を返し、[`Uart16550::irq_level`] が
//! `High` になる。保留は ETBEI を 0 から 1 にしたとき・THR 書き込み（ループバック中も含む）・FCR の送信 FIFO リセット
//! （bit2）で立ち、IIR の読み出し（THRE を返したとき）と ETBEI を 0 にしたときに下がる（QEMU の `hw/char/serial.c` と
//! 16550 の理解。LSR.THRE は常に 1 で、送信は即時に終わる）。MCR.OUT2 では線を絞らない（QEMU と同じ）。
//! 優先度は RLS > RDA > CTI > THRE > MSR（PC16550D / TL16C550 のデータシートの IIR 表。QEMU の `hw/char/serial.c` も同じ）。
//! 線の更新はモデルが自分の線（[`SerialConsole::mmio_device_with_irq`] が設定）へ値の変化だけを伝える。ゲストの MMIO
//! アクセスの後と、ホストの [`SerialConsole::push_input`] の後に、UART の lock を持ったまま行う
//! （arm64 は macOS の level SPI〔`crate::spi::SpiLevelLine`〕、x86 は KVM の `KVM_IRQ_LINE`〔`crate::irq::IrqLevelLine`。#3918〕）。
//! x86 の Linux の `serial8250_do_startup` の THRE 試験（IER=THRI → IIR、IER=0 → IER=THRI → IIR）は、ETBEI の 0 から 1 のたびに
//! 保留を立てるため 2 回とも 0x02 を返し BUG_THRE を立てない（`drivers/tty/serial/8250/8250_port.c`）。
//!
//! # ゲスト入力（#3893・MVM-5・MVM-1・CORE-7）
//! ホストは [`SerialConsole::push_input`] でゲストへ文字を渡す。入力は上限（既定 [`MAX_INPUT_BYTES`]）つきの受信 FIFO に
//! 積み、溢れた分は**新しく入ってきた超過分**を捨てて [`UartStats::input_dropped_bytes`] に数える（ハードウェアの overrun と
//! 同じ向き。送信バッファが古い方から捨てるのとは逆）。RBR の読み出しで先頭を返し（空なら 0）、LSR.DR は FIFO が空でない間 1。
//! IER.ERBFI（bit0）が 1 で FIFO が空でなければ、線がある経路だけ IIR は 0x04（FIFO 有効時は 0xC4）で線は `High`。
//! THRE と同時に保留なら受信データが上（データシートの優先度）。IIR の読み出しでは下ろさず、RBR で読み切ると下がる
//! （THRE の保留は 0x04 を返した IIR 読み出しでは下がらない）。FCR bit1 は受信 FIFO を空にし、捨てた数を
//! [`UartStats::input_flushed_bytes`] に数える（Linux は起動時に書くので、その前に積んだ入力は消える）。
//! 受信トリガ（FCR bit7:6）は見ず、空でなければ常に出す（実効トリガ 1）。CTI を実装しないので、トリガを守ると
//! 1 文字では割り込みが来ない。Linux の 8250 は IIR の種類によらず LSR.DR を見て読み切るので RDA で足りる。
//! 入力のバイト列は非信頼で、ゲストへ渡すだけ。ログ・`Debug` へは出さない。ホストスレッドから線を更新するので
//! ロック順は「UART → 線（GIC の生存フラグ）」で、vCPU 側と同じ。WFI で待つゲストへは、線の assert 成功後の通知（`hvf_wake`・#3887）で待ちが即座に起き、遅れて届かない。
//!
//! # 未実装（REPAIR-3）
//! - x86 の線なしの PIO（[`SerialConsole::port_device`]）は IIR が従来どおり常に「保留なし」を返す（届かない THRE を報告すると
//!   ドライバが来ない割り込みを待つため）。`microvm::assemble` は x86_64 で [`SerialConsole::port_device_with_irq`] を使い、
//!   [`COM1_IRQ`] を `KVM_IRQ_LINE` の level 線で結ぶ（#3918）。実機での確認は #3781。KVM aarch64 は MMIO の `mmio_device_with_irq` で SPI 1（INTID 33）を `KVM_IRQ_LINE` の level 線（`IrqLevelLine`）に結ぶ（#3943。MMIO の窓は #3898）。線なしの `mmio_device`（ポーリング）は試験と線を持たない構成用。
//! - 受信トリガ（FCR bit7:6）・CTI（IIR 0x0C）・LSR.OE と RLS 割り込みは未実装。ループバック中の THR 書き込みは RX へ回さない。
//! - `hv_gic_set_spi` を vCPU 以外のスレッドから呼べるかは未確認（#3803 の実機確認項目）。

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use crate::dispatch::{MmioDevice, PortIoDevice, PortIoOutcome};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::interrupt::{IrqLevel, LevelInterruptLine};
use crate::virtio_mmio::{IgnoredAccess, MmioReadOutcome, MmioWriteOutcome};

/// COM1 の基底ポート。
pub const COM1_BASE: u16 = 0x3f8;
/// UART が占めるポート数（offset 0..8）。
pub const UART_PORT_LEN: u16 = 8;
/// COM1 の IRQ 番号（ISA IRQ 4 = GSI 4。MP テーブルでは IOAPIC pin 4・edge・active high）。x86_64 の KVM では
/// `microvm::assemble` が `KVM_IRQ_LINE` の線をこの番号に結ぶ（#3918）。線なしの [`SerialConsole::port_device`] は割り込みを出さない。
pub const COM1_IRQ: u32 = 4;
/// 出力バッファの上限バイト数（64 KiB）。
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// 受信 FIFO の既定の上限バイト数（ホスト入力は端末の貼り付け程度で足りる。超過は捨てる。CORE-7・#3893）。
pub const MAX_INPUT_BYTES: usize = 4 * 1024;

const LSR_THRE_TEMT: u8 = 0x60;
const LCR_DLAB: u8 = 0x80;
const MCR_LOOP: u8 = 0x10;
const MCR_MASK: u8 = 0x1F;
const IER_MASK: u8 = 0x0F;
const FCR_ENABLE: u8 = 0x01;
const IIR_NO_INT: u8 = 0x01;
const IIR_THRE: u8 = 0x02;
const IIR_RDA: u8 = 0x04;
const IER_ERBFI: u8 = 0x01;
const LSR_DR: u8 = 0x01;
const FCR_RX_RESET: u8 = 0x02;
const IER_ETBEI: u8 = 0x02;
const FCR_TX_RESET: u8 = 0x04;
/// `int_pending` のビット: 送信保持レジスタ空きの保留。
const INT_THRE: u8 = 0x01;
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
    /// 割り込み線の更新に失敗した回数（#3892。失敗しても MMIO は処理済みで、次のアクセスで再試行する）。
    pub irq_line_errors: u64,
    /// ホストが `push_input` で受理した累計バイト数（#3893）。
    pub input_received_bytes: u64,
    /// 受信 FIFO に今あるバイト数。
    pub input_buffered_bytes: usize,
    /// 受信 FIFO の上限超過で捨てた累計バイト数。
    pub input_dropped_bytes: u64,
    /// FCR の受信 FIFO リセットで捨てた累計バイト数。
    pub input_flushed_bytes: u64,
    /// ゲストが RBR から読んだ累計バイト数。
    pub input_read_bytes: u64,
}

/// `push_input` の結果（#3893）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct InputReport {
    /// 受信 FIFO に積んだバイト数。
    pub accepted: usize,
    /// 上限超過で捨てたバイト数。
    pub dropped: usize,
}

/// 8250 / 16550 互換の最小 UART のレジスタモデル。
#[derive(Clone)]
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
    int_pending: u8,
    irq_reported: IrqLevel,
    irq_line_errors: u64,
    /// 割り込み線が結線済みか（[`SerialConsole::mmio_device_with_irq`] が立てる）。線が無い経路では THRE を IIR に出さない。
    irq_wired: bool,
    /// IIR に RDA・THRE の保留を出すか。線ありの経路に加え、ポーリング用 MMIO（[`SerialConsole::mmio_device`]）でも立てる。
    /// Linux 8250 は irq=0 のタイマーポーリングでも IIR を見て送受信を進めるため、線の駆動（`irq_wired`）とは分ける（MVM-1）。
    iir_reports: bool,
    /// 線の実体（[`SerialConsole::mmio_device_with_irq`] が設定する）。ホストの `push_input` からも更新するため UART が持つ。
    line: Option<Weak<dyn LevelInterruptLine>>,
    rx: VecDeque<u8>,
    rx_capacity: usize,
    input_received_bytes: u64,
    input_dropped_bytes: u64,
    input_flushed_bytes: u64,
    input_read_bytes: u64,
}

impl fmt::Debug for Uart16550 {
    // 送信・受信のバイト列（非信頼）は出さない。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uart16550").finish_non_exhaustive()
    }
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

    /// 出力・入力の上限を指定して作る。それぞれ `1..=MAX_*_BYTES` の外は `InvalidArgument`（#3893）。
    pub fn with_capacities(output: usize, input: usize) -> Result<Self, MicrovmError> {
        if input == 0 || input > MAX_INPUT_BYTES {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "uart input capacity out of range",
            ));
        }
        let mut u = Self::with_output_capacity(output)?;
        u.rx_capacity = input;
        Ok(u)
    }

    /// ホストからの入力を受信 FIFO へ積む（#3893）。残り容量を超えた分は捨てて数える。線があれば同期する。
    pub fn push_input(&mut self, bytes: &[u8]) -> InputReport {
        let room = self.rx_capacity.saturating_sub(self.rx.len());
        let take = bytes.len().min(room);
        let (head, rest) = bytes.split_at(take);
        self.rx.extend(head.iter().copied());
        self.input_received_bytes = self.input_received_bytes.saturating_add(take as u64);
        self.input_dropped_bytes = self.input_dropped_bytes.saturating_add(rest.len() as u64);
        self.sync_line();
        InputReport {
            accepted: take,
            dropped: rest.len(),
        }
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
            int_pending: 0,
            irq_reported: IrqLevel::Low,
            irq_line_errors: 0,
            irq_wired: false,
            iir_reports: false,
            line: None,
            rx: VecDeque::new(),
            rx_capacity: MAX_INPUT_BYTES,
            input_received_bytes: 0,
            input_dropped_bytes: 0,
            input_flushed_bytes: 0,
            input_read_bytes: 0,
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
            irq_line_errors: self.irq_line_errors,
            input_received_bytes: self.input_received_bytes,
            input_buffered_bytes: self.rx.len(),
            input_dropped_bytes: self.input_dropped_bytes,
            input_flushed_bytes: self.input_flushed_bytes,
            input_read_bytes: self.input_read_bytes,
        }
    }

    fn rda_pending(&self) -> bool {
        self.iir_reports && self.ier & IER_ERBFI != 0 && !self.rx.is_empty()
    }

    fn thre_pending(&self) -> bool {
        self.iir_reports && self.ier & IER_ETBEI != 0 && self.int_pending & INT_THRE != 0
    }

    /// 割り込み線が今あるべき値。受信データ（ERBFI=1 で FIFO が空でない）か THRE（ETBEI=1 で保留）があれば `High`（#3892・#3893）。
    pub fn irq_level(&self) -> IrqLevel {
        if self.irq_wired && (self.rda_pending() || self.thre_pending()) {
            IrqLevel::High
        } else {
            IrqLevel::Low
        }
    }

    /// IIR の値。優先度の高い要因から返す（RDA > THRE。RLS・CTI は未実装）。
    fn iir(&self) -> u8 {
        let id = if self.rda_pending() {
            IIR_RDA
        } else if self.thre_pending() {
            IIR_THRE
        } else {
            IIR_NO_INT
        };
        if self.fifo_enabled { id | IIR_FIFO } else { id }
    }

    /// 自分の線（あれば）へ値の変化を伝える。
    pub(crate) fn sync_line(&mut self) {
        if let Some(line) = self.line.as_ref().and_then(Weak::upgrade) {
            self.sync_irq_line(line.as_ref());
        }
    }

    /// 線の値が最後に伝えた値と違うときだけ `line` へ伝える。失敗は計数して据え置き、次のアクセスで再試行する。
    pub(crate) fn sync_irq_line(&mut self, line: &dyn LevelInterruptLine) {
        let level = self.irq_level();
        if level == self.irq_reported {
            return;
        }
        match line.set_level(level) {
            Ok(()) => self.irq_reported = level,
            Err(_) => self.irq_line_errors = self.irq_line_errors.saturating_add(1),
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

    fn read_reg(&mut self, offset: u16) -> Option<u8> {
        let dlab = self.dlab();
        Some(match offset {
            0 if dlab => self.dll,
            0 => match self.rx.pop_front() {
                Some(b) => {
                    self.input_read_bytes = self.input_read_bytes.saturating_add(1);
                    b
                }
                None => 0,
            },
            1 if dlab => self.dlm,
            1 => self.ier,
            2 => {
                let v = self.iir();
                // THRE を返した読み出しで保留を下ろす（これが IIR の「ACK」）。
                if v & 0x0F == IIR_THRE {
                    self.int_pending &= !INT_THRE;
                }
                v
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => LSR_THRE_TEMT | if self.rx.is_empty() { 0 } else { LSR_DR },
            6 => self.msr(),
            7 => self.scr,
            _ => return None,
        })
    }

    fn write_reg(&mut self, offset: u16, value: u8) -> bool {
        let dlab = self.dlab();
        match offset {
            0 if dlab => self.dll = value,
            0 => {
                self.push_output(value);
                // 送信は即時に終わり THR はすぐ空になる。
                self.int_pending |= INT_THRE;
            }
            1 if dlab => self.dlm = value,
            1 => {
                let was = self.ier & IER_ETBEI;
                self.ier = value & IER_MASK;
                if self.ier & IER_ETBEI != was {
                    if self.ier & IER_ETBEI != 0 {
                        self.int_pending |= INT_THRE;
                    } else {
                        self.int_pending &= !INT_THRE;
                    }
                }
            }
            2 => {
                self.fifo_enabled = value & FCR_ENABLE != 0;
                if value & FCR_TX_RESET != 0 {
                    self.int_pending |= INT_THRE;
                }
                if value & FCR_RX_RESET != 0 {
                    self.input_flushed_bytes = self
                        .input_flushed_bytes
                        .saturating_add(self.rx.len() as u64);
                    self.rx.clear();
                }
            }
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

fn poisoned() -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, "uart lock poisoned")
}

/// [`Uart16550`] の共有ハンドル（PIO バス側とホスト側で同じバッファを見る。#3740・MVM-1）。
///
/// `microvm::DeviceBus` が [`SerialConsole::port_device`] を COM1 に登録し、ホストは clone を持って
/// [`SerialConsole::take_output`] で THR 出力を取り出す。fd を持たないので VM の drop 順序に影響しない。
/// lock が poison したら fail-closed（ホスト API は `Internal`、ゲスト側は `Ignored`）で、panic しない。
#[derive(Clone)]
pub struct SerialConsole {
    inner: Arc<Mutex<Uart16550>>,
}

impl fmt::Debug for SerialConsole {
    // ゲスト由来のバイト列（最大 64 KiB）を出さない。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerialConsole").finish_non_exhaustive()
    }
}

impl Default for SerialConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialConsole {
    /// 上限 [`MAX_OUTPUT_BYTES`] のコンソールを作る。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Uart16550::new())),
        }
    }

    /// 出力バッファの上限を指定して作る。範囲外は `InvalidArgument`。
    pub fn with_output_capacity(capacity: usize) -> Result<Self, MicrovmError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(Uart16550::with_output_capacity(capacity)?)),
        })
    }

    /// 出力・入力の上限を指定して作る。範囲外は `InvalidArgument`（#3893）。
    pub fn with_capacities(output: usize, input: usize) -> Result<Self, MicrovmError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(Uart16550::with_capacities(output, input)?)),
        })
    }

    /// ホストからゲストへ文字を渡す（#3893・MVM-5）。受信 FIFO の残りを超えた分は捨てて数える。
    ///
    /// 線がある経路では、ゲストのアクセスを待たずここで線を更新する（WFI で寝ているゲストは UART に触らないため）。
    /// 線の失敗は [`UartStats::irq_line_errors`] に数え、入力は受理済みとして `Ok` を返す。lock の poison は `Internal`。
    /// バイト列は非信頼で、解釈も記録もしない。
    pub fn push_input(&self, bytes: &[u8]) -> Result<InputReport, MicrovmError> {
        let mut u = self.inner.lock().map_err(|_| poisoned())?;
        Ok(u.push_input(bytes))
    }

    /// バッファのバイト列を全部取り出して空にする（長さは上限以下）。中身は非信頼のゲスト出力。
    pub fn take_output(&self) -> Result<Vec<u8>, MicrovmError> {
        let mut u = self.inner.lock().map_err(|_| poisoned())?;
        Ok(u.take_output())
    }

    /// 計数の写しを返す。
    pub fn stats(&self) -> Result<UartStats, MicrovmError> {
        let u = self.inner.lock().map_err(|_| poisoned())?;
        Ok(u.stats())
    }

    /// `ExitDispatcher::register_pio` へ渡すデバイス（同じバッファを共有する）を作る。
    pub fn port_device(&self) -> Box<dyn PortIoDevice> {
        Box::new(SharedUart(Arc::clone(&self.inner), None))
    }

    /// [`Self::port_device`] に割り込みの線をつけたもの（x86 の COM1 = IRQ 4。#3918・MVM-1・REPAIR-3）。
    ///
    /// 線は `crate::irq::IrqLevelLine`（`KVM_IRQ_LINE`）。各 PIO アクセスの後と [`Self::push_input`] の後に、UART の lock を
    /// 持ったまま線の値の変化だけを伝える。`line` の失敗でもアクセスは `Handled` のまま返し、
    /// [`UartStats::irq_line_errors`] に数える。この時点から THRE・受信データを IIR に出す。
    pub fn port_device_with_irq(&self, line: Arc<dyn LevelInterruptLine>) -> Box<dyn PortIoDevice> {
        if let Ok(mut u) = self.inner.lock() {
            u.irq_wired = true;
            u.iir_reports = true;
            u.iir_reports = true;
            u.line = Some(Arc::downgrade(&line));
        }
        // 線の強参照はデバイス（= DeviceBus・VM 側）が持つ。UART（SerialConsole の clone と共有）は Weak のみで、
        // 停止後に console を保持しても VM fd を延長しない（#3922）。
        Box::new(SharedUart(Arc::clone(&self.inner), Some(line)))
    }
}

impl SerialConsole {
    /// arm64 の MMIO バス用デバイス（同じバッファを共有する。割り込みは出さない。#3864・MVM-5）を作る。
    ///
    /// FDT の `reg-shift = 0`・`reg-io-width = 1` に合わせ、受けるのは 1 バイト幅・offset 0..8 のみ。
    pub fn mmio_device(&self) -> Box<dyn MmioDevice> {
        // 線は駆動しないが、ポーリングするゲストのため IIR には RDA・THRE の保留を出す（MVM-1）。
        if let Ok(mut u) = self.inner.lock() {
            u.iir_reports = true;
        }
        Box::new(SharedUartMmio {
            inner: Arc::clone(&self.inner),
            _line: None,
        })
    }

    /// [`Self::mmio_device`] に THRE 割り込みの線をつけたもの（#3892・MVM-5・MVM-1）。
    ///
    /// 各アクセスの後、UART の lock を持ったまま線の値の変化だけを `line` へ伝える（線の更新順を UART の状態の順に揃える）。
    /// `line` の失敗でもアクセスは `Handled` のまま返し、[`UartStats::irq_line_errors`] に数える。
    pub fn mmio_device_with_irq(&self, line: Arc<dyn LevelInterruptLine>) -> Box<dyn MmioDevice> {
        // 線ができたこの時点から THRE を IIR に出す（lock の poison は各アクセスが fail-closed に扱う）。
        if let Ok(mut u) = self.inner.lock() {
            u.irq_wired = true;
            u.iir_reports = true;
            u.iir_reports = true;
            u.line = Some(Arc::downgrade(&line));
        }
        Box::new(SharedUartMmio {
            inner: Arc::clone(&self.inner),
            _line: Some(line),
        })
    }
}

/// MMIO 用の共有ラッパー。幅・offset を検査してから [`Uart16550`] へ委ね、lock の poison は `Ignored`（fail-closed）。
struct SharedUartMmio {
    inner: Arc<Mutex<Uart16550>>,
    /// 線の強参照（VM 側の寿命に揃える。UART 本体は Weak のみ。#3922）。
    _line: Option<Arc<dyn LevelInterruptLine>>,
}

impl SharedUartMmio {
    fn reg(offset: u64, width: usize) -> Option<u16> {
        if width != 1 {
            return None;
        }
        u16::try_from(offset).ok().filter(|o| *o < UART_PORT_LEN)
    }

    fn sync(&self, u: &mut Uart16550) {
        u.sync_line();
    }
}

impl MmioDevice for SharedUartMmio {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        let Some(reg) = Self::reg(offset, data.len()) else {
            data.fill(0);
            return MmioReadOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth);
        };
        match self.inner.lock() {
            Ok(mut u) => match PortIoDevice::read(&mut *u, reg, data) {
                PortIoOutcome::Handled => {
                    self.sync(&mut u);
                    MmioReadOutcome::Handled
                }
                _ => {
                    data.fill(0);
                    MmioReadOutcome::Ignored(IgnoredAccess::UnknownRegister)
                }
            },
            Err(_) => {
                data.fill(0);
                MmioReadOutcome::Ignored(IgnoredAccess::UnknownRegister)
            }
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        let Some(reg) = Self::reg(offset, data.len()) else {
            return MmioWriteOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth);
        };
        match self.inner.lock() {
            Ok(mut u) => match PortIoDevice::write(&mut *u, reg, data) {
                PortIoOutcome::Handled => {
                    self.sync(&mut u);
                    MmioWriteOutcome::Handled
                }
                _ => MmioWriteOutcome::Ignored(IgnoredAccess::UnknownRegister),
            },
            Err(_) => MmioWriteOutcome::Ignored(IgnoredAccess::UnknownRegister),
        }
    }
}

/// dispatcher に登録する共有ラッパー。lock の poison には応答しない（read は dispatcher が 0xFF 埋め）。
struct SharedUart(
    Arc<Mutex<Uart16550>>,
    // 線の強参照（VM 側の寿命に揃える。UART 本体は Weak のみ）。
    #[allow(dead_code)] Option<Arc<dyn LevelInterruptLine>>,
);

impl PortIoDevice for SharedUart {
    fn read(&mut self, offset: u16, data: &mut [u8]) -> PortIoOutcome {
        match self.0.lock() {
            Ok(mut u) => {
                let out = u.read(offset, data);
                if out == PortIoOutcome::Handled {
                    // 線なし（`port_device`）では何もしない。線あり（#3918）は変化を UART の lock の下で伝える。
                    u.sync_line();
                }
                out
            }
            Err(_) => PortIoOutcome::Ignored,
        }
    }

    fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
        match self.0.lock() {
            Ok(mut u) => {
                let out = u.write(offset, data);
                if out == PortIoOutcome::Handled {
                    u.sync_line();
                }
                out
            }
            Err(_) => PortIoOutcome::Ignored,
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

    /// MVM-1・REPAIR-5・#3740: lock が poison したらホスト API は `Internal`、ゲスト側は応答しない。
    #[test]
    fn mvm1_3740_serial_console_poison_fails_closed() {
        let console = SerialConsole::new();
        let inner = Arc::clone(&console.inner);
        let _ = std::thread::spawn(move || {
            let _g = inner.lock().unwrap();
            panic!("poison the uart lock");
        })
        .join();
        assert_eq!(
            console.take_output().unwrap_err().code(),
            MicrovmErrorCode::Internal
        );
        assert_eq!(
            console.stats().unwrap_err().code(),
            MicrovmErrorCode::Internal
        );
        let mut dev = console.port_device();
        let mut buf = [0u8; 1];
        assert_eq!(dev.read(5, &mut buf), PortIoOutcome::Ignored);
        assert_eq!(dev.write(0, b"a"), PortIoOutcome::Ignored);
    }

    /// MVM-5・#3864: MMIO アダプタ経由の THR 書き込みがコンソールの出力に届く。
    #[test]
    fn mvm5_3864_mmio_adapter_writes_reach_console() {
        let console = SerialConsole::new();
        let mut dev = console.mmio_device();
        assert_eq!(dev.write(0, b"h"), MmioWriteOutcome::Handled);
        assert_eq!(dev.write(0, b"i"), MmioWriteOutcome::Handled);
        assert_eq!(console.take_output().unwrap(), b"hi".to_vec());
    }

    /// MVM-5・#3864: LSR（offset 5）は 0x60。
    #[test]
    fn mvm5_3864_mmio_adapter_reads_lsr() {
        let console = SerialConsole::new();
        let dev = console.mmio_device();
        let mut buf = [0xffu8; 1];
        assert_eq!(dev.read(5, &mut buf), MmioReadOutcome::Handled);
        assert_eq!(buf, [0x60]);
    }

    /// MVM-5・#3864: 幅違い・範囲外 offset は無視し、読み出しは 0 埋め。
    #[test]
    fn mvm5_3864_mmio_adapter_rejects_bad_access() {
        let console = SerialConsole::new();
        let mut dev = console.mmio_device();
        let mut wide = [0xffu8; 4];
        assert_eq!(
            dev.read(0, &mut wide),
            MmioReadOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(wide, [0; 4]);
        let mut one = [0xffu8; 1];
        assert!(matches!(dev.read(8, &mut one), MmioReadOutcome::Ignored(_)));
        assert_eq!(one, [0]);
        assert!(matches!(dev.write(8, b"x"), MmioWriteOutcome::Ignored(_)));
        assert!(matches!(
            dev.write(0, b"abcd"),
            MmioWriteOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth)
        ));
        assert_eq!(console.take_output().unwrap(), Vec::<u8>::new());
    }

    /// MVM-5・REPAIR-5・#3864: lock が poison しても panic せず `Ignored`。
    #[test]
    fn mvm5_3864_mmio_adapter_poison_fails_closed() {
        let console = SerialConsole::new();
        let inner = Arc::clone(&console.inner);
        let _ = std::thread::spawn(move || {
            let _g = inner.lock().unwrap();
            panic!("poison the uart lock");
        })
        .join();
        let mut dev = console.mmio_device();
        let mut buf = [0xffu8; 1];
        assert!(matches!(dev.read(5, &mut buf), MmioReadOutcome::Ignored(_)));
        assert_eq!(buf, [0]);
        assert!(matches!(dev.write(0, b"a"), MmioWriteOutcome::Ignored(_)));
    }

    /// 呼び出し列を記録する偽の線。`fail` が真なら失敗する。
    #[derive(Debug, Clone, Default)]
    struct FakeLine {
        calls: Arc<Mutex<Vec<IrqLevel>>>,
        fail: bool,
    }

    impl LevelInterruptLine for FakeLine {
        fn set_level(&self, level: IrqLevel) -> Result<(), MicrovmError> {
            if self.fail {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "fake failure",
                ));
            }
            self.calls.lock().unwrap().push(level);
            Ok(())
        }
    }

    /// MVM-5・MVM-1・#3892: ETBEI で線が立ち、IIR 読み出しで下がる。
    #[test]
    fn mvm5_3892_uart_etbei_raises_thre() {
        let mut u = Uart16550::new();
        u.irq_wired = true;
        u.iir_reports = true;
        assert_eq!(u.irq_level(), IrqLevel::Low);
        wr(&mut u, 1, 0x02);
        assert_eq!(u.irq_level(), IrqLevel::High);
        assert_eq!(rd(&mut u, 2), 0x02);
        assert_eq!(u.irq_level(), IrqLevel::Low);
        assert_eq!(rd(&mut u, 2), 0x01);
    }

    /// MVM-5・MVM-1・#3892: 線の無い経路（x86 の PIO・線なしの MMIO）は ETBEI=1 でも IIR が常に 0x01 で線も Low。
    #[test]
    fn mvm5_3892_uart_unwired_iir_stays_no_int() {
        let console = SerialConsole::new();
        let mut dev = console.port_device();
        assert_eq!(dev.write(1, &[0x02]), PortIoOutcome::Handled);
        let mut buf = [0u8; 1];
        assert_eq!(dev.read(2, &mut buf), PortIoOutcome::Handled);
        assert_eq!(buf, [0x01]);
        assert_eq!(console.inner.lock().unwrap().irq_level(), IrqLevel::Low);
    }

    /// MVM-1・#3898: ポーリング用 MMIO（線なし）でも IER に応じて IIR に THRE・RDA を返し、線は Low のまま。
    #[test]
    fn mvm1_3898_polling_mmio_reports_iir_pending() {
        let console = SerialConsole::new();
        let mut dev = console.mmio_device();
        let mut buf = [0u8; 1];
        assert_eq!(dev.write(1, &[0x02]), MmioWriteOutcome::Handled);
        assert_eq!(dev.read(2, &mut buf), MmioReadOutcome::Handled);
        assert_eq!(buf, [0x02]);
        assert_eq!(dev.read(2, &mut buf), MmioReadOutcome::Handled);
        assert_eq!(buf, [0x01]);
        assert_eq!(dev.write(1, &[0x01]), MmioWriteOutcome::Handled);
        console.push_input(b"a").unwrap();
        assert_eq!(dev.read(2, &mut buf), MmioReadOutcome::Handled);
        assert_eq!(buf, [0x04]);
        assert_eq!(console.inner.lock().unwrap().irq_level(), IrqLevel::Low);
    }

    /// MVM-5・MVM-1・#3892: THR 書き込みで再び立つ。
    #[test]
    fn mvm5_3892_uart_thr_write_reasserts() {
        let mut u = Uart16550::new();
        u.irq_wired = true;
        u.iir_reports = true;
        wr(&mut u, 1, 0x02);
        assert_eq!(rd(&mut u, 2), 0x02);
        wr(&mut u, 0, b'x');
        assert_eq!(u.irq_level(), IrqLevel::High);
        assert_eq!(rd(&mut u, 2), 0x02);
    }

    /// MVM-5・MVM-1・#3892: ETBEI=0 では立たない。
    #[test]
    fn mvm5_3892_uart_etbei_zero_never_raises() {
        let mut u = Uart16550::new();
        wr(&mut u, 0, b'x');
        assert_eq!(u.irq_level(), IrqLevel::Low);
        wr(&mut u, 2, 0x04);
        assert_eq!(u.irq_level(), IrqLevel::Low);
        assert_eq!(rd(&mut u, 2), 0x01);
        assert_eq!(u.irq_level(), IrqLevel::Low);
    }

    /// MVM-5・#3892: FIFO 有効時の IIR は上位 0xC0 つき。
    #[test]
    fn mvm5_3892_uart_fifo_iir_values() {
        let mut u = Uart16550::new();
        u.irq_wired = true;
        u.iir_reports = true;
        wr(&mut u, 2, 0x01);
        wr(&mut u, 1, 0x02);
        assert_eq!(rd(&mut u, 2), 0xC2);
        assert_eq!(rd(&mut u, 2), 0xC1);
    }

    /// MVM-5・#3892: ETBEI を落とすと線が下がる。
    #[test]
    fn mvm5_3892_uart_etbei_clear_drops_line() {
        let mut u = Uart16550::new();
        u.irq_wired = true;
        u.iir_reports = true;
        wr(&mut u, 1, 0x02);
        assert_eq!(u.irq_level(), IrqLevel::High);
        wr(&mut u, 1, 0x00);
        assert_eq!(u.irq_level(), IrqLevel::Low);
    }

    /// MVM-5・#3892: DLAB=1 の offset 1 は DLM で、割り込み状態を変えない。
    #[test]
    fn mvm5_3892_uart_dlab_does_not_touch_irq() {
        let mut u = Uart16550::new();
        wr(&mut u, 3, 0x83);
        wr(&mut u, 1, 0x02);
        assert_eq!(u.irq_level(), IrqLevel::Low);
        wr(&mut u, 3, 0x03);
        assert_eq!(rd(&mut u, 1), 0x00);
    }

    /// MVM-5・MVM-1・#3892: MMIO ラッパー経由で値が変わったときだけ線へ伝わる。
    #[test]
    fn mvm5_3892_mmio_irq_line_sequence() {
        let console = SerialConsole::new();
        let line = FakeLine::default();
        let mut dev = console.mmio_device_with_irq(Arc::new(line.clone()));
        let calls = || line.calls.lock().unwrap().clone();
        assert_eq!(dev.write(1, &[0x02]), MmioWriteOutcome::Handled);
        assert_eq!(calls(), vec![IrqLevel::High]);
        assert_eq!(dev.write(1, &[0x02]), MmioWriteOutcome::Handled);
        assert_eq!(calls(), vec![IrqLevel::High]);
        let mut b = [0u8; 1];
        assert_eq!(dev.read(2, &mut b), MmioReadOutcome::Handled);
        assert_eq!(b, [0x02]);
        assert_eq!(calls(), vec![IrqLevel::High, IrqLevel::Low]);
        assert_eq!(dev.write(0, b"a"), MmioWriteOutcome::Handled);
        assert_eq!(calls(), vec![IrqLevel::High, IrqLevel::Low, IrqLevel::High]);
        assert_eq!(dev.write(1, &[0x00]), MmioWriteOutcome::Handled);
        assert_eq!(
            calls(),
            vec![IrqLevel::High, IrqLevel::Low, IrqLevel::High, IrqLevel::Low]
        );
        assert_eq!(console.take_output().unwrap(), b"a".to_vec());
    }

    /// MVM-5・REPAIR-4・#3892: 線の失敗でもアクセスは成立し、計数して次のアクセスで再試行する。
    #[test]
    fn mvm5_3892_mmio_irq_line_failure_counted() {
        let console = SerialConsole::new();
        let line = FakeLine {
            fail: true,
            ..Default::default()
        };
        let mut dev = console.mmio_device_with_irq(Arc::new(line));
        assert_eq!(dev.write(1, &[0x02]), MmioWriteOutcome::Handled);
        assert_eq!(console.stats().unwrap().irq_line_errors, 1);
        assert_eq!(dev.write(1, &[0x02]), MmioWriteOutcome::Handled);
        assert_eq!(console.stats().unwrap().irq_line_errors, 2);
    }

    /// MVM-1・REPAIR-5・#3922: console の clone を保持したままデバイスを drop すると線の強参照が解放され、出力は読める。
    #[test]
    fn mvm1_3922_device_drop_releases_line_keeps_output() {
        let console = SerialConsole::new();
        let line: Arc<dyn LevelInterruptLine> = Arc::new(FakeLine::default());
        let weak = Arc::downgrade(&line);
        let mut dev = console.port_device_with_irq(line);
        assert_eq!(dev.write(0, b"A"), PortIoOutcome::Handled);
        assert_eq!(weak.strong_count(), 1);
        drop(dev);
        assert_eq!(weak.strong_count(), 0);
        assert!(weak.upgrade().is_none());
        assert_eq!(console.take_output().unwrap(), b"A".to_vec());
        // 線が無くなっても push_input は失敗せず受理される。
        assert!(console.push_input(b"k").is_ok());
        assert_eq!(console.stats().unwrap().irq_line_errors, 0);
    }

    /// MVM-5・MVM-1・#3918: PIO ラッパー経由でも値が変わったときだけ線へ伝わる（THRE・受信データ）。
    #[test]
    fn mvm5_3918_pio_irq_line_sequence() {
        let console = SerialConsole::new();
        let line = FakeLine::default();
        let mut dev = console.port_device_with_irq(Arc::new(line.clone()));
        let calls = || line.calls.lock().unwrap().clone();
        let (h, l) = (IrqLevel::High, IrqLevel::Low);
        assert_eq!(dev.write(1, &[0x02]), PortIoOutcome::Handled);
        assert_eq!(calls(), vec![h]);
        assert_eq!(dev.write(1, &[0x02]), PortIoOutcome::Handled);
        assert_eq!(calls(), vec![h]);
        let mut b = [0u8; 1];
        assert_eq!(dev.read(2, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [0x02]);
        assert_eq!(calls(), vec![h, l]);
        // ETBEI を下げてから ERBFI だけにし、ホストの入力で上がる。
        assert_eq!(dev.write(1, &[0x01]), PortIoOutcome::Handled);
        assert_eq!(calls(), vec![h, l]);
        console.push_input(b"k").unwrap();
        assert_eq!(calls(), vec![h, l, h]);
        assert_eq!(dev.read(2, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [0x04]);
        assert_eq!(calls(), vec![h, l, h]);
        assert_eq!(dev.read(0, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [b'k']);
        assert_eq!(calls(), vec![h, l, h, l]);
    }

    /// MVM-5・REPAIR-4・#3918: PIO の線の失敗でもアクセスは成立し、計数して次のアクセスで再試行する。
    #[test]
    fn mvm5_3918_pio_irq_line_failure_counted() {
        let console = SerialConsole::new();
        let line = FakeLine {
            fail: true,
            ..Default::default()
        };
        let mut dev = console.port_device_with_irq(Arc::new(line));
        assert_eq!(dev.write(1, &[0x02]), PortIoOutcome::Handled);
        assert_eq!(console.stats().unwrap().irq_line_errors, 1);
        assert_eq!(dev.write(1, &[0x02]), PortIoOutcome::Handled);
        assert_eq!(console.stats().unwrap().irq_line_errors, 2);
    }

    fn wired(u: &mut Uart16550) {
        u.irq_wired = true;
        u.iir_reports = true;
    }

    /// MVM-5・CORE-7・#3893: 入力は先頭から順に RBR で読め、LSR.DR が追従する。
    #[test]
    fn mvm5_3893_rx_dr_and_rbr_order() {
        let mut u = Uart16550::new();
        assert_eq!(rd(&mut u, 5), 0x60);
        let r = u.push_input(b"ab");
        assert_eq!((r.accepted, r.dropped), (2, 0));
        assert_eq!(rd(&mut u, 5), 0x61);
        assert_eq!(rd(&mut u, 0), b'a');
        assert_eq!(rd(&mut u, 0), b'b');
        assert_eq!(rd(&mut u, 5), 0x60);
        assert_eq!(rd(&mut u, 0), 0);
        let st = u.stats();
        assert_eq!(
            (
                st.input_received_bytes,
                st.input_read_bytes,
                st.input_buffered_bytes
            ),
            (2, 2, 0)
        );
    }

    /// MVM-5・CORE-7・#3893: 上限超過は新しい方を捨てて数え、上限の範囲外は拒否する。
    #[test]
    fn mvm5_3893_rx_overflow_drops_newest() {
        let mut u = Uart16550::with_capacities(8, 4).unwrap();
        let r = u.push_input(b"abcdefg");
        assert_eq!((r.accepted, r.dropped), (4, 3));
        let st = u.stats();
        assert_eq!((st.input_dropped_bytes, st.input_buffered_bytes), (3, 4));
        let got: Vec<u8> = (0..4).map(|_| rd(&mut u, 0)).collect();
        assert_eq!(got, b"abcd".to_vec());
        for bad in [0, MAX_INPUT_BYTES + 1] {
            assert_eq!(
                Uart16550::with_capacities(8, bad).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument
            );
        }
    }

    /// MVM-5・#3893: ERBFI と入力で IIR=0x04・High、読み切ると解除。
    #[test]
    fn mvm5_3893_rx_interrupt_raise_and_clear() {
        let mut u = Uart16550::new();
        wired(&mut u);
        wr(&mut u, 2, 0x01);
        wr(&mut u, 1, 0x01);
        assert_eq!(u.irq_level(), IrqLevel::Low);
        u.push_input(b"x");
        assert_eq!(u.irq_level(), IrqLevel::High);
        assert_eq!(rd(&mut u, 2), 0xC4);
        assert_eq!(rd(&mut u, 2), 0xC4);
        assert_eq!(rd(&mut u, 0), b'x');
        assert_eq!(u.irq_level(), IrqLevel::Low);
        assert_eq!(rd(&mut u, 2), 0xC1);
    }

    /// MVM-5・#3893: THRE と同時保留でも IIR は受信データが先で、読み切ると THRE が出る。
    #[test]
    fn mvm5_3893_rx_priority_over_thre() {
        let mut u = Uart16550::new();
        wired(&mut u);
        wr(&mut u, 1, 0x03);
        u.push_input(b"a");
        assert_eq!(rd(&mut u, 2), 0x04);
        assert_eq!(rd(&mut u, 0), b'a');
        assert_eq!(rd(&mut u, 2), 0x02);
        assert_eq!(rd(&mut u, 2), 0x01);
    }

    /// MVM-5・#3893: 偽の線で、ゲストのアクセス無しに push_input が線を立てる。
    #[test]
    fn mvm5_3893_push_input_drives_line() {
        let console = SerialConsole::new();
        let line = FakeLine::default();
        let mut dev = console.mmio_device_with_irq(Arc::new(line.clone()));
        let calls = || line.calls.lock().unwrap().clone();
        assert_eq!(dev.write(1, &[0x01]), MmioWriteOutcome::Handled);
        assert!(calls().is_empty());
        console.push_input(b"x").unwrap();
        assert_eq!(calls(), vec![IrqLevel::High]);
        console.push_input(b"y").unwrap();
        assert_eq!(calls(), vec![IrqLevel::High]);
        let mut b = [0u8; 1];
        assert_eq!(dev.read(0, &mut b), MmioReadOutcome::Handled);
        assert_eq!(b, [b'x']);
        assert_eq!(calls(), vec![IrqLevel::High]);
        assert_eq!(dev.read(0, &mut b), MmioReadOutcome::Handled);
        assert_eq!(b, [b'y']);
        assert_eq!(calls(), vec![IrqLevel::High, IrqLevel::Low]);
    }

    /// MVM-5・#3893: 線の無い経路でも DR と RBR は動き、IIR は 0x01 のまま。
    #[test]
    fn mvm5_3893_unwired_polling_works() {
        let console = SerialConsole::new();
        let mut dev = console.port_device();
        assert_eq!(dev.write(1, &[0x01]), PortIoOutcome::Handled);
        console.push_input(b"z").unwrap();
        let mut b = [0u8; 1];
        assert_eq!(dev.read(2, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [0x01]);
        assert_eq!(dev.read(5, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [0x61]);
        assert_eq!(dev.read(0, &mut b), PortIoOutcome::Handled);
        assert_eq!(b, [b'z']);
    }

    /// MVM-5・REPAIR-4・#3893: FCR の RX リセットで FIFO が空になり、数えられ、線が下がる。
    #[test]
    fn mvm5_3893_fcr_rx_reset_flushes() {
        let console = SerialConsole::new();
        let line = FakeLine::default();
        let mut dev = console.mmio_device_with_irq(Arc::new(line.clone()));
        assert_eq!(dev.write(1, &[0x01]), MmioWriteOutcome::Handled);
        console.push_input(b"abc").unwrap();
        assert_eq!(dev.write(2, &[0x03]), MmioWriteOutcome::Handled);
        let st = console.stats().unwrap();
        assert_eq!((st.input_flushed_bytes, st.input_buffered_bytes), (3, 0));
        assert_eq!(
            *line.calls.lock().unwrap(),
            vec![IrqLevel::High, IrqLevel::Low]
        );
    }

    /// MVM-5・#3893: DLAB=1 の offset 0 は DLL で、FIFO を消費しない。
    #[test]
    fn mvm5_3893_dlab_read_keeps_fifo() {
        let mut u = Uart16550::new();
        u.push_input(b"a");
        wr(&mut u, 3, 0x83);
        assert_eq!(rd(&mut u, 0), 0x0C);
        wr(&mut u, 3, 0x03);
        assert_eq!(rd(&mut u, 5), 0x61);
    }

    /// MVM-5・#3893: poison で push_input は Internal を返す。
    #[test]
    fn mvm5_3893_push_input_poison_fails_closed() {
        let console = SerialConsole::new();
        let c2 = console.clone();
        let _ = std::thread::spawn(move || {
            let _g = c2.inner.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(
            console.push_input(b"a").unwrap_err().code(),
            MicrovmErrorCode::Internal
        );
    }

    /// MVM-5・REPAIR-4・#3893: 線が失敗しても push_input は成功し、数えられる。
    #[test]
    fn mvm5_3893_push_input_line_failure_counted() {
        let console = SerialConsole::new();
        let line = FakeLine {
            fail: true,
            ..Default::default()
        };
        let mut dev = console.mmio_device_with_irq(Arc::new(line));
        assert_eq!(dev.write(1, &[0x01]), MmioWriteOutcome::Handled);
        let before = console.stats().unwrap().irq_line_errors;
        let r = console.push_input(b"a").unwrap();
        assert_eq!(r.accepted, 1);
        assert_eq!(console.stats().unwrap().irq_line_errors, before + 1);
    }
}
