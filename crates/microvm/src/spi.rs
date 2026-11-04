//! SPI 線の注入方式（edge / level）と ACK 後の deassert・resample（#3863・MVM-5・MVM-1）。
//!
//! 役割: macOS の `hv_gic_set_spi(intid, level)` のような「INTID と線の値を渡す」口を [`SpiSink`] に抽象し、
//! その上で [`crate::interrupt::InterruptLine`] を実装する [`SpiLine`] を OS 非依存に置く。注入方式による分岐
//! （edge は上げるだけ、level は ACK 後に要因の残りで下げる / 上げ直す）をここに閉じ込め、Linux の CI で
//! 偽の GIC（呼び出し列を記録する sink）に対して具体値で試験できるようにする。macOS 固有部は
//! `crate::hvf::gic` の sink（`hv_gic_set_spi` を呼ぶだけ）に限る。
//!
//! 呼び出し元: 完了通知（`complete_block_notify` 等）が `trigger`、MMIO exit の `InterruptACK` の後処理
//! （`complete_interrupt_ack`）が `resample` を呼ぶ。FDT の trigger との整合は `arm64_layout` の
//! `check_virtio_spi_injection` が組み立て時に照合する。待ちは持たない（REPAIR-5 不要）。`unsafe` は持たない。

use crate::error::MicrovmError;
use crate::interrupt::{InterruptLine, IrqTrigger, LineResample};

/// SPI の線の値を設定する口（macOS では `GicApi::set_spi`、試験では偽の GIC）。
pub trait SpiSink: Send + Sync + std::fmt::Debug {
    /// `intid` の SPI の線を `level` にする。
    fn set_spi(&self, intid: u32, level: bool) -> Result<(), MicrovmError>;
}

/// 1 本の SPI を [`SpiSink`] 経由で注入する [`InterruptLine`]。
#[derive(Debug, Clone)]
pub struct SpiLine<S: SpiSink> {
    sink: S,
    intid: u32,
    injection: IrqTrigger,
}

impl<S: SpiSink> SpiLine<S> {
    /// 線を作る。INTID の範囲検査は呼び出し元（`check_spi_intid`）が済ませている前提。
    pub fn new(sink: S, intid: u32, injection: IrqTrigger) -> Self {
        Self {
            sink,
            intid,
            injection,
        }
    }

    /// 注入する INTID。
    pub fn intid(&self) -> u32 {
        self.intid
    }
}

impl<S: SpiSink> InterruptLine for SpiLine<S> {
    /// edge・level とも `set_spi(intid, true)` を 1 回呼ぶ（edge の `false` は framework が無視するため呼ばない）。
    fn trigger(&self) -> Result<(), MicrovmError> {
        self.sink.set_spi(self.intid, true)
    }

    fn injection(&self) -> IrqTrigger {
        self.injection
    }

    /// level: 要因が無ければ `false` で下げ、残っていれば `true` で上げ直す（冪等）。edge: 何もしない。
    fn resample(&self, pending: bool) -> Result<LineResample, MicrovmError> {
        match self.injection {
            IrqTrigger::LevelHigh if pending => {
                self.sink.set_spi(self.intid, true)?;
                Ok(LineResample::Reasserted)
            }
            IrqTrigger::LevelHigh => {
                self.sink.set_spi(self.intid, false)?;
                Ok(LineResample::Deasserted)
            }
            _ => Ok(LineResample::NotApplicable),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! 偽の GIC による試験（全 OS。MVM-5・MVM-1・REPAIR-12）。
    use super::*;
    use crate::error::MicrovmErrorCode;
    use std::sync::{Arc, Mutex};

    /// 呼び出し列 `(intid, level)` を記録する偽の GIC。`fail` が真なら全呼び出しが `Internal` で失敗する。
    #[derive(Debug, Clone, Default)]
    pub(crate) struct RecordingGic {
        pub(crate) calls: Arc<Mutex<Vec<(u32, bool)>>>,
        pub(crate) fail: bool,
    }

    impl RecordingGic {
        pub(crate) fn calls(&self) -> Vec<(u32, bool)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl SpiSink for RecordingGic {
        fn set_spi(&self, intid: u32, level: bool) -> Result<(), MicrovmError> {
            if self.fail {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "fake gic failure",
                ));
            }
            self.calls.lock().unwrap().push((intid, level));
            Ok(())
        }
    }

    #[test]
    fn mvm5_3863_level_spi_assert_ack_deassert_order() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::LevelHigh);
        line.trigger().unwrap();
        assert_eq!(line.resample(false).unwrap(), LineResample::Deasserted);
        assert_eq!(gic.calls(), vec![(48, true), (48, false)]);
    }

    #[test]
    fn mvm5_3863_level_spi_resample_keeps_pending() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::LevelHigh);
        line.trigger().unwrap();
        assert_eq!(line.resample(true).unwrap(), LineResample::Reasserted);
        assert_eq!(gic.calls(), vec![(48, true), (48, true)]);
    }

    #[test]
    fn mvm5_3863_edge_spi_ack_is_noop() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::EdgeRising);
        line.trigger().unwrap();
        assert_eq!(line.resample(false).unwrap(), LineResample::NotApplicable);
        assert_eq!(line.resample(true).unwrap(), LineResample::NotApplicable);
        assert_eq!(gic.calls(), vec![(48, true)]);
        assert_eq!(line.injection(), IrqTrigger::EdgeRising);
    }

    #[test]
    fn mvm5_3863_sink_failure_is_propagated() {
        let gic = RecordingGic {
            fail: true,
            ..Default::default()
        };
        let line = SpiLine::new(gic, 48, IrqTrigger::LevelHigh);
        assert_eq!(
            line.trigger().unwrap_err().code(),
            MicrovmErrorCode::Internal
        );
        assert_eq!(
            line.resample(false).unwrap_err().code(),
            MicrovmErrorCode::Internal
        );
    }
}
