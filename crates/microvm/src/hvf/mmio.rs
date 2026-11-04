//! MMIO（ISV=1 の data abort）の exit 処理（スタブ。TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した data abort を、デバイスモデルの MMIO 窓へ振り分ける入口。
//! 本ファイルのシグネチャは `hvf::vcpu` との契約で、担当 issue（#3793）が `vcpu.rs` に触れず本ファイルだけを差し替える。
//! 現状は何もせず `Unimplemented` を返し、ループは VM を止める（実装済みを装わない）。
//!
//! # 将来仕様（#3793）
//! `DataAbort` の幅・符号拡張・転送レジスタ・向きを使って MMIO を処理し、読みの結果を `SRT` のレジスタへ書く。PC を進める
//! 責務はここにある（data abort は faulting 命令自身を指すため、`esr::instruction_length` の分だけ進める。esr.rs の要確認事項）。
//! 窓の外のアクセスは `Failed` で止める（fail-closed）。ゲスト由来のアドレス・値は信頼せず、長さを検証する。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::DataAbort;
use crate::hvf_abi::HvVcpuExitException;
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;

/// MMIO ハンドラの状態（デバイスバス等。#3793 が持たせる）。
#[derive(Debug, Default)]
pub struct MmioHandler {
    _private: (),
}

impl MmioHandler {
    /// 空のハンドラを作る。
    pub fn new() -> Self {
        Self::default()
    }
}

/// data abort を処理する（スタブ）。常に `Unimplemented`。
pub fn handle_data_abort(
    _vcpu: &mut HvVcpu<'_>,
    _handler: &mut MmioHandler,
    _abort: &DataAbort,
    _exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    Err(MicrovmError::new(
        MicrovmErrorCode::Unimplemented,
        "data abort exit handling is not implemented",
    ))
}
