//! x86_64 の AP（vCPU 1 以上）の起動計画と SIPI の開始ページの検証を行う純粋な論理（#3737・MVM-1・MS-7・TASK-75.4・TASK-75.5。
//! OS・arch 非依存・`unsafe` なし）。
//!
//! 呼び出し元は `microvm::MicroVm::assemble`（[`plan_vcpus`] で vCPU の APIC ID と初期 MP 状態を決める）と
//! `microvm::MicroVm::write_ap_startup_code`（[`sipi_startup_range`] で起動コードの置き場所を検証する）。
//! ioctl（`KVM_{GET,SET}_MP_STATE`）は `device` / `sys` 側にあり、本モジュールは KVM なしで具体値を試験できる。
//!
//! # 一次情報
//! - Intel SDM Vol. 3A の MP 初期化（BSP が INIT IPI と STARTUP IPI〔SIPI〕で AP を起こす）。SIPI のベクタ V は AP の開始アドレス
//!   `V << 12`（real mode の CS = V << 8・IP = 0）を表し、SDM は V = 0xA0〜0xBF を予約する。
//! - `include/uapi/linux/kvm.h`（v6.12）の `KVM_MP_STATE_*` と `struct kvm_mp_state`。in-kernel LAPIC のある VM では、
//!   非 BSP の vCPU は作成時に `UNINITIALIZED`（INIT/SIPI 待ち）になる。
//!
//! Firecracker・rust-vmm のコードは参照も流用もしない（MVM-4）。
//!
//! # 範囲外（REPAIR-3）
//! Linux ゲストは自分で AP 用の trampoline を置いて SIPI を送る。本 API はファームウェアの無い起動コードと試験のためのもので、
//! e820 への予約領域の記載は範囲外。vCPU ごとのスレッドでの実行と `start` の 2 台以上の対応は #3738。

use crate::boot_x86::{CMDLINE_ADDR, CMDLINE_CAPACITY, LOW_RAM_END, ZERO_PAGE_ADDR};
use crate::error::{MicrovmError, MicrovmErrorCode};

/// xAPIC の APIC ID が 8 bit であることから来る vCPU 数の上限（0xFF は broadcast のため除く）。
pub const MAX_XAPIC_VCPUS: u32 = 255;
/// SIPI の開始ページ 1 枚のバイト数。
pub const SIPI_PAGE_SIZE: u64 = 0x1000;

/// KVM の MP 状態（`KVM_MP_STATE_*`。kvm.h v6.12）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpState {
    Runnable,
    Uninitialized,
    InitReceived,
    Halted,
    SipiReceived,
    /// 上記以外（観測用）。
    Other(u32),
}

impl MpState {
    /// カーネルの値から変換する。
    pub fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Runnable,
            1 => Self::Uninitialized,
            2 => Self::InitReceived,
            3 => Self::Halted,
            4 => Self::SipiReceived,
            n => Self::Other(n),
        }
    }

    /// カーネルの値へ変換する。
    pub fn as_raw(self) -> u32 {
        match self {
            Self::Runnable => 0,
            Self::Uninitialized => 1,
            Self::InitReceived => 2,
            Self::Halted => 3,
            Self::SipiReceived => 4,
            Self::Other(n) => n,
        }
    }
}

/// vCPU の役割。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRole {
    /// ブートプロセッサ（vCPU 0）。
    Bsp,
    /// アプリケーションプロセッサ（vCPU 1 以上）。
    Ap,
}

/// vCPU 1 台分の起動計画。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcpuBootPlan {
    /// vCPU id（`KVM_CREATE_VCPU` の引数）。
    pub index: u32,
    /// CPUID と LAPIC に載せる APIC ID（vCPU id と同じ）。
    pub apic_id: u32,
    pub role: VcpuRole,
    /// 作成直後に設定する MP 状態（BSP は実行可、AP は INIT/SIPI 待ち）。
    pub initial_mp_state: MpState,
}

/// `count` 台の vCPU の起動計画を返す。0 台と [`MAX_XAPIC_VCPUS`] 超は `InvalidArgument`（確保の前に検証する）。
pub fn plan_vcpus(count: u32) -> Result<Vec<VcpuBootPlan>, MicrovmError> {
    if count == 0 || count > MAX_XAPIC_VCPUS {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "vcpu count is out of range for xAPIC",
        ));
    }
    Ok((0..count)
        .map(|index| {
            let bsp = index == 0;
            VcpuBootPlan {
                index,
                apic_id: index,
                role: if bsp { VcpuRole::Bsp } else { VcpuRole::Ap },
                initial_mp_state: if bsp {
                    MpState::Runnable
                } else {
                    MpState::Uninitialized
                },
            }
        })
        .collect())
}

/// SIPI のベクタ（開始アドレスの上位。`V << 12`）。SDM が予約する 0xA0〜0xBF は作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SipiVector(u8);

impl SipiVector {
    /// 予約範囲（0xA0〜0xBF）を拒否して作る。
    pub fn new(v: u8) -> Result<Self, MicrovmError> {
        if (0xA0..=0xBF).contains(&v) {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "SIPI vector is reserved",
            ));
        }
        Ok(Self(v))
    }

    /// ベクタの値。
    pub fn value(self) -> u8 {
        self.0
    }

    /// AP の開始アドレス（`V << 12`）。
    pub fn start_address(self) -> u64 {
        u64::from(self.0) << 12
    }
}

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

/// AP の起動コードを `vector` のページへ `code_len` バイト置けるかを検証し、`(開始, 終端)` を返す（終端は排他）。
///
/// 拒否: `code_len` が 0 か 1 ページ超・ページ 0（IVT/BDA と BSP 用の GDT・IDT）・boot_params からコマンドライン末尾までの
/// ブート用領域との重なり・低位 RAM の終端（[`LOW_RAM_END`]）超・ゲストメモリ長（`mem_len`）超。値はエラー message に載せない（ERR-1）。
pub fn sipi_startup_range(
    vector: SipiVector,
    code_len: usize,
    mem_len: u64,
) -> Result<(u64, u64), MicrovmError> {
    let len = u64::try_from(code_len).map_err(|_| invalid("AP startup code is too long"))?;
    if len == 0 || len > SIPI_PAGE_SIZE {
        return Err(invalid("AP startup code length must be 1..=4096 bytes"));
    }
    let start = vector.start_address();
    let end = start
        .checked_add(SIPI_PAGE_SIZE)
        .ok_or_else(|| invalid("AP startup page overflows"))?;
    if start < SIPI_PAGE_SIZE {
        return Err(invalid("AP startup page overlaps the real-mode data area"));
    }
    let boot_end = CMDLINE_ADDR
        .checked_add(CMDLINE_CAPACITY)
        .ok_or_else(|| invalid("boot area overflows"))?;
    if start < boot_end && end > ZERO_PAGE_ADDR {
        return Err(invalid("AP startup page overlaps the boot data area"));
    }
    if end > LOW_RAM_END {
        return Err(invalid("AP startup page exceeds low RAM"));
    }
    if end > mem_len {
        return Err(invalid("AP startup page is outside guest memory"));
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1・#3737: APIC ID は vCPU id と同じで、BSP だけが Runnable。
    #[test]
    fn mvm1_3737_plan_vcpus_assigns_apic_id_and_mp_state() {
        let one = plan_vcpus(1).unwrap();
        assert_eq!(
            one,
            vec![VcpuBootPlan {
                index: 0,
                apic_id: 0,
                role: VcpuRole::Bsp,
                initial_mp_state: MpState::Runnable
            }]
        );
        let three = plan_vcpus(3).unwrap();
        let got: Vec<(u32, u32, MpState)> = three
            .iter()
            .map(|p| (p.index, p.apic_id, p.initial_mp_state))
            .collect();
        assert_eq!(
            got,
            vec![
                (0, 0, MpState::Runnable),
                (1, 1, MpState::Uninitialized),
                (2, 2, MpState::Uninitialized)
            ]
        );
        assert_eq!(three[1].role, VcpuRole::Ap);
        let last = *plan_vcpus(32).unwrap().last().unwrap();
        assert_eq!(last.apic_id, 31);
        assert_eq!(last.initial_mp_state, MpState::Uninitialized);
    }

    /// MVM-1・#3737: 0 台と上限超は InvalidArgument。
    #[test]
    fn mvm1_3737_plan_vcpus_rejects_out_of_range() {
        assert_eq!(
            plan_vcpus(0).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            plan_vcpus(MAX_XAPIC_VCPUS + 1).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(plan_vcpus(MAX_XAPIC_VCPUS).unwrap().len(), 255);
    }

    /// MVM-1・#3737: kvm.h v6.12 の値との往復。
    #[test]
    fn mvm1_3737_mp_state_raw_roundtrip() {
        let table = [
            (0, MpState::Runnable),
            (1, MpState::Uninitialized),
            (2, MpState::InitReceived),
            (3, MpState::Halted),
            (4, MpState::SipiReceived),
        ];
        for (raw, st) in table {
            assert_eq!(MpState::from_raw(raw), st);
            assert_eq!(st.as_raw(), raw);
        }
        assert_eq!(MpState::from_raw(99), MpState::Other(99));
        assert_eq!(MpState::Other(99).as_raw(), 99);
    }

    /// MVM-1・#3737: SDM の予約ベクタ 0xA0〜0xBF を拒否し、開始アドレスは V << 12。
    #[test]
    fn mvm1_3737_sipi_vector_reserved_range() {
        assert!(SipiVector::new(0x9F).is_ok());
        assert!(SipiVector::new(0xA0).is_err());
        assert!(SipiVector::new(0xBF).is_err());
        assert!(SipiVector::new(0xC0).is_ok());
        assert_eq!(SipiVector::new(0x01).unwrap().start_address(), 0x1000);
        assert_eq!(SipiVector::new(0x9E).unwrap().start_address(), 0x9_E000);
        assert_eq!(SipiVector::new(0x9E).unwrap().value(), 0x9E);
    }

    /// MVM-1・#3737: 開始ページの受理 / 拒否の表（ゲストメモリ 64 MiB）。
    #[test]
    fn mvm1_3737_sipi_startup_range_table() {
        let mem = 64 << 20;
        for v in [0x01u8, 0x06, 0x21, 0x9E] {
            let start = u64::from(v) << 12;
            assert_eq!(
                sipi_startup_range(SipiVector::new(v).unwrap(), 16, mem).unwrap(),
                (start, start + 0x1000),
                "vector {v:#x}"
            );
        }
        for v in [0x00u8, 0x07, 0x20, 0x9F, 0xC0] {
            assert_eq!(
                sipi_startup_range(SipiVector::new(v).unwrap(), 16, mem)
                    .unwrap_err()
                    .code(),
                MicrovmErrorCode::InvalidArgument,
                "vector {v:#x}"
            );
        }
        let ok = SipiVector::new(0x01).unwrap();
        assert!(sipi_startup_range(ok, 0, mem).is_err());
        assert!(sipi_startup_range(ok, 4096, mem).is_ok());
        assert!(sipi_startup_range(ok, 4097, mem).is_err());
        assert!(sipi_startup_range(SipiVector::new(0x02).unwrap(), 16, 0x2000).is_err());
        assert!(sipi_startup_range(SipiVector::new(0x02).unwrap(), 16, 0x3000).is_ok());
    }
}
