//! macOS（Apple Silicon）のゲスト RAM（TASK-192.4・#3787・MVM-5・MVM-1・MVM-4）。
//!
//! Linux の `crate::microvm` の `GuestRam` / `RegisteredGuestRam` に対応する。匿名 mmap の確保（[`HvfGuestRam`]）と、
//! `HvVm` への `hv_vm_map`（RWX）による対応付け（[`RegisteredHvfRam`]）だけを持ち、アクセスは OS 非依存の
//! `crate::guest_memory::GuestMemory` を通すコピー API に限る（参照を外へ出さない。判断記録
//! `docs/design/microvm-memory-ownership.md`）。後続の VM 構成体（#3797）と GIC 配置の検証（#3792）が使う。
//! `unsafe` は `sys/hvf.rs` に閉じ、このファイルは持たない。
//!
//! # 寿命の契約
//! 登録済みの RAM は `&'vm HvVm` を借用するため、`HvVm`（`hv_vm_destroy`）より先に drop される。drop は
//! `hv_vm_unmap` が成功したときだけ munmap し、失敗したら backing をリークする（fail-closed）。
//!
//! # volatile アクセスの前提（MVM-1・MVM-5・#3844・#3862）
//! - `read` / `write`（とその上の `GuestMemory` の `read_u16_le` などの多バイトの読み書き）は 1 バイト単位の
//!   volatile コピーで、2 / 4 / 8 バイトの値を 1 命令でも原子的にも読み書きしない。vCPU が並行して書く値は
//!   途中の状態（tear）で読めることがある。
//! - 例外は virtqueue の共有 index（`avail.idx`・`used.idx`）専用の `read_u16_le_aligned` /
//!   `write_u16_le_aligned`（#3862）。2 バイト整列した u16 を単一の volatile で読み書きし、tear しない。
//!   「単一命令」は Rust の言語仕様の保証ではなく、aarch64 の `ldrh` / `strh` に下りる前提（Linux の
//!   `READ_ONCE` / `WRITE_ONCE` と同じ）。ring の要素・記述子・u32 以上には適用しない（理由は `virtqueue` のモジュール doc）。
//! - volatile はバイト同士の順序もゲストとの順序も保証せず、Rust のメモリモデルの上では `fence` も非 atomic の
//!   アクセスを順序づけない。順序は arm64 の実機のバリア命令に頼る（`virtqueue.rs` のモジュール doc と同じ前提）。
//! - デバイス側（virtqueue とその上の virtio デバイス）の責務: 記述子は 1 回だけコピーして同じ値で検査して使う
//!   （TOCTOU 防止）。読む順序と書く順序は fence で表す（`SplitQueue::pop` の Acquire・`add_used` の Release）。
//!   tear しうる値（記述子など）も非信頼入力として範囲検査で受け止め、リング破損として扱う。
//!
//! # 範囲外（REPAIR-3）
//! 複数領域・`hv_vm_protect`・`Send` / `Sync`（#3798 の範囲外。期限切れで切り離したスレッドの資源の回収と合わせて担当は #3908）。IPA の上限の値は既定の 36 ビット（実機の値は #3997）。
//! `register` はレイアウトの上限を、`HvVm::map` は既定の上限を検査する（#3844）。
//! 解除失敗の構造化ログは未実装。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};
use crate::hvf::gic::VmWithGic;
use crate::hvf_abi::{MemoryFlags, check_ipa_limit};
use crate::sys::{GuestMapping, HostMapping, HvVm};

fn out_of_range() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::InvalidArgument,
        "guest memory access out of range",
    )
}

fn to_usize(v: u64) -> Result<usize, MicrovmError> {
    usize::try_from(v).map_err(|_| out_of_range())
}

/// 未登録のゲスト RAM（匿名 mmap）。`register` で VM に対応付ける。
#[derive(Debug)]
pub struct HvfGuestRam {
    host: HostMapping,
}

impl HvfGuestRam {
    /// `size` バイトを確保する。0・ページ倍数でない・16 GiB 超は mmap の前に `InvalidArgument`。
    pub fn new(size: u64) -> Result<Self, MicrovmError> {
        let len = usize::try_from(size).map_err(|_| {
            MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "size exceeds the maximum mapping size",
            )
        })?;
        Ok(Self {
            host: HostMapping::new(len)?,
        })
    }

    /// `vm` の `[base, base + size)` に RWX で対応付け、アクセス型に包んで返す。
    ///
    /// `ipa_limit` は IPA の上限（レイアウトの値。暫定は `HVF_DEFAULT_IPA_LIMIT`）。`HvVm::map` も既定の上限を
    /// 検査するため二重の検査になり、こちらの（より厳しい）上限が先に効く。失敗しても取得済みの資源は解放する。
    pub fn register<'vm>(
        self,
        vm: &'vm HvVm,
        base: GuestAddress,
        ipa_limit: u64,
    ) -> Result<GuestMemory<RegisteredHvfRam<'vm>>, MicrovmError> {
        let len = self.host.len();
        check_ipa_limit(base.raw(), len as u64, ipa_limit)?;
        let mapping = vm.map(self.host, 0, base.raw(), len, MemoryFlags::RWX)?;
        GuestMemory::new(base, RegisteredHvfRam { mapping })
    }

    /// [`Self::register`] の `Arc` 版。対応付けが VM を `Arc` で保持するため `'static` になり、`VmWithGic` を `Arc` で共有する構成体
    /// （`HvfMicroVm`。#3797）が自己参照なしに RAM を持てる。検査の順序と失敗時の解放は `register` と同じ。
    ///
    /// 契約: 対応付けが残る間は `Arc<HvVm>` も残るので、VM の破棄（`hv_vm_destroy`）は必ず unmap の後になる。
    /// `GuestMapping` は生ポインタを持つため `Send` ではない（vCPU スレッドからゲスト RAM を触る必要が出たときの担当は #3908 で、#3798 の範囲外。REPAIR-3）。
    pub fn register_shared(
        self,
        vm: &VmWithGic,
        base: GuestAddress,
        ipa_limit: u64,
    ) -> Result<GuestMemory<RegisteredHvfRam<'static>>, MicrovmError> {
        let len = self.host.len();
        check_ipa_limit(base.raw(), len as u64, ipa_limit)?;
        let mapping = vm
            .shared_vm()
            .map_shared(self.host, 0, base.raw(), len, MemoryFlags::RWX)?;
        GuestMemory::new(base, RegisteredHvfRam { mapping })
    }
}

impl GuestMemoryBacking for HvfGuestRam {
    fn len(&self) -> u64 {
        self.host.len() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.host.read_into(to_usize(offset)?, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        self.host.write_from(to_usize(offset)?, data)
    }
    fn read_u16_le_aligned(&self, offset: u64) -> Result<u16, MicrovmError> {
        self.host.read_u16_le_aligned(to_usize(offset)?)
    }
    fn write_u16_le_aligned(&mut self, offset: u64, v: u16) -> Result<(), MicrovmError> {
        self.host.write_u16_le_aligned(to_usize(offset)?, v)
    }
}

/// `HvVm` に対応付け済みのゲスト RAM。drop で `hv_vm_unmap` → munmap。
#[derive(Debug)]
pub struct RegisteredHvfRam<'vm> {
    mapping: GuestMapping<'vm>,
}

impl RegisteredHvfRam<'_> {
    /// 明示的に解除し、結果を観測する（失敗時は backing をリークする）。
    pub fn unregister(self) -> Result<(), MicrovmError> {
        self.mapping.unmap()
    }
}

impl GuestMemoryBacking for RegisteredHvfRam<'_> {
    fn len(&self) -> u64 {
        self.mapping.size() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.mapping.read_into(to_usize(offset)?, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        self.mapping.write_from(to_usize(offset)?, data)
    }
    fn read_u16_le_aligned(&self, offset: u64) -> Result<u16, MicrovmError> {
        self.mapping.read_u16_le_aligned(to_usize(offset)?)
    }
    fn write_u16_le_aligned(&mut self, offset: u64, v: u16) -> Result<(), MicrovmError> {
        self.mapping.write_u16_le_aligned(to_usize(offset)?, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvf_abi::MAX_MAP_BYTES;

    fn page() -> u64 {
        HostMapping::page_size().unwrap() as u64
    }

    fn check(size: u64, msg: &str) {
        let e = HvfGuestRam::new(size).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), msg);
    }

    #[test]
    fn mvm5_guest_ram_size_zero_is_invalid() {
        check(0, "size is zero");
    }

    #[test]
    fn mvm5_guest_ram_size_below_page_is_invalid() {
        check(page() / 2, "size is not a multiple of the page size");
    }

    #[test]
    fn mvm5_guest_ram_size_not_page_multiple_is_invalid() {
        check(
            page() + page() / 2,
            "size is not a multiple of the page size",
        );
    }

    #[test]
    fn mvm5_guest_ram_size_too_large_is_invalid() {
        check(
            MAX_MAP_BYTES + page(),
            "size exceeds the maximum mapping size",
        );
    }

    /// MVM-5・MVM-1・#3862: 整列 u16 の往復（バイト列と一致）、奇数アドレス・範囲外の拒否。
    #[test]
    fn mvm5_aligned_u16_roundtrip_and_rejects_unaligned() {
        let p = page();
        let base = 0x4000_0000u64;
        let mut mem =
            GuestMemory::new(GuestAddress::new(base), HvfGuestRam::new(p * 2).unwrap()).unwrap();
        mem.write_u16_le_aligned(GuestAddress::new(base + 2), 0xBEEF)
            .unwrap();
        let mut b = [0u8; 2];
        mem.read_at(GuestAddress::new(base + 2), &mut b).unwrap();
        assert_eq!(b, [0xEF, 0xBE]);
        mem.write_at(GuestAddress::new(base + 4), &[0x34, 0x12])
            .unwrap();
        assert_eq!(
            mem.read_u16_le_aligned(GuestAddress::new(base + 4))
                .unwrap(),
            0x1234
        );
        let last = GuestAddress::new(base + p * 2 - 2);
        assert!(mem.read_u16_le_aligned(last).is_ok());
        let e = mem
            .read_u16_le_aligned(GuestAddress::new(base + 3))
            .unwrap_err();
        assert_eq!(e.message(), "unaligned guest memory access");
        let e = mem
            .write_u16_le_aligned(GuestAddress::new(base + p * 2), 1)
            .unwrap_err();
        assert_eq!(e.message(), "guest memory access out of range");
    }

    #[test]
    fn mvm5_unregistered_guest_ram_roundtrips() {
        let p = page();
        let base = GuestAddress::new(0x4000_0000);
        let mut mem = GuestMemory::new(base, HvfGuestRam::new(p * 2).unwrap()).unwrap();
        let at = GuestAddress::new(0x4000_0000 + p - 2);
        let mut zero = [0xffu8; 4];
        mem.read_at(at, &mut zero).unwrap();
        assert_eq!(zero, [0; 4]);
        mem.write_at(at, &[1, 2, 3, 4]).unwrap();
        let mut got = [0u8; 4];
        mem.read_at(at, &mut got).unwrap();
        assert_eq!(got, [1, 2, 3, 4]);
        let end = GuestAddress::new(0x4000_0000 + p * 2 - 2);
        let e = mem.read_at(end, &mut got).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }
}
