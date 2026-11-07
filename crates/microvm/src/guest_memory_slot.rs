//! ゲスト RAM を複数スレッドで共有するスロット（#4025・MVM-1・MVM-5・REPAIR-5。OS 非依存・`unsafe` なし）。
//!
//! [`GuestMemory`] を `Arc<Mutex<Option<_>>>` で包み、vCPU スレッド（MMIO exit の処理）と VM 構成体が
//! 同じゲスト RAM を触れるようにする入れ物。停止の経路は [`GuestMemorySlot::take`] で決まった時点に
//! 中身を取り出して解放する。最後の `Arc` が落ちたときは中身が 1 回だけ drop される。
//!
//! # 契約
//! - ロックはメモリのコピー 1 回分だけ持ち、待ちを持たない。そのためタイムアウトは不要（REPAIR-5）。
//! - ロックの順序は、dispatcher の lock を解放した後に、トランスポート、メモリの順で取る（#4026 の契約）。
//!   `with_memory` / `with_memory_mut` のクロージャの中で他の lock を取らない。
//! - 取り出し済みと lock の毒化は、固定の文言の [`MicrovmError`]（`Internal`）で返し、panic しない。
//!   毒化で `take` が `Err` を返しても中身は `Mutex` の中に残り、最後の `Arc` で drop される
//!   （リークはしないが解放の時点は決まらない。扱いは呼び出し元が決める）。
//! - ゲストが書きうるメモリを vCPU が使っている間は解放しない。`take` を呼ぶ時点は呼び出し元が決める。
//!
//! # 未結線（REPAIR-3）
//! #4026 で `interrupt::BlockQueueNotifyRoute` が使い始めた。#4027 で `hvf::microvm` の `HvfVmParts` が macOS のゲスト RAM の所有に使う（clone はまだ持たない）。
//! vCPU スレッドへの clone の結線は #4028（`MmioHandler` への route 結線）、最後の `Arc` での回収は #4032。
//!
//! # cfg
//! `interrupt::BoundAckRoute` と同じく Linux と macOS（aarch64）だけ。Windows（WHP）は MVP 外（MVM-5）。

use std::sync::{Arc, Mutex};

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestMemory, GuestMemoryBacking};

/// 取り出し済みのときのエラー文言（`hvf::microvm` の `read_guest` と同じ）。
pub const RELEASED_MESSAGE: &str = "guest memory is already released";
/// lock が毒化したときのエラー文言。
pub const POISONED_MESSAGE: &str = "guest memory lock poisoned";

fn released() -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, RELEASED_MESSAGE)
}

fn poisoned() -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, POISONED_MESSAGE)
}

/// 複数スレッドで共有できるゲスト RAM の入れ物（`Clone` は `Arc` の複製）。
pub struct GuestMemorySlot<M: GuestMemoryBacking> {
    inner: Arc<Mutex<Option<GuestMemory<M>>>>,
}

impl<M: GuestMemoryBacking> Clone for GuestMemorySlot<M> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<M: GuestMemoryBacking> std::fmt::Debug for GuestMemorySlot<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ロックは取らない（Debug 出力でデッドロックさせない）。
        f.debug_struct("GuestMemorySlot").finish_non_exhaustive()
    }
}

impl<M: GuestMemoryBacking> GuestMemorySlot<M> {
    /// `memory` を包んで新しいスロットを作る。
    pub fn new(memory: GuestMemory<M>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(memory))),
        }
    }

    /// ロックの中で `f` に読み取り参照を渡す。取り出し済みは固定のエラー。
    pub fn with_memory<R>(
        &self,
        f: impl FnOnce(&GuestMemory<M>) -> Result<R, MicrovmError>,
    ) -> Result<R, MicrovmError> {
        let guard = self.inner.lock().map_err(|_| poisoned())?;
        let mem = guard.as_ref().ok_or_else(released)?;
        f(mem)
    }

    /// ロックの中で `f` に書き込み参照を渡す。取り出し済みは固定のエラー。
    pub fn with_memory_mut<R>(
        &self,
        f: impl FnOnce(&mut GuestMemory<M>) -> Result<R, MicrovmError>,
    ) -> Result<R, MicrovmError> {
        let mut guard = self.inner.lock().map_err(|_| poisoned())?;
        let mem = guard.as_mut().ok_or_else(released)?;
        f(mem)
    }

    /// 中身を取り出す。1 回目は `Some`、2 回目以降は `None`。毒化していれば固定のエラー。
    pub fn take(&self) -> Result<Option<GuestMemory<M>>, MicrovmError> {
        let mut guard = self.inner.lock().map_err(|_| poisoned())?;
        Ok(guard.take())
    }
}

impl<M: GuestMemoryBacking> GuestMemorySlot<M> {
    /// [`Self::take`] と同じだが、lock が毒化していたら中身を永久にリークしてからエラーを返す（fail-closed）。
    ///
    /// `hvf::microvm` の解放が使う。毒化のまま `Err` で戻ると、呼び出し元の構造体の drop で最後の `Arc` が落ち、
    /// vCPU スレッドが残っていても RAM が解放されうる。これは期限切れの経路（ゲストがまだ書けうるメモリを
    /// 解放しない）と食い違うため、`Arc` を 1 つ `forget` して中身が drop されないようにする。
    /// 何度呼んでも `Arc` が増えるだけで中身は drop されない。回収はプロセスの終了だけ（#4032・#3908 が扱う）。
    pub fn take_or_leak(&self) -> Result<Option<GuestMemory<M>>, MicrovmError> {
        match self.inner.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(_) => {
                std::mem::forget(self.clone());
                Err(poisoned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_memory::{GuestAddress, HeapBacking};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const _: () = {
        fn assert_send_sync<T: Send + Sync>() {}
        fn check() {
            assert_send_sync::<GuestMemorySlot<HeapBacking>>();
        }
        let _ = check;
    };

    fn slot() -> GuestMemorySlot<HeapBacking> {
        GuestMemorySlot::new(
            GuestMemory::new(GuestAddress::new(0x1000), HeapBacking::new(0x100).unwrap()).unwrap(),
        )
    }

    fn read4(s: &GuestMemorySlot<HeapBacking>) -> Result<[u8; 4], MicrovmError> {
        s.with_memory(|m| {
            let mut b = [0u8; 4];
            m.read_at(GuestAddress::new(0x1010), &mut b)?;
            Ok(b)
        })
    }

    fn assert_err(e: MicrovmError, msg: &str) {
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), msg);
    }

    #[test]
    fn mvm1_slot_roundtrip_read_write() {
        let s = slot();
        s.with_memory_mut(|m| m.write_at(GuestAddress::new(0x1010), &[1, 2, 3, 4]))
            .unwrap();
        assert_eq!(read4(&s).unwrap(), [1, 2, 3, 4]);
        assert_eq!(read4(&s.clone()).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn mvm1_slot_access_after_take_is_fixed_error() {
        let s = slot();
        s.with_memory_mut(|m| m.write_at(GuestAddress::new(0x1010), &[9, 8, 7, 6]))
            .unwrap();
        let taken = s.take().unwrap().unwrap();
        let mut b = [0u8; 4];
        taken.read_at(GuestAddress::new(0x1010), &mut b).unwrap();
        assert_eq!(b, [9, 8, 7, 6]);
        assert_err(read4(&s).unwrap_err(), "guest memory is already released");
        assert_err(
            s.with_memory_mut(|_| Ok(())).unwrap_err(),
            "guest memory is already released",
        );
    }

    #[test]
    fn mvm1_slot_second_take_returns_none() {
        let s = slot();
        let c = s.clone();
        assert!(s.take().unwrap().is_some());
        assert!(s.take().unwrap().is_none());
        assert!(c.take().unwrap().is_none());
    }

    #[test]
    fn repair5_slot_poisoned_lock_is_fixed_error() {
        let s = slot();
        let c = s.clone();
        let r = std::thread::spawn(move || {
            let _ = c.with_memory(|_| -> Result<(), MicrovmError> { panic!("poison for test") });
        })
        .join();
        assert!(r.is_err());
        assert_err(read4(&s).unwrap_err(), "guest memory lock poisoned");
        assert_err(
            s.with_memory_mut(|_| Ok(())).unwrap_err(),
            "guest memory lock poisoned",
        );
        assert_err(s.take().unwrap_err(), "guest memory lock poisoned");
    }

    struct DropCounting {
        inner: HeapBacking,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for DropCounting {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl GuestMemoryBacking for DropCounting {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
            self.inner.read(offset, buf)
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
            self.inner.write(offset, data)
        }
        fn read_u16_le_aligned(&self, offset: u64) -> Result<u16, MicrovmError> {
            self.inner.read_u16_le_aligned(offset)
        }
        fn write_u16_le_aligned(&mut self, offset: u64, v: u16) -> Result<(), MicrovmError> {
            self.inner.write_u16_le_aligned(offset, v)
        }
    }

    fn counting(drops: &Arc<AtomicUsize>) -> GuestMemorySlot<DropCounting> {
        let b = DropCounting {
            inner: HeapBacking::new(0x100).unwrap(),
            drops: Arc::clone(drops),
        };
        GuestMemorySlot::new(GuestMemory::new(GuestAddress::new(0x1000), b).unwrap())
    }

    #[test]
    fn mvm1_slot_drops_contents_once_after_all_arcs() {
        let drops = Arc::new(AtomicUsize::new(0));
        let a = counting(&drops);
        let b = a.clone();
        let c = a.clone();
        drop(a);
        drop(b);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(c);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let drops = Arc::new(AtomicUsize::new(0));
        let a = counting(&drops);
        let b = a.clone();
        let taken = a.take().unwrap().unwrap();
        drop(a);
        drop(b);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(taken);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mvm1_4027_take_or_leak_returns_contents_once() {
        let s = slot();
        s.with_memory_mut(|m| m.write_at(GuestAddress::new(0x1010), &[5, 6, 7, 8]))
            .unwrap();
        let taken = s.take_or_leak().unwrap().unwrap();
        let mut b = [0u8; 4];
        taken.read_at(GuestAddress::new(0x1010), &mut b).unwrap();
        assert_eq!(b, [5, 6, 7, 8]);
        assert!(s.take_or_leak().unwrap().is_none());
        assert_err(read4(&s).unwrap_err(), "guest memory is already released");
    }

    #[test]
    fn repair5_4027_take_or_leak_poisoned_never_drops_contents() {
        let drops = Arc::new(AtomicUsize::new(0));
        let s = counting(&drops);
        let c = s.clone();
        let r = std::thread::spawn(move || {
            let _ = c.with_memory(|_| -> Result<(), MicrovmError> { panic!("poison for test") });
        })
        .join();
        assert!(r.is_err());
        assert_err(
            s.take_or_leak().err().unwrap(),
            "guest memory lock poisoned",
        );
        assert_err(
            s.take_or_leak().err().unwrap(),
            "guest memory lock poisoned",
        );
        drop(s);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
}
