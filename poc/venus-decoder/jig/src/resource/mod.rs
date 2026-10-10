//! blob リソースの資源表（GPU-6・TASK-172.4・#1601。設計書 10.4.3）。
//!
//! 役割: `adapter::CtrlAdapter` が `RESOURCE_CREATE_BLOB` / `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` /
//! `RESOURCE_UNREF` の可否を決めるための、resource_id・大きさ・所属 ctx の固定長の表。`adapter` が所有するので、
//! `session` が応答を書き戻せなかった要求を `CtrlAdapter` ごと巻き戻すと資源表も元に戻る。
//!
//! 上限（件数・1 件の大きさ・合計）は確保・計上より前に検査し、加算は `checked_add` で行う。表は固定長配列で、
//! ゲスト入力によってアロケーションは増えない。上限値は設計書 10.4.3 の案で、実機（#725）で見直す。
//!
//! `RESOURCE_MAP_BLOB` / `UNMAP_BLOB`（F5.2b.4a・#1643）の map 状態（host-visible 領域内の offset）も本表が持つ。実メモリ
//! （memfd）の確保と frontend への `SHMEM_MAP` は `session` が行い、本表は検証と重なり検査だけを担う（I/O を持たない）。
//! 本表の上限（1 件 16 MiB・合計 64 MiB）は `CREATE_BLOB` の時点で検査済みなので、memfd の長さはその範囲に収まる。
//!
//! map 中の資源の解放（確定。#1645・GPU-6）:
//!
//! - D1: map 中の resource への `RESOURCE_UNREF` は `ERR_INVALID_PARAMETER` で拒否する（表と合計は変えない）。実ゲストは
//!   `UNMAP` → `UNREF` の順に出すので通常の流れは妨げない。拒否が起きるのは治具の `SHMEM_UNMAP` が失敗した後だけで、
//!   その時点で frontend 側に map が残っているか分からないため、区間を解放して重なる map を許さない。残った資源は
//!   セッション終了時の片づけ（`session` の `release_blobs_at_end`）が解放する。
//! - D2: map 中の resource を持つ ctx の `CTX_DESTROY` は detach だけ行い、map は残す（map は ctx ではなくデバイスの
//!   host-visible 領域に属する。`detach_all_from`）。

/// 同時に持つ resource の上限件数。
pub const MAX_RESOURCES: usize = 256;
/// 1 件の大きさの上限（16 MiB）。
pub const MAX_RESOURCE_SIZE: u64 = 16 * 1024 * 1024;
/// 合計の大きさの上限（64 MiB）。
pub const MAX_TOTAL_RESOURCE_SIZE: u64 = 64 * 1024 * 1024;
/// 大きさの倍数条件（ページ単位）。
pub const RESOURCE_SIZE_ALIGN: u64 = 4096;

// 所属 ctx を ctx 表のスロット番号のビット集合（u64）で持つため、ctx 表は 64 スロットまで。
const _: () = assert!(crate::adapter::MAX_CONTEXTS <= 64);

/// 資源表操作の失敗理由（応答種別への写像は `adapter` が行う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// resource_id が 0・重複・未作成（`ERR_INVALID_RESOURCE_ID`）。
    InvalidId,
    /// 大きさ・attach 状態の不正（`ERR_INVALID_PARAMETER`）。
    InvalidParameter,
    /// 件数または合計の上限（`ERR_OUT_OF_MEMORY`）。
    Full,
}

/// host-visible 領域内の 1 区間（`MAP_BLOB` / `UNMAP_BLOB` の対象。`session` が `SHMEM_MAP` / `SHMEM_UNMAP` へ渡す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmemRange {
    /// 領域内のバイトオフセット（ページ境界）。
    pub offset: u64,
    /// 長さ（resource の大きさ）。
    pub len: u64,
}

/// 表の 1 スロット（`res_id == 0` は空き）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceEntry {
    res_id: u32,
    size: u64,
    /// attach 中の ctx のスロット番号の集合。
    attached: u64,
    /// map 中なら host-visible 領域内の offset（長さは `size`）。
    mapped: Option<u64>,
}

const EMPTY: ResourceEntry = ResourceEntry {
    res_id: 0,
    size: 0,
    attached: 0,
    mapped: None,
};

/// 固定長の資源表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTable {
    slots: [ResourceEntry; MAX_RESOURCES],
    total_size: u64,
}

impl Default for ResourceTable {
    fn default() -> Self {
        Self {
            slots: [EMPTY; MAX_RESOURCES],
            total_size: 0,
        }
    }
}

impl ResourceTable {
    fn find_mut(&mut self, res_id: u32) -> Option<&mut ResourceEntry> {
        if res_id == 0 {
            return None;
        }
        self.slots.iter_mut().find(|e| e.res_id == res_id)
    }

    /// 現在の合計の大きさ（バイト）。
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// 作成済みの件数。
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|e| e.res_id != 0).count()
    }

    /// 1 件も無いか。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// resource を作る。id・大きさの検査 → 合計 → 件数の順で、すべて計上前に行う。
    pub fn create(&mut self, res_id: u32, size: u64) -> Result<(), ResourceError> {
        if res_id == 0 || self.slots.iter().any(|e| e.res_id == res_id) {
            return Err(ResourceError::InvalidId);
        }
        if size == 0 || !size.is_multiple_of(RESOURCE_SIZE_ALIGN) || size > MAX_RESOURCE_SIZE {
            return Err(ResourceError::InvalidParameter);
        }
        let new_total = self
            .total_size
            .checked_add(size)
            .filter(|t| *t <= MAX_TOTAL_RESOURCE_SIZE)
            .ok_or(ResourceError::Full)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|e| e.res_id == 0)
            .ok_or(ResourceError::Full)?;
        *slot = ResourceEntry {
            res_id,
            size,
            attached: 0,
            mapped: None,
        };
        self.total_size = new_total;
        Ok(())
    }

    /// resource を ctx（スロット番号）へ attach する。二重 attach は `InvalidParameter`。
    pub fn attach(&mut self, res_id: u32, ctx_slot: usize) -> Result<(), ResourceError> {
        let bit = slot_bit(ctx_slot)?;
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        if e.attached & bit != 0 {
            return Err(ResourceError::InvalidParameter);
        }
        e.attached |= bit;
        Ok(())
    }

    /// resource を ctx から detach する。未 attach は `InvalidParameter`。
    pub fn detach(&mut self, res_id: u32, ctx_slot: usize) -> Result<(), ResourceError> {
        let bit = slot_bit(ctx_slot)?;
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        if e.attached & bit == 0 {
            return Err(ResourceError::InvalidParameter);
        }
        e.attached &= !bit;
        Ok(())
    }

    /// resource を host-visible 領域（大きさ `region_size`）へ map したことにする。検査順は固定: id（`InvalidId`）→
    /// map 済み → offset のページ境界 → `offset + size` が領域内（`checked_add`）→ 他の map との区間の重なり
    /// （いずれも `InvalidParameter`）。ctx への attach は要求しない（Linux のドライバは `CTX_ATTACH` より先に MAP を出す）。
    pub fn map(
        &mut self,
        res_id: u32,
        offset: u64,
        region_size: u64,
    ) -> Result<ShmemRange, ResourceError> {
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        if e.mapped.is_some() {
            return Err(ResourceError::InvalidParameter);
        }
        let len = e.size;
        if !offset.is_multiple_of(RESOURCE_SIZE_ALIGN) {
            return Err(ResourceError::InvalidParameter);
        }
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= region_size)
            .ok_or(ResourceError::InvalidParameter)?;
        let overlaps = self.slots.iter().any(|o| {
            o.res_id != res_id
                && o.mapped.is_some_and(|start| {
                    // 既存の区間は map 時に検査済みで溢れないが、溢れる場合は重なりとして拒否する（fail-closed）。
                    start
                        .checked_add(o.size)
                        .is_none_or(|o_end| offset < o_end && start < end)
                })
        });
        if overlaps {
            return Err(ResourceError::InvalidParameter);
        }
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        e.mapped = Some(offset);
        Ok(ShmemRange { offset, len })
    }

    /// map 中の resource の map を外す。未作成は `InvalidId`、map していなければ `InvalidParameter`。
    pub fn unmap(&mut self, res_id: u32) -> Result<ShmemRange, ResourceError> {
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        let offset = e.mapped.take().ok_or(ResourceError::InvalidParameter)?;
        Ok(ShmemRange {
            offset,
            len: e.size,
        })
    }

    /// resource の大きさ。無ければ `None`。
    pub fn size_of(&self, res_id: u32) -> Option<u64> {
        self.slots
            .iter()
            .find(|e| e.res_id == res_id && res_id != 0)
            .map(|e| e.size)
    }

    /// map 中の offset（試験用の参照）。
    #[cfg(test)]
    pub fn mapped(&self, res_id: u32) -> Option<u64> {
        self.slots
            .iter()
            .find(|e| e.res_id == res_id && res_id != 0)
            .and_then(|e| e.mapped)
    }

    /// resource を消す。attach 中・map 中は `InvalidParameter`（map 中の拒否は D1。#1645 で確定）。
    pub fn unref(&mut self, res_id: u32) -> Result<(), ResourceError> {
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        if e.attached != 0 || e.mapped.is_some() {
            return Err(ResourceError::InvalidParameter);
        }
        let size = e.size;
        *e = EMPTY;
        self.total_size = self.total_size.saturating_sub(size);
        Ok(())
    }

    /// ctx の破棄時に、その ctx への attach をすべて外す（スロット再利用時の取り違えを防ぐ）。
    pub fn detach_all_from(&mut self, ctx_slot: usize) {
        if let Ok(bit) = slot_bit(ctx_slot) {
            for e in self.slots.iter_mut() {
                e.attached &= !bit;
            }
        }
    }
}

fn slot_bit(ctx_slot: usize) -> Result<u64, ResourceError> {
    u32::try_from(ctx_slot)
        .ok()
        .and_then(|s| 1u64.checked_shl(s))
        .ok_or(ResourceError::InvalidParameter)
}

#[cfg(test)]
mod tests;
