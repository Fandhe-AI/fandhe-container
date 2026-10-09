//! blob リソースの資源表（GPU-6・TASK-172.4・#1601。設計書 10.4.3）。
//!
//! 役割: `adapter::CtrlAdapter` が `RESOURCE_CREATE_BLOB` / `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` /
//! `RESOURCE_UNREF` の可否を決めるための、resource_id・大きさ・所属 ctx の固定長の表。`adapter` が所有するので、
//! `session` が応答を書き戻せなかった要求を `CtrlAdapter` ごと巻き戻すと資源表も元に戻る。
//!
//! 上限（件数・1 件の大きさ・合計）は確保・計上より前に検査し、加算は `checked_add` で行う。表は固定長配列で、
//! ゲスト入力によってアロケーションは増えない。上限値は設計書 10.4.3 の案で、実機（#725）で見直す。
//!
//! 未実装（REPAIR-3）: 実メモリの確保（memfd 等）と `RESOURCE_MAP_BLOB` / `UNMAP_BLOB`。共有メモリの対応（F5.2b・承認待ち）で
//! 実確保と結び付け、上限もそのとき実確保の上限として扱う。本モジュールの上限は計上上のものにとどまる。

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

/// 表の 1 スロット（`res_id == 0` は空き）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceEntry {
    res_id: u32,
    size: u64,
    /// attach 中の ctx のスロット番号の集合。
    attached: u64,
}

const EMPTY: ResourceEntry = ResourceEntry {
    res_id: 0,
    size: 0,
    attached: 0,
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

    /// resource を消す。attach 中は `InvalidParameter`。
    pub fn unref(&mut self, res_id: u32) -> Result<(), ResourceError> {
        let e = self.find_mut(res_id).ok_or(ResourceError::InvalidId)?;
        if e.attached != 0 {
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
