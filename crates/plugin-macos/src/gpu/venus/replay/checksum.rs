//! 記録ファイル用の CRC-32C（Castagnoli。GPU-6・TASK-172.5・REPAIR-2）。
//!
//! `crates/io`・`crates/plugin` にも同種の実装があるが、いずれも `pub(crate)` で、記録形式を UDS
//! プロトコルへ結合させないため本モジュールにローカル実装する（共通化はスコープ外）。
//! 偶発的な破損の検出用で、改ざん耐性はない。

/// 反射形式の多項式（0x1EDC6F41 の反射）。
const POLY: u32 = 0x82F6_3B78;

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = make_table();

/// 複数の断片を連結したものの CRC-32C を求める。
pub(crate) fn crc32c(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    for part in parts {
        for &b in *part {
            let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
            // idx は 0..=255 で TABLE は 256 要素。get で添字アクセスを避ける。
            let t = TABLE.get(idx).copied().unwrap_or(0);
            crc = (crc >> 8) ^ t;
        }
    }
    !crc
}
