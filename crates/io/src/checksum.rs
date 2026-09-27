//! CRC-32C（Castagnoli）チェックサムの自前実装（TASK-11.3・IO-1・REPAIR-2・MS-1・#70）。
//!
//! [`crate::protocol::Frame`] がヘッダ＋ペイロードの偶発的破損・フレーム境界ずれ
//! （PoC-8 の BREAK-2 相当）を検出するために使う。依存追加なし（std のみ。
//! dependency-policy のフルスクラッチ方針）。採用理由・パラメータの詳細は
//! `docs/design/io-protocol.md`（IO-1・REPAIR-2・TASK-11.3）を参照。
//!
//! 本モジュールは crate 内部専用（`pub(crate)`）。呼び出し側が任意のチェックサムを
//! 注入できる公開 API は [`crate::protocol`] 側でも用意しない（REPAIR-2）。

/// CRC-32C の反射多項式（`0x82F63B78`）に基づく 256 エントリのルックアップテーブル。
///
/// `const fn` でビルド時に計算するため、実行時コストもテーブル生成用の追加依存も
/// 発生しない。
const TABLE: [u32; 256] = build_table();

/// CRC-32C（Castagnoli）多項式の反射表現。
const POLY: u32 = 0x82F6_3B78;

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0usize;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

/// CRC-32C のストリーミング計算器。ヘッダとペイロードを連結コピーせずに
/// 逐次 `update` することを想定する（[`crate::protocol::Frame`] から利用）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc32c {
    state: u32,
}

impl Crc32c {
    /// 初期値 `0xFFFF_FFFF` で新しい計算器を作る。
    pub(crate) fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// バイト列を計算に取り込む。複数回に分けて呼んでも、一括で呼んだ場合と
    /// 同じ結果になる（多項式除算の線形性による。テストで確認する）。
    ///
    /// `byte` は `u8`（値域 0..=255）を `usize::from` で `TABLE`（長さ 256）の
    /// 添字に変換しており、値域が静的にテーブル長へ収まるため境界外アクセスは
    /// 起こらない（coding-rust の「外部入力での添字アクセス禁止」は任意長・任意値の
    /// 入力に対する規約であり、本関数のように添字の値域がコンパイル時に保証されている
    /// 場合は対象外。テーブルなしのビット単位実装も可能だが約 8 倍遅くなるため
    /// 採らない）。
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        for &byte in bytes {
            let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE[index];
        }
        self.state = crc;
    }

    /// 最終 XOR（`0xFFFF_FFFF`）を適用してチェックサム値を確定する。
    pub(crate) fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

/// バイト列全体から CRC-32C を計算する簡便関数。
///
/// 現時点ではテスト（本モジュール・`protocol` モジュールの期待値照合）専用の
/// ヘルパーのため `#[cfg(test)]` にしている。非テストコードは
/// [`Crc32c`]（ストリーミング API）を使う（[`crate::protocol::Frame`] 参照）。
#[cfg(test)]
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IO-1・REPAIR-2: CRC-32C の標準 check 値（`"123456789"` → `0xE3069283`）。
    #[test]
    fn io1_crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// IO-1: 空入力は `0x00000000`（初期値と最終 XOR が打ち消し合う）。
    #[test]
    fn io1_crc32c_empty_input_is_zero() {
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    /// IO-1: RFC 3720 Appendix B.4 のベクタ（iSCSI CRC-32C の既知解）。
    #[test]
    fn io1_crc32c_matches_rfc3720_vectors() {
        assert_eq!(crc32c(&[0x00; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFF; 32]), 0x62A8_AB43);

        let ascending: Vec<u8> = (0x00u8..=0x1F).collect();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);

        let descending: Vec<u8> = (0x00u8..=0x1F).rev().collect();
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }

    /// IO-1・REPAIR-2: 分割 `update` と一括計算が一致する（ストリーミング計算の
    /// 正しさの確認。Frame がヘッダ・ペイロードを別々に取り込む前提と整合）。
    #[test]
    fn io1_crc32c_split_update_matches_single_call() {
        let data = b"the quick brown fox jumps over the lazy dog";

        let single = crc32c(data);

        let mut split = Crc32c::new();
        split.update(&data[..10]);
        split.update(&data[10..25]);
        split.update(&data[25..]);
        assert_eq!(split.finalize(), single);
    }
}
