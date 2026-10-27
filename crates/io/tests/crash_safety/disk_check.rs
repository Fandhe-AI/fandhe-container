//! kill / 電源断の後にディスク上へ残った `data.bin` のレコード列を seq 0..n と照合する共有部分
//! （IO-3・IO-2・TASK-18.2・#95・#1965）。
//!
//! 役割: `crash_safety.rs`（SIGKILL 試験）と `power_loss.rs`（dm-flakey の書き込み破棄試験）が
//! 同じ判定でディスクを照合するための純粋関数 [`check_disk_records`] と結果型 [`DiskCheck`]。
//! 試行の台帳・有効 / 無効判定（`trial`）には依存しないため、取り込む側は試行管理コードを
//! 抱えず、モジュール全体の lint 抑止も要らない。OS 非依存で 3 OS でコンパイルできる。
//!
//! 境界: 損失の合否判断はしない。件数の事実を返すだけで、判定は呼び出し側が行う（REPAIR-3）。

/// `data.bin` の 1 レコードのバイト長（Write の body は seq の u64 LE。`drive_client` 参照）。
pub const RECORD_LEN: usize = 8;

/// ディスク上のレコード列と期待値（seq 0..expected）の照合結果（IO-3・TASK-18.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCheck {
    /// 期待した件数（ACK 目標数）。
    pub expected: u64,
    /// ディスク上にあった完全レコードの seq（ファイル順）。
    pub found: Vec<u64>,
    /// 期待集合にあるのにディスクに無かった seq（昇順）。損失件数はこの長さ。
    pub missing: Vec<u64>,
    /// 期待集合の範囲外の値、または重複して現れた seq（ファイル順）。
    pub unexpected: Vec<u64>,
    /// 末尾の `RECORD_LEN` に満たない半端なバイト数。
    pub trailing_partial_bytes: usize,
}

impl DiskCheck {
    /// 損失件数（ACK 済みなのにディスクに無い件数）。
    pub fn lost(&self) -> u64 {
        u64::try_from(self.missing.len()).unwrap_or(u64::MAX)
    }

    /// 0..expected がこの順にちょうど並び、想定外も半端バイトも無い。
    pub fn is_exact(&self) -> bool {
        self.missing.is_empty()
            && self.unexpected.is_empty()
            && self.trailing_partial_bytes == 0
            && self.found.iter().copied().eq(0..self.expected)
    }
}

/// `data.bin` の内容を seq 0..expected と照合する。外部入力扱いのため添字を使わない。
pub fn check_disk_records(bytes: &[u8], expected: u64) -> DiskCheck {
    let (chunks, remainder) = bytes.as_chunks::<RECORD_LEN>();
    let trailing_partial_bytes = remainder.len();
    let found: Vec<u64> = chunks.iter().map(|c| u64::from_le_bytes(*c)).collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut unexpected = Vec::new();
    for &seq in &found {
        if seq >= expected || !seen.insert(seq) {
            unexpected.push(seq);
        }
    }
    let missing = (0..expected).filter(|s| !seen.contains(s)).collect();
    DiskCheck {
        expected,
        found,
        missing,
        unexpected,
        trailing_partial_bytes,
    }
}
