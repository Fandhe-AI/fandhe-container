//! レイヤー展開が tar の uid / gid をホストの ID へ写す写像（SEC-5・OCI-1・#2225）。
//!
//! `IdRange` は 1 行の写像、`IdMap` は検証済みの複数行の写像である。`extract` の
//! `OwnershipPolicy::ChownMapped`（展開物の `chown`）と `SpecialBitsPolicy` が使う。
//!
//! 定義は core の `IdMapping`（`container_id host_id count`）と `IdMapSet::new`（#2009・本番 launcher の範囲写像）
//! にそろえる。oci は core に依存しない（core は dev-dependency だけ）ため型は共有せず写している。
//! 検証規則を変えるときは両方をそろえること（`tests/idmap_core_parity.rs` が同じ入力の表で受理 / 拒否を照合する）。
//! 共有型を下位 crate へ移すかどうかは crate 境界の判断で、本モジュールの対象外。

use crate::error::{OciError, OciErrorCode};

/// 写像の行数の上限。core の `MAX_EXTENTS`（カーネルの `/proc/<pid>/uid_map` の行数上限）と同じ。
/// 件数は確保の前に検証する。
pub const MAX_ID_MAP_LINES: usize = 340;

fn invalid(msg: &'static str) -> OciError {
    OciError::new(OciErrorCode::InvalidArgument, msg)
}

/// uid / gid の 1 行の写像（コンテナ内 `container_id` から `count` 個を host の `host_id` 以降へ）。
///
/// core の `IdMapping`（`container_id host_id count`）と同じ意味。複数行の写像は `IdMap`。
///
/// `host_id` は、展開するプロセス自身の user namespace から見える ID（そのプロセスで `fstat` が返す
/// uid / gid）で渡す。入れ子の user namespace の中で展開するときは、初期 user namespace のホスト ID ではなく
/// 展開プロセスの名前空間での ID を渡す。取り違えると所有者の照合が別の ID と一致したり、常に食い違ったりする
/// （SEC-5・#2251 P2-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    /// コンテナ内の開始 ID。
    pub container_id: u32,
    /// ホストの開始 ID（展開するプロセスの user namespace から見た値）。
    pub host_id: u32,
    /// 範囲の長さ。
    pub count: u32,
}

impl IdRange {
    /// コンテナ内の `id` に対応する host の ID。範囲外・オーバーフローは `None`（checked 演算）。
    #[must_use]
    pub fn map_to_host(&self, id: u32) -> Option<u32> {
        let off = id.checked_sub(self.container_id)?;
        if off >= self.count {
            return None;
        }
        self.host_id.checked_add(off)
    }
}

/// 検証済みの複数行の写像。生成は `IdMap::new` のみで、壊れた写像を表現できない。
///
/// 拒否条件（core の `IdMapSet::new` と同じ）: 空・`MAX_ID_MAP_LINES` 超過・`count == 0`・u32 オーバーフロー・
/// コンテナ側 / ホスト側の範囲重複・コンテナ内 0 が写されていない構成（いずれも `InvalidArgument`）、
/// ホスト ID 0 を含む写像（SEC-5。`PermissionDenied`）。
/// 各範囲の `host_id` の見え方は `IdRange` と同じ（`chown` の引数として展開プロセスの user namespace で解釈される。
/// `ChownMapped` の呼び出し側は初期 user namespace にいる契約。`OwnershipPolicy` を参照）。
/// ホスト側の範囲が `u32::MAX` を含む写像も拒否する（chown の「変更なし」指定と衝突するため。core の `IdMapSet::new` より厳しい）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMap {
    lines: Vec<IdRange>,
}

/// 半開区間 `[start, end)` の列に重なりがあるか。
fn overlaps(mut ranges: Vec<(u64, u64)>) -> bool {
    ranges.sort_unstable();
    ranges.windows(2).any(|w| match (w.first(), w.get(1)) {
        (Some(a), Some(b)) => b.0 < a.1,
        _ => false,
    })
}

impl IdMap {
    /// 写像を検証して作る。
    pub fn new(lines: Vec<IdRange>) -> Result<Self, OciError> {
        if lines.is_empty() {
            return Err(invalid("id mapping is empty"));
        }
        if lines.len() > MAX_ID_MAP_LINES {
            return Err(invalid("too many id mapping lines"));
        }
        let mut container = Vec::with_capacity(lines.len());
        let mut host = Vec::with_capacity(lines.len());
        for l in &lines {
            if l.count == 0 {
                return Err(invalid("id mapping count is zero"));
            }
            let c_end = u64::from(l.container_id) + u64::from(l.count);
            let h_end = u64::from(l.host_id) + u64::from(l.count);
            let limit = u64::from(u32::MAX) + 1;
            if c_end > limit || h_end > limit {
                return Err(invalid("id mapping range overflows u32"));
            }
            // chown の引数 u32::MAX（(uid_t)-1）は「所有者を変えない」の意味になるため、
            // ホスト側の範囲に含めない（含めると所有者未適用のまま Applied を返してしまう）。
            if h_end >= limit {
                return Err(invalid(
                    "id mapping host range must not include u32::MAX (chown no-change value)",
                ));
            }
            if l.host_id == 0 {
                return Err(OciError::new(
                    OciErrorCode::PermissionDenied,
                    "id mapping must not map any container id to host id 0",
                ));
            }
            container.push((u64::from(l.container_id), c_end));
            host.push((u64::from(l.host_id), h_end));
        }
        if overlaps(container) || overlaps(host) {
            return Err(invalid("id mapping ranges overlap"));
        }
        if !lines.iter().any(|l| l.container_id == 0) {
            return Err(invalid("container id 0 must be mapped"));
        }
        Ok(Self { lines })
    }

    /// 検証済みの写像行。
    #[must_use]
    pub fn lines(&self) -> &[IdRange] {
        &self.lines
    }

    /// コンテナ内の `id` が写るホストの ID。どの行にも無い・オーバーフローは `None`。
    #[must_use]
    pub fn map_to_host(&self, id: u32) -> Option<u32> {
        self.lines.iter().find_map(|l| l.map_to_host(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(c: u32, h: u32, n: u32) -> IdRange {
        IdRange {
            container_id: c,
            host_id: h,
            count: n,
        }
    }

    fn code(v: Vec<IdRange>) -> OciErrorCode {
        IdMap::new(v).unwrap_err().code()
    }

    /// SEC-5: 複数行の写像の境界（先頭・末尾・末尾 + 1・隙間）。
    #[test]
    fn sec5_idmap_maps_boundaries() {
        let m = IdMap::new(vec![
            r(0, 100_000, 1),
            r(1, 100_001, 65_535),
            r(70_000, 200_000, 10),
        ])
        .unwrap();
        assert_eq!(m.map_to_host(0), Some(100_000));
        assert_eq!(m.map_to_host(1), Some(100_001));
        assert_eq!(m.map_to_host(65_535), Some(165_535));
        assert_eq!(m.map_to_host(65_536), None);
        assert_eq!(m.map_to_host(69_999), None);
        assert_eq!(m.map_to_host(70_000), Some(200_000));
        assert_eq!(m.map_to_host(70_009), Some(200_009));
        assert_eq!(m.map_to_host(70_010), None);
        assert_eq!(m.lines().len(), 3);
    }

    /// SEC-5: u32 の上端付近でも checked 演算で溢れない。
    #[test]
    fn sec5_idmap_u32_max_edge() {
        let m = IdMap::new(vec![r(0, 1, 1), r(u32::MAX - 1, u32::MAX - 2, 2)]).unwrap();
        assert_eq!(m.map_to_host(u32::MAX), Some(u32::MAX - 1));
        assert_eq!(m.map_to_host(u32::MAX - 1), Some(u32::MAX - 2));
        // 末尾が u32::MAX - 1 までのホスト範囲は受理する。
        assert!(IdMap::new(vec![r(0, u32::MAX - 1, 1)]).is_ok());
    }

    /// SEC-5: 拒否する各ケースの code。
    #[test]
    fn sec5_idmap_rejects_invalid() {
        use OciErrorCode::{InvalidArgument as Inv, PermissionDenied as Perm};
        assert_eq!(code(vec![]), Inv);
        assert_eq!(code(vec![r(0, 1, 0)]), Inv);
        assert_eq!(code(vec![r(0, 1, u32::MAX), r(u32::MAX, 5, 2)]), Inv);
        assert_eq!(code(vec![r(0, 0, 1)]), Perm);
        // chown の「変更なし」指定 u32::MAX をホスト範囲に含む写像は拒否する。
        assert_eq!(code(vec![r(0, u32::MAX, 1)]), Inv);
        assert_eq!(code(vec![r(0, u32::MAX - 1, 2)]), Inv);
        assert_eq!(code(vec![r(0, 1, 1), r(5, u32::MAX - 1, 2)]), Inv);
        assert_eq!(code(vec![r(0, 10, 5), r(1, 100, 1)]), Inv);
        assert_eq!(code(vec![r(0, 10, 5), r(100, 12, 1)]), Inv);
        assert_eq!(code(vec![r(1, 10, 5)]), Inv);
        let many: Vec<IdRange> = (0..=u32::try_from(MAX_ID_MAP_LINES).unwrap())
            .map(|i| r(i, 1000 + i, 1))
            .collect();
        assert_eq!(many.len(), MAX_ID_MAP_LINES + 1);
        assert_eq!(code(many), Inv);
        let ok: Vec<IdRange> = (0..u32::try_from(MAX_ID_MAP_LINES).unwrap())
            .map(|i| r(i, 1000 + i, 1))
            .collect();
        assert!(IdMap::new(ok).is_ok());
    }
}
