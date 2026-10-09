//! fd 受け渡しとゲストメモリ I/O の観測レコード（GPU-6・REPAIR-4・TASK-172 F1.2・#1517）。
//!
//! 役割: `fd_passing`（`recvmsg` / `sendmsg` / memfd 作成）と `guest_memory`（領域の map・`SET_MEM_TABLE` の検証・境界検査つき read / write）の各操作について、
//! 成功数・失敗数・失敗 code 別の件数・所要時間の合計と分布（2 の冪の固定区画ヒストグラム）をプロセス内のカウンタに集計する。境界検査の拒否（`OUT_OF_BOUNDS` 等）と
//! syscall の失敗（`OS_ERROR`）も失敗として数える。呼び出し元は計測する各操作で、[`snapshot_lines`] はセッション（F1.4・#1519）が終了時に 1 回出力する（実装済み）。定期的な出力は未実装（REPAIR-3・REPAIR-4。後続）。virtqueue 個別の観測カウンタも未実装で、セッション全体の集計は `session::metrics` が別に持つ。
//! 出す場合の形式は `log` モジュールと同じ `venus_jig event=...`。
//!
//! ログは固定語彙と数値だけを出し、frontend 由来のバイト列・fd 番号・GPA をエコーしない（ログ注入の防止）。
//! 集計はロックを持たない原子カウンタで、ホットパス（virtqueue の走査）の待ちを増やさない。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::transport_error::{TransportError, TransportErrorCode};

/// 観測対象の操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `recv_with_fds`。
    RecvFds,
    /// `send_with_fds`。
    SendFds,
    /// ゲストメモリの読み出し。
    MemRead,
    /// ゲストメモリの書き込み。
    MemWrite,
    /// `create_memfd` / `create_memfd_unsealed`（memfd の作成と seal）。
    MemfdCreate,
    /// `GuestMemoryRegion::map`（領域 1 個の検証と mmap）。
    MemMap,
    /// `GuestMemory::from_table`（`SET_MEM_TABLE` 全体の検証と map。入口の検証失敗も含む）。
    MemTable,
}

impl Op {
    /// 全操作（添字は `as usize` と一致する）。
    pub const ALL: [Op; 7] = [
        Op::RecvFds,
        Op::SendFds,
        Op::MemRead,
        Op::MemWrite,
        Op::MemfdCreate,
        Op::MemMap,
        Op::MemTable,
    ];

    /// ログに出す固定語彙。
    pub fn word(self) -> &'static str {
        match self {
            Self::RecvFds => "recv_fds",
            Self::SendFds => "send_fds",
            Self::MemRead => "mem_read",
            Self::MemWrite => "mem_write",
            Self::MemfdCreate => "memfd_create",
            Self::MemMap => "mem_map",
            Self::MemTable => "mem_table",
        }
    }
}

const OPS: usize = Op::ALL.len();
const CODES: usize = TransportErrorCode::ALL.len();

/// 所要時間ヒストグラムの区画数。区画 `i`（`1 <= i < LAT_BUCKETS - 1`）は `2^(i-1) <= ns < 2^i`、
/// 区画 0 は 0ns、末尾の区画は残り（約 2^38 ns = 275 秒以上）を受ける。操作ごとの固定サイズで、無制限に増えない。
pub const LAT_BUCKETS: usize = 40;

/// 所要時間（ナノ秒）の区画番号。
fn lat_bucket(nanos: u64) -> usize {
    let i = (u64::BITS - nanos.leading_zeros()) as usize;
    i.min(LAT_BUCKETS - 1)
}

struct OpCounters {
    ok: AtomicU64,
    err: AtomicU64,
    nanos: AtomicU64,
    by_code: [AtomicU64; CODES],
    lat: [AtomicU64; LAT_BUCKETS],
}

impl OpCounters {
    const fn new() -> Self {
        Self {
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
            by_code: [const { AtomicU64::new(0) }; CODES],
            lat: [const { AtomicU64::new(0) }; LAT_BUCKETS],
        }
    }
}

/// 操作別カウンタの集合。プロセス全体用の [`global`] と、試験用に独立して作れる [`Metrics::new`] がある。
pub struct Metrics {
    ops: [OpCounters; OPS],
}

/// 1 操作ぶんの集計値のコピー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpSnapshot {
    /// 成功数。
    pub ok: u64,
    /// 失敗数（`by_code` の合計と一致する）。
    pub err: u64,
    /// 所要時間の合計（ナノ秒。成功・失敗の両方を含む）。
    pub total_nanos: u64,
    /// 失敗 code 別の件数（添字は [`TransportErrorCode::ALL`] と対応）。
    pub by_code: [u64; CODES],
    /// 所要時間ヒストグラム（添字は区画番号。成功・失敗の両方を含む。REPAIR-4）。
    pub latency: [u64; LAT_BUCKETS],
}

impl Metrics {
    /// 全カウンタ 0 の集合を作る。
    pub const fn new() -> Self {
        Self {
            ops: [const { OpCounters::new() }; OPS],
        }
    }

    /// 1 回の結果と所要時間を記録する。
    pub fn record(&self, op: Op, result: Result<(), TransportErrorCode>, nanos: u64) {
        let Some(c) = self.ops.get(op as usize) else {
            return;
        };
        match result {
            Ok(()) => {
                c.ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(code) => {
                if let Some(n) = c.by_code.get(code as usize) {
                    n.fetch_add(1, Ordering::Relaxed);
                }
                c.err.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 合計は飽和させる（巻き戻りを避ける）。
        // `fetch_update` は toolchain 間で名前が変わる（`try_update`）ため、`compare_exchange_weak` のループで書く。
        let mut cur = c.nanos.load(Ordering::Relaxed);
        while let Err(seen) = c.nanos.compare_exchange_weak(
            cur,
            cur.saturating_add(nanos),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            cur = seen;
        }
        if let Some(b) = c.lat.get(lat_bucket(nanos)) {
            b.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `f` を実行して結果と所要時間を記録し、結果をそのまま返す。
    pub fn observe<T>(
        &self,
        op: Op,
        f: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let start = Instant::now();
        let r = f();
        let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.record(op, r.as_ref().map(|_| ()).map_err(|e| e.code), nanos);
        r
    }

    /// 1 操作の集計値を読む。
    pub fn snapshot(&self, op: Op) -> OpSnapshot {
        let mut s = OpSnapshot {
            ok: 0,
            err: 0,
            total_nanos: 0,
            by_code: [0; CODES],
            latency: [0; LAT_BUCKETS],
        };
        if let Some(c) = self.ops.get(op as usize) {
            s.ok = c.ok.load(Ordering::Relaxed);
            s.err = c.err.load(Ordering::Relaxed);
            s.total_nanos = c.nanos.load(Ordering::Relaxed);
            for (dst, src) in s.by_code.iter_mut().zip(c.by_code.iter()) {
                *dst = src.load(Ordering::Relaxed);
            }
            for (dst, src) in s.latency.iter_mut().zip(c.lat.iter()) {
                *dst = src.load(Ordering::Relaxed);
            }
        }
        s
    }

    /// 構造化ログ行（操作ごとに 1 行 + 失敗 code ごとに 1 行。件数 0 の code は出さない）。
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for op in Op::ALL {
            let s = self.snapshot(op);
            out.push(format!(
                "venus_jig event=vhost_user_io op={} ok={} err={} total_ns={}",
                op.word(),
                s.ok,
                s.err,
                s.total_nanos
            ));
            // 所要時間の分布（件数 0 の区画は出さない。lt_ns は区画の上限（排他）、末尾の区画は inf）。
            for (i, n) in s.latency.iter().enumerate() {
                if *n == 0 {
                    continue;
                }
                let lt = if i + 1 >= LAT_BUCKETS {
                    "inf".to_string()
                } else {
                    (1u64 << i).to_string()
                };
                out.push(format!(
                    "venus_jig event=vhost_user_io_latency op={} lt_ns={lt} count={n}",
                    op.word()
                ));
            }
            for (code, n) in TransportErrorCode::ALL.iter().zip(s.by_code) {
                if n > 0 {
                    out.push(format!(
                        "venus_jig event=vhost_user_io_error op={} code={} count={n}",
                        op.word(),
                        code.as_str()
                    ));
                }
            }
        }
        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL: Metrics = Metrics::new();

/// プロセス全体の集計。`fd_passing` と `guest_memory` の公開操作がここへ記録する。
pub fn global() -> &'static Metrics {
    &GLOBAL
}

/// プロセス全体の集計を構造化ログ行にする（F1.4 が定期的に出す）。
pub fn snapshot_lines() -> Vec<String> {
    GLOBAL.lines()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GPU-6・REPAIR-4: 成功・失敗（code 別）・所要時間が具体値で集計され、ログ行に出る。
    #[test]
    fn gpu6_metrics_count_ok_err_and_time() {
        let m = Metrics::new();
        m.record(Op::MemRead, Ok(()), 100);
        m.record(Op::MemRead, Ok(()), 50);
        m.record(Op::MemRead, Err(TransportErrorCode::OutOfBounds), 25);
        m.record(Op::SendFds, Err(TransportErrorCode::OsError), 7);
        let s = m.snapshot(Op::MemRead);
        assert_eq!((s.ok, s.err, s.total_nanos), (2, 1, 175));
        assert_eq!(s.by_code[TransportErrorCode::OutOfBounds as usize], 1);
        let s = m.snapshot(Op::SendFds);
        assert_eq!((s.ok, s.err, s.total_nanos), (0, 1, 7));
        assert_eq!(m.snapshot(Op::RecvFds).ok, 0);
        let lines = m.lines();
        assert!(lines.contains(
            &"venus_jig event=vhost_user_io op=mem_read ok=2 err=1 total_ns=175".to_string()
        ));
        assert!(
            lines.contains(
                &"venus_jig event=vhost_user_io_error op=mem_read code=OUT_OF_BOUNDS count=1"
                    .to_string()
            )
        );
        assert!(lines.contains(
            &"venus_jig event=vhost_user_io_error op=send_fds code=OS_ERROR count=1".to_string()
        ));
    }

    /// GPU-6・REPAIR-4: `observe` は結果をそのまま返しつつ記録する。
    #[test]
    fn gpu6_observe_passes_result_through() {
        let m = Metrics::new();
        let r: Result<u8, TransportError> = m.observe(Op::RecvFds, || Ok(5));
        assert_eq!(r.expect("ok"), 5);
        let e = m
            .observe::<()>(Op::RecvFds, || {
                Err(TransportError::new(TransportErrorCode::Timeout))
            })
            .expect_err("err");
        assert_eq!(e.code, TransportErrorCode::Timeout);
        let s = m.snapshot(Op::RecvFds);
        assert_eq!((s.ok, s.err), (1, 1));
        assert_eq!(s.by_code[TransportErrorCode::Timeout as usize], 1);
    }

    /// REPAIR-4: 所要時間が 2 の冪の区画に分類され、分布がログ行に出る（具体値）。
    #[test]
    fn gpu6_latency_histogram_buckets_and_lines() {
        assert_eq!(lat_bucket(0), 0);
        assert_eq!(lat_bucket(1), 1);
        assert_eq!(lat_bucket(3), 2);
        assert_eq!(lat_bucket(4), 3);
        assert_eq!(lat_bucket(u64::MAX), LAT_BUCKETS - 1);
        let m = Metrics::new();
        m.record(Op::MemWrite, Ok(()), 3);
        m.record(Op::MemWrite, Ok(()), 2);
        m.record(Op::MemWrite, Err(TransportErrorCode::OsError), 1000);
        m.record(Op::MemWrite, Ok(()), u64::MAX);
        let s = m.snapshot(Op::MemWrite);
        assert_eq!(s.latency[2], 2);
        assert_eq!(s.latency[10], 1);
        assert_eq!(s.latency[LAT_BUCKETS - 1], 1);
        assert_eq!(s.latency.iter().sum::<u64>(), 4);
        let lines = m.lines();
        assert!(lines.contains(
            &"venus_jig event=vhost_user_io_latency op=mem_write lt_ns=4 count=2".to_string()
        ));
        assert!(lines.contains(
            &"venus_jig event=vhost_user_io_latency op=mem_write lt_ns=1024 count=1".to_string()
        ));
        assert!(lines.contains(
            &"venus_jig event=vhost_user_io_latency op=mem_write lt_ns=inf count=1".to_string()
        ));
    }

    /// GPU-6・REPAIR-4: memfd 作成・map・table の成功と拒否が構造化ログ行に出る。
    #[test]
    fn gpu6_memfd_and_map_ops_are_listed_in_lines() {
        let m = Metrics::new();
        m.record(Op::MemMap, Err(TransportErrorCode::ShrinkNotSealed), 5);
        m.record(Op::MemTable, Err(TransportErrorCode::FdCountMismatch), 6);
        m.record(Op::MemfdCreate, Ok(()), 7);
        let lines = m.lines();
        for l in [
            "venus_jig event=vhost_user_io op=mem_map ok=0 err=1 total_ns=5",
            "venus_jig event=vhost_user_io_error op=mem_map code=SHRINK_NOT_SEALED count=1",
            "venus_jig event=vhost_user_io_error op=mem_table code=FD_COUNT_MISMATCH count=1",
            "venus_jig event=vhost_user_io op=memfd_create ok=1 err=0 total_ns=7",
        ] {
            assert!(lines.contains(&l.to_string()), "missing: {l}");
        }
    }

    /// 添字と列挙順の対応（`as usize` で配列を引くため）。
    #[test]
    fn gpu6_index_tables_match_discriminants() {
        for (i, op) in Op::ALL.iter().enumerate() {
            assert_eq!(*op as usize, i);
        }
        for (i, c) in TransportErrorCode::ALL.iter().enumerate() {
            assert_eq!(*c as usize, i);
        }
    }
}
