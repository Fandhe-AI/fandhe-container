//! fd 受け渡しとゲストメモリ I/O の観測レコード（GPU-6・REPAIR-4・TASK-172 F1.2・#1517）。
//!
//! 役割: `fd_passing`（`recvmsg` / `sendmsg`）と `guest_memory`（境界検査つき read / write）の各操作について、
//! 成功数・失敗数・失敗 code 別の件数・所要時間の合計をプロセス内のカウンタに集計する。境界検査の拒否（`OUT_OF_BOUNDS` 等）と
//! syscall の失敗（`OS_ERROR`）も失敗として数える。呼び出し元は F1.4（セッション。#1519）で、定期的に [`snapshot_lines`] を
//! 構造化ログへ出す（`log` モジュールと同じ `venus_jig event=...` 形式）。
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
}

impl Op {
    /// 全操作（添字は `as usize` と一致する）。
    pub const ALL: [Op; 4] = [Op::RecvFds, Op::SendFds, Op::MemRead, Op::MemWrite];

    /// ログに出す固定語彙。
    pub fn word(self) -> &'static str {
        match self {
            Self::RecvFds => "recv_fds",
            Self::SendFds => "send_fds",
            Self::MemRead => "mem_read",
            Self::MemWrite => "mem_write",
        }
    }
}

const OPS: usize = Op::ALL.len();
const CODES: usize = TransportErrorCode::ALL.len();

struct OpCounters {
    ok: AtomicU64,
    err: AtomicU64,
    nanos: AtomicU64,
    by_code: [AtomicU64; CODES],
}

impl OpCounters {
    const fn new() -> Self {
        Self {
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
            by_code: [const { AtomicU64::new(0) }; CODES],
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
        let _ = c
            .nanos
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(nanos))
            });
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
        };
        if let Some(c) = self.ops.get(op as usize) {
            s.ok = c.ok.load(Ordering::Relaxed);
            s.err = c.err.load(Ordering::Relaxed);
            s.total_nanos = c.nanos.load(Ordering::Relaxed);
            for (dst, src) in s.by_code.iter_mut().zip(c.by_code.iter()) {
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
