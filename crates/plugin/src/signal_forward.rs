//! 起動中の plugin の追跡表と、親が受けたシグナルの転送 API（#1513・PLUG-7・REPAIR-5・CORE-1。#1403 の方式 A）。
//!
//! # 役割
//! `fandhe-container` バイナリ（`fandhe-container-cli`）は常駐デーモンを持たず、plugin は CLI プロセスの
//! 子として起動される（`lifecycle` の都度起動・常駐）。端末の Ctrl-C やシステムの終了要求で親が
//! SIGINT・SIGTERM・SIGHUP を受けたとき、起動中の plugin へ転送してから親が終了できるよう、
//! 起動中の子の pid を固定長の登録表に記録する。シグナルハンドラの登録は CLI バイナリの責務で
//! （#1403 判断 2）、本モジュールは「登録中の plugin へ送る」安全な API だけを提供する。
//!
//! # 呼び出し文脈
//! - 登録・解除: `lifecycle::spawn_registered`（spawn 成功時に登録）と `ChildGuard`（子を回収し得る
//!   `try_wait` の直前に登録を外し、回収・破棄で解放）。呼び出し側（core の plugin proxy 等）は意識しない。
//! - 送信: CLI のシグナルハンドラが [`forward_to_running_plugins`] を呼ぶ。
//!
//! # 契約
//! - [`forward_to_running_plugins`] はシグナルハンドラから呼べる（async-signal-safe）。atomic の load・
//!   `kill(2)`・[`ForwardReport`] の構築だけを行い、割り当て・ロック・panic・I/O をしない。
//! - 送り先は登録中の子のグループ宛て（`kill(-pid)`）を優先し、グループが無い（子が自グループの
//!   リーダーでなく `ESRCH`）ときだけ直接の子（`kill(pid)`）へ送る。リーダーへの二重配送はしない。送れるシグナルは [`ForwardSignal`] の 3 種のみ。
//! - 登録表は [`PLUGIN_SIGNAL_TABLE_CAPACITY`] 件の固定長。満杯のとき plugin の spawn は子を起動せず
//!   `RESOURCE_EXHAUSTED`（[`crate::PluginErrorCode::ResourceExhausted`]）で拒否する（fail-closed）。
//! - 回収の前に登録を外す。外してから回収する窓は `waitpid(WNOHANG)` 1 回分で、その間に届いた
//!   シグナルは転送されない（取りこぼす側に倒す。回収後に再利用された pid へ送る窓は作らない）。
//!   登録表の待ち（シグナル送信中の走査の完了待ち）には上限がある（`REGISTRY_QUIESCE_TIMEOUT`）。
//!
//! # plugin 作者向けの推奨規約
//! 継承した pipe・接続（UDS）の EOF で親の終了を検知し、自ら終了すること。plugin は untrusted で
//! あり、この規約もシグナル転送も停止の保証ではなく補助である。停止の保証は `ChildGuard` の
//! SIGKILL＋回収が担う。
//!
//! # 制限
//! - 親が SIGKILL された場合・`panic = abort` で異常終了した場合は転送されない。Linux は
//!   `PR_SET_PDEATHSIG` で補う予定（#1514）。macOS では plugin が残留し得る。Windows は対象外。
//! - spawn から登録（`activate`）までの間は転送対象外。
//! - 他所での回収（継承した `SIGCHLD` の `SIG_IGN`・`SA_NOCLDWAIT`・利用側の `waitpid(-1)` 等）は契約外。
//!   その場合カーネルや利用側が子を回収しても、登録は `ChildGuard::try_wait` が `ECHILD` を受けるまで
//!   残り、その間に pid が再利用されると転送が無関係なプロセス（グループ）へ届き得る。`ECHILD`（および
//!   他の `waitpid` の失敗）を受けた時点で終端として登録を外し、以後 kill もしない（`Reap::Lost`）。
//!   窓を閉じるのは利用側の責務で、`SIGCHLD` を `SIG_DFL` に保ち、plugin の子を `waitpid(-1)` で回収しないこと。
//! - plugin を独立したプロセスグループで起動する変更（#1311・PR #1397）の前は、端末の Ctrl-C が
//!   カーネルのグループ配送と本転送の双方で plugin に届き得る（無害）。変更後は転送のみになり、
//!   `kill(-pid)` が孫まで届く経路になる。

use crate::error::{PluginError, PluginErrorCode};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// 登録表の件数。CLI 1 プロセスが同時に保持する plugin は、常駐バックエンド数個と並行する都度起動の
/// 数個程度で、64 件は十分な余裕を持つ。シグナルハンドラ内の走査は最大 64 スロット × 2 回の `kill` で
/// 上限が定まる。超過は異常な並列度として spawn を fail-closed で拒否する。
pub const PLUGIN_SIGNAL_TABLE_CAPACITY: usize = 64;

/// 登録を外した後、進行中のシグナル送信（走査）の完了を待つ上限（REPAIR-5）。走査は最大 128 回の
/// `kill` で、通常は数マイクロ秒で終わる。
pub(crate) const REGISTRY_QUIESCE_TIMEOUT: Duration = Duration::from_millis(50);

/// 転送できるシグナル。呼び出し側に任意の番号を指定させない（任意シグナルの注入経路を作らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardSignal {
    /// SIGINT（端末の Ctrl-C）。
    Interrupt,
    /// SIGTERM（終了要求）。
    Terminate,
    /// SIGHUP（端末の切断）。
    Hangup,
}

impl ForwardSignal {
    /// シグナル番号（Linux・macOS とも SIGHUP=1・SIGINT=2・SIGTERM=15。`signal.h` で確認）。
    #[cfg(unix)]
    fn number(self) -> i32 {
        match self {
            Self::Hangup => 1,
            Self::Interrupt => 2,
            Self::Terminate => 15,
        }
    }

    /// ハンドラが受けた番号を列挙型へ戻す。対象外の番号は `None`。
    #[cfg(unix)]
    pub fn from_raw(sig: i32) -> Option<Self> {
        match sig {
            1 => Some(Self::Hangup),
            2 => Some(Self::Interrupt),
            15 => Some(Self::Terminate),
            _ => None,
        }
    }
}

/// [`forward_to_running_plugins`] の結果（将来の拡張に備えた構造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForwardReport {
    /// 送信を試みた登録中の plugin の件数。
    pub targets: usize,
}

/// 登録中の plugin の全てへ `sig` を送る（シグナルハンドラから呼べる。async-signal-safe）。
///
/// モジュール冒頭の契約を参照。非 unix では何も送らない（`targets` は 0）。
pub fn forward_to_running_plugins(sig: ForwardSignal) -> ForwardReport {
    PLUGIN_REGISTRY.forward(sig)
}

/// 登録中の plugin の pid のスナップショット（テスト・診断用）。割り当てをするため、
/// シグナルハンドラから呼ばないこと。
pub fn registered_plugin_pids() -> Vec<u32> {
    PLUGIN_REGISTRY.snapshot()
}

const EMPTY: i32 = 0;
/// spawn 中の予約。送信側は 1 以下を飛ばす。
const RESERVED: i32 = -1;

static GLOBAL_SLOTS: [AtomicI32; PLUGIN_SIGNAL_TABLE_CAPACITY] =
    [const { AtomicI32::new(EMPTY) }; PLUGIN_SIGNAL_TABLE_CAPACITY];

/// プロセス全体の登録表。
pub(crate) static PLUGIN_REGISTRY: Registry = Registry::over(&GLOBAL_SLOTS);

/// 起動中の子の pid を保持する固定長の登録表。スロットは `0`=空き・`-1`=予約・`>1`=登録中の pid。
/// スロットへ書き込むのは確保した [`SlotToken`] の所有者だけで、確保以外は単純な store でよい。
pub(crate) struct Registry {
    slots: &'static [AtomicI32],
    /// 進行中の送信（走査）の数。登録を外す側が、ロード済みの pid への送信完了を待つために使う。
    in_flight: AtomicUsize,
}

impl Registry {
    pub(crate) const fn over(slots: &'static [AtomicI32]) -> Self {
        Self {
            slots,
            in_flight: AtomicUsize::new(0),
        }
    }

    /// 空きスロットを確保する。満杯なら `ResourceExhausted`（fail-closed）。
    pub(crate) fn reserve(&'static self) -> Result<SlotToken, PluginError> {
        for (idx, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(EMPTY, RESERVED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(SlotToken {
                    registry: self,
                    idx,
                    pid: 0,
                });
            }
        }
        Err(PluginError::new(
            PluginErrorCode::ResourceExhausted,
            "plugin signal table is full",
        ))
    }

    fn snapshot(&self) -> Vec<u32> {
        self.slots
            .iter()
            .filter_map(|s| u32::try_from(s.load(Ordering::SeqCst)).ok())
            .filter(|p| *p > 1)
            .collect()
    }

    /// 登録中の pid へ直接とグループ宛てに送る。async-signal-safe（割り当て・ロックなし）。
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub(crate) fn forward(&self, sig: ForwardSignal) -> ForwardReport {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut targets = 0usize;
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        for slot in self.slots {
            let pid = slot.load(Ordering::SeqCst);
            if pid > 1 {
                // グループ宛てが届いたなら（子がグループリーダー）、リーダー自身にも含めて配送済みのため
                // 直接送信はしない（二重配送で SA_RESETHAND の plugin が 2 回目に既定動作で死ぬのを防ぐ）。
                // グループが無い（ESRCH 等）ときだけ直接の子へ送る。失敗は許容し結果は使わない。
                if !crate::sys::send_signal(-pid, sig.number()) {
                    let _ = crate::sys::send_signal(pid, sig.number());
                }
                targets += 1;
            }
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        ForwardReport { targets }
    }
}

/// 登録表の 1 スロットの所有権。Drop で解放する。
pub(crate) struct SlotToken {
    registry: &'static Registry,
    idx: usize,
    pid: i32,
}

impl SlotToken {
    fn slot(&self) -> Option<&AtomicI32> {
        self.registry.slots.get(self.idx)
    }

    /// 子の pid を登録する。1 以下・`i32` 超は `kill(0)`・`kill(-1)` の事故になり得るため拒否する。
    pub(crate) fn activate(&mut self, pid: u32) -> Result<(), PluginError> {
        let pid = i32::try_from(pid).ok().filter(|p| *p > 1).ok_or_else(|| {
            PluginError::new(PluginErrorCode::Internal, "plugin pid is out of range")
        })?;
        self.pid = pid;
        if let Some(s) = self.slot() {
            s.store(pid, Ordering::SeqCst);
        }
        Ok(())
    }

    /// 登録を外し、進行中の送信の完了を [`REGISTRY_QUIESCE_TIMEOUT`] まで待つ。完了を確認できたら true。
    /// false の間は子を回収してはならない（ロード済みの pid へ送信中の可能性がある）。
    pub(crate) fn suspend(&self) -> bool {
        if let Some(s) = self.slot() {
            s.store(RESERVED, Ordering::SeqCst);
        }
        let start = Instant::now();
        while self.registry.in_flight.load(Ordering::SeqCst) != 0 {
            if start.elapsed() >= REGISTRY_QUIESCE_TIMEOUT {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    /// [`Self::suspend`] で外した登録を戻す（子がまだ回収されていないとき）。
    pub(crate) fn resume(&self) {
        if let Some(s) = self.slot() {
            s.store(self.pid, Ordering::SeqCst);
        }
    }
}

impl Drop for SlotToken {
    fn drop(&mut self) {
        if let Some(s) = self.slot() {
            s.store(EMPTY, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(n: usize) -> &'static Registry {
        let slots: &'static [AtomicI32] = Box::leak(
            (0..n)
                .map(|_| AtomicI32::new(EMPTY))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(Registry::over(slots)))
    }

    /// PLUG-7: 上限に達した確保は具体的な code で拒否され、解放後は再び確保できる（#1513）。
    #[test]
    fn plug7_reserve_fails_with_resource_exhausted_when_full() {
        let reg = local(2);
        let a = reg.reserve().unwrap();
        let _b = reg.reserve().unwrap();
        let e = reg.reserve().err().unwrap();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
        drop(a);
        assert!(reg.reserve().is_ok());
    }

    /// PLUG-7: pid 1 以下・i32 超は登録できない。
    #[test]
    fn plug7_activate_rejects_out_of_range_pid() {
        let reg = local(1);
        let mut t = reg.reserve().unwrap();
        for bad in [0u32, 1, u32::MAX, i32::MAX as u32 + 1] {
            assert_eq!(
                t.activate(bad).unwrap_err().code(),
                PluginErrorCode::Internal
            );
        }
        assert!(reg.snapshot().is_empty());
        t.activate(4242).unwrap();
        assert_eq!(reg.snapshot(), vec![4242]);
        t.suspend();
        assert!(reg.snapshot().is_empty());
        t.resume();
        assert_eq!(reg.snapshot(), vec![4242]);
        drop(t);
        assert!(reg.snapshot().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn plug7_forward_signal_from_raw_maps_three_signals_only() {
        assert_eq!(ForwardSignal::from_raw(2), Some(ForwardSignal::Interrupt));
        assert_eq!(ForwardSignal::from_raw(15), Some(ForwardSignal::Terminate));
        assert_eq!(ForwardSignal::from_raw(1), Some(ForwardSignal::Hangup));
        assert_eq!(ForwardSignal::from_raw(9), None);
        assert_eq!(ForwardSignal::from_raw(0), None);
        assert_eq!(ForwardSignal::Interrupt.number(), 2);
    }

    /// 登録の無い表への転送は誰にも送らない。
    #[test]
    fn plug7_forward_with_no_targets_reports_zero() {
        let reg = local(4);
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
        // 予約中のスロットも対象外。
        let _t = reg.reserve().unwrap();
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
    }
}
