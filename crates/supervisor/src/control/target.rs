//! 制御チャネルのサーバと、起動ハンドルを持つ監視スレッドの橋渡し（SUP-1・SUP-9・SEC-1・CORE-1・REPAIR-5・#2058・#2162）。
//!
//! `LaunchedProcess` は `Send` だけで `Sync` ではなく、別スレッドから同じハンドルを触れない（core のトレイトを
//! `Sync` に広げるとすべてのフェイクへ波及し、core と supervisor の境界も変わる）。そこで次の形にする。
//!
//! - [`ControlledProcess`]: 起動ハンドルを包む `LaunchedProcess`。監視ループが `wait` を呼ぶたびに、先に
//!   受け箱（有界チャネル）の要求を処理してから内側の `wait` を呼ぶ。シグナルの送信は常にハンドルを持つ
//!   スレッドの上で行われ、回収状態のロックの下で送られる（pid 再利用で無関係なプロセスへ送らない）。
//! - [`SignalSlot`]: サーバが見る共有の状態（`Empty` / `Active` / `Exited`）。ハンドルなし・終了済み・pid 不一致を
//!   監視スレッドを待たずに即答するために使う。世代番号で、再起動後の新しいハンドルを古いハンドルの `Drop` から守る。
//! - [`ControlledRelauncher`]: restart の再 launch で得た新しいハンドルを、新しい世代の [`ControlledProcess`] として
//!   登録する（古い世代の受け箱の要求は新しいプロセスへ届かない）。
//!
//! # 明示 stop の意図（SUP-9・#2162）
//!
//! StopRequest（`RequestKind::Stop`）は、シグナルを送る前に `StopToken::mark_explicit_stop` で意図を立てる
//! （書き先は [`SignalSlot::with_stop_intent`]。無ければ送らずに `StopIntentUnavailable`。fail-closed）。送信が失敗したら、
//! この要求で立てた分だけ戻す（先に別の stop が立てていた意図は消さない）。回収済み（`FailedPrecondition`）は、
//! 止めたい対象がもう終わっているので意図を残す。競合しない理由: 意図の設定・取り消しと、restart の判定
//! （`supervise_with_restart` が `monitor` から戻った後に読む）は、どちらも監視スレッドの上で順に起きる。
//! [`ControlledProcess`] の `wait` は内側の `wait` の前に受け箱を処理するので、SIGTERM による終了が観測されるのは必ず
//! 意図が立った後になる。`RequestKind::Signal`（CLI の `kill`。#1902）は意図に触れない。
//!
//! # バックオフ中・再 launch 中の stop（SUP-9・SUP-3・#2440）
//!
//! 終了を検知した後のバックオフ中は記録が `Stopped`（pid なし）で、StopRequest の pid が使えない。そこで CancelRestartRequest
//! （[`SignalSlot::cancel_pending_restart`]）を別に設ける。スロットが `Exited`（終了済みで再起動が保留中）のときだけ
//! 明示 stop の意図を立てて `Ok` を返し、restart ループがバックオフ・再 launch の最中にそれを見て再起動を取りやめる。
//! `Active`（新しいプロセスが既に動いている）は `ContainerRunning` で拒否し（同じ uid の別プロセスが稼働中コンテナの restart を
//! 黙って外せないようにする）、クライアントは通常の StopRequest をやり直す。上の「終了済みの Stop では意図を立てない」と
//! 両立するのは、StopRequest が pid を指定して「そのプロセスを止める」要求なのに対し、取り消しは利用者がはっきり
//! 「保留中の再起動の取り消し」を求める要求で、`Exited` のときだけ意図を立てるため。意図の設定とスロットの状態遷移（再 launch の
//! 登録）は同じロックの下で起きるので、取り消しは必ず「登録前（意図が立ち再起動が止まる）」か「登録後（`ContainerRunning`）」のどちらかになる。
//!
//! # 終了の購読（SUP-1・CRI-1・REPAIR-5・#3683）
//!
//! ExitWatchRequest（kind 8）の受け入れ先として、スロットは購読の接続（[`ExitWatchHandle`]）を `SlotInner` に預かる。
//! `Active` で pid が一致し枠に空きがあるときだけ預かり、`mark_exited`（init の回収）・`clear`・世代交代の `register` で
//! 一覧を空にする。一覧を空にすること（= 接続を閉じること）が購読者への「起きよ」で、スレッドも I/O も使わない
//! （ロックの下で行うのは fd の close だけ）。期限切れと相手が閉じた購読は [`SignalSlot::prune_exit_watchers`]
//! （accept ループが定期的に呼ぶ）で落とす。保持の数は [`DEFAULT_MAX_EXIT_WATCHERS`]、1 購読の長さは
//! `MAX_EXIT_WATCH_HOLD` + [`EXIT_WATCH_PRUNE_GRACE`] で有界。
//!
//! 応答の遅れは最大で監視ループの poll 間隔（`start_entry::POLL_INTERVAL`、100ms）。`run.rs`・`restart.rs` の
//! 公開関数のシグネチャは変えない（REPAIR-1）。全 OS でコンパイル・テストする（std のみ）。

use std::num::NonZeroU32;
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use fandhe_container_core::exec::PtyMaster;
#[cfg(target_os = "linux")]
use fandhe_container_core::oci_runtime::ContainerStdin;
use fandhe_container_core::oci_runtime::{
    ContainerOutput, LaunchMode, LaunchedProcess, ProcessExit,
};
use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

use super::protocol::{ControlReason, RequestKind};

use crate::log_pipeline::CaptureHub;
use crate::restart::{LateOrphan, Relauncher};
use crate::run::{ExplicitStopRecord, StopToken};
use crate::start_contract::StdinOption;

/// 受け箱の容量（超えたら `Busy`。資源の使用量を固定に抑える）。
pub const INBOX_CAPACITY: usize = 4;

/// 預かれる終了購読の最大数（超えたら `Busy`。資源の使用量を固定に抑える。REPAIR-5・#3683）。
/// plugin-cri の Wait はコンテナあたり通常 1 件で、数倍の余裕がある。
pub const DEFAULT_MAX_EXIT_WATCHERS: usize = 8;

/// 購読の保持期限の後に、サーバが接続を預かり続ける猶予。クライアントが先に期限を迎えるための差で、
/// 通常はサーバ側の期限切れ（早すぎる EOF）は起きない。
pub const EXIT_WATCH_PRUNE_GRACE: Duration = Duration::from_secs(1);

/// 預かった終了購読の接続の口。`Drop` で接続を閉じる（= 購読者の起床）実装を前提にする（本番は `UnixStream`）。
pub trait ExitWatchHandle: Send {
    /// 相手が接続を閉じた、または規約違反のデータを送ってきたなら `true`（待たない。落としてよい購読）。
    fn is_dead(&mut self) -> bool;
}

struct ExitWatcher {
    expires: Instant,
    handle: Box<dyn ExitWatchHandle>,
}

/// 監視スレッドへ渡す 1 件のシグナル送信要求。
struct PendingSignal {
    kind: RequestKind,
    pid: NonZeroU32,
    signal: Signal,
    /// この時刻以降は送らない（`Timeout` を返す）。
    deadline: Instant,
    /// 結果の返信先（容量 1。受け手が居なくても送信は詰まらない）。
    reply: SyncSender<ControlReason>,
}

/// exec 用に CLI へ渡す、起動時 pidfd の複製（SUP-6・SEC-1・#2626）。Linux 以外は pidfd が無く、値を持たない型にする。
#[cfg(target_os = "linux")]
pub type PidfdDup = Arc<std::os::fd::OwnedFd>;
/// exec 用に CLI へ渡す、起動時 pidfd の複製（Linux 以外は pidfd が無く、常に `None`）。
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub enum PidfdDup {}

/// 世代ごとの attach 用の入出力（stdin の書き込み端・tty の master の複製。SUP-7・SUP-3・CRI-6・SEC-1・#4074）。
///
/// [`SlotState::Active`] の中にだけ置く（pidfd の複製と同じ形）。`Exited`・`Empty` への遷移と、再 launch の
/// `register`（新しい世代による上書き）で必ず drop されるので、古い世代の fd が新しい世代に残らない・終了済みの
/// コンテナの stdin を保持し続けない、が型の上で保証される。取り出しは [`SignalSlot::take_attach_input`]（kind 9 `AttachRequest` の
/// サーバ側。C6 #4075）。Linux 以外は pty も stdin の pipe も無く、値を持たない型にする。
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct GenerationIo {
    /// 非 tty で `--stdin` を指定したときの init の stdin の書き込み端。
    pub(crate) stdin: Option<ContainerStdin>,
    /// tty のときの pty の master の複製（捕捉用の読み取り側とは別の fd。close-on-exec）。
    pub(crate) master: Option<PtyMaster>,
    /// `stdin_once` の stdin を attach が既に消費したか（世代ごとに初期化する。[`SignalSlot::take_attach_input`] が書く）。
    pub(crate) stdin_consumed: bool,
}

/// 世代ごとの attach 用の入出力（Linux 以外は値を持たない）。
#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub(crate) struct GenerationIo;

enum SlotState {
    Empty,
    Active {
        generation: u64,
        pid: NonZeroU32,
        inbox: SyncSender<PendingSignal>,
        /// 起動ハンドルの pidfd の複製（close-on-exec）。`Active` の間だけ持ち、`Exited`・`Empty` へ遷移したら落とす。
        pidfd: Option<PidfdDup>,
        /// 世代ごとの attach 用の入出力。pidfd の複製と同じく `Active` の間だけ持つ。Linux 以外は値を持たず、読み手も無い。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        io: GenerationIo,
    },
    Exited {
        generation: u64,
        pid: NonZeroU32,
    },
}

struct SlotInner {
    next_generation: u64,
    state: SlotState,
    /// 明示 stop の意図の書き先（SUP-9）。`None` なら StopRequest は受けられない。
    stop_intent: Option<StopToken>,
    /// 預かっている終了購読（`Active` の間だけ。遷移・世代交代で空にして閉じる。#3683）。
    exit_watchers: Vec<ExitWatcher>,
    /// コンテナ単位の `--stdin` の指定（世代をまたいで保つ。`with_stdin_option`。#4074）。
    stdin_option: Option<StdinOption>,
    /// コンテナ単位の出力の捕捉ハブ（kind 9 の tap の購読先。`with_output_capture`。#4075）。
    output: Option<Arc<CaptureHub>>,
}

/// Attach の入力として取り出した fd の持ち主（#4075）。送信に成功したら drop する（= 所有の移転）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum TakenInput {
    /// 複製（`--stdin open` の書き込み端・tty の master）。スロットは元を持ち続ける。
    Dup(std::os::fd::OwnedFd),
    /// `stdin_once` の元の端（スロットからは外してある）。送れなかったら [`SignalSlot::restore_stdin_once`] で戻す。
    Once(ContainerStdin),
}

#[cfg(target_os = "linux")]
impl std::os::fd::AsFd for TakenInput {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self {
            Self::Dup(fd) => fd.as_fd(),
            Self::Once(stdin) => stdin.as_fd(),
        }
    }
}

/// [`SignalSlot::take_attach_input`] の結果（#4075）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct AttachTaken {
    /// 取り出した時点の世代（`stdin_once` の巻き戻しが同じ世代にだけ効くように持ち回る）。
    pub(crate) generation: u64,
    /// 入力の fd。要求が入力を求めなかったときは `None`。
    pub(crate) input: Option<TakenInput>,
}

/// [`SignalSlot::take_attach_input`] / [`SignalSlot::check_attach`] の本体（ロックを持った状態で呼ぶ）。
#[cfg(target_os = "linux")]
fn attach_locked(
    inner: &mut SlotInner,
    pid: NonZeroU32,
    tty: bool,
    wants_stdin: bool,
    commit: bool,
) -> Result<AttachTaken, ControlReason> {
    let stdin_option = inner.stdin_option;
    let (generation, io) = match &mut inner.state {
        SlotState::Empty => return Err(ControlReason::NoHandle),
        SlotState::Exited { pid: held, .. } => {
            return Err(if *held == pid {
                ControlReason::ContainerExited
            } else {
                ControlReason::PidMismatch
            });
        }
        SlotState::Active {
            generation,
            pid: held,
            io,
            ..
        } => {
            if *held != pid {
                return Err(ControlReason::PidMismatch);
            }
            (*generation, io)
        }
    };
    let none = |generation| AttachTaken {
        generation,
        input: None,
    };
    if tty {
        if io.master.is_none() {
            return Err(if io.stdin.is_some() {
                ControlReason::TtyMismatch
            } else {
                ControlReason::NoHandle
            });
        }
    } else if io.master.is_some() {
        return Err(ControlReason::TtyMismatch);
    }
    if !wants_stdin {
        return Ok(none(generation));
    }
    if tty {
        if !commit {
            return Ok(none(generation));
        }
        let Some(master) = io.master.as_ref() else {
            return Err(ControlReason::NoHandle);
        };
        let dup = master
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| ControlReason::Internal)?;
        return Ok(AttachTaken {
            generation,
            input: Some(TakenInput::Dup(dup)),
        });
    }
    match stdin_option {
        None => return Err(ControlReason::StdinNotOpen),
        Some(StdinOption::Once) if io.stdin_consumed => return Err(ControlReason::StdinClosed),
        Some(_) => {}
    }
    if io.stdin.is_none() {
        return Err(ControlReason::NoHandle);
    }
    if !commit {
        return Ok(none(generation));
    }
    let input = match stdin_option {
        Some(StdinOption::Once) => {
            let stdin = io.stdin.take().ok_or(ControlReason::NoHandle)?;
            io.stdin_consumed = true;
            TakenInput::Once(stdin)
        }
        _ => {
            let stdin = io.stdin.as_ref().ok_or(ControlReason::NoHandle)?;
            let dup = stdin.try_clone().map_err(|_| ControlReason::Internal)?;
            TakenInput::Dup(dup.into_owned_fd())
        }
    };
    Ok(AttachTaken {
        generation,
        input: Some(input),
    })
}

/// サーバと監視スレッドが共有する、起動ハンドルの有無・世代の状態。
#[derive(Clone)]
pub struct SignalSlot(Arc<Mutex<SlotInner>>);

impl Default for SignalSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalSlot {
    /// ハンドルなし（`Empty`）の状態で作る。stop の意図の書き先は無く、StopRequest は `StopIntentUnavailable` で断る。
    pub fn new() -> Self {
        Self::build(None)
    }

    /// stop の意図の書き先 `stop` を持つ状態で作る（本番。`stop` は restart の判定に渡すトークンと同じもの。SUP-9）。
    pub fn with_stop_intent(stop: StopToken) -> Self {
        Self::build(Some(stop))
    }

    fn build(stop_intent: Option<StopToken>) -> Self {
        Self(Arc::new(Mutex::new(SlotInner {
            next_generation: 1,
            state: SlotState::Empty,
            stop_intent,
            exit_watchers: Vec::new(),
            stdin_option: None,
            output: None,
        })))
    }

    /// コンテナ単位の `--stdin` の指定を設定する（本番の入口が `install` で設定する。SUP-7・CRI-6・#4074）。
    /// 世代交代（再 launch）をまたいで保たれる。attach の入口（C6 #4075）が `stdin_once` の判断に使う。
    #[must_use]
    pub fn with_stdin_option(self, option: Option<StdinOption>) -> Self {
        self.lock().stdin_option = option;
        self
    }

    /// コンテナの出力の捕捉ハブを設定する（`install_with_exec_reclaimer` が `Running.logs` から渡す。#4075）。
    /// kind 9 の tap の購読先で、世代交代をまたいで保たれる（ハブ側が世代ごとの捕捉を持つ）。ハンドラはロックの下で
    /// `Arc` を複製するだけで、購読はロックの外で行う（スロットのロックの下でハブのロックを取らない）。サーバの
    /// 引数に通さないのは、`spawn*` 系 4 つと `PausableInner` の全てを変えることになり、スロットはもともと
    /// pause / resume をまたいで共有されているため。
    #[must_use]
    pub fn with_output_capture(self, hub: Option<Arc<CaptureHub>>) -> Self {
        self.lock().output = hub;
        self
    }

    /// 設定された出力の捕捉ハブ（`Arc` の複製）。
    #[cfg(target_os = "linux")]
    pub(crate) fn output_capture(&self) -> Option<Arc<CaptureHub>> {
        self.lock().output.clone()
    }

    /// 設定された `--stdin` の指定（試験用）。
    #[cfg(test)]
    pub(crate) fn stdin_option(&self) -> Option<StdinOption> {
        self.lock().stdin_option
    }

    /// `Active` で記録 pid が `pid` と一致するときだけ、現世代の入出力へ `f` を適用する（スロットのロックの下。
    /// `f` では待たない・I/O をしないこと）。それ以外は既存の呼び出しと同じ理由コードで断る（`Empty`: `NoHandle`、
    /// `Exited`: pid 一致なら `ContainerExited`・不一致なら `PidMismatch`、`Active` で pid 不一致: `PidMismatch`）。
    /// 世代交代後の古い入出力は `Active` の入れ替えで落ちており、渡らない（試験用。本番の取り出しは
    /// [`Self::take_attach_input`]）。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_generation_io<R>(
        &self,
        pid: NonZeroU32,
        f: impl FnOnce(&mut GenerationIo) -> R,
    ) -> Result<R, ControlReason> {
        let mut inner = self.lock();
        match &mut inner.state {
            SlotState::Empty => Err(ControlReason::NoHandle),
            SlotState::Exited { pid: held, .. } => Err(if *held == pid {
                ControlReason::ContainerExited
            } else {
                ControlReason::PidMismatch
            }),
            SlotState::Active { pid: held, io, .. } => {
                if *held != pid {
                    return Err(ControlReason::PidMismatch);
                }
                Ok(f(io))
            }
        }
    }

    /// Attach の事前の照合（何も取り出さない）。[`Self::take_attach_input`] と同じ判定を `commit = false` で行う。
    #[cfg(target_os = "linux")]
    pub(crate) fn check_attach(
        &self,
        pid: NonZeroU32,
        tty: bool,
        wants_stdin: bool,
    ) -> Result<(), ControlReason> {
        let mut inner = self.lock();
        attach_locked(&mut inner, pid, tty, wants_stdin, false).map(|_| ())
    }

    /// Attach の入力 fd を、スロットのロックの下で取り出す（kind 9。SUP-4・SUP-7・SEC-1・#4075）。
    ///
    /// 判定（`Active` で pid 一致・入出力の構成との照合）は [`ControlReason`] で断る。
    /// - 要求 `tty` が偽でコンテナが pty: `TtyMismatch`。真でコンテナに master が無い: stdin の端があれば
    ///   `TtyMismatch`、無ければ `NoHandle`（master の複製に失敗した tty のコンテナと `--stdin` の無い非 tty は
    ///   区別できず、どちらも拒否する安全側。tty の正式な照合は cri の D7〔C10〕が担う）。
    /// - 非 tty で入力を求める: `--stdin` が無ければ `StdinNotOpen`、`Once` で消費済みなら `StdinClosed`、
    ///   端が無ければ `NoHandle`。
    ///
    /// 取り出し: tty は master の複製（消費済みにしない。D5: tty の `stdin_once` は閉じない）、非 tty の `Open` は
    /// 書き込み端の複製、`Once` は元の端そのもの（`stdin_consumed = true`。受け手が唯一の書き込み端を持つ）。
    /// 複製は `fcntl(F_DUPFD_CLOEXEC)` だけで待たず、ロックの下の契約（待たない・I/O をしない）の範囲に収まる。
    #[cfg(target_os = "linux")]
    pub(crate) fn take_attach_input(
        &self,
        pid: NonZeroU32,
        tty: bool,
        wants_stdin: bool,
    ) -> Result<AttachTaken, ControlReason> {
        let mut inner = self.lock();
        attach_locked(&mut inner, pid, tty, wants_stdin, true)
    }

    /// 送れなかった `stdin_once` の端をスロットへ戻し、消費済みを取り消す。同じ世代がまだ `Active` で `stdin` が空の
    /// ときだけ戻る（世代が変わっていたり `Exited` なら drop が正しい）。戻さないと、失敗した attach がコンテナの
    /// stdin を閉じてしまう（#4075）。
    #[cfg(target_os = "linux")]
    pub(crate) fn restore_stdin_once(&self, generation: u64, stdin: ContainerStdin) {
        let mut inner = self.lock();
        if let SlotState::Active {
            generation: g, io, ..
        } = &mut inner.state
            && *g == generation
            && io.stdin.is_none()
        {
            io.stdin = Some(stdin);
            io.stdin_consumed = false;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 新しいハンドルを登録し、世代と受け箱を返す（直前の状態は上書きする）。
    fn register(
        &self,
        pid: NonZeroU32,
        pidfd: Option<PidfdDup>,
        io: GenerationIo,
    ) -> (u64, Receiver<PendingSignal>) {
        let (tx, rx) = sync_channel(INBOX_CAPACITY);
        let mut inner = self.lock();
        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        // 旧世代の購読は新しいプロセスのものではない。閉じて購読者を起こす（状態の読み直しで新しい pid を見る）。
        inner.exit_watchers.clear();
        inner.state = SlotState::Active {
            generation,
            pid,
            inbox: tx,
            pidfd,
            io,
        };
        (generation, rx)
    }

    /// CLI の `exec` へ渡す起動時 pidfd の複製を取り出す（ExecHandoverRequest。SUP-6・SEC-1・#2626）。
    ///
    /// スロットのロックの下で判定し（受け箱は経由しない。シグナルも送らない）、`Active` で記録 pid が `pid` と一致し、
    /// 複製を持っているときだけ `Ok`。それ以外の理由は次のとおり（世代交代後の古い複製は `Active` の入れ替えで落ちており、
    /// 渡らない）。
    /// - `Empty`: `NoHandle`。`Exited`: pid 一致なら `ContainerExited`、不一致なら `PidMismatch`。
    /// - `Active` で pid 不一致: `PidMismatch`。複製を持たない（pidfd 非対応のカーネル・起動ハンドルなし）: `NoHandle`。
    pub fn handover_pidfd(&self, pid: NonZeroU32) -> Result<PidfdDup, ControlReason> {
        let inner = self.lock();
        match &inner.state {
            SlotState::Empty => Err(ControlReason::NoHandle),
            SlotState::Exited { pid: held, .. } => Err(if *held == pid {
                ControlReason::ContainerExited
            } else {
                ControlReason::PidMismatch
            }),
            SlotState::Active {
                pid: held, pidfd, ..
            } => {
                if *held != pid {
                    return Err(ControlReason::PidMismatch);
                }
                pidfd.clone().ok_or(ControlReason::NoHandle)
            }
        }
    }

    /// `generation` の `Active` を `Exited` にする（別世代なら何もしない）。
    fn mark_exited(&self, generation: u64) {
        let mut inner = self.lock();
        if let SlotState::Active {
            generation: g, pid, ..
        } = &inner.state
            && *g == generation
        {
            let pid = *pid;
            inner.state = SlotState::Exited { generation, pid };
            // 終了を購読者へ伝える（接続を閉じる）。
            inner.exit_watchers.clear();
        }
    }

    /// `generation` の状態を `Empty` に戻す（別世代なら何もしない）。
    fn clear(&self, generation: u64) {
        let mut inner = self.lock();
        let matches = match &inner.state {
            SlotState::Active { generation: g, .. } | SlotState::Exited { generation: g, .. } => {
                *g == generation
            }
            SlotState::Empty => false,
        };
        if matches {
            inner.state = SlotState::Empty;
            inner.exit_watchers.clear();
        }
    }

    /// 終了の購読を預かる（ExitWatchRequest。SUP-1・CRI-1・REPAIR-5・#3683）。
    ///
    /// スロットのロックの下で判定する（シグナルは送らず、受け箱も経由しない）。`Active` で記録 pid が `pid` と一致し、
    /// 枠（期限切れ・相手が閉じたものを整理した後の [`DEFAULT_MAX_EXIT_WATCHERS`]）に空きがあるときだけ `Ok` で、
    /// `handle` を `hold` + [`EXIT_WATCH_PRUNE_GRACE`] まで預かる。それ以外は次のとおりで、`handle` は drop される。
    /// - `Empty`: `NoHandle`。`Exited`: pid 一致なら `ContainerExited`、不一致なら `PidMismatch`。
    /// - `Active` で pid 不一致: `PidMismatch`。枠が満杯: `Busy`。
    pub fn watch_exit(
        &self,
        pid: NonZeroU32,
        handle: Box<dyn ExitWatchHandle>,
        hold: Duration,
    ) -> ControlReason {
        let mut inner = self.lock();
        match &inner.state {
            SlotState::Empty => return ControlReason::NoHandle,
            SlotState::Exited { pid: held, .. } => {
                return if *held == pid {
                    ControlReason::ContainerExited
                } else {
                    ControlReason::PidMismatch
                };
            }
            SlotState::Active { pid: held, .. } => {
                if *held != pid {
                    return ControlReason::PidMismatch;
                }
            }
        }
        let now = Instant::now();
        inner
            .exit_watchers
            .retain_mut(|w| now < w.expires && !w.handle.is_dead());
        if inner.exit_watchers.len() >= DEFAULT_MAX_EXIT_WATCHERS {
            return ControlReason::Busy;
        }
        let expires = now
            .checked_add(hold)
            .and_then(|t| t.checked_add(EXIT_WATCH_PRUNE_GRACE))
            .unwrap_or(now);
        inner.exit_watchers.push(ExitWatcher { expires, handle });
        ControlReason::Ok
    }

    /// 期限切れと、相手が閉じた終了購読を落とす（accept ループが周回ごとに呼ぶ。#3683・REPAIR-5）。
    pub fn prune_exit_watchers(&self, now: Instant) {
        self.lock()
            .exit_watchers
            .retain_mut(|w| now < w.expires && !w.handle.is_dead());
    }

    /// 預かっている終了購読の数（試験と計測用）。
    pub fn exit_watcher_count(&self) -> usize {
        self.lock().exit_watchers.len()
    }

    /// 保留中の再起動を取り消す（明示 stop の意図を立てる。CancelRestartRequest。SUP-9・SUP-3・#2440）。
    ///
    /// 受け箱は経由せず、スロットのロックの下で判定する（シグナルは送らない）。結果は次のとおり。
    /// - `Exited`: 意図を立てて `Ok`（restart ループがバックオフ・再 launch の最中に見て再起動を取りやめ、state.json に残す）。
    /// - `Active`: `ContainerRunning`（意図に触れない）。
    /// - `Empty`: `NoHandle`。意図の書き先が無い: `StopIntentUnavailable`。期限切れ: `Timeout`（意図を立てない）。
    pub fn cancel_pending_restart(&self, deadline: Instant) -> ControlReason {
        if Instant::now() >= deadline {
            return ControlReason::Timeout;
        }
        let inner = self.lock();
        let Some(token) = inner.stop_intent.as_ref() else {
            return ControlReason::StopIntentUnavailable;
        };
        match &inner.state {
            SlotState::Empty => ControlReason::NoHandle,
            SlotState::Active { .. } => ControlReason::ContainerRunning,
            SlotState::Exited { .. } => {
                // 受付が閉じていたら（restart ループが再起動なしで終わる最終判定を済ませた）成功にしない。
                if token.mark_explicit_stop() == ExplicitStopRecord::Closed {
                    return ControlReason::ContainerExited;
                }
                #[cfg(target_os = "linux")]
                super::log_control_event("restart_cancel_recorded", None);
                ControlReason::Ok
            }
        }
    }

    /// サーバから要求を預ける。受け付けたら返信用の受け口を返し、その場で断れるものは理由コードを返す。
    ///
    /// `RequestKind::Stop` で意図の書き先が無ければ、受け箱に入れず `StopIntentUnavailable` を返す（シグナルは送らない）。
    pub fn submit(
        &self,
        kind: RequestKind,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<Receiver<ControlReason>, ControlReason> {
        let inner = self.lock();
        if kind == RequestKind::Stop && inner.stop_intent.is_none() {
            return Err(ControlReason::StopIntentUnavailable);
        }
        match &inner.state {
            SlotState::Empty => Err(ControlReason::NoHandle),
            SlotState::Exited { pid: held, .. } => {
                if *held != pid {
                    Err(ControlReason::PidMismatch)
                } else {
                    // 終了済みの Stop では意図を立てない（意図は StopToken に残り、再 launch 後の新しい
                    // インスタンスの restart を無効化してしまうため。クラッシュとの競合に負けた stop は
                    // 何も止めない。SUP-9・#2162）。
                    Err(ControlReason::ContainerExited)
                }
            }
            SlotState::Active {
                pid: held, inbox, ..
            } => {
                if *held != pid {
                    return Err(ControlReason::PidMismatch);
                }
                let (reply, rx) = sync_channel(1);
                match inbox.try_send(PendingSignal {
                    kind,
                    pid,
                    signal,
                    deadline,
                    reply,
                }) {
                    Ok(()) => Ok(rx),
                    Err(TrySendError::Full(_)) => Err(ControlReason::Busy),
                    Err(TrySendError::Disconnected(_)) => Err(ControlReason::NoHandle),
                }
            }
        }
    }
}

/// 起動ハンドルの pidfd を close-on-exec で複製する（`F_DUPFD_CLOEXEC`。std の `try_clone_to_owned`）。
/// 複製できない（pidfd が無い・fd 枯渇）ときは `None`: exec の受け渡しは `NoHandle` で断り、起動ハンドルの
/// 監視・シグナル送信には影響しない（fail-closed。記録 pid からの縮退はしない）。
#[cfg(target_os = "linux")]
fn dup_launch_pidfd(inner: &dyn LaunchedProcess) -> Option<PidfdDup> {
    inner
        .launch_pidfd()
        .and_then(|fd| fd.try_clone_to_owned().ok())
        .map(Arc::new)
}

#[cfg(not(target_os = "linux"))]
fn dup_launch_pidfd(_inner: &dyn LaunchedProcess) -> Option<PidfdDup> {
    None
}

/// 起動ハンドルを包み、制御チャネルからの送信要求を監視ループの `wait` で処理する `LaunchedProcess`。
///
/// 呼び出し元は `supervise_with_restart`（監視ループ）。`pid`・`terminate`・`signal`・`take_output`・
/// `launch_pidfd` は内側へ転送する（`take_output` はログ捕捉〔#1471〕、`launch_pidfd` は exec の pidfd 固定
/// 〔#1461〕に必須）。
pub struct ControlledProcess {
    inner: Box<dyn LaunchedProcess>,
    slot: SignalSlot,
    generation: u64,
    inbox: Receiver<PendingSignal>,
}

impl ControlledProcess {
    /// `inner` を包み、`slot` へ新しい世代として登録する。
    ///
    /// Linux では `inner` の `take_stdin` / `take_pty_master` をここで取り出して世代の入出力（`GenerationIo`）として
    /// スロットへ移す（以後の本ハンドルの `take_stdin` / `take_pty_master` は `None`）。tty の捕捉用の読み取り側は
    /// `take_output` で別に渡る（`crate::attach_io::AttachIoProcess` が構築時に分けている。#4074）。
    pub fn new(inner: Box<dyn LaunchedProcess>, slot: SignalSlot) -> Self {
        #[cfg(target_os = "linux")]
        let io = GenerationIo {
            stdin: inner.take_stdin(),
            master: inner.take_pty_master(),
            stdin_consumed: false,
        };
        #[cfg(not(target_os = "linux"))]
        let io = GenerationIo;
        let (generation, inbox) = slot.register(inner.pid(), dup_launch_pidfd(inner.as_ref()), io);
        Self {
            inner,
            slot,
            generation,
            inbox,
        }
    }

    /// 受け箱が空になるまで処理する。`fixed` があれば送信せずその理由で返信する。
    fn drain(&self, fixed: Option<ControlReason>) {
        loop {
            match self.inbox.try_recv() {
                Ok(req) => {
                    let reason = match fixed {
                        Some(r) => {
                            // 終了を観測済みでも、受け箱に入っていた期限内の Stop の意図は記録する（SUP-9。
                            // 記録しないと restart の判定が `always` / `unless-stopped` で再 launch してしまう）。
                            // 期限切れの Stop は Timeout で断る要求なので意図を立てない（REPAIR-5）。
                            if req.kind == RequestKind::Stop && Instant::now() < req.deadline {
                                let token = self.slot.lock().stop_intent.clone();
                                if let Some(token) = token {
                                    token.mark_explicit_stop();
                                }
                            }
                            if req.kind == RequestKind::Stop && Instant::now() >= req.deadline {
                                ControlReason::Timeout
                            } else {
                                r
                            }
                        }
                        None => self.handle(&req),
                    };
                    // 受け手（サーバ）が期限で諦めていても詰まらない（容量 1・送信は 1 回）。
                    let _ = req.reply.try_send(reason);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    fn handle(&self, req: &PendingSignal) -> ControlReason {
        // 期限後には送らない（REPAIR-5）。core の `signal` も送信直前に再確認する。
        if Instant::now() >= req.deadline {
            return ControlReason::Timeout;
        }
        if req.pid != self.inner.pid() {
            return ControlReason::PidMismatch;
        }
        // 明示 stop は、シグナルを送る前に意図を立てる（終了の観測より必ず先。モジュール doc）。
        let intent = if req.kind == RequestKind::Stop {
            let Some(token) = self.slot.lock().stop_intent.clone() else {
                return ControlReason::StopIntentUnavailable;
            };
            let record = token.mark_explicit_stop();
            #[cfg(target_os = "linux")]
            super::log_control_event("stop_intent_recorded", None);
            Some((token, record))
        } else {
            None
        };
        let reason = match self.inner.signal(req.signal, req.deadline) {
            Ok(()) => ControlReason::Ok,
            Err(e) => match e.code() {
                ErrorCode::FailedPrecondition => ControlReason::ContainerExited,
                ErrorCode::Timeout => ControlReason::Timeout,
                _ => ControlReason::SignalFailed,
            },
        };
        // 送れなかったとき、この要求で立てた意図だけ戻す。回収済みは止めたい対象が終わっているので残す。
        if let Some((token, ExplicitStopRecord::NewlyRecorded)) = &intent
            && !matches!(reason, ControlReason::Ok | ControlReason::ContainerExited)
        {
            token.revert_explicit_stop();
            #[cfg(target_os = "linux")]
            super::log_control_event("stop_intent_reverted", Some(reason.name()));
        }
        reason
    }
}

impl LaunchedProcess for ControlledProcess {
    fn pid(&self) -> NonZeroU32 {
        self.inner.pid()
    }

    /// 内側の launch 時の分離の記録へ転送する(転送しないと restart の記録の置き換えが落ち、restart 後の exec が
    /// `/` の照合で拒否される。SUP-6・#2007)。
    fn launch_isolation(
        &self,
    ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
        self.inner.launch_isolation()
    }

    /// 内側の launch 時の rlimit 集合へ転送する(転送しないと restart の記録の置き換えが落ちる。SUP-12・#2713)。
    fn launch_rlimits(&self) -> Option<&fandhe_container_core::rlimits::Rlimits> {
        self.inner.launch_rlimits()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        self.drain(None);
        let result = self.inner.wait(timeout);
        if matches!(result, Ok(Some(_))) {
            self.slot.mark_exited(self.generation);
            self.drain(Some(ControlReason::ContainerExited));
        }
        result
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let result = self.inner.terminate(timeout);
        if result.is_ok() {
            self.slot.mark_exited(self.generation);
            self.drain(Some(ControlReason::ContainerExited));
        }
        result
    }

    fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
        self.inner.signal(signal, deadline)
    }

    #[cfg(target_os = "linux")]
    fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.launch_pidfd()
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.inner.take_output()
    }

    /// seccomp の listener を内側へ転送する(転送しないと、包み直した後は取り出せず #2025 の応答ハブが
    /// listener を得られない。`take_output` と同じ注意。SEC-4・#2024)。
    #[cfg(target_os = "linux")]
    fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
        self.inner.take_seccomp_listener()
    }

    /// 内側へ転送する。`new` が世代の入出力としてスロットへ移し済みのため、通常は `None`（#4074）。
    #[cfg(target_os = "linux")]
    fn take_stdin(&self) -> Option<ContainerStdin> {
        self.inner.take_stdin()
    }

    /// 内側へ転送する。`new` が世代の入出力としてスロットへ移し済みのため、通常は `None`（CRI-6・#4070・#4074）。
    #[cfg(target_os = "linux")]
    fn take_pty_master(&self) -> Option<fandhe_container_core::exec::PtyMaster> {
        self.inner.take_pty_master()
    }
}

impl Drop for ControlledProcess {
    fn drop(&mut self) {
        // 自分の世代のときだけ空に戻す（再起動後の新しい世代を消さない）。
        self.slot.clear(self.generation);
        self.drain(Some(ControlReason::NoHandle));
    }
}

/// 再 launch の間だけ制御チャネルの accept スレッドを止める口（本番は `server::PausableServer`。試験は偽を渡す）。
pub trait RelaunchPause: Send + Sync {
    /// 止める。`timeout` 内に止まらなければ `Err`（呼び出し側は launch しない）。止まっていれば何もしない。
    fn pause(&self, timeout: Duration) -> Result<(), TraitError>;
    /// 止めたものを作り直す。動いていれば何もしない。
    fn resume(&self) -> Result<(), TraitError>;
}

/// restart の再 launch で得た新しいハンドルを、新しい世代の [`ControlledProcess`] として登録する。
///
/// [`Self::with_pause`] で制御チャネルのサーバを渡すと、再 launch の間だけ accept スレッドを止める（core の本番 launcher は
/// 単一スレッドを要求するため。#2043・SUP-3・CORE-1）。止められなければ内側を呼ばずに `Err`（fail-closed）。
pub struct ControlledRelauncher {
    inner: Arc<dyn Relauncher>,
    slot: SignalSlot,
    pause: Option<Arc<dyn RelaunchPause>>,
    /// 再開に失敗し terminate もできなかった新プロセス（[`Relauncher::take_stranded`] が引き渡す）。
    stranded: Mutex<Vec<LateOrphan>>,
}

/// accept スレッドと exec のガードの停止を待つ上限の合計。内訳は `PausableServer::pause` が分ける: ガードに 3 秒
/// （回収の待ち 2 秒 + 余裕）、accept に残りの 3 秒（接続の読み取り期限 1 秒 + 余裕）。REPAIR-5。
const PAUSE_TIMEOUT: Duration = Duration::from_secs(6);

impl ControlledRelauncher {
    /// `inner` の再 launch の結果を `slot` に登録して返す relauncher を作る。
    pub fn new(inner: Arc<dyn Relauncher>, slot: SignalSlot) -> Self {
        Self {
            inner,
            slot,
            pause: None,
            stranded: Mutex::new(Vec::new()),
        }
    }

    /// 再 launch の間 `server` の accept スレッドを止める。
    #[must_use]
    pub fn with_pause(mut self, server: Arc<dyn RelaunchPause>) -> Self {
        self.pause = Some(server);
        self
    }
}

impl Relauncher for ControlledRelauncher {
    /// 内側の relauncher の時間上限の守り方を転送する（転送しないと `SelfBounded` が `CallerBounded` へ降格し、
    /// 単一スレッドを要求する本番 launcher が拒否される。#1816・#2043）。
    fn launch_mode(&self) -> LaunchMode {
        self.inner.launch_mode()
    }

    fn relaunch(&self, timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let started = Instant::now();
        let Some(server) = &self.pause else {
            let process = self.inner.relaunch(timeout)?;
            return Ok(Box::new(ControlledProcess::new(process, self.slot.clone())));
        };
        if let Err(e) = server.pause(PAUSE_TIMEOUT.min(timeout)) {
            // launch しない。ただし制御チャネルは復旧を試みる（止めたままだと稼働中のコンテナを stop できない）。
            // 止まらなかったガードはプールに残り、次の pause が再び join する。失敗は fail-closed のまま
            // （再 launch の失敗として Stopped へ向かう）。
            let _ = server.resume();
            return Err(e);
        }
        // 停止に使った時間を差し引いた残りを内側へ渡す。残りが無ければ launch しない。
        let remaining = timeout.saturating_sub(started.elapsed());
        let result = if remaining.is_zero() {
            Err(TraitError::new(ErrorCode::Timeout, "relaunch timed out"))
        } else {
            self.inner.relaunch(remaining)
        };
        // launch の成否に関わらず再開する。再開できないときは新プロセスを動かしたままにせず失敗にする
        // （制御チャネルの無い稼働は stop できない。fail-closed。回収できなければ stranded へ積む）。
        let resumed = server.resume();
        match (result, resumed) {
            (Ok(process), Ok(())) => {
                Ok(Box::new(ControlledProcess::new(process, self.slot.clone())))
            }
            // terminate にも単一の期限の残りだけを渡す（一時停止 + launch + terminate で timeout を超えない）。
            (Ok(process), Err(e)) => {
                match process.terminate(timeout.saturating_sub(started.elapsed())) {
                    Ok(()) => Err(e),
                    Err(t) => {
                        self.stranded
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((process, t.clone()));
                        Err(t)
                    }
                }
            }
            (Err(e), _) => Err(e),
        }
    }

    fn take_stranded(&self) -> Vec<LateOrphan> {
        let mut own =
            std::mem::take(&mut *self.stranded.lock().unwrap_or_else(PoisonError::into_inner));
        own.extend(self.inner.take_stranded());
        own
    }
}

/// 返信を期限つきで待つ（サーバ側の補助。送信期限 + 猶予まで）。
pub fn wait_reply(
    rx: &Receiver<ControlReason>,
    deadline: Instant,
    grace: Duration,
) -> ControlReason {
    let limit = deadline.checked_add(grace).unwrap_or(deadline);
    let remaining = limit.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(reason) => reason,
        Err(RecvTimeoutError::Timeout) => ControlReason::Timeout,
        Err(RecvTimeoutError::Disconnected) => ControlReason::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::run::ExplicitStopState;

    /// 送られたシグナル番号を記録する模擬プロセス。
    struct Fake {
        pid: u32,
        signals: Arc<Mutex<Vec<u8>>>,
        exited: Arc<AtomicBool>,
        output_taken: Arc<AtomicBool>,
        isolation: Option<fandhe_container_core::launch_isolation::LaunchIsolationRecord>,
        /// 起動時 pidfd の代役（実 pidfd である必要はない。複製と寿命の試験用）。
        #[cfg(target_os = "linux")]
        pidfd: Option<std::os::fd::OwnedFd>,
    }

    impl Fake {
        fn new(pid: u32) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>) {
            let signals = Arc::new(Mutex::new(Vec::new()));
            let exited = Arc::new(AtomicBool::new(false));
            (
                Self {
                    pid,
                    signals: Arc::clone(&signals),
                    exited: Arc::clone(&exited),
                    output_taken: Arc::new(AtomicBool::new(false)),
                    isolation: None,
                    #[cfg(target_os = "linux")]
                    pidfd: None,
                },
                signals,
                exited,
            )
        }
    }

    impl LaunchedProcess for Fake {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(self.pid).unwrap()
        }
        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            if self.exited.load(Ordering::SeqCst) {
                return Ok(Some(ProcessExit::Exited(0)));
            }
            std::thread::sleep(timeout.min(Duration::from_millis(5)));
            Ok(None)
        }
        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.exited.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn signal(&self, signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
            if self.exited.load(Ordering::SeqCst) {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "reaped"));
            }
            self.signals.lock().unwrap().push(signal.as_u8());
            Ok(())
        }
        fn launch_isolation(
            &self,
        ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
            self.isolation.as_ref()
        }
        fn take_output(&self) -> Option<ContainerOutput> {
            self.output_taken.store(true, Ordering::SeqCst);
            Some(ContainerOutput::default())
        }
        #[cfg(target_os = "linux")]
        fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
            use std::os::fd::AsFd as _;
            self.pidfd.as_ref().map(|fd| fd.as_fd())
        }
        #[cfg(target_os = "linux")]
        fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
            self.output_taken.store(true, Ordering::SeqCst);
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn fake_with_pidfd(pid: u32) -> Fake {
        let (mut fake, _, _) = Fake::new(pid);
        let file = std::fs::File::open("/dev/null").unwrap();
        fake.pidfd = Some(std::os::fd::OwnedFd::from(file));
        fake
    }

    /// SUP-6・SEC-1・#2626: exec 用の pidfd の複製は `Active` で pid が一致するときだけ渡り、元の fd とは別番号の
    /// close-on-exec の複製である。拒否の理由は状態ごとに固定。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_handover_pidfd_only_for_active_matching_pid() {
        use std::os::fd::AsRawFd as _;
        let slot = SignalSlot::new();
        // 空: NoHandle。
        assert_eq!(
            slot.handover_pidfd(pid(100)).unwrap_err(),
            ControlReason::NoHandle
        );

        let fake = fake_with_pidfd(100);
        let original = fake.pidfd.as_ref().unwrap().as_raw_fd();
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let dup = slot.handover_pidfd(pid(100)).unwrap();
        assert_ne!(dup.as_raw_fd(), original);
        // close-on-exec が付いている（std の複製は F_DUPFD_CLOEXEC）。fdinfo の flags は 8 進で O_CLOEXEC = 0o2000000。
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", dup.as_raw_fd())).unwrap();
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .map(|v| u32::from_str_radix(v.trim(), 8).unwrap())
            .unwrap();
        assert_eq!(flags & 0o2_000_000, 0o2_000_000);
        // pid 不一致。
        assert_eq!(
            slot.handover_pidfd(pid(101)).unwrap_err(),
            ControlReason::PidMismatch
        );
        // 終了を観測したら複製を渡さない（一致は ContainerExited、不一致は PidMismatch）。
        slot.mark_exited(cp.generation);
        assert_eq!(
            slot.handover_pidfd(pid(100)).unwrap_err(),
            ControlReason::ContainerExited
        );
        assert_eq!(
            slot.handover_pidfd(pid(101)).unwrap_err(),
            ControlReason::PidMismatch
        );
        // 内部の複製は落ちている（呼び出し側が持つ Arc だけが残る）。
        assert_eq!(Arc::strong_count(&dup), 1);
        drop(cp);
        assert_eq!(
            slot.handover_pidfd(pid(100)).unwrap_err(),
            ControlReason::NoHandle
        );
    }

    /// SUP-6・SEC-1・#2626: pidfd を持たない起動ハンドル（未対応カーネル等）は `NoHandle`。記録 pid からの縮退はしない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_handover_pidfd_without_launch_pidfd_is_no_handle() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(
            slot.handover_pidfd(pid(100)).unwrap_err(),
            ControlReason::NoHandle
        );
    }

    /// SUP-6・SEC-1・#2626: 再起動で世代が替わったら、新しい世代の複製だけを渡す（古い世代の複製は落ちる）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_handover_pidfd_follows_new_generation() {
        use std::os::fd::AsRawFd as _;
        let slot = SignalSlot::new();
        let old_cp = ControlledProcess::new(Box::new(fake_with_pidfd(100)), slot.clone());
        let old = slot.handover_pidfd(pid(100)).unwrap();
        let new_fake = fake_with_pidfd(200);
        let _new_cp = ControlledProcess::new(Box::new(new_fake), slot.clone());
        drop(old_cp);
        // 古い pid は渡らず、スロットが保持していた古い複製は落ちて呼び出し側の Arc だけが残る。
        assert_eq!(
            slot.handover_pidfd(pid(100)).unwrap_err(),
            ControlReason::PidMismatch
        );
        assert_eq!(Arc::strong_count(&old), 1);
        let new = slot.handover_pidfd(pid(200)).unwrap();
        assert_ne!(new.as_raw_fd(), old.as_raw_fd());
    }

    fn pid(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// 要求を預けて、監視役のつもりで 1 回 `wait` を回し、結果を受け取る。
    fn roundtrip(
        slot: &SignalSlot,
        process: &ControlledProcess,
        p: u32,
        sig: u8,
        deadline: Instant,
    ) -> ControlReason {
        let rx = match slot.submit(
            RequestKind::Signal,
            pid(p),
            Signal::new(sig).unwrap(),
            deadline,
        ) {
            Ok(rx) => rx,
            Err(r) => return r,
        };
        let _ = process.wait(Duration::from_millis(1));
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// SUP-6(#2007): 包み直しは内側の分離の記録をそのまま返す(記録なしの内側では `None`)。
    #[test]
    fn sup6_controlled_process_forwards_launch_isolation() {
        use fandhe_container_core::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let landlock =
            RecordedLandlock::new(0x3f, vec![RecordedRule::new(RecordedTarget::Root, 0x0f)])
                .unwrap();
        let record = LaunchIsolationRecord::from_parts(RootIdentity::new(5, 6), landlock);
        let (mut fake, _, _) = Fake::new(100);
        fake.isolation = Some(record.clone());
        let cp = ControlledProcess::new(Box::new(fake), SignalSlot::new());
        assert!(cp.launch_isolation() == Some(&record));
        let (plain, _, _) = Fake::new(101);
        let cp = ControlledProcess::new(Box::new(plain), SignalSlot::new());
        assert!(cp.launch_isolation().is_none());
    }

    /// SUP-1・SEC-1: 一致する pid の要求だけがシグナル番号つきで内側へ届く。
    #[test]
    fn sup1_sec1_matching_pid_delivers_signal_15() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(roundtrip(&slot, &cp, 100, 15, far()), ControlReason::Ok);
        assert_eq!(*signals.lock().unwrap(), vec![15]);
    }

    /// SUP-1・SEC-1: pid 不一致は送らずに `PidMismatch`。
    #[test]
    fn sup1_sec1_pid_mismatch_does_not_signal() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(
            roundtrip(&slot, &cp, 101, 15, far()),
            ControlReason::PidMismatch
        );
        assert!(signals.lock().unwrap().is_empty());
    }

    /// REPAIR-5・SEC-1: 期限切れの要求は後から処理しても送らない。
    #[test]
    fn repair5_sec1_expired_request_is_not_delivered() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let deadline = Instant::now() + Duration::from_millis(20);
        let rx = slot
            .submit(RequestKind::Signal, pid(100), Signal::SIGTERM, deadline)
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _ = cp.wait(Duration::from_millis(1));
        assert_eq!(rx.recv().unwrap(), ControlReason::Timeout);
        assert!(signals.lock().unwrap().is_empty());
    }

    /// SUP-1: 終了後は `ContainerExited`、`Drop` の後は `NoHandle`、ハンドル登録前も `NoHandle`。
    #[test]
    fn sup1_exited_then_dropped_then_empty() {
        let slot = SignalSlot::new();
        assert_eq!(
            slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::NoHandle
        );
        let (fake, signals, exited) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        // 受け箱に要求が残ったまま終了を検知したら、送らずに ContainerExited を返す。
        let rx = slot
            .submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
            .unwrap();
        exited.store(true, Ordering::SeqCst);
        assert!(cp.wait(Duration::from_millis(1)).unwrap().is_some());
        // drain(None) が先に走るが、模擬は終了済みなら FailedPrecondition を返すので同じ結果になる。
        assert_eq!(rx.recv().unwrap(), ControlReason::ContainerExited);
        assert!(signals.lock().unwrap().is_empty());
        assert_eq!(
            slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::ContainerExited
        );
        drop(cp);
        assert_eq!(
            slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::NoHandle
        );
    }

    /// SEC-1: 古い世代の `Drop` は、再起動後の新しい世代を空に戻さない。
    #[test]
    fn sec1_old_generation_drop_keeps_new_generation() {
        let slot = SignalSlot::new();
        let (old, _, _) = Fake::new(100);
        let old_cp = ControlledProcess::new(Box::new(old), slot.clone());
        let (new, signals, _) = Fake::new(200);
        let new_cp = ControlledProcess::new(Box::new(new), slot.clone());
        drop(old_cp);
        assert_eq!(roundtrip(&slot, &new_cp, 200, 2, far()), ControlReason::Ok);
        assert_eq!(*signals.lock().unwrap(), vec![2]);
        // 古い pid へは届かない。
        assert_eq!(
            slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::PidMismatch
        );
    }

    /// 受け箱が満杯なら `Busy`。
    #[test]
    fn sup1_full_inbox_is_busy() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let mut held = Vec::new();
        for _ in 0..INBOX_CAPACITY {
            held.push(
                slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                    .unwrap(),
            );
        }
        assert_eq!(
            slot.submit(RequestKind::Signal, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::Busy
        );
    }

    /// SEC-4・#2024: `take_seccomp_listener` が内側へ転送される(転送を忘れると包み直した後に listener を取れない)。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2024_take_seccomp_listener_is_forwarded() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let called = Arc::clone(&fake.output_taken);
        let cp = ControlledProcess::new(Box::new(fake), slot);
        assert!(cp.take_seccomp_listener().is_none());
        assert!(
            called.load(Ordering::SeqCst),
            "the inner process was not asked"
        );
    }

    /// `take_output` が内側へ転送される（ログ捕捉に必須。#1471）。
    #[test]
    fn sup1_take_output_is_forwarded() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let taken = Arc::clone(&fake.output_taken);
        let cp = ControlledProcess::new(Box::new(fake), slot);
        assert!(cp.take_output().is_some());
        assert!(taken.load(Ordering::SeqCst));
    }

    /// 送られたシグナルの時点の意図フラグを記録する模擬（順序の照合用）。
    struct IntentProbe {
        token: StopToken,
        seen: Arc<Mutex<Vec<bool>>>,
        outcome: ErrorCode,
        fail: bool,
    }

    impl LaunchedProcess for IntentProbe {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(100).unwrap()
        }
        fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            Ok(())
        }
        fn signal(&self, _signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
            self.seen
                .lock()
                .unwrap()
                .push(self.token.explicit_stop_state() == ExplicitStopState::Requested);
            if self.fail {
                Err(TraitError::new(self.outcome, "x"))
            } else {
                Ok(())
            }
        }
    }

    type Probe = (
        SignalSlot,
        ControlledProcess,
        StopToken,
        Arc<Mutex<Vec<bool>>>,
    );

    fn probe_setup(fail: bool, outcome: ErrorCode) -> Probe {
        let token = StopToken::new();
        let slot = SignalSlot::with_stop_intent(token.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let probe = IntentProbe {
            token: token.clone(),
            seen: Arc::clone(&seen),
            outcome,
            fail,
        };
        let cp = ControlledProcess::new(Box::new(probe), slot.clone());
        (slot, cp, token, seen)
    }

    fn stop_roundtrip(slot: &SignalSlot, cp: &ControlledProcess) -> ControlReason {
        let rx = match slot.submit(RequestKind::Stop, pid(100), Signal::SIGTERM, far()) {
            Ok(rx) => rx,
            Err(r) => return r,
        };
        let _ = cp.wait(Duration::from_millis(1));
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// SUP-9: Stop は、シグナルを送る時点で意図が立っている（順序）。停止要求（監視の打ち切り）は立たない。
    #[test]
    fn sup9_stop_marks_intent_before_signal() {
        let (slot, cp, token, seen) = probe_setup(false, ErrorCode::Internal);
        assert_eq!(stop_roundtrip(&slot, &cp), ControlReason::Ok);
        assert_eq!(*seen.lock().unwrap(), vec![true]);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::Requested);
        assert!(!token.is_stop_requested());
    }

    /// SUP-9: Signal 要求は意図を立てない。
    #[test]
    fn sup9_signal_request_does_not_mark_intent() {
        let (slot, cp, token, seen) = probe_setup(false, ErrorCode::Internal);
        assert_eq!(roundtrip(&slot, &cp, 100, 15, far()), ControlReason::Ok);
        assert_eq!(*seen.lock().unwrap(), vec![false]);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
    }

    /// SUP-9: 書き先の無い slot の Stop は、送らずに `StopIntentUnavailable`（fail-closed）。
    #[test]
    fn sup9_stop_without_intent_sink_is_refused() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(
            slot.submit(RequestKind::Stop, pid(100), Signal::SIGTERM, far())
                .unwrap_err(),
            ControlReason::StopIntentUnavailable
        );
        let _ = cp.wait(Duration::from_millis(1));
        assert!(signals.lock().unwrap().is_empty());
    }

    /// SUP-9: 送信が失敗したら、この要求で立てた意図を戻す。
    #[test]
    fn sup9_failed_signal_reverts_intent() {
        let (slot, cp, token, _) = probe_setup(true, ErrorCode::Internal);
        assert_eq!(stop_roundtrip(&slot, &cp), ControlReason::SignalFailed);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
    }

    /// SUP-9: 先に別の stop が立てた意図は、後の stop の失敗で消さない。
    #[test]
    fn sup9_failed_signal_keeps_prior_intent() {
        let (slot, cp, token, _) = probe_setup(true, ErrorCode::Timeout);
        token.mark_explicit_stop();
        assert_eq!(stop_roundtrip(&slot, &cp), ControlReason::Timeout);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::Requested);
    }

    /// SUP-9・REPAIR-5: 期限切れの Stop は意図を立てず、送らない。
    #[test]
    fn sup9_expired_stop_does_not_mark_intent() {
        let (slot, cp, token, seen) = probe_setup(false, ErrorCode::Internal);
        let deadline = Instant::now() + Duration::from_millis(20);
        let rx = slot
            .submit(RequestKind::Stop, pid(100), Signal::SIGTERM, deadline)
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _ = cp.wait(Duration::from_millis(1));
        assert_eq!(rx.recv().unwrap(), ControlReason::Timeout);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
        assert!(seen.lock().unwrap().is_empty());
    }

    /// SUP-9: 回収済み（FailedPrecondition）の Stop は意図を残す（止めたい対象はもう終わっている）。
    #[test]
    fn sup9_reaped_stop_keeps_intent() {
        let (slot, cp, token, _) = probe_setup(true, ErrorCode::FailedPrecondition);
        assert_eq!(stop_roundtrip(&slot, &cp), ControlReason::ContainerExited);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::Requested);
    }

    /// SUP-9: 終了を観測した `wait` の後始末で返す `ContainerExited` の Stop でも、意図を記録する。
    #[test]
    fn sup9_stop_answered_container_exited_in_drain_marks_intent() {
        let (slot, cp, token, _) = probe_setup(false, ErrorCode::Internal);
        let rx = slot
            .submit(RequestKind::Stop, pid(100), Signal::SIGTERM, far())
            .unwrap();
        slot.mark_exited(cp.generation);
        cp.drain(Some(ControlReason::ContainerExited));
        assert_eq!(rx.recv().unwrap(), ControlReason::ContainerExited);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::Requested);
    }

    /// SUP-9: `Exited` スロットへの Stop の submit は意図を立てない（再 launch 後の新インスタンスの restart を
    /// 無効化しないため。#2162）。Signal も立てない。
    #[test]
    fn sup9_stop_submit_to_exited_slot_does_not_mark_intent() {
        let (slot, cp, token, _) = probe_setup(false, ErrorCode::Internal);
        slot.mark_exited(cp.generation);
        for kind in [RequestKind::Signal, RequestKind::Stop] {
            assert_eq!(
                slot.submit(kind, pid(100), Signal::SIGTERM, far())
                    .unwrap_err(),
                ControlReason::ContainerExited
            );
            assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
        }
    }

    /// SUP-9・SUP-3・#2440: 取り消しは `Exited`（終了済みで再起動が保留中）でだけ意図を立てて `Ok`。
    #[test]
    fn sup9_cancel_pending_restart_marks_intent_only_when_exited() {
        let (slot, cp, token, seen) = probe_setup(false, ErrorCode::Internal);
        // Active: 稼働中の restart を外させない。意図は立たず、シグナルも送られない。
        assert_eq!(
            slot.cancel_pending_restart(far()),
            ControlReason::ContainerRunning
        );
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
        assert!(seen.lock().unwrap().is_empty());
        // Exited: 意図が立つ。stop_requested（監視の打ち切り）は立たない。冪等。
        slot.mark_exited(cp.generation);
        assert_eq!(slot.cancel_pending_restart(far()), ControlReason::Ok);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::Requested);
        assert!(!token.is_stop_requested());
        assert_eq!(slot.cancel_pending_restart(far()), ControlReason::Ok);
        assert!(seen.lock().unwrap().is_empty());
    }

    /// SUP-9・#2440: 取り消しの拒否（ハンドルなし・書き先なし・期限切れ）は意図を立てない。
    #[test]
    fn sup9_cancel_pending_restart_rejections_do_not_mark_intent() {
        let token = StopToken::new();
        let slot = SignalSlot::with_stop_intent(token.clone());
        assert_eq!(slot.cancel_pending_restart(far()), ControlReason::NoHandle);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);

        let (slot, cp, token, _) = probe_setup(false, ErrorCode::Internal);
        slot.mark_exited(cp.generation);
        assert_eq!(
            slot.cancel_pending_restart(Instant::now()),
            ControlReason::Timeout
        );
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);

        // 書き先の無いスロット（意図を記録できない supervisor）は fail-closed。
        let slot = SignalSlot::new();
        assert_eq!(
            slot.cancel_pending_restart(far()),
            ControlReason::StopIntentUnavailable
        );
    }

    /// SUP-9・REPAIR-5: 終了観測後の drain で、期限切れの Stop は Timeout で断り意図を立てない。
    #[test]
    fn sup9_expired_stop_in_drain_after_exit_does_not_mark_intent() {
        let (slot, cp, token, _) = probe_setup(false, ErrorCode::Internal);
        let deadline = Instant::now() + Duration::from_millis(20);
        let rx = slot
            .submit(RequestKind::Stop, pid(100), Signal::SIGTERM, deadline)
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        slot.mark_exited(cp.generation);
        cp.drain(Some(ControlReason::ContainerExited));
        assert_eq!(rx.recv().unwrap(), ControlReason::Timeout);
        assert_eq!(token.explicit_stop_state(), ExplicitStopState::NotRequested);
    }

    /// 呼ばれた順を記録する、`pause` / `resume` と内側の relaunch の偽。
    struct OrderFake {
        events: Arc<Mutex<Vec<&'static str>>>,
        pause_fails: bool,
        relaunch_fails: bool,
        mode: LaunchMode,
        timeouts: Mutex<Vec<Duration>>,
        resume_fails: bool,
        /// 内側が返したプロセスの `terminate` に渡された時間上限。
        terminated: Arc<Mutex<Vec<Duration>>>,
        /// `relaunch` が返る前に待つ時間（launch の所要時間の模擬）。
        launch_delay: Duration,
    }

    /// `terminate` に渡された上限を記録するプロセスの偽。
    struct TermProbe(Arc<Mutex<Vec<Duration>>>);

    impl LaunchedProcess for TermProbe {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(778).unwrap()
        }
        fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
            self.0.lock().unwrap().push(timeout);
            Ok(())
        }
        fn signal(&self, _signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
            Ok(())
        }
    }

    impl RelaunchPause for OrderFake {
        fn pause(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.events.lock().unwrap().push("pause");
            if self.pause_fails {
                return Err(TraitError::new(ErrorCode::Timeout, "pause failed"));
            }
            Ok(())
        }
        fn resume(&self) -> Result<(), TraitError> {
            self.events.lock().unwrap().push("resume");
            if self.resume_fails {
                return Err(TraitError::new(ErrorCode::Unavailable, "resume failed"));
            }
            Ok(())
        }
    }

    impl Relauncher for OrderFake {
        fn launch_mode(&self) -> LaunchMode {
            self.mode
        }
        fn relaunch(&self, timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.events.lock().unwrap().push("relaunch");
            self.timeouts.lock().unwrap().push(timeout);
            std::thread::sleep(self.launch_delay);
            if self.relaunch_fails {
                return Err(TraitError::new(ErrorCode::Internal, "relaunch failed"));
            }
            if self.resume_fails {
                return Ok(Box::new(TermProbe(self.terminated.clone())));
            }
            Ok(Box::new(Fake::new(777).0))
        }
    }

    fn order_fake(pause_fails: bool, relaunch_fails: bool) -> Arc<OrderFake> {
        Arc::new(OrderFake {
            events: Arc::new(Mutex::new(Vec::new())),
            pause_fails,
            relaunch_fails,
            mode: LaunchMode::SelfBounded,
            timeouts: Mutex::new(Vec::new()),
            resume_fails: false,
            terminated: Arc::new(Mutex::new(Vec::new())),
            launch_delay: Duration::ZERO,
        })
    }

    /// SUP-3・CORE-1・#2043: 再 launch は「止める → 内側の relaunch → 再開」の順で、`launch_mode` を内側から転送し、
    /// 止めるのに使った時間を差し引いた残りだけを内側へ渡す(0 を超え、元の上限以下)。
    #[test]
    fn sup3_2043_controlled_relauncher_pauses_around_relaunch_and_forwards_mode() {
        let fake = order_fake(false, false);
        let r = ControlledRelauncher::new(fake.clone(), SignalSlot::new())
            .with_pause(fake.clone() as Arc<dyn RelaunchPause>);
        assert_eq!(r.launch_mode(), LaunchMode::SelfBounded);
        let process = r.relaunch(Duration::from_secs(5)).expect("relaunched");
        assert_eq!(process.pid().get(), 777);
        assert_eq!(
            *fake.events.lock().unwrap(),
            vec!["pause", "relaunch", "resume"]
        );
        let passed = fake.timeouts.lock().unwrap()[0];
        assert!(passed > Duration::ZERO && passed <= Duration::from_secs(5));
    }

    /// SUP-3・REPAIR-5・#2043: 止められなければ内側を呼ばずに失敗する(fail-closed)。制御チャネルの復旧(resume)は試みる。
    #[test]
    fn sup3_2043_pause_failure_does_not_relaunch() {
        let fake = order_fake(true, false);
        let r = ControlledRelauncher::new(fake.clone(), SignalSlot::new())
            .with_pause(fake.clone() as Arc<dyn RelaunchPause>);
        let err = r.relaunch(Duration::from_secs(5)).err().expect("fails");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(*fake.events.lock().unwrap(), vec!["pause", "resume"]);
    }

    /// SUP-3・#2043: 内側の relaunch が失敗しても制御チャネルを再開する。
    #[test]
    fn sup3_2043_relaunch_failure_still_resumes() {
        let fake = order_fake(false, true);
        let r = ControlledRelauncher::new(fake.clone(), SignalSlot::new())
            .with_pause(fake.clone() as Arc<dyn RelaunchPause>);
        let err = r.relaunch(Duration::from_secs(5)).err().expect("fails");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            *fake.events.lock().unwrap(),
            vec!["pause", "relaunch", "resume"]
        );
    }

    /// REPAIR-5・SUP-3・#2043: 再開に失敗して新プロセスを terminate するときも、残りの時間だけを渡し、
    /// 一時停止 + launch + terminate の全体が元の `timeout` を超えない。
    #[test]
    fn repair5_2043_terminate_after_resume_failure_gets_remaining_time_only() {
        let fake = Arc::new(OrderFake {
            events: Arc::new(Mutex::new(Vec::new())),
            pause_fails: false,
            relaunch_fails: false,
            mode: LaunchMode::SelfBounded,
            timeouts: Mutex::new(Vec::new()),
            resume_fails: true,
            terminated: Arc::new(Mutex::new(Vec::new())),
            launch_delay: Duration::from_millis(300),
        });
        let r = ControlledRelauncher::new(fake.clone(), SignalSlot::new())
            .with_pause(fake.clone() as Arc<dyn RelaunchPause>);
        let total = Duration::from_secs(5);
        let err = r.relaunch(total).err().expect("fails");
        assert_eq!(err.code(), ErrorCode::Unavailable);
        let term = fake.terminated.lock().unwrap()[0];
        // launch に使った 300ms 以上が差し引かれている。
        assert!(term <= total - Duration::from_millis(300), "{term:?}");
        assert!(term > Duration::ZERO);
    }

    /// 閉じられた（drop された）回数を数え、`dead` が真なら相手が閉じたものとして報告する偽の購読。
    struct FakeWatch {
        closed: Arc<std::sync::atomic::AtomicUsize>,
        dead: Arc<AtomicBool>,
    }

    impl ExitWatchHandle for FakeWatch {
        fn is_dead(&mut self) -> bool {
            self.dead.load(Ordering::SeqCst)
        }
    }

    impl Drop for FakeWatch {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn watch(
        closed: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> (Box<dyn ExitWatchHandle>, Arc<AtomicBool>) {
        let dead = Arc::new(AtomicBool::new(false));
        (
            Box::new(FakeWatch {
                closed: Arc::clone(closed),
                dead: Arc::clone(&dead),
            }),
            dead,
        )
    }

    /// SUP-1・CRI-1・#3683: 購読は `Active` で pid が一致するときだけ預かり、拒否では接続を drop する。
    #[test]
    fn sup1_3683_watch_exit_accepts_only_active_matching_pid() {
        let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slot = SignalSlot::new();
        let hold = Duration::from_secs(5);
        let (h, _) = watch(&closed);
        assert_eq!(slot.watch_exit(pid(100), h, hold), ControlReason::NoHandle);
        let (fake, _, exited) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(101), h, hold),
            ControlReason::PidMismatch
        );
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        let (h, _) = watch(&closed);
        assert_eq!(slot.watch_exit(pid(100), h, hold), ControlReason::Ok);
        assert_eq!(slot.exit_watcher_count(), 1);
        // 終了の観測で購読は閉じられ、以後は ContainerExited / PidMismatch。
        exited.store(true, Ordering::SeqCst);
        assert!(cp.wait(Duration::from_millis(1)).unwrap().is_some());
        assert_eq!(slot.exit_watcher_count(), 0);
        assert_eq!(closed.load(Ordering::SeqCst), 3);
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(100), h, hold),
            ControlReason::ContainerExited
        );
        let (h, _) = watch(&closed);
        assert_eq!(slot.watch_exit(pid(7), h, hold), ControlReason::PidMismatch);
    }

    /// REPAIR-5・#3683: 預かる購読は 8 件まで。9 件目は `Busy`、相手が閉じたものを整理すると空く。
    #[test]
    fn repair5_3683_watchers_are_bounded_and_dead_ones_pruned() {
        let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let mut deads = Vec::new();
        for _ in 0..DEFAULT_MAX_EXIT_WATCHERS {
            let (h, dead) = watch(&closed);
            assert_eq!(
                slot.watch_exit(pid(100), h, Duration::from_secs(5)),
                ControlReason::Ok
            );
            deads.push(dead);
        }
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(100), h, Duration::from_secs(5)),
            ControlReason::Busy
        );
        deads[0].store(true, Ordering::SeqCst);
        slot.prune_exit_watchers(Instant::now());
        assert_eq!(slot.exit_watcher_count(), DEFAULT_MAX_EXIT_WATCHERS - 1);
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(100), h, Duration::from_secs(5)),
            ControlReason::Ok
        );
    }

    /// REPAIR-5・#3683: 保持期限 + 猶予を過ぎた購読は整理で閉じられる。
    #[test]
    fn repair5_3683_expired_watcher_is_pruned() {
        let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(100), h, Duration::from_millis(10)),
            ControlReason::Ok
        );
        slot.prune_exit_watchers(Instant::now());
        assert_eq!(slot.exit_watcher_count(), 1);
        slot.prune_exit_watchers(
            Instant::now() + Duration::from_millis(10) + EXIT_WATCH_PRUNE_GRACE,
        );
        assert_eq!(slot.exit_watcher_count(), 0);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }

    /// SUP-1・#3683: `ControlledProcess` の drop（clear）と世代交代（register）でも購読が閉じる。
    #[test]
    fn sup1_3683_watchers_closed_on_clear_and_new_generation() {
        let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(100), h, Duration::from_secs(5)),
            ControlReason::Ok
        );
        // 世代交代: 旧世代の購読は閉じる（新しい世代の購読は残る）。
        let (fake2, _, _) = Fake::new(200);
        let cp2 = ControlledProcess::new(Box::new(fake2), slot.clone());
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        let (h, _) = watch(&closed);
        assert_eq!(
            slot.watch_exit(pid(200), h, Duration::from_secs(5)),
            ControlReason::Ok
        );
        // 旧世代の drop は新世代の購読に触れない。
        drop(cp);
        assert_eq!(slot.exit_watcher_count(), 1);
        drop(cp2);
        assert_eq!(slot.exit_watcher_count(), 0);
        assert_eq!(closed.load(Ordering::SeqCst), 2);
    }

    // ---- 世代ごとの入出力（SUP-7・SUP-3・CRI-6・#4074）----

    /// stdin の書き込み端と終了の観測を操作できる世代の偽。
    #[cfg(target_os = "linux")]
    struct GenFake {
        pid: NonZeroU32,
        stdin: Mutex<Option<ContainerStdin>>,
        exited: Arc<AtomicBool>,
    }

    #[cfg(target_os = "linux")]
    impl LaunchedProcess for GenFake {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(self
                .exited
                .load(Ordering::SeqCst)
                .then_some(ProcessExit::Exited(0)))
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
        fn take_stdin(&self) -> Option<ContainerStdin> {
            self.stdin.lock().unwrap().take()
        }
    }

    /// 世代の偽と、その stdin の読み取り側・終了フラグを作る。
    #[cfg(target_os = "linux")]
    fn gen_fake(pid: u32) -> (GenFake, std::io::PipeReader, Arc<AtomicBool>) {
        let (r, w) = std::io::pipe().unwrap();
        let exited = Arc::new(AtomicBool::new(false));
        (
            GenFake {
                pid: NonZeroU32::new(pid).unwrap(),
                stdin: Mutex::new(Some(ContainerStdin::from_pipe_writer_for_test(w))),
                exited: exited.clone(),
            },
            r,
            exited,
        )
    }

    /// 世代の偽を順に返す relauncher。
    #[cfg(target_os = "linux")]
    struct QueueRelauncher(Mutex<Vec<Box<dyn LaunchedProcess>>>);

    #[cfg(target_os = "linux")]
    impl Relauncher for QueueRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            let mut q = self.0.lock().unwrap();
            if q.is_empty() {
                return Err(TraitError::new(ErrorCode::Internal, "empty"));
            }
            Ok(q.remove(0))
        }
    }

    /// 読み取り側から、いま読める分を読む（書き込み端が全て閉じていれば EOF の `0`）。
    #[cfg(target_os = "linux")]
    fn read_some(r: &mut std::io::PipeReader) -> Vec<u8> {
        use std::io::Read;
        let mut buf = [0u8; 16];
        let n = r.read(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    /// SUP-7・SUP-3・#4074（受け入れ基準）: 世代の stdin は `Exited` で閉じ、再 launch の登録で新しい世代の fd に差し替わり、
    /// 古い世代の端は閉じたまま。`Drop` で最後の世代も閉じる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_sup3_4074_generation_io_replaced_on_relaunch() {
        use std::io::Write;
        let slot = SignalSlot::new();
        let (g1, mut r1, exited1) = gen_fake(100);
        let cp1 = ControlledProcess::new(Box::new(g1), slot.clone());
        // 世代の入出力へ移った後は、ハンドル経由では取り出せない。
        assert!(cp1.take_stdin().is_none());
        slot.with_generation_io(pid(100), |io| {
            io.stdin.as_mut().unwrap().write_all(b"g1").unwrap();
        })
        .unwrap();
        assert_eq!(read_some(&mut r1), b"g1");
        // 終了を観測すると `Exited` になり、第 1 世代の stdin は EOF になる。
        exited1.store(true, Ordering::SeqCst);
        assert!(matches!(
            cp1.wait(Duration::from_millis(1)),
            Ok(Some(ProcessExit::Exited(0)))
        ));
        assert_eq!(read_some(&mut r1), b"");
        assert_eq!(
            slot.with_generation_io(pid(100), |_| ()).unwrap_err(),
            ControlReason::ContainerExited
        );
        // 再 launch: 第 2 世代の登録で第 2 世代の fd に差し替わる。
        let (g2, mut r2, _) = gen_fake(200);
        let relauncher = ControlledRelauncher::new(
            Arc::new(QueueRelauncher(Mutex::new(vec![Box::new(g2)]))),
            slot.clone(),
        );
        let cp2 = relauncher.relaunch(Duration::from_secs(1)).unwrap();
        slot.with_generation_io(pid(200), |io| {
            io.stdin.as_mut().unwrap().write_all(b"g2").unwrap();
        })
        .unwrap();
        assert_eq!(read_some(&mut r2), b"g2");
        // 古い世代の端は閉じたまま（新しい世代に残らない）。古い pid は一致しない。
        assert_eq!(read_some(&mut r1), b"");
        assert_eq!(
            slot.with_generation_io(pid(100), |_| ()).unwrap_err(),
            ControlReason::PidMismatch
        );
        // 古い世代のハンドルの drop は新しい世代の入出力に触れない。
        drop(cp1);
        slot.with_generation_io(pid(200), |io| assert!(io.stdin.is_some()))
            .unwrap();
        // 最後の世代の drop で閉じる。
        drop(cp2);
        assert_eq!(read_some(&mut r2), b"");
        assert_eq!(
            slot.with_generation_io(pid(200), |_| ()).unwrap_err(),
            ControlReason::NoHandle
        );
    }

    /// CRI-6・#4074: tty の master の複製も同じ世代の寿命に従う（`Exited` で閉じる）。
    #[cfg(target_os = "linux")]
    #[test]
    fn cri6_4074_generation_master_closed_on_exit() {
        use fandhe_container_core::exec::{WindowSize, open_host_pty_for_test};
        struct TtyFake {
            master: Mutex<Option<PtyMaster>>,
            exited: Arc<AtomicBool>,
        }
        impl LaunchedProcess for TtyFake {
            fn pid(&self) -> NonZeroU32 {
                NonZeroU32::new(300).unwrap()
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                Ok(self
                    .exited
                    .load(Ordering::SeqCst)
                    .then_some(ProcessExit::Exited(0)))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
            fn take_pty_master(&self) -> Option<PtyMaster> {
                self.master.lock().unwrap().take()
            }
        }
        let (master, slave) = open_host_pty_for_test(WindowSize::new(24, 80)).unwrap();
        // slave 側から見た master の開き数は、master の複製が閉じると EIO（全閉鎖）として観測できないため、
        // 複製した fd の参照を弱く保つ代わりに、master 側の fd を別に複製して読む。
        let observer = std::fs::File::from(master.as_fd().try_clone_to_owned().unwrap());
        let exited = Arc::new(AtomicBool::new(false));
        let slot = SignalSlot::new();
        let cp = ControlledProcess::new(
            Box::new(TtyFake {
                master: Mutex::new(Some(master)),
                exited: exited.clone(),
            }),
            slot.clone(),
        );
        assert!(cp.take_pty_master().is_none());
        slot.with_generation_io(pid(300), |io| assert!(io.master.is_some()))
            .unwrap();
        exited.store(true, Ordering::SeqCst);
        assert!(matches!(
            cp.wait(Duration::from_millis(1)),
            Ok(Some(ProcessExit::Exited(0)))
        ));
        slot.with_generation_io(pid(300), |_| ()).unwrap_err();
        // 保持分は閉じた。観測用の複製だけが master を保つ。
        drop(observer);
        drop(slave);
    }

    /// SUP-7・CRI-6・#4074: `--stdin` の指定は世代交代をまたいで保たれる。
    #[test]
    fn sup7_cri6_4074_stdin_option_survives_generations() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Once));
        assert_eq!(slot.stdin_option(), Some(StdinOption::Once));
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let (fake2, _, _) = Fake::new(200);
        let _cp2 = ControlledProcess::new(Box::new(fake2), slot.clone());
        assert_eq!(slot.stdin_option(), Some(StdinOption::Once));
        assert_eq!(SignalSlot::new().stdin_option(), None);
    }

    /// 取り出した入力の端へ書いたバイト列が、読み取り側へ届く（具体値）。
    #[cfg(target_os = "linux")]
    fn write_via(input: &TakenInput, bytes: &[u8]) {
        use std::io::Write;
        let fd = std::os::fd::AsFd::as_fd(input)
            .try_clone_to_owned()
            .unwrap();
        let mut f = std::fs::File::from(fd);
        f.write_all(bytes).unwrap();
    }

    /// SUP-4・SUP-7・SEC-1・#4075: `--stdin open` は毎回複製を返し、スロットは元の端を持ち続ける。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sup7_4075_attach_open_returns_dup_each_time() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Open));
        let (g, mut r, _) = gen_fake(100);
        let _cp = ControlledProcess::new(Box::new(g), slot.clone());
        for text in [&b"a"[..], b"b"] {
            let taken = slot.take_attach_input(pid(100), false, true).unwrap();
            let input = taken.input.unwrap();
            assert!(matches!(input, TakenInput::Dup(_)));
            write_via(&input, text);
            drop(input);
            assert_eq!(read_some(&mut r), text);
        }
        slot.with_generation_io(pid(100), |io| {
            assert!(io.stdin.is_some());
            assert!(!io.stdin_consumed);
        })
        .unwrap();
    }

    /// SUP-4・SUP-7・SEC-1・#4075: `--stdin once` は 1 回目で元の端を渡し、2 回目は `StdinClosed`。
    /// 受け手が端を閉じるとコンテナ側が EOF になる（スロットは端を持たない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sup7_4075_attach_once_moves_ownership() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Once));
        let (g, mut r, _) = gen_fake(100);
        let _cp = ControlledProcess::new(Box::new(g), slot.clone());
        let taken = slot.take_attach_input(pid(100), false, true).unwrap();
        let input = taken.input.unwrap();
        assert!(matches!(input, TakenInput::Once(_)));
        slot.with_generation_io(pid(100), |io| {
            assert!(io.stdin.is_none());
            assert!(io.stdin_consumed);
        })
        .unwrap();
        write_via(&input, b"x");
        assert_eq!(read_some(&mut r), b"x");
        assert_eq!(
            slot.take_attach_input(pid(100), false, true).unwrap_err(),
            ControlReason::StdinClosed
        );
        assert_eq!(
            slot.check_attach(pid(100), false, true).unwrap_err(),
            ControlReason::StdinClosed
        );
        // 受け手が閉じると唯一の書き込み端が無くなり、読み取り側は EOF。
        drop(input);
        assert_eq!(read_some(&mut r), b"");
    }

    /// SUP-4・SUP-7・#4075: `--stdin` が無ければ入力は `StdinNotOpen`。出力だけの要求は通る。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sup7_4075_attach_without_stdin_option() {
        let slot = SignalSlot::new();
        let (g, _r, _) = gen_fake(100);
        let _cp = ControlledProcess::new(Box::new(g), slot.clone());
        assert_eq!(
            slot.take_attach_input(pid(100), false, true).unwrap_err(),
            ControlReason::StdinNotOpen
        );
        let taken = slot.take_attach_input(pid(100), false, false).unwrap();
        assert!(taken.input.is_none());
    }

    /// SUP-4・SEC-1・#4075: 状態と pid の照合（`Empty`・pid 不一致・`Exited`）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sec1_4075_attach_state_checks() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Open));
        assert_eq!(
            slot.check_attach(pid(100), false, true).unwrap_err(),
            ControlReason::NoHandle
        );
        let (g, _r, exited) = gen_fake(100);
        let cp = ControlledProcess::new(Box::new(g), slot.clone());
        assert_eq!(
            slot.check_attach(pid(101), false, true).unwrap_err(),
            ControlReason::PidMismatch
        );
        exited.store(true, Ordering::SeqCst);
        let _ = cp.wait(Duration::from_millis(1));
        assert_eq!(
            slot.take_attach_input(pid(100), false, true).unwrap_err(),
            ControlReason::ContainerExited
        );
    }

    /// SUP-4・SEC-1・#4075: 要求の tty と構成の不一致。非 tty のコンテナへ tty 要求は `TtyMismatch`（stdin があるため）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sec1_4075_attach_tty_mismatch() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Open));
        let (g, _r, _) = gen_fake(100);
        let _cp = ControlledProcess::new(Box::new(g), slot.clone());
        assert_eq!(
            slot.check_attach(pid(100), true, true).unwrap_err(),
            ControlReason::TtyMismatch
        );
    }

    /// SUP-4・SUP-7・#4075: `restore_stdin_once` は同じ世代でだけ端を戻し、消費済みを取り消す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_sup7_4075_restore_stdin_once_same_generation_only() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Once));
        let (g, mut r, _) = gen_fake(100);
        let _cp = ControlledProcess::new(Box::new(g), slot.clone());
        let taken = slot.take_attach_input(pid(100), false, true).unwrap();
        let Some(TakenInput::Once(stdin)) = taken.input else {
            panic!("expected Once");
        };
        slot.restore_stdin_once(taken.generation, stdin);
        slot.with_generation_io(pid(100), |io| {
            assert!(io.stdin.is_some());
            assert!(!io.stdin_consumed);
        })
        .unwrap();
        // 戻した後は再び取り出せる。
        let again = slot.take_attach_input(pid(100), false, true).unwrap();
        let Some(TakenInput::Once(stdin)) = again.input else {
            panic!("expected Once");
        };
        // 世代が変わった後は戻らない（drop で閉じる = コンテナ側の旧世代の端は EOF）。
        let (g2, _r2, _) = gen_fake(200);
        let _cp2 = ControlledProcess::new(Box::new(g2), slot.clone());
        slot.restore_stdin_once(again.generation, stdin);
        slot.with_generation_io(pid(200), |io| {
            assert!(io.stdin.is_some());
            assert!(!io.stdin_consumed);
        })
        .unwrap();
        assert_eq!(read_some(&mut r), b"");
    }

    /// SUP-7・CRI-6・#4075: 再 launch すると `stdin_consumed` が世代ごとに初期化される。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_cri6_4075_stdin_consumed_resets_per_generation() {
        let slot = SignalSlot::new().with_stdin_option(Some(StdinOption::Once));
        let (g1, _r1, _) = gen_fake(100);
        let _cp1 = ControlledProcess::new(Box::new(g1), slot.clone());
        slot.take_attach_input(pid(100), false, true).unwrap();
        assert_eq!(
            slot.check_attach(pid(100), false, true).unwrap_err(),
            ControlReason::StdinClosed
        );
        let (g2, _r2, _) = gen_fake(200);
        let _cp2 = ControlledProcess::new(Box::new(g2), slot.clone());
        slot.check_attach(pid(200), false, true).unwrap();
    }
}
