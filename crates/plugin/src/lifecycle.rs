//! plugin プロセスの都度起動モード（PLUG-7・TASK-110.1・#258）と、子モジュール `resident` の常駐モード
//! （TASK-110.2・#259。起動仕様 [`PluginLaunchSpec`]・stderr 収集・子の回収ガードを共用する）と、
//! 子モジュール `mode` のモード選択 API（TASK-110.3・#260）。
//!
//! 呼び出しごとに plugin プロセスを spawn し、1 往復（要求フレーム送信 -> 応答フレーム受信）の
//! 完了後に終了させる。呼び出し元は core 側の plugin proxy（#1869 の設計〔docs/design/plugin-backend-wiring.md。承認待ち・実装 issue は未起票〕・TASK-114 ほか。依存方向は
//! `core -> plugin` のため、本モジュールは core の登録表を参照せず、検証済みの fd を持つ起動対象 [`PluginLaunchTarget`] を受け取る。#1856）。
//!
//! # 契約
//!
//! - 接続方向は「core 側が [`UdsListener`] を bind し、plugin が接続する」（`transport` 冒頭の契約）。
//!   socket の絶対パスは環境変数 [`PLUGIN_SOCKET_ENV`] で子へ渡す（暫定契約。spec 未規定）。
//! - spawn から応答受信までは [`OneShotTimeout`] の合計期限で打ち切る（REPAIR-5）。応答後の自発終了
//!   待ちは別枠の [`PLUGIN_EXIT_TIMEOUT`]。猶予内に終了しなければ強制終了する。
//! - 子プロセスの回収: [`call_once`] が `Ok` を返した時点で、直接起動した子は wait または kill で
//!   回収済み。`Err` の場合も、返す前に必ず kill と [`PLUGIN_REAP_TIMEOUT`] までの回収を試みる。
//!   回収を確認できなかった場合に限り、`Internal`（メッセージに `could not be reaped` と子の pid を
//!   含む）を元のエラーに代えて返す。報告した pid の子は、この呼び出しではそれ以降回収しない
//!   （報告後に回収すると、解放済みの pid を未回収として伝えることになるため）。子は終了済みでも
//!   ゾンビとして残り、親プロセスの終了時に OS が引き取る。呼び出し側はその pid を未回収として扱う。
//! - プロセスグループの停止失敗（#1311）: 直接の子は回収できたが、子のプロセスグループ宛ての kill が
//!   失敗して孫の停止を保証できない場合、応答前の失敗経路では元のエラーの `code` と `message` を保ち、
//!   `message` に `process group could not be killed` の付記を加えて返す（`with_group_kill_failure`。
//!   元の失敗の分類を失わず、孫が残り得ることも黙らない）。元のエラーが無い経路（応答後・常駐の
//!   shutdown）は未回収の子とは別の `Internal`（同じ文言を含み、解放済みの子の pid は含めない）を返す。
//!   いずれも `could not be reaped` とは報告しない（PLUG-7・REPAIR-5）。応答後・常駐の shutdown でも、
//!   自発終了の観測後のグループ送信が Linux で失敗した場合に同じ形で現れ得る（#1604）。macOS はゾンビだけのグループへの
//!   `killpg` にも `EPERM` を返すため、接続後・応答前に plugin が終了した場合は孫がいなくても付記が付き得る
//!   （`EPERM` を許容しない理由は `group_kill_tolerated` の doc）。
//! - `Drop` 経路の記録（#1605・#1673・REPAIR-4）: `ChildGuard` の破棄時にグループ停止の失敗（`GroupKillFailed`。
//!   孫が残り得る）または直接の子の未回収（`Unreaped`）が起きた場合、1 行の JSON
//!   （`{"event":"plugin_child_cleanup","op":"drop","outcome":"error","reason":"group_kill_failed"|"unreaped"}`。
//!   `unreaped` のみ保持中の `pid` を整数で付す）を 1 回だけ残す。ブロックしないことを保証できる出力先（Linux の
//!   AF_UNIX の socket。`crate::sys` の `write_nonblocking`）へは `Drop` の中で stderr へ即時に書く。それ以外（TCP 等の
//!   他の socket・pipe・端末・通常ファイル・macOS）と、即時書き込みが全部は書けなかった場合は、固定長の延期表
//!   （`drop_report`）へ積み、ホストが終了時に `take_pending_child_cleanup_failures` で取り出して出す。
//!   即時に全部書けた記録は表へ積まない（重複させない）。SIGKILL・abort・シグナル再送出による終了と、取り出しを
//!   呼ばないホスト（core の plugin proxy は #1869 の設計・TASK-114 で配線予定）では延期した記録は残らない（REPAIR-3）。plugin 由来の文字列は
//!   載せない。`unreaped_error` で報告済みの子と、`Drop` の前に明示的な経路で手放した子（回収済み・他所で回収された
//!   `Lost`。そこで返したグループ停止の失敗を含む）は記録しない。
//! - 子の環境変数は `env_clear()` 後に [`PLUGIN_SOCKET_ENV`] を設定する（資格情報を継承させない）。
//!   追加は [`PluginLaunchSpec::with_env`] で呼び出し側が名前と値を明示した組だけで、親の環境を暗黙に
//!   継承する指定は無い。`FANDHE_CONTAINER_PLUGIN_`・`LD_`・`DYLD_` 始まりの名前・規則外の名前・重複・
//!   NUL を含む値・上限超過（[`PLUGIN_ENV_MAX_COUNT`] 等）は `InvalidArgument` で拒否し、spawn しない
//!   （#1858・#1319・PLUG-7）。
//!   stdin / stdout は null。stderr は親へ継承させず、専用の UNIX ソケット対で受けて
//!   [`PluginStderr`] として返す（untrusted。保持は [`PLUGIN_STDERR_MAX_BYTES`] まで。超過分は
//!   読み捨てて件数だけ数える）。親の stderr・構造化ログへ内容を転記しない（量の上限なしの出力・
//!   ログ行の偽装を防ぐ）。子から見た stderr は端末でも pipe でもなくソケットで、書き込みは pipe と
//!   同様に扱える（`/dev/stderr` の開き直しは Linux では失敗する）。
//! - 親の強制終了時の停止（#1514・#1403 の方式 B・PLUG-7・REPAIR-5・CORE-1）: Linux では spawn 直前に
//!   `prctl(PR_SET_PDEATHSIG, SIGKILL)` を子へ設定し、親が SIGKILL・abort で落ちても plugin 本体が
//!   孤児で残らないようにする（fork から prctl までに親が先に終わった競合は `getppid` の照合で exec を
//!   中止して拾う）。効くのは直接の子だけで、孫には届かない（未実装節の孫の項目と #1397・#1513 を参照）。
//!   発火条件は子を fork した**スレッド**の終了で、都度起動は呼び出しスレッド上で完結するため影響しない
//!   （常駐モードの契約は `resident` を参照）。setuid・ファイル capability つき実行ファイルでは設定が
//!   解除される。macOS には同等の機構がなく親の強制終了で残留し得る（kqueue `NOTE_EXIT` は将来課題）。
//!   Windows は対象外。
//! - stderr の読み取りスレッドは呼び出しごとに 1 本で、[`call_once`] が戻るまでに停止させる
//!   （呼び出しを繰り返してもスレッドが増え続けない）。子の回収後 [`PLUGIN_STDERR_DRAIN_TIMEOUT`]
//!   以内に終端へ達しなければ、停止用 pipe へ書いて読み取りを打ち切る（待ちは `poll` の期限で有限。
//!   macOS の `shutdown` と `recv` の競合に依存しない。#3003。`poll` 非対応の構成だけ従来の `shutdown`）。
//!
//! # 未実装（REPAIR-3）
//!
//! - 外部管理の常駐 plugin への再接続（attach）と、観測記録を受け取る統一 API（`mode` の冒頭を参照）。
//! - 起動対象の信頼性検証そのもの（所有者・モード・sha256 照合。TASK-122・PLUG-11）。本 API は検証を
//!   行わず、呼び出し側が検証済みの fd を持つ起動対象を渡すことを前提とする（起動 API はパスだけでは
//!   起動できない。#1856）。Linux は fd の実体を実行し、検証後のパス差し替えでは別の実行ファイルを
//!   起動しない。macOS は実体のパスで起動するが、spawn 直前に `lstat` の dev / ino を保持 fd と照合し、
//!   不一致なら spawn しない（#1866。残余は確認から exec までの窓での同じ UID / root による差し替えで、
//!   PLUG-11 の脅威の外）。構築口と本番配線は #1857・#1869。
//! - 孫プロセスの回収の残る制限（#1311・#1604）。タイムアウト・後始末の kill は子のプロセスグループ全体へ
//!   送るため孫も止まる。plugin が自発終了した場合も、`waitid(WNOWAIT)`（`sys::probe_child_exit`）で回収せずに
//!   終了を観測し（ゾンビのまま pgid は再利用されない）、グループへ `SIGKILL` を送ってから回収する
//!   （Linux x86_64 / aarch64・macOS）。残るのは、(a) プローブ非対応の OS・アーキテクチャ（従来どおり回収後は
//!   送らず孫が残る）、UID を変えた孫（Linux の `killpg` は部分配送でも成功し検出できない。macOS は孫が
//!   いなくてもゾンビだけのグループへの送信が `EPERM` になり、権限外の生存者と区別できないため、有限時間の再送後も残る自発終了後の
//!   送信では `EPERM` を失敗扱いにしない）、(b) `setsid` / `setpgid` でグループを抜けた孫（plugin 本体が抜けた場合、
//!   グループ宛ての kill・転送は旧グループに残った孫にだけ届き、本体は `Child::kill` のフォールバックで
//!   止めて回収する。本体が抜けた後に起動した孫は届かない）、(c) Windows
//!   （プロセスグループ単位の kill が無く、相当する Job Object は別タスク）では孫が残る。孫が stderr の
//!   書き込み端を保持し続けた場合、収集は [`PLUGIN_STDERR_DRAIN_TIMEOUT`] で打ち切り、
//!   [`PluginStderr::is_complete`] が false になる。打ち切り後は読み取り側を閉じるため、孫の以後の
//!   書き込みは `EPIPE` になる。子は親と別のプロセスグループになるため、端末由来のシグナル（Ctrl-C 等）は
//!   カーネルからは届かない。親が受けた SIGINT・SIGTERM・SIGHUP は CLI バイナリのハンドラが
//!   `signal_forward` 経由でグループ宛て（`kill(-pid)`）に転送し、孫まで届く（#1513）。親が SIGKILL・
//!   abort で落ちた場合は転送されず、Linux の `PR_SET_PDEATHSIG` が止めるのは plugin 本体だけで孫は
//!   残留し得る。macOS では plugin 本体も孫も残留し得る（kqueue `NOTE_EXIT` は将来課題）。
//! - 要求 ID と応答 ID の対応づけ（#1869 の設計）。

mod drop_report;
mod env;
mod launch_target;
mod mode;
mod resident;

pub use env::{
    PLUGIN_ENV_MAX_BYTES, PLUGIN_ENV_MAX_COUNT, PLUGIN_ENV_NAME_MAX_BYTES,
    PLUGIN_ENV_VALUE_MAX_BYTES,
};
#[cfg(unix)]
pub use launch_target::PluginFileIdentity;
pub use launch_target::PluginLaunchTarget;

pub use mode::{
    OneShotSummary, PluginCallOutcome, PluginCallRecord, PluginMode, PluginModeKind, PluginSession,
    PluginSessionShutdown,
};

pub use resident::{
    RESIDENT_EXIT_DETECT_TIMEOUT, RESIDENT_START_TIMEOUT_DEFAULT, RESIDENT_START_TIMEOUT_MAX,
    ResidentCallRecord, ResidentPlugin, ResidentShutdown, ResidentShutdownError,
    ResidentStartTimeout, ResidentState,
};

use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;
use crate::signal_forward::{PLUGIN_REGISTRY, Registry, SlotToken};
use crate::transport::{RpcTimeout, UDS_RPC_TIMEOUT_MAX, UdsListener};

// `ONE_SHOT_TIMEOUT_MAX` の doc が約束する「残り時間を常に `RpcTimeout` へ変換できる」をコンパイル時に固定する。
const _: () = assert!(ONE_SHOT_TIMEOUT_MAX.as_nanos() <= UDS_RPC_TIMEOUT_MAX.as_nanos());
pub use drop_report::{
    ChildCleanupFailure, DROP_REPORT_CAPACITY, PendingChildCleanup,
    take_pending_child_cleanup_failures, write_stderr_nonblocking,
};
use drop_report::{GLOBAL_TABLE, record_drop_failure};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

/// 子へ接続先 socket の絶対パスを渡す環境変数名。
pub const PLUGIN_SOCKET_ENV: &str = "FANDHE_CONTAINER_PLUGIN_SOCKET";

/// [`OneShotTimeout`] の既定値（10 秒）。
///
/// `OneShot*` の期限型は都度起動の「spawn から応答受信まで」の合計期限を表す専用の名前で、改名しない
/// （常駐の対応物は `ResidentStartTimeout` と呼び出しごとの `RpcTimeout`。#2608・PLUG-11・REPAIR-1）。
pub const ONE_SHOT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// [`OneShotTimeout`] の上限（10 秒。残り時間を常に `RpcTimeout` へ変換できる値にする）。
pub const ONE_SHOT_TIMEOUT_MAX: Duration = Duration::from_secs(10);

/// 応答受信後（都度起動）・`shutdown`（常駐）で子の自発終了を待つ猶予（合計期限とは別枠。両モードで共用する。#2608）。
pub const PLUGIN_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// 起動引数の件数上限。
pub const PLUGIN_ARGS_MAX_COUNT: usize = 64;

/// 起動引数の合計バイト数上限。
pub const PLUGIN_ARGS_MAX_BYTES: usize = 4096;

/// 子の終了待ちポーリング間隔の上限。
const POLL_MAX: Duration = Duration::from_millis(5);

/// 強制終了後の回収（`try_wait` ポーリング）を待つ上限（REPAIR-5。無期限の `wait` を避ける。都度起動と常駐で共用する。#2608）。
pub const PLUGIN_REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// plugin の stderr として保持するバイト数の上限（64 KiB。超過分は読み捨てる。無制限確保の防止。都度起動と常駐で共用する。#2608）。
pub const PLUGIN_STDERR_MAX_BYTES: usize = 64 * 1024;

/// 子の回収後に stderr の読み取り完了（終端）を待つ上限（REPAIR-5。合計期限とは別枠。都度起動と常駐で共用する。#2608）。
/// 子が終了していれば書き込み端は閉じており即座に完了する。孫プロセスが書き込み端を保持している
/// 場合のみこの期限まで待ち、読み取りを打ち切ってスレッドを停止させる。
pub const PLUGIN_STDERR_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// 打ち切りを指示した後、読み取りスレッドの停止を確認するまで待つ上限（REPAIR-5。都度起動と常駐で共用する。#2608）。
/// 停止用 pipe で読み取りは即座に戻るため通常は待たない。スケジューリング遅延への余裕として設ける
/// （この期限内に止まらなければ最後の手段としてソケットを shutdown する。#3003）。
pub const PLUGIN_STDERR_STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// stderr の読み取り 1 回の待ち上限。読み取りスレッドはこの間隔で停止指示を確認する
/// （`poll` の期限。停止用 pipe の起床が効かない場合でも、この間隔で停止できる）。
#[cfg(unix)]
const STDERR_READ_POLL: Duration = Duration::from_millis(100);

/// spawn から応答受信までの合計期限（REPAIR-5。都度起動専用のため名前を保つ。常駐の対応物は `ResidentStartTimeout`。#2608）。0 と [`ONE_SHOT_TIMEOUT_MAX`] 超は構築できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OneShotTimeout(Duration);

impl OneShotTimeout {
    /// 0 または [`ONE_SHOT_TIMEOUT_MAX`] 超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, PluginError> {
        if timeout.is_zero() || timeout > ONE_SHOT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "one-shot timeout must be non-zero and within the maximum",
            ));
        }
        Ok(Self(timeout))
    }

    /// 保持している期間を返す。
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl Default for OneShotTimeout {
    /// [`ONE_SHOT_TIMEOUT_DEFAULT`]（10 秒）。
    fn default() -> Self {
        Self(ONE_SHOT_TIMEOUT_DEFAULT)
    }
}

impl TryFrom<Duration> for OneShotTimeout {
    type Error = PluginError;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        Self::new(timeout)
    }
}

/// 都度起動・常駐（`PluginSession` を含む）で共用する plugin の起動仕様。検証済みの値のみ保持する。
#[derive(Debug, Clone)]
pub struct PluginLaunchSpec {
    target: PluginLaunchTarget,
    args: Vec<OsString>,
    socket_dir: PathBuf,
    env: env::PluginEnvVars,
}

impl PluginLaunchSpec {
    /// `target` は検証済みの fd を持つ起動対象（パスだけでは起動できない。`PATH` 探索もしない。
    /// PLUG-11・#1856）。引数は件数・合計バイト数を検証する。
    /// `socket_dir` は listener を置く 0700 ディレクトリ（通常は `RuntimeDir::path()`）。
    /// 違反は `InvalidArgument`。`target` の信頼性は構築側（core の検証。TASK-122）の責務で、ここでは
    /// 検証しない。
    pub fn new(
        target: PluginLaunchTarget,
        args: Vec<OsString>,
        socket_dir: PathBuf,
    ) -> Result<Self, PluginError> {
        let total: usize = args.iter().map(|a| a.len()).sum();
        if args.len() > PLUGIN_ARGS_MAX_COUNT || total > PLUGIN_ARGS_MAX_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "plugin arguments exceed the allowed count or size",
            ));
        }
        Ok(Self {
            target,
            args,
            socket_dir,
            env: env::PluginEnvVars::default(),
        })
    }

    /// 子へ追加で渡す環境変数の組を検証して設定する（既定は空。呼ぶたびに組全体を置き換え、空の
    /// `Vec` で既定へ戻る）。都度起動・常駐・[`PluginSession`] のすべての経路で同じ組が渡る。
    ///
    /// 違反は `InvalidArgument`（固定の英語文言。名前も値も載せない）で、spawn しない。規則は
    /// `lifecycle` の契約と [`PLUGIN_ENV_MAX_COUNT`] 等の上限を参照。親の環境は読まない。
    /// どの plugin に何を渡すかは呼び出し側（core）が決める（#1869）。PLUG-7・#1858。
    pub fn with_env(mut self, vars: Vec<(String, OsString)>) -> Result<Self, PluginError> {
        self.env = env::validate(vars)?;
        Ok(self)
    }

    /// 起動する実行ファイルの実体の絶対パス（表示専用。開き直し・起動には使わない。Linux は fd の
    /// 実体を実行する）。
    pub fn program(&self) -> &Path {
        self.target.exec_path()
    }

    /// 起動対象（検証済み fd を持つ）。
    pub fn launch_target(&self) -> &PluginLaunchTarget {
        &self.target
    }
}

/// 応答受信後（都度起動）・`shutdown`（常駐）の子プロセスの終了状況（両モードで共用する。#2608）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginTermination {
    /// 自発終了した（強制終了を試みる直前・直後に自発終了していた場合を含む）。`code` はシグナル
    /// 終了などで取得できない場合 `None`。他所で回収され終了状態が不明な場合（`code: None`）を含む。
    Exited { code: Option<i32> },
    /// 猶予内に終了せず強制終了し、回収まで確認した（回収した終了状態が強制終了によるもの）。
    Killed,
    /// 強制終了を試みたが、[`PLUGIN_REAP_TIMEOUT`] 内に直接の子の回収を確認できなかった（直接の子への
    /// kill 失敗を含む）。呼び出し側は孤児の可能性として扱う（REPAIR-5・PLUG-7）。
    Unreaped,
    /// 直接の子は回収済み（pid は解放済み）だが、子のプロセスグループ宛ての kill が失敗し、孫プロセスの
    /// 停止を保証できない（#1311・PLUG-7・REPAIR-5）。未回収の子（[`Self::Unreaped`]）とは別の結果で、
    /// 成功した呼び出しの結果には現れない（呼び出しは `Internal` で失敗する）。
    ///
    /// 契約の限界: 送信自体が失敗した場合だけを表す。Linux の `killpg` は 1 プロセスにでも送れれば成功する
    /// ため、setuid 実行ファイル等で UID を変えた孫には SIGKILL が届かず残り得る。この部分配送による
    /// 残留は検出できず保証対象外（全数停止は cgroup・pidfd 等を要する別課題）。逆に macOS は、ゾンビだけの
    /// グループ（孫がいない）への `killpg` にも `EPERM` を返し、生存者への権限不足と区別できないため、
    /// 孫がいなくても本結果になり得る（fail-closed。主に応答前の失敗経路で `reap_after_failure` の付記として
    /// 現れる。自発終了を観測した後の送信〔#1604〕は、孫の有無と区別できない macOS の `EPERM` を許容するため
    /// 本結果にならず、Linux の送信失敗だけが応答後・常駐の経路にも現れる）。
    GroupKillFailed,
}

/// plugin が stderr へ書いた内容の収集結果（untrusted。出所は起動した plugin プロセス）。
///
/// 内容は plugin が任意に書けるバイト列であり、解釈・検証はしていない。呼び出し側がログへ出す
/// 場合は、plugin 由来であることを明示し、エスケープしたうえで扱うこと（構造化ログの行を偽装
/// され得るため、そのまま自プロセスの stderr・ログへ流さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStderr {
    bytes: Vec<u8>,
    total_bytes: u64,
    complete: bool,
    reader_stopped: bool,
}

impl PluginStderr {
    /// 何も収集していない完了済みの結果（子を spawn しなかった経路用。読み取りスレッドなし）。
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: true,
            reader_stopped: true,
        }
    }

    /// 保持している先頭部分（最大 [`PLUGIN_STDERR_MAX_BYTES`] バイト）。
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 収集を打ち切るまでに plugin が書いた総バイト数（読み捨てた分を含む）。
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// 上限超過で読み捨てた部分があるか。
    pub fn is_truncated(&self) -> bool {
        u64::try_from(self.bytes.len()).map_or(true, |kept| self.total_bytes > kept)
    }

    /// 終端（全書き込み端の close）まで読み切ったか。false は [`PLUGIN_STDERR_DRAIN_TIMEOUT`] で
    /// 打ち切ったことを表す（孫プロセスが書き込み端を保持している等）。
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// 読み取りスレッドの停止を確認できたか（終端到達、または打ち切り指示への応答）。
    /// false はスレッドが [`PLUGIN_STDERR_STOP_TIMEOUT`] 内に停止を返さなかったことを表し、
    /// 呼び出し側は資源の残留として扱う（REPAIR-4 の観測記録にも出す）。
    pub fn reader_stopped(&self) -> bool {
        self.reader_stopped
    }
}

/// 子の stderr を専用スレッドで読み、上限つきで保持する収集器（REPAIR-5）。
///
/// 読み取りは接続待ちの前から別スレッドで行う。親（呼び出しスレッド）は接続待ち・往復・回収の
/// 間に読まないため、子がバッファを超えて書いても子は詰まらず、親も読み取りでブロックしない。
/// 結果の受け取り（[`Self::finish`]）は期限つきで、期限内に終端へ達しなければ読み取りを打ち切って
/// スレッドを停止させる（スレッドを残さない）。`join` は行わず、停止の確認も期限つきで行う。
/// 常駐モード（`resident`。TASK-110.2）はセッション全期間で 1 本の収集器を保持する。
struct StderrCapture {
    state: Arc<Mutex<PluginStderr>>,
    done: mpsc::Receiver<()>,
    stop_requested: Arc<AtomicBool>,
    /// ブロック中の読み取りを起こす操作（停止用 pipe への書き込み。`poll` 非対応の構成はソケットの
    /// shutdown）。1 回だけ実行する。
    wake: Option<Box<dyn FnOnce() + Send>>,
    /// 停止用 pipe の起床でも [`PLUGIN_STDERR_STOP_TIMEOUT`] 内に止まらなかったときだけ実行する最後の
    /// 手段（ソケットの shutdown。以後、孫の書き込みは `EPIPE` になる。#3003）。
    last_resort: Option<Box<dyn FnOnce() + Send>>,
}

impl StderrCapture {
    /// `source` を終端または停止指示まで読むスレッドを起動する。起動できなければ `Err`
    /// （呼び出し側が子を回収する）。
    ///
    /// `source` の `read` は有限時間で戻ること（読み取り期限を設定済みで、期限切れは `WouldBlock` /
    /// `TimedOut` を返す）。`wake` はブロック中の `read` を即座に戻すための操作で、停止指示の後に
    /// 1 回だけ呼ぶ。
    fn start<R: Read + Send + 'static>(
        source: R,
        wake: Box<dyn FnOnce() + Send>,
    ) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(PluginStderr {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: false,
            reader_stopped: false,
        }));
        let stop_requested = Arc::new(AtomicBool::new(false));
        let (tx, done) = mpsc::channel();
        let shared = Arc::clone(&state);
        let stop = Arc::clone(&stop_requested);
        std::thread::Builder::new()
            .name("plugin-stderr".to_string())
            .spawn(move || {
                drain_stderr(source, &shared, &stop);
                // 受け手が先に去っていても構わない。
                let _ = tx.send(());
            })?;
        Ok(Self {
            state,
            done,
            stop_requested,
            wake: Some(wake),
            last_resort: None,
        })
    }

    /// 子の stderr を受けるソケットの読み取り側から収集を始める。
    ///
    /// `poll` 対応の構成では、読み取りスレッドが「ソケット」と「停止用 pipe」を `poll` で待つ。停止時は
    /// pipe へ 1 バイト書いて起こし、`shutdown` は呼ばない（macOS で `shutdown` が別スレッドの `recv` と
    /// 競合して読み取りが戻らない場面の回避。REPAIR-5・#3003）。それでも止まらなかった場合に限り、最後の
    /// 手段として `shutdown` する。対応外の構成は従来どおり受信期限と `shutdown` で止める。
    #[cfg(unix)]
    fn attach(reader: StderrReader, deadline: Instant) -> io::Result<Self> {
        let shutdown_sock = reader.try_clone()?;
        let shutdown = move || {
            let _ = shutdown_sock.shutdown(std::net::Shutdown::Both);
        };
        if !crate::sys::POLL_SUPPORTED {
            return Self::start(reader, Box::new(shutdown));
        }
        // 読み取り側は非ブロッキングにする（`poll` が読めると言った後だけ読む。偽の起床でも止まらない）。
        reader.set_nonblocking(true)?;
        // ゲート待ちは呼び出し元の合計期限までに限る（REPAIR-5）。
        let (stop_rx, stop_tx) = crate::spawn_gate::create_fds(deadline, io::pipe)?;
        let mut capture = Self::start(
            PolledStderr {
                sock: reader,
                stop: stop_rx,
            },
            Box::new(move || {
                // 書き込み端を閉じて `POLLHUP` で起こす。pipe へは書かない（読み手が先に去っていると `EPIPE` と
                // `SIGPIPE` になり、ホストの signal 設定が既定のままだとプロセスごと落ちるため。REPAIR-5・#3003）。
                drop(stop_tx);
            }),
        )?;
        capture.last_resort = Some(Box::new(shutdown));
        Ok(capture)
    }

    /// 非 unix では子を spawn しないため、空の入力を読むだけになる（即座に終端へ達する）。
    #[cfg(not(unix))]
    fn attach(reader: StderrReader, _deadline: Instant) -> io::Result<Self> {
        Self::start(reader, Box::new(|| {}))
    }

    /// 読み取りスレッドへ停止を指示し、ブロック中の読み取りを起こす。
    fn request_stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(wake) = self.wake.take() {
            wake();
        }
    }

    /// 読み取り完了を `limit` まで待ち、その時点までの収集結果を返す。期限内に終端へ達しなければ
    /// 読み取りを打ち切り、スレッドの停止を [`PLUGIN_STDERR_STOP_TIMEOUT`] まで確認して
    /// `is_complete() == false` の途中結果を返す。
    fn finish(mut self, limit: Duration) -> PluginStderr {
        // 送信側の消滅（Disconnected）はスレッドが終了したことを意味するため、停止済みとして扱う。
        let timed_out =
            |r: Result<(), mpsc::RecvTimeoutError>| r == Err(mpsc::RecvTimeoutError::Timeout);
        let mut stopped = !timed_out(self.done.recv_timeout(limit));
        if !stopped {
            self.request_stop();
            stopped = !timed_out(self.done.recv_timeout(PLUGIN_STDERR_STOP_TIMEOUT));
            if !stopped && let Some(last_resort) = self.last_resort.take() {
                last_resort();
            }
        }
        let mut result = lock_stderr(&self.state).clone();
        result.reader_stopped = stopped;
        result
    }
}

impl Drop for StderrCapture {
    /// `finish` を経ずに破棄される経路（panic 等）でもスレッドを残さない。
    fn drop(&mut self) {
        self.request_stop();
    }
}

/// 読み取りスレッドが panic しても収集結果を取り出せるよう、poison を無視して lock する。
fn lock_stderr(state: &Mutex<PluginStderr>) -> MutexGuard<'_, PluginStderr> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `source` を終端・エラー・停止指示のいずれかまで読み、先頭 [`PLUGIN_STDERR_MAX_BYTES`] バイト
/// だけ保持する。上限到達後も読み捨てを続ける（読むのを止めると子が書き込みで詰まり、応答・終了が
/// 遅れるため）。停止指示は読み取りのたびに確認するので、書き込みが続いていても停止できる。
fn drain_stderr<R: Read>(mut source: R, state: &Mutex<PluginStderr>, stop: &AtomicBool) {
    let mut chunk = [0u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match source.read(&mut chunk) {
            // 最後の手段の shutdown でも 0 が返るため、指示後の 0 は終端として扱わない。
            Ok(0) => {
                if !stop.load(Ordering::SeqCst) {
                    lock_stderr(state).complete = true;
                }
                return;
            }
            Ok(n) => {
                let mut s = lock_stderr(state);
                let room = PLUGIN_STDERR_MAX_BYTES.saturating_sub(s.bytes.len());
                if let Some(kept) = chunk.get(..n.min(room)) {
                    s.bytes.extend_from_slice(kept);
                }
                s.total_bytes = s
                    .total_bytes
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            }
            // 読み取り期限切れ・割り込みは継続する（ループ先頭で停止指示を確認する）。
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            // その他の読み取りエラーは終端として扱わない（complete を立てない）。
            Err(_) => return,
        }
    }
}

/// ソケットと停止用 pipe を `poll` で同時に待つ stderr 入力（unix。`poll` 対応の構成のみ。#3003）。
///
/// [`StderrCapture::attach`] が作り、読み取りスレッド（[`drain_stderr`]）の `read` として呼ばれる。
/// 1 回の待ちは [`STDERR_READ_POLL`] で有限。停止用 pipe が読めれば `Interrupted` を返し、呼び出し側が
/// 停止フラグ（pipe より先に立つ）を見て抜ける。ソケット側は `sock` が非ブロッキングなので、起床後の
/// `read` が待つことはない。
#[cfg(unix)]
struct PolledStderr {
    sock: std::os::unix::net::UnixStream,
    stop: io::PipeReader,
}

#[cfg(unix)]
impl Read for PolledStderr {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ms = i32::try_from(STDERR_READ_POLL.as_millis()).unwrap_or(100);
        match crate::sys::poll_two(&self.sock, &self.stop, ms)? {
            crate::sys::PollOutcome::TimedOut => Err(io::ErrorKind::WouldBlock.into()),
            crate::sys::PollOutcome::Ready { second: true, .. } => {
                Err(io::ErrorKind::Interrupted.into())
            }
            crate::sys::PollOutcome::Ready { .. } => self.sock.read(buf),
        }
    }
}

/// 親が読む側の stderr 入力。unix は UNIX ソケット、非 unix は空の入力（子を spawn しないため）。
#[cfg(unix)]
type StderrReader = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
type StderrReader = io::Empty;

/// 子の stderr に渡す書き込み端と、親が読む側の組を作る（REPAIR-5）。
///
/// pipe ではなく UNIX ソケット対を使う。pipe の読み取りは期限を掛けられず、書き込み端を孫が保持
/// している間は読み取りスレッドを止められない。ソケットなら `poll` の期限と停止用 pipe（対応外の構成は
/// 受信期限と shutdown）で確実に止められる。子から見た書き込みは pipe と同様（端末ではなく、読み手が
/// 閉じれば `EPIPE`）。どちらの端も close-on-exec で、子へ渡るのは fd 2 に複製した書き込み端のみ。
/// macOS では作成と close-on-exec の設定が別 syscall のため、並行する spawn へ漏れないよう
/// `spawn_gate` で排他する（#3139）。
#[cfg(unix)]
fn stderr_channel(deadline: Instant) -> io::Result<(Stdio, StderrReader)> {
    // macOS の std は close-on-exec を作成後に別 syscall で立てるため、並行する spawn と排他にする
    // （`spawn_gate`。PLUG-7・SEC-1・#3139）。
    // ゲート待ちは呼び出し元の合計期限までに限る（REPAIR-5）。
    let (reader, writer) =
        crate::spawn_gate::create_fds(deadline, std::os::unix::net::UnixStream::pair)?;
    // 相手が健在なうちに期限を設定する（macOS は相手切断後の設定が EINVAL になる）。
    reader.set_read_timeout(Some(STDERR_READ_POLL))?;
    Ok((Stdio::from(std::os::fd::OwnedFd::from(writer)), reader))
}

/// 非 unix では listener を bind できず子を spawn しないため到達しない（stderr は破棄する設定を返す）。
#[cfg(not(unix))]
fn stderr_channel(_deadline: Instant) -> io::Result<(Stdio, StderrReader)> {
    Ok((Stdio::null(), io::empty()))
}

/// [`call_once`] の成功結果（都度起動専用のため名前を保つ。常駐の対応物は `ResidentShutdown`。#2608）。
#[derive(Debug)]
#[non_exhaustive]
pub struct OneShotOutcome {
    response: Frame,
    termination: PluginTermination,
    stderr: PluginStderr,
}

impl OneShotOutcome {
    /// plugin から受信した応答フレーム（untrusted。内容は解釈していない）。
    pub fn response(&self) -> &Frame {
        &self.response
    }

    /// 応答フレームを取り出す。
    pub fn into_response(self) -> Frame {
        self.response
    }

    /// 子プロセスの終了状況。
    pub fn termination(&self) -> PluginTermination {
        self.termination
    }

    /// plugin が stderr へ書いた内容（untrusted・上限つき）。
    pub fn stderr(&self) -> &PluginStderr {
        &self.stderr
    }
}

/// 子プロセスを保持し、Drop で kill・回収を試みるガード（panic 等の早期離脱でも子を残さない）。
///
/// 回収の成否を呼び出し側へ返す責務は明示的な [`Self::kill_and_reap`] / [`Self::wait_or_kill`] の
/// 呼び出しが担う。直接の子の未回収（`Unreaped`）と、直接の子は回収済みでプロセスグループの停止だけが
/// 失敗した場合（`GroupKillFailed`）は別の結果として返し、呼び出し側はそれぞれ [`unreaped_error`]・
/// [`group_kill_failed_error`] で報告する（#1311・PLUG-7・REPAIR-5）。plugin の自発終了は `try_wait` が
/// `waitid(WNOWAIT)` で観測し、回収の前にグループへ `SIGKILL` を送る（#1604）。未回収として報告した後（[`unreaped_error`]）は `Drop` で回収しない。報告後に回収
/// すると、呼び出し側へ伝えた pid が解放済みになり、別プロセスを指し得るため（kill は報告前に送信
/// 済みで、`Drop` での再試行は待ち時間を延ばすだけになる）。
struct ChildGuard {
    child: Option<Child>,
    /// 未回収として pid を報告済みか。true なら `Drop` で回収しない。
    reported_unreaped: bool,
    /// シグナル転送の登録表のスロット（#1513）。子を回収し得る `waitpid` の前に登録を外し、回収した時点で
    /// 解放する。回収後に再利用された pid へシグナルを送らないための構造で、回収は必ず
    /// [`Self::try_wait`] / [`Self::kill_and_reap`] を経由する。
    slot: Option<SlotToken>,
    /// 直接の子（プロセスグループのリーダー）を wait 済みか、追跡できなくなったか。true ならグループ宛ての
    /// 送信をしない。回収後は pid（= pgid）が再利用され得るため、別プロセスのグループへ誤送信しないための印。
    /// `try_wait` が `Some` を返した時点（[`Self::release_reaped`]）と終端化（[`Self::mark_lost`]）で立てる
    /// （#1311・PLUG-7・REPAIR-5）。
    leader_reaped: bool,
    /// 子の状態を追跡できなくなったか（`waitpid` が失敗した。主に `ECHILD`＝契約外の回収者による回収）。
    /// true なら `child` と `slot` は手放し済みで、以後 kill（プロセスグループ宛てを含む）も回収も転送もしない
    /// 終端状態（[`Reap::Lost`]。#1513）。
    lost: bool,
    /// 自発終了を観測した後に行ったグループ宛て `SIGKILL` が、許容外のエラーで失敗したか（#1604）。
    /// 直接の子は [`Self::try_wait`] で回収済みでも孫の停止を保証できないため、各消費者
    /// （`wait_or_kill`・`kill_and_reap`・常駐の `call` / `fail_session`）が `GroupKillFailed` として
    /// 報告する。`try_wait` の戻り値は std の `ExitStatus` のままなので、失敗はこの印で運ぶ。
    group_kill_failed_after_exit: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            reported_unreaped: false,
            slot: None,
            leader_reaped: false,
            lost: false,
            group_kill_failed_after_exit: false,
        }
    }

    /// 登録表のスロットを持たせる（[`spawn_registered`] が使う）。
    fn with_slot(mut self, slot: SlotToken) -> Self {
        self.slot = Some(slot);
        self
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// 終了を非ブロックで確認する。回収し得るため、直前に登録表から外し（進行中の転送の完了を待つ）、
    /// まだ動いていれば戻す。外した窓の間に届いたシグナルは転送されない（取りこぼす側）。進行中の転送の
    /// 完了を確認できないときは回収せず `Ok(None)`（まだ動いている扱い）を返し、次の周回に委ねる。
    /// 将来 `suspend` を使わず pidfd 等で回収と転送の競合を除く案がある（現状は #1514 の `PR_SET_PDEATHSIG` で補完する）。
    ///
    /// 自発終了の扱い（#1604）: 回収しない `waitid(WNOWAIT)` で終了を観測できたら、回収（`waitpid`）の前に
    /// グループへ `SIGKILL` を 1 回送る（リーダーがゾンビのまま残るため pgid は再利用されない）。動作中は
    /// `waitpid` を呼ばず `Ok(None)`（観測と回収の間に終了した子を、送信なしで回収する競合を作らない）。
    /// 送信が許容外のエラーで失敗したら `group_kill_failed_after_exit` を立て、各消費者が報告する。
    /// 観測の失敗（`ECHILD` 等）は次の `waitpid` の失敗と同じ終端として扱い、グループへ送らない。
    /// プローブ非対応の OS は従来どおり `waitpid` だけで回収する。
    /// 制限（残存リスク）: 「pgid は再利用されない」は契約外の回収者がいない前提である。観測（`Exited`）から
    /// グループ送信までの間に契約外の回収者（`crate::signal_forward` の「制限」）が回収すると、グループが空で、
    /// かつ再利用された pid が新しいグループのリーダーになった場合に限り、送信が無関係なグループへ届き得る。
    /// この窓は本関数では検出できず、閉じるのは利用側の責務（同「制限」）。回収と送信の競合を pidfd 等で
    /// 除くのは将来課題（PLUG-7）。
    ///
    /// `waitpid` の失敗（`Err`）は終端として扱う（[`Self::mark_lost`]）。`ECHILD` は契約外の回収者
    /// （継承した `SIGCHLD` の `SIG_IGN`・`SA_NOCLDWAIT`・ライブラリ利用側の `waitpid(-1)` 等）が子を回収
    /// 済みであることを意味し、pid は既に再利用され得る。登録を戻すと転送が無関係なプロセス（グループ）へ
    /// 届き得るため戻さず、以後 kill もしない（#1513・PLUG-7。core の `exec::process` の `Lost` と同じ扱い）。
    /// `WNOHANG` の `waitpid` が返し得る他のエラー（`EINVAL` 等）は実質起きないが、状態を確認できない子へ
    /// 送らない側（fail-closed）に倒して同じく終端にする。終端後の呼び出しは `Err` を返し続ける。
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(pid) = self.pid() else {
            if self.lost {
                return Err(lost_error());
            }
            return Ok(None);
        };
        // 自発終了の観測（#1604）。`waitid(WNOWAIT)` は回収しないので、ゾンビのまま残る間は pid（= pgid）が
        // 再利用されない。観測した場合に限り、回収の前にグループ（孫）へ `SIGKILL` を送る。
        // 動作中・割り込みは `waitpid` を呼ばず次の周回に委ねる（観測と回収の間に終了した子を、グループ送信
        // なしで回収してしまう競合を作らない）。観測自体の失敗（`ECHILD`＝契約外の回収者による回収、
        // `si_pid` の不整合）は終端にし、グループへ送らない（#1513 と同じ fail-closed）。プローブ非対応の
        // OS は従来どおり `waitpid` だけで回収する。
        #[cfg(not(unix))]
        let _ = pid;
        #[cfg(unix)]
        let mut observed_exit = false;
        #[cfg(unix)]
        if !self.leader_reaped {
            match crate::sys::probe_child_exit(pid) {
                Ok(crate::sys::ChildExitProbe::Running) => return Ok(None),
                Ok(crate::sys::ChildExitProbe::Exited) => observed_exit = true,
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
                Err(e) => {
                    self.mark_lost();
                    return Err(e);
                }
            }
        }
        if let Some(slot) = &self.slot
            && !slot.suspend()
        {
            slot.resume();
            return Ok(None);
        }
        #[cfg(unix)]
        if observed_exit && !self.leader_reaped && kill_group_after_exit(pid) {
            self.group_kill_failed_after_exit = true;
        }
        let Some(c) = self.child.as_mut() else {
            return Ok(None);
        };
        let result = c.try_wait();
        match result {
            // 回収した。pid は再利用され得るため、登録を戻さず解放する。グループ宛ての送信も止める。
            Ok(Some(_)) => {
                self.slot = None;
                self.leader_reaped = true;
            }
            Ok(None) => {
                if let Some(slot) = &self.slot {
                    slot.resume();
                }
            }
            // 他所で回収済み（ECHILD）または状態不明。登録を戻さず、子を手放す。
            Err(_) => self.mark_lost(),
        }
        result
    }

    /// 子を回収済みとして手放す。以後 `kill_and_reap` は何も送らない。
    fn release_reaped(&mut self) {
        self.child = None;
        self.slot = None;
        self.leader_reaped = true;
    }

    /// 子を追跡できない終端状態にする。登録表のスロットを解放し（以後転送しない）、`Child` を手放す
    /// （以後 `kill` しない。std の `Child::kill` は回収済みを知らない限り `kill(pid)` を送るため、
    /// 再利用された pid へ SIGKILL を送らないよう保持しない）。`Child` の破棄は kill も wait もしない。
    /// pgid（= pid）も再利用され得るため、プロセスグループ宛ての SIGKILL も以後送らない（#1311）。
    fn mark_lost(&mut self) {
        self.slot = None;
        self.child = None;
        self.leader_reaped = true;
        self.lost = true;
    }

    /// kill して回収を `PLUGIN_REAP_TIMEOUT` まで待つ。
    ///
    /// kill の失敗は無視せず、回収確認ができなければ `Unreaped` を返す（呼び出し側が報告する）。
    /// 直接の子を回収できてもグループ宛ての送信が許容外のエラーで失敗した場合は `GroupKillFailed` を
    /// 返す（子は手放し済みで、未回収とは区別する）。
    /// 回収できなかった場合は `Child` を保持し続ける（呼び出し側が pid を報告できるよう手放さない）。
    /// 回収できた場合は終了状態を捨てずに返す。kill の直前・直後に子が自発終了していた場合、
    /// 回収される状態は「こちらの kill」ではなく子自身の終了状態になるため、呼び出し側が
    /// [`classify_reaped`] で区別する（異常終了を強制終了と取り違えて成功扱いしない。PLUG-7）。
    ///
    /// `waitpid` が失敗した場合（他所での回収の `ECHILD` 等）は kill せず [`Reap::Lost`] を返す
    /// （[`Self::try_wait`] の終端の扱いと同じ。pid が再利用され得るため）。
    fn kill_and_reap(&mut self) -> Reap {
        let Some(c) = self.child.as_mut() else {
            // 自発終了の観測後のグループ送信が失敗していた場合（#1604）は、孫の停止を保証できないことを
            // 優先して返す（`Lost` より前。送信は回収の前に済んでいる）。
            if self.group_kill_failed_after_exit {
                return Reap::GroupKillFailed;
            }
            if self.lost {
                return Reap::Lost;
            }
            return Reap::AlreadyReaped;
        };
        // 回収しない確認（`waitid(WNOWAIT)`）を送信より前に行う（#1604）。契約外の回収者（`SIGCHLD` の
        // `SIG_IGN`・`waitpid(-1)` 等）が既に回収していれば `ECHILD` で分かり、pid（= pgid）が再利用され得る
        // ため何も送らず終端にする（従来は確認の前にグループと `Child::kill` を送っていた）。回収済みと
        // 分かっている（`leader_reaped`）場合は確認しない。プローブ非対応の OS は従来どおり。
        #[cfg(unix)]
        if !self.leader_reaped {
            match crate::sys::probe_child_exit(c.id()) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
                // 割り込みは判定不能なだけで回収済みとは限らない。従来どおり進める。
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let group_failed = self.group_kill_failed_after_exit;
                    self.mark_lost();
                    return if group_failed {
                        Reap::GroupKillFailed
                    } else {
                        Reap::Lost
                    };
                }
            }
        }
        // 直後に SIGKILL するため転送は不要。以後の回収で pid が再利用され得るので、先に登録を外し、
        // 進行中の転送の完了を待つ。上限内に確認できなければ回収しない（ロード済みの pid へ送信中の
        // 転送スレッドが、回収後に再利用された pid へ送る誤配送を防ぐ。PLUG-7・fail-closed）。
        // この場合も kill は安全（未回収の子の pid は再利用されない）なので送り、`Unreaped` を返す。
        // ただし suspend できないこの経路は上の確認の後の送信で、契約外の他所での回収（`signal_forward`
        // の「制限」）が確認から送信までの間に重なった場合だけ再利用された pid へ届き得る（#1513・#1604）。
        // `Child` は保持し続け、回収は行わない（pid を回収前に手放さない）。
        if let Some(slot) = self.slot.take()
            && !slot.suspend()
        {
            // 直接の子は未回収なので pid（= pgid）は再利用されず、グループへの送信は安全。通常経路と同じく
            // macOS の exec 窓の一過性 `EPERM` を再送で吸収する（`kill_group_retrying_eperm`）。結果は
            // 直接の子の未回収（`Unreaped`）が優先するため使わない（`Drop` は報告後に再送しない）。
            #[cfg(unix)]
            if !self.leader_reaped {
                let _ = kill_group_retrying_eperm(c.id());
            }
            let _ = c.kill();
            self.slot = Some(slot);
            return Reap::Unreaped;
        }
        // 子のプロセスグループ全体（孫を含む）へ SIGKILL を 1 回送る（#1311）。リーダーを自分がまだ
        // wait していない間に限る。ゾンビでも未回収の間は pid（= pgid）が再利用されないため、送信先は
        // 自分が起動したグループに限られる（契約外の回収者を除く。下記）。最初の `try_wait` より前に送るのは、自発終了済み（ゾンビ）の
        // 子を先に回収すると孫へ送る安全な機会を失うため（ゾンビの終了状態はシグナルで変わらず、
        // `classify_reaped` の区別は保たれる）。許容するエラーは「グループに生存者がいない」ことを
        // 示すものに限る（`group_kill_tolerated`）。それ以外の失敗は孫の停止を保証できないため、
        // 直接の子を回収できても `GroupKillFailed` を返す（成功扱いにしない。回収済みの子を未回収とも
        // 報告しない。PLUG-7・REPAIR-5）。直接の子も回収できなければ `Unreaped` が優先する。
        //
        // 残る窓（#1513・`signal_forward` の「制限」と同じ契約外の場合）: 冒頭の `waitid(WNOWAIT)` による
        // 確認（#1604）で、利用側が既に回収していた（`SIGCHLD` の `SIG_IGN`・`waitpid(-1)` 等）場合は送信前に
        // 検出して終端にする。残るのは、確認から送信までの間に回収された場合と、プローブ非対応の OS（確認なしで
        // 送る）である。ただし pid はその値のプロセスグループに生存メンバーがいる間は再利用されないため、孫が 1 つでも
        // 生きていれば宛先は自分のグループのままで、誤配送は「グループが空になり、かつ再利用された pid が
        // 新しいグループのリーダーになった」場合に限られる。`waitpid` の失敗を観測した後は終端
        // （[`Self::mark_lost`]）にし、以後はグループ宛てを含めて何も送らない。
        // 自発終了の観測後の送信（`try_wait`）が既に失敗していた場合も引き継ぐ（#1604）。
        #[cfg(unix)]
        let group_failed = self.group_kill_failed_after_exit
            || (!self.leader_reaped
                && kill_group_retrying_eperm(c.id())
                    .err()
                    .is_some_and(|e| !group_kill_tolerated(&e)));
        #[cfg(not(unix))]
        let group_failed = false;
        // kill の前に終了済みかを確認し、自発終了の状態をそのまま拾う（kill との競合窓を狭める）。
        // 失敗（他所で回収済み等）なら以後 kill を送らない（再利用された pid・pgid を撃たない。fail-closed）。
        match c.try_wait() {
            Ok(Some(status)) => {
                self.release_reaped();
                if group_failed {
                    return Reap::GroupKillFailed;
                }
                return Reap::Reaped(status);
            }
            Ok(None) => {}
            // グループ停止の失敗は、リーダーを誰が回収したかと無関係に孫が残り得るため優先して返す。
            Err(_) => {
                self.mark_lost();
                if group_failed {
                    return Reap::GroupKillFailed;
                }
                return Reap::Lost;
            }
        }
        // setsid / setpgid でグループを抜けた plugin 本体も確実に止めるフォールバック。
        let _ = c.kill();
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match c.try_wait() {
                Ok(Some(status)) => {
                    self.release_reaped();
                    if group_failed {
                        return Reap::GroupKillFailed;
                    }
                    return Reap::Reaped(status);
                }
                Ok(None) => {}
                // kill の後に他所で回収された（ECHILD）等。`Child` を残すと `Drop` が再び kill するため手放す。
                // グループ停止の失敗は `Ok(Some)` と同じく優先して返す（孫が残り得る）。
                Err(_) => {
                    self.mark_lost();
                    if group_failed {
                        return Reap::GroupKillFailed;
                    }
                    return Reap::Lost;
                }
            }
            if start.elapsed() >= PLUGIN_REAP_TIMEOUT {
                return Reap::Unreaped;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(POLL_MAX);
        }
    }

    /// 終了を `limit` まで待つ。終了していれば状態を返し、猶予超過なら強制終了する。
    /// 強制終了後に回収した終了状態は [`classify_reaped`] で分類する（`Killed` と決め打ちしない）。
    fn wait_or_kill(&mut self, limit: Duration) -> PluginTermination {
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match self.try_wait() {
                Ok(Some(status)) => {
                    self.release_reaped();
                    // 自発終了の観測後のグループ送信が失敗した（#1604）。孫の停止を保証できないため成功扱いにしない。
                    if self.group_kill_failed_after_exit {
                        return PluginTermination::GroupKillFailed;
                    }
                    return PluginTermination::Exited {
                        code: status.code(),
                    };
                }
                Ok(None) => {}
                Err(_) => break,
            }
            if start.elapsed() >= limit {
                break;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(POLL_MAX);
        }
        termination_after_kill(self.kill_and_reap())
    }
}

/// 終了猶予の超過後に行った [`ChildGuard::kill_and_reap`] の結果を終了状況へ写す（PLUG-7・REPAIR-5）。
///
/// グループ停止の失敗（直接の子は回収済み）は未回収の子と区別して保つ。`Unreaped` へ畳むと、呼び出し側が
/// 回収済みの子を「回収できなかった」と誤って報告するため（#1311）。
fn termination_after_kill(reap: Reap) -> PluginTermination {
    match reap {
        Reap::Reaped(status) => classify_reaped(status),
        // 孫の停止を保証できないため成功扱いにしないが、直接の子は回収済みなので未回収にもしない。
        Reap::GroupKillFailed => PluginTermination::GroupKillFailed,
        // 他所で回収された。孤児ではないが終了状態は失われたため、終了コード不明の終了として返す
        // （呼び出し側で成功扱いにならない。`call_once` は `Unavailable`、常駐の終了は `exited_error`。#1513）。
        Reap::Lost => PluginTermination::Exited { code: None },
        // 既に回収済みのガードに対して呼ばれることはないが、終了状態が不明なため成功扱いしない。
        Reap::AlreadyReaped | Reap::Unreaped => PluginTermination::Unreaped,
    }
}

/// `Drop` 時の `Reap` を記録対象へ写す。孫が残り得る `GroupKillFailed` と未回収の `Unreaped` だけが対象で、
/// `Lost`（他所で回収済み。孤児ではない）や回収成功は記録しない。
fn drop_failure(reap: Reap, pid: Option<u32>) -> Option<ChildCleanupFailure> {
    match reap {
        Reap::GroupKillFailed => Some(ChildCleanupFailure::GroupKillFailed),
        Reap::Unreaped => Some(ChildCleanupFailure::Unreaped { pid }),
        Reap::Reaped(_) | Reap::AlreadyReaped | Reap::Lost => None,
    }
}

impl ChildGuard {
    /// `Drop` の本体。後始末の失敗があれば `emit` を 1 回だけ呼ぶ。
    ///
    /// 報告済み（`reported_unreaped`）のときは何もしない。`Unreaped` を記録したら報告済みにして登録を
    /// 解放し、以後の `Drop` で再記録・再 kill をしない（`unreaped_error` と同じ扱い）。
    ///
    /// `Drop` の前に子を手放していた（`child` が `None`。回収済み・終端）ときも何もしない。手放すのは明示的な
    /// 経路（`wait_or_kill`・`kill_and_reap` の呼び出し側・常駐の `call` / `fail_session`）だけで、そこで
    /// 残った失敗（自発終了の観測後のグループ送信の失敗の印 `group_kill_failed_after_exit` を含む）は既に
    /// 呼び出し側へ返している。ここで `kill_and_reap` を呼ぶと印から `GroupKillFailed` が再び返り、同じ
    /// 失敗を 2 回記録するため呼ばない（子を持たない `kill_and_reap` は何も送らないので後始末は変わらない）。
    fn finish_on_drop(&mut self, emit: &mut dyn FnMut(&ChildCleanupFailure)) {
        if self.reported_unreaped || self.child.is_none() {
            return;
        }
        let pid = self.pid();
        let reap = self.kill_and_reap();
        if let Some(failure) = drop_failure(reap, pid) {
            if matches!(failure, ChildCleanupFailure::Unreaped { .. }) {
                self.reported_unreaped = true;
                self.slot = None;
            }
            emit(&failure);
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `Result` を返せないため、ブロックしないことを保証できる経路（Linux の AF_UNIX socket）でだけ即時に
        // 1 回書き、書けなければ固定長の延期表へ積む。ホストが終了時に取り出して出す（#1673・REPAIR-4・
        // REPAIR-5・PLUG-7）。スレッドもロックも確保も残さない。
        self.finish_on_drop(&mut |rec| {
            record_drop_failure(&io::stderr(), &GLOBAL_TABLE, *rec);
        });
    }
}

/// `EPERM` が出た間だけ短時間再送する上限（#1311・PLUG-7・REPAIR-5）。
#[cfg(unix)]
const GROUP_KILL_EPERM_RETRY: Duration = Duration::from_millis(200);

/// プロセスグループへ `SIGKILL` を送る。`EPERM` のときだけ [`GROUP_KILL_EPERM_RETRY`] まで再送する。
///
/// macOS は spawn 直後で plugin 本体が `exec` 中の窓にも `kill(2)` が `EPERM` を返すことがあり、この一過性の
/// 失敗を 1 回で確定すると生存中のグループを `GroupKillFailed` と誤報し、直後の `Child::kill` も同じ窓で
/// 失敗して回収できなくなる。窓は短いので再送で解消する。ゾンビのみのグループの `EPERM` は解消しないため、
/// 上限後は最後のエラーをそのまま返し、呼び出し側が `GroupKillFailed` として報告する（成功扱いにしない）。
/// 呼び出し側の不変条件（リーダー未回収）は [`crate::sys::kill_process_group`] と同じ。
#[cfg(unix)]
fn kill_group_retrying_eperm(pgid: u32) -> io::Result<()> {
    const EPERM: i32 = 1;
    // テスト専用: 非特権では再現できない許容外のエラーを注入する（本番ビルドには存在しない）。
    #[cfg(test)]
    if let Some(e) = tests::FORCED_GROUP_KILL_ERRNO.with(|c| c.get()) {
        return Err(io::Error::from_raw_os_error(e));
    }
    let start = Instant::now();
    let mut interval = Duration::from_millis(1);
    loop {
        match send_group_kill(pgid) {
            Err(e)
                if e.raw_os_error() == Some(EPERM) && start.elapsed() < GROUP_KILL_EPERM_RETRY =>
            {
                std::thread::sleep(interval);
                interval = (interval * 2).min(POLL_MAX);
            }
            other => return other,
        }
    }
}

/// グループ送信の唯一の窓口（テストでは送信回数を数え、「送った / 送っていない」を観測できる）。
#[cfg(unix)]
fn send_group_kill(pgid: u32) -> io::Result<()> {
    #[cfg(test)]
    GROUP_KILL_SENDS.with(|c| c.set(c.get() + 1));
    crate::sys::kill_process_group(pgid)
}

// テスト専用: 現在のスレッドで [`send_group_kill`] を呼んだ回数。
#[cfg(all(test, unix))]
thread_local! {
    static GROUP_KILL_SENDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// 自発終了を観測した（ゾンビのまま未回収の）リーダーのグループへ `SIGKILL` を 1 回送り、孫の停止を
/// 保証できない失敗なら true を返す（#1604・PLUG-7・REPAIR-5）。
///
/// リーダーが終了済みでも同じグループの孫は `exec` 中であり得て、macOS の一過性 `EPERM` は孫にも当てはまる。
/// 最初の `EPERM` で諦めると `SIGKILL` が孫に届かないままリーダーを回収し、回収後は再送できない。そのため
/// [`kill_group_retrying_eperm`] と同じ仕組みで `EPERM` を [`GROUP_KILL_EPERM_RETRY`] まで再送してから判断する。
/// 再送を尽くしても残る macOS の `EPERM` は、孫がいない（ゾンビだけの）グループと区別できない
/// （`killpg` はゾンビを除いて数える）。従来この経路は何も送らず何も報告しなかったため、許容しても退行では
/// ない（権限外の孫は元から保証対象外。区別には生存者の列挙が要り、将来課題）。ゾンビのみの場合は
/// 上限（200ms）まで待つことになる（macOS のみ・自発終了の観測時のみ）。Linux はゾンビのリーダーへの送信が
/// 成功するため `EPERM` を許容しない。許容するのは [`group_kill_tolerated`] と、この macOS の `EPERM` である。
#[cfg(unix)]
fn kill_group_after_exit(pgid: u32) -> bool {
    const EPERM: i32 = 1;
    match kill_group_retrying_eperm(pgid) {
        Ok(()) => false,
        Err(e) => {
            let macos_zombie_only = cfg!(target_os = "macos") && e.raw_os_error() == Some(EPERM);
            !(group_kill_tolerated(&e) || macos_zombie_only)
        }
    }
}

/// プロセスグループへの `SIGKILL` 送信エラーのうち、グループに生存者がいないことを示すものか。
///
/// `ESRCH`（グループが空）は正常。`EPERM` はどの OS でも許容しない。macOS ではゾンビのみのグループでも
/// 生存者への送信権限不足（setuid 実行ファイル経由で別 UID に変わった孫など）でも `EPERM` になり、再送後も
/// 両者を区別できないため、生存者不在の証明として扱わず、孫の停止を保証できない失敗として呼び出し側
/// （`kill_and_reap`）が `GroupKillFailed` として報告する（PLUG-7・REPAIR-5）。`Unsupported` はグループ送信を持たない unix
/// （Linux・macOS 以外）で、送信自体ができないことと直接の子の回収成否は別問題のため許容し、
/// `Child::kill` による直接の子の kill・回収だけにフォールバックする（孫の回収は保証しない。この環境では
/// 回収済みの pid を未回収として報告しない。PLUG-7・#1311）。それ以外（`InvalidInput` 等）は孫の停止を
/// 保証できず、同じく `GroupKillFailed` として報告する（直接の子も回収できなかった場合だけ `Unreaped`）。
#[cfg(unix)]
fn group_kill_tolerated(e: &io::Error) -> bool {
    const ESRCH: i32 = 3;
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    e.raw_os_error() == Some(ESRCH)
}

/// [`ChildGuard::kill_and_reap`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reap {
    /// 今回の呼び出しで回収した。終了状態は子の自発終了・こちらの kill のどちらの場合もある。
    Reaped(ExitStatus),
    /// 既に回収済みで保持している子がない。
    AlreadyReaped,
    /// 直接の子は回収済み（pid は解放済みで報告対象にしない）だが、グループ宛て SIGKILL が許容外の
    /// エラーで失敗し、孫の停止を保証できない。呼び出し側は `Unreaped`（未回収の子）へ畳まず、元の
    /// エラーに代えて [`group_kill_failed_error`] を返す（PLUG-7・REPAIR-5）。
    GroupKillFailed,
    /// kill 失敗または期限超過で回収を確認できなかった（孤児の可能性）。
    Unreaped,
    /// `waitpid` が失敗した（主に `ECHILD`＝契約外の回収者による回収）。終了状態は失われ、pid は再利用
    /// され得るため、以後 kill も回収もしない終端（[`ChildGuard::mark_lost`]）。自プロセスの子としては
    /// 残っていないため孤児の報告（[`unreaped_error`]）はしない。
    Lost,
}

impl Reap {
    /// 子が残っておらず（回収を確認できた、または他所で回収済み）、グループ停止も失敗していないか。
    /// `GroupKillFailed` は孫の停止を保証できないため偽（呼び出し側は [`group_kill_failed_error`] で後始末の
    /// 失敗として報告する）。本体の経路は各結果を明示的に場合分けし、本関数はテストの照合にだけ使う。
    #[cfg(test)]
    fn is_reaped(self) -> bool {
        matches!(self, Self::Reaped(_) | Self::AlreadyReaped | Self::Lost)
    }
}

/// 強制終了を試みた後に回収した終了状態を分類する（PLUG-7・REPAIR-5）。
///
/// 終了猶予の境界では、最後の `try_wait` と `kill` の間に子が自発終了し得る。その場合に回収される
/// のは子自身の終了状態であり、`Killed`（成功扱い）にすると非ゼロ終了を見逃す。そのため終了コードを
/// 持つ状態と `SIGKILL` 以外のシグナルによる終了は `Exited` として返し、成功 / 失敗の判定を
/// `call_once` 側の終了コード検査へ委ねる。`SIGKILL` による終了のみ `Killed` とする
/// （外部からの `SIGKILL` とこちらの kill は区別できないが、どちらも kill を試みた後の強制終了である）。
fn classify_reaped(status: ExitStatus) -> PluginTermination {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal() == Some(crate::sys::SIGKILL) {
            return PluginTermination::Killed;
        }
        PluginTermination::Exited {
            code: status.code(),
        }
    }
    // 非 unix では listener を bind できず子を spawn しないため到達しない。終了コード 0 の自発終了
    // だけを `Exited` とし、それ以外は強制終了（`TerminateProcess` 相当）と区別できないため
    // `Killed` として扱う。
    #[cfg(not(unix))]
    {
        match status.code() {
            Some(0) => PluginTermination::Exited { code: Some(0) },
            _ => PluginTermination::Killed,
        }
    }
}

/// 終端（[`ChildGuard::mark_lost`]）後の [`ChildGuard::try_wait`] が返すエラー（呼び出し側は内容を解釈しない）。
fn lost_error() -> io::Error {
    io::Error::other("plugin child process is no longer tracked")
}

fn remaining(deadline: Instant) -> Result<Duration, PluginError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => Ok(d),
        _ => Err(timeout_error()),
    }
}

fn timeout_error() -> PluginError {
    PluginError::new(PluginErrorCode::Timeout, "one-shot plugin call timed out")
}

/// 残り時間を 1 往復の期限へ変換する。都度起動と常駐の往復から呼ばれるため、上限は `RpcTimeout` 自身の
/// 上限 [`UDS_RPC_TIMEOUT_MAX`] で切る（#2608）。
fn rpc_timeout(remaining: Duration) -> Result<RpcTimeout, PluginError> {
    RpcTimeout::new(remaining.min(UDS_RPC_TIMEOUT_MAX))
}

/// stderr 収集の準備で失敗した `io::Error` を写す。ゲート待ちの期限切れ（`TimedOut`）は `Timeout`、
/// それ以外は `Internal`（`message` 付き）にする（REPAIR-5。`spawn_gate::create_fds` の契約）。
/// 期限切れ時の `Timeout` の文言は呼び出し側（都度起動・常駐）が `on_timeout` で与える。
fn stderr_prepare_error(
    e: &io::Error,
    message: &'static str,
    on_timeout: fn() -> PluginError,
) -> PluginError {
    if e.kind() == io::ErrorKind::TimedOut {
        return on_timeout();
    }
    PluginError::new(PluginErrorCode::Internal, message)
}

fn spawn_error(e: &io::Error) -> PluginError {
    let (code, msg) = match e.kind() {
        io::ErrorKind::NotFound => (PluginErrorCode::NotFound, "plugin program not found"),
        io::ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied spawning plugin program",
        ),
        io::ErrorKind::TimedOut => (
            PluginErrorCode::Timeout,
            "timed out waiting to spawn plugin program",
        ),
        _ => (
            PluginErrorCode::Unavailable,
            "failed to spawn plugin program",
        ),
    };
    PluginError::new(code, msg)
}

/// plugin を 1 回起動して 1 往復し、終了を確認して回収する（PLUG-7・REPAIR-5）。
///
/// 流れ: 一意名で listener を bind -> 子を spawn -> 接続を受け付け -> `request` 送信 -> 応答受信 ->
/// 接続を閉じて子の終了を待つ。spawn から応答受信までが `timeout` の合計期限。接続前に子が
/// 終了した場合は期限を待たず `Unavailable`。応答は得たが子が [`PLUGIN_EXIT_TIMEOUT`] 内に
/// 終了しなかった場合は強制終了し、`Ok` と [`PluginTermination::Killed`] を返す。応答後に非ゼロ・
/// シグナルで終了した場合は `Unavailable`、回収を確認できない場合は `Internal` を返す（このときだけ
/// 子が残っている可能性がある。メッセージに子の pid を含み、その子は以後回収しない。モジュール冒頭の
/// 契約を参照）。
///
/// stderr の読み取りスレッドは戻るまでに停止させる。停止を確認できなかった場合は
/// [`PluginStderr::reader_stopped`] が false になる。
/// 非 unix では listener の bind が `Unimplemented` を返し、子は spawn されない。
///
/// plugin の stderr は親へ継承させず [`OneShotOutcome::stderr`] で返す。本関数が親の stderr へ出す
/// 構造化ログには、plugin の stderr の内容は含めず件数のみ載せる。失敗時の内容が必要な呼び出し側は
/// [`call_once_observed`] の [`OneShotRecord::stderr`] を使う。
///
/// `audit` は受付で拒否した接続（UID・pid の不一致・取得失敗）の監査イベントの受け手で、拒否 1 件に
/// つき 1 回、同期で呼ばれる（PLUG-12・SEC-4・TASK-124.5）。必須で、既定の出力先は無い（出力・永続化は
/// 呼び出し側の責務。`crate::audit` のモジュール doc）。
/// 別 UID・別 pid の接続は切断して子の接続を待ち続けるが、その拒否が合算で
/// [`crate::transport::UDS_ACCEPT_PEER_REJECTION_LIMIT`] 件を超えると `PermissionDenied` で失敗する
/// （UID・pid の取得失敗は即エラー。#1861）。peer 認証による拒否かどうかは、返るエラーのコードでなく
/// `audit` に渡る `PeerAuthRejectReason` で判別する。
pub fn call_once(
    plugin: &PluginLaunchSpec,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
) -> Result<OneShotOutcome, PluginError> {
    call_once_observed(plugin, request, timeout, audit, &mut |record| {
        use std::io::Write;
        // 構造化ログ（JSON Lines）を stderr へ 1 行出す。書き込み失敗は呼び出し結果に影響させない。
        let _ = writeln!(io::stderr(), "{}", record.to_json_line());
    })
}

/// 1 回の [`call_once`] の観測記録（成功 / 失敗とレイテンシ。REPAIR-4）。
///
/// 呼び出し側（core の plugin proxy 等）が `observer` で受け取り、成功 / 失敗件数とレイテンシ分布へ
/// 集計する。`fandhe-container-core` の `OpRecorder` は依存方向（`core -> plugin`）のため本 crate から
/// 参照できないので、記録の受け渡しは本型で行う。都度起動専用のため名前を保つ（常駐の対応物は
/// `ResidentCallRecord`。#2608）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OneShotRecord {
    /// 操作名（固定値 `plugin.call_once`）。
    pub operation: &'static str,
    /// 成功したか。
    pub success: bool,
    /// 失敗時の機械可読な `code`（ERR-1）。成功時は `None`。
    pub error_code: Option<&'static str>,
    /// 開始から戻るまでの所要時間（子の回収待ち・stderr の収集待ちを含む）。
    pub elapsed: Duration,
    /// plugin が stderr へ書いた内容（untrusted・上限つき）。成功・失敗のどちらでも渡す。
    /// [`Self::to_json_line`] には内容を含めず、件数と打ち切りの有無だけを出す。
    pub stderr: PluginStderr,
}

impl OneShotRecord {
    /// JSON Lines の 1 行（改行なし）へ符号化する。値はすべて固定文字列・数値・真偽値のみで、外部入力
    /// （plugin の stderr の内容を含む）を埋め込まない。stderr は出所を明示したキー
    /// （`plugin_stderr_*`）で件数・打ち切りの有無・読み取りスレッドの停止確認だけを出す。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{c}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{},\
             \"plugin_stderr_bytes\":{},\"plugin_stderr_truncated\":{},\
             \"plugin_stderr_complete\":{},\"plugin_stderr_reader_stopped\":{}}}",
            self.operation,
            self.success,
            code,
            self.elapsed.as_micros(),
            self.stderr.total_bytes(),
            self.stderr.is_truncated(),
            self.stderr.is_complete(),
            self.stderr.reader_stopped()
        )
    }
}

/// [`call_once`] と同じ処理を行い、終了時に 1 件の [`OneShotRecord`] を `observer` へ渡す（REPAIR-4）。
///
/// 成功・失敗のどの終了経路でも必ず 1 回だけ呼ばれる。`observer` は呼び出しスレッド上で同期的に
/// 実行されるため、長時間ブロックしないこと。`audit` は [`call_once`] と同じ（peer 認証の拒否イベントの
/// 受け手。必須）。
pub fn call_once_observed(
    plugin: &PluginLaunchSpec,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
    observer: &mut dyn FnMut(&OneShotRecord),
) -> Result<OneShotOutcome, PluginError> {
    let start = Instant::now();
    let (result, stderr) = call_once_inner(plugin, request, timeout, audit, &PLUGIN_REGISTRY);
    observer(&OneShotRecord {
        operation: "plugin.call_once",
        success: result.is_ok(),
        error_code: result.as_ref().err().map(|e| e.code().as_str()),
        elapsed: start.elapsed(),
        stderr: stderr.clone(),
    });
    result.map(|(response, termination)| OneShotOutcome {
        response,
        termination,
        stderr,
    })
}

/// plugin 本体（直接の子）を親の生存に結び付ける（Linux のみ。`PR_SET_PDEATHSIG`。#1514・#1403 の方式 B・
/// PLUG-7・REPAIR-5・CORE-1）。都度起動 / 常駐の spawn 直前に呼び、spawn 箇所へ cfg を持ち込まない。
/// Linux 以外では何もしない（macOS に同等の機構はなく残留し得る。Windows は対象外）。
#[cfg(target_os = "linux")]
fn bind_to_parent_lifetime(cmd: &mut Command) -> Result<(), PluginError> {
    crate::sys::set_parent_death_sigkill(cmd, std::process::id()).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to configure plugin parent-death signal",
        )
    })
}

/// Linux 以外では親死亡シグナルを設定しない（従来どおり起動する）。
#[cfg(not(target_os = "linux"))]
fn bind_to_parent_lifetime(_cmd: &mut Command) -> Result<(), PluginError> {
    Ok(())
}

/// 都度起動・常駐の両モードが共用する plugin の `Command` を組み立てる（起動条件を 1 か所に置く。
/// REPAIR-1）。子の環境は `env_clear()` 後に [`PluginLaunchSpec::with_env`] で検証済みの組、最後に
/// [`PLUGIN_SOCKET_ENV`]（socket の変数が必ず勝つ）、stdin / stdout は null、stderr は
/// 呼び出し側が用意した収集用の端、Linux では親死亡シグナルを設定する。
///
/// 実行するプログラムは起動対象から決める（#1856・PLUG-11）。Linux は保持した fd の実体を
/// `/proc/self/fd/<N>` 経由で実行し（実行できなければ `FailedPrecondition`。パスへ縮退しない）、
/// Linux 以外の unix はパス（`exec_path`）で起動するが、spawn の直前に `lstat` で dev / ino を保持 fd と
/// 照合し、違えば `FailedPrecondition` で子を spawn しない（#1866。常駐の再起動でも毎回通る）。
/// 非 unix はパスで起動する（listener の bind が先に `Unimplemented` を返し子は spawn されない）。
/// `argv[0]` は OS を問わず実体の正規パス。
fn plugin_command(
    plugin: &PluginLaunchSpec,
    socket_path: &Path,
    child_stderr: Stdio,
) -> Result<Command, PluginError> {
    #[cfg(target_os = "linux")]
    let program = launch_target::linux_fd_exec_path(&plugin.target, Path::new("/proc/self/fd"))?;
    #[cfg(all(unix, not(target_os = "linux")))]
    let program = launch_target::checked_exec_path(&plugin.target)?;
    #[cfg(not(unix))]
    let program = plugin.target.exec_path().to_path_buf();

    let mut cmd = Command::new(program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0(plugin.target.exec_path());
    }
    cmd.args(&plugin.args)
        .env_clear()
        .envs(plugin.env.iter())
        .env(PLUGIN_SOCKET_ENV, socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(child_stderr);
    bind_to_parent_lifetime(&mut cmd)?;
    Ok(cmd)
}

/// spawn の失敗を起動対象の経路に合わせて写す。Linux は fd を保持しているのでファイル不在
/// （`NotFound`）はあり得ず、確認後に `/proc` が使えなくなった等の競合として fd 経由の起動失敗にする。
/// Linux 以外の unix の `NotFound` は、直前の `lstat` 確認を通った後にパスが消えた（残余の窓）ことなので、
/// 確認での拒否と同じ「検証したファイルを指していない」エラーにする（#1866）。
fn launch_spawn_error(e: PluginError) -> PluginError {
    #[cfg(target_os = "linux")]
    if e.code() == PluginErrorCode::NotFound {
        return launch_target::fd_launch_error();
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    if e.code() == PluginErrorCode::NotFound {
        return launch_target::path_identity_error();
    }
    e
}

/// listener の bind・子の spawn・stderr の収集・往復・回収までを行う。戻り値の第 2 要素は、
/// 成功・失敗のどちらでも子の回収後に確定した stderr の収集結果（spawn 前の失敗は空）。
fn call_once_inner(
    plugin: &PluginLaunchSpec,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
    registry: &'static Registry,
) -> (
    Result<(Frame, PluginTermination), PluginError>,
    PluginStderr,
) {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let Some(deadline) = Instant::now().checked_add(timeout.as_duration()) else {
        return (Err(timeout_error()), PluginStderr::empty());
    };

    // 異常終了で残るこの名前の socket とロックファイルは、runtime directory の初期化時に掃除される
    // （`RuntimeDir::sweep_one_shot_leftovers`。#1310）。呼び出しごとの列挙で境界レイテンシを増やさない。
    let name = format!(
        "oneshot-{}-{}.sock",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let listener = match UdsListener::bind_before(&plugin.socket_dir.join(name), deadline) {
        Ok(l) => l,
        Err(e) => return (Err(e), PluginStderr::empty()),
    };

    // stderr は親へ継承させない（plugin が親の stderr へ任意の量・内容を書けてしまうため）。
    let (child_stderr, reader) = match stderr_channel(deadline) {
        Ok(pair) => pair,
        Err(e) => {
            return (
                Err(stderr_prepare_error(
                    &e,
                    "failed to prepare capturing plugin stderr",
                    timeout_error,
                )),
                PluginStderr::empty(),
            );
        }
    };
    // `Command` は文の終わりで drop され、親側に書き込み端は残らない（終端の検出を妨げない）。
    let spawned = {
        let mut cmd = match plugin_command(plugin, listener.path(), child_stderr) {
            Ok(c) => c,
            Err(e) => return (Err(e), PluginStderr::empty()),
        };
        spawn_registered(&mut cmd, registry, deadline).map_err(launch_spawn_error)
    };
    let mut guard = match spawned {
        Ok(g) => g,
        Err(e) => return (Err(e), PluginStderr::empty()),
    };

    // 接続待ちより前に読み取りを始める（子が接続前に大量に書いても詰まらせない）。
    let capture = match StderrCapture::attach(reader, deadline) {
        Ok(c) => c,
        // 読み取り手がいないまま子を走らせるとバッファが埋まって子が詰まるため、往復せず回収する。
        Err(e) => {
            drop(listener);
            let error = reap_after_failure(
                &mut guard,
                stderr_prepare_error(&e, "failed to start capturing plugin stderr", timeout_error),
            );
            return (Err(error), PluginStderr::empty());
        }
    };
    let result = exchange_and_reap(&mut guard, listener, request, deadline, audit);
    // 子の回収後に収集結果を受け取る。子が終了していれば書き込み端は閉じており即座に完了する。
    // 戻る時点で読み取りスレッドは停止している（停止を確認できなければ結果に記録する）。
    let stderr = capture.finish(PLUGIN_STDERR_DRAIN_TIMEOUT);
    (result, stderr)
}

/// 登録表のスロットを確保してから子を spawn し、pid を登録したガードを返す（#1513・PLUG-7）。
///
/// unix では子を新しいプロセスグループ（pgid == 子の pid）で起動する（`process_group(0)`。#1311）。
/// 都度起動・常駐の両モードがこの関数を共用するので 2 か所の起動条件は食い違わない。`ChildGuard::kill_and_reap` が
/// グループ全体へ SIGKILL を送って plugin の孫を残さず、登録表のシグナル転送（#1513）も `kill(-pid)` で
/// 孫まで届く。`PR_SET_PDEATHSIG`（#1514。`bind_to_parent_lifetime`）とは独立に併用できる（前者は `pre_exec`、
/// 後者は fork 時のグループ設定で干渉しない）。
/// Windows にプロセスグループ単位の kill は無く（Job Object は別タスク）、unix transport も無いため対象外。
///
/// pgid 確立の同期性: `Command::spawn` は子の `exec` 成功（または失敗の報告）を CLOEXEC パイプで待ってから
/// 返り、`process_group(0)` の `setpgid(0, 0)` は `pre_exec` フックより前に子の `exec` 前で完了する。
/// このため `spawn` 復帰時点で pgid == 子の pid は確立済みで、`kill_and_reap` の `killpg(pid)` が
/// 親のグループや無関係なグループへ届くことはない（`PR_SET_PDEATHSIG` の fork 経路でも同じ。
/// 回帰テスト `plug7_spawn_registered_establishes_own_process_group`）。
///
/// 確保を spawn より前に行うので、表が満杯のときは子を一切起動せず `ResourceExhausted` で拒否する
/// （fail-closed。追跡できない子を作らない）。spawn の失敗・pid の範囲外ではスロットを解放し、
/// 起動済みの子は kill・回収する。`registry` は本番では [`PLUGIN_REGISTRY`]（テストは局所の表）。
fn spawn_registered(
    cmd: &mut Command,
    registry: &'static Registry,
    deadline: Instant,
) -> Result<ChildGuard, PluginError> {
    let mut slot = registry.reserve()?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    // 非原子の fd 生成と排他で spawn する（`spawn_gate`。PLUG-7・SEC-1・#3139）。非 unix は fd を作らない。
    #[cfg(unix)]
    let spawned = crate::spawn_gate::spawn(deadline, cmd);
    #[cfg(not(unix))]
    let spawned = {
        let _ = deadline;
        cmd.spawn()
    };
    let child = spawned.map_err(|e| spawn_error(&e))?;
    let pid = child.id();
    // activate が失敗した場合は guard の Drop が子を kill・回収する。
    let guard = ChildGuard::new(child);
    slot.activate(pid)?;
    Ok(guard.with_slot(slot))
}

/// 応答前の失敗経路で子を明示的に kill・回収する。回収を確認できなければ、元のエラーではなく
/// 回収失敗（`Internal`）を返す（孤児の可能性を呼び出し側へ伝える。REPAIR-5・PLUG-7）。
///
/// プロセスグループの停止失敗（`GroupKillFailed`）では、元のエラーの `code` を保ち、`message` に付記を
/// 加える（[`with_group_kill_failure`]。#1311）。この経路は plugin が接続後・応答前に終了した場合
/// （最頻の失敗経路）を含み、子は未回収のゾンビのまま `kill_and_reap` に入る。macOS はゾンビだけの
/// グループへの `killpg` に `EPERM` を返すため、孫がいなくても付記が付き得るが、元の分類
/// （`Unavailable` 等）は失わない。Linux はゾンビへの送信が成功するため付記は付かない。
fn reap_after_failure(guard: &mut ChildGuard, error: PluginError) -> PluginError {
    match guard.kill_and_reap() {
        // 他所で回収された（`Lost`。#1513）子は自プロセスの子として残っていないため、元のエラーを返す。
        Reap::Reaped(_) | Reap::AlreadyReaped | Reap::Lost => error,
        Reap::GroupKillFailed => with_group_kill_failure(error, "a failed exchange"),
        Reap::Unreaped => unreaped_error(guard, "a failed exchange"),
    }
}

/// 元のエラーの `code` と `message` を保ったまま、プロセスグループを停止できず孫が残り得ることを
/// `message` に付記する（#1311・PLUG-7・REPAIR-5）。付記が上限（[`crate::error::PLUGIN_ERROR_MESSAGE_MAX_BYTES`]）
/// で切り捨てられないよう、元の `message` 側を文字境界で詰める。直接の子の pid は解放済みのため含めない。
pub(crate) fn with_group_kill_failure(error: PluginError, phase: &str) -> PluginError {
    let note = format!(
        "; additionally, the plugin process group could not be killed after {phase}, so descendant processes may remain"
    );
    let original = error.message();
    let mut end = original
        .len()
        .min(crate::error::PLUGIN_ERROR_MESSAGE_MAX_BYTES.saturating_sub(note.len()));
    while end > 0 && !original.is_char_boundary(end) {
        end -= 1;
    }
    let head = original.get(..end).unwrap_or_default();
    PluginError::new(error.code(), format!("{head}{note}"))
}

/// 直接の子は回収済みだが、プロセスグループ宛て SIGKILL が失敗し孫の停止を保証できないことを
/// 伝えるエラー（`Internal`）。元のエラーが無い経路（応答後・常駐の shutdown）で、後始末の失敗として
/// 呼び出し側へ返す（元のエラーがある経路は [`with_group_kill_failure`]。PLUG-7・REPAIR-5・#1311）。
/// 直接の子の pid は解放済みのため含めない。
pub(crate) fn group_kill_failed_error(phase: &str) -> PluginError {
    PluginError::new(
        PluginErrorCode::Internal,
        format!(
            "plugin process group could not be killed after {phase}; the direct child was reaped but descendant processes may remain"
        ),
    )
}

/// 回収を確認できなかった子についてのエラー（`Internal`）。呼び出し側が未回収の子を特定できるよう
/// pid を含める（pid は自プロセスが起動した子のもので、外部入力ではない）。
///
/// 報告した pid を以後も有効に保つため、`guard` に報告済みの印を付けて `Drop` での回収を止める。
fn unreaped_error(guard: &mut ChildGuard, phase: &str) -> PluginError {
    let message = match guard.pid() {
        Some(pid) => {
            guard.reported_unreaped = true;
            // 以後は回収しないが、SIGKILL は送信済み。スロットのリークを防ぐため解放する。
            guard.slot = None;
            format!("plugin process (pid {pid}) could not be reaped after {phase}")
        }
        None => format!("plugin process could not be reaped after {phase}"),
    };
    PluginError::new(PluginErrorCode::Internal, message)
}

/// 接続の受付・1 往復・子の回収を行う。`Ok` で戻る時点で子は回収済み。回収を確認できなかった場合は
/// `Internal`（[`unreaped_error`]）を返し、以後 `guard` はその子を回収しない。子は回収できたが
/// プロセスグループを停止できなかった場合は `Internal`（[`group_kill_failed_error`]）を返す。
fn exchange_and_reap(
    guard: &mut ChildGuard,
    listener: UdsListener,
    request: &Frame,
    deadline: Instant,
    audit: &mut dyn crate::audit::PeerAuthObserver,
) -> Result<(Frame, PluginTermination), PluginError> {
    // 受付・往復はブロック内で完結させ、抜けた時点で接続を閉じて子に EOF を見せる
    // （続けて listener を drop して socket を unlink してから終了を待つ）。
    let exchange = (|| -> Result<Frame, PluginError> {
        let child_pid = guard.pid().ok_or_else(|| {
            PluginError::new(
                PluginErrorCode::Internal,
                "plugin process handle is missing",
            )
        })?;
        let mut stream = {
            let left = remaining(deadline)?;
            // 接続待ちの間は子の早期終了を確認し、期限を待たず Unavailable にする。
            // 応答者は spawn した子の pid に限定する（同一 UID の別プロセスの先取りを防ぐ。PLUG-7）。
            let mut check_child = || match guard.try_wait() {
                Ok(None) => None,
                Ok(Some(_)) | Err(_) => Some(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "plugin exited before connecting",
                )),
            };
            listener.accept_peer_pid(left, child_pid, &mut check_child, audit)?
        };
        stream.write_frame(request, rpc_timeout(remaining(deadline)?)?)?;
        stream.read_frame(rpc_timeout(remaining(deadline)?)?)
    })();
    drop(listener);
    // 応答前のエラー経路でも、ここで子を明示的に kill・回収し、回収失敗を呼び出し側へ返す（REPAIR-5・PLUG-7）。
    let response = match exchange {
        Ok(r) => r,
        Err(e) => return Err(reap_after_failure(guard, e)),
    };
    let termination = guard.wait_or_kill(PLUGIN_EXIT_TIMEOUT);
    check_termination_after_response(guard, termination).map(|()| (response, termination))
}

/// 応答受信後の終了状況を検査する。回収を確認できない子（孤児の可能性）・グループ停止の失敗（孫が残る
/// 可能性）・異常終了（非ゼロ・シグナル）は成功扱いにしない（REPAIR-5・PLUG-7）。
///
/// グループ停止の失敗では直接の子は回収済みのため、未回収（[`unreaped_error`]）としては報告せず、
/// `guard` に報告済みの印も付けない（#1311）。
fn check_termination_after_response(
    guard: &mut ChildGuard,
    termination: PluginTermination,
) -> Result<(), PluginError> {
    match termination {
        PluginTermination::Unreaped => Err(unreaped_error(guard, "the response")),
        PluginTermination::GroupKillFailed => Err(group_kill_failed_error("the response")),
        PluginTermination::Exited { code: Some(0) } | PluginTermination::Killed => Ok(()),
        PluginTermination::Exited { .. } => Err(PluginError::new(
            PluginErrorCode::Unavailable,
            "plugin process exited abnormally after the response",
        )),
    }
}

#[cfg(test)]
mod tests {
    /// 試験用の十分遠い合計期限。
    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// REPAIR-5: stderr 準備のゲート待ちの期限切れは `Internal` ではなく `Timeout` に写す。
    #[test]
    fn repair5_stderr_prepare_timeout_maps_to_timeout() {
        let e = io::Error::new(io::ErrorKind::TimedOut, "gate");
        assert_eq!(
            stderr_prepare_error(&e, "m", timeout_error).code(),
            PluginErrorCode::Timeout
        );
        let e = io::Error::other("x");
        assert_eq!(
            stderr_prepare_error(&e, "m", timeout_error).code(),
            PluginErrorCode::Internal
        );
    }

    use super::*;

    thread_local! {
        /// `kill_group_retrying_eperm` へ注入する errno（スレッドローカルで並列テストに影響しない）。
        pub(super) static FORCED_GROUP_KILL_ERRNO: std::cell::Cell<Option<i32>> =
            const { std::cell::Cell::new(None) };
    }

    /// 他の試験と混ざらない専用の延期表（プロセス全体の表は共有しない）。
    // 使う試験は `cfg(unix)`・Linux 限定などで OS ごとに有効な集合が違い、Windows 等では
    // 呼び出し元が 1 つも残らず dead_code 警告になる。cfg を試験側と二重管理しないため抑止する。
    #[allow(dead_code)]
    fn local_table() -> &'static drop_report::DropReportTable {
        let slots: &'static [AtomicU64] = Box::leak(
            (0..8)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(drop_report::DropReportTable::over(slots)))
    }

    const GROUP_KILL_FAILED_LINE: &str = "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"group_kill_failed\"}";

    #[cfg(unix)]
    fn spawn_sleeper_group() -> ChildGuard {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        ChildGuard::new(child)
    }

    /// REPAIR-4・PLUG-7・#1605: Drop でグループ停止に失敗したとき、記録がちょうど 1 件出る。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_records_group_kill_failure_once() {
        let mut guard = spawn_sleeper_group();
        FORCED_GROUP_KILL_ERRNO.with(|c| c.set(Some(22)));
        let mut lines: Vec<String> = Vec::new();
        guard.finish_on_drop(&mut |rec| lines.push(rec.to_json_line()));
        FORCED_GROUP_KILL_ERRNO.with(|c| c.set(None));
        assert_eq!(lines, vec![GROUP_KILL_FAILED_LINE.to_string()]);
        // 直接の子はフォールバックの `Child::kill` で回収済み。
        assert_eq!(guard.pid(), None);
        // 2 回目は AlreadyReaped で記録しない。
        guard.finish_on_drop(&mut |rec| lines.push(rec.to_json_line()));
        assert_eq!(lines.len(), 1);
        drop(guard);
    }

    /// REPAIR-4・#1605: 通常の破棄は何も記録せず、子を回収する。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_of_running_child_records_nothing() {
        let mut guard = spawn_sleeper_group();
        let mut lines: Vec<String> = Vec::new();
        guard.finish_on_drop(&mut |rec| lines.push(rec.to_json_line()));
        assert!(lines.is_empty());
        assert_eq!(guard.pid(), None);
    }

    /// Drop 診断の試験用に、一時ディレクトリ直下へ新しいディレクトリを作る（REPAIR-12）。`create_dir` は既存の
    /// 名前（先置きされた symlink を含む）で失敗するため、予測可能な名前でも他者の置いたものを辿らない。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn drop_log_test_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "fc-droplog-{tag}-{}-{nanos}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// REPAIR-5・PLUG-7・#1605: 満杯の socket（ブロッキングのまま）でも診断出力が期限内に `WouldBlock` で戻る。
    #[test]
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn repair5_drop_log_does_not_block_on_full_socket() {
        // 満杯のソケットを stderr に見立てる。ブロックしない保証のある経路（MSG_DONTWAIT）で即座に戻る
        // （#1605・REPAIR-5・PLUG-7）。
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let chunk = [0u8; 4096];
        loop {
            match (&a).write(&chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill failed: {e}"),
            }
        }
        // 非ブロッキングに戻さない（ブロッキング fd なら無条件 write は永久に止まる状況）。
        a.set_nonblocking(false).unwrap();
        let start = Instant::now();
        let r = crate::sys::write_nonblocking(&a, GROUP_KILL_FAILED_LINE.as_bytes());
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        // `Drop` 経路の入口も同様に期限内に戻る。
        let start = Instant::now();
        let table = local_table();
        record_drop_failure(&a, table, ChildCleanupFailure::GroupKillFailed);
        assert!(start.elapsed() < Duration::from_millis(100));
        // 書けなかった記録は延期表へ積まれる（#1673）。
        assert_eq!(
            table.take().failures(),
            &[ChildCleanupFailure::GroupKillFailed]
        );
    }

    /// REPAIR-5・PLUG-7・#1605: 無名 pipe は `/proc` 経由の開き直し（絶対パスの解決が止まり得る）と `SIGPIPE` を
    /// 避けられないため書かず `Unsupported`。期限内に戻り、読み手には何も届かず、共有 fd も非ブロッキング化しない。
    #[test]
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn repair5_drop_log_discards_on_anonymous_pipe() {
        use std::io::Read;
        use std::os::unix::io::AsRawFd;
        let (mut r, w) = io::pipe().unwrap();
        let line = GROUP_KILL_FAILED_LINE.as_bytes();
        let start = Instant::now();
        let res = crate::sys::write_nonblocking(&w, line);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::Unsupported);
        let start = Instant::now();
        let table = local_table();
        record_drop_failure(&w, table, ChildCleanupFailure::GroupKillFailed);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(
            table.take().failures(),
            &[ChildCleanupFailure::GroupKillFailed]
        );
        // 共有 description のフラグ（`O_NONBLOCK` = 0o4000）は変わっていない。
        let flags_of = |fd: i32| {
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
            info.lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .map(|v| i64::from_str_radix(v.trim(), 8).unwrap())
                .unwrap()
        };
        assert_eq!(flags_of(w.as_raw_fd()) & 0o4000, 0);
        // 何も書かれていない（書き込み端を閉じた後の読み出しは即座に EOF の 0 バイト）。
        drop(w);
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, Vec::<u8>::new());
    }

    /// REPAIR-5・PLUG-7・#1605: 名前付き FIFO も書かず `Unsupported`（診断は捨て、読み手には何も届かない）。
    #[test]
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn repair5_drop_log_discards_on_named_fifo() {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        const O_NONBLOCK: i32 = 0o4000;
        let dir = drop_log_test_dir("fifo");
        let path = dir.join("fifo");
        let status = Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(status.success(), "mkfifo failed: {status}");
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(&path)
            .unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open(&path)
            .unwrap();
        let r = crate::sys::write_nonblocking(&writer, b"x\n");
        let mut buf = [0u8; 8];
        let read = reader.read(&mut buf);
        drop(writer);
        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    /// REPAIR-5・PLUG-7・#1605: 通常ファイルは待たない保証がないため書かず `Unsupported`（診断は捨てる）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn repair5_drop_log_discards_on_regular_file() {
        let dir = drop_log_test_dir("file");
        let path = dir.join("log");
        let f = std::fs::File::create_new(&path).unwrap();
        let r = crate::sys::write_nonblocking(&f, b"x\n");
        drop(f);
        let len = std::fs::metadata(&path).unwrap().len();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(len, 0);
    }

    /// REPAIR-5・PLUG-7・#1605: キャラクタデバイスは CUSE 等で open / write が止まり得るため書かず `Unsupported`。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn repair5_drop_log_discards_on_char_device() {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let r = crate::sys::write_nonblocking(&f, b"x\n");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_drop_log_writes_line_when_fd_ready() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().unwrap();
        let line = b"{\"event\":\"x\"}\n";
        assert_eq!(crate::sys::write_nonblocking(&a, line).unwrap(), line.len());
        let mut got = vec![0u8; line.len()];
        // 診断が届かない場合に無期限停止しないよう受信側に期限を設ける（REPAIR-5）。
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.read_exact(&mut got).unwrap();
        assert_eq!(got, line);
    }

    /// REPAIR-5・PLUG-7・#1605: macOS は socket でも書かず `Unsupported`（満杯のブロッキング socket への
    /// `send(MSG_DONTWAIT)` が戻らないことを CI で観測したため。診断は捨て、相手には何も届かない）。
    #[cfg(target_os = "macos")]
    #[test]
    fn repair5_drop_log_discards_on_socket_on_macos() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let r = crate::sys::write_nonblocking(&a, GROUP_KILL_FAILED_LINE.as_bytes());
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        b.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            b.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    /// REPAIR-4・#1673: AF_UNIX socket へ全部書けた記録は延期表へ積まない（重複させない）。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_drop_log_full_write_on_socket_not_deferred() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().unwrap();
        let table = local_table();
        record_drop_failure(&a, table, ChildCleanupFailure::GroupKillFailed);
        let want = format!("{GROUP_KILL_FAILED_LINE}\n");
        let mut got = vec![0u8; want.len()];
        // 診断が届かない場合に無期限停止しないよう受信側に期限を設ける（REPAIR-5）。
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.read_exact(&mut got).unwrap();
        assert_eq!(got, want.as_bytes());
        let p = table.take();
        assert_eq!(p.failures().len(), 0);
        assert_eq!(p.dropped(), 0);
    }

    /// REPAIR-4・REPAIR-5・#1673: 通常ファイル・キャラクタデバイスへは書かず、延期表へ積んで期限内に戻る。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn repair5_drop_log_defers_on_regular_file_and_char_device() {
        let dir = drop_log_test_dir("defer-file");
        let path = dir.join("log");
        let f = std::fs::File::create_new(&path).unwrap();
        let table = local_table();
        let start = Instant::now();
        record_drop_failure(&f, table, ChildCleanupFailure::Unreaped { pid: Some(4321) });
        assert!(start.elapsed() < Duration::from_millis(100));
        drop(f);
        let len = std::fs::metadata(&path).unwrap().len();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(len, 0);
        assert_eq!(
            table.take().failures(),
            &[ChildCleanupFailure::Unreaped { pid: Some(4321) }]
        );
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        record_drop_failure(&null, table, ChildCleanupFailure::GroupKillFailed);
        assert_eq!(
            table.take().failures(),
            &[ChildCleanupFailure::GroupKillFailed]
        );
    }

    /// REPAIR-4・#1673: 報告済みの `Unreaped` は `Drop` で再記録せず、延期表にも積まない。
    #[cfg(unix)]
    #[test]
    fn repair4_reported_unreaped_is_not_deferred() {
        let mut guard = spawn_sleeper_group();
        guard.reported_unreaped = true;
        let table = local_table();
        guard.finish_on_drop(&mut |rec| table.push(*rec));
        assert_eq!(table.take().failures().len(), 0);
        guard.reported_unreaped = false;
    }

    #[cfg(unix)]
    const DROP_REPORT_CHILD_ENV: &str = "FANDHE_DROP_REPORT_CHILD_1673";

    /// 往復試験の子の役（環境変数が無ければ何もしない）。実際の `Drop` を通し、期限内に戻ることを確かめ、
    /// 最後にプロセス全体の延期表を stderr へ出す（ホストの終了時の取り出しの模擬。#1673）。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_report_roundtrip_child_role() {
        if std::env::var_os(DROP_REPORT_CHILD_ENV).is_none() {
            return;
        }
        let guard = spawn_sleeper_group();
        FORCED_GROUP_KILL_ERRNO.with(|c| c.set(Some(22)));
        let start = Instant::now();
        drop(guard);
        let elapsed = start.elapsed();
        FORCED_GROUP_KILL_ERRNO.with(|c| c.set(None));
        assert!(elapsed < Duration::from_secs(5), "drop took {elapsed:?}");
        let _ = take_pending_child_cleanup_failures().write_json_lines(&mut io::stderr());
    }

    /// 子の役を `stderr` を向け先に付けて再実行し、期限内の正常終了を確かめる。
    #[cfg(unix)]
    fn run_roundtrip_child(stderr: Stdio) {
        run_child_role(
            "lifecycle::tests::repair4_drop_report_roundtrip_child_role",
            DROP_REPORT_CHILD_ENV,
            "1",
            stderr,
        );
    }

    /// テスト名 `test` の子の役を、環境変数 `env`=`value` と `stderr` の向け先を付けて再実行し、期限内の
    /// 正常終了を確かめる（子の役の assert が失敗すれば非ゼロ終了で検出する）。
    #[cfg(unix)]
    fn run_child_role(test: &str, env: &str, value: &str, stderr: Stdio) {
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(exe)
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(env, value)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let failure = loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    assert!(st.success(), "child failed: {st}");
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => break "child did not exit in time".to_string(),
                Err(e) => break format!("try_wait failed: {e}"),
            }
        };
        // `Child` の破棄は子を止めも回収もしないため、失敗を報告する前に SIGKILL を送り、有限の猶予で回収する
        // （検出対象の子がブロックしたまま残らないように。REPAIR-5・PLUG-7）。
        let _ = child.kill();
        let grace = Instant::now() + Duration::from_secs(5);
        let reaped = loop {
            match child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if Instant::now() < grace => std::thread::sleep(Duration::from_millis(10)),
                _ => break false,
            }
        };
        panic!("{failure} (killed child, reaped: {reaped})");
    }

    #[cfg(unix)]
    fn only_cleanup_lines(text: &str) -> Vec<String> {
        text.lines()
            .filter(|l| l.contains("plugin_child_cleanup"))
            .map(str::to_string)
            .collect()
    }

    /// REPAIR-4・REPAIR-5・PLUG-7・#1673: stderr が通常ファイルでも、Drop は期限内に戻り、終了時の取り出しで
    /// 記録がちょうど 1 行（全文一致）残る。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_report_roundtrip_regular_file() {
        let dir = drop_log_test_dir("roundtrip-file");
        let path = dir.join("stderr");
        let f = std::fs::File::create_new(&path).unwrap();
        run_roundtrip_child(Stdio::from(f));
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            only_cleanup_lines(&text),
            vec![GROUP_KILL_FAILED_LINE.to_string()]
        );
    }

    /// REPAIR-4・REPAIR-5・PLUG-7・#1673: stderr が pipe（読み手あり）でも記録がちょうど 1 行残る。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_report_roundtrip_pipe() {
        use std::io::Read;
        let (mut r, w) = io::pipe().unwrap();
        // 書き込み端が別プロセスに残ると EOF が来ないため、収集は完了を期限付きで待つ（REPAIR-5）。
        let (tx, rx) = std::sync::mpsc::channel();
        let _reader = std::thread::spawn(move || {
            let mut text = String::new();
            let res = r.read_to_string(&mut text).map(|_| text);
            let _ = tx.send(res);
        });
        run_roundtrip_child(Stdio::from(w));
        let text = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("pipe collection did not finish in time")
            .unwrap();
        assert_eq!(
            only_cleanup_lines(&text),
            vec![GROUP_KILL_FAILED_LINE.to_string()]
        );
    }

    /// REPAIR-4・#1673: stderr が AF_UNIX socket（Linux）なら Drop 時に即時に届き、取り出しで重複しない。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_drop_report_roundtrip_socket_not_duplicated() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().unwrap();
        // 継承された書き込み端が残っても無期限に待たない（REPAIR-5）。
        b.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        run_roundtrip_child(Stdio::from(std::os::fd::OwnedFd::from(a)));
        let mut text = String::new();
        b.read_to_string(&mut text).unwrap();
        assert_eq!(
            only_cleanup_lines(&text),
            vec![GROUP_KILL_FAILED_LINE.to_string()]
        );
    }

    #[cfg(unix)]
    const NONBLOCKING_CHILD_ENV: &str = "FANDHE_STDERR_NONBLOCKING_CHILD_1673";
    #[cfg(unix)]
    const NONBLOCKING_MARKER: &[u8] = b"{\"event\":\"nonblocking_marker_1673\"}\n";

    /// `write_stderr_nonblocking` の子の役（環境変数が無ければ何もしない）。値で期待する結果を受け取り、
    /// 1 回だけ書いて期限内に戻ることと結果の種別を確かめる（#1673・REPAIR-5）。
    #[cfg(unix)]
    #[test]
    fn repair5_write_stderr_nonblocking_child_role() {
        let Some(expect) = std::env::var_os(NONBLOCKING_CHILD_ENV) else {
            return;
        };
        let start = Instant::now();
        let r = write_stderr_nonblocking(NONBLOCKING_MARKER);
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_secs(5), "write took {elapsed:?}");
        match expect.to_str() {
            Some("written") => assert_eq!(r.unwrap(), NONBLOCKING_MARKER.len()),
            Some("would_block") => assert_eq!(r.unwrap_err().kind(), io::ErrorKind::WouldBlock),
            Some("unsupported") => assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported),
            other => panic!("unknown expectation: {other:?}"),
        }
    }

    #[cfg(unix)]
    fn run_nonblocking_child(expect: &str, stderr: Stdio) {
        run_child_role(
            "lifecycle::tests::repair5_write_stderr_nonblocking_child_role",
            NONBLOCKING_CHILD_ENV,
            expect,
            stderr,
        );
    }

    /// REPAIR-5・#1673: stderr が pipe なら、ブロックしない保証が無いため書かず `Unsupported`（どの unix も）。
    #[cfg(unix)]
    #[test]
    fn repair5_write_stderr_nonblocking_skips_pipe() {
        use std::io::Read;
        let (mut r, w) = io::pipe().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let _reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            let res = r.read_to_end(&mut text).map(|_| text);
            let _ = tx.send(res);
        });
        run_nonblocking_child("unsupported", Stdio::from(w));
        let text = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("pipe collection did not finish in time")
            .unwrap();
        let marker = &NONBLOCKING_MARKER[..NONBLOCKING_MARKER.len() - 1];
        assert!(!text.windows(marker.len()).any(|w| w == marker));
    }

    /// REPAIR-5・#1673: stderr が AF_UNIX socket（Linux x86_64 / aarch64）なら 1 回で全文が届く。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair5_write_stderr_nonblocking_writes_unix_socket() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (a, mut b) = UnixStream::pair().unwrap();
        b.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        run_nonblocking_child("written", Stdio::from(std::os::fd::OwnedFd::from(a)));
        let mut text = Vec::new();
        b.read_to_end(&mut text).unwrap();
        let count = text
            .windows(NONBLOCKING_MARKER.len())
            .filter(|w| *w == NONBLOCKING_MARKER)
            .count();
        assert_eq!(count, 1);
    }

    /// REPAIR-5・#1673: 読み手が読まず送信バッファが満杯の AF_UNIX socket（Linux x86_64 / aarch64）でも、
    /// 待たずに `WouldBlock` で戻り、子は期限内に終了する（共有 fd の `O_NONBLOCK` は立てない）。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair5_write_stderr_nonblocking_does_not_block_on_full_socket() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        // fd の状態を変えない `MSG_DONTWAIT` の送信で、`EAGAIN` になるまで満たす。上限は既定で数百 KiB の
        // ため、100 万回で打ち切る（REPAIR-5）。
        let chunk = [b'x'; 4096];
        let mut last = Ok(0);
        for _ in 0..1_000_000 {
            last = crate::sys::write_nonblocking(&a, &chunk);
            if last.is_err() {
                break;
            }
        }
        assert_eq!(last.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        run_nonblocking_child("would_block", Stdio::from(std::os::fd::OwnedFd::from(a)));
        drop(b);
    }

    /// REPAIR-4・#1605: `Reap` から記録への写像と JSON 行の全文。
    #[test]
    fn repair4_drop_failure_mapping() {
        assert_eq!(
            drop_failure(Reap::GroupKillFailed, Some(7)),
            Some(ChildCleanupFailure::GroupKillFailed)
        );
        assert_eq!(
            drop_failure(Reap::Unreaped, Some(1234)),
            Some(ChildCleanupFailure::Unreaped { pid: Some(1234) })
        );
        assert_eq!(drop_failure(Reap::AlreadyReaped, Some(1)), None);
        assert_eq!(drop_failure(Reap::Lost, Some(1)), None);
        assert_eq!(
            ChildCleanupFailure::GroupKillFailed.to_json_line(),
            GROUP_KILL_FAILED_LINE
        );
        assert_eq!(
            ChildCleanupFailure::Unreaped { pid: Some(1234) }.to_json_line(),
            "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\",\"pid\":1234}"
        );
        assert_eq!(
            ChildCleanupFailure::Unreaped { pid: None }.to_json_line(),
            "{\"event\":\"plugin_child_cleanup\",\"op\":\"drop\",\"outcome\":\"error\",\"reason\":\"unreaped\"}"
        );
    }

    /// PLUG-7・#1311: グループ送信エラーの許容は ESRCH と Unsupported（送信非対応 unix で直接の子の
    /// 回収結果を Unreaped に変えない）のみ。InvalidInput は許容しない。
    #[cfg(unix)]
    #[test]
    fn plug7_group_kill_tolerates_only_empty_group_errors() {
        assert!(group_kill_tolerated(&io::Error::from_raw_os_error(3)));
        assert!(!group_kill_tolerated(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
        assert!(group_kill_tolerated(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        assert!(!group_kill_tolerated(&io::Error::from_raw_os_error(22)));
        // EPERM は生存者への権限不足と区別できないため、どの OS でも失敗として扱う。
        assert!(!group_kill_tolerated(&io::Error::from_raw_os_error(1)));
    }

    #[test]
    fn plug7_timeout_rejects_zero_and_over_max() {
        for d in [
            Duration::ZERO,
            ONE_SHOT_TIMEOUT_MAX + Duration::from_millis(1),
        ] {
            let e = OneShotTimeout::new(d).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        }
        assert_eq!(
            OneShotTimeout::default().as_duration(),
            Duration::from_secs(10)
        );
        assert!(OneShotTimeout::new(ONE_SHOT_TIMEOUT_MAX).is_ok());
    }

    /// REPAIR-4: 失敗経路でも観測記録が 1 件・機械可読 code 付きで渡される。
    #[test]
    fn repair4_observer_receives_failure_record() {
        let dir = std::env::temp_dir().join("fcos-nonexistent-observer-dir");
        let plugin =
            PluginLaunchSpec::new(launch_target::current_exe_target(), vec![], dir).unwrap();
        let req = Frame::new(Vec::new()).unwrap();
        let mut records = Vec::new();
        let r = call_once_observed(
            &plugin,
            &req,
            OneShotTimeout::default(),
            &mut crate::audit::NoopPeerAuthObserver,
            &mut |rec| records.push(rec.clone()),
        );
        assert!(r.is_err());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, "plugin.call_once");
        assert!(!records[0].success);
        assert!(records[0].error_code.is_some());
        // 子を spawn していない経路では stderr の収集結果は空で完了済み。
        assert_eq!(records[0].stderr, PluginStderr::empty());
    }

    #[test]
    fn repair4_record_json_line_is_stable() {
        let rec = OneShotRecord {
            operation: "plugin.call_once",
            success: false,
            error_code: Some("TIMEOUT"),
            elapsed: Duration::from_micros(1500),
            stderr: PluginStderr {
                bytes: b"\"}\n{\"op\":\"forged\"}".to_vec(),
                total_bytes: 70000,
                complete: false,
                reader_stopped: true,
            },
        };
        // plugin の stderr の内容は行へ埋め込まず、出所を明示したキーで件数だけを出す。
        assert_eq!(
            rec.to_json_line(),
            "{\"op\":\"plugin.call_once\",\"success\":false,\"error_code\":\"TIMEOUT\",\
             \"elapsed_us\":1500,\"plugin_stderr_bytes\":70000,\
             \"plugin_stderr_truncated\":true,\"plugin_stderr_complete\":false,\
             \"plugin_stderr_reader_stopped\":true}"
        );
    }

    /// PLUG-7・REPAIR-5: 強制終了を試みた後に回収した終了状態を、子自身の終了と取り違えない。
    #[cfg(unix)]
    #[test]
    fn plug7_classify_reaped_keeps_own_exit_status() {
        use std::os::unix::process::ExitStatusExt;
        // wait status の生値: 終了コードは上位 8 bit、シグナル番号は下位 7 bit。
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(0)),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(3 << 8)),
            PluginTermination::Exited { code: Some(3) }
        );
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(9)),
            PluginTermination::Killed
        );
        // SIGKILL 以外のシグナル（SIGSEGV = 11）は強制終了扱いにせず、異常終了として返す。
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(11)),
            PluginTermination::Exited { code: None }
        );
    }

    /// テスト用の局所の登録表（グローバル表を汚さない）。
    #[cfg(unix)]
    fn local_registry(n: usize) -> &'static Registry {
        use std::sync::atomic::AtomicI32;
        let slots: &'static [AtomicI32] = Box::leak(
            (0..n)
                .map(|_| AtomicI32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(Registry::over(slots)))
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    /// PLUG-7・#1513 (A3): 表が満杯なら子を起動せず `RESOURCE_EXHAUSTED` で拒否する。
    #[cfg(unix)]
    #[test]
    fn plug7_spawn_registered_rejects_when_table_full_without_spawning() {
        let reg = local_registry(1);
        let _held = reg.reserve().unwrap();
        let marker = std::env::temp_dir().join(format!("fcos-spawn-marker-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("touch '{}'", marker.display());
        let e = spawn_registered(&mut sh(&script), reg, far_deadline())
            .err()
            .unwrap();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!marker.exists(), "child must not be spawned");
    }

    /// PLUG-7・#1513 (A2): 登録は spawn 成功で載り、kill・回収・自発終了の回収・未回収報告のいずれでも外れる。
    #[cfg(unix)]
    #[test]
    fn plug7_registration_is_released_on_every_reap_path() {
        use crate::signal_forward::ForwardSignal;
        let reg = local_registry(4);
        let targets = |r: &Registry| r.forward(ForwardSignal::Hangup).targets;
        // 登録の有無（targets）だけを見る。確認用の転送（SIGHUP）で死なないよう HUP を無視する子を使う。
        // trap 設定前の HUP で sh が死ぬ競合（macOS ではゾンビのみのグループへの killpg が EPERM になる）を
        // 避けるため、trap 後にマーカーを作らせ、確認してから転送する。
        let marker_dir = std::env::temp_dir();
        let make_ignoring = |tag: &str| {
            let marker = marker_dir.join(format!("fcos-trap-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_file(&marker);
            // パスはシェルの文字列へ埋め込まず位置引数（`$1`）で渡す（`TMPDIR` に `'` 等を含んでも壊れない）。
            let mut cmd = sh("trap '' HUP; touch \"$1\"; exec sleep 30");
            cmd.arg("sh").arg(&marker);
            (cmd, marker)
        };
        let wait_marker = |m: &std::path::Path| {
            let start = Instant::now();
            while !m.exists() {
                assert!(start.elapsed() < Duration::from_secs(10), "trap marker");
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = std::fs::remove_file(m);
        };
        // kill_and_reap
        let (mut cmd, marker) = make_ignoring("a");
        let mut g = spawn_registered(&mut cmd, reg, far_deadline()).unwrap();
        wait_marker(&marker);
        assert_eq!(targets(reg), 1);
        assert!(g.kill_and_reap().is_reaped());
        assert_eq!(targets(reg), 0);
        // 自発終了を try_wait で回収
        let mut g = spawn_registered(&mut sh("exit 0"), reg, far_deadline()).unwrap();
        let start = Instant::now();
        while g.try_wait().unwrap().is_none() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(targets(reg), 0);
        // 生存中の try_wait は登録を保つ
        let (mut cmd, marker) = make_ignoring("b");
        let mut live = spawn_registered(&mut cmd, reg, far_deadline()).unwrap();
        wait_marker(&marker);
        assert!(live.try_wait().unwrap().is_none());
        assert_eq!(targets(reg), 1);
        // 未回収の報告でスロットを解放する
        let _ = unreaped_error(&mut live, "test");
        assert_eq!(targets(reg), 0);
        // 後始末（報告済みの子は Drop で回収されない）
        live.reported_unreaped = false;
        assert!(live.kill_and_reap().is_reaped());
    }

    /// PLUG-7・#1513 (A2): 登録していない生存中の子には転送しない。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_does_not_touch_unregistered_children() {
        use crate::signal_forward::ForwardSignal;
        let reg = local_registry(2);
        let mut other = ChildGuard::new(sh("exec sleep 30").spawn().unwrap());
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
        std::thread::sleep(Duration::from_millis(50));
        assert!(other.try_wait().unwrap().is_none());
        assert!(other.kill_and_reap().is_reaped());
    }

    /// #1311・PLUG-7: `spawn_registered` の復帰時点で子は自分専用のプロセスグループ（pgid == pid）に
    /// いる。`kill_and_reap` の `killpg(pid)` が親や他のグループへ届かないことの前提を固定する。
    #[cfg(unix)]
    #[test]
    fn plug7_spawn_registered_establishes_own_process_group() {
        let reg = local_registry(2);
        let mut g = spawn_registered(&mut sh("exec sleep 30"), reg, far_deadline()).unwrap();
        let pid = g.child.as_ref().unwrap().id();
        assert_eq!(process_group_of(pid), pid);
        assert!(g.kill_and_reap().is_reaped());
    }

    /// PLUG-7・#1513: 登録中の子へ転送するとシグナルで終了する。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_terminates_registered_child() {
        use crate::signal_forward::ForwardSignal;
        use std::os::unix::process::ExitStatusExt;
        let reg = local_registry(2);
        let mut g = spawn_registered(&mut sh("exec sleep 30"), reg, far_deadline()).unwrap();
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 1);
        let start = Instant::now();
        let status = loop {
            if let Some(st) = g.try_wait().unwrap() {
                break st;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(status.signal(), Some(15));
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
    }

    /// #1311・#1513・PLUG-7: 登録中の plugin へ転送した SIGTERM・SIGHUP は、`spawn_registered` が作る
    /// プロセスグループ宛て（`kill(-pid)`）で孫にも届き、plugin 本体と孫の両方が止まる。
    /// SIGINT は非対話 sh が非同期起動の孫で無視するため、孫の停止は SIGTERM・SIGHUP で確かめる。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_stops_plugin_and_grandchild_via_group() {
        use crate::signal_forward::ForwardSignal;
        for sig in [ForwardSignal::Terminate, ForwardSignal::Hangup] {
            let reg = local_registry(2);
            let mut cmd = sh("/bin/sleep 30 >/dev/null 2>&1 & echo $!; wait");
            cmd.stdout(Stdio::piped());
            let mut g = spawn_registered(&mut cmd, reg, far_deadline()).unwrap();
            let out = g.child.as_mut().unwrap().stdout.take().unwrap();
            let gc: u32 = read_grandchild_pid(&mut g, out);
            assert!(is_running(gc));
            assert_eq!(reg.forward(sig).targets, 1);
            let start = Instant::now();
            while g.try_wait().unwrap().is_none() {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "{sig:?}: leader alive"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            while is_running(gc) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "{sig:?}: grandchild {gc} alive"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// PLUG-7: kill の前に自発終了していた子は、その終了状態のまま回収される（`Killed` にしない）。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_returns_status_of_already_exited_child() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // stdout の EOF は子の終了処理の開始後にしか来ない。回収（wait）はせずに終了だけを待つ。
        let mut out = child.stdout.take().unwrap();
        let mut sink = Vec::new();
        io::Read::read_to_end(&mut out, &mut sink).unwrap();
        assert_eq!(sink, b"");
        let mut guard = ChildGuard::new(child);
        let Reap::Reaped(status) = guard.kill_and_reap() else {
            panic!("child was not reaped");
        };
        assert_eq!(status.code(), Some(3));
        assert_eq!(
            classify_reaped(status),
            PluginTermination::Exited { code: Some(3) }
        );
        assert_eq!(guard.kill_and_reap(), Reap::AlreadyReaped);
    }

    /// 子の標準出力 1 行目の孫 pid を有限の期限内に読む（REPAIR-5・#1311）。期限内に改行も EOF も来なければ
    /// 起動したグループへ SIGKILL を送り、直接の子を回収してから panic する（`read_line` の無期限ブロック防止）。
    #[cfg(unix)]
    fn read_grandchild_pid(guard: &mut ChildGuard, out: std::process::ChildStdout) -> u32 {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let r = io::BufRead::read_line(&mut io::BufReader::new(out), &mut line).map(|_| line);
            let _ = tx.send(r);
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => line.trim().parse().expect("grandchild pid line"),
            Ok(Err(e)) => {
                let _ = guard.kill_and_reap();
                panic!("failed to read grandchild pid: {e}");
            }
            Err(_) => {
                let reap = guard.kill_and_reap();
                panic!("timed out reading grandchild pid (reap: {reap:?})");
            }
        }
    }

    /// 新しいプロセスグループで `script` を起動し、標準出力 1 行目の孫 pid を返す（#1311 のテスト用）。
    #[cfg(unix)]
    fn spawn_group_with_grandchild(script: &str) -> (ChildGuard, u32) {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sh")
            .args(["-c", script])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildGuard::new(child);
        let out = guard.child.as_mut().unwrap().stdout.take().unwrap();
        let pid = read_grandchild_pid(&mut guard, out);
        (guard, pid)
    }

    /// `pid` のプロセスグループ ID（#1311 のテスト用）。Linux は `/proc/<pid>/stat` の pgrp 欄を読み、
    /// 外部コマンドに依存しない（開発コンテナの slim イメージには procps〔`ps`・`kill`〕が無い）。
    #[cfg(target_os = "linux")]
    fn process_group_of(pid: u32) -> u32 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc stat");
        // `pid (comm) state ppid pgrp ...`。comm に空白や括弧を含み得るため最後の ')' の後ろを見る。
        let (_, rest) = stat.rsplit_once(')').expect("stat comm");
        rest.split_whitespace()
            .nth(2)
            .expect("pgrp field")
            .parse()
            .expect("pgrp")
    }

    /// `pid` のプロセスグループ ID（#1311 のテスト用）。`/proc` の無い unix（macOS）は OS 標準の `/bin/ps` を
    /// 期限付きで実行して読む。
    #[cfg(all(unix, not(target_os = "linux")))]
    fn process_group_of(pid: u32) -> u32 {
        let mut ps = Command::new("/bin/ps");
        ps.args(["-o", "pgid=", "-p", &pid.to_string()]);
        let (_, stdout) =
            run_bounded(ps, Duration::from_secs(10)).expect("ps failed to start or timed out");
        stdout.trim().parse().expect("pgid")
    }

    /// 確認用の外部コマンド（`ps`）を期限付きで実行する（REPAIR-5・#1311）。`output()` / `status()` は
    /// 子の終了を無期限に待つため、spawn して `try_wait` を期限までポーリングし、超過時は kill して
    /// 有限時間だけ回収を試みる。起動失敗・期限切れは `None`（呼び出し側が失敗として扱う）。
    #[cfg(all(unix, not(target_os = "linux")))]
    fn run_bounded(mut cmd: Command, limit: Duration) -> Option<(ExitStatus, String)> {
        cmd.stdin(Stdio::null()).stdout(Stdio::piped());
        let mut child = cmd.spawn().ok()?;
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    let mut s = String::new();
                    if let Some(mut o) = child.stdout.take() {
                        let _ = o.read_to_string(&mut s);
                    }
                    return Some((st, s));
                }
                Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(5)),
                _ => break,
            }
        }
        let _ = child.kill();
        let reap = Instant::now();
        while reap.elapsed() < Duration::from_secs(2) {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    /// 孫が実行中か（Linux ではゾンビ `Z` を実行中に数えない）。存在確認は `kill(pid, 0)`（`sys::send_signal`）で
    /// 行い、外部コマンド（procps の `kill`。開発コンテナに無い）に依存しない。
    #[cfg(unix)]
    fn is_running(pid: u32) -> bool {
        let alive = crate::sys::send_signal(i32::try_from(pid).expect("pid fits in i32"), 0);
        #[cfg(target_os = "linux")]
        let alive = alive
            && std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|st| {
                    !st.rsplit(')')
                        .next()
                        .unwrap_or("")
                        .trim_start()
                        .starts_with('Z')
                })
                .unwrap_or(false);
        alive
    }

    /// 試験の後始末で、生存を確認した直後の孫へ SIGKILL を送る（外部コマンドに依存しない）。
    #[cfg(unix)]
    fn force_kill(pid: u32) {
        let pid = i32::try_from(pid).expect("pid fits in i32");
        let _ = crate::sys::send_signal(pid, crate::sys::SIGKILL);
    }

    #[cfg(unix)]
    const GRANDCHILD_SCRIPT_EXIT: &str = "/bin/sleep 30 >/dev/null 2>&1 & echo $!; exit 0";
    #[cfg(unix)]
    const GRANDCHILD_SCRIPT_WAIT: &str = "/bin/sleep 30 >/dev/null 2>&1 & echo $!; wait";

    /// #1311・PLUG-7: 子が生存中の `kill_and_reap` はグループ内の孫も止める。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_kills_grandchild_in_process_group() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_WAIT);
        assert!(is_running(gc));
        assert!(matches!(guard.kill_and_reap(), Reap::Reaped(_)));
        let start = Instant::now();
        while is_running(gc) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "grandchild {gc} alive"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 孫が止まる（実行中でなくなる）まで期限つきで待つ（REPAIR-5）。
    #[cfg(unix)]
    fn assert_grandchild_gone(gc: u32) {
        let start = Instant::now();
        while is_running(gc) {
            if start.elapsed() >= Duration::from_secs(5) {
                force_kill(gc);
                panic!("grandchild {gc} is still alive");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// このスレッドの [`send_group_kill`] 呼び出し回数を 0 に戻す。
    #[cfg(unix)]
    fn reset_group_kill_sends() {
        GROUP_KILL_SENDS.with(|c| c.set(0));
    }

    #[cfg(unix)]
    fn group_kill_sends() -> usize {
        GROUP_KILL_SENDS.with(std::cell::Cell::get)
    }

    /// #1604・PLUG-7: 自発終了したリーダーは、`try_wait` が回収する前にグループへ `SIGKILL` を送り、孫を止める。
    /// 回収後の `kill_and_reap` は再び送らない（pid 再利用による誤送信の防止）。
    #[cfg(unix)]
    #[test]
    fn plug7_try_wait_kills_group_of_self_exited_leader_once() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        reset_group_kill_sends();
        let start = Instant::now();
        while guard.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "leader did not exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(guard.child.is_some());
        assert!(!guard.group_kill_failed_after_exit);
        assert_grandchild_gone(gc);
        assert_eq!(group_kill_sends(), 1);
        assert!(matches!(guard.kill_and_reap(), Reap::Reaped(_)));
        assert_eq!(
            group_kill_sends(),
            1,
            "group was signalled after the leader was reaped"
        );
    }

    /// #1311・PLUG-7・REPAIR-5: グループ送信失敗は後始末の成功に数えない（`is_reaped` は偽）。
    #[test]
    fn plug7_group_kill_failed_is_not_a_successful_reap() {
        assert!(!Reap::GroupKillFailed.is_reaped());
        assert!(!Reap::Unreaped.is_reaped());
        assert!(Reap::AlreadyReaped.is_reaped());
    }

    /// #1311・PLUG-7・REPAIR-5: 終了猶予超過後のグループ停止失敗は、未回収の子（`Unreaped`）へ畳まずに
    /// 別の終了状況として保つ。
    #[test]
    fn plug7_termination_after_kill_keeps_group_kill_failure_distinct() {
        assert_eq!(
            termination_after_kill(Reap::GroupKillFailed),
            PluginTermination::GroupKillFailed
        );
        assert_eq!(
            termination_after_kill(Reap::Unreaped),
            PluginTermination::Unreaped
        );
        assert_eq!(
            termination_after_kill(Reap::AlreadyReaped),
            PluginTermination::Unreaped
        );
    }

    /// #1311・PLUG-7・REPAIR-5: 応答前の失敗経路のグループ停止失敗は、元のエラーの code と message を保って
    /// 付記する（macOS のゾンビだけのグループの `EPERM` で `Unavailable` 等を `Internal` に置き換えない）。
    #[test]
    fn plug7_with_group_kill_failure_keeps_original_code_and_message() {
        let e = with_group_kill_failure(
            PluginError::new(PluginErrorCode::Unavailable, "peer closed the connection"),
            "a failed exchange",
        );
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(
            e.message(),
            "peer closed the connection; additionally, the plugin process group could not be \
             killed after a failed exchange, so descendant processes may remain"
        );
        // 元の message が上限近くでも付記は切り捨てられない（元の側を文字境界で詰める）。
        let long = "あ".repeat(crate::error::PLUGIN_ERROR_MESSAGE_MAX_BYTES / 3);
        let e = with_group_kill_failure(
            PluginError::new(PluginErrorCode::Timeout, &long),
            "a failed start",
        );
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let note = "; additionally, the plugin process group could not be killed after a failed \
                    start, so descendant processes may remain";
        assert!(e.message().ends_with(note), "{}", e.message());
        assert!(e.message().len() <= crate::error::PLUGIN_ERROR_MESSAGE_MAX_BYTES);
        assert!(e.message().starts_with("あ"));
    }

    /// #1311・PLUG-7・REPAIR-5: 応答後のグループ停止失敗は `group_kill_failed_error` で報告し、回収済みの
    /// 子を「回収できなかった」とは報告しない（pid を含めず、報告済みの印も付けない）。
    #[cfg(unix)]
    #[test]
    fn plug7_group_kill_failure_after_response_is_not_reported_as_unreaped() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildGuard::new(child);
        // グループ停止失敗の時点で直接の子は回収済み（`child` は `None`）。その状態を再現する。
        assert_eq!(
            guard.wait_or_kill(Duration::from_secs(5)),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_eq!(guard.pid(), None);

        let e = check_termination_after_response(&mut guard, PluginTermination::GroupKillFailed)
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            "plugin process group could not be killed after the response; \
             the direct child was reaped but descendant processes may remain"
        );
        assert!(!guard.reported_unreaped);

        // 未回収の子は従来どおり別のメッセージで報告する（両者を取り違えない）。
        let e =
            check_termination_after_response(&mut guard, PluginTermination::Unreaped).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            "plugin process could not be reaped after the response"
        );
        assert_eq!(
            check_termination_after_response(&mut guard, PluginTermination::Killed),
            Ok(())
        );
    }

    /// #1311・#1604・PLUG-7: 自発終了を `wait_or_kill` が回収した時点で孫は止まっており、回収して `child` を
    /// 手放した後は何も送らない（`AlreadyReaped`）。
    #[cfg(unix)]
    #[test]
    fn plug7_wait_or_kill_stops_grandchild_then_skips_group_after_release() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        reset_group_kill_sends();
        assert_eq!(
            guard.wait_or_kill(Duration::from_secs(5)),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_grandchild_gone(gc);
        assert_eq!(group_kill_sends(), 1);
        assert_eq!(guard.kill_and_reap(), Reap::AlreadyReaped);
        assert_eq!(
            group_kill_sends(),
            1,
            "group was signalled after the leader was reaped"
        );
    }

    /// PLUG-7: 終了猶予を使い切った後の回収でも、自発的な非ゼロ終了は `Exited` として返る。
    #[cfg(unix)]
    #[test]
    fn plug7_wait_or_kill_reports_killed_only_for_forced_kill() {
        let spawn = |script: &str| {
            Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut lingering = ChildGuard::new(spawn("exec sleep 60"));
        assert_eq!(
            lingering.wait_or_kill(Duration::from_millis(50)),
            PluginTermination::Killed
        );
        let mut failing = ChildGuard::new(spawn("exit 7"));
        assert_eq!(
            failing.wait_or_kill(Duration::from_secs(5)),
            PluginTermination::Exited { code: Some(7) }
        );
    }

    /// REPAIR-5・PLUG-7: 回収できなかった子のエラーは `Internal` で、未回収の pid を特定できる。
    #[cfg(unix)]
    #[test]
    fn repair5_unreaped_error_names_the_child_pid() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut guard = ChildGuard::new(child);
        let e = unreaped_error(&mut guard, "the response");
        assert!(guard.reported_unreaped);
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            format!("plugin process (pid {pid}) could not be reaped after the response")
        );
        // 回収済み（ハンドルなし）の場合は pid を含めない。
        assert!(guard.kill_and_reap().is_reaped());
        let e = unreaped_error(&mut guard, "a failed exchange");
        assert_eq!(
            e.message(),
            "plugin process could not be reaped after a failed exchange"
        );
    }

    /// 上限を超える stderr は先頭 `PLUGIN_STDERR_MAX_BYTES` だけ保持し、総量を数える（REPAIR-5）。
    #[test]
    fn plug7_stderr_capture_keeps_only_the_cap() {
        let mut data = vec![b'a'; PLUGIN_STDERR_MAX_BYTES];
        data.extend_from_slice(&[b'b'; 34_464]);
        let capture = StderrCapture::start(io::Cursor::new(data), Box::new(|| {})).unwrap();
        let got = capture.finish(Duration::from_secs(5));
        assert_eq!(got.bytes().len(), 65_536);
        assert_eq!(got.bytes().iter().filter(|b| **b == b'a').count(), 65_536);
        assert_eq!(got.total_bytes(), 100_000);
        assert!(got.is_truncated());
        assert!(got.is_complete());
    }

    /// 上限以内の stderr はそのまま保持する。
    #[test]
    fn plug7_stderr_capture_keeps_small_output_verbatim() {
        let capture =
            StderrCapture::start(io::Cursor::new(b"warn: x\n".to_vec()), Box::new(|| {})).unwrap();
        let got = capture.finish(Duration::from_secs(5));
        assert_eq!(got.bytes(), b"warn: x\n");
        assert_eq!(got.total_bytes(), 8);
        assert!(!got.is_truncated());
        assert!(got.is_complete());
        assert!(got.reader_stopped());
    }

    /// REPAIR-5: 書き込み端が閉じない（孫プロセスが保持する等）場合でも、収集待ちは期限で打ち切り、
    /// 読み取りスレッドは停止指示で止まる（スレッドを残さない）。
    #[test]
    fn repair5_stderr_capture_finish_stops_reader_when_source_never_closes() {
        /// 最初に 3 バイト返し、その後は終端に達しないまま読み取り期限切れを返し続ける入力。
        struct Stalled(Option<&'static [u8]>);
        impl Read for Stalled {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if let Some(first) = self.0.take() {
                    let n = first.len().min(buf.len());
                    buf[..n].copy_from_slice(&first[..n]);
                    return Ok(n);
                }
                std::thread::sleep(Duration::from_millis(10));
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
        let woken = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&woken);
        let capture = StderrCapture::start(
            Stalled(Some(b"abc")),
            Box::new(move || flag.store(true, Ordering::SeqCst)),
        )
        .unwrap();
        // 先頭の 3 バイトが保持されるまで待つ（最大 5 秒）。
        let waited = Instant::now();
        while lock_stderr(&capture.state).total_bytes < 3 {
            assert!(waited.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let got = capture.finish(Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(got.bytes(), b"abc");
        assert_eq!(got.total_bytes(), 3);
        assert!(!got.is_complete());
        assert!(got.reader_stopped());
        assert!(woken.load(Ordering::SeqCst));
    }

    /// REPAIR-5・PLUG-7: 子の終了後も別プロセスが stderr の書き込み端を保持している場合、収集は
    /// 期限で打ち切り、ソケットの shutdown で読み取りスレッドを停止させる。
    #[cfg(unix)]
    #[test]
    fn repair5_stderr_capture_stops_reader_while_another_process_holds_the_writer() {
        let (child_stderr, reader) = stderr_channel(far_deadline()).unwrap();
        // 書き込み端を保持したまま何も書かないプロセス（孫プロセスの代役）。
        let holder = Command::new("/bin/sh")
            .args(["-c", "echo held >&2; exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(child_stderr)
            .spawn()
            .unwrap();
        let mut holder = ChildGuard::new(holder);
        let capture = StderrCapture::attach(reader, far_deadline()).unwrap();
        let waited = Instant::now();
        while lock_stderr(&capture.state).total_bytes < 5 {
            assert!(waited.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let got = capture.finish(Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(got.bytes(), b"held\n");
        assert_eq!(got.total_bytes(), 5);
        assert!(!got.is_complete());
        assert!(got.reader_stopped());
        assert!(holder.kill_and_reap().is_reaped());
    }

    /// REPAIR-5・PLUG-7・#3003: 書き込み端を保持する別プロセスがいても、`shutdown` を使わない通常の
    /// 停止（`poll` と停止用 pipe）で毎回、期限内に読み取りスレッドが止まる。macOS で `shutdown` との
    /// 競合により 1 回だけ止まらなかった間欠失敗を拾うため、同じ場面を繰り返す。
    #[cfg(unix)]
    #[test]
    fn repair5_stderr_capture_stops_reader_repeatedly_while_writer_is_held() {
        for round in 0..20 {
            let (child_stderr, reader) = stderr_channel(far_deadline()).unwrap();
            let holder = Command::new("/bin/sh")
                .args(["-c", "exec sleep 30"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(child_stderr)
                .spawn()
                .unwrap();
            let mut holder = ChildGuard::new(holder);
            let capture = StderrCapture::attach(reader, far_deadline()).unwrap();
            let limit = Duration::from_millis(50);
            let started = Instant::now();
            let got = capture.finish(limit);
            let elapsed = started.elapsed();
            assert!(got.reader_stopped(), "round {round}: {elapsed:?}");
            assert!(!got.is_complete(), "round {round}");
            assert_eq!(got.total_bytes(), 0, "round {round}");
            assert!(elapsed >= limit, "round {round}: {elapsed:?}");
            assert!(
                elapsed < limit + PLUGIN_STDERR_STOP_TIMEOUT,
                "round {round}: {elapsed:?}"
            );
            assert!(holder.kill_and_reap().is_reaped());
        }
    }

    /// PLUG-7: 未回収として pid を報告した子は、ガードの破棄時に回収しない（報告した pid を
    /// 解放済みにしない）。報告していない子は破棄時に kill・回収する。
    #[cfg(unix)]
    #[test]
    fn plug7_reported_unreaped_child_is_not_reaped_on_drop() {
        let spawn = |script: &str| {
            Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let exists = |pid: u32| std::path::Path::new(&format!("/proc/{pid}")).exists();

        // すぐ自発終了する子。回収しなければゾンビとして pid が残る。
        let mut reported = ChildGuard::new(spawn("exit 0"));
        let reported_pid = reported.pid().unwrap();
        let e = unreaped_error(&mut reported, "the response");
        assert_eq!(
            e.message(),
            format!("plugin process (pid {reported_pid}) could not be reaped after the response")
        );
        drop(reported);

        let unreported = ChildGuard::new(spawn("exec sleep 30"));
        let unreported_pid = unreported.pid().unwrap();
        drop(unreported);

        // `/proc` で確認できるのは Linux のみ。他の unix では破棄が戻ることだけを確認する。
        if cfg!(target_os = "linux") {
            assert!(exists(reported_pid), "pid {reported_pid}");
            assert!(!exists(unreported_pid), "pid {unreported_pid}");
        }
    }

    #[test]
    fn plug7_plugin_rejects_too_many_or_too_long_args() {
        let many = vec![OsString::from("a"); PLUGIN_ARGS_MAX_COUNT + 1];
        let e = PluginLaunchSpec::new(launch_target::current_exe_target(), many, "/tmp".into())
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let long = vec![OsString::from("a".repeat(PLUGIN_ARGS_MAX_BYTES + 1))];
        let e = PluginLaunchSpec::new(launch_target::current_exe_target(), long, "/tmp".into())
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let ok = vec![OsString::from("a"); PLUGIN_ARGS_MAX_COUNT];
        assert!(
            PluginLaunchSpec::new(launch_target::current_exe_target(), ok, "/tmp".into()).is_ok()
        );
    }

    /// 応答者を pid で限定する: 同一 UID でも pid が異なる接続は受理しない（PLUG-7）。
    #[cfg(unix)]
    #[test]
    fn plug7_accept_rejects_other_pid_and_accepts_expected() {
        use crate::transport::UdsStream;
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("fcos-unit-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = UdsListener::bind(&dir.join("a.sock")).unwrap();
        let path = listener.path().to_path_buf();
        let me = std::process::id();
        let _c = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        let e = listener
            .accept_peer_pid(
                Duration::from_millis(300),
                me.wrapping_add(1),
                &mut || None,
                &mut crate::audit::NoopPeerAuthObserver,
            )
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let _c2 = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        assert!(
            listener
                .accept_peer_pid(
                    Duration::from_secs(2),
                    me,
                    &mut || None,
                    &mut crate::audit::NoopPeerAuthObserver,
                )
                .is_ok()
        );
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// pid 不一致の接続が続いても abort を確認し、子の早期終了を期限前に返す（PLUG-7・REPAIR-5）。
    #[cfg(unix)]
    #[test]
    fn plug7_abort_is_checked_after_pid_mismatch() {
        use crate::transport::UdsStream;
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("fcos-abort-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = UdsListener::bind(&dir.join("a.sock")).unwrap();
        let path = listener.path().to_path_buf();
        let me = std::process::id();
        let _c = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let e = listener
            .accept_peer_pid(
                Duration::from_secs(10),
                me.wrapping_add(1),
                &mut || {
                    calls += 1;
                    Some(PluginError::new(
                        PluginErrorCode::Unavailable,
                        "child exited early",
                    ))
                },
                &mut crate::audit::NoopPeerAuthObserver,
            )
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(calls, 1);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 子を起動して登録し、ガードの外で（`waitpid(pid, WNOHANG)` を期限つきでポーリングして）回収する
    /// （他所での回収を模す）。戻り値のガードの子は回収済みで、以後の `waitpid` は `ECHILD` になる。
    /// 待ちはポーリングの期限（10 秒）で打ち切る（REPAIR-5。ブロッキングの読み取り・wait をしない）。
    #[cfg(unix)]
    fn spawn_then_reap_elsewhere(reg: &'static Registry) -> ChildGuard {
        use crate::signal_forward::ForwardSignal;
        let g = spawn_registered(&mut sh("exit 0"), reg, far_deadline()).unwrap();
        assert_eq!(reg.forward(ForwardSignal::Hangup).targets, 1);
        let pid = g.pid().unwrap();
        let start = Instant::now();
        while !crate::sys::reap_child_for_test(pid).unwrap() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "child did not exit"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        g
    }

    /// PLUG-7・#1513: 他所で回収された子（`ECHILD`）は終端として扱い、登録を戻さず（転送しない）、
    /// 以後 kill も回収もしない。終了状態は失われるため、終了コード不明の終了（成功扱いにならない）になる。
    #[cfg(unix)]
    #[test]
    fn plug7_try_wait_echild_releases_registration_and_stops_tracking() {
        use crate::signal_forward::ForwardSignal;
        // ECHILD は Linux（asm-generic/errno-base.h）・macOS（sys/errno.h）とも 10。
        const ECHILD: i32 = 10;
        let reg = local_registry(2);
        let mut g = spawn_then_reap_elsewhere(reg);
        let e = g.try_wait().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ECHILD));
        // 登録は戻らない（pid が再利用されても転送が届かない）。子は手放し済み。
        assert_eq!(reg.forward(ForwardSignal::Hangup).targets, 0);
        assert_eq!(g.pid(), None);
        assert!(g.lost);
        // 終端後も Ok(None)（生存扱い）に戻らない。kill もしない。
        assert!(g.try_wait().is_err());
        assert_eq!(g.kill_and_reap(), Reap::Lost);
        assert!(Reap::Lost.is_reaped());
        assert_eq!(
            g.wait_or_kill(Duration::from_millis(10)),
            PluginTermination::Exited { code: None }
        );
        // スロットは解放済みで、表の容量を消費し続けない。
        let _a = reg.reserve().unwrap();
        let _b = reg.reserve().unwrap();
    }

    /// #1311・#1513・PLUG-7: `try_wait` が `ECHILD`（他所での回収）を観測した後は終端になり、`kill_and_reap` は
    /// プロセスグループ宛ての SIGKILL も送らない（pgid が再利用され得るため）。生存中の孫が止まらないことを
    /// pid で確かめる。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_skips_group_after_try_wait_echild() {
        // ECHILD は Linux（asm-generic/errno-base.h）・macOS（sys/errno.h）とも 10。
        const ECHILD: i32 = 10;
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        let pid = guard.pid().unwrap();
        let start = Instant::now();
        while !crate::sys::reap_child_for_test(pid).unwrap() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "leader did not exit"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let e = guard.try_wait().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ECHILD));
        assert!(guard.lost && guard.leader_reaped);
        assert_eq!(guard.kill_and_reap(), Reap::Lost);
        let still_running = is_running(gc);
        force_kill(gc);
        assert!(
            still_running,
            "group was signalled after waitpid failed with ECHILD"
        );
    }

    /// 終了を `probe_child_exit` で観測してから `reap_child_for_test` で回収し、プローブの後に契約外の
    /// 回収者が回収した状況を作る（#1604。`ECHILD` の経路の再現）。
    #[cfg(unix)]
    fn probe_then_reap_elsewhere(pid: u32) {
        let start = Instant::now();
        while crate::sys::probe_child_exit(pid).unwrap() != crate::sys::ChildExitProbe::Exited {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "leader did not exit"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(crate::sys::reap_child_for_test(pid).unwrap());
    }

    /// #1604・#1513・PLUG-7: プローブの後に他所で回収された場合、`try_wait` は `ECHILD` で終端になり、
    /// グループへ送らない（孫は生存したまま）。
    #[cfg(unix)]
    #[test]
    fn plug7_try_wait_does_not_signal_group_when_reaped_after_probe() {
        const ECHILD: i32 = 10;
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        reset_group_kill_sends();
        probe_then_reap_elsewhere(guard.pid().unwrap());
        let e = guard.try_wait().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ECHILD));
        assert!(guard.lost && guard.leader_reaped);
        assert_eq!(group_kill_sends(), 0);
        let still_running = is_running(gc);
        force_kill(gc);
        assert!(still_running, "group was signalled after ECHILD");
    }

    /// #1604・#1577・PLUG-7: プローブの後に他所で回収された場合、`kill_and_reap` は冒頭のプローブで `ECHILD` を
    /// 検出して `Lost` で終え、グループへ送らない（従来は確認の前に送っていた窓）。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_does_not_signal_group_when_reaped_after_probe() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        reset_group_kill_sends();
        probe_then_reap_elsewhere(guard.pid().unwrap());
        assert_eq!(guard.kill_and_reap(), Reap::Lost);
        assert_eq!(group_kill_sends(), 0);
        assert!(guard.lost && guard.child.is_none());
        let still_running = is_running(gc);
        force_kill(gc);
        assert!(still_running, "group was signalled after ECHILD");
    }

    /// #1604・PLUG-7・REPAIR-5: 自発終了の観測後のグループ送信失敗の印は、回収済み（`child == None`）の
    /// `kill_and_reap` でも `GroupKillFailed` として返り、`wait_or_kill` も成功扱いにしない。
    #[cfg(unix)]
    #[test]
    fn plug7_group_kill_failure_after_exit_is_reported_not_swallowed() {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let mut guard = ChildGuard::new(child);
        guard.group_kill_failed_after_exit = true;
        assert_eq!(
            guard.wait_or_kill(Duration::from_secs(5)),
            PluginTermination::GroupKillFailed
        );
        assert_eq!(guard.kill_and_reap(), Reap::GroupKillFailed);
    }

    /// REPAIR-4・PLUG-7・#1605: 自発終了の観測後のグループ送信失敗を `wait_or_kill` が返した後（子は手放し済み）、
    /// `Drop` は同じ失敗を再記録しない。子を保持したまま印が立っている場合は `Drop` が 1 回だけ記録する。
    #[cfg(unix)]
    #[test]
    fn repair4_drop_does_not_relog_group_kill_failure_already_reported() {
        use std::os::unix::process::CommandExt;
        let spawn_exit0 = || {
            Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut reported = ChildGuard::new(spawn_exit0());
        reported.group_kill_failed_after_exit = true;
        assert_eq!(
            reported.wait_or_kill(Duration::from_secs(5)),
            PluginTermination::GroupKillFailed
        );
        assert!(reported.child.is_none());
        let mut lines: Vec<String> = Vec::new();
        reported.finish_on_drop(&mut |rec| lines.push(rec.to_json_line()));
        assert_eq!(lines, Vec::<String>::new());

        // 陽性対照: 子を保持したまま印が立っている（呼び出し側へ未報告）なら `Drop` が 1 回記録する。
        let mut unreported = ChildGuard::new(spawn_exit0());
        unreported.group_kill_failed_after_exit = true;
        unreported.finish_on_drop(&mut |rec| lines.push(rec.to_json_line()));
        assert_eq!(lines, vec![GROUP_KILL_FAILED_LINE.to_string()]);
        assert_eq!(unreported.pid(), None);
    }

    /// PLUG-7・#1513: `kill_and_reap` の kill 前の確認で `ECHILD` を受けたら kill を送らず `Lost` で終える
    /// （再利用され得る pid へ SIGKILL を送らない）。`Drop` も再び kill しない。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_echild_does_not_kill_and_is_terminal() {
        use crate::signal_forward::ForwardSignal;
        let reg = local_registry(1);
        let mut g = spawn_then_reap_elsewhere(reg);
        assert_eq!(g.kill_and_reap(), Reap::Lost);
        assert_eq!(g.pid(), None);
        assert!(g.child.is_none() && g.slot.is_none());
        assert_eq!(reg.forward(ForwardSignal::Hangup).targets, 0);
        assert_eq!(g.kill_and_reap(), Reap::Lost);
        drop(g);
        // 解放されたスロットは再び確保できる。
        assert!(reg.reserve().is_ok());
    }
}
