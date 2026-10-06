//! `ContainerRuntime` アダプタ: core からの create / start / stop 要求を `fandhe-container-platform-macos`
//! の VM 起動・virtiofs 共有へ委譲し、失敗を plugin のエラーフレームへ写す（TASK-115.3・#387。
//! PLUG-1・MAC-1・ERR-1・REPAIR-2・REPAIR-3・REPAIR-5・REPAIR-12）。
//!
//! 呼び出し元: `main.rs` が [`MacosRuntimeAdapter`] を [`crate::frame_loop::serve`] の `RequestHandler` として
//! 渡す。フレームの復号・応答の組み立ては `frame_loop` が担い、本モジュールは「要求本体 → platform-macos の
//! 関数呼び出し → 応答本体 / [`PluginError`]」だけを担う。呼び出し先の VM 操作は [`MacosBackend`] 越しにし、
//! 実 VM を起動できない 3 OS の CI でも偽実装でテストできるようにする。
//!
//! # 暫定ワイヤー契約（spec 未規定。型つき本体への置換は core 側 proxy の TASK-114）
//!
//! | 操作 | 要求本体 | 成功応答本体 |
//! | ---- | -------- | ------------ |
//! | create | `["create", id, kernel, initrd または "", cmdline, (tag, host_dir, "ro" / "rw")*]` | `["created"]` |
//! | start | `["start", id]` | `["running"]` |
//! | stop | `["stop", id]` | `["stopped"]` |
//! | kill / delete / state / その他 | — | Error `UNIMPLEMENTED` |
//!
//! `id` は core の `ContainerId` と同じ規則（空・`.`・`..` 不可、255 バイト以下、`[A-Za-z0-9._-]`）で
//! 検証する（TASK-114 で core 型へ置換）。create は検証と登録のみ、start が `Vm::launch`、stop が
//! `Vm::stop` と登録解除（delete が無いため stop が資源をすべて手放す）。
//!
//! # エラー対応表（[`to_plugin_error`] が唯一の変換箇所）
//!
//! | platform-macos | `PluginErrorCode` |
//! | -------------- | ----------------- |
//! | `Config`（既定） | `INVALID_ARGUMENT` |
//! | `Config`: `PathIo`・`UrlConversion`・`DiskAttachment`・`ConsoleLogOpen`・`ConsoleLogWriter` | `INTERNAL` |
//! | `Config`: `ConsoleLogNotOwned`・`ConsoleLogInsecureMode`・`ConsoleLogParentWorldWritable` | `PERMISSION_DENIED` |
//! | `Config`: `ConsoleLogInUse` | `FAILED_PRECONDITION` |
//! | `Config`: `SharedDirScanTimeout` | `TIMEOUT` |
//! | `Vm`: `VirtualizationUnsupported`・`InvalidConfiguration`・`InvalidState` | `FAILED_PRECONDITION` |
//! | `Vm`: `InvalidTimeout` | `INVALID_ARGUMENT` |
//! | `Vm`: `StartFailed`・`StopFailed` | `INTERNAL` |
//! | `Vm`・`GuestMount`: `Timeout` | `TIMEOUT` |
//! | `Vm::CallbackLost`・`GuestMount::VmStopped`・`GuestMount::ReportChannelClosed` | `UNAVAILABLE` |
//! | `GuestMount::Failed`・`InvalidReport` | `INTERNAL` |
//! | `VirtiofsIo::Protocol` | 同名コードへ 1:1（`resource_exhausted` は `FAILED_PRECONDITION`） |
//! | `VirtiofsIo::ReadOnlyShare` | `FAILED_PRECONDITION` |
//! | `VirtiofsIo::InFlightLimitTooSmall`・`InvalidReconnectPolicy` | `INVALID_ARGUMENT` |
//! | `VirtiofsIo::ConnectionLost`・`ReconnectFailed` | 未永続化 write があれば `DATA_LOSS`、なければ `UNAVAILABLE` |
//! | 上記以外・将来追加分 | `INTERNAL`（fail-closed） |
//! | [`BackendError::UnsupportedHost`] | `UNIMPLEMENTED` |
//! | [`BackendError::LaunchTimedOut`]・create の検証の期限超過 | `TIMEOUT` |
//! | [`BackendError::LaunchNotStarted`]・create の検証を開始できない | `UNAVAILABLE` |
//!
//! message は先頭に元の `code()` を付ける（core が元の分類を区別できる）。`Config` 系は `message()` が要求由来の
//! パスを埋め込むため使わず固定文言にする（入力の反射防止）。`GuestMount` 系も共有タグを含むため固定文言にする。
//! `VirtiofsIo` 系（共有タグ・相手由来の本文を含む）と将来追加される分類も固定文言にする。`message()` を
//! そのまま載せるのは `Vm` 系（操作名・VM 状態・期限・VZ の NSError の domain / code で、要求由来の値を含まない）だけ。アダプタ自身の検証エラーも固定文言のみ。
//!
//! # 共有ディレクトリの検証（MAC-1・SEC-4。分離境界のため fail-closed）
//!
//! `host_dir` は要求の値をそのまま `SharedDirectoryPath::try_new` に渡して検証する（相対パス・`.`/`..`・
//! symlink 経由・非実在を拒否。検証の実装は platform-macos に一本化し、本モジュールで事前に解決しない）。
//! 例外は macOS の既知の祖先 symlink（[`KNOWN_ROOT_ALIASES`]。`/tmp`・`/var`）だけで、先頭がその別名に
//! 一致する絶対パスに限り、別名が実際に既知の実体を指すことを確かめてから実体パスへ文字列置換する
//! （[`rewrite_known_alias`]）。それ以外の symlink は辿らない。置換後のパスも `try_new` が全要素を検証する。
//! 共有配下の走査（範囲外 symlink・ハードリンク・マウント境界）は create と start（`Vm::launch` 内の再検査）の
//! どちらも [`SHARE_SCAN_TIMEOUT`] で打ち切り、超過は `TIMEOUT`（`config.shared_dir_scan_timeout`）で返す（REPAIR-5）。
//!
//! # 取り消せない OS 呼び出しの隔離（REPAIR-5）
//!
//! 要求由来のパスに触れる処理（create の kernel・initrd・共有元の検証と共有走査、start の `Vm::launch`）は
//! 応答しないファイルシステム（NFS・autofs 等）の上で 1 回の OS 呼び出しが戻らないことがあり、走査の期限
//! （呼び出しの合間に確かめる）では打ち切れない。これらは [`crate::isolate::run`] で作業スレッドへ隔離し、
//! 要求処理スレッドは [`CREATE_VALIDATION_TIMEOUT`]・[`LAUNCH_TOTAL_TIMEOUT`] だけ待って `TIMEOUT` を返す。
//! 戻らない作業スレッドは残るが数を上限で抑え（[`crate::isolate::MAX_WORKERS`]。create 用・launch 用で
//! 別々に 4、合計 8）、上限に達した側は新しい
//! 処理を開始せず `UNAVAILABLE` で拒否する。start の期限超過は VM が作られ得るため停止未確認
//! （`LaunchFailed`）として扱う。stop は VM キューへの期限つき要求だけでファイルシステムに触れない。
//!
//! # 未実装範囲（実装済みを装わない。REPAIR-3）
//! - 型つき本体と core の `ContainerRuntime` トレイトへの接続・kill / delete / state（TASK-114 待ち）。
//! - virtiofs 共有は「デバイス構成のみ」。ゲスト内 mount 先の指定は受け付けない（ゲスト init 未実装のため
//!   `guest_mount.timeout` になる。MAC-1）。rootfs ブロックデバイス・コンソールログ・CPU / メモリ指定も含まない。
//! - VM が作られ得た起動失敗（`VmError::StartFailed`・`GuestMount` 等）の後の `start` 再試行は拒否する
//!   （VM 生成前に確定した失敗〔`UnsupportedHost`・構成エラー〕は `Created` のまま再試行・`stop` を許す。
//!   失敗した VM の停止は非同期で完了を確認できず、VM が重複し得るため。
//!   `stop` も拒否し、同じ ID の再作成を許さない。登録は plugin プロセス終了まで残る）。同時実行 VM 数は
//!   [`SHUTDOWN_BUDGET`] 内に逐次停止できる数から 1 台分の処理余裕を引いた数（停止待ち 2 秒なら 1。起動失敗後に停止未確認の VM も算入）に制限する。停止できず残った VM（起動失敗後に停止を確認できない VM を含む）は `stop_all` の `remaining` として報告し、回収は `Vm` の drop 停止要求（非同期）と
//!   core の終了処理に委ね、完了は保証しない。
//! - 1 コンテナ = 1 VM（常駐 VM 共用の MAC-4 は未決）。状態はプロセス内メモリのみ（都度起動モードでは引き継げない）。
//! - VM 操作の期限は core 側 RPC・都度起動の合計期限（10 秒）と終了猶予（5 秒）に収まる固定値
//!   （[`LAUNCH_START_TIMEOUT`] 等・[`SHUTDOWN_BUDGET`]）。core からの期限伝達（要求本体への期限指定）は TASK-114。
//!   既定の `OpTimeouts`（start 30 秒・guest mount 60 秒・stop 15 秒）は使わない。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fandhe_container_platform_macos::config::{ConfigError, VmConfigSpec};
use fandhe_container_platform_macos::error::{GuestMountError, PlatformError, VmError};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsIoError, VirtiofsShareSpec, VirtiofsSharesSpec,
    VirtiofsTag,
};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

use crate::frame_loop::RequestHandler;
use crate::isolate::{self, IsolateError, Workers};

/// 登録できるコンテナ数の上限（無制限確保の防止）。
pub const MAX_CONTAINERS: usize = 64;

/// core 側 plugin RPC・都度起動の合計期限（10 秒）に収めるための `start` 完了待ち（REPAIR-5・TASK-115.3）。
pub const LAUNCH_START_TIMEOUT: Duration = Duration::from_secs(3);
/// 同 `stop` 完了待ち。停止はゲスト mount 待ちの失敗後始末と終了時停止でも使う。
pub const LAUNCH_STOP_TIMEOUT: Duration = Duration::from_secs(2);
/// 同 状態照会の応答待ち。
pub const LAUNCH_STATE_QUERY_TIMEOUT: Duration = Duration::from_secs(1);
/// 同 ゲスト内 virtiofs mount 報告の待機。共有走査（[`SHARE_SCAN_TIMEOUT`] 1 秒）・start（3 秒）と合わせた
/// `Vm::launch` の最大所要は 7 秒で、10 秒の RPC・都度起動の合計期限に 3 秒の余裕（plugin プロセスの起動・
/// UDS 接続・フレーム送受信の分）を残す。各段階は固定配分で、合計がこの上限を超えない。
pub const LAUNCH_GUEST_MOUNT_TIMEOUT: Duration = Duration::from_secs(3);
/// start（`Vm::launch`）全体を作業スレッドで待つ上限。各段階（走査 1 秒・start 3 秒・ゲスト mount 3 秒）の
/// 合計と同じ 7 秒で、段階ごとの期限で打ち切れない OS 呼び出しのブロックもここで打ち切る（REPAIR-5）。
pub const LAUNCH_TOTAL_TIMEOUT: Duration = Duration::from_secs(7);
/// create の検証全体（kernel・initrd・共有元の検証と共有走査）を作業スレッドで待つ上限（REPAIR-5）。
/// 走査の期限（[`SHARE_SCAN_TIMEOUT`] 1 秒）に検証の余裕を足した値で、10 秒の RPC 期限に 7 秒の余裕を残す。
pub const CREATE_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
/// 共有ディレクトリ配下の走査（`VmConfigSpec::check_share_conflicts_within`）の期限（REPAIR-5・MAC-1）。
///
/// create は検証と登録だけなので 10 秒の RPC 期限に 9 秒の余裕を残す。start は `Vm::launch` が構成構築時に
/// 同じ走査をやり直すため、同じ値を `OpTimeouts::with_share_scan` で渡す。全共有の合計で、超過は
/// `config.shared_dir_scan_timeout`（`TIMEOUT`）。期限はエントリの合間に確かめるため、応答しないファイル
/// システム上で 1 回の OS 呼び出しがブロックした場合は打ち切れない（platform-macos 側の残余）。
pub const SHARE_SCAN_TIMEOUT: Duration = Duration::from_secs(1);
/// 接続終了後の一括停止に使う総予算。core の `ResidentPlugin` は接続を閉じて 5 秒の猶予後に
/// 強制終了するため、それより短くして `plugin.cleanup` の報告まで完了させる（REPAIR-5）。
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(4);

/// id の最大バイト数（core の `ContainerId` と同じ）。
const ID_MAX_BYTES: usize = 255;

const MSG_MALFORMED: &str = "malformed request";
const MSG_INVALID_ID: &str = "invalid container id";
const MSG_UNIMPLEMENTED: &str = "operation is not implemented";
const MSG_UNSUPPORTED_HOST: &str = "Virtualization.framework is only available on macOS";
const MSG_CONFIG_REJECTED: &str = "VM configuration was rejected";
const MSG_VIRTIOFS_IO_FAILED: &str = "virtiofs I/O operation failed";
const MSG_PLATFORM_FAILED: &str = "platform operation failed";
const MSG_VALIDATION_TIMEOUT: &str = "request validation did not finish in time";
const MSG_LAUNCH_TIMEOUT: &str = "VM launch did not finish in time";
const MSG_WORKERS_BUSY: &str = "too many operations are blocked on the host file system";
const MSG_WORKER_FAILED: &str = "isolated operation failed";

/// platform-macos への委譲境界。実機は [`PlatformBackend`]、テストは偽実装。
pub trait MacosBackend {
    /// 起動済み VM のハンドル。drop で資源を手放す。
    type Handle;
    /// VM を構築して起動する（失敗時の後始末は実装側が担う）。
    fn launch(&self, spec: &VmConfigSpec) -> Result<Self::Handle, BackendError>;
    /// 期限つきで VM を停止する。
    fn stop(&self, handle: &Self::Handle) -> Result<(), BackendError>;
    /// [`MacosBackend::stop`] が 1 回に最大で待つ時間。一括停止の予算配分に使う。
    fn stop_timeout(&self) -> Duration;
}

/// [`MacosBackend`] の失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendError {
    /// platform-macos が返したエラー。
    Platform(PlatformError),
    /// 非 macOS ビルド。Virtualization.framework を呼べない（fail-closed）。
    UnsupportedHost,
    /// 起動全体の期限（`after`）内に `launch` が終わらなかった。作業スレッドは起動を続け得るため、
    /// VM が作られた可能性がある（期限後に完成した VM は drop の停止要求へ回るが、完了は確認できない）。
    LaunchTimedOut { after: Duration },
    /// `launch` を開始しなかった（作業スレッドの上限・作業スレッドの起動失敗）。VM は作られていない。
    /// `busy` は上限に達していた場合 true。
    LaunchNotStarted { busy: bool },
}

impl BackendError {
    /// VM が既に停止済み（`Stopped`）で停止操作が `InvalidState` になった場合 true。
    ///
    /// ゲスト側のシャットダウン後は再試行しても同じ理由で失敗し解放できなくなるため、呼び出し側は
    /// 停止済みとして登録を外す（TASK-115.3・MAC-1）。停止完了を確認できるのは `Stopped` だけで、
    /// `Error` を含む他の状態は停止を確認できないため false（登録を残し、`stop` は失敗、`stop_all` は
    /// `remaining` に数える。停止未確認を成功扱いしない。REPAIR-3）。`Error` の VM が `Stopped` へ
    /// 遷移した後の `stop` 再試行で登録が外れる。
    fn is_already_halted(&self) -> bool {
        use fandhe_container_platform_macos::vm::VmState;
        matches!(
            self,
            BackendError::Platform(PlatformError::Vm(VmError::InvalidState {
                state: VmState::Stopped,
                ..
            }))
        )
    }
}

impl BackendError {
    /// 失敗した `launch` が VM（Virtualization.framework のインスタンス）を作った可能性がある場合 true。
    ///
    /// 非 macOS の `UnsupportedHost`・VM 構成の構築失敗（`PlatformError::Config`）・VM 生成前に確定する
    /// `VirtualizationUnsupported` / `InvalidConfiguration` / `InvalidTimeout` は VM が存在しないので false。
    /// 起動・停止・mount 待ちの失敗や未知の分類は停止を確認できないため true（fail-closed。REPAIR-3）。
    fn vm_may_exist(&self) -> bool {
        match self {
            BackendError::UnsupportedHost => false,
            BackendError::LaunchNotStarted { .. } => false,
            BackendError::LaunchTimedOut { .. } => true,
            BackendError::Platform(PlatformError::Config(_)) => false,
            BackendError::Platform(PlatformError::Vm(
                VmError::VirtualizationUnsupported
                | VmError::InvalidConfiguration { .. }
                | VmError::InvalidTimeout { .. },
            )) => false,
            BackendError::Platform(_) => true,
        }
    }
}

impl From<PlatformError> for BackendError {
    fn from(e: PlatformError) -> Self {
        BackendError::Platform(e)
    }
}

/// 実バックエンド。macOS では `Vm::launch` / `Vm::stop` へ委譲し、他 OS では常に `UnsupportedHost`。
///
/// `launch` は [`crate::isolate`] の作業スレッドで実行する。`workers` はその生存数（複製は計数を共有する）。
#[derive(Debug, Default, Clone)]
pub struct PlatformBackend {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    workers: Workers,
}

#[cfg(target_os = "macos")]
impl MacosBackend for PlatformBackend {
    type Handle = fandhe_container_platform_macos::vm::Vm;

    fn launch(&self, spec: &VmConfigSpec) -> Result<Self::Handle, BackendError> {
        use fandhe_container_platform_macos::vm::{OpTimeouts, Vm};
        // 値は固定で範囲内だが、失敗しても panic せず構造化エラーへ写す。
        let timeouts = OpTimeouts::try_new(
            LAUNCH_START_TIMEOUT,
            LAUNCH_STOP_TIMEOUT,
            LAUNCH_STATE_QUERY_TIMEOUT,
        )
        .and_then(|t| t.with_guest_mount(LAUNCH_GUEST_MOUNT_TIMEOUT))
        .and_then(|t| t.with_share_scan(SHARE_SCAN_TIMEOUT))
        .map_err(PlatformError::Vm)?;
        // 構成構築のファイルシステム操作は取り消せないため、起動全体を作業スレッドへ隔離して期限つきで待つ。
        // 期限後に完成した `Vm` は受け手が無く作業スレッド側で drop され、停止要求が走る（REPAIR-5）。
        let spec = spec.clone();
        match isolate::run(&self.workers, LAUNCH_TOTAL_TIMEOUT, move || {
            Vm::launch(&spec, timeouts)
        }) {
            Ok(launched) => Ok(launched?),
            Err(IsolateError::Timeout { after }) => Err(BackendError::LaunchTimedOut { after }),
            Err(IsolateError::Busy) => Err(BackendError::LaunchNotStarted { busy: true }),
            // 作業スレッドを起動できなかった場合は起動を始めていない（VM なし）。
            Err(IsolateError::SpawnFailed) => Err(BackendError::LaunchNotStarted { busy: false }),
            // 起動を始めた作業スレッドが結果を返さずに終わった場合、VM が作られたかを確かめられない（fail-closed）。
            Err(IsolateError::Died) => Err(BackendError::LaunchTimedOut {
                after: LAUNCH_TOTAL_TIMEOUT,
            }),
        }
    }

    fn stop_timeout(&self) -> Duration {
        LAUNCH_STOP_TIMEOUT
    }

    fn stop(&self, handle: &Self::Handle) -> Result<(), BackendError> {
        handle.stop().map_err(|e| PlatformError::Vm(e).into())
    }
}

/// 非 macOS 用の構築不能なハンドル型（起動が成功しないことを型で表す）。
#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
pub enum NoVm {}

#[cfg(not(target_os = "macos"))]
impl MacosBackend for PlatformBackend {
    type Handle = NoVm;

    fn launch(&self, _spec: &VmConfigSpec) -> Result<Self::Handle, BackendError> {
        Err(BackendError::UnsupportedHost)
    }

    fn stop(&self, handle: &Self::Handle) -> Result<(), BackendError> {
        match *handle {}
    }

    fn stop_timeout(&self) -> Duration {
        LAUNCH_STOP_TIMEOUT
    }
}

enum State<H> {
    Created,
    /// 起動に失敗した。`Vm` の drop による停止要求は非同期で完了を待てないため、先の VM が止まったことを
    /// 確認できない。そのため `start` の再試行と `stop` による登録解除（同じ ID の再 `create`）を拒否し、
    /// VM の重複起動を防ぐ（REPAIR-3）。登録は plugin プロセス終了まで残る。
    LaunchFailed,
    Running(H),
}

struct Entry<H> {
    spec: VmConfigSpec,
    state: State<H>,
}

/// [`MacosRuntimeAdapter::stop_all`] の結果（件数のみ。秘匿情報を含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopAllSummary {
    /// 停止に成功した実行中 VM の数。
    pub stopped: usize,
    /// 停止に失敗して残った実行中 VM と、起動失敗後に停止を確認できない VM の数。
    pub remaining: usize,
}

/// 1 回の操作の計測結果（REPAIR-4）。入力値（id・パス・cmdline）は含めず、固定の列挙名と数値のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpEvent {
    /// 操作名（`create` / `start` / `stop` のいずれか。それ以外の操作は計測しない）。
    pub op: &'static str,
    /// 失敗時のエラーコード名（成功は `None`）。
    pub error_code: Option<&'static str>,
    /// この操作の所要時間（マイクロ秒）。
    pub latency_us: u64,
    /// この操作種別の累計成功数。
    pub ok_total: u64,
    /// この操作種別の累計失敗数。
    pub err_total: u64,
}

impl OpEvent {
    /// 構造化ログ 1 行分の JSON（固定の識別子と数値のみで、エスケープ不要）。
    pub fn to_json_line(&self) -> String {
        let result = if self.error_code.is_some() {
            "err"
        } else {
            "ok"
        };
        let code = self
            .error_code
            .map_or_else(String::new, |c| format!(",\"code\":\"{c}\""));
        format!(
            "{{\"event\":\"plugin.op\",\"op\":\"{}\",\"result\":\"{result}\"{code},\"latency_us\":{},\"ok_total\":{},\"err_total\":{}}}",
            self.op, self.latency_us, self.ok_total, self.err_total
        )
    }
}

/// 操作種別ごとの累計 [成功, 失敗]（create / start / stop の順）。
type OpCounts = [[u64; 2]; 3];

/// create / start / stop を [`MacosBackend`] へ委譲する要求ハンドラ。
pub struct MacosRuntimeAdapter<B: MacosBackend> {
    backend: B,
    entries: BTreeMap<String, Entry<B::Handle>>,
    counts: OpCounts,
    sink: Box<dyn FnMut(&OpEvent)>,
    /// create の共有走査の期限（既定 [`SHARE_SCAN_TIMEOUT`]。テストだけが差し替える）。
    share_scan_timeout: Duration,
    /// create の検証全体を待つ上限（既定 [`CREATE_VALIDATION_TIMEOUT`]。テストだけが差し替える）。
    create_validation_timeout: Duration,
    /// create の検証を隔離する作業スレッドの生存数。
    workers: Workers,
    /// テスト専用: 次の create の検証を、送信側が閉じるまで作業スレッド内で止める（応答しない OS 呼び出しの代役）。
    #[cfg(test)]
    validation_gate: Option<std::sync::mpsc::Receiver<()>>,
}

impl<B: MacosBackend> MacosRuntimeAdapter<B> {
    /// 空の登録簿で作る。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            entries: BTreeMap::new(),
            counts: [[0; 2]; 3],
            sink: Box::new(|_| {}),
            share_scan_timeout: SHARE_SCAN_TIMEOUT,
            create_validation_timeout: CREATE_VALIDATION_TIMEOUT,
            workers: Workers::default(),
            #[cfg(test)]
            validation_gate: None,
        }
    }

    /// 操作ごとの計測イベントの出力先を設定する（既定は捨てる。`main.rs` が stderr の JSON 行へ出す。REPAIR-4）。
    #[must_use]
    pub fn with_op_sink(mut self, sink: impl FnMut(&OpEvent) + 'static) -> Self {
        self.sink = Box::new(sink);
        self
    }

    /// [`SHUTDOWN_BUDGET`] 内で [`Self::stop_all_within`] を行う。
    ///
    /// `Vm` の `Drop` は停止を要求するだけで待たないため、接続終了時に `main.rs` が明示的に呼ぶ。
    pub fn stop_all(&mut self) -> StopAllSummary {
        self.stop_all_within(SHUTDOWN_BUDGET)
    }

    /// 実行中の VM に総予算 `budget` 内で順に停止を試み、停止できた分を登録簿から外す。
    ///
    /// 残り予算が 1 回の停止待ち（[`MacosBackend::stop_timeout`]）に満たなければ以降の VM は試さず
    /// `remaining` に数える（core の終了猶予を超えて plugin が強制終了されるのを避ける。REPAIR-5）。
    /// 同時に実行できる VM 数は [`Self::max_running`] で予算内に全件停止できる数へ抑えているため、
    /// 通常は `remaining` が 0 になる。起動に失敗して停止を確認できない VM（`LaunchFailed`）も `remaining` に数える。
    /// 停止できず残った VM は登録簿に残り、呼び出し側（`main.rs`）が
    /// `plugin.cleanup` の `remaining` と終了コードで報告する。以降の回収は `Vm` の drop による停止要求
    /// （非同期・有界回数）と core 側の終了処理に委ねる（完了は保証しない。REPAIR-3）。
    pub fn stop_all_within(&mut self, budget: Duration) -> StopAllSummary {
        // 表現範囲を超える予算は期限なしとして扱う（panic させない）。
        let deadline = Instant::now().checked_add(budget);
        let per_stop = self.backend.stop_timeout();
        let mut summary = StopAllSummary {
            stopped: 0,
            remaining: 0,
        };
        let backend = &self.backend;
        self.entries.retain(|_, entry| match &entry.state {
            State::Created => false,
            // 起動に失敗した VM は drop による非同期の停止要求しか出せず、停止を確認できない。
            // 登録を残して remaining に数え、呼び出し側が成功終了を避けられるようにする（REPAIR-3）。
            State::LaunchFailed => {
                summary.remaining += 1;
                true
            }
            State::Running(h) => {
                let affordable = deadline.is_none_or(|d| {
                    d.checked_duration_since(Instant::now())
                        .is_some_and(|left| left >= per_stop)
                });
                if affordable
                    && backend
                        .stop(h)
                        .map_or_else(|e| e.is_already_halted(), |()| true)
                {
                    summary.stopped += 1;
                    false
                } else {
                    summary.remaining += 1;
                    true
                }
            }
        });
        summary
    }

    /// 同時に実行できる VM 数の上限。[`SHUTDOWN_BUDGET`] 内で逐次停止できる数から 1 台分の処理余裕を引いた数
    /// （最低 1。停止待ちが 0 なら制限しない）。余裕を引くのは、先の停止が期限ぎりぎりまでかかっても
    /// `stop_all_within` が最後の VM の停止を試みられる（残り時間が停止待ち以上になる）ようにするため（REPAIR-5）。
    fn max_running(&self) -> usize {
        let per_stop = self.backend.stop_timeout().as_millis();
        if per_stop == 0 {
            return usize::MAX;
        }
        usize::try_from(SHUTDOWN_BUDGET.as_millis() / per_stop)
            .unwrap_or(usize::MAX)
            .saturating_sub(1)
            .max(1)
    }

    fn create(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let (id, kernel, initrd, cmdline, rest) = match body {
            [_, id, kernel, initrd, cmdline, rest @ ..] => (id, kernel, initrd, cmdline, rest),
            _ => return Err(invalid(MSG_MALFORMED)),
        };
        validate_id(id)?;
        if rest.len() % 3 != 0 {
            return Err(invalid(MSG_MALFORMED));
        }
        if self.entries.contains_key(id.as_str()) {
            return Err(PluginError::new(
                PluginErrorCode::AlreadyExists,
                "container already exists",
            ));
        }
        if self.entries.len() >= MAX_CONTAINERS {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "too many containers",
            ));
        }
        // 以降はホストのファイルシステムに触れる。取り消せない呼び出しで要求処理を止めないよう作業スレッドへ
        // 隔離し、期限を過ぎたら結果を待たない（残った検証は副作用を持たず、結果は捨てられる。REPAIR-5）。
        let (kernel, initrd, cmdline) = (kernel.clone(), initrd.clone(), cmdline.clone());
        let (rest, scan) = (rest.to_vec(), self.share_scan_timeout);
        #[cfg(test)]
        let gate = self.validation_gate.take();
        let spec = isolate::run(&self.workers, self.create_validation_timeout, move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            build_spec(&kernel, &initrd, &cmdline, &rest, scan)
        })
        .map_err(|e| match e {
            IsolateError::Timeout { .. } => {
                PluginError::new(PluginErrorCode::Timeout, MSG_VALIDATION_TIMEOUT)
            }
            IsolateError::Busy => PluginError::new(PluginErrorCode::Unavailable, MSG_WORKERS_BUSY),
            IsolateError::SpawnFailed | IsolateError::Died => {
                PluginError::new(PluginErrorCode::Internal, MSG_WORKER_FAILED)
            }
        })??;
        self.entries.insert(
            id.clone(),
            Entry {
                spec,
                state: State::Created,
            },
        );
        Ok(vec!["created".to_string()])
    }

    fn start(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let id = single_id(body)?;
        let running = self
            .entries
            .values()
            .filter(|e| matches!(e.state, State::Running(_) | State::LaunchFailed))
            .count();
        let max_running = self.max_running();
        let entry = self.entries.get_mut(id).ok_or_else(not_found)?;
        if !matches!(entry.state, State::Created) {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "container is not in the created state",
            ));
        }
        if running >= max_running {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "too many running VMs",
            ));
        }
        // VM が作られ得た失敗は LaunchFailed にして再試行を拒否する（失敗した VM の停止は非同期で完了を
        // 確認できず、再試行すると VM が重複し得るため。後始末は backend.launch が担う）。LaunchFailed は
        // 上の上限判定にも算入する（停止未確認の VM を除外して別 ID を起動すると終了予算を超える。REPAIR-5）。
        // VM 生成前に確定した失敗（非 macOS・構成エラー等）は Created のまま残し、修正後の再試行と
        // stop による登録解除を許す（REPAIR-3）。
        match self.backend.launch(&entry.spec) {
            Ok(handle) => {
                entry.state = State::Running(handle);
                Ok(vec!["running".to_string()])
            }
            Err(e) => {
                if e.vm_may_exist() {
                    entry.state = State::LaunchFailed;
                }
                Err(backend_to_plugin(&e))
            }
        }
    }

    fn stop(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let id = single_id(body)?;
        let entry = self.entries.get(id).ok_or_else(not_found)?;
        if matches!(entry.state, State::LaunchFailed) {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "previous launch failed and VM shutdown is unconfirmed",
            ));
        }
        if let State::Running(h) = &entry.state {
            // 失敗時は登録を残す（再試行可）。
            // 既に停止済み（`Stopped` の InvalidState）なら停止成功として扱い、登録を外す。
            if let Err(e) = self.backend.stop(h)
                && !e.is_already_halted()
            {
                return Err(backend_to_plugin(&e));
            }
        }
        self.entries.remove(id);
        Ok(vec!["stopped".to_string()])
    }
}

impl<B: MacosBackend> RequestHandler for MacosRuntimeAdapter<B> {
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let (idx, op) = match body.first().map(String::as_str) {
            Some("create") => (0, "create"),
            Some("start") => (1, "start"),
            Some("stop") => (2, "stop"),
            _ => {
                return Err(PluginError::new(
                    PluginErrorCode::Unimplemented,
                    MSG_UNIMPLEMENTED,
                ));
            }
        };
        let started = Instant::now();
        let result = match idx {
            0 => self.create(body),
            1 => self.start(body),
            _ => self.stop(body),
        };
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let slot = usize::from(result.is_err());
        if let Some(c) = self.counts.get_mut(idx).and_then(|c| c.get_mut(slot)) {
            *c = c.saturating_add(1);
        }
        let [ok_total, err_total] = self.counts.get(idx).copied().unwrap_or([0; 2]);
        let event = OpEvent {
            op,
            error_code: result.as_ref().err().map(|e| e.code().as_str()),
            latency_us,
            ok_total,
            err_total,
        };
        (self.sink)(&event);
        result
    }
}

fn invalid(msg: &str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

fn not_found() -> PluginError {
    PluginError::new(PluginErrorCode::NotFound, "container not found")
}

/// `["start" | "stop", id]` の形を検証して id を返す。
fn single_id(body: &[String]) -> Result<&str, PluginError> {
    match body {
        [_, id] => {
            validate_id(id)?;
            Ok(id.as_str())
        }
        _ => Err(invalid(MSG_MALFORMED)),
    }
}

/// create の要求本体から検証済みの VM 設定を組み立てる（ホストのファイルシステムに触れる唯一の create 処理）。
///
/// `MacosRuntimeAdapter::create` が [`crate::isolate::run`] の作業スレッドで呼ぶ。`shares` は
/// `(tag, host_dir, "ro" / "rw")` の並び（長さが 3 の倍数であることは呼び出し側が検査済み）。副作用は無い。
fn build_spec(
    kernel: &str,
    initrd: &str,
    cmdline: &str,
    shares: &[String],
    share_scan_timeout: Duration,
) -> Result<VmConfigSpec, PluginError> {
    let initrd = if initrd.is_empty() {
        None
    } else {
        Some(Path::new(initrd))
    };
    let mut specs = Vec::new();
    // 端数は呼び出し側で検査済みのため捨てる剰余は空。
    let (triples, _) = shares.as_chunks::<3>();
    for [tag, dir, access] in triples {
        let access = match access.as_str() {
            "ro" => ShareAccess::ReadOnly,
            "rw" => ShareAccess::ReadWrite,
            _ => return Err(invalid(MSG_MALFORMED)),
        };
        specs.push(VirtiofsShareSpec::new(
            VirtiofsTag::try_new(tag).map_err(config_to_plugin)?,
            // 要求の値を解決せずに検証する（既知の別名だけ実体へ置換。モジュール doc 参照）。
            SharedDirectoryPath::try_new(&rewrite_known_alias(dir, KNOWN_ROOT_ALIASES))
                .map_err(config_to_plugin)?,
            access,
        ));
    }
    let spec = VmConfigSpec::from_parts(Path::new(kernel), initrd, cmdline)
        .map_err(config_to_plugin)?
        .with_shared_directories(VirtiofsSharesSpec::try_new(specs).map_err(config_to_plugin)?);
    // 走査は期限内に打ち切る（巨大な共有元で処理を占有しない。REPAIR-5）。
    spec.check_share_conflicts_within(share_scan_timeout)
        .map_err(config_to_plugin)?;
    Ok(spec)
}

/// core の `ContainerId` と同じ規則（TASK-114 で core 型へ置換予定）。
fn validate_id(id: &str) -> Result<(), PluginError> {
    let ok = !id.is_empty()
        && id.len() <= ID_MAX_BYTES
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(invalid(MSG_INVALID_ID))
    }
}

/// macOS で既定の祖先 symlink（別名, 実体）。`/tmp`・`/var`（一時ディレクトリ `/var/folders/...` を含む）は
/// `/private/...` への symlink で、通常の共有元がここを通る。他 OS では置換しない（空）。
///
/// ここに無い symlink は一切辿らない（`SharedDirectoryPath::try_new` が拒否する）。追加は分離境界の変更に
/// あたるため、レビューを経て行う（MAC-1・SEC-4）。
#[cfg(target_os = "macos")]
const KNOWN_ROOT_ALIASES: &[(&str, &str)] = &[("/tmp", "/private/tmp"), ("/var", "/private/var")];
#[cfg(not(target_os = "macos"))]
const KNOWN_ROOT_ALIASES: &[(&str, &str)] = &[];

/// 要求の共有ディレクトリ `dir` の先頭が既知の別名（`aliases` の `(別名, 実体)`）なら実体へ置換する。
///
/// 置換は次をすべて満たす場合だけ行い、それ以外は `dir` をそのまま返す（検証は呼び出し側の
/// `SharedDirectoryPath::try_new` が行う。本関数は検証を緩めない）:
/// - `dir` が別名そのもの、または別名 + `/` で始まる（要素境界で一致。`/tmpx` は対象外。相対パスは
///   絶対の別名に一致しないため置換されず、`try_new` が拒否する）。
/// - 別名が実際に symlink で、解決先が表の実体と一致する（別名が実ディレクトリの環境や、別の場所を指す
///   環境では置換しない。呼び出し元が指定したのと別のディレクトリを共有しないため）。
///
/// 残りの部分は文字列のまま連結する（`..` 等を正規化で消さず、`try_new` の検査に掛ける）。解決するのは
/// 表の別名 1 段だけで、要求由来の symlink は辿らない。
fn rewrite_known_alias(dir: &str, aliases: &[(&str, &str)]) -> PathBuf {
    for (alias, real) in aliases {
        let Some(rest) = dir.strip_prefix(alias) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with('/')) {
            continue;
        }
        let points_to_real = std::fs::symlink_metadata(alias)
            .is_ok_and(|m| m.file_type().is_symlink())
            && std::fs::canonicalize(alias).is_ok_and(|p| p == Path::new(real));
        if points_to_real {
            return PathBuf::from(format!("{real}{rest}"));
        }
    }
    PathBuf::from(dir)
}

fn config_to_plugin(e: ConfigError) -> PluginError {
    to_plugin_error(&PlatformError::Config(e))
}

fn backend_to_plugin(e: &BackendError) -> PluginError {
    match e {
        BackendError::Platform(p) => to_plugin_error(p),
        BackendError::UnsupportedHost => {
            PluginError::new(PluginErrorCode::Unimplemented, MSG_UNSUPPORTED_HOST)
        }
        BackendError::LaunchTimedOut { .. } => {
            PluginError::new(PluginErrorCode::Timeout, MSG_LAUNCH_TIMEOUT)
        }
        BackendError::LaunchNotStarted { busy: true } => {
            PluginError::new(PluginErrorCode::Unavailable, MSG_WORKERS_BUSY)
        }
        BackendError::LaunchNotStarted { busy: false } => {
            PluginError::new(PluginErrorCode::Unavailable, MSG_WORKER_FAILED)
        }
    }
}

/// platform-macos のエラーを plugin のエラーフレーム用へ変換する唯一の箇所（モジュール doc の対応表）。
pub fn to_plugin_error(e: &PlatformError) -> PluginError {
    use PluginErrorCode as C;
    let (code, detail): (C, String) = match e {
        PlatformError::Config(c) => {
            let code = match c {
                ConfigError::PathIo { .. }
                | ConfigError::UrlConversion { .. }
                | ConfigError::DiskAttachment { .. }
                | ConfigError::ConsoleLogOpen { .. }
                | ConfigError::ConsoleLogWriter { .. } => C::Internal,
                ConfigError::ConsoleLogNotOwned { .. }
                | ConfigError::ConsoleLogInsecureMode { .. }
                | ConfigError::ConsoleLogParentWorldWritable { .. } => C::PermissionDenied,
                ConfigError::ConsoleLogInUse { .. } => C::FailedPrecondition,
                ConfigError::SharedDirScanTimeout { .. } => C::Timeout,
                _ => C::InvalidArgument,
            };
            // message() は要求由来のパスを埋め込むため使わない。
            (code, MSG_CONFIG_REJECTED.to_string())
        }
        PlatformError::Vm(v) => {
            let code = match v {
                VmError::VirtualizationUnsupported
                | VmError::InvalidConfiguration { .. }
                | VmError::InvalidState { .. } => C::FailedPrecondition,
                VmError::InvalidTimeout { .. } => C::InvalidArgument,
                VmError::Timeout { .. } => C::Timeout,
                VmError::CallbackLost { .. } => C::Unavailable,
                _ => C::Internal,
            };
            (code, e.message())
        }
        PlatformError::GuestMount(g) => {
            // message() は Failed / Timeout / InvalidReport が要求由来の共有タグ・報告内容を埋め込むため
            // 使わない。詳細は入力値を含まないコード（`guest_mount.*`）で伝え、本文は固定文言にする。
            let (code, detail) = match g {
                GuestMountError::Timeout { .. } => {
                    (C::Timeout, "guest did not report mount results in time")
                }
                GuestMountError::VmStopped { .. } => (
                    C::Unavailable,
                    "virtual machine stopped before guest mounts completed",
                ),
                GuestMountError::ReportChannelClosed => (
                    C::Unavailable,
                    "console reader ended before guest mounts completed",
                ),
                GuestMountError::Failed { .. } => {
                    (C::Internal, "guest failed to mount a virtiofs share")
                }
                GuestMountError::InvalidReport { .. } => {
                    (C::Internal, "invalid guest mount report")
                }
                _ => (C::Internal, "guest mount failed"),
            };
            (code, detail.to_string())
        }
        PlatformError::VirtiofsIo(v) => {
            let code = match v {
                VirtiofsIoError::Protocol { .. } => match e.code() {
                    "virtiofs_io.invalid_argument" => C::InvalidArgument,
                    "virtiofs_io.timeout" => C::Timeout,
                    "virtiofs_io.unavailable" => C::Unavailable,
                    "virtiofs_io.unimplemented" => C::Unimplemented,
                    "virtiofs_io.data_loss" => C::DataLoss,
                    "virtiofs_io.already_exists" => C::AlreadyExists,
                    "virtiofs_io.resource_exhausted" => C::FailedPrecondition,
                    _ => C::Internal,
                },
                VirtiofsIoError::ReadOnlyShare { .. } => C::FailedPrecondition,
                VirtiofsIoError::InFlightLimitTooSmall { .. }
                | VirtiofsIoError::InvalidReconnectPolicy { .. } => C::InvalidArgument,
                VirtiofsIoError::ConnectionLost {
                    unflushed_writes, ..
                }
                | VirtiofsIoError::ReconnectFailed {
                    unflushed_writes, ..
                } => {
                    if *unflushed_writes > 0 {
                        C::DataLoss
                    } else {
                        C::Unavailable
                    }
                }
                _ => C::Internal,
            };
            // message() は ReadOnlyShare が要求由来の共有タグ、Protocol・ConnectionLost・ReconnectFailed が
            // 相手（ゲスト側サーバ）由来の本文を埋め込むため使わない。分類は `virtiofs_io.*` のコードで伝える。
            (code, MSG_VIRTIOFS_IO_FAILED.to_string())
        }
        // 将来追加される分類は fail-closed で INTERNAL にし、内容の分からない message() は載せない。
        _ => (C::Internal, MSG_PLATFORM_FAILED.to_string()),
    };
    PluginError::new(code, format!("{}: {}", e.code(), detail))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::Duration;

    use fandhe_container_io::{IoError, IoErrorCode};
    use fandhe_container_platform_macos::error::VmOp;
    use fandhe_container_platform_macos::virtiofs::VirtiofsIoOp;
    use fandhe_container_platform_macos::vm::VmState;

    use super::*;

    #[derive(Default)]
    struct Calls {
        launched: Vec<(PathBuf, Vec<(String, bool)>)>,
        stopped: Vec<u32>,
        fail_launch: bool,
        /// VM 生成前に確定する失敗（非 macOS 相当）を返す。
        unsupported_launch: bool,
        fail_stop: bool,
        halted_stop: bool,
        /// 停止要求を VM の `Error` 状態で拒否する（停止未確認）。
        error_stop: bool,
        stop_timeout: Duration,
        next: u32,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<Calls>>);

    impl MacosBackend for Fake {
        type Handle = u32;
        fn launch(&self, spec: &VmConfigSpec) -> Result<u32, BackendError> {
            let mut c = self.0.borrow_mut();
            if c.unsupported_launch {
                return Err(BackendError::UnsupportedHost);
            }
            if c.fail_launch {
                return Err(BackendError::Platform(PlatformError::Vm(
                    VmError::StartFailed {
                        domain: "d".into(),
                        code: 1,
                    },
                )));
            }
            let shares = spec
                .shares
                .shares()
                .iter()
                .map(|s| (s.tag.as_str().to_string(), s.access.is_read_only()))
                .collect();
            c.launched
                .push((spec.kernel.as_path().to_path_buf(), shares));
            c.next += 1;
            Ok(c.next)
        }
        fn stop_timeout(&self) -> Duration {
            self.0.borrow().stop_timeout
        }
        fn stop(&self, h: &u32) -> Result<(), BackendError> {
            let mut c = self.0.borrow_mut();
            if c.halted_stop {
                return Err(BackendError::Platform(PlatformError::Vm(
                    VmError::InvalidState {
                        op: VmOp::Stop,
                        state: VmState::Stopped,
                    },
                )));
            }
            if c.error_stop {
                return Err(BackendError::Platform(PlatformError::Vm(
                    VmError::InvalidState {
                        op: VmOp::Stop,
                        state: VmState::Error,
                    },
                )));
            }
            if c.fail_stop {
                return Err(BackendError::UnsupportedHost);
            }
            c.stopped.push(*h);
            Ok(())
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-adapter-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).expect("mkdir");
        d.canonicalize().expect("canon")
    }

    fn kernel(dir: &Path) -> String {
        let k = dir.join("vmlinuz");
        std::fs::write(&k, b"k").expect("write");
        k.to_str().expect("utf8").to_string()
    }

    fn adapter() -> (MacosRuntimeAdapter<Fake>, Fake) {
        let f = Fake::default();
        (MacosRuntimeAdapter::new(f.clone()), f)
    }

    fn create_ok(a: &mut MacosRuntimeAdapter<Fake>, id: &str, k: &str) {
        let r = a.handle(&s(&["create", id, k, "", "console=hvc0"]));
        assert_eq!(r.expect("create"), s(&["created"]));
    }

    fn err_of(r: Result<Vec<String>, PluginError>) -> (PluginErrorCode, String) {
        let e = r.expect_err("must fail");
        (e.code(), e.message().to_string())
    }

    /// TASK-115.3・PLUG-1・MAC-1: create は登録のみ、start が launch を 1 回、stop が stop を 1 回呼ぶ。
    #[test]
    fn task115_3_plug1_mac1_create_start_stop_delegate() {
        let dir = tmp_dir("flow");
        let k = kernel(&dir);
        let share = dir.join("share");
        std::fs::create_dir_all(&share).expect("mkdir");
        let (mut a, f) = adapter();
        let r = a.handle(&s(&[
            "create",
            "c1",
            &k,
            "",
            "console=hvc0",
            "data",
            share.to_str().expect("utf8"),
            "rw",
        ]));
        assert_eq!(r.expect("create"), s(&["created"]));
        assert!(f.0.borrow().launched.is_empty());
        assert_eq!(
            a.handle(&s(&["start", "c1"])).expect("start"),
            s(&["running"])
        );
        assert_eq!(
            f.0.borrow().launched,
            vec![(PathBuf::from(&k), vec![("data".to_string(), false)])]
        );
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).expect("stop"),
            s(&["stopped"])
        );
        assert_eq!(f.0.borrow().stopped, vec![1]);
        assert_eq!(
            err_of(a.handle(&s(&["start", "c1"]))).0,
            PluginErrorCode::NotFound
        );
    }

    /// TASK-115.3・PLUG-1: 状態遷移・重複・上限・未登録のエラーコード。
    #[test]
    fn task115_3_plug1_state_errors() {
        let dir = tmp_dir("state");
        let k = kernel(&dir);
        let (mut a, _f) = adapter();
        create_ok(&mut a, "a", &k);
        let dup = a.handle(&s(&["create", "a", &k, "", ""]));
        assert_eq!(err_of(dup).0, PluginErrorCode::AlreadyExists);
        assert_eq!(
            err_of(a.handle(&s(&["stop", "zz"]))).0,
            PluginErrorCode::NotFound
        );
        a.handle(&s(&["start", "a"])).expect("start");
        let (c, m) = err_of(a.handle(&s(&["start", "a"])));
        assert_eq!(c, PluginErrorCode::FailedPrecondition);
        assert_eq!(m, "container is not in the created state");
        for i in 1..MAX_CONTAINERS {
            create_ok(&mut a, &format!("n{i}"), &k);
        }
        let over = a.handle(&s(&["create", "over", &k, "", ""]));
        assert_eq!(
            err_of(over),
            (
                PluginErrorCode::FailedPrecondition,
                "too many containers".to_string()
            )
        );
    }

    /// TASK-115.3・PLUG-1・REPAIR-2: 不正本体は固定文言で拒否し、入力値を反射しない。
    #[test]
    fn task115_3_plug1_malformed_requests_do_not_reflect_input() {
        let (mut a, _f) = adapter();
        let cases: Vec<Vec<String>> = vec![
            s(&["create", "a", "/k", ""]),
            s(&["create", "a", "/k", "", "c", "tag"]),
            s(&["create", "a", "/k", "", "c", "tag", "/d", "SECRETMODE"]),
            s(&["create", "..", "/k", "", "c"]),
            s(&["create", "a/b", "/k", "", "c"]),
            s(&["start"]),
            s(&["start", "a", "extra"]),
            s(&["stop", ""]),
        ];
        for body in cases {
            let (c, m) = err_of(a.handle(&body));
            assert_eq!(c, PluginErrorCode::InvalidArgument, "{body:?}");
            assert!(
                m == "malformed request" || m == "invalid container id",
                "{m}"
            );
        }
    }

    /// TASK-115.3・PLUG-1: kill / delete / state / 未知操作は UNIMPLEMENTED。
    #[test]
    fn task115_3_plug1_unknown_ops_unimplemented() {
        let (mut a, _f) = adapter();
        for op in ["kill", "delete", "state", "bogus"] {
            let (c, m) = err_of(a.handle(&s(&[op, "a"])));
            assert_eq!(c, PluginErrorCode::Unimplemented);
            assert_eq!(m, "operation is not implemented");
        }
    }

    /// TASK-115.3・REPAIR-3: launch 失敗後は start 再試行・stop による登録解除・同 ID の再 create を拒否する（VM 重複防止）。
    #[test]
    fn task115_3_repair3_launch_failure_blocks_restart() {
        let dir = tmp_dir("launchfail");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        f.0.borrow_mut().fail_launch = true;
        let (c, m) = err_of(a.handle(&s(&["start", "a"])));
        assert_eq!(c, PluginErrorCode::Internal);
        assert!(m.starts_with("vm.start_failed: "), "{m}");
        f.0.borrow_mut().fail_launch = false;
        let (c, m) = err_of(a.handle(&s(&["start", "a"])));
        assert_eq!(c, PluginErrorCode::FailedPrecondition);
        assert_eq!(m, "container is not in the created state");
        assert!(f.0.borrow().launched.is_empty());
        let (c, m) = err_of(a.handle(&s(&["stop", "a"])));
        assert_eq!(c, PluginErrorCode::FailedPrecondition);
        assert_eq!(m, "previous launch failed and VM shutdown is unconfirmed");
        let (c, _) = err_of(a.handle(&s(&["create", "a", &k, "", ""])));
        assert_eq!(c, PluginErrorCode::AlreadyExists);
        assert!(f.0.borrow().stopped.is_empty());
    }

    /// TASK-115.3・REPAIR-3: 起動失敗後の停止未確認 VM は stop_all で remaining に数え、登録を残す。
    #[test]
    fn task115_3_repair3_launch_failed_counts_as_remaining() {
        let dir = tmp_dir("launchfail-remaining");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        f.0.borrow_mut().fail_launch = true;
        err_of(a.handle(&s(&["start", "a"])));
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 0,
                remaining: 1
            }
        );
        // 登録は残るため再度数える。
        assert_eq!(a.stop_all().remaining, 1);
    }

    /// TASK-115.3・REPAIR-4: 操作ごとに成功・失敗の累計とレイテンシを入力値抜きで出力する。
    #[test]
    fn task115_3_repair4_op_events_count_without_inputs() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let dir = tmp_dir("opevents");
        let k = kernel(&dir);
        let events: Rc<RefCell<Vec<OpEvent>>> = Rc::default();
        let sink = Rc::clone(&events);
        let (a, _f) = adapter();
        let mut a = a.with_op_sink(move |e| sink.borrow_mut().push(e.clone()));
        create_ok(&mut a, "SECRETID", &k);
        a.handle(&s(&["start", "SECRETID"])).expect("start");
        err_of(a.handle(&s(&["start", "SECRETID"])));
        a.handle(&s(&["stop", "SECRETID"])).expect("stop");
        let ev = events.borrow();
        let ops: Vec<_> = ev.iter().map(|e| (e.op, e.error_code)).collect();
        assert_eq!(
            ops,
            vec![
                ("create", None),
                ("start", None),
                ("start", Some("FAILED_PRECONDITION")),
                ("stop", None),
            ]
        );
        assert_eq!((ev[2].ok_total, ev[2].err_total), (1, 1));
        let line = ev[2].to_json_line();
        assert!(line.starts_with("{\"event\":\"plugin.op\",\"op\":\"start\",\"result\":\"err\""));
        assert!(line.contains("\"code\":\"FAILED_PRECONDITION\""), "{line}");
        assert!(!line.contains("SECRETID"));
    }

    /// TASK-115.3・REPAIR-5: 同時実行 VM 数は終了予算内に全件停止できる数に制限され、全件停止できる。
    #[test]
    fn task115_3_repair5_running_cap_fits_shutdown_budget() {
        let dir = tmp_dir("cap");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        f.0.borrow_mut().stop_timeout = Duration::from_secs(2);
        for id in ["a", "b"] {
            create_ok(&mut a, id, &k);
        }
        a.handle(&s(&["start", "a"])).expect("start");
        assert_eq!(
            err_of(a.handle(&s(&["start", "b"]))),
            (
                PluginErrorCode::FailedPrecondition,
                "too many running VMs".to_string()
            )
        );
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 1,
                remaining: 0
            }
        );
    }

    /// TASK-115.3・REPAIR-5: 起動失敗後の停止未確認 VM（LaunchFailed）も実行中 VM 数の上限に算入する。
    #[test]
    fn task115_3_repair5_launch_failed_counts_toward_running_cap() {
        let dir = tmp_dir("cap-launchfailed");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        f.0.borrow_mut().stop_timeout = Duration::from_secs(2);
        for id in ["a", "b"] {
            create_ok(&mut a, id, &k);
        }
        f.0.borrow_mut().fail_launch = true;
        err_of(a.handle(&s(&["start", "a"])));
        f.0.borrow_mut().fail_launch = false;
        assert_eq!(
            err_of(a.handle(&s(&["start", "b"]))),
            (
                PluginErrorCode::FailedPrecondition,
                "too many running VMs".to_string()
            )
        );
        assert!(f.0.borrow().launched.is_empty());
    }

    /// TASK-115.3・REPAIR-3: VM 生成前に確定した失敗は Created のまま残り、再試行と stop による登録解除ができる。
    #[test]
    fn task115_3_repair3_pre_vm_failure_keeps_created() {
        let dir = tmp_dir("prevm");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        f.0.borrow_mut().unsupported_launch = true;
        assert_eq!(
            err_of(a.handle(&s(&["start", "a"]))),
            (
                PluginErrorCode::Unimplemented,
                MSG_UNSUPPORTED_HOST.to_string()
            )
        );
        create_ok(&mut a, "b", &k);
        f.0.borrow_mut().unsupported_launch = false;
        a.handle(&s(&["start", "b"])).expect("retry start");
        // 同 ID の再作成のため stop で登録を外せる。
        a.handle(&s(&["stop", "a"])).expect("stop created");
        create_ok(&mut a, "a", &k);
    }

    /// TASK-115.3・REPAIR-3: VM が作られ得た失敗と生成前に確定する失敗の判別。
    #[test]
    fn task115_3_repair3_vm_may_exist_classification() {
        let vm = |e| BackendError::Platform(PlatformError::Vm(e));
        assert!(!BackendError::UnsupportedHost.vm_may_exist());
        assert!(!vm(VmError::VirtualizationUnsupported).vm_may_exist());
        assert!(
            !vm(VmError::InvalidConfiguration {
                domain: "d".into(),
                code: 1
            })
            .vm_may_exist()
        );
        assert!(
            vm(VmError::StartFailed {
                domain: "d".into(),
                code: 1
            })
            .vm_may_exist()
        );
        assert!(
            vm(VmError::Timeout {
                op: VmOp::Start,
                after: Duration::from_secs(1)
            })
            .vm_may_exist()
        );
        assert!(
            BackendError::Platform(PlatformError::GuestMount(
                GuestMountError::ReportChannelClosed
            ))
            .vm_may_exist()
        );
    }

    /// TASK-115.3・MAC-1: guest mount のエラーは要求由来の共有タグを message に含めない。
    #[test]
    fn task115_3_mac1_guest_mount_message_has_no_tag() {
        let gm = |e| PlatformError::GuestMount(e);
        for e in [
            GuestMountError::Timeout {
                after: Duration::from_secs(60),
                pending: vec!["SECRETTAG".into()],
            },
            GuestMountError::Failed {
                tag: "SECRETTAG".into(),
                errno: 5,
            },
            GuestMountError::InvalidReport {
                reason: "SECRETTAG".into(),
            },
        ] {
            let (_, m) = pe(gm(e));
            assert!(!m.contains("SECRETTAG"), "{m}");
        }
        assert_eq!(
            pe(gm(GuestMountError::Timeout {
                after: Duration::from_secs(60),
                pending: vec!["t".into()]
            })),
            (
                PluginErrorCode::Timeout,
                "guest_mount.timeout: guest did not report mount results in time".to_string()
            )
        );
    }

    #[cfg(unix)]
    fn create_share(
        a: &mut MacosRuntimeAdapter<Fake>,
        id: &str,
        k: &str,
        host_dir: &str,
    ) -> Result<Vec<String>, PluginError> {
        a.handle(&s(&["create", id, k, "", "", "data", host_dir, "ro"]))
    }

    /// TASK-115.3・MAC-1・SEC-4: 共有元は要求の値のまま検証し、symlink 経由（最終要素・祖先）・相対パス・
    /// `..`・非実在を解決せずに拒否する（固定文言。パスを反射しない）。
    #[cfg(unix)]
    #[test]
    fn task115_3_mac1_sec4_share_dir_rejects_symlink_and_relative() {
        let dir = tmp_dir("share-strict");
        let k = kernel(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(real.join("sub")).expect("mkdir");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let (mut a, f) = adapter();
        let rejected = |code: &str| {
            (
                PluginErrorCode::InvalidArgument,
                format!("{code}: VM configuration was rejected"),
            )
        };
        for via_link in [link.clone(), link.join("sub")] {
            assert_eq!(
                err_of(create_share(
                    &mut a,
                    "c1",
                    &k,
                    via_link.to_str().expect("utf8")
                )),
                rejected("config.shared_dir_symlink")
            );
        }
        // 相対パスは plugin の CWD 基準で解決しない（CWD に実在する `.` 始まりでも拒否）。
        for relative in ["real", "./", "tmp/x"] {
            assert_eq!(
                err_of(create_share(&mut a, "c1", &k, relative)),
                rejected("config.path_not_absolute")
            );
        }
        let dotdot = format!("{}/sub/..", real.to_str().expect("utf8"));
        assert_eq!(
            err_of(create_share(&mut a, "c1", &k, &dotdot)),
            rejected("config.shared_dir_not_normalized")
        );
        let missing = dir.join("missing");
        assert_eq!(
            err_of(create_share(
                &mut a,
                "c1",
                &k,
                missing.to_str().expect("utf8")
            )),
            rejected("config.path_not_found")
        );
        // 拒否された要求は登録されず、実体パスなら受理される。
        assert_eq!(
            err_of(a.handle(&s(&["start", "c1"]))).0,
            PluginErrorCode::NotFound
        );
        assert_eq!(
            create_share(&mut a, "c1", &k, real.to_str().expect("utf8")).expect("create"),
            s(&["created"])
        );
        assert!(f.0.borrow().launched.is_empty());
    }

    /// TASK-115.3・MAC-1: OS の一時ディレクトリ配下の共有元を、呼び出し側が実体パスへ直さなくても受理する
    /// （macOS は `/var/folders/...` が既知の別名 `/var` → `/private/var` を通る。Linux は別名なしで通る）。
    #[cfg(unix)]
    #[test]
    fn task115_3_mac1_share_dir_under_os_temp_dir_is_accepted() {
        let dir = tmp_dir("share-temp");
        let k = kernel(&dir);
        // 正規化していない綴り（macOS では祖先に symlink を含む）。
        let raw = std::env::temp_dir()
            .join(format!("fc-adapter-{}-share-temp", std::process::id()))
            .join("share");
        std::fs::create_dir_all(&raw).expect("mkdir");
        let (mut a, f) = adapter();
        assert_eq!(
            create_share(&mut a, "c1", &k, raw.to_str().expect("utf8")).expect("create"),
            s(&["created"])
        );
        a.handle(&s(&["start", "c1"])).expect("start");
        assert_eq!(
            f.0.borrow().launched,
            vec![(PathBuf::from(&k), vec![("data".to_string(), true)])]
        );
    }

    /// TASK-115.3・MAC-1・SEC-4: 既知の別名の置換は、別名が実際に表の実体を指す symlink で、要素境界で
    /// 一致する絶対パスのときだけ行う。それ以外は入力をそのまま返す（検証は `try_new` に委ねる）。
    #[cfg(unix)]
    #[test]
    fn task115_3_mac1_sec4_known_alias_rewrite_is_exact() {
        let dir = tmp_dir("alias");
        let real = dir.join("private-tmp");
        let other = dir.join("other");
        std::fs::create_dir_all(real.join("x")).expect("mkdir");
        std::fs::create_dir_all(&other).expect("mkdir");
        let alias = dir.join("tmp");
        std::os::unix::fs::symlink(&real, &alias).expect("symlink");
        let plain = dir.join("plain");
        std::fs::create_dir_all(&plain).expect("mkdir");
        let (alias, real, other, plain) = (
            alias.to_str().expect("utf8"),
            real.to_str().expect("utf8"),
            other.to_str().expect("utf8"),
            plain.to_str().expect("utf8"),
        );
        let table = [(alias, real)];
        let rw = |d: &str, t: &[(&str, &str)]| rewrite_known_alias(d, t);
        assert_eq!(rw(alias, &table), PathBuf::from(real));
        assert_eq!(
            rw(&format!("{alias}/x"), &table),
            PathBuf::from(format!("{real}/x"))
        );
        // 残りは正規化せずに連結し、`..` を `try_new` の検査へ残す。
        assert_eq!(
            rw(&format!("{alias}/x/../y"), &table),
            PathBuf::from(format!("{real}/x/../y"))
        );
        // 要素境界で一致しない・相対・表に無いパスは置換しない。
        for untouched in [
            format!("{alias}x/y"),
            "tmp/x".to_string(),
            plain.to_string(),
        ] {
            assert_eq!(rw(&untouched, &table), PathBuf::from(&untouched));
        }
        // 別名が表と違う場所を指す symlink・symlink でない実ディレクトリなら置換しない。
        for wrong in [[(alias, other)], [(plain, real)]] {
            let d = format!("{}/x", wrong[0].0);
            assert_eq!(rw(&d, &wrong), PathBuf::from(&d));
        }
        // 既定の表は macOS だけが持ち、/tmp・/var の 2 件に限る。
        #[cfg(target_os = "macos")]
        assert_eq!(
            KNOWN_ROOT_ALIASES,
            &[("/tmp", "/private/tmp"), ("/var", "/private/var")]
        );
        #[cfg(not(target_os = "macos"))]
        assert!(KNOWN_ROOT_ALIASES.is_empty());
    }

    /// TASK-115.3・REPAIR-5・MAC-1: create の共有走査は期限で打ち切り、`TIMEOUT` の固定文言で返して登録しない。
    #[cfg(unix)]
    #[test]
    fn task115_3_repair5_share_scan_deadline_returns_timeout() {
        let dir = tmp_dir("scan-deadline");
        let k = kernel(&dir);
        let share = dir.join("share");
        std::fs::create_dir_all(&share).expect("mkdir");
        std::fs::write(share.join("f"), b"x").expect("write");
        let (mut a, _f) = adapter();
        assert_eq!(a.share_scan_timeout, Duration::from_secs(1));
        a.share_scan_timeout = Duration::ZERO;
        let share = share.to_str().expect("utf8");
        assert_eq!(
            err_of(create_share(&mut a, "c1", &k, share)),
            (
                PluginErrorCode::Timeout,
                "config.shared_dir_scan_timeout: VM configuration was rejected".to_string()
            )
        );
        assert_eq!(
            err_of(a.handle(&s(&["start", "c1"]))).0,
            PluginErrorCode::NotFound
        );
        // 既定の期限なら同じ要求は通る。
        a.share_scan_timeout = SHARE_SCAN_TIMEOUT;
        assert_eq!(
            create_share(&mut a, "c1", &k, share).expect("create"),
            s(&["created"])
        );
    }

    /// TASK-115.3・REPAIR-5: create の検証が戻らなくても要求処理は期限で `TIMEOUT` を返して登録せず、
    /// 戻らない検証が上限まで溜まったら新しい検証を開始せず `UNAVAILABLE` で拒否する。検証が戻れば再び通る。
    #[test]
    fn task115_3_repair5_blocked_create_validation_times_out() {
        let dir = tmp_dir("blocked-validation");
        let k = kernel(&dir);
        let (mut a, _f) = adapter();
        assert_eq!(a.create_validation_timeout, Duration::from_secs(3));
        a.create_validation_timeout = Duration::from_millis(20);
        let mut releases = Vec::new();
        for _ in 0..isolate::MAX_WORKERS {
            let (release, gate) = std::sync::mpsc::channel::<()>();
            releases.push(release);
            a.validation_gate = Some(gate);
            assert_eq!(
                err_of(a.handle(&s(&["create", "a", &k, "", ""]))),
                (
                    PluginErrorCode::Timeout,
                    "request validation did not finish in time".to_string()
                )
            );
        }
        assert_eq!(a.workers.live(), isolate::MAX_WORKERS);
        assert_eq!(
            err_of(a.handle(&s(&["create", "a", &k, "", ""]))),
            (
                PluginErrorCode::Unavailable,
                "too many operations are blocked on the host file system".to_string()
            )
        );
        // どの要求も登録していない。
        assert_eq!(
            err_of(a.handle(&s(&["start", "a"]))).0,
            PluginErrorCode::NotFound
        );
        drop(releases);
        for _ in 0..500 {
            if a.workers.live() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(a.workers.live(), 0);
        a.create_validation_timeout = CREATE_VALIDATION_TIMEOUT;
        create_ok(&mut a, "a", &k);
    }

    /// TASK-115.3・REPAIR-5・REPAIR-3: 起動全体の期限超過は `TIMEOUT` で VM が作られ得る失敗（停止未確認）、
    /// 起動を開始しなかった失敗は `UNAVAILABLE` で VM なしとして扱う。
    #[test]
    fn task115_3_repair5_launch_isolation_errors_map() {
        let timed_out = BackendError::LaunchTimedOut {
            after: LAUNCH_TOTAL_TIMEOUT,
        };
        assert!(timed_out.vm_may_exist());
        let p = backend_to_plugin(&timed_out);
        assert_eq!(
            (p.code(), p.message()),
            (PluginErrorCode::Timeout, "VM launch did not finish in time")
        );
        for (busy, msg) in [
            (
                true,
                "too many operations are blocked on the host file system",
            ),
            (false, "isolated operation failed"),
        ] {
            let e = BackendError::LaunchNotStarted { busy };
            assert!(!e.vm_may_exist());
            let p = backend_to_plugin(&e);
            assert_eq!((p.code(), p.message()), (PluginErrorCode::Unavailable, msg));
        }
    }

    /// TASK-115.3・REPAIR-5: 走査期限の超過は `TIMEOUT` へ写し、VM を作らない失敗として扱う。
    #[test]
    fn task115_3_repair5_scan_timeout_maps_to_timeout() {
        let e = PlatformError::Config(ConfigError::SharedDirScanTimeout {
            after: Duration::from_secs(2),
        });
        let p = to_plugin_error(&e);
        assert_eq!(
            (p.code(), p.message()),
            (
                PluginErrorCode::Timeout,
                "config.shared_dir_scan_timeout: VM configuration was rejected"
            )
        );
        assert!(!BackendError::Platform(e).vm_may_exist());
    }

    /// TASK-115.3・REPAIR-3: stop 失敗は登録を残す。
    #[test]
    fn task115_3_mac1_failures_keep_state_for_retry() {
        let dir = tmp_dir("retry");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        a.handle(&s(&["start", "a"])).expect("start");
        f.0.borrow_mut().fail_stop = true;
        let (c, m) = err_of(a.handle(&s(&["stop", "a"])));
        assert_eq!(c, PluginErrorCode::Unimplemented);
        assert_eq!(m, MSG_UNSUPPORTED_HOST);
        f.0.borrow_mut().fail_stop = false;
        a.handle(&s(&["stop", "a"])).expect("retry stop");
    }

    /// TASK-115.3・MAC-1: Config 系エラーは要求由来のパスを message に含めない。
    #[test]
    fn task115_3_mac1_config_error_does_not_leak_path() {
        let (mut a, _f) = adapter();
        // OS 非依存の絶対パス（Windows では Unix 形式パスが相対扱いになるため temp_dir 基準にする）。
        let missing = std::env::temp_dir().join("fc-adapter-SECRETPATH-missing");
        let missing = missing.to_str().expect("utf8");
        let (c, m) = err_of(a.handle(&s(&["create", "a", missing, "", ""])));
        assert_eq!(c, PluginErrorCode::InvalidArgument);
        assert_eq!(m, "config.path_not_found: VM configuration was rejected");
        assert!(!m.contains("SECRETPATH"));
    }

    /// TASK-115.3・MAC-1: 停止済み VM の InvalidState は停止成功として登録を外す。
    #[test]
    fn task115_3_mac1_already_halted_stop_releases_entry() {
        let dir = tmp_dir("halted");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        create_ok(&mut a, "b", &k);
        a.handle(&s(&["start", "a"])).expect("start");
        a.handle(&s(&["start", "b"])).expect("start");
        f.0.borrow_mut().halted_stop = true;
        assert_eq!(a.handle(&s(&["stop", "a"])).expect("stop"), s(&["stopped"]));
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 1,
                remaining: 0
            }
        );
    }

    /// TASK-115.3・REPAIR-3: `Error` 状態で停止要求が拒否された VM は停止未確認として登録を残し、
    /// `stop` は失敗、`stop_all` は `remaining` に数える。`Stopped` を確認できた再試行で登録が外れる。
    #[test]
    fn task115_3_repair3_error_state_stop_is_not_confirmed() {
        let dir = tmp_dir("error-state");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        create_ok(&mut a, "a", &k);
        a.handle(&s(&["start", "a"])).expect("start");
        f.0.borrow_mut().error_stop = true;
        assert_eq!(
            err_of(a.handle(&s(&["stop", "a"]))),
            (
                PluginErrorCode::FailedPrecondition,
                "vm.invalid_state: cannot stop the virtual machine in state Error".to_string()
            )
        );
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 0,
                remaining: 1
            }
        );
        f.0.borrow_mut().error_stop = false;
        f.0.borrow_mut().halted_stop = true;
        assert_eq!(a.handle(&s(&["stop", "a"])).expect("stop"), s(&["stopped"]));
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 0,
                remaining: 0
            }
        );
    }

    /// TASK-115.3・REPAIR-5: 表現範囲を超える停止予算でも panic せず、期限なしとして全件の停止を試みる。
    #[test]
    fn task115_3_repair5_stop_all_huge_budget_does_not_panic() {
        let dir = tmp_dir("huge-budget");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        f.0.borrow_mut().stop_timeout = Duration::from_secs(1);
        create_ok(&mut a, "a", &k);
        a.handle(&s(&["start", "a"])).expect("start");
        assert_eq!(
            a.stop_all_within(Duration::MAX),
            StopAllSummary {
                stopped: 1,
                remaining: 0
            }
        );
        assert_eq!(f.0.borrow().stopped, vec![1]);
    }

    /// TASK-115.3・REPAIR-5: 起動・終了の待機は core の RPC 期限 10 秒・終了猶予 5 秒に収まる。
    #[test]
    fn task115_3_repair5_timeouts_fit_core_deadlines() {
        let launch = LAUNCH_START_TIMEOUT + LAUNCH_GUEST_MOUNT_TIMEOUT + SHARE_SCAN_TIMEOUT;
        // 走査 1 秒＋start 3 秒＋ゲスト mount 3 秒。RPC 期限 10 秒に 3 秒の余裕を残す。
        assert_eq!(SHARE_SCAN_TIMEOUT, Duration::from_secs(1));
        assert_eq!(LAUNCH_START_TIMEOUT, Duration::from_secs(3));
        assert_eq!(LAUNCH_GUEST_MOUNT_TIMEOUT, Duration::from_secs(3));
        assert_eq!(launch, Duration::from_secs(7));
        assert_eq!(Duration::from_secs(10) - launch, Duration::from_secs(3));
        // 起動全体の待ち上限は段階の合計と同じで、段階の期限で打ち切れないブロックもこの時間で打ち切る。
        assert_eq!(LAUNCH_TOTAL_TIMEOUT, launch);
        assert_eq!(CREATE_VALIDATION_TIMEOUT, Duration::from_secs(3));
        assert!(SHARE_SCAN_TIMEOUT < CREATE_VALIDATION_TIMEOUT);
        assert_eq!(SHUTDOWN_BUDGET, Duration::from_secs(4));
        assert!(SHUTDOWN_BUDGET < Duration::from_secs(5));
        assert!(LAUNCH_STOP_TIMEOUT <= SHUTDOWN_BUDGET);
    }

    /// TASK-115.3・REPAIR-5: 予算が 1 回の停止待ちに満たなければ VM を試さず remaining に数える。
    #[test]
    fn task115_3_repair5_stop_all_respects_budget() {
        let dir = tmp_dir("budget");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        f.0.borrow_mut().stop_timeout = Duration::from_secs(1);
        for id in ["a", "b"] {
            create_ok(&mut a, id, &k);
            a.handle(&s(&["start", id])).expect("start");
        }
        assert_eq!(
            a.stop_all_within(Duration::from_millis(500)),
            StopAllSummary {
                stopped: 0,
                remaining: 2
            }
        );
        assert!(f.0.borrow().stopped.is_empty());
        assert_eq!(
            a.stop_all_within(Duration::from_secs(60)),
            StopAllSummary {
                stopped: 2,
                remaining: 0
            }
        );
    }

    /// TASK-115.3・PLUG-1: stop_all は実行中のみ数え、失敗分は残す。
    #[test]
    fn task115_3_plug1_stop_all_counts() {
        let dir = tmp_dir("stopall");
        let k = kernel(&dir);
        let (mut a, f) = adapter();
        for id in ["a", "b", "c"] {
            create_ok(&mut a, id, &k);
        }
        a.handle(&s(&["start", "a"])).expect("start");
        a.handle(&s(&["start", "b"])).expect("start");
        f.0.borrow_mut().fail_stop = true;
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 0,
                remaining: 2
            }
        );
        f.0.borrow_mut().fail_stop = false;
        assert_eq!(
            a.stop_all(),
            StopAllSummary {
                stopped: 2,
                remaining: 0
            }
        );
    }

    fn pe(e: PlatformError) -> (PluginErrorCode, String) {
        let p = to_plugin_error(&e);
        (p.code(), p.message().to_string())
    }

    /// TASK-115.3・ERR-1: エラー対応表の各行を具体値で照合する。
    #[test]
    fn task115_3_err1_mapping_table() {
        use PluginErrorCode as C;
        let p = || PathBuf::from("/x");
        let cfg = |e| PlatformError::Config(e);
        assert_eq!(pe(cfg(ConfigError::InvalidCpuCount)).0, C::InvalidArgument);
        assert_eq!(
            pe(cfg(ConfigError::PathIo {
                field: fandhe_container_platform_macos::config::ConfigField::Kernel,
                kind: std::io::ErrorKind::Other
            }))
            .0,
            C::Internal
        );
        assert_eq!(
            pe(cfg(ConfigError::ConsoleLogParentWorldWritable {
                path: p()
            })),
            (
                C::PermissionDenied,
                "config.console_log_parent_world_writable: VM configuration was rejected"
                    .to_string()
            )
        );
        assert_eq!(
            pe(cfg(ConfigError::ConsoleLogInUse { path: p() })).0,
            C::FailedPrecondition
        );
        let vm = |e| PlatformError::Vm(e);
        let d = || "dom".to_string();
        assert_eq!(
            pe(vm(VmError::VirtualizationUnsupported)).0,
            C::FailedPrecondition
        );
        assert_eq!(
            pe(vm(VmError::InvalidConfiguration {
                domain: d(),
                code: 1
            }))
            .0,
            C::FailedPrecondition
        );
        assert_eq!(
            pe(vm(VmError::InvalidState {
                op: VmOp::Start,
                state: VmState::Running
            }))
            .0,
            C::FailedPrecondition
        );
        assert_eq!(
            pe(vm(VmError::InvalidTimeout {
                field: "start",
                requested: Duration::ZERO,
                min: Duration::from_millis(100),
                max: Duration::from_secs(600)
            }))
            .0,
            C::InvalidArgument
        );
        assert_eq!(
            pe(vm(VmError::StopFailed {
                domain: d(),
                code: 2
            })),
            (
                C::Internal,
                "vm.stop_failed: virtual machine failed to stop (dom, code 2)".to_string()
            )
        );
        assert_eq!(
            pe(vm(VmError::Timeout {
                op: VmOp::Start,
                after: Duration::from_secs(30)
            })),
            (
                C::Timeout,
                "vm.timeout: start did not complete within 30s".to_string()
            )
        );
        assert_eq!(
            pe(vm(VmError::CallbackLost { op: VmOp::Stop })).0,
            C::Unavailable
        );
        let gm = |e| PlatformError::GuestMount(e);
        assert_eq!(
            pe(gm(GuestMountError::Timeout {
                after: Duration::from_secs(60),
                pending: vec![]
            }))
            .0,
            C::Timeout
        );
        assert_eq!(
            pe(gm(GuestMountError::VmStopped {
                state: VmState::Stopped
            }))
            .0,
            C::Unavailable
        );
        assert_eq!(
            pe(gm(GuestMountError::ReportChannelClosed)).0,
            C::Unavailable
        );
        assert_eq!(
            pe(gm(GuestMountError::Failed {
                tag: "t".into(),
                errno: 5
            }))
            .0,
            C::Internal
        );
        assert_eq!(
            pe(gm(GuestMountError::InvalidReport { reason: "r".into() })).0,
            C::Internal
        );
    }

    /// TASK-115.3・ERR-1・IO-2: virtiofs I/O エラーの対応（データ喪失の可能性を区別する）。
    #[test]
    fn task115_3_err1_virtiofs_io_mapping() {
        use PluginErrorCode as C;
        let io = |c| IoError::new(c, "x");
        let proto = |c| {
            PlatformError::VirtiofsIo(VirtiofsIoError::Protocol {
                op: VirtiofsIoOp::Write,
                source: io(c),
            })
        };
        assert_eq!(pe(proto(IoErrorCode::Timeout)).0, C::Timeout);
        assert_eq!(pe(proto(IoErrorCode::Unavailable)).0, C::Unavailable);
        assert_eq!(pe(proto(IoErrorCode::DataLoss)).0, C::DataLoss);
        assert_eq!(pe(proto(IoErrorCode::AlreadyExists)).0, C::AlreadyExists);
        assert_eq!(
            pe(proto(IoErrorCode::ResourceExhausted)),
            (
                C::FailedPrecondition,
                "virtiofs_io.resource_exhausted: virtiofs I/O operation failed".to_string()
            )
        );
        // 相手由来の本文（IoError の message）を応答へ載せない。
        let peer = PlatformError::VirtiofsIo(VirtiofsIoError::Protocol {
            op: VirtiofsIoOp::Write,
            source: IoError::new(IoErrorCode::Timeout, "PEERTEXT"),
        });
        assert_eq!(
            pe(peer),
            (
                C::Timeout,
                "virtiofs_io.timeout: virtiofs I/O operation failed".to_string()
            )
        );
        let lost = |n| {
            PlatformError::VirtiofsIo(VirtiofsIoError::ConnectionLost {
                op: VirtiofsIoOp::Write,
                unflushed_writes: n,
                reconnected: false,
                source: io(IoErrorCode::Unavailable),
            })
        };
        assert_eq!(pe(lost(3)).0, C::DataLoss);
        assert_eq!(pe(lost(0)).0, C::Unavailable);
        let failed = PlatformError::VirtiofsIo(VirtiofsIoError::ReconnectFailed {
            attempts: 3,
            unflushed_writes: 1,
            source: io(IoErrorCode::Unavailable),
        });
        assert_eq!(pe(failed).0, C::DataLoss);
        assert_eq!(
            pe(PlatformError::VirtiofsIo(
                VirtiofsIoError::InFlightLimitTooSmall { limit: 1 }
            ))
            .0,
            C::InvalidArgument
        );
        assert_eq!(
            pe(PlatformError::VirtiofsIo(
                VirtiofsIoError::InvalidReconnectPolicy { field: "f" }
            ))
            .0,
            C::InvalidArgument
        );
        assert_eq!(
            pe(PlatformError::VirtiofsIo(VirtiofsIoError::UnexpectedAck {
                op: VirtiofsIoOp::Flush
            }))
            .0,
            C::Internal
        );
        // 要求由来の共有タグを応答へ載せない。
        let tag = VirtiofsTag::try_new("SECRETTAG").expect("tag");
        assert_eq!(
            pe(PlatformError::VirtiofsIo(VirtiofsIoError::ReadOnlyShare {
                tag
            })),
            (
                C::FailedPrecondition,
                "virtiofs_io.read_only_share: virtiofs I/O operation failed".to_string()
            )
        );
    }

    /// TASK-115.3・REPAIR-3: 非 macOS の実バックエンドは UNIMPLEMENTED で成功を装わない。
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn task115_3_repair3_platform_backend_is_unsupported_off_macos() {
        let dir = tmp_dir("unsupported");
        let k = kernel(&dir);
        let mut a = MacosRuntimeAdapter::new(PlatformBackend::default());
        assert_eq!(
            a.handle(&s(&["create", "a", &k, "", ""])).expect("create"),
            s(&["created"])
        );
        assert_eq!(
            err_of(a.handle(&s(&["start", "a"]))),
            (
                PluginErrorCode::Unimplemented,
                MSG_UNSUPPORTED_HOST.to_string()
            )
        );
    }
}
