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
//!
//! message は先頭に元の `code()` を付ける（core が元の分類を区別できる）。`Config` 系は `message()` が要求由来の
//! パスを埋め込むため使わず固定文言にする（入力の反射防止）。アダプタ自身の検証エラーも固定文言のみ。
//!
//! # 未実装範囲（実装済みを装わない。REPAIR-3）
//! - 型つき本体と core の `ContainerRuntime` トレイトへの接続・kill / delete / state（TASK-114 待ち）。
//! - virtiofs 共有は「デバイス構成のみ」。ゲスト内 mount 先の指定は受け付けない（ゲスト init 未実装のため
//!   `guest_mount.timeout` になる。MAC-1）。rootfs ブロックデバイス・コンソールログ・CPU / メモリ指定も含まない。
//! - 起動失敗後の `start` 再試行は拒否する（失敗した VM の停止は非同期で完了を確認できず、VM が重複し得るため。
//!   `stop` も拒否し、同じ ID の再作成を許さない。登録は plugin プロセス終了まで残る）。同時実行 VM 数は
//!   [`SHUTDOWN_BUDGET`] 内に逐次停止できる数から 1 台分の処理余裕を引いた数（停止待ち 2 秒なら 1）に制限する。停止できず残った VM の回収は `Vm` の drop 停止要求（非同期）と
//!   core の終了処理に委ね、完了は保証しない。
//! - 1 コンテナ = 1 VM（常駐 VM 共用の MAC-4 は未決）。状態はプロセス内メモリのみ（都度起動モードでは引き継げない）。
//! - VM 操作の期限は core 側 RPC・都度起動の合計期限（10 秒）と終了猶予（5 秒）に収まる固定値
//!   （[`LAUNCH_START_TIMEOUT`] 等・[`SHUTDOWN_BUDGET`]）。core からの期限伝達（要求本体への期限指定）は TASK-114。
//!   既定の `OpTimeouts`（start 30 秒・guest mount 60 秒・stop 15 秒）は使わない。

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use fandhe_container_platform_macos::config::{ConfigError, VmConfigSpec};
use fandhe_container_platform_macos::error::{GuestMountError, PlatformError, VmError};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsIoError, VirtiofsShareSpec, VirtiofsSharesSpec,
    VirtiofsTag,
};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

use crate::frame_loop::RequestHandler;

/// 登録できるコンテナ数の上限（無制限確保の防止）。
pub const MAX_CONTAINERS: usize = 64;

/// core 側 plugin RPC・都度起動の合計期限（10 秒）に収めるための `start` 完了待ち（REPAIR-5・TASK-115.3）。
pub const LAUNCH_START_TIMEOUT: Duration = Duration::from_secs(3);
/// 同 `stop` 完了待ち。停止はゲスト mount 待ちの失敗後始末と終了時停止でも使う。
pub const LAUNCH_STOP_TIMEOUT: Duration = Duration::from_secs(2);
/// 同 状態照会の応答待ち。
pub const LAUNCH_STATE_QUERY_TIMEOUT: Duration = Duration::from_secs(1);
/// 同 ゲスト内 virtiofs mount 報告の待機。start と合わせて 7 秒で、10 秒の RPC 期限に 3 秒の余裕を残す。
pub const LAUNCH_GUEST_MOUNT_TIMEOUT: Duration = Duration::from_secs(4);
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
}

impl BackendError {
    /// VM が既に停止済み（`Stopped` / `Error`）で停止操作が `InvalidState` になった場合 true。
    ///
    /// ゲスト側のシャットダウン・クラッシュ後は再試行しても同じ理由で失敗し解放できなくなるため、
    /// 呼び出し側は停止済みとして登録を外す（TASK-115.3・MAC-1）。
    fn is_already_halted(&self) -> bool {
        use fandhe_container_platform_macos::vm::VmState;
        matches!(
            self,
            BackendError::Platform(PlatformError::Vm(VmError::InvalidState {
                state: VmState::Stopped | VmState::Error,
                ..
            }))
        )
    }
}

impl From<PlatformError> for BackendError {
    fn from(e: PlatformError) -> Self {
        BackendError::Platform(e)
    }
}

/// 実バックエンド。macOS では `Vm::launch` / `Vm::stop` へ委譲し、他 OS では常に `UnsupportedHost`。
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformBackend;

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
        .map_err(PlatformError::Vm)?;
        Ok(Vm::launch(spec, timeouts)?)
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
    /// 停止に失敗して残った実行中 VM の数。
    pub remaining: usize,
}

/// create / start / stop を [`MacosBackend`] へ委譲する要求ハンドラ。
pub struct MacosRuntimeAdapter<B: MacosBackend> {
    backend: B,
    entries: BTreeMap<String, Entry<B::Handle>>,
}

impl<B: MacosBackend> MacosRuntimeAdapter<B> {
    /// 空の登録簿で作る。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            entries: BTreeMap::new(),
        }
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
    /// 通常は `remaining` が 0 になる。停止できず残った VM は登録簿に残り、呼び出し側（`main.rs`）が
    /// `plugin.cleanup` の `remaining` と終了コードで報告する。以降の回収は `Vm` の drop による停止要求
    /// （非同期・有界回数）と core 側の終了処理に委ねる（完了は保証しない。REPAIR-3）。
    pub fn stop_all_within(&mut self, budget: Duration) -> StopAllSummary {
        let deadline = Instant::now() + budget;
        let per_stop = self.backend.stop_timeout();
        let mut summary = StopAllSummary {
            stopped: 0,
            remaining: 0,
        };
        let backend = &self.backend;
        self.entries.retain(|_, entry| match &entry.state {
            State::Created | State::LaunchFailed => false,
            State::Running(h) => {
                let affordable = deadline
                    .checked_duration_since(Instant::now())
                    .is_some_and(|left| left >= per_stop);
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
        let initrd = if initrd.is_empty() {
            None
        } else {
            Some(Path::new(initrd.as_str()))
        };
        let mut shares = Vec::new();
        // 端数は上で検査済みのため捨てる剰余は空。
        let (triples, _) = rest.as_chunks::<3>();
        for triple in triples {
            {
                let [tag, dir, access] = triple;
                let access = match access.as_str() {
                    "ro" => ShareAccess::ReadOnly,
                    "rw" => ShareAccess::ReadWrite,
                    _ => return Err(invalid(MSG_MALFORMED)),
                };
                shares.push(VirtiofsShareSpec::new(
                    VirtiofsTag::try_new(tag).map_err(config_to_plugin)?,
                    SharedDirectoryPath::try_new(Path::new(dir.as_str()))
                        .map_err(config_to_plugin)?,
                    access,
                ));
            }
        }
        let spec = VmConfigSpec::from_parts(Path::new(kernel.as_str()), initrd, cmdline)
            .map_err(config_to_plugin)?
            .with_shared_directories(
                VirtiofsSharesSpec::try_new(shares).map_err(config_to_plugin)?,
            );
        spec.check_share_conflicts().map_err(config_to_plugin)?;
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
            .filter(|e| matches!(e.state, State::Running(_)))
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
        // 失敗時は LaunchFailed にして再試行を拒否する（失敗した VM の停止は非同期で完了を確認できず、
        // 再試行すると VM が重複し得るため。後始末は backend.launch が担う）。
        match self.backend.launch(&entry.spec) {
            Ok(handle) => {
                entry.state = State::Running(handle);
                Ok(vec!["running".to_string()])
            }
            Err(e) => {
                entry.state = State::LaunchFailed;
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
            // 既に停止済み（InvalidState）なら停止成功として扱い、登録を外す。
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
        match body.first().map(String::as_str) {
            Some("create") => self.create(body),
            Some("start") => self.start(body),
            Some("stop") => self.stop(body),
            _ => Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                MSG_UNIMPLEMENTED,
            )),
        }
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

fn config_to_plugin(e: ConfigError) -> PluginError {
    to_plugin_error(&PlatformError::Config(e))
}

fn backend_to_plugin(e: &BackendError) -> PluginError {
    match e {
        BackendError::Platform(p) => to_plugin_error(p),
        BackendError::UnsupportedHost => {
            PluginError::new(PluginErrorCode::Unimplemented, MSG_UNSUPPORTED_HOST)
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
            let code = match g {
                GuestMountError::Timeout { .. } => C::Timeout,
                GuestMountError::VmStopped { .. } | GuestMountError::ReportChannelClosed => {
                    C::Unavailable
                }
                _ => C::Internal,
            };
            (code, e.message())
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
            (code, e.message())
        }
        // 将来追加される分類は fail-closed で INTERNAL にする。
        _ => (C::Internal, e.message()),
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
        fail_stop: bool,
        halted_stop: bool,
        stop_timeout: Duration,
        next: u32,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<Calls>>);

    impl MacosBackend for Fake {
        type Handle = u32;
        fn launch(&self, spec: &VmConfigSpec) -> Result<u32, BackendError> {
            let mut c = self.0.borrow_mut();
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

    /// TASK-115.3・REPAIR-5: 起動・終了の待機は core の RPC 期限 10 秒・終了猶予 5 秒に収まる。
    #[test]
    fn task115_3_repair5_timeouts_fit_core_deadlines() {
        let launch = LAUNCH_START_TIMEOUT + LAUNCH_GUEST_MOUNT_TIMEOUT;
        assert_eq!(launch, Duration::from_secs(7));
        assert!(launch < Duration::from_secs(10));
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
                format!(
                    "virtiofs_io.resource_exhausted: {}",
                    proto(IoErrorCode::ResourceExhausted).message()
                )
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
        let tag = VirtiofsTag::try_new("t").expect("tag");
        assert_eq!(
            pe(PlatformError::VirtiofsIo(VirtiofsIoError::ReadOnlyShare {
                tag
            }))
            .0,
            C::FailedPrecondition
        );
    }

    /// TASK-115.3・REPAIR-3: 非 macOS の実バックエンドは UNIMPLEMENTED で成功を装わない。
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn task115_3_repair3_platform_backend_is_unsupported_off_macos() {
        let dir = tmp_dir("unsupported");
        let k = kernel(&dir);
        let mut a = MacosRuntimeAdapter::new(PlatformBackend);
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
