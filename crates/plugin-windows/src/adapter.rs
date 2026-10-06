//! `ContainerRuntime` 相当の要求を `fandhe-container-platform-windows` へ委譲するアダプタ
//! （TASK-116.3・#394。PLUG-1・WIN-1・WIN-2・ERR-1・REPAIR-2・REPAIR-3・REPAIR-4・REPAIR-5）。
//!
//! `frame_loop::serve` が復号した要求本体（`Vec<String>`）を [`WindowsRuntimeAdapter`]
//! （[`RequestHandler`]）が受け取り、create / start / stop を platform-windows の WSL2 検出・virtiofs
//! 共有マウントの準備・解除へ対応づける。platform-windows の失敗は [`to_plugin_error`] で 1 箇所に集約し、
//! plugin のエラーフレーム（`code` / `message`）として core へ返す。
//!
//! # 暫定ワイヤー契約（spec 未規定。型つき本体への置換は core 側 proxy の TASK-114 で確定）
//! | 操作 | 要求本体 | 成功応答本体 |
//! | ---- | -------- | ------------ |
//! | create | `["create", id, distro, policy, (mount_name, host_dir, mode)*]` | `["created", "", ""]` |
//! | start | `["start", id]` | `["running", transport, warning]` |
//! | stop | `["stop", id]` | `["stopped", "", ""]` |
//! | ping | `["ping"]`（要素 1 つのみ） | `["pong"]`（1 要素） |
//!
//! `ping` はヘルスチェック（TASK-116.5・#396）。登録簿・バックエンド・`wsl.exe` に触れずメモリ内だけで応答し、
//! 内部状態（件数・id）を返さず、操作記録も出さない。単一スレッドで順次処理するため先行要求の後ろに並び、
//! 最悪でも [`REQUEST_BUDGET`] ＋送受信で core の RPC 既定期限内に応答する。core 側のタイムアウト・
//! 再起動判定は対象外（PLUG-4）。余分な要素は `INVALID_ARGUMENT`。
//!
//! `policy` は `prefer-virtiofs` / `require-virtiofs`、`mode` は `ro` / `rw`。`transport` は
//! `virtiofs` / `9p` / 未観測は空、`warning` は 9P 降格の警告コード（WIN-2）または空。
//!
//! # 未実装範囲（REPAIR-3）
//! - ゲスト内ランタイムの起動ステップ（[`GuestStart`]）の実体は未実装で、既定の [`UnimplementedGuestStart`]
//!   は `UNIMPLEMENTED` を返す（成功を装わない）。start は共有マウントの準備後にこれが失敗し、
//!   マウントはロールバックされる。
//! - 終了時（SIGTERM 含む）に止める対象は共有マウントのみで、ゲスト内ランタイムの停止は未実装（`GuestStart` の実体が無い）。
//! - kill / delete / state は未実装（`UNIMPLEMENTED`）。状態はプロセス内メモリのみで永続化しない。
//! - delete が無いため stop が保持資源をすべて手放す（上限 [`MAX_CONTAINERS`] を残骸で埋めない）。
//! - プロセスをまたぐ共有マウントの回収は未実装（#1412 で実装する。WIN-2・REPAIR-3）。現状は接続終了時・
//!   adapter 破棄時に [`WindowsRuntimeAdapter::release_all`] が解除を試み、解除できなかった件数を
//!   [`ReleaseAllReport::remaining`] で返すだけで、プロセス終了後は本 plugin から回収できない。
//!   - 解除に使う記録（マウント ID）はゲスト内 `/run/fandhe/<nonce>` に既にあるが、マウント先のパスと
//!     コンテナ ID を含まないため、別プロセスからは回収対象を特定できない。
//!   - 起動時の一括解除は採らない。起動モード（都度起動・常駐。PLUG-7）は core 側 proxy（TASK-114）で
//!     確定し、都度起動では別の plugin プロセスが使用中のマウントと残骸を区別できず、稼働中のコンテナの
//!     マウントを外す恐れがある。
//!   - ホスト側への保存も採らない。WSL の VM 再起動でマウントが消えた後も記録が残り、古い記録で別の
//!     マウントを外す恐れがある。
//!   - #1412 では、ゲスト内の記録を正とし、コンテナ ID 指定の stop と core 側の後始末から回収する。
//!
//! # 期限（REPAIR-5）
//! 要求 1 件の WSL2 操作全体（検出・マウント準備・回復・解除）は、受信時に始まる合計期限
//! [`REQUEST_BUDGET`]（要求元の plugin RPC 既定期限 `UDS_RPC_TIMEOUT_DEFAULT` から応答の余裕を引いた値）を
//! 共有し、各段には残り時間から配分する。期限切れは `TIMEOUT` のエラーフレームで返し、解除できなかった
//! マウントの所有情報は保持して stop / 終了時の解除で回収する（WIN-2）。
//!
//! # 実行場所の前提（WIN-1）
//! 実バックエンド [`PlatformBackend`] は Windows ホスト上で `wsl.exe` を起動して WSL2 の検出・virtiofs
//! マウントを行う。したがって本 plugin は Windows ホスト側プロセスとして動く前提である。非 Windows
//! ビルド（WSL2 ゲスト内の Linux 等）では `wsl.exe` を解決できず、create は `UNIMPLEMENTED` で
//! fail-closed になる（成功を装わない）。Windows ホスト上の UDS 接続は plugin 境界機構側が未対応で、
//! TASK-114 で確定する（REPAIR-3）。
//!
//! # 外部入力の扱い
//! 受信文字列はすべて untrusted。platform-windows へは検証済み newtype（`DistroName`・`MountName`・
//! `HostDir`）経由でのみ渡し、検証エラーの message は固定文言で受信値を反射しない。

use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

use fandhe_container_platform_windows::error::{WinError, WinErrorCode};
use fandhe_container_platform_windows::instrument::{
    WinOpOutcome, WinOpRecorder, WinOpSample, WinWarning, WinWarningCode,
};
use fandhe_container_platform_windows::wsl2::{
    self, DistroName, HostDir, LaunchRequest, Launched, MAX_SHARED_MOUNTS, MountError, MountName,
    PreparedLaunch, SharedMount, SharedTransport, TransportPolicy,
};
use fandhe_container_plugin::{
    ONE_SHOT_EXIT_TIMEOUT, PluginError, PluginErrorCode, UDS_RPC_TIMEOUT_DEFAULT, UdsStream,
};

use crate::frame_loop::RequestHandler;

/// 同時に保持するコンテナ登録の上限（無制限確保の防止）。
pub const MAX_CONTAINERS: usize = 64;

/// 応答フレームの符号化・送信と、要求元が計時を始めてから本 plugin が受信するまでの遅延に残す余裕。
pub const RESPONSE_MARGIN: Duration = Duration::from_secs(2);

/// 要求 1 件（create / start / stop）の WSL2 操作全体で共有する合計期限（REPAIR-5）。
///
/// 要求元（core 側 proxy）の plugin RPC 既定期限 `UDS_RPC_TIMEOUT_DEFAULT`（上限も同じ値）から
/// [`RESPONSE_MARGIN`] を引いた値で、起点は要求の処理開始時。検出・マウント準備・回復・解除の各段には
/// この期限の残り時間から配分するため、成功応答も失敗時の解除結果も RPC 期限内に要求元へ届く。
/// 要求ごとの期限はワイヤーに載っていないため既定値を前提にする（期限の受け渡しは TASK-114 で確定。
/// REPAIR-3）。期限切れになった `wsl.exe` を kill して回収する猶予（platform-windows 側）は含まない。
pub const REQUEST_BUDGET: Duration = UDS_RPC_TIMEOUT_DEFAULT.saturating_sub(RESPONSE_MARGIN);

/// stop 1 回・[`WindowsRuntimeAdapter::release_all`] の 1 エントリで使うマウント解除の合計期限の上限
/// （全マウントで共有。stop では要求の残り時間とのうち短い方を渡す。REPAIR-5・WIN-2）。
pub const RELEASE_BUDGET: Duration = Duration::from_secs(4);

/// 終了時の解除の後、終了行の出力とプロセス終了に残す余裕。
pub const EXIT_MARGIN: Duration = Duration::from_secs(1);

/// [`WindowsRuntimeAdapter::release_all`] 全体の合計期限（複数コンテナ・複数マウントで共有）。
/// 超過分は解除せず `entries` に残し、[`ReleaseAllReport::remaining`] で報告する。
///
/// 呼び出し元（core 側）が plugin の自発終了を待つ猶予 `ONE_SHOT_EXIT_TIMEOUT`（超過で強制終了）から
/// [`EXIT_MARGIN`] を引いた値。終了時の解除はこの 1 回だけで、[`Drop`] は再試行しない（終了処理全体を
/// 猶予内に収める。REPAIR-5・WIN-2）。
pub const RELEASE_ALL_BUDGET: Duration = ONE_SHOT_EXIT_TIMEOUT.saturating_sub(EXIT_MARGIN);

/// 残り期限がこの値未満のときは新たな解除を始めない（platform-windows の最小期限より十分大きく取る）。
const MIN_STEP_BUDGET: Duration = Duration::from_millis(50);

/// コンテナ ID の最大バイト数（core の `ContainerId` と同じ規則。TASK-114 で core 型へ置換予定）。
const MAX_ID_LEN: usize = 255;

const MSG_DEADLINE: &str = "request deadline exceeded before the WSL2 operation started";
const MSG_UNIMPLEMENTED: &str = "operation is not implemented";
/// ヘルスチェック要求の操作名（TASK-116.5・#396。plugin-macos と同じ文字列の暫定契約。PLUG-1）。
pub const OP_PING: &str = "ping";
/// ヘルスチェックの成功応答（1 要素。内部状態を含めない）。
pub const REPLY_PONG: &str = "pong";
const MSG_BAD_REQUEST: &str = "malformed request";
const MSG_BAD_ID: &str = "invalid container id";

// ---- エラー変換（受け入れ基準 2）----

/// platform-windows のエラー分類を plugin のエラーフレームへ変換する唯一の箇所（ERR-1）。
///
/// plugin 側に `RESOURCE_EXHAUSTED` が無いため `FAILED_PRECONDITION` へ写し、message 先頭に元の分類を残す。
/// `#[non_exhaustive]` の将来追加分は `Internal`（fail-closed）。長さ上限は `PluginError::new` が担う。
pub fn to_plugin_error(code: WinErrorCode, message: &str) -> PluginError {
    let plain = |c| PluginError::new(c, message);
    match code {
        WinErrorCode::InvalidArgument => plain(PluginErrorCode::InvalidArgument),
        WinErrorCode::NotFound => plain(PluginErrorCode::NotFound),
        WinErrorCode::PermissionDenied => plain(PluginErrorCode::PermissionDenied),
        WinErrorCode::Unimplemented => plain(PluginErrorCode::Unimplemented),
        WinErrorCode::FailedPrecondition => plain(PluginErrorCode::FailedPrecondition),
        WinErrorCode::Timeout => plain(PluginErrorCode::Timeout),
        WinErrorCode::DataLoss => plain(PluginErrorCode::DataLoss),
        WinErrorCode::Internal => plain(PluginErrorCode::Internal),
        WinErrorCode::ResourceExhausted => PluginError::new(
            PluginErrorCode::FailedPrecondition,
            format!("{}: {message}", code.as_str()),
        ),
        _ => plain(PluginErrorCode::Internal),
    }
}

fn failure_to_plugin_error<P>(f: &BackendFailure<P>) -> PluginError {
    let mut msg = f.error.message().to_string();
    if let Some(w) = f.warning {
        // Error フレームに警告欄が無いため末尾へ添える（9P 降格を暗黙にしない。WIN-2）。
        msg.push_str("; warning=");
        msg.push_str(w.as_str());
    }
    to_plugin_error(f.error.code(), &msg)
}

fn err(code: PluginErrorCode, message: &'static str) -> PluginError {
    PluginError::new(code, message)
}

fn invalid(message: &'static str) -> PluginError {
    err(PluginErrorCode::InvalidArgument, message)
}

fn win_err(e: WinError) -> PluginError {
    to_plugin_error(e.code(), e.message())
}

// ---- 要求の合計期限（REPAIR-5）----

/// 要求 1 件の合計期限。`handle` の入口で作り、バックエンドの各操作へ残り時間を配分する。
#[derive(Debug, Clone, Copy)]
struct RequestDeadline(Instant);

impl RequestDeadline {
    fn after(total: Duration) -> Self {
        Self(Instant::now() + total)
    }

    /// 残り時間を返す。[`MIN_STEP_BUDGET`] 未満なら操作に着手させず `TIMEOUT` を返す。
    fn remaining(self) -> Result<Duration, PluginError> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left < MIN_STEP_BUDGET {
            return Err(err(PluginErrorCode::Timeout, MSG_DEADLINE));
        }
        Ok(left)
    }
}

/// start の残り時間 `left` から [`WindowsBackend::launch`] へ渡す `budget` を決める。
///
/// launch は「検出 + マウント準備」と「回復・ロールバック」にそれぞれ `budget` を使えるため、半分ずつ
/// 配分して合計を `left` 以内に収める（回復の持ち分を先に確保し、準備が期限を使い切っても解除できる）。
fn launch_budget(left: Duration) -> Duration {
    left / 2
}

// ---- 継ぎ目（3 OS の CI で実 wsl.exe を起動せずテストするため）----

/// バックエンド失敗（未解除マウントと 9P 降格の警告を保持する）。
#[derive(Debug)]
pub struct BackendFailure<P> {
    /// 構造化エラー。
    pub error: WinError,
    /// 解除できずに残った準備済みマウント（stop で後始末をやり直せる）。
    pub unreleased: Option<P>,
    /// 9P 降格の警告分類。
    pub warning: Option<WinWarningCode>,
}

impl<P> From<WinError> for BackendFailure<P> {
    fn from(error: WinError) -> Self {
        Self {
            error,
            unreleased: None,
            warning: None,
        }
    }
}

/// 起動成功の結果。
#[derive(Debug)]
pub struct LaunchOutcome<P> {
    /// 停止時に解除へ渡す準備済みマウント。
    pub prepared: P,
    /// 観測した輸送方式（共有マウント 0 件では `None`）。
    pub transport: Option<SharedTransport>,
    /// 9P 降格の警告分類。
    pub warning: Option<WinWarningCode>,
}

/// ゲスト内ランタイムの起動ステップ（platform-windows の `launch_with` の `start` に注入する。TASK-116 の後続）。
///
/// 現状の実装（[`UnimplementedGuestStart`]）は即座に返るため、要求の合計期限 [`REQUEST_BUDGET`] に
/// 起動ステップの持ち分は無い。実体を実装するときは有界時間で返すようにし、その持ち分を
/// [`REQUEST_BUDGET`] の配分へ加える（REPAIR-3・REPAIR-5）。
pub trait GuestStart<P> {
    /// 共有マウント準備後に呼ばれる。`Err` ならマウントはロールバックされる。
    fn start(&self, prepared: &P) -> Result<(), WinError>;
}

/// 既定の起動ステップ。実体が無いため `UNIMPLEMENTED` を返す（REPAIR-3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedGuestStart;

impl<P> GuestStart<P> for UnimplementedGuestStart {
    fn start(&self, _prepared: &P) -> Result<(), WinError> {
        Err(WinError::new(
            WinErrorCode::Unimplemented,
            "in-guest runtime start is not implemented",
        ))
    }
}

/// platform-windows への委譲境界。実装は [`PlatformBackend`]、テストは偽実装。
pub trait WindowsBackend {
    /// 準備済みマウントを表す型（実装では `PreparedLaunch`。外部から構築できないため関連型にする）。
    type Prepared;

    /// WSL2 が有効で、`distro` が起動可能な WSL2 ディストリとして存在することを確認する（WIN-1）。
    ///
    /// `budget` は検出全体の合計期限（REPAIR-5）。
    fn check_distro(&self, distro: &DistroName, budget: Duration) -> Result<(), WinError>;

    /// 共有マウントを準備し、成功時のみ `guest` を呼ぶ。`guest` 失敗時はマウントをロールバックする。
    ///
    /// `budget` は WSL2 の検出とマウント準備全体（複数マウント）で共有する合計期限。準備失敗時の回復と
    /// `guest` 失敗時のロールバックには、準備とは別に同じ長さが割り当てられる（解除できなければ
    /// `unreleased` で返す。WIN-2・REPAIR-5）。したがって `guest` を除く合計は `2 * budget` 以内。
    fn launch(
        &self,
        req: &LaunchRequest,
        guest: &dyn GuestStart<Self::Prepared>,
        budget: Duration,
    ) -> Result<LaunchOutcome<Self::Prepared>, BackendFailure<Self::Prepared>>;

    /// 準備済みマウントを解除する。`budget` は全マウントの解除で共有する合計期限。
    fn release(
        &self,
        prepared: &Self::Prepared,
        budget: Duration,
    ) -> Result<(), BackendFailure<Self::Prepared>>;
}

/// 実バックエンド。platform-windows の関数へ委譲する（期限は呼び出し側が渡す合計期限。REPAIR-5）。
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformBackend;

fn failure_from_mount(e: MountError) -> BackendFailure<PreparedLaunch> {
    let (error, unreleased, warning) = e.into_parts();
    BackendFailure {
        error,
        unreleased,
        warning: warning.map(|w| w.code()),
    }
}

impl WindowsBackend for PlatformBackend {
    type Prepared = PreparedLaunch;

    fn check_distro(&self, distro: &DistroName, budget: Duration) -> Result<(), WinError> {
        let status = wsl2::detect(budget)?;
        let found = status
            .distros
            .iter()
            .any(|d| d.name.eq_ignore_ascii_case(distro.as_str()) && d.is_usable_wsl2());
        if found {
            Ok(())
        } else {
            Err(WinError::new(
                WinErrorCode::NotFound,
                "no usable WSL2 distribution with the requested name",
            ))
        }
    }

    fn launch(
        &self,
        req: &LaunchRequest,
        guest: &dyn GuestStart<PreparedLaunch>,
        budget: Duration,
    ) -> Result<LaunchOutcome<PreparedLaunch>, BackendFailure<PreparedLaunch>> {
        let Launched { prepared, .. } =
            wsl2::launch_with_recorder(req, budget, &StderrJsonRecorder, |p| guest.start(p))
                .map_err(failure_from_mount)?;
        Ok(LaunchOutcome {
            transport: prepared.transport(),
            warning: prepared.warning().map(|w| w.code()),
            prepared,
        })
    }

    fn release(
        &self,
        prepared: &PreparedLaunch,
        budget: Duration,
    ) -> Result<(), BackendFailure<PreparedLaunch>> {
        wsl2::release_virtiofs_launch_with_recorder(prepared, budget, &StderrJsonRecorder)
            .map_err(failure_from_mount)
    }
}

// ---- 計装（REPAIR-4・WIN-2）----

/// 操作サンプルの JSON 1 行を組み立てる（列挙名・固定文言・数値のみ）。
pub fn op_line(sample: &WinOpSample) -> String {
    let outcome = match sample.outcome() {
        WinOpOutcome::Success => "success",
        WinOpOutcome::Failure => "failure",
        _ => "unknown",
    };
    format!(
        "{{\"event\":\"win.op\",\"kind\":\"{}\",\"outcome\":\"{outcome}\",\"latency_us\":{}}}",
        sample.kind().as_str(),
        sample.latency().as_micros()
    )
}

/// 警告の JSON 1 行を組み立てる（`level: warn`。固定文言のみ）。
pub fn warning_line(w: &WinWarning) -> String {
    format!(
        "{{\"level\":\"warn\",\"event\":\"win.warning\",\"code\":\"{}\",\"message\":\"{}\"}}",
        w.code().as_str(),
        w.message()
    )
}

/// stderr へ 1 行書く。書き込みの失敗（閉じられた・壊れた stderr）は無視し、panic しない。
///
/// `eprintln!` は書き込み失敗で panic する。記録先がマウント準備・解除の途中で panic すると、
/// platform-windows の内側にある準備済みマウントの所有情報を失うため、本 plugin の診断出力は
/// すべて本関数を通す（WIN-2・REPAIR-4）。
pub fn stderr_line(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// platform-windows の計測・警告を stderr へ 1 行 JSON で出す記録先。有界時間・非 panic の契約を満たす。
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrJsonRecorder;

impl WinOpRecorder for StderrJsonRecorder {
    fn record_win_op(&self, sample: &WinOpSample) {
        stderr_line(&op_line(sample));
    }

    fn record_win_warning(&self, warning: &WinWarning) {
        stderr_line(&warning_line(warning));
    }
}

// ---- 要求の解析 ----

/// ID 規則は core の `ContainerId::new` と同じ（`[A-Za-z0-9._-]`・1〜255 バイト・`.` / `..` 不可）。
fn parse_id(s: &str) -> Result<&str, PluginError> {
    let ok = !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok { Ok(s) } else { Err(invalid(MSG_BAD_ID)) }
}

fn parse_policy(s: &str) -> Result<TransportPolicy, PluginError> {
    match s {
        "prefer-virtiofs" => Ok(TransportPolicy::PreferVirtiofs),
        "require-virtiofs" => Ok(TransportPolicy::RequireVirtiofs),
        _ => Err(invalid("invalid transport policy")),
    }
}

fn parse_mode(s: &str) -> Result<bool, PluginError> {
    match s {
        "ro" => Ok(true),
        "rw" => Ok(false),
        _ => Err(invalid("invalid mount mode")),
    }
}

fn parse_create(body: &[String]) -> Result<(&str, LaunchRequest), PluginError> {
    let [_, id, distro, policy, rest @ ..] = body else {
        return Err(invalid(MSG_BAD_REQUEST));
    };
    if rest.len() % 3 != 0 || rest.len() / 3 > MAX_SHARED_MOUNTS {
        return Err(invalid(MSG_BAD_REQUEST));
    }
    let id = parse_id(id)?;
    let distro = DistroName::parse(distro).map_err(win_err)?;
    let policy = parse_policy(policy)?;
    let mut mounts = Vec::with_capacity(rest.len() / 3);
    // 上で 3 の倍数を確認済みのため、余りは常に空。
    let (chunks, _) = rest.as_chunks::<3>();
    for [name, host, mode] in chunks {
        mounts.push(SharedMount::new(
            HostDir::parse(host).map_err(win_err)?,
            MountName::parse(name).map_err(win_err)?,
            parse_mode(mode)?,
        ));
    }
    let req = LaunchRequest::new(distro, mounts)
        .map_err(win_err)?
        .with_transport_policy(policy);
    Ok((id, req))
}

fn parse_id_only(body: &[String]) -> Result<&str, PluginError> {
    match body {
        [_, id] => parse_id(id),
        _ => Err(invalid(MSG_BAD_REQUEST)),
    }
}

fn reply(state: &str, transport: &str, warning: &str) -> Vec<String> {
    vec![
        state.to_string(),
        transport.to_string(),
        warning.to_string(),
    ]
}

// ---- アダプタ本体 ----

enum Entry<P> {
    Created(LaunchRequest),
    Running(P),
    /// 起動失敗後に解除できず残ったマウント（stop で解除をやり直す）。
    Unreleased(P),
}

/// [`WindowsRuntimeAdapter::release_all`] の結果（件数のみ。識別子・パスは含めない）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReleaseAllReport {
    /// 解除に成功したマウント保持エントリ数。
    pub released: usize,
    /// 解除に失敗して残ったエントリ数（0 でなければ手動回収が必要）。
    pub remaining: usize,
}

/// `frame_loop::serve` のハンドラ。create / start / stop を [`WindowsBackend`] へ委譲する。
///
/// 状態はプロセス内メモリのみ（都度起動モードでは create と start が別プロセスになり引き継げない。
/// REPAIR-3）。`main.rs` が `PlatformBackend` と `UnimplementedGuestStart` で構築する。
pub struct WindowsRuntimeAdapter<B: WindowsBackend, G: GuestStart<B::Prepared>> {
    backend: B,
    guest: G,
    entries: BTreeMap<String, Entry<B::Prepared>>,
    /// 直近の要求より後に [`Self::release_all`] が最後まで走ったか（`Drop` での二重の解除を避ける）。
    release_all_done: bool,
}

impl<B: WindowsBackend, G: GuestStart<B::Prepared>> WindowsRuntimeAdapter<B, G> {
    /// バックエンドとゲスト起動ステップからアダプタを作る。
    pub fn new(backend: B, guest: G) -> Self {
        Self {
            backend,
            guest,
            entries: BTreeMap::new(),
            release_all_done: false,
        }
    }

    fn create(
        &mut self,
        body: &[String],
        deadline: RequestDeadline,
    ) -> Result<Vec<String>, PluginError> {
        let (id, req) = parse_create(body)?;
        if self.entries.contains_key(id) {
            return Err(err(
                PluginErrorCode::AlreadyExists,
                "container already exists",
            ));
        }
        if self.entries.len() >= MAX_CONTAINERS {
            return Err(err(
                PluginErrorCode::FailedPrecondition,
                "too many containers",
            ));
        }
        self.backend
            .check_distro(req.distro(), deadline.remaining()?)
            .map_err(win_err)?;
        self.entries.insert(id.to_string(), Entry::Created(req));
        Ok(reply("created", "", ""))
    }

    fn start(
        &mut self,
        body: &[String],
        deadline: RequestDeadline,
    ) -> Result<Vec<String>, PluginError> {
        let id = parse_id_only(body)?;
        let result = match self.entries.get(id) {
            None => return Err(err(PluginErrorCode::NotFound, "container not found")),
            Some(Entry::Running(_) | Entry::Unreleased(_)) => {
                return Err(err(
                    PluginErrorCode::FailedPrecondition,
                    "container is not in created state",
                ));
            }
            Some(Entry::Created(req)) => {
                let budget = launch_budget(deadline.remaining()?);
                let (backend, guest) = (&self.backend, &self.guest);
                // stop / release_all と同じく panic を要求元へのエラーフレームに変える。panic 時は
                // 準備済みマウントの所有情報がバックエンドの内側で失われており、ここでは回収できない
                // （そのため記録先 `StderrJsonRecorder` は panic しない実装にしている）。登録は Created の
                // まま残し、再度の start は platform-windows が既存マウントを検出して拒否する（fail-closed）。
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    backend.launch(req, guest, budget)
                })) {
                    Ok(r) => r,
                    Err(_) => return Err(err(PluginErrorCode::Internal, "launch panicked")),
                }
            }
        };
        match result {
            Ok(o) => {
                let transport = o.transport.map(SharedTransport::as_str).unwrap_or("");
                let warning = o.warning.map(WinWarningCode::as_str).unwrap_or("");
                let out = reply("running", transport, warning);
                self.entries
                    .insert(id.to_string(), Entry::Running(o.prepared));
                Ok(out)
            }
            Err(f) => {
                let e = failure_to_plugin_error(&f);
                if let Some(u) = f.unreleased {
                    self.entries.insert(id.to_string(), Entry::Unreleased(u));
                }
                Err(e)
            }
        }
    }

    /// 要求 1 件を、いまから `total` 以内の合計期限で処理する（[`RequestHandler::handle`] の本体。
    /// 本番は [`REQUEST_BUDGET`]、テストは期限切れの経路を確かめるため短い値を渡す。REPAIR-5）。
    fn handle_within(
        &mut self,
        body: &[String],
        total: Duration,
    ) -> Result<Vec<String>, PluginError> {
        // ヘルスチェックは状態・バックエンド・時計に一切触れず即応答する（TASK-116.5・#396）。
        // `release_all_done` を倒す前に処理するのは、ping で終了時の解除が二重に走る余地を作らないため。
        if body.first().map(String::as_str) == Some(OP_PING) {
            return if body.len() == 1 {
                Ok(vec![REPLY_PONG.to_string()])
            } else {
                Err(invalid(MSG_BAD_REQUEST))
            };
        }
        let deadline = RequestDeadline::after(total);
        // 要求を処理した後の状態は未解除かもしれないため、終了時の解除をやり直せるようにする。
        self.release_all_done = false;
        match body.first().map(String::as_str) {
            Some("create") => self.create(body, deadline),
            Some("start") => self.start(body, deadline),
            Some("stop") => self.stop(body, deadline),
            _ => Err(err(PluginErrorCode::Unimplemented, MSG_UNIMPLEMENTED)),
        }
    }

    /// 保持中のマウントをすべて解除する（接続終了・異常終了時の後始末。WIN-2・REPAIR-5）。
    ///
    /// `serve` 終了後に呼ぶ（冪等）。呼ばれないまま破棄された場合（panic・早期 return）に限り [`Drop`] が
    /// 1 回呼ぶ。本関数が最後まで走った後の `Drop` は再試行しない（解除の合計を [`RELEASE_ALL_BUDGET`] の
    /// 1 回分に収め、呼び出し元の終了猶予を超えない）。全体で [`RELEASE_ALL_BUDGET`] の
    /// 合計期限を持ち、各解除には残り時間（最大 [`RELEASE_BUDGET`]）だけを渡す。解除に失敗した・期限切れで
    /// 着手できなかった準備済みマウントは `entries` に残し、件数を [`ReleaseAllReport::remaining`] で返す
    /// （手動回収または次回の stop / release_all で再試行できる）。
    pub fn release_all(&mut self) -> ReleaseAllReport {
        self.release_all_within(RELEASE_ALL_BUDGET)
    }

    fn release_all_within(&mut self, total: Duration) -> ReleaseAllReport {
        let mut report = ReleaseAllReport::default();
        let deadline = Instant::now() + total;
        // 1 件ずつ取り出して解除する。`backend.release` が panic しても（記録先 stderr の破損による
        // 想定外の panic 等）、未処理のエントリは `entries` に残り、Drop で再試行できる。
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in ids {
            if matches!(self.entries.get(&id), Some(Entry::Created(_)) | None) {
                continue;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left < MIN_STEP_BUDGET {
                // 期限切れ: 着手しないエントリは所有情報ごとそのまま残す。
                report.remaining += 1;
                continue;
            }
            let Some(entry) = self.entries.remove(&id) else {
                continue;
            };
            let p = match entry {
                Entry::Created(_) => continue,
                Entry::Running(p) | Entry::Unreleased(p) => p,
            };
            let backend = &self.backend;
            let budget = left.min(RELEASE_BUDGET);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                backend.release(&p, budget)
            }));
            match outcome {
                Ok(Ok(())) => report.released += 1,
                Ok(Err(f)) => {
                    report.remaining += 1;
                    // 所有情報を失わないため、元の ID のまま再試行可能な形で保持し直す。
                    let keep = f.unreleased.unwrap_or(p);
                    self.entries.insert(id, Entry::Unreleased(keep));
                }
                Err(_) => {
                    // panic 時は解除済みか不明なため、未解除として保持し直す。
                    report.remaining += 1;
                    self.entries.insert(id, Entry::Unreleased(p));
                }
            }
        }
        // 途中で panic して巻き戻った場合は立てない（その場合は Drop が残りの解除を試みる）。
        self.release_all_done = true;
        report
    }

    fn stop(
        &mut self,
        body: &[String],
        deadline: RequestDeadline,
    ) -> Result<Vec<String>, PluginError> {
        let id = parse_id_only(body)?;
        if !self.entries.contains_key(id) {
            return Err(err(PluginErrorCode::NotFound, "container not found"));
        }
        // 期限切れなら解除に着手せず、エントリ（所有情報）をそのまま残して `TIMEOUT` を返す
        // （次の stop / release_all で解除できる。WIN-2）。マウントを持たない登録の削除は期限を要しない。
        let budget = match self.entries.get(id) {
            Some(Entry::Running(_) | Entry::Unreleased(_)) => {
                deadline.remaining()?.min(RELEASE_BUDGET)
            }
            _ => RELEASE_BUDGET,
        };
        let Some(entry) = self.entries.remove(id) else {
            return Err(err(PluginErrorCode::NotFound, "container not found"));
        };
        match entry {
            Entry::Created(_) => Ok(reply("stopped", "", "")),
            Entry::Running(p) | Entry::Unreleased(p) => {
                let backend = &self.backend;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    backend.release(&p, budget)
                }));
                match outcome {
                    Ok(Ok(())) => Ok(reply("stopped", "", "")),
                    Ok(Err(f)) => {
                        let e = failure_to_plugin_error(&f);
                        // 解除失敗時は所有情報を失わない（特権操作の後始末。WIN-2）。バックエンドが
                        // 未解除部分を明示したときだけ置き換え、不明なら元の準備済みマウントを保持して
                        // 次の stop で解除を再試行できるようにする。
                        let keep = f.unreleased.unwrap_or(p);
                        self.entries.insert(id.to_string(), Entry::Unreleased(keep));
                        Err(e)
                    }
                    Err(_) => {
                        // panic 時は解除済みか不明なため、未解除として保持し直す（次の stop /
                        // release_all で再試行できる。WIN-2）。
                        self.entries.insert(id.to_string(), Entry::Unreleased(p));
                        Err(err(PluginErrorCode::Internal, "unmount panicked"))
                    }
                }
            }
        }
    }
}

impl<B: WindowsBackend, G: GuestStart<B::Prepared>> Drop for WindowsRuntimeAdapter<B, G> {
    fn drop(&mut self) {
        // panic・早期 return 経路でも共有マウントを残さない（WIN-2）。明示的な `release_all` が
        // 最後まで走った後は再試行しない（終了処理が呼び出し元の終了猶予を超えて強制終了されると、
        // 解除が途中で止まるため。REPAIR-5）。残った件数はその戻り値で報告済み。
        if !self.release_all_done {
            let _ = self.release_all();
        }
    }
}

/// [`serve_session`] の結果（フレームループの終了要因と、終了時の共有マウント解除の件数）。
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionOutcome {
    /// フレームループの終了結果（相手の切断・SIGTERM・異常終了）。
    pub result: Result<crate::frame_loop::LoopExit, PluginError>,
    /// ループ終了後の [`WindowsRuntimeAdapter::release_all`] の結果（WIN-2）。
    pub cleanup: ReleaseAllReport,
}

/// 接続 1 本分のセッションを処理する（`main.rs` から呼ばれる。TASK-116.5・#396）。
///
/// `stop`（SIGTERM フラグ）が立つまで要求を処理し、終了要因（切断・SIGTERM・異常終了）に関わらず
/// `release_all` で保持中の共有マウントを解除し、`plugin.shutdown` / `plugin.cleanup` を stderr へ出す
/// （固定文言と件数のみ）。終了コードの決定は呼び出し側が行う。結合試験が偽バックエンドで
/// 「SIGTERM 時に保持中のマウントを解除する」契約を検証できるよう、バイナリ入口から切り出している。
pub fn serve_session<B: WindowsBackend, G: GuestStart<B::Prepared>>(
    stream: &mut UdsStream,
    adapter: &mut WindowsRuntimeAdapter<B, G>,
    stop: &std::sync::atomic::AtomicBool,
) -> SessionOutcome {
    let result = crate::frame_loop::serve_until(stream, adapter, stop);
    if matches!(result, Ok(crate::frame_loop::LoopExit::ShutdownRequested)) {
        stderr_line("{\"event\":\"plugin.shutdown\",\"reason\":\"signal\"}");
    }
    let cleanup = adapter.release_all();
    if cleanup.released + cleanup.remaining > 0 {
        stderr_line(&format!(
            "{{\"event\":\"plugin.cleanup\",\"released\":{},\"remaining\":{}}}",
            cleanup.released, cleanup.remaining
        ));
    }
    SessionOutcome { result, cleanup }
}

impl<B: WindowsBackend, G: GuestStart<B::Prepared>> RequestHandler for WindowsRuntimeAdapter<B, G> {
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        self.handle_within(body, REQUEST_BUDGET)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use fandhe_container_platform_windows::instrument::WinOpKind;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakePrepared(String);

    #[derive(Default)]
    struct Fake {
        calls: Rc<RefCell<Vec<String>>>,
        check_err: Option<WinErrorCode>,
        launch_err: RefCell<Option<BackendFailure<FakePrepared>>>,
        release_err: RefCell<Option<BackendFailure<FakePrepared>>>,
        panic_once: RefCell<bool>,
        launch_panic_once: RefCell<bool>,
        /// 渡された合計期限（launch / release の呼び出し順）。
        budgets: RefCell<Vec<Duration>>,
        /// check_distro へ渡された合計期限。
        check_budgets: RefCell<Vec<Duration>>,
    }

    impl WindowsBackend for Fake {
        type Prepared = FakePrepared;
        fn check_distro(&self, d: &DistroName, budget: Duration) -> Result<(), WinError> {
            self.check_budgets.borrow_mut().push(budget);
            self.calls
                .borrow_mut()
                .push(format!("check:{}", d.as_str()));
            match self.check_err {
                Some(c) => Err(WinError::new(c, "fake check failure")),
                None => Ok(()),
            }
        }
        fn launch(
            &self,
            req: &LaunchRequest,
            guest: &dyn GuestStart<FakePrepared>,
            budget: Duration,
        ) -> Result<LaunchOutcome<FakePrepared>, BackendFailure<FakePrepared>> {
            self.budgets.borrow_mut().push(budget);
            let mounts: Vec<String> = req
                .mounts()
                .iter()
                .map(|m| format!("{}={}:{}", m.name.as_str(), m.host.as_str(), m.read_only))
                .collect();
            self.calls.borrow_mut().push(format!(
                "launch:{}:{:?}:{}",
                req.distro().as_str(),
                req.transport_policy(),
                mounts.join(",")
            ));
            if self.launch_panic_once.replace(false) {
                panic!("fake launch panic");
            }
            if let Some(f) = self.launch_err.borrow_mut().take() {
                return Err(f);
            }
            let p = FakePrepared(req.distro().as_str().to_string());
            guest.start(&p)?;
            Ok(LaunchOutcome {
                prepared: p,
                transport: Some(SharedTransport::Virtiofs),
                warning: None,
            })
        }
        fn release(
            &self,
            p: &FakePrepared,
            budget: Duration,
        ) -> Result<(), BackendFailure<FakePrepared>> {
            self.budgets.borrow_mut().push(budget);
            self.calls.borrow_mut().push(format!("release:{}", p.0));
            if self.panic_once.replace(false) {
                panic!("fake release panic");
            }
            match self.release_err.borrow_mut().take() {
                Some(f) => Err(f),
                None => Ok(()),
            }
        }
    }

    struct OkGuest;
    impl GuestStart<FakePrepared> for OkGuest {
        fn start(&self, _: &FakePrepared) -> Result<(), WinError> {
            Ok(())
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    type TestAdapter = WindowsRuntimeAdapter<Fake, OkGuest>;

    fn adapter(fake: Fake) -> (TestAdapter, Rc<RefCell<Vec<String>>>) {
        let calls = Rc::clone(&fake.calls);
        (WindowsRuntimeAdapter::new(fake, OkGuest), calls)
    }

    const CREATE: &[&str] = &[
        "create",
        "c1",
        "Ubuntu",
        "prefer-virtiofs",
        "data",
        "C:\\data\\app",
        "rw",
    ];

    #[test]
    fn task116_3_plug1_create_start_stop_delegate_in_order() {
        let (mut a, calls) = adapter(Fake::default());
        assert_eq!(a.handle(&s(CREATE)).unwrap(), s(&["created", "", ""]));
        assert_eq!(
            a.handle(&s(&["start", "c1"])).unwrap(),
            s(&["running", "virtiofs", ""])
        );
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        assert_eq!(
            *calls.borrow(),
            vec![
                "check:Ubuntu",
                "launch:Ubuntu:PreferVirtiofs:data=C:\\data\\app:false",
                "release:Ubuntu"
            ]
        );
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
    }

    #[test]
    fn task116_3_win1_error_mapping_covers_all_codes() {
        let cases = [
            (WinErrorCode::InvalidArgument, "INVALID_ARGUMENT", "m"),
            (WinErrorCode::NotFound, "NOT_FOUND", "m"),
            (WinErrorCode::PermissionDenied, "PERMISSION_DENIED", "m"),
            (WinErrorCode::Unimplemented, "UNIMPLEMENTED", "m"),
            (WinErrorCode::FailedPrecondition, "FAILED_PRECONDITION", "m"),
            (WinErrorCode::Timeout, "TIMEOUT", "m"),
            (WinErrorCode::DataLoss, "DATA_LOSS", "m"),
            (WinErrorCode::Internal, "INTERNAL", "m"),
            (
                WinErrorCode::ResourceExhausted,
                "FAILED_PRECONDITION",
                "RESOURCE_EXHAUSTED: m",
            ),
        ];
        for (w, code, msg) in cases {
            let e = to_plugin_error(w, "m");
            assert_eq!(e.code().as_str(), code);
            assert_eq!(e.message(), msg);
        }
    }

    #[test]
    fn task116_3_plug1_backend_failures_become_error_frames_with_same_id() {
        use fandhe_container_plugin::{ControlMessage, MessageId, decode_message, encode_message};
        let (mut a, _) = adapter(Fake {
            check_err: Some(WinErrorCode::FailedPrecondition),
            ..Fake::default()
        });
        let req = encode_message(&ControlMessage::Request {
            id: MessageId::new(7),
            body: s(CREATE),
        })
        .unwrap();
        let out = crate::frame_loop::handle_frame(&req, &mut a).unwrap();
        match decode_message::<Vec<String>>(&out).unwrap() {
            ControlMessage::Error { id, error } => {
                assert_eq!(id, MessageId::new(7));
                assert_eq!(error.code().as_str(), "FAILED_PRECONDITION");
                assert_eq!(error.message(), "fake check failure");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn task116_3_win2_launch_failure_keeps_unreleased_and_stop_retries() {
        let fake = Fake::default();
        *fake.launch_err.borrow_mut() = Some(BackendFailure {
            error: WinError::new(WinErrorCode::Internal, "unmount failed"),
            unreleased: Some(FakePrepared("Ubuntu".into())),
            warning: Some(WinWarningCode::VirtiofsNotEnabled),
        });
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(e.message(), "unmount failed; warning=VIRTIOFS_NOT_ENABLED");
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        assert_eq!(calls.borrow().last().unwrap(), "release:Ubuntu");
    }

    #[test]
    fn task116_3_plug1_release_failure_with_unreleased_stays_registered() {
        let fake = Fake::default();
        *fake.release_err.borrow_mut() = Some(BackendFailure {
            error: WinError::new(WinErrorCode::Timeout, "timed out"),
            unreleased: Some(FakePrepared("Ubuntu".into())),
            warning: None,
        });
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let e = a.handle(&s(&["stop", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        let releases = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .count();
        assert_eq!(releases, 2);
    }

    #[test]
    fn task116_3_win2_release_failure_without_unreleased_keeps_original_for_retry() {
        let fake = Fake::default();
        *fake.release_err.borrow_mut() = Some(BackendFailure {
            error: WinError::new(WinErrorCode::Timeout, "timed out"),
            unreleased: None,
            warning: None,
        });
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let e = a.handle(&s(&["stop", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        let releases: Vec<String> = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .cloned()
            .collect();
        assert_eq!(releases, vec!["release:Ubuntu", "release:Ubuntu"]);
        let e = a.handle(&s(&["stop", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
    }

    #[test]
    fn task116_3_win2_release_all_cleans_running_and_unreleased_on_shutdown() {
        let fake = Fake::default();
        *fake.launch_err.borrow_mut() = Some(BackendFailure {
            error: WinError::new(WinErrorCode::Internal, "unmount failed"),
            unreleased: Some(FakePrepared("Ubuntu".into())),
            warning: None,
        });
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap_err();
        let mut c2 = s(CREATE);
        c2[1] = "c2".into();
        a.handle(&c2).unwrap();
        a.handle(&s(&["start", "c2"])).unwrap();
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (2, 0));
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|c| c.starts_with("release"))
                .count(),
            2
        );
        assert_eq!(a.release_all(), ReleaseAllReport::default());
    }

    #[test]
    fn task116_3_win2_release_all_panic_keeps_remaining_entries_for_retry() {
        let fake = Fake::default();
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let mut c2 = s(CREATE);
        c2[1] = "c2".into();
        a.handle(&c2).unwrap();
        a.handle(&s(&["start", "c2"])).unwrap();
        *a.backend.panic_once.borrow_mut() = true;
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (1, 1));
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (1, 0));
        assert_eq!(a.release_all(), ReleaseAllReport::default());
        drop(calls);
    }

    /// WIN-2・REPAIR-5: stop 中の解除が panic しても所有情報を失わず、次の stop で再試行できる。
    #[test]
    fn task116_3_win2_stop_panic_keeps_entry_for_retry() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        *a.backend.panic_once.borrow_mut() = true;
        let e = a.handle(&s(&["stop", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        let releases = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .count();
        assert_eq!(releases, 2);
        assert_eq!(a.release_all(), ReleaseAllReport::default());
    }

    /// WIN-2: launch が panic しても plugin は落ちず INTERNAL のエラーフレームを返す。登録は Created の
    /// まま残り（解除すべき所有情報は持たない）、続く start はやり直せ、stop は解除を呼ばずに登録を消す。
    #[test]
    fn task116_3_win2_launch_panic_becomes_internal_error_and_keeps_created() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        *a.backend.launch_panic_once.borrow_mut() = true;
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(
            (e.code().as_str(), e.message()),
            ("INTERNAL", "launch panicked")
        );
        assert_eq!(calls.borrow().len(), 2);
        assert_eq!(
            a.handle(&s(&["start", "c1"])).unwrap(),
            s(&["running", "virtiofs", ""])
        );

        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        *a.backend.launch_panic_once.borrow_mut() = true;
        a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        assert!(!calls.borrow().iter().any(|c| c.starts_with("release")));
        assert_eq!(a.release_all(), ReleaseAllReport::default());
    }

    /// REPAIR-5: 要求の合計期限は plugin RPC の既定期限（10 秒）より応答の余裕 2 秒だけ短い 8 秒で、
    /// start の配分（検出 + 準備 4 秒・回復 4 秒）も stop の解除（4 秒）もその内側に収まる。
    #[test]
    fn task116_3_repair5_request_budget_fits_in_plugin_rpc_timeout() {
        assert_eq!(UDS_RPC_TIMEOUT_DEFAULT, Duration::from_secs(10));
        assert_eq!(RESPONSE_MARGIN, Duration::from_secs(2));
        assert_eq!(REQUEST_BUDGET, Duration::from_secs(8));
        assert_eq!(launch_budget(REQUEST_BUDGET), Duration::from_secs(4));
        assert_eq!(2 * launch_budget(REQUEST_BUDGET), REQUEST_BUDGET);
        assert_eq!(
            launch_budget(Duration::from_millis(900)),
            Duration::from_millis(450)
        );
        assert_eq!(RELEASE_BUDGET, Duration::from_secs(4));
        assert!(RELEASE_BUDGET <= REQUEST_BUDGET);
    }

    /// REPAIR-5: create は要求の残り時間（8 秒以内）を検出へ、start はその半分（4 秒以内）を準備へ渡す
    /// （残りの半分は回復の持ち分）。処理開始からの経過分だけ短くなるため、下限は 1 秒の余裕で確かめる。
    #[test]
    fn task116_3_repair5_create_and_start_share_the_request_deadline() {
        let (mut a, _) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let slack = Duration::from_secs(1);
        let c = a.backend.check_budgets.borrow().clone();
        assert_eq!(c.len(), 1);
        assert!(c[0] <= Duration::from_secs(8) && c[0] > Duration::from_secs(8) - slack);
        let b = a.backend.budgets.borrow().clone();
        assert_eq!(b.len(), 1);
        assert!(b[0] <= Duration::from_secs(4) && b[0] > Duration::from_secs(4) - slack);

        // 短い合計期限でも同じ配分になる（create は全体、start は半分）。
        let (mut a, _) = adapter(Fake::default());
        let total = Duration::from_secs(2);
        a.handle_within(&s(CREATE), total).unwrap();
        a.handle_within(&s(&["start", "c1"]), total).unwrap();
        a.handle_within(&s(&["stop", "c1"]), total).unwrap();
        let c = a.backend.check_budgets.borrow().clone();
        assert!(c[0] <= Duration::from_secs(2) && c[0] > Duration::from_secs(1));
        let b = a.backend.budgets.borrow().clone();
        assert_eq!(b.len(), 2);
        assert!(b[0] <= Duration::from_secs(1) && b[0] > Duration::from_millis(500));
        // stop の解除は残り時間（2 秒以内）と RELEASE_BUDGET（4 秒）の短い方。
        assert!(b[1] <= Duration::from_secs(2) && b[1] > Duration::from_secs(1));
    }

    /// REPAIR-5・WIN-2: 合計期限を使い切った要求はバックエンドに着手せず TIMEOUT のエラーフレームを返す。
    /// 登録も所有情報も変えないため、期限内の再要求で create / start / stop（解除）をやり直せる。
    #[test]
    fn task116_3_repair5_exhausted_request_deadline_is_timeout_and_keeps_state() {
        let (mut a, calls) = adapter(Fake::default());
        let timeout = |r: Result<Vec<String>, PluginError>| {
            let e = r.unwrap_err();
            assert_eq!(e.code().as_str(), "TIMEOUT");
            assert_eq!(
                e.message(),
                "request deadline exceeded before the WSL2 operation started"
            );
        };
        timeout(a.handle_within(&s(CREATE), Duration::ZERO));
        assert!(calls.borrow().is_empty());
        // create は登録されていない（start は NOT_FOUND）。
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code().as_str(), "NOT_FOUND");

        a.handle(&s(CREATE)).unwrap();
        timeout(a.handle_within(&s(&["start", "c1"]), Duration::ZERO));
        assert_eq!(*calls.borrow(), vec!["check:Ubuntu"]);
        // Created のまま残り、期限内の start は成功する。
        a.handle(&s(&["start", "c1"])).unwrap();

        timeout(a.handle_within(&s(&["stop", "c1"]), Duration::ZERO));
        assert!(!calls.borrow().iter().any(|c| c.starts_with("release")));
        // 所有情報は残っており、期限内の stop で解除できる。
        assert_eq!(
            a.handle(&s(&["stop", "c1"])).unwrap(),
            s(&["stopped", "", ""])
        );
        assert_eq!(calls.borrow().last().unwrap(), "release:Ubuntu");

        // マウントを持たない登録（Created）の stop は WSL2 操作が無いため期限切れでも削除できる。
        a.handle(&s(CREATE)).unwrap();
        assert_eq!(
            a.handle_within(&s(&["stop", "c1"]), Duration::ZERO)
                .unwrap(),
            s(&["stopped", "", ""])
        );
    }

    /// REPAIR-5: start / stop は要求の期限から配分した合計期限を、release_all は残り時間（上限 RELEASE_BUDGET）を渡す。
    #[test]
    fn task116_3_repair5_budgets_are_propagated_to_backend() {
        let (mut a, _) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        a.handle(&s(&["stop", "c1"])).unwrap();
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (1, 0));
        let b = a.backend.budgets.borrow().clone();
        assert_eq!(b.len(), 4);
        let launch = launch_budget(REQUEST_BUDGET);
        let slack = Duration::from_secs(1);
        assert!(b[0] <= launch && b[0] > launch - slack);
        assert_eq!(b[1], RELEASE_BUDGET);
        assert!(b[2] <= launch && b[2] > launch - slack);
        assert!(b[3] <= RELEASE_BUDGET && b[3] >= MIN_STEP_BUDGET);
    }

    /// REPAIR-5・WIN-2: 合計期限を使い切った release_all は着手せず所有情報ごと残し、後の呼び出しで解除する。
    #[test]
    fn task116_3_repair5_release_all_exhausted_budget_keeps_entries() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let r = a.release_all_within(Duration::ZERO);
        assert_eq!((r.released, r.remaining), (0, 1));
        assert!(!calls.borrow().iter().any(|c| c.starts_with("release")));
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (1, 0));
    }

    /// REPAIR-5: 終了時の解除の合計期限は、呼び出し元の終了猶予 5 秒から余裕 1 秒を引いた 4 秒。
    #[test]
    fn task116_3_repair5_release_all_budget_fits_in_exit_grace() {
        assert_eq!(ONE_SHOT_EXIT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(EXIT_MARGIN, Duration::from_secs(1));
        assert_eq!(RELEASE_ALL_BUDGET, Duration::from_secs(4));
    }

    /// REPAIR-5・WIN-2: release_all を呼ばずに破棄した場合は Drop が 1 回だけ解除を試みる。
    #[test]
    fn task116_3_win2_drop_releases_when_release_all_was_not_called() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        drop(a);
        assert_eq!(calls.borrow().last().unwrap(), "release:Ubuntu");
        let releases = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .count();
        assert_eq!(releases, 1);
    }

    /// REPAIR-5・WIN-2: 明示的な release_all が残り件数を報告した後、Drop は解除を再試行しない
    /// （解除の試行は 1 回。終了処理の合計を RELEASE_ALL_BUDGET の 1 回分に収める）。
    #[test]
    fn task116_3_win2_release_all_reports_remaining_and_drop_does_not_retry() {
        let fake = Fake::default();
        *fake.release_err.borrow_mut() = Some(BackendFailure {
            error: WinError::new(WinErrorCode::Timeout, "timed out"),
            unreleased: None,
            warning: None,
        });
        let (mut a, calls) = adapter(fake);
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let r = a.release_all();
        assert_eq!((r.released, r.remaining), (0, 1));
        drop(a);
        let releases = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .count();
        assert_eq!(releases, 1);
    }

    /// TASK-116.5・PLUG-1: ping は pong を返し、余分な要素は入力を反射せず拒否する。
    #[test]
    fn task116_5_plug1_ping_returns_pong_and_rejects_extra() {
        let (mut a, _) = adapter(Fake::default());
        assert_eq!(a.handle(&s(&["ping"])).unwrap(), s(&["pong"]));
        let e = a.handle(&s(&["ping", "SECRETARG"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "malformed request");
    }

    /// TASK-116.5・PLUG-1: ping はバックエンド呼び出し・期限配分に触れない。
    #[test]
    fn task116_5_plug1_ping_touches_nothing() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        let before = calls.borrow().clone();
        let (b0, c0) = (
            a.backend.budgets.borrow().len(),
            a.backend.check_budgets.borrow().len(),
        );
        for _ in 0..3 {
            assert_eq!(a.handle(&s(&["ping"])).unwrap(), s(&["pong"]));
        }
        assert_eq!(*calls.borrow(), before);
        assert_eq!(a.backend.budgets.borrow().len(), b0);
        assert_eq!(a.backend.check_budgets.borrow().len(), c0);
    }

    /// TASK-116.5・WIN-2: release_all 後の ping は解除済みフラグを倒さず、Drop が再解除しない。
    #[test]
    fn task116_5_win2_ping_after_release_all_does_not_rearm_drop() {
        let (mut a, calls) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        assert_eq!(a.release_all().released, 1);
        assert_eq!(a.handle(&s(&["ping"])).unwrap(), s(&["pong"]));
        drop(a);
        let releases = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("release"))
            .count();
        assert_eq!(releases, 1);
    }

    /// WIN-2: release_all の後に要求を処理した場合は、破棄時に Drop が改めて解除を試みる。
    #[test]
    fn task116_3_win2_drop_releases_mounts_created_after_release_all() {
        let (mut a, calls) = adapter(Fake::default());
        assert_eq!(a.release_all(), ReleaseAllReport::default());
        a.handle(&s(CREATE)).unwrap();
        a.handle(&s(&["start", "c1"])).unwrap();
        drop(a);
        assert_eq!(calls.borrow().last().unwrap(), "release:Ubuntu");
    }

    #[test]
    fn task116_3_win1_invalid_requests_never_reach_backend_or_echo_input() {
        let long_id = "a".repeat(256);
        let mut many = s(&["create", "c1", "Ubuntu", "prefer-virtiofs"]);
        for i in 0..17 {
            many.extend(s(&[&format!("m{i}"), &format!("C:\\d{i}"), "ro"]));
        }
        let bad: Vec<Vec<String>> = vec![
            s(&["create"]),
            s(&["create", "c1", "Ubuntu", "prefer-virtiofs", "x"]),
            s(&["create", "..", "Ubuntu", "prefer-virtiofs"]),
            s(&["create", "a/b", "Ubuntu", "prefer-virtiofs"]),
            s(&["create", &long_id, "Ubuntu", "prefer-virtiofs"]),
            s(&["create", "c1", "Ubuntu", "SECRETPOLICY"]),
            s(&[
                "create",
                "c1",
                "Ubuntu",
                "prefer-virtiofs",
                "d",
                "C:\\d",
                "SECRETMODE",
            ]),
            s(&["create", "c1", "-bad", "prefer-virtiofs"]),
            s(&[
                "create",
                "c1",
                "Ubuntu",
                "prefer-virtiofs",
                "d",
                "relative\\path",
                "ro",
            ]),
            many,
            s(&["start"]),
            s(&["stop", "c1", "extra"]),
        ];
        for b in bad {
            let (mut a, calls) = adapter(Fake::default());
            let e = a.handle(&b).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument, "{b:?}");
            assert!(calls.borrow().is_empty());
            assert!(!e.message().contains("SECRET"));
        }
    }

    #[test]
    fn task116_3_plug1_duplicate_limit_double_start_unknown_op() {
        let (mut a, _) = adapter(Fake::default());
        a.handle(&s(CREATE)).unwrap();
        let e = a.handle(&s(CREATE)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        a.handle(&s(&["start", "c1"])).unwrap();
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
        let e = a.handle(&s(&["list"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
        assert_eq!(e.message(), "operation is not implemented");

        let (mut a, _) = adapter(Fake::default());
        for i in 0..MAX_CONTAINERS {
            a.handle(&s(&[
                "create",
                &format!("c{i}"),
                "Ubuntu",
                "prefer-virtiofs",
            ]))
            .unwrap();
        }
        let e = a
            .handle(&s(&["create", "extra", "Ubuntu", "prefer-virtiofs"]))
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "too many containers");
    }

    #[test]
    fn task116_3_plug1_default_guest_start_is_unimplemented() {
        let mut a = WindowsRuntimeAdapter::new(Fake::default(), UnimplementedGuestStart);
        a.handle(&s(CREATE)).unwrap();
        let e = a.handle(&s(&["start", "c1"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
        assert_eq!(e.message(), "in-guest runtime start is not implemented");
    }

    /// Windows では実 `wsl.exe` を起動してしまうため、非 Windows 限定にする。
    #[cfg(not(windows))]
    #[test]
    fn task116_3_win1_real_backend_is_unimplemented_off_windows() {
        let mut a = WindowsRuntimeAdapter::new(PlatformBackend, UnimplementedGuestStart);
        let e = a.handle(&s(CREATE)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
        assert_eq!(e.message(), "WSL2 detection is only supported on Windows");
    }

    #[test]
    fn task116_3_repair4_recorder_lines_are_stable() {
        let sample = WinOpSample::new(
            WinOpKind::Wsl2MountShared,
            WinOpOutcome::Success,
            Duration::from_micros(1500),
        );
        assert_eq!(
            op_line(&sample),
            "{\"event\":\"win.op\",\"kind\":\"wsl2.mount_shared\",\"outcome\":\"success\",\"latency_us\":1500}"
        );
        let w = WinWarning::new(WinWarningCode::VirtiofsNotEnabled);
        let line = warning_line(&w);
        assert!(line.starts_with(
            "{\"level\":\"warn\",\"event\":\"win.warning\",\"code\":\"VIRTIOFS_NOT_ENABLED\",\"message\":\""
        ));
        assert!(line.ends_with("\"}"));
    }
}
