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
//!
//! `policy` は `prefer-virtiofs` / `require-virtiofs`、`mode` は `ro` / `rw`。`transport` は
//! `virtiofs` / `9p` / 未観測は空、`warning` は 9P 降格の警告コード（WIN-2）または空。
//!
//! # 未実装範囲（REPAIR-3）
//! - ゲスト内ランタイムの起動ステップ（[`GuestStart`]）の実体は未実装で、既定の [`UnimplementedGuestStart`]
//!   は `UNIMPLEMENTED` を返す（成功を装わない）。start は共有マウントの準備後にこれが失敗し、
//!   マウントはロールバックされる。
//! - kill / delete / state は未実装（`UNIMPLEMENTED`）。状態はプロセス内メモリのみで永続化しない。
//! - delete が無いため stop が保持資源をすべて手放す（上限 [`MAX_CONTAINERS`] を残骸で埋めない）。
//!
//! # 外部入力の扱い
//! 受信文字列はすべて untrusted。platform-windows へは検証済み newtype（`DistroName`・`MountName`・
//! `HostDir`）経由でのみ渡し、検証エラーの message は固定文言で受信値を反射しない。

use std::collections::BTreeMap;

use fandhe_container_platform_windows::error::{WinError, WinErrorCode};
use fandhe_container_platform_windows::instrument::{
    WinOpOutcome, WinOpRecorder, WinOpSample, WinWarning, WinWarningCode,
};
use fandhe_container_platform_windows::wsl2::{
    self, DEFAULT_WSL_TIMEOUT, DistroName, HostDir, LaunchRequest, Launched, MAX_SHARED_MOUNTS,
    MountError, MountName, PreparedLaunch, SharedMount, SharedTransport, TransportPolicy,
};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

use crate::frame_loop::RequestHandler;

/// 同時に保持するコンテナ登録の上限（無制限確保の防止）。
pub const MAX_CONTAINERS: usize = 64;

/// コンテナ ID の最大バイト数（core の `ContainerId` と同じ規則。TASK-114 で core 型へ置換予定）。
const MAX_ID_LEN: usize = 255;

const MSG_UNIMPLEMENTED: &str = "operation is not implemented";
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
    fn check_distro(&self, distro: &DistroName) -> Result<(), WinError>;

    /// 共有マウントを準備し、成功時のみ `guest` を呼ぶ。`guest` 失敗時はマウントをロールバックする。
    fn launch(
        &self,
        req: &LaunchRequest,
        guest: &dyn GuestStart<Self::Prepared>,
    ) -> Result<LaunchOutcome<Self::Prepared>, BackendFailure<Self::Prepared>>;

    /// 準備済みマウントを解除する。
    fn release(&self, prepared: &Self::Prepared) -> Result<(), BackendFailure<Self::Prepared>>;
}

/// 実バックエンド。platform-windows の関数へそのまま委譲する（期限は `DEFAULT_WSL_TIMEOUT`。REPAIR-5）。
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

    fn check_distro(&self, distro: &DistroName) -> Result<(), WinError> {
        let status = wsl2::detect(DEFAULT_WSL_TIMEOUT)?;
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
    ) -> Result<LaunchOutcome<PreparedLaunch>, BackendFailure<PreparedLaunch>> {
        let Launched { prepared, .. } =
            wsl2::launch_with_recorder(req, DEFAULT_WSL_TIMEOUT, &StderrJsonRecorder, |p| {
                guest.start(p)
            })
            .map_err(failure_from_mount)?;
        Ok(LaunchOutcome {
            transport: prepared.transport(),
            warning: prepared.warning().map(|w| w.code()),
            prepared,
        })
    }

    fn release(&self, prepared: &PreparedLaunch) -> Result<(), BackendFailure<PreparedLaunch>> {
        wsl2::release_virtiofs_launch_with_recorder(
            prepared,
            DEFAULT_WSL_TIMEOUT,
            &StderrJsonRecorder,
        )
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

/// platform-windows の計測・警告を stderr へ 1 行 JSON で出す記録先。有界時間・非 panic の契約を満たす。
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrJsonRecorder;

impl WinOpRecorder for StderrJsonRecorder {
    fn record_win_op(&self, sample: &WinOpSample) {
        eprintln!("{}", op_line(sample));
    }

    fn record_win_warning(&self, warning: &WinWarning) {
        eprintln!("{}", warning_line(warning));
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

/// `frame_loop::serve` のハンドラ。create / start / stop を [`WindowsBackend`] へ委譲する。
///
/// 状態はプロセス内メモリのみ（都度起動モードでは create と start が別プロセスになり引き継げない。
/// REPAIR-3）。`main.rs` が `PlatformBackend` と `UnimplementedGuestStart` で構築する。
pub struct WindowsRuntimeAdapter<B: WindowsBackend, G: GuestStart<B::Prepared>> {
    backend: B,
    guest: G,
    entries: BTreeMap<String, Entry<B::Prepared>>,
}

impl<B: WindowsBackend, G: GuestStart<B::Prepared>> WindowsRuntimeAdapter<B, G> {
    /// バックエンドとゲスト起動ステップからアダプタを作る。
    pub fn new(backend: B, guest: G) -> Self {
        Self {
            backend,
            guest,
            entries: BTreeMap::new(),
        }
    }

    fn create(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
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
        self.backend.check_distro(req.distro()).map_err(win_err)?;
        self.entries.insert(id.to_string(), Entry::Created(req));
        Ok(reply("created", "", ""))
    }

    fn start(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let id = parse_id_only(body)?;
        let result = match self.entries.get(id) {
            None => return Err(err(PluginErrorCode::NotFound, "container not found")),
            Some(Entry::Running(_) | Entry::Unreleased(_)) => {
                return Err(err(
                    PluginErrorCode::FailedPrecondition,
                    "container is not in created state",
                ));
            }
            Some(Entry::Created(req)) => self.backend.launch(req, &self.guest),
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

    fn stop(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let id = parse_id_only(body)?;
        let Some(entry) = self.entries.remove(id) else {
            return Err(err(PluginErrorCode::NotFound, "container not found"));
        };
        match entry {
            Entry::Created(_) => Ok(reply("stopped", "", "")),
            Entry::Running(p) | Entry::Unreleased(p) => match self.backend.release(&p) {
                Ok(()) => Ok(reply("stopped", "", "")),
                Err(f) => {
                    let e = failure_to_plugin_error(&f);
                    // 解除失敗時は所有情報を失わない（特権操作の後始末。WIN-2）。バックエンドが
                    // 未解除部分を明示したときだけ置き換え、不明なら元の準備済みマウントを保持して
                    // 次の stop で解除を再試行できるようにする。
                    let keep = f.unreleased.unwrap_or(p);
                    self.entries.insert(id.to_string(), Entry::Unreleased(keep));
                    Err(e)
                }
            },
        }
    }
}

impl<B: WindowsBackend, G: GuestStart<B::Prepared>> RequestHandler for WindowsRuntimeAdapter<B, G> {
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        match body.first().map(String::as_str) {
            Some("create") => self.create(body),
            Some("start") => self.start(body),
            Some("stop") => self.stop(body),
            _ => Err(err(PluginErrorCode::Unimplemented, MSG_UNIMPLEMENTED)),
        }
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
    }

    impl WindowsBackend for Fake {
        type Prepared = FakePrepared;
        fn check_distro(&self, d: &DistroName) -> Result<(), WinError> {
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
        ) -> Result<LaunchOutcome<FakePrepared>, BackendFailure<FakePrepared>> {
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
        fn release(&self, p: &FakePrepared) -> Result<(), BackendFailure<FakePrepared>> {
            self.calls.borrow_mut().push(format!("release:{}", p.0));
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
