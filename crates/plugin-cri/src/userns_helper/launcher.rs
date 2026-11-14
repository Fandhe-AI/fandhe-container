//! userns helper の親側の起動部品（同期のブロッキング API。Linux のみ。SEC-5・OCI-1・REPAIR-5。#4795）。
//!
//! 呼び出し元は将来の展開（H2。OCI-1・OCI-2）・削除（H3。OCI-7）の経路で、`spawn_blocking` 等から使う。
//! plugin-cri 自身（`/proc/self/exe`）を隠し引数 [`super::USERNS_HELPER_ARG`] で再 exec し、制御 socket の要求と応答の
//! frame（[`super::wire`]）で単一スレッドの helper と対話する。`pre_exec` と SCM_RIGHTS は使わない（unsafe の面を最小に保つ）。
//!
//! # fd の割り当て
//! 0 = 親との `UnixStream::pair()` の片端、1 = 対象ディレクトリの fd（パスは渡さない）、2 = null。argv は隠し引数の 1 個だけ、
//! 環境変数は空、cwd は `/`。実体は `/proc/self/exe` を 1 回開いて通常ファイルを確かめ、その fd を `/proc/self/fd/N` として
//! exec する（検証した実体を起動し、パスを探し直さない。PLUG-11）。
//!
//! # 待ちの上限（REPAIR-5）
//! 全体期限は [`JOIN_BUDGET`] + 呼び出し側の [`WorkBudget`]。期限切れ・EOF・不正な応答・終了コードの不整合では子を kill して回収を試み、
//! 回収できなかった子は [`UsernsHelperError::take_unreaped`] で呼び出し側へ返す。`PDEATHSIG` は使わない（呼び出しスレッドに
//! 結びつき、tokio の blocking thread で壊れるため）。親が死ねば socket が EOF になり、helper は次の読み書きで終わる。
//! 同時実行数の上限は呼び出し側（H2・H3）が持つ（1 呼び出し 1 プロセス）。

#[cfg(any(test, feature = "userns-helper-test-support"))]
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
#[cfg(any(test, feature = "userns-helper-test-support"))]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::rootless::DEFAULT_HELPER_TIMEOUT;
use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::USERNS_HELPER_ARG;
use super::wire::{HelperErrorCode, Mode, RESPONSE_LEN, Report, decode_response, encode_request};
use crate::pod_holder::kill_and_reap;

/// 参加（user namespace の作成・写像の書き込み・release）に見込む上限: helper の 3 段（holder・mapper・helper）の期限 +
/// 余裕 5 秒 + slack 5 秒（`isolate_rootless_subordinate` の契約。REPAIR-5）。
pub const JOIN_BUDGET: Duration = Duration::from_secs(3 * DEFAULT_HELPER_TIMEOUT.as_secs() + 5 + 5);
/// 要求の書き込み期限。
const REQUEST_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// 応答を受けた後に子の終了を待つ上限。
const EXIT_WAIT: Duration = Duration::from_secs(1);
const POLL_STEP: Duration = Duration::from_millis(10);

/// モード実行に呼び出し側が見込む時間（1 秒〜600 秒。範囲外は作れない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkBudget(Duration);

impl WorkBudget {
    /// 下限。
    pub const MIN: Duration = Duration::from_secs(1);
    /// 上限。
    pub const MAX: Duration = Duration::from_secs(600);

    /// 範囲外は `InvalidArgument`。
    pub fn new(d: Duration) -> Result<Self, TraitError> {
        if d < Self::MIN || d > Self::MAX {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "userns helper work budget is out of range",
            ));
        }
        Ok(Self(d))
    }

    /// 値。
    pub fn get(self) -> Duration {
        self.0
    }
}

/// 起動の失敗。文言は固定で、パス・errno・uid を含めない（REPAIR-4）。
#[derive(Debug)]
pub struct UsernsHelperError {
    code: ErrorCode,
    message: &'static str,
    helper: Option<HelperErrorCode>,
    unreaped: Option<Child>,
}

impl UsernsHelperError {
    fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            helper: None,
            unreaped: None,
        }
    }

    /// core の `ErrorCode`。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 固定の英語の文言。
    pub fn message(&self) -> &'static str {
        self.message
    }

    /// helper が応答で返した失敗の語彙（親側の失敗では `None`）。
    pub fn helper_code(&self) -> Option<HelperErrorCode> {
        self.helper
    }

    /// kill したが回収できなかった子（呼び出し側が数えて後で回収する）。
    pub fn take_unreaped(&mut self) -> Option<Child> {
        self.unreaped.take()
    }

    /// `TraitError` へ写す（子の保持は引き継がない）。
    pub fn to_trait_error(&self) -> TraitError {
        TraitError::new(self.code, self.message)
    }
}

impl std::fmt::Display for UsernsHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for UsernsHelperError {}

enum Program {
    /// 通常: `/proc/self/exe`（plugin-cri 自身）を隠し引数で再 exec する。
    SelfExe,
    /// 試験専用: 任意の実行ファイルを引数つきで起動する（偽 helper）。
    #[cfg(any(test, feature = "userns-helper-test-support"))]
    Fixed {
        program: PathBuf,
        args: Vec<OsString>,
    },
}

/// helper の起動役。
pub struct UsernsHelperLauncher {
    program: Program,
    join_budget: Duration,
}

impl Default for UsernsHelperLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl UsernsHelperLauncher {
    /// plugin-cri 自身を helper として再 exec する起動役。
    pub fn new() -> Self {
        Self {
            program: Program::SelfExe,
            join_budget: JOIN_BUDGET,
        }
    }

    /// 試験専用: 実行ファイルと引数を差し替える（偽 helper・`--no-join` の実バイナリ）。
    #[cfg(any(test, feature = "userns-helper-test-support"))]
    pub fn with_fixed_command(program: impl Into<PathBuf>, args: Vec<OsString>) -> Self {
        Self {
            program: Program::Fixed {
                program: program.into(),
                args,
            },
            join_budget: JOIN_BUDGET,
        }
    }

    /// 試験専用: 参加の見込み時間を縮める（期限切れの試験を短くする）。
    #[cfg(any(test, feature = "userns-helper-test-support"))]
    pub fn with_join_budget(mut self, d: Duration) -> Self {
        self.join_budget = d;
        self
    }

    /// helper を 1 回起動して `mode` を実行させ、報告を返す。`target` は helper の fd 1 として渡す（ディレクトリ）。
    pub fn run(
        &self,
        mode: Mode,
        target: BorrowedFd<'_>,
        work_budget: WorkBudget,
    ) -> Result<Report, UsernsHelperError> {
        let deadline = Instant::now() + self.join_budget + work_budget.get();
        let internal = |m: &'static str| UsernsHelperError::new(ErrorCode::Internal, m);

        // 対象がディレクトリでなければ spawn の前に拒否する（副作用なし）。
        let owned = target
            .try_clone_to_owned()
            .map_err(|_| internal("failed to duplicate the target descriptor"))?;
        let probe = owned
            .try_clone()
            .map_err(|_| internal("failed to duplicate the target descriptor"))?;
        if !File::from(probe)
            .metadata()
            .map_err(|_| internal("failed to inspect the target descriptor"))?
            .is_dir()
        {
            return Err(UsernsHelperError::new(
                ErrorCode::InvalidArgument,
                "userns helper target must be a directory",
            ));
        }

        let (parent_end, child_end) = UnixStream::pair()
            .map_err(|_| UsernsHelperError::new(ErrorCode::Unavailable, MSG_SPAWN))?;
        parent_end
            .set_write_timeout(Some(REQUEST_WRITE_TIMEOUT))
            .map_err(|_| internal("failed to configure the control socket"))?;

        let (mut cmd, exe_guard) = self.command()?;
        cmd.env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(child_end)))
            .stdout(Stdio::from(owned))
            .stderr(Stdio::null());
        let spawned = cmd.spawn();
        // 子は exec 済み（または失敗）なので、検証済み fd はここで閉じてよい。
        drop(exe_guard);
        drop(cmd);
        let child =
            spawned.map_err(|_| UsernsHelperError::new(ErrorCode::Unavailable, MSG_SPAWN))?;

        converse(child, parent_end, mode, deadline)
    }

    /// 起動する Command（と、`/proc/self/exe` の検証済み fd のガード）。
    fn command(&self) -> Result<(Command, Option<File>), UsernsHelperError> {
        match &self.program {
            Program::SelfExe => {
                let exe = File::open("/proc/self/exe")
                    .map_err(|_| UsernsHelperError::new(ErrorCode::FailedPrecondition, MSG_EXE))?;
                if !exe.metadata().is_ok_and(|m| m.is_file()) {
                    return Err(UsernsHelperError::new(
                        ErrorCode::FailedPrecondition,
                        MSG_EXE,
                    ));
                }
                let mut cmd = Command::new(format!("/proc/self/fd/{}", exe.as_raw_fd()));
                cmd.arg(USERNS_HELPER_ARG);
                Ok((cmd, Some(exe)))
            }
            #[cfg(any(test, feature = "userns-helper-test-support"))]
            Program::Fixed { program, args } => {
                let mut cmd = Command::new(program);
                cmd.args(args);
                Ok((cmd, None))
            }
        }
    }
}

const MSG_SPAWN: &str = "failed to start the userns helper";
const MSG_EXE: &str = "cannot resolve the plugin executable for the userns helper";
const MSG_TIMEOUT: &str = "userns helper did not respond in time";
const MSG_PROTOCOL: &str = "userns helper returned an invalid response";
const MSG_FAILED: &str = "userns helper reported a failure";

/// 要求を書き、期限つきで応答を読み、子の終了を確かめる。失敗した経路はすべて kill・回収を試みる。
fn converse(
    child: Child,
    mut sock: UnixStream,
    mode: Mode,
    deadline: Instant,
) -> Result<Report, UsernsHelperError> {
    let mut child = child;
    if sock.write_all(&encode_request(mode)).is_err() {
        return Err(fail(child, ErrorCode::Unavailable, MSG_PROTOCOL));
    }
    let mut buf = [0u8; RESPONSE_LEN];
    let mut got = 0usize;
    while got < RESPONSE_LEN {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(fail(child, ErrorCode::Timeout, MSG_TIMEOUT));
        }
        if sock.set_read_timeout(Some(left)).is_err() {
            return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL));
        }
        let Some(dst) = buf.get_mut(got..) else {
            return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL));
        };
        match sock.read(dst) {
            // 応答の途中での EOF（helper が応答なしで終わった）。
            Ok(0) => return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL)),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(fail(child, ErrorCode::Timeout, MSG_TIMEOUT));
            }
            Err(_) => return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL)),
        }
    }
    let Some(result) = decode_response(&buf) else {
        return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL));
    };
    // 成功は終了コード 0、応答できた失敗は 1 でなければ不整合（kill して回収する）。
    let want = i32::from(result.is_err());
    let until = Instant::now() + EXIT_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.code() != Some(want) {
                    return Err(UsernsHelperError::new(ErrorCode::Internal, MSG_PROTOCOL));
                }
                break;
            }
            Ok(None) => {}
            Err(_) => return Err(UsernsHelperError::new(ErrorCode::Internal, MSG_PROTOCOL)),
        }
        let now = Instant::now();
        if now >= until {
            return Err(fail(child, ErrorCode::Timeout, MSG_TIMEOUT));
        }
        std::thread::sleep(POLL_STEP.min(until - now));
    }
    result.map_err(|code| UsernsHelperError {
        code: code.core_code(),
        message: MSG_FAILED,
        helper: Some(code),
        unreaped: None,
    })
}

/// 子を kill・回収して失敗を返す。回収できなかった子は失敗に持たせる。
fn fail(child: Child, code: ErrorCode, message: &'static str) -> UsernsHelperError {
    let mut e = UsernsHelperError::new(code, message);
    e.unreaped = kill_and_reap(child);
    e
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;
    use crate::pod_holder::POD_HOLDER_KILL_REAP_WAIT;

    fn budget() -> WorkBudget {
        WorkBudget::new(Duration::from_secs(1)).expect("budget")
    }

    fn pid_gone(pid: u32) -> bool {
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// REPAIR-5・#4795: 作業予算は 1〜600 秒だけ作れる。
    #[test]
    fn sec5_4795_work_budget_bounds() {
        assert!(WorkBudget::new(Duration::from_millis(999)).is_err());
        assert!(WorkBudget::new(Duration::ZERO).is_err());
        assert!(WorkBudget::new(Duration::from_secs(601)).is_err());
        assert_eq!(
            WorkBudget::new(Duration::from_secs(1)).expect("min").get(),
            Duration::from_secs(1)
        );
        assert_eq!(
            WorkBudget::new(Duration::from_secs(600))
                .expect("max")
                .get(),
            Duration::from_secs(600)
        );
        assert_eq!(JOIN_BUDGET, Duration::from_secs(25));
    }

    /// REPAIR-5・#4795: 応答しない helper は期限で `Timeout`・kill・回収され、`/proc/<pid>` が残らない。
    #[test]
    fn sec5_4795_unresponsive_helper_is_killed_and_reaped() {
        let dir = File::open("/").expect("open /");
        let launcher = UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()])
            .with_join_budget(Duration::ZERO);
        let started = Instant::now();
        let mut err = launcher
            .run(Mode::Inspect, dir.as_fd(), budget())
            .expect_err("must time out");
        let elapsed = started.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), MSG_TIMEOUT);
        assert!(
            elapsed < Duration::from_secs(1) + POD_HOLDER_KILL_REAP_WAIT + Duration::from_secs(2),
            "took {elapsed:?}"
        );
        assert!(err.take_unreaped().is_none(), "child must be reaped");
    }

    /// REPAIR-5・#4795: 応答なしで終わる helper（EOF）は `Internal`（プロトコル違反）で、子は残らない。
    #[test]
    fn sec5_4795_helper_exiting_without_a_response_is_a_protocol_error() {
        let dir = File::open("/").expect("open /");
        let launcher = UsernsHelperLauncher::with_fixed_command("/bin/true", vec![]);
        let mut err = launcher
            .run(Mode::Inspect, dir.as_fd(), budget())
            .expect_err("no response");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(err.message(), MSG_PROTOCOL);
        assert!(err.helper_code().is_none());
        assert!(err.take_unreaped().is_none());
    }

    /// SEC-5・#4795: 対象 fd がディレクトリでなければ spawn の前に `InvalidArgument`。
    #[test]
    fn sec5_4795_non_directory_target_is_rejected_before_spawn() {
        let file = File::open("/etc/hostname").or_else(|_| File::open("/proc/self/exe"));
        let file = file.expect("open a regular file");
        // spawn されないので、存在しない実行ファイルでも `Unavailable` ではなく `InvalidArgument` になる。
        let launcher = UsernsHelperLauncher::with_fixed_command("/nonexistent/helper", vec![]);
        let err = launcher
            .run(Mode::Inspect, file.as_fd(), budget())
            .expect_err("not a directory");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "userns helper target must be a directory");
    }

    /// REPAIR-5・#4795: kill 済みの子の pid は回収後に消える（残骸を残さない）。
    #[test]
    fn sec5_4795_reaped_pid_disappears() {
        let child = Command::new("/bin/sleep").arg("60").spawn().expect("spawn");
        let pid = child.id();
        assert!(kill_and_reap(child).is_none());
        assert!(pid_gone(pid));
    }
}
