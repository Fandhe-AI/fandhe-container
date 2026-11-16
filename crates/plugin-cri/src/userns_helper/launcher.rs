//! userns helper の親側の起動部品（同期のブロッキング API。Linux のみ。SEC-5・OCI-1・REPAIR-5。#4795）。
//!
//! 呼び出し元は展開（[`UsernsHelperLauncher::run_extract_bounded`]。OCI-1・OCI-2・#4847。cri の注入点と pull・create からの
//! 呼び出しは後続の issue）・削除（`remover`。OCI-7）の経路で、`spawn_blocking` 等から使う。
//! plugin-cri 自身（`/proc/self/exe`）を隠し引数 [`super::USERNS_HELPER_ARG`] で再 exec し、制御 socket の要求と応答の
//! frame（[`super::wire`]）で単一スレッドの helper と対話する。`pre_exec` は使わない（unsafe の面を最小に保つ）。`SCM_RIGHTS` は
//! 展開要求の blob の fd だけに使い、要求 frame の後に 1 通で送る（`sys::fd_passing`。helper は参加の後に受ける）。
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
//! 同時実行数の上限は呼び出し側が持つ（1 呼び出し 1 プロセス）。
//!
//! # 展開の契約（#4847）
//! - blob の fd は親と helper が同じ open file description を共有する（読み取り位置も共有）。helper は検証で先頭へ seek するため、
//!   展開が終わる（応答を受ける・失敗を返す）まで、親は同じ fd を読まない・seek しない
//! - `Err` のとき展開先は途中まで書かれている。呼び出し側が展開先を破棄する（oci の契約と同じ）
//! - 件数・長さ・形式の不備は spawn の前に拒否する（副作用なし）

#[cfg(any(test, feature = "userns-helper-test-support"))]
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
#[cfg(any(test, feature = "userns-helper-test-support"))]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::rootless::DEFAULT_HELPER_TIMEOUT;
use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::USERNS_HELPER_ARG;
use super::wire::{
    EXTRACT_FD_TOKEN, ExtractReport, ExtractRequest, HelperErrorCode, MAX_EXTRACT_LAYERS, Mode,
    RESPONSE_LEN, Report, decode_response, encode_extract_request, encode_request,
};
use crate::pod_holder::kill_and_reap;
use crate::sys::fd_passing;

/// 参加（user namespace の作成・写像の書き込み・release）に見込む上限: helper の 3 段（holder・mapper・helper）の期限 +
/// 余裕 5 秒 + slack 5 秒（`isolate_rootless_subordinate` の契約。REPAIR-5）。
pub const JOIN_BUDGET: Duration = Duration::from_secs(3 * DEFAULT_HELPER_TIMEOUT.as_secs() + 5 + 5);
/// 要求の書き込み期限。
const REQUEST_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// 応答を受けた後に子の終了を待つ上限。
const EXIT_WAIT: Duration = Duration::from_secs(1);
const POLL_STEP: Duration = Duration::from_millis(10);
/// 応答待ちで取り消しの旗を見る間隔。
const CANCEL_POLL: Duration = Duration::from_millis(100);

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
        self.run_bounded(mode, target, work_budget, None, None)
    }

    /// 展開モードを 1 回実行する（#4847。OCI-1・OCI-2・SEC-5）。`blobs` はレイヤーの blob の fd（`request.layers()` と同じ順・
    /// 同じ件数。通常ファイル）、`dest` は展開先ディレクトリの fd（helper の fd 1。パスは渡さない）。helper は参加の後に blob を
    /// 再検証して展開する。絶対期限と取り消しの旗は [`Self::run_bounded`] と同じで、どちらかが尽きたら helper を kill・回収して
    /// `Timeout` を返す。helper に渡す作業時間は `work_budget` と期限までの残りの小さい方（1 ms 以上）。
    pub fn run_extract_bounded(
        &self,
        request: &ExtractRequest,
        blobs: &[BorrowedFd<'_>],
        dest: BorrowedFd<'_>,
        work_budget: WorkBudget,
        hard_deadline: Option<Instant>,
        cancel: Option<&AtomicBool>,
    ) -> Result<ExtractReport, UsernsHelperError> {
        // spawn の前の検査（副作用なし）: 件数・種別。
        if blobs.len() > MAX_EXTRACT_LAYERS {
            return Err(UsernsHelperError::new(
                ErrorCode::ResourceExhausted,
                "too many layer descriptors for the userns helper",
            ));
        }
        if blobs.len() != request.layers().len() {
            return Err(UsernsHelperError::new(
                ErrorCode::InvalidArgument,
                MSG_BLOBS,
            ));
        }
        for b in blobs {
            let probe = b
                .try_clone_to_owned()
                .map_err(|_| UsernsHelperError::new(ErrorCode::Internal, MSG_DUP))?;
            let is_file = File::from(probe)
                .metadata()
                .map_err(|_| UsernsHelperError::new(ErrorCode::Internal, MSG_DUP))?
                .is_file();
            if !is_file {
                return Err(UsernsHelperError::new(
                    ErrorCode::InvalidArgument,
                    MSG_BLOBS,
                ));
            }
        }
        let mut work = work_budget.get();
        if let Some(h) = hard_deadline {
            work = work.min(h.saturating_duration_since(Instant::now()));
        }
        let request = request
            .clone()
            .with_work(work)
            .map_err(|_| UsernsHelperError::new(ErrorCode::InvalidArgument, MSG_BLOBS))?;
        let frame = encode_extract_request(&request);
        match self.run_frame(
            frame.as_bytes(),
            blobs,
            dest,
            work_budget,
            hard_deadline,
            cancel,
        )? {
            Report::Extracted(r) => Ok(r),
            _ => Err(UsernsHelperError::new(ErrorCode::Internal, MSG_PROTOCOL)),
        }
    }

    /// [`Self::run`] に絶対期限と取り消しの旗を足した版。どちらかが尽きたら待ちを止め、helper を kill・回収して `Timeout`
    /// を返す（呼び出し側の `ReleaseBudget` の契約。REPAIR-5・#3142）。
    pub fn run_bounded(
        &self,
        mode: Mode,
        target: BorrowedFd<'_>,
        work_budget: WorkBudget,
        hard_deadline: Option<Instant>,
        cancel: Option<&AtomicBool>,
    ) -> Result<Report, UsernsHelperError> {
        let frame = encode_request(mode);
        self.run_frame(
            frame.as_bytes(),
            &[],
            target,
            work_budget,
            hard_deadline,
            cancel,
        )
    }

    /// 要求 frame と、後に添える fd（空なら添えない）で helper を 1 回起動して応答を得る共通部。
    fn run_frame(
        &self,
        frame: &[u8],
        fds: &[BorrowedFd<'_>],
        target: BorrowedFd<'_>,
        work_budget: WorkBudget,
        hard_deadline: Option<Instant>,
        cancel: Option<&AtomicBool>,
    ) -> Result<Report, UsernsHelperError> {
        let mut deadline = Instant::now() + self.join_budget + work_budget.get();
        if let Some(h) = hard_deadline {
            deadline = deadline.min(h);
        }
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

        converse(child, parent_end, frame, fds, deadline, cancel)
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
const MSG_BLOBS: &str = "userns helper layer descriptors do not match the request";
const MSG_DUP: &str = "failed to inspect a layer descriptor";

/// 要求を書き、期限つきで応答を読み、子の終了を確かめる。失敗した経路はすべて kill・回収を試みる。
fn converse(
    child: Child,
    mut sock: UnixStream,
    frame: &[u8],
    fds: &[BorrowedFd<'_>],
    deadline: Instant,
    cancel: Option<&AtomicBool>,
) -> Result<Report, UsernsHelperError> {
    let mut child = child;
    if sock.write_all(frame).is_err() {
        return Err(fail(child, ErrorCode::Unavailable, MSG_PROTOCOL));
    }
    // fd は要求 frame の後に 1 通で送る（helper は参加の後に受ける）。送れなければ kill・回収する。
    if !fds.is_empty() && fd_passing::send_fds(sock.as_fd(), EXTRACT_FD_TOKEN, fds).is_err() {
        return Err(fail(child, ErrorCode::Unavailable, MSG_PROTOCOL));
    }
    let mut buf = [0u8; RESPONSE_LEN];
    let mut got = 0usize;
    while got < RESPONSE_LEN {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err(fail(child, ErrorCode::Timeout, MSG_TIMEOUT));
        }
        if sock.set_read_timeout(Some(left.min(CANCEL_POLL))).is_err() {
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
                ) => {}
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
            // 終了を確かめられないので、生きている前提で kill・回収する（回収漏れを残さない）。
            Err(_) => return Err(fail(child, ErrorCode::Internal, MSG_PROTOCOL)),
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

    /// REPAIR-5・SEC-5・#4800: 削除モードの期限切れでも子は kill・回収され、`/proc/<pid>` が残らない。
    #[test]
    fn sec5_4800_remove_mode_timeout_kills_and_reaps_the_helper() {
        use super::super::wire::RemoveTarget;
        let dir = File::open("/").expect("open /");
        let launcher = UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()])
            .with_join_budget(Duration::ZERO);
        let mut err = launcher
            .run(
                Mode::Remove(RemoveTarget::BundleRootfs),
                dir.as_fd(),
                budget(),
            )
            .expect_err("must time out");
        assert_eq!(err.code(), ErrorCode::Timeout);
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

    fn spec(c: char) -> super::super::wire::ExtractLayerSpec {
        let d = fandhe_container_oci::reference::Digest::parse(&format!(
            "sha256:{}",
            c.to_string().repeat(64)
        ))
        .expect("digest");
        super::super::wire::ExtractLayerSpec::new(
            "application/vnd.oci.image.layer.v1.tar",
            1,
            d.clone(),
            d,
        )
        .expect("spec")
    }

    fn extract_request(n: usize) -> ExtractRequest {
        use super::super::wire::ExtractSpecialBits;
        ExtractRequest::new(
            ExtractSpecialBits::Strip,
            fandhe_container_oci::layer::extract::ExtractLimits::default(),
            fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            (0..n).map(|_| spec('a')).collect(),
        )
        .expect("request")
    }

    /// REPAIR-5・SEC-5・#4847: 応答しない helper への展開要求も期限で `Timeout`・kill・回収され、`/proc/<pid>` が残らない
    /// （偽 helper は blob の fd を受けないが、親の送信は成功し、待ちが期限で止まる）。
    #[test]
    fn sec5_4847_extract_timeout_kills_and_reaps_the_helper() {
        let dir = File::open("/").expect("open /");
        let blob = File::open("/proc/self/exe").expect("open a regular file");
        let launcher = UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()])
            .with_join_budget(Duration::ZERO);
        let started = Instant::now();
        let mut err = launcher
            .run_extract_bounded(
                &extract_request(1),
                &[blob.as_fd()],
                dir.as_fd(),
                budget(),
                None,
                None,
            )
            .expect_err("must time out");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(
            started.elapsed()
                < Duration::from_secs(1) + POD_HOLDER_KILL_REAP_WAIT + Duration::from_secs(2)
        );
        assert!(err.take_unreaped().is_none(), "child must be reaped");
    }

    /// REPAIR-5・#4847: 取り消しの旗が立つと、作業予算よりずっと前に `Timeout` で止まり、子は回収される。
    #[test]
    fn sec5_4847_extract_cancel_flag_stops_early() {
        let dir = File::open("/").expect("open /");
        let blob = File::open("/proc/self/exe").expect("open a regular file");
        let launcher = UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()]);
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let mut err = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                cancel.store(true, Ordering::Release);
            });
            launcher
                .run_extract_bounded(
                    &extract_request(1),
                    &[blob.as_fd()],
                    dir.as_fd(),
                    WorkBudget::new(Duration::from_secs(600)).expect("budget"),
                    None,
                    Some(&cancel),
                )
                .expect_err("cancelled")
        });
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(err.take_unreaped().is_none(), "child must be reaped");
    }

    /// SEC-5・REPAIR-5・#4847: 件数の不一致・通常ファイルでない blob・ディレクトリでない展開先は、spawn の前に拒否する
    /// （存在しない実行ファイルでも `Unavailable` にならない）。
    #[test]
    fn sec5_4847_extract_inputs_are_rejected_before_spawn() {
        let dir = File::open("/").expect("open /");
        let file = File::open("/proc/self/exe").expect("open a regular file");
        let launcher = UsernsHelperLauncher::with_fixed_command("/nonexistent/helper", vec![]);
        let run = |req: &ExtractRequest, blobs: &[BorrowedFd<'_>], dest: BorrowedFd<'_>| {
            launcher
                .run_extract_bounded(req, blobs, dest, budget(), None, None)
                .expect_err("rejected")
        };
        let e = run(&extract_request(2), &[file.as_fd()], dir.as_fd());
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::InvalidArgument, MSG_BLOBS)
        );
        let e = run(&extract_request(1), &[dir.as_fd()], dir.as_fd());
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::InvalidArgument, MSG_BLOBS)
        );
        let e = run(&extract_request(1), &[file.as_fd()], file.as_fd());
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "userns helper target must be a directory");
        let many = vec![file.as_fd(); MAX_EXTRACT_LAYERS + 1];
        let e = run(&extract_request(1), &many, dir.as_fd());
        assert_eq!(e.code(), ErrorCode::ResourceExhausted);
    }
}
