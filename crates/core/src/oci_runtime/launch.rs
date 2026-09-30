//! start が起動を委ねる境界（`ProcessLauncher`。TASK-29.3・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! `start.rs` の [`start`](super::start) は検証済みの [`LaunchSpec`] を組み立て、実際のプロセス起動を
//! [`ProcessLauncher`] へ委ねる。`ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、
//! create が `StateStore` を依存注入で受けるのと同様に、起動も依存注入とした。
//!
//! # 時間上限（REPAIR-5）
//!
//! launcher・起動済みプロセスへの呼び出しの上限は呼び出し側が [`StartTimeouts`] で渡す。上限は
//! 各メソッドの引数として実装へも渡すが、実装が守ることには依存せず、start が呼び出し境界で強制する
//! （別スレッドで呼び、上限を過ぎたら待つのをやめる。`start.rs` の `call_bounded`）。
//!
//! # 本番実装が未提供である理由（REPAIR-3: 実装済みを装わない）
//!
//! TASK-27 の exec フロー（`exec::spawn_container`）は「分離済み・シングルスレッド・使い捨て」の
//! 親プロセスを要求し、さらに制限ステージ（capability 削減・seccomp・Landlock。TASK-37〜39）の
//! 証跡が無い限り exec を拒否する（SEC-1・CORE-5）。任意の文脈から呼ばれる `start` はこれを
//! 保証できないため、fork した中間プロセスでの `isolate` → `spawn_container` と pid 返却・子の回収
//! を行う本番 launcher は後続 sub-issue（TASK-29 / TASK-157 系）で提供する。現時点で本 crate に
//! launcher 実装は無く、実プロセスの起動は行われない。起動済みの子の終了・回収だけは、本番 launcher が
//! そのまま使えるよう `ContainerChildProcess`（Linux。`exec::ContainerChild` の回収状態の排他を
//! 再利用する）として提供する。

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;

use super::config::NamespaceKind;
use crate::traits::{ContainerId, ErrorCode, Signal, TraitError};

/// [`StartTimeouts`] の各上限が取れる最大値（無期限相当の値を型で拒否する。REPAIR-5）。
///
/// `StopRequest` の猶予上限と同じく「無期限を許さない」契約を表す暫定値。
pub const START_TIMEOUT_MAX: Duration = Duration::from_secs(10 * 60);

/// start・中断回復が launcher・起動済みプロセスを待つ上限時間（REPAIR-5）。
///
/// 呼び出し側（将来の plugin 側 `ContainerRuntime::start` 実装・CLI）が渡す。各値は 0 より大きく
/// [`START_TIMEOUT_MAX`] 以下。上限は `ProcessLauncher` / `LaunchedProcess` の各メソッドへも渡すが、
/// start は実装が守ることに依存せず呼び出し境界で強制する。境界での打ち切りは、各値に実装自身の
/// `Timeout` 応答を受け取る猶予 `LAUNCHER_REPLY_GRACE`（1 秒）を足した時点で行う（実効の待ち上限は
/// 各値 + 1 秒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartTimeouts {
    launch: Duration,
    terminate: Duration,
    confirm: Duration,
}

impl StartTimeouts {
    /// 既定の起動待ち上限（[`ProcessLauncher::launch`]。子プロセスの応答待ちの推奨 5〜10 秒の範囲。
    /// AGENTS.md・REPAIR-5）。
    pub const DEFAULT_LAUNCH: Duration = Duration::from_secs(10);
    /// 既定の終了待ち上限（[`LaunchedProcess::terminate`]）。
    pub const DEFAULT_TERMINATE: Duration = Duration::from_secs(5);
    /// 既定の生存確認待ち上限（[`ProcessLauncher::confirm_no_process`]）。
    pub const DEFAULT_CONFIRM: Duration = Duration::from_secs(10);

    /// 起動・終了・生存確認の各上限から作る。0 または [`START_TIMEOUT_MAX`] 超過は `InvalidArgument`。
    pub fn new(
        launch: Duration,
        terminate: Duration,
        confirm: Duration,
    ) -> Result<Self, TraitError> {
        for value in [launch, terminate, confirm] {
            if value.is_zero() || value > START_TIMEOUT_MAX {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "start timeouts must be greater than zero and at most {START_TIMEOUT_MAX:?}"
                    ),
                ));
            }
        }
        Ok(Self {
            launch,
            terminate,
            confirm,
        })
    }

    /// [`ProcessLauncher::launch`] を待つ上限。
    pub fn launch(&self) -> Duration {
        self.launch
    }

    /// [`LaunchedProcess::terminate`] を待つ上限。
    pub fn terminate(&self) -> Duration {
        self.terminate
    }

    /// [`ProcessLauncher::confirm_no_process`] を待つ上限。
    pub fn confirm(&self) -> Duration {
        self.confirm
    }
}

impl Default for StartTimeouts {
    fn default() -> Self {
        Self {
            launch: Self::DEFAULT_LAUNCH,
            terminate: Self::DEFAULT_TERMINATE,
            confirm: Self::DEFAULT_CONFIRM,
        }
    }
}

/// 検査済み rootfs ディレクトリの固定ハンドル（検査対象と使用対象を同一にする。SEC-1）。
///
/// start は `/` から bundle を経て rootfs までの**全要素**（祖先を含む）を、直前の要素の fd を起点に
/// `O_PATH|O_DIRECTORY|O_NOFOLLOW` で 1 要素ずつ開いて rootfs を固定する（`exec::mount_proc` と同じ
/// `exec::open_dir_beneath` を再利用する）。パスを別の操作で解決し直さないため、途中の祖先を symlink に
/// 差し替えても・改名しても、固定した実体は bundle 配下で辿った rootfs のまま変わらない（TOCTOU の防止）。
/// `O_PATH|O_DIRECTORY` は FIFO 等を open せず `ENOTDIR` で拒否するため、差し替えで open がブロック
/// することもない（REPAIR-5）。
///
/// launcher は `LaunchSpec::rootfs` のパス文字列を再解決せず、`as_fd`（Linux） の fd（dirfd・
/// `/proc/thread-self/fd/N`・`fchdir`）から rootfs を使うこと。fd は O_PATH のため読み書きはできない。
///
/// fd 相対の open は Linux の `sys` モジュールにしか無く、本番 launcher も Linux のみのため、Linux 以外
/// では値を作れない（start は固定段で `Unimplemented` を返す。fail-closed。CLI-1）。
#[derive(Debug, Clone)]
pub struct RootfsDir {
    #[cfg(target_os = "linux")]
    fd: Arc<OwnedFd>,
    /// Linux 以外では構築できないことを型で表す（値を持たない型）。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl RootfsDir {
    /// `bundle`（絶対パス）配下の `rootfs` を、祖先を含む全要素を symlink 非追従で辿って固定する。
    ///
    /// `rootfs` は `validate_bundle` が返した検査済みパス（`bundle` 配下・`..` なし）。検査後に
    /// bundle 配下の要素が symlink・非ディレクトリ・不在へ変わっていれば `PermissionDenied`
    /// （`rootfs changed after validation`）、bundle 自体やその祖先が symlink を含む・ディレクトリで
    /// ないなら `InvalidArgument`。本番 launcher の `exec::prepare_rootfs` も `/` から同じ条件で rootfs を
    /// 辿るため、ここで先に拒否する。メッセージは固定文言のみ（パス・errno を含めない）。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(bundle: &Path, rootfs: &Path) -> Result<Self, TraitError> {
        use crate::exec::ViolationReason;
        let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
        if !bundle.is_absolute() {
            return Err(invalid("bundle path must be absolute"));
        }
        let rel = rootfs
            .strip_prefix(bundle)
            .map_err(|_| invalid("rootfs must be inside the bundle"))?;
        let mut names: Vec<&OsStr> = Vec::new();
        for c in rel.components() {
            match c {
                Component::Normal(n) => names.push(n),
                Component::CurDir => {}
                _ => return Err(invalid("root.path must not contain '..'")),
            }
        }
        let fd = crate::exec::open_dir_beneath(bundle, &names).map_err(|e| {
            match e.violation.as_ref().map(|v| v.reason) {
                Some(ViolationReason::PathSymlinkOrNotDirectory | ViolationReason::PathMissing) => {
                    TraitError::new(
                        ErrorCode::PermissionDenied,
                        "rootfs changed after validation",
                    )
                }
                Some(_) => invalid("bundle path must be a directory reachable without symlinks"),
                None => TraitError::new(e.code, "failed to open the rootfs directory"),
            }
        })?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Linux 以外では rootfs を fd で固定できないため、起動仕様を作らず拒否する（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(_bundle: &Path, _rootfs: &Path) -> Result<Self, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "start requires Linux to pin the rootfs directory",
        ))
    }

    /// 固定した rootfs ディレクトリの fd（O_PATH。dirfd・`/proc/thread-self/fd/N`・`fchdir` 専用）。
    #[cfg(target_os = "linux")]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl PartialEq for RootfsDir {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            Arc::ptr_eq(&self.fd, &other.fd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            match self.never {}
        }
    }
}

impl Eq for RootfsDir {}

/// 起動権の所有ロック（bundle ディレクトリの inode への排他 `flock`。CORE-2・SEC-1）。
///
/// start は起動権の予約（状態の Created → Running・pid なし）の前に、recover は予約を Created へ戻す
/// 前に取得し、launch（上限超過後に続く分と遅れて返ったプロセスの後始末を含む）が終わるまで保持する。
/// `flock` はロックを持つプロセスが終了するとカーネルが解放するため、別プロセスの start の launch が
/// 進行中である間は取得できず、そのプロセスが終了していれば取得できる。これにより
/// `recover_interrupted_start` は呼び出し元の事前確認に依存せず、所有プロセスの終了（または launch の
/// 完了）を回復の条件にできる。
///
/// ロック対象は bundle ディレクトリそのもの（ファイルを作らない。読み取り専用の bundle でも使え、
/// 置き換え可能なロックファイルを持たない）。`/` から bundle までを `exec::open_dir_beneath` で
/// symlink 非追従に辿って固定し、その fd を `/proc/thread-self/fd/N` から読み取り専用で開き直して
/// ロックする（O_PATH の fd には `flock` できないため）。Linux 以外は rootfs の固定と同じく未対応で
/// `Unimplemented`（fail-closed）。
///
/// # 前提（信頼境界）
///
/// ロックは「いま bundle のパスが指すディレクトリ」の inode に掛かる。bundle ディレクトリ（またはその
/// 祖先）を rename して作り直せる者は、所有者と別の inode をロックさせてこの排他を外せる。ただし bundle の
/// パスは状態記録が指す信頼境界で、rootfs の固定（`RootfsDir::pin`）と `config.json` の読み込みも同じ前提に
/// 立つ（その者は config.json と rootfs を丸ごと差し替えて起動内容を制御できるため、新たな能力にはならない）。
/// bundle とその祖先を書き換えられない者に対する排他であり、パスに依存しない起動権（所有者の識別を
/// `StateStore` 側に持つ等）は公開トレイトの変更を要するため後続で扱う（TASK-31）。
#[derive(Debug)]
pub(super) struct BundleLock {
    #[cfg(target_os = "linux")]
    _file: std::fs::File,
    #[cfg(not(target_os = "linux"))]
    _never: std::convert::Infallible,
}

impl BundleLock {
    /// `bundle`（絶対パス）の所有ロックを待たずに取得する。
    ///
    /// 別のロック保持者がいれば `FailedPrecondition`（`container start is in progress in another
    /// process`）。bundle 自体や祖先が symlink・ディレクトリでなければ `InvalidArgument`。メッセージは
    /// 固定文言のみ（パス・errno を含めない）。
    #[cfg(target_os = "linux")]
    pub(super) fn acquire(bundle: &Path) -> Result<Self, TraitError> {
        use std::os::fd::AsRawFd;
        let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
        if !bundle.is_absolute() {
            return Err(invalid("bundle path must be absolute"));
        }
        let dir = crate::exec::open_dir_beneath(bundle, &[]).map_err(|e| {
            if e.violation.is_some() {
                invalid("bundle path must be a directory reachable without symlinks")
            } else {
                TraitError::new(e.code, "failed to open the bundle directory")
            }
        })?;
        let file = std::fs::File::open(format!("/proc/thread-self/fd/{}", dir.as_raw_fd()))
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to open the bundle directory")
            })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container start is in progress in another process",
            )),
            Err(std::fs::TryLockError::Error(_)) => Err(TraitError::new(
                ErrorCode::Internal,
                "failed to lock the bundle directory",
            )),
        }
    }

    /// Linux 以外では所有ロックを取れないため拒否する（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn acquire(_bundle: &Path) -> Result<Self, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "start requires Linux to lock the bundle directory",
        ))
    }
}

/// launcher へ渡す、検証済みの起動仕様。
///
/// 構築は `start` のみ（`pub(super)`）で、一度だけ読んだ `config.json` について、config パーサの上限
/// （`CONFIG_MAX_*`）検証と `validate_bundle` の rootfs 検査・`RootfsDir::pin` の固定を通った値だけを
/// 持つ。`args` は 1 件以上・先頭は絶対パス。シェルを介さず配列のまま渡すこと（インジェクション防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchSpec {
    rootfs: PathBuf,
    rootfs_dir: RootfsDir,
    args: Vec<String>,
    env: Vec<String>,
    hostname: Option<String>,
    namespaces: Vec<NamespaceKind>,
}

impl LaunchSpec {
    pub(super) fn new(
        rootfs: PathBuf,
        rootfs_dir: RootfsDir,
        args: Vec<String>,
        env: Vec<String>,
        hostname: Option<String>,
        namespaces: Vec<NamespaceKind>,
    ) -> Self {
        Self {
            rootfs,
            rootfs_dir,
            args,
            env,
            hostname,
            namespaces,
        }
    }

    /// 検査済みの rootfs の絶対パス（表示・記録用。使用には [`Self::rootfs_dir`] を使うこと）。
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    /// 検査済み rootfs の固定ハンドル（SEC-1。[`RootfsDir`] 参照）。
    pub fn rootfs_dir(&self) -> &RootfsDir {
        &self.rootfs_dir
    }

    /// `process.args`（そのまま。先頭は実行ファイルの絶対パス）。
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// `process.env`（`KEY=VALUE` 形式のままの文字列）。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// `hostname`（UTS namespace 内で設定する値）。
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// 新規作成する namespace（未対応の種別は `start` が拒否済み）。
    pub fn namespaces(&self) -> &[NamespaceKind] {
        &self.namespaces
    }
}

/// 起動済みプロセスの終了状態（OS 非依存。`exec::ChildExit` 等を写す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessExit {
    /// `exit` した（終了コード）。
    Exited(i32),
    /// シグナルで終了した（シグナル番号）。
    Signaled(i32),
}

/// 起動済みプロセスへのハンドル。
///
/// start は上限を強制するため別スレッド（上限超過後の後始末を含む）へハンドルを移すので `Send` を要求する。
/// start が成功すると、ハンドルは `StartedContainer` として呼び出し元へ引き渡され、呼び出し元
/// （supervisor〔TASK-157・SUP 系〕等）が監視・回収の所有者になる（[`Self::wait`]・[`Self::terminate`]）。
/// 実装は `Drop` で kill / 回収しなくてよい（コンテナの寿命をハンドルに暗黙で縛らない）ため、所有者は
/// 終了まで待って回収する責任を負う。
pub trait LaunchedProcess: Send {
    /// 起動したコンテナプロセスの pid。
    fn pid(&self) -> NonZeroU32;

    /// プロセスの終了を `timeout` まで待つ。期限を過ぎても kill しない（監視用。REPAIR-5）。
    ///
    /// 終了していれば回収して `Ok(Some(終了状態))`、期限までに終了しなければ `Ok(None)`（プロセスは
    /// 動き続け、再び待てる）。Linux の子プロセスは `ContainerChildProcess`
    /// （`exec::ContainerChild::wait_for_exit`）で実装できる。
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError>;

    /// 状態の記録に失敗したとき・起動待ちが上限を超えた後に返ってきたときの後始末として、
    /// プロセスを終了（kill）させて回収（wait）する。
    ///
    /// `timeout` までに回収できなければ `ErrorCode::Timeout` 等の `Err` を返す（REPAIR-5）。start は
    /// 実装が `timeout` を守ることに依存せず、呼び出し境界でも同じ上限を強制する。Linux の子プロセスは
    /// `ContainerChildProcess`（`exec::ContainerChild::kill_and_reap`）で実装できる。
    fn terminate(&self, timeout: Duration) -> Result<(), TraitError>;

    /// プロセスへシグナルを 1 つ送る。終了は待たない（`kill` 用。`oci_runtime::kill` の `ProcessSignaler`
    /// の本番実装が、保持する起動ハンドルへ委ねる。CORE-2・OCI-6・TASK-30.1）。
    ///
    /// 回収済みのプロセスへは送らず `FailedPrecondition` を返すこと（pid 再利用対策。SEC-1）。待ちは
    /// `timeout` まで（REPAIR-5）。既定実装は送信手段を持たないため fail-closed で `Unimplemented` を返す。
    fn signal(&self, signal: Signal, timeout: Duration) -> Result<(), TraitError> {
        let _ = (signal, timeout);
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "the launched process cannot be signaled",
        ))
    }
}

/// `exec::ContainerChild`（fork した子）を [`LaunchedProcess`] として扱うアダプタ（Linux。CORE-1・REPAIR-5）。
///
/// 本番 launcher（後続 sub-issue）が `exec::spawn_container` の戻り値を包んで返すために置く。
/// [`LaunchedProcess::terminate`] は `ContainerChild::kill_and_reap`、[`LaunchedProcess::wait`] は
/// `ContainerChild::wait_for_exit` を呼び、`wait_timeout` と同じ回収状態の排他の下で回収する（回収済みの
/// pid へは `SIGKILL` を送らない）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ContainerChildProcess {
    child: crate::exec::ContainerChild,
    pid: NonZeroU32,
}

#[cfg(target_os = "linux")]
impl ContainerChildProcess {
    /// fork した子のハンドルから作る。pid が 0 のハンドルは `InvalidArgument`（fork の戻り値では生じない）。
    pub fn new(child: crate::exec::ContainerChild) -> Result<Self, TraitError> {
        let pid = NonZeroU32::new(child.pid()).ok_or_else(|| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                "the child process id must be non-zero",
            )
        })?;
        Ok(Self { child, pid })
    }

    /// 包んでいる子のハンドル（終了待ち `wait_timeout` 等に使う）。
    pub fn child(&self) -> &crate::exec::ContainerChild {
        &self.child
    }
}

#[cfg(target_os = "linux")]
impl LaunchedProcess for ContainerChildProcess {
    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        use crate::exec::ChildExit;
        let exit = self
            .child
            .wait_for_exit(timeout)
            .map_err(|e| TraitError::new(e.code, "failed to wait for the container process"))?;
        match exit {
            None => Ok(None),
            Some(ChildExit::Exited(code)) => Ok(Some(ProcessExit::Exited(code))),
            Some(ChildExit::Signaled(sig)) => Ok(Some(ProcessExit::Signaled(sig))),
        }
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        self.child
            .kill_and_reap(timeout)
            .map(|_| ())
            .map_err(|e| TraitError::new(e.code, "failed to terminate the container process"))
    }

    /// `ContainerChild::send_signal`（回収状態のロック下で送信）へ委ねる。回収済み・既に消えていた
    /// 場合は送らずに `FailedPrecondition` を返す。`timeout` はロック待ちの上限で、超過後は送らない（REPAIR-5）。
    fn signal(&self, signal: Signal, timeout: Duration) -> Result<(), TraitError> {
        use crate::exec::SignalDelivery;
        let number = std::num::NonZeroU8::new(signal.as_u8()).ok_or_else(|| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                "signal number must be in 1..=64",
            )
        })?;
        // ロック待ちが `timeout` を超えたら送信を抑止する（呼び出し側が `Timeout` を返した後に送らない）。
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| {
                TraitError::new(ErrorCode::InvalidArgument, "signal timeout is too large")
            })?;
        match self.child.send_signal_until(number, deadline) {
            Ok(SignalDelivery::Delivered) => Ok(()),
            Ok(_) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the container process has already exited",
            )),
            Err(e) => Err(TraitError::new(
                e.code,
                "failed to signal the container process",
            )),
        }
    }
}

/// [`LaunchSpec`] からコンテナプロセスを起動する境界。
///
/// # 契約
///
/// - 各メソッドの待ちは引数 `timeout` までに打ち切り、超過時は起動した子を kill・回収してから
///   `ErrorCode::Timeout` を返す（REPAIR-5）。start は実装が守ることに依存せず、呼び出し境界でも上限を
///   強制する（超過後に返ってきた起動済みプロセスは start が [`LaunchedProcess::terminate`] で後始末する）。
///   別スレッドから呼ばれ得るため `Send + Sync` とする
/// - exec フローの fail-closed（制限証跡なしの exec 拒否。SEC-1・CORE-5）を回避しない
/// - 失敗時にプロセスを残さない
/// - rootfs は [`LaunchSpec::rootfs_dir`] の固定ハンドルから使い、`rootfs()` のパスを再解決しない（SEC-1）
/// - `linux.uidMappings` / `gidMappings` は `start` が拒否済みで `LaunchSpec` に載らない。user namespace の
///   写像は launcher の責務で、コンテナ内 root（uid/gid 0）をホストの非特権 UID・GID（呼び出しプロセスの
///   euid・egid。0 なら拒否）へ写すこと。`exec::plan` / `exec::isolate` が既定でこの写像を行う（SEC-5）
/// - `LaunchSpec::namespaces` には Pid・Mount・User・Ipc・Uts が必ず含まれる（`start` が検証済み）
///
/// 本番実装は本 crate に未提供（モジュール doc 参照）。
pub trait ProcessLauncher: Send + Sync {
    /// プロセスを起動し、ハンドルを返す。`timeout` は起動確認（子からの通知待ち等）の上限。
    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError>;

    /// `id` の起動が生存プロセスを残していないことを確認する（中断された start の回復用。CORE-2・SEC-1）。
    ///
    /// start は launch 後・pid 記録前に異常終了すると、pid が状態に残らないまま生きたプロセスを残し得る。
    /// `recover_interrupted_start` は予約を Created へ戻す前に本メソッドを呼び、`Ok(())` のときだけ戻す
    /// （戻すと同じ ID の二重起動が可能になるため）。実装は、`id` のプロセスが存在しないと確証できる場合、
    /// または存在する場合に終了・回収したうえで `Ok(())` を返し、確証できない場合は `Err` を返すこと。
    /// 進行中の launch との排他は start 側が担う（同一プロセス内は予約、プロセス間は bundle ディレクトリの
    /// 所有ロック。本メソッドは所有ロックを取れた後にだけ呼ばれる）ため、実装は生存プロセスの確認に専念する。
    /// 既定実装は確認手段を持たないため fail-closed で `Unimplemented` を返す。待ちは `timeout` まで。
    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        let _ = (id, timeout);
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "the launcher cannot confirm that no process remains for this container",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-5: 上限は 0 と `START_TIMEOUT_MAX` 超過を拒否し、境界値は受理する。
    #[test]
    fn repair5_start_timeouts_reject_zero_and_unbounded() {
        let one = Duration::from_secs(1);
        let ok = StartTimeouts::new(one, START_TIMEOUT_MAX, Duration::from_millis(1)).expect("ok");
        assert_eq!(
            (ok.launch(), ok.terminate(), ok.confirm()),
            (one, START_TIMEOUT_MAX, Duration::from_millis(1))
        );
        for (launch, terminate, confirm) in [
            (Duration::ZERO, one, one),
            (one, Duration::ZERO, one),
            (one, one, Duration::ZERO),
            (START_TIMEOUT_MAX + Duration::from_nanos(1), one, one),
            (one, Duration::MAX, one),
        ] {
            let err = StartTimeouts::new(launch, terminate, confirm).expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "start timeouts must be greater than zero and at most 600s"
            );
        }
        let d = StartTimeouts::default();
        assert_eq!(
            (d.launch(), d.terminate(), d.confirm()),
            (
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(10)
            )
        );
    }

    /// CORE-2・OCI-6（TASK-30.1）: `ContainerChildProcess::signal` は実プロセスへ SIGKILL を送り、
    /// 回収後の再送は `FailedPrecondition` になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_container_child_process_signal_delivers_and_reports_exited() {
        #[allow(clippy::zombie_processes)]
        let pid = std::process::Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
            .id();
        let process =
            ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                .expect("wrap");
        let t = Duration::from_secs(5);
        process.signal(Signal::SIGKILL, t).expect("signal");
        assert_eq!(
            process.wait(t).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        let err = process.signal(Signal::SIGKILL, t).expect_err("exited");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "the container process has already exited");
    }

    /// テスト用の一意なディレクトリ（終了時に削除）。
    #[cfg(target_os = "linux")]
    struct TempDir(PathBuf);

    #[cfg(target_os = "linux")]
    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-oci-launch-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn dev_ino(meta: &std::fs::Metadata) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }

    /// 固定した fd の実体（`/proc/thread-self/fd/N` 経由の fstat 相当）。
    #[cfg(target_os = "linux")]
    fn held(dir: &RootfsDir) -> (u64, u64) {
        use std::os::fd::AsRawFd;
        let meta = std::fs::metadata(format!("/proc/thread-self/fd/{}", dir.as_fd().as_raw_fd()))
            .expect("fd meta");
        dev_ino(&meta)
    }

    /// SEC-1: bundle 配下の祖先が bundle 外への symlink なら固定を拒否する（検査後の差し替え = TOCTOU）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_symlinked_ancestor_below_bundle() {
        let t = TempDir::new("anc");
        let bundle = t.0.join("bundle");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(outside.join("rootfs")).expect("outside");
        std::fs::create_dir_all(&bundle).expect("bundle");
        std::os::unix::fs::symlink(&outside, bundle.join("a")).expect("symlink");
        let err = RootfsDir::pin(&bundle, &bundle.join("a").join("rootfs")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "rootfs changed after validation");
    }

    /// SEC-1・REPAIR-5: rootfs が FIFO に差し替えられていても open でブロックせず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_fifo_without_blocking() {
        let t = TempDir::new("fifo");
        let fifo = t.0.join("rootfs");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let err = RootfsDir::pin(&t.0, &fifo).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "rootfs changed after validation");
    }

    /// SEC-1: 固定後に祖先を改名して同名の別ディレクトリを置いても、ハンドルは元の実体を指し続ける。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_keeps_original_entity_after_ancestor_rename() {
        let t = TempDir::new("rename");
        let rootfs = t.0.join("a").join("rootfs");
        std::fs::create_dir_all(&rootfs).expect("rootfs");
        let original = dev_ino(&std::fs::metadata(&rootfs).expect("meta"));
        let dir = RootfsDir::pin(&t.0, &rootfs).expect("pin");
        std::fs::rename(t.0.join("a"), t.0.join("moved")).expect("rename");
        std::fs::create_dir_all(&rootfs).expect("replacement");
        let replacement = dev_ino(&std::fs::metadata(&rootfs).expect("meta"));
        assert_ne!(original, replacement);
        assert_eq!(held(&dir), original);
    }

    /// SEC-1: bundle 自体（または祖先）が symlink なら InvalidArgument（本番 launcher も同条件で辿る）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_symlinked_bundle() {
        let t = TempDir::new("bl");
        let real = t.0.join("real");
        std::fs::create_dir_all(real.join("rootfs")).expect("real");
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = RootfsDir::pin(&link, &link.join("rootfs")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "bundle path must be a directory reachable without symlinks"
        );
        let err = RootfsDir::pin(Path::new("rel"), Path::new("rel/rootfs")).expect_err("fail");
        assert_eq!(err.message(), "bundle path must be absolute");
    }

    /// CORE-1・REPAIR-5: `ContainerChildProcess::terminate` は実プロセスを kill して回収する。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_container_child_process_terminate_kills_and_reaps() {
        #[allow(clippy::zombie_processes)]
        let pid = std::process::Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
            .id();
        let process =
            ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                .expect("wrap");
        assert_eq!(process.pid().get(), pid);
        assert_eq!(
            process.wait(Duration::from_millis(100)).expect("wait"),
            None
        );
        process
            .terminate(Duration::from_secs(10))
            .expect("terminate");
        assert_eq!(
            process.wait(Duration::ZERO).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert_eq!(
            process
                .child()
                .wait_timeout(Duration::ZERO)
                .expect("reaped"),
            crate::exec::ChildExit::Signaled(9)
        );
    }
}
