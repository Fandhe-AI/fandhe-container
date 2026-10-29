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
//! # 本番実装(#1816)
//!
//! 本番の [`ProcessLauncher`] は `launcher.rs` の `ProductionLauncher`(Linux)。fork した中間プロセスで
//! `isolate` → PID 1 の起動を行い、Landlock を必須とする制限ステージ列の証跡が無い限り exec しない
//! (`exec::spawn_container_via_intermediate`)。fork は単一スレッドの呼び出しを要求するため、
//! `ProductionLauncher` は [`LaunchMode::SelfBounded`] を宣言し、start は別スレッドを作らず呼び出しスレッドで
//! 直接 `launch` を呼ぶ。起動済みの子の終了・回収は `ContainerChildProcess`(Linux。`exec::ContainerChild` の
//! 回収状態の排他を再利用する)が担う。実機前提の結合試験は `tests/production_launcher.rs`(#1818。実行は
//! `-- --ignored`)。supervisor の start 経路は呼び出しスレッドでの直接 launch へ再構成済み(#1819)。restart の再 launch は未対応(#2043。REPAIR-3)。

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

use super::bind_mounts::BindMountSet;
use super::cgroup_requirement::CgroupRequirement;
use super::config::{NamespaceKind, OciConfig};
use super::namespace_join::NamespaceJoin;
use super::network_mode::{EffectiveNetwork, LaunchNetworkMode};
use super::sysfs_mount::SysfsMountSpec;
use super::working_dir::ContainerWorkingDir;
use crate::traits::{CgroupPlacement, ContainerId, ErrorCode, Signal, TraitError};

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

/// `RootfsDir::pin` の失敗（拒否の `TraitError` と、記録すべき分離違反の理由。SEC-4・SEC-1・SUP-6・#1702）。
///
/// `TraitError` は違反記録を運べないため、`rootfs changed after validation`（検証後に bundle 配下の要素が
/// symlink・非ディレクトリ・不在へ差し替えられた）のときだけ理由を並べて持つ。supervisor の exec の経路
/// （`load_exec_bundle`）が [`pin_bundle_rootfs_audited`] で受け取り、拒否は `error` のまま、理由は
/// 親プロセスが監査ログの層 `mount` へ記録する。理由だけを持ち（`IsolationViolation` の subject は持たない）、
/// ホスト側の bundle パスを呼び出し側へ渡さない。違反を伴わない失敗（I/O エラー・検証前の失敗・bundle 自体や
/// 祖先の差し替え）は `violation` が `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsPinError {
    error: TraitError,
    /// 違反の理由型 `exec::ViolationReason` は Linux 限定のため、フィールドも Linux のみ（CLI-1）。
    #[cfg(target_os = "linux")]
    violation: Option<crate::exec::ViolationReason>,
}

impl RootfsPinError {
    fn without_violation(error: TraitError) -> Self {
        Self {
            error,
            #[cfg(target_os = "linux")]
            violation: None,
        }
    }

    /// 拒否の `TraitError`（`code` と固定文言。start と共通）。
    pub fn error(&self) -> &TraitError {
        &self.error
    }

    /// 記録すべき分離違反の理由（`path_symlink_or_not_directory` / `path_missing`）。違反を伴わない失敗は `None`。
    /// 理由型が Linux 限定のため Linux のみ（非 Linux は rootfs を固定できず違反も起きない。CLI-1）。
    #[cfg(target_os = "linux")]
    pub fn violation(&self) -> Option<crate::exec::ViolationReason> {
        self.violation
    }

    /// 違反の情報を捨てて `TraitError` だけを取り出す。
    pub fn into_error(self) -> TraitError {
        self.error
    }
}

impl From<RootfsPinError> for TraitError {
    fn from(e: RootfsPinError) -> Self {
        e.error
    }
}

impl RootfsDir {
    /// `bundle`（絶対パス）配下の `rootfs` を、祖先を含む全要素を symlink 非追従で辿って固定する。
    ///
    /// `rootfs` は `validate_bundle` が返した検査済みパス（`bundle` 配下・`..` なし）。検査後に
    /// bundle 配下の要素が symlink・非ディレクトリ・不在へ変わっていれば `PermissionDenied`
    /// （`rootfs changed after validation`）、bundle 自体やその祖先が symlink を含む・ディレクトリで
    /// ないなら `InvalidArgument`。本番 launcher の `exec::prepare_rootfs` も `/` から同じ条件で rootfs を
    /// 辿るため、ここで先に拒否する。メッセージは固定文言のみ（パス・errno を含めない）。
    ///
    /// 前者（`rootfs changed after validation`）に限り、`open_dir_beneath` が返した違反の理由
    /// （`path_symlink_or_not_directory`・`path_missing`）を [`RootfsPinError::violation`] で運ぶ
    /// （SEC-4・SEC-1・SUP-6・#1702）。exec の経路（supervisor の `load_exec_bundle`）はこれを監査ログの層
    /// `mount` へ記録する。start の経路は `build_spec` が launcher の拒否の記録先（`ProcessLauncher::rejection_audit_sink`）へ記録する（supervisor の relay は閉じた表の理由として運ぶ。#2623）。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(bundle: &Path, rootfs: &Path) -> Result<Self, RootfsPinError> {
        use crate::exec::ViolationReason;
        let invalid = |msg: &'static str| {
            RootfsPinError::without_violation(TraitError::new(ErrorCode::InvalidArgument, msg))
        };
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
                // 明示の列挙にする（`exec/violation_scan.rs` がソースから理由名を抽出して一覧と照合する）。
                Some(
                    reason @ (ViolationReason::PathSymlinkOrNotDirectory
                    | ViolationReason::PathMissing),
                ) => RootfsPinError {
                    error: TraitError::new(
                        ErrorCode::PermissionDenied,
                        "rootfs changed after validation",
                    ),
                    violation: Some(reason),
                },
                // bundle 自体や祖先の差し替えは、理由コード `rootfs_*` が bundle を rootfs と誤読させるため運ばない。
                Some(_) => invalid("bundle path must be a directory reachable without symlinks"),
                None => RootfsPinError::without_violation(TraitError::new(
                    e.code,
                    "failed to open the rootfs directory",
                )),
            }
        })?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Linux 以外では rootfs を fd で固定できないため、起動仕様を作らず拒否する（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(_bundle: &Path, _rootfs: &Path) -> Result<Self, RootfsPinError> {
        Err(RootfsPinError::without_violation(TraitError::new(
            ErrorCode::Unimplemented,
            "start requires Linux to pin the rootfs directory",
        )))
    }

    /// 固定した rootfs ディレクトリの fd（O_PATH。dirfd・`/proc/thread-self/fd/N`・`fchdir` 専用）。
    #[cfg(target_os = "linux")]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// 稼働中コンテナの `bundle` と読み込み済みの `config` から、コンテナの rootfs ディレクトリを固定する
/// （SUP-6・SEC-1・TASK-163.3・#502）。
///
/// exec の制限再適用（`exec::prepare_exec_restrictions`）が、`setns` 参加後の `/` が「記録したコンテナの
/// rootfs」であることを照合する基準に使う。start と同じ検査（`root.path` が bundle 配下・`..` なし・
/// symlink なしのディレクトリ）と同じ固定（`/` から全要素を symlink 非追従で辿る。[`RootfsDir`]）を通すため、
/// start が launcher へ渡す rootfs と同じ実体を指す。`process` の有無・未解釈フィールドは検査しない
/// （起動可否の判定ではなく、稼働中コンテナの rootfs の特定だけを行う）。
///
/// エラーは start と同じ固定文言で、パスを含めない。Linux 以外は `Unimplemented`（fail-closed。CLI-1）。
pub fn pin_bundle_rootfs(bundle: &Path, config: &OciConfig) -> Result<RootfsDir, TraitError> {
    pin_bundle_rootfs_audited(bundle, config).map_err(TraitError::from)
}

/// [`pin_bundle_rootfs`] と同じ固定を行い、失敗時に分離違反の理由も運ぶ（SEC-4・SEC-1・SUP-6・#1702）。
///
/// supervisor の exec の経路（`load_exec_bundle`）が使う。検証後の差し替えによる拒否のとき
/// `RootfsPinError::violation`（Linux のみ） が `Some` になり、呼び出し側が監査ログへ記録する。検証前の失敗
/// （`check_rootfs`）は違反を伴わない。
pub fn pin_bundle_rootfs_audited(
    bundle: &Path,
    config: &OciConfig,
) -> Result<RootfsDir, RootfsPinError> {
    let rootfs = super::create::check_rootfs(bundle, config.root().path())
        .map_err(RootfsPinError::without_violation)?;
    RootfsDir::pin(bundle, &rootfs)
}

/// 試験専用: [`pin_bundle_rootfs_audited`] の検証（`check_rootfs`）と固定（`pin`）の間で `swap` を呼ぶ。
///
/// 「検証後に bundle 配下の要素が差し替えられた」競合を決定的に再現し、exec の経路の記録を結合試験で
/// 通すための差し込み口（SEC-4・#1702）。本番経路には存在しない（`exec-test-support` feature の下のみ。
/// この feature を付けたリリースビルドは supervisor が `compile_error!` で拒否する）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn pin_bundle_rootfs_with_swap_for_test(
    bundle: &Path,
    config: &OciConfig,
    swap: impl FnOnce(),
) -> Result<RootfsDir, RootfsPinError> {
    let rootfs = super::create::check_rootfs(bundle, config.root().path())
        .map_err(RootfsPinError::without_violation)?;
    swap();
    RootfsDir::pin(bundle, &rootfs)
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
/// bundle とその祖先を書き換えられない者に対する排他である。
///
/// # 既知の制約（待たない取得と tmpfiles の aging 走査。#2840・CORE-2・REPAIR-5）
///
/// 取得は待たない（`try_lock`）。bundle の inode を読み取りで開ける者が一時的に `flock` を持つと、create・start・
/// delete が `FailedPrecondition`（`container start is in progress in another process`）で失敗しうる。
/// 例は `systemd-tmpfiles-clean` で、aging 対象のディレクトリ（Ubuntu の `/tmp`・`/var/tmp`）の走査中は
/// サブディレクトリごとに `flock(LOCK_EX|LOCK_NB)` を取る。そこに bundle を置くと、走査と重なった 1 回だけ
/// 誤って失敗する。挙動は変えていない（方式の見直しは追跡 issue で判断する）。
///
/// # 設計判断（起動権の排他方式。#1316・2026-10-12 確定、#1854。CORE-2・OCI-5・PLUG-1・SEC-1）
///
/// 起動権は、revision 照合つきの `StateStore::update`（Created から Running・pid なし）と、この
/// bundle の `flock` で排他する現状の方式を維持する。起動権（所有者の識別）を `StateStore` 側へ持たせず、
/// トレイトも変えない。
///
/// - 二重 start は revision 照合が防ぐ
/// - `flock` が受け持つのは、中断された start の回復（`recover_interrupted_start`）で元の所有プロセスの
///   終了を確かめることだけである
/// - `flock` を外せるのは bundle か祖先を書き換えられる者で、その者は `config.json` と rootfs を差し替えて
///   起動内容を決められる。起動権を `StateStore` 側へ移しても防げる攻撃は増えない
/// - #1314 の決定で start を呼ぶのはコンテナごとの supervisor になり、争う相手は同じコンテナの別の
///   supervisor だけである
///
/// 再検討の条件は、`StateStore` の別実装（plugin で差し替える実装）を作るときである。
#[derive(Debug)]
pub(super) struct BundleLock {
    #[cfg(target_os = "linux")]
    _file: std::fs::File,
    #[cfg(not(target_os = "linux"))]
    _never: std::convert::Infallible,
}

/// 予約の解放と同時にロックを外す。`flock` は open file description に付くため、コンテナの子が fork から
/// exec までの間にこの fd を引き継ぐと close だけではロックが残り、別プロセスの `start` / `recover` が
/// 誤って拒否される。`LOCK_UN` で fd の参照数に関係なく明示的に解放する（CORE-2・#1537）。
impl Drop for BundleLock {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = self._file.unlock();
    }
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

    /// `bundle` が指す実体（symlink を解決した先）の所有ロックを待たずに取得する（create・delete 用。OCI-7・#2378）。
    ///
    /// まず [`Self::acquire`] で取り、bundle 自体や祖先が symlink で拒否されたときだけ、`canonicalize` で
    /// 解決した実体の経路で取り直す。ロックは inode に掛かるため、別の表記（symlink 経由・実体の絶対パス）で
    /// 同じ bundle を指す create・delete・start とも排他できる。start は symlink 経由の bundle を拒否する
    /// （[`Self::acquire`]）ので、このフォールバックを使わない。解決の失敗は元のエラーを返す。
    /// 解決と取得の間に経路を差し替えられる者は信頼境界の外（型 doc「前提（信頼境界）」）。
    #[cfg(target_os = "linux")]
    pub(super) fn acquire_resolved(bundle: &Path) -> Result<Self, TraitError> {
        match Self::acquire(bundle) {
            Err(e) if e.code() == ErrorCode::InvalidArgument && bundle.is_absolute() => {
                match std::fs::canonicalize(bundle) {
                    Ok(real) if real != bundle => Self::acquire(&real),
                    _ => Err(e),
                }
            }
            other => other,
        }
    }

    /// Linux 以外では所有ロックを取れないため拒否する（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn acquire_resolved(bundle: &Path) -> Result<Self, TraitError> {
        Self::acquire(bundle)
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
    cgroup: CgroupRequirement,
    /// start が一度だけ読んだ config（本番 launcher が Landlock の ruleset 等を作る入力。bundle は読み直さない）。
    config: std::sync::Arc<OciConfig>,
    /// 起動対象のコンテナ ID（監査記録の `container` に使う。SEC-4）。
    container_id: ContainerId,
    /// `config` と同じ `mounts[]` から `start` が検証した bind mount の集合（#1915）。
    bind_mounts: BindMountSet,
    /// `config` の `mounts[]` から `start` が検証した `/sys` の sysfs（無ければ `None`。#2020）。
    sysfs: Option<SysfsMountSpec>,
    /// `process.cwd`（start が字句検証済み。pivot 後に移る。OCI-1・TASK-29）。
    working_dir: ContainerWorkingDir,
    /// `process.user` の (uid, gid)（名前空間内の値。写像との整合は launcher が fork 前に検査する。OCI-1・SEC-5）。
    user: (u32, u32),
    /// `process.user.additionalGids`（start が件数の上限を検証済み。写像との照合と適用は launcher。
    /// OCI-1・SEC-5・CORE-6・#2667）。
    additional_gids: Vec<u32>,
    /// pod の user・ipc namespace への join（`linux.namespaces[].path`。start が fork 前に fd へ固定して検証済み。
    /// 無ければ `None`。CRI-2・CORE-3・SEC-1・SEC-5。#2674）。
    namespace_join: Option<NamespaceJoin>,
    /// start が起動オプションと config を突き合わせた network の実効の扱い(NET-6・SEC-1・#3058)。
    network: EffectiveNetwork,
    /// 突き合わせに使ったモード(launcher が自身のモードと照合し、転送漏れによる縮退を拒否する)。
    network_mode: LaunchNetworkMode,
    /// `start` が使った状態ルート（`StateStore::host_state_root()`。管理ルートの `/etc/hosts` 等の元の場所を導く入力。
    /// 無ければ `None`。NET-12・#1872）。
    state_root: Option<PathBuf>,
}

impl LaunchSpec {
    // 理由: start が一度だけ検証した各値を欠落なく束ねる唯一の構築点で、同じ型の引数を取り違えない
    // よう公開しない(`pub(super)`)。呼び出しは start の 1 か所だけのため、引数用の中間構造体は設けない。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        rootfs: PathBuf,
        rootfs_dir: RootfsDir,
        args: Vec<String>,
        env: Vec<String>,
        hostname: Option<String>,
        namespaces: Vec<NamespaceKind>,
        cgroup: CgroupRequirement,
        config: std::sync::Arc<OciConfig>,
        container_id: ContainerId,
        bind_mounts: BindMountSet,
        working_dir: ContainerWorkingDir,
        user: (u32, u32),
    ) -> Self {
        Self {
            rootfs,
            rootfs_dir,
            args,
            env,
            hostname,
            namespaces,
            cgroup,
            config,
            container_id,
            bind_mounts,
            sysfs: None,
            working_dir,
            user,
            additional_gids: Vec::new(),
            namespace_join: None,
            network: EffectiveNetwork::HostShared,
            network_mode: LaunchNetworkMode::FromConfig,
            state_root: None,
        }
    }

    /// 突き合わせた network の扱いとそのモードを載せる(`start` だけが呼ぶ。NET-6・#3058)。
    pub(super) fn with_network(
        mut self,
        network: EffectiveNetwork,
        mode: LaunchNetworkMode,
    ) -> Self {
        self.network = network;
        self.network_mode = mode;
        self
    }

    /// network の実効の扱い(NET-6・SEC-1)。`NewLoopback` は新しい netns の作成を要求する(実体は #3064 で実装済み。`Attachable` モードも同じ実効値で、同期点が fd 2 本を渡す差だけ。#1939)。
    pub fn network(&self) -> EffectiveNetwork {
        self.network
    }

    /// `network()` を決めた起動オプションのモード。
    pub fn network_mode(&self) -> LaunchNetworkMode {
        self.network_mode
    }

    /// `start` が使った状態ルートを載せる(`start` だけが呼ぶ。呼び出し側が任意のパスを渡す入口にしない。NET-12・#1872)。
    pub(super) fn with_state_root(mut self, state_root: Option<PathBuf>) -> Self {
        self.state_root = state_root;
        self
    }

    /// `start` が使った状態ルート(`StateStore::host_state_root()` の値。無ければ `None`)。
    ///
    /// 本番 launcher が、`LaunchOptions::etc_files` の指定時に `<state_root>/@container-etc/<id>/` の生成物を
    /// fork 前に検証するために使う(NET-12・#1872)。
    pub fn state_root(&self) -> Option<&Path> {
        self.state_root.as_deref()
    }

    /// 検証済みの補助グループ（`process.user.additionalGids`）を載せる（`start` だけが呼ぶ。#2667）。
    pub(super) fn with_additional_gids(mut self, gids: Vec<u32>) -> Self {
        self.additional_gids = gids;
        self
    }

    /// `process.user.additionalGids`（名前空間内の値。OCI-1・SEC-5・CORE-6・#2667）。
    ///
    /// 本番 launcher が fork の前に gid の写像と照合し、子の capability 削減段が `setgroups(list)` で適用する。
    /// 空なら補助グループを持たせない（持ち越しもしない）。
    pub fn additional_gids(&self) -> &[u32] {
        &self.additional_gids
    }

    /// 検証済みの pod の namespace への join を載せる（`start` と launcher の試験が呼ぶ。#2674）。
    pub(super) fn with_namespace_join(mut self, join: Option<NamespaceJoin>) -> Self {
        self.namespace_join = join;
        self
    }

    /// pod の user・ipc namespace への join（無ければ `None`。CRI-2・CORE-3。#2674）。
    ///
    /// 本番 launcher が中間プロセスの分離で `setns` に使う。`namespaces()` には `User`・`Ipc` が含まれ（新規作成ではなく
    /// join する）、restart の再 launch でも同じ fd を使う。
    pub fn namespace_join(&self) -> Option<&NamespaceJoin> {
        self.namespace_join.as_ref()
    }

    /// 検証済みの sysfs の指定を載せる（`start` だけが呼ぶ。#2020）。
    pub(super) fn with_sysfs(mut self, sysfs: Option<SysfsMountSpec>) -> Self {
        self.sysfs = sysfs;
        self
    }

    /// `start` が検証した `/sys` の sysfs（TASK-29 追補・#2020・SEC-2・OCI-4）。
    ///
    /// 本番 launcher が pivot 前段の `mount_sysfs` へ渡す。restart でも捕捉した spec を clone して再 launch
    /// するため同じ指定が再適用される。`None` なら `/sys` には何も供給しない（rootfs の `sys` を読み取り専用に
    /// するだけの従来の動作）。
    pub fn sysfs_mount(&self) -> Option<&SysfsMountSpec> {
        self.sysfs.as_ref()
    }

    /// 検証済みの作業ディレクトリ（`process.cwd`。OCI-1・TASK-29）。
    pub fn working_dir(&self) -> &ContainerWorkingDir {
        &self.working_dir
    }

    /// `process.user` の (uid, gid)（コンテナ内の値。OCI-1・SEC-5）。
    pub fn user(&self) -> (u32, u32) {
        self.user
    }

    /// `start` が検証した bind mount の集合（`mounts[]` の指定順。TASK-29 追補・#1915・OCI-4・SEC-1）。
    ///
    /// `config` と同じ `Arc<OciConfig>` の `mounts()` から作るため、Landlock の ruleset
    /// （`build_path_rules`）と入力が同一で、適用する bind と許可ルールが食い違わない。restart でも
    /// 捕捉した spec を clone して再 launch するため、同じ集合が再適用される。空なら bind は無い。
    pub fn bind_mounts(&self) -> &BindMountSet {
        &self.bind_mounts
    }

    /// 起動対象のコンテナ ID（launcher が pivot 前段の違反を監査記録する際の `container`。SEC-4）。
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// start が一度だけ読んだ config（同一 crate の本番 launcher が Landlock の ruleset 生成に使う。CORE-5）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // 読み手は Linux 限定の本番 launcher
    pub(crate) fn config(&self) -> &OciConfig {
        &self.config
    }

    /// config が cgroup を使う設定かどうか（CORE-3・#1814）。必要なのに join の手段が無ければ、
    /// launcher は fork の前に `require_cgroup_join` で拒否する。`linux.resources` の指定（`{}` を含む）で必要に
    /// なる（#2019）。`linux.cgroupsPath` は `start` が先に拒否するため、その由来では必要にならない（値は配置に使わない方針。#2010）。
    pub fn cgroup_requirement(&self) -> CgroupRequirement {
        self.cgroup
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

/// [`ProcessLauncher::launch`] の時間上限の守り方（REPAIR-5）。
///
/// start が launch をどのスレッドで・どう上限づけて呼ぶかを launcher 自身が宣言する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LaunchMode {
    /// 既定。start が別スレッドで launch を呼び、上限（＋猶予）を過ぎたら待つのをやめる（`call_bounded`）。
    CallerBounded,
    /// launcher が自身の上限を守る。start は launch を**呼び出しスレッドで直接**呼ぶ（別スレッドを作らない）。
    ///
    /// fork する本番 launcher は呼び出しプロセスが単一スレッドであること（`Threads: 1`）を要求するため、
    /// start が別スレッドを作る経路からは起動できない（CORE-1・CORE-5）。この宣言をした実装は次を守る:
    /// 入口で 1 つの `Instant` 期限（`timeout`）を取りすべての待ちをそこから導く。失敗後の後始末が足す上限は
    /// 固定値で示す。戻りは `timeout` ＋後始末の上限以内とする。start はこの上限を強制しない（直接呼びのため）。
    SelfBounded,
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

/// 起動済みコンテナの標準出力・標準エラーの読み取り側（TASK-164 追補・#1471・SUP-7・SUP-1）。
///
/// launcher が子の stdout / stderr をパイプへ接続して作り、[`LaunchedProcess::take_output`] で supervisor へ
/// 渡す。supervisor はこれを行単位捕捉（`LogCapture`）へ移し、ローテーション付きの sink へ流す。OS 固有の型
/// （fd）は公開せず `Read + Send` に包む（CLI-1）。どちらかが `None` なら、そのストリームは捕捉しない。
/// 読み取り側は書き込み側（子とその孫）がすべて閉じると EOF になる。
#[derive(Default)]
pub struct ContainerOutput {
    /// コンテナの標準出力。
    pub stdout: Option<Box<dyn std::io::Read + Send>>,
    /// コンテナの標準エラー。
    pub stderr: Option<Box<dyn std::io::Read + Send>>,
}

impl std::fmt::Debug for ContainerOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerOutput")
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .finish()
    }
}

/// 起動済みプロセスへのハンドル。
///
/// start は上限を強制するため別スレッド（上限超過後の後始末を含む）へハンドルを移すので `Send` を要求する。
/// start が成功すると、ハンドルは `StartedContainer` として呼び出し元へ引き渡され、呼び出し元
/// （supervisor〔TASK-157・SUP 系〕等）が監視・回収の所有者になる（[`Self::wait`]・[`Self::terminate`]）。
/// 実装は `Drop` で kill / 回収しなくてよい（コンテナの寿命をハンドルに暗黙で縛らない）ため、所有者は
/// 終了まで待って回収する責任を負う。
pub trait LaunchedProcess: Send {
    /// 起動したコンテナプロセスの pid。**コンテナの PID 1**（launcher の PID namespace から見て `NSpid` が
    /// 2 要素で末尾 1）を指すこと。中間プロセス（fork 親・mapper・代役 init）を返してはならない。違反すると
    /// exec が `exec_target_not_nested_pid1` で拒否する。PID 1 の pidfd の取得は本番 launcher の責務
    /// （SUP-6・SEC-1・CORE-1・TASK-163 追補・#1463）。
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
    /// 回収済みのプロセスへは送らず `FailedPrecondition` を返すこと（pid 再利用対策。SEC-1）。
    /// `deadline` は呼び出し側（`kill`）が `Timeout` を返す時刻以前の絶対期限で、実装は実際の送信直前に
    /// 期限切れを確認し、切れていれば送らずに `Timeout` を返すこと（期限後にシグナルが届かない。REPAIR-5）。
    /// 既定実装は送信手段を持たないため fail-closed で `Unimplemented` を返す。
    fn signal(&self, signal: Signal, deadline: std::time::Instant) -> Result<(), TraitError> {
        let _ = (signal, deadline);
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "the launched process cannot be signaled",
        ))
    }

    /// 起動時（fork 直後・回収前）に開いた pidfd の借用。exec の対象（pid1）をこの pidfd で固定するために
    /// supervisor が参照する（記録 pid や cgroup の所属に同一性を依存させない。SUP-6・SEC-1・CORE-1・
    /// TASK-163 追補・#1461）。
    /// 指す先は [`Self::pid`] と同じ PID 1 であること（#1463）。
    /// 既定は `None`（pidfd を保持しない実装。呼び出し側は fail-closed にする）。
    #[cfg(target_os = "linux")]
    fn launch_pidfd(&self) -> Option<BorrowedFd<'_>> {
        None
    }

    /// コンテナの stdout / stderr の読み取り側を 1 回だけ取り出す（TASK-164 追補・#1471・SUP-7・SUP-1）。
    ///
    /// supervisor が起動・再起動のたびに呼び、行単位捕捉へ渡す。2 回目以降と、出力を捕捉しない実装は `None`
    /// （既定）。取り出した後の所有権は呼び出し側に移る。`LaunchedProcess` を包み直す実装は、内側の
    /// `take_output` へ転送すること（転送しないと出力が捕捉されず、コンテナの出力が失われる）。
    fn take_output(&self) -> Option<ContainerOutput> {
        None
    }

    /// seccomp の listener fd を 1 回だけ取り出す(Linux。SEC-4・TASK-41 追補・#2024。監査配送 2/6)。
    ///
    /// 本番 launcher は PID 1 が `NEW_LISTENER` 付きで filter を載せて渡した fd を、検証のうえ持たせる。supervisor が
    /// 起動・再起動のたびに呼び、監視の間保持する(閉じると `USER_NOTIF` 側の待機中の syscall が `ENOSYS` になる)。
    /// 通知を読んで応答するのは supervisor の `SeccompNotifyHub`（#2025）。filter が `UserNotif` 版（builder の opt-in）のとき
    /// 応答者がいないと拒否対象の syscall が止まる。既定の ERRNO 版では通知は生じない。2 回目以降と、listener を
    /// 持たない実装は `None`(既定)。`LaunchedProcess` を包み直す実装は内側へ転送すること(`take_output` と同じ注意)。
    #[cfg(target_os = "linux")]
    fn take_seccomp_listener(&self) -> Option<crate::exec::SeccompListener> {
        None
    }

    /// launch が確定した分離の記録（`/` の識別子と適用した Landlock ルール）。start が Running の更新と同じ
    /// `update` で、restart が Running(新 pid) の更新で `state.json` へ書く（SUP-6・CORE-5・SEC-1・#2007）。
    ///
    /// 本番 launcher は必ず `Some` を持たせる（作れなければ launch が `Err` になる）。既定の `None` は記録を
    /// 作らない実装（偽の launcher・Linux 以外）用で、状態の記録は前の値のまま引き継がれ、exec は記録が無ければ
    /// 拒否する。`LaunchedProcess` を包み直す実装は内側へ転送すること（転送しないと restart の後の exec が
    /// 拒否される。`take_output` と同じ注意）。
    fn launch_isolation(&self) -> Option<&crate::launch_isolation::LaunchIsolationRecord> {
        None
    }

    /// launch が `Rlimits` 段へ渡した全 16 種の rlimit 集合(`--ulimit` の指定値と継承値の補完。SUP-12・#2713)。
    /// start / restart が Running の更新と同じ `update` で `state.json` へ書き、exec の再適用が launch と同じ制限を
    /// 載せる根拠になる。`LaunchedProcess` を包み直す実装は内側へ転送すること(`launch_isolation` と同じ注意)。
    /// 持たない実装は `None`(既定。前の記録が引き継がれる)。
    fn launch_rlimits(&self) -> Option<&crate::rlimits::Rlimits> {
        None
    }
}

/// `exec::ContainerChild`（fork した子）を [`LaunchedProcess`] として扱うアダプタ（Linux。CORE-1・REPAIR-5）。
///
/// 本番 launcher（`ProductionLauncher`）が `exec::spawn_container_via_intermediate` の戻り値を包んで返すために置く。
/// [`LaunchedProcess::terminate`] は `ContainerChild::kill_and_reap`、[`LaunchedProcess::wait`] は
/// `ContainerChild::wait_for_exit` を呼び、`wait_timeout` と同じ回収状態の排他の下で回収する（回収済みの
/// pid へは `SIGKILL` を送らない）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ContainerChildProcess {
    child: crate::exec::ContainerChild,
    pid: NonZeroU32,
    /// `take_output` で 1 回だけ取り出す stdout / stderr の読み取り側（無ければ `None`）。`take_output` が
    /// `&self` のため `Mutex` で保持する。
    output: std::sync::Mutex<Option<ContainerOutput>>,
    /// `take_seccomp_listener` で 1 回だけ取り出す listener(SEC-4・#2024)。`&self` のため `Mutex` で保持する。
    seccomp_listener: std::sync::Mutex<Option<crate::exec::SeccompListener>>,
    /// `terminate` が成功（回収を確かめられた）したときに 1 回呼ぶ通知。本番 launcher が起動台帳へ回収の
    /// 証跡を引き継ぐために付ける（CORE-2）。
    reap_notice: Option<ReapNotice>,
    /// launch が確定した分離の記録（本番 launcher が付ける。[`LaunchedProcess::launch_isolation`]）。
    launch_isolation: Option<crate::launch_isolation::LaunchIsolationRecord>,
    /// launch が `Rlimits` 段へ渡した全 16 種の集合(本番 launcher が付ける。[`LaunchedProcess::launch_rlimits`])。
    launch_rlimits: Option<crate::rlimits::Rlimits>,
    /// SIGSYS 終了の補助記録（SEC-4・ESC-06・#2004）。本番 launcher だけが付ける。
    exit_audit: Option<ExitAudit>,
}

/// SIGSYS（x86_64・aarch64 とも asm-generic の 31）。
#[cfg(target_os = "linux")]
const SIGSYS: i32 = 31;

/// [`ContainerChildProcess::with_exit_audit`] の記録先とコンテナ ID。`recorded` は 1 回だけ記録するための印。
#[cfg(target_os = "linux")]
struct ExitAudit {
    sink: Arc<dyn crate::audit_log::AuditSink>,
    container: ContainerId,
    recorded: std::sync::atomic::AtomicBool,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for ExitAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExitAudit")
    }
}

/// [`ContainerChildProcess::with_reap_notice`] の通知。
#[cfg(target_os = "linux")]
type ReapNoticeFn = Box<dyn Fn() + Send + Sync>;

/// 回収通知の入れ物（`Debug` を手で実装する。クロージャは `Debug` を持たないため）。
#[cfg(target_os = "linux")]
struct ReapNotice(ReapNoticeFn);

#[cfg(target_os = "linux")]
impl std::fmt::Debug for ReapNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReapNotice")
    }
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
        Ok(Self {
            child,
            pid,
            output: std::sync::Mutex::new(None),
            seccomp_listener: std::sync::Mutex::new(None),
            reap_notice: None,
            launch_isolation: None,
            launch_rlimits: None,
            exit_audit: None,
        })
    }

    /// launch が確定した分離の記録を持たせる（[`LaunchedProcess::launch_isolation`] で返る。#2007）。
    #[must_use]
    pub(crate) fn with_launch_isolation(
        mut self,
        record: crate::launch_isolation::LaunchIsolationRecord,
    ) -> Self {
        self.launch_isolation = Some(record);
        self
    }

    /// launch が適用した全 16 種の rlimit 集合を持たせる([`LaunchedProcess::launch_rlimits`] で返る。#2713)。
    #[must_use]
    pub(crate) fn with_launch_rlimits(mut self, rlimits: crate::rlimits::Rlimits) -> Self {
        self.launch_rlimits = Some(rlimits);
        self
    }

    /// SIGSYS で終了したと回収した時に、補助の監査レコード（層 `exit_signal`）を 1 件出すよう設定する
    /// （SEC-4・ESC-06・TASK-41 追補・#2004）。本番 launcher（`ProductionLauncher::launch`）が付ける。
    ///
    /// 契約:
    /// - **補助**である。`SECCOMP_RET_KILL_PROCESS` で終了したプロセスは自分では記録を書けず、正の記録
    ///   （syscall・arch・pid）はカーネルの `AUDIT_SECCOMP` が担う。コンテナ内の `kill(SIGSYS)` とは
    ///   区別できないため、seccomp 由来とは断定せず、syscall も推測しない（`AuditEvent::ExitSignal` は
    ///   型として syscall・arch を持たない）
    /// - 記録は `wait` / `terminate` が SIGSYS の終了を初めて見たときにちょうど 1 回、回収の**後**に出す。
    ///   sink の失敗は握りつぶし、終了状態の返却を変えない（`AuditSink` の契約）
    /// - 記録の `target_pid` は回収した側（呼び出しプロセス）の PID namespace の値
    /// - 複数スレッドのプロセスでは `FileAuditSink` の隔離が使えず、rootless では代替経路も失敗するため、本番
    ///   launcher は `ProductionLauncherBuilder::exit_audit_sink` で指定された記録先（supervisor は単一スレッドの間に
    ///   作った `ControlAuditRelay`。#2236）を渡す
    /// - 制約（後続）: pid 1 以外の子孫の SIGSYS 終了は、コンテナの PID namespace の外にいる親から `waitpid` で見えない
    ///   （孤児は namespace 内の init に再親付けされる）。親が観測できる手段は承認済みの最小権限の範囲に無く、
    ///   正の記録はカーネルの `AUDIT_SECCOMP` が担う（`docs/design/audit-delivery.md` 9.1）
    #[must_use]
    pub(crate) fn with_exit_audit(
        mut self,
        sink: Arc<dyn crate::audit_log::AuditSink>,
        container: ContainerId,
    ) -> Self {
        self.exit_audit = Some(ExitAudit {
            sink,
            container,
            recorded: std::sync::atomic::AtomicBool::new(false),
        });
        self
    }

    /// 回収した終了状態が SIGSYS なら、補助の `exit_signal` レコードを 1 回だけ出す（#2004）。
    fn record_exit_signal_once(&self, exit: crate::exec::ChildExit) {
        use std::sync::atomic::Ordering;
        let crate::exec::ChildExit::Signaled(SIGSYS) = exit else {
            return;
        };
        let Some(audit) = &self.exit_audit else {
            return;
        };
        if audit.recorded.swap(true, Ordering::SeqCst) {
            return;
        }
        // 配送結果は呼び出し側の終了状態に影響させない（失敗の通知は sink の責務）。
        // 共有の relay のロック待ちを含め、配送全体を絶対期限で制限する（REPAIR-5・SEC-4・ESC-06・#2236）。
        let deadline = std::time::Instant::now() + crate::audit_log::RECORD_WAIT_LIMIT;
        let _ = crate::audit_log::record_exit_signal_until(
            SIGSYS,
            self.pid.get(),
            Some(&audit.container),
            audit.sink.as_ref(),
            Some(deadline),
        );
    }

    /// `terminate` が成功したときに呼ぶ通知を持たせる（起動台帳への回収の証跡の引き継ぎ。CORE-2）。
    #[must_use]
    pub(crate) fn with_reap_notice(mut self, notice: ReapNoticeFn) -> Self {
        self.reap_notice = Some(ReapNotice(notice));
        self
    }

    /// 子の stdout / stderr の読み取り側を持たせる（`exec::ChildStdio::pipes` が返したもの。#1471）。
    /// [`LaunchedProcess::take_output`] で 1 回だけ取り出される。
    #[must_use]
    pub fn with_output(self, stdout: std::io::PipeReader, stderr: std::io::PipeReader) -> Self {
        let output = ContainerOutput {
            stdout: Some(Box::new(stdout)),
            stderr: Some(Box::new(stderr)),
        };
        *self
            .output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(output);
        self
    }

    /// PID 1 から受け取った seccomp の listener を持たせる(`LaunchedProcess::take_seccomp_listener` で 1 回だけ返る)。
    #[must_use]
    pub(crate) fn with_seccomp_listener(
        self,
        listener: Option<crate::exec::SeccompListener>,
    ) -> Self {
        *self
            .seccomp_listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = listener;
        self
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

    fn launch_pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.child.pidfd()
    }

    fn launch_isolation(&self) -> Option<&crate::launch_isolation::LaunchIsolationRecord> {
        self.launch_isolation.as_ref()
    }

    fn launch_rlimits(&self) -> Option<&crate::rlimits::Rlimits> {
        self.launch_rlimits.as_ref()
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn take_seccomp_listener(&self) -> Option<crate::exec::SeccompListener> {
        self.seccomp_listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
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
            Some(ChildExit::Signaled(sig)) => {
                self.record_exit_signal_once(ChildExit::Signaled(sig));
                Ok(Some(ProcessExit::Signaled(sig)))
            }
        }
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let exit = self
            .child
            .kill_and_reap(timeout)
            .map_err(|e| TraitError::new(e.code, "failed to terminate the container process"))?;
        self.record_exit_signal_once(exit);
        if let Some(notice) = &self.reap_notice {
            (notice.0)();
        }
        Ok(())
    }

    /// `ContainerChild::send_signal_until`（回収状態のロック下で送信）へ委ねる。回収済み・既に消えていた
    /// 場合は送らずに `FailedPrecondition` を返す。`deadline` は呼び出し側から引き継いだ絶対期限で、
    /// ロック取得後・送信直前に確認し、切れていれば送らない（REPAIR-5）。
    fn signal(&self, signal: Signal, deadline: std::time::Instant) -> Result<(), TraitError> {
        use crate::exec::SignalDelivery;
        let number = std::num::NonZeroU8::new(signal.as_u8()).ok_or_else(|| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                "signal number must be in 1..=64",
            )
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
///   強制する（[`LaunchMode::CallerBounded`] のとき。`SelfBounded` は launcher が自身の上限を守り、start は呼び出しスレッドで直接呼ぶ）（超過後に返ってきた起動済みプロセスは start が [`LaunchedProcess::terminate`] で後始末する）。
///   別スレッドから呼ばれ得るため `Send + Sync` とする
/// - exec フローの fail-closed（制限証跡なしの exec 拒否。SEC-1・CORE-5）を回避しない
/// - 失敗時にプロセスを残さない
/// - rootfs は [`LaunchSpec::rootfs_dir`] の固定ハンドルから使い、`rootfs()` のパスを再解決しない（SEC-1）
/// - `linux.uidMappings` / `gidMappings` は `start` が拒否済みで `LaunchSpec` に載らない。user namespace の
///   写像は launcher の責務で、コンテナ内 root（uid/gid 0）をホストの非特権 UID・GID（呼び出しプロセスの
///   euid・egid。0 なら拒否）へ写すこと。`exec::plan` / `exec::isolate` が既定でこの写像を行う（SEC-5）
///   subuid / subgid の範囲写像（コンテナ内に複数 UID を持たせる通常の rootless 構成）が要る場合は
///   `exec::plan_rootless_subordinate` / `exec::isolate_rootless_subordinate` を使う（TASK-40.2・CORE-6。
///   `linux.uidMappings` を `LaunchSpec` へ載せる経路は未実装。受けるかは #2240 で判断待ち）
/// - [`LaunchSpec::cgroup_requirement`] が必要なのに cgroup への join の手段が無ければ、fork の前に
///   `require_cgroup_join` で拒否する（SEC-1・CORE-3・#1814）。join の手段は `LaunchSpec` に載せず、
///   launcher の構築時に保持する
/// - `LaunchSpec::namespaces` には Pid・Mount・User・Ipc・Uts が必ず含まれる（`start` が検証済み）
///
/// 本番実装は `ProductionLauncher`（`launcher.rs`。Linux。モジュール doc 参照）。
pub trait ProcessLauncher: Send + Sync {
    /// 時間上限の守り方（[`LaunchMode`]）。既定は `CallerBounded`（start が別スレッドで上限を強制する）。
    ///
    /// ラッパー実装は内側へ転送すること（転送しないと `CallerBounded` へ黙って降格し、`SelfBounded` の
    /// 本番 launcher が複数スレッドの呼び出しとして拒否される）。
    fn launch_mode(&self) -> LaunchMode {
        LaunchMode::CallerBounded
    }

    /// `start` が設定の検証（bind mount 等）で拒否したとき、その違反を記録する launch 経路の監査 sink（SEC-4・#1915）。
    ///
    /// `start` は sink を持たないため、launcher が持つ sink を借りて拒否を記録する。既定は `None`
    /// （記録先なし）。ラッパー実装は必ず内側へ転送すること（転送しないと本番で監査が黙って落ちる）。
    fn rejection_audit_sink(&self) -> Option<&dyn crate::audit_log::AuditSink> {
        None
    }

    /// 起動オプションの network モード(NET-6・SEC-1・#3058)。start が予約・fork より前に config と突き合わせる。
    ///
    /// 既定は `FromConfig`。ラッパー実装は必ず内側へ転送すること(転送しないと `FromConfig` へ黙って縮退する。
    /// 本番 launcher は spec のモードと自身のモードの不一致を `FailedPrecondition` で拒否する)。
    fn network_mode(&self) -> LaunchNetworkMode {
        LaunchNetworkMode::FromConfig
    }

    /// プロセスを起動し、ハンドルを返す。`timeout` は起動確認（子からの通知待ち等）の上限。
    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError>;

    /// 直近の `launch` が `Err` で戻ったとき、回収を確認できていない子が残っている可能性があるか(CORE-2)。
    ///
    /// `true` なら start は起動予約(Running・pid なし)を `Created` へ戻さず保持する。戻すと、残った子が
    /// いる状態で同じ ID の start や(cgroup 記録のない構成での)delete が通ってしまうため。回復は
    /// `recover_interrupted_start`(`confirm_no_process` による確認つき)に限る。`launch` が `Ok` のときは
    /// 呼ばれない。既定は `false`(失敗時にプロセスを残さない契約を信頼する)。
    fn last_launch_may_have_left_process(&self) -> bool {
        false
    }

    /// `id` の起動が生存プロセスを残していないことを確認する（中断された start の回復用。CORE-2・SEC-1）。
    ///
    /// start は launch 後・pid 記録前に異常終了すると、pid が状態に残らないまま生きたプロセスを残し得る。
    /// `recover_interrupted_start` は予約を Created へ戻す前に本メソッドを呼び、`Ok(())` のときだけ戻す
    /// （戻すと同じ ID の二重起動が可能になるため）。実装は、`id` のプロセスが存在しないと確証できる場合、
    /// または存在する場合に終了・回収したうえで `Ok(())` を返し、確証できない場合は `Err` を返すこと。
    /// 進行中の launch との排他は start 側が担う（同一プロセス内は予約、プロセス間は bundle ディレクトリの
    /// 所有ロック。本メソッドは所有ロックを取れた後にだけ呼ばれる）ため、実装は生存プロセスの確認に専念する。
    /// 既定実装は確認手段を持たないため fail-closed で `Unimplemented` を返す。待ちは `timeout` まで。
    ///
    /// 本番の `ProductionLauncher` は、自身が起動した範囲だけを確証できる（起動台帳。#1817）。失敗した launch の
    /// 回収できなかった子と報告前の PID 1 を期限内に再回収・再探索し、消滅を確かめられたときだけ `Ok(())` を返す。
    /// 台帳に無い ID（別プロセスで起動した残存）とハンドルを渡し済みの ID は、このメソッドでは確証できないため
    /// `FailedPrecondition`。別プロセスの残存は [`Self::confirm_no_process_recorded`] が記録済みの cgroup から確かめる。
    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        let _ = (id, timeout);
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "the launcher cannot confirm that no process remains for this container",
        ))
    }

    /// [`Self::confirm_no_process`] に、状態記録の cgroup の配置 `recorded` を添えたもの（別プロセスで起動した
    /// 残存の確認。#2011・CORE-2・SEC-1）。
    ///
    /// `recover_interrupted_start` が、照合済みのレコードの `StateRecord::cgroup` をそのまま渡す（配置は start の
    /// 手順 5 で 1 回だけ記録され上書きされないため、読んだ時点の値でよい）。ID だけからパスを組み立てない。
    /// 本番の `ProductionLauncher` は、台帳にある ID は従来どおり台帳で判定し、台帳に無い ID だけ、`recorded` の
    /// コンテナ cgroup にプロセスが居ないことを確かめる（居れば止めて確かめる。記録が無い・検証できない・読めない
    /// ときは `Ok` にしない）。既定実装は `recorded` を使わず [`Self::confirm_no_process`] へ転送する。
    ///
    /// ラッパー実装は必ず内側へ転送すること（転送しないと既定実装へ黙って縮退し、別プロセスの残存を確かめられず
    /// 回復が成功しなくなる）。
    fn confirm_no_process_recorded(
        &self,
        id: &ContainerId,
        recorded: Option<&CgroupPlacement>,
        timeout: Duration,
    ) -> Result<(), TraitError> {
        let _ = recorded;
        self.confirm_no_process(id, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORE-2・#1537: fork で継承された fd（同じ open file description）が残っていても、`BundleLock` の
    /// drop でロックが外れて再取得できる。素の `File` は close だけでは外れない（仕組みの照合）。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_bundle_lock_release_survives_inherited_fd() {
        use std::process::{Command, Stdio};
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        // 製品の `BundleLock` は `ScratchDir` 自身ではなくその子の bundle にかける（親の共有 flock と衝突させない。#3373）。
        let scratch = crate::scratch_root::ScratchDir::new(
            "fandhe-bundle-lock-inherit",
            std::time::Duration::from_secs(10),
        );
        let dir = scratch.path().join("bundle");
        std::fs::create_dir(&dir).expect("mkdir");
        let lock = BundleLock::acquire(&dir).expect("acquire");
        // 子の stdin へ同じ OFD の dup を渡し、fork 継承で fd が残る状況を模す。
        let dup = lock._file.try_clone().expect("dup");
        let _child = Child(
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::from(dup))
                .spawn()
                .expect("spawn sleep"),
        );
        drop(lock);
        let again = BundleLock::acquire(&dir).expect("reacquire after drop");
        drop(again);

        // 対照: unlock なしの close ではロックが残る。
        let plain = std::fs::File::open(&dir).expect("open");
        plain.try_lock().expect("lock");
        let dup = plain.try_clone().expect("dup");
        drop(plain);
        let probe = std::fs::File::open(&dir).expect("open");
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(dup);
    }

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

    /// CORE-1・SUP-6（#1461）: `launch_pidfd` の既定は `None`、`ContainerChildProcess` は起動時の pidfd を返し、
    /// その fdinfo の `Pid:` が子の pid と一致する。
    #[cfg(target_os = "linux")]
    #[test]
    fn core1_launch_pidfd_default_none_and_child_process_returns_pidfd() {
        struct NoPidfd;
        impl LaunchedProcess for NoPidfd {
            fn pid(&self) -> NonZeroU32 {
                NonZeroU32::new(1).unwrap()
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                Ok(None)
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        assert!(NoPidfd.launch_pidfd().is_none());

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let process =
            ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                .expect("wrap");
        let fd = process
            .launch_pidfd()
            .expect("pidfd は Linux 5.3 以降が前提（pidfd 非対応環境では失敗させる）");
        use std::os::fd::AsRawFd as _;
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
            .expect("fdinfo");
        let line = info.lines().find(|l| l.starts_with("Pid:")).expect("Pid:");
        assert_eq!(line.trim_start_matches("Pid:").trim(), pid.to_string());
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// SUP-7・SUP-1（TASK-164 追補・#1471）: `take_output` は既定で `None`、`with_output` で持たせた読み取り側は
    /// 1 回だけ取り出せて、子の stdout / stderr の行が別々のパイプから具体値どおりに読める。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_1471_take_output_returns_stdout_and_stderr_once() {
        use std::io::Read as _;
        let (out_r, out_w) = std::io::pipe().expect("pipe");
        let (err_r, err_w) = std::io::pipe().expect("pipe");
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "echo out-line; echo err-line >&2"])
            .stdin(std::process::Stdio::null())
            .stdout(out_w)
            .stderr(err_w);
        let child = cmd.spawn().expect("spawn");
        // `cmd` が持つ書き込み側を閉じる（閉じないと読み取り側が EOF にならない）。
        drop(cmd);
        let pid = child.id();
        // 読み取りが戻らない場合に備え、期限（REPAIR-5）で子を kill する見張りを付ける。
        // kill された子のパイプは EOF になり、下の assert が失敗として戻る。
        let child = std::sync::Arc::new(std::sync::Mutex::new(child));
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
        let watchdog = {
            let child = std::sync::Arc::clone(&child);
            std::thread::spawn(move || {
                if cancel_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .is_err()
                {
                    let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
                }
            })
        };
        let process =
            ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                .expect("wrap");
        assert!(process.take_output().is_none(), "既定は出力なし");
        let process = process.with_output(out_r, err_r);
        let output = process.take_output().expect("output");
        assert!(process.take_output().is_none(), "2 回目は None");
        let (mut a, mut b) = (String::new(), String::new());
        output
            .stdout
            .expect("stdout")
            .read_to_string(&mut a)
            .expect("read stdout");
        output
            .stderr
            .expect("stderr")
            .read_to_string(&mut b)
            .expect("read stderr");
        // 子の終了も期限内に確認する（見張りが kill した場合は wait が戻る）。
        let status = loop {
            let polled = child
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .try_wait()
                .expect("try_wait");
            if let Some(s) = polled {
                break s;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let _ = cancel_tx.send(());
        watchdog.join().expect("watchdog");
        assert!(status.success(), "子が期限内に正常終了する: {status:?}");
        assert_eq!((a.as_str(), b.as_str()), ("out-line\n", "err-line\n"));
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
        let deadline = || std::time::Instant::now() + t;
        process.signal(Signal::SIGKILL, deadline()).expect("signal");
        assert_eq!(
            process.wait(t).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        let err = process
            .signal(Signal::SIGKILL, deadline())
            .expect_err("exited");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "the container process has already exited");
    }

    /// REPAIR-5・CORE-2（TASK-30.1）: 期限切れの絶対期限を渡された `signal` は送らずに `Timeout` を返し、
    /// 子は生きたまま（期限後にシグナルが届かない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_container_child_process_signal_suppressed_after_deadline() {
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
        let err = process
            .signal(Signal::SIGKILL, std::time::Instant::now())
            .expect_err("expired");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            process.wait(Duration::from_millis(100)).expect("wait"),
            None
        );
        process.terminate(Duration::from_secs(10)).expect("cleanup");
    }

    /// テスト用の一意なディレクトリ（終了時に削除）。
    #[cfg(target_os = "linux")]
    struct TempDir(
        PathBuf,
        #[allow(dead_code)] // drop で後始末するための guard（#3434・REPAIR-12）。
        crate::scratch_root::ScratchDir,
    );

    #[cfg(target_os = "linux")]
    impl TempDir {
        fn new(name: &str) -> Self {
            // pid だけの名前を先に消さず、排他作成の `ScratchDir` の子を使う（#3434・REPAIR-12）。
            let (scratch, dir) =
                crate::test_support::scratch_child(&format!("fandhe-oci-launch-{name}"), "d");
            Self(dir, scratch)
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
        assert_eq!(err.error().code(), ErrorCode::PermissionDenied);
        assert_eq!(err.error().message(), "rootfs changed after validation");
        assert_eq!(
            err.violation(),
            Some(crate::exec::ViolationReason::PathSymlinkOrNotDirectory)
        );
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
        assert_eq!(err.error().code(), ErrorCode::PermissionDenied);
        assert_eq!(err.error().message(), "rootfs changed after validation");
        assert_eq!(
            err.violation(),
            Some(crate::exec::ViolationReason::PathSymlinkOrNotDirectory)
        );
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
        assert_eq!(err.error().code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.error().message(),
            "bundle path must be a directory reachable without symlinks"
        );
        // bundle 自体の差し替えは、理由コード `rootfs_*` が bundle を rootfs と誤読させるため運ばない（#1702）。
        assert_eq!(err.violation(), None);
        let err = RootfsDir::pin(Path::new("rel"), Path::new("rel/rootfs")).expect_err("fail");
        assert_eq!(err.error().message(), "bundle path must be absolute");
        assert_eq!(err.violation(), None);
    }

    /// SEC-4・SEC-1・SUP-6・#1702: rootfs が不在へ差し替えられた拒否は `path_missing` を運ぶ（文言・code は不変）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_pin_carries_path_missing_when_rootfs_vanishes() {
        let t = TempDir::new("gone");
        let err = RootfsDir::pin(&t.0, &t.0.join("rootfs")).expect_err("fail");
        assert_eq!(err.error().code(), ErrorCode::PermissionDenied);
        assert_eq!(err.error().message(), "rootfs changed after validation");
        assert_eq!(
            err.violation(),
            Some(crate::exec::ViolationReason::PathMissing)
        );
        assert_eq!(
            TraitError::from(err).message(),
            "rootfs changed after validation"
        );
    }

    /// SEC-4・#1702: 検証（`check_rootfs`）の後・固定の前の差し替えを、差し込み関数で決定的に再現して拒否と理由を照合する。
    /// 検証前の失敗は違反を運ばない。
    #[cfg(all(target_os = "linux", feature = "exec-test-support"))]
    #[test]
    fn sec4_pin_bundle_rootfs_with_swap_carries_violation_only_after_validation() {
        use crate::exec::ViolationReason;
        let t = TempDir::new("swap");
        std::fs::write(
            t.0.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#,
        )
        .expect("config");
        std::fs::create_dir(t.0.join("rootfs")).expect("rootfs");
        let config = crate::oci_runtime::load_config(&t.0.join("config.json")).expect("config");
        let err = pin_bundle_rootfs_with_swap_for_test(&t.0, &config, || {
            std::fs::remove_dir(t.0.join("rootfs")).expect("remove");
            std::os::unix::fs::symlink("/", t.0.join("rootfs")).expect("symlink");
        })
        .expect_err("swapped");
        assert_eq!(err.error().code(), ErrorCode::PermissionDenied);
        assert_eq!(
            err.violation(),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );

        // 検証前に不在なら `check_rootfs` で拒否され、違反は運ばない。
        std::fs::remove_file(t.0.join("rootfs")).expect("remove link");
        let err = pin_bundle_rootfs_audited(&t.0, &config).expect_err("missing");
        assert_eq!(err.error().code(), ErrorCode::NotFound);
        assert_eq!(err.violation(), None);
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

    /// SEC-4・ESC-06・#2004: テスト用の記録先。`fail` なら常に `Err`。`pid` は spawn 済みの子。
    #[cfg(target_os = "linux")]
    fn audit_wrap(
        pid: u32,
        fail: bool,
    ) -> (
        ContainerChildProcess,
        Arc<crate::audit_log::mount::tests::VecSink>,
        u32,
    ) {
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(fail));
        let process =
            ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                .expect("wrap")
                .with_exit_audit(sink.clone(), ContainerId::new("c1").expect("id"));
        (process, sink, pid)
    }

    /// `sh -c <script>` の子を起動して `audit_wrap` で包む（SIGSYS を使わない試験用）。
    #[cfg(target_os = "linux")]
    fn exit_audit_process(
        script: &str,
        fail: bool,
    ) -> (
        ContainerChildProcess,
        Arc<crate::audit_log::mount::tests::VecSink>,
        u32,
    ) {
        #[allow(clippy::zombie_processes)]
        let pid = std::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
            .id();
        audit_wrap(pid, fail)
    }

    /// 子側の目印。立っているとき、試験は本体を実行せず `become_sigsys_child` へ入る（#2538）。
    #[cfg(target_os = "linux")]
    const SIGSYS_CHILD_MARK: &str = "FANDHE_TEST_SIGSYS_CHILD";

    /// SIGSYS で死ぬ子の本体（自テストバイナリの再実行先）。non-dumpable にしてから自分へ SIGSYS を送る。
    ///
    /// SIGSYS の既定動作は core dump で、`core_pattern` が apport 等のパイプだと RLIMIT_CORE=0 でも
    /// カーネルが helper の終了まで子を回収可能にしない。helper は直列に処理されるため、並列の試験が
    /// 重なると `wait(10s)` が `None` で期限切れになった（#2538）。non-dumpable なら core を作らず、
    /// 即座に `Signaled(31)` になる。`sh` では `execve` が dumpable を戻すので自バイナリで行う。
    /// 終了コード: 71 = non-dumpable にできない・72 = SIGSYS を送れない・73 = SIGSYS の後も生きていた。
    /// 親は `Signaled(31)` を期待するので、いずれも親の照合で検出される。
    #[cfg(target_os = "linux")]
    fn become_sigsys_child() -> ! {
        if crate::sys::set_non_dumpable().is_err() {
            std::process::exit(71);
        }
        let sig = std::num::NonZeroU8::new(31).map(crate::sys::Signal::Number);
        let Some(sig) = sig else {
            std::process::exit(72)
        };
        if crate::sys::kill_pid(std::process::id(), sig).is_err() {
            std::process::exit(72);
        }
        std::thread::sleep(Duration::from_secs(30));
        std::process::exit(73);
    }

    /// 自テストバイナリを `test_name`（`--exact` の完全名）で再実行し、SIGSYS で死ぬ子として包む（#2538）。
    /// 名前を誤ると子は 0 件実行で `Exited(0)` になり、`Signaled(31)` の照合が落ちる（fail-closed）。
    #[cfg(target_os = "linux")]
    fn sigsys_exit_audit_process(
        test_name: &str,
        fail: bool,
    ) -> (
        ContainerChildProcess,
        Arc<crate::audit_log::mount::tests::VecSink>,
        u32,
    ) {
        #[allow(clippy::zombie_processes)]
        let pid = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", test_name, "--test-threads=1", "--quiet"])
            .env(SIGSYS_CHILD_MARK, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
            .id();
        audit_wrap(pid, fail)
    }

    /// 期限切れ時の診断用に `/proc/<pid>/status` の `State`・`CoreDumping` 行を返す（REPAIR-4）。
    #[cfg(target_os = "linux")]
    fn proc_status_excerpt(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map(|s| {
                s.lines()
                    .filter(|l| l.starts_with("State:") || l.starts_with("CoreDumping:"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_else(|_| "<unavailable>".to_string())
    }

    /// SEC-4・ESC-06・#2004: SIGSYS 終了を回収すると `exit_signal` が 1 件出る。seccomp を経ない
    /// （自己 SIGSYS）ので syscall・arch は持たない（終了シグナルから syscall を推測しない）。
    /// `wait` の再呼び出しや `terminate` でも件数は 1 のまま。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2004_sigsys_exit_records_exit_signal_once_without_syscall() {
        if std::env::var_os(SIGSYS_CHILD_MARK).is_some() {
            become_sigsys_child();
        }
        let (process, sink, pid) = sigsys_exit_audit_process(
            "oci_runtime::launch::tests::sec4_2004_sigsys_exit_records_exit_signal_once_without_syscall",
            false,
        );
        let t = Duration::from_secs(10);
        assert_eq!(
            process.wait(t).expect("wait"),
            Some(ProcessExit::Signaled(31)),
            "{}",
            proc_status_excerpt(pid)
        );
        assert_eq!(
            process.wait(Duration::ZERO).expect("wait again"),
            Some(ProcessExit::Signaled(31))
        );
        process.terminate(t).expect("terminate after reap");
        let records = sink.snapshot();
        assert_eq!(records.len(), 1);
        let r = records.first().expect("record");
        assert_eq!(r.layer().as_str(), "exit_signal");
        assert_eq!(r.exit_signal().map(|s| s.get()), Some(31));
        assert_eq!(r.target_pid().map(|p| p.get()), Some(pid));
        assert_eq!(r.container_id().map(ContainerId::as_str), Some("c1"));
        assert_eq!(r.syscall(), None);
        assert_eq!(r.seccomp_arch(), None);
    }

    /// SEC-4・REPAIR-5・#2236: 複数スレッドが同時に `wait` を呼び、続けて `terminate` を呼んでも、SIGSYS 終了の記録は 1 件だけ
    /// （回収点は supervisor の複数スレッドから呼ばれる）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2236_concurrent_reap_points_record_exit_signal_once() {
        if std::env::var_os(SIGSYS_CHILD_MARK).is_some() {
            become_sigsys_child();
        }
        let (process, sink, _) = sigsys_exit_audit_process(
            "oci_runtime::launch::tests::sec4_2236_concurrent_reap_points_record_exit_signal_once",
            false,
        );
        let t = Duration::from_secs(10);
        std::thread::scope(|s| {
            for _ in 0..4 {
                let p = &process;
                s.spawn(move || {
                    let _ = p.wait(t);
                });
            }
        });
        // SIGSYS が先に確定した後の terminate も数えない（terminate が先に SIGKILL を送る競合を避けるため後段）。
        let _ = process.terminate(t);
        assert_eq!(sink.snapshot().len(), 1);
    }

    /// SEC-4・#2004: SIGSYS 以外の終了（SIGKILL・通常終了）では記録しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2004_other_exits_record_nothing() {
        let t = Duration::from_secs(10);
        let (killed, sink, _) = exit_audit_process("exec sleep 30", false);
        killed.terminate(t).expect("terminate");
        assert_eq!(
            killed.wait(t).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert!(sink.snapshot().is_empty());
        let (exited, sink, _) = exit_audit_process("exit 0", false);
        assert_eq!(exited.wait(t).expect("wait"), Some(ProcessExit::Exited(0)));
        assert!(sink.snapshot().is_empty());
    }

    /// SEC-4・#2004: sink が `Err` でも終了状態は変わらない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2004_sink_failure_does_not_change_exit() {
        if std::env::var_os(SIGSYS_CHILD_MARK).is_some() {
            become_sigsys_child();
        }
        let (process, _sink, pid) = sigsys_exit_audit_process(
            "oci_runtime::launch::tests::sec4_2004_sink_failure_does_not_change_exit",
            true,
        );
        assert_eq!(
            process.wait(Duration::from_secs(10)).expect("wait"),
            Some(ProcessExit::Signaled(31)),
            "{}",
            proc_status_excerpt(pid)
        );
    }
}
