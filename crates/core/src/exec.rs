//! 実行層の最小実行フロー（CORE-1・TASK-27・MS-2）を担うモジュール。
//!
//! 現状は先頭段の namespace 分離（[`isolate`]・[`mount_proc`]。#134・TASK-27.2）のみ実装済み。
//! `pivot_root`・fork / exec 等の後続段は未実装で、後続の sub-issue
//! （#135・#136・#137・#831〜#834）が本モジュールへ追記する（REPAIR-3: 実装済みを装わない）。
//!
//! # 目指すフロー（Linux 専用）
//!
//! 1. namespace 分離（PID / mount / UTS / IPC / user。#134・TASK-27.2。**実装済み**）
//! 2. `pivot_root` による rootfs 切替と旧 root の後始末（#135・TASK-27.3。未実装）
//! 3. 基本デバイスノード 6 種の作成（#834・TASK-27.6。実体は別モジュール `devices` の予定）
//! 4. 順序固定のステージ列: cgroup 参加 → capability 削減 → `PR_SET_NO_NEW_PRIVS`
//!    → Landlock → seccomp（#136・#832・#833。後続の TASK-32・37・38・39・40 が差し込む）。
//!    `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提で、
//!    後続実装はこの順序を崩さない
//! 5. `fork` / `exec`（#831・TASK-27.4。未実装）
//!
//! # 前提・契約
//!
//! - 本モジュールは `#[cfg(target_os = "linux")]` でモジュールごとビルド対象から外れる。
//!   macOS / Windows ではコンテナはゲスト VM（Linux）内で実行されるため、ホスト側から
//!   直接呼ぶ経路は存在しない（非 Linux ビルドの確認は #137・TASK-27.5）
//! - syscall を呼ぶ `unsafe` は `crate::sys` に閉じ込め、本ファイルには置かない
//! - 呼び出し元は TASK-29 の `oci_runtime`（`create` / `start`）および fork 段（#831）を想定する
//! - 常駐デーモンを前提にしない（CORE-1・D-19）
//! - 分離違反の試行を拒否したエラーは `ExecError::violation` に構造化された違反記録
//!   （[`IsolationViolation`]: 種別・理由コード・ビヘイビア ID・対象）を持つ。**記録の経路のみ**で、
//!   保存・集約・出力先は TASK-41（#191。SEC-4）が担う。システムエラーには付かない
//!
//! # namespace 分離の契約（[`isolate`]・[`isolate_rootful_host_root`]）
//!
//! - 分離は検証済みの計画を型で受け取る。既定は [`plan`] → [`isolate`]（user namespace 必須・
//!   非 root 起動。SEC-5）。ホスト root のまま動く rootful 分離は [`plan_rootful_host_root`] →
//!   [`isolate_rootful_host_root`] という別経路で、計画の型（[`IsolationPlan`] /
//!   [`RootfulHostRootPlan`]）が異なるため既定経路が rootful へ暗黙に落ちることはない
//! - シングルスレッドのプロセスから呼ぶこと（マルチスレッドからの `CLONE_NEWUSER` は
//!   `EINVAL` になり、`FailedPrecondition` で返す）
//! - `unshare(CLONE_NEWPID)` は呼び出し元自身を移動させず、**次に生成する子が PID 1** になる。
//!   その PID 1 側で [`MountIsolation::establish`]（PID 1・入れ子の PID namespace の実行時
//!   検証と、PID 1 自身による新しい mount namespace の作成）を通し、[`mount_proc`] を呼んで
//!   初めて `/proc` からホストのプロセスが見えなくなる。証跡は呼び出し側の申告に依存しない
//!   （fail-closed）
//! - 途中で失敗しても namespace を元へ戻す手段はない。呼び出し元はそのプロセスを破棄する
//!   （長寿命のホストプロセスで呼ばない）
//! - user namespace は自 euid / egid を コンテナ内 0 へ写す単一 ID 写像のみ提供する。
//!   euid 0 での自 ID 写像はコンテナ root がホスト root に写るため拒否する（SEC-5）。
//!   subuid 範囲の写像は TASK-40（CORE-6）が担う

use std::ffi::{CString, OsStr};
use std::fmt;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;

mod violation;

pub use violation::{
    IsolationViolation, VIOLATION_SUBJECT_MAX_CHARS, ViolationKind, ViolationReason,
    ViolationSubject,
};

/// 分離対象の namespace 種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Namespace {
    /// PID namespace（次に生成する子が PID 1 になる）。
    Pid,
    /// mount namespace。
    Mount,
    /// UTS namespace（hostname）。
    Uts,
    /// IPC namespace。
    Ipc,
    /// user namespace。
    User,
}

impl Namespace {
    const ALL: [Namespace; 5] = [
        Namespace::Pid,
        Namespace::Mount,
        Namespace::Uts,
        Namespace::Ipc,
        Namespace::User,
    ];

    fn flag(self) -> NsFlag {
        match self {
            Self::Pid => NsFlag::Pid,
            Self::Mount => NsFlag::Mount,
            Self::Uts => NsFlag::Uts,
            Self::Ipc => NsFlag::Ipc,
            Self::User => NsFlag::User,
        }
    }

    fn index(self) -> u8 {
        match self {
            Self::Pid => 0,
            Self::Mount => 1,
            Self::Uts => 2,
            Self::Ipc => 3,
            Self::User => 4,
        }
    }
}

/// [`Namespace`] の集合（生のビット値は公開しない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NamespaceSet(u8);

impl NamespaceSet {
    /// 空集合。
    pub fn empty() -> Self {
        Self(0)
    }

    /// 5 種すべて。
    pub fn all() -> Self {
        Namespace::ALL
            .iter()
            .fold(Self::empty(), |s, ns| s.with(*ns))
    }

    /// `ns` を加えた集合を返す。
    pub fn with(mut self, ns: Namespace) -> Self {
        self.0 |= 1 << ns.index();
        self
    }

    /// `ns` を含むか。
    pub fn contains(&self, ns: Namespace) -> bool {
        self.0 & (1 << ns.index()) != 0
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn flags(&self) -> Vec<NsFlag> {
        Namespace::ALL
            .iter()
            .filter(|ns| self.contains(**ns))
            .map(|ns| ns.flag())
            .collect()
    }
}

/// `HOST_NAME_MAX`（Linux は 64 バイト）。
const HOSTNAME_MAX_LEN: usize = 64;
/// DNS ラベル長の上限。
const HOSTNAME_LABEL_MAX_LEN: usize = 63;

/// 検証済みの hostname。外部入力（将来の OCI `config.json`）由来を想定し、生成は
/// [`Hostname::new`] のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(String);

impl Hostname {
    /// 検証して作る。拒否条件（`InvalidArgument`）: 空・64 バイト超・`[A-Za-z0-9-.]` 以外
    /// （NUL 含む）・空ラベル・63 バイト超ラベル・先頭 / 末尾ハイフンのラベル。
    pub fn new(value: impl Into<String>) -> Result<Self, ExecError> {
        let value = value.into();
        let bad = |msg: &str| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                format!("invalid hostname: {msg}"),
            )
        };
        if value.is_empty() {
            return Err(bad("must not be empty"));
        }
        if value.len() > HOSTNAME_MAX_LEN {
            return Err(bad("must be at most 64 bytes"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(bad("must match [A-Za-z0-9-.]"));
        }
        for label in value.split('.') {
            if label.is_empty() || label.len() > HOSTNAME_LABEL_MAX_LEN {
                return Err(bad("labels must be 1 to 63 bytes"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(bad("labels must not start or end with '-'"));
            }
        }
        Ok(Self(value))
    }

    /// 検証済み文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `uid_map` / `gid_map` の 1 行（`container_id host_id count`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapping {
    /// コンテナ内の先頭 ID。
    pub container_id: u32,
    /// ホスト側の先頭 ID。
    pub host_id: u32,
    /// 写像する ID 数。
    pub count: u32,
}

impl IdMapping {
    /// カーネルが受け付ける書式（改行終端の 1 行）。
    pub fn to_map_line(&self) -> String {
        format!("{} {} {}\n", self.container_id, self.host_id, self.count)
    }

    /// 自 ID をコンテナ内 0 へ写す単一 ID 写像。
    fn single(host_id: u32) -> Self {
        Self {
            container_id: 0,
            host_id,
            count: 1,
        }
    }
}

/// 分離の設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationConfig {
    /// 分離する namespace。
    pub namespaces: NamespaceSet,
    /// コンテナの hostname（指定時は `Uts` が必須）。
    pub hostname: Option<Hostname>,
}

/// 失敗した段（ERR-1 の機械可読な文脈）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationStage {
    /// 設定・前提の検証。
    Validate,
    /// `unshare(2)`。
    Unshare,
    /// `/proc/self/setgroups` への `deny` 書き込み。
    SetGroups,
    /// `/proc/self/uid_map` への書き込み。
    UidMap,
    /// `/proc/self/gid_map` への書き込み。
    GidMap,
    /// `/` の propagation を private にする `mount(2)`。
    MountPrivate,
    /// `sethostname(2)`。
    SetHostname,
    /// procfs のマウント。
    MountProc,
}

/// 実行層の構造化エラー（`code` は `traits::types::ErrorCode` を再利用）。
///
/// 分離違反の試行を拒否した場合は `violation` に構造化された違反記録が入り、システム
/// エラー（syscall 失敗・procfs の読み取り失敗等）では `None`。区別の定義と、記録の保存が
/// 未実装（TASK-41・#191）であることは [`IsolationViolation`] のモジュール doc を参照（SEC-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecError {
    /// 機械可読な分類。
    pub code: ErrorCode,
    /// 失敗した段。
    pub stage: IsolationStage,
    /// 英語のメッセージ。
    pub message: String,
    /// 分離違反の記録（違反による拒否のときだけ `Some`）。
    pub violation: Option<IsolationViolation>,
}

impl ExecError {
    /// 違反ではない失敗（システムエラー・入力書式エラー）を作る。
    fn new(code: ErrorCode, stage: IsolationStage, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            violation: None,
        }
    }

    /// 分離違反の拒否を作る。`code`・`stage`・`message` は理由から決まり、`subject` は
    /// 呼び出し側が渡したパス（パス検証の拒否のときだけ）。
    fn from_violation(reason: ViolationReason, subject: Option<&Path>) -> Self {
        Self {
            code: reason.error_code(),
            stage: reason.stage(),
            message: reason.message().to_string(),
            violation: Some(IsolationViolation::new(reason, subject)),
        }
    }

    fn from_sys(err: SysError, stage: IsolationStage, what: &str) -> Self {
        let code = errno_to_code(err);
        Self::new(code, stage, format!("{what} failed: {}", describe(err)))
    }

    fn from_io(err: &std::io::Error, stage: IsolationStage, what: &str) -> Self {
        let sys_err = SysError::Os(err.raw_os_error().unwrap_or(0));
        let code = errno_to_code(sys_err);
        Self::new(code, stage, format!("{what} failed: {err}"))
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:?}: {}",
            self.code.as_str(),
            self.stage,
            self.message
        )?;
        if let Some(v) = &self.violation {
            write!(
                f,
                " (violation: {}/{}, {})",
                v.kind.as_str(),
                v.reason.as_str(),
                v.behavior_id
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ExecError {}

fn describe(err: SysError) -> String {
    match err {
        SysError::Unsupported => "unsupported target architecture".to_string(),
        SysError::Os(errno) => std::io::Error::from_raw_os_error(errno).to_string(),
    }
}

/// errno を `ErrorCode` に写す。`EPERM`/`EACCES` → `PermissionDenied`、
/// `EINVAL`（例: マルチスレッドからの `CLONE_NEWUSER`）→ `FailedPrecondition`、
/// 対応外 arch → `Unimplemented`、その他 → `Internal`。
fn errno_to_code(err: SysError) -> ErrorCode {
    match err {
        SysError::Unsupported => ErrorCode::Unimplemented,
        SysError::Os(e) if e == sys::EPERM || e == sys::EACCES => ErrorCode::PermissionDenied,
        SysError::Os(e) if e == sys::EINVAL => ErrorCode::FailedPrecondition,
        SysError::Os(_) => ErrorCode::Internal,
    }
}

/// 分離がどの権限モデルで行われたか（[`IsolationReport::privilege`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationPrivilege {
    /// 既定経路（[`isolate`]）。非 root の自 ID をコンテナ内 0 へ写す user namespace 付き。
    RootlessSingleId,
    /// rootful 経路（[`isolate_rootful_host_root`]）。user namespace なしでホスト root 権限を
    /// 保ったまま分離した。
    RootfulHostRoot,
}

/// [`isolate`] / [`isolate_rootful_host_root`] の成功結果（将来拡張できる構造化された戻り値）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationReport {
    /// どの権限モデルで分離したか。
    pub privilege: IsolationPrivilege,
    /// 分離した namespace。
    pub namespaces: NamespaceSet,
    /// 設定した hostname。
    pub hostname: Option<Hostname>,
    /// 書き込んだ uid 写像（`User` を含む場合のみ）。
    pub uid_mapping: Option<IdMapping>,
    /// 書き込んだ gid 写像（`User` を含む場合のみ）。
    pub gid_mapping: Option<IdMapping>,
}

/// [`mount_proc`] を呼べる状態（新しい PID namespace の PID 1 で、そのスレッドだけが属する
/// 新しい mount namespace にいる）を、PID 1 自身が作って確かめた証跡（CORE-1）。前提を
/// 満たさない呼び出しは fail-closed で拒否する。拒否の監査ログ記録（SEC-4）は未実装（REPAIR-3）。
///
/// 生成は [`MountIsolation::establish`] のみで、呼び出し側の申告では作れない。証跡は作成時の
/// mount namespace・PID namespace に束縛され、[`mount_proc`] は呼び出し直前に「PID 1 である
/// こと」「呼び出しスレッドの両 namespace が証跡と一致すること」を再検証する。
///
/// 持ち出し対策として `Clone` を実装せず、`!Send` にしている（mount namespace は
/// `unshare(CLONE_NEWNS)` を呼んだスレッドだけが移るため、別スレッドへ渡すと前提が崩れる）。
/// 別スレッドへは渡せない:
///
/// 下の `compile_fail` doctest は「コンパイルに失敗すること」しか確かめないため、`!Send` 以外の
/// 理由（名前の誤り・モジュールが無い等）のエラーでも通ってしまう。また `exec` モジュールは
/// Linux 限定のため、非 Linux では型が存在せず常に失敗し、この doctest は常に通る
/// （`!Send` の実質的な確認は Linux のみ）。
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<fandhe_container_core::exec::MountIsolation>();
/// ```
///
/// procfs を再マウントした後は `/proc/thread-self` が新しい procfs を指すが、namespace の
/// 識別子（`mnt:[inode]` 等）は procfs に依存しないため、再マウントを繰り返す呼び出し側
/// （#135 の `pivot_root` 後等）は同じ証跡を使い回せる。
#[derive(Debug, PartialEq, Eq)]
pub struct MountIsolation {
    /// 作成した mount namespace（`/proc/thread-self/ns/mnt` のリンク先 `mnt:[inode]`）。
    mnt_ns: String,
    /// 作成時の PID namespace（`/proc/thread-self/ns/pid`）。procfs はマウントした
    /// プロセス自身の PID namespace（`ns/pid`）を映すため、子向けの `pid_for_children`
    /// ではなくこちらを束縛する。
    pid_ns: String,
    /// `!Send`・`!Sync` にするための印（生ポインタは Send / Sync でない）。
    _not_send: std::marker::PhantomData<*const ()>,
}

/// `/proc/self/status` の `NSpid:` 行の要素数（PID namespace の入れ子段数）。
fn nspid_depth(status: &str) -> Option<usize> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .map(|rest| rest.split_whitespace().count())
}

/// `/proc/self/status` の `NSpid:` 行の末尾要素（最も内側の PID namespace での PID）。
fn nspid_innermost(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .and_then(|rest| rest.split_whitespace().last())
        .and_then(|v| v.parse().ok())
}

/// `/proc/self/status` の `Threads:` 行（スレッドグループのスレッド数）。
fn status_threads(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

/// [`MountIsolation::establish`] の前提（副作用の前に判定するテスト可能な純関数）。
/// `pid` は `getpid()`、`status` は `/proc/self/status` の内容。
///
/// - PID が 1 で、`NSpid` の末尾要素も 1、かつ `NSpid` が 2 段以上（ホスト側 procfs 越しに
///   見て入れ子の PID namespace の PID 1）
/// - `Threads:` が 1（シングルスレッド）。`unshare(CLONE_NEWNS)` は呼んだスレッドだけを移すため、
///   他のスレッドが古い mount namespace に残り、後続の `pivot_root`・exec（#135・#831）が別
///   スレッドで行われるとホストの procfs・ファイルシステムが見えてしまう
fn check_establish_preconditions(pid: u32, status: &str) -> Result<(), ViolationReason> {
    if pid != 1 {
        return Err(ViolationReason::EstablishNotPid1);
    }
    if nspid_innermost(status) != Some(1) {
        return Err(ViolationReason::EstablishNspidNotPid1);
    }
    if nspid_depth(status).is_none_or(|d| d < 2) {
        return Err(ViolationReason::EstablishNotNestedPidNamespace);
    }
    if status_threads(status) != Some(1) {
        return Err(ViolationReason::EstablishMultiThreaded);
    }
    Ok(())
}

/// 呼び出しスレッドの namespace リンク（`/proc/thread-self/ns/<kind>`）を読む。
///
/// `unshare(CLONE_NEWNS)` はマルチスレッドのプロセスでは呼んだスレッドだけを移すため、
/// スレッドグループの代表を指す `/proc/self` ではなく `/proc/thread-self` を使う。
fn thread_ns_link(kind: &str) -> std::io::Result<String> {
    std::fs::read_link(Path::new("/proc/thread-self/ns").join(kind))
        .map(|l| l.to_string_lossy().into_owned())
}

/// [`MountIsolation::establish`] の mount namespace 判定（テスト可能な純関数）。
/// `unshare(CLONE_NEWNS)` の前後でリンク先が変わっていなければ拒否する。
fn check_fresh_mount_ns(before: &str, after: &str) -> Result<(), ViolationReason> {
    if before == after {
        return Err(ViolationReason::EstablishMountNamespaceNotFresh);
    }
    Ok(())
}

/// [`mount_proc`] 直前の証跡の再検証（テスト可能な純関数）。`pid` は `getpid()`、
/// `mnt_ns` / `pid_ns` は呼び出しスレッドの現在のリンク先。
fn check_evidence(
    evidence: &MountIsolation,
    pid: u32,
    mnt_ns: &str,
    pid_ns: &str,
) -> Result<(), ViolationReason> {
    if pid != 1 {
        return Err(ViolationReason::EvidenceCallerNotPid1);
    }
    if mnt_ns != evidence.mnt_ns {
        return Err(ViolationReason::EvidenceMountNamespaceMismatch);
    }
    if pid_ns != evidence.pid_ns {
        return Err(ViolationReason::EvidencePidNamespaceMismatch);
    }
    Ok(())
}

impl MountIsolation {
    /// 新しい PID namespace の PID 1 が、自分だけの mount namespace を作って証跡を得る。
    ///
    /// 手順（前提検証はすべて副作用の前に行う）:
    ///
    /// 1. PID が 1（`getpid()` と `NSpid` の末尾要素の両方）で、`NSpid` が 2 段以上、かつ
    ///    シングルスレッド（`Threads: 1`）。満たさなければ副作用なしで `FailedPrecondition`
    ///    （判定は [`check_establish_preconditions`]）
    /// 2. 呼び出しスレッドを `unshare(CLONE_NEWNS)` で新しい mount namespace へ移し、`/` を
    ///    再帰 private にする（コピーされたマウントの shared peer から切り離し、以後のマウントを
    ///    外へ伝播させない）
    /// 3. `unshare` の前後で `/proc/thread-self/ns/mnt` が変わったことを確かめ、作成直後の
    ///    mount namespace と PID namespace を証跡に記録する
    ///
    /// この mount namespace の所属は作成直後は呼び出しスレッドだけであり、他プロセスとの
    /// 共有がないことを他プロセスの情報（`/proc/1/ns/mnt` 等）を読まずに自分で保証する。
    /// rootless でも user namespace 内の CAP_SYS_ADMIN で実行でき、比較を省く分岐は持たない。
    ///
    /// 手順 2 以降の失敗は namespace を戻せない（モジュール doc の「失敗時はプロセスを破棄」の
    /// 契約に従う）。
    ///
    /// **同一スレッドの契約**: 返った証跡は同じスレッドで [`mount_proc`] に渡し、以後の
    /// `pivot_root`（#135）・exec（#831）も同じスレッドで行う。新しい mount namespace に
    /// 移るのは呼んだスレッドだけのため、前提としてシングルスレッドであることを確かめている
    /// （establish 後に作ったスレッドは新しい mount namespace を引き継ぐ）。
    pub fn establish() -> Result<Self, ExecError> {
        let fail = |msg: &str| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountProc,
                msg,
            )
        };
        let violation = |r: ViolationReason| ExecError::from_violation(r, None);
        let pid = std::process::id();
        if pid != 1 {
            // /proc を読む前に拒否する（PID 1 でないことは getpid だけで確定する）。
            return Err(violation(ViolationReason::EstablishNotPid1));
        }
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| fail("cannot read /proc/self/status to verify the PID namespace"))?;
        check_establish_preconditions(pid, &status).map_err(violation)?;
        let before =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        sys::unshare_namespaces(&[NsFlag::Mount])
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Unshare, "unshare(CLONE_NEWNS)"))?;
        sys::mount_root_private_recursive().map_err(|e| {
            ExecError::from_sys(e, IsolationStage::MountPrivate, "mount(MS_PRIVATE)")
        })?;
        let mnt_ns =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        check_fresh_mount_ns(&before, &mnt_ns).map_err(violation)?;
        let pid_ns =
            thread_ns_link("pid").map_err(|_| fail("cannot read /proc/thread-self/ns/pid"))?;
        Ok(Self {
            mnt_ns,
            pid_ns,
            _not_send: std::marker::PhantomData,
        })
    }

    /// 呼び出し元の現在の状態（PID・スレッドの mount / PID namespace）が証跡と一致するか。
    fn verify_caller(&self) -> Result<(), ExecError> {
        let fail = |msg: &str| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountProc,
                msg,
            )
        };
        let mnt_ns =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        let pid_ns =
            thread_ns_link("pid").map_err(|_| fail("cannot read /proc/thread-self/ns/pid"))?;
        check_evidence(self, std::process::id(), &mnt_ns, &pid_ns)
            .map_err(|r| ExecError::from_violation(r, None))?;
        // getpid に加え、procfs 側の NSpid 末尾も 1 であることを確かめる（procfs を再マウント
        // した後も NSpid の末尾は最も内側の namespace の PID）。
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| fail("cannot read /proc/self/status to verify the PID"))?;
        if nspid_innermost(&status) != Some(1) {
            return Err(ExecError::from_violation(
                ViolationReason::EvidenceNspidNotPid1,
                None,
            ));
        }
        Ok(())
    }
}

/// 既定経路（rootless）の検証済み計画。[`plan`] だけが作り、[`isolate`] だけが受け取る。
///
/// user namespace を必ず含み、非 root の自 euid / egid をコンテナ内 0 へ写す単一 ID 写像を
/// 持つ（SEC-5。subuid 範囲の写像は TASK-40・#186 で扱う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPlan {
    namespaces: NamespaceSet,
    hostname: Option<Hostname>,
    uid_mapping: IdMapping,
    gid_mapping: IdMapping,
}

/// rootful 経路の検証済み計画。[`plan_rootful_host_root`] だけが作り、
/// [`isolate_rootful_host_root`] だけが受け取る。
///
/// **権限条件**: sudo 等で euid 0 として起動し、user namespace を作らずに**ホストの root 権限を
/// 保ったまま**分離する。コンテナ内 root はホスト root そのものであり、SEC-5（非 root 起動時に
/// コンテナ内 root をホストの非特権 UID へ写す）の保護は受けない。
///
/// **用途**: CORE-7・CORE-9 の rootful 分離（spec 上、dev-box02 の PoC-14・15・17 で実機実証済みの
/// 構成）。root 起動でもコンテナ内 root を非特権 UID へ写す構成は TASK-40（#186）の subuid 写像で
/// 既定経路に加える予定で、それまでの暫定経路ではなく明示的に選ぶ別経路として分けている。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfulHostRootPlan {
    namespaces: NamespaceSet,
    hostname: Option<Hostname>,
}

/// 既定・rootful に共通する設定の検証（副作用なしの純関数）。
///
/// - namespace が空、または hostname 指定なのに `Uts` が無い場合は `InvalidArgument`
///   （ホストの hostname を書き換える経路を作らない）
/// - `Pid` を含み `Mount` を含まない場合は `InvalidArgument`（PID 1 が外側と mount
///   namespace を共有した状態から始まる構成を作らない。[`MountIsolation::establish`] が
///   PID 1 自身で mount namespace を分けることとの二重の防御）
fn validate_common(config: &IsolationConfig) -> Result<(), ExecError> {
    let violation = |r: ViolationReason| Err(ExecError::from_violation(r, None));
    if config.namespaces.is_empty() {
        return violation(ViolationReason::NoNamespaces);
    }
    if config.hostname.is_some() && !config.namespaces.contains(Namespace::Uts) {
        return violation(ViolationReason::HostnameWithoutUts);
    }
    if config.namespaces.contains(Namespace::Pid) && !config.namespaces.contains(Namespace::Mount) {
        return violation(ViolationReason::PidWithoutMount);
    }
    Ok(())
}

/// [`plan`] の本体（euid / egid を引数に取りテスト可能にした純関数）。
fn plan_for(config: &IsolationConfig, euid: u32, egid: u32) -> Result<IsolationPlan, ExecError> {
    validate_common(config)?;
    if !config.namespaces.contains(Namespace::User) {
        return Err(ExecError::from_violation(
            ViolationReason::UserNamespaceRequired,
            None,
        ));
    }
    if euid == 0 || egid == 0 {
        return Err(ExecError::from_violation(
            ViolationReason::HostRootIdentityMapping,
            None,
        ));
    }
    Ok(IsolationPlan {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
        uid_mapping: IdMapping::single(euid),
        gid_mapping: IdMapping::single(egid),
    })
}

/// [`plan_rootful_host_root`] の本体（euid を引数に取りテスト可能にした純関数）。
fn plan_rootful_for(config: &IsolationConfig, euid: u32) -> Result<RootfulHostRootPlan, ExecError> {
    validate_common(config)?;
    if config.namespaces.contains(Namespace::User) {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulWithUserNamespace,
            None,
        ));
    }
    if euid != 0 {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulRequiresRoot,
            None,
        ));
    }
    Ok(RootfulHostRootPlan {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
    })
}

/// 既定経路の計画を作る（副作用なし）。拒否条件は共通検証（空・hostname に Uts なし・Pid に
/// Mount なし）に加え、`User` を含まない場合は `InvalidArgument`、euid / egid が 0 の場合は
/// `FailedPrecondition`（SEC-5）。
pub fn plan(config: &IsolationConfig) -> Result<IsolationPlan, ExecError> {
    plan_for(config, sys::effective_uid(), sys::effective_gid())
}

/// rootful 経路の計画を作る（副作用なし）。用途と権限条件は [`RootfulHostRootPlan`] を参照。
/// 共通検証に加え、`User` を含む場合は `InvalidArgument`、euid が 0 でない場合は
/// `FailedPrecondition`。
pub fn plan_rootful_host_root(config: &IsolationConfig) -> Result<RootfulHostRootPlan, ExecError> {
    plan_rootful_for(config, sys::effective_uid())
}

/// `/proc/self/<name>` へ内容を 1 回の write で書く（カーネルは map を 1 回しか受け付けない）。
fn write_proc_self(name: &str, content: &str, stage: IsolationStage) -> Result<(), ExecError> {
    let path = Path::new("/proc/self").join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| ExecError::from_io(&e, stage, name))?;
    file.write_all(content.as_bytes())
        .map_err(|e| ExecError::from_io(&e, stage, name))
}

/// 既定経路の計画に従い、呼び出しプロセスを namespace 分離する（CORE-1・SEC-5）。
///
/// 処理順: 実行 ID の再検証 → `unshare` を全フラグで 1 回 → `setgroups` deny・`uid_map`・
/// `gid_map` → （`Mount`）`/` を再帰 private 化 → （`Uts` かつ hostname）`sethostname`。
/// 契約はモジュール doc（シングルスレッド・PID 1 は次の子・失敗時はプロセス破棄）を参照。
pub fn isolate(plan: &IsolationPlan) -> Result<IsolationReport, ExecError> {
    // unshare 後の euid / egid は overflow id になるため、先に取得する。計画作成後に
    // setuid 等で ID が変わっていれば写像がずれるため、副作用の前に拒否する。
    let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
    if euid != plan.uid_mapping.host_id || egid != plan.gid_mapping.host_id {
        return Err(ExecError::from_violation(
            ViolationReason::IdentityChanged,
            None,
        ));
    }
    unshare_and_configure(
        plan.namespaces,
        plan.hostname.as_ref(),
        Some((plan.uid_mapping, plan.gid_mapping)),
    )?;
    Ok(IsolationReport {
        privilege: IsolationPrivilege::RootlessSingleId,
        namespaces: plan.namespaces,
        hostname: plan.hostname.clone(),
        uid_mapping: Some(plan.uid_mapping),
        gid_mapping: Some(plan.gid_mapping),
    })
}

/// rootful 経路の計画に従い、ホスト root 権限を保ったまま namespace 分離する（CORE-1・
/// CORE-7・CORE-9）。用途と権限条件は [`RootfulHostRootPlan`] を参照。
///
/// 処理順: euid 0 の再検証 → `unshare` を全フラグで 1 回 → （`Mount`）`/` を再帰 private 化
/// → （`Uts` かつ hostname）`sethostname`。user namespace は作らない。
pub fn isolate_rootful_host_root(plan: &RootfulHostRootPlan) -> Result<IsolationReport, ExecError> {
    if sys::effective_uid() != 0 {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulRequiresRoot,
            None,
        ));
    }
    unshare_and_configure(plan.namespaces, plan.hostname.as_ref(), None)?;
    Ok(IsolationReport {
        privilege: IsolationPrivilege::RootfulHostRoot,
        namespaces: plan.namespaces,
        hostname: plan.hostname.clone(),
        uid_mapping: None,
        gid_mapping: None,
    })
}

/// 両経路に共通する副作用部（検証済みの計画からだけ呼ぶ）。
fn unshare_and_configure(
    namespaces: NamespaceSet,
    hostname: Option<&Hostname>,
    mappings: Option<(IdMapping, IdMapping)>,
) -> Result<(), ExecError> {
    sys::unshare_namespaces(&namespaces.flags())
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Unshare, "unshare"))?;

    if let Some((uid, gid)) = mappings {
        // 非特権の gid_map 書き込みには setgroups の deny が先に必要。
        write_proc_self("setgroups", "deny", IsolationStage::SetGroups)?;
        write_proc_self("uid_map", &uid.to_map_line(), IsolationStage::UidMap)?;
        write_proc_self("gid_map", &gid.to_map_line(), IsolationStage::GidMap)?;
    }

    if namespaces.contains(Namespace::Mount) {
        sys::mount_root_private_recursive().map_err(|e| {
            ExecError::from_sys(e, IsolationStage::MountPrivate, "mount(MS_PRIVATE)")
        })?;
    }

    if let Some(hostname) = hostname {
        sys::set_hostname(hostname.as_str().as_bytes())
            .map_err(|e| ExecError::from_sys(e, IsolationStage::SetHostname, "sethostname"))?;
    }
    Ok(())
}

/// `rootfs` 配下の `target` に procfs をマウントする。新しい PID namespace の PID 1 側で呼ぶ
/// （#135 の `pivot_root` 後の再マウントでも再利用する想定）。
///
/// マウント前に次をすべて検証し、1 つでも満たさなければ副作用なしで拒否する（fail-closed。
/// security.md「rootfs の外へ書き込める経路を作らない」）。
///
/// - 呼び出し側が [`MountIsolation::establish`] で得た証跡を提示し、呼び出し直前の状態が
///   証跡と一致する（PID 1 であること・呼び出しスレッドの mount / PID namespace が作成時と
///   同じこと）。証跡を受け取った親・PID 1 が fork した子・別スレッドからの呼び出しは拒否する
/// - `rootfs` 自体とその祖先に symlink がない（`canonicalize` した実パスが `rootfs` と一致）
/// - `rootfs` / `target` は絶対パスで NUL・`..` を含まず、`target` は `rootfs` より下の専用ディレクトリ
///   （`target == rootfs` は拒否）
/// - `/` から `target` までを `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` で 1 要素ずつ辿って
///   fd で固定し（[`open_dir_beneath`]）、マウントは `/proc/thread-self/fd/N` 経由で同じ実体に対して
///   行う（検証後の差し替え = TOCTOU の防止）。symlink・非ディレクトリ・不在の要素があれば
///   拒否する。O_PATH のため祖先に要るのは search（実行）権限だけで、user namespace 内から
///   読み取り不可・実行可のホスト側ディレクトリを辿れる
/// - 固定した fd が属するマウント（`/proc/thread-self/fdinfo/N` の `mnt_id`）の propagation が
///   `shared` でない（mount namespace 分離済みで `MS_PRIVATE` 化されていること。shared の
///   ままではマウントがホストへ伝播する）。パス文字列ではなく fd で判定し、検証と実マウント
///   の対象を一致させる
pub fn mount_proc(
    isolation: &MountIsolation,
    rootfs: &Path,
    target: &Path,
) -> Result<(), ExecError> {
    isolation.verify_caller()?;
    mount_proc_verified(rootfs, target)
}

/// [`mount_proc`] の証跡検証後の本体（パス検証 → fd 固定 → propagation 検査 → マウント）。
/// 証跡を取らないため、単体テストは証跡を偽造せずにパス検証を直接確かめられる（最終段の
/// `mount(2)` はテストビルドでは dry-run）。
fn mount_proc_verified(rootfs: &Path, target: &Path) -> Result<(), ExecError> {
    let violation = |r: ViolationReason, p: &Path| ExecError::from_violation(r, Some(p));
    for p in [rootfs, target] {
        if !p.is_absolute() {
            return Err(violation(ViolationReason::PathNotAbsolute, p));
        }
        if p.as_os_str().as_bytes().contains(&0) {
            return Err(violation(ViolationReason::PathContainsNul, p));
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(violation(ViolationReason::PathParentComponent, p));
        }
    }
    let rel = target
        .strip_prefix(rootfs)
        .map_err(|_| violation(ViolationReason::TargetOutsideRootfs, target))?;
    // rootfs 自体・祖先が symlink だとマウント先を誘導できるため、実パスとの一致を要求する。
    // 不在は違反（呼び出し側のパス誤り）、それ以外の失敗（権限不足等）はシステムエラー。
    // 正規化後の実パス（ホスト側の詳細）は違反記録・メッセージに含めない。
    let real_root = std::fs::canonicalize(rootfs).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            violation(ViolationReason::RootfsMissing, rootfs)
        } else {
            ExecError::from_io(&e, IsolationStage::MountProc, "canonicalize(rootfs)")
        }
    })?;
    if real_root.components().ne(rootfs.components()) {
        return Err(violation(ViolationReason::RootfsNotCanonical, rootfs));
    }
    // rootfs 自体をマウント先にすると rootfs 全体を procfs で覆えるため、専用の下位ディレクトリを要求する。
    let names: Vec<&OsStr> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return Err(violation(ViolationReason::TargetIsRootfs, target));
    }
    // `/` から rootfs・target まで 1 要素ずつ開き、検証した実体を fd で固定する
    // （検証後のパス差し替え = TOCTOU の防止）。以後の判定・マウントはこの fd 経由でのみ行う。
    let dir = open_dir_beneath(&real_root, &names)?;
    if mount_is_shared(&dir)? {
        return Err(violation(ViolationReason::TargetOnSharedMount, target));
    }
    // fd が指す実体へマウントする（`/proc/thread-self/fd/N` は fd の dentry へ解決される）。
    // `establish` は呼び出しスレッドだけを新しい mount namespace へ移すため、パス解決・
    // mountinfo の参照はスレッドグループの代表（`/proc/self`）ではなく呼び出しスレッドで行う。
    // 数値だけから組む文字列のため NUL は含まれ得ない（失敗は内部エラー扱い）。
    let c_target =
        CString::new(format!("/proc/thread-self/fd/{}", dir.as_raw_fd())).map_err(|_| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::MountProc,
                "failed to build the fd path of the proc mount target",
            )
        })?;
    mount_proc_syscall(&c_target)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::MountProc, "mount(proc)"))
}

/// [`mount_proc`] の最終段（`mount(2)`）。本番ビルドでは [`sys::mount_proc_at`] を呼ぶ。
#[cfg(not(test))]
fn mount_proc_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    sys::mount_proc_at(target)
}

/// テストビルドの dry-run 差し込み点。`mount(2)` を呼ばず、渡されたマウント先をスレッド
/// ローカルに記録するだけにする。単体テストは証跡の検証を経ない `mount_proc_verified` を
/// 直接呼ぶため、将来パス検証が後退しても root 実行のテストからホストへ `mount(2)` が
/// 届かないことを cfg で構造的に保証する。
#[cfg(test)]
fn mount_proc_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    tests::DRY_RUN_MOUNTS.with(|m| m.borrow_mut().push(target.to_string_lossy().into_owned()));
    Ok(())
}

/// `/` から `real_root`（symlink を含まない正規化済み絶対パス）の各要素、続けて `names` を
/// 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開き、最後の要素の fd を返す（副作用なし）。
///
/// [`mount_proc`] のマウント先固定に使う。各要素は直前の fd を起点に開くため、途中の要素を
/// symlink へ差し替えても辿る実体は変わらない。O_PATH は読み取り権限を要求しないため、
/// 実行権限のみの祖先（`CLONE_NEWUSER` 後のホスト所有ディレクトリ等）も辿れる。
/// 拒否は違反記録付きの `InvalidArgument`（symlink・非ディレクトリ・不在・NUL）。search 権限
/// 不足（`PermissionDenied`）等のその他の errno はシステムエラー（違反記録なし）。違反記録の
/// 対象は `real_root` と `names` を連結したパス（呼び出し側が渡したマウント先と同じ）。
fn open_dir_beneath(real_root: &Path, names: &[&OsStr]) -> Result<OwnedFd, ExecError> {
    let target = || names.iter().fold(real_root.to_path_buf(), |p, n| p.join(n));
    let violation = |r: ViolationReason| ExecError::from_violation(r, Some(&target()));
    let open_err = |e: SysError| match e {
        // O_DIRECTORY|O_NOFOLLOW では symlink も ENOTDIR になる。ELOOP は念のため残す。
        SysError::Os(sys::ELOOP) | SysError::Os(sys::ENOTDIR) => {
            violation(ViolationReason::PathSymlinkOrNotDirectory)
        }
        SysError::Os(sys::ENOENT) => violation(ViolationReason::PathMissing),
        other => ExecError::from_sys(other, IsolationStage::MountProc, "openat"),
    };
    let mut cur = sys::open_dir_path_nofollow(None, c"/").map_err(open_err)?;
    let root_names = real_root.components().filter_map(|c| match c {
        Component::Normal(n) => Some(n),
        _ => None,
    });
    for name in root_names.chain(names.iter().copied()) {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| violation(ViolationReason::PathContainsNul))?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c_name).map_err(open_err)?;
    }
    Ok(cur)
}

/// `/proc/thread-self/fdinfo/<fd>` の `mnt_id:` 行（fd が属するマウントの ID）を取り出す。
fn parse_fdinfo_mnt_id(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `dir` が属するマウントが shared propagation か判定する。fdinfo の `mnt_id` と
/// 呼び出しスレッドの `/proc/thread-self/mountinfo` の先頭フィールド（mount ID）を
/// 突き合わせる（`/proc/self/mountinfo` はスレッドグループの代表の mount namespace を映し、
/// `establish` 後の別スレッドでは一致しないため）。読み取り・解析
/// できない場合は安全側（エラー）に倒す。
fn mount_is_shared(dir: &OwnedFd) -> Result<bool, ExecError> {
    let fdinfo = std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", dir.as_raw_fd()))
        .map_err(|_| mountinfo_error("cannot read fdinfo of the proc mount target"))?;
    let mnt_id = parse_fdinfo_mnt_id(&fdinfo)
        .ok_or_else(|| mountinfo_error("no mnt_id in fdinfo of the proc mount target"))?;
    let info = std::fs::read_to_string("/proc/thread-self/mountinfo").map_err(|_| {
        mountinfo_error("cannot read /proc/thread-self/mountinfo to verify mount propagation")
    })?;
    mount_is_shared_in(&info, mnt_id)
}

fn mountinfo_error(msg: &str) -> ExecError {
    ExecError::new(
        ErrorCode::FailedPrecondition,
        IsolationStage::MountProc,
        msg,
    )
}

/// mountinfo の 1 行に必須の固定フィールド数（`id parent major:minor root mount_point options`）。
const MOUNTINFO_FIXED_FIELDS: usize = 6;
/// 区切り `-` の後ろの必須フィールド数（`fstype source super_options`）。
const MOUNTINFO_TAIL_FIELDS: usize = 3;

/// [`mount_is_shared`] の解析部（テスト可能な純関数）。先頭フィールド（mount ID）が
/// `mnt_id` の行の optional fields に `shared:` があるかを返す。書式に反する行は 1 行でも
/// あれば候補行かどうかに関わらずエラーにする（fail-closed。壊れた行を黙って飛ばして
/// 非 shared と誤判定しない）。該当行が無い・同じ mount ID の行が複数ある場合もエラー。
fn mount_is_shared_in(info: &str, mnt_id: u64) -> Result<bool, ExecError> {
    let malformed = || mountinfo_error("malformed line in /proc/thread-self/mountinfo");
    let mut found: Option<bool> = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // optional fields（0 個以上）の終端 `-` を、固定フィールドの後ろから探す。
        let sep = fields
            .iter()
            .skip(MOUNTINFO_FIXED_FIELDS)
            .position(|f| *f == "-")
            .map(|i| i + MOUNTINFO_FIXED_FIELDS)
            .ok_or_else(malformed)?;
        if fields.len() < sep + 1 + MOUNTINFO_TAIL_FIELDS {
            return Err(malformed());
        }
        let id: u64 = fields
            .first()
            .and_then(|f| f.parse().ok())
            .ok_or_else(malformed)?;
        if id != mnt_id {
            continue;
        }
        if found.is_some() {
            return Err(mountinfo_error(
                "duplicate mount ID in /proc/thread-self/mountinfo",
            ));
        }
        let shared = fields
            .get(MOUNTINFO_FIXED_FIELDS..sep)
            .ok_or_else(malformed)?
            .iter()
            .any(|f| f.starts_with("shared:"));
        found = Some(shared);
    }
    found.ok_or_else(|| mountinfo_error("no mount entry found for proc mount target"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(namespaces: NamespaceSet, hostname: Option<&str>) -> IsolationConfig {
        IsolationConfig {
            namespaces,
            hostname: hostname.map(|h| Hostname::new(h).unwrap()),
        }
    }

    /// CORE-1: 5 種の集合と単体の所属判定。
    #[test]
    fn core1_namespace_set_membership() {
        let all = NamespaceSet::all();
        assert!(Namespace::ALL.iter().all(|ns| all.contains(*ns)));
        let only_uts = NamespaceSet::empty().with(Namespace::Uts);
        assert!(only_uts.contains(Namespace::Uts));
        assert!(!only_uts.contains(Namespace::Pid));
        assert!(NamespaceSet::empty().is_empty());
        // 単体フラグの合成値（sys の具体値と一致）
        let bits = all.flags().iter().fold(0i32, |a, f| a | f.bits());
        assert_eq!(bits, 0x3C02_0000);
    }

    /// CORE-1: hostname の受理例。
    #[test]
    fn core1_hostname_accepts_valid() {
        assert_eq!(
            Hostname::new("fandhe-probe").unwrap().as_str(),
            "fandhe-probe"
        );
        assert_eq!(Hostname::new("a.b-c").unwrap().as_str(), "a.b-c");
        assert!(Hostname::new("a".repeat(63)).is_ok());
    }

    /// CORE-1: hostname の拒否例はすべて `InvalidArgument`。
    #[test]
    fn core1_hostname_rejects_invalid() {
        let too_long = "a".repeat(65);
        let long_label = "a".repeat(64);
        for bad in [
            "",
            "a_b",
            "-a",
            "a-",
            "a..b",
            "a.",
            ".a",
            "a\0b",
            too_long.as_str(),
            long_label.as_str(),
            "日本",
        ] {
            let err = Hostname::new(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "input: {bad:?}");
            assert_eq!(err.stage, IsolationStage::Validate);
        }
    }

    /// CORE-1: uid_map / gid_map の書式。
    #[test]
    fn core1_id_mapping_line_format() {
        assert_eq!(IdMapping::single(1000).to_map_line(), "0 1000 1\n");
    }

    /// CORE-1: 空集合は拒否。
    #[test]
    fn core1_plan_rejects_empty_namespaces() {
        let err = plan_for(&cfg(NamespaceSet::empty(), None), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = plan_rootful_for(&cfg(NamespaceSet::empty(), None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// CORE-1: UTS 無しの hostname はホストの hostname を書き換え得るため拒否。
    #[test]
    fn core1_plan_rejects_hostname_without_uts() {
        let ns = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        let err = plan_for(&cfg(ns.with(Namespace::User), Some("x")), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(err.message, "hostname requires the UTS namespace");
        let err = plan_rootful_for(&cfg(ns, Some("x")), 0).unwrap_err();
        assert_eq!(err.message, "hostname requires the UTS namespace");
    }

    /// SEC-5: root（euid 0 / egid 0）の自 ID 写像は拒否。
    #[test]
    fn sec5_plan_rejects_root_identity_mapping() {
        for (u, g) in [(0, 1000), (1000, 0), (0, 0)] {
            let err = plan_for(&cfg(NamespaceSet::all(), None), u, g).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "({u},{g})");
        }
    }

    /// 監査 P1-1: Pid あり・Mount なしは両経路とも拒否し、Mount を加えれば通る。
    #[test]
    fn core1_plan_rejects_pid_without_mount() {
        let pid_only = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Uts);
        let err = plan_rootful_for(&cfg(pid_only, None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "the PID namespace requires the mount namespace"
        );
        let err = plan_for(&cfg(pid_only.with(Namespace::User), None), 1000, 1000).unwrap_err();
        assert_eq!(
            err.message,
            "the PID namespace requires the mount namespace"
        );
        assert!(plan_rootful_for(&cfg(pid_only.with(Namespace::Mount), None), 0).is_ok());
    }

    /// SEC-5（監査 P2-4）: 拒否文言は弱い分離ではなく subuid / subgid 写像へ案内する。
    #[test]
    fn sec5_rejection_message_points_to_subordinate_ids() {
        let err = plan_for(&cfg(NamespaceSet::all(), None), 0, 0).unwrap_err();
        assert!(err.message.contains("/etc/subuid"), "{}", err.message);
        assert!(err.message.contains("TASK-40"), "{}", err.message);
        assert!(!err.message.contains("rootful"), "{}", err.message);
    }

    /// SEC-5: 既定経路は非 root の自 ID を 0 へ写す単一写像を計画する。
    #[test]
    fn sec5_plan_maps_unprivileged_ids_to_zero() {
        let p = plan_for(&cfg(NamespaceSet::all(), Some("h")), 1000, 1001).unwrap();
        assert_eq!(p.uid_mapping.to_map_line(), "0 1000 1\n");
        assert_eq!(p.gid_mapping.to_map_line(), "0 1001 1\n");
        assert_eq!(p.namespaces, NamespaceSet::all());
        assert_eq!(p.hostname.as_ref().map(Hostname::as_str), Some("h"));
    }

    /// CORE-7・CORE-9: rootful 経路は euid 0 で User なしの構成を計画する。
    #[test]
    fn rootful_plan_accepts_root_without_user() {
        let rootful = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        let p = plan_rootful_for(&cfg(rootful, Some("h")), 0).unwrap();
        assert_eq!(
            p,
            RootfulHostRootPlan {
                namespaces: rootful,
                hostname: Some(Hostname::new("h").unwrap()),
            }
        );
    }

    /// Codex P0: 既定経路は User を含まない構成を拒否する（root でも非 root でも）。
    #[test]
    fn default_plan_requires_user_namespace() {
        let no_user = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        for (u, g) in [(1000, 1000), (0, 0)] {
            let err = plan_for(&cfg(no_user, None), u, g).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "({u},{g})");
            assert_eq!(err.stage, IsolationStage::Validate);
            assert_eq!(
                err.message,
                "the user namespace is required to map container root to an unprivileged host ID"
            );
        }
    }

    /// Codex P0: rootful 経路は euid が 0 でなければ拒否する。
    #[test]
    fn rootful_plan_requires_euid_zero() {
        let rootful = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        for euid in [1, 1000, u32::MAX] {
            let err = plan_rootful_for(&cfg(rootful, None), euid).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "euid {euid}");
            assert_eq!(err.stage, IsolationStage::Validate);
            assert_eq!(err.message, "the rootful host-root plan requires euid 0");
        }
    }

    /// Codex P0: rootful 経路は User を含められない（euid 0 でも拒否）。
    #[test]
    fn rootful_plan_rejects_user_namespace() {
        let err = plan_rootful_for(&cfg(NamespaceSet::all(), None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "the rootful host-root plan must not include the user namespace"
        );
    }

    /// 既定経路の isolate は、計画作成時と実行 ID が変わっていれば副作用なしで拒否する。
    #[test]
    fn isolate_rejects_plan_for_other_ids() {
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let other = |id: u32| if id == 4242 { 4243 } else { 4242 };
        let p = plan_for(&cfg(NamespaceSet::all(), None), other(euid), other(egid)).unwrap();
        let err = isolate(&p).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "effective uid/gid changed after the plan was created"
        );
    }

    const STATUS_PID1: &str = "Name:\tx\nNSpid:\t4321\t1\nThreads:\t1\n";

    /// 再監査 P2-2・P2-3: establish の前提（PID 1・NSpid 末尾 1・入れ子・シングルスレッド）。
    #[test]
    fn establish_preconditions() {
        assert_eq!(check_establish_preconditions(1, STATUS_PID1), Ok(()));
        let cases: [(u32, &str, ViolationReason); 5] = [
            (7, STATUS_PID1, ViolationReason::EstablishNotPid1),
            (
                1,
                "NSpid:\t4321\t7\nThreads:\t1\n",
                ViolationReason::EstablishNspidNotPid1,
            ),
            (
                1,
                "NSpid:\t1\nThreads:\t1\n",
                ViolationReason::EstablishNotNestedPidNamespace,
            ),
            (
                1,
                "NSpid:\t4321\t1\nThreads:\t2\n",
                ViolationReason::EstablishMultiThreaded,
            ),
            (
                1,
                "NSpid:\t4321\t1\n",
                ViolationReason::EstablishMultiThreaded,
            ),
        ];
        for (pid, status, want) in cases {
            assert_eq!(
                check_establish_preconditions(pid, status),
                Err(want),
                "{status:?}"
            );
        }
    }

    /// `Threads:`・`NSpid` 末尾の解析。
    #[test]
    fn status_fields_parsing() {
        assert_eq!(status_threads("Threads:\t12\n"), Some(12));
        assert_eq!(status_threads("Threads:\tx\n"), None);
        assert_eq!(status_threads("Name:\tx\n"), None);
        assert_eq!(nspid_innermost("NSpid:\t4321\t55\t1\n"), Some(1));
        assert_eq!(nspid_innermost("NSpid:\t4321\n"), Some(4321));
        assert_eq!(nspid_innermost("NSpid:\n"), None);
        // 実プロセスの status でも取れる（libtest はマルチスレッド）。
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status_threads(&status).is_some_and(|n| n >= 1));
        assert_eq!(
            nspid_innermost(&status),
            Some(std::process::id()),
            "innermost NSpid equals getpid"
        );
    }

    /// errno 写像の具体値。
    #[test]
    fn errno_maps_to_error_code() {
        assert_eq!(
            errno_to_code(SysError::Os(sys::EPERM)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            errno_to_code(SysError::Os(sys::EACCES)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            errno_to_code(SysError::Os(sys::EINVAL)),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(errno_to_code(SysError::Os(2)), ErrorCode::Internal);
        assert_eq!(
            errno_to_code(SysError::Unsupported),
            ErrorCode::Unimplemented
        );
    }

    thread_local! {
        /// dry-run の `mount_proc_syscall` が記録したマウント先（テストスレッドごと）。
        pub(super) static DRY_RUN_MOUNTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// パス検証は相対パス・NUL を副作用なしで拒否する。
    #[test]
    fn mount_proc_rejects_bad_targets() {
        let rel = mount_proc_verified(Path::new("/"), Path::new("proc")).unwrap_err();
        assert_eq!(rel.code, ErrorCode::InvalidArgument);
        assert_eq!(rel.stage, IsolationStage::MountProc);
        let nul = mount_proc_verified(Path::new("/"), Path::new("/pr\0oc")).unwrap_err();
        assert_eq!(nul.code, ErrorCode::InvalidArgument);
    }

    /// テストプロセスは PID 1 ではないため、証跡の作成は副作用なしで拒否される
    /// （CORE-1・fail-closed）。
    #[test]
    fn establish_rejects_non_pid1() {
        let before = thread_ns_link("mnt").unwrap();
        let err = MountIsolation::establish().unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
        assert!(err.message.starts_with("not PID 1"), "{}", err.message);
        // unshare 前に拒否しており、スレッドの mount namespace は変わらない。
        assert_eq!(thread_ns_link("mnt").unwrap(), before);
    }

    fn evidence(mnt_ns: &str, pid_ns: &str) -> MountIsolation {
        MountIsolation {
            mnt_ns: mnt_ns.to_string(),
            pid_ns: pid_ns.to_string(),
            _not_send: std::marker::PhantomData,
        }
    }

    /// CORE-1（Codex P0）: 証跡の再検証は PID 1・mount ns・PID ns のすべての一致を要求する。
    #[test]
    fn check_evidence_requires_pid1_and_both_namespaces() {
        let e = evidence("mnt:[10]", "pid:[20]");
        assert_eq!(check_evidence(&e, 1, "mnt:[10]", "pid:[20]"), Ok(()));
        // 証跡を受け取った親や PID 1 が fork した子（PID が 1 でない）。
        assert_eq!(
            check_evidence(&e, 42, "mnt:[10]", "pid:[20]"),
            Err(ViolationReason::EvidenceCallerNotPid1)
        );
        // 別の mount namespace（別スレッド・親）。
        assert_eq!(
            check_evidence(&e, 1, "mnt:[11]", "pid:[20]"),
            Err(ViolationReason::EvidenceMountNamespaceMismatch)
        );
        // 同じ mount namespace だが別の PID namespace（procfs が別の PID 集合を映す）。
        assert_eq!(
            check_evidence(&e, 1, "mnt:[10]", "pid:[21]"),
            Err(ViolationReason::EvidencePidNamespaceMismatch)
        );
    }

    /// CORE-1（Codex P0・監査 P1-1）: unshare の前後で mount ns が変わらなければ拒否する。
    #[test]
    fn check_fresh_mount_ns_rejects_unchanged_namespace() {
        assert_eq!(check_fresh_mount_ns("mnt:[1]", "mnt:[2]"), Ok(()));
        assert_eq!(
            check_fresh_mount_ns("mnt:[1]", "mnt:[1]"),
            Err(ViolationReason::EstablishMountNamespaceNotFresh)
        );
    }

    /// 現在のスレッドの値で作った証跡でも、PID 1 でなければ mount_proc は副作用なしで拒否し、
    /// dry-run の mount にも到達しない。
    #[test]
    fn mount_proc_rejects_caller_that_is_not_pid1() {
        let e = evidence(
            &thread_ns_link("mnt").unwrap(),
            &thread_ns_link("pid").unwrap(),
        );
        let err = mount_proc(&e, Path::new("/"), Path::new("/proc")).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
        assert_eq!(
            err.message,
            "mount_proc must be called by PID 1 of the isolated PID namespace"
        );
        DRY_RUN_MOUNTS.with(|m| assert_eq!(*m.borrow(), Vec::<String>::new()));
    }

    /// `NSpid` の入れ子段数（1 段 = 初期 namespace、2 段以上 = 入れ子）。
    #[test]
    fn nspid_depth_counts_levels() {
        assert_eq!(nspid_depth("Name:\tx\nNSpid:\t1234\t1\nUid:\t0\n"), Some(2));
        assert_eq!(nspid_depth("NSpid:\t1\n"), Some(1));
        assert_eq!(nspid_depth("Name:\tx\n"), None);
    }

    const MI_SHARED: &str = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n";
    const MI_PRIVATE: &str = "30 22 0:5 / /proc rw - proc proc rw\n";

    /// mountinfo の shared 判定は mount ID で行い、パスの前後関係に依存しない。
    #[test]
    fn mountinfo_detects_shared_and_private_by_mount_id() {
        let both = format!("{MI_SHARED}{MI_PRIVATE}");
        assert!(mount_is_shared_in(&both, 22).unwrap());
        assert!(!mount_is_shared_in(&both, 30).unwrap());
        // optional fields が複数（master: 等）でも shared: を見つける。
        let multi = "40 22 0:6 / /x rw master:3 shared:7 - tmpfs t rw\n";
        assert!(mount_is_shared_in(multi, 40).unwrap());
    }

    /// 書式に反する行（区切り `-` 欠落・フィールド不足・末尾欠落・数値でない ID）・
    /// 該当なし・ID 重複はエラー。
    #[test]
    fn mountinfo_rejects_malformed_lines() {
        for bad in [
            "22 1 8:1 / / rw,relatime\n",
            "22 1 8:1 /\n",
            "22 1 8:1 / / rw,relatime shared:1 - ext4\n",
            "22 1 8:1 / / rw,relatime -\n",
            "\n",
            "x 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
            // 候補でない行が壊れていても黙って飛ばさない。
            "23 1 8:1 / /other rw\n22 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
            // 該当する mount ID が無い。
            "23 1 8:1 / /other rw - ext4 /dev/sda1 rw\n",
            // 同じ mount ID が 2 行。
            "22 1 8:1 / / rw - ext4 a rw\n22 1 8:1 / /b rw - ext4 b rw\n",
        ] {
            let err = mount_is_shared_in(bad, 22).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "input: {bad:?}");
            assert_eq!(err.stage, IsolationStage::MountProc);
        }
    }

    /// テスト用の一時ディレクトリ（`chmod` で絞ったディレクトリを戻してから削除する）。
    /// `TMPDIR` に symlink があると rootfs の正規化検査が先に失敗して各ケースが意図と
    /// 違う理由で通るため、正規化したパスを起点にする。
    struct TempTree {
        base: std::path::PathBuf,
        restore: Vec<std::path::PathBuf>,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-exec-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self {
                base,
                restore: Vec::new(),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            for p in &self.restore {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// `..`・rootfs 外・symlink・非ディレクトリのターゲットは、それぞれ意図した理由で
    /// 副作用なしに拒否する（mount(2) へは到達しない）。
    #[test]
    fn mount_proc_rejects_escape_paths() {
        let t = TempTree::new("escape");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("file"), b"").unwrap();
        std::os::unix::fs::symlink("/", root.join("link")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("dirlink")).unwrap();
        let not_dir = "must be directories, not symlinks";
        let cases = [
            (root.join("real/../real"), "must not contain '..'"),
            (t.base.join("outside"), "must be under rootfs"),
            (root.join("link"), not_dir),
            (root.join("dirlink"), not_dir),
            (root.join("link/proc"), not_dir),
            (root.join("file"), not_dir),
            (root.join("missing"), "must exist"),
            (root.clone(), "not rootfs itself"),
        ];
        for (target, want) in &cases {
            let err = mount_proc_verified(&root, target).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{target:?}");
            assert_eq!(err.stage, IsolationStage::MountProc, "{target:?}");
            assert!(err.message.contains(want), "{target:?}: {}", err.message);
        }
        DRY_RUN_MOUNTS.with(|m| assert_eq!(*m.borrow(), Vec::<String>::new()));
        // rootfs 自体が symlink（実体は base/root）の場合は拒否する。
        let alias = t.base.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let err = mount_proc_verified(&alias, &alias.join("real")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "rootfs symlink");
        assert!(err.message.contains("canonical path"), "{}", err.message);
    }

    /// CORE-1（Cursor Bugbot 指摘の回帰）: rootfs の祖先に実行権限のみ（読み取り不可）の
    /// ディレクトリがあっても、マウント先まで辿って fd を固定できる。mount(2) を呼ばない
    /// 走査部だけを検証する（root で実行されてもホストにマウントしないため）。root では DAC を
    /// 迂回するため判別力はないが失敗もしない。
    #[test]
    fn open_dir_beneath_traverses_execute_only_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut t = TempTree::new("xonly");
        let xonly = t.base.join("xonly");
        let root = xonly.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::set_permissions(&xonly, std::fs::Permissions::from_mode(0o100)).unwrap();
        t.restore.push(xonly.clone());
        if sys::effective_uid() != 0 {
            // 前提の確認: 読み取りで開く方式ではこの祖先を開けない（修正前の失敗条件）。
            let err = std::fs::read_dir(&xonly).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        }
        let fd = open_dir_beneath(&root, &[OsStr::new("proc")]).unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/thread-self/fd/{}", fd.as_raw_fd())).unwrap(),
            root.join("proc")
        );
    }

    /// 走査の途中に symlink があれば、実体がディレクトリでも拒否する（パス差し替え対策）。
    #[test]
    fn open_dir_beneath_rejects_symlink_component() {
        let t = TempTree::new("beneath-link");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real/proc")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let err = open_dir_beneath(&root, &[OsStr::new("link"), OsStr::new("proc")]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::MountProc);
    }

    /// fdinfo の `mnt_id:` を取り出す（無い・数値でない場合は None）。
    #[test]
    fn fdinfo_mnt_id_parsing() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t012600000\nmnt_id:\t52\nino:\t1\n"),
            Some(52)
        );
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\nflags:\t0\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\tx\n"), None);
    }

    /// 走査で固定した `/` の fd の mnt_id は、mountinfo で最後に現れる（最上位の）
    /// マウントポイント `/` の mount ID と一致し、その行の shared 判定を返す。
    #[test]
    fn mount_is_shared_uses_mount_id_of_fd() {
        let fd = open_dir_beneath(Path::new("/"), &[]).unwrap();
        let fdinfo =
            std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))
                .unwrap();
        let mnt_id = parse_fdinfo_mnt_id(&fdinfo).unwrap();
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").unwrap();
        let root_line = info
            .lines()
            .rev()
            .find(|l| l.split(' ').nth(4) == Some("/"))
            .unwrap();
        let id: u64 = root_line.split(' ').next().unwrap().parse().unwrap();
        assert_eq!(mnt_id, id);
        let want = root_line
            .split(" - ")
            .next()
            .unwrap()
            .split(' ')
            .skip(6)
            .any(|f| f.starts_with("shared:"));
        assert_eq!(mount_is_shared(&fd).unwrap(), want);
    }

    /// 違反記録の中身を具体値で取り出す（種別名・理由コード・ビヘイビア ID・対象）。
    fn violation_of(err: &ExecError) -> (&'static str, &'static str, &'static str, Option<String>) {
        let v = err.violation.as_ref().expect("violation record");
        (
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id,
            v.subject.as_ref().map(|s| s.as_str().to_string()),
        )
    }

    /// SEC-4（記録経路）: plan / plan_rootful_host_root / isolate の各拒否に違反記録が付く。
    #[test]
    fn sec4_plan_rejections_carry_violation_records() {
        let pm = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        let pid_only = NamespaceSet::empty().with(Namespace::Pid);
        let cases: [(Result<(), ExecError>, &str, &str); 7] = [
            (
                plan_for(&cfg(NamespaceSet::empty(), None), 1000, 1000).map(drop),
                "no_namespaces",
                "CORE-1",
            ),
            (
                plan_for(&cfg(pm.with(Namespace::User), Some("h")), 1000, 1000).map(drop),
                "hostname_without_uts",
                "CORE-1",
            ),
            (
                plan_rootful_for(&cfg(pid_only, None), 0).map(drop),
                "pid_without_mount",
                "CORE-1",
            ),
            (
                plan_for(&cfg(pm, None), 1000, 1000).map(drop),
                "user_namespace_required",
                "SEC-5",
            ),
            (
                plan_for(&cfg(NamespaceSet::all(), None), 0, 1000).map(drop),
                "host_root_identity_mapping",
                "SEC-5",
            ),
            (
                plan_rootful_for(&cfg(NamespaceSet::all(), None), 0).map(drop),
                "rootful_with_user_namespace",
                "CORE-1",
            ),
            (
                plan_rootful_for(&cfg(pm, None), 1000).map(drop),
                "rootful_requires_root",
                "CORE-1",
            ),
        ];
        for (result, reason, id) in cases {
            let err = result.unwrap_err();
            assert_eq!(err.stage, IsolationStage::Validate, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("plan_rejected", reason, id, None),
                "{reason}"
            );
        }
        // isolate の実行 ID 再検証（unshare 前に拒否）。
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let other = |id: u32| if id == 4242 { 4243 } else { 4242 };
        let p = plan_for(&cfg(NamespaceSet::all(), None), other(euid), other(egid)).unwrap();
        let err = isolate(&p).unwrap_err();
        assert_eq!(
            violation_of(&err),
            ("plan_rejected", "identity_changed", "SEC-5", None)
        );
        assert!(
            err.to_string()
                .ends_with("(violation: plan_rejected/identity_changed, SEC-5)")
        );
    }

    /// SEC-4（記録経路）: establish の前提違反と証跡不一致に違反記録が付く（対象なし。
    /// namespace の識別子は記録しない）。
    #[test]
    fn sec4_establish_and_evidence_rejections_carry_violation_records() {
        let err = MountIsolation::establish().unwrap_err();
        assert_eq!(
            violation_of(&err),
            (
                "establish_precondition",
                "establish_not_pid1",
                "CORE-1",
                None
            )
        );
        let e = evidence(
            &thread_ns_link("mnt").unwrap(),
            &thread_ns_link("pid").unwrap(),
        );
        let err = mount_proc(&e, Path::new("/"), Path::new("/proc")).unwrap_err();
        assert_eq!(
            violation_of(&err),
            (
                "evidence_mismatch",
                "evidence_caller_not_pid1",
                "CORE-1",
                None
            )
        );
        assert!(!err.to_string().contains("mnt:["), "{err}");
    }

    /// SEC-4（記録経路）: mount_proc のパス検証の各拒否に、理由コードと対象パスが付く。
    #[test]
    fn sec4_mount_path_rejections_carry_violation_records() {
        let t = TempTree::new("sec4-path");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("file"), b"").unwrap();
        std::os::unix::fs::symlink("/", root.join("link")).unwrap();
        let alias = t.base.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let s = |p: &Path| Some(p.to_str().unwrap().to_string());
        let dotdot = root.join("real/../real");
        let cases = [
            (
                root.clone(),
                dotdot.clone(),
                "path_parent_component",
                s(&dotdot),
            ),
            (
                root.clone(),
                t.base.join("outside"),
                "target_outside_rootfs",
                s(&t.base.join("outside")),
            ),
            (
                root.clone(),
                root.join("link/proc"),
                "path_symlink_or_not_directory",
                s(&root.join("link/proc")),
            ),
            (
                root.clone(),
                root.join("file"),
                "path_symlink_or_not_directory",
                s(&root.join("file")),
            ),
            (
                root.clone(),
                root.join("missing"),
                "path_missing",
                s(&root.join("missing")),
            ),
            (root.clone(), root.clone(), "target_is_rootfs", s(&root)),
            (
                alias.clone(),
                alias.join("real"),
                "rootfs_not_canonical",
                s(&alias),
            ),
            (
                t.base.join("nope"),
                t.base.join("nope/proc"),
                "rootfs_missing",
                s(&t.base.join("nope")),
            ),
            (
                PathBuf::from("/"),
                PathBuf::from("proc"),
                "path_not_absolute",
                Some("proc".to_string()),
            ),
            (
                PathBuf::from("/"),
                PathBuf::from("/pr\0oc"),
                "path_contains_nul",
                Some("/pr\\u{0}oc".to_string()),
            ),
        ];
        for (rootfs, target, reason, subject) in cases {
            let err = mount_proc_verified(&rootfs, &target).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("mount_target", reason, "CORE-1", subject),
                "{reason}"
            );
        }
        DRY_RUN_MOUNTS.with(|m| assert_eq!(*m.borrow(), Vec::<String>::new()));
    }

    /// SEC-4（記録経路）: shared 伝播上のマウント先は違反記録付きで拒否し、shared でなければ
    /// dry-run の mount まで進む（実行環境の propagation に応じてどちらかを具体値で照合する）。
    #[test]
    fn sec4_shared_propagation_carries_violation_record() {
        let t = TempTree::new("sec4-shared");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        let target = root.join("proc");
        let dir = open_dir_beneath(&root, &[OsStr::new("proc")]).unwrap();
        let shared = mount_is_shared(&dir).unwrap();
        drop(dir);
        let result = mount_proc_verified(&root, &target);
        if shared {
            let err = result.unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(
                violation_of(&err),
                (
                    "shared_propagation",
                    "target_on_shared_mount",
                    "CORE-1",
                    Some(target.to_str().unwrap().to_string())
                )
            );
            DRY_RUN_MOUNTS.with(|m| assert_eq!(*m.borrow(), Vec::<String>::new()));
        } else {
            assert_eq!(result, Ok(()));
            DRY_RUN_MOUNTS.with(|m| {
                let m = m.borrow();
                assert_eq!(m.len(), 1);
                assert!(m[0].starts_with("/proc/thread-self/fd/"), "{m:?}");
            });
        }
    }

    /// SEC-4: システムエラー（syscall 失敗・mountinfo の書式不正・権限不足）と hostname の
    /// 書式エラーには違反記録を付けない。
    #[test]
    fn sec4_system_errors_have_no_violation_record() {
        let enomem = ExecError::from_sys(SysError::Os(12), IsolationStage::Unshare, "unshare");
        assert_eq!(enomem.code, ErrorCode::Internal);
        assert_eq!(enomem.violation, None);
        let err = mount_is_shared_in("22 1 8:1 / / rw\n", 22).unwrap_err();
        assert_eq!(err.violation, None);
        assert_eq!(Hostname::new("a_b").unwrap_err().violation, None);
        if sys::effective_uid() != 0 {
            // search 権限の無い祖先: 走査・rootfs の正規化とも権限不足のシステムエラー。
            use std::os::unix::fs::PermissionsExt as _;
            let mut t = TempTree::new("sec4-eacces");
            let locked = t.base.join("locked");
            std::fs::create_dir_all(locked.join("root/proc")).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            t.restore.push(locked.clone());
            let err = open_dir_beneath(&locked.join("root"), &[OsStr::new("proc")]).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.violation, None);
            let err =
                mount_proc_verified(&locked.join("root"), &locked.join("root/proc")).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.violation, None);
        }
    }
}
