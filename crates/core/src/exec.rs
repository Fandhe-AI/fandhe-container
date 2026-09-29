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
//!
//! # namespace 分離の契約（[`isolate`]）
//!
//! - シングルスレッドのプロセスから呼ぶこと（マルチスレッドからの `CLONE_NEWUSER` は
//!   `EINVAL` になり、`FailedPrecondition` で返す）
//! - `unshare(CLONE_NEWPID)` は呼び出し元自身を移動させず、**次に生成する子が PID 1** になる。
//!   その PID 1 側で [`MountIsolation::verify_current`] により実行時検証（PID 1・入れ子の
//!   PID namespace・分離済み mount namespace）を通し、[`mount_proc`] を呼んで初めて `/proc`
//!   からホストのプロセスが見えなくなる。検証は呼び出し側の申告に依存しない（fail-closed）
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError {
    /// 機械可読な分類。
    pub code: ErrorCode,
    /// 失敗した段。
    pub stage: IsolationStage,
    /// 英語のメッセージ。
    pub message: String,
}

impl ExecError {
    fn new(code: ErrorCode, stage: IsolationStage, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
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
        )
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

/// [`isolate`] の成功結果（将来拡張できる構造化された戻り値）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationReport {
    /// 分離した namespace。
    pub namespaces: NamespaceSet,
    /// 設定した hostname。
    pub hostname: Option<Hostname>,
    /// 書き込んだ uid 写像（`User` を含む場合のみ）。
    pub uid_mapping: Option<IdMapping>,
    /// 書き込んだ gid 写像（`User` を含む場合のみ）。
    pub gid_mapping: Option<IdMapping>,
}

/// [`mount_proc`] を呼べる状態（新しい PID namespace の PID 1・ホストと分離した mount
/// namespace）を実行時に検証済みであることの証跡（CORE-1・SEC-4）。
///
/// 生成は [`MountIsolation::verify_current`] のみで、呼び出し側の申告では作れない。
/// exec を跨ぐ経路（親が [`isolate`]、子が exec 後に呼ぶ）でも、子自身が現在の状態を
/// 検証するため親の申告に依存しない。証跡は検証時の mount namespace に紐づき、別 namespace
/// では [`mount_proc`] が拒否する。procfs を再マウントした後は、ホスト側 `/proc` 越しの
/// 検証ができなくなるため、再マウントを繰り返す呼び出し側（#135 の `pivot_root` 後等）は
/// 最初のマウント前に取得した証跡を使い回す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIsolation {
    /// 検証時の `/proc/self/ns/mnt` のリンク先（`mnt:[inode]`）。
    mnt_ns: String,
}

/// `/proc/self/status` の `NSpid:` 行の要素数（PID namespace の入れ子段数）。
fn nspid_depth(status: &str) -> Option<usize> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .map(|rest| rest.split_whitespace().count())
}

/// `uid_map` が初期 user namespace の恒等写像（`0 0 4294967295` のみ）か。
fn is_initial_userns_uid_map(uid_map: &str) -> bool {
    let mut lines = uid_map.lines().filter(|l| !l.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return false;
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields == ["0", "0", "4294967295"]
}

impl MountIsolation {
    /// 現在のプロセスが procfs を安全にマウントできる状態かを実行時に検証して証跡を得る。
    ///
    /// すべて満たさなければ `FailedPrecondition`（fail-closed。副作用なし）:
    ///
    /// - PID が 1 で、`/proc/self/status` の `NSpid` が 2 段以上（ホスト側 procfs 越しに見て
    ///   入れ子の PID namespace の PID 1。Mount だけ分離したプロセスや、ホストの PID
    ///   namespace のプロセスでは procfs にホストの PID が見えてしまうため拒否する）
    /// - 初期 user namespace（rootful）では、`/proc/1/ns/mnt`（ホスト init）と自身の mount
    ///   namespace が異なること。読めない場合も拒否する。非初期 user namespace（rootless）
    ///   では mount namespace の所有者がその user namespace であることをカーネルが保証し、
    ///   別 mount namespace の共有マウントは変更できないため、この比較は省略する
    pub fn verify_current() -> Result<Self, ExecError> {
        let fail = |msg: &str| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountProc,
                msg,
            )
        };
        if std::process::id() != 1 {
            return Err(fail(
                "not PID 1; call from the first child created after unshare(CLONE_NEWPID)",
            ));
        }
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| fail("cannot read /proc/self/status to verify the PID namespace"))?;
        if nspid_depth(&status).is_none_or(|d| d < 2) {
            return Err(fail(
                "not in a nested PID namespace; isolate with Namespace::Pid first",
            ));
        }
        let mnt_ns = std::fs::read_link("/proc/self/ns/mnt")
            .map_err(|_| fail("cannot read /proc/self/ns/mnt to verify the mount namespace"))?
            .to_string_lossy()
            .into_owned();
        let uid_map = std::fs::read_to_string("/proc/self/uid_map")
            .map_err(|_| fail("cannot read /proc/self/uid_map to verify the user namespace"))?;
        if is_initial_userns_uid_map(&uid_map) {
            let host_mnt = std::fs::read_link("/proc/1/ns/mnt")
                .map_err(|_| fail("cannot read /proc/1/ns/mnt to compare mount namespaces"))?
                .to_string_lossy()
                .into_owned();
            if host_mnt == mnt_ns {
                return Err(fail(
                    "mount namespace is shared with the host; isolate with Namespace::Mount first",
                ));
            }
        }
        Ok(Self { mnt_ns })
    }

    /// 証跡が現在の mount namespace のものか。
    fn matches_current(&self) -> bool {
        std::fs::read_link("/proc/self/ns/mnt")
            .is_ok_and(|l| l.to_string_lossy() == self.mnt_ns.as_str())
    }
}

/// 前提検証の結果として得る、副作用なしの実行計画。
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    uid_mapping: Option<IdMapping>,
    gid_mapping: Option<IdMapping>,
}

/// 副作用なしで設定と実行 ID を検証する（euid を引数に取りテスト可能にした純関数）。
///
/// - namespace が空、または hostname 指定なのに `Uts` が無い場合は `InvalidArgument`
///   （ホストの hostname を書き換える経路を作らない）
/// - `User` を含み euid / egid が 0 の場合は `FailedPrecondition`（SEC-5）
fn plan(config: &IsolationConfig, euid: u32, egid: u32) -> Result<Plan, ExecError> {
    let invalid =
        |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg);
    if config.namespaces.is_empty() {
        return Err(invalid("at least one namespace must be selected"));
    }
    if config.hostname.is_some() && !config.namespaces.contains(Namespace::Uts) {
        return Err(invalid("hostname requires the UTS namespace"));
    }
    if !config.namespaces.contains(Namespace::User) {
        return Ok(Plan {
            uid_mapping: None,
            gid_mapping: None,
        });
    }
    if euid == 0 || egid == 0 {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "refusing identity mapping of host root into the user namespace \
             (use a rootful configuration without User or subuid mapping)",
        ));
    }
    Ok(Plan {
        uid_mapping: Some(IdMapping::single(euid)),
        gid_mapping: Some(IdMapping::single(egid)),
    })
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

/// 設定に従い、呼び出しプロセスを namespace 分離する（CORE-1・SEC-5）。
///
/// 処理順: 検証 → `unshare` を全フラグで 1 回 → （`User`）`setgroups` deny・`uid_map`・
/// `gid_map` → （`Mount`）`/` を再帰 private 化 → （`Uts` かつ hostname）`sethostname`。
/// 契約はモジュール doc（シングルスレッド・PID 1 は次の子・失敗時はプロセス破棄）を参照。
pub fn isolate(config: &IsolationConfig) -> Result<IsolationReport, ExecError> {
    // unshare 後の euid / egid は overflow id になるため、先に取得する。
    let plan = plan(config, sys::effective_uid(), sys::effective_gid())?;

    sys::unshare_namespaces(&config.namespaces.flags())
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Unshare, "unshare"))?;

    if let (Some(uid), Some(gid)) = (plan.uid_mapping, plan.gid_mapping) {
        // 非特権の gid_map 書き込みには setgroups の deny が先に必要。
        write_proc_self("setgroups", "deny", IsolationStage::SetGroups)?;
        write_proc_self("uid_map", &uid.to_map_line(), IsolationStage::UidMap)?;
        write_proc_self("gid_map", &gid.to_map_line(), IsolationStage::GidMap)?;
    }

    if config.namespaces.contains(Namespace::Mount) {
        sys::mount_root_private_recursive().map_err(|e| {
            ExecError::from_sys(e, IsolationStage::MountPrivate, "mount(MS_PRIVATE)")
        })?;
    }

    if let Some(hostname) = &config.hostname {
        sys::set_hostname(hostname.as_str().as_bytes())
            .map_err(|e| ExecError::from_sys(e, IsolationStage::SetHostname, "sethostname"))?;
    }

    Ok(IsolationReport {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
        uid_mapping: plan.uid_mapping,
        gid_mapping: plan.gid_mapping,
    })
}

/// `rootfs` 配下の `target` に procfs をマウントする。新しい PID namespace の PID 1 側で呼ぶ
/// （#135 の `pivot_root` 後の再マウントでも再利用する想定）。
///
/// マウント前に次をすべて検証し、1 つでも満たさなければ副作用なしで拒否する（fail-closed。
/// security.md「rootfs の外へ書き込める経路を作らない」）。
///
/// - 呼び出し側が [`MountIsolation::verify_current`] で得た証跡（新しい PID namespace の
///   PID 1・分離済み mount namespace の実行時検証結果）を提示し、現在の mount namespace と一致する
/// - `rootfs` 自体とその祖先に symlink がない（`canonicalize` した実パスが `rootfs` と一致）
/// - `rootfs` / `target` は絶対パスで NUL・`..` を含まず、`target` は `rootfs` より下の専用ディレクトリ
///   （`target == rootfs` は拒否）
/// - `/` から `target` までを `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` で 1 要素ずつ辿って
///   fd で固定し（[`open_dir_beneath`]）、マウントは `/proc/self/fd/N` 経由で同じ実体に対して
///   行う（検証後の差し替え = TOCTOU の防止）。symlink・非ディレクトリ・不在の要素があれば
///   拒否する。O_PATH のため祖先に要るのは search（実行）権限だけで、user namespace 内から
///   読み取り不可・実行可のホスト側ディレクトリを辿れる
/// - 固定した fd が属するマウント（`/proc/self/fdinfo/N` の `mnt_id`）の propagation が
///   `shared` でない（mount namespace 分離済みで `MS_PRIVATE` 化されていること。shared の
///   ままではマウントがホストへ伝播する）。パス文字列ではなく fd で判定し、検証と実マウント
///   の対象を一致させる
pub fn mount_proc(
    isolation: &MountIsolation,
    rootfs: &Path,
    target: &Path,
) -> Result<(), ExecError> {
    let invalid =
        |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::MountProc, msg);
    if !isolation.matches_current() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::MountProc,
            "isolation evidence does not belong to the current mount namespace",
        ));
    }
    for (label, p) in [("rootfs", rootfs), ("proc mount target", target)] {
        if !p.is_absolute() {
            return Err(invalid(&format!("{label} must be an absolute path")));
        }
        if p.as_os_str().as_bytes().contains(&0) {
            return Err(invalid(&format!("{label} must not contain NUL")));
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(invalid(&format!("{label} must not contain '..'")));
        }
    }
    let rel = target
        .strip_prefix(rootfs)
        .map_err(|_| invalid("proc mount target must be under rootfs"))?;
    // rootfs 自体・祖先が symlink だとマウント先を誘導できるため、実パスとの一致を要求する。
    let real_root = std::fs::canonicalize(rootfs).map_err(|_| invalid("rootfs must exist"))?;
    if real_root.components().ne(rootfs.components()) {
        return Err(invalid(
            "rootfs must be a canonical path without symlinks in itself or its ancestors",
        ));
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
        return Err(invalid(
            "proc mount target must be a dedicated directory below rootfs, not rootfs itself",
        ));
    }
    // `/` から rootfs・target まで 1 要素ずつ開き、検証した実体を fd で固定する
    // （検証後のパス差し替え = TOCTOU の防止）。以後の判定・マウントはこの fd 経由でのみ行う。
    let dir = open_dir_beneath(&real_root, &names)?;
    if mount_is_shared(&dir)? {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::MountProc,
            "proc mount target is on a shared mount; isolate the mount namespace first",
        ));
    }
    // fd が指す実体へマウントする（`/proc/self/fd/N` は fd の dentry へ解決される）。
    let c_target = CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| invalid("proc mount target must not contain NUL"))?;
    sys::mount_proc_at(&c_target)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::MountProc, "mount(proc)"))
}

/// `/` から `real_root`（symlink を含まない正規化済み絶対パス）の各要素、続けて `names` を
/// 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開き、最後の要素の fd を返す（副作用なし）。
///
/// [`mount_proc`] のマウント先固定に使う。各要素は直前の fd を起点に開くため、途中の要素を
/// symlink へ差し替えても辿る実体は変わらない。O_PATH は読み取り権限を要求しないため、
/// 実行権限のみの祖先（`CLONE_NEWUSER` 後のホスト所有ディレクトリ等）も辿れる。
/// 拒否は `InvalidArgument`（symlink・非ディレクトリ・不在）、search 権限不足は
/// `PermissionDenied`、それ以外は errno に応じたコード。
fn open_dir_beneath(real_root: &Path, names: &[&OsStr]) -> Result<OwnedFd, ExecError> {
    let invalid =
        |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::MountProc, msg);
    let open_err = |e: SysError| match e {
        // O_DIRECTORY|O_NOFOLLOW では symlink も ENOTDIR になる。ELOOP は念のため残す。
        SysError::Os(sys::ELOOP) | SysError::Os(sys::ENOTDIR) => {
            invalid("proc mount target path components must be directories, not symlinks")
        }
        SysError::Os(sys::ENOENT) => invalid("proc mount target path must exist"),
        other => ExecError::from_sys(other, IsolationStage::MountProc, "openat"),
    };
    let mut cur = sys::open_dir_path_nofollow(None, c"/").map_err(open_err)?;
    let root_names = real_root.components().filter_map(|c| match c {
        Component::Normal(n) => Some(n),
        _ => None,
    });
    for name in root_names.chain(names.iter().copied()) {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| invalid("proc mount target must not contain NUL"))?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c_name).map_err(open_err)?;
    }
    Ok(cur)
}

/// `/proc/self/fdinfo/<fd>` の `mnt_id:` 行（fd が属するマウントの ID）を取り出す。
fn parse_fdinfo_mnt_id(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `dir` が属するマウントが shared propagation か判定する。fdinfo の `mnt_id` と
/// `/proc/self/mountinfo` の先頭フィールド（mount ID）を突き合わせる。読み取り・解析
/// できない場合は安全側（エラー）に倒す。
fn mount_is_shared(dir: &OwnedFd) -> Result<bool, ExecError> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", dir.as_raw_fd()))
        .map_err(|_| mountinfo_error("cannot read fdinfo of the proc mount target"))?;
    let mnt_id = parse_fdinfo_mnt_id(&fdinfo)
        .ok_or_else(|| mountinfo_error("no mnt_id in fdinfo of the proc mount target"))?;
    let info = std::fs::read_to_string("/proc/self/mountinfo").map_err(|_| {
        mountinfo_error("cannot read /proc/self/mountinfo to verify mount propagation")
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
    let malformed = || mountinfo_error("malformed line in /proc/self/mountinfo");
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
                "duplicate mount ID in /proc/self/mountinfo",
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
        let err = plan(&cfg(NamespaceSet::empty(), None), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// CORE-1: UTS 無しの hostname はホストの hostname を書き換え得るため拒否。
    #[test]
    fn core1_plan_rejects_hostname_without_uts() {
        let ns = NamespaceSet::empty().with(Namespace::Pid);
        let err = plan(&cfg(ns, Some("x")), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
    }

    /// SEC-5: root（euid 0 / egid 0）の自 ID 写像は拒否。
    #[test]
    fn sec5_plan_rejects_root_identity_mapping() {
        for (u, g) in [(0, 1000), (1000, 0), (0, 0)] {
            let err = plan(&cfg(NamespaceSet::all(), None), u, g).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "({u},{g})");
        }
    }

    /// SEC-5: 非 root では自 ID を 0 へ写す単一写像を計画し、root は User 無しなら通る。
    #[test]
    fn sec5_plan_maps_unprivileged_ids_to_zero() {
        let p = plan(&cfg(NamespaceSet::all(), None), 1000, 1001).unwrap();
        assert_eq!(p.uid_mapping.unwrap().to_map_line(), "0 1000 1\n");
        assert_eq!(p.gid_mapping.unwrap().to_map_line(), "0 1001 1\n");
        let rootful = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        let p = plan(&cfg(rootful, Some("h")), 0, 0).unwrap();
        assert_eq!(
            p,
            Plan {
                uid_mapping: None,
                gid_mapping: None
            }
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

    /// 検証を通さず作る、テスト専用の証跡（現在の mount namespace に紐づく）。
    fn test_evidence() -> MountIsolation {
        MountIsolation {
            mnt_ns: std::fs::read_link("/proc/self/ns/mnt")
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        }
    }

    /// `mount_proc` は相対パス・NUL を副作用なしで拒否する。
    #[test]
    fn mount_proc_rejects_bad_targets() {
        let iso = test_evidence();
        let rel = mount_proc(&iso, Path::new("/"), Path::new("proc")).unwrap_err();
        assert_eq!(rel.code, ErrorCode::InvalidArgument);
        assert_eq!(rel.stage, IsolationStage::MountProc);
        let nul = mount_proc(&iso, Path::new("/"), Path::new("/pr\0oc")).unwrap_err();
        assert_eq!(nul.code, ErrorCode::InvalidArgument);
    }

    /// 別 mount namespace の証跡は副作用なしで拒否する（CORE-1）。
    #[test]
    fn mount_proc_rejects_foreign_evidence() {
        let iso = MountIsolation {
            mnt_ns: "mnt:[0]".to_string(),
        };
        let err = mount_proc(&iso, Path::new("/"), Path::new("/proc")).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
    }

    /// テストプロセスは PID 1 ではないため、証跡の取得は拒否される（CORE-1・fail-closed）。
    #[test]
    fn verify_current_rejects_non_pid1() {
        let err = MountIsolation::verify_current().unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
    }

    /// `NSpid` の入れ子段数（1 段 = 初期 namespace、2 段以上 = 入れ子）。
    #[test]
    fn nspid_depth_counts_levels() {
        assert_eq!(nspid_depth("Name:\tx\nNSpid:\t1234\t1\nUid:\t0\n"), Some(2));
        assert_eq!(nspid_depth("NSpid:\t1\n"), Some(1));
        assert_eq!(nspid_depth("Name:\tx\n"), None);
    }

    /// 初期 user namespace の uid_map のみ恒等写像として判定する。
    #[test]
    fn initial_userns_uid_map_detection() {
        assert!(is_initial_userns_uid_map(
            "         0          0 4294967295\n"
        ));
        assert!(!is_initial_userns_uid_map(
            "         0       1000          1\n"
        ));
        assert!(!is_initial_userns_uid_map("0 0 4294967295\n1 5 3\n"));
        assert!(!is_initial_userns_uid_map(""));
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
        let iso = test_evidence();
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
            let err = mount_proc(&iso, &root, target).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{target:?}");
            assert_eq!(err.stage, IsolationStage::MountProc, "{target:?}");
            assert!(err.message.contains(want), "{target:?}: {}", err.message);
        }
        // rootfs 自体が symlink（実体は base/root）の場合は拒否する。
        let alias = t.base.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let err = mount_proc(&iso, &alias, &alias.join("real")).unwrap_err();
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
            std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap(),
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
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        let mnt_id = parse_fdinfo_mnt_id(&fdinfo).unwrap();
        let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
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
}
