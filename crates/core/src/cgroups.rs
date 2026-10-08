//! 委譲済み cgroup v2 の検出と、コンテナ用子 cgroup の作成（CORE-3・TASK-32.1・MS-2・#158）。
//!
//! # 役割
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（自プロセスが属する cgroup）を検出し、その
//! 配下にコンテナ用の子 cgroup を作る。controller（`memory`・`cpu` 等）の有効化は、cgroup v2 の
//! no-internal-process 制約により「自プロセスが親 cgroup から退避済み」であることが前提になる。
//! 本モジュールはその順序を型で強制する: [`DelegatedCgroup::prepare`] が退避と検証を済ませて
//! 証明トークン [`Evacuated`] を返し、[`DelegatedCgroup::enable_controllers`] はそのトークンを
//! 要求する（退避前に有効化するコードはコンパイルできない）。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー。本番 launcher（TASK-29 / TASK-157 系）はまだ無く、`detect` / `prepare` の
//!   呼び出しと [`ContainerCgroup::join_hook`] の登録は未結線（REPAIR-3）
//! - `unsafe` は持たない。syscall は `crate::sys` の薄いラッパー（`mkdirat`・`unlinkat`・`fstatfs`・
//!   `O_NOFOLLOW` 付き `openat`）経由で、検証した実体を fd で固定する（TOCTOU・symlink 対策）
//! - `/proc/self/cgroup`・`cgroup.procs` 等はカーネル応答（外部入力）として上限付きで読み、
//!   `unwrap` / 添字アクセスを使わずに検証する
//! - 待機を伴う処理はない（ファイル I/O のみ）ためタイムアウトは設けない
//! - エラーは [`CgroupError`]（`ErrorCode`＋失敗した段）。`ExecError` への変換は `exec` 側（`ExecError::from_cgroup`）
//!
//! # レイアウト
//! ```text
//! <委譲された親 P>/            ← 自プロセスの元の所属。controller を有効化する対象
//! ├── fc-runtime/             ← 退避リーフ（自プロセス〔runtime / supervisor〕の移動先）
//! └── fc-<container-id>@<n>/  ← コンテナ用子 cgroup（この時点では空。名前は [`CgroupName::for_instance`]）
//! ```
//! コンテナ用子 cgroup の名前は、状態記録の create で割り当てた revision（instance `n`。ストア全体で再利用
//! されない）を含む `fc-<id>@<n>` とする（TASK-30.3・OCI-6）。同じ ID の削除・再作成をまたいでも名前が
//! 重ならないため、古いレコードを読んだ delete が再作成後のコンテナの cgroup を名前で消すことはない。
//! `@` は `ContainerId` の許容文字に無いため、`fc-runtime` や ID だけの名前とも衝突しない。
//! [`CgroupName::new`]（`fc-<id>`）は instance を持たない名前で、TASK-32 の結合試験が使う。delete はこの名前の
//! cgroup を削除しないので、本番 launcher は `for_instance` で作る。
//! 退避リーフは 1 supervisor = 1 委譲スコープを前提とする（CORE-1・D-19）。複数コンテナが同一
//! スコープを共有する運用の扱いは本番 launcher（TASK-29 / TASK-157 系）で整合させる。退避リーフは自プロセスが入るため削除せず、
//! スコープ終了時に systemd が回収する。
//!
//! # 実装済みの資源制限
//! - `cpu.max`（TASK-32.3・#160）: [`ContainerCgroup::set_cpu_max`]（`cpu` サブモジュール。起動フローからは
//!   未呼び出しで、本番 launcher〔TASK-29 / TASK-157 系〕で結線する）。`--cpus` 相当値の変換
//!   [`CpuMax::parse_cpus`]（TASK-170.1・SUP-13）を含む
//! - `memory.max` / `memory.swap.max`（TASK-32.2・#159）: [`ContainerCgroup::set_memory_limits`]
//!   （同上。未結線）
//! - `pids.max` / `io.max`（SUP-13・TASK-170.2・#533）: [`ContainerCgroup::set_pids_max`]（`pids` サブモジュール）・
//!   [`ContainerCgroup::set_io_max`]（`io_max` サブモジュール。1 デバイス分の絶対値スロットル）（同上。未結線）
//! - `io.weight`（SUP-13・TASK-170.4・#1474）: [`ContainerCgroup::set_io_weight`]（`io_weight` サブモジュール）と
//!   `--blkio-weight` の変換 [`IoWeight::from_blkio_weight`]（同上。未結線）
//! - fork 後の子の `cgroup.procs` 参加（TASK-32.4・#161）: [`ContainerCgroup::join_hook`] が返す
//!   [`CgroupJoin`] を `exec::StagePipeline` の `CgroupJoin` 段へ登録する（`exec::StageHook` 実装済み）
//! - exec 経路の cgroup 参加（SUP-6・TASK-163.2・#501）: 記録した cgroup パスから fd で開いて `cgroup.procs` へ
//!   書く `exec_join` サブモジュール（`exec::prepare_cgroup_join` / `join_cgroup` の実体。起動経路の
//!   [`CgroupJoin`] とは別の入口）
//!
//! - delete 時の cgroup 削除（TASK-30.3・OCI-6）: [`DelegatedCgroup::open_child`] で名前から既存の子 cgroup を
//!   検証つきで開き、`oci_runtime::ContainerCgroupRemover` の実装として [`DelegatedCgroup::remove_child`] へ渡す
//!   （`oci_runtime::delete` が状態記録の削除の前に呼ぶ。本番の呼び出し元による結線は未実装）。
//!   `ContainerCgroupRemover::scope` は検出した委譲パス（[`DelegatedCgroup::path`] と同じ文字列）を返し、
//!   delete は状態に記録された配置（`StateRecord::cgroup`）のスコープと一致するときだけ、記録された instance の
//!   名前（`fc-<id>@<n>`）で削除・不存在確認を行う
//!
//! # 未実装（REPAIR-3）
//! - OCI `linux.resources` から `set_memory_limits` / `set_cpu_max` への反映、本番 launcher での
//!   `detect` → `prepare` → `join_hook` の結線（TASK-29 / TASK-157 系）
//! - OCI `linux.cgroupsPath` の反映・create での委譲スコープの記録（`CreateStateRequest::with_cgroup_scope`）と
//!   delete への本番の呼び出し元（CLI / plugin / supervisor）からの結線
//! - OCI `linux.resources.pids` / `blockIO`（weight を含む）からの `set_pids_max` / `set_io_max` /
//!   `set_io_weight` への反映（TASK-170.3 ほか）
//! - cgroup v1 / hybrid は非対応（CORE-4。v2 以外は fail-closed）

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;

use crate::oci_runtime::{CgroupRemoval, ContainerCgroupRemover};
use crate::sys::{self, SysError};
use crate::traits::{CgroupScope, ContainerId, ErrorCode, StateRevision, TraitError};

mod cpu;
pub use cpu::{CpuMax, CpuQuota, NANO_CPUS_PER_CPU};
mod io_max;
pub use io_max::{BlockDevice, IoLimit, IoMax};
mod io_weight;
pub use io_weight::{
    BLKIO_WEIGHT_MAX, BLKIO_WEIGHT_MIN, IO_WEIGHT_DEFAULT, IO_WEIGHT_MAX, IO_WEIGHT_MIN, IoWeight,
};
mod pids;
pub use pids::{PIDS_MAX_LIMIT, PidsMax};
mod exec_join;
mod exec_kill;
pub(crate) use exec_join::{ExecJoinFds, contains_pid, open_cgroup_by_path};
pub(crate) use exec_kill::{
    ExecChildCgroupFds, ExecChildRemoval, remove_exec_child_cgroup_at, validate_exec_child_name,
};

/// 退避リーフ cgroup の名前。自プロセスの移動先（レイアウトは本モジュール冒頭を参照）。
const EVACUATION_LEAF: &str = "fc-runtime";
/// コンテナ用子 cgroup の接頭辞。`cgroup.procs` 等のインターフェースファイル名との衝突を避ける。
const CONTAINER_PREFIX: &str = "fc-";
/// コンテナ ID と instance の区切り（`ContainerId` の許容文字に含まれない。TASK-30.3）。
const INSTANCE_SEPARATOR: char = '@';
/// cgroup 名（ディレクトリ要素）の最大バイト数（`NAME_MAX`）。
const NAME_MAX: usize = 255;
/// `/proc/self/cgroup` の読み取り上限。
const SELF_CGROUP_LIMIT: u64 = 64 * 1024;
/// `cgroup.procs` の読み取り上限。
const PROCS_LIMIT: u64 = 1024 * 1024;
/// `cgroup.controllers` / `cgroup.subtree_control` / `cgroup.type` の読み取り上限。
const SMALL_FILE_LIMIT: u64 = 4 * 1024;
/// `io.stat` の読み取り上限。デバイス数に比例して伸びるため他の小さなファイルより大きく取る。
const IO_STAT_LIMIT: u64 = 256 * 1024;
/// cgroup パスの要素数の上限。
const MAX_PATH_DEPTH: usize = 64;
/// 子 cgroup ディレクトリのモード（umask 適用前。cgroup の所有者のみ書き込み可）。
const CGROUP_DIR_MODE: u32 = 0o755;

/// 失敗した段（機械可読。AI 自己補修・ログでの切り分け用。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupStep {
    /// `/proc/self/cgroup` の読み取り・解析。
    ReadSelfCgroup,
    /// `/sys/fs/cgroup` から委譲 cgroup までのディレクトリを開く段。
    OpenRoot,
    /// cgroup2 ファイルシステムであることの検証。
    VerifyCgroup2,
    /// 委譲（所有者・`cgroup.type`）の検証。
    CheckDelegation,
    /// `cgroup.controllers` / `cgroup.subtree_control` の読み取り。
    ReadControllers,
    /// 子 cgroup の作成。
    CreateChild,
    /// 自プロセスの退避。
    Evacuate,
    /// 退避状態の検証。
    VerifyEvacuation,
    /// controller の有効化。
    EnableControllers,
    /// 失敗後の後始末。
    Cleanup,
    /// `memory.max` / `memory.swap.max` の設定（TASK-32.2）。
    SetMemoryLimit,
    /// `cpu.max` の検証・書き込み・読み戻し。
    SetCpuMax,
    /// `pids.max` の検証・書き込み・読み戻し（SUP-13・TASK-170.2）。
    SetPidsMax,
    /// `io.max` の検証・書き込み・読み戻し（SUP-13・TASK-170.2）。
    SetIoMax,
    /// `io.weight` の検証・書き込み・読み戻し（SUP-13・TASK-170.4）。
    SetIoWeight,
    /// fork 後の子プロセスの `cgroup.procs` への参加（TASK-32.4）。
    JoinContainer,
    /// `memory.current` / `cpu.stat` / `io.stat` の読み取り（SUP-10・TASK-167.1）。
    ReadStats,
}

/// cgroup 操作のエラー。`code` は ERR 系の機械可読コード、`message` は英語の説明。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupError {
    /// 機械可読なエラーコード。
    pub code: ErrorCode,
    /// 失敗した段。
    pub step: CgroupStep,
    /// 人間向けの説明（英語）。
    pub message: String,
}

impl CgroupError {
    fn new(code: ErrorCode, step: CgroupStep, message: impl Into<String>) -> Self {
        Self {
            code,
            step,
            message: message.into(),
        }
    }

    fn precondition(step: CgroupStep, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::FailedPrecondition, step, message)
    }
}

impl fmt::Display for CgroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:?}: {}",
            self.code.as_str(),
            self.step,
            self.message
        )
    }
}

impl std::error::Error for CgroupError {}

/// errno を `ErrorCode` へ写す。
fn errno_code(errno: i32) -> ErrorCode {
    if errno == sys::EPERM || errno == sys::EACCES {
        ErrorCode::PermissionDenied
    } else if errno == sys::EBUSY || errno == sys::ENOTEMPTY {
        ErrorCode::FailedPrecondition
    } else if errno == sys::EEXIST {
        ErrorCode::AlreadyExists
    } else if errno == sys::ENOENT {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    }
}

fn sys_error(step: CgroupStep, what: &str, err: SysError) -> CgroupError {
    match err {
        SysError::Unsupported => CgroupError::new(
            ErrorCode::Unimplemented,
            step,
            format!("{what}: unsupported architecture"),
        ),
        SysError::Os(errno) => {
            CgroupError::new(errno_code(errno), step, format!("{what}: errno {errno}"))
        }
        SysError::MultiThreaded => CgroupError::new(
            ErrorCode::FailedPrecondition,
            step,
            format!("{what}: multi-threaded process"),
        ),
    }
}

fn io_error(step: CgroupStep, what: &str, err: &std::io::Error) -> CgroupError {
    match err.raw_os_error() {
        Some(errno) => CgroupError::new(errno_code(errno), step, format!("{what}: errno {errno}")),
        None => CgroupError::new(ErrorCode::Internal, step, format!("{what}: {}", err.kind())),
    }
}

// ---------------------------------------------------------------------------------------------
// 純関数（カーネル応答の解析。`unsafe`・I/O なし）
// ---------------------------------------------------------------------------------------------

/// 検証済みの cgroup 相対パス（`/sys/fs/cgroup` 起点。ルート cgroup は空）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupPath {
    components: Vec<String>,
}

impl CgroupPath {
    fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    fn child(&self, name: &str) -> Self {
        let mut components = self.components.clone();
        components.push(name.to_owned());
        Self { components }
    }

    /// `"/a/b"` 形式（ルートは `"/"`）。
    fn display(&self) -> String {
        if self.components.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", self.components.join("/"))
        }
    }
}

/// パス要素 1 つを検証する（`.`・`..`・空・NUL・過大長を拒否）。
fn validate_component(step: CgroupStep, comp: &str) -> Result<(), CgroupError> {
    if comp.is_empty()
        || comp == "."
        || comp == ".."
        || comp.len() > NAME_MAX
        || comp.contains('\0')
    {
        return Err(CgroupError::precondition(
            step,
            "cgroup path contains an invalid component",
        ));
    }
    Ok(())
}

/// `/proc/self/cgroup` の内容から v2 unified 行（`0::<path>`）のパスを取り出す。
///
/// v1 行（`<n>:<controllers>:<path>`）が 1 行でも混在する hybrid 構成は非対応（CORE-4・SEC-6）として
/// 拒否する。`0::` 行が無い・複数ある・`(deleted)` 付き・相対 / `..` を含む・過大長も、カーネル応答の
/// 異常として fail-closed（`FailedPrecondition`）にする。
fn parse_self_cgroup_v2(text: &str) -> Result<CgroupPath, CgroupError> {
    let step = CgroupStep::ReadSelfCgroup;
    let mut found: Option<&str> = None;
    for line in text.lines() {
        if !line.is_empty() && !line.starts_with("0::") {
            return Err(CgroupError::precondition(
                step,
                "cgroup v1 or hybrid hierarchy detected in /proc/self/cgroup (only pure cgroup v2 is supported)",
            ));
        }
        if let Some(path) = line.strip_prefix("0::") {
            if found.is_some() {
                return Err(CgroupError::precondition(
                    step,
                    "multiple cgroup v2 entries in /proc/self/cgroup",
                ));
            }
            found = Some(path);
        }
    }
    let path = found.ok_or_else(|| {
        CgroupError::precondition(
            step,
            "no cgroup v2 entry in /proc/self/cgroup (v1/hybrid only)",
        )
    })?;
    if path.ends_with(" (deleted)") {
        return Err(CgroupError::precondition(
            step,
            "own cgroup has been deleted",
        ));
    }
    let rest = path.strip_prefix('/').ok_or_else(|| {
        CgroupError::precondition(step, "cgroup path in /proc/self/cgroup is not absolute")
    })?;
    if rest.is_empty() {
        return Ok(CgroupPath {
            components: Vec::new(),
        });
    }
    let mut components = Vec::new();
    for comp in rest.split('/') {
        validate_component(step, comp)?;
        if components.len() >= MAX_PATH_DEPTH {
            return Err(CgroupError::precondition(step, "cgroup path is too deep"));
        }
        components.push(comp.to_owned());
    }
    Ok(CgroupPath { components })
}

/// 既知の cgroup v2 controller。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Controller {
    /// `cpu`（`cpu.max` 等。TASK-32.3）。
    Cpu,
    /// `cpuset`。
    Cpuset,
    /// `io`。
    Io,
    /// `memory`（`memory.max` 等。TASK-32.2）。
    Memory,
    /// `hugetlb`。
    Hugetlb,
    /// `pids`。
    Pids,
    /// `rdma`。
    Rdma,
    /// `misc`。
    Misc,
}

impl Controller {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cpuset => "cpuset",
            Self::Io => "io",
            Self::Memory => "memory",
            Self::Hugetlb => "hugetlb",
            Self::Pids => "pids",
            Self::Rdma => "rdma",
            Self::Misc => "misc",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "cpu" => Self::Cpu,
            "cpuset" => Self::Cpuset,
            "io" => Self::Io,
            "memory" => Self::Memory,
            "hugetlb" => Self::Hugetlb,
            "pids" => Self::Pids,
            "rdma" => Self::Rdma,
            "misc" => Self::Misc,
            _ => return None,
        })
    }
}

/// controller の集合。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControllerSet {
    items: BTreeSet<Controller>,
}

impl ControllerSet {
    /// 指定した controller から集合を作る。
    pub fn of(controllers: &[Controller]) -> Self {
        Self {
            items: controllers.iter().copied().collect(),
        }
    }

    /// `cgroup.controllers` / `cgroup.subtree_control` の空白区切りトークンを解析する。
    /// 未知のトークンは将来のカーネル互換のため無視する。
    pub fn parse(text: &str) -> Self {
        Self {
            items: text
                .split_whitespace()
                .filter_map(Controller::from_token)
                .collect(),
        }
    }

    /// `controller` を含むか。
    pub fn contains(&self, controller: Controller) -> bool {
        self.items.contains(&controller)
    }

    /// 要素を昇順で列挙する。
    pub fn iter(&self) -> impl Iterator<Item = Controller> + '_ {
        self.items.iter().copied()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// `self` がすべて `other` に含まれるか。
    fn is_subset(&self, other: &Self) -> bool {
        self.items.is_subset(&other.items)
    }

    /// `cgroup.subtree_control` へ書く `+a +b` 形式。
    fn to_enable_request(&self) -> String {
        self.items
            .iter()
            .map(|c| format!("+{}", c.as_str()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// `cgroup.procs` の内容（改行区切りの PID 列）を解析する。非数値は `FailedPrecondition`。
fn parse_procs(step: CgroupStep, text: &str) -> Result<Vec<u32>, CgroupError> {
    let mut pids = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let pid = line.trim().parse::<u32>().map_err(|_| {
            CgroupError::precondition(step, "cgroup.procs contains a non-numeric entry")
        })?;
        pids.push(pid);
    }
    Ok(pids)
}

/// `cgroup.subtree_control` へ書き込んだ後に読み戻した集合 `enabled` が、要求 `want` をすべて含むことを
/// 検証する（CORE-3）。カーネルは 1 回の書き込みを全部か無しで適用するため、書き込み成功後の不足は
/// 同じ親を操作する別主体の `-<controller>` 書き込み等の競合を意味する。要求を満たさない状態を成功と
/// して返さないよう `FailedPrecondition` にする（何が有効だったかは書き込み前に分からないため巻き戻さない）。
fn verify_enabled(want: &ControllerSet, enabled: &ControllerSet) -> Result<(), CgroupError> {
    let missing: Vec<&str> = want
        .iter()
        .filter(|c| !enabled.contains(*c))
        .map(Controller::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(CgroupError::precondition(
        CgroupStep::EnableControllers,
        format!(
            "controllers not enabled after writing cgroup.subtree_control: {}",
            missing.join(" ")
        ),
    ))
}

/// 削除後に保持 fd 経由で interface ファイルを開いた結果が「保持していた cgroup が削除済み」を示すか。
///
/// `rmdir` 成功後のディレクトリ inode は dead（`S_DEAD`）になり、それを起点にした lookup は `ENOENT`
/// を返す。削除済みの証拠として扱うのは `ENOENT` だけで、`EACCES`・`EINTR`・`EMFILE` 等の他の失敗は
/// 保持していた cgroup が残っている可能性を否定できないため成功扱いしない（fail-closed）。
fn removal_confirmed(err: &SysError) -> bool {
    matches!(err, SysError::Os(e) if *e == sys::ENOENT)
}

/// 要求された controller が利用可能集合に収まることを書き込み前に検証する。
fn validate_controller_request(
    available: &ControllerSet,
    want: &ControllerSet,
) -> Result<(), CgroupError> {
    if want.is_empty() {
        return Err(CgroupError::new(
            ErrorCode::InvalidArgument,
            CgroupStep::EnableControllers,
            "no controllers requested",
        ));
    }
    if !want.is_subset(available) {
        return Err(CgroupError::precondition(
            CgroupStep::EnableControllers,
            "requested controllers are not available in the delegated cgroup",
        ));
    }
    Ok(())
}

/// コンテナ用子 cgroup の名前（`fc-<container-id>@<instance>` または `fc-<container-id>`）。検証済みの 1 要素。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupName(String);

impl CgroupName {
    /// `ContainerId`（文字種検証済み）から名前を作る。接頭辞込みで 255 バイトを超えると
    /// `InvalidArgument`。`fc-runtime`（退避リーフ）と同名になる ID `runtime` は拒否する。
    pub fn new(id: &ContainerId) -> Result<Self, CgroupError> {
        let name = format!("{CONTAINER_PREFIX}{}", id.as_str());
        if name.len() > NAME_MAX {
            return Err(CgroupError::new(
                ErrorCode::InvalidArgument,
                CgroupStep::CreateChild,
                "cgroup name exceeds 255 bytes",
            ));
        }
        if name == EVACUATION_LEAF {
            return Err(CgroupError::new(
                ErrorCode::InvalidArgument,
                CgroupStep::CreateChild,
                "container id \"runtime\" is reserved for the evacuation leaf",
            ));
        }
        Ok(Self(name))
    }

    /// 状態記録の cgroup 配置の instance（create 時の revision）を含む名前 `fc-<id>@<n>` を作る
    /// （TASK-30.3・OCI-6。本番のコンテナ用 cgroup の名前。モジュール doc「レイアウト」）。
    ///
    /// instance はストア全体で再利用されないため、同じ ID でも別のレコードとは名前が重ならない。
    /// 255 バイトを超えると `InvalidArgument`（`prepare` でも delete でも同じ規則なので、作れない名前の
    /// cgroup は存在しない）。
    pub fn for_instance(id: &ContainerId, instance: StateRevision) -> Result<Self, CgroupError> {
        let name = format!(
            "{CONTAINER_PREFIX}{}{INSTANCE_SEPARATOR}{}",
            id.as_str(),
            instance.value()
        );
        if name.len() > NAME_MAX {
            return Err(CgroupError::new(
                ErrorCode::InvalidArgument,
                CgroupStep::CreateChild,
                "cgroup name exceeds 255 bytes",
            ));
        }
        Ok(Self(name))
    }

    /// 名前の文字列表現（`fc-<id>@<n>` または `fc-<id>`）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------------------------
// fd ベースの操作
// ---------------------------------------------------------------------------------------------

fn cstring(step: CgroupStep, s: &str) -> Result<CString, CgroupError> {
    CString::new(s).map_err(|_| CgroupError::precondition(step, "name contains NUL"))
}

/// fd から上限付きで UTF-8 文字列を読む。上限超過・非 UTF-8 は `FailedPrecondition`。
fn read_limited(step: CgroupStep, fd: OwnedFd, limit: u64) -> Result<String, CgroupError> {
    let mut buf = Vec::new();
    File::from(fd)
        .take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_error(step, "read", &e))?;
    if buf.len() as u64 > limit {
        return Err(CgroupError::precondition(
            step,
            "kernel response exceeds size limit",
        ));
    }
    String::from_utf8(buf)
        .map_err(|_| CgroupError::precondition(step, "kernel response is not valid UTF-8"))
}

/// `dir` 配下のインターフェースファイルを上限付きで読む。
fn read_iface(
    step: CgroupStep,
    dir: BorrowedFd<'_>,
    file: &str,
    limit: u64,
) -> Result<String, CgroupError> {
    let name = cstring(step, file)?;
    let fd = sys::open_read_at(dir, &name).map_err(|e| sys_error(step, file, e))?;
    read_limited(step, fd, limit)
}

fn read_self_cgroup() -> Result<CgroupPath, CgroupError> {
    let step = CgroupStep::ReadSelfCgroup;
    let file = File::open("/proc/self/cgroup")
        .map_err(|e| io_error(step, "open /proc/self/cgroup", &e))?;
    let text = read_limited(step, OwnedFd::from(file), SELF_CGROUP_LIMIT)?;
    parse_self_cgroup_v2(&text)
}

/// fd の (dev, ino)（O_PATH fd でも `fstat` できる）。同一ディレクトリ判定に使う。
/// `step` は失敗時のエラーに載せる呼び出し元の段（REPAIR-4 の切り分け用）。
fn dir_identity(
    step: CgroupStep,
    fd: BorrowedFd<'_>,
    what: &str,
) -> Result<(u64, u64), CgroupError> {
    let dup = fd
        .try_clone_to_owned()
        .map_err(|e| io_error(step, what, &e))?;
    File::from(dup)
        .metadata()
        .map(|m| (m.dev(), m.ino()))
        .map_err(|e| io_error(step, what, &e))
}

fn verify_cgroup2(fd: BorrowedFd<'_>, what: &str) -> Result<(), CgroupError> {
    let step = CgroupStep::VerifyCgroup2;
    let t = sys::fs_type(fd).map_err(|e| sys_error(step, what, e))?;
    if t != sys::CGROUP2_MAGIC {
        return Err(CgroupError::precondition(
            step,
            format!("{what} is not a cgroup2 filesystem"),
        ));
    }
    Ok(())
}

/// fd の所有者 uid（O_PATH fd でも `fstat` できる）。
fn owner_uid(step: CgroupStep, fd: OwnedFd, what: &str) -> Result<u32, CgroupError> {
    File::from(fd)
        .metadata()
        .map(|m| m.uid())
        .map_err(|e| io_error(step, what, &e))
}

/// `dir` 配下の cgroup ディレクトリを O_PATH で開き、cgroup2 であることを確認する。
fn open_cgroup_dir(
    step: CgroupStep,
    dir: BorrowedFd<'_>,
    name: &str,
) -> Result<OwnedFd, CgroupError> {
    let c = cstring(step, name)?;
    let fd = sys::open_dir_path_nofollow(Some(dir), &c).map_err(|e| sys_error(step, name, e))?;
    verify_cgroup2(fd.as_fd(), name)?;
    Ok(fd)
}

/// `/sys/fs/cgroup`（cgroup v2 ルート）を O_PATH で開き、cgroup2 であることを確認する。
///
/// `DelegatedCgroup::detect`（自プロセスの cgroup を辿る起点）と `exec_join`（記録した cgroup パスを辿る
/// 起点。SUP-6・TASK-163.2）が共用する。各要素は `O_NOFOLLOW` で開く。
fn open_cgroup_root() -> Result<OwnedFd, CgroupError> {
    let open_step = CgroupStep::OpenRoot;
    let mut cur = {
        let slash = cstring(open_step, "/")?;
        sys::open_dir_path_nofollow(None, &slash).map_err(|e| sys_error(open_step, "/", e))?
    };
    for comp in ["sys", "fs", "cgroup"] {
        let c = cstring(open_step, comp)?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c)
            .map_err(|e| sys_error(open_step, comp, e))?;
    }
    verify_cgroup2(cur.as_fd(), "/sys/fs/cgroup")?;
    Ok(cur)
}

/// 委譲された cgroup（検出結果）。
#[derive(Debug)]
pub struct DelegatedCgroup {
    path: CgroupPath,
    fd: OwnedFd,
    controllers: ControllerSet,
}

/// コンテナ用子 cgroup。O_PATH ディレクトリ fd を保持し、fork 後の子が fd 経由で `cgroup.procs` へ
/// 書けるようにする（`exec/stages.rs` の契約。TASK-32.4）。
#[derive(Debug)]
pub struct ContainerCgroup {
    name: CgroupName,
    fd: OwnedFd,
    /// 作成時の親 cgroup の (dev, ino)。`remove_child` で別スコープの親への流用を拒否する。
    parent_id: (u64, u64),
}

impl ContainerCgroup {
    /// cgroup 名。
    pub fn name(&self) -> &CgroupName {
        &self.name
    }

    /// cgroup ディレクトリの fd（O_PATH。`openat` の dirfd 専用）。
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// テスト専用: 通常のディレクトリ fd から組み立てる（CORE-3・TASK-32.5）。
    ///
    /// 実 cgroup を要さず `set_memory_limits` / `set_cpu_max` の書き込み経路を既定のテスト集合で
    /// 検証するために使う（`CgroupJoin::from_dir_for_test` と同じ位置づけ）。`parent_id` はダミーのため
    /// `DelegatedCgroup::remove_child` には渡さない。
    #[cfg(test)]
    pub(crate) fn from_dir_for_test(name: CgroupName, fd: OwnedFd) -> Self {
        Self {
            name,
            fd,
            parent_id: (0, 0),
        }
    }
}

/// fork 後の子プロセスが自分自身をコンテナ用子 cgroup へ参加させるためのフック（CORE-3・TASK-32.4）。
///
/// [`ContainerCgroup::join_hook`] が親で作り、`exec::StagePipeline` の `CgroupJoin` 段へ登録する。
/// 検証済みの O_PATH ディレクトリ fd（`O_CLOEXEC`）だけを保持し、パス文字列では再解決しない
/// （pivot 後はホストの `/sys/fs/cgroup` が見えないため。symlink・TOCTOU 対策）。
/// 契約: fork 後の子でのみ `CgroupJoin::join_current_process` が呼ばれる。親で呼ぶと runtime 自身が
/// コンテナ cgroup へ移るため `pub(crate)` に留める。cgroup namespace（`CLONE_NEWCGROUP`）導入時は
/// 親で `cgroup.procs` を書き込み用に事前 open する方式へ切り替える（未導入のため現状は不要）。
pub struct CgroupJoin {
    name: CgroupName,
    fd: OwnedFd,
}

impl fmt::Debug for CgroupJoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CgroupJoin")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// `cgroup.procs` を読み戻した `text` に `pid` が含まれることを検証する（fail-closed）。
fn verify_joined(pid: u32, text: &str) -> Result<(), CgroupError> {
    let step = CgroupStep::JoinContainer;
    if parse_procs(step, text)?.contains(&pid) {
        Ok(())
    } else {
        Err(CgroupError::precondition(
            step,
            "own pid is not listed in cgroup.procs after the join",
        ))
    }
}

impl CgroupJoin {
    /// 自プロセスの TGID を `cgroup.procs` へ書き、読み戻して参加を確認する。
    ///
    /// 呼び出し元: `exec::stages` の `CgroupJoin` 段（fork 後・pivot 後・capability 削減前の子）。
    /// カーネルは書き手の PID namespace で解決するため、新 PID ns の PID 1 でも自分自身を指す。
    pub(crate) fn join_current_process(&mut self) -> Result<(), CgroupError> {
        let step = CgroupStep::JoinContainer;
        let pid = std::process::id();
        let procs = cstring(step, "cgroup.procs")?;
        let wfd = sys::open_write_at(self.fd.as_fd(), &procs)
            .map_err(|e| sys_error(step, "cgroup.procs", e))?;
        File::from(wfd)
            .write_all(pid.to_string().as_bytes())
            .map_err(|e| io_error(step, "cgroup.procs", &e))?;
        verify_joined(
            pid,
            &read_iface(step, self.fd.as_fd(), "cgroup.procs", PROCS_LIMIT)?,
        )
    }

    /// テスト用: 任意のディレクトリ fd から組み立てる。
    #[cfg(test)]
    pub(crate) fn from_dir_for_test(name: CgroupName, fd: OwnedFd) -> Self {
        Self { name, fd }
    }
}

impl ContainerCgroup {
    /// 子プロセスの参加フックを作る（fd を `F_DUPFD_CLOEXEC` で複製）。
    ///
    /// 呼び出し順: `detect` / `prepare`（および任意の資源制限設定）→ 本メソッド → `isolate`（user ns 等へ
    /// 入る）→ `StagePipeline::with_hook(StageKind::CgroupJoin, hook)`。`detect` / `prepare` は
    /// `isolate` より前に呼ぶこと（pivot 後はホストの cgroupfs が見えず、所有者検証の前提も変わる）。
    pub fn join_hook(&self) -> Result<CgroupJoin, CgroupError> {
        let fd = self
            .fd
            .try_clone()
            .map_err(|e| io_error(CgroupStep::JoinContainer, "duplicate cgroup fd", &e))?;
        Ok(CgroupJoin {
            name: self.name.clone(),
            fd,
        })
    }
}

/// 自プロセスの退避が完了し検証済みであることの証明。`cgroups` モジュール内でのみ生成できる。
#[derive(Debug)]
pub struct Evacuated {
    /// 退避元（委譲された親）のパス。別の委譲スコープへの流用を防ぐ。
    parent: CgroupPath,
    /// 退避元の親 cgroup ディレクトリの (dev, ino)。同パスの cgroup が置換された場合の検出に使う。
    parent_id: (u64, u64),
}

/// `prepare` の途中失敗時に巻き戻す対象の記録。
#[derive(Debug, Default)]
struct Rollback {
    /// 自プロセスを退避リーフへ移した（または移した可能性がある）。
    moved: bool,
    /// 退避リーフを本処理が新規作成した（既存の再利用では削除しない）。
    leaf_created: bool,
    /// 新規作成した退避リーフの fd（`leaf_created` のときのみ）。削除時の同一性確認に使う。
    /// 作成後に開けなかった場合は `None` のままで、名前指定の削除に落ちる（結果に未検証と記す）。
    leaf_fd: Option<OwnedFd>,
}

/// `parent` 配下の `name` を名前指定で削除する（保持 fd が無い巻き戻し経路専用）。
/// 削除した実体が本処理の作成物か確認できないため、成否にかかわらず結果を `err` に併記する。
fn remove_unverified(parent: BorrowedFd<'_>, name: &str, err: &mut CgroupError) {
    let step = CgroupStep::Cleanup;
    let outcome = cstring(step, name)
        .and_then(|c| sys::remove_dir_at(parent, &c).map_err(|e| sys_error(step, "rmdir", e)));
    match outcome {
        Ok(()) => err.message.push_str(&format!(
            "; {name} was removed by name without identity verification"
        )),
        Err(e) => err
            .message
            .push_str(&format!("; cleanup of {name} failed ({})", e.message)),
    }
}

impl DelegatedCgroup {
    /// 委譲された cgroup（自プロセスが属する cgroup v2）を検出する。
    ///
    /// 検証: v2 unified 行の取得・`/sys/fs/cgroup` と対象の cgroup2 確認・委譲（euid が 0、または
    /// ディレクトリ・`cgroup.procs`・`cgroup.subtree_control` の所有者が euid）・`cgroup.type` が
    /// `domain`。ルート cgroup は euid 0 のときのみ許可する。
    pub fn detect() -> Result<Self, CgroupError> {
        let path = read_self_cgroup()?;
        let euid = sys::effective_uid();
        if path.is_root() && euid != 0 {
            return Err(CgroupError::new(
                ErrorCode::PermissionDenied,
                CgroupStep::CheckDelegation,
                "own cgroup is the root cgroup and the process is not root",
            ));
        }
        let open_step = CgroupStep::OpenRoot;
        let mut cur = open_cgroup_root()?;
        for comp in &path.components {
            cur = open_cgroup_dir(open_step, cur.as_fd(), comp)?;
        }
        let fd = cur;

        if euid != 0 {
            check_owned_by(&fd, euid)?;
        }
        // `cgroup.type` はルート cgroup にのみ存在しない。非ルートで欠落する場合は
        // 委譲済みと確認できないため fail-closed でエラーにする（ENOENT を許容するのはルートのみ）。
        match read_iface(
            CgroupStep::CheckDelegation,
            fd.as_fd(),
            "cgroup.type",
            SMALL_FILE_LIMIT,
        ) {
            Ok(t) if t.trim() != "domain" => {
                return Err(CgroupError::precondition(
                    CgroupStep::CheckDelegation,
                    "delegated cgroup is not of type domain",
                ));
            }
            Ok(_) => {}
            Err(e) if e.code == ErrorCode::NotFound && path.is_root() => {}
            Err(e) => return Err(e),
        }
        let controllers = ControllerSet::parse(&read_iface(
            CgroupStep::ReadControllers,
            fd.as_fd(),
            "cgroup.controllers",
            SMALL_FILE_LIMIT,
        )?);
        Ok(Self {
            path,
            fd,
            controllers,
        })
    }

    /// 親 cgroup で利用可能な controller（`cgroup.controllers`）。
    pub fn controllers(&self) -> &ControllerSet {
        &self.controllers
    }

    /// 委譲された cgroup のパス（`/sys/fs/cgroup` 起点。例 `/user.slice/x.scope`）。
    pub fn path(&self) -> String {
        self.path.display()
    }

    /// 親 cgroup ディレクトリの fd（O_PATH）。
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// コンテナ用子 cgroup を作り、自プロセスを退避リーフへ移し、退避を検証する。
    ///
    /// 検証（すべて満たさなければ `FailedPrecondition`）: 自プロセスの現在の所属が検出済みの親で親の
    /// `cgroup.procs` に自プロセスがいる・親の `cgroup.procs` に自プロセス以外が
    /// いない（他者の PID は動かさない）・退避後に親の `cgroup.procs` が空・`/proc/self/cgroup` が
    /// 退避リーフを指す・コンテナ用子 cgroup の `cgroup.procs` が空。既存の同名子 cgroup は採用せず
    /// `AlreadyExists`。途中失敗時は、自プロセスを移していれば元の親へ戻して所属を読み戻しで検証し、
    /// 本処理が作った子 cgroup・退避リーフを作成直後に固定した fd との同一性を確認してから best-effort で
    /// 削除する（`Self::remove_verified`。巻き戻しの失敗・fd が無く名前指定で消した事実はエラー文に併記）。
    ///
    /// 呼び出し元は、本関数で子 cgroup を作る前にこの委譲スコープ（`ContainerCgroupRemover::scope`）を
    /// 状態記録へ記録し（`CreateStateRequest::with_cgroup_scope`。TASK-30.3・OCI-6）、返された配置の instance
    /// から [`CgroupName::for_instance`] で作った名前を渡す。記録の無いレコードの `oci_runtime::delete` は
    /// cgroup に触れず、`fc-<id>@<n>` 以外の名前の cgroup も削除しないため、それ以外の手順で作った子 cgroup は
    /// 回収されない。
    pub fn prepare(&self, name: &CgroupName) -> Result<(ContainerCgroup, Evacuated), CgroupError> {
        let me = std::process::id();
        let parent_procs = parse_procs(
            CgroupStep::Evacuate,
            &read_iface(
                CgroupStep::Evacuate,
                self.fd.as_fd(),
                "cgroup.procs",
                PROCS_LIMIT,
            )?,
        )?;
        // detect 後に自プロセスが別 cgroup へ移っていると、別の所属先から退避リーフへ移してしまう。
        // 現在の所属が検出済みの親であり、親の PID 一覧に自プロセスがいることを退避前に確認する。
        let current = read_self_cgroup().map_err(|mut e| {
            e.step = CgroupStep::Evacuate;
            e
        })?;
        if current != self.path || !parent_procs.contains(&me) {
            return Err(CgroupError::precondition(
                CgroupStep::Evacuate,
                "current process is not in the detected delegated cgroup; refusing to evacuate",
            ));
        }
        if parent_procs.iter().any(|p| *p != me) {
            return Err(CgroupError::precondition(
                CgroupStep::Evacuate,
                "delegated cgroup contains other processes; refusing to move them",
            ));
        }

        let child_name = cstring(CgroupStep::CreateChild, name.as_str())?;
        sys::mkdir_at(self.fd.as_fd(), &child_name, CGROUP_DIR_MODE)
            .map_err(|e| sys_error(CgroupStep::CreateChild, name.as_str(), e))?;
        // 作成直後の子を fd で固定する。以後の巻き戻しはこの fd との同一性を確認してから削除する。
        let child_fd =
            match open_cgroup_dir(CgroupStep::CreateChild, self.fd.as_fd(), name.as_str()) {
                Ok(fd) => fd,
                Err(mut err) => {
                    remove_unverified(self.fd.as_fd(), name.as_str(), &mut err);
                    return Err(err);
                }
            };

        let mut rollback = Rollback::default();
        match self.evacuate_and_verify(child_fd.as_fd(), &mut rollback) {
            Ok(parent_id) => Ok((
                ContainerCgroup {
                    name: name.clone(),
                    fd: child_fd,
                    parent_id,
                },
                Evacuated {
                    parent: self.path.clone(),
                    parent_id,
                },
            )),
            Err(mut err) => {
                // 自プロセスを退避リーフへ移した後の失敗は、元の親へ戻してから子・退避リーフを削除する。
                if rollback.moved
                    && let Err(e) = self.restore_self()
                {
                    err.message.push_str(&format!(
                        "; restoring process membership failed ({})",
                        e.message
                    ));
                }
                if rollback.leaf_created {
                    match &rollback.leaf_fd {
                        Some(leaf_fd) => {
                            if let Err(e) = self.remove_verified(EVACUATION_LEAF, leaf_fd.as_fd()) {
                                err.message.push_str(&format!(
                                    "; cleanup of {EVACUATION_LEAF} failed ({})",
                                    e.message
                                ));
                            }
                        }
                        None => remove_unverified(self.fd.as_fd(), EVACUATION_LEAF, &mut err),
                    }
                }
                if let Err(e) = self.remove_verified(name.as_str(), child_fd.as_fd()) {
                    err.message.push_str(&format!(
                        "; cleanup of {} failed ({})",
                        name.as_str(),
                        e.message
                    ));
                }
                Err(err)
            }
        }
    }

    /// 自プロセスを委譲された親 cgroup へ戻す（退避後に失敗した場合の巻き戻し）。
    ///
    /// 書き込みの成功だけでは所属の復元を確認できないため、書き込み後に `/proc/self/cgroup` が
    /// 検出済みの親を指すことを読み戻して検証する（不一致は `FailedPrecondition`）。
    fn restore_self(&self) -> Result<(), CgroupError> {
        let step = CgroupStep::Cleanup;
        let procs = cstring(step, "cgroup.procs")?;
        let wfd = sys::open_write_at(self.fd.as_fd(), &procs)
            .map_err(|e| sys_error(step, "open parent cgroup.procs", e))?;
        File::from(wfd)
            .write_all(std::process::id().to_string().as_bytes())
            .map_err(|e| io_error(step, "write parent cgroup.procs", &e))?;
        let actual = read_self_cgroup().map_err(|mut e| {
            e.step = step;
            e
        })?;
        if actual != self.path {
            return Err(CgroupError::precondition(
                step,
                format!(
                    "self cgroup is {} after restoring, expected {}",
                    actual.display(),
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    /// 自プロセスを退避リーフへ移し、退避を検証する。成功時は親 cgroup の (dev, ino) を返す。
    /// `child` は `prepare` が作成直後に固定したコンテナ用子 cgroup の fd。
    fn evacuate_and_verify(
        &self,
        child: BorrowedFd<'_>,
        rollback: &mut Rollback,
    ) -> Result<(u64, u64), CgroupError> {
        // 退避リーフ。既存なら再利用（cgroup2 であることは open_cgroup_dir が確認する）。
        let leaf_c = cstring(CgroupStep::CreateChild, EVACUATION_LEAF)?;
        match sys::mkdir_at(self.fd.as_fd(), &leaf_c, CGROUP_DIR_MODE) {
            Ok(()) => rollback.leaf_created = true,
            Err(SysError::Os(e)) if e == sys::EEXIST => {}
            Err(e) => return Err(sys_error(CgroupStep::CreateChild, EVACUATION_LEAF, e)),
        }
        let leaf_fd = open_cgroup_dir(CgroupStep::Evacuate, self.fd.as_fd(), EVACUATION_LEAF)?;
        if rollback.leaf_created {
            // 巻き戻し時の同一性確認用に複製を持たせる（失敗時は名前指定の削除に落ちる）。
            rollback.leaf_fd = Some(
                leaf_fd
                    .try_clone()
                    .map_err(|e| io_error(CgroupStep::Evacuate, "dup leaf cgroup fd", &e))?,
            );
        }

        // TGID を書くとスレッドグループ全体が移動する。
        let procs = cstring(CgroupStep::Evacuate, "cgroup.procs")?;
        let wfd = sys::open_write_at(leaf_fd.as_fd(), &procs)
            .map_err(|e| sys_error(CgroupStep::Evacuate, "open leaf cgroup.procs", e))?;
        // 書き込みが部分的に効いた場合に備え、書き込み前に移動済みとして扱う（復元は冪等）。
        rollback.moved = true;
        File::from(wfd)
            .write_all(std::process::id().to_string().as_bytes())
            .map_err(|e| io_error(CgroupStep::Evacuate, "write leaf cgroup.procs", &e))?;

        let verify = CgroupStep::VerifyEvacuation;
        // 検証 1: 親に誰も残っていない。
        let remaining = parse_procs(
            verify,
            &read_iface(verify, self.fd.as_fd(), "cgroup.procs", PROCS_LIMIT)?,
        )?;
        if !remaining.is_empty() {
            return Err(CgroupError::precondition(
                verify,
                "delegated cgroup still has processes after evacuation",
            ));
        }
        // 検証 2: 自プロセスの所属が退避リーフである。
        let expected = self.path.child(EVACUATION_LEAF);
        let actual = read_self_cgroup().map_err(|mut e| {
            e.step = verify;
            e
        })?;
        if actual != expected {
            return Err(CgroupError::precondition(
                verify,
                format!(
                    "self cgroup is {} after evacuation, expected {}",
                    actual.display(),
                    expected.display()
                ),
            ));
        }
        // 検証 3: 自プロセスがコンテナ用子 cgroup の外にいる（子が空）。
        let in_child = parse_procs(
            verify,
            &read_iface(verify, child, "cgroup.procs", PROCS_LIMIT)?,
        )?;
        if !in_child.is_empty() {
            return Err(CgroupError::precondition(
                verify,
                "container cgroup is not empty after evacuation",
            ));
        }

        dir_identity(verify, self.fd.as_fd(), "stat parent cgroup")
    }

    /// 親 cgroup の `cgroup.subtree_control` で controller を有効化し、有効化後の集合を返す。
    ///
    /// 退避済みの証明 [`Evacuated`] を要求する（no-internal-process 制約。CORE-3）。`want` が
    /// 利用可能集合に収まらない場合は書き込まず `FailedPrecondition`。書き込み後に読み戻した集合が
    /// `want` をすべて含まない場合も `FailedPrecondition`（要求を満たさない状態を成功として返さない）。
    pub fn enable_controllers(
        &self,
        proof: &Evacuated,
        want: &ControllerSet,
    ) -> Result<ControllerSet, CgroupError> {
        let step = CgroupStep::EnableControllers;
        if proof.parent != self.path {
            return Err(CgroupError::precondition(
                step,
                "evacuation proof belongs to a different cgroup",
            ));
        }
        validate_controller_request(&self.controllers, want)?;
        // トークン取得後に親が置換された・自プロセスが親へ戻った場合は書き込まない
        // （no-internal-process 制約違反の防止）。
        let current_id = dir_identity(step, self.fd.as_fd(), "stat parent cgroup")?;
        if current_id != proof.parent_id {
            return Err(CgroupError::precondition(
                step,
                "delegated cgroup no longer matches the evacuation proof",
            ));
        }
        let remaining = parse_procs(
            step,
            &read_iface(step, self.fd.as_fd(), "cgroup.procs", PROCS_LIMIT)?,
        )?;
        if !remaining.is_empty() {
            return Err(CgroupError::precondition(
                step,
                "delegated cgroup has processes again; evacuation is no longer valid",
            ));
        }
        let name = cstring(step, "cgroup.subtree_control")?;
        let wfd = sys::open_write_at(self.fd.as_fd(), &name)
            .map_err(|e| sys_error(step, "open cgroup.subtree_control", e))?;
        File::from(wfd)
            .write_all(want.to_enable_request().as_bytes())
            .map_err(|e| io_error(step, "write cgroup.subtree_control", &e))?;
        let enabled = ControllerSet::parse(&read_iface(
            step,
            self.fd.as_fd(),
            "cgroup.subtree_control",
            SMALL_FILE_LIMIT,
        )?);
        verify_enabled(want, &enabled)?;
        Ok(enabled)
    }

    /// コンテナ用子 cgroup を削除する（空であること。残りがあれば `FailedPrecondition`）。
    ///
    /// `child` は借用で受けるため、`EBUSY` 等で失敗しても呼び出し側がハンドルを保持したまま再試行できる。
    /// `child` がこの親の配下で作られたものであることを確認したうえで、`Self::remove_verified` で
    /// 同一性確認・削除・削除済み確認を行う。
    pub fn remove_child(&self, child: &ContainerCgroup) -> Result<(), CgroupError> {
        let step = CgroupStep::Cleanup;
        if child.parent_id != dir_identity(step, self.fd.as_fd(), "stat parent cgroup")? {
            return Err(CgroupError::precondition(
                step,
                "container cgroup does not belong to this delegated cgroup",
            ));
        }
        self.remove_verified(child.name.as_str(), child.fd.as_fd())
    }

    /// 名前で既存のコンテナ用子 cgroup を検証つきで開く（TASK-30.3・別プロセスの delete 用）。
    ///
    /// `prepare` と同じ `ContainerCgroup` ハンドルを、作成した同一プロセス内に限らず再取得するために使う。
    /// 存在しなければ `Ok(None)`。`O_NOFOLLOW`・O_PATH で開いて cgroup2 を確認し、euid が 0 でなければ
    /// 所有者が euid であることも確かめる（他主体が作った同名ディレクトリを採用しない。不一致は
    /// `PermissionDenied`）。返すハンドルの `parent_id` は本スコープの親で、[`Self::remove_child`] の
    /// 親照合を通る。開いた後の差し替えは `remove_verified` の同一性確認が検出する。
    pub fn open_child(&self, name: &CgroupName) -> Result<Option<ContainerCgroup>, CgroupError> {
        let step = CgroupStep::Cleanup;
        let fd = match open_cgroup_dir(step, self.fd.as_fd(), name.as_str()) {
            Ok(fd) => fd,
            Err(e) if e.code == ErrorCode::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let euid = sys::effective_uid();
        if euid != 0 {
            let dup = fd
                .try_clone()
                .map_err(|e| io_error(step, "dup container cgroup", &e))?;
            if owner_uid(step, dup, "stat container cgroup")? != euid {
                return Err(CgroupError::new(
                    ErrorCode::PermissionDenied,
                    step,
                    "container cgroup is not owned by the effective user",
                ));
            }
        }
        let parent_id = dir_identity(step, self.fd.as_fd(), "stat parent cgroup")?;
        Ok(Some(ContainerCgroup {
            name: name.clone(),
            fd,
            parent_id,
        }))
    }

    /// 親直下の `name` を、保持 fd `held` と同一の cgroup であることを確かめてから削除し、削除済みを確認する。
    /// `remove_child` と `prepare` の巻き戻し（コンテナ用子 cgroup・新規作成した退避リーフ）が共用する。
    ///
    /// 削除前に、親ディレクトリ上の同名エントリが `held` と同一の cgroup であることを検証する
    /// （別スコープの同名子・差し替えられた子の誤削除を防ぐ）。cgroup の削除は fd 指定ができず
    /// 名前指定の `unlinkat` のみのため、同一性確認と削除の間に同一 euid の別主体が同名エントリを
    /// 差し替える競合は原理的に塞げない（親は euid 所有の委譲 cgroup で、他 UID は差し替えられない。
    /// 削除できるのは空の cgroup のみ）。そこで削除後に `held` 経由で `cgroup.events` を開き、
    /// `ENOENT`（[`removal_confirmed`]）のときだけ成功とする。開けた場合は別の cgroup を消したとして
    /// `Internal`、その他の失敗は保持していた cgroup が残っている可能性を否定できないためエラーを返す。
    fn remove_verified(&self, name: &str, held: BorrowedFd<'_>) -> Result<(), CgroupError> {
        remove_verified_at(self.fd.as_fd(), name, held)
    }
}

/// `parent` 直下の `name` を、保持 fd `held` と同一の cgroup であることを確かめてから削除し、削除済みを確認する
/// （[`DelegatedCgroup::remove_verified`] の実体。exec 用の子 cgroup の削除〔`exec_kill`〕も共用する）。
fn remove_verified_at(
    parent: BorrowedFd<'_>,
    name: &str,
    held: BorrowedFd<'_>,
) -> Result<(), CgroupError> {
    let step = CgroupStep::Cleanup;
    let entry = open_cgroup_dir(step, parent, name)?;
    if dir_identity(step, entry.as_fd(), "stat cgroup entry")?
        != dir_identity(step, held, "stat held cgroup")?
    {
        return Err(CgroupError::precondition(
            step,
            "cgroup entry no longer matches the held handle",
        ));
    }
    drop(entry);
    let c = cstring(step, name)?;
    sys::remove_dir_at(parent, &c).map_err(|e| sys_error(step, name, e))?;
    let events = cstring(step, "cgroup.events")?;
    match sys::open_read_at(held, &events) {
        Err(e) if removal_confirmed(&e) => Ok(()),
        Ok(_) => Err(CgroupError::new(
            ErrorCode::Internal,
            step,
            "removed cgroup entry was not the held cgroup (concurrent replacement)",
        )),
        Err(e) => Err(sys_error(step, "confirm removal via held cgroup.events", e)),
    }
}

/// `oci_runtime::delete` が使う cgroup 削除（TASK-30.3・OCI-6）。対象は `fc-<id>@<instance>`（CORE-3 で作った子）だけ。
///
/// 待機を伴わないファイル I/O のみのためタイムアウトは持たない（REPAIR-5 の対象外）。
impl ContainerCgroupRemover for DelegatedCgroup {
    /// 検出した委譲パス（[`DelegatedCgroup::path`]。ルートは `"/"`）を [`CgroupScope`] にして返す。
    ///
    /// 要素は `detect` で検証済み（`validate_component` と [`CgroupScope`] は同じ要素規則）のため、
    /// 失敗するのは全体長が `MAX_CGROUP_SCOPE_BYTES` を超える場合だけである。その場合は記録と照合
    /// できないので `InvalidArgument` を返す（delete は状態記録を削除しない）。
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        CgroupScope::new(&self.path.display())
    }

    fn remove(
        &self,
        id: &ContainerId,
        instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        // 名前を作れない（長さ超過）cgroup は `prepare` に渡す名前も同じ規則で作れないため存在し得ない。
        // 失敗にすると該当レコードが永久に削除不能になるので NotPresent とする。
        let Ok(name) = CgroupName::for_instance(id, instance) else {
            return Ok(CgroupRemoval::NotPresent);
        };
        match self.open_child(&name).map_err(removal_error)? {
            None => Ok(CgroupRemoval::NotPresent),
            Some(child) => {
                match self.remove_child(&child) {
                    Ok(()) => Ok(CgroupRemoval::Removed),
                    // open_child の後に並行 delete 等で既に消えた。目的の状態（cgroup 無し）に
                    // 到達済みなので成功扱いにする（OCI-6。TraitError にするとレコードが残る）。
                    Err(e) if e.code == ErrorCode::NotFound => Ok(CgroupRemoval::NotPresent),
                    Err(e) => Err(removal_error(e)),
                }
            }
        }
    }
}

/// `CgroupError` を `TraitError` へ写す。`code` だけを保ち、メッセージは固定文言にする
/// （errno・パスを `oci_runtime::delete` の呼び出し元へ漏らさない）。
fn removal_error(e: CgroupError) -> TraitError {
    let message = match e.code {
        ErrorCode::FailedPrecondition => "container cgroup is not empty or changed; retry",
        ErrorCode::PermissionDenied => "container cgroup is not owned by the effective user",
        _ => "failed to remove container cgroup",
    };
    TraitError::new(e.code, message)
}

/// ディレクトリ・`cgroup.procs`・`cgroup.subtree_control` の所有者がすべて `euid` であること
/// （カーネル文書の委譲要件）。`dir` は O_PATH fd のため複製して `fstat` する。
fn check_owned_by(dir: &OwnedFd, euid: u32) -> Result<(), CgroupError> {
    let step = CgroupStep::CheckDelegation;
    let denied = |what: &str| {
        CgroupError::new(
            ErrorCode::PermissionDenied,
            step,
            format!("{what} is not owned by the current user (cgroup not delegated)"),
        )
    };
    let dup = dir
        .try_clone()
        .map_err(|e| io_error(step, "dup cgroup fd", &e))?;
    if owner_uid(step, dup, "stat cgroup directory")? != euid {
        return Err(denied("cgroup directory"));
    }
    for file in ["cgroup.procs", "cgroup.subtree_control"] {
        let c = cstring(step, file)?;
        let fd = sys::open_read_at(dir.as_fd(), &c).map_err(|e| sys_error(step, file, e))?;
        if owner_uid(step, fd, file)? != euid {
            return Err(denied(file));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// メモリ上限（CORE-3・TASK-32.2・#159）
// ---------------------------------------------------------------------------------------------

/// 上限文字列の最大バイト数（パース前に検証し、巨大入力の処理を避ける）。
const MEMORY_LIMIT_INPUT_MAX: usize = 32;

/// cgroup v2 のメモリ上限値（`memory.max` / `memory.swap.max` に書く値。CORE-3）。
///
/// `Bytes` は `0..=i64::MAX` に制限する（カーネルの page counter 上限に張り付く値を避ける）。
/// OCI `linux.resources.memory` の `-1`（無制限）・未指定の写像は呼び出し側（TASK-32.4・#161 以降）の
/// 責務で、本型は受け取った値を検証して正規形で書くだけを担う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryLimit {
    /// 無制限（`max`）。
    Max,
    /// バイト数（`0..=i64::MAX`）。
    Bytes(u64),
}

fn memory_invalid(message: impl Into<String>) -> CgroupError {
    CgroupError::new(
        ErrorCode::InvalidArgument,
        CgroupStep::SetMemoryLimit,
        message,
    )
}

impl MemoryLimit {
    /// バイト数から作る。`i64::MAX` 超は `InvalidArgument`。
    pub fn bytes(n: u64) -> Result<Self, CgroupError> {
        if i64::try_from(n).is_err() {
            return Err(memory_invalid("memory limit exceeds i64::MAX"));
        }
        Ok(Self::Bytes(n))
    }

    /// 文字列から作る。受理するのは `max`・10 進数字列・10 進数字列＋単一サフィックス
    /// （`k`/`m`/`g`/`t`、大文字小文字可、1024 進）のみ。負数・符号・空白・小数・未知のサフィックス・
    /// オーバーフローは `InvalidArgument`（CORE-3）。
    pub fn parse(s: &str) -> Result<Self, CgroupError> {
        if s.len() > MEMORY_LIMIT_INPUT_MAX {
            return Err(memory_invalid("memory limit string is too long"));
        }
        if s == "max" {
            return Ok(Self::Max);
        }
        if s.starts_with('-') {
            return Err(memory_invalid("memory limit must not be negative"));
        }
        let (digits, shift) = match s.char_indices().last() {
            Some((i, c)) if !c.is_ascii_digit() => {
                let shift = match c {
                    'k' | 'K' => 10u32,
                    'm' | 'M' => 20,
                    'g' | 'G' => 30,
                    't' | 'T' => 40,
                    _ => return Err(memory_invalid("unknown memory limit suffix")),
                };
                (s.get(..i).unwrap_or(""), shift)
            }
            _ => (s, 0),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(memory_invalid("memory limit must be decimal digits"));
        }
        let n: u64 = digits
            .parse()
            .map_err(|_| memory_invalid("memory limit is out of range"))?;
        let bytes = n
            .checked_mul(1u64 << shift)
            .ok_or_else(|| memory_invalid("memory limit is out of range"))?;
        Self::bytes(bytes)
    }

    /// 値が `0..=i64::MAX`（または `Max`）であることを再確認して返す。
    fn validated(self) -> Result<Self, CgroupError> {
        match self {
            Self::Max => Ok(self),
            Self::Bytes(n) => Self::bytes(n),
        }
    }

    /// カーネルへ書く正規形（呼び出し元の文字列はカーネルへ渡さない）。
    fn render(self) -> String {
        match self {
            Self::Max => "max".to_string(),
            Self::Bytes(n) => n.to_string(),
        }
    }
}

impl TryFrom<i64> for MemoryLimit {
    type Error = CgroupError;

    /// 負数は `InvalidArgument`。OCI の `-1`（無制限）の意味付けは呼び出し側で行う。
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let n = u64::try_from(value)
            .map_err(|_| memory_invalid("memory limit must not be negative"))?;
        Self::bytes(n)
    }
}

/// メモリ上限の設定要求。`swap_max` が `None` なら `memory.swap.max` には触れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimits {
    /// `memory.max` に書く値。
    pub memory_max: MemoryLimit,
    /// `memory.swap.max` に書く値（CORE-3 の例では `Bytes(0)`）。
    pub swap_max: Option<MemoryLimit>,
}

/// 書き込み後に読み戻した実効値（カーネルは値をページ境界へ切り下げる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppliedMemoryLimits {
    /// 読み戻した `memory.max`。
    pub memory_max: MemoryLimit,
    /// 読み戻した `memory.swap.max`（要求しなかった場合は `None`）。
    pub swap_max: Option<MemoryLimit>,
}

/// カーネルが返す `memory.max` 系の値（`max` または 10 進）を解析する。
fn parse_kernel_limit(text: &str) -> Result<MemoryLimit, CgroupError> {
    let step = CgroupStep::SetMemoryLimit;
    let t = text.trim_end_matches('\n');
    if t == "max" {
        return Ok(MemoryLimit::Max);
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CgroupError::precondition(
            step,
            "unexpected memory limit value read back from the kernel",
        ));
    }
    let n: u64 = t.parse().map_err(|_| {
        CgroupError::precondition(
            step,
            "memory limit read back from the kernel is out of range",
        )
    })?;
    Ok(MemoryLimit::Bytes(n))
}

/// カーネルのページ切り下げ幅の上限。Linux の最大ページサイズ（aarch64 の 64 KiB）を採る。
const MAX_PAGE_SIZE_BYTES: u64 = 64 * 1024;

/// 要求値と読み戻した実効値を照合し、実効値を返す。カーネルはページ境界へ切り下げるため
/// `Bytes` は実効値が「要求以下かつ切り下げ幅がページサイズ上限（64 KiB）未満」であれば成功とし、
/// 要求を上回る・大幅な低下（64 MiB 要求で 0 が読み戻される等）・`max` への化けは `FailedPrecondition`。
fn verify_effective(
    requested: MemoryLimit,
    effective: MemoryLimit,
) -> Result<MemoryLimit, CgroupError> {
    let ok = match (requested, effective) {
        (MemoryLimit::Max, MemoryLimit::Max) => true,
        (MemoryLimit::Bytes(req), MemoryLimit::Bytes(eff)) => {
            eff <= req && req - eff < MAX_PAGE_SIZE_BYTES
        }
        _ => false,
    };
    if ok {
        Ok(effective)
    } else {
        Err(CgroupError::precondition(
            CgroupStep::SetMemoryLimit,
            "effective memory limit does not satisfy the request",
        ))
    }
}

impl ContainerCgroup {
    /// 子 cgroup の `memory.max`（および要求があれば `memory.swap.max`）を設定し、読み戻した実効値を返す。
    ///
    /// 呼び出し文脈: 起動フロー（TASK-32.4・#161）が `enable_controllers` の後・子プロセス参加の前に
    /// 呼ぶ予定。`enabled` はその戻り値で、`memory` が含まれなければ書き込まず `FailedPrecondition`。
    /// 書き込み順は `memory.max` → `memory.swap.max`。途中で失敗しても巻き戻さない（子 cgroup は空で、
    /// 呼び出し側が `DelegatedCgroup::remove_child` で削除する前提）。値は検証済みの正規形のみ書く。
    pub fn set_memory_limits(
        &self,
        enabled: &ControllerSet,
        limits: &MemoryLimits,
    ) -> Result<AppliedMemoryLimits, CgroupError> {
        if !enabled.contains(Controller::Memory) {
            return Err(CgroupError::precondition(
                CgroupStep::SetMemoryLimit,
                "memory controller is not enabled for the container cgroup",
            ));
        }
        // 公開バリアント `Bytes(u64)` は直接構築できるため、書き込み前に両値を再検証する
        // （`i64::MAX` 超を memory.max / memory.swap.max へ渡さない。部分書き込みも避ける）。
        let memory_max_req = limits.memory_max.validated()?;
        let swap_max_req = limits.swap_max.map(MemoryLimit::validated).transpose()?;
        let memory_max = self.write_memory_file("memory.max", memory_max_req)?;
        let swap_max = match swap_max_req {
            Some(req) => Some(self.write_memory_file("memory.swap.max", req)?),
            None => None,
        };
        Ok(AppliedMemoryLimits {
            memory_max,
            swap_max,
        })
    }

    /// `file` へ正規形を書き、読み戻して要求を満たすことを確認する。ファイル不在は controller 未有効
    /// （または swap accounting 無効）として `FailedPrecondition`（fail-closed）。
    fn write_memory_file(
        &self,
        file: &str,
        requested: MemoryLimit,
    ) -> Result<MemoryLimit, CgroupError> {
        let step = CgroupStep::SetMemoryLimit;
        let name = cstring(step, file)?;
        let wfd = match sys::open_write_at(self.fd.as_fd(), &name) {
            Ok(fd) => fd,
            Err(SysError::Os(errno)) if errno == sys::ENOENT => {
                return Err(CgroupError::precondition(
                    step,
                    format!("{file} does not exist (controller or swap accounting is unavailable)"),
                ));
            }
            Err(e) => return Err(sys_error(step, file, e)),
        };
        File::from(wfd)
            .write_all(requested.render().as_bytes())
            .map_err(|e| io_error(step, file, &e))?;
        let effective =
            parse_kernel_limit(&read_iface(step, self.fd.as_fd(), file, SMALL_FILE_LIMIT)?)?;
        verify_effective(requested, effective)
    }
}
/// 読み取れる統計ファイルの閉じた列挙（SUP-10・TASK-167.1）。
///
/// ファイル名と読み取り上限は本 crate 側で固定し、呼び出し側（supervisor の `stats`）から
/// 任意のパス要素を注入できないようにする（パストラバーサル対策）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatFile {
    /// `memory.current`（現在のメモリ使用量。バイト）。
    MemoryCurrent,
    /// `cpu.stat`（CPU 使用時間・スロットリング）。
    CpuStat,
    /// `io.stat`（デバイスごとの I/O 量）。
    IoStat,
}

impl StatFile {
    /// cgroup ディレクトリ直下のファイル名。
    fn file_name(self) -> &'static str {
        match self {
            Self::MemoryCurrent => "memory.current",
            Self::CpuStat => "cpu.stat",
            Self::IoStat => "io.stat",
        }
    }

    /// 読み取り上限（バイト）。
    fn limit(self) -> u64 {
        match self {
            Self::MemoryCurrent | Self::CpuStat => SMALL_FILE_LIMIT,
            Self::IoStat => IO_STAT_LIMIT,
        }
    }
}

impl ContainerCgroup {
    /// 統計ファイルを上限付きで読む（SUP-10・TASK-167.1）。
    ///
    /// 呼び出し文脈: supervisor の `stats`（`fandhe-container-supervisor`）が自コンテナの cgroup に対し
    /// 3 ファイルを順に読み、パースする。保持している cgroup ディレクトリ fd 起点の `openat` で開き、
    /// パス文字列から cgroup を再解決しない。ファイル不在（controller 未有効）は `Ok(None)`、
    /// 上限超過・非 UTF-8 は `FailedPrecondition`。読み取り専用で cgroup へは書き込まない。
    pub fn read_stat_file(&self, file: StatFile) -> Result<Option<String>, CgroupError> {
        read_stat_file_at(self.fd.as_fd(), file)
    }
}

/// `dir` 起点で統計ファイルを読む。`ENOENT` のみ `None` に写し、他のエラーは伝える。
fn read_stat_file_at(dir: BorrowedFd<'_>, file: StatFile) -> Result<Option<String>, CgroupError> {
    let step = CgroupStep::ReadStats;
    let name = cstring(step, file.file_name())?;
    match sys::open_read_at(dir, &name) {
        Ok(fd) => read_limited(step, fd, file.limit()).map(Some),
        Err(SysError::Os(errno)) if errno == sys::ENOENT => Ok(None),
        Err(e) => Err(sys_error(step, file.file_name(), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(s: &str) -> Result<CgroupPath, CgroupError> {
        parse_self_cgroup_v2(s)
    }

    /// CORE-3・TASK-32.1: v2 unified 行の解析（具体値）。
    #[test]
    fn core3_task32_1_parse_self_cgroup_v2_extracts_path() {
        let p = path("0::/user.slice/user-1000.slice/x.scope\n").unwrap();
        assert_eq!(
            p.components,
            vec!["user.slice", "user-1000.slice", "x.scope"]
        );
        assert_eq!(p.display(), "/user.slice/user-1000.slice/x.scope");
        assert!(path("0::/\n").unwrap().is_root());
        assert_eq!(path("0::/\n").unwrap().display(), "/");
    }

    /// CORE-4・SEC-6・TASK-32.1: hybrid（v1 行との混在）は順序を問わず fail-closed で拒否する。
    #[test]
    fn core4_sec6_task32_1_parse_self_cgroup_v2_rejects_hybrid() {
        for text in [
            "12:memory:/old\n1:name=systemd:/old2\n0::/new/leaf\n",
            "0::/new/leaf\n1:name=systemd:/old2\n",
        ] {
            let e = path(text).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.step, CgroupStep::ReadSelfCgroup);
            assert!(e.message.contains("hybrid"), "{}", e.message);
        }
    }

    /// CORE-3・TASK-32.1: 異常なカーネル応答は fail-closed。
    #[test]
    fn core3_task32_1_parse_self_cgroup_v2_rejects_anomalies() {
        let long = format!("0::/{}\n", "a".repeat(256));
        let deep = format!("0::/{}\n", vec!["a"; 65].join("/"));
        let cases = [
            "",
            "12:memory:/x\n",
            "0::/a\n0::/b\n",
            "0::/a/../b\n",
            "0::/a/./b\n",
            "0::/a//b\n",
            "0::relative\n",
            "0::/a/b (deleted)\n",
            "0::/a\0b\n",
            long.as_str(),
            deep.as_str(),
        ];
        for c in cases {
            let e = path(c).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "case {c:?}");
            assert_eq!(e.step, CgroupStep::ReadSelfCgroup, "case {c:?}");
        }
    }

    /// CORE-3・TASK-32.1: controller 集合の解析（未知トークン無視・空）。
    #[test]
    fn core3_task32_1_controller_set_parse() {
        let s = ControllerSet::parse("cpuset cpu io memory hugetlb pids rdma misc\n");
        assert_eq!(s.iter().count(), 8);
        assert!(s.contains(Controller::Memory) && s.contains(Controller::Cpu));
        let s = ControllerSet::parse("cpu future_ctl memory");
        assert_eq!(s, ControllerSet::of(&[Controller::Cpu, Controller::Memory]));
        assert!(ControllerSet::parse("\n").is_empty());
        assert_eq!(
            ControllerSet::of(&[Controller::Memory, Controller::Cpu]).to_enable_request(),
            "+cpu +memory"
        );
    }

    /// 一時ディレクトリ（std のみ）。drop で削除する。
    struct TmpDir(std::path::PathBuf);

    impl TmpDir {
        fn new(label: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("fandhe-cgjoin-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn join_for(dir: &std::path::Path) -> CgroupJoin {
        let fd = OwnedFd::from(File::open(dir).unwrap());
        let name = CgroupName::new(&ContainerId::new("t").unwrap()).unwrap();
        CgroupJoin::from_dir_for_test(name, fd)
    }

    /// CORE-3・TASK-32.4: 自 PID を `cgroup.procs` へ書き、読み戻して検証する。
    #[test]
    fn core3_task32_4_join_current_process_writes_own_pid() {
        let tmp = TmpDir::new("ok");
        std::fs::write(tmp.0.join("cgroup.procs"), "").unwrap();
        let mut join = join_for(&tmp.0);
        join.join_current_process().unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.0.join("cgroup.procs")).unwrap(),
            std::process::id().to_string()
        );
    }

    /// CORE-3・TASK-32.4: `cgroup.procs` 不在は `NotFound`（段は `JoinContainer`）。
    #[test]
    fn core3_task32_4_join_missing_procs_is_not_found() {
        let tmp = TmpDir::new("missing");
        let mut join = join_for(&tmp.0);
        let err = join.join_current_process().unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.step, CgroupStep::JoinContainer);
    }

    /// CORE-3・TASK-32.4: 読み戻しに自 PID が無ければ成功扱いしない（fail-closed）。
    #[test]
    fn core3_task32_4_verify_joined_requires_own_pid() {
        verify_joined(123, "5\n123\n").unwrap();
        let err = verify_joined(123, "5\n124\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.step, CgroupStep::JoinContainer);
        assert_eq!(
            verify_joined(123, "").unwrap_err().code,
            ErrorCode::FailedPrecondition
        );
    }

    /// CORE-3・TASK-32.1: `cgroup.procs` の解析。
    #[test]
    fn core3_task32_1_parse_procs() {
        let step = CgroupStep::Evacuate;
        assert_eq!(parse_procs(step, "").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_procs(step, "\n").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_procs(step, "123\n456\n").unwrap(), vec![123, 456]);
        assert_eq!(
            parse_procs(step, "12x\n").unwrap_err().code,
            ErrorCode::FailedPrecondition
        );
    }

    /// CORE-3・TASK-32.1: cgroup 名の生成・長さ上限・予約名。
    #[test]
    fn core3_task32_1_cgroup_name() {
        let id = ContainerId::new("abc").unwrap();
        assert_eq!(CgroupName::new(&id).unwrap().as_str(), "fc-abc");
        let ok = ContainerId::new("a".repeat(252)).unwrap();
        assert_eq!(CgroupName::new(&ok).unwrap().as_str().len(), 255);
        let over = ContainerId::new("a".repeat(253)).unwrap();
        assert_eq!(
            CgroupName::new(&over).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        let reserved = ContainerId::new("runtime").unwrap();
        assert_eq!(
            CgroupName::new(&reserved).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    /// CORE-3・TASK-32.1: 利用可能集合外・空の要求は書き込み前に拒否する。
    #[test]
    fn core3_task32_1_validate_controller_request() {
        let avail = ControllerSet::of(&[Controller::Cpu, Controller::Memory]);
        assert_eq!(
            validate_controller_request(&avail, &ControllerSet::of(&[Controller::Memory])),
            Ok(())
        );
        let e =
            validate_controller_request(&avail, &ControllerSet::of(&[Controller::Io])).unwrap_err();
        assert_eq!(
            (e.code, e.step),
            (ErrorCode::FailedPrecondition, CgroupStep::EnableControllers)
        );
        let e = validate_controller_request(&avail, &ControllerSet::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }

    /// CORE-3・TASK-32.1: 書き込み後に読み戻した集合が要求をすべて含むときだけ成功（不足は具体名つき）。
    #[test]
    fn core3_task32_1_verify_enabled_requires_all_requested() {
        let want = ControllerSet::of(&[Controller::Cpu, Controller::Memory]);
        assert_eq!(verify_enabled(&want, &want.clone()), Ok(()));
        let superset = ControllerSet::of(&[Controller::Cpu, Controller::Io, Controller::Memory]);
        assert_eq!(verify_enabled(&want, &superset), Ok(()));
        let e = verify_enabled(&want, &ControllerSet::of(&[Controller::Cpu])).unwrap_err();
        assert_eq!(
            (e.code, e.step),
            (ErrorCode::FailedPrecondition, CgroupStep::EnableControllers)
        );
        assert_eq!(
            e.message,
            "controllers not enabled after writing cgroup.subtree_control: memory"
        );
        let e = verify_enabled(&want, &ControllerSet::default()).unwrap_err();
        assert_eq!(
            e.message,
            "controllers not enabled after writing cgroup.subtree_control: cpu memory"
        );
    }

    /// CORE-3・TASK-32.1: 削除済みの証拠は `ENOENT` のみ（他の errno・非 OS エラーは削除済みとしない）。
    #[test]
    fn core3_task32_1_removal_confirmed_only_on_enoent() {
        assert!(removal_confirmed(&SysError::Os(sys::ENOENT)));
        for e in [
            SysError::Os(sys::EACCES),
            SysError::Os(sys::EPERM),
            SysError::Os(sys::EBADF),
            SysError::Os(sys::EINTR),
            SysError::Os(sys::EINVAL),
            SysError::Unsupported,
            SysError::MultiThreaded,
        ] {
            assert!(!removal_confirmed(&e), "{e:?}");
        }
    }

    /// CORE-3・TASK-32.1: `remove_verified` が頼るカーネルの挙動（削除済みディレクトリの保持 fd を起点に
    /// した lookup は `ENOENT`）を一時ディレクトリで具体値照合する。削除前は同じ fd 起点で開ける。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_1_lookup_under_removed_dir_is_enoent() {
        let base = std::env::temp_dir().join(format!("fc-cgroups-rm-{}", std::process::id()));
        std::fs::create_dir_all(base.join("child")).unwrap();
        std::fs::write(base.join("child").join("cgroup.events"), b"populated 0\n").unwrap();
        let parent = File::open(&base).unwrap();
        let name = CString::new("child").unwrap();
        let held = sys::open_dir_path_nofollow(Some(parent.as_fd()), &name).unwrap();
        let events = CString::new("cgroup.events").unwrap();
        assert!(sys::open_read_at(held.as_fd(), &events).is_ok());
        std::fs::remove_file(base.join("child").join("cgroup.events")).unwrap();
        assert_eq!(sys::remove_dir_at(parent.as_fd(), &name), Ok(()));
        let err = sys::open_read_at(held.as_fd(), &events).unwrap_err();
        assert_eq!(err, SysError::Os(sys::ENOENT));
        assert!(removal_confirmed(&err));
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// CORE-3・TASK-32.1: errno から `ErrorCode` への写像。
    #[test]
    fn core3_task32_1_errno_mapping() {
        assert_eq!(errno_code(sys::EACCES), ErrorCode::PermissionDenied);
        assert_eq!(errno_code(sys::EPERM), ErrorCode::PermissionDenied);
        assert_eq!(errno_code(sys::EBUSY), ErrorCode::FailedPrecondition);
        assert_eq!(errno_code(sys::EEXIST), ErrorCode::AlreadyExists);
        assert_eq!(errno_code(sys::ENOENT), ErrorCode::NotFound);
        assert_eq!(errno_code(sys::EINVAL), ErrorCode::Internal);
    }

    /// CORE-3・TASK-32.1: 退避の型強制（`enable_controllers` は `&Evacuated` が必須）。
    /// シグネチャの照合（コンパイルが通ること自体が検証）。
    #[test]
    fn core3_task32_1_enable_controllers_requires_proof() {
        let _f: fn(
            &DelegatedCgroup,
            &Evacuated,
            &ControllerSet,
        ) -> Result<ControllerSet, CgroupError> = DelegatedCgroup::enable_controllers;
    }

    fn mem_err(r: Result<MemoryLimit, CgroupError>) -> (ErrorCode, CgroupStep) {
        let e = r.expect_err("must be rejected");
        (e.code, e.step)
    }

    #[test]
    fn core3_task32_2_parse_accepts() {
        let cases: [(&str, MemoryLimit); 6] = [
            ("max", MemoryLimit::Max),
            ("67108864", MemoryLimit::Bytes(67_108_864)),
            ("64M", MemoryLimit::Bytes(67_108_864)),
            ("64m", MemoryLimit::Bytes(67_108_864)),
            ("1G", MemoryLimit::Bytes(1_073_741_824)),
            ("0", MemoryLimit::Bytes(0)),
        ];
        for (s, want) in cases {
            assert_eq!(MemoryLimit::parse(s).expect(s), want, "{s}");
        }
        assert_eq!(
            MemoryLimit::parse("9223372036854775807").expect("max i64"),
            MemoryLimit::Bytes(i64::MAX as u64)
        );
    }

    #[test]
    fn core3_task32_2_parse_rejects() {
        let long = "1".repeat(MEMORY_LIMIT_INPUT_MAX + 1);
        let cases = [
            "-1",
            "-64M",
            "+5",
            "",
            " 64",
            "64 ",
            "64MB",
            "64X",
            "64KiB",
            "1.5G",
            "M",
            "9223372036854775808",
            "9999999999T",
            long.as_str(),
        ];
        for s in cases {
            assert_eq!(
                mem_err(MemoryLimit::parse(s)),
                (ErrorCode::InvalidArgument, CgroupStep::SetMemoryLimit),
                "{s:?}"
            );
        }
    }

    #[test]
    fn core3_task32_2_try_from_i64() {
        assert!(MemoryLimit::try_from(-1i64).is_err());
        assert!(MemoryLimit::try_from(i64::MIN).is_err());
        assert_eq!(
            MemoryLimit::try_from(0i64).expect("0"),
            MemoryLimit::Bytes(0)
        );
        assert_eq!(
            MemoryLimit::try_from(67_108_864i64).expect("64MiB"),
            MemoryLimit::Bytes(67_108_864)
        );
        assert!(MemoryLimit::bytes(u64::MAX).is_err());
    }

    /// CORE-3・TASK-32.2: 公開バリアントを直接構築した範囲外の値も書き込み前の再検証で拒否する。
    #[test]
    fn core3_task32_2_validated_rejects_directly_built_out_of_range() {
        assert_eq!(
            MemoryLimit::Bytes(i64::MAX as u64)
                .validated()
                .expect("i64::MAX"),
            MemoryLimit::Bytes(i64::MAX as u64)
        );
        assert_eq!(MemoryLimit::Max.validated().expect("max"), MemoryLimit::Max);
        for n in [i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                mem_err(MemoryLimit::Bytes(n).validated()),
                (ErrorCode::InvalidArgument, CgroupStep::SetMemoryLimit),
                "{n}"
            );
        }
    }

    #[test]
    fn core3_task32_2_render_is_canonical() {
        assert_eq!(MemoryLimit::Max.render(), "max");
        assert_eq!(MemoryLimit::Bytes(67_108_864).render(), "67108864");
        assert_eq!(MemoryLimit::parse("64M").expect("64M").render(), "67108864");
    }

    #[test]
    fn core3_task32_2_parse_kernel_limit() {
        assert_eq!(parse_kernel_limit("max\n").expect("max"), MemoryLimit::Max);
        assert_eq!(
            parse_kernel_limit("67108864\n").expect("num"),
            MemoryLimit::Bytes(67_108_864)
        );
        for s in ["abc\n", "", "-1\n", "\n"] {
            let e = parse_kernel_limit(s).expect_err(s);
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{s:?}");
        }
    }

    #[test]
    fn core3_task32_2_verify_effective() {
        use MemoryLimit::{Bytes, Max};
        assert_eq!(
            verify_effective(Bytes(10_000), Bytes(8192)).expect("floor"),
            Bytes(8192)
        );
        assert_eq!(verify_effective(Max, Max).expect("max"), Max);
        assert!(verify_effective(Bytes(4096), Bytes(8192)).is_err());
        assert!(verify_effective(Bytes(64 * 1024 * 1024), Bytes(0)).is_err());
        assert_eq!(
            verify_effective(Bytes(8191), Bytes(4096)).expect("floor"),
            Bytes(4096)
        );
        assert!(verify_effective(Max, Bytes(1)).is_err());
        assert!(verify_effective(Bytes(1), Max).is_err());
    }

    fn limits_for(dir: &std::path::Path) -> ContainerCgroup {
        let fd = OwnedFd::from(File::open(dir).unwrap());
        let name = CgroupName::new(&ContainerId::new("t").unwrap()).unwrap();
        ContainerCgroup::from_dir_for_test(name, fd)
    }

    /// 通常ファイル上の書き込みは `O_TRUNC` なしのため、対象は事前に空で作る（cpu.rs のテストと同じ前提）。
    fn touch(tmp: &TmpDir, names: &[&str]) {
        for n in names {
            std::fs::write(tmp.0.join(n), "").unwrap();
        }
    }

    fn read(tmp: &TmpDir, name: &str) -> String {
        std::fs::read_to_string(tmp.0.join(name)).unwrap()
    }

    fn mem_limits(max: &str, swap: Option<MemoryLimit>) -> MemoryLimits {
        MemoryLimits {
            memory_max: MemoryLimit::parse(max).unwrap(),
            swap_max: swap,
        }
    }

    /// CORE-3・TASK-32.5: memory.max / memory.swap.max / cpu.max に書かれる値を具体値で照合する。
    #[test]
    fn core3_task32_5_memory_and_cpu_values_written() {
        let tmp = TmpDir::new("t325-ok");
        touch(&tmp, &["memory.max", "memory.swap.max", "cpu.max"]);
        let cg = limits_for(&tmp.0);
        let enabled = ControllerSet::of(&[Controller::Memory, Controller::Cpu]);
        let applied = cg
            .set_memory_limits(&enabled, &mem_limits("64M", Some(MemoryLimit::Bytes(0))))
            .unwrap();
        assert_eq!(
            applied,
            AppliedMemoryLimits {
                memory_max: MemoryLimit::Bytes(67_108_864),
                swap_max: Some(MemoryLimit::Bytes(0)),
            }
        );
        assert_eq!(read(&tmp, "memory.max"), "67108864");
        assert_eq!(read(&tmp, "memory.swap.max"), "0");
        let cpu = CpuMax::new(CpuQuota::Micros(50_000), 100_000).unwrap();
        assert_eq!(cg.set_cpu_max(&cpu), Ok(cpu));
        assert_eq!(read(&tmp, "cpu.max").trim_end(), "50000 100000");
    }

    /// CORE-3・TASK-32.5: `max` は `max` と書かれ、swap 未指定なら memory.swap.max に触れない。
    #[test]
    fn core3_task32_5_max_and_no_swap_leaves_swap_untouched() {
        let tmp = TmpDir::new("t325-max");
        touch(&tmp, &["memory.max"]);
        std::fs::write(tmp.0.join("memory.swap.max"), "sentinel").unwrap();
        let cg = limits_for(&tmp.0);
        let enabled = ControllerSet::of(&[Controller::Memory]);
        let applied = cg
            .set_memory_limits(&enabled, &mem_limits("max", None))
            .unwrap();
        assert_eq!(applied.memory_max, MemoryLimit::Max);
        assert_eq!(applied.swap_max, None);
        assert_eq!(read(&tmp, "memory.max"), "max");
        assert_eq!(read(&tmp, "memory.swap.max"), "sentinel");
    }

    /// CORE-3・TASK-32.5: memory controller 未有効なら何も書かず `FailedPrecondition`。
    #[test]
    fn core3_task32_5_memory_controller_not_enabled_writes_nothing() {
        let tmp = TmpDir::new("t325-noctl");
        touch(&tmp, &["memory.max", "memory.swap.max"]);
        let cg = limits_for(&tmp.0);
        let e = cg
            .set_memory_limits(
                &ControllerSet::of(&[Controller::Cpu]),
                &mem_limits("64M", Some(MemoryLimit::Bytes(0))),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetMemoryLimit);
        assert_eq!(read(&tmp, "memory.max"), "");
        assert_eq!(read(&tmp, "memory.swap.max"), "");
    }

    /// CORE-3・TASK-32.5: 範囲外の swap 値は書き込み前に拒否され memory.max も書かれない（部分書き込みなし）。
    #[test]
    fn core3_task32_5_out_of_range_swap_rejected_before_any_write() {
        let tmp = TmpDir::new("t325-range");
        touch(&tmp, &["memory.max", "memory.swap.max"]);
        let cg = limits_for(&tmp.0);
        let e = cg
            .set_memory_limits(
                &ControllerSet::of(&[Controller::Memory]),
                &mem_limits("64M", Some(MemoryLimit::Bytes(i64::MAX as u64 + 1))),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.step, CgroupStep::SetMemoryLimit);
        assert_eq!(read(&tmp, "memory.max"), "");
        assert_eq!(read(&tmp, "memory.swap.max"), "");
    }

    /// CORE-3・TASK-32.5: memory.max 不在は `FailedPrecondition`（swap は未変更）。
    #[test]
    fn core3_task32_5_missing_memory_max_is_failed_precondition() {
        let tmp = TmpDir::new("t325-nomax");
        touch(&tmp, &["memory.swap.max"]);
        let cg = limits_for(&tmp.0);
        let e = cg
            .set_memory_limits(
                &ControllerSet::of(&[Controller::Memory]),
                &mem_limits("64M", Some(MemoryLimit::Bytes(0))),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetMemoryLimit);
        assert_eq!(read(&tmp, "memory.swap.max"), "");
    }

    /// CORE-3・TASK-32.5: memory.swap.max 不在（swap accounting 無効相当）は `FailedPrecondition`。
    /// 書き込み順は memory.max が先で、失敗しても巻き戻さない契約どおり memory.max は書かれたまま。
    #[test]
    fn core3_task32_5_missing_swap_file_is_failed_precondition() {
        let tmp = TmpDir::new("t325-noswap");
        touch(&tmp, &["memory.max"]);
        let cg = limits_for(&tmp.0);
        let e = cg
            .set_memory_limits(
                &ControllerSet::of(&[Controller::Memory]),
                &mem_limits("64M", Some(MemoryLimit::Bytes(0))),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetMemoryLimit);
        assert_eq!(read(&tmp, "memory.max"), "67108864");
    }

    /// CORE-3・TASK-32.5: memory.max が symlink なら `O_NOFOLLOW` で拒否し、リンク先は変更しない。
    #[test]
    fn core3_task32_5_symlink_memory_max_is_rejected() {
        let tmp = TmpDir::new("t325-symlink");
        std::fs::write(tmp.0.join("target"), "untouched").unwrap();
        std::os::unix::fs::symlink(tmp.0.join("target"), tmp.0.join("memory.max")).unwrap();
        let cg = limits_for(&tmp.0);
        let r = cg.set_memory_limits(
            &ControllerSet::of(&[Controller::Memory]),
            &mem_limits("64M", None),
        );
        assert!(r.is_err());
        assert_eq!(read(&tmp, "target"), "untouched");
    }

    /// OCI-6・TASK-30.3: cgroup 削除の失敗は `code` を保ち、errno・パスを含まない固定文言へ写す。
    #[test]
    fn oci6_removal_error_keeps_code_and_hides_errno() {
        let busy = CgroupError::new(
            ErrorCode::FailedPrecondition,
            CgroupStep::Cleanup,
            "fc-c1: errno 16",
        );
        let mapped = removal_error(busy);
        assert_eq!(mapped.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            mapped.message(),
            "container cgroup is not empty or changed; retry"
        );
        let other = removal_error(CgroupError::new(
            ErrorCode::Internal,
            CgroupStep::Cleanup,
            "/sys/fs/cgroup/x: errno 5",
        ));
        assert_eq!(other.code(), ErrorCode::Internal);
        assert_eq!(other.message(), "failed to remove container cgroup");
        assert!(!other.message().contains("errno"));
    }

    /// OCI-6・TASK-30.3: instance つきの名前は `fc-<id>@<n>` で、同じ ID でも instance が違えば別名になり、
    /// instance を持たない `fc-<id>`・退避リーフとも重ならない。255 バイトを超えると `InvalidArgument`。
    #[test]
    fn oci6_task30_3_cgroup_name_for_instance() {
        let id = ContainerId::new("x").unwrap();
        let r7 = CgroupName::for_instance(&id, StateRevision::from_raw(7)).unwrap();
        assert_eq!(r7.as_str(), "fc-x@7");
        let r8 = CgroupName::for_instance(&id, StateRevision::from_raw(8)).unwrap();
        assert_eq!(r8.as_str(), "fc-x@8");
        assert_ne!(r7, r8);
        assert_ne!(r7, CgroupName::new(&id).unwrap());
        // ID に `-` を含んでも、区切りの `@` は ID の許容文字に無いので組の取り違えが起きない。
        let dashed = ContainerId::new("x-7").unwrap();
        assert_eq!(
            CgroupName::for_instance(&dashed, StateRevision::from_raw(0))
                .unwrap()
                .as_str(),
            "fc-x-7@0"
        );
        // 退避リーフと同名の ID も instance つきなら衝突しない。
        let runtime = ContainerId::new("runtime").unwrap();
        assert_eq!(
            CgroupName::for_instance(&runtime, StateRevision::from_raw(1))
                .unwrap()
                .as_str(),
            "fc-runtime@1"
        );
        let max = u64::MAX;
        let fits = ContainerId::new("a".repeat(255 - 3 - 1 - max.to_string().len())).unwrap();
        assert_eq!(
            CgroupName::for_instance(&fits, StateRevision::from_raw(max))
                .unwrap()
                .as_str()
                .len(),
            255
        );
        let over = ContainerId::new("a".repeat(252)).unwrap();
        let err = CgroupName::for_instance(&over, StateRevision::from_raw(0)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// SUP-10・TASK-167.1: 統計ファイルが具体値で読め、不在は None になる。
    #[test]
    fn sup10_task167_1_read_stat_file_reads_and_maps_missing_to_none() {
        let tmp = TmpDir::new("t1671-ok");
        std::fs::write(tmp.0.join("memory.current"), "12345678\n").unwrap();
        std::fs::write(
            tmp.0.join("cpu.stat"),
            "usage_usec 10\nuser_usec 6\nsystem_usec 4\n",
        )
        .unwrap();
        let cg = limits_for(&tmp.0);
        assert_eq!(
            cg.read_stat_file(StatFile::MemoryCurrent),
            Ok(Some("12345678\n".to_string()))
        );
        assert_eq!(
            cg.read_stat_file(StatFile::CpuStat),
            Ok(Some(
                "usage_usec 10\nuser_usec 6\nsystem_usec 4\n".to_string()
            ))
        );
        assert_eq!(cg.read_stat_file(StatFile::IoStat), Ok(None));
    }

    /// SUP-10・TASK-167.1: 上限超過と非 UTF-8 は FailedPrecondition・ReadStats。
    #[test]
    fn sup10_task167_1_read_stat_file_rejects_oversize_and_non_utf8() {
        let tmp = TmpDir::new("t1671-bad");
        std::fs::write(tmp.0.join("memory.current"), vec![b'1'; 4097]).unwrap();
        std::fs::write(tmp.0.join("cpu.stat"), [0xff, 0xfe]).unwrap();
        std::fs::write(tmp.0.join("io.stat"), vec![b'x'; 256 * 1024 + 1]).unwrap();
        let cg = limits_for(&tmp.0);
        for f in [StatFile::MemoryCurrent, StatFile::CpuStat, StatFile::IoStat] {
            let e = cg.read_stat_file(f).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{f:?}");
            assert_eq!(e.step, CgroupStep::ReadStats, "{f:?}");
        }
        // 上限ちょうどは読める。
        std::fs::write(tmp.0.join("memory.current"), vec![b'1'; 4096]).unwrap();
        assert_eq!(
            cg.read_stat_file(StatFile::MemoryCurrent)
                .unwrap()
                .map(|s| s.len()),
            Some(4096)
        );
    }
}
