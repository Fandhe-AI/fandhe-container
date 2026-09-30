//! rootless 起動の user namespace UID/GID 写像（CORE-6・SEC-5・TASK-40.1・MS-2）。
//!
//! # 役割
//!
//! `CLONE_NEWUSER` で分離した対象プロセスに対し、検証済みの UID/GID 写像を設定し、
//! `/proc/<pid>/{uid,gid}_map` を読み戻して反映を確かめる。書き込み経路は 2 種:
//!
//! - [`IdMapWriter::Direct`]: `/proc/<pid>/{setgroups,uid_map,gid_map}` へ直接書く
//!   （非特権では「自 euid/egid → 1 行の単一 ID 写像」のみ。`user_namespaces(7)`）
//! - [`IdMapWriter::Helper`]: setuid の `newuidmap` / `newgidmap` 経由で `/etc/subuid`・
//!   `/etc/subgid` の範囲写像を書く（シェルを介さず、固定の絶対パスのみ・PATH 探索なし）
//!
//! # 呼び出し文脈・契約
//!
//! - 起動フローへの組み込みは `exec::isolate_rootless_subordinate`（TASK-40.2・#188）が担う。
//!   呼び出し元が [`unshare_user_namespace`] し、fork した mapper（`run_id_map_mapper`。外側の
//!   user namespace に残る）が親 pid へ [`apply_id_maps`] する。応答は型付きの固定 3 バイト
//!   （`MapperReply`）で返す。エラーは `ExecError`（段 `UserNamespaceMap`）へ写す
//! - 写像はカーネルが write-once（1 回しか受け付けない）。途中で失敗した対象プロセスは
//!   破棄すること（再設定できない）
//! - pid 再利用（TOCTOU）対策: 書き込み先は pid 番号ではなく、対象の `/proc/<pid>` ディレクトリ fd
//!   （[`ProcHandle`]）で固定する。mapper は先に fd を開き、その**後**に `parent_id()` が期待した親のまま
//!   であることを確認する（開いた時点で pid は生きた親を指していたと言える）。以後の書き込み・読み戻しは
//!   fd 経由（`/proc/self/fd/N/...`）で、対象が死んで pid が再利用されても別プロセスへは届かず失敗する。
//!   `newuidmap` / `newgidmap` にも pid 文字列ではなく `fd:0`（stdin に渡した同じ fd）を渡す
//!   （shadow の `fd:N` 形式。未対応の版ではヘルパーが失敗し fail-closed になる）。新規 FFI は不要
//!   （pidfd は採らない）。単独で [`apply_id_maps`] を呼ぶ場合は pid から fd を開くため、対象を reap する前
//!   （`Child` を保持した状態）に呼ぶこと
//! - SEC-5: ホスト ID 0 を含む写像と、コンテナ内 0 を持たない写像は [`IdMapSet::new`] が拒否する
//!
//! # rootless 経路の操作対応表（CORE-6・SEC-5。root 権限を要する操作の回避・代替）
//!
//! | 操作 | rootless 経路での扱い |
//! | ---- | ---- |
//! | 範囲 UID/GID 写像の書き込み | setuid の `newuidmap` / `newgidmap`（[`IdMapWriter::Helper`]）で代替 |
//! | 単一 ID 写像（自 euid → 0） | [`IdMapWriter::Direct`]（非特権で許されるのは自 ID の 1 行のみ） |
//! | `setgroups` | Direct は `deny` を書く。Helper は `newgidmap` に任せる |
//! | unshare（PID / mount / UTS / IPC）・`MS_PRIVATE`・`sethostname` | 写像後の user namespace 内 uid 0 で実行 |
//! | 自己 bind・`/proc` マウント・`pivot_root` | user namespace が所有する mount namespace 内で実行 |
//! | `mknod` によるデバイスノード作成 | 代替しない（`PermissionDenied` で fail-closed。ホスト `/dev` の bind は未実装） |
//! | cgroup 参加 | 対象外（TASK-32・CORE-3） |
//!
//! # 未実装（REPAIR-3）
//!
//! - ユーザー名 → `/etc/subuid` 行の NSS 解決は**追加しない**（`getpwuid_r` は新規 FFI のため。
//!   呼び出し側が [`SubIdOwner`] に数値 uid と検証済みユーザー名を渡す方式を維持する。
//!   ライブラリコードは `$USER` を読まない）
//! - `oci_runtime` の `linux.uidMappings` / `gidMappings` の受理（start.rs は現状拒否のまま。後続）
//! - ファイル所有者の検証（TASK-40.3・#189）

use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::exec::IdMapping;
use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;

/// カーネルが 1 つの map に受け付ける extent（行）数の上限。`user_namespaces(7)` の
/// 「Linux 4.15 以降は最大 340 行」に基づく（それ以前は 5 行だが、新しい値を上限にして
/// 旧カーネルはカーネル側の拒否に任せる）。
pub const MAX_EXTENTS: usize = 340;
/// `/etc/subuid`・`/etc/subgid` の読み取り上限（DoS 防止）。
const MAX_SUBID_FILE_BYTES: u64 = 1024 * 1024;
/// `/etc/subuid`・`/etc/subgid` の走査行数上限。
const MAX_SUBID_LINES: usize = 10_000;
/// `/proc/<pid>/{uid,gid}_map` の読み取り上限（340 行 × 最大 32 文字に十分な余裕）。
const MAX_PROC_MAP_BYTES: u64 = 64 * 1024;
/// ヘルパーの stderr をメッセージへ含める上限。
const MAX_HELPER_STDERR_BYTES: usize = 4096;
/// ヘルパー実行タイムアウトの既定（REPAIR-5）。範囲は `1..=60` 秒。
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HELPER_TIMEOUT: Duration = Duration::from_secs(60);
/// 所有者名の最大長。
const MAX_OWNER_NAME_LEN: usize = 32;

/// 失敗した段（ERR-1 の機械可読な文脈）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RootlessStage {
    /// 写像・引数の検証。
    Validate,
    /// subuid / subgid の読み取り・解析。
    ParseSubordinateIds,
    /// `newuidmap` / `newgidmap` の解決・検証。
    ResolveHelper,
    /// `unshare(CLONE_NEWUSER)`。
    Unshare,
    /// `/proc/<pid>/setgroups` への書き込み。
    SetGroups,
    /// `uid_map` への書き込み。
    UidMap,
    /// `gid_map` への書き込み。
    GidMap,
    /// ヘルパープロセスの実行。
    Helper,
    /// 書き込み後の読み戻し検証。
    Verify,
}

impl RootlessStage {
    /// 段の機械可読な名前。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::ParseSubordinateIds => "parse_subordinate_ids",
            Self::ResolveHelper => "resolve_helper",
            Self::Unshare => "unshare",
            Self::SetGroups => "setgroups",
            Self::UidMap => "uid_map",
            Self::GidMap => "gid_map",
            Self::Helper => "helper",
            Self::Verify => "verify",
        }
    }
}

/// 写像設定の失敗（ERR-1 と同形の `code` / `stage` / `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessError {
    /// 機械可読なエラーコード。
    pub code: ErrorCode,
    /// 失敗した段。
    pub stage: RootlessStage,
    /// 人間向けメッセージ（英語）。
    pub message: String,
}

impl RootlessError {
    fn new(code: ErrorCode, stage: RootlessStage, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
        }
    }

    fn invalid(stage: RootlessStage, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, stage, message)
    }
}

impl fmt::Display for RootlessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.code.as_str(),
            self.stage.as_str(),
            self.message
        )
    }
}

impl std::error::Error for RootlessError {}

/// errno を `ErrorCode` へ写す（`exec` と同じ方針。`exec` の関数は非公開のため持つ）。
fn errno_code(errno: i32) -> ErrorCode {
    if errno == sys::EPERM || errno == sys::EACCES {
        ErrorCode::PermissionDenied
    } else if errno == sys::ENOENT || errno == sys::ESRCH {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    }
}

fn io_error(stage: RootlessStage, what: &str, err: &std::io::Error) -> RootlessError {
    let code = err.raw_os_error().map_or(ErrorCode::Internal, errno_code);
    RootlessError::new(code, stage, format!("{what}: {err}"))
}

/// 写像の対象（UID か GID か）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// `uid_map` / `newuidmap`。
    Uid,
    /// `gid_map` / `newgidmap`。
    Gid,
}

impl IdKind {
    fn map_file(self) -> &'static str {
        match self {
            Self::Uid => "uid_map",
            Self::Gid => "gid_map",
        }
    }
}

/// 検証済みの写像集合。生成は [`IdMapSet::new`] のみで、壊れた写像を表現できない。
///
/// 拒否条件: 空・[`MAX_EXTENTS`] 超過・`count == 0`・u32 オーバーフロー・コンテナ側 / ホスト側の
/// 範囲重複（いずれも `InvalidArgument`）、ホスト ID 0 を含む写像（SEC-5・`PermissionDenied`）、
/// コンテナ内 0 が写像されていない構成（`InvalidArgument`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapSet {
    entries: Vec<IdMapping>,
}

fn overlaps(mut ranges: Vec<(u64, u64)>) -> bool {
    ranges.sort_unstable();
    ranges.windows(2).any(|w| match (w.first(), w.get(1)) {
        (Some(a), Some(b)) => b.0 < a.1,
        _ => false,
    })
}

impl IdMapSet {
    /// 写像を検証して集合にする。
    pub fn new(entries: Vec<IdMapping>) -> Result<Self, RootlessError> {
        let stage = RootlessStage::Validate;
        if entries.is_empty() {
            return Err(RootlessError::invalid(stage, "id mapping is empty"));
        }
        if entries.len() > MAX_EXTENTS {
            return Err(RootlessError::invalid(
                stage,
                format!("too many id mapping extents (max {MAX_EXTENTS})"),
            ));
        }
        let mut container = Vec::with_capacity(entries.len());
        let mut host = Vec::with_capacity(entries.len());
        for e in &entries {
            if e.count == 0 {
                return Err(RootlessError::invalid(stage, "id mapping count is zero"));
            }
            let c_end = u64::from(e.container_id) + u64::from(e.count);
            let h_end = u64::from(e.host_id) + u64::from(e.count);
            if c_end > u64::from(u32::MAX) + 1 || h_end > u64::from(u32::MAX) + 1 {
                return Err(RootlessError::invalid(
                    stage,
                    "id mapping range overflows u32",
                ));
            }
            if e.host_id == 0 {
                return Err(RootlessError::new(
                    ErrorCode::PermissionDenied,
                    stage,
                    "id mapping must not map any container id to host id 0 (SEC-5)",
                ));
            }
            container.push((u64::from(e.container_id), c_end));
            host.push((u64::from(e.host_id), h_end));
        }
        if overlaps(container) || overlaps(host) {
            return Err(RootlessError::invalid(stage, "id mapping ranges overlap"));
        }
        if !entries.iter().any(|e| e.container_id == 0) {
            return Err(RootlessError::invalid(
                stage,
                "container id 0 must be mapped",
            ));
        }
        Ok(Self { entries })
    }

    /// 検証済みの写像行。
    pub fn entries(&self) -> &[IdMapping] {
        &self.entries
    }

    /// コンテナ内 ID が写るホスト ID（範囲外は `None`）。
    pub fn host_id_of(&self, container_id: u32) -> Option<u32> {
        self.entries.iter().find_map(|e| {
            let off = container_id.checked_sub(e.container_id)?;
            if off < e.count {
                e.host_id.checked_add(off)
            } else {
                None
            }
        })
    }

    /// カーネルへ 1 回の write で渡す全行の連結。
    pub fn to_map_content(&self) -> String {
        self.entries.iter().map(IdMapping::to_map_line).collect()
    }
}

/// 自 ID をコンテナ内 0 へ写す単一 ID 写像（`Direct` 用）。`host_id == 0` は SEC-5 で拒否。
pub fn single_id_mapping(host_id: u32) -> Result<IdMapSet, RootlessError> {
    IdMapSet::new(vec![IdMapping {
        container_id: 0,
        host_id,
        count: 1,
    }])
}

/// 検証済みの subordinate ID 範囲。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubordinateRange {
    start: u32,
    count: u32,
}

impl SubordinateRange {
    /// 範囲を検証して作る（`count > 0` かつ u32 に収まる）。
    pub fn new(start: u32, count: u32) -> Result<Self, RootlessError> {
        if count == 0 || u64::from(start) + u64::from(count) > u64::from(u32::MAX) + 1 {
            return Err(RootlessError::invalid(
                RootlessStage::ParseSubordinateIds,
                "invalid subordinate id range",
            ));
        }
        Ok(Self { start, count })
    }

    /// 先頭のホスト ID。
    pub fn start(&self) -> u32 {
        self.start
    }

    /// ID 数。
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// `/etc/subuid` 行の第 1 フィールドと照合する所有者（数値 uid と任意のユーザー名）。
/// 名前解決（NSS）は未実装のため、名前は呼び出し側が渡す（モジュール doc 参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIdOwner {
    uid: u32,
    name: Option<String>,
}

impl SubIdOwner {
    /// 所有者を作る。名前は `[A-Za-z0-9._-]`・32 文字以内のみ許可する。
    pub fn new(uid: u32, name: Option<String>) -> Result<Self, RootlessError> {
        if let Some(n) = &name {
            let ok = !n.is_empty()
                && n.len() <= MAX_OWNER_NAME_LEN
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !ok {
                return Err(RootlessError::invalid(
                    RootlessStage::ParseSubordinateIds,
                    "invalid subordinate id owner name",
                ));
            }
        }
        Ok(Self { uid, name })
    }

    fn matches(&self, field: &str) -> bool {
        self.name.as_deref() == Some(field) || field == self.uid.to_string()
    }
}

/// `subuid(5)` 形式（`name_or_uid:start:count`）を解析し、所有者の行だけを返す。
///
/// 空行・`#` コメントは読み飛ばす。**他人の行は内容を検証せず読み飛ばし**（他ユーザーの設定不備で
/// 自分が起動できなくなるのを避ける）、**所有者の行が不正なら fail-closed**（`InvalidArgument`）。
/// 入力サイズ・行数・採用件数に上限がある。所有者の行が無ければ空 `Vec`（エラーではない）。
pub fn parse_subordinate_ids(
    bytes: &[u8],
    owner: &SubIdOwner,
) -> Result<Vec<SubordinateRange>, RootlessError> {
    let stage = RootlessStage::ParseSubordinateIds;
    if bytes.len() as u64 > MAX_SUBID_FILE_BYTES {
        return Err(RootlessError::invalid(
            stage,
            "subordinate id file too large",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RootlessError::invalid(stage, "subordinate id file is not valid UTF-8"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i >= MAX_SUBID_LINES {
            return Err(RootlessError::invalid(
                stage,
                "subordinate id file has too many lines",
            ));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let Some(first) = fields.next() else { continue };
        if !owner.matches(first) {
            continue;
        }
        let bad =
            || RootlessError::invalid(stage, format!("malformed subordinate id line {}", i + 1));
        let start = fields
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(bad)?;
        let count = fields
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(bad)?;
        if fields.next().is_some() {
            return Err(bad());
        }
        out.push(SubordinateRange::new(start, count).map_err(|_| bad())?);
        if out.len() >= MAX_EXTENTS {
            return Err(RootlessError::invalid(
                stage,
                "too many subordinate id ranges",
            ));
        }
    }
    Ok(out)
}

/// `path`（`/etc/subuid` 等）を上限付きで読み、[`parse_subordinate_ids`] へ渡す。
pub fn load_subordinate_ids(
    path: &Path,
    owner: &SubIdOwner,
) -> Result<Vec<SubordinateRange>, RootlessError> {
    let stage = RootlessStage::ParseSubordinateIds;
    let file =
        std::fs::File::open(path).map_err(|e| io_error(stage, "open subordinate id file", &e))?;
    let mut buf = Vec::new();
    file.take(MAX_SUBID_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_error(stage, "read subordinate id file", &e))?;
    parse_subordinate_ids(&buf, owner)
}

/// 「コンテナ 0 → `host_id`（1 個）、コンテナ 1.. → subordinate 範囲を順に連結」の写像を作る
/// （CORE-6・SEC-5）。`host_id == 0` は拒否。
pub fn rootless_mapping(
    host_id: u32,
    ranges: &[SubordinateRange],
) -> Result<IdMapSet, RootlessError> {
    // 確保前に件数を上限検証する（先頭の 1 件 + ranges。無制限確保による DoS を防ぐ）。
    if ranges.len() >= MAX_EXTENTS {
        return Err(RootlessError::invalid(
            RootlessStage::Validate,
            format!("too many id mapping extents (max {MAX_EXTENTS})"),
        ));
    }
    let mut entries = Vec::with_capacity(ranges.len() + 1);
    entries.push(IdMapping {
        container_id: 0,
        host_id,
        count: 1,
    });
    // 終端は u64 で持つ（u32::MAX + 1 で終わる範囲も有効。次の範囲がある場合だけ u32 へ変換する）。
    let mut next: u64 = 1;
    for r in ranges {
        let container_id = u32::try_from(next).map_err(|_| {
            RootlessError::invalid(RootlessStage::Validate, "container id range overflows u32")
        })?;
        entries.push(IdMapping {
            container_id,
            host_id: r.start,
            count: r.count,
        });
        next += u64::from(r.count);
    }
    IdMapSet::new(entries)
}

/// 書き込み対象プロセスの pid（`1..=i32::MAX`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetPid(u32);

impl TargetPid {
    /// pid を検証して作る。
    pub fn new(pid: u32) -> Result<Self, RootlessError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(RootlessError::invalid(
                RootlessStage::Validate,
                "invalid target pid",
            ));
        }
        Ok(Self(pid))
    }

    /// pid の値。
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// 対象プロセスの `/proc/<pid>` ディレクトリ fd。pid 番号ではなくプロセス同一性へ書き込み先を固定する
/// （SEC-5・CORE-6・TASK-40.2。pid 再利用の TOCTOU 対策）。
///
/// fd を開いた後に対象が終了すると、fd 配下のファイル open は `ENOENT` / `ESRCH` で失敗し、同じ pid を
/// 得た別プロセスへは届かない。
#[derive(Debug)]
pub struct ProcHandle {
    dir: std::fs::File,
    pid: TargetPid,
}

impl ProcHandle {
    /// `/proc/<pid>` を開く。呼び出し側は、開いた**後**に対象が期待したプロセスのままであること
    /// （例: `parent_id()`）を確認すること。
    pub fn open(pid: TargetPid) -> Result<Self, RootlessError> {
        let dir = std::fs::File::open(format!("/proc/{}", pid.0))
            .map_err(|e| io_error(RootlessStage::Validate, "open target proc directory", &e))?;
        Ok(Self { dir, pid })
    }

    /// 対象 pid（表示・検証用。書き込み先の解決には使わない）。
    pub fn pid(&self) -> TargetPid {
        self.pid
    }

    /// fd 配下のファイルのパス（`/proc/self/fd/N/<name>`。fd の指すプロセスへ解決される）。
    fn proc_file(&self, name: &str) -> PathBuf {
        use std::os::fd::AsRawFd as _;
        PathBuf::from(format!("/proc/self/fd/{}/{name}", self.dir.as_raw_fd()))
    }
}

/// ヘルパーの同一性（`st_dev` / `st_ino`）。検証時点と実行直前の再検証で比較し、差し替えを検出する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

/// `newuidmap` / `newgidmap` の検証済みパス。絶対パスのみ・PATH 探索なし・通常ファイル
/// （symlink 不可）・所有者 root・group/other 書き込み不可（差し替えられた実行ファイルを拒否。
/// PLUG-11 と同じ思想）。さらに全祖先ディレクトリも root 所有・group/other 書き込み不可を要求し
/// （非 root がディレクトリエントリを差し替えられない状態を保証して TOCTOU を塞ぐ）、検証時の
/// dev/ino を保持して [`run_helper`] の exec 直前に再検証・同一性比較する。
/// setuid ビットは要求しない（file capability 方式の配布があるため）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPaths {
    newuidmap: PathBuf,
    newgidmap: PathBuf,
    uid_identity: FileIdentity,
    gid_identity: FileIdentity,
}

fn check_helper(path: &Path) -> Result<FileIdentity, RootlessError> {
    let stage = RootlessStage::ResolveHelper;
    if !path.is_absolute() {
        return Err(RootlessError::invalid(
            stage,
            "helper path must be absolute",
        ));
    }
    let meta = std::fs::symlink_metadata(path).map_err(|e| io_error(stage, "stat helper", &e))?;
    if !meta.file_type().is_file() {
        return Err(RootlessError::new(
            ErrorCode::PermissionDenied,
            stage,
            "helper must be a regular file",
        ));
    }
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(RootlessError::new(
            ErrorCode::PermissionDenied,
            stage,
            "helper must be owned by root and not writable by group/other",
        ));
    }
    // 祖先ディレクトリ（symlink は解決した先の実体）が root 所有かつ group/other 書き込み不可で
    // あること。非 root が親ディレクトリのエントリを差し替えられる経路を閉じる。
    for dir in path.ancestors().skip(1) {
        let dmeta =
            std::fs::metadata(dir).map_err(|e| io_error(stage, "stat helper parent", &e))?;
        if !dmeta.is_dir() || dmeta.uid() != 0 || dmeta.mode() & 0o022 != 0 {
            return Err(RootlessError::new(
                ErrorCode::PermissionDenied,
                stage,
                "helper parent directories must be owned by root and not writable by group/other",
            ));
        }
    }
    Ok(FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

impl HelperPaths {
    /// 明示パスを検証して作る。
    pub fn new(newuidmap: &Path, newgidmap: &Path) -> Result<Self, RootlessError> {
        let uid_identity = check_helper(newuidmap)?;
        let gid_identity = check_helper(newgidmap)?;
        Ok(Self {
            newuidmap: newuidmap.to_path_buf(),
            newgidmap: newgidmap.to_path_buf(),
            uid_identity,
            gid_identity,
        })
    }

    /// 固定の既定位置（`/usr/bin/newuidmap`・`/usr/bin/newgidmap`）を検証して作る。
    pub fn system_default() -> Result<Self, RootlessError> {
        Self::new(
            Path::new("/usr/bin/newuidmap"),
            Path::new("/usr/bin/newgidmap"),
        )
    }

    fn path_for(&self, kind: IdKind) -> &Path {
        match kind {
            IdKind::Uid => &self.newuidmap,
            IdKind::Gid => &self.newgidmap,
        }
    }

    fn identity_for(&self, kind: IdKind) -> FileIdentity {
        match kind {
            IdKind::Uid => self.uid_identity,
            IdKind::Gid => self.gid_identity,
        }
    }
}

/// 写像の書き込み経路。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdMapWriter {
    /// `/proc/<pid>/*` へ直接書く。
    Direct,
    /// `newuidmap` / `newgidmap` を実行する（タイムアウトは [`apply_id_maps`] の引数）。
    Helper(HelperPaths),
}

/// 書き込み経路の種別（[`IdMapReport`] 用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterKind {
    /// 直接書き込み。
    Direct,
    /// ヘルパー経由。
    Helper,
}

/// 設定・読み戻し検証が済んだ写像の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapReport {
    /// 設定した UID 写像。
    pub uid: IdMapSet,
    /// 設定した GID 写像。
    pub gid: IdMapSet,
    /// 使った書き込み経路。
    pub writer: WriterKind,
}

/// 新しい user namespace へ入る（写像は書かない）。写像は write-once のため、親が子 pid に
/// [`apply_id_maps`] で後から書く方式で使う。
///
/// シングルスレッドから呼ぶこと（マルチスレッドは `EINVAL`）。失敗したプロセスは破棄する。
pub fn unshare_user_namespace() -> Result<(), RootlessError> {
    sys::unshare_namespaces(&[NsFlag::User]).map_err(|e| {
        let code = match e {
            SysError::Unsupported => ErrorCode::Unimplemented,
            SysError::MultiThreaded => ErrorCode::FailedPrecondition,
            SysError::Os(n) if n == sys::EINVAL => ErrorCode::FailedPrecondition,
            SysError::Os(n) => errno_code(n),
        };
        RootlessError::new(
            code,
            RootlessStage::Unshare,
            format!("unshare(CLONE_NEWUSER) failed: {e:?}"),
        )
    })
}

/// 非特権（euid != 0）の `Direct` 書き込みが満たすべき条件を書き込み前に検証する
/// （カーネルの EPERM を待たない fail-closed）。`user_namespaces(7)`: 単一行・自 euid/egid への写像。
fn check_direct_allowed(
    uid: &IdMapSet,
    gid: &IdMapSet,
    euid: u32,
    egid: u32,
) -> Result<(), RootlessError> {
    if euid == 0 {
        return Ok(());
    }
    let single_to =
        |set: &IdMapSet, id: u32| matches!(set.entries(), [e] if e.count == 1 && e.host_id == id);
    if single_to(uid, euid) && single_to(gid, egid) {
        Ok(())
    } else {
        Err(RootlessError::new(
            ErrorCode::PermissionDenied,
            RootlessStage::Validate,
            "unprivileged direct write allows only a single mapping to the caller's own euid/egid; use the helper writer",
        ))
    }
}

fn write_proc(path: &Path, content: &str, stage: RootlessStage) -> Result<(), RootlessError> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| io_error(stage, "open proc file", &e))?;
    f.write_all(content.as_bytes())
        .map_err(|e| io_error(stage, "write proc file", &e))
}

fn sanitize_stderr(raw: &[u8]) -> String {
    let cut = raw.get(..MAX_HELPER_STDERR_BYTES).unwrap_or(raw);
    String::from_utf8_lossy(cut)
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect()
}

/// 検証済みヘルパーを実行する。exec 直前に所有者・権限・祖先ディレクトリ・dev/ino を再検証し、
/// [`HelperPaths::new`] 時点から差し替えられていれば拒否する（TOCTOU 対策。祖先が root 専有のため
/// 非 root は残る窓でも差し替えられない）。
fn run_helper(
    paths: &HelperPaths,
    target: &ProcHandle,
    set: &IdMapSet,
    kind: IdKind,
    timeout: Duration,
) -> Result<(), RootlessError> {
    let stage = RootlessStage::Helper;
    let path = paths.path_for(kind);
    if check_helper(path)? != paths.identity_for(kind) {
        return Err(RootlessError::new(
            ErrorCode::PermissionDenied,
            RootlessStage::ResolveHelper,
            "helper was replaced after validation",
        ));
    }
    // 対象は pid 番号ではなく `/proc/<pid>` fd（stdin = fd 0）で渡す（pid 再利用対策）。
    let stdin_fd = target
        .dir
        .try_clone()
        .map_err(|e| io_error(stage, "duplicate target proc directory", &e))?;
    let mut cmd = Command::new(path);
    cmd.arg("fd:0");
    for e in set.entries() {
        cmd.arg(e.container_id.to_string())
            .arg(e.host_id.to_string())
            .arg(e.count.to_string());
    }
    cmd.env_clear()
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(stdin_fd)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| io_error(stage, "spawn id map helper", &e))?;
    // stderr は実行中に上限付きで並行読み取りする（パイプ詰まりによるヘルパー停止の防止。REPAIR-5）。
    // 上限超過分は読み捨ててパイプを空け続ける。
    let stderr_rx = child.stderr.take().map(|mut s| {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = MAX_HELPER_STDERR_BYTES.saturating_sub(kept.len());
                        if let Some(chunk) = buf.get(..n.min(room)) {
                            kept.extend_from_slice(chunk);
                        }
                    }
                }
            }
            let _ = tx.send(kept);
        });
        rx
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RootlessError::new(
                    ErrorCode::Timeout,
                    stage,
                    format!("id map helper for {} timed out", kind.map_file()),
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io_error(stage, "wait id map helper", &e));
            }
        }
    };
    if status.success() {
        return Ok(());
    }
    // 読み取りスレッドはパイプ EOF で合流する。孫プロセスが fd を保持する場合に備え待ちは有界にする。
    let err = stderr_rx
        .and_then(|rx| rx.recv_timeout(Duration::from_secs(1)).ok())
        .unwrap_or_default();
    Err(RootlessError::new(
        ErrorCode::PermissionDenied,
        stage,
        format!("id map helper failed ({status}): {}", sanitize_stderr(&err)),
    ))
}

/// `/proc/<pid>/{uid,gid}_map` の内容（空白区切り 3 数値の行）を解析する。
pub fn parse_id_map(bytes: &[u8]) -> Result<Vec<IdMapping>, RootlessError> {
    let stage = RootlessStage::Verify;
    let bad = || RootlessError::new(ErrorCode::Internal, stage, "malformed id map line");
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut it = line.split_whitespace().map(|f| f.parse::<u32>().ok());
        let (Some(Some(c)), Some(Some(h)), Some(Some(n)), None) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(bad());
        };
        if out.len() >= MAX_EXTENTS {
            return Err(bad());
        }
        out.push(IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        });
    }
    Ok(out)
}

/// `/proc/<pid>/{uid,gid}_map` を上限付きで読んで解析する。
pub fn read_id_map(pid: TargetPid, kind: IdKind) -> Result<Vec<IdMapping>, RootlessError> {
    read_id_map_of(&ProcHandle::open(pid)?, kind)
}

/// [`ProcHandle`] の指すプロセスの map を上限付きで読んで解析する。
pub fn read_id_map_of(target: &ProcHandle, kind: IdKind) -> Result<Vec<IdMapping>, RootlessError> {
    let stage = RootlessStage::Verify;
    let f = std::fs::File::open(target.proc_file(kind.map_file()))
        .map_err(|e| io_error(stage, "open id map", &e))?;
    let mut buf = Vec::new();
    f.take(MAX_PROC_MAP_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_error(stage, "read id map", &e))?;
    if buf.len() as u64 > MAX_PROC_MAP_BYTES {
        return Err(RootlessError::new(
            ErrorCode::Internal,
            stage,
            "id map too large",
        ));
    }
    parse_id_map(&buf)
}

/// 対象 pid の user namespace に UID/GID 写像を設定し、読み戻して一致を確かめる（CORE-6・SEC-5）。
///
/// `timeout` は `Helper` のみに効き、`1..=60` 秒に制限する（範囲外は `InvalidArgument`）。
/// 失敗した場合、写像は write-once のため対象プロセスは破棄すること。
pub fn apply_id_maps(
    pid: TargetPid,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
) -> Result<IdMapReport, RootlessError> {
    apply_id_maps_to(&ProcHandle::open(pid)?, uid, gid, writer, timeout)
}

/// 開いた [`ProcHandle`] の指すプロセスへ写像を設定する（pid 再利用に耐える本体。CORE-6・SEC-5）。
pub fn apply_id_maps_to(
    target: &ProcHandle,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
) -> Result<IdMapReport, RootlessError> {
    apply_id_maps_as(
        target,
        uid,
        gid,
        writer,
        timeout,
        sys::effective_uid(),
        sys::effective_gid(),
    )
}

/// euid / egid を注入できる本体（事前検証をテストするため分離）。
fn apply_id_maps_as(
    pid: &ProcHandle,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
    euid: u32,
    egid: u32,
) -> Result<IdMapReport, RootlessError> {
    if timeout < Duration::from_secs(1) || timeout > MAX_HELPER_TIMEOUT {
        return Err(RootlessError::invalid(
            RootlessStage::Validate,
            "helper timeout must be within 1..=60 seconds",
        ));
    }
    let kind = match writer {
        IdMapWriter::Direct => {
            check_direct_allowed(uid, gid, euid, egid)?;
            if euid != 0 {
                write_proc(
                    &pid.proc_file("setgroups"),
                    "deny",
                    RootlessStage::SetGroups,
                )?;
            }
            write_proc(
                &pid.proc_file("uid_map"),
                &uid.to_map_content(),
                RootlessStage::UidMap,
            )?;
            write_proc(
                &pid.proc_file("gid_map"),
                &gid.to_map_content(),
                RootlessStage::GidMap,
            )?;
            WriterKind::Direct
        }
        IdMapWriter::Helper(paths) => {
            run_helper(paths, pid, uid, IdKind::Uid, timeout)?;
            run_helper(paths, pid, gid, IdKind::Gid, timeout)?;
            WriterKind::Helper
        }
    };
    for (k, set) in [(IdKind::Uid, uid), (IdKind::Gid, gid)] {
        let got = read_id_map_of(pid, k)?;
        if got != set.entries() {
            return Err(RootlessError::new(
                ErrorCode::Internal,
                RootlessStage::Verify,
                format!(
                    "{} read back does not match the written mapping",
                    k.map_file()
                ),
            ));
        }
    }
    Ok(IdMapReport {
        uid: uid.clone(),
        gid: gid.clone(),
        writer: kind,
    })
}

/// 親へ「unshare 完了。写像を書いてよい」と知らせる 1 バイト（[`run_id_map_mapper`] が待つ）。
pub(crate) const MAPPER_GO: u8 = 1;

/// mapper の応答フレーム長（`[tag, code, stage]` の固定 3 バイト）。
pub(crate) const MAPPER_REPLY_LEN: usize = 3;
const REPLY_TAG_OK: u8 = 0;
const REPLY_TAG_FAILED: u8 = 1;

/// mapper（外側の user namespace に残る fork 子）が、写像を書いた呼び出し元へ返す応答（REPAIR-2）。
///
/// 固定 3 バイト `[tag, code, stage]` に符号化し、自由形式の文字列は載せない（詳細は mapper の
/// stderr へ出す）。復号は完全一致のみ受け付け、未知の値・長さ不足は `Internal` で拒否する
/// （`exec::isolate_rootless_subordinate` が読む。CORE-6・TASK-40.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapperReply {
    /// 写像の書き込みと読み戻し検証が済んだ。
    Ok,
    /// 失敗した（`RootlessError` の `code` / `stage` のみ運ぶ）。
    Failed {
        code: ErrorCode,
        stage: RootlessStage,
    },
}

/// 応答へ載せられる `ErrorCode`（`RootlessError` が取り得るものに限る）。
const REPLY_CODES: [ErrorCode; 7] = [
    ErrorCode::InvalidArgument,
    ErrorCode::PermissionDenied,
    ErrorCode::NotFound,
    ErrorCode::Internal,
    ErrorCode::Timeout,
    ErrorCode::FailedPrecondition,
    ErrorCode::Unimplemented,
];

const REPLY_STAGES: [RootlessStage; 9] = [
    RootlessStage::Validate,
    RootlessStage::ParseSubordinateIds,
    RootlessStage::ResolveHelper,
    RootlessStage::Unshare,
    RootlessStage::SetGroups,
    RootlessStage::UidMap,
    RootlessStage::GidMap,
    RootlessStage::Helper,
    RootlessStage::Verify,
];

impl MapperReply {
    /// 固定長フレームへ符号化する。表に無い `code`（到達しない）は `Internal` に丸める。
    pub(crate) fn encode(&self) -> [u8; MAPPER_REPLY_LEN] {
        match self {
            Self::Ok => [REPLY_TAG_OK, 0, 0],
            Self::Failed { code, stage } => {
                let c = REPLY_CODES.iter().position(|x| x == code).unwrap_or(3);
                let s = REPLY_STAGES.iter().position(|x| x == stage).unwrap_or(0);
                // 表の添字は 255 に収まる（長さ 7 / 9）。
                [REPLY_TAG_FAILED, c as u8, s as u8]
            }
        }
    }

    /// 完全一致のみ受け付ける復号。長さ不一致・未知の tag / code / stage は `Internal`。
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RootlessError> {
        let bad = |m: &str| RootlessError::new(ErrorCode::Internal, RootlessStage::Helper, m);
        let [tag, code, stage] = match <[u8; MAPPER_REPLY_LEN]>::try_from(bytes) {
            Ok(a) => a,
            Err(_) => return Err(bad("malformed mapper reply length")),
        };
        match tag {
            REPLY_TAG_OK if code == 0 && stage == 0 => Ok(Self::Ok),
            REPLY_TAG_FAILED => {
                let code = REPLY_CODES
                    .get(usize::from(code))
                    .copied()
                    .ok_or_else(|| bad("unknown error code in mapper reply"))?;
                let stage = REPLY_STAGES
                    .get(usize::from(stage))
                    .copied()
                    .ok_or_else(|| bad("unknown stage in mapper reply"))?;
                Ok(Self::Failed { code, stage })
            }
            _ => Err(bad("unknown tag in mapper reply")),
        }
    }
}

/// mapper の処理本体（fork 子が呼ぶ。成功なら終了コード 0、失敗なら 1）。
///
/// 流れ: `sock` から [`MAPPER_GO`] を `timeout` まで待つ → 親の `/proc/<pid>` fd を開いたうえで、親が
/// 最初の親 `expected_parent` のままであることを `parent_id()` で再確認する（reparent 後に無関係な
/// pid へ書かない。pid 再利用・TOCTOU 対策）→ [`apply_id_maps_to`] を fd に対して実行 → 応答フレームを返す。
/// 親が死んでも mapper 側の fd は閉じられず EOF を当てにできないため、待ちは read タイムアウトで
/// 止める（REPAIR-5）。詳細は stderr へ出す（自由形式の文字列は応答に載せない）。
pub(crate) fn run_id_map_mapper(
    expected_parent: u32,
    mut sock: std::os::unix::net::UnixStream,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
) -> i32 {
    let outcome = mapper_outcome(expected_parent, &mut sock, uid, gid, writer, timeout);
    let (reply, code) = match outcome {
        Ok(()) => (MapperReply::Ok, 0),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "fandhe-container: id map mapper: {e}");
            (
                MapperReply::Failed {
                    code: e.code,
                    stage: e.stage,
                },
                1,
            )
        }
    };
    let _ = sock.set_write_timeout(Some(timeout));
    let _ = sock.write_all(&reply.encode());
    code
}

fn mapper_outcome(
    expected_parent: u32,
    sock: &mut std::os::unix::net::UnixStream,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
) -> Result<(), RootlessError> {
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| io_error(RootlessStage::Validate, "set mapper read timeout", &e))?;
    let mut go = [0u8; 1];
    sock.read_exact(&mut go).map_err(|e| {
        RootlessError::new(
            ErrorCode::Timeout,
            RootlessStage::Validate,
            format!("did not receive the go signal from the parent: {e}"),
        )
    })?;
    if go[0] != MAPPER_GO {
        return Err(RootlessError::invalid(
            RootlessStage::Validate,
            "unexpected go signal byte",
        ));
    }
    // 先に `/proc/<pid>` fd を確保し、その後で親が変わっていないことを確認する。親が生きていれば
    // （= reparent されていなければ）fd は確実に元の親を指す。以後の書き込みは fd 経由のため、
    // 確認後に親が死んで pid が再利用されても別プロセスへは届かない（SEC-5・TASK-40.2）。
    let handle = ProcHandle::open(TargetPid::new(expected_parent)?)?;
    if std::os::unix::process::parent_id() != expected_parent {
        return Err(RootlessError::new(
            ErrorCode::FailedPrecondition,
            RootlessStage::Validate,
            "the parent process changed before the mapping was written",
        ));
    }
    apply_id_maps_to(&handle, uid, gid, writer, timeout).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        }
    }

    fn owner() -> SubIdOwner {
        SubIdOwner::new(1000, Some("alice".to_string())).expect("owner")
    }

    #[test]
    fn core6_sec5_rootless_mapping_maps_container_root_to_host_uid() {
        let r = SubordinateRange::new(100000, 65536).expect("range");
        let set = rootless_mapping(1000, &[r]).expect("mapping");
        assert_eq!(set.entries(), &[m(0, 1000, 1), m(1, 100000, 65536)]);
        assert_eq!(set.host_id_of(0), Some(1000));
        assert_eq!(set.host_id_of(2), Some(100001));
        assert_eq!(set.host_id_of(65537), None);
        assert_eq!(set.to_map_content(), "0 1000 1\n1 100000 65536\n");
    }

    #[test]
    fn sec5_rejects_host_root_in_any_range() {
        let e = rootless_mapping(0, &[]).expect_err("host 0");
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::PermissionDenied, RootlessStage::Validate)
        );
        let r = SubordinateRange::new(0, 10).expect("range");
        let e = rootless_mapping(1000, &[r]).expect_err("range with host 0");
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        let e = IdMapSet::new(vec![m(0, 0, 1)]).expect_err("0 0 1");
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(
            single_id_mapping(0).expect_err("single").code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn core6_rejects_invalid_sets() {
        let inv = |v: Vec<IdMapping>| IdMapSet::new(v).expect_err("invalid").code;
        assert_eq!(inv(vec![]), ErrorCode::InvalidArgument);
        assert_eq!(inv(vec![m(0, 1000, 0)]), ErrorCode::InvalidArgument);
        assert_eq!(
            inv(vec![m(0, 1000, 2), m(1, 5000, 1)]),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            inv(vec![m(0, 1000, 2), m(5, 1001, 1)]),
            ErrorCode::InvalidArgument
        );
        assert_eq!(inv(vec![m(0, u32::MAX, 2)]), ErrorCode::InvalidArgument);
        assert_eq!(inv(vec![m(1, 1000, 1)]), ErrorCode::InvalidArgument);
        let many: Vec<IdMapping> = (0..=MAX_EXTENTS as u32)
            .map(|i| m(i, 1000 + i, 1))
            .collect();
        assert_eq!(many.len(), 341);
        assert_eq!(inv(many), ErrorCode::InvalidArgument);
        assert!(IdMapSet::new(vec![m(0, u32::MAX, 1)]).is_ok());
    }

    #[test]
    fn core6_rootless_mapping_rejects_too_many_ranges_before_allocation() {
        let ranges: Vec<SubordinateRange> = (0..MAX_EXTENTS as u32)
            .map(|i| SubordinateRange {
                start: 100_000 + i * 10,
                count: 1,
            })
            .collect();
        assert_eq!(ranges.len(), MAX_EXTENTS);
        let err = rootless_mapping(1000, &ranges).expect_err("too many");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(rootless_mapping(1000, &ranges[..MAX_EXTENTS - 1]).is_ok());
    }

    #[test]
    fn core6_parse_subordinate_ids_selects_owner_lines() {
        let text = b"# c\n\nbob:200000:65536\nalice:100000:65536\n1000:300000:10\n";
        let got = parse_subordinate_ids(text, &owner()).expect("parse");
        assert_eq!(
            got,
            vec![
                SubordinateRange::new(100000, 65536).expect("r"),
                SubordinateRange::new(300000, 10).expect("r")
            ]
        );
        assert_eq!(
            parse_subordinate_ids(b"bob:1:2\n", &owner()).expect("none"),
            vec![]
        );
        // 他人の不正行は読み飛ばす。
        assert!(parse_subordinate_ids(b"bob:x\nalice:1:2\n", &owner()).is_ok());
    }

    #[test]
    fn core6_parse_subordinate_ids_rejects_malformed_owner_lines_and_limits() {
        for bad in [
            "alice:1\n",
            "alice:x:2\n",
            "alice:1:0\n",
            "alice:1:2:3\n",
            "alice:4294967295:2\n",
        ] {
            let e = parse_subordinate_ids(bad.as_bytes(), &owner()).expect_err(bad);
            assert_eq!(
                (e.code, e.stage),
                (
                    ErrorCode::InvalidArgument,
                    RootlessStage::ParseSubordinateIds
                )
            );
        }
        let big = vec![b'#'; (MAX_SUBID_FILE_BYTES + 1) as usize];
        assert!(parse_subordinate_ids(&big, &owner()).is_err());
        let lines = "#\n".repeat(MAX_SUBID_LINES + 1);
        assert!(parse_subordinate_ids(lines.as_bytes(), &owner()).is_err());
        assert!(SubIdOwner::new(1, Some("a b".to_string())).is_err());
        assert!(SubIdOwner::new(1, Some("a:b".to_string())).is_err());
    }

    #[test]
    fn core6_parse_id_map_handles_kernel_padding() {
        let got =
            parse_id_map(b"         0       1000          1\n         1     100000      65536\n")
                .expect("parse");
        assert_eq!(got, vec![m(0, 1000, 1), m(1, 100000, 65536)]);
        assert!(parse_id_map(b"0 1000\n").is_err());
        assert!(parse_id_map(b"0 1000 1 9\n").is_err());
        assert!(parse_id_map(b"a b c\n").is_err());
    }

    #[test]
    fn core6_target_pid_and_helper_paths_validation() {
        assert!(TargetPid::new(0).is_err());
        assert!(TargetPid::new(i32::MAX as u32 + 1).is_err());
        assert_eq!(TargetPid::new(42).expect("pid").get(), 42);
        assert!(HelperPaths::new(Path::new("newuidmap"), Path::new("/usr/bin/newgidmap")).is_err());
        // 一時ファイルは呼び出しユーザー所有（root 所有ではない）ため拒否される。
        if sys::effective_uid() != 0 {
            let dir = std::env::temp_dir().join(format!("fandhe-rootless-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");
            let f = dir.join("helper");
            std::fs::write(&f, b"x").expect("write");
            let e = HelperPaths::new(&f, &f).expect_err("not root owned");
            assert_eq!(
                (e.code, e.stage),
                (ErrorCode::PermissionDenied, RootlessStage::ResolveHelper)
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// PLUG-11 相当: 祖先ディレクトリが呼び出しユーザー所有（差し替え可能）なら root 所有の
    /// ヘルパーでも拒否する。root 実行時は検証できないためスキップ相当（所有者が一致するため）。
    #[test]
    fn core6_helper_rejects_non_root_parent_directory() {
        if sys::effective_uid() == 0 {
            return;
        }
        // /usr/bin/env は root 所有だが、親が非 root のディレクトリへ置いた場合の拒否を
        // 一時ディレクトリ配下の通常ファイルで確認する（ファイル自体も非 root のため
        // ResolveHelper 段で PermissionDenied になる）。
        let dir =
            std::env::temp_dir().join(format!("fandhe-rootless-parent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let f = dir.join("helper");
        std::fs::write(&f, b"x").expect("write");
        let e = check_helper(&f).expect_err("non-root parent");
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::PermissionDenied, RootlessStage::ResolveHelper)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sec5_direct_precheck_rejects_range_for_unprivileged() {
        let single = single_id_mapping(1000).expect("single");
        let range = rootless_mapping(1000, &[SubordinateRange::new(100000, 10).expect("r")])
            .expect("range");
        assert!(check_direct_allowed(&single, &single, 1000, 1000).is_ok());
        assert!(check_direct_allowed(&range, &single, 1000, 1000).is_err());
        assert!(check_direct_allowed(&single, &single, 1001, 1000).is_err());
        assert!(check_direct_allowed(&range, &range, 0, 0).is_ok());
        let pid = ProcHandle::open(TargetPid::new(std::process::id()).expect("pid")).expect("fd");
        let pid = &pid;
        let e = apply_id_maps_as(
            pid,
            &range,
            &single,
            &IdMapWriter::Direct,
            DEFAULT_HELPER_TIMEOUT,
            1000,
            1000,
        )
        .expect_err("precheck");
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::PermissionDenied, RootlessStage::Validate)
        );
        let e = apply_id_maps_as(
            pid,
            &single,
            &single,
            &IdMapWriter::Direct,
            Duration::from_secs(0),
            1000,
            1000,
        )
        .expect_err("timeout range");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }

    /// CORE-6（TASK-40.2）: mapper 応答は全 code・全 stage で往復し、固定 3 バイトになる。
    #[test]
    fn core6_mapper_reply_roundtrip() {
        assert_eq!(MapperReply::Ok.encode(), [0, 0, 0]);
        assert_eq!(
            MapperReply::decode(&[0, 0, 0]).expect("ok"),
            MapperReply::Ok
        );
        for code in REPLY_CODES {
            for stage in REPLY_STAGES {
                let r = MapperReply::Failed { code, stage };
                let bytes = r.encode();
                assert_eq!(bytes.len(), 3);
                assert_eq!(MapperReply::decode(&bytes).expect("decode"), r);
            }
        }
        assert_eq!(
            MapperReply::Failed {
                code: ErrorCode::Timeout,
                stage: RootlessStage::Helper
            }
            .encode(),
            [1, 4, 7]
        );
    }

    /// CORE-6（TASK-40.2）: 未知の tag・code・stage と長さ不一致は `Internal` で拒否する（REPAIR-2）。
    #[test]
    fn core6_mapper_reply_rejects_malformed() {
        let cases: [&[u8]; 9] = [
            &[],
            &[0],
            &[0, 0],
            &[0, 0, 0, 0],
            &[2, 0, 0],
            &[0, 1, 0],
            &[1, 7, 0],
            &[1, 0, 9],
            &[1, 255, 255],
        ];
        for bytes in cases {
            let e = MapperReply::decode(bytes).expect_err("malformed");
            assert_eq!(e.code, ErrorCode::Internal, "bytes {bytes:?}");
        }
    }

    fn mapper_fixture() -> (IdMapSet, IdMapSet) {
        let s = single_id_mapping(1000).expect("single");
        (s.clone(), s)
    }

    /// CORE-6（TASK-40.2）: go 信号が来ないまま timeout になると mapper は書き込まずに
    /// `Timeout` を返して終了コード 1 になる（親の死・停止でハングしない。REPAIR-5）。
    #[test]
    fn core6_mapper_times_out_without_go_signal() {
        let (parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        let (uid, gid) = mapper_fixture();
        let code = run_id_map_mapper(
            std::os::unix::process::parent_id(),
            mapper_end,
            &uid,
            &gid,
            &IdMapWriter::Direct,
            Duration::from_secs(1),
        );
        assert_eq!(code, 1);
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        let mut p = parent_end;
        p.read_exact(&mut buf).expect("reply");
        assert_eq!(
            MapperReply::decode(&buf).expect("decode"),
            MapperReply::Failed {
                code: ErrorCode::Timeout,
                stage: RootlessStage::Validate
            }
        );
    }

    /// CORE-6・SEC-5（TASK-40.2）: 親 pid が期待と違えば（reparent 後の pid 再利用を想定）
    /// 書き込まず `FailedPrecondition` を返す。
    #[test]
    fn core6_mapper_refuses_when_parent_changed() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[MAPPER_GO]).expect("go");
        let (uid, gid) = mapper_fixture();
        let wrong = std::os::unix::process::parent_id() ^ 1;
        let code = run_id_map_mapper(
            wrong,
            mapper_end,
            &uid,
            &gid,
            &IdMapWriter::Direct,
            Duration::from_secs(1),
        );
        assert_eq!(code, 1);
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        parent_end.read_exact(&mut buf).expect("reply");
        assert_eq!(
            MapperReply::decode(&buf).expect("decode"),
            MapperReply::Failed {
                code: ErrorCode::FailedPrecondition,
                stage: RootlessStage::Validate
            }
        );
    }

    /// CORE-6（TASK-40.2）: go 以外のバイトは `InvalidArgument` で拒否する。
    #[test]
    fn core6_mapper_rejects_unexpected_go_byte() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[9]).expect("byte");
        let (uid, gid) = mapper_fixture();
        let code = run_id_map_mapper(
            std::os::unix::process::parent_id(),
            mapper_end,
            &uid,
            &gid,
            &IdMapWriter::Direct,
            Duration::from_secs(1),
        );
        assert_eq!(code, 1);
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        parent_end.read_exact(&mut buf).expect("reply");
        assert_eq!(
            MapperReply::decode(&buf).expect("decode"),
            MapperReply::Failed {
                code: ErrorCode::InvalidArgument,
                stage: RootlessStage::Validate
            }
        );
    }
}
