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
//! - 起動フローへの組み込み（子が [`unshare_user_namespace`] → 親が子 pid に
//!   [`apply_id_maps`]）は TASK-40.2（#188）で `exec` 側から行う予定で、本モジュールは部品のみ。
//!   エラーは `ExecError` へ写す想定（`RootlessError` は ERR-1 と同形の `code` / `stage`）
//! - 写像はカーネルが write-once（1 回しか受け付けない）。途中で失敗した対象プロセスは
//!   破棄すること（再設定できない）
//! - pid 再利用（TOCTOU）対策として、呼び出し側は対象を reap する前（`Child` を保持した状態）に
//!   [`apply_id_maps`] を呼ぶこと。pidfd による固定は新規 FFI になるため未実装（#188 で判断）
//! - SEC-5: ホスト ID 0 を含む写像と、コンテナ内 0 を持たない写像は [`IdMapSet::new`] が拒否する
//!
//! # 未実装（REPAIR-3）
//!
//! - ユーザー名 → `/etc/subuid` 行の NSS 解決（`getpwuid_r` は新規 FFI のため採らない。
//!   呼び出し側が [`SubIdOwner`] に数値 uid と検証済みユーザー名を渡す）。TASK-40.2（#188）で判断
//! - `oci_runtime` の `linux.uidMappings` / `gidMappings` の受理（TASK-40.2）
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
    let mut entries = vec![IdMapping {
        container_id: 0,
        host_id,
        count: 1,
    }];
    let mut next: u32 = 1;
    for r in ranges {
        entries.push(IdMapping {
            container_id: next,
            host_id: r.start,
            count: r.count,
        });
        next = next.checked_add(r.count).ok_or_else(|| {
            RootlessError::invalid(RootlessStage::Validate, "container id range overflows u32")
        })?;
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

    fn proc_file(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/{}/{name}", self.0))
    }
}

/// `newuidmap` / `newgidmap` の検証済みパス。絶対パスのみ・PATH 探索なし・通常ファイル
/// （symlink 不可）・所有者 root・group/other 書き込み不可（差し替えられた実行ファイルを拒否。
/// PLUG-11 と同じ思想）。setuid ビットは要求しない（file capability 方式の配布があるため）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPaths {
    newuidmap: PathBuf,
    newgidmap: PathBuf,
}

fn check_helper(path: &Path) -> Result<(), RootlessError> {
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
    Ok(())
}

impl HelperPaths {
    /// 明示パスを検証して作る。
    pub fn new(newuidmap: &Path, newgidmap: &Path) -> Result<Self, RootlessError> {
        check_helper(newuidmap)?;
        check_helper(newgidmap)?;
        Ok(Self {
            newuidmap: newuidmap.to_path_buf(),
            newgidmap: newgidmap.to_path_buf(),
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

fn run_helper(
    path: &Path,
    pid: TargetPid,
    set: &IdMapSet,
    kind: IdKind,
    timeout: Duration,
) -> Result<(), RootlessError> {
    let stage = RootlessStage::Helper;
    let mut cmd = Command::new(path);
    cmd.arg(pid.get().to_string());
    for e in set.entries() {
        cmd.arg(e.container_id.to_string())
            .arg(e.host_id.to_string())
            .arg(e.count.to_string());
    }
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| io_error(stage, "spawn id map helper", &e))?;
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
    let mut err = Vec::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s
            .by_ref()
            .take(MAX_HELPER_STDERR_BYTES as u64)
            .read_to_end(&mut err);
    }
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
    let stage = RootlessStage::Verify;
    let f = std::fs::File::open(pid.proc_file(kind.map_file()))
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
    apply_id_maps_as(
        pid,
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
    pid: TargetPid,
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
            run_helper(paths.path_for(IdKind::Uid), pid, uid, IdKind::Uid, timeout)?;
            run_helper(paths.path_for(IdKind::Gid), pid, gid, IdKind::Gid, timeout)?;
            WriterKind::Helper
        }
    };
    for (k, set) in [(IdKind::Uid, uid), (IdKind::Gid, gid)] {
        let got = read_id_map(pid, k)?;
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

    #[test]
    fn sec5_direct_precheck_rejects_range_for_unprivileged() {
        let single = single_id_mapping(1000).expect("single");
        let range = rootless_mapping(1000, &[SubordinateRange::new(100000, 10).expect("r")])
            .expect("range");
        assert!(check_direct_allowed(&single, &single, 1000, 1000).is_ok());
        assert!(check_direct_allowed(&range, &single, 1000, 1000).is_err());
        assert!(check_direct_allowed(&single, &single, 1001, 1000).is_err());
        assert!(check_direct_allowed(&range, &range, 0, 0).is_ok());
        let pid = TargetPid::new(std::process::id()).expect("pid");
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
}
