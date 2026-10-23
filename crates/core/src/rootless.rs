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
//! - 起動フローへの組み込みは `exec::isolate_rootless_subordinate`（TASK-40.2・#188）が担う。本番 launcher
//!   （`oci_runtime::ProductionLauncher`）は `RootlessSubordinateIds` のとき、構築時に `SubordinateIdSource` から
//!   [`load_subordinate_ids`]・[`rootless_mapping`]・[`HelperPaths`] を解決し、中間プロセスから呼ぶ（#2009）。
//!   呼び出し元(中間プロセス I)は自分では [`unshare_user_namespace`] せず、使い捨ての holder(dumpable で構わない
//!   専用プロセス)に user namespace を作らせる。fork した mapper（`run_id_map_mapper`。外側の user namespace に
//!   残る）が holder の pid へ [`apply_id_maps`] し、I は写像後に `setns` で参加する。I が dumpable になる窓を
//!   なくすため(`docs/design/rootless-id-map-holder.md`・#2374)。応答は型付きの固定 3 バイト
//!   （`MapperReply`）で返す。エラーは `ExecError`（段 `UserNamespaceMap`）へ写す
//! - 写像はカーネルが write-once（1 回しか受け付けない）。途中で失敗した対象プロセスは
//!   破棄すること（再設定できない）
//! - pid 再利用（TOCTOU）対策: 書き込み先は pid 番号ではなく、対象の `/proc/<pid>` ディレクトリ fd
//!   （[`ProcHandle`]）で固定する。mapper は先に fd を開き、その**後**に mapper 自身の `parent_id()` と対象(holder)の
//!   親(fd 経由の stat)がともに I のままであることを確認する（開いた時点で pid は生きた親を指していたと言える）。以後の書き込み・読み戻しは
//!   fd 経由（`/proc/self/fd/N/...`）で、対象が死んで pid が再利用されても別プロセスへは届かず失敗する。
//!   `newuidmap` / `newgidmap` へは、公開 API（[`apply_id_maps_to`]）は `fd:0`（stdin の `/proc/<pid>` fd。`fd:N`
//!   未対応の helper では fail-closed）で、mapper は pid 文字列で渡す（shadow 4.13 は `fd:N` を受け付けないため。#2376。
//!   `HelperTarget`）。pid 文字列では helper の書き込み先が fd で固定されないため、対象（holder）の pid が解放されるのは
//!   helper が止まった後に限る: holder は `PDEATHSIG` を持たず、helper の stdin に渡した socket の EOF（I・mapper・
//!   全 helper の終了）か期限まで終了しない（I が死んだ場合）。成功時は mapper が helper を回収してから応答する。失敗時は I が mapper とそのプロセスグループ（helper を含む）へ
//!   `SIGKILL` を送り、セッションの全員の終了を確かめてから holder を回収し、確かめられなければ holder を回収しない
//!   （`exec::isolate_rootless_subordinate_with`）。I が死んだ場合は C の識別子の再探索が全候補の helper を止めて
//!   から holder を回収する（`exec::launch_intermediate::rescan_unreported_init`）。
//!   新規 FFI は不要（pidfd は採らない）。単独で [`apply_id_maps`] を呼ぶ場合は pid から fd を開くため、対象を reap する前
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
//! | `mknod` によるデバイスノード作成 | 代替しない（`mknod` は使わず、`exec::create_default_devices` がホスト `/dev/<名前>` を fd 起点で bind して供給する。#1660） |
//! | cgroup 参加 | 対象外（TASK-32・CORE-3） |
//!
//! # 未実装（REPAIR-3）
//!
//! - ユーザー名 → `/etc/subuid` 行の NSS 解決は core では行わない。名前の解決は supervisor の `id_model` が
//!   `/etc/passwd` を先に読み、無いときだけ `getent` を期限つきで実行して行う（#2390・SEC-5・CORE-6。
//!   `docs/design/subid-owner-resolution.md`）。core は [`SubIdOwner`] に数値 uid と検証済みユーザー名を
//!   受け取るだけで、ライブラリコードは `$USER` を読まない
//! - `oci_runtime` の `linux.uidMappings` / `gidMappings` の受理（start.rs は現状拒否のまま。受けるかは SEC-5 に関わるオーナー判断待ち。#2240・`docs/design/config-id-mappings.md`）
//!
//! ファイル所有者の写像（SEC-5。ns 内 0 → ホスト非特権 UID）の照合は `tests/rootless_file_owner.rs`
//! （TASK-40.3・#189）が担う。

use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::exec::IdMapping;
use crate::sanitize::{is_display_unsafe_char, push_sanitized_bounded};
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
/// 所有者名の最大バイト長（`LOGIN_NAME_MAX`）。sssd / LDAP の長い名前（`user@example.com` 等）を受けるため
/// shadow 側に制限が無いことに合わせて緩める（#2390）。
const MAX_OWNER_NAME_LEN: usize = 256;

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
    /// 所有者を作る。名前は空でなく 256 バイト以内で、`:`・空白・ASCII 制御文字を含まないものだけ許可する。
    ///
    /// 名前は分割した欄との `==` 比較にしか使わず helper にもシェルにも渡さないため、文字種は注入面にならない
    /// （`newuidmap` 側にも文字種の制限は無い。#2390）。
    pub fn new(uid: u32, name: Option<String>) -> Result<Self, RootlessError> {
        if let Some(n) = &name {
            let ok = !n.is_empty()
                && n.len() <= MAX_OWNER_NAME_LEN
                && n.chars()
                    .all(|c| c != ':' && !c.is_whitespace() && !c.is_ascii_control());
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

/// subuid / subgid の本文に「名前の行」があるか（第 1 欄が空でなく `u32` として解釈できない行。
/// 空行・`#` コメントは読み飛ばす。読み方・上限は [`parse_subordinate_ids`] と同じ。CORE-6・SEC-5・#2545）。
///
/// supervisor の `id_model` が、所有者名を引けない（`getent` が無い）ホストで、名前の行が自分のものかを
/// 判定できないまま 1 対 1 写像へ落ちるのを拒否するために使う。行の中身（欄数・範囲）は検証しない。
pub fn subordinate_ids_have_named_rows(bytes: &[u8]) -> Result<bool, RootlessError> {
    let stage = RootlessStage::ParseSubordinateIds;
    if bytes.len() as u64 > MAX_SUBID_FILE_BYTES {
        return Err(RootlessError::invalid(
            stage,
            "subordinate id file too large",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RootlessError::invalid(stage, "subordinate id file is not valid UTF-8"))?;
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
        let first = line.split(':').next().unwrap_or("");
        if !first.is_empty() && first.parse::<u32>().is_err() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `path` を上限付きで読み、[`subordinate_ids_have_named_rows`] へ渡す（ファイル無しは `NotFound`）。
pub fn load_has_named_rows(path: &Path) -> Result<bool, RootlessError> {
    let stage = RootlessStage::ParseSubordinateIds;
    let file =
        std::fs::File::open(path).map_err(|e| io_error(stage, "open subordinate id file", &e))?;
    let mut buf = Vec::new();
    file.take(MAX_SUBID_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_error(stage, "read subordinate id file", &e))?;
    subordinate_ids_have_named_rows(&buf)
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

    /// fd の指すプロセスの親 pid(`/proc/<pid>/stat` の ppid。fd 経由で読むため pid の再利用に影響されない)。
    ///
    /// mapper が「書き込み先の holder が、期待した中間プロセスの子であること」を確かめるために使う
    /// (CORE-6・SEC-5・#2374)。読み取りは 4096 バイトで打ち切り、comm が `)` を含んでも最後の `)` より後ろ
    /// だけを解析する。形式が崩れていれば `Internal` で拒否する(fail-closed)。
    pub(crate) fn parent_pid(&self) -> Result<u32, RootlessError> {
        self.stat_field(1)
    }

    /// fd の指すプロセスのセッション ID(`/proc/<pid>/stat` の session)を、kill の判断に必要な 3 つに分けて返す。
    ///
    /// holder が期限切れのとき、錨にした mapper が `setsid` 済み(ID = mapper の pid)であることを kill の直前に
    /// 確かめるために使う(CORE-6・SEC-5・#2551)。
    ///
    /// 対象が既に回収されていれば fd 経由の読み取りは `ESRCH` / `ENOENT` で失敗する(`Gone`)。それ以外の失敗・
    /// 解析の失敗は `Unreadable` で、呼び出し側は kill しない(fail-closed)。
    pub(crate) fn session_probe(&self) -> SessionProbe {
        match self.read_stat() {
            Ok(buf) => match parse_stat_field(&buf, 3) {
                Ok(sid) => SessionProbe::Session(sid),
                Err(_) => SessionProbe::Unreadable,
            },
            Err(e) if matches!(e.raw_os_error(), Some(sys::ESRCH | sys::ENOENT)) => {
                SessionProbe::Gone
            }
            Err(_) => SessionProbe::Unreadable,
        }
    }

    /// `/proc/<pid>/stat` を 4096 バイトまで読む(fd 経由。pid の再利用に影響されない)。
    fn read_stat(&self) -> std::io::Result<Vec<u8>> {
        use std::io::Read as _;
        let mut buf = Vec::with_capacity(512);
        std::fs::File::open(self.proc_file("stat"))
            .and_then(|f| f.take(4096).read_to_end(&mut buf))?;
        Ok(buf)
    }

    /// stat の `) <state> <ppid> <pgrp> <session> ...` の `n` 番目(0 起点)を数値で返す。
    fn stat_field(&self, n: usize) -> Result<u32, RootlessError> {
        let buf = self
            .read_stat()
            .map_err(|e| io_error(RootlessStage::Validate, "read target stat", &e))?;
        parse_stat_field(&buf, n)
    }

    /// fd 配下のファイルのパス（`/proc/self/fd/N/<name>`。fd の指すプロセスへ解決される）。
    fn proc_file(&self, name: &str) -> PathBuf {
        use std::os::fd::AsRawFd as _;
        PathBuf::from(format!("/proc/self/fd/{}/{name}", self.dir.as_raw_fd()))
    }
}

/// [`ProcHandle::session_probe`] の結果(#2551)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionProbe {
    /// 対象のセッション ID。
    Session(u32),
    /// 対象は既に回収されている(`ESRCH` / `ENOENT`)。
    Gone,
    /// 読めない・形式が崩れている。
    Unreadable,
}

/// stat の本文から、最後の `)`(comm の終端。comm が `)` を含んでも壊れない)より後ろの `n` 番目の欄を読む。
/// 形式が崩れていれば `Internal` で拒否する(fail-closed)。
fn parse_stat_field(buf: &[u8], n: usize) -> Result<u32, RootlessError> {
    let bad = || {
        RootlessError::new(
            ErrorCode::Internal,
            RootlessStage::Validate,
            "malformed target stat",
        )
    };
    let close = buf.iter().rposition(|b| *b == b')').ok_or_else(bad)?;
    let rest = buf.get(close + 1..).ok_or_else(bad)?;
    let rest = std::str::from_utf8(rest).map_err(|_| bad())?;
    rest.split_whitespace()
        .nth(n)
        .and_then(|f| f.parse::<u32>().ok())
        .ok_or_else(bad)
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
/// dev/ino を保持して `run_helper` の exec 直前に再検証・同一性比較する。
/// setuid ビットは要求しない（file capability 方式の配布があるため）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPaths {
    newuidmap: PathBuf,
    newgidmap: PathBuf,
    uid_identity: FileIdentity,
    gid_identity: FileIdentity,
}

/// `newuidmap` の既定位置。
pub const SYSTEM_NEWUIDMAP: &str = "/usr/bin/newuidmap";
/// `newgidmap` の既定位置。
pub const SYSTEM_NEWGIDMAP: &str = "/usr/bin/newgidmap";

/// helper 1 本を [`HelperPaths::new`] と同じ規則で検証する（`doctor` が `newuidmap` / `newgidmap` を個別に診断する
/// ために公開する。規則は二重に持たない。失敗の `code` が `NotFound` なら存在しない。#2545・CORE-6）。
pub fn verify_helper_path(path: &Path) -> Result<(), RootlessError> {
    check_helper(path).map(|_| ())
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
        Self::new(Path::new(SYSTEM_NEWUIDMAP), Path::new(SYSTEM_NEWGIDMAP))
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
pub(crate) fn check_direct_allowed(
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

/// newuidmap / newgidmap の stderr を、エラーメッセージへ入れられる形に整える（TASK-40・SEC-5・ERR-2）。
///
/// 表示を乱す文字（Cc・Cf・Zl・Zp。判定は `crate::sanitize` に一本化）は除去する（行区切りを
/// 潰す既存の形）。出力は UTF-8 文字境界で `MAX_HELPER_STDERR_BYTES` バイト以下に収まる
/// （不正バイトが U+FFFD へ膨らむ場合も含む）。
fn sanitize_stderr(raw: &[u8]) -> String {
    let cut = raw.get(..MAX_HELPER_STDERR_BYTES).unwrap_or(raw);
    let lossy = String::from_utf8_lossy(cut);
    let mut out = String::with_capacity(lossy.len().min(MAX_HELPER_STDERR_BYTES));
    push_sanitized_bounded(
        &mut out,
        lossy.chars().filter(|&c| !is_display_unsafe_char(c)),
        MAX_HELPER_STDERR_BYTES,
    );
    out
}

/// `newuidmap` / `newgidmap` へ渡す写像の対象（[`run_helper`] が使う。CORE-6・SEC-5・#2376）。
///
/// どちらの形でも、helper が書く先が別プロセスへ移らないことを保証できる経路だけが構築する。
#[derive(Clone, Copy)]
enum HelperTarget<'a> {
    /// `fd:0`（stdin に `/proc/<pid>` の fd を渡す shadow の形式）。書き込み先が fd で固定され、対象の回収に依らず
    /// pid 再利用に耐える。shadow 4.13 等の `fd:N` 未対応の helper は usage で失敗する（fail-closed）。公開 API
    /// （[`apply_id_maps_to`]）はこの形だけを使う。
    ProcFd(&'a ProcHandle),
    /// pid の数値（`fd:N` 未対応の helper でも動く）。helper の stdin に `keepalive` の複製を渡す。`keepalive` は対象
    /// （holder）が持つ socket の相手側で、holder はその EOF（= 呼び出し元・mapper・全 helper の終了）まで終了しない
    /// （[`run_userns_holder`]）。そのため helper の実行中に対象の pid が解放されない。mapper（[`run_id_map_mapper`]）
    /// だけが構築する。
    HeldPid {
        handle: &'a ProcHandle,
        keepalive: std::os::fd::BorrowedFd<'a>,
    },
}

/// 検証済みヘルパーを実行する。exec 直前に所有者・権限・祖先ディレクトリ・dev/ino を再検証し、
/// [`HelperPaths::new`] 時点から差し替えられていれば拒否する（TOCTOU 対策。祖先が root 専有のため
/// 非 root は残る窓でも差し替えられない）。
fn run_helper(
    paths: &HelperPaths,
    target: HelperTarget<'_>,
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
    // 対象の渡し方は `HelperTarget` が決める（モジュール doc の「pid 再利用（TOCTOU）対策」。CORE-6・SEC-5・#2376）。
    let (target_arg, stdin) = match target {
        HelperTarget::ProcFd(handle) => {
            let dir = handle
                .dir
                .try_clone()
                .map_err(|e| io_error(stage, "duplicate target proc directory", &e))?;
            (
                "fd:0".to_string(),
                Stdio::from(std::os::fd::OwnedFd::from(dir)),
            )
        }
        HelperTarget::HeldPid { handle, keepalive } => {
            let keep = keepalive
                .try_clone_to_owned()
                .map_err(|e| io_error(stage, "duplicate the holder keepalive", &e))?;
            (handle.pid().get().to_string(), Stdio::from(keep))
        }
    };
    let mut cmd = Command::new(path);
    cmd.arg(target_arg);
    for e in set.entries() {
        cmd.arg(e.container_id.to_string())
            .arg(e.host_id.to_string())
            .arg(e.count.to_string());
    }
    cmd.env_clear()
        .stdin(stdin)
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
    Err(helper_failure(stage, status, &err))
}

/// ヘルパーが非ゼロ終了したときのエラーを作る（stderr は [`sanitize_stderr`] を通して載せる）。
///
/// [`run_helper`] の失敗経路の本体。結合試験が実ヘルパー（root 所有の実行ファイルが要る）なしで
/// メッセージの具体値を照合できるよう分離している（REPAIR-12）。
fn helper_failure(
    stage: RootlessStage,
    status: std::process::ExitStatus,
    stderr: &[u8],
) -> RootlessError {
    RootlessError::new(
        ErrorCode::PermissionDenied,
        stage,
        format!(
            "id map helper failed ({status}): {}",
            sanitize_stderr(stderr)
        ),
    )
}

/// holder の期限切れ後始末を本番の namespace 構成で観測する試験専用の入口(`tests/rootless_holder_expiry.rs`。#2551)。
#[cfg(feature = "exec-test-support")]
mod holder_expiry_probe;
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use holder_expiry_probe::{HolderExpiryObservation, observe_holder_expiry};

/// 結合試験 `tests/sanitize_integration.rs` 専用の入口: ヘルパー失敗のエラー生成経路を、終了状態と
/// stderr の生バイトから直接呼ぶ（TASK-96.1・ERR-2・REPAIR-12。通常の利用者は呼ばない）。
///
/// 実ヘルパーの起動は root 所有の実行ファイルを要し既定のテスト集合で再現できないため、
/// [`run_helper`] が失敗時に通るのと同じ `helper_failure` を公開する。`exec-test-support` feature を
/// 付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn helper_failure_error_for_test(
    status: std::process::ExitStatus,
    stderr: &[u8],
) -> RootlessError {
    helper_failure(RootlessStage::Helper, status, stderr)
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
///
/// `Helper` の書き込みは、helper へ対象を `fd:0`（stdin の `/proc/<pid>` fd）で渡す。書き込み先が fd で固定されるため、
/// 呼び出し元が対象を回収しても別プロセスへは届かない。shadow 4.13 等の `fd:N` 未対応の `newuidmap` / `newgidmap`
/// では helper が usage で失敗する（fail-closed。pid の数値へは退避しない。#2376）。pid の数値で渡すのは、対象が
/// helper の終了まで生き続けることを保証できる内部の経路（holder と mapper。`exec::isolate_rootless_subordinate`）だけ。
pub fn apply_id_maps_to(
    target: &ProcHandle,
    uid: &IdMapSet,
    gid: &IdMapSet,
    writer: &IdMapWriter,
    timeout: Duration,
) -> Result<IdMapReport, RootlessError> {
    apply_id_maps_as(
        target,
        None,
        uid,
        gid,
        writer,
        timeout,
        sys::effective_uid(),
        sys::effective_gid(),
    )
}

/// euid / egid を注入できる本体（事前検証をテストするため分離）。`keepalive` は mapper だけが渡す
/// （[`HelperTarget::HeldPid`]）。`None` なら helper へ `fd:0` で渡す。
// 引数 8 個: 公開 API と mapper が共有する内部の本体で、試験が euid / egid を注入する(#2376 の最小変更)。
#[allow(clippy::too_many_arguments)]
fn apply_id_maps_as(
    pid: &ProcHandle,
    keepalive: Option<std::os::fd::BorrowedFd<'_>>,
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
            let target = match keepalive {
                Some(keepalive) => HelperTarget::HeldPid {
                    handle: pid,
                    keepalive,
                },
                None => HelperTarget::ProcFd(pid),
            };
            run_helper(paths, target, uid, IdKind::Uid, timeout)?;
            run_helper(paths, target, gid, IdKind::Gid, timeout)?;
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

/// mapper へ「holder の unshare 完了。写像を書いてよい」と知らせる 1 バイト（[`run_id_map_mapper`] が待つ）。
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

/// holder の制御フレーム長(`[tag, pid の u32 big-endian 4 バイト]` の固定 5 バイト)。
pub(crate) const HOLDER_CONTROL_LEN: usize = 5;
const CTL_TAG_MAPPER_PID: u8 = 1;
const CTL_TAG_RELEASE: u8 = 2;

/// holder が期限切れのときに止める mapper のセッションの錨にする pid(`2..=i32::MAX`。#2551)。
///
/// 0(自グループ)・1(`kill(-1)` は全プロセス宛て)・`i32` を超える値(負の pid になる)を型で表現できなくする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MapperPid(u32);

impl MapperPid {
    /// pid を検証して作る。範囲外は `Internal`。
    pub(crate) fn new(pid: u32) -> Result<Self, RootlessError> {
        if (2..=i32::MAX as u32).contains(&pid) {
            Ok(Self(pid))
        } else {
            Err(RootlessError::new(
                ErrorCode::Internal,
                RootlessStage::Helper,
                "mapper pid out of range in holder control frame",
            ))
        }
    }

    /// pid の値。
    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

/// 中間プロセス I が holder へ送る制御フレーム(REPAIR-2。CORE-6・SEC-5・#2551)。
///
/// 固定 5 バイト `[tag, pid]` で、書くのは I だけ(mapper・helper は socket の複製を持つが書かない)。順序は
/// `MapperPid`(mapper の fork 直後・go の前)→ 応答待ち → `Release`(参加が済んだ後)。復号は完全一致のみ受け付け、
/// 長さ不一致・未知の tag・`Release` の payload が 0 でない値・範囲外の pid は `Internal` で拒否する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HolderControl {
    /// mapper の pid。holder は期限切れのとき、このプロセスのセッション(mapper と helper)を止める。
    MapperPid(MapperPid),
    /// 参加が済んだ。終了してよい。
    Release,
}

impl HolderControl {
    /// 固定長フレームへ符号化する。
    pub(crate) fn encode(&self) -> [u8; HOLDER_CONTROL_LEN] {
        let (tag, pid) = match self {
            Self::MapperPid(p) => (CTL_TAG_MAPPER_PID, p.get()),
            Self::Release => (CTL_TAG_RELEASE, 0),
        };
        let [a, b, c, d] = pid.to_be_bytes();
        [tag, a, b, c, d]
    }

    /// 完全一致のみ受け付ける復号。
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RootlessError> {
        let bad = |m: &str| RootlessError::new(ErrorCode::Internal, RootlessStage::Helper, m);
        let [tag, a, b, c, d] = <[u8; HOLDER_CONTROL_LEN]>::try_from(bytes)
            .map_err(|_| bad("malformed holder control frame length"))?;
        let pid = u32::from_be_bytes([a, b, c, d]);
        match tag {
            CTL_TAG_MAPPER_PID => Ok(Self::MapperPid(MapperPid::new(pid)?)),
            CTL_TAG_RELEASE if pid == 0 => Ok(Self::Release),
            CTL_TAG_RELEASE => Err(bad("non-zero payload in holder release frame")),
            _ => Err(bad("unknown tag in holder control frame")),
        }
    }
}

/// [`holder_await_release`] の結末(終了コードへ写す。`Released` だけが 0)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HolderExit {
    /// `Release` を受けた。
    Released,
    /// 相手側が全員閉じた(EOF)。helper も居ない。
    PeersClosed,
    /// 期限切れ。mapper のセッションへ SIGKILL を送り、続けて EOF を待った(`drained` は EOF まで届いたか)。
    ExpiredKilled { drained: bool },
    /// 期限切れ(または壊れたフレーム)だが、錨が無い・同一性を確かめられないため kill しなかった。
    ExpiredNoKill,
    /// socket の読み取りが失敗した。
    ReadFailed,
}

impl HolderExit {
    fn code(self) -> i32 {
        i32::from(self != Self::Released)
    }
}

/// 読み取り 1 フレームの結果。
enum FrameRead {
    Full,
    /// EOF、または相手が未読のデータを残したまま閉じた(`ECONNRESET`)。どちらも相手側が全員閉じたことを表す
    /// (holder が書いた錨の応答が未読のまま相手が終わると後者になる。#2551)。
    Eof,
    TimedOut,
    Failed,
}

/// `buf` が満たされるか EOF・`deadline` になるまで読む。1 回ごとに残り時間を read timeout に設定する(REPAIR-5)。
fn read_frame_until(
    sock: &mut std::os::unix::net::UnixStream,
    buf: &mut [u8; HOLDER_CONTROL_LEN],
    deadline: Instant,
) -> FrameRead {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return FrameRead::TimedOut;
        }
        if sock.set_read_timeout(Some(remaining)).is_err() {
            return FrameRead::Failed;
        }
        let Some(dst) = buf.get_mut(filled..) else {
            return FrameRead::Failed;
        };
        match sock.read(dst) {
            Ok(0) => return FrameRead::Eof,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return FrameRead::TimedOut;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return FrameRead::Eof,
            Err(_) => return FrameRead::Failed,
        }
    }
    FrameRead::Full
}

/// [`holder_await_release`] の入力(値の束)。
pub(crate) struct HolderWait<'a> {
    /// holder 自身の pid(錨にできない値)。
    pub(crate) self_pid: u32,
    /// holder を fork した中間プロセス I の pid(錨にできない値)。
    pub(crate) expected_parent: u32,
    /// holder の現在の親 pid。I が死ぬと subreaper か init に変わり、mapper も同じ親に再親付けされる。
    pub(crate) current_parent: &'a dyn Fn() -> u32,
    /// `Release` を待つ上限。
    pub(crate) release_wait: Duration,
    /// 期限切れで kill した後、EOF を待つ上限。
    pub(crate) drain_wait: Duration,
    /// 錨にした mapper の pidfd でそのグループ全員へ SIGKILL を送る関数(`None` なら使わない。#2551)。
    /// pid の数値ではなく `struct pid` へ送るため、mapper が回収された後も元のグループ以外には届かない。
    /// 本番は `sys::pidfd_send_signal_group`(Linux 6.9 以降)。未対応カーネルの `EINVAL` では数値 PGID の経路へ退避する。
    pub(crate) pidfd_kill: Option<&'a PidfdKill<'a>>,
}

/// pidfd でグループへ SIGKILL を送る関数の型([`HolderWait::pidfd_kill`])。
pub(crate) type PidfdKill<'a> = dyn Fn(std::os::fd::BorrowedFd<'_>) -> Result<(), SysError> + 'a;

/// holder の錨(mapper の `/proc/<pid>` の fd・pid・pidfd)。
struct Anchor {
    handle: ProcHandle,
    pid: u32,
    /// pid の数値に依らずグループへ送るための pidfd。開けなければ `None`(数値 PGID の経路だけになる)。
    pidfd: Option<std::os::fd::OwnedFd>,
}

/// 錨(mapper の `/proc/<pid>` の fd と pid)を作る。作れない・親が一致しない場合は `None`(診断を 1 行出す)。
///
/// 開けないのは mapper が既に回収された場合で、mapper は helper を回収してから終わるか go を受けずに終わる
/// ため helper は残らない。`/proc/<pid>` の fd と pidfd を確保した**後**に親を確かめる(読めれば、どちらの fd も
/// 回収前の同じプロセスを指す)ため、別プロセスを錨にしない。pidfd は mapper の `struct pid` を保持し、回収後に
/// 番号が再利用されても元のグループにだけ送れる(#2551)。pidfd を開けない環境では `None` のまま数値 PGID へ退避する。
fn open_anchor(
    pid: MapperPid,
    w: &HolderWait<'_>,
    diag: &mut dyn std::io::Write,
) -> Option<Anchor> {
    let pid = pid.get();
    let anchor = (|| {
        if pid == w.self_pid || pid == w.expected_parent {
            return Err("mapper pid is the holder or its parent");
        }
        let handle = TargetPid::new(pid)
            .and_then(ProcHandle::open)
            .map_err(|_| "cannot open the mapper proc directory")?;
        let pidfd = sys::pidfd_open(pid).ok();
        match handle.parent_pid() {
            Ok(ppid) if ppid == (w.current_parent)() => Ok(Anchor { handle, pid, pidfd }),
            _ => Err("mapper is not a sibling of the holder"),
        }
    })();
    match anchor {
        Ok(a) => Some(a),
        Err(m) => {
            let _ = writeln!(diag, "fandhe-container: userns holder: no anchor: {m}");
            None
        }
    }
}

/// holder の READY 後の待ち(#2551)。`Release`・EOF で終わる。期限が来たら mapper のセッション(helper を含む)へ
/// SIGKILL を送ってから EOF を待ち、どの待ちも有限にする(REPAIR-5)。`kill` は試験が差し替える継ぎ目。
///
/// kill の安全性: 期限が来ても EOF でないのは、相手側(I・mapper・helper)の誰かが生きているときだけである。
/// I が生きていれば、mapper を回収するのは holder を kill した後に限るため、mapper の pid(セッション ID)は保たれる。
/// I が死んでいても、mapper が回収済みなら生きている helper がセッションを継承して番号を保つ。kill の直前に
/// fd 経由でセッション ID が mapper の pid であることを確かめ、読めなくなっていれば EOF を確かめ直す。
/// 残る窓: 期限の直前に最後の helper が終わり、その pid が `setsid` した無関係なプロセスへ再利用される極小の窓。
/// 送信は錨と同時に開いた mapper の pidfd で行い(`HolderWait::pidfd_kill`。`PIDFD_SIGNAL_PROCESS_GROUP`、Linux 6.9 以降)、
/// 宛先を pid の数値ではなく `struct pid` のグループにするため、回収後の番号の再利用に影響されない(`Gone` でも送れる)。
/// 未対応(`EINVAL`)・pidfd を開けない場合は数値 PGID へ退避し、その経路で mapper が回収済み(`Gone`)なら送らない(fail-closed)。回収後は元のグループの同一性を保つ手段が無く、番号が
/// 無関係なプロセスへ再利用されて `setsid`・fork・親の終了まで進むと、現在の所属情報だけでは元のグループと区別できない
/// ため(`/proc` の走査による判定は走査前に成立する誤判定を除けない)。
pub(crate) fn holder_await_release(
    sock: &mut std::os::unix::net::UnixStream,
    w: &HolderWait<'_>,
    kill: &mut dyn FnMut(u32) -> Result<(), SysError>,
    diag: &mut dyn std::io::Write,
) -> HolderExit {
    // 診断は kill・EOF 待ちが終わるまで書き出さず、メモリに溜める(#2551・REPAIR-5)。書き先が止まっていても
    // (満杯の pipe の stderr 等)SIGKILL と待ちの期限が診断に先行し、止まらない。溜める行は有限個の短い固定文のみ。
    let mut pending: Vec<u8> = Vec::new();
    let exit = holder_await_release_inner(sock, w, kill, &mut pending);
    let _ = diag.write_all(&pending);
    exit
}

/// [`holder_await_release`] の本体。`diag` はメモリ上の溜め先(書き込みで止まらない)を渡す。
fn holder_await_release_inner(
    sock: &mut std::os::unix::net::UnixStream,
    w: &HolderWait<'_>,
    kill: &mut dyn FnMut(u32) -> Result<(), SysError>,
    diag: &mut dyn std::io::Write,
) -> HolderExit {
    let deadline = Instant::now() + w.release_wait;
    let mut anchor: Option<Anchor> = None;
    let mut seen_pid = false;
    let mut buf = [0u8; HOLDER_CONTROL_LEN];
    loop {
        match read_frame_until(sock, &mut buf, deadline) {
            FrameRead::Eof => return HolderExit::PeersClosed,
            FrameRead::Failed => return HolderExit::ReadFailed,
            FrameRead::TimedOut => break,
            FrameRead::Full => match HolderControl::decode(&buf) {
                Ok(HolderControl::Release) => return HolderExit::Released,
                Ok(HolderControl::MapperPid(p)) if !seen_pid => {
                    seen_pid = true;
                    anchor = open_anchor(p, w, diag);
                    // 錨を確保できたか(できなかったか)を I へ返す。I はこの応答を受けてから go を送る(write_all の成功
                    // は holder が錨を開けた保証にならないため。#2551・CORE-6・SEC-5)。書けなくても待ちは続け、
                    // I は応答の期限切れで失敗にする。
                    let reply = if anchor.is_some() {
                        MapperReply::Ok
                    } else {
                        MapperReply::Failed {
                            code: ErrorCode::FailedPrecondition,
                            stage: RootlessStage::Validate,
                        }
                    };
                    let left = deadline
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_millis(1));
                    let _ = sock.set_write_timeout(Some(left));
                    let _ = sock.write_all(&reply.encode());
                }
                _ => {
                    let _ = writeln!(diag, "fandhe-container: userns holder: bad control frame");
                    break;
                }
            },
        }
    }
    let _ = writeln!(diag, "fandhe-container: userns holder: release wait ended");
    let Some(Anchor {
        handle,
        pid: mapper_pid,
        pidfd,
    }) = anchor
    else {
        return HolderExit::ExpiredNoKill;
    };
    // pidfd 経由のグループ送信(番号の再利用に影響されない)。済めば数値 PGID へは送らない。mapper が回収済みでも、
    // pidfd は元のグループにしか届かない(誰も居なければ ESRCH)ので、`Gone` でも安全に送れる。
    let mut sent = false;
    if let (Some(fd), Some(send)) = (pidfd.as_ref(), w.pidfd_kill) {
        match send(std::os::fd::AsFd::as_fd(fd)) {
            Ok(()) => sent = true,
            Err(SysError::Os(e)) if e == sys::ESRCH => sent = true,
            // 未対応カーネル(6.9 未満の EINVAL)・seccomp 等での拒否: 下の数値 PGID の経路へ退避する。
            Err(SysError::Os(e)) if e == sys::EINVAL || e == sys::ENOSYS => {}
            Err(SysError::Unsupported) => {}
            Err(_) => {
                let _ = writeln!(diag, "fandhe-container: userns holder: kill failed");
                return HolderExit::ExpiredNoKill;
            }
        }
    }
    if !sent {
        match handle.session_probe() {
            SessionProbe::Session(sid) if sid == mapper_pid => {}
            SessionProbe::Gone => {
                // mapper は回収済み。生きている helper が無ければ EOF になっているはずなので、確かめ直す。
                let mut b = [0u8; HOLDER_CONTROL_LEN];
                match read_frame_until(sock, &mut b, Instant::now() + Duration::from_millis(1)) {
                    FrameRead::Eof => return HolderExit::PeersClosed,
                    FrameRead::Full if HolderControl::decode(&b) == Ok(HolderControl::Release) => {
                        return HolderExit::Released;
                    }
                    _ => {}
                }
                // EOF が無いことは、元のグループの生存を証明しない(I も socket を持つ。SIGCHLD=SIG_IGN の継承で
                // mapper が自動回収された場合など)。pidfd で送れない以上、回収後は番号の連続した保持を証明できない
                // ため、数値 PGID へは送らない。
                let _ = writeln!(
                    diag,
                    "fandhe-container: userns holder: mapper gone and its group is not verified, not killing"
                );
                return HolderExit::ExpiredNoKill;
            }
            // mapper が `setsid` の前(helper を作っていない)か、読めない: kill しない(fail-closed)。
            _ => return HolderExit::ExpiredNoKill,
        }
        match kill(mapper_pid) {
            Ok(()) => {}
            Err(SysError::Os(e)) if e == sys::ESRCH => {}
            Err(_) => {
                let _ = writeln!(diag, "fandhe-container: userns holder: kill failed");
                return HolderExit::ExpiredNoKill;
            }
        }
    }
    let _ = writeln!(
        diag,
        "fandhe-container: userns holder: killed the id map mapper session"
    );
    // SIGKILL は止められたプロセスも終わらせ、終了で複製した fd が閉じて EOF になる。届いたバイトは捨てる。
    let drain_deadline = Instant::now() + w.drain_wait;
    loop {
        match read_frame_until(sock, &mut buf, drain_deadline) {
            FrameRead::Full => {}
            FrameRead::Eof => return HolderExit::ExpiredKilled { drained: true },
            FrameRead::TimedOut | FrameRead::Failed => {
                return HolderExit::ExpiredKilled { drained: false };
            }
        }
    }
}
/// 待たずに送れる出力先にだけ書き、それ以外は出力を捨てる診断用ライター(#2551・CORE-6・SEC-5・REPAIR-5)。
///
/// 本番の `stderr` は呼び出し元が与えた pipe・socket・ファイルの可能性があり、読み手が止まって満杯だと `write` が
/// 無期限にブロックする。`poll(POLLOUT, 0)` は後続の `write` が待たないことを保証しない(別プロセスが直後に空きを
/// 埋め得る。通常ファイルは停止した FUSE / NFS でも書込み可能と返る)ため、poll 後のブロッキング `write` は使わない。
/// `sys::send_nonblocking_unix`(`MSG_DONTWAIT`)で送れる AF_UNIX socket にだけ書き、それ以外の出力先・`EAGAIN`・
/// その他の失敗は成功を装って捨てる(診断は最善努力で、応答・終了コード・holder の寿命上限に影響しない)。
pub(crate) struct NonBlockingDiag<W: std::io::Write + std::os::fd::AsFd>(pub(crate) W);

impl<W: std::io::Write + std::os::fd::AsFd> std::io::Write for NonBlockingDiag<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(512);
        if n == 0 {
            return Ok(0);
        }
        match sys::send_nonblocking_unix(self.0.as_fd(), &buf[..n]) {
            Ok(w) if w > 0 => Ok(w),
            _ => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// user namespace を作って保持するだけの使い捨てプロセス(holder)の処理本体(fork 子が呼ぶ。#2374)。
///
/// 中間プロセス I(`exec::isolate_rootless_subordinate`)は non-dumpable のまま保つ必要があるが、
/// `newuidmap` / `newgidmap` は写像の対象の `/proc/<pid>` の所有者が呼び出し元と一致することを要求し、
/// non-dumpable な対象は root 所有に見えて拒否される。そこで写像の対象を I ではなくこのプロセスにし、
/// ここだけを dumpable にする。I は写像の後に `setns` でこの user namespace へ参加する(CORE-6・SEC-5・SEC-1)。
///
/// 流れ: fd 3 以上を閉じる(I から継承した報告 pipe・listener 等を持たない)
/// → 親が `expected_parent`(I)のままか確認 → `unshare(CLONE_NEWUSER)` → dumpable にする → READY(`MapperReply::Ok`)
/// を返す → [`HolderControl::Release`] を `release_wait` まで待って終了する(REPAIR-5。待ちは [`holder_await_release`])。
///
/// `PDEATHSIG` は設定しない(#2376)。helper(`newuidmap` / `newgidmap`)は holder を pid の数値で受け取るため、I が
/// helper の実行中に死んでも holder は先に終了して pid を解放してはならない。`sock` の相手側は I・mapper(fork で
/// 継承)・各 helper(stdin に複製。`HelperTarget::HeldPid`)が持ち、全員が閉じるまで EOF にならない。そのため I が
/// 死んだ場合も、holder は mapper と全 helper の終了(EOF)か `release_wait` の期限で終わる。`release_wait`
/// (`3 × timeout + 5s`)は mapper の go 待ち(`timeout`)と helper 2 回(各 `timeout`)の和を上回る。待ちは有限に
/// する(REPAIR-5)ため、I が死んだうえで helper が期限を超えて止められていると、期限で holder が先に終わって pid が
/// 再利用され得た(#2551)。これを閉じるため、I は mapper の fork 直後(go の前)に [`HolderControl::MapperPid`] を
/// 送り、holder は期限が来たとき**自分が終わる前に** mapper のセッション(helper を含む)へ SIGKILL を送って EOF を
/// 待つ([`holder_await_release`]。待ちはどちらも有限で、生存は最長 `release_wait + drain_wait`)。同一性が確かめられ
/// ない場合は kill しない(fail-closed)。残る窓(期限直前の最後の helper の終了と pid の再利用が重なる極小の窓、
/// SIGKILL でも `drain_wait` を超えて終わらない helper)は `docs/design/rootless-id-map-holder.md` に記す。
/// I・C は helper を止めた後に holder を kill する(`exec::stop_mapper_and_helpers`・
/// `exec::launch_intermediate::rescan_unreported_init`)。
/// `diag`(#2546): 失敗の 1 行の書き先。本番は fork 後の子の中で作った unbuffered の `std::io::stderr()` を渡し、試験は
/// `Vec<u8>` で照合する(`run_id_map_mapper` の `diag` と同じ契約)。
/// 失敗は `MapperReply::Failed` で返して終了コード 1。exec せず I の `comm`(起動識別子)を引き継ぐため、I が
/// 報告せずに死んでも C の再探索が回収できる(CORE-2)。
pub(crate) fn run_userns_holder(
    expected_parent: u32,
    mut sock: std::os::unix::net::UnixStream,
    timeout: Duration,
    release_wait: Duration,
    drain_wait: Duration,
    diag: &mut dyn std::io::Write,
) -> i32 {
    use std::os::fd::AsFd as _;

    let outcome = (|| -> Result<(), RootlessError> {
        let internal =
            |m: &str| RootlessError::new(ErrorCode::Internal, RootlessStage::Validate, m);
        sys::close_fds_from_except(3, sock.as_fd())
            .map_err(|_| internal("close inherited fds in the holder"))?;
        if std::os::unix::process::parent_id() != expected_parent {
            return Err(RootlessError::new(
                ErrorCode::FailedPrecondition,
                RootlessStage::Validate,
                "the parent process changed before the holder started",
            ));
        }
        unshare_user_namespace()?;
        // 写像の書き込み先として、このプロセスだけを dumpable にする(I は終始 non-dumpable)。
        sys::set_dumpable_user().map_err(|_| internal("PR_SET_DUMPABLE in the holder"))
    })();
    if !report_holder_outcome(outcome, &mut sock, timeout, diag) {
        return 1;
    }
    let w = HolderWait {
        self_pid: std::process::id(),
        expected_parent,
        current_parent: &std::os::unix::process::parent_id,
        release_wait,
        drain_wait,
        pidfd_kill: Some(&|fd| sys::pidfd_send_signal_group(fd, sys::Signal::Kill)),
    };
    holder_await_release(
        &mut sock,
        &w,
        &mut |pgid| sys::kill_process_group(pgid, sys::Signal::Kill),
        diag,
    )
    .code()
}

/// holder の準備結果を固定 3 バイトの応答で返し、失敗なら `diag` へ 1 行出す([`run_userns_holder`]の一部。#2546)。
///
/// 応答を相手へ書けたときだけ `true`(続けて [`HolderControl::Release`] を待つ)。失敗の応答を書いた場合は `false`。
/// `diag` の書き込みの失敗は無視し、応答は必ず試みる(`run_id_map_mapper` の `diag` と同じ契約)。
fn report_holder_outcome(
    outcome: Result<(), RootlessError>,
    sock: &mut std::os::unix::net::UnixStream,
    timeout: Duration,
    diag: &mut dyn std::io::Write,
) -> bool {
    let _ = sock.set_write_timeout(Some(timeout));
    match outcome {
        Ok(()) => sock.write_all(&MapperReply::Ok.encode()).is_ok(),
        Err(e) => {
            let _ = writeln!(diag, "fandhe-container: userns holder: {e}");
            let reply = MapperReply::Failed {
                code: e.code,
                stage: e.stage,
            };
            let _ = sock.write_all(&reply.encode());
            false
        }
    }
}

/// mapper([`run_id_map_mapper`])へ渡す値の束(CORE-6・REPAIR-12。#2546)。
///
/// 以前は 9 引数で `clippy::too_many_arguments` を許可していた。fork 子の単一呼び出し口であるため、値だけを
/// 借用の束にまとめる(所有権を持つ資源の `sock`・`keepalive` と書き出し先の `diag` は別引数に残す)。
/// 束はスタック上の参照だけで割り当てもロックも行わないため、fork 後の単一スレッドの前提を崩さない。
#[derive(Clone, Copy)]
pub(crate) struct MapperRequest<'a> {
    /// 写像の対象(専用の holder プロセス)の pid。
    pub(crate) target: u32,
    /// mapper 自身と対象の親であるべき pid(中間プロセス I)。
    pub(crate) expected_parent: u32,
    /// uid の写像。
    pub(crate) uid: &'a IdMapSet,
    /// gid の写像。
    pub(crate) gid: &'a IdMapSet,
    /// 書き込み方式。
    pub(crate) writer: &'a IdMapWriter,
    /// go 待ち・書き込みの期限(REPAIR-5)。
    pub(crate) timeout: Duration,
}

/// mapper の処理本体（fork 子が呼ぶ。成功なら終了コード 0、失敗なら 1）。
///
/// 流れ: `sock` から [`MAPPER_GO`] を `timeout` まで待つ → 対象(`target`。専用の holder プロセス)の
/// `/proc/<pid>` fd を開いたうえで、mapper 自身の親と対象の親がともに `expected_parent`(中間プロセス)
/// のままであることを確認する（reparent 後に無関係な pid へ書かない。pid 再利用・TOCTOU 対策）→ [`apply_id_maps_to`] を fd に対して実行 → 応答フレームを返す。
/// 親が死んでも mapper 側の fd は閉じられず EOF を当てにできないため、待ちは read タイムアウトで
/// 止める（REPAIR-5）。詳細は呼び出し側が渡す `diag` へ 1 行で出す（自由形式の文字列は応答に載せない）。
///
/// `diag`（CORE-6・REPAIR-12・#2393）: 本番（`exec.rs` の mapper の fork 子）は fork 後の子の中で作った
/// unbuffered の `std::io::stderr()` を渡す。子は `_exit` で終わるため、`BufWriter` 等のバッファ付きは
/// 渡さない（flush されず出力が失われる）。試験は `Vec<u8>` を渡して内容を具体値で照合する（libtest の
/// 出力捕捉を通らず成功試験の実行中に雑音が出るのを避ける）。書き込みの失敗は無視し応答は必ず返す。
/// 書き先は呼び出しごとの引数とし、グローバルな差し替えは採らない（fork 時に他スレッドが持つロックで
/// 子がデッドロックするため。`eprintln!` も書き込み失敗で panic するため使わない）。
///
/// `keepalive`（#2376）: holder が持つ socket の相手側の複製（`exec` の handshake が渡す）。あれば helper へ対象を pid の
/// 数値で渡し、各 helper の stdin にこの複製を持たせる（[`HelperTarget::HeldPid`]。holder は全員が閉じるまで終了しない）。
/// `None` なら `fd:0` で渡す。
pub(crate) fn run_id_map_mapper(
    req: &MapperRequest<'_>,
    mut sock: std::os::unix::net::UnixStream,
    keepalive: Option<std::os::fd::OwnedFd>,
    diag: &mut dyn std::io::Write,
) -> i32 {
    use std::os::fd::AsFd as _;
    let outcome = mapper_outcome(req, &mut sock, keepalive.as_ref().map(|k| k.as_fd()));
    let (reply, code) = match outcome {
        Ok(()) => (MapperReply::Ok, 0),
        Err(e) => {
            let _ = writeln!(diag, "fandhe-container: id map mapper: {e}");
            (
                MapperReply::Failed {
                    code: e.code,
                    stage: e.stage,
                },
                1,
            )
        }
    };
    let _ = sock.set_write_timeout(Some(req.timeout));
    let _ = sock.write_all(&reply.encode());
    code
}

fn mapper_outcome(
    req: &MapperRequest<'_>,
    sock: &mut std::os::unix::net::UnixStream,
    keepalive: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<(), RootlessError> {
    let MapperRequest {
        target,
        expected_parent,
        uid,
        gid,
        writer,
        timeout,
    } = *req;
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
    // 先に対象の `/proc/<pid>` fd を確保し、その後で次の 2 点を確認する。(1) mapper 自身の親が呼び出し元
    // (中間プロセス I)のまま(reparent されていない)。(2) 対象(holder)の親が I である。I が生きていて
    // 対象が I の未回収の子なら pid は再利用されておらず、fd は確実に holder を指す。以後の書き込みは fd 経由の
    // ため、確認後に対象が死んで pid が再利用されても別プロセスへは届かない(SEC-5・TASK-40.2・#2374)。
    let handle = ProcHandle::open(TargetPid::new(target)?)?;
    if std::os::unix::process::parent_id() != expected_parent {
        return Err(RootlessError::new(
            ErrorCode::FailedPrecondition,
            RootlessStage::Validate,
            "the parent process changed before the mapping was written",
        ));
    }
    if handle.parent_pid()? != expected_parent {
        return Err(RootlessError::new(
            ErrorCode::FailedPrecondition,
            RootlessStage::Validate,
            "the mapping target is not a child of the expected parent",
        ));
    }
    apply_id_maps_as(
        &handle,
        keepalive,
        uid,
        gid,
        writer,
        timeout,
        sys::effective_uid(),
        sys::effective_gid(),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-5・CORE-6（#2545）: 名前の行の検出（数値行・コメント・空行は名前の行ではない）。
    #[test]
    fn sec5_named_rows_detection() {
        assert_eq!(subordinate_ids_have_named_rows(b"alice:1:2\n"), Ok(true));
        assert_eq!(
            subordinate_ids_have_named_rows(b"1000:1:2\n# c\n\n  \n"),
            Ok(false)
        );
        assert_eq!(subordinate_ids_have_named_rows(b""), Ok(false));
        assert_eq!(
            subordinate_ids_have_named_rows(b"1000:1:2\nbob:3:4\n"),
            Ok(true)
        );
        assert!(subordinate_ids_have_named_rows(&[0xff, 0xfe]).is_err());
        let big = vec![b'#'; (MAX_SUBID_FILE_BYTES + 1) as usize];
        assert!(subordinate_ids_have_named_rows(&big).is_err());
    }

    /// CORE-6（#2545）: `verify_helper_path` は `HelperPaths::new` と同じ拒否（相対パス・不在は `NotFound`）。
    #[test]
    fn core6_verify_helper_path_matches_helper_paths() {
        assert!(verify_helper_path(Path::new("newuidmap")).is_err());
        let e = verify_helper_path(Path::new("/nonexistent-dir-2545/newuidmap")).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    /// TASK-40・ERR-2: stderr から Cf・Zl・Zp・Cc を除去する。
    #[test]
    fn task40_sanitize_stderr_drops_format_and_separator_chars() {
        let out = sanitize_stderr("a\u{202E}b\u{2060}c\u{2028}d\u{2029}e".as_bytes());
        assert_eq!(out, "abcde");
        let out = sanitize_stderr("x\u{1b}[31my\nz\tw".as_bytes());
        assert_eq!(out, "x[31myzw");
    }

    /// TASK-40: 出力は 4096 バイトを超えない（不正バイトが U+FFFD へ膨らむ場合も）。
    #[test]
    fn task40_sanitize_stderr_output_is_bounded() {
        let ascii = vec![b'a'; MAX_HELPER_STDERR_BYTES + 100];
        assert_eq!(sanitize_stderr(&ascii).len(), MAX_HELPER_STDERR_BYTES);
        let invalid = vec![0xFFu8; MAX_HELPER_STDERR_BYTES];
        assert_eq!(sanitize_stderr(&invalid).len(), 4095);
    }

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

    /// CORE-6・SEC-5（#2390）: sssd / LDAP 形式の長い名前・`@` つきの名前を受け、規則違反は拒否する。
    #[test]
    fn core6_owner_name_accepts_directory_service_names() {
        for ok in ["alice@example.com".to_string(), "a".repeat(256)] {
            assert!(SubIdOwner::new(1, Some(ok)).is_ok());
        }
        for bad in [
            "a".repeat(257),
            "a\nb".to_string(),
            "a\tb".to_string(),
            "a\0b".to_string(),
            String::new(),
        ] {
            assert!(SubIdOwner::new(1, Some(bad)).is_err());
        }
        let owner = SubIdOwner::new(1000, Some("alice@example.com".to_string())).expect("owner");
        let ranges =
            parse_subordinate_ids(b"alice@example.com:100000:65536\n", &owner).expect("parse");
        assert_eq!(ranges.len(), 1);
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
            None,
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
            None,
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

    /// CORE-6・REPAIR-12(#2546): holder の失敗は固定 3 バイトの応答になり、診断は引数の書き先へ出る。
    #[test]
    fn core6_holder_failure_reports_frame_and_diag() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut diag: Vec<u8> = Vec::new();
        let err = RootlessError::new(
            ErrorCode::Internal,
            RootlessStage::Validate,
            "injected holder failure",
        );
        let ok = report_holder_outcome(Err(err), &mut a, Duration::from_secs(1), &mut diag);
        assert!(!ok);
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        b.read_exact(&mut buf).expect("reply");
        assert_eq!(
            MapperReply::decode(&buf).expect("decode"),
            MapperReply::Failed {
                code: ErrorCode::Internal,
                stage: RootlessStage::Validate,
            }
        );
        let text = String::from_utf8(diag).expect("utf8");
        assert!(
            text.starts_with("fandhe-container: userns holder: "),
            "{text}"
        );
        assert_eq!(text.lines().count(), 1);
    }

    /// CORE-6・REPAIR-12(#2546): holder の成功は `MapperReply::Ok` の枠になり、診断は何も出ない。
    #[test]
    fn core6_holder_success_reports_ok_frame_without_diag() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut diag: Vec<u8> = Vec::new();
        assert!(report_holder_outcome(
            Ok(()),
            &mut a,
            Duration::from_secs(1),
            &mut diag
        ));
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        b.read_exact(&mut buf).expect("reply");
        assert_eq!(MapperReply::decode(&buf).expect("decode"), MapperReply::Ok);
        assert!(diag.is_empty());
    }

    /// CORE-6（TASK-40.2）: go 信号が来ないまま timeout になると mapper は書き込まずに
    /// `Timeout` を返して終了コード 1 になる（親の死・停止でハングしない。REPAIR-5）。
    #[test]
    fn core6_mapper_times_out_without_go_signal() {
        let (parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        let (uid, gid) = mapper_fixture();
        let mut diag: Vec<u8> = Vec::new();
        let code = run_id_map_mapper(
            &MapperRequest {
                target: std::process::id(),
                expected_parent: std::os::unix::process::parent_id(),
                uid: &uid,
                gid: &gid,
                writer: &IdMapWriter::Direct,
                timeout: Duration::from_secs(1),
            },
            mapper_end,
            None,
            &mut diag,
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
        let text = String::from_utf8(diag).expect("utf8");
        assert_eq!(text.matches('\n').count(), 1);
        assert!(text.starts_with("fandhe-container: id map mapper: TIMEOUT (validate): did not receive the go signal from the parent: "), "{text}");
    }

    /// CORE-6・SEC-5（TASK-40.2）: 親 pid が期待と違えば（reparent 後の pid 再利用を想定）
    /// 書き込まず `FailedPrecondition` を返す。
    #[test]
    fn core6_mapper_refuses_when_parent_changed() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[MAPPER_GO]).expect("go");
        let (uid, gid) = mapper_fixture();
        // 実在するが親ではない pid（自プロセス）を使う。存在しない pid だと `/proc/<pid>` の open が
        // 先に `NotFound` で失敗し、親不一致の検証まで到達しない。
        let wrong = std::process::id();
        let mut diag: Vec<u8> = Vec::new();
        let code = run_id_map_mapper(
            &MapperRequest {
                target: wrong,
                expected_parent: wrong,
                uid: &uid,
                gid: &gid,
                writer: &IdMapWriter::Direct,
                timeout: Duration::from_secs(1),
            },
            mapper_end,
            None,
            &mut diag,
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
        let text = String::from_utf8(diag).expect("utf8");
        assert_eq!(text.matches('\n').count(), 1);
        assert_eq!(
            text,
            "fandhe-container: id map mapper: FAILED_PRECONDITION (validate): the parent process changed before the mapping was written\n"
        );
    }

    /// CORE-6・SEC-5（#2374）: 対象の親が期待した中間プロセスでなければ(mapper 自身の親は一致していても)
    /// 書き込まず `FailedPrecondition` を返す。pid 1 の親は 0 で、実在し読めて親が一致しない対象として使う。
    #[test]
    fn core6_mapper_refuses_when_target_is_not_child_of_expected_parent() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[MAPPER_GO]).expect("go");
        let (uid, gid) = mapper_fixture();
        let mut diag: Vec<u8> = Vec::new();
        let code = run_id_map_mapper(
            &MapperRequest {
                target: 1,
                expected_parent: std::os::unix::process::parent_id(),
                uid: &uid,
                gid: &gid,
                writer: &IdMapWriter::Direct,
                timeout: Duration::from_secs(1),
            },
            mapper_end,
            None,
            &mut diag,
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
        let text = String::from_utf8(diag).expect("utf8");
        assert_eq!(text.matches('\n').count(), 1);
        assert_eq!(
            text,
            "fandhe-container: id map mapper: FAILED_PRECONDITION (validate): the mapping target is not a child of the expected parent\n"
        );
    }

    /// SEC-5（#2374）: fd 経由で読んだ親 pid は `parent_id()` と一致する(具体値)。
    #[test]
    fn sec5_proc_handle_reads_parent_pid_via_fd() {
        let h = ProcHandle::open(TargetPid::new(std::process::id()).expect("pid")).expect("open");
        assert_eq!(
            h.parent_pid().expect("ppid"),
            std::os::unix::process::parent_id()
        );
    }

    /// CORE-6（TASK-40.2）: go 以外のバイトは `InvalidArgument` で拒否する。
    #[test]
    fn core6_mapper_rejects_unexpected_go_byte() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[9]).expect("byte");
        let (uid, gid) = mapper_fixture();
        let mut diag: Vec<u8> = Vec::new();
        let code = run_id_map_mapper(
            &MapperRequest {
                target: std::process::id(),
                expected_parent: std::os::unix::process::parent_id(),
                uid: &uid,
                gid: &gid,
                writer: &IdMapWriter::Direct,
                timeout: Duration::from_secs(1),
            },
            mapper_end,
            None,
            &mut diag,
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
        let text = String::from_utf8(diag).expect("utf8");
        assert_eq!(text.matches('\n').count(), 1);
        assert_eq!(
            text,
            "fandhe-container: id map mapper: INVALID_ARGUMENT (validate): unexpected go signal byte\n"
        );
    }

    /// 常に失敗する書き先。
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("sink closed"))
        }
    }

    /// CORE-6・REPAIR-12・REPAIR-5（#2393）: 診断の書き先が失敗しても応答フレームと終了コードは変わらない。
    #[test]
    fn core6_mapper_reply_survives_diag_write_failure() {
        let (mut parent_end, mapper_end) = std::os::unix::net::UnixStream::pair().expect("pair");
        parent_end.write_all(&[9]).expect("byte");
        let (uid, gid) = mapper_fixture();
        let code = run_id_map_mapper(
            &MapperRequest {
                target: std::process::id(),
                expected_parent: std::os::unix::process::parent_id(),
                uid: &uid,
                gid: &gid,
                writer: &IdMapWriter::Direct,
                timeout: Duration::from_secs(1),
            },
            mapper_end,
            None,
            &mut FailingWriter,
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

    /// SEC-5・CORE-6・REPAIR-2(#2551): holder 制御フレームの往復と、壊れた値の拒否。
    #[test]
    fn sec5_holder_control_roundtrip_and_rejects_malformed() {
        let p = MapperPid::new(12345).expect("pid");
        assert_eq!(HolderControl::MapperPid(p).encode(), [1, 0, 0, 0x30, 0x39]);
        assert_eq!(HolderControl::Release.encode(), [2, 0, 0, 0, 0]);
        assert_eq!(
            HolderControl::decode(&[1, 0, 0, 0x30, 0x39]).expect("decode"),
            HolderControl::MapperPid(p)
        );
        assert_eq!(
            HolderControl::decode(&[2, 0, 0, 0, 0]).expect("decode"),
            HolderControl::Release
        );
        let over = (i32::MAX as u32 + 1).to_be_bytes();
        let cases: [&[u8]; 9] = [
            &[1, 0, 0, 0, 0],
            &[1, 0, 0, 0, 1],
            &[1, over[0], over[1], over[2], over[3]],
            &[3, 0, 0, 0, 0],
            &[0, 0, 0, 0, 0],
            &[2, 0, 0, 0, 1],
            &[2, 0, 0, 0],
            &[2, 0, 0, 0, 0, 0],
            &[],
        ];
        for bytes in cases {
            let e = HolderControl::decode(bytes).expect_err("malformed");
            assert_eq!(e.code, ErrorCode::Internal, "{bytes:?}");
        }
    }

    /// CORE-6・SEC-5(#2551): `session_probe` は自プロセスの `/proc/self/stat` のセッション ID と一致する。
    #[test]
    fn core6_proc_handle_session_probe_matches_proc_stat() {
        let h = ProcHandle::open(TargetPid::new(std::process::id()).expect("pid")).expect("open");
        let stat = std::fs::read_to_string("/proc/self/stat").expect("stat");
        let after = &stat[stat.rfind(')').expect("close") + 1..];
        let sid: u32 = after
            .split_whitespace()
            .nth(3)
            .expect("field")
            .parse()
            .expect("num");
        assert_eq!(h.session_probe(), SessionProbe::Session(sid));
        assert_eq!(
            h.parent_pid().expect("ppid"),
            std::os::unix::process::parent_id()
        );
    }

    fn holder_test_wait<'a>(release_ms: u64, drain_ms: u64) -> HolderWait<'a> {
        HolderWait {
            self_pid: std::process::id(),
            expected_parent: 1,
            current_parent: &std::process::id,
            release_wait: Duration::from_millis(release_ms),
            drain_wait: Duration::from_millis(drain_ms),
            pidfd_kill: None,
        }
    }

    /// `setsid` 済みの `sleep`(セッション ID = 自分の pid)を、`stdin` に `keep` の複製を持たせて起動する。
    fn spawn_session_leader(keep: &std::os::unix::net::UnixStream) -> std::process::Child {
        let dup = keep.try_clone().expect("clone");
        let child = Command::new("setsid")
            .args(["sleep", "30"])
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(dup)))
            .spawn()
            .expect("spawn setsid");
        let h = ProcHandle::open(TargetPid::new(child.id()).expect("pid")).expect("open");
        let t = Instant::now();
        while h.session_probe() != SessionProbe::Session(child.id()) {
            assert!(t.elapsed() < Duration::from_secs(5), "setsid not done");
            std::thread::sleep(Duration::from_millis(5));
        }
        child
    }

    fn send_pid(sock: &mut std::os::unix::net::UnixStream, pid: u32) {
        let p = MapperPid::new(pid).expect("pid");
        sock.write_all(&HolderControl::MapperPid(p).encode())
            .expect("send");
    }

    /// SEC-5(#2551): pid の後に Release を受ければ 0 で終わり、kill しない。
    #[test]
    fn sec5_holder_release_after_mapper_pid_exits_zero_without_kill() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        a.write_all(&HolderControl::Release.encode()).expect("send");
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(5000, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::Released);
        assert_eq!(r.code(), 0);
        assert!(kills.is_empty());
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// SEC-5(#2551): pid より前に相手側が全員閉じれば EOF で終わり、kill しない。
    #[test]
    fn sec5_holder_eof_before_mapper_pid_does_not_kill() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        drop(a);
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(5000, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::PeersClosed);
        assert_eq!(r.code(), 1);
        assert!(kills.is_empty());
    }

    /// SEC-5・REPAIR-5(#2551): pid が来ないまま期限が来ても kill せず、期限で終わる。
    #[test]
    fn sec5_holder_expiry_without_mapper_pid_does_not_kill() {
        let (_a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut kills = Vec::new();
        let t = Instant::now();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::ExpiredNoKill);
        assert!(kills.is_empty());
        assert!(t.elapsed() >= Duration::from_millis(200));
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    /// SEC-5・CORE-6(#2551): 期限切れで mapper のセッションへ kill をちょうど 1 回送り、EOF まで待つ。
    #[test]
    fn sec5_holder_expiry_kills_mapper_session_then_drains() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 300),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(kills, vec![child.id()]);
        // 注入した kill は何も止めないので、子の複製が残り EOF には届かない。
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// 書き込みの時点で kill が済んでいたかを記録するライター。
    struct OrderProbe<'a> {
        killed: &'a std::cell::Cell<bool>,
        wrote_after_kill: Option<bool>,
    }

    impl std::io::Write for OrderProbe<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.wrote_after_kill
                .get_or_insert_with(|| self.killed.get());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// SEC-5・REPAIR-5(#2551): 診断の書き込みは SIGKILL の送信より後になる(書き先が止まっても kill に届く)。
    #[test]
    fn sec5_holder_diag_is_written_after_kill() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let killed = std::cell::Cell::new(false);
        let mut probe = OrderProbe {
            killed: &killed,
            wrote_after_kill: None,
        };
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 100),
            &mut |_| {
                killed.set(true);
                Ok(())
            },
            &mut probe,
        );
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
        assert_eq!(probe.wrote_after_kill, Some(true));
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// REPAIR-5・SEC-5(#2551): 読み手が止まって満杯の AF_UNIX socket を stderr に見立てても、`NonBlockingDiag` は
    /// 待たずに戻り、ブロックする素の `write` と違って holder の期限切れの経路を止めない。
    #[test]
    fn sec5_nonblocking_diag_does_not_stall_on_full_socket() {
        use std::io::Write as _;
        let (w, _r) = std::os::unix::net::UnixStream::pair().expect("pair");
        // 満杯にする(`EAGAIN` になるまで待たずに送る)。
        let chunk = [b'x'; 512];
        while sys::send_nonblocking_unix(std::os::fd::AsFd::as_fd(&w), &chunk).is_ok() {}
        let mut diag = NonBlockingDiag(w);
        let t = Instant::now();
        writeln!(diag, "fandhe-container: userns holder: release wait ended").expect("dropped");
        // 満杯の pipe に対しても kill 経路ごと期限内に戻る。
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut diag,
        );
        assert_eq!(kills, vec![child.id()]);
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
        assert!(t.elapsed() < Duration::from_secs(3));
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// REPAIR-5(#2551): pipe など待たない送信を保証できない出力先には書かず、`EAGAIN` でもエラーにせず捨てる。
    #[test]
    fn repair5_nonblocking_diag_discards_for_non_socket() {
        use std::io::Read as _;
        use std::io::Write as _;
        let (mut r, w) = std::io::pipe().expect("pipe");
        let mut diag = NonBlockingDiag(w);
        writeln!(diag, "dropped").expect("discarded without error");
        drop(diag);
        let mut got = Vec::new();
        r.read_to_end(&mut got).expect("eof");
        assert_eq!(got, Vec::<u8>::new());
    }

    /// SEC-5・CORE-6・REPAIR-5(#2551): 本番の kill で、SIGSTOP で止められた mapper のセッションも SIGKILL で終わり、
    /// EOF に届く。
    #[test]
    fn sec5_holder_expiry_real_kill_ends_stopped_session() {
        use std::os::unix::process::ExitStatusExt as _;
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let sigstop = std::num::NonZeroU8::new(19).expect("nonzero");
        sys::kill_pid(child.id(), sys::Signal::Number(sigstop)).expect("stop");
        drop(a);
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 5000),
            &mut |pgid| sys::kill_process_group(pgid, sys::Signal::Kill),
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::ExpiredKilled { drained: true });
        assert_eq!(child.wait().expect("wait").signal(), Some(9));
    }

    /// REPAIR-5(#2551): kill の後に EOF が来なくても `drain_wait` で戻る。
    #[test]
    fn sec5_holder_drain_wait_is_bounded() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let t = Instant::now();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 300),
            &mut |_| Ok(()),
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
        assert!(t.elapsed() >= Duration::from_millis(500));
        assert!(t.elapsed() < Duration::from_secs(5));
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// SEC-5(#2551): holder 自身・親の pid は錨にせず、期限切れでも kill しない。
    #[test]
    fn sec5_holder_rejects_mapper_pid_equal_to_self_or_parent() {
        let own = std::process::id();
        for (pid, parent) in [(own, 1), (own + 1, own + 1)] {
            let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
            send_pid(&mut a, pid);
            let mut w = holder_test_wait(200, 100);
            w.expected_parent = parent;
            let mut kills = Vec::new();
            let mut diag = Vec::new();
            let r = holder_await_release(
                &mut b,
                &w,
                &mut |p| {
                    kills.push(p);
                    Ok(())
                },
                &mut diag,
            );
            assert_eq!(r, HolderExit::ExpiredNoKill, "{pid}");
            assert!(kills.is_empty());
            let text = String::from_utf8(diag).expect("utf8");
            assert!(text.contains("no anchor"), "{text}");
        }
    }

    /// SEC-5(#2551): mapper が `setsid` の前(セッション ID が自分の pid でない)なら kill しない。
    #[test]
    fn sec5_holder_skips_kill_when_mapper_has_not_set_session() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = Command::new("sleep").arg("30").spawn().expect("spawn");
        send_pid(&mut a, child.id());
        let mut kills = Vec::new();
        // 子は holder(この試験)の子なので、錨の親照合を通る。
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(200, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::ExpiredNoKill);
        assert!(kills.is_empty());
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// SEC-5(#2551): mapper が回収済み(`Gone`)で元のグループの生存を確かめられなければ、数値 PGID へ送らない。
    /// (SIGCHLD=SIG_IGN の継承で mapper が自動回収され、I が Release 前に止まった場合の形。)
    #[test]
    fn sec5_holder_gone_unverified_group_does_not_kill() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        let pid = child.id();
        send_pid(&mut a, pid);
        let reaper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            child.kill().expect("kill");
            child.wait().expect("wait");
        });
        let mut kills = Vec::new();
        let mut diag = Vec::new();
        let r = holder_await_release(
            &mut b,
            &holder_test_wait(500, 100),
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut diag,
        );
        reaper.join().expect("join");
        drop(a);
        assert_eq!(r, HolderExit::ExpiredNoKill);
        assert!(kills.is_empty());
        let text = String::from_utf8(diag).expect("utf8");
        assert!(text.contains("not verified"), "{text}");
    }

    /// SEC-5・CORE-6(#2551): mapper が回収済み(`Gone`)でも、pidfd 経由のグループ送信は元のグループにしか届かないため
    /// 送る(数値 PGID の `kill` は呼ばない)。pidfd 経由が使えない場合の `Gone` は上の試験のとおり送らない。
    #[test]
    fn sec5_holder_gone_sends_via_pidfd_group_only() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        let pid = child.id();
        send_pid(&mut a, pid);
        let reaper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            child.kill().expect("kill");
            child.wait().expect("wait");
        });
        let sent = std::cell::Cell::new(0_u32);
        let send = |_fd: std::os::fd::BorrowedFd<'_>| {
            sent.set(sent.get() + 1);
            Ok(())
        };
        let mut w = holder_test_wait(500, 100);
        w.pidfd_kill = Some(&send);
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &w,
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        reaper.join().expect("join");
        drop(a);
        assert_eq!(sent.get(), 1);
        assert!(kills.is_empty(), "{kills:?}");
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
    }

    /// SEC-5(#2551): pidfd 経由が未対応(`EINVAL`)なら、生きている mapper に限って数値 PGID の経路へ退避する。
    #[test]
    fn sec5_holder_pidfd_einval_falls_back_to_numeric_group() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let send = |_fd: std::os::fd::BorrowedFd<'_>| Err(SysError::Os(sys::EINVAL));
        let mut w = holder_test_wait(200, 100);
        w.pidfd_kill = Some(&send);
        let mut kills = Vec::new();
        let r = holder_await_release(
            &mut b,
            &w,
            &mut |p| {
                kills.push(p);
                Ok(())
            },
            &mut Vec::new(),
        );
        assert_eq!(kills, vec![child.id()]);
        assert_eq!(r, HolderExit::ExpiredKilled { drained: false });
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// SEC-5・CORE-6(#2551): 本番の pidfd 経由のグループ送信(未対応カーネルでは数値 PGID へ退避)で、SIGSTOP された
    /// mapper のセッションも SIGKILL で終わり EOF に届く。
    #[test]
    fn sec5_holder_expiry_real_pidfd_group_kill_ends_stopped_session() {
        use std::os::unix::process::ExitStatusExt as _;
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        let sigstop = std::num::NonZeroU8::new(19).expect("nonzero");
        sys::kill_pid(child.id(), sys::Signal::Number(sigstop)).expect("stop");
        drop(a);
        let send =
            |fd: std::os::fd::BorrowedFd<'_>| sys::pidfd_send_signal_group(fd, sys::Signal::Kill);
        let mut w = holder_test_wait(200, 5000);
        w.pidfd_kill = Some(&send);
        let r = holder_await_release(
            &mut b,
            &w,
            &mut |pgid| sys::kill_process_group(pgid, sys::Signal::Kill),
            &mut Vec::new(),
        );
        assert_eq!(r, HolderExit::ExpiredKilled { drained: true });
        assert_eq!(child.wait().expect("wait").signal(), Some(9));
    }

    /// SEC-5(#2551): 錨を確保できたら `MapperReply::Ok`、できなければ `Failed` を I へ返す。
    #[test]
    fn sec5_holder_acks_anchor_result() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut child = spawn_session_leader(&a);
        send_pid(&mut a, child.id());
        a.write_all(&HolderControl::Release.encode()).expect("send");
        let _ = holder_await_release(
            &mut b,
            &holder_test_wait(2000, 100),
            &mut |_| Ok(()),
            &mut Vec::new(),
        );
        let mut buf = [0u8; MAPPER_REPLY_LEN];
        a.read_exact(&mut buf).expect("ack");
        assert_eq!(MapperReply::decode(&buf).expect("decode"), MapperReply::Ok);
        child.kill().expect("kill");
        child.wait().expect("wait");

        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let own = std::process::id();
        send_pid(&mut a, own + 1);
        let mut w = holder_test_wait(200, 100);
        w.expected_parent = own + 1;
        let _ = holder_await_release(&mut b, &w, &mut |_| Ok(()), &mut Vec::new());
        a.read_exact(&mut buf).expect("ack");
        assert_eq!(
            MapperReply::decode(&buf).expect("decode"),
            MapperReply::Failed {
                code: ErrorCode::FailedPrecondition,
                stage: RootlessStage::Validate
            }
        );
    }
}
