//! CDI `deviceNodes` の検証・ホスト情報の補完・`mknod` による作成（TASK-127.1・GPU-2・MS-10）。
//!
//! # 役割と呼び出し順（契約）
//! 1. `resolve_device_nodes`: spec 由来の `DeviceNode` を検証し、path だけの指定などの欠けた
//!    type / major / minor / mode をホストの `lstat` で補う。ホストの `/dev` を読むため
//!    `pivot_root` の前に呼ぶ。
//! 2. core の `create_default_devices` がコンテナの `/dev`（tmpfs）を載せる。
//! 3. `create_device_nodes`（Linux 限定）: その `/dev` のマウントのルート fd を起点に、major/minor を保って
//!    `mknodat` する。名前から開き直した fd ではなく、マウント時に得たルート fd を渡す。
//! 4. `pivot_root`。1 プロセス 1 回、`MountIsolation::establish` と同じスレッドで呼ぶ。
//!
//! 上記の core の実行フローへの配線は未実装（REPAIR-3）。rootless（`mknod` が `EPERM`）でホストのノードを
//! bind する経路も未実装で、`EPERM` は `PermissionDenied` のまま返し、黙って別経路へ縮退しない（fail-closed）。
//!
//! # 上流 CDI 参照実装との意図的な差（厳しくする方向。fail-closed）
//! - path は `/dev/` 配下だけ受ける（rootfs の自己 bind は `nodev` のため `/dev` の外のノードは開けない）
//! - major は 0..=0xfff、minor は 0..=0xfffff の範囲外を拒否する（`dev_t` へ詰める前に検査し、切り詰めない）
//! - mode は 0o777 以下だけ（setuid / setgid / sticky のノードは作らない）
//!
//! ホスト情報の補完規則は上流 `pkg/cdi/container-edits_unix.go`（v1.1.1）の `fillMissingInfo` に合わせる。

use super::{CdiApplyError, CdiApplyErrorCode as Code};
use crate::cdi_spec::DeviceNode;

/// 1 回の適用で受けるデバイスノード数の上限（実際の nvidia.yaml は 7 件前後。無制限確保を避ける）。
pub const CDI_APPLY_MAX_DEVICE_NODES: usize = 1024;
/// コンテナ内 path 全体の最大バイト数。
const MAX_PATH_BYTES: usize = 4096;
/// path の 1 要素の最大バイト数。
const MAX_COMPONENT_BYTES: usize = 255;
/// `/dev` からの最大の深さ。
const MAX_DEPTH: usize = 16;
const MAX_MAJOR: i64 = 0xfff;
const MAX_MINOR: i64 = 0xfffff;
/// mode 未指定のときの既定（runc の specconv と同じ）。
const DEFAULT_MODE: u32 = 0o666;

/// デバイスノードの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceNodeKind {
    /// キャラクタデバイス（`c` / `u`）。
    Char,
    /// ブロックデバイス（`b`）。
    Block,
    /// FIFO（`p`）。
    Fifo,
}

/// 検証済み・補完済みのデバイスノード（作成に必要な値がすべて確定している）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedDeviceNode {
    path: Vec<String>,
    kind: DeviceNodeKind,
    major: u32,
    minor: u32,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl ResolvedDeviceNode {
    /// `/dev/` を除いた、検証済みの path 構成要素。
    pub fn dev_relative_path(&self) -> &[String] {
        &self.path
    }
    /// 種別。
    pub fn kind(&self) -> DeviceNodeKind {
        self.kind
    }
    /// メジャー番号（FIFO は 0）。
    pub fn major(&self) -> u32 {
        self.major
    }
    /// マイナー番号（FIFO は 0）。
    pub fn minor(&self) -> u32 {
        self.minor
    }
    /// 権限ビット（0o777 以下）。
    pub fn mode(&self) -> u32 {
        self.mode
    }
    /// 所有 UID（`None` は chown しない）。
    pub fn uid(&self) -> Option<u32> {
        self.uid
    }
    /// 所有 GID（`None` は chown しない）。
    pub fn gid(&self) -> Option<u32> {
        self.gid
    }
}

/// `dev_t` を glibc の `makedev` と同じビット配置で組み立てる（範囲は呼び出し側が検査済み）。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn encode_dev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (u64::from(major), u64::from(minor));
    ((ma & 0xfff) << 8) | ((ma & !0xfff) << 32) | (mi & 0xff) | ((mi & !0xff) << 12)
}

/// `dev_t` を glibc の `gnu_dev_major` / `gnu_dev_minor` と同じ配置で分解する。
/// Linux のビット配置であり、他 OS の `st_rdev` には使わない（`RealHost` は Linux 限定）。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn decode_dev(dev: u64) -> (u64, u64) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major, minor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum HostKind {
    Char,
    Block,
    Fifo,
    Other,
}

/// ホストパスの `lstat` 結果（必要な項目だけ）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostStat {
    pub kind: HostKind,
    pub rdev: u64,
    pub mode: u32,
}

/// ホストの `lstat` の差し替え口（試験用に偽物を注入する）。
pub(crate) trait HostDeviceLookup {
    fn lstat(&self, path: &str) -> Result<HostStat, Code>;
}

/// 実ホストの `lstat`（symlink を辿らない。デバイスを open しない）。
struct RealHost;

#[cfg(target_os = "linux")]
impl HostDeviceLookup for RealHost {
    fn lstat(&self, path: &str) -> Result<HostStat, Code> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        let md = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Code::NotFound,
            std::io::ErrorKind::PermissionDenied => Code::PermissionDenied,
            _ => Code::Internal,
        })?;
        let ft = md.file_type();
        let kind = if ft.is_char_device() {
            HostKind::Char
        } else if ft.is_block_device() {
            HostKind::Block
        } else if ft.is_fifo() {
            HostKind::Fifo
        } else {
            HostKind::Other
        };
        Ok(HostStat {
            kind,
            rdev: md.rdev(),
            mode: md.mode(),
        })
    }
}

/// Linux 以外では `st_rdev` の復号が異なるため未実装として明示的に拒否する（3 OS 一級対応の
/// うち macOS / Windows の復号は未実装。誤った major/minor を黙って返さない）。
#[cfg(not(target_os = "linux"))]
impl HostDeviceLookup for RealHost {
    fn lstat(&self, _path: &str) -> Result<HostStat, Code> {
        Err(Code::Unimplemented)
    }
}

fn err(code: Code, msg: &'static str) -> CdiApplyError {
    CdiApplyError::new(code, msg)
}

/// `/dev/` 配下の正規形だけを受け、構成要素に分解する。
fn parse_dev_path(path: &str) -> Result<Vec<String>, CdiApplyError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(err(Code::ResourceExhausted, "device node path is too long"));
    }
    if path.contains('\0') {
        return Err(err(Code::InvalidArgument, "device node path contains NUL"));
    }
    let Some(rest) = path.strip_prefix("/dev/") else {
        return Err(err(
            Code::InvalidArgument,
            "device node path must be under /dev/",
        ));
    };
    let mut out = Vec::new();
    for c in rest.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            return Err(err(
                Code::InvalidArgument,
                "device node path has an empty, '.' or '..' component",
            ));
        }
        if c.len() > MAX_COMPONENT_BYTES {
            return Err(err(
                Code::ResourceExhausted,
                "device node path component is too long",
            ));
        }
        out.push(c.to_owned());
        if out.len() > MAX_DEPTH {
            return Err(err(Code::ResourceExhausted, "device node path is too deep"));
        }
    }
    Ok(out)
}

fn parse_type(t: Option<&str>) -> Result<Option<DeviceNodeKind>, CdiApplyError> {
    match t {
        None | Some("") => Ok(None),
        Some("c") | Some("u") => Ok(Some(DeviceNodeKind::Char)),
        Some("b") => Ok(Some(DeviceNodeKind::Block)),
        Some("p") => Ok(Some(DeviceNodeKind::Fifo)),
        Some(_) => Err(err(
            Code::InvalidArgument,
            "device node type must be one of c, b, u, p",
        )),
    }
}

fn check_major(v: Option<i64>) -> Result<Option<u32>, CdiApplyError> {
    match v {
        None => Ok(None),
        Some(n) if (0..=MAX_MAJOR).contains(&n) => Ok(u32::try_from(n).ok()),
        Some(_) => Err(err(
            Code::InvalidArgument,
            "device node major is out of range",
        )),
    }
}

fn check_minor(v: Option<i64>) -> Result<Option<u32>, CdiApplyError> {
    match v {
        None => Ok(None),
        Some(n) if (0..=MAX_MINOR).contains(&n) => Ok(u32::try_from(n).ok()),
        Some(_) => Err(err(
            Code::InvalidArgument,
            "device node minor is out of range",
        )),
    }
}

/// ホストの `st_rdev` を major/minor へ分解する。復号は Linux のビット配置に限るため、
/// 他 OS では誤った値を返さず `Unimplemented`（`RealHost` も他 OS では常に拒否する）。
#[cfg(any(target_os = "linux", test))]
fn host_dev_numbers(rdev: u64) -> Result<(u64, u64), CdiApplyError> {
    Ok(decode_dev(rdev))
}

#[cfg(not(any(target_os = "linux", test)))]
fn host_dev_numbers(_rdev: u64) -> Result<(u64, u64), CdiApplyError> {
    Err(err(
        Code::Unimplemented,
        "host device number decoding is not supported on this OS",
    ))
}

fn host_kind_to_kind(k: HostKind) -> Option<DeviceNodeKind> {
    match k {
        HostKind::Char => Some(DeviceNodeKind::Char),
        HostKind::Block => Some(DeviceNodeKind::Block),
        HostKind::Fifo => Some(DeviceNodeKind::Fifo),
        HostKind::Other => None,
    }
}

fn lookup_error(code: Code) -> CdiApplyError {
    match code {
        Code::NotFound => err(Code::NotFound, "host device node was not found"),
        Code::PermissionDenied => err(
            Code::PermissionDenied,
            "host device node could not be inspected",
        ),
        Code::Unimplemented => err(
            Code::Unimplemented,
            "host device inspection is not supported on this OS",
        ),
        _ => err(Code::Internal, "host device node lookup failed"),
    }
}

/// 試験用に lookup を注入できる本体。
pub(crate) fn resolve_device_nodes_with(
    nodes: &[DeviceNode],
    lookup: &impl HostDeviceLookup,
) -> Result<Vec<ResolvedDeviceNode>, CdiApplyError> {
    if nodes.len() > CDI_APPLY_MAX_DEVICE_NODES {
        return Err(err(Code::ResourceExhausted, "too many device nodes"));
    }
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        out.push(resolve_one(n, lookup)?);
    }
    Ok(out)
}

fn resolve_one(
    n: &DeviceNode,
    lookup: &impl HostDeviceLookup,
) -> Result<ResolvedDeviceNode, CdiApplyError> {
    let path = parse_dev_path(&n.path)?;
    let spec_kind = parse_type(n.r#type.as_deref())?;
    let spec_major = check_major(n.major)?;
    let spec_minor = check_minor(n.minor)?;
    if let Some(m) = n.file_mode
        && m > 0o777
    {
        return Err(err(
            Code::InvalidArgument,
            "device node fileMode must not exceed 0o777",
        ));
    }
    // u32::MAX は chown(2) で -1（変更しない）と同じ意味になり、指定と観測が黙って食い違うため入口で拒否する
    // （GPU-1・SEC-1）。ホストの lookup より前に判定し、結果がホストの状態に依らないようにする。
    if n.uid == Some(u32::MAX) {
        return Err(err(
            Code::InvalidArgument,
            "device node uid must not be 4294967295 (reserved as -1 by chown)",
        ));
    }
    if n.gid == Some(u32::MAX) {
        return Err(err(
            Code::InvalidArgument,
            "device node gid must not be 4294967295 (reserved as -1 by chown)",
        ));
    }
    let host_path = match n.host_path.as_deref() {
        None | Some("") => n.path.as_str(),
        Some(h) => {
            if !h.starts_with('/') || h.contains('\0') {
                return Err(err(
                    Code::InvalidArgument,
                    "device node hostPath must be absolute and NUL-free",
                ));
            }
            h
        }
    };

    // 上流の minimal に近いが、minor の省略は完全指定とみなさない（上流は type と major だけで真になり、
    // minor 省略のとき後段で補完できず拒否される。ここではホストから補完する側へ倒す）。
    let is_fifo_spec = matches!(spec_kind, Some(DeviceNodeKind::Fifo));
    let minimal = spec_kind.is_some()
        && (is_fifo_spec || (spec_major.unwrap_or(0) != 0 && spec_minor.is_some()));

    let host = match lookup.lstat(host_path) {
        Ok(h) => Some(h),
        Err(code) if minimal => {
            let _ = code;
            None
        }
        Err(code) => return Err(lookup_error(code)),
    };

    let mut kind = spec_kind;
    let mut major = spec_major;
    let mut minor = spec_minor;
    let mut host_mode = None;
    if let Some(h) = host {
        if minimal {
            // 完全指定でも mode をホストから補う場合は、種別を検証する（symlink 自身の 0777 や
            // 非デバイスの mode を適用しない。fail-closed）。
            if n.file_mode.is_none() {
                if host_kind_to_kind(h.kind) != kind {
                    return Err(err(
                        Code::InvalidArgument,
                        "device node type does not match the host device",
                    ));
                }
                host_mode = Some(h.mode & 0o777);
            }
        } else {
            host_mode = Some(h.mode & 0o777);
            let Some(hk) = host_kind_to_kind(h.kind) else {
                return Err(err(Code::InvalidArgument, "host path is not a device node"));
            };
            match kind {
                None => kind = Some(hk),
                Some(k) if k != hk => {
                    return Err(err(
                        Code::InvalidArgument,
                        "device node type does not match the host device",
                    ));
                }
                Some(_) => {}
            }
            if hk != DeviceNodeKind::Fifo {
                let (hma, hmi) = host_dev_numbers(h.rdev)?;
                if major.unwrap_or(0) == 0 {
                    major = u32::try_from(hma).ok();
                    minor = u32::try_from(hmi).ok();
                } else if minor.is_none() {
                    // major だけ指定された場合は、ホストの major が一致するときに限り minor を補う。
                    if u32::try_from(hma).ok() != major {
                        return Err(err(
                            Code::InvalidArgument,
                            "device node major does not match the host device",
                        ));
                    }
                    minor = u32::try_from(hmi).ok();
                }
            }
        }
    }

    let Some(kind) = kind else {
        return Err(err(Code::InvalidArgument, "device node type is unknown"));
    };
    let (major, minor) = if kind == DeviceNodeKind::Fifo {
        (0, 0)
    } else {
        match (major, minor) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                return Err(err(
                    Code::InvalidArgument,
                    "device node major and minor are required",
                ));
            }
        }
    };
    if i64::from(major) > MAX_MAJOR || i64::from(minor) > MAX_MINOR {
        return Err(err(
            Code::InvalidArgument,
            "device node number is out of range",
        ));
    }
    Ok(ResolvedDeviceNode {
        path,
        kind,
        major,
        minor,
        mode: n.file_mode.or(host_mode).unwrap_or(DEFAULT_MODE),
        uid: n.uid,
        gid: n.gid,
    })
}

/// `deviceNodes` を検証し、欠けた値をホストの `lstat` で補う。ホストの `/dev` を読むので
/// `pivot_root` の前に呼ぶ（モジュール doc の呼び出し順）。
///
/// 非 unix では `Unimplemented`（minimal 指定以外のホスト参照ができないため、全体を拒否する）。
pub fn resolve_device_nodes(
    nodes: &[DeviceNode],
) -> Result<Vec<ResolvedDeviceNode>, CdiApplyError> {
    if cfg!(not(unix)) {
        return Err(err(
            Code::Unimplemented,
            "device node resolution is not supported on this OS",
        ));
    }
    resolve_device_nodes_with(nodes, &RealHost)
}

#[cfg(target_os = "linux")]
pub use linux::{
    DeviceNodeCreateRecorder, DeviceNodeCreateSample, DeviceNodeOutcome, DeviceNodeReport,
    DeviceNodeStatus, create_device_nodes, create_device_nodes_with_recorder,
};

#[cfg(target_os = "linux")]
mod linux {
    use super::{DeviceNodeKind, ResolvedDeviceNode, decode_dev, encode_dev};
    use crate::cdi_apply::{CdiApplyError, CdiApplyErrorCode as Code};
    use crate::sys::{self, SysError, consts};
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::time::{Duration, Instant};

    /// ノード 1 件の結果。
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct DeviceNodeOutcome {
        /// `/dev` からの相対 path（`/` 区切り）。
        pub path: String,
        /// 要求された種別。
        pub kind: DeviceNodeKind,
        /// 作成か、完全一致の既存か。
        pub status: DeviceNodeStatus,
        /// 作成後に fstat で観測したメジャー番号。
        pub observed_major: u64,
        /// 作成後に fstat で観測したマイナー番号。
        pub observed_minor: u64,
        /// 作成後に観測した権限ビット（0o7777 マスク）。
        pub observed_mode: u32,
    }

    /// 作成か既存か。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum DeviceNodeStatus {
        /// この呼び出しが作った。
        Created,
        /// 種別・rdev・mode（と指定された uid / gid）が完全一致する既存のノード。
        AlreadyPresent,
    }

    /// 作成結果。観測値は「ホストと major/minor が一致」を機械的に照合する材料になる。
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    #[non_exhaustive]
    pub struct DeviceNodeReport {
        /// 入力順のノードごとの結果。
        pub outcomes: Vec<DeviceNodeOutcome>,
    }

    fn map_sys(e: SysError, msg: &'static str) -> CdiApplyError {
        match e {
            SysError::Unsupported => CdiApplyError::new(
                Code::Unimplemented,
                "device node creation is not supported on this architecture",
            ),
            SysError::Os(n) => {
                let code = match n {
                    2 => Code::NotFound,
                    1 | 13 => Code::PermissionDenied,
                    22 => Code::InvalidArgument,
                    12 | 28 | 122 => Code::ResourceExhausted,
                    17 | 20 | 40 => Code::FailedPrecondition,
                    _ => Code::Internal,
                };
                CdiApplyError::new(code, msg).with_errno(n)
            }
        }
    }

    fn io_err(e: &std::io::Error, msg: &'static str) -> CdiApplyError {
        let code = match e.kind() {
            std::io::ErrorKind::PermissionDenied => Code::PermissionDenied,
            std::io::ErrorKind::NotFound => Code::FailedPrecondition,
            _ => Code::Internal,
        };
        let mut r = CdiApplyError::new(code, msg);
        if let Some(n) = e.raw_os_error() {
            r = r.with_errno(n);
        }
        r
    }

    fn precondition(msg: &'static str) -> CdiApplyError {
        CdiApplyError::new(Code::FailedPrecondition, msg)
    }

    fn cstr(s: &str) -> Result<CString, CdiApplyError> {
        CString::new(s).map_err(|_| CdiApplyError::new(Code::InvalidArgument, "name contains NUL"))
    }

    fn clone_fd(fd: BorrowedFd<'_>) -> Result<OwnedFd, CdiApplyError> {
        fd.try_clone_to_owned()
            .map_err(|e| io_err(&e, "failed to duplicate a directory fd"))
    }

    /// 観測した inode の属性（fd を `File` にして `File::metadata` で読む。std が `statx`、使えなければ `fstat` を選ぶ）。
    struct Observed {
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
        dev: u64,
        ino: u64,
    }

    #[cfg(test)]
    thread_local! {
        /// 試験用: `observe` を n 回目（0 起点）に失敗させる（EMFILE 等の模擬）。
        pub(super) static FAIL_OBSERVE_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
        /// 試験用: 発火後にさらに連続して失敗させる回数（再観測も失敗する場面の模擬）。
        pub(super) static FAIL_OBSERVE_EXTRA: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// fd を複製せずに fstat する（FD 枯渇下の回収でも追加の FD を要しない）。fd は結果と一緒に返す。
    fn observe(fd: OwnedFd) -> Result<(Observed, OwnedFd), CdiApplyError> {
        #[cfg(test)]
        {
            let hit = FAIL_OBSERVE_AT.with(|c| match c.get() {
                Some(0) => {
                    let extra = FAIL_OBSERVE_EXTRA.with(|x| x.replace(0));
                    if extra > 0 {
                        FAIL_OBSERVE_EXTRA.with(|x| x.set(extra - 1));
                        c.set(Some(0));
                    } else {
                        c.set(None);
                    }
                    true
                }
                Some(n) => {
                    c.set(Some(n - 1));
                    false
                }
                None => false,
            });
            if hit {
                return Err(CdiApplyError::new(Code::ResourceExhausted, "injected").with_errno(24));
            }
        }
        let f = File::from(fd);
        let md = f
            .metadata()
            .map_err(|e| io_err(&e, "failed to stat the created node"))?;
        Ok((
            Observed {
                mode: md.mode(),
                rdev: md.rdev(),
                uid: md.uid(),
                gid: md.gid(),
                dev: md.dev(),
                ino: md.ino(),
            },
            OwnedFd::from(f),
        ))
    }

    fn type_bits(kind: DeviceNodeKind) -> u32 {
        match kind {
            DeviceNodeKind::Char => consts::S_IFCHR,
            DeviceNodeKind::Block => consts::S_IFBLK,
            DeviceNodeKind::Fifo => consts::S_IFIFO,
        }
    }

    const S_IFMT: u32 = 0o170_000;
    const S_IFDIR: u32 = 0o040_000;

    /// この呼び出しが作ったものの記録（失敗時の逆順の後始末用）。
    #[derive(Default)]
    pub(super) struct Created {
        pub(super) dirs: Vec<CreatedDir>,
        pub(super) nodes: Vec<CreatedNode>,
    }

    /// 作成した中間ディレクトリ 1 件。`mkdirat` の成功直後に `ident: None` で登録し、開き直して観測できたら
    /// `(dev, ino)` を埋める。後始末は同一性を照合できたものだけを消す（GPU-2・SEC-1）。
    pub(super) struct CreatedDir {
        pub(super) parent: OwnedFd,
        pub(super) name: CString,
        pub(super) ident: Option<(u64, u64)>,
    }

    /// 作成したノード 1 件。`mknodat` の直前に親 fd を複製しておき、成功した直後に登録する
    /// （再オープン・観測・複製の失敗でも回収できるようにする。特権操作の後始末）。
    pub(super) struct CreatedNode {
        pub(super) parent: OwnedFd,
        pub(super) name: CString,
        /// 作成した種別ビット（`S_IFCHR` 等）と rdev。識別が未確定の間の照合に使う。
        pub(super) type_bits: u32,
        pub(super) rdev: u64,
        /// 再オープンして観測できた後に埋める `(dev, ino)`。
        pub(super) ident: Option<(u64, u64)>,
    }

    impl Created {
        /// 最善努力の後始末。失敗しても元のエラーを優先するため結果は捨てる。
        ///
        /// ディレクトリは `(dev, ino)` が作成時の記録と一致する場合だけ `rmdir` する。識別が未確定
        /// （作成直後の開き直し・観測の失敗）のものは、差し替えられた別物を消さないよう残す（fail-closed）。
        /// 残った空ディレクトリは再試行の `walk_dirs` が既存として開くので作成を妨げない。照合から `rmdir`
        /// までの名前の差し替えは、fd 指定の rmdir が Linux に無いため残余（空ディレクトリ 1 個に限る）。
        pub(super) fn rollback(self) {
            for n in self.nodes.into_iter().rev() {
                // 識別が未確定でも、種別と rdev が作ったものと一致する場合だけ消す。
                let same = sys::open_path_nofollow_at(n.parent.as_fd(), &n.name)
                    .ok()
                    .and_then(|fd| observe(fd).ok())
                    .is_some_and(|(o, _fd)| {
                        o.mode & S_IFMT == n.type_bits
                            && o.rdev == n.rdev
                            && n.ident.is_none_or(|(d, i)| o.dev == d && o.ino == i)
                    });
                if same {
                    let _ = sys::unlink_at(n.parent.as_fd(), &n.name, false);
                }
            }
            for d in self.dirs.into_iter().rev() {
                let Some((di, ii)) = d.ident else { continue };
                let same = sys::open_dir_nofollow_at(d.parent.as_fd(), &d.name)
                    .ok()
                    .and_then(|fd| observe(fd).ok())
                    .is_some_and(|(o, _fd)| {
                        o.mode & S_IFMT == S_IFDIR && o.dev == di && o.ino == ii
                    });
                if same {
                    let _ = sys::unlink_at(d.parent.as_fd(), &d.name, true);
                }
            }
        }
    }

    /// 中間ディレクトリを 1 要素ずつ `O_NOFOLLOW` で辿り、無ければ作る。
    fn walk_dirs(
        dev_root: BorrowedFd<'_>,
        comps: &[String],
        created: &mut Created,
    ) -> Result<OwnedFd, CdiApplyError> {
        let mut cur = clone_fd(dev_root)?;
        for c in comps {
            let name = cstr(c)?;
            let next = match sys::open_dir_nofollow_at(cur.as_fd(), &name) {
                Ok(fd) => recover_leftover_dir(fd)?,
                Err(SysError::Os(2)) => {
                    // 複製は作成の前に済ませる（作成後に失敗して取り残さない）。
                    let rec_parent = clone_fd(cur.as_fd())?;
                    let mut made = false;
                    match sys::mkdir_at(cur.as_fd(), &name, 0o755) {
                        Ok(()) => {
                            created.dirs.push(CreatedDir {
                                parent: rec_parent,
                                name: name.clone(),
                                ident: None,
                            });
                            made = true;
                        }
                        Err(SysError::Os(17)) => {}
                        Err(e) => return Err(map_sys(e, "failed to create a /dev subdirectory")),
                    }
                    let mut fd = sys::open_dir_nofollow_at(cur.as_fd(), &name)
                        .map_err(|e| map_sys(e, "failed to open a /dev subdirectory"))?;
                    if made {
                        // 開き直した fd の (dev, ino) を記録して、後始末で同一性を照合できるようにする。
                        // 観測が一時的に失敗しても 0700 のまま識別なしで残さないよう、開き直して 1 回だけ再観測する。
                        // 再観測も失敗した場合は識別が未確定のまま残る（残余。後始末は fail-closed で消さない）。
                        let (o, back) = match observe(fd) {
                            Ok(v) => v,
                            Err(_) => {
                                let again =
                                    sys::open_dir_nofollow_at(cur.as_fd(), &name).map_err(|e| {
                                        map_sys(e, "failed to open a /dev subdirectory")
                                    })?;
                                observe(again)?
                            }
                        };
                        fd = back;
                        if o.mode & S_IFMT != S_IFDIR {
                            return Err(precondition(
                                "a created /dev subdirectory is not a directory",
                            ));
                        }
                        if let Some(last) = created.dirs.last_mut() {
                            last.ident = Some((o.dev, o.ino));
                        }
                        // umask で削られた権限を、開き直した検証済み fd に対してだけ 0755 へ補正する
                        // （プロセス全体の umask は変えない。GPU-2）。
                        std::fs::set_permissions(
                            proc_fd_path(&fd),
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .map_err(|e| io_err(&e, "failed to set the /dev subdirectory mode"))?;
                    }
                    fd
                }
                Err(SysError::Os(20 | 40)) => {
                    return Err(precondition(
                        "a /dev path component is a symlink or not a directory",
                    ));
                }
                Err(e) => return Err(map_sys(e, "failed to open a /dev subdirectory")),
            };
            cur = next;
        }
        Ok(cur)
    }

    /// 既存ディレクトリのうち、前回の試行が識別できないまま 0700 で残したものを 0755 へ回復する（GPU-2・SEC-1）。
    ///
    /// umask 077 の `mkdirat` 成功後に開き直し・観測が失敗すると、補正前の 0700 のディレクトリが識別なしで
    /// 残る（後始末は fail-closed で消さない）。再試行はこれを既存として開くため、ここで fd 経由に
    /// 種別（ディレクトリ）・所有者（実効 uid）・権限（ちょうど 0700）を再確認できたものだけを fd 経由で
    /// 0755 にする。他人の所有物や別の権限のものは変更しない。観測・補正に失敗したら、
    /// 別 UID から到達できない状態を成功扱いにしないためエラーを返す。
    fn recover_leftover_dir(fd: OwnedFd) -> Result<OwnedFd, CdiApplyError> {
        let (o, fd) = observe(fd)?;
        if o.mode & S_IFMT == S_IFDIR && o.uid == sys::geteuid() && o.mode & 0o7777 == 0o700 {
            std::fs::set_permissions(proc_fd_path(&fd), std::fs::Permissions::from_mode(0o755))
                .map_err(|e| io_err(&e, "failed to set the /dev subdirectory mode"))?;
        }
        Ok(fd)
    }

    fn proc_fd_path(fd: &OwnedFd) -> String {
        format!("/proc/self/fd/{}", fd.as_raw_fd())
    }

    fn matches_exact(o: &Observed, n: &ResolvedDeviceNode, dev: u64) -> bool {
        o.mode & S_IFMT == type_bits(n.kind)
            && o.rdev == dev
            && o.mode & 0o7777 == n.mode
            && n.uid.is_none_or(|u| u == o.uid)
            && n.gid.is_none_or(|g| g == o.gid)
    }

    fn create_one(
        dev_root: BorrowedFd<'_>,
        n: &ResolvedDeviceNode,
        created: &mut Created,
    ) -> Result<DeviceNodeOutcome, CdiApplyError> {
        let Some((leaf, dirs)) = n.path.split_last() else {
            return Err(CdiApplyError::new(
                Code::InvalidArgument,
                "empty device node path",
            ));
        };
        let parent = walk_dirs(dev_root, dirs, created)?;
        let name = cstr(leaf)?;
        let dev = if n.kind == DeviceNodeKind::Fifo {
            0
        } else {
            encode_dev(n.major, n.minor)
        };
        // 回収用の親 fd は mknodat の前に確保する（作成後の複製失敗で取り残さない）。
        let rec_parent = clone_fd(parent.as_fd())?;
        let status = match sys::mknod_at(parent.as_fd(), &name, type_bits(n.kind) | n.mode, dev) {
            Ok(()) => {
                // 作成直後に登録する。以降のどの失敗でも rollback が回収できる。
                created.nodes.push(CreatedNode {
                    parent: rec_parent,
                    name: name.clone(),
                    type_bits: type_bits(n.kind),
                    rdev: dev,
                    ident: None,
                });
                DeviceNodeStatus::Created
            }
            Err(SysError::Os(17)) => DeviceNodeStatus::AlreadyPresent,
            Err(e) => return Err(map_sys(e, "mknod failed")),
        };
        let fd = sys::open_path_nofollow_at(parent.as_fd(), &name)
            .map_err(|e| map_sys(e, "failed to reopen the device node"))?;
        let (obs, fd) = observe(fd)?;
        if status == DeviceNodeStatus::Created {
            // 開き直した inode の識別を記録してから検証する（差し替えられても他人の inode は消さない）。
            if let Some(last) = created.nodes.last_mut() {
                last.ident = Some((obs.dev, obs.ino));
            }
            if obs.mode & S_IFMT != type_bits(n.kind) || obs.rdev != dev {
                return Err(precondition(
                    "created node does not match the requested type or rdev",
                ));
            }
            // umask で削られた権限を、検証した fd に対してだけ補正する。
            let p = proc_fd_path(&fd);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(n.mode))
                .map_err(|e| io_err(&e, "failed to set the device node mode"))?;
            if n.uid.is_some() || n.gid.is_some() {
                std::os::unix::fs::chown(&p, n.uid, n.gid)
                    .map_err(|e| io_err(&e, "failed to change the device node owner"))?;
            }
            let (after, _fd) = observe(fd)?;
            if !matches_exact(&after, n, dev) {
                return Err(precondition("created node attributes differ after fixup"));
            }
            return Ok(outcome(n, status, &after));
        }
        if !matches_exact(&obs, n, dev) {
            return Err(precondition(
                "an existing /dev entry differs from the requested device node",
            ));
        }
        Ok(outcome(n, status, &obs))
    }

    fn outcome(
        n: &ResolvedDeviceNode,
        status: DeviceNodeStatus,
        o: &Observed,
    ) -> DeviceNodeOutcome {
        let (ma, mi) = decode_dev(o.rdev);
        DeviceNodeOutcome {
            path: n.path.join("/"),
            kind: n.kind,
            status,
            observed_major: ma,
            observed_minor: mi,
            observed_mode: o.mode & 0o7777,
        }
    }

    /// `dev_root`（コンテナの `/dev` のマウントのルート fd）の下へ、major/minor を保って
    /// デバイスノードを作る（GPU-2・TASK-127.1）。
    ///
    /// 途中ディレクトリは 1 要素ずつ `O_NOFOLLOW` で辿り、symlink は `FailedPrecondition` で拒否する。
    /// 既存の末端は完全一致のときだけ `AlreadyPresent` とし、上書きも削除もしない。失敗時はこの呼び出しが
    /// 作ったノード・ディレクトリを逆順に消す。`mknod` の `EPERM` は `PermissionDenied` で返す。
    /// Linux 限定（他 OS には存在しない）。
    pub fn create_device_nodes(
        dev_root: BorrowedFd<'_>,
        nodes: &[ResolvedDeviceNode],
    ) -> Result<DeviceNodeReport, CdiApplyError> {
        create_device_nodes_with_recorder(dev_root, nodes, &NoopRecorder)
    }

    /// 1 回の作成の計測結果（REPAIR-4）。path・デバイス番号は持たない。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct DeviceNodeCreateSample {
        error_code: Option<Code>,
        latency: Duration,
        requested: usize,
        created: usize,
    }

    impl DeviceNodeCreateSample {
        /// 成功したか。
        pub fn is_success(&self) -> bool {
            self.error_code.is_none()
        }
        /// 失敗時の分類（成功なら `None`）。
        pub fn error_code(&self) -> Option<Code> {
            self.error_code
        }
        /// 所要時間（後始末を含む）。
        pub fn latency(&self) -> Duration {
            self.latency
        }
        /// 要求されたノード数。
        pub fn requested(&self) -> usize {
            self.requested
        }
        /// 新規に作ったノード数（失敗時は回収前に作っていた数）。
        pub fn created(&self) -> usize {
            self.created
        }
    }

    /// [`create_device_nodes_with_recorder`] の計測先。成功・失敗（件数上限超過を含む）の全経路で 1 回呼ぶ。
    pub trait DeviceNodeCreateRecorder {
        /// 1 回の結果を記録する。
        fn record(&self, sample: DeviceNodeCreateSample);
    }

    struct NoopRecorder;

    impl DeviceNodeCreateRecorder for NoopRecorder {
        fn record(&self, _sample: DeviceNodeCreateSample) {}
    }

    /// [`create_device_nodes`] に計測（REPAIR-4）を付けたもの。
    pub fn create_device_nodes_with_recorder(
        dev_root: BorrowedFd<'_>,
        nodes: &[ResolvedDeviceNode],
        recorder: &dyn DeviceNodeCreateRecorder,
    ) -> Result<DeviceNodeReport, CdiApplyError> {
        let start = Instant::now();
        let mut created_count = 0;
        let result = create_inner(dev_root, nodes, &mut created_count);
        recorder.record(DeviceNodeCreateSample {
            error_code: result.as_ref().err().map(CdiApplyError::code),
            latency: start.elapsed(),
            requested: nodes.len(),
            created: created_count,
        });
        result
    }

    fn create_inner(
        dev_root: BorrowedFd<'_>,
        nodes: &[ResolvedDeviceNode],
        created_count: &mut usize,
    ) -> Result<DeviceNodeReport, CdiApplyError> {
        // 公開入口でも件数を先に検証する（確保・作成の前。無制限確保の防止）。
        if nodes.len() > super::CDI_APPLY_MAX_DEVICE_NODES {
            return Err(CdiApplyError::new(
                Code::ResourceExhausted,
                "too many device nodes",
            ));
        }
        let mut created = Created::default();
        let mut report = DeviceNodeReport::default();
        for n in nodes {
            match create_one(dev_root, n, &mut created) {
                Ok(o) => {
                    if o.status == DeviceNodeStatus::Created {
                        *created_count += 1;
                    }
                    report.outcomes.push(o);
                }
                Err(e) => {
                    *created_count = created.nodes.len();
                    created.rollback();
                    return Err(e);
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<&'static str, HostStat>);
    impl HostDeviceLookup for Fake {
        fn lstat(&self, path: &str) -> Result<HostStat, Code> {
            self.0.get(path).copied().ok_or(Code::NotFound)
        }
    }

    fn node(path: &str) -> DeviceNode {
        DeviceNode {
            path: path.to_owned(),
            host_path: None,
            r#type: None,
            major: None,
            minor: None,
            file_mode: None,
            permissions: None,
            uid: None,
            gid: None,
        }
    }

    fn host(kind: HostKind, major: u32, minor: u32, mode: u32) -> HostStat {
        HostStat {
            kind,
            rdev: encode_dev(major, minor),
            mode,
        }
    }

    fn one(n: DeviceNode, f: &Fake) -> Result<ResolvedDeviceNode, CdiApplyError> {
        resolve_device_nodes_with(&[n], f).map(|mut v| v.remove(0))
    }

    /// GPU-2: dev_t の符号化は glibc と同じ配置で、往復する。
    #[test]
    fn encode_decode_dev_concrete_values() {
        assert_eq!(encode_dev(1, 3), 0x103);
        assert_eq!(encode_dev(195, 255), 0xc3ff);
        assert_eq!(decode_dev(0x103), (1, 3));
        assert_eq!(decode_dev(encode_dev(0xfff, 0xfffff)), (0xfff, 0xfffff));
        assert_eq!(encode_dev(0, 0), 0);
    }

    /// GPU-2: 範囲外は切り詰めずに拒否する。
    #[test]
    fn out_of_range_numbers_are_rejected() {
        let f = Fake(HashMap::new());
        for (ma, mi) in [(-1, 0), (0x1000, 0), (1, -1), (1, 0x100000)] {
            let mut n = node("/dev/x");
            n.r#type = Some("c".into());
            n.major = Some(ma);
            n.minor = Some(mi);
            assert_eq!(
                one(n, &f).unwrap_err().code(),
                Code::InvalidArgument,
                "{ma}:{mi}"
            );
        }
    }

    /// GPU-2: path だけの指定はホストの type・major・minor・mode で補う。
    #[test]
    fn path_only_is_filled_from_host() {
        let f = Fake(HashMap::from([(
            "/dev/nvidiactl",
            host(HostKind::Char, 195, 255, 0o020_666),
        )]));
        let r = one(node("/dev/nvidiactl"), &f).unwrap();
        assert_eq!(
            (r.kind(), r.major(), r.minor(), r.mode()),
            (DeviceNodeKind::Char, 195, 255, 0o666)
        );
        assert_eq!(r.dev_relative_path(), ["nvidiactl"]);
    }

    /// GPU-2: minimal 指定はホストの lstat が失敗しても通り、host があれば mode だけ補う。
    #[test]
    fn minimal_spec_passes_without_host() {
        let mut n = node("/dev/nvidia0");
        n.r#type = Some("c".into());
        n.major = Some(195);
        n.minor = Some(0);
        let r = one(n.clone(), &Fake(HashMap::new())).unwrap();
        assert_eq!((r.major(), r.minor(), r.mode()), (195, 0, 0o666));
        let f = Fake(HashMap::from([(
            "/dev/nvidia0",
            host(HostKind::Char, 9, 9, 0o020_660),
        )]));
        let r = one(n, &f).unwrap();
        assert_eq!((r.major(), r.minor(), r.mode()), (195, 0, 0o660));
    }

    /// GPU-2: 完全指定でも mode をホストから補う場合は種別を検証し、非デバイス（symlink 等）を拒否する。
    /// fileMode を明示すればホストの mode は使わない。
    #[test]
    fn minimal_spec_rejects_non_device_host_when_mode_is_borrowed() {
        let f = Fake(HashMap::from([(
            "/dev/nvidia0",
            host(HostKind::Other, 0, 0, 0o120_777),
        )]));
        let mut n = node("/dev/nvidia0");
        n.r#type = Some("c".into());
        n.major = Some(195);
        n.minor = Some(0);
        assert_eq!(
            one(n.clone(), &f).unwrap_err().code(),
            Code::InvalidArgument
        );
        n.file_mode = Some(0o600);
        assert_eq!(one(n, &f).unwrap().mode(), 0o600);
    }

    /// GPU-2: type の食い違い・デバイスでないホストは拒否する。
    #[test]
    fn type_mismatch_and_non_device_are_rejected() {
        let f = Fake(HashMap::from([
            ("/dev/a", host(HostKind::Char, 1, 3, 0o666)),
            ("/dev/f", host(HostKind::Other, 0, 0, 0o644)),
        ]));
        let mut n = node("/dev/a");
        n.r#type = Some("b".into());
        n.major = Some(0);
        assert_eq!(one(n, &f).unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(
            one(node("/dev/f"), &f).unwrap_err().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            one(node("/dev/missing"), &f).unwrap_err().code(),
            Code::NotFound
        );
    }

    /// GPU-2: major == 0 のときは major と minor の両方をホストの値で置き換える。FIFO は補わない。
    #[test]
    fn zero_major_takes_host_numbers_and_fifo_stays_zero() {
        let f = Fake(HashMap::from([
            ("/dev/n", host(HostKind::Char, 1, 3, 0o666)),
            ("/dev/q", host(HostKind::Fifo, 0, 0, 0o600)),
        ]));
        let mut n = node("/dev/n");
        n.r#type = Some("c".into());
        n.major = Some(0);
        n.minor = Some(7);
        let r = one(n, &f).unwrap();
        assert_eq!((r.major(), r.minor()), (1, 3));
        let r = one(node("/dev/q"), &f).unwrap();
        assert_eq!(
            (r.kind(), r.major(), r.minor(), r.mode()),
            (DeviceNodeKind::Fifo, 0, 0, 0o600)
        );
    }

    /// GPU-2: path の検証。
    #[test]
    fn bad_paths_are_rejected() {
        let f = Fake(HashMap::new());
        let long = format!("/dev/{}", "a".repeat(256));
        let deep = format!("/dev/{}", vec!["d"; 17].join("/"));
        for p in [
            "/etc/passwd",
            "/dev",
            "/dev/",
            "/dev//x",
            "/dev/./x",
            "/dev/../x",
            "/dev/x\0y",
            "dev/x",
            long.as_str(),
            deep.as_str(),
        ] {
            let mut n = node(p);
            n.r#type = Some("p".into());
            assert!(one(n, &f).is_err(), "{p:?}");
        }
        let toolong = format!("/dev/{}", "a/".repeat(2100));
        assert_eq!(
            parse_dev_path(&toolong).unwrap_err().code(),
            Code::ResourceExhausted
        );
    }

    /// GPU-2: 件数の上限。
    #[test]
    fn too_many_nodes_are_rejected() {
        let nodes: Vec<DeviceNode> = (0..=CDI_APPLY_MAX_DEVICE_NODES)
            .map(|_| node("/dev/x"))
            .collect();
        assert_eq!(
            resolve_device_nodes_with(&nodes, &Fake(HashMap::new()))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    }

    /// GPU-2: mode の検証と既定。
    #[test]
    fn mode_is_limited_and_defaulted() {
        let f = Fake(HashMap::new());
        let mut n = node("/dev/p");
        n.r#type = Some("p".into());
        assert_eq!(one(n.clone(), &f).unwrap().mode(), 0o666);
        for m in [0o4755, 0o1777, 0o2000, 0o1_000_000] {
            n.file_mode = Some(m);
            assert_eq!(
                one(n.clone(), &f).unwrap_err().code(),
                Code::InvalidArgument
            );
        }
        n.file_mode = Some(0o660);
        assert_eq!(one(n, &f).unwrap().mode(), 0o660);
    }

    /// GPU-2: 不明な type と hostPath の形。
    #[test]
    fn unknown_type_and_bad_host_path() {
        let f = Fake(HashMap::new());
        let mut n = node("/dev/x");
        n.r#type = Some("z".into());
        assert_eq!(one(n, &f).unwrap_err().code(), Code::InvalidArgument);
        let mut n = node("/dev/x");
        n.host_path = Some("relative".into());
        assert_eq!(one(n, &f).unwrap_err().code(), Code::InvalidArgument);
    }

    /// GPU-2: minor 省略は完全指定とみなさず、ホストの minor で補う（major が一致するとき）。
    #[test]
    fn omitted_minor_is_filled_from_host() {
        let f = Fake(HashMap::from([(
            "/dev/nvidia0",
            host(HostKind::Char, 195, 7, 0o020_660),
        )]));
        let mut n = node("/dev/nvidia0");
        n.r#type = Some("c".into());
        n.major = Some(195);
        let r = one(n.clone(), &f).unwrap();
        assert_eq!((r.major(), r.minor(), r.mode()), (195, 7, 0o660));
        // major が食い違うホストは拒否し、ホストが無ければ補完できず拒否する。
        n.major = Some(10);
        assert_eq!(
            one(n.clone(), &f).unwrap_err().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            one(n, &Fake(HashMap::new())).unwrap_err().code(),
            Code::NotFound
        );
    }

    /// GPU-2・REPAIR-3: 作成直後の観測失敗（EMFILE 相当）でも作ったノードと親ディレクトリを回収する。
    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_after_observe_failure_removes_created_node_and_dir() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::FileTypeExt as _;
        let d = std::env::temp_dir().join(format!("fc-gpu-ut-obs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::File::open(&d).unwrap();
        let mut n = node("/dev/sub/q");
        n.r#type = Some("p".into());
        let resolved = resolve_device_nodes_with(&[n], &Fake(HashMap::new())).unwrap();
        // 観測の 2 回目（0 回目は中間ディレクトリの観測。ここはノード作成直後の観測）を失敗させる。
        linux::FAIL_OBSERVE_AT.with(|c| c.set(Some(1)));
        let e = create_device_nodes(root.as_fd(), &resolved).unwrap_err();
        linux::FAIL_OBSERVE_AT.with(|c| c.set(None));
        assert_eq!(e.code(), Code::ResourceExhausted);
        assert_eq!(e.errno(), Some(24));
        assert!(!d.join("sub").exists(), "dir must be rolled back");
        // 再試行は FailedPrecondition にならず成功する。
        let rep = create_device_nodes(root.as_fd(), &resolved).unwrap();
        assert_eq!(rep.outcomes.len(), 1);
        assert!(
            std::fs::symlink_metadata(d.join("sub/q"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GPU-1・SEC-1: uid / gid の `u32::MAX`（chown の -1）を lookup より前に拒否する。
    #[test]
    fn uid_gid_u32_max_is_rejected() {
        let empty = Fake(HashMap::new());
        let mut n = node("/dev/null");
        n.uid = Some(u32::MAX);
        assert_eq!(one(n, &empty).unwrap_err().code(), Code::InvalidArgument);
        let mut n = node("/dev/null");
        n.gid = Some(u32::MAX);
        assert_eq!(one(n, &empty).unwrap_err().code(), Code::InvalidArgument);
        for (u, g) in [(u32::MAX - 1, u32::MAX - 1), (0, 0)] {
            let mut n = node("/dev/null");
            n.uid = Some(u);
            n.gid = Some(g);
            n.r#type = Some("c".into());
            n.major = Some(1);
            n.minor = Some(3);
            let r = one(n, &empty).unwrap();
            assert_eq!((r.uid(), r.gid()), (Some(u), Some(g)));
        }
    }

    /// GPU-2・SEC-1: 差し替えられたディレクトリは消さず、差し替えが無ければ消す（陽性対照）。
    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_skips_replaced_empty_dir() {
        use linux::{Created, CreatedDir};
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::MetadataExt as _;
        for replace in [false, true] {
            let d = std::env::temp_dir()
                .join(format!("fc-gpu-ut-repl-{}-{replace}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(d.join("sub")).unwrap();
            let md = std::fs::metadata(d.join("sub")).unwrap();
            let parent = OwnedFd::from(std::fs::File::open(&d).unwrap());
            let created = Created {
                dirs: vec![CreatedDir {
                    parent,
                    name: std::ffi::CString::new("sub").unwrap(),
                    ident: Some((md.dev(), md.ino())),
                }],
                nodes: vec![],
            };
            if replace {
                // 元の inode は生かしたまま（番号の再利用を避ける）別の空ディレクトリに差し替える。
                std::fs::rename(d.join("sub"), d.join("sub.orig")).unwrap();
                std::fs::create_dir(d.join("sub")).unwrap();
            }
            created.rollback();
            if replace {
                assert!(d.join("sub").is_dir(), "replaced dir must be left");
                assert_ne!(std::fs::metadata(d.join("sub")).unwrap().ino(), md.ino());
            } else {
                assert!(!d.join("sub").exists(), "same dir must be removed");
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// GPU-2・SEC-1: 作成直後の観測に失敗して識別できないディレクトリは消さず、再試行は成功する。
    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_leaves_dir_with_unknown_identity() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
        let d = std::env::temp_dir().join(format!("fc-gpu-ut-unk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::File::open(&d).unwrap();
        let mut n = node("/dev/sub/q");
        n.r#type = Some("p".into());
        let resolved = resolve_device_nodes_with(&[n], &Fake(HashMap::new())).unwrap();
        // 最初の観測と再観測の両方を失敗させる。
        linux::FAIL_OBSERVE_EXTRA.with(|c| c.set(1));
        linux::FAIL_OBSERVE_AT.with(|c| c.set(Some(0)));
        let e = create_device_nodes(root.as_fd(), &resolved).unwrap_err();
        linux::FAIL_OBSERVE_AT.with(|c| c.set(None));
        linux::FAIL_OBSERVE_EXTRA.with(|c| c.set(0));
        assert_eq!(e.code(), Code::ResourceExhausted);
        assert_eq!(e.errno(), Some(24));
        assert!(d.join("sub").is_dir(), "unidentified dir must be left");
        assert_eq!(std::fs::read_dir(d.join("sub")).unwrap().count(), 0);
        // 0700 のまま識別なしで残った状況を再現し、再試行が 0755 へ回復することを確かめる。
        std::fs::set_permissions(d.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
        create_device_nodes(root.as_fd(), &resolved).unwrap();
        assert_eq!(
            std::fs::metadata(d.join("sub"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert!(
            std::fs::symlink_metadata(d.join("sub/q"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GPU-2: umask 077 でも、この呼び出しが作った中間ディレクトリは 0755 に補正される。
    #[cfg(target_os = "linux")]
    #[test]
    fn intermediate_dirs_are_0755_under_restrictive_umask() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        // プロセス全体の umask を試験内で変えない（unsafe 回避）。umask 077 の子プロセスで自身を再実行する。
        if std::env::var_os("FC_GPU_UMASK_CHILD").is_none() {
            let exe = std::env::current_exe().unwrap();
            let mut child = std::process::Command::new("sh")
                .arg("-c")
                .arg("umask 077; exec \"$0\" --exact cdi_apply::device_nodes::tests::intermediate_dirs_are_0755_under_restrictive_umask")
                .arg(exe)
                .env("FC_GPU_UMASK_CHILD", "1")
                .spawn()
                .unwrap();
            // REPAIR-5: 子が停止しても無期限に待たない。期限超過で kill し、回収にも上限を設ける。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            let st = loop {
                if let Some(st) = child.try_wait().unwrap() {
                    break st;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let reap_deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(5);
                    while child.try_wait().unwrap().is_none()
                        && std::time::Instant::now() < reap_deadline
                    {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    panic!("umask child did not finish within 60s");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            };
            assert!(st.success());
            return;
        }
        let d = std::env::temp_dir().join(format!("fc-gpu-ut-umask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::File::open(&d).unwrap();
        let mut n = node("/dev/dri/q1");
        n.r#type = Some("p".into());
        let resolved = resolve_device_nodes_with(&[n], &Fake(HashMap::new())).unwrap();
        // 中間ディレクトリの最初の観測を失敗させても、再観測で 0755 に補正される（#2982）。
        linux::FAIL_OBSERVE_AT.with(|c| c.set(Some(0)));
        create_device_nodes(root.as_fd(), &resolved).unwrap();
        linux::FAIL_OBSERVE_AT.with(|c| c.set(None));
        let mode = std::fs::metadata(d.join("dri"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GPU-2・REPAIR-5: 公開の作成入口も件数上限を作成前に検証する。
    #[cfg(target_os = "linux")]
    #[test]
    fn create_rejects_too_many_nodes_before_touching_dev() {
        use std::os::fd::AsFd as _;
        let d = std::env::temp_dir().join(format!("fc-gpu-ut-max-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::File::open(&d).unwrap();
        let mut n = node("/dev/q0");
        n.r#type = Some("p".into());
        let one = resolve_device_nodes_with(&[n], &Fake(HashMap::new())).unwrap();
        let many = vec![one[0].clone(); CDI_APPLY_MAX_DEVICE_NODES + 1];
        let e = create_device_nodes(root.as_fd(), &many).unwrap_err();
        assert_eq!(e.code(), Code::ResourceExhausted);
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GPU-2・REPAIR-4: 成功と失敗の両経路で結果と所要時間を 1 回ずつ記録する。
    #[cfg(target_os = "linux")]
    #[test]
    fn recorder_sees_success_and_failure() {
        use std::cell::RefCell;
        use std::os::fd::AsFd as _;
        struct Rec(RefCell<Vec<linux::DeviceNodeCreateSample>>);
        impl linux::DeviceNodeCreateRecorder for Rec {
            fn record(&self, s: linux::DeviceNodeCreateSample) {
                self.0.borrow_mut().push(s);
            }
        }
        let d = std::env::temp_dir().join(format!("fc-gpu-ut-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::File::open(&d).unwrap();
        let mut n = node("/dev/q1");
        n.r#type = Some("p".into());
        let resolved = resolve_device_nodes_with(&[n], &Fake(HashMap::new())).unwrap();
        let rec = Rec(RefCell::new(Vec::new()));
        linux::create_device_nodes_with_recorder(root.as_fd(), &resolved, &rec).unwrap();
        let many = vec![resolved[0].clone(); CDI_APPLY_MAX_DEVICE_NODES + 1];
        linux::create_device_nodes_with_recorder(root.as_fd(), &many, &rec).unwrap_err();
        let v = rec.0.borrow();
        assert_eq!(v.len(), 2);
        assert!(v[0].is_success());
        assert_eq!((v[0].requested(), v[0].created()), (1, 1));
        assert_eq!(v[1].error_code(), Some(Code::ResourceExhausted));
        assert_eq!(v[1].requested(), CDI_APPLY_MAX_DEVICE_NODES + 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// GPU-2 受け入れ条件 1 の純粋版: 本物の lookup で /dev/null を補完し、rdev がホストと一致する。ノードは作らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn real_dev_null_resolves_to_char_1_3() {
        use std::os::unix::fs::MetadataExt as _;
        let r = resolve_device_nodes(&[node("/dev/null")])
            .unwrap()
            .remove(0);
        assert_eq!(
            (r.kind(), r.major(), r.minor()),
            (DeviceNodeKind::Char, 1, 3)
        );
        let rdev = std::fs::symlink_metadata("/dev/null").unwrap().rdev();
        assert_eq!(encode_dev(r.major(), r.minor()), rdev);
    }
}
