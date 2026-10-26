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
#[cfg_attr(not(unix), allow(dead_code))]
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
                let (hma, hmi) = decode_dev(h.rdev);
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
pub use linux::{DeviceNodeOutcome, DeviceNodeReport, DeviceNodeStatus, create_device_nodes};

#[cfg(target_os = "linux")]
mod linux {
    use super::{DeviceNodeKind, ResolvedDeviceNode, decode_dev, encode_dev};
    use crate::cdi_apply::{CdiApplyError, CdiApplyErrorCode as Code};
    use crate::sys::{self, SysError, consts};
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

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

    /// 観測した inode の属性（O_PATH の fd を `File` にして `statx` で読む）。
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
    }

    fn observe(fd: &OwnedFd) -> Result<Observed, CdiApplyError> {
        #[cfg(test)]
        {
            let hit = FAIL_OBSERVE_AT.with(|c| match c.get() {
                Some(0) => {
                    c.set(None);
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
        let f = File::from(clone_fd(fd.as_fd())?);
        let md = f
            .metadata()
            .map_err(|e| io_err(&e, "failed to stat the created node"))?;
        Ok(Observed {
            mode: md.mode(),
            rdev: md.rdev(),
            uid: md.uid(),
            gid: md.gid(),
            dev: md.dev(),
            ino: md.ino(),
        })
    }

    fn type_bits(kind: DeviceNodeKind) -> u32 {
        match kind {
            DeviceNodeKind::Char => consts::S_IFCHR,
            DeviceNodeKind::Block => consts::S_IFBLK,
            DeviceNodeKind::Fifo => consts::S_IFIFO,
        }
    }

    const S_IFMT: u32 = 0o170_000;

    /// この呼び出しが作ったものの記録（失敗時の逆順の後始末用）。
    #[derive(Default)]
    struct Created {
        dirs: Vec<(OwnedFd, CString)>,
        nodes: Vec<CreatedNode>,
    }

    /// 作成したノード 1 件。`mknodat` の直前に親 fd を複製しておき、成功した直後に登録する
    /// （再オープン・観測・複製の失敗でも回収できるようにする。特権操作の後始末）。
    struct CreatedNode {
        parent: OwnedFd,
        name: CString,
        /// 作成した種別ビット（`S_IFCHR` 等）と rdev。識別が未確定の間の照合に使う。
        type_bits: u32,
        rdev: u64,
        /// 再オープンして観測できた後に埋める `(dev, ino)`。
        ident: Option<(u64, u64)>,
    }

    impl Created {
        /// 最善努力の後始末。失敗しても元のエラーを優先するため結果は捨てる。
        fn rollback(self) {
            for n in self.nodes.into_iter().rev() {
                // 識別が未確定でも、種別と rdev が作ったものと一致する場合だけ消す。
                let same = sys::open_path_nofollow_at(n.parent.as_fd(), &n.name)
                    .ok()
                    .and_then(|fd| observe(&fd).ok())
                    .is_some_and(|o| {
                        o.mode & S_IFMT == n.type_bits
                            && o.rdev == n.rdev
                            && n.ident.is_none_or(|(d, i)| o.dev == d && o.ino == i)
                    });
                if same {
                    let _ = sys::unlink_at(n.parent.as_fd(), &n.name, false);
                }
            }
            for (parent, name) in self.dirs.into_iter().rev() {
                let _ = sys::unlink_at(parent.as_fd(), &name, true);
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
                Ok(fd) => fd,
                Err(SysError::Os(2)) => {
                    // 複製は作成の前に済ませる（作成後に失敗して取り残さない）。
                    let rec_parent = clone_fd(cur.as_fd())?;
                    match sys::mkdir_at(cur.as_fd(), &name, 0o755) {
                        Ok(()) => created.dirs.push((rec_parent, name.clone())),
                        Err(SysError::Os(17)) => {}
                        Err(e) => return Err(map_sys(e, "failed to create a /dev subdirectory")),
                    }
                    sys::open_dir_nofollow_at(cur.as_fd(), &name)
                        .map_err(|e| map_sys(e, "failed to open a /dev subdirectory"))?
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
        let obs = observe(&fd)?;
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
            let after = observe(&fd)?;
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
        let mut created = Created::default();
        let mut report = DeviceNodeReport::default();
        for n in nodes {
            match create_one(dev_root, n, &mut created) {
                Ok(o) => report.outcomes.push(o),
                Err(e) => {
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
        // 観測の 1 回目（作成直後の観測）を失敗させる。
        linux::FAIL_OBSERVE_AT.with(|c| c.set(Some(0)));
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
