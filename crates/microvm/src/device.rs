//! `/dev/kvm` のオープンと VM fd の作成（TASK-74.1.1・MVM-1・MVM-4。Linux のみ）。
//!
//! 将来の起動フロー（TASK-75）・`fandhe-container-plugin-microvm`（TASK-117）から呼ばれる入口。
//! [`KvmDevice`] が `/dev/kvm` を `O_RDWR | O_CLOEXEC` で開き、API 版数 12 を確認してから
//! [`KvmDevice::create_vm`] で [`VmFd`] を返し、[`VmFd::create_vcpu`] で [`VcpuFd`] を返す（TASK-74.1.2）。
//! ゲストメモリ（アクセス型は TASK-74.1 配下の後続 sub-issue、mmap と KVM 登録は TASK-75.1。docs/design/microvm-memory-ownership.md）・
//! レジスタ設定・virtio・実行ループ（`KVM_RUN`）は未実装で、後続の TASK-74・TASK-75 が
//! [`VmFd`]・[`VcpuFd`]（いずれも `AsFd`）を使って足す（REPAIR-3）。
//! 失敗は panic せず [`MicrovmError`]（ERR-1）で返す。`unsafe` は `crate::sys` に閉じる。
//!
//! # アーキテクチャ別の vCPU 作成
//! - x86_64: `KVM_CREATE_VCPU` だけで vCPU fd が使える。レジスタ設定は TASK-74.4 / TASK-75
//! - aarch64: `KVM_CREATE_VCPU` の後に VM fd へ `KVM_ARM_PREFERRED_TARGET`、vCPU fd へ `KVM_ARM_VCPU_INIT`
//!   （features はすべて 0）を発行して初期化済みの vCPU を返す。未初期化だと `KVM_RUN` が ENOEXEC で失敗する。
//!   features（PSCI 等）の選択は TASK-75 で再検討する。aarch64 はネイティブ CI が無く型検査のみで実行は未検証
//!
//! aarch64 の machine type（IPA サイズ）は既定の 0 を使う。指定は TASK-75 で再検討する。
//! [`KvmDevice`]・[`VmFd`]・[`VcpuFd`] は `OwnedFd` を持つため `Send` / `Sync`。

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::sys::{self, SysError};

/// 本番で開くデバイスパス（固定リテラル。外部入力は届かない）。
const KVM_PATH: &str = "/dev/kvm";

// errno（Linux 共通。x86_64・aarch64 で同値）。`io::ErrorKind` で分類できないものだけ使う。
const EPERM: i32 = 1;
const ENOMEM: i32 = 12;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const EACCES: i32 = 13;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOTTY: i32 = 25;

/// 開いた `/dev/kvm`。
#[derive(Debug)]
pub struct KvmDevice {
    fd: OwnedFd,
}

/// `KVM_CREATE_VM` で得た VM fd。drop で close される。
#[derive(Debug)]
pub struct VmFd {
    fd: OwnedFd,
}

/// `KVM_CREATE_VCPU` で得た vCPU fd。drop で close される。`KVM_RUN`（TASK-74.4.1）が `AsFd` で借用する。
#[derive(Debug)]
pub struct VcpuFd {
    fd: OwnedFd,
    id: u32,
}

impl VcpuFd {
    /// 作成時に指定した vCPU id。
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl AsFd for VcpuFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// vCPU 作成の段（errno 分類のメッセージ切り替え用）。`PreferredTarget`・`VcpuInit` は aarch64 だけが使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
enum VcpuStage {
    Create,
    PreferredTarget,
    VcpuInit,
}

fn classify_vcpu_error(stage: VcpuStage, e: SysError) -> MicrovmError {
    let name = match stage {
        VcpuStage::Create => "KVM_CREATE_VCPU",
        VcpuStage::PreferredTarget => "KVM_ARM_PREFERRED_TARGET",
        VcpuStage::VcpuInit => "KVM_ARM_VCPU_INIT",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(EINVAL) if stage == VcpuStage::Create => {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "invalid vCPU id")
        }
        SysError::Os(EEXIST) => {
            MicrovmError::new(MicrovmErrorCode::AlreadyExists, "vCPU id already exists")
        }
        SysError::Os(ENOTTY) => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating vCPU",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating vCPU (os error {n})"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

impl VmFd {
    /// `KVM_CREATE_VCPU` で vCPU を作る（aarch64 は続けて初期化する。モジュール doc 参照）。
    /// id の上限は検証せずカーネルの EINVAL（`InvalidArgument`）に任せる。重複は `AlreadyExists`。
    /// 初期化に失敗したときは作成済みの fd を drop で close する。
    pub fn create_vcpu(&self, id: u32) -> Result<VcpuFd, MicrovmError> {
        let fd = sys::kvm_create_vcpu(self.fd.as_fd(), u64::from(id))
            .map_err(|e| classify_vcpu_error(VcpuStage::Create, e))?;
        #[cfg(target_arch = "aarch64")]
        {
            let init = sys::kvm_arm_preferred_target(self.fd.as_fd())
                .map_err(|e| classify_vcpu_error(VcpuStage::PreferredTarget, e))?;
            sys::kvm_arm_vcpu_init(fd.as_fd(), &init)
                .map_err(|e| classify_vcpu_error(VcpuStage::VcpuInit, e))?;
        }
        Ok(VcpuFd { fd, id })
    }
}

impl AsFd for VmFd {
    /// `KVM_CREATE_VCPU` が借用する。
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn classify_open_error(e: &io::Error) -> MicrovmError {
    match e.kind() {
        io::ErrorKind::NotFound => {
            MicrovmError::new(MicrovmErrorCode::NotFound, "KVM device not found")
        }
        io::ErrorKind::PermissionDenied => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied opening KVM device",
        ),
        _ => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!(
                "failed to open KVM device (os error {})",
                e.raw_os_error().unwrap_or(0)
            ),
        ),
    }
}

fn classify_create_vm_error(e: SysError) -> MicrovmError {
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating VM",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating VM (os error {n})"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("KVM_CREATE_VM failed (os error {n})"),
        ),
    }
}

impl KvmDevice {
    /// `/dev/kvm` を開き、KVM API 版数が 12 であることを確かめる。
    pub fn open() -> Result<KvmDevice, MicrovmError> {
        Self::open_at(Path::new(KVM_PATH))
    }

    /// 任意のパスを KVM デバイスとして開く（試験・将来の差し替え用）。エラーの `message` にパスは載せない。
    pub fn open_at(path: &Path) -> Result<KvmDevice, MicrovmError> {
        // std は Linux で O_CLOEXEC を付ける。KVM は O_RDWR が必要。
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| classify_open_error(&e))?;
        let dev = KvmDevice {
            fd: OwnedFd::from(file),
        };
        let v = dev.api_version()?;
        if v != sys::consts::KVM_API_VERSION {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!(
                    "unsupported KVM API version {v} (expected {})",
                    sys::consts::KVM_API_VERSION
                ),
            ));
        }
        Ok(dev)
    }

    /// `KVM_GET_API_VERSION` の値。KVM デバイスでない fd（ENOTTY 等）は `FailedPrecondition`。
    pub fn api_version(&self) -> Result<i32, MicrovmError> {
        sys::kvm_get_api_version(self.fd.as_fd()).map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(_) => {
                MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM device")
            }
        })
    }

    /// `KVM_CREATE_VM`（machine type 0）で VM fd を作る。
    pub fn create_vm(&self) -> Result<VmFd, MicrovmError> {
        sys::kvm_create_vm(self.fd.as_fd(), 0)
            .map(|fd| VmFd { fd })
            .map_err(classify_create_vm_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_missing_path_is_not_found() {
        let p = std::env::temp_dir().join(format!(
            "fandhe-microvm-missing-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let e = KvmDevice::open_at(&p).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::NotFound);
        assert_eq!(e.message(), "KVM device not found");
    }

    /// MVM-1: KVM でないデバイスは ioctl が ENOTTY で失敗し FailedPrecondition（unsafe 経路を KVM 無しで通す）。
    #[test]
    fn open_dev_null_is_failed_precondition() {
        let e = KvmDevice::open_at(Path::new("/dev/null")).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM device");
    }

    #[test]
    fn classify_open_error_table() {
        let c = |e: io::Error| classify_open_error(&e).code();
        assert_eq!(
            c(io::Error::from(io::ErrorKind::NotFound)),
            MicrovmErrorCode::NotFound
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EACCES)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EPERM)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(5)),
            MicrovmErrorCode::Internal
        );
        let m = classify_open_error(&io::Error::from_raw_os_error(5));
        assert_eq!(m.message(), "failed to open KVM device (os error 5)");
    }

    #[test]
    fn classify_create_vm_error_table() {
        let c = |e| classify_create_vm_error(e).code();
        assert_eq!(c(SysError::Os(EACCES)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(EPERM)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(ENOMEM)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(EMFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(ENFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Unsupported), MicrovmErrorCode::Unimplemented);
        let m = classify_create_vm_error(SysError::Os(22));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_CREATE_VM failed (os error 22)");
    }

    /// 権限なしファイルは非 root で PermissionDenied。root では対照も成功するので期待値を対照に合わせる。
    #[test]
    fn open_unreadable_file_matches_std_behavior() {
        use std::os::unix::fs::PermissionsExt as _;
        let p = std::env::temp_dir().join(format!("fandhe-microvm-perm-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let std_denied = OpenOptions::new().read(true).write(true).open(&p).is_err();
        let r = KvmDevice::open_at(&p);
        std::fs::remove_file(&p).unwrap();
        let e = r.unwrap_err();
        if std_denied {
            assert_eq!(e.code(), MicrovmErrorCode::PermissionDenied);
        } else {
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        }
    }

    /// MVM-1: KVM の VM fd でない fd への `KVM_CREATE_VCPU` は ENOTTY で FailedPrecondition（KVM 無しで unsafe 経路を通す）。
    #[test]
    fn create_vcpu_on_non_vm_fd_is_failed_precondition() {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let vm = VmFd {
            fd: OwnedFd::from(f),
        };
        let e = vm.create_vcpu(0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM VM fd");
    }

    #[test]
    fn classify_vcpu_error_table() {
        let c = classify_vcpu_error;
        let m = c(VcpuStage::Create, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(m.message(), "invalid vCPU id");
        let m = c(VcpuStage::Create, SysError::Os(EEXIST));
        assert_eq!(m.code(), MicrovmErrorCode::AlreadyExists);
        assert_eq!(m.message(), "vCPU id already exists");
        let m = c(VcpuStage::VcpuInit, SysError::Os(ENOTTY));
        assert_eq!(m.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(m.message(), "not a KVM VM fd");
        for n in [EACCES, EPERM] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::PermissionDenied);
        }
        for n in [ENOMEM, EMFILE, ENFILE] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::ResourceExhausted);
        }
        let m = c(VcpuStage::Create, SysError::Unsupported);
        assert_eq!(m.code(), MicrovmErrorCode::Unimplemented);
        // aarch64 の初期化段の EINVAL は id の誤りではなく Internal。
        let m = c(VcpuStage::PreferredTarget, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_ARM_PREFERRED_TARGET failed (os error 22)");
        let m = c(VcpuStage::VcpuInit, SysError::Os(5));
        assert_eq!(m.message(), "KVM_ARM_VCPU_INIT failed (os error 5)");
        let m = c(VcpuStage::Create, SysError::Os(5));
        assert_eq!(m.message(), "KVM_CREATE_VCPU failed (os error 5)");
    }
}
