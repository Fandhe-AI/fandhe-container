//! VM 設定（`VZVirtualMachineConfiguration` 相当）の検証型と構築関数（MAC-1・TASK-64.2）。
//!
//! 構成は 2 層に分かれる。
//! - OS 非依存層（全 OS でビルド・3 OS CI でテスト）: カーネル / initrd パス・コマンドライン・CPU 数・
//!   メモリ量を「壊れた値を表現できない」検証済み型にし、[`VmConfigSpec`] にまとめる。不正値は
//!   panic ではなく [`ConfigError`] で返す。
//! - macOS 限定層: [`VmConfigSpec`] から Virtualization.framework の設定オブジェクトを組み立てる
//!   [`build_vz_configuration`]。FFI は `sys` モジュールに閉じ込める。
//!
//! 呼び出し文脈: TASK-64.3（デバイス構成）が本設定へストレージ・シリアル等を足し、TASK-64.4 が
//! `VZVirtualMachine` を生成して起動する。[`ConfigError`] は TASK-64.5 で `VmError` に包む予定
//! （REPAIR-3: 現時点では未統合）。検証後〜起動までの TOCTOU（ファイル差し替え）は残るため、
//! 起動時の読み込み失敗は TASK-64.4/64.5 のエラー経路で扱う。

use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// カーネルコマンドラインの最大バイト数（Linux の `COMMAND_LINE_SIZE` 相当。無制限確保の防止）。
pub const MAX_COMMAND_LINE_BYTES: usize = 2048;

/// メモリ量の刻み（VZ は 1 MiB の倍数を要求する）。
pub const MEMORY_ALIGNMENT_BYTES: u64 = 1024 * 1024;

/// 既定の CPU 数（最小構成のゲスト起動に十分で常駐消費を抑える。CORE-7 方針）。
pub const DEFAULT_CPU_COUNT: u32 = 2;

/// 既定のメモリ量（1 GiB。同上）。
pub const DEFAULT_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;

/// エラーの対象となった入力フィールド。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigField {
    /// Linux カーネルイメージ。
    Kernel,
    /// 初期 RAM ディスク。
    Initrd,
}

impl ConfigField {
    fn as_str(self) -> &'static str {
        match self {
            ConfigField::Kernel => "kernel",
            ConfigField::Initrd => "initrd",
        }
    }
}

/// VM 設定の検証・構築エラー。`code()` は機械可読、`message()` は英語の人間向け文（ERR 系・REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// パスが絶対パスでない。
    PathNotAbsolute { field: ConfigField, path: PathBuf },
    /// パスが存在しない。
    PathNotFound { field: ConfigField, path: PathBuf },
    /// パスが通常ファイルでない（ディレクトリ・デバイス等）。
    NotAFile { field: ConfigField, path: PathBuf },
    /// パスが UTF-8 でない、または NUL を含む。
    PathInvalidEncoding { field: ConfigField },
    /// パスのメタデータ取得に失敗した（存在しない以外）。
    PathIo {
        field: ConfigField,
        kind: std::io::ErrorKind,
    },
    /// コマンドラインが上限を超えた。
    CommandLineTooLong { len: usize, max: usize },
    /// コマンドラインに許可外の文字がある（`index` はバイト位置）。
    CommandLineInvalidChar { index: usize },
    /// CPU 数が 0。
    InvalidCpuCount,
    /// メモリ量が 0 または 1 MiB の倍数でない。
    InvalidMemorySize { bytes: u64 },
    /// CPU 数が VZ の許容範囲外。
    CpuCountOutOfRange { requested: u32, min: u64, max: u64 },
    /// メモリ量が VZ の許容範囲外。
    MemorySizeOutOfRange { requested: u64, min: u64, max: u64 },
    /// パスから `NSURL` への変換に失敗した。
    UrlConversion { field: ConfigField },
}

impl ConfigError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::PathNotAbsolute { .. } => "config.path_not_absolute",
            ConfigError::PathNotFound { .. } => "config.path_not_found",
            ConfigError::NotAFile { .. } => "config.not_a_file",
            ConfigError::PathInvalidEncoding { .. } => "config.path_invalid_encoding",
            ConfigError::PathIo { .. } => "config.path_io",
            ConfigError::CommandLineTooLong { .. } => "config.command_line_too_long",
            ConfigError::CommandLineInvalidChar { .. } => "config.command_line_invalid_char",
            ConfigError::InvalidCpuCount => "config.invalid_cpu_count",
            ConfigError::InvalidMemorySize { .. } => "config.invalid_memory_size",
            ConfigError::CpuCountOutOfRange { .. } => "config.cpu_count_out_of_range",
            ConfigError::MemorySizeOutOfRange { .. } => "config.memory_size_out_of_range",
            ConfigError::UrlConversion { .. } => "config.url_conversion",
        }
    }

    /// 英語の人間向けメッセージ。
    pub fn message(&self) -> String {
        match self {
            ConfigError::PathNotAbsolute { field, path } => {
                format!(
                    "{} path must be absolute: {}",
                    field.as_str(),
                    path.display()
                )
            }
            ConfigError::PathNotFound { field, path } => {
                format!("{} path does not exist: {}", field.as_str(), path.display())
            }
            ConfigError::NotAFile { field, path } => {
                format!(
                    "{} path is not a regular file: {}",
                    field.as_str(),
                    path.display()
                )
            }
            ConfigError::PathInvalidEncoding { field } => {
                format!("{} path must be valid UTF-8 without NUL", field.as_str())
            }
            ConfigError::PathIo { field, kind } => {
                format!("failed to inspect {} path: {kind}", field.as_str())
            }
            ConfigError::CommandLineTooLong { len, max } => {
                format!("kernel command line is {len} bytes, max is {max}")
            }
            ConfigError::CommandLineInvalidChar { index } => {
                format!("kernel command line has a disallowed character at byte {index}")
            }
            ConfigError::InvalidCpuCount => "cpu count must be at least 1".to_string(),
            ConfigError::InvalidMemorySize { bytes } => {
                format!("memory size {bytes} must be a non-zero multiple of 1 MiB")
            }
            ConfigError::CpuCountOutOfRange {
                requested,
                min,
                max,
            } => {
                format!("cpu count {requested} is outside the allowed range {min}..={max}")
            }
            ConfigError::MemorySizeOutOfRange {
                requested,
                min,
                max,
            } => {
                format!("memory size {requested} is outside the allowed range {min}..={max}")
            }
            ConfigError::UrlConversion { field } => {
                format!("failed to convert {} path to a file URL", field.as_str())
            }
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for ConfigError {}

/// 絶対・UTF-8・NUL なし・通常ファイルであることを検証する。
///
/// symlink は追従した先が通常ファイルなら許可する（ホスト側ファイルを同一ユーザーが指定するため）。
/// 非 UTF-8 パスは `NSURL` 変換の決定性のため fail-closed で拒否する。
fn validate_file_path(field: ConfigField, path: &Path) -> Result<PathBuf, ConfigError> {
    match path.to_str() {
        Some(s) if !s.contains('\0') => {}
        _ => return Err(ConfigError::PathInvalidEncoding { field }),
    }
    if !path.is_absolute() {
        return Err(ConfigError::PathNotAbsolute {
            field,
            path: path.to_path_buf(),
        });
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ConfigError::PathNotFound {
                field,
                path: path.to_path_buf(),
            }
        } else {
            ConfigError::PathIo {
                field,
                kind: e.kind(),
            }
        }
    })?;
    if !meta.is_file() {
        return Err(ConfigError::NotAFile {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(path.to_path_buf())
}

/// 検証済みの Linux カーネルイメージパス。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelImagePath(PathBuf);

impl KernelImagePath {
    /// パスを検証して生成する。
    pub fn try_new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        validate_file_path(ConfigField::Kernel, path.as_ref()).map(Self)
    }

    /// 検証済みパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// 検証済みの initrd パス。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitrdPath(PathBuf);

impl InitrdPath {
    /// パスを検証して生成する。
    pub fn try_new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        validate_file_path(ConfigField::Initrd, path.as_ref()).map(Self)
    }

    /// 検証済みパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// 検証済みのカーネルコマンドライン（印字可能 ASCII と空白のみ・上限あり）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCommandLine(String);

impl KernelCommandLine {
    /// 長さを先に検証してから所有化する。NUL・改行・制御文字・非 ASCII は拒否する。
    pub fn try_new(s: &str) -> Result<Self, ConfigError> {
        if s.len() > MAX_COMMAND_LINE_BYTES {
            return Err(ConfigError::CommandLineTooLong {
                len: s.len(),
                max: MAX_COMMAND_LINE_BYTES,
            });
        }
        if let Some((index, _)) = s
            .bytes()
            .enumerate()
            .find(|(_, b)| !(*b == b' ' || b.is_ascii_graphic()))
        {
            return Err(ConfigError::CommandLineInvalidChar { index });
        }
        Ok(Self(s.to_string()))
    }

    /// 文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 検証済みの CPU 数（1 以上）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCount(NonZeroU32);

impl CpuCount {
    /// 0 を拒否して生成する。
    pub fn try_new(n: u32) -> Result<Self, ConfigError> {
        NonZeroU32::new(n)
            .map(Self)
            .ok_or(ConfigError::InvalidCpuCount)
    }

    /// CPU 数。
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl Default for CpuCount {
    fn default() -> Self {
        Self(NonZeroU32::MIN.saturating_add(DEFAULT_CPU_COUNT - 1))
    }
}

/// 検証済みのメモリ量（バイト。非 0 かつ 1 MiB の倍数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySize(u64);

impl MemorySize {
    /// 0 と 1 MiB 非倍数を拒否して生成する。
    pub fn try_new(bytes: u64) -> Result<Self, ConfigError> {
        if bytes == 0 || !bytes.is_multiple_of(MEMORY_ALIGNMENT_BYTES) {
            return Err(ConfigError::InvalidMemorySize { bytes });
        }
        Ok(Self(bytes))
    }

    /// バイト数。
    pub fn bytes(self) -> u64 {
        self.0
    }
}

impl Default for MemorySize {
    fn default() -> Self {
        Self(DEFAULT_MEMORY_BYTES)
    }
}

/// 検証済み値だけで構成される VM 設定仕様。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmConfigSpec {
    /// Linux カーネル。
    pub kernel: KernelImagePath,
    /// 初期 RAM ディスク（任意）。
    pub initrd: Option<InitrdPath>,
    /// カーネルコマンドライン。
    pub cmdline: KernelCommandLine,
    /// CPU 数。
    pub cpus: CpuCount,
    /// メモリ量。
    pub memory: MemorySize,
}

impl VmConfigSpec {
    /// カーネル・initrd・コマンドラインから生成する（CPU・メモリは既定値）。
    pub fn from_parts(
        kernel: &Path,
        initrd: Option<&Path>,
        cmdline: &str,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            kernel: KernelImagePath::try_new(kernel)?,
            initrd: initrd.map(InitrdPath::try_new).transpose()?,
            cmdline: KernelCommandLine::try_new(cmdline)?,
            cpus: CpuCount::default(),
            memory: MemorySize::default(),
        })
    }
}

/// 構築済みの `VZVirtualMachineConfiguration`（不透明型）。TASK-64.3/64.4 が内部を取り出して使う。
#[cfg(target_os = "macos")]
pub struct VzVmConfiguration(
    objc2::rc::Retained<objc2_virtualization::VZVirtualMachineConfiguration>,
);

#[cfg(target_os = "macos")]
impl VzVmConfiguration {
    #[allow(dead_code)] // TASK-64.3/64.4 が利用する。
    pub(crate) fn inner(&self) -> &objc2_virtualization::VZVirtualMachineConfiguration {
        &self.0
    }

    /// 設定済みの CPU 数（診断用）。
    pub fn cpu_count(&self) -> usize {
        crate::sys::cpu_count(&self.0)
    }

    /// 設定済みのメモリ量（バイト。診断用）。
    pub fn memory_size(&self) -> u64 {
        crate::sys::memory_size(&self.0)
    }

    /// 設定済みのカーネルパス（診断用）。
    pub fn kernel_path(&self) -> Option<PathBuf> {
        crate::sys::read_back_boot(&self.0).and_then(|b| b.kernel)
    }

    /// 設定済みの initrd パス（診断用）。
    pub fn initrd_path(&self) -> Option<PathBuf> {
        crate::sys::read_back_boot(&self.0).and_then(|b| b.initrd)
    }

    /// 設定済みのコマンドライン（診断用）。
    pub fn command_line(&self) -> Option<String> {
        crate::sys::read_back_boot(&self.0).map(|b| b.command_line)
    }
}

/// [`VmConfigSpec`] から `VZVirtualMachineConfiguration` を構築する（MAC-1・TASK-64.2）。
///
/// Rust 側の検証と VZ の許容範囲照合をすべて終えてから FFI の setter を呼ぶ（ObjC 例外は捕捉できないため）。
/// `validateWithError` は entitlement 依存の可能性があり、ここでは呼ばない（TASK-64.4 以降）。
#[cfg(target_os = "macos")]
pub fn build_vz_configuration(spec: &VmConfigSpec) -> Result<VzVmConfiguration, ConfigError> {
    use objc2_foundation::{NSString, NSURL};

    let (cpu_min, cpu_max) = crate::sys::allowed_cpu_range();
    let requested_cpus = spec.cpus.get();
    let cpus = usize::try_from(requested_cpus)
        .ok()
        .filter(|c| (cpu_min..=cpu_max).contains(c))
        .ok_or(ConfigError::CpuCountOutOfRange {
            requested: requested_cpus,
            min: cpu_min as u64,
            max: cpu_max as u64,
        })?;

    let (mem_min, mem_max) = crate::sys::allowed_memory_range();
    let memory = spec.memory.bytes();
    if !(mem_min..=mem_max).contains(&memory) {
        return Err(ConfigError::MemorySizeOutOfRange {
            requested: memory,
            min: mem_min,
            max: mem_max,
        });
    }

    let kernel_url =
        NSURL::from_file_path(spec.kernel.as_path()).ok_or(ConfigError::UrlConversion {
            field: ConfigField::Kernel,
        })?;
    let initrd_url = match &spec.initrd {
        Some(p) => Some(
            NSURL::from_file_path(p.as_path()).ok_or(ConfigError::UrlConversion {
                field: ConfigField::Initrd,
            })?,
        ),
        None => None,
    };
    let cmdline = NSString::from_str(spec.cmdline.as_str());

    let boot = crate::sys::new_linux_boot_loader(&kernel_url, initrd_url.as_deref(), &cmdline);
    Ok(VzVmConfiguration(crate::sys::new_vm_configuration(
        &boot, cpus, memory,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト専用の一時ディレクトリ（終了時に削除）。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("fandhe-macos-cfg-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, b"dummy").expect("write fixture");
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// MAC-1・TASK-64.2: 正常な 3 入力で仕様が組み立てられ、既定の CPU・メモリが入る。
    #[test]
    fn spec_from_valid_parts() {
        let t = TempDir::new("ok");
        let k = t.file("vmlinux");
        let i = t.file("initrd.img");
        let spec = VmConfigSpec::from_parts(&k, Some(&i), "console=hvc0 root=/dev/vda").unwrap();
        assert_eq!(spec.kernel.as_path(), k);
        assert_eq!(spec.initrd.as_ref().unwrap().as_path(), i);
        assert_eq!(spec.cmdline.as_str(), "console=hvc0 root=/dev/vda");
        assert_eq!(spec.cpus.get(), 2);
        assert_eq!(spec.memory.bytes(), 1024 * 1024 * 1024);
    }

    /// MAC-1・TASK-64.2: 存在しないパスは `config.path_not_found`。
    #[test]
    fn missing_path_is_not_found() {
        let t = TempDir::new("missing");
        let err = KernelImagePath::try_new(t.0.join("nope")).unwrap_err();
        assert_eq!(err.code(), "config.path_not_found");
    }

    /// MAC-1・TASK-64.2: ディレクトリは `config.not_a_file`。
    #[test]
    fn directory_is_not_a_file() {
        let t = TempDir::new("dir");
        let err = InitrdPath::try_new(&t.0).unwrap_err();
        assert_eq!(err.code(), "config.not_a_file");
    }

    /// MAC-1・TASK-64.2: 相対パスは `config.path_not_absolute`。
    #[test]
    fn relative_path_is_rejected() {
        let err = KernelImagePath::try_new("relative/vmlinux").unwrap_err();
        assert_eq!(err.code(), "config.path_not_absolute");
    }

    /// MAC-1・TASK-64.2: 非 UTF-8 パスは `config.path_invalid_encoding`（Unix のみ）。
    #[cfg(unix)]
    #[test]
    fn non_utf8_path_is_rejected() {
        use std::os::unix::ffi::OsStrExt;
        let p = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe"));
        let err = KernelImagePath::try_new(p).unwrap_err();
        assert_eq!(err.code(), "config.path_invalid_encoding");
    }

    /// MAC-1・TASK-64.2: コマンドラインは 2048 バイトちょうどまで許可、2049 で拒否。
    #[test]
    fn command_line_length_limit() {
        assert!(KernelCommandLine::try_new(&"a".repeat(2048)).is_ok());
        let err = KernelCommandLine::try_new(&"a".repeat(2049)).unwrap_err();
        assert_eq!(
            err,
            ConfigError::CommandLineTooLong {
                len: 2049,
                max: 2048
            }
        );
        assert_eq!(err.code(), "config.command_line_too_long");
    }

    /// MAC-1・TASK-64.2: 改行・NUL・非 ASCII は位置付きで拒否し、空文字列は許可する。
    #[test]
    fn command_line_invalid_chars() {
        let e = KernelCommandLine::try_new("ro\nquiet").unwrap_err();
        assert_eq!(e, ConfigError::CommandLineInvalidChar { index: 2 });
        let e = KernelCommandLine::try_new("a\0b").unwrap_err();
        assert_eq!(e, ConfigError::CommandLineInvalidChar { index: 1 });
        let e = KernelCommandLine::try_new("é").unwrap_err();
        assert_eq!(e.code(), "config.command_line_invalid_char");
        assert_eq!(KernelCommandLine::try_new("").unwrap().as_str(), "");
    }

    /// MAC-1・TASK-64.2: CPU 0 とメモリ 0・1 MiB 非倍数を拒否する。
    #[test]
    fn cpu_and_memory_validation() {
        assert_eq!(
            CpuCount::try_new(0).unwrap_err().code(),
            "config.invalid_cpu_count"
        );
        assert_eq!(CpuCount::try_new(4).unwrap().get(), 4);
        assert_eq!(
            MemorySize::try_new(0).unwrap_err(),
            ConfigError::InvalidMemorySize { bytes: 0 }
        );
        assert_eq!(
            MemorySize::try_new(1024 * 1024 + 1).unwrap_err().code(),
            "config.invalid_memory_size"
        );
        assert_eq!(
            MemorySize::try_new(512 * 1024 * 1024).unwrap().bytes(),
            536_870_912
        );
    }

    /// MAC-1・TASK-64.2: エラーのメッセージは英語で code を含む Display になる。
    #[test]
    fn error_display_has_code_and_english_message() {
        let e = ConfigError::InvalidCpuCount;
        assert_eq!(
            e.to_string(),
            "config.invalid_cpu_count: cpu count must be at least 1"
        );
    }

    /// MAC-1・TASK-64.2: macOS で設定を構築し、読み戻した値が入力と一致する。
    #[cfg(target_os = "macos")]
    #[test]
    fn builds_vz_configuration_and_reads_back() {
        let t = TempDir::new("vz");
        let k = t.file("vmlinux");
        let i = t.file("initrd.img");
        let spec = VmConfigSpec::from_parts(&k, Some(&i), "console=hvc0").unwrap();
        let cfg = build_vz_configuration(&spec).unwrap();
        assert_eq!(cfg.cpu_count(), 2);
        assert_eq!(cfg.memory_size(), 1024 * 1024 * 1024);
        assert_eq!(cfg.command_line().as_deref(), Some("console=hvc0"));
        // /var → /private/var 等の正規化差を吸収するため canonicalize 同士で比較する。
        assert_eq!(
            cfg.kernel_path().and_then(|p| p.canonicalize().ok()),
            k.canonicalize().ok()
        );
        assert_eq!(
            cfg.initrd_path().and_then(|p| p.canonicalize().ok()),
            i.canonicalize().ok()
        );
    }

    /// MAC-1・TASK-64.2: macOS で VZ の最大 CPU 数を超える指定は `config.cpu_count_out_of_range`。
    #[cfg(target_os = "macos")]
    #[test]
    fn cpu_over_max_is_rejected() {
        let t = TempDir::new("vzcpu");
        let k = t.file("vmlinux");
        let mut spec = VmConfigSpec::from_parts(&k, None, "").unwrap();
        let (_, max) = crate::sys::allowed_cpu_range();
        let over = u32::try_from(max).unwrap().checked_add(1).unwrap();
        spec.cpus = CpuCount::try_new(over).unwrap();
        let err = build_vz_configuration(&spec).err().unwrap();
        assert_eq!(err.code(), "config.cpu_count_out_of_range");
    }
}
