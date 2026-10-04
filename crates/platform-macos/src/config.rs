//! VM 設定（`VZVirtualMachineConfiguration` 相当）の検証型と構築関数（MAC-1・TASK-64.2・64.3）。
//!
//! 構成は 2 層に分かれる。
//! - OS 非依存層（全 OS でビルド・3 OS CI でテスト）: カーネル / initrd パス・コマンドライン・CPU 数・
//!   メモリ量を「壊れた値を表現できない」検証済み型にし、[`VmConfigSpec`] にまとめる。不正値は
//!   panic ではなく [`ConfigError`] で返す。
//! - macOS 限定層: [`VmConfigSpec`] から Virtualization.framework の設定オブジェクトを組み立てる
//!   [`build_vz_configuration`]。FFI は `sys` モジュールに閉じ込める。
//!
//! 最小デバイス構成（TASK-64.3）として virtio-blk のルートディスクと virtio-console のシリアル
//! コンソール（ログファイル出力）を [`DeviceConfigSpec`] で表す。
//!
//! 呼び出し文脈: TASK-64.4 が構築済み設定から `VZVirtualMachine` を生成して起動し、ゲストの
//! `console=hvc0` 出力をコンソールログから確認する（TASK-64.6 の vm_boot 結合試験）。[`ConfigError`] は TASK-64.5 で `VmError` に包む予定
//! （REPAIR-3: 現時点では未統合）。検証後〜起動までの TOCTOU（ファイル差し替え）は残るため、
//! 起動時の読み込み失敗は TASK-64.4/64.5 のエラー経路で扱う。
//! コンソールログの open は `O_NOFOLLOW` で最終パス要素の symlink 追従を open 時点で拒否し、
//! open 後に fd と lstat の `(dev, ino)` も照合する（事前検査〜open 間の symlink 差し替えを塞ぐ）。
//! 新規作成は `O_CREAT | O_EXCL` で行い、既存ファイルは作成フラグなしで開く。open 後の fd が
//! kernel / initrd / ディスクイメージと同一ファイルなら拒否し（initrd への追記は次回起動時の
//! initramfs 注入になり得る）、リンク数が 1 でない・所有者が実効 uid でないファイルも拒否する。
//!
//! 信頼前提（fail-closed で検査しない範囲）: 直近の親ディレクトリは symlink なら拒否し（macOS の `/tmp`
//! 等は呼び出し側が実体パスへ正規化して渡す）、「他者書き込み可能かつ sticky bit なし」なら拒否するが、
//! group 書き込み可は group メンバーを信頼するものとして許可する。祖先ディレクトリ要素（親より上）の
//! 差し替えは対象外で、呼び出し側の配置ディレクトリの権限管理に委ねる。

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

/// ブロックデバイスの最大件数（無制限確保の防止）。
pub const MAX_BLOCK_DEVICES: usize = 8;

/// virtio-blk デバイス識別子の最大バイト数（VZ の `blockDeviceIdentifier` は ASCII 20 バイト以下）。
pub const MAX_BLOCK_DEVICE_ID_BYTES: usize = 20;

/// エラーの対象となった入力フィールド。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigField {
    /// Linux カーネルイメージ。
    Kernel,
    /// 初期 RAM ディスク。
    Initrd,
    /// ブロックデバイスのディスクイメージ。
    DiskImage,
    /// シリアルコンソールのログファイル。
    ConsoleLog,
}

impl ConfigField {
    fn as_str(self) -> &'static str {
        match self {
            ConfigField::Kernel => "kernel",
            ConfigField::Initrd => "initrd",
            ConfigField::DiskImage => "disk_image",
            ConfigField::ConsoleLog => "console_log",
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
    /// ブロックデバイス数が上限を超えた。
    TooManyBlockDevices { count: usize, max: usize },
    /// ブロックデバイス識別子が空、または ASCII 印字可能文字でない（`index` はバイト位置）。
    InvalidBlockDeviceId { index: usize },
    /// ブロックデバイス識別子が上限を超えた。
    BlockDeviceIdTooLong { len: usize, max: usize },
    /// ブロックデバイス識別子（大文字小文字非区別）が重複した。
    DuplicateBlockDeviceId { id: String },
    /// 同一のディスクイメージが複数指定された。
    DuplicateDiskImage { path: PathBuf },
    /// コンソールログのパスが symlink。
    ConsoleLogIsSymlink { path: PathBuf },
    /// コンソールログの親ディレクトリが存在しない（またはディレクトリでない）。
    ConsoleLogParentNotFound { path: PathBuf },
    /// コンソールログがディスクイメージと同一ファイル。
    ConsoleLogConflictsWithDiskImage { path: PathBuf },
    /// コンソールログが kernel / initrd と同一ファイル（`field` はどちらか）。
    ConsoleLogConflictsWithBootFile { field: ConfigField, path: PathBuf },
    /// 既存のコンソールログの所有者が実効 uid でない（他ユーザーの事前作成）。
    ConsoleLogNotOwned {
        path: PathBuf,
        owner: u32,
        euid: u32,
    },
    /// 既存のコンソールログのハードリンク数が 1 でない（別名経由の追記先すり替え）。
    ConsoleLogMultipleLinks { path: PathBuf, links: u64 },
    /// コンソールログの親ディレクトリが他者書き込み可能で sticky bit がない（`path` は親ディレクトリ）。
    ConsoleLogParentWorldWritable { path: PathBuf },
    /// コンソールログの親ディレクトリ自体が symlink（`path` は親ディレクトリ）。
    ConsoleLogParentIsSymlink { path: PathBuf },
    /// コンソールログを開けない、または open 後の同一性検査に失敗した。
    ConsoleLogOpen { kind: std::io::ErrorKind },
    /// コンソールログの上限つき書き出し（pipe・書き出しスレッド）を開始できない。
    ConsoleLogWriter { kind: std::io::ErrorKind },
    /// 同じコンソールログを別の書き出し（別の VM）が使用中。
    ConsoleLogInUse { path: PathBuf },
    /// VZ がディスクイメージ attachment を拒否した（NSError の domain / code）。
    DiskAttachment { domain: String, code: isize },
    /// VZ がブロックデバイス識別子を拒否した（NSError の domain / code）。
    BlockDeviceIdRejected { domain: String, code: isize },
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
            ConfigError::TooManyBlockDevices { .. } => "config.too_many_block_devices",
            ConfigError::InvalidBlockDeviceId { .. } => "config.invalid_block_device_id",
            ConfigError::BlockDeviceIdTooLong { .. } => "config.block_device_id_too_long",
            ConfigError::DuplicateBlockDeviceId { .. } => "config.duplicate_block_device_id",
            ConfigError::DuplicateDiskImage { .. } => "config.duplicate_disk_image",
            ConfigError::ConsoleLogIsSymlink { .. } => "config.console_log_is_symlink",
            ConfigError::ConsoleLogParentNotFound { .. } => "config.console_log_parent_not_found",
            ConfigError::ConsoleLogConflictsWithDiskImage { .. } => {
                "config.console_log_conflicts_with_disk_image"
            }
            ConfigError::ConsoleLogConflictsWithBootFile { .. } => {
                "config.console_log_conflicts_with_boot_file"
            }
            ConfigError::ConsoleLogNotOwned { .. } => "config.console_log_not_owned",
            ConfigError::ConsoleLogMultipleLinks { .. } => "config.console_log_multiple_links",
            ConfigError::ConsoleLogParentWorldWritable { .. } => {
                "config.console_log_parent_world_writable"
            }
            ConfigError::ConsoleLogParentIsSymlink { .. } => "config.console_log_parent_is_symlink",
            ConfigError::ConsoleLogOpen { .. } => "config.console_log_open",
            ConfigError::ConsoleLogWriter { .. } => "config.console_log_writer",
            ConfigError::ConsoleLogInUse { .. } => "config.console_log_in_use",
            ConfigError::DiskAttachment { .. } => "config.disk_attachment",
            ConfigError::BlockDeviceIdRejected { .. } => "config.block_device_id_rejected",
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
            ConfigError::TooManyBlockDevices { count, max } => {
                format!("{count} block devices requested, max is {max}")
            }
            ConfigError::InvalidBlockDeviceId { index } => {
                format!("block device id is empty or has a disallowed character at byte {index}")
            }
            ConfigError::BlockDeviceIdTooLong { len, max } => {
                format!("block device id is {len} bytes, max is {max}")
            }
            ConfigError::DuplicateBlockDeviceId { id } => {
                format!("block device id is used more than once: {id}")
            }
            ConfigError::DuplicateDiskImage { path } => {
                format!("disk image is attached more than once: {}", path.display())
            }
            ConfigError::ConsoleLogIsSymlink { path } => {
                format!("console log path must not be a symlink: {}", path.display())
            }
            ConfigError::ConsoleLogParentNotFound { path } => {
                format!(
                    "console log parent directory does not exist: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogConflictsWithDiskImage { path } => {
                format!(
                    "console log is the same file as a disk image: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogConflictsWithBootFile { field, path } => {
                format!(
                    "console log is the same file as the {} image: {}",
                    field.as_str(),
                    path.display()
                )
            }
            ConfigError::ConsoleLogNotOwned { path, owner, euid } => {
                format!(
                    "console log is owned by uid {owner}, expected effective uid {euid}: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogMultipleLinks { path, links } => {
                format!(
                    "console log has {links} hard links, expected 1: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogParentWorldWritable { path } => {
                format!(
                    "console log parent directory is world-writable without the sticky bit: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogParentIsSymlink { path } => {
                format!(
                    "console log parent directory must not be a symlink: {}",
                    path.display()
                )
            }
            ConfigError::ConsoleLogOpen { kind } => {
                format!("failed to open console log safely: {kind}")
            }
            ConfigError::ConsoleLogWriter { kind } => {
                format!("failed to start the capped console log writer: {kind}")
            }
            ConfigError::ConsoleLogInUse { path } => {
                format!(
                    "console log is in use by another virtual machine: {}",
                    path.display()
                )
            }
            ConfigError::DiskAttachment { domain, code } => {
                format!("virtualization framework rejected the disk image ({domain} {code})")
            }
            ConfigError::BlockDeviceIdRejected { domain, code } => {
                format!("virtualization framework rejected the block device id ({domain} {code})")
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

/// UTF-8・NUL なし・絶対パスであることだけを検証する（読み込み元・書き込み先で共通）。
fn check_absolute_utf8(field: ConfigField, path: &Path) -> Result<(), ConfigError> {
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
    Ok(())
}

/// 絶対・UTF-8・NUL なし・通常ファイルであることを検証する。
///
/// symlink は追従した先が通常ファイルなら許可する（ホスト側ファイルを同一ユーザーが指定するため）。
/// 非 UTF-8 パスは `NSURL` 変換の決定性のため fail-closed で拒否する。
fn validate_file_path(field: ConfigField, path: &Path) -> Result<PathBuf, ConfigError> {
    check_absolute_utf8(field, path)?;
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

/// 検証済みのディスクイメージパス（RAW 形式。読み込み対象のため kernel / initrd と同じ規則）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskImagePath(PathBuf);

impl DiskImagePath {
    /// パスを検証して生成する。
    pub fn try_new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        validate_file_path(ConfigField::DiskImage, path.as_ref()).map(Self)
    }

    /// 検証済みパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// 検証済みの virtio-blk デバイス識別子（ASCII 印字可能・1〜20 バイト）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceId(String);

impl BlockDeviceId {
    /// 長さを先に検証してから所有化する。空・非 ASCII・制御文字は拒否する。
    pub fn try_new(s: &str) -> Result<Self, ConfigError> {
        if s.len() > MAX_BLOCK_DEVICE_ID_BYTES {
            return Err(ConfigError::BlockDeviceIdTooLong {
                len: s.len(),
                max: MAX_BLOCK_DEVICE_ID_BYTES,
            });
        }
        if s.is_empty() {
            return Err(ConfigError::InvalidBlockDeviceId { index: 0 });
        }
        if let Some((index, _)) = s
            .bytes()
            .enumerate()
            .find(|(_, b)| !b.is_ascii_graphic() && *b != b' ')
        {
            return Err(ConfigError::InvalidBlockDeviceId { index });
        }
        Ok(Self(s.to_string()))
    }

    /// 文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// virtio-blk デバイス 1 台の仕様。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceSpec {
    /// ディスクイメージ。
    pub image: DiskImagePath,
    /// 読み取り専用で attach するか。
    pub read_only: bool,
    /// デバイス識別子（タグ。任意）。
    pub id: Option<BlockDeviceId>,
}

impl BlockDeviceSpec {
    /// ルートディスク用（書き込み可・識別子なし）。
    pub fn root(image: DiskImagePath) -> Self {
        Self {
            image,
            read_only: false,
            id: None,
        }
    }
}

/// 検証済みのコンソールログパス。書き込み先のため、存在しなくてもよいが symlink は拒否する。
///
/// 既存ファイルはリンク数 1・所有者が実効 uid であることも検証する（unix。他ユーザーの事前作成・
/// ハードリンクによる追記先のすり替えを拒否する）。検証は生成時点のもので、使用時点の再検査は
/// `VmConfigSpec` 経由の open が fd に対して行う（MAC-1・TASK-64.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleLogPath(PathBuf);

impl ConsoleLogPath {
    /// 絶対・UTF-8・親ディレクトリ存在（他者書き込み可能かつ sticky bit なしは拒否）・（存在すれば）
    /// symlink でない通常ファイル・リンク数 1・実効 uid 所有を検証して生成する。
    pub fn try_new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let field = ConfigField::ConsoleLog;
        check_absolute_utf8(field, path)?;
        check_console_log_parent(path)?;
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => Err(ConfigError::ConsoleLogIsSymlink {
                path: path.to_path_buf(),
            }),
            Ok(m) if !m.is_file() => Err(ConfigError::NotAFile {
                field,
                path: path.to_path_buf(),
            }),
            Ok(_m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    check_log_ownership(
                        path,
                        LogFileAttrs {
                            nlink: _m.nlink(),
                            uid: _m.uid(),
                        },
                        crate::sys::effective_uid(),
                    )?;
                }
                Ok(Self(path.to_path_buf()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self(path.to_path_buf())),
            Err(e) => Err(ConfigError::PathIo {
                field,
                kind: e.kind(),
            }),
        }
    }

    /// 検証済みパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// 追記モードで開く。無ければ `O_CREAT | O_EXCL`・0600 で新規作成する（既存ファイルのモードは変えない）。
    ///
    /// 非公開。[`VmConfigSpec::open_serial_console_log`] 経由でのみ呼ばれ、照合対象（kernel / initrd /
    /// ディスクイメージ）を呼び出し側が省略・差し替えできない（MAC-1・TASK-64.3）。
    ///
    /// 検査（いずれも fail-closed。拒否時は fd を drop で閉じ、何も書き込まない）:
    /// 1. 親ディレクトリが他者書き込み可能かつ sticky bit なしなら拒否する（P2-4 の信頼前提はモジュール doc）。
    /// 2. 事前の lstat で存在すれば作成フラグなし、無ければ `O_CREAT | O_EXCL` で開く。後者は事前検査〜open
    ///    間に他者が作ったファイル（symlink・ハードリンクを含む）を開かず `AlreadyExists` で失敗する。
    ///    `O_NOFOLLOW` で最終要素が symlink なら open 自体を失敗させる。
    /// 3. open 後に fd の種別と lstat との `(dev, ino)` を照合する（事前検査との間の差し替え検出）。
    /// 4. fd の `(dev, ino)` を各照合対象の現在の `(dev, ino)` と比べ、一致すれば
    ///    `ConsoleLogConflictsWithDiskImage` / `ConsoleLogConflictsWithBootFile` を返す。検証時点の
    ///    照合は 1 回きりで、その後のハードリンク差し替えはここで塞ぐ。追記 open は内容を変更しない
    ///    ため、拒否時に照合対象は破損しない。
    /// 5. fd のリンク数が 1 でなければ `ConsoleLogMultipleLinks`、所有者が実効 uid でなければ
    ///    `ConsoleLogNotOwned` を返す（4 の後に行い、照合対象へのハードリンクはより具体的な衝突エラーで報告する）。
    #[cfg(unix)]
    fn open_for_append_excluding(
        &self,
        protected: &[ProtectedInput<'_>],
    ) -> Result<std::fs::File, ConfigError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let path = self.as_path();
        let open_err = |kind: std::io::ErrorKind| ConfigError::ConsoleLogOpen { kind };
        check_console_log_parent(path)?;
        let pre = match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(ConfigError::ConsoleLogIsSymlink {
                    path: path.to_path_buf(),
                });
            }
            Ok(m) if !m.is_file() => {
                return Err(ConfigError::NotAFile {
                    field: ConfigField::ConsoleLog,
                    path: path.to_path_buf(),
                });
            }
            Ok(m) => Some((m.dev(), m.ino())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(open_err(e.kind())),
        };
        let mut options = std::fs::OpenOptions::new();
        options.append(true).custom_flags(O_NOFOLLOW);
        if pre.is_none() {
            // 新規作成は O_EXCL 付き（他者が先に作ったファイルを開かない）。
            options.create_new(true).mode(0o600);
        }
        let file = options.open(path).map_err(|e| {
            // O_NOFOLLOW による拒否（ELOOP 等）は symlink として報告する。
            match std::fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() => ConfigError::ConsoleLogIsSymlink {
                    path: path.to_path_buf(),
                },
                _ => open_err(e.kind()),
            }
        })?;
        let fd_meta = file.metadata().map_err(|e| open_err(e.kind()))?;
        let post = std::fs::symlink_metadata(path).map_err(|e| open_err(e.kind()))?;
        let fd_id = (fd_meta.dev(), fd_meta.ino());
        let swapped = post.file_type().is_symlink()
            || !fd_meta.is_file()
            || fd_id != (post.dev(), post.ino())
            || pre.is_some_and(|p| p != fd_id);
        if swapped {
            return Err(open_err(std::io::ErrorKind::Other));
        }
        for input in protected {
            // 取得失敗は fail-closed（fd は drop で閉じる）。
            if file_identity(input.field, input.path)? == fd_id {
                return Err(conflict_error(input.field, path));
            }
        }
        check_log_ownership(
            path,
            LogFileAttrs {
                nlink: fd_meta.nlink(),
                uid: fd_meta.uid(),
            },
            crate::sys::effective_uid(),
        )?;
        Ok(file)
    }
}

/// コンソールログの追記先と同一ファイルであってはならない入力（kernel / initrd / ディスクイメージ）。
#[derive(Debug, Clone, Copy)]
struct ProtectedInput<'a> {
    field: ConfigField,
    path: &'a Path,
}

/// 照合対象の種別に応じた衝突エラー（`path` はコンソールログ側のパス）。
fn conflict_error(field: ConfigField, path: &Path) -> ConfigError {
    match field {
        ConfigField::Kernel | ConfigField::Initrd => ConfigError::ConsoleLogConflictsWithBootFile {
            field,
            path: path.to_path_buf(),
        },
        // ConsoleLog は照合対象に来ない（`protected_inputs` は Kernel / Initrd / DiskImage だけを生成する）。
        // match を網羅するための腕で、ディスクイメージとの衝突として扱う。
        ConfigField::DiskImage | ConfigField::ConsoleLog => {
            ConfigError::ConsoleLogConflictsWithDiskImage {
                path: path.to_path_buf(),
            }
        }
    }
}

/// 検証時点のコンソールログと照合対象の同一性検査（ログが未作成なら検査不要）。
///
/// 使用時点の再検査は open 後の fd に対して行う（`ConsoleLogPath::open_for_append_excluding`）。
fn check_console_log_conflicts(
    log: &ConsoleLogPath,
    protected: &[ProtectedInput<'_>],
) -> Result<(), ConfigError> {
    match std::fs::symlink_metadata(log.as_path()) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(ConfigError::PathIo {
                field: ConfigField::ConsoleLog,
                kind: e.kind(),
            });
        }
    }
    let log_id = file_identity(ConfigField::ConsoleLog, log.as_path())?;
    for input in protected {
        if file_identity(input.field, input.path)? == log_id {
            return Err(conflict_error(input.field, log.as_path()));
        }
    }
    Ok(())
}

/// 既存ログファイルの所有・リンク数の判定材料（lstat / fstat から写す。判定を syscall から分離して
/// 実効 uid 不一致等を root なしでテストできるようにする。REPAIR-12）。
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogFileAttrs {
    nlink: u64,
    uid: u32,
}

/// リンク数 1 かつ所有者が `euid` であることを検査する（MAC-1・TASK-64.3）。
///
/// ハードリンクが複数あるファイル（他所の重要ファイルの別名かもしれない）と、他ユーザーが事前作成した
/// ファイルへは追記しない。リンク数を先に見る（所有者一致でも別名経由の追記は拒否する）。
#[cfg(unix)]
fn check_log_ownership(path: &Path, attrs: LogFileAttrs, euid: u32) -> Result<(), ConfigError> {
    if attrs.nlink != 1 {
        return Err(ConfigError::ConsoleLogMultipleLinks {
            path: path.to_path_buf(),
            links: attrs.nlink,
        });
    }
    if attrs.uid != euid {
        return Err(ConfigError::ConsoleLogNotOwned {
            path: path.to_path_buf(),
            owner: attrs.uid,
            euid,
        });
    }
    Ok(())
}

/// unix の他者書き込みビット（`S_IWOTH`）と sticky bit（`S_ISVTX`）。値は POSIX 共通。
#[cfg(unix)]
const MODE_OTHER_WRITE: u32 = 0o002;
#[cfg(unix)]
const MODE_STICKY: u32 = 0o1000;

/// 親ディレクトリのモードを判定する（他者書き込み可能かつ sticky bit なしなら拒否）。
///
/// sticky bit 付き（`/tmp` 等）なら他者は自分のエントリを差し替え・削除できず、他者が事前作成した
/// ファイルは所有者検査で拒否されるため許可する。
#[cfg(unix)]
fn check_parent_mode(parent: &Path, mode: u32) -> Result<(), ConfigError> {
    if mode & MODE_OTHER_WRITE != 0 && mode & MODE_STICKY == 0 {
        return Err(ConfigError::ConsoleLogParentWorldWritable {
            path: parent.to_path_buf(),
        });
    }
    Ok(())
}

/// コンソールログの親ディレクトリが存在するディレクトリで、（unix では）安全なモードであることを検査する。
fn check_console_log_parent(path: &Path) -> Result<(), ConfigError> {
    let no_parent = || ConfigError::ConsoleLogParentNotFound {
        path: path.to_path_buf(),
    };
    let parent = path.parent().ok_or_else(no_parent)?;
    // 親自体が symlink なら追従せず拒否する（他者所有の symlink だと検査後にリンク先を張り替えられ、
    // 検査したディレクトリと実際に作成するディレクトリが食い違うため）。
    match std::fs::symlink_metadata(parent) {
        Ok(m) if m.file_type().is_symlink() => Err(ConfigError::ConsoleLogParentIsSymlink {
            path: parent.to_path_buf(),
        }),
        Ok(m) if m.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                check_parent_mode(parent, m.permissions().mode())?;
            }
            Ok(())
        }
        Ok(_) => Err(no_parent()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(no_parent()),
        Err(e) => Err(ConfigError::PathIo {
            field: ConfigField::ConsoleLog,
            kind: e.kind(),
        }),
    }
}

/// `open(2)` の `O_NOFOLLOW`（libc 非依存のため OS・アーキ別に定義する。値は各 OS の fcntl.h）。
#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const O_NOFOLLOW: i32 = 0x0100;
// Linux uapi の `arch/{arm,arm64,powerpc,m68k}/include/uapi/asm/fcntl.h` は `0100000`（= 0x8000）、
// それ以外（asm-generic・x86・mips・sparc・riscv・loongarch・s390x 等）は 0x20000 相当。
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "m68k"
    )
))]
const O_NOFOLLOW: i32 = 0x8000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "m68k"
    ))
))]
const O_NOFOLLOW: i32 = 0x2_0000;

/// シリアルコンソールの出力先。
///
/// 現状はログファイルのみ。TASK-64.4 / 64.6 で必要になった時点で pipe・stdio 等の variant を足す
/// （`#[non_exhaustive]` のため破壊的変更にならない。REPAIR-3・MAC-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SerialConsoleSink {
    /// ゲストの出力をホストのファイルへ追記する。
    LogFile(ConsoleLogPath),
}

/// ファイルの同一性（大文字小文字非区別 FS・symlink 別名を越えて比較するため）。
#[cfg(unix)]
type FileIdentity = (u64, u64);
#[cfg(not(unix))]
type FileIdentity = PathBuf;

/// パスが指すファイルの同一性を取得する（失敗は fail-closed で `PathIo`）。
fn file_identity(field: ConfigField, path: &Path) -> Result<FileIdentity, ConfigError> {
    let io_err = |e: std::io::Error| ConfigError::PathIo {
        field,
        kind: e.kind(),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).map_err(io_err)?;
        Ok((m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        std::fs::canonicalize(path).map_err(io_err)
    }
}

/// 検証済みのデバイス構成（ブロックデバイス群とシリアルコンソール）。
///
/// フィールドは非公開で、[`DeviceConfigSpec::try_new`] を通った組み合わせだけが存在する（REPAIR-2）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceConfigSpec {
    block_devices: Vec<BlockDeviceSpec>,
    serial_console: Option<SerialConsoleSink>,
}

impl DeviceConfigSpec {
    /// 組み合わせを検証して生成する（MAC-1・TASK-64.3）。
    ///
    /// 件数上限 → 識別子重複（大文字小文字非区別）→ ディスクイメージ重複（ファイル同一性）→
    /// コンソールログとディスクイメージの衝突、の順に検査する。
    pub fn try_new(
        block_devices: Vec<BlockDeviceSpec>,
        serial_console: Option<SerialConsoleSink>,
    ) -> Result<Self, ConfigError> {
        if block_devices.len() > MAX_BLOCK_DEVICES {
            return Err(ConfigError::TooManyBlockDevices {
                count: block_devices.len(),
                max: MAX_BLOCK_DEVICES,
            });
        }
        for (i, dev) in block_devices.iter().enumerate() {
            let Some(id) = &dev.id else { continue };
            if block_devices
                .iter()
                .skip(i + 1)
                .filter_map(|d| d.id.as_ref())
                .any(|o| o.as_str().eq_ignore_ascii_case(id.as_str()))
            {
                return Err(ConfigError::DuplicateBlockDeviceId {
                    id: id.as_str().to_string(),
                });
            }
        }
        let mut identities = Vec::with_capacity(block_devices.len());
        for dev in &block_devices {
            let ident = file_identity(ConfigField::DiskImage, dev.image.as_path())?;
            if identities.contains(&ident) {
                return Err(ConfigError::DuplicateDiskImage {
                    path: dev.image.as_path().to_path_buf(),
                });
            }
            identities.push(ident);
        }
        if let Some(SerialConsoleSink::LogFile(log)) = &serial_console
            && log.as_path().exists()
            && identities.contains(&file_identity(ConfigField::ConsoleLog, log.as_path())?)
        {
            return Err(ConfigError::ConsoleLogConflictsWithDiskImage {
                path: log.as_path().to_path_buf(),
            });
        }
        Ok(Self {
            block_devices,
            serial_console,
        })
    }

    /// ブロックデバイス群。
    pub fn block_devices(&self) -> &[BlockDeviceSpec] {
        &self.block_devices
    }

    /// シリアルコンソールの出力先。
    pub fn serial_console(&self) -> Option<&SerialConsoleSink> {
        self.serial_console.as_ref()
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
    /// 最小デバイス構成（TASK-64.3。既定はデバイスなし）。
    pub devices: DeviceConfigSpec,
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
            devices: DeviceConfigSpec::default(),
        })
    }

    /// デバイス構成を差し替える（TASK-64.3）。
    ///
    /// コンソールログが既存なら、kernel / initrd / ディスクイメージと同一ファイルでないことを検証する
    /// （initrd への追記は次回起動時の initramfs 注入になり得る。MAC-1）。フィールドは公開のため
    /// 生成後に差し替えられ得るが、使用時点の照合は [`build_vz_configuration`] の open が必ず行う。
    pub fn with_devices(mut self, devices: DeviceConfigSpec) -> Result<Self, ConfigError> {
        self.devices = devices;
        if let Some(SerialConsoleSink::LogFile(log)) = self.devices.serial_console() {
            check_console_log_conflicts(log, &self.protected_inputs())?;
        }
        Ok(self)
    }

    /// コンソールログの追記先と同一ファイルであってはならない入力（kernel・initrd・全ディスクイメージ）。
    ///
    /// 自身のフィールドから導出し、呼び出し側が照合対象を省略・差し替えできないようにする。
    fn protected_inputs(&self) -> Vec<ProtectedInput<'_>> {
        let mut inputs = Vec::with_capacity(2 + self.devices.block_devices().len());
        inputs.push(ProtectedInput {
            field: ConfigField::Kernel,
            path: self.kernel.as_path(),
        });
        if let Some(initrd) = &self.initrd {
            inputs.push(ProtectedInput {
                field: ConfigField::Initrd,
                path: initrd.as_path(),
            });
        }
        inputs.extend(self.devices.block_devices().iter().map(|d| ProtectedInput {
            field: ConfigField::DiskImage,
            path: d.image.as_path(),
        }));
        inputs
    }

    /// シリアルコンソールの出力先を上限つきの書き出しとして開く（無ければ `None`）。
    ///
    /// ログファイルを検証つきで開き（[`Self::open_serial_console_log`]）、ファイル長が
    /// [`crate::console_log::MAX_CONSOLE_LOG_BYTES`] に達するまでゲスト出力を書き出すスレッドへ渡す
    /// （超過分は区切り文 1 回と stderr の構造化ログを残して捨てる）。戻り値は pipe の書き込み端で、
    /// 生のログファイルは返さない（上限を迂回する経路を公開しない。#1366 の P1-3・MAC-1・TASK-64.3）。
    /// 書き出しの開始に失敗した場合、作成済みのログファイル（空）は残る。
    #[cfg(unix)]
    pub fn open_serial_console(
        &self,
    ) -> Result<Option<crate::console_log::ConsoleLogSink>, ConfigError> {
        use crate::console_log::{ConsoleLogSink, MAX_CONSOLE_LOG_BYTES, SpawnError};
        let Some(SerialConsoleSink::LogFile(log)) = self.devices.serial_console() else {
            return Ok(None);
        };
        let log_path = log.as_path();
        let Some(file) = self.open_serial_console_log()? else {
            return Ok(None);
        };
        match ConsoleLogSink::spawn(file, MAX_CONSOLE_LOG_BYTES) {
            Ok(sink) => Ok(Some(sink)),
            Err(SpawnError::InUse) => Err(ConfigError::ConsoleLogInUse {
                path: log_path.to_path_buf(),
            }),
            Err(SpawnError::Io(kind)) => Err(ConfigError::ConsoleLogWriter { kind }),
        }
    }

    /// シリアルコンソールのログファイルを追記モードで開く（無ければ `None`）。
    ///
    /// 照合対象（kernel / initrd / ディスクイメージ）は [`Self::protected_inputs`] に固定され、
    /// 呼び出し側が省略・差し替えできない（MAC-1・TASK-64.3）。生の `File` を返すため非公開とし、
    /// 外部へは [`Self::open_serial_console`]（上限つき）だけを公開する。
    #[cfg(unix)]
    fn open_serial_console_log(&self) -> Result<Option<std::fs::File>, ConfigError> {
        match self.devices.serial_console() {
            Some(SerialConsoleSink::LogFile(log)) => log
                .open_for_append_excluding(&self.protected_inputs())
                .map(Some),
            None => Ok(None),
        }
    }
}

/// 読み戻した virtio-blk デバイス設定（診断用）。
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceReadBack {
    /// ディスクイメージのパス。
    pub path: Option<PathBuf>,
    /// 読み取り専用か。
    pub read_only: bool,
    /// デバイス識別子（未設定なら空文字列）。
    pub id: String,
}

/// 構築済みの `VZVirtualMachineConfiguration`（不透明型）。`vm::Vm::create`（TASK-64.4）が内部を取り出して使う。
#[cfg(target_os = "macos")]
pub struct VzVmConfiguration(
    objc2::rc::Retained<objc2_virtualization::VZVirtualMachineConfiguration>,
);

#[cfg(target_os = "macos")]
impl VzVmConfiguration {
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

    /// 設定済みの virtio-blk デバイス（診断用。TASK-64.3）。
    pub fn block_devices(&self) -> Vec<BlockDeviceReadBack> {
        crate::sys::read_back_storage(&self.0)
            .into_iter()
            .map(|d| BlockDeviceReadBack {
                path: d.path,
                read_only: d.read_only,
                id: d.id,
            })
            .collect()
    }

    /// 設定済みのシリアルポート数（診断用。TASK-64.3）。
    pub fn serial_port_count(&self) -> usize {
        crate::sys::serial_port_count(&self.0)
    }

    /// 設定済みのコマンドライン（診断用）。
    pub fn command_line(&self) -> Option<String> {
        crate::sys::read_back_boot(&self.0).map(|b| b.command_line)
    }
}

/// [`VmConfigSpec`] から `VZVirtualMachineConfiguration` を構築する（MAC-1・TASK-64.2・64.3）。
///
/// `vm::Vm::create`（TASK-64.4）がこの構成から `VZVirtualMachine` を生成する。ゲストのカーネルコマンドライン
/// `console=hvc0` の出力は pipe 経由で上限つきの書き出しスレッドへ渡り、コンソールログへ追記される
/// （`crate::console_log`。スレッドは VM が書き込み端を手放すまで残る）。ホスト側の副作用（ログファイルの
/// 作成・書き出しスレッドの起動）は失敗し得る処理をすべて終えた後に行う。
///
/// Rust 側の検証と VZ の許容範囲照合をすべて終えてから FFI の setter を呼ぶ（ObjC 例外は捕捉できないため）。
/// `validateWithError` は entitlement 依存の可能性があり、ここでは呼ばず、`vm::Vm::create` が VM 生成前に呼ぶ（TASK-64.4）。
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

    // ブロックデバイス（副作用なし。件数は DeviceConfigSpec が上限検証済み）。
    let mut storage = Vec::with_capacity(spec.devices.block_devices().len());
    for dev in spec.devices.block_devices() {
        let url = NSURL::from_file_path(dev.image.as_path()).ok_or(ConfigError::UrlConversion {
            field: ConfigField::DiskImage,
        })?;
        let attachment = crate::sys::new_disk_image_attachment(&url, dev.read_only)
            .map_err(|(domain, code)| ConfigError::DiskAttachment { domain, code })?;
        let id = match &dev.id {
            Some(id) => {
                let ns = NSString::from_str(id.as_str());
                crate::sys::validate_block_device_id(&ns).map_err(|(domain, code)| {
                    ConfigError::BlockDeviceIdRejected { domain, code }
                })?;
                Some(ns)
            }
            None => None,
        };
        storage.push(crate::sys::new_virtio_block_device(
            &attachment,
            id.as_deref(),
        ));
    }

    // シリアルコンソール（ここで初めてログファイルを作成・open する）。
    // 使用時点で fd を kernel / initrd / ディスクイメージと照合し、リンク数・所有者も検査する。
    // VZ へはログファイルではなく上限つき書き出しの pipe の書き込み端を渡す（追記量の上限。P1-3）。
    let mut serial = Vec::new();
    if let Some(sink) = spec.open_serial_console()? {
        let handle = crate::sys::new_file_handle(sink.into_write_fd());
        serial.push(crate::sys::new_console_serial_port(&handle));
    }

    let boot = crate::sys::new_linux_boot_loader(&kernel_url, initrd_url.as_deref(), &cmdline);
    let config = crate::sys::new_vm_configuration(&boot, cpus, memory);
    crate::sys::set_devices(&config, &storage, &serial);
    Ok(VzVmConfiguration(config))
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
            // umask に依らず親ディレクトリ検査（他者書き込み可能かつ sticky なしは拒否）を通る 0700 にする。
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod temp dir");
            }
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

    fn disk(path: &Path) -> BlockDeviceSpec {
        BlockDeviceSpec::root(DiskImagePath::try_new(path).unwrap())
    }

    fn with_id(mut dev: BlockDeviceSpec, id: &str) -> BlockDeviceSpec {
        dev.id = Some(BlockDeviceId::try_new(id).unwrap());
        dev
    }

    /// MAC-1・TASK-64.3: ルートディスクとコンソールログで構成でき、getter が入力と一致する。
    #[test]
    fn device_spec_with_root_disk_and_console() {
        let t = TempDir::new("dev-ok");
        let img = t.file("root.img");
        let log = ConsoleLogPath::try_new(t.0.join("console.log")).unwrap();
        let spec = DeviceConfigSpec::try_new(
            vec![disk(&img)],
            Some(SerialConsoleSink::LogFile(log.clone())),
        )
        .unwrap();
        assert_eq!(spec.block_devices().len(), 1);
        assert_eq!(spec.block_devices()[0].image.as_path(), img);
        assert!(!spec.block_devices()[0].read_only);
        assert_eq!(spec.block_devices()[0].id, None);
        assert_eq!(
            spec.serial_console(),
            Some(&SerialConsoleSink::LogFile(log))
        );
        assert_eq!(DeviceConfigSpec::default().block_devices().len(), 0);
    }

    /// MAC-1・TASK-64.3: 存在しないディスクイメージは `config.path_not_found`。
    #[test]
    fn missing_disk_image_is_not_found() {
        let t = TempDir::new("dev-missing");
        let err = DiskImagePath::try_new(t.0.join("nope.img")).unwrap_err();
        assert_eq!(err.code(), "config.path_not_found");
        assert!(err.message().starts_with("disk_image path"));
    }

    /// MAC-1・TASK-64.3: ディレクトリのディスクイメージは `config.not_a_file`。
    #[test]
    fn disk_image_directory_is_not_a_file() {
        let t = TempDir::new("dev-dir");
        let err = DiskImagePath::try_new(&t.0).unwrap_err();
        assert_eq!(err.code(), "config.not_a_file");
    }

    /// MAC-1・TASK-64.3: 識別子は 20 バイトまで許可、21 バイトで拒否する。
    #[test]
    fn block_device_id_too_long() {
        assert!(BlockDeviceId::try_new(&"a".repeat(20)).is_ok());
        assert_eq!(
            BlockDeviceId::try_new(&"a".repeat(21)).unwrap_err(),
            ConfigError::BlockDeviceIdTooLong { len: 21, max: 20 }
        );
    }

    /// MAC-1・TASK-64.3: 空・非 ASCII・制御文字の識別子は位置付きで拒否する。
    #[test]
    fn block_device_id_invalid_chars() {
        assert_eq!(
            BlockDeviceId::try_new("").unwrap_err(),
            ConfigError::InvalidBlockDeviceId { index: 0 }
        );
        assert_eq!(
            BlockDeviceId::try_new("ab\ncd").unwrap_err(),
            ConfigError::InvalidBlockDeviceId { index: 2 }
        );
        assert_eq!(
            BlockDeviceId::try_new("é").unwrap_err().code(),
            "config.invalid_block_device_id"
        );
    }

    /// MAC-1・TASK-64.3: 重複する識別子は大文字小文字を区別せず拒否する。
    #[test]
    fn duplicate_block_device_id_is_rejected() {
        let t = TempDir::new("dev-dupid");
        let a = t.file("a.img");
        let b = t.file("b.img");
        let err = DeviceConfigSpec::try_new(
            vec![with_id(disk(&a), "root"), with_id(disk(&b), "ROOT")],
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::DuplicateBlockDeviceId {
                id: "root".to_string()
            }
        );
        assert_eq!(err.code(), "config.duplicate_block_device_id");
    }

    /// MAC-1・TASK-64.3: 同じディスクイメージの二重指定は `config.duplicate_disk_image`。
    #[test]
    fn duplicate_disk_image_is_rejected() {
        let t = TempDir::new("dev-dupimg");
        let a = t.file("a.img");
        let err = DeviceConfigSpec::try_new(vec![disk(&a), disk(&a)], None).unwrap_err();
        assert_eq!(err.code(), "config.duplicate_disk_image");
    }

    /// MAC-1・TASK-64.3・IO-5: symlink 経由の別名でも同一ディスクイメージとして検出する。
    #[cfg(unix)]
    #[test]
    fn duplicate_disk_image_via_symlink_is_rejected() {
        let t = TempDir::new("dev-dupsym");
        let a = t.file("a.img");
        let link = t.0.join("link.img");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        let err = DeviceConfigSpec::try_new(vec![disk(&a), disk(&link)], None).unwrap_err();
        assert_eq!(err.code(), "config.duplicate_disk_image");
    }

    /// MAC-1・TASK-64.3: 9 台は `TooManyBlockDevices { count: 9, max: 8 }`（走査前に拒否）。
    #[test]
    fn too_many_block_devices() {
        let t = TempDir::new("dev-many");
        let a = t.file("a.img");
        let devs = (0..9).map(|_| disk(&a)).collect();
        assert_eq!(
            DeviceConfigSpec::try_new(devs, None).unwrap_err(),
            ConfigError::TooManyBlockDevices { count: 9, max: 8 }
        );
    }

    /// MAC-1・TASK-64.3: コンソールログの相対パスは `config.path_not_absolute`。
    #[test]
    fn console_log_relative_path_rejected() {
        assert_eq!(
            ConsoleLogPath::try_new("console.log").unwrap_err().code(),
            "config.path_not_absolute"
        );
    }

    /// MAC-1・TASK-64.3: 親ディレクトリが無いコンソールログは `config.console_log_parent_not_found`。
    #[test]
    fn console_log_missing_parent_rejected() {
        let t = TempDir::new("log-noparent");
        let err = ConsoleLogPath::try_new(t.0.join("missing").join("c.log")).unwrap_err();
        assert_eq!(err.code(), "config.console_log_parent_not_found");
    }

    /// MAC-1・TASK-64.3: ディレクトリをログ先にすると `config.not_a_file`。
    #[test]
    fn console_log_directory_rejected() {
        let t = TempDir::new("log-dir");
        let err = ConsoleLogPath::try_new(&t.0).unwrap_err();
        assert_eq!(err.code(), "config.not_a_file");
    }

    /// MAC-1・TASK-64.3: ログ先がディスクイメージと同一ファイルなら拒否する。
    #[test]
    fn console_log_conflicts_with_disk_image() {
        let t = TempDir::new("log-conflict");
        let img = t.file("root.img");
        let log = ConsoleLogPath::try_new(&img).unwrap();
        let err =
            DeviceConfigSpec::try_new(vec![disk(&img)], Some(SerialConsoleSink::LogFile(log)))
                .unwrap_err();
        assert_eq!(err.code(), "config.console_log_conflicts_with_disk_image");
    }

    /// MAC-1・TASK-64.3: symlink のログ先は `config.console_log_is_symlink`。
    #[cfg(unix)]
    #[test]
    fn console_log_symlink_rejected() {
        let t = TempDir::new("log-sym");
        let target = t.file("target.log");
        let link = t.0.join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = ConsoleLogPath::try_new(&link).unwrap_err();
        assert_eq!(err.code(), "config.console_log_is_symlink");
    }

    /// MAC-1・TASK-64.3: 検証後に symlink へ差し替えられても `O_NOFOLLOW` でリンク先を開かない。
    #[cfg(unix)]
    #[test]
    fn open_for_append_rejects_symlink_swapped_after_validation() {
        let t = TempDir::new("log-swap");
        let victim = t.file("victim.log");
        let before = std::fs::metadata(&victim).unwrap().len();
        let link = t.0.join("console.log");
        let log = ConsoleLogPath::try_new(&link).unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let err = log.open_for_append_excluding(&[]).unwrap_err();
        assert_eq!(err.code(), "config.console_log_is_symlink");
        assert_eq!(std::fs::metadata(&victim).unwrap().len(), before);
    }

    /// MAC-1・TASK-64.3: 検証後にログがディスクイメージへのハードリンクへ差し替えられても、
    /// 使用時点の fd 照合で拒否しイメージを変更しない。
    #[cfg(unix)]
    #[test]
    fn open_for_append_rejects_hardlink_to_disk_image_swapped_after_validation() {
        let t = TempDir::new("log-hardlink");
        let image = t.file("disk.img");
        let before = std::fs::read(&image).unwrap();
        let link = t.0.join("console.log");
        let log = ConsoleLogPath::try_new(&link).unwrap();
        let protected = [ProtectedInput {
            field: ConfigField::DiskImage,
            path: &image,
        }];
        std::fs::hard_link(&image, &link).unwrap();
        let err = log.open_for_append_excluding(&protected).unwrap_err();
        assert_eq!(err.code(), "config.console_log_conflicts_with_disk_image");
        assert_eq!(std::fs::read(&image).unwrap(), before);
    }

    /// MAC-1・TASK-64.3: 新規作成は 0600、既存内容は保持したまま追記される。
    #[cfg(unix)]
    #[test]
    fn open_console_log_creates_0600_and_appends() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("log-open");
        let path = t.0.join("console.log");
        let log = ConsoleLogPath::try_new(&path).unwrap();
        let mut f = log.open_for_append_excluding(&[]).unwrap();
        f.write_all(b"first\n").unwrap();
        drop(f);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut f = log.open_for_append_excluding(&[]).unwrap();
        f.write_all(b"second\n").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
    }

    /// MAC-1・TASK-64.3: 追加した variant の code と Display を具体値で固定する。
    #[test]
    fn device_error_codes_are_stable() {
        let e = ConfigError::TooManyBlockDevices { count: 9, max: 8 };
        assert_eq!(
            e.to_string(),
            "config.too_many_block_devices: 9 block devices requested, max is 8"
        );
        let e = ConfigError::BlockDeviceIdTooLong { len: 21, max: 20 };
        assert_eq!(
            e.to_string(),
            "config.block_device_id_too_long: block device id is 21 bytes, max is 20"
        );
        let e = ConfigError::ConsoleLogOpen {
            kind: std::io::ErrorKind::Other,
        };
        assert_eq!(e.code(), "config.console_log_open");
        let e = ConfigError::DiskAttachment {
            domain: "VZErrorDomain".to_string(),
            code: 2,
        };
        assert_eq!(
            e.to_string(),
            "config.disk_attachment: virtualization framework rejected the disk image (VZErrorDomain 2)"
        );
        let e = ConfigError::BlockDeviceIdRejected {
            domain: "VZErrorDomain".to_string(),
            code: 3,
        };
        assert_eq!(e.code(), "config.block_device_id_rejected");
    }

    /// MAC-1・TASK-64.3: macOS でデバイス付き設定を構築し、読み戻した値が入力と一致する。
    #[cfg(target_os = "macos")]
    #[test]
    fn builds_vz_configuration_with_devices_and_reads_back() {
        let t = TempDir::new("vz-dev");
        let k = t.file("vmlinux");
        let img = t.0.join("root.img");
        std::fs::write(&img, vec![0u8; 1024 * 1024]).unwrap();
        let log_path = t.0.join("console.log");
        let devices = DeviceConfigSpec::try_new(
            vec![with_id(disk(&img), "root")],
            Some(SerialConsoleSink::LogFile(
                ConsoleLogPath::try_new(&log_path).unwrap(),
            )),
        )
        .unwrap();
        let spec = VmConfigSpec::from_parts(&k, None, "console=hvc0 root=/dev/vda")
            .unwrap()
            .with_devices(devices)
            .unwrap();
        let cfg = match build_vz_configuration(&spec) {
            Ok(c) => c,
            Err(e) => panic!("build failed: {e}"),
        };
        let devs = cfg.block_devices();
        assert_eq!(devs.len(), 1);
        assert_eq!(
            devs[0].path.as_ref().and_then(|p| p.canonicalize().ok()),
            img.canonicalize().ok()
        );
        assert!(!devs[0].read_only);
        assert_eq!(devs[0].id, "root");
        assert_eq!(cfg.serial_port_count(), 1);
        assert!(log_path.exists());
    }

    /// テスト用の VM 設定仕様（kernel・initrd あり、デバイスなし）。
    fn spec_with_initrd(t: &TempDir) -> (VmConfigSpec, PathBuf, PathBuf) {
        let k = t.file("vmlinux");
        let i = t.file("initrd.img");
        let spec = VmConfigSpec::from_parts(&k, Some(&i), "console=hvc0").unwrap();
        (spec, k, i)
    }

    fn console_only(log: ConsoleLogPath) -> DeviceConfigSpec {
        DeviceConfigSpec::try_new(vec![], Some(SerialConsoleSink::LogFile(log))).unwrap()
    }

    /// MAC-1・TASK-64.3: ログ先が initrd と同一ファイルなら検証時に
    /// `config.console_log_conflicts_with_boot_file`（field = initrd）で拒否する。
    #[test]
    fn with_devices_rejects_console_log_same_as_initrd() {
        let t = TempDir::new("log-initrd");
        let (spec, _k, i) = spec_with_initrd(&t);
        let err = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&i).unwrap()))
            .unwrap_err();
        assert_eq!(
            err,
            ConfigError::ConsoleLogConflictsWithBootFile {
                field: ConfigField::Initrd,
                path: i.clone(),
            }
        );
        assert_eq!(err.code(), "config.console_log_conflicts_with_boot_file");
        assert_eq!(
            err.message(),
            format!(
                "console log is the same file as the initrd image: {}",
                i.display()
            )
        );
    }

    /// MAC-1・TASK-64.3: ログ先が kernel と同一ファイルなら検証時に拒否する（field = kernel）。
    #[test]
    fn with_devices_rejects_console_log_same_as_kernel() {
        let t = TempDir::new("log-kernel");
        let (spec, k, _i) = spec_with_initrd(&t);
        let err = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&k).unwrap()))
            .unwrap_err();
        assert_eq!(
            err,
            ConfigError::ConsoleLogConflictsWithBootFile {
                field: ConfigField::Kernel,
                path: k,
            }
        );
    }

    /// MAC-1・TASK-64.3: 未作成のログ先は検証を通り、照合対象と衝突しない。
    #[test]
    fn with_devices_accepts_new_console_log() {
        let t = TempDir::new("log-new");
        let (spec, _k, _i) = spec_with_initrd(&t);
        let log = ConsoleLogPath::try_new(t.0.join("console.log")).unwrap();
        let spec = spec.with_devices(console_only(log.clone())).unwrap();
        assert_eq!(
            spec.devices.serial_console(),
            Some(&SerialConsoleSink::LogFile(log))
        );
    }

    /// MAC-1・TASK-64.3: 検証後にログが initrd へのハードリンクへ差し替えられても、使用時点の
    /// fd 照合で拒否し initrd を変更しない（次回起動時の initramfs 注入の防止）。
    #[cfg(unix)]
    #[test]
    fn open_rejects_hardlink_to_initrd_swapped_after_validation() {
        let t = TempDir::new("log-initrd-swap");
        let (spec, _k, i) = spec_with_initrd(&t);
        let before = std::fs::read(&i).unwrap();
        let link = t.0.join("console.log");
        let spec = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&link).unwrap()))
            .unwrap();
        std::fs::hard_link(&i, &link).unwrap();
        let err = spec.open_serial_console_log().unwrap_err();
        assert_eq!(
            err,
            ConfigError::ConsoleLogConflictsWithBootFile {
                field: ConfigField::Initrd,
                path: link,
            }
        );
        assert_eq!(std::fs::read(&i).unwrap(), before);
    }

    /// MAC-1・TASK-64.3: 検証後にログが kernel へのハードリンクへ差し替えられても拒否する。
    #[cfg(unix)]
    #[test]
    fn open_rejects_hardlink_to_kernel_swapped_after_validation() {
        let t = TempDir::new("log-kernel-swap");
        let (spec, k, _i) = spec_with_initrd(&t);
        let link = t.0.join("console.log");
        let spec = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&link).unwrap()))
            .unwrap();
        std::fs::hard_link(&k, &link).unwrap();
        assert_eq!(
            spec.open_serial_console_log().unwrap_err().code(),
            "config.console_log_conflicts_with_boot_file"
        );
        assert_eq!(std::fs::read(&k).unwrap(), b"dummy");
    }

    /// MAC-1・TASK-64.3: ハードリンクが複数ある既存ファイルは検証時に `config.console_log_multiple_links`。
    #[cfg(unix)]
    #[test]
    fn console_log_with_multiple_links_rejected_at_validation() {
        let t = TempDir::new("log-nlink");
        let victim = t.file("victim.txt");
        let link = t.0.join("console.log");
        std::fs::hard_link(&victim, &link).unwrap();
        assert_eq!(
            ConsoleLogPath::try_new(&link).unwrap_err(),
            ConfigError::ConsoleLogMultipleLinks {
                path: link,
                links: 2,
            }
        );
    }

    /// MAC-1・TASK-64.3: 検証後に照合対象外のファイルへのハードリンクへ差し替えられても、
    /// 使用時点の fd のリンク数検査で拒否し、リンク先を変更しない。
    #[cfg(unix)]
    #[test]
    fn open_rejects_hardlink_created_after_validation() {
        let t = TempDir::new("log-nlink-swap");
        let victim = t.file("victim.txt");
        let link = t.0.join("console.log");
        let log = ConsoleLogPath::try_new(&link).unwrap();
        std::fs::hard_link(&victim, &link).unwrap();
        assert_eq!(
            log.open_for_append_excluding(&[]).unwrap_err(),
            ConfigError::ConsoleLogMultipleLinks {
                path: link,
                links: 2,
            }
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"dummy");
    }

    /// MAC-1・TASK-64.3: 所有者・リンク数の判定（root なしで uid 不一致を検査するため純粋関数で照合する）。
    #[cfg(unix)]
    #[test]
    fn log_ownership_judgement() {
        let p = Path::new("/var/log/console.log");
        assert_eq!(
            check_log_ownership(p, LogFileAttrs { nlink: 1, uid: 501 }, 501),
            Ok(())
        );
        let err = check_log_ownership(p, LogFileAttrs { nlink: 1, uid: 0 }, 501).unwrap_err();
        assert_eq!(
            err,
            ConfigError::ConsoleLogNotOwned {
                path: p.to_path_buf(),
                owner: 0,
                euid: 501,
            }
        );
        assert_eq!(
            err.to_string(),
            "config.console_log_not_owned: console log is owned by uid 0, expected effective uid 501: /var/log/console.log"
        );
        // リンク数を所有者より先に見る。
        let err = check_log_ownership(p, LogFileAttrs { nlink: 3, uid: 0 }, 501).unwrap_err();
        assert_eq!(
            err.to_string(),
            "config.console_log_multiple_links: console log has 3 hard links, expected 1: /var/log/console.log"
        );
    }

    /// MAC-1・TASK-64.3: 親ディレクトリのモード判定（他者書き込み可能かつ sticky なしのみ拒否）。
    #[cfg(unix)]
    #[test]
    fn parent_mode_judgement() {
        let p = Path::new("/srv/logs");
        let rejected = ConfigError::ConsoleLogParentWorldWritable {
            path: p.to_path_buf(),
        };
        assert_eq!(check_parent_mode(p, 0o40777), Err(rejected.clone()));
        assert_eq!(check_parent_mode(p, 0o40703), Err(rejected.clone()));
        assert_eq!(check_parent_mode(p, 0o41777), Ok(()));
        assert_eq!(check_parent_mode(p, 0o40775), Ok(()));
        assert_eq!(check_parent_mode(p, 0o40700), Ok(()));
        assert_eq!(
            rejected.to_string(),
            "config.console_log_parent_world_writable: console log parent directory is world-writable without the sticky bit: /srv/logs"
        );
    }

    /// MAC-1・TASK-64.3: 実ディレクトリでも、0777 の親は検証時・open 時とも拒否し、0777 + sticky は許可する。
    #[cfg(unix)]
    #[test]
    fn world_writable_parent_without_sticky_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("log-parent");
        let dir = t.0.join("shared");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("console.log");
        let log = ConsoleLogPath::try_new(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let rejected = ConfigError::ConsoleLogParentWorldWritable { path: dir.clone() };
        assert_eq!(ConsoleLogPath::try_new(&path).unwrap_err(), rejected);
        assert_eq!(log.open_for_append_excluding(&[]).unwrap_err(), rejected);
        assert!(!path.exists());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(ConsoleLogPath::try_new(&path).is_ok());
        assert!(log.open_for_append_excluding(&[]).is_ok());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// MAC-1・TASK-64.3: 自分が作成した単一リンクの既存ログは所有者・リンク数検査を通り、追記できる。
    #[cfg(unix)]
    #[test]
    fn existing_own_console_log_is_accepted() {
        use std::io::Write;
        let t = TempDir::new("log-own");
        let path = t.file("console.log");
        let log = ConsoleLogPath::try_new(&path).unwrap();
        let mut f = log.open_for_append_excluding(&[]).unwrap();
        f.write_all(b"+more").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&path).unwrap(), b"dummy+more");
    }

    /// MAC-1・TASK-64.3: 公開 API の open は上限つきの書き出しを返し、出力は検証済みログへ追記される。
    #[cfg(unix)]
    #[test]
    fn open_serial_console_writes_through_capped_sink() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("log-sink");
        let (spec, _k, _i) = spec_with_initrd(&t);
        let path = t.0.join("console.log");
        let spec = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&path).unwrap()))
            .unwrap();
        let mut sink = spec.open_serial_console().unwrap().expect("console sink");
        sink.writer()
            .write_all(b"[    0.000000] Linux version\n")
            .unwrap();
        let out = sink
            .finish(std::time::Duration::from_secs(10))
            .expect("writer thread finished");
        assert_eq!(out.written_bytes, 29);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"[    0.000000] Linux version\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let none = VmConfigSpec::from_parts(&t.file("k2"), None, "").unwrap();
        assert!(none.open_serial_console().unwrap().is_none());
    }

    /// MAC-1・TASK-64.3: 書き出し中の同じログを別の VM 構成が開くと `config.console_log_in_use` で拒否する
    /// （上限の二重使用によるディスク枯渇の防止）。
    #[cfg(unix)]
    #[test]
    fn open_serial_console_rejects_log_in_use() {
        let t = TempDir::new("log-inuse");
        let (spec, _k, _i) = spec_with_initrd(&t);
        let path = t.0.join("console.log");
        let spec = spec
            .with_devices(console_only(ConsoleLogPath::try_new(&path).unwrap()))
            .unwrap();
        let first = spec.open_serial_console().unwrap().expect("console sink");
        let err = spec.open_serial_console().unwrap_err();
        assert_eq!(err, ConfigError::ConsoleLogInUse { path: path.clone() });
        assert_eq!(
            err.to_string(),
            format!(
                "config.console_log_in_use: console log is in use by another virtual machine: {}",
                path.display()
            )
        );
        first
            .finish(std::time::Duration::from_secs(10))
            .expect("writer thread finished");
        assert!(spec.open_serial_console().unwrap().is_some());
    }

    /// MAC-1・TASK-64.3: 親ディレクトリ自体が symlink なら検証時・open 時とも
    /// `config.console_log_parent_is_symlink` で拒否し、リンク先にファイルを作らない。
    #[cfg(unix)]
    #[test]
    fn console_log_parent_symlink_is_rejected() {
        let t = TempDir::new("log-parent-sym");
        let real = t.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let rejected = ConfigError::ConsoleLogParentIsSymlink { path: link.clone() };
        assert_eq!(
            ConsoleLogPath::try_new(link.join("console.log")).unwrap_err(),
            rejected
        );
        assert_eq!(
            rejected.to_string(),
            format!(
                "config.console_log_parent_is_symlink: console log parent directory must not be a symlink: {}",
                link.display()
            )
        );
        // 検証後に親が symlink へ差し替えられた場合も open 時に拒否する。
        let swapped = t.0.join("swapped");
        std::fs::create_dir(&swapped).unwrap();
        let log = ConsoleLogPath::try_new(swapped.join("console.log")).unwrap();
        std::fs::remove_dir(&swapped).unwrap();
        std::os::unix::fs::symlink(&real, &swapped).unwrap();
        assert_eq!(
            log.open_for_append_excluding(&[]).unwrap_err(),
            ConfigError::ConsoleLogParentIsSymlink { path: swapped }
        );
        assert!(!real.join("console.log").exists());
    }
}
