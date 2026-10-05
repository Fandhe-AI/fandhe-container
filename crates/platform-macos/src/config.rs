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
//! virtiofs 共有（TASK-65.1）は [`VmConfigSpec::shares`]（`crate::virtiofs`）で表し、
//! [`build_vz_configuration`] が `VZVirtioFileSystemDeviceConfiguration` として VM 構成へ追加する。
//!
//! 呼び出し文脈: TASK-64.4 が構築済み設定から `VZVirtualMachine` を生成して起動し、ゲストの
//! `console=hvc0` 出力をコンソールログから確認する（TASK-64.6 の vm_boot 結合試験）。[`ConfigError`] は
//! `error::PlatformError`（TASK-64.5）に包まれて返る。検証後〜起動までの TOCTOU（ファイル差し替え）は残るため、
//! 起動時の読み込み失敗は TASK-64.4/64.5 のエラー経路で扱う。kernel / initrd / ディスクイメージの配置
//! ディレクトリは他者書き込み不可であることを前提とする（他者が差し替えられる場所に置かない）。
//! コンソールログの open は `O_NOFOLLOW` で最終パス要素の symlink 追従を open 時点で拒否し、
//! open 後に fd と lstat の `(dev, ino)` も照合する（事前検査〜open 間の symlink 差し替えを塞ぐ）。
//! 新規作成は `O_CREAT | O_EXCL` で行い、既存ファイルは作成フラグなしで開く。open 後の fd が
//! kernel / initrd / ディスクイメージと同一ファイルなら拒否し（initrd への追記は次回起動時の
//! initramfs 注入になり得る）、リンク数が 1 でない・所有者が実効 uid でない・group / other が読み書き
//! できるファイルも拒否する。
//!
//! 信頼前提（fail-closed で検査しない範囲）: 直近の親ディレクトリは symlink なら拒否し（macOS の `/tmp`
//! 等は呼び出し側が実体パスへ正規化して渡す）、「他者書き込み可能かつ sticky bit なし」なら拒否するが、
//! group 書き込み可は group メンバーを信頼するものとして許可する。祖先ディレクトリ要素（親より上）の
//! 差し替えは対象外で、呼び出し側の配置ディレクトリの権限管理に委ねる。既存ログファイルは group / other
//! が読み書きできるモードなら拒否する（モードは変更しない）。権限を狭める前から他者が開いていた fd 経由の
//! 書き込みは対象外。

use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use crate::virtiofs::VirtiofsSharesSpec;

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
    /// virtiofs で共有するホストディレクトリ（TASK-65.1）。
    SharedDirectory,
}

impl ConfigField {
    fn as_str(self) -> &'static str {
        match self {
            ConfigField::Kernel => "kernel",
            ConfigField::Initrd => "initrd",
            ConfigField::DiskImage => "disk_image",
            ConfigField::ConsoleLog => "console_log",
            ConfigField::SharedDirectory => "shared_directory",
        }
    }
}

/// 共有（ReadWrite・ReadOnly 共通）で拒否する特殊ファイルの種別（[`ConfigError::SharedDirSpecialFile`]。TASK-65.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecialFileKind {
    /// キャラクタデバイス。
    CharDevice,
    /// ブロックデバイス。
    BlockDevice,
    /// FIFO（名前付きパイプ）。
    Fifo,
}

impl SpecialFileKind {
    /// メッセージ用の英語名。
    pub fn as_str(self) -> &'static str {
        match self {
            SpecialFileKind::CharDevice => "character device",
            SpecialFileKind::BlockDevice => "block device",
            SpecialFileKind::Fifo => "fifo",
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
    /// 既存のコンソールログを group / other が読み書きできる（`mode` は権限ビット）。
    ConsoleLogInsecureMode { path: PathBuf, mode: u32 },
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
    /// virtiofs 共有タグが空（TASK-65.1）。
    VirtiofsTagEmpty,
    /// virtiofs 共有タグが上限を超えた。
    VirtiofsTagTooLong { len: usize, max: usize },
    /// virtiofs 共有タグに許可外の文字がある（`index` はバイト位置）。
    VirtiofsTagInvalidChar { index: usize },
    /// VZ が virtiofs 共有タグを拒否した（NSError の domain / code）。
    VirtiofsTagRejected { domain: String, code: isize },
    /// virtiofs 共有タグ（大文字小文字非区別）が重複した。
    DuplicateVirtiofsTag { tag: String },
    /// ゲスト mount point が `GUEST_MOUNT_BASE` 配下でない（MAC-1・TASK-65.3）。
    GuestMountPointNotUnderBase,
    /// ゲスト mount point に許可外の要素・文字がある（`index` はバイト位置）。
    GuestMountPointInvalid { index: usize },
    /// ゲスト mount point が長さの上限を超えた。
    GuestMountPointTooLong { len: usize, max: usize },
    /// ゲスト mount point が他の共有と重複または入れ子になっている。
    DuplicateGuestMountPoint { path: String },
    /// ゲスト mount 指定があるのにシリアルコンソールがなく、結果を検証できない（fail-closed）。
    GuestMountRequiresConsole,
    /// ユーザー指定のコマンドラインに予約キー（`fandhe.` 始まり）のトークンがある（`index` はバイト位置）。
    CommandLineReservedKey { index: usize },
    /// virtiofs 共有数が上限を超えた。
    TooManyVirtiofsShares { count: usize, max: usize },
    /// 共有ディレクトリがディレクトリでない。
    SharedDirNotDirectory { path: PathBuf },
    /// 共有ディレクトリのパス要素に symlink が含まれる（`path` は最初に見つかった symlink）。
    SharedDirSymlink { path: PathBuf },
    /// 共有ディレクトリのパスに `.` / `..` が含まれる。
    SharedDirNotNormalized { path: PathBuf },
    /// 共有ディレクトリがファイルシステムのルート。
    SharedDirIsRoot,
    /// 共有（ReadWrite・ReadOnly 共通）の配下に別のファイルシステムのマウントポイントがある
    /// （`path` は最初に見つかった境界）。
    ///
    /// 共有範囲の外のホスト領域がゲストへ公開されるのを防ぐ（MAC-1・SEC-4・TASK-65.1）。
    SharedDirCrossesMount { path: PathBuf, share_dir: PathBuf },
    /// 共有（ReadWrite・ReadOnly 共通）の配下にある symlink のリンク先が、共有範囲内に収まることを確認できない
    /// （範囲外を指す・リンク先の親まで解決できない。`path` は symlink 自身のパス）。
    ///
    /// virtiofs サーバのホスト側での symlink の扱いを検証できないため、範囲外への書き込み経路になり得る
    /// 構成を fail-closed で拒否する（範囲外の読み出し・書き込み経路。MAC-1・SEC-4・TASK-65.1）。
    SharedDirSymlinkEscapes { path: PathBuf, share_dir: PathBuf },
    /// 共有（ReadWrite・ReadOnly 共通）の配下に、リンク数が 2 以上の通常ファイル（ハードリンク）がある（`links` はリンク数）。
    ///
    /// 他のリンクが共有範囲外にあるかを確かめられないため、ゲストがリンクを辿らずに範囲外と同じ inode を
    /// 読み書きできる経路として fail-closed で拒否する（MAC-1・TASK-65.1）。
    SharedDirHardlinkedFile {
        path: PathBuf,
        links: u64,
        share_dir: PathBuf,
    },
    /// 共有（ReadWrite・ReadOnly 共通）の配下に、許可しない特殊ファイル（キャラクタ / ブロックデバイス・FIFO）がある。
    SharedDirSpecialFile {
        path: PathBuf,
        kind: SpecialFileKind,
        share_dir: PathBuf,
    },
    /// 共有（ReadWrite・ReadOnly 共通）がディレクトリのハードリンクを作れるファイルシステム（HFS+）上にある（macOS）。
    ///
    /// ディレクトリのハードリンクはリンク数で見分けられず、共有範囲外のディレクトリを配下に持ち込めるため
    /// fail-closed で拒否する（MAC-1・TASK-65.1）。`fs_type` は `statfs` の `f_fstypename`。
    SharedDirUnsupportedFilesystem { fs_type: String, share_dir: PathBuf },
    /// 読み書き共有が VM の保護入力（kernel・initrd・ディスクイメージ・コンソールログ）を含む。
    ///
    /// `field` は保護入力の種別、`path` はその実体パス、`share_dir` は共有ディレクトリ。
    SharedDirContainsProtectedInput {
        field: ConfigField,
        path: PathBuf,
        share_dir: PathBuf,
    },
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
            ConfigError::ConsoleLogInsecureMode { .. } => "config.console_log_insecure_mode",
            ConfigError::ConsoleLogParentWorldWritable { .. } => {
                "config.console_log_parent_world_writable"
            }
            ConfigError::ConsoleLogParentIsSymlink { .. } => "config.console_log_parent_is_symlink",
            ConfigError::ConsoleLogOpen { .. } => "config.console_log_open",
            ConfigError::ConsoleLogWriter { .. } => "config.console_log_writer",
            ConfigError::ConsoleLogInUse { .. } => "config.console_log_in_use",
            ConfigError::DiskAttachment { .. } => "config.disk_attachment",
            ConfigError::BlockDeviceIdRejected { .. } => "config.block_device_id_rejected",
            ConfigError::VirtiofsTagEmpty => "config.virtiofs_tag_empty",
            ConfigError::VirtiofsTagTooLong { .. } => "config.virtiofs_tag_too_long",
            ConfigError::VirtiofsTagInvalidChar { .. } => "config.virtiofs_tag_invalid_char",
            ConfigError::VirtiofsTagRejected { .. } => "config.virtiofs_tag_rejected",
            ConfigError::DuplicateVirtiofsTag { .. } => "config.duplicate_virtiofs_tag",
            ConfigError::GuestMountPointNotUnderBase => "config.guest_mount_point_not_under_base",
            ConfigError::GuestMountPointInvalid { .. } => "config.guest_mount_point_invalid",
            ConfigError::GuestMountPointTooLong { .. } => "config.guest_mount_point_too_long",
            ConfigError::DuplicateGuestMountPoint { .. } => "config.duplicate_guest_mount_point",
            ConfigError::GuestMountRequiresConsole => "config.guest_mount_requires_console",
            ConfigError::CommandLineReservedKey { .. } => "config.command_line_reserved_key",
            ConfigError::TooManyVirtiofsShares { .. } => "config.too_many_virtiofs_shares",
            ConfigError::SharedDirNotDirectory { .. } => "config.shared_dir_not_directory",
            ConfigError::SharedDirSymlink { .. } => "config.shared_dir_symlink",
            ConfigError::SharedDirNotNormalized { .. } => "config.shared_dir_not_normalized",
            ConfigError::SharedDirIsRoot => "config.shared_dir_is_root",
            ConfigError::SharedDirContainsProtectedInput { .. } => {
                "config.shared_dir_contains_protected_input"
            }
            ConfigError::SharedDirCrossesMount { .. } => "config.shared_dir_crosses_mount",
            ConfigError::SharedDirSymlinkEscapes { .. } => "config.shared_dir_symlink_escapes",
            ConfigError::SharedDirHardlinkedFile { .. } => "config.shared_dir_hardlinked_file",
            ConfigError::SharedDirSpecialFile { .. } => "config.shared_dir_special_file",
            ConfigError::SharedDirUnsupportedFilesystem { .. } => {
                "config.shared_dir_unsupported_filesystem"
            }
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
            ConfigError::ConsoleLogInsecureMode { path, mode } => {
                format!(
                    "console log mode {mode:o} allows group or other access, expected 600: {}",
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
            ConfigError::VirtiofsTagEmpty => "virtiofs tag must not be empty".to_string(),
            ConfigError::VirtiofsTagTooLong { len, max } => {
                format!("virtiofs tag is {len} bytes, max is {max}")
            }
            ConfigError::VirtiofsTagInvalidChar { index } => {
                format!(
                    "virtiofs tag has a disallowed character at byte {index} (allowed: ASCII letters, digits, '.', '_', '-')"
                )
            }
            ConfigError::VirtiofsTagRejected { domain, code } => {
                format!("virtualization framework rejected the virtiofs tag ({domain} {code})")
            }
            ConfigError::GuestMountPointNotUnderBase => format!(
                "guest mount point must be under {}/",
                crate::guest_mount::GUEST_MOUNT_BASE
            ),
            ConfigError::GuestMountPointInvalid { index } => format!(
                "guest mount point has an invalid element or character at byte {index} (allowed: ASCII letters, digits, '.', '_', '-'; '.' and '..' are not allowed)"
            ),
            ConfigError::GuestMountPointTooLong { len, max } => {
                format!("guest mount point is {len} bytes (or has too many elements), max is {max}")
            }
            ConfigError::DuplicateGuestMountPoint { path } => {
                format!("guest mount point is duplicated or nested: {path}")
            }
            ConfigError::GuestMountRequiresConsole => {
                "guest mount requires a serial console to verify the result".to_string()
            }
            ConfigError::CommandLineReservedKey { index } => {
                format!("kernel command line has a reserved 'fandhe.' key at byte {index}")
            }
            ConfigError::DuplicateVirtiofsTag { tag } => {
                format!("virtiofs tag is used more than once: {tag}")
            }
            ConfigError::TooManyVirtiofsShares { count, max } => {
                format!("{count} virtiofs shares requested, max is {max}")
            }
            ConfigError::SharedDirNotDirectory { path } => {
                format!("shared directory is not a directory: {}", path.display())
            }
            ConfigError::SharedDirSymlink { path } => {
                format!(
                    "shared directory path must not contain a symlink: {}",
                    path.display()
                )
            }
            ConfigError::SharedDirNotNormalized { path } => {
                format!(
                    "shared directory path must not contain '.' or '..': {}",
                    path.display()
                )
            }
            ConfigError::SharedDirIsRoot => {
                "sharing the filesystem root is not allowed".to_string()
            }
            ConfigError::SharedDirCrossesMount { path, share_dir } => {
                format!(
                    "shared directory {} contains a mount point: {}",
                    share_dir.display(),
                    path.display()
                )
            }
            ConfigError::SharedDirHardlinkedFile {
                path,
                links,
                share_dir,
            } => {
                format!(
                    "shared directory {} contains a hard-linked file ({links} links): {} (hint: replace hard links with copies, e.g. pnpm install --package-import-method=copy or git clone --no-hardlinks)",
                    share_dir.display(),
                    path.display()
                )
            }
            ConfigError::SharedDirSpecialFile {
                path,
                kind,
                share_dir,
            } => {
                format!(
                    "shared directory {} contains a {}: {}",
                    share_dir.display(),
                    kind.as_str(),
                    path.display()
                )
            }
            ConfigError::SharedDirUnsupportedFilesystem { fs_type, share_dir } => {
                format!(
                    "shared directory {} is on a {fs_type} filesystem, which allows directory hard links (hint: share a directory on an APFS volume)",
                    share_dir.display()
                )
            }
            ConfigError::SharedDirSymlinkEscapes { path, share_dir } => {
                format!(
                    "shared directory {} contains a symlink whose target is not confirmed to stay inside it: {} (hint: use relative symlinks that stay inside the share, or replace symlinks with copies)",
                    share_dir.display(),
                    path.display()
                )
            }
            ConfigError::SharedDirContainsProtectedInput {
                field,
                path,
                share_dir,
            } => {
                format!(
                    "read-write shared directory {} contains protected {} input: {}",
                    share_dir.display(),
                    field.as_str(),
                    path.display()
                )
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
pub(crate) fn check_absolute_utf8(field: ConfigField, path: &Path) -> Result<(), ConfigError> {
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
                            mode: _m.mode(),
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
                mode: fd_meta.mode(),
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

/// 包含検査用に symlink を解決した実体パスを返す。パス自体が解決できなければ親を解決して補い、
/// それも失敗したら元のパスを返す（コンソールログは未作成でもあり得るため）。
fn resolve_for_containment(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
        && let Ok(real_parent) = std::fs::canonicalize(parent)
    {
        return real_parent.join(name);
    }
    path.to_path_buf()
}

/// 照合対象の種別に応じた衝突エラー（`path` はコンソールログ側のパス）。
fn conflict_error(field: ConfigField, path: &Path) -> ConfigError {
    match field {
        ConfigField::Kernel | ConfigField::Initrd => ConfigError::ConsoleLogConflictsWithBootFile {
            field,
            path: path.to_path_buf(),
        },
        // ConsoleLog / SharedDirectory は照合対象に来ない（`protected_inputs` は Kernel / Initrd / DiskImage だけを生成する）。
        // match を網羅するための腕で、ディスクイメージとの衝突として扱う。
        ConfigField::DiskImage | ConfigField::ConsoleLog | ConfigField::SharedDirectory => {
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
    mode: u32,
}

/// group / other の読み書きビット（`S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH`。値は POSIX 共通）。
#[cfg(unix)]
const MODE_GROUP_OTHER_RW: u32 = 0o066;

/// リンク数 1・所有者が `euid`・group / other が読み書きできないことを検査する（MAC-1・TASK-64.3）。
///
/// ハードリンクが複数あるファイル（他所の重要ファイルの別名かもしれない）・他ユーザーが事前作成した
/// ファイル・他者が読み書きできるファイル（ゲスト出力の漏えいと、外部からの追記・切り詰めで上限を維持
/// できない）へは追記しない。リンク数 → 所有者 → モードの順に見る。モードは変更しない（拒否のみ。
/// 呼び出し側が `chmod 600` 等で直す）。
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
    if attrs.mode & MODE_GROUP_OTHER_RW != 0 {
        return Err(ConfigError::ConsoleLogInsecureMode {
            path: path.to_path_buf(),
            mode: attrs.mode & 0o7777,
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

/// ハードリンク検査で走査する共有配下のエントリ数の上限（無制限走査による DoS の防止）。
#[cfg(unix)]
const MAX_SHARE_SCAN_ENTRIES: usize = 1_000_000;

/// エントリのデバイス番号が共有ルートと異なれば、マウント境界を越えている。
#[cfg(unix)]
fn crosses_mount(root_dev: u64, entry_dev: u64) -> bool {
    root_dev != entry_dev
}

/// `/proc/self/mountinfo` の読み込み上限（無制限確保の防止。超えたら fail-closed で拒否する）。
#[cfg(target_os = "linux")]
const MAX_MOUNTINFO_BYTES: u64 = 16 * 1024 * 1024;

/// `/proc/self/mountinfo` の `mountpoint` 欄（8 進エスケープ `\040` 等）を元のバイト列へ戻す。
///
/// `fandhe-container-net` の `netns.rs` と同じ流儀の最小実装（crate をまたいで非公開関数を共有しないため
/// 本 crate に置く）。
#[cfg(target_os = "linux")]
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'\\'
            && let Some(oct) = b.get(i + 1..i + 4)
            && oct.iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let v = oct
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `mountinfo`（`/proc/self/mountinfo` の内容）上で、`dir` の真の配下にあるマウントポイントを返す
/// （OS 呼び出しを含まない純粋関数）。`dir` 自身がマウントポイントなのは対象外。比較は要素単位
/// （`/x/share2` を `/x/share` の配下と誤判定しない）。欄が欠けた行は読み飛ばす。
#[cfg(target_os = "linux")]
fn mount_point_under(mountinfo: &str, dir: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    mountinfo.lines().find_map(|line| {
        let field = line.split_ascii_whitespace().nth(4)?;
        let mp = PathBuf::from(std::ffi::OsStr::from_bytes(&unescape_mountinfo(field)));
        (mp != dir && mp.starts_with(dir)).then_some(mp)
    })
}

/// 共有ルート `dir` の配下にあるマウントを、マウント表から検出して拒否する（MAC-1・TASK-65.1）。
///
/// `st_dev` の比較だけでは、同一ファイルシステム上の別ディレクトリの bind mount（同じ `st_dev`）を
/// 見分けられない。Linux は `/proc/self/mountinfo` のマウントポイントを列挙して判定する。
#[cfg(target_os = "linux")]
fn reject_mounts_under(dir: &Path) -> Result<(), ConfigError> {
    use std::io::Read;
    let io_err = |e: std::io::Error| ConfigError::PathIo {
        field: ConfigField::SharedDirectory,
        kind: e.kind(),
    };
    let mut raw = Vec::new();
    std::fs::File::open("/proc/self/mountinfo")
        .map_err(io_err)?
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(io_err)?;
    if u64::try_from(raw.len()).map_or(true, |n| n > MAX_MOUNTINFO_BYTES) {
        return Err(ConfigError::PathIo {
            field: ConfigField::SharedDirectory,
            kind: std::io::ErrorKind::Other,
        });
    }
    match mount_point_under(&String::from_utf8_lossy(&raw), dir) {
        Some(path) => Err(ConfigError::SharedDirCrossesMount {
            path,
            share_dir: dir.to_path_buf(),
        }),
        None => Ok(()),
    }
}

/// macOS はマウント表を列挙せず、走査中のディレクトリごとに `statfs(2)` のマウント識別子
/// （`f_fsid`・`f_mntonname`）を共有ルートと比較する（[`find_hardlink_to_protected`]）。ここでは何もしない。
#[cfg(target_os = "macos")]
fn reject_mounts_under(_dir: &Path) -> Result<(), ConfigError> {
    Ok(())
}

/// Linux・macOS 以外の unix はマウント境界を確かめる手段を持たないため、fail-closed で拒否する。
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn reject_mounts_under(_dir: &Path) -> Result<(), ConfigError> {
    Err(ConfigError::PathIo {
        field: ConfigField::SharedDirectory,
        kind: std::io::ErrorKind::Unsupported,
    })
}

/// 共有（ReadWrite・ReadOnly 共通）配下の symlink `link` のリンク先が、共有範囲 `dir`（symlink を解決済みの実体パス）に
/// 収まることを確認する（MAC-1・TASK-65.1。AGENTS.md の rootfs・マウント・ボリューム境界）。
///
/// 背景: FUSE（virtiofs）では symlink はゲストの VFS が `FUSE_READLINK` でリンク先文字列を受け取って
/// ゲストの名前空間で解決する（Linux `fs/fuse/dir.c` の `fuse_get_link`）。一方、Virtualization.framework
/// の virtiofs サーバ（ホスト側）は非公開実装で、侵害されたゲストカーネルが symlink の nodeid へ直接
/// 要求を送った場合にホスト上でリンクを辿らないことは文書化されておらず検証できない。そのため
/// ホスト視点でリンク先を解決し、範囲外なら [`ConfigError::SharedDirSymlinkEscapes`] で拒否する
/// （fail-closed）。絶対パスの symlink もホスト視点で判定するため、ゲスト内では無害なもの（Python venv の
/// `bin/python -> /usr/bin/python3` 等）も範囲外として拒否する保守的な判定になる。
///
/// - リンク先が実在する: 全段の symlink を解決した実体パスが `dir` 配下であることを要素単位・大文字小文字
///   区別で照合する（`dir` も実体パスのため綴りが揃う。大小無視の照合は範囲外を範囲内と誤判定し得る）。
/// - リンク先が未作成（dangling）: リンク先の親ディレクトリを解決し、それが `dir` 配下で、最終要素が
///   通常の名前（`..` でない）なら許可する。親まで解決できなければ範囲を確認できないため拒否する。
/// - それ以外の解決失敗（ループ・権限等）は `PathIo` で fail-closed にする。
///
/// 残余（検査では防げない）: 検査から VM 起動・使用までの間のホスト側での差し替え（TOCTOU）と、
/// ゲストが実行時に `FUSE_SYMLINK` で新たに作る symlink。後者はホスト側サーバがリンクを辿らないことに依存する。
#[cfg(unix)]
fn check_symlink_within_share(link: &Path, dir: &Path) -> Result<(), ConfigError> {
    let escapes = || ConfigError::SharedDirSymlinkEscapes {
        path: link.to_path_buf(),
        share_dir: dir.to_path_buf(),
    };
    let io_err = |e: std::io::Error| ConfigError::PathIo {
        field: ConfigField::SharedDirectory,
        kind: e.kind(),
    };
    match std::fs::canonicalize(link) {
        Ok(real) if real.starts_with(dir) => Ok(()),
        Ok(_) => Err(escapes()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let target = std::fs::read_link(link).map_err(io_err)?;
            // 走査は実ディレクトリだけを辿るため、`link` の親は symlink を経由しない実体パス。
            // 絶対パスの `target` は `join` で置き換わる。
            let full = link.parent().ok_or_else(escapes)?.join(target);
            let (Some(parent), Some(_)) = (full.parent(), full.file_name()) else {
                return Err(escapes());
            };
            match std::fs::canonicalize(parent) {
                Ok(real_parent) if real_parent.starts_with(dir) => Ok(()),
                Ok(_) => Err(escapes()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(escapes()),
                Err(e) => Err(io_err(e)),
            }
        }
        Err(e) => Err(io_err(e)),
    }
}

/// 共有ルートのファイルシステム種別（`statfs` の `f_fstypename`）が、ディレクトリのハードリンクを作れる
/// HFS+（`hfs`）なら拒否する（macOS。リンク数では見分けられないため fail-closed。MAC-1・TASK-65.1）。
#[cfg(any(target_os = "macos", test))]
fn check_share_fs_type(fs_type: &[u8], dir: &Path) -> Result<(), ConfigError> {
    if fs_type.eq_ignore_ascii_case(b"hfs") {
        return Err(ConfigError::SharedDirUnsupportedFilesystem {
            fs_type: String::from_utf8_lossy(fs_type).into_owned(),
            share_dir: dir.to_path_buf(),
        });
    }
    Ok(())
}

/// 共有（ReadWrite・ReadOnly 共通）の配下で拒否する特殊ファイルの種別を返す（拒否しないものは `None`）。
///
/// - キャラクタ / ブロックデバイス: 拒否する。FUSE ではゲストが自分のデバイスとして開く
///   （Linux `fs/fuse/inode.c` の `fuse_init_inode` → `init_special_inode`）が、共有経由で任意の
///   major / minor のデバイスノードを持ち込めるため。
/// - FIFO: 拒否する。正常なゲストカーネルはゲスト内で完結させるが、侵害されたゲストカーネルが
///   `FUSE_OPEN` を送った場合に、ホスト側サーバがホスト上の FIFO を開くか（ホストのプロセスとの経路・
///   読み書き待ちでの停止）を確かめられないため。ReadOnly 共有でも読み出しの open だけで待ちに入り得る
///   （ホストサーバの停止）ため、書き込み権とは無関係に拒否する。デバイスも共有の RO 指定に関係なく
///   ゲスト側で任意の major / minor として開けるため同様に拒否する。
/// - ソケット: 許可する。`open(2)` はソケットに対して `ENXIO` で失敗し、FUSE には `connect` に当たる
///   要求が無いため、ホスト上のソケットへ届く経路が無い。git の fsmonitor が `.git` 配下に置く
///   ソケット等を含む開発用ディレクトリを共有できるようにする。
#[cfg(unix)]
fn special_file_kind(ft: &std::fs::FileType) -> Option<SpecialFileKind> {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_char_device() {
        Some(SpecialFileKind::CharDevice)
    } else if ft.is_block_device() {
        Some(SpecialFileKind::BlockDevice)
    } else if ft.is_fifo() {
        Some(SpecialFileKind::Fifo)
    } else {
        None
    }
}

/// 共有（ReadWrite・ReadOnly 共通）の配下を走査し、保護入力と同一 inode（`(dev, ino)` 一致）のエントリがあれば拒否する。
///
/// パスの包含検査（[`crate::virtiofs::path_is_within`]）では、共有の外にある保護入力へのハードリンクを
/// 共有内に置かれると検出できず、ゲストが同じ inode を書き換えられる（MAC-1・TASK-65.1。
/// AGENTS.md の rootfs・マウント・ボリューム境界）。共有配下を symlink を辿らずに走査して照合する。
/// 共有配下にルートと異なる `st_dev` のエントリ（マウントポイント）があれば
/// [`ConfigError::SharedDirCrossesMount`] で拒否する（別ホスト領域の ReadWrite 公開防止）。
/// 同一デバイス上の別マウント（Linux の bind mount・macOS の nullfs 等）は `st_dev` が同じため、
/// Linux はマウント表（[`reject_mounts_under`]）、macOS はディレクトリごとの `statfs(2)` のマウント識別子で
/// 検出する。検査後に新たにマウントされる TOCTOU は残る。
/// ReadOnly 共有では `protected` を空で呼ぶ（保護入力の包含は ReadWrite 限定の検査）が、残りの共有範囲外
/// 経路の検査は同じ厳しさで行う。`nlink > 1` のファイルは他のリンクの位置を確かめられず、範囲外 inode の
/// 内容を読み出しで露出し得るため RO でも fail-closed で拒否する（ハードリンクを多用するツリーの RO 共有が
/// できなくなる利便性コストは受け入れる）。MAC-1・SEC-4・TASK-65.1 追補。
/// 共有配下の symlink はリンク先が共有範囲に収まることを [`check_symlink_within_share`] で確認し、
/// 確認できなければ [`ConfigError::SharedDirSymlinkEscapes`] で拒否する（範囲外への読み書き経路の防止）。
/// 保護入力以外でも、リンク数 2 以上の通常ファイルは [`ConfigError::SharedDirHardlinkedFile`]、
/// キャラクタ / ブロックデバイス・FIFO は [`ConfigError::SharedDirSpecialFile`]（[`special_file_kind`]）、
/// macOS の HFS+ 上の共有は [`ConfigError::SharedDirUnsupportedFilesystem`] で拒否する。
/// 残余（#1374 で暫定判断。symlink・ハードリンクの実機確認は人間担当で未完了。REPAIR-3・REPAIR-5）:
/// - 拒否範囲は緩めない（fail-closed）。侵害ゲストが symlink の nodeid へ直接 FUSE 要求を送る脅威は
///   正常ゲストの観測では否定できないため、緩和は実機結果とユーザー判断を経た別 PR に限る。
/// - 検査〜VM 使用間の差し替え（TOCTOU）は `build_vz_configuration` で VZ 呼び出し直前に検査する以上の
///   安価な短縮策が無く、残余リスクとして受け入れる。根本対策は VZ の API 制約上、別途設計が要る。
/// - `canonicalize`・`statfs`・走査にタイムアウトは無く、応答しない NFS・autofs 等の配下では検査が止まり得る
///   （ブロック中の呼び出しは取り消せない）。ネットワーク / 自動マウント系 FS 上の ReadWrite 共有を
///   `f_fstypename` で拒否する案はフォローアップ候補で、未実装。
///
/// 保護入力が未作成（コンソールログ等）なら照合対象から外す。走査の I/O 失敗・件数上限超過は
/// fail-closed で `PathIo` を返す。unix 限定（Windows には `(dev, ino)` が無く、本 crate の
/// 実行対象は macOS のため走査しない）。`check_share_conflicts` から呼ばれる。
#[cfg(unix)]
fn find_hardlink_to_protected(
    dir: &Path,
    protected: &[(ConfigField, PathBuf)],
) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let io_err = |e: std::io::Error| ConfigError::PathIo {
        field: ConfigField::SharedDirectory,
        kind: e.kind(),
    };
    let mut ids: Vec<(ConfigField, PathBuf, (u64, u64))> = Vec::new();
    for (field, path) in protected {
        match std::fs::metadata(path) {
            Ok(m) => ids.push((*field, path.clone(), (m.dev(), m.ino()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ConfigError::PathIo {
                    field: *field,
                    kind: e.kind(),
                });
            }
        }
    }
    // 同一デバイスの bind mount をマウント表で検出する（Linux。macOS は下の走査で statfs により検出）。
    reject_mounts_under(dir)?;
    // マウント境界の検出用に共有ルートのデバイス番号を控える（保護入力の有無に依らず走査する）。
    let root_dev = std::fs::metadata(dir).map_err(io_err)?.dev();
    // macOS: 共有ルートのマウント識別子（`f_fsid`・`f_mntonname`）。同一デバイスの別マウント検出用。
    #[cfg(target_os = "macos")]
    let root_mount = crate::sys::mount_identity(dir).map_err(io_err)?;
    // macOS: HFS+ はディレクトリのハードリンクを作れ、リンク数では見分けられない。走査中のディレクトリは
    // すべて共有ルートと同じマウント（下で照合）なので、共有ルートの種別だけで判定して拒否する。
    #[cfg(target_os = "macos")]
    check_share_fs_type(root_mount.fs_type(), dir)?;
    let mut stack = vec![dir.to_path_buf()];
    let mut scanned = 0usize;
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(io_err)? {
            let entry = entry.map_err(io_err)?;
            scanned += 1;
            if scanned > MAX_SHARE_SCAN_ENTRIES {
                return Err(ConfigError::PathIo {
                    field: ConfigField::SharedDirectory,
                    kind: std::io::ErrorKind::Other,
                });
            }
            // symlink は走査で辿らない（共有外を走査に含めない）。リンク先の範囲は下で別途検証する。
            let meta = std::fs::symlink_metadata(entry.path()).map_err(io_err)?;
            // 共有ルートと異なるデバイスのエントリはマウントポイント（別領域）。辿らず拒否する。
            if crosses_mount(root_dev, meta.dev()) {
                return Err(ConfigError::SharedDirCrossesMount {
                    path: entry.path(),
                    share_dir: dir.to_path_buf(),
                });
            }
            if meta.file_type().is_symlink() {
                check_symlink_within_share(&entry.path(), dir)?;
            } else if meta.is_dir() {
                // macOS の mount(2) はディレクトリにだけマウントできるため、識別子の照合はディレクトリに限る。
                // `statfs` は symlink を辿るが、ここに来るのは symlink でない実ディレクトリだけ。
                #[cfg(target_os = "macos")]
                if crate::sys::mount_identity(&entry.path()).map_err(io_err)? != root_mount {
                    return Err(ConfigError::SharedDirCrossesMount {
                        path: entry.path(),
                        share_dir: dir.to_path_buf(),
                    });
                }
                stack.push(entry.path());
            } else if meta.is_file() {
                let id = (meta.dev(), meta.ino());
                if let Some((field, _, _)) = ids.iter().find(|(_, _, pid)| *pid == id) {
                    return Err(ConfigError::SharedDirContainsProtectedInput {
                        field: *field,
                        path: entry.path(),
                        share_dir: dir.to_path_buf(),
                    });
                }
                // 保護入力でなくても、他のリンクが共有範囲外にあればゲストが範囲外の inode を書き換えられる。
                // 他のリンクの位置は確かめられないため、リンク数 2 以上は一律に拒否する（fail-closed）。
                if meta.nlink() > 1 {
                    return Err(ConfigError::SharedDirHardlinkedFile {
                        path: entry.path(),
                        links: meta.nlink(),
                        share_dir: dir.to_path_buf(),
                    });
                }
            } else if let Some(kind) = special_file_kind(&meta.file_type()) {
                return Err(ConfigError::SharedDirSpecialFile {
                    path: entry.path(),
                    kind,
                    share_dir: dir.to_path_buf(),
                });
            }
        }
    }
    Ok(())
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
    /// virtiofs 共有（TASK-65.1。既定は共有なし）。
    pub shares: VirtiofsSharesSpec,
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
            shares: VirtiofsSharesSpec::default(),
        })
    }

    /// virtiofs 共有を差し替える（TASK-65.1）。検証は [`VirtiofsSharesSpec::try_new`] 済み。
    pub fn with_shared_directories(mut self, shares: VirtiofsSharesSpec) -> Self {
        self.shares = shares;
        self
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

    /// virtiofs 共有の衝突・共有範囲外経路を検査する（MAC-1・SEC-4・TASK-65.1）。
    ///
    /// ReadWrite 共有は VM の保護入力（kernel・initrd・ディスクイメージ・コンソールログ）を含まないこと
    /// （ゲストによる起動入力の書き換え防止）を検査する。ReadOnly 共有は書き換えられず、ゲスト自身の
    /// 起動入力を読めても新たな露出にならないため、保護入力の包含検査だけを行わない。
    /// 共有ディレクトリの配下（同一ディレクトリ自身を含む）に保護入力があれば
    /// [`ConfigError::SharedDirContainsProtectedInput`] を返す。比較は symlink を解決した実体パスで、
    /// 解決できない（未作成のコンソールログ等）場合は親を解決して補う。unix では共有配下も走査し、
    /// 保護入力へのハードリンク・マウント境界・共有範囲外を指す symlink を拒否する（`find_hardlink_to_protected`）。
    /// 共有範囲外経路の検査（マウント境界・範囲外 symlink・ハードリンク・特殊ファイル・HFS+）は
    /// ReadOnly 共有にも適用する（範囲外ホストファイルの読み出し露出の防止）。
    /// `build_vz_configuration` が VZ 呼び出しの前に実行する。
    /// 検査から VM 起動・使用までの差し替え（TOCTOU）とゲストが実行時に作る symlink は検査できない。
    pub fn check_share_conflicts(&self) -> Result<(), ConfigError> {
        let mut protected = self.protected_inputs();
        if let Some(SerialConsoleSink::LogFile(log)) = self.devices.serial_console() {
            protected.push(ProtectedInput {
                field: ConfigField::ConsoleLog,
                path: log.as_path(),
            });
        }
        let resolved: Vec<(ConfigField, PathBuf)> = protected
            .iter()
            .map(|p| (p.field, resolve_for_containment(p.path)))
            .collect();
        for share in self.shares.shares() {
            let read_only = share.access.is_read_only();
            let dir = resolve_for_containment(share.host_dir.as_path());
            if !read_only {
                for (field, path) in &resolved {
                    if crate::virtiofs::path_is_within(path, &dir) {
                        return Err(ConfigError::SharedDirContainsProtectedInput {
                            field: *field,
                            path: path.clone(),
                            share_dir: dir,
                        });
                    }
                }
            }
            // ReadOnly は保護入力の照合なし（空）で、範囲外経路の走査だけ行う。
            #[cfg(unix)]
            find_hardlink_to_protected(&dir, if read_only { &[] } else { &resolved })?;
        }
        Ok(())
    }

    /// ゲストへ渡す実効コマンドライン（ユーザー指定＋ゲスト mount の指示。MAC-1・TASK-65.3）。
    ///
    /// ユーザー指定に予約キー（`fandhe.` 始まり）があれば拒否し、連結後に [`KernelCommandLine::try_new`] を
    /// 再度通して長さ上限を実効値に対して適用する。mount 指定が無ければユーザー指定と同一。
    pub fn effective_cmdline(&self) -> Result<KernelCommandLine, ConfigError> {
        crate::guest_mount::reject_reserved_keys(self.cmdline.as_str())?;
        let directives = crate::guest_mount::encode_directives(&self.shares);
        if directives.is_empty() {
            return Ok(self.cmdline.clone());
        }
        let joined = if self.cmdline.as_str().is_empty() {
            directives
        } else {
            format!("{} {directives}", self.cmdline.as_str())
        };
        KernelCommandLine::try_new(&joined)
    }

    /// ゲスト mount の結果を待つ対象の tag（mount 指定が無ければ `None`）。
    ///
    /// mount 指定があるのにシリアルコンソールが無い構成は、結果を検証する経路が無いため拒否する（fail-closed）。
    pub fn guest_mount_plan(&self) -> Result<Option<Vec<String>>, ConfigError> {
        let tags = self.shares.guest_mount_tags();
        if tags.is_empty() {
            return Ok(None);
        }
        if self.devices.serial_console().is_none() {
            return Err(ConfigError::GuestMountRequiresConsole);
        }
        Ok(Some(tags))
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
        self.open_serial_console_with_reports(None)
    }

    /// [`Self::open_serial_console`] に、ゲストの mount 報告の送信側を渡す版（MAC-1・TASK-65.3）。
    #[cfg(unix)]
    pub fn open_serial_console_with_reports(
        &self,
        reports: Option<std::sync::mpsc::SyncSender<crate::guest_mount::ReportItem>>,
    ) -> Result<Option<crate::console_log::ConsoleLogSink>, ConfigError> {
        use crate::console_log::{ConsoleLogSink, MAX_CONSOLE_LOG_BYTES, SpawnError};
        let Some(SerialConsoleSink::LogFile(log)) = self.devices.serial_console() else {
            return Ok(None);
        };
        let log_path = log.as_path();
        let Some(file) = self.open_serial_console_log()? else {
            return Ok(None);
        };
        match ConsoleLogSink::spawn(file, MAX_CONSOLE_LOG_BYTES, reports) {
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

/// 読み戻した virtiofs 共有設定（診断用。TASK-65.1）。
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedDirectoryReadBack {
    /// 共有タグ。
    pub tag: String,
    /// ホストディレクトリのパス。
    pub path: Option<PathBuf>,
    /// 読み取り専用か。
    pub read_only: bool,
}

/// 構築済みの `VZVirtualMachineConfiguration`（不透明型）。`vm::Vm::create`（TASK-64.4）が内部を取り出して使う。
#[cfg(target_os = "macos")]
pub struct VzVmConfiguration(
    objc2::rc::Retained<objc2_virtualization::VZVirtualMachineConfiguration>,
    Option<crate::guest_mount::GuestMountWatch>,
);

#[cfg(target_os = "macos")]
impl VzVmConfiguration {
    pub(crate) fn inner(&self) -> &objc2_virtualization::VZVirtualMachineConfiguration {
        &self.0
    }

    /// ゲスト mount の待機対象を取り出す（mount 指定が無ければ `None`。1 度だけ取り出せる。TASK-65.3）。
    pub(crate) fn take_guest_mount_watch(&mut self) -> Option<crate::guest_mount::GuestMountWatch> {
        self.1.take()
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

    /// 設定済みの virtiofs 共有（診断用。TASK-65.1）。
    pub fn shared_directories(&self) -> Vec<SharedDirectoryReadBack> {
        crate::sys::read_back_shares(&self.0)
            .into_iter()
            .map(|s| SharedDirectoryReadBack {
                tag: s.tag,
                path: s.path,
                read_only: s.read_only,
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

    // ReadWrite 共有が起動入力を含む構成と、ReadOnly を含む共有範囲外経路のある構成は、副作用の前に拒否する。
    spec.check_share_conflicts()?;

    // 実効コマンドライン（ゲスト mount の指示を含む）と待機対象を、副作用（ログ作成・スレッド起動）の前に確定する。
    let effective_cmdline = spec.effective_cmdline()?;
    let (report_tx, mount_watch) = match spec.guest_mount_plan()? {
        Some(tags) => {
            let (tx, watch) = crate::guest_mount::GuestMountWatch::channel(tags);
            (Some(tx), Some(watch))
        }
        None => (None, None),
    };

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
    let cmdline = NSString::from_str(effective_cmdline.as_str());

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

    // virtiofs 共有（副作用なし。件数は VirtiofsSharesSpec が上限検証済み）。
    // タグは VZ 側でも検証してから init する（init は不正値で ObjC 例外を投げ、捕捉できず abort するため）。
    let mut sharing = Vec::with_capacity(spec.shares.shares().len());
    for share in spec.shares.shares() {
        let tag = NSString::from_str(share.tag.as_str());
        crate::sys::validate_virtiofs_tag(&tag)
            .map_err(|(domain, code)| ConfigError::VirtiofsTagRejected { domain, code })?;
        let url =
            NSURL::from_file_path(share.host_dir.as_path()).ok_or(ConfigError::UrlConversion {
                field: ConfigField::SharedDirectory,
            })?;
        sharing.push(crate::sys::new_virtiofs_device(
            &tag,
            &url,
            share.access.is_read_only(),
        ));
    }

    // シリアルコンソール（ここで初めてログファイルを作成・open する）。
    // 使用時点で fd を kernel / initrd / ディスクイメージと照合し、リンク数・所有者も検査する。
    // VZ へはログファイルではなく上限つき書き出しの pipe の書き込み端を渡す（追記量の上限。P1-3）。
    let mut serial = Vec::new();
    if let Some(sink) = spec.open_serial_console_with_reports(report_tx)? {
        let handle = crate::sys::new_file_handle(sink.into_write_fd());
        serial.push(crate::sys::new_console_serial_port(&handle));
    }

    let boot = crate::sys::new_linux_boot_loader(&kernel_url, initrd_url.as_deref(), &cmdline);
    let config = crate::sys::new_vm_configuration(&boot, cpus, memory);
    crate::sys::set_devices(&config, &storage, &serial);
    crate::sys::set_directory_sharing_devices(&config, &sharing);
    Ok(VzVmConfiguration(config, mount_watch))
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
            // umask に依らず、既存ログのモード検査（group / other の読み書き不可）を通る 0600 にする。
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod fixture");
            }
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

    /// MAC-1・TASK-65.1: virtiofs 関連の code と Display を具体値で固定する。
    #[test]
    fn virtiofs_error_codes_are_stable() {
        let e = ConfigError::TooManyVirtiofsShares { count: 9, max: 8 };
        assert_eq!(
            e.to_string(),
            "config.too_many_virtiofs_shares: 9 virtiofs shares requested, max is 8"
        );
        let e = ConfigError::VirtiofsTagTooLong { len: 36, max: 35 };
        assert_eq!(
            e.to_string(),
            "config.virtiofs_tag_too_long: virtiofs tag is 36 bytes, max is 35"
        );
        assert_eq!(
            ConfigError::SharedDirIsRoot.to_string(),
            "config.shared_dir_is_root: sharing the filesystem root is not allowed"
        );
        let e = ConfigError::SharedDirHardlinkedFile {
            path: PathBuf::from("/s/f"),
            links: 2,
            share_dir: PathBuf::from("/s"),
        };
        assert_eq!(
            e.to_string(),
            "config.shared_dir_hardlinked_file: shared directory /s contains a hard-linked file (2 links): /s/f (hint: replace hard links with copies, e.g. pnpm install --package-import-method=copy or git clone --no-hardlinks)"
        );
        let e = ConfigError::SharedDirSpecialFile {
            path: PathBuf::from("/s/p"),
            kind: SpecialFileKind::Fifo,
            share_dir: PathBuf::from("/s"),
        };
        assert_eq!(
            e.to_string(),
            "config.shared_dir_special_file: shared directory /s contains a fifo: /s/p"
        );
        assert_eq!(SpecialFileKind::CharDevice.as_str(), "character device");
        assert_eq!(SpecialFileKind::BlockDevice.as_str(), "block device");
        let e = ConfigError::SharedDirUnsupportedFilesystem {
            fs_type: "hfs".to_string(),
            share_dir: PathBuf::from("/s"),
        };
        assert_eq!(
            e.to_string(),
            "config.shared_dir_unsupported_filesystem: shared directory /s is on a hfs filesystem, which allows directory hard links (hint: share a directory on an APFS volume)"
        );
        let e = ConfigError::SharedDirSymlinkEscapes {
            path: PathBuf::from("/s/link"),
            share_dir: PathBuf::from("/s"),
        };
        assert_eq!(
            e.to_string(),
            "config.shared_dir_symlink_escapes: shared directory /s contains a symlink whose target is not confirmed to stay inside it: /s/link (hint: use relative symlinks that stay inside the share, or replace symlinks with copies)"
        );
        let e = ConfigError::VirtiofsTagRejected {
            domain: "VZErrorDomain".to_string(),
            code: 1,
        };
        assert_eq!(e.code(), "config.virtiofs_tag_rejected");
        assert_eq!(
            ConfigError::DuplicateVirtiofsTag {
                tag: "a".to_string()
            }
            .code(),
            "config.duplicate_virtiofs_tag"
        );
    }

    fn shares_for(dir: &Path) -> VirtiofsSharesSpec {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let real = std::fs::canonicalize(dir).unwrap();
        VirtiofsSharesSpec::try_new(vec![
            VirtiofsShareSpec::new(
                VirtiofsTag::try_new("ro").unwrap(),
                SharedDirectoryPath::try_new(&real).unwrap(),
                ShareAccess::ReadOnly,
            ),
            VirtiofsShareSpec::new(
                VirtiofsTag::try_new("rw").unwrap(),
                SharedDirectoryPath::try_new(&real).unwrap(),
                ShareAccess::ReadWrite,
            ),
        ])
        .unwrap()
    }

    /// MAC-1・TASK-65.1: 既定は共有なしで、`with_shared_directories` が `shares` に入る。
    #[test]
    fn with_shared_directories_sets_shares() {
        let t = TempDir::new("shares-spec");
        let k = t.file("vmlinux");
        let spec = VmConfigSpec::from_parts(&k, None, "console=hvc0").unwrap();
        assert!(spec.shares.shares().is_empty());
        let spec = spec.with_shared_directories(shares_for(&t.0));
        assert_eq!(spec.shares.shares().len(), 2);
        assert_eq!(spec.shares.shares()[0].tag.as_str(), "ro");
        assert!(spec.shares.shares()[0].access.is_read_only());
        assert!(!spec.shares.shares()[1].access.is_read_only());
    }

    /// MAC-1・TASK-65.1: ReadWrite 共有が kernel・initrd・ディスク・コンソールログを含む構成は拒否し、
    /// 別ディレクトリや ReadOnly 共有は許可する。
    #[test]
    fn rejects_read_write_share_containing_protected_inputs() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("share-conflict");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let k = real.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        let other = real.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let shares = |dir: &Path, access| {
            VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                VirtiofsTag::try_new("s").unwrap(),
                SharedDirectoryPath::try_new(dir).unwrap(),
                access,
            )])
            .unwrap()
        };
        let base = VmConfigSpec::from_parts(&k, None, "console=hvc0").unwrap();
        let err = base
            .clone()
            .with_shared_directories(shares(&real, ShareAccess::ReadWrite))
            .check_share_conflicts()
            .unwrap_err();
        assert_eq!(err.code(), "config.shared_dir_contains_protected_input");
        assert!(matches!(
            err,
            ConfigError::SharedDirContainsProtectedInput {
                field: ConfigField::Kernel,
                ..
            }
        ));
        base.clone()
            .with_shared_directories(shares(&real, ShareAccess::ReadOnly))
            .check_share_conflicts()
            .unwrap();
        base.clone()
            .with_shared_directories(shares(&other, ShareAccess::ReadWrite))
            .check_share_conflicts()
            .unwrap();

        // 未作成のコンソールログも、共有配下なら拒否する。
        let log = ConsoleLogPath::try_new(other.join("console.log")).unwrap();
        let devices =
            DeviceConfigSpec::try_new(vec![], Some(SerialConsoleSink::LogFile(log))).unwrap();
        let err = base
            .with_devices(devices)
            .unwrap()
            .with_shared_directories(shares(&other, ShareAccess::ReadWrite))
            .check_share_conflicts()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::SharedDirContainsProtectedInput {
                field: ConfigField::ConsoleLog,
                ..
            }
        ));
    }

    /// MAC-1・TASK-65.1: 共有内に置かれた保護入力へのハードリンクは、パス包含では検出できないが
    /// `(dev, ino)` 照合で拒否する。無関係なファイルだけの共有は許可する。
    #[cfg(unix)]
    #[test]
    fn rejects_read_write_share_with_hardlink_to_protected_input() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("share-hardlink");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let outside = real.join("outside");
        let shared = real.join("shared");
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let k = outside.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        let shares = VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
            VirtiofsTag::try_new("s").unwrap(),
            SharedDirectoryPath::try_new(&shared).unwrap(),
            ShareAccess::ReadWrite,
        )])
        .unwrap();
        let spec = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(shares);
        std::fs::write(shared.join("sub").join("plain"), b"x").unwrap();
        spec.check_share_conflicts().unwrap();

        let link = shared.join("sub").join("alias");
        std::fs::hard_link(&k, &link).unwrap();
        let err = spec.check_share_conflicts().unwrap_err();
        assert_eq!(err.code(), "config.shared_dir_contains_protected_input");
        match err {
            ConfigError::SharedDirContainsProtectedInput { field, path, .. } => {
                assert_eq!(field, ConfigField::Kernel);
                assert_eq!(path, link);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// MAC-1・TASK-65.1: マウント境界（`st_dev` の差）を判定し、共有配下の別デバイスを拒否する。
    #[cfg(unix)]
    #[test]
    fn mount_boundary_detection() {
        assert!(!crosses_mount(5, 5));
        assert!(crosses_mount(5, 6));
        let t = TempDir::new("share-mount");
        let real = std::fs::canonicalize(&t.0).unwrap();
        std::fs::create_dir_all(real.join("a")).unwrap();
        find_hardlink_to_protected(&real, &[]).unwrap();
        // ルート直下にマウントポイント（/proc 等）を持つ実ディレクトリで拒否を確認する。
        use std::os::unix::fs::MetadataExt;
        let root_dev = std::fs::metadata("/").unwrap().dev();
        let has_mount = std::fs::read_dir("/").unwrap().any(|e| {
            std::fs::symlink_metadata(e.unwrap().path())
                .map(|m| m.dev() != root_dev)
                .unwrap_or(false)
        });
        if has_mount {
            let err = find_hardlink_to_protected(Path::new("/"), &[]);
            assert!(
                matches!(err, Err(ConfigError::SharedDirCrossesMount { .. })),
                "{err:?}"
            );
        }
    }

    /// MAC-1・TASK-65.1: 同一デバイスの bind mount（`st_dev` が同じ）もマウント表から検出する。
    /// root なしでは bind mount を作れないため、mountinfo の fixture 文字列で照合する。
    #[cfg(target_os = "linux")]
    #[test]
    fn mount_point_under_share_is_detected_from_mountinfo() {
        let mountinfo = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 8:1 /x/share /x/share rw,relatime shared:1 - ext4 /dev/sda1 rw
41 22 8:1 /data /x/share2/sub rw,relatime shared:1 - ext4 /dev/sda1 rw
42 22 8:1 /etc /x/share/my\\040dir/etc rw,relatime shared:1 - ext4 /dev/sda1 rw
broken line
";
        let share = Path::new("/x/share");
        // 共有自身のマウント（40）と兄弟 `/x/share2`（41）は対象外で、配下の bind mount（42）を返す。
        assert_eq!(
            mount_point_under(mountinfo, share),
            Some(PathBuf::from("/x/share/my dir/etc"))
        );
        assert_eq!(
            mount_point_under(mountinfo, Path::new("/x/share2/sub")),
            None
        );
        assert_eq!(
            mount_point_under(mountinfo, Path::new("/x/share/my dir/etc")),
            None
        );
        assert_eq!(
            unescape_mountinfo("a\\040b\\011c\\x"),
            b"a b\tc\\x".to_vec()
        );
        // 実環境の mountinfo でも `/` 配下のマウント（/proc 等）を検出する。
        assert!(matches!(
            reject_mounts_under(Path::new("/")),
            Err(ConfigError::SharedDirCrossesMount { .. })
        ));
    }

    /// MAC-1・TASK-65.1: 保護入力でなくても、ReadWrite 共有配下のリンク数 2 以上の通常ファイルは
    /// 拒否する（共有範囲外のリンク・共有内だけのリンクとも）。ReadOnly 共有にも同じ検査を適用する（SEC-4）。
    #[cfg(unix)]
    #[test]
    fn rejects_share_with_hardlinked_file_for_both_access_modes() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("share-nlink");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let outside = real.join("outside");
        let shared = real.join("shared");
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let k = outside.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        let spec_for = |access| {
            VmConfigSpec::from_parts(&k, None, "console=hvc0")
                .unwrap()
                .with_shared_directories(
                    VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                        VirtiofsTag::try_new("s").unwrap(),
                        SharedDirectoryPath::try_new(&shared).unwrap(),
                        access,
                    )])
                    .unwrap(),
                )
        };
        let rw = spec_for(ShareAccess::ReadWrite);
        let ro = spec_for(ShareAccess::ReadOnly);

        // 共有範囲外の（保護入力でない）ファイルへのハードリンク。
        let store = outside.join("store-file");
        std::fs::write(&store, b"s").unwrap();
        let link = shared.join("sub").join("from-store");
        std::fs::hard_link(&store, &link).unwrap();
        let err = rw.check_share_conflicts().unwrap_err();
        assert_eq!(err.code(), "config.shared_dir_hardlinked_file");
        assert_eq!(
            err,
            ConfigError::SharedDirHardlinkedFile {
                path: link.clone(),
                links: 2,
                share_dir: shared.clone(),
            }
        );
        assert_eq!(ro.check_share_conflicts().unwrap_err(), err);
        std::fs::remove_file(&link).unwrap();
        rw.check_share_conflicts().unwrap();
        ro.check_share_conflicts().unwrap();

        // 共有内だけで完結するハードリンクも、他のリンクの位置を確かめないため拒否する（3 リンク）。
        let a = shared.join("a");
        std::fs::write(&a, b"a").unwrap();
        std::fs::hard_link(&a, shared.join("sub").join("b")).unwrap();
        std::fs::hard_link(&a, shared.join("sub").join("c")).unwrap();
        let err = rw.check_share_conflicts().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::SharedDirHardlinkedFile { links: 3, .. }
        ));
        assert!(matches!(
            ro.check_share_conflicts().unwrap_err(),
            ConfigError::SharedDirHardlinkedFile { links: 3, .. }
        ));
        std::fs::remove_file(shared.join("sub").join("b")).unwrap();
        std::fs::remove_file(shared.join("sub").join("c")).unwrap();
        ro.check_share_conflicts().unwrap();
    }

    /// MAC-1・SEC-4・TASK-65.1: ReadOnly 共有内の kernel へのハードリンクは、保護入力の包含検査ではなく
    /// ハードリンク検査（`SharedDirHardlinkedFile`）で拒否する。
    #[cfg(unix)]
    #[test]
    fn rejects_read_only_share_with_hardlink_to_kernel() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("share-ro-kernel-link");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let shared = real.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        let k = real.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        let ro = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(
                VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                    VirtiofsTag::try_new("s").unwrap(),
                    SharedDirectoryPath::try_new(&shared).unwrap(),
                    ShareAccess::ReadOnly,
                )])
                .unwrap(),
            );
        ro.check_share_conflicts().unwrap();
        let link = shared.join("k-copy");
        std::fs::hard_link(&k, &link).unwrap();
        assert_eq!(
            ro.check_share_conflicts().unwrap_err(),
            ConfigError::SharedDirHardlinkedFile {
                path: link,
                links: 2,
                share_dir: shared,
            }
        );
    }

    /// MAC-1・TASK-65.1: 特殊ファイルの判定（キャラクタデバイス・FIFO は拒否、ディレクトリは対象外）と、
    /// ReadWrite 共有配下のソケットを許可することを確認する。デバイスノードの作成には root が要り、
    /// FIFO の作成（`mkfifo`）は std に無く子プロセスを起こすと並行テストの fd（ロック）を fork で一時的に
    /// 引き継いでしまうため、判定は `/dev/null` と `std::io::pipe` の読み出し端（`/dev/fd/N`）で行う。
    #[cfg(unix)]
    #[test]
    fn classifies_special_files_and_allows_sockets_in_share() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("sp");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let shared = real.join("sh");
        std::fs::create_dir_all(&shared).unwrap();
        let k = real.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        let rw = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(
                VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                    VirtiofsTag::try_new("s").unwrap(),
                    SharedDirectoryPath::try_new(&shared).unwrap(),
                    ShareAccess::ReadWrite,
                )])
                .unwrap(),
            );
        let ro = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(
                VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                    VirtiofsTag::try_new("s").unwrap(),
                    SharedDirectoryPath::try_new(&shared).unwrap(),
                    ShareAccess::ReadOnly,
                )])
                .unwrap(),
            );

        let null = std::fs::symlink_metadata("/dev/null").unwrap();
        assert_eq!(
            special_file_kind(&null.file_type()),
            Some(SpecialFileKind::CharDevice)
        );
        let dir = std::fs::symlink_metadata(&shared).unwrap();
        assert_eq!(special_file_kind(&dir.file_type()), None);
        {
            use std::os::fd::AsRawFd;
            let (reader, _writer) = std::io::pipe().unwrap();
            // `/dev/fd/N` は fd の実体（ここでは pipe = FIFO）を返す（Linux・macOS 共通）。
            let fifo = std::fs::metadata(format!("/dev/fd/{}", reader.as_raw_fd())).unwrap();
            assert_eq!(
                special_file_kind(&fifo.file_type()),
                Some(SpecialFileKind::Fifo)
            );
        }

        // ソケットは許可する（open(2) は ENXIO で、FUSE に connect 相当の要求は無い）。
        // macOS の `sun_path` は 104 バイトのため、一時ディレクトリ配下でも収まる短い名前にする。
        let sock = shared.join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        rw.check_share_conflicts().unwrap();
        ro.check_share_conflicts().unwrap();
    }

    /// MAC-1・SEC-4・TASK-65.1: 配下に別マウントを持つ実ディレクトリ（Linux の `/sys`）の ReadOnly 共有は
    /// `check_share_conflicts` 経由でも `SharedDirCrossesMount` で拒否する。前提が満たされない環境では
    /// 理由を出力して判定を省く。
    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_read_only_share_crossing_mount() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("share-ro-mount");
        let k = t.file("vmlinux");
        let sys = Path::new("/sys");
        let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
            eprintln!("note: /proc/self/mountinfo is unreadable; mount check not exercised");
            return;
        };
        let Some(mount) = mount_point_under(&mountinfo, sys) else {
            eprintln!("note: no mount point under /sys; mount check not exercised");
            return;
        };
        let Ok(dir) = SharedDirectoryPath::try_new(sys) else {
            eprintln!(
                "note: /sys is not accepted as a shared directory; mount check not exercised"
            );
            return;
        };
        let ro = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(
                VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                    VirtiofsTag::try_new("s").unwrap(),
                    dir,
                    ShareAccess::ReadOnly,
                )])
                .unwrap(),
            );
        let err = ro.check_share_conflicts().unwrap_err();
        assert_eq!(err.code(), "config.shared_dir_crosses_mount");
        assert!(
            matches!(&err, ConfigError::SharedDirCrossesMount { share_dir, .. } if share_dir == sys),
            "{err:?} (mount under /sys: {mount:?})"
        );
    }

    /// MAC-1・TASK-65.1: HFS+（`hfs`）上の共有はディレクトリのハードリンクを見分けられないため拒否する。
    #[test]
    fn rejects_share_on_hfs() {
        let dir = Path::new("/Volumes/ext/share");
        assert_eq!(
            check_share_fs_type(b"hfs", dir),
            Err(ConfigError::SharedDirUnsupportedFilesystem {
                fs_type: "hfs".to_string(),
                share_dir: dir.to_path_buf(),
            })
        );
        assert!(check_share_fs_type(b"HFS", dir).is_err());
        assert_eq!(check_share_fs_type(b"apfs", dir), Ok(()));
        assert_eq!(check_share_fs_type(b"hfsplus-like", dir), Ok(()));
    }

    /// MAC-1・TASK-65.1: ReadWrite 共有配下の symlink は、リンク先が共有範囲内なら許可し、範囲外
    /// （絶対・相対・ディレクトリ・dangling）・ループは拒否する。ReadOnly 共有にも同じ検査を適用する。
    #[cfg(unix)]
    #[test]
    fn rejects_share_with_symlink_escaping_share_for_both_access_modes() {
        use crate::virtiofs::{ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        use std::os::unix::fs::symlink;
        let t = TempDir::new("share-symlink");
        let real = std::fs::canonicalize(&t.0).unwrap();
        let outside = real.join("outside");
        let shared = real.join("shared");
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let k = outside.join("vmlinux");
        std::fs::write(&k, b"k").unwrap();
        std::fs::write(shared.join("sub").join("data"), b"x").unwrap();
        let spec_for = |access| {
            VmConfigSpec::from_parts(&k, None, "console=hvc0")
                .unwrap()
                .with_shared_directories(
                    VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                        VirtiofsTag::try_new("s").unwrap(),
                        SharedDirectoryPath::try_new(&shared).unwrap(),
                        access,
                    )])
                    .unwrap(),
                )
        };
        let rw = spec_for(ShareAccess::ReadWrite);
        let ro = spec_for(ShareAccess::ReadOnly);

        // 範囲内を指す symlink（実在・相対・dangling）は許可する。
        let inside_abs = shared.join("to-data");
        symlink(shared.join("sub").join("data"), &inside_abs).unwrap();
        let inside_rel = shared.join("sub").join("to-sibling");
        symlink("data", &inside_rel).unwrap();
        let inside_dangling = shared.join("sub").join("lock");
        symlink("not-yet-created", &inside_dangling).unwrap();
        rw.check_share_conflicts().unwrap();
        ro.check_share_conflicts().unwrap();

        let expect_escape = |link: &Path| {
            let err = rw.check_share_conflicts().unwrap_err();
            assert_eq!(err.code(), "config.shared_dir_symlink_escapes");
            assert_eq!(
                err,
                ConfigError::SharedDirSymlinkEscapes {
                    path: link.to_path_buf(),
                    share_dir: shared.clone(),
                }
            );
            // ReadOnly 共有でも同じ値で拒否する（範囲外の読み出し経路。SEC-4）。
            assert_eq!(ro.check_share_conflicts().unwrap_err(), err);
            std::fs::remove_file(link).unwrap();
            rw.check_share_conflicts().unwrap();
            ro.check_share_conflicts().unwrap();
        };

        // 共有外の kernel を指す絶対 symlink。
        let link = shared.join("sub").join("kernel-abs");
        symlink(&k, &link).unwrap();
        expect_escape(&link);
        // `..` で共有外へ出る相対 symlink。
        let link = shared.join("sub").join("kernel-rel");
        symlink("../../outside/vmlinux", &link).unwrap();
        expect_escape(&link);
        // 共有外のディレクトリを指す symlink。
        let link = shared.join("dir-out");
        symlink(&outside, &link).unwrap();
        expect_escape(&link);
        // 共有外の未作成ファイルを指す dangling symlink。
        let link = shared.join("dangling-out");
        symlink(outside.join("later"), &link).unwrap();
        expect_escape(&link);
        // リンク先の親も未作成で範囲を確認できない dangling symlink。
        let link = shared.join("dangling-deep");
        symlink("missing/later", &link).unwrap();
        expect_escape(&link);
        // 共有ディレクトリ自身の親を指す symlink（`..` 終端）。
        let link = shared.join("parent");
        symlink("..", &link).unwrap();
        expect_escape(&link);

        // 解決できないループは PathIo で fail-closed にする。
        let a = shared.join("loop-a");
        let b = shared.join("loop-b");
        symlink(&b, &a).unwrap();
        symlink(&a, &b).unwrap();
        let err = rw.check_share_conflicts().unwrap_err();
        assert_eq!(err.code(), "config.path_io");
        assert!(matches!(
            err,
            ConfigError::PathIo {
                field: ConfigField::SharedDirectory,
                ..
            }
        ));
        assert!(matches!(
            ro.check_share_conflicts().unwrap_err(),
            ConfigError::PathIo {
                field: ConfigField::SharedDirectory,
                ..
            }
        ));
    }

    /// MAC-1・TASK-65.1: macOS で virtiofs 付き設定を構築し、読み戻した値が入力と一致する。
    #[cfg(target_os = "macos")]
    #[test]
    fn builds_vz_configuration_with_virtiofs_and_reads_back() {
        let t = TempDir::new("vz-fs");
        let k = t.file("vmlinux");
        let plain = VmConfigSpec::from_parts(&k, None, "console=hvc0").unwrap();
        let cfg = build_vz_configuration(&plain).expect("build without shares");
        assert!(cfg.shared_directories().is_empty());

        // ReadWrite 共有は kernel を含んではならないため、kernel と別のサブディレクトリを共有する。
        let share_dir = t.0.join("share");
        std::fs::create_dir_all(&share_dir).unwrap();
        let spec = plain.with_shared_directories(shares_for(&share_dir));
        let cfg = build_vz_configuration(&spec).expect("build with shares");
        let real = std::fs::canonicalize(&share_dir).unwrap();
        let got = cfg.shared_directories();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].tag, "ro");
        assert!(got[0].read_only);
        assert_eq!(
            got[0]
                .path
                .as_ref()
                .map(|p| std::fs::canonicalize(p).unwrap()),
            Some(real.clone())
        );
        assert_eq!(got[1].tag, "rw");
        assert!(!got[1].read_only);
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
            check_log_ownership(
                p,
                LogFileAttrs {
                    nlink: 1,
                    uid: 501,
                    mode: 0o100600
                },
                501
            ),
            Ok(())
        );
        let err = check_log_ownership(
            p,
            LogFileAttrs {
                nlink: 1,
                uid: 0,
                mode: 0o100600,
            },
            501,
        )
        .unwrap_err();
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
        // group / other の読み書きビットがあれば拒否する（実行ビットは問わない）。
        let err = check_log_ownership(
            p,
            LogFileAttrs {
                nlink: 1,
                uid: 501,
                mode: 0o100644,
            },
            501,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::ConsoleLogInsecureMode {
                path: p.to_path_buf(),
                mode: 0o644,
            }
        );
        assert_eq!(
            err.to_string(),
            "config.console_log_insecure_mode: console log mode 644 allows group or other access, expected 600: /var/log/console.log"
        );
        assert_eq!(
            check_log_ownership(
                p,
                LogFileAttrs {
                    nlink: 1,
                    uid: 501,
                    mode: 0o100620
                },
                501
            )
            .unwrap_err()
            .code(),
            "config.console_log_insecure_mode"
        );
        assert_eq!(
            check_log_ownership(
                p,
                LogFileAttrs {
                    nlink: 1,
                    uid: 501,
                    mode: 0o100711
                },
                501
            ),
            Ok(())
        );
        // 所有者をモードより先に見る。
        assert_eq!(
            check_log_ownership(
                p,
                LogFileAttrs {
                    nlink: 1,
                    uid: 0,
                    mode: 0o100666
                },
                501
            )
            .unwrap_err()
            .code(),
            "config.console_log_not_owned"
        );
        // リンク数を所有者より先に見る。
        let err = check_log_ownership(
            p,
            LogFileAttrs {
                nlink: 3,
                uid: 0,
                mode: 0o100600,
            },
            501,
        )
        .unwrap_err();
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

    /// MAC-1・TASK-64.3: group / other が読み書きできる既存ログは検証時に拒否し、検証後に権限を広げられても
    /// open 後の fd 検査で拒否する（ゲスト出力の漏えいと、他者の追記・切り詰めによる上限の崩れを防ぐ）。
    #[cfg(unix)]
    #[test]
    fn console_log_with_group_or_other_access_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("log-mode");
        let path = t.file("console.log");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            ConsoleLogPath::try_new(&path).unwrap_err(),
            ConfigError::ConsoleLogInsecureMode {
                path: path.clone(),
                mode: 0o644,
            }
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let log = ConsoleLogPath::try_new(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606)).unwrap();
        assert_eq!(
            log.open_for_append_excluding(&[]).unwrap_err(),
            ConfigError::ConsoleLogInsecureMode {
                path: path.clone(),
                mode: 0o606,
            }
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"dummy");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o606
        );
    }

    /// ゲスト mount 指定つき共有（tag, mount point, access）。
    fn mount_shares(
        dir: &Path,
        specs: &[(&str, &str, crate::virtiofs::ShareAccess)],
    ) -> VirtiofsSharesSpec {
        use crate::guest_mount::GuestMountPoint;
        use crate::virtiofs::{SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let host = SharedDirectoryPath::try_new(dir).unwrap();
        VirtiofsSharesSpec::try_new(
            specs
                .iter()
                .map(|(tag, mp, access)| {
                    VirtiofsShareSpec::new(
                        VirtiofsTag::try_new(tag).unwrap(),
                        host.clone(),
                        *access,
                    )
                    .with_guest_mount(GuestMountPoint::try_new(mp).unwrap())
                })
                .collect(),
        )
        .unwrap()
    }

    /// MAC-1・TASK-65.3: 実効コマンドラインは具体的な文字列で、mount 指定なしならユーザー指定のまま。
    #[test]
    fn effective_cmdline_appends_directives() {
        use crate::virtiofs::ShareAccess::{ReadOnly, ReadWrite};
        let t = TempDir::new("eff-cmdline");
        let k = t.file("vmlinux");
        let base = VmConfigSpec::from_parts(&k, None, "console=hvc0").unwrap();
        assert_eq!(base.effective_cmdline().unwrap().as_str(), "console=hvc0");
        let spec = base.clone().with_shared_directories(mount_shares(
            &t.0,
            &[
                ("a", "/mnt/fandhe/a", ReadOnly),
                ("b", "/mnt/fandhe/b", ReadWrite),
            ],
        ));
        assert_eq!(
            spec.effective_cmdline().unwrap().as_str(),
            "console=hvc0 fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/b:rw"
        );
        let empty = VmConfigSpec::from_parts(&k, None, "")
            .unwrap()
            .with_shared_directories(mount_shares(&t.0, &[("a", "/mnt/fandhe/a", ReadOnly)]));
        assert_eq!(
            empty.effective_cmdline().unwrap().as_str(),
            "fandhe.virtiofs=a:/mnt/fandhe/a:ro"
        );
    }

    /// MAC-1・TASK-65.3: ユーザー指定の予約キーは拒否し、実効長は連結後に上限検証する。
    #[test]
    fn effective_cmdline_rejects_reserved_and_overlong() {
        use crate::virtiofs::ShareAccess::ReadWrite;
        let t = TempDir::new("eff-reserved");
        let k = t.file("vmlinux");
        for user in ["fandhe.virtiofs=x:/mnt/fandhe/x:rw", "quiet fandhe.x=1"] {
            let spec = VmConfigSpec::from_parts(&k, None, user).unwrap();
            assert_eq!(
                spec.effective_cmdline().unwrap_err().code(),
                "config.command_line_reserved_key",
                "{user}"
            );
        }
        // ユーザー指定は上限内でも、指示の連結後に 2048 バイトを超えれば拒否する。
        let user = "a".repeat(2000);
        let specs: Vec<(String, String)> = (0..8)
            .map(|i| (format!("tag{i}"), format!("/mnt/fandhe/m{i}")))
            .collect();
        let refs: Vec<(&str, &str, crate::virtiofs::ShareAccess)> = specs
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str(), ReadWrite))
            .collect();
        let spec = VmConfigSpec::from_parts(&k, None, &user)
            .unwrap()
            .with_shared_directories(mount_shares(&t.0, &refs));
        assert_eq!(
            spec.effective_cmdline().unwrap_err().code(),
            "config.command_line_too_long"
        );
    }

    /// MAC-1・TASK-65.3: mount 指定があるのにコンソールが無い構成は fail-closed で拒否する。
    #[test]
    fn guest_mount_requires_console() {
        use crate::virtiofs::ShareAccess::ReadOnly;
        let t = TempDir::new("mount-console");
        let k = t.file("vmlinux");
        let shares = mount_shares(&t.0, &[("a", "/mnt/fandhe/a", ReadOnly)]);
        let spec = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(shares.clone());
        assert_eq!(
            spec.guest_mount_plan(),
            Err(ConfigError::GuestMountRequiresConsole)
        );
        let log = ConsoleLogPath::try_new(t.0.join("console.log")).unwrap();
        let devices =
            DeviceConfigSpec::try_new(vec![], Some(SerialConsoleSink::LogFile(log))).unwrap();
        let with_console = spec.with_devices(devices).unwrap();
        assert_eq!(
            with_console.guest_mount_plan(),
            Ok(Some(vec!["a".to_string()]))
        );
        // mount 指定の無い共有だけなら待機対象なし（コンソールも不要）。
        let plain = VmConfigSpec::from_parts(&k, None, "console=hvc0")
            .unwrap()
            .with_shared_directories(shares_for(&t.0));
        assert_eq!(plain.guest_mount_plan(), Ok(None));
    }

    /// MAC-1・TASK-65.3: mount point の重複・入れ子は共有の集合として拒否する。
    #[test]
    fn duplicate_or_nested_mount_points_rejected() {
        use crate::guest_mount::GuestMountPoint;
        use crate::virtiofs::{SharedDirectoryPath, VirtiofsShareSpec, VirtiofsTag};
        let t = TempDir::new("mount-dup");
        let host = SharedDirectoryPath::try_new(&t.0).unwrap();
        let mk = |tag: &str, mp: &str| {
            VirtiofsShareSpec::new(
                VirtiofsTag::try_new(tag).unwrap(),
                host.clone(),
                crate::virtiofs::ShareAccess::ReadOnly,
            )
            .with_guest_mount(GuestMountPoint::try_new(mp).unwrap())
        };
        for (a, b) in [
            ("/mnt/fandhe/x", "/mnt/fandhe/x"),
            ("/mnt/fandhe/x", "/mnt/fandhe/x/y"),
            ("/mnt/fandhe/x/y", "/mnt/fandhe/x"),
        ] {
            let err = VirtiofsSharesSpec::try_new(vec![mk("t1", a), mk("t2", b)]).unwrap_err();
            assert_eq!(err.code(), "config.duplicate_guest_mount_point", "{a} {b}");
        }
        assert!(
            VirtiofsSharesSpec::try_new(vec![
                mk("t1", "/mnt/fandhe/x"),
                mk("t2", "/mnt/fandhe/xy")
            ])
            .is_ok()
        );
    }

    /// MAC-1・TASK-65.3: 追加した ConfigError の code / message は具体値。
    #[test]
    fn guest_mount_config_error_strings() {
        let cases = [
            (
                ConfigError::GuestMountPointNotUnderBase,
                "config.guest_mount_point_not_under_base",
                "guest mount point must be under /mnt/fandhe/",
            ),
            (
                ConfigError::GuestMountRequiresConsole,
                "config.guest_mount_requires_console",
                "guest mount requires a serial console to verify the result",
            ),
            (
                ConfigError::CommandLineReservedKey { index: 4 },
                "config.command_line_reserved_key",
                "kernel command line has a reserved 'fandhe.' key at byte 4",
            ),
            (
                ConfigError::DuplicateGuestMountPoint {
                    path: "/mnt/fandhe/x".into(),
                },
                "config.duplicate_guest_mount_point",
                "guest mount point is duplicated or nested: /mnt/fandhe/x",
            ),
        ];
        for (e, code, msg) in cases {
            assert_eq!(e.code(), code);
            assert_eq!(e.message(), msg);
        }
    }
}
