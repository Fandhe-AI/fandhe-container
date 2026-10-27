//! `mounts[]` の bind mount の指定を検証済みの型へ変換する（TASK-29 追補・#1911・CORE-2・OCI-4・CORE-5・SEC-1）。
//!
//! # 役割と呼び出し元
//!
//! Linux の fandhe のコンテナは、利用者指定の bind mount（`config.json` の `mounts[]`）を適用する（#1907 の
//! オーナー判断）。本モジュールは「何を受けて何を拒否するか」を 1 か所の純粋関数 [`BindMountSet::from_mounts`] と
//! 検証済みの型 [`BindMountSpec`] に固定する。適用側は #1912（sys ラッパー）・#1913（適用の段）・#1914（pivot 前段）・
//! #1915（`start` への結線。済み）が本型だけを入力にする。`OciMount` は「未検証の指定」、[`BindMountSet`] は
//! 「検証済みの bind」の分担で、`OciMount` 側は変更しない。
//!
//! 受け入れ範囲は #1910 のオーナー決定（2026-10-12）による。`cfg` を付けず 3 OS でビルドし、syscall・
//! ファイルシステムへのアクセスをしない（CLI-1）。パスはホスト OS の `Path` 解釈に依存せず `/` で自前分割する。
//!
//! # 受け入れ規則
//!
//! - 種類: bind のみ（`type == "bind"`、または options に `bind` / `rbind`）。それ以外は `UNIMPLEMENTED`（受けるかは #2347 で判断待ち。docs/design/oci-mounts-implicit-entries.md）。
//!   ただし bind でない `type == "sysfs"` は読み飛ばし（位置は元のまま）、`SysfsMountSpec` が受ける（#2020）
//! - 受けるオプション: `bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・`rprivate`・`rslave`
//!   （`rslave` はホストの peer group から受けるだけの slave。ホストへは伝播しない。#2669・CRI-2・OCI-4・SEC-1。
//!   `private`・`rprivate` との併記は `ConflictingPropagation`）
//! - 拒否: `suid`・`dev`（制限を外す側。SEC-1）、`shared`・`rshared`・`slave`・`unbindable`・
//!   `runbindable`（伝播。`rshared` を受けない理由は `docs/design/mount-propagation.md`）、上記以外すべて（未知は fail-closed）
//! - 常に付ける: `nosuid`・`nodev`（型が常に真を返し、外した値を表現できない。REPAIR-2）。伝播は private、
//!   `rslave` 指定時だけ [`BindPropagation::HostSlave`]（適用側は `BindMountSpec::propagation` に従う契約）。`noexec` は指定時のみ
//! - 再帰: 既定は非再帰。`rbind` 指定時のみ再帰（属性を再帰で付けるのは適用側）
//! - マウント元: 字句検証（絶対・`..`/`.`/空要素/NUL/`\` なし・`/` 不可）。rootfs・bundle の同一・祖先は
//!   [`BindMountSet::check_against_host_paths`]（子孫は受ける）、状態ルートの同一・祖先・子孫は
//!   [`BindMountSet::check_against_protected_trees`]
//! - マウント先: `/proc`・`/sys`・`/dev` とその配下を拒否。先行 bind との同一・入れ子を拒否。tmpfs・注入・
//!   保護パスとの重なりは各 `check_against_*`
//!
//! # OCI Runtime Spec との差
//!
//! 一次情報は opencontainers/runtime-spec v1.2.1 の `config.md`（Mounts 節と Linux mount options 表）。
//!
//! | 項目 | 仕様の読み | 本実装 |
//! | -- | -- | -- |
//! | bind の判定 | options に `bind` / `rbind`。type は dummy | 同じ＋`type == "bind"` も bind |
//! | 非 bind の種類 | kernel の fs 種別 | `UNIMPLEMENTED` |
//! | `source` | 絶対、または bundle 相対 | 絶対のみ |
//! | `nosuid`・`nodev` | 指定時のみ | 常に付与・外せない |
//! | `suid`・`dev` | 受ける | 拒否 |
//! | 伝播系・`unbindable` | 受ける | `rslave` のみ受ける（ホスト側が shared / slave の元に限る）。他は拒否 |
//! | `defaults` | no-op | 拒否（許可集合外） |
//! | 再帰版 `rro` 等・`idmap` | 受ける | 拒否 |
//! | 宛先 `/proc`・`/sys`・`/dev` 配下 | 制限なし | 拒否 |
//! | bind 同士の入れ子 | Linux は列挙順に適用 | 拒否 |
//!
//! # 決定（#2063・2026-10-16 のオーナー決定。SEC-1・OCI-4）
//!
//! #1910 の決定外だった 4 点は #2063 で確定した。各点は単体・結合試験で具体値により固定する（REPAIR-3・REPAIR-12）。
//!
//! | 点 | 決定 | 判定を担う箇所 |
//! | -- | -- | -- |
//! | (a) | `bind` と `rbind` の併記は拒否 | `parse_options` の `ConflictingBindKind` |
//! | (b) | マウント元の `.` 要素と `\` は両方拒否（PR #2044 の本文の「`/`」は誤記で、対象は `.` 要素と `\`） | `validate_source` の `InvalidSource` |
//! | (c) | bind 同士の入れ子（宛先が同一・親子）は拒否。子の宛先がホストのディレクトリになり、無いディレクトリの作成がホストへ書き込む経路になるため | `from_mounts` の `DuplicateDestination` / `NestedDestination` |
//! | (d) | 状態ルートは同一・祖先・子孫を拒否する。rootfs・bundle は同一・祖先だけを拒否し、子孫は受ける | 下記 |
//!
//! (d) のうち状態ルート側は [`BindMountSet::check_against_protected_trees`]・
//! [`BindMountSet::check_resolved_sources_against_protected_trees`]（`canonicalize` 後の照合）・`start` の mountinfo と inode の鎖による
//! 実体照合・適用の段の `ProtectedFsRoot::new` が担う。rootfs・bundle 側は
//! [`BindMountSet::check_against_host_paths`]・`start` の `source_contains`・適用の段の `ProtectedFsRoot::contained`
//! が担う。暫定の「子孫はすべて受ける」から、状態ルートの子孫だけが拒否に変わった。
//!
//! # Landlock との解釈の共有
//!
//! `ro`/`rw`・`noexec`/`exec` の「後の指定が勝つ」畳み込みは `landlock::rules::mount_rights` と同じ読みで、
//! `landlock/rules.rs` の照合試験が両者の結果を突き合わせる。解釈を変えるときはもう一方と照合試験を更新する。
//! `crate::landlock` は Linux 限定のため intra-doc リンクは張らない。
//!
//! # スコープ外（REPAIR-3）
//!
//! 本型は字句検証のみで、検証から適用までの TOCTOU を防がない。symlink を含む実体の照合・fd 起点 `O_NOFOLLOW` の
//! 走査・種別と存在の確認・宛先ディレクトリの作成・利用者権限での到達性・rootfs 自身とその祖先の実体照合（`dev`/`ino`）・疑似 FS 上の元の拒否（`f_type`。#2098）は、
//! 適用の段 `crate::exec::mount_binds`（#1913。実装済み。Linux 限定のため intra-doc リンクは張らない）が担う。
//! bundle は適用の段の rootfs の鎖（inode）と mountinfo（`ProtectedFsRoot::contained`）で、状態ルートは start が固定した inode の鎖（`with_inode_chain`。#2066）と mountinfo で照合する。start の後に状態ルートが移動・改名された場合は、適用の段が固定したパスを辿り直して一致しなければ `FAILED_PRECONDITION` で拒否する（#2129）。状態ルートの (dev, path) と子マウントも適用の段が毎回作り直して照合し、overlayfs の層は付け替えた木の super_options から照合する（#2166）。残余（REPAIR-3）は、FUSE 系の別 superblock 経由の同一データ、入れ子の overlay の再帰的な照合（拒否で代える）、fstype が `overlay` の完全一致でない積層 FS（`fuse.fuse-overlayfs` 等。保護対象の下にあると層を解決できず逆方向の照合が効かない。#2536）で、詳細は `crate::exec::mount_binds` のモジュール doc。`run_pre_pivot` への組み込みは済み（#1914）、`start` と本番 launcher への結線は済み（#1915。検証は `start`、tmpfs との重なりは launcher、
//! 監査は `ProcessLauncher::rejection_audit_sink` 経由）。`ro` と Landlock の衝突は #1917 で解消済み
//! （launcher が `spec.bind_mounts()` を Landlock のルール生成へ渡し、検証済みの `ro` の bind だけ書き込み可能な root の下でも受ける）。状態ルートとの重なりは `start` が字句比較・`canonicalize` 比較・
//! mountinfo によるファイルシステム内の実体照合（別の bind mount による別名）で検査する。適用の段も固定した元に対して状態ルートとの重なりを毎回再検証する（`ProtectedFsRoot`。元のマウントは fd の `mnt_id` で特定し、`rbind` のときだけ配下のマウントを照合する。保護対象と同じ FS 上のリンク数 2 以上の通常ファイルは拒否する。状態ルート配下にリンク数 2 以上の通常ファイルがあれば、同じ FS 上のディレクトリ元も拒否する）。`MountDestination::resolve_in` の文字列結合で直接 mount してはならない。

use std::fmt;
use std::path::Path;

use super::config::{CONFIG_MAX_MOUNTS, CONFIG_MAX_PATH_BYTES, OciMount};
use super::mount_destination::MountDestination;
use super::sysfs_mount::OciMountKind;
use crate::audit_log::{AuditSink, AuditedRejection, record_mount_rejection};
use crate::injected_files::{InjectedFileSet, overlaps};
use crate::path_masks::ProtectedPath;
use crate::tmpfs::TmpfsMountSet;
use crate::traits::{ContainerId, ErrorCode};

/// 暗黙・固定のマウントがある、bind を置けないコンテナ内の最上位（`/dev` 系は `crate::dev_mounts` の暗黙分と
/// `crate::path_masks` の固定集合をすべて覆う）。
const RESERVED_DESTINATIONS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// 検証済みの bind mount 1 件（フィールドは非公開。REPAIR-2）。
///
/// `nosuid` / `nodev` は常に付与され外せない（#1910）。伝播は [`Self::propagation`] に従い、既定は private、
/// `rslave` 指定時だけホストからの slave（#2669）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountSpec {
    index: usize,
    destination: MountDestination,
    source: String,
    read_only: bool,
    noexec: bool,
    recursive: bool,
    propagation: BindPropagation,
}

/// bind mount の伝播（検証済み。値は 2 通りで、`shared` 系を表現できない。REPAIR-2・SEC-1）。
///
/// `exec::MountIsolation::establish_with` が `HostSlave` の元を `/` の再帰 private 化の前に複製し、
/// `mount_binds` がその複製を載せる。コンテナからホストへ伝播する向きは表現できない（OCI-4・CRI-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindPropagation {
    /// 伝播させず、受けない（既定。`private`・`rprivate`・指定なし）。
    Private,
    /// ホストの peer group から受けるだけの slave（`rslave`）。ホスト側の元が shared か slave であることが前提で、
    /// 満たさなければ適用の段が起動を拒否する。
    HostSlave,
}

impl BindMountSpec {
    /// `mounts[]` 内の位置（監査・エラーの対応づけ用）。
    pub fn index(&self) -> usize {
        self.index
    }

    /// 正規化済みのコンテナ内マウント先。
    pub fn destination(&self) -> &MountDestination {
        &self.destination
    }

    /// 字句検証済みのホスト絶対パス（`/a/b` 形式）。
    pub fn source(&self) -> &str {
        &self.source
    }

    /// [`Self::source`] を `Path` として返す。
    pub fn source_path(&self) -> &Path {
        Path::new(&self.source)
    }

    /// 読み取り専用で付けるか。
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// `nosuid` を付ける（常に真。外せない）。
    pub fn nosuid(&self) -> bool {
        true
    }

    /// `nodev` を付ける（常に真。外せない）。
    pub fn nodev(&self) -> bool {
        true
    }

    /// `noexec` を付けるか（指定時のみ）。
    pub fn noexec(&self) -> bool {
        self.noexec
    }

    /// 再帰 bind（`rbind`）か。
    pub fn recursive(&self) -> bool {
        self.recursive
    }

    /// 伝播（既定は private。`rslave` 指定時だけ `HostSlave`）。
    pub fn propagation(&self) -> BindPropagation {
        self.propagation
    }
}

/// bind mount 変換・検証の失敗分類。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindMountErrorKind {
    /// bind ではない種類（`UNIMPLEMENTED`）。
    NotBind,
    /// 件数が上限超過（位置なし）。
    TooMany {
        /// 指定された件数。
        count: usize,
        /// 上限。
        max: usize,
    },
    /// `source` が無い。
    MissingSource,
    /// `source` が字句規則に反する。
    InvalidSource,
    /// `source` が rootfs・bundle・状態ルートと同一または祖先。
    ForbiddenSource,
    /// `suid` / `dev`（制限を外す指定）。
    RestrictionLifting,
    /// 伝播系（`shared` / `rshared` / `slave` / `unbindable` 等。`rslave` は受ける）。
    Propagation,
    /// `rslave` と `private` / `rprivate` の併記（#2669。#2063 の (a) と同じ扱い）。
    ConflictingPropagation,
    /// 許可集合外のオプション。
    UnsupportedOption,
    /// `bind` と `rbind` の併記（暫定）。
    ConflictingBindKind,
    /// `/proc`・`/sys`・`/dev` とその配下への bind。
    ReservedDestination,
    /// 先行の bind と同一の宛先。
    DuplicateDestination {
        /// 重複先の位置。
        other: usize,
    },
    /// 先行の bind と親子の宛先（暫定）。
    NestedDestination {
        /// 親子関係の相手の位置。
        other: usize,
    },
    /// tmpfs のマウント先と重なる。
    OverlapsTmpfs,
    /// 注入ファイルの親ディレクトリ・宛先と重なる。
    OverlapsInjected,
    /// `readonlyPaths` / `maskedPaths` と重なる。
    OverlapsProtectedPath,
}

/// bind mount 変換・検証のエラー（ERR-1）。メッセージは位置と固定英文のみで、パス・オプション値を含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountError {
    index: Option<usize>,
    kind: BindMountErrorKind,
}

impl BindMountError {
    fn at(index: usize, kind: BindMountErrorKind) -> Self {
        Self {
            index: Some(index),
            kind,
        }
    }

    /// 構造化エラーコード。`NotBind` は `Unimplemented`、他は `InvalidArgument`。
    pub fn code(&self) -> ErrorCode {
        match self.kind {
            BindMountErrorKind::NotBind => ErrorCode::Unimplemented,
            _ => ErrorCode::InvalidArgument,
        }
    }

    /// 対象の `mounts[]` 内の位置（件数超過など集合全体の失敗は `None`）。
    pub fn index(&self) -> Option<usize> {
        self.index
    }

    /// 分類。
    pub fn kind(&self) -> &BindMountErrorKind {
        &self.kind
    }

    /// 位置と固定英文のみのメッセージ（入力値を含めない）。
    pub fn message(&self) -> String {
        let text = match &self.kind {
            BindMountErrorKind::NotBind => "mount type is not supported (only bind mounts)",
            BindMountErrorKind::TooMany { count, max } => {
                return format!("too many mounts: {count} exceeds limit {max}");
            }
            BindMountErrorKind::MissingSource => "bind mount has no source",
            BindMountErrorKind::InvalidSource => "bind mount source is not a valid absolute path",
            BindMountErrorKind::ForbiddenSource => "bind mount source is a forbidden host path",
            BindMountErrorKind::RestrictionLifting => "mount option lifts a mandatory restriction",
            BindMountErrorKind::Propagation => "mount propagation options are not supported",
            BindMountErrorKind::ConflictingPropagation => "conflicting mount propagation options",
            BindMountErrorKind::UnsupportedOption => "unsupported mount option",
            BindMountErrorKind::ConflictingBindKind => "both bind and rbind are specified",
            BindMountErrorKind::ReservedDestination => {
                "bind mount destination is reserved (/proc, /sys or /dev)"
            }
            BindMountErrorKind::DuplicateDestination { .. } => "duplicate bind mount destination",
            BindMountErrorKind::NestedDestination { .. } => "nested bind mount destinations",
            BindMountErrorKind::OverlapsTmpfs => "bind mount destination overlaps a tmpfs mount",
            BindMountErrorKind::OverlapsInjected => {
                "bind mount destination overlaps an injected file"
            }
            BindMountErrorKind::OverlapsProtectedPath => {
                "bind mount destination overlaps a readonly or masked path"
            }
        };
        match self.index {
            Some(i) => format!("mounts[{i}]: {text}"),
            None => text.to_owned(),
        }
    }
}

impl fmt::Display for BindMountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for BindMountError {}

/// 検証済みの bind mount 集合（`mounts[]` の指定順）。生成口は [`Self::from_mounts`] のみ。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindMountSet {
    mounts: Vec<BindMountSpec>,
    /// start の段が検査した保護対象（状態ストアのルート）のファイルシステム内の実体。適用の段が毎回照合する（SEC-1）。
    protected: Vec<ProtectedFsRoot>,
}

/// 保護対象のファイルシステム内の実体（mountinfo の `major:minor` と FS 内パス。bind mount の別名は同じ値になる）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtectedFsRoot {
    dev: String,
    path: String,
    /// 状態ルート配下にリンク数 2 以上の通常ファイル（別名のハードリンクを持つ状態ファイル）があった。
    /// 真なら同じ FS 上のディレクトリ元は、配下に状態ファイルの別名を含み得るため拒否する（SEC-1）。
    has_hard_linked_files: bool,
    /// 設定されていれば、適用の段が毎回この状態ルート（ホストの正規化済みパス）配下を走査し直して
    /// `has_hard_linked_files` を更新する（start 後に追加されたハードリンクを restart でも検出する。SEC-1・#1915）。
    scan_root: Option<String>,
    /// 走査で降りないホストのパス（別のファイルシステムのマウントポイント）。そのマウントは別の `ProtectedFsRoot` が
    /// 自分のマウントポイントを `scan_root` にして走査する。これにより、他の FS 上のリンクでこの FS を拒否しない（SEC-1・#1915）。
    scan_prune: Vec<String>,
    /// 真なら状態ルートではなく rootfs・bundle の実体。ハードリンクの検査は行わず、元（と rbind で公開される子孫マウント）が
    /// この実体と同一・祖先のときだけ拒否する（配下の別の実体を元にすることは許す。SEC-1）。
    containment_only: bool,
    /// 状態ルート自身を先頭に `/` を末尾にした `(st_dev, st_ino)` の鎖（start の段が fd で固定した実体。SEC-1・#2066）。
    /// 空なら固定していない。適用の段が元との同一・祖先・子孫を、mountinfo の文字列に依らず inode で照合する。
    inode_chain: Vec<(u64, u64)>,
    /// `inode_chain` を固定したときのホスト側パス（正規化済み）。適用の段が毎回これを `/` から辿り直し、固定した実体と
    /// 一致するかを確かめる。start の後に状態ルートが移動・改名されたら一致せず fail-closed になる（SEC-1・#2129）。
    chain_path: Option<String>,
}

impl ProtectedFsRoot {
    pub(crate) fn new(dev: String, path: String, has_hard_linked_files: bool) -> Self {
        Self {
            dev,
            path,
            has_hard_linked_files,
            scan_root: None,
            scan_prune: Vec::new(),
            containment_only: false,
            inode_chain: Vec::new(),
            chain_path: None,
        }
    }

    /// start の段が固定した状態ルートの inode の鎖（先頭が自身、末尾が `/`）を持たせる（SEC-1・#2066）。
    /// `host_path` は鎖を固定したホスト側のパスで、適用の段の辿り直し（#2129）に使う。
    pub(crate) fn with_inode_chain(mut self, host_path: String, chain: Vec<(u64, u64)>) -> Self {
        self.chain_path = Some(host_path);
        self.inode_chain = chain;
        self
    }

    /// 鎖を固定したホスト側のパス（適用の段が辿り直す。Linux 限定の `exec::mount_binds` だけが読む）。
    #[cfg(target_os = "linux")]
    pub(crate) fn chain_path(&self) -> Option<&str> {
        self.chain_path.as_deref()
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）だけが読む。空なら固定されていない。
    #[cfg(target_os = "linux")]
    pub(crate) fn inode_chain(&self) -> &[(u64, u64)] {
        &self.inode_chain
    }

    /// rootfs・bundle の実体を保護対象にする（同一・祖先の元だけを拒否する）。
    pub(crate) fn contained(dev: String, path: String) -> Self {
        Self {
            containment_only: true,
            ..Self::new(dev, path, false)
        }
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）だけが読む。
    #[cfg(target_os = "linux")]
    pub(crate) fn is_containment_only(&self) -> bool {
        self.containment_only
    }

    /// 適用のたびに `root` 配下のハードリンクを走査し直すようにする（`new` の固定値より優先）。
    /// `prune` のパス（走査根の配下の他 FS のマウントポイント）へは降りない。
    pub(crate) fn with_scan_root(mut self, root: String, prune: Vec<String>) -> Self {
        self.scan_root = Some(root);
        self.scan_prune = prune;
        self
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）だけが読む。
    #[cfg(target_os = "linux")]
    ///
    /// `scan_root` があれば呼び出しのたびに走査し直す。走査できない・項目数が多すぎる場合は「持つ」とみなす（fail-closed）。
    pub(crate) fn has_hard_linked_files(&self) -> bool {
        match &self.scan_root {
            Some(root) => state_tree_has_hard_links(std::path::Path::new(root), &self.scan_prune)
                .unwrap_or(true),
            None => self.has_hard_linked_files,
        }
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）だけが読む。
    #[cfg(target_os = "linux")]
    pub(crate) fn dev(&self) -> &str {
        &self.dev
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）だけが読む。
    #[cfg(target_os = "linux")]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

/// 状態ルート配下の走査で見る項目数の上限（超過は `None`。無制限の走査を避ける）。
#[cfg(target_os = "linux")]
const STATE_SCAN_MAX_ENTRIES: usize = 100_000;

/// 状態ルート配下に、リンク数 2 以上の通常ファイルがあるかを調べる（SEC-1・#1915）。
/// symlink は辿らない。読めない・項目数が `STATE_SCAN_MAX_ENTRIES` を超える場合は `None`（呼び出し側が「持つ」とみなす）。
/// 走査から attach までの間に追加されるハードリンクは検出できない（残る競合。状態ルートへの書き込み権限が前提）。
#[cfg(target_os = "linux")]
/// `prune` に一致するパスのディレクトリには降りない（別 FS のマウントを、この FS の判定に混ぜない）。
fn state_tree_has_hard_links(root: &std::path::Path, prune: &[String]) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            seen += 1;
            if seen > STATE_SCAN_MAX_ENTRIES {
                return None;
            }
            let meta = std::fs::symlink_metadata(entry.path()).ok()?;
            if meta.is_dir() {
                let path = entry.path();
                if prune.iter().any(|p| path == std::path::Path::new(p)) {
                    continue;
                }
                stack.push(path);
            } else if meta.is_file() && meta.nlink() > 1 {
                return Some(true);
            }
        }
    }
    Some(false)
}

impl BindMountSet {
    /// start の段が検査した保護対象の実体を持たせる。適用の段が固定した元に対して毎回照合する（SEC-1・#1915）。
    pub(crate) fn with_protected_roots(mut self, roots: Vec<ProtectedFsRoot>) -> Self {
        self.protected = roots;
        self
    }

    /// 適用の段（Linux 限定の `exec::mount_binds`）が照合する保護対象の実体。
    #[cfg(target_os = "linux")]
    pub(crate) fn protected_roots(&self) -> &[ProtectedFsRoot] {
        &self.protected
    }

    /// `mounts[]` を検証して bind の集合へ変換する。1 件でも拒否されれば全体を拒否する（fail-closed）。
    ///
    /// 件数は確保前に検証する。処理順は種類 → オプション → マウント元 → マウント先 → 先行 bind との関係。
    pub fn from_mounts(mounts: &[OciMount]) -> Result<Self, BindMountError> {
        if mounts.len() > CONFIG_MAX_MOUNTS {
            return Err(BindMountError {
                index: None,
                kind: BindMountErrorKind::TooMany {
                    count: mounts.len(),
                    max: CONFIG_MAX_MOUNTS,
                },
            });
        }
        let mut out: Vec<BindMountSpec> = Vec::with_capacity(mounts.len());
        for (index, m) in mounts.iter().enumerate() {
            // `/sys` の sysfs は `SysfsMountSpec` が受ける（#2020）。位置（index）は元の `mounts[]` のまま保つ。
            if OciMountKind::of(m) == OciMountKind::Sysfs {
                continue;
            }
            let opts = parse_options(index, m)?;
            let source = validate_source(index, m)?;
            let dest = m.mount_destination();
            if RESERVED_DESTINATIONS
                .iter()
                .any(|r| overlaps(dest.as_str(), r) && dest.as_str().len() >= r.len())
            {
                return Err(BindMountError::at(
                    index,
                    BindMountErrorKind::ReservedDestination,
                ));
            }
            for prev in &out {
                if prev.destination.as_str() == dest.as_str() {
                    return Err(BindMountError::at(
                        index,
                        BindMountErrorKind::DuplicateDestination { other: prev.index },
                    ));
                }
                if overlaps(prev.destination.as_str(), dest.as_str()) {
                    return Err(BindMountError::at(
                        index,
                        BindMountErrorKind::NestedDestination { other: prev.index },
                    ));
                }
            }
            out.push(BindMountSpec {
                index,
                destination: dest.clone(),
                source,
                read_only: opts.read_only,
                noexec: opts.noexec,
                recursive: opts.recursive,
                propagation: opts.propagation,
            });
        }
        Ok(Self {
            mounts: out,
            protected: Vec::new(),
        })
    }

    /// 指定順の bind 一覧。
    pub fn mounts(&self) -> &[BindMountSpec] {
        &self.mounts
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// `rslave`（ホストからの slave）の bind を 1 件でも含むか。launcher が中間プロセス側の `/` の伝播を選ぶ根拠にする。
    pub fn has_host_slave(&self) -> bool {
        self.mounts
            .iter()
            .any(|m| m.propagation == BindPropagation::HostSlave)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// 利用者指定の tmpfs のマウント先と同一・祖先・子孫なら拒否する。
    pub fn check_against_tmpfs(&self, tmpfs: &TmpfsMountSet) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if tmpfs
                .mounts()
                .iter()
                .any(|t| overlaps(b.destination.as_str(), t.destination.as_str()))
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsTmpfs,
                ));
            }
        }
        Ok(())
    }

    /// 注入ファイルの親ディレクトリ・宛先と同一・祖先・子孫なら拒否する。
    pub fn check_against_injected(&self, injected: &InjectedFileSet) -> Result<(), BindMountError> {
        for b in &self.mounts {
            let hit = injected.files().iter().any(|f| {
                overlaps(b.destination.as_str(), f.parent())
                    || overlaps(b.destination.as_str(), f.destination().as_str())
            });
            if hit {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsInjected,
                ));
            }
        }
        Ok(())
    }

    /// `linux.readonlyPaths` / `linux.maskedPaths` と同一・祖先・子孫なら拒否する。
    ///
    /// `/proc`・`/sys` 配下の固定集合は [`Self::from_mounts`] の予約先拒否が覆う。
    pub fn check_against_protected_paths(
        &self,
        readonly: &[ProtectedPath],
        masked: &[ProtectedPath],
    ) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if readonly
                .iter()
                .chain(masked.iter())
                .any(|p| overlaps(b.destination.as_str(), p.as_str()))
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsProtectedPath,
                ));
            }
        }
        Ok(())
    }

    /// マウント元が `forbidden`（rootfs・bundle・状態ルートのホスト絶対パス。呼び出し側が渡す）と
    /// 同一または祖先なら拒否する。
    ///
    /// 字句比較のみ。子孫は受ける（#2063 の決定 (d)。rootfs・bundle の配下は公開してよい）。状態ルートはこの関数に
    /// 渡さず [`Self::check_against_protected_trees`] で検査する。実体照合（rootfs・bundle の祖先を別名経由で
    /// 公開させない）は `start` と適用の段（#1913）が担う（詳細は module doc）。
    pub fn check_against_host_paths(&self, forbidden: &[&str]) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if forbidden
                .iter()
                .any(|f| overlaps(f, &b.source) && f.len() >= b.source.len())
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::ForbiddenSource,
                ));
            }
        }
        Ok(())
    }

    /// 元が `protected` のいずれかと同一・祖先・子孫のとき `ForbiddenSource` で拒否する（状態ルート用）。
    ///
    /// [`Self::check_against_host_paths`] は子孫を許すが、状態ルートの配下を書込み可能で公開すると
    /// `state.json` 等を改変できるため、両方向で拒否する（SEC-1・OCI-4・#1915。#2063 の決定 (d)）。字句比較のみ。
    pub fn check_against_protected_trees(&self, protected: &[&str]) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if protected.iter().any(|f| overlaps(f, &b.source)) {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::ForbiddenSource,
                ));
            }
        }
        Ok(())
    }

    /// 各指定（元と `recursive` の指定を含む）を `hits` に渡し、`true`（保護対象に到達する）なら
    /// `ForbiddenSource` で拒否する。
    ///
    /// 到達の判定（mountinfo によるファイルシステム内の実体照合など）は呼び出し側が担う（SEC-1・#1915）。
    pub fn check_sources_with<F>(&self, hits: F) -> Result<(), BindMountError>
    where
        F: Fn(&BindMountSpec) -> bool,
    {
        for b in &self.mounts {
            if hits(b) {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::ForbiddenSource,
                ));
            }
        }
        Ok(())
    }

    /// 各元を `resolve`（実体のパスへの正規化。解決できなければ `None` で対象外）で解決してから
    /// [`Self::check_against_protected_trees`] と同じ規則で拒否する（symlink 経由の到達を塞ぐ）。
    pub fn check_resolved_sources_against_protected_trees<F>(
        &self,
        protected: &[&str],
        resolve: F,
    ) -> Result<(), BindMountError>
    where
        F: Fn(&str) -> Option<String>,
    {
        for b in &self.mounts {
            if let Some(real) = resolve(&b.source)
                && protected.iter().any(|f| overlaps(f, &real))
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::ForbiddenSource,
                ));
            }
        }
        Ok(())
    }
}

/// options を畳み込んだ結果。
struct ParsedOptions {
    read_only: bool,
    noexec: bool,
    recursive: bool,
    propagation: BindPropagation,
}

fn parse_options(index: usize, m: &OciMount) -> Result<ParsedOptions, BindMountError> {
    let err = |kind| BindMountError::at(index, kind);
    let (mut has_bind, mut has_rbind) = (false, false);
    let (mut read_only, mut noexec) = (false, false);
    let (mut has_slave, mut has_private) = (false, false);
    // 種類判定を先に行う（処理順は種類 → オプション）。bind 以外は他オプションの内容に依らず NotBind。
    let opts_have = |name: &str| m.options().iter().any(|o| o.as_str() == name);
    if !(m.fs_type() == Some("bind") || opts_have("bind") || opts_have("rbind")) {
        return Err(err(BindMountErrorKind::NotBind));
    }
    for opt in m.options() {
        match opt.as_str() {
            "bind" => has_bind = true,
            "rbind" => has_rbind = true,
            "ro" => read_only = true,
            "rw" => read_only = false,
            "noexec" => noexec = true,
            "exec" => noexec = false,
            // 効果は常時付与済み（nosuid / nodev）または既定（private）。
            "nosuid" | "nodev" => {}
            "private" | "rprivate" => has_private = true,
            "rslave" => has_slave = true,
            "suid" | "dev" => return Err(err(BindMountErrorKind::RestrictionLifting)),
            "shared" | "rshared" | "slave" | "unbindable" | "runbindable" => {
                return Err(err(BindMountErrorKind::Propagation));
            }
            _ => return Err(err(BindMountErrorKind::UnsupportedOption)),
        }
    }
    if has_bind && has_rbind {
        return Err(err(BindMountErrorKind::ConflictingBindKind));
    }
    if has_slave && has_private {
        return Err(err(BindMountErrorKind::ConflictingPropagation));
    }
    Ok(ParsedOptions {
        read_only,
        noexec,
        recursive: has_rbind,
        propagation: if has_slave {
            BindPropagation::HostSlave
        } else {
            BindPropagation::Private
        },
    })
}

fn validate_source(index: usize, m: &OciMount) -> Result<String, BindMountError> {
    let invalid = || BindMountError::at(index, BindMountErrorKind::InvalidSource);
    let path = m
        .source()
        .ok_or_else(|| BindMountError::at(index, BindMountErrorKind::MissingSource))?;
    let s = path.to_str().ok_or_else(invalid)?;
    if s.len() > CONFIG_MAX_PATH_BYTES || s.contains('\0') || s.contains('\\') {
        return Err(invalid());
    }
    let rest = s.strip_prefix('/').ok_or_else(invalid)?;
    // `/` のみ（rest が空）はホスト全体を覆うため拒否する。空要素・`.`・`..` も正規形以外として拒否する。
    if rest.is_empty() || rest.split('/').any(|e| matches!(e, "" | "." | "..")) {
        return Err(invalid());
    }
    Ok(s.to_owned())
}

/// bind mount の変換拒否を `Mount` 監査レコードにする（SEC-4）。
///
/// `path` は位置が `mounts` で解決できるときだけコンテナ内の宛先を載せる。マウント元（ホスト側パス）は載せない。
/// エラーは常にそのまま返る。本番では `start` が `ProcessLauncher::rejection_audit_sink` の sink を渡す（#1915）。
pub fn audit_bind_mount_error(
    err: BindMountError,
    mounts: &[OciMount],
    container: Option<&ContainerId>,
    sink: &dyn AuditSink,
) -> AuditedRejection<BindMountError> {
    let path = err
        .index()
        .and_then(|i| mounts.get(i))
        .map(|m| m.mount_destination().as_path());
    record_mount_rejection(err, path, container, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::AuditDelivery;
    use crate::audit_log::mount::tests::VecSink;
    use crate::dev_mounts::ImplicitDevMount;
    use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
    use crate::oci_runtime::{OciConfig, parse_config_bytes};
    use crate::tmpfs::TmpfsMountSpec;
    use serde_json::{Value, json};

    fn cfg_with(mounts: Value, extra: Value) -> OciConfig {
        let mut v = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": mounts,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in e {
                o.insert(k.clone(), val.clone());
            }
        }
        parse_config_bytes(v.to_string().as_bytes()).expect("valid config")
    }

    fn cfg(mounts: Value) -> OciConfig {
        cfg_with(mounts, json!({}))
    }

    fn one(ty: Option<&str>, dest: &str, src: Option<&str>, opts: &[&str]) -> Value {
        let mut m = json!({"destination": dest, "options": opts});
        if let (Some(o), Some(t)) = (m.as_object_mut(), ty) {
            o.insert("type".into(), json!(t));
        }
        if let (Some(o), Some(s)) = (m.as_object_mut(), src) {
            o.insert("source".into(), json!(s));
        }
        m
    }

    fn bind(opts: &[&str]) -> Value {
        one(Some("bind"), "/mnt/d", Some("/data"), opts)
    }

    fn set(mounts: Value) -> Result<BindMountSet, BindMountError> {
        BindMountSet::from_mounts(cfg(mounts).mounts())
    }

    fn kind_of(mounts: Value) -> (BindMountErrorKind, Option<usize>, ErrorCode) {
        let e = set(mounts).expect_err("must be rejected");
        (e.kind().clone(), e.index(), e.code())
    }

    /// OCI-4・CORE-2: 受ける bind の各フィールドを具体値で照合する。
    #[test]
    fn core2_oci4_bind_accepts_forms() {
        let s = set(json!([
            one(Some("bind"), "/a", Some("/data/a"), &[]),
            one(Some("none"), "/b", Some("/data/b"), &["rbind", "rprivate"]),
            one(None, "/c", Some("/data/c"), &["bind", "ro"]),
            one(
                Some("none"),
                "/d",
                Some("/data/d"),
                &["rbind", "nosuid", "nodev", "noexec", "private"]
            ),
        ]))
        .expect("accepted");
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        let m = s.mounts();
        assert_eq!(m[0].index(), 0);
        assert_eq!(m[0].destination().as_str(), "/a");
        assert_eq!(m[0].source(), "/data/a");
        assert_eq!(m[0].source_path(), Path::new("/data/a"));
        assert_eq!(
            (m[0].read_only(), m[0].noexec(), m[0].recursive()),
            (false, false, false)
        );
        assert_eq!(
            (m[1].read_only(), m[1].noexec(), m[1].recursive()),
            (false, false, true)
        );
        assert_eq!(
            (m[2].read_only(), m[2].noexec(), m[2].recursive()),
            (true, false, false)
        );
        assert_eq!(
            (m[3].read_only(), m[3].noexec(), m[3].recursive()),
            (false, true, true)
        );
        assert_eq!(m[3].index(), 3);
        for x in m {
            assert!(x.nosuid());
            assert!(x.nodev());
        }
    }

    /// CORE-5: ro/rw・noexec/exec は後の指定が勝つ。
    #[test]
    fn core5_bind_option_last_wins() {
        for (opts, ro, nx) in [
            (vec!["bind", "ro", "rw"], false, false),
            (vec!["bind", "rw", "ro"], true, false),
            (vec!["bind", "noexec", "exec"], false, false),
            (vec!["bind", "exec", "noexec"], false, true),
            (vec!["bind", "ro", "ro"], true, false),
        ] {
            let s = set(json!([bind(&opts)])).expect("accepted");
            let m = &s.mounts()[0];
            assert_eq!((m.read_only(), m.noexec()), (ro, nx), "opts={opts:?}");
        }
    }

    /// OCI-4・SEC-2（#2020）: `/sys` の sysfs は bind 側で読み飛ばされ、後続の bind の位置は元のまま残る。
    #[test]
    fn oci4_bind_skips_sysfs_and_keeps_indexes() {
        let s = set(json!([
            one(Some("sysfs"), "/sys", Some("sysfs"), &["ro", "nosuid"]),
            one(Some("bind"), "/a", Some("/data/a"), &[]),
            one(Some("sysfs"), "/anywhere", None, &["rw"]),
            one(Some("bind"), "/b", Some("/data/b"), &[]),
        ]))
        .expect("sysfs entries are not the bind set's concern");
        let seen: Vec<_> = s
            .mounts()
            .iter()
            .map(|m| (m.index(), m.destination().as_str().to_owned()))
            .collect();
        assert_eq!(seen, [(1, "/a".to_owned()), (3, "/b".to_owned())]);
    }

    /// OCI-4: bind 以外の種類は UNIMPLEMENTED。位置を照合する。
    #[test]
    fn oci4_bind_rejects_non_bind_types() {
        for ty in ["proc", "tmpfs", "devpts", "mqueue", "cgroup"] {
            let (k, i, c) = kind_of(json!([
                bind(&[]),
                one(Some(ty), "/x", Some("/data/x"), &["nosuid"])
            ]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::NotBind,
                    Some(1),
                    ErrorCode::Unimplemented
                )
            );
        }
        let (k, _, c) = kind_of(json!([one(None, "/x", None, &[])]));
        assert_eq!(
            (k, c),
            (BindMountErrorKind::NotBind, ErrorCode::Unimplemented)
        );
        // 許可集合外のオプションがあっても種類判定が先（UNIMPLEMENTED）。
        for opts in [
            &["size=64m"][..],
            &["mode=755", "strictatime"],
            &["newinstance"],
        ] {
            let (k, i, c) = kind_of(json!([one(Some("tmpfs"), "/x", Some("/data/x"), opts)]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::NotBind,
                    Some(0),
                    ErrorCode::Unimplemented
                ),
                "opts={opts:?}"
            );
        }
    }

    /// SEC-1: 制限を外すオプションは拒否する。
    #[test]
    fn sec1_bind_rejects_lifting_options() {
        for o in ["suid", "dev"] {
            let (k, i, c) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::RestrictionLifting,
                    Some(0),
                    ErrorCode::InvalidArgument
                )
            );
        }
    }

    /// SEC-1: 伝播系は拒否する。
    #[test]
    fn sec1_bind_rejects_propagation() {
        for o in ["shared", "rshared", "slave", "unbindable", "runbindable"] {
            let (k, _, _) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(k, BindMountErrorKind::Propagation, "opt={o}");
        }
    }

    /// OCI-4・CRI-2（#2669）: `rslave` は受け、伝播は `HostSlave`。`bind` でも `rbind` でも同じ。
    #[test]
    fn oci4_bind_accepts_rslave() {
        let m = set(json!([
            one(Some("bind"), "/x", Some("/var/lib/x"), &["rbind", "rslave"]),
            one(Some("bind"), "/y", Some("/var/lib/y"), &["bind", "rslave"]),
            one(
                Some("bind"),
                "/z",
                Some("/var/lib/z"),
                &["rbind", "rprivate"]
            ),
        ]))
        .expect("accepted");
        let got: Vec<_> = m
            .mounts()
            .iter()
            .map(|b| (b.recursive(), b.propagation()))
            .collect();
        assert_eq!(
            got,
            vec![
                (true, BindPropagation::HostSlave),
                (false, BindPropagation::HostSlave),
                (true, BindPropagation::Private),
            ]
        );
        assert!(m.has_host_slave());
        let plain = set(json!([bind(&["bind"])])).expect("plain");
        assert!(!plain.has_host_slave());
    }

    /// SEC-1（#2669）: `rslave` と `private` / `rprivate` の併記は拒否する。
    #[test]
    fn sec1_bind_rejects_rslave_with_private() {
        for o in ["private", "rprivate"] {
            for opts in [["bind", "rslave", o], ["bind", o, "rslave"]] {
                let (k, i, c) = kind_of(json!([bind(&opts)]));
                assert_eq!(
                    (k, i, c),
                    (
                        BindMountErrorKind::ConflictingPropagation,
                        Some(0),
                        ErrorCode::InvalidArgument
                    ),
                    "opts={opts:?}"
                );
            }
        }
    }

    /// SEC-1: 許可集合外は拒否する（fail-closed）。
    #[test]
    fn sec1_bind_rejects_unknown_options() {
        for o in [
            "defaults", "rro", "rnosuid", "rdev", "idmap", "remount", "", "RO",
        ] {
            let (k, _, _) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(k, BindMountErrorKind::UnsupportedOption, "opt={o:?}");
        }
    }

    /// CORE-2: bind と rbind の併記は拒否する（#2063 の決定 (a)。SEC-1・OCI-4）。
    #[test]
    fn core2_bind_rejects_bind_and_rbind() {
        let (k, i, _) = kind_of(json!([bind(&["bind", "rbind"])]));
        assert_eq!((k, i), (BindMountErrorKind::ConflictingBindKind, Some(0)));
    }

    /// CORE-2: マウント元の字句規則（#2063 の決定 (b)。`.` 要素と `\` は拒否）。
    #[test]
    fn core2_bind_source_lexical() {
        for ok in ["/data", "/a/b"] {
            assert!(
                set(json!([one(Some("bind"), "/x", Some(ok), &[])])).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "data", "./a", "/", "/.", "/a/.", "//", "/a//b", "/a/", "/a/./b", "/a/../b", "/a\\b",
        ] {
            let (k, i, _) = kind_of(json!([one(Some("bind"), "/x", Some(bad), &[])]));
            assert_eq!(
                (k, i),
                (BindMountErrorKind::InvalidSource, Some(0)),
                "src={bad}"
            );
        }
        let (k, _, _) = kind_of(json!([one(Some("bind"), "/x", None, &[])]));
        assert_eq!(k, BindMountErrorKind::MissingSource);
    }

    /// CORE-2・SEC-1: /proc・/sys・/dev とその配下は拒否する。
    #[test]
    fn core2_bind_rejects_reserved_destinations() {
        for d in [
            "/proc",
            "/proc/sys",
            "/sys",
            "/sys/fs",
            "/dev",
            "/dev/shm",
            "/dev/pts",
            "/dev/x",
        ] {
            let (k, _, _) = kind_of(json!([one(Some("bind"), d, Some("/data"), &[])]));
            assert_eq!(k, BindMountErrorKind::ReservedDestination, "dest={d}");
        }
        for d in ["/devx", "/procfs", "/system"] {
            assert!(
                set(json!([one(Some("bind"), d, Some("/data"), &[])])).is_ok(),
                "{d}"
            );
        }
        for m in ImplicitDevMount::ALL {
            let (k, _, _) = kind_of(json!([one(
                Some("bind"),
                m.destination(),
                Some("/data"),
                &[]
            )]));
            assert_eq!(k, BindMountErrorKind::ReservedDestination);
        }
    }

    /// CORE-2: 同一宛先・入れ子は拒否し、相手の位置を返す（#2063 の決定 (c)）。
    #[test]
    fn core2_bind_rejects_duplicate_and_nested() {
        let m = |d: &str| one(Some("bind"), d, Some("/data"), &[]);
        let (k, i, _) = kind_of(json!([m("/a"), m("/a")]));
        assert_eq!(
            (k, i),
            (
                BindMountErrorKind::DuplicateDestination { other: 0 },
                Some(1)
            )
        );
        let (k, i, _) = kind_of(json!([m("/a"), m("/a/b")]));
        assert_eq!(
            (k, i),
            (BindMountErrorKind::NestedDestination { other: 0 }, Some(1))
        );
        let (k, i, _) = kind_of(json!([m("/a/b"), m("/a")]));
        assert_eq!(
            (k, i),
            (BindMountErrorKind::NestedDestination { other: 0 }, Some(1))
        );
        assert!(set(json!([m("/a"), m("/ab")])).is_ok());
    }

    /// CORE-2: 件数超過は確保前に拒否する。
    #[test]
    fn core2_bind_rejects_too_many() {
        let c = cfg(json!([bind(&[])]));
        let one_mount = c.mounts()[0].clone();
        let many = vec![one_mount; CONFIG_MAX_MOUNTS + 1];
        let e = BindMountSet::from_mounts(&many).expect_err("too many");
        assert_eq!(
            *e.kind(),
            BindMountErrorKind::TooMany {
                count: CONFIG_MAX_MOUNTS + 1,
                max: CONFIG_MAX_MOUNTS
            }
        );
        assert_eq!(e.index(), None);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// ERR-1: メッセージは位置と固定英文のみで入力値を含めない。
    #[test]
    fn err1_bind_error_message_has_no_values() {
        let c = cfg(json!([
            bind(&[]),
            one(
                Some("bind"),
                "/x",
                Some("/secret-host-dir"),
                &["bind", "x-token"]
            )
        ]));
        let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
        let (m, d) = (e.message(), e.to_string());
        assert_eq!(m, d);
        assert_eq!(m, "mounts[1]: unsupported mount option");
        assert!(!m.contains("x-token") && !m.contains("secret-host-dir"));
        // 伝播の併記（#2669）も位置と固定文言だけ。
        let e =
            BindMountSet::from_mounts(cfg(json!([bind(&["bind", "rslave", "rprivate"])])).mounts())
                .expect_err("rejected");
        assert_eq!(
            e.message(),
            "mounts[0]: conflicting mount propagation options"
        );
    }

    /// CORE-2: tmpfs・注入・保護パス・ホストパスとの交差検査。
    #[test]
    fn core2_bind_cross_checks() {
        let b = |d: &str| set(json!([one(Some("bind"), d, Some("/var/lib/y"), &[])])).expect("set");
        // tmpfs
        for d in ["/scratch", "/scratch/x", "/scratch/x/y"] {
            let mut t = TmpfsMountSet::new();
            t.push(TmpfsMountSpec::new("/scratch/x", None).expect("tmpfs"))
                .expect("push");
            let e = b(d).check_against_tmpfs(&t).expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsTmpfs);
        }
        let mut t = TmpfsMountSet::new();
        t.push(TmpfsMountSpec::new("/scratch", None).expect("tmpfs"))
            .expect("push");
        assert!(b("/other").check_against_tmpfs(&t).is_ok());
        // 注入
        let inj = |dest: &str| {
            let mut set = InjectedFileSet::new();
            set.push(
                InjectedFileSpec::new(
                    dest,
                    InjectedContent::from_bytes(b"x".to_vec()).expect("content"),
                    InjectedFileMode::DEFAULT,
                )
                .expect("spec"),
            )
            .expect("push");
            set
        };
        for d in ["/run/secrets", "/run", "/run/secrets/a"] {
            let e = b(d)
                .check_against_injected(&inj("/run/secrets/a"))
                .expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsInjected);
        }
        assert!(
            b("/other")
                .check_against_injected(&inj("/run/secrets/a"))
                .is_ok()
        );
        // 保護パス
        let c = cfg_with(
            json!([]),
            json!({"linux": {"readonlyPaths": ["/data/x"], "maskedPaths": ["/m/y"]}}),
        );
        for d in ["/data", "/data/x", "/m"] {
            let e = b(d)
                .check_against_protected_paths(c.readonly_paths(), c.masked_paths())
                .expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsProtectedPath);
        }
        assert!(
            b("/datax")
                .check_against_protected_paths(c.readonly_paths(), c.masked_paths())
                .is_ok()
        );
        // ホストパス
        let host = ["/var/lib/x/rootfs"];
        for src in ["/var/lib", "/var/lib/x/rootfs"] {
            let one_b = set(json!([one(Some("bind"), "/d", Some(src), &[])])).expect("set");
            let e = one_b.check_against_host_paths(&host).expect_err(src);
            assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
        }
        let ok = set(json!([one(Some("bind"), "/d", Some("/var/lib/y"), &[])])).expect("set");
        assert!(ok.check_against_host_paths(&host).is_ok());
    }

    /// SEC-1・OCI-4: #2063 の決定 (d)。rootfs・bundle の子孫は受け、同一・祖先は拒否する。状態ルートは子孫も拒否する。
    #[test]
    fn sec1_oci4_host_paths_decision_d() {
        let src = |p: &str| set(json!([one(Some("bind"), "/d", Some(p), &[])])).expect("set");
        let host = ["/var/lib/x/rootfs", "/var/lib/x"];
        for ok in ["/var/lib/x/rootfs/sub", "/var/lib/x/data"] {
            assert!(src(ok).check_against_host_paths(&host).is_ok(), "{ok}");
        }
        for bad in ["/var/lib/x", "/var/lib"] {
            let e = src(bad).check_against_host_paths(&host).expect_err(bad);
            assert_eq!(
                (e.kind().clone(), e.index()),
                (BindMountErrorKind::ForbiddenSource, Some(0)),
                "{bad}"
            );
        }
        let state = ["/var/lib/fandhe"];
        for bad in ["/var/lib/fandhe/ctr-1", "/var/lib/fandhe", "/var/lib"] {
            let e = src(bad)
                .check_against_protected_trees(&state)
                .expect_err(bad);
            assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource, "{bad}");
        }
        assert!(
            src("/var/lib/fandhe-other")
                .check_against_protected_trees(&state)
                .is_ok()
        );
    }

    /// SEC-4: 監査はコンテナ内の宛先のみを載せ、マウント元を載せない。
    #[test]
    fn sec4_bind_audit_records_destination_only() {
        let c = cfg(json!([
            bind(&[]),
            one(
                Some("bind"),
                "/mnt/two",
                Some("/secret-host-dir"),
                &["bind", "suid"]
            )
        ]));
        let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
        let sink = VecSink::new(false);
        let r = audit_bind_mount_error(e, c.mounts(), None, &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(r.error.code(), ErrorCode::InvalidArgument);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        let line = format!("{:?}", recs[0]);
        assert!(line.contains("/mnt/two"), "{line}");
        assert!(!line.contains("secret-host-dir"), "{line}");

        // 位置なし（件数超過）は path なしで記録し、sink 失敗でもエラーは返る。
        let many = vec![c.mounts()[0].clone(); CONFIG_MAX_MOUNTS + 1];
        let e = BindMountSet::from_mounts(&many).expect_err("too many");
        let bad = VecSink::new(true);
        let r = audit_bind_mount_error(e, &many, None, &bad);
        assert!(matches!(r.error.kind(), BindMountErrorKind::TooMany { .. }));
        assert_ne!(r.delivery, AuditDelivery::Recorded);
    }
}
