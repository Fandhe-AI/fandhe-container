//! tmpfs マウントの検証済み仕様型（SUP-12・TASK-169.2・MS-9。`--shm-size` / `--tmpfs`）。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `container_options`（Docker 互換の文字列文法）が `--shm-size` / `--tmpfs` を解析して
//! 本モジュールの型へ変換し、`crate::exec` の `mount_tmpfs`（Linux 限定・`prepare_rootfs` の後・
//! `pivot_root` の前）が実マウントする。本モジュールは OS 非依存の純粋な型だけを持ち、`mount(2)` の
//! data 文字列は型付きフィールドからのみ組み立てる（利用者由来の文字列を data へ連結する経路を
//! 作らない。インジェクション対策）。
//!
//! # 契約
//!
//! - `nosuid`・`nodev` は常に付与し、外せない（SEC-1 の fail-closed）
//! - マウント先は [`MountDestination`]（字句正規化・`..` 拒否）で検証する。`/proc` とその配下・`/dev`
//!   そのものは覆い隠しになるため拒否する。重複と件数上限（[`TMPFS_MAX_MOUNTS`]）も拒否する
//! - サイズ未指定（`None`）はカーネル既定（物理メモリの 50%）で、Docker と同じ挙動。tmpfs のページは
//!   コンテナの memory cgroup に課金されるため `memory.max`（CORE-3）で抑えられる
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! `uid=`・`gid=`・`%` 指定・`suid` / `dev` の許可・OCI `mounts[]` からの変換（TASK-127・TASK-29 系）。

use crate::oci_runtime::MountDestination;
use crate::traits::types::{ErrorCode, TraitError};

/// 1 コンテナあたりの tmpfs マウント件数の上限（無制限確保・過大な設定の拒否）。
pub const TMPFS_MAX_MOUNTS: usize = 64;

/// `/dev/shm` のマウント先。
pub const DEV_SHM_PATH: &str = "/dev/shm";

fn invalid(msg: impl Into<String>) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

/// tmpfs のサイズ（バイト）。0 と `i64::MAX` 超は表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TmpfsSize(u64);

impl TmpfsSize {
    /// バイト数から作る。0 と `i64::MAX` 超は拒否する。
    pub fn from_bytes(bytes: u64) -> Result<Self, TraitError> {
        if bytes == 0 {
            return Err(invalid("tmpfs size must be greater than zero"));
        }
        if bytes > i64::MAX as u64 {
            return Err(invalid("tmpfs size is too large"));
        }
        Ok(Self(bytes))
    }

    /// バイト数。
    pub fn bytes(self) -> u64 {
        self.0
    }
}

/// tmpfs ルートのモード（`0o7777` 以下）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpfsMode(u32);

impl TmpfsMode {
    /// 既定の `1777`（Docker の `--tmpfs` と同じ）。
    pub const DEFAULT: Self = Self(0o1777);

    /// モードから作る。`0o7777` 超は拒否する。
    pub fn new(mode: u32) -> Result<Self, TraitError> {
        if mode > 0o7777 {
            return Err(invalid("tmpfs mode must not exceed 07777"));
        }
        Ok(Self(mode))
    }

    /// モード値。
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// 検証済みの tmpfs マウント 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TmpfsMountSpec {
    /// コンテナ内のマウント先（正規化済み）。
    pub destination: MountDestination,
    /// サイズ。`None` はカーネル既定。
    pub size: Option<TmpfsSize>,
    /// ルートのモード。
    pub mode: TmpfsMode,
    /// 読み取り専用か。
    pub read_only: bool,
    /// 実行を許すか（偽なら `noexec`）。
    pub exec: bool,
}

impl TmpfsMountSpec {
    /// 任意のマウント先の tmpfs（`noexec`・読み書き・mode 1777）。
    pub fn new(destination: &str, size: Option<TmpfsSize>) -> Result<Self, TraitError> {
        let destination = MountDestination::parse(destination)
            .map_err(|_| invalid("invalid tmpfs mount destination"))?;
        Ok(Self {
            destination,
            size,
            mode: TmpfsMode::DEFAULT,
            read_only: false,
            exec: false,
        })
    }

    /// `/dev/shm` 用（`--shm-size`）。`noexec`・mode 1777。
    pub fn dev_shm(size: TmpfsSize) -> Result<Self, TraitError> {
        Self::new(DEV_SHM_PATH, Some(size))
    }

    /// `mount(2)` の data 文字列（`mode=1777,size=67108864`）。型付きフィールドからのみ組み立てる。
    pub fn data_string(&self) -> String {
        match self.size {
            Some(s) => format!("mode={:o},size={}", self.mode.bits(), s.bytes()),
            None => format!("mode={:o}", self.mode.bits()),
        }
    }
}

/// 検証済みの tmpfs マウント集合（指定順）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TmpfsMountSet {
    mounts: Vec<TmpfsMountSpec>,
}

impl TmpfsMountSet {
    /// 空の集合。
    pub fn new() -> Self {
        Self::default()
    }

    /// マウントを追加する。予約先・重複・件数上限超過は拒否する。
    pub fn push(&mut self, spec: TmpfsMountSpec) -> Result<(), TraitError> {
        let dest = spec.destination.as_str();
        if dest == "/proc" || dest.starts_with("/proc/") {
            return Err(invalid("tmpfs must not be mounted on /proc or below"));
        }
        if dest == "/dev" {
            return Err(invalid("tmpfs must not be mounted on /dev itself"));
        }
        if self
            .mounts
            .iter()
            .any(|m| m.destination == spec.destination)
        {
            return Err(invalid("duplicate tmpfs mount destination"));
        }
        if self.mounts.len() >= TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs mounts"));
        }
        self.mounts.push(spec);
        Ok(())
    }

    /// 指定順のマウント一覧。
    pub fn mounts(&self) -> &[TmpfsMountSpec] {
        &self.mounts
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(b: u64) -> TmpfsSize {
        TmpfsSize::from_bytes(b).expect("size")
    }

    #[test]
    fn sup12_task169_2_size_bounds() {
        assert!(TmpfsSize::from_bytes(0).is_err());
        assert!(TmpfsSize::from_bytes(i64::MAX as u64 + 1).is_err());
        assert_eq!(TmpfsSize::from_bytes(1).expect("one").bytes(), 1);
        assert_eq!(
            TmpfsSize::from_bytes(i64::MAX as u64).expect("max").bytes(),
            i64::MAX as u64
        );
    }

    #[test]
    fn sup12_task169_2_mode_bounds() {
        assert_eq!(TmpfsMode::new(0o7777).expect("max").bits(), 0o7777);
        assert!(TmpfsMode::new(0o10000).is_err());
        assert_eq!(TmpfsMode::DEFAULT.bits(), 0o1777);
    }

    #[test]
    fn sup12_task169_2_data_string_exact() {
        let shm = TmpfsMountSpec::dev_shm(size(64 * 1024 * 1024)).expect("shm");
        assert_eq!(shm.destination.as_str(), "/dev/shm");
        assert_eq!(shm.data_string(), "mode=1777,size=67108864");
        assert!(!shm.exec && !shm.read_only);
        let none = TmpfsMountSpec::new("/run", None).expect("run");
        assert_eq!(none.data_string(), "mode=1777");
    }

    #[test]
    fn sup12_task169_2_destination_is_normalized_and_validated() {
        let s = TmpfsMountSpec::new("scratch//a/./b/", None).expect("normalized");
        assert_eq!(s.destination.as_str(), "/scratch/a/b");
        assert!(TmpfsMountSpec::new("/a/../b", None).is_err());
        assert!(TmpfsMountSpec::new("/", None).is_err());
        assert!(TmpfsMountSpec::new("", None).is_err());
    }

    #[test]
    fn sup12_task169_2_set_rejects_reserved_duplicate_and_overflow() {
        let mut set = TmpfsMountSet::new();
        for bad in ["/proc", "/proc/sys", "/dev"] {
            let e = set
                .push(TmpfsMountSpec::new(bad, None).expect("spec"))
                .expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
        set.push(TmpfsMountSpec::dev_shm(size(65536)).expect("shm"))
            .expect("first");
        assert!(
            set.push(TmpfsMountSpec::new("/dev/shm/", None).expect("dup"))
                .is_err()
        );
        let mut full = TmpfsMountSet::new();
        for i in 0..TMPFS_MAX_MOUNTS {
            full.push(TmpfsMountSpec::new(&format!("/m{i}"), None).expect("m"))
                .expect("within limit");
        }
        assert!(
            full.push(TmpfsMountSpec::new("/extra", None).expect("extra"))
                .is_err()
        );
        assert_eq!(set.mounts().len(), 1);
    }
}
