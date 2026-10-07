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

use crate::oci_runtime::{CONFIG_MAX_PATH_BYTES, MountDestination};
use crate::traits::types::{ErrorCode, TraitError};

/// 1 コンテナあたりの tmpfs マウント件数の上限（無制限確保・過大な設定の拒否）。
pub const TMPFS_MAX_MOUNTS: usize = 64;

/// マウント先の要素数（深さ）の上限。
///
/// `exec::mount_tmpfs` は要素ごとに `openat`（無ければ `mkdirat`）を行い、失敗時の後始末は作成した
/// 要素ごとに先頭から辿り直すため、処理量は深さの 2 乗に比例する。上限が無いと 4096 バイトの入力で
/// 約 2000 段の自動作成になる。実用上のマウント先（`/dev/shm`・`/run/lock`・`/var/lib/<app>/cache` 等）は
/// 数段で、余裕を見て 32 とする。
pub const TMPFS_MAX_DESTINATION_DEPTH: usize = 32;

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
    ///
    /// `destination` は外部入力として扱い、正規化の確保より前に長さ（[`CONFIG_MAX_PATH_BYTES`]）と
    /// 要素数（[`TMPFS_MAX_DESTINATION_DEPTH`]）を検証する。
    pub fn new(destination: &str, size: Option<TmpfsSize>) -> Result<Self, TraitError> {
        if destination.len() > CONFIG_MAX_PATH_BYTES {
            return Err(invalid("tmpfs mount destination is too long"));
        }
        // 確保せずに数える（空要素と `.` は正規化で消えるため数えない）。
        let depth = destination
            .split('/')
            .filter(|e| !e.is_empty() && *e != ".")
            .count();
        if depth > TMPFS_MAX_DESTINATION_DEPTH {
            return Err(invalid("tmpfs mount destination is too deep"));
        }
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

    /// 表示・照合用の表現（`mode=1777,size=67108864`）。型付きフィールドからのみ組み立てる。カーネルへは
    /// 渡さない（`crate::exec::mount_tmpfs` は新マウント API へ `mode`・`size` を型付きで渡す。SUP-12・TASK-169 追補・#1472）。
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

    /// マウントを追加する。予約先・重複・子より後の親指定・件数上限超過は拒否する。
    pub fn push(&mut self, spec: TmpfsMountSpec) -> Result<(), TraitError> {
        // 件数は他の検証（走査）より先に確かめる。
        if self.mounts.len() >= TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs mounts"));
        }
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
        // 子が親より先に指定されると、後から重なる親の tmpfs が子を覆い隠して黙って無効になる。
        if self.mounts.iter().any(|m| {
            m.destination
                .as_str()
                .strip_prefix(dest)
                .is_some_and(|rest| rest.starts_with('/'))
        }) {
            return Err(invalid(
                "tmpfs parent mount must be specified before its child",
            ));
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

    /// 失敗の `(code, message)`。
    fn err_of<T: std::fmt::Debug>(r: Result<T, TraitError>) -> (ErrorCode, String) {
        let e = r.expect_err("must be rejected");
        (e.code(), e.message().to_owned())
    }

    /// SUP-12・TASK-169.2: マウント先の深さは 32 要素まで（空要素と `.` は数えない）。
    #[test]
    fn sup12_task169_2_destination_depth_is_capped() {
        assert_eq!(TMPFS_MAX_DESTINATION_DEPTH, 32);
        let at_limit = "/d".repeat(32);
        assert_eq!(
            TmpfsMountSpec::new(&at_limit, None)
                .expect("32 components")
                .destination
                .as_str(),
            at_limit
        );
        let padded = format!("//./{}/./", "d/".repeat(32));
        assert_eq!(
            TmpfsMountSpec::new(&padded, None)
                .expect("empty and dot components are not counted")
                .destination
                .as_str(),
            at_limit
        );
        assert_eq!(
            err_of(TmpfsMountSpec::new(&"/d".repeat(33), None)),
            (
                ErrorCode::InvalidArgument,
                "tmpfs mount destination is too deep".to_owned()
            )
        );
    }

    fn size(b: u64) -> TmpfsSize {
        TmpfsSize::from_bytes(b).expect("size")
    }

    #[test]
    fn sup12_task169_2_size_bounds() {
        assert_eq!(
            err_of(TmpfsSize::from_bytes(0)),
            (
                ErrorCode::InvalidArgument,
                "tmpfs size must be greater than zero".to_owned()
            )
        );
        assert_eq!(
            err_of(TmpfsSize::from_bytes(i64::MAX as u64 + 1)),
            (
                ErrorCode::InvalidArgument,
                "tmpfs size is too large".to_owned()
            )
        );
        assert_eq!(TmpfsSize::from_bytes(1).expect("one").bytes(), 1);
        assert_eq!(
            TmpfsSize::from_bytes(i64::MAX as u64).expect("max").bytes(),
            i64::MAX as u64
        );
    }

    #[test]
    fn sup12_task169_2_mode_bounds() {
        assert_eq!(TmpfsMode::new(0o7777).expect("max").bits(), 0o7777);
        assert_eq!(
            err_of(TmpfsMode::new(0o10000)),
            (
                ErrorCode::InvalidArgument,
                "tmpfs mode must not exceed 07777".to_owned()
            )
        );
        assert_eq!(TmpfsMode::DEFAULT.bits(), 0o1777);
    }

    #[test]
    fn sup12_task169_2_data_string_exact() {
        let shm = TmpfsMountSpec::dev_shm(size(64 * 1024 * 1024)).expect("shm");
        assert_eq!(shm.destination.as_str(), "/dev/shm");
        assert_eq!(shm.data_string(), "mode=1777,size=67108864");
        assert_eq!((shm.exec, shm.read_only), (false, false));
        let none = TmpfsMountSpec::new("/run", None).expect("run");
        assert_eq!(none.data_string(), "mode=1777");
    }

    #[test]
    fn sup12_task169_2_destination_is_normalized_and_validated() {
        let s = TmpfsMountSpec::new("scratch//a/./b/", None).expect("normalized");
        assert_eq!(s.destination.as_str(), "/scratch/a/b");
        for bad in ["/a/../b", "/", "", "/a\\b", "/a\0b"] {
            assert_eq!(
                err_of(TmpfsMountSpec::new(bad, None)),
                (
                    ErrorCode::InvalidArgument,
                    "invalid tmpfs mount destination".to_owned()
                ),
                "{bad:?}"
            );
        }
        // 過長な入力は正規化（分割・連結の確保）より前に拒否する。
        let long = "/".repeat(CONFIG_MAX_PATH_BYTES) + "a";
        let e = TmpfsMountSpec::new(&long, None).expect_err("too long");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "tmpfs mount destination is too long");
        let fits = format!("{}a", "/".repeat(CONFIG_MAX_PATH_BYTES - 1));
        assert_eq!(
            TmpfsMountSpec::new(&fits, None)
                .expect("fits")
                .destination
                .as_str(),
            "/a"
        );
    }

    #[test]
    fn sup12_task169_2_set_rejects_reserved_duplicate_and_overflow() {
        let spec = |d: &str| TmpfsMountSpec::new(d, None).expect("spec");
        let rejected = |set: &mut TmpfsMountSet, d: &str| err_of(set.push(spec(d)));
        let invalid = |m: &str| (ErrorCode::InvalidArgument, m.to_owned());

        let mut set = TmpfsMountSet::new();
        let below_proc = "tmpfs must not be mounted on /proc or below";
        assert_eq!(rejected(&mut set, "/proc"), invalid(below_proc));
        assert_eq!(rejected(&mut set, "/proc/sys"), invalid(below_proc));
        assert_eq!(
            rejected(&mut set, "/dev"),
            invalid("tmpfs must not be mounted on /dev itself")
        );
        set.push(TmpfsMountSpec::dev_shm(size(65536)).expect("shm"))
            .expect("first");
        assert_eq!(
            rejected(&mut set, "/dev/shm/"),
            invalid("duplicate tmpfs mount destination")
        );
        assert_eq!(set.mounts().len(), 1);

        let mut order = TmpfsMountSet::new();
        order.push(spec("/a/b")).expect("child first");
        assert_eq!(
            rejected(&mut order, "/a"),
            invalid("tmpfs parent mount must be specified before its child")
        );
        // 名前が前方一致するだけの兄弟（`/a` と `/a/b` の関係ではない）は親子として扱わない。
        order.push(spec("/a/bc")).expect("sibling");
        order.push(spec("/ab")).expect("prefix-like sibling");
        assert_eq!(order.mounts().len(), 3);

        let mut ok = TmpfsMountSet::new();
        ok.push(spec("/a")).expect("parent first");
        ok.push(spec("/a/b")).expect("child after parent");
        assert_eq!(ok.mounts().len(), 2);

        let mut full = TmpfsMountSet::new();
        for i in 0..TMPFS_MAX_MOUNTS {
            full.push(spec(&format!("/m{i}"))).expect("within limit");
        }
        assert_eq!(full.mounts().len(), 64);
        // 件数超過は他の検証（予約先）より先に報告する。
        assert_eq!(
            rejected(&mut full, "/extra"),
            invalid("too many tmpfs mounts")
        );
        assert_eq!(
            rejected(&mut full, "/proc"),
            invalid("too many tmpfs mounts")
        );
        assert_eq!(full.mounts().len(), 64);
    }
}
