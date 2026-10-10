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
//! - `/dev/shm` は暗黙の固定集合として常に載せる（オーナー判断 2・`docs/design/dev-default-mounts.md` 3.4・
//!   TASK-29 追補・#1654）。[`TmpfsMountSet::ensure_default_dev_shm`] が、集合に `/dev/shm` が無いときだけ
//!   既定（[`DEFAULT_DEV_SHM_SIZE_BYTES`]）の件を足す。`--shm-size` も `--tmpfs /dev/shm` も利用者の指定として
//!   優先し、既定は足さない（同じマウント先に 2 枚重ねない）。`--tmpfs /dev/shm` でサイズを省くとカーネル既定になる。
//!   既定の件も [`TMPFS_MAX_MOUNTS`] に数える。`--ipc=host` で足すかどうかは呼び出し側（supervisor）が決める
//! - サイズ未指定（`None`）はカーネル既定（物理メモリの 50%）で、Docker と同じ挙動。tmpfs のページは
//!   コンテナの memory cgroup に課金されるため `memory.max`（CORE-3）で抑えられる
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! `uid=`・`gid=`・`%` 指定・`suid` / `dev` の許可・OCI `mounts[]` からの変換（TASK-127・TASK-29 系）。

use crate::dev_mounts::ImplicitDevMount;
use crate::oci_runtime::{CONFIG_MAX_PATH_BYTES, MountDestination};

// `TmpfsMountFlags` は `nosuid`・`nodev` を常に付ける。暗黙の固定集合の定義が食い違ったらビルドを止める（#1657）。
const _: () =
    assert!(ImplicitDevMount::DevShm.attrs().nosuid && ImplicitDevMount::DevShm.attrs().nodev);
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

/// `--shm-size` 未指定時の `/dev/shm` の既定サイズ（64 MiB）。既定値の唯一の定義。
///
/// Docker の既定 64 MiB と runc v1.5.2 の `size=65536k` に揃える（SUP-12・TASK-29 追補・#1654）。
pub const DEFAULT_DEV_SHM_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// [`TmpfsMountSet::ensure_default_dev_shm`] の結果（既定を足したかを呼び出し側のログ・報告へ渡す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevShmOrigin {
    /// 利用者の指定が既にあり、既定は足していない。
    Specified,
    /// 既定の `/dev/shm`（64 MiB）を足した。
    Default,
}

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

    /// `--shm-size` 未指定時の既定の `/dev/shm`（[`DEFAULT_DEV_SHM_SIZE_BYTES`]・`noexec`・mode 1777）。
    pub fn default_dev_shm() -> Result<Self, TraitError> {
        let mut spec = Self::dev_shm(TmpfsSize::from_bytes(DEFAULT_DEV_SHM_SIZE_BYTES)?)?;
        // 暗黙の固定集合の定義（Landlock 側のルールと共有。#1657）から属性を設定する。
        let attrs = ImplicitDevMount::DevShm.attrs();
        spec.read_only = attrs.read_only;
        spec.exec = !attrs.noexec;
        Ok(spec)
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

    /// `/dev/shm` が無ければ既定の件（64 MiB）を足す。何度呼んでも同じ結果になる（冪等）。
    ///
    /// 利用者の指定（`--shm-size`・`--tmpfs /dev/shm`）が既にあれば何もしない。supervisor の
    /// `to_tmpfs_set` が `--ipc=host` 以外のときに呼ぶ（SUP-12・#1654）。件数上限は挿入の前に確かめる。
    /// 既定の件は先頭へ挿入する。末尾へ足すと、先にある `/dev/shm/sub` を親が後から覆い隠すか
    /// 「親を子より後に指定」の不変条件に反するため。`/dev/shm` の親になりうる `/dev`・`/` は
    /// `push` と `MountDestination` で拒否済みなので、先頭挿入で親子順序は崩れない。
    pub fn ensure_default_dev_shm(&mut self) -> Result<DevShmOrigin, TraitError> {
        if self
            .mounts
            .iter()
            .any(|m| m.destination.as_str() == DEV_SHM_PATH)
        {
            return Ok(DevShmOrigin::Specified);
        }
        if self.mounts.len() >= TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs mounts"));
        }
        self.mounts.insert(0, TmpfsMountSpec::default_dev_shm()?);
        Ok(DevShmOrigin::Default)
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

    /// SUP-12・TASK-29 追補（#1654）: 空の集合へ既定の `/dev/shm`（64 MiB）を足す。
    #[test]
    fn sup12_task29_default_dev_shm_added_when_unspecified() {
        assert_eq!(DEFAULT_DEV_SHM_SIZE_BYTES, 67_108_864);
        let mut set = TmpfsMountSet::new();
        assert_eq!(set.ensure_default_dev_shm(), Ok(DevShmOrigin::Default));
        assert_eq!(set.mounts().len(), 1);
        let m = &set.mounts()[0];
        assert_eq!(m.destination.as_str(), "/dev/shm");
        assert_eq!(m.data_string(), "mode=1777,size=67108864");
        assert!(!m.exec);
        assert!(!m.read_only);
        // 冪等: 2 回目は既存扱いで件数は 1 のまま。
        assert_eq!(set.ensure_default_dev_shm(), Ok(DevShmOrigin::Specified));
        assert_eq!(set.mounts().len(), 1);
    }

    /// SUP-12・TASK-29 追補（#1654）: 利用者の `--shm-size` が既定より優先される。
    #[test]
    fn sup12_task29_default_dev_shm_yields_to_shm_size() {
        let mut set = TmpfsMountSet::new();
        let size = TmpfsSize::from_bytes(131_072).expect("size");
        set.push(TmpfsMountSpec::dev_shm(size).expect("spec"))
            .expect("push");
        assert_eq!(set.ensure_default_dev_shm(), Ok(DevShmOrigin::Specified));
        let shm: Vec<_> = set
            .mounts()
            .iter()
            .filter(|m| m.destination.as_str() == "/dev/shm")
            .collect();
        assert_eq!(shm.len(), 1);
        assert_eq!(shm[0].data_string(), "mode=1777,size=131072");
    }

    /// SUP-12・TASK-29 追補（#1654）: `--tmpfs /dev/shm`（サイズ省略）も利用者の指定として扱う。
    #[test]
    fn sup12_task29_default_dev_shm_yields_to_tmpfs_flag() {
        let mut set = TmpfsMountSet::new();
        set.push(TmpfsMountSpec::new("/dev/shm", None).expect("spec"))
            .expect("push");
        assert_eq!(set.ensure_default_dev_shm(), Ok(DevShmOrigin::Specified));
        assert_eq!(set.mounts().len(), 1);
        assert_eq!(set.mounts()[0].data_string(), "mode=1777");
    }

    /// SUP-12・TASK-29 追補（#1654）: 既定は先頭へ入り、子 `/dev/shm/sub` との親子順序を保つ。
    #[test]
    fn sup12_task29_default_dev_shm_inserted_before_child() {
        let mut set = TmpfsMountSet::new();
        set.push(TmpfsMountSpec::new("/dev/shm/sub", None).expect("spec"))
            .expect("push");
        assert_eq!(set.ensure_default_dev_shm(), Ok(DevShmOrigin::Default));
        let dests: Vec<_> = set
            .mounts()
            .iter()
            .map(|m| m.destination.as_str().to_owned())
            .collect();
        assert_eq!(dests, ["/dev/shm", "/dev/shm/sub"]);
    }

    /// SUP-12・TASK-29 追補（#1654）: 既定の件も上限 64 に数える。
    #[test]
    fn sup12_task29_default_dev_shm_counts_toward_limit() {
        let mk = |n: usize| {
            let mut set = TmpfsMountSet::new();
            for i in 0..n {
                set.push(TmpfsMountSpec::new(&format!("/m{i}"), None).expect("spec"))
                    .expect("push");
            }
            set
        };
        let mut full = mk(TMPFS_MAX_MOUNTS);
        assert_eq!(
            full.ensure_default_dev_shm().expect_err("limit").message(),
            "too many tmpfs mounts"
        );
        assert_eq!(full.mounts().len(), 64);
        let mut almost = mk(TMPFS_MAX_MOUNTS - 1);
        assert_eq!(almost.ensure_default_dev_shm(), Ok(DevShmOrigin::Default));
        assert_eq!(almost.mounts().len(), 64);
        assert_eq!(almost.mounts()[0].destination.as_str(), "/dev/shm");
    }
}
