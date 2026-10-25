//! pivot 前段が載せたマウントの識別子の記録と、Landlock の適用時の照合入力（#2071・CORE-5・SEC-1・SEC-4）。
//!
//! # 役割
//!
//! Landlock のルールのパスは、適用の段（pivot 後・exec 前）でコンテナの `/` から辿って開く。ruleset は fork 前に
//! 親が `config.json` から作るため、辿り着いた先が pivot 前段で実際に載せたマウントのルートかどうかは、記録が
//! 無ければ確かめられない。本モジュールは、pivot 前段（`exec/process.rs` の `RealPrePivotOps`）が各段の成功直後に
//! 残すマウントの識別子（[`MountIdentity`]）の集合 [`MountedTargets`] と、`apply` が照合の有無を選ぶ
//! [`MountCheck`] を定義する。
//!
//! # 呼び出し文脈・契約
//!
//! - 記録: `RealPrePivotOps` が `create_default_devices`・`mount_tmpfs`・`inject_files`・`mount_binds` の成功直後に
//!   [`MountedTargets::push`] する。段の順に並ぶ（同じキーが複数あれば後勝ち。後から載せたものが上になる）
//! - 受け渡し: `run_child_then` が `StagePipeline::with_mounted_targets` で Landlock 段へ渡す（pivot で `mnt_id` と
//!   `(st_dev, st_ino)` は変わらない。`PivotReport.new_root_mnt_id` の pivot 後の再照合が先例）
//! - 照合: `apply` が、ルールの対象として開いた fd（開き直さない）を同じ方法で観測し、記録と 3 つとも一致する
//!   ことを要求する。1 つのマウントの中でディレクトリの inode に対応する dentry は 1 つで、単一ファイルの bind は
//!   マウントのルートしか持たないため、`mnt_id` と `(st_dev, st_ino)` が一致すればその fd はそのマウントのルート。
//!   `mnt_id` はマウントが外れた後に再利用されうるので、`(st_dev, st_ino)` も照合して取り違えを防ぐ
//! - 記録が引けない・観測できない・値が違うときはどれも `landlock_restrict_self` の前に拒否する（fail-closed）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - exec の再適用（SUP-6）は launch 時の記録を持たない（`LaunchIsolationRecord` がマウントの識別子を持たず、
//!   マウント ID は restart で変わる）ため [`MountCheck::NotRecorded`] で、従来どおり暗黙のマウントの
//!   fs 種別・独立性の確認だけを行う。永続化と照合は後続作業
//! - 利用者の tmpfs・注入の宛先には今は Landlock のルールが無い。識別子は記録するが、照合の対象は
//!   今あるルール（暗黙の `/dev` 系 3 本と bind）だけ
//! - `STATX_MNT_ID_UNIQUE`（64 ビット・再利用されない ID）による強化は将来仕様

use crate::dev_mounts::ImplicitDevMount;

use super::rules::RuleOrigin;

/// 記録できるマウントの上限（無制限確保を避ける。`/dev` 系 2 ＋ tmpfs ＋ 注入 ＋ bind の各上限に十分な余裕を持つ値）。
pub(crate) const MAX_MOUNTED_TARGETS: usize = 1024;

/// マウントのルートの識別子（`/proc/thread-self/fdinfo/N` の `mnt_id` と、`fstat` の `st_dev`・`st_ino`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MountIdentity {
    /// fd が属するマウントの ID。
    pub(crate) mnt_id: u64,
    /// ルートの `st_dev`。
    pub(crate) dev: u64,
    /// ルートの `st_ino`。
    pub(crate) ino: u64,
}

/// 記録したマウントを載せた段。ルールの由来（[`RuleOrigin`]）から型付きのキーで引くために持つ
/// （パス文字列の正規化の食い違いを避ける）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum MountedBy {
    /// 専用 `/dev` の段（`/dev` の tmpfs と `/dev/pts` の devpts）。
    DefaultDevices(ImplicitDevMount),
    /// tmpfs の段（既定の `/dev/shm` を含む）。
    Tmpfs,
    /// ファイル注入の段（注入ディレクトリの tmpfs）。
    Inject,
    /// bind mount の段。`index` は `mounts[]` 内の位置（`RuleOrigin::Mount` と同じ番号）。
    Bind {
        /// `mounts[]` 内の位置。
        index: usize,
    },
}

/// 記録 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountedTarget {
    /// 載せた段。
    pub(crate) by: MountedBy,
    /// コンテナ内のマウント先（正規化済み）。
    pub(crate) destination: String,
    /// 載せた直後に観測した識別子。
    pub(crate) identity: MountIdentity,
}

/// pivot 前段が載せたマウントの記録（段の順）。既定値は空で、空のまま Mount 由来のルールがあれば照合は拒否する。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MountedTargets(Vec<MountedTarget>);

/// 上限を超えた（記録できない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MountedTargetsFull;

impl MountedTargets {
    /// 空の記録。
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 1 件足す。上限（[`MAX_MOUNTED_TARGETS`]）を超える場合は足さずに `Err`。
    pub(crate) fn push(&mut self, target: MountedTarget) -> Result<(), MountedTargetsFull> {
        if self.0.len() >= MAX_MOUNTED_TARGETS {
            return Err(MountedTargetsFull);
        }
        self.0.push(target);
        Ok(())
    }

    /// 件数。
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// 全件（段の順）。
    #[cfg(test)]
    pub(crate) fn targets(&self) -> &[MountedTarget] {
        &self.0
    }

    /// ルールの由来から、期待する識別子を引く（同じキーが複数あれば後勝ち）。`Root` は対象外で `None`。
    ///
    /// - `Implicit{Dev|DevPts}` は専用 `/dev` の段、`Implicit{DevShm}` は tmpfs の段で宛先が `/dev/shm` の件
    /// - `Mount{index}` は bind の段の同じ `index`
    /// - `UserTmpfs` は tmpfs の段で宛先がルールの宛先（`destination`）と一致する件（SUP-12・#2625）
    pub(crate) fn expected_for(
        &self,
        origin: &RuleOrigin,
        destination: &str,
    ) -> Option<&MountIdentity> {
        let found = self.0.iter().rev().find(|t| match origin {
            RuleOrigin::Implicit {
                mount: ImplicitDevMount::DevShm,
            } => {
                t.by == MountedBy::Tmpfs && t.destination == ImplicitDevMount::DevShm.destination()
            }
            RuleOrigin::Implicit { mount } => t.by == MountedBy::DefaultDevices(*mount),
            RuleOrigin::Mount { index } => t.by == MountedBy::Bind { index: *index },
            RuleOrigin::UserTmpfs => t.by == MountedBy::Tmpfs && t.destination == destination,
            _ => false,
        });
        found.map(|t| &t.identity)
    }
}

/// `apply` が Mount 由来のルールをどう確かめるか。
#[derive(Debug, Clone, Copy)]
pub(crate) enum MountCheck<'a> {
    /// launch 経路。pivot 前段が記録した識別子と照合する。ルールが Mount 由来で記録が引けなければ拒否する。
    Recorded(&'a MountedTargets),
    /// launch 時の記録を照合に使えない経路（exec の再適用と結合試験専用の観測関数）。暗黙のマウントの
    /// fs 種別・独立性の確認は従来どおり行い、識別子の照合はしない（弱めない。REPAIR-3 の例外。launch の入口
    /// 〔`StagePipeline`〕はこの variant を構築しない）。
    NotRecorded,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: MountIdentity = MountIdentity {
        mnt_id: 1,
        dev: 2,
        ino: 3,
    };

    fn target(by: MountedBy, destination: &str, mnt_id: u64) -> MountedTarget {
        MountedTarget {
            by,
            destination: destination.to_string(),
            identity: MountIdentity { mnt_id, ..ID },
        }
    }

    /// CORE-5・#2071: 型付きのキーで引き、同じキーは後勝ち。`/dev/shm` は tmpfs の段の宛先で引く。
    #[test]
    fn core5_2071_mounted_targets_lookup_is_typed_and_last_wins() {
        let mut m = MountedTargets::new();
        for t in [
            target(MountedBy::DefaultDevices(ImplicitDevMount::Dev), "/dev", 10),
            target(
                MountedBy::DefaultDevices(ImplicitDevMount::DevPts),
                "/dev/pts",
                11,
            ),
            target(MountedBy::Tmpfs, "/run", 12),
            target(MountedBy::Tmpfs, "/dev/shm", 13),
            target(MountedBy::Bind { index: 0 }, "/a", 14),
            target(MountedBy::Bind { index: 0 }, "/a", 15),
            target(MountedBy::Bind { index: 1 }, "/b", 16),
        ] {
            m.push(t).expect("capacity");
        }
        let id = |o: RuleOrigin| m.expected_for(&o, "").map(|i| i.mnt_id);
        let tmpfs = |d: &str| m.expected_for(&RuleOrigin::UserTmpfs, d).map(|i| i.mnt_id);
        assert_eq!(
            id(RuleOrigin::Implicit {
                mount: ImplicitDevMount::Dev
            }),
            Some(10)
        );
        assert_eq!(
            id(RuleOrigin::Implicit {
                mount: ImplicitDevMount::DevPts
            }),
            Some(11)
        );
        assert_eq!(
            id(RuleOrigin::Implicit {
                mount: ImplicitDevMount::DevShm
            }),
            Some(13)
        );
        assert_eq!(id(RuleOrigin::Mount { index: 0 }), Some(15));
        assert_eq!(id(RuleOrigin::Mount { index: 1 }), Some(16));
        assert_eq!(id(RuleOrigin::Mount { index: 2 }), None);
        assert_eq!(id(RuleOrigin::Root), None);
        // 利用者 tmpfs は tmpfs の段の同じ宛先で引く(bind の段は拾わない)。
        assert_eq!(tmpfs("/run"), Some(12));
        assert_eq!(tmpfs("/a"), None);
        assert_eq!(m.len(), 7);
        assert_eq!(m.targets().len(), 7);
    }

    /// CORE-5・#2071: 上限を超える件数は記録しない。
    #[test]
    fn core5_2071_mounted_targets_rejects_over_capacity() {
        let mut m = MountedTargets::new();
        for _ in 0..MAX_MOUNTED_TARGETS {
            m.push(target(MountedBy::Inject, "/x", 1))
                .expect("capacity");
        }
        assert_eq!(
            m.push(target(MountedBy::Inject, "/x", 1)),
            Err(MountedTargetsFull)
        );
        assert_eq!(m.len(), MAX_MOUNTED_TARGETS);
    }
}
