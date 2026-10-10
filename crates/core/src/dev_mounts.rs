//! 暗黙の固定集合（`/dev`・`/dev/pts`・`/dev/shm`）の唯一の定義（CORE-1・CORE-5・SEC-1・TASK-29 追補・#1657）。
//!
//! # 役割
//!
//! オーナー判断（2026-10-10・#1609）で、これら 3 つは `config.json` の `mounts[]` に関係なく
//! ランタイムが常に載せるマウントになった。マウント先・fs 種別・属性（`nosuid` / `nodev` / `noexec` /
//! 読み取り専用）をここに 1 か所で持ち、実マウント側と Landlock 側が同じ定義を参照して食い違わないようにする。
//! OS に依存しない純粋な型だけを置く（`landlock`・`exec`・`sys` は Linux 限定のため、そちらへ置くと
//! `tmpfs` が参照できず 3 OS のビルドが壊れる）。
//!
//! # 参照元
//!
//! - `crate::tmpfs`: `/dev/shm` の既定の仕様（`read_only`・`exec`）を [`ImplicitDevMount::attrs`] から設定する
//! - `crate::exec`（`devices`）: `/dev`・`/dev/pts` の事後検証で [`ImplicitDevMount::destination`] を使う。
//!   fsmount の属性ビットは `sys` が固定で持ち、`sys` の単体テストが本定義との一致を照合する
//! - `crate::landlock`: [`ImplicitDevMounts`] に従い、実マウントの属性から導いた最小の権利でルールを足す
//!
//! # 未実装範囲（REPAIR-3）
//!
//! `--ipc=host` 等で `/dev/shm` を載せない構成の細かい選択肢は無い。呼び出し側（supervisor）の判断が決まった後に
//! [`ImplicitDevMounts`] へ足す（TASK-29 系）。

/// 暗黙に載るマウント 1 件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImplicitDevMount {
    /// `/dev`（専用の tmpfs。#1652・#1653）。
    Dev,
    /// `/dev/pts`（独立した devpts。#1656）。
    DevPts,
    /// `/dev/shm`（tmpfs。#1654）。
    DevShm,
}

/// 暗黙マウントの属性。実マウントのフラグと 1 対 1 に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImplicitMountAttrs {
    /// 読み取り専用か。
    pub read_only: bool,
    /// `nosuid` か。
    pub nosuid: bool,
    /// `nodev` か。
    pub nodev: bool,
    /// `noexec` か。
    pub noexec: bool,
}

/// 暗黙マウントの件数（Landlock のルール本数の上限計算に使う）。
pub const IMPLICIT_DEV_MOUNT_COUNT: usize = ImplicitDevMount::ALL.len();

impl ImplicitDevMount {
    /// 全件（マウント順: `/dev` → `/dev/pts` → `/dev/shm`）。
    pub const ALL: [ImplicitDevMount; 3] = [Self::Dev, Self::DevPts, Self::DevShm];

    /// コンテナ内のマウント先。
    pub const fn destination(self) -> &'static str {
        match self {
            Self::Dev => "/dev",
            Self::DevPts => "/dev/pts",
            Self::DevShm => crate::tmpfs::DEV_SHM_PATH,
        }
    }

    /// fs 種別。
    pub const fn fs_type(self) -> &'static str {
        match self {
            Self::Dev | Self::DevShm => "tmpfs",
            Self::DevPts => "devpts",
        }
    }

    /// 実マウントの属性。
    ///
    /// `/dev` は runc 方式（`nosuid` + `strictatime`）で `nodev`・`noexec` を付けない（#1652・#1653）。
    /// `/dev/pts` は pty のスレーブを開くため `nodev` を付けない（#1656）。
    pub const fn attrs(self) -> ImplicitMountAttrs {
        match self {
            Self::Dev => ImplicitMountAttrs {
                read_only: false,
                nosuid: true,
                nodev: false,
                noexec: false,
            },
            Self::DevPts => ImplicitMountAttrs {
                read_only: false,
                nosuid: true,
                nodev: false,
                noexec: true,
            },
            Self::DevShm => ImplicitMountAttrs {
                read_only: false,
                nosuid: true,
                nodev: true,
                noexec: true,
            },
        }
    }
}

/// 暗黙マウントを Landlock のルールに含めるか。
///
/// `None` は rootfs にこれらのマウントが無い経路（`spawn_container` の最小フロー。#1314 未配線）向けで、
/// ルールが減るだけで権利は広がらない（緩む方向には働かない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImplicitDevMounts {
    /// 3 件すべて。
    All,
    /// 含めない。
    None,
}

impl ImplicitDevMounts {
    /// 対象のマウント。
    pub fn entries(self) -> &'static [ImplicitDevMount] {
        match self {
            Self::All => &ImplicitDevMount::ALL,
            Self::None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORE-5: マウント先・fs 種別・属性の具体値。
    #[test]
    fn core5_implicit_dev_mount_table() {
        let t = [
            (
                ImplicitDevMount::Dev,
                "/dev",
                "tmpfs",
                (false, true, false, false),
            ),
            (
                ImplicitDevMount::DevPts,
                "/dev/pts",
                "devpts",
                (false, true, false, true),
            ),
            (
                ImplicitDevMount::DevShm,
                "/dev/shm",
                "tmpfs",
                (false, true, true, true),
            ),
        ];
        for (m, dest, fs, (ro, nosuid, nodev, noexec)) in t {
            assert_eq!(m.destination(), dest);
            assert_eq!(m.fs_type(), fs);
            let a = m.attrs();
            assert_eq!(
                (a.read_only, a.nosuid, a.nodev, a.noexec),
                (ro, nosuid, nodev, noexec),
                "{dest}"
            );
        }
        assert_eq!(ImplicitDevMount::ALL.len(), 3);
        assert_eq!(IMPLICIT_DEV_MOUNT_COUNT, 3);
        assert_eq!(ImplicitDevMounts::All.entries(), &ImplicitDevMount::ALL);
        assert!(ImplicitDevMounts::None.entries().is_empty());
    }
}
