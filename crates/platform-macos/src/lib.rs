//! fandhe-container-platform-macos: macOS Virtualization.framework 経由の VM 起動・VirtioFS（MAC-1）。
//!
//! 現状は VM 設定・最小デバイス構成（`config`。TASK-64.2・64.3）とライフサイクル（`vm`。TASK-64.4）まで実装済みで、
//! タイムアウト既定値・クリーンアップ・エラー型統合は TASK-64.5 で実装する（REPAIR-3: 実装済みを装わない）。
//!
//! - プラットフォーム対応: OS 非依存の検証ロジックは全 OS でビルドし 3 OS CI でテストする。
//!   Virtualization.framework 呼び出し（`sys`・構築関数）のみ `cfg(target_os = "macos")` で局所化する（CLI-1）。
//! - 実行前提: `com.apple.security.virtualization` entitlement とコード署名（ad-hoc 可）、最低 macOS 13。
//! - 呼び出し文脈: 実行時は `fandhe-container-plugin-macos`（TASK-115）が本 crate を別プロセスとして動かす。
//!   PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。

pub mod config;
pub mod vm;

#[cfg(target_os = "macos")]
mod sys;

/// macOS 以外の unix 向けの `sys`: unix 共通の POSIX ラッパー（`src/sys/posix.rs`）だけを持つ。
///
/// コンソールログの所有者検査（MAC-1・TASK-64.3）を 3 OS CI の Linux でも実行するため、macOS の `sys` と
/// 同じパス（`crate::sys::effective_uid`）で呼べるようにする。Virtualization.framework 層は含まない。
#[cfg(all(unix, not(target_os = "macos")))]
mod sys {
    mod posix;
    pub(crate) use posix::effective_uid;
}

/// 本バックエンドの利用可否と前提 macOS 版数（拡張可能なように構造体で返す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformSupport {
    /// ビルド対象 OS で本バックエンドが利用可能か（macOS のみ true）。
    pub supported: bool,
    /// 前提とする macOS のメジャー版数（vsock 11・virtio-fs 12・virtio-graphics 13 の最大）。
    pub min_macos_major: u32,
}

/// ビルド対象 OS での利用可否と前提版数を返す。実機の OS 版数判定はしない（MAC-1・TASK-64.1）。
pub const fn platform_support() -> PlatformSupport {
    PlatformSupport {
        supported: cfg!(target_os = "macos"),
        min_macos_major: 13,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC-1・TASK-64.1: 利用可否はビルド対象 OS に一致し、前提版数は 13 である。
    #[test]
    fn platform_support_matches_target_os() {
        #[cfg(target_os = "macos")]
        let expected = PlatformSupport {
            supported: true,
            min_macos_major: 13,
        };
        #[cfg(not(target_os = "macos"))]
        let expected = PlatformSupport {
            supported: false,
            min_macos_major: 13,
        };
        assert_eq!(platform_support(), expected);
    }
}
