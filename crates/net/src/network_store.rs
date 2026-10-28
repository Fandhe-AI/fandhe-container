//! ネットワーク定義の状態ストア（`@networks`・FCNET1・ロック・権限・上限。NET-6・CORE-1・REPAIR-2・REPAIR-5・SEC-1・#3059）。
//!
//! 役割: ユーザー定義ネットワークの定義を、常駐デーモンなしでファイルとロックだけで持つ（CORE-1・D-19）。
//! CLI の `network create/rm/ls`（#3066）、supervisor、`NetworkPlugin` の実装のどれからも使う共有の土台で、
//! 定義の符号化（FCNET1）は [`definition`]、置き場の検査・排他・上限は本モジュールが担う。
//! 設計の正は `docs/design/network-wiring.md` の D10（ストア）と D15（期限）。
//!
//! # ディスク上の配置
//! ```text
//! <state_root>/@networks/        0700・所有者は実効 uid
//! ├── @lock                      0600。全体のロック（通常ファイル）
//! ├── @staging-<一意値>/          作成途中（クラッシュの残骸。全体の排他ロックの下でだけ掃除する）
//! ├── @removing-<一意値>/         削除途中（同上）
//! └── <name>/                    0700
//!     ├── definition             0600。FCNET1
//!     ├── dns-helper             0600。起動済み DNS ヘルパーの記録 FCDNSH1（pid・開始時刻・boot id。#3070）
//!     ├── dns-helper.intent      0600。起動窓の意図記録 FCDNSI1（起動の前に書き、記録の確定後に消す。#3070）
//!     └── @lock                  0600。ネットワークのロック
//! ```
//! `NetworkName` は先頭が `[a-z0-9]` のため、`@lock`・`@staging-*`・`@removing-*` はネットワーク名と衝突しない。
//! ディレクトリには flock を掛けず、ロックは通常ファイルの `@lock` だけに掛ける（systemd-tmpfiles の
//! aging が掛ける flock と競合した前例の回避。`docs/design/measurements/production-launcher-tmpfiles-flock.md`）。
//!
//! # 検査（fail-closed）
//! 権限ビットの完全一致（ディレクトリ 0700・ファイル 0600）、所有者（実効 uid）、symlink の拒否（`O_NOFOLLOW`）、
//! nlink = 1、通常ファイルであることを、開いた fd の fstat で検査する。既存の違反は自動修復せず
//! `PermissionDenied` / `FailedPrecondition` にする。子要素は検査済みの親 fd 起点（`/proc/self/fd/<fd>/<名前>`）
//! で開く。定義 1 件は [`DEFINITION_MAX_BYTES`]（4 KiB）以下で、サイズを検証してから確保する。
//!
//! # ロックの順序と期限（REPAIR-5）
//! 順序は「全体 → ネットワーク」に固定し、型で強制する（[`NetworkLockGuard`] は [`GlobalLockGuard`] を借用してしか作れない）。
//! 待ちは既定 [`DEFAULT_LOCK_TIMEOUT`]（5 秒）で `Timeout` になる。解放直後の再取得による飢えを避けるため、
//! 解放から [`LOCK_HANDOFF_GAP`] 経つまで次の取得を待つ（`docs/design/measurements/state-lock-contention.md`）。
//!
//! # 未実装（REPAIR-3）
//! メンバー記録・`realized`・IPAM は #3067、subnet の pool 予約は D13（#3057）。
//! `remove` は `definition` と `@lock` 以外の項目があれば拒否するため、それらが増えても誤って消さない。
//! Linux 以外ではストアの全操作が `Unimplemented`（FCNET1 コーデックは 3 OS で動く）。

pub mod definition;

use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
pub use definition::{
    DEFINITION_MAX_BYTES, InstallMode, MAX_NETWORKS, NetworkDefinition, RESERVED_NETWORK_NAMES,
    is_reserved_network_name,
};

/// ロック待ちの既定の期限（D15・REPAIR-5）。
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// `try_lock` の再試行間隔。
pub const LOCK_RETRY: Duration = Duration::from_millis(1);
/// ロック解放から次の取得を始めるまでの最小の間隔（手渡し）。
pub const LOCK_HANDOFF_GAP: Duration = Duration::from_millis(2);

/// ディレクトリの期待する権限ビット。
pub const DIR_MODE: u32 = 0o700;
/// ファイルの期待する権限ビット。
pub const FILE_MODE: u32 = 0o600;

/// 一覧の結果。1 件の破損で他を隠さない。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkListing {
    /// 読めた定義（名前順）。
    pub definitions: Vec<NetworkDefinition>,
    /// 妥当な名前だが検査か復号に失敗した項目（名前順）と、その分類。
    pub broken: Vec<(String, NetErrorCode)>,
    /// 名前として不正（予約名を含む）な項目の数。
    pub unrecognized: usize,
}

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

/// ディレクトリの fstat 結果を検査する（純関数。値を注入して試験できる）。
pub fn check_dir_meta(
    is_dir: bool,
    uid: u32,
    mode: u32,
    expected_uid: u32,
) -> Result<(), NetError> {
    if !is_dir {
        return Err(err(
            NetErrorCode::FailedPrecondition,
            "network store path is not a directory",
        ));
    }
    if uid != expected_uid {
        return Err(err(
            NetErrorCode::PermissionDenied,
            "network store directory owner mismatch",
        ));
    }
    if mode & 0o7777 != DIR_MODE {
        return Err(err(
            NetErrorCode::PermissionDenied,
            "network store directory mode must be 0700",
        ));
    }
    Ok(())
}

/// ファイルの fstat 結果を検査する（純関数）。
pub fn check_file_meta(
    is_file: bool,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    expected_uid: u32,
    max_len: u64,
) -> Result<(), NetError> {
    if !is_file {
        return Err(err(
            NetErrorCode::FailedPrecondition,
            "network store entry is not a regular file",
        ));
    }
    if nlink != 1 {
        return Err(err(
            NetErrorCode::FailedPrecondition,
            "network store file has extra hard links",
        ));
    }
    if uid != expected_uid {
        return Err(err(
            NetErrorCode::PermissionDenied,
            "network store file owner mismatch",
        ));
    }
    if mode & 0o7777 != FILE_MODE {
        return Err(err(
            NetErrorCode::PermissionDenied,
            "network store file mode must be 0600",
        ));
    }
    if len > max_len {
        return Err(err(
            NetErrorCode::DataLoss,
            "network store file exceeds the size limit",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod imp;
#[cfg(target_os = "linux")]
pub use imp::{GlobalLockGuard, NetworkLockGuard, NetworkStore};

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::{GlobalLockGuard, NetworkLockGuard, NetworkStore};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net6_3059_lock_constants() {
        assert_eq!(DEFAULT_LOCK_TIMEOUT, Duration::from_secs(5));
        assert_eq!(LOCK_RETRY, Duration::from_millis(1));
        assert_eq!(LOCK_HANDOFF_GAP, Duration::from_millis(2));
    }

    #[test]
    fn net6_3059_check_dir_meta() {
        assert!(check_dir_meta(true, 1000, 0o40700, 1000).is_ok());
        for mode in [0o755, 0o750, 0o701, 0o1700] {
            assert_eq!(
                check_dir_meta(true, 1000, mode, 1000).unwrap_err().code(),
                NetErrorCode::PermissionDenied,
                "{mode:o}"
            );
        }
        assert_eq!(
            check_dir_meta(true, 1234, 0o700, 1000).unwrap_err().code(),
            NetErrorCode::PermissionDenied
        );
        assert_eq!(
            check_dir_meta(false, 1000, 0o700, 1000).unwrap_err().code(),
            NetErrorCode::FailedPrecondition
        );
    }

    #[test]
    fn net6_3059_check_file_meta() {
        assert!(check_file_meta(true, 1000, 0o100600, 1, 10, 1000, 4096).is_ok());
        for mode in [0o644, 0o640, 0o400] {
            assert_eq!(
                check_file_meta(true, 1000, mode, 1, 10, 1000, 4096)
                    .unwrap_err()
                    .code(),
                NetErrorCode::PermissionDenied,
                "{mode:o}"
            );
        }
        assert_eq!(
            check_file_meta(true, 1000, 0o600, 2, 10, 1000, 4096)
                .unwrap_err()
                .code(),
            NetErrorCode::FailedPrecondition
        );
        assert_eq!(
            check_file_meta(true, 1000, 0o600, 1, 4097, 1000, 4096)
                .unwrap_err()
                .code(),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            check_file_meta(true, 1234, 0o600, 1, 10, 1000, 4096)
                .unwrap_err()
                .code(),
            NetErrorCode::PermissionDenied
        );
        assert_eq!(
            check_file_meta(false, 1000, 0o600, 1, 10, 1000, 4096)
                .unwrap_err()
                .code(),
            NetErrorCode::FailedPrecondition
        );
    }
}
