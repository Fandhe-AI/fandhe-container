//! `--image-root` を省いたときの既定の位置の解決（OCI-7・CLI-1・MAC-4・WIN-1・#2384）。
//!
//! # 役割と呼び出し元
//!
//! `image ls` / `image rm` / `image tag` / `image prune` / `system df` が `--image-root` を省いたとき、
//! `image::image_root_for` から [`resolve_default_image_root`] を呼んで root を決める。解決は純関数で、
//! ディレクトリは作らない（存在・symlink・所有者・mode の検査は後段の `ImageStore::open` が行う。#2381・#2547）。
//! 判断の記録は `docs/design/image-root-default.md`。
//!
//! # 規則
//!
//! - Linux（WSL2 ゲスト内を含む）: `<状態ルート>/.cri/images`。状態ルートは `StateRoot::resolve(--root)` の結果。
//!   在庫を埋める経路は plugin-cri の `PullImage` だけで、そのキャッシュは既定の状態ルート直下の `.cri/images` にあるため。
//!   Agent の記録した判断で、オーナー確認待ち。
//! - macOS ホスト: 既定なし（恒久の fail-closed。#2431 案 A・承認済み）。`--root` の有無によらず拒否する。
//! - Windows ホスト: `UNIMPLEMENTED`。core と CLI は WSL2 ゲスト内で動く構成で、ホスト側の `ImageStore::open` は恒久拒否
//!   （WIN-1・#2428）。オーナー確認待ち。

use std::path::PathBuf;

use fandhe_container_core::state_store::StateRoot;
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// plugin-cri の `IMAGES_DIR`（`crates/plugin-cri/src/adapter.rs`）と一致させる契約の定数。
/// cli は plugin-cri に依存しないため二重定義で、値は試験で固定する。
pub(super) const CRI_IMAGE_STORE_SUBDIR: &str = ".cri/images";

/// macOS ホストで既定の image root を拒否するときの固定文言（#2431 案 A・MAC-4）。
pub(super) const MSG_MACOS_NO_DEFAULT: &str = "default image root is not defined on a macOS host by design; pass --image-root or use the Linux guest path";
/// Windows ホストで既定の image root を拒否するときの固定文言（WIN-1）。
pub(super) const MSG_WINDOWS_NO_DEFAULT: &str =
    "default image root is defined only inside a Linux guest";

/// 既定の image root を解決するときのホストの種類（`cfg` の値を引数にして 3 OS で試験できるようにする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ImageRootHost {
    /// Linux（ホストまたは WSL2 ゲスト内）。
    Linux,
    /// macOS ホスト。既定なし。
    MacosHost,
    /// その他（Windows ホスト）。
    OtherHost,
}

impl ImageRootHost {
    /// ビルド対象の値。`cfg(target_os)` の分岐はここに局所化する（CLI-1）。
    pub(super) const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacosHost
        } else {
            Self::OtherHost
        }
    }
}

/// 既定の image root を決める。`state_root` は Linux のときだけ呼ぶ（他では環境を読まない）。
pub(super) fn resolve_default_image_root(
    host: ImageRootHost,
    state_root: impl FnOnce() -> Result<StateRoot, TraitError>,
) -> Result<PathBuf, TraitError> {
    match host {
        ImageRootHost::Linux => Ok(state_root()?.path().join(CRI_IMAGE_STORE_SUBDIR)),
        ImageRootHost::MacosHost => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_MACOS_NO_DEFAULT,
        )),
        ImageRootHost::OtherHost => Err(TraitError::new(
            ErrorCode::Unimplemented,
            MSG_WINDOWS_NO_DEFAULT,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn root(p: &str) -> Result<StateRoot, TraitError> {
        StateRoot::from_override(PathBuf::from(p))
    }

    /// OCI-7・CLI-1: Linux は状態ルート直下の `.cri/images`（末尾の区切り文字は正規化される）。
    #[test]
    fn oci7_cli1_default_image_root_linux_is_state_root_cri_images() {
        let got = resolve_default_image_root(ImageRootHost::Linux, || root("/r/")).unwrap();
        assert_eq!(got, PathBuf::from("/r/.cri/images"));
    }

    /// ERR-2: 状態ルートの解決失敗はそのまま返す（`/tmp` へ落とさない）。
    #[test]
    fn oci7_cli1_default_image_root_linux_propagates_state_root_error() {
        let e = resolve_default_image_root(ImageRootHost::Linux, || {
            Err(TraitError::new(ErrorCode::FailedPrecondition, "xdg"))
        })
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "xdg");
    }

    /// MAC-4: macOS ホストは `--root` があっても状態ルートを解決せずに拒否する。
    #[test]
    fn mac4_default_image_root_refused_on_macos_host() {
        let called = Cell::new(false);
        let e = resolve_default_image_root(ImageRootHost::MacosHost, || {
            called.set(true);
            root("/r")
        })
        .unwrap_err();
        assert!(!called.get());
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_MACOS_NO_DEFAULT);
    }

    /// WIN-1: Windows ホストは `UNIMPLEMENTED`。
    #[test]
    fn win1_default_image_root_unimplemented_on_windows_host() {
        let e = resolve_default_image_root(ImageRootHost::OtherHost, || root("/r")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.message(), MSG_WINDOWS_NO_DEFAULT);
    }

    /// OCI-7: plugin-cri の `IMAGES_DIR` と一致させる契約の値を固定する。
    #[test]
    fn oci7_cri_image_store_subdir_matches_plugin_cri() {
        assert_eq!(CRI_IMAGE_STORE_SUBDIR, ".cri/images");
    }
}
