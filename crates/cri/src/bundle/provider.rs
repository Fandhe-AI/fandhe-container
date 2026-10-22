//! bundle ディレクトリの作成・`config.json` の書き込み・解放を担う汎用の [`BundleProvider`] 実装
//! （CRI-1・CRI-2・OCI-4・SEC-1。#2395）。
//!
//! `CriRuntimeService` の `CreateContainer`（worker スレッド上）が `prepare` を、Create の巻き戻しと
//! `RemoveContainer` が `release` を呼ぶ。bundle は `<root>/<container_id>/` に作り、`config.json` を書く。
//! `rootfs/` の中身（イメージの展開）は注入された [`RootfsSource`] が用意する。
//!
//! 安全性: `root` は構築時に固定し要求から受けない。コンテナ ID は `ContainerId::new` で検証してから join し、
//! ディレクトリは `create_dir`（末尾の symlink を辿らない・既存は `FAILED_PRECONDITION` で消さない）で作る。
//! 解放は `symlink_metadata` で通常のディレクトリと確認できたものだけを消し、symlink は消さずに拒否する。
//! I/O エラーの OS 文字列やパスはメッセージへ含めない（固定文言のみ）。

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fandhe_container_core::traits::ContainerId;

use super::spec::{ImageDefaults, build_runtime_config, validate_config};
use crate::adapter::{BundleProvider, BundleRequest};
use crate::error::CriError;
use crate::runtime::v1::ImageSpec;

/// `rootfs/` の用意と解放の注入点（本番の実装はイメージ展開。#2433）。
///
/// **未実装（REPAIR-3）**: 本番実装は本 crate に無い（oci のレイヤー展開とイメージ config の読み取りは #2433）。
/// 実装は rootfs の内容と digest を検証する責務を持つ。
pub trait RootfsSource: Send + Sync {
    /// 存在しないパス `rootfs` を作成して `image` の内容で満たし、イメージ config 由来の既定値を返す。
    fn prepare(&self, image: &ImageSpec, rootfs: &Path) -> Result<ImageDefaults, CriError>;

    /// `prepare` で作った rootfs を解放する（不在は `Ok`）。
    fn release(&self, rootfs: &Path) -> Result<(), CriError>;
}

/// `<root>/<container_id>/{config.json,rootfs/}` を作る [`BundleProvider`]。
pub struct SpecBundleProvider {
    root: PathBuf,
    rootfs: Arc<dyn RootfsSource>,
}

impl std::fmt::Debug for SpecBundleProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpecBundleProvider")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl SpecBundleProvider {
    /// bundle の置き場所 `root` を検証して作る。
    ///
    /// `root` は絶対パスで、symlink でない既存のディレクトリであること（unix では group / other に
    /// 書き込み権が無いこと）。反すれば `INVALID_ARGUMENT` / `FAILED_PRECONDITION`。
    pub fn new(root: PathBuf, rootfs: Arc<dyn RootfsSource>) -> Result<Self, CriError> {
        if !root.is_absolute() {
            return Err(CriError::invalid_argument("bundle root must be absolute"));
        }
        let meta = fs::symlink_metadata(&root)
            .map_err(|_| CriError::failed_precondition("bundle root is unavailable"))?;
        if !meta.file_type().is_dir() {
            return Err(CriError::failed_precondition(
                "bundle root must be a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if meta.permissions().mode() & 0o022 != 0 {
                return Err(CriError::failed_precondition(
                    "bundle root must not be writable by group or others",
                ));
            }
        }
        Ok(Self { root, rootfs })
    }

    fn bundle_dir(&self, container_id: &str) -> Result<PathBuf, CriError> {
        let id = ContainerId::new(container_id)
            .map_err(|_| CriError::invalid_argument("container id is invalid"))?;
        Ok(self.root.join(id.as_str()))
    }
}

fn create_private_dir(path: &Path) -> Result<(), CriError> {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CriError::failed_precondition("bundle already exists")
        } else {
            CriError::internal("failed to create bundle directory")
        }
    })
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CriError> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|_| CriError::internal("failed to create config.json"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| CriError::internal("failed to write config.json"))
}

impl BundleProvider for SpecBundleProvider {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PathBuf, CriError> {
        let dir = self.bundle_dir(req.container_id)?;
        // ファイルシステムに触れる前に、設定だけで判定できる拒否を済ませる。
        validate_config(req.sandbox_config, req.config)?;
        let image = req
            .config
            .image
            .as_ref()
            .filter(|i| !i.image.is_empty())
            .ok_or_else(|| CriError::invalid_argument("image is required"))?;

        create_private_dir(&dir)?;
        let rootfs = dir.join("rootfs");
        let built = (|| {
            let defaults = self.rootfs.prepare(image, &rootfs)?;
            let json = build_runtime_config(req.sandbox_config, req.config, &defaults)?;
            write_new_file(&dir.join("config.json"), json.as_bytes())
        })();
        if let Err(e) = built {
            // 自分が作ったものだけを後始末する。失敗しても元のエラーを返す（後始末の再試行は release が担う）。
            let _ = self.rootfs.release(&rootfs);
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }
        Ok(dir)
    }

    fn release(&self, container_id: &str) -> Result<(), CriError> {
        let dir = self.bundle_dir(container_id)?;
        let meta = match fs::symlink_metadata(&dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CriError::internal("failed to inspect bundle")),
        };
        // symlink・通常ファイル等は消さない（リンク先の削除を防ぐ。fail-closed）。
        if !meta.file_type().is_dir() {
            return Err(CriError::internal("bundle path is not a directory"));
        }
        self.rootfs.release(&dir.join("rootfs"))?;
        fs::remove_dir_all(&dir).map_err(|_| CriError::internal("failed to remove bundle"))
    }
}
