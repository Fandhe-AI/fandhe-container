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
//!
//! 所有: 既存の bundle を理由に `prepare` が拒否した ID は「この provider が作っていない」ため記録し、直後の
//! `release`（呼び出し元の巻き戻し）では何も消さない。`root` は構築時に所有者・祖先の書き込み権・symlink を検証し、
//! 操作のたびに構築時の (dev, ino) と一致することを確かめる。
//!
//! **残る制約（REPAIR-3）**: 検証済みディレクトリを fd で固定して `openat` 系で操作することは、`unsafe` / FFI を要し
//! 本 crate には `sys` モジュールが無いため未実装。root の差し替えは (dev, ino) の再確認で検出するが、確認から
//! 操作までの極小の窓は残る。`root` を信頼できる所有者の非共有ディレクトリに置く前提で使う。

use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::ContainerId;

use super::resolv_conf;
use super::spec::{
    BundleFiles, ImageDefaults, build_runtime_config_with_files_and_pod_netns, validate_config,
};
use crate::adapter::{BundleProvider, BundleRequest};
use crate::error::CriError;
use crate::runtime::v1::ImageSpec;

/// `RootfsSource::prepare` へ渡す、rootfs の passwd 等で解決してほしい User 関連の要求（#2664・CRI-2・SEC-5）。
///
/// `SpecBundleProvider::prepare` が CRI の設定から作る。将来 `supplemental_groups` 等の解決（#2667）を
/// 足せるよう、裸の引数にせず構造体にしている。外部から作るときは [`Self::none`] / [`Self::with_run_as_username`]。
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct UserResolveRequest<'a> {
    /// CRI の `run_as_username`（未指定は `None`）。形式は `validate_config` が検証済みだが、実装側も再検証する。
    pub run_as_username: Option<&'a str>,
}

impl<'a> UserResolveRequest<'a> {
    /// 解決要求なし。
    pub fn none() -> Self {
        Self::default()
    }

    /// `run_as_username` の解決を要求する。
    pub fn with_run_as_username(name: &'a str) -> Self {
        Self {
            run_as_username: Some(name),
        }
    }
}

/// `rootfs/` の用意と解放の注入点（本番の実装は [`super::ImageRootfsSource`]。#2433）。
///
/// 実装は rootfs の内容と digest を検証する責務を持つ。
pub trait RootfsSource: Send + Sync {
    /// 存在しないパス `rootfs` を作成して `image` の内容で満たし、イメージ config 由来の既定値を返す。
    ///
    /// `user.run_as_username` が `Some` なら rootfs の passwd で解決して
    /// [`ImageDefaults::resolved_run_as_username`] を埋めるか `Err` を返す。対応しない実装は無視してよく、
    /// その場合 `build_runtime_config` が `UNIMPLEMENTED` で拒否する（#2664）。
    fn prepare(
        &self,
        image: &ImageSpec,
        rootfs: &Path,
        user: &UserResolveRequest<'_>,
    ) -> Result<ImageDefaults, CriError>;

    /// `prepare` で作った rootfs を解放する（不在は `Ok`）。
    fn release(&self, rootfs: &Path) -> Result<(), CriError>;
}

/// `<root>/<container_id>/{config.json,rootfs/}` を作る [`BundleProvider`]。
pub struct SpecBundleProvider {
    root: PathBuf,
    rootfs: Arc<dyn RootfsSource>,
    /// 構築時に検証した root の (dev, ino)（unix のみ）。
    #[cfg(unix)]
    root_identity: (u64, u64),
    /// `prepare` が bundle を作成できずに失敗した ID（事前検証の失敗・既存 bundle を含む）（この provider が作っていない実体を `release` が消さないため）。
    refused: Mutex<HashSet<String>>,
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
        // 非 unix（Windows）は root の所有者・祖先・実体固定の検証と、bundle / config.json の専用 ACL・再解析ポイントの
        // 検証が未実装（REPAIR-3。実装は Windows 実行構成の確定後。WIN-1）。保護なしで bundle を作らないよう、
        // 副作用の前に拒否する（fail-closed。SEC-1）。
        #[cfg(not(unix))]
        {
            let _ = (&root, &rootfs);
            Err(CriError::unimplemented(
                "bundle generation is not supported on this platform",
            ))
        }
        #[cfg(unix)]
        {
            Self::new_unix(root, rootfs)
        }
    }

    #[cfg(unix)]
    fn new_unix(root: PathBuf, rootfs: Arc<dyn RootfsSource>) -> Result<Self, CriError> {
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
        let root_identity = {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if meta.permissions().mode() & 0o022 != 0 {
                return Err(CriError::failed_precondition(
                    "bundle root must not be writable by group or others",
                ));
            }
            // 途中に symlink があれば正規化したパスと一致しない。
            let canonical = fs::canonicalize(&root)
                .map_err(|_| CriError::failed_precondition("bundle root is unavailable"))?;
            if canonical != root {
                return Err(CriError::failed_precondition(
                    "bundle root must not contain symlinks",
                ));
            }
            check_trusted_chain(&root, &meta)?;
            (meta.dev(), meta.ino())
        };
        Ok(Self {
            root,
            rootfs,
            #[cfg(unix)]
            root_identity,
            refused: Mutex::new(HashSet::new()),
        })
    }

    /// root が構築時と同じディレクトリ（差し替わっていない）ことを確かめる。
    fn verify_root(&self) -> Result<(), CriError> {
        let meta = fs::symlink_metadata(&self.root)
            .map_err(|_| CriError::failed_precondition("bundle root is unavailable"))?;
        if !meta.file_type().is_dir() {
            return Err(CriError::failed_precondition(
                "bundle root must be a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if (meta.dev(), meta.ino()) != self.root_identity {
                return Err(CriError::failed_precondition("bundle root has changed"));
            }
        }
        Ok(())
    }

    fn lock_refused(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.refused.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn bundle_dir(&self, container_id: &str) -> Result<PathBuf, CriError> {
        if container_id.len() > 255 {
            return Err(CriError::invalid_argument("container id is invalid"));
        }
        let id = ContainerId::new(container_id)
            .map_err(|_| CriError::invalid_argument("container id is invalid"))?;
        Ok(self.root.join(id.as_str()))
    }
}

/// この process の実効 UID を、root 直下に作った使い捨てファイルの所有者から独立に求める（unix）。
///
/// 新規作成したファイルの所有者は作成者の実効 UID になる。検証対象（root）の所有者や `/proc/self` の所有者
/// （non-dumpable 時は root になる）を代用しない。作成・読み取りに失敗したら拒否する（fail-closed）。
#[cfg(unix)]
fn effective_uid(root: &Path) -> Result<u32, CriError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let probe = root.join(format!(".fandhe-uid-probe-{}", std::process::id()));
    let _ = fs::remove_file(&probe);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe);
    let uid = file
        .and_then(|f| f.metadata())
        .map(|m| m.uid())
        .map_err(|_| CriError::failed_precondition("effective uid is unavailable"));
    let _ = fs::remove_file(&probe);
    uid
}

/// root 自身と祖先の所有者・書き込み権を検証する（unix）。
///
/// 所有者は root（uid 0）か、この process の実効 UID（[`effective_uid`] で独立に取得。取得できなければ拒否）。
/// group / other に書き込み権のある祖先は、sticky bit がある場合だけ許す。
#[cfg(unix)]
fn check_trusted_chain(root: &Path, root_meta: &fs::Metadata) -> Result<(), CriError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let me = effective_uid(root)?;
    if root_meta.uid() != me && root_meta.uid() != 0 {
        return Err(CriError::failed_precondition(
            "bundle root has an untrusted owner",
        ));
    }
    for anc in root.ancestors().skip(1) {
        let m = fs::symlink_metadata(anc)
            .map_err(|_| CriError::failed_precondition("bundle root is unavailable"))?;
        if m.uid() != me && m.uid() != 0 {
            return Err(CriError::failed_precondition(
                "bundle root has an untrusted ancestor",
            ));
        }
        let mode = m.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(CriError::failed_precondition(
                "bundle root has a writable ancestor",
            ));
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), CriError> {
    #[cfg_attr(not(unix), allow(unused_mut))]
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

/// 既存・symlink を辿らず排他作成して書く。失敗の文言は固定（`what` はファイル名）。
fn write_new_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    what: &'static str,
) -> Result<(), CriError> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = o
        .open(path)
        .map_err(|_| CriError::internal(format!("failed to create {what}")))?;
    // open 時の mode は umask で削られる（umask 077 だと 0644 が 0600 になる）。排他作成した自分のハンドルに
    // 対して明示的に設定し直す（プロセス全体の umask は変えない）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| CriError::internal(format!("failed to set permissions of {what}")))?;
    }
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| CriError::internal(format!("failed to write {what}")))
}

impl BundleProvider for SpecBundleProvider {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PathBuf, CriError> {
        let dir = self.bundle_dir(req.container_id)?;
        // 事前検証の失敗でも、同 ID の既存実体はこの provider が作っていない。直後の release（呼び出し元の
        // 巻き戻し）で消さないよう、bundle を作成できるまで ID を拒否扱いにしておく。
        self.lock_refused().insert(req.container_id.to_owned());
        self.verify_root()?;
        // ファイルシステムに触れる前に、設定だけで判定できる拒否を済ませる。
        validate_config(req.sandbox_config, req.config)?;
        let image = req
            .config
            .image
            .as_ref()
            .filter(|i| !i.image.is_empty())
            .ok_or_else(|| CriError::invalid_argument("image is required"))?;

        // 作成に成功した時だけ所有する（拒否扱いを外す）。既存・作成失敗は拒否扱いのまま残す。
        create_private_dir(&dir)?;
        self.lock_refused().remove(req.container_id);
        let rootfs = dir.join("rootfs");
        let username = req
            .config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref())
            .map(|s| s.run_as_username.as_str())
            .filter(|n| !n.is_empty());
        let user = UserResolveRequest {
            run_as_username: username,
        };
        let built = (|| {
            let defaults = self.rootfs.prepare(image, &rootfs, &user)?;
            // dns_config: 検証済みの resolv.conf を bundle に書き、そのパスを config.json の bind の source にする。
            // mode は 0644（mount の root がファイル自身になり bundle の 0700 が効かないため、写像された
            // 非 root の uid で動く process が読めるようにする。DNS 設定だけで秘密値は含まない）。
            let resolv = req
                .sandbox_config
                .dns_config
                .as_ref()
                .map(resolv_conf::render)
                .transpose()?
                .flatten();
            let resolv_path = dir.join("resolv.conf");
            let files = match &resolv {
                Some(r) => {
                    write_new_file(&resolv_path, r.as_bytes(), 0o644, "resolv.conf")?;
                    let p = resolv_path
                        .to_str()
                        .ok_or_else(|| CriError::internal("bundle path is not valid UTF-8"))?;
                    BundleFiles::with_resolv_conf(p)
                }
                None => BundleFiles::none(),
            };
            let json = build_runtime_config_with_files_and_pod_netns(
                req.sandbox_config,
                req.config,
                &defaults,
                &files,
                req.pod_netns_path.and_then(|p| p.to_str()),
            )?;
            write_new_file(
                &dir.join("config.json"),
                json.as_bytes(),
                0o600,
                "config.json",
            )
        })();
        if let Err(e) = built {
            // 自分が作ったものだけを後始末する。rootfs の解放に失敗したら bundle を残し（通常の release と同じ
            // 順序: rootfs 解放 → bundle 削除）、再試行は呼び出し元の release が担う。元のエラーを返す。
            if self.rootfs.release(&rootfs).is_ok() {
                let _ = fs::remove_dir_all(&dir);
            }
            return Err(e);
        }
        Ok(dir)
    }

    fn release(&self, container_id: &str) -> Result<(), CriError> {
        let dir = self.bundle_dir(container_id)?;
        // この provider が作っていない実体（prepare が既存を理由に拒否した ID）は消さない。
        if self.lock_refused().remove(container_id) {
            return Ok(());
        }
        self.verify_root()?;
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
