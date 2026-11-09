//! bundle ディレクトリの作成・`config.json` の書き込み・解放を担う汎用の [`BundleProvider`] 実装
//! （CRI-1・CRI-2・OCI-4・SEC-1。#2395）。
//!
//! `CriRuntimeService` の `CreateContainer`（worker スレッド上）が `prepare` を、Create の巻き戻しと
//! `RemoveContainer` が `release` を呼ぶ。bundle は `<root>/<container_id>/` に作り、`config.json` を書く。
//! `rootfs/` の中身（イメージの展開）は注入された [`RootfsSource`] が用意する。
//!
//! 安全性: `root` は構築時に固定し要求から受けない。コンテナ ID は `ContainerId::new` で検証してから 1 コンポーネントの
//! 名前として使う。bundle ディレクトリは構築時に開いた root の fd 起点で `mkdirat`（末尾の symlink を辿らない・既存は
//! `FAILED_PRECONDITION` で消さない）し、fd で受けた [`BundleDir`] を `RootfsSource` と `config.json` の書き込みへ渡す。
//! 解放と `prepare` の巻き戻しも fd 起点で、`<root>/<id>` が作った実体と同じことを (dev, ino) で確かめた時だけ名前を
//! 消す（差し替えを検出したら名前に触れず `FAILED_PRECONDITION`。おとりの木を消さない。OCI-7・SEC-1・#4321）。
//! symlink・通常ファイルの bundle は消さずに拒否する。I/O エラーの OS 文字列やパスはメッセージへ含めない（固定文言のみ）。
//!
//! 所有: 既存の bundle を理由に `prepare` が拒否した ID は「この provider が作っていない」ため記録し、直後の
//! `release`（呼び出し元の巻き戻し）では何も消さない。`root` は構築時に所有者・祖先の書き込み権・symlink を検証し、
//! 操作のたびに構築時の (dev, ino) と一致することを確かめる。
//!
//! **fd 起点にしない範囲（残余。REPAIR-3）**: fd 起点の操作は oci の `ExtractRoot` の安全な API（`unsafe` は oci の `sys` に
//! 閉じる）を使い、本 crate に `unsafe` は足さない。Linux の x86_64 / aarch64 以外（macOS 等）はパス起点の実装で、入口の
//! 再検査に頼る。`list_bundle_ids` の列挙と `effective_uid` の使い捨てファイルも root の fd 起点（#4378。前後の
//! `verify_root` は検出器として残す）。パス起点に残るのは root の祖先の所有者・書き込み権の検査（`check_trusted_chain`）。
//! 差し替えを検出した巻き戻しは、移動先に残る空の
//! bundle ディレクトリの名前が分からないため回収しない（`config.json`・`resolv.conf` と rootfs の中身だけを消す）。
//! `PreparedBundle` が返すパスを core がその後に使う経路は対象外（返す時点の同一性だけを確かめる）。
//! `root` を信頼できる所有者の非共有ディレクトリに置く前提で使う。

use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::ContainerId;
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::layer::extract::{ExtractBudget, ExtractRoot};

use super::resolv_conf;
use super::spec::{
    BundleFiles, ImageDefaults, build_runtime_config_with_files_and_pods, validate_config_with_pods,
};
use crate::adapter::{BundleProvider, BundleRequest, PreparedBundle, ReleaseBudget};
use crate::error::CriError;
use crate::runtime::v1::{ImageSpec, SupplementalGroupsPolicy};
use crate::stop_signal::resolve_stop_signal;

/// `RootfsSource::prepare` へ渡す、rootfs の passwd 等で解決してほしい User 関連の要求（#2664・CRI-2・SEC-5）。
///
/// `SpecBundleProvider::prepare` が CRI の設定から作る。解決の要求を足せるよう、裸の引数にせず構造体にしている
/// （`supplemental_groups` のイメージ由来の解決は #2667）。外部から作るときは [`Self::none`] /
/// [`Self::with_run_as_username`] / [`Self::with_run_as_user`] / [`Self::with_image_groups`]。
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct UserResolveRequest<'a> {
    /// CRI の `run_as_username`（未指定は `None`）。形式は `validate_config` が検証済みだが、実装側も再検証する。
    pub run_as_username: Option<&'a str>,
    /// CRI の `run_as_user`（未指定は `None`）。実効ユーザーの名前を passwd から引くために使う（#2667）。
    pub run_as_user: Option<u32>,
    /// 実効ユーザーのイメージの `/etc/group` での所属グループを求めてほしい（`supplemental_groups_policy` が
    /// `Merge`。#2667）。真のとき実装は [`ImageDefaults::supplementary_gids`] を埋める。
    pub image_groups: bool,
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
            ..Self::default()
        }
    }

    /// CRI の `run_as_user` を伝える（#2667）。
    pub fn with_run_as_user(mut self, uid: u32) -> Self {
        self.run_as_user = Some(uid);
        self
    }

    /// イメージ由来の補助グループの解決を要求する（#2667）。
    pub fn with_image_groups(mut self) -> Self {
        self.image_groups = true;
        self
    }
}

/// 作成済みの bundle ディレクトリ `<root>/<id>` を検査済み fd で保持する値（OCI-7・SEC-1・#4321）。
///
/// `SpecBundleProvider` が `prepare` / `release` で作って [`RootfsSource`] へ渡す。`RootfsSource` は直下の `rootfs/` の
/// 作成・解放を、パスで開き直さずこの fd 起点で行う（bundle の親を symlink へ差し替えられても、おとりの木を作らず消さない）。
/// 子の名前は `rootfs` / `config.json` / `resolv.conf` の固定値に閉じる。[`Self::path`] は `PreparedBundle` と
/// `config.json` の bind source に載せる表示・引き渡し用のパスで、操作には使わない。
#[derive(Debug)]
pub struct BundleDir {
    dir: ExtractRoot,
    path: PathBuf,
}

/// bundle 直下の rootfs の固定名。
const ROOTFS_NAME: &str = "rootfs";

impl BundleDir {
    /// 既存のディレクトリ `path` を symlink を辿らず開いて fd で保持する（試験・外部実装向け）。
    pub fn open(path: &Path) -> Result<Self, OciError> {
        Ok(Self {
            dir: ExtractRoot::open_existing_dir(path)?,
            path: path.to_path_buf(),
        })
    }

    /// bundle ディレクトリのパス（引き渡し・表示用。操作には使わない）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `rootfs/` のパス（`path().join("rootfs")`。fd を使わない照合・表示用）。
    pub fn rootfs_path(&self) -> PathBuf {
        self.path.join(ROOTFS_NAME)
    }

    /// 直下に 0700 の `rootfs/` を新規に作って fd で開く。既存は `AlreadyExists`。
    pub fn create_rootfs_dir(&self) -> Result<ExtractRoot, OciError> {
        self.dir.create_child_private_dir(ROOTFS_NAME)
    }

    /// 直下の `rootfs/` を開く。無ければ `None`、ディレクトリでなければ `FailedPrecondition`。
    pub fn open_rootfs_dir(&self) -> Result<Option<ExtractRoot>, OciError> {
        self.dir.open_child_dir(ROOTFS_NAME)
    }

    /// 直下に `rootfs/` がディレクトリとして在るか（読み取り権限を要求しない。mode 0000 でも `true`）。
    /// 無ければ `false`、ディレクトリでなければ `FailedPrecondition`。解放前の種別確認用（CRI-2）。
    pub fn rootfs_dir_exists(&self) -> Result<bool, OciError> {
        self.dir.child_dir_exists(ROOTFS_NAME)
    }

    /// 直下の `rootfs/` を symlink を辿らず木ごと消す（不在は成功）。
    pub fn remove_rootfs_tree(&self) -> Result<(), OciError> {
        self.dir.remove_child_tree(ROOTFS_NAME)
    }

    /// `remove_rootfs_tree` に期限と取り消しを足した版。
    pub fn remove_rootfs_tree_bounded(&self, budget: &ExtractBudget<'_>) -> Result<(), OciError> {
        self.dir.remove_child_tree_bounded(ROOTFS_NAME, budget)
    }

    /// 直下に `name`（`config.json` 等の固定名）を排他作成して書き込み用に開く。
    fn create_file(&self, name: &str, mode: u32) -> Result<fs::File, OciError> {
        self.dir.create_new_file(name, mode)
    }

    /// 直下の `name`（固定名）を消す（不在は成功）。
    fn remove_child(&self, name: &str) -> Result<(), OciError> {
        self.dir.remove_child_tree(name)
    }
}

/// `rootfs/` の用意と解放の注入点（本番の実装は [`super::ImageRootfsSource`]。#2433）。
///
/// 実装は rootfs の内容と digest を検証する責務を持つ。
pub trait RootfsSource: Send + Sync {
    /// `bundle` 直下に存在しない `rootfs/` を作成して `image` の内容で満たし、イメージ config 由来の既定値を返す。
    /// 作成は `bundle` の fd 起点で行うこと（[`BundleDir::create_rootfs_dir`]。OCI-7・SEC-1・#4321）。
    ///
    /// `user.run_as_username` が `Some` なら rootfs の passwd で解決して
    /// [`ImageDefaults::resolved_run_as_username`] を埋めるか `Err` を返す。対応しない実装は無視してよく、
    /// その場合 `build_runtime_config` が `UNIMPLEMENTED` で拒否する（#2664）。
    fn prepare(
        &self,
        image: &ImageSpec,
        bundle: &BundleDir,
        user: &UserResolveRequest<'_>,
    ) -> Result<ImageDefaults, CriError>;

    /// `prepare` に取り消しの旗を足した版（REPAIR-5・CRI-2・#2899）。`cancel` が立ったら、実装は分割できない区間の
    /// 合間で止まり `Timeout` を返してよい。既定は旗を無視して `prepare` を呼ぶ（取り消しに対応しない実装向け）。
    /// `Err` のとき rootfs を残さない契約は `prepare` と同じ。
    fn prepare_cancellable(
        &self,
        image: &ImageSpec,
        bundle: &BundleDir,
        user: &UserResolveRequest<'_>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<ImageDefaults, CriError> {
        let _ = cancel;
        self.prepare(image, bundle, user)
    }

    /// `prepare` で作った `bundle` 直下の rootfs を fd 起点で解放する（不在は `Ok`）。
    fn release(&self, bundle: &BundleDir) -> Result<(), CriError>;

    /// `release` に期限と取り消しを足した版（#3142・CRI-2・REPAIR-5）。既定は予算を無視して `release` を呼ぶ。
    fn release_bounded(
        &self,
        bundle: &BundleDir,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), CriError> {
        let _ = budget;
        self.release(bundle)
    }
}

/// `SpecBundleProvider::list_bundle_ids` の結果（R8 #2937）。ID 以外は件数のみ。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct BundleListing {
    /// サービス採番の形のディレクトリ名（昇順）。
    pub ids: Vec<String>,
    /// サービス採番の形でない名前（触らない）。
    pub skipped_unrecognized: usize,
    /// 採番の形だがディレクトリでない（symlink・通常ファイル等。触らない）。
    pub skipped_not_dir: usize,
}

/// `<root>/<container_id>/{config.json,rootfs/}` を作る [`BundleProvider`]。
pub struct SpecBundleProvider {
    root: PathBuf,
    rootfs: Arc<dyn RootfsSource>,
    /// 構築時に検証した root の (dev, ino)（unix のみ）。
    #[cfg(unix)]
    root_identity: (u64, u64),
    /// 構築時に検査して開いた root の fd（構築できるのは unix のみ）。bundle の作成・巻き戻し・解放はこの fd 起点（#4321）。
    root_dir: ExtractRoot,
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
            (meta.dev(), meta.ino())
        };
        // 検査したパスと同じ実体を、symlink を辿らず fd で固定する。以後の操作（使い捨てファイルの作成を含む）は
        // この fd を起点にする。
        let root_dir = ExtractRoot::open_existing_dir(&root)
            .map_err(|_| CriError::failed_precondition("bundle root is unavailable"))?;
        if root_dir.identity().ok() != Some(root_identity) {
            return Err(CriError::failed_precondition("bundle root has changed"));
        }
        check_trusted_chain(&root, &meta, &root_dir)?;
        Ok(Self {
            root,
            rootfs,
            #[cfg(unix)]
            root_identity,
            root_dir,
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

    /// bundle の置き場 `root` 直下の ID を列挙する（孤児 bundle の回収の候補作り。R8 #2937・OCI-7・CRI-1）。
    ///
    /// plugin-cri の `reclaim_orphan_bundles`（インスタンスロックの下）が呼ぶ。列挙は構築時に開いた root の fd 起点
    /// （独立した open file description）で行い、各エントリも同じ fd から symlink を辿らずに種別を判定する（#4378）。
    /// このため root のパスが列挙の途中で symlink へ差し替えられても、おとりの中身は読まない。前後の `verify_root` は
    /// 差し替えを成功に見せない検出器として残す。サービス採番の
    /// ID（64 文字の小文字 16 進。`RecordId` と同じ形）でない名前は [`BundleListing::skipped_unrecognized`]、
    /// ディレクトリでないもの（symlink・通常ファイル等）は [`BundleListing::skipped_not_dir`] に数え、どちらも
    /// 触らない。走査数が `max_entries` を超えたら何も返さず `FAILED_PRECONDITION`（無制限確保の防止）。
    /// ID は昇順。パス・OS のエラー文字列は文言に含めない（REPAIR-4）。
    #[cfg(unix)]
    pub fn list_bundle_ids(&self, max_entries: usize) -> Result<BundleListing, CriError> {
        self.verify_root()?;
        let mut listing = self.scan_bundle_ids(max_entries)?;
        // fd 起点の列挙では冗長だが、列挙の間に root が差し替わったなら成功として返さない（fail-closed）。
        self.verify_root()?;
        listing.ids.sort();
        Ok(listing)
    }

    /// `list_bundle_ids` の本体。`verify_root` を呼ばず、root の fd 起点の列挙と分類だけを行う
    /// （試験が差し替えの窓を直接突くための継ぎ目。#4378）。
    #[cfg(unix)]
    fn scan_bundle_ids(&self, max_entries: usize) -> Result<BundleListing, CriError> {
        let names = self
            .root_dir
            .child_names(max_entries)
            .map_err(|e| match e.code() {
                OciErrorCode::ResourceExhausted => {
                    CriError::failed_precondition("bundle root has too many entries")
                }
                _ => CriError::internal("failed to list bundle root"),
            })?;
        let mut listing = BundleListing::default();
        for name in names {
            let Some(name) = name.to_str() else {
                listing.skipped_unrecognized += 1;
                continue;
            };
            if crate::runtime_service::RecordId::new(name).is_err() {
                listing.skipped_unrecognized += 1;
                continue;
            }
            // `Ok(false)`（列挙の後に消えた）と判定の失敗は、従来の `unwrap_or(false)` と同じく数えて触らない。
            if matches!(self.root_dir.child_dir_exists(name), Ok(true)) {
                listing.ids.push(name.to_owned());
            } else {
                listing.skipped_not_dir += 1;
            }
        }
        Ok(listing)
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
/// （non-dumpable 時は root になる）を代用しない。使い捨てファイルは構築時に開いた root の fd 起点で
/// 排他作成し（`O_EXCL | O_NOFOLLOW`）、`unlinkat` で消す（#4378）。root のパスが差し替わってもおとりへ書かない。
/// 作成・読み取りに失敗したら拒否する（fail-closed）。
#[cfg(unix)]
fn effective_uid(root_dir: &ExtractRoot) -> Result<u32, CriError> {
    use std::os::unix::fs::MetadataExt as _;
    let name = format!(".fandhe-uid-probe-{}", std::process::id());
    // 同名のディレクトリ等が既にあっても再帰削除せず拒否する（#4378。所有者検証より前に破壊的操作をしない）
    root_dir
        .unlink_child_file(&name)
        .map_err(|_| CriError::failed_precondition("effective uid is unavailable"))?;
    let uid = root_dir
        .create_new_file(&name, 0o600)
        .map_err(|_| ())
        .and_then(|f| f.metadata().map_err(|_| ()))
        .map(|m| m.uid())
        .map_err(|()| CriError::failed_precondition("effective uid is unavailable"));
    let _ = root_dir.unlink_child_file(&name);
    uid
}

/// root 自身と祖先の所有者・書き込み権を検証する（unix）。
///
/// 所有者は root（uid 0）か、この process の実効 UID（[`effective_uid`] で独立に取得。取得できなければ拒否）。
/// group / other に書き込み権のある祖先は、sticky bit がある場合だけ許す。
#[cfg(unix)]
fn check_trusted_chain(
    root: &Path,
    root_meta: &fs::Metadata,
    root_dir: &ExtractRoot,
) -> Result<(), CriError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let me = effective_uid(root_dir)?;
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

/// bundle 直下に `name` を排他作成して書く（fd 起点・symlink を辿らない）。失敗の文言は固定（`what` はファイル名）。
fn write_new_file(
    bundle: &BundleDir,
    name: &str,
    bytes: &[u8],
    mode: u32,
    what: &'static str,
) -> Result<(), CriError> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut f = bundle
        .create_file(name, mode)
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

/// 期限切れ・取り消し（oci の `Timeout`）を cri の `Timeout` に、それ以外を `fallback` の固定文言に写す。
fn map_remove_err(e: &OciError, fallback: &'static str) -> CriError {
    if e.code() == OciErrorCode::Timeout {
        CriError::timeout("bundle release exceeded its deadline")
    } else {
        CriError::internal(fallback)
    }
}

impl BundleProvider for SpecBundleProvider {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let dir = self.bundle_dir(req.container_id)?;
        // 事前検証の失敗でも、同 ID の既存実体はこの provider が作っていない。直後の release（呼び出し元の
        // 巻き戻し）で消さないよう、bundle を作成できるまで ID を拒否扱いにしておく。
        self.lock_refused().insert(req.container_id.to_owned());
        self.verify_root()?;
        // ファイルシステムに触れる前に、設定だけで判定できる拒否を済ませる。
        validate_config_with_pods(
            req.sandbox_config,
            req.config,
            req.pod_namespaces,
            req.pod_netns_path.and_then(|p| p.to_str()),
        )?;
        let image = req
            .config
            .image
            .as_ref()
            .filter(|i| !i.image.is_empty())
            .ok_or_else(|| CriError::invalid_argument("image is required"))?;

        // 作成に成功した時だけ所有する（拒否扱いを外す）。既存・作成失敗は拒否扱いのまま残す。
        // root の fd 起点で作り、以後の操作は作った実体の fd だけを使う（OCI-7・SEC-1・#4321）。
        let created = self
            .root_dir
            .create_child_private_dir(req.container_id)
            .map_err(|e| {
                if e.code() == OciErrorCode::AlreadyExists {
                    CriError::failed_precondition("bundle already exists")
                } else {
                    CriError::internal("failed to create bundle directory")
                }
            })?;
        self.lock_refused().remove(req.container_id);
        let bundle = BundleDir {
            dir: created,
            path: dir,
        };
        let username = req
            .config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref())
            .map(|s| s.run_as_username.as_str())
            .filter(|n| !n.is_empty());
        let sc = req
            .config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref());
        // `validate_config` が値の範囲と方針を検証済みなので、ここでの変換失敗は「要求なし」に倒す。
        let run_as_user = sc
            .and_then(|s| s.run_as_user.as_ref())
            .and_then(|v| u32::try_from(v.value).ok());
        let merge = sc
            .is_none_or(|s| s.supplemental_groups_policy == SupplementalGroupsPolicy::Merge as i32);
        let user = UserResolveRequest {
            run_as_username: username,
            run_as_user,
            image_groups: merge,
        };
        let built = (|| -> Result<_, CriError> {
            let defaults = self
                .rootfs
                .prepare_cancellable(image, &bundle, &user, req.cancel)?;
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
            let resolv_path = bundle.path().join("resolv.conf");
            let files = match &resolv {
                Some(r) => {
                    write_new_file(&bundle, "resolv.conf", r.as_bytes(), 0o644, "resolv.conf")?;
                    let p = resolv_path
                        .to_str()
                        .ok_or_else(|| CriError::internal("bundle path is not valid UTF-8"))?;
                    BundleFiles::with_resolv_conf(p)
                }
                None => BundleFiles::none(),
            };
            let json = build_runtime_config_with_files_and_pods(
                req.sandbox_config,
                req.config,
                &defaults,
                &files,
                req.pod_namespaces,
                req.pod_netns_path.and_then(|p| p.to_str()),
            )?;
            write_new_file(
                &bundle,
                "config.json",
                json.as_bytes(),
                0o600,
                "config.json",
            )?;
            // 返すパスが作った実体であることを確かめる（root・`<root>/<id>` の差し替えを成功に見せない。fd 起点の
            // 書き込みは作った実体にだけ届いており、おとりへは書かれていない）。
            if !self.root_dir.child_matches(req.container_id, &bundle.dir) {
                return Err(CriError::failed_precondition(
                    "bundle path changed during preparation",
                ));
            }
            self.verify_root()?;
            // CRI が RUNTIME_DEFAULT のときだけイメージの StopSignal を使う（#2771・CRI-2・OCI-1）。
            let stop = resolve_stop_signal(req.config.stop_signal, defaults.stop_signal)?;
            Ok((
                json.process_user().clone(),
                stop,
                defaults.resolved_image.clone(),
            ))
        })();
        let (applied, stop, image) = match built {
            Ok(v) => v,
            Err(e) => {
                // 自分が作ったものだけを後始末する。rootfs の解放に失敗したら bundle を残し（通常の release と同じ
                // 順序: rootfs 解放 → bundle 削除）、再試行は呼び出し元の release が担う。元のエラーを返す。
                // すべて fd 起点。`<root>/<id>` が差し替わっていれば名前に触れず、作った実体の中の固定名のファイルだけ
                // を消す（移動先の空ディレクトリは名前が分からず残る。モジュール冒頭「残余」）。
                if self.rootfs.release(&bundle).is_ok() {
                    if self.root_dir.child_matches(req.container_id, &bundle.dir) {
                        let _ = self.root_dir.remove_child_tree(req.container_id);
                    } else {
                        let _ = bundle.remove_child("config.json");
                        let _ = bundle.remove_child("resolv.conf");
                    }
                }
                return Err(e);
            }
        };
        let prepared = PreparedBundle::new(bundle.path)
            .with_user(applied)
            .with_stop_signal(stop);
        Ok(match image {
            Some(image) => prepared.with_image(image),
            None => prepared,
        })
    }

    fn release(&self, container_id: &str) -> Result<(), CriError> {
        self.release_bounded(container_id, &ReleaseBudget::new())
    }

    fn release_bounded(
        &self,
        container_id: &str,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), CriError> {
        let dir = self.bundle_dir(container_id)?;
        // この provider が作っていない実体（prepare が既存を理由に拒否した ID）は消さない。
        if self.lock_refused().remove(container_id) {
            return Ok(());
        }
        self.verify_root()?;
        // symlink・通常ファイル等は消さない（リンク先の削除を防ぐ。fail-closed）。不在は冪等に成功。
        let opened = match self.root_dir.open_child_dir(container_id) {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(()),
            Err(e) if e.code() == OciErrorCode::FailedPrecondition => {
                return Err(CriError::internal("bundle path is not a directory"));
            }
            Err(_) => return Err(CriError::internal("failed to inspect bundle")),
        };
        let bundle = BundleDir {
            dir: opened,
            path: dir,
        };
        budget.check()?;
        self.rootfs.release_bounded(&bundle, budget)?;
        // 確認から削除までの間に `<root>/<id>` が差し替わっていたら、名前に触れない（おとりを消さない。#4321）。
        if !self.root_dir.child_matches(container_id, &bundle.dir) {
            return Err(CriError::failed_precondition(
                "bundle path changed during release",
            ));
        }
        // rootfs を消した後の bundle 直下は小さなファイル（config.json 等）だけで、分割しない。
        self.root_dir
            .remove_child_tree_bounded(container_id, &budget.to_extract_budget())
            .map_err(|e| map_remove_err(&e, "failed to remove bundle"))
    }
}
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// 何も用意しない `RootfsSource`（列挙と uid 取得の試験には使わない）。
    struct NoRootfs;

    impl RootfsSource for NoRootfs {
        fn prepare(
            &self,
            _image: &ImageSpec,
            _bundle: &BundleDir,
            _user: &UserResolveRequest<'_>,
        ) -> Result<ImageDefaults, CriError> {
            Err(CriError::unimplemented("test"))
        }
        fn release(&self, _bundle: &BundleDir) -> Result<(), CriError> {
            Ok(())
        }
    }

    /// `<base>/bundles` を 0755 で作って `(base, bundles)` を返す。
    fn setup(tag: &str) -> (PathBuf, PathBuf) {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("fc-cri-provider-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let bundles = base.join("bundles");
        fs::create_dir(&bundles).unwrap();
        fs::set_permissions(&bundles, fs::Permissions::from_mode(0o755)).unwrap();
        (base, bundles)
    }

    fn swap_to_decoy(base: &Path, bundles: &Path, decoy: &Path) {
        fs::rename(bundles, base.join("bundles-real")).unwrap();
        std::os::unix::fs::symlink(decoy, bundles).unwrap();
    }

    /// OCI-7・SEC-1・#4378: 列挙の窓（`verify_root` の外）で root がおとりへ差し替わっても、`scan_bundle_ids` は
    /// 元の実体の ID だけを返し、おとりの ID を返さない。公開の `list_bundle_ids` は差し替えを拒否する。
    #[test]
    fn oci7_sec1_4378_scan_after_root_swap_returns_only_real_ids() {
        let (base, bundles) = setup("scan");
        let id_a = "a".repeat(64);
        let id_b = "b".repeat(64);
        fs::create_dir(bundles.join(&id_a)).unwrap();
        let p = SpecBundleProvider::new(bundles.clone(), Arc::new(NoRootfs)).unwrap();
        let decoy = base.join("decoy");
        fs::create_dir_all(decoy.join(&id_b)).unwrap();
        swap_to_decoy(&base, &bundles, &decoy);

        let listing = p.scan_bundle_ids(10).unwrap();
        assert_eq!(
            listing,
            BundleListing {
                ids: vec![id_a],
                skipped_unrecognized: 0,
                skipped_not_dir: 0,
            }
        );
        let e = p.list_bundle_ids(10).unwrap_err();
        assert_eq!(e.message(), "bundle root must be a directory");
        assert!(decoy.join(&id_b).is_dir());
        let _ = fs::remove_dir_all(&base);
    }

    /// OCI-7・SEC-1・#4378: 差し替え後の `effective_uid` は固定した実体の fd 起点で動き、おとりにファイルを
    /// 作らず、元の実体にも残さない。返す uid は新規作成したファイルの所有者と一致する。
    #[test]
    fn oci7_sec1_4378_effective_uid_does_not_create_files_in_the_decoy() {
        let (base, bundles) = setup("uid");
        let root_dir = ExtractRoot::open_existing_dir(&bundles).unwrap();
        let decoy = base.join("decoy");
        fs::create_dir_all(&decoy).unwrap();
        swap_to_decoy(&base, &bundles, &decoy);

        let uid = effective_uid(&root_dir).unwrap();
        let probe = base.join("probe-owner");
        fs::write(&probe, b"x").unwrap();
        assert_eq!(uid, fs::metadata(&probe).unwrap().uid());
        assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
        assert_eq!(fs::read_dir(base.join("bundles-real")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&base);
    }

    /// OCI-7・SEC-1・#4378: 同名のディレクトリが root 直下にあっても `effective_uid` は拒否するだけで、
    /// 再帰削除せず中身を残す。
    #[test]
    fn oci7_sec1_4378_effective_uid_keeps_a_same_named_directory() {
        let (base, bundles) = setup("uiddir");
        let root_dir = ExtractRoot::open_existing_dir(&bundles).unwrap();
        let name = format!(".fandhe-uid-probe-{}", std::process::id());
        let dir = bundles.join(&name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("keep"), b"x").unwrap();
        let e = effective_uid(&root_dir).unwrap_err();
        assert_eq!(e.message(), "effective uid is unavailable");
        assert!(dir.join("keep").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
