//! イメージつき create でレイヤーを rootfs へ展開するための依存注入口と、展開先の作成・後始末
//! （#2342・OCI-7・TASK-183.8 追補・TASK-29）。
//!
//! # 役割と呼び出し元
//!
//! `create::create_with_image` が「参照登録 → config 検証 → 展開先の作成 → 展開 → bundle 検証 → 状態作成」の
//! 順で呼ぶ。展開の実体（`fandhe-container-oci` の `layer::extract`）は oci にあり、core は oci に
//! 依存しない（`docs/architecture.md`）ため、`ContainerImageRefs` と同様に
//! トレイト [`ImageRootfsUnpacker`] を上位 crate が `ImageStore` で満たす。展開先のパスの決定・作成・
//! 失敗時の後始末は core の責務で、本ファイルの `prepare_rootfs_target` と `CreatedRootfs::remove` が担う。
//!
//! # 展開途中の木の回収（#2379・OCI-7）
//!
//! 展開先は core 専有のラッパー `.fandhe-unpack-<pid>-<seq>/`（0700・実効 uid 所有。展開器には渡さない）と
//! その子 `rootfs/`（展開器に渡す実際の展開先）の 2 段である（#2635）。イメージ（展開器）が所有者や mode を
//! 変えられるのは子だけなので、rootful でイメージの `./` の項目が所有者を 0 以外へ変えても、回収が判定する
//! ラッパーは実効 uid 所有のまま回収できる。公開は子をラッパーから最終の名前へ `renameat2` で移し、空の
//! ラッパーを best effort で消す（消し損ねても次の回収が拾う）。ラッパーの名前が予約名なので `root.path` から
//! 子へは到達できない。bundle の親に書ける者は rootful では bundle の設定自体を握る信頼された主体で、予約名の
//! 位置に他人が置いたディレクトリは所有者の照合で落ちる（この前提は従来と同じ）。この変更より前の平らな構造の
//! 木（予約名の木そのものが展開先）は従来の挙動のまま残り、rootful で所有者が変わったものは
//! `Unverified(Owner)` で観測できる。
//!
//! 展開の途中でプロセスが落ちると、非公開の名前 `.fandhe-unpack-<pid>-<seq>` の木が残る（連番は
//! プロセスごとに 0 から数えるため、PID が再利用されると次の create が `EEXIST` で止まる）。
//! 持ち主がいるかは PID ではなく、木のディレクトリ自体への OS ロック（`flock`）で判定する。作る側は作った
//! 直後に排他ロックを取り、`CreatedRootfs` が生きている間保持する（プロセスが落ちれば OS が外す）。
//! 回収する側は固定した親の fd の下で予約名（`^\.fandhe-unpack-[0-9]{1,10}-[0-9]{1,20}$`）の兄弟を調べ、
//! 次の条件をすべて満たすものだけを消す: リンクでないディレクトリ・所有者が実効 uid・mode 0700・
//! ロックが取れる（`WouldBlock` は生きているので残す）・ロック保持中に名前から開き直した実体が同じ
//! （dev・ino）。どれかを確かめられなければ残す（OCI-7: 誤るときは余分に残す側だけ）。件数・深さ・走査数に
//! 上限を置き、ロックは `try_lock` だけで待たない。回収は create の時点（`prepare_rootfs_target`）と、
//! 起動時の照合用の公開入口 [`reap_stale_unpacks`] の 2 か所で行い、生きている create を壊さない。
//!
//! 作る側と回収側の競合: `mkdir` からロックまでの間に回収側が空の新しい木を取ることがある。作る側は
//! ロックの失敗か開き直しの不一致を `Internal` で返し（後始末はしない。持ち主は回収側）、再試行で成功する。
//! 既知の残り: 本変更より前に作られたロックの無い木も「ロックが取れる」ため、名前・所有者・mode の条件を
//! 満たせば回収対象になる（予約名のため許容）。ロックはローカルのファイルシステムが前提で、NFS 等での意味は
//! 保証しない。mode は証拠にしない（userns の展開器はイメージの `./` の項目で展開先の root の mode を変えうる。
//! 所有者は実効 uid、権限が `SubordinateIds` なら subuid の範囲も受ける）。確かめられず残した木の理由は
//! [`UnverifiedReason`] で観測でき、[`reap_stale_unpacks_with`] は残した木・消せなかった木を 1 件ずつ失敗として
//! 記録する（#2540・REPAIR-4）。Linux 以外は作成自体が `Unimplemented` で木が生じず、[`reap_stale_unpacks`] も
//! `Unimplemented` を返す（REPAIR-3）。状態ルート全体の掃引はしない（決定 E。#2635）。回収の契機は
//! 同じ bundle への次の `create_with_image` と、bundle を知る呼び出し元が呼ぶ [`reap_stale_unpacks`] /
//! [`reap_stale_unpacks_with`] に限る。
//!
//! # 公開済みで状態の無い rootfs の回収（#2540・OCI-7）
//!
//! 公開（`renameat2`）の後・状態作成の前にクラッシュした木、delete が状態を消した後の rootfs 削除に失敗した木、
//! 状態を失った木は、次の同じ bundle の create を `AlreadyExists` で塞ぎ続ける。`create_with_image` は展開先を
//! 作る前に [`reap_published_orphan`] を呼び、孤児と確かめられたときだけ消す（条件は同関数の doc）。印は v3
//! （トークン + 作成時の (dev, ino) + 状態ルートの識別子）で、同一性が一致しない複製（`cp -a`）や v1 の印は残す。生きている create は
//! `CreatedRootfs` が状態作成まで木の `flock` を保持することで見分ける。
//!
//! 印は v3（#2635・OCI-5）で、3 行目に状態ルートの識別子（`StateStore::host_state_root` の絶対パスの SHA-256 の
//! 先頭 128 bit。`state_root_scope`）を載せる。孤児の回収は識別子が現在のストアと一致する木だけを消す
//! （別の状態ルート〔`--root` 違い〕のコンテナが使う公開済みの rootfs を、`StateStore::list` に見えないことを
//! 理由に孤児と取り違えない fail-closed）。v2 の印・識別子を持たないストアの木は残す（`OrphanReap::ForeignStateRoot`）。
//! 状態ルート全体の掃引（journal・起動時の全件照合）は決定 E として入れない（`docs/design/image-rootfs-lifetime.md`）。
//!
//! # subuid 所有の木の削除（#2540・SEC-5・CORE-6）
//!
//! rootless で userns の中の展開器が作った木はホストの実効 uid では消せない。[`ImageRootfsPrivilege::SubordinateIds`]
//! のときは、子プロセスの user namespace の中で（固定済みの親の fd を継承して）消す。delete・create 失敗の後始末・
//! 展開途中の回収・孤児の回収が共有する。印は最後に消すので、途中で失敗しても次の回収が木を見分けられる。
//!
//! 本番の展開器（manifest からレイヤーの blob・mediaType・diff_id を引いて oci へ渡すアダプタ）と
//! CLI / plugin の配線は未実装である（REPAIR-3。#2315 の配線で扱う）。

use std::path::{Component, Path, PathBuf};

use super::image_refs::ImageManifestDigest;
#[cfg(target_os = "linux")]
use super::launcher::SubordinateIdSource;
use crate::observability::{OpName, OpOutcome, OpRecorder};
use crate::traits::{ErrorCode, ImageRootfsOwnership, ImageRootfsRecord, StateStore, TraitError};

/// 非公開の展開先の名前の接頭辞。`root.path` の要素としてこの接頭辞を持つ名前は、展開中の非公開の木を
/// 通常の create が rootfs として採用することを防ぐため、`prepare_rootfs_target` と `check_rootfs` が拒否する
/// （OCI-7: 使用中 rootfs の保持。展開中の木は名前を列挙でき、別 ID の create が指せてしまう）。
/// 記録（`ImageRootfsRecord`）の経路検証と同じ定数を使い、単一の真実源にする（#2378）。
pub(super) const STAGING_PREFIX: &str = crate::traits::state_store::IMAGE_ROOTFS_STAGING_PREFIX;

/// 作った rootfs の直下に置く所有トークンの印のファイル名。delete が記録のトークンと内容を照合し、
/// 一致したときだけ消す（作成世代の識別。inode の再利用で別のディレクトリを誤認しない。OCI-7・SEC-1・#2378）。
#[cfg(target_os = "linux")]
const OWNER_TOKEN_FILE: &str = ".fandhe-container-rootfs-owner";

/// 印のファイルの最大バイト数（v3 は 32 + 1 + 41 + 1 + 32 + 1 = 108 バイト以下。余裕を見て 128）。
#[cfg(target_os = "linux")]
const MARKER_MAX_BYTES: u64 = 128;

/// userns の中での削除に与える、削除そのものの予算（写像の書き込みの期限とは別。REPAIR-5）。
#[cfg(target_os = "linux")]
const USERNS_REMOVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// userns の中での seal / publish に与える予算（写像の書き込みの期限とは別。REPAIR-5・#2690）。
#[cfg(target_os = "linux")]
const USERNS_FINALIZE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// 公開済みの孤児の回収で、状態を調べるページ数・1 ページの件数の上限（無制限の走査を避ける。REPAIR-5）。
#[cfg(target_os = "linux")]
const ORPHAN_SCAN_MAX_PAGES: usize = 200;
#[cfg(target_os = "linux")]
const ORPHAN_SCAN_PAGE_SIZE: u32 = 500;

/// 公開済みの孤児の回収の操作名（REPAIR-4・#2540）。
const IMAGE_ROOTFS_ORPHAN_REAP_OP_NAME: &str = "image_rootfs_orphan_reap";
/// 展開途中の木の回収の結果の内訳を 1 件ずつ失敗として記録する操作名（REPAIR-4・#2540）。
/// `OpRecorder::snapshot` の失敗数が、残した木の件数として読める。
const REAP_KEPT_UNVERIFIED_OP_NAME: &str = "image_rootfs_reap_kept_unverified";
const REAP_FAILED_OP_NAME: &str = "image_rootfs_reap_failed";
const REAP_TRUNCATED_OP_NAME: &str = "image_rootfs_reap_truncated";
const REAP_SCAN_FAILED_OP_NAME: &str = "image_rootfs_reap_scan_failed";
const IMAGE_ROOTFS_REAP_OP_NAME: &str = "image_rootfs_reap";

/// 後始末で権限を補正しながら辿る項目数の上限（無制限の走査を避ける。展開側の既定上限と同程度）。
#[cfg(target_os = "linux")]
const CLEANUP_MAX_ENTRIES: usize = 1_000_000;
/// 後始末で辿るディレクトリの深さの上限。
#[cfg(target_os = "linux")]
const CLEANUP_MAX_DEPTH: usize = 256;

/// core が作った rootfs の木を消すときの権限（SEC-5・CORE-6・OCI-7・#2540）。
///
/// rootless で userns の中の展開器が作った木（`OwnershipPolicy::ChownInUserNamespace`）は、subuid 所有の
/// inode を含み、ホストの実効 uid では `chmod`・`read_dir`・`unlink` が `EPERM` / `EACCES` になる。
/// `SubordinateIds` のときは、削除を子プロセスの user namespace（コンテナ 0 → 自 euid、1.. → subordinate 範囲。
/// start と pull の展開が共有する `SubordinateIdSource` の写像）の中で行う。
///
/// 呼び出し元: create は [`crate::oci_runtime::ContainerImage::with_rootfs_privilege`]（記録の
/// `imageRootfs.ownership` にも反映）、delete は [`crate::oci_runtime::DeleteOptions`]、展開途中の回収は
/// [`ReapOptions`] で渡す。既定は `HostEffectiveIds`（従来の挙動）。CLI / CRI / supervisor からの配線は
/// #2315・#2243 の範囲で未実装（REPAIR-3）。Linux 以外は `HostEffectiveIds` だけ（作成自体が `Unimplemented`）。
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum ImageRootfsPrivilege {
    /// ホストの実効 ID で消す（既定）。
    #[default]
    HostEffectiveIds,
    /// subuid / subgid の範囲を含む user namespace の中で消す。
    #[cfg(target_os = "linux")]
    SubordinateIds(SubordinateIdSource),
}

impl ImageRootfsPrivilege {
    /// create が記録に残す、木の所有者の種別。
    pub(super) fn ownership(&self) -> ImageRootfsOwnership {
        match self {
            Self::HostEffectiveIds => ImageRootfsOwnership::HostIds,
            #[cfg(target_os = "linux")]
            Self::SubordinateIds(_) => ImageRootfsOwnership::SubordinateIds,
        }
    }
}

/// 既定の権限（ホストの実効 ID）。記録がホスト所有なら、呼び出し元の権限に依らずこれで消す。
pub(super) static HOST_PRIVILEGE: ImageRootfsPrivilege = ImageRootfsPrivilege::HostEffectiveIds;

/// [`reap_stale_unpacks_with`] の設定（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ReapOptions {
    privilege: ImageRootfsPrivilege,
}

impl ReapOptions {
    /// 既定の設定（ホストの実効 ID）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 木を消す権限を指定する（subuid 所有の展開途中の木を回収する場合は `SubordinateIds`）。
    pub fn with_privilege(mut self, privilege: ImageRootfsPrivilege) -> Self {
        self.privilege = privilege;
        self
    }
}

/// [`ImageRootfsUnpacker::unpack`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImageRootfsUnpacked {
    /// 展開したレイヤーの数。
    pub layers: usize,
}

/// 持ち主のいない展開途中の木の回収結果（#2379・OCI-7）。各一覧は名前の昇順で決定的。
///
/// 名前だけを持ち、パスや OS のエラー文字列は含めない。呼び出し元（create の記録・起動時の照合）が
/// 構造化ログへ出す。`kept_*` と `failed` は「消さずに残した」もので、余分に残すだけの安全側。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StagingReclamation {
    /// 回収（削除）できた木の名前。
    pub reclaimed: Vec<std::ffi::OsString>,
    /// ロックが取れず、生きている create が持つと判断して残した木。
    pub kept_alive: Vec<std::ffi::OsString>,
    /// 種別・所有者・同一性・ロックのいずれかを確かめられず残した木。
    pub kept_unverified: Vec<std::ffi::OsString>,
    /// `kept_unverified` と同じ並び（名前の昇順）で、確かめられなかった理由（REPAIR-4・#2540）。
    pub kept_unverified_reasons: Vec<UnverifiedReason>,
    /// 回収を試みて削除に失敗した木（一部が消えて残っていることがある）。
    pub failed: Vec<std::ffi::OsString>,
    /// 走査の上限で打ち切り、残りを調べなかったか。
    pub truncated: bool,
    /// 親ディレクトリの列挙そのものに失敗した（`read_dir` の失敗・列挙中のエラー）か。
    /// 失敗した範囲に木が残っていても見えないため、回収は不完全として扱う（REPAIR-4）。
    pub scan_failed: bool,
}

/// 展開途中の木を「持ち主がいない」と確かめられず残した理由（REPAIR-4・#2540）。
///
/// 残した木は余分に持つだけの安全側だが、恒久に残り続けると見えないため、理由を観測できるようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnverifiedReason {
    /// リンクなどディレクトリでない実体だった。
    NotDirectory,
    /// 所有者が実効 uid（権限が許せば subuid の範囲）ではなかった。
    Owner,
    /// ロックを取った後に開き直した実体が、検査した実体と一致しなかった。
    Identity,
    /// ロックの取得で `WouldBlock` 以外の失敗をした。
    LockError,
    /// 開く・検査する段階で失敗した。
    Open,
}

impl StagingReclamation {
    /// 何かを回収した・残した・失敗した・打ち切ったか（記録に値するか）。
    pub fn is_noteworthy(&self) -> bool {
        !(self.reclaimed.is_empty()
            && self.kept_alive.is_empty()
            && self.kept_unverified.is_empty()
            && self.failed.is_empty())
            || self.truncated
            || self.scan_failed
    }

    /// 回収が完全でなかったか（消せなかった・確かめられなかった・打ち切った・走査に失敗した。
    /// 生きている木は含めない）。
    pub fn is_incomplete(&self) -> bool {
        !(self.kept_unverified.is_empty() && self.failed.is_empty())
            || self.truncated
            || self.scan_failed
    }
}

/// イメージのレイヤーを rootfs へ展開する（OCI-7・#2342）。
///
/// 契約:
///
/// - `rootfs` は core が作った、存在する空のディレクトリ（Unix は実行ユーザー所有の 0700）を指す経路。oci の
///   `extract_*` の「root は呼び出し側が排他的に所有する既存の空ディレクトリ」と一致する
/// - Linux では、`rootfs` は core が保持するディレクトリ fd を指す `/proc/self/fd/N`（bundle 配下の経路ではない）で、
///   最終要素が symlink（magic link）である。作成後に bundle 内の中間ディレクトリを symlink へ差し替えられても、
///   展開先は固定したディレクトリのままで bundle 外へ書かない（SEC-1）。展開器は `rootfs` を開くとき
///   最終要素の symlink を辿ること（`O_NOFOLLOW` を付けて開かない）。以降の要素は `rootfs` 配下を fd 相対・
///   リンク非追従で扱うこと。この経路は展開の呼び出しの間だけ有効で、保持・保存してはならない
///   （Linux 以外は作成の前に `Unimplemented` で拒否されるため、この経路は渡されない）
/// - 展開中の rootfs は、Linux では最終の `root.path` とは別の非公開の名前（core 専有のラッパーディレクトリの
///   子）にあり、展開の成功後に core が最終の名前へ公開する（展開中に別の create が rootfs を使用中と見なして
///   成功する競合を防ぐ。OCI-7・#2635）
/// - 展開器は `rootfs` 自体を作り直したり別の場所へ移したりしない
/// - 失敗時に部分的な展開物を残してよい。後始末は core が行う
/// - イメージストアの排他は blob パスの解決に必要な間だけ取り、展開の全体にわたっては保持しない
///   （呼び出し元が参照を登録済みで、GC から blob は守られる。REPAIR-5）
/// - 展開量・件数の上限を必ず課す（無制限の展開をしない）
/// - digest・diff_id の検証、mediaType の選択、所有者の写像、特殊ビットの扱いは実装側の責務
/// - エラーメッセージにパス・OS のエラー文字列を含めない
pub trait ImageRootfsUnpacker {
    /// `manifest` のレイヤーを下位から順に `rootfs` へ展開する。
    fn unpack(
        &self,
        manifest: &ImageManifestDigest,
        rootfs: &Path,
    ) -> Result<ImageRootfsUnpacked, TraitError>;
}

/// core が排他的に作った rootfs ディレクトリ（展開途中の後始末の対象）。
///
/// Linux では作成時に検証した親ディレクトリの fd を保持し、作成・展開先の指定・公開・後始末を `mkdirat` /
/// `renameat2` / `unlinkat` 等の fd 相対・リンク非追従の操作だけで行う（作成後に親を symlink へ差し替えられても
/// bundle 外に作用しない）。展開は非公開の名前で行い、成功後に [`CreatedRootfs::publish`] で最終の名前へ
/// 改名する。Linux 以外（macOS 等の Unix・Windows）は fd 相対の操作が未実装で、経路を再解決する
/// 後始末は差し替えで bundle 外を消しうるため、作成の前に `Unimplemented` で拒否する（fail-closed。何も作らないので展開物は残らない。REPAIR-3）。
#[derive(Debug)]
pub(super) struct CreatedRootfs {
    path: PathBuf,
    /// bundle 相対の正規化済みの経路（Normal 要素だけ。[`CreatedRootfs::record`] が状態へ記録する）。
    relative: PathBuf,
    backing: imp::Backing,
    // 読むのは Linux の試験だけ（本番の読み手は #2315 の配線で追加する。REPAIR-3）。それ以外の構成では未使用になる。
    #[cfg_attr(
        not(all(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "reclamation is read only by Linux tests until the #2315 wiring"
        )
    )]
    reclamation: StagingReclamation,
}

/// [`remove_recorded_rootfs`] の結果（将来の拡張に備え非網羅）。
// Linux 以外は削除経路が常に `Unimplemented` で拒否するため、各 variant は Linux でしか構築されない。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RecordedRootfsRemoval {
    /// 記録の実体を消した。
    Removed,
    /// 既に無かった（どの段でも `ENOENT`）。冪等な再実行として成功扱いにする。
    NotPresent,
}

fn invalid(message: &str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

fn refuse() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "rootfs was replaced; refusing to remove",
    )
}

#[cfg(target_os = "linux")]
fn remove_failed() -> TraitError {
    TraitError::new(ErrorCode::Internal, "failed to remove rootfs")
}

/// `root.path` を検査し、bundle 配下の Normal 要素だけの列（親の要素 + 末尾の要素）へ分解する。
///
/// 規則: `..`・予約名・ファイルシステムのルート・bundle 外の絶対指定・bundle そのものを拒否する。
/// `prepare_rootfs_target` と [`reap_stale_unpacks`] が共有する。
fn split_target(bundle: &Path, root_path: &Path) -> Result<Vec<std::ffi::OsString>, TraitError> {
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid("root.path must not contain '..'"));
    }
    if has_staging_component(root_path) {
        return Err(invalid("root.path must not use a reserved staging name"));
    }
    let rootfs = bundle.join(root_path);
    if !rootfs
        .components()
        .any(|c| matches!(c, Component::Normal(_)))
    {
        return Err(invalid("rootfs must not be the filesystem root"));
    }
    let rel = rootfs
        .strip_prefix(bundle)
        .map_err(|_| invalid("rootfs must be inside the bundle"))?;
    let parts: Vec<std::ffi::OsString> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_os_string()),
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        return Err(invalid("rootfs must be a directory below the bundle"));
    }
    Ok(parts)
}

/// `root.path` の経路を検査し、末尾の要素を空のディレクトリとして排他的に作る。
///
/// `check_rootfs` と同じ規則（`..`・ファイルシステムのルート・bundle 外の絶対指定・中間要素の
/// symlink / junction を拒否）に加え、末尾が既に存在すれば `AlreadyExists` で拒否して利用者の既存データへ
/// 展開しない。相対部分が空（rootfs が bundle そのもの）は拒否する。作成の前に、同じ親の下の持ち主のいない
/// 展開途中の木を回収する（結果は [`CreatedRootfs::reclamation`]。#2379・OCI-7）。
#[cfg(test)]
pub(super) fn prepare_rootfs_target(
    bundle: &Path,
    root_path: &Path,
) -> Result<CreatedRootfs, TraitError> {
    prepare_rootfs_target_with(bundle, root_path, &HOST_PRIVILEGE, &|reap| reap())
}

/// 回収の実処理を包む関数。回収を呼んだ結果をそのまま返す。
pub(super) type ReapHook<'a> = &'a dyn Fn(&dyn Fn() -> StagingReclamation) -> StagingReclamation;

/// [`prepare_rootfs_target`] の本体。`reap_hook` は回収の実処理（走査と再帰削除）を引数に取って呼ぶ関数で、
/// 呼び出し元が計測区間で包める（その後の作成が失敗しても、回収の結果と所要時間を記録できる。REPAIR-4）。
pub(super) fn prepare_rootfs_target_with(
    bundle: &Path,
    root_path: &Path,
    privilege: &ImageRootfsPrivilege,
    reap_hook: ReapHook<'_>,
) -> Result<CreatedRootfs, TraitError> {
    let parts = split_target(bundle, root_path)?;
    let Some((last, parents)) = parts.split_last() else {
        return Err(invalid("rootfs must be a directory below the bundle"));
    };
    let parents: Vec<&std::ffi::OsStr> = parents.iter().map(|p| p.as_os_str()).collect();
    let (backing, reclamation) = imp::create_dir(bundle, &parents, last, privilege, reap_hook)?;
    // 正規化した（Normal 要素だけの）経路。
    let path = parts.iter().fold(bundle.to_path_buf(), |mut p, part| {
        p.push(part);
        p
    });
    let relative = parts.iter().collect::<PathBuf>();
    Ok(CreatedRootfs {
        path,
        relative,
        backing,
        reclamation,
    })
}

/// `root.path` の親の下に残った、持ち主のいない展開途中の木（`.fandhe-unpack-*`）を回収する（#2379・OCI-7）。
///
/// 起動時の照合（#2315 の配線。`reconcile_container_refs` と並べ、`StateStore::list` で列挙した bundle ごとに
/// 呼ぶ想定。配線は未実装で、本関数は呼ばれるまで何も回収しない。REPAIR-3）の入口。生きている create
/// （ロックを保持中の木）は壊さず、いつ呼んでもよい。経路検査は `prepare_rootfs_target` と同じで、
/// 回収は固定した親の fd の下だけで行う。回収の失敗はエラーにせず結果へ記録する。
/// Linux 以外は `Unimplemented`。
pub fn reap_stale_unpacks(
    bundle: &Path,
    root_path: &Path,
) -> Result<StagingReclamation, TraitError> {
    let parts = split_target(bundle, root_path)?;
    let Some((_, parents)) = parts.split_last() else {
        return Err(invalid("rootfs must be a directory below the bundle"));
    };
    let parents: Vec<&std::ffi::OsStr> = parents.iter().map(|p| p.as_os_str()).collect();
    imp::reap_stale(bundle, &parents, &HOST_PRIVILEGE)
}

/// [`reap_stale_unpacks`] に、結果の記録（REPAIR-4）を足したもの。起動時の照合用の入口（#2540）。
///
/// 回収の結果を `recorder` へ、従来の `image_rootfs_reap`（成功 / 失敗）に加え、残した木・消せなかった木・
/// 打ち切り・走査の失敗を **1 件ずつ** 失敗として記録する（`image_rootfs_reap_kept_unverified` 等）。
/// `options` の権限が `SubordinateIds` なら、subuid 所有の木も userns の中で回収する（SEC-5）。
/// `OpRecorder::snapshot` の失敗数が件数として読めるので、恒久に `Unverified` のまま残る木を見落とさない。
pub fn reap_stale_unpacks_with(
    bundle: &Path,
    root_path: &Path,
    options: &ReapOptions,
    recorder: &OpRecorder,
) -> Result<StagingReclamation, TraitError> {
    let started = std::time::Instant::now();
    let parts = split_target(bundle, root_path)?;
    let Some((_, parents)) = parts.split_last() else {
        return Err(invalid("rootfs must be a directory below the bundle"));
    };
    let parents: Vec<&std::ffi::OsStr> = parents.iter().map(|p| p.as_os_str()).collect();
    let reclamation = imp::reap_stale(bundle, &parents, &options.privilege)?;
    record_staging_reclamation(recorder, &reclamation, started.elapsed());
    Ok(reclamation)
}

/// 展開途中の木の回収結果を記録する（`create_with_image` と [`reap_stale_unpacks_with`] が共有。REPAIR-4）。
///
/// 何も無ければ記録しない。消せなかった・確かめられなかった・打ち切った・走査に失敗したものがあれば
/// `image_rootfs_reap` を失敗として記録し（create 自体は失敗させない）、内訳を 1 件ずつ別の操作名で
/// 失敗として記録する。
pub(super) fn record_staging_reclamation(
    recorder: &OpRecorder,
    reclamation: &StagingReclamation,
    elapsed: std::time::Duration,
) {
    if !reclamation.is_noteworthy() {
        return;
    }
    let outcome = if reclamation.is_incomplete() {
        OpOutcome::Failure
    } else {
        OpOutcome::Success
    };
    let record = |name: &str, outcome: OpOutcome, elapsed: std::time::Duration| {
        if let Ok(name) = OpName::new(name) {
            let _ = recorder.record(&name, outcome, elapsed);
        }
    };
    record(IMAGE_ROOTFS_REAP_OP_NAME, outcome, elapsed);
    let none = std::time::Duration::ZERO;
    for _ in &reclamation.kept_unverified {
        record(REAP_KEPT_UNVERIFIED_OP_NAME, OpOutcome::Failure, none);
    }
    for _ in &reclamation.failed {
        record(REAP_FAILED_OP_NAME, OpOutcome::Failure, none);
    }
    if reclamation.truncated {
        record(REAP_TRUNCATED_OP_NAME, OpOutcome::Failure, none);
    }
    if reclamation.scan_failed {
        record(REAP_SCAN_FAILED_OP_NAME, OpOutcome::Failure, none);
    }
}

/// 公開済みで状態の無い rootfs（孤児）の回収結果（REPAIR-4・#2540）。
// Linux 以外は孤児が生じず `NotPresent` しか構築されない。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum OrphanReap {
    /// 最終の名前に何も無かった（回収する物が無い）。
    NotPresent,
    /// 孤児と確かめて消した。
    Reclaimed,
    /// ツリーのロックを他が持つ（生きている create）ため残した。
    Alive,
    /// bundle の所有ロックを他が持つ（delete・状態作成の最中）ため残した。
    Held,
    /// 印・所有者・同一性・状態の照合のいずれかを確かめられず残した。
    Unverified,
    /// 回収を試みて削除に失敗した（一部が消えて残っていることがある）。
    Failed,
    /// 印の状態ルートの識別子が現在のストアと一致しない（別の状態ルートの木かもしれない）、印が識別子を持たない
    /// （v2）、またはストアが状態ルートを示せないため残した（#2635・OCI-5。fail-closed）。
    ForeignStateRoot,
}

/// `root.path` の最終の名前に公開済みの rootfs があり、状態を持たない孤児と確かめられれば消す（#2540・OCI-7）。
///
/// 呼び出し元は `create_with_image` の展開先の作成の前。公開後・状態作成前のクラッシュ、delete が状態を
/// 消した後の rootfs 削除の失敗、状態の喪失で残った木が、同じ bundle の次の create を `AlreadyExists` で
/// 塞ぎ続けないようにする。消すのは次のすべてを満たすときだけで、どれかを確かめられなければ残す（OCI-7:
/// 誤るときは余分に残す側だけ）。
///
/// 1. bundle の所有ロックを取れる（delete・通常の create の状態作成と排他。保持中は `Held`）
/// 2. 最終の名前がリンクでないディレクトリで、親と同じマウント
/// 3. 木のディレクトリの `flock` が取れる（`WouldBlock` は生きている create。`Alive`）
/// 4. 印のファイルが v3 形式で、所有者が実効 uid・mode 0400・nlink 1・通常ファイル、かつ印の (dev, ino) が
///    木の実体と一致する（`cp -a` での複製や利用者のデータを消さない）
/// 5. 印の状態ルートの識別子（[`state_root_scope`]）が `store` の識別子と一致する。不一致・v2 の印・`store` が
///    状態ルートを示せない（`host_state_root` が `None`）ときは消さず `ForeignStateRoot`（別の状態ルートの
///    コンテナが使う rootfs を、`store` に見えないことを理由に孤児と取り違えない。#2635・OCI-5）
/// 6. `store` の全レコードに、印のトークンを持つものも、同じ bundle を指すものも無い（一覧の失敗・打ち切りは
///    確かめられないので残す）
///
/// 別の状態ルート（`--root` 違い）のコンテナが同じ bundle の rootfs を共有する構成は支援しない。core 製の木に
/// ついては 5. で消さずに残す。通常の create が core 製の木を `root.path` で採用した構成は検出できない
/// （`docs/design/image-rootfs-lifetime.md`）。Linux 以外は常に `NotPresent`（作成が `Unimplemented`）。
pub(super) fn reap_published_orphan(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    bundle: &Path,
    root_path: &Path,
    privilege: &ImageRootfsPrivilege,
) -> OrphanReap {
    let started = std::time::Instant::now();
    let outcome = imp::reap_published_orphan(store, bundle, root_path, privilege);
    let result = match outcome {
        OrphanReap::NotPresent | OrphanReap::Alive => None,
        OrphanReap::Reclaimed => Some(OpOutcome::Success),
        OrphanReap::Held
        | OrphanReap::Unverified
        | OrphanReap::Failed
        | OrphanReap::ForeignStateRoot => Some(OpOutcome::Failure),
    };
    if let Some(result) = result
        && let Ok(name) = OpName::new(IMAGE_ROOTFS_ORPHAN_REAP_OP_NAME)
    {
        let _ = recorder.record(&name, result, started.elapsed());
    }
    outcome
}

/// 状態ルートの識別子（印 v3 の 3 行目。#2635・OCI-5）。
///
/// `store.host_state_root()` の絶対パスのバイト列の SHA-256 の先頭 128 bit を小文字 16 進 32 文字にしたもの。
/// 印はコンテナの `/` から見えるため、生のパスは書かない。(dev, ino) でなくパスにしたのは、tmpfs の状態ルートが
/// 再起動をまたいで一致しなくなり、正当な孤児の回収が退行するのを避けるため。パスの表記が変わる（symlink 経由・
/// 移設）と別の状態ルート扱いになり、孤児の回収は木を残す側に倒れる。ストアが状態ルートを示せない（`None`）ときは
/// `None`。`create::unpack_rootfs` が `seal` へ渡し、孤児の回収が現在のストアの値と照合する。
pub(super) fn state_root_scope(store: &dyn StateStore) -> Option<String> {
    store.host_state_root().map(scope_of)
}

/// [`state_root_scope`] の本体（状態ルートのパス → 識別子）。
fn scope_of(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// 経路のいずれかの要素が非公開の展開先の予約名（[`STAGING_PREFIX`] 始まり）か。
pub(super) fn has_staging_component(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(p) => p.to_string_lossy().starts_with(STAGING_PREFIX),
        _ => false,
    })
}

impl CreatedRootfs {
    /// 作った rootfs のパス（bundle 配下。Normal 要素だけの正規化済みの経路）。
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// 作成の前に同じ親の下で回収した、持ち主のいない展開途中の木の結果（#2379・OCI-7）。
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn reclamation(&self) -> &StagingReclamation {
        &self.reclamation
    }

    /// 展開器へ渡す経路（[`ImageRootfsUnpacker::unpack`] の契約）。Linux は保持した fd を指す
    /// `/proc/self/fd/N`、それ以外は [`Self::path`] と同じ。
    pub(super) fn unpack_path(&self) -> PathBuf {
        imp::unpack_path(&self.path, &self.backing)
    }

    /// 展開済みの rootfs を最終の名前（`root.path`）へ公開する。公開後は他の create が rootfs として見る。
    ///
    /// Linux は固定した親の下で `renameat2(RENAME_NOREPLACE)` により改名し、最終の名前が既にあれば
    /// `AlreadyExists`（置き換えない）。Linux 以外は作成自体が拒否されるため到達しない。
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn publish(&mut self) -> Result<(), TraitError> {
        self.publish_with(&HOST_PRIVILEGE)
    }

    /// [`Self::publish`] に権限を指定したもの。子 rootfs が subuid 所有で権限が `SubordinateIds` なら、改名を
    /// userns の中で行う（rootless の `./` が root 以外の所有のとき。OCI-7・SEC-5・#2690）。
    pub(super) fn publish_with(
        &mut self,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        imp::publish(&mut self.backing, privilege)
    }

    /// 最終の名前への改名が済んでいるか。`publish` が Err でも true なら公開済みで、他の create が
    /// 使いうるため後始末で消してはならない（OCI-7）。
    pub(super) fn is_published(&self) -> bool {
        imp::is_published(&self.backing)
    }

    /// `path`（bundle の検証で得た最終の rootfs の経路）を今解決した実体が、展開した実体か（dev・ino）。
    ///
    /// 展開中に bundle の途中の要素が別名へ移され、同じ文字列の別ディレクトリに差し替わっていないかの確認。
    pub(super) fn is_unpacked_at(&self, path: &Path) -> bool {
        imp::path_is_unpacked(path, &self.backing)
    }

    /// 公開済みの rootfs を、状態レコードへ残す記録にする（契約 13。OCI-7・#2378）。
    ///
    /// 経路は bundle 相対の正規化済みのもの、同一性は作成時に固定した実体の (dev, ino)。delete が
    /// [`remove_recorded_rootfs`] で「作ったときと同じ実体」だけを消すための印になる。Linux 以外は作成自体が
    /// 拒否されるため到達しない（`Unimplemented`）。
    pub(super) fn record(&self) -> Result<ImageRootfsRecord, TraitError> {
        let (dev, ino) = imp::identity(&self.backing)?;
        let token = imp::token(&self.backing)?;
        ImageRootfsRecord::new(self.relative.clone(), dev, ino)?.with_token(token)
    }

    /// 展開後・公開前に、作成世代を区別する所有トークンを rootfs 直下の印のファイルへ書く（OCI-7・#2378）。
    ///
    /// 展開済みの木に同名のファイルがあれば（イメージ由来の偽の印を採用しない）`AlreadyExists` で拒否する。
    ///
    /// `state_root_scope` は [`state_root_scope`] の識別子（印 v3 の 3 行目。`None` なら v2 を書き、孤児の回収は
    /// この木を残す。#2635・OCI-5）。
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn seal(&mut self, state_root_scope: Option<&str>) -> Result<(), TraitError> {
        self.seal_with(state_root_scope, &HOST_PRIVILEGE)
    }

    /// [`Self::seal`] に権限を指定したもの。子 rootfs が subuid 所有で権限が `SubordinateIds` なら、印の書き込みを
    /// userns の中で行う（OCI-7・SEC-5・#2690）。
    pub(super) fn seal_with(
        &mut self,
        state_root_scope: Option<&str>,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        imp::seal(&mut self.backing, state_root_scope, privilege)
    }

    /// rootfs を消す。
    ///
    /// 作成時に固定した親（Linux は fd）の下で、末尾が作ったときと同じディレクトリ（dev・ino）で
    /// なければ削除しない（`FailedPrecondition`。差し替えられた先 = bundle 外の実体を消さない fail-closed）。
    /// Linux 以外は同一性を保証できないため常に `FailedPrecondition` で拒否する。
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn remove(self) -> Result<(), TraitError> {
        self.remove_with(&HOST_PRIVILEGE)
    }

    /// [`Self::remove`] に、木を消す権限を指定したもの（subuid 所有の木は userns の中で消す。SEC-5・#2540）。
    pub(super) fn remove_with(self, privilege: &ImageRootfsPrivilege) -> Result<(), TraitError> {
        imp::remove(&self.path, self.backing, privilege)
    }
}

/// 状態レコードに記録された rootfs を消す（delete が状態削除の成功後に呼ぶ。OCI-7・OCI-5・#2378）。
///
/// 呼び出し元は `oci_runtime::delete`。`bundle` はレコードの bundle、`rec` は create が記録した経路と実体の
/// 同一性。bundle は作成時と同じく追従して開き、記録の経路は中間要素をリンク非追従の fd 相対で辿る。
/// 末尾が記録の (dev, ino) と一致するディレクトリのときだけ中身ごと消す。symlink・ディレクトリでないもの・
/// 同一性の不一致は `FailedPrecondition` で拒否し何も消さない（fail-closed）。どの段でも `ENOENT` なら
/// [`RecordedRootfsRemoval::NotPresent`]。Linux 以外は同一性を保証できないため `Unimplemented`。
#[cfg(all(test, target_os = "linux"))]
pub(super) fn remove_recorded_rootfs(
    bundle: &Path,
    rec: &ImageRootfsRecord,
) -> Result<RecordedRootfsRemoval, TraitError> {
    remove_recorded_rootfs_with(bundle, rec, &HOST_PRIVILEGE)
}

/// [`remove_recorded_rootfs`] に、木を消す権限を指定したもの（SEC-5・#2540）。
///
/// 記録の `ownership` が `SubordinateIds`（subuid 所有の inode を含む）なのに `privilege` が
/// `HostEffectiveIds` のときは、ホストの ID では消せないので木に触れず `FailedPrecondition` で拒否する
/// （部分削除で印だけ消える順序依存を避ける）。ホスト所有の記録は、権限に依らず従来どおりホストの ID で消す。
pub(super) fn remove_recorded_rootfs_with(
    bundle: &Path,
    rec: &ImageRootfsRecord,
    privilege: &ImageRootfsPrivilege,
) -> Result<RecordedRootfsRemoval, TraitError> {
    imp::remove_recorded(bundle, rec, privilege)
}

#[cfg(target_os = "linux")]
mod imp {
    //! Linux: 親ディレクトリの fd を保持して fd 相対・リンク非追従で作成・後始末する。

    use std::ffi::{CString, OsStr, OsString};
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, ImageRootfsRecord, MARKER_MAX_BYTES,
        ORPHAN_SCAN_MAX_PAGES, ORPHAN_SCAN_PAGE_SIZE, OrphanReap, RecordedRootfsRemoval,
        STAGING_PREFIX, StagingReclamation, UnverifiedReason, invalid, refuse, remove_failed,
    };
    use super::{
        HOST_PRIVILEGE, ImageRootfsPrivilege, USERNS_FINALIZE_BUDGET, USERNS_REMOVE_BUDGET,
    };
    use crate::exec::{
        ChildExit, IsolationConfig, Namespace, NamespaceSet, isolate_rootless_subordinate,
        plan_rootless_subordinate, wait_forked_child,
    };
    use crate::oci_runtime::launch::BundleLock;
    use crate::oci_runtime::launcher::SubordinateIdSource;
    use crate::rootless::IdMapSet;
    use crate::sys::{self, SysError};
    use crate::traits::{
        ErrorCode, ImageRootfsOwnership, ListStateRequest, StateStore, TraitError,
    };

    /// 非公開の展開先の名前の連番（同一プロセス内の衝突を避ける。別プロセスとは pid で分ける）。
    static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 展開先のラッパー（予約名のディレクトリ）の下の、展開器に渡す子の名前（#2635）。
    ///
    /// ラッパーは core 専有（0700・実効 uid 所有）で展開器へ渡さない。イメージが所有者や mode を変えられるのは
    /// 子だけなので、回収側が判定するラッパーの所有者は崩れない。子の名前自体は予約名ではないが、ラッパーが予約名
    /// なので `root.path` から子へは到達できない（`has_staging_component` が拒否する）。
    const STAGING_CHILD: &str = "rootfs";

    /// 検証済みの親ディレクトリの fd と、その下の rootfs の名前・同一性。
    ///
    /// 作成直後は rootfs が親の下の非公開のラッパー `wrapper_name` の子 [`STAGING_CHILD`] にあり、`publish` で
    /// 最終の名前 `final_name` へ改名する（その後、空のラッパーは best effort で消す）。
    #[derive(Debug)]
    pub(super) struct Backing {
        parent: OwnedFd,
        final_name: CString,
        wrapper_name: CString,
        /// 非公開のラッパーディレクトリの fd・同一性（未公開の後始末はラッパーごと消す）。
        wrapper: OwnedFd,
        wrapper_identity: (u64, u64),
        /// 最終の名前への改名が済んだか。
        published: bool,
        /// 作った rootfs ディレクトリ（ラッパーの子）そのものの fd（展開器へ `/proc/self/fd/N` で渡す）。
        dir: OwnedFd,
        identity: (u64, u64),
        /// `seal` が書いた所有トークン（小文字 16 進 32 文字）。
        token: Option<String>,
        /// 展開先（子）のディレクトリ自体への排他の `flock`。公開後も状態作成まで保持し、孤児の回収から
        /// 「持ち主あり」に見せる。プロセスが落ちれば OS が外す（#2379・OCI-7）。
        _lock: File,
        /// ラッパーへの排他の `flock`。展開途中の回収から「持ち主あり」に見せる。
        _wrapper_lock: File,
    }

    /// 削除時に照合する所有トークンの扱い。
    #[derive(Clone, Copy)]
    enum Owner<'a> {
        /// 自分が作った直後の木の後始末（トークンを照合しない）。
        Unchecked,
        /// 記録のトークンと照合する。`None`（記録欠落）は拒否する。
        Token(Option<&'a str>),
    }

    pub(super) fn token(b: &Backing) -> Result<String, TraitError> {
        b.token.clone().ok_or_else(|| {
            TraitError::new(ErrorCode::Internal, "rootfs owner token is not written")
        })
    }

    /// OS の乱数から 128 bit のトークンを作り、小文字 16 進 32 文字にする。
    fn new_token() -> Result<String, TraitError> {
        use std::io::Read;
        let mut buf = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to create rootfs token"))?;
        Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// 子が実効 uid 所有でない（rootless で `./` が subuid 所有）ときの、ホストでは改名できないことの明示エラー。
    fn foreign_root_err() -> TraitError {
        TraitError::new(
            ErrorCode::Internal,
            "failed to publish rootfs: cannot make unpacked root writable for rename (owned by another uid)",
        )
    }

    /// seal / publish の実行場所（[`finalize_route`] の結果）。
    #[derive(Debug)]
    pub(super) enum FinalizeRoute<'a> {
        /// ホストの実効 uid で行う。`foreign` は子が別 uid 所有（失敗時に明示エラーへ読み替える）。
        Host { foreign: bool },
        /// 子プロセスの user namespace の中で行う（子が subuid 所有で、権限が `SubordinateIds`。#2690）。
        Userns(&'a SubordinateIdSource),
    }

    /// 子 rootfs の所有者と権限から、seal / publish を行う場所を決める（純関数。OCI-7・SEC-5・#2690）。
    ///
    /// 所有者が実効 uid または不明なら従来どおりホスト（fork しない）。別 uid 所有で権限が `SubordinateIds` のときだけ
    /// userns の中で行う。`HostEffectiveIds` では暗黙に userns へ昇格せず、ホストで試して明示エラーで拒否する。
    pub(super) fn finalize_route<'a>(
        child_owner: Option<u32>,
        euid: u32,
        privilege: &'a ImageRootfsPrivilege,
    ) -> FinalizeRoute<'a> {
        let foreign = child_owner.is_some_and(|o| o != euid);
        match (foreign, privilege) {
            (true, ImageRootfsPrivilege::SubordinateIds(source)) => FinalizeRoute::Userns(source),
            _ => FinalizeRoute::Host { foreign },
        }
    }

    /// seal の失敗（userns の子の終了コードの語彙と 1 対 1）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SealFailure {
        Stat,
        Exists,
        Widen,
        Write,
        Restore,
    }

    const SEAL_OK: i32 = 0;
    const SEAL_EXISTS: i32 = 30;
    const SEAL_WIDEN_FAILED: i32 = 31;
    const SEAL_WRITE_FAILED: i32 = 32;
    const SEAL_RESTORE_FAILED: i32 = 33;
    const SEAL_STAT_FAILED: i32 = 34;

    impl SealFailure {
        fn code(self) -> i32 {
            match self {
                Self::Stat => SEAL_STAT_FAILED,
                Self::Exists => SEAL_EXISTS,
                Self::Widen => SEAL_WIDEN_FAILED,
                Self::Write => SEAL_WRITE_FAILED,
                Self::Restore => SEAL_RESTORE_FAILED,
            }
        }

        /// 失敗の写し方。`foreign` なら書き込み系の失敗は原因が分かる明示エラーにする。
        fn into_error(self, foreign: bool) -> TraitError {
            match self {
                Self::Stat => TraitError::new(ErrorCode::Internal, "failed to stat rootfs"),
                Self::Exists => TraitError::new(
                    ErrorCode::AlreadyExists,
                    "rootfs owner marker already exists",
                ),
                Self::Widen | Self::Write if foreign => foreign_root_err(),
                Self::Widen | Self::Write => {
                    TraitError::new(ErrorCode::Internal, "failed to write rootfs owner token")
                }
                Self::Restore => {
                    TraitError::new(ErrorCode::Internal, "failed to restore rootfs mode")
                }
            }
        }
    }

    /// fd の指す rootfs の mode を一時的に補って印を書き、成功・失敗のどちらでも元の mode へ戻す。
    ///
    /// ホストの `seal` と、userns の子（#2690）の両方が呼ぶ。展開器は rootfs 自身の mode を変えてよい（契約は
    /// 禁止していない）ので、所有者の write・search 権限が無いと印を作れず従来成功した create が失敗する
    /// 退行になる。`/proc/self/fd/N` は経路を再解決しない。
    fn write_marker_widened(dir: BorrowedFd<'_>, content: &str) -> Result<(), SealFailure> {
        let proc_dir = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let original = fstat(dir)
            .map(|(_, _, _, mode)| mode & 0o7777)
            .map_err(|_| SealFailure::Stat)?;
        let widened = original | 0o300;
        if widened != original {
            std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(widened))
                .map_err(|_| SealFailure::Widen)?;
        }
        let written = write_marker(&proc_dir, content).map_err(|e| match e.code() {
            ErrorCode::AlreadyExists => SealFailure::Exists,
            _ => SealFailure::Write,
        });
        if widened != original {
            let restored =
                std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(original));
            written?;
            restored.map_err(|_| SealFailure::Restore)?;
        } else {
            written?;
        }
        Ok(())
    }

    /// userns の子の実行が親へ返すエラー（固定語彙）。
    #[derive(Debug, PartialEq, Eq)]
    enum UsernsRunError {
        MultiThreaded,
        Timeout,
        Other(ErrorCode),
    }

    impl UsernsRunError {
        fn into_error(self) -> TraitError {
            match self {
                Self::MultiThreaded => TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "cannot finalize a subordinate-owned rootfs in a user namespace",
                ),
                Self::Timeout => TraitError::new(
                    ErrorCode::Timeout,
                    "finalizing a subordinate-owned rootfs timed out",
                ),
                Self::Other(code) => TraitError::new(
                    code,
                    "failed to finalize a subordinate-owned rootfs in a user namespace",
                ),
            }
        }
    }

    /// 子プロセスの user namespace（User のみ・holder / mapper 方式。#2374）の中で `child` を実行し、終了コードを返す。
    ///
    /// seal / publish（#2690）が使う。親は期限つきで待ち、超えたら kill して回収する（REPAIR-5）。呼び出しプロセスが
    /// マルチスレッドなら fork の検査が拒否する（CRI / tokio 経路の子プロセス方式の配線は #2315 の範囲）。
    fn run_in_userns(
        source: &SubordinateIdSource,
        child: impl FnOnce() -> i32,
    ) -> Result<i32, UsernsRunError> {
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let inputs = source
            .removal_inputs(euid, egid)
            .map_err(|e| UsernsRunError::Other(e.code()))?;
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let helper_timeout = inputs.timeout;
        let plan = plan_rootless_subordinate(
            &config,
            inputs.uid,
            inputs.gid,
            inputs.writer,
            helper_timeout,
        )
        .map_err(|e| UsernsRunError::Other(e.code))?;
        let pid = sys::fork_single_threaded(
            || {
                if isolate_rootless_subordinate(&plan).is_err() {
                    return CHILD_SETUP_FAILED;
                }
                child()
            },
            CHILD_SETUP_FAILED,
        )
        .map_err(|e| match e {
            SysError::MultiThreaded => UsernsRunError::MultiThreaded,
            _ => UsernsRunError::Other(ErrorCode::Internal),
        })?;
        let budget =
            helper_timeout * 3 + std::time::Duration::from_secs(5) + USERNS_FINALIZE_BUDGET;
        match wait_forked_child(pid, budget) {
            Ok(ChildExit::Exited(code)) => Ok(code),
            Err(e) if e.code == ErrorCode::Timeout => Err(UsernsRunError::Timeout),
            _ => Err(UsernsRunError::Other(ErrorCode::Internal)),
        }
    }

    /// userns の中の seal の結果を親の結果へ写す（純関数）。
    fn seal_outcome(run: Result<i32, UsernsRunError>) -> Result<(), TraitError> {
        match run {
            Ok(SEAL_OK) => Ok(()),
            Ok(SEAL_EXISTS) => Err(SealFailure::Exists.into_error(true)),
            Ok(SEAL_WIDEN_FAILED) => Err(SealFailure::Widen.into_error(true)),
            Ok(SEAL_WRITE_FAILED) => Err(SealFailure::Write.into_error(true)),
            Ok(SEAL_RESTORE_FAILED) => Err(SealFailure::Restore.into_error(true)),
            Ok(SEAL_STAT_FAILED) => Err(SealFailure::Stat.into_error(true)),
            Ok(_) => Err(TraitError::new(
                ErrorCode::Internal,
                "failed to write rootfs owner token",
            )),
            Err(e) => Err(e.into_error()),
        }
    }

    pub(super) fn seal(
        b: &mut Backing,
        scope: Option<&str>,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        if scope.is_some_and(|s| !is_hex32(s)) {
            return Err(TraitError::new(
                ErrorCode::Internal,
                "invalid state root scope",
            ));
        }
        let token = new_token()?;
        // v2: 1 行目 = トークン、2 行目 = 木の作成時の `<dev>:<ino>`。複製（`cp -a`）は inode が新しくなり
        // 2 行目が一致しないので、孤児の回収が利用者の複製を消さない（#2540）。
        // v3（#2635）: 3 行目 = 状態ルートの識別子。別の状態ルートの木を孤児の回収が消さない（OCI-5）。
        // 識別子が無いストアは v2 を書き、孤児の回収はその木を残す。
        let content = match scope {
            Some(scope) => format!("{token}\n{}:{}\n{scope}\n", b.identity.0, b.identity.1),
            None => format!("{token}\n{}:{}\n", b.identity.0, b.identity.1),
        };
        match finalize_route(fd_owner(b.dir.as_fd()), sys::effective_uid(), privilege) {
            FinalizeRoute::Host { foreign } => {
                write_marker_widened(b.dir.as_fd(), &content).map_err(|f| f.into_error(foreign))?;
            }
            FinalizeRoute::Userns(source) => {
                // 子が subuid 所有（#2690）。ホストの uid では mode の補完も印の作成もできないので、userns の中で
                // 行う。印はコンテナ 0 = ホストの実効 uid 所有・0400 で作られ、孤児の回収の厳格照合と整合する。
                let dir = b.dir.as_fd();
                let run = run_in_userns(source, || match write_marker_widened(dir, &content) {
                    Ok(()) => SEAL_OK,
                    Err(f) => f.code(),
                });
                seal_outcome(run)?;
            }
        }
        b.token = Some(token);
        Ok(())
    }

    /// 固定した rootfs（`proc_dir`）の直下へ所有トークンの印を新規作成して書く。
    fn write_marker(proc_dir: &str, content: &str) -> Result<(), TraitError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = format!("{proc_dir}/{}", super::OWNER_TOKEN_FILE);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(sys::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    TraitError::new(
                        ErrorCode::AlreadyExists,
                        "rootfs owner marker already exists",
                    )
                } else {
                    TraitError::new(ErrorCode::Internal, "failed to write rootfs owner token")
                }
            })?;
        f.write_all(content.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to write rootfs owner token")
            })?;
        Ok(())
    }

    /// 印のファイルの内容（#2378 の v1 = トークンのみ、#2540 の v2 = トークン + 作成時の (dev, ino)、
    /// #2635 の v3 = v2 + 状態ルートの識別子）。
    pub(super) struct Marker {
        pub(super) token: String,
        /// v2 以降が持つ、木の作成時の実体の (dev, ino)。v1 は `None`。
        pub(super) identity: Option<(u64, u64)>,
        /// v3 だけが持つ、状態ルートの識別子（小文字 16 進 32 文字）。v1・v2 は `None`。
        pub(super) scope: Option<String>,
    }

    /// 小文字 16 進ちょうど 32 文字か（トークン・状態ルートの識別子の形式）。
    fn is_hex32(v: &str) -> bool {
        v.len() == 32 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// 印の内容を厳密に解析する（16 進と 10 進だけ。長さは呼び出し側が [`MARKER_MAX_BYTES`] で制限済み）。
    pub(super) fn parse_marker(buf: &[u8]) -> Option<Marker> {
        let text = std::str::from_utf8(buf).ok()?;
        let mut lines = text.split('\n');
        let token = lines.next()?;
        if !is_hex32(token) {
            return None;
        }
        let Some(second) = lines.next() else {
            return Some(Marker {
                token: token.to_owned(),
                identity: None,
                scope: None,
            });
        };
        let (dev, ino) = second.split_once(':')?;
        let num = |v: &str| {
            (!v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
                .then(|| v.parse::<u64>().ok())
                .flatten()
        };
        // 2 行目の後は、v2 なら空（末尾の改行）だけ、v3 なら識別子の行と空だけで、それ以外は拒否する。
        let scope = match lines.next()? {
            "" => None,
            third if is_hex32(third) => {
                if lines.next() != Some("") {
                    return None;
                }
                Some(third.to_owned())
            }
            _ => return None,
        };
        if lines.next().is_some() {
            return None;
        }
        Some(Marker {
            token: token.to_owned(),
            identity: Some((num(dev)?, num(ino)?)),
            scope,
        })
    }

    /// 固定した rootfs の fd 直下の印のファイルを読む（リンク非追従・通常ファイルのみ・FIFO で止まらない）。
    ///
    /// `strict` のときは、孤児の回収の証拠として所有者が実効 uid・mode 0400・nlink 1 も要求する
    /// （利用者が置いた別のファイルを印と見なさない。#2540）。
    fn read_marker(root: BorrowedFd<'_>, strict: bool) -> Option<Marker> {
        use std::io::Read;
        // 先に `O_PATH|O_NOFOLLOW` で実体を固定し、fstat で通常ファイルと確かめてから、固定済みの fd を
        // 読み取りで開き直す。種別確認が open より前のため、デバイス・FIFO への差し替えでも open の
        // 副作用（端末の取得・ブロック）が起きない（SEC-1）。
        let name = CString::new(super::OWNER_TOKEN_FILE).ok()?;
        let pinned = sys::open_path_nofollow_at(root, &name).ok()?;
        let meta = File::from(pinned.as_fd().try_clone_to_owned().ok()?)
            .metadata()
            .ok()?;
        // S_IFMT = 0o170000・S_IFREG = 0o100000。
        if meta.mode() & 0o170_000 != 0o100_000 {
            return None;
        }
        if strict
            && (meta.uid() != sys::effective_uid()
                || meta.nlink() != 1
                || meta.mode() & 0o7777 != 0o400)
        {
            return None;
        }
        let fd = sys::reopen_pinned_read_nonblock(pinned.as_fd()).ok()?;
        let f = File::from(fd);
        if !f
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() <= MARKER_MAX_BYTES)
        {
            return None;
        }
        let mut buf = Vec::new();
        f.take(MARKER_MAX_BYTES + 1).read_to_end(&mut buf).ok()?;
        parse_marker(&buf)
    }

    /// 固定した rootfs の fd 直下の印のファイルのトークンが `expected` と一致するか（v1・v2・v3 のすべてを受ける）。
    fn token_matches(root: BorrowedFd<'_>, expected: &str) -> bool {
        read_marker(root, false).is_some_and(|m| m.token == expected)
    }

    pub(super) fn unpack_path(_path: &Path, b: &Backing) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", b.dir.as_raw_fd()))
    }

    /// 改名の失敗（userns の子の終了コードの語彙と 1 対 1）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PublishFailure {
        Stat,
        Widen,
        Exists,
        Rename,
        /// 改名には成功したが、mode を戻せなかった。
        RestoreAfterRename,
    }

    const PUB_RENAMED: i32 = 0;
    const PUB_EXISTS: i32 = 20;
    const PUB_WIDEN_FAILED: i32 = 21;
    const PUB_RENAME_FAILED: i32 = 22;
    const PUB_RESTORE_FAILED: i32 = 23;
    const PUB_STAT_FAILED: i32 = 24;

    impl PublishFailure {
        fn code(self) -> i32 {
            match self {
                Self::Stat => PUB_STAT_FAILED,
                Self::Widen => PUB_WIDEN_FAILED,
                Self::Exists => PUB_EXISTS,
                Self::Rename => PUB_RENAME_FAILED,
                Self::RestoreAfterRename => PUB_RESTORE_FAILED,
            }
        }

        fn into_error(self) -> TraitError {
            match self {
                Self::Stat => TraitError::new(ErrorCode::Internal, "failed to stat rootfs"),
                Self::Widen => foreign_root_err(),
                Self::Exists => TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists"),
                Self::Rename => TraitError::new(ErrorCode::Internal, "failed to publish rootfs"),
                Self::RestoreAfterRename => {
                    TraitError::new(ErrorCode::Internal, "failed to restore rootfs mode")
                }
            }
        }
    }

    /// 子 rootfs を最終の名前へ `RENAME_NOREPLACE` で改名する。ホストと userns の子（#2690）の両方が呼ぶ。
    ///
    /// 別のディレクトリの下へ移すには、移すディレクトリ自身への write 権限が要る（`..` の付け替え。同じ親の下の
    /// 改名では要らなかった）。展開器は rootfs 自身の mode を変えてよい（例: 0555）ので、write が無ければ固定した
    /// fd の実体（`/proc/self/fd/N` は経路を再解決しない）の mode を一時的に補い、改名の後に戻す。
    fn rename_widened(b: &Backing) -> Result<(), PublishFailure> {
        let child = cstr(OsStr::new(STAGING_CHILD)).map_err(|_| PublishFailure::Rename)?;
        let proc_dir = format!("/proc/self/fd/{}", b.dir.as_raw_fd());
        let original = fstat(b.dir.as_fd())
            .map(|(_, _, _, mode)| mode & 0o7777)
            .map_err(|_| PublishFailure::Stat)?;
        let widened = original | 0o200;
        if widened != original {
            std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(widened))
                .map_err(|_| PublishFailure::Widen)?;
        }
        let renamed =
            sys::rename_noreplace_at(b.wrapper.as_fd(), &child, b.parent.as_fd(), &b.final_name);
        if widened != original {
            let restored =
                std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(original));
            // 改名に成功していれば公開済みとして扱い、戻せなかったことだけを報告する。
            if renamed.is_ok() && restored.is_err() {
                return Err(PublishFailure::RestoreAfterRename);
            }
        }
        renamed.map_err(|e| match e {
            SysError::Os(n) if n == sys::EEXIST || n == sys::ENOTEMPTY => PublishFailure::Exists,
            _ => PublishFailure::Rename,
        })
    }

    /// 最終の名前が、展開した実体（dev・ino）を指しているか。改名は原子的なので、これが公開済みの判定になる。
    fn observe_published(b: &Backing) -> bool {
        open_dir(b.parent.as_fd(), &b.final_name)
            .ok()
            .and_then(|fd| fstat(fd.as_fd()).ok())
            .is_some_and(|(dev, ino, is_dir, _)| is_dir && (dev, ino) == b.identity)
    }

    /// userns の中の改名の結果を `(公開済みか, 結果)` へ写す（純関数）。
    ///
    /// 公開済みかは終了コードではなく観測（`observed`）で決める。期限切れで kill した場合も、改名が済んでいれば
    /// 公開済みとして残す（OCI-7 の使用中 rootfs の保持。create は公開済みの木を消さない）。
    fn publish_outcome(
        run: Result<i32, UsernsRunError>,
        observed: bool,
    ) -> (bool, Result<(), TraitError>) {
        if observed {
            // 公開済みの観測が保証するのは改名が済んだことだけで、mode の復元までは保証しない。
            // 子が改名の後・復元の前に止まった場合（期限切れの kill・異常終了）に成功を装わない（fail-closed）。
            // 公開済みの木は消さず（published = true）、エラーで返す。
            return match run {
                Ok(PUB_RENAMED) => (true, Ok(())),
                Ok(PUB_RESTORE_FAILED) | Ok(_) => {
                    (true, Err(PublishFailure::RestoreAfterRename.into_error()))
                }
                Err(e) => (true, Err(e.into_error())),
            };
        }
        let err = match run {
            Ok(PUB_EXISTS) => PublishFailure::Exists.into_error(),
            Ok(PUB_WIDEN_FAILED) => PublishFailure::Widen.into_error(),
            Ok(PUB_STAT_FAILED) => PublishFailure::Stat.into_error(),
            // 改名したと言うのに最終の名前が展開した実体を指さない。成功を装わない。
            Ok(PUB_RENAMED) => refuse(),
            Ok(_) => PublishFailure::Rename.into_error(),
            Err(e) => e.into_error(),
        };
        (false, Err(err))
    }

    pub(super) fn publish(
        b: &mut Backing,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        if b.published {
            return Ok(());
        }
        match finalize_route(fd_owner(b.dir.as_fd()), sys::effective_uid(), privilege) {
            FinalizeRoute::Host { .. } => match rename_widened(b) {
                Ok(()) => {}
                Err(PublishFailure::RestoreAfterRename) => {
                    b.published = true;
                    return Err(PublishFailure::RestoreAfterRename.into_error());
                }
                Err(f) => return Err(f.into_error()),
            },
            FinalizeRoute::Userns(source) => {
                // 子が subuid 所有（#2690）。ホストの uid では mode の補完も改名もできないので userns の中で行う。
                // 子が触れるのは固定済みの fd と固定の 2 つの名前だけで、経路を再解決しない。
                let run = run_in_userns(source, || match rename_widened(b) {
                    Ok(()) => PUB_RENAMED,
                    Err(f) => f.code(),
                });
                let observed = observe_published(b);
                let (published, result) = publish_outcome(run, observed);
                if published {
                    b.published = true;
                    let _ = sys::remove_dir_at(b.parent.as_fd(), &b.wrapper_name);
                }
                return result;
            }
        }
        b.published = true;
        // 空になったラッパーは best effort で消す（消し損ねても、次の回収が予約名の空の木として拾う）。
        let _ = sys::remove_dir_at(b.parent.as_fd(), &b.wrapper_name);
        // 改名した先を固定済みの親から開き直し、展開した実体（保持中の fd の dev・ino）と一致することを確認する。
        // 一致しなければ公開した名前は別の実体を指しており、成功を装わず拒否する。
        if observe_published(b) {
            Ok(())
        } else {
            Err(refuse())
        }
    }

    /// 最終の名前への改名が済んでいるか。
    pub(super) fn is_published(b: &Backing) -> bool {
        b.published
    }

    pub(super) fn path_is_unpacked(path: &Path, b: &Backing) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == b.identity)
    }

    fn cstr(s: &OsStr) -> Result<CString, TraitError> {
        CString::new(s.as_bytes()).map_err(|_| invalid("rootfs path contains a NUL byte"))
    }

    /// `parent` 配下の `name` をリンク非追従のディレクトリとして開く。
    fn open_dir(parent: BorrowedFd<'_>, name: &CString) -> Result<OwnedFd, TraitError> {
        sys::open_dir_path_nofollow(Some(parent), name).map_err(|e| match e {
            SysError::Os(n) if n == sys::ENOTDIR || n == sys::ELOOP => {
                invalid("rootfs must not contain a symlink or a non-directory")
            }
            SysError::Os(n) if n == sys::ENOENT => {
                TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
            }
            SysError::Os(n) if n == sys::EACCES || n == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot access rootfs")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to open rootfs directory"),
        })
    }

    /// bundle を開く。最終要素の symlink は辿るが、ディレクトリ以外は open の時点で拒否する
    /// （FIFO への差し替えで delete がブロックしない。OCI-7・SEC-1）。
    fn open_bundle(bundle: &Path) -> Result<OwnedFd, SysError> {
        let c =
            CString::new(bundle.as_os_str().as_bytes()).map_err(|_| SysError::Os(sys::EINVAL))?;
        sys::open_dir_path_follow(&c)
    }

    /// fd の指す実体の (dev, ino, ディレクトリか, mode)。fd は複製して `File` として fstat する。
    fn fstat(fd: BorrowedFd<'_>) -> Result<(u64, u64, bool, u32), std::io::Error> {
        let file = File::from(fd.try_clone_to_owned()?);
        let m = file.metadata()?;
        Ok((m.dev(), m.ino(), m.is_dir(), m.mode()))
    }

    /// fd の指す実体の所有者 uid。
    fn fd_owner(fd: BorrowedFd<'_>) -> Option<u32> {
        let file = File::from(fd.try_clone_to_owned().ok()?);
        file.metadata().ok().map(|m| m.uid())
    }

    /// fd の指すディレクトリが空か（`/proc/self/fd/N` 経由で列挙。読めなければ空と見なさない）。
    fn dir_is_empty(fd: BorrowedFd<'_>) -> bool {
        std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .is_ok_and(|mut it| it.next().is_none())
    }

    /// 展開先の走査の上限（これを超える兄弟は調べずに残す。無制限の走査を避ける。REPAIR-5）。
    const REAP_MAX_SCAN: usize = 4096;

    /// bundle を開き、`parents` を 1 要素ずつリンク非追従で辿って親ディレクトリの fd を返す。
    fn open_parent(bundle: &Path, parents: &[&OsStr]) -> Result<OwnedFd, TraitError> {
        // bundle そのものは呼び出し側が渡した経路（上位が symlink でもよい）。追従して開き、以降は fd で固定する。
        let mut cur = open_bundle(bundle).map_err(|e| match e {
            SysError::Os(n) if n == sys::ENOENT => {
                TraitError::new(ErrorCode::NotFound, "bundle directory not found")
            }
            SysError::Os(n) if n == sys::ENOTDIR => invalid("bundle is not a directory"),
            SysError::Os(n) if n == sys::EACCES || n == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot access bundle")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to open bundle"),
        })?;
        for part in parents {
            cur = open_dir(cur.as_fd(), &cstr(part)?)?;
        }
        Ok(cur)
    }

    pub(super) fn reap_stale(
        bundle: &Path,
        parents: &[&OsStr],
        privilege: &ImageRootfsPrivilege,
    ) -> Result<StagingReclamation, TraitError> {
        let cur = open_parent(bundle, parents)?;
        Ok(reap_under(cur.as_fd(), privilege))
    }

    /// 名前が `.fandhe-unpack-<pid>-<seq>`（pid は 1〜10 桁・seq は 1〜20 桁の 10 進数）に厳密に一致するか。
    fn is_staging_name(name: &[u8]) -> bool {
        let Some(rest) = name.strip_prefix(STAGING_PREFIX.as_bytes()) else {
            return false;
        };
        let mut it = rest.splitn(2, |b| *b == b'-');
        let (Some(pid), Some(seq)) = (it.next(), it.next()) else {
            return false;
        };
        let digits = |v: &[u8], max: usize| {
            !v.is_empty() && v.len() <= max && v.iter().all(|b| b.is_ascii_digit())
        };
        digits(pid, 10) && digits(seq, 20)
    }

    /// 親 `cur`（固定済みの fd）の下の、持ち主のいない展開途中の木を回収する。結果は名前の昇順。
    fn reap_under(cur: BorrowedFd<'_>, privilege: &ImageRootfsPrivilege) -> StagingReclamation {
        let policy = OwnerPolicy::new(privilege);
        let mut result = StagingReclamation::default();
        let Ok(rd) = std::fs::read_dir(format!("/proc/self/fd/{}", cur.as_raw_fd())) else {
            result.scan_failed = true;
            return result;
        };
        let mut names: Vec<OsString> = Vec::new();
        for (scanned, ent) in rd.enumerate() {
            if scanned >= REAP_MAX_SCAN {
                result.truncated = true;
                break;
            }
            let Ok(ent) = ent else {
                result.scan_failed = true;
                continue;
            };
            let name = ent.file_name();
            if is_staging_name(name.as_bytes()) {
                names.push(name);
            }
        }
        names.sort();
        for name in names {
            match reap_one(cur, &name, &policy, privilege) {
                Reap::Reclaimed => result.reclaimed.push(name),
                Reap::Alive => result.kept_alive.push(name),
                Reap::Unverified(reason) => {
                    result.kept_unverified.push(name);
                    result.kept_unverified_reasons.push(reason);
                }
                Reap::Failed => result.failed.push(name),
                Reap::Gone => {}
            }
        }
        result
    }

    enum Reap {
        Reclaimed,
        Alive,
        Unverified(UnverifiedReason),
        Failed,
        /// 調べている間に消えた（別の回収側が先に消した）。
        Gone,
    }

    /// 1 つの候補を調べ、持ち主がいないと確かめられたときだけ消す（確かめられなければ残す）。
    ///
    /// 証拠は予約名の正規表現・実効 uid 所有・`flock` が取れること・ロック中の同一性の再確認である。
    /// mode は証拠にしない: userns の中の展開器はイメージの `./` の項目で展開先の root の mode を変えうる
    /// （例: 0755）ため、0700 を要求するとクラッシュした展開の木が恒久に `Unverified` になる。消すのは
    /// マウントを跨がずリンクも辿らない再帰削除なので、他人が足したハードリンクを消しても相手のデータは
    /// 消えない（#2540）。
    fn reap_one(
        cur: BorrowedFd<'_>,
        name: &OsStr,
        policy: &OwnerPolicy,
        privilege: &ImageRootfsPrivilege,
    ) -> Reap {
        let Ok(cname) = cstr(name) else {
            return Reap::Unverified(UnverifiedReason::Open);
        };
        let fd = match sys::open_dir_path_nofollow(Some(cur), &cname) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => return Reap::Gone,
            // 予約名の位置にリンクやディレクトリでない実体があると、`O_DIRECTORY | O_NOFOLLOW` が ENOTDIR / ELOOP。
            Err(SysError::Os(n)) if n == sys::ENOTDIR || n == sys::ELOOP => {
                return Reap::Unverified(UnverifiedReason::NotDirectory);
            }
            Err(_) => return Reap::Unverified(UnverifiedReason::Open),
        };
        let identity = match fstat(fd.as_fd()) {
            Ok((dev, ino, true, _)) => {
                if !fd_owner(fd.as_fd()).is_some_and(|uid| policy.allows(uid)) {
                    return Reap::Unverified(UnverifiedReason::Owner);
                }
                (dev, ino)
            }
            Ok(_) => return Reap::Unverified(UnverifiedReason::NotDirectory),
            Err(_) => return Reap::Unverified(UnverifiedReason::Open),
        };
        // O_PATH の fd には flock できないため、`/proc/self/fd/N` から開き直したディレクトリにロックを掛ける。
        let lock = match File::open(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
            Ok(lock) => lock,
            // 展開途中で落ちた subuid 所有の木は mode 0700 のことがあり、ホストの実効 uid では開けない
            // （EACCES）。権限が `SubordinateIds` なら、ロック取得・同一性の再確認・削除を userns の子の中で
            // 続けて行う（子は固定済みの親 fd を継承し、ロックは子の終了まで保持される。#2540・SEC-5）。
            Err(e)
                if e.raw_os_error() == Some(sys::EACCES)
                    && matches!(privilege, ImageRootfsPrivilege::SubordinateIds(_)) =>
            {
                return reap_in_userns(privilege, cur, &cname, identity);
            }
            Err(_) => return Reap::Unverified(UnverifiedReason::LockError),
        };
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Reap::Alive,
            Err(_) => return Reap::Unverified(UnverifiedReason::LockError),
        }
        // ロックを保持したまま名前から開き直し、検査した実体と同じことを確かめる（差し替え・別の回収側の
        // 取り直しを弾く）。ロックはこの関数を出るまで保持する。
        match sys::open_dir_path_nofollow(Some(cur), &cname) {
            Ok(again) => match fstat(again.as_fd()) {
                Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
                _ => return Reap::Unverified(UnverifiedReason::Identity),
            },
            Err(SysError::Os(n)) if n == sys::ENOENT => return Reap::Gone,
            Err(_) => return Reap::Unverified(UnverifiedReason::Identity),
        }
        match remove_tree_priv(privilege, cur, &cname, identity, Owner::Unchecked) {
            Ok(_) => Reap::Reclaimed,
            Err(_) => Reap::Failed,
        }
    }

    /// ホストの実効 uid ではロックを取れない subuid 所有の木を、userns の子の中で回収する。
    fn reap_in_userns(
        privilege: &ImageRootfsPrivilege,
        cur: BorrowedFd<'_>,
        cname: &CString,
        identity: (u64, u64),
    ) -> Reap {
        let ImageRootfsPrivilege::SubordinateIds(source) = privilege else {
            return Reap::Unverified(UnverifiedReason::LockError);
        };
        match userns_run(source, cur, cname, identity, Owner::Unchecked, true) {
            Ok(UsernsOutcome::Removed) => Reap::Reclaimed,
            Ok(UsernsOutcome::NotPresent) => Reap::Gone,
            Ok(UsernsOutcome::Alive) => Reap::Alive,
            Ok(UsernsOutcome::LockError) => Reap::Unverified(UnverifiedReason::LockError),
            Ok(UsernsOutcome::Identity) => Reap::Unverified(UnverifiedReason::Identity),
            Err(_) => Reap::Failed,
        }
    }

    /// 公開済みの最終の名前の検査結果。
    enum Probe {
        Gone,
        Alive,
        Unverified,
        /// 印の状態ルートの識別子が現在のストアと一致しない・無い（#2635）。
        ForeignStateRoot,
        Orphan(Orphan),
    }

    /// 孤児と確かめた木（ロックを保持している間は他の回収側・create から「持ち主あり」に見える）。
    struct Orphan {
        identity: (u64, u64),
        token: String,
        _lock: File,
    }

    /// 親 `cur`（固定済みの fd）の下の最終の名前 `cname` が、孤児の条件（[`super::reap_published_orphan`] の
    /// 2〜5）を満たすかを調べる。`expected_scope` は現在のストアの状態ルートの識別子。
    fn inspect_published(
        cur: BorrowedFd<'_>,
        cname: &CString,
        expected_scope: Option<&str>,
    ) -> Probe {
        let fd = match sys::open_dir_path_nofollow(Some(cur), cname) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => return Probe::Gone,
            Err(_) => return Probe::Unverified,
        };
        let identity = match fstat(fd.as_fd()) {
            Ok((dev, ino, true, _)) => (dev, ino),
            _ => return Probe::Unverified,
        };
        // 親と別のマウント（マウントポイント・bind mount）の木は消さない。
        let Some(mnt) = mount_id(fd.as_fd()) else {
            return Probe::Unverified;
        };
        if mount_id(cur) != Some(mnt) {
            return Probe::Unverified;
        }
        let Ok(lock) = File::open(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
            return Probe::Unverified;
        };
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Probe::Alive,
            Err(_) => return Probe::Unverified,
        }
        match sys::open_dir_path_nofollow(Some(cur), cname) {
            Ok(again) => match fstat(again.as_fd()) {
                Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
                _ => return Probe::Unverified,
            },
            Err(SysError::Os(n)) if n == sys::ENOENT => return Probe::Gone,
            Err(_) => return Probe::Unverified,
        }
        // 印は v2 以降（同一性つき）で、木の実体と一致するものだけを証拠にする。v1 や複製された印は残す。
        let Some(marker) = read_marker(fd.as_fd(), true) else {
            return Probe::Unverified;
        };
        if marker.identity != Some(identity) {
            return Probe::Unverified;
        }
        // 状態ルートの識別子が現在のストアと一致する木だけを孤児の候補にする（別の状態ルートのコンテナが
        // 使う rootfs は、このストアの一覧に見えないだけで孤児ではない。v2・識別子の無いストアも残す。#2635）。
        if !matches!((marker.scope.as_deref(), expected_scope), (Some(m), Some(e)) if m == e) {
            return Probe::ForeignStateRoot;
        }
        Probe::Orphan(Orphan {
            identity,
            token: marker.token,
            _lock: lock,
        })
    }

    /// `store` の全レコードを調べ、印のトークンを持つもの・同じ bundle を指すものがあるか。
    /// 一覧の失敗・ページ数の上限超過・bundle の同一性を確かめられない場合は `None`（不明。呼び出し側は残す）。
    fn store_references(store: &dyn StateStore, bundle: &Path, token: &str) -> Option<bool> {
        let bundle_meta = std::fs::metadata(bundle).ok()?;
        let page_size = std::num::NonZeroU32::new(ORPHAN_SCAN_PAGE_SIZE)?;
        let mut cursor = None;
        for _ in 0..ORPHAN_SCAN_MAX_PAGES {
            let mut req = ListStateRequest::new(page_size).ok()?;
            if let Some(c) = cursor.take() {
                req = req.with_cursor(c);
            }
            let page = store.list(&req).ok()?;
            for rec in page.records() {
                if rec.image_rootfs().and_then(ImageRootfsRecord::token) == Some(token) {
                    return Some(true);
                }
                if rec.bundle() == bundle {
                    return Some(true);
                }
                match std::fs::metadata(rec.bundle()) {
                    Ok(m) if (m.dev(), m.ino()) == (bundle_meta.dev(), bundle_meta.ino()) => {
                        return Some(true);
                    }
                    Ok(_) => {}
                    // 相手の bundle が無ければ別物。それ以外の失敗は判定不能として残す。
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return None,
                }
            }
            match page.next_cursor() {
                None => return Some(false),
                Some(c) => cursor = Some(c.clone()),
            }
        }
        None
    }

    pub(super) fn reap_published_orphan(
        store: &dyn StateStore,
        bundle: &Path,
        root_path: &Path,
        privilege: &ImageRootfsPrivilege,
    ) -> OrphanReap {
        // 経路の検査エラーは後続の `prepare_rootfs_target_with` が従来どおり報告する。ここでは回収しない。
        let Ok(parts) = super::split_target(bundle, root_path) else {
            return OrphanReap::NotPresent;
        };
        let Some((last, parents)) = parts.split_last() else {
            return OrphanReap::NotPresent;
        };
        let parents: Vec<&OsStr> = parents.iter().map(|p| p.as_os_str()).collect();
        let Ok(cur) = open_parent(bundle, &parents) else {
            return OrphanReap::NotPresent;
        };
        let Ok(cname) = cstr(last) else {
            return OrphanReap::NotPresent;
        };
        match sys::open_path_nofollow_at(cur.as_fd(), &cname) {
            Err(SysError::Os(n)) if n == sys::ENOENT => return OrphanReap::NotPresent,
            Err(_) => return OrphanReap::Unverified,
            Ok(_) => {}
        }
        // delete の後始末・通常の create の状態作成と排他する（回収の判定と削除の間だけ保持する）。
        let _bundle_lock = match BundleLock::acquire_resolved(bundle) {
            Ok(lock) => lock,
            Err(e) if e.code() == ErrorCode::FailedPrecondition => return OrphanReap::Held,
            Err(_) => return OrphanReap::Unverified,
        };
        let expected_scope = super::state_root_scope(store);
        let orphan = match inspect_published(cur.as_fd(), &cname, expected_scope.as_deref()) {
            Probe::Gone => return OrphanReap::NotPresent,
            Probe::Alive => return OrphanReap::Alive,
            Probe::Unverified => return OrphanReap::Unverified,
            Probe::ForeignStateRoot => return OrphanReap::ForeignStateRoot,
            Probe::Orphan(o) => o,
        };
        if store_references(store, bundle, &orphan.token) != Some(false) {
            return OrphanReap::Unverified;
        }
        match remove_tree_priv(
            privilege,
            cur.as_fd(),
            &cname,
            orphan.identity,
            Owner::Token(Some(&orphan.token)),
        ) {
            Ok(_) => OrphanReap::Reclaimed,
            Err(_) => OrphanReap::Failed,
        }
    }

    pub(super) fn create_dir(
        bundle: &Path,
        parents: &[&OsStr],
        last: &OsStr,
        privilege: &ImageRootfsPrivilege,
        reap_hook: super::ReapHook<'_>,
    ) -> Result<(Backing, StagingReclamation), TraitError> {
        let cur = open_parent(bundle, parents)?;
        // 同じ親の下に残った、持ち主のいない展開途中の木を先に回収する（PID の再利用による名前の衝突も解く）。
        let reclamation = reap_hook(&|| reap_under(cur.as_fd(), privilege));
        let final_name = cstr(last)?;
        // 最終の名前が既にあれば展開せずに拒否する（利用者の既存データへ展開しない。公開時の
        // `RENAME_NOREPLACE` が最終的な排他）。
        match sys::open_path_nofollow_at(cur.as_fd(), &final_name) {
            Ok(_) => {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "rootfs already exists",
                ));
            }
            Err(SysError::Os(n)) if n == sys::ENOENT => {}
            Err(_) => {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to create rootfs",
                ));
            }
        }
        let staging = format!(
            "{}{}-{}",
            super::STAGING_PREFIX,
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let wrapper_name = cstr(OsStr::new(&staging))?;
        // 展開先の名前が回収側に取られた場合の失敗（後始末はしない。持ち主は回収側。#2379）。
        let reclaimed_concurrently = || {
            TraitError::new(
                ErrorCode::Internal,
                "rootfs staging was reclaimed concurrently",
            )
        };
        // 1 段目: core 専有のラッパー（展開器へは渡さない。回収側が判定する名前）。
        let (wrapper, wrapper_identity) = make_private_dir(cur.as_fd(), &wrapper_name)?;
        // ラッパー自体に排他ロックを取る。取れない・取った後に名前の実体が変わっていれば、直前に回収側が
        // 空の木を取った（持ち主はその回収側）ので、後始末せず失敗する。再試行で成功する（#2379）。
        let wrapper_lock = lock_dir(wrapper.as_fd())?;
        if !same_dir(cur.as_fd(), &wrapper_name, wrapper_identity) {
            return Err(reclaimed_concurrently());
        }
        // 2 段目: 展開器に渡す子（#2635）。ラッパーのロックを保持しているので回収側は触れない。失敗はラッパーごと
        // 消す（まだ展開物は無い。空のラッパーと子だけ）。
        let child_name = cstr(OsStr::new(STAGING_CHILD))?;
        let cleanup_wrapper = |err: TraitError| {
            let _ = remove_tree_priv(
                privilege,
                cur.as_fd(),
                &wrapper_name,
                wrapper_identity,
                Owner::Unchecked,
            );
            err
        };
        let (dir, identity) = match make_private_dir(wrapper.as_fd(), &child_name) {
            Ok(v) => v,
            Err(e) => return Err(cleanup_wrapper(e)),
        };
        // 子のロックは公開後も状態作成まで保持する（孤児の回収が生きている create を見分ける）。
        let lock = match lock_dir(dir.as_fd()) {
            Ok(l) => l,
            Err(e) => return Err(cleanup_wrapper(e)),
        };
        if !same_dir(wrapper.as_fd(), &child_name, identity) {
            return Err(cleanup_wrapper(TraitError::new(
                ErrorCode::Internal,
                "created rootfs is not a directory",
            )));
        }
        Ok((
            Backing {
                parent: cur,
                final_name,
                wrapper_name,
                wrapper,
                wrapper_identity,
                published: false,
                dir,
                identity,
                token: None,
                _lock: lock,
                _wrapper_lock: wrapper_lock,
            },
            reclamation,
        ))
    }

    /// `parent` の下に `name` を 0700 のディレクトリとして排他的に作り、開いて返す。
    ///
    /// mkdirat と open の間に、親へ書ける別プロセスが別の実体へ差し替えうる。採用する実体は、自分（実効 uid）
    /// 所有・権限 0700・空のディレクトリに限る（既存データへ展開せず、失敗時の再帰削除が他人のデータに
    /// 及ばない）。0700（setgid 親の下の 02700 も許容）で自分の所有なら、検証後に他者は中身を足せない（root を除く）。
    fn make_private_dir(
        parent: BorrowedFd<'_>,
        name: &CString,
    ) -> Result<(OwnedFd, (u64, u64)), TraitError> {
        sys::mkdir_at(parent, name, 0o700).map_err(|e| match e {
            SysError::Os(n) if n == sys::EEXIST => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            SysError::Os(n) if n == sys::ENOENT || n == sys::ENOTDIR => {
                TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
            }
            SysError::Os(n) if n == sys::EACCES || n == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot create rootfs")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to create rootfs"),
        })?;
        let opened = open_dir(parent, name).ok().and_then(|fd| {
            fstat(fd.as_fd())
                .ok()
                .map(|(dev, ino, is_dir, _)| (fd, dev, ino, is_dir))
        });
        let owned_empty = opened.as_ref().is_some_and(|(fd, _, _, _)| {
            fstat(fd.as_fd()).is_ok_and(|(_, _, is_dir, mode)| is_dir && mode & 0o777 == 0o700)
                && fd_owner(fd.as_fd()) == Some(sys::effective_uid())
                && dir_is_empty(fd.as_fd())
        });
        match opened {
            Some((fd, dev, ino, true)) if owned_empty => Ok((fd, (dev, ino))),
            _ => {
                // 作った直後に差し替えられた。差し替えられた実体は自分のものと確認できないため消さない
                // （空ディレクトリでなければ `remove_dir_at` は失敗する。best effort で戻すのは空の場合だけ）。
                let _ = sys::remove_dir_at(parent, name);
                Err(TraitError::new(
                    ErrorCode::Internal,
                    "created rootfs is not a directory",
                ))
            }
        }
    }

    /// 固定したディレクトリ自体に排他の `flock` を取って返す（`try_lock` だけで待たない）。
    fn lock_dir(dir: BorrowedFd<'_>) -> Result<File, TraitError> {
        let lock = File::open(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to lock rootfs staging"))?;
        lock.try_lock().map_err(|_| {
            TraitError::new(
                ErrorCode::Internal,
                "rootfs staging was reclaimed concurrently",
            )
        })?;
        Ok(lock)
    }

    /// `parent` の下の `name` を今開き直した実体が、`identity` のディレクトリのままか。
    fn same_dir(parent: BorrowedFd<'_>, name: &CString, identity: (u64, u64)) -> bool {
        matches!(
            open_dir(parent, name).ok().and_then(|fd| fstat(fd.as_fd()).ok()),
            Some((dev, ino, true, _)) if (dev, ino) == identity
        )
    }

    pub(super) fn identity(b: &Backing) -> Result<(u64, u64), TraitError> {
        Ok(b.identity)
    }

    pub(super) fn remove(
        _path: &Path,
        b: Backing,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        // 既に無ければ消す物が無い（`NotPresent` も成功）。未公開ならラッパーごと、公開済みなら最終の名前の木を消す。
        let (name, identity) = if b.published {
            (&b.final_name, b.identity)
        } else {
            (&b.wrapper_name, b.wrapper_identity)
        };
        remove_tree_priv(
            privilege,
            b.parent.as_fd(),
            name,
            identity,
            Owner::Unchecked,
        )
        .map(|_| ())
    }

    /// `privilege` に従って木を消す。`HostEffectiveIds` はホストの ID で、`SubordinateIds` は子プロセスの
    /// user namespace の中で（subuid 所有の inode を消すため）消す。
    fn remove_tree_priv(
        privilege: &ImageRootfsPrivilege,
        parent: BorrowedFd<'_>,
        name: &CString,
        identity: (u64, u64),
        owner: Owner<'_>,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        match privilege {
            ImageRootfsPrivilege::SubordinateIds(source) => {
                remove_tree_in_userns(source, parent, name, identity, owner)
            }
            _ => remove_tree_at(parent, name, identity, owner),
        }
    }

    // userns の子の終了コード（固定語彙。パス・errno を親へ運ばない）。`EXIT_SETUP_FAILED`（125）と区別する。
    const CHILD_REMOVED: i32 = 0;
    const CHILD_NOT_PRESENT: i32 = 10;
    const CHILD_REFUSED: i32 = 11;
    const CHILD_FAILED: i32 = 12;
    const CHILD_SETUP_FAILED: i32 = 13;
    const CHILD_ALIVE: i32 = 14;
    const CHILD_LOCK_ERROR: i32 = 15;
    const CHILD_IDENTITY: i32 = 16;

    /// userns の子の結果（`lock_in_child` のときだけ `Alive` / `LockError` / `Identity` が出る）。
    enum UsernsOutcome {
        Removed,
        NotPresent,
        Alive,
        LockError,
        Identity,
    }

    /// subuid 所有の木を、子プロセスの user namespace の中で消す（SEC-5・CORE-6・#2540）。
    ///
    /// 子は呼び出し元が固定済みの親の fd・(dev, ino)・所有者照合をそのまま継承し（経路を再解決しないので
    /// TOCTOU の保証はホスト側と同じ）、`isolate_rootless_subordinate`（User namespace のみ。Mount は分けず
    /// `mnt_id` の照合を保つ。holder / mapper 方式で呼び出し側は dumpable にならない。#2374）で
    /// コンテナ 0 → 自 euid の ns に入ってから `remove_tree_at` を呼び、固定の終了コードで結果を返して
    /// `_exit` する。親は期限つきで待ち、超えたら kill して回収する（REPAIR-5）。
    ///
    /// 呼び出しプロセスがマルチスレッドなら fork の検査が拒否し、`FailedPrecondition` で木を残す
    /// （CRI / tokio 経路の子プロセス方式の配線は #2315 の範囲）。
    fn remove_tree_in_userns(
        source: &SubordinateIdSource,
        parent: BorrowedFd<'_>,
        name: &CString,
        identity: (u64, u64),
        owner: Owner<'_>,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        match userns_run(source, parent, name, identity, owner, false)? {
            UsernsOutcome::Removed => Ok(RecordedRootfsRemoval::Removed),
            UsernsOutcome::NotPresent => Ok(RecordedRootfsRemoval::NotPresent),
            _ => Err(remove_failed()),
        }
    }

    /// [`remove_tree_in_userns`] の本体。`lock_in_child` なら、子が userns に入った後で木に `flock` を取り、
    /// 名前から開き直した実体の同一性を再確認してから削除する（ホストの uid では開けない 0700 の木用）。
    fn userns_run(
        source: &SubordinateIdSource,
        parent: BorrowedFd<'_>,
        name: &CString,
        identity: (u64, u64),
        owner: Owner<'_>,
        lock_in_child: bool,
    ) -> Result<UsernsOutcome, TraitError> {
        let unavailable = |code: ErrorCode| {
            TraitError::new(
                code,
                "cannot remove a subordinate-owned rootfs in a user namespace",
            )
        };
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let inputs = source.removal_inputs(euid, egid)?;
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let helper_timeout = inputs.timeout;
        let plan = plan_rootless_subordinate(
            &config,
            inputs.uid,
            inputs.gid,
            inputs.writer,
            helper_timeout,
        )
        .map_err(|e| unavailable(e.code))?;
        let pid = sys::fork_single_threaded(
            || {
                if isolate_rootless_subordinate(&plan).is_err() {
                    return CHILD_SETUP_FAILED;
                }
                // ロックは子の終了（`_exit`）まで保持する。
                let _lock;
                if lock_in_child {
                    let Ok(fd) = sys::open_dir_path_nofollow(Some(parent), name) else {
                        return CHILD_LOCK_ERROR;
                    };
                    let Ok(lock) = File::open(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
                        return CHILD_LOCK_ERROR;
                    };
                    match lock.try_lock() {
                        Ok(()) => {}
                        Err(std::fs::TryLockError::WouldBlock) => return CHILD_ALIVE,
                        Err(_) => return CHILD_LOCK_ERROR,
                    }
                    _lock = lock;
                    match sys::open_dir_path_nofollow(Some(parent), name) {
                        Ok(again) => match fstat(again.as_fd()) {
                            Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
                            _ => return CHILD_IDENTITY,
                        },
                        Err(SysError::Os(n)) if n == sys::ENOENT => return CHILD_NOT_PRESENT,
                        Err(_) => return CHILD_IDENTITY,
                    }
                }
                match remove_tree_at(parent, name, identity, owner) {
                    Ok(RecordedRootfsRemoval::Removed) => CHILD_REMOVED,
                    Ok(RecordedRootfsRemoval::NotPresent) => CHILD_NOT_PRESENT,
                    Err(e) if e.code() == ErrorCode::FailedPrecondition => CHILD_REFUSED,
                    Err(_) => CHILD_FAILED,
                }
            },
            CHILD_SETUP_FAILED,
        )
        .map_err(|e| match e {
            SysError::MultiThreaded => unavailable(ErrorCode::FailedPrecondition),
            _ => unavailable(ErrorCode::Internal),
        })?;
        // 写像の書き込み（holder の待ちを含む最大 3 × 期限 + 5 秒）と削除の予算を合わせた期限。
        let budget = helper_timeout * 3 + std::time::Duration::from_secs(5) + USERNS_REMOVE_BUDGET;
        match wait_forked_child(pid, budget) {
            Ok(ChildExit::Exited(CHILD_REMOVED)) => Ok(UsernsOutcome::Removed),
            Ok(ChildExit::Exited(CHILD_NOT_PRESENT)) => Ok(UsernsOutcome::NotPresent),
            Ok(ChildExit::Exited(CHILD_ALIVE)) if lock_in_child => Ok(UsernsOutcome::Alive),
            Ok(ChildExit::Exited(CHILD_LOCK_ERROR)) if lock_in_child => {
                Ok(UsernsOutcome::LockError)
            }
            Ok(ChildExit::Exited(CHILD_IDENTITY)) if lock_in_child => Ok(UsernsOutcome::Identity),
            Ok(ChildExit::Exited(CHILD_REFUSED)) => Err(refuse()),
            Err(e) if e.code == ErrorCode::Timeout => Err(TraitError::new(
                ErrorCode::Timeout,
                "removing a subordinate-owned rootfs timed out",
            )),
            _ => Err(remove_failed()),
        }
    }

    /// 展開途中の木の所有者として受ける uid（実効 uid。権限が `SubordinateIds` なら subuid の範囲も）。
    struct OwnerPolicy {
        euid: u32,
        subordinate: Option<IdMapSet>,
    }

    impl OwnerPolicy {
        fn new(privilege: &ImageRootfsPrivilege) -> Self {
            let euid = sys::effective_uid();
            let subordinate = match privilege {
                ImageRootfsPrivilege::SubordinateIds(source) => source
                    .resolve_id_maps(euid, sys::effective_gid())
                    .ok()
                    .map(|m| m.uid().clone()),
                _ => None,
            };
            Self { euid, subordinate }
        }

        fn allows(&self, uid: u32) -> bool {
            uid == self.euid
                || self.subordinate.as_ref().is_some_and(|m| {
                    m.entries().iter().any(|e| {
                        let start = u64::from(e.host_id);
                        let end = start + u64::from(e.count);
                        (start..end).contains(&u64::from(uid))
                    })
                })
        }
    }

    /// 固定済みの `parent` の下の `name` を、(dev, ino) が `identity` と一致するときだけ中身ごと消す。
    /// 末尾はリンク非追従で開く。`ENOENT` は `NotPresent`、それ以外の開く失敗・種類や同一性の不一致は拒否する。
    fn remove_tree_at(
        parent: BorrowedFd<'_>,
        name: &CString,
        identity: (u64, u64),
        owner: Owner<'_>,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        let root = match sys::open_dir_path_nofollow(Some(parent), name) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => {
                return Ok(RecordedRootfsRemoval::NotPresent);
            }
            Err(_) => return Err(refuse()),
        };
        let (root_dev, root_mode) = match fstat(root.as_fd()) {
            Ok((dev, ino, true, mode)) if (dev, ino) == identity => (dev, mode & 0o7777),
            _ => return Err(refuse()),
        };
        // rootfs 自身がマウントポイントなら（親と別のマウント）マウント元を消さないよう拒否する。
        // 下位の bind mount は、再帰の各エントリを開くたびに `mnt_id` を照合して跨がない（検査後に足された
        // マウントも、経路の snapshot に依存せず fd の実体で拒否する。fail-closed）。
        let root_mnt = mount_id(root.as_fd()).ok_or_else(refuse)?;
        if mount_id(parent) != Some(root_mnt) {
            return Err(refuse());
        }
        // 作成世代の照合（inode の再利用で作り直された別のディレクトリを消さない）。記録欠落・不一致・
        // 印の欠落はいずれも拒否する（fail-closed）。
        if let Owner::Token(expected) = owner {
            // 展開器が rootfs 自身の mode から所有者の search 権限を外していると（`seal` は一時的に補って
            // 印を書く）、印を開けず正しい記録でも拒否してしまう。固定した fd の実体（`/proc/self/fd/N` は
            // 経路を再解決しない）の mode を一時的に補って照合し、不一致なら元の mode へ戻してから拒否する。
            // 一致すれば続く `remove_children` が中身ごと消すので戻さない。
            let proc_root = format!("/proc/self/fd/{}", root.as_raw_fd());
            let widened = root_mode | 0o100;
            if widened != root_mode {
                std::fs::set_permissions(&proc_root, std::fs::Permissions::from_mode(widened))
                    .map_err(|_| refuse())?;
            }
            if !expected.is_some_and(|t| token_matches(root.as_fd(), t)) {
                if widened != root_mode {
                    let _ = std::fs::set_permissions(
                        &proc_root,
                        std::fs::Permissions::from_mode(root_mode),
                    );
                }
                return Err(refuse());
            }
        }
        let mut seen = 0usize;
        remove_children(root.as_fd(), root_dev, root_mnt, 0, &mut seen)?;
        match sys::remove_dir_at(parent, name) {
            Ok(()) => Ok(RecordedRootfsRemoval::Removed),
            Err(SysError::Os(n)) if n == sys::ENOENT => Ok(RecordedRootfsRemoval::Removed),
            Err(_) => Err(remove_failed()),
        }
    }

    pub(super) fn remove_recorded(
        bundle: &Path,
        rec: &ImageRootfsRecord,
        privilege: &ImageRootfsPrivilege,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        // 記録が subuid 所有を示すのに権限が無ければ、ホストの ID では消せないので木に触れず拒否する。
        // ホスト所有の記録は、権限に依らずホストの ID で消す（不要な userns を作らない）。
        let effective = match (rec.ownership(), privilege) {
            (ImageRootfsOwnership::SubordinateIds, ImageRootfsPrivilege::SubordinateIds(_)) => {
                privilege
            }
            (ImageRootfsOwnership::SubordinateIds, _) => {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "rootfs is owned by subordinate ids; a subordinate id privilege is required",
                ));
            }
            _ => &HOST_PRIVILEGE,
        };
        // FIFO 等への差し替えでも open でブロックしない（`O_DIRECTORY`）。差し替えは拒否として扱う。
        let mut cur = match open_bundle(bundle) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => {
                return Ok(RecordedRootfsRemoval::NotPresent);
            }
            Err(SysError::Os(n)) if n == sys::ENOTDIR => return Err(refuse()),
            Err(_) => return Err(remove_failed()),
        };
        let mut parts = rec.relative_path().iter().peekable();
        while let Some(part) = parts.next() {
            let name = cstr(part)?;
            if parts.peek().is_none() {
                return remove_tree_priv(
                    effective,
                    cur.as_fd(),
                    &name,
                    rec.identity(),
                    Owner::Token(rec.token()),
                );
            }
            cur = match open_dir(cur.as_fd(), &name) {
                Ok(fd) => fd,
                // 中間の要素が無ければ rootfs も無い。
                Err(e) if e.code() == ErrorCode::NotFound => {
                    return Ok(RecordedRootfsRemoval::NotPresent);
                }
                // symlink・ディレクトリでないものへの差し替え（リンクは辿らない）。
                Err(e) if e.code() == ErrorCode::InvalidArgument => return Err(refuse()),
                Err(e) => return Err(e),
            };
        }
        // 空の経路は `ImageRootfsRecord::new` が拒否済みで到達しない。
        Err(refuse())
    }

    /// fd の属するマウント ID（fdinfo の `mnt_id`）。経路の文字列に依存せず、固定した fd の実体で判定する
    /// （改名・bind mount の別名・非 UTF-8 の名前の影響を受けない。SEC-1）。読めない場合は `None`。
    fn mount_id(fd: BorrowedFd<'_>) -> Option<u64> {
        crate::oci_runtime::mountinfo_identity::read_fd_mnt_id(fd).ok()
    }

    /// `dir`（固定済みの fd）の中身を、fd 相対・リンク非追従で再帰的に消す（件数・深さの上限つき）。
    ///
    /// 展開が適用した読み取り専用の mode は、ディレクトリごとに所有者の rwx を足して戻す。
    /// 列挙と chmod は `/proc/self/fd/N` 経由（magic link は fd の実体へ解決され、経路は再解決されない）。
    fn remove_children(
        dir: BorrowedFd<'_>,
        root_dev: u64,
        root_mnt: u64,
        depth: usize,
        seen: &mut usize,
    ) -> Result<(), TraitError> {
        if depth > CLEANUP_MAX_DEPTH {
            return Err(remove_failed());
        }
        let proc_path = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let (dev, _, is_dir, mode) = fstat(dir).map_err(|_| remove_failed())?;
        // 別ファイルシステム・別マウント（同一 FS の bind mount を含む）を跨がない。
        if !is_dir || dev != root_dev || mount_id(dir) != Some(root_mnt) {
            return Err(remove_failed());
        }
        if mode & 0o700 != 0o700 {
            std::fs::set_permissions(&proc_path, std::fs::Permissions::from_mode(mode | 0o700))
                .map_err(|_| remove_failed())?;
        }
        // 最上位の印のファイルは最後に消す。途中で失敗・期限切れになっても印が残り、次の孤児の回収が
        // 木を見分けられる（#2540）。
        let mut marker_deferred = false;
        for entry in std::fs::read_dir(&proc_path).map_err(|_| remove_failed())? {
            let entry = entry.map_err(|_| remove_failed())?;
            *seen += 1;
            if *seen > CLEANUP_MAX_ENTRIES {
                return Err(remove_failed());
            }
            if depth == 0 && entry.file_name() == OsStr::new(super::OWNER_TOKEN_FILE) {
                marker_deferred = true;
                continue;
            }
            remove_entry(dir, &entry.file_name(), root_dev, root_mnt, depth, seen)?;
        }
        if marker_deferred {
            remove_entry(
                dir,
                OsStr::new(super::OWNER_TOKEN_FILE),
                root_dev,
                root_mnt,
                depth,
                seen,
            )?;
        }
        Ok(())
    }

    /// `dir` の直下の 1 項目をリンク非追従で開いて消す（ディレクトリは再帰）。マウントを跨がない。
    fn remove_entry(
        dir: BorrowedFd<'_>,
        file_name: &OsStr,
        root_dev: u64,
        root_mnt: u64,
        depth: usize,
        seen: &mut usize,
    ) -> Result<(), TraitError> {
        let name = cstr(file_name)?;
        let child = match sys::open_path_nofollow_at(dir, &name) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => return Ok(()),
            Err(_) => return Err(remove_failed()),
        };
        if mount_id(child.as_fd()) != Some(root_mnt) {
            return Err(remove_failed());
        }
        let is_child_dir = fstat(child.as_fd())
            .map(|(_, _, d, _)| d)
            .map_err(|_| remove_failed())?;
        if is_child_dir {
            remove_children(child.as_fd(), root_dev, root_mnt, depth + 1, seen)?;
            sys::remove_dir_at(dir, &name).map_err(|_| remove_failed())?;
        } else {
            sys::remove_file_at(dir, &name).map_err(|_| remove_failed())?;
        }
        Ok(())
    }

    /// OCI-7・SEC-5・#2690: seal / publish の実行場所の分岐と、userns の子の終了コードの写し方。
    #[cfg(test)]
    mod finalize_tests {
        use super::*;

        fn sub() -> ImageRootfsPrivilege {
            let source = SubordinateIdSource::with_id_files(
                None,
                Path::new("/nonexistent/subuid"),
                Path::new("/nonexistent/subgid"),
            )
            .expect("source");
            ImageRootfsPrivilege::SubordinateIds(source)
        }

        #[test]
        fn route_host_when_owner_is_euid_or_unknown() {
            let p = sub();
            assert!(matches!(
                finalize_route(Some(1000), 1000, &p),
                FinalizeRoute::Host { foreign: false }
            ));
            assert!(matches!(
                finalize_route(None, 1000, &p),
                FinalizeRoute::Host { foreign: false }
            ));
        }

        #[test]
        fn route_foreign_host_effective_ids_stays_on_host() {
            assert!(matches!(
                finalize_route(Some(100_000), 1000, &HOST_PRIVILEGE),
                FinalizeRoute::Host { foreign: true }
            ));
        }

        #[test]
        fn route_userns_when_foreign_and_subordinate() {
            let p = sub();
            assert!(matches!(
                finalize_route(Some(100_000), 1000, &p),
                FinalizeRoute::Userns(_)
            ));
        }

        #[test]
        fn seal_outcome_maps_every_exit_code() {
            assert!(seal_outcome(Ok(SEAL_OK)).is_ok());
            let e = seal_outcome(Ok(SEAL_EXISTS)).expect_err("exists");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            let e = seal_outcome(Ok(SEAL_WIDEN_FAILED)).expect_err("widen");
            assert_eq!(e.code(), ErrorCode::Internal);
            assert!(e.message().contains("cannot make unpacked root writable"));
            let e = seal_outcome(Ok(SEAL_WRITE_FAILED)).expect_err("write");
            assert!(e.message().contains("cannot make unpacked root writable"));
            let e = seal_outcome(Ok(SEAL_RESTORE_FAILED)).expect_err("restore");
            assert_eq!(e.message(), "failed to restore rootfs mode");
            let e = seal_outcome(Ok(CHILD_SETUP_FAILED)).expect_err("setup");
            assert_eq!(e.code(), ErrorCode::Internal);
            let e = seal_outcome(Err(UsernsRunError::MultiThreaded)).expect_err("mt");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            let e = seal_outcome(Err(UsernsRunError::Timeout)).expect_err("timeout");
            assert_eq!(e.code(), ErrorCode::Timeout);
        }

        #[test]
        fn publish_outcome_observation_decides_published() {
            let (p, r) = publish_outcome(Ok(PUB_RENAMED), true);
            assert!(p && r.is_ok());
            // 期限切れで kill しても、改名が済んでいれば公開済みとして残す（削除しない）が、
            // mode の復元を確認できないので成功にはしない（Timeout のエラーで返す）。
            let (p, r) = publish_outcome(Err(UsernsRunError::Timeout), true);
            assert!(p);
            assert_eq!(r.expect_err("timeout").code(), ErrorCode::Timeout);
            // 改名の後に異常終了した子も同様（復元前に止まった可能性）。
            let (p, r) = publish_outcome(Ok(99), true);
            assert!(p);
            assert_eq!(
                r.expect_err("abnormal").message(),
                "failed to restore rootfs mode"
            );
            let (p, r) = publish_outcome(Err(UsernsRunError::Other(ErrorCode::Internal)), true);
            assert!(p);
            assert_eq!(r.expect_err("other").code(), ErrorCode::Internal);
            let (p, r) = publish_outcome(Ok(PUB_RESTORE_FAILED), true);
            assert!(p);
            assert_eq!(
                r.expect_err("restore").message(),
                "failed to restore rootfs mode"
            );
            let (p, r) = publish_outcome(Ok(PUB_EXISTS), false);
            assert!(!p);
            assert_eq!(r.expect_err("exists").code(), ErrorCode::AlreadyExists);
            let (p, r) = publish_outcome(Ok(PUB_WIDEN_FAILED), false);
            assert!(!p);
            assert!(
                r.expect_err("widen")
                    .message()
                    .contains("cannot make unpacked root writable")
            );
            // 改名したと言うのに観測できない場合は成功を装わない。
            let (p, r) = publish_outcome(Ok(PUB_RENAMED), false);
            assert!(!p);
            assert_eq!(r.expect_err("refuse").code(), ErrorCode::FailedPrecondition);
            let (_, r) = publish_outcome(Ok(PUB_RENAME_FAILED), false);
            assert_eq!(r.expect_err("rename").message(), "failed to publish rootfs");
            let (_, r) = publish_outcome(Ok(99), false);
            assert_eq!(r.expect_err("unknown").code(), ErrorCode::Internal);
            let (_, r) = publish_outcome(Err(UsernsRunError::MultiThreaded), false);
            assert_eq!(r.expect_err("mt").code(), ErrorCode::FailedPrecondition);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! Linux 以外（macOS 等の Unix・Windows）: 展開先を fd／ハンドルで固定する実装が無い。経路を再解決して
    //! 作成・展開・削除すると、検査後や作成後に親が symlink／junction へ差し替えられて bundle 外へ
    //! 作成・書き込み・削除しうる（SEC-1）。そのため作成の前に Unimplemented を返して展開を拒否する
    //! （fail-closed。REPAIR-3: 実装済みを装わない。固定の実装は 3 OS 対応の課題として追跡する）。

    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{
        ImageRootfsPrivilege, ImageRootfsRecord, OrphanReap, RecordedRootfsRemoval,
        StagingReclamation, refuse,
    };
    use crate::traits::{ErrorCode, StateStore, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing;

    pub(super) fn unpack_path(path: &Path, _b: &Backing) -> PathBuf {
        path.to_path_buf()
    }

    pub(super) fn publish(
        _b: &mut Backing,
        _privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        Ok(())
    }

    /// 作成自体が拒否される（`create_dir` は Unimplemented）ため到達しない。
    pub(super) fn is_published(_b: &Backing) -> bool {
        true
    }

    pub(super) fn path_is_unpacked(_path: &Path, _b: &Backing) -> bool {
        false
    }

    pub(super) fn create_dir(
        _bundle: &Path,
        _parents: &[&OsStr],
        _last: &OsStr,
        _privilege: &ImageRootfsPrivilege,
        _reap_hook: super::ReapHook<'_>,
    ) -> Result<(Backing, StagingReclamation), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs unpacking is not supported on this OS yet",
        ))
    }

    /// 展開途中の木が生じないので回収する物も無いが、実装済みを装わず `Unimplemented` を返す（REPAIR-3）。
    pub(super) fn reap_stale(
        _bundle: &Path,
        _parents: &[&OsStr],
        _privilege: &ImageRootfsPrivilege,
    ) -> Result<StagingReclamation, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "reclaiming image rootfs staging is not supported on this OS yet",
        ))
    }

    /// 作成自体が拒否されるので公開済みの木は生じない（REPAIR-3）。
    pub(super) fn reap_published_orphan(
        _store: &dyn StateStore,
        _bundle: &Path,
        _root_path: &Path,
        _privilege: &ImageRootfsPrivilege,
    ) -> OrphanReap {
        OrphanReap::NotPresent
    }

    pub(super) fn remove(
        _path: &Path,
        _b: Backing,
        _privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        Err(refuse())
    }

    /// 作成自体が拒否される（`create_dir` は Unimplemented）ため到達しない。
    pub(super) fn seal(
        _b: &mut Backing,
        _scope: Option<&str>,
        _privilege: &ImageRootfsPrivilege,
    ) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs requires Linux",
        ))
    }

    pub(super) fn token(_b: &Backing) -> Result<String, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs requires Linux",
        ))
    }

    pub(super) fn identity(_b: &Backing) -> Result<(u64, u64), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs unpacking is not supported on this OS yet",
        ))
    }

    /// 同一性を fd で固定できないため、経路を再解決して消さない（SEC-1。記録は失敗として残す）。
    pub(super) fn remove_recorded(
        _bundle: &Path,
        _rec: &ImageRootfsRecord,
        _privilege: &ImageRootfsPrivilege,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs removal is not supported on this OS yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        // 呼び出しごとに固有（並行する試験が同じ名前を使っても相手のディレクトリを消さない。REPAIR-12）。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fandhe-image-rootfs-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// OCI-7・SEC-1: 公開後の最終の経路が別の実体（同名の差し替え）なら展開した実体と見なさない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_is_unpacked_at_rejects_replaced_directory() {
        let b = tmp("replaced");
        std::fs::create_dir(b.join("p")).expect("parent");
        let mut c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        c.publish().expect("publish");
        assert!(c.is_unpacked_at(&b.join("p/rootfs")));
        std::fs::rename(b.join("p"), b.join("moved")).expect("rename");
        std::fs::create_dir_all(b.join("p/rootfs")).expect("new");
        assert!(!c.is_unpacked_at(&b.join("p/rootfs")));
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 空の rootfs を作り、展開先の経路へ書いて公開し、remove で消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_creates_empty_dir_publishes_and_remove_deletes_it() {
        let b = tmp("basic");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        // 公開前は最終の名前に存在しない（他の create から rootfs として見えない）。
        assert!(!b.join("rootfs").exists());
        let up = c.unpack_path();
        assert_eq!(std::fs::read_dir(&up).expect("read").count(), 0);
        std::fs::write(up.join("f"), b"x").expect("write");
        c.publish().expect("publish");
        assert!(b.join("rootfs").join("f").exists());
        c.remove().expect("remove");
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 既存の rootfs・bundle 自身・`..` は拒否し、既存の中身に触れない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_rejects_existing_bundle_itself_and_parent_dir() {
        let b = tmp("reject");
        std::fs::create_dir(b.join("rootfs")).expect("mk");
        std::fs::write(b.join("rootfs").join("keep"), b"x").expect("w");
        let e = prepare_rootfs_target(&b, Path::new("rootfs")).expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        assert!(b.join("rootfs").join("keep").exists());
        let e = prepare_rootfs_target(&b, Path::new(".")).expect_err("bundle itself");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let e = prepare_rootfs_target(&b, Path::new("../x")).expect_err("parent");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 読み取り専用 mode の木も権限を補正して消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_restores_permissions_for_read_only_tree() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("ro");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let sub = c.unpack_path().join("sub");
        std::fs::create_dir(&sub).expect("sub");
        std::fs::write(sub.join("f"), b"x").expect("f");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).expect("ro");
        c.remove().expect("remove");
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 中間要素が symlink なら拒否し、bundle 外に何も作らない。
    #[cfg(target_os = "linux")]
    #[cfg(unix)]
    #[test]
    fn oci7_prepare_rejects_symlink_parent() {
        let b = tmp("symparent");
        let outside = tmp("symparent-out");
        std::os::unix::fs::symlink(&outside, b.join("link")).expect("symlink");
        let e = prepare_rootfs_target(&b, Path::new("link/rootfs")).expect_err("symlink");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_dir(&outside).expect("read").count(), 0);
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 差し替えられた rootfs（symlink）は消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_refuses_replaced_rootfs() {
        let b = tmp("replaced");
        let outside = tmp("replaced-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        c.publish().expect("publish");
        std::fs::remove_dir(c.path()).expect("rm");
        std::os::unix::fs::symlink(&outside, c.path()).expect("symlink");
        let e = c.remove().expect_err("refuse");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("marker").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 作成後に親ディレクトリが symlink へ差し替えられても、後始末は固定済みの親の下だけを消し、
    /// 差し替え先（bundle 外）には触れない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_ignores_parent_swapped_for_symlink() {
        let b = tmp("parentswap");
        let outside = tmp("parentswap-out");
        std::fs::create_dir(b.join("p")).expect("p");
        let mut c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join("mine"), b"x").expect("mine");
        c.publish().expect("publish");
        std::fs::create_dir(outside.join("rootfs")).expect("o rootfs");
        std::fs::write(outside.join("rootfs").join("marker"), b"x").expect("marker");
        std::fs::rename(b.join("p"), b.join("p_moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        c.remove().expect("remove");
        assert!(outside.join("rootfs").join("marker").exists());
        assert!(!b.join("p_moved").join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 後始末は木の内側の symlink を辿らず、リンク自体だけを消す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_does_not_follow_symlinks_inside_tree() {
        let b = tmp("innerlink");
        let outside = tmp("innerlink-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::os::unix::fs::symlink(&outside, c.unpack_path().join("dirlink")).expect("symlink");
        c.publish().expect("publish");
        c.remove().expect("remove");
        assert!(outside.join("marker").exists());
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 展開中の非公開の名前（予約名）は root.path として拒否する。
    #[test]
    fn oci7_prepare_rejects_reserved_staging_name() {
        let b = tmp("reserved");
        let e = prepare_rootfs_target(&b, Path::new(".fandhe-unpack-1-0")).expect_err("reserved");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(has_staging_component(Path::new("a/.fandhe-unpack-x/b")));
        assert!(!has_staging_component(Path::new("a/rootfs")));
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: setgid の親の下で 02700 になる展開先も採用できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_accepts_setgid_parent() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("setgid");
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o2755)).expect("setgid");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        c.publish().expect("publish");
        assert!(c.is_published());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 返す経路は正規化済みで、等価な書き方の `root.path` でも同じ場所に作る。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_normalizes_path() {
        let b = tmp("normalize");
        let mut c = prepare_rootfs_target(&b, Path::new("./rootfs/")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        c.publish().expect("publish");
        assert!(b.join("rootfs").is_dir());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// SEC-1: 展開先は固定した rootfs の fd を指し、作成後に親を symlink へ差し替えても bundle 外へ書かない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_unpack_path_survives_parent_swap() {
        let b = tmp("unpackswap");
        let outside = tmp("unpackswap-out");
        std::fs::create_dir(b.join("p")).expect("p");
        let c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        std::fs::rename(b.join("p"), b.join("p_moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        std::fs::write(c.unpack_path().join("payload"), b"x").expect("write");
        assert_eq!(std::fs::read_dir(&outside).expect("read").count(), 0);
        assert_eq!(
            std::fs::read_dir(b.join("p_moved")).expect("read").count(),
            1
        );
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 最終の名前が公開前に作られていたら、公開は置き換えずに拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_publish_refuses_when_final_name_appeared() {
        let b = tmp("pubrace");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::create_dir(b.join("rootfs")).expect("mk");
        std::fs::write(b.join("rootfs").join("keep"), b"x").expect("w");
        let e = c.publish().expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        assert!(b.join("rootfs").join("keep").exists());
        c.remove().expect("remove staging");
        assert!(b.join("rootfs").join("keep").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// 公開済みの rootfs を作り、記録を返す（`<b>/<rel>` に `f` を置く）。
    #[cfg(target_os = "linux")]
    fn published_record(b: &Path, rel: &str) -> ImageRootfsRecord {
        let mut c = prepare_rootfs_target(b, Path::new(rel)).expect("prepare");
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        c.seal(None).expect("seal");
        c.publish().expect("publish");
        c.record().expect("record")
    }

    /// OCI-7（#2378）: 展開器が rootfs 自身を 0555 にしても seal は印を書け、公開後の mode は展開器が
    /// 残したまま（0555）で、記録から消せる（削除側が mode を補って辿る）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_seal_works_on_read_only_rootfs_and_restores_mode() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("seal-ro");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        std::fs::set_permissions(c.unpack_path(), std::fs::Permissions::from_mode(0o555))
            .expect("chmod 0555");
        c.seal(None)
            .expect("seal must not fail on a read-only rootfs");
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o7777;
        assert_eq!(mode(&c.unpack_path()), 0o555);
        c.publish().expect("publish");
        let rec = c.record().expect("record");
        assert_eq!(mode(&b.join("rootfs")), 0o555);
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7（#2378）: 展開器が rootfs 自身から所有者の search 権限まで外しても（0600・0000）、削除側は
    /// 照合の前に権限を一時的に補うので、正しい記録なら消せる（印の検索が EACCES で拒否にならない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_without_owner_search_permission() {
        use std::os::unix::fs::PermissionsExt;
        for (i, m) in [0o600u32, 0o000].into_iter().enumerate() {
            let b = tmp(&format!("rec-nosearch-{i}"));
            let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
            std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
            std::fs::set_permissions(c.unpack_path(), std::fs::Permissions::from_mode(m))
                .expect("chmod");
            c.seal(None).expect("seal");
            c.publish().expect("publish");
            let rec = c.record().expect("record");
            assert_eq!(
                remove_recorded_rootfs(&b, &rec).expect("remove"),
                RecordedRootfsRemoval::Removed,
                "mode {m:o}"
            );
            assert!(!b.join("rootfs").exists());
            let _ = std::fs::remove_dir_all(&b);
        }
    }

    /// OCI-7・SEC-1（#2378）: 照合のために補った権限は、照合が不一致（拒否）なら元の mode へ戻す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_restores_mode_on_token_mismatch() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("rec-nosearch-mismatch");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        std::fs::set_permissions(c.unpack_path(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        c.seal(None).expect("seal");
        c.publish().expect("publish");
        let rec = c.record().expect("record");
        let (dev, ino) = rec.identity();
        let wrong = ImageRootfsRecord::new(rec.relative_path().to_path_buf(), dev, ino)
            .and_then(|r| r.with_token("0".repeat(32)))
            .expect("wrong token record");
        let root = b.join("rootfs");
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o7777;
        let e = remove_recorded_rootfs(&b, &wrong).expect_err("mismatch");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(mode(&root), 0o000);
        // 正しい記録では消せる。
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・SEC-1（#2378）: 記録した rootfs を手で消して同名のディレクトリを作り直した（印が無い・別の印）
    /// ときは、(dev, ino) が偶然一致しても消さない。利用者の新しいデータが残る。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_recreated_dir_without_matching_token() {
        let b = tmp("rec-token");
        let rec = published_record(&b, "rootfs");
        let token = rec.token().expect("token").to_owned();
        assert_eq!(token.len(), 32);
        let root = b.join("rootfs");
        // 印を別の値へ差し替えた作り直し（同じ inode の再利用を模す）。
        std::fs::set_permissions(
            root.join(super::OWNER_TOKEN_FILE),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("chmod");
        std::fs::write(root.join(super::OWNER_TOKEN_FILE), "0".repeat(32)).expect("other token");
        std::fs::write(root.join("user-data"), b"keep").expect("data");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("mismatch");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            std::fs::read(root.join("user-data")).expect("kept"),
            b"keep"
        );
        // 印が無い（利用者が作り直した空のディレクトリ相当）。
        std::fs::remove_file(root.join(super::OWNER_TOKEN_FILE)).expect("rm marker");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("no marker");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(root.join("user-data").exists());
        // 印が symlink（リンクは辿らない）。
        std::os::unix::fs::symlink("/etc/hostname", root.join(super::OWNER_TOKEN_FILE))
            .expect("symlink");
        assert!(remove_recorded_rootfs(&b, &rec).is_err());
        assert!(root.join("user-data").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・SEC-1（#2378）: トークンの無い旧記録は、実体が一致しても消さない（fail-closed）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_record_without_token() {
        let b = tmp("rec-notoken");
        let rec = published_record(&b, "rootfs");
        let (dev, ino) = rec.identity();
        let legacy =
            ImageRootfsRecord::new(rec.relative_path().to_path_buf(), dev, ino).expect("legacy");
        assert!(legacy.token().is_none());
        let e = remove_recorded_rootfs(&b, &legacy).expect_err("no token");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(b.join("rootfs").join("f").exists());
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("matching"),
            RecordedRootfsRemoval::Removed
        );
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7（#2378）: 展開済みの木に同名の印のファイルがあれば（イメージ由来の偽の印）採用せず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_seal_refuses_preexisting_marker() {
        let b = tmp("seal-pre");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join(super::OWNER_TOKEN_FILE), "x").expect("fake");
        let e = c.seal(None).expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        c.remove().expect("cleanup");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 記録から公開済みの rootfs を消せる。bundle と他のファイルは残る。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_deletes_tree() {
        let b = tmp("rec-del");
        std::fs::write(b.join("config.json"), b"{}").expect("config");
        let rec = published_record(&b, "rootfs");
        assert_eq!(rec.relative_path(), Path::new("rootfs"));
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!b.join("rootfs").exists());
        assert!(b.join("config.json").is_file());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 入れ子の `root.path` でも記録の経路で消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_nested_path() {
        let b = tmp("rec-nested");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(b.join("p").is_dir());
        assert!(!b.join("p/rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 既に無ければ `NotPresent`（冪等な再実行）。bundle・中間要素が無い場合も同じ。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_absent_is_not_present() {
        let b = tmp("rec-absent");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        std::fs::remove_dir_all(b.join("p/rootfs")).expect("gone");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("absent"),
            RecordedRootfsRemoval::NotPresent
        );
        std::fs::remove_dir_all(b.join("p")).expect("parent gone");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("no parent"),
            RecordedRootfsRemoval::NotPresent
        );
        let _ = std::fs::remove_dir_all(&b);
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("no bundle"),
            RecordedRootfsRemoval::NotPresent
        );
    }

    /// SEC-1: 同名の別ディレクトリ・symlink に差し替えられていたら `FailedPrecondition` で何も消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_replaced_dir() {
        let b = tmp("rec-replaced");
        let rec = published_record(&b, "rootfs");
        std::fs::rename(b.join("rootfs"), b.join("moved")).expect("move");
        std::fs::create_dir(b.join("rootfs")).expect("replacement");
        std::fs::write(b.join("rootfs/marker"), b"o").expect("marker");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("replaced");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(b.join("rootfs/marker").is_file());

        std::fs::remove_dir_all(b.join("rootfs")).expect("rm replacement");
        let outside = tmp("rec-replaced-out");
        std::fs::write(outside.join("marker"), b"o").expect("marker");
        std::os::unix::fs::symlink(&outside, b.join("rootfs")).expect("symlink");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("symlink");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("marker").is_file());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 中間要素が bundle 外への symlink に差し替えられても、外側は消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_parent_symlink_untouched() {
        let b = tmp("rec-parent");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        let outside = tmp("rec-parent-out");
        std::fs::create_dir(outside.join("rootfs")).expect("outside rootfs");
        std::fs::write(outside.join("rootfs/marker"), b"o").expect("marker");
        std::fs::rename(b.join("p"), b.join("p-moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("symlinked parent");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("rootfs/marker").is_file());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 展開時に読み取り専用にされたディレクトリを含む木も消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_handles_read_only_dirs() {
        use std::os::unix::fs::PermissionsExt as _;
        let b = tmp("rec-ro");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let up = c.unpack_path();
        std::fs::create_dir(up.join("ro")).expect("ro");
        std::fs::write(up.join("ro/f"), b"x").expect("f");
        std::fs::set_permissions(up.join("ro"), std::fs::Permissions::from_mode(0o500))
            .expect("chmod");
        c.seal(None).expect("seal");
        c.publish().expect("publish");
        let rec = c.record().expect("record");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・SEC-1: Linux 以外は展開先を固定できないため、作成の前に Unimplemented で拒否する。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_prepare_refuses_without_fd_pinning() {
        let b = tmp("winrefuse");
        let e = prepare_rootfs_target(&b, Path::new("rootfs")).expect_err("refuse");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// `mkfifo` の終了待ちの期限（REPAIR-5）。
    #[cfg(target_os = "linux")]
    const MKFIFO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    /// `mkfifo(1)` で FIFO を作る（std・`sys` に FIFO を作る手段が無いため、テストに限り外部コマンドを使う）。
    /// 終了を期限つきで待ち、超過したら kill して回収してから失敗させる（REPAIR-5。無期限に待たない）。
    /// 起動失敗・失敗終了・期限超過はすべてテスト失敗にする（skip で成功扱いにしない）。
    #[cfg(target_os = "linux")]
    fn make_fifo(path: &Path) {
        let mut child = std::process::Command::new("mkfifo")
            .arg(path)
            .spawn()
            .expect("mkfifo must be runnable to verify FIFO handling");
        let start = std::time::Instant::now();
        loop {
            match child.try_wait().expect("failed to poll mkfifo") {
                Some(status) => {
                    assert!(status.success(), "mkfifo failed: {status}");
                    return;
                }
                None if start.elapsed() > MKFIFO_DEADLINE => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("mkfifo did not finish within {MKFIFO_DEADLINE:?}");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }

    /// SEC-1・OCI-7: 所有印が FIFO に差し替えられても open せず（ブロックせず）拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_non_regular_marker() {
        let b = tmp("marker-fifo");
        let rec = published_record(&b, "rootfs");
        let root = b.join("rootfs");
        let marker = root.join(super::OWNER_TOKEN_FILE);
        std::fs::remove_file(&marker).expect("rm marker");
        make_fifo(&marker);
        let (tx, rx) = std::sync::mpsc::channel();
        let b2 = b.clone();
        std::thread::spawn(move || {
            let _ = tx.send(remove_recorded_rootfs(&b2, &rec).is_err());
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("must not block");
        assert!(refused);
        assert!(root.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// SEC-1・OCI-7: bundle が FIFO に差し替えられても delete は open でブロックせず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_fifo_bundle_does_not_block() {
        let b = tmp("fifo-bundle");
        let fifo = b.join("fifo");
        make_fifo(&fifo);
        let rec = published_record(&b, "rootfs");
        let (tx, rx) = std::sync::mpsc::channel();
        let f = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(remove_recorded_rootfs(&f, &rec).is_err());
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("must not block");
        assert!(refused);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// 持ち主のいない展開途中の木を `parent` の下に作る（`name` は予約名。中にファイルとサブディレクトリを置く）。
    #[cfg(target_os = "linux")]
    fn plant_staging(parent: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let t = parent.join(name);
        std::fs::create_dir(&t).expect("plant");
        std::fs::create_dir(t.join("sub")).expect("sub");
        std::fs::write(t.join("sub").join("f"), b"x").expect("f");
        std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o700)).expect("0700");
        t
    }

    /// OCI-7・#2379: create の途中で落ちた（`remove` も `publish` もせず drop した = ロックが外れた）展開途中の
    /// 木は、次の create の時点で回収される。予約名でない兄弟・公開済みの rootfs は残り、2 回目は何も回収しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_reap_reclaims_staging_left_by_crashed_create() {
        let b = tmp("reap-crashed");
        let mut published = prepare_rootfs_target(&b, Path::new("rootfs")).expect("first");
        std::fs::write(published.unpack_path().join("keep"), b"x").expect("write");
        published.publish().expect("publish");
        // 別の root.path で作って中身を書き、落ちたことにする（drop でロックが外れる）。
        let crashed = prepare_rootfs_target(&b, Path::new("other")).expect("second");
        std::fs::write(crashed.unpack_path().join("partial"), b"x").expect("partial");
        let leftover = std::fs::read_dir(&b)
            .expect("read")
            .map(|e| e.expect("ent").file_name())
            .find(|n| n.to_string_lossy().starts_with(STAGING_PREFIX))
            .expect("staging exists");
        drop(crashed);
        std::fs::create_dir(b.join(".fandhe-unpack-x")).expect("not reserved shape");
        std::fs::write(b.join("sibling"), b"x").expect("sibling");

        let next = prepare_rootfs_target(&b, Path::new("third")).expect("third");
        assert_eq!(next.reclamation().reclaimed, vec![leftover.clone()]);
        assert!(next.reclamation().kept_alive.is_empty());
        assert!(!b.join(&leftover).exists());
        assert!(b.join("rootfs/keep").exists());
        assert!(b.join(".fandhe-unpack-x").is_dir());
        assert!(b.join("sibling").exists());
        let again = reap_stale_unpacks(&b, Path::new("third")).expect("public");
        assert!(again.reclaimed.is_empty());
        assert_eq!(again.kept_alive.len(), 1, "the live `third` staging");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2379: ロックを保持中の（生きている）create の展開先は回収せず、両方が共存する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_reap_keeps_live_staging() {
        let b = tmp("reap-live");
        let first = prepare_rootfs_target(&b, Path::new("a")).expect("first");
        std::fs::write(first.unpack_path().join("f"), b"x").expect("write");
        let second = prepare_rootfs_target(&b, Path::new("b")).expect("second");
        assert_eq!(second.reclamation().kept_alive.len(), 1);
        assert!(second.reclamation().reclaimed.is_empty());
        assert_eq!(
            std::fs::read(first.unpack_path().join("f")).expect("alive"),
            b"x"
        );
        let r = reap_stale_unpacks(&b, Path::new("a")).expect("public");
        assert_eq!(r.kept_alive.len(), 2);
        assert!(r.reclaimed.is_empty());
        first.remove().expect("rm first");
        second.remove().expect("rm second");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2379: PID が再利用されて同じ名前の持ち主のいない木が残っていても、次の create は
    /// `AlreadyExists` にならず、その木を回収して成功する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_reap_resolves_pid_reuse_collision() {
        let b = tmp("reap-pid-reuse");
        let pid = std::process::id();
        for seq in 0..16 {
            plant_staging(&b, &format!("{STAGING_PREFIX}{pid}-{seq}"));
        }
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("must not collide");
        assert_eq!(c.reclamation().reclaimed.len(), 16);
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        c.publish().expect("publish");
        assert!(b.join("rootfs/f").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// SEC-1・OCI-7・#2379: 回収は予約名の symlink・通常ファイル・mode が違うディレクトリを辿らず消さず、
    /// bundle 外の実体にも触れない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_reap_does_not_follow_or_delete_foreign_entries() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("reap-foreign");
        let outside = tmp("reap-foreign-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        std::os::unix::fs::symlink(&outside, b.join(".fandhe-unpack-1-1")).expect("symlink");
        std::fs::write(b.join(".fandhe-unpack-2-2"), b"file").expect("file");
        let wide = plant_staging(&b, ".fandhe-unpack-3-3");
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).expect("0755");
        std::fs::create_dir(b.join(".fandhe-unpack-4-")).expect("bad shape");
        std::fs::create_dir(b.join(".fandhe-unpack-99999999999-1")).expect("too long pid");

        let r = reap_stale_unpacks(&b, Path::new("rootfs")).expect("reap");
        // mode 0755 の木は回収する（mode は証拠にしない。userns の展開器が root の mode を変えうる。#2540）。
        assert_eq!(
            r.reclaimed,
            vec![std::ffi::OsString::from(".fandhe-unpack-3-3")]
        );
        assert_eq!(
            r.kept_unverified,
            vec![
                std::ffi::OsString::from(".fandhe-unpack-1-1"),
                ".fandhe-unpack-2-2".into(),
            ]
        );
        assert_eq!(
            r.kept_unverified_reasons,
            vec![
                UnverifiedReason::NotDirectory,
                UnverifiedReason::NotDirectory
            ]
        );
        assert!(outside.join("marker").exists());
        assert!(b.join(".fandhe-unpack-2-2").is_file());
        assert!(!wide.exists());
        assert!(b.join(".fandhe-unpack-4-").is_dir());
        assert!(b.join(".fandhe-unpack-99999999999-1").is_dir());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1・#2379: 持ち主のいない木の中の symlink は辿らず、リンクだけを消す。読み取り専用の木も消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_reap_does_not_follow_symlinks_inside_tree() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("reap-inner");
        let outside = tmp("reap-inner-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let t = plant_staging(&b, ".fandhe-unpack-5-5");
        std::os::unix::fs::symlink(&outside, t.join("dirlink")).expect("symlink");
        std::fs::set_permissions(t.join("sub"), std::fs::Permissions::from_mode(0o555))
            .expect("ro");
        let r = reap_stale_unpacks(&b, Path::new("rootfs")).expect("reap");
        assert_eq!(
            r.reclaimed,
            vec![std::ffi::OsString::from(".fandhe-unpack-5-5")]
        );
        assert!(!t.exists());
        assert!(outside.join("marker").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7・#2379: 別のプロセス（ここでは別の open file description）がロックを持つ木は生きていると
    /// 見なして消さず、ロックが外れたら次の回収で消える。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_lock_held_by_other_is_reported_as_alive_not_deleted() {
        let b = tmp("reap-lock-other");
        let t = plant_staging(&b, ".fandhe-unpack-6-6");
        let holder = std::fs::File::open(&t).expect("open");
        holder.try_lock().expect("lock");
        let r = reap_stale_unpacks(&b, Path::new("rootfs")).expect("reap");
        assert_eq!(
            r.kept_alive,
            vec![std::ffi::OsString::from(".fandhe-unpack-6-6")]
        );
        assert!(t.join("sub/f").exists());
        drop(holder);
        let r = reap_stale_unpacks(&b, Path::new("rootfs")).expect("reap");
        assert_eq!(r.reclaimed.len(), 1);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// REPAIR-4・#2379: 親が書込・探索可能だが読めない（走査できない）とき、create は成功するが回収は
    /// 不完全（`scan_failed`）として報告される。木が無い場合（`is_incomplete() == false`）と区別できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair4_reap_reports_scan_failure_for_unreadable_parent() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("reap-unreadable");
        std::fs::create_dir(b.join("p")).expect("p");
        std::fs::set_permissions(b.join("p"), std::fs::Permissions::from_mode(0o300))
            .expect("chmod");
        if std::fs::read_dir(b.join("p")).is_ok() {
            // root 等で権限が効かない環境では前提を作れない。
            std::fs::set_permissions(b.join("p"), std::fs::Permissions::from_mode(0o700)).ok();
            let _ = std::fs::remove_dir_all(&b);
            return;
        }
        let r = reap_stale_unpacks(&b, Path::new("p/rootfs")).expect("reap");
        assert!(r.scan_failed);
        assert!(r.is_incomplete());
        assert!(r.is_noteworthy());
        assert!(r.reclaimed.is_empty() && r.failed.is_empty());
        let c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("create succeeds");
        assert!(c.reclamation().scan_failed);
        assert!(c.reclamation().is_incomplete());
        drop(c);
        std::fs::set_permissions(b.join("p"), std::fs::Permissions::from_mode(0o700)).ok();
        let clean = reap_stale_unpacks(&b, Path::new("p/rootfs")).expect("reap");
        assert!(!clean.scan_failed);
        assert!(!clean.is_incomplete());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// SEC-1・#2379: 公開入口は `prepare_rootfs_target` と同じ経路検査を通す（`..`・予約名・bundle 自身・symlink の親）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_reap_stale_unpacks_validates_paths() {
        let b = tmp("reap-paths");
        let outside = tmp("reap-paths-out");
        plant_staging(&outside, ".fandhe-unpack-7-7");
        std::os::unix::fs::symlink(&outside, b.join("link")).expect("symlink");
        for bad in ["../x", ".fandhe-unpack-1-0", ".", "link/rootfs"] {
            let e = reap_stale_unpacks(&b, Path::new(bad)).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
        assert!(outside.join(".fandhe-unpack-7-7/sub/f").exists());
        let e = reap_stale_unpacks(&b.join("nope"), Path::new("rootfs")).expect_err("no bundle");
        assert_eq!(e.code(), ErrorCode::NotFound);
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7・SEC-1: Linux 以外は回収も `Unimplemented`（実装済みを装わない。REPAIR-3）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_reap_stale_unpacks_is_unimplemented_outside_linux() {
        let b = tmp("reap-nonlinux");
        let e = reap_stale_unpacks(&b, Path::new("rootfs")).expect_err("unimplemented");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[cfg(target_os = "linux")]
    fn rewrite_marker(root: &Path, content: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        let marker = root.join(super::OWNER_TOKEN_FILE);
        std::fs::remove_file(&marker).expect("rm marker");
        std::fs::write(&marker, content).expect("write marker");
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o400)).expect("mode");
    }

    /// OCI-7・#2540: 印は v2（トークン + 作成時の `<dev>:<ino>`）で書かれ、delete は v1（トークンだけ）の旧記録の
    /// 印も受ける。形式が不正な印は拒否する（何も消さない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_marker_v2_is_written_and_v1_is_still_accepted_by_delete() {
        let b = tmp("marker-v2");
        let rec = published_record(&b, "rootfs");
        let root = b.join("rootfs");
        let token = rec.token().expect("token").to_owned();
        let text = std::fs::read_to_string(root.join(super::OWNER_TOKEN_FILE)).expect("marker");
        let (dev, ino) = rec.identity();
        assert_eq!(text, format!("{token}\n{dev}:{ino}\n"));

        for bad in [
            format!("{token}\nx:y\n"),
            format!("{token}\n{dev}:{ino}"),
            format!("{token}\n{dev}:{ino}\nextra\n"),
            format!("{token}\n{dev}\n"),
            format!("{token}\n{dev}:{}\n", "9".repeat(21)),
            format!("{}\n{dev}:{ino}\n", token.to_uppercase()),
        ] {
            rewrite_marker(&root, bad.as_bytes());
            let e = remove_recorded_rootfs(&b, &rec).expect_err("malformed marker");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{bad}");
            assert!(root.join("f").exists());
        }
        rewrite_marker(&root, token.as_bytes());
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("v1 accepted"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2540: 削除の途中で失敗しても印は最後に消すので残り、次の孤児の回収が木を見分けられる。
    /// 深さの上限（256）を超える入れ子で失敗させる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_keeps_marker_until_the_rest_is_removed() {
        let b = tmp("marker-last");
        let rec = published_record(&b, "rootfs");
        let root = b.join("rootfs");
        let deep: PathBuf = std::iter::repeat_n("d", 300).collect();
        std::fs::create_dir_all(root.join(&deep)).expect("deep");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("too deep");
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(root.join(super::OWNER_TOKEN_FILE).is_file());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// REPAIR-4・#2540: `reap_stale_unpacks_with` は確かめられず残した木を 1 件ずつ失敗として記録し、
    /// 理由を `kept_unverified_reasons` に出す。何も無ければ記録しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair4_reap_with_records_each_kept_unverified_tree() {
        let b = tmp("reap-with");
        let rec = OpRecorder::new();
        let r = reap_stale_unpacks_with(&b, Path::new("rootfs"), &ReapOptions::new(), &rec)
            .expect("empty");
        assert!(!r.is_noteworthy());
        assert!(rec.snapshot().is_empty());

        let outside = tmp("reap-with-out");
        std::os::unix::fs::symlink(&outside, b.join(".fandhe-unpack-1-1")).expect("symlink");
        std::fs::write(b.join(".fandhe-unpack-2-2"), b"file").expect("file");
        plant_staging(&b, ".fandhe-unpack-3-3");
        let r = reap_stale_unpacks_with(&b, Path::new("rootfs"), &ReapOptions::new(), &rec)
            .expect("reap");
        assert_eq!(
            r.reclaimed,
            vec![std::ffi::OsString::from(".fandhe-unpack-3-3")]
        );
        assert_eq!(r.kept_unverified.len(), 2);
        let count = |name: &str| {
            rec.snapshot_op(&OpName::new(name).expect("name"))
                .map_or((0, 0), |s| (s.success(), s.failure()))
        };
        assert_eq!(count("image_rootfs_reap"), (0, 1));
        assert_eq!(count("image_rootfs_reap_kept_unverified"), (0, 2));
        assert_eq!(count("image_rootfs_reap_failed"), (0, 0));
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }
    /// 印 v3 の検証用の状態ルートの識別子（小文字 16 進 32 文字）。
    #[cfg(target_os = "linux")]
    const SCOPE: &str = "d2cd8dfaa9ec16995946ca58e01842e2";

    /// OCI-5・#2635: 状態ルートの識別子は絶対パスの SHA-256 の先頭 128 bit（小文字 16 進 32 文字）で、
    /// パスが違えば値も違う。`printf '%s' /run/x | sha256sum | cut -c1-32` と一致する。
    #[test]
    fn oci5_2635_scope_of_is_sha256_prefix_of_path() {
        assert_eq!(
            scope_of(Path::new("/run/x")),
            "d2cd8dfaa9ec16995946ca58e01842e2"
        );
        assert_ne!(scope_of(Path::new("/run/x")), scope_of(Path::new("/run/y")));
        assert_eq!(scope_of(Path::new("/run/x")), scope_of(Path::new("/run/x")));
        assert_eq!(scope_of(Path::new("/run/x")).len(), 32);
    }

    /// OCI-7・#2635: 展開先は core 専有のラッパー（実効 uid 所有・0700）とその子 `rootfs` の 2 段で、展開器へ渡す
    /// 経路は子を指す。公開すると子が最終の名前になり、空のラッパーは消える。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_staging_uses_core_owned_wrapper() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let b = tmp("wrapper");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let wrappers = |dir: &Path| -> Vec<std::ffi::OsString> {
            let mut v: Vec<_> = std::fs::read_dir(dir)
                .expect("read")
                .map(|e| e.expect("ent").file_name())
                .filter(|n| n.to_string_lossy().starts_with(STAGING_PREFIX))
                .collect();
            v.sort();
            v
        };
        let live = wrappers(&b);
        assert_eq!(live.len(), 1);
        let wrapper = b.join(&live[0]);
        let meta = std::fs::metadata(&wrapper).expect("wrapper");
        assert_eq!(meta.uid(), crate::sys::effective_uid());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let inner: Vec<_> = std::fs::read_dir(&wrapper)
            .expect("read wrapper")
            .map(|e| e.expect("ent").file_name())
            .collect();
        assert_eq!(inner, vec![std::ffi::OsString::from("rootfs")]);
        let child = std::fs::metadata(c.unpack_path()).expect("child");
        let child_id = (child.dev(), child.ino());
        assert_eq!(
            (
                std::fs::metadata(wrapper.join("rootfs")).expect("c").dev(),
                std::fs::metadata(wrapper.join("rootfs")).expect("c").ino()
            ),
            child_id
        );
        assert_ne!(child_id, (meta.dev(), meta.ino()));

        c.seal(Some(SCOPE)).expect("seal");
        c.publish().expect("publish");
        assert!(wrappers(&b).is_empty(), "the empty wrapper is removed");
        let published = std::fs::metadata(b.join("rootfs")).expect("published");
        assert_eq!((published.dev(), published.ino()), child_id);
        let rec = c.record().expect("record");
        assert_eq!(rec.identity(), child_id);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2635: 展開器が子の mode を 0 にしても（rootful で所有者が変わる場合の代役）、回収が判定するのは
    /// 実効 uid 所有のラッパーなので、持ち主のいない木は回収される。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_reap_reclaims_wrapper_when_child_mode_changed() {
        use std::os::unix::fs::PermissionsExt;
        for child_mode in [0o000, 0o755] {
            let b = tmp("wrapper-reap");
            let w = b.join(".fandhe-unpack-1-0");
            std::fs::create_dir(&w).expect("wrapper");
            std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o700)).expect("0700");
            let child = w.join("rootfs");
            std::fs::create_dir(&child).expect("child");
            std::fs::write(child.join("f"), b"x").expect("f");
            std::fs::set_permissions(&child, std::fs::Permissions::from_mode(child_mode))
                .expect("child mode");
            let r = reap_stale_unpacks(&b, Path::new("rootfs")).expect("reap");
            assert_eq!(
                r.reclaimed,
                vec![std::ffi::OsString::from(".fandhe-unpack-1-0")],
                "child mode {child_mode:o}"
            );
            assert!(r.kept_unverified.is_empty() && r.failed.is_empty());
            assert!(!w.exists());
            let _ = std::fs::remove_dir_all(&b);
        }
    }

    /// OCI-7・#2635: 公開前の `remove` はラッパーごと消し、bundle 直下に何も残さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_unpublished_remove_removes_wrapper() {
        let b = tmp("wrapper-remove");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        c.remove().expect("remove");
        assert_eq!(std::fs::read_dir(&b).expect("read").count(), 0);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2635: 展開器が子を 0555（write なし）にしても、公開（別ディレクトリへの改名）は成功し、公開後の
    /// mode は展開器が残したままになる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_publish_works_when_child_has_no_write_permission() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("wrapper-ro");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::set_permissions(c.unpack_path(), std::fs::Permissions::from_mode(0o555))
            .expect("ro");
        c.publish().expect("publish");
        let mode = std::fs::metadata(b.join("rootfs"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o555);
        std::fs::set_permissions(b.join("rootfs"), std::fs::Permissions::from_mode(0o755))
            .expect("restore");
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・OCI-5・#2635: 印 v3 は `トークン\n<dev>:<ino>\n識別子\n` と完全に一致し、識別子の無い seal は v2 を書く。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_seal_writes_v3_with_scope_and_v2_without() {
        let b = tmp("seal-v3");
        let mut c = prepare_rootfs_target(&b, Path::new("a")).expect("prepare");
        c.seal(Some(SCOPE)).expect("seal");
        c.publish().expect("publish");
        let rec = c.record().expect("record");
        let token = rec.token().expect("token");
        let (dev, ino) = rec.identity();
        let text = std::fs::read_to_string(b.join("a").join(super::OWNER_TOKEN_FILE)).expect("m");
        assert_eq!(text, format!("{token}\n{dev}:{ino}\n{SCOPE}\n"));

        let mut c2 = prepare_rootfs_target(&b, Path::new("b")).expect("prepare 2");
        c2.seal(None).expect("seal v2");
        c2.publish().expect("publish 2");
        let rec2 = c2.record().expect("record 2");
        let (dev2, ino2) = rec2.identity();
        let text2 = std::fs::read_to_string(b.join("b").join(super::OWNER_TOKEN_FILE)).expect("m");
        assert_eq!(
            text2,
            format!("{}\n{dev2}:{ino2}\n", rec2.token().expect("token"))
        );

        let mut c3 = prepare_rootfs_target(&b, Path::new("c")).expect("prepare 3");
        let e = c3.seal(Some("NOT-HEX")).expect_err("invalid scope");
        assert_eq!(e.code(), ErrorCode::Internal);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・#2635: 印の解析は v1・v2・v3 だけを受け、3 行目が小文字 16 進 32 文字でない・4 行目がある・
    /// 末尾の改行が無いものは拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_2635_parse_marker_accepts_only_v1_v2_v3() {
        let token = "0123456789abcdef0123456789abcdef";
        let parse = |t: String| imp::parse_marker(t.as_bytes());
        let m = parse(format!("{token}\n7:9\n{SCOPE}\n")).expect("v3");
        assert_eq!(m.identity, Some((7, 9)));
        assert_eq!(m.scope.as_deref(), Some(SCOPE));
        let m = parse(format!("{token}\n7:9\n")).expect("v2");
        assert_eq!((m.identity, m.scope), (Some((7, 9)), None));
        let m = parse(token.to_owned()).expect("v1");
        assert_eq!((m.identity, m.scope), (None, None));
        for bad in [
            format!("{token}\n7:9\n{}\n", &SCOPE[..31]),
            format!("{token}\n7:9\n{}\n", SCOPE.to_uppercase()),
            format!("{token}\n7:9\n{SCOPE}\nextra\n"),
            format!("{token}\n7:9\n{SCOPE}"),
            format!("{token}\n7:9\n\n"),
            format!("{token}\n7:9\nzz\n"),
        ] {
            assert!(parse(bad.clone()).is_none(), "{bad:?}");
        }
    }
}
