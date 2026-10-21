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
//! 保証しない。公開済みで状態の無い `rootfs`（公開後・状態作成前のクラッシュ）は利用者のデータと
//! 見分けられず、通常の create と共有する排他も無いため対象外で、手動で回復する。Linux 以外は作成自体が
//! `Unimplemented` で木が生じず、[`reap_stale_unpacks`] も `Unimplemented` を返す（REPAIR-3）。
//! 起動時の照合への配線（`StateStore::list` で列挙した bundle への呼び出し）は #2315 で扱う。
//!
//! 本番の展開器（manifest からレイヤーの blob・mediaType・diff_id を引いて oci へ渡すアダプタ）と
//! CLI / plugin の配線は未実装である（REPAIR-3。#2315 の配線で扱う）。

use std::path::{Component, Path, PathBuf};

use super::image_refs::ImageManifestDigest;
use crate::traits::{ErrorCode, ImageRootfsRecord, TraitError};

/// 非公開の展開先の名前の接頭辞。`root.path` の要素としてこの接頭辞を持つ名前は、展開中の非公開の木を
/// 通常の create が rootfs として採用することを防ぐため、`prepare_rootfs_target` と `check_rootfs` が拒否する
/// （OCI-7: 使用中 rootfs の保持。展開中の木は名前を列挙でき、別 ID の create が指せてしまう）。
/// 記録（`ImageRootfsRecord`）の経路検証と同じ定数を使い、単一の真実源にする（#2378）。
pub(super) const STAGING_PREFIX: &str = crate::traits::state_store::IMAGE_ROOTFS_STAGING_PREFIX;

/// 作った rootfs の直下に置く所有トークンの印のファイル名。delete が記録のトークンと内容を照合し、
/// 一致したときだけ消す（作成世代の識別。inode の再利用で別のディレクトリを誤認しない。OCI-7・SEC-1・#2378）。
#[cfg(target_os = "linux")]
const OWNER_TOKEN_FILE: &str = ".fandhe-container-rootfs-owner";

/// 後始末で権限を補正しながら辿る項目数の上限（無制限の走査を避ける。展開側の既定上限と同程度）。
#[cfg(target_os = "linux")]
const CLEANUP_MAX_ENTRIES: usize = 1_000_000;
/// 後始末で辿るディレクトリの深さの上限。
#[cfg(target_os = "linux")]
const CLEANUP_MAX_DEPTH: usize = 256;

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
    /// 種別・所有者・mode・同一性のいずれかを確かめられず残した木。
    pub kept_unverified: Vec<std::ffi::OsString>,
    /// 回収を試みて削除に失敗した木（一部が消えて残っていることがある）。
    pub failed: Vec<std::ffi::OsString>,
    /// 走査の上限で打ち切り、残りを調べなかったか。
    pub truncated: bool,
    /// 親ディレクトリの列挙そのものに失敗した（`read_dir` の失敗・列挙中のエラー）か。
    /// 失敗した範囲に木が残っていても見えないため、回収は不完全として扱う（REPAIR-4）。
    pub scan_failed: bool,
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
/// - 展開中の rootfs は、Linux では最終の `root.path` とは別の非公開の名前にあり、展開の成功後に core が
///   最終の名前へ公開する（展開中に別の create が rootfs を使用中と見なして成功する競合を防ぐ。OCI-7）
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
    prepare_rootfs_target_with(bundle, root_path, &|reap| reap())
}

/// 回収の実処理を包む関数。回収を呼んだ結果をそのまま返す。
pub(super) type ReapHook<'a> = &'a dyn Fn(&dyn Fn() -> StagingReclamation) -> StagingReclamation;

/// [`prepare_rootfs_target`] の本体。`reap_hook` は回収の実処理（走査と再帰削除）を引数に取って呼ぶ関数で、
/// 呼び出し元が計測区間で包める（その後の作成が失敗しても、回収の結果と所要時間を記録できる。REPAIR-4）。
pub(super) fn prepare_rootfs_target_with(
    bundle: &Path,
    root_path: &Path,
    reap_hook: ReapHook<'_>,
) -> Result<CreatedRootfs, TraitError> {
    let parts = split_target(bundle, root_path)?;
    let Some((last, parents)) = parts.split_last() else {
        return Err(invalid("rootfs must be a directory below the bundle"));
    };
    let parents: Vec<&std::ffi::OsStr> = parents.iter().map(|p| p.as_os_str()).collect();
    let (backing, reclamation) = imp::create_dir(bundle, &parents, last, reap_hook)?;
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
    imp::reap_stale(bundle, &parents)
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
    pub(super) fn publish(&mut self) -> Result<(), TraitError> {
        imp::publish(&mut self.backing)
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
    pub(super) fn seal(&mut self) -> Result<(), TraitError> {
        imp::seal(&mut self.backing)
    }

    /// rootfs を消す。
    ///
    /// 作成時に固定した親（Linux は fd）の下で、末尾が作ったときと同じディレクトリ（dev・ino）で
    /// なければ削除しない（`FailedPrecondition`。差し替えられた先 = bundle 外の実体を消さない fail-closed）。
    /// Linux 以外は同一性を保証できないため常に `FailedPrecondition` で拒否する。
    pub(super) fn remove(self) -> Result<(), TraitError> {
        imp::remove(&self.path, self.backing)
    }
}

/// 状態レコードに記録された rootfs を消す（delete が状態削除の成功後に呼ぶ。OCI-7・OCI-5・#2378）。
///
/// 呼び出し元は `oci_runtime::delete`。`bundle` はレコードの bundle、`rec` は create が記録した経路と実体の
/// 同一性。bundle は作成時と同じく追従して開き、記録の経路は中間要素をリンク非追従の fd 相対で辿る。
/// 末尾が記録の (dev, ino) と一致するディレクトリのときだけ中身ごと消す。symlink・ディレクトリでないもの・
/// 同一性の不一致は `FailedPrecondition` で拒否し何も消さない（fail-closed）。どの段でも `ENOENT` なら
/// [`RecordedRootfsRemoval::NotPresent`]。Linux 以外は同一性を保証できないため `Unimplemented`。
pub(super) fn remove_recorded_rootfs(
    bundle: &Path,
    rec: &ImageRootfsRecord,
) -> Result<RecordedRootfsRemoval, TraitError> {
    imp::remove_recorded(bundle, rec)
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
        CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, ImageRootfsRecord, RecordedRootfsRemoval,
        STAGING_PREFIX, StagingReclamation, invalid, refuse, remove_failed,
    };
    use crate::sys::{self, SysError};
    use crate::traits::{ErrorCode, TraitError};

    /// 非公開の展開先の名前の連番（同一プロセス内の衝突を避ける。別プロセスとは pid で分ける）。
    static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 検証済みの親ディレクトリの fd と、その下の rootfs の名前・同一性。
    ///
    /// 作成直後は `current` が非公開の展開先の名前で、`publish` 後に最終の名前 `final_name` になる。
    #[derive(Debug)]
    pub(super) struct Backing {
        parent: OwnedFd,
        final_name: CString,
        current: CString,
        /// 作った rootfs ディレクトリそのものの fd（展開器へ `/proc/self/fd/N` で渡す）。
        dir: OwnedFd,
        identity: (u64, u64),
        /// `seal` が書いた所有トークン（小文字 16 進 32 文字）。
        token: Option<String>,
        /// 展開先のディレクトリ自体への排他の `flock`。生きている間は他の回収側から「持ち主あり」に見え、
        /// プロセスが落ちれば OS が外す（#2379・OCI-7）。`Backing` と同じ寿命で保持する。
        _lock: File,
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

    pub(super) fn seal(b: &mut Backing) -> Result<(), TraitError> {
        let token = new_token()?;
        // 展開器は rootfs 自身の mode を変えてよい（契約は禁止していない）。所有者の write・search 権限が無いと
        // 印を作れず、従来成功した create が失敗する退行になるため、固定した fd の実体（`/proc/self/fd/N` は
        // 経路を再解決しない）の mode を一時的に補って印を書き、成功・失敗のどちらでも元の mode へ戻す。
        let proc_dir = format!("/proc/self/fd/{}", b.dir.as_raw_fd());
        let original = fstat(b.dir.as_fd())
            .map(|(_, _, _, mode)| mode & 0o7777)
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to stat rootfs"))?;
        let widened = original | 0o300;
        if widened != original {
            std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(widened)).map_err(
                |_| TraitError::new(ErrorCode::Internal, "failed to write rootfs owner token"),
            )?;
        }
        let written = write_marker(&proc_dir, &token);
        if widened != original {
            let restored =
                std::fs::set_permissions(&proc_dir, std::fs::Permissions::from_mode(original));
            written?;
            restored.map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to restore rootfs mode")
            })?;
        } else {
            written?;
        }
        b.token = Some(token);
        Ok(())
    }

    /// 固定した rootfs（`proc_dir`）の直下へ所有トークンの印を新規作成して書く。
    fn write_marker(proc_dir: &str, token: &str) -> Result<(), TraitError> {
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
        f.write_all(token.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to write rootfs owner token")
            })?;
        Ok(())
    }

    /// 固定した rootfs の fd 直下の印のファイルが `expected` と一致するか（リンク非追従・通常ファイルのみ・
    /// FIFO で止まらない）。
    fn token_matches(root: BorrowedFd<'_>, expected: &str) -> bool {
        use std::io::Read;
        // 先に `O_PATH|O_NOFOLLOW` で実体を固定し、fstat で通常ファイルと確かめてから、固定済みの fd を
        // 読み取りで開き直す。種別確認が open より前のため、デバイス・FIFO への差し替えでも open の
        // 副作用（端末の取得・ブロック）が起きない（SEC-1）。
        let Ok(name) = CString::new(super::OWNER_TOKEN_FILE) else {
            return false;
        };
        let Ok(pinned) = sys::open_path_nofollow_at(root, &name) else {
            return false;
        };
        let Ok((_, _, _, mode)) = fstat(pinned.as_fd()) else {
            return false;
        };
        // S_IFMT = 0o170000・S_IFREG = 0o100000。
        if mode & 0o170_000 != 0o100_000 {
            return false;
        }
        let Ok(fd) = sys::reopen_pinned_read_nonblock(pinned.as_fd()) else {
            return false;
        };
        let f = File::from(fd);
        if !f.metadata().is_ok_and(|m| m.is_file() && m.len() <= 64) {
            return false;
        }
        let mut buf = Vec::new();
        f.take(65).read_to_end(&mut buf).is_ok() && buf == expected.as_bytes()
    }

    pub(super) fn unpack_path(_path: &Path, b: &Backing) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", b.dir.as_raw_fd()))
    }

    pub(super) fn publish(b: &mut Backing) -> Result<(), TraitError> {
        if b.current == b.final_name {
            return Ok(());
        }
        sys::rename_noreplace_at(
            b.parent.as_fd(),
            &b.current,
            b.parent.as_fd(),
            &b.final_name,
        )
        .map_err(|e| match e {
            SysError::Os(n) if n == sys::EEXIST || n == sys::ENOTEMPTY => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to publish rootfs"),
        })?;
        b.current = b.final_name.clone();
        // 改名した先を固定済みの親から開き直し、展開した実体（保持中の fd の dev・ino）と一致することを確認する。
        // 一致しなければ公開した名前は別の実体を指しており、成功を装わず拒否する。
        let same = open_dir(b.parent.as_fd(), &b.final_name)
            .ok()
            .and_then(|fd| fstat(fd.as_fd()).ok())
            .is_some_and(|(dev, ino, is_dir, _)| is_dir && (dev, ino) == b.identity);
        if same { Ok(()) } else { Err(refuse()) }
    }

    /// 経路を今ここで解決した実体が、展開した実体（保持中の fd の dev・ino）か。
    pub(super) fn is_published(b: &Backing) -> bool {
        b.current == b.final_name
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
    ) -> Result<StagingReclamation, TraitError> {
        let cur = open_parent(bundle, parents)?;
        Ok(reap_under(cur.as_fd()))
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
    fn reap_under(cur: BorrowedFd<'_>) -> StagingReclamation {
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
            match reap_one(cur, &name) {
                Reap::Reclaimed => result.reclaimed.push(name),
                Reap::Alive => result.kept_alive.push(name),
                Reap::Unverified => result.kept_unverified.push(name),
                Reap::Failed => result.failed.push(name),
                Reap::Gone => {}
            }
        }
        result
    }

    enum Reap {
        Reclaimed,
        Alive,
        Unverified,
        Failed,
        /// 調べている間に消えた（別の回収側が先に消した）。
        Gone,
    }

    /// 1 つの候補を調べ、持ち主がいないと確かめられたときだけ消す（確かめられなければ残す）。
    fn reap_one(cur: BorrowedFd<'_>, name: &OsStr) -> Reap {
        let Ok(cname) = cstr(name) else {
            return Reap::Unverified;
        };
        let fd = match sys::open_dir_path_nofollow(Some(cur), &cname) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => return Reap::Gone,
            Err(_) => return Reap::Unverified,
        };
        let identity = match fstat(fd.as_fd()) {
            Ok((dev, ino, true, mode))
                if mode & 0o777 == 0o700 && fd_owner(fd.as_fd()) == Some(sys::effective_uid()) =>
            {
                (dev, ino)
            }
            _ => return Reap::Unverified,
        };
        // O_PATH の fd には flock できないため、`/proc/self/fd/N` から開き直したディレクトリにロックを掛ける。
        let Ok(lock) = File::open(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
            return Reap::Unverified;
        };
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Reap::Alive,
            Err(_) => return Reap::Unverified,
        }
        // ロックを保持したまま名前から開き直し、検査した実体と同じことを確かめる（差し替え・別の回収側の
        // 取り直しを弾く）。ロックはこの関数を出るまで保持する。
        match sys::open_dir_path_nofollow(Some(cur), &cname) {
            Ok(again) => match fstat(again.as_fd()) {
                Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
                _ => return Reap::Unverified,
            },
            Err(SysError::Os(n)) if n == sys::ENOENT => return Reap::Gone,
            Err(_) => return Reap::Unverified,
        }
        match remove_tree_at(cur, &cname, identity, Owner::Unchecked) {
            Ok(_) => Reap::Reclaimed,
            Err(_) => Reap::Failed,
        }
    }

    pub(super) fn create_dir(
        bundle: &Path,
        parents: &[&OsStr],
        last: &OsStr,
        reap_hook: super::ReapHook<'_>,
    ) -> Result<(Backing, StagingReclamation), TraitError> {
        let cur = open_parent(bundle, parents)?;
        // 同じ親の下に残った、持ち主のいない展開途中の木を先に回収する（PID の再利用による名前の衝突も解く）。
        let reclamation = reap_hook(&|| reap_under(cur.as_fd()));
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
        let name = cstr(OsStr::new(&staging))?;
        sys::mkdir_at(cur.as_fd(), &name, 0o700).map_err(|e| match e {
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
        let opened = open_dir(cur.as_fd(), &name).ok().and_then(|fd| {
            fstat(fd.as_fd())
                .ok()
                .map(|(dev, ino, is_dir, _)| (fd, dev, ino, is_dir))
        });
        // mkdirat と open の間に、親へ書ける別プロセスが別の実体へ差し替えうる。採用する実体は、自分（実効 uid）
        // 所有・権限 0700・空のディレクトリに限る（既存データへ展開せず、失敗時の再帰削除が他人のデータに
        // 及ばない）。0700（setgid 親の下の 02700 も許容）で自分の所有なら、検証後に他者は中身を足せない（root を除く）。
        let owned_empty = opened.as_ref().is_some_and(|(fd, _, _, _)| {
            fstat(fd.as_fd()).is_ok_and(|(_, _, is_dir, mode)| is_dir && mode & 0o777 == 0o700)
                && fd_owner(fd.as_fd()) == Some(sys::effective_uid())
                && dir_is_empty(fd.as_fd())
        });
        let (dir, identity) = match opened {
            Some((fd, dev, ino, true)) if owned_empty => (fd, (dev, ino)),
            _ => {
                // 作った直後に差し替えられた。差し替えられた実体は自分のものと確認できないため消さない
                // （空ディレクトリでなければ `remove_dir_at` は失敗する。best effort で戻すのは空の場合だけ）。
                let _ = sys::remove_dir_at(cur.as_fd(), &name);
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "created rootfs is not a directory",
                ));
            }
        };
        // 展開先自体に排他ロックを取る。取れない・取った後に名前の実体が変わっていれば、直前に回収側が
        // 空の木を取った（持ち主はその回収側）ので、後始末せず失敗する。再試行で成功する（#2379）。
        let reclaimed_concurrently = || {
            TraitError::new(
                ErrorCode::Internal,
                "rootfs staging was reclaimed concurrently",
            )
        };
        let lock = File::open(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to lock rootfs staging"))?;
        lock.try_lock().map_err(|_| reclaimed_concurrently())?;
        match open_dir(cur.as_fd(), &name)
            .ok()
            .and_then(|fd| fstat(fd.as_fd()).ok())
        {
            Some((dev, ino, true, _)) if (dev, ino) == identity => {}
            _ => return Err(reclaimed_concurrently()),
        }
        Ok((
            Backing {
                parent: cur,
                final_name,
                current: name,
                dir,
                identity,
                token: None,
                _lock: lock,
            },
            reclamation,
        ))
    }

    pub(super) fn identity(b: &Backing) -> Result<(u64, u64), TraitError> {
        Ok(b.identity)
    }

    pub(super) fn remove(_path: &Path, b: Backing) -> Result<(), TraitError> {
        // 既に無ければ消す物が無い（`NotPresent` も成功）。
        remove_tree_at(b.parent.as_fd(), &b.current, b.identity, Owner::Unchecked).map(|_| ())
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
        match fstat(root.as_fd()) {
            Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
            _ => return Err(refuse()),
        }
        // 作成世代の照合（inode の再利用で作り直された別のディレクトリを消さない）。記録欠落・不一致・
        // 印の欠落はいずれも拒否する（fail-closed）。
        if let Owner::Token(expected) = owner
            && !expected.is_some_and(|t| token_matches(root.as_fd(), t))
        {
            return Err(refuse());
        }
        let root_dev = fstat(root.as_fd())
            .map(|(d, _, _, _)| d)
            .map_err(|_| remove_failed())?;
        // rootfs 自身がマウントポイントなら（親と別のマウント）マウント元を消さないよう拒否する。
        // 下位の bind mount は、再帰の各エントリを開くたびに `mnt_id` を照合して跨がない（検査後に足された
        // マウントも、経路の snapshot に依存せず fd の実体で拒否する。fail-closed）。
        let root_mnt = mount_id(root.as_fd()).ok_or_else(refuse)?;
        if mount_id(parent) != Some(root_mnt) {
            return Err(refuse());
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
    ) -> Result<RecordedRootfsRemoval, TraitError> {
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
                return remove_tree_at(
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
        let text =
            std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd())).ok()?;
        crate::oci_runtime::mountinfo_identity::parse_fdinfo_mnt_id(&text)
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
        for entry in std::fs::read_dir(&proc_path).map_err(|_| remove_failed())? {
            let entry = entry.map_err(|_| remove_failed())?;
            *seen += 1;
            if *seen > CLEANUP_MAX_ENTRIES {
                return Err(remove_failed());
            }
            let name = cstr(&entry.file_name())?;
            let child = match sys::open_path_nofollow_at(dir, &name) {
                Ok(fd) => fd,
                Err(SysError::Os(n)) if n == sys::ENOENT => continue,
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
        }
        Ok(())
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

    use super::{ImageRootfsRecord, RecordedRootfsRemoval, StagingReclamation, refuse};
    use crate::traits::{ErrorCode, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing;

    pub(super) fn unpack_path(path: &Path, _b: &Backing) -> PathBuf {
        path.to_path_buf()
    }

    pub(super) fn publish(_b: &mut Backing) -> Result<(), TraitError> {
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
    ) -> Result<StagingReclamation, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "reclaiming image rootfs staging is not supported on this OS yet",
        ))
    }

    pub(super) fn remove(_path: &Path, _b: Backing) -> Result<(), TraitError> {
        Err(refuse())
    }

    /// 作成自体が拒否される（`create_dir` は Unimplemented）ため到達しない。
    pub(super) fn seal(_b: &mut Backing) -> Result<(), TraitError> {
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
        c.seal().expect("seal");
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
        c.seal().expect("seal must not fail on a read-only rootfs");
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
        let e = c.seal().expect_err("exists");
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
        c.seal().expect("seal");
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

    /// SEC-1・OCI-7: 所有印が FIFO に差し替えられても open せず（ブロックせず）拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_non_regular_marker() {
        let b = tmp("marker-fifo");
        let rec = published_record(&b, "rootfs");
        let root = b.join("rootfs");
        let marker = root.join(super::OWNER_TOKEN_FILE);
        std::fs::remove_file(&marker).expect("rm marker");
        let st = std::process::Command::new("mkfifo")
            .arg(&marker)
            .status()
            .expect("mkfifo");
        assert!(st.success());
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
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(st.success());
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
        assert!(r.reclaimed.is_empty());
        assert_eq!(
            r.kept_unverified,
            vec![
                std::ffi::OsString::from(".fandhe-unpack-1-1"),
                ".fandhe-unpack-2-2".into(),
                ".fandhe-unpack-3-3".into()
            ]
        );
        assert!(outside.join("marker").exists());
        assert!(b.join(".fandhe-unpack-2-2").is_file());
        assert!(wide.join("sub/f").exists());
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
}
