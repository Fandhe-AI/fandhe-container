//! 起動オプション文書の置き場と読み書き(SUP-12・CLI-1・SEC-1・REPAIR-5・#2713)。
//!
//! # 役割と呼び出し文脈
//!
//! 文書の形は [`document`](super::document)。置き場所は `<state_root>/@container-options/<id>`(ディレクトリは
//! 0700、ファイルは 0600)で、`--root` と `<id>` だけから導く(supervisor の起動契約・`start_client`・ランチャーは
//! 変えない)。書くのは CLI の `create`、読むのは supervisor の `start`(`start_entry` の手順 2c)、消すのは CLI の
//! `delete`。ファイルが無ければ既定値で動く(plugin-cri や従来のコンテナは書かない)。ファイルがあって壊れている・
//! 権限が不正なら fail-closed で拒否する。
//!
//! # 外部入力の扱い
//!
//! 読み取りは symlink を辿らず(`O_NOFOLLOW`)、端末を制御端末にせず(`O_NOCTTY`)、FIFO で止まらない
//! (`O_NONBLOCK`)。開いた fd を fstat し、通常ファイル・所有者が実効 uid・group / other のビットなし・サイズが上限以下で
//! あることを確かめてから、上限つき(`take`)で読む。エラーの文言は固定の英語で、パス・errno を含めない。
//! 上限なしの待ち(FUSE 上の状態ルート等)は呼び出し側(`start_entry`)が期限つきの作業スレッドで包む(REPAIR-5)。
//!
//! # 残余(REPAIR-3)
//!
//! 同じ ID の `create` と `delete` は ID 単位のロック(`@container-options/@lock-<id>`。[`acquire_lock`])で直列化する
//! (並行 create で成功した側の文書を消さない)。plugin-cri の create は残骸を掃除しない
//! ため、CLI で作ったコンテナの delete 後の掃除に失敗した ID を CRI で作り直すと残骸が残りうるが、文書は作成世代
//! (`gen` レコード)を持ち、状態記録の annotations([`GENERATION_ANNOTATION`])と一致しない文書は採用しない
//! ([`select_document`]。#2713・SEC-1)。
//! Linux 以外では `Unimplemented` で拒否する(CLI の create は Linux のローカル実行のみ)。

use std::path::{Path, PathBuf};

use fandhe_container_core::traits::ContainerId;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::document::{ContainerOptionsDocument, OPTIONS_DOC_MAX_BYTES};

/// 状態ルート直下の文書ディレクトリ名(`@container-logs` と同じ命名)。
pub const OPTIONS_DIR_NAME: &str = "@container-options";

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

#[cfg(target_os = "linux")]
fn io_failed(_: std::io::Error) -> TraitError {
    err(ErrorCode::Internal, "container options file I/O failed")
}

/// 文書ディレクトリの絶対パス。
pub fn options_dir(root: &Path) -> PathBuf {
    root.join(OPTIONS_DIR_NAME)
}

/// 文書ファイルのパス。
pub fn options_path(root: &Path, id: &ContainerId) -> PathBuf {
    options_dir(root).join(id.as_str())
}

/// 書き込んだ文書の識別(巻き戻しで別の文書を消さないための inode 照合に使う)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenOptions {
    dev: u64,
    ino: u64,
}

/// 開いたファイルの fstat 相当の検査(純関数。値の注入で試験できる)。
pub fn check_file_meta(
    is_file: bool,
    owner_uid: u32,
    mode: u32,
    len: u64,
    expected_uid: u32,
) -> Result<(), TraitError> {
    if !is_file || owner_uid != expected_uid || mode & 0o077 != 0 {
        return Err(err(
            ErrorCode::PermissionDenied,
            "the container options file is not private to the current user",
        ));
    }
    if len > OPTIONS_DOC_MAX_BYTES as u64 {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the container options file is too large",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    use super::*;
    use crate::control::listener::{check_dir_meta, effective_uid};

    /// `<root>/@container-options/` を用意する(無ければ 0700 で作り、あれば所有者・権限・種別を検証する)。
    /// 戻り値は検証済みのディレクトリのパス。
    fn ensure_dir(root: &Path, uid: u32) -> Result<PathBuf, TraitError> {
        let dir = options_dir(root);
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            // 新しく作ったディレクトリのエントリ(状態ルート側)も永続化する。
            Ok(()) => sync_dir(root)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_failed(e)),
        }
        // symlink を辿らない lstat で検査する(差し替えられた symlink を拒否する)。
        let meta = std::fs::symlink_metadata(&dir).map_err(io_failed)?;
        check_dir_meta(meta.is_dir(), meta.uid(), meta.mode(), uid)?;
        Ok(dir)
    }

    /// 文書を新規作成する(既存なら `AlreadyExists`)。0600・`O_EXCL`・`O_NOFOLLOW`。
    pub fn write_new(
        root: &Path,
        id: &ContainerId,
        doc: &ContainerOptionsDocument,
    ) -> Result<WrittenOptions, TraitError> {
        let uid = effective_uid()?;
        let dir = ensure_dir(root, uid)?;
        let path = dir.join(id.as_str());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(crate::container_options::env::O_NOCTTY | no_follow())
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    err(
                        ErrorCode::AlreadyExists,
                        "the container options file already exists",
                    )
                } else {
                    io_failed(e)
                }
            })?;
        let meta = file.metadata().map_err(io_failed)?;
        let written = WrittenOptions {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let result = file
            .write_all(&doc.encode())
            .and_then(|()| file.sync_all())
            .map_err(io_failed)
            // 文書の中身に加えて、親ディレクトリのエントリも永続化してから成功を返す。
            .and_then(|()| sync_dir(&dir));
        if let Err(e) = result {
            // 書きかけを残さない(自分が作った inode だけを消す)。
            let _ = remove_if_same(root, id, &written);
            return Err(e);
        }
        Ok(written)
    }

    /// ID 単位の排他ロック(`<dir>/@lock-<id>`。`@` は ID に使えないので文書名と衝突しない)。
    /// drop で解放する。ロックファイルは [`OptionsLock::remove_lock_file`] で消す(消さなければ残る)。
    #[derive(Debug)]
    pub struct OptionsLock {
        /// 保持するだけ(drop で flock が解放される)。
        _file: File,
        path: PathBuf,
    }

    impl OptionsLock {
        /// ロックを保持したままロックファイルを消す(取得側は取得後に実体の一致を確かめるので、孤立 inode を掴んだ側は再取得する)。
        pub fn remove_lock_file(self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// 取得の再試行間隔。
    const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(5);

    /// ID 単位のロックを `timeout` まで待って取る(期限切れは `Timeout`)。
    ///
    /// `try_lock` と短い sleep の繰り返しで、他者が保持し続けても無期限に待たない(REPAIR-5)。
    /// 取れたあと、パスの実体が掴んだ fd と同じ(dev・ino)であることを確かめ、違えば(他者がロックファイルを消した)取り直す。
    /// open 自体が止まる(FUSE 等)場合は呼び出し側が作業スレッドで包む。
    pub fn acquire_lock(
        root: &Path,
        id: &ContainerId,
        timeout: std::time::Duration,
    ) -> Result<OptionsLock, TraitError> {
        let uid = effective_uid()?;
        let dir = ensure_dir(root, uid)?;
        let path = dir.join(format!("@lock-{}", id.as_str()));
        if path.file_name().is_none_or(|n| n.len() > 255) {
            return Err(err(
                ErrorCode::InvalidArgument,
                "the container id is too long for the options lock",
            ));
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(crate::container_options::env::O_NOCTTY | no_follow())
                .open(&path)
                .map_err(io_failed)?;
            match file.try_lock() {
                Ok(()) => {
                    let current = std::fs::symlink_metadata(&path).ok();
                    let held = file.metadata().map_err(io_failed)?;
                    if current.is_some_and(|m| m.dev() == held.dev() && m.ino() == held.ino()) {
                        return Ok(OptionsLock { _file: file, path });
                    }
                    // 孤立した inode を掴んだ。取り直す。
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(e)) => return Err(io_failed(e)),
            }
            if std::time::Instant::now() >= deadline {
                return Err(err(
                    ErrorCode::Timeout,
                    "the container options lock was not acquired in time",
                ));
            }
            std::thread::sleep(LOCK_POLL);
        }
    }

    /// 親ディレクトリのエントリを永続化する(クラッシュ後に文書が消えて既定値に戻るのを防ぐ。OCI-5・SUP-12)。
    fn sync_dir(dir: &Path) -> Result<(), TraitError> {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(io_failed)
    }

    /// `O_NOFOLLOW`(`logs::rotating` と同じ値の取り方に揃える)。
    fn no_follow() -> i32 {
        crate::logs::rotating::NOFOLLOW_FLAG
    }

    /// 文書を読む。無ければ `Ok(None)`。所有者・権限・種別・サイズが不正なら拒否する。
    pub fn read(
        root: &Path,
        id: &ContainerId,
    ) -> Result<Option<ContainerOptionsDocument>, TraitError> {
        let path = options_path(root, id);
        let file = match crate::logs::rotating::open_read_nofollow_nonblocking(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // symlink(ELOOP)・その他の open 失敗は拒否する(パス・errno は出さない)。
            Err(_) => {
                return Err(err(
                    ErrorCode::InvalidArgument,
                    "the container options file cannot be opened",
                ));
            }
        };
        let meta = file.metadata().map_err(io_failed)?;
        check_file_meta(
            meta.is_file(),
            meta.uid(),
            meta.mode(),
            meta.len(),
            effective_uid()?,
        )?;
        read_bounded(file).map(Some)
    }

    fn read_bounded(file: File) -> Result<ContainerOptionsDocument, TraitError> {
        let mut bytes = Vec::new();
        file.take(OPTIONS_DOC_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_failed)?;
        ContainerOptionsDocument::decode(&bytes)
    }

    /// `written` と同じ inode のときだけ消す(巻き戻し用)。違う・無いときは何もしない。
    pub fn remove_if_same(
        root: &Path,
        id: &ContainerId,
        written: &WrittenOptions,
    ) -> Result<(), TraitError> {
        let path = options_path(root, id);
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.dev() == written.dev && m.ino() == written.ino => {
                std::fs::remove_file(&path).map_err(io_failed)
            }
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_failed(e)),
        }
    }

    /// 作成世代の識別子(`/dev/urandom` の 16 バイトを 16 進にした 32 文字)を作る。
    pub fn new_generation() -> Result<String, TraitError> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(io_failed)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// 文書を消す(無ければ成功)。delete と、record の無い残骸の掃除に使う。
    pub fn remove(root: &Path, id: &ContainerId) -> Result<(), TraitError> {
        match std::fs::remove_file(options_path(root, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_failed(e)),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    fn unsupported() -> TraitError {
        err(
            ErrorCode::Unimplemented,
            "container options files are not supported on this platform",
        )
    }

    pub fn write_new(
        _root: &Path,
        _id: &ContainerId,
        _doc: &ContainerOptionsDocument,
    ) -> Result<WrittenOptions, TraitError> {
        Err(unsupported())
    }

    pub fn read(
        _root: &Path,
        _id: &ContainerId,
    ) -> Result<Option<ContainerOptionsDocument>, TraitError> {
        Err(unsupported())
    }

    pub fn remove_if_same(
        _root: &Path,
        _id: &ContainerId,
        _written: &WrittenOptions,
    ) -> Result<(), TraitError> {
        Err(unsupported())
    }

    pub fn remove(_root: &Path, _id: &ContainerId) -> Result<(), TraitError> {
        Err(unsupported())
    }

    pub fn new_generation() -> Result<String, TraitError> {
        Err(unsupported())
    }

    /// ID 単位のロック(Linux 以外では取得できない)。
    #[derive(Debug)]
    pub struct OptionsLock;

    impl OptionsLock {
        pub fn remove_lock_file(self) {}
    }

    pub fn acquire_lock(
        _root: &Path,
        _id: &ContainerId,
        _timeout: std::time::Duration,
    ) -> Result<OptionsLock, TraitError> {
        Err(unsupported())
    }
}

pub use imp::{OptionsLock, acquire_lock, new_generation, read, remove, remove_if_same, write_new};

/// 作成世代の識別子を載せる状態記録の annotations のキー(#2713・SEC-1)。
///
/// CLI の create が文書(`gen` レコード)と状態記録の両方へ同じ値を書く。非秘密の識別子で、利用者の label とは
/// 名前空間で分ける。
pub const GENERATION_ANNOTATION: &str = "io.fandhe.container.options-generation";

/// 読んだ文書を、状態記録が持つ作成世代と照合して採否を決める(純関数。SUP-12・SEC-1・#2713)。
///
/// - 文書あり・世代が記録と一致: 採用する
/// - 文書あり・世代が無い、または記録の値と違う: 別のコンテナ(同じ ID の前の世代・plugin-cri 経由で作られた記録)の
///   残骸なので採用しない(`None`。前の世代の env・ulimit・`--ipc=host` を次のコンテナへ適用しない)
/// - 文書なし・記録が世代を持つ: 文書が失われているため `FailedPrecondition`(オプションを黙って落とさない)
/// - 文書なし・記録も世代なし: 既定値(`None`)
pub fn select_document(
    doc: Option<ContainerOptionsDocument>,
    recorded: Option<&str>,
) -> Result<Option<ContainerOptionsDocument>, TraitError> {
    match (doc, recorded) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(err(
            ErrorCode::FailedPrecondition,
            "the container options file is missing",
        )),
        (Some(d), recorded) => match (d.generation(), recorded) {
            (Some(g), Some(r)) if g == r => Ok(Some(d)),
            _ => Ok(None),
        },
    }
}

/// 状態記録と照合した、launch 時の env 上書き(`KEY=VALUE`)を返す。無い・別世代の文書なら空(#2713・SUP-12)。
///
/// exec(healthcheck を含む)が launch と同じ env を使うための入口(`exec::run_command_with_pidfd_env` の
/// `launch_env`)。文書の I/O は止まりうるため、呼び出し側は期限つきの作業スレッドで包む(REPAIR-5)。
pub fn launch_env_for(
    root: &Path,
    record: &fandhe_container_core::traits::StateRecord,
) -> Result<Vec<String>, TraitError> {
    let recorded = record.annotations().get(GENERATION_ANNOTATION);
    let doc = read(root, record.status().id())?;
    Ok(select_document(doc, recorded)?
        .map(|d| d.env().to_vec())
        .unwrap_or_default())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fcopt-store-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn doc() -> ContainerOptionsDocument {
        ContainerOptionsDocument::new(
            vec!["nofile=1024:2048".into()],
            vec!["A=1".into()],
            None,
            None,
            vec![],
        )
        .expect("doc")
    }

    /// SUP-12・SEC-1: 0600 のファイルが 0700 のディレクトリに作られ、読み戻せる。無ければ `None`。
    #[test]
    fn sup12_options_store_write_read_modes() {
        let root = tmp("rw");
        assert_eq!(read(&root, &id("c1")).expect("read"), None);
        write_new(&root, &id("c1"), &doc()).expect("write");
        let dir_mode = std::fs::metadata(options_dir(&root)).expect("dir").mode() & 0o777;
        let file_mode = std::fs::metadata(options_path(&root, &id("c1")))
            .expect("file")
            .mode()
            & 0o777;
        assert_eq!((dir_mode, file_mode), (0o700, 0o600));
        assert_eq!(read(&root, &id("c1")).expect("read"), Some(doc()));
        assert_eq!(
            std::fs::read(options_path(&root, &id("c1"))).expect("bytes"),
            doc().encode()
        );
        let e = write_new(&root, &id("c1"), &doc()).expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        remove(&root, &id("c1")).expect("remove");
        remove(&root, &id("c1")).expect("remove again");
        assert_eq!(read(&root, &id("c1")).expect("read"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: symlink・group 可読・FIFO・上限超過の文書は読まずに拒否する(FIFO で止まらない)。
    #[test]
    fn sec1_options_store_read_rejections() {
        let root = tmp("rej");
        write_new(&root, &id("seed"), &doc()).expect("seed");
        let dir = options_dir(&root);
        // symlink
        std::fs::write(root.join("target"), doc().encode()).expect("target");
        symlink(root.join("target"), dir.join("lnk")).expect("symlink");
        assert_eq!(
            read(&root, &id("lnk")).expect_err("symlink").code(),
            ErrorCode::InvalidArgument
        );
        // 0644
        write_new(&root, &id("open"), &doc()).expect("write");
        std::fs::set_permissions(dir.join("open"), std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert_eq!(
            read(&root, &id("open")).expect_err("mode").code(),
            ErrorCode::PermissionDenied
        );
        // 上限超過
        let big = dir.join("big");
        std::fs::write(&big, vec![b'x'; OPTIONS_DOC_MAX_BYTES + 1]).expect("big");
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            read(&root, &id("big")).expect_err("big").code(),
            ErrorCode::InvalidArgument
        );
        // 壊れた中身
        let junk = dir.join("junk");
        std::fs::write(&junk, b"nonsense").expect("junk");
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            read(&root, &id("junk")).expect_err("junk").message(),
            "options document has an unknown header"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: `remove_if_same` は別の inode(差し替えられた文書)を消さない。
    #[test]
    fn sec1_options_store_remove_if_same_keeps_other_inode() {
        let root = tmp("same");
        let written = write_new(&root, &id("c1"), &doc()).expect("write");
        let path = options_path(&root, &id("c1"));
        // 元の inode を別名で生かしたまま差し替える(解放された inode 番号の再利用で同一と見なされないようにする)。
        std::fs::hard_link(&path, root.join("keep-old-inode")).expect("link");
        std::fs::remove_file(&path).expect("unlink");
        write_new(&root, &id("c1"), &doc()).expect("rewrite");
        remove_if_same(&root, &id("c1"), &written).expect("noop");
        assert!(path.exists(), "a different inode must survive");
        let current = std::fs::metadata(&path).expect("meta");
        let same = WrittenOptions {
            dev: current.dev(),
            ino: current.ino(),
        };
        remove_if_same(&root, &id("c1"), &same).expect("remove");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SUP-12・REPAIR-5: ID 単位のロックは同じ ID の二重取得を期限で諦め、別 ID とは干渉せず、解放後は取れる。
    #[test]
    fn sup12_options_lock_is_per_id_and_bounded() {
        let root = tmp("lock");
        let short = std::time::Duration::from_millis(50);
        let first = acquire_lock(&root, &id("c1"), short).expect("lock");
        let e = acquire_lock(&root, &id("c1"), short).expect_err("held");
        assert_eq!(e.code(), ErrorCode::Timeout);
        acquire_lock(&root, &id("c2"), short).expect("other id");
        first.remove_lock_file();
        assert!(!options_dir(&root).join("@lock-c1").exists());
        acquire_lock(&root, &id("c1"), short).expect("after release");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: 検査の純関数(所有者違い・サイズ超過)。
    #[test]
    fn sec1_options_check_file_meta() {
        assert!(check_file_meta(true, 1000, 0o100600, 10, 1000).is_ok());
        assert_eq!(
            check_file_meta(true, 0, 0o100600, 10, 1000)
                .expect_err("owner")
                .code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            check_file_meta(false, 1000, 0o100600, 10, 1000)
                .expect_err("kind")
                .code(),
            ErrorCode::PermissionDenied
        );
    }

    /// SUP-12・SEC-1(#2713): 文書は状態記録の作成世代と一致したときだけ採用する。
    #[test]
    fn sup12_select_document_checks_generation() {
        let doc = ContainerOptionsDocument::new(vec![], vec!["A=1".into()], None, None, vec![])
            .expect("doc");
        let with_gen = doc.clone().with_generation("g1".into()).expect("gen");
        assert_eq!(
            select_document(Some(with_gen.clone()), Some("g1")).expect("match"),
            Some(with_gen.clone())
        );
        // 別世代・記録に世代なし・文書に世代なしは、残骸として採用しない。
        assert_eq!(
            select_document(Some(with_gen.clone()), Some("g2")).expect("x"),
            None
        );
        assert_eq!(select_document(Some(with_gen), None).expect("x"), None);
        assert_eq!(select_document(Some(doc), Some("g1")).expect("x"), None);
        assert_eq!(select_document(None, None).expect("none"), None);
        let e = select_document(None, Some("g1")).expect_err("missing");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    }
}
