//! イメージつき create の「進行中」を表すイメージストア単位のゲート（OCI-7・OCI-5・CORE-1・#2495）。
//!
//! # 役割と呼び出し元
//!
//! 未確定のコンテナ参照（`register` 済みで `bind` 前）の回収は「その ID の create が進行中でない」
//! ことを前提にする（`reconcile.rs`・`container_ref.rs`）。常駐デーモンの無い CLI（CORE-1）には
//! 「起動時に 1 回」の保証点が無いため、root 直下の固定名ファイル `@create-gate` への OS ロックで保証する。
//!
//! - イメージつき create の呼び出し側（cli の `create`）は、`register` から `bind` / 巻き戻しまでの間
//!   [`ImageStore::enter_container_create`] の [`ContainerCreatePass`]（共有ロック）を保持する
//! - 未確定参照を回収する側は [`ImageStore::quiesce_container_creates`] の [`CreateQuiescence`]
//!   （排他ロック）を取れたときだけ回収する。取れた＝進行中の create が 0 件。プロセスが落ちれば
//!   カーネルがロックを外すので、クラッシュした create の参照は回収可能になる
//! - 排他が期限内に取れなければ回収しない（余分に残す側に誤る。OCI-7）
//!
//! # ロック順序
//!
//! ゲート ＞ `ImageStore::lock`（`@lock`）＞ `StateStore` のロック。ゲートは常に最も外側で、
//! `ImageStoreGuard` や状態ストアのロックを保持したままゲートを取らない。同じスレッドが共有を持ったまま
//! 排他を取りに行かない（自己待ちで期限まで待つ）。取得はすべて期限つき（REPAIR-5）。
//!
//! 確定済み参照の回収にゲートは要らない（確定済みの間は同じ ID の `register` が拒否されるため）。
//! 設計の詳細は `docs/design/container-ref-reconcile.md`。

use super::store::{open_named_lock_file, wait_or_timeout};
use super::{
    ContainerRefGeneration, ContainerRefId, ContainerRefReconciliation, ContainerRefRelease,
    ContainerStatePresence, ImageStore,
};
use crate::error::{OciError, OciErrorCode};
use std::fs::{File, TryLockError};
use std::time::Instant;

/// create ゲートのロックファイル名（ストア root 直下）。
pub const IMAGE_STORE_CREATE_GATE_FILE_NAME: &str = "@create-gate";

/// イメージつき create の進行中を示す共有ロックの保持証（Drop で解放）。
#[derive(Debug)]
pub struct ContainerCreatePass<'a> {
    _file: File,
    _store: &'a ImageStore,
}

/// 進行中のイメージつき create が無いことを示す排他ロックの保持証（Drop で解放）。
///
/// 未確定参照の回収入口（`*_quiesced`）はこの型を要求する。
#[derive(Debug)]
pub struct CreateQuiescence<'a> {
    _file: File,
    store: &'a ImageStore,
}

fn gate_error() -> OciError {
    OciError::new(
        OciErrorCode::Internal,
        "failed to lock the container create gate",
    )
}

impl ImageStore {
    /// イメージつき create の開始を宣言し、共有ロックを期限まで待って取る。期限切れは `Timeout`。
    pub fn enter_container_create(&self) -> Result<ContainerCreatePass<'_>, OciError> {
        let deadline = self.gate_deadline()?;
        // ゲートファイルの作成より前に root の信頼性を再検査する（#2547・SEC-1）。
        self.reverify_root()?;
        let file = open_named_lock_file(self.root(), IMAGE_STORE_CREATE_GATE_FILE_NAME)?;
        loop {
            match file.try_lock_shared() {
                Ok(()) => {
                    return Ok(ContainerCreatePass {
                        _file: file,
                        _store: self,
                    });
                }
                Err(TryLockError::WouldBlock) => {
                    wait_or_timeout(deadline).map_err(|_| {
                        OciError::new(
                            OciErrorCode::Timeout,
                            "timed out waiting for the container create gate",
                        )
                    })?;
                }
                Err(TryLockError::Error(_)) => return Err(gate_error()),
            }
        }
    }

    /// 進行中のイメージつき create が無いことを排他ロックで確かめる。期限内に取れなければ `Ok(None)`。
    pub fn quiesce_container_creates(&self) -> Result<Option<CreateQuiescence<'_>>, OciError> {
        let deadline = self.gate_deadline()?;
        // ゲートファイルの作成より前に root の信頼性を再検査する（#2547・SEC-1）。
        self.reverify_root()?;
        let file = open_named_lock_file(self.root(), IMAGE_STORE_CREATE_GATE_FILE_NAME)?;
        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Some(CreateQuiescence {
                        _file: file,
                        store: self,
                    }));
                }
                Err(TryLockError::WouldBlock) => {
                    if wait_or_timeout(deadline).is_err() {
                        return Ok(None);
                    }
                }
                Err(TryLockError::Error(_)) => return Err(gate_error()),
            }
        }
    }

    fn gate_deadline(&self) -> Result<Instant, OciError> {
        Instant::now()
            .checked_add(self.lock_timeout())
            .ok_or_else(|| {
                OciError::new(
                    OciErrorCode::InvalidArgument,
                    "image store lock timeout is too large",
                )
            })
    }

    fn ensure_same_store(&self, q: &CreateQuiescence<'_>) -> Result<(), OciError> {
        if std::ptr::eq(self, q.store) {
            Ok(())
        } else {
            Err(OciError::new(
                OciErrorCode::FailedPrecondition,
                "create quiescence belongs to another image store",
            ))
        }
    }

    /// 未確定かつ世代一致の参照を、ゲート排他の下で外す（`release_unbound_container_ref_if` の本番入口）。
    pub fn release_unbound_container_ref_quiesced(
        &self,
        quiescence: &CreateQuiescence<'_>,
        id: &ContainerRefId,
        expected: ContainerRefGeneration,
    ) -> Result<ContainerRefRelease, OciError> {
        self.ensure_same_store(quiescence)?;
        self.release_unbound_container_ref_if(id, expected)
    }

    /// 全参照を `probe` で照合して回収する（`reconcile_container_refs` の本番入口。ゲート排他の下）。
    pub fn reconcile_container_refs_quiesced<F>(
        &self,
        quiescence: &CreateQuiescence<'_>,
        probe: F,
    ) -> Result<ContainerRefReconciliation, OciError>
    where
        F: FnMut(&ContainerRefId) -> ContainerStatePresence,
    {
        self.ensure_same_store(quiescence)?;
        self.reconcile_container_refs(probe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use crate::reference::Digest;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn cid(s: &str) -> ContainerRefId {
        ContainerRefId::new(s).expect("id")
    }

    fn open_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fandhe-oci-gate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        dir
    }

    fn open(dir: &Path) -> ImageStore {
        ImageStore::open(dir)
            .expect("open")
            .with_timeout(Duration::from_millis(100))
    }

    fn seeded(dir: &Path) -> ImageStore {
        let store = open(dir);
        {
            let mut g = store.lock().expect("lock");
            g.register_manifest(
                d(0xa0),
                ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
            )
            .expect("manifest");
        }
        store
    }

    fn unbound_generation(store: &ImageStore) -> ContainerRefGeneration {
        store
            .lock()
            .expect("lock")
            .unbound_containers()
            .next()
            .map(|(_, g, _)| g)
            .expect("unbound")
    }

    /// OCI-7: 共有は同時に複数取れる。
    #[test]
    fn oci7_create_gate_passes_coexist() {
        let dir = open_dir("coexist");
        let a = open(&dir);
        let b = open(&dir);
        let _p1 = a.enter_container_create().expect("pass 1");
        let _p2 = b.enter_container_create().expect("pass 2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// OCI-7: 共有保持中の排他は None、drop 後は Some。
    #[test]
    fn oci7_quiesce_is_none_while_pass_held() {
        let dir = open_dir("quiesce");
        let a = open(&dir);
        let b = open(&dir);
        let pass = a.enter_container_create().expect("pass");
        assert!(b.quiesce_container_creates().expect("quiesce").is_none());
        drop(pass);
        assert!(b.quiesce_container_creates().expect("quiesce").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REPAIR-5: 排他保持中の共有取得は期限で Timeout・固定文言。
    #[test]
    fn repair5_enter_times_out_while_quiesced() {
        let dir = open_dir("enter-timeout");
        let a = open(&dir);
        let b = open(&dir);
        let q = a.quiesce_container_creates().expect("q").expect("some");
        let e = b.enter_container_create().expect_err("timeout");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert_eq!(
            e.message(),
            "timed out waiting for the container create gate"
        );
        drop(q);
        assert!(b.enter_container_create().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: symlink・ディレクトリのゲートファイルは拒否する。
    #[test]
    fn sec1_create_gate_rejects_symlink_and_directory() {
        let dir = open_dir("reject");
        let store = open(&dir);
        let path = dir.join(IMAGE_STORE_CREATE_GATE_FILE_NAME);
        std::fs::create_dir(&path).expect("mkdir");
        assert!(store.enter_container_create().is_err());
        std::fs::remove_dir(&path).expect("rmdir");
        #[cfg(unix)]
        {
            std::fs::write(dir.join("target"), b"").expect("target");
            std::os::unix::fs::symlink(dir.join("target"), &path).expect("symlink");
            assert!(store.enter_container_create().is_err());
            assert!(store.quiesce_container_creates().is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: ゲートファイルは 0600 で作られる。
    #[cfg(unix)]
    #[test]
    fn oci7_create_gate_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = open_dir("mode");
        let store = open(&dir);
        let _p = store.enter_container_create().expect("pass");
        let mode = std::fs::metadata(dir.join(IMAGE_STORE_CREATE_GATE_FILE_NAME))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// OCI-7: 別ストアのトークンは FailedPrecondition で何も外さない。
    #[test]
    fn oci7_quiesced_release_rejects_foreign_token() {
        let dir_a = open_dir("foreign-a");
        let dir_b = open_dir("foreign-b");
        let a = seeded(&dir_a);
        let b = open(&dir_b);
        a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let generation = unbound_generation(&a);
        let q = b.quiesce_container_creates().expect("q").expect("some");
        let e = a
            .release_unbound_container_ref_quiesced(&q, &cid("c1"), generation)
            .expect_err("foreign");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(a.lock().expect("lock").unbound_containers().count(), 1);
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// OCI-7: 世代一致かつ未確定だけが外れる。
    #[test]
    fn oci7_quiesced_release_removes_only_unbound_matching_generation() {
        let dir = open_dir("release");
        let store = seeded(&dir);
        store
            .register_container_ref(&cid("c1"), &d(0xa0))
            .expect("reg");
        let generation = unbound_generation(&store);
        let q = store.quiesce_container_creates().expect("q").expect("some");
        let bumped = ContainerRefGeneration::from_raw(generation.as_raw() + 1);
        assert_eq!(
            store
                .release_unbound_container_ref_quiesced(&q, &cid("c1"), bumped)
                .expect("no-op"),
            ContainerRefRelease::NotRegistered
        );
        assert_eq!(store.lock().expect("lock").unbound_containers().count(), 1);
        assert_eq!(
            store
                .release_unbound_container_ref_quiesced(&q, &cid("c1"), generation)
                .expect("release"),
            ContainerRefRelease::Released(d(0xa0))
        );
        assert_eq!(store.lock().expect("lock").unbound_containers().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
