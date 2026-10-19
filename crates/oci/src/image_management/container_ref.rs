//! コンテナ → manifest 参照の登録・解除を、ストア単位の排他の下で 1 呼び出しとして行う入口
//! （OCI-7・TASK-183.8.1・MS-4・#853）。
//!
//! # 役割と呼び出し元
//!
//! core のライフサイクル（`create` / `delete`）は oci に依存できないため、core 側のトレイト
//! `ContainerImageRefs` を満たすアダプタ（oci と core の両方に依存する上位 crate。後続）が
//! 本ファイルの [`ImageStore::register_container_ref`] / [`ImageStore::release_container_ref`] を呼ぶ。
//! 各呼び出しは内側で [`ImageStore::lock`]（期限つき。REPAIR-5）を取り、返る前に解放する。
//! `StateStore` の操作や start の所有ロックをまたいで排他を持たないため、デッドロックの経路を作らない。
//!
//! 排他の取得は `AcquireImageStoreLock` として記録済みなので、ここでは別の操作種別を増やさない。

use super::{ContainerRefId, ImageStore};
use crate::error::{OciError, OciErrorCode};
use crate::reference::Digest;

/// [`ImageStore::register_container_ref`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainerRefRegistration {
    /// 新しく登録した。
    Registered,
    /// 同じ ID が同じ manifest で既に登録されていた（テーブルは変わらない）。
    AlreadyRegistered,
}

/// [`ImageStore::release_container_ref`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainerRefRelease {
    /// 参照を外した。参照していた manifest を持つ。
    Released(Digest),
    /// 登録が無かった。
    NotRegistered,
}

impl ImageStore {
    /// コンテナ `id` から `manifest` への参照を、排他の下で登録する。
    ///
    /// manifest が在庫に無ければ `NotFound`、同じ ID が別の manifest を指していれば `AlreadyExists`
    /// （テーブルは変えない）。同じ manifest なら `AlreadyRegistered` を返す。
    pub fn register_container_ref(
        &self,
        id: &ContainerRefId,
        manifest: &Digest,
    ) -> Result<ContainerRefRegistration, OciError> {
        let mut guard = self.lock()?;
        let already = guard.container_refs.get(id) == Some(manifest);
        guard.register_container(id.clone(), manifest)?;
        Ok(if already {
            ContainerRefRegistration::AlreadyRegistered
        } else {
            ContainerRefRegistration::Registered
        })
    }

    /// コンテナ `id` の参照を、排他の下で外す。登録が無ければ `NotRegistered`（エラーにしない）。
    pub fn release_container_ref(
        &self,
        id: &ContainerRefId,
    ) -> Result<ContainerRefRelease, OciError> {
        let mut guard = self.lock()?;
        match guard.unregister_container(id) {
            Ok(digest) => Ok(ContainerRefRelease::Released(digest)),
            Err(e) if e.code() == OciErrorCode::NotFound => Ok(ContainerRefRelease::NotRegistered),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use std::time::Duration;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn cid(s: &str) -> ContainerRefId {
        ContainerRefId::new(s).expect("id")
    }

    /// 一意な一時ディレクトリ上のストア（manifest `d(0xa0)` と `d(0xb0)` を登録済み）。
    fn store(name: &str) -> (ImageStore, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("fandhe-oci-cref-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let store = ImageStore::open(&dir)
            .expect("open")
            .with_timeout(Duration::from_millis(200));
        {
            let mut g = store.lock().expect("lock");
            for (m, c) in [(0xa0, 0xc1), (0xb0, 0xc2)] {
                g.register_manifest(
                    d(m),
                    ManifestComposition::new(d(c), vec![d(0x10)]).expect("comp"),
                )
                .expect("register manifest");
            }
        }
        (store, dir)
    }

    /// OCI-7: 新規は Registered、同じ manifest の再登録は AlreadyRegistered。
    #[test]
    fn oci7_register_container_ref_reports_new_vs_existing() {
        let (s, dir) = store("new");
        assert_eq!(
            s.register_container_ref(&cid("c1"), &d(0xa0))
                .expect("first"),
            ContainerRefRegistration::Registered
        );
        assert_eq!(
            s.register_container_ref(&cid("c1"), &d(0xa0))
                .expect("again"),
            ContainerRefRegistration::AlreadyRegistered
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: 別 manifest への再登録は AlreadyExists で、元の参照は変わらない。
    #[test]
    fn oci7_register_container_ref_rejects_other_manifest() {
        let (s, dir) = store("other");
        s.register_container_ref(&cid("c1"), &d(0xa0))
            .expect("first");
        let e = s
            .register_container_ref(&cid("c1"), &d(0xb0))
            .expect_err("other manifest");
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        let g = s.lock().expect("lock");
        assert_eq!(g.manifest_references(&d(0xa0)).containers, vec![cid("c1")]);
        assert_eq!(g.manifest_references(&d(0xb0)).count(), 0);
        drop(g);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: 在庫に無い manifest は NotFound でテーブルは変わらない。
    #[test]
    fn oci7_register_container_ref_unknown_manifest_not_found() {
        let (s, dir) = store("unknown");
        let e = s
            .register_container_ref(&cid("c1"), &d(0xee))
            .expect_err("unknown");
        assert_eq!(e.code(), OciErrorCode::NotFound);
        assert_eq!(
            s.lock()
                .expect("lock")
                .manifest_references(&d(0xee))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: 解除は参照先を返し、2 回目と未登録は NotRegistered。
    #[test]
    fn oci7_release_container_ref_not_registered() {
        let (s, dir) = store("release");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        assert_eq!(
            s.release_container_ref(&cid("c1")).expect("release"),
            ContainerRefRelease::Released(d(0xa0))
        );
        assert_eq!(
            s.release_container_ref(&cid("c1")).expect("again"),
            ContainerRefRelease::NotRegistered
        );
        assert_eq!(
            s.release_container_ref(&cid("never")).expect("never"),
            ContainerRefRelease::NotRegistered
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・REPAIR-5: どの入口も返る前に排他を解放する（直後に短い期限で取れる）。
    #[test]
    fn oci7_container_ref_ops_release_lock() {
        let (s, dir) = store("lock");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        drop(s.lock().expect("lock after register"));
        s.release_container_ref(&cid("c1")).expect("release");
        drop(s.lock().expect("lock after release"));
        let _ = s.register_container_ref(&cid("c2"), &d(0xee));
        drop(s.lock().expect("lock after failed register"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
