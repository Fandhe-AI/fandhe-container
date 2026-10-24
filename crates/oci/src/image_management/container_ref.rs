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
//! # 未確定・確定と登録世代（#2315・core の `ContainerImageRefs` の契約）
//!
//! 登録は未確定で入り、[`ImageStore::bind_container_ref`]（create の状態作成の成功直後）で確定する。
//! 世代は新規登録ごとに採番され、外して登録し直しても過去の値を再発行しない。世代の比較と解除は
//! [`ImageStore::release_container_ref_if`] が 1 回の排他の中で行う。
//!
//! # 未確定参照の回収と #854 との分担
//!
//! 状態作成の曖昧な失敗（`Internal`・`Timeout`）で未確定のまま残った参照は、ID 指定の delete では外れず、
//! 同じ ID の再作成を `AlreadyExists` で塞ぐ。これを外す部品が [`ImageStore::release_unbound_container_ref_if`]
//! （未確定かつ世代一致のときだけ外す）。呼び出し元は「その ID の create が進行中でない」ことを保証できる
//! 場合だけに限る。保証は create ゲート（`create_gate.rs`。#2495）の排他で与え、本番では
//! `release_unbound_container_ref_quiesced` / `reconcile_container_refs_quiesced` を使う。起動点は cli の
//! 契機 A・B（`docs/design/container-ref-reconcile.md`）で、順序は「進行中の create が無いことの保証 →
//! `StateStore` で状態が無いことを確認 → `unbound_containers` で読んだ世代つきで回収」とする。
//! `register` 時に未確定を置き換えない理由は、並行する同じ ID の create の未確定参照と区別できるのが
//! 世代だけで、競合側のロールバック（ID 指定の `release`）が勝った側の参照を外しうるため。
//!
//! # 永続化（#2341）
//!
//! コンテナ参照のエントリと世代カウンタは、変更する入口が排他の中で `container_ref_persist` へ保存してから
//! 結果を返す（変更 → 保存 → 失敗したら元へ戻して保存のエラーを返す）。返した世代を含む状態は
//! 保存済みなので、ディスク上のカウンタは発行済みのどの世代よりも大きい。何も変わらない結果
//! （`AlreadyRegistered`・`NotRegistered`・エラー）では書かない。保存の最後の親ディレクトリ `fsync` だけが
//! 失敗した場合は、ディスクは新しい状態でメモリは戻り、呼び出し元はエラーを受け取る。次の排他取得で
//! ディスクの内容に揃い、誤りは「余分に残す」側（未確定の参照が残る・外れているのに解除がエラー）に限り、
//! 世代は再発行しない。永続化されるのはこれらの入口を通った変更だけで、ガードから
//! `ReferenceTable::register_container` 等を直接呼んだ変更は保存されない（ファイルがあれば次の排他取得で
//! 上書きされる。試験と `with_table` の種入れ用の口）。manifest・タグ・リースは別ファイル `@image-inventory.json` に永続化する（#2380。`inventory_persist`）。
//!
//! 排他の取得は `AcquireImageStoreLock` として記録済みなので、ここでは別の操作種別を増やさない。

use super::container_ref_persist::{ContainerPortion, MAX_CONTAINER_REFS, save_container_refs};
use super::{ContainerRefGeneration, ContainerRefId, ImageStore, ImageStoreGuard};
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
    /// 排他の中でコンテナ参照を保存する。失敗したら `before` へ戻して保存のエラーを返す（#2341）。
    pub(super) fn persist_container_refs(
        &self,
        guard: &mut ImageStoreGuard<'_>,
        before: ContainerPortion,
    ) -> Result<(), OciError> {
        match save_container_refs(self.handle(), guard) {
            Ok(()) => Ok(()),
            Err(e) => {
                guard.restore_container_portion(before);
                Err(e)
            }
        }
    }

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
        let already = guard.container_refs.get(id).map(|e| &e.manifest) == Some(manifest);
        if !guard.container_refs.contains_key(id)
            && guard.container_refs.len() >= MAX_CONTAINER_REFS
        {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "too many container refs",
            ));
        }
        let before = guard.container_portion();
        guard.register_container(id.clone(), manifest)?;
        if already {
            return Ok(ContainerRefRegistration::AlreadyRegistered);
        }
        self.persist_container_refs(&mut guard, before)?;
        Ok(ContainerRefRegistration::Registered)
    }

    /// 未確定の登録だけを確定し、その登録世代を返す（`ContainerImageRefs::bind`）。
    ///
    /// 登録が無い、または確定済みなら `NotFound`（二重の確定を許さない）。
    pub fn bind_container_ref(
        &self,
        id: &ContainerRefId,
    ) -> Result<ContainerRefGeneration, OciError> {
        let mut guard = self.lock()?;
        let before = guard.container_portion();
        let generation = match guard.container_refs.get_mut(id) {
            Some(e) if !e.bound => {
                e.bound = true;
                e.generation
            }
            _ => {
                return Err(OciError::new(
                    OciErrorCode::NotFound,
                    "no unbound container reference",
                ));
            }
        };
        self.persist_container_refs(&mut guard, before)?;
        Ok(generation)
    }

    /// 確定済みの登録の世代を返す。登録が無い・未確定なら `None`（`ContainerImageRefs::registration`）。
    pub fn container_ref_registration(
        &self,
        id: &ContainerRefId,
    ) -> Result<Option<ContainerRefGeneration>, OciError> {
        let guard = self.lock()?;
        Ok(guard
            .container_refs
            .get(id)
            .filter(|e| e.bound)
            .map(|e| e.generation))
    }

    /// 登録世代が `expected` のときだけ外す。比較と解除は同じ排他の中（`ContainerImageRefs::release_if`）。
    ///
    /// 世代が違う・登録が無ければテーブルを変えず `NotRegistered`。
    pub fn release_container_ref_if(
        &self,
        id: &ContainerRefId,
        expected: ContainerRefGeneration,
    ) -> Result<ContainerRefRelease, OciError> {
        let mut guard = self.lock()?;
        if guard.container_refs.get(id).map(|e| e.generation) != Some(expected) {
            return Ok(ContainerRefRelease::NotRegistered);
        }
        let before = guard.container_portion();
        let removed = guard.unregister_container(id)?;
        self.persist_container_refs(&mut guard, before)?;
        Ok(ContainerRefRelease::Released(removed))
    }

    /// 未確定かつ世代が `expected` のときだけ外す（確定済みには触れない）。未確定参照の回収の部品。
    ///
    /// 呼び出し元は、その ID の create が進行中でないことを保証できる場合だけ使う（モジュール doc、#854）。
    pub fn release_unbound_container_ref_if(
        &self,
        id: &ContainerRefId,
        expected: ContainerRefGeneration,
    ) -> Result<ContainerRefRelease, OciError> {
        let mut guard = self.lock()?;
        let matches = guard
            .container_refs
            .get(id)
            .is_some_and(|e| !e.bound && e.generation == expected);
        if !matches {
            return Ok(ContainerRefRelease::NotRegistered);
        }
        let before = guard.container_portion();
        let removed = guard.unregister_container(id)?;
        self.persist_container_refs(&mut guard, before)?;
        Ok(ContainerRefRelease::Released(removed))
    }

    /// コンテナ `id` の参照を、排他の下で外す。登録が無ければ `NotRegistered`（エラーにしない）。
    pub fn release_container_ref(
        &self,
        id: &ContainerRefId,
    ) -> Result<ContainerRefRelease, OciError> {
        let mut guard = self.lock()?;
        let before = guard.container_portion();
        match guard.unregister_container(id) {
            Ok(digest) => {
                self.persist_container_refs(&mut guard, before)?;
                Ok(ContainerRefRelease::Released(digest))
            }
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
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

    /// OCI-7: 登録直後は未確定（registration は None）、bind で確定し世代を返す。二重の bind と未登録は NotFound。
    #[test]
    fn oci7_bind_confirms_and_rejects_twice() {
        let (s, dir) = store("bind");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        assert_eq!(s.container_ref_registration(&cid("c1")).expect("r"), None);
        let g = s.bind_container_ref(&cid("c1")).expect("bind");
        assert_eq!(g.as_raw(), 1);
        assert_eq!(
            s.container_ref_registration(&cid("c1")).expect("r"),
            Some(g)
        );
        assert_eq!(
            s.bind_container_ref(&cid("c1")).expect_err("twice").code(),
            OciErrorCode::NotFound
        );
        assert_eq!(
            s.bind_container_ref(&cid("none")).expect_err("none").code(),
            OciErrorCode::NotFound
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: release_if は世代違いでテーブルを変えず、一致で外す。再登録の世代は前より大きい。
    #[test]
    fn oci7_release_if_checks_generation_and_never_reissues() {
        let (s, dir) = store("relif");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let g1 = s.bind_container_ref(&cid("c1")).expect("bind");
        let stale = ContainerRefGeneration::from_raw(g1.as_raw() + 5);
        assert_eq!(
            s.release_container_ref_if(&cid("c1"), stale)
                .expect("stale"),
            ContainerRefRelease::NotRegistered
        );
        assert_eq!(
            s.container_ref_registration(&cid("c1")).expect("r"),
            Some(g1)
        );
        assert_eq!(
            s.release_container_ref_if(&cid("c1"), g1).expect("match"),
            ContainerRefRelease::Released(d(0xa0))
        );
        assert_eq!(
            s.release_container_ref_if(&cid("c1"), g1).expect("again"),
            ContainerRefRelease::NotRegistered
        );
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("re");
        let g2 = s.bind_container_ref(&cid("c1")).expect("bind2");
        assert_eq!((g1.as_raw(), g2.as_raw()), (1, 2));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: 回収の部品は未確定かつ世代一致だけを外し、確定済みには触れない。未確定も GC の参照数に入る。
    #[test]
    fn oci7_release_unbound_only_touches_unbound_matching_generation() {
        let (s, dir) = store("unbound");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        s.register_container_ref(&cid("c2"), &d(0xb0)).expect("reg");
        let g2 = s.bind_container_ref(&cid("c2")).expect("bind");
        let (g1, listed) = {
            let g = s.lock().expect("lock");
            let v: Vec<_> = g
                .unbound_containers()
                .map(|(i, gen_, m)| (i.clone(), gen_, m.clone()))
                .collect();
            assert_eq!(g.manifest_references(&d(0xa0)).containers, vec![cid("c1")]);
            (v[0].1, v)
        };
        assert_eq!(listed, vec![(cid("c1"), g1, d(0xa0))]);
        // 確定済みは世代が合っても外れない。
        assert_eq!(
            s.release_unbound_container_ref_if(&cid("c2"), g2)
                .expect("bound"),
            ContainerRefRelease::NotRegistered
        );
        // 世代違いは外れない。
        assert_eq!(
            s.release_unbound_container_ref_if(&cid("c1"), g2)
                .expect("stale"),
            ContainerRefRelease::NotRegistered
        );
        assert_eq!(
            s.release_unbound_container_ref_if(&cid("c1"), g1)
                .expect("ok"),
            ContainerRefRelease::Released(d(0xa0))
        );
        s.register_container_ref(&cid("c1"), &d(0xa0))
            .expect("re-create");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・REPAIR-5: 新しい入口も返る前に排他を解放する。
    #[test]
    fn oci7_new_container_ref_ops_release_lock() {
        let (s, dir) = store("lock2");
        s.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let g = s.bind_container_ref(&cid("c1")).expect("bind");
        drop(s.lock().expect("after bind"));
        let _ = s.bind_container_ref(&cid("c1"));
        drop(s.lock().expect("after failed bind"));
        s.container_ref_registration(&cid("c1")).expect("r");
        drop(s.lock().expect("after registration"));
        s.release_unbound_container_ref_if(&cid("c1"), g)
            .expect("u");
        drop(s.lock().expect("after unbound"));
        s.release_container_ref_if(&cid("c1"), g).expect("i");
        drop(s.lock().expect("after release_if"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
