//! 再起動時のコンテナ参照の照合（OCI-7・TASK-183.8.2・MS-4・#854）。
//!
//! create は「参照登録 → rootfs の使用 → 状態作成」の順に進むため、状態作成の前後でクラッシュすると
//! `StateStore` に状態の無いコンテナ参照が参照テーブルに残り、manifest を GC から守り続け同じ ID の
//! 再作成も塞ぐ。本ファイルの [`ImageStore::reconcile_container_refs`] は、状態の不在を確認できた
//! 参照だけを外す。確認できない・判定不能の参照は残す（誤る方向を「余分に残す」側に限る。OCI-7）。
//!
//! # 役割と呼び出し元
//!
//! oci は core に依存できないため、`StateStore` を直接受けず、oci の内側で閉じた probe
//! （[`ContainerStatePresence`] を返す呼び出し）を受ける。probe の本番実装（`StateStore::get` の結果の
//! 写し方）と起動時の呼び出しの配線は oci と core の両方に依存するアダプタの担当で、#2315 で扱う
//! （REPAIR-3: 本ファイルは照合の規則だけを実装済みで、配線は未実装）。
//!
//! 写し方の規約: `Ok` は [`ContainerStatePresence::Present`]、`NotFound` は
//! [`ContainerStatePresence::Absent`]、それ以外のエラー（`Timeout`・`Internal`・`PermissionDenied`・
//! Linux 以外の `Unimplemented` 等）は [`ContainerStatePresence::Undetermined`]。
//! probe の期限は `StateStore` 側が持つ（REPAIR-5）。
//!
//! # 排他の規律と前提
//!
//! ガードを保持したまま `StateStore` の操作を取らない（`store` の契約）ため、probe は排他の外で呼ぶ。
//! 「排他下で参照を複製 → 排他の外で probe → 排他を取り直して、登録が複製時から変わっていない
//! `Absent` だけを外す（compare-and-remove）」の 3 段で行い、外す処理は 1 回の排他区間でまとめる。
//! 2 回目の排他取得が失敗したら何も外さずエラーを返す。
//!
//! # 確定・未確定の参照の扱い（#2315・#2345）
//!
//! 参照は登録世代と確定・未確定の状態を持つ（`container_ref.rs` のモジュール doc）。比較は複製時の
//! 世代と確定状態の一致で行うため、同じ ID が同じ manifest で登録し直されても（ABA）外さない。
//!
//! - 確定済み参照が `Absent`: 状態の削除後に解除だけが落ちた残骸なので外す。
//! - 未確定参照が `Absent`: 状態作成の前後で止まった create の残骸なので、`release_unbound_container_ref_if`
//!   と同じ条件（未確定かつ世代一致）で外す。確定済みへ変わっていたら（`bind` が済んだ）外さない。
//!   進行中の create が無いことは、本関数を「ライフサイクル操作を受け付ける前に 1 回」呼ぶ前提で保証する。
//! - `Present` は確定・未確定とも残す（未確定のまま状態がある場合は `bind` 前のクラッシュで、
//!   余分に残す側に誤るだけで GC は参照数に数える。確定への昇格は #2315 の配線側の担当）。
//!
//! 前提: 再起動時、ライフサイクル操作（create / delete）を受け付ける前に 1 回呼ぶ。
//! 結果のログ出力も配線側の担当で、ここでは操作種別を増やさない。
//!
//! 外した結果は最後に 1 回まとめてディスクへ保存する（#2341。`container_ref` の永続化の節）。保存に失敗したら
//! 全部元へ戻してエラーを返す。

use super::{ContainerRefEntry, ContainerRefId, ImageStore};
use crate::error::OciError;
use crate::reference::Digest;

/// probe が返す、コンテナ状態の有無の 3 値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatePresence {
    /// `StateStore` に状態がある（参照を残す）。
    Present,
    /// 状態が無いと確認できた（参照を外す候補）。
    Absent,
    /// 確認できなかった（参照を残す）。
    Undetermined,
}

/// [`ImageStore::reconcile_container_refs`] の結果。各一覧は ID の昇順で決定的（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerRefReconciliation {
    removed: Vec<(ContainerRefId, Digest)>,
    removed_unbound: Vec<ContainerRefId>,
    kept_present: Vec<ContainerRefId>,
    kept_undetermined: Vec<ContainerRefId>,
    skipped_changed: Vec<ContainerRefId>,
}

impl ContainerRefReconciliation {
    /// 外した参照と、参照していた manifest。
    pub fn removed(&self) -> &[(ContainerRefId, Digest)] {
        &self.removed
    }

    /// `removed` のうち、未確定（状態作成まで済んでいない create の残骸）だった参照。
    pub fn removed_unbound(&self) -> &[ContainerRefId] {
        &self.removed_unbound
    }

    /// 状態が存在したため残した参照。
    pub fn kept_present(&self) -> &[ContainerRefId] {
        &self.kept_present
    }

    /// 判定不能のため残した参照。
    pub fn kept_undetermined(&self) -> &[ContainerRefId] {
        &self.kept_undetermined
    }

    /// `Absent` だったが、複製の後に登録が変わった・消えたため触らなかった参照。
    pub fn skipped_changed(&self) -> &[ContainerRefId] {
        &self.skipped_changed
    }
}

impl ImageStore {
    /// 各コンテナ参照を `probe` で照合し、状態の不在を確認できたものだけを外す（OCI-7・#854）。
    ///
    /// 排他の取得（複製時と取り直し時）が失敗したらエラーを返し、その場合は何も外さない。
    pub fn reconcile_container_refs<F>(
        &self,
        mut probe: F,
    ) -> Result<ContainerRefReconciliation, OciError>
    where
        F: FnMut(&ContainerRefId) -> ContainerStatePresence,
    {
        let snapshot: Vec<(ContainerRefId, ContainerRefEntry)> = {
            let guard = self.lock()?;
            guard
                .container_refs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        let mut result = ContainerRefReconciliation::default();
        let mut candidates: Vec<(ContainerRefId, ContainerRefEntry)> = Vec::new();
        for (id, entry) in snapshot {
            match probe(&id) {
                ContainerStatePresence::Present => result.kept_present.push(id),
                ContainerStatePresence::Undetermined => result.kept_undetermined.push(id),
                ContainerStatePresence::Absent => candidates.push((id, entry)),
            }
        }
        if candidates.is_empty() {
            return Ok(result);
        }

        let mut guard = self.lock()?;
        let before = guard.container_portion();
        for (id, entry) in candidates {
            // 世代と確定状態が複製時のままのときだけ外す（登録し直し・確定への変化は触れない）。
            let unchanged = guard.container_refs.get(&id) == Some(&entry);
            if unchanged && guard.unregister_container(&id).is_ok() {
                if !entry.bound {
                    result.removed_unbound.push(id.clone());
                }
                result.removed.push((id, entry.manifest));
            } else {
                result.skipped_changed.push(id);
            }
        }
        // 1 件でも外したら最後に 1 回保存する。失敗したら全部戻し、何も外さなかったことにする（#2341）。
        if !result.removed.is_empty() {
            self.persist_container_refs(&mut guard, before)?;
        }
        Ok(result)
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
            std::env::temp_dir().join(format!("fandhe-oci-recon-{name}-{}", std::process::id()));
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

    fn reg(s: &ImageStore, id: &str, m: u8) {
        s.register_container_ref(&cid(id), &d(m)).expect("reg");
    }

    /// OCI-7: 不在を確認できた参照だけが外れ、存在・判定不能は残る。
    #[test]
    fn oci7_reconcile_removes_only_confirmed_absent_refs() {
        let (s, dir) = store("basic");
        reg(&s, "c-present", 0xa0);
        reg(&s, "c-absent", 0xa0);
        reg(&s, "c-unknown", 0xb0);
        reg(&s, "c-absent2", 0xb0);
        let r = s
            .reconcile_container_refs(|id| match id.as_str() {
                "c-present" => ContainerStatePresence::Present,
                "c-unknown" => ContainerStatePresence::Undetermined,
                _ => ContainerStatePresence::Absent,
            })
            .expect("reconcile");
        assert_eq!(
            r.removed(),
            &[(cid("c-absent"), d(0xa0)), (cid("c-absent2"), d(0xb0))]
        );
        assert_eq!(r.kept_present(), &[cid("c-present")]);
        assert_eq!(r.kept_undetermined(), &[cid("c-unknown")]);
        assert!(r.skipped_changed().is_empty());
        let g = s.lock().expect("lock");
        assert_eq!(
            g.manifest_references(&d(0xa0)).containers,
            vec![cid("c-present")]
        );
        assert_eq!(
            g.manifest_references(&d(0xb0)).containers,
            vec![cid("c-unknown")]
        );
        drop(g);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・#2345: 確定・未確定の参照を別々に照合する（不在の未確定・確定は外れ、存在は両方残る）。
    #[test]
    fn oci7_reconcile_handles_bound_and_unbound_refs() {
        let (s, dir) = store("bound");
        reg(&s, "b-absent", 0xa0);
        reg(&s, "u-absent", 0xa0);
        reg(&s, "b-present", 0xb0);
        reg(&s, "u-present", 0xb0);
        reg(&s, "u-unknown", 0xb0);
        for id in ["b-absent", "b-present"] {
            s.bind_container_ref(&cid(id)).expect("bind");
        }
        let r = s
            .reconcile_container_refs(|id| match id.as_str() {
                "b-absent" | "u-absent" => ContainerStatePresence::Absent,
                "u-unknown" => ContainerStatePresence::Undetermined,
                _ => ContainerStatePresence::Present,
            })
            .expect("reconcile");
        assert_eq!(
            r.removed(),
            &[(cid("b-absent"), d(0xa0)), (cid("u-absent"), d(0xa0))]
        );
        assert_eq!(r.removed_unbound(), &[cid("u-absent")]);
        assert_eq!(r.kept_present(), &[cid("b-present"), cid("u-present")]);
        assert_eq!(r.kept_undetermined(), &[cid("u-unknown")]);
        assert!(r.skipped_changed().is_empty());
        let g = s.lock().expect("lock");
        assert_eq!(g.manifest_references(&d(0xa0)).count(), 0);
        assert_eq!(
            g.manifest_references(&d(0xb0)).containers,
            vec![cid("b-present"), cid("u-present"), cid("u-unknown")]
        );
        drop(g);
        // 回収した ID は同じ manifest で再作成できる。
        reg(&s, "u-absent", 0xa0);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・#2345: probe 中に同じ ID が同じ manifest で登録し直された（世代が変わった）参照と、
    /// 未確定から確定へ変わった参照は外さない。
    #[test]
    fn oci7_reconcile_skips_regenerated_or_newly_bound_refs() {
        let (s, dir) = store("aba");
        reg(&s, "regen", 0xa0);
        reg(&s, "bound-late", 0xa0);
        let r = s
            .reconcile_container_refs(|id| {
                if id.as_str() == "regen" {
                    s.release_container_ref(id).expect("release");
                    s.register_container_ref(id, &d(0xa0)).expect("re-register");
                } else {
                    s.bind_container_ref(id).expect("bind");
                }
                ContainerStatePresence::Absent
            })
            .expect("reconcile");
        assert!(r.removed().is_empty());
        assert_eq!(r.skipped_changed(), &[cid("bound-late"), cid("regen")]);
        assert_eq!(
            s.lock()
                .expect("lock")
                .manifest_references(&d(0xa0))
                .containers,
            vec![cid("bound-late"), cid("regen")]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: すべて判定不能なら何も外れない。
    #[test]
    fn oci7_reconcile_keeps_all_when_undetermined() {
        let (s, dir) = store("undet");
        reg(&s, "c1", 0xa0);
        reg(&s, "c2", 0xb0);
        let before = s.lock().expect("lock").container_refs.clone();
        let r = s
            .reconcile_container_refs(|_| ContainerStatePresence::Undetermined)
            .expect("reconcile");
        assert!(r.removed().is_empty());
        assert_eq!(r.kept_undetermined(), &[cid("c1"), cid("c2")]);
        assert_eq!(s.lock().expect("lock").container_refs, before);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7: 2 回目は何も外さず、空のテーブルでも結果は空。
    #[test]
    fn oci7_reconcile_is_idempotent() {
        let (s, dir) = store("idem");
        assert_eq!(
            s.reconcile_container_refs(|_| ContainerStatePresence::Absent)
                .expect("empty"),
            ContainerRefReconciliation::default()
        );
        reg(&s, "c1", 0xa0);
        let first = s
            .reconcile_container_refs(|_| ContainerStatePresence::Absent)
            .expect("first");
        assert_eq!(first.removed(), &[(cid("c1"), d(0xa0))]);
        let second = s
            .reconcile_container_refs(|_| ContainerStatePresence::Absent)
            .expect("second");
        assert!(second.removed().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・REPAIR-5: probe は排他の外で呼ばれ、probe 中に付け替わった参照は外さない。
    #[test]
    fn oci7_reconcile_probes_without_holding_lock() {
        let (s, dir) = store("nolock");
        reg(&s, "c1", 0xa0);
        let r = s
            .reconcile_container_refs(|id| {
                drop(s.lock().expect("lock inside probe"));
                s.release_container_ref(id).expect("release");
                s.register_container_ref(id, &d(0xb0)).expect("rebind");
                ContainerStatePresence::Absent
            })
            .expect("reconcile");
        assert!(r.removed().is_empty());
        assert_eq!(r.skipped_changed(), &[cid("c1")]);
        assert_eq!(
            s.lock()
                .expect("lock")
                .manifest_references(&d(0xb0))
                .containers,
            vec![cid("c1")]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OCI-7・REPAIR-5: 照合の後に排他を解放している。
    #[test]
    fn oci7_reconcile_releases_lock() {
        let (s, dir) = store("release");
        reg(&s, "c1", 0xa0);
        s.reconcile_container_refs(|_| ContainerStatePresence::Absent)
            .expect("reconcile");
        drop(s.lock().expect("lock after reconcile"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
