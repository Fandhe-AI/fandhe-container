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
//! 前提: 再起動時、ライフサイクル操作（create / delete）を受け付ける前に 1 回呼ぶ。複製と取り直しの間に
//! 同じ ID が同じ manifest で登録し直される（ABA）と比較では見分けられないが、この前提では起きない。
//! 将来仕様（#2315）: テーブルに世代と「未確定」状態が入ったら、比較を世代の一致へ切り替え、
//! 実行中の未確定参照の回収も #2315 が担う。結果のログ出力も配線側の担当で、ここでは操作種別を増やさない。

use super::{ContainerRefId, ImageStore};
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
    kept_present: Vec<ContainerRefId>,
    kept_undetermined: Vec<ContainerRefId>,
    skipped_changed: Vec<ContainerRefId>,
}

impl ContainerRefReconciliation {
    /// 外した参照と、参照していた manifest。
    pub fn removed(&self) -> &[(ContainerRefId, Digest)] {
        &self.removed
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
        let snapshot: Vec<(ContainerRefId, Digest)> = {
            let guard = self.lock()?;
            guard
                .container_refs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        let mut result = ContainerRefReconciliation::default();
        let mut candidates: Vec<(ContainerRefId, Digest)> = Vec::new();
        for (id, digest) in snapshot {
            match probe(&id) {
                ContainerStatePresence::Present => result.kept_present.push(id),
                ContainerStatePresence::Undetermined => result.kept_undetermined.push(id),
                ContainerStatePresence::Absent => candidates.push((id, digest)),
            }
        }
        if candidates.is_empty() {
            return Ok(result);
        }

        let mut guard = self.lock()?;
        for (id, digest) in candidates {
            if guard.container_refs.get(&id) == Some(&digest)
                && guard.unregister_container(&id).is_ok()
            {
                result.removed.push((id, digest));
            } else {
                result.skipped_changed.push(id);
            }
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
