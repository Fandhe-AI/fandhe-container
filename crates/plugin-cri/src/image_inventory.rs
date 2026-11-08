//! CRI の在庫（`ImageService` の `ListImages`・`ImageStatus`・create のタグ解決の元）を、oci の `ImageStore` の
//! root の下へ永続化する `ImageStore` 実装 [`PersistentImageStore`]（#4176・CRI-1・CRI-2・OCI-7・REPAIR-3）。
//!
//! 呼び出し元は [`crate::adapter`] の `production_image_store_in`（`CriPluginBackends::production` の組み立て）。
//! 記録の形式（符号化と復号）は cri の `image_service::{encode,decode}_image_records` が持つ。
//!
//! # 方針
//!
//! - 保存先は pull と同じ root（`<state_root>/.cri/images`）直下の `@cri-image-records.json`。oci の在庫
//!   （`@image-inventory.json`）から導出しないのは、`repo_digests` の top-level（multi-arch の index digest）と
//!   タグ無し pull の repo 名が oci の在庫に残らないため（`docs/design/pull-inventory-wiring.md`）
//! - `remove`（`RemoveImage`。#4177）も同じ排他区間で読み直し、cri の `InMemoryImageStore::remove`（記録ごと外す）で
//!   組み直して同じ手順で書く。該当が無ければファイルを書かず、読み直した永続側の内容へメモリ表示だけ揃える
//!   （冪等）。blob・展開済み rootfs には触れない（回収は #471 系）
//! - 書き込みと起動時の読み込みは oci の `ImageStore::lock()` の排他区間の中で行う（root の再検査とプロセス間の
//!   排他を oci と共有する）。`list` / `get` はメモリ上の表示だけを読み、I/O をしない
//! - `upsert` は排他区間の中でファイルを読み直し、cri の `InMemoryImageStore::upsert`（統合・タグの付け替え）で
//!   組み直してから、一時ファイル → fsync → rename → ディレクトリの fsync で原子的に書く。成功した後だけメモリ表示を
//!   差し替える（rename 前の失敗はメモリもファイルも元のまま。rename 後のディレクトリ fsync の失敗は永続側が
//!   新しい内容なので、メモリ表示も新しい内容へ揃えたうえで `Io` を返す）
//!
//! # fail-closed
//!
//! - root の不信・排他の失敗・読み取りの I/O 失敗は [`PersistentImageStore::open`] が `Err` で返す（起動を止める）
//! - 記録ファイルだけが壊れている（不正・矛盾・通常ファイルでない・symlink・所有者違い・group / other の書き込み権・
//!   上限超過）ときは「使えない」状態で開き、`list`・`get`・`upsert` は `ImageStoreError::Corrupt` を返す。空の在庫と
//!   して扱わず、壊れたファイルを上書きしない（RuntimeService を生かして既存コンテナの stop / remove を通すため）。
//!   直すには記録を手で直して plugin を再起動する
//! - エラー文言にパス・OS の文字列・イメージ名を含めない
//!
//! # 残余（REPAIR-3）
//!
//! - 記録ファイルの読み書きはパス起点（oci の `RootHandle` は公開されない）。`lock()` が root を再検査し、root と
//!   祖先は所有者専用という前提で守る。読み取りは fstat の dev / ino を lstat と照合して差し替えを検出する
//! - `upsert` は `CriImageService::pull` の blocking worker の中で呼ばれる（#4178）。RPC の future が publish の後に
//!   破棄されても worker は登録まで進むため、取り消しの窓（publish と upsert の間）は稼働中に開かない。
//!   oci のロック待ち（既定 5 秒）と fsync は実行器のスレッドを止めない
//! - プロセスが publish の後、upsert の完了前に死ぬと、oci の在庫にだけ載る。`open` は oci の在庫を読まないため
//!   再起動では揃わず、同じ参照の次の `PullImage` で揃う
//! - oci の在庫との突き合わせ（manifest が消えた記録を落とす）は未実装で、#4264 で追跡（#4177 の範囲外）

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::image_service::{
    ImageRecord, ImageStore, ImageStoreError, InMemoryImageStore, MAX_IMAGE_RECORDS_FILE_BYTES,
    RemoveOutcome, decode_image_records, encode_image_records,
};
use fandhe_container_oci::image_management::ImageStore as OciImageStore;
use fandhe_container_oci::instrument::OciOpRecorder;

/// 記録ファイル名（oci の `blobs/`・`staging/` の走査と `STALE_TMP_PREFIXES` に当たらないよう `@` で始める）。
pub const CRI_IMAGE_RECORDS_FILE_NAME: &str = "@cri-image-records.json";
/// 書き込み途中の一時ファイルの接頭辞（残骸は `open` の排他区間で回収する）。
const TMP_PREFIX: &str = "@cri-image-records.json.tmp-";
/// 残骸の回収で走査する root 直下のエントリ数の上限。
const SWEEP_MAX_ENTRIES: usize = 100_000;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// メモリ上の表示。壊れた記録で開いたときは `Unusable`。
enum View {
    Ready(Arc<InMemoryImageStore>),
    Unusable,
}

/// oci の `ImageStore` の root の下へ CRI の在庫記録を永続化する `ImageStore`（モジュール doc 参照）。
pub struct PersistentImageStore {
    oci: OciImageStore,
    view: Mutex<View>,
}

impl std::fmt::Debug for PersistentImageStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentImageStore")
            .finish_non_exhaustive()
    }
}

impl PersistentImageStore {
    /// `images_root`（oci の `ImageStore::open` の root と同じ位置）を開き、記録をメモリへ読み込む。
    pub fn open(images_root: &Path) -> Result<Self, CriError> {
        Self::open_inner(images_root, None)
    }

    /// [`Self::open`] に、oci の排他取得の計装の記録先を足した形。
    pub fn open_with_recorder(
        images_root: &Path,
        recorder: Arc<dyn OciOpRecorder>,
    ) -> Result<Self, CriError> {
        Self::open_inner(images_root, Some(recorder))
    }

    fn open_inner(
        images_root: &Path,
        recorder: Option<Arc<dyn OciOpRecorder>>,
    ) -> Result<Self, CriError> {
        let fail = || CriError::failed_precondition("failed to open the image store");
        let mut oci = OciImageStore::open(images_root).map_err(|_| fail())?;
        if let Some(recorder) = recorder {
            oci = oci.with_recorder(recorder);
        }
        let view = {
            let _guard = oci.lock().map_err(|_| fail())?;
            sweep_leftover_tmp(oci.root()).map_err(|_| fail())?;
            match read_records(oci.root()) {
                Ok(records) => View::Ready(Arc::new(build_memory(records).map_err(|_| fail())?)),
                Err(ImageStoreError::Corrupt) => View::Unusable,
                Err(_) => return Err(fail()),
            }
        };
        Ok(Self {
            oci,
            view: Mutex::new(view),
        })
    }

    fn ready(&self) -> Result<Arc<InMemoryImageStore>, ImageStoreError> {
        match &*self.view.lock().map_err(|_| ImageStoreError::Poisoned)? {
            View::Ready(mem) => Ok(Arc::clone(mem)),
            View::Unusable => Err(ImageStoreError::Corrupt),
        }
    }
}

impl ImageStore for PersistentImageStore {
    fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
        self.ready()?.list()
    }

    fn get(&self, reference: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
        self.ready()?.get(reference)
    }

    fn upsert(&self, record: ImageRecord) -> Result<(), ImageStoreError> {
        self.upsert_with(record, PRODUCTION_OPS)
    }

    fn remove(&self, reference: &str) -> Result<RemoveOutcome, ImageStoreError> {
        self.remove_with(reference, None, PRODUCTION_OPS)
    }

    fn remove_resolving(
        &self,
        reference: &str,
        canonical: Option<&str>,
    ) -> Result<RemoveOutcome, ImageStoreError> {
        self.remove_with(reference, canonical, PRODUCTION_OPS)
    }
}

/// 書き込みの失敗注入点（rename と、公開後のディレクトリ fsync）。本番は [`PRODUCTION_OPS`]。
#[derive(Clone, Copy)]
struct WriteOps {
    rename: fn(&Path, &Path) -> std::io::Result<()>,
    sync: fn(&Path) -> std::io::Result<()>,
}

const PRODUCTION_OPS: WriteOps = WriteOps {
    rename: |from, to| std::fs::rename(from, to),
    sync: |root| File::open(root)?.sync_all(),
};

/// 排他区間で永続側を読み直した結果に `apply` を適用した後の扱い。
enum Change<T> {
    /// 書き換えが要る（戻り値つき）。
    Write(T),
    /// 書き換え不要（永続側は変わらない。メモリ表示だけ永続側へ揃える）。
    Keep(T),
}

impl PersistentImageStore {
    /// [`ImageStore::upsert`] の本体。書き込みの失敗注入点を差し替えられる（試験用）。
    fn upsert_with(&self, record: ImageRecord, ops: WriteOps) -> Result<(), ImageStoreError> {
        self.commit_with(ops, |mem| {
            mem.upsert(record)?;
            Ok(Change::Write(()))
        })
    }

    /// [`ImageStore::remove`] の本体（#4177）。記録ごと外す。該当が無ければファイルを書かず `Absent`。
    fn remove_with(
        &self,
        reference: &str,
        canonical: Option<&str>,
        ops: WriteOps,
    ) -> Result<RemoveOutcome, ImageStoreError> {
        // 1 回目の Absent と 2 回目（正規化形）を同じ排他区間で行う（PullImage の割り込みで新規 pull を消さない）。
        self.commit_with(ops, |mem| {
            let mut outcome = mem.remove(reference)?;
            if let (RemoveOutcome::Absent, Some(c)) = (&outcome, canonical)
                && c != reference
            {
                outcome = mem.remove(c)?;
            }
            Ok(match outcome {
                outcome @ RemoveOutcome::Removed { .. } => Change::Write(outcome),
                outcome => Change::Keep(outcome),
            })
        })
    }

    /// 排他区間の中で永続側を読み直し、`apply` で組み直して、必要なら原子的に書く共通手順。
    ///
    /// 書けたとき（または書き換え不要のとき）だけメモリ表示を永続側の内容へ揃える。rename 前の失敗は永続側が元の
    /// ままなのでメモリも元のまま、rename 後の失敗は永続側が新しい内容なのでメモリを新しい内容へ揃えて失敗を返す。
    fn commit_with<T>(
        &self,
        ops: WriteOps,
        apply: impl FnOnce(&InMemoryImageStore) -> Result<Change<T>, ImageStoreError>,
    ) -> Result<T, ImageStoreError> {
        // 壊れた状態で開いたストアは書かない（壊れたファイルを上書きしない）。
        self.ready()?;
        // 排他区間の中で永続側を読み直して適用し、書けたときだけメモリ表示を差し替える。
        let _guard = self.oci.lock().map_err(|_| ImageStoreError::Io)?;
        let mem = build_memory(read_records(self.oci.root())?)?;
        let (value, needs_write) = match apply(&mem)? {
            Change::Write(v) => (v, true),
            Change::Keep(v) => (v, false),
        };
        if needs_write {
            let bytes = encode_image_records(&mem.list()?)?;
            match write_atomically(self.oci.root(), &bytes, ops) {
                Ok(()) => {}
                // rename 前の失敗は永続側が元のまま。メモリも元のまま失敗を返す。
                Err(WriteFailure {
                    error,
                    published: false,
                }) => return Err(error),
                // rename 後（公開後）の失敗は永続側が新しい内容になっている。古い対応を使い続けないよう、
                // メモリ表示を新しい内容へ揃えてから失敗を返す（再起動後の見え方と一致させる）。
                Err(WriteFailure {
                    error,
                    published: true,
                }) => {
                    *self.view.lock().map_err(|_| ImageStoreError::Poisoned)? =
                        View::Ready(Arc::new(mem));
                    return Err(error);
                }
            }
        }
        *self.view.lock().map_err(|_| ImageStoreError::Poisoned)? = View::Ready(Arc::new(mem));
        Ok(value)
    }
}

fn build_memory(records: Vec<ImageRecord>) -> Result<InMemoryImageStore, ImageStoreError> {
    let mem = InMemoryImageStore::new();
    for record in records {
        mem.insert(record)?;
    }
    Ok(mem)
}

/// root 直下の記録ファイルを検査して読む。無ければ空。検査に反すれば `Corrupt`。
fn read_records(root: &Path) -> Result<Vec<ImageRecord>, ImageStoreError> {
    let path = root.join(CRI_IMAGE_RECORDS_FILE_NAME);
    let lmeta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(ImageStoreError::Io),
    };
    let owner = std::fs::symlink_metadata(root)
        .map_err(|_| ImageStoreError::Io)?
        .uid();
    let max = MAX_IMAGE_RECORDS_FILE_BYTES as u64;
    if !lmeta.file_type().is_file()
        || lmeta.uid() != owner
        || lmeta.permissions().mode() & 0o022 != 0
        || lmeta.len() > max
    {
        return Err(ImageStoreError::Corrupt);
    }
    let file = File::open(&path).map_err(|_| ImageStoreError::Io)?;
    let fmeta = file.metadata().map_err(|_| ImageStoreError::Io)?;
    if (fmeta.dev(), fmeta.ino()) != (lmeta.dev(), lmeta.ino()) {
        return Err(ImageStoreError::Corrupt);
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImageStoreError::Io)?;
    decode_image_records(&bytes)
}

/// 一時ファイル → fsync → rename → ディレクトリの fsync。失敗したら一時ファイルを消す（最善努力）。
///
/// 失敗時は rename の前後を `published` で区別する（rename 後は永続側が新しい内容になっている）。
fn write_atomically(root: &Path, bytes: &[u8], ops: WriteOps) -> Result<(), WriteFailure> {
    let tmp: PathBuf = root.join(format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut published = false;
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        (ops.rename)(&tmp, &root.join(CRI_IMAGE_RECORDS_FILE_NAME))?;
        published = true;
        (ops.sync)(root)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|_| WriteFailure {
        error: ImageStoreError::Io,
        published,
    })
}

/// [`write_atomically`] の失敗。`published` は rename が成功した後の失敗かどうか。
struct WriteFailure {
    error: ImageStoreError,
    published: bool,
}

/// 前回の書き込み途中の残骸（自前の接頭辞の通常ファイル）を消す。排他区間の中で呼ぶ。
fn sweep_leftover_tmp(root: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)?.take(SWEEP_MAX_ENTRIES) {
        let entry = entry?;
        let is_tmp = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(TMP_PREFIX));
        if is_tmp && entry.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! 往復・空・壊れた記録の fail-closed・oci との共存・読み直し（CRI-1・CRI-2・OCI-7）。

    use std::os::unix::fs::symlink;

    use fandhe_container_cri::image_pull::{ImagePuller, PullError, PullRequest, PulledImage};
    use fandhe_container_cri::image_service::CriImageService;
    use fandhe_container_cri::runtime::v1::{self, image_service_server::ImageService as _};
    use tonic::{Code, Request};

    use super::*;
    use crate::test_root::{TestRoot, test_root};

    struct FixedPuller(PulledImage);

    impl ImagePuller for FixedPuller {
        fn pull(&self, _request: &PullRequest) -> Result<PulledImage, PullError> {
            Ok(self.0.clone())
        }
    }

    fn id_a() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn pulled_a() -> PulledImage {
        PulledImage {
            id: id_a(),
            repo_tags: vec!["docker.io/library/busybox:1.36".to_owned()],
            repo_digests: vec![
                "docker.io/library/busybox@sha256:1111".to_owned(),
                "docker.io/library/busybox@sha256:2222".to_owned(),
            ],
            size: 4096,
        }
    }

    fn rec(id: &str, tag: &str) -> ImageRecord {
        ImageRecord::new(id, vec![tag.to_owned()], vec![], 10).expect("record")
    }

    fn scratch(tag: &str) -> TestRoot {
        test_root("fcpc-imginv", tag)
    }

    fn pull_request() -> Request<v1::PullImageRequest> {
        Request::new(v1::PullImageRequest {
            image: Some(v1::ImageSpec {
                image: "docker.io/library/busybox:1.36".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn write_records_file(root: &Path, bytes: &[u8]) -> PathBuf {
        let p = root.join(CRI_IMAGE_RECORDS_FILE_NAME);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .expect("create");
        f.write_all(bytes).expect("write");
        p
    }

    /// CRI-1・CRI-2・OCI-7: pull したイメージが、開き直した別の service の ListImages / ImageStatus に同じ値で出る。
    #[tokio::test]
    async fn cri1_cri2_pulled_image_survives_reopen() {
        let dir = scratch("reopen");
        let a = Arc::new(PersistentImageStore::open(&dir).expect("open a"));
        let svc_a =
            CriImageService::with_store(a.clone()).with_puller(Arc::new(FixedPuller(pulled_a())));
        let resp = svc_a.pull_image(pull_request()).await.expect("pull");
        assert_eq!(resp.into_inner().image_ref, id_a());
        let before = svc_a
            .list_images(Request::new(v1::ListImagesRequest::default()))
            .await
            .expect("list a")
            .into_inner()
            .images;
        drop(svc_a);
        drop(a);

        let b = Arc::new(PersistentImageStore::open(&dir).expect("open b"));
        let svc_b = CriImageService::with_store(b);
        let after = svc_b
            .list_images(Request::new(v1::ListImagesRequest::default()))
            .await
            .expect("list b")
            .into_inner()
            .images;
        assert_eq!(after.len(), 1);
        assert_eq!(after, before);
        assert_eq!(after[0].id, id_a());
        assert_eq!(after[0].repo_tags, vec!["docker.io/library/busybox:1.36"]);
        assert_eq!(
            after[0].repo_digests,
            vec![
                "docker.io/library/busybox@sha256:1111".to_owned(),
                "docker.io/library/busybox@sha256:2222".to_owned()
            ]
        );
        assert_eq!(after[0].size, 4096);
        let status = svc_b
            .image_status(Request::new(v1::ImageStatusRequest {
                image: Some(v1::ImageSpec {
                    image: "docker.io/library/busybox:1.36".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .expect("status")
            .into_inner();
        assert_eq!(status.image.expect("image").id, id_a());
    }

    fn multi_arch_pull(index: &str, tag: &str, repo: &str) -> PulledImage {
        // 補助（プラットフォーム）digest は全桁 0 で、辞書順では top-level（index）より前に来る。
        PulledImage {
            id: id_a(),
            repo_tags: vec![format!("{repo}:{tag}")],
            repo_digests: vec![
                format!("{repo}@sha256:{}", index.repeat(64)),
                format!("{repo}@sha256:{}", "0".repeat(64)),
            ],
            size: 4096,
        }
    }

    /// OCI-1・CRI-2・#4178: multi-arch の統合後も、top-level 区間が先、補助区間が後の並びが書いて読み直しても変わらない。
    /// 補助 digest が辞書順で top-level より前になる fixture で、全体を 1 本に並べ直す誤りを検出する。
    #[tokio::test]
    async fn cri2_oci1_multi_arch_digest_order_survives_reopen() {
        let dir = scratch("order");
        let a = Arc::new(PersistentImageStore::open(&dir).expect("open a"));
        for (index, repo) in [
            ("f", "docker.io/library/busybox"),
            ("e", "registry.example/mirror/busybox"),
        ] {
            let svc = CriImageService::with_store(a.clone())
                .with_puller(Arc::new(FixedPuller(multi_arch_pull(index, "1.36", repo))));
            svc.pull_image(pull_request()).await.expect("pull");
        }
        let list = |store: Arc<PersistentImageStore>| async move {
            CriImageService::with_store(store)
                .list_images(Request::new(v1::ListImagesRequest::default()))
                .await
                .expect("list")
                .into_inner()
                .images
        };
        let before = list(a.clone()).await;
        drop(a);
        let b = Arc::new(PersistentImageStore::open(&dir).expect("open b"));
        let after = list(b.clone()).await;
        assert_eq!(after, before);
        let h = |c: &str, repo: &str| format!("{repo}@sha256:{}", c.repeat(64));
        let (d, m) = (
            "docker.io/library/busybox",
            "registry.example/mirror/busybox",
        );
        let expected = vec![h("f", d), h("e", m), h("0", d), h("0", m)];
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].repo_digests, expected);
        assert_eq!(
            after[0].repo_tags,
            vec![
                "docker.io/library/busybox:1.36".to_owned(),
                "registry.example/mirror/busybox:1.36".to_owned()
            ]
        );
        let got = b
            .get("docker.io/library/busybox:1.36")
            .expect("get")
            .expect("present");
        assert_eq!(got.top_level_digests().to_vec(), vec![h("f", d), h("e", m)]);
        assert_eq!(got.auxiliary_digests().to_vec(), vec![h("0", d), h("0", m)]);
        assert_eq!(got.repo_digests()[0], h("f", d));
    }

    /// 窓への注入用: publish 済みの合図を出し、解放まで待ってから成功を返す puller。
    struct PublishThenWait {
        published: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl ImagePuller for PublishThenWait {
        fn pull(&self, _request: &PullRequest) -> Result<PulledImage, PullError> {
            let _ = self.published.lock().expect("lock").send(());
            let _ = self
                .release
                .lock()
                .expect("lock")
                .recv_timeout(std::time::Duration::from_secs(10));
            Ok(multi_arch_pull("f", "1.36", "docker.io/library/busybox"))
        }
    }

    /// CRI-2・OCI-7・REPAIR-5・#4178: publish と upsert の間で RPC が取り消されても、取り消し後の ListImages が
    /// 永続在庫を別に開いた service の ListImages と一致し、空でない（稼働中に不一致が残らない）。
    #[tokio::test]
    async fn cri2_oci7_pull_cancelled_between_publish_and_upsert_matches_persistent_store() {
        let dir = scratch("window");
        let (published_tx, published_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let store = Arc::new(PersistentImageStore::open(&dir).expect("open"));
        let svc = Arc::new(CriImageService::with_store(store).with_puller(Arc::new(
            PublishThenWait {
                published: std::sync::Mutex::new(published_tx),
                release: std::sync::Mutex::new(release_rx),
            },
        )));
        let first = {
            let svc = svc.clone();
            tokio::spawn(async move { svc.pull_image(pull_request()).await })
        };
        tokio::task::spawn_blocking(move || {
            published_rx.recv_timeout(std::time::Duration::from_secs(10))
        })
        .await
        .expect("join")
        .expect("publish reached");
        first.abort();
        let _ = first.await;
        release_tx.send(()).expect("release");
        let list = |s: Arc<CriImageService>| async move {
            s.list_images(Request::new(v1::ListImagesRequest::default()))
                .await
                .expect("list")
                .into_inner()
                .images
        };
        // worker の登録の完了まで有界に待つ。
        let mut live = Vec::new();
        for _ in 0..200 {
            live = list(svc.clone()).await;
            if !live.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, id_a());
        let reopened = Arc::new(CriImageService::with_store(Arc::new(
            PersistentImageStore::open(&dir).expect("reopen"),
        )));
        assert_eq!(list(reopened).await, live);
    }

    /// CRI-2: 空の root は空の一覧。開いただけではファイルを作らず、最初の upsert 後は 0600 の通常ファイル。
    #[test]
    fn cri2_empty_root_lists_nothing() {
        let dir = scratch("empty");
        let store = PersistentImageStore::open(&dir).expect("open");
        assert_eq!(store.list().expect("list"), vec![]);
        let file = dir.join(CRI_IMAGE_RECORDS_FILE_NAME);
        assert!(!file.exists());
        store.upsert(rec("sha256:aaa", "t:1")).expect("upsert");
        let m = std::fs::symlink_metadata(&file).expect("meta");
        assert!(m.file_type().is_file());
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }

    /// OCI-7・CRI-2: 壊れた記録は空にせず Internal。上書きもしない。
    #[tokio::test]
    async fn cri2_oci7_corrupt_records_fail_closed() {
        let dir = scratch("corrupt");
        let file = write_records_file(&dir, b"{ not json");
        let store = Arc::new(PersistentImageStore::open(&dir).expect("open"));
        let svc = CriImageService::with_store(store.clone())
            .with_puller(Arc::new(FixedPuller(pulled_a())));
        let list = svc
            .list_images(Request::new(v1::ListImagesRequest::default()))
            .await
            .expect_err("list");
        assert_eq!(list.code(), Code::Internal);
        assert_eq!(list.message(), "image store failure");
        let status = svc
            .image_status(Request::new(v1::ImageStatusRequest {
                image: Some(v1::ImageSpec {
                    image: "x".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .expect_err("status");
        assert_eq!(status.code(), Code::Internal);
        let pull = svc.pull_image(pull_request()).await.expect_err("pull");
        assert_eq!(pull.code(), Code::Internal);
        assert_eq!(std::fs::read(file).expect("read"), b"{ not json");
    }

    /// OCI-7・SEC-1: symlink・group 書き込み可・ディレクトリの記録ファイルも Corrupt。
    #[test]
    fn cri2_oci7_unsafe_record_files_fail_closed() {
        let dir = scratch("unsafe-link");
        let target = dir.join("elsewhere");
        std::fs::write(&target, br#"{"version":1,"images":[]}"#).expect("target");
        symlink(&target, dir.join(CRI_IMAGE_RECORDS_FILE_NAME)).expect("symlink");
        let s = PersistentImageStore::open(&dir).expect("open");
        assert_eq!(s.list(), Err(ImageStoreError::Corrupt));

        let dir = scratch("unsafe-mode");
        let f = write_records_file(&dir, br#"{"version":1,"images":[]}"#);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).expect("chmod");
        let s = PersistentImageStore::open(&dir).expect("open");
        assert_eq!(s.list(), Err(ImageStoreError::Corrupt));
        assert_eq!(
            s.upsert(rec("sha256:a", "t:1")),
            Err(ImageStoreError::Corrupt)
        );

        let dir = scratch("unsafe-dir");
        std::fs::create_dir(dir.join(CRI_IMAGE_RECORDS_FILE_NAME)).expect("mkdir");
        let s = PersistentImageStore::open(&dir).expect("open");
        assert_eq!(s.get("x"), Err(ImageStoreError::Corrupt));
    }

    /// OCI-7: oci の ImageStore と同じ root で共存する。自前の残骸は open が消し、oci は触れない。
    #[test]
    fn oci7_coexists_with_oci_store() {
        let dir = scratch("coexist");
        let seed = PersistentImageStore::open(&dir).expect("seed");
        seed.upsert(rec("sha256:aaa", "t:1")).expect("upsert");
        drop(seed);
        let leftover = dir.join(format!("{TMP_PREFIX}1-1"));
        std::fs::write(&leftover, b"x").expect("leftover");

        let oci = OciImageStore::open(&dir).expect("oci open");
        {
            let _g = oci.lock().expect("oci lock");
        }
        oci.recover_stale_pulls().expect("recover");
        assert!(leftover.exists(), "oci must not touch the cri leftovers");

        let store = PersistentImageStore::open(&dir).expect("reopen");
        assert!(!leftover.exists());
        assert_eq!(store.list().expect("list").len(), 1);
    }

    /// CRI-2・OCI-7: rename 後のディレクトリ fsync が失敗しても、永続側は新しい内容になっているため、
    /// メモリ表示も新しい対応へ揃い（古いタグの対応を使い続けない）、`Io` を返す。再起動後の見え方とも一致する。
    #[test]
    fn cri2_oci7_post_publish_sync_failure_resyncs_view() {
        let dir = scratch("postpub");
        let s = PersistentImageStore::open(&dir).expect("open");
        s.upsert(rec("sha256:aaa", "t:1")).expect("first");
        let r = s.upsert_with(
            rec("sha256:bbb", "t:1"),
            WriteOps {
                sync: |_| Err(std::io::Error::other("injected")),
                ..PRODUCTION_OPS
            },
        );
        assert_eq!(r, Err(ImageStoreError::Io));
        assert_eq!(s.get("t:1").expect("get").expect("rec").id(), "sha256:bbb");
        drop(s);
        let again = PersistentImageStore::open(&dir).expect("reopen");
        assert_eq!(
            again.get("t:1").expect("get").expect("rec").id(),
            "sha256:bbb"
        );
    }

    /// CRI-2: upsert は排他区間でファイルを読み直す。別の store の書き込みを落とさない。
    #[test]
    fn cri2_upsert_rereads_disk() {
        let dir = scratch("reread");
        let a = PersistentImageStore::open(&dir).expect("a");
        let b = PersistentImageStore::open(&dir).expect("b");
        a.upsert(rec("sha256:aaa", "t:a")).expect("a upsert");
        b.upsert(rec("sha256:bbb", "t:b")).expect("b upsert");
        let c = PersistentImageStore::open(&dir).expect("c");
        let ids: Vec<String> = c
            .list()
            .expect("list")
            .iter()
            .map(|r| r.id().to_owned())
            .collect();
        assert_eq!(ids, vec!["sha256:aaa", "sha256:bbb"]);
    }

    fn two_image_service(dir: &Path) -> (Arc<PersistentImageStore>, CriImageService) {
        let store = Arc::new(PersistentImageStore::open(dir).expect("open"));
        store
            .upsert(
                ImageRecord::new(
                    "sha256:aaa",
                    vec!["reg/a:1".into(), "reg/a:latest".into()],
                    vec!["reg/a@sha256:11".into()],
                    4096,
                )
                .expect("a"),
            )
            .expect("upsert a");
        store
            .upsert(
                ImageRecord::new("sha256:bbb", vec!["reg/b:2".into()], vec![], 2048).expect("b"),
            )
            .expect("upsert b");
        let svc = CriImageService::with_store(store.clone());
        (store, svc)
    }

    async fn images(svc: &CriImageService) -> Vec<v1::Image> {
        svc.list_images(Request::new(v1::ListImagesRequest::default()))
            .await
            .expect("list")
            .into_inner()
            .images
    }

    async fn image_status(svc: &CriImageService, r: &str) -> Option<v1::Image> {
        svc.image_status(Request::new(v1::ImageStatusRequest {
            image: Some(v1::ImageSpec {
                image: r.to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .expect("status")
        .into_inner()
        .image
    }

    async fn remove_image(svc: &CriImageService, r: &str) -> Result<(), Code> {
        svc.remove_image(Request::new(v1::RemoveImageRequest {
            image: Some(v1::ImageSpec {
                image: r.to_owned(),
                ..Default::default()
            }),
        }))
        .await
        .map(|_| ())
        .map_err(|s| s.code())
    }

    /// CRI-1・CRI-2・OCI-7: 2 イメージが再起動後も同じ ID・タグ・サイズで ListImages / ImageStatus に出る。
    #[tokio::test]
    async fn cri1_cri2_two_images_survive_reopen_with_same_status() {
        let dir = scratch("two-reopen");
        let (store, svc) = two_image_service(&dir);
        let before = images(&svc).await;
        let status_before = (
            image_status(&svc, "reg/a:1").await,
            image_status(&svc, "reg/b:2").await,
        );
        drop((svc, store));

        let (_s2, svc2) = {
            let s = Arc::new(PersistentImageStore::open(&dir).expect("reopen"));
            (s.clone(), CriImageService::with_store(s))
        };
        let after = images(&svc2).await;
        assert_eq!(after.len(), 2);
        assert_eq!(after, before);
        let a = image_status(&svc2, "reg/a:1").await.expect("a");
        assert_eq!((a.id.as_str(), a.size), ("sha256:aaa", 4096));
        assert_eq!(a.repo_tags, vec!["reg/a:1", "reg/a:latest"]);
        let b = image_status(&svc2, "reg/b:2").await.expect("b");
        assert_eq!((b.id.as_str(), b.size), ("sha256:bbb", 2048));
        assert_eq!(
            (Some(a), Some(b)),
            (status_before.0.clone(), status_before.1.clone())
        );
    }

    /// CRI-1・CRI-2・OCI-7: RemoveImage は記録ごと（全タグ）外し、再起動後も戻らない。残りは変わらない。
    #[tokio::test]
    async fn cri1_cri2_remove_image_persists_across_reopen() {
        let dir = scratch("rm-reopen");
        let (store, svc) = two_image_service(&dir);
        let b_before = image_status(&svc, "reg/b:2").await.expect("b");
        assert_eq!(remove_image(&svc, "reg/a:1").await, Ok(()));
        for phase in 0..2 {
            let svc = if phase == 0 {
                CriImageService::with_store(store.clone())
            } else {
                CriImageService::with_store(Arc::new(
                    PersistentImageStore::open(&dir).expect("reopen"),
                ))
            };
            let list = images(&svc).await;
            assert_eq!(list.len(), 1, "phase {phase}");
            assert_eq!(list[0].id, "sha256:bbb");
            for gone in ["reg/a:1", "reg/a:latest", "sha256:aaa", "reg/a@sha256:11"] {
                assert!(image_status(&svc, gone).await.is_none(), "{gone}");
            }
            assert_eq!(image_status(&svc, "reg/b:2").await, Some(b_before.clone()));
        }
    }

    /// CRI-2: 存在しない参照の RemoveImage は成功し、ファイルを書き換えない。再起動後も同じ。
    #[tokio::test]
    async fn cri2_remove_image_absent_is_idempotent_across_reopen() {
        let dir = scratch("rm-absent");
        let empty = Arc::new(PersistentImageStore::open(&dir).expect("open"));
        let svc = CriImageService::with_store(empty);
        assert_eq!(remove_image(&svc, "reg/none:1").await, Ok(()));
        assert!(!dir.join(CRI_IMAGE_RECORDS_FILE_NAME).exists());
        drop(svc);

        let dir = scratch("rm-absent2");
        let (_store, svc) = two_image_service(&dir);
        let file = dir.join(CRI_IMAGE_RECORDS_FILE_NAME);
        let bytes = std::fs::read(&file).expect("read");
        assert_eq!(remove_image(&svc, "reg/none:1").await, Ok(()));
        assert_eq!(remove_image(&svc, "reg/none:1").await, Ok(()));
        assert_eq!(std::fs::read(&file).expect("read"), bytes);
        let reopened = CriImageService::with_store(Arc::new(
            PersistentImageStore::open(&dir).expect("reopen"),
        ));
        assert_eq!(remove_image(&reopened, "reg/none:1").await, Ok(()));
        assert_eq!(images(&reopened).await.len(), 2);
    }

    /// CRI-2・OCI-7: rename 前の失敗はメモリも永続側も元のまま（食い違わない）。一時ファイルも残らない。
    #[test]
    fn cri2_oci7_remove_pre_publish_failure_keeps_view_and_disk() {
        let dir = scratch("rm-prepub");
        let s = PersistentImageStore::open(&dir).expect("open");
        s.upsert(rec("sha256:aaa", "t:a")).expect("a");
        s.upsert(rec("sha256:bbb", "t:b")).expect("b");
        let r = s.remove_with(
            "t:a",
            None,
            WriteOps {
                rename: |_, _| Err(std::io::Error::other("injected")),
                ..PRODUCTION_OPS
            },
        );
        assert_eq!(r, Err(ImageStoreError::Io));
        assert_eq!(s.list().expect("list").len(), 2);
        let leftovers = std::fs::read_dir(&dir)
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(TMP_PREFIX))
            .count();
        assert_eq!(leftovers, 0);
        drop(s);
        let again = PersistentImageStore::open(&dir).expect("reopen");
        assert_eq!(again.list().expect("list").len(), 2);
    }

    /// CRI-2・OCI-7・#4177: 短縮名の削除は 1 回の排他区間で解決する。正規化形に当たれば消し、どちらにも当たらなければ他の記録を残す。
    #[test]
    fn cri2_oci7_remove_resolving_uses_canonical_in_one_commit() {
        let dir = scratch("rm-resolving");
        let s = PersistentImageStore::open(&dir).expect("open");
        s.upsert(rec("sha256:aaa", "docker.io/library/busybox:1.36"))
            .expect("a");
        assert_eq!(
            s.remove_resolving("nomatch", Some("docker.io/library/other:1")),
            Ok(RemoveOutcome::Absent)
        );
        assert_eq!(s.list().expect("list").len(), 1);
        assert_eq!(
            s.remove_resolving("busybox:1.36", Some("docker.io/library/busybox:1.36")),
            Ok(RemoveOutcome::Removed {
                id: "sha256:aaa".to_owned()
            })
        );
        assert!(s.list().expect("list").is_empty());
    }

    /// CRI-2・OCI-7: rename 後のディレクトリ fsync の失敗では、メモリ表示が新しい内容へ揃い、再起動後と一致する。
    #[test]
    fn cri2_oci7_remove_post_publish_failure_resyncs_view() {
        let dir = scratch("rm-postpub");
        let s = PersistentImageStore::open(&dir).expect("open");
        s.upsert(rec("sha256:aaa", "t:a")).expect("a");
        s.upsert(rec("sha256:bbb", "t:b")).expect("b");
        let r = s.remove_with(
            "t:a",
            None,
            WriteOps {
                sync: |_| Err(std::io::Error::other("injected")),
                ..PRODUCTION_OPS
            },
        );
        assert_eq!(r, Err(ImageStoreError::Io));
        let ids = |st: &PersistentImageStore| -> Vec<String> {
            st.list()
                .expect("list")
                .iter()
                .map(|r| r.id().to_owned())
                .collect()
        };
        assert_eq!(ids(&s), vec!["sha256:bbb"]);
        drop(s);
        assert_eq!(
            ids(&PersistentImageStore::open(&dir).expect("reopen")),
            vec!["sha256:bbb"]
        );
    }

    /// CRI-2: 別の store が先に消した記録の remove は成功（Absent）し、メモリ表示が永続側へ揃う。
    #[test]
    fn cri2_remove_rereads_disk_and_converges() {
        let dir = scratch("rm-reread");
        let a = PersistentImageStore::open(&dir).expect("a");
        a.upsert(rec("sha256:aaa", "t:a")).expect("upsert");
        let b = PersistentImageStore::open(&dir).expect("b");
        assert_eq!(
            b.remove("t:a"),
            Ok(RemoveOutcome::Removed {
                id: "sha256:aaa".into()
            })
        );
        assert_eq!(a.list().expect("stale view").len(), 1);
        assert_eq!(a.remove("t:a"), Ok(RemoveOutcome::Absent));
        assert_eq!(a.list().expect("converged"), vec![]);
    }

    /// OCI-7・CRI-2: 壊れた記録で開いたストアの remove は Corrupt（RPC は Internal）。ファイルは上書きしない。
    #[tokio::test]
    async fn cri2_oci7_remove_on_corrupt_store_fails_closed() {
        let dir = scratch("rm-corrupt");
        let file = write_records_file(&dir, b"{ not json");
        let store = Arc::new(PersistentImageStore::open(&dir).expect("open"));
        assert_eq!(store.remove("x"), Err(ImageStoreError::Corrupt));
        let svc = CriImageService::with_store(store);
        assert_eq!(remove_image(&svc, "x").await, Err(Code::Internal));
        assert_eq!(std::fs::read(file).expect("read"), b"{ not json");
    }
}
