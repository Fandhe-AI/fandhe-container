//! コンテナ参照テーブル（エントリと世代カウンタ）のディスク永続化（OCI-7・TASK-183.8 追補・#2341）。
//!
//! # 役割と呼び出し元
//!
//! CLI は常駐デーモンを持たない（CORE-1）ため、プロセスが変わると参照テーブルのメモリ上の内容は失われる。
//! 別プロセスの `image rm` / `image prune` が使用中の manifest を消さないよう、また世代カウンタが 1 から
//! やり直して過去の世代を再発行しないよう、コンテナ参照の部分だけをイメージストア root 直下の
//! [`CONTAINER_REFS_FILE_NAME`] へ保存する。読み込みは `ImageStore::lock` の排他区間に入るたびに
//! （`store` モジュール）、書き込みはコンテナ参照を変える `ImageStore` の入口（`container_ref` / `reconcile`）が
//! 排他区間の中で行う。
//!
//! # 永続化しないもの（実装済みを装わない。REPAIR-3）
//!
//! manifest の在庫と構成・タグ・pull リースは、別ファイル `@image-inventory.json` に永続化する（#2380。
//! `inventory_persist`）。各操作が書き換えるのはどちらか一方のファイルだけで、
//! 両方を同じ排他区間で読み直す。在庫ファイルが無い（本番で在庫を埋める経路は未実装）場合などは、
//! 読み直した直後のエントリがテーブルに無い manifest を指しうる。読み込みでは在庫を確かめない。参照数の集計・未確定の
//! 一覧・照合・`remove_manifest` の参照確認は manifest の在庫が無くても正しく動く。一方 blob の参照は
//! manifest の構成から数えるため、在庫に無い manifest への参照は構成が分からず、その manifest だけが
//! 使う blob を守れない。このため `has_unresolved_container_refs` が真の間は `image rm` / `image prune` が
//! blob ファイルを一切削除しない（残す側へ倒す。manifest の外し自体は従来どおり）。残ったままの一時ファイル（クラッシュ時の `*.tmp-*`）は、`ImageStore::lock` の
//! 取得直後（排他区間の中。書き手は排他の中でしか作らないので残っているものは中断の残骸）に通常ファイルだけを回収する（#2379・OCI-7。
//! 照合 `reconcile_container_refs` も最初に lock を取るので同じ経路で回収される）。読み込みは固定名のファイルしか見ない。
//!
//! # 形式と安全性
//!
//! JSON（`version`・`next_generation`・id 昇順の `entries`）。書き込みは一時ファイル → `fsync` → `rename`
//! → （unix は）親ディレクトリの `fsync` で、途中で落ちても古い完全なファイルか新しい完全なファイルの
//! どちらかしか読まれない。読み込みは外部入力として扱い、確保の前にサイズと件数の上限を検証し、壊れた・
//! 矛盾したファイルは fail-closed で拒否する（空として扱うと参照が消えて GC が誤削除するため）。
//! 世代の矛盾（`generation >= next_generation`・重複）は再発行の恐れがあるため `DataLoss` とする。
//! group / other に書き込み権のあるファイル（`PermissionDenied`）・symlink・通常ファイル以外（`Internal`）も拒否する。
//! root の所有者・権限・祖先の検査は `ImageStore::open` が行う（#2381。unix のみ）。読み書きは検査済み root の
//! ハンドル（`root_handle::RootHandle`）起点で、Linux の x86_64 / aarch64 では検査後に root が差し替えられても
//! 差し替え後のディレクトリへ届かない（#2638。他の OS はパス起点で入口の再検査のみ）。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use std::cell::Cell;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use super::root_handle::RootHandle;
use super::{ContainerRefEntry, ContainerRefGeneration, ContainerRefId, ReferenceTable};
use crate::error::{OciError, OciErrorCode};
use crate::reference::Digest;

/// ストア root 直下のコンテナ参照ファイル名。`@` で始め、`blobs/`・`staging/` の走査にかからない。
pub const CONTAINER_REFS_FILE_NAME: &str = "@container-refs.json";

/// 保存の一時ファイル名の接頭辞（`<固定名>.tmp-<pid>-<nonce>`）。書き込み中のクラッシュで残ったものは
/// `ImageStore::lock` の取得直後に `gc_journal::reap_stale_tmp` が回収する（#2379・OCI-7）。
pub(super) const CONTAINER_REFS_TMP_PREFIX: &str = "@container-refs.json.tmp-";

/// 永続化できるコンテナ参照の件数の上限（読み込みでも書き込みでも守る）。
pub const MAX_CONTAINER_REFS: usize = 16_384;

/// 1 件あたりの最大バイト数の見積り（id 255・manifest 71 に、キー・世代・区切りの余裕を足した値）。
const BYTES_PER_ENTRY: u64 = 512;

/// コンテナ参照ファイルの最大バイト数（約 8 MiB。確保の前に検証する）。
pub const MAX_CONTAINER_REFS_FILE_BYTES: u64 = MAX_CONTAINER_REFS as u64 * BYTES_PER_ENTRY + 4096;

const FORMAT_VERSION: u32 = 1;

#[derive(Serialize)]
struct RawOut<'a> {
    version: u32,
    next_generation: u64,
    entries: Vec<RawEntryOut<'a>>,
}

#[derive(Serialize)]
struct RawEntryOut<'a> {
    id: &'a str,
    manifest: &'a str,
    generation: u64,
    bound: bool,
}

struct RawIn {
    version: u32,
    next_generation: u64,
    entries: Vec<RawEntryIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntryIn {
    id: String,
    manifest: String,
    generation: u64,
    bound: bool,
}

/// 読み込み結果（検証済み）。
#[derive(Debug)]
pub(super) struct PersistedContainerRefs {
    entries: BTreeMap<ContainerRefId, ContainerRefEntry>,
    next_generation: u64,
}

fn e(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

/// 保存に失敗したときに戻すための、コンテナ参照部分の複製。
#[derive(Debug, Clone)]
pub(super) struct ContainerPortion {
    entries: BTreeMap<ContainerRefId, ContainerRefEntry>,
    next_generation: u64,
}

impl ReferenceTable {
    /// コンテナ参照の部分の複製（保存に失敗したときに戻すため）。
    pub(super) fn container_portion(&self) -> ContainerPortion {
        ContainerPortion {
            entries: self.container_refs.clone(),
            next_generation: self.next_container_generation,
        }
    }

    /// `container_portion` で取った複製へ戻す。
    pub(super) fn restore_container_portion(&mut self, p: ContainerPortion) {
        self.container_refs = p.entries;
        self.next_container_generation = p.next_generation;
    }

    /// 構成が分からない（在庫に無い manifest を指す）コンテナ参照があるか。真の間は、どの blob が
    /// その manifest の構成に含まれるか分からないため、blob の削除を拒否する（OCI-7 fail-closed。#2341）。
    pub fn has_unresolved_container_refs(&self) -> bool {
        self.container_refs
            .values()
            .any(|en| !self.manifests.contains_key(&en.manifest))
    }

    /// 読み込んだ内容で置き換える。世代カウンタは単調性を保つため大きい方を採る。
    pub(super) fn apply_persisted_container_refs(&mut self, p: PersistedContainerRefs) {
        self.container_refs = p.entries;
        self.next_container_generation = self.next_container_generation.max(p.next_generation);
    }
}

/// 保存先が信頼できる通常ファイルか（通常ファイル以外・他者書き込み可を拒否）。
fn check_trust(m: &fs::Metadata) -> Result<(), OciError> {
    if !m.is_file() {
        return Err(e(
            OciErrorCode::Internal,
            "container refs file is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.mode() & 0o022 != 0 {
            return Err(e(
                OciErrorCode::PermissionDenied,
                "container refs file is writable by group or others",
            ));
        }
    }
    Ok(())
}

/// コンテナ参照ファイルを読む。無ければ `Ok(None)`（永続化された状態なし）。
pub(super) fn load_container_refs(
    root: &RootHandle,
) -> Result<Option<PersistedContainerRefs>, OciError> {
    load_with_limits(root, MAX_CONTAINER_REFS, MAX_CONTAINER_REFS_FILE_BYTES)
}

fn load_with_limits(
    root: &RootHandle,
    max_entries: usize,
    max_bytes: u64,
) -> Result<Option<PersistedContainerRefs>, OciError> {
    let pre = match root.stat_name(CONTAINER_REFS_FILE_NAME) {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(None),
        Err(_) => {
            return Err(e(
                OciErrorCode::Internal,
                "failed to inspect the container refs file",
            ));
        }
    };
    check_trust(&pre)?;
    let open_failed = || {
        e(
            OciErrorCode::Internal,
            "failed to open the container refs file",
        )
    };
    let file = root
        .open_read(CONTAINER_REFS_FILE_NAME)
        .map_err(|_| open_failed())?
        .ok_or_else(open_failed)?;
    let post = file.metadata().map_err(|_| {
        e(
            OciErrorCode::Internal,
            "failed to inspect the container refs file",
        )
    })?;
    check_trust(&post)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != post.dev() || pre.ino() != post.ino() {
            return Err(e(
                OciErrorCode::Internal,
                "container refs file changed while opening",
            ));
        }
    }
    let len = post.len();
    if len > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "container refs file is too large",
        ));
    }
    // len は上限検証済み。読み込み中に伸びた場合に備え take でも上限をかける。
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|_| {
            e(
                OciErrorCode::Internal,
                "failed to read the container refs file",
            )
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "container refs file is too large",
        ));
    }
    parse(&buf, max_entries).map(Some)
}

/// 件数上限つきで `RawIn` を読む種。`entries` は上限を超える要素を蓄積する前に拒否する
/// （通常の `Vec` で読むと全件確保した後でしか件数を検査できない）。
struct RawInSeed<'a> {
    max_entries: usize,
    exceeded: &'a Cell<bool>,
}

struct EntriesSeed<'a> {
    max_entries: usize,
    exceeded: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for EntriesSeed<'_> {
    type Value = Vec<RawEntryIn>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a>(usize, &'a Cell<bool>);
        impl<'de> Visitor<'de> for V<'_> {
            type Value = Vec<RawEntryIn>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of container refs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(item) = seq.next_element::<RawEntryIn>()? {
                    if v.len() >= self.0 {
                        self.1.set(true);
                        return Err(de::Error::custom("too many container refs"));
                    }
                    v.push(item);
                }
                Ok(v)
            }
        }
        d.deserialize_seq(V(self.max_entries, self.exceeded))
    }
}

impl<'de> DeserializeSeed<'de> for RawInSeed<'_> {
    type Value = RawIn;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a>(usize, &'a Cell<bool>);
        impl<'de> Visitor<'de> for V<'_> {
            type Value = RawIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a container refs object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut version, mut next, mut entries) = (None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" if version.is_none() => version = Some(map.next_value()?),
                        "next_generation" if next.is_none() => next = Some(map.next_value()?),
                        "entries" if entries.is_none() => {
                            entries = Some(map.next_value_seed(EntriesSeed {
                                max_entries: self.0,
                                exceeded: self.1,
                            })?);
                        }
                        _ => return Err(de::Error::custom("unknown or duplicate field")),
                    }
                }
                match (version, next, entries) {
                    (Some(version), Some(next_generation), Some(entries)) => Ok(RawIn {
                        version,
                        next_generation,
                        entries,
                    }),
                    _ => Err(de::Error::custom("missing field")),
                }
            }
        }
        d.deserialize_map(V(self.max_entries, self.exceeded))
    }
}

fn parse(buf: &[u8], max_entries: usize) -> Result<PersistedContainerRefs, OciError> {
    let exceeded = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(buf);
    let parsed = RawInSeed {
        max_entries,
        exceeded: &exceeded,
    }
    .deserialize(&mut de)
    .and_then(|r| de.end().map(|()| r));
    let raw = match parsed {
        Ok(r) => r,
        Err(_) if exceeded.get() => {
            return Err(e(
                OciErrorCode::ResourceExhausted,
                "too many container refs",
            ));
        }
        Err(_) => {
            return Err(e(
                OciErrorCode::DataLoss,
                "container refs file is not valid JSON",
            ));
        }
    };
    if raw.version != FORMAT_VERSION {
        return Err(e(
            OciErrorCode::FailedPrecondition,
            "unsupported container refs file version",
        ));
    }
    if raw.next_generation == 0 {
        return Err(e(OciErrorCode::DataLoss, "invalid next generation"));
    }
    let mut entries = BTreeMap::new();
    let mut seen_gen = BTreeSet::new();
    for r in raw.entries {
        let id = ContainerRefId::new(&r.id)
            .map_err(|_| e(OciErrorCode::DataLoss, "invalid container id in refs file"))?;
        let manifest = Digest::parse(&r.manifest)
            .map_err(|_| e(OciErrorCode::DataLoss, "invalid manifest in refs file"))?;
        if r.generation == 0 || r.generation >= raw.next_generation {
            return Err(e(
                OciErrorCode::DataLoss,
                "container ref generation out of range",
            ));
        }
        if !seen_gen.insert(r.generation) {
            return Err(e(
                OciErrorCode::DataLoss,
                "duplicate container ref generation",
            ));
        }
        let entry = ContainerRefEntry {
            manifest,
            generation: ContainerRefGeneration(r.generation),
            bound: r.bound,
        };
        if entries.insert(id, entry).is_some() {
            return Err(e(OciErrorCode::DataLoss, "duplicate container id"));
        }
    }
    Ok(PersistedContainerRefs {
        entries,
        next_generation: raw.next_generation,
    })
}

/// 保存用の一時ファイルごとの一意な採番（プロセス内で単調増加）。
fn next_tmp_nonce() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn tmp_name(nonce: u64) -> String {
    format!("{CONTAINER_REFS_TMP_PREFIX}{}-{nonce}", std::process::id())
}

#[cfg(test)]
thread_local! {
    /// 試験用: 真の間、`save_container_refs` は書かずに失敗する。
    static FAIL_SAVE: Cell<bool> = const { Cell::new(false) };
}

/// テーブルのコンテナ参照部分を保存する（一時ファイル → fsync → rename → 親ディレクトリ fsync）。
pub(super) fn save_container_refs(
    root: &RootHandle,
    table: &ReferenceTable,
) -> Result<(), OciError> {
    #[cfg(test)]
    if FAIL_SAVE.with(Cell::get) {
        // 権限に依存せず（root・DAC 迂回環境でも）保存失敗を再現する試験用の注入。
        return Err(e(OciErrorCode::Internal, "injected save failure"));
    }
    save_with_limits(
        root,
        table,
        MAX_CONTAINER_REFS,
        MAX_CONTAINER_REFS_FILE_BYTES,
    )
}

fn save_with_limits(
    root: &RootHandle,
    table: &ReferenceTable,
    max_entries: usize,
    max_bytes: u64,
) -> Result<(), OciError> {
    if table.container_refs.len() > max_entries {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "too many container refs to persist",
        ));
    }
    let out = RawOut {
        version: FORMAT_VERSION,
        next_generation: table.next_container_generation.max(1),
        entries: table
            .container_refs
            .iter()
            .map(|(id, en)| RawEntryOut {
                id: id.as_str(),
                manifest: en.manifest.as_str(),
                generation: en.generation.0,
                bound: en.bound,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&out)
        .map_err(|_| e(OciErrorCode::Internal, "failed to serialize container refs"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "container refs file would be too large",
        ));
    }
    let tmp = tmp_name(next_tmp_nonce());
    let result = write_and_rename(root, &tmp, &bytes);
    if result.is_err() {
        // rename 前の失敗では一時ファイルを残さない（ベストエフォート）。
        let _ = root.unlink(&tmp);
    }
    result
}

/// 一時ファイルを書いて固定名へ公開し、root を fsync する。すべて検査済み root の fd 起点（#2638）。
fn write_and_rename(root: &RootHandle, tmp: &str, bytes: &[u8]) -> Result<(), OciError> {
    let fail = |msg: &'static str| e(OciErrorCode::Internal, msg);
    let mut f = root
        .create_new(tmp)
        .map_err(|_| fail("failed to create the container refs temp file"))?;
    f.write_all(bytes)
        .map_err(|_| fail("failed to write the container refs temp file"))?;
    f.sync_all()
        .map_err(|_| fail("failed to sync the container refs temp file"))?;
    drop(f);
    root.rename(tmp, CONTAINER_REFS_FILE_NAME)
        .map_err(|_| fail("failed to replace the container refs file"))?;
    // 新しい名前を永続化する（Windows ではディレクトリを開けないため `sync` は何もしない）。
    root.sync()
        .map_err(|_| fail("failed to sync the image store directory"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::root_handle::rh;
    use crate::image_management::{ContainerRefRelease, ImageStore, ManifestComposition};
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn cid(s: &str) -> ContainerRefId {
        ContainerRefId::new(s).expect("id")
    }

    fn root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-cref-persist-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        p
    }

    /// manifest `d(0xa0)` を種に入れたストアを開く（在庫は永続化されないので毎回入れ直す）。
    fn open(root: &Path) -> ImageStore {
        let store = ImageStore::open(root)
            .expect("open")
            .with_timeout(Duration::from_millis(500));
        seed(&store);
        store
    }

    fn seed(store: &ImageStore) {
        store
            .lock()
            .expect("lock")
            .register_manifest(
                d(0xa0),
                ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
            )
            .expect("manifest");
    }

    fn write_file(root: &Path, json: &str) {
        fs::write(root.join(CONTAINER_REFS_FILE_NAME), json).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.join(CONTAINER_REFS_FILE_NAME),
                fs::Permissions::from_mode(0o600),
            )
            .expect("chmod");
        }
    }

    fn lock_code(root: &Path) -> OciErrorCode {
        let s = ImageStore::open(root)
            .expect("open")
            .with_timeout(Duration::from_millis(500));
        s.lock().expect_err("must fail").code()
    }

    fn entry_json(id: &str, generation: u64) -> String {
        format!(
            r#"{{"id":"{id}","manifest":"sha256:{}","generation":{generation},"bound":true}}"#,
            "a0".repeat(32)
        )
    }

    fn containers_of(s: &ImageStore, m: u8) -> Vec<ContainerRefId> {
        s.lock()
            .expect("lock")
            .manifest_references(&d(m))
            .containers
    }

    /// OCI-7・#2341: 登録・確定・解除の状態と世代が、開き直した後も具体値で一致する。
    #[test]
    fn oci7_save_and_reload_preserves_state_and_generations() {
        let r = root("reload");
        {
            let a = open(&r);
            a.register_container_ref(&cid("c1"), &d(0xa0)).expect("c1");
            a.register_container_ref(&cid("c2"), &d(0xa0)).expect("c2");
            assert_eq!(a.bind_container_ref(&cid("c2")).expect("bind").as_raw(), 2);
            a.register_container_ref(&cid("c3"), &d(0xa0)).expect("c3");
            assert_eq!(
                a.release_container_ref(&cid("c3")).expect("rel"),
                ContainerRefRelease::Released(d(0xa0))
            );
        }
        let b = open(&r);
        let unbound: Vec<_> = {
            let g = b.lock().expect("lock");
            g.unbound_containers()
                .map(|(i, g, m)| (i.clone(), g.as_raw(), m.clone()))
                .collect()
        };
        assert_eq!(unbound, vec![(cid("c1"), 1, d(0xa0))]);
        assert_eq!(
            b.container_ref_registration(&cid("c2"))
                .expect("r")
                .map(|g| g.as_raw()),
            Some(2)
        );
        assert_eq!(b.container_ref_registration(&cid("c1")).expect("r"), None);
        assert_eq!(
            b.release_container_ref(&cid("c3")).expect("c3"),
            ContainerRefRelease::NotRegistered
        );
        assert_eq!(containers_of(&b, 0xa0), vec![cid("c1"), cid("c2")]);
        b.register_container_ref(&cid("c4"), &d(0xa0)).expect("c4");
        assert_eq!(b.bind_container_ref(&cid("c4")).expect("bind").as_raw(), 4);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 解除した ID の再登録は過去の世代を再発行せず、旧世代の解除は効かない。
    #[test]
    fn oci7_generation_is_not_reissued_after_reopen() {
        let r = root("regen");
        {
            let a = open(&r);
            a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
            let g1 = a.bind_container_ref(&cid("c1")).expect("bind");
            assert_eq!(g1.as_raw(), 1);
            a.release_container_ref(&cid("c1")).expect("rel");
        }
        let b = open(&r);
        b.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let g2 = b.bind_container_ref(&cid("c1")).expect("bind");
        assert_eq!(g2.as_raw(), 2);
        assert_eq!(
            b.release_container_ref_if(&cid("c1"), ContainerRefGeneration::from_raw(1))
                .expect("stale"),
            ContainerRefRelease::NotRegistered
        );
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 同じ root の 2 ハンドルは区間ごとにディスクを読み直し、世代が重複しない。
    #[test]
    fn oci7_two_handles_share_state_per_critical_section() {
        let r = root("share");
        let a = open(&r);
        let b = open(&r);
        a.register_container_ref(&cid("c1"), &d(0xa0)).expect("c1");
        assert_eq!(b.bind_container_ref(&cid("c1")).expect("b").as_raw(), 1);
        b.register_container_ref(&cid("c2"), &d(0xa0)).expect("c2");
        a.register_container_ref(&cid("c3"), &d(0xa0)).expect("c3");
        assert_eq!(a.bind_container_ref(&cid("c3")).expect("c3").as_raw(), 3);
        assert_eq!(b.bind_container_ref(&cid("c2")).expect("c2").as_raw(), 2);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 壊れた JSON は DataLoss で、ファイルは変わらない。
    #[test]
    fn oci7_corrupt_json_is_data_loss_and_file_untouched() {
        let r = root("corrupt");
        write_file(&r, "{not json");
        assert_eq!(lock_code(&r), OciErrorCode::DataLoss);
        assert_eq!(
            fs::read_to_string(r.join(CONTAINER_REFS_FILE_NAME)).expect("read"),
            "{not json"
        );
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 上限を 1 バイト超えるファイルは確保の前に ResourceExhausted。
    #[test]
    fn oci7_oversized_file_is_resource_exhausted() {
        let r = root("big");
        write_file(&r, "");
        let f = OpenOptions::new()
            .write(true)
            .open(r.join(CONTAINER_REFS_FILE_NAME))
            .expect("open");
        f.set_len(MAX_CONTAINER_REFS_FILE_BYTES + 1).expect("len");
        drop(f);
        assert_eq!(lock_code(&r), OciErrorCode::ResourceExhausted);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 件数上限（小さい上限で検証）を超えると ResourceExhausted、上限ちょうどは通る。
    #[test]
    fn oci7_too_many_entries_is_resource_exhausted() {
        let json = format!(
            r#"{{"version":1,"next_generation":10,"entries":[{},{}]}}"#,
            entry_json("c1", 1),
            entry_json("c2", 2)
        );
        assert_eq!(
            parse(json.as_bytes(), 1).expect_err("over").code(),
            OciErrorCode::ResourceExhausted
        );
        assert_eq!(parse(json.as_bytes(), 2).expect("exact").entries.len(), 2);
    }

    /// OCI-7・#2341: 世代・id・digest・版の矛盾は fail-closed で拒否する。
    #[test]
    fn oci7_inconsistent_content_is_rejected() {
        let wrap = |next: u64, entries: &[String]| {
            format!(
                r#"{{"version":1,"next_generation":{next},"entries":[{}]}}"#,
                entries.join(",")
            )
        };
        let code = |s: String| parse(s.as_bytes(), 10).expect_err("reject").code();
        assert_eq!(
            code(wrap(5, &[entry_json("c1", 5)])),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(wrap(5, &[entry_json("c1", 0)])),
            OciErrorCode::DataLoss
        );
        assert_eq!(code(wrap(0, &[])), OciErrorCode::DataLoss);
        assert_eq!(
            code(wrap(5, &[entry_json("c1", 2), entry_json("c2", 2)])),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(wrap(5, &[entry_json("c1", 2), entry_json("c1", 3)])),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(wrap(5, &[entry_json("../x", 2)])),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(wrap(
                5,
                &[r#"{"id":"c1","manifest":"bad","generation":1,"bound":true}"#.to_string()]
            )),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(r#"{"version":2,"next_generation":1,"entries":[]}"#.to_string()),
            OciErrorCode::FailedPrecondition
        );
    }

    /// OCI-7・#2341: symlink とディレクトリの参照ファイルは拒否し、リンク先を変えない。
    #[cfg(unix)]
    #[test]
    fn oci7_symlink_and_directory_are_rejected() {
        let r = root("symlink");
        let target = r.join("target.json");
        fs::write(&target, "orig").expect("write");
        std::os::unix::fs::symlink(&target, r.join(CONTAINER_REFS_FILE_NAME)).expect("link");
        assert_eq!(lock_code(&r), OciErrorCode::Internal);
        assert_eq!(fs::read_to_string(&target).expect("read"), "orig");
        let _ = fs::remove_dir_all(&r);

        let r = root("dir");
        fs::create_dir(r.join(CONTAINER_REFS_FILE_NAME)).expect("dir");
        assert_eq!(lock_code(&r), OciErrorCode::Internal);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 作るファイルは 0600、group 書き込み可のファイルは読まない。
    #[cfg(unix)]
    #[test]
    fn oci7_file_mode_is_0600_and_group_writable_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let r = root("mode");
        let a = open(&r);
        a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let path = r.join(CONTAINER_REFS_FILE_NAME);
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("chmod");
        assert_eq!(lock_code(&r), OciErrorCode::PermissionDenied);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 残った一時ファイル（書きかけを含む）は読み込みに影響せず、完全な状態だけが読まれる。
    #[test]
    fn oci7_leftover_temp_file_is_ignored() {
        let r = root("tmp");
        {
            let a = open(&r);
            a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        }
        fs::write(
            r.join(format!("{CONTAINER_REFS_FILE_NAME}.tmp-1-1")),
            r#"{"version":1,"next_gener"#,
        )
        .expect("tmp");
        let b = open(&r);
        assert_eq!(containers_of(&b, 0xa0), vec![cid("c1")]);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2379: クラッシュで残った参照表の一時ファイルは lock 取得時に回収される。symlink・ディレクトリ・
    /// 固定名の本体・無関係なファイルは残り、登録済みの参照は変わらない。
    #[test]
    fn oci7_stale_container_refs_tmp_is_reaped_on_lock() {
        let r = root("reap-tmp");
        {
            let a = open(&r);
            a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        }
        let stale = r.join(format!("{CONTAINER_REFS_TMP_PREFIX}1-1"));
        fs::write(&stale, r#"{"version":1,"next_gener"#).expect("tmp");
        let dir = r.join(format!("{CONTAINER_REFS_TMP_PREFIX}2-2"));
        fs::create_dir(&dir).expect("dir");
        let unrelated = r.join("unrelated.tmp-1");
        fs::write(&unrelated, b"keep").expect("unrelated");
        #[cfg(unix)]
        let link = {
            let link = r.join(format!("{CONTAINER_REFS_TMP_PREFIX}3-3"));
            std::os::unix::fs::symlink(&unrelated, &link).expect("symlink");
            link
        };
        let b = open(&r);
        assert!(fs::symlink_metadata(&stale).is_err());
        assert!(dir.is_dir());
        assert!(unrelated.exists());
        #[cfg(unix)]
        assert!(fs::symlink_metadata(&link).is_ok());
        assert!(r.join(CONTAINER_REFS_FILE_NAME).is_file());
        assert_eq!(containers_of(&b, 0xa0), vec![cid("c1")]);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2379: 照合（`reconcile_container_refs`）の経路でも、残った一時ファイルが回収される。
    #[test]
    fn oci7_reconcile_reaps_stale_container_refs_tmp() {
        use crate::image_management::ContainerStatePresence;
        let r = root("reap-reconcile");
        let a = open(&r);
        a.register_container_ref(&cid("c1"), &d(0xa0)).expect("reg");
        let stale = r.join(format!("{CONTAINER_REFS_TMP_PREFIX}9-9"));
        fs::write(&stale, b"partial").expect("tmp");
        a.reconcile_container_refs(|_| ContainerStatePresence::Present)
            .expect("reconcile");
        assert!(fs::symlink_metadata(&stale).is_err());
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 件数・サイズの上限を超える保存は ResourceExhausted で、既存ファイルを壊さない。
    #[test]
    fn oci7_save_over_limits_is_rejected_and_keeps_existing_file() {
        let r = root("save-limits");
        {
            let a = open(&r);
            a.register_container_ref(&cid("c1"), &d(0xa0)).expect("c1");
        }
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
        )
        .expect("m");
        t.register_container(cid("x1"), &d(0xa0)).expect("x1");
        t.register_container(cid("x2"), &d(0xa0)).expect("x2");
        assert_eq!(
            save_with_limits(&rh(&r), &t, 1, MAX_CONTAINER_REFS_FILE_BYTES)
                .expect_err("over")
                .code(),
            OciErrorCode::ResourceExhausted
        );
        assert_eq!(
            save_with_limits(&rh(&r), &t, 2, 10)
                .expect_err("bytes")
                .code(),
            OciErrorCode::ResourceExhausted
        );
        let b = open(&r);
        assert_eq!(containers_of(&b, 0xa0), vec![cid("c1")]);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 登録が件数上限に達していたら ResourceExhausted でテーブルを変えない。
    #[test]
    fn oci7_register_at_limit_is_rejected() {
        let r = root("reg-limit");
        let a = open(&r);
        {
            let mut g = a.lock().expect("lock");
            for i in 0..MAX_CONTAINER_REFS {
                g.register_container(cid(&format!("c{i}")), &d(0xa0))
                    .expect("seed");
            }
        }
        let e = a
            .register_container_ref(&cid("overflow"), &d(0xa0))
            .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        let g = a.lock().expect("lock");
        assert_eq!(g.container_refs.len(), MAX_CONTAINER_REFS);
        assert_eq!(g.next_container_generation, MAX_CONTAINER_REFS as u64 + 1);
        drop(g);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 保存に失敗したら登録を戻して保存のエラーを返し、件数と次の世代が変わらない。
    #[test]
    fn oci7_failed_save_rolls_back_table() {
        /// 失敗注入を必ず解除する（assert が失敗しても他の試験へ漏らさない）。
        struct FailGuard;
        impl FailGuard {
            fn on() -> Self {
                FAIL_SAVE.with(|f| f.set(true));
                FailGuard
            }
        }
        impl Drop for FailGuard {
            fn drop(&mut self) {
                FAIL_SAVE.with(|f| f.set(false));
            }
        }
        let r = root("rollback");
        let a = open(&r);
        a.register_container_ref(&cid("c1"), &d(0xa0)).expect("c1");
        let before = fs::read(r.join(CONTAINER_REFS_FILE_NAME)).expect("read");
        {
            let _fail = FailGuard::on();
            let err = a
                .register_container_ref(&cid("c2"), &d(0xa0))
                .expect_err("save fails");
            assert_eq!(err.code(), OciErrorCode::Internal);
            let g = a.lock().expect("lock");
            assert_eq!(g.container_refs.len(), 1);
            assert_eq!(g.next_container_generation, 2);
        }
        assert_eq!(
            fs::read(r.join(CONTAINER_REFS_FILE_NAME)).expect("read"),
            before
        );
        assert_eq!(containers_of(&open(&r), 0xa0), vec![cid("c1")]);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 在庫に無い manifest への参照が残る間は、`image rm` / `image prune` が blob を消さない。
    #[test]
    fn oci7_unresolved_container_ref_blocks_blob_deletion() {
        let r = root("unresolved");
        // 別プロセスが manifest B（レイヤー 0x10 を共有）へのコンテナ参照を保存した状態を作る。
        write_file(
            &r,
            &format!(
                r#"{{"version":1,"next_generation":2,"entries":[{{"id":"other","manifest":"sha256:{}","generation":1,"bound":true}}]}}"#,
                "b0".repeat(32)
            ),
        );
        let s = open(&r);
        let g = s.lock().expect("lock");
        assert!(g.has_unresolved_container_refs());
        let plan = g.plan_image_prune();
        assert_eq!(plan.delete_blobs, Vec::<Digest>::new());
        assert_eq!(plan.manifests, vec![d(0xa0)]);
        assert_eq!(plan.kept_shared_blobs, vec![d(0x10), d(0xc1)]);
        drop(g);
        let _ = fs::remove_dir_all(r);
    }

    /// OCI-7・#2341: 件数上限は要素を蓄積する前に効く（上限 + 1 件目で打ち切る）。
    #[test]
    fn oci7_entries_limit_applies_while_deserializing() {
        let many: Vec<String> = (1..=50).map(|i| entry_json(&format!("c{i}"), i)).collect();
        let json = format!(
            r#"{{"version":1,"next_generation":100,"entries":[{}]}}"#,
            many.join(",")
        );
        assert_eq!(
            parse(json.as_bytes(), 3).expect_err("over").code(),
            OciErrorCode::ResourceExhausted
        );
        assert_eq!(parse(json.as_bytes(), 50).expect("ok").entries.len(), 50);
        // 未知のフィールドと末尾のゴミは DataLoss。
        assert_eq!(
            parse(
                br#"{"version":1,"next_generation":1,"entries":[],"x":1}"#,
                3
            )
            .expect_err("unknown")
            .code(),
            OciErrorCode::DataLoss
        );
    }
}
