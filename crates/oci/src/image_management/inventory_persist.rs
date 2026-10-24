//! manifest の在庫・タグ・pull リースのディスク永続化（OCI-7・TASK-183 追補・#2380）。
//!
//! # 役割と呼び出し元
//!
//! CLI は常駐デーモンを持たない（CORE-1）ため、プロセスが変わるとメモリ上の参照テーブルは失われる。
//! コンテナ参照（`container_ref_persist`・#2341）に続き、テーブルの残り 3 種、つまり manifest の在庫と構成
//! （`manifests`）・タグ（`tag_refs`）・pull リース（`pull_leases`）をイメージストア root 直下の
//! [`IMAGE_INVENTORY_FILE_NAME`] へ保存する。読み込みは `ImageStore::lock` の排他区間に入るたびに
//! （`store` モジュール）行い、書き込みは在庫・タグ・リースを変えるひとまとまりの操作の入口
//! （`tag`・`remove`・`prune`・`gc_journal` の復旧・`pull`・`pull_recovery`）が排他区間の中で行う。
//! これにより、別プロセスの `PullSession` のリースが `image rm` / `image prune` と削除ジャーナルの復旧の
//! 数え直しに入り、`image tag` のタグがプロセスをまたいで残る。
//!
//! コンテナ参照は別ファイル（`@container-refs.json`）のまま分ける。各操作が書き換えるのはどちらか一方の
//! ファイルだけで、1 操作 = 1 ファイルの原子的な更新で整合を保てるため。
//!
//! # 書き込みの規約
//!
//! 下位の変更メソッド（`register_manifest`・`register_tag`・`acquire_lease` 等）は保存しない。保存するのは
//! ひとまとまりの操作の入口だけで、手順は「在庫部分の複製を取る → 変更 → `ReferenceTable::persist_inventory`
//! で 1 回だけ保存 → 失敗したら複製へ戻してエラー」とする。保存先の root は `ImageStore::lock` が区間ごとに
//! 設定する `journal_root` を使う（単体のテーブルでは `None` で保存しない）。ガードから下位メソッドを直接
//! 呼んだ変更は保存されず、ファイルがあれば次の排他取得でディスクの内容に置き換わる（試験と `with_table` の
//! 種入れ用の口。コンテナ参照と同じ扱い）。保存の最後の親ディレクトリ `fsync` だけが失敗した場合は、
//! ディスクは新しい状態でメモリは戻り、次の排他取得でディスクに揃う。
//!
//! # 形式と安全性
//!
//! JSON（`version`・digest 昇順の `manifests`・`TagKey` 昇順の `tags`・blob 昇順の `leases`）。書き込みは
//! 一時ファイル → `fsync` → `rename` → （unix は）親ディレクトリの `fsync` で、途中で落ちても古い完全な
//! ファイルか新しい完全なファイルのどちらかしか読まれない。読み込みは外部入力として扱い、確保の前に
//! サイズを、蓄積の前に件数を上限検証し、壊れた・矛盾したファイルは fail-closed で拒否する（空として
//! 扱うとリースや参照が消えて GC が誤削除するため）。タグが在庫に無い manifest を指すファイルは
//! `register_tag` の不変条件違反として `DataLoss` とする。group / other に書き込み権のあるファイル
//! （`PermissionDenied`）・symlink・通常ファイル以外（`Internal`）も拒否する。
//!
//! root の所有者・権限・祖先の検査は `ImageStore::open` が行い、`lock` と create ゲートの取得ごとに
//! 再検査する（#2381・#2547。unix のみ）。root は所有者専用のディレクトリである前提で、ここでは
//! 通常ファイル・symlink・権限・dev/ino だけを見る。
//! 読み書きは検査済み root のハンドル（`root_handle::RootHandle`）起点で、Linux の x86_64 / aarch64 では
//! 検査後に root が差し替えられても差し替え後のディレクトリへ届かない（#2638）。
//!
//! # 既知の残り（実装済みを装わない。REPAIR-3）
//!
//! `staging/<pull-id>` が無いのに残った永続化済みのリース（保存の順序「リース解放を保存してからステージングを
//! 消す」を守る限り通常は生じない）を解放する経路は無い。`recover_stale_pulls` はステージングを手がかりに
//! 回収するため、その経路が拾えない孤児リースは blob を余分に残す側にだけ作用する。

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use super::root_handle::RootHandle;
use super::tag::MAX_TAG_REFS;
use super::{ManifestComposition, PullId, ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::reference::{Digest, RegistryHost, Repository, Tag};

/// ストア root 直下の在庫ファイル名。`@` で始め、`blobs/`・`staging/` の走査にかからない。
pub const IMAGE_INVENTORY_FILE_NAME: &str = "@image-inventory.json";

/// 保存の一時ファイル名の接頭辞（`<固定名>.tmp-<pid>-<nonce>`）。書き込み中のクラッシュで残ったものは
/// `ImageStore::lock` の取得直後に `gc_journal::reap_stale_tmp` が回収する（#2379 と同じ経路）。
pub(super) const IMAGE_INVENTORY_TMP_PREFIX: &str = "@image-inventory.json.tmp-";

/// 永続化できる manifest の件数の上限（読み込みでも書き込みでも守る）。
pub const MAX_IMAGE_MANIFESTS: usize = 2_048;

/// 永続化できる pull リース（blob と pull ID の組）の総数の上限（読み込みでも書き込みでも守る）。
pub const MAX_PULL_LEASES: usize = 16_384;

/// manifest 1 件の最大バイト数の見積り（config と layers 128 件の digest に、キー・区切りの余裕を足した値）。
const BYTES_PER_MANIFEST: u64 = 10_240;
/// タグ 1 件の最大バイト数の見積り（host 259・repository 255・tag 128・manifest 71 に、キー等の余裕を足した値）。
const BYTES_PER_TAG: u64 = 1_024;
/// リース 1 組の最大バイト数の見積り（blob 71・pull ID 128 に、キー・区切りの余裕を足した値）。
const BYTES_PER_LEASE: u64 = 384;

/// 在庫ファイルの最大バイト数（確保の前に検証する）。
pub const MAX_IMAGE_INVENTORY_FILE_BYTES: u64 = MAX_IMAGE_MANIFESTS as u64 * BYTES_PER_MANIFEST
    + MAX_TAG_REFS as u64 * BYTES_PER_TAG
    + MAX_PULL_LEASES as u64 * BYTES_PER_LEASE
    + 4096;

const FORMAT_VERSION: u32 = 1;

fn e(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

// ---- 保存用の形 ----

#[derive(Serialize)]
struct RawOut<'a> {
    version: u32,
    manifests: Vec<RawManifestOut<'a>>,
    tags: Vec<RawTagOut<'a>>,
    leases: Vec<RawLeaseOut<'a>>,
}

#[derive(Serialize)]
struct RawManifestOut<'a> {
    digest: &'a str,
    config: &'a str,
    layers: Vec<&'a str>,
}

#[derive(Serialize)]
struct RawTagOut<'a> {
    host: String,
    repository: &'a str,
    tag: String,
    manifest: &'a str,
}

#[derive(Serialize)]
struct RawLeaseOut<'a> {
    blob: &'a str,
    pulls: Vec<&'a str>,
}

// ---- 読み込み用の形 ----

struct RawIn {
    version: u32,
    manifests: Vec<RawManifestIn>,
    tags: Vec<RawTagIn>,
    leases: Vec<RawLeaseIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestIn {
    digest: String,
    config: String,
    layers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTagIn {
    host: String,
    repository: String,
    tag: String,
    manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLeaseIn {
    blob: String,
    pulls: Vec<String>,
}

/// 在庫・タグ・リースの 3 種の複製（保存に失敗したときに戻すため）であり、読み込み結果の型でもある。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct InventoryPortion {
    manifests: BTreeMap<Digest, ManifestComposition>,
    tag_refs: BTreeMap<TagKey, Digest>,
    pull_leases: BTreeMap<Digest, BTreeSet<PullId>>,
}

impl ReferenceTable {
    /// 在庫・タグ・リースの複製（保存に失敗したときに戻すため）。
    pub(super) fn inventory_portion(&self) -> InventoryPortion {
        InventoryPortion {
            manifests: self.manifests.clone(),
            tag_refs: self.tag_refs.clone(),
            pull_leases: self.pull_leases.clone(),
        }
    }

    /// `inventory_portion` で取った複製へ戻す。
    pub(super) fn restore_inventory_portion(&mut self, p: InventoryPortion) {
        self.manifests = p.manifests;
        self.tag_refs = p.tag_refs;
        self.pull_leases = p.pull_leases;
    }

    /// 読み込んだ内容で 3 種をまとめて置き換える（ディスクを正とする）。
    pub(super) fn apply_persisted_inventory(&mut self, p: InventoryPortion) {
        self.restore_inventory_portion(p);
    }

    /// 現在の 3 種が `p` と同じか（変わっていなければ保存しないために使う）。
    fn inventory_equals(&self, p: &InventoryPortion) -> bool {
        self.manifests == p.manifests
            && self.tag_refs == p.tag_refs
            && self.pull_leases == p.pull_leases
    }

    /// pull リースの組（blob と pull ID）の総数。
    pub(super) fn lease_pair_count(&self) -> usize {
        self.pull_leases.values().map(BTreeSet::len).sum()
    }

    /// 在庫・タグ・リースを排他区間の root へ保存する。`before` から変わっていなければ書かない。
    ///
    /// 失敗したら `before` へ戻して保存のエラーを返す。root が未設定の単体テーブルでは何もしない。
    /// 呼び出し元はひとまとまりの操作の入口で、`before` は変更の前に `inventory_portion` で取る。
    pub(super) fn persist_inventory(&mut self, before: InventoryPortion) -> Result<(), OciError> {
        let Some(root) = self.journal_root.0.clone() else {
            return Ok(());
        };
        if self.inventory_equals(&before) {
            return Ok(());
        }
        match save_image_inventory(&root, self) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.restore_inventory_portion(before);
                Err(err)
            }
        }
    }
}

/// 保存先が信頼できる通常ファイルか（通常ファイル以外・他者書き込み可を拒否）。
fn check_trust(m: &fs::Metadata) -> Result<(), OciError> {
    if !m.is_file() {
        return Err(e(
            OciErrorCode::Internal,
            "image inventory file is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.mode() & 0o022 != 0 {
            return Err(e(
                OciErrorCode::PermissionDenied,
                "image inventory file is writable by group or others",
            ));
        }
    }
    Ok(())
}

/// 在庫ファイルを読む。無ければ `Ok(None)`（永続化された状態なし。メモリ上の内容を保つ）。
pub(super) fn load_image_inventory(
    root: &RootHandle,
) -> Result<Option<InventoryPortion>, OciError> {
    load_with_limits(root, Limits::DEFAULT, MAX_IMAGE_INVENTORY_FILE_BYTES)
}

/// 件数の上限（試験で小さい値を注入できるようにまとめる）。
#[derive(Clone, Copy)]
struct Limits {
    manifests: usize,
    tags: usize,
    leases: usize,
}

impl Limits {
    const DEFAULT: Limits = Limits {
        manifests: MAX_IMAGE_MANIFESTS,
        tags: MAX_TAG_REFS,
        leases: MAX_PULL_LEASES,
    };
}

fn load_with_limits(
    root: &RootHandle,
    limits: Limits,
    max_bytes: u64,
) -> Result<Option<InventoryPortion>, OciError> {
    let pre = match root.stat_name(IMAGE_INVENTORY_FILE_NAME) {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(None),
        Err(_) => {
            return Err(e(
                OciErrorCode::Internal,
                "failed to inspect the image inventory file",
            ));
        }
    };
    check_trust(&pre)?;
    let open_failed = || {
        e(
            OciErrorCode::Internal,
            "failed to open the image inventory file",
        )
    };
    let file = root
        .open_read(IMAGE_INVENTORY_FILE_NAME)
        .map_err(|_| open_failed())?
        .ok_or_else(open_failed)?;
    let post = file.metadata().map_err(|_| {
        e(
            OciErrorCode::Internal,
            "failed to inspect the image inventory file",
        )
    })?;
    check_trust(&post)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != post.dev() || pre.ino() != post.ino() {
            return Err(e(
                OciErrorCode::Internal,
                "image inventory file changed while opening",
            ));
        }
    }
    let len = post.len();
    if len > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "image inventory file is too large",
        ));
    }
    // len は上限検証済み。読み込み中に伸びた場合に備え take でも上限をかける。
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|_| {
            e(
                OciErrorCode::Internal,
                "failed to read the image inventory file",
            )
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "image inventory file is too large",
        ));
    }
    parse(&buf, limits).map(Some)
}

/// 件数上限つきで配列を読む種。上限を超える要素は蓄積する前に拒否する
/// （通常の `Vec` で読むと全件確保した後でしか件数を検査できない）。
/// `make` は要素 1 件ごとの種を作る（入れ子の配列にも上限を掛けるため）。
struct CappedSeq<'a, F> {
    max: usize,
    exceeded: &'a Cell<bool>,
    make: F,
}

impl<'de, S, F> DeserializeSeed<'de> for CappedSeq<'_, F>
where
    S: DeserializeSeed<'de>,
    F: Fn() -> S,
{
    type Value = Vec<S::Value>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a, F>(usize, &'a Cell<bool>, F);
        impl<'de, S, F> Visitor<'de> for V<'_, F>
        where
            S: DeserializeSeed<'de>,
            F: Fn() -> S,
        {
            type Value = Vec<S::Value>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of image inventory entries")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(item) = seq.next_element_seed((self.2)())? {
                    if v.len() >= self.0 {
                        self.1.set(true);
                        return Err(de::Error::custom("too many image inventory entries"));
                    }
                    v.push(item);
                }
                Ok(v)
            }
        }
        d.deserialize_seq(V(self.max, self.exceeded, self.make))
    }
}

/// manifest 1 件の種。`layers` は `MAX_LAYERS` 件を超える要素を確保前に拒否する。
struct ManifestSeed<'a> {
    exceeded: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for ManifestSeed<'_> {
    type Value = RawManifestIn;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a>(&'a Cell<bool>);
        impl<'de> Visitor<'de> for V<'_> {
            type Value = RawManifestIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an image inventory manifest entry")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut digest, mut config, mut layers) = (None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "digest" if digest.is_none() => digest = Some(map.next_value()?),
                        "config" if config.is_none() => config = Some(map.next_value()?),
                        "layers" if layers.is_none() => {
                            layers = Some(map.next_value_seed(CappedSeq {
                                max: crate::manifest::MAX_LAYERS,
                                exceeded: self.0,
                                make: || std::marker::PhantomData::<String>,
                            })?);
                        }
                        _ => return Err(de::Error::custom("unknown or duplicate field")),
                    }
                }
                match (digest, config, layers) {
                    (Some(digest), Some(config), Some(layers)) => Ok(RawManifestIn {
                        digest,
                        config,
                        layers,
                    }),
                    _ => Err(de::Error::custom("missing field")),
                }
            }
        }
        d.deserialize_map(V(self.exceeded))
    }
}

/// リース 1 件の種。`pulls` はファイル全体で共有する残り件数（`remaining`）を超える要素を
/// 確保前に拒否し、読めた件数を残りから引く。
struct LeaseSeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for LeaseSeed<'_> {
    type Value = RawLeaseIn;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a>(&'a Cell<usize>, &'a Cell<bool>);
        impl<'de> Visitor<'de> for V<'_> {
            type Value = RawLeaseIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an image inventory lease entry")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut blob, mut pulls) = (None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "blob" if blob.is_none() => blob = Some(map.next_value()?),
                        "pulls" if pulls.is_none() => {
                            let list: Vec<String> = map.next_value_seed(CappedSeq {
                                max: self.0.get(),
                                exceeded: self.1,
                                make: || std::marker::PhantomData::<String>,
                            })?;
                            self.0.set(self.0.get().saturating_sub(list.len()));
                            pulls = Some(list);
                        }
                        _ => return Err(de::Error::custom("unknown or duplicate field")),
                    }
                }
                match (blob, pulls) {
                    (Some(blob), Some(pulls)) => Ok(RawLeaseIn { blob, pulls }),
                    _ => Err(de::Error::custom("missing field")),
                }
            }
        }
        d.deserialize_map(V(self.remaining, self.exceeded))
    }
}

struct RawInSeed<'a> {
    limits: Limits,
    exceeded: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for RawInSeed<'_> {
    type Value = RawIn;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<'a>(Limits, &'a Cell<bool>);
        impl<'de> Visitor<'de> for V<'_> {
            type Value = RawIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an image inventory object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut version, mut manifests, mut tags, mut leases) = (None, None, None, None);
                let remaining = Cell::new(self.0.leases);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" if version.is_none() => version = Some(map.next_value()?),
                        "manifests" if manifests.is_none() => {
                            manifests = Some(map.next_value_seed(CappedSeq {
                                max: self.0.manifests,
                                exceeded: self.1,
                                make: || ManifestSeed { exceeded: self.1 },
                            })?);
                        }
                        "tags" if tags.is_none() => {
                            tags = Some(map.next_value_seed(CappedSeq {
                                max: self.0.tags,
                                exceeded: self.1,
                                make: || std::marker::PhantomData::<RawTagIn>,
                            })?);
                        }
                        "leases" if leases.is_none() => {
                            leases = Some(map.next_value_seed(CappedSeq {
                                max: self.0.leases,
                                exceeded: self.1,
                                make: || LeaseSeed {
                                    remaining: &remaining,
                                    exceeded: self.1,
                                },
                            })?);
                        }
                        _ => return Err(de::Error::custom("unknown or duplicate field")),
                    }
                }
                match (version, manifests, tags, leases) {
                    (Some(version), Some(manifests), Some(tags), Some(leases)) => Ok(RawIn {
                        version,
                        manifests,
                        tags,
                        leases,
                    }),
                    _ => Err(de::Error::custom("missing field")),
                }
            }
        }
        d.deserialize_map(V(self.limits, self.exceeded))
    }
}

fn bad(msg: &'static str) -> OciError {
    e(OciErrorCode::DataLoss, msg)
}

fn parse(buf: &[u8], limits: Limits) -> Result<InventoryPortion, OciError> {
    let exceeded = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(buf);
    let parsed = RawInSeed {
        limits,
        exceeded: &exceeded,
    }
    .deserialize(&mut de)
    .and_then(|r| de.end().map(|()| r));
    let raw = match parsed {
        Ok(r) => r,
        Err(_) if exceeded.get() => {
            return Err(e(
                OciErrorCode::ResourceExhausted,
                "too many image inventory entries",
            ));
        }
        Err(_) => {
            return Err(bad("image inventory file is not valid JSON"));
        }
    };
    if raw.version != FORMAT_VERSION {
        return Err(e(
            OciErrorCode::FailedPrecondition,
            "unsupported image inventory file version",
        ));
    }
    let digest = |s: &str| Digest::parse(s).map_err(|_| bad("invalid digest in image inventory"));

    let mut manifests = BTreeMap::new();
    for m in &raw.manifests {
        let layers = m
            .layers
            .iter()
            .map(|s| digest(s))
            .collect::<Result<Vec<_>, _>>()?;
        let composition = ManifestComposition::new(digest(&m.config)?, layers)?;
        if manifests.insert(digest(&m.digest)?, composition).is_some() {
            return Err(bad("duplicate manifest in image inventory"));
        }
    }

    let mut tag_refs = BTreeMap::new();
    for t in &raw.tags {
        let invalid = || bad("invalid tag in image inventory");
        let key = TagKey::new(
            RegistryHost::parse(&t.host).map_err(|_| invalid())?,
            Repository::parse(&t.repository).map_err(|_| invalid())?,
            Tag::parse(&t.tag).map_err(|_| invalid())?,
        );
        let target = digest(&t.manifest)?;
        // register_tag の不変条件: タグは在庫にある manifest だけを指す。
        if !manifests.contains_key(&target) {
            return Err(bad("tag points to a manifest missing from the inventory"));
        }
        if tag_refs.insert(key, target).is_some() {
            return Err(bad("duplicate tag in image inventory"));
        }
    }

    let mut pull_leases: BTreeMap<Digest, BTreeSet<PullId>> = BTreeMap::new();
    let mut pairs = 0usize;
    for l in &raw.leases {
        if l.pulls.is_empty() {
            return Err(bad("lease without pull ids in image inventory"));
        }
        let mut set = BTreeSet::new();
        for p in &l.pulls {
            let id = PullId::new(p).map_err(|_| bad("invalid pull id in image inventory"))?;
            if !set.insert(id) {
                return Err(bad("duplicate pull id in image inventory"));
            }
        }
        pairs = pairs.saturating_add(set.len());
        if pairs > limits.leases {
            return Err(e(
                OciErrorCode::ResourceExhausted,
                "too many pull leases in image inventory",
            ));
        }
        if pull_leases.insert(digest(&l.blob)?, set).is_some() {
            return Err(bad("duplicate lease blob in image inventory"));
        }
    }
    Ok(InventoryPortion {
        manifests,
        tag_refs,
        pull_leases,
    })
}

/// 保存用の一時ファイルごとの一意な採番（プロセス内で単調増加）。
fn next_tmp_nonce() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn tmp_name(nonce: u64) -> String {
    format!("{IMAGE_INVENTORY_TMP_PREFIX}{}-{nonce}", std::process::id())
}

#[cfg(test)]
thread_local! {
    /// 試験用: 真の間、`save_image_inventory` は書かずに失敗する。
    static FAIL_SAVE: Cell<bool> = const { Cell::new(false) };
}

/// 試験用: このスレッドの在庫の保存失敗の注入を切り替える（権限に依存せず保存失敗を再現する）。
#[cfg(test)]
pub(super) fn set_fail_save(on: bool) {
    FAIL_SAVE.with(|c| c.set(on));
}

/// テーブルの在庫・タグ・リースを保存する（一時ファイル → fsync → rename → 親ディレクトリ fsync）。
pub(super) fn save_image_inventory(
    root: &RootHandle,
    table: &ReferenceTable,
) -> Result<(), OciError> {
    #[cfg(test)]
    if FAIL_SAVE.with(Cell::get) {
        return Err(e(OciErrorCode::Internal, "injected save failure"));
    }
    save_with_limits(root, table, Limits::DEFAULT, MAX_IMAGE_INVENTORY_FILE_BYTES)
}

fn save_with_limits(
    root: &RootHandle,
    table: &ReferenceTable,
    limits: Limits,
    max_bytes: u64,
) -> Result<(), OciError> {
    if table.manifests.len() > limits.manifests
        || table.tag_refs.len() > limits.tags
        || table.lease_pair_count() > limits.leases
    {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "too many image inventory entries to persist",
        ));
    }
    let out = RawOut {
        version: FORMAT_VERSION,
        manifests: table
            .manifests
            .iter()
            .map(|(d, c)| RawManifestOut {
                digest: d.as_str(),
                config: c.config().as_str(),
                layers: c.layers().iter().map(Digest::as_str).collect(),
            })
            .collect(),
        tags: table
            .tag_refs
            .iter()
            .map(|(k, m)| RawTagOut {
                host: k.host.to_string(),
                repository: k.repository.as_str(),
                tag: k.tag.to_string(),
                manifest: m.as_str(),
            })
            .collect(),
        leases: table
            .pull_leases
            .iter()
            .map(|(b, set)| RawLeaseOut {
                blob: b.as_str(),
                pulls: set.iter().map(PullId::as_str).collect(),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&out).map_err(|_| {
        e(
            OciErrorCode::Internal,
            "failed to serialize image inventory",
        )
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(e(
            OciErrorCode::ResourceExhausted,
            "image inventory file would be too large",
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
        .map_err(|_| fail("failed to create the image inventory temp file"))?;
    f.write_all(bytes)
        .map_err(|_| fail("failed to write the image inventory temp file"))?;
    f.sync_all()
        .map_err(|_| fail("failed to sync the image inventory temp file"))?;
    drop(f);
    root.rename(tmp, IMAGE_INVENTORY_FILE_NAME)
        .map_err(|_| fail("failed to replace the image inventory file"))?;
    // 新しい名前を永続化する（Windows ではディレクトリを開けないため `sync` は何もしない）。
    root.sync()
        .map_err(|_| fail("failed to sync the image store directory"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ImageStore;
    use crate::image_management::root_handle::rh;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn tk(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").expect("host"),
            Repository::parse("lib/app").expect("repo"),
            Tag::parse(t).expect("tag"),
        )
    }

    fn pid(s: &str) -> PullId {
        PullId::new(s).expect("pull id")
    }

    fn root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-inv-persist-{}-{}-{label}",
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

    fn open(root: &Path) -> ImageStore {
        ImageStore::open(root)
            .expect("open")
            .with_timeout(Duration::from_millis(500))
    }

    fn sample() -> ReferenceTable {
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).expect("comp"),
        )
        .expect("manifest a");
        t.register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10)]).expect("comp"),
        )
        .expect("manifest b");
        t.register_tag(tk("v1"), &d(0xa0)).expect("tag v1");
        t.register_tag(tk("v2"), &d(0xb0)).expect("tag v2");
        t.acquire_lease(d(0x10), pid("pull-1")).expect("lease");
        t.acquire_lease(d(0x10), pid("pull-2")).expect("lease");
        t.acquire_lease(d(0xc9), pid("pull-1")).expect("lease");
        t
    }

    fn code<T: fmt::Debug>(r: Result<T, OciError>) -> OciErrorCode {
        r.expect_err("must fail").code()
    }

    fn write_raw(root: &Path, body: &str) {
        let p = root.join(IMAGE_INVENTORY_FILE_NAME);
        fs::write(&p, body).expect("write");
        // umask に依らず信頼条件（group / other 書き込み不可）を満たす権限にする。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }

    /// OCI-7: 保存して読み直すと在庫・タグ・リースが具体値で戻る。
    #[test]
    fn oci7_round_trip_restores_inventory_tags_and_leases() {
        let r = root("roundtrip");
        let t = sample();
        save_image_inventory(&rh(&r), &t).expect("save");
        let loaded = load_image_inventory(&rh(&r)).expect("load").expect("some");
        assert_eq!(loaded, t.inventory_portion());
        assert_eq!(
            loaded.manifests.keys().cloned().collect::<Vec<_>>(),
            vec![d(0xa0), d(0xb0)]
        );
        assert_eq!(loaded.tag_refs.get(&tk("v1")), Some(&d(0xa0)));
        assert_eq!(loaded.pull_leases.get(&d(0x10)).map(BTreeSet::len), Some(2));
        // 一時ファイルは残らない。
        let leftovers = fs::read_dir(&r)
            .expect("ls")
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(IMAGE_INVENTORY_TMP_PREFIX)
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    /// OCI-7: ファイルが無ければ `None`（メモリ上の内容を保つ）。
    #[test]
    fn oci7_missing_file_loads_as_none() {
        let r = root("missing");
        assert!(load_image_inventory(&rh(&r)).expect("load").is_none());
    }

    /// OCI-7: 入れ子の `layers`（`MAX_LAYERS` 超）と `pulls`（ファイル全体の残りリース件数超）も
    /// 確保前に `ResourceExhausted` で拒否する。
    #[test]
    fn oci7_load_rejects_over_limit_nested_arrays() {
        let r = root("nested-limits");
        let lim = Limits {
            manifests: 4,
            tags: 4,
            leases: 3,
        };
        let a = d(0x10).as_str().to_owned();
        let layers = vec![format!("\"{}\"", d(1).as_str()); crate::manifest::MAX_LAYERS + 1];
        let body = format!(
            r#"{{"version":{FORMAT_VERSION},"manifests":[{{"digest":"{}","config":"{}","layers":[{}]}}],"tags":[],"leases":[]}}"#,
            d(2).as_str(),
            d(3).as_str(),
            layers.join(",")
        );
        write_raw(&r, &body);
        assert_eq!(
            code(load_with_limits(
                &rh(&r),
                lim,
                MAX_IMAGE_INVENTORY_FILE_BYTES
            )),
            OciErrorCode::ResourceExhausted
        );
        // 2 件 + 2 件 = 4 件のリースは上限 3 を超える（2 件目の pulls の途中で拒否される）。
        let b = d(0x11).as_str().to_owned();
        let body = format!(
            r#"{{"version":{FORMAT_VERSION},"manifests":[],"tags":[],"leases":[{{"blob":"{a}","pulls":["p1","p2"]}},{{"blob":"{b}","pulls":["p3","p4"]}}]}}"#
        );
        write_raw(&r, &body);
        assert_eq!(
            code(load_with_limits(
                &rh(&r),
                lim,
                MAX_IMAGE_INVENTORY_FILE_BYTES
            )),
            OciErrorCode::ResourceExhausted
        );
        // ちょうど 3 件なら受け入れる。
        let body = format!(
            r#"{{"version":{FORMAT_VERSION},"manifests":[],"tags":[],"leases":[{{"blob":"{a}","pulls":["p1","p2"]}},{{"blob":"{b}","pulls":["p3"]}}]}}"#
        );
        write_raw(&r, &body);
        assert!(load_with_limits(&rh(&r), lim, MAX_IMAGE_INVENTORY_FILE_BYTES).is_ok());
    }

    /// OCI-7: 件数の上限超過は蓄積の前に `ResourceExhausted`（小さい上限を注入して確かめる）。
    #[test]
    fn oci7_load_rejects_over_limit_counts() {
        let r = root("limits");
        save_image_inventory(&rh(&r), &sample()).expect("save");
        let lim = |manifests, tags, leases| Limits {
            manifests,
            tags,
            leases,
        };
        for (l, label) in [
            (lim(1, 16, 16), "manifests"),
            (lim(16, 1, 16), "tags"),
            (lim(16, 16, 1), "leases"),
            (lim(16, 16, 2), "lease pairs"),
        ] {
            assert_eq!(
                code(load_with_limits(&rh(&r), l, MAX_IMAGE_INVENTORY_FILE_BYTES)),
                OciErrorCode::ResourceExhausted,
                "{label}"
            );
        }
        // 上限ちょうどは通る（manifests 2・tags 2・leases の組 3）。
        assert!(load_with_limits(&rh(&r), lim(2, 2, 3), MAX_IMAGE_INVENTORY_FILE_BYTES).is_ok());
    }

    /// OCI-7: サイズ上限超過は読み込む前に `ResourceExhausted`。
    #[test]
    fn oci7_load_rejects_oversized_file() {
        let r = root("size");
        save_image_inventory(&rh(&r), &sample()).expect("save");
        assert_eq!(
            code(load_with_limits(&rh(&r), Limits::DEFAULT, 16)),
            OciErrorCode::ResourceExhausted
        );
    }

    /// OCI-7: 壊れた・矛盾したファイルは fail-closed（version は FailedPrecondition、他は DataLoss）。
    #[test]
    fn oci7_load_rejects_corrupt_or_inconsistent_files() {
        let man = |dg: &str| format!(r#"{{"digest":"{dg}","config":"{}","layers":[]}}"#, d(1));
        let tag = |m: &str| {
            format!(
                r#"{{"host":"registry.example","repository":"lib/app","tag":"v1","manifest":"{m}"}}"#
            )
        };
        let doc = |v: u32, m: &str, t: &str, l: &str| {
            format!(r#"{{"version":{v},"manifests":[{m}],"tags":[{t}],"leases":[{l}]}}"#)
        };
        let a = d(0xa0).to_string();
        let cases: Vec<(String, OciErrorCode, &str)> = vec![
            (
                doc(2, "", "", ""),
                OciErrorCode::FailedPrecondition,
                "version",
            ),
            ("{".to_string(), OciErrorCode::DataLoss, "broken json"),
            (
                r#"{"version":1,"manifests":[],"tags":[],"leases":[],"extra":1}"#.to_string(),
                OciErrorCode::DataLoss,
                "unknown field",
            ),
            (
                doc(1, &format!("{},{}", man(&a), man(&a)), "", ""),
                OciErrorCode::DataLoss,
                "duplicate manifest",
            ),
            (
                doc(1, &man(&a), &tag(&d(0xee).to_string()), ""),
                OciErrorCode::DataLoss,
                "tag to missing manifest",
            ),
            (
                doc(1, &man(&a), &format!("{0},{0}", tag(&a)), ""),
                OciErrorCode::DataLoss,
                "duplicate tag",
            ),
            (
                doc(1, "", "", &format!(r#"{{"blob":"{a}","pulls":[]}}"#)),
                OciErrorCode::DataLoss,
                "empty pulls",
            ),
            (
                doc(1, "", "", &format!(r#"{{"blob":"{a}","pulls":["x","x"]}}"#)),
                OciErrorCode::DataLoss,
                "duplicate pull id",
            ),
            (
                doc(1, "", "", &format!(r#"{{"blob":"{a}","pulls":["../x"]}}"#)),
                OciErrorCode::DataLoss,
                "invalid pull id",
            ),
            (
                doc(1, &man("sha256:zz"), "", ""),
                OciErrorCode::DataLoss,
                "invalid digest",
            ),
        ];
        for (body, want, label) in cases {
            let r = root("corrupt");
            write_raw(&r, &body);
            assert_eq!(code(load_image_inventory(&rh(&r))), want, "{label}");
        }
    }

    /// OCI-7: symlink・通常ファイル以外・group/other 書き込み可は拒否する。
    #[test]
    fn oci7_load_rejects_untrusted_files() {
        let r = root("trust-dir");
        fs::create_dir(r.join(IMAGE_INVENTORY_FILE_NAME)).expect("mkdir");
        assert_eq!(code(load_image_inventory(&rh(&r))), OciErrorCode::Internal);

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let r = root("trust-symlink");
            let real = r.join("real.json");
            save_image_inventory(&rh(&r), &sample()).expect("save");
            fs::rename(r.join(IMAGE_INVENTORY_FILE_NAME), &real).expect("mv");
            symlink(&real, r.join(IMAGE_INVENTORY_FILE_NAME)).expect("symlink");
            assert_eq!(code(load_image_inventory(&rh(&r))), OciErrorCode::Internal);

            let r = root("trust-perm");
            save_image_inventory(&rh(&r), &sample()).expect("save");
            let p = r.join(IMAGE_INVENTORY_FILE_NAME);
            fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).expect("chmod");
            assert_eq!(
                code(load_image_inventory(&rh(&r))),
                OciErrorCode::PermissionDenied
            );
        }
    }

    /// OCI-7: 最大件数のテーブルを直列化してもファイルサイズの上限に収まる。
    #[test]
    fn oci7_max_table_fits_within_file_size_limit() {
        let mut t = ReferenceTable::new();
        let dg = |n: usize| Digest::parse(&format!("sha256:{n:064x}")).expect("digest");
        for i in 0..MAX_IMAGE_MANIFESTS {
            let layers = (0..crate::manifest::MAX_LAYERS)
                .map(|j| dg(1_000_000 + i * 1000 + j))
                .collect();
            t.register_manifest(
                dg(i),
                ManifestComposition::new(dg(500_000 + i), layers).expect("comp"),
            )
            .expect("manifest");
        }
        let host = format!(
            "{}.{}.{}.{}:65535",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61)
        );
        for i in 0..MAX_TAG_REFS {
            let key = TagKey::new(
                RegistryHost::parse(&host).expect("host"),
                Repository::parse(&"a".repeat(255)).expect("repo"),
                Tag::parse(&format!("t{i:05}{}", "a".repeat(122))).expect("tag"),
            );
            t.register_tag(key, &dg(0)).expect("tag");
        }
        for i in 0..MAX_PULL_LEASES {
            let p = PullId::new(&format!("{i:06}{}", "p".repeat(122))).expect("pull");
            t.acquire_lease(dg(9_000_000 + i), p).expect("lease");
        }
        let r = root("max");
        save_image_inventory(&rh(&r), &t).expect("max table must be persistable");
        let len = fs::metadata(r.join(IMAGE_INVENTORY_FILE_NAME))
            .expect("meta")
            .len();
        assert!(len <= MAX_IMAGE_INVENTORY_FILE_BYTES, "{len}");
        // 往復も通る（上限ちょうどの件数を読み込める）。
        let loaded = load_image_inventory(&rh(&r)).expect("load").expect("some");
        assert_eq!(loaded.manifests.len(), MAX_IMAGE_MANIFESTS);
        assert_eq!(loaded.tag_refs.len(), MAX_TAG_REFS);
        let _ = fs::remove_dir_all(&r);
    }

    /// OCI-7: 書き込み側も上限を守る（保存できない状態を作らない）。
    #[test]
    fn oci7_register_beyond_limits_is_resource_exhausted() {
        let mut t = ReferenceTable::new();
        let dg = |n: usize| Digest::parse(&format!("sha256:{n:064x}")).expect("digest");
        for i in 0..MAX_IMAGE_MANIFESTS {
            t.register_manifest(
                dg(i),
                ManifestComposition::new(dg(100_000), vec![]).expect("comp"),
            )
            .expect("manifest");
        }
        let extra = ManifestComposition::new(dg(100_000), vec![]).expect("comp");
        assert_eq!(
            code(t.register_manifest(dg(MAX_IMAGE_MANIFESTS), extra.clone())),
            OciErrorCode::ResourceExhausted
        );
        // 既存キーの冪等な再登録は通る。
        t.register_manifest(dg(0), extra).expect("idempotent");
        assert_eq!(t.manifests().count(), MAX_IMAGE_MANIFESTS);

        for i in 0..MAX_PULL_LEASES {
            t.acquire_lease(dg(i), pid("p1")).expect("lease");
        }
        assert_eq!(
            code(t.acquire_lease(dg(MAX_PULL_LEASES), pid("p1"))),
            OciErrorCode::ResourceExhausted
        );
        // 既存の組の冪等な再取得は通る。
        assert!(
            !t.acquire_lease(dg(0), pid("p1"))
                .expect("again")
                .newly_added
        );
        assert_eq!(t.lease_pair_count(), MAX_PULL_LEASES);
    }

    /// OCI-7: 保存の失敗では一時ファイルを残さず、書き込み前のファイルも壊さない。
    #[test]
    fn oci7_failed_save_leaves_no_temp_file_and_keeps_old_file() {
        let r = root("savefail");
        save_image_inventory(&rh(&r), &sample()).expect("save");
        let before = fs::read(r.join(IMAGE_INVENTORY_FILE_NAME)).expect("read");
        // root を消すと create_new が失敗する（rename 前の失敗）。別 root で再現する。
        let gone = root("gone");
        let gone_handle = rh(&gone);
        fs::remove_dir_all(&gone).expect("remove root");
        assert_eq!(
            code(save_image_inventory(&gone_handle, &sample())),
            OciErrorCode::Internal
        );
        assert_eq!(
            fs::read(r.join(IMAGE_INVENTORY_FILE_NAME)).expect("read"),
            before
        );
        // 上限超過の保存は書かずに失敗する。
        let tiny = Limits {
            manifests: 1,
            tags: 1,
            leases: 1,
        };
        assert_eq!(
            code(save_with_limits(
                &rh(&r),
                &sample(),
                tiny,
                MAX_IMAGE_INVENTORY_FILE_BYTES
            )),
            OciErrorCode::ResourceExhausted
        );
        assert_eq!(
            code(save_with_limits(&rh(&r), &sample(), Limits::DEFAULT, 16)),
            OciErrorCode::ResourceExhausted
        );
        let names: Vec<String> = fs::read_dir(&r)
            .expect("ls")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![IMAGE_INVENTORY_FILE_NAME.to_string()]);
    }

    /// OCI-7: 別のストアインスタンス（別プロセス相当）の保存が、次の `lock` で見える。
    #[test]
    fn oci7_store_reload_sees_other_instances_saves() {
        let r = root("reload");
        let a = open(&r);
        {
            let mut g = a.lock().expect("lock");
            g.register_manifest(
                d(0xa0),
                ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
            )
            .expect("manifest");
        }
        let before = {
            let g = a.lock().expect("lock");
            g.inventory_portion()
        };
        {
            let mut g = a.lock().expect("lock");
            g.register_tag(tk("v1"), &d(0xa0)).expect("tag");
            g.persist_inventory(before).expect("persist");
        }
        let b = open(&r);
        let g = b.lock().expect("lock");
        assert_eq!(
            g.tags()
                .map(|(k, m)| (k.clone(), m.clone()))
                .collect::<Vec<_>>(),
            vec![(tk("v1"), d(0xa0))]
        );
        assert_eq!(g.manifests().count(), 1);
    }

    /// OCI-7: 壊れた在庫ファイルでは `lock` 自体が失敗する（fail-closed）。
    #[test]
    fn oci7_store_lock_fails_on_corrupt_inventory() {
        let r = root("lockfail");
        write_raw(&r, "{");
        let s = open(&r);
        assert_eq!(code(s.lock()), OciErrorCode::DataLoss);
    }

    /// OCI-7: 保存失敗の注入で `persist_inventory` はテーブルを元へ戻し、書かない。
    #[test]
    fn oci7_persist_failure_restores_table() {
        let r = root("restore");
        let s = open(&r);
        let mut g = s.lock().expect("lock");
        let before = g.inventory_portion();
        g.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![]).expect("comp"),
        )
        .expect("manifest");
        set_fail_save(true);
        let res = g.persist_inventory(before);
        set_fail_save(false);
        assert_eq!(code(res), OciErrorCode::Internal);
        assert_eq!(g.manifests().count(), 0);
        assert!(!r.join(IMAGE_INVENTORY_FILE_NAME).exists());
    }

    /// OCI-7: 変わっていなければ保存しない（失敗注入が効かない）。
    #[test]
    fn oci7_persist_skips_when_unchanged() {
        let r = root("unchanged");
        let s = open(&r);
        let mut g = s.lock().expect("lock");
        let before = g.inventory_portion();
        set_fail_save(true);
        let res = g.persist_inventory(before);
        set_fail_save(false);
        assert!(res.is_ok());
        assert!(!r.join(IMAGE_INVENTORY_FILE_NAME).exists());
    }
}
