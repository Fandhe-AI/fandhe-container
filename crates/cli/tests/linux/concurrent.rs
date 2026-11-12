//! 50 並行の実行基盤と、受け入れ条件 (i)〜(vi) の照合（#868・#869・TASK-184.4.1・TASK-184.4.2・OCI-7・CLI-1・REPAIR-5・REPAIR-12。MS-6）。
//!
//! # 役割と呼び出し元
//! `local_image_gc.rs` の `linux` モジュールの子（`#[path]`）。親の非公開ヘルパー（`run_cli`・`make_bundle`・`start_created`・
//! `stop_container`・`image_rm`・`system_df` 等）をそのまま使う。入口は 2 つ。
//! - [`scenario_real`]: `--ignored --scenario concurrent` の実機シナリオ（CLI の実バイナリ）。CI の専用ステップが実行する。
//! - [`offline_self_check`]: 既定のテスト集合（`--ignored` なし）で回る自己検証。コンテナを使わず、pull と prune の並行だけを
//!   小さい件数で通し、同じ照合関数を使う。実機前提の部分を手元で回せなくても、ハーネスの照合自体はここで検証できる。
//!
//! # 操作の種類（拡張点）
//! [`OpKind`] とワーカープール [`pool`] が拡張点で、(iv)〜(vi) は #869 が操作の種類（`CreatingRef`・`SharedPull`・`TagRace`）
//! を足した。種類ごとに専用のワーカーを立て、共有の原子カウンタから回の番号を取り、合計 [`ITERATIONS`] 回を処理する。
//! コンテナの `rm` は CreateStart の各回の `stop` → `delete` で 50 回数える。(iv)〜(vi) の 1 回分の本体は子モジュール
//! `races`（`concurrent/races.rs`）に分ける（改修の波及を小さく保つ。REPAIR-1）。
//!
//! # 照合の概要
//! - (i): 保護集合（参照中の manifest・config・レイヤー）を監視スレッドが [`POLL`] ごとに調べ、一度でも欠けたら失敗にする。
//!   prune の結果に保護 blob が出ないことも見る。最後に `blobs/sha256` の集合が期待と完全一致することを見る。
//! - (ii): 参照中のイメージ（タグ・running / stopped のコンテナが参照するもの）から 50 回 create → start できる。
//! - (iii): prune と並行する pull 50 回が成功し、公開されたイメージの全 blob が揃い（内容の sha256 を digest と照合）、
//!   そのタグから create → start できる。pull はリースを取ってから prune の完了を待つので、リースだけが守る blob の経路を通る。
//! - (iv): 作成途中のコンテナ（参照テーブルへの登録は済み〔未確定〕、状態作成と確定はまだ）の参照するイメージとレイヤーは、
//!   タグも他の参照も無くなった窓の中で prune が完了しても消えない（prune は `manifest_references` で未確定参照も数える）。
//!   CLI の実 create の内部の窓は外から止められないため、同じ手順（ゲート共有 → 登録 → 状態作成の代役 → 確定）を oci の
//!   公開 API でなぞる模擬である（実 CLI の create は (ii) が同じゲートと `@lock` を取り合いながら並走する）。
//!   create ゲートを排他で握る reconcile の役者は足さない（(ii) の CLI create が共有を待って Timeout しうるため）。
//! - (v): 同じ blob X を共有する 3 本の pull が全員リースを取った後、X を持つ種イメージを `image rm` し、先頭の pull が
//!   公開して自分のリースを解放しても、残りの 2 本は prune の完了を待った後に成功し、X は欠けない（pull ID ごとの個別リース）。
//!   prune が X を「リースだけが守った blob」として報告した回数を数え、1 回以上を必須にする（空振り防止）。
//! - (vi): 無参照で公開した T に `image tag` と prune を競わせる。結果は「tag 成功で manifest・blob が全部ある」か
//!   「NOT_FOUND でタグも manifest も blob も無い」のどちらかだけで、タグだけあって中身が無い状態は残らない。
//!   偶数の回は prune の完了を待ってから tag するので NOT_FOUND は決定的（件数を必須にする）。奇数の回は待たずに競わせる
//!   ため勝敗は観測値で、件数は情報行（`tag_won=`・`prune_won=`）に出すだけにして必須にしない（妥当性は #668 で判断）。
//!
//! # 方針
//! - Timeout は再試行しない（50/50 の基準を弱めない）。失敗は 1 回の失敗として数える。
//! - すべての待ちに期限を付ける（[`PHASE_DEADLINE`]・[`OVERLAP_WAIT`]・CLI の期限。REPAIR-5）。
//! - `pull` と `image prune` は CLI に未配線（#2384）のため、oci の公開 API をスレッドごとの `ImageStore::open` で呼ぶ。
//!   別インスタンスの間は `@lock` の OS ロックで排他され、プロセス間と同じ経路になる。
//! - `create` は `--unpack` を使わない。したがって (iii) の「create・start できる」は参照の登録と起動の成功までで、
//!   レイヤーの中身を使った証拠ではない。レイヤーが揃っていることは blob の内容の sha256 で直接照合する。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    BlobReuse, ContainerRefId, ContainerRefRegistration, ContainerRefRelease, ImageRmKind,
    PullPublishRequest, PullSession,
};

use super::*;

mod races;

/// 操作の種類ごとの回数（受け入れ条件の「50 回」）。
const ITERATIONS: usize = 50;
const _: () = assert!(ITERATIONS == 50);
/// 種類ごとに同時に走るワーカー数。情報行で必ず出す。
const PULL_IN_FLIGHT: usize = 6;
const START_IN_FLIGHT: usize = 6;
const RM_IN_FLIGHT: usize = 4;
const PRUNE_IN_FLIGHT: usize = 2;
/// 自己検証の件数とワーカー数。
const OFFLINE_ITERATIONS: usize = 8;
const OFFLINE_PULL_IN_FLIGHT: usize = 4;
/// (iv)〜(vi) のワーカー数。(v) は 1 回で 3 本の pull を走らせる。
const CREATING_IN_FLIGHT: usize = 4;
const SHARED_PULL_IN_FLIGHT: usize = 2;
const TAG_IN_FLIGHT: usize = 4;
const OFFLINE_CREATING_IN_FLIGHT: usize = 2;
const OFFLINE_SHARED_PULL_IN_FLIGHT: usize = 2;
const OFFLINE_TAG_IN_FLIGHT: usize = 2;
/// 並行フェーズ全体の期限。
const PHASE_DEADLINE: Duration = Duration::from_secs(300);
/// 「リースや参照を持つ間に prune が 1 回完了する」のを待つ上限。
const OVERLAP_WAIT: Duration = Duration::from_secs(30);
/// prune の反復の間隔（flock の再試行を飢えさせない）。
const PRUNE_PAUSE: Duration = Duration::from_millis(10);
const BLOB_LEN: usize = 4 * KIB;
const SHARED_LEN: usize = 16 * KIB;
const TAG_PREFIX: &str = "registry.example/fandhe/";

/// 操作の種類。(iv)〜(vi) は #869 が足した。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpKind {
    Pull,
    CreateStart,
    ImageRm,
    /// (iv) 作成途中の参照。
    CreatingRef,
    /// (v) 同じ blob を共有する 3 本の pull。
    SharedPull,
    /// (vi) `image tag` と prune の競合。
    TagRace,
}

/// 1 回の操作の成功の付加情報。
#[derive(Debug)]
enum Detail {
    Pull,
    CreateStart,
    ImageRm,
    CreatingRef,
    SharedPull,
    /// `won` は tag が成功した（prune に消されなかった）こと。
    TagRace {
        won: bool,
    },
}

struct OpRecord {
    kind: OpKind,
    index: usize,
    ms: u128,
    result: Result<Detail, String>,
}

/// prune 1 回の結果（検証済み）。
struct PruneRec {
    removed: Vec<String>,
}

/// 実行の規模。
struct Params {
    iterations: usize,
    pull_workers: usize,
    start_workers: usize,
    rm_workers: usize,
    prune_workers: usize,
    creating_workers: usize,
    shared_workers: usize,
    tag_workers: usize,
}

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 決定的な擬似乱数の内容（`write_blob` と同じ生成。名前が種）。
fn content(name: &str, len: usize) -> Vec<u8> {
    let mut x: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        x = (x ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    if x == 0 {
        x = 1;
    }
    let mut buf = Vec::with_capacity(len);
    while buf.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let take = (len - buf.len()).min(8);
        buf.extend_from_slice(x.to_le_bytes().get(..take).unwrap_or(&[]));
    }
    buf
}

/// 実 digest を持つ blob。
#[derive(Clone)]
struct Blob {
    digest: Digest,
    hex: String,
    data: Vec<u8>,
}

impl Blob {
    fn new(name: &str, len: usize) -> Self {
        let data = content(name, len);
        let digest = Digest::sha256_of(&data);
        let hex = digest
            .to_string()
            .strip_prefix("sha256:")
            .unwrap_or_default()
            .to_string();
        Self { digest, hex, data }
    }
}

/// config 1 つと layer の並びを持つイメージ。manifest の digest は名前から決める（ストアは manifest の内容を見ない）。
struct Image {
    manifest: Digest,
    config: Blob,
    layers: Vec<Blob>,
}

impl Image {
    fn new(name: &str, layers: Vec<Blob>) -> Self {
        Self {
            manifest: Digest::sha256_of(format!("manifest/{name}").as_bytes()),
            config: Blob::new(&format!("{name}/config"), BLOB_LEN),
            layers,
        }
    }

    fn blobs(&self) -> impl Iterator<Item = &Blob> {
        std::iter::once(&self.config).chain(self.layers.iter())
    }

    fn composition(&self) -> Result<ManifestComposition, String> {
        ManifestComposition::new(
            self.config.digest.clone(),
            self.layers.iter().map(|l| l.digest.clone()).collect(),
        )
        .map_err(|e| format!("composition: {e:?}"))
    }

    /// 重複を除いた blob の大きさの合計（`image ls` の SIZE）。
    fn size(&self) -> u64 {
        let mut seen = BTreeSet::new();
        self.blobs()
            .filter(|b| seen.insert(b.hex.clone()))
            .map(|b| b.data.len() as u64)
            .sum()
    }
}

fn tag_of(name: &str) -> String {
    format!("{TAG_PREFIX}{name}:v1")
}

/// フェーズ前の在庫の全体。
struct World {
    /// 自己検証にはコンテナが無いため、Rr・Rs にタグを付けて prune から守る。
    resident_tagged: bool,
    shared: Blob,
    /// タグ付き（保護）。
    p: Image,
    /// タグ付き。CreateStart が使う。
    r: Image,
    /// タグなし。常駐の running のコンテナが参照する。
    rr: Image,
    /// タグなし。常駐の stopped のコンテナが参照する。
    rs: Image,
    /// タグ付き・参照なし。ImageRm が消す。
    v: Vec<Image>,
    /// タグなし・参照なし。prune が回収する。固有 layer の 2 番目が「リースの的」。
    d: Vec<Image>,
    /// pull で公開するイメージ。layer は [S, d_i のリースの的, 固有]。
    pulls: Vec<Image>,
    /// (iv) 作成途中の参照が守るイメージ。タグ付きで種入れし、窓の中でタグを外す。固有 layer 1 枚（他と blob を共有しない）。
    creating: Vec<Image>,
    /// (v) グループ g の共有 blob X_g（固有の決定的な内容）。
    x: Vec<Blob>,
    /// (v) X_g だけを持つ種イメージ Y_g。タグ付きで種入れし、3 本がリースを取った後に `image rm` する。
    y: Vec<Image>,
    /// (v) グループ g の 3 本の pull の公開物。0 は先頭（タグなし）、1・2 は後続（タグ付き）。layer は [X_g, 固有]。
    sp: Vec<[Image; 3]>,
    /// (vi) 無参照で公開する T_k（固有 layer 1 枚）。
    t: Vec<Image>,
}

impl World {
    fn new(n: usize, with_rm: bool, resident_tagged: bool) -> Self {
        let shared = Blob::new("shared", SHARED_LEN);
        let with_s = |name: &str| {
            Image::new(
                name,
                vec![shared.clone(), Blob::new(&format!("{name}/own"), BLOB_LEN)],
            )
        };
        let p = with_s("p");
        let r = with_s("r");
        let rr = Image::new("rr", vec![Blob::new("rr/own", BLOB_LEN)]);
        let rs = Image::new("rs", vec![Blob::new("rs/own", BLOB_LEN)]);
        let v = if with_rm {
            (0..n).map(|j| with_s(&format!("v{j}"))).collect()
        } else {
            Vec::new()
        };
        let d: Vec<Image> = (0..n)
            .map(|i| {
                Image::new(
                    &format!("d{i}"),
                    vec![
                        Blob::new(&format!("d{i}/own"), BLOB_LEN),
                        Blob::new(&format!("d{i}/lease"), BLOB_LEN),
                    ],
                )
            })
            .collect();
        let pulls = d
            .iter()
            .enumerate()
            .map(|(i, di)| {
                Image::new(
                    &format!("pull{i}"),
                    vec![
                        shared.clone(),
                        di.layers[1].clone(),
                        Blob::new(&format!("pull{i}/own"), BLOB_LEN),
                    ],
                )
            })
            .collect();
        let own_one = |prefix: &str, k: usize| {
            Image::new(
                &format!("{prefix}{k}"),
                vec![Blob::new(&format!("{prefix}{k}/own"), BLOB_LEN)],
            )
        };
        let creating = (0..n).map(|k| own_one("w", k)).collect();
        let t = (0..n).map(|k| own_one("t", k)).collect();
        let x: Vec<Blob> = (0..n)
            .map(|g| Blob::new(&format!("x{g}"), BLOB_LEN))
            .collect();
        let y = x
            .iter()
            .enumerate()
            .map(|(g, xg)| Image::new(&format!("y{g}"), vec![xg.clone()]))
            .collect();
        let sp = x
            .iter()
            .enumerate()
            .map(|(g, xg)| {
                let member = |role: &str| {
                    let name = format!("sp{g}{role}");
                    Image::new(
                        &name,
                        vec![xg.clone(), Blob::new(&format!("{name}/own"), BLOB_LEN)],
                    )
                };
                [member("l"), member("f1"), member("f2")]
            })
            .collect();
        Self {
            resident_tagged,
            shared,
            p,
            r,
            rr,
            rs,
            v,
            d,
            pulls,
            creating,
            x,
            y,
            sp,
            t,
        }
    }

    fn creating_tag(k: usize) -> String {
        tag_of(&format!("gc-c-w{k}"))
    }

    fn y_tag(g: usize) -> String {
        tag_of(&format!("gc-c-y{g}"))
    }

    fn follower_tag(g: usize, role: usize) -> String {
        tag_of(&format!("gc-c-sp{g}-{role}"))
    }

    fn t_tag(k: usize) -> String {
        tag_of(&format!("gc-c-t{k}"))
    }

    fn pull_tag(i: usize) -> String {
        tag_of(&format!("gc-c-pull{i}"))
    }

    /// フェーズの終わりに `blobs/sha256` にあるべき blob（名前 → 大きさ）。V と D の blob は含まない。
    /// (v) の後続 pull（タグ付きで残る）と、tag が勝った T は含む。W・先頭の pull・Y の config・負けた T は含まない。
    fn expected_blobs(&self, won: &BTreeSet<usize>) -> BTreeMap<String, usize> {
        self.survivors(won)
            .into_iter()
            .flat_map(Image::blobs)
            .map(|b| (b.hex.clone(), b.data.len()))
            .collect()
    }

    /// フェーズの終わりに在庫に残るイメージ（`image ls` の行になるもの。常駐の Rr・Rs を含む）。
    fn survivors(&self, won: &BTreeSet<usize>) -> Vec<&Image> {
        [&self.p, &self.r, &self.rr, &self.rs]
            .into_iter()
            .chain(self.pulls.iter())
            .chain(self.sp.iter().flat_map(|g| &g[1..]))
            .chain(won.iter().filter_map(|k| self.t.get(*k)))
            .collect()
    }

    /// `image ls` の期待行（整列済み）。`T|digest|size` はタグ付き、`U|...` はタグなし。
    fn expected_rows(&self, won: &BTreeSet<usize>) -> Vec<String> {
        let mut rows: Vec<String> = [&self.p, &self.r]
            .into_iter()
            .chain(self.pulls.iter())
            .chain(self.sp.iter().flat_map(|g| &g[1..]))
            .chain(won.iter().filter_map(|k| self.t.get(*k)))
            .map(|im| format!("T|{}|{}", im.manifest, im.size()))
            .chain([&self.rr, &self.rs].into_iter().map(|im| {
                format!(
                    "{}|{}|{}",
                    if self.resident_tagged { "T" } else { "U" },
                    im.manifest,
                    im.size()
                )
            }))
            .collect();
        rows.sort();
        rows
    }
}

/// prune の結果を照合する集合。
struct Sets {
    /// prune が消してよい manifest（D・W・(v) の先頭の pull・T）。W は窓の後、T は tag が負けたときだけ実際に消える。
    d_manifests: BTreeSet<String>,
    d_blobs: BTreeSet<String>,
    /// prune が「リースだけが守った」と報告してよい blob（D のリースの的と (v) の X_g）。
    lease_targets: BTreeSet<String>,
    /// (v) の X_g（`kept_leased_blobs` に出た回数を数える対象）。
    x_blobs: BTreeSet<String>,
    /// 常に消える（W と (v) の先頭の pull の manifest）。D もここに含める。
    always_removed: BTreeSet<String>,
    /// T_k の manifest（添字が k）。tag が負けた k のものだけ消える。
    t_manifests: Vec<String>,
}

impl Sets {
    fn of(w: &World) -> Self {
        // 先頭の pull の固有 blob だけを数える（X_g は後続の pull とリースが守るため消えてはならない）。
        let leaders: Vec<&Image> = w.sp.iter().map(|g| &g[0]).collect();
        let removable: Vec<&Image> =
            w.d.iter()
                .chain(w.creating.iter())
                .chain(w.t.iter())
                .chain(leaders.iter().copied())
                .collect();
        let x_blobs: BTreeSet<String> = w.x.iter().map(|b| b.digest.to_string()).collect();
        let x_hex: BTreeSet<&String> = w.x.iter().map(|b| &b.hex).collect();
        Self {
            d_manifests: removable.iter().map(|i| i.manifest.to_string()).collect(),
            d_blobs: removable
                .iter()
                .flat_map(|i| i.blobs())
                .filter(|b| !x_hex.contains(&b.hex))
                .map(|b| b.digest.to_string())
                .collect(),
            lease_targets: w
                .d
                .iter()
                .map(|i| i.layers[1].digest.to_string())
                .chain(x_blobs.iter().cloned())
                .collect(),
            x_blobs,
            always_removed: w
                .d
                .iter()
                .chain(w.creating.iter())
                .chain(leaders.iter().copied())
                .map(|i| i.manifest.to_string())
                .collect(),
            t_manifests: w.t.iter().map(|i| i.manifest.to_string()).collect(),
        }
    }
}

/// スレッド間で共有する状態。
struct Shared {
    images: PathBuf,
    iterations: usize,
    gate_leases: usize,
    /// prune ワーカー数。「窓の後に始まった prune が 1 回以上完了した」ことの判定に使う（[`Shared::wait_prune_after`]）。
    prune_workers: usize,
    /// (iv) の未確定参照の ID。
    create_ids: Vec<String>,
    pull_ids: Vec<String>,
    start_ids: Vec<String>,
    start: AtomicBool,
    abort: AtomicBool,
    others_done: AtomicBool,
    monitor_stop: AtomicBool,
    prunes_completed: AtomicUsize,
    leases_taken: AtomicUsize,
    leased_hits: AtomicUsize,
    absent_hits: AtomicUsize,
    monitor_polls: AtomicUsize,
    monitor_lock_errors: AtomicUsize,
    /// prune が X_g を「リースだけが守った blob」として報告した延べ回数（(v) の空振り防止）。
    shared_lease_kept: AtomicUsize,
    protected_blobs: Mutex<BTreeMap<String, u64>>,
    protected_manifests: Mutex<BTreeSet<String>>,
    violation: Mutex<Option<String>>,
}

impl Shared {
    fn violate(&self, what: String) {
        let mut v = lk(&self.violation);
        if v.is_none() {
            *v = Some(what);
        }
    }

    /// 現在の prune 完了数 `seen` より多くなるまで待つ（期限つき）。
    fn wait_prune_progress(&self, seen: usize, what: &str) -> Result<(), String> {
        let deadline = Instant::now() + OVERLAP_WAIT;
        loop {
            if self.abort.load(Ordering::SeqCst) {
                return Err(format!("{what}: aborted"));
            }
            if self.prunes_completed.load(Ordering::SeqCst) > seen {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{what}: no image prune completed within {OVERLAP_WAIT:?}"
                ));
            }
            thread::sleep(POLL);
        }
    }

    /// `seen`（呼び出し時点の完了数）より後に **始まった** prune が 1 回以上完了するのを待つ。
    ///
    /// `seen` の時点で走っている prune は高々 `prune_workers` 本で、その完了は `seen` を超える数に含まれうる。
    /// 完了数が `seen + prune_workers` を超えれば、少なくとも 1 本は `seen` の後に始まったと言える。
    fn wait_prune_after(&self, seen: usize, what: &str) -> Result<(), String> {
        self.wait_prune_progress(seen.saturating_add(self.prune_workers), what)
    }

    fn protect_blob(&self, b: &Blob) {
        lk(&self.protected_blobs).insert(b.hex.clone(), b.data.len() as u64);
    }

    /// 保護集合から外す（W のように、後で prune に消されてよくなるイメージ）。
    ///
    /// 監視スレッドは保護集合の複製を取って 1 周する。外した直後に参照を解いて prune が消すと、古い複製で調べ終える前の
    /// 周回が正しい削除を違反と誤検出しうる。そのため、外した後に監視が **1 周まるごと** 回り終わるのを待ってから返す。
    /// 外す blob は他のイメージと共有しない（名前から決まる固有の内容）。
    fn unprotect_image(&self, im: &Image) -> Result<(), String> {
        {
            let mut blobs = lk(&self.protected_blobs);
            for b in im.blobs() {
                blobs.remove(&b.hex);
            }
        }
        lk(&self.protected_manifests).remove(&im.manifest.to_string());
        let start = self.monitor_polls.load(Ordering::SeqCst);
        let deadline = Instant::now() + OVERLAP_WAIT;
        while self.monitor_polls.load(Ordering::SeqCst) < start.saturating_add(2) {
            if Instant::now() >= deadline {
                return Err("monitor did not complete a full pass after unprotecting".to_string());
            }
            thread::sleep(POLL);
        }
        Ok(())
    }

    fn protect_image(&self, im: &Image) {
        let mut blobs = lk(&self.protected_blobs);
        for b in im.blobs() {
            blobs.insert(b.hex.clone(), b.data.len() as u64);
        }
        lk(&self.protected_manifests).insert(im.manifest.to_string());
    }
}

fn blob_path(images: &Path, hex: &str) -> PathBuf {
    images.join("blobs").join("sha256").join(hex)
}

/// blob をステージングへ書いて検証する（pull の本番の経路）。
fn stage(s: &mut PullSession<'_>, b: &Blob) -> Result<(), String> {
    let mut w = s
        .open_staged_blob(&b.digest)
        .map_err(|e| format!("open_staged_blob: {e:?}"))?;
    w.write_all(&b.data)
        .map_err(|e| format!("stage write: {e}"))?;
    w.commit().map_err(|e| format!("stage commit: {e:?}"))?;
    s.verify_staged_blob(&b.digest, b.data.len() as u64)
        .map_err(|e| format!("verify_staged_blob: {e:?}"))?;
    Ok(())
}

/// 在庫へ公開する（フェーズ前の種入れ。pull の公開 API を通すので digest は実物）。
fn seed(images: &Path, im: &Image, tag: Option<&str>) -> Result<(), String> {
    let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
    let mut s = store
        .begin_pull_generated()
        .map_err(|e| format!("begin pull: {e:?}"))?;
    let mut seen = BTreeSet::new();
    for b in im.blobs() {
        if seen.insert(b.hex.clone()) {
            stage(&mut s, b)?;
        }
    }
    let mut req = PullPublishRequest::new(im.manifest.clone(), im.composition()?);
    if let Some(t) = tag {
        req = req.with_tag(tag_key(t)?);
    }
    s.publish(req).map_err(|e| format!("seed publish: {e:?}"))?;
    Ok(())
}

/// pull 1 回。リースを取り、prune の完了を待ってから公開し、全 blob の内容を照合する。
fn pull_once(
    sh: &Shared,
    w: &World,
    env: Option<&Env>,
    slot: usize,
    i: usize,
) -> Result<(), String> {
    let img = &w.pulls[i];
    let what = format!("pull {i}");
    let store = ImageStore::open(&sh.images).map_err(|e| format!("{what}: open store: {e:?}"))?;
    let mut s = store
        .begin_pull_generated()
        .map_err(|e| format!("{what}: begin pull: {e:?}"))?;
    match s
        .lease_existing_blob(&w.shared.digest)
        .map_err(|e| format!("{what}: lease shared layer: {e:?}"))?
    {
        BlobReuse::Leased(_) => {}
        other => return Err(format!("{what}: shared layer was not leasable: {other:?}")),
    }
    let target = &img.layers[1];
    let leased = match s
        .lease_existing_blob(&target.digest)
        .map_err(|e| format!("{what}: lease target layer: {e:?}"))?
    {
        BlobReuse::Leased(_) => {
            let mut f = s
                .open_leased_blob(&target.digest)
                .map_err(|e| format!("{what}: open leased blob: {e:?}"))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| format!("{what}: read leased blob: {e}"))?;
            if Digest::sha256_of(&buf) != target.digest {
                return Err(format!(
                    "{what}: leased blob content does not match its digest"
                ));
            }
            sh.leased_hits.fetch_add(1, Ordering::SeqCst);
            true
        }
        BlobReuse::Absent => {
            stage(&mut s, target)?;
            sh.absent_hits.fetch_add(1, Ordering::SeqCst);
            false
        }
        other => return Err(format!("{what}: target layer: {other:?}")),
    };
    sh.leases_taken.fetch_add(1, Ordering::SeqCst);
    stage(&mut s, &img.config)?;
    stage(&mut s, &img.layers[2])?;
    // リースを持つ間に prune が 1 回以上完了することを毎回保証する。
    let seen = sh.prunes_completed.load(Ordering::SeqCst);
    sh.wait_prune_progress(seen, &what)?;
    let tag = World::pull_tag(i);
    let request =
        PullPublishRequest::new(img.manifest.clone(), img.composition()?).with_tag(tag_key(&tag)?);
    let out = s
        .publish(request)
        .map_err(|e| format!("{what}: publish: {e:?}"))?;
    if leased && !out.reused_blobs.contains(&target.digest) {
        return Err(format!(
            "{what}: leased blob was not reported as reused: {out:?}"
        ));
    }
    sh.protect_image(img);
    for b in img.blobs() {
        let bytes = fs::read(blob_path(&sh.images, &b.hex))
            .map_err(|e| format!("{what}: published blob {} is missing: {e}", b.hex))?;
        if Digest::sha256_of(&bytes) != b.digest {
            return Err(format!(
                "{what}: published blob {} has a wrong digest",
                b.hex
            ));
        }
    }
    drop(store);
    if let Some(env) = env {
        container_cycle(sh, env, "pull", slot, &sh.pull_ids[i], &tag)?;
    }
    Ok(())
}

/// bundle が無ければ作る（delete が bundle を片づける場合に備え、毎回存在を確かめる）。
fn ensure_bundle(bundle: &Path) -> Result<(), String> {
    if bundle.join("config.json").is_file() && bundle.join("rootfs").join("probe").is_file() {
        return Ok(());
    }
    make_bundle(bundle)
}

/// create（`--image`）。後始末の対象は呼び出し側が先に `Cleanup.live` へ登録している。
fn create_cli(env: &Env, id_s: &str, bundle: &Path, image: &str) -> Result<(), String> {
    let bundle_s = bundle.to_str().ok_or("bundle path is not UTF-8")?;
    let out = run_cli(
        &env.cli,
        &[
            "--root",
            &env.root_s,
            "create",
            "--image-root",
            &env.images_s,
            "--image",
            image,
            "--bundle",
            bundle_s,
            id_s,
        ],
        CLI_TIMEOUT,
    )?;
    expect_ok(&out, &format!("create {id_s}"))
}

/// 停止済みのコンテナを delete し、2 回目が `NOT_FOUND`（3）であることを確かめる。
fn delete_cli(env: &Env, id_s: &str) -> Result<(), String> {
    let args = [
        "--root",
        env.root_s.as_str(),
        "delete",
        "--image-root",
        env.images_s.as_str(),
        id_s,
    ];
    let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
    expect_ok(&out, &format!("delete {id_s}"))?;
    let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
    if out.code != Some(3) || !out.stdout.is_empty() {
        return Err(format!(
            "second delete {id_s}: want exit 3, got {:?} stdout={:?} stderr={:?}",
            out.code, out.stdout, out.stderr
        ));
    }
    let code = stderr_field(&out.stderr, "code")?;
    expect(
        code == "NOT_FOUND",
        &format!("second delete {id_s}: want NOT_FOUND, got {code}"),
    )
}

/// create → start → stop → delete。bundle はワーカーのスロットごとに使い回す。
/// `kind` が `start` のときは、create の後に prune が 1 回以上完了するのを待つ（Created のコンテナの参照が守られることの観測）。
fn container_cycle(
    sh: &Shared,
    env: &Env,
    kind: &str,
    slot: usize,
    id_s: &str,
    image: &str,
) -> Result<(), String> {
    let bundle = env.work.join(format!("cbundle-{kind}-{slot}"));
    ensure_bundle(&bundle)?;
    create_cli(env, id_s, &bundle, image)?;
    if kind == "start" {
        let seen = sh.prunes_completed.load(Ordering::SeqCst);
        sh.wait_prune_progress(seen, &format!("create {id_s}"))?;
    }
    let run = start_created(env, id_s)?;
    stop_container(env, &run)?;
    delete_cli(env, id_s)
}

/// CreateStart の 1 回。参照中のイメージ（R のタグ・Rr と Rs の digest）を順に使う。
fn start_once(sh: &Shared, w: &World, env: &Env, slot: usize, k: usize) -> Result<(), String> {
    let image = match k % 3 {
        0 => tag_of("gc-c-r"),
        1 => w.rr.manifest.to_string(),
        _ => w.rs.manifest.to_string(),
    };
    container_cycle(sh, env, "start", slot, &sh.start_ids[k], &image)
}

/// `image rm`（`--force` なし）で V_j を消し、出力が固有 blob にちょうど一致し、共有レイヤーが残ることを見る。
fn rm_once(w: &World, env: &Env, j: usize) -> Result<(), String> {
    let v = &w.v[j];
    let tag = tag_of(&format!("gc-c-v{j}"));
    let stdout = image_rm(env, false, &tag)?;
    let mut lines = stdout.lines();
    let got_head: Vec<&str> = lines.by_ref().take(2).collect();
    let want_head = [
        format!("untagged\t{tag}"),
        format!("deleted\t{}", v.manifest),
    ];
    expect(
        got_head == want_head,
        &format!("image rm {tag} head lines: {got_head:?}"),
    )?;
    let mut got: Vec<String> = lines.map(str::to_string).collect();
    got.sort();
    let mut want: Vec<String> = v
        .blobs()
        .filter(|b| b.hex != w.shared.hex)
        .map(|b| format!("deleted-blob\t{}", b.digest))
        .collect();
    want.sort();
    expect(
        got == want,
        &format!("image rm {tag} blob lines: want {want:?}, got {got:?}"),
    )
}

/// prune 1 回を実行して結果を照合する。
fn prune_once(sh: &Shared, sets: &Sets) -> Result<PruneRec, String> {
    let store = ImageStore::open(&sh.images).map_err(|e| format!("prune: open store: {e:?}"))?;
    let mut guard = store.lock().map_err(|e| format!("prune: lock: {e:?}"))?;
    let out = guard
        .execute_image_prune(store.root())
        .map_err(|e| format!("prune: {e:?}"))?;
    drop(guard);
    let removed: Vec<String> = out
        .removed_manifests
        .iter()
        .map(ToString::to_string)
        .collect();
    let deleted: Vec<String> = out.deleted_blobs.iter().map(ToString::to_string).collect();
    let kept: Vec<String> = out
        .kept_leased_blobs
        .iter()
        .map(ToString::to_string)
        .collect();
    if let Some(m) = removed.iter().find(|m| !sets.d_manifests.contains(*m)) {
        return Err(format!(
            "prune removed a manifest outside the unreferenced set: {m}"
        ));
    }
    if let Some(b) = deleted.iter().find(|b| !sets.d_blobs.contains(*b)) {
        return Err(format!(
            "prune deleted a blob outside the unreferenced set: {b}"
        ));
    }
    if let Some(b) = kept.iter().find(|b| !sets.lease_targets.contains(*b)) {
        return Err(format!(
            "prune kept a leased blob that is not a lease target: {b}"
        ));
    }
    if !out.undeleted_blobs.is_empty() {
        return Err(format!(
            "prune left undeleted blobs: {:?}",
            out.undeleted_blobs
        ));
    }
    let x_kept = kept.iter().filter(|b| sets.x_blobs.contains(*b)).count();
    sh.shared_lease_kept.fetch_add(x_kept, Ordering::SeqCst);
    Ok(PruneRec { removed })
}

/// prune のワーカー。他の種類がすべて終わり、かつ合計が `iterations` 回に達するまで繰り返す。
fn prune_worker(sh: &Shared, sets: &Sets) -> Result<Vec<PruneRec>, String> {
    while !sh.start.load(Ordering::SeqCst) {
        if sh.abort.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        thread::sleep(Duration::from_millis(2));
    }
    let mut recs = Vec::new();
    loop {
        if sh.abort.load(Ordering::SeqCst) {
            break;
        }
        if sh.prunes_completed.load(Ordering::SeqCst) == 0 {
            // 最初の波の pull がリースを取るまで待つ（リースだけが守る blob の経路を確実に通す）。
            let deadline = Instant::now() + OVERLAP_WAIT;
            while sh.leases_taken.load(Ordering::SeqCst) < sh.gate_leases
                && Instant::now() < deadline
                && !sh.abort.load(Ordering::SeqCst)
            {
                thread::sleep(POLL);
            }
        }
        match prune_once(sh, sets) {
            Ok(rec) => recs.push(rec),
            Err(e) => {
                sh.abort.store(true, Ordering::SeqCst);
                return Err(e);
            }
        }
        sh.prunes_completed.fetch_add(1, Ordering::SeqCst);
        if sh.others_done.load(Ordering::SeqCst)
            && sh.prunes_completed.load(Ordering::SeqCst) >= sh.iterations
        {
            break;
        }
        thread::sleep(PRUNE_PAUSE);
    }
    Ok(recs)
}

/// 保護集合を [`POLL`] ごとに調べ、一度でも欠けたら記録する（受け入れ条件 (i) の「一度も」）。
fn monitor(sh: &Shared) {
    let mut tick = 0usize;
    while !sh.monitor_stop.load(Ordering::SeqCst) {
        let snapshot: Vec<(String, u64)> = lk(&sh.protected_blobs)
            .iter()
            .map(|(h, l)| (h.clone(), *l))
            .collect();
        for (hex, len) in snapshot {
            match fs::symlink_metadata(blob_path(&sh.images, &hex)) {
                Ok(m) if m.is_file() && m.len() == len => {}
                other => sh.violate(format!(
                    "protected blob {hex} was lost or changed (want {len} bytes): {:?}",
                    other.map(|m| m.len())
                )),
            }
        }
        tick += 1;
        if tick.is_multiple_of(12) {
            let want: Vec<String> = lk(&sh.protected_manifests).iter().cloned().collect();
            let got = ImageStore::open(&sh.images).ok().and_then(|store| {
                let g = store.lock().ok()?;
                Some(
                    g.manifests()
                        .map(|(d, _)| d.to_string())
                        .collect::<BTreeSet<_>>(),
                )
            });
            match got {
                Some(have) => {
                    if let Some(m) = want.iter().find(|m| !have.contains(*m)) {
                        sh.violate(format!(
                            "protected manifest {m} was removed from the inventory"
                        ));
                    }
                }
                None => {
                    sh.monitor_lock_errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        sh.monitor_polls.fetch_add(1, Ordering::SeqCst);
        thread::sleep(POLL);
    }
}

/// 種類ごとのワーカープール。共有カウンタから回の番号を取り、結果を `tx` へ送る。
// 抑止の理由: 3 種のワーカーが共有する値（scope・共有状態・カウンタ・種類・人数・総数・送信口・操作）を
// 呼び出し側ごとに束ねる構造体を作ると、各呼び出しの組み立てが増えるだけで読みやすくならない試験専用の補助のため。
#[allow(clippy::too_many_arguments)]
fn pool<'scope, 'env, F>(
    scope: &'scope thread::Scope<'scope, 'env>,
    sh: &'scope Shared,
    counter: &'scope AtomicUsize,
    kind: OpKind,
    workers: usize,
    total: usize,
    tx: &mpsc::Sender<OpRecord>,
    op: &'scope F,
) where
    F: Fn(usize, usize) -> Result<Detail, String> + Sync + 'scope,
{
    for slot in 0..workers {
        let tx = tx.clone();
        scope.spawn(move || {
            while !sh.start.load(Ordering::SeqCst) {
                if sh.abort.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(2));
            }
            loop {
                if sh.abort.load(Ordering::SeqCst) {
                    break;
                }
                let index = counter.fetch_add(1, Ordering::SeqCst);
                if index >= total {
                    break;
                }
                let t0 = Instant::now();
                let result = op(slot, index);
                let rec = OpRecord {
                    kind,
                    index,
                    ms: t0.elapsed().as_millis(),
                    result,
                };
                if tx.send(rec).is_err() {
                    break;
                }
            }
        });
    }
}

struct Outcome {
    records: Vec<OpRecord>,
    prunes: Vec<PruneRec>,
}

/// 並行フェーズ。期限つきで結果を集め、失敗したら abort を立てて全ワーカーを止める。
fn run_phase(
    sh: &Shared,
    w: &World,
    env: Option<&Env>,
    p: &Params,
    sets: &Sets,
) -> Result<Outcome, String> {
    let (tx, rx) = mpsc::channel::<OpRecord>();
    let pull_counter = AtomicUsize::new(0);
    let start_counter = AtomicUsize::new(0);
    let rm_counter = AtomicUsize::new(0);
    let creating_counter = AtomicUsize::new(0);
    let shared_counter = AtomicUsize::new(0);
    let tag_counter = AtomicUsize::new(0);
    let creating_op =
        |_slot: usize, k: usize| races::creating_ref_once(sh, w, k).map(|()| Detail::CreatingRef);
    let shared_op =
        |_slot: usize, g: usize| races::shared_pull_once(sh, w, g).map(|()| Detail::SharedPull);
    let tag_op = |_slot: usize, k: usize| {
        races::tag_race_once(sh, w, env, k).map(|won| Detail::TagRace { won })
    };
    let pull_op = |slot: usize, i: usize| pull_once(sh, w, env, slot, i).map(|()| Detail::Pull);
    let start_op = |slot: usize, k: usize| match env {
        Some(e) => start_once(sh, w, e, slot, k).map(|()| Detail::CreateStart),
        None => Err("no environment".to_string()),
    };
    let rm_op = |_slot: usize, j: usize| match env {
        Some(e) => rm_once(w, e, j).map(|()| Detail::ImageRm),
        None => Err("no environment".to_string()),
    };
    // pull に加えて (iv)〜(vi) の 3 種が、実機・自己検証のどちらでも各 `iterations` 回走る。
    let mut expected = 4 * p.iterations;
    thread::scope(|scope| {
        let mon = scope.spawn(|| monitor(sh));
        pool(
            scope,
            sh,
            &pull_counter,
            OpKind::Pull,
            p.pull_workers,
            p.iterations,
            &tx,
            &pull_op,
        );
        pool(
            scope,
            sh,
            &creating_counter,
            OpKind::CreatingRef,
            p.creating_workers,
            p.iterations,
            &tx,
            &creating_op,
        );
        pool(
            scope,
            sh,
            &shared_counter,
            OpKind::SharedPull,
            p.shared_workers,
            p.iterations,
            &tx,
            &shared_op,
        );
        pool(
            scope,
            sh,
            &tag_counter,
            OpKind::TagRace,
            p.tag_workers,
            p.iterations,
            &tx,
            &tag_op,
        );
        if env.is_some() {
            pool(
                scope,
                sh,
                &start_counter,
                OpKind::CreateStart,
                p.start_workers,
                p.iterations,
                &tx,
                &start_op,
            );
            pool(
                scope,
                sh,
                &rm_counter,
                OpKind::ImageRm,
                p.rm_workers,
                p.iterations,
                &tx,
                &rm_op,
            );
            expected += 2 * p.iterations;
        }
        let prunes: Vec<_> = (0..p.prune_workers)
            .map(|_| scope.spawn(|| prune_worker(sh, sets)))
            .collect();
        drop(tx);
        sh.start.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + PHASE_DEADLINE;
        let mut records = Vec::new();
        let mut failure: Option<String> = None;
        while records.len() < expected {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(r) => {
                    if let Err(e) = &r.result {
                        failure = Some(format!("{:?} #{}: {e}", r.kind, r.index));
                        break;
                    }
                    records.push(r);
                }
                Err(_) => {
                    failure = Some(format!(
                        "phase did not finish within {PHASE_DEADLINE:?} ({} of {expected} operations done)",
                        records.len()
                    ));
                    break;
                }
            }
        }
        if failure.is_some() {
            sh.abort.store(true, Ordering::SeqCst);
        }
        sh.others_done.store(true, Ordering::SeqCst);
        let mut recs = Vec::new();
        let mut prune_err = None;
        for h in prunes {
            match h.join() {
                Ok(Ok(v)) => recs.extend(v),
                Ok(Err(e)) => prune_err = Some(e),
                Err(_) => prune_err = Some("prune worker panicked".to_string()),
            }
        }
        sh.monitor_stop.store(true, Ordering::SeqCst);
        let _ = mon.join();
        let violation = lk(&sh.violation).clone();
        if let Some(v) = violation {
            return Err(format!("(i) violated: {v}"));
        }
        if let Some(e) = prune_err {
            return Err(format!("prune worker failed: {e}"));
        }
        if let Some(f) = failure {
            return Err(f);
        }
        Ok(Outcome {
            records,
            prunes: recs,
        })
    })
}

/// 件数と最大・中央の所要 ms。
fn stats(records: &[OpRecord], kind: OpKind) -> (usize, u128, u128) {
    let mut ms: Vec<u128> = records
        .iter()
        .filter(|r| r.kind == kind)
        .map(|r| r.ms)
        .collect();
    ms.sort_unstable();
    let max = ms.last().copied().unwrap_or(0);
    let med = ms.get(ms.len() / 2).copied().unwrap_or(0);
    (ms.len(), max, med)
}

/// `blobs/sha256` の集合と内容が期待に完全一致することを見る。
fn verify_blob_set(images: &Path, want: &BTreeMap<String, usize>) -> Result<(), String> {
    let dir = images.join("blobs").join("sha256");
    let rd = fs::read_dir(&dir).map_err(|e| format!("read blobs dir: {e}"))?;
    let mut got = BTreeSet::new();
    for ent in rd {
        let ent = ent.map_err(|e| format!("read blobs entry: {e}"))?;
        let name = ent.file_name().to_string_lossy().into_owned();
        let md = fs::symlink_metadata(ent.path()).map_err(|e| format!("stat blob {name}: {e}"))?;
        if !md.is_file() {
            return Err(format!("blob entry {name} is not a regular file"));
        }
        let bytes = fs::read(ent.path()).map_err(|e| format!("read blob {name}: {e}"))?;
        if Digest::sha256_of(&bytes).to_string() != format!("sha256:{name}") {
            return Err(format!("blob {name}: content does not match its digest"));
        }
        if want.get(&name).copied() != Some(bytes.len()) {
            return Err(format!(
                "blob {name} ({} bytes) is not an expected survivor",
                bytes.len()
            ));
        }
        got.insert(name);
    }
    let missing: Vec<&String> = want.keys().filter(|k| !got.contains(*k)).take(5).collect();
    expect(
        missing.is_empty() && got.len() == want.len(),
        &format!(
            "blob set differs: expected {}, found {}, missing e.g. {missing:?}",
            want.len(),
            got.len()
        ),
    )
}

fn rows_diff(want: &[String], got: &[String]) -> String {
    let w: BTreeSet<&String> = want.iter().collect();
    let g: BTreeSet<&String> = got.iter().collect();
    let missing: Vec<&&String> = w.difference(&g).take(3).collect();
    let extra: Vec<&&String> = g.difference(&w).take(3).collect();
    format!(
        "want {} rows, got {}; missing e.g. {missing:?}; extra e.g. {extra:?}",
        want.len(),
        got.len()
    )
}

/// 在庫の行を CLI（実機）か `list_images`（自己検証）から `T|digest|size` / `U|...` の形で得る。MISSING があれば失敗。
fn listed_rows(images: &Path, env: Option<&Env>) -> Result<Vec<String>, String> {
    let mut rows = Vec::new();
    if let Some(env) = env {
        for line in image_ls(env)?.lines().skip(1) {
            let c: Vec<&str> = line.split('\t').collect();
            let [repo, _tag, digest, size, missing] = c[..] else {
                return Err(format!("image ls row: {line:?}"));
            };
            expect(
                missing == "0",
                &format!("image ls row has missing blobs: {line:?}"),
            )?;
            rows.push(format!(
                "{}|{digest}|{size}",
                if repo == "-" { "U" } else { "T" }
            ));
        }
    } else {
        let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
        let guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        let list = guard
            .list_images(store.root())
            .map_err(|e| format!("list_images: {e:?}"))?;
        for e in &list.entries {
            expect(
                e.missing_blobs.is_empty(),
                &format!("listed image {} has missing blobs", e.digest),
            )?;
            rows.push(format!(
                "{}|{}|{}",
                if e.tag.is_some() { "T" } else { "U" },
                e.digest,
                e.size_bytes
            ));
        }
    }
    rows.sort();
    Ok(rows)
}

/// manifest を参照するコンテナ（ID の文字列）とタグ（Display）。
fn refs_of(images: &Path, d: &Digest) -> Result<(Vec<String>, Vec<String>), String> {
    let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
    let refs = store
        .lock()
        .map_err(|e| format!("lock: {e:?}"))?
        .manifest_references(d);
    Ok((
        refs.containers
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        refs.tags.iter().map(ToString::to_string).collect(),
    ))
}

/// (vi) の中核と (iv)・(v) の後始末の照合。タグだけあって中身（manifest）が無いイメージが無く、未確定参照が残らず、
/// 種イメージ Y が消えている。
fn verify_inventory(sh: &Shared, w: &World) -> Result<(), String> {
    let store = ImageStore::open(&sh.images).map_err(|e| format!("open store: {e:?}"))?;
    let g = store.lock().map_err(|e| format!("lock: {e:?}"))?;
    let manifests: BTreeSet<Digest> = g.manifests().map(|(d, _)| d.clone()).collect();
    if let Some((tag, d)) = g.tags().find(|(_, d)| !manifests.contains(*d)) {
        return Err(format!(
            "tag {tag} points to {d}, which is not in the inventory"
        ));
    }
    if let Some((id, generation, d)) = g.unbound_containers().next() {
        return Err(format!(
            "unbound container reference left behind: {id} (generation {generation:?}) -> {d}"
        ));
    }
    for im in w.creating.iter().chain(w.y.iter()) {
        let refs = g.manifest_references(&im.manifest);
        if refs.count() != 0 {
            return Err(format!(
                "{} still has references: containers={:?} tags={:?}",
                im.manifest, refs.containers, refs.tags
            ));
        }
    }
    if let Some(y) = w.y.iter().find(|y| manifests.contains(&y.manifest)) {
        return Err(format!("seed image {} was not removed", y.manifest));
    }
    Ok(())
}

/// フェーズ後の最終照合。
fn verify_final(
    sh: &Shared,
    w: &World,
    env: Option<&Env>,
    sets: &Sets,
    out: &mut Outcome,
    resident: Option<(&str, &str)>,
    won: &BTreeSet<usize>,
) -> Result<(), String> {
    // 取り残しの回収のため、prune をもう 1 回実行する。
    out.prunes.push(prune_once(sh, sets)?);
    let mut removed = BTreeSet::new();
    let mut count = 0usize;
    for r in &out.prunes {
        for m in &r.removed {
            removed.insert(m.clone());
            count += 1;
        }
    }
    // 常に消えるもの（D・W・(v) の先頭の pull）に、tag が負けた T だけを足した集合に、各 manifest がちょうど 1 回ずつ一致する。
    let mut want_removed = sets.always_removed.clone();
    want_removed.extend(
        sets.t_manifests
            .iter()
            .enumerate()
            .filter(|(k, _)| !won.contains(k))
            .map(|(_, m)| m.clone()),
    );
    expect(
        removed == want_removed && count == want_removed.len(),
        &format!(
            "prune removed {count} manifests ({} distinct); want exactly the {} unreferenced ones",
            removed.len(),
            want_removed.len()
        ),
    )?;
    verify_blob_set(&sh.images, &w.expected_blobs(won))?;
    verify_inventory(sh, w)?;
    let got = listed_rows(&sh.images, env)?;
    let want = w.expected_rows(won);
    expect(
        got == want,
        &format!("image rows differ: {}", rows_diff(&want, &got)),
    )?;
    let (containers, tags) = refs_of(&sh.images, &w.r.manifest)?;
    expect(
        containers.is_empty() && tags == [tag_of("gc-c-r")],
        &format!("references of R: {containers:?} {tags:?}"),
    )?;
    if let Some((id_rr, id_rs)) = resident {
        for (im, id) in [(&w.rr, id_rr), (&w.rs, id_rs)] {
            let (containers, tags) = refs_of(&sh.images, &im.manifest)?;
            expect(
                containers.len() == 1
                    && containers[0].ends_with(&format!(".{id}"))
                    && tags.is_empty(),
                &format!("references of the resident image for {id}: {containers:?} {tags:?}"),
            )?;
        }
    }
    if let Ok(rd) = fs::read_dir(sh.images.join("staging")) {
        let left: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .take(5)
            .collect();
        expect(left.is_empty(), &format!("staging has leftovers: {left:?}"))?;
    }
    if let Some(env) = env {
        let df = system_df(env)?;
        let expected = w.expected_blobs(won);
        let bytes: u64 = expected.values().map(|l| *l as u64).sum();
        expect(
            df.missing == 0
                && df.unregistered_count == 0
                && df.unregistered_bytes == 0
                && df.foreign == 0
                && df.images_count == want.len() as u64
                && df.blob_count == expected.len() as u64
                && df.images_bytes == bytes
                && df.cache_bytes == bytes,
            &format!(
                "system df after the phase: {df:?}, want blobs={} bytes={bytes}",
                expected.len()
            ),
        )?;
    }
    Ok(())
}

/// 共通の本体。種入れ → 並行フェーズ → 最終照合。
fn execute(
    images: &Path,
    env: Option<&Env>,
    mut cleanup: Option<&mut Cleanup>,
    p: &Params,
) -> Result<(), String> {
    let w = World::new(p.iterations, p.rm_workers > 0, env.is_none());
    let pid = std::process::id();
    let sh = Shared {
        images: images.to_path_buf(),
        iterations: p.iterations,
        gate_leases: p.pull_workers.min(p.iterations),
        prune_workers: p.prune_workers,
        create_ids: (0..p.iterations)
            .map(|k| format!("gciv{pid}x{k:04}"))
            .collect(),
        pull_ids: (0..p.iterations)
            .map(|i| format!("gcp{pid}x{i:04}"))
            .collect(),
        start_ids: (0..if env.is_some() { p.iterations } else { 0 })
            .map(|k| format!("gck{pid}x{k:04}"))
            .collect(),
        start: AtomicBool::new(false),
        abort: AtomicBool::new(false),
        others_done: AtomicBool::new(false),
        monitor_stop: AtomicBool::new(false),
        prunes_completed: AtomicUsize::new(0),
        leases_taken: AtomicUsize::new(0),
        leased_hits: AtomicUsize::new(0),
        absent_hits: AtomicUsize::new(0),
        monitor_polls: AtomicUsize::new(0),
        monitor_lock_errors: AtomicUsize::new(0),
        shared_lease_kept: AtomicUsize::new(0),
        protected_blobs: Mutex::new(BTreeMap::new()),
        protected_manifests: Mutex::new(BTreeSet::new()),
        violation: Mutex::new(None),
    };
    // 種入れ。
    seed(images, &w.p, Some(&tag_of("gc-c-p")))?;
    seed(images, &w.r, Some(&tag_of("gc-c-r")))?;
    let resident_tag = |name: &str| env.is_none().then(|| tag_of(name));
    seed(images, &w.rr, resident_tag("gc-c-rr").as_deref())?;
    seed(images, &w.rs, resident_tag("gc-c-rs").as_deref())?;
    for (j, v) in w.v.iter().enumerate() {
        seed(images, v, Some(&tag_of(&format!("gc-c-v{j}"))))?;
    }
    for d in &w.d {
        seed(images, d, None)?;
    }
    for (k, im) in w.creating.iter().enumerate() {
        seed(images, im, Some(&World::creating_tag(k)))?;
    }
    for (g, im) in w.y.iter().enumerate() {
        seed(images, im, Some(&World::y_tag(g)))?;
    }
    for im in [&w.p, &w.r, &w.rr, &w.rs] {
        sh.protect_image(im);
    }
    // 常駐のコンテナ（Rr は running、Rs は stopped）。
    let id_rr = format!("gcrr{pid}");
    let id_rs = format!("gcrs{pid}");
    let mut resident_run = None;
    if let (Some(env), Some(cleanup)) = (env, cleanup.as_deref_mut()) {
        cleanup.live.extend(sh.pull_ids.iter().cloned());
        cleanup.live.extend(sh.start_ids.iter().cloned());
        cleanup.live.push(id_rr.clone());
        cleanup.live.push(id_rs.clone());
        let bundle_rr = env.work.join("cbundle-rr");
        ensure_bundle(&bundle_rr)?;
        create_cli(env, &id_rr, &bundle_rr, &w.rr.manifest.to_string())?;
        resident_run = Some(start_created(env, &id_rr)?);
        let bundle_rs = env.work.join("cbundle-rs");
        ensure_bundle(&bundle_rs)?;
        create_cli(env, &id_rs, &bundle_rs, &w.rs.manifest.to_string())?;
        let run = start_created(env, &id_rs)?;
        stop_container(env, &run)?;
    }
    let sets = Sets::of(&w);
    let t0 = Instant::now();
    let mut out = run_phase(&sh, &w, env, p, &sets)?;
    let phase_ms = t0.elapsed().as_millis();
    // (vi) の勝敗（tag が成功した k）。期待する在庫は、この実行時の記録から組み立てる。
    let won: BTreeSet<usize> = out
        .records
        .iter()
        .filter(|r| matches!(r.result, Ok(Detail::TagRace { won: true })))
        .map(|r| r.index)
        .collect();
    verify_final(
        &sh,
        &w,
        env,
        &sets,
        &mut out,
        env.map(|_| (id_rr.as_str(), id_rs.as_str())),
        &won,
    )?;

    let leased = sh.leased_hits.load(Ordering::SeqCst);
    let absent = sh.absent_hits.load(Ordering::SeqCst);
    let prunes = out.prunes.len();
    expect(
        leased >= 1,
        "no pull reused a blob that only its lease protected",
    )?;
    expect(
        prunes >= p.iterations,
        &format!("only {prunes} image prune runs"),
    )?;
    // 決定的な部分: (v) は X_g が「リースだけが守った blob」として 1 回以上報告される。
    // (vi) は偶数の回で prune が必ず先に回収する。奇数の回の勝敗は観測値で、件数は情報行にだけ出す。
    let lease_kept = sh.shared_lease_kept.load(Ordering::SeqCst);
    expect(
        lease_kept >= 1,
        "(v): prune never reported a shared blob as kept only by the remaining pull leases",
    )?;
    let tag_won = won.len();
    let prune_won = p.iterations - tag_won;
    expect(
        prune_won >= p.iterations.div_ceil(2),
        &format!(
            "(vi): only {prune_won} of {} tag runs lost to image prune; the even runs wait for a prune and must lose",
            p.iterations
        ),
    )?;
    for (kind, name, want) in [
        (OpKind::Pull, "pull", p.iterations),
        (OpKind::CreatingRef, "creating_ref", p.iterations),
        (OpKind::SharedPull, "shared_pull", p.iterations),
        (OpKind::TagRace, "tag_race", p.iterations),
        (
            OpKind::CreateStart,
            "create_start",
            if env.is_some() { p.iterations } else { 0 },
        ),
        (
            OpKind::ImageRm,
            "image_rm",
            if env.is_some() { p.iterations } else { 0 },
        ),
    ] {
        let (n, max, med) = stats(&out.records, kind);
        expect(n == want, &format!("{name}: {n} of {want} operations"))?;
        eprintln!("info: local_image_gc concurrent {name}: ok={n} max_ms={max} median_ms={med}");
    }
    eprintln!(
        "info: local_image_gc concurrent in_flight pull={} create_start={} image_rm={} creating_ref={} shared_pull={} tag_race={} prune={} prune_runs={prunes} lease_reused={leased} lease_absent={absent} shared_lease_kept={lease_kept} tag_won={tag_won} prune_won={prune_won} monitor_polls={} monitor_lock_errors={} phase_ms={phase_ms}",
        p.pull_workers,
        if env.is_some() { p.start_workers } else { 0 },
        if env.is_some() { p.rm_workers } else { 0 },
        p.creating_workers,
        p.shared_workers * 3,
        p.tag_workers,
        p.prune_workers,
        sh.monitor_polls.load(Ordering::SeqCst),
        sh.monitor_lock_errors.load(Ordering::SeqCst),
    );
    // 常駐のコンテナを片づける。
    if let (Some(env), Some(cleanup)) = (env, cleanup) {
        if let Some(run) = resident_run {
            stop_container(env, &run)?;
        }
        delete_cli(env, &id_rr)?;
        delete_cli(env, &id_rs)?;
        cleanup.live.clear();
    }
    Ok(())
}

/// 実機シナリオ（`--ignored --scenario concurrent`）。
pub(super) fn scenario_real(env: &Env, cleanup: &mut Cleanup) -> Result<(), String> {
    let p = Params {
        iterations: ITERATIONS,
        pull_workers: PULL_IN_FLIGHT,
        start_workers: START_IN_FLIGHT,
        rm_workers: RM_IN_FLIGHT,
        prune_workers: PRUNE_IN_FLIGHT,
        creating_workers: CREATING_IN_FLIGHT,
        shared_workers: SHARED_PULL_IN_FLIGHT,
        tag_workers: TAG_IN_FLIGHT,
    };
    execute(&env.images, Some(env), Some(cleanup), &p)
}

/// 既定のテスト集合で回る自己検証。コンテナを使わず、pull と prune の並行だけを通す。
pub(super) fn offline_self_check() -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let root = crate::scratch_root::scratch_root("fandhe-lig-offline-scratch", CLI_TIMEOUT)
        .join(format!("fandhe-lig-offline-{}-{nanos}", std::process::id()));
    fs::create_dir(&root).map_err(|e| format!("create offline dir: {e}"))?;
    set_mode(&root, 0o700)?;
    let images = root.join("images");
    fs::create_dir(&images).map_err(|e| format!("mkdir images: {e}"))?;
    set_mode(&images, 0o700)?;
    let p = Params {
        iterations: OFFLINE_ITERATIONS,
        pull_workers: OFFLINE_PULL_IN_FLIGHT,
        start_workers: 0,
        rm_workers: 0,
        prune_workers: PRUNE_IN_FLIGHT,
        creating_workers: OFFLINE_CREATING_IN_FLIGHT,
        shared_workers: OFFLINE_SHARED_PULL_IN_FLIGHT,
        tag_workers: OFFLINE_TAG_IN_FLIGHT,
    };
    let r = execute(&images, None, None, &p);
    if r.is_ok() {
        let _ = fs::remove_dir_all(&root);
        crate::scratch_root::remove_scratch_root();
    }
    r
}
