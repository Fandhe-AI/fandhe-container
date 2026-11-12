//! 削除処理中の SIGKILL からの復旧の照合（#667・TASK-184.5・OCI-7・CLI-1・REPAIR-5・REPAIR-12。MS-6）。
//!
//! # 役割と呼び出し元
//! `local_image_gc.rs` の `linux` モジュールの子（`#[path]` を使わず `tests/linux/crash.rs` で解決される）。入口は 3 つ。
//! - [`scenario_real`]: `--ignored --scenario crash`。コンテナ参照を CLI の実 `create --image` で付ける実機層（CI の専用ステップ）。
//! - [`offline_self_check`]: 既定のテスト集合で回る自己検証。コンテナ参照を oci の公開 API で付ける以外は実機層と同じ試行を回す。
//! - [`child`]: 試験専用の再入口 `--gc-crash-child prune <images>`。`image prune` は CLI に未配線（#2384）のため、
//!   試験バイナリ自身を子として起動して `execute_image_prune` をプロセス内で実行する。配線後は CLI 経由へ切り替える。
//!
//! # 試行の手順（`image rm` と `image prune` の 2 種類 × トリガー × 繰り返し）
//! 1. 用意した「削除前」のイメージルート（テンプレート）を作業用に複製する。
//! 2. 削除の子プロセスを起動し、ディスクの状態を監視して、トリガー（ジャーナルの出現・blob の消え始め・半分・終盤）が
//!    立った瞬間に SIGKILL する。子はロックを持ったまま死ぬ（flock は kill で外れる）。
//! 3. 回復前にファイルだけを見て段階を分類する（ジャーナルの有無と予定した blob の残数）。ジャーナルが無いのに blob が
//!    一部だけ消えている状態は中間状態の直接の証拠なので、その場で失敗にする。参照中の blob は全部あることも見る。
//! 4. 新しい `ImageStore::lock`（別プロセスから見た再起動後の GC の入口。中断された削除のロールフォワードを含む）で回復し、
//!    スナップショット（在庫の行・コンテナ参照・`blobs/sha256` の名前と大きさ）が「削除前」か「削除後」のどちらかと
//!    完全に一致することを照合する。段階との対応（ジャーナル前は削除前、ジャーナル後と完了は削除後）、2 回目の回復が
//!    何もしないこと、ジャーナルと一時ファイルが残らないことも見る。
//! 5. 続けて `execute_image_prune` を 1 回回し、参照を数え直しても状態が期待どおりに収束することを見る。
//!
//! # 主張の範囲
//! SIGKILL はプロセスの強制終了で、ページキャッシュは残る。電源断・カーネルクラッシュ後の媒体への永続化（IO-2）は
//! 対象外で、#1965（`docs/design/io-power-loss-verification.md`）の範囲。回復処理（`recover_pending_deletion`）自体の
//! 途中での再クラッシュも扱わない。件数と段階の分布の妥当性の判断は人間担当の #668（TASK-184.h1）。
//!
//! # 空振り防止
//! prune は `mid-unlink`（予定した blob の一部だけが消えた段階）、rm はジャーナルありの段階を 1 回以上観測することを必須にする。
//! 予定の回数で観測できなければ、上限つきで追加の試行を重ねる。分布は情報行（`info: crash ...`）で出す。

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

use fandhe_container_oci::image_management::{
    ContainerRefId, DeletionDurability, GC_JOURNAL_FILE_NAME, PendingDeletionRecovery,
};

use super::*;

/// rm の対象のタグ（ダミーのレジストリ名）。
const TAG_TARGET: &str = "registry.example/fandhe/gc-crash-target:v1";
const TAG_K: &str = "registry.example/fandhe/gc-crash-keep:v1";
/// 在庫を大きくして rm の「ジャーナル永続化から在庫保存まで」の窓を広げる添え物のタグの件数。
const FILLER_IMAGES: usize = 64;
/// prune 用の無参照イメージの件数。1 件が config 1 つと自前の layer 127 件で、合計約 3,000 件の unlink になる。
const PRUNE_UNREFERENCED: usize = 24;
/// 1 つのイメージの layer 数（`MAX_LAYERS`）。
const LAYERS: usize = 128;
/// トリガーを待つ上限（REPAIR-5）。
const TRIGGER_DEADLINE: Duration = Duration::from_secs(30);
/// 空振り防止のために重ねる追加の試行の上限。
const EXTRA_RUNS: usize = 24;
/// 作業用の複製先のディレクトリ名（子の再入口はこの接頭辞だけを受ける）。
const TRIAL_DIR: &str = "crash-trial-images";
const CHILD_FLAG: &str = "--gc-crash-child";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OpKind {
    Rm,
    Prune,
}

impl OpKind {
    fn name(self) -> &'static str {
        match self {
            OpKind::Rm => "rm",
            OpKind::Prune => "prune",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Trigger {
    /// spawn の直後。削除前の側を作る。
    Spawned,
    /// `@gc-pending.json` が現れた。
    Journal,
    /// 予定した blob の標本のうち 1 つが消えた。
    FirstBlob,
    /// 標本の半分が消えた。
    HalfBlobs,
    /// 標本が全部消えた。
    LastBlob,
}

impl Trigger {
    fn name(self) -> &'static str {
        match self {
            Trigger::Spawned => "spawned",
            Trigger::Journal => "journal",
            Trigger::FirstBlob => "first-blob",
            Trigger::HalfBlobs => "half-blobs",
            Trigger::LastBlob => "last-blob",
        }
    }
}

/// kill 直後・回復前の段階。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Phase {
    BeforeJournal,
    JournalWritten,
    MidUnlink,
    Unlinked,
    Completed,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::BeforeJournal => "before-journal",
            Phase::JournalWritten => "journal-written",
            Phase::MidUnlink => "mid-unlink",
            Phase::Unlinked => "unlinked",
            Phase::Completed => "completed",
        }
    }
}

/// 回復後の状態。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Before,
    After,
}

/// 状態の写し。在庫の行・コンテナ参照・`blobs/sha256` の名前と大きさ。
#[derive(Clone, PartialEq, Eq, Debug)]
struct Snapshot {
    rows: Vec<String>,
    containers: Vec<String>,
    blobs: BTreeMap<String, u64>,
}

impl Snapshot {
    /// 食い違いの要約（先頭の数件）。
    fn diff(&self, other: &Snapshot) -> String {
        let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<_>>();
        let (r1, r2) = (set(&self.rows), set(&other.rows));
        let (c1, c2) = (set(&self.containers), set(&other.containers));
        let b1: BTreeSet<&String> = self.blobs.keys().collect();
        let b2: BTreeSet<&String> = other.blobs.keys().collect();
        let first = |it: Vec<String>| it.into_iter().take(3).collect::<Vec<_>>();
        format!(
            "rows -{:?} +{:?}; containers -{:?} +{:?}; blobs -{:?} +{:?} (sizes differ: {})",
            first(r1.difference(&r2).cloned().collect()),
            first(r2.difference(&r1).cloned().collect()),
            first(c1.difference(&c2).cloned().collect()),
            first(c2.difference(&c1).cloned().collect()),
            first(b1.difference(&b2).map(|s| (*s).clone()).collect()),
            first(b2.difference(&b1).map(|s| (*s).clone()).collect()),
            self.blobs
                .iter()
                .any(|(k, v)| other.blobs.get(k).is_some_and(|o| o != v)),
        )
    }
}

/// 1 つのイメージ（manifest の 64 桁の 16 進と、config・layer の blob 名）。
#[derive(Clone)]
struct Img {
    manifest: String,
    config: String,
    layers: Vec<String>,
}

impl Img {
    fn blobs(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.config).chain(self.layers.iter())
    }
}

/// 先頭 2 桁の系列と通し番号から 64 桁の 16 進名を作る。
fn hexn(series: u8, idx: usize) -> String {
    format!("{series:02x}{idx:062x}")
}

fn digest(hex: &str) -> Result<Digest, String> {
    Digest::parse(&format!("sha256:{hex}")).map_err(|e| format!("digest {hex}: {e:?}"))
}

/// 削除前のテンプレートの内容。
struct Tpl {
    dir: PathBuf,
    /// 削除対象に固有の blob（これだけが消える予定）。
    planned: Vec<String>,
    /// 削除後も残る blob。
    protected: Vec<String>,
    before: Snapshot,
    after: Snapshot,
}

/// 実行の文脈。
struct Ctx {
    cli: PathBuf,
    state_s: String,
    work: PathBuf,
}

/// 共有レイヤー S と、守る側 K・C。
struct Common {
    shared: String,
    keep: Img,
    cref: Img,
}

fn common() -> Common {
    let shared = hexn(0xa3, 0);
    let mut keep_layers = vec![shared.clone()];
    keep_layers.extend((1..LAYERS).map(|i| hexn(0xb1, i)));
    Common {
        keep: Img {
            manifest: hexn(0xe2, 0),
            config: hexn(0xb1, 0),
            layers: keep_layers,
        },
        cref: Img {
            manifest: hexn(0xe4, 0),
            config: hexn(0xc1, 0),
            layers: (1..=3).map(|i| hexn(0xc1, i)).collect(),
        },
        shared,
    }
}

fn write_blobs<'a>(dir: &Path, names: impl Iterator<Item = &'a String>) -> Result<(), String> {
    let blobs = dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).map_err(|e| format!("mkdir blobs: {e}"))?;
    for n in names {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(blobs.join(n))
            .map_err(|e| format!("create blob {n}: {e}"))?;
        f.write_all(format!("fandhe-crash-blob/{n}\n").as_bytes())
            .map_err(|e| format!("write blob {n}: {e}"))?;
    }
    Ok(())
}

/// 在庫へ manifest を登録しタグを付ける。タグなしのイメージは、同じ排他区間の最後のタグ付けの保存に便乗して永続化する。
fn seed_bulk(dir: &Path, tagged: &[(&Img, String)], untagged: &[&Img]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let all: Vec<&Img> = tagged
        .iter()
        .map(|t| t.0)
        .chain(untagged.iter().copied())
        .collect();
    let names: Vec<&String> = all
        .iter()
        .flat_map(|i| i.blobs())
        .filter(|n| seen.insert((*n).clone()))
        .collect();
    write_blobs(dir, names.into_iter())?;
    let store = ImageStore::open(dir).map_err(|e| format!("open store: {e:?}"))?;
    let mut guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
    for img in &all {
        let comp = ManifestComposition::new(
            digest(&img.config)?,
            img.layers
                .iter()
                .map(|l| digest(l))
                .collect::<Result<_, _>>()?,
        )
        .map_err(|e| format!("composition: {e:?}"))?;
        guard
            .register_manifest(digest(&img.manifest)?, comp)
            .map_err(|e| format!("register: {e:?}"))?;
    }
    for (img, tag) in tagged {
        guard
            .tag_image(
                &ImageTagSource::Manifest(digest(&img.manifest)?),
                tag_key(tag)?,
            )
            .map_err(|e| format!("tag {tag}: {e:?}"))?;
    }
    Ok(())
}

/// 再帰的な複製。symlink と通常ファイル・ディレクトリ以外は拒否し、ディレクトリは 0700 にする。
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    set_mode(dst, 0o700)?;
    for ent in fs::read_dir(src).map_err(|e| format!("read_dir {}: {e}", src.display()))? {
        let ent = ent.map_err(|e| format!("read_dir entry: {e}"))?;
        let to = dst.join(ent.file_name());
        let ft = ent.file_type().map_err(|e| format!("file_type: {e}"))?;
        if ft.is_dir() {
            copy_tree(&ent.path(), &to)?;
        } else if ft.is_file() {
            fs::copy(ent.path(), &to).map_err(|e| format!("copy {}: {e}", to.display()))?;
        } else {
            return Err(format!("unexpected entry type: {}", ent.path().display()));
        }
    }
    Ok(())
}

fn blob_dir(images: &Path) -> PathBuf {
    images.join("blobs").join("sha256")
}

/// スナップショットと、その `lock` が行った中断削除の復旧結果。`lock` が回復を行うので、回復前の観測にはここを使わない。
fn snapshot(images: &Path) -> Result<(Snapshot, Option<PendingDeletionRecovery>), String> {
    let (rows, containers, recovered) = {
        let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
        let guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        let recovered = guard.recovery().cloned();
        let list = guard
            .list_images(store.root())
            .map_err(|e| format!("list_images: {e:?}"))?;
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        let mut containers = Vec::new();
        for e in &list.entries {
            rows.push(format!(
                "{}|{}|{}|{}",
                e.tag.as_ref().map_or("-".to_string(), ToString::to_string),
                e.digest,
                e.size_bytes,
                e.missing_blobs.len()
            ));
            if seen.insert(e.digest.to_string()) {
                for c in guard.manifest_references(&e.digest).containers {
                    containers.push(format!("{}<-{}", e.digest, c.as_str()));
                }
            }
        }
        rows.sort();
        containers.sort();
        (rows, containers, recovered)
    };
    let mut blobs = BTreeMap::new();
    for ent in fs::read_dir(blob_dir(images)).map_err(|e| format!("read blobs dir: {e}"))? {
        let ent = ent.map_err(|e| format!("read blobs entry: {e}"))?;
        let name = ent.file_name().to_string_lossy().into_owned();
        let md = fs::symlink_metadata(ent.path()).map_err(|e| format!("stat blob {name}: {e}"))?;
        if !md.is_file() {
            return Err(format!("blob entry {name} is not a regular file"));
        }
        blobs.insert(name, md.len());
    }
    Ok((
        Snapshot {
            rows,
            containers,
            blobs,
        },
        recovered,
    ))
}

/// ストア root 直下のジャーナルとその一時ファイル、在庫の一時ファイルなど、削除の途中で作られる名前。
fn leftovers(images: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for ent in fs::read_dir(images).map_err(|e| format!("read root: {e}"))? {
        let name = ent
            .map_err(|e| format!("read root entry: {e}"))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.starts_with(GC_JOURNAL_FILE_NAME) || name.contains(".tmp-") {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// テンプレートの設計図。
struct Spec {
    tagged: Vec<(Img, String)>,
    untagged: Vec<Img>,
    /// 削除対象に固有の blob。
    planned: Vec<String>,
    /// 削除後も残る blob。
    protected: Vec<String>,
}

fn build_rm() -> Spec {
    let c = common();
    let mut m_layers: Vec<String> = (0..LAYERS - 1).map(|i| hexn(0xa2, i)).collect();
    m_layers.push(c.shared.clone());
    let target = Img {
        manifest: hexn(0xe1, 0),
        config: hexn(0xa1, 0),
        layers: m_layers,
    };
    let planned: Vec<String> = target
        .blobs()
        .filter(|n| **n != c.shared)
        .cloned()
        .collect();
    let mut tagged = vec![
        (target.clone(), TAG_TARGET.to_string()),
        (c.keep.clone(), TAG_K.to_string()),
    ];
    for i in 0..FILLER_IMAGES {
        tagged.push((
            Img {
                manifest: hexn(0xe3, i),
                config: c.keep.config.clone(),
                layers: c.keep.layers.clone(),
            },
            format!("registry.example/fandhe/gc-crash-b{i}:v1"),
        ));
    }
    let planned_set: BTreeSet<&String> = planned.iter().collect();
    let mut protected = BTreeSet::new();
    for img in [&c.keep, &c.cref] {
        protected.extend(img.blobs().cloned());
    }
    protected.insert(c.shared.clone());
    debug_assert!(planned_set.iter().all(|p| !protected.contains(*p)));
    Spec {
        tagged,
        untagged: vec![c.cref],
        planned,
        protected: protected.into_iter().collect(),
    }
}

fn build_prune() -> Spec {
    let c = common();
    let mut planned = Vec::new();
    let mut untagged = vec![c.cref.clone()];
    for j in 0..PRUNE_UNREFERENCED {
        let base = j * 1000;
        let mut layers: Vec<String> = (1..LAYERS).map(|k| hexn(0xd1, base + k)).collect();
        layers.push(c.shared.clone());
        let u = Img {
            manifest: hexn(0xe5, j),
            config: hexn(0xd1, base),
            layers,
        };
        planned.extend(u.blobs().filter(|n| **n != c.shared).cloned());
        untagged.push(u);
    }
    let mut protected = BTreeSet::new();
    for img in [&c.keep, &c.cref] {
        protected.extend(img.blobs().cloned());
    }
    protected.insert(c.shared.clone());
    Spec {
        tagged: vec![(c.keep.clone(), TAG_K.to_string())],
        untagged,
        planned,
        protected: protected.into_iter().collect(),
    }
}

/// 子プロセスを起動する。標準出力は捨て、標準エラーは失敗時の診断用に回収する。
fn spawn_child(ctx: &Ctx, op: OpKind, images: &Path) -> Result<Child, String> {
    let images_s = images.to_str().ok_or("images path is not UTF-8")?;
    let mut cmd = match op {
        OpKind::Rm => {
            let mut c = Command::new(&ctx.cli);
            c.args([
                "--root",
                ctx.state_s.as_str(),
                "image",
                "rm",
                "--image-root",
                images_s,
                TAG_TARGET,
            ]);
            c
        }
        OpKind::Prune => {
            let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
            let mut c = Command::new(exe);
            c.args([CHILD_FLAG, "prune", images_s]);
            c
        }
    };
    cmd.env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
        .env_remove("FANDHE_CONTAINER_OP_LOG")
        .env_remove("FANDHE_CONTAINER_TEST_SYSTEMD_RUN")
        .env_remove("FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd.spawn().map_err(|e| format!("spawn {}: {e}", op.name()))
}

/// 期限つきで子を回収して終了状態を返す（無期限の `wait` を避ける。REPAIR-5）。
fn reap(c: &mut Child) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match c.try_wait() {
            Ok(Some(s)) => return Ok(s),
            Ok(None) if Instant::now() >= deadline => {
                return Err(format!("child was not reaped within {REAP_TIMEOUT:?}"));
            }
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(format!("reap child: {e}")),
        }
    }
}

/// ディスクの状態からトリガーの成立を判定する。blob は予定した中から等間隔に選んだ標本だけを stat する。
struct Probe {
    journal: PathBuf,
    sample: Vec<PathBuf>,
}

impl Probe {
    fn new(images: &Path, planned: &[String]) -> Self {
        let n = planned.len().min(32);
        let sample = (0..n)
            .filter_map(|i| planned.get(i * planned.len() / n.max(1)))
            .map(|name| blob_dir(images).join(name))
            .collect();
        Self {
            journal: images.join(GC_JOURNAL_FILE_NAME),
            sample,
        }
    }

    fn missing(&self) -> usize {
        self.sample
            .iter()
            .filter(|p| fs::symlink_metadata(p).is_err())
            .count()
    }

    fn fired(&self, t: Trigger) -> bool {
        match t {
            Trigger::Spawned => true,
            Trigger::Journal => fs::symlink_metadata(&self.journal).is_ok(),
            Trigger::FirstBlob => self.missing() >= 1,
            Trigger::HalfBlobs => self.missing() * 2 >= self.sample.len(),
            Trigger::LastBlob => self.missing() >= self.sample.len(),
        }
    }
}

/// 子の終わり方。
enum End {
    /// SIGKILL で終わった。
    Killed,
    /// kill が届く前に自然終了した（終了コード 0）。
    Completed,
}

fn supervise(mut child: Child, t: Trigger, probe: &Probe) -> Result<End, String> {
    let err_rx = super::spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
    let deadline = Instant::now() + TRIGGER_DEADLINE;
    loop {
        if probe.fired(t) {
            let _ = child.kill();
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => return Err(format!("poll child: {e}")),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = reap(&mut child);
            return Err(format!(
                "trigger {} did not fire within {TRIGGER_DEADLINE:?}",
                t.name()
            ));
        }
        thread::yield_now();
    }
    let status = reap(&mut child)?;
    let stderr = err_rx
        .recv_timeout(REAP_TIMEOUT)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    if status.signal() == Some(9) {
        Ok(End::Killed)
    } else if status.code() == Some(0) {
        Ok(End::Completed)
    } else {
        Err(format!(
            "child ended abnormally: {status:?} stderr={stderr:?}"
        ))
    }
}

/// 回復前にファイルだけを見て段階を決める。中間状態（ジャーナルが無いのに blob が一部だけ消えた）は失敗にする。
fn classify(images: &Path, tpl: &Tpl) -> Result<Phase, String> {
    let journal = fs::symlink_metadata(images.join(GC_JOURNAL_FILE_NAME)).is_ok();
    let dir = blob_dir(images);
    let present = tpl
        .planned
        .iter()
        .filter(|n| fs::symlink_metadata(dir.join(n)).is_ok())
        .count();
    let total = tpl.planned.len();
    // 参照中の blob は kill のどの時点でも全部ある。
    for n in &tpl.protected {
        if fs::symlink_metadata(dir.join(n)).is_err() {
            return Err(format!("protected blob {n} is missing before recovery"));
        }
    }
    match (journal, present) {
        (false, p) if p == total => Ok(Phase::BeforeJournal),
        (false, 0) => Ok(Phase::Completed),
        (false, p) => Err(format!(
            "intermediate state: no journal but only {} of {total} planned blobs are gone",
            total - p
        )),
        (true, p) if p == total => Ok(Phase::JournalWritten),
        (true, 0) => Ok(Phase::Unlinked),
        (true, _) => Ok(Phase::MidUnlink),
    }
}

struct Rec {
    phase: Phase,
    outcome: Outcome,
    crashed: bool,
}

/// 試行 1 回。手順はモジュール doc。
fn trial(ctx: &Ctx, op: OpKind, tpl: &Tpl, trigger: Trigger, run: usize) -> Result<Rec, String> {
    let what = format!("crash {} trigger={} run={run}", op.name(), trigger.name());
    let dir = ctx.work.join(TRIAL_DIR);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("{what}: clear trial dir: {e}"))?;
    }
    copy_tree(&tpl.dir, &dir).map_err(|e| format!("{what}: {e}"))?;
    let probe = Probe::new(&dir, &tpl.planned);
    let child = spawn_child(ctx, op, &dir).map_err(|e| format!("{what}: {e}"))?;
    let end = supervise(child, trigger, &probe).map_err(|e| format!("{what}: {e}"))?;
    let phase = classify(&dir, tpl).map_err(|e| format!("{what}: {e}"))?;

    // 再起動後の GC の入口。ここでロールフォワードが走る。
    let (snap, rec) = snapshot(&dir).map_err(|e| format!("{what}: recovery snapshot: {e}"))?;
    match (phase, &rec) {
        (Phase::JournalWritten | Phase::MidUnlink, Some(r)) | (Phase::Unlinked, Some(r)) => {
            if r.durability != DeletionDurability::Confirmed
                || !r.undeleted_blobs.is_empty()
                || !r.conflicted_manifests.is_empty()
            {
                return Err(format!(
                    "{what}: phase={} recovery not clean: {r:?}",
                    phase.name()
                ));
            }
        }
        (Phase::JournalWritten | Phase::MidUnlink, None) => {
            return Err(format!(
                "{what}: phase={} expected a recovery",
                phase.name()
            ));
        }
        (Phase::Unlinked, None) => {}
        (Phase::BeforeJournal | Phase::Completed, None) => {}
        (p, Some(r)) => {
            return Err(format!(
                "{what}: phase={} unexpected recovery {r:?}",
                p.name()
            ));
        }
    }
    let outcome = if snap == tpl.before {
        Outcome::Before
    } else if snap == tpl.after {
        Outcome::After
    } else {
        return Err(format!(
            "{what}: phase={} state matches neither pre-delete nor post-delete: vs before {}; vs after {}",
            phase.name(),
            snap.diff(&tpl.before),
            snap.diff(&tpl.after)
        ));
    };
    let want = if phase == Phase::BeforeJournal {
        Outcome::Before
    } else {
        Outcome::After
    };
    if outcome != want {
        return Err(format!(
            "{what}: phase={} converged to {outcome:?}, want {want:?}",
            phase.name()
        ));
    }
    // 冪等と後始末。
    let store = ImageStore::open(&dir).map_err(|e| format!("{what}: open: {e:?}"))?;
    if let Some(r) = store
        .recover_pending_deletion()
        .map_err(|e| format!("{what}: second recovery: {e:?}"))?
    {
        return Err(format!("{what}: second recovery was not a no-op: {r:?}"));
    }
    let left = leftovers(&dir).map_err(|e| format!("{what}: {e}"))?;
    if !left.is_empty() {
        return Err(format!(
            "{what}: journal or temporary files remained: {left:?}"
        ));
    }
    // 参照を数え直す GC。rm の試行では何も変えず、prune の試行では削除後に収束する。
    {
        let mut guard = store.lock().map_err(|e| format!("{what}: lock: {e:?}"))?;
        let out = guard
            .execute_image_prune(store.root())
            .map_err(|e| format!("{what}: prune: {e:?}"))?;
        if !out.undeleted_blobs.is_empty() {
            return Err(format!(
                "{what}: prune left undeleted blobs {:?}",
                out.undeleted_blobs
            ));
        }
    }
    drop(store);
    let (post, rec2) = snapshot(&dir).map_err(|e| format!("{what}: gc snapshot: {e}"))?;
    if rec2.is_some() {
        return Err(format!("{what}: a recovery ran after the GC"));
    }
    let want_post = if op == OpKind::Prune {
        &tpl.after
    } else {
        &snap
    };
    if &post != want_post {
        return Err(format!(
            "{what}: GC changed the state: {}",
            post.diff(want_post)
        ));
    }
    let crashed = matches!(end, End::Killed);
    eprintln!(
        "info: crash op={} trigger={} run={run} phase={} outcome={} signal={}",
        op.name(),
        trigger.name(),
        phase.name(),
        if outcome == Outcome::Before {
            "before"
        } else {
            "after"
        },
        if crashed { "9" } else { "none" }
    );
    Ok(Rec {
        phase,
        outcome,
        crashed,
    })
}

/// テンプレートを作り、対照（kill なし）の完走で期待する「削除後」を採って手で決めた期待値と照合する。
fn build_template(
    ctx: &Ctx,
    op: OpKind,
    attach: &mut dyn FnMut(&Path, &str, &str) -> Result<(), String>,
) -> Result<Tpl, String> {
    let dir = ctx.work.join(format!("crash-tpl-{}", op.name()));
    fs::create_dir(&dir).map_err(|e| format!("mkdir template: {e}"))?;
    set_mode(&dir, 0o700)?;
    let Spec {
        tagged,
        untagged,
        planned,
        protected,
    } = match op {
        OpKind::Rm => build_rm(),
        OpKind::Prune => build_prune(),
    };
    let tagged_ref: Vec<(&Img, String)> = tagged.iter().map(|(i, t)| (i, t.clone())).collect();
    let untagged_ref: Vec<&Img> = untagged.iter().collect();
    seed_bulk(&dir, &tagged_ref, &untagged_ref)?;
    let cref = common().cref;
    attach(&dir, &format!("crash-c-{}", op.name()), &cref.manifest)?;
    let (before, rec) = snapshot(&dir)?;
    expect(rec.is_none(), "template has a pending deletion")?;
    expect(
        leftovers(&dir)?.is_empty(),
        "template has journal or temporary files",
    )?;
    expect(
        before.containers.len() == 1,
        &format!("template container refs: {:?}", before.containers),
    )?;

    // 対照: kill せず完走させた「削除後」。
    let ctrl = ctx.work.join("crash-ctrl-images");
    if ctrl.exists() {
        fs::remove_dir_all(&ctrl).map_err(|e| format!("clear control dir: {e}"))?;
    }
    copy_tree(&dir, &ctrl)?;
    let child = spawn_child(ctx, op, &ctrl)?;
    let probe = Probe::new(&ctrl, &planned);
    // 完走を待つ（トリガーは立たない値にせず、終了まで待つ専用の経路）。
    let end = wait_to_end(child, &probe)?;
    expect(matches!(end, End::Completed), "control run was killed")?;
    let (after, rec) = snapshot(&ctrl)?;
    expect(rec.is_none(), "control run left a pending deletion")?;
    let _ = fs::remove_dir_all(&ctrl);

    // 手で決めた期待値（空振りでないこと）。
    let planned_set: BTreeSet<&String> = planned.iter().collect();
    let want_blobs: BTreeSet<&String> = before
        .blobs
        .keys()
        .filter(|n| !planned_set.contains(*n))
        .collect();
    let got_blobs: BTreeSet<&String> = after.blobs.keys().collect();
    expect(
        want_blobs == got_blobs && planned.iter().all(|n| before.blobs.contains_key(n)),
        "control run did not delete exactly the planned blobs",
    )?;
    let survivors: BTreeSet<String> = match op {
        OpKind::Rm => {
            let all: BTreeSet<String> = tagged
                .iter()
                .map(|t| t.0.manifest.clone())
                .chain(untagged.iter().map(|i| i.manifest.clone()))
                .collect();
            all.into_iter().filter(|m| *m != hexn(0xe1, 0)).collect()
        }
        OpKind::Prune => [common().keep.manifest, common().cref.manifest]
            .into_iter()
            .collect(),
    };
    let got_manifests: BTreeSet<String> = after
        .rows
        .iter()
        .filter_map(|r| r.split('|').nth(1))
        .filter_map(|d| d.strip_prefix("sha256:"))
        .map(str::to_string)
        .collect();
    expect(
        got_manifests == survivors,
        &format!("control run kept the wrong manifests: {got_manifests:?}"),
    )?;
    expect(before != after, "control run changed nothing")?;
    Ok(Tpl {
        dir,
        planned,
        protected,
        before,
        after,
    })
}

/// kill せず、子の自然終了を期限つきで待つ。
fn wait_to_end(mut child: Child, _probe: &Probe) -> Result<End, String> {
    let err_rx = super::spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
    let deadline = Instant::now() + TRIGGER_DEADLINE;
    let status = loop {
        match child.try_wait().map_err(|e| format!("poll child: {e}"))? {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = reap(&mut child);
                return Err("control run did not finish in time".to_string());
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    };
    let stderr = err_rx
        .recv_timeout(REAP_TIMEOUT)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    if status.code() == Some(0) {
        Ok(End::Completed)
    } else {
        Err(format!("control run failed: {status:?} stderr={stderr:?}"))
    }
}

/// 度数分布。
#[derive(Default)]
struct Stats {
    phases: BTreeMap<Phase, usize>,
    before: usize,
    after: usize,
    crashed: usize,
    completed_before_kill: usize,
    runs: usize,
}

impl Stats {
    fn add(&mut self, r: &Rec) {
        *self.phases.entry(r.phase).or_insert(0) += 1;
        match r.outcome {
            Outcome::Before => self.before += 1,
            Outcome::After => self.after += 1,
        }
        if r.crashed {
            self.crashed += 1;
        } else {
            self.completed_before_kill += 1;
        }
        self.runs += 1;
    }

    fn count(&self, p: Phase) -> usize {
        self.phases.get(&p).copied().unwrap_or(0)
    }

    /// 空振り防止の必須条件を満たしたか。
    fn satisfied(&self, op: OpKind) -> bool {
        let journaled = self.count(Phase::JournalWritten)
            + self.count(Phase::MidUnlink)
            + self.count(Phase::Unlinked);
        let phase_ok = match op {
            OpKind::Prune => self.count(Phase::MidUnlink) >= 1,
            OpKind::Rm => journaled >= 1,
        };
        phase_ok && self.crashed >= 1
    }

    fn summary(&self) -> String {
        let phases: Vec<String> = self
            .phases
            .iter()
            .map(|(p, n)| format!("{}={n}", p.name()))
            .collect();
        format!(
            "runs={} crashed={} completed_before_kill={} before={} after={} phases=[{}]",
            self.runs,
            self.crashed,
            self.completed_before_kill,
            self.before,
            self.after,
            phases.join(",")
        )
    }
}

/// 1 つの op の試行群を回す。予定の回数で必須の段階が観測できなければ、上限つきで追加の試行を重ねる。
fn run_op(
    ctx: &Ctx,
    op: OpKind,
    tpl: &Tpl,
    triggers: &[Trigger],
    per_trigger: usize,
) -> Result<Stats, String> {
    let started = Instant::now();
    let mut stats = Stats::default();
    let mut run = 0;
    for t in triggers {
        for _ in 0..per_trigger {
            run += 1;
            stats.add(&trial(ctx, op, tpl, *t, run)?);
        }
    }
    let extra_trigger = match op {
        OpKind::Prune => Trigger::HalfBlobs,
        OpKind::Rm => Trigger::Journal,
    };
    let mut extra = 0;
    while !stats.satisfied(op) && extra < EXTRA_RUNS {
        extra += 1;
        run += 1;
        stats.add(&trial(ctx, op, tpl, extra_trigger, run)?);
    }
    eprintln!(
        "info: crash op={} summary {} extra_runs={extra} secs={:.1}",
        op.name(),
        stats.summary(),
        started.elapsed().as_secs_f64()
    );
    if !stats.satisfied(op) {
        return Err(format!(
            "crash {}: required phases were not observed ({})",
            op.name(),
            stats.summary()
        ));
    }
    Ok(stats)
}

const RM_TRIGGERS: [Trigger; 3] = [Trigger::Spawned, Trigger::Journal, Trigger::FirstBlob];
const PRUNE_TRIGGERS: [Trigger; 5] = [
    Trigger::Spawned,
    Trigger::Journal,
    Trigger::FirstBlob,
    Trigger::HalfBlobs,
    Trigger::LastBlob,
];

fn run_all(
    ctx: &Ctx,
    rm_runs: usize,
    prune_runs: usize,
    attach: &mut dyn FnMut(&Path, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let rm = build_template(ctx, OpKind::Rm, attach)?;
    run_op(ctx, OpKind::Rm, &rm, &RM_TRIGGERS, rm_runs)?;
    let prune = build_template(ctx, OpKind::Prune, attach)?;
    run_op(ctx, OpKind::Prune, &prune, &PRUNE_TRIGGERS, prune_runs)?;
    Ok(())
}

/// 実機シナリオ（`--ignored --scenario crash`）。コンテナ参照は CLI の実 `create --image` で付ける。
pub(super) fn scenario_real(env: &Env, cleanup: &mut Cleanup) -> Result<(), String> {
    let ctx = Ctx {
        cli: env.cli.clone(),
        state_s: env.root_s.clone(),
        work: env.work.clone(),
    };
    let mut created: Vec<(String, String)> = Vec::new();
    let mut attach = |dir: &Path, id: &str, manifest: &str| -> Result<(), String> {
        let dir_s = dir
            .to_str()
            .ok_or("template path is not UTF-8")?
            .to_string();
        let bundle = env.work.join(format!("crash-bundle-{id}"));
        make_bundle(&bundle)?;
        let bundle_s = bundle.to_str().ok_or("bundle path is not UTF-8")?;
        cleanup.live.push(id.to_string());
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "create",
                "--image-root",
                &dir_s,
                "--image",
                &format!("sha256:{manifest}"),
                "--bundle",
                bundle_s,
                id,
            ],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, &format!("create {id}"))?;
        created.push((id.to_string(), dir_s));
        Ok(())
    };
    run_all(&ctx, 4, 3, &mut attach)?;
    for (id, dir_s) in &created {
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "delete", "--image-root", dir_s, id],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, &format!("delete {id}"))?;
    }
    cleanup.live.clear();
    Ok(())
}

/// 既定のテスト集合で回る自己検証。コンテナ参照は oci の公開 API で付け、各トリガー 1 回ずつ回す。
pub(super) fn offline_self_check() -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let work = crate::scratch_root::scratch_root("fandhe-lig-offline-scratch", CLI_TIMEOUT)
        .join(format!("fandhe-lig-crash-{}-{nanos}", std::process::id()));
    fs::create_dir(&work).map_err(|e| format!("create offline dir: {e}"))?;
    set_mode(&work, 0o700)?;
    let state = work.join("state");
    fs::create_dir(&state).map_err(|e| format!("mkdir state: {e}"))?;
    set_mode(&state, 0o700)?;
    let ctx = Ctx {
        cli: PathBuf::from(env!("CARGO_BIN_EXE_fandhe-container")),
        state_s: state.to_str().ok_or("state path is not UTF-8")?.to_string(),
        work: work.clone(),
    };
    let mut attach = |dir: &Path, id: &str, manifest: &str| -> Result<(), String> {
        let store = ImageStore::open(dir).map_err(|e| format!("open store: {e:?}"))?;
        let cid = ContainerRefId::new(id).map_err(|e| format!("container id: {e:?}"))?;
        store
            .register_container_ref(&cid, &digest(manifest)?)
            .map_err(|e| format!("register ref: {e:?}"))?;
        store
            .bind_container_ref(&cid)
            .map_err(|e| format!("bind ref: {e:?}"))?;
        Ok(())
    };
    let r = run_all(&ctx, 1, 1, &mut attach);
    if r.is_ok() {
        // 親の作業領域（scratch root）は、後続の自己検証が共有するためここでは消さない。
        let _ = fs::remove_dir_all(&work);
    }
    r
}

/// 試験専用の再入口 `--gc-crash-child prune <images>`。`image prune` の本体をプロセス内で実行する（#2384 の配線まで）。
///
/// 引数は固定の形だけを受ける。op は `prune` のみ、パスは絶対パスで `..` を含まず、末尾が [`TRIAL_DIR`] であること。
/// 外れたら非 0 で終わる（親が作る作業用ディレクトリ以外には触れない）。
pub(super) fn child() -> ! {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run_child(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("local_image_gc: crash child FAILED: {e}");
            1
        }
    };
    std::process::exit(code)
}

fn run_child(args: &[String]) -> Result<(), String> {
    let [flag, op, path] = args else {
        return Err("expected `--gc-crash-child prune <images>`".to_string());
    };
    if flag != CHILD_FLAG || op != "prune" {
        return Err("only the prune operation is accepted".to_string());
    }
    let path = Path::new(path);
    let ok = path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, std::path::Component::ParentDir))
        && path
            .file_name()
            .is_some_and(|n| n == TRIAL_DIR || n == "crash-ctrl-images");
    if !ok {
        return Err(format!("unexpected images path: {}", path.display()));
    }
    let store = ImageStore::open(path).map_err(|e| format!("open store: {e:?}"))?;
    let mut guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
    guard
        .execute_image_prune(store.root())
        .map_err(|e| format!("prune: {e:?}"))?;
    Ok(())
}
