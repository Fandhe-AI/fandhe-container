//! CRI 記録の fsync が各 RPC のレイテンシに与える影響の計測ハーネス（#3224・CORE-10・CRI-1・REPAIR-8）。
//!
//! 役割: `CriRuntimeService` に実行層（フェイク）を注入した同一構成で、記録ストア（`FileRecordStore`）を
//! 注入した構成（`with_store`）と注入しない構成（`without_store`）の RPC レイテンシ（p50・p95）を比べる。
//! あわせて `FileRecordStore` の `put` / `remove` 1 回（一時ファイルの fsync → rename → ディレクトリの
//! fsync）の所要時間を、ストアの記録器（`RecordStoreOpRecorder`）が受けた値で採る。
//! 設計文書は `docs/design/cri-record-readoption.md` の「計測（#3224）」。
//!
//! 計測区間: RPC の `.await` の前後（リクエスト構築は含めない）。実行層はフェイクで即座に成功するため、
//! 絶対値は CRI 層（記録ストアの I/O と期限つき実行〔`run_bounded`〕のスレッド起動）の費用だけを表し、
//! core の起動費用は含まない。(with − without) の差は fsync のほか、sandbox 側の `store_io_bounded` の
//! スレッド生成を含む（本番でも払う費用）。
//!
//! 使い方: 引数なし（または `--bench` のみ）は I/O をしないスモーク（終了コード 0）。計測は
//! `--state-root <既存ディレクトリの絶対パス>` を指定したときだけ行い、その下に 0700 の作業ディレクトリを
//! 新規作成して終了時に消す。CI では実行せず、結果は手元の実測による暫定値（基準値の確定 #230 とは別）。
//! 出力に ID・パス・記録のバイト列は載せない（REPAIR-4）。
//!
//! 機械照合（REPAIR-12）: with_store では RPC ごとの記録器への到達件数を期待値と照合し、without_store では
//! 何も届かないことを照合する。不一致・RPC 失敗・期限切れは部分的な標本を出さず、1 行の JSON エラーで
//! 終了コード 1 にする。非 unix では「計測しない」旨を出して終了コード 0。

#[cfg(not(unix))]
fn main() {
    println!(
        "{{\"bench\":\"record_store_rpc_latency\",\"measured\":false,\"reason\":\"not measured; unsupported on this OS\"}}"
    );
}

#[cfg(unix)]
fn main() {
    std::process::exit(bench::run());
}

#[cfg(unix)]
mod bench {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use fandhe_container_core::traits::{
        ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
        KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
    };
    use fandhe_container_cri::adapter::{
        BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
    };
    use fandhe_container_cri::error::CriError;
    use fandhe_container_cri::runtime::v1::{
        self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
        runtime_service_server::RuntimeService,
    };
    use fandhe_container_cri::runtime_service::{
        CriRuntimeService, FileRecordStore, RecordId, RecordKind, RecordStore, RecordStoreOp,
        RecordStoreOpRecorder, RecordStoreOpSample, RecordStoreOutcome,
    };
    use serde_json::{Value, json};
    use tonic::Request;

    const BENCH: &str = "record_store_rpc_latency";
    const DEFAULT_TRIALS: usize = 200;
    const DEFAULT_WARMUP: usize = 20;
    const DEFAULT_TIMEOUT_SECS: u64 = 600;
    /// RPC の名前（出力順）。前の 5 つが #3224 の対象、後ろの 2 つは後始末（参考値）。
    const RPCS: [&str; 7] = [
        "RunPodSandbox",
        "CreateContainer",
        "StartContainer",
        "StopContainer",
        "RemoveContainer",
        "StopPodSandbox",
        "RemovePodSandbox",
    ];
    /// with_store で RPC ごとに記録器へ届くはずの (sandbox put, sandbox remove, container put, container remove)。
    /// 根拠: 設計文書「書く時点・消す時点」の R4・R5（Create は write-ahead と確定版の 2 回）。
    const EXPECTED: [(usize, usize, usize, usize); 7] = [
        (1, 0, 0, 0),
        (0, 0, 2, 0),
        (0, 0, 1, 0),
        (0, 0, 1, 0),
        (0, 0, 0, 1),
        (1, 0, 0, 0),
        (0, 1, 0, 0),
    ];

    struct Args {
        state_root: PathBuf,
        trials: usize,
        warmup: usize,
        timeout: Duration,
        host_kind: String,
        output: Option<PathBuf>,
    }

    enum Parsed {
        Smoke,
        Run(Args),
    }

    fn fail(code: &str, message: &str) -> i32 {
        eprintln!("{}", json!({ "code": code, "message": message }));
        1
    }

    fn parse_range(name: &str, v: &str, lo: usize, hi: usize) -> Result<usize, String> {
        match v.parse::<usize>() {
            Ok(n) if (lo..=hi).contains(&n) => Ok(n),
            _ => Err(format!("{name} must be an integer in {lo}..={hi}")),
        }
    }

    fn parse_args() -> Result<Parsed, String> {
        let mut it = std::env::args().skip(1);
        let mut state_root = None;
        let mut trials = DEFAULT_TRIALS;
        let mut warmup = DEFAULT_WARMUP;
        let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
        let mut host_kind = "unknown".to_owned();
        let mut output = None;
        let mut any = false;
        while let Some(a) = it.next() {
            if a == "--bench" {
                continue;
            }
            any = true;
            let name = a.as_str();
            let v = it.next().ok_or_else(|| format!("{name} needs a value"))?;
            match name {
                "--state-root" => state_root = Some(PathBuf::from(v)),
                "--trials" => trials = parse_range(name, &v, 50, 5000)?,
                "--warmup" => warmup = parse_range(name, &v, 0, 500)?,
                "--timeout-secs" => timeout_secs = parse_range(name, &v, 10, 7200)? as u64,
                "--host-kind" => {
                    if !matches!(v.as_str(), "bare-metal" | "vm" | "wsl2") {
                        return Err("--host-kind must be bare-metal, vm or wsl2".into());
                    }
                    host_kind = v;
                }
                "--output" => output = Some(PathBuf::from(v)),
                _ => return Err("unknown argument".into()),
            }
        }
        if !any {
            return Ok(Parsed::Smoke);
        }
        let state_root = state_root.ok_or("--state-root is required to measure")?;
        if !state_root.is_absolute() {
            return Err("--state-root must be an absolute path".into());
        }
        Ok(Parsed::Run(Args {
            state_root,
            trials,
            warmup,
            timeout: Duration::from_secs(timeout_secs),
            host_kind,
            output,
        }))
    }

    // ---- フェイクの実行層（副作用なし。ContainerRuntime / BundleProvider の最小実装）----

    struct FakeRuntime;

    impl ContainerRuntime for FakeRuntime {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::created(r.id().clone(), None))
        }
        fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::running(
                r.id().clone(),
                std::num::NonZeroU32::new(4242),
            ))
        }
        fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::stopped(r.id().clone(), Some(0)))
        }
        fn delete(&self, _r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            Ok(DeleteResponse::new())
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::created(r.id().clone(), None))
        }
    }

    struct FakeBundles;

    impl BundleProvider for FakeBundles {
        fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
            Ok(PreparedBundle::new(
                PathBuf::from("/bundles").join(req.container_id),
            ))
        }
        fn release(&self, _container_id: &str) -> Result<(), CriError> {
            Ok(())
        }
    }

    // ---- 記録器（ストアの put / remove の所要時間を受ける）----

    #[derive(Default)]
    struct Collector(Mutex<Vec<RecordStoreOpSample>>);

    impl RecordStoreOpRecorder for Collector {
        fn record_store_op(&self, sample: &RecordStoreOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*sample);
            }
        }
    }

    impl Collector {
        /// 溜まった標本を取り出す（RPC の計測区間の外で呼ぶ）。
        fn drain(&self) -> Vec<RecordStoreOpSample> {
            self.0
                .lock()
                .map(|mut v| std::mem::replace(&mut *v, Vec::with_capacity(16)))
                .unwrap_or_default()
        }
    }

    // ---- 1 構成分の計測器 ----

    struct Rig {
        service: CriRuntimeService,
        collector: Option<Arc<Collector>>,
        rpc: [Vec<Duration>; 7],
        /// (op, kind) ごとの記録器の所要時間。
        store_ops: BTreeMap<(&'static str, &'static str), Vec<Duration>>,
    }

    impl Rig {
        fn new(store_root: Option<&Path>, cap: usize) -> Result<Self, String> {
            let mut service = CriRuntimeService::new().with_runtime(
                RuntimeAdapter::new(Arc::new(FakeRuntime)),
                Arc::new(FakeBundles),
            );
            let mut collector = None;
            if let Some(root) = store_root {
                let c = Arc::new(Collector::default());
                let store = FileRecordStore::open(root)
                    .map_err(|_| "failed to open the record store".to_owned())?
                    .with_recorder(c.clone());
                service = service.with_record_store(Arc::new(store));
                collector = Some(c);
            }
            Ok(Self {
                service,
                collector,
                rpc: std::array::from_fn(|_| Vec::with_capacity(cap)),
                store_ops: BTreeMap::new(),
            })
        }

        /// RPC 1 回の後に、記録器への到達件数を期待値と照合し、所要時間を貯める。
        fn account(&mut self, idx: usize, elapsed: Duration, measure: bool) -> Result<(), String> {
            let samples = self.collector.as_ref().map(|c| c.drain());
            let name = RPCS.get(idx).copied().unwrap_or("?");
            let want = match (&samples, EXPECTED.get(idx)) {
                (Some(_), Some(e)) => *e,
                _ => (0, 0, 0, 0),
            };
            let got = samples.as_ref().map_or((0, 0, 0, 0), |s| {
                let count = |op, kind| s.iter().filter(|x| x.op == op && x.kind == kind).count();
                (
                    count(RecordStoreOp::Put, RecordKind::Sandbox),
                    count(RecordStoreOp::Remove, RecordKind::Sandbox),
                    count(RecordStoreOp::Put, RecordKind::Container),
                    count(RecordStoreOp::Remove, RecordKind::Container),
                )
            });
            if got != want {
                return Err(format!(
                    "store op count mismatch on {name}: got {got:?}, want {want:?}"
                ));
            }
            for x in samples.iter().flatten() {
                if x.outcome != RecordStoreOutcome::Ok {
                    return Err(format!("store op did not succeed on {name}"));
                }
                if measure {
                    let key = (x.op.as_str(), kind_name(x.kind));
                    self.store_ops.entry(key).or_default().push(x.latency);
                }
            }
            if measure && let Some(v) = self.rpc.get_mut(idx) {
                v.push(elapsed);
            }
            Ok(())
        }

        /// 1 試行（7 RPC）。`measure` が偽ならウォームアップ。
        async fn trial(&mut self, n: usize, measure: bool) -> Result<(), String> {
            let cfg = PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: format!("pod-{n}"),
                    uid: format!("uid-{n}"),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                ..Default::default()
            };
            let req = Request::new(v1::RunPodSandboxRequest {
                config: Some(cfg),
                runtime_handler: String::new(),
            });
            let t = Instant::now();
            let r = RuntimeService::run_pod_sandbox(&self.service, req).await;
            let el = t.elapsed();
            let sb = r
                .map_err(|_| "RunPodSandbox failed".to_owned())?
                .into_inner()
                .pod_sandbox_id;
            self.account(0, el, measure)?;

            let req = Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: sb.clone(),
                config: Some(ContainerConfig {
                    metadata: Some(ContainerMetadata {
                        name: format!("c-{n}"),
                        attempt: 0,
                    }),
                    image: Some(ImageSpec {
                        image: "busybox:1.36".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                sandbox_config: None,
            });
            let t = Instant::now();
            let r = RuntimeService::create_container(&self.service, req).await;
            let el = t.elapsed();
            let cid = r
                .map_err(|_| "CreateContainer failed".to_owned())?
                .into_inner()
                .container_id;
            self.account(1, el, measure)?;

            let req = Request::new(v1::StartContainerRequest {
                container_id: cid.clone(),
            });
            let t = Instant::now();
            let r = RuntimeService::start_container(&self.service, req).await;
            let el = t.elapsed();
            r.map_err(|_| "StartContainer failed".to_owned())?;
            self.account(2, el, measure)?;

            let req = Request::new(v1::StopContainerRequest {
                container_id: cid.clone(),
                timeout: 0,
            });
            let t = Instant::now();
            let r = RuntimeService::stop_container(&self.service, req).await;
            let el = t.elapsed();
            r.map_err(|_| "StopContainer failed".to_owned())?;
            self.account(3, el, measure)?;

            let req = Request::new(v1::RemoveContainerRequest { container_id: cid });
            let t = Instant::now();
            let r = RuntimeService::remove_container(&self.service, req).await;
            let el = t.elapsed();
            r.map_err(|_| "RemoveContainer failed".to_owned())?;
            self.account(4, el, measure)?;

            let req = Request::new(v1::StopPodSandboxRequest {
                pod_sandbox_id: sb.clone(),
            });
            let t = Instant::now();
            let r = RuntimeService::stop_pod_sandbox(&self.service, req).await;
            let el = t.elapsed();
            r.map_err(|_| "StopPodSandbox failed".to_owned())?;
            self.account(5, el, measure)?;

            let req = Request::new(v1::RemovePodSandboxRequest { pod_sandbox_id: sb });
            let t = Instant::now();
            let r = RuntimeService::remove_pod_sandbox(&self.service, req).await;
            let el = t.elapsed();
            r.map_err(|_| "RemovePodSandbox failed".to_owned())?;
            self.account(6, el, measure)?;
            Ok(())
        }
    }

    fn kind_name(k: RecordKind) -> &'static str {
        match k {
            RecordKind::Sandbox => "sandbox",
            RecordKind::Container => "container",
        }
    }

    // ---- 統計（nearest-rank。benches/src/startup_latency/stats.rs と同じ算式）----

    fn sorted(samples: &[Duration]) -> Vec<Duration> {
        let mut s = samples.to_vec();
        s.sort();
        s
    }

    fn pct(s: &[Duration], p: u64) -> Option<Duration> {
        let n = u64::try_from(s.len()).ok()?;
        let rank = n.checked_mul(p)?.div_ceil(100);
        s.get(usize::try_from(rank.checked_sub(1)?).ok()?).copied()
    }

    fn ns(d: Duration) -> u64 {
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
    }

    /// 標本の要約（ns）。空なら null。
    fn summary(samples: &[Duration]) -> Value {
        let s = sorted(samples);
        match (pct(&s, 50), pct(&s, 95), s.last()) {
            (Some(p50), Some(p95), Some(max)) => json!({
                "samples": s.len(), "p50_ns": ns(p50), "p95_ns": ns(p95), "max_ns": ns(*max),
            }),
            _ => Value::Null,
        }
    }

    fn pn(samples: &[Duration], q: u64) -> i64 {
        pct(&sorted(samples), q).map_or(0, |d| i64::try_from(ns(d)).unwrap_or(i64::MAX))
    }

    // ---- ホスト情報 ----

    fn read_capped(path: &str, cap: u64) -> Option<String> {
        let mut s = String::new();
        fs::File::open(path)
            .ok()?
            .take(cap)
            .read_to_string(&mut s)
            .ok()?;
        Some(s)
    }

    /// 状態ルートを含む最も長いマウントの fstype。取れなければ "unknown"。
    fn fs_type(root: &Path) -> String {
        let Ok(root) = fs::canonicalize(root) else {
            return "unknown".into();
        };
        let Some(text) = read_capped("/proc/self/mountinfo", 1 << 20) else {
            return "unknown".into();
        };
        let mut best: Option<(usize, String)> = None;
        for line in text.lines().take(4096) {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let (Some(mount), Some(fstype)) = (pre.split(' ').nth(4), post.split(' ').next())
            else {
                continue;
            };
            if root.starts_with(mount) && best.as_ref().is_none_or(|(l, _)| mount.len() > *l) {
                best = Some((mount.len(), fstype.to_owned()));
            }
        }
        best.map_or_else(|| "unknown".into(), |(_, t)| t)
    }

    // ---- 作業ディレクトリ（自分が作った子だけを消す）----

    struct Work(PathBuf);

    impl Drop for Work {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_work(root: &Path) -> Result<Work, String> {
        let meta = fs::metadata(root).map_err(|_| "--state-root does not exist".to_owned())?;
        if !meta.is_dir() {
            return Err("--state-root is not a directory".into());
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = root.join(format!("cri-record-bench-{}-{nanos}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| "failed to create the work directory".to_owned())?;
        Ok(Work(dir))
    }

    // ---- 副: put / remove の直接計測 ----

    fn micro(root: &Path, n: usize) -> Result<Value, String> {
        let store = FileRecordStore::open(root)
            .map_err(|_| "failed to open the record store".to_owned())?;
        let mut out = Vec::new();
        for size in [1024usize, 4096] {
            let bytes = vec![b'x'; size];
            let (mut puts, mut removes) = (Vec::with_capacity(n), Vec::with_capacity(n));
            for i in 0..n {
                let id = RecordId::new(&format!("{i:064x}"))
                    .map_err(|_| "invalid micro id".to_owned())?;
                let t = Instant::now();
                let r = store.put(RecordKind::Container, &id, &bytes);
                let el = t.elapsed();
                r.map_err(|_| "micro put failed".to_owned())?;
                puts.push(el);
                let t = Instant::now();
                let r = store.remove(RecordKind::Container, &id);
                let el = t.elapsed();
                r.map_err(|_| "micro remove failed".to_owned())?;
                removes.push(el);
            }
            out.push(json!({ "bytes": size, "put": summary(&puts), "remove": summary(&removes) }));
        }
        Ok(Value::Array(out))
    }

    // ---- 全体 ----

    fn measure(args: &Args) -> Result<Value, String> {
        let work = make_work(&args.state_root)?;
        let total = args.trials + args.warmup;
        let mut without = Rig::new(None, args.trials)?;
        let mut with = Rig::new(Some(&work.0), args.trials)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|_| "failed to build the runtime".to_owned())?;
        let started = Instant::now();
        for n in 0..total {
            if started.elapsed() > args.timeout {
                return Err("overall deadline exceeded".into());
            }
            let m = n >= args.warmup;
            // 時間による偏りを打ち消すため、試行ごとに構成の順序を入れ替える。
            if n % 2 == 0 {
                rt.block_on(without.trial(n, m))?;
                rt.block_on(with.trial(n, m))?;
            } else {
                rt.block_on(with.trial(n, m))?;
                rt.block_on(without.trial(n, m))?;
            }
        }
        let rpcs: Vec<Value> = RPCS
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let a = without.rpc.get(i).map_or(&[][..], |v| v.as_slice());
                let b = with.rpc.get(i).map_or(&[][..], |v| v.as_slice());
                json!({
                    "rpc": name,
                    "without_store": summary(a),
                    "with_store": summary(b),
                    "diff_p50_ns": pn(b, 50) - pn(a, 50),
                    "diff_p95_ns": pn(b, 95) - pn(a, 95),
                })
            })
            .collect();
        let store_ops: Vec<Value> = with
            .store_ops
            .iter()
            .map(|((op, kind), v)| json!({ "op": op, "kind": kind, "stats": summary(v) }))
            .collect();
        let direct = micro(&work.0, args.trials.min(500))?;
        let kernel = read_capped("/proc/sys/kernel/osrelease", 256)
            .map_or_else(|| "unknown".into(), |s| s.trim().to_owned());
        Ok(json!({
            "schema_version": 1,
            "bench": BENCH,
            "method": "fake ContainerRuntime/BundleProvider; RPC latency around .await; tmp fsync+rename+dir fsync via FileRecordStore",
            "provisional": true,
            "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "trials": args.trials,
            "warmup": args.warmup,
            "host": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "kernel": kernel,
                "fs_type": fs_type(&work.0),
                "host_kind": args.host_kind,
            },
            "expected_store_ops_per_trial": {
                "sandbox_put": 2, "sandbox_remove": 1, "container_put": 4, "container_remove": 1,
            },
            "rpcs": rpcs,
            "store_ops": store_ops,
            "store_direct": direct,
        }))
    }

    pub fn run() -> i32 {
        let args = match parse_args() {
            Ok(Parsed::Smoke) => {
                println!(
                    "{}",
                    json!({"bench": BENCH, "measured": false, "reason": "smoke; pass --state-root <dir> to measure"})
                );
                return 0;
            }
            Ok(Parsed::Run(a)) => a,
            Err(m) => return fail("invalid_argument", &m),
        };
        let doc = match measure(&args) {
            Ok(d) => d,
            Err(m) => return fail("bench_failed", &m),
        };
        let text = doc.to_string();
        if let Some(path) = &args.output {
            let res = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut f| f.write_all(text.as_bytes()));
            if res.is_err() {
                return fail("output_failed", "failed to create the output file");
            }
        }
        println!("{text}");
        0
    }
}
