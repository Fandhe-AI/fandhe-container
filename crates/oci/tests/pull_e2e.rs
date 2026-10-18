//! 公開 OCI イメージの pull・digest 検証・展開・rootfs 実行を一括で自動検証するハーネス
//! （OCI-1・MS-4。TASK-55.1・#420。親は TASK-55・#419、実際の 3 種以上の実行とレポートは TASK-55.2・#421）。
//!
//! イメージ参照のリストを与えると、各イメージについて次を順に行い、結果を 1 イメージ 1 行の JSON
//! （REPAIR-4。トークン・URL は出さない）と要約行で報告する。1 件でも失敗すれば非 0 で終了する（fail-closed）。
//!
//! 1. 匿名認証 → manifest 取得（image index は host の linux platform へ解決）→ config と全レイヤーの取得
//! 2. 全 blob の digest 検証（`layer::verify_fetched_blob`。検証前のファイルは展開・パースしない）
//! 3. レイヤーの展開（`layer::extract::extract_layer_blobs`。whiteout 統合済み。パス検証・hardlink 制限は
//!    oci 側に任せ、ハーネスで緩めない）→ `proc`/`dev`/`sys` の補完 → image config から `config.json` を生成
//! 4. TASK-29 の `create` → `start`（本番 `ProductionLauncher`）で実行し、終了コード 0 を確認
//!
//! # 入力
//! - `--image <ref> [--cmd <arg>...]` を繰り返す。`--cmd` はそのイメージの Cmd を置き換える（Entrypoint は残す。
//!   Docker と同じ意味）。`--work-dir <dir>` で作業ディレクトリの親を指定する（既定は `std::env::temp_dir()`）
//! - 環境変数 `FANDHE_CONTAINER_PULL_E2E_IMAGES`（改行区切り。1 行が `<ref>` または `<ref> -- <arg>...`）。
//!   `--image` が 1 つも無いときだけ読む
//! - どちらも無ければ既定のリスト（alpine〔単一レイヤー〕・debian:bookworm-slim・nginx:alpine〔複数レイヤー〕）
//! - 件数・引数の数・1 引数の長さに上限がある。`ImageReference::parse` を通らない参照は通信前に引数エラー（exit 2）
//! - `process.args[0]` は絶対パスが必要（start が PATH 探索を未実装のため）。`bash` のような Cmd のイメージは
//!   `--cmd /bin/true` のように絶対パスで上書きする
//!
//! # 出力
//! イメージごとに 1 行: `{"image","manifest_digest","from_index","layers","config_bytes","layer_bytes",
//! "stripped_special_bits","durations_ms":{auth,manifest,blobs,verify,extract,run},"exit":{"kind","code"},
//! "stage_failed","error_code","outcome"}`（失敗時は `stdout_tail`/`stderr_tail` を足す）。最終行は
//! `pull_e2e: N/N images pulled, verified, extracted and exited 0`。失敗時は `pull_e2e: FAILED k/N images failed`。
//! 終了コードは 0 = 全件成功、1 = 1 件以上失敗または前提不足、2 = 引数エラー。
//!
//! # 既定のテスト集合で動く部分（REPAIR-12）
//! `--ignored` が無いときは通信も実行もせず、オフラインの自己検証（引数の解釈、image config からの argv / env の
//! 算出、ローカルで作った 2 レイヤーの digest 検証 → 展開 → bundle 生成）だけを具体値で照合し、`ignored` の行を
//! 出して成功終了する。
//!
//! # 必要環境（実機前提テスト。`-- --ignored` 指定時のみ実行）
//! - Linux 6.12 以上（Landlock ABI 6 以上）・非 root・非特権 user namespace・委譲された cgroup v2 サブツリー
//!   （`core` の `production_launcher` と同じ。実行方法は同じく `systemd-run --user --scope -p Delegate=yes`）
//! - registry-1.docker.io への外向き HTTPS（匿名 pull。Docker Hub のレート制限で失敗しうる）
//! - exec 可能で十分な空きのある作業ディレクトリ
//!
//! 前提が満たされない場合も失敗として扱い、検証せずに成功する分岐は持たない。GitHub ホステッド runner では
//! 保証できないため CI には組み込まない（ci.md「実機前提テスト」）。
//!
//! ```text
//! cargo test -p fandhe-container-oci --test pull_e2e --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/pull_e2e-XXXX> --ignored \
//!   [--image alpine] [--image debian:bookworm-slim --cmd /bin/true] [--work-dir <dir>]
//! ```
//!
//! 待ちの期限は `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 30 秒・最大 295 秒）。pull 側の期限は
//! `RegistryClientConfig` の既定値（REPAIR-5）。
//!
//! # 既知の制約（REPAIR-3）
//! - uid / gid の写像（SEC-5）と setuid ビットの保持は未実装。image config の `User` と `WorkingDir` は無視し、
//!   コンテナ内 root・cwd `/` で実行する（start が cwd `/` 以外を拒否するため）
//! - manifest の `diff_id` の検証は未実装（config blob と各レイヤーの digest のみ）
//! - gzip 以外（zstd・無圧縮）のレイヤーは `UNIMPLEMENTED` として失敗にする
//! - stdin は `/dev/null` に置き換わるため、対話シェルを Cmd にしたイメージは EOF で終了する
//! - 展開時にデバイス・FIFO・hardlink 制限等で失敗するイメージは、ハーネスで回避せず #421 の所見として記録する
//! - ステージング・リース・公開の意味づけ（TASK-183・OCI-7）は対象外。pull の部品を公開 API のまま組み合わせるだけ
//! - `oci` が `core` に dev 依存する辺（`docs/architecture.md`）。将来 `core` が `oci` に通常依存すると dev 循環に
//!   なるため、その時はこのハーネスの置き場所を見直す

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pull_e2e: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("pull_e2e: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    linux::main();
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::collections::VecDeque;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::{CgroupName, ContainerCgroup, DelegatedCgroup};
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ProcessExit, ProcessLauncher, ProductionLauncher, StartTimeouts, create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{ContainerId, CreateRequest, StartRequest, TraitError};
    use fandhe_container_oci::error::{OciError, OciErrorCode};
    use fandhe_container_oci::layer::extract::{ExtractLimits, extract_layer_blobs};
    use fandhe_container_oci::layer::{
        DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, verify_blob_digest, verify_fetched_blob,
    };
    use fandhe_container_oci::manifest::Platform;
    use fandhe_container_oci::reference::ImageReference;
    use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};
    use serde_json::{Value, json};

    /// 既定のイメージ（`--image` も環境変数も無いとき）。最終的な選定は #421（TASK-55.2）で行う。
    const DEFAULT_IMAGES: &[(&str, &[&str])] = &[
        ("alpine", &[]),
        ("debian:bookworm-slim", &["/bin/true"]),
        ("nginx:alpine", &["/usr/sbin/nginx", "-v"]),
    ];
    const IMAGES_ENV: &str = "FANDHE_CONTAINER_PULL_E2E_IMAGES";
    /// 1 回に扱うイメージ数の上限。
    const MAX_IMAGES: usize = 32;
    /// `--cmd` の引数の数の上限。
    const MAX_CMD_ARGS: usize = 64;
    /// 1 つの引数（参照・Cmd 要素・パス）の最大バイト数。
    const MAX_ARG_BYTES: usize = 4096;
    /// image config blob の許容最大バイト数。
    const CONFIG_MAX_BYTES: u64 = 1024 * 1024;
    /// image config の配列（Entrypoint / Cmd / Env）の要素数の上限。
    const CONFIG_ARRAY_MAX: usize = 4096;
    /// 失敗診断のためにコンテナ出力の末尾から残す最大バイト数。
    const TAIL_BYTES: usize = 1024;
    /// image config が PATH を持たないときの既定値。
    const DEFAULT_PATH_ENV: &str =
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    /// 受け付ける gzip レイヤーの mediaType。
    const GZIP_LAYER_TYPES: &[&str] = &[
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    ];

    // ----- 失敗の表現 --------------------------------------------------------------------------------------

    /// 失敗した段と機械可読な code（ERR-1）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Failure {
        stage: &'static str,
        code: String,
    }

    impl Failure {
        fn new(stage: &'static str, code: &str) -> Self {
            Self {
                stage,
                code: code.to_string(),
            }
        }

        fn oci(stage: &'static str, e: &OciError) -> Self {
            Self::new(stage, e.code().as_str())
        }

        fn core(stage: &'static str, code: impl std::fmt::Debug) -> Self {
            // `PermissionDenied` -> `PERMISSION_DENIED`（oci 側の code 文字列と語彙を揃える。ERR-1）。
            let mut out = String::new();
            for (i, c) in format!("{code:?}").chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_uppercase());
            }
            Self { stage, code: out }
        }
    }

    // ----- 引数の解釈 --------------------------------------------------------------------------------------

    /// 検証対象のイメージ 1 件。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ImageSpec {
        reference: String,
        cmd_override: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RunArgs {
        images: Vec<ImageSpec>,
        work_dir: Option<PathBuf>,
    }

    fn check_arg(s: &str) -> Result<(), String> {
        if s.len() > MAX_ARG_BYTES {
            return Err(format!("argument exceeds {MAX_ARG_BYTES} bytes"));
        }
        if s.contains('\0') {
            return Err("argument contains NUL".to_string());
        }
        Ok(())
    }

    fn make_spec(reference: &str, cmd: Option<Vec<String>>) -> Result<ImageSpec, String> {
        check_arg(reference)?;
        ImageReference::parse(reference)
            .map_err(|e| format!("invalid image reference ({})", e.code().as_str()))?;
        if let Some(c) = &cmd {
            if c.is_empty() {
                return Err("--cmd needs at least one argument".to_string());
            }
            if c.len() > MAX_CMD_ARGS {
                return Err(format!("--cmd exceeds {MAX_CMD_ARGS} arguments"));
            }
            for a in c {
                check_arg(a)?;
            }
        }
        Ok(ImageSpec {
            reference: reference.to_string(),
            cmd_override: cmd,
        })
    }

    /// コマンドライン引数（argv[0] を除く）と環境変数の値から実行内容を決める。
    fn parse_args(argv: &[String], env_images: Option<&str>) -> Result<RunArgs, String> {
        let mut images: Vec<ImageSpec> = Vec::new();
        let mut work_dir: Option<PathBuf> = None;
        let mut i = 0usize;
        while let Some(arg) = argv.get(i) {
            match arg.as_str() {
                "--ignored" | "--nocapture" => i += 1,
                "--work-dir" => {
                    let v = argv.get(i + 1).ok_or("--work-dir needs a value")?;
                    check_arg(v)?;
                    if work_dir.replace(PathBuf::from(v)).is_some() {
                        return Err("--work-dir given twice".to_string());
                    }
                    i += 2;
                }
                "--image" => {
                    let v = argv.get(i + 1).ok_or("--image needs a value")?;
                    i += 2;
                    let mut cmd: Option<Vec<String>> = None;
                    if argv.get(i).map(String::as_str) == Some("--cmd") {
                        i += 1;
                        let mut c = Vec::new();
                        while let Some(a) = argv.get(i) {
                            if matches!(
                                a.as_str(),
                                "--image" | "--work-dir" | "--ignored" | "--nocapture"
                            ) {
                                break;
                            }
                            c.push(a.clone());
                            i += 1;
                        }
                        cmd = Some(c);
                    }
                    images.push(make_spec(v, cmd)?);
                    if images.len() > MAX_IMAGES {
                        return Err(format!("more than {MAX_IMAGES} images"));
                    }
                }
                "--cmd" => return Err("--cmd must directly follow --image".to_string()),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        if images.is_empty()
            && let Some(text) = env_images
        {
            {
                for line in text.lines() {
                    let mut words = line.split_whitespace();
                    let Some(reference) = words.next() else {
                        continue;
                    };
                    let rest: Vec<String> = match words.next() {
                        None => Vec::new(),
                        Some("--") => words.map(str::to_string).collect(),
                        Some(_) => {
                            return Err(format!("{IMAGES_ENV}: expected `<ref> -- <arg>...`"));
                        }
                    };
                    let cmd = if rest.is_empty() { None } else { Some(rest) };
                    images.push(make_spec(reference, cmd)?);
                    if images.len() > MAX_IMAGES {
                        return Err(format!("more than {MAX_IMAGES} images"));
                    }
                }
            }
        }
        if images.is_empty() {
            for (r, c) in DEFAULT_IMAGES {
                let cmd = (!c.is_empty()).then(|| c.iter().map(|s| (*s).to_string()).collect());
                images.push(make_spec(r, cmd)?);
            }
        }
        Ok(RunArgs { images, work_dir })
    }

    // ----- image config から実行内容を作る ------------------------------------------------------------------

    /// image config（OCI image config の `config` オブジェクト）の必要部分。
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    struct ImageConfig {
        entrypoint: Vec<String>,
        cmd: Vec<String>,
        env: Vec<String>,
    }

    /// `config.json` に写す実行内容。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Process {
        args: Vec<String>,
        env: Vec<String>,
    }

    fn parse_image_config(bytes: &[u8]) -> Result<ImageConfig, Failure> {
        let bad = || Failure::new("config", "DATA_LOSS");
        let v: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
        let cfg = v.get("config");
        let strings = |key: &str| -> Result<Vec<String>, Failure> {
            match cfg.and_then(|c| c.get(key)) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(a)) => {
                    if a.len() > CONFIG_ARRAY_MAX {
                        return Err(Failure::new("config", "RESOURCE_EXHAUSTED"));
                    }
                    a.iter()
                        .map(|x| x.as_str().map(str::to_string).ok_or_else(bad))
                        .collect()
                }
                Some(_) => Err(bad()),
            }
        };
        Ok(ImageConfig {
            entrypoint: strings("Entrypoint")?,
            cmd: strings("Cmd")?,
            env: strings("Env")?,
        })
    }

    /// Entrypoint ++ (override または Cmd)。Env に PATH が無ければ既定値を足す。
    fn derive_process(
        cfg: &ImageConfig,
        cmd_override: Option<&[String]>,
    ) -> Result<Process, Failure> {
        let mut args = cfg.entrypoint.clone();
        match cmd_override {
            Some(c) => args.extend(c.iter().cloned()),
            None => args.extend(cfg.cmd.iter().cloned()),
        }
        let Some(first) = args.first() else {
            return Err(Failure::new("config", "INVALID_ARGUMENT"));
        };
        if !first.starts_with('/') {
            // start は PATH 探索を未実装で、args[0] が絶対パスでなければ拒否する。
            return Err(Failure::new("config", "INVALID_ARGUMENT"));
        }
        let mut env = cfg.env.clone();
        if env.iter().any(|e| !e.contains('=')) {
            return Err(Failure::new("config", "DATA_LOSS"));
        }
        if !env.iter().any(|e| e.starts_with("PATH=")) {
            env.push(DEFAULT_PATH_ENV.to_string());
        }
        Ok(Process { args, env })
    }

    // ----- 展開後の bundle 生成 ----------------------------------------------------------------------------

    fn mkdir_mode(path: &Path, mode: u32) -> std::io::Result<()> {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    /// rootfs 直下の固定名のマウント先を補う。既に在る場合はディレクトリであることだけ確認する（symlink は辿らない）。
    fn ensure_mountpoints(rootfs: &Path) -> Result<Vec<&'static str>, Failure> {
        let mut created = Vec::new();
        for name in ["proc", "dev", "sys"] {
            let p = rootfs.join(name);
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Err(Failure::new("extract", "FAILED_PRECONDITION")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    mkdir_mode(&p, 0o755).map_err(|_| Failure::new("extract", "INTERNAL"))?;
                    created.push(name);
                }
                Err(_) => return Err(Failure::new("extract", "INTERNAL")),
            }
        }
        Ok(created)
    }

    const HOSTNAME: &str = "fandhe-pull-e2e";

    fn write_config(bundle: &Path, process: &Process) -> Result<(), Failure> {
        let config = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": false},
            "hostname": HOSTNAME,
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": process.args,
                "env": process.env,
                "cwd": "/"
            },
            "mounts": [],
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
            ]}
        });
        let bytes = serde_json::to_vec(&config).map_err(|_| Failure::new("config", "INTERNAL"))?;
        std::fs::write(bundle.join("config.json"), bytes)
            .map_err(|_| Failure::new("config", "INTERNAL"))
    }

    /// 検証済みレイヤー blob（下位から順）を `bundle/rootfs` へ展開し、マウント先の補完と `config.json` を作る。
    /// 実 pull と、ローカルのレイヤーによる自己検証が共有する。戻り値は (展開所要, 落とした特殊ビット数)。
    fn extract_and_finalize(
        blobs: &[PathBuf],
        bundle: &Path,
        process: &Process,
    ) -> Result<(Duration, u64), Failure> {
        let rootfs = bundle.join("rootfs");
        let t = Instant::now();
        let refs: Vec<&Path> = blobs.iter().map(PathBuf::as_path).collect();
        let layers = extract_layer_blobs(
            &refs,
            &rootfs,
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            ExtractLimits::default(),
        )
        .map_err(|e| Failure::oci("extract", &e))?;
        let stripped: u64 = layers
            .iter()
            .map(|l| l.files_with_stripped_special_bits)
            .sum();
        ensure_mountpoints(&rootfs)?;
        let took = t.elapsed();
        write_config(bundle, process)?;
        Ok((took, stripped))
    }

    // ----- 後始末 ------------------------------------------------------------------------------------------

    /// 書き込み不可のディレクトリを含む展開物を消せるよう、symlink を辿らずに権限を戻す。
    fn make_removable(path: &Path, depth: u32) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if !meta.is_dir() || depth > 512 {
            return;
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(rd) = std::fs::read_dir(path) {
            for entry in rd.flatten() {
                make_removable(&entry.path(), depth + 1);
            }
        }
    }

    /// 後始末（作業ディレクトリ・cgroup の削除）に失敗した件数。残置物があれば終了コードを非ゼロにする。
    static CLEANUP_FAILURES: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    fn record_cleanup_failure() {
        CLEANUP_FAILURES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn cleanup_failures() -> usize {
        CLEANUP_FAILURES.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 削除に失敗したら件数へ計上し、手動回収に必要な場所を出力する。
    fn force_remove(path: &Path) {
        make_removable(path, 0);
        if let Err(e) = std::fs::remove_dir_all(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            record_cleanup_failure();
            eprintln!(
                "pull_e2e: FAILED cleanup: could not remove work directory {} ({:?}); remove it manually",
                path.display(),
                e.kind()
            );
        }
    }

    /// drop で削除する、自分専用の作業ディレクトリ。`create_dir` で排他的に作り、既存パスを再利用しない。
    struct WorkDir {
        dir: PathBuf,
    }

    impl WorkDir {
        fn new(base: &Path, tag: &str) -> Result<Self, Failure> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let base =
                std::fs::canonicalize(base).map_err(|_| Failure::new("setup", "NOT_FOUND"))?;
            let dir = base.join(format!(
                "fandhe-pull-e2e-{tag}-{}-{nanos}",
                std::process::id()
            ));
            mkdir_mode(&dir, 0o700).map_err(|_| Failure::new("setup", "INTERNAL"))?;
            Ok(Self { dir })
        }
    }

    impl Drop for WorkDir {
        fn drop(&mut self) {
            force_remove(&self.dir);
        }
    }

    // ----- /proc の観測 ------------------------------------------------------------------------------------

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s >= 1)
            .map_or(30, |s| s.min(295));
        Duration::from_secs(secs)
    }

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    fn is_root() -> bool {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn children_of_self() -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
            for t in tasks.flatten() {
                if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                    out.extend(s.split_whitespace().map(str::to_string));
                }
            }
        }
        out
    }

    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork の前提）。
    fn wait_single_thread() -> bool {
        eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1"))
    }

    // ----- 実行段（TASK-29） -------------------------------------------------------------------------------

    struct MemSink(std::sync::Mutex<Vec<String>>);

    impl AuditSink for MemSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{record:?}"));
            Ok(())
        }
    }

    /// 子の出力を最後まで読み捨てる。末尾 `TAIL_BYTES` だけを残して送る（パイプを詰まらせない）。
    fn spawn_drain(
        mut src: Box<dyn std::io::Read + Send>,
    ) -> (mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut tail: VecDeque<u8> = VecDeque::with_capacity(TAIL_BYTES + 8192);
            let mut buf = vec![0u8; 8192];
            loop {
                match src.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Some(chunk) = buf.get(..n) {
                            tail.extend(chunk.iter().copied());
                        }
                        while tail.len() > TAIL_BYTES {
                            tail.pop_front();
                        }
                    }
                }
            }
            let bytes: Vec<u8> = tail.into_iter().collect();
            let _ = tx.send(String::from_utf8_lossy(&bytes).into_owned());
        });
        (rx, handle)
    }

    /// 実行段の結果。
    #[derive(Debug, Default)]
    struct RunResult {
        kind: &'static str,
        code: Option<i32>,
        failure: Option<Failure>,
        stdout_tail: String,
        stderr_tail: String,
        /// 以降のコンテナを起動してはいけない（子・スレッドの後始末を確認できなかった）。
        abort_rest: bool,
    }

    struct RunEnv {
        store: FileStateStore,
        launcher: Arc<dyn ProcessLauncher>,
        recorder: OpRecorder,
        tag: u32,
    }

    fn start_timeouts() -> Option<StartTimeouts> {
        let t = timeout();
        StartTimeouts::new(t, t, t).ok()
    }

    /// `create` → `start` → 出力の読み捨て → `wait`。期限切れは terminate して回収する。
    fn run_container(env: &RunEnv, idx: usize, bundle: &Path) -> RunResult {
        let mut res = RunResult {
            kind: "not_started",
            ..RunResult::default()
        };
        let fail = |res: &mut RunResult, f: Failure| {
            res.failure = Some(f);
        };
        let Some(timeouts) = start_timeouts() else {
            fail(&mut res, Failure::new("run", "INVALID_ARGUMENT"));
            return res;
        };
        let Ok(id) = ContainerId::new(format!("pe{}i{idx}", env.tag)) else {
            fail(&mut res, Failure::new("run", "INVALID_ARGUMENT"));
            return res;
        };
        let Ok(req) = CreateRequest::new(id.clone(), bundle.to_path_buf()) else {
            fail(&mut res, Failure::new("run", "INVALID_ARGUMENT"));
            return res;
        };
        if let Err(e) = create(&env.store, &env.recorder, &req) {
            fail(&mut res, Failure::core("run", e.code()));
            return res;
        }
        if !wait_single_thread() {
            fail(&mut res, Failure::new("run", "FAILED_PRECONDITION"));
            res.abort_rest = true;
            return res;
        }
        let started = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id),
            &timeouts,
        ) {
            Ok(s) => s,
            Err(e) => {
                fail(&mut res, Failure::core("run", e.code()));
                // start はプロセスを回収できないときも Err を返す（CORE-2）。残存を確認できなければ
                // 後続の起動と bundle の削除前提の進行を止める。
                if !eventually(|| children_of_self().is_empty()) {
                    res.abort_rest = true;
                }
                return res;
            }
        };
        let (_record, process) = started.into_parts();
        let pid = process.pid();
        let output = process.take_output();
        let (mut out_rx, mut err_rx, mut handles) = (None, None, Vec::new());
        if let Some(o) = output {
            if let Some(s) = o.stdout {
                let (rx, h) = spawn_drain(s);
                out_rx = Some(rx);
                handles.push(h);
            }
            if let Some(s) = o.stderr {
                let (rx, h) = spawn_drain(s);
                err_rx = Some(rx);
                handles.push(h);
            }
        }
        match process.wait(timeout()) {
            Ok(Some(ProcessExit::Exited(code))) => {
                res.kind = "exited";
                res.code = Some(code);
                if code != 0 {
                    fail(&mut res, Failure::new("run", "NONZERO_EXIT"));
                }
            }
            Ok(Some(ProcessExit::Signaled(sig))) => {
                res.kind = "signaled";
                res.code = Some(sig);
                fail(&mut res, Failure::new("run", "SIGNALED"));
            }
            Ok(Some(_)) => {
                res.kind = "exited";
                fail(&mut res, Failure::new("run", "UNKNOWN_EXIT"));
            }
            Ok(None) => {
                res.kind = "timeout";
                fail(&mut res, Failure::new("run", "TIMEOUT"));
                if process.terminate(timeout()).is_err() {
                    res.abort_rest = true;
                }
            }
            Err(e) => {
                res.kind = "wait_error";
                fail(&mut res, Failure::core("run", e.code()));
                if process.terminate(timeout()).is_err() {
                    res.abort_rest = true;
                }
            }
        }
        // 出力パイプは PID 1 の終了（PID namespace の解体）で EOF になる。期限内に読み終えられなければ
        // スレッドが残るため、以降の起動は行わない。
        let mut collect_failed = false;
        let mut collect = |rx: Option<mpsc::Receiver<String>>| -> String {
            match rx {
                Some(rx) => rx.recv_timeout(timeout()).unwrap_or_else(|_| {
                    res.abort_rest = true;
                    collect_failed = true;
                    String::new()
                }),
                None => String::new(),
            }
        };
        let (so, se) = (collect(out_rx), collect(err_rx));
        res.stdout_tail = so;
        res.stderr_tail = se;
        if collect_failed && res.failure.is_none() {
            fail(&mut res, Failure::new("run", "OUTPUT_COLLECT_FAILED"));
        }
        if !res.abort_rest {
            for h in handles {
                let _ = h.join();
            }
        }
        if !eventually(|| !Path::new(&format!("/proc/{pid}")).exists())
            || !eventually(|| children_of_self().is_empty())
        {
            res.abort_rest = true;
            if res.failure.is_none() {
                fail(&mut res, Failure::new("run", "LEAKED_PROCESS"));
            }
        }
        res
    }

    // ----- 1 イメージの処理 --------------------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct Report {
        manifest_digest: Option<String>,
        from_index: Option<bool>,
        layers: usize,
        config_bytes: u64,
        layer_bytes: u64,
        stripped: u64,
        auth_ms: u64,
        manifest_ms: u64,
        blobs_ms: u64,
        verify_ms: u64,
        extract_ms: u64,
        run_ms: u64,
        exit_kind: &'static str,
        exit_code: Option<i32>,
        failure: Option<Failure>,
        stdout_tail: String,
        stderr_tail: String,
    }

    fn ms(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    impl Report {
        fn ok(&self) -> bool {
            self.failure.is_none() && self.exit_kind == "exited" && self.exit_code == Some(0)
        }

        fn to_json(&self, image: &str) -> Value {
            let mut v = json!({
                "image": image,
                "manifest_digest": self.manifest_digest,
                "from_index": self.from_index,
                "layers": self.layers,
                "config_bytes": self.config_bytes,
                "layer_bytes": self.layer_bytes,
                "stripped_special_bits": self.stripped,
                "durations_ms": {
                    "auth": self.auth_ms, "manifest": self.manifest_ms, "blobs": self.blobs_ms,
                    "verify": self.verify_ms, "extract": self.extract_ms, "run": self.run_ms,
                },
                "exit": {"kind": self.exit_kind, "code": self.exit_code},
                "stage_failed": self.failure.as_ref().map(|f| f.stage),
                "error_code": self.failure.as_ref().map(|f| f.code.clone()),
                "outcome": if self.ok() { "ok" } else { "fail" },
            });
            if !self.ok()
                && let Some(obj) = v.as_object_mut()
            {
                obj.insert("stdout_tail".to_string(), json!(self.stdout_tail));
                obj.insert("stderr_tail".to_string(), json!(self.stderr_tail));
            }
            v
        }
    }

    /// pull → 検証 → 展開 → bundle 生成。`client` は呼び出し側が drop してから起動する。
    fn pull_and_prepare(
        spec: &ImageSpec,
        blobs_dir: &Path,
        bundle: &Path,
        r: &mut Report,
    ) -> Result<(), Failure> {
        let reference =
            ImageReference::parse(&spec.reference).map_err(|e| Failure::oci("auth", &e))?;
        let platform = Platform::host().map_err(|e| Failure::oci("manifest", &e))?;
        let client = RegistryClient::new(&RegistryClientConfig::default())
            .map_err(|e| Failure::oci("auth", &e))?;
        let endpoint = RegistryEndpoint::new(reference.registry().clone());

        let t = Instant::now();
        let auth = client
            .authenticate_anonymous(&endpoint, reference.repository())
            .map_err(|e| Failure::oci("auth", &e))?;
        r.auth_ms = ms(t.elapsed());

        let t = Instant::now();
        let resolved = client
            .fetch_manifest(
                &endpoint,
                reference.repository(),
                reference.reference(),
                &auth,
                &platform,
            )
            .map_err(|e| Failure::oci("manifest", &e))?;
        r.manifest_ms = ms(t.elapsed());
        r.manifest_digest = Some(resolved.manifest_digest.as_str().to_string());
        r.from_index = Some(resolved.from_index);
        r.layers = resolved.manifest.layers.len();
        // 未対応の圧縮は通信の前に失敗にする（実装済みを装わない。REPAIR-3）。
        if resolved
            .manifest
            .layers
            .iter()
            .any(|l| !GZIP_LAYER_TYPES.contains(&l.media_type.as_str()))
        {
            return Err(Failure::new(
                "extract",
                OciErrorCode::Unimplemented.as_str(),
            ));
        }
        let config_desc = &resolved.manifest.config;
        if config_desc.size > CONFIG_MAX_BYTES {
            return Err(Failure::new(
                "blobs",
                OciErrorCode::ResourceExhausted.as_str(),
            ));
        }

        // config → 各レイヤーの順に取得し、取得ごとに digest を検証する（検証前のファイルは読まない）。
        let fetch_verify = |desc: &fandhe_container_oci::manifest::Descriptor,
                            name: String,
                            r: &mut Report|
         -> Result<PathBuf, Failure> {
            let dest = blobs_dir.join(name);
            let t = Instant::now();
            let blob = client
                .fetch_blob(&endpoint, reference.repository(), desc, &auth, &dest)
                .map_err(|e| Failure::oci("blobs", &e))?;
            r.blobs_ms += ms(t.elapsed());
            let t = Instant::now();
            verify_fetched_blob(&blob, desc.size).map_err(|e| Failure::oci("verify", &e))?;
            r.verify_ms += ms(t.elapsed());
            Ok(dest)
        };
        let config_path = fetch_verify(config_desc, "config.json".to_string(), r)?;
        r.config_bytes = config_desc.size;
        let mut layer_paths = Vec::new();
        for (i, d) in resolved.manifest.layers.iter().enumerate() {
            layer_paths.push(fetch_verify(d, format!("layer-{i}.tar.gz"), r)?);
            r.layer_bytes = r.layer_bytes.saturating_add(d.size);
        }
        drop(client);

        let mut config_bytes = Vec::new();
        std::fs::File::open(&config_path)
            .and_then(|f| f.take(CONFIG_MAX_BYTES + 1).read_to_end(&mut config_bytes))
            .map_err(|_| Failure::new("config", "INTERNAL"))?;
        let cfg = parse_image_config(&config_bytes)?;
        let process = derive_process(&cfg, spec.cmd_override.as_deref())?;
        let (took, stripped) = extract_and_finalize(&layer_paths, bundle, &process)?;
        r.extract_ms = ms(took);
        r.stripped = stripped;
        Ok(())
    }

    fn process_image(env: &RunEnv, idx: usize, spec: &ImageSpec, base: &Path) -> (Report, bool) {
        let mut r = Report {
            exit_kind: "not_started",
            ..Report::default()
        };
        let dir = match WorkDir::new(base, &format!("img{idx}")) {
            Ok(d) => d,
            Err(f) => {
                r.failure = Some(f);
                return (r, false);
            }
        };
        let blobs_dir = dir.dir.join("blobs");
        let bundle = dir.dir.join("bundle");
        let rootfs = bundle.join("rootfs");
        for (p, mode) in [(&blobs_dir, 0o700), (&bundle, 0o700), (&rootfs, 0o755)] {
            if mkdir_mode(p, mode).is_err() {
                r.failure = Some(Failure::new("setup", "INTERNAL"));
                return (r, false);
            }
        }
        if let Err(f) = pull_and_prepare(spec, &blobs_dir, &bundle, &mut r) {
            r.failure = Some(f);
            return (r, false);
        }
        let t = Instant::now();
        let run = run_container(env, idx, &bundle);
        r.run_ms = ms(t.elapsed());
        r.exit_kind = run.kind;
        r.exit_code = run.code;
        r.failure = run.failure;
        r.stdout_tail = run.stdout_tail;
        r.stderr_tail = run.stderr_tail;
        (r, run.abort_rest)
    }

    // ----- 実機モード --------------------------------------------------------------------------------------

    fn run_live(args: &RunArgs) -> i32 {
        if is_root() {
            eprintln!(
                "pull_e2e: FAILED setup: refusing to run as root (SEC-5); run as a regular user"
            );
            return 1;
        }
        let delegated = match DelegatedCgroup::detect() {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "pull_e2e: FAILED setup: no delegated cgroup v2 ({:?})",
                    e.code
                );
                return 1;
            }
        };
        let tag = std::process::id();
        let Ok(cg_id) = ContainerId::new(format!("pe{tag}")) else {
            eprintln!("pull_e2e: FAILED setup: container id");
            return 1;
        };
        let Ok(cg_name) = CgroupName::new(&cg_id) else {
            eprintln!("pull_e2e: FAILED setup: cgroup name");
            return 1;
        };
        let container = match delegated.prepare(&cg_name) {
            Ok((c, _proof)) => Arc::new(c),
            Err(e) => {
                eprintln!("pull_e2e: FAILED setup: prepare cgroup ({:?})", e.code);
                return 1;
            }
        };
        let base = args.work_dir.clone().unwrap_or_else(std::env::temp_dir);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            live_inner(args, &base, &container, tag)
        }));
        if let Err(e) = delegated.remove_child(&container) {
            record_cleanup_failure();
            eprintln!(
                "pull_e2e: FAILED cleanup: could not remove the container cgroup pe{tag} ({:?}); remove it manually",
                e.code
            );
        }
        match result {
            Ok(code) if code == 0 && cleanup_failures() > 0 => {
                println!(
                    "pull_e2e: FAILED {} cleanup step(s) left residue",
                    cleanup_failures()
                );
                1
            }
            Ok(code) => code,
            Err(_) => {
                eprintln!("pull_e2e: FAILED harness panicked");
                1
            }
        }
    }

    fn live_inner(args: &RunArgs, base: &Path, container: &Arc<ContainerCgroup>, tag: u32) -> i32 {
        let state_dir = match WorkDir::new(base, "state") {
            Ok(d) => d,
            Err(f) => {
                eprintln!("pull_e2e: FAILED setup: state dir ({})", f.code);
                return 1;
            }
        };
        let store = match StateRoot::from_override(state_dir.dir.join("state"))
            .and_then(FileStateStore::open)
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pull_e2e: FAILED setup: state store ({:?})", e.code());
                return 1;
            }
        };
        let join_container = Arc::clone(container);
        let launcher = match ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSingleId)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .cgroup_join_source(move || join_container.join_hook())
            .build()
        {
            Ok(l) => l,
            Err(e) => {
                eprintln!("pull_e2e: FAILED setup: launcher ({:?})", e.code());
                return 1;
            }
        };
        let env = RunEnv {
            store,
            launcher: Arc::new(launcher),
            recorder: OpRecorder::new(),
            tag,
        };
        let total = args.images.len();
        let mut failed = 0usize;
        let mut abort = false;
        for (idx, spec) in args.images.iter().enumerate() {
            if abort {
                let r = Report {
                    exit_kind: "not_started",
                    failure: Some(Failure::new("setup", "ABORTED")),
                    ..Report::default()
                };
                println!("{}", r.to_json(&spec.reference));
                failed += 1;
                continue;
            }
            let (r, abort_rest) = process_image(&env, idx, spec, base);
            println!("{}", r.to_json(&spec.reference));
            if !r.ok() {
                failed += 1;
            }
            abort = abort_rest;
        }
        if failed == 0 {
            println!("pull_e2e: {total}/{total} images pulled, verified, extracted and exited 0");
            0
        } else {
            println!("pull_e2e: FAILED {failed}/{total} images failed");
            1
        }
    }

    // ----- オフライン自己検証 ------------------------------------------------------------------------------

    mod selfcheck {
        use std::io::Write as _;

        use flate2::Compression;
        use flate2::write::GzEncoder;
        use sha2::{Digest as _, Sha256};

        use super::*;
        use fandhe_container_oci::reference::Digest;

        fn strs(v: &[&str]) -> Vec<String> {
            v.iter().map(|s| (*s).to_string()).collect()
        }

        fn args_cases() {
            // 既定のリスト。
            let d = parse_args(&[], None).expect("defaults");
            assert_eq!(d.images.len(), 3);
            assert_eq!(
                d.images.first().map(|i| i.reference.as_str()),
                Some("alpine")
            );
            assert_eq!(
                d.images.get(2).and_then(|i| i.cmd_override.clone()),
                Some(strs(&["/usr/sbin/nginx", "-v"]))
            );
            // --image / --cmd の境界。
            let a = parse_args(
                &strs(&[
                    "--ignored",
                    "--image",
                    "alpine",
                    "--image",
                    "debian:bookworm-slim",
                    "--cmd",
                    "/bin/true",
                    "--image",
                    "busybox",
                    "--work-dir",
                    "/var/tmp",
                ]),
                None,
            )
            .expect("args");
            assert_eq!(
                a,
                RunArgs {
                    images: vec![
                        ImageSpec {
                            reference: "alpine".into(),
                            cmd_override: None
                        },
                        ImageSpec {
                            reference: "debian:bookworm-slim".into(),
                            cmd_override: Some(strs(&["/bin/true"]))
                        },
                        ImageSpec {
                            reference: "busybox".into(),
                            cmd_override: None
                        },
                    ],
                    work_dir: Some(PathBuf::from("/var/tmp")),
                }
            );
            // 環境変数は --image が無いときだけ使う。
            let e = parse_args(&[], Some("alpine\nnginx:alpine -- /usr/sbin/nginx -v\n\n"))
                .expect("env");
            assert_eq!(e.images.len(), 2);
            assert_eq!(
                e.images.get(1).and_then(|i| i.cmd_override.clone()),
                Some(strs(&["/usr/sbin/nginx", "-v"]))
            );
            let both = parse_args(&strs(&["--image", "busybox"]), Some("alpine")).expect("both");
            assert_eq!(both.images.len(), 1);
            // 不正入力。
            // --cmd の後ろの --ignored / --nocapture は区切りで、コンテナの引数にしない。
            let t = parse_args(
                &strs(&[
                    "--image",
                    "x",
                    "--cmd",
                    "/bin/true",
                    "--ignored",
                    "--nocapture",
                ]),
                None,
            )
            .expect("args");
            assert_eq!(
                t.images.first().and_then(|i| i.cmd_override.clone()),
                Some(strs(&["/bin/true"]))
            );
            assert!(parse_args(&strs(&["--cmd", "x"]), None).is_err());
            assert!(parse_args(&strs(&["--image", "alpine", "--cmd"]), None).is_err());
            assert!(parse_args(&strs(&["--image"]), None).is_err());
            assert!(parse_args(&strs(&["--image", "UPPER/Case:"]), None).is_err());
            assert!(parse_args(&strs(&["--bogus"]), None).is_err());
            let many: Vec<String> = (0..=MAX_IMAGES)
                .flat_map(|_| strs(&["--image", "alpine"]))
                .collect();
            assert!(parse_args(&many, None).is_err());
            let long = "a".repeat(MAX_ARG_BYTES + 1);
            assert!(parse_args(&strs(&["--image", "alpine", "--cmd", &long]), None).is_err());
        }

        fn config_cases() {
            let full = br#"{"config":{"Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g"],
                "Env":["PATH=/x","FOO=bar"],"WorkingDir":"/app"}}"#;
            let cfg = parse_image_config(full).expect("cfg");
            let p = derive_process(&cfg, None).expect("process");
            assert_eq!(p.args, strs(&["/docker-entrypoint.sh", "nginx", "-g"]));
            assert_eq!(p.env, strs(&["PATH=/x", "FOO=bar"]));
            // override は Cmd だけを置き換える。
            let p = derive_process(&cfg, Some(&strs(&["-v"]))).expect("override");
            assert_eq!(p.args, strs(&["/docker-entrypoint.sh", "-v"]));
            // Cmd のみ・Env 無しは既定 PATH を足す。
            let cfg = parse_image_config(br#"{"config":{"Cmd":["/bin/sh"],"Entrypoint":null}}"#)
                .expect("cmd");
            let p = derive_process(&cfg, None).expect("cmd only");
            assert_eq!(p.args, strs(&["/bin/sh"]));
            assert_eq!(p.env, vec![DEFAULT_PATH_ENV.to_string()]);
            // Entrypoint のみ。
            let cfg = parse_image_config(br#"{"config":{"Entrypoint":["/app"]}}"#).expect("ep");
            assert_eq!(
                derive_process(&cfg, None).expect("ep only").args,
                strs(&["/app"])
            );
            // 空・相対パス・壊れた JSON・型違い。
            let empty = parse_image_config(br#"{"config":{}}"#).expect("empty");
            assert_eq!(
                derive_process(&empty, None),
                Err(Failure::new("config", "INVALID_ARGUMENT"))
            );
            let rel = parse_image_config(br#"{"config":{"Cmd":["bash"]}}"#).expect("rel");
            assert_eq!(
                derive_process(&rel, None),
                Err(Failure::new("config", "INVALID_ARGUMENT"))
            );
            assert_eq!(
                derive_process(&rel, Some(&strs(&["/bin/true"])))
                    .expect("abs")
                    .args,
                strs(&["/bin/true"])
            );
            assert_eq!(
                parse_image_config(b"{").unwrap_err(),
                Failure::new("config", "DATA_LOSS")
            );
            assert_eq!(
                parse_image_config(br#"{"config":{"Cmd":"sh"}}"#).unwrap_err(),
                Failure::new("config", "DATA_LOSS")
            );
            let bad_env = parse_image_config(br#"{"config":{"Cmd":["/a"],"Env":["NOEQUALS"]}}"#)
                .expect("env");
            assert_eq!(
                derive_process(&bad_env, None),
                Err(Failure::new("config", "DATA_LOSS"))
            );
        }

        enum Ent<'a> {
            Dir(&'a str),
            File(&'a str, &'a [u8], u32),
        }

        fn make_layer(entries: &[Ent<'_>]) -> Vec<u8> {
            let mut b = tar::Builder::new(Vec::new());
            for e in entries {
                let mut h = tar::Header::new_gnu();
                match e {
                    Ent::Dir(p) => {
                        h.set_entry_type(tar::EntryType::Directory);
                        h.set_mode(0o755);
                        h.set_size(0);
                        h.set_cksum();
                        b.append_data(&mut h, p, std::io::empty())
                            .expect("append dir");
                    }
                    Ent::File(p, data, mode) => {
                        h.set_entry_type(tar::EntryType::Regular);
                        h.set_mode(*mode);
                        h.set_size(data.len() as u64);
                        h.set_cksum();
                        b.append_data(&mut h, p, *data).expect("append file");
                    }
                }
            }
            let tar_bytes = b.into_inner().expect("finish tar");
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            gz.write_all(&tar_bytes).expect("gzip");
            gz.finish().expect("gzip finish")
        }

        fn digest_of(bytes: &[u8]) -> Digest {
            let hex: String = Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Digest::parse(&format!("sha256:{hex}")).expect("digest")
        }

        /// ローカルの 2 レイヤー（上書き・追加・whiteout を含む）で、digest 検証 → 展開 → bundle 生成を通す。
        fn local_pipeline() {
            let work = WorkDir::new(&std::env::temp_dir(), "selfcheck").expect("work dir");
            let blobs = work.dir.join("blobs");
            let bundle = work.dir.join("bundle");
            for (p, m) in [
                (&blobs, 0o700),
                (&bundle, 0o700),
                (&bundle.join("rootfs"), 0o755),
            ] {
                mkdir_mode(p, m).expect("mkdir");
            }
            let l1 = make_layer(&[
                Ent::Dir("bin"),
                Ent::File("bin/hello", b"hello from layer 1\n", 0o755),
                Ent::Dir("etc"),
                Ent::File("etc/os-release", b"old\n", 0o644),
                Ent::File("etc/gone", b"to be removed\n", 0o644),
            ]);
            let l2 = make_layer(&[
                Ent::File("etc/os-release", b"new\n", 0o644),
                Ent::File("etc/.wh.gone", b"", 0o644),
                Ent::Dir("app"),
                Ent::File("app/run.txt", b"layer 2\n", 0o644),
            ]);
            let mut paths = Vec::new();
            for (i, bytes) in [&l1, &l2].into_iter().enumerate() {
                let p = blobs.join(format!("layer-{i}.tar.gz"));
                std::fs::write(&p, bytes).expect("write blob");
                let d = digest_of(bytes);
                let v = verify_blob_digest(&p, &d, bytes.len() as u64).expect("verify");
                assert_eq!(v.size, bytes.len() as u64);
                paths.push(p);
            }
            // 別の digest は DataLoss で拒否される（検証前の blob を展開しない）。
            let wrong = digest_of(b"other");
            let err = verify_blob_digest(&paths[0], &wrong, l1.len() as u64).expect_err("mismatch");
            assert_eq!(err.code(), OciErrorCode::DataLoss);

            let cfg = parse_image_config(
                br#"{"config":{"Entrypoint":["/bin/hello"],"Cmd":["x"],"Env":["A=b"]}}"#,
            )
            .expect("cfg");
            let process = derive_process(&cfg, Some(&strs(&["y"]))).expect("process");
            let (_took, stripped) =
                extract_and_finalize(&paths, &bundle, &process).expect("extract");
            assert_eq!(stripped, 0);

            let rootfs = bundle.join("rootfs");
            let read = |p: &str| std::fs::read_to_string(rootfs.join(p)).expect("read");
            assert_eq!(read("bin/hello"), "hello from layer 1\n");
            assert_eq!(read("etc/os-release"), "new\n");
            assert_eq!(read("app/run.txt"), "layer 2\n");
            assert!(
                std::fs::symlink_metadata(rootfs.join("etc/gone")).is_err(),
                "whiteout applied"
            );
            assert!(
                std::fs::symlink_metadata(rootfs.join("etc/.wh.gone")).is_err(),
                "marker not extracted"
            );
            for d in ["proc", "dev", "sys"] {
                assert!(rootfs.join(d).is_dir(), "{d} mountpoint");
            }
            let config: Value = serde_json::from_slice(
                &std::fs::read(bundle.join("config.json")).expect("config.json"),
            )
            .expect("json");
            let at = |ptr: &str| config.pointer(ptr).cloned().expect("pointer");
            assert_eq!(at("/process/args"), json!(["/bin/hello", "y"]));
            assert_eq!(at("/process/env"), json!(["A=b", DEFAULT_PATH_ENV]));
            assert_eq!(at("/process/cwd"), json!("/"));
            assert_eq!(at("/root/path"), json!("rootfs"));
            assert_eq!(at("/hostname"), json!(HOSTNAME));
        }

        pub fn run() {
            args_cases();
            config_cases();
            local_pipeline();
        }
    }

    pub fn main() {
        selfcheck::run();
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if !argv.iter().any(|a| a == "--ignored") {
            println!(
                "pull_e2e: offline self-checks passed; ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            return;
        }
        let env_images = std::env::var(IMAGES_ENV).ok();
        let args = match parse_args(&argv, env_images.as_deref()) {
            Ok(a) => a,
            Err(msg) => {
                eprintln!("pull_e2e: invalid arguments: {msg}");
                std::process::exit(2);
            }
        };
        let code = run_live(&args);
        if code != 0 {
            std::process::exit(code);
        }
    }
}
