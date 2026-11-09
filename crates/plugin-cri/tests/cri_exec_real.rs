//! plugin-cri の本番バイナリ越しに、実コンテナへの CRI Exec を通す実機前提試験
//! （CRI-6・SEC-1・REPAIR-5・REPAIR-12・TASK-63.2・#3762。親 #3726・前提 #3761）。
//!
//! 呼び出し文脈: 本番バイナリ（`main.rs` が `with_streaming` と本番の `ExecStreamLauncher` を注入した構成）に対し、
//! UDS＋gRPC で `Exec` を呼んで URL を得て、client-go 相当の SPDY クライアント（`crates/cri/tests/support/spdy_client.rs`）で
//! 接続する。plugin は `SupervisorExecLauncher` → supervisor の `stream-exec` helper → core の exec 段の順で実コンテナ
//! （busybox の `sleep 300`）へ入る。既定の集合の `streaming.rs`（偽 launcher）・`streaming_grpc.rs`（未知 ID の `NOT_FOUND`）は
//! 実コンテナを使わないため、次を本物で具体値に固定する。
//!
//! - `echo` の stdout と `Success` の Status、`exit 3` の `NonZeroExitCode`（cause の reason `ExitCode`・message `"3"`）
//! - exec のプロセスの `/proc/<pid>/status` の `CapEff`・`CapPrm`・`CapBnd`・`Seccomp` が、コンテナの init を超えないこと（SEC-1）。
//!   `CapEff` は OCI 既定（`0xa80425fb`）と一致し、`Seccomp` は 2（filter）
//!
//! - 要求元の異常終了（段 4。SUP-6・SEC-1・REPAIR-5・#4167）: 終わらない exec（`sleep 617`）を SPDY で開いたまま plugin-cri を SIGKILL
//!   すると、helper（`--timeout-ms` は 60 秒以上）が fd 0 の切断を検知して 2 秒以内に終わり、exec のコマンドが `/proc` に残らない。
//!   helper は plugin-cri の子から探し、開始時刻つきで消滅を判定する（plugin-cri の死後は init 等へ再親付けされるため）。
//!   段 4 の後は再起動した plugin-cri が記録を再採用して後始末する（本物の状態ルートに記録を残さないため）。
//!
//!
//! 失敗後の残骸の回収（#4142）: 本体を 2 回走らせる（1 回目は StartContainer の直後に注入した失敗、回収、2 回目は同じ metadata で通す）。
//! 注入では plugin-cri を SIGKILL してから panic させ、外側の回収が死活を判定して起動し直して回収する（#4326。共有部品 `reclaim_restarting`）。
//! 回収の部品は `support/cri_real_reclaim.rs`（トークンのラベルと台帳の ID だけを期限つきで Stop / Remove する）。
//!
//! ハーネス（TempDir・ChildGuard・接続待ち・pull の失敗行）は `container_grpc.rs` の段 C と同じものを最小化して複製した
//! （試験 crate 間でモジュールを共有できないため）。`container_grpc.rs` は変更しない（波及の最小化。REPAIR-1）。
//!
//! 残余（REPAIR-3）: tty（`kubectl exec -it`）は supervisor の pty 結線の後続まで `INVALID_ARGUMENT`。相対の `argv[0]` は
//! #2439 まで拒否されるため、argv は絶対パスの固定リテラルだけを使う。実機の crictl での確認は人間担当（#3730 の子）。
//!
//! Linux 限定の理由: 本番の既定の状態ルート・supervisor・Landlock・cgroup v2 は Linux でだけ成り立つ（`container_grpc.rs` と同じ）。

#![cfg(target_os = "linux")]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;
// 前提欠如を `<試験名>: PRECONDITION FAILED (test environment, not a ... regression)` の 1 行目で失敗させる共有部品。
#[path = "../../core/tests/support/precondition.rs"]
mod precondition;
// client-go 相当の SPDY クライアント（cri の試験と共有。cri へ逆依存できないため `#[path]`）。
#[path = "../../cri/tests/support/spdy_client.rs"]
mod spdy_client;
// serde_json を plugin-cri の依存に足さないための最小 JSON 読み取り。
#[path = "support/mini_json.rs"]
mod mini_json;
#[path = "support/cri_real_reclaim.rs"]
mod reclaim;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::image_service_client::ImageServiceClient;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_cri::streaming::spdy::goaway_status;
use fandhe_container_plugin::grpc::{GrpcClientConfig, call_with_deadline, connect_uds_channel};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginErrorCode};
use spdy_client::{Spdy, split_url};
use tonic::transport::Channel;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const IMAGE: &str = "docker.io/library/busybox:1.36";
const TEST: &str = "production_binary_exec_real";
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
const RPC_DEADLINE: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(5);
/// pull の期限（ImageService の pull 期限 540 秒に収まる範囲）。
const PULL_DEADLINE: Duration = Duration::from_secs(300);
/// 試験全体の上限。CI の補助の期限（540 秒）より先に効かせる（REPAIR-5）。
const WATCHDOG: Duration = Duration::from_secs(480);
/// 1 回の exec の SPDY 往復の上限。helper の起動・setns・exec を経るため既定の 5 秒より長くする（helper の起動予算 25 秒より長い）。
const SPDY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const EXEC_VERSIONS: [&str; 4] = [
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
];
/// OCI 既定の capability 集合（14 個）のビット列。`sec1_3762_oci_default_mask_literal_matches_core` が core の定義と突き合わせる。
const OCI_DEFAULT_MASK: u64 = 0x0000_0000_a804_25fb;

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        Self(exclusive_dir::create(&format!("fcce-{tag}")).expect("create temp dir"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 子プロセスのガード。Drop で kill し、期限つきで回収する（REPAIR-5）。
struct ChildGuard(Child);

impl ChildGuard {
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let start = Instant::now();
        while start.elapsed() < REAP_GRACE {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// 環境を引き継いで本番バイナリを spawn する（`XDG_RUNTIME_DIR` 等を systemd --user の private ソケットへ届けるため
/// `env_clear` しない）。
fn spawn_server_inherit_env(bin: &Path, sock: &Path) -> ChildGuard {
    let child = Command::new(bin)
        .arg("--socket")
        .arg(sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    ChildGuard(child)
}

/// plugin と supervisor だけを 0700 の専用ディレクトリへ複製して返す（SUP-14）。隣に特権ランチャーがあると
/// rootful 経路に入るため、置かないことも assert する。stream-exec の helper は plugin と同じディレクトリの supervisor を起動する。
fn production_bin_dir(tag: &str) -> (TempDir, PathBuf) {
    let bin_dir = TempDir::new(tag);
    let plugin_src = Path::new(BIN);
    let sup_name = "fandhe-container-supervisor";
    let sup_src = plugin_src
        .parent()
        .expect("plugin binary parent")
        .join(sup_name);
    assert!(
        sup_src.is_file(),
        "supervisor binary is not built next to the plugin binary; run cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor"
    );
    let plugin_bin = bin_dir.0.join("fandhe-container-plugin-cri");
    std::fs::copy(plugin_src, &plugin_bin).expect("copy plugin binary");
    std::fs::copy(&sup_src, bin_dir.0.join(sup_name)).expect("copy supervisor binary");
    assert!(
        !bin_dir.0.join("fandhe-container-launcher").exists(),
        "a privileged launcher must not sit next to the plugin binary"
    );
    (bin_dir, plugin_bin)
}

/// socket の出現と接続の成功を期限内で待つ。子が先に終了したら診断つきで失敗する。
async fn connect_when_ready_with(
    sock: &Path,
    guard: &mut ChildGuard,
    config: GrpcClientConfig,
) -> Channel {
    let start = Instant::now();
    loop {
        if let Some(status) = guard.exited() {
            let mut err = String::new();
            if let Some(mut s) = guard.0.stderr.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut err);
            }
            panic!("plugin binary exited early: {status:?}: {err}");
        }
        if sock.exists() {
            match connect_uds_channel(sock, &config, Box::new(JsonLinesPeerAuthObserver::new()))
                .await
            {
                Ok(ch) => return ch,
                Err(e)
                    if matches!(
                        e.code(),
                        PluginErrorCode::NotFound | PluginErrorCode::Unavailable
                    ) => {}
                Err(e) => panic!("connect failed: {:?}", e.code()),
            }
        }
        assert!(start.elapsed() < STARTUP_DEADLINE, "startup deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn image_spec(image: &str) -> cri::ImageSpec {
    cri::ImageSpec {
        image: image.into(),
        ..Default::default()
    }
}

/// `PullImage`。生の `tonic::Status` を返してレジストリの HTTP 状態（トレーラーメタデータ）を読めるようにする（#2966）。
async fn pull_image_raw(
    c: &mut ImageServiceClient<Channel>,
    image: &str,
    deadline: Duration,
) -> Result<String, tonic::Status> {
    let call = c.pull_image(cri::PullImageRequest {
        image: Some(image_spec(image)),
        auth: None,
        sandbox_config: None,
    });
    match tokio::time::timeout(deadline, call).await {
        Ok(r) => r.map(|r| r.into_inner().image_ref),
        Err(_) => Err(tonic::Status::deadline_exceeded("pull deadline exceeded")),
    }
}

/// pull の失敗を HTTP 状態の区分つきの固定の 1 行にする（429 は rate limit と識別。生の message・参照・URL は出さない）。
fn pull_failure_line(status: &tonic::Status) -> String {
    use fandhe_container_cri::error::registry_http_status_from_metadata;
    use fandhe_container_cri::instrument::{RegistryHttpClass, code_name};
    let test = "production_binary_exec_real";
    let class = registry_http_status_from_metadata(status.metadata())
        .and_then(RegistryHttpClass::from_http_status);
    match class {
        Some(RegistryHttpClass::RateLimited) => format!(
            "{test}: registry rate limit (HTTP 429); docker hub anonymous pull rate limit is likely exhausted"
        ),
        Some(c) => format!(
            "{test}: pull failed with code {} registry_http={}",
            code_name(status.code()),
            c.as_str()
        ),
        None => format!(
            "{test}: pull failed with code {} registry_http=none",
            code_name(status.code())
        ),
    }
}

// ---- /proc/<pid>/status の解析 ----

/// `/proc/<pid>/status` の本文から `Key:\tvalue` を map にする。
fn parse_status(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// 16 進の capability 集合の欄を読む。欠けた欄・解析できない値は失敗にする。
fn hex_field(m: &HashMap<String, String>, key: &str) -> u64 {
    let raw = m
        .get(key)
        .unwrap_or_else(|| panic!("status has no {key} field: {m:?}"));
    u64::from_str_radix(raw, 16).unwrap_or_else(|e| panic!("{key} is not hex ({e}): {raw}"))
}

// ---- Exec の往復 ----

/// 1 回の exec の結果。
struct ExecOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: mini_json::Json,
    goaway: u32,
}

/// `Exec` RPC で URL を得て、SPDY で接続して stdout・stderr・error を FIN まで読む（stdin・tty なし）。
async fn exec_once(c: &mut RuntimeServiceClient<Channel>, id: &str, cmd: &[&str]) -> ExecOutcome {
    let url = call_with_deadline(
        c.exec(cri::ExecRequest {
            container_id: id.into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("exec rpc")
    .into_inner()
    .url;
    assert!(url.starts_with("http://127.0.0.1:"), "url: {url}");
    let (authority, path) = split_url(&url);
    let addr: SocketAddr = authority.parse().expect("authority");
    let join = tokio::task::spawn_blocking(move || {
        let mut s = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        s.tcp
            .set_read_timeout(Some(SPDY_READ_TIMEOUT))
            .expect("read timeout");
        // client-go の順（error → stdout → stderr）で張る。
        let error = s.create_stream(&[("streamtype", "error")]);
        let stdout = s.create_stream(&[("streamtype", "stdout")]);
        let stderr = s.create_stream(&[("streamtype", "stderr")]);
        let out = s.read_until_fin(stdout);
        let err = s.read_until_fin(stderr);
        let raw = s.read_until_fin(error);
        let goaway = s.wait_goaway();
        (out, err, raw, goaway)
    });
    let (stdout, stderr, raw, goaway) = tokio::time::timeout(Duration::from_secs(90), join)
        .await
        .expect("exec deadline")
        .expect("join");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = mini_json::parse(&text).unwrap_or_else(|| panic!("status is not JSON: {text}"));
    ExecOutcome {
        stdout,
        stderr,
        status,
        goaway,
    }
}

// ---- /proc の走査（段 4。外部入力なので失敗は「不一致」へ倒す） ----

/// `/proc/<pid>/stat` の (状態, 開始時刻)。comm に `)` が入りうるため最後の `)` 以降を読む。
fn proc_state_and_start(pid: u32) -> Option<(char, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    // rest の先頭は 3 番目のフィールド（state）。開始時刻は 22 番目なので state の後 19 個目。
    let start = fields.nth(18)?.parse::<u64>().ok()?;
    Some((state, start))
}

/// 記録した (pid, 開始時刻) のプロセスが消えている（stat が無い・ゾンビ・死亡・開始時刻が違う＝pid の再利用）か。
fn is_gone(pid: u32, starttime: u64) -> bool {
    match proc_state_and_start(pid) {
        None => true,
        Some((state, start)) => state == 'Z' || state == 'X' || start != starttime,
    }
}

/// `/proc/<pid>/cmdline` の引数列（NUL 区切り）。
fn cmdline_args(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
    )
}

/// cmdline が `argv` に完全一致し、ゾンビ・死亡でない生きたプロセスの (pid, 開始時刻)。
fn live_pids_with_argv(argv: &[&str]) -> Vec<(u32, u64)> {
    let mut found = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return found;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if cmdline_args(pid).is_some_and(|a| a == argv)
            && let Some((state, start)) = proc_state_and_start(pid)
            && state != 'Z'
            && state != 'X'
        {
            found.push((pid, start));
        }
    }
    found
}

/// `parent` の子のうち、第 1 引数が `stream-exec` のもの（helper）の (pid, 開始時刻, `--timeout-ms`)。
fn stream_exec_helpers_of(parent: u32) -> Vec<(u32, u64, u64)> {
    let mut found = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent}/task")) else {
        return found;
    };
    for t in tasks.flatten() {
        let Ok(children) = std::fs::read_to_string(t.path().join("children")) else {
            continue;
        };
        for pid in children
            .split_whitespace()
            .filter_map(|v| v.parse::<u32>().ok())
        {
            let Some(args) = cmdline_args(pid) else {
                continue;
            };
            if args.get(1).map(String::as_str) != Some("stream-exec") {
                continue;
            }
            let timeout_ms = args
                .iter()
                .position(|a| a == "--timeout-ms")
                .and_then(|i| args.get(i + 1))
                .and_then(|v| v.parse::<u64>().ok());
            if let (Some((_, start)), Some(timeout_ms)) = (proc_state_and_start(pid), timeout_ms) {
                found.push((pid, start, timeout_ms));
            }
        }
    }
    found
}

/// 終わらない exec を開き、`marker` の出力（コマンドの起動の合図）を読んだ接続をそのまま返す（段 4）。
///
/// 接続は呼び出し側が plugin-cri を殺すまで閉じない。先に閉じると `ExecSession` の drop が通常の経路で helper を止めてしまい、
/// 要求元の消滅の検知を照合したことにならないため。
async fn exec_open_until_marker(
    c: &mut RuntimeServiceClient<Channel>,
    id: &str,
    cmd: &[&str],
    marker: &'static [u8],
) -> Spdy {
    let url = call_with_deadline(
        c.exec(cri::ExecRequest {
            container_id: id.into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("exec rpc")
    .into_inner()
    .url;
    assert!(url.starts_with("http://127.0.0.1:"), "url: {url}");
    let (authority, path) = split_url(&url);
    let addr: SocketAddr = authority.parse().expect("authority");
    let join = tokio::task::spawn_blocking(move || {
        let mut s = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        s.tcp
            .set_read_timeout(Some(SPDY_READ_TIMEOUT))
            .expect("read timeout");
        let _error = s.create_stream(&[("streamtype", "error")]);
        let stdout = s.create_stream(&[("streamtype", "stdout")]);
        let _stderr = s.create_stream(&[("streamtype", "stderr")]);
        let got = s.read_at_least(stdout, marker.len());
        assert_eq!(got, marker, "the long exec must report that it started");
        s
    });
    tokio::time::timeout(Duration::from_secs(90), join)
        .await
        .expect("exec open deadline")
        .expect("join")
}

/// plugin を SIGKILL して期限つきで回収する（試験自身の子。REPAIR-5）。
fn kill_and_reap(guard: &mut ChildGuard) {
    let _ = guard.0.kill();
    let start = Instant::now();
    while start.elapsed() < REAP_GRACE {
        if matches!(guard.0.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("plugin binary was not reaped within {REAP_GRACE:?} after SIGKILL");
}

fn status_str<'a>(j: &'a mini_json::Json, key: &str) -> &'a str {
    j.get(key)
        .and_then(mini_json::Json::as_str)
        .unwrap_or_else(|| panic!("status has no string {key}: {j:?}"))
}

async fn status_of_pid(
    c: &mut RuntimeServiceClient<Channel>,
    id: &str,
    pid: &str,
) -> HashMap<String, String> {
    let path = format!("/proc/{pid}/status");
    let o = exec_once(c, id, &["/bin/cat", &path]).await;
    assert_eq!(o.stderr, b"", "cat {path} wrote to stderr");
    assert_eq!(status_str(&o.status, "status"), "Success", "{:?}", o.status);
    assert_eq!(o.goaway, goaway_status::OK);
    parse_status(&String::from_utf8(o.stdout).expect("status is utf-8"))
}

/// 起動中の plugin-cri とその接続。段 4 で plugin-cri を殺して再起動するため、本体と外側（回収・終了確認）で共有する。
struct Srv {
    guard: ChildGuard,
    ch: Channel,
}

type SharedSrv = std::sync::Arc<std::sync::Mutex<Srv>>;

/// 共有の `Srv` を取る（保持したまま await しない。poison は試験の失敗なので素通しで取り出す）。
fn lock_srv(srv: &SharedSrv) -> std::sync::MutexGuard<'_, Srv> {
    srv.lock().unwrap_or_else(|e| e.into_inner())
}

/// 外側の回収が呼ぶ起動し直し（#4326）。旧 plugin-cri を kill・回収して `.cri/@instance.lock` を解放してから、
/// `sock` で起動し直して接続し、共有の `srv` を差し替えて新しい client を返す。`srv` の lock は await をまたがない。
async fn restart_plugin(srv: &SharedSrv, bin: &Path, sock: &Path) -> RuntimeServiceClient<Channel> {
    kill_and_reap(&mut lock_srv(srv).guard);
    let mut guard = spawn_server_inherit_env(bin, sock);
    let config = GrpcClientConfig::new()
        .with_request_timeout(Duration::from_secs(600))
        .expect("request timeout");
    let ch = connect_when_ready_with(sock, &mut guard, config).await;
    *lock_srv(srv) = Srv {
        guard,
        ch: ch.clone(),
    };
    RuntimeServiceClient::new(ch)
}

/// 試験本体（sandbox の作成から exec の照合・後始末まで）。`inject` が真なら StartContainer と Running の確認の直後に
/// 固定文言で panic する（失敗後の回収の自己照合。#4142）。作った ID は台帳へ登録し、Remove が成功したら外す。
async fn scenario(
    mut c: RuntimeServiceClient<Channel>,
    token: String,
    ledger: reclaim::Ledger,
    inject: bool,
    srv: SharedSrv,
    plugin_bin: PathBuf,
    sock2: PathBuf,
) {
    // core の start が受けられる NODE の network namespace にする（container_grpc.rs の段 C と同じ）。
    let mut run = cri::RunPodSandboxRequest {
        config: Some(cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: "pod-exec-real".into(),
                uid: reclaim::sandbox_uid("uid-exec", &token),
                namespace: "default".into(),
                attempt: 0,
            }),
            labels: reclaim::config_labels(TEST, &token),
            ..Default::default()
        }),
        ..Default::default()
    };
    run.config
        .as_mut()
        .expect("config")
        .linux
        .get_or_insert_with(Default::default)
        .security_context
        .get_or_insert_with(Default::default)
        .namespace_options = Some(cri::NamespaceOption {
        network: cri::NamespaceMode::Node as i32,
        ..Default::default()
    });
    let sb = call_with_deadline(c.run_pod_sandbox(run), RPC_DEADLINE)
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;
    reclaim::record_sandbox(&ledger, &sb);

    let long = Duration::from_secs(120);
    let id = call_with_deadline(
        c.create_container(cri::CreateContainerRequest {
            pod_sandbox_id: sb.clone(),
            config: Some(cri::ContainerConfig {
                metadata: Some(cri::ContainerMetadata {
                    name: "c".into(),
                    attempt: 0,
                }),
                image: Some(image_spec(IMAGE)),
                command: vec!["/bin/sleep".into(), "300".into()],
                labels: reclaim::config_labels(TEST, &token),
                ..Default::default()
            }),
            sandbox_config: None,
        }),
        long,
    )
    .await
    .expect("create by tag")
    .into_inner()
    .container_id;
    reclaim::record_container(&ledger, &id);
    call_with_deadline(
        c.start_container(cri::StartContainerRequest {
            container_id: id.clone(),
        }),
        long,
    )
    .await
    .expect("start");
    let st = call_with_deadline(
        c.container_status(cri::ContainerStatusRequest {
            container_id: id.clone(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("status")
    .into_inner()
    .status
    .expect("status body");
    assert_eq!(st.state, cri::ContainerState::ContainerRunning as i32);
    if inject {
        // plugin-cri が予期せず死んだ場面を作る（#4326）。外側の回収が起動し直して回収する。
        kill_and_reap(&mut lock_srv(&srv).guard);
        panic!("{}", reclaim::injected_message(TEST));
    }

    // 1. echo: stdout の内容・stderr が空・Success。
    let o = exec_once(&mut c, &id, &["/bin/echo", "hello", "exec"]).await;
    assert_eq!(o.stdout, b"hello exec\n");
    assert_eq!(o.stderr, b"");
    assert_eq!(status_str(&o.status, "status"), "Success", "{:?}", o.status);
    assert_eq!(o.goaway, goaway_status::OK);

    // 2. exit 3: NonZeroExitCode と cause の ExitCode / "3"。
    let o = exec_once(&mut c, &id, &["/bin/sh", "-c", "exit 3"]).await;
    assert_eq!(status_str(&o.status, "status"), "Failure", "{:?}", o.status);
    assert_eq!(
        status_str(&o.status, "reason"),
        "NonZeroExitCode",
        "{:?}",
        o.status
    );
    let causes = match o.status.get("details").and_then(|d| d.get("causes")) {
        Some(mini_json::Json::Array(v)) => v,
        other => panic!("details.causes is not an array: {other:?}"),
    };
    assert_eq!(causes.len(), 1, "{:?}", o.status);
    assert_eq!(status_str(&causes[0], "reason"), "ExitCode");
    assert_eq!(status_str(&causes[0], "message"), "3");
    assert_eq!(o.goaway, goaway_status::OK);

    // 3. SEC-1: exec のプロセス自身とコンテナの init の capability・seccomp を照合する。
    let exec_st = status_of_pid(&mut c, &id, "self").await;
    assert_eq!(exec_st.get("Name").map(String::as_str), Some("cat"));
    let init_st = status_of_pid(&mut c, &id, "1").await;
    assert_eq!(init_st.get("Name").map(String::as_str), Some("sleep"));

    let init_eff = hex_field(&init_st, "CapEff");
    assert_eq!(
        init_eff, OCI_DEFAULT_MASK,
        "init CapEff {init_eff:#x} is not the OCI default {OCI_DEFAULT_MASK:#x}"
    );
    assert_eq!(init_st.get("Seccomp").map(String::as_str), Some("2"));
    for key in ["CapEff", "CapPrm", "CapBnd"] {
        let (e, i) = (hex_field(&exec_st, key), hex_field(&init_st, key));
        assert_eq!(
            e & !i,
            0,
            "exec {key} {e:#x} exceeds the container init {i:#x} (SEC-1)"
        );
    }
    let exec_eff = hex_field(&exec_st, "CapEff");
    assert_eq!(
        exec_eff, OCI_DEFAULT_MASK,
        "exec CapEff {exec_eff:#x} is not the OCI default {OCI_DEFAULT_MASK:#x}"
    );
    assert_eq!(exec_st.get("Seccomp").map(String::as_str), Some("2"));
    assert_eq!(hex_field(&exec_st, "CapInh"), 0);
    assert_eq!(hex_field(&exec_st, "CapAmb"), 0);

    // 4. 要求元の異常終了（SUP-6・SEC-1・REPAIR-5・#4167）: 終わらない exec を開いたまま plugin-cri を SIGKILL すると、
    //    helper が 2 秒以内に終わり、exec のコマンドが残らない。helper の期限は 60 秒以上で、期限や hold_grace では説明できない。
    const LONG_ARG: &str = "617";
    let long_argv = ["/bin/sleep", LONG_ARG];
    let spdy = exec_open_until_marker(
        &mut c,
        &id,
        &["/bin/sh", "-c", "echo started; exec /bin/sleep 617"],
        b"started\n",
    )
    .await;
    let helpers = stream_exec_helpers_of(lock_srv(&srv).guard.0.id());
    assert_eq!(
        helpers.len(),
        1,
        "exactly one helper under plugin-cri: {helpers:?}"
    );
    let (helper_pid, helper_start, helper_timeout_ms) = helpers[0];
    assert!(
        helper_timeout_ms >= 60_000,
        "the helper timeout {helper_timeout_ms} ms must be far above the 2s budget"
    );
    // started の出力は sh が sleep へ exec する前に出るため、期待 argv のプロセスが現れるまで有限の期限で待つ（REPAIR-12）。
    let cmds = {
        let wait_start = Instant::now();
        loop {
            let found = live_pids_with_argv(&long_argv);
            if !found.is_empty() || wait_start.elapsed() >= Duration::from_secs(10) {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    assert_eq!(
        cmds.len(),
        1,
        "exactly one live long exec command: {cmds:?}"
    );
    let (cmd_pid, cmd_start) = cmds[0];

    let t0 = Instant::now();
    kill_and_reap(&mut lock_srv(&srv).guard);
    let elapsed = loop {
        if is_gone(helper_pid, helper_start) {
            break t0.elapsed();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(15),
            "the helper did not exit within 15s after plugin-cri was killed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(
        elapsed <= Duration::from_secs(2),
        "the helper took {elapsed:?} to exit after plugin-cri was killed (budget 2s)"
    );
    // helper は cgroup の回収を終えてから終わるため、終了の直後に確かめる。
    assert!(
        is_gone(cmd_pid, cmd_start),
        "the exec command (pid {cmd_pid}) must be gone once the helper has exited"
    );
    assert_eq!(
        live_pids_with_argv(&long_argv),
        Vec::<(u32, u64)>::new(),
        "no long exec command may remain"
    );
    // libtest のキャプチャを迂回して情報行を出す（`^test ... ` の形にしない）。
    {
        use std::io::Write as _;
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let _ = writeln!(
            std::io::stderr(),
            "production_binary_exec_real: info plugin_kill_elapsed_ms={} budget_ms=2000 helper_timeout_ms={helper_timeout_ms} kernel={kernel}",
            elapsed.as_millis()
        );
    }
    // kill の後は pump せず、接続は drop するだけにする。
    drop(spdy);

    // plugin-cri を再起動して記録を再採用させ、同じ状態ルートの後始末をそこで行う
    // （本物の状態ルートに記録を残さない。残った場合は docs/setup/cri-record-recovery.md の手順で回収する）。
    // 新しい接続は共有の `srv` へも入れる（外側の回収が最新の接続を使えるように。#4142）。
    let mut new_guard = spawn_server_inherit_env(&plugin_bin, &sock2);
    let config2 = GrpcClientConfig::new()
        .with_request_timeout(Duration::from_secs(600))
        .expect("request timeout");
    let new_ch = connect_when_ready_with(&sock2, &mut new_guard, config2).await;
    c = RuntimeServiceClient::new(new_ch.clone());
    *lock_srv(&srv) = Srv {
        guard: new_guard,
        ch: new_ch,
    };

    // 後始末（成功経路。#4285）。SIGKILL の後に再採用された記録を、台帳とトークンの回収で消す。Stop だけは先に通して
    // 結果を厳密に見る。回収が Remove・一覧での残存確認を担い、回収した ID が自分の 1 件ずつであることを具体値で照合する。
    call_with_deadline(
        c.stop_container(cri::StopContainerRequest {
            container_id: id.clone(),
            timeout: 2,
        }),
        long,
    )
    .await
    .expect("stop");
    call_with_deadline(
        c.stop_pod_sandbox(cri::StopPodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
        long,
    )
    .await
    .expect("stop sandbox");
    let rep = reclaim::reclaim(&mut c, &ledger, &token, reclaim::CLEANUP_BUDGET).await;
    assert_eq!(rep.reclaimed_containers, vec![id.clone()], "{rep:?}");
    assert_eq!(rep.reclaimed_sandboxes, vec![sb.clone()], "{rep:?}");
    assert!(rep.is_clean(), "{rep:?}");
    eprintln!(
        "{TEST}: info readopted records reclaimed containers=1 sandboxes=1 after plugin restart"
    );
}

/// 段階（本番バイナリ越しの実コンテナへの exec）。
///
/// 失敗後の回収（#4142）: 本体（[`scenario`]）を 2 回走らせる。1 回目は StartContainer の直後に固定文言で panic させ
/// （注入）、回収が `containers=1 sandboxes=1 left=0` で旧 ID を `NOT_FOUND` にすることを照合する。2 回目は同じ metadata で
/// 最後まで通し、`ALREADY_EXISTS` にならないことを機械照合する。2 回目が失敗しても回収してから元の panic を再送出する。
/// 回収にも失敗したら残った ID と回収手順の文書を 1 行で出す（uid にトークンが入るので次の実行は守られる）。
///
/// `#[ignore]` の理由（既定の集合から分ける）: (1) StartContainer と Exec は supervisor 経由の本番経路で、`systemd --user` の
/// 委譲 cgroup scope の中で動かす必要がある（Landlock ABI 6 以上・user manager の private ソケット・`XDG_RUNTIME_DIR` も要る）、
/// (2) 外向き HTTPS で実レジストリ（Docker Hub）から取得する、(3) supervisor の bin を plugin の bin と同じ
/// `target/<profile>/` に先にビルドしておく（`cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor`）。
/// 前提が欠けていれば skip せず失敗させる。委譲 cgroup と Landlock の欠如は `PRECONDITION FAILED` の 1 行目で見分けられる。
/// pull の失敗時は `production_binary_exec_real:` で始まる固定行で出す（429 は rate limit と識別）。
/// CI では `platform-ci`（ubuntu）が委譲スコープの中で実行する。実機の crictl での確認は人間担当（#3730 の子）。実行例:
/// `systemd-run --user --scope -p Delegate=yes cargo test -p fandhe-container-plugin-cri --test cri_exec_real -- --ignored --exact production_binary_exec_real`
#[tokio::test]
#[ignore = "requires systemd --user delegated scope, supervisor bin, Landlock ABI 6+, and outbound HTTPS to a registry (CRI-6/SEC-1, #3762)"]
async fn production_binary_exec_real() {
    let started = Instant::now();
    tokio::time::timeout(WATCHDOG, async {
        // 前提欠如は plugin を起動する前に 1 行目で見分けられる形で失敗させる（skip しない）。
        let _cgroup = precondition::delegated_cgroup();
        let _landlock = precondition::landlock_support();
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .unwrap_or_else(|| panic!("production_binary_exec_real: XDG_RUNTIME_DIR is not set"));
        assert!(
            PathBuf::from(xdg).is_absolute(),
            "XDG_RUNTIME_DIR must be absolute"
        );

        let dir = TempDir::new("sock");
        let sock = dir.0.join("s.sock");
        let (bin_dir, plugin_bin) = production_bin_dir("bin");
        let _keep_bin_dir = &bin_dir;
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock);
        let config = GrpcClientConfig::new()
            .with_request_timeout(Duration::from_secs(600))
            .expect("request timeout");
        let ch = connect_when_ready_with(&sock, &mut guard, config).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let mut images = ImageServiceClient::new(ch.clone());
        // 段 4 が plugin-cri を殺して再起動するため、起動中の plugin-cri と接続は共有の入れ物に置く。
        let srv: SharedSrv = std::sync::Arc::new(std::sync::Mutex::new(Srv {
            guard,
            ch: ch.clone(),
        }));
        let sock2 = dir.0.join("b.sock");
        let r1_sock = dir.0.join("r1.sock");
        let r2_sock = dir.0.join("r2.sock");

        if let Err(st) = pull_image_raw(&mut images, IMAGE, PULL_DEADLINE).await {
            let line = pull_failure_line(&st);
            eprintln!("{line}");
            panic!("pull image: {line}");
        }

        let token = reclaim::run_token();
        let ledger = reclaim::Ledger::default();

        // 試行 1（注入）: StartContainer の直後に固定文言で panic させ、回収が効くことを確かめる。
        let b1 = reclaim::scenario_budget(started.elapsed(), WATCHDOG, 4)
            .min(reclaim::INJECT_ATTEMPT_LIMIT);
        let r1 = reclaim::guarded(
            scenario(
                c.clone(),
                token.clone(),
                ledger.clone(),
                true,
                srv.clone(),
                plugin_bin.clone(),
                sock2.clone(),
            ),
            b1,
        )
        .await;
        let exited = lock_srv(&srv).guard.exited().is_some();
        let rr1 = reclaim::reclaim_restarting(&mut c, &ledger, &token, exited, async || {
            restart_plugin(&srv, &plugin_bin, &r1_sock).await
        })
        .await;
        let rep1 = rr1.final_report();
        if let Some(line) = reclaim::left_line(TEST, rep1) {
            eprintln!("{line}");
        }
        match r1 {
            Err(reclaim::AttemptFailure::Panicked(p)) if reclaim::is_injected(TEST, p.as_ref()) => {
            }
            Err(reclaim::AttemptFailure::Panicked(p)) => std::panic::resume_unwind(p),
            Err(reclaim::AttemptFailure::Deadline) => {
                panic!("{TEST}: injected attempt exceeded its deadline")
            }
            Ok(()) => panic!("{TEST}: injected attempt did not fail"),
        }
        // 注入で plugin-cri が死んでいるので、起動し直して回収したことを具体値で照合する（#4326）。
        assert!(rr1.restarted(), "{rr1:?}");
        assert!(reclaim::plugin_unreachable(&rr1.first), "{rr1:?}");
        assert_eq!(rep1.reclaimed_containers.len(), 1, "{rr1:?}");
        assert_eq!(rep1.reclaimed_sandboxes.len(), 1, "{rr1:?}");
        assert!(rep1.is_clean(), "{rr1:?}");
        let old_c = rep1.reclaimed_containers[0].clone();
        let old_s = rep1.reclaimed_sandboxes[0].clone();
        let st = call_with_deadline(
            c.container_status(cri::ContainerStatusRequest {
                container_id: old_c,
                verbose: false,
            }),
            RPC_DEADLINE,
        )
        .await
        .expect_err("reclaimed container must be gone");
        assert_eq!(st.code(), PluginErrorCode::NotFound);
        let st = call_with_deadline(
            c.pod_sandbox_status(cri::PodSandboxStatusRequest {
                pod_sandbox_id: old_s,
                verbose: false,
            }),
            RPC_DEADLINE,
        )
        .await
        .expect_err("reclaimed sandbox must be gone");
        assert_eq!(st.code(), PluginErrorCode::NotFound);
        let want =
            format!("{TEST}: plugin restarted for reclaim reclaimed containers=1 sandboxes=1");
        assert_eq!(
            reclaim::restart_reclaim_line(TEST, &rr1),
            Some(want.clone())
        );
        // libtest の出力捕捉を迂回して CI の `--require` で照合できるようにする。
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "{want}");
        }
        eprintln!("{TEST}: injected failure reclaimed containers=1 sandboxes=1");

        // 試行 2（本番）: 同じトークン（同じ metadata）で最後まで通す。回収が効いていなければ ALREADY_EXISTS で落ちる。
        let b2 = reclaim::scenario_budget(started.elapsed(), WATCHDOG, 2)
            .saturating_sub(STARTUP_DEADLINE);
        let r2 = reclaim::guarded(
            scenario(
                c.clone(),
                token.clone(),
                ledger.clone(),
                false,
                srv.clone(),
                plugin_bin.clone(),
                sock2.clone(),
            ),
            b2,
        )
        .await;
        // 段 4 の後は plugin-cri が再起動済みなので、回収は共有の入れ物の最新の接続で行う（死んでいれば起動し直す。#4326）。
        let mut c = RuntimeServiceClient::new(lock_srv(&srv).ch.clone());
        let exited = lock_srv(&srv).guard.exited().is_some();
        let rr2 = reclaim::reclaim_restarting(&mut c, &ledger, &token, exited, async || {
            restart_plugin(&srv, &plugin_bin, &r2_sock).await
        })
        .await;
        let rep2 = rr2.final_report();
        if let Some(line) = reclaim::left_line(TEST, rep2) {
            eprintln!("{line}");
        }
        match r2 {
            // 成功時だけ「plugin が生きたまま」を確かめる。失敗・期限切れの回は起動し直しが正当なので、
            // 先に下の失敗の報告（deadline 等）を出す。
            Ok(()) => assert!(
                !rr2.restarted(),
                "plugin must be alive after scenario: {rr2:?}"
            ),
            Err(reclaim::AttemptFailure::Panicked(p)) => std::panic::resume_unwind(p),
            Err(reclaim::AttemptFailure::Deadline) => {
                panic!("{TEST}: scenario deadline exceeded")
            }
        }
        assert_eq!(
            *rep2,
            reclaim::ReclaimReport {
                token: token.clone(),
                ..reclaim::ReclaimReport::default()
            },
            "nothing may be left to reclaim"
        );
        drop((c, images, ch));
        assert!(
            lock_srv(&srv).guard.exited().is_none(),
            "server must still be running"
        );
    })
    .await
    .expect("watchdog");
}

// ---- 既定の集合で走る自己照合 ----

/// 前提欠如メッセージの形式と分類の自己照合（REPAIR-12）。
#[test]
fn repair12_precondition_self_check() {
    precondition::self_check();
}

/// 期待マスクのリテラルを core の `OCI_DEFAULT_CAPABILITIES` から導いた値と突き合わせる（リテラルの打ち間違いで
/// 試験が弱まるのを防ぐ。SEC-1・#3762）。
#[test]
fn sec1_3762_oci_default_mask_literal_matches_core() {
    use fandhe_container_core::capabilities::OCI_DEFAULT_CAPABILITIES;
    let derived = OCI_DEFAULT_CAPABILITIES
        .iter()
        .fold(0u64, |m, c| m | (1u64 << c.index()));
    assert_eq!(derived, OCI_DEFAULT_MASK, "derived {derived:#x}");
}

/// `/proc/<pid>/status` の解析が固定の入力から具体値を読めること（SEC-1・#3762）。
#[test]
fn sec1_3762_status_parser_reads_cap_and_seccomp() {
    let text = "Name:\tcat\nCapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\nCapAmb:\t0000000000000000\nSeccomp:\t2\n";
    let m = parse_status(text);
    assert_eq!(m.get("Name").map(String::as_str), Some("cat"));
    assert_eq!(hex_field(&m, "CapEff"), 0xa804_25fb);
    assert_eq!(hex_field(&m, "CapInh"), 0);
    assert_eq!(m.get("Seccomp").map(String::as_str), Some("2"));
}
