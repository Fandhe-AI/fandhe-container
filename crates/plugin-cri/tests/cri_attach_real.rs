//! plugin-cri の本番バイナリ越しに、実コンテナへの完全版 CRI Attach（stdin・stdin_once・tty・resize）を通す実機前提試験
//! （CRI-6・SUP-4・SEC-1・REPAIR-5・REPAIR-12・TASK-63.3・#4079。設計は `docs/design/cri-streaming-server.md` の #3765、
//! 実装は #4069〜#4078）。
//!
//! 呼び出し文脈: 本番バイナリ（`main.rs` が `with_streaming` と本番の `SupervisorAttachBackend` を注入した構成）に対し、
//! UDS＋gRPC で `Attach` を呼んで URL を得て、client-go 相当の SPDY クライアント（`crates/cri/tests/support/spdy_client.rs`）で
//! 接続する。plugin は supervisor の制御チャネル kind 9 で fd（tty は pty master、非 tty は stdin pipe）と出力 tap を受け、
//! core の実コンテナ（busybox）の PID 1 の入出力へ中継する。既定の集合の偽 backend の試験
//! （`crates/cri/tests/streaming_attach.rs`・`supervisor_attach_boundary.rs`）は実コンテナを使わないため、次を本物で具体値に固定する。
//!
//! - 場面 A（非 tty・`stdin_once`）: `cat` へ送った入力が stdout にそのまま返ること、stdin の FIN で唯一の書き込み端が閉じて
//!   `cat` が EOF で終わること（Status `Success`・`CONTAINER_EXITED`・終了コード 0）、終了後の Attach の `FAILED_PRECONDITION`
//! - 場面 B（tty）: tty の不一致の拒否（D7。`MSG_ATTACH_TTY_MISMATCH`）、`echo` の往復、resize の反映（`stty size` の出力が
//!   送った寸法と一致）、`exit` による終了
//!
//! 失敗後の残骸の回収（#4142）: 本体を 2 回走らせる（1 回目は場面 A の StartContainer の直後に注入した失敗、回収、2 回目は同じ metadata で通す）。
//! 注入では plugin-cri を SIGKILL してから panic させ、外側の回収が死活を判定して起動し直して回収する（#4326。共有部品 `reclaim_restarting`）。
//! 回収の部品は `support/cri_real_reclaim.rs`。
//!
//! ハーネスは `cri_exec_real.rs` と同じものを最小化して複製した（試験 crate 間でモジュールを共有できないため）。
//!
//! 残余（REPAIR-3）: 実 crictl（`crictl attach -i -t`）・kubectl での確認は人間担当（#3730 の子）。`StdinNotOpen` は
//! 既定の集合（`crates/cri/tests/streaming_attach.rs`）で照合済みのため扱わない。attach の Status は終了コードを持たないので、
//! 終了コードは、`StopContainer` を送らずに CRI が自然終了を観測して exited にした後の `ContainerStatus` で見る
//! （`ContainerStatus`・`ListContainers` は running の記録について実行層の状態を読む。#4174・#4175・CRI-1・CRI-2）。
//!
//! Linux 限定の理由: 本番の既定の状態ルート・supervisor・Landlock・cgroup v2・pty は Linux でだけ成り立つ（`cri_exec_real.rs` と同じ）。

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
const TEST: &str = "production_binary_attach_real";
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
const RPC_DEADLINE: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(5);
/// StopContainer を送らずに自然終了の観測（exited）を待つ上限（#4175。試験の watchdog より十分短い）。
const NATURAL_EXIT_DEADLINE: Duration = Duration::from_secs(30);
/// pull の期限（ImageService の pull 期限 540 秒に収まる範囲）。
const PULL_DEADLINE: Duration = Duration::from_secs(300);
/// 試験全体の上限。CI の補助の期限（540 秒）より先に効かせる（REPAIR-5）。
const WATCHDOG: Duration = Duration::from_secs(480);
/// SPDY の読み取り期限（1 フレームあたり）。出力待ちの全体期限は `OUTPUT_DEADLINE`。
const SPDY_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
/// rootful 経路に入るため、置かないことも assert する。attach 用の制御チャネルは plugin と同じディレクトリの supervisor を起動する。
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
    let test = "production_binary_attach_real";
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
const ATTACH_VERSIONS: [&str; 3] = [
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
];
/// 出力待ち・状態照会の全体期限（REPAIR-5）。
const OUTPUT_DEADLINE: Duration = Duration::from_secs(60);
// ---- 補助 ----

/// resize ストリームへ送る JSON（kubelet の `TerminalSize`。キーは `Width`・`Height`）。
fn resize_json(width: u16, height: u16) -> Vec<u8> {
    format!("{{\"Width\":{width},\"Height\":{height}}}").into_bytes()
}

/// `haystack` の中に `needle` が含まれるか。
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// ストリーム `id` の `from` バイト目以降に `needle` が現れるまで読み、現在の長さを返す。期限を超えたら失敗にする
/// （REPAIR-5。失敗文は長さとストリーム ID だけで、出力本文は出さない）。
fn read_until_contains(s: &mut Spdy, id: u32, from: usize, needle: &[u8]) -> usize {
    let start = Instant::now();
    loop {
        let buf = s.data.get(&id).map(Vec::as_slice).unwrap_or_default();
        if contains(buf.get(from..).unwrap_or_default(), needle) {
            return buf.len();
        }
        assert!(
            start.elapsed() < OUTPUT_DEADLINE,
            "expected output did not arrive on stream {id} (received {} bytes)",
            buf.len()
        );
        s.pump_one();
    }
}

fn attach_request(
    id: &str,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    tty: bool,
) -> cri::AttachRequest {
    cri::AttachRequest {
        container_id: id.into(),
        stdin,
        tty,
        stdout,
        stderr,
    }
}

/// `Attach` RPC で URL を得る（loopback であることも確認する）。
async fn attach_url(c: &mut RuntimeServiceClient<Channel>, req: cri::AttachRequest) -> String {
    let url = call_with_deadline(c.attach(req), RPC_DEADLINE)
        .await
        .expect("attach rpc")
        .into_inner()
        .url;
    assert!(url.starts_with("http://127.0.0.1:"), "url: {url}");
    url
}

fn connect_spdy(url: &str) -> Spdy {
    let (authority, path) = split_url(url);
    let addr: SocketAddr = authority.parse().expect("authority");
    let s = Spdy::connect(addr, &path, &ATTACH_VERSIONS, "v4.channel.k8s.io");
    s.tcp
        .set_read_timeout(Some(SPDY_READ_TIMEOUT))
        .expect("read timeout");
    s
}

async fn container_status(c: &mut RuntimeServiceClient<Channel>, id: &str) -> cri::ContainerStatus {
    call_with_deadline(
        c.container_status(cri::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("status")
    .into_inner()
    .status
    .expect("status body")
}

/// セッションが終わった（tap の EOF = コンテナの終了）後、`StopContainer` を送らずに CRI が自然終了を観測するのを
/// 待ち、`CONTAINER_EXITED` の `ContainerStatus` を返す（#4174・#4175。CRI-1・CRI-2・REPAIR-12）。
///
/// `ContainerStatus` は running の記録について実行層の状態を期限つきで読み、停止済みなら終了コードを取り込む。
/// 取り込みが 1 回で済まないことがあるため、期限（[`NATURAL_EXIT_DEADLINE`]）つきで繰り返し読む。
/// `StopContainer` を送らないので、SIGTERM で止まった可能性が無く、終了コード 0 の照合が「EOF / `exit` で自然に
/// 終わった」ことのより強い証拠になる。期限内に exited にならなければ失敗する。
async fn wait_natural_exit(
    c: &mut RuntimeServiceClient<Channel>,
    id: &str,
) -> cri::ContainerStatus {
    let deadline = Instant::now() + NATURAL_EXIT_DEADLINE;
    loop {
        let st = container_status(c, id).await;
        if st.state == cri::ContainerState::ContainerExited as i32 {
            return st;
        }
        assert!(
            Instant::now() < deadline,
            "container must be observed as exited without StopContainer"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// 自然終了の観測の後の照合（`ListContainers` の EXITED フィルタに 1 件だけ返ること、続く `StopContainer` が
/// 冪等に成功して終了コード・終了時刻が変わらないこと）をまとめて行い、終了コードを返す（#4175・E2 の本番経路での確認）。
async fn exited_exit_code(c: &mut RuntimeServiceClient<Channel>, id: &str) -> i32 {
    // ContainerStatus より先に、EXITED フィルタの ListContainers だけで自然終了が検知されることを期限つきで確かめる
    // （List の観測を外すとこの段が期限切れで失敗する。#4175・REPAIR-12）。
    let deadline = Instant::now() + NATURAL_EXIT_DEADLINE;
    loop {
        let listed = call_with_deadline(
            c.list_containers(cri::ListContainersRequest {
                filter: Some(cri::ContainerFilter {
                    id: id.into(),
                    state: Some(cri::ContainerStateValue {
                        state: cri::ContainerState::ContainerExited as i32,
                    }),
                    ..Default::default()
                }),
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("list")
        .into_inner()
        .containers;
        if !listed.is_empty() {
            assert_eq!(
                listed.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
                vec![id],
                "ListContainers with the EXITED filter must return the naturally exited container"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ListContainers with the EXITED filter must observe the natural exit without StopContainer"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let observed = wait_natural_exit(c, id).await;
    call_with_deadline(
        c.stop_container(cri::StopContainerRequest {
            container_id: id.into(),
            timeout: 2,
        }),
        Duration::from_secs(120),
    )
    .await
    .expect("idempotent stop after natural exit");
    let after = container_status(c, id).await;
    assert_eq!(
        (after.state, after.exit_code, after.finished_at),
        (observed.state, observed.exit_code, observed.finished_at),
        "StopContainer after the observed exit must not change the recorded values"
    );
    observed.exit_code
}

async fn create_and_start(
    c: &mut RuntimeServiceClient<Channel>,
    (token, ledger): (&str, &reclaim::Ledger),
    sb: &str,
    name: &str,
    cmd: &str,
    (stdin, stdin_once, tty): (bool, bool, bool),
) -> String {
    let long = Duration::from_secs(120);
    let id = call_with_deadline(
        c.create_container(cri::CreateContainerRequest {
            pod_sandbox_id: sb.into(),
            config: Some(cri::ContainerConfig {
                metadata: Some(cri::ContainerMetadata {
                    name: name.into(),
                    attempt: 0,
                }),
                image: Some(image_spec(IMAGE)),
                command: vec![cmd.into()],
                labels: reclaim::config_labels(TEST, token),
                stdin,
                stdin_once,
                tty,
                ..Default::default()
            }),
            sandbox_config: None,
        }),
        long,
    )
    .await
    .expect("create")
    .into_inner()
    .container_id;
    reclaim::record_container(ledger, &id);
    call_with_deadline(
        c.start_container(cri::StartContainerRequest {
            container_id: id.clone(),
        }),
        long,
    )
    .await
    .expect("start");
    let st = container_status(c, &id).await;
    assert_eq!(st.state, cri::ContainerState::ContainerRunning as i32);
    id
}

async fn remove(c: &mut RuntimeServiceClient<Channel>, ledger: &reclaim::Ledger, id: &str) {
    call_with_deadline(
        c.remove_container(cri::RemoveContainerRequest {
            container_id: id.into(),
        }),
        Duration::from_secs(120),
    )
    .await
    .expect("remove");
    reclaim::forget_container(ledger, id);
}

fn status_str<'a>(j: &'a mini_json::Json, key: &str) -> &'a str {
    j.get(key)
        .and_then(mini_json::Json::as_str)
        .unwrap_or_else(|| panic!("status has no string {key}: {j:?}"))
}

/// error ストリームを FIN まで読み、Status が `Success` で GOAWAY が OK であることを確認する。
fn assert_success_end(s: &mut Spdy, error: u32) {
    let raw = s.read_until_fin(error);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = mini_json::parse(&text).unwrap_or_else(|| panic!("status is not JSON: {text}"));
    assert_eq!(status_str(&status, "status"), "Success", "{status:?}");
    assert_eq!(s.wait_goaway(), goaway_status::OK);
}

/// 起動中の plugin-cri とその接続。注入で plugin-cri を殺し、外側の回収が起動し直すため、本体と外側で共有する（#4326）。
struct Srv {
    guard: ChildGuard,
}

type SharedSrv = std::sync::Arc<std::sync::Mutex<Srv>>;

/// 共有の `Srv` を取る（保持したまま await しない。poison は試験の失敗なので素通しで取り出す）。
fn lock_srv(srv: &SharedSrv) -> std::sync::MutexGuard<'_, Srv> {
    srv.lock().unwrap_or_else(|e| e.into_inner())
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

/// 外側の回収が呼ぶ起動し直し（#4326）。旧 plugin-cri を kill・回収して `.cri/@instance.lock` を解放してから、
/// `sock` で起動し直して接続し、共有の `srv` を差し替えて新しい client を返す。`srv` の lock は await をまたがない。
async fn restart_plugin(srv: &SharedSrv, bin: &Path, sock: &Path) -> RuntimeServiceClient<Channel> {
    kill_and_reap(&mut lock_srv(srv).guard);
    let mut guard = spawn_server_inherit_env(bin, sock);
    let config = GrpcClientConfig::new()
        .with_request_timeout(Duration::from_secs(600))
        .expect("request timeout");
    let ch = connect_when_ready_with(sock, &mut guard, config).await;
    *lock_srv(srv) = Srv { guard };
    RuntimeServiceClient::new(ch)
}

/// 試験本体（sandbox の作成から場面 A・B の照合・後始末まで）。`inject` が真なら場面 A の StartContainer の直後に固定文言で
/// panic する（失敗後の回収の自己照合。#4142）。作った ID は台帳へ登録し、Remove が成功したら外す。
async fn scenario(
    mut c: RuntimeServiceClient<Channel>,
    token: String,
    ledger: reclaim::Ledger,
    inject: bool,
    srv: SharedSrv,
) {
    let mut run = cri::RunPodSandboxRequest {
        config: Some(cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: "pod-attach-real".into(),
                uid: reclaim::sandbox_uid("uid-attach", &token),
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
    let long = Duration::from_secs(120);
    let sb = call_with_deadline(c.run_pod_sandbox(run), RPC_DEADLINE)
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;
    reclaim::record_sandbox(&ledger, &sb);

    // ---- 場面 A: 非 tty・stdin_once（往復と EOF） ----
    let id = create_and_start(
        &mut c,
        (&token, &ledger),
        &sb,
        "cat",
        "/bin/cat",
        (true, true, false),
    )
    .await;
    if inject {
        // plugin-cri が予期せず死んだ場面を作る（#4326）。外側の回収が起動し直して回収する。
        kill_and_reap(&mut lock_srv(&srv).guard);
        panic!("{}", reclaim::injected_message(TEST));
    }
    let url = attach_url(&mut c, attach_request(&id, true, true, true, false)).await;
    let join = tokio::task::spawn_blocking(move || {
        let mut s = connect_spdy(&url);
        // client-go の順（error → stdin → stdout → stderr）で張る。
        let error = s.create_stream(&[("streamtype", "error")]);
        let stdin = s.create_stream(&[("streamtype", "stdin")]);
        let stdout = s.create_stream(&[("streamtype", "stdout")]);
        let stderr = s.create_stream(&[("streamtype", "stderr")]);
        s.send_data(stdin, b"hello attach\n", false);
        read_until_contains(&mut s, stdout, 0, b"hello attach\n");
        assert_eq!(
            s.data.get(&stdout).map(Vec::as_slice),
            Some(&b"hello attach\n"[..])
        );
        // stdin の FIN で唯一の書き込み端が閉じ、cat が EOF で終わる。
        s.send_data(stdin, b"", true);
        assert_success_end(&mut s, error);
        assert!(
            s.data.get(&stderr).is_none_or(Vec::is_empty),
            "stderr must be empty"
        );
    });
    tokio::time::timeout(Duration::from_secs(120), join)
        .await
        .expect("scene A deadline")
        .expect("scene A join");
    assert_eq!(exited_exit_code(&mut c, &id).await, 0);
    let st = call_with_deadline(
        c.attach(attach_request(&id, true, true, true, false)),
        RPC_DEADLINE,
    )
    .await
    .expect_err("attach to an exited container");
    assert_eq!(st.code(), PluginErrorCode::FailedPrecondition);
    remove(&mut c, &ledger, &id).await;

    // ---- 場面 B: tty（往復と resize） ----
    let id = create_and_start(
        &mut c,
        (&token, &ledger),
        &sb,
        "sh",
        "/bin/sh",
        (true, false, true),
    )
    .await;
    // D7: tty の不一致は記録と照合して拒否する。
    let st = call_with_deadline(
        c.attach(attach_request(&id, true, true, true, false)),
        RPC_DEADLINE,
    )
    .await
    .expect_err("tty mismatch");
    assert_eq!(st.code(), PluginErrorCode::FailedPrecondition);
    assert_eq!(
        st.message(),
        fandhe_container_cri::streaming::MSG_ATTACH_TTY_MISMATCH
    );
    // tty では stderr を真にできない（INVALID_ARGUMENT）ため偽にする。
    let url = attach_url(&mut c, attach_request(&id, true, true, false, true)).await;
    let join = tokio::task::spawn_blocking(move || {
        let mut s = connect_spdy(&url);
        let error = s.create_stream(&[("streamtype", "error")]);
        let stdin = s.create_stream(&[("streamtype", "stdin")]);
        let stdout = s.create_stream(&[("streamtype", "stdout")]);
        let resize = s.create_stream(&[("streamtype", "resize")]);
        // 往復: pty の行規律が入力をエコーするため、シェルの実行結果 `ab3cd` だけで判定する。
        s.send_data(stdin, b"echo ab$((1+2))cd\n", false);
        let mut pos = read_until_contains(&mut s, stdout, 0, b"ab3cd");
        // resize の反映: 寸法を送ってから `stty size` の出力（行 列）を照合する。
        for (w, h) in [(100u16, 30u16), (120, 40)] {
            s.send_data(resize, &resize_json(w, h), false);
            s.send_data(stdin, b"stty size\n", false);
            let want = format!("{h} {w}");
            pos = read_until_contains(&mut s, stdout, pos, want.as_bytes());
        }
        s.send_data(stdin, b"exit\n", false);
        assert_success_end(&mut s, error);
    });
    tokio::time::timeout(Duration::from_secs(120), join)
        .await
        .expect("scene B deadline")
        .expect("scene B join");
    assert_eq!(exited_exit_code(&mut c, &id).await, 0);
    remove(&mut c, &ledger, &id).await;

    // 後始末（成功経路）。照合は自分の sandbox とトークンのラベルで絞る（他の記録の有無には依らない）。
    let left = call_with_deadline(
        c.list_containers(cri::ListContainersRequest {
            filter: Some(cri::ContainerFilter {
                pod_sandbox_id: sb.clone(),
                label_selector: reclaim::labels(&token),
                ..Default::default()
            }),
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("list containers")
    .into_inner()
    .containers
    .len();
    assert_eq!(left, 0);
    call_with_deadline(
        c.stop_pod_sandbox(cri::StopPodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
        long,
    )
    .await
    .expect("stop sandbox");
    call_with_deadline(
        c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
        long,
    )
    .await
    .expect("remove sandbox");
    reclaim::forget_sandbox(&ledger, &sb);
    let left_sb = call_with_deadline(
        c.list_pod_sandbox(cri::ListPodSandboxRequest {
            filter: Some(cri::PodSandboxFilter {
                label_selector: reclaim::labels(&token),
                ..Default::default()
            }),
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("list sandboxes")
    .into_inner()
    .items
    .len();
    assert_eq!(left_sb, 0);
}

/// 段階（本番バイナリ越しの実コンテナへの完全版 attach）。
///
/// 失敗後の回収（#4142）: 本体（[`scenario`]）を 2 回走らせる。1 回目は場面 A の StartContainer の直後に固定文言で panic させ
/// （注入）、回収が `containers=1 sandboxes=1 left=0` で旧 ID を `NOT_FOUND` にすることを照合する。2 回目は同じ metadata で
/// 場面 A・B を最後まで通し、`ALREADY_EXISTS` にならないことを機械照合する。回収にも失敗したら残った ID と回収手順の
/// 文書を 1 行で出す（uid にトークンが入るので次の実行は守られる）。
///
/// `#[ignore]` の理由（既定の集合から分ける）: (1) StartContainer と Attach は supervisor 経由の本番経路で、`systemd --user` の
/// 委譲 cgroup scope の中で動かす必要がある（Landlock ABI 6 以上・user manager の private ソケット・`XDG_RUNTIME_DIR` も要る）、
/// (2) 外向き HTTPS で実レジストリ（Docker Hub）から取得する、(3) supervisor の bin を plugin の bin と同じ
/// `target/<profile>/` に先にビルドしておく（`cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor`）。
/// 前提が欠けていれば skip せず失敗させる。pull の失敗時は `production_binary_attach_real:` で始まる固定行で出す。
/// CI では `platform-ci`（ubuntu）が委譲スコープの中で実行する。実行例:
/// `systemd-run --user --scope -p Delegate=yes cargo test -p fandhe-container-plugin-cri --test cri_attach_real -- --ignored --exact production_binary_attach_real`
#[tokio::test]
#[ignore = "requires systemd --user delegated scope, supervisor bin, Landlock ABI 6+, and outbound HTTPS to a registry (CRI-6/SUP-4/SEC-1, #4079)"]
async fn production_binary_attach_real() {
    let started = Instant::now();
    tokio::time::timeout(WATCHDOG, async {
        let _cgroup = precondition::delegated_cgroup();
        let _landlock = precondition::landlock_support();
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .unwrap_or_else(|| panic!("production_binary_attach_real: XDG_RUNTIME_DIR is not set"));
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
        // 注入で plugin-cri を殺して起動し直すため、起動中の plugin-cri と接続は共有の入れ物に置く。
        let srv: SharedSrv = std::sync::Arc::new(std::sync::Mutex::new(Srv { guard }));
        let r1_sock = dir.0.join("r1.sock");
        let r2_sock = dir.0.join("r2.sock");

        if let Err(st) = pull_image_raw(&mut images, IMAGE, PULL_DEADLINE).await {
            let line = pull_failure_line(&st);
            eprintln!("{line}");
            panic!("pull image: {line}");
        }

        let token = reclaim::run_token();
        let ledger = reclaim::Ledger::default();

        // 試行 1（注入）: 場面 A の StartContainer の直後に固定文言で panic させ、回収が効くことを確かめる。
        // 試行 1 が確保するのは自分の回収（再起動を含め 2 回）分だけにする。試行 2 の分は試行 2 の直前に
        // 経過を差し引いて確保するため、ここで先取りすると pull が長引いたときに注入の期限が 0 になる。
        let b1 = reclaim::scenario_budget(started.elapsed(), WATCHDOG, 2)
            .min(reclaim::INJECT_ATTEMPT_LIMIT);
        let r1 = reclaim::guarded(
            scenario(c.clone(), token.clone(), ledger.clone(), true, srv.clone()),
            b1,
        )
        .await;
        let rr1 = reclaim::reclaim_restarting(
            &mut c,
            &ledger,
            &token,
            || lock_srv(&srv).guard.exited().is_some(),
            async || restart_plugin(&srv, &plugin_bin, &r1_sock).await,
        )
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
        // `std::io::stderr()` への直接書き込みは libtest の出力捕捉（`print!` / `eprintln!` 系のみが対象）を受けないため、
        // `--nocapture` なしの CI でも `--require` で照合できる。
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "{want}");
        }
        eprintln!("{TEST}: injected failure reclaimed containers=1 sandboxes=1");

        // 試行 2（本番）: 同じトークン（同じ metadata）で場面 A・B を最後まで通す。回収が効いていなければ ALREADY_EXISTS で落ちる。
        // 試行 1 で PULL_DEADLINE 近くまで使っても 0 にならないよう下限を持つ（試行 2 の pull は取得済みで速い）。
        let b2 = reclaim::scenario_budget(started.elapsed(), WATCHDOG, 2)
            .saturating_sub(STARTUP_DEADLINE)
            .max(Duration::from_secs(30));
        let r2 = reclaim::guarded(
            scenario(c.clone(), token.clone(), ledger.clone(), false, srv.clone()),
            b2,
        )
        .await;
        let rr2 = reclaim::reclaim_restarting(
            &mut c,
            &ledger,
            &token,
            || lock_srv(&srv).guard.exited().is_some(),
            async || restart_plugin(&srv, &plugin_bin, &r2_sock).await,
        )
        .await;
        let rep2 = rr2.final_report();
        if let Some(line) = reclaim::left_line(TEST, rep2) {
            eprintln!("{line}");
        }
        assert!(
            !rr2.restarted(),
            "plugin must be alive after scenario: {rr2:?}"
        );
        match r2 {
            Ok(()) => {}
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

/// 包含判定が tty のエコー混じりの出力から結果だけを見分けること（REPAIR-12・#4079）。
#[test]
fn cri6_4079_contains_helper_matches_tty_output() {
    let echoed_and_result = b"echo ab$((1+2))cd\r\nab3cd\r\n/ # ";
    assert!(contains(echoed_and_result, b"ab3cd"));
    assert!(!contains(b"echo ab$((1+2))cd\r\n", b"ab3cd"));
    assert!(contains(b"stty size\r\n30 100\r\n", b"30 100"));
    assert!(!contains(b"", b"30 100"));
}

/// resize の JSON が kubelet の `TerminalSize` と同じキーで出ること（CRI-6・#4079）。
#[test]
fn cri6_4079_resize_json_literal() {
    assert_eq!(resize_json(100, 30), br#"{"Width":100,"Height":30}"#);
}
