//! plugin 境界越しの CRI 統合結合テスト
//! （TASK-114.5・#461・PLUG-1・PLUG-12・CRI-2・CRI-7・REPAIR-5・REPAIR-12）。
//!
//! 実バイナリ `fandhe-container-plugin-cri` を絶対パスで spawn し、core 側クライアント相当の
//! `connect_uds_channel`（同一 UID・peer UID 検証つき）で接続する。確かめる内容は 2 つ。
//!
//! - 既定集合の試験 A: socket が 0600・所有者一致・配置ディレクトリが 0700 であること（PLUG-12 の前提）と、
//!   正規クライアントから PodSandbox の一連のライフサイクルが成功し、拒否の監査行が 0 件であること。
//! - 実機前提（`#[ignore]`）の試験 B: 別 UID の connector が plugin-cri 側の peer credential 検証で
//!   1 バイトも受け取らず切断され、拒否の監査行が出て、その後も同一 UID の接続が成功すること。
//!   別 UID のプロセスは root 権限なしに用意できないため分離している（手順は `AGENTS.md`「実機前提テスト」）。
//!
//! 未達（REPAIR-3）: コンテナ系 RPC の実バイナリ越しの成功は本番の `BundleProvider`（#2433）と
//! start / stop の結線（#2434）の後に成功経路へ切り替える。それまでは `tests/container_grpc.rs` の
//! 段 B（フェイクの実行層）が一連を照合している。切り替え時はこのファイルに Container 系の一連を足す。
//!
//! ハーネス（TempDir・Server 等）は試験 crate 間でモジュールを共有できないため
//! `tests/pod_sandbox_grpc.rs` から最小限を複製している。
//!
//! Linux 限定の理由: `CriPluginBackends::production()` の既定の状態ルートは Linux（ゲスト）でだけ
//! 定義され、macOS / Windows では `Unimplemented` になるため（`tests/adapter.rs` と同じ扱い）。

#![cfg(target_os = "linux")]

// 残骸・PID 再利用と衝突しない排他作成の補助（REPAIR-12・#3435）。
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_plugin::grpc::{GrpcClientConfig, call_with_deadline, connect_uds_channel};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginErrorCode};
use fandhe_container_plugin_cri::telemetry::AUDIT_DRAIN_INTERVAL;
use tonic::transport::Channel;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const WATCHDOG: Duration = Duration::from_secs(60);
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
const RPC_DEADLINE: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(5);
const CONNECTOR_DEADLINE: Duration = Duration::from_secs(10);
const AUDIT_LINE_DEADLINE: Duration = Duration::from_secs(10);
const OTHER_UID_CONNECT_CMD_ENV: &str = "FANDHE_CONTAINER_TEST_OTHER_UID_CONNECT_CMD";

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // 残骸・PID 再利用との衝突を避ける排他作成（既存のパスは消さず連番を進める。REPAIR-12・#3435）。
        // 別 UID（root）の `#[ignore]` の場面を持つ試験があるため、予測できる名前を消す補助は使わない。
        Self(exclusive_dir::create(&format!("fcit-{tag}")).expect("create temp dir"))
    }

    fn owner_uid(&self) -> u32 {
        std::fs::metadata(&self.0).expect("stat temp dir").uid()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 起動した plugin-cri。Drop で kill し、期限つきで回収する（REPAIR-5）。
/// stderr（監査行）は背景 thread が 1 行ずつ `lines` へ送る。
struct Server {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

/// サーバーが監査を書く `@audit.log` の場所（`StateRoot::resolve(None)` と同じ規則。root は `/run/fandhe-container`、
/// それ以外は `$XDG_RUNTIME_DIR/fandhe-container`。#2484）。
fn audit_log_path(xdg: &Path, euid: u32) -> PathBuf {
    if euid == 0 {
        PathBuf::from("/run/fandhe-container/@audit.log")
    } else {
        xdg.join("fandhe-container").join("@audit.log")
    }
}

impl Server {
    fn spawn(sock: &Path, xdg: &Path) -> Self {
        let mut child = Command::new(BIN)
            .arg("--socket")
            .arg(sock)
            .env_clear()
            .env("XDG_RUNTIME_DIR", xdg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn plugin binary");
        let stderr = child.stderr.take().expect("stderr piped");
        let (tx, lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// 届いている stderr の行を `seen` へ取り込む（待たない）。
    fn collect_lines(&mut self) {
        while let Ok(l) = self.lines.try_recv() {
            self.seen.push(l);
        }
    }

    /// 期限まで stderr を受け取りながら、条件を満たす行が現れたら返す。
    fn wait_for_line(&mut self, deadline: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
        let start = Instant::now();
        loop {
            self.collect_lines();
            if let Some(l) = self.seen.iter().find(|l| pred(l)) {
                return Some(l.clone());
            }
            let left = deadline.saturating_sub(start.elapsed());
            if left.is_zero() {
                return None;
            }
            match self
                .lines
                .recv_timeout(left.min(Duration::from_millis(200)))
            {
                Ok(l) => self.seen.push(l),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let start = Instant::now();
        while start.elapsed() < REAP_GRACE {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// socket の出現と接続の成功を、全体の期限内で待つ。子が先に終了したら診断つきで失敗する。
async fn connect_when_ready(sock: &Path, server: &mut Server) -> Channel {
    let start = Instant::now();
    loop {
        if let Some(status) = server.exited() {
            std::thread::sleep(Duration::from_millis(100));
            server.collect_lines();
            panic!(
                "plugin binary exited early: {status:?}: {}",
                server.seen.join("\n")
            );
        }
        if sock.exists() {
            match connect_uds_channel(
                sock,
                &GrpcClientConfig::new(),
                Box::new(JsonLinesPeerAuthObserver::new()),
            )
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

fn run_req(name: &str) -> cri::RunPodSandboxRequest {
    cri::RunPodSandboxRequest {
        config: Some(cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: name.into(),
                uid: "uid-1".into(),
                namespace: "default".into(),
                attempt: 0,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// `call_with_deadline` の PluginError を gRPC コードへ戻して照合しやすくする。
fn into_status(e: fandhe_container_plugin::PluginError) -> tonic::Status {
    let code = match e.code() {
        PluginErrorCode::NotFound => tonic::Code::NotFound,
        PluginErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        PluginErrorCode::Timeout => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::Unknown,
    };
    tonic::Status::new(code, e.message().to_string())
}

async fn status_state(
    c: &mut RuntimeServiceClient<Channel>,
    id: &str,
) -> Result<i32, tonic::Status> {
    let r = call_with_deadline(
        c.pod_sandbox_status(cri::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .map_err(into_status)?;
    Ok(r.into_inner().status.expect("status").state)
}

/// Run → Status(Ready) → Stop → Status(NotReady) → Remove → Status(NotFound) を具体値で照合する。
async fn assert_pod_sandbox_lifecycle(ch: Channel, name: &str) {
    let mut c = RuntimeServiceClient::new(ch);
    let id = call_with_deadline(c.run_pod_sandbox(run_req(name)), RPC_DEADLINE)
        .await
        .expect("run")
        .into_inner()
        .pod_sandbox_id;
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        status_state(&mut c, &id).await.expect("status"),
        cri::PodSandboxState::SandboxReady as i32
    );
    call_with_deadline(
        c.stop_pod_sandbox(cri::StopPodSandboxRequest {
            pod_sandbox_id: id.clone(),
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("stop");
    assert_eq!(
        status_state(&mut c, &id).await.expect("status"),
        cri::PodSandboxState::SandboxNotready as i32
    );
    call_with_deadline(
        c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
            pod_sandbox_id: id.clone(),
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("remove");
    let st = status_state(&mut c, &id).await.expect_err("removed");
    assert_eq!(st.code(), tonic::Code::NotFound);
}

/// 試験 A: PLUG-12 の前提（socket 0600・所有者一致・配置ディレクトリ 0700）と、
/// 正規の core 側クライアント（同一 UID）からの一連の成功、および拒否の監査行が 0 件であること。
#[tokio::test]
async fn task114_5_legit_core_client_lifecycle_over_plug12_uds() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock");
        let xdg = TempDir::new("xdg");
        let sock = dir.0.join("s.sock");
        let mut server = Server::spawn(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, &mut server).await;

        let meta = std::fs::symlink_metadata(&sock).expect("stat socket");
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), dir.owner_uid());
        let dmeta = std::fs::metadata(&dir.0).expect("stat dir");
        assert_eq!(dmeta.mode() & 0o777, 0o700);

        assert_pod_sandbox_lifecycle(ch, "pod-legit").await;

        // drain 周期を 2 回跨いでも、正規クライアントに対する拒否の監査行は出ない。
        tokio::time::sleep(AUDIT_DRAIN_INTERVAL * 2 + Duration::from_millis(500)).await;
        server.collect_lines();
        let denied: Vec<&String> = server
            .seen
            .iter()
            .filter(|l| l.contains("\"event\":\"plugin_peer_auth\""))
            .collect();
        assert!(denied.is_empty(), "unexpected peer auth lines: {denied:?}");
        // 永続化側（@audit.log）にも、この socket への plugin_peer の記録は無い（#2484）。
        // 本番バイナリが監査の記録経路（relay）を起動前に作れた上で、一連が成功していることも兼ねて確かめる。
        let log =
            std::fs::read_to_string(audit_log_path(&xdg.0, dir.owner_uid())).unwrap_or_default();
        let sock_s = sock.to_str().expect("utf-8 socket path");
        assert!(
            !log.lines()
                .any(|l| l.contains("\"layer\":\"plugin_peer\"") && l.contains(sock_s)),
            "unexpected plugin_peer audit records: {log}"
        );
        assert!(server.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}

fn connector_path() -> PathBuf {
    let v = std::env::var_os(OTHER_UID_CONNECT_CMD_ENV)
        .unwrap_or_else(|| panic!("{OTHER_UID_CONNECT_CMD_ENV} must be set (see AGENTS.md)"));
    let p = PathBuf::from(v);
    assert!(p.is_absolute(), "connector path must be absolute");
    let meta = std::fs::metadata(&p).expect("connector command must exist");
    assert!(meta.is_file(), "connector command must be a regular file");
    p
}

/// 試験 B（実機前提）: 別 UID の connector は plugin-cri の peer credential 検証で切断され（受信 0 バイト）、
/// 拒否の監査行が出て、その後も同一 UID の接続で一連が成功する（PLUG-12・TASK-114.5）。
/// connector は絶対パスを直接起動する（PATH 探索・シェル・sudo なし）。準備は `AGENTS.md`「実機前提テスト」。
#[tokio::test]
#[ignore = "requires a connector running as another UID (root) prepared by a human; PLUG-12"]
async fn task114_5_plug12_rejects_other_uid_connection_to_cri_plugin() {
    tokio::time::timeout(WATCHDOG, async {
        let cmd = connector_path();
        let dir = TempDir::new("sock");
        let xdg = TempDir::new("xdg");
        let uid = dir.owner_uid();
        assert_ne!(uid, 0, "this test must run as a non-root user");
        let sock = dir.0.join("s.sock");
        let mut server = Server::spawn(&sock, &xdg.0);
        // 準備完了の確認を兼ねて、同一 UID の接続が成功することを先に確かめる。
        let ch = connect_when_ready(&sock, &mut server).await;
        drop(ch);

        // 回収不能時は同期 wait() で無期限に待たず panic で報告するため、zombie 警告を許可する（REPAIR-5）。
        #[allow(clippy::zombie_processes)]
        let mut child = Command::new(&cmd)
            .arg(&sock)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn the connector command");
        let mut stdout = child.stdout.take().expect("stdout piped");
        // 孫プロセスが stdout を保持すると read_to_end が戻らないため、期限つき recv で受け取る。
        let (tx, rx) = channel::<Vec<u8>>();
        let _reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });

        let deadline = Instant::now() + CONNECTOR_DEADLINE;
        let mut exited = false;
        while Instant::now() < deadline {
            if child.try_wait().expect("try_wait").is_some() {
                exited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !exited {
            // 強制終了後の回収にも期限を設ける（REPAIR-5）。同期 wait() は使わない。
            let kill_result = child.kill();
            let reap_deadline = Instant::now() + REAP_GRACE;
            let mut reaped = false;
            while Instant::now() < reap_deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    reaped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!(
                "connector did not exit after the connection was rejected \
                 (kill result: {kill_result:?}, reaped within grace: {reaped})"
            );
        }
        let received = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("connector stdout must be collected");
        assert_eq!(
            received.len(),
            0,
            "server must not send anything before peer auth"
        );

        let sock_s = sock.to_str().expect("utf-8 socket path").to_string();
        let line = server
            .wait_for_line(AUDIT_LINE_DEADLINE, |l| {
                l.contains("\"event\":\"plugin_peer_auth\"")
            })
            .unwrap_or_else(|| panic!("no peer auth line: {:?}", server.seen));
        for needle in [
            "\"op\":\"accept\"".to_string(),
            "\"reason\":\"peer_uid_mismatch\"".to_string(),
            "\"code\":\"PERMISSION_DENIED\"".to_string(),
            format!("\"expected_uid\":{uid}"),
            format!("\"socket_path\":\"{sock_s}\""),
        ] {
            assert!(line.contains(&needle), "missing {needle} in {line}");
        }
        assert!(
            !line.contains(&format!("\"peer_uid\":{uid},"))
                && !line.contains(&format!("\"peer_uid\":{uid}}}")),
            "peer_uid must differ from the expected uid: {line}"
        );

        // 永続的な監査ログ（@audit.log）にも同じ拒否が 1 件届く（SEC-4・PLUG-12・#2484）。
        let log_path = audit_log_path(&xdg.0, uid);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let persisted = loop {
            let found: Vec<String> = std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .lines()
                .filter(|l| l.contains("\"layer\":\"plugin_peer\"") && l.contains(&sock_s))
                .map(str::to_owned)
                .collect();
            if !found.is_empty() || std::time::Instant::now() >= deadline {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(persisted.len(), 1, "persisted audit lines: {persisted:?}");
        assert!(
            persisted[0].contains("\"reason\":\"plugin_peer_uid_mismatch\""),
            "{persisted:?}"
        );

        // 拒否の後も、同じサーバーへ新しい同一 UID の接続で一連が成功する。
        let ch = connect_when_ready(&sock, &mut server).await;
        assert_pod_sandbox_lifecycle(ch, "pod-after-reject").await;
        assert!(server.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}
