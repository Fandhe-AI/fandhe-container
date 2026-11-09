//! CRI ストリーミングサーバー基盤と URL 発行の結合試験（CRI-6・TASK-63.1・#679）。
//!
//! loopback の TCP だけで完結し、root も外部ネットワークも要らない。クライアントは std の `TcpStream` で生の
//! HTTP/1.1 を送る（ブロッキングなので `spawn_blocking` で別スレッドに逃がし、サーバー側のタスクを塞がない）。
//! トークンの乱数源は unix の `/dev/urandom` のみで、非 unix では発行が `Unavailable` になることだけを照合する。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime::v1::{self, runtime_service_server::RuntimeService};
#[cfg(unix)]
use fandhe_container_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_cri::streaming::{StreamKind, StreamWiring, StreamingConfig, StreamingServer};
use tonic::{Code, Request};

/// 生の HTTP/1.1 要求を送り、EOF まで（5 秒の読み取り期限つきで）応答を読む。
async fn http_raw(addr: SocketAddr, raw: String) -> String {
    tokio::task::spawn_blocking(move || {
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
    .await
    .expect("join")
}

#[cfg(unix)]
async fn request(addr: SocketAddr, method: &str, path: &str) -> String {
    http_raw(
        addr,
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await
}

#[cfg(unix)]
fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

#[cfg(unix)]
fn path_of(url: &str) -> String {
    let rest = url.strip_prefix("http://").expect("http url");
    let idx = rest.find('/').expect("path");
    rest[idx..].to_string()
}

#[cfg(unix)]
fn pod_config() -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        // PortForward は NODE の pod だけ結線済み（POD は #3766 まで UNIMPLEMENTED。#3755）。
        linux: Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(v1::NamespaceOption {
                    network: v1::NamespaceMode::Node as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(unix)]
async fn run_sandbox(service: &CriRuntimeService) -> String {
    service
        .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
            config: Some(pod_config()),
            runtime_handler: String::new(),
        }))
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id
}

#[cfg(unix)]
async fn create_container(service: &CriRuntimeService, sandbox_id: &str) -> String {
    service
        .create_container(Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox_id.to_string(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "c".into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            sandbox_config: Some(pod_config()),
        }))
        .await
        .expect("create container")
        .into_inner()
        .container_id
}

#[cfg(unix)]
async fn start_container(service: &CriRuntimeService, container_id: &str) {
    service
        .start_container(Request::new(v1::StartContainerRequest {
            container_id: container_id.to_string(),
        }))
        .await
        .expect("start container");
}

fn exec_request(container_id: &str) -> v1::ExecRequest {
    v1::ExecRequest {
        container_id: container_id.to_string(),
        cmd: vec!["/bin/sh".into()],
        tty: false,
        stdin: false,
        stdout: true,
        stderr: false,
    }
}

/// 結線した種別の有効なトークンに `200 OK` と種別名の本文を返すテスト用ハンドラ。
/// 200 は、有効なトークンがハンドラへ届いた証拠になる（#3753・REPAIR-3。以前は 501 で代用していた）。
struct AcceptHandler {
    wiring: StreamWiring,
}

impl fandhe_container_cri::streaming::StreamHandler for AcceptHandler {
    fn wiring(&self) -> StreamWiring {
        self.wiring
    }

    fn handle(
        &self,
        request: fandhe_container_cri::streaming::StreamRequest,
        _http: hyper::Request<hyper::body::Incoming>,
        _permit: fandhe_container_cri::streaming::ConnectionPermit,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = hyper::Response<fandhe_container_cri::streaming::StreamBody>,
                > + Send
                + '_,
        >,
    > {
        // 本文は種別名の固定文字列だけ（StreamBody::text は 'static が要るため match で選ぶ）。
        let text: &'static str = match request.kind() {
            StreamKind::Exec => "exec",
            StreamKind::Attach => "attach",
            StreamKind::PortForward => "portforward",
        };
        Box::pin(async move {
            hyper::Response::new(fandhe_container_cri::streaming::StreamBody::text(text))
        })
    }
}

fn all_wired() -> std::sync::Arc<AcceptHandler> {
    std::sync::Arc::new(AcceptHandler {
        wiring: StreamWiring::all(),
    })
}

/// CRI-6: 既定は loopback で待ち受け、URL は `http://127.0.0.1:` で始まる。
#[cfg(unix)]
#[tokio::test]
async fn cri6_default_binds_loopback_and_url_prefix() {
    let server = StreamingServer::bind_with_handler(StreamingConfig::default(), all_wired())
        .await
        .expect("bind");
    assert!(server.local_addr().ip().is_loopback());
    let url = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    assert!(url.starts_with("http://127.0.0.1:"), "url={url}");
}

/// CRI-6: 外部アドレスは opt-in が無ければ起動しない（fail-closed）。
#[tokio::test]
async fn cri6_bind_rejects_external_without_opt_in() {
    let err = StreamingServer::bind(
        StreamingConfig::default().with_bind("0.0.0.0:0".parse().expect("addr")),
    )
    .await
    .expect_err("must reject");
    assert_eq!(err.code(), CriErrorCode::InvalidArgument);
}

/// CRI-6・SEC-1・#4290: broadcast・IPv4 互換形の広告アドレスは起動を拒否し、
/// 射影形の広告アドレスは URL の host を IPv4 表記・ポートを実ポートで発行する。
#[cfg(unix)]
#[tokio::test]
async fn cri6_sec1_4290_advertise_addr_rejects_and_canonicalizes() {
    let external = || {
        StreamingConfig::default()
            .with_bind("0.0.0.0:0".parse().expect("addr"))
            .with_allow_external(true)
    };
    for adv in ["255.255.255.255", "::ffff:255.255.255.255", "::192.0.2.7"] {
        let err = StreamingServer::bind_with_handler(
            external().with_advertise_addr(adv.parse().expect("ip")),
            all_wired(),
        )
        .await
        .expect_err(adv);
        assert_eq!(err.code(), CriErrorCode::InvalidArgument, "{adv}");
    }

    let server = StreamingServer::bind_with_handler(
        external().with_advertise_addr("::ffff:192.0.2.7".parse().expect("ip")),
        all_wired(),
    )
    .await
    .expect("bind");
    let port = server.local_addr().port();
    let url = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    assert!(
        url.starts_with(&format!("http://192.0.2.7:{port}/exec/")),
        "{url}"
    );
}

/// CRI-6: 有効なトークンはハンドラへ届き（200）、2 回目は 404。
#[cfg(unix)]
#[tokio::test]
async fn cri6_valid_token_reaches_handler_then_single_use_404() {
    let server = StreamingServer::bind_with_handler(StreamingConfig::default(), all_wired())
        .await
        .expect("bind");
    let url = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    let path = path_of(&url);
    let first = request(server.local_addr(), "GET", &path).await;
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK", "{first}");
    assert!(first.ends_with("exec"), "{first}");
    let second = request(server.local_addr(), "GET", &path).await;
    assert_eq!(status_line(&second), "HTTP/1.1 404 Not Found", "{second}");
}

/// CRI-6: 未知のトークン・種別違い・TTL 切れ・許可しないメソッド。
#[cfg(unix)]
#[tokio::test]
async fn cri6_unknown_mismatch_expired_and_method() {
    let server = StreamingServer::bind_with_handler(
        StreamingConfig::default().with_token_ttl(Duration::from_millis(100)),
        all_wired(),
    )
    .await
    .expect("bind");
    let addr = server.local_addr();
    let issuer = server.issuer();
    let unknown = format!("/exec/{}", "0".repeat(64));
    assert_eq!(
        status_line(&request(addr, "GET", &unknown).await),
        "HTTP/1.1 404 Not Found"
    );

    let url = issuer
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    let token = path_of(&url).trim_start_matches("/exec/").to_string();
    let wrong_kind = request(addr, "GET", &format!("/attach/{token}")).await;
    assert_eq!(status_line(&wrong_kind), "HTTP/1.1 404 Not Found");
    // 種別違いでも消費されるため、正しい種別でも通らない。
    let after = request(addr, "GET", &format!("/exec/{token}")).await;
    assert_eq!(status_line(&after), "HTTP/1.1 404 Not Found");

    let expired_url = issuer
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let expired = request(addr, "GET", &path_of(&expired_url)).await;
    assert_eq!(status_line(&expired), "HTTP/1.1 404 Not Found");

    let method = request(addr, "DELETE", &unknown).await;
    assert_eq!(status_line(&method), "HTTP/1.1 405 Method Not Allowed");
}

/// CRI-6・REPAIR-5: ヘッダを送らない接続は期限の後に閉じられる（応答が 200/501 になることはない）。
#[tokio::test]
async fn cri6_header_read_timeout_closes_idle_connection() {
    let server = StreamingServer::bind(
        StreamingConfig::default().with_header_read_timeout(Duration::from_millis(200)),
    )
    .await
    .expect("bind");
    let addr = server.local_addr();
    let started = std::time::Instant::now();
    let response = http_raw(addr, String::new()).await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "connection must be closed by the server before the client read timeout"
    );
    assert!(
        !response.contains(" 200 ") && !response.contains(" 501 "),
        "{response}"
    );
}

/// CRI-6: 注入が無ければ 3 RPC は `Unimplemented` のまま。
#[tokio::test]
async fn cri6_rpcs_unimplemented_without_streaming() {
    let service = CriRuntimeService::new();
    let exec = service
        .exec(Request::new(exec_request("c1")))
        .await
        .expect_err("unimplemented");
    assert_eq!(exec.code(), Code::Unimplemented);
    let attach = service
        .attach(Request::new(v1::AttachRequest {
            container_id: "c1".into(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .expect_err("unimplemented");
    assert_eq!(attach.code(), Code::Unimplemented);
    let pf = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: "p".into(),
            port: vec![80],
        }))
        .await
        .expect_err("unimplemented");
    assert_eq!(pf.code(), Code::Unimplemented);
}

/// CRI-6: 注入すると、既存コンテナへの Exec・Attach と既存 sandbox への PortForward が URL を返し、毎回異なる。
#[cfg(unix)]
#[tokio::test]
async fn cri6_rpcs_return_unique_urls_when_injected() {
    let server = StreamingServer::bind_with_handler(StreamingConfig::default(), all_wired())
        .await
        .expect("bind");
    let service = CriRuntimeService::new().with_streaming(server.issuer());
    let sandbox = run_sandbox(&service).await;
    let container = create_container(&service, &sandbox).await;
    // Attach は running のコンテナだけに URL を発行する（TASK-63.3）。
    start_container(&service, &container).await;

    let a = service
        .exec(Request::new(exec_request(&container)))
        .await
        .expect("exec a")
        .into_inner()
        .url;
    let b = service
        .exec(Request::new(exec_request(&container)))
        .await
        .expect("exec b")
        .into_inner()
        .url;
    assert_ne!(a, b);
    assert!(a.contains("/exec/") && b.contains("/exec/"));

    let attach = service
        .attach(Request::new(v1::AttachRequest {
            container_id: container.clone(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .expect("attach")
        .into_inner()
        .url;
    assert!(attach.contains("/attach/"), "{attach}");

    let pf = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: sandbox.clone(),
            port: vec![8080],
        }))
        .await
        .expect("port forward")
        .into_inner()
        .url;
    assert!(pf.contains("/portforward/"), "{pf}");

    // 発行した URL は実際に有効なトークンとしてサーバーに照合され、ハンドラへ届く（200）。
    let resp = request(server.local_addr(), "GET", &path_of(&a)).await;
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK", "{resp}");
}

/// CRI-6: 入力検証と存在照合のエラーコード。
#[cfg(unix)]
#[tokio::test]
async fn cri6_rpc_validation_errors() {
    let server = StreamingServer::bind_with_handler(StreamingConfig::default(), all_wired())
        .await
        .expect("bind");
    let service = CriRuntimeService::new().with_streaming(Arc::clone(&server.issuer()));
    let sandbox = run_sandbox(&service).await;
    let container = create_container(&service, &sandbox).await;

    let unknown = service
        .exec(Request::new(exec_request("no-such-container")))
        .await
        .expect_err("not found");
    assert_eq!(unknown.code(), Code::NotFound);

    let mut no_stream = exec_request(&container);
    no_stream.stdout = false;
    let invalid = service
        .exec(Request::new(no_stream))
        .await
        .expect_err("invalid");
    assert_eq!(invalid.code(), Code::InvalidArgument);

    let bad_port = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: sandbox.clone(),
            port: vec![80, 0],
        }))
        .await
        .expect_err("invalid port");
    assert_eq!(bad_port.code(), Code::InvalidArgument);

    let unknown_pod = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: "no-such-pod".into(),
            port: vec![80],
        }))
        .await
        .expect_err("not found");
    assert_eq!(unknown_pod.code(), Code::NotFound);

    // Attach（TASK-63.3）: running でないコンテナは FAILED_PRECONDITION、tty と stderr の併用は INVALID_ARGUMENT。
    let not_running = service
        .attach(Request::new(v1::AttachRequest {
            container_id: container.clone(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .expect_err("not running");
    assert_eq!(not_running.code(), Code::FailedPrecondition);
    start_container(&service, &container).await;
    let tty_stderr = service
        .attach(Request::new(v1::AttachRequest {
            container_id: container.clone(),
            tty: true,
            stdout: true,
            stderr: true,
            ..Default::default()
        }))
        .await
        .expect_err("tty with stderr");
    assert_eq!(tty_stderr.code(), Code::InvalidArgument);
    let unknown_attach = service
        .attach(Request::new(v1::AttachRequest {
            container_id: "no-such-container".into(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .expect_err("not found");
    assert_eq!(unknown_attach.code(), Code::NotFound);
}

/// CRI-6: 乱数源の無い OS では URL を発行せず `Unavailable` を返す（弱い代替を作らない）。
#[cfg(not(unix))]
#[tokio::test]
async fn cri6_issue_unavailable_on_non_unix() {
    let server = StreamingServer::bind_with_handler(StreamingConfig::default(), all_wired())
        .await
        .expect("bind");
    let err = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect_err("unavailable");
    assert_eq!(err.code(), CriErrorCode::Unavailable);
}

/// Upgrade を受け付けて、期限の数倍の間つないだ後に 1 バイト列を書くテスト用ハンドラ。
#[cfg(unix)]
struct UpgradeHoldHandler {
    hold: Duration,
}

#[cfg(unix)]
impl fandhe_container_cri::streaming::StreamHandler for UpgradeHoldHandler {
    fn wiring(&self) -> StreamWiring {
        StreamWiring::only(StreamKind::Exec)
    }

    fn handle(
        &self,
        _request: fandhe_container_cri::streaming::StreamRequest,
        mut http: hyper::Request<hyper::body::Incoming>,
        permit: fandhe_container_cri::streaming::ConnectionPermit,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = hyper::Response<fandhe_container_cri::streaming::StreamBody>,
                > + Send
                + '_,
        >,
    > {
        let hold = self.hold;
        Box::pin(async move {
            let on_upgrade = hyper::upgrade::on(&mut http);
            // Upgrade 後の IO の寿命まで接続枠を保持する（契約: StreamHandler::handle。#4164 で追跡対象にした）。
            permit.spawn_session(async move {
                let Ok(upgraded) = on_upgrade.await else {
                    return;
                };
                let mut io = upgraded;
                tokio::time::sleep(hold).await;
                let _ = std::future::poll_fn(|cx| {
                    hyper::rt::Write::poll_write(std::pin::Pin::new(&mut io), cx, b"late-data")
                })
                .await;
            });
            let mut response =
                hyper::Response::new(fandhe_container_cri::streaming::StreamBody::empty());
            *response.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
            response.headers_mut().insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("Upgrade"),
            );
            response.headers_mut().insert(
                hyper::header::UPGRADE,
                hyper::header::HeaderValue::from_static("SPDY/3.1"),
            );
            response
        })
    }
}

/// CRI-6・REPAIR-5・#679: Upgrade した接続は、Upgrade しない要求向けの接続全体の期限
/// （`header_read_timeout * 3`）を超えても切られない（Upgrade 後の期限は #680〜#682 が決める）。
#[cfg(unix)]
#[tokio::test]
async fn cri6_upgraded_connection_survives_overall_deadline() {
    let header_timeout = Duration::from_millis(100);
    let hold = header_timeout * 8;
    let server = StreamingServer::bind_with_handler(
        StreamingConfig::default().with_header_read_timeout(header_timeout),
        Arc::new(UpgradeHoldHandler { hold }),
    )
    .await
    .expect("bind");
    let url = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("c1"),
        ))
        .expect("issue");
    let path = path_of(&url);
    let raw = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n"
    );
    let response = tokio::time::timeout(Duration::from_secs(8), http_raw(server.local_addr(), raw))
        .await
        .expect("client must finish within the test deadline");
    assert_eq!(
        status_line(&response),
        "HTTP/1.1 101 Switching Protocols",
        "{response}"
    );
    assert!(
        response.ends_with("late-data"),
        "upgraded connection was closed before the handler wrote: {response}"
    );
}

/// 観測イベントを溜めるテスト用の観測口。
#[cfg(unix)]
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<fandhe_container_cri::streaming::ConnectionEvent>>);

#[cfg(unix)]
impl fandhe_container_cri::streaming::ConnectionObserver for Recorder {
    fn observe(&self, event: fandhe_container_cri::streaming::ConnectionEvent) {
        self.0.lock().expect("lock").push(event);
    }
}

/// CRI-6・REPAIR-5・REPAIR-4・#679: Upgrade 後の IO が生きている間は接続枠が返らず
/// （`max_connections = 1` で 2 本目が閉じられ `Rejected` が記録される）、解放後は再び受け付ける。
/// 結果別の観測（`Finished`）も記録され、トークンを含まない。
#[cfg(unix)]
#[tokio::test]
async fn cri6_upgrade_holds_connection_slot_and_observes() {
    use fandhe_container_cri::streaming::{ConnectionEvent, ConnectionOutcome, StreamRequest};
    let hold = Duration::from_millis(1500);
    let recorder = Arc::new(Recorder::default());
    let server = StreamingServer::bind_with_observer(
        StreamingConfig::default().with_max_connections(1),
        Arc::new(UpgradeHoldHandler { hold }),
        recorder.clone(),
    )
    .await
    .expect("bind");
    let addr = server.local_addr();
    let url = server
        .issuer()
        .issue(StreamRequest::exec(exec_request("c1")))
        .expect("issue");
    let path = path_of(&url);
    let raw = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n"
    );
    let first = tokio::spawn(http_raw(addr, raw));
    // 1 本目の接続の future は 101 の直後に終わるので、少し待ってから 2 本目を送る。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let second = request(addr, "GET", "/exec/none").await;
    assert_eq!(
        second, "",
        "second connection must be closed while the slot is held"
    );
    let response = first.await.expect("join");
    assert!(response.ends_with("late-data"), "{response}");
    // 枠が返った後は受け付ける（404 が返る）。
    tokio::time::sleep(Duration::from_millis(200)).await;
    let third = request(addr, "GET", "/exec/none").await;
    assert_eq!(status_line(&third), "HTTP/1.1 404 Not Found", "{third}");
    let events = recorder.0.lock().expect("lock").clone();
    assert!(events.contains(&ConnectionEvent::Rejected), "{events:?}");
    assert!(
        events.iter().any(|e| matches!(
            e,
            ConnectionEvent::Finished {
                outcome: ConnectionOutcome::Completed,
                ..
            }
        )),
        "{events:?}"
    );
}

/// 部分結線（`kinds` だけ登録）の `StreamDispatcher` を `AcceptHandler` で組む。
#[cfg(unix)]
fn partial_dispatcher(
    kinds: &[StreamKind],
) -> std::sync::Arc<dyn fandhe_container_cri::streaming::StreamHandler> {
    let mut dispatcher = fandhe_container_cri::streaming::StreamDispatcher::new();
    for kind in kinds {
        let handler = std::sync::Arc::new(AcceptHandler {
            wiring: StreamWiring::only(*kind),
        });
        dispatcher = match kind {
            StreamKind::Exec => dispatcher.with_exec(handler),
            StreamKind::Attach => dispatcher.with_attach(handler),
            StreamKind::PortForward => dispatcher.with_port_forward(handler),
        };
    }
    std::sync::Arc::new(dispatcher)
}

#[cfg(unix)]
type RpcUrl = Result<String, tonic::Status>;

#[cfg(unix)]
async fn rpc_results(
    service: &CriRuntimeService,
    sandbox: &str,
    container: &str,
) -> (RpcUrl, RpcUrl, RpcUrl) {
    let exec = service
        .exec(Request::new(exec_request(container)))
        .await
        .map(|r| r.into_inner().url);
    let attach = service
        .attach(Request::new(v1::AttachRequest {
            container_id: container.to_string(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .map(|r| r.into_inner().url);
    let pf = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: sandbox.to_string(),
            port: vec![8080],
        }))
        .await
        .map(|r| r.into_inner().url);
    (exec, attach, pf)
}

/// CRI-6・REPAIR-3・#3753: Exec だけ結線した構成で、exec は URL を返し、attach と port_forward は
/// URL を返さず `UNIMPLEMENTED`（未知コンテナでも NOT_FOUND より先に `UNIMPLEMENTED`）。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair3_partial_dispatcher_issues_only_wired_kinds() {
    let server = StreamingServer::bind_with_handler(
        StreamingConfig::default(),
        partial_dispatcher(&[StreamKind::Exec]),
    )
    .await
    .expect("bind");
    let issuer = server.issuer();
    assert!(issuer.is_wired(StreamKind::Exec));
    assert!(!issuer.is_wired(StreamKind::Attach));
    assert!(!issuer.is_wired(StreamKind::PortForward));
    let service = CriRuntimeService::new().with_streaming(issuer);
    let sandbox = run_sandbox(&service).await;
    let container = create_container(&service, &sandbox).await;
    start_container(&service, &container).await;

    let (exec, attach, pf) = rpc_results(&service, &sandbox, &container).await;
    assert!(exec.expect("exec url").contains("/exec/"));
    assert_eq!(attach.expect_err("attach").code(), Code::Unimplemented);
    assert_eq!(pf.expect_err("port forward").code(), Code::Unimplemented);

    let unknown = service
        .attach(Request::new(v1::AttachRequest {
            container_id: "no-such-container".to_string(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .expect_err("unwired");
    assert_eq!(unknown.code(), Code::Unimplemented);
}

/// CRI-6・REPAIR-3・#3753: PortForward だけ結線した構成。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair3_partial_dispatcher_port_forward_only() {
    let server = StreamingServer::bind_with_handler(
        StreamingConfig::default(),
        partial_dispatcher(&[StreamKind::PortForward]),
    )
    .await
    .expect("bind");
    let service = CriRuntimeService::new().with_streaming(server.issuer());
    let sandbox = run_sandbox(&service).await;
    let container = create_container(&service, &sandbox).await;
    start_container(&service, &container).await;

    let (exec, attach, pf) = rpc_results(&service, &sandbox, &container).await;
    assert_eq!(exec.expect_err("exec").code(), Code::Unimplemented);
    assert_eq!(attach.expect_err("attach").code(), Code::Unimplemented);
    assert!(pf.expect("pf url").contains("/portforward/"));
}

/// CRI-6・REPAIR-3・SEC-1・#3755: POD ネットワークの sandbox の PortForward は URL を返さず `UNIMPLEMENTED`、
/// NODE の sandbox は URL を返す。
#[cfg(unix)]
#[tokio::test]
async fn cri6_3755_port_forward_pod_network_is_unimplemented() {
    let server = StreamingServer::bind_with_handler(
        StreamingConfig::default(),
        partial_dispatcher(&[StreamKind::PortForward]),
    )
    .await
    .expect("bind");
    let service = CriRuntimeService::new().with_streaming(server.issuer());
    let node = run_sandbox(&service).await;
    let pod = service
        .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod2".into(),
                    uid: "uid-2".into(),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .expect("run pod sandbox")
        .into_inner()
        .pod_sandbox_id;
    let node_url = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: node,
            port: vec![80],
        }))
        .await
        .expect("node url")
        .into_inner()
        .url;
    assert!(node_url.contains("/portforward/"));
    let err = service
        .port_forward(Request::new(v1::PortForwardRequest {
            pod_sandbox_id: pod,
            port: vec![80],
        }))
        .await
        .expect_err("pod is unimplemented");
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(
        err.message(),
        "port-forward for pod network is not implemented"
    );
}

/// CRI-6・REPAIR-3・#3753: `StreamingServer::bind`（どの種別も未結線）では 3 RPC とも URL を返さない。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair3_default_bind_issues_nothing() {
    let server = StreamingServer::bind(StreamingConfig::default())
        .await
        .expect("bind");
    let service = CriRuntimeService::new().with_streaming(server.issuer());
    let sandbox = run_sandbox(&service).await;
    let container = create_container(&service, &sandbox).await;
    start_container(&service, &container).await;

    let (exec, attach, pf) = rpc_results(&service, &sandbox, &container).await;
    assert_eq!(exec.expect_err("exec").code(), Code::Unimplemented);
    assert_eq!(attach.expect_err("attach").code(), Code::Unimplemented);
    assert_eq!(pf.expect_err("port forward").code(), Code::Unimplemented);
}
/// Upgrade の後、container_id が `fast` なら短い遅延の後に `done-fast` を書いて閉じ、
/// それ以外は永久に保持するテスト用ハンドラ（停止時のドレインと強制クローズの照合用。#4164）。
#[cfg(unix)]
struct DrainHandler;

#[cfg(unix)]
impl fandhe_container_cri::streaming::StreamHandler for DrainHandler {
    fn wiring(&self) -> StreamWiring {
        StreamWiring::only(StreamKind::Exec)
    }

    fn handle(
        &self,
        request: fandhe_container_cri::streaming::StreamRequest,
        mut http: hyper::Request<hyper::body::Incoming>,
        permit: fandhe_container_cri::streaming::ConnectionPermit,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = hyper::Response<fandhe_container_cri::streaming::StreamBody>,
                > + Send
                + '_,
        >,
    > {
        let fast = matches!(
            &request,
            fandhe_container_cri::streaming::StreamRequest::Exec { request: r, .. } if r.container_id == "fast"
        );
        Box::pin(async move {
            let on_upgrade = hyper::upgrade::on(&mut http);
            permit.spawn_session(async move {
                let Ok(upgraded) = on_upgrade.await else {
                    return;
                };
                let mut io = upgraded;
                if fast {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = std::future::poll_fn(|cx| {
                        hyper::rt::Write::poll_write(std::pin::Pin::new(&mut io), cx, b"done-fast")
                    })
                    .await;
                } else {
                    std::future::pending::<()>().await;
                }
            });
            let mut response =
                hyper::Response::new(fandhe_container_cri::streaming::StreamBody::empty());
            *response.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
            response.headers_mut().insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("Upgrade"),
            );
            response.headers_mut().insert(
                hyper::header::UPGRADE,
                hyper::header::HeaderValue::from_static("SPDY/3.1"),
            );
            response
        })
    }
}

/// Upgrade 要求を送り、EOF まで（読み取り期限つきで）読んだ内容を返す。
#[cfg(unix)]
fn upgrade_client(addr: SocketAddr, path: String) -> tokio::task::JoinHandle<String> {
    tokio::task::spawn_blocking(move || {
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let raw = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n"
        );
        stream.write_all(raw.as_bytes()).expect("write");
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
}

/// 件数が `n` に達するまで（2 秒の上限で）待つ。
#[cfg(unix)]
async fn wait_open(sessions: &fandhe_container_cri::streaming::StreamingSessions, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while sessions.open() < n && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sessions.open(), n);
}

/// CRI-6・REPAIR-5・#4164: 3 セッションを開いたまま待ち受けを閉じると、期限内に自然に終わった 1 件の応答は
/// 欠けず、残り 2 件は `close_all` で閉じられる（EOF）。全体が時間の上限内に収まる。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair5_4164_drain_keeps_natural_response_and_force_closes_rest() {
    let started = std::time::Instant::now();
    let server =
        StreamingServer::bind_with_handler(StreamingConfig::default(), Arc::new(DrainHandler))
            .await
            .expect("bind");
    let addr = server.local_addr();
    let sessions = server.sessions();
    let mut clients = Vec::new();
    for id in ["fast", "slow-b", "slow-c"] {
        let url = server
            .issuer()
            .issue(fandhe_container_cri::streaming::StreamRequest::exec(
                exec_request(id),
            ))
            .expect("issue");
        clients.push(upgrade_client(addr, path_of(&url)));
    }
    wait_open(&sessions, 3).await;

    server.shutdown();
    let left = sessions
        .wait_idle_until(std::time::Instant::now() + Duration::from_millis(1500))
        .await;
    assert_eq!(left, 2, "the natural session must have finished by itself");
    sessions.close_all();
    let left = sessions
        .wait_idle_until(std::time::Instant::now() + Duration::from_millis(1000))
        .await;
    assert_eq!(left, 0, "forced close must release every slot");
    assert!(started.elapsed() < Duration::from_secs(5));

    let mut results = Vec::new();
    for c in clients {
        results.push(
            tokio::time::timeout(Duration::from_secs(3), c)
                .await
                .expect("client must see EOF")
                .expect("join"),
        );
    }
    assert!(results[0].ends_with("done-fast"), "{}", results[0]);
    for body in &results[1..] {
        assert!(body.starts_with("HTTP/1.1 101"), "{body}");
        assert!(!body.contains("done-"), "{body}");
    }
}

/// CRI-6・REPAIR-5・#4164: 強制クローズの後に受け付けた接続は直ちに閉じられ、件数は 0 に戻る
/// （登録の取りこぼしを作らない）。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair5_4164_connection_after_close_all_is_aborted() {
    let server =
        StreamingServer::bind_with_handler(StreamingConfig::default(), Arc::new(DrainHandler))
            .await
            .expect("bind");
    let sessions = server.sessions();
    sessions.close_all();
    let url = server
        .issuer()
        .issue(fandhe_container_cri::streaming::StreamRequest::exec(
            exec_request("slow"),
        ))
        .expect("issue");
    let client = upgrade_client(server.local_addr(), path_of(&url));
    let body = tokio::time::timeout(Duration::from_secs(3), client)
        .await
        .expect("client must see EOF")
        .expect("join");
    assert!(!body.contains("done-"), "{body}");
    let left = sessions
        .wait_idle_until(std::time::Instant::now() + Duration::from_secs(2))
        .await;
    assert_eq!(left, 0);
}

/// CRI-6・REPAIR-5・#4164: ヘッダを送らない（Upgrade 前の）接続も `close_all` で閉じられ、
/// ヘッダ読み取りの期限（既定 10 秒）を待たない。
#[cfg(unix)]
#[tokio::test]
async fn cri6_repair5_4164_close_all_cuts_pre_upgrade_connections() {
    let server =
        StreamingServer::bind_with_handler(StreamingConfig::default(), Arc::new(DrainHandler))
            .await
            .expect("bind");
    let addr = server.local_addr();
    let sessions = server.sessions();
    let started = std::time::Instant::now();
    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(tokio::task::spawn_blocking(move || {
            let mut stream =
                TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut out = Vec::new();
            let _ = stream.read_to_end(&mut out);
            out
        }));
    }
    wait_open(&sessions, 3).await;
    sessions.close_all();
    assert_eq!(
        sessions
            .wait_idle_until(std::time::Instant::now() + Duration::from_millis(1000))
            .await,
        0
    );
    for c in clients {
        let out = tokio::time::timeout(Duration::from_secs(3), c)
            .await
            .expect("client must see EOF")
            .expect("join");
        assert!(out.is_empty());
    }
    assert!(started.elapsed() < Duration::from_secs(4));
}
