//! UDS 上の gRPC（`UdsIncoming` / `connect_uds_channel`）の結合試験（TASK-108.2・#454・PLUG-2・PLUG-12・
//! MS-4・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! TCP は一切 bind せず、`UdsListener` の配置検証・0600 化・peer UID 認証を通した UDS 経由で tonic の unary RPC が
//! 成功することを機械照合する。別 UID の peer 認証拒否（期待 UID の差し替え）は `grpc.rs` の単体試験で行う。
//! protoc も `build.rs` も使わず、手書きの prost メッセージと Echo 風 unary サービスを使う。root・特権は不要。
//! CRI proto の RPC 疎通は TASK-108.3（#455）で別に試験する。

// WIN-1: UDS 固有の実装は unix のみ。非 unix では本試験は空になる（黙って通すのではなく、この明示を残す）。
#![cfg(unix)]

use std::convert::Infallible;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use fandhe_container_plugin::grpc::{
    GRPC_MAX_MESSAGE_BYTES, GrpcClientConfig, GrpcOpStats, GrpcServerConfig, UdsIncoming,
    call_with_deadline, connect_uds_channel, grpc_stats, serve_router, server_builder,
    status_to_plugin_error,
};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginErrorCode, UdsListener};
use tonic::codegen::{BoxFuture, Service, http};
use tonic::transport::Channel;

#[derive(Clone, PartialEq, prost::Message)]
struct Msg {
    #[prost(string, tag = "1")]
    text: String,
}

/// 受け取った文字列をそのまま返す。`delay` だけ待ってから返す。
#[derive(Clone)]
struct EchoSvc {
    delay: Duration,
}

impl tonic::server::NamedService for EchoSvc {
    const NAME: &'static str = "test.Echo";
}

struct SayHandler {
    delay: Duration,
}

impl tonic::server::UnaryService<Msg> for SayHandler {
    type Response = Msg;
    type Future = BoxFuture<tonic::Response<Msg>, tonic::Status>;
    fn call(&mut self, request: tonic::Request<Msg>) -> Self::Future {
        let delay = self.delay;
        Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Ok(tonic::Response::new(request.into_inner()))
        })
    }
}

impl Service<http::Request<tonic::body::Body>> for EchoSvc {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let delay = self.delay;
        match req.uri().path() {
            "/test.Echo/Say" => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES);
                Ok(grpc.unary(SayHandler { delay }, req).await)
            }),
            _ => Box::pin(
                async move { Ok(tonic::Status::unimplemented("unknown method").into_http()) },
            ),
        }
    }
}

async fn say(channel: Channel, text: String) -> Result<String, tonic::Status> {
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| tonic::Status::unavailable(e.to_string()))?;
    let resp = client
        .unary::<Msg, Msg, _>(
            tonic::Request::new(Msg { text }),
            http::uri::PathAndQuery::from_static("/test.Echo/Say"),
            tonic_prost::ProstCodec::default(),
        )
        .await?;
    Ok(resp.into_inner().text)
}

/// 0700 の一時ディレクトリ（`UdsListener::bind` の配置検証を満たす）。
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fcgu-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn sock(&self) -> PathBuf {
        self.0.join("s.sock")
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Running {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<Result<(), fandhe_container_plugin::PluginError>>,
}

fn start(sock: &Path, delay: Duration, cfg: GrpcServerConfig) -> Running {
    let listener = UdsListener::bind(sock).unwrap();
    let incoming = UdsIncoming::new(listener, Box::new(JsonLinesPeerAuthObserver::new())).unwrap();
    let mut builder = server_builder(&cfg);
    let router = builder.add_service(EchoSvc { delay });
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let task = tokio::spawn(async move {
        serve_router(
            router,
            incoming,
            async move {
                // tokio の sync feature は承認範囲外のため、フラグを短周期で見る。
                while !flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            },
            &cfg,
        )
        .await
    });
    Running { stop, task }
}

async fn connect(sock: &Path, cfg: &GrpcClientConfig) -> Channel {
    connect_uds_channel(sock, cfg, Box::new(JsonLinesPeerAuthObserver::new()))
        .await
        .unwrap()
}

const WATCHDOG: Duration = Duration::from_secs(20);

/// 受入基準（PLUG-2）: TCP を使わず UDS 経由で unary RPC が成功し、socket は 0600。
#[tokio::test]
async fn plug2_uds_unary_roundtrip_without_tcp() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let sock = dir.sock();
        let srv = start(&sock, Duration::ZERO, GrpcServerConfig::new());
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let before = grpc_stats();
        let ch = connect(&sock, &GrpcClientConfig::new()).await;
        let text = call_with_deadline(say(ch.clone(), "hello".into()), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(text, "hello");
        // 観測性（REPAIR-4）: UDS 経路でも connect / call の件数が増える（並行試験のため下限で照合）。
        let ok = |v: &[GrpcOpStats], op: &str| v.iter().find(|s| s.op == op).unwrap().success;
        let after = grpc_stats();
        assert!(ok(&after, "connect") > ok(&before, "connect"));
        assert!(ok(&after, "call") > ok(&before, "call"));
        drop(ch);
        srv.stop.store(true, Ordering::SeqCst);
        let r = tokio::time::timeout(Duration::from_secs(10), srv.task)
            .await
            .expect("server must stop in bounded time")
            .unwrap();
        assert!(r.is_ok(), "{r:?}");
        // PLUG-12: graceful shutdown 後に socket ファイルが残らない。
        assert!(!sock.exists());
    })
    .await
    .expect("watchdog");
}

/// shutdown 猶予超過の強制回収は UDS でも働き Timeout（reclaimed=true。REPAIR-5）。
#[tokio::test]
async fn repair5_uds_shutdown_grace_force_closes() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let sock = dir.sock();
        let cfg = GrpcServerConfig::new()
            .with_shutdown_grace(Duration::from_millis(300))
            .unwrap();
        let srv = start(&sock, Duration::from_secs(8), cfg);
        let ch = connect(&sock, &GrpcClientConfig::new()).await;
        let inflight = tokio::spawn(say(ch.clone(), "stuck".into()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        srv.stop.store(true, Ordering::SeqCst);
        let r = tokio::time::timeout(Duration::from_secs(6), srv.task)
            .await
            .expect("server must stop in bounded time")
            .unwrap();
        let e = r.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout, "{e:?}");
        assert!(e.message().contains("reclaimed=true"), "{e:?}");
        let st = tokio::time::timeout(Duration::from_secs(5), inflight)
            .await
            .expect("client call must end")
            .unwrap();
        assert!(st.is_err());
    })
    .await
    .expect("watchdog");
}

/// 遅いハンドラーはリクエストタイムアウトで Timeout へ写る（REPAIR-5）。
#[tokio::test]
async fn repair5_uds_request_timeout_maps_to_timeout() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let sock = dir.sock();
        let scfg = GrpcServerConfig::new()
            .with_request_timeout(Duration::from_millis(200))
            .unwrap();
        let srv = start(&sock, Duration::from_secs(5), scfg);
        let ch = connect(&sock, &GrpcClientConfig::new()).await;
        let st = say(ch, "slow".into()).await.unwrap_err();
        assert_eq!(
            status_to_plugin_error(&st).code(),
            PluginErrorCode::Timeout,
            "{st:?}"
        );
        srv.stop.store(true, Ordering::SeqCst);
    })
    .await
    .expect("watchdog");
}

/// GRPC_MAX_MESSAGE_BYTES 超過は UDS でも拒否される（OWASP A04）。
#[tokio::test]
async fn uds_oversized_message_rejected() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let sock = dir.sock();
        let srv = start(&sock, Duration::ZERO, GrpcServerConfig::new());
        let ch = connect(&sock, &GrpcClientConfig::new()).await;
        let st = say(ch, "a".repeat(GRPC_MAX_MESSAGE_BYTES + 1024))
            .await
            .unwrap_err();
        assert!(
            matches!(
                st.code(),
                tonic::Code::OutOfRange | tonic::Code::ResourceExhausted
            ),
            "{st:?}"
        );
        srv.stop.store(true, Ordering::SeqCst);
    })
    .await
    .expect("watchdog");
}

/// 異常系は fail-closed で期限内に返り、コードは `UdsStream::connect` の契約と揃う（REPAIR-5・PLUG-2）。
#[tokio::test]
async fn uds_connect_errors_are_mapped_and_bounded() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let cfg = GrpcClientConfig::new()
            .with_connect_timeout(Duration::from_secs(2))
            .unwrap();
        let obs = || Box::new(JsonLinesPeerAuthObserver::new());
        // 存在しない path。
        let e = connect_uds_channel(&dir.sock(), &cfg, obs())
            .await
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound, "{e:?}");
        // listener のいない stale socket。
        let stale = dir.0.join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        let e = connect_uds_channel(&stale, &cfg, obs()).await.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable, "{e:?}");
        // 空パス・sun_path 超過。
        let e = connect_uds_channel(Path::new(""), &cfg, obs())
            .await
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument, "{e:?}");
        let long = dir.0.join("x".repeat(200));
        let e = connect_uds_channel(&long, &cfg, obs()).await.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument, "{e:?}");
        // NUL を含むパスと巨大パス（検証前に複製せず InvalidArgument。PLUG-2・REPAIR-5）。
        let nul = Path::new(
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"/tmp/a\0b.sock"),
        );
        let e = connect_uds_channel(nul, &cfg, obs()).await.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument, "{e:?}");
        let huge = dir.0.join("y".repeat(1 << 20));
        let e = connect_uds_channel(&huge, &cfg, obs()).await.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument, "{e:?}");
    })
    .await
    .expect("watchdog");
    // 接続タイムアウトの 0 は構築時に InvalidArgument。
    assert_eq!(
        GrpcClientConfig::new()
            .with_connect_timeout(Duration::ZERO)
            .unwrap_err()
            .code(),
        PluginErrorCode::InvalidArgument
    );
}

/// サーバーを停止して同一 path で再起動しても、同じ `Channel` で再接続して RPC できる
/// （再接続のたびに connector が peer を検証する。PLUG-12）。
#[tokio::test]
async fn uds_channel_reconnects_after_server_restart() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new();
        let sock = dir.sock();
        let scfg = GrpcServerConfig::new()
            .with_shutdown_grace(Duration::from_millis(300))
            .unwrap();
        let srv = start(&sock, Duration::ZERO, scfg.clone());
        let ch = connect(&sock, &GrpcClientConfig::new()).await;
        assert_eq!(say(ch.clone(), "one".into()).await.unwrap(), "one");
        srv.stop.store(true, Ordering::SeqCst);
        // 猶予超過の Timeout で終わってもよい（接続を保持したままのため）。終了の有界性だけを見る。
        let _ = tokio::time::timeout(Duration::from_secs(6), srv.task)
            .await
            .expect("server must stop in bounded time");
        let srv2 = start(&sock, Duration::ZERO, scfg);
        // 条件待ち（期限付き）。切断の検知前は Unavailable になりうる。
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let text = loop {
            match say(ch.clone(), "two".into()).await {
                Ok(t) => break t,
                Err(st) => {
                    assert!(std::time::Instant::now() < deadline, "no reconnect: {st:?}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        assert_eq!(text, "two");
        srv2.stop.store(true, Ordering::SeqCst);
    })
    .await
    .expect("watchdog");
}
