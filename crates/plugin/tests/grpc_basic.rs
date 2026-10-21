//! gRPC 基盤（`fandhe_container_plugin::grpc`）の結合試験（TASK-108.1・#453・PLUG-2・MS-3・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! protoc も `build.rs` も使わず、手書きの prost メッセージと Echo 風 unary サービスでサーバー起動・
//! クライアント接続・graceful shutdown・各種タイムアウト・サイズ上限を機械照合する。TCP はテスト内の
//! `127.0.0.1` ループバックに限り、公開 API としての TCP 待ち受けは無い。root・特権は不要。
//! UDS 統合は TASK-108.2（#454）、CRI proto 疎通は TASK-108.3（#455）で別に試験する。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use fandhe_container_plugin::PluginErrorCode;
use fandhe_container_plugin::grpc::{
    GRPC_MAX_MESSAGE_BYTES, GrpcClientConfig, GrpcServerConfig, call_with_deadline,
    connect_channel, export_stats_json_lines, grpc_stats, serve_router, server_builder,
    status_to_plugin_error,
};
use tonic::codegen::{BoxFuture, Service, http};
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};

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

struct Running {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<Result<(), fandhe_container_plugin::PluginError>>,
}

fn start(delay: Duration, cfg: GrpcServerConfig) -> Running {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
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
    Running { addr, stop, task }
}

async fn connect(addr: SocketAddr, cfg: &GrpcClientConfig) -> Channel {
    let ep = Endpoint::from_shared(format!("http://{addr}")).unwrap();
    connect_channel(cfg.apply(ep), cfg.connect_timeout())
        .await
        .unwrap()
}

const WATCHDOG: Duration = Duration::from_secs(20);

/// 受入基準: サーバー起動・クライアント接続・unary 往復・graceful shutdown（PLUG-2）。
#[tokio::test]
async fn roundtrip_and_graceful_shutdown() {
    tokio::time::timeout(WATCHDOG, async {
        let srv = start(Duration::ZERO, GrpcServerConfig::new());
        let ch = connect(srv.addr, &GrpcClientConfig::new()).await;
        assert_eq!(say(ch.clone(), "hello".into()).await.unwrap(), "hello");
        drop(ch);
        srv.stop.store(true, Ordering::SeqCst);
        let r = tokio::time::timeout(Duration::from_secs(10), srv.task)
            .await
            .expect("server must stop in bounded time")
            .unwrap();
        assert!(r.is_ok(), "{r:?}");
    })
    .await
    .expect("watchdog");
}

/// 誰も listen していないポートへの接続は期限内に Unavailable か Timeout で失敗する（REPAIR-5）。
///
/// bind だけして listen しないソケットで番号を予約し、接続試行の後まで保持する。解放したポートを
/// 並行試験のサーバーが再利用すると接続が成功してしまう間欠失敗を防ぐ（#2348）。
#[tokio::test]
async fn connect_refused_is_bounded() {
    tokio::time::timeout(WATCHDOG, async {
        // listen() を呼ばないこと。std の TcpListener は bind 時に listen まで行い接続が成功するため使わない。
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = reserved.local_addr().unwrap().port();
        let cfg = GrpcClientConfig::new()
            .with_connect_timeout(Duration::from_secs(2))
            .unwrap();
        let ep = Endpoint::from_shared(format!("http://127.0.0.1:{port}")).unwrap();
        let e = connect_channel(cfg.apply(ep), cfg.connect_timeout())
            .await
            .unwrap_err();
        assert!(
            matches!(
                e.code(),
                PluginErrorCode::Unavailable | PluginErrorCode::Timeout
            ),
            "{e:?}"
        );
        // 接続試行とアサーションが終わるまで予約を保持する。
        drop(reserved);
    })
    .await
    .expect("watchdog");
}

/// ハンドラーがリクエストタイムアウトより遅いと DeadlineExceeded 相当（Timeout）で失敗する。
#[tokio::test]
async fn request_timeout_fires() {
    tokio::time::timeout(WATCHDOG, async {
        let scfg = GrpcServerConfig::new()
            .with_request_timeout(Duration::from_millis(200))
            .unwrap();
        let srv = start(Duration::from_secs(5), scfg);
        let ccfg = GrpcClientConfig::new()
            .with_request_timeout(Duration::from_secs(10))
            .unwrap();
        let ch = connect(srv.addr, &ccfg).await;
        let st = say(ch, "slow".into()).await.unwrap_err();
        let e = status_to_plugin_error(&st);
        assert_eq!(e.code(), PluginErrorCode::Timeout, "{st:?}");
        srv.stop.store(true, Ordering::SeqCst);
    })
    .await
    .expect("watchdog");
}

/// GRPC_MAX_MESSAGE_BYTES を超えるペイロードはサーバー側で拒否される。
#[tokio::test]
async fn oversized_message_rejected() {
    tokio::time::timeout(WATCHDOG, async {
        let srv = start(Duration::ZERO, GrpcServerConfig::new());
        let ch = connect(srv.addr, &GrpcClientConfig::new()).await;
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

/// 応答ヘッダ後の本文が来ない RPC も `call_with_deadline` の期限で Timeout になる（REPAIR-5）。
#[tokio::test]
async fn call_with_deadline_bounds_whole_rpc() {
    tokio::time::timeout(WATCHDOG, async {
        let srv = start(Duration::from_secs(5), GrpcServerConfig::new());
        let ch = connect(srv.addr, &GrpcClientConfig::new()).await;
        let started = std::time::Instant::now();
        let e = call_with_deadline(say(ch, "slow".into()), Duration::from_millis(200))
            .await
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout, "{e:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        srv.stop.store(true, Ordering::SeqCst);
    })
    .await
    .expect("watchdog");
}

/// shutdown 猶予を超えて居座る接続は強制的に閉じられ、Timeout で返る（REPAIR-5）。
#[tokio::test]
async fn shutdown_grace_expiry_force_closes_connections() {
    tokio::time::timeout(WATCHDOG, async {
        let cfg = GrpcServerConfig::new()
            .with_shutdown_grace(Duration::from_millis(300))
            .unwrap();
        let srv = start(Duration::from_secs(8), cfg);
        let ch = connect(srv.addr, &GrpcClientConfig::new()).await;
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
        // 強制停止で進行中の RPC も終わる。
        let st = tokio::time::timeout(Duration::from_secs(5), inflight)
            .await
            .expect("client call must end")
            .unwrap();
        assert!(st.is_err());
    })
    .await
    .expect("watchdog");
}

/// 記録した件数が JSON Lines に現れる（REPAIR-4）。他試験と並行のため下限で照合する。
#[tokio::test]
async fn stats_are_recorded_and_exported() {
    tokio::time::timeout(WATCHDOG, async {
        let srv = start(Duration::ZERO, GrpcServerConfig::new());
        let ch = connect(srv.addr, &GrpcClientConfig::new()).await;
        call_with_deadline(say(ch, "x".into()), Duration::from_secs(5))
            .await
            .unwrap();
        srv.stop.store(true, Ordering::SeqCst);
        let stats = grpc_stats();
        let by = |op: &str| stats.iter().find(|s| s.op == op).unwrap().clone();
        assert!(by("connect").success >= 1);
        assert!(by("call").success >= 1);
        let mut out = Vec::new();
        export_stats_json_lines(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.starts_with("{\"event\":\"grpc_op_stats\",\"op\":\"serve\""));
    })
    .await
    .expect("watchdog");
}
