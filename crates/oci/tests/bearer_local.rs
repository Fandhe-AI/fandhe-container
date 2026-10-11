//! Bearer トークン交換の公開 API（`RegistryClient::authenticate_bearer`）をローカルの制御可能な
//! サーバーに対して通す結合試験（TASK-54.2・OCI-3・MS-4・REPAIR-4・REPAIR-12。外向き通信なし）。
//!
//! 本番経路は https 固定で、ローカルに TLS サーバーを立てる依存は持たないため、ここでは
//! 「TLS を話さないサーバーに接続した」失敗経路（拒否）と、その計測記録を公開 API だけで確認する。
//! 成功経路（401 Basic チャレンジ → 資格情報つき 200）は `registry.rs` のユニットテスト（通信を差し替えた
//! 公開メソッド経由の照合）が担い、実レジストリの live 試験は資格情報を要するため置かない。

use fandhe_container_oci::auth::BasicCredentials;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample};
use fandhe_container_oci::reference::{RegistryHost, Repository};
use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct Collect(Mutex<Vec<OciOpSample>>);

impl OciOpRecorder for Collect {
    fn record_oci_op(&self, s: &OciOpSample) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*s);
        }
    }
}

/// OCI-3・REPAIR-4: TLS を話さないレジストリ宛ては分類つきのエラーで拒否され、失敗が 1 件記録される。
#[test]
fn non_tls_registry_is_rejected_and_recorded_for_bearer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    // accept・read・write に期限を付け、試験の終わりに join して回収する（REPAIR-5）。
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let config = RegistryClientConfig {
        token_request_timeout: Duration::from_secs(5),
        ..RegistryClientConfig::default()
    };
    let rec = Arc::new(Collect::default());
    let client = RegistryClient::new(&config)
        .expect("client")
        .with_recorder(rec.clone());
    let ep =
        RegistryEndpoint::new(RegistryHost::parse(&format!("localhost:{port}")).expect("host"));
    let repo = Repository::parse("team/app").expect("repo");
    let creds = BasicCredentials::new("user", "SECRET-PW").expect("creds");
    let e = client
        .authenticate_bearer(&ep, &repo, &creds, &[])
        .expect_err("plain http must not be accepted as a registry");
    assert!(!e.message().contains("SECRET-PW"));
    assert!(!format!("{e:?}").contains("SECRET-PW"));
    let items = rec.0.lock().expect("lock").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].kind(), OciOpKind::AuthenticateBearer);
    assert_eq!(items[0].outcome(), OciOpOutcome::Failure);
    assert_eq!(items[0].error_code(), Some(e.code()));
    assert_ne!(e.code(), OciErrorCode::Unimplemented);
    server.join().expect("server thread");
}
