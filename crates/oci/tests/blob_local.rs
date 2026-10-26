//! blob 取得の公開 API（`RegistryClient::fetch_blob`）をローカルの制御可能なサーバーに対して通す
//! 結合試験（TASK-51.4・OCI-1・MS-4・REPAIR-4・REPAIR-12。外向き通信なし）。
//!
//! 本番経路は https 固定で、ローカルに TLS サーバーを立てる依存は持たないため、ここでは
//! 「TLS を話さないサーバーに接続した」失敗経路（拒否）と、その計測記録・後始末を公開 API だけで確認する。
//! 成功経路とリダイレクトは `registry.rs` のユニットテスト（通信を差し替えた照合）が担い、
//! 実ネットワークでの成功は `blob_live.rs`（ignore）が担う。

use fandhe_container_oci::auth::RegistryAuth;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::ImageStore;
use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample};
use fandhe_container_oci::manifest::Descriptor;
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

/// `Descriptor` は `non_exhaustive` のため、公開の `ImageManifest` を介さず JSON 経由では作れない。
/// ここでは公開 API の `parse_manifest` で config descriptor を得る。
fn descriptor(size: u64) -> Descriptor {
    let hex = "1".repeat(64);
    let body = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{hex}","size":{size}}},"layers":[]}}"#
    );
    match fandhe_container_oci::manifest::parse_manifest(body.as_bytes(), None).expect("manifest") {
        fandhe_container_oci::manifest::ParsedManifest::Image(m) => m.config,
        _ => panic!("expected image manifest"),
    }
}

/// OCI-1・REPAIR-4: TLS を話さないレジストリ宛ては分類つきのエラーで拒否され、失敗が 1 件記録され、
/// 保存先にも `.part` にもファイルが残らない。
#[test]
fn non_tls_registry_is_rejected_and_recorded() {
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
        blob_request_timeout: Duration::from_secs(5),
        ..RegistryClientConfig::default()
    };
    let rec = Arc::new(Collect::default());
    let client = RegistryClient::new(&config)
        .expect("client")
        .with_recorder(rec.clone());
    let ep =
        RegistryEndpoint::new(RegistryHost::parse(&format!("localhost:{port}")).expect("host"));
    let repo = Repository::parse("library/alpine").expect("repo");
    let dir = std::env::temp_dir().join(format!("fandhe-oci-blob-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    // 書き込み先は検査済み root の fd 起点の writer（#2765。パスは渡せない）。
    let store = ImageStore::open(&dir).expect("open store");
    let mut session = store.begin_pull_generated().expect("begin pull");
    let d = descriptor(3);
    let mut writer = session.open_staged_blob(&d.digest).expect("writer");
    let e = client
        .fetch_blob(&ep, &repo, &d, &RegistryAuth::None, &mut writer)
        .expect_err("plain http must not be accepted as a registry");
    drop(writer);
    let items = rec.0.lock().expect("lock").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].kind(), OciOpKind::FetchBlob);
    assert_eq!(items[0].outcome(), OciOpOutcome::Failure);
    assert_eq!(items[0].error_code(), Some(e.code()));
    assert_ne!(e.code(), OciErrorCode::Unimplemented);
    // 失敗した取得は `<hex>` も `<hex>.part` も残さない（`@pull.lock` だけ）。
    let pull_dir = session.staging_dir().to_path_buf();
    let mut left: Vec<String> = std::fs::read_dir(&pull_dir)
        .expect("read pull dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, vec!["@pull.lock".to_string()]);
    session.abort().expect("abort");
    let _ = std::fs::remove_dir_all(&dir);
    server.join().expect("server thread");
}
