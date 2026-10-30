//! ユーザー定義名の `--network` が指すネットワーク定義の照合(NET-6・NET-9・CLI-1・SEC-1・#3329)。
//!
//! # 役割と呼び出し文脈
//!
//! rootless のユーザー定義ネットワーク(pasta 構成)は、定義ストア(`<状態ルート>/@networks`。D10)の定義が
//! `InstallMode::Pasta` であることを前提にする。この前提を次の 2 か所が同じ関数で確かめ、規則を二重に書かない
//! (REPAIR-1)。
//!
//! - CLI の `create`: 状態ルート・`@networks` を作る前に、読み取りだけで確かめる
//!   (`docs/design/network-wiring.md` D2)。
//! - supervisor の start の手順 2c: create から start までの間に `network rm` された場合の起動を拒否する(D10)。
//!
//! 本関数は**分類だけ**を返す([`DefinitionCheck`])。コードと文言への写像は create と start で異なるため、
//! 呼び出し側が持つ。ストアは `NetworkStore::open_existing_with_recorder` で開き、何も作らない。
//!
//! # 残余(REPAIR-3)
//!
//! 照合の後、pasta の起動までの間の `network rm` は防げない。pasta の定義はカーネル資源を持たないラベルのため、
//! 分離は弱まらない(`network-wiring.md` D10)。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::instrument::NetOpRecorder;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_store::{InstallMode, NetworkStore};

/// 照合の失敗の分類(入力値を含めない)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionCheck {
    /// 状態ルート・`@networks` が無い、または名前の定義が無い。
    Missing,
    /// 定義はあるが pasta 構成(`InstallMode::Pasta`)ではない。
    NotPasta,
    /// ストアの検査違反・ロックの期限切れなど(コードは net のものを保つ)。
    Store(NetError),
}

/// `name` の定義が存在し、pasta 構成であることを、何も作らずに確かめる。
///
/// `lock_timeout` は定義の読み取りで取る共有ロックの待ちの上限(REPAIR-5)。`recorder` は定義ストアの
/// 操作の記録先(REPAIR-4)。
pub fn check_pasta_definition(
    state_root: &Path,
    name: &NetworkName,
    lock_timeout: Duration,
    recorder: Option<Arc<dyn NetOpRecorder>>,
) -> Result<(), DefinitionCheck> {
    let opened = match recorder {
        Some(r) => NetworkStore::open_existing_with_recorder(state_root, r),
        None => NetworkStore::open_existing(state_root),
    };
    let store = match opened.map_err(DefinitionCheck::Store)? {
        Some(s) => s.with_lock_timeout(lock_timeout),
        None => return Err(DefinitionCheck::Missing),
    };
    match store.get(name) {
        Ok(def) => match def.install() {
            InstallMode::Pasta => Ok(()),
            _ => Err(DefinitionCheck::NotPasta),
        },
        Err(e) if e.code() == NetErrorCode::NotFound => Err(DefinitionCheck::Missing),
        Err(e) => Err(DefinitionCheck::Store(e)),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use fandhe_container_net::netlink_route::IpPrefix;
    use fandhe_container_net::network_store::NetworkDefinition;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let p = std::env::temp_dir()
                .join(format!("fc-netdef-{}-{tag}-{nanos}", std::process::id()));
            std::fs::create_dir(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn nn(s: &str) -> NetworkName {
        NetworkName::new(s).expect("name")
    }

    fn check(root: &Path, name: &str) -> Result<(), DefinitionCheck> {
        check_pasta_definition(root, &nn(name), Duration::from_secs(1), None)
    }

    /// NET-6・CLI-1(#3329): pasta の定義は `Ok`、無い・状態ルートが無いは `Missing`(何も作らない)。
    #[test]
    fn net6_3329_pasta_definition_ok_and_missing() {
        let t = Tmp::new("ok");
        assert_eq!(check(&t.0, "web"), Err(DefinitionCheck::Missing));
        assert!(!t.0.join("@networks").exists());
        let gone = t.0.join("none");
        assert_eq!(check(&gone, "web"), Err(DefinitionCheck::Missing));
        assert!(!gone.exists());
        let s = NetworkStore::open(&t.0).expect("open");
        s.create(&NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        assert_eq!(check(&t.0, "web"), Ok(()));
        assert_eq!(check(&t.0, "other"), Err(DefinitionCheck::Missing));
        s.remove(&nn("web")).expect("rm");
        assert_eq!(check(&t.0, "web"), Err(DefinitionCheck::Missing));
    }

    /// NET-6(#3329): bridge の定義は `NotPasta`。
    #[test]
    fn net6_3329_bridge_definition_is_not_pasta() {
        let t = Tmp::new("bridge");
        let sub = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 1, 0)), 24).expect("prefix");
        NetworkStore::open(&t.0)
            .expect("open")
            .create(&NetworkDefinition::bridge("br", sub).expect("def"))
            .expect("create");
        assert_eq!(check(&t.0, "br"), Err(DefinitionCheck::NotPasta));
    }

    /// REPAIR-5(#3329): 排他ロックが握られていれば期限内に `Store(Timeout)` で戻る。
    #[test]
    fn repair5_3329_lock_contention_times_out_within_deadline() {
        let t = Tmp::new("lock");
        let s = NetworkStore::open(&t.0).expect("open");
        s.create(&NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        let _g = s.lock_global_exclusive().expect("lock");
        let started = std::time::Instant::now();
        let r = check_pasta_definition(&t.0, &nn("web"), Duration::from_millis(200), None);
        let el = started.elapsed();
        match r {
            Err(DefinitionCheck::Store(e)) => assert_eq!(e.code(), NetErrorCode::Timeout),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(el < Duration::from_secs(3), "{el:?}");
    }
}
