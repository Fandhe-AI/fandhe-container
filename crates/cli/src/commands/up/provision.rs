//! `up` の本番 `NetworkProvisioner`: ネットワーク定義の存在確認と作成（STACK-8・NET-6・NET-9・SEC-1・REPAIR-5・TASK-155・#4638）。
//!
//! # 役割と呼び出し元
//! stack の `up()` が、参照されるネットワークを名前の昇順に [`ProductionNetworkProvisioner::ensure`] で用意する
//! （失敗は起動ゼロ）。実装は `network ls` / `network create` と **同じ関数**（`network::run_network_with`）を同じプロセス内で
//! 呼ぶだけで、名前の検証（予約名 `none` / `host`・文字種・長さ）・権限モデルの判定（rootful は `UNIMPLEMENTED`）・定義ストアの
//! 排他と期限（REPAIR-5）・op ログは既存の経路をそのまま使う。ロジックの複製は無い。
//!
//! # 契約
//! - `external = true`: 存在の確認だけを行い、無ければ `NOT_FOUND`。作らない。
//! - `external = false`: 無ければ作る（`Created`）。あれば rootless の pasta 定義であることを確かめて `Reused`。別の定義
//!   （bridge 等）なら `FAILED_PRECONDITION`（黙って流用しない）。
//! - 確認と作成の間に別プロセスが同名を作った場合（`ALREADY_EXISTS`）は、再確認して `Reused` にする。
//! - 返すのは今回の呼び出しで行ったことだけ。エラーは固定文言と `code` だけで、ネットワーク名などの値を含めない。

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_stack::cli::up::{
    NetworkProvisionError, NetworkProvisioner, NetworkRequest, ProvisionOutcome, ProvisionedNetwork,
};

use super::super::CliExit;
use super::super::args::{GlobalArgs, NetworkArgs};
use super::super::create_network::PublishPrivilege;
use super::super::network::run_network_with;

/// 権限モデルの解決（本番は `create_network::resolve_publish_privilege`。試験は差し替える）。
pub(super) type ResolvePrivilege = fn() -> Result<PublishPrivilege, TraitError>;

/// 本番の [`NetworkProvisioner`]。
pub(super) struct ProductionNetworkProvisioner<'a> {
    global: &'a GlobalArgs,
    resolve: ResolvePrivilege,
}

impl<'a> ProductionNetworkProvisioner<'a> {
    pub(super) fn new(global: &'a GlobalArgs, resolve: ResolvePrivilege) -> Self {
        Self { global, resolve }
    }

    /// `network ls` の出力から `(名前, モード)` の組を読む。
    fn list(&self) -> Result<Vec<(String, String)>, NetworkProvisionError> {
        let mut buf = Vec::new();
        let resolve = self.resolve;
        match run_network_with(self.global, &NetworkArgs::Ls, &mut buf, resolve) {
            CliExit::Success => {}
            CliExit::Error(e) => return Err(NetworkProvisionError::new(e.code_str(), MSG_LIST)),
            _ => return Err(NetworkProvisionError::new("INTERNAL", MSG_LIST)),
        }
        let text =
            String::from_utf8(buf).map_err(|_| NetworkProvisionError::new("INTERNAL", MSG_LIST))?;
        Ok(text
            .lines()
            .skip(1)
            .filter_map(|l| {
                let mut cols = l.split('\t');
                Some((cols.next()?.to_owned(), cols.next()?.to_owned()))
            })
            .collect())
    }
}

const MSG_LIST: &str = "failed to list network definitions";
const MSG_CREATE: &str = "failed to create the network definition";
const MSG_NOT_FOUND: &str = "network definition was not found";
const MSG_INCOMPATIBLE: &str = "network exists with an incompatible definition";

impl NetworkProvisioner for ProductionNetworkProvisioner<'_> {
    fn ensure(
        &mut self,
        request: &NetworkRequest<'_>,
    ) -> Result<ProvisionedNetwork, NetworkProvisionError> {
        let name = request.name;
        let find = |defs: &[(String, String)]| {
            defs.iter()
                .find(|(n, _)| n == name)
                .map(|(_, mode)| mode.clone())
        };
        let check_mode = |mode: &str| -> Result<(), NetworkProvisionError> {
            if mode == "pasta" {
                Ok(())
            } else {
                Err(NetworkProvisionError::new(
                    ErrorCode::FailedPrecondition.as_str(),
                    MSG_INCOMPATIBLE,
                ))
            }
        };
        if let Some(mode) = find(&self.list()?) {
            check_mode(&mode)?;
            let outcome = if request.external {
                ProvisionOutcome::External
            } else {
                ProvisionOutcome::Reused
            };
            return Ok(ProvisionedNetwork::new(name, outcome));
        }
        if request.external {
            return Err(NetworkProvisionError::new(
                ErrorCode::NotFound.as_str(),
                MSG_NOT_FOUND,
            ));
        }
        let resolve = self.resolve;
        let mut sink = Vec::new();
        match run_network_with(
            self.global,
            &NetworkArgs::Create(name.to_owned()),
            &mut sink,
            resolve,
        ) {
            CliExit::Success => Ok(ProvisionedNetwork::new(name, ProvisionOutcome::Created)),
            CliExit::Error(e) if e.code() == ErrorCode::AlreadyExists => {
                // 確認と作成の間に別プロセスが作った。再確認して互換なら流用する。
                let mode = find(&self.list()?).ok_or_else(|| {
                    NetworkProvisionError::new(ErrorCode::Internal.as_str(), MSG_CREATE)
                })?;
                check_mode(&mode)?;
                Ok(ProvisionedNetwork::new(name, ProvisionOutcome::Reused))
            }
            CliExit::Error(e) => Err(NetworkProvisionError::new(e.code_str(), MSG_CREATE)),
            _ => Err(NetworkProvisionError::new(
                ErrorCode::Internal.as_str(),
                MSG_CREATE,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_stack::cli::up::NetworkDriver;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-up-prov-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rootless() -> Result<PublishPrivilege, TraitError> {
        Ok(PublishPrivilege::Rootless)
    }
    fn rootful() -> Result<PublishPrivilege, TraitError> {
        Ok(PublishPrivilege::Rootful)
    }

    fn global(s: &Scratch) -> GlobalArgs {
        GlobalArgs {
            root: Some(s.0.join("state")),
            ..GlobalArgs::default()
        }
    }

    fn req(name: &str, external: bool) -> NetworkRequest<'_> {
        NetworkRequest {
            name,
            driver: NetworkDriver::Bridge,
            external,
        }
    }

    /// NET-6・STACK-8・#4638: 無ければ作り（Created）、2 回目は流用（Reused）。external は作らず存在確認だけ
    /// （無ければ NOT_FOUND、あれば External）。
    #[test]
    fn net6_4638_ensure_creates_reuses_and_checks_external() {
        let s = Scratch::new("ensure");
        let g = global(&s);
        let mut p = ProductionNetworkProvisioner::new(&g, rootless);
        let e = p
            .ensure(&req("backend", true))
            .expect_err("missing external");
        assert_eq!(e.code(), "NOT_FOUND");
        let r = p.ensure(&req("backend", false)).expect("create");
        assert_eq!(
            (r.name(), r.outcome()),
            ("backend", ProvisionOutcome::Created)
        );
        let r = p.ensure(&req("backend", false)).expect("reuse");
        assert_eq!(r.outcome(), ProvisionOutcome::Reused);
        let r = p.ensure(&req("backend", true)).expect("external");
        assert_eq!(r.outcome(), ProvisionOutcome::External);
    }

    /// SEC-1・NET-6・#4638: 予約名は作れず（INVALID_ARGUMENT）、rootful は UNIMPLEMENTED で fail-closed。
    #[test]
    fn net6_4638_reserved_names_and_rootful_are_rejected() {
        let s = Scratch::new("reject");
        let g = global(&s);
        let mut p = ProductionNetworkProvisioner::new(&g, rootless);
        for reserved in ["none", "host"] {
            let e = p.ensure(&req(reserved, false)).expect_err(reserved);
            assert_eq!(e.code(), "INVALID_ARGUMENT", "{reserved}");
        }
        let s2 = Scratch::new("rootful");
        let g2 = global(&s2);
        let mut p2 = ProductionNetworkProvisioner::new(&g2, rootful);
        let e = p2.ensure(&req("backend", false)).expect_err("rootful");
        assert_eq!(e.code(), "UNIMPLEMENTED");
    }
}
