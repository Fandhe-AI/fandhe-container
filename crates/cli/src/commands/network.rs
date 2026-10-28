//! `network create` / `network rm` / `network ls` コマンド本体（定義ストアへの配線。#3066・NET-6・CLI-1・ERR-1）。
//!
//! `commands::run_to` が argv を解析した後に [`run_network`] を呼ぶ。ユーザー定義ネットワークの定義の永続化・排他・上限は
//! `fandhe-container-net` の `network_store`（`NetworkStore`・FCNET1。#3059）が担い、CLI は名前の事前検証・OS と権限モデルの
//! 判定・エラーの写像・一覧の整形だけを行う（設計は `docs/design/network-wiring.md` の D1・D2・D10）。
//!
//! # 判定順（副作用より前に拒否する。D1・D2）
//!
//! 1. 名前の検証（予約名・文字種・長さ。3 OS 共通。状態ルートを作る前）
//! 2. OS の判定（Linux 以外は `UNIMPLEMENTED`。状態ルートも作らない）
//! 3. `create` のみ権限モデル。rootless は pasta の定義、rootful は subnet の pool 予約（D13・#3207 のオーナー判断待ち）が
//!    無いため `UNIMPLEMENTED`
//! 4. 状態ルートを開き（`open_store`）、定義ストアを開いて操作する
//!
//! # 出力形式（`ls`・stdout・タブ区切り・LF 固定。`list` に揃える）
//!
//! 固定ヘッダ `NAME\tMODE\tSUBNET`、1 定義 1 行（名前昇順は net の順序）。`MODE` は `pasta` / `bridge`、`SUBNET` は
//! bridge の `a.b.c.d/nn`、pasta は `-`。0 件はヘッダのみ。値は net が検証済みの名前・固定語・prefix だけでエスケープ不要。
//! 破損した項目があれば、読めた定義を出力したうえで固定文言で非 0 終了する（1 件の破損で他を隠さず、成功とも見せない）。
//!
//! # エラー写像（ERR-1）
//!
//! net の `NetErrorCode` を core の `ErrorCode` へ同名で写し、文言は本 module の固定表だけを使う。入力値・パス・
//! `NetError::message` は出力へ流さない。supervisor の `net_error_to_trait` は `AlreadyExists` などを `Internal` に潰すため使わない。
//!
//! # 未実装・前提（REPAIR-3）
//!
//! - rootful（bridge）の `create` は subnet の pool 予約（D13）が決まるまで `UNIMPLEMENTED`。
//! - メンバー記録（#3067）が入るまで `rm` が拒否するのは、`definition` と `@lock` 以外の項目がある場合（net の `remove` の契約）。
//! - `create --network <名前>` での定義の存在照合は #1873 の範囲で、ここでは触れない。
//! - net の `NetOpRecorder` の CLI の `OpRecorder` への結線（REPAIR-4）は未配線。

use std::io::Write;

use fandhe_container_core::traits::{ErrorCode, StateStore, TraitError};
use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_store::{
    InstallMode, NetworkDefinition, NetworkStore, is_reserved_network_name,
};

use super::CliExit;
use super::args::{GlobalArgs, NetworkArgs};
use super::create_network::{PublishPrivilege, resolve_publish_privilege};
use super::create_start::open_store;
use super::list_logs::store_open_failure;
use crate::error::CliError;

/// `ls` の固定ヘッダ行（LF 終端）。
const NETWORK_LS_HEADER: &str = "NAME\tMODE\tSUBNET\n";

const MSG_RESERVED: &str = "network name is reserved";
const MSG_INVALID: &str = "invalid network name";
const MSG_ALREADY_EXISTS: &str = "network already exists";
const MSG_NOT_FOUND: &str = "network not found";
const MSG_RM_PRECONDITION: &str = "network cannot be removed in its current state";
const MSG_STORE_PRECONDITION: &str = "network store is not in the expected state";
const MSG_LIMIT: &str = "network limit reached";
const MSG_PERMISSION: &str = "network store permission denied";
const MSG_TIMEOUT: &str = "network store lock timed out";
const MSG_UNSUPPORTED_OS: &str = "network commands are not supported on this platform yet";
const MSG_ROOTFUL: &str = "user-defined networks on rootful installations are not supported yet";
const MSG_INTERNAL: &str = "network store operation failed";
const MSG_CORRUPTED: &str =
    "network store has a corrupted entry; ask an administrator to inspect and repair it manually";

/// どの操作の失敗か。同じ `FailedPrecondition` でも `rm` と他では案内が違う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Create,
    Rm,
    Ls,
}

/// 本番入口。権限モデルは `create` と同じ解決（`start` と共有の `classify_launcher_beside`）を使う。
pub(super) fn run_network(
    global: &GlobalArgs,
    args: &NetworkArgs,
    stdout: &mut dyn Write,
) -> CliExit {
    run_network_with(global, args, stdout, resolve_publish_privilege)
}

/// 権限モデルの解決を差し替えられる本体（試験用。`create` のときだけ呼ぶ）。
pub(super) fn run_network_with(
    global: &GlobalArgs,
    args: &NetworkArgs,
    stdout: &mut dyn Write,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
) -> CliExit {
    match args {
        NetworkArgs::Create(name) => {
            let name = match validate_name(name) {
                Ok(n) => n,
                Err(e) => return e,
            };
            if !cfg!(target_os = "linux") {
                return unsupported_os();
            }
            match resolve_privilege() {
                Ok(PublishPrivilege::Rootless) => {}
                Ok(PublishPrivilege::Rootful) => return unimplemented(MSG_ROOTFUL),
                Ok(PublishPrivilege::Unavailable) => return unsupported_os(),
                Err(e) => return CliExit::Error(CliError::new(e.code(), e.message())),
            }
            let def = match NetworkDefinition::pasta(name.as_str()) {
                Ok(d) => d,
                Err(e) => return net_failure(e.code(), Op::Create),
            };
            let store = match open_net_store(global, Op::Create) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match store.create(&def) {
                Ok(()) => CliExit::Success,
                Err(e) => net_failure(e.code(), Op::Create),
            }
        }
        NetworkArgs::Rm(name) => {
            let name = match validate_name(name) {
                Ok(n) => n,
                Err(e) => return e,
            };
            if !cfg!(target_os = "linux") {
                return unsupported_os();
            }
            let store = match open_net_store(global, Op::Rm) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match store.remove(&name) {
                Ok(()) => CliExit::Success,
                Err(e) => net_failure(e.code(), Op::Rm),
            }
        }
        NetworkArgs::Ls => {
            if !cfg!(target_os = "linux") {
                return unsupported_os();
            }
            let store = match open_net_store(global, Op::Ls) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let listing = match store.list() {
                Ok(l) => l,
                Err(e) => return net_failure(e.code(), Op::Ls),
            };
            let mut out = String::from(NETWORK_LS_HEADER);
            for def in &listing.definitions {
                let (mode, subnet) = match def.install() {
                    InstallMode::Pasta => ("pasta", "-".to_owned()),
                    InstallMode::Bridge { subnet } => (
                        "bridge",
                        format!("{}/{}", subnet.addr(), subnet.prefix_len()),
                    ),
                };
                out.push_str(&format!("{}\t{mode}\t{subnet}\n", def.name().as_str()));
            }
            if stdout.write_all(out.as_bytes()).is_err() {
                return CliExit::failed(ErrorCode::Internal);
            }
            // 読めた行は出した上で、破損は成功と見せない。項目名は出さない。
            if let Some((_, code)) = listing.broken.first() {
                return corrupted(map_code(*code));
            }
            if listing.unrecognized > 0 {
                return corrupted(ErrorCode::FailedPrecondition);
            }
            CliExit::Success
        }
    }
}

/// 名前を検証する。予約名と文字種・長さの違反は `INVALID_ARGUMENT`（副作用より前。D2）。
fn validate_name(name: &str) -> Result<NetworkName, CliExit> {
    if is_reserved_network_name(name) {
        return Err(invalid(MSG_RESERVED));
    }
    NetworkName::new(name).map_err(|_| invalid(MSG_INVALID))
}

fn invalid(msg: &'static str) -> CliExit {
    CliExit::Error(CliError::new(ErrorCode::InvalidArgument, msg))
}

fn unimplemented(msg: &'static str) -> CliExit {
    CliExit::Error(CliError::new(ErrorCode::Unimplemented, msg))
}

fn unsupported_os() -> CliExit {
    unimplemented(MSG_UNSUPPORTED_OS)
}

fn corrupted(code: ErrorCode) -> CliExit {
    CliExit::Error(CliError::new(code, MSG_CORRUPTED))
}

/// 状態ルートを開き、その配下の定義ストアを開く。
fn open_net_store(global: &GlobalArgs, op: Op) -> Result<NetworkStore, CliExit> {
    let state = open_store(global).map_err(|e| store_open_failure(&e))?;
    let root = state
        .host_state_root()
        .ok_or_else(|| CliExit::failed(ErrorCode::Internal))?;
    NetworkStore::open(root).map_err(|e| net_failure(e.code(), op))
}

/// net の分類を core の `ErrorCode` へ写す（`DataLoss`・未知は `Internal`）。
fn map_code(code: NetErrorCode) -> ErrorCode {
    match code {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        NetErrorCode::NotFound => ErrorCode::NotFound,
        NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        NetErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        NetErrorCode::Timeout => ErrorCode::Timeout,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        _ => ErrorCode::Internal,
    }
}

/// net の失敗を ERR-1 の固定文言つきの終了値へ写す。
fn net_failure(code: NetErrorCode, op: Op) -> CliExit {
    let msg = match code {
        NetErrorCode::InvalidArgument => MSG_INVALID,
        NetErrorCode::AlreadyExists => MSG_ALREADY_EXISTS,
        NetErrorCode::NotFound => MSG_NOT_FOUND,
        NetErrorCode::FailedPrecondition if op == Op::Rm => MSG_RM_PRECONDITION,
        NetErrorCode::FailedPrecondition => MSG_STORE_PRECONDITION,
        NetErrorCode::ResourceExhausted => MSG_LIMIT,
        NetErrorCode::PermissionDenied => MSG_PERMISSION,
        NetErrorCode::Timeout => MSG_TIMEOUT,
        NetErrorCode::Unimplemented => MSG_UNSUPPORTED_OS,
        _ => MSG_INTERNAL,
    };
    CliExit::Error(CliError::new(map_code(code), msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stderr_of(exit: &CliExit) -> String {
        let mut v = Vec::new();
        exit.write_stderr(&mut v).expect("write");
        String::from_utf8(v).expect("utf8")
    }

    fn json(code: &str, msg: &str) -> String {
        format!("{{\"code\":\"{code}\",\"message\":\"{msg}\"}}\n")
    }

    /// ERR-1・NET-6: 全 `NetErrorCode` の写像が表どおりで、文言が JSON 安全な定数であること。
    #[test]
    fn err1_net6_network_failure_mapping_is_total() {
        let expect = |c: NetErrorCode, op: Op| -> (&'static str, &'static str) {
            match (c, op) {
                (NetErrorCode::InvalidArgument, _) => ("INVALID_ARGUMENT", MSG_INVALID),
                (NetErrorCode::AlreadyExists, _) => ("ALREADY_EXISTS", MSG_ALREADY_EXISTS),
                (NetErrorCode::NotFound, _) => ("NOT_FOUND", MSG_NOT_FOUND),
                (NetErrorCode::FailedPrecondition, Op::Rm) => {
                    ("FAILED_PRECONDITION", MSG_RM_PRECONDITION)
                }
                (NetErrorCode::FailedPrecondition, _) => {
                    ("FAILED_PRECONDITION", MSG_STORE_PRECONDITION)
                }
                (NetErrorCode::ResourceExhausted, _) => ("RESOURCE_EXHAUSTED", MSG_LIMIT),
                (NetErrorCode::PermissionDenied, _) => ("PERMISSION_DENIED", MSG_PERMISSION),
                (NetErrorCode::Timeout, _) => ("TIMEOUT", MSG_TIMEOUT),
                (NetErrorCode::Unimplemented, _) => ("UNIMPLEMENTED", MSG_UNSUPPORTED_OS),
                _ => ("INTERNAL", MSG_INTERNAL),
            }
        };
        assert_eq!(NetErrorCode::ALL.len(), 10);
        for c in NetErrorCode::ALL {
            for op in [Op::Create, Op::Rm, Op::Ls] {
                let (code, msg) = expect(c, op);
                assert_eq!(
                    stderr_of(&net_failure(c, op)),
                    json(code, msg),
                    "{c:?} {op:?}"
                );
            }
        }
        for m in [
            MSG_RESERVED,
            MSG_INVALID,
            MSG_ALREADY_EXISTS,
            MSG_NOT_FOUND,
            MSG_RM_PRECONDITION,
            MSG_STORE_PRECONDITION,
            MSG_LIMIT,
            MSG_PERMISSION,
            MSG_TIMEOUT,
            MSG_UNSUPPORTED_OS,
            MSG_ROOTFUL,
            MSG_INTERNAL,
            MSG_CORRUPTED,
        ] {
            assert!(
                m.chars().all(|c| c != '"' && c != '\\' && !c.is_control()),
                "{m}"
            );
        }
    }

    /// NET-6・D2: 名前の検証は副作用（状態ルートの作成）より前で、3 OS で同じ結果になる。
    #[test]
    fn net6_network_reserved_and_invalid_names_rejected_first() {
        let global = GlobalArgs::default();
        let long = "a".repeat(65);
        for (name, msg) in [
            ("none", MSG_RESERVED),
            ("host", MSG_RESERVED),
            ("bridge", MSG_RESERVED),
            ("default", MSG_RESERVED),
            ("Bad!", MSG_INVALID),
            (long.as_str(), MSG_INVALID),
        ] {
            for args in [
                NetworkArgs::Create(name.to_owned()),
                NetworkArgs::Rm(name.to_owned()),
            ] {
                let mut out = Vec::new();
                let exit = run_network_with(&global, &args, &mut out, || {
                    panic!("privilege must not be resolved before name validation")
                });
                assert_eq!(stderr_of(&exit), json("INVALID_ARGUMENT", msg), "{name}");
                assert_eq!(exit.exit_code(), 2);
                assert!(out.is_empty());
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn net6_network_non_linux_is_unimplemented_without_side_effects() {
        let global = GlobalArgs::default();
        for args in [
            NetworkArgs::Create("n1".into()),
            NetworkArgs::Rm("n1".into()),
            NetworkArgs::Ls,
        ] {
            let mut out = Vec::new();
            let exit = run_network_with(&global, &args, &mut out, || {
                panic!("privilege must not be resolved")
            });
            assert_eq!(stderr_of(&exit), json("UNIMPLEMENTED", MSG_UNSUPPORTED_OS));
            assert_eq!(exit.exit_code(), 8);
            assert!(out.is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;

        /// 0700 の一時ディレクトリ（状態ルートの親。Drop で親ごと消える）。
        struct Base(
            PathBuf,
            #[allow(dead_code)] crate::scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
        );

        impl Base {
            fn new() -> Self {
                use std::os::unix::fs::PermissionsExt;
                let scratch = crate::scratch_root::ScratchDir::new(
                    "fc-cli-net6",
                    std::time::Duration::from_secs(10),
                );
                let p = scratch.path().join("base");
                std::fs::create_dir(&p).expect("mkdir");
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
                Self(p, scratch)
            }
            fn global(&self) -> GlobalArgs {
                GlobalArgs {
                    root: Some(self.0.join("state")),
                    ..GlobalArgs::default()
                }
            }
        }

        fn rootless() -> Result<PublishPrivilege, TraitError> {
            Ok(PublishPrivilege::Rootless)
        }

        fn run(g: &GlobalArgs, a: NetworkArgs) -> (CliExit, String) {
            let mut out = Vec::new();
            let exit = run_network_with(g, &a, &mut out, rootless);
            (exit, String::from_utf8(out).expect("utf8"))
        }

        fn ok(g: &GlobalArgs, a: NetworkArgs) -> String {
            let (exit, out) = run(g, a);
            assert_eq!(exit.exit_code(), 0, "{}", stderr_of(&exit));
            out
        }

        /// NET-6・CLI-1: create → ls → rm → ls の往復と、出力が名前昇順・固定ヘッダであること。
        #[test]
        fn net6_cli1_network_create_ls_rm_roundtrip() {
            let base = Base::new();
            let g = base.global();
            assert_eq!(ok(&g, NetworkArgs::Ls), "NAME\tMODE\tSUBNET\n");
            ok(&g, NetworkArgs::Create("n2".into()));
            ok(&g, NetworkArgs::Create("n1".into()));
            assert_eq!(
                ok(&g, NetworkArgs::Ls),
                "NAME\tMODE\tSUBNET\nn1\tpasta\t-\nn2\tpasta\t-\n"
            );
            ok(&g, NetworkArgs::Rm("n1".into()));
            assert_eq!(
                ok(&g, NetworkArgs::Ls),
                "NAME\tMODE\tSUBNET\nn2\tpasta\t-\n"
            );
        }

        /// ERR-1・NET-6: 既存の名前への create は ALREADY_EXISTS（定義は変わらない）。
        #[test]
        fn err1_net6_network_create_existing_is_already_exists() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let (exit, out) = run(&g, NetworkArgs::Create("n1".into()));
            assert_eq!(
                stderr_of(&exit),
                json("ALREADY_EXISTS", "network already exists")
            );
            assert_eq!(exit.exit_code(), 4);
            assert!(out.is_empty());
        }

        #[test]
        fn err1_net6_network_rm_missing_is_not_found() {
            let base = Base::new();
            let g = base.global();
            let (exit, _) = run(&g, NetworkArgs::Rm("n1".into()));
            assert_eq!(stderr_of(&exit), json("NOT_FOUND", "network not found"));
            assert_eq!(exit.exit_code(), 3);
        }

        /// ERR-1・NET-6・D10: メンバー等の余分な項目があるネットワークの rm は FAILED_PRECONDITION で、定義を消さない。
        #[test]
        fn err1_net6_network_rm_with_members_is_failed_precondition() {
            use std::os::unix::fs::DirBuilderExt;
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let members = base.0.join("state/@networks/n1/members");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&members)
                .expect("members");
            let (exit, _) = run(&g, NetworkArgs::Rm("n1".into()));
            assert_eq!(
                stderr_of(&exit),
                json(
                    "FAILED_PRECONDITION",
                    "network cannot be removed in its current state"
                )
            );
            assert_eq!(exit.exit_code(), 5);
            assert_eq!(
                ok(&g, NetworkArgs::Ls),
                "NAME\tMODE\tSUBNET\nn1\tpasta\t-\n"
            );
        }

        /// NET-6・D2: 名前の違反は状態ルートを作る前に拒否する。
        #[test]
        fn net6_network_invalid_name_does_not_create_state_root() {
            let base = Base::new();
            let g = base.global();
            let (exit, _) = run(&g, NetworkArgs::Create("none".into()));
            assert_eq!(exit.exit_code(), 2);
            assert!(!base.0.join("state").exists());
        }

        /// NET-6・D13: rootful / 判定不能の create は UNIMPLEMENTED で、状態ルートを作らない。解決の失敗は FAILED_PRECONDITION。
        #[test]
        fn net6_network_create_rootful_is_unimplemented() {
            let base = Base::new();
            let g = base.global();
            let mut out = Vec::new();
            let a = NetworkArgs::Create("n1".into());
            let exit = run_network_with(&g, &a, &mut out, || Ok(PublishPrivilege::Rootful));
            assert_eq!(stderr_of(&exit), json("UNIMPLEMENTED", MSG_ROOTFUL));
            assert_eq!(exit.exit_code(), 8);
            let exit = run_network_with(&g, &a, &mut out, || Ok(PublishPrivilege::Unavailable));
            assert_eq!(stderr_of(&exit), json("UNIMPLEMENTED", MSG_UNSUPPORTED_OS));
            let exit = run_network_with(&g, &a, &mut out, || {
                Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "privileged launcher is not a trusted executable",
                ))
            });
            assert_eq!(
                stderr_of(&exit),
                json(
                    "FAILED_PRECONDITION",
                    "privileged launcher is not a trusted executable"
                )
            );
            assert!(out.is_empty());
            assert!(!base.0.join("state").exists());
        }

        /// NET-6・ERR-1: 定義が壊れていても、読めた行は出した上で非 0 と固定文言で終える。
        #[test]
        fn net6_network_ls_reports_corruption_after_valid_rows() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            ok(&g, NetworkArgs::Create("n2".into()));
            std::fs::write(base.0.join("state/@networks/n2/definition"), b"garbage")
                .expect("corrupt");
            let (exit, out) = run(&g, NetworkArgs::Ls);
            assert_eq!(out, "NAME\tMODE\tSUBNET\nn1\tpasta\t-\n");
            assert_ne!(exit.exit_code(), 0);
            assert!(
                stderr_of(&exit).contains(MSG_CORRUPTED),
                "{}",
                stderr_of(&exit)
            );
            assert!(!stderr_of(&exit).contains("n2"));
        }
    }
}
