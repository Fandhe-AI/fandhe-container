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
//! 5. `rm` のみ、全体の排他ロックを取り、そのロックの下で定義の存在確認（無ければ `NOT_FOUND`）→ 参照するコンテナの走査
//!    （`network_refs`。#3529）→ 定義ストアの `remove`（#3550。create は定義の照合から状態記録の作成まで共有ロックを持つので、
//!    その間の rm は待たされ、期限で `TIMEOUT`。REPAIR-5）
//!
//! # 出力形式（`ls`・stdout・タブ区切り・LF 固定。`list` に揃える）
//!
//! 固定ヘッダ `NAME\tMODE\tSUBNET`、1 定義 1 行（名前昇順は net の順序）。`MODE` は `pasta` / `bridge`、`SUBNET` は
//! bridge の `a.b.c.d/nn`、pasta は `-`。0 件はヘッダのみ。値は net が検証済みの名前・固定語・prefix だけでエスケープ不要。
//! 破損した項目があれば、読めた定義を出力したうえで固定文言で非 0 終了する（1 件の破損で他を隠さず、成功とも見せない）。
//!
//! # エラー写像（ERR-1）
//!
//! net の `NetErrorCode` を core の `ErrorCode` へ同名で写し（写像は supervisor の `net_error::net_code_to_trait` を共有）、
//! 文言は本 module の固定表だけを使う。入力値・パス・`NetError::message` は出力へ流さない。
//! `container_options::network::net_error_to_trait` は `AlreadyExists` などを `Internal` に潰す別の契約のため使わない。
//!
//! # 未実装・前提（REPAIR-3）
//!
//! - rootful（bridge）の `create` は subnet の pool 予約（D13）が決まるまで `UNIMPLEMENTED`。
//! - `rm` は、net の `remove`（`definition` と `@lock` 以外の項目、つまり bridge のメンバー・孤児の記録があれば拒否）に加え、
//!   rootless（pasta）のコンテナの起動オプション文書（FCOPT1）が対象を参照していれば、作成済み・停止中・実行中を問わず
//!   `FAILED_PRECONDITION` で拒否する（#3529・D10）。create との窓は #3550 で閉じた（`network_refs` の doc を参照）。
//! - `create --network <名前>` での定義の存在照合は `create_network::require_named_definition`(#3329)で、ここでは触れない。
//! - 計測（REPAIR-4）: `net_recorder::CliNetRecorder` で定義ストアの操作を `network.store.*`、コマンド全体を `network_create` /
//!   `network_rm` / `network_ls` の名前で記録し、`FANDHE_CONTAINER_OP_LOG` へ出す。

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::state_store::FileStateStore;
use fandhe_container_core::traits::{ErrorCode, StateStore, TraitError};
use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_store::{
    DEFAULT_LOCK_TIMEOUT, InstallMode, MSG_RESERVED_NETWORK_NAME, NetworkDefinition, NetworkStore,
    is_reserved_network_name,
};

use super::CliExit;
use super::args::{GlobalArgs, NetworkArgs};
use super::create_network::{
    MSG_NOT_FOUND, MSG_ROOTFUL, PublishPrivilege, resolve_publish_privilege,
};
use super::create_start::{OP_LOG_ENV, export_ops, open_store};
use super::list_logs::{record_op, store_open_failure};
use super::net_recorder::CliNetRecorder;
use super::network_refs;
use crate::error::CliError;

/// `ls` の固定ヘッダ行（LF 終端）。
const NETWORK_LS_HEADER: &str = "NAME\tMODE\tSUBNET\n";

const MSG_RESERVED: &str = MSG_RESERVED_NETWORK_NAME;
const MSG_INVALID: &str = "invalid network name";
const MSG_ALREADY_EXISTS: &str = "network already exists";
const MSG_RM_PRECONDITION: &str = "network cannot be removed in its current state";
const MSG_RM_IN_USE: &str =
    "network is in use by a container; delete the containers that use it first";
const MSG_RM_UNVERIFIED: &str =
    "network references could not be verified; inspect or delete broken containers first";
const MSG_STORE_PRECONDITION: &str = "network store is not in the expected state";
const MSG_LIMIT: &str = "network limit reached";
const MSG_PERMISSION: &str = "network store permission denied";
const MSG_TIMEOUT: &str = "network store lock timed out";
const MSG_UNSUPPORTED_OS: &str = "network commands are not supported on this platform yet";
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
    let started = Instant::now();
    let recorder = Arc::new(OpRecorder::new());
    let exit = run_network_recorded(global, args, stdout, resolve_privilege, &recorder);
    let op_name = match args {
        NetworkArgs::Create(_) => "network_create",
        NetworkArgs::Rm(_) => "network_rm",
        NetworkArgs::Ls => "network_ls",
    };
    record_op(
        &recorder,
        op_name,
        matches!(exit, CliExit::Success),
        started,
    );
    export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    exit
}

/// 記録器を外から渡せる本体（`network.store.*` がその記録器へ入る。試験で内容を固定するための入口）。
fn run_network_recorded(
    global: &GlobalArgs,
    args: &NetworkArgs,
    stdout: &mut dyn Write,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
    recorder: &Arc<OpRecorder>,
) -> CliExit {
    run_network_recorded_with_timeout(
        global,
        args,
        stdout,
        resolve_privilege,
        recorder,
        DEFAULT_LOCK_TIMEOUT,
    )
}

/// [`run_network_recorded`] の、定義ストアのロック待ちの期限を差し替えられる本体(REPAIR-5。本番は既定の期限。
/// 試験が「保持中の create に rm が期限で `TIMEOUT` になる」ことを短い時間で確かめる入口。#3550)。
fn run_network_recorded_with_timeout(
    global: &GlobalArgs,
    args: &NetworkArgs,
    stdout: &mut dyn Write,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
    recorder: &Arc<OpRecorder>,
    lock_timeout: Duration,
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
            let (_, store) = match open_net_store(global, Op::Create, recorder, lock_timeout) {
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
            let (state, store) = match open_net_store(global, Op::Rm, recorder, lock_timeout) {
                Ok(s) => s,
                Err(e) => return e,
            };
            // 参照の判定から削除までを全体の排他ロックの下で行う(create は定義の照合から状態記録の作成までを共有
            // ロックで持つので、その間の rm はここで待たされ、期限で TIMEOUT になる。D10・#3550)。
            let guard = match store.lock_global_exclusive() {
                Ok(g) => g,
                Err(e) => return net_failure(e.code(), Op::Rm),
            };
            // 定義が無い名前は、古いコンテナが参照していても NOT_FOUND(走査しない。#3529)。
            if let Err(e) = guard.get(&name) {
                return net_failure(e.code(), Op::Rm);
            }
            if let Some(exit) = refuse_if_referenced(state, &name, recorder) {
                return exit;
            }
            match guard.remove(&name) {
                Ok(()) => CliExit::Success,
                Err(e) => net_failure(e.code(), Op::Rm),
            }
        }
        NetworkArgs::Ls => {
            if !cfg!(target_os = "linux") {
                return unsupported_os();
            }
            let (_, store) = match open_net_store(global, Op::Ls, recorder, lock_timeout) {
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

/// 状態ルートを開き、その状態ストアと配下の定義ストアを返す(`rm` の使用中判定が状態ストアを使う)。
fn open_net_store(
    global: &GlobalArgs,
    op: Op,
    recorder: &Arc<OpRecorder>,
    lock_timeout: Duration,
) -> Result<(FileStateStore, NetworkStore), CliExit> {
    let state = open_store(global).map_err(|e| store_open_failure(&e))?;
    let root = state
        .host_state_root()
        .ok_or_else(|| CliExit::failed(ErrorCode::Internal))?;
    let net =
        NetworkStore::open_with_recorder(root, Arc::new(CliNetRecorder::new(Arc::clone(recorder))))
            .map_err(|e| net_failure(e.code(), op))?
            .with_lock_timeout(lock_timeout);
    Ok((state, net))
}

/// `rm` の使用中判定(#3529・D10)。参照するコンテナがあれば `FAILED_PRECONDITION`、判定できなければ fail-closed。
/// 走査は net のロックの外で、期限つきに行う。成否と所要時間は `network.refs.scan` で記録する(REPAIR-4)。
fn refuse_if_referenced(
    state: FileStateStore,
    name: &NetworkName,
    recorder: &Arc<OpRecorder>,
) -> Option<CliExit> {
    let started = Instant::now();
    let root = match state.host_state_root() {
        Some(r) => r.to_path_buf(),
        None => return Some(CliExit::failed(ErrorCode::Internal)),
    };
    let result = network_refs::scan_bounded(state, root, name.clone());
    record_op(recorder, "network.refs.scan", result.is_ok(), started);
    match result {
        Ok(network_refs::RefScan::Clear) => None,
        Ok(network_refs::RefScan::Referenced { .. }) => Some(CliExit::Error(CliError::new(
            ErrorCode::FailedPrecondition,
            MSG_RM_IN_USE,
        ))),
        Ok(_) => Some(CliExit::Error(CliError::new(
            ErrorCode::FailedPrecondition,
            MSG_RM_UNVERIFIED,
        ))),
        Err(e) => Some(CliExit::failed(e.code())),
    }
}

/// net の分類を core の `ErrorCode` へ写す（`DataLoss`・未知は `Internal`）。
fn map_code(code: NetErrorCode) -> ErrorCode {
    fandhe_container_supervisor::net_error::net_code_to_trait(code)
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
            MSG_RM_IN_USE,
            MSG_RM_UNVERIFIED,
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
        use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
        use fandhe_container_core::state_store::StateRoot;
        use fandhe_container_core::traits::{
            Annotations, ContainerId, ContainerState, ContainerStatus, CreateStateRequest,
            DeleteStateRequest, GetStateRequest, UpdateStateRequest,
        };
        use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
        use fandhe_container_supervisor::container_options::store::{
            self as options_store, GENERATION_ANNOTATION,
        };
        use std::path::PathBuf;
        use std::time::Duration;

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
            // 空の既知ディレクトリは許されるため、中身のある状態にする。
            std::fs::write(members.join("c1"), b"x").expect("member record");
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

        const PASTA_BODY: &str =
            "20260120 2049 131074 1234567 1760000000 123456789 -5 0 0 755\n/usr/bin/pasta";
        const IN_USE: &str =
            "network is in use by a container; delete the containers that use it first";
        const UNVERIFIED: &str =
            "network references could not be verified; inspect or delete broken containers first";

        fn open_state(base: &Base) -> FileStateStore {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            FileStateStore::open(root).expect("open")
        }

        /// 起動せずに状態記録だけを作る(世代注釈つき。`gen` が `None` なら plugin-cri 相当の注釈なし)。
        fn add_record(base: &Base, name: &str, generation: Option<&str>, state: ContainerState) {
            use std::num::NonZeroU32;
            let store = open_state(base);
            let bundle = base.0.join("bundle");
            std::fs::create_dir_all(&bundle).expect("bundle");
            let id = ContainerId::new(name).expect("id");
            let mut req =
                CreateStateRequest::new(ContainerStatus::created(id.clone(), None), bundle)
                    .expect("req");
            if let Some(g) = generation {
                req = req.with_annotations(
                    Annotations::new([(GENERATION_ANNOTATION.to_owned(), g.to_owned())])
                        .expect("ann"),
                );
            }
            let rev = store.create(&req).expect("create").revision();
            let status = match state {
                ContainerState::Running => ContainerStatus::running(id, NonZeroU32::new(4242)),
                ContainerState::Stopped => ContainerStatus::stopped(id, Some(0)),
                _ => return,
            };
            store
                .update(&UpdateStateRequest::new(status, rev))
                .expect("update");
        }

        /// 起動オプション文書(`--network <network>`・pasta の記録つき)を書く。
        fn write_doc(base: &Base, name: &str, network: &str, generation: &str) {
            let store = open_state(base);
            let root = store.host_state_root().expect("root").to_path_buf();
            let doc = ContainerOptionsDocument::default()
                .with_network(Some(network.to_owned()), vec![], vec![])
                .expect("net");
            let doc = if network == "none" || network == "host" {
                doc
            } else {
                doc.with_pasta(Some(PASTA_BODY.to_owned())).expect("pasta")
            };
            let doc = doc.with_generation(generation.to_owned()).expect("gen");
            options_store::write_new(&root, &ContainerId::new(name).expect("id"), &doc)
                .expect("write doc");
        }

        fn rm_exit(g: &GlobalArgs, name: &str) -> (u8, String) {
            let (exit, _) = run(g, NetworkArgs::Rm(name.into()));
            (exit.exit_code(), stderr_of(&exit))
        }

        const LS_N1: &str = "NAME\tMODE\tSUBNET\nn1\tpasta\t-\n";

        /// NET-6・NET-9・CLI-1(#3529・D10): pasta のコンテナが参照するネットワークは、作成済み・停止中・実行中のどれでも
        /// `network rm` が FAILED_PRECONDITION(終了コード 5)で拒否し、定義を消さない。入力値・コンテナ ID は出力に出ない。
        #[test]
        fn net6_net9_cli1_3529_rm_refused_for_created_stopped_running() {
            for (state, label) in [
                (ContainerState::Created, "created"),
                (ContainerState::Stopped, "stopped"),
                (ContainerState::Running, "running"),
            ] {
                let base = Base::new();
                let g = base.global();
                ok(&g, NetworkArgs::Create("n1".into()));
                add_record(&base, "c1", Some("g1"), state);
                write_doc(&base, "c1", "n1", "g1");
                let (code, err) = rm_exit(&g, "n1");
                assert_eq!(err, json("FAILED_PRECONDITION", IN_USE), "{label}");
                assert_eq!(code, 5, "{label}");
                assert!(!err.contains("c1") && !err.contains("n1"), "{label}");
                assert_eq!(ok(&g, NetworkArgs::Ls), LS_N1, "{label}");
            }
        }

        /// NET-6・NET-9・CLI-1(#3529): 参照するコンテナを delete(記録と文書を消す)すれば、rm は成功する。
        #[test]
        fn net6_net9_cli1_3529_rm_succeeds_after_referencing_container_deleted() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            add_record(&base, "c1", Some("g1"), ContainerState::Stopped);
            write_doc(&base, "c1", "n1", "g1");
            assert_eq!(rm_exit(&g, "n1").0, 5);
            let store = open_state(&base);
            let id = ContainerId::new("c1").expect("id");
            let rev = store
                .get(&GetStateRequest::new(id.clone()))
                .expect("get")
                .revision();
            store
                .delete(&DeleteStateRequest::new(id.clone(), rev))
                .expect("delete");
            let root = store.host_state_root().expect("root").to_path_buf();
            options_store::remove(&root, &id).expect("remove doc");
            assert_eq!(rm_exit(&g, "n1").0, 0);
            assert_eq!(ok(&g, NetworkArgs::Ls), "NAME\tMODE\tSUBNET\n");
        }

        /// NET-6・NET-9・CLI-1(#3529): 別のネットワーク・`none`・世代注釈なしの記録・記録の無い文書は参照とみなさない。
        #[test]
        fn net6_net9_cli1_3529_rm_ignores_unrelated_records() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            ok(&g, NetworkArgs::Create("n2".into()));
            add_record(&base, "c2", Some("g1"), ContainerState::Created);
            write_doc(&base, "c2", "n2", "g1");
            add_record(&base, "c3", Some("g1"), ContainerState::Created);
            write_doc(&base, "c3", "none", "g1");
            // plugin-cri 相当(世代注釈なし)の記録に、n1 を指す文書が残っていても参照とみなさない。
            add_record(&base, "c4", None, ContainerState::Created);
            write_doc(&base, "c4", "n1", "g1");
            // 記録の無い文書だけ(create の残骸)。
            write_doc(&base, "c5", "n1", "g1");
            assert_eq!(rm_exit(&g, "n1").0, 0);
            assert_eq!(
                ok(&g, NetworkArgs::Ls),
                "NAME\tMODE\tSUBNET\nn2\tpasta\t-\n"
            );
        }

        /// NET-6・NET-9・CLI-1(#3529): 世代つきの記録で文書が無い・世代が不一致のときは判定不能で、fail-closed に拒否する。
        #[test]
        fn net6_net9_cli1_3529_rm_unverifiable_when_document_missing_or_mismatched() {
            for mismatch in [false, true] {
                let base = Base::new();
                let g = base.global();
                ok(&g, NetworkArgs::Create("n1".into()));
                add_record(&base, "c1", Some("g1"), ContainerState::Created);
                if mismatch {
                    write_doc(&base, "c1", "n1", "g2");
                }
                let (code, err) = rm_exit(&g, "n1");
                assert_eq!(
                    err,
                    json("FAILED_PRECONDITION", UNVERIFIED),
                    "mismatch={mismatch}"
                );
                assert_eq!(code, 5);
                assert_eq!(ok(&g, NetworkArgs::Ls), LS_N1);
            }
        }

        /// NET-6・CLI-1(#3529): 定義が無い名前は、参照するコンテナが残っていても NOT_FOUND(終了コード 3)。走査の結果で変わらない。
        #[test]
        fn net6_net9_cli1_3529_rm_missing_network_is_not_found_without_scan() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            add_record(&base, "c1", Some("g1"), ContainerState::Created);
            write_doc(&base, "c1", "n1", "g1");
            let (code, err) = rm_exit(&g, "gone");
            assert_eq!(err, json("NOT_FOUND", "network not found"));
            assert_eq!(code, 3);
        }

        /// 窓の注入試験で使う: 2 回目の照合から状態記録の作成までを保持する本番の関数(`create` が使うもの)。
        fn held_create<T>(
            base: &Base,
            name: &str,
            timeout: Duration,
            body: impl FnOnce() -> Result<T, OciRuntimeError>,
        ) -> Result<T, OciRuntimeError> {
            let store = open_state(base);
            let root = store.host_state_root().expect("root").to_path_buf();
            crate::commands::create_network::with_named_definition_held(
                &root,
                &NetworkName::new(name).expect("name"),
                timeout,
                None,
                body,
            )
        }

        /// NET-6・NET-9・CLI-1・REPAIR-5(#3550): create が定義の照合から状態記録の作成までを共有ロックで持つ間に
        /// 始まった `network rm` は待たされ、create が記録を作った後に FAILED_PRECONDITION(終了コード 5)で拒否される。
        /// 定義は消えない(窓が閉じている)。
        #[test]
        fn net6_net9_cli1_3550_rm_during_create_window_waits_then_refused() {
            use std::sync::mpsc;
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let (locked_tx, locked_rx) = mpsc::channel::<()>();
            let (go_tx, go_rx) = mpsc::channel::<()>();
            let (rm_tx, rm_rx) = mpsc::channel::<(u8, String)>();
            std::thread::scope(|sc| {
                let base_ref = &base;
                let create = sc.spawn(move || {
                    let base = base_ref;
                    held_create(base, "n1", Duration::from_secs(5), || {
                        locked_tx.send(()).expect("locked");
                        go_rx.recv_timeout(Duration::from_secs(20)).expect("go");
                        // create が作る起動オプション文書と状態記録の代役。
                        write_doc(base, "c1", "n1", "g1");
                        add_record(base, "c1", Some("g1"), ContainerState::Created);
                        Ok(())
                    })
                });
                locked_rx
                    .recv_timeout(Duration::from_secs(20))
                    .expect("create holds the lock");
                sc.spawn(|| rm_tx.send(rm_exit(&g, "n1")).expect("send"));
                assert!(
                    matches!(
                        rm_rx.recv_timeout(Duration::from_millis(300)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ),
                    "rm must wait while create holds the shared lock"
                );
                go_tx.send(()).expect("go");
                let (code, err) = rm_rx
                    .recv_timeout(Duration::from_secs(20))
                    .expect("rm finishes");
                assert_eq!(err, json("FAILED_PRECONDITION", IN_USE));
                assert_eq!(code, 5);
                assert!(create.join().expect("create thread").is_ok());
            });
            assert_eq!(ok(&g, NetworkArgs::Ls), LS_N1);
        }

        /// NET-6・CLI-1(#3550): create が窓の中で失敗して何も作らなければ、rm は拒否しすぎず成功する。
        #[test]
        fn net6_cli1_3550_rm_after_failed_create_succeeds() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let r = held_create(&base, "n1", Duration::from_secs(5), || {
                Err::<(), _>(OciRuntimeError::new(
                    LifecycleOp::Create,
                    ErrorCode::Internal,
                    "injected failure",
                ))
            });
            assert!(r.is_err());
            assert_eq!(rm_exit(&g, "n1").0, 0);
            assert_eq!(ok(&g, NetworkArgs::Ls), "NAME\tMODE\tSUBNET\n");
        }

        /// NET-6・REPAIR-5(#3550): create の保持が rm のロック待ちの期限を超えたら、rm は TIMEOUT で失敗し定義を消さない。
        #[test]
        fn net6_repair5_3550_rm_times_out_while_create_holds_lock() {
            use std::sync::mpsc;
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let (locked_tx, locked_rx) = mpsc::channel::<()>();
            std::thread::scope(|sc| {
                sc.spawn(|| {
                    held_create(&base, "n1", Duration::from_secs(5), || {
                        locked_tx.send(()).expect("locked");
                        std::thread::sleep(Duration::from_millis(1500));
                        Ok(())
                    })
                });
                locked_rx
                    .recv_timeout(Duration::from_secs(20))
                    .expect("create holds the lock");
                let mut out = Vec::new();
                let exit = run_network_recorded_with_timeout(
                    &g,
                    &NetworkArgs::Rm("n1".into()),
                    &mut out,
                    rootless,
                    &Arc::new(OpRecorder::new()),
                    Duration::from_millis(300),
                );
                assert_eq!(
                    stderr_of(&exit),
                    json("TIMEOUT", "network store lock timed out")
                );
                assert_eq!(exit.exit_code(), 7);
            });
            assert_eq!(ok(&g, NetworkArgs::Ls), LS_N1);
        }

        /// NET-6・CLI-1・REPAIR-5(#3550): rm が排他ロックを持っている間の create の 2 回目の照合は、期限で TIMEOUT になり
        /// `body`(状態記録の作成)を呼ばない。定義が既に無ければ NOT_FOUND で、やはり `body` を呼ばない。
        #[test]
        fn net6_cli1_3550_create_check_times_out_or_not_found_without_body() {
            let base = Base::new();
            let g = base.global();
            ok(&g, NetworkArgs::Create("n1".into()));
            let store = open_state(&base);
            let root = store.host_state_root().expect("root").to_path_buf();
            {
                let net = NetworkStore::open(&root).expect("net");
                let _excl = net.lock_global_exclusive().expect("exclusive");
                let called = std::cell::Cell::new(false);
                let e = held_create(&base, "n1", Duration::from_millis(300), || {
                    called.set(true);
                    Ok(())
                })
                .expect_err("timeout");
                assert_eq!(e.code(), ErrorCode::Timeout);
                assert!(!called.get());
            }
            assert_eq!(rm_exit(&g, "n1").0, 0);
            let called = std::cell::Cell::new(false);
            let e = held_create(&base, "n1", Duration::from_secs(5), || {
                called.set(true);
                Ok(())
            })
            .expect_err("not found");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.message(), "network not found");
            assert!(!called.get());
        }

        /// REPAIR-4・NET-6: 成功と失敗の両方で `network.store.*` が記録器へ入る（具体値）。
        #[test]
        fn repair4_net6_network_ops_are_recorded_on_success_and_failure() {
            let base = Base::new();
            let g = base.global();
            let rec = Arc::new(OpRecorder::new());
            let mut out = Vec::new();
            let mut go =
                |a: NetworkArgs| run_network_recorded(&g, &a, &mut out, rootless, &rec).exit_code();
            assert_eq!(go(NetworkArgs::Create("n1".into())), 0);
            assert_eq!(go(NetworkArgs::Create("n1".into())), 4);
            assert_eq!(go(NetworkArgs::Ls), 0);
            assert_eq!(go(NetworkArgs::Rm("n1".into())), 0);
            assert_eq!(go(NetworkArgs::Rm("n1".into())), 3);
            let snap = rec.snapshot();
            let count = |name: &str| {
                snap.iter()
                    .find(|s| s.name().as_str() == name)
                    .map(|s| (s.success(), s.failure()))
            };
            assert_eq!(count("network.store.open"), Some((5, 0)));
            assert_eq!(count("network.store.create"), Some((1, 1)));
            assert_eq!(count("network.store.list"), Some((1, 0)));
            assert_eq!(count("network.store.remove"), Some((1, 0)));
            assert_eq!(count("network.store.get"), Some((1, 1)));
            assert_eq!(count("network.refs.scan"), Some((1, 0)));
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
