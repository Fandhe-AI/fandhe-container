//! `up` の実行本体（Linux）: 入力の読み取り・事前検査・stack の `up()` の呼び出し・出力（STACK-8・STACK-10・SEC-1・ERR-1・
//! REPAIR-5・TASK-155・#4638）。
//!
//! 流れは副作用の前に拒否する順（`up` module の doc）:
//! 1. `--file` を O_NONBLOCK で開き、通常ファイルであることを確かめてから stack の `read_compose_toml`（4 MiB 上限）で解析する。
//! 2. プロジェクト名（`resolve_project_name`: flag ＞ `[project].name` ＞ ディレクトリ名）、プロファイル、有効サービス、
//!    依存閉包を stack の関数で決める。サービス数は `MAX_PS_SERVICES` で上限を置く。
//! 3. 状態ストアとイメージストアを開き、全サービスを [`Preparer`] で事前検査する。同じ ID の記録が既にあれば
//!    `ALREADY_EXISTS`（再利用は未実装）。
//! 4. pasta のフラグがあるのにユーザー定義ネットワークを持つサービスが無ければ `INVALID_ARGUMENT`。
//! 5. ここで初めて `up()` を呼び、ネットワークの用意・bundle の作成・子プロセスの起動を行う。
//!
//! 出力: 成功時は stdout に `SERVICE\tCONTAINER\tNETWORK` と起動順の行（名前は表示用に無害化し、長さと件数を制限する。#3651）。
//! 失敗時は ERR-1 の構造化エラー 1 行（stderr の最後の行）で、`message` の末尾に先に起動済みのサービス名（最大 8 件）を添える（stderr へ直接書かず main の期限つき出力経路に載せる。#4734）。
//! 終了コードは `UpError::exit_code`（子の終了コードを運ぶ）を ERR-2 の表で `ErrorCode` に戻したもの。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use fandhe_container_core::traits::{ErrorCode, StateStore as _, TraitError};
use fandhe_container_stack::cli::up::{
    UpClock, UpError, UpFailure, UpPolicy, UpProject, UpReport, plan_networks,
    resolve_project_name, up,
};
use fandhe_container_stack::cli::{MAX_PS_NAME_BYTES, MAX_PS_SERVICES, sanitize_display};
use fandhe_container_stack::depends_on::dependency_closure;
use fandhe_container_stack::profile_filter::{
    PROFILES_ENV, resolve_active_profiles, select_enabled_services,
};
use fandhe_container_stack::schema::Service;
use fandhe_container_stack::toml_input::read_compose_toml;

use super::super::CliExit;
use super::super::args::{CreateNetworkArgs, GlobalArgs, PastaSource, UpArgs};
use super::super::create_network::{check_network_options, resolve_publish_privilege};
use super::super::create_pasta::{decide as decide_pasta, detect_install};
use super::super::create_start::open_store;
use super::super::image::open_image_store_for_lifecycle;
use super::super::list_logs::store_open_failure;
use super::bundle::ProjectLock;
use super::error_code_for_exit;
use super::launcher::{LauncherConfig, ProductionServiceLauncher};
use super::observe::{Ledger, SharedLedger, StateHealth, StateObserver, read_status};
use super::prepare::{EnvReadBudget, Prepared, Preparer};
use super::provision::ProductionNetworkProvisioner;
use crate::error::CliError;

/// `O_NONBLOCK`（Linux の x86_64 / aarch64 とも 0o4000）。FIFO を開いて止まらないために使う。
const O_NONBLOCK: i32 = 0o4000;
/// 成功出力の書き込みを待つ上限（`main.rs` の `DEFERRED_REPORT_TIMEOUT` と同じ値。REPAIR-5）。
const STDOUT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// 失敗時に `info:` の行へ出す起動済みサービス名の最大件数。
const MAX_INFO_NAMES: usize = 8;

fn err(code: ErrorCode, msg: impl AsRef<str>) -> CliExit {
    CliExit::Error(CliError::new(code, msg))
}

fn from_trait(e: &TraitError) -> CliExit {
    err(e.code(), e.message())
}

/// 成功出力を別スレッドで process の stdout へ書き、`timeout` までだけ待つ（REPAIR-5・#4734）。
///
/// `commands::run` は main スレッドで動くため、読み進められない pipe / socket への `write_all` は無期限に止まり得る。
/// 出力サイズの上限では書き込み待ちを制限できないので、書き込みを作業スレッドへ出す。期限切れのスレッドは置き去りにする
/// （main の return でプロセスごと破棄される）。起動失敗・書き込み失敗は `INTERNAL`、期限切れは `TIMEOUT`。
fn write_stdout_bounded(bytes: Vec<u8>, timeout: std::time::Duration) -> Result<(), ErrorCode> {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("up-stdout".to_owned())
        .spawn(move || {
            let mut out = std::io::stdout().lock();
            let r = out.write_all(&bytes).and_then(|()| out.flush());
            let _ = tx.send(r.is_ok());
        });
    if spawned.is_err() {
        return Err(ErrorCode::Internal);
    }
    match rx.recv_timeout(timeout) {
        Ok(true) => Ok(()),
        Ok(false) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(ErrorCode::Internal)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(ErrorCode::Timeout),
    }
}

/// 無害化して長さを制限した表示用の名前。
fn display_name(s: &str) -> String {
    let mut end = s.len().min(MAX_PS_NAME_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    sanitize_display(&s[..end])
}

/// `--file` を読んで解析する（FIFO・デバイスで止まらない。上限は stack の入口が持つ）。
fn read_project_file(file: &Path) -> Result<fandhe_container_stack::schema::ComposeToml, CliExit> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(file)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => err(ErrorCode::NotFound, "project file was not found"),
            std::io::ErrorKind::PermissionDenied => {
                err(ErrorCode::PermissionDenied, "project file is not readable")
            }
            _ => err(
                ErrorCode::InvalidArgument,
                "project file could not be opened",
            ),
        })?;
    let meta = f
        .metadata()
        .map_err(|_| err(ErrorCode::Internal, "project file could not be inspected"))?;
    if !meta.is_file() {
        return Err(err(
            ErrorCode::InvalidArgument,
            "project file must be a regular file",
        ));
    }
    read_compose_toml(f).map_err(|e| err(error_code_for_exit(e.exit_code()), e.message()))
}

/// 有効なサービスと依存閉包を決める（STACK-10・STACK-2）。
fn select_services(
    toml: &fandhe_container_stack::schema::ComposeToml,
    args: &UpArgs,
) -> Result<BTreeMap<String, Service>, CliExit> {
    let env = std::env::var_os(PROFILES_ENV);
    let active = resolve_active_profiles(
        args.profiles.iter().map(OsString::as_os_str),
        env.as_deref(),
    )
    .map_err(|e| err(error_code_for_exit(e.exit_code().get()), e.message()))?;
    let enabled = select_enabled_services(
        &toml.services,
        &active,
        args.services.iter().map(String::as_str),
    )
    .map_err(|e| err(error_code_for_exit(e.exit_code().get()), e.message()))?;
    let selected = enabled.select(&toml.services);
    let closure = dependency_closure(&selected, enabled.targets())
        .map_err(|e| err(ErrorCode::InvalidArgument, e.message()))?;
    if closure.len() > MAX_PS_SERVICES {
        return Err(err(
            ErrorCode::ResourceExhausted,
            "too many services in the project",
        ));
    }
    Ok(closure)
}

/// 成功時の stdout（ヘッダと起動順の行。LF 固定）。
fn render_success(report: &UpReport) -> String {
    let mut out = String::from("SERVICE\tCONTAINER\tNETWORK\n");
    for step in report.steps() {
        out.push_str(&display_name(step.launched().service()));
        out.push('\t');
        out.push_str(&display_name(step.launched().container_id()));
        out.push('\t');
        out.push_str(&step.network().map_or_else(|| "-".to_owned(), display_name));
        out.push('\n');
    }
    out
}

/// `NetworkProvisioner` の失敗の `code` 文字列を `ErrorCode` に戻す（未知は `Internal`。fail-closed の既定ではなく分類のみ）。
fn network_error_code(code: &str) -> ErrorCode {
    ErrorCode::from_name(code).unwrap_or(ErrorCode::Internal)
}

/// 失敗を構造化エラーへ写す（`message` は固定文言に、無害化した名前だけを添える）。
fn failure_exit(f: &UpFailure) -> CliExit {
    let e = f.error();
    let code = match e {
        // ネットワーク側の失敗は `source.code()`（ERR-1 の文字列）をそのまま運ぶ。`exit_code` は常に 1 で、
        // 使うと NOT_FOUND・UNIMPLEMENTED 等が INTERNAL に潰れる（ERR-1・#4734）。未知の文字列は INTERNAL。
        UpError::NetworkProvision { source, .. } => network_error_code(source.code()),
        _ => error_code_for_exit(e.exit_code().get()),
    };
    let message = match e {
        UpError::Launch { service, source } => format!(
            "{}: {} ({})",
            e.message(),
            display_name(service),
            source.message()
        ),
        UpError::NetworkProvision { network, source } => format!(
            "{}: {} ({})",
            e.message(),
            display_name(network),
            source.message()
        ),
        _ => e.message().to_owned(),
    };
    CliExit::Error(CliError::new(
        code,
        format!("{message}{}", launched_suffix(f)),
    ))
}

/// 起動済みのサービス名の添え書き（空なら空文字列。件数を制限する）。
///
/// stderr へ直接 `eprintln!` せず、エラーの `message` に含めて main の期限つき出力経路で出す（満杯の pipe / socket で
/// main が止まらないため。REPAIR-5・#4734）。
fn launched_suffix(f: &UpFailure) -> String {
    if f.launched().is_empty() {
        return String::new();
    }
    let shown: Vec<String> = f
        .launched()
        .iter()
        .take(MAX_INFO_NAMES)
        .map(|n| display_name(n))
        .collect();
    let more = f.launched().len().saturating_sub(MAX_INFO_NAMES);
    let more = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    format!(
        "; launched {} service(s) before the failure: {}{more}",
        f.launched().len(),
        shown.join(", ")
    )
}

/// 全サービスの `ports` を、子の `create` と同じ検証関数（`check_network_options`）で副作用の前に検証する。
/// 接続先は stack の `plan_networks` の決定（サービスごとに高々 1 つ）に従う。計画自体の失敗は `up()` の冒頭が
/// 同じ分類で報告するため、ここでは検証せず委ねる。
fn check_ports(
    services: &BTreeMap<String, Service>,
    networks: &BTreeMap<String, fandhe_container_stack::schema::Network>,
) -> Result<(), CliError> {
    let Ok(plan) = plan_networks(services, networks) else {
        return Ok(());
    };
    for (name, spec) in services {
        if spec.ports.is_empty() {
            continue;
        }
        let args = CreateNetworkArgs {
            network: plan.attachment_for(name).map(|a| a.name().to_owned()),
            publish: spec.ports.clone(),
            ..CreateNetworkArgs::default()
        };
        check_network_options(&args, resolve_publish_privilege)
            .map_err(|e| CliError::new(e.code(), e.message()))?;
    }
    Ok(())
}

/// pasta のグローバルフラグ（子の `create` の前置き）。
fn pasta_args(global: &GlobalArgs) -> Vec<OsString> {
    match &global.pasta {
        Some(PastaSource::Path(p)) => vec!["--pasta-path".into(), p.as_os_str().to_owned()],
        Some(PastaSource::PathSearch) => vec!["--pasta-path-search".into()],
        None => vec![],
    }
}

/// 子の CLI に前置きするグローバルオプション（`--root`・`--plugin-path-search`）。
fn child_globals(global: &GlobalArgs) -> Vec<OsString> {
    let mut v = Vec::new();
    if let Some(root) = &global.root {
        v.push("--root".into());
        v.push(root.as_os_str().to_owned());
    }
    if global.plugin_path_search {
        v.push("--plugin-path-search".into());
    }
    v
}

/// `up` の本体。成功出力は注入された書き込み先ではなく process の stdout へ期限つきで書く（[`write_stdout_bounded`]）。
pub(super) fn run_up(global: &GlobalArgs, args: &UpArgs, _stdout: &mut dyn Write) -> CliExit {
    // 1. 入力。
    let file: PathBuf = match std::path::absolute(&args.file) {
        Ok(p) => p,
        Err(_) => return err(ErrorCode::InvalidArgument, "project file path is invalid"),
    };
    let Some(project_dir) = file.parent().map(Path::to_path_buf) else {
        return err(ErrorCode::InvalidArgument, "project file path is invalid");
    };
    let toml = match read_project_file(&file) {
        Ok(t) => t,
        Err(e) => return e,
    };

    // 2. プロジェクト名・有効サービス・依存閉包。
    let toml_name = toml.project.as_ref().and_then(|p| p.name.as_deref());
    let project = match resolve_project_name(args.project_name.as_deref(), toml_name, &project_dir)
    {
        Ok(p) => p,
        Err(e) => return err(ErrorCode::InvalidArgument, e.message()),
    };
    let services = match select_services(&toml, args) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // pasta フラグの整合: ユーザー定義ネットワークに付くサービスが無ければ、ストアに触れる前に拒否する。
    // 参照名の検証（予約名・未定義）は stack の `plan_networks` が `up()` の冒頭で行う（起動ゼロ）。
    if global.pasta.is_some() && services.values().all(|s| s.networks.is_empty()) {
        return err(
            ErrorCode::InvalidArgument,
            "pasta flags require a service on a user-defined network",
        );
    }

    // pasta の未設定（ユーザー定義ネットワークがあるのに pasta のフラグが無い等）は、子の `create` と同じ判定
    // （`create_pasta::decide`）で、ネットワーク作成・サービス起動の前に拒否する（STACK-8・NET-9・#4734）。
    if services.values().any(|s| !s.networks.is_empty()) {
        let install = match detect_install() {
            Ok(i) => i,
            Err(e) => return from_trait(&e),
        };
        if let Err(e) = decide_pasta(global.pasta.as_ref(), true, install) {
            return from_trait(&e);
        }
    }

    // 3. ストアを開き、全サービスを事前検査する。
    let store = match open_store(global) {
        Ok(s) => s,
        Err(e) => return store_open_failure(&e),
    };
    let image_store = match open_image_store_for_lifecycle(&args.image_root) {
        Ok(s) => s,
        Err(e) => return from_trait(&e),
    };
    let Some(state_root) = store.host_state_root().map(Path::to_path_buf) else {
        return err(ErrorCode::Internal, "state root is unavailable");
    };
    // 同じプロジェクトの並行する `up` を排他する。事前検査から create / start の完了（この関数の終わり）まで保持する
    // （共有 bundle の更新と利用の競合を防ぐ。STACK-8・SEC-1・#4734）。
    let _project_lock = match ProjectLock::acquire(&state_root, project.as_str()) {
        Ok(l) => l,
        Err(e) => return CliExit::Error(e),
    };
    // env_files は symlink を辿らず読むため、起点は実体のパスにする（名前の決定には使わない）。
    let read_dir = match std::fs::canonicalize(&project_dir) {
        Ok(p) => p,
        Err(_) => {
            return err(
                ErrorCode::InvalidArgument,
                "project directory is not usable",
            );
        }
    };
    let preparer = Preparer {
        project: &project,
        project_dir: &read_dir,
        image_root: &args.image_root,
        store: &image_store,
        env_budget: EnvReadBudget::new(),
    };
    let mut prepared: BTreeMap<String, Prepared> = BTreeMap::new();
    for (name, spec) in &services {
        let p = match preparer.prepare(name, spec) {
            Ok(p) => p,
            Err(e) => return CliExit::Error(e),
        };
        match read_status(&store, &p.id) {
            Ok(o)
                if o.state
                    != fandhe_container_stack::depends_on::wait::DependencyObservation::Absent =>
            {
                return err(
                    ErrorCode::AlreadyExists,
                    format!(
                        "a container for the service already exists ({})",
                        display_name(name)
                    ),
                );
            }
            Ok(_) => {}
            Err(_) => return err(ErrorCode::Internal, "container state could not be read"),
        }
        prepared.insert(name.clone(), p);
    }

    // 3b. `ports`（`--publish`）の意味検証を副作用の前に行う（構文・ユーザー定義ネットワークとの組・rootless のみ）。
    // 子の `create` が同じ検証でネットワーク作成後に拒否する事態を防ぐ（STACK-8・NET-9・SEC-1・#4734）。
    if let Err(e) = check_ports(&services, &toml.networks) {
        return CliExit::Error(e);
    }

    // 4. 副作用はここから。
    let ledger: SharedLedger = Rc::new(std::cell::RefCell::new(Ledger::default()));
    let store = Rc::new(store);
    let cli_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => {
            return err(
                ErrorCode::FailedPrecondition,
                "cannot resolve the cli executable path",
            );
        }
    };
    let (create_deadline, start_deadline) = LauncherConfig::production_deadlines();
    let mut launcher = ProductionServiceLauncher::new(LauncherConfig {
        cli_exe,
        global_args: child_globals(global),
        pasta_args: pasta_args(global),
        image_root: args.image_root.clone(),
        state_root,
        prepared,
        ledger: Rc::clone(&ledger),
        create_deadline,
        start_deadline,
    });
    let mut provisioner = ProductionNetworkProvisioner::new(global, resolve_publish_privilege);
    let mut observer = StateObserver::new(Rc::clone(&store), Rc::clone(&ledger));
    let mut health = StateHealth::new(Rc::clone(&store), Rc::clone(&ledger));
    let mut clock = UpClock::new();
    let up_project = UpProject {
        services: &services,
        networks: &toml.networks,
    };
    match up(
        &up_project,
        &mut launcher,
        &mut provisioner,
        &mut observer,
        &mut health,
        &mut clock,
        &UpPolicy::default(),
    ) {
        Ok(report) => {
            match write_stdout_bounded(render_success(&report).into_bytes(), STDOUT_WRITE_TIMEOUT) {
                Ok(()) => CliExit::Success,
                Err(code) => CliExit::failed(code),
            }
        }
        Err(f) => failure_exit(&f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::CommandKind;

    /// CLI-2・#4638: `up` は日常操作で、`setup` を参照しない（区分の分類漏れの照合は commands の試験が担う）。
    #[test]
    fn cli2_4638_up_is_a_daily_command() {
        assert_eq!(super::super::super::Command::Up.kind(), CommandKind::Daily);
    }

    /// STACK-8・NET-9・SEC-1・#4734: `ports` の不正な構文・ネットワークなしの公開は、副作用の前の検査で
    /// `INVALID_ARGUMENT` になる（権限の解決より前に拒否されるため環境に依らない）。
    #[test]
    fn stack8_4734_check_ports_rejects_before_any_side_effect() {
        let svc = |ports: &[&str], nets: &[&str]| Service {
            image: Some("x".to_owned()),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
            networks: nets.iter().map(|s| (*s).to_owned()).collect(),
            ..Service::default()
        };
        let defs = BTreeMap::from([(
            "n".to_owned(),
            fandhe_container_stack::schema::Network::default(),
        )]);
        // 構文不正。
        let bad = BTreeMap::from([("a".to_owned(), svc(&["not a port"], &["n"]))]);
        let e = check_ports(&bad, &defs).expect_err("syntax");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // ネットワークなしの公開。
        let nonet = BTreeMap::from([("a".to_owned(), svc(&["8080:80"], &[]))]);
        let e = check_ports(&nonet, &defs).expect_err("no network");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 後ろのサービスの不正も見つける（先頭が正常でも全件を検査する）。
        let later = BTreeMap::from([
            ("a".to_owned(), svc(&[], &[])),
            ("b".to_owned(), svc(&["zzz"], &["n"])),
        ]);
        assert_eq!(
            check_ports(&later, &defs).expect_err("later").code(),
            ErrorCode::InvalidArgument
        );
        // ports なしは何も解決せず通る。
        check_ports(&BTreeMap::from([("a".to_owned(), svc(&[], &[]))]), &defs).expect("none");
    }

    /// STACK-8・SEC-1・#3651・#4638: 表示用の名前は制御文字・bidi 制御を無害化し、長さを制限する。
    #[test]
    fn stack8_4638_display_name_sanitizes_and_truncates() {
        assert_eq!(display_name("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(display_name("x\u{202e}y"), "x\\u{202e}y");
        let long = "あ".repeat(200);
        assert!(display_name(&long).len() <= MAX_PS_NAME_BYTES);
        assert!(display_name(&long).chars().all(|c| c == 'あ'));
    }

    /// STACK-8・#4638: 成功の出力は固定ヘッダと起動順の行。
    #[test]
    fn stack8_4638_render_success_header_only_for_empty_report() {
        assert_eq!(
            render_success(&UpReport::default()),
            "SERVICE\tCONTAINER\tNETWORK\n"
        );
    }

    /// STACK-8・SEC-1・#4638: TOML は FIFO で止まらず、通常ファイル以外・無いファイルを固定文言で拒否する。
    #[test]
    fn sec1_4638_project_file_must_be_a_regular_file() {
        let dir = std::env::temp_dir().join(format!("fc-up-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let missing = read_project_file(&dir.join("nope.toml"));
        assert!(matches!(missing, Err(CliExit::Error(ref e)) if e.code() == ErrorCode::NotFound));
        let as_dir = read_project_file(&dir);
        assert!(
            matches!(as_dir, Err(CliExit::Error(ref e)) if e.code() == ErrorCode::InvalidArgument)
        );
        let ok = dir.join("ok.toml");
        std::fs::write(&ok, "[services.a]\nimage = \"x\"\n").expect("write");
        assert!(read_project_file(&ok).is_ok());
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "[services.a]\nunknown = 1\n").expect("write");
        assert!(
            matches!(read_project_file(&bad), Err(CliExit::Error(ref e)) if e.code() == ErrorCode::InvalidArgument)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
