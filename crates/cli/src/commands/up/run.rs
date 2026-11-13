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
//! 失敗時は ERR-1 の構造化エラー 1 行（stderr の最後の行）で、先に起動済みのサービス名を `info:` の行で stderr に出す。
//! 終了コードは `UpError::exit_code`（子の終了コードを運ぶ）を ERR-2 の表で `ErrorCode` に戻したもの。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use fandhe_container_core::traits::{ErrorCode, StateStore as _, TraitError};
use fandhe_container_stack::cli::up::{
    UpClock, UpError, UpFailure, UpPolicy, UpProject, UpReport, resolve_project_name, up,
};
use fandhe_container_stack::cli::{MAX_PS_NAME_BYTES, MAX_PS_SERVICES, sanitize_display};
use fandhe_container_stack::depends_on::dependency_closure;
use fandhe_container_stack::profile_filter::{
    PROFILES_ENV, resolve_active_profiles, select_enabled_services,
};
use fandhe_container_stack::schema::Service;
use fandhe_container_stack::toml_input::read_compose_toml;

use super::super::CliExit;
use super::super::args::{GlobalArgs, PastaSource, UpArgs};
use super::super::create_network::resolve_publish_privilege;
use super::super::create_start::open_store;
use super::super::image::open_image_store_for_lifecycle;
use super::super::list_logs::store_open_failure;
use super::error_code_for_exit;
use super::launcher::{LauncherConfig, ProductionServiceLauncher};
use super::observe::{Ledger, SharedLedger, StateHealth, StateObserver, read_status};
use super::prepare::{Prepared, Preparer};
use super::provision::ProductionNetworkProvisioner;
use crate::error::CliError;

/// `O_NONBLOCK`（Linux の x86_64 / aarch64 とも 0o4000）。FIFO を開いて止まらないために使う。
const O_NONBLOCK: i32 = 0o4000;
/// 失敗時に `info:` の行へ出す起動済みサービス名の最大件数。
const MAX_INFO_NAMES: usize = 32;

fn err(code: ErrorCode, msg: impl AsRef<str>) -> CliExit {
    CliExit::Error(CliError::new(code, msg))
}

fn from_trait(e: &TraitError) -> CliExit {
    err(e.code(), e.message())
}

/// 無害化して長さを制限した表示用の名前。
fn display_name(s: &str) -> String {
    let mut end = s.len().min(MAX_PS_NAME_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    sanitize_display(&s[..end])
}

/// `--file` の開く・読む・解析に許す時間（応答しない FUSE・ネットワーク FS で main が止まらないための上限。REPAIR-5）。
const PROJECT_FILE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `--file` を期限つきの作業スレッドで読んで解析する（REPAIR-5・STACK-8）。
///
/// O_NONBLOCK は通常ファイルの読み取り時間を制限しないため、開く・読む処理ごと作業スレッドへ移し、
/// 期限切れは `TIMEOUT`、同時実行枠の満杯は `RESOURCE_EXHAUSTED` で返す（`env_file` の読み取りと同じ分類）。
fn read_project_file(file: &Path) -> Result<fandhe_container_stack::schema::ComposeToml, CliExit> {
    use fandhe_container_supervisor::supervisor_log::{BoundedFailure, run_bounded_waiting};
    let file = file.to_path_buf();
    match run_bounded_waiting(
        move || read_project_file_blocking(&file),
        PROJECT_FILE_READ_TIMEOUT,
    ) {
        Ok(result) => result,
        Err(BoundedFailure::Busy) => Err(err(
            ErrorCode::ResourceExhausted,
            "project file workers are busy",
        )),
        Err(BoundedFailure::Unfinished) => Err(err(
            ErrorCode::Timeout,
            "reading the project file did not finish within the deadline",
        )),
    }
}

/// [`read_project_file`] の本体（FIFO・デバイスで止まらない。上限は stack の入口が持つ）。ブロックし得るため作業スレッドで呼ぶ。
fn read_project_file_blocking(
    file: &Path,
) -> Result<fandhe_container_stack::schema::ComposeToml, CliExit> {
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

/// 失敗を構造化エラーへ写す（`message` は固定文言に、無害化した名前だけを添える）。
fn failure_exit(f: &UpFailure) -> CliExit {
    let e = f.error();
    let code = error_code_for_exit(e.exit_code().get());
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
    CliExit::Error(CliError::new(code, message))
}

/// 起動済みのサービスを `info:` の行で stderr に出す（件数を制限する）。
fn print_launched_info(f: &UpFailure) {
    if f.launched().is_empty() {
        return;
    }
    let shown: Vec<String> = f
        .launched()
        .iter()
        .take(MAX_INFO_NAMES)
        .map(|n| display_name(n))
        .collect();
    let more = f.launched().len().saturating_sub(MAX_INFO_NAMES);
    let suffix = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    eprintln!(
        "info: launched {} service(s) before the failure: {}{suffix}",
        f.launched().len(),
        shown.join(", ")
    );
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

pub(super) fn run_up(global: &GlobalArgs, args: &UpArgs, stdout: &mut dyn Write) -> CliExit {
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
            if stdout
                .write_all(render_success(&report).as_bytes())
                .is_err()
            {
                return CliExit::failed(ErrorCode::Internal);
            }
            CliExit::Success
        }
        Err(f) => {
            print_launched_info(&f);
            failure_exit(&f)
        }
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
