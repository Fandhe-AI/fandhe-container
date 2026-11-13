//! `up` の本番 `ServiceLauncher`: bundle を用意して CLI 自身の `create --unpack` → `start` を子プロセスで呼ぶ
//! （STACK-8・SUP-1・SEC-1・REPAIR-5・TASK-155・TASK-157・#4638）。
//!
//! # 役割と呼び出し元
//! stack の `up()` が依存順に 1 サービスずつ [`ProductionServiceLauncher::launch`] を呼ぶ。サービスごとに
//! (1) `bundle::write_bundle` で `config.json` と `env/` を置く、(2) stack の `create_argv` で `create` の argv を組む、
//! (3) CLI 自身（`current_exe()`）を子プロセスで起動して `create` を期限つきで待つ、(4) 成功したら台帳へ記録してから
//! `start_argv` で `start` を期限つきで待つ。ライフサイクルの実処理（状態ストアの作成・supervisor の起動）は子の
//! `create` / `start` が既存の経路で行うため、`up` は同じ前提・同じ検査（rootless のみ・rootful は `UNIMPLEMENTED` 等）を
//! そのまま継承する。
//!
//! # 契約（`ServiceLauncher` の契約への対応）
//! - (a) サービス名は `Preparer` が `ServiceContainerId::derive` で検証済み。子へは `--` の後ろの ID 1 要素だけを渡す。
//! - (b) create に成功した時点で [`Ledger`](super::observe::Ledger) へ記録する（前回の残骸を返さない）。
//! - (c) 期限（REPAIR-5）: `create` は展開の期限 + 30 秒、`start` は supervisor の受信期限 + 10 秒。超えたら子を kill して
//!   `TIMEOUT`（7）にする。待ちは `try_wait` のポーリングで、子が出力の書き込み端を握って止まることはない（stdout は
//!   `/dev/null`、stdin も `/dev/null`）。
//! - (d) `Service`（`env` に資格情報を含みうる）をエラー・ログに出さない。子の stderr は継承する（子の構造化エラー 1 行が
//!   そのまま利用者に見える。子は値を出さない）。
//! - (e) pasta: `--pasta-path` / `--pasta-path-search` は、そのサービスが **ユーザー定義名のネットワーク** に付くときだけ
//!   子の `create` の前置きグローバルオプションとして渡す。rootless かどうかの判定と pasta の検証は子の `create` が行う。
//!
//! 子の終了コードは ERR-2 の表で `ErrorCode` へ戻し、`LaunchError` に終了コードとして運ぶ（`up` の終了コードに反映される）。
//! シグナルで終わった子は `INTERNAL`。
//!
//! 残余: `create` の後に `start` が失敗しても作ったコンテナは消さない（`up` はロールバックしない。`down` の責務）。
//! 期限で kill した `create` が展開途中の rootfs を残しうる（回収手順は `docs/design/stack-up-wiring.md`）。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_stack::cli::up::{
    CreateArgvContext, LaunchError, LaunchRequest, LaunchedService, ServiceLauncher, create_argv,
    start_argv,
};

use super::super::image_unpack::UNPACK_DEADLINE;
use super::bundle::write_bundle;
use super::error_code_for_exit;
use super::observe::SharedLedger;
use super::prepare::Prepared;
use crate::error::CliError;

/// `create` の期限に足す余裕（子の起動・状態ストアの作成。展開の期限は [`UNPACK_DEADLINE`]）。
const CREATE_SLACK: Duration = Duration::from_secs(30);
/// `start` の期限に足す余裕（supervisor の受信期限に対する子の後始末）。
const START_SLACK: Duration = Duration::from_secs(10);
/// 子の終了を見るポーリング間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// 本番の [`ServiceLauncher`]。
pub(super) struct ProductionServiceLauncher {
    /// 子として起動する CLI の実体（本番は `current_exe()` だけ。`PATH` 探索・環境変数による差し替えは作らない）。
    cli_exe: PathBuf,
    /// サブコマンドの前に置くグローバルオプション（`--root` 等）。
    global_args: Vec<OsString>,
    /// ユーザー定義名のネットワークに付くサービスの `create` にだけ足すグローバルオプション（pasta）。
    pasta_args: Vec<OsString>,
    image_root: PathBuf,
    /// 開いた状態ストアの正規パス（bundle の置き場の根）。
    state_root: PathBuf,
    prepared: BTreeMap<String, Prepared>,
    ledger: SharedLedger,
    create_deadline: Duration,
    start_deadline: Duration,
}

/// launcher の構成。
pub(super) struct LauncherConfig {
    pub(super) cli_exe: PathBuf,
    pub(super) global_args: Vec<OsString>,
    pub(super) pasta_args: Vec<OsString>,
    pub(super) image_root: PathBuf,
    pub(super) state_root: PathBuf,
    pub(super) prepared: BTreeMap<String, Prepared>,
    pub(super) ledger: SharedLedger,
    pub(super) create_deadline: Duration,
    pub(super) start_deadline: Duration,
}

impl LauncherConfig {
    /// 本番の期限（`create` は展開の期限 + 30 秒、`start` は supervisor の受信期限 + 10 秒）。
    pub(super) fn production_deadlines() -> (Duration, Duration) {
        (
            UNPACK_DEADLINE.saturating_add(CREATE_SLACK),
            fandhe_container_supervisor::start_client::production_deadline()
                .saturating_add(START_SLACK),
        )
    }
}

impl ProductionServiceLauncher {
    pub(super) fn new(c: LauncherConfig) -> Self {
        Self {
            cli_exe: c.cli_exe,
            global_args: c.global_args,
            pasta_args: c.pasta_args,
            image_root: c.image_root,
            state_root: c.state_root,
            prepared: c.prepared,
            ledger: c.ledger,
            create_deadline: c.create_deadline,
            start_deadline: c.start_deadline,
        }
    }

    /// 子を起動して `deadline` まで待つ。`phase` は失敗文言の選択に使う。
    fn run_child(
        &self,
        extra_globals: &[OsString],
        argv: &[OsString],
        deadline: Duration,
        phase: Phase,
    ) -> Result<(), LaunchError> {
        let mut child = Command::new(&self.cli_exe)
            .args(&self.global_args)
            .args(extra_globals)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| phase.failure(ErrorCode::Unavailable, None))?;
        let limit = Instant::now() + deadline;
        let status: ExitStatus = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= limit => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(phase.failure(ErrorCode::Timeout, None));
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(phase.failure(ErrorCode::Internal, None));
                }
            }
        };
        match status.code() {
            Some(0) => Ok(()),
            Some(n) => {
                let code = error_code_for_exit(u8::try_from(n).unwrap_or(1));
                Err(phase.failure(code, std::num::NonZeroU8::new(u8::try_from(n).unwrap_or(1))))
            }
            None => Err(phase.failure(ErrorCode::Internal, None)),
        }
    }
}

/// 失敗の段（固定文言の選択）。
#[derive(Clone, Copy)]
enum Phase {
    Bundle,
    Create,
    Start,
}

impl Phase {
    fn failure(self, code: ErrorCode, exit: Option<std::num::NonZeroU8>) -> LaunchError {
        let message = match self {
            Phase::Bundle => "failed to prepare the service bundle",
            Phase::Create => "the create subprocess failed",
            Phase::Start => "the start subprocess failed",
        };
        let e = LaunchError::new(code.as_str(), message);
        match exit {
            Some(n) => e.with_exit_code(n),
            None => e.with_exit_code(fandhe_container_core::oci_runtime::exit_code_for(code)),
        }
    }
}

fn from_cli(e: &CliError) -> LaunchError {
    LaunchError::new(e.code_str(), "failed to prepare the service bundle")
        .with_exit_code(e.exit_code())
}

impl ServiceLauncher for ProductionServiceLauncher {
    fn launch(&mut self, request: &LaunchRequest<'_>) -> Result<LaunchedService, LaunchError> {
        let service = request.service();
        let Some(p) = self.prepared.get(service) else {
            return Err(Phase::Bundle.failure(ErrorCode::Internal, None));
        };
        let paths = write_bundle(&self.state_root, p).map_err(|e| from_cli(&e))?;
        let ctx = CreateArgvContext {
            id: &p.id,
            project_dir: &paths.env_dir,
            bundle: &paths.bundle,
            image_root: &self.image_root,
            unpack: true,
        };
        let create =
            create_argv(&p.spec, request.network(), &ctx).map_err(|e| e.to_launch_error())?;
        let pasta: &[OsString] = if request.network().is_some() {
            &self.pasta_args
        } else {
            &[]
        };
        self.run_child(pasta, &create, self.create_deadline, Phase::Create)?;
        // create に成功した時点で台帳へ記録する（以後 observer / health がこのコンテナを読む）。
        self.ledger
            .try_borrow_mut()
            .map_err(|_| Phase::Create.failure(ErrorCode::Internal, None))?
            .record(service, p.id.clone());
        self.run_child(&[], &start_argv(&p.id), self.start_deadline, Phase::Start)?;
        Ok(LaunchedService::new(service, p.id.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use fandhe_container_stack::cli::up::{
        NetworkProvisionError, NetworkProvisioner, NetworkRequest, ProjectName, ProvisionOutcome,
        ProvisionedNetwork, ServiceContainerId, UpClock, UpPolicy, UpProject, up,
    };
    use fandhe_container_stack::depends_on::wait::{
        DependencyObservation, DependencyObserver, ObserveError,
    };
    use fandhe_container_stack::depends_on::{HealthSource, HealthSourceError, ObservedHealth};
    use fandhe_container_stack::toml_input::parse_compose_toml;

    use super::super::observe::Ledger;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-up-launch-{tag}-{}-{}",
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

    const TOML: &str = r#"
[networks.backend]

[services.web]
image = "example/web:1"
networks = ["backend"]
[services.web.depends_on]
db = "started"

[services.db]
image = "example/db:1"
"#;

    fn prepared(project: &ProjectName, name: &str) -> Prepared {
        let svc = parse_compose_toml(TOML).expect("toml").services[name].clone();
        Prepared {
            id: ServiceContainerId::derive(project, name).expect("id"),
            spec: svc,
            args: vec!["/bin/true".to_owned()],
            cwd: "/".to_owned(),
            image_env: vec![],
            uid: 0,
            gid: 0,
            env_files: vec![],
        }
    }

    /// 偽の CLI: `/bin/sh <script> <引数...>` を子にする。argv を 1 行 1 回の呼び出しとしてログへ追記する。
    /// `behavior` は sh の case 文の本体（`$*` を見て exit / sleep する）。
    fn fake_cli(dir: &Scratch, behavior: &str) -> (PathBuf, PathBuf) {
        let log = dir.0.join("calls.log");
        let script = dir.0.join("fake-cli.sh");
        let body = format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\n{behavior}\nexit 0\n",
            log.display()
        );
        std::fs::write(&script, body).expect("script");
        (script, log)
    }

    struct Net;
    impl NetworkProvisioner for Net {
        fn ensure(
            &mut self,
            r: &NetworkRequest<'_>,
        ) -> Result<ProvisionedNetwork, NetworkProvisionError> {
            Ok(ProvisionedNetwork::new(r.name, ProvisionOutcome::Created))
        }
    }
    struct Obs(SharedLedger);
    impl DependencyObserver for Obs {
        fn observe(&mut self, s: &str) -> Result<DependencyObservation, ObserveError> {
            Ok(if self.0.borrow().get(s).is_some() {
                DependencyObservation::Running
            } else {
                DependencyObservation::Absent
            })
        }
    }
    struct NoHealth;
    impl HealthSource for NoHealth {
        fn observe(&mut self, _: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
            Ok(None)
        }
    }

    struct Outcome {
        result: Result<Vec<String>, (String, u8)>,
        calls: Vec<String>,
        state_root: PathBuf,
    }

    fn drive(behavior: &str, create_deadline: Duration, pasta: bool) -> Outcome {
        let s = Scratch::new("drive");
        let state_root = s.0.join("state");
        std::fs::create_dir(&state_root).expect("state");
        let (script, log) = fake_cli(&s, behavior);
        let project = ProjectName::new("shop").expect("project");
        let ledger: SharedLedger = Rc::new(RefCell::new(Ledger::default()));
        let mut prepared = BTreeMap::new();
        for n in ["web", "db"] {
            prepared.insert(n.to_owned(), prepared_for(&project, n));
        }
        let mut launcher = ProductionServiceLauncher::new(LauncherConfig {
            cli_exe: PathBuf::from("/bin/sh"),
            global_args: vec![script.into_os_string(), "--root".into(), "/r".into()],
            pasta_args: if pasta {
                vec!["--pasta-path-search".into()]
            } else {
                vec![]
            },
            image_root: PathBuf::from("/imgroot"),
            state_root: state_root.clone(),
            prepared,
            ledger: ledger.clone(),
            create_deadline,
            start_deadline: Duration::from_secs(20),
        });
        let stack = parse_compose_toml(TOML).expect("toml");
        let project_in = UpProject {
            services: &stack.services,
            networks: &stack.networks,
        };
        let mut clock = UpClock::new();
        let r = up(
            &project_in,
            &mut launcher,
            &mut Net,
            &mut Obs(ledger),
            &mut NoHealth,
            &mut clock,
            &UpPolicy::default(),
        );
        let result = match r {
            Ok(rep) => Ok(rep.service_names().map(str::to_owned).collect()),
            Err(f) => Err((f.error().code().to_owned(), f.error().exit_code().get())),
        };
        let calls = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        // state_root は Scratch の Drop で消えるため、確認に要る名前だけ返す。
        let keep = state_root.clone();
        drop(s);
        Outcome {
            result,
            calls,
            state_root: keep,
        }
    }

    fn prepared_for(project: &ProjectName, name: &str) -> Prepared {
        prepared(project, name)
    }

    /// STACK-8・SUP-1・#4638: 依存順（db → web）に `create`・`start` を子プロセスで呼び、argv の列が具体値で一致する。
    /// pasta のフラグはユーザー定義ネットワークに付く web の `create` にだけ前置される。
    #[test]
    fn stack8_4638_launcher_runs_create_then_start_in_dependency_order() {
        let o = drive("", Duration::from_secs(20), true);
        assert_eq!(o.result, Ok(vec!["db".to_owned(), "web".to_owned()]));
        let b = |id: &str| {
            o.state_root
                .join(format!(".stack/bundles/{id}"))
                .display()
                .to_string()
        };
        // 先頭は偽スクリプトが受けたグローバル `--root /r`。
        assert_eq!(
            o.calls,
            vec![
                format!(
                    "--root /r create --bundle {} --image-root /imgroot --image example/db:1 --unpack -- shop.db",
                    b("shop.db")
                ),
                "--root /r start -- shop.db".to_owned(),
                format!(
                    "--root /r --pasta-path-search create --bundle {} --image-root /imgroot --image example/web:1 --unpack --network backend -- shop.web",
                    b("shop.web")
                ),
                "--root /r start -- shop.web".to_owned(),
            ]
        );
    }

    /// ERR-2・STACK-8・#4638: 子の `create` の終了コード 3（NOT_FOUND）で以降は呼ばれず、`up` の終了コードに運ばれる。
    #[test]
    fn err2_4638_child_exit_code_is_carried_and_stops_the_rest() {
        let o = drive(
            "case \"$*\" in *' create '*) exit 3;; esac",
            Duration::from_secs(20),
            false,
        );
        assert_eq!(o.result, Err(("SERVICE_LAUNCH_FAILED".to_owned(), 3)));
        assert_eq!(o.calls.len(), 1, "{:?}", o.calls);
        assert!(o.calls[0].contains("create"), "{:?}", o.calls);
    }

    /// REPAIR-5・#4638: 期限を過ぎた子は kill され、`TIMEOUT`（7）で失敗する（ハングしない）。
    #[test]
    fn repair5_4638_child_past_its_deadline_is_killed_with_timeout() {
        let started = Instant::now();
        let o = drive("exec sleep 30", Duration::from_millis(300), false);
        assert_eq!(o.result, Err(("SERVICE_LAUNCH_FAILED".to_owned(), 7)));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(o.calls.len(), 1);
    }

    /// REPAIR-3: シグナルで終わった子は INTERNAL（終了コード 1）。
    #[test]
    fn err2_4638_signaled_child_is_internal() {
        let o = drive("kill -KILL $$", Duration::from_secs(20), false);
        assert_eq!(o.result, Err(("SERVICE_LAUNCH_FAILED".to_owned(), 1)));
    }
}
