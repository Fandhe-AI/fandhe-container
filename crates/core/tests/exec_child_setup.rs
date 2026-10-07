//! exec の子の `execveat` 前の手順を実プロセスで照合する結合試験（SUP-6・SEC-1・REPAIR-12・TASK-163 追補・#1456）。
//!
//! 稼働中コンテナへの exec（`exec/exec_command.rs`）と launch（`exec/process.rs`）の子は、`execveat` の前に
//! 同じ手順（fd の後始末 → `setsid` → エントリポイントの検査 → 標準入出力の `/dev/null` への置換）を通る。
//! 単体テストは libtest がマルチスレッドのため dry-run（呼び出し順の記録）でしか確かめられず、通しの結合試験
//! （supervisor の `tests/exec.rs`）は root と Landlock ABI 6 以上を要して hosted runner で実行できない。
//! そこで本試験は、同じ手順を **fork した実プロセス** で通す観測用の入口
//! `fandhe_container_core::exec::observe_exec_child_setup`（`exec-test-support` feature。`execveat` は呼ばず、
//! 子が `execveat` の直前の自分の状態を報告する）を使い、非特権で照合できる性質を具体値で確かめる。
//!
//! - **セッションの切り離し（#1456）**: 子のセッション ID・プロセスグループ ID が子自身の pid と一致し、
//!   呼び出し側のセッション ID と異なる。制御端末を持たない（`tty_nr` = 0・`/dev/tty` が `ENXIO`）。
//!   呼び出し側が制御端末を持つ状況は util-linux の `script`（疑似端末を割り当てる）の下で本バイナリを
//!   再実行して作り、「制御端末を持つ呼び出し側から起動しても子は持たない」ことを照合する
//!   同じ疑似端末の下で、端末そのもの・端末を指す symlink をエントリポイントにしても、子が開かずに拒否する
//!   （`setsid` の後に端末を `O_NOCTTY` なしで開くと制御端末として取得し直すため。終了コード 126）ことも照合する
//! - **標準入出力**: fd 0〜2 がすべて文字デバイス 1:3（`/dev/null`）
//! - **インタープリタ経由の拒否（#1458・SEC-4）**: `#!/proc/self/exe`・`#!/proc/<pid>/exe`・スクリプトの連鎖の
//!   先がランタイム自身（ここでは試験バイナリ自身）に解決されるスクリプトは、子が `execveat` の前に終了コード 126 で
//!   拒否し、報告は書かれない。対照として、通常のシェルスクリプト（`#!/bin/sh`）は手順を通る
//!
//! - **`execve` 前の失敗の区別（#1460）**: 子が本番と同じ pipe で親へ知らせた内容から、「コマンドは起動して
//!   いない」（終了コード 125〜127 と違反の理由）と「`execveat` の直前まで到達した」が区別される。子に残る fd が
//!   その pipe と検査済みのエントリポイントの 2 本だけであること（継承 fd の後始末）も照合する
//! - **環境変数（#1457）**: `execveat` に渡る環境変数が、コンテナ定義（`config.json` の `process.env`）と明示の
//!   上書きだけで、試験プロセスの環境を含まない
//! - **補助グループ（#1457）**: launch・exec が共有する補助グループの消去を、使い捨ての子で実 syscall により通す
//!   （非特権では `CAP_SETGID` が無いため拒否されること、root では消去されること）
//!
//! root・実コンテナ・user namespace は不要で、既定のテスト集合（`cargo test --workspace`・
//! `make test-integration`）で実行する。fork は呼び出しプロセスが単一スレッドであることを要求するため、
//! libtest ではなく `harness = false` の単一スレッド `main` で動かす。非 Linux では対象外（OS 非該当）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_child_setup: Linux only, not applicable on this OS");
}

/// feature なしのビルドでは観測用の入口が無い。検証せずに成功しない（fail-closed）。core の dev-dependency
/// （自己参照）が `exec-test-support` を有効にするため、通常の `cargo test` ではこの分岐にならない。
#[cfg(all(target_os = "linux", not(feature = "exec-test-support")))]
fn main() {
    eprintln!("exec_child_setup: not verified; the exec-test-support feature is not enabled");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some(linux::PTY_CHILD) => {
            linux::pty_child(std::path::Path::new(args.get(2).expect("work directory")));
        }
        Some(linux::GROUPS_CHILD) => linux::groups_child(),
        _ => linux::run(),
    }
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, ContainerEnv, ExecChildSetupReport, ExecCommand, ExecExit, SupplementaryGroups,
        ViolationReason, clear_supplementary_groups_for_test, observe_exec_child_setup,
    };
    use fandhe_container_core::oci_runtime::parse_config_bytes;
    use fandhe_container_core::traits::ErrorCode;

    /// 疑似端末の下で再実行される子の再入フラグ（引数: 作業ディレクトリ）。
    pub const PTY_CHILD: &str = "--pty-child";
    /// 補助グループを実 syscall で消去する使い捨ての子の再入フラグ。
    pub const GROUPS_CHILD: &str = "--groups-child";
    /// 疑似端末の下の子が、照合を終えたことを知らせる合図ファイルの名前と内容。
    const PTY_OK: &str = "pty-ok";
    /// `ENXIO`（制御端末を持たないプロセスが `/dev/tty` を開いたときの errno。全アーキテクチャ共通の 6）。
    const ENXIO: i32 = 6;
    /// `/dev/null` のデバイス番号 1:3 の `st_rdev`（glibc の `makedev(1, 3)`）。
    const NULL_RDEV: u64 = 0x103;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(20);
        Duration::from_secs(secs)
    }

    /// 使い捨ての作業ディレクトリ（drop で削除）。名前に pid と時刻を混ぜ、`mkdir` で排他的に作る。
    pub struct WorkDir(pub PathBuf);

    impl WorkDir {
        pub fn create(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let dir = fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!(
                    "fandhe-exec-child-{label}-{}-{nanos}",
                    std::process::id()
                ));
            fs::create_dir(&dir).expect("exclusively create the work directory");
            Self(dir)
        }
    }

    impl Drop for WorkDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 自プロセスの `(セッション ID, tty_nr)`（`/proc/self/stat`。`comm` の後ろを読む）。
    fn own_session_and_tty() -> (u32, i64) {
        let stat = fs::read_to_string("/proc/self/stat").expect("read own stat");
        let rest = &stat[stat.rfind(')').expect("comm terminator") + 1..];
        let mut fields = rest.split_whitespace().skip(3);
        let session = fields.next().expect("session").parse().expect("session");
        let tty_nr = fields.next().expect("tty_nr").parse().expect("tty_nr");
        (session, tty_nr)
    }

    /// 観測用の入口で `entry` の手順を通し、手順が通った子の報告を返す（通らなければ panic）。
    pub fn observe_ok(entry: &ExecCommand, work: &Path, name: &str) -> ExecChildSetupReport {
        let observation = observe_exec_child_setup(entry, &work.join(name), timeout())
            .expect("observe the exec child setup");
        // 手順を通った子は、本番と同じ pipe で「`execveat` の直前まで到達した」ことを知らせる（#1460）。
        assert_eq!(
            observation.exit,
            ExecExit::Command(ChildExit::Exited(0)),
            "{name}"
        );
        observation.report.expect("the child must write its report")
    }

    /// 実在する実行ファイルを指すエントリポイント（開いて検査するだけで、実行はしない）。
    pub fn shell_entry() -> ExecCommand {
        ExecCommand::new("/bin/sh", ["sh"], &ContainerEnv::empty()).expect("command")
    }

    pub fn run() {
        let work = WorkDir::create("main");
        session_is_detached_from_the_caller(&work.0, "report");
        child_has_no_controlling_terminal_under_a_pty(&work.0);
        runtime_interpreter_is_rejected_before_exec(&work.0);
        setup_failures_are_distinguished_from_command_exits(&work.0);
        inherited_fds_are_closed_except_the_status_pipe(&work.0);
        environment_comes_only_from_the_container_definition(&work.0);
        supplementary_groups_are_cleared_or_refused();
        println!("exec_child_setup: all scenarios passed");
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1456）: 子は新しいセッションのリーダーで、制御端末を持たず、標準入出力は
    /// `/dev/null`。呼び出し側のセッションは変わらない。
    fn session_is_detached_from_the_caller(work: &Path, name: &str) {
        let (caller_session, caller_tty) = own_session_and_tty();
        let report = observe_ok(&shell_entry(), work, name);
        assert_ne!(report.pid, std::process::id());
        assert_eq!(
            report.session_id, report.pid,
            "the child must lead its session"
        );
        assert_eq!(report.process_group, report.pid);
        assert_ne!(
            report.session_id, caller_session,
            "the child must leave the caller's session"
        );
        assert_eq!(report.tty_nr, 0, "the child must have no controlling tty");
        assert_eq!(report.dev_tty_errno, Some(ENXIO));
        assert_eq!(report.stdio, [(true, NULL_RDEV); 3]);
        assert_eq!(report.env, Vec::<String>::new());
        // 呼び出し側のセッション・制御端末は変わらない（切り離すのは子だけ）。
        assert_eq!(own_session_and_tty(), (caller_session, caller_tty));
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1456）: 制御端末を持つ呼び出し側から起動しても、子は制御端末を持たない。
    ///
    /// util-linux の `script` で疑似端末を割り当てて本バイナリを再実行し（[`pty_child`]）、その中で同じ照合を行う。
    /// `script` は 0 で終わり、子が照合を終えた合図ファイルが残っていなければならない（実行されなかった場合を
    /// 成功にしない）。`script` が無い環境は失敗にする（skip で通さない）。
    fn child_has_no_controlling_terminal_under_a_pty(work: &Path) {
        let exe = std::env::current_exe().expect("current_exe");
        let exe = exe.to_str().expect("utf-8 test binary path");
        let dir = work.to_str().expect("utf-8 work directory");
        assert!(
            !exe.contains('\'') && !dir.contains('\''),
            "paths must not contain a single quote"
        );
        let mut script = Command::new("script")
            .args(["-q", "-e", "-c"])
            .arg(format!("'{exe}' {PTY_CHILD} '{dir}'"))
            .arg("/dev/null")
            // 標準入力の EOF で `script` が先に終わらないよう、子の終了まで開いたままのパイプを渡す。
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn `script` (util-linux) to allocate a pseudo terminal");
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(status) = script.try_wait().expect("try_wait") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = script.kill();
                let _ = script.wait();
                panic!("`script` did not exit within {:?}", timeout());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0), "the pty child must succeed");
        assert_eq!(
            fs::read_to_string(work.join(PTY_OK)).expect("the pty child must have run"),
            PTY_OK
        );
    }

    /// `path` へ `content` を排他的に書き、実行ビットを立てる。
    fn write_script(path: &Path, content: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create the script");
        file.write_all(content.as_bytes())
            .expect("write the script");
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .expect("chmod the script");
    }

    /// SUP-6・SEC-1・SEC-4・CORE-5・TASK-163 追補（#1458）: インタープリタがランタイム自身（試験バイナリ自身）に
    /// 解決されるスクリプトは、実プロセスの子が `execveat` の前に拒否する（終了コード 126・報告なし）。
    ///
    /// 検査が無ければ子は手順を通って報告を書く（`execveat` まで進めば、カーネルが `/proc/self/exe` を
    /// インタープリタとして開き、ホスト側のランタイムのバイナリがコンテナ内で実行される）。
    fn runtime_interpreter_is_rejected_before_exec(work: &Path) {
        let chained = work.join("chained");
        write_script(&chained, "#!/proc/self/exe\n");
        let cases = [
            ("self", "#!/proc/self/exe\n".to_owned()),
            ("arg", "#! /proc/self/exe --flag\n".to_owned()),
            ("pid", format!("#!/proc/{}/exe\n", std::process::id())),
            ("chain", format!("#!{}\n", chained.display())),
        ];
        for (name, content) in cases {
            let script = work.join(format!("script-{name}"));
            write_script(&script, &content);
            let entry =
                ExecCommand::new(&script, ["script"], &ContainerEnv::empty()).expect("command");
            let report = work.join(format!("report-{name}"));
            let observation = observe_exec_child_setup(&entry, &report, timeout())
                .expect("observe the exec child setup");
            // 終了コード 126 に加えて、「コマンドは起動していない」ことと違反の理由が親へ届く（#1460・SEC-4）。
            assert_eq!(
                observation.exit,
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointInterpreterIsRuntimeBinary),
                },
                "{name}"
            );
            assert_eq!(observation.report, None, "{name}");
            assert!(!report.exists(), "{name}: the child must not reach exec");
        }
        // 対照: 通常のシェルスクリプトは手順を通る（スクリプトであること自体は拒否の理由にならない）。
        let script = work.join("script-sh");
        write_script(&script, "#!/bin/sh\nexit 0\n");
        let entry = ExecCommand::new(&script, ["script"], &ContainerEnv::empty()).expect("command");
        let report = observe_ok(&entry, work, "report-sh");
        assert_eq!(report.stdio, [(true, NULL_RDEV); 3]);
    }

    /// SUP-6・REPAIR-3・TASK-163 追補（#1460）: `execveat` より前の失敗は、終了コード（125〜127。コマンド自身も
    /// 返し得る）ではなく、子が pipe で知らせた内容で「コマンドは起動していない」と判定される。
    fn setup_failures_are_distinguished_from_command_exits(work: &Path) {
        let observe = |command: &ExecCommand, name: &str| {
            observe_exec_child_setup(command, &work.join(name), timeout())
                .expect("observe the exec child setup")
        };
        let env = ContainerEnv::empty();
        // 不在のエントリポイント: 終了コード 127。違反ではない。
        let missing = ExecCommand::new("/no/such/entrypoint", ["x"], &env).expect("command");
        let observation = observe(&missing, "report-missing");
        assert_eq!(
            observation.exit,
            ExecExit::SetupFailed {
                exit: ChildExit::Exited(127),
                violation: None,
            }
        );
        assert!(!observation.exit.command_started());
        assert_eq!(observation.report, None);
        // ランタイム自身のバイナリ（ここでは試験バイナリ自身）: 終了コード 126 と違反の理由。
        let exe = std::env::current_exe().expect("current_exe");
        let runtime = ExecCommand::new(&exe, ["x"], &env).expect("command");
        assert_eq!(
            observe(&runtime, "report-runtime").exit,
            ExecExit::SetupFailed {
                exit: ChildExit::Exited(126),
                violation: Some(ViolationReason::EntrypointIsRuntimeBinary),
            }
        );
        // 対照: 手順を通った子は「起動した」側に分類される。
        let started = observe(&shell_entry(), "report-started");
        assert_eq!(started.exit, ExecExit::Command(ChildExit::Exited(0)));
        assert!(started.exit.command_started());
    }

    /// SUP-6・SEC-1・TASK-163.4 / 追補（#1460）: 子は呼び出し側から継承した fd 3 以上をすべて閉じ、残るのは
    /// 状態を返す pipe と検査済みのエントリポイントの 2 本だけ（pipe の番号より小さい fd も大きい fd も閉じる）。
    fn inherited_fds_are_closed_except_the_status_pipe(work: &Path) {
        // 継承される fd を、状態を返す pipe の書き込み側より小さい番号と大きい番号の両方に用意する（std の fd は
        // close-on-exec だが、`execveat` の前の子には見えている。子はこれらを閉じてからエントリポイントを開く）。
        // 6 本開いてから先頭の 2 本を閉じると、観測用の入口が作る pipe は空いた 2 つの番号（読み取り側が小さい方）を
        // 取り、残りの 4 本は pipe より大きい番号になる。小さい側は pipe の読み取り側自身が担う。
        let mut inherited: Vec<fs::File> = (0..6)
            .map(|_| fs::File::open("/proc/self/status").expect("open"))
            .collect();
        inherited.drain(..2);
        let report = work.join("report-fds");
        let observation = observe_exec_child_setup(&shell_entry(), &report, timeout())
            .expect("observe the exec child setup");
        drop(inherited);
        let fds = observation.report.expect("report").open_fds;
        let targets: Vec<&str> = fds.iter().map(|(_, target)| target.as_str()).collect();
        assert_eq!(targets.len(), 2, "unexpected fds remain: {fds:?}");
        assert!(
            targets.iter().any(|t| t.starts_with("pipe:[")),
            "the status pipe must remain: {fds:?}"
        );
        let shell = fs::canonicalize("/bin/sh").expect("canonicalize /bin/sh");
        assert!(
            targets.contains(&shell.to_str().expect("utf-8 path")),
            "the verified entrypoint must remain: {fds:?}"
        );
        assert!(
            !targets.iter().any(|t| t.contains("/status")),
            "inherited fds must be closed: {fds:?}"
        );
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: `execveat` に渡る環境変数は、コンテナ定義（`config.json` の
    /// `process.env`）と明示の上書きだけで、試験プロセス（= exec を起動する側）の環境は 1 つも入らない。
    ///
    /// 子が報告する `env` は `execveat` の envp を作る元の列そのもの（`ExecCommand` が持つ値）。exec された
    /// プロセスの `/proc/<pid>/environ` の照合は、実際に `execveat` する supervisor の `tests/exec.rs`（実機前提）が行う。
    fn environment_comes_only_from_the_container_definition(work: &Path) {
        // 対照: 試験プロセス自身は、コンテナ定義に無い環境変数を持つ。
        let host: Vec<String> = std::env::vars_os()
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(
            !host.is_empty(),
            "the test process must have an environment"
        );
        assert_ne!(
            std::env::var("PATH").ok().as_deref(),
            Some("/container/bin")
        );
        let config = parse_config_bytes(
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"cwd":"/","args":["/bin/sh"],"env":["GREETING=hello","PATH=/container/bin"]}}"#,
        )
        .expect("config.json");
        let env = ContainerEnv::from_config(&config)
            .expect("container env")
            .with_var("EXTRA", "1")
            .expect("explicit override");
        let command = ExecCommand::new("/bin/sh", ["sh"], &env).expect("command");
        let report = observe_ok(&command, work, "report-env");
        assert_eq!(
            report.env,
            ["GREETING=hello", "PATH=/container/bin", "EXTRA=1"]
        );
        // 空の定義なら環境は空（既定値の補完もホスト環境の継承もしない）。
        assert_eq!(
            observe_ok(&shell_entry(), work, "report-noenv").env,
            Vec::<String>::new()
        );
    }

    /// 自プロセスの `(補助グループの件数, effective に CAP_SETGID を持つか, user namespace が setgroups を禁じているか)`。
    fn own_group_state() -> (usize, bool, bool) {
        let status = fs::read_to_string("/proc/self/status").expect("read own status");
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} missing in status"))
                .trim()
                .to_owned()
        };
        let groups = field("Groups:").split_whitespace().count();
        let effective = u64::from_str_radix(&field("CapEff:"), 16).expect("CapEff");
        let denied =
            fs::read_to_string("/proc/self/setgroups").expect("read setgroups") == "deny\n";
        (groups, effective & (1 << 6) != 0, denied)
    }

    /// `--groups-child`: 本番と同じ関数・実 syscall で自分の補助グループを空にし、結果と適用後の件数を 1 行で出す。
    pub fn groups_child() {
        let outcome = match clear_supplementary_groups_for_test() {
            Ok(SupplementaryGroups::AlreadyEmpty) => "ok already_empty 0".to_owned(),
            Ok(SupplementaryGroups::Cleared { cleared }) => format!("ok cleared {cleared}"),
            Ok(SupplementaryGroups::KeptSetgroupsDenied { kept }) => {
                format!("ok kept_setgroups_denied {kept}")
            }
            Ok(other) => format!("ok unknown {other:?}"),
            Err(e) => format!("err {} {}", e.code.as_str(), e.message),
        };
        println!("{outcome}; groups after: {}", own_group_state().0);
    }

    /// SUP-6・SEC-1・SEC-5・TASK-163 追補（#1457）: 補助グループの消去（launch・exec が共有する関数）を、
    /// 使い捨ての子で実 syscall により通す。結果は実行環境で決まり、どの環境でも具体値で照合する:
    ///
    /// - 補助グループが無い → 何もしない（`already_empty`）
    /// - `CAP_SETGID` が無く、user namespace が `setgroups` を禁じていない（非特権。hosted runner の既定）→
    ///   ホスト側の補助グループを持ち越したまま進めないため拒否し（`PERMISSION_DENIED`）、補助グループは変わらない
    /// - user namespace が `setgroups` を禁じている（procfs で `deny`）→ 現状維持を記録する
    /// - `CAP_SETGID` があり禁じられていない（root）→ 消去され、適用後の件数は 0
    fn supplementary_groups_are_cleared_or_refused() {
        let (groups, has_setgid, denied) = own_group_state();
        // 出力は一時ファイルへ書かせ、終了を期限つきで待つ（pipe の EOF 待ちで固まらない。REPAIR-5）。
        let work = WorkDir::create("groups");
        let out_path = work.0.join("stdout");
        let stdout = fs::File::create_new(&out_path).expect("create the output file");
        let mut child = Command::new(std::env::current_exe().expect("current_exe"))
            .arg(GROUPS_CHILD)
            .stdin(Stdio::null())
            .stdout(stdout)
            .spawn()
            .expect("run the groups child");
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the groups child did not exit within {:?}", timeout());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0), "the groups child must exit with 0");
        let line = fs::read_to_string(&out_path)
            .expect("read the groups child output")
            .trim_end()
            .to_owned();
        let expected = match (groups, has_setgid, denied) {
            (0, _, _) => "ok already_empty 0; groups after: 0".to_owned(),
            (n, true, false) => format!("ok cleared {n}; groups after: 0"),
            (n, _, true) => format!("ok kept_setgroups_denied {n}; groups after: {n}"),
            (n, false, false) => format!(
                "err {} cannot clear the supplementary groups: setgroups(0) was refused and the user namespace is not confirmed to deny setgroups; groups after: {n}",
                ErrorCode::PermissionDenied.as_str()
            ),
        };
        assert_eq!(line, expected);
        // 子だけが変わり、試験プロセス自身の補助グループは変わらない。
        assert_eq!(own_group_state().0, groups);
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1456）: 端末（呼び出し側の疑似端末・`/dev/tty`・`/dev/ptmx`）や、端末を指す
    /// symlink をエントリポイントにしても、子は開かずに拒否する（終了コード 126・コマンドは起動していない）。
    ///
    /// `setsid` 直後の子はセッションリーダーで制御端末を持たないため、端末を `O_NOCTTY` なしで開くと、その端末を
    /// 制御端末として取得し直してしまう。種別は `O_PATH` で固定して確かめ、通常ファイルだけを `O_NOCTTY` つきで
    /// 開き直す。
    fn terminal_entrypoint_is_refused_without_opening_it(work: &Path) {
        // 呼び出し側の疑似端末（`script` が割り当てたもの。fd 0 のリンク先）。
        let pty = fs::read_link("/proc/self/fd/0").expect("read the terminal path");
        assert!(
            pty.starts_with("/dev/pts"),
            "stdin must be the pseudo terminal: {pty:?}"
        );
        let link = work.join("tty-link");
        std::os::unix::fs::symlink(&pty, &link).expect("symlink to the terminal");
        let ptmx_link = work.join("ptmx-link");
        std::os::unix::fs::symlink("/dev/ptmx", &ptmx_link).expect("symlink to ptmx");
        let cases = [
            ("pty", pty.clone()),
            ("pty-link", link),
            ("dev-tty", PathBuf::from("/dev/tty")),
            ("ptmx", PathBuf::from("/dev/ptmx")),
            ("ptmx-link", ptmx_link),
        ];
        for (name, path) in cases {
            let command = ExecCommand::new(&path, ["x"], &ContainerEnv::empty()).expect("command");
            let report = work.join(format!("report-tty-{name}"));
            let observation = observe_exec_child_setup(&command, &report, timeout())
                .expect("observe the exec child setup");
            assert_eq!(
                observation.exit,
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: None,
                },
                "{name}"
            );
            assert_eq!(observation.report, None, "{name}");
        }
        // 拒否の後も、通常のエントリポイントの子は制御端末を持たない（端末を取得する経路が残っていない）。
        let report = observe_ok(&shell_entry(), work, "report-after-tty");
        assert_eq!((report.tty_nr, report.dev_tty_errno), (0, Some(ENXIO)));
    }

    /// `--pty-child`: 疑似端末を制御端末に持つ状態で、子が制御端末を持たないことを照合する。
    pub fn pty_child(work: &Path) {
        let (_, caller_tty) = own_session_and_tty();
        assert_ne!(
            caller_tty, 0,
            "the caller must have a controlling terminal in this scenario"
        );
        fs::File::open("/dev/tty").expect("the caller can open its controlling terminal");
        session_is_detached_from_the_caller(work, "report-pty");
        terminal_entrypoint_is_refused_without_opening_it(work);
        fs::write(work.join(PTY_OK), PTY_OK).expect("write the pty marker");
    }
}
