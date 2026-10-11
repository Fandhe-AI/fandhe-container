//! 権限昇格の実体 `privilege::elevate` の結合試験（SUP-14・SEC-1・TASK-171.1.3・#1475・MS-9）。
//!
//! `capset`・keepcaps はスレッド単位で、`elevate` は単一スレッドのプロセスを要求するため、libtest ではなく
//! `harness = false` の単一スレッド `main` で動かす。
//!
//! - 既定のシナリオ（`--ignored` なし。CI の既定集合。root は使わない）: 昇格できない環境で `elevate` が
//!   fail-closed に拒否し、資格情報（`Cap*`・`Uid`・`Gid`・`Groups`）を一切変えないことを具体値で照合する
//! - 実機のシナリオ（`-- --ignored` のときだけ。root・util-linux の `setpriv`・libcap の `setcap`・xattr と suid が
//!   効く一時ディレクトリが要る。AGENTS.md「実機前提テスト」）: 方式 (a) setuid 相当と方式 (c) ランチャー相当で
//!   縮退後の資格情報が必要最小集合（`0x0000000028201122`）ちょうどであることを、自分自身を子として起動して照合する。
//!   前提が満たせないときは skip せず非ゼロで失敗する
//!
//! fd 検証付き exec・入口検証は #1719 の範囲で、本試験の対象外。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("privilege_elevate: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::privilege::{PrivilegeErrorReason, PrivilegeMethod, elevate};

    const CHILD_ENV: &str = "FANDHE_PRIVILEGE_ELEVATE_CHILD";
    const MIN_HEX: &str = "0000000028201122";
    /// 実機のシナリオで子の待機に設ける上限（REPAIR-5）。
    const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

    pub fn run() {
        if let Ok(role) = std::env::var(CHILD_ENV) {
            child(&role);
            return;
        }
        default_scenario();
        if std::env::args().any(|a| a == "--ignored") {
            real_scenarios();
        } else {
            println!(
                "privilege_elevate: real-machine scenarios skipped (run with -- --ignored as root)"
            );
        }
        println!("privilege_elevate: all scenarios passed");
    }

    /// `/proc/self/status` のうち資格情報に関わる行（キー: 値）を取り出す。
    fn credential_lines() -> Vec<String> {
        let text = fs::read_to_string("/proc/self/status").expect("read status");
        text.lines()
            .filter(|l| {
                [
                    "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "Uid", "Gid", "Groups",
                ]
                .iter()
                .any(|k| l.starts_with(&format!("{k}:")))
            })
            .map(str::to_owned)
            .collect()
    }

    fn status_field(name: &str) -> String {
        let text = fs::read_to_string("/proc/self/status").expect("read status");
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")))
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    }

    /// SUP-14・TASK-171.1.3: 昇格できない環境では fail-closed に拒否し、資格情報を変えない。
    fn default_scenario() {
        let before = credential_lines();
        let e = elevate(PrivilegeMethod::LauncherAmbient).expect_err("must refuse");
        let is_root = status_field("Uid").split_whitespace().any(|u| u == "0");
        if is_root {
            // root（make docker-ci 等）: 方式 (c) の前提（非 root）を満たさない。
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.reason, PrivilegeErrorReason::MethodMismatch);
        } else if status_field("NoNewPrivs") == "1" {
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.reason, PrivilegeErrorReason::NoNewPrivsSet);
        } else {
            // 非 root で file capability も無い通常の CI: 必要な capability が無い。
            assert_eq!(e.code, ErrorCode::PermissionDenied);
            assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
        }
        assert_eq!(
            credential_lines(),
            before,
            "a refused elevate must not change credentials"
        );
        println!("privilege_elevate: refusal leaves credentials unchanged: ok");
    }

    // ---- 実機のシナリオ ----

    /// 子の役割。`elevate` を呼び、結果と縮退後の状態を `key=value` で標準出力へ出す。
    fn child(role: &str) {
        let method = match role {
            "setuid" => PrivilegeMethod::SetuidRoot,
            _ => PrivilegeMethod::LauncherAmbient,
        };
        match elevate(method) {
            Ok(r) => println!("elevate=ok held={}", r.held.len()),
            Err(e) => println!("elevate=err {}:{:?}", e.code.as_str(), e.reason),
        }
        for k in [
            "CapPrm",
            "CapEff",
            "CapInh",
            "CapBnd",
            "CapAmb",
            "Uid",
            "Gid",
            "Groups",
            "NoNewPrivs",
        ] {
            println!("{k}={}", status_field(k).replace('\t', " "));
        }
        // 縮退後の確認: 集合内の CAP_KILL は有効（pid 1 へ kill -0 が通る）、集合外の CAP_CHOWN は無効（EPERM）。
        let kill_ok = Command::new("kill")
            .args(["-0", "1"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        println!("kill_pid1={kill_ok}");
        let path = std::env::temp_dir().join(format!("fc-elevate-chown-{}", std::process::id()));
        let chown = fs::write(&path, b"x")
            .and_then(|()| std::os::unix::fs::chown(&path, Some(0), None))
            .map_err(|e| e.raw_os_error());
        let _ = fs::remove_file(&path);
        println!("chown_to_root={chown:?}");
    }

    fn run_child(mut cmd: Command) -> Vec<(String, String)> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut c = cmd.spawn().expect("spawn child (setpriv required)");
        let start = Instant::now();
        let status = loop {
            if let Some(s) = c.try_wait().expect("try_wait") {
                break s;
            }
            if start.elapsed() > CHILD_TIMEOUT {
                let _ = c.kill();
                let _ = c.wait();
                panic!("child timed out");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut out = String::new();
        if let Some(mut so) = c.stdout.take() {
            so.read_to_string(&mut out).expect("read child output");
        }
        assert!(status.success(), "child failed: {status:?}\n{out}");
        out.lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn get<'a>(kv: &'a [(String, String)], key: &str) -> &'a str {
        kv.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing key {key}"))
    }

    fn assert_reduced(kv: &[(String, String)]) {
        assert!(get(kv, "elevate").starts_with("ok held=7"), "{kv:?}");
        for k in ["CapPrm", "CapEff", "CapInh", "CapBnd", "CapAmb"] {
            assert_eq!(get(kv, k), MIN_HEX, "{k}");
        }
        assert_eq!(get(kv, "Uid"), "65534 65534 65534 65534");
        assert_eq!(get(kv, "Gid"), "65534 65534 65534 65534");
        assert_eq!(get(kv, "Groups"), "");
        assert_eq!(get(kv, "NoNewPrivs"), "0");
        assert_eq!(get(kv, "kill_pid1"), "true");
        assert_eq!(get(kv, "chown_to_root"), "Err(Some(1))");
    }

    fn real_scenarios() {
        let exe = std::env::current_exe().expect("current_exe");
        // (a) setuid 相当: real は非 root、effective / saved は 0。
        let mut a = Command::new("setpriv");
        a.args([
            "--ruid",
            "65534",
            "--rgid",
            "65534",
            "--clear-groups",
            "--euid",
            "0",
            "--egid",
            "0",
        ])
        .arg(&exe)
        .env(CHILD_ENV, "setuid");
        assert_reduced(&run_child(a));
        println!("privilege_elevate: setuid-root scenario: ok");

        // (c) ランチャー相当: root 所有 0755 の複製に file capability を付け、非 root で起動する。
        let dir = std::env::temp_dir().join(format!("fc-elevate-launcher-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let copy = dir.join("launcher");
        let result = std::panic::catch_unwind(|| {
            fs::copy(&exe, &copy).expect("copy exe");
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).expect("chmod");
            let caps = "cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill+ep";
            let st = Command::new("setcap")
                .arg(caps)
                .arg(&copy)
                .status()
                .expect("setcap required");
            assert!(
                st.success(),
                "setcap failed (xattr must be supported on the temp dir)"
            );
            let mut c = Command::new("setpriv");
            c.args(["--reuid", "65534", "--regid", "65534", "--clear-groups"])
                .arg(&copy)
                .env(CHILD_ENV, "launcher");
            assert_reduced(&run_child(c));
        });
        let _ = fs::remove_dir_all(&dir);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        println!("privilege_elevate: launcher-ambient scenario: ok");
    }
}
