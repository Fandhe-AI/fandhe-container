//! supervisor の bin の入口が継承 fd（fd 3 以降）を閉じることと、fd 0〜2 が閉じた状態の起動の結合試験
//! （SEC-1・SUP-14・SUP-1・CORE-1・#2070・#2132）。
//!
//! `harness = false`。親は `sh` で CLOEXEC の無い fd 7 を開く（`leak7`）か fd 0・1・2 のどれかを閉じて（`closed0`・
//! `closed1`・`closed2`）から自分自身を子として exec し、子は `start_entry::run_main`（bin の `main` と同じ入口）の
//! 前後で `/proc/self/fd` を記録する。閉じた fd 0〜2 は Rust std が `main` の前に `/dev/null` で埋める。fd 1 が埋まった
//! 場合は結果チャネルの FIFO 検査が拒否する。Linux 限定。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("inherited_fds: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::Read;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

    /// `(fd, リンク先)` の一覧。列挙に使う `read_dir` 自身の fd は除く。
    fn list_fds() -> Vec<(u32, String)> {
        let me = format!("/proc/{}/fd", std::process::id());
        let mut v = Vec::new();
        for e in std::fs::read_dir("/proc/self/fd").unwrap() {
            let e = e.unwrap();
            let fd: u32 = e.file_name().to_str().unwrap().parse().unwrap();
            if let Ok(t) = std::fs::read_link(e.path()) {
                if t.to_str() == Some(me.as_str()) {
                    continue;
                }
                v.push((fd, t.to_string_lossy().into_owned()));
            }
        }
        v.sort();
        v
    }

    fn render(v: &[(u32, String)]) -> String {
        v.iter()
            .map(|(f, t)| format!("{f}={t}"))
            .collect::<Vec<_>>()
            .join("\t")
    }

    pub fn run() {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        if args.first().and_then(|a| a.to_str()) == Some("--child") {
            child(&args[2], Path::new(&args[3]));
        } else {
            parent();
        }
    }

    fn child(root: &OsString, report: &Path) -> ! {
        let before = list_fds();
        let code = fandhe_container_supervisor::start_entry::run_main(
            ["start", "--root", root.to_str().unwrap(), "c1"]
                .into_iter()
                .map(OsString::from),
        );
        let after = list_fds();
        std::fs::write(
            report,
            format!("before\t{}\nafter\t{}\n", render(&before), render(&after)),
        )
        .unwrap();
        // 終了コードの詳細は stdout の報告で見るため、ここでは run_main の値をそのまま返す。
        std::process::exit(if format!("{code:?}").contains("(0)") {
            0
        } else {
            3
        });
    }

    struct Outcome {
        before: String,
        after: String,
        stdout: String,
        stderr: String,
    }

    /// `scenario` の fd 状態を `sh` で作ってから子を起動し、子の報告・stdout・stderr を集める。
    fn run_scenario(scenario: &str) -> Outcome {
        let dir = std::env::temp_dir().join(format!(
            "fc-inherited-fds-{}-{scenario}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let root = dir.join("root");
        std::fs::create_dir(&root).unwrap();
        let marker = dir.join("leak-marker");
        std::fs::write(&marker, b"x").unwrap();
        let report = dir.join("report");
        let me = std::env::current_exe().unwrap();
        // 固定スクリプト。値は位置引数で渡し、文字列連結しない。
        let script = r#"s=$1; m=$2; shift 2
case "$s" in
  leak7) exec 7<"$m";;
  closed0) exec 0<&-;;
  closed1) exec 1>&-;;
  closed2) exec 2>&-;;
esac
exec "$0" "$@""#;
        let mut c = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .arg(&me)
            .arg(scenario)
            .arg(&marker)
            .arg("--child")
            .arg(scenario)
            .arg(&root)
            .arg(&report)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = c.stdout.take().unwrap();
        let mut err = c.stderr.take().unwrap();
        let t_out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        });
        let start = Instant::now();
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > CHILD_TIMEOUT {
                crate::reap::reap_or_report(&mut c, crate::reap::REAP_WITHIN);
                panic!("inherited_fds: child timed out ({scenario})");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = t_out.join().unwrap();
        let stderr = t_err.join().unwrap();
        let rep = std::fs::read_to_string(&report).unwrap_or_else(|e| {
            panic!(
                "report missing ({e}); scenario={scenario} status={status:?} stdout={stdout:?} stderr={stderr:?}"
            )
        });
        let field = |name: &str| -> String {
            rep.lines()
                .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('\t')))
                .unwrap_or_default()
                .to_owned()
        };
        let o = Outcome {
            before: field("before"),
            after: field("after"),
            stdout,
            stderr,
        };
        let _ = std::fs::remove_dir_all(&dir);
        o
    }

    fn fd_numbers(rendered: &str) -> Vec<&str> {
        rendered
            .split('\t')
            .map(|e| e.split('=').next().unwrap())
            .collect()
    }

    const STDIO_MSG: &str = "stdin, stdout and stderr must be open";

    fn parent() {
        // leak7: CLOEXEC の無い fd 7 が入口で閉じられる（#2070）。
        let o = run_scenario("leak7");
        assert!(
            o.before.contains("7=") && o.before.contains("leak-marker"),
            "leak setup did not take effect: {}",
            o.before
        );
        assert_eq!(
            fd_numbers(&o.after),
            ["0", "1", "2"],
            "fds after entry: {}",
            o.after
        );
        assert!(
            !o.after.contains("leak-marker"),
            "marker still open: {}",
            o.after
        );
        println!(
            "inherited_fds: fd 7 inherited without CLOEXEC was closed at the supervisor entry; remaining fds 0,1,2"
        );

        // closed0 / closed2: std が /dev/null で埋め、入口の fd 0〜2 の確認を通って起動へ進む（#2132）。
        for (scenario, fd) in [("closed0", "0"), ("closed2", "2")] {
            let o = run_scenario(scenario);
            assert!(
                o.before.split('\t').any(|e| e == format!("{fd}=/dev/null")),
                "{scenario}: fd {fd} not refilled with /dev/null: {}",
                o.before
            );
            assert_eq!(
                fd_numbers(&o.after),
                ["0", "1", "2"],
                "{scenario}: {}",
                o.after
            );
            assert!(
                o.stdout.starts_with("FCSUP1 "),
                "{scenario}: stdout={:?}",
                o.stdout
            );
            assert!(
                !o.stderr.contains(STDIO_MSG),
                "{scenario}: stderr={:?}",
                o.stderr
            );
            println!(
                "inherited_fds: {scenario}: fd {fd} refilled with /dev/null and the entry proceeded"
            );
        }

        // closed1: fd 1 が /dev/null になり、結果チャネルの FIFO 検査が拒否する（stderr の JSON 1 行）。
        let o = run_scenario("closed1");
        assert!(
            o.before.split('\t').any(|e| e == "1=/dev/null"),
            "closed1: fd 1 not refilled with /dev/null: {}",
            o.before
        );
        assert_eq!(o.stdout, "", "closed1: nothing may reach stdout");
        assert!(
            o.stderr
                .contains("stdout must be a pipe for the result channel"),
            "closed1: stderr={:?}",
            o.stderr
        );
        println!(
            "inherited_fds: closed1: fd 1 refilled with /dev/null and the result channel was refused"
        );
    }
}
