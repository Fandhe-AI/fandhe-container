//! supervisor の bin の入口が継承 fd（fd 3 以降）を閉じることの結合試験（SEC-1・SUP-14・CORE-1・#2070）。
//!
//! `harness = false`。親は `sh` で CLOEXEC の無い fd 7 を開いてから自分自身を子として exec し、子は
//! `start_entry::run_main`（bin の `main` と同じ入口）の前後で `/proc/self/fd` を記録する。Linux 限定。

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
            child(&args[1], Path::new(&args[2]));
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

    fn parent() {
        let dir = std::env::temp_dir().join(format!("fc-inherited-fds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let root = dir.join("root");
        std::fs::create_dir(&root).unwrap();
        let marker = dir.join("leak-marker");
        std::fs::write(&marker, b"x").unwrap();
        let report = dir.join("report");
        let me = std::env::current_exe().unwrap();
        let mut c = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"exec 7<"$1"; shift; exec "$0" "$@""#)
            .arg(&me)
            .arg(&marker)
            .arg("--child")
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
                let _ = c.kill();
                let _ = c.wait();
                panic!("inherited_fds: child timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = t_out.join().unwrap();
        let stderr = t_err.join().unwrap();
        let rep = std::fs::read_to_string(&report).unwrap_or_else(|e| {
            panic!("report missing ({e}); status={status:?} stdout={stdout:?} stderr={stderr:?}")
        });
        let field = |name: &str| -> String {
            rep.lines()
                .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('\t')))
                .unwrap_or_default()
                .to_owned()
        };
        let marker_real = std::fs::canonicalize(&marker).unwrap();
        let before = field("before");
        assert!(
            before.contains(&format!("7={}", marker_real.display())),
            "leak setup did not take effect: {before}"
        );
        let after = field("after");
        let fds: Vec<&str> = after
            .split('\t')
            .map(|e| e.split('=').next().unwrap())
            .collect();
        assert_eq!(fds, ["0", "1", "2"], "fds after entry: {after}");
        assert!(!after.contains("leak-marker"), "marker still open: {after}");
        let _ = std::fs::remove_dir_all(&dir);
        println!(
            "inherited_fds: fd 7 inherited without CLOEXEC was closed at the supervisor entry; remaining fds 0,1,2"
        );
    }
}
