//! 特権ランチャー bin の実機シナリオ（SUP-14・SEC-1・TASK-171 追補・#1719・MS-9）。
//!
//! `harness = false` の単一 `main` で、同じ実行ファイルが 2 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に
//!   実機前提を混ぜないため）。root・libcap の `setcap`・xattr（security.capability）が効き、exec できる
//!   ディレクトリ（`/opt` 配下。root 所有・0755 の経路）が要る（AGENTS.md「実機前提テスト」）。前提が満たせない
//!   ときは skip せず、1 行目 `launcher_entry_real: PRECONDITION FAILED (test environment, not a privileged launcher
//!   regression)` で非ゼロ失敗する（分類は既定の集合でも自己照合する。#2788・SEC-4・REPAIR-12）
//! - supervisor の代役: 自分のファイル名が `fandhe-container-supervisor` のとき、`/proc/self/status` の `Cap*` 行を
//!   stdout へ書いて終わる（ランチャーが環境変数を消すため、役は環境ではなくファイル名で決める）
//!
//! シナリオ: root 所有 0755 の一時ディレクトリへランチャー（本物の bin のコピー）と代役を置き、ランチャーへ
//! 必要最小集合 + `CAP_SETGID`（`+ep`）の file capability を付け、非特権 uid（65534）で起動する。代役が書いた
//! `CapPrm`・`CapEff`・`CapAmb`・`CapBnd` が必要最小集合 `0000000028201122` ちょうどであることを照合する。
//! 実行と結果の記録は人間担当（#538・#539）。Linux 限定。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("launcher_entry_real: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const MIN_HEX: &str = "0000000028201122";
    const LAUNCHER: &str = env!("CARGO_BIN_EXE_fandhe-container-launcher");
    const UNPRIVILEGED_UID: u32 = 65534;
    const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn run() {
        let me = std::env::current_exe().unwrap();
        if me.file_name().and_then(|n| n.to_str()) == Some("fandhe-container-supervisor") {
            stand_in();
            return;
        }
        // 前提欠如の分類の自己照合（既定のテスト集合でも常に走る。#2788）。
        self_check_precondition();
        if !std::env::args().any(|a| a == "--ignored") {
            println!("launcher_entry_real: skipped (run with -- --ignored as root)");
            return;
        }
        real_scenario(&me);
        println!("launcher_entry_real: all scenarios passed");
    }

    /// supervisor の代役。`Cap*` 行と、セッション関連（`Sess pid pgrp session tty_nr`）、fd 0〜2 が端末かを書く
    /// （TASK-171.2・#537）。exec で置き換わるため pid はランチャーの pid と同じ。
    fn stand_in() {
        use std::io::IsTerminal;
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for l in status.lines().filter(|l| l.starts_with("Cap")) {
            println!("{l}");
        }
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let rest = stat.rsplit_once(')').map(|(_, r)| r).unwrap_or_default();
        let f: Vec<&str> = rest.split_whitespace().collect();
        println!(
            "Sess: {} {} {} {}",
            std::process::id(),
            f.get(2).copied().unwrap_or("?"),
            f.get(3).copied().unwrap_or("?"),
            f.get(4).copied().unwrap_or("?")
        );
        println!(
            "Tty: {} {} {}",
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal()
        );
    }

    /// 前提の判定結果（#2788・SEC-4・REPAIR-12。純関数で自己照合する）。
    #[derive(Debug, PartialEq)]
    enum Precondition {
        Ok,
        /// root で実行されていない（試験環境の問題）。
        NotRoot {
            euid: String,
        },
        /// `setcap` が成功しない（libcap・xattr 非対応。試験環境の問題）。
        SetcapFailed,
        /// 判定不能（`Uid:` 行が無い・数値でない）。前提欠如とは断定しない。
        Unknown,
    }

    /// `/proc/self/status` の内容から euid の前提を分類する。
    fn classify_euid(status: Option<&str>) -> Precondition {
        let Some(status) = status else {
            return Precondition::Unknown;
        };
        match field(status, "Uid:").split_whitespace().nth(1) {
            Some("0") => Precondition::Ok,
            Some(v) if v.parse::<u32>().is_ok() => Precondition::NotRoot {
                euid: v.to_string(),
            },
            _ => Precondition::Unknown,
        }
    }

    /// 前提欠如の 2 種だけ panic メッセージを返す（1 行目で前提欠如と回帰を判別できる）。
    fn precondition_message(p: &Precondition) -> Option<String> {
        let (what, hint) = match p {
            Precondition::NotRoot { euid } => (
                format!("must run as root (euid={euid})."),
                "run it as root on the host (execution is a human task, #539)",
            ),
            Precondition::SetcapFailed => (
                "setcap must succeed (libcap, security.capability xattr support under /opt)."
                    .to_string(),
                "install libcap and use a filesystem that supports security.capability xattrs under /opt",
            ),
            Precondition::Ok | Precondition::Unknown => return None,
        };
        Some(format!(
            "launcher_entry_real: PRECONDITION FAILED (test environment, not a privileged launcher regression): {what}\n\
             hint: {hint}: sudo cargo test -p fandhe-container-supervisor --test launcher_entry_real -- --ignored. \
             See AGENTS.md launcher_entry_real."
        ))
    }

    fn self_check_precondition() {
        assert_eq!(
            classify_euid(Some("Uid:\t1000\t0\t0\t0\n")),
            Precondition::Ok
        );
        assert_eq!(
            classify_euid(Some("Uid:\t0\t1000\t0\t0\n")),
            Precondition::NotRoot {
                euid: "1000".into()
            }
        );
        assert_eq!(classify_euid(Some("Name:\tx\n")), Precondition::Unknown);
        assert_eq!(classify_euid(Some("Uid:\t0\tx\n")), Precondition::Unknown);
        assert_eq!(classify_euid(None), Precondition::Unknown);
        let m = precondition_message(&Precondition::NotRoot {
            euid: "1000".into(),
        })
        .expect("NotRoot is a precondition failure");
        assert_eq!(
            m.lines().next(),
            Some(
                "launcher_entry_real: PRECONDITION FAILED (test environment, not a privileged launcher regression): must run as root (euid=1000)."
            )
        );
        let m = precondition_message(&Precondition::SetcapFailed).expect("setcap");
        assert_eq!(
            m.lines().next(),
            Some(
                "launcher_entry_real: PRECONDITION FAILED (test environment, not a privileged launcher regression): setcap must succeed (libcap, security.capability xattr support under /opt)."
            )
        );
        assert_eq!(precondition_message(&Precondition::Ok), None);
        assert_eq!(precondition_message(&Precondition::Unknown), None);
    }

    fn field(out: &str, name: &str) -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    }

    fn real_scenario(me: &Path) {
        // libc を使わず /proc で effective uid を読む。
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let euid = classify_euid(Some(&status));
        if let Some(m) = precondition_message(&euid) {
            panic!("{m}");
        }
        if euid != Precondition::Ok {
            panic!("launcher_entry_real: could not determine euid from /proc/self/status");
        }
        let dir = PathBuf::from(format!("/opt/fandhe-launcher-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = scenario_in(&dir, me);
        let _ = std::fs::remove_dir_all(&dir);
        let (status, o, e) = match outcome {
            Ok(v) => v,
            Err(p) => panic!(
                "{}",
                precondition_message(&p)
                    .unwrap_or_else(|| "launcher_entry_real: setup failed".to_string())
            ),
        };
        assert!(
            status.success(),
            "launcher failed: {status:?}\nstdout: {o}\nstderr: {e}"
        );
        for name in ["CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
            assert_eq!(field(&o, name), MIN_HEX, "{name}\nstdout: {o}");
        }
        // セッションの切り離し（SUP-14 の要素 (B)）: pgrp == session == pid、制御端末なし、標準入出力が端末でない。
        let sess = field(&o, "Sess:");
        let v: Vec<&str> = sess.split_whitespace().collect();
        assert_eq!(v.len(), 4, "Sess: {sess}");
        assert_eq!(v[0], v[1], "pgrp must equal pid: {sess}");
        assert_eq!(v[0], v[2], "session must equal pid: {sess}");
        assert_eq!(v[3], "0", "tty_nr must be 0: {sess}");
        assert_eq!(field(&o, "Tty:"), "false false false", "stdout: {o}");
    }

    /// 一時ディレクトリを構成してランチャーを非特権 uid で起動し、終了状態・stdout・stderr を返す（後始末は呼び出し側）。
    fn scenario_in(
        dir: &Path,
        me: &Path,
    ) -> Result<(std::process::ExitStatus, String, String), Precondition> {
        let launcher = dir.join("fandhe-container-launcher");
        let sup = dir.join("fandhe-container-supervisor");
        std::fs::copy(LAUNCHER, &launcher).unwrap();
        std::fs::copy(me, &sup).unwrap();
        for p in [&launcher, &sup] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let caps = "cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill,cap_setgid+ep";
        let mut setcap = Command::new("setcap");
        setcap.arg(caps).arg(&launcher);
        // 期限なしの `status()` を避ける。期限切れ・spawn 失敗も前提欠如（SetcapFailed）として扱う（REPAIR-5・#3409）。
        let st = crate::reap::run_within(&mut setcap, crate::reap::reap_within())
            .inspect_err(|e| eprintln!("setcap: {e}"));
        if !st.is_ok_and(|s| s.success()) {
            return Err(Precondition::SetcapFailed);
        }
        let mut child = Command::new(&launcher)
            .args(["start", "--root", "/var/lib/fandhe-container", "c1"])
            .env_clear()
            .uid(UNPRIVILEGED_UID)
            .gid(UNPRIVILEGED_UID)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let deadline = Instant::now() + CHILD_TIMEOUT;
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                let _ = std::fs::remove_dir_all(dir);
                panic!("launcher did not exit within the timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (mut o, mut e) = (String::new(), String::new());
        let _ = out.read_to_string(&mut o);
        let _ = err.read_to_string(&mut e);
        Ok((status, o, e))
    }
}
