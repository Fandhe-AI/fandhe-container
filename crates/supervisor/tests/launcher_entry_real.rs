//! 特権ランチャー bin の実機シナリオ（SUP-14・SEC-1・TASK-171 追補・#1719・MS-9）。
//!
//! `harness = false` の単一 `main` で、同じ実行ファイルが 2 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に
//!   実機前提を混ぜないため）。root・libcap の `setcap`・xattr（security.capability）が効き、exec できる
//!   ディレクトリ（`/opt` 配下。root 所有・0755 の経路）が要る（AGENTS.md「実機前提テスト」）。前提が満たせない
//!   ときは skip せず非ゼロで失敗する
//! - supervisor の代役: 自分のファイル名が `fandhe-container-supervisor` のとき、`/proc/self/status` の `Cap*` 行を
//!   stdout へ書いて終わる（ランチャーが環境変数を消すため、役は環境ではなくファイル名で決める）
//!
//! シナリオ: root 所有 0755 の一時ディレクトリへランチャー（本物の bin のコピー）と代役を置き、ランチャーへ
//! 必要最小集合 + `CAP_SETGID`（`+ep`）の file capability を付け、非特権 uid（65534）で起動する。代役が書いた
//! `CapPrm`・`CapEff`・`CapAmb`・`CapBnd` が必要最小集合 `0000000028201122` ちょうどであることを照合する。
//! 実行と結果の記録は人間担当（#538・#539）。Linux 限定。

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
        if !std::env::args().any(|a| a == "--ignored") {
            println!("launcher_entry_real: skipped (run with -- --ignored as root)");
            return;
        }
        real_scenario(&me);
        println!("launcher_entry_real: all scenarios passed");
    }

    /// supervisor の代役。`Cap*` 行だけを書く。
    fn stand_in() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for l in status.lines().filter(|l| l.starts_with("Cap")) {
            println!("{l}");
        }
    }

    fn require(ok: bool, msg: &str) {
        if !ok {
            eprintln!("launcher_entry_real: precondition failed: {msg}");
            std::process::exit(1);
        }
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
        require(
            field(&status, "Uid:").split_whitespace().nth(1) == Some("0"),
            "must run as root",
        );
        let dir = PathBuf::from(format!("/opt/fandhe-launcher-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = scenario_in(&dir, me);
        let _ = std::fs::remove_dir_all(&dir);
        let (status, o, e) = outcome;
        assert!(
            status.success(),
            "launcher failed: {status:?}\nstdout: {o}\nstderr: {e}"
        );
        for name in ["CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
            assert_eq!(field(&o, name), MIN_HEX, "{name}\nstdout: {o}");
        }
    }

    /// 一時ディレクトリを構成してランチャーを非特権 uid で起動し、終了状態・stdout・stderr を返す（後始末は呼び出し側）。
    fn scenario_in(dir: &Path, me: &Path) -> (std::process::ExitStatus, String, String) {
        let launcher = dir.join("fandhe-container-launcher");
        let sup = dir.join("fandhe-container-supervisor");
        std::fs::copy(LAUNCHER, &launcher).unwrap();
        std::fs::copy(me, &sup).unwrap();
        for p in [&launcher, &sup] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let caps = "cap_sys_admin,cap_mknod,cap_setpcap,cap_net_admin,cap_audit_write,cap_dac_override,cap_kill,cap_setgid+ep";
        let st = Command::new("setcap").arg(caps).arg(&launcher).status();
        require(
            st.map(|s| s.success()).unwrap_or(false),
            "setcap must succeed (libcap, xattr support)",
        );
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
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(dir);
                panic!("launcher did not exit within the timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (mut o, mut e) = (String::new(), String::new());
        let _ = out.read_to_string(&mut o);
        let _ = err.read_to_string(&mut e);
        (status, o, e)
    }
}
