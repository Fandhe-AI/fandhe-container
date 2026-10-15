//! child subreaper の設定と、再親付けされた孫の pid 指定回収の結合試験（CORE-1・CORE-2・TASK-29 追補・#1813）。Linux 専用。
//!
//! 本番 launcher は中間プロセスの中でコンテナの PID 1 を起動し、中間プロセスが先に終わると PID 1 は孫になる。
//! 呼び出し側を child subreaper にしておくと、再親付けされた孫を `waitpid(<pid>)` で回収できる。本試験は
//! 試験バイナリ自身を `--intermediate` で再起動して中間プロセスにし、次を具体値で照合する。
//!
//! - 再親付け前（中間プロセスの生存中）の adopt は `ECHILD` 由来の `Err`（段 `Wait`）で、他の子を巻き込まない
//! - 中間プロセスの終了後、孫の ppid が自プロセスになり、`wait_timeout` が `Exited(7)` を返す
//! - 対照の無関係な子は、孫の回収の後でも自分の終了コード 9 で回収できる（`waitpid(-1)` で奪っていない）
//!
//! subreaper はプロセス全体の属性なので、`harness = false` の単一スレッド `main` で動かす。
//! root・実コンテナは不要。subreaper 未設定の対照は、init の構成（systemd --user 等が subreaper の場合がある）に
//! 依存して不安定になるため置かない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("child_subreaper: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::num::NonZeroU32;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use fandhe_container_core::exec::{ChildExit, ChildSubreaper, ContainerChild, IsolationStage};

    pub fn run() {
        if std::env::args().any(|a| a == "--intermediate") {
            intermediate();
            return;
        }
        parent();
        println!("child_subreaper: ok");
    }

    /// 中間プロセス: 孫を起動して pid を 1 行出し、stdin が EOF になるまで待って終わる（孫は待たない）。
    fn intermediate() {
        let grandchild = Command::new("sh")
            .args(["-c", "sleep 0.3; exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn grandchild");
        let mut out = std::io::stdout();
        writeln!(out, "{}", grandchild.id()).expect("write pid");
        out.flush().expect("flush");
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        // 孫は意図的に待たない（回収は呼び出し側の subreaper が行う）。
        std::mem::forget(grandchild);
    }

    fn ppid_of(pid: u32) -> u32 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
        // comm は括弧内に空白を含み得るため、最後の ')' の後ろを分割する。
        let rest = &stat[stat.rfind(')').expect("paren") + 2..];
        rest.split(' ')
            .nth(1)
            .expect("ppid")
            .parse()
            .expect("ppid number")
    }

    fn parent() {
        let proof = ChildSubreaper::enable().expect("enable subreaper");
        // 冪等。
        ChildSubreaper::enable().expect("enable twice");

        let exe = std::env::current_exe().expect("current_exe");
        let mut mid = Command::new(&exe)
            .arg("--intermediate")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn intermediate");
        let mut unrelated = Command::new("sh")
            .args(["-c", "exit 9"])
            .spawn()
            .expect("spawn unrelated");

        let mut line = String::new();
        BufReader::new(mid.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read grandchild pid");
        let gpid: u32 = line.trim().parse().expect("grandchild pid");
        let gpid_nz = NonZeroU32::new(gpid).expect("non-zero pid");

        // A: 再親付け前は自分の子ではなく ECHILD。
        let early = ContainerChild::adopt_reparented(gpid_nz, &proof);
        let err = early
            .wait_timeout(Duration::from_millis(50))
            .expect_err("grandchild is not yet our child");
        assert_eq!(err.stage, IsolationStage::Wait, "{}", err.message);

        // B: 中間プロセスを終わらせて回収し、孫が自分へ再親付けされたことを確認する。
        drop(mid.stdin.take());
        let mid_status = mid.wait().expect("wait intermediate");
        assert_eq!(mid_status.code(), Some(0));
        let me = std::process::id();
        let mut reparented = false;
        for _ in 0..200 {
            if ppid_of(gpid) == me {
                reparented = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(reparented, "grandchild {gpid} was not reparented to {me}");
        let adopted = ContainerChild::adopt_reparented(gpid_nz, &proof);
        assert_eq!(
            adopted
                .wait_timeout(Duration::from_secs(5))
                .expect("reap grandchild"),
            ChildExit::Exited(7)
        );

        // C: 無関係な子は奪われていない。
        assert_eq!(unrelated.wait().expect("wait unrelated").code(), Some(9));
    }
}
