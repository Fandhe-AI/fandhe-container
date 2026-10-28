//! fd の生成と子の spawn を crate 内で直列化するゲート（PLUG-7・REPAIR-5・SEC-1。#3139）。
//!
//! # 守る窓
//! macOS の Rust std は `UnixStream::pair`・`io::pipe`・`UnixListener::bind`（`socket`）・`accept` で
//! close-on-exec を原子的に立てない。`socketpair(2)` / `pipe(2)` / `socket(2)` / `accept(2)` の後に、fd ごとに
//! 別の `ioctl(FIOCLEX)` で立てる（toolchain `rustc 1.99.0 (b940084d7)` の
//! `library/std/src/sys/net/connection/socket/unix.rs` の `Socket::new_pair` L135〜L139・`Socket::new` L95〜L98・
//! `Socket::accept` L266〜L269、`sys/pipe/unix.rs` の `pipe` L34〜L39、`sys/fd/unix.rs` の `set_cloexec` L586〜L590）。
//! 一方 macOS の `Command::spawn` は `posix_spawn` で `POSIX_SPAWN_CLOEXEC_DEFAULT` を付けず
//! （`sys/process/unix/unix.rs` L730〜L759 の flags は SETPGROUP・SETSIGDEF・SETSID のみ）、fd の生成と spawn を
//! 排他するロックも std に無い。この間に別スレッドが子を spawn すると、まだ close-on-exec の立っていない fd
//! （plugin の stderr の書き込み端・停止用 pipe・listener・受理した接続）が無関係な子へ継承され、子が生きている間
//! 保持され続ける（stderr の EOF が遅れ、別 plugin の listener を継承して接続を横取りしうる）。
//! fork から exec までの一過性の保持（Linux にもある）とは別の窓である。
//!
//! # 効く範囲
//! - このゲートを通る生成（[`create_fds`]）と spawn（[`spawn`]）どうしは同時に起きない。生成どうしは並行できる。
//!   unix の全 OS で同じ挙動にする（分岐を増やさない。REPAIR-1）。Linux の std は原子的に作るので実害はない。
//! - 効かない範囲: 本 crate の外（core・cli 等）の `Command::spawn` との組。窓は std の内部にあり、
//!   プロセス全体のロックが std に無いため crate 単独では塞げない。塞ぐ案の比較は #3139 を参照。
//!
//! # 使い方の制約
//! [`create_fds`] の中で [`spawn`] や再び [`create_fds`] を呼ばない（同じスレッドが読み取りロックを持ったまま
//! 書き込みロックを待つとデッドロックする）。クロージャは短時間で戻る処理（1 回の syscall と設定）に限り、
//! 期限のないブロッキング処理を入れない（REPAIR-5）。ロックの poison は無視する（先行スレッドの panic で
//! 以後の起動を恒久的に止めない）。

use std::io;
use std::process::{Child, Command};
use std::sync::{PoisonError, RwLock};

/// 生成（読み取り）と spawn（書き込み）を排他するゲート。
static GATE: RwLock<()> = RwLock::new(());

/// close-on-exec を非原子に立てうる fd の生成 `f` を、spawn と排他で実行する。
///
/// 呼び出し元: `lifecycle` の stderr 用ソケット対・停止用 pipe、`transport` の listener bind と accept。
/// 生成どうしは並行できる。`f` の中で [`spawn`] を呼んではならない（モジュール doc 参照）。
pub(crate) fn create_fds<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = GATE.read().unwrap_or_else(PoisonError::into_inner);
    f()
}

/// `cmd` を、fd の生成と排他で spawn する。`lifecycle::spawn_registered` が本番の呼び出し元。
pub(crate) fn spawn(cmd: &mut Command) -> io::Result<Child> {
    let _guard = GATE.write().unwrap_or_else(PoisonError::into_inner);
    cmd.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn holder() -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "exec sleep 5"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    fn kill_reap(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// 短命の子の回収を期限つきで待つ。超過時は kill して失敗にする（REPAIR-5）。
    fn wait_bounded(mut child: Child) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                return;
            }
            if Instant::now() >= deadline {
                kill_reap(child);
                panic!("short-lived child did not exit in time");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// reader を非ブロッキングで 1 回読む。EOF なら `Ok(0)`、相手が生きていれば `WouldBlock`。
    fn probe_eof(reader: &mut UnixStream) -> io::Result<usize> {
        reader.set_nonblocking(true)?;
        let mut b = [0u8; 1];
        reader.read(&mut b)
    }

    const ROLE_ENV: &str = "FANDHE_SPAWN_GATE_ROLE";

    /// 親プロセスなら自分自身を `--exact` で単独再実行して成否を返す（`true`）。再実行された側なら `false`。
    /// 同一 libtest プロセス内の他試験の直接 spawn による fd の継承を避けるため（REPAIR-12）。
    /// 子の終了待ちには期限を設け、超過時は kill して回収し失敗にする（REPAIR-5）。
    fn reexec_isolated(name: &str) -> bool {
        if std::env::var_os(ROLE_ENV).is_some() {
            return false;
        }
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(exe)
            .args(["--exact", name, "--test-threads=1"])
            .env(ROLE_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated child of {name} exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "child role failed: {status}");
        true
    }

    /// PLUG-7・SEC-1・#3139: 本番が作る fd はすべて close-on-exec。
    #[test]
    fn plug7_spawn_gate_production_fds_are_cloexec() {
        let (reader, writer) = create_fds(UnixStream::pair).unwrap();
        assert!(sys::fd_cloexec(reader.as_fd()).unwrap());
        assert!(sys::fd_cloexec(writer.as_fd()).unwrap());
        let (r, w) = create_fds(std::io::pipe).unwrap();
        assert!(sys::fd_cloexec(r.as_fd()).unwrap());
        assert!(sys::fd_cloexec(w.as_fd()).unwrap());
        let dir = std::env::temp_dir().join(format!("sg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let l = create_fds(|| std::os::unix::net::UnixListener::bind(&sock)).unwrap();
        assert!(sys::fd_cloexec(l.as_fd()).unwrap());
        drop(l);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PLUG-7・SEC-1・#3139: (a) close-on-exec の無い writer は並行 spawn の子に保持され EOF が来ない
    /// （漏れの因果の対照）。(b) ゲートは、fd が継承可能な間の spawn を待たせ、窓を閉じてから spawn させる。
    #[test]
    fn plug7_sec1_spawn_gate_blocks_spawn_while_fd_is_inheritable() {
        if reexec_isolated(
            "spawn_gate::tests::plug7_sec1_spawn_gate_blocks_spawn_while_fd_is_inheritable",
        ) {
            return;
        }
        // (a) 対照: ゲートを通さず spawn すると writer を子が保持する。
        let (mut reader, writer) = UnixStream::pair().unwrap();
        sys::set_fd_cloexec(writer.as_fd(), false).unwrap();
        let child = holder().spawn().unwrap();
        drop(writer);
        let got = probe_eof(&mut reader);
        kill_reap(child);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::WouldBlock);

        // (b) ゲートあり: 窓が開いている間、spawn は待たされる。
        let (mut reader, writer) = UnixStream::pair().unwrap();
        let (open_tx, open_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Child>();
        std::thread::scope(|s| {
            let w = &writer;
            s.spawn(move || {
                create_fds(|| {
                    sys::set_fd_cloexec(w.as_fd(), false)?;
                    open_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(300));
                    sys::set_fd_cloexec(w.as_fd(), true)
                })
                .unwrap();
            });
            open_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            s.spawn(move || {
                let child = spawn(&mut holder()).unwrap();
                done_tx.send(child).unwrap();
            });
            // 窓が開いている間は spawn が完了しない。
            assert!(matches!(
                done_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
        });
        // 窓が閉じた後に spawn された子は writer を持たない。writer を閉じれば EOF が期限内に来る。
        let child = done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_millis(500);
        let eof = loop {
            match probe_eof(&mut reader) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        };
        kill_reap(child);
        assert_eq!(eof, 0);
    }

    /// PLUG-7・REPAIR-5・SEC-1・#3139: 並行 spawn の下でも、作った直後の stderr 用ソケット対の writer を
    /// 閉じれば EOF になる（macOS では本番の窓を突く回帰試験）。他の試験の子の干渉を避けるため、
    /// 自分自身を単独で再実行したプロセスの中で回す。
    #[test]
    fn plug7_repair5_concurrent_spawn_does_not_inherit_stderr_writer() {
        if reexec_isolated(
            "spawn_gate::tests::plug7_repair5_concurrent_spawn_does_not_inherit_stderr_writer",
        ) {
            return;
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut leaked = 0u32;
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut spawned = 0u32;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) && spawned < 20_000 {
                    let mut c = Command::new("/bin/sh");
                    c.args(["-c", "exit 0"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    let child = spawn(&mut c).unwrap();
                    wait_bounded(child);
                    spawned += 1;
                }
            });
            for _ in 0..1000 {
                let mut counted = false;
                let r = create_fds(|| {
                    let (mut reader, writer) = UnixStream::pair()?;
                    drop(writer);
                    if probe_eof(&mut reader)? != 0 {
                        counted = true;
                    }
                    Ok(())
                });
                r.unwrap();
                if counted {
                    leaked += 1;
                }
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(leaked, 0);
    }
}
