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

    /// 通常の子の終了待ちの上限。`/bin/sh -c "exit 0"` は通常ミリ秒で終わるため、負荷の高い CI でも
    /// 十分余る 10 秒とする（REPAIR-5: 期限なしの `wait()` を置かない）。
    const WAIT_LIMIT: Duration = Duration::from_secs(10);
    /// 再実行した試験プロセス（20,000 回の spawn と 1,000 回の窓の試行）の終了待ちの上限。
    const REEXEC_LIMIT: Duration = Duration::from_secs(120);
    /// SIGKILL 後の回収確認の上限。SIGKILL の配送は即時でないことがあるが、数秒で回収できない子は
    /// 割り込み不能待ち等の異常として、待ち続けず失敗にする。
    const REAP_LIMIT: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(5);

    /// `limit` 以内に `try_wait` が終了を返すまでポーリングする。期限切れなら `Ok(None)`。
    fn poll_exit(
        child: &mut Child,
        limit: Duration,
    ) -> io::Result<Option<std::process::ExitStatus>> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(st) = child.try_wait()? {
                return Ok(Some(st));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL);
        }
    }

    /// 期限つきの終了待ち。`limit` を超えたら kill し、`reap_limit` 以内の回収を確認する。
    /// 期限超過・回収不能はどちらも具体的なメッセージの `Err` にする。
    fn wait_bounded(
        child: &mut Child,
        limit: Duration,
        reap_limit: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        if let Some(st) = poll_exit(child, limit).map_err(|e| format!("try_wait failed: {e}"))? {
            return Ok(st);
        }
        let _ = child.kill();
        match poll_exit(child, reap_limit) {
            Ok(Some(_)) => Err(format!(
                "child did not exit within {limit:?}; killed and reaped"
            )),
            Ok(None) => Err(format!(
                "child did not exit within {limit:?} and was not reaped within {reap_limit:?} after SIGKILL"
            )),
            Err(e) => Err(format!(
                "child did not exit within {limit:?}; try_wait after kill failed: {e}"
            )),
        }
    }

    /// kill して `REAP_LIMIT` 以内の回収を確認する。確認できなければ panic で試験を失敗させる。
    fn kill_reap(mut child: Child) {
        let _ = child.kill();
        match poll_exit(&mut child, REAP_LIMIT) {
            Ok(Some(_)) => {}
            other => panic!("child was not reaped within {REAP_LIMIT:?} after SIGKILL: {other:?}"),
        }
    }

    /// REPAIR-5: 期限切れでは子を kill して回収し、期限超過を具体的なメッセージで報告する。
    #[test]
    fn repair5_wait_bounded_kills_and_reports_on_timeout() {
        let mut child = holder().spawn().unwrap();
        let err = wait_bounded(&mut child, Duration::from_millis(100), REAP_LIMIT).unwrap_err();
        assert_eq!(err, "child did not exit within 100ms; killed and reaped");
        // 回収済みなので、以後の try_wait は SIGKILL の終了状態を返す。
        assert!(child.try_wait().unwrap().is_some());
    }

    /// REPAIR-5: 期限内に終了した子は終了状態を返す。
    #[test]
    fn repair5_wait_bounded_returns_status_when_child_exits() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = c.spawn().unwrap();
        let st = wait_bounded(&mut child, WAIT_LIMIT, REAP_LIMIT).unwrap();
        assert_eq!(st.code(), Some(3));
    }

    /// reader を非ブロッキングで 1 回読む。EOF なら `Ok(0)`、相手が生きていれば `WouldBlock`。
    fn probe_eof(reader: &mut UnixStream) -> io::Result<usize> {
        reader.set_nonblocking(true)?;
        let mut b = [0u8; 1];
        reader.read(&mut b)
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

    const ROLE_ENV: &str = "FANDHE_SPAWN_GATE_ROLE";

    /// PLUG-7・REPAIR-5・SEC-1・#3139: 並行 spawn の下でも、作った直後の stderr 用ソケット対の writer を
    /// 閉じれば EOF になる（macOS では本番の窓を突く回帰試験）。他の試験の子の干渉を避けるため、
    /// 自分自身を単独で再実行したプロセスの中で回す。
    #[test]
    fn plug7_repair5_concurrent_spawn_does_not_inherit_stderr_writer() {
        if std::env::var_os(ROLE_ENV).is_none() {
            let exe = std::env::current_exe().unwrap();
            let mut reexec = Command::new(exe)
                .args([
                    "--exact",
                    "spawn_gate::tests::plug7_repair5_concurrent_spawn_does_not_inherit_stderr_writer",
                    "--test-threads=1",
                ])
                .env(ROLE_ENV, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let status = wait_bounded(&mut reexec, REEXEC_LIMIT, REAP_LIMIT).unwrap();
            assert!(status.success(), "child role failed: {status}");
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
                    let mut child = spawn(&mut c).unwrap();
                    let st = wait_bounded(&mut child, WAIT_LIMIT, REAP_LIMIT).unwrap();
                    assert!(st.success(), "exit 0 child failed: {st}");
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
