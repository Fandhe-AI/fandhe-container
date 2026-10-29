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
//! - 効かない範囲（feature `grpc` と `connect_unix`。#3262）: macOS では次の fd 生成も close-on-exec が非原子で、
//!   このゲートの外にある。tokio 1.53.3 / mio 1.2.4（`Cargo.lock` の固定版）の `accept`（`accept(2)` の後に
//!   `fcntl(F_SETFD)`）と client connect（mio の `new_socket` が `socket(2)` の後に `fcntl`）、および
//!   `sys::connect_unix` の macOS 分岐（`socket` の後に `fcntl`）。grpc の listener の bind は `transport` の
//!   bind（ゲートの中）で作った fd を `F_DUPFD_CLOEXEC` で複製するので原子的で、対応済み。
//!   載せない理由: これらを使うプロセス（plugin-cri・plugin-macos）に [`spawn`] を呼ぶ箇所が無く、載せても
//!   排他する相手がいない。また [`create_fds`] はブロッキングな待ちを持つため、async の accept / connect の
//!   poll の中に置くと tokio の worker を止める（REPAIR-5）。載せるには非ブロッキングの取得 API が要る。
//!   見直す条件: 同じプロセスで grpc の accept / connect か `connect_unix` と [`spawn`] を併用する実装が
//!   macOS に現れたとき。依存（tokio・mio）の版を更新したら該当箇所を再確認する。
//!
//! # 使い方の制約
//! [`create_fds`] の中で [`spawn`] や再び [`create_fds`] を呼ばない（同じスレッドが読み取りロックを持ったまま
//! 書き込みロックを待つとデッドロックする）。クロージャは短時間で戻る処理（1 回の syscall と設定）に限り、
//! 期限のないブロッキング処理を入れない（REPAIR-5）。ゲートの取得待ちは呼び出し元の期限で打ち切る。ロックの poison は無視する（先行スレッドの panic で
//! 以後の起動を恒久的に止めない）。

use std::io;
use std::process::{Child, Command};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
use std::time::{Duration, Instant};

/// 期限を呼び出し元が持たない経路（stderr 用 fd の生成・listener の bind・spawn）がゲートの取得を待つ上限。
pub(crate) const GATE_WAIT_DEFAULT: Duration = Duration::from_secs(5);

/// ゲート取得のポーリング間隔（`try_read` / `try_write` の再試行。REPAIR-5）。
const GATE_POLL: Duration = Duration::from_millis(1);

/// ゲートの取得期限切れを表すエラー（`io::ErrorKind::TimedOut`）。呼び出し元は Timeout 系へ写像する。
fn gate_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for the spawn gate",
    )
}

fn read_until(deadline: Instant) -> io::Result<RwLockReadGuard<'static, ()>> {
    loop {
        match GATE.try_read() {
            Ok(g) => return Ok(g),
            Err(TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(gate_timeout());
                }
                std::thread::sleep(GATE_POLL);
            }
        }
    }
}

fn write_until(deadline: Instant) -> io::Result<RwLockWriteGuard<'static, ()>> {
    loop {
        match GATE.try_write() {
            Ok(g) => return Ok(g),
            Err(TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(gate_timeout());
                }
                std::thread::sleep(GATE_POLL);
            }
        }
    }
}

/// 生成（読み取り）と spawn（書き込み）を排他するゲート。
static GATE: RwLock<()> = RwLock::new(());

/// close-on-exec を非原子に立てうる fd の生成 `f` を、spawn と排他で実行する。
///
/// 呼び出し元: `lifecycle` の stderr 用ソケット対・停止用 pipe、`transport` の listener bind と accept。
/// 生成どうしは並行できる。`f` の中で [`spawn`] を呼んではならない（モジュール doc 参照）。
///
/// ゲートの取得は `deadline` まで（超えたら `ErrorKind::TimedOut`。REPAIR-5）。別の spawn が止まっても
/// 呼び出し元の期限（accept の接続期限等）に到達できる。
pub(crate) fn create_fds<T>(deadline: Instant, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = read_until(deadline)?;
    f()
}

/// `cmd` を、fd の生成と排他で spawn する。`lifecycle::spawn_registered` が本番の呼び出し元。
/// ゲートの取得は `deadline` まで（超えたら `ErrorKind::TimedOut`）。
pub(crate) fn spawn(deadline: Instant, cmd: &mut Command) -> io::Result<Child> {
    let _guard = write_until(deadline)?;
    // 期限後は子を作らない（待ちの途中で期限を過ぎた場合を含む。REPAIR-5）。
    if Instant::now() >= deadline {
        return Err(gate_timeout());
    }
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

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn holder() -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "exec sleep 5"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    /// SIGKILL 後の回収確認の上限。SIGKILL の配送は即時でないことがあるが、10 秒で回収できない子は
    /// 割り込み不能待ち等の異常として、待ち続けずに失敗にする（REPAIR-5: 期限なしの `wait()` を置かない）。
    const REAP_LIMIT: Duration = Duration::from_secs(10);

    /// kill した子を `limit` 以内に `try_wait` のポーリングで回収する。回収できれば `true`。
    fn kill_reap_within(child: &mut Child, limit: Duration) -> bool {
        let _ = child.kill();
        let deadline = Instant::now() + limit;
        loop {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// kill して `REAP_LIMIT` 以内の回収を確認する。確認できなければ panic で試験を失敗させる。
    fn kill_reap(mut child: Child) {
        assert!(
            kill_reap_within(&mut child, REAP_LIMIT),
            "child was not reaped within {REAP_LIMIT:?} after SIGKILL"
        );
    }

    /// REPAIR-5: kill 後の回収が期限内に確認でき、回収済みの子は終了状態を返さない（再 wait 不要）。
    #[test]
    fn repair5_kill_reap_within_reaps_a_live_child() {
        let mut child = holder().spawn().unwrap();
        assert!(kill_reap_within(&mut child, REAP_LIMIT));
        // 回収済みの子の try_wait は SIGKILL の終了状態を返し続ける。
        let st = child.try_wait().unwrap().unwrap();
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&st), Some(9));
    }

    /// REPAIR-5: 期限 0 では、SIGKILL の直後に回収できなくても待たずに `false` で返る（期限切れ経路）。
    #[test]
    fn repair5_kill_reap_within_zero_limit_returns_without_blocking() {
        let mut child = holder().spawn().unwrap();
        let started = Instant::now();
        let reaped = kill_reap_within(&mut child, Duration::ZERO);
        assert!(started.elapsed() < Duration::from_secs(1));
        // true でも false でも待ちは有界。後始末は期限つきで行う。
        if !reaped {
            assert!(kill_reap_within(&mut child, REAP_LIMIT));
        }
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
                let reaped = kill_reap_within(&mut child, REAP_LIMIT);
                panic!(
                    "isolated child of {name} exceeded its deadline (reaped after SIGKILL within {REAP_LIMIT:?}: {reaped})"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "child role failed: {status}");
        true
    }

    /// PLUG-7・SEC-1・#3139: 本番が作る fd はすべて close-on-exec。
    #[test]
    fn plug7_spawn_gate_production_fds_are_cloexec() {
        let (reader, writer) = create_fds(far(), UnixStream::pair).unwrap();
        assert!(sys::fd_cloexec(reader.as_fd()).unwrap());
        assert!(sys::fd_cloexec(writer.as_fd()).unwrap());
        let (r, w) = create_fds(far(), std::io::pipe).unwrap();
        assert!(sys::fd_cloexec(r.as_fd()).unwrap());
        assert!(sys::fd_cloexec(w.as_fd()).unwrap());
        let dir = std::env::temp_dir().join(format!("sg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let l = create_fds(far(), || std::os::unix::net::UnixListener::bind(&sock)).unwrap();
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
                create_fds(far(), || {
                    sys::set_fd_cloexec(w.as_fd(), false)?;
                    open_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(300));
                    sys::set_fd_cloexec(w.as_fd(), true)
                })
                .unwrap();
            });
            open_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            s.spawn(move || {
                let child = spawn(far(), &mut holder()).unwrap();
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
                    let child = spawn(far(), &mut c).unwrap();
                    wait_bounded(child);
                    spawned += 1;
                }
            });
            for _ in 0..1000 {
                let mut counted = false;
                let r = create_fds(far(), || {
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

    /// REPAIR-5・PLUG-7・#3139: ゲートを他スレッドが保持している間、取得は期限で `TimedOut` になる
    /// （書き込み側 spawn が止まっても生成側が無期限に待たず、生成側が保持していても spawn が待たない）。
    /// REPAIR-5: 期限を過ぎていれば（ゲートが空いていても）子を spawn しない。
    #[test]
    fn repair5_spawn_after_deadline_does_not_spawn() {
        let marker =
            std::env::temp_dir().join(format!("spawn_gate_expired_{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("touch \"$1\"").arg("sh").arg(&marker);
        let e = spawn(Instant::now() - Duration::from_millis(1), &mut cmd).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(200));
        assert!(!marker.exists());
    }

    #[test]
    fn repair5_spawn_gate_acquisition_times_out_at_deadline() {
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        std::thread::scope(|s| {
            s.spawn(move || {
                create_fds(far(), || {
                    held_tx.send(()).unwrap();
                    let _ = release_rx.recv_timeout(Duration::from_secs(10));
                    Ok(())
                })
                .unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let start = Instant::now();
            let e = spawn(start + Duration::from_millis(50), &mut holder()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() < Duration::from_secs(5));
            release_tx.send(()).unwrap();
        });
        // 書き込みロックを保持している間は読み取り側の取得も期限で戻る。
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        std::thread::scope(|s| {
            s.spawn(move || {
                let _g = write_until(far()).unwrap();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(10));
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let e = create_fds(Instant::now() + Duration::from_millis(50), || Ok(())).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::TimedOut);
            release_tx.send(()).unwrap();
        });
    }
}
