//! タイムアウトと出力量上限つきの外部プロセス実行器（TASK-67.3・REPAIR-5）。
//!
//! `Command::output()` は待ち時間の上限を持たないため使わない。呼び出し元は `wsl2` モジュールで、
//! プログラムのパスを引数で受け取るので、テストでは本物の `wsl.exe` を起動せずに済む。
//! 期限切れでは子を kill して回収する。読み取りスレッドは孫プロセスがパイプを握り続けても
//! 戻れるよう、無期限に join しない。
//!
//! Windows では子を `CREATE_SUSPENDED` で起動し、Job Object（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）へ
//! 割り当ててから再開する（[`ProcessTree`]）。これで `wsl.exe` が先に終了した後もパイプを継承した
//! 子孫を終了でき、読み取りスレッドは EOF で必ず終わる（REPAIR-5）。

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use super::{Wsl2Error, Wsl2ErrorCode};

/// 実行結果（stdout・stderr は `max_bytes` 以下のバイト列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Captured {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// kill 後に子の終了を待つ上限（REPAIR-5）。超えたら回収不能として `INTERNAL` で返す。
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// 同時に生存を許す読み取りスレッド数の上限（REPAIR-5）。
///
/// 孫プロセスがパイプを握り続けると、読み取りスレッドはブロッキング `read()` から戻れない。
/// Windows では [`ProcessTree`] が子孫ごと終了させるのでスレッドは EOF で終わるが、Job の
/// 終了に失敗した場合や Windows 以外でも残留スレッドが無制限に蓄積しないよう、多重防御として
/// 上限を設け、超過時は新規起動を `RESOURCE_EXHAUSTED` で拒否する（パイプが閉じれば EOF で
/// スレッドは終了し、カウントは戻る）。
const MAX_LIVE_READERS: usize = 64;

/// 生存中の読み取りスレッド数。
static LIVE_READERS: AtomicUsize = AtomicUsize::new(0);

/// 生存カウントの RAII ガード（スレッドの終了・panic で必ず減算する）。
struct ReaderGuard(&'static AtomicUsize);

impl ReaderGuard {
    fn acquire_in(counter: &'static AtomicUsize, max: usize) -> Option<Self> {
        // `fetch_update` / `try_update` は stable の版で改名されるため、版差を避けて CAS ループで書く。
        let mut cur = counter.load(Ordering::SeqCst);
        loop {
            if cur >= max {
                return None;
            }
            match counter.compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(ReaderGuard(counter)),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 1 本のパイプの読み取り結果。
struct Pipe {
    /// 読み取れたバイト列（上限超過時は途中まで）。
    buf: Vec<u8>,
    /// `max_bytes` を超えたか。
    overflow: bool,
    /// `read()` が EOF 以外のエラーで終わったか（途中出力を成功として返さないための印）。
    io_error: bool,
}

/// パイプを `max_bytes` を超えるまで読み、上限超過かどうかと一緒に送る。
fn spawn_reader<R: Read + Send + 'static>(
    mut r: R,
    max_bytes: usize,
    guard: ReaderGuard,
) -> Receiver<Pipe> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _guard = guard;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut overflow = false;
        let mut io_error = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    io_error = true;
                    break;
                }
                Ok(n) => {
                    let Some(part) = chunk.get(..n) else {
                        io_error = true;
                        break;
                    };
                    buf.extend_from_slice(part);
                    if buf.len() > max_bytes {
                        overflow = true;
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Pipe {
            buf,
            overflow,
            io_error,
        });
    });
    rx
}

/// 子とその子孫をまとめて終了させる手段（Windows は Job Object。REPAIR-5）。
///
/// [`ProcessTree::prepare`] で起動前の `Command` を設定し、起動直後に [`ProcessTree::attach`] で
/// 子を Job に入れてから再開する。停止状態のまま割り当てるので、割り当て前に子孫が生まれて Job の
/// 外へ漏れる競合はない。値を破棄すると Job のハンドルが閉じ、残っている子孫もすべて終了する
/// （`run_capture` はどの経路で戻っても子孫を残さない）。
#[cfg(windows)]
struct ProcessTree(crate::sys::Job);

#[cfg(windows)]
impl ProcessTree {
    /// 初期スレッドを停止状態で作るよう `cmd` を設定する。
    fn prepare(cmd: &mut Command) {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(crate::sys::CREATE_SUSPENDED);
    }

    /// 停止状態の `child` を Job に割り当ててから再開する。失敗時は Job を破棄する（割り当て済みなら
    /// 子も終了する）ので、呼び出し側は子を kill・回収するだけでよい。
    fn attach(child: &Child) -> std::io::Result<Self> {
        let job = crate::sys::Job::new_kill_on_close()?;
        job.assign(child)?;
        if crate::sys::resume_suspended_threads(child)? == 0 {
            return Err(std::io::Error::other(
                "no thread of the suspended child was resumed",
            ));
        }
        Ok(Self(job))
    }

    /// Job に属する子と子孫をすべて終了させる。失敗は無視する（回収は `kill_and_reap` が期限付きで
    /// 行い、残留スレッドは `MAX_LIVE_READERS` で抑える）。
    fn kill(&self) {
        let _ = self.0.terminate(1);
    }
}

/// Windows 以外では子孫をまとめる手段を持たない（`wsl.exe` は Windows にしかなく、本経路は
/// 3 OS でのテスト用。子だけを kill する）。
#[cfg(not(windows))]
struct ProcessTree;

#[cfg(not(windows))]
impl ProcessTree {
    fn prepare(_cmd: &mut Command) {}

    fn attach(_child: &Child) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn kill(&self) {}
}

/// 子を kill して `REAP_TIMEOUT` 以内に回収する。kill の失敗は無視せず、回収できるまで待つ
/// （既に終了していれば kill は失敗しうるが、その場合は回収に成功する）。
/// 回収できなければ `INTERNAL`（無期限に `wait()` しない。REPAIR-5）。
/// `tree` があれば先に子孫ごと終了させる（親が終了済みでもパイプを握る子孫を残さない）。
fn kill_and_reap(child: &mut Child, tree: Option<&ProcessTree>) -> Result<(), Wsl2Error> {
    if let Some(tree) = tree {
        tree.kill();
    }
    let kill_result = child.kill();
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(_) => {
                return Err(Wsl2Error::new(
                    Wsl2ErrorCode::Internal,
                    "failed to reap wsl.exe after kill",
                ));
            }
        }
        if Instant::now() >= deadline {
            let msg = if kill_result.is_err() {
                "failed to kill wsl.exe; the process was not reaped"
            } else {
                "wsl.exe was not reaped before the reap deadline"
            };
            return Err(Wsl2Error::new(Wsl2ErrorCode::Internal, msg));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// 子を kill・回収したうえで `err` を返す。回収に失敗したときはそのエラーを優先する。
fn abort_with(child: &mut Child, tree: Option<&ProcessTree>, err: Wsl2Error) -> Wsl2Error {
    match kill_and_reap(child, tree) {
        Ok(()) => err,
        Err(reap_err) => reap_err,
    }
}

fn spawn_error(e: &std::io::Error) -> Wsl2Error {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => Wsl2Error::new(
            Wsl2ErrorCode::NotFound,
            format!(
                "wsl.exe was not found. WSL is not installed. {}",
                super::ENABLE_GUIDE
            ),
        ),
        ErrorKind::PermissionDenied => Wsl2Error::new(
            Wsl2ErrorCode::PermissionDenied,
            "permission denied while starting wsl.exe",
        ),
        _ => Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to start wsl.exe"),
    }
}

/// `program` を固定の `args`・追加環境変数 `envs` で起動し、`timeout` 以内の出力を回収する。
///
/// stdin は null、stdout / stderr はパイプ。期限切れは `TIMEOUT`、出力が `max_bytes` を超えたら
/// `RESOURCE_EXHAUSTED`（どちらも子を kill して回収済み）。
pub(super) fn run_capture(
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> Result<Captured, Wsl2Error> {
    run_capture_in(&LIVE_READERS, program, args, envs, timeout, max_bytes)
}

/// [`run_capture`] の本体。読み取りスレッドの生存数を `readers` で数える（テストは専用のカウンタを
/// 渡し、並行する他のテストに影響されずにスレッドの終了を確認する）。
fn run_capture_in(
    readers: &'static AtomicUsize,
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> Result<Captured, Wsl2Error> {
    let deadline = Instant::now() + timeout;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    ProcessTree::prepare(&mut cmd);
    let (Some(out_guard), Some(err_guard)) = (
        ReaderGuard::acquire_in(readers, MAX_LIVE_READERS),
        ReaderGuard::acquire_in(readers, MAX_LIVE_READERS),
    ) else {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::ResourceExhausted,
            "too many outstanding wsl.exe output readers",
        ));
    };
    let mut child = cmd.spawn().map_err(|e| spawn_error(&e))?;
    let tree = match ProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(_) => {
            return Err(abort_with(
                &mut child,
                None,
                Wsl2Error::new(
                    Wsl2ErrorCode::Internal,
                    "failed to place wsl.exe in a job object",
                ),
            ));
        }
    };
    let tree = Some(&tree);
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(abort_with(
            &mut child,
            tree,
            Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to capture output pipes"),
        ));
    };
    let out_rx = spawn_reader(out_pipe, max_bytes, out_guard);
    let err_rx = spawn_reader(err_pipe, max_bytes, err_guard);

    let mut out: Option<Pipe> = None;
    let mut err: Option<Pipe> = None;
    let mut status = None;
    loop {
        if out.is_none() {
            out = out_rx.try_recv().ok();
        }
        if err.is_none() {
            err = err_rx.try_recv().ok();
        }
        if out.as_ref().is_some_and(|o| o.io_error) || err.as_ref().is_some_and(|e| e.io_error) {
            return Err(abort_with(
                &mut child,
                tree,
                Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to read wsl.exe output"),
            ));
        }
        if out.as_ref().is_some_and(|o| o.overflow) || err.as_ref().is_some_and(|e| e.overflow) {
            return Err(abort_with(
                &mut child,
                tree,
                Wsl2Error::new(
                    Wsl2ErrorCode::ResourceExhausted,
                    "wsl.exe output exceeded the size limit",
                ),
            ));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(s) => status = s,
                Err(_) => {
                    return Err(abort_with(
                        &mut child,
                        tree,
                        Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to wait for wsl.exe"),
                    ));
                }
            }
        }
        if let (Some(s), Some(o), Some(e)) = (status, out.as_ref(), err.as_ref()) {
            return Ok(Captured {
                success: s.success(),
                code: s.code(),
                stdout: o.buf.clone(),
                stderr: e.buf.clone(),
            });
        }
        if Instant::now() >= deadline {
            return Err(abort_with(
                &mut child,
                tree,
                Wsl2Error::new(
                    Wsl2ErrorCode::Timeout,
                    "wsl.exe did not finish before the deadline",
                ),
            ));
        }
        // 短い間隔のポーリング。期限は上のチェックで保証される。
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV_MODE: &str = "FANDHE_WSL2_TEST_HELPER";
    /// 読み取りスレッド単体のテスト用カウンタ（本番の `LIVE_READERS` と分ける）。
    static TEST_READERS: AtomicUsize = AtomicUsize::new(0);
    const HELPER: &str = "wsl2::run::tests::helper";

    /// 自己再実行される子側。環境変数がなければ即座に成功する（通常のテスト実行では何もしない）。
    #[test]
    fn helper() {
        match std::env::var(ENV_MODE).as_deref() {
            Ok("sleep") => thread::sleep(Duration::from_secs(60)),
            Ok("flood") => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&vec![b'x'; 100_000]);
            }
            // 孫（`sleep`）を起動して即座に終了する。孫は stdout / stderr（`run_capture` のパイプ）を
            // 継承して握り続けるので、親の終了後もパイプは EOF にならない。
            Ok("orphan") => {
                let exe = std::env::current_exe().unwrap();
                let grandchild = Command::new(exe)
                    .args(["--exact", HELPER, "--nocapture", "--test-threads=1"])
                    .env(ENV_MODE, "sleep")
                    .stdin(Stdio::null())
                    .spawn();
                // 孫の回収は行わずに終了する（親が先に終了する状況を作るため）。
                std::mem::forget(grandchild);
            }
            _ => {}
        }
    }

    fn run_helper(mode: &str, timeout: Duration, max: usize) -> Result<Captured, Wsl2Error> {
        let exe = std::env::current_exe().unwrap();
        run_capture(
            &exe,
            &["--exact", HELPER, "--nocapture", "--test-threads=1"],
            &[(ENV_MODE, mode)],
            timeout,
            max,
        )
    }

    /// REPAIR-5: 期限を過ぎたら TIMEOUT で戻り、子は kill・回収される。
    #[test]
    fn timeout_kills_child() {
        let start = Instant::now();
        let e = run_helper("sleep", Duration::from_millis(500), 65536).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    /// REPAIR-5: 親（`wsl.exe` 相当）が先に終了し、パイプを継承した孫が残っても、期限切れで Job ごと
    /// 終了させて読み取りスレッドを有限時間で終わらせる（PID 指定の `taskkill /T` では終了済みの
    /// 親から孫を辿れず、スレッドが残っていた）。Job Object は Windows の機構なので Windows で検証する。
    #[cfg(windows)]
    #[test]
    fn orphaned_grandchild_is_terminated_with_job() {
        static READERS: AtomicUsize = AtomicUsize::new(0);
        let exe = std::env::current_exe().unwrap();
        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        let e = run_capture_in(
            &READERS,
            &exe,
            &["--exact", HELPER, "--nocapture", "--test-threads=1"],
            &[(ENV_MODE, "orphan")],
            timeout,
            65536,
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert!(start.elapsed() < timeout + REAP_TIMEOUT + Duration::from_secs(10));
        // 孫が終了すれば両パイプが EOF になり、2 本の読み取りスレッドが終わってカウントが 0 に戻る。
        // 孫は 60 秒眠るので、Job で終了させなければ以下の 10 秒以内に 0 にはならない。
        let wait_deadline = Instant::now() + Duration::from_secs(10);
        while READERS.load(Ordering::SeqCst) != 0 && Instant::now() < wait_deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(READERS.load(Ordering::SeqCst), 0);
    }

    /// REPAIR-5: 出力が上限を超えたら RESOURCE_EXHAUSTED。
    #[test]
    fn output_limit_enforced() {
        let e = run_helper("flood", Duration::from_secs(30), 1024).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::ResourceExhausted);
    }

    /// 正常終了では終了コードと stdout を回収する。
    #[test]
    fn captures_success() {
        let o = run_helper("none", Duration::from_secs(30), 65536).unwrap();
        assert!(o.success);
        assert_eq!(o.code, Some(0));
        assert!(!o.stdout.is_empty());
    }

    /// 読み取りエラーは EOF と区別され、途中出力と一緒に io_error として報告される。
    #[test]
    fn reader_reports_io_error() {
        struct Failing(bool);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("boom"));
                }
                self.0 = true;
                buf[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
        let p = spawn_reader(
            Failing(false),
            1024,
            ReaderGuard::acquire_in(&TEST_READERS, MAX_LIVE_READERS).unwrap(),
        )
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
        assert!(p.io_error);
        assert!(!p.overflow);
        assert_eq!(p.buf, b"abc");
    }

    /// 正常な EOF は io_error にならない。
    #[test]
    fn reader_eof_is_not_error() {
        let p = spawn_reader(
            &b"hello"[..],
            1024,
            ReaderGuard::acquire_in(&TEST_READERS, MAX_LIVE_READERS).unwrap(),
        )
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
        assert!(!p.io_error);
        assert_eq!(p.buf, b"hello");
    }

    /// REPAIR-5: ガードは上限で取得に失敗し、解放で枠が戻る。
    #[test]
    fn reader_guard_is_bounded() {
        static LOCAL: AtomicUsize = AtomicUsize::new(0);
        let g1 = ReaderGuard::acquire_in(&LOCAL, 2).unwrap();
        let g2 = ReaderGuard::acquire_in(&LOCAL, 2).unwrap();
        assert!(ReaderGuard::acquire_in(&LOCAL, 2).is_none());
        drop(g1);
        assert_eq!(LOCAL.load(Ordering::SeqCst), 1);
        let g3 = ReaderGuard::acquire_in(&LOCAL, 2).unwrap();
        drop((g2, g3));
        assert_eq!(LOCAL.load(Ordering::SeqCst), 0);
    }

    /// WIN-1: 存在しないパスは NOT_FOUND。
    #[test]
    fn missing_program() {
        let e = run_capture(
            Path::new("/nonexistent/fandhe/none"),
            &[],
            &[],
            Duration::from_secs(1),
            10,
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::NotFound);
    }
}
