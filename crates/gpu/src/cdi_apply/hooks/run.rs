//! `createContainer` フックの前提状態ゲートと実行（Linux 限定。TASK-127.3・GPU-2）。
//!
//! 呼び出し元は core の pre-pivot 段（配線は #2774）。検証済みフック（`validate_create_container_hooks`）と
//! `verify_hook_stage` の証跡を受け、各フックを直列に host 側プロセスとして起動する。新しい `unsafe` は無く、
//! std の `Command`・`fs` だけで実装する。

use super::{CDI_HOOK_MAX_MOUNTINFO_BYTES, CdiCreateContainerHook, check_hook_stage_mountinfo};
use crate::cdi_apply::{CdiApplyError, CdiApplyErrorCode as Code};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 報告に載せる stderr の先頭最大バイト数。
pub const CDI_HOOK_STDERR_CAP: usize = 8 * 1024;
/// stdin へ渡す state JSON の最大バイト数（pipe 容量内に収め書き込みで塞がらないため）。
const MAX_STATE_BYTES: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const OCI_VERSION: &str = "1.2.0";

const fn e(code: Code, message: &'static str) -> CdiApplyError {
    CdiApplyError::new(code, message)
}

/// 実行順序の前提を満たしたことの証跡。[`verify_hook_stage`] だけが発行する（構築子は非公開）。
#[derive(Debug)]
pub struct CdiHookStage {
    rootfs: PathBuf,
}

impl CdiHookStage {
    /// 検証した rootfs。
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[cfg(test)]
    pub(crate) fn for_test(rootfs: &Path) -> Self {
        Self {
            rootfs: rootfs.to_path_buf(),
        }
    }
}

/// 実際の `/proc/self/mountinfo` と `/` で前提（自己 bind 済み・proc 済み・pivot 前）を検証し、証跡を返す。
/// 逸脱時は `FailedPrecondition`（GPU-2）。
pub fn verify_hook_stage(rootfs: &Path) -> Result<CdiHookStage, CdiApplyError> {
    let canon = fs::canonicalize(rootfs).map_err(|_| {
        e(
            Code::InvalidArgument,
            "rootfs must be an existing absolute path",
        )
    })?;
    if !rootfs.is_absolute() || canon != rootfs {
        return Err(e(
            Code::InvalidArgument,
            "rootfs must be a canonical absolute path",
        ));
    }
    let (Ok(r), Ok(host)) = (fs::metadata(&canon), fs::metadata("/")) else {
        return Err(e(Code::Internal, "failed to stat rootfs"));
    };
    if (r.dev(), r.ino()) == (host.dev(), host.ino()) {
        return Err(e(
            Code::FailedPrecondition,
            "rootfs is the host root (already pivoted or not separated)",
        ));
    }
    let mut text = String::new();
    File::open("/proc/self/mountinfo")
        .and_then(|f| {
            f.take(CDI_HOOK_MAX_MOUNTINFO_BYTES as u64 + 1)
                .read_to_string(&mut text)
        })
        .map_err(|_| e(Code::Internal, "failed to read mountinfo"))?;
    let root = std::str::from_utf8(canon.as_os_str().as_bytes())
        .map_err(|_| e(Code::InvalidArgument, "rootfs is not valid UTF-8"))?;
    check_hook_stage_mountinfo(root, &text)?;
    Ok(CdiHookStage { rootfs: canon })
}

/// フックへ渡す OCI state の材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiHookState {
    id: String,
    pid: i32,
}

impl CdiHookState {
    /// `id` は `[A-Za-z0-9_.-]` の 1〜256 バイト、`pid` は正。`CLONE_NEWPID` 内の `getpid()` は 1 になるため、
    /// 呼び出し元がホストから見た pid を与える（PoC-14 の記録）。
    pub fn new(id: &str, pid: i32) -> Result<Self, CdiApplyError> {
        let ok = !id.is_empty()
            && id.len() <= 256
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        if !ok || pid <= 0 {
            return Err(e(Code::InvalidArgument, "invalid hook state id or pid"));
        }
        Ok(Self {
            id: id.to_string(),
            pid,
        })
    }
}

/// 1 フックの結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiHookReport {
    /// 入力での添字。
    pub index: usize,
    /// 終了コード（0 のみ成功として報告に残る）。
    pub exit_code: i32,
    /// 実行時間。
    pub elapsed: Duration,
    /// stderr の先頭（最大 [`CDI_HOOK_STDERR_CAP`] バイト。UTF-8 は損失変換）。
    pub stderr: String,
}

/// フック失敗。何件目かと、診断用の stderr の先頭を持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiHookError {
    /// 失敗したフックの添字。
    pub index: usize,
    /// 分類と固定文言。
    pub error: CdiApplyError,
    /// stderr の先頭（取れた場合）。
    pub stderr: String,
    /// 失敗までに成功したフックの報告。
    pub completed: Vec<CdiHookReport>,
}

impl std::fmt::Display for CdiHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hook {}: {}", self.index, self.error)
    }
}

impl std::error::Error for CdiHookError {}

/// 全フックの結果。
pub type CdiHookResult = Result<Vec<CdiHookReport>, CdiHookError>;

/// JSON 文字列リテラルとしてエスケープする（`"`・`\`・制御文字）。
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn config_json(rootfs: &str) -> String {
    format!(
        "{{\"ociVersion\":\"{OCI_VERSION}\",\"root\":{{\"path\":{}}}}}",
        json_str(rootfs)
    )
}

fn state_json(st: &CdiHookState, bundle: &str) -> String {
    format!(
        "{{\"ociVersion\":\"{OCI_VERSION}\",\"id\":{},\"status\":\"creating\",\"pid\":{},\"bundle\":{}}}",
        json_str(&st.id),
        st.pid,
        json_str(bundle)
    )
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// フック 1 件分の最小 bundle（`config.json` のみ）。全経路で削除する。
struct Bundle {
    dir: PathBuf,
    removed: bool,
}

impl Bundle {
    fn create(work_dir: &Path, rootfs: &str) -> Result<Self, CdiApplyError> {
        let err = || e(Code::Internal, "failed to prepare hook bundle");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let name = format!(
            "fandhe-cdi-hook-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = work_dir.join(name);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| err())?;
        let mut b = Self {
            dir,
            removed: false,
        };
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(b.dir.join("config.json"))
            .map_err(|_| err())?;
        f.write_all(config_json(rootfs).as_bytes())
            .map_err(|_| err())?;
        drop(f);
        b.removed = false;
        Ok(b)
    }

    fn remove(&mut self) -> std::io::Result<()> {
        self.removed = true;
        fs::remove_dir_all(&self.dir)
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        if !self.removed {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn map_io(err: &std::io::Error) -> CdiApplyError {
    let r = match err.kind() {
        ErrorKind::NotFound => e(Code::NotFound, "hook executable not found"),
        ErrorKind::PermissionDenied => e(Code::PermissionDenied, "hook executable not permitted"),
        _ => e(Code::Internal, "failed to start hook"),
    };
    match err.raw_os_error() {
        Some(n) => r.with_errno(n),
        None => r,
    }
}

/// 実行ファイルの検査（通常ファイル・実行ビット・group / other 書き込み不可。A08）。
fn check_executable(path: &str) -> Result<(), CdiApplyError> {
    let m = fs::metadata(path).map_err(|err| map_io(&err))?;
    let mode = m.permissions().mode();
    if !m.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(e(
            Code::PermissionDenied,
            "hook executable is not a safe regular file",
        ));
    }
    Ok(())
}

fn read_head(path: &Path) -> String {
    let mut buf = Vec::new();
    if let Ok(f) = File::open(path) {
        let _ = f.take(CDI_HOOK_STDERR_CAP as u64).read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 1 フックを実行する。失敗時は (エラー, stderr 先頭)。
fn run_one(
    stage: &CdiHookStage,
    st: &CdiHookState,
    h: &CdiCreateContainerHook,
    work_dir: &Path,
    index: usize,
) -> Result<CdiHookReport, (CdiApplyError, String)> {
    let bare = |x| (x, String::new());
    check_executable(h.path()).map_err(bare)?;
    let rootfs = std::str::from_utf8(stage.rootfs.as_os_str().as_bytes())
        .map_err(|_| bare(e(Code::InvalidArgument, "rootfs is not valid UTF-8")))?;
    let mut bundle = Bundle::create(work_dir, rootfs).map_err(bare)?;
    let bundle_str = std::str::from_utf8(bundle.dir.as_os_str().as_bytes())
        .map_err(|_| bare(e(Code::InvalidArgument, "work_dir is not valid UTF-8")))?
        .to_string();
    let state = state_json(st, &bundle_str);
    if state.len() > MAX_STATE_BYTES {
        return Err(bare(e(Code::ResourceExhausted, "hook state is too large")));
    }
    let err_path = bundle.dir.join("stderr");
    let err_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&err_path)
        .map_err(|_| bare(e(Code::Internal, "failed to prepare hook bundle")))?;

    let (arg0, rest) = h
        .args
        .split_first()
        .ok_or_else(|| bare(e(Code::InvalidArgument, "CDI hook args must not be empty")))?;
    let mut cmd = Command::new(&h.path);
    cmd.arg0(arg0)
        .args(rest)
        .env_clear()
        .envs(h.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err_file));
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|err| bare(map_io(&err)))?;
    drop(cmd);

    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(state.as_bytes()) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(bare(e(Code::Internal, "failed to write hook state")));
            }
        }
    }

    let deadline = Duration::from_secs(h.timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if started.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let tail = read_head(&err_path);
                    let _ = bundle.remove();
                    return Err((e(Code::Timeout, "hook timed out"), tail));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(bare(e(Code::Internal, "failed to wait for hook")));
            }
        }
    };
    let elapsed = started.elapsed();
    let stderr = read_head(&err_path);
    if bundle.remove().is_err() {
        return Err((e(Code::Internal, "failed to remove hook bundle"), stderr));
    }
    match status.code() {
        Some(0) => Ok(CdiHookReport {
            index,
            exit_code: 0,
            elapsed,
            stderr,
        }),
        Some(_) => Err((
            e(Code::FailedPrecondition, "hook exited with failure"),
            stderr,
        )),
        None => Err((
            e(Code::FailedPrecondition, "hook was terminated by a signal"),
            stderr,
        )),
    }
}

/// 検証済みフックを集計順に直列実行する。最初の失敗で中止し、後続は起動しない（fail-closed）。
/// `work_dir` は bundle を作る既存の絶対パスのディレクトリ（呼び出し元の一時領域。状態ルート配下を推奨）。
/// ホストの環境変数は継承せず、フック指定の env だけを渡す。
pub fn run_create_container_hooks(
    stage: &CdiHookStage,
    hooks: &[CdiCreateContainerHook],
    state: &CdiHookState,
    work_dir: &Path,
) -> CdiHookResult {
    let mut done = Vec::with_capacity(hooks.len());
    if !work_dir.is_absolute() {
        return Err(CdiHookError {
            index: 0,
            error: e(Code::InvalidArgument, "work_dir must be an absolute path"),
            stderr: String::new(),
            completed: done,
        });
    }
    for (index, h) in hooks.iter().enumerate() {
        match run_one(stage, state, h, work_dir, index) {
            Ok(r) => done.push(r),
            Err((error, stderr)) => {
                return Err(CdiHookError {
                    index,
                    error,
                    stderr,
                    completed: done,
                });
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdi_apply::hooks::validate_create_container_hooks;
    use crate::cdi_spec::{EnvList, Hook};

    /// テスト用の一時ディレクトリ（`std::env::temp_dir` 配下に一意名。終了時に削除）。
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fandhe-gpu-hooks-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn script(&self, name: &str, body: &str) -> String {
            let p = self.0.join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            p.to_str().unwrap().to_string()
        }
        fn work(&self) -> PathBuf {
            let w = self.0.join("work");
            let _ = fs::DirBuilder::new().mode(0o700).create(&w);
            w
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mk(path: &str, args: &[&str], env: &[&str], timeout: Option<i64>) -> Hook {
        Hook {
            hook_name: "createContainer".into(),
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: EnvList::from_entries(env.iter().map(|s| s.to_string()).collect()),
            timeout,
        }
    }

    fn state() -> CdiHookState {
        CdiHookState::new("c1", 4242).unwrap()
    }

    /// GPU-2: argv[0]・引数・stdin の state・bundle の config.json・env を具体値で照合する。
    #[test]
    fn hook_receives_argv_state_and_env() {
        let t = Tmp::new("ok");
        let out = t.0.join("out.txt");
        let sh = t.script(
            "h.sh",
            &format!(
                "echo \"$1|$2\" > {o}\ncat >> {o}\necho >> {o}\ncat \"$(sed -n 's/.*\"bundle\":\"\\([^\"]*\\)\".*/\\1/p' {o} | head -1)/config.json\" >> {o}\nenv > {e}",
                o = out.display(),
                e = t.0.join("env.txt").display()
            ),
        );
        let hooks = validate_create_container_hooks(&[mk(
            &sh,
            &["nvidia-cdi-hook", "create-symlinks", "--x"],
            &["FOO=bar baz"],
            Some(10),
        )])
        .unwrap();
        let rootfs = t.0.join("rootfs");
        let stage = CdiHookStage::for_test(&rootfs);
        let reports = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].exit_code, 0);
        let got = fs::read_to_string(&out).unwrap();
        let mut lines = got.lines();
        assert_eq!(lines.next(), Some("create-symlinks|--x"));
        let st_line = lines.next().unwrap();
        assert!(st_line.starts_with(
            "{\"ociVersion\":\"1.2.0\",\"id\":\"c1\",\"status\":\"creating\",\"pid\":4242,\"bundle\":\""
        ));
        assert!(got.contains(&format!(
            "{{\"ociVersion\":\"1.2.0\",\"root\":{{\"path\":\"{}\"}}}}",
            rootfs.display()
        )));
        let mut envs: Vec<String> = fs::read_to_string(t.0.join("env.txt"))
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        envs.sort();
        // ホストの環境変数（PATH 等）を継承しない。sh が足す PWD 等を除き、指定分が入っている。
        assert!(envs.contains(&"FOO=bar baz".to_string()), "{envs:?}");
        assert!(!envs.iter().any(|l| l.starts_with("PATH=")), "{envs:?}");
        assert!(!envs.iter().any(|l| l.starts_with("HOME=")), "{envs:?}");
        // bundle は全経路で消える。
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2: `args[0]` が argv[0] になり、引数が重複しない（stderr 経由で /proc の cmdline を観測する）。
    #[test]
    fn args0_becomes_argv0() {
        let t = Tmp::new("argv0");
        let hooks = validate_create_container_hooks(&[mk(
            "/bin/sh",
            &["custom0", "-c", "tr '\\0' '|' < /proc/$$/cmdline >&2"],
            &[],
            None,
        )])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let r = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap();
        assert_eq!(
            r[0].stderr,
            "custom0|-c|tr '\\0' '|' < /proc/$$/cmdline >&2|"
        );
    }

    /// GPU-2: 最初の失敗で中止し、後続のフックは起動しない。
    #[test]
    fn stops_at_first_failure() {
        let t = Tmp::new("fail");
        let m1 = t.0.join("m1");
        let m3 = t.0.join("m3");
        let h1 = t.script("h1.sh", &format!("touch {}", m1.display()));
        let h2 = t.script("h2.sh", "echo boom >&2; exit 1");
        let h3 = t.script("h3.sh", &format!("touch {}", m3.display()));
        let hooks = validate_create_container_hooks(&[
            mk(&h1, &["h1"], &[], None),
            mk(&h2, &["h2"], &[], None),
            mk(&h3, &["h3"], &[], None),
        ])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(err.error.message(), "hook exited with failure");
        assert_eq!(err.stderr, "boom\n");
        assert_eq!(err.completed.len(), 1);
        assert!(m1.exists());
        assert!(!m3.exists());
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2・REPAIR-5: timeout で kill され Timeout になり、bundle も消える。
    #[test]
    fn times_out() {
        let t = Tmp::new("to");
        let sh = t.script("slow.sh", "exec sleep 30");
        let hooks = validate_create_container_hooks(&[mk(&sh, &["slow"], &[], Some(1))]).unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let start = Instant::now();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::Timeout);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2: 存在しない実行ファイルは NotFound、group 書き込み可は PermissionDenied。
    #[test]
    fn executable_checks() {
        let t = Tmp::new("exe");
        let stage = CdiHookStage::for_test(&t.0);
        let missing = t.0.join("nope").to_str().unwrap().to_string();
        let hooks = validate_create_container_hooks(&[mk(&missing, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::NotFound);
        let sh = t.script("w.sh", "exit 0");
        fs::set_permissions(&sh, fs::Permissions::from_mode(0o775)).unwrap();
        let hooks = validate_create_container_hooks(&[mk(&sh, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::PermissionDenied);
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2: 前提を満たさない状態ではゲートが失敗し、フックは起動されない。
    #[test]
    fn gate_failure_never_runs_hooks() {
        let t = Tmp::new("gate");
        let marker = t.0.join("ran");
        let sh = t.script("h.sh", &format!("touch {}", marker.display()));
        let hooks = validate_create_container_hooks(&[mk(&sh, &["h"], &[], None)]).unwrap();
        let canon = fs::canonicalize(&t.0).unwrap();
        let res = verify_hook_stage(&canon).and_then(|s| {
            run_create_container_hooks(&s, &hooks, &state(), &t.work()).map_err(|x| x.error)
        });
        assert_eq!(res.unwrap_err().code(), Code::FailedPrecondition);
        assert!(!marker.exists());
        assert_eq!(
            verify_hook_stage(Path::new("/")).unwrap_err().code(),
            Code::FailedPrecondition
        );
    }

    /// JSON エスケープを具体文字列で照合する。
    #[test]
    fn json_escape() {
        assert_eq!(
            json_str("a\"b\\c\nd\u{1}"),
            "\"a\\\"b\\\\c\\u000ad\\u0001\""
        );
    }

    /// state の id・pid の検証。
    #[test]
    fn state_validation() {
        assert!(CdiHookState::new("a_b.c-1", 1).is_ok());
        for (id, pid) in [("", 1), ("a b", 1), ("a\"b", 1), ("ok", 0), ("ok", -3)] {
            assert_eq!(
                CdiHookState::new(id, pid).unwrap_err().code(),
                Code::InvalidArgument,
                "{id:?} {pid}"
            );
        }
    }
}
