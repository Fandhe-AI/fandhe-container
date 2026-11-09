//! pod 保持役プロセスの本体（Linux のみ。CRI-2・CORE-1・SEC-5・REPAIR-5・#2874。
//! 設計は `docs/design/pod-namespace-holder.md`）。
//!
//! bin の main が第 1 引数 `pod-holder` で [`run`] へ振り分ける。core の
//! `establish_pod_namespaces`（H1・#2870）で user（写像つき）・ipc・net を作り、READY を返した後は待つだけ。
//!
//! # 手順（案 (a): `unshare(USER)` の後に自身を再 exec して non-dumpable を保つ）
//! **段 1**（argv は `pod-holder` のみ）: fd 3 以上を閉じる → stdio と SIGTERM の検査 → `PR_SET_DUMPABLE 0` →
//! 権限モデルを `start` と同じ規則で決める → `/proc/self/exe` を開く → namespace を確立 → 素性を引数に載せて
//! 開いた fd を `execveat` で再 exec。**段 2**（`pod-holder --stage2 <6 個の 10 進>`）: 直ちに `PR_SET_DUMPABLE 0` →
//! fd を再度閉じる → 引数・dumpable・素性・`uid_map`・子の不在を照合 → capability を全て落とす → READY を書く →
//! stdin を待つ（EOF で 0、予期しない入力で 1。SIGTERM は既定の動作で終わる）。PDEATHSIG は使わない（#2376 と同じ理由）。
//!
//! # なぜ再 exec か
//! `/proc/<pid>/ns/*` の open は `ptrace_may_access` を通り、non-dumpable のプロセスには `mm->user_ns` での
//! `CAP_SYS_PTRACE` が要る。`mm->user_ns` は exec 時の userns で決まるので、再 exec すると pod の userns になり、
//! その作成者（親 ns の同 uid）は全 capability を持って開ける。一方 pod の userns の中の capability を持たない
//! プロセスは開けない。根拠と残余は設計文書の脚注を参照。
//!
//! # 契約
//! 単一スレッドで動く（`CLONE_NEWUSER` の条件）。エラー文言は固定の英文でパス・pid・errno・写像の値を含めない
//! （REPAIR-4）。失敗は READY の前に限り、ERROR フレーム・stderr の 1 行・終了コード 1 で返す。
//! 引数の不正は終了コード 2。

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_core::oci_runtime::establish_pod_namespaces;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::frame::{NsId, PodHolderFrame, PodHolderReady};
use crate::sys;

/// 段 2 を示す固定の第 2 引数。
const STAGE2: &str = "--stage2";
/// 再 exec の `argv[0]`（固定。パス文字列を使わない）。
const HOLDER_ARG0: &str = "fandhe-container-supervisor";
/// `/proc/self/status` を読む上限（バイト）。
const STATUS_LIMIT: u64 = 64 * 1024;
/// 失敗行の stderr 書き込みを待つ上限（読み手が止まっていても終わる。REPAIR-5）。
const FAIL_LINE_TIMEOUT: Duration = Duration::from_millis(500);
/// SIGTERM のビット（`SigIgn`・`SigBlk` は `1 << (signo - 1)`）。
const SIGTERM_MASK: u64 = 1 << 14;
/// 初期 user namespace の `uid_map` の 1 行目（`inside outside count`）。
const INITIAL_MAP: [&str; 3] = ["0", "0", "4294967295"];

/// 失敗の分類と固定の英文。
struct Fail {
    code: ErrorCode,
    message: &'static str,
}

impl Fail {
    const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

fn from_trait(e: &TraitError, fallback: &'static str) -> Fail {
    // 文言は core の固定英文だが、本プロセスの出力は常に固定文言に揃えるため分類だけを引き継ぐ。
    Fail::new(e.code(), fallback)
}

/// 保持役の入口。`args` は `pod-holder` の後ろの引数。
pub(super) fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.collect();
    let result = match args.first() {
        None => stage1(),
        Some(first) if first.as_bytes() == STAGE2.as_bytes() => {
            stage2(args.get(1..).unwrap_or(&[]))
        }
        Some(_) => return usage_error("pod-holder takes no arguments"),
    };
    match result {
        // 成功は戻らない（段 1 は exec、段 2 は待ちの後に `Ok` を返す）。
        Ok(()) => ExitCode::SUCCESS,
        Err(StageEnd::Usage(m)) => usage_error(m),
        Err(StageEnd::Fail(f)) => fail(&f),
        Err(StageEnd::Unexpected(m)) => {
            // READY の後なので ERROR フレームは出さない(受信側は READY で解釈を終えている)。
            stderr_line(ErrorCode::FailedPrecondition, m);
            ExitCode::from(1)
        }
    }
}

enum StageEnd {
    Usage(&'static str),
    Fail(Fail),
    /// READY の後の予期しない入力（ERROR フレームは出さない）。
    Unexpected(&'static str),
}

impl From<Fail> for StageEnd {
    fn from(f: Fail) -> Self {
        StageEnd::Fail(f)
    }
}

fn usage_error(message: &'static str) -> ExitCode {
    stderr_line(ErrorCode::InvalidArgument, message);
    ExitCode::from(2)
}

fn fail(f: &Fail) -> ExitCode {
    // READY の前だけ呼ばれる。ERROR フレームは best effort（読み手がいなければ書けない）。
    if let Ok(owned) = std::io::stdout().as_fd().try_clone_to_owned() {
        let mut out = File::from(owned);
        let _ = out.write_all(PodHolderFrame::error(f.code).as_bytes());
    }
    stderr_line(f.code, f.message);
    ExitCode::from(1)
}

/// 失敗行を stderr へ出す。読み手が止まって pipe が満杯でも終了を妨げないよう別スレッドで書き、期限で見切る
/// （失敗経路でだけ呼ぶ。`CLONE_NEWUSER` の後なので単一スレッド前提を壊さない）。
fn stderr_line(code: ErrorCode, message: &str) {
    let line = format!("error code={} message={message}\n", code.as_str());
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let spawned = std::thread::Builder::new().spawn(move || {
        let _ = std::io::stderr().write_all(line.as_bytes());
        let _ = tx.send(());
    });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(FAIL_LINE_TIMEOUT);
    }
}

// ---- 純関数（ユニット試験の対象） ----

/// `/proc/self/status` の `SigIgn`・`SigBlk` に SIGTERM が含まれていないかを判定する。欄の欠落・壊れた値は `Err`。
pub(super) fn sigterm_is_default(status: &str) -> Result<bool, &'static str> {
    let mut seen = 0u8;
    let mut clear = true;
    for line in status.lines() {
        let (v, bit) = match line.split_once(':') {
            Some(("SigIgn", v)) => (v, 1u8),
            Some(("SigBlk", v)) => (v, 2u8),
            _ => continue,
        };
        let mask = u64::from_str_radix(v.trim(), 16).map_err(|_| "malformed signal mask")?;
        seen |= bit;
        clear &= mask & SIGTERM_MASK == 0;
    }
    if seen != 3 {
        return Err("missing signal mask field");
    }
    Ok(clear)
}

/// 段 2 の引数（6 個の 10 進 u64: user・ipc・net の dev, ino）を解析する。個数・形式が不正なら `None`。
pub(super) fn parse_stage2_args(args: &[OsString]) -> Option<[u64; 6]> {
    if args.len() != 6 {
        return None;
    }
    let mut out = [0u64; 6];
    for (slot, a) in out.iter_mut().zip(args) {
        let s = std::str::from_utf8(a.as_bytes()).ok()?;
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = s.parse().ok()?;
    }
    Some(out)
}

/// `uid_map` が初期 user namespace の恒等写像（1 行目が `0 0 4294967295`）か。
pub(super) fn is_initial_uid_map(text: &str) -> bool {
    text.lines()
        .next()
        .is_some_and(|l| l.split_whitespace().eq(INITIAL_MAP))
}

// ---- 共通の検査 ----

fn read_limited(path: &str) -> Result<String, Fail> {
    let mut text = String::new();
    File::open(path)
        .and_then(|f| f.take(STATUS_LIMIT + 1).read_to_string(&mut text))
        .map_err(|_| {
            Fail::new(
                ErrorCode::FailedPrecondition,
                "process status is unreadable",
            )
        })?;
    if text.len() as u64 > STATUS_LIMIT {
        return Err(Fail::new(
            ErrorCode::FailedPrecondition,
            "process status is too large",
        ));
    }
    Ok(text)
}

fn check_sigterm() -> Result<(), Fail> {
    let status = read_limited("/proc/self/status")?;
    match sigterm_is_default(&status) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Fail::new(
            ErrorCode::FailedPrecondition,
            "SIGTERM must not be ignored or blocked",
        )),
        Err(m) => Err(Fail::new(ErrorCode::FailedPrecondition, m)),
    }
}

fn close_inherited_fds() -> Result<(), Fail> {
    sys::close_fds_from(3).map_err(|_| {
        Fail::new(
            ErrorCode::FailedPrecondition,
            "failed to close inherited descriptors",
        )
    })
}

fn check_stdio() -> Result<(), Fail> {
    let bad = || {
        Fail::new(
            ErrorCode::FailedPrecondition,
            "standard streams are not usable",
        )
    };
    if !(0..=2).all(sys::fd_is_open) {
        return Err(bad());
    }
    let kind = |fd: std::os::fd::BorrowedFd<'_>| -> Option<bool> {
        let t = File::from(fd.try_clone_to_owned().ok()?).metadata().ok()?;
        let ft = t.file_type();
        Some(ft.is_fifo() || ft.is_socket())
    };
    if kind(std::io::stdin().as_fd()) != Some(true) || kind(std::io::stdout().as_fd()) != Some(true)
    {
        return Err(bad());
    }
    Ok(())
}

fn set_non_dumpable() -> Result<(), Fail> {
    sys::set_dumpable(false).map_err(|_| {
        Fail::new(
            ErrorCode::Internal,
            "failed to make the process non-dumpable",
        )
    })
}

fn ns_identity(path: &str) -> Result<NsId, Fail> {
    let md = std::fs::metadata(path).map_err(|_| {
        Fail::new(
            ErrorCode::Internal,
            "failed to inspect a namespace of the process",
        )
    })?;
    Ok(NsId {
        dev: md.dev(),
        ino: md.ino(),
    })
}

// ---- 段 1 ----

fn stage1() -> Result<(), StageEnd> {
    close_inherited_fds()?;
    check_stdio()?;
    check_sigterm()?;
    set_non_dumpable()?;
    let (privilege, source) = crate::start_entry::resolve_self_launch_privilege()
        .map_err(|e| from_trait(&e, "failed to resolve the isolation privilege"))?;
    // パス差し替えの TOCTOU を避けるため、実行ファイルは先に開いた fd で exec する(O_CLOEXEC)。
    let exe = File::open("/proc/self/exe").map_err(|_| {
        Fail::new(
            ErrorCode::FailedPrecondition,
            "failed to open the executable",
        )
    })?;
    let ns = establish_pod_namespaces(privilege, source)
        .map_err(|e| from_trait(&e, "failed to establish the pod namespaces"))?;
    let (u, i, n) = (ns.user(), ns.ipc(), ns.net());
    let cstr = |s: String| {
        CString::new(s).map_err(|_| Fail::new(ErrorCode::Internal, "failed to build arguments"))
    };
    let argv = vec![
        cstr(HOLDER_ARG0.to_owned())?,
        cstr(super::POD_HOLDER_SUBCOMMAND.to_owned())?,
        cstr(STAGE2.to_owned())?,
        cstr(u.dev().to_string())?,
        cstr(u.ino().to_string())?,
        cstr(i.dev().to_string())?,
        cstr(i.ino().to_string())?,
        cstr(n.dev().to_string())?,
        cstr(n.ino().to_string())?,
    ];
    // 成功すれば戻らない。環境変数は渡さない。
    sys::execveat_fd(exe.as_raw_fd(), &argv, &[])
        .map_err(|_| Fail::new(ErrorCode::Internal, "failed to re-execute the holder"))?;
    Err(StageEnd::Fail(Fail::new(
        ErrorCode::Internal,
        "failed to re-execute the holder",
    )))
}

// ---- 段 2 ----

fn stage2(args: &[OsString]) -> Result<(), StageEnd> {
    // exec で dumpable は 1 に戻るため最初に落とす(この窓の間、プロセスは秘密を持たない)。
    let dumpable_reset = set_non_dumpable();
    close_inherited_fds()?;
    let Some(expected) = parse_stage2_args(args) else {
        return Err(StageEnd::Usage("invalid stage 2 arguments"));
    };
    dumpable_reset?;
    check_stdio()?;
    match sys::get_dumpable() {
        Ok(false) => {}
        _ => {
            return Err(Fail::new(ErrorCode::Internal, "the process is dumpable").into());
        }
    }
    // 待つだけのプロセスに pod の user namespace の capability を残さない(SEC-1)。
    sys::cap_ambient_clear_all()
        .map_err(|_| Fail::new(ErrorCode::Internal, "failed to drop capabilities"))?;
    sys::cap_set_thread(sys::ThreadCaps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    })
    .map_err(|_| Fail::new(ErrorCode::Internal, "failed to drop capabilities"))?;

    let user = ns_identity("/proc/self/ns/user")?;
    let ipc = ns_identity("/proc/self/ns/ipc")?;
    let net = ns_identity("/proc/self/ns/net")?;
    let want = |d, i| NsId { dev: d, ino: i };
    let [ud, ui, id, ii, nd, ni] = expected;
    if user != want(ud, ui) || ipc != want(id, ii) || net != want(nd, ni) {
        return Err(Fail::new(
            ErrorCode::FailedPrecondition,
            "namespace identities do not match",
        )
        .into());
    }
    let uid_map = read_limited("/proc/self/uid_map")?;
    if is_initial_uid_map(&uid_map) {
        return Err(Fail::new(
            ErrorCode::PermissionDenied,
            "the process is not in a pod user namespace",
        )
        .into());
    }
    match sys::has_any_child() {
        Ok(false) => {}
        _ => {
            return Err(
                Fail::new(ErrorCode::FailedPrecondition, "unexpected child processes").into(),
            );
        }
    }
    check_sigterm()?;

    let ready = PodHolderReady::new(std::process::id(), user, ipc, net)
        .map_err(|e| from_trait(&e, "failed to build the READY frame"))?;
    let owned = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| Fail::new(ErrorCode::Internal, "failed to write READY"))?;
    File::from(owned)
        .write_all(PodHolderFrame::ready(&ready).as_bytes())
        .map_err(|_| Fail::new(ErrorCode::Unavailable, "failed to write READY"))?;
    wait_for_stdin_close()
}

/// stdin の EOF まで待つ。1 バイトでも来たら予期しない入力として失敗する(net の holder の `wait_for_stop` に合わせる)。
fn wait_for_stdin_close() -> Result<(), StageEnd> {
    // stdin を直接読む(fd を複製しないので、待ちの間に開いている fd は 0〜2 だけに保たれる)。
    let mut input = std::io::stdin();
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(StageEnd::Unexpected("unexpected input on the stop channel")),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StageEnd::Unexpected("failed to wait for the stop signal")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// CRI-2・REPAIR-5・#2874: SIGTERM が無視・ブロックされた起動を見分ける。
    #[test]
    fn cri2_sigterm_mask_parser() {
        let ok = "Name:\tx\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000001000\n";
        assert_eq!(sigterm_is_default(ok), Ok(true));
        let ign = "SigBlk:\t0000000000000000\nSigIgn:\t0000000000004000\n";
        assert_eq!(sigterm_is_default(ign), Ok(false));
        let blk = "SigBlk:\t0000000000004000\nSigIgn:\t0000000000000000\n";
        assert_eq!(sigterm_is_default(blk), Ok(false));
        assert!(sigterm_is_default("SigIgn:\t0\n").is_err());
        assert!(sigterm_is_default("SigIgn:\tzz\nSigBlk:\t0\n").is_err());
        assert!(sigterm_is_default("").is_err());
    }

    /// 段 2 の引数は 6 個の 10 進だけを受ける。
    #[test]
    fn cri2_stage2_args_parser() {
        assert_eq!(
            parse_stage2_args(&os(&["4", "1", "4", "2", "4", "3"])),
            Some([4, 1, 4, 2, 4, 3])
        );
        assert_eq!(parse_stage2_args(&os(&["1", "2", "3", "4", "5"])), None);
        assert_eq!(
            parse_stage2_args(&os(&["1", "2", "3", "4", "5", "6", "7"])),
            None
        );
        assert_eq!(
            parse_stage2_args(&os(&["1", "2", "3", "4", "5", "-6"])),
            None
        );
        assert_eq!(parse_stage2_args(&os(&["1", "2", "3", "4", "5", ""])), None);
        assert_eq!(
            parse_stage2_args(&os(&["1", "2", "3", "4", "5", "0x6"])),
            None
        );
        assert_eq!(
            parse_stage2_args(&os(&["1", "2", "3", "4", "5", "18446744073709551616"])),
            None
        );
    }

    /// 初期 user namespace の恒等写像だけを拒否する。
    #[test]
    fn cri2_initial_uid_map_detection() {
        assert!(is_initial_uid_map("         0          0 4294967295\n"));
        assert!(!is_initial_uid_map("         0       1000          1\n"));
        assert!(!is_initial_uid_map("         0          0          1\n"));
        assert!(!is_initial_uid_map(""));
    }
}
