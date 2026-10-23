//! supervisor の bin から core の本番 launcher を経て `monitor` まで通す実機シナリオ
//! （TASK-157 追補・#1819・SUP-1・SUP-3・SUP-7・CORE-1・CORE-2・CORE-3・CORE-5・SEC-1・REPAIR-3・REPAIR-12）。
//!
//! `harness = false` の単一 `main` で、同じ実行ファイルが 3 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に
//!   実機前提を混ぜないため）。
//! - コンテナ内のプローブ（`--container-probe`）: 禁止 syscall（`kcmp`）を 1 回呼んで `KCMP_ERRNO=<errno>` と `READY` を出し、約 2 秒待って終了コード 7 で終わる。
//!   `--term-probe` を足すと SIGTERM のハンドラ（`_exit(43)` のみ）を登録して `READY_TERM` を出し、SIGTERM を待つ（シナリオ D。
//!   寿命の上限 60 秒を過ぎたら終了コード 8）。PID 1 は `SIG_DFL` のシグナルをカーネルが配送しないため、ハンドラ無しでは SIGTERM が
//!   黙って捨てられ、寿命切れの終了を「SIGTERM で止まった」と取り違える（REPAIR-3）。
//! - delete の補助役（`--delete-helper --root <root> <id>`）: `systemd-run --user --scope` の委譲 cgroup の中で本番の
//!   `DelegatedCgroup::detect()` を remover にして core の `delete` を呼び、`DELETE_RESULT <OK|コード>` を 1 行出す
//!   （端末のセッション scope は root 所有で検出に失敗するため、試験プロセス自身では delete できない）。
//!
//! # 照合項目
//! - シナリオ A の起動直後、PID 1 の `uid_map`・`gid_map` が選択規則（subuid / subgid の自分の行が両方あれば範囲写像、
//!   無ければ 1 対 1。CORE-6・SEC-5・#2243）どおりであること。成功行の前に `id mapping verified (model=...)` を出す。
//!   `FANDHE_CONTAINER_TEST_ID_HELPER=1` では範囲写像を必須にする（設定・`uidmap` が無ければ失敗）
//! - シナリオ A（正常起動 → 監視 → 記録）: bin が `FCSUP1 OK <pid>` を報告し、状態が Running（pid 一致）で、ホストの
//!   `/proc/<pid>/status` の `NSpid` 末尾が 1。プローブの終了を `monitor` が回収して状態が Stopped（終了コード 7）に
//!   なり、bin が終了コード 0 で終わり、`/proc/<pid>` が消え、コンテナの出力（`READY`）がログ sink のファイルに残る。
//!   あわせて seccomp の通知経路を照合する（SEC-4・REPAIR-5・#2025）: プローブが呼んだ `kcmp` が `EPERM`（ログ sink の
//!   `KCMP_ERRNO=1`）で返り、`<状態ルート>/@audit.log` に seccomp 層の行がちょうど 1 行（syscall 番号・arch・pid=1・コンテナ ID）
//!   届く。成功行の前に `seccomp denial returned EPERM and left exactly 1 record in @audit.log` を出す
//! - シナリオ B（起動失敗で何も残らない。A6）: rootfs から `proc/` を除いて pre-pivot 段で失敗させ、報告が ERR・bin の
//!   終了コードが非 0・状態が Created（pid なし）・作った cgroup が消え・プローブのプロセスが残らないことを照合する
//! - シナリオ C（restart の fail-closed。SUP-3・#2043）: `--restart always` でプローブが終了した後、再 launch は
//!   単一スレッドの要求を満たせず本番 launcher が拒否する。新しい子は作られず、状態は Stopped で、bin の終了コードは
//!   FAILED_PRECONDITION の写像になる。再 launch が実機で成立する再構成（#2043）が入ったら、この項目を置き換える
//! - シナリオ D（SIGTERM の配送 → Stopped → 停止後の delete。SUP-4・SUP-1・CORE-2・OCI-6・#2392）: Running の間の delete は
//!   FAILED_PRECONDITION で拒否され記録が残る。プローブの SIGTERM ハンドラ登録を待ってから、CLI `stop` と同じ
//!   `ControlSignaler::for_stop` 経由で core の `kill`（SIGTERM）を送る。monitor が Stopped を記録し、終了コードは
//!   ハンドラの 43（寿命切れの 8・`Signaled(15)` の 143・SIGKILL の 137 ではない）。bin は終了コード 0 で終わり、
//!   プロセスが残らない。その後の delete は補助役（本番の remover）で成功し、状態が消え、2 回目は NOT_FOUND になる
//! - シナリオ E（ESC-03 を supervisor の `SeccompNotifyHub` 経由で照合。SEC-4・SEC-2・CORE-5・#2482）: コンテナ内のプローブ
//!   （`--mount-probe`）が core の `escape_probe_mount` で `mount(2)` を 1 回試行する。専用の状態ルートで `kcmp` は呼ばない。
//!   拒否が `EPERM`（ログ sink の `MOUNT_ERRNO=1`。listener が閉じていれば `ENOSYS`）で返り、`@audit.log` の seccomp 層の行が
//!   ちょうど 1 行（mount の syscall 番号・arch・pid=1・コンテナ ID）届くことを、コンテナの外で回収した記録で具体値照合する
//!
//! # 必要環境
//! - Linux 6.12 以上（Landlock ABI 6 以上。満たさないと launcher が起動を拒否する。CORE-5）
//! - 非特権ユーザーでの実行（root では rootful として拒否される。SEC-5）
//! - `systemd-run --user`（supervisor と、シナリオ D の delete の補助役の両方が使う）
//! - 非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=0` 等の緩和が要る場合がある）
//! - `systemd-run --user`（bin を非特権ユーザーに委譲された cgroup v2 の新しいスコープで起動するため。試験プロセスと同じ
//!   cgroup に他プロセスがいると `DelegatedCgroup::prepare` が失敗する）。包み込みの引数は本番（CLI の `start`）と同じ
//!   `start_contract::USER_SCOPE_WRAPPER_ARGS` で、CLI 経由で CLI が居残らないことの照合は
//!   `crates/cli/tests/start_scope_real.rs` が行う（#2081・CORE-3・CORE-4）
//! - 動的リンクのためホストの共有ライブラリを rootfs へコピーする（ネットワークは不要）
//!
//! # 実機前提テストとしての分離
//! 上記の環境は既定のテスト集合では保証できないため、`-- --ignored` 指定時のみ実行する（`platform-ci` の ubuntu は #2596 で実行し成功行を照合する。ci.md「実機前提テスト」。
//! 既定集合で動くはずの試験を移したものではない。既定集合では `supervisor_bin.rs` が fail-closed の不変条件を照合する）。
//! 実行された場合は、user namespace の拒否・Landlock ABI 不足・cgroup の委譲無しを含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test supervisor_bin_real --no-run
//! <target/debug/deps/supervisor_bin_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `supervisor_bin_real: start reported OK, NSpid ends with 1, monitor recorded Stopped(7), logs
//! captured, seccomp denial recorded once; failed start left no process; restart fails closed until #2043; SIGTERM
//! via the control channel recorded Stopped(43) and the stopped container was deleted; ESC-03 mount denied via the
//! SeccompNotifyHub and recorded once`。
//! CI（ubuntu-latest）以外の環境・root の分岐の実行と結果の記録は人間担当（#499・#485・#491・#219 のうち該当するもの、または PR）。Linux 限定。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("supervisor_bin_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("supervisor_bin_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // 子（コンテナ内）は同じバイナリを `--container-probe` で再実行したもの。
    let has = |flag: &str| std::env::args().any(|a| a == flag);
    if has("--container-probe") {
        if has("--term-probe") {
            linux::term_probe();
        } else if has("--mount-probe") {
            linux::mount_probe();
        } else {
            linux::probe();
        }
    } else if has("--delete-helper") {
        linux::delete_helper();
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "supervisor_bin_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::DelegatedCgroup;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        KillTimeout, ProcessSignaler, create, delete, exit_code_for, kill,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, DeleteRequest, ErrorCode, GetStateRequest,
        KillRequest, Signal, StateRecord, StateStore,
    };
    use fandhe_container_supervisor::control::ControlSignaler;
    use fandhe_container_supervisor::start_contract::StartReport;
    use fandhe_container_supervisor::state::open_default_store;

    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-supervisor");
    /// プローブの終了コード（状態の `Stopped` の終了コードと照合する）。
    const PROBE_EXIT: i32 = 7;
    /// プローブが `READY` を出してから終了するまでの時間。
    const PROBE_LIFETIME: Duration = Duration::from_secs(2);
    /// 報告 1 行を待つ上限と、bin の終了を待つ上限（REPAIR-5）。
    const REPORT_TIMEOUT: Duration = Duration::from_secs(60);
    const EXIT_TIMEOUT: Duration = Duration::from_secs(90);
    /// 報告 1 行の長さの上限（契約の最大長に十分な余裕。無制限確保を避ける）。
    const LINE_MAX: u64 = 1024;
    /// SIGTERM 用プローブの寿命の上限（`EXIT_TIMEOUT` より短く、無期限に待たない。REPAIR-5）と、その終了コード。
    const TERM_PROBE_LIFETIME: Duration = Duration::from_secs(60);
    const TERM_PROBE_TIMEOUT_EXIT: i32 = 8;
    /// SIGTERM のハンドラが `_exit` へ渡す終了コード（core の試験用の口と同じ値。`Stopped` の終了コードと照合する）。
    const TERM_HANDLER_EXIT: i32 = fandhe_container_core::exec::SIGTERM_HANDLER_EXIT_CODE_FOR_TEST;
    /// `/proc/<pid>/status` の `SigCgt`（捕捉中シグナルのマスク）で SIGTERM（15）に当たるビット（1 << 14）。
    const SIGTERM_CAUGHT_BIT: u64 = 1 << 14;
    /// ハンドラ登録の待ちの上限（REPAIR-5）。
    const HANDLER_WAIT: Duration = Duration::from_secs(30);

    /// コンテナ内で動く SIGTERM 用プローブ（シナリオ D）。SIGTERM のハンドラ（`_exit(43)` のみ）を登録してから
    /// `READY_TERM` を出し、SIGTERM を待つ。`kcmp` は呼ばない（シナリオ A の監査レコード件数を崩さないため）。
    pub fn term_probe() {
        let mut out = std::io::stdout();
        if let Err(e) = fandhe_container_core::exec::exit_on_sigterm_for_test() {
            let _ = writeln!(out, "TERM_HANDLER_FAILED {e}");
            let _ = out.flush();
            std::process::exit(9);
        }
        let _ = writeln!(out, "READY_TERM");
        let _ = out.flush();
        let deadline = Instant::now() + TERM_PROBE_LIFETIME;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(TERM_PROBE_TIMEOUT_EXIT);
    }

    /// コンテナ内で動く mount プローブ（シナリオ E。ESC-03 と同じ攻撃。SEC-2・SEC-4・#2482）。core の
    /// `escape_probe_mount`（PID 1 かつ `Seccomp: 2` のときだけ `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` を
    /// 1 回発行。新しいマウントは作らない）の結果を `MOUNT_ERRNO=<errno>` で出す。`kcmp` は呼ばない（シナリオ A の
    /// 件数の契約を崩さないため）。前提の不成立は終了コード 9 にして親の Stopped(7) の照合で落とす。
    pub fn mount_probe() {
        use fandhe_container_core::exec::{ProbeOutcome, escape_probe_mount};
        let mut out = std::io::stdout();
        let mut exit = PROBE_EXIT;
        match escape_probe_mount() {
            Ok(ProbeOutcome::Errno(n)) => {
                let _ = writeln!(out, "MOUNT_ERRNO={n}");
            }
            Ok(ProbeOutcome::Ok) => {
                let _ = writeln!(out, "MOUNT_ERRNO=0");
            }
            Ok(other) => {
                let _ = writeln!(out, "MOUNT_PROBE_FAILED {other:?}");
            }
            Err(e) => {
                let _ = writeln!(out, "MOUNT_PRECONDITION_FAILED {}", e.code.as_str());
                exit = 9;
            }
        }
        let _ = writeln!(out, "READY");
        let _ = out.flush();
        std::thread::sleep(PROBE_LIFETIME);
        std::process::exit(exit);
    }

    /// delete の補助役。委譲 cgroup（`systemd-run --user --scope`）の中で、本番の remover（`DelegatedCgroup::detect()`）を
    /// 使って core の `delete` を呼び、結果を `DELETE_RESULT <OK|コード>` の 1 行で出す。失敗は非 0 で終わる。
    pub fn delete_helper() {
        let args: Vec<String> = std::env::args().collect();
        let value_after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        let (Some(root), Some(id)) = (value_after("--root"), args.last().cloned()) else {
            println!("DELETE_RESULT BAD_ARGS");
            std::process::exit(2);
        };
        let Ok(id) = ContainerId::new(id) else {
            println!("DELETE_RESULT BAD_ID");
            std::process::exit(2);
        };
        let store = match open_default_store(Some(PathBuf::from(root))) {
            Ok(s) => s,
            Err(e) => {
                println!("DELETE_RESULT STORE_{}", e.code().as_str());
                std::process::exit(2);
            }
        };
        let delegated = match DelegatedCgroup::detect() {
            Ok(d) => d,
            Err(e) => {
                println!("DELETE_RESULT DETECT_{}", e.code.as_str());
                std::process::exit(2);
            }
        };
        match delete(
            store.as_ref(),
            &OpRecorder::new(),
            &delegated,
            &DeleteRequest::new(id),
        ) {
            Ok(_) => println!("DELETE_RESULT OK"),
            Err(e) => {
                println!("DELETE_RESULT {}", e.code().as_str());
                std::process::exit(i32::from(e.exit_code().get()));
            }
        }
    }

    /// 拒否される syscall 番号（アーキテクチャごとに別。流用しない）。kcmp は x86_64 = 312 / aarch64 = 272、
    /// mount は x86_64 = 165 / aarch64 = 40。aarch64 の値は CI の型検査でだけ確認され、実行はされない。
    #[cfg(target_arch = "x86_64")]
    const KCMP_NR: u32 = 312;
    #[cfg(target_arch = "aarch64")]
    const KCMP_NR: u32 = 272;
    #[cfg(target_arch = "x86_64")]
    const MOUNT_NR: u32 = 165;
    #[cfg(target_arch = "aarch64")]
    const MOUNT_NR: u32 = 40;

    /// コンテナ内で動くプローブ。`READY` を出して一定時間待ち、`PROBE_EXIT` で終わる。
    pub fn probe() {
        let mut out = std::io::stdout();
        // ERRNO 側の禁止 syscall(kcmp)を 1 回呼ぶ。本番の launcher は USER_NOTIF 版の filter を載せ、supervisor の応答ハブが
        // 記録して EPERM(1) で応答する(SEC-4・#2025)。出力はログ sink に捕捉され、親が errno を照合する。
        let errno = fandhe_container_core::exec::kcmp_self_errno_for_test();
        let _ = writeln!(out, "KCMP_ERRNO={}", errno.unwrap_or(0));
        let _ = writeln!(out, "READY");
        let _ = out.flush();
        std::thread::sleep(PROBE_LIFETIME);
        std::process::exit(PROBE_EXIT);
    }

    fn require(ok: bool, msg: &str) {
        if !ok {
            eprintln!("supervisor_bin_real: precondition failed: {msg}");
            std::process::exit(1);
        }
    }

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    fn mkdir(path: &Path) {
        std::fs::create_dir_all(path).unwrap_or_else(|e| panic!("mkdir {}: {e}", path.display()));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }

    /// `host` のファイルを rootfs 内の同じ絶対パスへコピーする。
    fn copy_into(rootfs: &Path, host: &Path, mode: u32) {
        let dest = rootfs.join(host.strip_prefix("/").expect("absolute path"));
        mkdir(dest.parent().expect("parent"));
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(host, &dest)
            .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", host.display(), dest.display()));
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", dest.display()));
    }

    /// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` で検査する。
    fn elf_interp(exe: &[u8]) -> Option<String> {
        let u16_at = |o: usize| Some(u16::from_le_bytes(exe.get(o..o + 2)?.try_into().ok()?));
        let u32_at = |o: usize| Some(u32::from_le_bytes(exe.get(o..o + 4)?.try_into().ok()?));
        let u64_at = |o: usize| Some(u64::from_le_bytes(exe.get(o..o + 8)?.try_into().ok()?));
        if exe.get(0..4)? != b"\x7fELF" {
            return None;
        }
        let phoff = usize::try_from(u64_at(0x20)?).ok()?;
        let phentsize = usize::from(u16_at(0x36)?);
        let phnum = usize::from(u16_at(0x38)?);
        for i in 0..phnum {
            let base = phoff.checked_add(i.checked_mul(phentsize)?)?;
            if u32_at(base)? == 3 {
                let off = usize::try_from(u64_at(base + 8)?).ok()?;
                let len = usize::try_from(u64_at(base + 32)?).ok()?;
                let raw = exe.get(off..off.checked_add(len)?)?;
                let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                return String::from_utf8(raw.get(..end)?.to_vec()).ok();
            }
        }
        None
    }

    /// 自プロセスに読み込み済みの共有ライブラリの実パス（`/proc/self/maps` から。重複なし）。
    fn loaded_libraries(exe: &Path) -> Vec<PathBuf> {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
        let mut libs: Vec<PathBuf> = Vec::new();
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            let p = PathBuf::from(path);
            if !path.starts_with('/')
                || p == exe
                || ["/dev/", "/proc/", "/sys/", "/tmp/", "/memfd:"]
                    .iter()
                    .any(|pre| path.starts_with(pre))
                || libs.contains(&p)
            {
                continue;
            }
            if std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                libs.push(p);
            }
        }
        libs
    }

    /// 最小 rootfs を作る。`with_proc` が false なら `proc/` を作らない（シナリオ B の失敗注入）。
    /// 戻り値はプローブが使う `LD_LIBRARY_PATH` の値。
    fn make_rootfs(rootfs: &Path, with_proc: bool) -> String {
        mkdir(rootfs);
        let dirs: &[&str] = if with_proc {
            &["proc", "dev", "tmp", "etc"]
        } else {
            &["dev", "tmp", "etc"]
        };
        for d in dirs {
            mkdir(&rootfs.join(d));
        }
        let exe = std::env::current_exe().expect("current_exe");
        let exe = std::fs::canonicalize(exe).expect("canonicalize exe");
        let probe = rootfs.join("probe");
        std::fs::copy(&exe, &probe).expect("copy probe binary");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755))
            .expect("chmod probe");
        let bytes = std::fs::read(&exe).expect("read exe");
        let mut lib_dirs: Vec<String> = Vec::new();
        if let Some(interp) = elf_interp(&bytes) {
            copy_into(rootfs, Path::new(&interp), 0o755);
        }
        for lib in loaded_libraries(&exe) {
            copy_into(rootfs, &lib, 0o755);
            if let Some(dir) = lib.parent().and_then(Path::to_str)
                && !lib_dirs.iter().any(|d| d == dir)
            {
                lib_dirs.push(dir.to_string());
            }
        }
        lib_dirs.join(":")
    }

    /// 一時ディレクトリ（bundle と状態ルート。drop で削除）。
    struct Env {
        dir: PathBuf,
        store: Arc<dyn StateStore>,
    }

    /// コンテナ内で動かすプローブの種類。
    #[derive(Clone, Copy)]
    enum Probe {
        /// 約 2 秒後に終了コード 7 で自ら終わる（シナリオ A〜C）。
        Exit7,
        /// SIGTERM を待ち、ハンドラ経由で終了コード 43 で終わる（シナリオ D）。
        Term,
        /// `mount(2)` を 1 回試行して終了コード 7 で終わる（シナリオ E。ESC-03）。
        Mount,
    }

    impl Env {
        fn new(tag: &str, with_proc: bool, probe: Probe) -> Self {
            let probe_args = match probe {
                Probe::Exit7 => r#""/probe","--container-probe""#,
                Probe::Term => r#""/probe","--container-probe","--term-probe""#,
                Probe::Mount => r#""/probe","--container-probe","--mount-probe""#,
            };
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!(
                    "fandhe-supbinreal-{tag}-{}-{nanos}",
                    std::process::id()
                ));
            std::fs::create_dir(&dir).expect("exclusively create the work dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod work dir");
            let bundle = dir.join("bundle");
            std::fs::create_dir(&bundle).expect("create bundle");
            let ld = make_rootfs(&bundle.join("rootfs"), with_proc);
            let config = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-supbin",
"process":{{"user":{{"uid":0,"gid":0}},"args":[{probe_args}],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
            );
            std::fs::write(bundle.join("config.json"), config).expect("write config.json");
            let root = dir.join("state");
            std::fs::create_dir(&root).expect("create state root");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("chmod state root");
            let store = open_default_store(Some(root)).expect("open the state store");
            Self { dir, store }
        }

        fn root(&self) -> PathBuf {
            self.dir.join("state")
        }

        fn create(&self, id: &str) {
            let req = CreateRequest::new(cid(id), self.dir.join("bundle")).expect("create request");
            create(self.store.as_ref(), &OpRecorder::new(), &req).expect("create");
        }

        fn record(&self, id: &str) -> StateRecord {
            self.store
                .get(&GetStateRequest::new(cid(id)))
                .expect("get state")
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn cid(id: &str) -> ContainerId {
        ContainerId::new(id).expect("container id")
    }

    /// 起動中の supervisor（`systemd-run --user --scope` 経由。stdout が結果チャネルの pipe）。
    struct Supervisor {
        child: Child,
        report: mpsc::Receiver<Vec<u8>>,
    }

    /// bin を非特権ユーザーに委譲された新しい cgroup スコープで起動する（CLI の契約と同じ argv・stdout は pipe）。
    fn spawn_supervisor(env: &Env, id: &str, restart: Option<&str>) -> Supervisor {
        let mut cmd = Command::new("systemd-run");
        cmd.args(fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS)
            .arg(BIN)
            .arg("start")
            .arg("--root")
            .arg(env.root());
        if let Some(policy) = restart {
            cmd.args(["--restart", policy]);
        }
        let mut child = cmd
            .arg(id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn systemd-run (is `systemd-run --user` available?)");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, report) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = Vec::new();
            let mut reader = std::io::BufReader::new(stdout);
            let _ = (&mut reader).take(LINE_MAX).read_until(b'\n', &mut line);
            let _ = tx.send(line);
        });
        Supervisor { child, report }
    }

    impl Supervisor {
        /// 結果の 1 行を期限つきで待って復号する。
        fn report(&self) -> StartReport {
            let line = self
                .report
                .recv_timeout(REPORT_TIMEOUT)
                .expect("the supervisor must report within the deadline");
            StartReport::decode(&line)
                .unwrap_or_else(|e| panic!("invalid report {line:?}: {}", e.message()))
        }

        /// bin の終了を期限つきで待ち、終了コードを返す（超過したら kill して失敗させる）。
        fn exit_code(&mut self) -> i32 {
            let deadline = Instant::now() + EXIT_TIMEOUT;
            loop {
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    return status.code().expect("exit code (not a signal)");
                }
                if Instant::now() >= deadline {
                    let killed = self.child.kill();
                    // 回収も有限期限まで try_wait で確かめる（kill の失敗・終了しない子で無期限に止まらない。REPAIR-5）。
                    let reap_until = Instant::now() + Duration::from_secs(10);
                    let mut reaped = false;
                    while Instant::now() < reap_until {
                        if matches!(self.child.try_wait(), Ok(Some(_))) {
                            reaped = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    panic!(
                        "the supervisor did not exit within the deadline (kill: {killed:?}, reaped: {reaped})"
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// `/proc` の全プロセスのうち、プローブ（`/probe --container-probe`）の数。
    fn probe_processes() -> usize {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return 0;
        };
        dir.flatten()
            .filter(|e| {
                std::fs::read(e.path().join("cmdline"))
                    .is_ok_and(|c| c.windows(17).any(|w| w == b"--container-probe"))
                    && e.file_name()
                        .to_str()
                        .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            })
            // 自プロセス自体（`--container-probe` を引数に持たない）は除外される。
            .count()
    }

    /// プローブが消えるまで期限つきで待つ。
    fn no_probe_remains() -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if probe_processes() == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        probe_processes() == 0
    }

    pub fn run() {
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        let euid_is_root = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_owned))
            .as_deref()
            == Some("0");
        require(
            !euid_is_root,
            "must run as a non-root user (rootful start is refused)",
        );
        scenario_a_start_monitor_record();
        scenario_b_failed_start_leaves_nothing();
        scenario_c_restart_fails_closed();
        scenario_d_sigterm_stop_delete();
        scenario_e_esc03_mount_via_hub();
        println!(
            "supervisor_bin_real: start reported OK, NSpid ends with 1, monitor recorded Stopped({PROBE_EXIT}), logs captured, seccomp denial recorded once; failed start left no process; restart fails closed until #2043; SIGTERM via the control channel recorded Stopped({TERM_HANDLER_EXIT}) and the stopped container was deleted; ESC-03 mount denied via the SeccompNotifyHub and recorded once"
        );
    }

    /// ホストの実効 uid・gid（`/proc/self/status`）。
    fn host_ids() -> (u32, u32) {
        let field = |key: &str| -> u32 {
            status_field("/proc/self/status", key)
                .and_then(|v| v.split_whitespace().nth(1).map(str::to_owned))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("cannot read {key} of this process"))
        };
        (field("Uid:"), field("Gid:"))
    }

    /// `/etc/subuid` 形式のファイルから、名前か数値 uid が一致する行の (start, count) を集める（試験側の独立実装）。
    fn owner_ranges(path: &str, name: Option<&str>, uid: u32) -> Vec<(u64, u64)> {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|l| {
                let mut f = l.trim().split(':');
                let who = f.next()?;
                if Some(who) != name && who != uid.to_string() {
                    return None;
                }
                Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
            })
            .collect()
    }

    /// 起動した PID 1 の `uid_map`・`gid_map` が supervisor の選択規則どおりか照合する（CORE-6・SEC-5・#2243）。
    /// subuid / subgid の両方に自分の行があれば「0 → 実効 ID × 1」と範囲の連結、どちらも無ければ 1 対 1 の 1 行。
    /// `FANDHE_CONTAINER_TEST_ID_HELPER=1` のときは範囲写像を必須にする（設定や uidmap が無ければ失敗）。
    fn verify_id_mapping(pid: u32) {
        let (uid, gid) = host_ids();
        let name = std::fs::read_to_string("/etc/passwd").ok().and_then(|t| {
            t.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.get(2).and_then(|u| u.parse::<u32>().ok()) == Some(uid))
                    .then(|| f.first().map(|n| (*n).to_owned()))
                    .flatten()
            })
        });
        let su = owner_ranges("/etc/subuid", name.as_deref(), uid);
        let sg = owner_ranges("/etc/subgid", name.as_deref(), uid);
        let subordinate = !su.is_empty() && !sg.is_empty();
        if std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1") {
            assert!(
                subordinate,
                "FANDHE_CONTAINER_TEST_ID_HELPER=1 needs subuid and subgid rows for this user"
            );
        }
        let read = |file: &str| -> Vec<(u64, u64, u64)> {
            std::fs::read_to_string(format!("/proc/{pid}/{file}"))
                .unwrap_or_else(|e| panic!("cannot read {file}: {e}"))
                .lines()
                .map(|l| {
                    let n: Vec<u64> = l.split_whitespace().map(|x| x.parse().unwrap()).collect();
                    (n[0], n[1], n[2])
                })
                .collect()
        };
        for (file, host, ranges) in [("uid_map", uid, &su), ("gid_map", gid, &sg)] {
            let map = read(file);
            if subordinate {
                // 期待する全行: (0, 実効 ID, 1) の後に、設定の範囲を順に container id 1.. へ連結（rootless_mapping と同じ規則）。
                let mut want = vec![(0u64, u64::from(host), 1u64)];
                let mut next = 1u64;
                for &(start, count) in ranges.iter() {
                    want.push((next, start, count));
                    next += count;
                }
                assert_eq!(map, want, "{file}: every extent (container, host, count)");
            } else {
                assert_eq!(
                    map,
                    vec![(0, u64::from(host), 1)],
                    "{file}: single id mapping"
                );
            }
        }
        println!(
            "supervisor_bin_real: id mapping verified (model={}, uid extents={}, gid extents={})",
            if subordinate { "subordinate" } else { "single" },
            read("uid_map").len(),
            read("gid_map").len()
        );
    }

    /// シナリオ A: 起動 → 報告 → 監視 → Stopped の記録。
    fn scenario_a_start_monitor_record() {
        let env = Env::new("a", true, Probe::Exit7);
        let id = format!("sba{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let running = env.record(&id);
        assert_eq!(running.status().state(), ContainerState::Running);
        assert_eq!(running.status().pid(), Some(pid));
        assert!(running.cgroup().is_some(), "the cgroup scope is recorded");
        let nspid = status_field(&format!("/proc/{pid}/status"), "NSpid:").expect("host NSpid");
        let parts: Vec<&str> = nspid.split_whitespace().collect();
        assert_eq!(parts.len(), 2, "NSpid must have two levels: {nspid:?}");
        assert_eq!(parts.first().copied(), Some(pid.to_string().as_str()));
        assert_eq!(parts.last().copied(), Some("1"));
        verify_id_mapping(pid.get());

        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let stopped = env.record(&id);
        assert_eq!(stopped.status().state(), ContainerState::Stopped);
        assert_eq!(stopped.status().exit_code(), Some(PROBE_EXIT));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the container process must be reaped"
        );
        assert!(no_probe_remains(), "no probe process may remain");
        // コンテナの出力が捕捉されてログ sink のファイルに残る（SUP-7）。
        let logs = fandhe_container_supervisor::logs::container_log_dir(&env.root());
        let captured = std::fs::read_dir(&logs)
            .expect("log directory")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&id))
            .any(|e| {
                std::fs::read_to_string(e.path())
                    .is_ok_and(|t| t.lines().any(|l| l.contains("READY")))
            });
        assert!(captured, "READY must be captured in the log sink");
        verify_seccomp_audit(&env, &id, "KCMP_ERRNO=1", KCMP_NR, "kcmp");
        println!("supervisor_bin_real: scenario=A ok pid={pid} nspid={nspid:?}");
    }

    /// seccomp の拒否の end-to-end(SEC-4・REPAIR-5・#2025): プローブが呼んだ `kcmp` が EPERM(1) で返り(ログ sink の
    /// `KCMP_ERRNO=1`)、`<状態ルート>/@audit.log` に seccomp 層の行がちょうど 1 行(コンテナ ID つき・pid はコンテナ内の 1)
    /// 届くことを具体値で照合する。
    /// `errno_marker` はプローブが出す EPERM の印、`nr` は拒否された syscall 番号、`label` は成功行に出す syscall 名。
    fn verify_seccomp_audit(env: &Env, id: &str, errno_marker: &str, nr: u32, label: &str) {
        let logs = fandhe_container_supervisor::logs::container_log_dir(&env.root());
        let denied = std::fs::read_dir(&logs)
            .expect("log directory")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(id))
            .any(|e| {
                std::fs::read_to_string(e.path())
                    .is_ok_and(|t| t.lines().any(|l| l.contains(errno_marker)))
            });
        assert!(
            denied,
            "the denied {label} must return EPERM ({errno_marker} in the log sink)"
        );
        let audit = std::fs::read_to_string(env.root().join("@audit.log")).unwrap_or_default();
        let lines: Vec<&str> = audit
            .lines()
            .filter(|l| l.contains("\"layer\":\"seccomp\""))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "exactly one seccomp record expected: {audit:?}"
        );
        let line = lines.first().copied().unwrap_or_default();
        #[cfg(target_arch = "x86_64")]
        let arch = 0xC000_003Eu32;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xC000_00B7u32;
        for needle in [
            format!("\"syscall\":{nr}"),
            format!("\"arch\":{arch}"),
            "\"pid\":1,".to_string(),
            format!("\"container_id\":\"{id}\""),
        ] {
            assert!(line.contains(&needle), "{needle} missing: {line}");
        }
        if label == "kcmp" {
            println!(
                "supervisor_bin_real: seccomp denial returned EPERM and left exactly 1 record in @audit.log"
            );
        } else {
            println!(
                "supervisor_bin_real: ESC-03 {label} denied with EPERM via the supervisor SeccompNotifyHub and left exactly 1 record in @audit.log"
            );
        }
    }

    /// シナリオ B: pre-pivot 段の失敗で、子を残さず、Created のまま、作った cgroup を消す。
    fn scenario_b_failed_start_leaves_nothing() {
        let env = Env::new("b", false, Probe::Exit7);
        let id = format!("sbb{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let (code, exit_code) = match sup.report() {
            StartReport::Failed {
                code, exit_code, ..
            } => (code, exit_code),
            other => panic!("expected ERR, got {other:?}"),
        };
        let bin_exit = sup.exit_code();
        assert_ne!(bin_exit, 0);
        assert_eq!(bin_exit, i32::from(exit_code.get()));
        assert_ne!(code, ErrorCode::Unimplemented, "must reach the launcher");
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Created);
        assert!(rec.status().pid().is_none());
        assert!(no_probe_remains(), "no probe process may remain");
        // 作った cgroup は消えている（スコープの記録は残るが、`fc-<id>@...` のディレクトリは無い）。
        let placement = rec.cgroup().expect("the scope stays recorded");
        let scope_dir = PathBuf::from("/sys/fs/cgroup")
            .join(placement.scope().as_str().trim_start_matches('/'));
        let leftover = container_cgroup_leftover(&scope_dir, &id);
        assert!(!leftover, "the container cgroup must be removed");
        println!("supervisor_bin_real: scenario=B ok code={}", code.as_str());
    }

    /// シナリオ C: restart の再 launch は fail-closed（#2043 まで）。
    fn scenario_c_restart_fails_closed() {
        let env = Env::new("c", true, Probe::Exit7);
        let id = format!("sbc{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, Some("always"));
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let bin_exit = sup.exit_code();
        assert_eq!(
            bin_exit,
            i32::from(exit_code_for(ErrorCode::FailedPrecondition).get()),
            "the relaunch must be refused by the single-thread requirement"
        );
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(no_probe_remains(), "no probe process may remain");
        println!("supervisor_bin_real: scenario=C ok first_pid={pid}");
    }

    /// delete の補助役の結果。
    struct DeleteOutcome {
        exit_code: i32,
        /// `DELETE_RESULT` 行の値（`OK` かエラーコード）。
        result: String,
    }

    /// 同じ実行ファイルを `--delete-helper` で、supervisor と同じ委譲 scope の包みの中で動かす。出力の読み取りは行長の
    /// 上限つき、終了待ちは期限つきで、超過したら kill して回収し失敗にする（REPAIR-5）。
    fn run_delete_helper(env: &Env, id: &str) -> DeleteOutcome {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new("systemd-run")
            .args(fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS)
            .arg(exe)
            .arg("--delete-helper")
            .arg("--root")
            .arg(env.root())
            .arg(id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the delete helper (is `systemd-run --user` available?)");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = Vec::new();
            let mut reader = std::io::BufReader::new(stdout);
            let _ = (&mut reader).take(LINE_MAX).read_until(b'\n', &mut line);
            let _ = tx.send(line);
        });
        let deadline = Instant::now() + EXIT_TIMEOUT;
        let exit_code = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break status.code().expect("exit code (not a signal)");
            }
            if Instant::now() >= deadline {
                let killed = child.kill();
                // 回収も有限期限まで try_wait で確かめる（kill の失敗・終了しない子で無期限に止まらない。REPAIR-5）。
                let reap_until = Instant::now() + Duration::from_secs(10);
                let mut reaped = false;
                while Instant::now() < reap_until {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        reaped = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                panic!(
                    "the delete helper did not exit within the deadline (kill: {killed:?}, reaped: {reaped})"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let line = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the delete helper must print its result line");
        let text = String::from_utf8_lossy(&line);
        let result = text
            .trim()
            .strip_prefix("DELETE_RESULT ")
            .unwrap_or_else(|| panic!("unexpected delete helper output: {text:?}"))
            .to_string();
        DeleteOutcome { exit_code, result }
    }

    /// ホストの `/proc/<pid>/status` の `SigCgt` に SIGTERM のビットが立つまで期限つきで待つ（ハンドラ登録前に送ると
    /// PID 1 では黙って捨てられる）。起動の OK 報告は制御ソケットの bind より前に出るが、`ControlSignaler` が
    /// `ENOENT`・`ECONNREFUSED` を短時間再試行するうえ、この待ちが先に入るので送信は bind 後になる。
    fn wait_sigterm_handler(pid: u32) {
        let deadline = Instant::now() + HANDLER_WAIT;
        while Instant::now() < deadline {
            let caught = status_field(&format!("/proc/{pid}/status"), "SigCgt:")
                .and_then(|v| u64::from_str_radix(&v, 16).ok())
                .unwrap_or(0);
            if caught & SIGTERM_CAUGHT_BIT != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the probe did not install its SIGTERM handler within the deadline");
    }

    /// シナリオ D: 制御チャネルの SIGTERM の配送 → monitor が Stopped を記録 → 停止後の delete の成功（SUP-4・#2392）。
    fn scenario_d_sigterm_stop_delete() {
        let env = Env::new("d", true, Probe::Term);
        let id = format!("sbd{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let running = env.record(&id);
        assert_eq!(running.status().state(), ContainerState::Running);
        assert_eq!(running.status().pid(), Some(pid));
        let placement = running
            .cgroup()
            .expect("the cgroup scope is recorded")
            .clone();

        // 停止前の delete は状態の判定で拒否され（cgroup に触れる前）、記録は Running のまま残る（OCI-6）。
        let early = run_delete_helper(&env, &id);
        assert_eq!(
            early.result, "FAILED_PRECONDITION",
            "delete of a running container"
        );
        assert_eq!(
            early.exit_code,
            i32::from(exit_code_for(ErrorCode::FailedPrecondition).get())
        );
        assert_eq!(env.record(&id).status().state(), ContainerState::Running);

        // CLI `stop` と同じ経路: for_stop の signaler で core の kill（SIGTERM）を制御チャネルへ送る。
        wait_sigterm_handler(pid.get());
        let signaler: Arc<dyn ProcessSignaler> = Arc::new(ControlSignaler::for_stop(env.root()));
        let killed = kill(
            env.store.as_ref(),
            &OpRecorder::new(),
            &signaler,
            &KillRequest::new(cid(&id), Signal::SIGTERM),
            &KillTimeout::default(),
        )
        .unwrap_or_else(|e| panic!("kill(SIGTERM) via the control channel failed: {e:?}"));
        // kill は状態を更新しない契約。照合した時点の状態は Running で pid が一致する。
        assert_eq!(killed.state(), ContainerState::Running);
        assert_eq!(killed.pid(), Some(pid));

        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let stopped = env.record(&id);
        assert_eq!(stopped.status().state(), ContainerState::Stopped);
        assert_eq!(
            stopped.status().exit_code(),
            Some(TERM_HANDLER_EXIT),
            "must stop through the SIGTERM handler (not lifetime expiry 8, Signaled(15) 143 or SIGKILL 137)"
        );
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the container process must be reaped"
        );
        assert!(no_probe_remains(), "no probe process may remain");
        println!(
            "supervisor_bin_real: SIGTERM delivered via the control channel, monitor recorded Stopped({TERM_HANDLER_EXIT})"
        );

        // 停止後の delete: 本番の remover（委譲 scope の中の `DelegatedCgroup`）で成功し、状態が消え、2 回目は NOT_FOUND。
        let deleted = run_delete_helper(&env, &id);
        assert_eq!(deleted.result, "OK", "delete of the stopped container");
        assert_eq!(deleted.exit_code, 0);
        let gone = env.store.get(&GetStateRequest::new(cid(&id)));
        assert!(
            matches!(gone, Err(ref e) if e.code() == ErrorCode::NotFound),
            "the state record must be gone: {gone:?}"
        );
        let again = run_delete_helper(&env, &id);
        assert_eq!(again.result, "NOT_FOUND", "second delete");
        let scope_dir = PathBuf::from("/sys/fs/cgroup")
            .join(placement.scope().as_str().trim_start_matches('/'));
        let leftover = container_cgroup_leftover(&scope_dir, &id);
        assert!(!leftover, "the container cgroup must be removed");
        println!(
            "supervisor_bin_real: scenario=D ok pid={pid} (stopped delete succeeded; second delete NOT_FOUND)"
        );
    }

    /// シナリオ E: ESC-03 の `mount(2)` 拒否を、本番 supervisor bin の `SeccompNotifyHub` 経由で記録させて照合する
    /// （SEC-4・SEC-2・CORE-5・#2482）。証拠はコンテナの外（この親）が状態ルートの `@audit.log` から回収した記録だけで、
    /// プローブの出力 `MOUNT_ERRNO=1` は攻撃結果の観測にとどめる。
    fn scenario_e_esc03_mount_via_hub() {
        let env = Env::new("e", true, Probe::Mount);
        let id = format!("sbe{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let running = env.record(&id);
        assert_eq!(running.status().state(), ContainerState::Running);
        assert_eq!(running.status().pid(), Some(pid));
        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let stopped = env.record(&id);
        assert_eq!(stopped.status().state(), ContainerState::Stopped);
        assert_eq!(
            stopped.status().exit_code(),
            Some(PROBE_EXIT),
            "the mount probe must pass its precondition (PID 1, Seccomp: 2) and exit 7"
        );
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the container process must be reaped"
        );
        assert!(no_probe_remains(), "no probe process may remain");
        verify_seccomp_audit(&env, &id, "MOUNT_ERRNO=1", MOUNT_NR, "mount");
        println!("supervisor_bin_real: scenario=E ok pid={pid}");
    }

    /// スコープ配下に `id` を含む子 cgroup が残っているかを返す。
    /// スコープ自体が無い（`NotFound`）場合は「残っていない」と明示して扱い、
    /// それ以外の読み取り失敗は握りつぶさず panic させる（検証が空振りしないようにする）。
    fn container_cgroup_leftover(scope_dir: &std::path::Path, id: &str) -> bool {
        match std::fs::read_dir(scope_dir) {
            Ok(d) => d
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains(id)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => panic!("cannot inspect scope dir {}: {e}", scope_dir.display()),
        }
    }
}
