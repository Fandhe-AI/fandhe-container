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
//! - シナリオ C（restart の再 launch。SUP-3・CORE-1・SUP-7・SEC-4・#2043）: `--restart on-failure:1` でプローブが終了した後、
//!   常駐スレッドを止めて監視ループのスレッドで直接再 launch する。`restart_count` が 1 に進んで新しい pid で Running に戻り、
//!   2 回目の終了で Stopped（終了コード 7）・bin の終了コード 0 で終わる。ログ sink に `READY` が 2 回、`@audit.log` に seccomp の
//!   行がちょうど 2 行届く
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
//! captured, seccomp denial recorded once; failed start left no process; restart relaunched on the calling thread with restart_count 1 and both launches captured and audited; SIGTERM
//! via the control channel recorded Stopped(43) and the stopped container was deleted; ESC-03 mount denied via the
//! SeccompNotifyHub and recorded once`。
//! - シナリオ F〜H（pod の pid namespace を共有するコンテナの kill-all。CRI-2・SUP-1・SUP-3・SUP-9・CORE-4・#4811）: 試験が
//!   supervisor の bin の `pod-holder` で pod の user・ipc namespace を作り、その中へ `nsenter` した `unshare --pid --fork` で pod の
//!   pid namespace（PID 1 は `sleep`）を作る。config の `linux.namespaces` の user・ipc は保持役の、pid は `unshare` の
//!   `pid_for_children` の `/proc/<pid>/ns/*` を path で入れる（cri の `PodNamespacePaths` と同じ形。#4815 の pod-init の代わり）。プローブは孤児になる子（`--orphan-child`）を作ってから終わる・止まる。
//!   - F: 共有では init の自然終了の後に孤児が消え、supervisor の構造化ログ（`@supervisor-logs`）に `pid_shared_kill_all` の `killed` が 1 件出る。
//!     対照（pid の path なし）は孤児が pid ns ごと消え、`pid_shared_kill_all` の行が出ない
//!   - G: 共有で制御チャネルの SIGTERM による停止の後に孤児が消える
//!   - H: 共有でコンテナ cgroup の `cgroup.kill` を書けなくすると（0444）、`--restart on-failure:3` でも再 launch せず
//!     （`restart_count` 0・Stopped(7)）、bin が非 0 で終わり、孤児が残る（後始末で試験が止める）
//!
//! - シナリオ I（pid namespace の TARGET。CRI-2・CORE-3・SEC-1・SEC-5・#4819）: 同じ pod の user・ipc（保持役の path）に join し pid は
//!   path なしの 2 コンテナを同じ状態ルートに作り、対象 T を起動した後、N を `--pid-target <T>` で起動する（対象の launch pidfd は T の
//!   supervisor の制御チャネルから受け取る）。N の init が T の pid ns に居て PID 1 でなく、N の記録の `pod_pid_ns` が T の pid ns の
//!   素性（dev, ino）と一致し、T 自身の記録は `None` のままであることを具体値で照合する。対照として、存在しない対象は `NOT_FOUND`
//!   （`the pid namespace target does not exist`）、稼働中でない（Created の）対象は `FAILED_PRECONDITION`
//!   （`the pid namespace target is not running`）の固定文言で報告され、状態は Created のまま pid を持たない。最後に N・T の順に SIGTERM を
//!   送り、どちらもハンドラの終了コードで Stopped になる。成功行: `supervisor_bin_real: scenario=I ok (pid target: ...)`
//!
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
        if has("--orphan-child") {
            linux::orphan_child();
        } else if has("--orphan-probe") {
            linux::orphan_probe();
        } else if has("--orphan-term-probe") {
            linux::orphan_term_probe();
        } else if has("--pidns-is") {
            linux::pidns_probe();
        } else if has("--term-probe") {
            linux::term_probe();
        } else if has("--mount-probe") {
            linux::mount_probe();
        } else {
            linux::probe();
        }
    } else if has("--delete-helper") {
        linux::delete_helper();
    } else {
        // 前提欠如の分類の自己照合（既定のテスト集合でも常に走る。#2788・REPAIR-12）。
        linux::self_check_precondition();
        if has("--ignored") {
            linux::run();
        } else {
            println!(
                "supervisor_bin_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
        }
    }
}

// 最小 rootfs の組み立て部品は `exec_subordinate_e2e` と共有する（REPAIR-1・#2889）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/rootfs.rs"]
mod rootfs;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

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
    use fandhe_container_supervisor::stream_exec::channel::{
        HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
    };
    use fandhe_container_supervisor::stream_exec::helper::{StreamExecArgs, stream_exec_command};
    use fandhe_container_supervisor::stream_exec::wire::{StdioMask, StreamExecOutcome};

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

    /// 孤児になる子の寿命（シナリオ F〜H。親より長く生きる。REPAIR-5 のため有限）。
    const ORPHAN_LIFETIME: Duration = Duration::from_secs(120);
    /// 孤児を作るプローブが終わるまでの時間（シナリオ H は `cgroup.kill` を書けなくする時間に使う）。
    const ORPHAN_PROBE_LIFETIME: Duration = Duration::from_secs(4);

    /// 孤児になる子（`--orphan-child`）。親の終了後は pod の PID 1 へ付け替わる（#4811）。
    pub fn orphan_child() {
        std::thread::sleep(ORPHAN_LIFETIME);
        std::process::exit(0);
    }

    /// 親が config で渡した実行ごとのトークン（`--orphan-token <値>`）。孤児の argv に載せ、親が今回の実行の孤児だけを数える。
    fn orphan_token_arg() -> String {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .position(|a| a == "--orphan-token")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_default()
    }

    /// 孤児になる子を起動する（stdio はつながない。wait しない）。
    fn spawn_orphan() -> bool {
        Command::new("/probe")
            .args(["--container-probe", "--orphan-child"])
            .arg(orphan_token_arg())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }

    /// 孤児を作ってから `ORPHAN_PROBE_LIFETIME` 後に終了コード 7 で終わるプローブ（シナリオ F・H）。
    pub fn orphan_probe() {
        let mut out = std::io::stdout();
        if !spawn_orphan() {
            let _ = writeln!(out, "ORPHAN_SPAWN_FAILED");
            let _ = out.flush();
            std::process::exit(9);
        }
        let _ = writeln!(out, "READY");
        let _ = out.flush();
        std::thread::sleep(ORPHAN_PROBE_LIFETIME);
        std::process::exit(PROBE_EXIT);
    }

    /// exec で動かすプローブ（シナリオ G。#4813）: 自分の `/proc/self/ns/pid` が `--pidns-is` の値と一致すれば 0、
    /// 違えば `PIDNS_MISMATCH_EXIT`、読めなければ 9 で終わる。
    pub fn pidns_probe() {
        let args: Vec<String> = std::env::args().collect();
        let want = args
            .windows(2)
            .find(|w| w[0] == "--pidns-is")
            .map(|w| w[1].clone());
        let got = std::fs::read_link("/proc/self/ns/pid").ok();
        let code = match (want, got) {
            (Some(w), Some(g)) if g.to_string_lossy() == w => 0,
            (Some(_), Some(_)) => PIDNS_MISMATCH_EXIT,
            _ => 9,
        };
        std::process::exit(code);
    }

    /// `pidns_probe` の不一致の終了コード。
    const PIDNS_MISMATCH_EXIT: i32 = 3;
    /// シナリオ G の exec 全体の期限（REPAIR-5）。
    const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

    /// SIGTERM のハンドラを登録し、孤児を作ってから SIGTERM を待つプローブ（シナリオ G）。
    pub fn orphan_term_probe() {
        let mut out = std::io::stdout();
        if fandhe_container_core::exec::exit_on_sigterm_for_test().is_err() || !spawn_orphan() {
            let _ = writeln!(out, "ORPHAN_TERM_PROBE_FAILED");
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

    /// euid の前提の分類（#2788・SEC-4・REPAIR-12。純関数で自己照合する）。
    #[derive(Debug, PartialEq)]
    enum EuidCheck {
        NonRoot,
        /// root で実行されている（rootful start は拒否されるため前提欠如。試験環境の問題）。
        Root,
        /// 判定不能。前提欠如とは断定しない（fail-closed）。
        Unknown,
    }

    /// `/proc/self/status` の内容から euid（`Uid:` の 2 列目）を分類する。
    fn classify_euid(status: Option<&str>) -> EuidCheck {
        let euid = status
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:")))
            .and_then(|v| v.split_whitespace().nth(1));
        match euid {
            Some("0") => EuidCheck::Root,
            Some(v) if v.parse::<u32>().is_ok() => EuidCheck::NonRoot,
            _ => EuidCheck::Unknown,
        }
    }

    /// 前提欠如の panic メッセージ（1 行目で前提欠如と回帰を判別できる）。
    fn precondition_message() -> String {
        "supervisor_bin_real: PRECONDITION FAILED (test environment, not a supervisor launch regression): \
         must run as a non-root user (euid=0); rootful start is refused (SEC-5).\n\
         hint: run it as an unprivileged user (see AGENTS.md supervisor_bin_real for the --no-run and systemd-run --user --scope steps)."
            .to_string()
    }

    pub fn self_check_precondition() {
        assert_eq!(
            classify_euid(Some("Uid:\t1000\t1000\t1000\t1000\n")),
            EuidCheck::NonRoot
        );
        assert_eq!(
            classify_euid(Some("Uid:\t1000\t0\t0\t0\n")),
            EuidCheck::Root
        );
        assert_eq!(classify_euid(Some("Name:\tx\n")), EuidCheck::Unknown);
        assert_eq!(classify_euid(Some("Uid:\t0\tx\n")), EuidCheck::Unknown);
        assert_eq!(classify_euid(None), EuidCheck::Unknown);
        assert_eq!(
            precondition_message().lines().next(),
            Some(
                "supervisor_bin_real: PRECONDITION FAILED (test environment, not a supervisor launch regression): must run as a non-root user (euid=0); rootful start is refused (SEC-5)."
            )
        );
    }

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
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
        /// 孤児を作ってから終了コード 7 で終わる（シナリオ F・H。#4811）。
        Orphan,
        /// 孤児を作ってから SIGTERM を待つ（シナリオ G。#4811）。
        OrphanTerm,
    }

    impl Env {
        fn new(tag: &str, with_proc: bool, probe: Probe) -> Self {
            Self::with_pod(tag, with_proc, probe, None)
        }

        /// `pod` があれば config の user・ipc・pid を pod の namespace への join（path つき）にする（#4811）。
        fn with_pod(tag: &str, with_proc: bool, probe: Probe, pod: Option<&Pod>) -> Self {
            Self::build(tag, with_proc, probe, pod, true)
        }

        /// pod の user・ipc だけを path つきで join し、pid は path なし（自分の新しい pid ns。#4819 の TARGET の対象と、
        /// TARGET で参加する側の config）にする。
        fn with_pod_user_ipc(tag: &str, probe: Probe, pod: &Pod) -> Self {
            Self::build(tag, true, probe, Some(pod), false)
        }

        /// `with_pod` の本体。`pid_path` が偽なら pid の entry に path を付けない。
        fn build(
            tag: &str,
            with_proc: bool,
            probe: Probe,
            pod: Option<&Pod>,
            pid_path: bool,
        ) -> Self {
            let dir = Self::scratch_dir(tag);
            let bundle = dir.join("bundle");
            Self::write_bundle(&bundle, with_proc, probe, pod, pid_path);
            let root = dir.join("state");
            std::fs::create_dir(&root).expect("create state root");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("chmod state root");
            let store = open_default_store(Some(root)).expect("open the state store");
            Self { dir, store }
        }

        /// 一時ディレクトリ（`fandhe-supbinreal-<tag>-<pid>-<ns>`）を排他的に作る。
        fn scratch_dir(tag: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir =
                super::scratch_root::scratch_root("fandhe-supbinreal-scratch", REPORT_TIMEOUT)
                    .join(format!(
                        "fandhe-supbinreal-{tag}-{}-{nanos}",
                        std::process::id()
                    ));
            std::fs::create_dir(&dir).expect("exclusively create the work dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod work dir");
            dir
        }

        /// 同じ状態ルートに 2 つ目以降の bundle（`<dir>/<name>`）を足す（#4819。TARGET の対象と参加する側は同じ状態ルートを使う）。
        fn add_bundle(&self, name: &str, probe: Probe, pod: &Pod) {
            Self::write_bundle(&self.dir.join(name), true, probe, Some(pod), false);
        }

        /// `<dir>/<bundle_name>` の bundle で create する。
        fn create_in(&self, id: &str, bundle_name: &str) {
            let req =
                CreateRequest::new(cid(id), self.dir.join(bundle_name)).expect("create request");
            create(self.store.as_ref(), &OpRecorder::new(), &req).expect("create");
        }

        /// rootfs と config.json を持つ bundle を作る。
        fn write_bundle(
            bundle: &Path,
            with_proc: bool,
            probe: Probe,
            pod: Option<&Pod>,
            pid_path: bool,
        ) {
            let probe_args = match probe {
                Probe::Exit7 => r#""/probe","--container-probe""#,
                Probe::Term => r#""/probe","--container-probe","--term-probe""#,
                Probe::Mount => r#""/probe","--container-probe","--mount-probe""#,
                Probe::Orphan => {
                    r#""/probe","--container-probe","--orphan-probe","--orphan-token","TOKEN""#
                }
                Probe::OrphanTerm => {
                    r#""/probe","--container-probe","--orphan-term-probe","--orphan-token","TOKEN""#
                }
            }
            .replace("TOKEN", run_token());
            let pid_entry = match (pod, pid_path) {
                (Some(p), true) => {
                    format!(r#"{{"type":"pid","path":"{}"}}"#, p.ns("pid_for_children"))
                }
                _ => r#"{"type":"pid"}"#.to_owned(),
            };
            let namespaces = match pod {
                None => r#"{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"user"}"#
                    .to_owned(),
                Some(p) => format!(
                    r#"{pid_entry},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc","path":"{}"}},{{"type":"user","path":"{}"}}"#,
                    p.ns("ipc"),
                    p.ns("user")
                ),
            };
            std::fs::create_dir(bundle).expect("create bundle");
            let proc_dir = if with_proc {
                super::rootfs::ProcDir::Create
            } else {
                super::rootfs::ProcDir::Omit
            };
            let ld = super::rootfs::make_rootfs(&bundle.join("rootfs"), proc_dir);
            let config = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-supbin",
"process":{{"user":{{"uid":0,"gid":0}},"args":[{probe_args}],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{namespaces}]}}}}"#
            );
            std::fs::write(bundle.join("config.json"), config).expect("write config.json");
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
        spawn_supervisor_with(env, id, restart, &[])
    }

    /// [`spawn_supervisor`] に追加の argv（`<id>` の前に置くオプション。例: `--pid-target <ID>`）を足す版。
    fn spawn_supervisor_with(
        env: &Env,
        id: &str,
        restart: Option<&str>,
        extra: &[&str],
    ) -> Supervisor {
        let mut cmd = Command::new("systemd-run");
        cmd.args(fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS)
            .arg(BIN)
            .arg("start")
            .arg("--root")
            .arg(env.root());
        if let Some(policy) = restart {
            cmd.args(["--restart", policy]);
        }
        cmd.args(extra);
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
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を panic でも消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let status = std::fs::read_to_string("/proc/self/status").ok();
        match classify_euid(status.as_deref()) {
            EuidCheck::NonRoot => {}
            EuidCheck::Root => panic!("{}", precondition_message()),
            EuidCheck::Unknown => {
                panic!("supervisor_bin_real: could not determine euid from /proc/self/status")
            }
        }
        scenario_a_start_monitor_record();
        scenario_b_failed_start_leaves_nothing();
        scenario_c_restart_relaunch_succeeds();
        scenario_d_sigterm_stop_delete();
        scenario_e_esc03_mount_via_hub();
        scenario_f_pid_shared_natural_exit();
        scenario_g_pid_shared_stop();
        scenario_h_pid_shared_kill_all_failure();
        scenario_i_pid_target();
        println!(
            "supervisor_bin_real: start reported OK, NSpid ends with 1, monitor recorded Stopped({PROBE_EXIT}), logs captured, seccomp denial recorded once; failed start left no process; restart relaunched on the calling thread with restart_count 1 and both launches captured and audited; SIGTERM via the control channel recorded Stopped({TERM_HANDLER_EXIT}) and the stopped container was deleted; ESC-03 mount denied via the SeccompNotifyHub and recorded once"
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

    /// シナリオ C: restart の再 launch が本番 launcher で成り立つ(SUP-3・CORE-1・SUP-7・SEC-4・#2043)。
    ///
    /// `--restart on-failure:1` でプローブが終了コード 7 で終わると、supervisor は stderr・制御チャネル・捕捉・seccomp 通知の
    /// 常駐スレッドを止めて監視ループのスレッドで直接再 launch する。`restart_count` が 1 に進み、新しい pid で Running に戻り、
    /// 2 回目の終了(上限)で Stopped(7)・bin の終了コード 0 で終わる。ログ sink に READY が 2 回、`@audit.log` に seccomp の
    /// 行がちょうど 2 行(各起動の listener がハブへ渡り直っている)届く。
    fn scenario_c_restart_relaunch_succeeds() {
        let env = Env::new("c", true, Probe::Exit7);
        let id = format!("sbc{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, Some("on-failure:1"));
        let first_pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        // 再 launch の後の Running(restart_count = 1・別の pid)を期限つきで待つ。
        let deadline = Instant::now() + Duration::from_secs(30);
        let relaunched_pid = loop {
            let rec = env.record(&id);
            if rec.restart_count() == 1
                && rec.status().state() == ContainerState::Running
                && let Some(pid) = rec.status().pid()
            {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "the restart did not reach Running with restart_count 1: {:?}",
                rec.status()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_ne!(
            relaunched_pid, first_pid,
            "the relaunch must create a new process"
        );
        // 上限(1 回)に達しているので、2 回目の終了で再起動せずに終わる。
        assert_eq!(
            sup.exit_code(),
            0,
            "the supervisor must finish cleanly after the restart limit"
        );
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(PROBE_EXIT));
        assert_eq!(rec.restart_count(), 1);
        for pid in [first_pid, relaunched_pid] {
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "pid {pid} must be reaped"
            );
        }
        assert!(no_probe_remains(), "no probe process may remain");
        // 再起動をまたいで、両方の起動の出力が同じログ sink に残る(SUP-7)。
        let logs = fandhe_container_supervisor::logs::container_log_dir(&env.root());
        let ready_lines: usize = std::fs::read_dir(&logs)
            .expect("log directory")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&id))
            .map(|e| {
                std::fs::read_to_string(e.path())
                    .map(|t| t.lines().filter(|l| l.contains("READY")).count())
                    .unwrap_or(0)
            })
            .sum();
        assert_eq!(ready_lines, 2, "READY must be captured once per launch");
        // seccomp の通知は各起動の listener で応答され、拒否が 2 行届く(SEC-4)。
        let audit = std::fs::read_to_string(env.root().join("@audit.log")).unwrap_or_default();
        let seccomp_lines = audit
            .lines()
            .filter(|l| l.contains("\"layer\":\"seccomp\""))
            .count();
        assert_eq!(seccomp_lines, 2, "one seccomp record per launch: {audit:?}");
        println!(
            "supervisor_bin_real: scenario=C ok first_pid={first_pid} relaunched_pid={relaunched_pid}"
        );
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

    // ---- シナリオ F〜H（pod の pid namespace の共有と kill-all。CRI-2・SUP-1・SUP-3・SUP-9・CORE-4・#4811） ----

    /// 試験が作る pod の user・ipc・pid namespace（cri の保持役の代わり）。
    ///
    /// user・ipc は supervisor の bin の `pod-holder`（start と同じ規則で写像を決める。#2874）が作り、pid は保持役の
    /// user・ipc へ `nsenter` した `unshare --pid --fork` が作る（pid ns の所有者が pod の userns になる。PID 1 は `sleep`）。
    /// core は参加先の userns の写像が起動の写像と完全一致することを要求するため、写像は保持役に任せる。
    /// drop で `unshare` を止め（`--kill-child` で PID 1 も止まる）、保持役の stdin を閉じて終わらせる。
    struct Pod {
        holder: Child,
        pid_owner: Child,
    }

    impl Pod {
        #[allow(
            clippy::zombie_processes,
            reason = "返した Pod の drop が kill と wait を行う"
        )]
        fn new() -> Self {
            use std::os::fd::AsFd as _;
            let mut holder = Command::new(BIN)
                .arg("pod-holder")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn the pod holder");
            let out = holder.stdout.take().expect("holder stdout");
            let ready = fandhe_container_supervisor::pod_holder::read_ready(
                out.as_fd(),
                Instant::now() + Duration::from_secs(30),
            );
            drop(out);
            let h = holder.id();
            if let Err(e) = ready {
                reap_bounded(&mut holder, Duration::ZERO);
                panic!("the pod holder did not report READY: {e:?}");
            }
            let mut pid_owner = Command::new("nsenter")
                .arg(format!("--user=/proc/{h}/ns/user"))
                .arg(format!("--ipc=/proc/{h}/ns/ipc"))
                .args([
                    "unshare",
                    "--pid",
                    "--fork",
                    "--kill-child",
                    "/bin/sleep",
                    "600",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn nsenter (util-linux)");
            let pid = pid_owner.id();
            // `unshare` へ exec して PID 1 を fork し終えるまで期限つきで待つ（REPAIR-5）。
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let forked = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                    .is_ok_and(|c| !c.trim().is_empty());
                let own = ns_link("/proc/self/ns/pid");
                let pod = ns_link(&format!("/proc/{pid}/ns/pid_for_children"));
                if forked && !pod.is_empty() && pod != own {
                    return Self { holder, pid_owner };
                }
                if Instant::now() >= deadline {
                    reap_bounded(&mut pid_owner, Duration::ZERO);
                    reap_bounded(&mut holder, Duration::ZERO);
                    panic!("the pod pid namespace was not ready within 10s");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// user・ipc は保持役、pid（`pid_for_children`）は `unshare` のパス。
        fn ns(&self, kind: &str) -> String {
            let pid = if kind == "pid_for_children" {
                self.pid_owner.id()
            } else {
                self.holder.id()
            };
            format!("/proc/{pid}/ns/{kind}")
        }

        /// pod の pid ns の識別子（`pid:[<inode>]`）。
        fn pid_ns(&self) -> String {
            ns_link(&self.ns("pid_for_children"))
        }
    }

    impl Drop for Pod {
        fn drop(&mut self) {
            reap_bounded(&mut self.pid_owner, Duration::ZERO);
            // 停止の合図は stdin の EOF。期限内に終わらなければ kill する。
            drop(self.holder.stdin.take());
            reap_bounded(&mut self.holder, Duration::from_secs(10));
        }
    }

    fn ns_link(path: &str) -> String {
        std::fs::read_link(path)
            .map(|l| l.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// 実行ごとのトークン（pid と起動時刻）。孤児の argv に載せ、並行実行・以前の実行の残りと区別する。
    fn run_token() -> &'static str {
        static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        TOKEN.get_or_init(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("sbr{}x{nanos}", std::process::id())
        })
    }

    /// 今回の実行の孤児（argv が `--orphan-child <トークン>` を含む）のホストの pid（ゾンビは cmdline が空なので数えない）。
    fn orphan_pids() -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        dir.flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| {
                    let args: Vec<&[u8]> = c.split(|b| *b == 0).collect();
                    args.windows(2)
                        .any(|w| w[0] == b"--orphan-child" && w[1] == run_token().as_bytes())
                })
            })
            .collect()
    }

    /// 子を期限つきで回収する。`grace` の間に終わらなければ kill し、さらに 10 秒まで回収を確かめる（REPAIR-5）。
    fn reap_bounded(child: &mut Child, grace: Duration) {
        let wait_until = |limit: Duration, child: &mut Child| {
            let deadline = Instant::now() + limit;
            while Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        };
        if wait_until(grace, child) {
            return;
        }
        let _ = child.kill();
        if !wait_until(Duration::from_secs(10), child) {
            eprintln!(
                "supervisor_bin_real: child {} was not reaped within 10s after kill",
                child.id()
            );
        }
    }

    /// 孤児の数が `want` になるまで期限つきで待ち、最後の観測を返す。
    fn wait_orphans(want: usize, limit: Duration) -> Vec<u32> {
        let deadline = Instant::now() + limit;
        loop {
            let now = orphan_pids();
            if now.len() == want || Instant::now() >= deadline {
                return now;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// supervisor の構造化ログ（bin の入口が `<状態ルート>/@supervisor-logs/<id>.log*` へ差し替える。#2067）のうち、
    /// `pid_shared_kill_all` の行（1 行 1 JSON）だけを取り出す。
    fn kill_all_lines(env: &Env, id: &str) -> Vec<String> {
        let dir = env
            .root()
            .join(fandhe_container_supervisor::supervisor_log::SUPERVISOR_LOG_DIR_NAME);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{id}.log"))
            })
            .flat_map(|e| {
                std::fs::read_to_string(e.path())
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| l.contains(r#""event":"pid_shared_kill_all""#))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// pod の pid ns を共有する起動で、孤児が pod の pid ns に居ることを確かめて pid を返す。
    fn shared_orphan(pod: &Pod) -> u32 {
        let orphans = wait_orphans(1, Duration::from_secs(30));
        let [orphan] = orphans.as_slice() else {
            panic!("exactly one orphan must appear: {orphans:?}");
        };
        assert_eq!(
            ns_link(&format!("/proc/{orphan}/ns/pid")),
            pod.pid_ns(),
            "the orphan must live in the pod pid namespace"
        );
        *orphan
    }

    /// シナリオ F: 共有では init の自然終了の後に kill-all が孤児を止める。対照（pid の path なし）は pid ns ごと消え、
    /// kill-all の行が出ない（#4811）。
    fn scenario_f_pid_shared_natural_exit() {
        // 対照: pid を共有しない。
        let env = Env::new("f0", true, Probe::Orphan);
        let id = format!("sbf0{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        assert!(matches!(sup.report(), StartReport::Started { .. }));
        assert_eq!(wait_orphans(1, Duration::from_secs(30)).len(), 1);
        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        assert_eq!(env.record(&id).status().exit_code(), Some(PROBE_EXIT));
        assert_eq!(wait_orphans(0, Duration::from_secs(10)), Vec::<u32>::new());
        assert_eq!(kill_all_lines(&env, &id), Vec::<String>::new());

        // 共有: pod の pid ns へ join する。
        let pod = Pod::new();
        let env = Env::with_pod("f1", true, Probe::Orphan, Some(&pod));
        let id = format!("sbf1{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        assert_eq!(
            ns_link(&format!("/proc/{pid}/ns/pid")),
            pod.pid_ns(),
            "the init must join the pod pid namespace"
        );
        shared_orphan(&pod);
        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(PROBE_EXIT));
        // kill-all は終了の記録の前に走るため、記録を見た時点で孤児は居ない。
        assert_eq!(orphan_pids(), Vec::<u32>::new());
        let lines = kill_all_lines(&env, &id);
        assert!(
            lines
                .iter()
                .any(|l| l.contains(r#""outcome":"killed","killed":1,"#)),
            "kill-all must report one killed process: {lines:?}"
        );
        println!(
            "supervisor_bin_real: scenario=F ok (pid shared: the orphan was killed by kill-all after the init exited; not shared: it ended with the pid namespace and no kill-all ran)"
        );
    }

    /// シナリオ G: 共有で launch pidfd の経路の exec が pod の pid ns で動き（#4813）、制御チャネルの SIGTERM による停止の後に
    /// 孤児が消える（#4811）。
    fn scenario_g_pid_shared_stop() {
        let pod = Pod::new();
        let env = Env::with_pod("g", true, Probe::OrphanTerm, Some(&pod));
        let id = format!("sbg{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        shared_orphan(&pod);
        wait_sigterm_handler(pid.get());
        // pod の pid ns の PID 1 ではない init へ、本番の exec の経路（CRI の Exec と同じ stream-exec helper。launch pidfd で
        // 対象を固定する）が入り、コマンドが pod の pid ns で動く。対照は期待をホストの pid ns にした不一致（#4813）。
        let nspid = status_field(&format!("/proc/{pid}/status"), "NSpid:").unwrap_or_default();
        assert_ne!(
            nspid.split_whitespace().last(),
            Some("1"),
            "the shared init must not be PID 1 of the pod pid namespace: NSpid={nspid}"
        );
        let outcome = exec_pidns_probe(&env, &id, pid, &pod.pid_ns());
        if outcome != StreamExecOutcome::Exited(0) {
            dump_exec_diag(&env, &id);
        }
        assert_eq!(
            outcome,
            StreamExecOutcome::Exited(0),
            "exec into the shared container must run in the pod pid namespace"
        );
        assert_eq!(
            exec_pidns_probe(&env, &id, pid, &ns_link("/proc/self/ns/pid")),
            StreamExecOutcome::Exited(PIDNS_MISMATCH_EXIT as u8),
            "the probe must tell the host pid namespace apart"
        );
        let signaler: Arc<dyn ProcessSignaler> = Arc::new(ControlSignaler::for_stop(env.root()));
        kill(
            env.store.as_ref(),
            &OpRecorder::new(),
            &signaler,
            &KillRequest::new(cid(&id), Signal::SIGTERM),
            &KillTimeout::default(),
        )
        .unwrap_or_else(|e| panic!("kill(SIGTERM) via the control channel failed: {e:?}"));
        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(TERM_HANDLER_EXIT));
        assert_eq!(orphan_pids(), Vec::<u32>::new());
        let lines = kill_all_lines(&env, &id);
        assert!(
            lines
                .iter()
                .any(|l| l.contains(r#""outcome":"killed","killed":1,"#)),
            "kill-all must report one killed process: {lines:?}"
        );
        println!(
            "supervisor_bin_real: scenario=G ok (pid shared: exec via the launch pidfd ran in the pod pid namespace; stopping via the control channel left no orphan)"
        );
    }

    /// 起動に失敗する `--pid-target` の対照: 報告が `Failed`（`code`・固定文言の完全一致）で、bin が非 0 で終わり、状態は Created のまま
    /// pid を持たない（#4819。固定文言に ID・pid・パスを含めない）。
    fn assert_pid_target_refused(
        env: &Env,
        id: &str,
        target: &str,
        want_code: ErrorCode,
        want_message: &str,
    ) {
        let mut sup = spawn_supervisor_with(env, id, None, &["--pid-target", target]);
        match sup.report() {
            StartReport::Failed {
                code,
                exit_code,
                message,
            } => {
                assert_eq!(code, want_code, "{target}");
                assert_eq!(message.as_str(), want_message, "{target}");
                assert_eq!(sup.exit_code(), i32::from(exit_code.get()));
            }
            other => panic!("expected ERR for target {target}, got {other:?}"),
        }
        let rec = env.record(id);
        assert_eq!(rec.status().state(), ContainerState::Created);
        assert!(rec.status().pid().is_none());
    }

    /// シナリオ I: pid namespace の TARGET（`--pid-target <ID>`）で、対象コンテナの pid ns へ参加して起動する
    /// （CRI-2・CORE-3・SEC-1・SEC-5・#4819）。
    ///
    /// 同じ pod の user・ipc（保持役の path）に join し pid は path なしの 2 コンテナを同じ状態ルートで作る。対象 T は自分の新しい
    /// pid ns の PID 1、N は `--pid-target T` で T の pid ns へ参加する（対象の launch pidfd は T の supervisor の制御チャネルから受け取る）。
    /// 照合: N の init が T の pid ns に居て PID 1 でない・N の記録の `pod_pid_ns` が T の pid ns の素性と一致する（exec・kill-all の
    /// 下流は #4813・#4811 の経路）。対照: 存在しない対象と、稼働中でない（Created の）対象は固定文言で拒否される。
    fn scenario_i_pid_target() {
        use std::os::unix::fs::MetadataExt as _;
        let pod = Pod::new();
        let env = Env::with_pod_user_ipc("i", Probe::Term, &pod);
        env.add_bundle("bundle-n", Probe::Term, &pod);
        let pid = std::process::id();
        let (target_id, joiner_id) = (format!("sbit{pid}"), format!("sbin{pid}"));
        env.create(&target_id);
        env.create_in(&joiner_id, "bundle-n");
        let mut target_sup = spawn_supervisor(&env, &target_id, None);
        let t_pid = match target_sup.report() {
            StartReport::Started { pid } => pid.get(),
            other => panic!("expected OK for the target, got {other:?}"),
        };
        wait_sigterm_handler(t_pid);
        let t_ns = ns_link(&format!("/proc/{t_pid}/ns/pid"));
        assert_ne!(t_ns, ns_link("/proc/self/ns/pid"));
        assert_ne!(t_ns, pod.pid_ns(), "the target owns a new pid namespace");
        let t_nspid = status_field(&format!("/proc/{t_pid}/status"), "NSpid:").unwrap_or_default();
        assert_eq!(
            t_nspid.split_whitespace().last(),
            Some("1"),
            "NSpid={t_nspid}"
        );

        // 参加する側（N）。
        let mut joiner_sup =
            spawn_supervisor_with(&env, &joiner_id, None, &["--pid-target", &target_id]);
        let n_pid = match joiner_sup.report() {
            StartReport::Started { pid } => pid.get(),
            other => panic!("expected OK for the joiner, got {other:?}"),
        };
        wait_sigterm_handler(n_pid);
        assert_eq!(
            ns_link(&format!("/proc/{n_pid}/ns/pid")),
            t_ns,
            "the joiner init must live in the target pid namespace"
        );
        let n_nspid = status_field(&format!("/proc/{n_pid}/status"), "NSpid:").unwrap_or_default();
        assert_ne!(
            n_nspid.split_whitespace().last(),
            Some("1"),
            "the joiner init must not be PID 1 of the target pid namespace: NSpid={n_nspid}"
        );
        let meta =
            std::fs::metadata(format!("/proc/{t_pid}/ns/pid")).expect("stat the target pid ns");
        let rec = env.record(&joiner_id);
        assert_eq!(
            rec.launch_isolation().and_then(|i| i.pod_pid_ns()),
            Some((meta.dev(), meta.ino())),
            "the launch record must hold the target pid namespace identity"
        );
        assert_eq!(
            env.record(&target_id)
                .launch_isolation()
                .and_then(|i| i.pod_pid_ns()),
            None,
            "the target keeps its own pid namespace"
        );

        // 対照: 存在しない対象・稼働中でない対象は、固定文言で拒否される。
        let missing = format!("sbim{pid}");
        let refused_a = format!("sbia{pid}");
        let refused_b = format!("sbib{pid}");
        env.add_bundle("bundle-a", Probe::Term, &pod);
        env.add_bundle("bundle-b", Probe::Term, &pod);
        env.create_in(&refused_a, "bundle-a");
        env.create_in(&refused_b, "bundle-b");
        assert_pid_target_refused(
            &env,
            &refused_a,
            &missing,
            ErrorCode::NotFound,
            "the pid namespace target does not exist",
        );
        // `refused_b` は Created のまま。`refused_a`（Created に戻った）を稼働中でない対象として指す。
        assert_pid_target_refused(
            &env,
            &refused_b,
            &refused_a,
            ErrorCode::FailedPrecondition,
            "the pid namespace target is not running",
        );

        // 停止: 参加した側 → 対象の順に SIGTERM を送り、どちらもハンドラの終了コードで Stopped になる。
        let signaler: Arc<dyn ProcessSignaler> = Arc::new(ControlSignaler::for_stop(env.root()));
        for (id, sup) in [(&joiner_id, &mut joiner_sup), (&target_id, &mut target_sup)] {
            kill(
                env.store.as_ref(),
                &OpRecorder::new(),
                &signaler,
                &KillRequest::new(cid(id), Signal::SIGTERM),
                &KillTimeout::default(),
            )
            .unwrap_or_else(|e| panic!("kill(SIGTERM) via the control channel failed: {e:?}"));
            assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
            let rec = env.record(id);
            assert_eq!(rec.status().state(), ContainerState::Stopped);
            assert_eq!(rec.status().exit_code(), Some(TERM_HANDLER_EXIT));
        }
        println!(
            "supervisor_bin_real: scenario=I ok (pid target: the joiner init lived in the target pid namespace as a non-PID-1 process and recorded its identity; a missing target and a not-running target were refused with fixed messages)"
        );
    }

    /// exec の失敗の診断として、supervisor の構造化ログと `@audit.log` の末尾を stderr へ出す（#4813）。
    fn dump_exec_diag(env: &Env, id: &str) {
        let logs = env
            .root()
            .join(fandhe_container_supervisor::supervisor_log::SUPERVISOR_LOG_DIR_NAME);
        let mut files: Vec<PathBuf> = std::fs::read_dir(&logs)
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        files.push(env.root().join("@audit.log"));
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            let tail = &lines[lines.len().saturating_sub(40)..];
            eprintln!(
                "supervisor_bin_real: diag {} ({id}, last {} lines)",
                f.display(),
                tail.len()
            );
            for l in tail {
                eprintln!("supervisor_bin_real: diag | {l}");
            }
        }
    }

    /// stream-exec helper（supervisor の bin の再実行。plugin-cri の Exec と同じ経路。委譲 scope で包む）で
    /// `/probe --pidns-is <want>` を実行し、`Result` の値を返す。stdio は渡さない（mask 0）。helper は期限つきで回収する（REPAIR-5・#4813）。
    fn exec_pidns_probe(
        env: &Env,
        id: &str,
        pid: std::num::NonZeroU32,
        want: &str,
    ) -> StreamExecOutcome {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let args = StreamExecArgs::new(
            env.root().to_path_buf(),
            cid(id),
            pid,
            EXEC_TIMEOUT,
            StdioMask::new(0).expect("empty stdio mask"),
            vec![
                "/probe".into(),
                "--container-probe".into(),
                "--pidns-is".into(),
                want.into(),
            ],
        )
        .expect("stream-exec args");
        let (plugin, helper_end) = UnixStream::pair().expect("socketpair");
        // helper は exec の子 cgroup へ自分を移すため、supervisor と同じ委譲 scope の包みの中で動かす（委譲の外からでは
        // 移動元と移動先の共通祖先の `cgroup.procs` に書けず EACCES になる。本番では plugin-cri が委譲 scope に居る）。
        // 引数は本番の `stream_exec_command` が組んだものをそのまま使う。
        let helper = stream_exec_command(Path::new(BIN), &args);
        let mut command = Command::new("systemd-run");
        command
            .args(fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS)
            .arg(BIN)
            .args(helper.get_args())
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .expect("spawn the stream-exec helper (is `systemd-run --user` available?)");
        // `command` が持つ子側の端は親に残さない（helper の終了で EOF になるように）。
        drop(command);
        let deadline = Instant::now() + EXEC_TIMEOUT;
        if let Err(e) = send_stdio_handover(&plugin, &StdioSend::default(), deadline) {
            reap_bounded(&mut child, Duration::ZERO);
            panic!("send the stdio handover: {e:?}");
        }
        let outcome = loop {
            match recv_from_helper(&plugin, deadline) {
                Ok(HelperMessage::Result(o)) => break o,
                Ok(_) => {}
                Err(e) => {
                    reap_bounded(&mut child, Duration::ZERO);
                    panic!("the exec channel failed before the result: {e:?}");
                }
            }
        };
        reap_bounded(&mut child, Duration::from_secs(10));
        outcome
    }

    /// シナリオ H: 共有で `cgroup.kill` を書けなくすると kill-all が失敗し、`--restart on-failure:3` でも再 launch しない
    /// （旧い世代の孤児が残る cgroup に新しい init を起動しない。#4811）。
    fn scenario_h_pid_shared_kill_all_failure() {
        let pod = Pod::new();
        let env = Env::with_pod("h", true, Probe::Orphan, Some(&pod));
        let id = format!("sbh{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, Some("on-failure:3"));
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let orphan = shared_orphan(&pod);
        // init のコンテナ cgroup（cgroup v2 の 1 行 `0::<path>`）の `cgroup.kill` を書けなくする。
        let rel = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .expect("read the init cgroup")
            .lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
            .expect("cgroup v2 path");
        let kill_file = PathBuf::from("/sys/fs/cgroup")
            .join(rel.trim_start_matches('/'))
            .join("cgroup.kill");
        std::fs::set_permissions(&kill_file, std::fs::Permissions::from_mode(0o444))
            .expect("make cgroup.kill read-only");
        let code = sup.exit_code();
        let rec = env.record(&id);
        let remaining = orphan_pids();
        // 後始末: 書き込みを戻して試験自身が止める（照合の前に行い、失敗でも孤児を残さない）。
        let _ = std::fs::set_permissions(&kill_file, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::write(&kill_file, "1");
        let after = wait_orphans(0, Duration::from_secs(10));
        assert_ne!(code, 0, "the supervisor must report the kill-all failure");
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(PROBE_EXIT));
        assert_eq!(
            rec.restart_count(),
            0,
            "no relaunch after a kill-all failure"
        );
        assert_eq!(
            remaining,
            vec![orphan],
            "the orphan remains when kill-all fails"
        );
        assert_eq!(after, Vec::<u32>::new(), "cleanup must stop the orphan");
        let lines = kill_all_lines(&env, &id);
        assert!(
            lines.iter().any(|l| l.contains(r#""outcome":"failed""#)),
            "kill-all must report the failure: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains(r#""outcome":"killed""#)),
            "nothing may be killed: {lines:?}"
        );
        println!(
            "supervisor_bin_real: scenario=H ok (pid shared: a kill-all failure stopped the restart loop with restart_count 0)"
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
