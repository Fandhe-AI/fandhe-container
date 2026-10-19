//! 本番 `ProcessLauncher`（`oci_runtime::ProductionLauncher`）を `create` → `start` 経由で実プロセスに通す結合試験
//! （CORE-1・CORE-2・CORE-5・SEC-1・SEC-5・REPAIR-3・REPAIR-12。TASK-29 追補・#1818）。
//!
//! 既存の `oci_start.rs` / `oci_lifecycle.rs` は launcher が模擬、`rootless.rs` は自前の代役 init で、
//! 本番 launcher を実プロセスで通した試験が無かった。本試験は `start` が検証して組み立てた `LaunchSpec` を
//! 本番 launcher が中間プロセス経由で PID 1 として起動するところまでを、親から具体値で照合する。
//!
//! # 照合項目
//! - シナリオ A（正常起動。非 root）: `StartedContainer` の状態が Running で pid が `process().pid()` と一致する。
//!   ホストの `/proc/<pid>/status` の `NSpid` 末尾が 1。コンテナ内プローブ（stdout の固定語彙の行）で、
//!   PID 1・hostname・既定 `/dev` ノード 6 種の種別と `rdev`・symlink 4 本・`/dev/null` 書き込み・`/dev/zero` 読み出し・
//!   `NoNewPrivs: 1`・`Seccomp: 2`（制限ステージ適用の間接証拠）を照合する。cgroup はホストの `/proc/<pid>/cgroup` と
//!   プローブ内の `/proc/self/cgroup` が、作成した子 cgroup と完全一致する。終了後は回収され `/proc/<pid>` が消える
//! - シナリオ B（起動失敗で何も残らない。#1817）: rootfs から `proc/` を除いて pre-pivot 段を失敗させ、`start` が
//!   `Err`・状態が Created に戻る・`last_launch_may_have_left_process() == false`・`confirm_no_process` が `Ok`・
//!   テストプロセスの子が 0 件であることを照合する
//! - シナリオ C（拒否に副作用が無い）: 補助スレッドが生きている状態の `start` が `FailedPrecondition`（単一スレッド要求。
//!   CORE-1）で拒否され、状態が Created のままで子が作られないことを照合する
//! - シナリオ D（bind mount。#1915）: `mounts[]` に `/data` の bind（`rw`）を指定して start し、コンテナ内プローブが
//!   `/data` へ固定の内容を書く。親はホスト側の元ディレクトリに同じ内容のファイルが現れることを完全一致で、
//!   mountinfo 上の `/data` のオプションに `rw`・`nosuid`・`nodev` が含まれることを照合する
//! - シナリオ E（状態ルートの bind 拒否。#2066・SEC-1）: 状態ルート自身とその symlink 別名を bind の元にした start が
//!   `InvalidArgument` で拒否され、状態が Created のまま子が残らないことを照合する
//! - シナリオ F（Landlock の Mount 識別子照合。#2071・CORE-5・SEC-1）: `linux.readonlyPaths` に `/dev` を足し、
//!   記録（`RealPrePivotOps`）より後に `/dev` へ別のマウントが重なる起動が、Landlock 適用時の照合で拒否されて
//!   失敗し、状態が Created のまま子が残らないことを照合する。記録と一致する側はシナリオ A・D の成功が担う
//! - シナリオ G（devtmpfs の bind 拒否。#2129・SEC-1）: ホストの `/dev`（fstype `devtmpfs`。`f_type` は tmpfs と同じで見分けられない）を
//!   `bind` / `rbind` で元にした start が、付け替えた自分のマウントの mountinfo の fstype 名で拒否される。起動は失敗し、
//!   状態が Created のまま子が残らず、後始末で bind 先（rootfs 内の `/data`）が残らないことを照合する
//! - シナリオ H（start 後の状態ルート移動。#2129・SEC-1）: start が状態ルートを固定した後、launcher が子を作る前に
//!   状態ルートを別名へ改名して同じパスに別の inode の複製を置くと、適用の段が記録パスを辿り直して食い違いを検出し fail-closed で拒否する。
//!   状態ルートが動かない場合に受理される側はシナリオ D が担う。状態が Created のまま子が残らず、bind 先も残らないことを照合する
//! - シナリオ I（範囲写像。`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ。CORE-6・SEC-5・#2009）: `RootlessSubordinateIds` の
//!   launcher（`SubordinateIdSource::system(USER)`）で start し、ホストから読んだ PID 1 の `uid_map` / `gid_map` が
//!   `/etc/subuid`・`/etc/subgid` の範囲写像（コンテナ 0 → 自 ID、コンテナ 1 以上 → subuid / subgid の範囲の先頭）と
//!   完全一致することを照合する。opt-in 時に前提（`uidmap`・自ユーザーの subuid / subgid 行・`USER`）が無ければ失敗とする。
//!   root で実行された場合は、この launcher の構築が `PermissionDenied`（SEC-5）で拒否されることだけを照合する
//! - シナリオ J（exec 後の capability と seccomp の実効。#2012・SEC-1・CORE-5）: コンテナ内プローブ（`--with-restrictions`）の
//!   `/proc/self/status` が `CapInh`・`CapAmb` = 0、`CapPrm`・`CapEff`・`CapBnd` = `0x0000_0000_a804_25fb`（OCI 既定の 14 個。
//!   公開 API の `OCI_DEFAULT_CAPABILITIES` から組んだマスクとリテラルの両方と照合）で、ホストから見た同プロセスの
//!   `/proc/<pid>/status` も同値であることを照合する。seccomp は、`mount(2)` が `EPERM`（`escape_probe_mount`。capability 不足でも
//!   `EPERM` になり得るため網羅確認）、許可された `openat` / `read`（`/proc/thread-self/status`）が成功する対照、
//!   `NoNewPrivs: 1`・`Seccomp: 2` を照合する
//! - シナリオ K（exec 後の seccomp の識別的な拒否。#2012・SEC-2・CORE-5）: コンテナ内プローブ（`--seccomp-kill <name>`）が
//!   `unshare` / `ptrace` / `kexec_load` を 1 件ずつ別の start で発行し、`ProcessExit::Signaled(31)`（SIGSYS。
//!   `SECCOMP_RET_KILL_PROCESS`）で終了することを照合する。フィルタが無ければ `unshare(0)` は成功して戻るため識別的になる
//! - シナリオ P（名前だけの `process.args[0]`。#2314・OCI-1・TASK-55 追補）: `args[0]` が `probe`（`/` 無し）、`process.env` の
//!   `PATH` が `/nonexistent:/opt/bin:/usr/local/bin` で、`/opt/bin/probe` は実行ビット無し・`/usr/local/bin/probe` が実行可能
//!   （`/probe` は削除して絶対パスの経路を断つ）。pivot 後に解決されて PID 1 として起動し、コンテナ内プローブが `READY` を
//!   出して終了コード 7（`ProcessExit::Exited(7)`）で終わることを照合する。`PATH` のどこにも無い名前は `start` の失敗
//!   （状態は Created のまま）か終了コード 127 で、成功起動にならず子も残らない
//! - root で実行された場合: 主経路は非 root（SEC-5）。launch が拒否され、状態が Created に戻り、子が残らないことだけを
//!   照合する（コンテナ内 root をホスト root へ写す起動は試さない）
//!
//! # 必要環境
//! - Linux 6.12 以上（Landlock ABI 6 以上。満たさないと launcher が起動を拒否するため、本試験は失敗する。CORE-5）
//! - 非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=0` 等の緩和が要る場合がある）
//! - 非特権ユーザーに委譲された cgroup v2 サブツリー（`DelegatedCgroup::detect` が成功すること）
//! - 動的リンクのためホストの共有ライブラリを rootfs へコピーする（ネットワークは不要）
//!
//! # 実機前提テストとしての分離
//! 上記の環境は GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行する（ci.md「実機前提
//! テスト」。既定集合で動くはずの試験を移したものではない）。実行された場合は user namespace の拒否・Landlock ABI
//! 不足・cgroup の委譲無しを含むあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。同一 cgroup に他
//! プロセスがいると `prepare` が失敗するため、`cargo` を経由せず委譲スコープの中でビルド済みバイナリを直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test production_launcher --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/production_launcher-XXXX> --ignored
//! ```
//!
//! シナリオ I（範囲写像）は `uidmap` パッケージ（`/usr/bin/newuidmap`・`/usr/bin/newgidmap`）と `/etc/subuid`・
//! `/etc/subgid` の自ユーザー行が要るため、`FANDHE_CONTAINER_TEST_ID_HELPER=1` を付けた時だけ実行する。実行時は成功行の前に
//! `production_launcher: subordinate id mapping verified (uid extents=N, gid extents=M)` を出す。
//!
//! 成功時の最終行: `production_launcher: pid1, default /dev nodes, landlock evidence, cgroup join verified; failed
//! launch left no process; bind mount visible on host; post-exec capabilities and seccomp verified (root=false)`（root 実行時は拒否のみ照合する旨の別の行）。
//!
//! # 既知の制約（REPAIR-3）
//! - Landlock の適用は、コンテナ内で `NoNewPrivs`・`Seccomp` を読む間接証拠に留まる。パス単位の拒否を直接観測する
//!   には `core` の公開 API の追加が要るため、本試験の範囲外（`landlock_implicit_dev` 等が単体で観測している）。
//!   capability と seccomp の実効はシナリオ J・K が exec 後のプロセスで直接照合する
//! - seccomp の識別は、シナリオ J の exec 後の `kcmp` の `EPERM`（test 限定の入口 `probe_denied_syscalls_for_test`。
//!   適用前の `kcmp` 対照は親側で要求し、満たさなければ前提欠如として失敗）とシナリオ K の SIGSYS が担う。`mount` の `EPERM` は網羅確認
//! - bind 以外の `mounts[]` の種類、`ro` の bind（#1917）、段ごとの個別観測（#1916）、`linux.resources`、
//!   supervisor 経由の起動（#1819）は対象外
//! - 実機での実行結果の記録は #1621（Phase 3 の分離系結合試験の実機実行。人間担当）

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("production_launcher: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("production_launcher: x86_64/aarch64 only, not applicable on this architecture");
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
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "production_launcher: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::capabilities::OCI_DEFAULT_CAPABILITIES;
    use fandhe_container_core::cgroups::{CgroupName, ContainerCgroup, DelegatedCgroup};
    use fandhe_container_core::exec::{
        EscapeSyscallProbe, IsolationPrivilege, ProbeOutcome, SeccompProbeRecord,
        escape_probe_mount, probe_denied_syscalls_for_test, probe_escape_syscall,
        probe_kcmp_self_for_test,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ProcessExit, ProcessLauncher, ProductionLauncher, StartTimeouts, SubordinateIdSource,
        create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateStore, TraitError,
    };
    use serde_json::json;

    /// launcher が子を作る直前（`cgroup_join_source` の呼び出し時。start の検証より後）に 1 回だけ実行する処理
    /// （シナリオ H が状態ルートを改名する。#2129）。
    type PreSpawnHook = Box<dyn FnOnce() + Send>;
    static PRE_SPAWN_HOOK: std::sync::Mutex<Option<PreSpawnHook>> = std::sync::Mutex::new(None);

    /// コンテナ内の hostname（config と照合する固有値）。
    const HOSTNAME: &str = "fandhe-prod-launcher";
    /// プローブが `READY` を出した後に待ち続ける（親が terminate するまで生存させる）。
    const PROBE_READY: &str = "READY";
    /// シナリオ D でコンテナ内が bind 先へ書く固定の内容（親がホスト側の同名ファイルと完全一致で照合する）。
    const BIND_CONTENT: &str = "written inside the container\n";
    /// シナリオ D の bind 先のコンテナ内パスと、書くファイル名。
    const BIND_DEST: &str = "/data";
    const BIND_FILE: &str = "from-container";
    /// 1 行の長さの上限（無制限確保を避ける。REPAIR-5 と同趣旨）。
    const LINE_MAX: u64 = 4096;
    /// 受け取る行数の上限。
    const LINES_MAX: usize = 256;

    /// 1 件の待ちの上限。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（未設定・不正値は 10 秒）。`StartTimeouts` が
    /// `START_TIMEOUT_MAX`（600 秒）以下を要求するため 295 秒に丸める。
    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s >= 1)
            .map_or(10, |s| s.min(295));
        Duration::from_secs(secs)
    }

    fn timeouts() -> StartTimeouts {
        let t = timeout();
        StartTimeouts::new(t, t, t).expect("start timeouts")
    }

    fn is_root() -> bool {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    /// `/proc/<x>/status` 形式のファイルから、`key` で始まる行の値（key の後ろ）を返す。
    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    /// 呼び出しプロセスの子（全スレッド分）の pid 一覧。
    fn children_of_self() -> Vec<String> {
        let mut out = Vec::new();
        let tasks = std::fs::read_dir("/proc/self/task").expect("read /proc/self/task");
        for t in tasks {
            let t = t.expect("task entry");
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(s.split_whitespace().map(str::to_string));
            }
        }
        out
    }

    /// `cond` が真になるまで `timeout()` までポーリングする（固定 sleep に頼らない）。
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork の前提。join 済みスレッドの消滅は僅かに遅れ得る）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch"
        );
    }

    // ----- コンテナ内プローブ ------------------------------------------------------------------------------

    /// rdev の major（glibc の `gnu_dev_major`）。
    fn dev_major(rdev: u64) -> u64 {
        ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)
    }

    /// rdev の minor（glibc の `gnu_dev_minor`）。
    fn dev_minor(rdev: u64) -> u64 {
        (rdev & 0xff) | ((rdev >> 12) & !0xff)
    }

    /// コンテナ内で動くプローブ。観測値を `KEY value` 形式の固定語彙で stdout へ出し、`READY` の後は親が
    /// 終了させるまで待つ。
    pub fn probe() {
        let mut out = std::io::stdout();
        let mut emit = |line: String| {
            writeln!(out, "{line}").expect("write probe line");
            out.flush().expect("flush probe line");
        };
        emit(format!("PID {}", std::process::id()));
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        emit(format!("HOSTNAME {hostname}"));
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        emit(format!("CGROUP {cgroup}"));
        let field = |key: &str| {
            status_field("/proc/self/status", key).unwrap_or_else(|| "missing".to_string())
        };
        emit(format!("NONEWPRIVS {}", field("NoNewPrivs:")));
        emit(format!("SECCOMP {}", field("Seccomp:")));
        for name in ["null", "zero", "full", "random", "urandom", "tty"] {
            let line = match std::fs::symlink_metadata(format!("/dev/{name}")) {
                Ok(m) if m.file_type().is_char_device() => {
                    format!(
                        "DEV {name} c {}:{}",
                        dev_major(m.rdev()),
                        dev_minor(m.rdev())
                    )
                }
                Ok(_) => format!("DEV {name} not-char"),
                Err(e) => format!("DEV {name} error:{:?}", e.kind()),
            };
            emit(line);
        }
        for name in ["fd", "stdin", "stdout", "stderr"] {
            let target = std::fs::read_link(format!("/dev/{name}")).map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |p| p.display().to_string(),
            );
            emit(format!("LINK {name} {target}"));
        }
        for name in ["pts", "shm"] {
            emit(format!(
                "DIR {name} {}",
                Path::new(&format!("/dev/{name}")).is_dir()
            ));
        }
        let wrote = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .and_then(|mut f| f.write_all(b"x"));
        emit(format!(
            "DEVNULL_WRITE {}",
            wrote.map_or_else(|e| format!("error:{:?}", e.kind()), |()| "ok".to_string())
        ));
        let mut buf = [0u8; 16];
        let read = std::fs::File::open("/dev/zero").and_then(|mut f| f.read(&mut buf));
        emit(format!(
            "DEVZERO_READ {}",
            read.map_or_else(|e| format!("error:{:?}", e.kind()), |n| n.to_string())
        ));
        // シナリオ L〜O・I の拡張(OCI-1・SEC-5): 作業ディレクトリと実・実効・保存・FS の uid / gid。
        let cwd = std::fs::read_link("/proc/self/cwd").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |p| p.display().to_string(),
        );
        emit(format!("CWD {cwd}"));
        for (name, key) in [("UIDS", "Uid:"), ("GIDS", "Gid:")] {
            emit(format!(
                "{name} {}",
                field(key).split_whitespace().collect::<Vec<_>>().join(",")
            ));
        }
        // シナリオ K（exec 後の seccomp の識別的な拒否。#2012）: 禁止 syscall を 1 件発行する。フィルタが効いていれば
        // SIGSYS で終了して戻らない。戻った場合（フィルタ欠落）は固定語彙の行を出して正常終了し、親が失敗にする。
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--seccomp-kill") {
            let name = args.get(i + 1).map_or("missing", String::as_str);
            let which = match name {
                "unshare" => EscapeSyscallProbe::Unshare,
                "ptrace" => EscapeSyscallProbe::Ptrace,
                "kexec_load" => EscapeSyscallProbe::KexecLoad,
                other => panic!("unknown seccomp-kill probe {other}"),
            };
            emit(format!("SECCOMP_KILL_ATTEMPT {name}"));
            let outcome = probe_escape_syscall(which);
            emit(format!("SECCOMP_KILL_RETURNED {outcome:?}"));
            std::process::exit(0);
        }
        // シナリオ J（exec 後の capability と seccomp の実効。#2012）。
        if args.iter().any(|a| a == "--with-restrictions") {
            for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
                emit(format!("CAP {key} {}", field(&format!("{key}:"))));
            }
            // PID 1 かつ `Seccomp: 2` のときだけ発行される安全な入口。`mount` は seccomp が `EPERM` で拒否する。
            emit(format!("SECCOMP_MOUNT {:?}", escape_probe_mount()));
            // exec 後の PID 1 の記録（`kcmp` の errno を識別的に照合する。#2234）。入口は PID 1 かつ `Seccomp: 2` でだけ発行する。
            match probe_denied_syscalls_for_test() {
                Ok(rec) => {
                    for line in rec.render().lines() {
                        emit(format!("SECCOMP_RECORD {line}"));
                    }
                }
                Err(e) => emit(format!("SECCOMP_RECORD_ERROR {:?}", e.code)),
            }
            // 許可された syscall（`openat`・`read`）の対照。拒否一辺倒のフィルタ（全拒否）と区別する。
            let control = std::fs::read_to_string("/proc/thread-self/status");
            emit(format!(
                "SECCOMP_CONTROL {}",
                control.map_or_else(|e| format!("error:{:?}", e.kind()), |_| "ok".to_string())
            ));
        }
        // シナリオ D（bind mount。#1915）: bind 先へ固定の内容を書き、mountinfo 上のマウントオプションを出す。
        if std::env::args().any(|a| a == "--with-bind") {
            let wrote = std::fs::write(format!("{BIND_DEST}/{BIND_FILE}"), BIND_CONTENT);
            emit(format!(
                "BIND_WRITE {}",
                wrote.map_or_else(|e| format!("error:{:?}", e.kind()), |()| "ok".to_string())
            ));
            let opts = std::fs::read_to_string("/proc/self/mountinfo").map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |info| {
                    info.lines()
                        .filter_map(|l| {
                            let f: Vec<&str> = l.split_whitespace().collect();
                            (f.get(4).copied() == Some(BIND_DEST))
                                .then(|| f.get(5).copied().unwrap_or("").to_string())
                        })
                        .next_back()
                        .unwrap_or_else(|| "not-mounted".to_string())
                },
            );
            emit(format!("BIND_OPTS {opts}"));
        }
        emit(PROBE_READY.to_string());
        // シナリオ P（名前だけの args[0]。#2314）: READY の後に指定の終了コードで終わる。
        let args: Vec<String> = std::env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--exit-code")
            && let Some(code) = args.get(pos + 1).and_then(|c| c.parse::<i32>().ok())
        {
            std::process::exit(code);
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // ----- 親側の準備 --------------------------------------------------------------------------------------

    /// 一時 bundle（drop で削除。`create_dir` で排他的に作り、既存パスを再利用しない）。
    struct Bundle {
        dir: PathBuf,
    }

    impl Bundle {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!(
                    "fandhe-prodlaunch-{tag}-{}-{nanos}",
                    std::process::id()
                ));
            std::fs::create_dir(&dir).expect("exclusively create bundle dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod bundle dir");
            Self { dir }
        }

        fn rootfs(&self) -> PathBuf {
            self.dir.join("rootfs")
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn mkdir(path: &Path) {
        // `create_dir_all` は途中の symlink を辿るため、祖先を 1 階層ずつ `lstat` して非 symlink のみ許容し、
        // 無ければ `create_dir` で作る（基点の bundle は排他作成済みの 0700。#2324・SEC-2）。
        let mut chain: Vec<&Path> = path.ancestors().filter(|a| a.parent().is_some()).collect();
        chain.reverse();
        for dir in chain {
            match std::fs::symlink_metadata(dir) {
                Ok(md) => assert!(
                    md.is_dir() && !md.file_type().is_symlink(),
                    "{} exists and is not a plain directory",
                    dir.display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(dir)
                        .unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
                }
                Err(e) => panic!("lstat {}: {e}", dir.display()),
            }
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }

    /// `host` のファイルを rootfs 内の同じ絶対パスへ（実体の内容を通常ファイルとして）コピーする。
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
            // ローダは PT_INTERP のパスのまま（シンボリックリンクを辿らず）rootfs 内で開かれるため、
            // 実体の内容をそのパスへ置く。
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

    fn write_config(
        bundle: &Bundle,
        ld_library_path: &str,
        extra_args: &[&str],
        mounts: serde_json::Value,
    ) {
        write_config_with(bundle, ld_library_path, extra_args, mounts, "/", (0, 0));
    }

    /// `write_config` に `process.cwd` と `process.user`(uid, gid)を指定できる版(OCI-1・SEC-5)。
    fn write_config_with(
        bundle: &Bundle,
        ld_library_path: &str,
        extra_args: &[&str],
        mounts: serde_json::Value,
        cwd: &str,
        (uid, gid): (u32, u32),
    ) {
        let mut args = vec!["/probe", "--container-probe"];
        args.extend_from_slice(extra_args);
        let config = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": false},
            "hostname": HOSTNAME,
            "process": {
                "user": {"uid": uid, "gid": gid},
                "args": args,
                "env": [
                    "PATH=/",
                    "TERM=dumb",
                    format!("LD_LIBRARY_PATH={ld_library_path}"),
                ],
                "cwd": cwd
            },
            "mounts": mounts,
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
            ]}
        });
        std::fs::write(
            bundle.dir.join("config.json"),
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("write config.json");
    }

    /// 監査レコードをメモリへ追記するだけの sink（本試験は監査内容を照合しない）。
    struct MemSink(std::sync::Mutex<Vec<String>>);

    impl AuditSink for MemSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{record:?}"));
            Ok(())
        }
    }

    /// 子の出力を行単位で読んで送るリーダースレッド。1 行と総行数に上限を設ける。
    fn spawn_reader(
        stdout: Box<dyn std::io::Read + Send>,
    ) -> (mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            for _ in 0..LINES_MAX {
                let mut line = String::new();
                match (&mut reader).take(LINE_MAX).read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if tx.send(line.trim_end().to_string()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        (rx, handle)
    }

    /// `READY` までのプローブ出力を集める（期限つき）。
    fn collect_probe(rx: &mpsc::Receiver<String>) -> Vec<String> {
        let deadline = Instant::now() + timeout();
        let mut lines = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = rx
                .recv_timeout(left)
                .unwrap_or_else(|e| panic!("probe output ended before READY ({e}); got {lines:?}"));
            if line == PROBE_READY {
                return lines;
            }
            lines.push(line);
        }
    }

    fn value_of<'a>(lines: &'a [String], key: &str) -> &'a str {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')))
            .unwrap_or_else(|| panic!("probe line {key:?} missing in {lines:?}"))
    }

    struct Env {
        store: FileStateStore,
        _root: Bundle,
        launcher: Arc<dyn ProcessLauncher>,
        recorder: OpRecorder,
    }

    fn state_of(store: &FileStateStore, id: &ContainerId) -> ContainerState {
        store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get state")
            .status()
            .state()
    }

    /// `state.json` から読み戻した launch 時の分離の記録を検証する(SUP-6・CORE-5・SEC-1・#2007)。`/` の識別子は
    /// ホスト側の rootfs ディレクトリの `(st_dev, st_ino)` と一致し(bind は inode と `st_dev` を保つ)、ルールは
    /// 先頭が rootfs で、`bind_dest` があれば `mounts[0]` 由来の Mount ルールを含む。
    fn assert_recorded_launch_isolation(
        env: &Env,
        id: &ContainerId,
        bundle: &Bundle,
        bind_dest: Option<&str>,
    ) {
        use fandhe_container_core::launch_isolation::RecordedTarget;
        use std::os::unix::fs::MetadataExt as _;
        let record = env
            .store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get state");
        let iso = record
            .launch_isolation()
            .expect("launch_isolation recorded");
        let meta = std::fs::metadata(bundle.rootfs()).expect("rootfs metadata");
        assert_eq!(iso.root().dev(), meta.dev());
        assert_eq!(iso.root().ino(), meta.ino());
        let rules = iso.landlock().rules();
        assert!(
            matches!(
                rules.first().map(|r| r.target()),
                Some(RecordedTarget::Root)
            ),
            "first rule must be the rootfs"
        );
        assert_ne!(iso.landlock().handled(), 0);
        let mounts: Vec<(String, usize)> = rules
            .iter()
            .filter_map(|r| match r.target() {
                RecordedTarget::Mount { destination, index } => {
                    Some((destination.as_str().to_owned(), *index))
                }
                _ => None,
            })
            .collect();
        let want: Vec<(String, usize)> = bind_dest.map(|d| (d.to_owned(), 0)).into_iter().collect();
        assert_eq!(mounts, want);
    }

    fn do_create(env: &Env, bundle: &Bundle, id: &ContainerId) {
        let req = CreateRequest::new(id.clone(), bundle.dir.clone()).expect("absolute bundle");
        create(&env.store, &env.recorder, &req).expect("create");
    }

    pub fn run() {
        let root = is_root();
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup v2");
        let tag = std::process::id();
        let cg_id = ContainerId::new(format!("pl{tag}")).expect("container id");
        let cg_name = CgroupName::new(&cg_id).expect("cgroup name");
        // detect / prepare / join_hook は isolate（pivot）より前。pivot 後はホストの cgroupfs が見えない。
        let (container, _proof) = delegated
            .prepare(&cg_name)
            .expect("prepare container cgroup");
        let container: Arc<ContainerCgroup> = Arc::new(container);
        let expected_cgroup = format!(
            "0::{}/{}",
            delegated.path().trim_end_matches('/'),
            cg_name.as_str()
        );

        // 後始末は成否に関わらず行う（panic でも cgroup と一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenarios(root, &container, &expected_cgroup, tag);
        }));
        let removed = delegated.remove_child(&container);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");

        if root {
            println!(
                "production_launcher: launch refused for root, no process left (SEC-5) (root=true)"
            );
        } else {
            println!(
                "production_launcher: pid1, default /dev nodes, landlock evidence, cgroup join verified; failed launch left no process; bind mount visible on host; post-exec capabilities and seccomp verified (root=false)"
            );
        }
    }

    fn scenarios(root: bool, container: &Arc<ContainerCgroup>, expected_cgroup: &str, tag: u32) {
        let state_dir = Bundle::new("state");
        let store = FileStateStore::open(
            StateRoot::from_override(state_dir.dir.join("state")).expect("state root"),
        );
        // 状態ルートは 0700 で自分が作る（`open` が作成し所有者・権限を検査する）。
        let store = store.expect("open state store");

        let join_container = Arc::clone(container);
        let launcher = ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSingleId)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .cgroup_join_source(move || {
                let hook = PRE_SPAWN_HOOK
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(hook) = hook {
                    hook();
                }
                join_container.join_hook()
            })
            .build()
            .expect("build production launcher");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(launcher);
        let env = Env {
            store,
            _root: state_dir,
            launcher,
            recorder: OpRecorder::new(),
        };

        if root {
            scenario_root_refused(&env, tag);
            if subordinate_requested() {
                scenario_i_root_refused();
            }
            return;
        }
        scenario_a_normal(&env, expected_cgroup, tag);
        scenario_b_failed_launch_leaves_nothing(&env, tag);
        scenario_c_multithreaded_refused(&env, tag);
        scenario_d_bind_mount(&env, tag);
        scenario_e_state_root_bind_refused(&env, tag);
        scenario_f_landlock_mount_identity_swapped(&env, tag);
        scenario_g_devtmpfs_bind_refused(&env, tag);
        scenario_h_state_root_moved_after_start(&env, tag);
        if subordinate_requested() {
            scenario_i_subordinate_ids(&env, tag);
        } else {
            println!(
                "production_launcher: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        scenario_j_exec_restrictions(&env, tag);
        scenario_k_seccomp_kill_after_exec(&env, tag);
        scenario_l_working_dir(&env, tag);
        scenario_m_n_working_dir_refused(&env, tag);
        scenario_o_user_outside_mapping_refused(&env, tag);
        scenario_p_bare_name_entrypoint(&env, tag);
        if subordinate_requested() {
            scenario_i_user_applied(tag);
        }
    }

    /// シナリオ A: 正常起動。
    fn scenario_a_normal(env: &Env, expected_cgroup: &str, tag: u32) {
        let bundle = Bundle::new("a");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("pla{tag}")).expect("id");
        do_create(env, &bundle, &id);
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        // 検証は catch_unwind の中で行い、成否に関わらず terminate と回収を行ってから panic を再送出する
        // （`LaunchedProcess` は Drop で終了・回収しないため、ここで回収しないと実機にプロセスが残る）。
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // 起動直後の状態検証も保護範囲に含め、panic 時も terminate と回収を行う。
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_eq!(started.record().status().pid(), Some(pid));
            assert_eq!(state_of(&env.store, &id), ContainerState::Running);
            assert_recorded_launch_isolation(env, &id, &bundle, None);
            // ホストから見た PID 1 の確認（NSpid の末尾が 1）。
            let nspid = status_field(&format!("/proc/{pid}/status"), "NSpid:").expect("host NSpid");
            let parts: Vec<&str> = nspid.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "NSpid must have two levels: {nspid:?}");
            assert_eq!(parts.first().copied(), Some(pid.to_string().as_str()));
            assert_eq!(parts.last().copied(), Some("1"));
            // 起動のたびに登録された CgroupJoin 段で、子 cgroup に参加している。
            let host_cgroup =
                std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("cgroup");
            assert_eq!(host_cgroup.trim(), expected_cgroup);

            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            let (rx, reader) = spawn_reader(stdout);
            // 以降の検証が panic しても、起動済みプロセスの終了と回収を必ず行うため rx / reader は外へ預ける。
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);

            assert_eq!(value_of(&lines, "PID"), "1");
            assert_eq!(value_of(&lines, "HOSTNAME"), HOSTNAME);
            assert_eq!(value_of(&lines, "CGROUP"), expected_cgroup);
            // 制限ステージ（no_new_privs・seccomp）の適用の間接証拠。Landlock 本体の直接観測は範囲外（モジュール doc）。
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            for (name, major, minor) in [
                ("null", 1, 3),
                ("zero", 1, 5),
                ("full", 1, 7),
                ("random", 1, 8),
                ("urandom", 1, 9),
                ("tty", 5, 0),
            ] {
                assert_eq!(
                    value_of(&lines, &format!("DEV {name}")),
                    format!("c {major}:{minor}"),
                    "/dev/{name}"
                );
            }
            for (name, target) in [
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
            ] {
                assert_eq!(
                    value_of(&lines, &format!("LINK {name}")),
                    target,
                    "/dev/{name}"
                );
            }
            assert_eq!(value_of(&lines, "DIR pts"), "true");
            assert_eq!(value_of(&lines, "DIR shm"), "true");
            assert_eq!(value_of(&lines, "DEVNULL_WRITE"), "ok");
            assert_eq!(value_of(&lines, "DEVZERO_READ"), "16");
            println!(
                "production_launcher: scenario=ok pid={pid} nspid={nspid:?} hostname={HOSTNAME}"
            );
        }));

        // 終了と回収。
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            // 検証側の panic を優先する。terminate の失敗で元の panic を覆い隠さない。
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        // 出力パイプは子の終了で EOF になり、リーダーは終了する。次の start の前に必ず join する。
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ B: rootfs に `proc/` が無く pre-pivot 段が失敗する起動。何も残さない（#1817）。
    fn scenario_b_failed_launch_leaves_nothing(env: &Env, tag: u32) {
        let bundle = Bundle::new("b");
        let ld = make_rootfs(&bundle.rootfs(), false);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plb{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must fail without rootfs/proc"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            env.store
                .get(&GetStateRequest::new(id.clone()))
                .expect("get state")
                .launch_isolation()
                .is_none(),
            "a failed launch must leave no launch_isolation"
        );
        assert!(!env.launcher.last_launch_may_have_left_process());
        env.launcher
            .confirm_no_process(&id, timeout())
            .expect("confirm_no_process must be Ok for a cleanly failed launch");
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no intermediate process or PID 1 may remain: {:?}",
            children_of_self()
        );
        println!(
            "production_launcher: scenario=failed-launch code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ C: 補助スレッドが生きている状態の start は fork 前に拒否される（副作用なし）。
    fn scenario_c_multithreaded_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("c");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plc{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = stop_rx.recv_timeout(Duration::from_secs(60));
        });
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        let _ = stop_tx.send(());
        helper.join().expect("join helper");
        let err = match result {
            Ok(_) => panic!("start must be refused while a second thread is alive"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            children_of_self().is_empty(),
            "a refused launch must not fork"
        );
        println!("production_launcher: scenario=multithreaded-refused code=FailedPrecondition");
    }

    /// シナリオ D: `mounts[]` の bind mount が start と本番 launcher を通って適用される（#1915・OCI-4・IO-8・SEC-1）。
    /// コンテナ内が bind 先へ書いた内容がホスト側の元に完全一致で現れ、bind 先のマウントに `nosuid`・`nodev` が付く。
    fn scenario_d_bind_mount(env: &Env, tag: u32) {
        let src = Bundle::new("d-src");
        let bundle = Bundle::new("d");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-bind"], mounts);
        let id = ContainerId::new(format!("pld{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "start with bind mount failed: {:?} {}",
                e.code(),
                e.message()
            )
        });
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_recorded_launch_isolation(env, &id, &bundle, Some(BIND_DEST));
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(value_of(&lines, "BIND_WRITE"), "ok");
            let opts = value_of(&lines, "BIND_OPTS");
            let opts: Vec<&str> = opts.split(',').collect();
            assert!(opts.contains(&"rw"), "{opts:?}");
            assert!(opts.contains(&"nosuid"), "{opts:?}");
            assert!(opts.contains(&"nodev"), "{opts:?}");
            let on_host = std::fs::read_to_string(src.dir.join(BIND_FILE)).expect("host file");
            assert_eq!(on_host, BIND_CONTENT);
            println!(
                "production_launcher: scenario=bind-mount pid={pid} dest={BIND_DEST} visible on host, nosuid+nodev"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ I の opt-in 環境変数(`rootless_file_owner` の helper ケースと同じ流儀)。
    fn subordinate_requested() -> bool {
        std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1")
    }

    /// 起動ユーザーの euid / egid(`/proc/self/status` の実効 ID)。
    fn own_ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            std::fs::read_to_string("/proc/self/status")
                .expect("read status")
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
                .expect("parse id")
        };
        (id("Uid:"), id("Gid:"))
    }

    /// `RootlessSubordinateIds` の launcher を作る。所有者名は試験側が `USER` から渡す(ライブラリは読まない)。
    fn build_subordinate_launcher() -> Result<ProductionLauncher, TraitError> {
        ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSubordinateIds)
            .subordinate_ids(SubordinateIdSource::system(std::env::var("USER").ok())?)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .build()
    }

    /// シナリオ I(`FANDHE_CONTAINER_TEST_ID_HELPER=1`。CORE-6・SEC-5・#2009): `RootlessSubordinateIds` の launcher で
    /// 起動し、ホストから見た PID 1 の `uid_map` / `gid_map` が `/etc/subuid`・`/etc/subgid` の範囲写像と完全一致する
    /// (コンテナ 0 → 自 ID、コンテナ 1 以上 → subuid / subgid の範囲)ことを照合する。コンテナ内の
    /// `/proc/self/uid_map` は読み手基準の表示になるため照合に使わない。前提(`uidmap`・subuid / subgid の自ユーザー行)が
    /// 無ければ失敗とする。
    fn scenario_i_subordinate_ids(env: &Env, tag: u32) {
        use fandhe_container_core::rootless::{
            IdKind, SubIdOwner, TargetPid, load_subordinate_ids, read_id_map, rootless_mapping,
        };
        let launcher: Arc<dyn ProcessLauncher> =
            Arc::new(build_subordinate_launcher().expect("build subordinate launcher"));
        let (euid, egid) = own_ids();
        let name = std::env::var("USER").ok();
        let uowner = SubIdOwner::new(euid, name.clone()).expect("uid owner");
        let gowner = SubIdOwner::new(euid, name).expect("gid owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &uowner).expect("load /etc/subuid");
        let granges =
            load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
        assert!(
            !uranges.is_empty() && !granges.is_empty(),
            "scenario I requires subuid/subgid entries for the current user"
        );
        let want_uid = rootless_mapping(euid, &uranges).expect("uid range mapping");
        let want_gid = rootless_mapping(egid, &granges).expect("gid range mapping");

        let bundle = Bundle::new("i");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("pli{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let target = TargetPid::new(pid.get()).expect("target pid");
            let uid_map = read_id_map(target, IdKind::Uid).expect("read uid_map");
            let gid_map = read_id_map(target, IdKind::Gid).expect("read gid_map");
            assert_eq!(uid_map.as_slice(), want_uid.entries());
            assert_eq!(gid_map.as_slice(), want_gid.entries());
            assert!(uid_map.len() >= 2 && gid_map.len() >= 2, "{uid_map:?}");
            let first_sub_uid = uranges.first().expect("a subuid range").start();
            assert_eq!(
                uid_map.get(1).map(|m| (m.container_id, m.host_id)),
                Some((1, first_sub_uid))
            );

            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(value_of(&lines, "PID"), "1");
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            println!(
                "production_launcher: subordinate id mapping verified (uid extents={}, gid extents={})",
                uid_map.len(),
                gid_map.len()
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// root で実行された場合のシナリオ I: `RootlessSubordinateIds` の構築が `PermissionDenied` で拒否される
    /// (コンテナ内 root をホスト root へ写さない。SEC-5・#2009)。
    fn scenario_i_root_refused() {
        let err = build_subordinate_launcher().expect_err("root must be refused");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        println!(
            "production_launcher: scenario=subordinate-root-refused code={:?}",
            err.code()
        );
    }

    /// 指定の `cwd`・`user` で create → start し、`READY` までのプローブ出力を返して terminate・回収する
    /// (OCI-1・SEC-5)。`prepare` は rootfs の準備(作業ディレクトリの作成など)。非 root の `user` のときは
    /// ホストから見た uid を `HOST_UIDS` 行として足す。
    fn run_probe_with(
        env: &Env,
        launcher: &Arc<dyn ProcessLauncher>,
        name: &str,
        cwd: &str,
        user: (u32, u32),
        prepare: &dyn Fn(&Path),
        tag: u32,
    ) -> Vec<String> {
        let bundle = Bundle::new(name);
        let ld = make_rootfs(&bundle.rootfs(), true);
        prepare(&bundle.rootfs());
        write_config_with(&bundle, &ld, &[], json!([]), cwd, user);
        let id = ContainerId::new(format!("pl{name}{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let mut lines = Vec::new();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            if user != (0, 0) {
                let host = status_field(&format!("/proc/{pid}/status"), "Uid:")
                    .unwrap_or_else(|| "missing".to_string());
                lines.push(format!(
                    "HOST_UIDS {}",
                    host.split_whitespace().collect::<Vec<_>>().join(",")
                ));
            }
        }));
        finish_started(started, verified);
        if let Some((rx, reader)) = reader_slot.take() {
            reader.join().expect("join reader");
            drop(rx);
        }
        assert!(eventually(|| children_of_self().is_empty()));
        lines
    }

    /// シナリオ L(OCI-1・TASK-29): `process.cwd` が rootfs 内の既存ディレクトリ(`/work/dir`)なら、
    /// pivot 直後に fd 起点で移り、コンテナ内の `/proc/self/cwd` がそのパスを指す。`/` のときは `/` のまま。
    fn scenario_l_working_dir(env: &Env, tag: u32) {
        let mk = |root: &Path| mkdir(&root.join("work/dir"));
        let lines = run_probe_with(env, &env.launcher, "l", "/work/dir", (0, 0), &mk, tag);
        assert_eq!(value_of(&lines, "CWD"), "/work/dir");
        assert_eq!(value_of(&lines, "UIDS"), "0,0,0,0");
        let lines = run_probe_with(env, &env.launcher, "l0", "/", (0, 0), &mk, tag);
        assert_eq!(value_of(&lines, "CWD"), "/");
        println!("production_launcher: scenario=working-dir cwd=/work/dir applied, / kept");
    }

    /// シナリオ M・N(OCI-1・TASK-29・SEC-1): 存在しない `cwd` は `NotFound`、ファイルを指す・symlink を含む `cwd` は
    /// `InvalidArgument` で start が失敗し、状態は Created のまま子が残らない。
    fn scenario_m_n_working_dir_refused(env: &Env, tag: u32) {
        for (name, cwd, want) in [
            ("m", "/missing", ErrorCode::NotFound),
            ("n", "/afile", ErrorCode::InvalidArgument),
            ("ns", "/alink/x", ErrorCode::InvalidArgument),
        ] {
            let bundle = Bundle::new(name);
            let ld = make_rootfs(&bundle.rootfs(), true);
            std::fs::write(bundle.rootfs().join("afile"), b"x").expect("write file");
            mkdir(&bundle.rootfs().join("real/x"));
            std::os::unix::fs::symlink("real", bundle.rootfs().join("alink")).expect("symlink");
            write_config_with(&bundle, &ld, &[], json!([]), cwd, (0, 0));
            let id = ContainerId::new(format!("pl{name}{tag}")).expect("id");
            do_create(env, &bundle, &id);
            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must fail for cwd {cwd}"),
                Err(e) => e,
            };
            assert_eq!(err.code(), want, "{cwd}: {}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                eventually(|| children_of_self().is_empty()),
                "no child may remain: {:?}",
                children_of_self()
            );
            println!(
                "production_launcher: scenario=working-dir-refused cwd={cwd} code={:?} state=created children=0",
                err.code()
            );
        }
    }

    /// シナリオ O(OCI-1・SEC-5): 単一 ID 写像で 0/0 以外の `process.user` は、fork の前に `FailedPrecondition` で
    /// 拒否される(状態は Created のまま、子は残らない)。
    fn scenario_o_user_outside_mapping_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("o");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config_with(&bundle, &ld, &[], json!([]), "/", (1000, 1000));
        let id = ContainerId::new(format!("plo{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must fail for an unmapped user"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(children_of_self().is_empty());
        println!(
            "production_launcher: scenario=user-unmapped-refused code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ I の拡張(`FANDHE_CONTAINER_TEST_ID_HELPER=1`。OCI-1・SEC-5): 範囲写像で `process.user` 1000:1000 を
    /// 指定すると、コンテナ内の実・実効・保存・FS の uid / gid が 1000 になり、ホストから見た uid は
    /// 「subuid の先頭 + 999」になる(コンテナ 1 → subuid 先頭)。
    fn scenario_i_user_applied(tag: u32) {
        use fandhe_container_core::rootless::{SubIdOwner, load_subordinate_ids};
        let state_dir = Bundle::new("istate");
        let store = FileStateStore::open(
            StateRoot::from_override(state_dir.dir.join("state")).expect("state root"),
        )
        .expect("open state store");
        let launcher: Arc<dyn ProcessLauncher> =
            Arc::new(build_subordinate_launcher().expect("build subordinate launcher"));
        let env = Env {
            store,
            _root: state_dir,
            launcher: Arc::clone(&launcher),
            recorder: OpRecorder::new(),
        };
        let (euid, _) = own_ids();
        let owner = SubIdOwner::new(euid, std::env::var("USER").ok()).expect("owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &owner).expect("load /etc/subuid");
        let base = uranges.first().expect("a subuid range").start();
        let lines = run_probe_with(&env, &launcher, "iu", "/", (1000, 1000), &|_| (), tag);
        assert_eq!(value_of(&lines, "UIDS"), "1000,1000,1000,1000");
        assert_eq!(value_of(&lines, "GIDS"), "1000,1000,1000,1000");
        let host_uid = base + 999;
        assert!(
            value_of(&lines, "HOST_UIDS")
                .split(',')
                .all(|v| v == host_uid.to_string()),
            "{lines:?}"
        );
        println!("production_launcher: scenario=user-applied uid=gid=1000 host_uid={host_uid}");
    }

    /// シナリオ E: 状態ルート自身、または状態ルートへの symlink 別名を bind mount の元にした start は、本番 launcher
    /// へ渡る前に `InvalidArgument` で拒否され、状態は Created のまま子が残らない（SEC-1・SEC-4・#2066）。
    /// start 後の改名・別の bind mount による別名は、namespace 内の mount 権限が要るため本試験の範囲外
    /// （`exec::mount_binds` の単体試験が inode の鎖で照合する）。
    fn scenario_e_state_root_bind_refused(env: &Env, tag: u32) {
        let state_root = env._root.dir.join("state");
        let alias_dir = Bundle::new("e-alias");
        let alias = alias_dir.dir.join("state-alias");
        std::os::unix::fs::symlink(&state_root, &alias).expect("symlink alias of state root");
        for (label, source) in [("direct", state_root.clone()), ("symlink", alias)] {
            let bundle = Bundle::new("e");
            let ld = make_rootfs(&bundle.rootfs(), true);
            let mounts = json!([{
                "destination": BIND_DEST,
                "type": "bind",
                "source": source.to_str().expect("utf8 source path"),
                "options": ["bind", "rw"]
            }]);
            write_config(&bundle, &ld, &["--with-bind"], mounts);
            let id = ContainerId::new(format!("ple{label}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must refuse a bind of the state root ({label})"),
                Err(e) => e,
            };
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                children_of_self().is_empty(),
                "no process may be spawned for a refused bind ({label})"
            );
            println!(
                "production_launcher: scenario=state-root-bind-refused kind={label} code={:?}",
                err.code()
            );
        }
    }

    /// シナリオ F: Landlock の Mount 由来のルールの識別子照合を、本番の起動経路（`RealPrePivotOps` の記録 → pivot →
    /// `StagePipeline` → 本物の Landlock 適用）で通す（CORE-5・SEC-1・SEC-4・REPAIR-10 (d)・REPAIR-12・#2071）。
    ///
    /// - 一致する場合: シナリオ D（`/data` の bind を記録し、Landlock 適用後も bind 先へ書ける）とシナリオ A
    ///   （既定の `/dev` 系の記録）が、記録と実マウントが一致したまま起動に成功することで担う
    /// - 記録後にマウントが変わる場合（本シナリオ）: `linux.readonlyPaths` に `/dev` を足すと、`apply_readonly_paths` が
    ///   `RealPrePivotOps` の記録（`create_devices` 直後）より後に `/dev` へ別のマウント（読み取り専用の bind）を重ねる。
    ///   Landlock の暗黙の `/dev` ルールの対象は記録と別のマウントになるため、適用時の照合が拒否し、起動は失敗する。
    ///   Landlock 段の拒否は pivot 後の子で起き、状態 pipe（pre-pivot 段のみ）では親へ届かない（`docs/design/audit-delivery.md`
    ///   8 章。#2023〜）ため、親から観測できるのは「起動が失敗し、状態が Created に戻り、子が残らない」ことまで。
    ///   拒否理由そのものは `exec/landlock.rs` の単体試験が `ViolationReason::LandlockMountIdentityMismatch` で照合する。
    fn scenario_f_landlock_mount_identity_swapped(env: &Env, tag: u32) {
        let bundle = Bundle::new("f");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config.json"))
                .expect("parse config.json");
        config["linux"]["readonlyPaths"] = json!(["/dev"]);
        std::fs::write(
            &path,
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("rewrite config.json");
        let id = ContainerId::new(format!("plf{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must be refused when a mount is swapped after it was recorded"),
            Err(e) => e,
        };
        // 検証段階（config の拒否）ではなく、launch 中の拒否であること。
        assert_ne!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no process may remain after a refused launch: {:?}",
            children_of_self()
        );
        println!(
            "production_launcher: scenario=landlock-mount-swapped code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ G: ホストの `/dev`（devtmpfs）を `bind` / `rbind` の元にした start は、付け替えた自分のマウントの
    /// fstype 名（`devtmpfs`）で拒否され、後始末で bind 先が残らない（SEC-1・#2129）。`f_type` は tmpfs と同じ値の
    /// ため `fstatfs` の判定では通り、mountinfo の照合だけが拒否する。拒否理由そのものは `exec::bind_mounts` の
    /// 単体試験が照合する（launch 中の拒否は pivot 後の子で起き、状態 pipe では親へ届かない。シナリオ F と同じ）。
    fn scenario_g_devtmpfs_bind_refused(env: &Env, tag: u32) {
        // 前提: ホストの `/dev` が devtmpfs であること（そうでない環境では本シナリオは意味を持たないため失敗させる）。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        assert!(
            mountinfo.lines().any(|l| {
                let (pre, post) = l.split_once(" - ").unwrap_or((l, ""));
                pre.split(' ').nth(4) == Some("/dev") && post.starts_with("devtmpfs ")
            }),
            "host /dev must be a devtmpfs mount for scenario G"
        );
        for label in ["bind", "rbind"] {
            let bundle = Bundle::new("g");
            let ld = make_rootfs(&bundle.rootfs(), true);
            let mounts = json!([{
                "destination": BIND_DEST,
                "type": "bind",
                "source": "/dev",
                "options": [label, "rw"]
            }]);
            write_config(&bundle, &ld, &["--with-bind"], mounts);
            let id = ContainerId::new(format!("plg{label}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must refuse a devtmpfs bind source ({label})"),
                Err(e) => e,
            };
            assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                eventually(|| children_of_self().is_empty()),
                "no process may remain after a refused launch ({label}): {:?}",
                children_of_self()
            );
            // 後始末: 適用の段が rootfs 内に作った bind 先は取り除かれている。
            assert!(
                !bundle
                    .rootfs()
                    .join(BIND_DEST.trim_start_matches('/'))
                    .exists(),
                "the bind destination must be rolled back ({label})"
            );
            println!(
                "production_launcher: scenario=devtmpfs-bind-refused kind={label} code={:?} state=created children=0 dest-removed",
                err.code()
            );
        }
    }

    /// ディレクトリ木を別の場所へ複製する（通常ファイルとディレクトリのみ。権限を引き継ぐ）。
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir(to).expect("create copy dir");
        let mode = std::fs::metadata(from)
            .expect("stat source dir")
            .permissions();
        std::fs::set_permissions(to, mode).expect("chmod copy dir");
        for entry in std::fs::read_dir(from).expect("read source dir") {
            let entry = entry.expect("dir entry");
            let target = to.join(entry.file_name());
            let kind = entry.file_type().expect("file type");
            if kind.is_dir() {
                copy_tree(&entry.path(), &target);
            } else if kind.is_file() {
                std::fs::copy(entry.path(), &target).expect("copy file");
            } else {
                panic!("unexpected entry kind in state root: {:?}", entry.path());
            }
        }
    }

    /// シナリオ H: start が状態ルートを固定した後（launcher が子を作る直前）に状態ルートが改名されると、適用の段が
    /// 記録したパスを辿り直して食い違いを検出し、bind mount を行わず拒否する（SEC-1・#2129）。元は状態ルートと
    /// 無関係なディレクトリで、改名が無ければ受理される（シナリオ D と同じ構成）。子を作る前に 1 回だけ、状態ルートを
    /// 別名へ改名し、同じパスへ内容を複製した別の inode のディレクトリを置く（start の後始末が同じパスの状態ストアを
    /// 使い続けられるようにするため。固定した実体は改名先に残る）。
    fn scenario_h_state_root_moved_after_start(env: &Env, tag: u32) {
        let src = Bundle::new("h-src");
        let bundle = Bundle::new("h");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-bind"], mounts);
        let id = ContainerId::new(format!("plh{tag}")).expect("id");
        do_create(env, &bundle, &id);

        let state_root = env._root.dir.join("state");
        let moved = env._root.dir.join("state-moved");
        {
            let (from, to) = (state_root.clone(), moved.clone());
            *PRE_SPAWN_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(move || {
                std::fs::rename(&from, &to).expect("rename state root after start");
                copy_tree(&to, &from);
            }));
        }
        wait_single_thread();
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        // 固定した実体（改名先）は不要になる。同じパスの複製が以降の状態ルートになる。
        let renamed = moved.exists();
        if renamed {
            std::fs::remove_dir_all(&moved).expect("remove the renamed original state root");
        }
        assert!(
            renamed,
            "the pre-spawn hook must have renamed the state root"
        );
        let err = match result {
            Ok(_) => panic!("start must refuse when the state root moved after start"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no process may remain after a refused launch: {:?}",
            children_of_self()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            std::fs::read_dir(&src.dir)
                .expect("read bind source")
                .next()
                .is_none(),
            "nothing may be written to the bind source"
        );
        assert!(
            !bundle
                .rootfs()
                .join(BIND_DEST.trim_start_matches('/'))
                .exists(),
            "no bind destination may remain"
        );
        println!(
            "production_launcher: scenario=state-root-moved-after-start code={:?} state=created children=0",
            err.code()
        );
    }

    /// `/proc/<x>/status` の cap 行（16 桁の 16 進）を `u64` へ直す。
    fn cap_value(text: &str) -> u64 {
        u64::from_str_radix(text.trim(), 16)
            .unwrap_or_else(|e| panic!("cap field {text:?} is not hex: {e}"))
    }

    /// 起動済みの子を、成否に関わらず terminate して回収する共通後始末（panic を覆い隠さない）。
    fn finish_started(
        started: fandhe_container_core::oci_runtime::StartedContainer,
        verified: std::thread::Result<()>,
    ) {
        let pid = started.process().pid();
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
    }

    /// シナリオ J: exec 後の capability と seccomp の実効（#2012・SEC-1・CORE-5）。
    fn scenario_j_exec_restrictions(env: &Env, tag: u32) {
        // 公開 API の OCI 既定集合から組んだマスクと、リテラルの両方で照合する（`tests/capabilities.rs` の `mask_of` と同じ作り方）。
        let from_api = OCI_DEFAULT_CAPABILITIES
            .iter()
            .fold(0u64, |m, c| m | (1u64 << c.index()));
        const OCI_DEFAULT_MASK: u64 = 0x0000_0000_a804_25fb;
        assert_eq!(from_api, OCI_DEFAULT_MASK, "OCI default capability mask");

        // 適用前の kcmp 対照（親は組み込みフィルタを載せていない）。外側が拒否する環境は前提欠如として失敗させる（#2234）。
        let kcmp_before = probe_kcmp_self_for_test();
        assert_eq!(
            kcmp_before,
            ProbeOutcome::Ok,
            "precondition failed: kcmp(self, self) must succeed before the built-in seccomp stage (got {kcmp_before:?}, Seccomp: {}); the outer environment already denies kcmp, so EPERM inside the container cannot be attributed to the built-in filter",
            status_field("/proc/self/status", "Seccomp:").unwrap_or_default()
        );

        let bundle = Bundle::new("j");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-restrictions"], json!([]));
        let id = ContainerId::new(format!("plj{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);

            // コンテナ内（exec 後の PID 1）から見た値。
            assert_eq!(value_of(&lines, "PID"), "1");
            for (key, want) in [
                ("CapInh", 0),
                ("CapAmb", 0),
                ("CapPrm", OCI_DEFAULT_MASK),
                ("CapEff", OCI_DEFAULT_MASK),
                ("CapBnd", OCI_DEFAULT_MASK),
            ] {
                assert_eq!(
                    cap_value(value_of(&lines, &format!("CAP {key}"))),
                    want,
                    "in-container {key}"
                );
                // ホストから見た同じプロセス（exec 後）の値。
                let host = status_field(&format!("/proc/{pid}/status"), &format!("{key}:"))
                    .unwrap_or_else(|| panic!("host {key} missing"));
                assert_eq!(cap_value(&host), want, "host view of {key}");
            }
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            // 拒否される syscall と、許可される syscall の対照。
            assert_eq!(value_of(&lines, "SECCOMP_MOUNT"), "Ok(Errno(1))");
            assert_eq!(value_of(&lines, "SECCOMP_CONTROL"), "ok");
            // 識別的な照合: kcmp の EPERM は seccomp 以外では生じない（親側の適用前の対照が成功している前提）。
            assert!(
                !lines.iter().any(|l| l.starts_with("SECCOMP_RECORD_ERROR")),
                "seccomp record probe failed: {lines:?}"
            );
            let record_text = lines
                .iter()
                .filter_map(|l| l.strip_prefix("SECCOMP_RECORD "))
                .collect::<Vec<_>>()
                .join("\n");
            let rec = SeccompProbeRecord::parse(&record_text)
                .unwrap_or_else(|e| panic!("parse post-exec seccomp record: {e}; {lines:?}"));
            assert_eq!(rec.kcmp, ProbeOutcome::Errno(1), "post-exec kcmp EPERM");
            assert_eq!(rec.seccomp_mode, "2", "post-exec SECCOMP_MODE_FILTER");
            assert_eq!(rec.control, ProbeOutcome::Ok, "post-exec control read");
            assert_eq!(rec.mount, ProbeOutcome::Errno(1), "post-exec mount EPERM");
            assert_eq!(
                rec.pivot_root,
                ProbeOutcome::Errno(1),
                "post-exec pivot_root EPERM"
            );
            assert_eq!(
                rec.umount2,
                ProbeOutcome::Errno(1),
                "post-exec umount2 EPERM"
            );
            println!("production_launcher: scenario=j pid={pid} post-exec caps and seccomp ok");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ K: exec 後の seccomp が禁止 syscall を SIGSYS で拒否する（#2012・SEC-2・CORE-5）。
    fn scenario_k_seccomp_kill_after_exec(env: &Env, tag: u32) {
        // SIGSYS（x86_64・aarch64 とも 31）。`SECCOMP_RET_KILL_PROCESS` は seccomp 以外では生じない。
        const SIGSYS: i32 = 31;
        for (n, name) in ["unshare", "ptrace", "kexec_load"].into_iter().enumerate() {
            let bundle = Bundle::new(&format!("k{n}"));
            let ld = make_rootfs(&bundle.rootfs(), true);
            write_config(&bundle, &ld, &["--seccomp-kill", name], json!([]));
            let id = ContainerId::new(format!("plk{n}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let started = start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            )
            .unwrap_or_else(|e| panic!("start failed ({name}): {:?} {}", e.code(), e.message()));
            let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> =
                None;
            let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let output = started.process().take_output().expect("container output");
                let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
                reader_slot = Some((rx, reader));
                let exit = started
                    .process()
                    .wait(timeout())
                    .expect("wait for the probe")
                    .unwrap_or_else(|| panic!("{name}: the probe did not exit within the timeout"));
                assert_eq!(
                    exit,
                    ProcessExit::Signaled(SIGSYS),
                    "{name}: a forbidden syscall must kill the process with SIGSYS"
                );
                // 出力は EOF まで読み、発行の直前の行があり、戻りの行が無いことを照合する。
                let rx = &reader_slot.as_ref().expect("reader slot").0;
                let mut lines = Vec::new();
                let deadline = Instant::now() + timeout();
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(left) {
                        Ok(line) => lines.push(line),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            panic!("{name}: the probe output did not reach EOF; got {lines:?}")
                        }
                    }
                }
                assert!(
                    lines.contains(&format!("SECCOMP_KILL_ATTEMPT {name}")),
                    "{name}: attempt line missing in {lines:?}"
                );
                assert!(
                    !lines.iter().any(|l| l.starts_with("SECCOMP_KILL_RETURNED")),
                    "{name}: the syscall returned instead of being killed: {lines:?}"
                );
                println!("production_launcher: scenario=k {name} killed with SIGSYS");
            }));
            finish_started(started, verified);
            let (rx, reader) = reader_slot.take().expect("reader slot");
            reader.join().expect("join reader");
            drop(rx);
            assert!(
                children_of_self().is_empty(),
                "no child may remain after terminate"
            );
        }
    }

    /// シナリオ P（OCI-1・TASK-55 追補・#2314）: 名前だけの `process.args[0]` を、コンテナ内の `process.env` の
    /// `PATH` で pivot 後に解決して実行する。`PATH` の前方にある実行ビットの無い同名ファイルは飛ばし、後方の
    /// 実行可能な `probe` を PID 1 として起動し、コンテナ内プローブの `READY` と具体値の終了コード 7 を照合する。
    /// `PATH` のどこにも無い名前は、`start` が失敗するか子が終了コード 127 で終わる（`exec` 層の `NotFound` と
    /// 同じ。どちらでも子が残らず、成功起動には決してならない）。
    fn scenario_p_bare_name_entrypoint(env: &Env, tag: u32) {
        const EXIT_CODE: i32 = 7;
        let write_named = |bundle: &Bundle, ld: &str, path_env: &str, name: &str| {
            let config = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs", "readonly": false},
                "hostname": HOSTNAME,
                "process": {
                    "user": {"uid": 0, "gid": 0},
                    "args": [name, "--container-probe", "--exit-code", EXIT_CODE.to_string()],
                    "env": [
                        format!("PATH={path_env}"),
                        "TERM=dumb",
                        format!("LD_LIBRARY_PATH={ld}"),
                    ],
                    "cwd": "/"
                },
                "mounts": [],
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
                ]}
            });
            std::fs::write(
                bundle.dir.join("config.json"),
                serde_json::to_vec(&config).expect("serialize config"),
            )
            .expect("write config.json");
        };

        // P1: 前方の非実行ファイルを飛ばして後方の実行可能ファイルを解決し、終了コード 7 で終わる。
        let bundle = Bundle::new("p1");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let root = bundle.rootfs();
        mkdir(&root.join("opt/bin"));
        mkdir(&root.join("usr/local/bin"));
        std::fs::write(root.join("opt/bin/probe"), b"not executable\n").expect("decoy");
        std::fs::set_permissions(
            root.join("opt/bin/probe"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod decoy");
        std::fs::copy(root.join("probe"), root.join("usr/local/bin/probe")).expect("copy probe");
        std::fs::set_permissions(
            root.join("usr/local/bin/probe"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod probe");
        // `/probe` が絶対パスの経路で拾われないよう、名前の解決は PATH だけに頼らせる。
        std::fs::remove_file(root.join("probe")).expect("remove /probe");
        write_named(
            &bundle,
            &ld,
            "/nonexistent:/opt/bin:/usr/local/bin",
            "probe",
        );
        let id = ContainerId::new(format!("plp1{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let exit = started
                .process()
                .wait(timeout())
                .expect("wait for the probe")
                .expect("the probe did not exit within the timeout");
            assert_eq!(exit, ProcessExit::Exited(EXIT_CODE), "resolved probe exit");
            let mut lines = Vec::new();
            let rx = &reader_slot.as_ref().expect("reader slot").0;
            let deadline = Instant::now() + timeout();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(line) => lines.push(line),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        panic!("probe output did not reach EOF; got {lines:?}")
                    }
                }
            }
            assert_eq!(value_of(&lines, "PID"), "1");
            assert!(lines.contains(&PROBE_READY.to_string()), "{lines:?}");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(eventually(|| children_of_self().is_empty()));

        // P2: PATH のどこにも無い名前は成功起動にならない（start の失敗なら Created のまま、起動後なら 127）。
        let bundle = Bundle::new("p2");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_named(&bundle, &ld, "/nonexistent:/opt/bin", "probe");
        let id = ContainerId::new(format!("plp2{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Err(e) => {
                println!(
                    "production_launcher: scenario=p2 start refused code={:?}",
                    e.code()
                );
                assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            }
            Ok(started) => {
                let exit = started.process().wait(timeout());
                let (_record, process) = started.into_parts();
                let _ = process.terminate(timeout());
                assert_eq!(exit.expect("wait"), Some(ProcessExit::Exited(127)));
            }
        }
        assert!(eventually(|| children_of_self().is_empty()));
        println!(
            "production_launcher: scenario=bare-name resolved via PATH, exit code {EXIT_CODE}; missing name not started"
        );
    }

    /// root 実行: launch が拒否され、状態は Created に戻り、子が残らない（SEC-5。成功起動は試さない）。
    fn scenario_root_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("r");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plr{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        let err = match result {
            Ok(_) => panic!("start must be refused for root (SEC-5)"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after a refused root launch"
        );
        println!(
            "production_launcher: scenario=root-refused code={:?}",
            err.code()
        );
    }
}
