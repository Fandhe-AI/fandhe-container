//! CLI の実バイナリだけで、`create` の `--network none|host`・`--add-host`・`--dns` が本番の rootless の `start` で
//! 実際にコンテナへ効くこと、`delete` の後に生成物の残骸が無いことを確かめる実機前提の結合試験
//! （#3345・NET-6・NET-12・CLI-1・SEC-1・REPAIR-5・REPAIR-12。TASK-186 追補・MS-4。結線は #1873・PR #3322）。
//!
//! # 既存の試験との分担（重複させない）
//! - core の `etc_files_mount`: launcher の `/etc/hosts`・`/etc/resolv.conf` の bind を直接照合する。
//! - core の `lo_self_delivery`: 非特権 netns の `lo` の up 前後の自己宛て配送を照合する。
//! - supervisor の `start_network_prepare`: start の手順 4b（生成・巻き戻し）を既定の集合で照合する。
//! - `start_stop_delete_real`: start から delete までの通し（network 指定なし）。
//!
//! 本試験は CLI の `create` → `start` → `logs` → `stop` → `delete` を通した観測だけを担う。コンテナ内のプローブ
//! （`--container-probe`）が netns の素性・インターフェース・`lo` の自己宛て配送・`/etc/hosts`・`/etc/resolv.conf`・
//! 名前解決を固定語彙の行で出し、親が `logs` の完全一致とホスト側のバイト列で照合する。
//!
//! # シナリオ
//! 1. 既定（`--network` 省略。Linux の create は文書に `network none` を書く）: 新しい netns に `lo` だけ。生成物は作られず、
//!    イメージ側の `/etc/hosts` がそのまま見える。
//! 2. `--network none --add-host ... --dns 127.0.0.53`: `lo` だけ。`--add-host` の名前が IPv4・IPv6 に解決され、
//!    resolv.conf は `--dns` だけ。running の間の 2 回目の `start` は `FAILED_PRECONDITION` で拒否され、
//!    生成物の inode・内容が変わらない（並行 start の負け側の巻き戻しが勝った側の生成物を消さないことの実機側の補強。
//!    既定の集合の照合は supervisor の `start_network_prepare`。`docs/design/network-wiring.md` D14）。
//! 3. `--network host --dns ...`: ホストの netns を共有し（`/proc/self/ns/net` が親と一致）、resolv.conf は `--dns` だけ。
//!    supervisor のログに固定行 `network_mode` が出る。
//!
//! 各シナリオの delete の後に `@container-etc/<id>`・状態ディレクトリ・起動オプションの文書・ログ・プロセスの残骸が無いこと、
//! 2 回目の delete が `NOT_FOUND` であることを確かめる。
//!
//! # 必要環境
//! Linux 6.12 以上（Landlock ABI 6 以上）・cgroup v2・非 root・非特権 user namespace・`systemd-run --user`（user マネージャ）。
//! 試験全体を `systemd-run --user --scope -p Delegate=yes` で包んで実行する。事前に `cargo build -p fandhe-container-supervisor`
//! を行う。CLI と supervisor は作業ディレクトリへ 0755 でコピーし、特権ランチャーは置かない。前提が欠けたら skip ではなく失敗する。
//! host モードは runner の netns を共有するだけで、ホストのネットワーク設定を変えない。
//!
//! # 実機前提テストとしての分離
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。未指定は案内を出して成功する。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor
//! cargo test -p fandhe-container-cli --test network_modes_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/network_modes_real-XXXX> --ignored
//! ```
//!
//! 前提欠如（委譲 cgroup・Landlock ABI）は 1 行目が `network_modes_real: PRECONDITION FAILED (test environment, ...)` になり、
//! それ以外の失敗は `network_modes_real: FAILED: ...`。CI は両方を禁止行にする。使い捨ての CI runner（`platform-ci` の ubuntu）で
//! 実行し、成功行を `scripts/check-success-lines.sh` が照合する。手元の実機での実行と記録は人間担当（#349）で、Agent はホストに
//! transient scope と cgroup を作るため手元では実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_modes_real: skipped (linux only)");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("network_modes_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    }
    linux::main()
}

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
#[path = "../../core/tests/support/minimal_rootfs.rs"]
mod minimal_rootfs;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::fs;
    use std::io::{Read, Write as _};
    use std::net::{ToSocketAddrs as _, UdpSocket};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use fandhe_container_core::etc_files::{
        ETC_DIR_NAME, EtcFileKind, INITIAL_HOSTS, etc_dir, etc_file_path,
    };
    use fandhe_container_core::exec::SIGTERM_HANDLER_EXIT_CODE_FOR_TEST;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{ContainerId, GetStateRequest, StateStore};
    use fandhe_container_net::add_host_dns::resolv_conf::ResolvConfPlan;
    use fandhe_container_net::network_mode::NetworkMode;
    use fandhe_container_supervisor::container_options::store::options_path;

    /// `start` を待つ上限（CLI 自身の受信期限より長く取る。REPAIR-5）。
    const START_TIMEOUT: Duration = Duration::from_secs(90);
    /// `start` 以外の CLI を待つ上限（REPAIR-5）。
    const CLI_TIMEOUT: Duration = Duration::from_secs(30);
    /// kill 後の回収・出力収集の上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 状態・ハンドラ登録の待ちの上限（REPAIR-5）。
    const STATE_TIMEOUT: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(20);
    /// プローブの寿命の上限。これを過ぎたら終了コード 8 で終わる（寿命切れを停止と取り違えないための目印）。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// プローブが `/proc`・`/etc` から読む上限(バイト)。
    const PROBE_READ_MAX: u64 = 64 * 1024;
    /// `/proc/<pid>/status` の `SigCgt` で SIGTERM（15）に当たるビット（1 << 14）。
    const SIGTERM_CAUGHT_BIT: u64 = 1 << 14;

    /// イメージ側（rootfs）の `/etc/hosts`。bind されないときにそのまま見えることの目印を含む。
    const BUNDLE_HOSTS: &str = "# bundle hosts 3345\n127.0.0.1\tlocalhost\n";
    /// rootfs の `/etc/nsswitch.conf`。DNS を引かせない（新 netns の待ち・失敗を避ける）。
    const NSSWITCH: &str = "hosts: files\n";
    /// `INITIAL_HOSTS` のリテラル（core の公開定数と二重に照合する）。
    const INITIAL_HOSTS_LITERAL: &str =
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";
    /// resolv.conf の先頭コメント（net の非公開定数の写し）。
    const RESOLV_HEADER: &str = "# Generated by fandhe-container (NET-12)\n";

    /// シナリオ 2 の `--add-host`（RFC 5737・RFC 3849・RFC 2606 の文書用の値）。
    const ADD_HOST_V4: &str = "v4.fandhe.test:192.0.2.10";
    const ADD_HOST_V6: &str = "v6.fandhe.test:2001:db8::10";
    const NONE_DNS: &str = "127.0.0.53";
    /// シナリオ 3 の `--dns`。
    const HOST_DNS_V4: &str = "192.0.2.53";
    const HOST_DNS_V6: &str = "2001:db8::53";
    /// supervisor が host モードの start 成功後に出す固定行（`start_entry.rs` の `log_network_mode_to`）。
    const HOST_MODE_LOG: &str =
        "{\"component\":\"supervisor\",\"event\":\"network_mode\",\"network_mode\":\"host\"}";

    /// コンテナ内で動くプローブ。観測値を固定語彙の行で出し、SIGTERM のハンドラ（`_exit(43)`）を登録して待つ。
    pub fn probe() -> ! {
        let mut out = std::io::stdout();
        if let Err(e) = fandhe_container_core::exec::exit_on_sigterm_for_test() {
            let _ = writeln!(out, "TERM_HANDLER_FAILED {e}");
            let _ = out.flush();
            std::process::exit(9);
        }
        let netns = fs::read_link("/proc/self/ns/net")
            .map_or_else(|e| format!("error {e}"), |p| p.display().to_string());
        let _ = writeln!(out, "NETNS {netns}");
        let _ = writeln!(out, "NET_IFACES {}", probe_ifaces());
        let _ = writeln!(out, "LO_UDP {}", probe_lo_udp());
        let _ = writeln!(out, "ETC_HOSTS_HEX {}", probe_file_hex("/etc/hosts"));
        let _ = writeln!(out, "ETC_RESOLV_HEX {}", probe_file_hex("/etc/resolv.conf"));
        if let Ok(names) = std::env::var("PROBE_RESOLVE") {
            for name in names.split(',').filter(|n| !n.is_empty()) {
                let _ = writeln!(out, "RESOLVE {name} {}", probe_resolve(name));
            }
        }
        let _ = writeln!(out, "READY_TERM");
        let _ = out.flush();
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    /// `/proc/self/net/dev` のインターフェース名（ソートしてカンマ区切り）。読めなければ `unreadable`。
    fn probe_ifaces() -> String {
        let mut text = String::new();
        let read = fs::File::open("/proc/self/net/dev")
            .and_then(|f| f.take(PROBE_READ_MAX).read_to_string(&mut text));
        if read.is_err() {
            return "unreadable".to_string();
        }
        let mut names: Vec<&str> = text
            .lines()
            .skip(2)
            .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim()))
            .collect();
        names.sort_unstable();
        names.join(",")
    }

    /// 127.0.0.1 の UDP で自分宛てに 1 バイト送って受ける（`lo` が up であることの観測）。成功は `ok`、失敗は理由。
    fn probe_lo_udp() -> String {
        let run = || -> std::io::Result<()> {
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            sock.set_read_timeout(Some(Duration::from_secs(2)))?;
            let addr = sock.local_addr()?;
            sock.send_to(&[0x5a], addr)?;
            let mut buf = [0u8; 1];
            let (n, _) = sock.recv_from(&mut buf)?;
            if n == 1 && buf[0] == 0x5a {
                Ok(())
            } else {
                Err(std::io::Error::other("unexpected payload"))
            }
        };
        match run() {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("error {:?}", e.kind()),
        }
    }

    /// ファイルの内容を 16 進で（タブ・改行をログ上で崩さないため）。無ければ `missing`、読めなければ `unreadable`。
    fn probe_file_hex(path: &str) -> String {
        let mut buf = Vec::new();
        match fs::File::open(path).and_then(|f| f.take(PROBE_READ_MAX).read_to_end(&mut buf)) {
            Ok(_) => hex(&buf),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing".to_string(),
            Err(_) => "unreadable".to_string(),
        }
    }

    /// `getaddrinfo`（`ToSocketAddrs`）で解決した IP を重複除去・ソートして空白区切りで返す。失敗は `error <kind>`。
    fn probe_resolve(name: &str) -> String {
        match (name, 0u16).to_socket_addrs() {
            Ok(it) => {
                let mut ips: Vec<String> = it.map(|a| a.ip().to_string()).collect();
                ips.sort_unstable();
                ips.dedup();
                ips.join(" ")
            }
            Err(e) => format!("error {:?}", e.kind()),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn main() -> ExitCode {
        super::precondition::self_check();
        if !std::env::args().skip(1).any(|a| a == "--ignored") {
            println!(
                "network_modes_real: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            return ExitCode::SUCCESS;
        }
        match scenario() {
            Ok(()) => {
                println!(
                    "network_modes_real: default network ran in a new network namespace with only lo up; image /etc/hosts was kept and no etc files were generated"
                );
                println!(
                    "network_modes_real: none resolved v4.fandhe.test and v6.fandhe.test from --add-host; resolv.conf held only the loopback --dns; only lo was present"
                );
                println!(
                    "network_modes_real: a second start of the running container was refused and left its generated hosts and resolv.conf unchanged"
                );
                println!(
                    "network_modes_real: host shared the host network namespace; resolv.conf held exactly the --dns nameservers; supervisor logged network_mode host"
                );
                println!(
                    "network_modes_real: delete left no generated etc files, state dir, options document or logs for the default, none and host containers"
                );
                ExitCode::SUCCESS
            }
            Err(super::precondition::Failure::Precondition(msg)) => {
                eprintln!("{msg}");
                ExitCode::FAILURE
            }
            Err(super::precondition::Failure::Other(e)) => {
                eprintln!("network_modes_real: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn expect(cond: bool, what: &str) -> Result<(), String> {
        if cond { Ok(()) } else { Err(what.to_string()) }
    }

    /// `logs` の出力に、行全体が `want` と一致する行があるか。
    fn has_line(logs: &str, want: &str) -> bool {
        logs.lines().any(|l| l == want)
    }

    fn expect_line(logs: &str, want: &str) -> Result<(), String> {
        expect(
            has_line(logs, want),
            &format!("logs lack the line {want:?}: {logs:?}"),
        )
    }

    /// ホスト側で読む生成物（内容と `(st_dev, st_ino)`）。
    struct Generated {
        content: Vec<u8>,
        ident: (u64, u64),
    }

    fn read_generated(
        root: &Path,
        id: &ContainerId,
        kind: EtcFileKind,
    ) -> Result<Generated, String> {
        let path = etc_file_path(root, id, kind);
        let content = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let md = fs::metadata(&path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        Ok(Generated {
            content,
            ident: (md.dev(), md.ino()),
        })
    }

    /// 失敗時の後始末。生きている ID を CLI の `stop`・`delete`（`NOT_FOUND` も成功扱い）で回収し、作業ディレクトリを消す。
    /// `state.json` の pid へ生の kill は送らない（PID 再利用で無関係なプロセスを止めない。SEC-1）。
    struct Cleanup {
        cli: PathBuf,
        work: PathBuf,
        root: String,
        live: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let mut left = false;
            for id in std::mem::take(&mut self.live) {
                if let Err(e) =
                    run_cli(&self.cli, &["--root", &self.root, "stop", &id], CLI_TIMEOUT)
                {
                    eprintln!("network_modes_real: cleanup stop failed: {e}");
                }
                let mut last = String::from("not attempted");
                let ok = wait_until(
                    STATE_TIMEOUT,
                    "cleanup delete to succeed",
                    || match run_cli(
                        &self.cli,
                        &["--root", &self.root, "delete", &id],
                        CLI_TIMEOUT,
                    ) {
                        Ok(o) if o.code == Some(0) || o.code == Some(3) => true,
                        Ok(o) => {
                            last = format!("exit {:?} stderr={:?}", o.code, o.stderr);
                            false
                        }
                        Err(e) => {
                            last = e;
                            false
                        }
                    },
                );
                if let Err(e) = ok {
                    eprintln!("network_modes_real: cleanup delete failed ({e}; last: {last})");
                    left = true;
                }
            }
            if left {
                eprintln!(
                    "network_modes_real: leaving {} for diagnosis",
                    self.work.display()
                );
                return;
            }
            if let Err(e) = fs::remove_dir_all(&self.work) {
                eprintln!("network_modes_real: cleanup remove work dir failed: {e}");
            }
            // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避。#2887）。
            super::scratch_root::remove_scratch_root();
        }
    }

    /// 前提の検査。欠けたら skip せず失敗にする。
    ///
    /// 委譲 cgroup と Landlock ABI の欠如だけを `PRECONDITION FAILED` にする（`start_stop_delete_real` と同じ分類。#2957）。
    fn check_prerequisites() -> Result<(), super::precondition::Failure> {
        if effective_uid()? == 0 {
            return Err(
                "must run as a non-root user: rootful network is UNIMPLEMENTED (#2241)".into(),
            );
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(
                "cgroup v2 is required (/sys/fs/cgroup/cgroup.controllers is missing)".into(),
            );
        }
        let hint = "run this test inside `systemd-run --user --scope -p Delegate=yes`";
        let delegated = super::precondition::delegated_cgroup()?;
        let own = fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
        let own_path = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or("no cgroup v2 line in /proc/self/cgroup")?;
        if own_path.trim_end_matches('/') != delegated.path().trim_end_matches('/') {
            return Err(format!("detected cgroup differs from own cgroup; {hint}").into());
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
        let private = Path::new(&runtime).join("systemd/private");
        let is_socket = fs::symlink_metadata(&private)
            .map(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()))
            .unwrap_or(false);
        expect(is_socket, "the systemd user manager socket is missing")?;
        super::precondition::landlock_support()?;
        Ok(())
    }

    fn scenario() -> Result<(), super::precondition::Failure> {
        check_prerequisites()?;
        scenario_body().map_err(super::precondition::Failure::Other)
    }

    /// 3 シナリオが共有する環境。
    struct Env {
        cli: PathBuf,
        root: PathBuf,
        root_s: String,
        work: PathBuf,
        sup_needle: Vec<u8>,
        root_needle: Vec<u8>,
        /// 親（本試験）の `/proc/self/ns/net`。host の判定と他モードの「異なる netns」の判定に使う。
        parent_netns: String,
    }

    /// 起動済みのコンテナ。
    struct Running {
        id_s: String,
        id: ContainerId,
        pid: u32,
        logs: String,
    }

    /// 前提の検査を終えた後の本体。ここでの失敗は回帰として扱う。
    fn scenario_body() -> Result<(), String> {
        // 期待値のリテラルを core・net の公開 API から導いた値と突き合わせる（打ち間違いで試験が弱まるのを防ぐ二重照合）。
        expect(
            INITIAL_HOSTS == INITIAL_HOSTS_LITERAL.as_bytes(),
            "INITIAL_HOSTS literal differs from core's INITIAL_HOSTS",
        )?;
        let none_resolv = expected_resolv(NetworkMode::None, &[NONE_DNS])?;
        expect(
            none_resolv == format!("{RESOLV_HEADER}nameserver {NONE_DNS}\n"),
            "none resolv.conf literal differs from net's ResolvConfPlan",
        )?;
        let host_resolv = expected_resolv(NetworkMode::Host, &[HOST_DNS_V4, HOST_DNS_V6])?;
        expect(
            host_resolv
                == format!("{RESOLV_HEADER}nameserver {HOST_DNS_V4}\nnameserver {HOST_DNS_V6}\n"),
            "host resolv.conf literal differs from net's ResolvConfPlan",
        )?;

        let cli_src = PathBuf::from(env!("CARGO_BIN_EXE_fandhe-container"));
        let sup_src = cli_src
            .parent()
            .map(|d| d.join("fandhe-container-supervisor"))
            .ok_or("cli has no parent directory")?;
        if !sup_src.is_file() {
            return Err(format!(
                "{} is missing; run `cargo build -p fandhe-container-supervisor` first",
                sup_src.display()
            ));
        }
        let parent_netns = fs::read_link("/proc/self/ns/net")
            .map_err(|e| format!("read own netns: {e}"))?
            .display()
            .to_string();

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let work = super::scratch_root::scratch_root("fandhe-nmr-real-scratch", CLI_TIMEOUT)
            .join(format!("fandhe-nmr-real-{}-{nanos}", std::process::id()));
        fs::create_dir(&work).map_err(|e| format!("create work dir: {e}"))?;
        set_mode(&work, 0o700)?;
        let root = work.join("state");
        let root_s = root.to_str().ok_or("work dir is not UTF-8")?.to_string();
        let mut cleanup = Cleanup {
            cli: PathBuf::new(),
            work: work.clone(),
            root: root_s.clone(),
            live: Vec::new(),
        };

        // CLI と supervisor を 0755 でコピーする。特権ランチャーは置かない（置くと rootful 経路に入る）。
        let bin = work.join("bin");
        fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        set_mode(&bin, 0o755)?;
        let cli = bin.join("fandhe-container");
        fs::copy(&cli_src, &cli).map_err(|e| format!("copy cli: {e}"))?;
        set_mode(&cli, 0o755)?;
        let supervisor = bin.join("fandhe-container-supervisor");
        fs::copy(&sup_src, &supervisor).map_err(|e| format!("copy supervisor: {e}"))?;
        set_mode(&supervisor, 0o755)?;
        expect(
            !bin.join("fandhe-container-launcher").exists(),
            "a privileged launcher must not sit next to the cli",
        )?;
        cleanup.cli = cli.clone();
        fs::create_dir(&root).map_err(|e| format!("mkdir state root: {e}"))?;
        set_mode(&root, 0o700)?;

        let env = Env {
            cli,
            root,
            root_s: root_s.clone(),
            work,
            sup_needle: supervisor.to_string_lossy().into_owned().into_bytes(),
            root_needle: root_s.into_bytes(),
            parent_netns,
        };
        let pid_s = std::process::id();

        default_network(&env, &mut cleanup, &format!("nmr{pid_s}a"))?;
        none_network(&env, &mut cleanup, &format!("nmr{pid_s}b"), &none_resolv)?;
        host_network(&env, &mut cleanup, &format!("nmr{pid_s}c"), &host_resolv)?;
        Ok(())
    }

    fn expected_resolv(mode: NetworkMode, dns: &[&str]) -> Result<String, String> {
        ResolvConfPlan::for_mode(mode, dns)
            .map_err(|e| format!("resolv plan: {e:?}"))?
            .map(|p| p.render())
            .ok_or_else(|| "resolv plan is empty".to_string())
    }

    /// シナリオ 1: `--network` 省略（Linux の create は文書に `network none` を書く）。
    fn default_network(env: &Env, cleanup: &mut Cleanup, id_s: &str) -> Result<(), String> {
        let run = launch(env, cleanup, id_s, &[], "")?;
        let logs = &run.logs;
        expect_line(logs, "stdout NET_IFACES lo")?;
        expect_line(logs, "stdout LO_UDP ok")?;
        expect(
            !has_line(logs, &format!("stdout NETNS {}", env.parent_netns)),
            "default network shares the parent's network namespace",
        )?;
        expect_line(
            logs,
            &format!("stdout ETC_HOSTS_HEX {}", hex(BUNDLE_HOSTS.as_bytes())),
        )?;
        expect_line(logs, "stdout ETC_RESOLV_HEX missing")?;
        expect(
            !etc_dir(&env.root, &run.id).exists(),
            "etc files were generated without --add-host or --dns",
        )?;
        let sup_log = read_supervisor_log(env, id_s)?;
        expect(
            !sup_log.contains("\"event\":\"network_mode\""),
            "supervisor logged network_mode for the default network",
        )?;
        finish(env, cleanup, &run)
    }

    /// シナリオ 2: `--network none` と `--add-host`・`--dns`。running の間の 2 回目の start も確かめる。
    fn none_network(
        env: &Env,
        cleanup: &mut Cleanup,
        id_s: &str,
        want_resolv: &str,
    ) -> Result<(), String> {
        let run = launch(
            env,
            cleanup,
            id_s,
            &[
                "--network",
                "none",
                "--add-host",
                ADD_HOST_V4,
                "--add-host",
                ADD_HOST_V6,
                "--dns",
                NONE_DNS,
            ],
            "v4.fandhe.test,v6.fandhe.test",
        )?;
        let logs = &run.logs;
        expect_line(logs, "stdout NET_IFACES lo")?;
        expect_line(logs, "stdout LO_UDP ok")?;
        expect(
            !has_line(logs, &format!("stdout NETNS {}", env.parent_netns)),
            "network none shares the parent's network namespace",
        )?;
        expect_line(logs, "stdout RESOLVE v4.fandhe.test 192.0.2.10")?;
        expect_line(logs, "stdout RESOLVE v6.fandhe.test 2001:db8::10")?;

        let want_hosts = format!(
            "{INITIAL_HOSTS_LITERAL}192.0.2.10\tv4.fandhe.test\n2001:db8::10\tv6.fandhe.test\n"
        );
        let hosts = read_generated(&env.root, &run.id, EtcFileKind::Hosts)?;
        let resolv = read_generated(&env.root, &run.id, EtcFileKind::ResolvConf)?;
        expect(
            hosts.content == want_hosts.as_bytes(),
            &format!(
                "generated hosts: {:?}",
                String::from_utf8_lossy(&hosts.content)
            ),
        )?;
        expect(
            resolv.content == want_resolv.as_bytes(),
            &format!(
                "generated resolv.conf: {:?}",
                String::from_utf8_lossy(&resolv.content)
            ),
        )?;
        // コンテナ内からも同じバイト列が見える（bind で載っていること）
        expect_line(
            logs,
            &format!("stdout ETC_HOSTS_HEX {}", hex(&hosts.content)),
        )?;
        expect_line(
            logs,
            &format!("stdout ETC_RESOLV_HEX {}", hex(&resolv.content)),
        )?;

        // running の間の 2 回目の start は拒否され、生成物に触れない
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "start", &run.id_s],
            START_TIMEOUT,
        )?;
        if out.code != Some(5) || !out.stdout.is_empty() {
            return Err(format!(
                "second start: want exit 5, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let (op, code) = op_and_code(&out.stderr)?;
        if op != "start" || code != "FAILED_PRECONDITION" {
            return Err(format!(
                "second start: want op=start code=FAILED_PRECONDITION, got op={op} code={code}"
            ));
        }
        let hosts_after = read_generated(&env.root, &run.id, EtcFileKind::Hosts)?;
        let resolv_after = read_generated(&env.root, &run.id, EtcFileKind::ResolvConf)?;
        expect(
            hosts_after.ident == hosts.ident && hosts_after.content == hosts.content,
            "the refused second start changed the generated hosts",
        )?;
        expect(
            resolv_after.ident == resolv.ident && resolv_after.content == resolv.content,
            "the refused second start changed the generated resolv.conf",
        )?;
        let logs_after = fetch_logs(env, &run.id_s)?;
        expect_line(
            &logs_after,
            &format!("stdout ETC_HOSTS_HEX {}", hex(&hosts.content)),
        )?;
        expect_line(&logs_after, "stdout RESOLVE v6.fandhe.test 2001:db8::10")?;
        finish(env, cleanup, &run)
    }

    /// シナリオ 3: `--network host` と `--dns`。
    fn host_network(
        env: &Env,
        cleanup: &mut Cleanup,
        id_s: &str,
        want_resolv: &str,
    ) -> Result<(), String> {
        let run = launch(
            env,
            cleanup,
            id_s,
            &[
                "--network",
                "host",
                "--dns",
                HOST_DNS_V4,
                "--dns",
                HOST_DNS_V6,
            ],
            "",
        )?;
        let logs = &run.logs;
        // 判定の決め手: コンテナの netns が親と同一
        expect_line(logs, &format!("stdout NETNS {}", env.parent_netns))?;
        let ifaces = logs
            .lines()
            .find_map(|l| l.strip_prefix("stdout NET_IFACES "))
            .ok_or("logs lack NET_IFACES")?;
        expect(
            ifaces.split(',').any(|n| n == "lo"),
            &format!("host interfaces lack lo: {ifaces:?}"),
        )?;
        // --dns だけなので生成されるのは resolv.conf だけ。hosts はイメージ側のまま見える
        let resolv = read_generated(&env.root, &run.id, EtcFileKind::ResolvConf)?;
        expect(
            resolv.content == want_resolv.as_bytes(),
            &format!(
                "generated resolv.conf: {:?}",
                String::from_utf8_lossy(&resolv.content)
            ),
        )?;
        expect(
            !etc_file_path(&env.root, &run.id, EtcFileKind::Hosts).exists(),
            "hosts was generated without --add-host",
        )?;
        expect_line(
            logs,
            &format!("stdout ETC_RESOLV_HEX {}", hex(&resolv.content)),
        )?;
        expect_line(
            logs,
            &format!("stdout ETC_HOSTS_HEX {}", hex(BUNDLE_HOSTS.as_bytes())),
        )?;
        // supervisor の構造化ログに固定行が出る（ログの flush は非同期のため期限内で待つ）
        wait_until(
            STATE_TIMEOUT,
            "supervisor log to record network_mode host",
            || read_supervisor_log(env, id_s).is_ok_and(|t| t.contains(HOST_MODE_LOG)),
        )?;
        finish(env, cleanup, &run)
    }

    fn read_supervisor_log(env: &Env, id_s: &str) -> Result<String, String> {
        let path = env
            .root
            .join("@supervisor-logs")
            .join(format!("{id_s}.log"));
        let mut text = String::new();
        fs::File::open(&path)
            .and_then(|f| f.take(4 * 1024 * 1024).read_to_string(&mut text))
            .map_err(|e| format!("read supervisor log: {e}"))?;
        Ok(text)
    }

    fn fetch_logs(env: &Env, id_s: &str) -> Result<String, String> {
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "logs", id_s],
            CLI_TIMEOUT,
        )?;
        expect_ok_code(&out, "logs")?;
        Ok(out.stdout)
    }

    /// create → start → プローブの出力待ちまで進める。`resolve` は `PROBE_RESOLVE`（空なら名前解決しない）。
    fn launch(
        env: &Env,
        cleanup: &mut Cleanup,
        id_s: &str,
        extra: &[&str],
        resolve: &str,
    ) -> Result<Running, String> {
        let bundle = env.work.join(format!("bundle-{id_s}"));
        make_bundle(&bundle, resolve)?;
        let bundle_s = bundle.to_str().ok_or("bundle path is not UTF-8")?;
        let mut args = vec!["--root", env.root_s.as_str(), "create"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--bundle", bundle_s, id_s]);
        let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
        expect_ok(&out, "create")?;
        cleanup.live.push(id_s.to_string());
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "start", id_s],
            START_TIMEOUT,
        )?;
        expect_ok(&out, "start")?;
        let out = run_cli(&env.cli, &["--root", &env.root_s, "list"], CLI_TIMEOUT)?;
        let pid = parse_running_list(&out, id_s)?;
        wait_sigterm_handler(pid, "SIGTERM handler registration")?;
        // ハンドラ登録後でも supervisor の非同期ログ捕捉は未完のことがあるため、READY_TERM まで期限内で再取得する（REPAIR-5）。
        let mut last = String::new();
        let mut logs = String::new();
        wait_until(
            STATE_TIMEOUT,
            "logs to contain READY_TERM",
            || match fetch_logs(env, id_s) {
                Ok(t) => {
                    let found = has_line(&t, "stdout READY_TERM");
                    logs = t.clone();
                    last = t;
                    found
                }
                Err(e) => {
                    last = e;
                    false
                }
            },
        )
        .map_err(|e| format!("{e}; last logs: {last:?}"))?;
        let id = ContainerId::new(id_s.to_string()).map_err(|e| format!("id: {e:?}"))?;
        Ok(Running {
            id_s: id_s.to_string(),
            id,
            pid,
            logs,
        })
    }

    /// stop → Stopped(43) → プロセスの消滅 → delete → 残骸の照合 → 2 回目の delete が `NOT_FOUND`。
    fn finish(env: &Env, cleanup: &mut Cleanup, run: &Running) -> Result<(), String> {
        let id_s = run.id_s.as_str();
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "stop", id_s],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, "stop")?;
        let want = format!("ID\tSTATUS\tPID\n{id_s}\tstopped\t-\n");
        wait_until(STATE_TIMEOUT, "list to report stopped", || {
            run_cli(&env.cli, &["--root", &env.root_s, "list"], CLI_TIMEOUT)
                .is_ok_and(|o| o.code == Some(0) && o.stdout == want)
        })?;
        let store = {
            let root =
                StateRoot::from_override(env.root.clone()).map_err(|e| format!("root: {e:?}"))?;
            FileStateStore::open(root).map_err(|e| format!("open store: {e:?}"))?
        };
        let rec = store
            .get(&GetStateRequest::new(run.id.clone()))
            .map_err(|e| format!("get: {e:?}"))?;
        if rec.status().exit_code() != Some(SIGTERM_HANDLER_EXIT_CODE_FOR_TEST) {
            return Err(format!(
                "exit code after stop: want {SIGTERM_HANDLER_EXIT_CODE_FOR_TEST}, got {:?}",
                rec.status().exit_code()
            ));
        }
        drop(store);
        let pid = run.pid;
        wait_until(REAP_TIMEOUT, "the container process to vanish", || {
            !Path::new(&format!("/proc/{pid}")).exists()
        })?;
        wait_supervisor_exit(&env.sup_needle, &env.root_needle, "the supervisor to exit")?;

        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "delete", id_s],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, "delete")?;
        cleanup.live.retain(|i| i != id_s);

        expect(
            !etc_dir(&env.root, &run.id).exists(),
            &format!("{ETC_DIR_NAME}/<id> remains after delete"),
        )?;
        expect(
            !env.root.join(id_s).exists(),
            "state dir remains after delete",
        )?;
        expect(
            !options_path(&env.root, &run.id).exists(),
            "options document remains after delete",
        )?;
        let log_prefix = format!("{id_s}.log");
        for dir in ["@supervisor-logs", "@container-logs"] {
            let names = list_prefixed(&env.root.join(dir), &log_prefix)?;
            expect(
                names.is_empty(),
                &format!("{dir} entries remain: {names:?}"),
            )?;
        }
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "delete", id_s],
            CLI_TIMEOUT,
        )?;
        if out.code != Some(3) || !out.stdout.is_empty() {
            return Err(format!(
                "second delete: want exit 3, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let (op, code) = op_and_code(&out.stderr)?;
        if op != "delete" || code != "NOT_FOUND" {
            return Err(format!(
                "second delete: want op=delete code=NOT_FOUND, got op={op} code={code}"
            ));
        }
        Ok(())
    }

    /// bundle（`config.json` と最小 rootfs）を作る。`/probe` は本試験の実行ファイルのコピー。
    /// `resolve` は `PROBE_RESOLVE`（名前解決させる名前のカンマ区切り。空なら解決しない）。
    fn make_bundle(bundle: &Path, resolve: &str) -> Result<(), String> {
        super::minimal_rootfs::mkdir(bundle)?;
        // glibc が NSS の files モジュールを dlopen する環境でも、そのライブラリを読み込み済みにして rootfs へコピーさせる。
        let _ = ("localhost", 0u16).to_socket_addrs();
        let rootfs = bundle.join("rootfs");
        let ld = super::minimal_rootfs::install_binary_at(
            &rootfs,
            "probe",
            &["proc", "dev", "tmp", "etc"],
        )?;
        for (name, body) in [("hosts", BUNDLE_HOSTS), ("nsswitch.conf", NSSWITCH)] {
            let path = rootfs.join("etc").join(name);
            fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
            set_mode(&path, 0o644)?;
        }
        // uidMappings / gidMappings・cgroupsPath は書かない。namespaces に network は書かない（モードで決まる）。
        let config = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-nmr",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}","PROBE_RESOLVE={resolve}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        );
        fs::write(bundle.join("config.json"), config).map_err(|e| format!("write config: {e}"))
    }
    /// `/proc/<pid>/status` の `SigCgt` に SIGTERM のビットが立つまで待つ（登録前に TERM を送ると PID 1 では捨てられる）。
    fn wait_sigterm_handler(pid: u32, what: &str) -> Result<(), String> {
        wait_until(STATE_TIMEOUT, what, || {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("SigCgt:"))
                        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                })
                .is_some_and(|m| m & SIGTERM_CAUGHT_BIT != 0)
        })
    }

    /// この状態ルートの supervisor が全員終わるまで待つ。delete の supervisor ログ削除は 1 回だけ試す（待たない）ため、
    /// sink のロックを手放す（プロセス終了）まで待つ。
    fn wait_supervisor_exit(
        sup_needle: &[u8],
        root_needle: &[u8],
        what: &str,
    ) -> Result<(), String> {
        wait_until(REAP_TIMEOUT, what, || {
            count_processes(|dir| {
                fs::read(dir.join("cmdline")).is_ok_and(|c| {
                    c.starts_with(sup_needle)
                        && c.windows(root_needle.len()).any(|w| w == root_needle)
                })
            }) == 0
        })
    }

    /// 子を kill し、`REAP_TIMEOUT` 内に `try_wait` で回収する（無期限の `wait` を避ける。REPAIR-5）。
    fn kill_and_reap(c: &mut Child) -> Result<(), String> {
        let kill_err = c.kill().err();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match c.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() >= deadline => {
                    return Err(format!(
                        "child was not reaped within {REAP_TIMEOUT:?} (kill: {kill_err:?})"
                    ));
                }
                Ok(None) => thread::sleep(POLL),
                Err(e) => return Err(format!("reap child: {e}")),
            }
        }
    }

    /// `dir` 直下で `prefix` 始まりの名前を返す。ディレクトリ不存在（NotFound）だけを空とし、
    /// それ以外の読み取り失敗（PermissionDenied 等）とエントリ単位の失敗はエラーにする。
    fn list_prefixed(dir: &Path, prefix: &str) -> Result<Vec<String>, String> {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("read dir {}: {e}", dir.display())),
        };
        let mut names = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| format!("read dir entry {}: {e}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) {
                names.push(name);
            }
        }
        Ok(names)
    }

    fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))
    }

    fn wait_until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        loop {
            if f() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out after {limit:?} waiting for {what}"));
            }
            thread::sleep(POLL);
        }
    }

    /// `/proc` の全プロセスのうち、`/proc/<pid>` のディレクトリが条件に合うものの数。
    fn count_processes(pred: impl Fn(&Path) -> bool) -> usize {
        let Ok(dir) = fs::read_dir("/proc") else {
            return 0;
        };
        dir.flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
                    && pred(&e.path())
            })
            .count()
    }

    /// `list` の stdout が `ID\tSTATUS\tPID\n<id>\trunning\t<pid>\n` と完全一致することを確かめ、pid を返す。
    fn parse_running_list(out: &RunOut, id: &str) -> Result<u32, String> {
        expect_ok_code(out, "list")?;
        let body = out
            .stdout
            .strip_prefix("ID\tSTATUS\tPID\n")
            .ok_or_else(|| format!("list header: {:?}", out.stdout))?;
        let row = body
            .strip_prefix(&format!("{id}\trunning\t"))
            .and_then(|r| r.strip_suffix('\n'))
            .ok_or_else(|| format!("list row: {:?}", out.stdout))?;
        let pid: u32 = row.parse().map_err(|_| format!("list pid: {row:?}"))?;
        expect(pid > 0, "list pid must be positive")?;
        Ok(pid)
    }

    fn expect_ok_code(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) {
            return Err(format!(
                "{what}: want exit 0, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    /// 終了コード 0・stdout と stderr が空。
    fn expect_ok(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) || !out.stdout.is_empty() || !out.stderr.is_empty() {
            return Err(format!(
                "{what}: want exit 0 with empty output, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    fn op_and_code(stderr: &str) -> Result<(String, String), String> {
        if !stderr.ends_with('\n') || stderr.matches('\n').count() != 1 {
            return Err(format!("stderr is not exactly one line: {stderr:?}"));
        }
        let field = |key: &str| -> Result<String, String> {
            let pat = format!("\"{key}\":\"");
            let start = stderr
                .find(&pat)
                .ok_or_else(|| format!("no {key} in {stderr:?}"))?
                + pat.len();
            let rest = stderr.get(start..).ok_or("bad offset")?;
            let len = rest
                .find('"')
                .ok_or_else(|| format!("unterminated {key} in {stderr:?}"))?;
            Ok(rest.get(..len).ok_or("bad slice")?.to_string())
        };
        Ok((field("op")?, field("code")?))
    }

    /// 実効 UID を `/proc/self/status` から読む（`unsafe` の syscall を使わないため）。
    fn effective_uid() -> Result<u32, String> {
        let text = fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        text.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "no effective uid in /proc/self/status".to_string())
    }

    struct RunOut {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    }

    /// 実バイナリを有限期限内で実行する（REPAIR-5）。試験用の差し替え口は子の環境から外し、本番の解決経路を通す。
    fn run_cli(cli: &Path, args: &[&str], limit: Duration) -> Result<RunOut, String> {
        let mut child = Command::new(cli)
            .args(args)
            .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
            .env_remove("FANDHE_CONTAINER_OP_LOG")
            .env_remove("FANDHE_CONTAINER_TEST_SYSTEMD_RUN")
            .env_remove("FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn cli: {e}"))?;
        let out_rx = spawn_reader(child.stdout.take().ok_or("stdout not piped")?);
        let err_rx = spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
        let deadline = Instant::now() + limit;
        let status = loop {
            match child.try_wait().map_err(|e| format!("poll cli: {e}"))? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    return Err(match kill_and_reap(&mut child) {
                        Ok(()) => format!("cli did not exit within {limit:?}"),
                        Err(e) => format!("cli did not exit within {limit:?}; {e}"),
                    });
                }
                None => thread::sleep(POLL),
            }
        };
        let collect = Instant::now() + REAP_TIMEOUT;
        let remaining = || collect.saturating_duration_since(Instant::now());
        let stdout = out_rx
            .recv_timeout(remaining())
            .map_err(|_| "stdout was not collected in time".to_string())?;
        let stderr = err_rx
            .recv_timeout(remaining())
            .map_err(|_| "stderr was not collected in time".to_string())?;
        Ok(RunOut {
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}
