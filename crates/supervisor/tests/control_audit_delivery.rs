//! 制御チャネルの別 uid の拒否が、実際の経路で監査の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験
//! （SEC-4・SEC-1・SUP-1・PLUG-12・#2140・REPAIR-12）。
//!
//! 既存の `control_channel` 試験は `serve_connection` へ偽の `PeerCred` と収集用の sink を渡す単体寄りの照合で、
//! accept ループ → `SO_PEERCRED` → `ControlObserver` → 監査 helper（`ControlAuditRelay`）→ `FileAuditSink` →
//! ファイルの全経路は通っていなかった。本試験は supervisor の `start` と同じ順序（スレッドを作る前に relay を
//! fork → listener を bind → サーバスレッド起動）で組み、本番の記録先のファイルの JSON Lines まで照合する。
//!
//! シナリオは排他で、`--ignored` を付けたときは実機のシナリオだけを実行する（既定のシナリオとは同一プロセスで
//! 両立しない。上記のスレッド要件のため）。
//!
//! - 既定のシナリオ（`--ignored` なし。CI の既定集合。root は使わない）: サーバに「期待する uid」として自分の実効 uid
//!   と異なる値を渡し、自プロセスからの接続を別 uid 相当として拒否させる。接続元の資格情報はカーネルの
//!   `SO_PEERCRED` で、注入するのは期待値だけ。1 バイトも書かれずに切断されること、`@audit.log` に層
//!   `control_channel`・理由 `control_peer_uid_mismatch`・コンテナ ID の 1 行が届くこと（uid・pid の値は載らない）を
//!   具体値で照合する
//! - 実機のシナリオ（`-- --ignored` のときだけ。root・uid/gid 65534 が要る。AGENTS.md「実機前提テスト」）: 本物の別
//!   kuid（65534）のクライアントが、1 層目のファイル権限を意図的に外した（試験内だけ。ディレクトリ 0711・ソケット
//!   0666）ソケットへ接続し、2 層目の `SO_PEERCRED` 検査で拒否されて同じ 1 行が届くことを照合する。前提が満たせない
//!   ときは skip せず非ゼロで失敗する
//!
//! `open_control_audit_relay`（`ControlAuditRelay::spawn_ignoring_stop_signals`）は単一スレッドの呼び出し元を要求するため、`harness = false` の単一スレッド `main`
//! で動かす（`exec_audit` と同じ）。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("control_audit_delivery: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditSink, RECORD_WAIT_LIMIT};
    use fandhe_container_core::traits::ContainerId;
    use fandhe_container_supervisor::audit_relay::open_control_audit_relay;
    use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
    use fandhe_container_supervisor::control::observe::ControlObserver;
    use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
    use fandhe_container_supervisor::control::target::SignalSlot;

    const CHILD_ENV: &str = "FANDHE_CONTROL_AUDIT_DELIVERY_CHILD";
    const CONTAINER: &str = "audited-2140";
    /// 実機のシナリオで接続する非特権 uid / gid（nobody 相当）。
    const OTHER_ID: u32 = 65534;
    /// 子（別 uid のクライアント）の待機上限（REPAIR-5）。
    const CHILD_TIMEOUT: Duration = Duration::from_secs(15);
    /// 記録の到達を待つ余裕（relay の最悪待ちに足す）。
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    pub fn run() {
        if let Ok(path) = std::env::var(CHILD_ENV) {
            child(Path::new(&path));
            return;
        }
        // 1 プロセスで走らせるシナリオは 1 つだけにする。既定シナリオの拒否処理が常駐の
        // `supervisor-stderr` スレッドを作り（static に保持され終了しない）、続けて実機シナリオが
        // `ControlAuditRelay::spawn` の単一スレッド要件に違反するため。
        if std::env::args().any(|a| a == "--ignored") {
            real_scenario();
        } else {
            default_scenario();
            println!(
                "control_audit_delivery: real-machine scenario skipped (run with -- --ignored as root)"
            );
        }
        println!("control_audit_delivery: all scenarios passed");
    }

    /// 0700 の排他作成で作る一時ディレクトリ（drop で削除。既存・symlink は追従せず失敗する）。
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for attempt in 0..16u32 {
                let path = std::env::temp_dir()
                    .join(format!("fc-cad-{}-{nanos}-{attempt}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => panic!("create temp root: {e}"),
                }
            }
            panic!("could not create a unique temp root");
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 本番（`start_entry`）と同じ順序の受け側一式。drop の順は server → listener → relay → 一時ルート。
    struct Rig {
        server: ControlServer,
        listener: ControlListener,
        root: TempRoot,
        /// 監査 helper の pid（停止シグナルの扱いの照合用。#3415）。
        helper_pid: u32,
    }

    impl Rig {
        fn start() -> Self {
            let root = TempRoot::new();
            let id = ContainerId::new(CONTAINER).expect("container id");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(root.0.join(id.as_str()))
                .expect("create state dir");
            // スレッドを作る前に relay を fork する（本番と同じ。以降の記録は helper へ渡る）。
            // 本番（`start_entry`）と同じ組み立て口を通す。helper は停止シグナルを無視する（#3415）。
            let relay =
                open_control_audit_relay(Some(root.0.clone())).expect("spawn the audit relay");
            let helper_pid = relay.pid();
            let listener = ControlListener::bind(&root.0, &id).expect("bind");
            let euid = effective_uid().expect("euid");
            let observer = Arc::new(ControlObserver::new(
                Some(Arc::new(relay) as Arc<dyn AuditSink>),
                Some(id),
            ));
            let server = ControlServer::spawn(
                listener.try_clone_listener().expect("clone listener"),
                SignalSlot::new(),
                // 既定シナリオでは自プロセス（= euid）を別 uid 相当にするため、期待値を euid と異なる値にする。
                euid.wrapping_add(1),
                ServeConfig::default(),
                observer,
            )
            .expect("spawn server");
            Self {
                server,
                listener,
                root,
                helper_pid,
            }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.server.shutdown();
            let _ = &self.listener;
            let _ = &self.root;
        }
    }

    /// 接続して 1 バイトも読めないまま EOF になること（拒否は何も書かずに切断）を照合する。
    fn assert_disconnected_without_a_byte(path: &Path) {
        let mut stream = UnixStream::connect(path).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).expect("read until EOF");
        assert_eq!(n, 0, "a rejected peer must not receive any byte");
    }

    /// `@audit.log` を期限つきでポーリングし、行が出そろったら返す。
    fn wait_for_audit_lines(root: &Path) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if !lines.is_empty() || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 届いた 1 行が、層・理由・コンテナ ID の具体値で期待どおりで、uid / pid の値を理由に載せないこと。
    fn assert_one_peer_mismatch_line(lines: &[String]) {
        assert_eq!(lines.len(), 1, "exactly one audit line expected: {lines:?}");
        let line = lines.first().expect("one line");
        assert!(
            line.contains("\"layer\":\"control_channel\""),
            "layer: {line}"
        );
        assert!(
            line.contains("\"reason\":\"control_peer_uid_mismatch\""),
            "reason: {line}"
        );
        assert!(
            line.contains(&format!("\"container_id\":\"{CONTAINER}\"")),
            "container_id: {line}"
        );
        assert!(!line.contains("\"path\":\""), "no path expected: {line}");
    }

    /// SIGTERM・SIGINT の `SigIgn` のビット（シグナル番号 n はビット n-1）。
    const STOP_MASK: u64 = (1 << (2 - 1)) | (1 << (15 - 1));

    /// `/proc/<pid>/status` の `SigIgn`（16 進）。
    fn sig_ign(pid: u32) -> u64 {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
        let line = text
            .lines()
            .find(|l| l.starts_with("SigIgn:"))
            .expect("SigIgn line");
        u64::from_str_radix(line.split_whitespace().nth(1).expect("mask"), 16).expect("hex mask")
    }

    /// `/proc/<pid>/stat` の状態文字（コマンド名の `)` の後ろの最初の語）。
    fn proc_state(pid: u32) -> char {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
        let after = text.rsplit_once(')').expect("comm end").1;
        after.trim_start().chars().next().expect("state char")
    }

    /// SEC-4・REPAIR-5・#3415: 本番の組み立て口の helper は SIGTERM・SIGINT を無視し（`SigIgn` のビットが両方立つ）、
    /// helper だけへ SIGTERM を送っても死なない（未回収の子が `Z` にならない）。SIGKILL での回収は drop が担う。
    fn assert_helper_ignores_stop_signals(pid: u32) {
        assert_eq!(sig_ign(pid) & STOP_MASK, STOP_MASK, "SigIgn of the helper");
        let status = Command::new("kill")
            .args(["-s", "TERM", &pid.to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -s TERM {pid}");
        std::thread::sleep(Duration::from_millis(300));
        assert_ne!(proc_state(pid), 'Z', "the helper must survive SIGTERM");
        println!("control_audit_delivery: helper ignores SIGTERM and SIGINT (SigIgn mask 0x4002)");
    }

    fn default_scenario() {
        let rig = Rig::start();
        assert_helper_ignores_stop_signals(rig.helper_pid);
        assert_disconnected_without_a_byte(&rig.listener.socket_path());
        let lines = wait_for_audit_lines(&rig.root.0);
        assert_one_peer_mismatch_line(&lines);
        println!(
            "control_audit_delivery: peer uid mismatch reached @audit.log (1 record, default scenario)"
        );
    }

    /// 子の役割（別 uid のクライアント）: 接続して 1 バイトも読めずに EOF になれば exit 0、それ以外は 1。
    fn child(socket: &Path) {
        let ok = UnixStream::connect(socket)
            .and_then(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut buf = [0u8; 16];
                s.read(&mut buf)
            })
            .is_ok_and(|n| n == 0);
        std::process::exit(i32::from(!ok));
    }

    fn real_scenario() {
        let euid = effective_uid().expect("euid");
        assert_eq!(euid, 0, "the real-machine scenario must run as root");
        let rig = Rig::start();
        // サーバの期待 uid は euid + 1（root でない別 uid 65534 とは一致しない）。実機では本物の別 kuid の接続を使う。
        let id_dir = rig.root.0.join(CONTAINER);
        // 1 層目（ファイル権限）を意図的に外し、2 層目の SO_PEERCRED 検査を露出させる（試験内だけ）。
        std::fs::set_permissions(&rig.root.0, std::fs::Permissions::from_mode(0o711))
            .expect("chmod root");
        std::fs::set_permissions(&id_dir, std::fs::Permissions::from_mode(0o711))
            .expect("chmod state dir");
        let socket = id_dir.join("supervisor.sock");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
            .expect("chmod socket");
        // 非特権 uid が実行できる場所へ自分自身の複製を置く（ビルド出力のディレクトリは辿れないことがある）。
        let exe = rig.root.0.join("client-bin");
        std::fs::copy(std::env::current_exe().expect("current exe"), &exe).expect("copy exe");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod exe");

        let mut cmd = Command::new(&exe);
        cmd.env(CHILD_ENV, &socket)
            .uid(OTHER_ID)
            .gid(OTHER_ID)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .expect("spawn the other-uid client (uid 65534 required)");
        let deadline = Instant::now() + CHILD_TIMEOUT;
        let status = loop {
            match child.try_wait().expect("try_wait") {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    let kill_result = child.kill();
                    // 回収も有限期限までの try_wait で確認する（REPAIR-5）。
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    let mut reaped = false;
                    while Instant::now() < reap_deadline {
                        if matches!(child.try_wait(), Ok(Some(_))) {
                            reaped = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    panic!(
                        "the other-uid client did not finish in time (kill: {kill_result:?}, reaped: {reaped}; unreaped child pid {} if false)",
                        child.id()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        assert!(
            status.success(),
            "the other-uid client must be disconnected without a byte: {status:?}"
        );
        let lines = wait_for_audit_lines(&rig.root.0);
        assert_one_peer_mismatch_line(&lines);
        println!(
            "control_audit_delivery: peer uid mismatch reached @audit.log (1 record, real other-uid client)"
        );
    }
}
