//! macOS の VM 保持役の骨格（`vm_keeper`）の受け入れ試験（MAC-4・CORE-1・PLUG-12・REPAIR-5・REPAIR-12・#2278）。
//!
//! 保持役の本体は unix の共通実装で、PR の CI（ubuntu）でも回せるよう、試験バイナリ自身を `--vm-keeper-child` で再実行して
//! 子（保持役）の役にする（VM の停止は呼ばれた回数を記録する偽の `VmLifecycle`）。macOS では main の `platform-ci` で回る。
//! 実機（macOS）での「CLI 終了後も保持役が生き続ける」確認は #2282（人間担当）。
//!
//! # シナリオ（各成功行は固定の文字列。`scripts/check-success-lines.sh` が本ファイルのリテラルから導出して照合する）
//! - A: 二重起動の拒否（後発は `already running` で非 0 終了し、先発が応答し続ける）
//! - B: 4 個の同時起動でちょうど 1 個だけが残る
//! - C: SIGKILL でロックが解放され、次の保持役が stale socket を置き換えて受け付ける
//! - D: ロックだけ握られ socket が無い状態で、取得と起動待ちの期限が守られる
//! - E: 登録・解除・猶予内の再登録・猶予後の終了（VM 停止 1 回・socket 削除・ロック解放）
//! - F: 安全でない配置ディレクトリ（group/other 書き込み可・symlink）の拒否
//!
//! 全体の watchdog（別スレッド）が期限を超えたら `WATCHDOG EXPIRED` と終了コード 124 で失敗する。

#[cfg(not(unix))]
fn main() {
    println!("vm_keeper: unix only, not applicable on this OS");
}

#[cfg(unix)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};
    use fandhe_container_plugin::RuntimeDir;
    use fandhe_container_supervisor::vm_keeper::client::KeeperClient;
    use fandhe_container_supervisor::vm_keeper::lock::KeeperLock;
    use fandhe_container_supervisor::vm_keeper::protocol::Reason;
    use fandhe_container_supervisor::vm_keeper::{KeeperConfig, VmLifecycle, VmStopOutcome, run};

    use super::test_root::{TestRoot, test_root_at};

    const SOCKET_FILE: &str = "vm-keeper-default.sock";
    const WATCHDOG: Duration = Duration::from_secs(180);
    const DEFAULT_GRACE_MS: u64 = 20_000;

    type Res<T = ()> = Result<T, String>;
    type Scenario = fn() -> Res;

    fn check(cond: bool, msg: impl FnOnce() -> String) -> Res {
        if cond { Ok(()) } else { Err(msg()) }
    }

    fn te(e: TraitError) -> String {
        format!("{e}")
    }

    /// 子（保持役）の役: 偽の VM は停止のたびに印を 1 行足す。
    struct RecordingVm(PathBuf);

    impl VmLifecycle for RecordingVm {
        fn stop(&mut self, _deadline: Duration) -> Result<VmStopOutcome, TraitError> {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "marker open failed"))?;
            f.write_all(b"stop\n")
                .map_err(|_| TraitError::new(ErrorCode::Internal, "marker write failed"))?;
            Ok(VmStopOutcome::Stopped)
        }
    }

    fn child_main(args: &[String]) -> ExitCode {
        let (Some(base), Some(grace_ms), Some(marker)) = (args.get(2), args.get(3), args.get(4))
        else {
            eprintln!("vm_keeper child: bad arguments");
            return ExitCode::from(2);
        };
        let Some(grace) = grace_ms.parse::<u64>().ok().map(Duration::from_millis) else {
            return ExitCode::from(2);
        };
        let config = match KeeperConfig::new(grace) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vm_keeper child: {e}");
                return ExitCode::from(2);
            }
        };
        let mut vm = RecordingVm(PathBuf::from(marker));
        match run(&config, Path::new(base), &mut vm) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vm_keeper child error: {e}");
                ExitCode::from(3)
            }
        }
    }

    struct Keeper {
        child: Child,
        stderr: PathBuf,
    }

    impl Drop for Keeper {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Keeper {
        fn stderr_text(&self) -> String {
            std::fs::read_to_string(&self.stderr).unwrap_or_default()
        }
    }

    fn spawn_keeper(
        scratch: &Path,
        base: &Path,
        grace_ms: u64,
        marker: &Path,
        tag: &str,
    ) -> Res<Keeper> {
        let stderr = scratch.join(format!("{tag}.stderr"));
        let child =
            spawn_raw(&stderr, base, grace_ms, marker).map_err(|e| format!("spawn keeper: {e}"))?;
        Ok(Keeper { child, stderr })
    }

    fn spawn_raw(stderr: &Path, base: &Path, grace_ms: u64, marker: &Path) -> io::Result<Child> {
        let exe = std::env::current_exe()?;
        let file = File::create(stderr)?;
        Command::new(exe)
            .arg("--vm-keeper-child")
            .arg(base)
            .arg(grace_ms.to_string())
            .arg(marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(file))
            .spawn()
    }

    fn wait_exit(child: &mut Child, within: Duration) -> Res<ExitStatus> {
        let until = Instant::now() + within;
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return Ok(st),
                Ok(None) => {}
                Err(e) => return Err(format!("try_wait: {e}")),
            }
            if Instant::now() >= until {
                return Err(format!(
                    "child {} did not exit within {within:?}",
                    child.id()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_ready(client: &KeeperClient, within: Duration) -> Res<u32> {
        let until = Instant::now() + within;
        loop {
            match client.status() {
                Ok(r) => return Ok(r.keeper_pid),
                Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("keeper not ready: {e}")),
            }
        }
    }

    /// socket を置く短いパスの試験用ディレクトリ（MAC-4・REPAIR-12）。
    /// macOS の `$TMPDIR` は長く、配下の socket が sun_path の上限（104 バイト）を超えるため、
    /// `/tmp` 直下を第 1 候補に共有の `test_root_at` で排他作成する（衝突時は別名で作り直し、Drop で消える）。
    fn scratch(tag: &str) -> TestRoot {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        test_root_at(PathBuf::from(format!(
            "/tmp/fcvk-{tag}-{}-{nanos:x}",
            std::process::id()
        )))
    }

    fn runtime_dir(base: &Path) -> Res<PathBuf> {
        RuntimeDir::ensure_under(base)
            .map(|d| d.path().to_path_buf())
            .map_err(|e| format!("runtime dir: {e}"))
    }

    fn id(s: &str) -> Res<ContainerId> {
        ContainerId::new(s).map_err(te)
    }

    fn scenario_a() -> Res {
        let s = scratch("a");
        let marker = s.join("marker");
        let k1 = spawn_keeper(&s, &s, DEFAULT_GRACE_MS, &marker, "k1")?;
        let client = KeeperClient::new(&s).map_err(te)?;
        let pid1 = wait_ready(&client, Duration::from_secs(10))?;
        check(pid1 == k1.child.id(), || {
            format!("pid {pid1} != first keeper")
        })?;
        let mut k2 = spawn_keeper(&s, &s, DEFAULT_GRACE_MS, &marker, "k2")?;
        let st = wait_exit(&mut k2.child, Duration::from_secs(10))?;
        check(st.code() == Some(3), || {
            format!("second keeper status {st:?}")
        })?;
        check(
            k2.stderr_text().contains("vm keeper is already running"),
            || format!("stderr was {:?}", k2.stderr_text()),
        )?;
        let after = client.status().map_err(te)?.keeper_pid;
        check(after == pid1, || format!("pid changed {pid1} -> {after}"))?;
        println!("vm_keeper: double start rejected");
        Ok(())
    }

    fn scenario_b() -> Res {
        let s = scratch("b");
        let marker = s.join("marker");
        let mut keepers = Vec::new();
        for i in 0..4 {
            keepers.push(spawn_keeper(
                &s,
                &s,
                DEFAULT_GRACE_MS,
                &marker,
                &format!("k{i}"),
            )?);
        }
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let exited = keepers
                .iter_mut()
                .filter_map(|k| k.child.try_wait().ok().flatten())
                .count();
            if exited == 3 {
                break;
            }
            check(exited < 4, || "all keepers exited".to_string())?;
            check(Instant::now() < until, || {
                format!("only {exited} of 3 losers exited")
            })?;
            std::thread::sleep(Duration::from_millis(20));
        }
        let client = KeeperClient::new(&s).map_err(te)?;
        let pid = wait_ready(&client, Duration::from_secs(10))?;
        let mut alive = 0;
        for k in &mut keepers {
            match k.child.try_wait().map_err(|e| e.to_string())? {
                None => {
                    alive += 1;
                    check(k.child.id() == pid, || {
                        "survivor is not the responder".into()
                    })?;
                }
                Some(st) => {
                    check(st.code() == Some(3), || format!("loser status {st:?}"))?;
                    check(
                        k.stderr_text().contains("vm keeper is already running"),
                        || format!("loser stderr {:?}", k.stderr_text()),
                    )?;
                }
            }
        }
        check(alive == 1, || format!("{alive} keepers alive"))?;
        println!("vm_keeper: concurrent starts leave exactly one keeper");
        Ok(())
    }

    fn scenario_c() -> Res {
        let s = scratch("c");
        let marker = s.join("marker");
        let dir = runtime_dir(&s)?;
        let mut k1 = spawn_keeper(&s, &s, DEFAULT_GRACE_MS, &marker, "k1")?;
        let client = KeeperClient::new(&s).map_err(te)?;
        wait_ready(&client, Duration::from_secs(10))?;
        check(
            KeeperLock::try_acquire(&dir)
                .err()
                .is_some_and(|e| e.code() == ErrorCode::FailedPrecondition),
            || "lock must be held while the keeper lives".into(),
        )?;
        k1.child.kill().map_err(|e| format!("kill: {e}"))?;
        wait_exit(&mut k1.child, Duration::from_secs(10))?;
        // 死亡でカーネルがロックを外す。取れるまでを 1 秒に限る。
        let t0 = Instant::now();
        let lock = KeeperLock::acquire_within(&dir, Duration::from_secs(1)).map_err(te)?;
        check(t0.elapsed() < Duration::from_secs(1), || {
            "lock release too slow".into()
        })?;
        check(dir.join(SOCKET_FILE).exists(), || {
            "the killed keeper must leave a stale socket".into()
        })?;
        drop(lock);
        let k3 = spawn_keeper(&s, &s, DEFAULT_GRACE_MS, &marker, "k3")?;
        let pid3 = wait_ready(&client, Duration::from_secs(10))?;
        check(pid3 == k3.child.id(), || {
            format!("responder {pid3} is not the new keeper")
        })?;
        println!("vm_keeper: lock released on SIGKILL and stale socket replaced");
        Ok(())
    }

    fn scenario_d() -> Res {
        let s = scratch("d");
        let marker = s.join("marker");
        let dir = runtime_dir(&s)?;
        let held = KeeperLock::try_acquire(&dir).map_err(te)?;
        let t0 = Instant::now();
        let e = KeeperLock::acquire_within(&dir, Duration::from_millis(300))
            .err()
            .ok_or("acquire_within must time out")?;
        let el = t0.elapsed();
        check(e.code() == ErrorCode::Timeout, || {
            format!("code {:?}", e.code())
        })?;
        check(
            el >= Duration::from_millis(300) && el < Duration::from_millis(2300),
            || format!("acquire elapsed {el:?}"),
        )?;
        // ロックだけ握られ socket が無い: 起動役の待ちも期限で切れる（起動した子は already running で終わる）。
        let client = KeeperClient::new(&s).map_err(te)?;
        let t1 = Instant::now();
        let stderr = s.join("kd.stderr");
        let r = client.ensure_running(
            || spawn_raw(&stderr, &s, DEFAULT_GRACE_MS, &marker),
            Duration::from_millis(300),
        );
        let el = t1.elapsed();
        let e = r.err().ok_or("ensure_running must time out")?;
        check(e.code() == ErrorCode::Timeout, || {
            format!("code {:?}", e.code())
        })?;
        check(
            el >= Duration::from_millis(300) && el < Duration::from_millis(2300),
            || format!("ensure elapsed {el:?}"),
        )?;
        drop(held);
        println!("vm_keeper: lock wait deadline enforced");
        Ok(())
    }

    fn scenario_e() -> Res {
        let s = scratch("e");
        let marker = s.join("marker");
        let dir = runtime_dir(&s)?;
        let grace = Duration::from_millis(2500);
        let mut k = spawn_keeper(&s, &s, 2500, &marker, "k")?;
        let client = KeeperClient::new(&s).map_err(te)?;
        let pid = wait_ready(&client, Duration::from_secs(10))?;
        let r = client.register(&id("c1")?).map_err(te)?;
        check(
            (r.reason, r.refcount, r.keeper_pid) == (Reason::Ok, 1, pid),
            || format!("register c1 -> {r:?}"),
        )?;
        let r = client.register(&id("c1")?).map_err(te)?;
        check(
            r.reason == Reason::AlreadyRegistered && r.refcount == 1,
            || format!("duplicate register -> {r:?}"),
        )?;
        let r = client.unregister(&id("c1")?).map_err(te)?;
        check((r.reason, r.refcount) == (Reason::Ok, 0), || {
            format!("unregister -> {r:?}")
        })?;
        // 猶予内の再登録は終了を取り消す: 猶予の 2 倍を過ぎても生きている。
        let r = client.register(&id("c2")?).map_err(te)?;
        check((r.reason, r.refcount) == (Reason::Ok, 1), || {
            format!("register c2 -> {r:?}")
        })?;
        std::thread::sleep(grace * 2);
        check(matches!(k.child.try_wait(), Ok(None)), || {
            "keeper exited while a container was registered".into()
        })?;
        let r = client.unregister(&id("zzz")?).map_err(te)?;
        check(r.reason == Reason::NotRegistered, || {
            format!("unknown unregister -> {r:?}")
        })?;
        // 最後の解除から猶予 + 余裕で、終了コード 0 で終わる。
        let t0 = Instant::now();
        let r = client.unregister(&id("c2")?).map_err(te)?;
        check((r.reason, r.refcount) == (Reason::Ok, 0), || {
            format!("unregister c2 -> {r:?}")
        })?;
        let st = wait_exit(&mut k.child, grace + Duration::from_secs(5))?;
        let el = t0.elapsed();
        check(st.code() == Some(0), || {
            format!("exit {st:?}, stderr {:?}", k.stderr_text())
        })?;
        check(el >= grace, || format!("exited before the grace: {el:?}"))?;
        check(!dir.join(SOCKET_FILE).exists(), || {
            "socket must be removed".into()
        })?;
        KeeperLock::try_acquire(&dir).map_err(te)?;
        let stops = std::fs::read_to_string(&marker).map_err(|e| format!("marker: {e}"))?;
        check(stops == "stop\n", || format!("vm stop marker {stops:?}"))?;
        println!("vm_keeper: idle grace exit stops vm once and releases socket and lock");
        Ok(())
    }

    fn scenario_f() -> Res {
        let s = scratch("f");
        let marker = s.join("marker");
        let config = KeeperConfig::default();
        let mut vm = RecordingVm(marker.clone());

        let wide = s.join("wide");
        std::fs::create_dir(&wide).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o777))
            .map_err(|e| e.to_string())?;
        let e = run(&config, &wide, &mut vm)
            .err()
            .ok_or("0777 base must be rejected")?;
        check(e.code() == ErrorCode::PermissionDenied, || {
            format!("0777 -> {:?}", e.code())
        })?;

        let real = s.join("real");
        std::fs::create_dir(&real).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let link = s.join("link");
        std::os::unix::fs::symlink(&real, &link).map_err(|e| e.to_string())?;
        let e = run(&config, &link, &mut vm)
            .err()
            .ok_or("symlink base must be rejected")?;
        check(e.code() == ErrorCode::PermissionDenied, || {
            format!("symlink -> {:?}", e.code())
        })?;
        check(!marker.exists(), || {
            "no vm stop must happen on a rejected start".into()
        })?;
        println!("vm_keeper: unsafe directory rejected");
        Ok(())
    }

    pub(super) fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--vm-keeper-child") {
            return child_main(&args);
        }
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            eprintln!("WATCHDOG EXPIRED: vm_keeper did not finish within {WATCHDOG:?}");
            std::process::exit(124);
        });
        let scenarios: [(&str, Scenario); 6] = [
            ("A", scenario_a),
            ("B", scenario_b),
            ("C", scenario_c),
            ("D", scenario_d),
            ("E", scenario_e),
            ("F", scenario_f),
        ];
        for (name, f) in scenarios {
            if let Err(e) = f() {
                eprintln!("vm_keeper: scenario {name} FAILED: {e}");
                return ExitCode::FAILURE;
            }
        }
        println!("vm_keeper: all scenarios ok");
        ExitCode::SUCCESS
    }
}
