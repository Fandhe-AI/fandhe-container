//! plugin-cri の本番の保持役 provider（`ProductionPodHolder`）を本物の supervisor の bin の `pod-holder` モードで通す実機前提の
//! 結合試験（CRI-2・CORE-1・SEC-5・REPAIR-5・REPAIR-12。H6・#2877。設計は `docs/design/pod-namespace-holder.md`）。
//!
//! 保持役は `unshare(CLONE_NEWUSER)` を使うため、非特権 user namespace を作れる環境（`kernel.apparmor_restrict_unprivileged_userns`
//! の緩和など）が要る。supervisor の bin は事前に `cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor`
//! で作り、本試験は試験バイナリの `target/<profile>/deps/..` の隣から探す。`harness = false` で `-- --ignored` 指定時のみ動かす
//! （AGENTS.md）。前提が欠けていれば `PRECONDITION FAILED` で終了コード 1（成功を装わない）。
//!
//! # シナリオ（各成功行は固定の文字列。`scripts/check-success-lines.sh` が本ファイルのリテラルから導出して照合する）
//! - A: `spawn` が READY を検証し、保持役の user・ipc・net namespace が自分のものと異なり、`liveness` が `Alive`
//! - B: `release`（stdin の EOF）で保持役が終わって回収され、`/proc/<pid>` が消える
//! - C: 外からの SIGKILL の後、`liveness` が `Exited` を返しても `/proc/<pid>` は zombie で残り（回収しない）、`release` が回収する
//! - D: 追跡する子の上限（2）を超える 3 件目の `spawn` は `RESOURCE_EXHAUSTED`
//!
//! 範囲外: 保持役の namespace へのコンテナの join と pod 間の通信（H5・#2876、H8・#2878、core の net join は H7・#2872）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pod_holder_provider_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("pod_holder_provider_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};
    use std::time::{Duration, Instant};

    use fandhe_container_cri::adapter::{
        PodHolderLiveness, PodHolderRequest, PodNamespaceHolderProvider, ProcessStartObservation,
    };
    use fandhe_container_cri::error::CriErrorCode;
    use fandhe_container_cri::runtime::v1::PodSandboxConfig;
    use fandhe_container_plugin_cri::pod_holder::ProductionPodHolder;

    const KILL: &str = "/usr/bin/kill";
    /// 全シナリオの上限(超えたら `WATCHDOG EXPIRED` と終了コード 124。REPAIR-5)。
    const WATCHDOG: Duration = Duration::from_secs(240);
    const STEP: Duration = Duration::from_secs(60);

    pub fn main() -> ExitCode {
        match std::env::args().nth(1).as_deref() {
            Some("--ignored") => run_all(),
            _ => {
                println!(
                    "pod_holder_provider_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
                );
                ExitCode::SUCCESS
            }
        }
    }

    fn fail(msg: &str) -> ! {
        println!("pod_holder_provider_real: FAILED: {msg}");
        std::process::exit(1)
    }

    fn start_watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            println!("pod_holder_provider_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            std::process::exit(124);
        });
    }

    /// 試験バイナリ（`target/<profile>/deps/<name>-<hash>`）の隣の `target/<profile>/` から supervisor の bin を探す。
    fn supervisor_bin() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        // 試験バイナリの置き場は cargo の版で変わる（旧: target/<profile>/deps/、新レイアウト:
        // target/<profile>/build/<pkg>/<hash>/out/）ため、祖先を上へたどって supervisor の bin を探す。
        exe.ancestors()
            .skip(1)
            .take(6)
            .map(|dir| dir.join("fandhe-container-supervisor"))
            .find(|bin| bin.is_file())
    }

    fn ns_id(pid: Option<u32>, name: &str) -> (u64, u64) {
        let path = match pid {
            Some(p) => format!("/proc/{p}/ns/{name}"),
            None => format!("/proc/self/ns/{name}"),
        };
        let md = std::fs::metadata(path).unwrap_or_else(|e| fail(&format!("stat ns {name}: {e}")));
        (md.dev(), md.ino())
    }

    fn proc_gone(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + STEP;
        while Instant::now() < end {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        fail(&format!("timed out waiting for {what}"));
    }

    fn run_all() -> ExitCode {
        let euid = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
        if euid == 0 {
            println!("pod_holder_provider_real: FAILED: must run as non-root (root=true)");
            return ExitCode::from(1);
        }
        if !Path::new(KILL).exists() {
            println!("pod_holder_provider_real: PRECONDITION FAILED: {KILL} is required");
            return ExitCode::from(1);
        }
        let Some(bin) = supervisor_bin() else {
            println!(
                "pod_holder_provider_real: PRECONDITION FAILED: build fandhe-container-supervisor first (target/<profile>/fandhe-container-supervisor)"
            );
            return ExitCode::from(1);
        };
        start_watchdog();
        let provider = ProductionPodHolder::with_fixed_program(bin, Vec::new(), true, 2);
        let cfg = PodSandboxConfig::default();
        let req = |id| PodHolderRequest::new(id, &cfg, STEP);

        // A: READY の検証と namespace の分離、生存。
        let a = provider
            .spawn(&req("sb-a"))
            .unwrap_or_else(|e| fail(&format!("spawn a: {e}")));
        let a_pid = a.pid().get();
        for name in ["user", "ipc", "net"] {
            if ns_id(Some(a_pid), name) == ns_id(None, name) {
                fail(&format!(
                    "holder shares the {name} namespace with the plugin"
                ));
            }
        }
        if provider.liveness("sb-a").ok() != Some(PodHolderLiveness::Alive) {
            fail("holder a is not alive");
        }
        // 素性(R11・#2940): spawn が返した pid・ns の dev:ino・starttime が /proc の実値と一致する。
        let Some(identity) = a.identity() else {
            fail("holder a has no identity");
        };
        if identity.pid().get() != a_pid {
            fail("identity pid differs from the holder pid");
        }
        for (name, got) in [
            ("user", identity.user()),
            ("ipc", identity.ipc()),
            ("net", identity.net()),
        ] {
            if (got.dev, got.ino) != ns_id(Some(a_pid), name) {
                fail(&format!("identity {name} namespace differs from /proc"));
            }
        }
        match provider.observe_process_start(a_pid) {
            Ok(ProcessStartObservation::Present { start_time_ticks })
                if start_time_ticks == identity.start_time_ticks() => {}
            _ => fail("identity starttime differs from the observed starttime"),
        }
        println!(
            "pod_holder_provider_real: scenario A ok: spawn verified READY and the holder namespaces differ from ours (root=false)"
        );

        // B: stdin の EOF での解放と回収。
        provider
            .release("sb-a", STEP)
            .unwrap_or_else(|e| fail(&format!("release a: {e}")));
        if !proc_gone(a_pid) || provider.liveness("sb-a").is_ok() {
            fail("holder a was not reaped by release");
        }
        println!(
            "pod_holder_provider_real: scenario B ok: release closed stdin and reaped the holder (root=false)"
        );

        // C: 外からの SIGKILL。Exited でも回収しない(zombie が残る)。release が回収する。
        let c = provider
            .spawn(&req("sb-c"))
            .unwrap_or_else(|e| fail(&format!("spawn c: {e}")));
        let c_pid = c.pid().get();
        let st = Command::new(KILL)
            .args(["-KILL", &c_pid.to_string()])
            .status()
            .unwrap_or_else(|e| fail(&format!("kill: {e}")));
        if !st.success() {
            fail("kill -KILL failed");
        }
        wait_until("liveness Exited", || {
            provider.liveness("sb-c").ok() == Some(PodHolderLiveness::Exited)
        });
        let stat = std::fs::read_to_string(format!("/proc/{c_pid}/stat"))
            .unwrap_or_else(|e| fail(&format!("holder c was reaped by liveness: {e}")));
        if !stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z')
        {
            fail("holder c is not a zombie after SIGKILL");
        }
        provider
            .release("sb-c", STEP)
            .unwrap_or_else(|e| fail(&format!("release c: {e}")));
        if !proc_gone(c_pid) {
            fail("holder c was not reaped by release");
        }
        println!(
            "pod_holder_provider_real: scenario C ok: Exited is observed without reaping and release reaps the zombie (root=false)"
        );

        // D: 追跡する子の上限。
        let d1 = provider
            .spawn(&req("sb-d1"))
            .unwrap_or_else(|e| fail(&format!("spawn d1: {e}")));
        let d2 = provider
            .spawn(&req("sb-d2"))
            .unwrap_or_else(|e| fail(&format!("spawn d2: {e}")));
        match provider.spawn(&req("sb-d3")) {
            Err(e) if e.code() == CriErrorCode::ResourceExhausted => {}
            other => fail(&format!(
                "third spawn must be RESOURCE_EXHAUSTED: {other:?}"
            )),
        }
        for id in ["sb-d1", "sb-d2"] {
            provider
                .release(id, STEP)
                .unwrap_or_else(|e| fail(&format!("release {id}: {e}")));
        }
        if !proc_gone(d1.pid().get()) || !proc_gone(d2.pid().get()) {
            fail("holders d1/d2 were not reaped");
        }
        println!(
            "pod_holder_provider_real: scenario D ok: the third spawn is RESOURCE_EXHAUSTED at the limit of 2 (root=false)"
        );

        println!(
            "pod_holder_provider_real: the production pod holder provider works end to end in a rootless user namespace (root=false)"
        );
        ExitCode::SUCCESS
    }
}
