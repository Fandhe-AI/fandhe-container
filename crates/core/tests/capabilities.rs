//! capability 最小化（`fandhe_container_core::capabilities` と、起動フローの組み込み段
//! `StageKind::CapabilityDrop`）の結合試験（SEC-1・TASK-37.3・#174。REPAIR-12 の機械照合）。
//!
//! `spawn_container_with_stages` が fork した実際のコンテナプロセス（新しい PID namespace の PID 1・
//! pivot_root 後）が、OCI 既定の最小集合（moby 既定の 14 個。マスク `0x0000_0000_a804_25fb`）だけを
//! 持つことを、プロセスの外側から親の `/proc/<pid>/status` を読んで照合する。`CAP_SYS_ADMIN` 等が
//! 付いていないこと、bounding set（`CapBnd`）にも残っていないこと（uid 0 の execve による取り戻しの
//! 防止）を具体値で確かめる。
//!
//! # 構成
//! - 常に走る部分（3 OS 共通・既定のテスト集合）: 公開 API から組み立てた OCI 既定マスクと危険な
//!   capability の不在、`/proc/<pid>/status` パーサの自己テスト
//! - 実機前提部分（Linux x86_64 / aarch64。`-- --ignored` 指定時のみ）: 子に実プロセスを起こして照合する。
//!   `unshare(CLONE_NEWPID)` の後の最初の子だけが PID 1 になるため、`fork_exec_isolation` と同様に
//!   ディスパッチャが自身を `--scenario capabilities <rootfs>` で再起動した別プロセスで行う。
//!
//! # 観測点
//! 現状は seccomp（TASK-38）・Landlock（TASK-39）が未実装で、制限の証跡が無い間は exec が常に拒否される
//! （fail-closed。REPAIR-3）ため、exec 後のプロセスは観測できない。そこで組み込みでない最後の段
//! （`StageKind::Seccomp` のフック）を、組み込みの `CapabilityDrop`・`NoNewPrivs` の後・exec の直前の
//! 観測点として使う。フックは親と合図ファイルで同期し、親は子が停止している間に `/proc/<pid>/status` を
//! 読む。TASK-38 で Seccomp が組み込み段になるとこの登録は `InvalidArgument` で失敗する（意図した仕掛け。
//! そのとき観測点と `Exited(126)` の期待値を見直す）。exec 後の capability（`retained_after_exec` の
//! 上限挙動を含む）の実測は、exec が許可された後の課題とする。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要（`fork_exec_isolation` と同じ）。GitHub
//! ホステッド runner で保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。
//! 実行された場合は分離の拒否・事前条件の不成立を含めあらゆる失敗を失敗として扱い、検証せずに成功する
//! 分岐は持たない。

use std::collections::BTreeMap;

use fandhe_container_core::capabilities::{Capability, CapabilitySet, OCI_DEFAULT_CAPABILITIES};

/// OCI 既定の 14 capability のマスク（moby 既定。Docker の root コンテナの `CapEff`）。
const OCI_DEFAULT_MASK: u64 = 0x0000_0000_a804_25fb;

/// 既定で付与してはならない危険な capability（SEC-1）。
const DANGEROUS: [Capability; 11] = [
    Capability::SysAdmin,
    Capability::SysModule,
    Capability::SysPtrace,
    Capability::NetAdmin,
    Capability::SysRawio,
    Capability::DacReadSearch,
    Capability::Bpf,
    Capability::Perfmon,
    Capability::SysBoot,
    Capability::SysTime,
    Capability::MacAdmin,
];

/// `/proc/<pid>/status` の `Cap*:` 行（`CapInh`・`CapPrm`・`CapEff`・`CapBnd`・`CapAmb`）。
const CAP_KEYS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

/// `status` のテキストから `Cap*:` 行を 16 進 64 bit として読む。行の欠落・不正値は `Err`。
fn parse_cap_status(status: &str) -> Result<BTreeMap<&'static str, u64>, String> {
    let mut out = BTreeMap::new();
    for key in CAP_KEYS {
        let prefix = format!("{key}:");
        let line = status
            .lines()
            .find(|l| l.starts_with(&prefix))
            .ok_or_else(|| format!("{key} line missing"))?;
        let value = line
            .get(prefix.len()..)
            .map(str::trim)
            .ok_or_else(|| format!("{key} line malformed"))?;
        let parsed = u64::from_str_radix(value, 16)
            .map_err(|e| format!("{key} value {value:?} is not hex: {e}"))?;
        out.insert(key, parsed);
    }
    Ok(out)
}

/// 公開 API から OCI 既定マスクを組み立てる（`to_cap_words` は crate 内部のため使わない）。
fn mask_of(set: CapabilitySet) -> u64 {
    set.iter().fold(0u64, |m, c| m | (1u64 << c.index()))
}

/// SEC-1: OCI 既定集合がマスク・件数ともに期待どおりで、危険な capability を含まない。
fn sec1_default_set_is_minimal() {
    let set = CapabilitySet::oci_default();
    assert_eq!(mask_of(set), OCI_DEFAULT_MASK, "OCI default mask");
    assert_eq!(set.len(), 14, "OCI default capability count");
    assert_eq!(OCI_DEFAULT_CAPABILITIES.len(), 14);
    for cap in DANGEROUS {
        assert!(
            !set.contains(cap),
            "SEC-1: dangerous capability {} must not be in the OCI default set",
            cap.as_str()
        );
    }
}

/// SEC-1: パーサを固定文字列で自己検証する（具体値・欠落・不正 16 進の検出）。
fn sec1_status_parser_selftest() {
    let ok = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\n\
              CapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\nCapAmb:\t0000000000000000\n";
    let parsed = parse_cap_status(ok).expect("well-formed status");
    assert_eq!(parsed.get("CapEff"), Some(&OCI_DEFAULT_MASK));
    assert_eq!(parsed.get("CapBnd"), Some(&OCI_DEFAULT_MASK));
    assert_eq!(parsed.get("CapInh"), Some(&0));
    assert_eq!(parsed.get("CapAmb"), Some(&0));
    let missing = ok.replace("CapBnd:\t00000000a80425fb\n", "");
    assert_eq!(
        parse_cap_status(&missing),
        Err("CapBnd line missing".to_string())
    );
    let bad = ok.replace("CapAmb:\t0000000000000000", "CapAmb:\tzz");
    assert!(
        parse_cap_status(&bad)
            .expect_err("non-hex value must be rejected")
            .starts_with("CapAmb value \"zz\" is not hex")
    );
}

fn always() {
    sec1_default_set_is_minimal();
    sec1_status_parser_selftest();
    println!("capabilities: SEC-1 default set and status parser verified");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    always();
    println!("capabilities: real-process part is Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    always();
    println!(
        "capabilities: real-process part is x86_64/aarch64 only, not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    // シナリオ再入時は常に走る部分を繰り返さない。
    if std::env::args().any(|a| a == "--scenario") {
        linux::run();
        return;
    }
    always();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "capabilities: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::collections::BTreeMap;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace, NamespaceSet,
        StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_with_stages,
    };

    use super::{CAP_KEYS, DANGEROUS, OCI_DEFAULT_MASK, parse_cap_status};

    /// 子が pivot 後の `/` に書く capability 記録（親からは `<rootfs>/cap-ready`）。
    const READY: &str = "cap-ready";
    /// 親が確認後に作る合図（親からは `<rootfs>/cap-go`）。
    const GO: &str = "cap-go";
    /// 存在しないエントリポイント。exec は証跡が無いため実体到達前に拒否される。
    const ENTRY: &str = "/fandhe-cap-probe";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let rootfs = args
                    .get(i + 2)
                    .expect("rootfs path after the scenario name");
                scenario(Path::new(rootfs));
            }
            None => dispatcher(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/` だけを持つ rootfs を排他的に作る（推測されにくい名前・`mkdir` は既存なら失敗）。
    fn make_rootfs() -> Rootfs {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-cap-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        rootfs
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(child: &mut std::process::Child, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    while child.try_wait().expect("try_wait").is_none() {
                        assert!(
                            Instant::now() < reap_deadline,
                            "the child was not reaped after SIGKILL"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn dispatcher() {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
        let mut child = Command::new(&exe)
            .args(["--scenario", "capabilities"])
            .arg(&rootfs.0)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn scenario");
        let status = wait_deadline(&mut child, timeout())
            .unwrap_or_else(|| panic!("scenario did not exit within {:?}", timeout()));
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("piped stderr")
            .read_to_string(&mut stderr)
            .expect("read scenario stderr");
        assert_eq!(
            status.code(),
            Some(0),
            "capabilities scenario must exit with 0; stderr:\n{stderr}"
        );
        // SEC-1・CORE-5: 証跡が無い間は exec が拒否される。
        assert!(
            stderr.contains("PERMISSION_DENIED"),
            "stderr must contain PERMISSION_DENIED; got:\n{stderr}"
        );
        println!(
            "capabilities: SEC-1 minimal capability set verified (root={})",
            is_root()
        );
    }

    /// 分離 → 事前条件 → fork → 子停止中に親が `/proc/<pid>/status` を照合する。
    fn scenario(rootfs: &Path) {
        let is_root = is_root();
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        // 事前条件（fail-closed）: 子は fork でこれを継承するため、満たさない環境では
        // 「削減された」ことを検証できない。
        let own = read_caps("/proc/self/status");
        for key in ["CapPrm", "CapBnd"] {
            let v = own.get(key).copied().unwrap_or(0);
            assert_eq!(
                v & OCI_DEFAULT_MASK,
                OCI_DEFAULT_MASK,
                "precondition: {key}={v:#018x} of the scenario process must contain the OCI default set"
            );
        }

        let entry = Entrypoint::new(ENTRY, [ENTRY], [] as [&str; 0]).expect("entrypoint");
        // Seccomp は現状組み込みでない最後の段。組み込みの CapabilityDrop・NoNewPrivs の後、exec の
        // 直前に走る（TASK-38 で組み込みになるとここは InvalidArgument になる）。
        let stages = StagePipeline::new()
            .with_hook(StageKind::Seccomp, handshake_hook)
            .unwrap_or_else(|e| panic!("register hook: {e}"));
        let child = spawn_container_with_stages(rootfs, &entry, stages)
            .unwrap_or_else(|e| panic!("spawn: {e}"));

        // 子が記録を書くまで待つ（待つ間に子が先に終わっていないかも確認する）。
        let limit = timeout();
        let deadline = Instant::now() + limit;
        let ready = rootfs.join(READY);
        while !ready.exists() {
            if let Ok(Some(exit)) = child.wait_for_exit(Duration::from_millis(10)) {
                panic!("child exited early with {exit:?} before reaching the observation point");
            }
            if Instant::now() >= deadline {
                let _ = child.kill_and_reap(Duration::from_secs(5));
                panic!("child did not reach the observation point within {limit:?}");
            }
        }

        // 親の PID namespace から見た起動プロセスの capability（主たる照合）。
        let outside = read_caps(&format!("/proc/{}/status", child.pid()));
        let inside_text =
            std::fs::read_to_string(&ready).unwrap_or_else(|e| panic!("read child record: {e}"));
        let inside =
            parse_cap_status(&inside_text).unwrap_or_else(|e| panic!("parse child record: {e}"));
        std::fs::write(rootfs.join(GO), b"go").expect("create go signal");
        let exit = child.wait_timeout(limit).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });

        verify("outside (/proc/<pid>/status)", &outside);
        verify("inside (child /proc/self/status)", &inside);
        assert_eq!(
            inside, outside,
            "the child's own view and the parent's view must agree"
        );
        // SEC-1・CORE-5: 制限証跡が無い間は exec が拒否される。
        assert_eq!(exit, ChildExit::Exited(126), "exec must still be refused");
    }

    /// 期待値との照合（SEC-1）。bounding set の一致が最重要（uid 0 の execve は bounding set から
    /// capability を取り戻せるため）。
    fn verify(label: &str, caps: &BTreeMap<&'static str, u64>) {
        let get = |k: &str| caps.get(k).copied().unwrap_or(u64::MAX);
        for key in ["CapEff", "CapPrm", "CapBnd"] {
            assert_eq!(
                get(key),
                OCI_DEFAULT_MASK,
                "{label}: {key} must equal the OCI default mask"
            );
        }
        for key in ["CapInh", "CapAmb"] {
            assert_eq!(get(key), 0, "{label}: {key} must be empty");
        }
        for key in CAP_KEYS {
            for cap in DANGEROUS {
                assert_eq!(
                    get(key) & (1u64 << cap.index()),
                    0,
                    "{label}: {key} must not contain {}",
                    cap.as_str()
                );
            }
            assert_eq!(
                get(key) >> 41,
                0,
                "{label}: {key} must not contain capability numbers >= 41"
            );
        }
    }

    fn read_caps(path: &str) -> BTreeMap<&'static str, u64> {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        parse_cap_status(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    /// 子側フック: 自身の capability を記録して親の合図を待つ（スレッドは作らない。待ちには期限）。
    fn handshake_hook() -> Result<(), ExecError> {
        use std::io::Write as _;
        let status = std::fs::read_to_string("/proc/self/status")
            .unwrap_or_else(|e| panic!("read /proc/self/status in the child: {e}"));
        let lines: String = status
            .lines()
            .filter(|l| CAP_KEYS.iter().any(|k| l.starts_with(&format!("{k}:"))))
            .map(|l| format!("{l}\n"))
            .collect();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("/cap-ready.tmp")
            .unwrap_or_else(|e| panic!("create record in the child: {e}"));
        f.write_all(lines.as_bytes())
            .unwrap_or_else(|e| panic!("write record in the child: {e}"));
        drop(f);
        std::fs::rename("/cap-ready.tmp", format!("/{READY}"))
            .unwrap_or_else(|e| panic!("publish record in the child: {e}"));
        let deadline = Instant::now() + timeout();
        while !Path::new(&format!("/{GO}")).exists() {
            if Instant::now() >= deadline {
                // 親が現れない場合は setup 失敗（125）で終わる。
                return Hostname::new("").map(|_| ());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
