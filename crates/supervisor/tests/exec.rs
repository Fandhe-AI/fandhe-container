//! 稼働中コンテナへのコマンド実行（`run_command`）の通し結合試験（TASK-163.4・#503・SUP-6・SEC-1・REPAIR-12）。
//!
//! 実コンテナ（`pivot_root` 済みの pid1）へ `setns` で参加し、cgroup へ join し、rlimit・capability 削減・
//! `NO_NEW_PRIVS`・Landlock・seccomp を再適用して `execve` するまでを、本番の `fandhe_container_supervisor::exec`
//! の入口（`run_command` / `run_command_in`）で通し、PoC-17 の確認項目を具体値で照合する。
//!
//! - `Seccomp: 2`・`NoNewPrivs: 1`（seccomp filter・`NO_NEW_PRIVS`）
//! - capability: `CapBnd` / `CapPrm` / `CapEff` が OCI 既定集合（SEC-1。core の `DEFAULT_MASK` = `0xa80425fb`）
//! - rlimit: `/proc/<pid>/limits` が pid1 と全 16 種で一致（launch と同じ値。SUP-12）
//! - Landlock: 読み取り専用の root 配下への書き込みが拒否され（`deny/no` は作られない）、`rw` の mount 先
//!   （`data/ok`）は作られる。seccomp: 禁止 syscall の `unshare(0)` が `EPERM`（`data/unshare_denied`）
//! - cgroup: `/proc/<pid>/cgroup` がコンテナ用 cgroup（`<scope>/fc-<id>@<instance>`）の絶対パスと完全一致し、
//!   joiner が元いた cgroup と異なる
//! - namespace: `NSpid` が入れ子で、`ns/{mnt,uts,ipc,net,pid}` が pid1 と一致（pid は参加後に fork した子の値）
//! - セッション（TASK-163 追補・#1456）: コマンドが新しいセッションのリーダーで、制御端末を持たず、joiner の
//!   セッションに残らない
//!
//! 条件 3・4 の拒否経路（#502 が #503 へ残した条件。`exec/reapply.rs` のモジュール doc）も照合する:
//! pivot していない pid1（`/` が記録した rootfs でない）の拒否（コマンドが起動しない）と、同じ rootfs を共有する
//! 別コンテナへ参加した場合の拒否（`exec_joined_namespace_mismatch`。何も適用しない）。
//!
//! TASK-163 追補の拒否経路: コンテナの `/dev/null` が symlink・別のデバイスノードへ差し替えられている場合に、
//! exec の子が差し替え先を開かずに拒否し、コマンドが起動しないこと（#1459）。`#!/proc/self/exe` のスクリプトを
//! エントリポイントにした exec が `execveat` の前に拒否されること（#1458）。
//!
//! 通しは 5 回繰り返し、1 回でも不一致なら失敗する（リトライで隠さない）。
//!
//! # 構成（再入）
//! `harness = false` の単一スレッド `main` で、自身を次の役で再実行する。
//! - 親（`--ignored`）: bundle を作り、コンテナ `A` / `B` を起動して観測する
//! - `--container`: `isolate_rootful_host_root`（pid / mnt / uts / ipc）→ pid1 を子として生成して待機
//! - `--pid1`: 新しい PID namespace の PID 1。`establish` → `prepare_rootfs` → `create_default_devices` →
//!   `pivot_root` の後、合図ファイルを置いて待機する（launch の exec は証跡未結線で拒否されるため exec しない）
//! - `--joiner`: 単一スレッドで `run_command` 等を呼ぶ exec 専用プロセス
//!
//! # 試験専用の入口（`exec-test-support` feature）
//! pivot していない pid1 の拒否経路は期待 cgroup パスを呼び出し側から渡す `run_command_in` を使う（既定の
//! ビルドの公開 API に含まれない。SEC-1）。feature なしのビルドでは本体をコンパイルせず、`-- --ignored` で実行を
//! 求められたら「検証していない」ことを非ゼロ終了で知らせる（`exec_setns_join` と同じ）。
//!
//! # 実機前提テストとしての分離
//! root・cgroup v2 の書き込み（`/sys/fs/cgroup`）・Landlock（Linux 6.12+・ABI 6+）・`unshare`（util-linux）が必要で、
//! x86_64 のみ（手組みのプローブが x86_64 の機械語のため）。GitHub ホステッド runner では保証できないため
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」。AGENTS.md に実行コマンドを記す）。実行された
//! 場合は拒否を含むあらゆる失敗を失敗として扱う。rootless は user namespace への参加が未実装のため対象外。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec: Linux only, not applicable on this OS");
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn main() {
    println!(
        "exec: x86_64 only (hand-made machine-code probe), not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "exec-test-support")
))]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a.starts_with("--joiner")) {
        eprintln!(
            "exec: not verified; rebuild with `--features exec-test-support` (see AGENTS.md)"
        );
        std::process::exit(2);
    }
    println!("exec: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "exec-test-support"
))]
fn main() {
    linux::run();
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "exec-test-support"
))]
mod linux {
    use std::fs;
    use std::io::{Read as _, Seek as _};
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::CgroupName;
    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, IsolationConfig, MountIsolation, Namespace, NamespaceSet,
        create_default_devices, isolate_rootful_host_root, pivot_root, plan_rootful_host_root,
        prepare_rootfs,
    };
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, StateRecord, StateRevision,
    };
    use fandhe_container_supervisor::exec::{
        enter_namespaces, identify_pid1, join_cgroup, prepare_cgroup_join, prepare_restrictions,
        reapply_restrictions, run_command, run_command_in,
    };

    /// 5 回の通し（受入条件: 5 回中 5 回成功）。
    const ROUNDS: u32 = 5;
    /// OCI 既定の capability 集合のマスク（core の `exec/capabilities.rs` の `DEFAULT_MASK`。SEC-1）。
    const OCI_DEFAULT_CAPS: &str = "00000000a80425fb";
    /// プローブの bundle 内の名前。
    const PROBE: &str = "probe";
    /// インタープリタにランタイム自身（`/proc/self/exe`）を指定したスクリプトの bundle 内の名前（#1458）。
    const RUNTIME_SCRIPT: &str = "runtime-script";
    /// コンテナ ID（cgroup 名 `fc-<id>@<instance>` に使う）。
    const CONTAINER_ID: &str = "exec-test";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(30);
        Duration::from_secs(secs)
    }

    /// 条件が真になるまで 20ms 間隔で待つ。期限超過は panic（失敗。REPAIR-5）。
    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout();
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        let arg = |i: usize| args.get(i).map(String::as_str);
        match arg(1) {
            Some("--container") => container(
                Path::new(arg(2).expect("rootfs")),
                arg(3).expect("ready name"),
            ),
            Some("--pid1") => pid1(
                Path::new(arg(2).expect("rootfs")),
                arg(3).expect("ready name"),
            ),
            Some("--joiner") => joiner(&args[2..]),
            // root 不要の補助: 手組みのプローブだけをホスト上で自己検証する（`orchestrate` も最初に行う）。
            Some("--selfcheck-probe") => {
                verify_probe_on_host(&make_bundle());
                println!("exec: probe self-check ok");
            }
            _ if args.iter().any(|a| a == "--ignored") => orchestrate(),
            _ => println!(
                "exec: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            ),
        }
    }

    // ---------------------------------------------------------------- プローブ

    /// 手組みの静的 ELF64（x86_64）。動的ローダ不要。cwd（コンテナの root）からの相対パスで次を行い、`pause` する。
    ///
    /// 1. `open("data/ok", O_WRONLY|O_CREAT, 0600)`: Landlock が `rw` の mount 先として許す
    /// 2. `open("deny/no", O_WRONLY|O_CREAT, 0600)`: 読み取り専用の root 配下のため Landlock が拒否する
    /// 3. `unshare(0)`: 戻り値 0 なら `data/unshare_ok`、`-EPERM` なら `data/unshare_denied` を作る（seccomp）
    ///
    /// 機械語は `as`（GNU as, Intel 構文）で組み立てた 169 バイトで、`probe.s` 相当の命令列（`_start` から
    /// `lea rdi,[rip+..]; mov esi,0x41; mov edx,0x180; mov eax,2; syscall` を 2 回、`unshare` 272、判定、`pause` 34、
    /// `exit` 60）と文字列 4 つ。ホスト上で直接実行して自己検証する（バイト列の誤りをランタイムの不具合と
    /// 取り違えない）。
    fn probe_elf() -> Vec<u8> {
        #[rustfmt::skip]
        const CODE: &[u8] = &[
            0x48, 0x8d, 0x3d, 0x6e, 0x00, 0x00, 0x00, 0xbe, 0x41, 0x00, 0x00, 0x00,
            0xba, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05,
            0x48, 0x8d, 0x3d, 0x5e, 0x00, 0x00, 0x00, 0xbe, 0x41, 0x00, 0x00, 0x00,
            0xba, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05,
            0xb8, 0x10, 0x01, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x48, 0x85, 0xc0,
            0x75, 0x09, 0x48, 0x8d, 0x3d, 0x40, 0x00, 0x00, 0x00, 0xeb, 0x0d, 0x48,
            0x83, 0xf8, 0xff, 0x75, 0x18, 0x48, 0x8d, 0x3d, 0x41, 0x00, 0x00, 0x00,
            0xbe, 0x41, 0x00, 0x00, 0x00, 0xba, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x02,
            0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x22, 0x00, 0x00, 0x00, 0x0f, 0x05,
            0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x64, 0x61, 0x74,
            0x61, 0x2f, 0x6f, 0x6b, 0x00, 0x64, 0x65, 0x6e, 0x79, 0x2f, 0x6e, 0x6f,
            0x00, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x75, 0x6e, 0x73, 0x68, 0x61, 0x72,
            0x65, 0x5f, 0x6f, 0x6b, 0x00, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x75, 0x6e,
            0x73, 0x68, 0x61, 0x72, 0x65, 0x5f, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64,
            0x00,
        ];
        const BASE: u64 = 0x40_0000;
        const HEADERS: u64 = 64 + 56;
        let total = HEADERS + CODE.len() as u64;
        let mut b = Vec::new();
        // e_ident: ELF64・little endian・version 1・System V ABI。
        b.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        b.extend_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
        b.extend_from_slice(&1u32.to_le_bytes()); // e_version
        b.extend_from_slice(&(BASE + HEADERS).to_le_bytes()); // e_entry
        b.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        b.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        b.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        b.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(b.len(), 64);
        b.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        b.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R + X
        b.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        b.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
        b.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
        b.extend_from_slice(&total.to_le_bytes()); // p_filesz
        b.extend_from_slice(&total.to_le_bytes()); // p_memsz
        b.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        assert_eq!(b.len(), 120);
        b.extend_from_slice(CODE);
        b
    }

    /// 自己検証: 分離前にホスト上でプローブを直接実行し、cwd 相対の 3 つの動作（書き込み 2 件と
    /// `unshare(0)` の成功）を確かめる。
    fn verify_probe_on_host(bundle: &Bundle) {
        let work = bundle.dir.join("selfcheck");
        fs::create_dir_all(work.join("data")).expect("mkdir selfcheck/data");
        fs::create_dir_all(work.join("deny")).expect("mkdir selfcheck/deny");
        let mut child = Command::new(bundle.rootfs().join(PROBE))
            .current_dir(&work)
            .stdin(Stdio::null())
            .spawn()
            .expect("run the probe directly on the host (is the temp dir mounted noexec?)");
        wait_until("the host probe to finish its steps", || {
            work.join("data/unshare_ok").exists()
        });
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            work.join("data/ok").exists() && work.join("deny/no").exists(),
            "the hand-made probe is broken; this is a test bug, not a runtime bug"
        );
    }

    // ---------------------------------------------------------------- bundle

    /// 使い捨ての bundle（`config.json` と `rootfs/`）。drop で削除する。
    struct Bundle {
        dir: PathBuf,
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    impl Bundle {
        fn rootfs(&self) -> PathBuf {
            self.dir.join("rootfs")
        }
    }

    /// 祖先に symlink を含まない一意なディレクトリへ bundle を作る。rootfs は読み取り専用（Landlock）で、
    /// `/dev`・`/data` だけ `rw`。`deny/` は書き込みを拒否される対象。
    fn make_bundle() -> Bundle {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-exec-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).expect("exclusively create bundle dir");
        let bundle = Bundle { dir };
        fs::set_permissions(&bundle.dir, fs::Permissions::from_mode(0o755)).expect("chmod bundle");
        let rootfs = bundle.rootfs();
        fs::create_dir(&rootfs).expect("mkdir rootfs");
        fs::set_permissions(&rootfs, fs::Permissions::from_mode(0o755)).expect("chmod rootfs");
        for sub in ["proc", "dev", "data", "deny"] {
            let d = rootfs.join(sub);
            fs::create_dir(&d).unwrap_or_else(|e| panic!("mkdir rootfs/{sub}: {e}"));
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        fs::write(rootfs.join(PROBE), probe_elf()).expect("write probe");
        fs::set_permissions(rootfs.join(PROBE), fs::Permissions::from_mode(0o755))
            .expect("chmod probe");
        fs::write(rootfs.join(RUNTIME_SCRIPT), b"#!/proc/self/exe\n").expect("write script");
        fs::set_permissions(
            rootfs.join(RUNTIME_SCRIPT),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod script");
        fs::write(
            bundle.dir.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},"mounts":[{"destination":"/dev","options":["rw"]},{"destination":"/data","options":["rw"]}]}"#,
        )
        .expect("write config.json");
        bundle
    }

    /// 前の通しの痕跡（プローブが作るファイル）を消す。
    fn clean_probe_files(bundle: &Bundle) {
        for rel in [
            "data/ok",
            "deny/no",
            "data/unshare_ok",
            "data/unshare_denied",
        ] {
            let _ = fs::remove_file(bundle.rootfs().join(rel));
        }
    }

    // ---------------------------------------------------------------- コンテナ（再入）

    /// `--container`: 分離（pid / mnt / uts / ipc）して pid1 を子として生成し、stdin の EOF まで待つ。
    /// pid1 の host 側 pid は `<rootfs の親>/pid1-<ready>` へ書く（親が読む）。
    fn container(rootfs: &Path, ready: &str) {
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty()
                .with(Namespace::Pid)
                .with(Namespace::Mount)
                .with(Namespace::Uts)
                .with(Namespace::Ipc),
            hostname: None,
        };
        plan_rootful_host_root(&config)
            .and_then(|p| isolate_rootful_host_root(&p))
            .unwrap_or_else(|e| panic!("isolate failed: {e}"));
        let exe = std::env::current_exe().expect("current_exe");
        // 分離後の最初の子が新しい PID namespace の PID 1 になる。
        let mut pid1 = Command::new(exe)
            .arg("--pid1")
            .arg(rootfs)
            .arg(ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn pid1");
        let parent = rootfs.parent().expect("rootfs parent");
        let tmp = parent.join(format!("pid1-{ready}.tmp"));
        fs::write(&tmp, pid1.id().to_string()).expect("write pid1 pid");
        fs::rename(&tmp, parent.join(format!("pid1-{ready}"))).expect("publish pid1 pid");
        // 親（orchestrator）が stdin を閉じるまで待つ。
        let mut sink = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
        let _ = pid1.kill();
        let _ = pid1.wait();
    }

    /// `--pid1`: launch と同じ手順で `pivot_root` まで進み、合図ファイルを置いて待機する。
    /// launch の exec は証跡未結線で拒否されるため exec しない。
    fn pid1(rootfs: &Path, ready: &str) {
        assert_eq!(std::process::id(), 1, "must be PID 1 of the new namespace");
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        create_default_devices(&isolation, &prepared).expect("create default devices");
        pivot_root(&isolation, prepared).expect("pivot_root");
        fs::write(format!("/{ready}"), b"ready").expect("write ready marker");
        // 親が stdin 経由で pid1 を kill するまで待機する（上限つき。REPAIR-5）。
        let deadline = Instant::now() + Duration::from_secs(600);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// 起動済みのコンテナ（A プロセスとその pid1・cgroup）。drop で pid1 を止め、cgroup を消す。
    struct Container {
        stdin: Option<ChildStdin>,
        a: Child,
        pid1: u32,
        cgroup_dir: PathBuf,
        /// `<scope>/fc-<id>@<instance>`（cgroup 名前空間の根からの絶対パス）。
        cgroup_path: String,
    }

    impl Drop for Container {
        fn drop(&mut self) {
            drop(self.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.a.try_wait().ok().flatten().is_none() {
                if Instant::now() >= deadline {
                    let _ = self.a.kill();
                    let _ = self.a.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            remove_cgroup(&self.cgroup_dir);
        }
    }

    /// 空になるまで `rmdir` を数回試す（pid1 の回収を待つ）。
    fn remove_cgroup(dir: &Path) {
        for _ in 0..100 {
            if fs::remove_dir(dir).is_ok() || !dir.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 自プロセスの cgroup v2 パス（`0::/...`）。
    fn own_cgroup_path() -> String {
        cgroup_of("self")
    }

    fn cgroup_of(who: &str) -> String {
        fs::read_to_string(format!("/proc/{who}/cgroup"))
            .expect("read cgroup")
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 path")
            .to_owned()
    }

    /// コンテナ用 cgroup（`<scope>/fc-<id>@<instance>`）を作り、`pid` を入れる。`(ディレクトリ, 絶対パス)`。
    fn create_container_cgroup(scope: &str, instance: u64, pid: u32) -> (PathBuf, String) {
        let id = ContainerId::new(CONTAINER_ID).expect("id");
        let name = CgroupName::for_instance(&id, StateRevision::from_raw(instance)).expect("name");
        let path = if scope == "/" {
            format!("/{}", name.as_str())
        } else {
            format!("{scope}/{}", name.as_str())
        };
        let dir = PathBuf::from(format!("/sys/fs/cgroup{path}"));
        fs::create_dir(&dir).unwrap_or_else(|e| panic!("create the container cgroup: {e}"));
        fs::write(dir.join("cgroup.procs"), pid.to_string())
            .unwrap_or_else(|e| panic!("move pid1 into the container cgroup: {e}"));
        (dir, path)
    }

    /// 記録（Running・pid1 の host 側 pid・cgroup 配置つき）。joiner も同じ関数で作る。
    fn make_record(pid1: u32, bundle: &Path, scope: &str, instance: u64) -> StateRecord {
        let status = ContainerStatus::running(
            ContainerId::new(CONTAINER_ID).expect("id"),
            NonZeroU32::new(pid1),
        );
        StateRecord::new(status, bundle.to_path_buf(), StateRevision::from_raw(1))
            .expect("record")
            .with_cgroup(CgroupPlacement::new(
                CgroupScope::new(scope).expect("scope"),
                StateRevision::from_raw(instance),
            ))
    }

    /// コンテナ（pivot 済みの pid1）を起動して cgroup へ入れる。`tag` は合図・pid ファイルの識別子。
    fn start_container(bundle: &Bundle, tag: &str, instance: u64) -> Container {
        let exe = std::env::current_exe().expect("current_exe");
        let mut a = Command::new(exe)
            .arg("--container")
            .arg(bundle.rootfs())
            .arg(format!("ready-{tag}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn container process");
        let stdin = a.stdin.take();
        let ready = bundle.rootfs().join(format!("ready-{tag}"));
        let pid_file = bundle.dir.join(format!("pid1-ready-{tag}"));
        wait_until("pid1 to pivot into the rootfs", || {
            ready.exists() && pid_file.exists()
        });
        let pid1: u32 = fs::read_to_string(&pid_file)
            .expect("read pid1 pid")
            .trim()
            .parse()
            .expect("pid1 pid");
        let scope = own_cgroup_path();
        let (cgroup_dir, cgroup_path) = create_container_cgroup(&scope, instance, pid1);
        // launch の `--ulimit` 相当: pid1 の NOFILE を既定と異なる値にし、exec プロセスが「pid1 と同じ値」を
        // 受け取ること（呼び出し元の既定値のままではないこと）を区別できるようにする。
        let prlimit = Command::new("prlimit")
            .arg("--pid")
            .arg(pid1.to_string())
            .arg("--nofile=700:1500")
            .status()
            .expect("run prlimit (util-linux)");
        assert!(prlimit.success(), "prlimit must lower pid1's NOFILE");
        Container {
            stdin,
            a,
            pid1,
            cgroup_dir,
            cgroup_path,
        }
    }

    // ---------------------------------------------------------------- joiner（再入）

    /// `--joiner <mode> <bundle> <scope> <instance> <pid1> [<pid1_b> <instance_b> | <expected cgroup path>]`。
    /// 単一スレッドの exec 専用プロセス。結果は標準出力 1 行（成功 `outcome ...`・拒否 `error: <message>`）と
    /// 終了コード（成功 0・拒否 3）で返す。
    fn joiner(args: &[String]) {
        let arg = |i: usize| args.get(i).map(String::as_str).expect("joiner argument");
        let mode = arg(0);
        let bundle = Path::new(arg(1));
        let scope = arg(2);
        let instance: u64 = arg(3).parse().expect("instance");
        let pid1: u32 = arg(4).parse().expect("pid1");
        let record = make_record(pid1, bundle, scope, instance);
        // `run-script` だけは、インタープリタがランタイム自身を指すスクリプトをエントリポイントにする（#1458）。
        let program = if mode == "run-script" {
            RUNTIME_SCRIPT
        } else {
            PROBE
        };
        let entry = Entrypoint::new(
            format!("/{program}"),
            [format!("/{program}")],
            [] as [&str; 0],
        )
        .expect("entrypoint");
        let result = match mode {
            "run" | "run-script" => run_command(&record, &entry, timeout()),
            "run-in" => run_command_in(&record, arg(5), &entry, timeout()),
            "mismatch" => return joiner_mismatch(bundle, scope, &record, args),
            other => panic!("unknown joiner mode {other}"),
        };
        match result {
            Ok(o) => {
                println!(
                    "outcome exit={:?} rlimits={} caps_dropped={} landlock_rules={} seccomp_instructions={}",
                    o.exit,
                    o.rlimits_applied,
                    o.capability_bounding_dropped,
                    o.landlock_rules,
                    o.seccomp_instructions
                );
            }
            Err(e) => {
                println!("error: {}", e.message());
                std::process::exit(3);
            }
        }
    }

    /// 同じ rootfs を共有する別コンテナ B へ、A 用に準備した制限を持って参加する（条件 3）。再適用が
    /// `exec_joined_namespace_mismatch` で拒否され、何も適用されないことを確かめる。
    fn joiner_mismatch(bundle: &Path, scope: &str, record_a: &StateRecord, args: &[String]) {
        let pid_b: u32 = args.get(5).expect("pid1 of B").parse().expect("pid1 of B");
        let instance_b: u64 = args
            .get(6)
            .expect("instance of B")
            .parse()
            .expect("instance of B");
        let record_b = make_record(pid_b, bundle, scope, instance_b);
        // `setns` の後は自プロセスを `/proc/thread-self` で解決できないため、参加前に status を開いておく。
        let mut own_status = fs::File::open("/proc/thread-self/status").expect("open own status");
        let a = identify_pid1(record_a).expect("identify A");
        let restrictions_for_a = prepare_restrictions(&a).expect("prepare restrictions for A");
        let b = identify_pid1(&record_b).expect("identify B");
        let cgroup_b = prepare_cgroup_join(&b).expect("prepare cgroup join for B");
        enter_namespaces(&b).expect("join B");
        join_cgroup(cgroup_b).expect("join B's cgroup");
        let err = reapply_restrictions(restrictions_for_a).expect_err("A's restrictions on B");
        assert_eq!(
            err.message(),
            "exec stage SetNs: the mount namespace after joining is not the one of the prepared exec \
             target (violation: exec_target/exec_joined_namespace_mismatch, SEC-1)"
        );
        // 何も適用していない（seccomp・NO_NEW_PRIVS とも未適用のまま）。
        own_status.rewind().expect("rewind own status");
        let mut status = String::new();
        own_status.read_to_string(&mut status).expect("own status");
        assert_eq!(status_field(&status, "Seccomp:"), "0");
        assert_eq!(status_field(&status, "NoNewPrivs:"), "0");
        println!("mismatch rejected");
    }

    // ---------------------------------------------------------------- 観測

    fn status_field(status: &str, name: &str) -> String {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} missing in status"))
            .trim()
            .to_owned()
    }

    fn link(path: &str) -> String {
        fs::read_link(path)
            .unwrap_or_else(|e| panic!("read_link {path}: {e}"))
            .to_string_lossy()
            .into_owned()
    }

    /// `/proc/<pid>/limits` の `Max ...` 行（前後の空白を除く。単位列まで含めて pid1 と比べる）。
    fn limit_lines(pid: u32) -> Vec<String> {
        fs::read_to_string(format!("/proc/{pid}/limits"))
            .expect("read limits")
            .lines()
            .filter(|l| l.starts_with("Max "))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    /// `pid` の `(セッション ID, tty_nr)`（`/proc/<pid>/stat`。`comm` は括弧を含み得るため最後の `)` より後ろを読む）。
    fn session_and_tty(pid: u32) -> (u32, i64) {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
        let rest = &stat[stat.rfind(')').expect("comm terminator") + 1..];
        let mut fields = rest.split_whitespace().skip(3);
        let session = fields.next().expect("session").parse().expect("session");
        let tty_nr = fields.next().expect("tty_nr").parse().expect("tty_nr");
        (session, tty_nr)
    }

    /// `pid` の直接の子（`/proc/<pid>/task/<pid>/children`）。
    fn children_of(pid: u32) -> Vec<u32> {
        fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .map(|c| {
                c.split_whitespace()
                    .filter_map(|t| t.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `joiner` の子孫（`run_command` は準備を worker プロセスへ隔離するため、プローブは joiner の孫になる。
    /// REPAIR-5）のうち、実行ファイルがプローブ（host 側の `rootfs/probe` と同じ inode）のものの pid。
    fn probe_child(joiner: u32, probe: &Path) -> Option<u32> {
        let want = fs::metadata(probe).ok()?;
        let mut candidates = children_of(joiner);
        let grandchildren: Vec<u32> = candidates.iter().flat_map(|c| children_of(*c)).collect();
        candidates.extend(grandchildren);
        candidates.into_iter().find(|pid| {
            fs::metadata(format!("/proc/{pid}/exe"))
                .is_ok_and(|m| (m.dev(), m.ino()) == (want.dev(), want.ino()))
        })
    }

    /// joiner を起動する（標準出力は 1 行を読むためパイプ）。
    fn spawn_joiner(args: &[String]) -> Child {
        let exe = std::env::current_exe().expect("current_exe");
        Command::new(exe)
            .arg("--joiner")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn joiner")
    }

    /// joiner の終了を待ち、`(終了コード, 標準出力)` を返す。期限超過は kill して panic（REPAIR-5）。
    fn finish_joiner(mut joiner: Child) -> (Option<i32>, String) {
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(s) = joiner.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = joiner.kill();
                let _ = joiner.wait();
                panic!("joiner did not exit within {:?}", timeout());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut out = String::new();
        if let Some(mut s) = joiner.stdout.take() {
            let _ = std::io::Read::read_to_string(&mut s, &mut out);
        }
        (status.code(), out)
    }

    /// 1 回ぶんの通し: `run_command` で参加・制限・exec し、稼働中のプローブをホスト側の `/proc` から観測する。
    fn one_round(bundle: &Bundle, c: &Container, round: u32, original_cgroup: &str) {
        clean_probe_files(bundle);
        let probe = bundle.rootfs().join(PROBE);
        let scope = own_cgroup_path();
        let joiner = spawn_joiner(&[
            "run".into(),
            bundle.dir.display().to_string(),
            scope,
            "1000".into(),
            c.pid1.to_string(),
        ]);
        let jpid = joiner.id();
        let denied = bundle.rootfs().join("data/unshare_denied");
        let mut child = None;
        wait_until("the probe to start and finish its checks", || {
            child = probe_child(jpid, &probe);
            child.is_some() && denied.exists()
        });
        let pid = child.expect("probe child");
        let status = fs::read_to_string(format!("/proc/{pid}/status")).expect("probe status");
        let ctx = format!("round {round}, probe pid {pid}");
        // PoC-17: seccomp filter・NO_NEW_PRIVS。
        assert_eq!(status_field(&status, "Seccomp:"), "2", "{ctx}");
        assert_eq!(status_field(&status, "NoNewPrivs:"), "1", "{ctx}");
        // SEC-1: capability は OCI 既定集合へ削減されている。
        for field in ["CapBnd:", "CapPrm:", "CapEff:"] {
            assert_eq!(
                status_field(&status, field),
                OCI_DEFAULT_CAPS,
                "{field} {ctx}"
            );
        }
        assert_eq!(
            status_field(&status, "CapInh:"),
            "0000000000000000",
            "{ctx}"
        );
        assert_eq!(
            status_field(&status, "CapAmb:"),
            "0000000000000000",
            "{ctx}"
        );
        // 入れ子の PID namespace（NSpid は 2 要素。先頭は host 側の pid）。
        let nspid = status_field(&status, "NSpid:");
        let nspid: Vec<&str> = nspid.split_whitespace().collect();
        assert_eq!(nspid.len(), 2, "NSpid {nspid:?} {ctx}");
        assert_eq!(
            nspid.first().copied(),
            Some(pid.to_string().as_str()),
            "{ctx}"
        );
        // TASK-163 追補（#1456）: コマンドは新しいセッションのリーダーで、制御端末を持たず、joiner のセッションに
        // 残らない（host 側の pid 番号で照合する）。
        let (session, tty_nr) = session_and_tty(pid);
        assert_eq!(session, pid, "the command must lead its session; {ctx}");
        assert_eq!(tty_nr, 0, "the command must have no controlling tty; {ctx}");
        assert_ne!(session, session_and_tty(jpid).0, "{ctx}");
        // namespace は pid1 と一致する（pid は参加後に fork した子の値）。
        for ns in ["mnt", "uts", "ipc", "net", "pid"] {
            assert_eq!(
                link(&format!("/proc/{pid}/ns/{ns}")),
                link(&format!("/proc/{}/ns/{ns}", c.pid1)),
                "{ns} {ctx}"
            );
        }
        // cgroup: コンテナ用 cgroup の絶対パスと完全一致し、joiner が元いた cgroup と異なる。
        let cgroup = cgroup_of(&pid.to_string());
        assert_eq!(cgroup, c.cgroup_path, "{ctx}");
        assert_ne!(cgroup, original_cgroup, "{ctx}");
        // rlimit は launch と同じ（pid1 の実効値と全 16 種で一致）。
        let lines = limit_lines(pid);
        assert_eq!(lines.len(), 16, "{ctx}");
        assert_eq!(lines, limit_lines(c.pid1), "{ctx}");
        assert!(
            lines.contains(&"Max open files 700 1500 files".to_owned()),
            "pid1's lowered NOFILE must be copied: {lines:?}; {ctx}"
        );
        // Landlock と seccomp の遮断（プローブが残したファイル）。
        let rootfs = bundle.rootfs();
        assert!(
            rootfs.join("data/ok").exists(),
            "rw mount is writable; {ctx}"
        );
        assert!(
            !rootfs.join("deny/no").exists(),
            "read-only root denied; {ctx}"
        );
        assert!(
            !rootfs.join("data/unshare_ok").exists(),
            "unshare allowed; {ctx}"
        );
        assert!(denied.exists(), "unshare must be EPERM; {ctx}");

        // プローブを止める（親は worker。数値 pid へ送るのは、worker が回収するまで再利用されない子のみ）。
        let killed = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .expect("run kill");
        assert!(killed.success(), "{ctx}");
        let (code, out) = finish_joiner(joiner);
        assert_eq!(code, Some(0), "joiner output: {out}; {ctx}");
        assert_eq!(
            out.trim_end(),
            format!(
                "outcome exit={:?} rlimits=16 caps_dropped={} landlock_rules=3 seccomp_instructions={}",
                ChildExit::Signaled(15),
                parse_after(&out, "caps_dropped="),
                parse_after(&out, "seccomp_instructions="),
            ),
            "{ctx}"
        );
    }

    /// `key` の直後の数値トークン（観測できる範囲で具体値を組み立てるため。0 より大きいことも照合する）。
    fn parse_after(out: &str, key: &str) -> u64 {
        let v: u64 = out
            .split(key)
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(|| panic!("{key} missing in joiner output: {out}"));
        assert!(v > 0, "{key} must be positive: {out}");
        v
    }

    /// pivot していない pid1（`unshare` した `sleep`。`/` はホストの root）への exec が、参加後の `/` の照合で
    /// 拒否され、コマンドが起動しないこと（条件 4(d)）。
    fn unpivoted_target_is_rejected(bundle: &Bundle) {
        clean_probe_files(bundle);
        let unshare = Command::new("unshare")
            .args([
                "--pid",
                "--fork",
                "--kill-child",
                "--mount",
                "--uts",
                "--ipc",
                "sleep",
                "60",
            ])
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare");
        let unshare_pid = unshare.id();
        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let guard = Guard(unshare);
        let mut pid1 = None;
        wait_until("the unshared pid1 to appear", || {
            pid1 = nested_pid1_child(unshare_pid);
            pid1.is_some()
        });
        let pid1 = pid1.expect("pid1");
        let scope = own_cgroup_path();
        let (dir, path) = create_container_cgroup(&scope, 3000, pid1);
        let joiner = spawn_joiner(&[
            "run-in".into(),
            bundle.dir.display().to_string(),
            scope,
            "3000".into(),
            pid1.to_string(),
            path,
        ]);
        let (code, out) = finish_joiner(joiner);
        // 後始末（pid1 を止めてから cgroup を消す）。
        drop(guard);
        remove_cgroup(&dir);
        assert_eq!(code, Some(3), "joiner output: {out}");
        assert_eq!(
            out.trim_end(),
            "error: exec stage SetNs: the root directory after joining is not the recorded container \
             rootfs (violation: exec_target/exec_root_not_container_rootfs, SEC-1)"
        );
        assert!(
            !bundle.rootfs().join("data/ok").exists(),
            "the command must not have started"
        );
    }

    /// TASK-163 追補（#1458・SEC-1・SEC-4・CORE-5）: `#!/proc/self/exe` のスクリプトをエントリポイントにした exec は、
    /// 子が `execveat` の前に拒否する（終了コード 126）。ホスト側のランタイムのバイナリ（ここでは試験バイナリ）は
    /// コンテナ内で実行されない。
    ///
    /// 拒否が Landlock（ルール外のバイナリの実行拒否）ではなくインタープリタの照合によることは、非特権で動く
    /// core の `tests/exec_child_setup.rs`（Landlock を適用しない）が同じ入力の拒否を照合している。
    fn runtime_interpreter_script_is_rejected(bundle: &Bundle, c: &Container) {
        clean_probe_files(bundle);
        let joiner = spawn_joiner(&[
            "run-script".into(),
            bundle.dir.display().to_string(),
            own_cgroup_path(),
            "1000".into(),
            c.pid1.to_string(),
        ]);
        let jpid = joiner.id();
        let (code, out) = finish_joiner(joiner);
        assert_eq!(code, Some(0), "joiner output: {out}");
        assert!(
            out.starts_with(&format!("outcome exit={:?} ", ChildExit::Exited(126))),
            "the exec child must refuse the runtime-interpreted script: {out}"
        );
        assert!(
            probe_child(jpid, &std::env::current_exe().expect("current_exe")).is_none(),
            "the runtime binary must not be running as the script interpreter"
        );
    }

    /// TASK-163 追補（#1459・SEC-1・SEC-4）: コンテナの `/dev/null` が symlink・別のデバイスノード（1:5）へ
    /// 差し替えられていたら、exec の子は差し替え先を開かずに拒否し、コマンドは起動しない（終了コード 126）。
    ///
    /// rootfs の `dev/` は pid1 が `create_default_devices` で作ったホスト側のディレクトリそのものなので、
    /// ホスト側から差し替える（コンテナが `CAP_MKNOD` で行う差し替えと同じ結果になる）。照合の前に必ず元へ戻す。
    fn replaced_dev_null_is_rejected(bundle: &Bundle, c: &Container) {
        let null = bundle.rootfs().join("dev/null");
        let saved = bundle.rootfs().join("dev/null.saved");
        for kind in ["symlink", "device"] {
            clean_probe_files(bundle);
            fs::rename(&null, &saved).expect("move the real /dev/null aside");
            let replaced = match kind {
                "symlink" => std::os::unix::fs::symlink("zero", &null).is_ok(),
                _ => Command::new("mknod")
                    .arg(&null)
                    .args(["c", "1", "5"])
                    .status()
                    .is_ok_and(|s| s.success()),
            };
            let joiner = replaced.then(|| {
                spawn_joiner(&[
                    "run".into(),
                    bundle.dir.display().to_string(),
                    own_cgroup_path(),
                    "1000".into(),
                    c.pid1.to_string(),
                ])
            });
            let result = joiner.map(finish_joiner);
            // 元へ戻してから照合する（失敗しても後続のシナリオと後始末を壊さない）。
            let _ = fs::remove_file(&null);
            fs::rename(&saved, &null).expect("restore the real /dev/null");
            let (code, out) = result.unwrap_or_else(|| panic!("replace /dev/null with a {kind}"));
            assert_eq!(code, Some(0), "joiner output: {out}; {kind}");
            assert!(
                out.starts_with(&format!("outcome exit={:?} ", ChildExit::Exited(126))),
                "the exec child must refuse the replaced /dev/null ({kind}): {out}"
            );
            assert!(
                !bundle.rootfs().join("data/ok").exists(),
                "the command must not have started ({kind})"
            );
        }
    }

    /// `unshare_pid` の子のうち、入れ子の PID namespace の PID 1（`NSpid` が 2 要素以上で末尾 1）のもの。
    fn nested_pid1_child(unshare_pid: u32) -> Option<u32> {
        let children =
            fs::read_to_string(format!("/proc/{unshare_pid}/task/{unshare_pid}/children")).ok()?;
        children
            .split_whitespace()
            .filter_map(|t| t.parse::<u32>().ok())
            .find(|pid| {
                let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                    return false;
                };
                let nspid = status_field(&status, "NSpid:");
                let toks: Vec<&str> = nspid.split_whitespace().collect();
                toks.len() >= 2 && toks.last() == Some(&"1")
            })
    }

    /// 同じ rootfs を共有する 2 つのコンテナ A・B で、A 用に準備した制限を B へ参加したプロセスへ適用させない
    /// こと（条件 3）。
    fn other_container_is_rejected(bundle: &Bundle, a: &Container, b: &Container) {
        let scope = own_cgroup_path();
        let joiner = spawn_joiner(&[
            "mismatch".into(),
            bundle.dir.display().to_string(),
            scope,
            "1000".into(),
            a.pid1.to_string(),
            b.pid1.to_string(),
            "2000".into(),
        ]);
        let (code, out) = finish_joiner(joiner);
        assert_eq!(code, Some(0), "joiner output: {out}");
        assert_eq!(out.trim_end(), "mismatch rejected");
    }

    fn orchestrate() {
        assert_eq!(
            fs::read_to_string("/proc/self/status")
                .expect("status")
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|r| r.split_whitespace().nth(1).map(str::to_owned))
                .as_deref(),
            Some("0"),
            "this test needs root (rootful pivot_root, cgroup v2 writes); rootless exec is not implemented"
        );
        let bundle = make_bundle();
        verify_probe_on_host(&bundle);
        let original_cgroup = own_cgroup_path();

        let a = start_container(&bundle, "a", 1000);
        // 5 回の通し（本番の `identify_pid1` 経路。記録の cgroup 配置から期待 cgroup を導く）。
        for round in 1..=ROUNDS {
            one_round(&bundle, &a, round, &original_cgroup);
        }
        // 拒否経路（TASK-163 追補）: `/dev/null` の差し替え（#1459）・インタープリタ経由のランタイム実行（#1458）。
        replaced_dev_null_is_rejected(&bundle, &a);
        runtime_interpreter_script_is_rejected(&bundle, &a);
        // 拒否経路（条件 3・4(d)）。
        let b = start_container(&bundle, "b", 2000);
        other_container_is_rejected(&bundle, &a, &b);
        drop(b);
        unpivoted_target_is_rejected(&bundle);
        println!("exec: {ROUNDS}/{ROUNDS} exec verified");
    }
}
