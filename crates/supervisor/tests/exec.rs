//! 稼働中コンテナへのコマンド実行（縮退経路の試験専用入口 `run_command` と本番の `run_command_with_pidfd`）の通し結合試験（TASK-163.4・#503・SUP-6・SEC-1・REPAIR-12）。
//!
//! 実コンテナ（`pivot_root` 済みの pid1）へ `setns` で参加し、cgroup へ join し、rlimit・capability 削減・
//! `NO_NEW_PRIVS`・Landlock・seccomp を再適用して `execve` するまでを、本番の `fandhe_container_supervisor::exec`
//! の入口（`run_command` / `run_command_in`）で通し、PoC-17 の確認項目を具体値で照合する。
//!
//! - `Seccomp: 2`・`NoNewPrivs: 1`（seccomp filter・`NO_NEW_PRIVS`）
//! - capability: `CapBnd` / `CapPrm` / `CapEff` が OCI 既定集合（SEC-1。core の `DEFAULT_MASK` = `0xa80425fb`）
//! - rlimit: `/proc/<pid>/limits` が launch 時の記録（`state.json` 相当の全 16 種）と一致し、pid1 が launch の後に soft を
//!   上げていても記録の値になる（SUP-12・TASK-169 追補・#1467）
//! - Landlock: 読み取り専用の root 配下への書き込みが拒否され（`deny/no` は作られない）、`rw` の mount 先
//!   （`data/ok`）は作られる。seccomp: 禁止 syscall の `setns(0, 0)` が `EPERM`（`data/unshare_denied`。フィルタ適用前は `EINVAL` で `data/unshare_ok`。ファイル名は `unshare` 時代の名残）
//! - cgroup: `/proc/<pid>/cgroup` がコンテナ用 cgroup（`<scope>/fc-<id>@<instance>`）直下の exec 用の子
//!   cgroup（`exec-<nonce>`。#1466）で、joiner が元いた cgroup と異なる
//! - namespace: `NSpid` が入れ子で、`ns/{mnt,uts,ipc,net,pid}` が pid1 と一致（pid は参加後に fork した子の値）
//! - 環境変数・補助グループ（TASK-163 追補・#1457）: コマンドの `/proc/<pid>/environ` が、コンテナ定義
//!   （`config.json` の `process.env`）へ明示の上書きを重ねたものと完全一致し、joiner だけが持つ環境変数を含まない。
//!   `Groups:` が空（launch と同じ扱い）
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
//! エントリポイントの実行方式（#1531。オーナー判断 2026-10-09「条件付き切り替え」）: ホストの環境で封印した複製
//! （`sealed_copy`）か現行方式（`pinned_inode`）が選ばれる。どちらでも exec は成功することを期待し、joiner の
//! 構造化ログ（joiner の stderr に繋いだ AF_UNIX の socket pair に届く `supervisor.exec` / `entrypoint_mode` の 1 行。
//! pipe・ファイルには出ない。#1698）・`ExecOutcome::entrypoint_mode`・稼働中の
//! プローブの `/proc/<pid>/exe`（封印した複製なら `/memfd:fandhe-exec-entrypoint (deleted)`、現行方式ならプローブの
//! inode）の三つが同じ方式を示すことを照合する。
//!
//! 通しは 5 回繰り返し、1 回でも不一致なら失敗する（リトライで隠さない）。
//!
//! # 2 つの場面
//! - rootful（`--ignored`。上記すべて）: root で `isolate_rootful_host_root` したコンテナ
//! - rootless（`--ignored --rootless`。TASK-163 追補・#1887・SUP-6・SEC-1・SEC-5・CORE-5・CORE-6・REPAIR-12）: 非 root で
//!   `unshare(1)` の `--user --map-root-user --pid --fork --kill-child --mount --uts --ipc --net`（`exec_setns_join` の rootless の
//!   場面と同じ構成。単一 ID の写像 `0 <euid> 1`）で起動し、launch と同じ手順で `pivot_root` した pid1 へ、
//!   rootful と同じ入口（`run_command`）で user namespace を含めて参加する。cgroup への join・rlimit・capability 削減・
//!   `NO_NEW_PRIVS`・Landlock・seccomp を経て `execve` するまでを 5 回通し、rootful と同じ項目を具体値で照合する。
//!   rootless 固有の期待値は [`RoundExpect`] に集める: `ns/user` が pid1 と一致して orchestrator と異なる・`Uid:` / `Gid:` が
//!   orchestrator の euid / egid（名前空間内の 0 が所有者へ写る）・`uid_map` / `gid_map` が `0 <id> 1`・`Groups:` が joiner の
//!   ままで結果が `kept_setgroups_denied`（所有者は初期 user namespace で `CAP_SETGID` を持たず、参加先は `setgroups` が
//!   `deny` のため）。capability の値は rootful と同じ `00000000a80425fb` だが、これはコンテナの user namespace に対する
//!   権限で、host に対する権限ではない（`ns/user` の不一致と `uid_map` で裏づける）。
//!   成功経路の 5 回のあと、拒否経路 4 つ（インタープリタ経由 `entrypoint_interpreter_is_runtime_binary`・別コンテナ
//!   `exec_joined_namespace_mismatch`・pivot していない対象 `exec_root_not_container_rootfs`・`/dev/null` の差し替え
//!   `stdio_null_not_null_device`。#2443）も rootful と同じ具体値で照合する。違いは `/dev/null` の差し替え方だけで、
//!   rootless の `/dev/null` はホストのノードの bind のため、ホストからの `rename` は `EBUSY`・user namespace 内の
//!   `mknod` は `EPERM` になる。そこで使い捨てのコンテナの pid1 が pivot の前に差し替える（symlink と、`/dev/zero`
//!   〔1:5〕の bind）。この場面は `mount` / `umount`（util-linux）も要る。
//!
//! # 構成（再入）
//! `harness = false` の単一スレッド `main` で、自身を次の役で再実行する。
//! - 親（`--ignored`）: bundle を作り、コンテナ `A` / `B` を起動して観測する。`--ignored --rootless` は rootless の場面
//! - `--container`: `isolate_rootful_host_root`（pid / mnt / uts / ipc）→ pid1 を子として生成して待機
//! - rootless のコンテナ役は再入ではなく `unshare(1)` を直接起動する。core の単一 ID 経路（`plan` → `isolate`）を使わないのは、
//!   `Namespace` に network が無く（rootless の起動経路への netns の追加は #1939）、core の `join_namespaces` が 5 種を必ず
//!   `setns` するため、user namespace へ参加した後は初期 user namespace が所有する netns へ入れないから（`--net` が要る）
//! - `--pid1` / `--pid1-rootless`（後者は末尾に任意の差し替え指定 `tamper-symlink` / `tamper-bind-zero`）: 新しい PID namespace の PID 1。`establish` → `prepare_rootfs` → `create_default_devices` →
//!   `pivot_root` の後、合図ファイルを置いて待機する（launch の exec は証跡未結線で拒否されるため exec しない）。
//!   rootless は `DevptsGidSource::Rootless`（本番 launcher の単一 ID 経路と同じ。host の gid は argv で受ける）
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
//! 場合は拒否を含むあらゆる失敗を失敗として扱う。
//!
//! rootless の場面（`--rootless`）は root ではなく、非 root・非特権 user namespace が作れるホスト（
//! `kernel.apparmor_restrict_unprivileged_userns` が 1 でない）・Landlock ABI 6+・委譲された cgroup v2
//! （`systemd-run --user --scope -p Delegate=yes` の下で実行する）・`cgroup.kill`（Linux 5.14+）・`unshare` / `prlimit`
//! （util-linux）を要する。満たさないときは副作用の前に「検証していない」ことを `exit 2` と
//! `exec: not verified (rootless): <理由>` で知らせ、成功を装わない。事前検査を通った後の不一致はすべて失敗とする。
//! feature なしのビルドは `--rootless` を付けても同じく `exit 2`（`--ignored` で判定するため）。
//! user namespace への参加と資格情報の処理だけは、非特権で動く `exec_setns_join` も照合する（#1462）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(target_arch = "x86_64", target_pointer_width = "64"))
))]
fn main() {
    println!(
        "exec: x86_64 only (hand-made machine-code probe), not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
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
    target_pointer_width = "64",
    feature = "exec-test-support"
))]
fn main() {
    linux::run();
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
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

    use fandhe_container_core::audit_log::{AuditDelivery, AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::CgroupName;
    use fandhe_container_core::exec::{
        ChildExit, ContainerEnv, DevptsGidSource, ExecExit, IsolationConfig, MountIsolation,
        Namespace, NamespaceSet, ViolationReason, create_default_devices,
        isolate_rootful_host_root, launch_isolation_from_bundle, launch_rlimits_from_self,
        mount_tmpfs, pivot_root, plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::oci_runtime::{load_config, pin_bundle_rootfs};
    use fandhe_container_core::rlimits::{Rlimit, RlimitKind, Rlimits};
    use fandhe_container_core::rootless::single_id_mapping;
    use fandhe_container_core::tmpfs::TmpfsMountSet;
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, StateRecord, StateRevision,
        TraitError,
    };
    use fandhe_container_supervisor::container_options::env::EnvVar;
    use fandhe_container_supervisor::exec::{
        AuditedOutcome, ExecListenerHandover, ExecRequest, enter_namespaces, identify_pid1,
        join_cgroup, prepare_cgroup_join, prepare_restrictions, reapply_restrictions, run_command,
        run_command_in,
    };

    /// 5 回の通し（受入条件: 5 回中 5 回成功）。
    const ROUNDS: u32 = 5;
    /// OCI 既定の capability 集合のマスク（core の `exec/capabilities.rs` の `DEFAULT_MASK`。SEC-1）。
    const OCI_DEFAULT_CAPS: &str = "00000000a80425fb";
    /// プローブの bundle 内の名前。
    const PROBE: &str = "probe";
    /// インタープリタにランタイム自身（`/proc/self/exe`）を指定したスクリプトの bundle 内の名前（#1458）。
    const RUNTIME_SCRIPT: &str = "runtime-script";
    /// exec を起動する側（joiner）だけが持つ環境変数。exec されたコマンドへ渡ってはならない（#1457）。
    const HOST_ONLY_ENV: &str = "FANDHE_EXEC_TEST_HOST_ONLY";
    /// exec されたコマンドの環境（`/proc/<pid>/environ`）の期待値: コンテナ定義（`config.json` の `process.env`）へ
    /// joiner の明示の上書き（`OVERRIDDEN`・`EXTRA`）を重ねたもの。
    const EXPECTED_ENVIRON: &[u8] = b"FANDHE_EXEC_ENV=from-config\0OVERRIDDEN=explicit\0EXTRA=1\0";
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
                None,
                None,
            ),
            // `--pid1-rootless <rootfs> <ready> <host egid> [tamper-symlink|tamper-bind-zero]`
            Some("--pid1-rootless") => pid1(
                Path::new(arg(2).expect("rootfs")),
                arg(3).expect("ready name"),
                Some(arg(4).expect("host egid").parse().expect("host egid")),
                arg(5).map(|t| match t {
                    "tamper-symlink" => Tamper::Symlink,
                    "tamper-bind-zero" => Tamper::BindZero,
                    other => panic!("unknown tamper {other}"),
                }),
            ),
            Some("--joiner") => joiner(&args[2..]),
            // root 不要の補助: 手組みのプローブだけをホスト上で自己検証する（`orchestrate` も最初に行う）。
            Some("--selfcheck-probe") => {
                let bundle = make_bundle();
                verify_bundle_definition(&bundle);
                verify_probe_on_host(&bundle);
                println!("exec: probe self-check ok");
            }
            // `--rootless` の判定は `--ignored` だけの分岐より先に置く（rootful の挙動は変えない）。
            _ if args.iter().any(|a| a == "--ignored")
                && args.iter().any(|a| a == "--rootless") =>
            {
                orchestrate_rootless()
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
    /// 3. `setns(0, 0)`（272 ではなく 308。`edi` と `esi` を明示的に 0 にする）: 戻り値が `-EINVAL`（-22。fd 0 は
    ///    namespace の fd ではない）なら `data/unshare_ok`（= seccomp に拒否されていない）、`-EPERM` なら
    ///    `data/unshare_denied` を作る（seccomp）。それ以外の値ではどちらも作らず `pause` する
    ///    `unshare`・`ptrace`・`kexec_load` は ESC-06 で `SECCOMP_RET_KILL_PROCESS`（SIGSYS）になり、プローブが死んで
    ///    稼働中の観測ができないため、`ERRNO(EPERM)` の `setns` で exec 後の deny フィルタ適用を確かめる
    ///    （KILL_PROCESS の経路は core の `exec_restrictions_reapply`・`seccomp` 試験が担う）。ファイル名は名残
    ///
    /// 機械語は `as`（GNU as, Intel 構文）で組み立てた 172 バイトで、`probe.s` 相当の命令列（`_start` から
    /// `lea rdi,[rip+..]; mov esi,0x41; mov edx,0x180; mov eax,2; syscall` を 2 回、`setns` 308（`xor edi,edi; xor esi,esi`）、`cmp rax,-22` の判定、`pause` 34、
    /// `exit` 60）と文字列 4 つ。ホスト上で直接実行して自己検証する（バイト列の誤りをランタイムの不具合と
    /// 取り違えない）。
    fn probe_elf() -> Vec<u8> {
        #[rustfmt::skip]
        const CODE: &[u8] = &[
            0x48, 0x8d, 0x3d, 0x71, 0x00, 0x00, 0x00, 0xbe, 0x41, 0x00, 0x00, 0x00,
            0xba, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05,
            0x48, 0x8d, 0x3d, 0x61, 0x00, 0x00, 0x00, 0xbe, 0x41, 0x00, 0x00, 0x00,
            0xba, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05,
            0xb8, 0x34, 0x01, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x0f, 0x05, 0x48, 0x83, 0xf8, 0xea,
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
    /// `setns(0, 0)` の `-EINVAL`。seccomp 適用前なので `data/unshare_ok` が作られ `data/unshare_denied` は作られない）を確かめる。
    fn verify_probe_on_host(bundle: &Bundle) {
        let work = bundle.dir.join("selfcheck");
        // bundle は排他作成済み。配下は `create_dir` で 1 階層ずつ作る（#2324・SEC-2）。
        fs::create_dir(&work).expect("mkdir selfcheck");
        fs::create_dir(work.join("data")).expect("mkdir selfcheck/data");
        fs::create_dir(work.join("deny")).expect("mkdir selfcheck/deny");
        let mut child = Command::new(bundle.rootfs().join(PROBE))
            .current_dir(&work)
            .stdin(Stdio::null())
            .spawn()
            .expect("run the probe directly on the host (is the temp dir mounted noexec?)");
        wait_until("the host probe to finish its steps", || {
            work.join("data/unshare_ok").exists()
        });
        kill_and_reap(&mut child);
        assert!(
            !work.join("data/unshare_denied").exists(),
            "the host probe must see -EINVAL from setns(0, 0), not -EPERM"
        );
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
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},"process":{"user":{"uid":0,"gid":0},"cwd":"/","args":["/probe"],"env":["FANDHE_EXEC_ENV=from-config","OVERRIDDEN=config"]},"mounts":[{"destination":"/data","options":["rw"]}]}"#,
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
        kill_and_reap(&mut pid1);
    }

    /// `--pid1`: launch と同じ手順で `pivot_root` まで進み、合図ファイルを置いて待機する。
    /// launch の exec は証跡未結線で拒否されるため exec しない。
    ///
    /// `rootless_host_egid` が `Some` なら rootless（`--pid1-rootless`）で、本番 launcher の単一 ID 経路と同じ
    /// `DevptsGidSource::Rootless(single_id_mapping(host の egid))` を使う（host の `/dev` のノードを bind して供給する）。
    ///
    /// `tamper` が `Some` なら、`pivot_root` の前に `<rootfs>/dev/null` を差し替える（rootless の `/dev/null` 拒否経路。
    /// #2443・#1459・SEC-1）。rootless の `/dev` はホストのノードの bind を載せた tmpfs で、コンテナの外（初期 user
    /// namespace の orchestrator）からは `rename` が `EBUSY`・`umount` が権限不足・user namespace 内の `mknod` が `EPERM` に
    /// なるため、まだホストの util-linux が見えるこの時点で、pid1 自身（名前空間内の root）が行う。
    fn pid1(rootfs: &Path, ready: &str, rootless_host_egid: Option<u32>, tamper: Option<Tamper>) {
        assert_eq!(std::process::id(), 1, "must be PID 1 of the new namespace");
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let gid_map =
            rootless_host_egid.map(|egid| single_id_mapping(egid).expect("single id gid map"));
        let gid_source = gid_map
            .as_ref()
            .map_or(DevptsGidSource::Rootful, DevptsGidSource::Rootless);
        let devices = create_default_devices(&isolation, &prepared, gid_source)
            .expect("create default devices");
        // 暗黙の `/dev/shm` を載せる（本番の順序: create_default_devices の後。#1654）。Landlock の暗黙分の
        // ルール（`/dev/shm`。#1657）が存在するパスを指すために必要。
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .ensure_default_dev_shm()
            .expect("default /dev/shm spec");
        mount_tmpfs(&isolation, &prepared, Some(&devices), &tmpfs).expect("mount default /dev/shm");
        if let Some(t) = tamper {
            tamper_dev_null(rootfs, t);
        }
        pivot_root(&isolation, prepared).expect("pivot_root");
        fs::write(format!("/{ready}"), b"ready").expect("write ready marker");
        // 親が stdin 経由で pid1 を kill するまで待機する（上限つき。REPAIR-5）。
        let deadline = Instant::now() + Duration::from_secs(600);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// rootless の pid1 が pivot の前に行う `/dev/null` の差し替えの種類（#2443）。
    #[derive(Clone, Copy)]
    enum Tamper {
        /// bind を外し、tmpfs 上のファイルを消して `zero` への symlink にする。
        Symlink,
        /// ホストの `/dev/zero`（文字デバイス 1:5）を `/dev/null` へ bind する（rootful の `mknod c 1 5` の代わり）。
        BindZero,
    }

    impl Tamper {
        fn arg(self) -> &'static str {
            match self {
                Tamper::Symlink => "tamper-symlink",
                Tamper::BindZero => "tamper-bind-zero",
            }
        }
    }

    /// 外部コマンド（util-linux）を期限つきで実行し、成功を要求する（REPAIR-5。失敗は panic = 試験の失敗）。
    fn run_tool(program: &str, args: &[&Path]) {
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("run {program}: {e}"));
        assert_eq!(finish_joiner(child).0, Some(0), "{program} must succeed");
    }

    /// [`pid1`] の差し替え本体。`<rootfs>/dev` は pid1 の mount namespace 内で tmpfs（#1653）。
    /// 失敗は panic にして試験を失敗させる（差し替えられていないのに拒否を期待する偽の成功を作らない）。
    fn tamper_dev_null(rootfs: &Path, tamper: Tamper) {
        let null = rootfs.join("dev/null");
        match tamper {
            Tamper::Symlink => {
                run_tool("umount", &[&null]);
                fs::remove_file(&null).expect("remove the unmounted /dev/null placeholder");
                std::os::unix::fs::symlink("zero", &null).expect("symlink /dev/null -> zero");
            }
            Tamper::BindZero => {
                run_tool(
                    "mount",
                    &[Path::new("--bind"), Path::new("/dev/zero"), &null],
                );
            }
        }
    }

    /// 起動済みのコンテナ（A プロセスとその pid1・cgroup）。drop で pid1 を止め、cgroup を消す。
    struct Container {
        stdin: Option<ChildStdin>,
        /// rootless のコンテナ役は `unshare --kill-child` で、stdin の EOF では終わらない（drop で kill する）。
        rootless: bool,
        a: Child,
        pid1: u32,
        cgroup_dir: PathBuf,
        /// `<scope>/fc-<id>@<instance>`（cgroup 名前空間の根からの絶対パス）。
        cgroup_path: String,
    }

    impl Drop for Container {
        fn drop(&mut self) {
            drop(self.stdin.take());
            if self.rootless {
                // `--kill-child` が pid1 を道連れにする。
                kill_and_reap(&mut self.a);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.a.try_wait().ok().flatten().is_none() {
                if Instant::now() >= deadline {
                    kill_and_reap(&mut self.a);
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // cgroup 作成前（起動途中の失敗）は空のまま。
            if !self.cgroup_dir.as_os_str().is_empty() {
                remove_cgroup(&self.cgroup_dir);
            }
        }
    }

    /// 子を kill し、期限つきで回収する（`Child::wait()` は期限なしのため使わない。REPAIR-5）。
    /// 回収できなければ標準エラーに記録して戻る（drop 内からも呼ぶため panic しない）。
    fn kill_and_reap(child: &mut Child) {
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "exec: child {} was not reaped within 10s after kill",
                    child.id()
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
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
        if let Err(e) = fs::write(dir.join("cgroup.procs"), pid.to_string()) {
            // 作った cgroup を残さない。
            let _ = fs::remove_dir(&dir);
            panic!("move pid1 into the container cgroup: {e}");
        }
        (dir, path)
    }

    /// launch 時の rlimit の記録（`--ulimit nofile=700:1500` 相当を指定し、残りの 15 種は launch 時点の実効値で埋めた
    /// 全 16 種。#1467）。joiner はオーケストレータの子で、pid1 と同じ継承値を持つため、本番の launcher が使う
    /// core の `launch_rlimits_from_self` で pid1 の launch 時の値と一致する集合が作れる。
    fn launch_rlimits() -> Rlimits {
        let specified = Rlimits::new(vec![
            Rlimit::new(RlimitKind::Nofile, 700, 1500).expect("rlimit"),
        ])
        .expect("rlimits");
        launch_rlimits_from_self(&specified).expect("launch rlimits")
    }

    /// launch 時の分離の記録（#1468）。コンテナは bundle の rootfs を自分自身へ bind して pivot する（launcher の
    /// 契約）ため、固定した rootfs の識別子と `config.json` 由来の Landlock ルールが pivot 後の `/` と一致する。
    fn launch_isolation(
        bundle: &Path,
    ) -> fandhe_container_core::launch_isolation::LaunchIsolationRecord {
        let config = load_config(&bundle.join("config.json")).expect("config");
        let rootfs = pin_bundle_rootfs(bundle, &config).expect("pin rootfs");
        launch_isolation_from_bundle(&config, &rootfs).expect("launch isolation")
    }

    /// 記録（Running・pid1 の host 側 pid・cgroup 配置・launch 時の rlimit と分離つき）。joiner も同じ関数で作る。
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
            .with_rlimits(launch_rlimits())
            .with_launch_isolation(launch_isolation(bundle))
    }

    /// コンテナ（pivot 済みの pid1）を起動して cgroup へ入れる。`tag` は合図・pid ファイルの識別子。
    fn start_container(bundle: &Bundle, tag: &str, instance: u64) -> Container {
        start_container_as(bundle, tag, instance, false)
    }

    /// [`start_container`] の本体。cgroup の作成と `prlimit` の 2 段は共通で、rootless でも orchestrator（pid1 の所有者）が
    /// 非特権で行える。
    ///
    /// `rootless` のコンテナ役は `unshare(1)`（`--user --map-root-user --pid --fork --kill-child --mount --uts --ipc --net`）で、
    /// `exec_setns_join` の rootless の場面と同じ構成。core の単一 ID 経路（`plan` → `isolate`）を使わないのは、
    /// `Namespace` に network が無く（#1939）、user namespace へ参加した後は初期 user namespace が所有する netns へ
    /// `setns` できない（core の `join_namespaces` は 5 種を必ず `setns` する）ため、netns を自前で分離する必要があるから。
    /// uid_map / gid_map は `0 <euid> 1` / `0 <egid> 1`（setgroups は deny）で、launcher の単一 ID 経路と同じ写像になる。
    /// pid1 の host 側 pid は、`unshare` の子のうち入れ子の PID 1（[`nested_pid1_child`]）として探す。
    fn start_container_as(bundle: &Bundle, tag: &str, instance: u64, rootless: bool) -> Container {
        start_container_with(bundle, tag, instance, rootless, None)
    }

    /// [`start_container_as`] の本体。`tamper` は rootless の pid1 にだけ渡る（rootful には無い）。
    fn start_container_with(
        bundle: &Bundle,
        tag: &str,
        instance: u64,
        rootless: bool,
        tamper: Option<Tamper>,
    ) -> Container {
        let exe = std::env::current_exe().expect("current_exe");
        let ready_name = format!("ready-{tag}");
        let mut a = if rootless {
            let mut cmd = Command::new("unshare");
            cmd.args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
            ])
            .arg(exe)
            .arg("--pid1-rootless")
            .arg(bundle.rootfs())
            .arg(&ready_name)
            // 名前空間内の egid は 0 になるため、host の egid を pid1 へ渡す（devpts の gid= の決定元）。
            .arg(own_status_ids().1.to_string())
            .stdin(Stdio::null());
            if let Some(t) = tamper {
                cmd.arg(t.arg());
            }
            cmd
        } else {
            let mut cmd = Command::new(exe);
            cmd.arg("--container")
                .arg(bundle.rootfs())
                .arg(&ready_name)
                .stdin(Stdio::piped());
            cmd
        }
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn container process");
        // spawn 直後から RAII ガードで保持する。以降の panic（待ち合わせ・cgroup 作成・prlimit の失敗）でも
        // drop が期限つきで kill・回収し、作成済みの cgroup を消す（pid1 と名前空間を残さない）。
        let stdin = a.stdin.take();
        let mut container = Container {
            stdin,
            rootless,
            a,
            pid1: 0,
            cgroup_dir: PathBuf::new(),
            cgroup_path: String::new(),
        };
        let ready = bundle.rootfs().join(&ready_name);
        let pid_file = bundle.dir.join(format!("pid1-ready-{tag}"));
        let mut found = None;
        wait_until("pid1 to pivot into the rootfs", || {
            if rootless {
                found = nested_pid1_child(container.a.id());
                ready.exists() && found.is_some()
            } else {
                ready.exists() && pid_file.exists()
            }
        });
        let pid1: u32 = match found {
            Some(pid) => pid,
            None => fs::read_to_string(&pid_file)
                .expect("read pid1 pid")
                .trim()
                .parse()
                .expect("pid1 pid"),
        };
        let scope = own_cgroup_path();
        container.pid1 = pid1;
        let (cgroup_dir, cgroup_path) = create_container_cgroup(&scope, instance, pid1);
        container.cgroup_dir = cgroup_dir;
        container.cgroup_path = cgroup_path;
        // launch の `--ulimit` 相当: pid1 の NOFILE を既定と異なる値にし、exec プロセスが「pid1 と同じ値」を
        // 受け取ること（呼び出し元の既定値のままではないこと）を区別できるようにする。
        let prlimit = Command::new("prlimit")
            .arg("--pid")
            .arg(pid1.to_string())
            .arg("--nofile=700:1500")
            .stdin(Stdio::null())
            .spawn()
            .expect("run prlimit (util-linux)");
        // 期限つきで待つ（REPAIR-5）。
        assert_eq!(
            finish_joiner(prlimit).0,
            Some(0),
            "prlimit must lower pid1's NOFILE"
        );
        // launch の後に pid1 が自分の soft を hard の範囲で上げる（コンテナ内のプロセスにできる操作）。exec は
        // pid1 の今の値（1400）ではなく、launch 時の記録（700）を適用しなければならない（#1467）。
        let raise = Command::new("prlimit")
            .arg("--pid")
            .arg(pid1.to_string())
            .arg("--nofile=1400:1500")
            .stdin(Stdio::null())
            .spawn()
            .expect("run prlimit (util-linux)");
        assert_eq!(
            finish_joiner(raise).0,
            Some(0),
            "prlimit must raise pid1's NOFILE soft limit"
        );
        container
    }

    // ---------------------------------------------------------------- joiner（再入）

    /// `--joiner <mode> <bundle> <scope> <instance> <pid1> [<pid1_b> <instance_b> | <expected cgroup path>]`。
    /// 単一スレッドの exec 専用プロセス。結果は標準出力（成功 `outcome ...` 1 行・拒否 `error: <message>` と監査記録の要約 `audit: ...` の 2 行）と
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
        let entry = ExecRequest::new(format!("/{program}"), [format!("/{program}")])
            .expect("request")
            .with_env(&explicit_env())
            .expect("explicit env");
        // 拒否の監査記録（SEC-4・SUP-6・#1465）を受けるメモリ上の sink。拒否の行の次に記録の要約を 1 行出す。
        let sink = CountingSink::default();
        let result = match mode {
            "run" | "run-script" => run_command(&record, &entry, timeout(), &sink),
            "run-in" => run_command_in(&record, arg(5), &entry, timeout(), &sink),
            "mismatch" => return joiner_mismatch(bundle, scope, &record, args),
            other => panic!("unknown joiner mode {other}"),
        };
        match result {
            Ok(AuditedOutcome {
                outcome: o, audit, ..
            }) => {
                println!(
                    "outcome exit={:?} rlimits={} rlimits_deferred={} caps_dropped={} landlock_rules={} seccomp_instructions={} groups={} entrypoint_mode={} reason={} seccomp_listener={}",
                    o.exit,
                    o.rlimits_applied,
                    o.rlimits_deferred,
                    o.capability_bounding_dropped,
                    o.landlock_rules,
                    o.seccomp_instructions,
                    o.supplementary_groups.as_str(),
                    o.entrypoint_mode.as_str(),
                    o.entrypoint_mode
                        .fallback_reason()
                        .map_or("-", |r| r.as_str()),
                    // listener の受け渡しの証跡（SEC-4・SUP-6・#2385）。本番の通しの入口は必ず `verified`。
                    match o.seccomp_listener {
                        ExecListenerHandover::Verified => "verified",
                        _ => "other",
                    },
                );
                // `execve` 前の拒否（`SetupFailed` の違反）だけ、層 `entrypoint` の記録の要約を 2 行目に出す（#1595）。
                // コマンドが起動した成功経路は 1 行のまま（既存の厳密一致の照合を保つ）。
                if audit != AuditDelivery::NotApplicable {
                    println!("audit: {}", sink.summary(&audit));
                }
            }
            Err(rejected) => {
                println!("error: {}", rejected.error.message());
                println!("audit: {}", sink.summary(&rejected.delivery));
                std::process::exit(3);
            }
        }
    }

    /// 拒否の監査記録を数えるだけの sink（実機試験の joiner 用）。
    #[derive(Default)]
    struct CountingSink {
        records: std::sync::Mutex<Vec<AuditRecord>>,
    }

    impl AuditSink for CountingSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            if let Ok(mut g) = self.records.lock() {
                g.push(record.clone());
            }
            Ok(())
        }
    }

    impl CountingSink {
        /// `delivery=<結果> records=<件数> layer=<層> reason=<理由> path=<none|some>`（先頭の 1 件）。
        fn summary(&self, delivery: &AuditDelivery) -> String {
            let g = self.records.lock().expect("sink lock");
            let first = g.first();
            format!(
                "delivery={delivery:?} records={} layer={} reason={} path={}",
                g.len(),
                first.map_or("-", |r| r.layer().as_str()),
                first
                    .and_then(AuditRecord::reason)
                    .map_or("-", |r| r.as_str()),
                if first.is_some_and(|r| r.path().is_some()) {
                    "some"
                } else {
                    "none"
                },
            )
        }
    }

    /// joiner が exec に対して明示する環境変数（CLI の `-e` 相当）。コンテナ定義の `OVERRIDDEN` を上書きし、
    /// `EXTRA` を足す。
    fn explicit_env() -> Vec<EnvVar> {
        ["OVERRIDDEN=explicit", "EXTRA=1"]
            .into_iter()
            .map(|v| EnvVar::parse(v).expect("env var"))
            .collect()
    }

    /// 自己検証（root 不要）: bundle の `config.json` が解釈でき、コンテナ定義の環境へ明示の上書きを重ねた結果が
    /// [`EXPECTED_ENVIRON`] と一致する（期待値の誤りをランタイムの不具合と取り違えない）。
    fn verify_bundle_definition(bundle: &Bundle) {
        let config = load_config(&bundle.dir.join("config.json")).expect("load config.json");
        let env = explicit_env()
            .iter()
            .try_fold(
                ContainerEnv::from_config(&config).expect("container env"),
                |env, var| env.with_var(var.key(), var.value()),
            )
            .expect("explicit overrides");
        let environ: Vec<u8> = env
            .iter()
            .flat_map(|(k, v)| format!("{k}={v}\0").into_bytes())
            .collect();
        assert_eq!(environ, EXPECTED_ENVIRON);
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
        // 試験専用の証跡: この joiner は使い捨ての再入プロセスなので、補助グループが消えてもよい（#1532）。
        let proof = fandhe_container_core::exec::ExecWorkerProof::assume_for_test();
        let restrictions_for_a =
            prepare_restrictions(&proof, &a).expect("prepare restrictions for A");
        let b = identify_pid1(&record_b).expect("identify B");
        let cgroup_b = prepare_cgroup_join(&b).expect("prepare cgroup join for B");
        enter_namespaces(&b).expect("join B");
        join_cgroup(cgroup_b).expect("join B's cgroup");
        let err = reapply_restrictions(restrictions_for_a).expect_err("A's restrictions on B");
        assert_eq!(
            err.message(),
            "exec stage SetNs: the user or mount namespace after joining is not the one of the prepared \
             exec target (violation: exec_target/exec_joined_namespace_mismatch, SEC-1)"
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
    /// REPAIR-5）のうち、実行ファイルがプローブのものの pid。現行方式ではプローブ（host 側の `rootfs/probe`）と同じ
    /// inode、封印した複製では同じサイズの memfd（[`SEALED_COPY_EXE`]）を実行している（#1531）。
    fn probe_child(joiner: u32, probe: &Path) -> Option<u32> {
        let mut candidates = children_of(joiner);
        let grandchildren: Vec<u32> = candidates.iter().flat_map(|c| children_of(*c)).collect();
        candidates.extend(grandchildren);
        candidates
            .into_iter()
            .find(|pid| exe_mode(*pid, probe).is_some())
    }

    /// 封印した複製を実行しているプロセスの `/proc/<pid>/exe` のリンク先（#1531）。
    const SEALED_COPY_EXE: &str = "/memfd:fandhe-exec-entrypoint (deleted)";

    /// `pid` の実行ファイルが `probe` そのもの（`pinned_inode`）か、`probe` と同じサイズの封印した複製（`sealed_copy`）か。
    /// どちらでもなければ `None`。
    fn exe_mode(pid: u32, probe: &Path) -> Option<&'static str> {
        let want = fs::metadata(probe).ok()?;
        let exe = format!("/proc/{pid}/exe");
        let got = fs::metadata(&exe).ok()?;
        if (got.dev(), got.ino()) == (want.dev(), want.ino()) {
            return Some("pinned_inode");
        }
        let link = fs::read_link(&exe).ok()?;
        (link.to_string_lossy() == SEALED_COPY_EXE && got.len() == want.len())
            .then_some("sealed_copy")
    }

    /// joiner を起動する（標準出力は 1 行を読むためパイプ）。
    fn spawn_joiner(args: &[String]) -> Child {
        spawn_joiner_with_stderr(args, Stdio::null())
    }

    /// [`spawn_joiner`] に、構造化ログ（実行方式の 1 行。#1531）を受ける AF_UNIX の socket pair の読み端を足したもの。
    /// 診断ログは pipe・ファイルには出ず（待たない出力経路は socket にだけ送る。#1698）、joiner の stderr を
    /// socket にしたときだけ 1 行届く。
    fn spawn_joiner_logged(args: &[String]) -> (Child, std::os::unix::net::UnixStream) {
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let joiner = spawn_joiner_with_stderr(args, Stdio::from(std::os::fd::OwnedFd::from(tx)));
        (joiner, rx)
    }

    fn spawn_joiner_with_stderr(args: &[String], stderr: Stdio) -> Child {
        let exe = std::env::current_exe().expect("current_exe");
        Command::new(exe)
            .arg("--joiner")
            .args(args)
            // exec を起動する側だけが持つ環境変数（exec されたコマンドへ渡らないことを照合する。#1457）。
            .env(HOST_ONLY_ENV, "must-not-leak")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("spawn joiner")
    }

    /// joiner の終了を待ち、`(終了コード, 標準出力)` を返す。期限超過は kill して panic（REPAIR-5）。
    fn finish_joiner(joiner: Child) -> (Option<i32>, String) {
        let (code, out, _) = finish_joiner_with_stderr(joiner, None);
        (code, out)
    }

    /// [`finish_joiner`] に標準エラー出力（`log_rx` の socket から読む。無ければ空）を足したもの。
    fn finish_joiner_with_stderr(
        mut joiner: Child,
        log_rx: Option<std::os::unix::net::UnixStream>,
    ) -> (Option<i32>, String, String) {
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(s) = joiner.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                kill_and_reap(&mut joiner);
                panic!("joiner did not exit within {:?}", timeout());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut out = String::new();
        if let Some(mut s) = joiner.stdout.take() {
            let _ = std::io::Read::read_to_string(&mut s, &mut out);
        }
        let mut err = String::new();
        if let Some(mut s) = log_rx {
            // joiner は終了済みで書き手は閉じている。EOF に頼り切らず読み取りにも期限を付ける（REPAIR-5）。
            s.set_read_timeout(Some(timeout())).expect("read timeout");
            std::io::Read::read_to_string(&mut s, &mut err).expect("read joiner log socket");
        }
        (status.code(), out, err)
    }

    /// joiner の stderr から実行方式の構造化ログを取り出し、`(mode, reason)` を返す（1 行ちょうどでなければ panic）。
    /// 封印した複製の `reason` は空文字列。
    fn logged_entrypoint_mode(stderr: &str) -> (String, String) {
        const PREFIX: &str =
            r#"{"component":"supervisor.exec","operation":"entrypoint_mode","mode":""#;
        let lines: Vec<&str> = stderr.lines().filter(|l| l.starts_with(PREFIX)).collect();
        assert_eq!(
            lines.len(),
            1,
            "exactly one entrypoint_mode log line: {stderr}"
        );
        let rest = lines[0].strip_prefix(PREFIX).expect("prefix");
        let (mode, rest) = rest.split_once(r#"","reason":""#).expect("reason field");
        let reason = rest.strip_suffix(r#""}"#).expect("closing");
        (mode.to_owned(), reason.to_owned())
    }

    /// 1 回ぶんの通しの場面別の期待値（rootful と rootless で切り替える。#1887）。rootful は従来の照合を 1 つも
    /// 弱めない値で組み立てる（[`RoundExpect::rootful`]）。
    struct RoundExpect {
        /// プローブの `Groups:`（空白区切りを 1 つの空白に正規化した値）。
        groups: String,
        /// 結果の `groups=`（`SupplementaryGroups::as_str`）。
        groups_outcome: &'static str,
        /// pid1 と一致を照合する `ns/` の種類。
        namespaces: &'static [&'static str],
        /// rootless のときだけ `Some`。
        rootless: Option<RootlessExpect>,
    }

    /// rootless に固有の期待値。host の `/proc` から読む値は読み手（初期 user namespace）から見た値になる。
    struct RootlessExpect {
        /// orchestrator の euid / egid。`process.user` は 0:0 で、名前空間内の 0 が所有者へ写る。
        euid: u32,
        egid: u32,
        /// orchestrator の `ns/user` のリンク先（コンテナの user namespace とは異なる）。
        host_user_ns: String,
    }

    impl RoundExpect {
        /// rootful: `Groups:` は空、結果は `cleared` / `already_empty`、`ns/user` は照合しない（user namespace を作らない）。
        fn rootful() -> Self {
            Self {
                groups: String::new(),
                groups_outcome: expected_groups_outcome(),
                namespaces: &["mnt", "uts", "ipc", "net", "pid"],
                rootless: None,
            }
        }

        /// rootless: 所有者は初期 user namespace で `CAP_SETGID` を持たず、参加先は `setgroups` が `deny` のため、
        /// 補助グループは joiner のまま（結果は `kept_setgroups_denied`、無ければ `already_empty`。`exec/reapply.rs`・#1457・#1462）。
        fn rootless() -> Self {
            let status = fs::read_to_string("/proc/self/status").expect("own status");
            let groups = normalize_ws(&status_field(&status, "Groups:"));
            let (euid, egid) = own_status_ids();
            Self {
                groups_outcome: if groups.is_empty() {
                    "already_empty"
                } else {
                    "kept_setgroups_denied"
                },
                groups,
                namespaces: &["user", "mnt", "uts", "ipc", "net", "pid"],
                rootless: Some(RootlessExpect {
                    euid,
                    egid,
                    host_user_ns: link("/proc/self/ns/user"),
                }),
            }
        }
    }

    /// 空白区切りの値を 1 つの空白に正規化する。
    fn normalize_ws(v: &str) -> String {
        v.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// 自プロセスの `(euid, egid)`（`/proc/self/status` の `Uid:` / `Gid:` の 2 番目）。
    fn own_status_ids() -> (u32, u32) {
        let status = fs::read_to_string("/proc/self/status").expect("own status");
        let second = |name: &str| -> u32 {
            status_field(&status, name)
                .split_whitespace()
                .nth(1)
                .unwrap_or_else(|| panic!("{name} effective id missing"))
                .parse()
                .unwrap_or_else(|_| panic!("{name} effective id"))
        };
        (second("Uid:"), second("Gid:"))
    }

    /// 1 回ぶんの通し: `run_command` で参加・制限・exec し、稼働中のプローブをホスト側の `/proc` から観測する。
    fn one_round(
        bundle: &Bundle,
        c: &Container,
        round: u32,
        original_cgroup: &str,
        expect: &RoundExpect,
    ) {
        clean_probe_files(bundle);
        let probe = bundle.rootfs().join(PROBE);
        let scope = own_cgroup_path();
        let (joiner, log_rx) = spawn_joiner_logged(&[
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
        // 稼働中に、どちらの方式の実行ファイルかを記録する（joiner の結果と後で突き合わせる。#1531）。
        let exe_seen = exe_mode(pid, &probe);
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
        // TASK-163 追補（#1457）: コマンドの環境はコンテナ定義と明示の上書きだけで、joiner の環境（対照として
        // joiner 自身は `HOST_ONLY_ENV` を持つ）は 1 つも渡らない。補助グループは空（launch と同じ扱い）。
        let joiner_environ = fs::read(format!("/proc/{jpid}/environ")).expect("joiner environ");
        assert!(
            joiner_environ
                .split(|b| *b == 0)
                .any(|v| v.starts_with(HOST_ONLY_ENV.as_bytes())),
            "the joiner must carry the host-only variable; {ctx}"
        );
        assert_eq!(
            fs::read(format!("/proc/{pid}/environ")).expect("probe environ"),
            EXPECTED_ENVIRON,
            "{ctx}"
        );
        assert_eq!(
            normalize_ws(&status_field(&status, "Groups:")),
            expect.groups,
            "{ctx}"
        );
        // namespace は pid1 と一致する（pid は参加後に fork した子の値）。rootless は user namespace も含む。
        for ns in expect.namespaces {
            assert_eq!(
                link(&format!("/proc/{pid}/ns/{ns}")),
                link(&format!("/proc/{}/ns/{ns}", c.pid1)),
                "{ns} {ctx}"
            );
        }
        if let Some(r) = &expect.rootless {
            // SEC-1・SEC-5: capability の値はコンテナの user namespace に対する権限で、host に対する権限ではない。
            // コマンドの user namespace は orchestrator（初期 user namespace）と異なり、名前空間内の 0 が所有者へ写る。
            assert_ne!(
                link(&format!("/proc/{pid}/ns/user")),
                r.host_user_ns,
                "the command must be in the container's user namespace; {ctx}"
            );
            let uid = format!("{0} {0} {0} {0}", r.euid);
            let gid = format!("{0} {0} {0} {0}", r.egid);
            assert_eq!(normalize_ws(&status_field(&status, "Uid:")), uid, "{ctx}");
            assert_eq!(normalize_ws(&status_field(&status, "Gid:")), gid, "{ctx}");
            for (file, host_id) in [("uid_map", r.euid), ("gid_map", r.egid)] {
                let map = |p: u32| {
                    normalize_ws(
                        &fs::read_to_string(format!("/proc/{p}/{file}"))
                            .unwrap_or_else(|e| panic!("read {file} of {p}: {e}")),
                    )
                };
                assert_eq!(map(pid), format!("0 {host_id} 1"), "{file} {ctx}");
                assert_eq!(map(pid), map(c.pid1), "{file} equals pid1's; {ctx}");
            }
        }
        // cgroup: コマンドはコンテナ用 cgroup の直下の exec 用の子 cgroup（`exec-<nonce>` の 1 要素。#1466）に
        // いて、joiner が元いた cgroup と異なる。通しの後に子 cgroup は削除済み（コンテナ cgroup 直下に残らない）。
        let cgroup = cgroup_of(&pid.to_string());
        let child = cgroup
            .strip_prefix(&format!("{}/", c.cgroup_path))
            .unwrap_or_else(|| panic!("{cgroup} is not under {} {ctx}", c.cgroup_path));
        assert!(
            child.starts_with("exec-") && !child.contains('/'),
            "{child} {ctx}"
        );
        assert_ne!(cgroup, original_cgroup, "{ctx}");
        // rlimit は launch 時の記録と同じ（#1467）。pid1 は launch の後に NOFILE の soft を 1400 へ上げているが、
        // exec は記録の 700 を適用する。他の 15 種は launch の継承値（記録）で、pid1 の値と一致する。
        let lines = limit_lines(pid);
        assert_eq!(lines.len(), 16, "{ctx}");
        let pid1_lines = limit_lines(c.pid1);
        assert!(
            pid1_lines.contains(&"Max open files 1400 1500 files".to_owned()),
            "pid1's NOFILE soft limit must have been raised after launch: {pid1_lines:?}; {ctx}"
        );
        assert!(
            lines.contains(&"Max open files 700 1500 files".to_owned()),
            "the recorded launch NOFILE must be applied, not pid1's current value: {lines:?}; {ctx}"
        );
        let others = |v: &[String]| -> Vec<String> {
            v.iter()
                .filter(|l| !l.starts_with("Max open files"))
                .cloned()
                .collect()
        };
        assert_eq!(others(&lines), others(&pid1_lines), "{ctx}");
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
            "setns allowed; {ctx}"
        );
        assert!(denied.exists(), "setns must be EPERM; {ctx}");

        // プローブを止める（親は worker。数値 pid へ送るのは、worker が回収するまで再利用されない子のみ）。
        let killed = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .spawn()
            .expect("run kill");
        // 期限つきで待つ（REPAIR-5）。
        assert_eq!(finish_joiner(killed).0, Some(0), "{ctx}");
        let (code, out, err) = finish_joiner_with_stderr(joiner, Some(log_rx));
        assert_eq!(code, Some(0), "joiner output: {out}; stderr: {err}; {ctx}");
        // 実行方式（#1531）: ログ・`ExecOutcome`・実行中のプローブの `exe` が同じ方式を示す。どちらの方式でも成功する。
        let (mode, reason) = logged_entrypoint_mode(&err);
        let outcome_reason = if reason.is_empty() {
            "-"
        } else {
            reason.as_str()
        };
        assert_eq!(
            out.trim_end(),
            format!(
                "outcome exit={:?} rlimits=15 rlimits_deferred=1 caps_dropped={} landlock_rules=5 seccomp_instructions={} groups={} entrypoint_mode={mode} reason={outcome_reason} seccomp_listener=verified",
                ExecExit::Command(ChildExit::Signaled(15)),
                parse_after(&out, "caps_dropped="),
                parse_after(&out, "seccomp_instructions="),
                expect.groups_outcome,
            ),
            "{ctx}"
        );
        assert_eq!(exe_seen, Some(mode.as_str()), "{ctx}");
        match mode.as_str() {
            "sealed_copy" => assert_eq!(reason, "", "{ctx}"),
            "pinned_inode" => assert!(!reason.is_empty(), "pinned_inode needs a reason; {ctx}"),
            other => panic!("unknown entrypoint mode {other}; {ctx}"),
        }
    }

    /// 補助グループの扱いの期待値。joiner は本プロセス（root）と同じ補助グループを持つため、本プロセスが
    /// 補助グループを持てば `cleared`（`setgroups(0)` で消去）、持たなければ `already_empty`。
    ///
    /// 消去は namespace へ参加する **前**（準備の最後）に行われ、参加後の capability 削減は「元から空」になるが、
    /// 結果には参加前の消去（`cleared`）が残る（root 起動の exec が起動者のホスト側の補助グループをコンテナへ
    /// 持ち込まないことの照合。TASK-163 追補・#1457。プローブの `Groups:` が空であることは `one_round` が照合する）。
    fn expected_groups_outcome() -> &'static str {
        let status = fs::read_to_string("/proc/self/status").expect("own status");
        if status_field(&status, "Groups:").is_empty() {
            "already_empty"
        } else {
            "cleared"
        }
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
    ///
    /// `rootless` のときは `start_container_as` と同じ構成（`--user --map-root-user ... --net`）で `sleep` を起動する。
    /// `--net` が要るのは、user namespace へ参加した後は初期 user namespace が所有する netns へ `setns` できないため。
    /// 照合の順序は rootful と同じで、最初に落ちるのは参加後の `/` の照合（`exec_root_not_container_rootfs`）。
    fn unpivoted_target_is_rejected(bundle: &Bundle, rootless: bool) {
        clean_probe_files(bundle);
        let unshare_args: &[&str] = if rootless {
            &[
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
                "sleep",
                "60",
            ]
        } else {
            &[
                "--pid",
                "--fork",
                "--kill-child",
                "--mount",
                "--uts",
                "--ipc",
                "sleep",
                "60",
            ]
        };
        let unshare = Command::new("unshare")
            .args(unshare_args)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare");
        let unshare_pid = unshare.id();
        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                kill_and_reap(&mut self.0);
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
             rootfs (violation: exec_target/exec_root_not_container_rootfs, SEC-1)\n\
             audit: delivery=Recorded records=1 layer=exec_target \
             reason=exec_root_not_container_rootfs path=none"
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
    /// 拒否が Landlock（ルール外のバイナリの実行拒否）ではなくインタープリタの照合によることは、結果に付く違反の
    /// 理由で確かめる（非特権で動く core の `tests/exec_child_setup.rs` も、Landlock を適用しない子で同じ入力の
    /// 拒否を照合している）。
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
        // 拒否の理由がインタープリタの照合（違反 `entrypoint_interpreter_is_runtime_binary`）であること。Landlock が
        // `execveat` を拒否した場合は違反の理由が付かない（`violation: None`）ため、ここで区別できる（#1460）。
        assert!(
            out.starts_with(&format!(
                "outcome exit={:?} ",
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointInterpreterIsRuntimeBinary),
                    code: ErrorCode::PermissionDenied,
                }
            )),
            "the exec child must refuse the runtime-interpreted script: {out}"
        );
        // 拒否は層 `entrypoint` で 1 件記録され、パスは載らない（#1595）。
        assert!(
            out.contains(
                "audit: delivery=Recorded records=1 layer=entrypoint \
                 reason=entrypoint_interpreter_is_runtime_binary path=none"
            ),
            "the setup rejection must be audited once: {out}"
        );
        assert!(
            probe_child(jpid, &std::env::current_exe().expect("current_exe")).is_none(),
            "the runtime binary must not be running as the script interpreter"
        );
    }

    /// TASK-163 追補（#1459・SEC-1・SEC-4）: コンテナの `/dev/null` が symlink・別のデバイスノード（1:5）へ
    /// 差し替えられていたら、exec の子は差し替え先を開かずに拒否し、コマンドは起動しない（終了コード 126）。
    ///
    /// コンテナの `/dev` は pid1 が `create_default_devices` で載せた tmpfs（#1653）で、ホスト側の rootfs の
    /// `dev/` ではない。ホストからは `/proc/<pid1>/root/dev` で到達できるので、そこで差し替える（コンテナが
    /// `CAP_MKNOD` で行う差し替えと同じ結果になる）。照合の前に必ず元へ戻す。
    fn replaced_dev_null_is_rejected(bundle: &Bundle, c: &Container) {
        let pid1_root = PathBuf::from(format!("/proc/{}/root", c.pid1));
        let null = pid1_root.join("dev/null");
        let saved = pid1_root.join("dev/null.saved");
        for kind in ["symlink", "device"] {
            clean_probe_files(bundle);
            fs::rename(&null, &saved).expect("move the real /dev/null aside");
            let replaced = match kind {
                "symlink" => std::os::unix::fs::symlink("zero", &null).is_ok(),
                // 期限つきで待つ（外部コマンドの待ちで固まらない。REPAIR-5）。
                _ => Command::new("mknod")
                    .arg(&null)
                    .args(["c", "1", "5"])
                    .stdin(Stdio::null())
                    .spawn()
                    .is_ok_and(|child| finish_joiner(child).0 == Some(0)),
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
            // コマンドは起動しておらず（終了コードではなく pipe の報告で区別する。#1460）、違反の理由が届く。
            assert!(
                out.starts_with(&format!(
                    "outcome exit={:?} ",
                    ExecExit::SetupFailed {
                        exit: ChildExit::Exited(126),
                        violation: Some(ViolationReason::StdioNullNotNullDevice),
                        code: ErrorCode::PermissionDenied,
                    }
                )),
                "the exec child must refuse the replaced /dev/null ({kind}): {out}"
            );
            assert!(
                out.contains(
                    "audit: delivery=Recorded records=1 layer=entrypoint \
                     reason=stdio_null_not_null_device path=none"
                ),
                "the setup rejection must be audited once ({kind}): {out}"
            );
            assert!(
                !bundle.rootfs().join("data/ok").exists(),
                "the command must not have started ({kind})"
            );
        }
    }

    /// rootless 版の `/dev/null` 差し替え（#2443・#1459・SEC-1・SEC-4）。照合は [`replaced_dev_null_is_rejected`] と同じ
    /// 具体値（`StdioNullNotNullDevice`・層 `entrypoint`・`data/ok` 無し）。
    ///
    /// rootful と手段が違う理由（経路ごと）:
    /// - ホストからの `rename`: rootless の `/dev/null` はホストのノードの bind（`DeviceSupply::BindFromHost`）で、
    ///   マウントポイントのため `EBUSY` になる
    /// - ホストからの `umount`: orchestrator は初期 user namespace にいて、コンテナの mount namespace を外せない
    /// - `nsenter -m` で入る: pivot 後の rootfs に `umount` / `ln` が無い
    /// - `mknod c 1 5`: user namespace 内では `EPERM`。別のデバイスノードへの差し替えは `/dev/zero`（1:5）の bind で再現する
    ///
    /// そのため種類ごとに使い捨てのコンテナを、pid1 が pivot の前に差し替える形（[`Tamper`]）で起動する。
    /// 使い捨てなので元へ戻さず、drop で破棄する。
    fn replaced_dev_null_is_rejected_rootless(bundle: &Bundle) {
        for (kind, tamper, instance) in [
            ("symlink", Tamper::Symlink, 4000_u64),
            ("device", Tamper::BindZero, 4001_u64),
        ] {
            clean_probe_files(bundle);
            let c = start_container_with(
                bundle,
                &format!("t{instance}"),
                instance,
                true,
                Some(tamper),
            );
            let joiner = spawn_joiner(&[
                "run".into(),
                bundle.dir.display().to_string(),
                own_cgroup_path(),
                instance.to_string(),
                c.pid1.to_string(),
            ]);
            let (code, out) = finish_joiner(joiner);
            drop(c);
            assert_eq!(code, Some(0), "joiner output: {out}; {kind}");
            assert!(
                out.starts_with(&format!(
                    "outcome exit={:?} ",
                    ExecExit::SetupFailed {
                        exit: ChildExit::Exited(126),
                        violation: Some(ViolationReason::StdioNullNotNullDevice),
                        code: ErrorCode::PermissionDenied,
                    }
                )),
                "the exec child must refuse the replaced /dev/null ({kind}): {out}"
            );
            assert!(
                out.contains(
                    "audit: delivery=Recorded records=1 layer=entrypoint \
                     reason=stdio_null_not_null_device path=none"
                ),
                "the setup rejection must be audited once ({kind}): {out}"
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
            "this scenario needs root (rootful pivot_root, cgroup v2 writes); for the non-root scenario run with `--ignored --rootless` (see AGENTS.md)"
        );
        let bundle = make_bundle();
        verify_bundle_definition(&bundle);
        verify_probe_on_host(&bundle);
        let original_cgroup = own_cgroup_path();

        let a = start_container(&bundle, "a", 1000);
        // 5 回の通し（本番の `identify_pid1` 経路。記録の cgroup 配置から期待 cgroup を導く）。
        for round in 1..=ROUNDS {
            one_round(
                &bundle,
                &a,
                round,
                &original_cgroup,
                &RoundExpect::rootful(),
            );
            // #1466: 通しの後に exec 用の子 cgroup は削除済み（コンテナ cgroup 直下に残らない）。
            let left: Vec<String> = fs::read_dir(&a.cgroup_dir)
                .expect("read the container cgroup")
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.starts_with("exec-"))
                .collect();
            assert_eq!(left, Vec::<String>::new(), "round {round}");
        }
        // 拒否経路（TASK-163 追補）: `/dev/null` の差し替え（#1459）・インタープリタ経由のランタイム実行（#1458）。
        replaced_dev_null_is_rejected(&bundle, &a);
        runtime_interpreter_script_is_rejected(&bundle, &a);
        // 拒否経路（条件 3・4(d)）。
        let b = start_container(&bundle, "b", 2000);
        other_container_is_rejected(&bundle, &a, &b);
        drop(b);
        unpivoted_target_is_rejected(&bundle, false);
        println!("exec: {ROUNDS}/{ROUNDS} exec verified");
    }

    /// 検証できない環境を知らせて終了する（`exit 2`。成功を装わない。rootless の事前検査用）。
    fn not_verified(reason: &str) -> ! {
        eprintln!("exec: not verified (rootless): {reason}");
        std::process::exit(2);
    }

    /// rootless の場面の事前検査（副作用の前。満たさなければ `exit 2`）。この後の不一致はすべて試験の失敗とする。
    fn rootless_preconditions() {
        let (euid, _) = own_status_ids();
        if euid == 0 {
            not_verified(
                "running as root; use the rootful scenario (`--ignored` without `--rootless`)",
            );
        }
        let proc_sys = |p: &str| fs::read_to_string(p).ok().map(|v| v.trim().to_owned());
        if proc_sys("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref()
            == Some("1")
        {
            not_verified(
                "kernel.apparmor_restrict_unprivileged_userns=1 forbids unprivileged user namespaces",
            );
        }
        if proc_sys("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
            not_verified("user.max_user_namespaces=0");
        }
        // 実際に試す（期限つき。REPAIR-5）。
        let probe = Command::new("unshare")
            .args(["--user", "--map-root-user", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match probe {
            Ok(child) => {
                if finish_joiner(child).0 != Some(0) {
                    not_verified(
                        "an unprivileged user namespace cannot be created (`unshare --user --map-root-user`)",
                    );
                }
            }
            Err(e) => not_verified(&format!("cannot run `unshare` (util-linux): {e}")),
        }
        if let Err(e) = fandhe_container_core::landlock::detect_landlock_abi() {
            not_verified(&format!("Landlock ABI 6+ is required (Linux 6.12+): {e}"));
        }
        if let Err(e) = fandhe_container_core::cgroups::DelegatedCgroup::detect() {
            not_verified(&format!(
                "not inside a delegated cgroup v2 (run under `systemd-run --user --scope -p Delegate=yes`): {e}"
            ));
        }
        let own = own_cgroup_path();
        let kill = PathBuf::from(format!("/sys/fs/cgroup{own}")).join("cgroup.kill");
        if !kill.exists() {
            not_verified("cgroup.kill is missing in the own cgroup (Linux 5.14+ is required)");
        }
        let prlimit = Command::new("prlimit")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .ok()
            .map(|child| finish_joiner(child).0);
        if prlimit != Some(Some(0)) {
            not_verified("`prlimit` (util-linux) is not available");
        }
        // `/dev/null` の差し替え（pid1 が pivot の前に行う。#2443）に使う。
        for tool in ["mount", "umount"] {
            let ok = Command::new(tool)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .ok()
                .map(|child| finish_joiner(child).0);
            if ok != Some(Some(0)) {
                not_verified(&format!("`{tool}` (util-linux) is not available"));
            }
        }
        // 削減後の期待値（OCI 既定集合）が成り立つには、joiner の bounding set がそれを含む必要がある。
        let status = fs::read_to_string("/proc/self/status").expect("own status");
        let bnd = u64::from_str_radix(&status_field(&status, "CapBnd:"), 16).expect("CapBnd");
        let want = u64::from_str_radix(OCI_DEFAULT_CAPS, 16).expect("default caps");
        if bnd & want != want {
            not_verified("the bounding set does not contain the OCI default capability set");
        }
    }

    /// rootless の場面（`--ignored --rootless`。#1887・SUP-6・SEC-1・SEC-5・CORE-5・CORE-6・REPAIR-12）。
    ///
    /// 分離の理由: 非 root・非特権 user namespace・Landlock ABI 6+・委譲 cgroup v2・x86_64 を要し、GitHub ホステッド
    /// runner では保証できない。環境が揃わないときは [`rootless_preconditions`] が `exit 2` で「検証していない」ことを
    /// 知らせる。成功経路の 5 回のあと、拒否経路 4 つ（インタープリタ経由・別コンテナ・pivot していない対象・
    /// `/dev/null` の差し替え。#2443）も rootful と同じ違反の理由で照合する。
    fn orchestrate_rootless() {
        rootless_preconditions();
        let bundle = make_bundle();
        verify_bundle_definition(&bundle);
        verify_probe_on_host(&bundle);
        let original_cgroup = own_cgroup_path();

        let a = start_container_as(&bundle, "a", 1000, true);
        for round in 1..=ROUNDS {
            one_round(
                &bundle,
                &a,
                round,
                &original_cgroup,
                &RoundExpect::rootless(),
            );
            // #1466: 通しの後に exec 用の子 cgroup は削除済み。
            let left: Vec<String> = fs::read_dir(&a.cgroup_dir)
                .expect("read the container cgroup")
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.starts_with("exec-"))
                .collect();
            assert_eq!(left, Vec::<String>::new(), "round {round}");
        }
        // 拒否経路（#2443）。違反の理由・監査の要約は rootful と同じ具体値で照合する。
        runtime_interpreter_script_is_rejected(&bundle, &a);
        let b = start_container_as(&bundle, "b", 2000, true);
        other_container_is_rejected(&bundle, &a, &b);
        drop(b);
        unpivoted_target_is_rejected(&bundle, true);
        replaced_dev_null_is_rejected_rootless(&bundle);
        println!("exec: {ROUNDS}/{ROUNDS} rootless exec verified");
    }
}
