//! user namespace UID/GID 写像（`fandhe_container_core::rootless`）の結合試験
//! （CORE-6・SEC-5・TASK-40.1・#187）。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` になるため
//! `harness = false` の単一スレッド `main` で動かす（`unshare_isolation` と同じ理由）。
//! 非 Linux では `rootless` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 流れ
//! - 親: 自身を `--child` で起動 → 子の `ready` 行をタイムアウト付きで待つ → 子 pid に写像を設定
//!   （`Direct`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` のときは `newuidmap` / `newgidmap` 経由の
//!   範囲写像も追加で検証）→ `uid_map` を具体値で照合 → 親から見た子の実 UID が非特権（≠0）を照合 →
//!   子へ継続を通知し、終了コード 0 をタイムアウト付きで待つ（REPAIR-5）
//! - 子: `unshare_user_namespace` → `ready` を出力 → 継続を待つ → 自分の UID が 0 であることを照合
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等では `PermissionDenied`）。
//! `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（ci.md
//! 「実機前提テスト」）。CI の `platform-ci` への組み込みは別 PR（ci.yml は infra-builder 担当）。
//! 実行された場合は拒否を含むあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。
//! Helper ケースは env の opt-in 時のみ実行し、opt-in 時に前提（uidmap・subuid/subgid 行）が
//! 無ければ失敗とする。root で実行された場合は euid 0 の自 ID 写像が SEC-5 で拒否されることを照合する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_id_map: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "rootless_id_map: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::IdMapping;
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdKind, IdMapSet, IdMapWriter, SubIdOwner, TargetPid,
        apply_id_maps, load_subordinate_ids, read_id_map, rootless_mapping, single_id_mapping,
        unshare_user_namespace,
    };

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// `/proc/<pid>/status` の `Uid:` 行の実 UID（第 1 値）。
    fn status_uid(pid: &str) -> u32 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .expect("parse Uid")
    }

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

    pub fn run() {
        if std::env::args().any(|a| a == "--child") {
            child();
            return;
        }
        let (euid, egid) = own_ids();
        if euid == 0 {
            // SEC-5: root の自 ID 写像（コンテナ root = ホスト root）は拒否される。
            let e = single_id_mapping(0).expect_err("host root mapping must be rejected");
            assert_eq!(e.code.as_str(), "PERMISSION_DENIED");
            println!("rootless_id_map: host root mapping rejected (SEC-5, root=true)");
            return;
        }
        let uid = single_id_mapping(euid).expect("uid mapping");
        let gid = single_id_mapping(egid).expect("gid mapping");
        run_case(&uid, &gid, &IdMapWriter::Direct, euid);
        println!("rootless_id_map: container root mapped to host uid {euid} (writer=direct)");

        if std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1") {
            let name = std::env::var("USER").ok();
            let uowner = SubIdOwner::new(euid, name.clone()).expect("uid owner");
            let gowner = SubIdOwner::new(euid, name).expect("gid owner");
            let uranges =
                load_subordinate_ids(Path::new("/etc/subuid"), &uowner).expect("load /etc/subuid");
            let granges =
                load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
            assert!(
                !uranges.is_empty() && !granges.is_empty(),
                "helper case requires subuid/subgid entries for the current user"
            );
            let uid = rootless_mapping(euid, &uranges).expect("uid range mapping");
            let gid = rootless_mapping(egid, &granges).expect("gid range mapping");
            assert!(uid.entries().len() >= 2);
            let helper = IdMapWriter::Helper(HelperPaths::system_default().expect("helpers"));
            run_case(&uid, &gid, &helper, euid);
            println!("rootless_id_map: range mapping via helper verified (writer=helper)");
        } else {
            println!(
                "rootless_id_map: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
    }

    fn run_case(uid: &IdMapSet, gid: &IdMapSet, writer: &IdMapWriter, euid: u32) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let result = drive(&mut child, uid, gid, writer, euid);
        if result.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
        if let Err(msg) = result {
            panic!("{msg}");
        }
    }

    fn drive(
        child: &mut Child,
        uid: &IdMapSet,
        gid: &IdMapSet,
        writer: &IdMapWriter,
        euid: u32,
    ) -> Result<(), String> {
        let stdout = child.stdout.take().ok_or("no child stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(timeout())
            .map_err(|_| "child did not become ready in time".to_string())?;
        if line.trim() != "ready" {
            return Err(format!("unexpected child output: {line:?}"));
        }
        let pid = TargetPid::new(child.id()).map_err(|e| e.to_string())?;
        let report = apply_id_maps(pid, uid, gid, writer, DEFAULT_HELPER_TIMEOUT)
            .map_err(|e| e.to_string())?;
        assert_eq!(&report.uid, uid);
        let got = read_id_map(pid, IdKind::Uid).map_err(|e| e.to_string())?;
        assert_eq!(
            got.first(),
            Some(&IdMapping {
                container_id: 0,
                host_id: euid,
                count: 1
            })
        );
        assert_eq!(got, uid.entries());
        // 受け入れ基準: コンテナ内 root はホスト側では非特権 UID に写る。
        assert_eq!(uid.host_id_of(0), Some(euid));
        assert_ne!(status_uid(&pid.get().to_string()), 0);
        assert_eq!(status_uid(&pid.get().to_string()), euid);
        let mut stdin = child.stdin.take().ok_or("no child stdin")?;
        stdin.write_all(b"go\n").map_err(|e| e.to_string())?;
        drop(stdin);
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(s) if s.code() == Some(0) => return Ok(()),
                Some(s) => return Err(format!("child failed: {s}")),
                None if Instant::now() >= deadline => return Err("child did not exit".into()),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn child() {
        unshare_user_namespace().expect("unshare user namespace");
        println!("ready");
        let _ = std::io::stdout().flush();
        let mut go = String::new();
        std::io::stdin().read_line(&mut go).expect("read go");
        assert_eq!(go.trim(), "go");
        let (uid, _) = own_ids();
        assert_eq!(uid, 0, "container root must be uid 0 inside the namespace");
    }
}
