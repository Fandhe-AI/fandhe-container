//! Landlock の拒否が exec 後もカーネル監査へ届くことの実機前提の結合試験（SEC-4・CORE-5・#2026・#2291）。
//!
//! 本番の適用経路（`observe_landlock_path_access` 経由の `landlock_ruleset_from_config` → `apply_landlock_stage`。
//! ABI 7 以上なら `landlock_restrict_self` へ `LOG_NEW_EXEC_ON` を渡す）を使い捨ての子プロセスで適用し、その子から
//! `execve` した `/bin/sh` に許可外ディレクトリへのファイル作成を試みさせる。作成が `EACCES` で拒否されることと、
//! ホストの audit ログ（`/var/log/audit/audit.log`）に、その拒否の `LANDLOCK_ACCESS` レコード（`blockers=fs.make_reg`・
//! 試験専用ディレクトリの名前つき）が出ることを具体値で照合する。
//!
//! # 実機前提の理由
//!
//! - Landlock ABI 7 以上（Linux 6.15 以降）: 監査のログ制御フラグを渡せる最小の ABI
//! - カーネル監査の記録先（auditd 等）が有効で、`/var/log/audit/audit.log` を読める権限（通常は root か audit グループ）
//!
//! GitHub ホステッド runner は満たせないため既定のテスト集合から分離している（CI 通過のための弱体化ではない）。
//! 適用は不可逆・単一スレッド前提のため libtest ではなく `harness = false` の `main` で動かし、親は子と audit ログの
//! 待ちにタイムアウトを設ける（REPAIR-5）。
//!
//! # 実行モード
//!
//! - 既定（`cargo test`）: 前提を要する旨を出力して成功終了する（実機前提テストの分離。検証はしない）
//! - `-- --ignored`: 前提（ABI 7 以上・audit ログの可読）が欠けると skip ではなく非ゼロで失敗する。実行:
//!   `sudo cargo test -p fandhe-container-core --test landlock_audit_exec -- --ignored`
//!   （Agent は root 権限のコマンドを実行しない。実機での実行と結果の記録は人間担当の #2306 で追跡する）

#[path = "support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("landlock_audit_exec: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("landlock_audit_exec: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    use fandhe_container_core::exec::observe_landlock_path_access;
    use fandhe_container_core::landlock::{MIN_LANDLOCK_AUDIT_ABI, detect_landlock_abi};
    use fandhe_container_core::oci_runtime::parse_config_bytes;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const AUDIT_LOG: &str = "/var/log/audit/audit.log";
    const MARKER: &str = "audit-marker";

    fn create_unique_dir(base: &Path) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("read /dev/urandom");
        let dir = base.join(format!(
            "fandhe-landlock-audit-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(buf)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create unique probe dir");
        dir
    }

    /// 子: 本番の適用経路で適用し、exec した sh に許可外ディレクトリへの作成を試みさせる。
    fn run_child(dir: &Path) {
        let allowed = dir.join("allowed");
        let allowed_json = format!("{:?}", allowed.to_str().expect("utf8 path"));
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":true}},"mounts":[{{"destination":{allowed_json},"options":["rw"]}}]}}"#
        );
        let cfg = parse_config_bytes(json.as_bytes()).expect("valid config");
        // sh の stderr は適用前に開いた一時ファイルへ向ける（fd は Landlock の対象外）。この段は適用後の単一スレッド
        // 前提を保つため、読み手スレッドを立てる `output_within` ではなく `run_within` を使う（REPAIR-5・#3409）。
        let mut err_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("allowed").join("sh-stderr"))
            .expect("open sh stderr file");
        let sh_stderr = err_file.try_clone().expect("clone stderr file");
        let o = observe_landlock_path_access(&cfg, &[]).expect("observe");
        assert!(o.ruleset_error.is_none(), "{:?}", o.ruleset_error);
        assert!(o.apply_error.is_none(), "{:?}", o.apply_error);
        assert!(o.applied, "landlock must be applied");
        let mut sh = Command::new("/bin/sh");
        sh.arg("-c")
            .arg(": > \"$1\"")
            .arg("sh")
            .arg(dir.join("denied").join(MARKER))
            // strerror の文言はロケールに従うため C に固定する（非英語ロケールでの誤失敗を防ぐ）。
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdout(Stdio::null())
            .stderr(Stdio::from(sh_stderr));
        let status = crate::reap::run_within(&mut sh, crate::reap::REAP_WITHIN)
            .unwrap_or_else(|e| panic!("exec'd sh: {e}"));
        let mut stderr = String::new();
        err_file
            .seek(SeekFrom::Start(0))
            .and_then(|_| err_file.read_to_string(&mut stderr))
            .expect("read sh stderr");
        assert!(
            !status.success() && stderr.contains("Permission denied"),
            "exec'd sh must be denied by landlock: status={status} stderr={stderr}",
        );
        assert!(!dir.join("denied").join(MARKER).exists());
        println!("landlock_audit_exec child: ok");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child-exec") {
        let dir = args
            .iter()
            .position(|a| a == "--probe-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .expect("--probe-dir");
        run_child(&dir);
        return;
    }

    if !args.iter().any(|a| a == "--ignored") {
        println!(
            "landlock_audit_exec: ignored (needs Landlock ABI {MIN_LANDLOCK_AUDIT_ABI}+ and a readable {AUDIT_LOG}; run with -- --ignored)"
        );
        return;
    }

    // 前提の検査（欠けたら skip ではなく失敗）。
    let support = detect_landlock_abi().expect("landlock must be available");
    assert!(
        support.abi.get() >= MIN_LANDLOCK_AUDIT_ABI,
        "needs Landlock ABI {MIN_LANDLOCK_AUDIT_ABI}+, detected {}",
        support.abi.get()
    );
    let mut log =
        std::fs::File::open(AUDIT_LOG).expect("audit log must be readable (auditd + permission)");
    let start = log.seek(SeekFrom::End(0)).expect("seek audit log");

    let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
    let dir = create_unique_dir(&base);
    for sub in ["allowed", "denied"] {
        std::fs::create_dir(dir.join(sub)).expect("create probe subdir");
    }
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .expect("utf8 dir name")
        .to_owned();
    let exe = std::env::current_exe().expect("current_exe");
    let mut child_cmd = Command::new(&exe);
    child_cmd.args(["--child-exec", "--probe-dir"]).arg(&dir);
    // spawn・期限・出力回収を一括で期限つきにする。孫が pipe を持ち続けても戻る（REPAIR-5・#3409）。
    let out = match crate::reap::output_within(&mut child_cmd, Duration::from_secs(30)) {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            panic!("landlock_audit_exec child: {e}");
        }
    };
    let status = out.status;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        status.success() && stdout.contains("landlock_audit_exec child: ok"),
        "child failed ({status}): {stdout}\n{stderr}"
    );

    // 子の拒否より後に追記された audit ログから、試験専用ディレクトリの名前つきの LANDLOCK_ACCESS を待つ。
    let mut found: Option<String> = None;
    let poll_deadline = Instant::now() + Duration::from_secs(10);
    while found.is_none() && Instant::now() < poll_deadline {
        let mut log = std::fs::File::open(AUDIT_LOG).expect("reopen audit log");
        log.seek(SeekFrom::Start(start)).expect("seek audit log");
        let mut text = String::new();
        log.read_to_string(&mut text).expect("read audit log");
        found = text
            .lines()
            .find(|l| l.contains("type=LANDLOCK_ACCESS") && l.contains(&dir_name))
            .map(str::to_owned);
        if found.is_none() {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let line = found.unwrap_or_else(|| {
        panic!("no LANDLOCK_ACCESS record for {dir_name} in {AUDIT_LOG} after the exec'd denial")
    });
    assert!(
        line.contains("blockers=fs.make_reg"),
        "unexpected record: {line}"
    );
    println!("landlock_audit_exec: ok");
}
