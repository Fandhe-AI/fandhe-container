//! rootless の user namespace の中でのレイヤー展開（`OwnershipPolicy::ChownInUserNamespace`）の実機前提試験
//! （OCI-2・SEC-5・#2382）。
//!
//! `harness = false`（単一スレッドの独自 `main`）。`-- --ignored` を付けたときだけ実行し、付けなければ
//! 何もせず成功する（既定のテスト集合に実機前提を混ぜない。AGENTS.md「実機前提テスト」）。
//!
//! 構成: 外側（初期 user namespace・非 root）が `unshare --user --map-root-user` で自分自身を `--case <名前>` つきで
//! 再起動する。子は単一スレッドの新しいプロセスで、ホストの euid / egid が namespace の中の 0 に写っている
//! （単一行の写像）。子が公開 API で展開し、外側がホストから見た所有者・mode を確かめる。
//! 前提: 非特権 user namespace を作れること・util-linux の `unshare`・非 root での実行。満たさなければ
//! 成功を装わず失敗する。
//!
//! 未検証の範囲: `newuidmap` による範囲写像（subuid）での展開は本試験の対象外（core の rootless_file_owner 相当の
//! 配線が要る。#2315）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("userns_extract: not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_oci::error::OciErrorCode;
    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        ExtractLimits, ExtractOptions, OwnershipDecision, OwnershipPolicy, SpecialBitsPolicy,
        extract_layers_with_options,
    };
    use fandhe_container_oci::layer::idmap::{IdMap, IdRange};

    const CASE_TIMEOUT: Duration = Duration::from_secs(60);

    fn tar_with(entries: &[(&str, u32, u64, u64, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, mode, uid, gid, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(*mode);
            h.set_uid(*uid);
            h.set_gid(*gid);
            h.set_size(data.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, name, *data).expect("append");
        }
        b.into_inner().expect("tar")
    }

    fn id_map(host: u32) -> IdMap {
        IdMap::new(vec![IdRange {
            container_id: 0,
            host_id: host,
            count: 1,
        }])
        .expect("id map")
    }

    fn options(uid: IdMap, gid: IdMap) -> ExtractOptions {
        ExtractOptions::new()
            .with_ownership(OwnershipPolicy::ChownInUserNamespace { uid, gid })
            .with_special_bits(SpecialBitsPolicy::PreserveIfChowned)
    }

    fn run(
        root: &Path,
        tar: Vec<u8>,
        opts: &ExtractOptions,
    ) -> Result<
        Vec<fandhe_container_oci::layer::extract::ExtractedLayer>,
        fandhe_container_oci::error::OciError,
    > {
        extract_layers_with_options(
            &NoopOciOpRecorder,
            [Cursor::new(tar)],
            root,
            ExtractLimits::default(),
            opts,
        )
    }

    fn root_is_empty(root: &Path) -> bool {
        fs::read_dir(root).map(|d| d.count() == 0).unwrap_or(false)
    }

    /// `/proc/self/status` の `Uid:` / `Gid:` 行の effective。
    fn effective_id(key: &str) -> u32 {
        let status = fs::read_to_string("/proc/self/status").expect("status");
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .expect("id line")
    }

    // ---- 子（user namespace の中）----

    fn child(case: &str, root: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        match case {
            "extract_ok" => {
                let tar = tar_with(&[("suid", 0o4755, 0, 0, b"a"), ("d/f", 0o644, 0, 0, b"b")]);
                let layers = run(root, tar, &options(id_map(huid), id_map(hgid)))
                    .map_err(|e| format!("extract failed: {e:?}"))?;
                let l = layers.first().ok_or("no layer")?;
                if l.ownership.decision != OwnershipDecision::Applied {
                    return Err("ownership not applied".into());
                }
                // suid・d/f・d（暗黙）・root の 4 件。
                if l.ownership.chowned_entries != 4 {
                    return Err(format!("chowned_entries={}", l.ownership.chowned_entries));
                }
                if l.special_bits.preserved_bits.setuid != 1 {
                    return Err("setuid was not preserved".into());
                }
                Ok(())
            }
            "outside_map" => {
                let tar = tar_with(&[("a", 0o644, 0, 0, b"a"), ("b", 0o644, 1, 0, b"b")]);
                match run(root, tar, &options(id_map(huid), id_map(hgid))) {
                    Err(e) if e.code() == OciErrorCode::PermissionDenied && root_is_empty(root) => {
                        Ok(())
                    }
                    other => Err(format!("unexpected: {other:?}")),
                }
            }
            "map_mismatch" => {
                // 実際の写像（huid）と異なる写像を渡すと、root に触れる前に拒否する。
                let tar = tar_with(&[("a", 0o644, 0, 0, b"a")]);
                match run(root, tar, &options(id_map(huid + 1), id_map(hgid))) {
                    Err(e)
                        if e.code() == OciErrorCode::FailedPrecondition && root_is_empty(root) =>
                    {
                        Ok(())
                    }
                    other => Err(format!("unexpected: {other:?}")),
                }
            }
            _ => Err("unknown case".into()),
        }
    }

    // ---- 外側（初期 user namespace）----

    fn spawn_case(exe: &Path, case: &str, root: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        let mut c = Command::new("unshare")
            .args(["--user", "--map-root-user"])
            .arg(exe)
            .args(["--case", case, "--root"])
            .arg(root)
            .args(["--ids", &format!("{huid},{hgid}")])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot run unshare: {e}"))?;
        let start = Instant::now();
        loop {
            match c.try_wait().map_err(|e| format!("wait: {e}"))? {
                Some(st) if st.success() => return Ok(()),
                Some(st) => return Err(format!("case {case} failed: {st}")),
                None if start.elapsed() > CASE_TIMEOUT => {
                    let _ = c.kill();
                    let _ = c.wait();
                    return Err(format!("case {case} timed out"));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn new_root(base: &Path, name: &str) -> PathBuf {
        let root = base.join(name);
        fs::create_dir(&root).expect("mkdir root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod root");
        root
    }

    fn dispatch() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let (huid, hgid) = (effective_id("Uid:"), effective_id("Gid:"));
        if huid == 0 || hgid == 0 {
            return Err("run as a non-root user (the mapping must not map to host id 0)".into());
        }
        let base =
            std::env::temp_dir().join(format!("fandhe-userns-extract-{}", std::process::id()));
        fs::create_dir(&base).map_err(|e| format!("mkdir base: {e}"))?;
        let result = dispatch_in(&exe, &base, huid, hgid);
        let _ = fs::remove_dir_all(&base);
        result
    }

    fn dispatch_in(exe: &Path, base: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        // 正常: ホストから見た所有者は起動ユーザー、setuid は残る。
        let root = new_root(base, "ok");
        spawn_case(exe, "extract_ok", &root, huid, hgid)?;
        for name in ["suid", "d/f", "d"] {
            let m =
                fs::symlink_metadata(root.join(name)).map_err(|e| format!("stat {name}: {e}"))?;
            if (m.uid(), m.gid()) != (huid, hgid) {
                return Err(format!("{name}: unexpected host owner"));
            }
        }
        let suid = fs::symlink_metadata(root.join("suid")).map_err(|e| e.to_string())?;
        if suid.mode() & 0o7777 != 0o4755 {
            return Err(format!("suid mode is {:o}", suid.mode() & 0o7777));
        }
        // 写像外・写像の不一致。
        for case in ["outside_map", "map_mismatch"] {
            let root = new_root(base, case);
            spawn_case(exe, case, &root, huid, hgid)?;
        }
        // 初期 user namespace から呼ぶと、root に触れる前に FailedPrecondition。
        let root = new_root(base, "initial_ns");
        let tar = tar_with(&[("a", 0o644, 0, 0, b"a")]);
        match run(&root, tar, &options(id_map(huid), id_map(hgid))) {
            Err(e) if e.code() == OciErrorCode::FailedPrecondition && root_is_empty(&root) => {}
            other => return Err(format!("initial namespace: unexpected {other:?}")),
        }
        Ok(())
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--case") {
            let get = |k: &str| {
                args.iter()
                    .position(|a| a == k)
                    .and_then(|p| args.get(p + 1))
                    .cloned()
            };
            let (Some(case), Some(root), Some(ids)) =
                (args.get(i + 1), get("--root"), get("--ids"))
            else {
                eprintln!("userns_extract: bad child arguments");
                std::process::exit(2);
            };
            let ids: Vec<u32> = ids.split(',').filter_map(|v| v.parse().ok()).collect();
            let (Some(&huid), Some(&hgid)) = (ids.first(), ids.get(1)) else {
                eprintln!("userns_extract: bad --ids");
                std::process::exit(2);
            };
            match child(case, Path::new(&root), huid, hgid) {
                Ok(()) => println!("ok: {case}"),
                Err(e) => {
                    eprintln!("FAIL: {case}: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if !args.iter().any(|a| a == "--ignored") {
            println!(
                "userns_extract: ignored (pass `-- --ignored` on a host that allows unprivileged user namespaces)"
            );
            return;
        }
        match dispatch() {
            Ok(()) => println!("test userns_extract ... ok"),
            Err(e) => {
                eprintln!("FAIL: userns_extract: {e}");
                std::process::exit(1);
            }
        }
    }
}
