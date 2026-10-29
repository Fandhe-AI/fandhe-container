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
//! 範囲写像のケース（`subordinate_*`。#2642）: `newuidmap` / `newgidmap` による範囲写像（コンテナ 0 → 起動ユーザー、
//! 1.. → subuid / subgid）の中での展開を確かめる。子は `unshare` を介さず、core の本番と同じ公開経路
//! （`SubordinateIdSource::resolve_id_maps` → `plan_rootless_subordinate` → `isolate_rootless_subordinate`。
//! start と pull の展開が共有する解決部品〔#2389〕）で user namespace へ入る（dev-dependency の core を使う）。
//! `ChownInUserNamespace` に渡す写像も同じ解決結果から作るため、`/proc/self/{uid,gid}_map` との一致照合が通る。
//! 外側はホストから見た所有者（subuid / subgid 範囲への写像）を具体値で照合し、最後に namespace の中で木を消す
//! （subuid 所有のディレクトリはホストの euid では消せない）。
//! 追加の前提: `uidmap`（setuid の `newuidmap` / `newgidmap`）・自分の subuid / subgid の行・環境変数 `USER`。
//! 欠けていれば skip せず失敗する（opt-in にしない。`rootless_image_rootfs_remove` と同じ扱い）。
//!
//! 未検証の範囲: 本番の展開器が user namespace へ入って `ImageRootfsUnpacker::unpack` から展開する配線は
//! 本試験の対象外（#2377・#2315・#482）。root で走る分岐は CI では回さない（#1621）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("userns_extract: not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, Namespace, NamespaceSet, isolate_rootless_subordinate,
        plan_rootless_subordinate,
    };
    use fandhe_container_core::oci_runtime::{SubordinateIdMaps, SubordinateIdSource};
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter,
    };
    use fandhe_container_oci::error::OciErrorCode;
    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        ExtractLimits, ExtractOptions, OwnershipDecision, OwnershipPolicy, SpecialBitsPolicy,
        extract_layers_with_options, remove_extracted_tree,
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
        if case.starts_with("subordinate_") {
            return subordinate_child(case, root, huid, hgid);
        }
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

    // ---- 範囲写像（newuidmap。#2642）----

    /// tar に使うコンテナ内の ID（範囲写像の 1.. に収まる値）。
    const TAR_UID: u64 = 1000;
    const TAR_GID: u64 = 2000;

    /// 起動ユーザーの subuid / subgid から作った写像。core の本番と同じ解決結果から oci の `IdMap` も作る。
    struct Maps {
        uid: IdMap,
        gid: IdMap,
        resolved: SubordinateIdMaps,
    }

    fn to_oci_map(set: &IdMapSet) -> Result<IdMap, String> {
        let lines = set
            .entries()
            .iter()
            .map(|e| IdRange {
                container_id: e.container_id,
                host_id: e.host_id,
                count: e.count,
            })
            .collect();
        IdMap::new(lines).map_err(|e| format!("oci id map: {:?}", e.code()))
    }

    fn resolve_maps(huid: u32, hgid: u32) -> Result<Maps, String> {
        let owner = std::env::var("USER").map_err(|_| "USER is not set".to_string())?;
        let source = SubordinateIdSource::system(Some(owner))
            .map_err(|e| format!("subordinate id source: {:?}", e.code()))?;
        let resolved = source
            .resolve_id_maps(huid, hgid)
            .map_err(|e| format!("resolve_id_maps: {:?}", e.code()))?;
        Ok(Maps {
            uid: to_oci_map(resolved.uid())?,
            gid: to_oci_map(resolved.gid())?,
            resolved,
        })
    }

    /// 子: 本番と同じ経路で範囲写像の user namespace へ入る。単一スレッドの新しいプロセスで呼ぶ。
    fn enter_range_namespace(maps: &Maps) -> Result<(), String> {
        let helper = HelperPaths::system_default()
            .map_err(|e| format!("helper paths: {:?} {}", e.code, e.message))?;
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            maps.resolved.uid().clone(),
            maps.resolved.gid().clone(),
            IdMapWriter::Helper(helper),
            DEFAULT_HELPER_TIMEOUT,
        )
        .map_err(|e| format!("plan: {:?} {}", e.code, e.message))?;
        isolate_rootless_subordinate(&plan)
            .map(|_| ())
            .map_err(|e| format!("isolate: {:?} {}", e.code, e.message))
    }

    /// 写像が占めるコンテナ内 ID の末尾 + 1（これ以上は写像の外）。
    fn first_unmapped(map: &IdMap) -> Result<u64, String> {
        map.lines()
            .iter()
            .map(|l| u64::from(l.container_id) + u64::from(l.count))
            .max()
            .ok_or_else(|| "empty id map".to_string())
    }

    fn subordinate_child(case: &str, root: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        let maps = resolve_maps(huid, hgid)?;
        enter_range_namespace(&maps)?;
        match case {
            "subordinate_extract_ok" => {
                let tar = tar_with(&[
                    ("r0", 0o644, 0, 0, b"a"),
                    ("u1", 0o644, 1, 1, b"b"),
                    ("d/n", 0o640, TAR_UID, TAR_GID, b"c"),
                    ("suid1", 0o4755, 1, 1, b"d"),
                    ("sgid", 0o2755, TAR_UID, TAR_GID, b"e"),
                ]);
                let layers = run(root, tar, &options(maps.uid.clone(), maps.gid.clone()))
                    .map_err(|e| format!("extract failed: {:?}", e.code()))?;
                let l = layers.first().ok_or("no layer")?;
                if l.ownership.decision != OwnershipDecision::Applied {
                    return Err("ownership not applied".into());
                }
                // r0・u1・d/n・d（暗黙）・suid1・sgid・root の 7 件。
                if l.ownership.chowned_entries != 7 {
                    return Err(format!("chowned_entries={}", l.ownership.chowned_entries));
                }
                let bits = &l.special_bits.preserved_bits;
                if bits.setuid != 1 || bits.setgid != 1 {
                    return Err(format!(
                        "preserved setuid={} setgid={}",
                        bits.setuid, bits.setgid
                    ));
                }
                Ok(())
            }
            "subordinate_outside_map" => {
                let outside = first_unmapped(&maps.uid)?;
                let tar = tar_with(&[("a", 0o644, 0, 0, b"a"), ("b", 0o644, outside, 0, b"b")]);
                match run(root, tar, &options(maps.uid.clone(), maps.gid.clone())) {
                    Err(e) if e.code() == OciErrorCode::PermissionDenied && root_is_empty(root) => {
                        Ok(())
                    }
                    other => Err(format!("unexpected: {other:?}")),
                }
            }
            "subordinate_map_mismatch" => {
                // 実際は範囲写像なのに単一行の写像を渡すと、root に触れる前に拒否する。
                let tar = tar_with(&[("a", 0o644, 0, 0, b"a")]);
                match run(root, tar, &options(id_map(huid), id_map(hgid))) {
                    Err(e)
                        if e.code() == OciErrorCode::FailedPrecondition && root_is_empty(root) =>
                    {
                        Ok(())
                    }
                    other => Err(format!("unexpected: {other:?}")),
                }
            }
            "subordinate_cleanup" => {
                remove_extracted_tree(root).map_err(|e| format!("remove: {:?}", e.code()))?;
                if root.exists() {
                    return Err("tree still exists".into());
                }
                Ok(())
            }
            _ => Err("unknown case".into()),
        }
    }

    // ---- 外側（初期 user namespace）----

    fn spawn_case(exe: &Path, case: &str, root: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--map-root-user"]).arg(exe);
        run_child(cmd, case, root, huid, hgid)
    }

    /// 範囲写像のケース: `unshare` を介さず、子が core の本番の経路で user namespace へ入る。
    fn spawn_subordinate_case(
        exe: &Path,
        case: &str,
        root: &Path,
        huid: u32,
        hgid: u32,
    ) -> Result<(), String> {
        run_child(Command::new(exe), case, root, huid, hgid)
    }

    /// 子を期限つきで待つ。超えたら kill して回収し失敗にする（REPAIR-5）。
    fn run_child(
        mut cmd: Command,
        case: &str,
        root: &Path,
        huid: u32,
        hgid: u32,
    ) -> Result<(), String> {
        let mut c = cmd
            .args(["--case", case, "--root"])
            .arg(root)
            .args(["--ids", &format!("{huid},{hgid}")])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot run child: {e}"))?;
        let start = Instant::now();
        loop {
            match c.try_wait().map_err(|e| format!("wait: {e}"))? {
                Some(st) if st.success() => return Ok(()),
                Some(st) => return Err(format!("case {case} failed: {st}")),
                None if start.elapsed() > CASE_TIMEOUT => {
                    crate::reap::reap_or_report(&mut c, crate::reap::reap_within());
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
        range_cases(exe, base, huid, hgid)
    }

    /// 範囲写像のケース。展開の照合に失敗しても、subuid 所有の木を消す後始末は必ず試みる。
    fn range_cases(exe: &Path, base: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        let maps = resolve_maps(huid, hgid)?;
        let (uid_lines, gid_lines) = (maps.uid.lines(), maps.gid.lines());
        if uid_lines.len() < 2 || gid_lines.len() < 2 {
            return Err("subordinate mapping must have a range row besides 0".into());
        }
        let host_of = |map: &IdMap, id: u64| -> Result<u32, String> {
            let id = u32::try_from(id).map_err(|_| "id out of range".to_string())?;
            map.map_to_host(id)
                .ok_or_else(|| format!("id {id} is not covered by the mapping"))
        };
        let (sub_uid, sub_gid) = (host_of(&maps.uid, 1)?, host_of(&maps.gid, 1)?);
        let (tar_uid, tar_gid) = (host_of(&maps.uid, TAR_UID)?, host_of(&maps.gid, TAR_GID)?);
        // core の解決結果を鵜呑みにせず、範囲の先頭からの素朴な計算とも突き合わせる。
        let first = uid_lines
            .iter()
            .find(|l| l.container_id == 1)
            .ok_or("no uid row starts at container id 1")?;
        if first.count <= 1000 || u64::from(tar_uid) != u64::from(first.host_id) + (TAR_UID - 1) {
            return Err("unexpected subordinate uid range".into());
        }
        if sub_uid == huid || sub_gid == hgid || sub_uid == 0 || sub_gid == 0 {
            return Err("container id 1 must map to a subordinate id".into());
        }

        let root = new_root(base, "range_ok");
        let result = range_extract_ok(
            exe,
            &root,
            (huid, hgid),
            (sub_uid, sub_gid),
            (tar_uid, tar_gid),
        );
        // 後始末は成否に関わらず試みる。失敗の報告を優先し、後始末の失敗は元のエラーを上書きしない。
        let cleanup = spawn_subordinate_case(exe, "subordinate_cleanup", &root, huid, hgid)
            .and_then(|()| {
                if root.exists() {
                    Err("cleanup left the tree".to_string())
                } else {
                    Ok(())
                }
            });
        result?;
        cleanup?;

        for case in ["subordinate_outside_map", "subordinate_map_mismatch"] {
            let root = new_root(base, case);
            spawn_subordinate_case(exe, case, &root, huid, hgid)?;
        }
        Ok(())
    }

    /// 範囲写像の namespace の中で展開し、ホストから見た所有者・mode を具体値で照合する。
    fn range_extract_ok(
        exe: &Path,
        root: &Path,
        (huid, hgid): (u32, u32),
        (sub_uid, sub_gid): (u32, u32),
        (tar_uid, tar_gid): (u32, u32),
    ) -> Result<(), String> {
        spawn_subordinate_case(exe, "subordinate_extract_ok", root, huid, hgid)?;
        let expect = [
            ("r0", (huid, hgid), None),
            ("d", (huid, hgid), None),
            ("u1", (sub_uid, sub_gid), None),
            ("suid1", (sub_uid, sub_gid), Some(0o4755)),
            ("d/n", (tar_uid, tar_gid), None),
            ("sgid", (tar_uid, tar_gid), Some(0o2755)),
        ];
        for (name, owner, mode) in expect {
            let m =
                fs::symlink_metadata(root.join(name)).map_err(|e| format!("stat {name}: {e}"))?;
            if (m.uid(), m.gid()) != owner {
                return Err(format!(
                    "{name}: host owner is {}:{}, expected {}:{}",
                    m.uid(),
                    m.gid(),
                    owner.0,
                    owner.1
                ));
            }
            if let Some(mode) = mode
                && m.mode() & 0o7777 != mode
            {
                return Err(format!("{name}: mode is {:o}", m.mode() & 0o7777));
            }
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
