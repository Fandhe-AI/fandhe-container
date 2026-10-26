//! 他 uid が所有する staged blob を `PullSession::verify_staged_blob` が chmod せずに拒否することの実機前提試験
//! （OCI-7・SEC-1・SEC-5・REPAIR-3・REPAIR-12・#2907）。
//!
//! 背景: 所有者違反は root / `CAP_CHOWN` が無いと実ファイルで作れず、これまでは純粋関数の判定
//! （`layer.rs` の `oci1_sec_blob_trust_rejects_untrusted_metadata`）でしか照合していなかった。本試験は
//! `newuidmap` の範囲写像（subuid）で非 root のまま他 uid 所有のファイルを実際に作り、本番の検証経路で照合する。
//!
//! 構成: 外側（初期 user namespace・非 root・ホストの euid）がストアを開いて blob を 3 つステージし（0o666 にする。
//! 所有者違反と group / other 書き込み違反を同時に持たせ、所有者の判定が chmod より先に効くことを示す）、
//! 子（core の本番と同じ公開経路で範囲写像の user namespace へ入る）が指定した blob だけを
//! コンテナ内 ID 1（= subuid）へ chown する。検証者がホストの euid のままなのは本番と同じで、ストアを
//! namespace の中で開く構成は採らない。外側は陰性対照（実際に subuid 所有になったこと）・本照合
//! （`FailedPrecondition`・`blob has an unexpected owner`・mode / 所有者 / 内容が不変・検証済みに登録されない）・
//! 陽性対照（自分の blob は 0600 に狭まって検証済みになる）・再検証の取り消し（検証済みだった blob が
//! 他 uid 所有になった後の再検証で登録が消える）を具体値で照合する。
//!
//! 前提: `uidmap`（setuid の `newuidmap` / `newgidmap`）・自分の subuid / subgid の行・環境変数 `USER`・非 root。
//! 欠けていれば skip せず失敗する（opt-in にしない）。`harness = false`（単一スレッドの独自 `main`）で、
//! `-- --ignored` を付けたときだけ実行する（AGENTS.md「実機前提テスト」）。
//!
//! 未検証の範囲: root で走る分岐は CI では回さない（#1621）。`secure_staged_blob` は private のため
//! `verify_staged_blob` 経由でしか届かない（直接の呼び出しは crate 内の単体試験が担う）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("staged_blob_owner: not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Write as _;
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
    use fandhe_container_oci::image_management::{ImageStore, PullId, PullSession};
    use fandhe_container_oci::layer::idmap::{IdMap, IdRange};
    use fandhe_container_oci::reference::Digest;

    const CASE_TIMEOUT: Duration = Duration::from_secs(60);
    const MAX_BYTES: u64 = 1 << 20;

    // ---- 子（範囲写像の user namespace の中）----

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

    /// 起動ユーザーの subuid / subgid から作った写像（core の本番と同じ解決結果）。
    fn resolve_maps(huid: u32, hgid: u32) -> Result<(SubordinateIdMaps, IdMap, IdMap), String> {
        let owner = std::env::var("USER").map_err(|_| "USER is not set".to_string())?;
        let source = SubordinateIdSource::system(Some(owner))
            .map_err(|e| format!("subordinate id source: {:?}", e.code()))?;
        let resolved = source
            .resolve_id_maps(huid, hgid)
            .map_err(|e| format!("resolve_id_maps: {:?}", e.code()))?;
        let (u, g) = (to_oci_map(resolved.uid())?, to_oci_map(resolved.gid())?);
        Ok((resolved, u, g))
    }

    /// 子: 本番と同じ経路で範囲写像の user namespace へ入る。単一スレッドの新しいプロセスで呼ぶ。
    fn enter_range_namespace(huid: u32, hgid: u32) -> Result<(), String> {
        let (resolved, _, _) = resolve_maps(huid, hgid)?;
        let helper = HelperPaths::system_default()
            .map_err(|e| format!("helper paths: {:?} {}", e.code, e.message))?;
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            resolved.uid().clone(),
            resolved.gid().clone(),
            IdMapWriter::Helper(helper),
            DEFAULT_HELPER_TIMEOUT,
        )
        .map_err(|e| format!("plan: {:?} {}", e.code, e.message))?;
        isolate_rootless_subordinate(&plan)
            .map(|_| ())
            .map_err(|e| format!("isolate: {:?} {}", e.code, e.message))
    }

    /// 子: 渡されたパスをコンテナ内 ID 1（subuid / subgid）へ chown するだけ。
    fn child(paths: &[PathBuf], huid: u32, hgid: u32) -> Result<(), String> {
        if paths.is_empty() {
            return Err("no --path".into());
        }
        enter_range_namespace(huid, hgid)?;
        for p in paths {
            std::os::unix::fs::chown(p, Some(1), Some(1))
                .map_err(|e| format!("chown {}: {e}", p.display()))?;
        }
        Ok(())
    }

    // ---- 外側（初期 user namespace・ホストの euid）----

    fn effective_id(key: &str) -> Result<u32, String> {
        let status = fs::read_to_string("/proc/self/status").map_err(|e| format!("status: {e}"))?;
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("no {key} line"))
    }

    /// 子を期限つきで待つ。超えたら kill して回収し失敗にする（REPAIR-5）。
    fn run_chown_child(exe: &Path, paths: &[PathBuf], huid: u32, hgid: u32) -> Result<(), String> {
        let mut cmd = Command::new(exe);
        for p in paths {
            cmd.arg("--path").arg(p);
        }
        let mut c = cmd
            .args(["--child", "--ids", &format!("{huid},{hgid}")])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot run child: {e}"))?;
        let start = Instant::now();
        loop {
            match c.try_wait().map_err(|e| format!("wait: {e}"))? {
                Some(st) if st.success() => return Ok(()),
                Some(st) => return Err(format!("chown child failed: {st}")),
                None if start.elapsed() > CASE_TIMEOUT => {
                    let _ = c.kill();
                    let _ = c.wait();
                    return Err("chown child timed out".into());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// blob を書いて確定し、0o666 にする。戻り値は digest とステージングのパス。
    fn stage(session: &mut PullSession<'_>, body: &[u8]) -> Result<(Digest, PathBuf), String> {
        let dg = Digest::sha256_of(body);
        let hex = dg
            .as_str()
            .strip_prefix("sha256:")
            .ok_or("digest without prefix")?
            .to_owned();
        let mut w = session
            .open_staged_blob(&dg)
            .map_err(|e| format!("open_staged_blob: {:?}", e.code()))?;
        w.write_all(body).map_err(|e| format!("write: {e}"))?;
        w.commit().map_err(|e| format!("commit: {:?}", e.code()))?;
        let path = session.staging_dir().join(hex);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .map_err(|e| format!("chmod 666: {e}"))?;
        Ok((dg, path))
    }

    fn owner_of(p: &Path) -> Result<(u32, u32), String> {
        let m = fs::symlink_metadata(p).map_err(|e| format!("stat: {e}"))?;
        Ok((m.uid(), m.gid()))
    }

    fn mode_of(p: &Path) -> Result<u32, String> {
        let m = fs::symlink_metadata(p).map_err(|e| format!("stat: {e}"))?;
        Ok(m.mode() & 0o7777)
    }

    /// 検証が所有者違反で拒否されたこと（種別・文言）を確かめる。
    fn expect_owner_rejection(
        session: &mut PullSession<'_>,
        dg: &Digest,
        what: &str,
    ) -> Result<(), String> {
        match session.verify_staged_blob(dg, MAX_BYTES) {
            Err(e)
                if e.code() == OciErrorCode::FailedPrecondition
                    && e.message() == "blob has an unexpected owner" =>
            {
                Ok(())
            }
            other => Err(format!("{what}: unexpected {other:?}")),
        }
    }

    /// 検証済みとして登録されていない（`open_verified_staged_blob` が拒否する）ことを確かめる。
    fn expect_not_verified(
        session: &PullSession<'_>,
        dg: &Digest,
        what: &str,
    ) -> Result<(), String> {
        match session.open_verified_staged_blob(dg) {
            Err(e) if e.code() == OciErrorCode::FailedPrecondition => Ok(()),
            other => Err(format!("{what}: blob is registered as verified: {other:?}")),
        }
    }

    fn dispatch_in(exe: &Path, base: &Path, huid: u32, hgid: u32) -> Result<(), String> {
        let (_, uid_map, gid_map) = resolve_maps(huid, hgid)?;
        if uid_map.lines().len() < 2 || gid_map.lines().len() < 2 {
            return Err("subordinate mapping must have a range row besides 0".into());
        }
        let sub_uid = uid_map
            .map_to_host(1)
            .ok_or("container uid 1 is not mapped")?;
        let sub_gid = gid_map
            .map_to_host(1)
            .ok_or("container gid 1 is not mapped")?;
        if sub_uid == huid || sub_gid == hgid || sub_uid == 0 || sub_gid == 0 {
            return Err("container id 1 must map to a subordinate id".into());
        }
        let sub = (sub_uid, sub_gid);

        let root = base.join("store");
        fs::create_dir(&root).map_err(|e| format!("mkdir store: {e}"))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod store: {e}"))?;
        let store = ImageStore::open(&root).map_err(|e| format!("open store: {:?}", e.code()))?;
        let id = PullId::new("p1").map_err(|e| format!("pull id: {:?}", e.code()))?;
        let mut session = store
            .begin_pull(id)
            .map_err(|e| format!("begin_pull: {:?}", e.code()))?;

        let foreign_body: &[u8] = b"foreign-owned-body";
        let (foreign_dg, foreign) = stage(&mut session, foreign_body)?;
        let (own_dg, own) = stage(&mut session, b"own-body")?;
        let (re_dg, re) = stage(&mut session, b"reverify-body")?;

        // 再検証の前提: 一度検証済みにする（この時点で 0600 に狭まる）。
        session
            .verify_staged_blob(&re_dg, MAX_BYTES)
            .map_err(|e| format!("initial verify: {:?}", e.code()))?;
        session
            .open_verified_staged_blob(&re_dg)
            .map_err(|e| format!("initial open_verified: {:?}", e.code()))?;

        // 0600 のまま他 uid 所有になると open 自体が EACCES になり所有者判定まで届かないため、読める mode に戻す。
        fs::set_permissions(&re, fs::Permissions::from_mode(0o666))
            .map_err(|e| format!("chmod 666: {e}"))?;

        run_chown_child(exe, &[foreign.clone(), re.clone()], huid, hgid)?;

        // 陰性対照: 非 root のまま、実際に subuid 所有のファイルを作れた。
        if owner_of(&foreign)? != sub || owner_of(&re)? != sub {
            return Err(format!(
                "foreign blob owner is {:?}, expected {sub:?}",
                owner_of(&foreign)?
            ));
        }
        println!("ok: foreign_owner_prepared");

        // 本照合: 拒否・chmod されない・所有者と内容が不変・検証済みに登録されない。
        expect_owner_rejection(&mut session, &foreign_dg, "foreign-owned blob")?;
        if mode_of(&foreign)? != 0o666 {
            return Err(format!("mode changed to {:o}", mode_of(&foreign)?));
        }
        if owner_of(&foreign)? != sub {
            return Err("owner changed".into());
        }
        if fs::read(&foreign).map_err(|e| format!("read: {e}"))? != foreign_body {
            return Err("content changed".into());
        }
        expect_not_verified(&session, &foreign_dg, "foreign-owned blob")?;
        println!("ok: foreign_owner_rejected_without_chmod");

        // 陽性対照: 自分の blob は同じ経路で 0600 に狭まって検証済みになる。
        let v = session
            .verify_staged_blob(&own_dg, MAX_BYTES)
            .map_err(|e| format!("verify of own blob: {:?}", e.code()))?;
        if v.size != b"own-body".len() as u64 {
            return Err(format!("own blob size is {}", v.size));
        }
        if mode_of(&own)? != 0o600 || owner_of(&own)? != (huid, hgid) {
            return Err("own blob was not narrowed to 0600".into());
        }
        session
            .open_verified_staged_blob(&own_dg)
            .map_err(|e| format!("own open_verified: {:?}", e.code()))?;
        println!("ok: own_owner_narrowed_to_0600");

        // 再検証: 検証済みだった blob が他 uid 所有になった後の再検証は拒否し、登録も消える。
        expect_owner_rejection(&mut session, &re_dg, "reverify")?;
        if mode_of(&re)? != 0o666 || owner_of(&re)? != sub {
            return Err("reverify changed mode or owner".into());
        }
        expect_not_verified(&session, &re_dg, "reverify")?;
        println!("ok: reverify_foreign_owner_drops_verified");
        Ok(())
    }

    fn dispatch() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let (huid, hgid) = (effective_id("Uid:")?, effective_id("Gid:")?);
        if huid == 0 || hgid == 0 {
            return Err("run as a non-root user (the mapping must not map to host id 0)".into());
        }
        let base =
            std::env::temp_dir().join(format!("fandhe-staged-blob-owner-{}", std::process::id()));
        fs::create_dir(&base).map_err(|e| format!("mkdir base: {e}"))?;
        // ストアの祖先は group / other に書き込めてはならない（umask に依らず 0700 にする）。
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod base: {e}"))?;
        let result = dispatch_in(&exe, &base, huid, hgid);
        // 後始末は成否に関わらず試みる。失敗の報告を優先する（subuid 所有の blob もホスト所有のディレクトリから消せる）。
        let _ = fs::remove_dir_all(&base);
        result
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--child") {
            let ids = args
                .iter()
                .position(|a| a == "--ids")
                .and_then(|p| args.get(p + 1))
                .map(|s| {
                    s.split(',')
                        .filter_map(|v| v.parse().ok())
                        .collect::<Vec<u32>>()
                })
                .unwrap_or_default();
            let (Some(&huid), Some(&hgid)) = (ids.first(), ids.get(1)) else {
                eprintln!("staged_blob_owner: bad --ids");
                std::process::exit(2);
            };
            let paths: Vec<PathBuf> = args
                .windows(2)
                .filter(|w| w[0] == "--path")
                .map(|w| PathBuf::from(&w[1]))
                .collect();
            match child(&paths, huid, hgid) {
                Ok(()) => println!("ok: child_chown"),
                Err(e) => {
                    eprintln!("FAIL: child_chown: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if !args.iter().any(|a| a == "--ignored") {
            println!(
                "staged_blob_owner: ignored (pass `-- --ignored` on a host that allows unprivileged user namespaces)"
            );
            return;
        }
        match dispatch() {
            Ok(()) => println!("test staged_blob_owner ... ok"),
            Err(e) => {
                eprintln!("FAIL: staged_blob_owner: {e}");
                std::process::exit(1);
            }
        }
    }
}
