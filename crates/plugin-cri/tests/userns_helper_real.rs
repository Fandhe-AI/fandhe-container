//! userns helper（隠し引数 `__extract-in-userns`）を実バイナリで本番の参加経路（`--no-join` なし）で通す実機前提の結合試験
//! （SEC-5・OCI-1・CORE-6・REPAIR-5・REPAIR-12。#4795。親 issue #4777 の H1。設計は `docs/design/userns-extract-helper.md`）。
//!
//! 必要環境: 非 root・非特権 user namespace を許す環境（`kernel.apparmor_restrict_unprivileged_userns` の緩和など）・
//! `uidmap`（`newuidmap` / `newgidmap`）・自分の subuid / subgid の行・Linux 6.9 以降（範囲写像の helper の停止手段）。
//! `harness = false` で `-- --ignored` 指定時のみ動かす（AGENTS.md）。前提の欠落・root は終了コード 1（成功を装わない）。
//! 全体 watchdog は 120 秒で、超えたら `WATCHDOG EXPIRED` と終了コード 124。CI へは platform-ci の ubuntu に組み込み済み（#4802）。
//!
//! # シナリオ（各成功行は固定の文字列。`scripts/check-success-lines.sh` が本ファイルのリテラルから導出して照合する）
//! - Inspect: 参加後に joined・euid 0・egid 0・threads 1・dumpable 0・写像 2 行以上
//! - StatTarget: 自分が所有するディレクトリが、名前空間の中では uid 0 の所有に見える
//! - Remove（H3。#4800）: 範囲写像の user namespace の中で作った subuid 所有の木（最上位自身も subuid 所有・0700、
//!   0555 の子を含む）は、ホスト側の削除では消えず（陽性対照）、削除モードで消える。親ディレクトリは残る。木の作成は本試験
//!   バイナリを `--populate <dir>` で再実行した子（単一スレッド）が行う
//! - Extract（#4847）: tar の所有者（uid 1000・gid 1000）が、範囲写像の user namespace の中では tar の値のまま見える
//!   （`ChownInUserNamespace`。StatTarget で `d/` の fd を名前空間の中から見る）。ホストから見ると別の（subuid の）所有者で
//!   あることを陽性対照にする。blob の fd と展開先の fd だけを渡し、パスは渡さない。後始末は削除モード
//! - 対応表（#4801・#4849）: 本番の解決 `resolve_extract_identity` → `extract_options_for` が `ChownInUserNamespace`（本番の写像）+
//!   `PreserveIfChowned` を返し、その options のまま、0700 の bundle を閉じ込めの祖先として本番の注入点
//!   `SubordinateLayerExtractor::extract_layers` で展開すると（rootfs は create と同じく 0755）、所有者は tar の値のまま見え、
//!   setuid / setgid / sticky が保たれる。別の uid（名前空間内の uid 1000 = ホストでは別の subuid）は bundle の下へ届かない
//!   （`--probe-reach <path>` の子。陽性対照: 同じ uid の子は届く・bundle を 0711 にすると別 uid も届く）

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("userns_helper_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("userns_helper_real: x86_64/aarch64 only, not applicable on this architecture");
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
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::Duration;

    use fandhe_container_plugin_cri::userns_helper::wire::{Mode, RemoveTarget, Report};
    use fandhe_container_plugin_cri::userns_helper::{
        USERNS_HELPER_ARG, UsernsHelperLauncher, WorkBudget,
    };

    const WATCHDOG: Duration = Duration::from_secs(120);
    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        // 子の役（単一スレッドのまま user namespace に入る。watchdog スレッドを起動する前に処理する）。
        if let Some(i) = args.iter().position(|a| a == "--probe-reach") {
            let path = args
                .get(i + 1)
                .unwrap_or_else(|| fail("path after --probe-reach"));
            return probe_reach(path, args.get(i + 2).is_some_and(|a| a == "other"));
        }
        if let Some(i) = args.iter().position(|a| a == "--populate") {
            let dir = args
                .get(i + 1)
                .unwrap_or_else(|| fail("directory after --populate"));
            populate(dir);
            return ExitCode::SUCCESS;
        }
        match args.get(1).map(String::as_str) {
            Some("--ignored") => run_all(),
            _ => {
                println!(
                    "userns_helper_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
                );
                ExitCode::SUCCESS
            }
        }
    }

    fn fail(msg: &str) -> ! {
        println!("userns_helper_real: FAILED: {msg}");
        std::process::exit(1);
    }

    fn start_watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            println!("userns_helper_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            std::process::exit(124);
        });
    }

    fn run_all() -> ExitCode {
        let euid = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
        if euid == 0 {
            println!("userns_helper_real: FAILED: must run as non-root (root=true)");
            return ExitCode::from(1);
        }
        for p in ["/usr/bin/newuidmap", "/usr/bin/newgidmap"] {
            if !Path::new(p).exists() {
                println!("userns_helper_real: PRECONDITION FAILED: {p} is required");
                return ExitCode::from(1);
            }
        }
        start_watchdog();

        let dir = scratch_dir();
        let target = File::open(&dir).unwrap_or_else(|e| fail(&format!("open scratch dir: {e}")));
        let launcher =
            UsernsHelperLauncher::with_fixed_command(BIN, vec![USERNS_HELPER_ARG.into()]);
        let budget =
            WorkBudget::new(Duration::from_secs(10)).unwrap_or_else(|e| fail(&e.to_string()));

        match launcher.run(Mode::Inspect, target.as_fd(), budget) {
            Ok(Report::Inspect(r)) => {
                if !(r.joined
                    && r.euid == 0
                    && r.egid == 0
                    && r.threads == 1
                    && r.dumpable == 0
                    && r.uid_map_rows >= 2
                    && r.gid_map_rows >= 2)
                {
                    fail(&format!("unexpected inspect report: {r:?}"));
                }
                println!(
                    "userns_helper_real: inspect joined ok (euid 0, egid 0, threads 1, dumpable 0, maps >= 2 rows)"
                );
            }
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("inspect: {e} (helper={:?})", e.helper_code())),
        }

        match launcher.run(Mode::StatTarget, target.as_fd(), budget) {
            Ok(Report::StatTarget(r)) => {
                if r.uid != 0 || r.gid != 0 || r.mode != 0o700 {
                    fail(&format!("unexpected stat report: {r:?}"));
                }
                println!(
                    "userns_helper_real: stat target owner is namespace root ok (uid 0, gid 0, mode 0700)"
                );
            }
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("stat: {e} (helper={:?})", e.helper_code())),
        }
        let _ = std::fs::remove_dir(&dir);
        remove_subordinate_owned_tree(&launcher, budget);
        extract_keeps_tar_owners_in_namespace(&launcher, budget);
        table_row_extracts_with_tar_owners_and_keeps_special_bits(&launcher);
        ExitCode::SUCCESS
    }

    /// 子の役: user namespace の中で `dir` に subuid 所有の木を作る（最上位自身も subuid 所有・0700。0555 の子を含む）。
    fn populate(dir: &str) {
        // namespace に入る前にディレクトリを開く（入った後は `/proc/self/fd/N` で触る）。
        let root = File::open(dir).unwrap_or_else(|e| fail(&format!("open target dir: {e}")));
        enter_userns();
        let base = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        let sub = base.join("sub");
        let step = |what: &str, r: std::io::Result<()>| {
            if let Err(e) = r {
                fail(&format!("populate {what}: {e}"));
            }
        };
        step("mkdir", std::fs::create_dir(&sub));
        step(
            "write",
            std::fs::write(sub.join("f"), b"owned by a subordinate id"),
        );
        step(
            "chmod f",
            std::fs::set_permissions(sub.join("f"), std::fs::Permissions::from_mode(0o444)),
        );
        step(
            "chmod sub",
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)),
        );
        step(
            "chown f",
            std::os::unix::fs::chown(sub.join("f"), Some(1), Some(1)),
        );
        step(
            "chown sub",
            std::os::unix::fs::chown(&sub, Some(1), Some(1)),
        );
        step(
            "chmod root",
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)),
        );
        step(
            "chown root",
            std::os::unix::fs::chown(&base, Some(1), Some(1)),
        );
    }

    /// 本番の helper と同じ解決で範囲写像の user namespace に入る（単一スレッドで呼ぶこと）。
    fn enter_userns() {
        use fandhe_container_core::exec::{
            IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet,
            isolate_rootless_subordinate, plan_rootless_subordinate,
        };
        use fandhe_container_core::rootless::{DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapWriter};

        let resolved = fandhe_container_supervisor::start_entry::resolve_self_launch_privilege()
            .unwrap_or_else(|e| fail(&format!("resolve privilege: {e}")));
        let (IsolationPrivilege::RootlessSubordinateIds, Some(source)) = resolved else {
            fail("a subordinate id range is required");
        };
        let meta = std::fs::metadata("/proc/self")
            .unwrap_or_else(|e| fail(&format!("stat /proc/self: {e}")));
        let maps = source
            .resolve_id_maps(meta.uid(), meta.gid())
            .unwrap_or_else(|e| fail(&format!("resolve id maps: {e}")));
        let helper = HelperPaths::system_default()
            .unwrap_or_else(|e| fail(&format!("newuidmap helper: {e}")));
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            maps.uid().clone(),
            maps.gid().clone(),
            IdMapWriter::Helper(helper),
            DEFAULT_HELPER_TIMEOUT,
        )
        .unwrap_or_else(|e| fail(&format!("plan: {e}")));
        isolate_rootless_subordinate(&plan).unwrap_or_else(|e| fail(&format!("enter userns: {e}")));
    }

    /// Remove（H3。#4800）: subuid 所有の木はホスト側では消せず、削除モードで消える。親は残る。
    fn remove_subordinate_owned_tree(launcher: &UsernsHelperLauncher, budget: WorkBudget) {
        use std::os::unix::fs::DirBuilderExt as _;
        let base = std::env::temp_dir().join(format!("userns-helper-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let parent = base.join("bundle");
        for d in [&base, &parent, &parent.join("rootfs")] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d)
                .unwrap_or_else(|e| fail(&format!("create {}: {e}", d.display())));
        }
        let rootfs = parent.join("rootfs");
        // --populate は試験バイナリ自身の main が処理する（plugin-cri の bin は受けない）。
        let self_exe =
            std::env::current_exe().unwrap_or_else(|e| fail(&format!("current_exe: {e}")));
        let status = std::process::Command::new(self_exe)
            .arg("--populate")
            .arg(&rootfs)
            .status()
            .unwrap_or_else(|e| fail(&format!("spawn populate child: {e}")));
        if !status.success() {
            fail(&format!("populate child failed: {status}"));
        }
        // 陽性対照: 最上位が subuid 所有・0700 の木はホストの uid では消せず、木は残る。
        if std::fs::remove_dir_all(&rootfs).is_ok() || !rootfs.exists() {
            fail("host-side removal unexpectedly succeeded (positive control)");
        }
        let target = File::open(&parent).unwrap_or_else(|e| fail(&format!("open parent: {e}")));
        match launcher.run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            target.as_fd(),
            budget,
        ) {
            Ok(Report::Removed) => {}
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("remove: {e} (helper={:?})", e.helper_code())),
        }
        if std::fs::symlink_metadata(&rootfs).is_ok() || !parent.is_dir() {
            fail("rootfs must be gone and the parent kept");
        }
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "userns_helper_real: remove subordinate-owned tree ok (rootfs absent, parent kept)"
        );
    }

    /// 最小の ustar 1 エントリ（所有者つき）。
    fn tar_entry(name: &str, mode: u32, owner: u32, data: &[u8], dir: bool) -> Vec<u8> {
        let mut h = [0u8; 512];
        let mut put = |off: usize, bytes: &[u8]| h[off..off + bytes.len()].copy_from_slice(bytes);
        put(0, name.as_bytes());
        put(100, format!("{mode:07o}\0").as_bytes());
        put(108, format!("{owner:07o}\0").as_bytes());
        put(116, format!("{owner:07o}\0").as_bytes());
        put(124, format!("{:011o}\0", data.len()).as_bytes());
        put(136, b"00000000000\0");
        put(148, b"        ");
        put(156, if dir { b"5" } else { b"0" });
        put(257, b"ustar\0");
        put(263, b"00");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        out.resize(512 + data.len().div_ceil(512) * 512, 0);
        out
    }

    /// 本番の helper と同じ解決で得た uid / gid の写像（oci の `IdMap`）。
    fn expected_maps() -> (
        fandhe_container_oci::layer::extract::IdMap,
        fandhe_container_oci::layer::extract::IdMap,
    ) {
        use fandhe_container_oci::layer::extract::{IdMap, IdRange};

        let resolved = fandhe_container_supervisor::start_entry::resolve_self_launch_privilege()
            .unwrap_or_else(|e| fail(&format!("resolve privilege: {e}")));
        let (_, Some(source)) = resolved else {
            fail("a subordinate id range is required");
        };
        let meta = std::fs::metadata("/proc/self")
            .unwrap_or_else(|e| fail(&format!("stat /proc/self: {e}")));
        let maps = source
            .resolve_id_maps(meta.uid(), meta.gid())
            .unwrap_or_else(|e| fail(&format!("resolve id maps: {e}")));
        let conv = |set: &fandhe_container_core::rootless::IdMapSet| {
            IdMap::new(
                set.entries()
                    .iter()
                    .map(|e| IdRange {
                        container_id: e.container_id,
                        host_id: e.host_id,
                        count: e.count,
                    })
                    .collect(),
            )
            .unwrap_or_else(|e| fail(&format!("id map: {e}")))
        };
        (conv(maps.uid()), conv(maps.gid()))
    }

    /// Extract（#4847）: tar の uid / gid（1000）は、名前空間の中では tar の値のまま見え、ホストからは subuid の所有者に見える。
    fn extract_keeps_tar_owners_in_namespace(launcher: &UsernsHelperLauncher, budget: WorkBudget) {
        use std::os::unix::fs::DirBuilderExt as _;

        use fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;
        use fandhe_container_oci::layer::extract::ExtractLimits;
        use fandhe_container_oci::reference::Digest;
        use fandhe_container_plugin_cri::userns_helper::wire::{
            ExtractLayerSpec, ExtractReport, ExtractRequest, ExtractSpecialBits,
        };

        let base = std::env::temp_dir().join(format!("userns-helper-ex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bundle = base.join("bundle");
        let rootfs = bundle.join("rootfs");
        for d in [&base, &bundle, &rootfs] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d)
                .unwrap_or_else(|e| fail(&format!("create {}: {e}", d.display())));
        }
        let mut tar = tar_entry("d/", 0o755, 1000, b"", true);
        tar.extend(tar_entry("d/f", 0o644, 1000, b"owned by 1000", false));
        tar.extend([0u8; 1024]);
        let blob_path = base.join("blob");
        std::fs::write(&blob_path, &tar).unwrap_or_else(|e| fail(&format!("write blob: {e}")));
        std::fs::set_permissions(&blob_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| fail(&format!("chmod blob: {e}")));
        let blob = File::open(&blob_path).unwrap_or_else(|e| fail(&format!("open blob: {e}")));
        let digest = Digest::sha256_of(&tar);
        let layer = ExtractLayerSpec::new(
            "application/vnd.oci.image.layer.v1.tar",
            u64::try_from(tar.len()).unwrap_or(0),
            digest.clone(),
            digest,
        )
        .unwrap_or_else(|e| fail(&format!("layer spec: {e:?}")));
        // 期待する写像は、親が同じ解決で得たもの（helper が参加した写像と指紋で照合される。SEC-5・#4848）。
        let (uid_map, gid_map) = expected_maps();
        let request = ExtractRequest::new(
            ExtractSpecialBits::Strip,
            ExtractLimits::default(),
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            vec![layer],
        )
        .unwrap_or_else(|e| fail(&format!("request: {e:?}")))
        .with_expected_maps(&uid_map, &gid_map);
        let dest = File::open(&rootfs).unwrap_or_else(|e| fail(&format!("open rootfs: {e}")));
        match launcher.run_extract_bounded(
            &request,
            &[blob.as_fd()],
            dest.as_fd(),
            None,
            budget,
            None,
            None,
        ) {
            Ok(ExtractReport {
                layers: 1,
                entries: 2,
            }) => {}
            Ok(other) => fail(&format!("unexpected extract report: {other:?}")),
            Err(e) => fail(&format!("extract: {e} (helper={:?})", e.helper_code())),
        }
        let d = File::open(rootfs.join("d")).unwrap_or_else(|e| fail(&format!("open d: {e}")));
        match launcher.run(Mode::StatTarget, d.as_fd(), budget) {
            Ok(Report::StatTarget(r)) if (r.uid, r.gid, r.mode) == (1000, 1000, 0o755) => {}
            Ok(other) => fail(&format!("unexpected owner in the namespace: {other:?}")),
            Err(e) => fail(&format!("stat d: {e} (helper={:?})", e.helper_code())),
        }
        // 陽性対照: ホストから見た所有者は tar の値（1000）でも自分（euid）でも 0 でもなく、subuid の範囲の値になる。
        let host = std::fs::metadata(rootfs.join("d"))
            .unwrap_or_else(|e| fail(&format!("stat d on the host: {e}")));
        let me = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
        if host.uid() == 1000 || host.uid() == me || host.uid() == 0 {
            fail(&format!(
                "host-side owner is not subordinate: {}",
                host.uid()
            ));
        }
        let bundle_fd = File::open(&bundle).unwrap_or_else(|e| fail(&format!("open bundle: {e}")));
        match launcher.run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            bundle_fd.as_fd(),
            budget,
        ) {
            Ok(Report::Removed) => {}
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("remove: {e} (helper={:?})", e.helper_code())),
        }
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "userns_helper_real: extract keeps tar owners in namespace ok (dir 1000:1000 mode 0755, host owner is subordinate)"
        );
    }

    /// 子の役（#4849）: 範囲写像の user namespace に入り、`other` なら名前空間内の uid / gid 1000（ホストでは別の subuid）に
    /// なって `path` を開く。開けたら 0、開けなければ 1。単一スレッドで処理する（watchdog の前）。
    fn probe_reach(path: &str, other: bool) -> ExitCode {
        use std::os::unix::process::CommandExt as _;
        enter_userns();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "exec 3< \"$1\"", "sh", path])
            .current_dir("/");
        if other {
            cmd.uid(1000).gid(1000);
        }
        match cmd.status() {
            Ok(s) if s.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::from(1),
            Err(e) => fail(&format!("probe spawn: {e}")),
        }
    }

    /// `path` を `--probe-reach` の子で開けるか（`other` は別 uid）。
    fn can_reach(path: &Path, other: bool) -> bool {
        let self_exe =
            std::env::current_exe().unwrap_or_else(|e| fail(&format!("current_exe: {e}")));
        let mut cmd = std::process::Command::new(self_exe);
        cmd.arg("--probe-reach").arg(path);
        if other {
            cmd.arg("other");
        }
        cmd.status()
            .unwrap_or_else(|e| fail(&format!("spawn probe child: {e}")))
            .success()
    }

    /// 対応表（#4801・#4849）: 本番の解決が返す展開設定で、本番の注入点を通して展開する。所有者は名前空間の中で tar の値のまま、
    /// setuid / setgid / sticky は 0700 の bundle を祖先とする閉じ込めで保たれ、別 uid は bundle の下へ届かない。
    fn table_row_extracts_with_tar_owners_and_keeps_special_bits(launcher: &UsernsHelperLauncher) {
        use std::os::unix::fs::DirBuilderExt as _;

        use fandhe_container_cri::adapter::ReleaseBudget;
        use fandhe_container_cri::bundle::SubordinateLayerExtractor as _;
        use fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;
        use fandhe_container_oci::layer::VerifiedLayerBlob;
        use fandhe_container_oci::layer::extract::{
            ExtractLimits, ExtractRoot, IdMap, ImageLayer, OwnershipPolicy, SpecialBitsPolicy,
        };
        use fandhe_container_oci::reference::Digest;
        use fandhe_container_plugin_cri::extract_identity::{
            extract_options_for, resolve_extract_identity,
        };
        use fandhe_container_plugin_cri::userns_helper::UsernsLayerExtractor;

        let identity = resolve_extract_identity()
            .unwrap_or_else(|e| fail(&format!("resolve identity: {}", e.message())));
        let options = extract_options_for(&identity);
        let (uid_map, gid_map) = expected_maps();
        if options.ownership
            != (OwnershipPolicy::ChownInUserNamespace {
                uid: uid_map.clone(),
                gid: gid_map.clone(),
            })
            || options.special_bits != SpecialBitsPolicy::PreserveIfChowned
        {
            fail(&format!("unexpected table row: {options:?}"));
        }

        let base = std::env::temp_dir().join(format!("userns-helper-tb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bundle = base.join("bundle");
        for d in [&base, &bundle] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d)
                .unwrap_or_else(|e| fail(&format!("create {}: {e}", d.display())));
        }
        // 別 uid の到達不能を bundle だけに負わせるため、その上の base は他者が辿れるようにする。
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| fail(&format!("chmod base: {e}")));
        let mut tar = tar_entry("d/", 0o755, 1000, b"", true);
        tar.extend(tar_entry("d/f", 0o644, 1000, b"f", false));
        tar.extend(tar_entry("d/s", 0o4755, 0, b"s", false));
        tar.extend(tar_entry("d/g", 0o2755, 1000, b"g", false));
        tar.extend([0u8; 1024]);
        let blob_path = base.join("blob");
        std::fs::write(&blob_path, &tar).unwrap_or_else(|e| fail(&format!("write blob: {e}")));
        std::fs::set_permissions(&blob_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| fail(&format!("chmod blob: {e}")));
        let digest = Digest::sha256_of(&tar);
        let me = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
        let verified = VerifiedLayerBlob::from_file(
            File::open(&blob_path).unwrap_or_else(|e| fail(&format!("open blob: {e}"))),
            &digest,
            u64::try_from(tar.len()).unwrap_or(0),
            me,
        )
        .unwrap_or_else(|e| fail(&format!("verified blob: {e}")));
        let root = ExtractRoot::create_private_dir(&bundle.join("rootfs"))
            .unwrap_or_else(|e| fail(&format!("create root: {e}")));
        // create の `open_rootfs_for_search` と同じく rootfs を 0755 にし、閉じ込めは 0700 の bundle（祖先）が担う。
        std::fs::set_permissions(
            bundle.join("rootfs"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap_or_else(|e| fail(&format!("chmod rootfs: {e}")));
        let ancestor = ExtractRoot::open_existing_dir(&bundle)
            .unwrap_or_else(|e| fail(&format!("open ancestor: {e}")));
        let layers = [ImageLayer::new(
            &verified,
            "application/vnd.oci.image.layer.v1.tar",
            &digest,
        )];
        let extractor = UsernsLayerExtractor::with_launcher_and_limit(
            UsernsHelperLauncher::with_fixed_command(BIN, vec![USERNS_HELPER_ARG.into()]),
            1,
        );
        extractor
            .extract_layers(
                &layers,
                &root,
                Some(&ancestor),
                DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
                ExtractLimits::default(),
                &options,
                &ReleaseBudget::new(),
            )
            .unwrap_or_else(|e| fail(&format!("extract_layers: {e}")));

        let budget =
            WorkBudget::new(Duration::from_secs(10)).unwrap_or_else(|e| fail(&e.to_string()));
        let stat = |rel: &str| {
            let f = File::open(bundle.join("rootfs").join(rel))
                .unwrap_or_else(|e| fail(&format!("open {rel}: {e}")));
            match launcher.run(Mode::StatTarget, f.as_fd(), budget) {
                Ok(Report::StatTarget(r)) => (r.uid, r.gid, r.mode),
                other => fail(&format!("stat {rel}: {other:?}")),
            }
        };
        // 名前空間の中から見た所有者は StatTarget で確かめる（StatTarget はディレクトリだけを受ける）。
        let got = stat("d");
        if got != (1000, 1000, 0o755) {
            fail(&format!("d: got {got:?}, want (1000, 1000, 0o755)"));
        }
        // ファイルはホスト側で確かめる: 所有者は tar の値を写像で変換したホストの ID、mode はホストから見ても同じ値
        // （setuid・setgid が保たれたことはここで分かる）。
        let host_of = |map: &IdMap, id: u32| {
            map.map_to_host(id)
                .unwrap_or_else(|| fail(&format!("id {id} is not in the subordinate map")))
        };
        for (rel, owner, want_mode) in [
            ("d/f", 1000, 0o644),
            // tar の uid 0 は名前空間の root。setuid（04755）は所有者が写像先の root のため保たれる。
            ("d/s", 0, 0o4755),
            // setgid（02755）は所有 gid が tar の gid の写像先と一致するため保たれる。
            ("d/g", 1000, 0o2755),
        ] {
            let m = std::fs::metadata(bundle.join("rootfs").join(rel))
                .unwrap_or_else(|e| fail(&format!("stat {rel} on the host: {e}")));
            let got = (m.uid(), m.gid(), m.mode() & 0o7777);
            let want = (
                host_of(&uid_map, owner),
                host_of(&gid_map, owner),
                want_mode,
            );
            if got != want {
                fail(&format!("{rel} on the host: got {got:?}, want {want:?}"));
            }
        }
        // 陽性対照: ホストから見た d の所有者は subuid の範囲の値（自分の uid・0・tar の値のままではない）。
        let host = std::fs::metadata(bundle.join("rootfs/d"))
            .unwrap_or_else(|e| fail(&format!("stat d on the host: {e}")));
        if host.uid() == 1000 || host.uid() == me || host.uid() == 0 {
            fail(&format!(
                "host-side owner is not subordinate: {}",
                host.uid()
            ));
        }
        // 別 uid（名前空間内の uid 1000）は、保たれた setuid のファイルがあっても 0700 の bundle の下へ届かない。
        let suid = bundle.join("rootfs/d/s");
        if can_reach(&suid, true) {
            fail("another uid reached below the 0700 bundle");
        }
        // 陽性対照 1: 同じ子の役でも uid を変えなければ（名前空間の root = 起動ユーザー）届く。
        if !can_reach(&suid, false) {
            fail("positive control: the owner could not reach the file");
        }
        // 陽性対照 2: bundle を一時的に 0711 にすると別 uid も届く（到達不能が bundle の 0700 によることの確認）。
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o711))
            .unwrap_or_else(|e| fail(&format!("chmod bundle open: {e}")));
        let reached = can_reach(&suid, true);
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| fail(&format!("chmod bundle back: {e}")));
        if !reached {
            fail("positive control: another uid could not reach the file under a 0711 bundle");
        }
        let bundle_fd = File::open(&bundle).unwrap_or_else(|e| fail(&format!("open bundle: {e}")));
        match launcher.run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            bundle_fd.as_fd(),
            budget,
        ) {
            Ok(Report::Removed) => {}
            other => fail(&format!("remove: {other:?}")),
        }
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "userns_helper_real: table row extracts with tar owners and keeps special bits ok (dir 1000:1000 mode 0755, setuid/setgid kept under a 0700 bundle with rootfs 0755, other uid cannot reach below the bundle, host owner is subordinate)"
        );
    }

    /// 自分が所有する 0700 のディレクトリ（名前空間の中では uid 0 の所有に見える）。
    fn scratch_dir() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = std::env::temp_dir().join(format!("userns-helper-real-{}", std::process::id()));
        let _ = std::fs::remove_dir(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .unwrap_or_else(|e| fail(&format!("create scratch dir: {e}")));
        dir
    }
}
