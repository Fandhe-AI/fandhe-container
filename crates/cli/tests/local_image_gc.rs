//! CLI の実バイナリで本物の running / stopped のコンテナを作り、`image rm` の既定の拒否と `--force` の境界を確かめる
//! 実機前提の結合試験（#663・TASK-184.1・OCI-7・CLI-1・REPAIR-5・REPAIR-12。MS-6）。
//!
//! # 既存の試験との分担
//! - oci の `image_management*.rs`: 公開 API だけをつないだ層。コンテナの状態は合成した集合で与える。
//! - cli の `image.rs` 内の単体試験: `image rm` の判定を合成スナップショットで照合する。
//!
//! 本試験は CLI の `create --image` → `start` → `stop` → `image rm [--force]` → `image ls` を実バイナリで通し、
//! 状態ストアの本物の running / stopped を参照元にして境界を観測する。置き場所は issue の記載（`crates/oci/tests/`）と違い
//! cli にある（`CARGO_BIN_EXE_*` は cli の試験でしか定義されず、oci から cli への依存は逆向きになるため）。
//!
//! # シナリオ
//! - A: running のコンテナが参照するイメージへの `image rm`（`--force` なし・あり）は `FAILED_PRECONDITION`（終了コード 5）で拒否され、
//!   タグ・コンテナ参照・blob は変わらない。
//! - B: stopped のコンテナだけが参照するイメージへの `--force` なしの `image rm` は拒否される。`--force` ありはタグだけを外し
//!   （`untagged` の 1 行のみ）、config / layer の blob・在庫の manifest・コンテナ参照は残る。
//! - C（補助）: タグの外れた digest から新しいコンテナを create → start できる。
//!
//! # 未充足の受け入れ条件（要オーナー判断）
//! 「`--force` 後に参照元の停止中コンテナを `start` できる」は現行の契約では観測できない。core の `start` は `Created` 以外を
//! `FAILED_PRECONDITION` で拒否し、CLI に停止したコンテナを再起動する経路が無い。本試験はこの拒否を期待値として固定しない
//! （B のコンテナには `start` を送らない）。C は残った manifest が参照の登録と起動に使えることの観測で、停止したコンテナ自身の
//! 再起動ではない。また `create --image` は展開器なしで、`start` はストアの blob を読まない（#2377）ため、C の成否は
//! レイヤーが残った証拠にならない。レイヤーの残存は blob ファイルの大きさで直接照合する。
//!
//! # 必要環境
//! Linux 6.12 以上（Landlock ABI 6 以上）・cgroup v2・非 root・非特権 user namespace・`systemd-run --user`（user マネージャ）。
//! 試験全体を `systemd-run --user --scope -p Delegate=yes` で包んで実行する。事前に `cargo build -p fandhe-container-supervisor`
//! を行う。CLI と supervisor は作業ディレクトリへ 0755 でコピーし、特権ランチャーは置かない。前提が欠けたら skip ではなく失敗する。
//!
//! # 実機前提テストとしての分離
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。未指定は案内を出して成功する。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor
//! cargo test -p fandhe-container-cli --test local_image_gc --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/local_image_gc-XXXX> --ignored
//! ```
//!
//! 前提欠如は 1 行目が `local_image_gc: PRECONDITION FAILED (test environment, ...)`、それ以外の失敗は
//! `local_image_gc: FAILED: ...`。CI は両方を禁止行にし、成功行を `scripts/check-success-lines.sh` が照合する。
//! Agent はホストに transient scope と cgroup を作るため手元では実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("local_image_gc: skipped (linux only)");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("local_image_gc: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    }
    linux::main()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/minimal_rootfs.rs"]
mod minimal_rootfs;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::fs;
    use std::io::{Read, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::SIGTERM_HANDLER_EXIT_CODE_FOR_TEST;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{ContainerId, GetStateRequest, StateStore};
    use fandhe_container_oci::image_management::{
        ImageStore, ImageTagSource, ManifestComposition, TagKey,
    };
    use fandhe_container_oci::reference::{Digest, ImageReference, Reference};

    /// `start` を待つ上限（CLI 自身の受信期限より長く取る。REPAIR-5）。
    const START_TIMEOUT: Duration = Duration::from_secs(90);
    /// `start` 以外の CLI を待つ上限（REPAIR-5）。
    const CLI_TIMEOUT: Duration = Duration::from_secs(30);
    /// kill 後の回収・出力収集の上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 状態・ハンドラ登録の待ちの上限（REPAIR-5）。
    const STATE_TIMEOUT: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(20);
    /// プローブの寿命の上限。これを過ぎたら終了コード 8 で終わる（寿命切れを停止と取り違えないための目印）。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// `/proc/<pid>/status` の `SigCgt` で SIGTERM（15）に当たるビット（1 << 14）。
    const SIGTERM_CAUGHT_BIT: u64 = 1 << 14;

    /// 在庫のタグ（ダミーのレジストリ名。資格情報は含まない）。
    const TAG_RUN: &str = "registry.example/fandhe/gc-run:v1";
    const TAG_STOP: &str = "registry.example/fandhe/gc-stopped:v1";
    /// `image ls` の REPOSITORY 列と TAG 列。
    const LS_RUN: &str = "registry.example/fandhe/gc-run\tv1";
    const LS_STOP: &str = "registry.example/fandhe/gc-stopped\tv1";
    /// `image rm` の拒否の文言（`crates/cli/src/commands/image.rs` の固定文字列。コンテナ ID は含まない）。
    const MSG_IN_USE: &str = "image is in use by a container";
    const MSG_IN_USE_HINT: &str = "image is in use by a container; use --force to untag images used only by stopped containers";
    const LS_HEADER: &str = "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n";

    /// 1 つの manifest の在庫（digest と、config・layer の blob の 16 進名と大きさ）。
    struct Fixture {
        manifest_hex: String,
        blobs: [(String, usize); 3],
    }

    impl Fixture {
        /// manifest の digest と blob 名は固定の 64 桁の 16 進にする（ストアは blob の内容を digest で照合しない）。
        /// 先頭 1 つが config、残りが layer。
        fn new(manifest: char, names: [char; 3], sizes: [usize; 3]) -> Self {
            let hex = |k: char| std::iter::repeat_n(k, 64).collect::<String>();
            Self {
                manifest_hex: hex(manifest),
                blobs: [
                    (hex(names[0]), sizes[0]),
                    (hex(names[1]), sizes[1]),
                    (hex(names[2]), sizes[2]),
                ],
            }
        }
        fn digest(&self) -> String {
            format!("sha256:{}", self.manifest_hex)
        }
        fn size(&self) -> usize {
            self.blobs.iter().map(|b| b.1).sum()
        }
    }

    /// コンテナ内で動くプローブ。SIGTERM のハンドラ（`_exit(43)`）を登録して待つ。
    pub fn probe() -> ! {
        let mut out = std::io::stdout();
        if let Err(e) = fandhe_container_core::exec::exit_on_sigterm_for_test() {
            let _ = writeln!(out, "TERM_HANDLER_FAILED {e}");
            let _ = out.flush();
            std::process::exit(9);
        }
        let _ = writeln!(out, "READY_TERM");
        let _ = out.flush();
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    pub fn main() -> ExitCode {
        super::precondition::self_check();
        if !std::env::args().skip(1).any(|a| a == "--ignored") {
            println!(
                "local_image_gc: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            return ExitCode::SUCCESS;
        }
        match scenario() {
            Ok(()) => {
                println!(
                    "local_image_gc: image rm --force on an image used by a running container was refused with FAILED_PRECONDITION; tag, container reference and blobs were kept"
                );
                println!(
                    "local_image_gc: image rm without --force on an image used only by a stopped container was refused with FAILED_PRECONDITION; tag and blobs were kept"
                );
                println!(
                    "local_image_gc: image rm --force on an image used only by a stopped container removed only the tag; config and layer blobs, the manifest entry and the container reference were kept"
                );
                println!(
                    "local_image_gc: a new container created from the untagged manifest digest started; restarting the stopped container itself is out of scope (start accepts only created)"
                );
                println!("local_image_gc: scenario ok");
                ExitCode::SUCCESS
            }
            Err(super::precondition::Failure::Precondition(msg)) => {
                eprintln!("{msg}");
                ExitCode::FAILURE
            }
            Err(super::precondition::Failure::Other(e)) => {
                eprintln!("local_image_gc: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn expect(cond: bool, what: &str) -> Result<(), String> {
        if cond { Ok(()) } else { Err(what.to_string()) }
    }

    /// 失敗時の後始末。生きている ID を CLI の `stop`・`delete`（`NOT_FOUND` も成功扱い）で回収し、作業ディレクトリを消す。
    /// `state.json` の pid へ生の kill は送らない（PID 再利用で無関係なプロセスを止めない。SEC-1）。
    struct Cleanup {
        cli: PathBuf,
        work: PathBuf,
        root: String,
        images: String,
        live: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let mut left = false;
            for id in std::mem::take(&mut self.live) {
                if let Err(e) =
                    run_cli(&self.cli, &["--root", &self.root, "stop", &id], CLI_TIMEOUT)
                {
                    eprintln!("local_image_gc: cleanup stop failed: {e}");
                }
                let mut last = String::from("not attempted");
                let ok = wait_until(
                    STATE_TIMEOUT,
                    "cleanup delete to succeed",
                    || match run_cli(
                        &self.cli,
                        &[
                            "--root",
                            &self.root,
                            "delete",
                            "--image-root",
                            &self.images,
                            &id,
                        ],
                        CLI_TIMEOUT,
                    ) {
                        Ok(o) if o.code == Some(0) || o.code == Some(3) => true,
                        Ok(o) => {
                            last = format!("exit {:?} stderr={:?}", o.code, o.stderr);
                            false
                        }
                        Err(e) => {
                            last = e;
                            false
                        }
                    },
                );
                if let Err(e) = ok {
                    eprintln!("local_image_gc: cleanup delete failed ({e}; last: {last})");
                    left = true;
                }
            }
            if left {
                eprintln!(
                    "local_image_gc: leaving {} for diagnosis",
                    self.work.display()
                );
                return;
            }
            if let Err(e) = fs::remove_dir_all(&self.work) {
                eprintln!("local_image_gc: cleanup remove work dir failed: {e}");
            }
            // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避。#2887）。
            super::scratch_root::remove_scratch_root();
        }
    }

    /// 前提の検査。欠けたら skip せず失敗にする。
    ///
    /// 委譲 cgroup と Landlock ABI の欠如だけを `PRECONDITION FAILED` にする（`network_modes_real` と同じ分類。#2957）。
    fn check_prerequisites() -> Result<(), super::precondition::Failure> {
        if effective_uid()? == 0 {
            return Err("must run as a non-root user: this test covers the rootless path".into());
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(
                "cgroup v2 is required (/sys/fs/cgroup/cgroup.controllers is missing)".into(),
            );
        }
        let hint = "run this test inside `systemd-run --user --scope -p Delegate=yes`";
        let delegated = super::precondition::delegated_cgroup()?;
        let own = fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
        let own_path = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or("no cgroup v2 line in /proc/self/cgroup")?;
        if own_path.trim_end_matches('/') != delegated.path().trim_end_matches('/') {
            return Err(format!("detected cgroup differs from own cgroup; {hint}").into());
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
        let private = Path::new(&runtime).join("systemd/private");
        let is_socket = fs::symlink_metadata(&private)
            .map(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()))
            .unwrap_or(false);
        expect(is_socket, "the systemd user manager socket is missing")?;
        super::precondition::landlock_support()?;
        Ok(())
    }

    fn scenario() -> Result<(), super::precondition::Failure> {
        check_prerequisites()?;
        scenario_body().map_err(super::precondition::Failure::Other)
    }

    /// シナリオが共有する環境。
    struct Env {
        cli: PathBuf,
        root: PathBuf,
        root_s: String,
        images: PathBuf,
        images_s: String,
        work: PathBuf,
        sup_needle: Vec<u8>,
        root_needle: Vec<u8>,
    }

    /// 起動済みのコンテナ。
    struct Running {
        id_s: String,
        id: ContainerId,
        pid: u32,
    }

    /// 前提の検査を終えた後の本体。ここでの失敗は回帰として扱う。
    fn scenario_body() -> Result<(), String> {
        let cli_src = PathBuf::from(env!("CARGO_BIN_EXE_fandhe-container"));
        let sup_src = cli_src
            .parent()
            .map(|d| d.join("fandhe-container-supervisor"))
            .ok_or("cli has no parent directory")?;
        if !sup_src.is_file() {
            return Err(format!(
                "{} is missing; run `cargo build -p fandhe-container-supervisor` first",
                sup_src.display()
            ));
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let work = super::scratch_root::scratch_root("fandhe-lig-real-scratch", CLI_TIMEOUT)
            .join(format!("fandhe-lig-real-{}-{nanos}", std::process::id()));
        fs::create_dir(&work).map_err(|e| format!("create work dir: {e}"))?;
        set_mode(&work, 0o700)?;
        let root = work.join("state");
        let root_s = root.to_str().ok_or("work dir is not UTF-8")?.to_string();
        let images = work.join("images");
        let images_s = images.to_str().ok_or("work dir is not UTF-8")?.to_string();
        let mut cleanup = Cleanup {
            cli: PathBuf::new(),
            work: work.clone(),
            root: root_s.clone(),
            images: images_s.clone(),
            live: Vec::new(),
        };

        // CLI と supervisor を 0755 でコピーする。特権ランチャーは置かない（置くと rootful 経路に入る）。
        let bin = work.join("bin");
        fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        set_mode(&bin, 0o755)?;
        let cli = bin.join("fandhe-container");
        fs::copy(&cli_src, &cli).map_err(|e| format!("copy cli: {e}"))?;
        set_mode(&cli, 0o755)?;
        let supervisor = bin.join("fandhe-container-supervisor");
        fs::copy(&sup_src, &supervisor).map_err(|e| format!("copy supervisor: {e}"))?;
        set_mode(&supervisor, 0o755)?;
        expect(
            !bin.join("fandhe-container-launcher").exists(),
            "a privileged launcher must not sit next to the cli",
        )?;
        cleanup.cli = cli.clone();
        fs::create_dir(&root).map_err(|e| format!("mkdir state root: {e}"))?;
        set_mode(&root, 0o700)?;

        // 在庫: manifest 2 件（共有する blob は無い）と、それぞれにタグ 1 件。
        let fx_run = Fixture::new('1', ['a', 'b', 'c'], [10, 20, 30]);
        let fx_stop = Fixture::new('2', ['d', 'e', 'f'], [11, 21, 31]);
        fs::create_dir(&images).map_err(|e| format!("mkdir images: {e}"))?;
        set_mode(&images, 0o700)?;
        seed_inventory(&images, &fx_run, TAG_RUN)?;
        seed_inventory(&images, &fx_stop, TAG_STOP)?;

        let env = Env {
            cli,
            root,
            root_s: root_s.clone(),
            images,
            images_s,
            work,
            sup_needle: supervisor.to_string_lossy().into_owned().into_bytes(),
            root_needle: root_s.into_bytes(),
        };
        let pid = std::process::id();
        let id_run = format!("gcrun{pid}");
        let id_stop = format!("gcstop{pid}");
        let id_new = format!("gcnew{pid}");

        // 参照 Display の表記は oci の TagKey から導く（正規化後の表記を推測で書かない）。
        expect(
            tag_key(TAG_STOP)?.to_string() == TAG_STOP,
            "TagKey display differs from the literal tag",
        )?;

        // A: running のコンテナが参照するイメージ
        let run = launch(&env, &mut cleanup, &id_run, "bundle-run", TAG_RUN)?;
        refuse_rm(&env, &[TAG_RUN], MSG_IN_USE_HINT)?;
        refuse_rm(&env, &["--force", TAG_RUN], MSG_IN_USE)?;
        expect_unchanged(&env, &fx_run, LS_RUN, &id_run)?;

        // B: stopped のコンテナだけが参照するイメージ
        let stopped = launch(&env, &mut cleanup, &id_stop, "bundle-stop", TAG_STOP)?;
        stop_container(&env, &stopped)?;
        refuse_rm(&env, &[TAG_STOP], MSG_IN_USE_HINT)?;
        expect_unchanged(&env, &fx_stop, LS_STOP, &id_stop)?;

        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "image",
                "rm",
                "--force",
                "--image-root",
                &env.images_s,
                TAG_STOP,
            ],
            CLI_TIMEOUT,
        )?;
        let want_stdout = format!("untagged\t{TAG_STOP}\n");
        if out.code != Some(0) || out.stdout != want_stdout || !out.stderr.is_empty() {
            return Err(format!(
                "image rm --force (stopped): want exit 0 stdout={want_stdout:?}, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        // タグだけが外れた: ls はタグなし行になり、blob と参照は残る。
        let ls = image_ls(&env)?;
        let want_dangling = format!("-\t-\t{}\t{}\t0\n", fx_stop.digest(), fx_stop.size());
        let want_run_row = format!("{LS_RUN}\t{}\t{}\t0\n", fx_run.digest(), fx_run.size());
        expect(
            ls == format!("{LS_HEADER}{want_run_row}{want_dangling}"),
            &format!("image ls after --force on the stopped image: {ls:?}"),
        )?;
        expect_blobs(&env, &fx_stop)?;
        expect_blobs(&env, &fx_run)?;
        let (containers, tags) = references(&env, &fx_stop)?;
        expect(
            containers.len() == 1 && containers[0].ends_with(&format!(".{id_stop}")),
            &format!("stopped container reference was not kept: {containers:?}"),
        )?;
        expect(tags.is_empty(), &format!("tags remain: {tags:?}"))?;
        let (containers, tags) = references(&env, &fx_run)?;
        expect(
            containers.len() == 1 && tags == [TAG_RUN],
            &format!("running image changed: {containers:?} {tags:?}"),
        )?;

        // C（補助）: タグの外れた digest から新しいコンテナを作って動かす。停止したコンテナ自身の再起動ではない
        // （start は Created だけを受ける）。展開器（#2377）が入るまでレイヤーの使用は観測できない。
        let fresh = launch(&env, &mut cleanup, &id_new, "bundle-new", &fx_stop.digest())?;
        stop_container(&env, &fresh)?;
        delete_container(&env, &mut cleanup, &fresh)?;

        // 後始末
        stop_container(&env, &run)?;
        delete_container(&env, &mut cleanup, &run)?;
        delete_container(&env, &mut cleanup, &stopped)?;
        Ok(())
    }

    /// 在庫へ manifest 1 件と blob ファイルを置き、タグを付ける。ストアとガードはこの関数の中で手放す。
    fn seed_inventory(images: &Path, fx: &Fixture, tag: &str) -> Result<(), String> {
        let blobs = images.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).map_err(|e| format!("mkdir blobs: {e}"))?;
        for (name, len) in &fx.blobs {
            fs::write(blobs.join(name), vec![b'x'; *len])
                .map_err(|e| format!("write blob: {e}"))?;
        }
        let digest = |hex: &str| {
            Digest::parse(&format!("sha256:{hex}")).map_err(|e| format!("digest: {e:?}"))
        };
        let comp = ManifestComposition::new(
            digest(&fx.blobs[0].0)?,
            vec![digest(&fx.blobs[1].0)?, digest(&fx.blobs[2].0)?],
        )
        .map_err(|e| format!("composition: {e:?}"))?;
        let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
        store
            .lock()
            .map_err(|e| format!("lock: {e:?}"))?
            .register_manifest(digest(&fx.manifest_hex)?, comp)
            .map_err(|e| format!("register: {e:?}"))?;
        store
            .tag_image(
                &ImageTagSource::Manifest(digest(&fx.manifest_hex)?),
                tag_key(tag)?,
            )
            .map_err(|e| format!("tag: {e:?}"))?;
        Ok(())
    }

    fn tag_key(tag: &str) -> Result<TagKey, String> {
        let r = ImageReference::parse(tag).map_err(|e| format!("parse {tag}: {e:?}"))?;
        let Reference::Tag(t) = r.reference() else {
            return Err(format!("{tag} is not a tag reference"));
        };
        Ok(TagKey::new(
            r.registry().clone(),
            r.repository().clone(),
            t.clone(),
        ))
    }

    /// manifest を参照するコンテナ（参照 ID の文字列）とタグ（Display）を、永続化された在庫から読む。
    fn references(env: &Env, fx: &Fixture) -> Result<(Vec<String>, Vec<String>), String> {
        let store = ImageStore::open(&env.images).map_err(|e| format!("open store: {e:?}"))?;
        let d = Digest::parse(&fx.digest()).map_err(|e| format!("digest: {e:?}"))?;
        let refs = store
            .lock()
            .map_err(|e| format!("lock: {e:?}"))?
            .manifest_references(&d);
        Ok((
            refs.containers
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            refs.tags.iter().map(ToString::to_string).collect(),
        ))
    }

    /// config と layer の blob ファイルが全部、既知の大きさで残っていること。
    fn expect_blobs(env: &Env, fx: &Fixture) -> Result<(), String> {
        for (name, len) in &fx.blobs {
            let path = env.images.join("blobs").join("sha256").join(name);
            let md = fs::metadata(&path).map_err(|e| format!("blob {name} is gone: {e}"))?;
            expect(
                md.len() == *len as u64,
                &format!("blob {name}: want {len} bytes, got {}", md.len()),
            )?;
        }
        Ok(())
    }

    /// 拒否後にタグ・コンテナ参照・blob が変わっていないこと。
    fn expect_unchanged(env: &Env, fx: &Fixture, ls_prefix: &str, id: &str) -> Result<(), String> {
        let ls = image_ls(env)?;
        let row = format!("{ls_prefix}\t{}\t{}\t0\n", fx.digest(), fx.size());
        expect(
            ls.contains(&row),
            &format!("image ls lacks the row {row:?}: {ls:?}"),
        )?;
        expect_blobs(env, fx)?;
        let (containers, tags) = references(env, fx)?;
        expect(
            containers.len() == 1 && containers[0].ends_with(&format!(".{id}")),
            &format!("container references changed: {containers:?}"),
        )?;
        expect(tags.len() == 1, &format!("tags changed: {tags:?}"))
    }

    fn image_ls(env: &Env) -> Result<String, String> {
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "image",
                "ls",
                "--image-root",
                &env.images_s,
            ],
            CLI_TIMEOUT,
        )?;
        if out.code != Some(0) || !out.stderr.is_empty() {
            return Err(format!(
                "image ls: got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(out.stdout)
    }

    /// `image rm [--force] <ref>` が終了コード 5・`FAILED_PRECONDITION`・固定の文言・空の stdout で拒否されること。
    /// `args` は `--force` と参照（順序は呼び出し側）。
    fn refuse_rm(env: &Env, args: &[&str], want_message: &str) -> Result<(), String> {
        let mut full = vec!["--root", env.root_s.as_str(), "image", "rm"];
        let (flags, target) = args.split_at(args.len() - 1);
        full.extend_from_slice(flags);
        full.extend_from_slice(&["--image-root", env.images_s.as_str()]);
        full.extend_from_slice(target);
        let out = run_cli(&env.cli, &full, CLI_TIMEOUT)?;
        if out.code != Some(5) || !out.stdout.is_empty() {
            return Err(format!(
                "image rm {args:?}: want exit 5, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let code = stderr_field(&out.stderr, "code")?;
        let message = stderr_field(&out.stderr, "message")?;
        if code != "FAILED_PRECONDITION" || message != want_message {
            return Err(format!(
                "image rm {args:?}: want FAILED_PRECONDITION {want_message:?}, got {code} {message:?}"
            ));
        }
        Ok(())
    }

    /// create（`--image`）→ start → list が running → SIGTERM のハンドラ登録まで進める。
    fn launch(
        env: &Env,
        cleanup: &mut Cleanup,
        id_s: &str,
        bundle_name: &str,
        image: &str,
    ) -> Result<Running, String> {
        let bundle = env.work.join(bundle_name);
        make_bundle(&bundle)?;
        let bundle_s = bundle.to_str().ok_or("bundle path is not UTF-8")?;
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "create",
                "--image-root",
                &env.images_s,
                "--image",
                image,
                "--bundle",
                bundle_s,
                id_s,
            ],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, "create")?;
        cleanup.live.push(id_s.to_string());
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "start", id_s],
            START_TIMEOUT,
        )?;
        expect_ok(&out, "start")?;
        let out = run_cli(&env.cli, &["--root", &env.root_s, "list"], CLI_TIMEOUT)?;
        let pid = parse_running_list(&out, id_s)?;
        wait_sigterm_handler(pid, "SIGTERM handler registration")?;
        let id = ContainerId::new(id_s.to_string()).map_err(|e| format!("id: {e:?}"))?;
        Ok(Running {
            id_s: id_s.to_string(),
            id,
            pid,
        })
    }

    /// stop → list が stopped → 終了コード 43 → プロセスの消滅 → supervisor の終了まで確かめる。
    fn stop_container(env: &Env, run: &Running) -> Result<(), String> {
        let id_s = run.id_s.as_str();
        let out = run_cli(
            &env.cli,
            &["--root", &env.root_s, "stop", id_s],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, "stop")?;
        let row = format!("{id_s}\tstopped\t-\n");
        wait_until(STATE_TIMEOUT, "list to report stopped", || {
            run_cli(&env.cli, &["--root", &env.root_s, "list"], CLI_TIMEOUT)
                .is_ok_and(|o| o.code == Some(0) && o.stdout.contains(&row))
        })?;
        let store = {
            let root =
                StateRoot::from_override(env.root.clone()).map_err(|e| format!("root: {e:?}"))?;
            FileStateStore::open(root).map_err(|e| format!("open store: {e:?}"))?
        };
        let rec = store
            .get(&GetStateRequest::new(run.id.clone()))
            .map_err(|e| format!("get: {e:?}"))?;
        if rec.status().exit_code() != Some(SIGTERM_HANDLER_EXIT_CODE_FOR_TEST) {
            return Err(format!(
                "exit code after stop: want {SIGTERM_HANDLER_EXIT_CODE_FOR_TEST}, got {:?}",
                rec.status().exit_code()
            ));
        }
        drop(store);
        let pid = run.pid;
        wait_until(REAP_TIMEOUT, "the container process to vanish", || {
            !Path::new(&format!("/proc/{pid}")).exists()
        })?;
        wait_until(REAP_TIMEOUT, "the supervisor to exit", || {
            count_processes(|dir| {
                fs::read(dir.join("cmdline")).is_ok_and(|c| {
                    c.starts_with(&env.sup_needle)
                        && c.windows(env.root_needle.len())
                            .any(|w| w == env.root_needle.as_slice())
                        && c.windows(run.id_s.len()).any(|w| w == run.id_s.as_bytes())
                })
            }) == 0
        })
    }

    /// 停止済みのコンテナを `--image-root` つきで delete する（参照の解除）。2 回目は `NOT_FOUND`（3）。
    fn delete_container(env: &Env, cleanup: &mut Cleanup, run: &Running) -> Result<(), String> {
        let id_s = run.id_s.as_str();
        let args = [
            "--root",
            env.root_s.as_str(),
            "delete",
            "--image-root",
            env.images_s.as_str(),
            id_s,
        ];
        let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
        expect_ok(&out, "delete")?;
        cleanup.live.retain(|i| i != id_s);
        let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
        if out.code != Some(3) || !out.stdout.is_empty() {
            return Err(format!(
                "second delete: want exit 3, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let code = stderr_field(&out.stderr, "code")?;
        expect(
            code == "NOT_FOUND",
            &format!("second delete: want NOT_FOUND, got {code}"),
        )
    }

    /// bundle（`config.json` と最小 rootfs）を作る。`/probe` は本試験の実行ファイルのコピー。
    fn make_bundle(bundle: &Path) -> Result<(), String> {
        super::minimal_rootfs::mkdir(bundle)?;
        let rootfs = bundle.join("rootfs");
        let ld = super::minimal_rootfs::install_binary_at(
            &rootfs,
            "probe",
            &["proc", "dev", "tmp", "etc"],
        )?;
        // uidMappings / gidMappings・cgroupsPath は書かない。ネットワークはモード省略（none）で既定のまま。
        let config = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-lig",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        );
        fs::write(bundle.join("config.json"), config).map_err(|e| format!("write config: {e}"))
    }

    /// `/proc/<pid>/status` の `SigCgt` に SIGTERM のビットが立つまで待つ（登録前に TERM を送ると PID 1 では捨てられる）。
    fn wait_sigterm_handler(pid: u32, what: &str) -> Result<(), String> {
        wait_until(STATE_TIMEOUT, what, || {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("SigCgt:"))
                        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                })
                .is_some_and(|m| m & SIGTERM_CAUGHT_BIT != 0)
        })
    }

    /// 子を kill し、`REAP_TIMEOUT` 内に `try_wait` で回収する（無期限の `wait` を避ける。REPAIR-5）。
    fn kill_and_reap(c: &mut Child) -> Result<(), String> {
        let kill_err = c.kill().err();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match c.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() >= deadline => {
                    return Err(format!(
                        "child was not reaped within {REAP_TIMEOUT:?} (kill: {kill_err:?})"
                    ));
                }
                Ok(None) => thread::sleep(POLL),
                Err(e) => return Err(format!("reap child: {e}")),
            }
        }
    }

    fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))
    }

    fn wait_until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        loop {
            if f() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out after {limit:?} waiting for {what}"));
            }
            thread::sleep(POLL);
        }
    }

    /// `/proc` の全プロセスのうち、`/proc/<pid>` のディレクトリが条件に合うものの数。
    fn count_processes(pred: impl Fn(&Path) -> bool) -> usize {
        let Ok(dir) = fs::read_dir("/proc") else {
            return 0;
        };
        dir.flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
                    && pred(&e.path())
            })
            .count()
    }

    /// `list` の stdout に `<id>\trunning\t<pid>` の行があることを確かめ、pid を返す。
    fn parse_running_list(out: &RunOut, id: &str) -> Result<u32, String> {
        if out.code != Some(0) {
            return Err(format!(
                "list: want exit 0, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let prefix = format!("{id}\trunning\t");
        let row = out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .ok_or_else(|| format!("list row: {:?}", out.stdout))?;
        let pid: u32 = row.parse().map_err(|_| format!("list pid: {row:?}"))?;
        expect(pid > 0, "list pid must be positive")?;
        Ok(pid)
    }

    /// 終了コード 0・stdout と stderr が空。
    fn expect_ok(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) || !out.stdout.is_empty() || !out.stderr.is_empty() {
            return Err(format!(
                "{what}: want exit 0 with empty output, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    /// 1 行の JSON エラーから文字列フィールドを取り出す（エスケープを含む値は対象外。固定語彙の照合用）。
    fn stderr_field(stderr: &str, key: &str) -> Result<String, String> {
        if !stderr.ends_with('\n') || stderr.matches('\n').count() != 1 {
            return Err(format!("stderr is not exactly one line: {stderr:?}"));
        }
        let pat = format!("\"{key}\":\"");
        let start = stderr
            .find(&pat)
            .ok_or_else(|| format!("no {key} in {stderr:?}"))?
            + pat.len();
        let rest = stderr.get(start..).ok_or("bad offset")?;
        let len = rest
            .find('"')
            .ok_or_else(|| format!("unterminated {key} in {stderr:?}"))?;
        Ok(rest.get(..len).ok_or("bad slice")?.to_string())
    }

    /// 実効 UID を `/proc/self/status` から読む（`unsafe` の syscall を使わないため）。
    fn effective_uid() -> Result<u32, String> {
        let text = fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        text.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "no effective uid in /proc/self/status".to_string())
    }

    struct RunOut {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    }

    /// 実バイナリを有限期限内で実行する（REPAIR-5）。試験用の差し替え口は子の環境から外し、本番の解決経路を通す。
    fn run_cli(cli: &Path, args: &[&str], limit: Duration) -> Result<RunOut, String> {
        let mut child = Command::new(cli)
            .args(args)
            .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
            .env_remove("FANDHE_CONTAINER_OP_LOG")
            .env_remove("FANDHE_CONTAINER_TEST_SYSTEMD_RUN")
            .env_remove("FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn cli: {e}"))?;
        let out_rx = spawn_reader(child.stdout.take().ok_or("stdout not piped")?);
        let err_rx = spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
        let deadline = Instant::now() + limit;
        let status = loop {
            match child.try_wait().map_err(|e| format!("poll cli: {e}"))? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    return Err(match kill_and_reap(&mut child) {
                        Ok(()) => format!("cli did not exit within {limit:?}"),
                        Err(e) => format!("cli did not exit within {limit:?}; {e}"),
                    });
                }
                None => thread::sleep(POLL),
            }
        };
        let collect = Instant::now() + REAP_TIMEOUT;
        let remaining = || collect.saturating_duration_since(Instant::now());
        let stdout = out_rx
            .recv_timeout(remaining())
            .map_err(|_| "stdout was not collected in time".to_string())?;
        let stderr = err_rx
            .recv_timeout(remaining())
            .map_err(|_| "stderr was not collected in time".to_string())?;
        Ok(RunOut {
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}
