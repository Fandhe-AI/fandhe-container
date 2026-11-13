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
//! - D（#664・TASK-184.2）: 参照するコンテナが無いイメージは `--force` なしの `image rm` で消え、manifest の在庫・config・
//!   非共有レイヤーの blob もディスクから消える。
//! - E（#664）: タグなしで stopped / created のコンテナだけが参照するイメージと blob は `image prune` の後も残り、
//!   タグもコンテナ参照も無い別のイメージは prune で消える（空振りでないことの対照）。
//! - C（補助）: タグの外れた digest から prune の前に create だけしたコンテナを、prune の後に start できる。
//! - F（#664）: 参照するコンテナを delete すると、次の prune でタグなしのイメージが消え、タグ付きは残る。
//!
//! - G（#665・TASK-184.3）: 複数のイメージが共有するレイヤー S は、参照が 1 つでも残る限り `image rm` でも `image prune` でも
//!   消えず（他のタグ付きイメージ・stopped のコンテナのどちらが守る場合も）、最後の参照が外れた prune で初めて消える。
//! - H（#665）: `system df` の `images.bytes` / `cache.bytes` は、共有レイヤーを 1 回だけ数えた blob の見かけの大きさの和集合に
//!   完全一致し、`blobs/sha256` の実ディスク使用量（各ファイルの `st_blocks * 512` の合計）との差が 5% 以内に収まる。
//!   `image prune` の前後で、減る量は prune の `reclaimed_bytes` にちょうど一致する。
//!
//! 50 並行（#868・TASK-184.4.1）は別の起動モード `--ignored --scenario concurrent`（実体は `tests/linux/concurrent.rs`）。
//! pull・create・start・container delete・image rm を 50 回ずつ prune と並行させ、受け入れ条件 (i)〜(iii) を照合する。
//! (iv)〜(vi)（#869・TASK-184.4.2）は同じハーネスに足した（実体は `tests/linux/concurrent/races.rs`）。
//! - (iv): 作成途中のコンテナ（参照は未確定で登録済み・状態作成前）の参照するイメージとレイヤーは、他の参照が無くなった窓の中で
//!   prune が完了しても消えない。CLI の実 create の内部の窓は外から止められないため、同じ手順を oci の公開 API でなぞる模擬である。
//! - (v): 同じ blob を共有する 3 本の pull で、先頭が公開してリースを解放しても、残りは成功し blob は欠けない。
//! - (vi): `image tag`（実機は CLI の実バイナリ）と prune の競合は「tag 成功で中身が全部ある」か「NOT_FOUND で何も無い」の一方だけ。
//!   偶数の回は prune が必ず先に回収する（決定的）。奇数の回の勝敗は観測値で、情報行に出すだけである（妥当性は #668）。
//!
//! `--ignored` なしでは、pull × prune に加えて (iv)〜(vi) も小さい件数で自己検証する（コンテナと CLI は使わない）。
//!
//! 削除処理中のクラッシュ復旧（#667・TASK-184.5）は別の起動モード `--ignored --scenario crash`（実体は `tests/linux/crash.rs`）。
//! `image rm`（CLI の実バイナリ）と `image prune`（試験バイナリ自身の再入口 `--gc-crash-child prune`。CLI は #2384 で配線済みだが、本試験は oci の API を直接呼ぶまま。CLI 経由への切り替えは別 issue）の
//! 削除の途中で SIGKILL し、別プロセスの新しい `ImageStore::lock` による回復後の状態が「削除前」か「削除後」の一方と完全に
//! 一致すること、中間状態（ジャーナル無しで blob が一部だけ消えた）が無いこと、参照中の blob が残ることを照合する。コンテナ参照は
//! 実機層が CLI の `create --image`、`--ignored` なしの自己検証が oci の公開 API で付ける。SIGKILL は電源断ではなく、
//! 媒体への永続化（IO-2）は #1965 の範囲。
//!
//! `image prune` の CLI は #2384 で配線済みだが、E・F・G・H は oci の公開 API（`execute_image_prune`）をプロセス内で呼ぶまま。
//! CLI 経由への切り替え（成功行・`ci.yml` の `--min`・`real-machine-tests.md` を同じ PR で更新）は別 issue で追う。
//!
//! # 「実ディスク使用量」の解釈（H）
//! 見かけのサイズ同士の比較は独立した基準にならないため、基準は割り当て済みブロック数（`st_blocks * 512`）とする。
//! blob は 4 KiB の倍数・圧縮されない決定的な擬似乱数・`sync_all` 済みにして、遅延割り当てや圧縮で値が揺れないようにする。
//! この解釈と 5% の妥当性の確認は人間担当の #668（TASK-184.h1）で行う。
//!
//! # 未充足の受け入れ条件（要オーナー判断）
//! 「`--force` 後に参照元の停止中コンテナを `start` できる」は現行の契約では観測できない。core の `start` は `Created` 以外を
//! `FAILED_PRECONDITION` で拒否し、CLI に停止したコンテナを再起動する経路が無い。本試験はこの拒否を期待値として固定しない
//! （B のコンテナには `start` を送らない）。C は残った manifest が参照の登録と起動に使えることの観測で、停止したコンテナ自身の
//! 再起動ではない（#664 の「prune 後に停止中コンテナ自身を start できる」も同じ理由で未充足）。また `create --image` は展開器なしで、`start` はストアの blob を読まない（#2377）ため、C の成否は
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
    // 試験専用の再入口（削除処理中クラッシュ復旧の子。#667）。
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--gc-crash-child")
    {
        linux::crash_child();
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
        ImagePruneOutcome, ImageRmOptions, ImageRmTarget, ImageStore, ImageTagSource,
        ManifestComposition, StoppedContainers, TagKey,
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
    /// プローブの寿命の上限（シナリオ全体の最悪所要時間より十分長く取る。短いと高負荷 runner で A の probe が先に終了コード 8 で抜け、stop の 43 を取り違える）。
    const PROBE_LIFETIME: Duration = Duration::from_secs(600);
    /// `/proc/<pid>/status` の `SigCgt` で SIGTERM（15）に当たるビット（1 << 14）。
    const SIGTERM_CAUGHT_BIT: u64 = 1 << 14;

    /// 在庫のタグ（ダミーのレジストリ名。資格情報は含まない）。
    const TAG_RUN: &str = "registry.example/fandhe/gc-run:v1";
    const TAG_STOP: &str = "registry.example/fandhe/gc-stopped:v1";
    /// 無参照（参照するコンテナが無い）イメージのタグ。シナリオ D が `--force` なしの `image rm` で消す。
    const TAG_ORPHAN: &str = "registry.example/fandhe/gc-orphan:v1";
    /// G・H（#665）の共有レイヤーを持つイメージのタグ。
    const TAG_SA: &str = "registry.example/fandhe/gc-shared-a:v1";
    const TAG_SB: &str = "registry.example/fandhe/gc-shared-b:v1";
    const TAG_KEEP: &str = "registry.example/fandhe/gc-keep:v1";
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
        /// 2 文字のパターンを 32 回並べた 64 桁の 16 進名で組む（1 文字の名前は既存の fixture が使い切っている）。
        /// 共有レイヤーは複数の fixture が同じパターンと同じ大きさで持つ。
        fn from_patterns(manifest: &str, names: [&str; 3], sizes: [usize; 3]) -> Self {
            let hex = |p: &str| p.repeat(32);
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

    /// 削除処理中クラッシュ復旧の試験の子（`image prune` の本体をプロセス内で実行する。#667・OCI-7）。
    pub fn crash_child() -> ! {
        crash::child()
    }

    pub fn main() -> ExitCode {
        super::precondition::self_check();
        let args: Vec<String> = std::env::args().skip(1).collect();
        if !args.iter().any(|a| a == "--ignored") {
            println!(
                "local_image_gc: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            // 既定のテスト集合で、50 並行の pull と prune の照合そのものを小さい件数で検証する（#868）。
            // 作業領域の親ディレクトリは最後の自己検証が消すため、削除処理中クラッシュ復旧（#667）を先に回す。
            let crash_ok = match crash::offline_self_check() {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("local_image_gc: FAILED: offline crash recovery self-check: {e}");
                    false
                }
            };
            if !crash_ok {
                return ExitCode::FAILURE;
            }
            println!("local_image_gc: offline crash recovery self-check ok");
            if let Err(e) = concurrent::offline_self_check() {
                eprintln!("local_image_gc: FAILED: offline pull and prune self-check: {e}");
                return ExitCode::FAILURE;
            }
            println!("local_image_gc: offline pull and prune self-check ok");
            return ExitCode::SUCCESS;
        }
        // 50 並行は別の起動モード（既存の通しシナリオの期限を食わず、失敗の切り分けを容易にする）。
        let concurrent_mode = args
            .windows(2)
            .any(|w| w[0] == "--scenario" && w[1] == "concurrent");
        let crash_mode = args
            .windows(2)
            .any(|w| w[0] == "--scenario" && w[1] == "crash");
        let result = if concurrent_mode {
            concurrent_scenario()
        } else if crash_mode {
            crash_scenario()
        } else {
            scenario()
        };
        match result {
            Ok(()) if concurrent_mode => {
                println!(
                    "local_image_gc: concurrent: 50 runs each of pull, create, start, container delete and image rm ran in parallel with at least 50 image prune runs, and every pull and create saw a prune complete while holding its reference"
                );
                println!(
                    "local_image_gc: concurrent (i): no manifest, config or layer referenced by a running or stopped container, a tag or an in-progress pull lease was deleted at any point"
                );
                println!(
                    "local_image_gc: concurrent (ii): 50/50 creates and starts of containers referencing in-use images succeeded"
                );
                println!(
                    "local_image_gc: concurrent (iii): 50/50 pulls racing image prune succeeded; every published image had all its manifest, config and layer blobs and a container created from it started"
                );
                println!(
                    "local_image_gc: concurrent (iv): 50/50 in-progress creates (container reference registered, state not yet created) kept their image and layers through at least one image prune each"
                );
                println!(
                    "local_image_gc: concurrent (v): 50/50 groups of three pulls sharing a blob succeeded after the first pull completed and released its lease; the shared blob was kept by the remaining leases and never lost"
                );
                println!(
                    "local_image_gc: concurrent (vi): 50/50 image tag runs racing image prune either tagged an image whose manifest and blobs were all present or failed with NOT_FOUND leaving no tag; no tag without content remained"
                );
                println!("local_image_gc: concurrent scenario ok");
                ExitCode::SUCCESS
            }
            Ok(()) if crash_mode => {
                println!(
                    "local_image_gc: crash (rm): image rm killed with SIGKILL during deletion recovered after restart to exactly the pre-delete or post-delete state; no journal, temporary file or partial blob set remained"
                );
                println!(
                    "local_image_gc: crash (prune): image prune killed with SIGKILL during deletion recovered after restart to exactly the pre-delete or post-delete state; no journal, temporary file or partial blob set remained"
                );
                println!(
                    "local_image_gc: crash (referenced): manifests, configs and layers referenced by another tag or a container were present at every kill point and after recovery"
                );
                println!("local_image_gc: crash scenario ok");
                ExitCode::SUCCESS
            }
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
                    "local_image_gc: a new container created from the untagged manifest digest started after image prune; restarting the stopped container itself is out of scope (start accepts only created)"
                );
                println!(
                    "local_image_gc: image rm without --force on an image with no referencing container deleted the manifest entry and its config and layer blobs"
                );
                println!(
                    "local_image_gc: image prune kept the untagged image referenced only by stopped or created containers; config and layer blobs, the manifest entry and both container references were kept"
                );
                println!(
                    "local_image_gc: image prune removed the untagged image with no tag and no container reference and deleted its config and layer blobs"
                );
                println!(
                    "local_image_gc: after the referencing containers were deleted, image prune removed the untagged image and its config and layer blobs"
                );
                println!(
                    "local_image_gc: a shared layer was kept while another tagged image or a stopped container still referenced it; image rm and image prune deleted only the unshared blobs"
                );
                println!(
                    "local_image_gc: once the last reference was gone, image prune deleted the shared layer"
                );
                println!(
                    "local_image_gc: system df images.bytes and cache.bytes matched the blob sizes with the shared layer counted once and stayed within 5% of the allocated disk usage"
                );
                println!(
                    "local_image_gc: system df usage dropped by exactly the reclaimed bytes after image prune"
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

    /// 50 並行（#868）。前提の検査は通しシナリオと同じ。
    fn concurrent_scenario() -> Result<(), super::precondition::Failure> {
        check_prerequisites()?;
        let (env, mut cleanup) = setup_env().map_err(super::precondition::Failure::Other)?;
        concurrent::scenario_real(&env, &mut cleanup).map_err(super::precondition::Failure::Other)
    }

    /// 削除処理中クラッシュ復旧（#667）。前提の検査は通しシナリオと同じ。
    fn crash_scenario() -> Result<(), super::precondition::Failure> {
        check_prerequisites()?;
        let (env, mut cleanup) = setup_env().map_err(super::precondition::Failure::Other)?;
        crash::scenario_real(&env, &mut cleanup).map_err(super::precondition::Failure::Other)
    }

    /// 実体は `tests/linux/concurrent.rs`（インライン `mod linux` の子モジュールは `tests/linux/` 基準で解決される。
    /// サブディレクトリの `.rs` は試験ターゲットとして自動検出されない）。
    mod concurrent;

    /// 実体は `tests/linux/crash.rs`（`concurrent` の兄弟。#667）。
    mod crash;

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

    /// 作業ディレクトリ・bin（CLI と supervisor の 0755 コピー）・状態ルート・空のイメージルートを作る。
    /// 通しシナリオ（A〜H）と 50 並行（`--scenario concurrent`）が共有する。特権ランチャーは置かない。
    fn setup_env() -> Result<(Env, Cleanup), String> {
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
        fs::create_dir(&images).map_err(|e| format!("mkdir images: {e}"))?;
        set_mode(&images, 0o700)?;

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
        Ok((env, cleanup))
    }

    /// 前提の検査を終えた後の本体。ここでの失敗は回帰として扱う。
    fn scenario_body() -> Result<(), String> {
        let (env, mut cleanup) = setup_env()?;

        // 在庫: manifest 2 件（共有する blob は無い）と、それぞれにタグ 1 件。
        let fx_run = Fixture::new('1', ['a', 'b', 'c'], [10, 20, 30]);
        let fx_stop = Fixture::new('2', ['d', 'e', 'f'], [11, 21, 31]);
        seed_inventory(&env.images, &fx_run, Some(TAG_RUN))?;
        seed_inventory(&env.images, &fx_stop, Some(TAG_STOP))?;

        let pid = std::process::id();
        let id_run = format!("gcrun{pid}");
        let id_stop = format!("gcstop{pid}");
        let id_new = format!("gcnew{pid}");
        let id_shared = format!("gcshared{pid}");

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

        // D（#664・受け入れ条件 1）: 参照するコンテナが無いイメージは `--force` なしで消え、
        // manifest・config・非共有レイヤーもディスクから消える。
        let fx_orphan = Fixture::new('3', ['5', '6', '7'], [12, 22, 32]);
        seed_inventory(&env.images, &fx_orphan, Some(TAG_ORPHAN))?;
        expect_blobs(&env, &fx_orphan)?;
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "image",
                "rm",
                "--image-root",
                &env.images_s,
                TAG_ORPHAN,
            ],
            CLI_TIMEOUT,
        )?;
        if out.code != Some(0) || !out.stderr.is_empty() {
            return Err(format!(
                "image rm (orphan): want exit 0, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        // 先頭 2 行は固定順（untagged → deleted）。blob の行の並びは契約に無いため整列して照合する。
        let mut lines = out.stdout.lines();
        let want_head = [
            format!("untagged\t{TAG_ORPHAN}"),
            format!("deleted\t{}", fx_orphan.digest()),
        ];
        let got_head: Vec<&str> = lines.by_ref().take(2).collect();
        expect(
            got_head == want_head,
            &format!("image rm (orphan) head lines: {got_head:?}"),
        )?;
        let mut got_blobs: Vec<String> = lines.map(str::to_string).collect();
        got_blobs.sort();
        let want_blobs: Vec<String> = sorted_blob_digests(&fx_orphan)
            .iter()
            .map(|d| format!("deleted-blob\t{d}"))
            .collect();
        expect(
            got_blobs == want_blobs,
            &format!("image rm (orphan) blob lines: want {want_blobs:?}, got {got_blobs:?}"),
        )?;
        expect_blobs_gone(&env, &fx_orphan)?;
        expect(
            !manifest_in_inventory(&env, &fx_orphan)?,
            "orphan manifest entry is still in the inventory",
        )?;
        let want_ls = format!("{LS_HEADER}{want_run_row}{want_dangling}");
        let ls = image_ls(&env)?;
        expect(
            ls == want_ls,
            &format!("image ls after removing the orphan image: {ls:?}"),
        )?;
        expect_blobs(&env, &fx_stop)?;
        expect_blobs(&env, &fx_run)?;

        // E（#664・受け入れ条件 2）: タグの外れた digest から、prune の前に create だけして Created のまま残す。
        // 停止中コンテナ自身の再起動は観測できない（start は Created だけを受ける）ため、最も近い観測として
        // prune の後にこの Created のコンテナを start する。
        create_container(&env, &mut cleanup, &id_new, "bundle-new", &fx_stop.digest())?;
        // タグもコンテナ参照も無く、blob も共有しない manifest。prune が空振りでないことを示す。
        let fx_dangling = Fixture::new('4', ['8', '9', '0'], [13, 23, 33]);
        seed_untagged(&env.images, &fx_dangling)?;
        // 別プロセスの store（新規 open）から見えること。永続化されていなければ prune は空振りする。
        expect(
            manifest_in_inventory(&env, &fx_dangling)?,
            "untagged seed was not persisted to the inventory",
        )?;
        let out = prune(&env)?;
        let got_removed: Vec<String> = out
            .removed_manifests
            .iter()
            .map(ToString::to_string)
            .collect();
        let got_deleted: Vec<String> = out.deleted_blobs.iter().map(ToString::to_string).collect();
        expect(
            got_removed == [fx_dangling.digest()]
                && got_deleted == sorted_blob_digests(&fx_dangling)
                && out.reclaimed_bytes == fx_dangling.size() as u64
                && out.absent_blobs.is_empty()
                && out.kept_shared_blobs.is_empty()
                && out.kept_leased_blobs.is_empty()
                && out.undeleted_blobs.is_empty(),
            &format!("prune outcome: {out:?}"),
        )?;
        expect_blobs_gone(&env, &fx_dangling)?;
        expect(
            !manifest_in_inventory(&env, &fx_dangling)?,
            "dangling manifest entry is still in the inventory",
        )?;
        // タグなしで stopped / created のコンテナだけが参照するイメージは残る。
        expect_blobs(&env, &fx_stop)?;
        expect(
            manifest_in_inventory(&env, &fx_stop)?,
            "referenced manifest entry was removed by prune",
        )?;
        let (containers, tags) = references(&env, &fx_stop)?;
        expect(
            containers.len() == 2
                && containers
                    .iter()
                    .any(|c| c.ends_with(&format!(".{id_stop}")))
                && containers
                    .iter()
                    .any(|c| c.ends_with(&format!(".{id_new}")))
                && tags.is_empty(),
            &format!("references after prune: {containers:?} {tags:?}"),
        )?;
        expect_unchanged(&env, &fx_run, LS_RUN, &id_run)?;
        let ls = image_ls(&env)?;
        expect(
            ls == want_ls,
            &format!("image ls after image prune: {ls:?}"),
        )?;
        // C（補助）: prune の後に Created のコンテナを start できる。展開器（#2377）が入るまで
        // start はストアの blob を読まないため、レイヤーの残存は上の blob の大きさで直接照合している。
        let fresh = start_created(&env, &id_new)?;
        stop_container(&env, &fresh)?;
        delete_container(&env, &mut cleanup, &fresh)?;

        // 後始末
        stop_container(&env, &run)?;
        delete_container(&env, &mut cleanup, &run)?;
        delete_container(&env, &mut cleanup, &stopped)?;

        // F: 参照するコンテナが無くなり、タグも無いイメージは次の prune で消える。タグ付きは残る。
        let out = prune(&env)?;
        let got_removed: Vec<String> = out
            .removed_manifests
            .iter()
            .map(ToString::to_string)
            .collect();
        let got_deleted: Vec<String> = out.deleted_blobs.iter().map(ToString::to_string).collect();
        expect(
            got_removed == [fx_stop.digest()]
                && got_deleted == sorted_blob_digests(&fx_stop)
                && out.reclaimed_bytes == fx_stop.size() as u64
                && out.undeleted_blobs.is_empty(),
            &format!("second prune outcome: {out:?}"),
        )?;
        expect_blobs_gone(&env, &fx_stop)?;
        expect_blobs(&env, &fx_run)?;
        let ls = image_ls(&env)?;
        expect(
            ls == format!("{LS_HEADER}{want_run_row}"),
            &format!("image ls after the second prune: {ls:?}"),
        )?;
        shared_layer_and_df(&env, &mut cleanup, &id_shared, &fx_run)?;
        Ok(())
    }

    const KIB: usize = 1024;
    /// 共有レイヤー S の名前と大きさ。全体（約 2.6 MiB）の 5% を大きく超え、df が二重に数えると 5% の照合も落ちる。
    const SHARED_LAYER: &str = "f3";
    const SHARED_LAYER_LEN: usize = 1024 * KIB;

    /// 共有レイヤー S を持つ fixture。`config` は config の名前、`layer` は固有 layer の名前の 16 進パターン。
    fn shared_fixture(manifest: &str, config: &str, layer: &str, layer_len: usize) -> Fixture {
        Fixture::from_patterns(
            manifest,
            [config, SHARED_LAYER, layer],
            [64 * KIB, SHARED_LAYER_LEN, layer_len],
        )
    }

    /// blob の内容は名前を種にした決定的な擬似乱数（圧縮されない）。書いた後に `sync_all` で割り当てを確定させる。
    fn write_blob(path: &Path, name: &str, len: usize) -> Result<(), String> {
        let mut x: u64 = 0xcbf2_9ce4_8422_2325;
        for b in name.bytes() {
            x = (x ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        if x == 0 {
            x = 1;
        }
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let take = (len - buf.len()).min(8);
            buf.extend_from_slice(x.to_le_bytes().get(..take).unwrap_or(&[]));
        }
        let mut f = fs::File::create(path).map_err(|e| format!("create blob: {e}"))?;
        f.write_all(&buf).map_err(|e| format!("write blob: {e}"))?;
        f.sync_all().map_err(|e| format!("sync blob: {e}"))
    }

    /// `system df` の 9 項目。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Df {
        images_count: u64,
        images_bytes: u64,
        reclaimable: u64,
        missing: u64,
        blob_count: u64,
        cache_bytes: u64,
        unregistered_count: u64,
        unregistered_bytes: u64,
        foreign: u64,
    }

    /// CLI の `system df --image-root` を実行して固定ヘッダと固定順 9 行を解析する。
    fn system_df(env: &Env) -> Result<Df, String> {
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "system",
                "df",
                "--image-root",
                &env.images_s,
            ],
            CLI_TIMEOUT,
        )?;
        if out.code != Some(0) || !out.stderr.is_empty() {
            return Err(format!(
                "system df: got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        const KEYS: [&str; 9] = [
            "images.count",
            "images.bytes",
            "images.reclaimable_bytes",
            "images.missing_blobs",
            "cache.blob_count",
            "cache.bytes",
            "cache.unregistered_count",
            "cache.unregistered_bytes",
            "cache.foreign_entries",
        ];
        let mut lines = out.stdout.lines();
        expect(
            lines.next() == Some("KEY\tVALUE"),
            &format!("system df header: {:?}", out.stdout),
        )?;
        let mut v = [0u64; 9];
        for (key, slot) in KEYS.iter().zip(v.iter_mut()) {
            let line = lines.next().ok_or(format!("system df lacks {key}"))?;
            let (k, val) = line
                .split_once('\t')
                .ok_or(format!("system df line {line:?}"))?;
            expect(k == *key, &format!("system df key: want {key}, got {k}"))?;
            *slot = val
                .parse::<u64>()
                .map_err(|e| format!("system df {key}={val:?}: {e}"))?;
        }
        expect(
            lines.next().is_none(),
            &format!("system df has extra lines: {:?}", out.stdout),
        )?;
        let [
            images_count,
            images_bytes,
            reclaimable,
            missing,
            blob_count,
            cache_bytes,
            unregistered_count,
            unregistered_bytes,
            foreign,
        ] = v;
        Ok(Df {
            images_count,
            images_bytes,
            reclaimable,
            missing,
            blob_count,
            cache_bytes,
            unregistered_count,
            unregistered_bytes,
            foreign,
        })
    }

    /// `blobs/sha256` の通常ファイルの件数と割り当て済みバイト数（`st_blocks * 512` の合計）。ディレクトリが無ければ (0, 0)。
    fn allocated_blob_bytes(env: &Env) -> Result<(u64, u64), String> {
        use std::os::unix::fs::MetadataExt as _;
        let dir = env.images.join("blobs").join("sha256");
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(format!("read_dir blobs: {e}")),
        };
        let (mut count, mut bytes) = (0u64, 0u64);
        for ent in rd {
            let ent = ent.map_err(|e| format!("blobs entry: {e}"))?;
            let md = fs::symlink_metadata(ent.path()).map_err(|e| format!("blob metadata: {e}"))?;
            if !md.is_file() {
                continue;
            }
            count += 1;
            bytes = md
                .blocks()
                .checked_mul(512)
                .and_then(|b| bytes.checked_add(b))
                .ok_or("allocated bytes overflow")?;
        }
        Ok((count, bytes))
    }

    /// 割り当て済みバイト数 `alloc` に対する `df` の差が 5% 以内か（整数演算。`alloc` が 0 は失敗）。
    fn expect_within_5pct(df: u64, alloc: u64, what: &str) -> Result<(), String> {
        let diff = u128::from(df.abs_diff(alloc));
        expect(
            alloc > 0 && diff * 100 <= 5 * u128::from(alloc),
            &format!("{what}: df={df} allocated={alloc} differs by more than 5%"),
        )
    }

    /// fixture 群の blob の和集合の件数と見かけの大きさ（共有 blob は 1 回だけ数える）。
    fn union_size(fxs: &[&Fixture]) -> (u64, u64) {
        let mut m = std::collections::BTreeMap::new();
        for fx in fxs {
            for (name, len) in &fx.blobs {
                m.insert(name.clone(), *len as u64);
            }
        }
        (m.len() as u64, m.values().sum())
    }

    /// `system df` が和集合に完全一致し（未登録・外来・欠落は 0）、実ディスク使用量と 5% 以内であること。
    fn expect_df(env: &Env, fxs: &[&Fixture], reclaimable: u64, what: &str) -> Result<Df, String> {
        let df = system_df(env)?;
        let (n, bytes) = union_size(fxs);
        expect(
            df.images_count == fxs.len() as u64
                && df.images_bytes == bytes
                && df.reclaimable == reclaimable
                && df.missing == 0
                && df.blob_count == n
                && df.cache_bytes == bytes
                && df.unregistered_count == 0
                && df.unregistered_bytes == 0
                && df.foreign == 0,
            &format!(
                "{what}: system df {df:?}, want count={} bytes={bytes} reclaimable={reclaimable} blobs={n}",
                fxs.len()
            ),
        )?;
        let (alloc_n, alloc) = allocated_blob_bytes(env)?;
        expect(
            alloc_n == n,
            &format!("{what}: {alloc_n} blob files on disk, want {n}"),
        )?;
        expect_within_5pct(df.images_bytes, alloc, &format!("{what}: images.bytes"))?;
        expect_within_5pct(df.cache_bytes, alloc, &format!("{what}: cache.bytes"))?;
        Ok(df)
    }

    /// `image rm [--force] <tag>` を実行して終了コード 0・空の stderr を確かめ、stdout を返す。
    fn image_rm(env: &Env, force: bool, tag: &str) -> Result<String, String> {
        let mut args = vec!["--root", env.root_s.as_str(), "image", "rm"];
        if force {
            args.push("--force");
        }
        args.extend(["--image-root", env.images_s.as_str(), tag]);
        let out = run_cli(&env.cli, &args, CLI_TIMEOUT)?;
        if out.code != Some(0) || !out.stderr.is_empty() {
            return Err(format!(
                "image rm {tag} (force={force}): got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(out.stdout)
    }

    /// `image ls` の SIZE 列（4 列目）の合計。共有レイヤーは行ごとに数えられる。
    fn ls_size_sum(ls: &str) -> Result<u64, String> {
        let mut sum = 0u64;
        for line in ls.lines().skip(1) {
            let col = line
                .split('\t')
                .nth(3)
                .ok_or(format!("image ls row {line:?}"))?;
            let n = col
                .parse::<u64>()
                .map_err(|e| format!("SIZE {col:?}: {e}"))?;
            sum = sum.checked_add(n).ok_or("SIZE sum overflow")?;
        }
        Ok(sum)
    }

    /// prune の結果が「`removed` の manifest だけが消え、`deleted` の blob が消え、`kept_shared` が共有のため残った」ことの照合。
    fn expect_prune(
        out: &ImagePruneOutcome,
        removed: &Fixture,
        deleted: &[String],
        kept_shared: &[String],
        reclaimed: u64,
        what: &str,
    ) -> Result<(), String> {
        let got_removed: Vec<String> = out
            .removed_manifests
            .iter()
            .map(ToString::to_string)
            .collect();
        let got_deleted: Vec<String> = out.deleted_blobs.iter().map(ToString::to_string).collect();
        let got_kept: Vec<String> = out
            .kept_shared_blobs
            .iter()
            .map(ToString::to_string)
            .collect();
        expect(
            got_removed == [removed.digest()]
                && got_deleted == deleted
                && got_kept == kept_shared
                && out.reclaimed_bytes == reclaimed
                && out.absent_blobs.is_empty()
                && out.kept_leased_blobs.is_empty()
                && out.undeleted_blobs.is_empty(),
            &format!(
                "{what}: prune outcome {out:?}, want deleted={deleted:?} kept_shared={kept_shared:?} reclaimed={reclaimed}"
            ),
        )
    }

    /// G・H（#665・TASK-184.3）。F の後の在庫（`fx_run` だけ）から始める。
    fn shared_layer_and_df(
        env: &Env,
        cleanup: &mut Cleanup,
        id_shared: &str,
        fx_run: &Fixture,
    ) -> Result<(), String> {
        // 前片づけ: 10〜30 バイトの小さな blob を基準から外し、5% の照合を濁らせない。
        image_rm(env, false, TAG_RUN)?;
        expect(
            image_ls(env)? == LS_HEADER,
            "image ls is not empty after removing the last image",
        )?;
        expect_blobs_gone(env, fx_run)?;
        expect(
            allocated_blob_bytes(env)? == (0, 0),
            "blobs remain after removing the last image",
        )?;

        let fx_sa = shared_fixture("a1", "a2", "a3", 256 * KIB);
        let fx_sb = shared_fixture("b1", "b2", "b3", 192 * KIB);
        let fx_sc = shared_fixture("c1", "c2", "c3", 128 * KIB);
        let fx_keep =
            Fixture::from_patterns("d1", ["d2", "d3", "d4"], [64 * KIB, 128 * KIB, 96 * KIB]);
        seed_inventory(&env.images, &fx_sa, Some(TAG_SA))?;
        seed_inventory(&env.images, &fx_sb, Some(TAG_SB))?;
        seed_inventory(&env.images, &fx_keep, Some(TAG_KEEP))?;
        seed_untagged(&env.images, &fx_sc)?;
        let shared_hex = SHARED_LAYER.repeat(32);
        let shared_digest = format!("sha256:{shared_hex}");
        let unshared = |fx: &Fixture| -> Vec<String> {
            let mut v: Vec<String> = fx
                .blobs
                .iter()
                .filter(|b| b.0 != shared_hex)
                .map(|b| format!("sha256:{}", b.0))
                .collect();
            v.sort();
            v
        };
        let unref_c = (fx_sc.size() - SHARED_LAYER_LEN) as u64;

        // H-1: 共有レイヤーを二重に数えない。reclaimable は参照の無い C の固有 blob だけ（S は A・B が守る）。
        let all = [&fx_sa, &fx_sb, &fx_sc, &fx_keep];
        expect_df(env, &all, unref_c, "H-1")?;
        let ls_sum = ls_size_sum(&image_ls(env)?)?;
        let (_, union) = union_size(&all);
        expect(
            ls_sum.checked_sub(union) == Some(2 * SHARED_LAYER_LEN as u64),
            &format!(
                "image ls SIZE sum {ls_sum} minus images.bytes {union} is not twice the shared layer"
            ),
        )?;

        // B を stopped のコンテナで参照する。
        let run = launch(env, cleanup, id_shared, "bundle-shared", TAG_SB)?;
        stop_container(env, &run)?;

        // G-1: 他のイメージ（B）が S を守る。A の固有 blob だけが消える。
        let stdout = image_rm(env, false, TAG_SA)?;
        let mut lines = stdout.lines();
        let got_head: Vec<&str> = lines.by_ref().take(2).collect();
        let want_head = [
            format!("untagged\t{TAG_SA}"),
            format!("deleted\t{}", fx_sa.digest()),
        ];
        expect(
            got_head == want_head,
            &format!("image rm A head lines: {got_head:?}"),
        )?;
        let mut got_blobs: Vec<String> = lines.map(str::to_string).collect();
        got_blobs.sort();
        let want_blobs: Vec<String> = unshared(&fx_sa)
            .iter()
            .map(|d| format!("deleted-blob\t{d}"))
            .collect();
        expect(
            got_blobs == want_blobs,
            &format!("image rm A blob lines: want {want_blobs:?}, got {got_blobs:?}"),
        )?;
        for (name, _) in &fx_sa.blobs {
            let exists = env.images.join("blobs").join("sha256").join(name).exists();
            expect(
                exists == (*name == shared_hex),
                &format!("blob {name} presence after image rm A: {exists}"),
            )?;
        }
        expect_blobs(env, &fx_sb)?;

        // B のタグを外す。以後 B を守るのは stopped のコンテナだけ。
        let stdout = image_rm(env, true, TAG_SB)?;
        expect(
            stdout == format!("untagged\t{TAG_SB}\n"),
            &format!("image rm --force B stdout: {stdout:?}"),
        )?;

        // H-2: prune の前。
        let before = expect_df(env, &[&fx_sb, &fx_sc, &fx_keep], unref_c, "H-2")?;

        // G-2: C だけが消え、S は B（stopped のコンテナ）が守る。
        let out = prune(env)?;
        expect_prune(
            &out,
            &fx_sc,
            &unshared(&fx_sc),
            std::slice::from_ref(&shared_digest),
            unref_c,
            "G-2",
        )?;
        expect_blobs(env, &fx_sb)?;
        expect_blobs(env, &fx_keep)?;
        let (containers, tags) = references(env, &fx_sb)?;
        expect(
            containers.len() == 1 && tags.is_empty(),
            &format!("references of B after prune: {containers:?} {tags:?}"),
        )?;

        // H-3: prune の後に減る量は reclaimed_bytes にちょうど一致する。
        let after = expect_df(env, &[&fx_sb, &fx_keep], 0, "H-3")?;
        expect(
            before.images_bytes.checked_sub(after.images_bytes) == Some(out.reclaimed_bytes)
                && before.cache_bytes.checked_sub(after.cache_bytes) == Some(out.reclaimed_bytes),
            &format!(
                "df drop {before:?} -> {after:?} differs from reclaimed {}",
                out.reclaimed_bytes
            ),
        )?;

        // 最後の参照（コンテナ）を外すと B と S が回収対象になる。
        delete_container(env, cleanup, &run)?;
        expect_df(env, &[&fx_sb, &fx_keep], fx_sb.size() as u64, "H-4")?;

        // G-3: 最後の参照が外れたので S も消える。
        let out = prune(env)?;
        let mut want_deleted: Vec<String> = fx_sb
            .blobs
            .iter()
            .map(|b| format!("sha256:{}", b.0))
            .collect();
        want_deleted.sort();
        expect_prune(&out, &fx_sb, &want_deleted, &[], fx_sb.size() as u64, "G-3")?;
        expect_blobs_gone(env, &fx_sb)?;

        // H-5
        let last = expect_df(env, &[&fx_keep], 0, "H-5")?;
        expect(
            after.images_bytes.checked_sub(last.images_bytes) == Some(out.reclaimed_bytes)
                && last.images_bytes == fx_keep.size() as u64
                && last.cache_bytes == fx_keep.size() as u64,
            &format!(
                "df drop {after:?} -> {last:?} differs from reclaimed {}",
                out.reclaimed_bytes
            ),
        )?;
        expect_blobs(env, &fx_keep)?;
        let ls = image_ls(env)?;
        let want = format!(
            "{LS_HEADER}registry.example/fandhe/gc-keep\tv1\t{}\t{}\t0\n",
            fx_keep.digest(),
            fx_keep.size()
        );
        expect(ls == want, &format!("image ls at the end: {ls:?}"))?;
        Ok(())
    }
    /// blob の digest（`sha256:<hex>`）の昇順。prune の `deleted_blobs`（digest の昇順）の期待値に使う。
    fn sorted_blob_digests(fx: &Fixture) -> Vec<String> {
        let mut v: Vec<String> = fx.blobs.iter().map(|b| format!("sha256:{}", b.0)).collect();
        v.sort();
        v
    }

    /// 在庫に manifest があるか（永続化された在庫から読む）。
    fn manifest_in_inventory(env: &Env, fx: &Fixture) -> Result<bool, String> {
        let store = ImageStore::open(&env.images).map_err(|e| format!("open store: {e:?}"))?;
        let guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        let want = fx.digest();
        Ok(guard.manifests().any(|(d, _)| d.to_string() == want))
    }

    /// blob ファイルが全部ディスクから消えていること（symlink を辿らず、NotFound だけを消えた扱いにする）。
    fn expect_blobs_gone(env: &Env, fx: &Fixture) -> Result<(), String> {
        for (name, _) in &fx.blobs {
            let path = env.images.join("blobs").join("sha256").join(name);
            match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("blob {name}: unexpected error: {e}")),
                Ok(_) => return Err(format!("blob {name} still exists")),
            }
        }
        Ok(())
    }

    /// 無参照イメージの prune をプロセス内で実行する（CLI の `image prune` は #2384 で配線済み。CLI 経由への切り替えは別 issue）。
    /// ストアとガードはこの関数の中で手放す（保持したまま CLI を呼ぶと CLI 側の lock が期限切れになる）。
    fn prune(env: &Env) -> Result<ImagePruneOutcome, String> {
        let store = ImageStore::open(&env.images).map_err(|e| format!("open store: {e:?}"))?;
        let mut guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        guard
            .execute_image_prune(store.root())
            .map_err(|e| format!("prune: {e:?}"))
    }

    /// 在庫へ manifest 1 件と blob ファイルを置き、`tag` があれば付ける（`None` はタグなしの無参照イメージ）。ストアとガードはこの関数の中で手放す。
    fn seed_inventory(images: &Path, fx: &Fixture, tag: Option<&str>) -> Result<(), String> {
        let blobs = images.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).map_err(|e| format!("mkdir blobs: {e}"))?;
        for (name, len) in &fx.blobs {
            write_blob(&blobs.join(name), name, *len)?;
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
        // 登録と tag は同じ排他区間（ガード）で行う。別々に lock すると 2 回目の lock が
        // 永続化済みの在庫を読み直し、未保存の登録が見えず NotFound になる。
        let mut guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        guard
            .register_manifest(digest(&fx.manifest_hex)?, comp)
            .map_err(|e| format!("register: {e:?}"))?;
        if let Some(tag) = tag {
            guard
                .tag_image(
                    &ImageTagSource::Manifest(digest(&fx.manifest_hex)?),
                    tag_key(tag)?,
                )
                .map_err(|e| format!("tag: {e:?}"))?;
        }
        Ok(())
    }

    /// タグなしの無参照イメージを永続化した在庫へ置く。
    ///
    /// `register_manifest` だけでは保存されず、新しい store の `lock()` の再読込で消える。そこで
    /// 一時タグ付きで seed（保存される）→ 同じ排他区間で一時タグを外し、使い捨ての運び屋イメージを
    /// 完全削除する `image rm` の保存に便乗して、タグなしの状態をディスクへ書く。
    fn seed_untagged(images: &Path, fx: &Fixture) -> Result<(), String> {
        const TAG_TMP: &str = "registry.example/fandhe/gc-tmp:v1";
        const TAG_CARRIER: &str = "registry.example/fandhe/gc-carrier:v1";
        let pat = |p: &str| p.repeat(32);
        let carrier = Fixture {
            manifest_hex: pat("5a"),
            blobs: [(pat("5b"), 1), (pat("5c"), 1), (pat("5d"), 1)],
        };
        seed_inventory(images, fx, Some(TAG_TMP))?;
        seed_inventory(images, &carrier, Some(TAG_CARRIER))?;
        let store = ImageStore::open(images).map_err(|e| format!("open store: {e:?}"))?;
        let mut guard = store.lock().map_err(|e| format!("lock: {e:?}"))?;
        guard
            .unregister_tag(&tag_key(TAG_TMP)?)
            .map_err(|e| format!("untag: {e:?}"))?;
        guard
            .execute_image_rm(
                store.root(),
                &ImageRmTarget::Tag(tag_key(TAG_CARRIER)?),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .map_err(|e| format!("rm carrier: {e:?}"))?;
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
        create_container(env, cleanup, id_s, bundle_name, image)?;
        start_created(env, id_s)
    }

    /// create（`--image`）だけ行い、後始末の対象（`cleanup.live`）に積む。
    fn create_container(
        env: &Env,
        cleanup: &mut Cleanup,
        id_s: &str,
        bundle_name: &str,
        image: &str,
    ) -> Result<(), String> {
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
        Ok(())
    }

    /// Created のコンテナを start → list が running → SIGTERM のハンドラ登録まで進める。
    fn start_created(env: &Env, id_s: &str) -> Result<Running, String> {
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
