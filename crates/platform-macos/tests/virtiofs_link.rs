//! virtiofs の symlink・ハードリンクのゲスト観測の実機入口（MAC-1・SEC-4・TASK-65.1 追補・#1877・#1374・MS-5）。
//!
//! `AGENTS.md`「virtiofs の symlink・ハードリンク挙動の手動確認」の手順 2・3 を、シェルもコマンドも無い
//! initrd（#362）でも実行できる形にする。ゲスト init の観測モード（`crates/guest-init/src/link_probe.rs`）が
//! 読み取り専用の共有 `ro` のリンクと、読み書きできる共有 `rw` に作ったリンクの観測結果を hvc0 へ出し、
//! 本試験はそれをコンソールログから集めて stderr へ出す。**判定はしない**: 観測結果の解釈と #1374 への
//! 記録は人間、拒否範囲を緩めるかはオーナーの判断（#1374 の条件 3〜5）。本試験が assert するのはプロトコルの
//! 健全性（終端 `done` があり、契約外の行がなく、ログが打ち切られていない）だけ。
//!
//! 補助関数は `tests/support/virtiofs_harness.rs` に共通化（単体試験は `tests/virtiofs_harness.rs`。#3099）。
//!
//! 二層構成（`virtiofs_io.rs` に倣う。他 OS では `#![cfg]` により 0 件）:
//! - 既定集合: spec の読み戻し・fixture のレイアウト・期限の境界など VM 生成前に確定する経路。
//! - 実機テスト（`#[ignore]`）: macOS 13 以上・`com.apple.security.virtualization` 付き署名・観測モードを実装した
//!   ゲスト init を要する。手順は AGENTS.md「virtiofs の symlink・ハードリンク挙動の手動確認」。
//!
//! 共有範囲外を指す symlink と既存のハードリンク（`nlink > 1`）は `VmConfigSpec::check_share_conflicts` が
//! 起動前に拒否するため fixture に入れられず、観測できない。ゲストが `rw` に作ったものはホストから
//! `lstat` だけで観察する（untrusted のため open も symlink の追従もしない）。
#![cfg(target_os = "macos")]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fandhe_container_platform_macos::config::{
    ConsoleLogPath, DeviceConfigSpec, SerialConsoleSink, VmConfigSpec, build_vz_configuration,
};
use fandhe_container_platform_macos::guest_link_probe::{
    LinkLog, RO_MOUNT, RO_TAG, RW_HARD_NAME, RW_MOUNT, RW_SRC_NAME, RW_SYM_NAME, RW_TAG,
    parse_link_log,
};
use fandhe_container_platform_macos::guest_mount::{GuestMountPoint, GuestTestMode};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};

#[path = "support/common.rs"]
mod common;
use common::Scratch;
#[path = "support/virtiofs_harness.rs"]
mod harness;
#[path = "support/vm_guest.rs"]
mod vm_guest;
use harness::{launch_until_done, resolve_probe_timeout};

/// ホストが `rw/` で観察するエントリ名の最大件数（想定外のエントリの列挙上限）。
const MAX_RW_ENTRIES: usize = 16;
/// ホストが起動前に置く fixture。`ro` / `rw` は共有ディレクトリ（実体パス）。
struct Fixture {
    ro: PathBuf,
    rw: PathBuf,
}

/// `ro/inside.txt`・`ro/inside_link`（相対）・`ro/abs_inside_link`（実体パスの絶対）・
/// `ro/dangling_inside_link`（共有内の未作成パス）と、空の `rw/` を作る。
///
/// 範囲外 symlink・ハードリンク（`nlink > 1`）は `check_share_conflicts` に拒否されるため作らない。
fn prepare_fixture(s: &Scratch) -> Fixture {
    let ro = s.dir.join("ro");
    let rw = s.dir.join("rw");
    std::fs::create_dir(&ro).expect("create ro");
    std::fs::create_dir(&rw).expect("create rw");
    std::fs::write(ro.join("inside.txt"), b"inside\n").expect("write inside.txt");
    std::os::unix::fs::symlink("inside.txt", ro.join("inside_link")).expect("inside_link");
    std::os::unix::fs::symlink(ro.join("inside.txt"), ro.join("abs_inside_link"))
        .expect("abs_inside_link");
    std::os::unix::fs::symlink(ro.join("missing"), ro.join("dangling_inside_link"))
        .expect("dangling_inside_link");
    Fixture { ro, rw }
}

/// コンソールログ・ro / rw の 2 共有（ゲスト mount つき）・観測モードつきの spec。
fn link_spec(
    s: &Scratch,
    f: &Fixture,
    kernel: &Path,
    initrd: Option<&Path>,
    cmdline: &str,
) -> VmConfigSpec {
    let log = s.dir.join("console.log");
    let devices = DeviceConfigSpec::try_new(
        Vec::new(),
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(&log).expect("console log path"),
        )),
    )
    .expect("device spec");
    let share = |tag: &str, dir: &Path, access, mount: &str| {
        VirtiofsShareSpec::new(
            VirtiofsTag::try_new(tag).expect("tag"),
            SharedDirectoryPath::try_new(dir).expect("share dir"),
            access,
        )
        .with_guest_mount(GuestMountPoint::try_new(mount).expect("mount point"))
    };
    let shares = VirtiofsSharesSpec::try_new(vec![
        share(RO_TAG, &f.ro, ShareAccess::ReadOnly, RO_MOUNT),
        share(RW_TAG, &f.rw, ShareAccess::ReadWrite, RW_MOUNT),
    ])
    .expect("shares");
    VmConfigSpec::from_parts(kernel, initrd, cmdline)
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices")
        .with_shared_directories(shares)
        .with_guest_test(GuestTestMode::VirtiofsLink)
}

/// 停止後に `rw/` をホストから観察して stderr へ出す。ゲストが作ったものは untrusted のため、
/// `lstat` と `read_link` だけを使い、open も symlink の追従もしない。
fn observe_rw_from_host(rw: &Path) {
    let md = match std::fs::symlink_metadata(rw) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("virtiofs_link: host rw: stat failed: {e}");
            return;
        }
    };
    if !md.file_type().is_dir() {
        eprintln!("virtiofs_link: host rw: not a real directory (replaced?); skip observation");
        return;
    }
    for name in [RW_SRC_NAME, RW_SYM_NAME, RW_HARD_NAME] {
        let p = rw.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(m) => {
                let kind = if m.file_type().is_symlink() {
                    "symlink"
                } else if m.file_type().is_file() {
                    "file"
                } else if m.file_type().is_dir() {
                    "dir"
                } else {
                    "other"
                };
                let target = if m.file_type().is_symlink() {
                    format!(" read_link={:?}", std::fs::read_link(&p))
                } else {
                    String::new()
                };
                eprintln!(
                    "virtiofs_link: host rw/{name}: kind={kind} nlink={} dev={} ino={} size={}{target}",
                    m.nlink(),
                    m.dev(),
                    m.ino(),
                    m.len()
                );
            }
            Err(e) => eprintln!("virtiofs_link: host rw/{name}: lstat failed: {e}"),
        }
    }
    match std::fs::read_dir(rw) {
        Ok(it) => {
            let unexpected: Vec<_> = it
                .take(MAX_RW_ENTRIES + 1)
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .filter(|n| {
                    ![RW_SRC_NAME, RW_SYM_NAME, RW_HARD_NAME]
                        .iter()
                        .any(|k| n == k)
                })
                .collect();
            eprintln!("virtiofs_link: host rw: unexpected entries: {unexpected:?}");
        }
        Err(e) => eprintln!("virtiofs_link: host rw: read_dir failed: {e}"),
    }
}

/// MAC-1・SEC-4・#1877: 観測用 spec（ro / rw の 2 共有＋ゲスト mount＋観測モード）が VZ 設定へ読み戻せる。
#[test]
fn mac1_sec4_link_spec_builds_with_ro_and_rw_shares() {
    let s = Scratch::new("link-spec", false);
    let kernel = s.file("vmlinux", b"dummy");
    let f = prepare_fixture(&s);
    let spec = link_spec(&s, &f, &kernel, None, "console=hvc0");
    let cfg = match build_vz_configuration(&spec) {
        Ok(c) => c,
        Err(e) => panic!("build failed: {e}"),
    };
    let shares = cfg.shared_directories();
    assert_eq!(shares.len(), 2);
    let by_tag = |tag: &str| shares.iter().find(|s| s.tag == tag).expect("share by tag");
    assert!(by_tag("ro").read_only);
    assert!(!by_tag("rw").read_only);
    assert_eq!(
        by_tag("ro")
            .path
            .as_ref()
            .and_then(|p| p.canonicalize().ok()),
        f.ro.canonicalize().ok()
    );
    assert_eq!(
        by_tag("rw")
            .path
            .as_ref()
            .and_then(|p| p.canonicalize().ok()),
        f.rw.canonicalize().ok()
    );
    // link_probe の契約（config.rs の単体テストと同一の文字列。打ち間違いを検出する）。
    assert_eq!(
        cfg.command_line().as_deref(),
        Some(
            "console=hvc0 fandhe.virtiofs=ro:/mnt/fandhe/ro:ro fandhe.virtiofs=rw:/mnt/fandhe/rw:rw fandhe.guest-test=virtiofs-link"
        )
    );
}

/// MAC-1・SEC-4・#1877: fixture のレイアウト（範囲内リンクだけ・rw は空）。
#[test]
fn mac1_sec4_link_fixture_layout() {
    let s = Scratch::new("link-fixture", false);
    let f = prepare_fixture(&s);
    assert_eq!(
        std::fs::read_link(f.ro.join("inside_link")).expect("inside_link"),
        Path::new("inside.txt")
    );
    assert_eq!(
        std::fs::read_link(f.ro.join("abs_inside_link")).expect("abs_inside_link"),
        f.ro.join("inside.txt")
    );
    assert_eq!(
        std::fs::read_link(f.ro.join("dangling_inside_link")).expect("dangling"),
        f.ro.join("missing")
    );
    assert!(!f.ro.join("missing").exists());
    assert_eq!(std::fs::read_dir(&f.rw).expect("rw").count(), 0);
    assert_eq!(
        std::fs::metadata(f.ro.join("inside.txt")).unwrap().nlink(),
        1
    );
}

/// kernel 未設定時の panic 文言（必須・任意の環境変数の一覧）。
const KERNEL_HELP: &str = "FANDHE_CONTAINER_MACOS_VM_KERNEL is required. Optional: FANDHE_CONTAINER_MACOS_VM_INITRD, \
             FANDHE_CONTAINER_MACOS_VM_CMDLINE (default \"console=hvc0\"), \
             FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS (1-600, default 60). See AGENTS.md.";

/// 実機で VM を起動して観測を走らせ、停止後に確定したログを返す。
fn boot_and_observe(tag: &str) -> (Fixture, LinkLog, String) {
    let assets = vm_guest::GuestAssets::from_env(KERNEL_HELP);
    let timeout =
        resolve_probe_timeout(std::env::var("FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS").ok())
            .unwrap_or_else(|e| panic!("{e}"));

    let s = Scratch::new(tag, true);
    let fixture = prepare_fixture(&s);
    let spec = link_spec(
        &s,
        &fixture,
        &assets.kernel,
        assets.initrd.as_deref(),
        &assets.cmdline,
    );
    let log_path = s.dir.join("console.log");
    eprintln!("virtiofs_link: console log at {}", log_path.display());
    let last = launch_until_done(&spec, &log_path, "link", timeout, |b| {
        parse_link_log(b).done
    });
    (
        fixture,
        parse_link_log(&last),
        log_path.display().to_string(),
    )
}

/// MAC-1・SEC-4・#1877・#1374: ゲストの symlink・ハードリンクの観測を実行して全観測行を stderr に出す。
///
/// assert するのはプロトコルの健全性（終端 done・契約外の行なし・ログの打ち切りなし）だけで、観測内容の
/// 判定は人間が行い #1374 に記録する。
#[test]
#[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and a guest init implementing the virtiofs-link observation mode; see AGENTS.md"]
fn mac1_sec4_virtiofs_link_observation_on_real_macos() {
    let (fixture, log, log_path) = boot_and_observe("virtiofs-link");
    for line in &log.lines {
        eprintln!("virtiofs_link: guest: {line}");
    }
    observe_rw_from_host(&fixture.rw);
    eprintln!("virtiofs_link: console log kept at {log_path}");
    assert!(
        log.done && !log.invalid,
        "link observation protocol is not sound (done={}, invalid={}); lines:\n{}",
        log.done,
        log.invalid,
        log.lines.join("\n")
    );
}
