//! `create-symlinks` フックが作る symlink の全リンク網羅検証（TASK-127.5・GPU-2・MS-10・REPAIR-12）。
//!
//! PoC-14 は `nvidia-cdi-hook create-symlinks` が作る約 33 リンクを 11 件のサンプルでしか照合して
//! いなかった。本試験は CDI spec の `create-symlinks` フックの `--link <target>::<link>` を全件取り出し
//! （期待集合）、フック実行の前後で rootfs の symlink を比べ、作られた数が期待件数と一致し、各リンクの
//! 向き先も spec どおりであることを機械照合する。1 件でも食い違えば不合格（fail-closed）。
//!
//! # 2 層の区分
//! - 層 A（本ファイル。既定テスト集合・CI で実行）: 検証器と、フックの役を `std::os::unix::fs::symlink`
//!   で代わりに務める一時 rootfs 上の結合試験。検証器はリンクの作られ方に依らず前後のスナップショットだけを
//!   比べるため、欠落・向き先違い・余分・既存リンクの取り違えを陰性ケースで検出できることも示す。
//! - 層 B（実機前提。#4589）: 本物の `nvidia-cdi-hook` を走らせての照合。検証器は共有モジュール
//!   `support/symlink_coverage_check.rs` に置き、`tests/cuda_workload.rs` の実機前提試験がフックごとの窓
//!   （`HookWindowCoverage`）で呼ぶ。core の pre-pivot 段への配線（#2774）が済むまでは同試験が rootfs を
//!   自分で組む。本ファイルの末尾の試験は窓の接着部を偽フックで既定の集合として照合する。実機の記録は #3001。
//!
//! # 前提
//! 期待集合は実行される値と同じ経路（`parse_cdi_spec` → `aggregate_container_edits` →
//! `validate_create_container_hooks`）から作る。フック実行は Linux 限定のため `cfg` を Linux に絞る。

#![cfg(target_os = "linux")]

// 残骸・PID 再利用との衝突を避ける作成前削除の補助（REPAIR-12・#3435）。
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fandhe_container_gpu::cdi_apply::hooks::{
    CdiCreateContainerHook, validate_create_container_hooks,
};
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::detect_usr_merge_layout;
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");
const NODE4: &str = include_str!("fixtures/poc14-node4.json");

// 検証器（層 A・層 B 共通。#4589）。
#[path = "support/symlink_coverage_check.rs"]
mod symlink_coverage_check;
use symlink_coverage_check::{
    Expected, ExtractError, Snapshot, SymlinkMismatch, expected_links, normalize_expected,
    snapshot as snapshot_checked, verify,
};

/// 層 A の呼び出し側では走査の I/O 失敗を panic にする（検証器は `Result` を返す）。
fn snapshot(rootfs: &Path, expected: &Expected) -> Snapshot {
    snapshot_checked(rootfs, expected).unwrap()
}

fn hooks_of(spec_json: &str, devices: &[&str]) -> Vec<CdiCreateContainerHook> {
    let spec = parse_cdi_spec(spec_json).unwrap();
    let agg = aggregate_container_edits(&spec, devices).unwrap();
    validate_create_container_hooks(agg.hooks()).unwrap()
}

fn link_counts(hooks: &[CdiCreateContainerHook]) -> Vec<usize> {
    hooks
        .iter()
        .filter(|h| h.args().get(1).map(String::as_str) == Some("create-symlinks"))
        .map(|h| h.args().iter().filter(|a| *a == "--link").count())
        .collect()
}

// ---------------------------------------------------------------- 試験の補助

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// 一時 rootfs。Drop で削除する。
struct TempRoot(PathBuf, #[allow(dead_code)] test_root::TestRoot);

impl TempRoot {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        Self::at(
            std::env::temp_dir().join(format!("fandhe-gpu-symlink-cov-{}-{n}", std::process::id())),
        )
    }

    /// 指定パスを第 1 候補に排他作成する。残骸（前回の symlink など）は消さず別名で作るため、古いリンクが
    /// 前後のスナップショットへ混ざらない（REPAIR-12・#3475）。
    fn at(p: PathBuf) -> Self {
        let root = test_root::test_root_at(p);
        Self(std::fs::canonicalize(&*root).unwrap(), root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// rootfs 内の `link`（絶対表記）に symlink を作る（親は作る）。
    fn link(&self, target: &str, link: &str) {
        let p = self.0.join(link.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target, p).unwrap();
    }
}

/// GPU-2・REPAIR-12・#3475: 残骸の symlink が残っていても消さず、別名の空の rootfs を作る。
/// 残骸のリンクは無傷で残り、新しい rootfs には混ざらない。
#[test]
fn gpu2_repair12_symlink_root_leaves_stale_links_untouched() {
    let parent = test_root::test_root("fandhe-gpu-symlink-residue", "parent");
    let p = parent.join("stale");
    std::fs::create_dir_all(p.join("usr")).unwrap();
    symlink("/etc/hostname", p.join("usr").join("stale-link")).unwrap();
    {
        let t = TempRoot::at(p.clone());
        assert_ne!(t.path(), p.as_path());
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
        assert!(std::fs::symlink_metadata(t.path().join("usr").join("stale-link")).is_err());
    }
    assert_eq!(
        std::fs::read_link(p.join("usr").join("stale-link")).unwrap(),
        Path::new("/etc/hostname")
    );
}

/// フックの役を務める: 期待どおりの全リンクを作る。
fn run_fake_hook(root: &TempRoot, expected: &Expected) {
    for (link, target) in expected {
        root.link(target, link);
    }
}

fn expected_of(json: &str) -> Expected {
    expected_links(&hooks_of(json, &["all"])).unwrap()
}

fn setup(json: &str) -> (TempRoot, Expected, Snapshot) {
    let expected = expected_of(json);
    let root = TempRoot::new();
    let before = snapshot(root.path(), &expected);
    (root, expected, before)
}

fn full_flow(json: &str, n: usize) {
    let expected = expected_of(json);
    assert_eq!(expected.len(), n);
    let root = TempRoot::new();
    root.link("usr/lib", "/lib");
    root.link("libc.so.6", "/usr/lib/x86_64-linux-gnu/unrelated-existing");
    let before = snapshot(root.path(), &expected);
    run_fake_hook(&root, &expected);
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert_eq!(r.expected_links, n);
    assert_eq!(r.created_symlinks, n);
    assert_eq!(r.mismatches, []);
    r.assert_pass();
}

fn synth_hooks(args: &[&[&str]]) -> Vec<CdiCreateContainerHook> {
    let hooks: Vec<String> = args
        .iter()
        .map(|a| {
            let list: Vec<String> = a.iter().map(|s| format!("{s:?}")).collect();
            format!(
                "{{\"hookName\":\"createContainer\",\"path\":\"/usr/bin/nvidia-cdi-hook\",\"args\":[\"nvidia-cdi-hook\",\"create-symlinks\",{}]}}",
                list.join(",")
            )
        })
        .collect();
    let json = format!(
        "{{\"cdiVersion\":\"0.5.0\",\"kind\":\"nvidia.com/gpu\",\"devices\":[{{\"name\":\"all\",\"containerEdits\":{{\"deviceNodes\":[{{\"path\":\"/dev/null\"}}]}}}}],\"containerEdits\":{{\"hooks\":[{}]}}}}",
        hooks.join(",")
    );
    hooks_of(&json, &["all"])
}

// ---------------------------------------------------------------- 期待集合の試験

/// GPU-2: dev-box02 の `all` は 37 リンク（フック内訳は 2・33・2）。
#[test]
fn gpu2_poc14_devbox02_expects_37_links() {
    let hooks = hooks_of(DEVBOX02, &["all"]);
    let mut counts = link_counts(&hooks);
    counts.sort_unstable();
    assert_eq!(counts, [2, 2, 33]);
    let e = expected_links(&hooks).unwrap();
    assert_eq!(e.len(), 37);
    assert_eq!(
        e.get("/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.0")
            .map(String::as_str),
        Some("libEGL_nvidia.so.595.91.07")
    );
}

/// GPU-2: node4 の `all` は 36 リンク（フック内訳は 2・32・2）。
#[test]
fn gpu2_poc14_node4_expects_36_links() {
    let hooks = hooks_of(NODE4, &["all"]);
    let mut counts = link_counts(&hooks);
    counts.sort_unstable();
    assert_eq!(counts, [2, 2, 32]);
    let e = expected_links(&hooks).unwrap();
    assert_eq!(e.len(), 36);
    assert_eq!(
        e.get("/usr/lib/aarch64-linux-gnu/libEGL_nvidia.so.0")
            .map(String::as_str),
        Some("libEGL_nvidia.so.580.173.02")
    );
}

/// GPU-2: `["0","all"]` のように同じフックが重なる要求でも、一意なリンクは 37 件（集計側が同一フックを畳む）。
#[test]
fn gpu2_overlapping_device_requests_keep_37_unique_links() {
    let hooks = hooks_of(DEVBOX02, &["0", "all"]);
    assert_eq!(expected_links(&hooks).unwrap().len(), 37);
}

/// GPU-2: 別々のフックに同じ (target, link) が現れたら 1 件に畳む（延べ 3 件、一意 2 件）。
#[test]
fn gpu2_identical_links_across_hooks_fold_to_one() {
    let h = synth_hooks(&[
        &["--link", "a::/x/l", "--link", "b::/x/m"],
        &["--link", "a::/x/l"],
    ]);
    assert_eq!(link_counts(&h).iter().sum::<usize>(), 3);
    assert_eq!(expected_links(&h).unwrap().len(), 2);
}

/// GPU-2: 同じリンクに別ターゲットがあれば抽出エラー。
#[test]
fn gpu2_conflicting_link_targets_are_rejected() {
    let h = synth_hooks(&[&["--link", "a::/x/l", "--link", "b::/x/l"]]);
    assert_eq!(
        expected_links(&h),
        Err(ExtractError::ConflictingTargets("/x/l".into()))
    );
}

/// GPU-2: 不正な `--link` 引数はそれぞれ種類つきで拒否する。
#[test]
fn gpu2_malformed_link_args_are_rejected() {
    let cases: Vec<(Vec<&str>, ExtractError)> = vec![
        (
            vec!["--link", "nocolons"],
            ExtractError::BadPair("nocolons".into()),
        ),
        (
            vec!["--link", "a::b::/c"],
            ExtractError::BadPair("a::b::/c".into()),
        ),
        (vec!["--link", "::/c"], ExtractError::BadPair("::/c".into())),
        (vec!["--link", "a::"], ExtractError::BadPair("a::".into())),
        (
            vec!["--link", "a::rel/path"],
            ExtractError::BadLinkPath("rel/path".into()),
        ),
        (
            vec!["--link", "a::/x/../y"],
            ExtractError::BadLinkPath("/x/../y".into()),
        ),
        (
            vec!["--link", "a::/x/./y"],
            ExtractError::BadLinkPath("/x/./y".into()),
        ),
        (
            vec!["--link", "a::/x//y"],
            ExtractError::BadLinkPath("/x//y".into()),
        ),
        (
            vec!["--link", "a::/"],
            ExtractError::BadLinkPath("/".into()),
        ),
        (vec!["--link"], ExtractError::MissingLinkValue),
        (
            vec!["--link=a::/x"],
            ExtractError::UnexpectedArg("--link=a::/x".into()),
        ),
        (
            vec!["--unknown", "v"],
            ExtractError::UnexpectedArg("--unknown".into()),
        ),
    ];
    for (args, want) in cases {
        let h = synth_hooks(&[&args]);
        assert_eq!(expected_links(&h), Err(want), "args={args:?}");
    }
}

// ---------------------------------------------------------------- 照合の試験

/// GPU-2: 全リンクが作られれば合格（dev-box02 は 37 件）。
#[test]
fn gpu2_full_coverage_passes_for_poc14_devbox02() {
    full_flow(DEVBOX02, 37);
}

/// GPU-2: 全リンクが作られれば合格（node4 は 36 件）。
#[test]
fn gpu2_full_coverage_passes_for_poc14_node4() {
    full_flow(NODE4, 36);
}

/// GPU-2: 1 件作られなければ不合格（Missing）。
#[test]
fn gpu2_missing_link_fails() {
    let (root, expected, before) = setup(DEVBOX02);
    let skip = "/usr/lib/x86_64-linux-gnu/libcuda.so";
    for (l, t) in &expected {
        if l != skip {
            root.link(t, l);
        }
    }
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert!(!r.is_pass());
    assert_eq!(r.created_symlinks, 36);
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::Missing { link: skip.into() }]
    );
}

/// GPU-2: 向き先が違えば不合格（WrongTarget）。
#[test]
fn gpu2_wrong_target_fails() {
    let (root, expected, before) = setup(DEVBOX02);
    let bad = "/usr/lib/x86_64-linux-gnu/libcuda.so";
    for (l, t) in &expected {
        root.link(if l == bad { "libwrong.so" } else { t }, l);
    }
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::WrongTarget {
            link: bad.into(),
            expected: "libcuda.so.1".into(),
            actual: "libwrong.so".into()
        }]
    );
}

/// GPU-2: spec に無いリンクが期待リンクの親に作られたら不合格（Unexpected）。
#[test]
fn gpu2_unexpected_link_fails() {
    let (root, expected, before) = setup(DEVBOX02);
    run_fake_hook(&root, &expected);
    root.link("x", "/usr/lib/x86_64-linux-gnu/extra-link");
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert!(!r.is_pass());
    assert_eq!(r.created_symlinks, 38);
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::Unexpected {
            link: "/usr/lib/x86_64-linux-gnu/extra-link".into(),
            target: "x".into()
        }]
    );
}

/// GPU-2: リンクの位置に通常ファイルがあれば不合格（NotSymlink）。
#[test]
fn gpu2_regular_file_at_link_path_fails() {
    let (root, expected, before) = setup(DEVBOX02);
    let bad = "/usr/lib/x86_64-linux-gnu/libcuda.so";
    for (l, t) in &expected {
        if l == bad {
            let p = root.path().join(l.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"x").unwrap();
        } else {
            root.link(t, l);
        }
    }
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::NotSymlink { link: bad.into() }]
    );
}

/// GPU-2: 実行前から在ったリンクは「作られた」に数えず不合格（PreExisting。向き先が同じでも）。
#[test]
fn gpu2_preexisting_link_is_not_counted_as_created() {
    let expected = expected_of(DEVBOX02);
    let root = TempRoot::new();
    let pre = "/usr/lib/x86_64-linux-gnu/libcuda.so";
    root.link("libcuda.so.1", pre);
    let before = snapshot(root.path(), &expected);
    for (l, t) in expected.iter().filter(|(l, _)| l.as_str() != pre) {
        root.link(t, l);
    }
    let r = verify(&expected, &before, &snapshot(root.path(), &expected));
    assert!(!r.is_pass());
    assert_eq!(r.created_symlinks, 36);
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::PreExisting {
            link: pre.into(),
            target: "libcuda.so.1".into()
        }]
    );
}

/// GPU-2: 親の途中が symlink なら辿らず不合格（BadParent）。外のディレクトリは読まない。
#[test]
fn gpu2_symlinked_parent_is_not_followed() {
    let expected: Expected = [("/usr/lib/libx.so".to_string(), "libx.so.1".to_string())].into();
    let outside = TempRoot::new();
    outside.link("libx.so.1", "/libx.so");
    let root = TempRoot::new();
    std::fs::create_dir_all(root.path().join("usr")).unwrap();
    symlink(outside.path(), root.path().join("usr/lib")).unwrap();
    let snap = snapshot(root.path(), &expected);
    assert!(snap.symlinks.is_empty());
    let r = verify(&expected, &Snapshot::default(), &snap);
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [SymlinkMismatch::BadParent {
            link: "/usr/lib/libx.so".into()
        }]
    );
}

/// GPU-2: usr-merge の rootfs では `/lib/...` のリンク側を `/usr/lib/...` へ正規化してから照合する。
#[test]
fn gpu2_usr_merge_link_path_is_normalized() {
    let h = synth_hooks(&[&["--link", "libfoo.so.1::/lib/libfoo.so"]]);
    let raw = expected_links(&h).unwrap();
    let root = TempRoot::new();
    root.link("usr/lib", "/lib");
    let layout = detect_usr_merge_layout(root.path()).unwrap();
    let expected = normalize_expected(&raw, &layout).unwrap();
    assert!(expected.contains_key("/usr/lib/libfoo.so"));
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    let before = snapshot(root.path(), &expected);
    root.link("libfoo.so.1", "/usr/lib/libfoo.so");
    verify(&expected, &before, &snapshot(root.path(), &expected)).assert_pass();
}

// ---------------------------------------------------------------- 層 B の接着部（偽フックで駆動。既定の集合）

use symlink_coverage_check::{HookWindowCoverage, per_hook_expected, per_hook_repeated};

/// PoC-14 の実機相当の 7 フック（添字 0・1・6 が create-symlinks）の窓を、偽の実行で駆動する。
/// `others` が真なら、間のフック（添字 3 の ldconfig 役）が期待リンクと同じ親に別の symlink を足す。
fn drive_windows(
    json: &str,
    others: bool,
    tamper: impl Fn(&TempRoot, usize, &Expected),
) -> symlink_coverage_check::LayerBReport {
    let hooks = hooks_of(json, &["all"]);
    let root = TempRoot::new();
    root.link("usr/lib", "/lib");
    std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
    let layout = detect_usr_merge_layout(root.path()).unwrap();
    let per_hook = per_hook_expected(&hooks, &layout).unwrap();
    let cov = HookWindowCoverage::new(root.path(), per_hook.clone());
    cov.begin();
    for (i, exp) in per_hook.iter().enumerate() {
        if let Some(exp) = exp {
            run_fake_hook(&root, exp);
            tamper(&root, i, exp);
        } else if others && i == 3 {
            root.link("libfoo.so.1", "/usr/lib/x86_64-linux-gnu/libfoo.so");
        }
        cov.on_hook_done(i, true);
    }
    cov.finish()
}

/// GPU-2・REPAIR-12: 窓の外の他フックが同じ親に作る symlink は数えず、PoC-14 の実機の 3 フック・37 件で合格する。
#[test]
fn gpu2_window_ignores_symlinks_made_by_other_hooks() {
    let r = drive_windows(DEVBOX02, true, |_, _, _| {});
    assert_eq!(
        (
            r.target_hooks,
            r.verified_hooks,
            r.expected_links,
            r.created_symlinks
        ),
        (3, 3, 37, 37)
    );
    r.assert_pass();
}

/// GPU-2: create-symlinks の窓の中で余分な symlink が作られたら Unexpected で不合格。
#[test]
fn gpu2_window_detects_unexpected_link_inside_window() {
    let r = drive_windows(DEVBOX02, false, |root, i, _| {
        if i == 1 {
            root.link("x", "/usr/lib/x86_64-linux-gnu/extra-link");
        }
    });
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [(
            1,
            SymlinkMismatch::Unexpected {
                link: "/usr/lib/x86_64-linux-gnu/extra-link".into(),
                target: "x".into()
            }
        )]
    );
}

/// GPU-2: 窓の中で 1 件作られなければ Missing、向き先違いなら WrongTarget（フックの添字つき）。
#[test]
fn gpu2_window_detects_missing_and_wrong_target() {
    let skip = "/usr/lib/x86_64-linux-gnu/libcuda.so";
    let hooks = hooks_of(DEVBOX02, &["all"]);
    let root = TempRoot::new();
    std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
    let layout = detect_usr_merge_layout(root.path()).unwrap();
    let per_hook = per_hook_expected(&hooks, &layout).unwrap();
    let cov = HookWindowCoverage::new(root.path(), per_hook.clone());
    cov.begin();
    for (i, exp) in per_hook.iter().enumerate() {
        if let Some(exp) = exp {
            for (l, t) in exp {
                if l == skip {
                    continue;
                }
                root.link(
                    if l.ends_with("libEGL_nvidia.so.0") {
                        "bad"
                    } else {
                        t
                    },
                    l,
                );
            }
        }
        cov.on_hook_done(i, true);
    }
    let r = cov.finish();
    assert!(!r.is_pass());
    assert!(
        r.mismatches
            .iter()
            .any(|(_, m)| *m == SymlinkMismatch::Missing { link: skip.into() })
    );
    assert!(
        r.mismatches.iter().any(
            |(_, m)| matches!(m, SymlinkMismatch::WrongTarget { actual, .. } if actual == "bad")
        )
    );
}

/// GPU-2: フック失敗の通知・添字の飛びは不合格にする。
#[test]
fn gpu2_window_rejects_failed_or_out_of_order_hooks() {
    let h = synth_hooks(&[&["--link", "a::/x/l"]]);
    let per_hook =
        per_hook_expected(&h, &detect_usr_merge_layout(Path::new("/")).unwrap()).unwrap();
    let root = TempRoot::new();
    let cov = HookWindowCoverage::new(root.path(), per_hook.clone());
    cov.begin();
    root.link("a", "/x/l");
    cov.on_hook_done(0, false);
    assert!(!cov.finish().is_pass());

    let cov = HookWindowCoverage::new(root.path(), per_hook);
    cov.begin();
    cov.on_hook_done(2, true);
    let r = cov.finish();
    assert!(!r.is_pass());
    assert!(r.errors.iter().any(|e| e.contains("out of order")));
}

/// GPU-2・REPAIR-12: 対象フックが 0 件（期待 0 件）の空振りは合格にしない。
#[test]
fn gpu2_window_with_no_target_hooks_is_not_a_pass() {
    let root = TempRoot::new();
    let cov = HookWindowCoverage::new(root.path(), vec![None, None]);
    cov.begin();
    cov.on_hook_done(0, true);
    cov.on_hook_done(1, true);
    assert!(!cov.finish().is_pass());
}

/// GPU-2: 窓の途中で止まり、対象フックの後ろの通知が来なければ不合格（窓が閉じていない）。
#[test]
fn gpu2_window_not_closed_is_not_a_pass() {
    let h = synth_hooks(&[&["--link", "a::/x/l"]]);
    let per_hook =
        per_hook_expected(&h, &detect_usr_merge_layout(Path::new("/")).unwrap()).unwrap();
    let root = TempRoot::new();
    let cov = HookWindowCoverage::new(root.path(), per_hook);
    cov.begin();
    assert!(!cov.finish().is_pass());
}

/// GPU-2: 2 つの create-symlinks が同じ (target, link) を持つとき、後のフックの窓では既存扱いにせず、
/// 割り当ては最初のフックだけで、全体の一意件数は 2 件。向き先違いは拒否する。
#[test]
fn gpu2_per_hook_assignment_folds_duplicates_across_hooks() {
    let layout = detect_usr_merge_layout(Path::new("/")).unwrap();
    let h = synth_hooks(&[
        &["--link", "a::/x/l", "--link", "b::/x/m"],
        &["--link", "a::/x/l"],
    ]);
    let per = per_hook_expected(&h, &layout).unwrap();
    let sizes: Vec<usize> = per
        .iter()
        .map(|e| e.as_ref().map_or(0, |m| m.len()))
        .collect();
    assert_eq!(sizes, [2, 0]);
    let bad = synth_hooks(&[&["--link", "a::/x/l"], &["--link", "b::/x/l"]]);
    assert_eq!(
        per_hook_expected(&bad, &layout),
        Err(ExtractError::ConflictingTargets("/x/l".into()))
    );
}

/// 2 番目も `a::/x/l` を挙げる（ほかに `b::/x/m`）2 フックを窓で駆動し、2 番目のフックの終了前に `after_second` で破損を注入する。
/// 戻りは (集計, 重複リンクの割り当て)。1 番目のフックは正しく作る。
fn drive_duplicate_hooks(
    after_second: impl Fn(&TempRoot),
) -> (symlink_coverage_check::LayerBReport, Vec<Option<Expected>>) {
    let layout = detect_usr_merge_layout(Path::new("/")).unwrap();
    let h = synth_hooks(&[
        &["--link", "a::/x/l"],
        &["--link", "a::/x/l", "--link", "b::/x/m"],
    ]);
    let per_hook = per_hook_expected(&h, &layout).unwrap();
    let repeated = per_hook_repeated(&h, &layout).unwrap();
    let root = TempRoot::new();
    let cov = HookWindowCoverage::new(root.path(), per_hook).with_repeated(repeated.clone());
    cov.begin();
    root.link("a", "/x/l");
    cov.on_hook_done(0, true);
    root.link("b", "/x/m");
    after_second(&root);
    cov.on_hook_done(1, true);
    (cov.finish(), repeated)
}

/// GPU-2・REPAIR-12: 重複リンクは件数に数えず（一意 2 件）、2 番目のフックの後も残っていれば合格する。
#[test]
fn gpu2_duplicate_link_in_later_hook_passes_when_intact() {
    let (r, repeated) = drive_duplicate_hooks(|_| {});
    let want: Expected = [("/x/l".to_string(), "a".to_string())].into();
    assert_eq!(repeated, [Some(Expected::new()), Some(want)]);
    assert_eq!(
        (
            r.target_hooks,
            r.verified_hooks,
            r.expected_links,
            r.created_symlinks
        ),
        (2, 2, 2, 2)
    );
    r.assert_pass();
}

/// GPU-2・REPAIR-12: 後続フックが先行フックの作ったリンクを削除したら Missing で不合格（終了コード 0 でも）。
#[test]
fn gpu2_duplicate_link_removed_by_later_hook_is_missing() {
    let (r, _) = drive_duplicate_hooks(|root| {
        std::fs::remove_file(root.path().join("x/l")).unwrap();
    });
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [(
            1,
            SymlinkMismatch::Missing {
                link: "/x/l".into()
            }
        )]
    );
}

/// GPU-2・REPAIR-12: 後続フックが先行フックのリンクを別の向き先へ付け替えたら WrongTarget で不合格。
#[test]
fn gpu2_duplicate_link_retargeted_by_later_hook_is_wrong_target() {
    let (r, _) = drive_duplicate_hooks(|root| {
        std::fs::remove_file(root.path().join("x/l")).unwrap();
        root.link("evil", "/x/l");
    });
    assert!(!r.is_pass());
    assert_eq!(
        r.mismatches,
        [(
            1,
            SymlinkMismatch::WrongTarget {
                link: "/x/l".into(),
                expected: "a".into(),
                actual: "evil".into()
            }
        )]
    );
}
