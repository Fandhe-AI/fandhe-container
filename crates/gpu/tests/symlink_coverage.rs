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
//! - 層 B（本 issue の範囲外）: 実 GPU ホストで本物の `nvidia-cdi-hook` を走らせての照合。core の
//!   pre-pivot 段への配線（#2774）が済むまで実行できず、実機（人間担当）の作業になる。
//!
//! # 前提
//! 期待集合は実行される値と同じ経路（`parse_cdi_spec` → `aggregate_container_edits` →
//! `validate_create_container_hooks`）から作る。フック実行は Linux 限定のため `cfg` を Linux に絞る。

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fandhe_container_gpu::cdi_apply::hooks::{
    CdiCreateContainerHook, validate_create_container_hooks,
};
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{detect_usr_merge_layout, normalize_usr_merge_path};
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");
const NODE4: &str = include_str!("fixtures/poc14-node4.json");

/// 1 ディレクトリあたりの列挙件数の上限（無制限確保の防止）。
const MAX_DIR_ENTRIES: usize = 65536;

// ---------------------------------------------------------------- 期待リンクの抽出

/// 期待リンク集合の抽出失敗の種類（spec の `--link` 引数が不正）。
#[derive(Debug, PartialEq, Eq)]
enum ExtractError {
    /// 最後の `--link` に値が無い。
    MissingLinkValue,
    /// `--link` 以外の引数（`--link=...` や未知のフラグを含む）。
    UnexpectedArg(String),
    /// `::` が無い、2 個以上ある、または片側が空。
    BadPair(String),
    /// リンク側が正規化済みの絶対パスでない。
    BadLinkPath(String),
    /// 同じリンクに別々のターゲットがある。
    ConflictingTargets(String),
}

/// 期待リンク（link パス -> target 文字列）。
type Expected = BTreeMap<String, String>;

/// 集計済みフックから `create-symlinks` の `--link` を全件取り出す。同一 (target, link) は 1 件に畳む。
///
/// 比べる件数は畳んだ後の一意な件数。ターゲットは文字列のまま（相対ターゲットを解決しない）。
fn expected_links(hooks: &[CdiCreateContainerHook]) -> Result<Expected, ExtractError> {
    let mut out = Expected::new();
    for h in hooks {
        if h.args().get(1).map(String::as_str) != Some("create-symlinks") {
            continue;
        }
        let mut it = h.args().iter().skip(2);
        while let Some(flag) = it.next() {
            if flag != "--link" {
                return Err(ExtractError::UnexpectedArg(flag.clone()));
            }
            let value = it.next().ok_or(ExtractError::MissingLinkValue)?;
            let parts: Vec<&str> = value.split("::").collect();
            let [target, link] = parts.as_slice() else {
                return Err(ExtractError::BadPair(value.clone()));
            };
            if target.is_empty() || link.is_empty() {
                return Err(ExtractError::BadPair(value.clone()));
            }
            if !is_clean_absolute(link) {
                return Err(ExtractError::BadLinkPath((*link).to_string()));
            }
            match out.get(*link) {
                Some(t) if t != target => {
                    return Err(ExtractError::ConflictingTargets((*link).to_string()));
                }
                Some(_) => {}
                None => {
                    out.insert((*link).to_string(), (*target).to_string());
                }
            }
        }
    }
    Ok(out)
}

/// `/` 始まりで、空要素・`.`・`..`・`\` を含まないパスか。
fn is_clean_absolute(p: &str) -> bool {
    let Some(rest) = p.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && !p.contains('\\')
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
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

// ---------------------------------------------------------------- スナップショットと照合

/// 期待リンクの親ディレクトリ（rootfs 相対の絶対表記）ごとの列挙結果。
#[derive(Debug, Default)]
struct Snapshot {
    symlinks: BTreeMap<String, String>,
    non_symlinks: BTreeSet<String>,
    bad_parents: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum SymlinkMismatch {
    Missing {
        link: String,
    },
    WrongTarget {
        link: String,
        expected: String,
        actual: String,
    },
    Unexpected {
        link: String,
        target: String,
    },
    NotSymlink {
        link: String,
    },
    PreExisting {
        link: String,
        target: String,
    },
    BadParent {
        link: String,
    },
}

#[derive(Debug)]
struct SymlinkCoverageReport {
    expected_links: usize,
    created_symlinks: usize,
    mismatches: Vec<SymlinkMismatch>,
}

impl SymlinkCoverageReport {
    fn is_pass(&self) -> bool {
        self.created_symlinks == self.expected_links && self.mismatches.is_empty()
    }

    /// 不合格なら全件を並べて panic する（どのリンクが落ちたかを 1 回で分かるようにする。REPAIR-4）。
    fn assert_pass(&self) {
        assert!(
            self.is_pass(),
            "symlink coverage failed: expected={} created={} mismatches={:#?}",
            self.expected_links,
            self.created_symlinks,
            self.mismatches
        );
    }
}

/// 期待リンクの親ディレクトリだけを 1 段（再帰しない）列挙する。
///
/// 親は rootfs から 1 要素ずつ `symlink_metadata` で辿り、途中が symlink・ディレクトリ以外なら
/// 不正な親として記録して列挙しない（rootfs の外へ出ない）。親が無いのは空の列挙。
/// エントリは辿らず `read_link` のみ使う。
fn snapshot(rootfs: &Path, expected: &Expected) -> Snapshot {
    let mut snap = Snapshot::default();
    let parents: BTreeSet<&str> = expected
        .keys()
        .filter_map(|l| l.rsplit_once('/').map(|(p, _)| p))
        .collect();
    for parent in parents {
        let mut dir = rootfs.to_path_buf();
        let mut bad = false;
        let mut absent = false;
        for comp in parent.split('/').filter(|c| !c.is_empty()) {
            dir.push(comp);
            match std::fs::symlink_metadata(&dir) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    bad = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    absent = true;
                    break;
                }
                Err(e) => panic!("cannot inspect link parent: {e}"),
            }
        }
        if bad {
            snap.bad_parents.insert(parent.to_string());
            continue;
        }
        if absent {
            continue;
        }
        for (n, ent) in std::fs::read_dir(&dir).unwrap().enumerate() {
            assert!(
                n < MAX_DIR_ENTRIES,
                "too many entries in a link parent directory"
            );
            let ent = ent.unwrap();
            let name = ent.file_name().into_string().expect("non UTF-8 entry name");
            let full = format!("{parent}/{name}");
            if std::fs::symlink_metadata(ent.path())
                .unwrap()
                .file_type()
                .is_symlink()
            {
                let t = std::fs::read_link(ent.path()).unwrap();
                snap.symlinks.insert(
                    full,
                    t.into_os_string().into_string().expect("non UTF-8 target"),
                );
            } else {
                snap.non_symlinks.insert(full);
            }
        }
    }
    snap
}

/// 実行前後のスナップショットを期待集合と照合する。
fn verify(expected: &Expected, before: &Snapshot, after: &Snapshot) -> SymlinkCoverageReport {
    let mut mismatches = Vec::new();
    let created: BTreeMap<&String, &String> = after
        .symlinks
        .iter()
        .filter(|(k, _)| !before.symlinks.contains_key(*k))
        .collect();
    for (link, target) in expected {
        let parent = link.rsplit_once('/').map_or("", |(p, _)| p);
        if after.bad_parents.contains(parent) {
            mismatches.push(SymlinkMismatch::BadParent { link: link.clone() });
        } else if let Some(t) = before.symlinks.get(link) {
            mismatches.push(SymlinkMismatch::PreExisting {
                link: link.clone(),
                target: t.clone(),
            });
        } else if let Some(actual) = after.symlinks.get(link) {
            if actual != target {
                mismatches.push(SymlinkMismatch::WrongTarget {
                    link: link.clone(),
                    expected: target.clone(),
                    actual: actual.clone(),
                });
            }
        } else if after.non_symlinks.contains(link) {
            mismatches.push(SymlinkMismatch::NotSymlink { link: link.clone() });
        } else {
            mismatches.push(SymlinkMismatch::Missing { link: link.clone() });
        }
    }
    for (link, target) in &created {
        if !expected.contains_key(*link) {
            mismatches.push(SymlinkMismatch::Unexpected {
                link: (*link).clone(),
                target: (*target).clone(),
            });
        }
    }
    SymlinkCoverageReport {
        expected_links: expected.len(),
        created_symlinks: created.len(),
        mismatches,
    }
}

// ---------------------------------------------------------------- 試験の補助

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// 一時 rootfs。Drop で削除する。
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("fandhe-gpu-symlink-cov-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(std::fs::canonicalize(&p).unwrap())
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

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
    let expected: Expected = raw
        .iter()
        .map(|(l, t)| (normalize_usr_merge_path(l, &layout).into_owned(), t.clone()))
        .collect();
    assert!(expected.contains_key("/usr/lib/libfoo.so"));
    std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
    let before = snapshot(root.path(), &expected);
    root.link("libfoo.so.1", "/usr/lib/libfoo.so");
    verify(&expected, &before, &snapshot(root.path(), &expected)).assert_pass();
}
