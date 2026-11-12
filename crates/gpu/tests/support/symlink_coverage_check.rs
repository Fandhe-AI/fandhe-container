//! `create-symlinks` フックの全リンク網羅検証器（TASK-127.5・GPU-2・MS-10・REPAIR-12。#4589）。
//!
//! `tests/symlink_coverage.rs`（層 A。既定の集合。フックの役を `symlink(2)` が務める）と
//! `tests/cuda_workload.rs`（層 B。実機前提。本物の `nvidia-cdi-hook` を走らせる）の両方が
//! `#[path]` で取り込む。検証器を 1 か所に置き、両層が同じ判定基準（欠落・向き先違い・余分・既存・
//! 不正な親を 1 件でも不合格）で照合する。
//!
//! # 不変条件（SEC-1）
//! rootfs は読むだけで書かない。期待リンクの親ディレクトリは 1 要素ずつ `symlink_metadata` で辿り、
//! 途中が symlink・ディレクトリ以外なら `BadParent` にして列挙しない。エントリは辿らず `read_link` のみ使う。
//! パス検査と列挙の間の競合（TOCTOU）は残るが、対象は試験用に複製した rootfs で、窓の前後ではフックは
//! 動いていない。
//!
//! # フックごとの窓（層 B）
//! `update-ldcache` 等の他フックは期待リンクと同じ親に別の symlink を作りうる。そこで `HookWindowCoverage`
//! は `create-symlinks` フック 1 件ごとの直前・直後のスナップショットだけで照合する。

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fandhe_container_gpu::cdi_apply::hooks::CdiCreateContainerHook;
use fandhe_container_gpu::cdi_paths::{UsrMergeLayout, normalize_usr_merge_path};

/// 1 ディレクトリあたりの列挙件数の上限（無制限確保の防止）。
const MAX_DIR_ENTRIES: usize = 65536;

// ---------------------------------------------------------------- 期待リンクの抽出

/// 期待リンク集合の抽出失敗の種類（spec の `--link` 引数が不正）。
#[derive(Debug, PartialEq, Eq)]
pub enum ExtractError {
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
pub type Expected = BTreeMap<String, String>;

/// 集計済みフックから `create-symlinks` の `--link` を全件取り出す。同一 (target, link) は 1 件に畳む。
///
/// 比べる件数は畳んだ後の一意な件数。ターゲットは文字列のまま（相対ターゲットを解決しない）。
pub fn expected_links(hooks: &[CdiCreateContainerHook]) -> Result<Expected, ExtractError> {
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
pub fn is_clean_absolute(p: &str) -> bool {
    let Some(rest) = p.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && !p.contains('\\')
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

// ---------------------------------------------------------------- スナップショットと照合

/// 期待リンクの親ディレクトリ（rootfs 相対の絶対表記）ごとの列挙結果。
#[derive(Debug, Default)]
pub struct Snapshot {
    pub symlinks: BTreeMap<String, String>,
    pub non_symlinks: BTreeSet<String>,
    pub bad_parents: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SymlinkMismatch {
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
pub struct SymlinkCoverageReport {
    pub expected_links: usize,
    pub created_symlinks: usize,
    pub mismatches: Vec<SymlinkMismatch>,
}

impl SymlinkCoverageReport {
    // 層 A（tests/symlink_coverage.rs）だけが使う。層 B（tests/cuda_workload.rs）は LayerBReport を使うため、
    // そちらの取り込みでは未使用になる（項目単位で許可する）。
    #[allow(dead_code)]
    pub fn is_pass(&self) -> bool {
        self.created_symlinks == self.expected_links && self.mismatches.is_empty()
    }

    /// 不合格なら全件を並べて panic する（どのリンクが落ちたかを 1 回で分かるようにする。REPAIR-4）。
    // 層 A（tests/symlink_coverage.rs）だけが使う。層 B（tests/cuda_workload.rs）は LayerBReport を使うため、
    // そちらの取り込みでは未使用になる（項目単位で許可する）。
    #[allow(dead_code)]
    pub fn assert_pass(&self) {
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
pub fn snapshot(rootfs: &Path, expected: &Expected) -> Result<Snapshot, String> {
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
                Err(e) => return Err(format!("cannot inspect link parent {parent}: {e}")),
            }
        }
        if bad {
            snap.bad_parents.insert(parent.to_string());
            continue;
        }
        if absent {
            continue;
        }
        let rd = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot list link parent {parent}: {e}"))?;
        for (n, ent) in rd.enumerate() {
            if n >= MAX_DIR_ENTRIES {
                return Err(format!("too many entries in link parent {parent}"));
            }
            let ent = ent.map_err(|e| format!("cannot read entry in {parent}: {e}"))?;
            let name = ent
                .file_name()
                .into_string()
                .map_err(|_| format!("non UTF-8 entry name in {parent}"))?;
            let full = format!("{parent}/{name}");
            let meta = std::fs::symlink_metadata(ent.path())
                .map_err(|e| format!("cannot stat {full}: {e}"))?;
            if meta.file_type().is_symlink() {
                let t = std::fs::read_link(ent.path())
                    .map_err(|e| format!("cannot read link {full}: {e}"))?;
                let t = t
                    .into_os_string()
                    .into_string()
                    .map_err(|_| format!("non UTF-8 target of {full}"))?;
                snap.symlinks.insert(full, t);
            } else {
                snap.non_symlinks.insert(full);
            }
        }
    }
    Ok(snap)
}

/// 実行前後のスナップショットを期待集合と照合する。
pub fn verify(expected: &Expected, before: &Snapshot, after: &Snapshot) -> SymlinkCoverageReport {
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
// ---------------------------------------------------------------- usr-merge 正規化とフックごとの割り当て

/// 期待集合のリンク側を usr-merge の rootfs の実位置へ正規化する。正規化後に衝突して向き先が違えば拒否する。
pub fn normalize_expected(
    expected: &Expected,
    layout: &UsrMergeLayout,
) -> Result<Expected, ExtractError> {
    let mut out = Expected::new();
    for (link, target) in expected {
        let n = normalize_usr_merge_path(link, layout).into_owned();
        match out.get(&n) {
            Some(t) if t != target => return Err(ExtractError::ConflictingTargets(n)),
            Some(_) => {}
            None => {
                out.insert(n, target.clone());
            }
        }
    }
    Ok(out)
}

/// `create-symlinks` フックか。
pub fn is_create_symlinks(h: &CdiCreateContainerHook) -> bool {
    h.args().get(1).map(String::as_str) == Some("create-symlinks")
}

/// フックごとの割り当て: 初出のリンク（`owned`。件数に数える）と、先行フックが既に挙げた同じ向き先のリンク（`repeated`）。
fn split_per_hook(
    hooks: &[CdiCreateContainerHook],
    layout: &UsrMergeLayout,
) -> Result<Vec<Option<(Expected, Expected)>>, ExtractError> {
    let mut seen = Expected::new();
    let mut out = Vec::with_capacity(hooks.len());
    for h in hooks {
        if !is_create_symlinks(h) {
            out.push(None);
            continue;
        }
        let own = normalize_expected(&expected_links(std::slice::from_ref(h))?, layout)?;
        let mut owned = Expected::new();
        let mut repeated = Expected::new();
        for (link, target) in own {
            match seen.get(&link) {
                Some(t) if *t != target => return Err(ExtractError::ConflictingTargets(link)),
                Some(_) => {
                    repeated.insert(link, target);
                }
                None => {
                    seen.insert(link.clone(), target.clone());
                    owned.insert(link, target);
                }
            }
        }
        out.push(Some((owned, repeated)));
    }
    Ok(out)
}

/// フックの添字ごとの期待集合（初出のリンクだけ）。`create-symlinks` 以外は `None`。
///
/// 別フックが同じ（正規化後の）link を挙げたら最初のフックだけに割り当てる（層 A の一意件数への畳み込みと同じ）。
/// 別フック間で向き先が違えば `ConflictingTargets`。全体の一意件数は各要素の `len` の和。
/// 後続フックの重複リンクは [`per_hook_repeated`] で取り出し、存在と向き先を別に検証する。
pub fn per_hook_expected(
    hooks: &[CdiCreateContainerHook],
    layout: &UsrMergeLayout,
) -> Result<Vec<Option<Expected>>, ExtractError> {
    Ok(split_per_hook(hooks, layout)?
        .into_iter()
        .map(|o| o.map(|(owned, _)| owned))
        .collect())
}

/// フックの添字ごとの、先行フックが既に挙げた同じ向き先のリンク。件数には数えず、後続フックの終了後に
/// 存在と向き先だけを照合する（先行が作ったリンクを後続が消す・付け替える破損を見逃さない。GPU-2）。
pub fn per_hook_repeated(
    hooks: &[CdiCreateContainerHook],
    layout: &UsrMergeLayout,
) -> Result<Vec<Option<Expected>>, ExtractError> {
    Ok(split_per_hook(hooks, layout)?
        .into_iter()
        .map(|o| o.map(|(_, repeated)| repeated))
        .collect())
}

/// 重複リンクが終了後のスナップショットに期待どおり残っているかを照合する。
fn verify_repeated(expected: &Expected, after: &Snapshot) -> Vec<SymlinkMismatch> {
    let mut out = Vec::new();
    for (link, target) in expected {
        let parent = link.rsplit_once('/').map_or("", |(p, _)| p);
        if after.bad_parents.contains(parent) {
            out.push(SymlinkMismatch::BadParent { link: link.clone() });
        } else if let Some(actual) = after.symlinks.get(link) {
            if actual != target {
                out.push(SymlinkMismatch::WrongTarget {
                    link: link.clone(),
                    expected: target.clone(),
                    actual: actual.clone(),
                });
            }
        } else if after.non_symlinks.contains(link) {
            out.push(SymlinkMismatch::NotSymlink { link: link.clone() });
        } else {
            out.push(SymlinkMismatch::Missing { link: link.clone() });
        }
    }
    out
}

// ---------------------------------------------------------------- 層 B: フックごとの窓

/// 層 B の集計結果。
#[derive(Debug, Default)]
pub struct LayerBReport {
    /// 期待集合を持つ（`create-symlinks`）フックの数。
    pub target_hooks: usize,
    /// 窓を閉じて照合したフックの数。
    pub verified_hooks: usize,
    pub expected_links: usize,
    pub created_symlinks: usize,
    /// (フックの添字, 不一致)。全件。
    pub mismatches: Vec<(usize, SymlinkMismatch)>,
    /// 呼び出し順の違反・フック失敗・スナップショット失敗。
    pub errors: Vec<String>,
}

impl LayerBReport {
    pub fn is_pass(&self) -> bool {
        self.target_hooks >= 1
            && self.verified_hooks == self.target_hooks
            && self.expected_links > 0
            && self.created_symlinks == self.expected_links
            && self.mismatches.is_empty()
            && self.errors.is_empty()
    }

    /// 不合格なら全件を並べて panic する（REPAIR-4）。
    pub fn assert_pass(&self) {
        assert!(
            self.is_pass(),
            "symlink coverage (layer B) failed: hooks={}/{} expected={} created={} mismatches={:#?} errors={:#?}",
            self.verified_hooks,
            self.target_hooks,
            self.expected_links,
            self.created_symlinks,
            self.mismatches,
            self.errors
        );
    }
}

struct WindowState {
    next_index: usize,
    before: Option<Snapshot>,
    report: LayerBReport,
}

/// 実フック実行の途中経過から、`create-symlinks` フックごとの窓で前後のスナップショットを採って照合する。
///
/// 呼び出し契約: `begin()` を実行前に 1 回、`on_hook_done(i, ..)` を添字 0, 1, 2, … の順に 1 回ずつ
/// （`run_create_container_hooks_with_recorder` の recorder が各試行の終了後・次の起動前に同期で呼ぶ）。
pub struct HookWindowCoverage {
    rootfs: PathBuf,
    per_hook: Vec<Option<Expected>>,
    /// 先行フックと重複するリンク（件数に数えず、存在と向き先だけ照合する）。
    repeated: Vec<Option<Expected>>,
    state: RefCell<WindowState>,
}

impl HookWindowCoverage {
    pub fn new(rootfs: &Path, per_hook: Vec<Option<Expected>>) -> Self {
        let report = LayerBReport {
            target_hooks: per_hook.iter().flatten().count(),
            ..LayerBReport::default()
        };
        Self {
            rootfs: rootfs.to_path_buf(),
            per_hook,
            repeated: Vec::new(),
            state: RefCell::new(WindowState {
                next_index: 0,
                before: None,
                report,
            }),
        }
    }

    /// 先行フックと重複するリンク（[`per_hook_repeated`]）を渡す。各フックの終了後に存在と向き先を照合する。
    pub fn with_repeated(mut self, repeated: Vec<Option<Expected>>) -> Self {
        self.repeated = repeated;
        self
    }

    fn open_window(&self, st: &mut WindowState, index: usize) {
        st.before = None;
        if let Some(Some(exp)) = self.per_hook.get(index) {
            match snapshot(&self.rootfs, exp) {
                Ok(s) => st.before = Some(s),
                Err(e) => st.report.errors.push(format!("hook {index} before: {e}")),
            }
        }
    }

    /// 実行前に呼ぶ。添字 0 が対象なら窓を開く。
    pub fn begin(&self) {
        let mut st = self.state.borrow_mut();
        self.open_window(&mut st, 0);
    }

    /// 添字 `index` のフックの試行が終わったときに呼ぶ。`succeeded` はエラーなしかつ終了コード 0。
    pub fn on_hook_done(&self, index: usize, succeeded: bool) {
        let mut st = self.state.borrow_mut();
        if index != st.next_index {
            let want = st.next_index;
            st.report
                .errors
                .push(format!("hook index out of order: got {index} want {want}"));
        }
        st.next_index = index.saturating_add(1);
        if !succeeded {
            st.report.errors.push(format!("hook {index} failed"));
        }
        if let Some(Some(exp)) = self.per_hook.get(index) {
            match (st.before.take(), snapshot(&self.rootfs, exp)) {
                (Some(before), Ok(after)) => {
                    let r = verify(exp, &before, &after);
                    st.report.verified_hooks += 1;
                    st.report.expected_links += r.expected_links;
                    st.report.created_symlinks += r.created_symlinks;
                    st.report
                        .mismatches
                        .extend(r.mismatches.into_iter().map(|m| (index, m)));
                }
                (None, _) => st
                    .report
                    .errors
                    .push(format!("hook {index}: no snapshot before the hook")),
                (_, Err(e)) => st.report.errors.push(format!("hook {index} after: {e}")),
            }
        }
        if let Some(Some(rep)) = self.repeated.get(index)
            && !rep.is_empty()
        {
            match snapshot(&self.rootfs, rep) {
                Ok(after) => st
                    .report
                    .mismatches
                    .extend(verify_repeated(rep, &after).into_iter().map(|m| (index, m))),
                Err(e) => st
                    .report
                    .errors
                    .push(format!("hook {index} repeated after: {e}")),
            }
        }
        let next = st.next_index;
        self.open_window(&mut st, next);
    }

    /// 集計を取り出す。
    pub fn finish(&self) -> LayerBReport {
        std::mem::take(&mut self.state.borrow_mut().report)
    }
}
