//! workspace の依存の向きの機械照合（#2435・TASK-114 追補・PLUG-1・PLUG-4・CRI-7・REPAIR-12）。
//!
//! 不変条件は「plugin-cri → cri・core の一方向で、core・cri から plugin-cri への辺は無い」こと。
//! `cargo metadata --no-deps` が返すマニフェスト上の宣言を、dependencies・build-dependencies・
//! dev-dependencies のすべてと `cfg(...)` 付きの target 依存も含めて辿り、core と cri の推移閉包に
//! plugin-cri が入らないことを確かめる。`--no-deps` は workspace のマニフェストだけを読むため、
//! 解決・ネットワーク・build ディレクトリのロックに触れず、`cargo test` の中から入れ子で呼べる。
//!
//! 役割の違い: `make plug4-core-invariance`（TASK-109.4）は plugin を足しても core の成果物
//! （rlib の sha256）が変わらないことを base と比べる。本試験はマニフェスト上の辺の向きを照合する。
//! `check-workspace-manifest` は membership の照合で、これらとは別の検査である。
//!
//! 置き場が plugin-cri ではなく cri なのは、JSON の解析に要る `serde_json` が cri の既存依存で、
//! plugin-cri へ足すと依存の追加（ユーザー承認事項）になるため。

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CORE: &str = "fandhe-container-core";
const CRI: &str = "fandhe-container-cri";
const PLUGIN_CRI: &str = "fandhe-container-plugin-cri";
const DEADLINE: Duration = Duration::from_secs(60);
/// kill 後の回収の猶予。
const REAP_GRACE: Duration = Duration::from_secs(5);

/// 出力を別スレッドで読み切りつつ、期限つきで待つ（パイプ詰まりと無期限待ちを避ける。REPAIR-5）。
fn run_cargo_metadata() -> serde_json::Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| env!("CARGO").into());
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let mut child = Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cargo metadata");
    let mut out = child.stdout.take().expect("stdout pipe");
    let mut err = child.stderr.take().expect("stderr pipe");
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if start.elapsed() > DEADLINE {
            let kill_result = child.kill();
            let reap_start = Instant::now();
            let mut reaped = false;
            while reap_start.elapsed() < REAP_GRACE {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    reaped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "cargo metadata did not exit within deadline (kill: {kill_result:?}, reaped: {reaped})"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = out_t.join().expect("stdout reader");
    let stderr = err_t.join().expect("stderr reader");
    assert!(status.success(), "cargo metadata failed: {stderr}");
    serde_json::from_str(&stdout).expect("metadata json")
}

/// workspace メンバーの名前から、その依存のうち workspace メンバーであるものの名前への写像。
/// 比較は package 名で行う（`manifest_path` は OS ごとに区切りが違うため使わない）。
fn workspace_graph(meta: &serde_json::Value) -> BTreeMap<String, BTreeSet<String>> {
    let packages = meta
        .get("packages")
        .and_then(|v| v.as_array())
        .expect("packages array");
    let names: BTreeSet<String> = packages
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
        .map(str::to_owned)
        .collect();
    let mut graph = BTreeMap::new();
    for p in packages {
        let name = p
            .get("name")
            .and_then(|n| n.as_str())
            .expect("package name");
        let deps = p
            .get("dependencies")
            .and_then(|v| v.as_array())
            .expect("dependencies array");
        let edges = deps
            .iter()
            .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
            .filter(|n| names.contains(*n))
            .map(str::to_owned)
            .collect();
        graph.insert(name.to_owned(), edges);
    }
    graph
}

/// `start` から到達できる package と、到達時の親（失敗時に経路を出すため）。
fn closure(graph: &BTreeMap<String, BTreeSet<String>>, start: &str) -> BTreeMap<String, String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut stack = vec![start.to_owned()];
    while let Some(cur) = stack.pop() {
        for next in graph.get(&cur).into_iter().flatten() {
            if !seen.contains_key(next) {
                seen.insert(next.clone(), cur.clone());
                stack.push(next.clone());
            }
        }
    }
    seen
}

fn path_to(parents: &BTreeMap<String, String>, start: &str, target: &str) -> String {
    let mut path = vec![target.to_owned()];
    let mut cur = target;
    while let Some(p) = parents.get(cur) {
        path.push(p.clone());
        if p == start {
            break;
        }
        cur = p;
    }
    path.reverse();
    path.join(" -> ")
}

/// core・cri から plugin-cri へ届く辺が無いこと（PLUG-1・PLUG-4・CRI-7）。
#[test]
fn plug1_plug4_core_and_cri_never_reach_plugin_cri() {
    let graph = workspace_graph(&run_cargo_metadata());
    for start in [CORE, CRI] {
        let reach = closure(&graph, start);
        assert!(
            !reach.contains_key(PLUGIN_CRI),
            "{start} must not depend on {PLUGIN_CRI}: {}",
            path_to(&reach, start, PLUGIN_CRI)
        );
    }
}

/// 陽性対照: 正しい向きの辺を検出できる（照合が空振りで通っていないこと）。
#[test]
fn plug1_metadata_graph_sees_plugin_cri_edges() {
    let graph = workspace_graph(&run_cargo_metadata());
    for name in [CORE, CRI, PLUGIN_CRI] {
        assert!(graph.contains_key(name), "{name} missing from metadata");
    }
    let direct = graph.get(PLUGIN_CRI).expect("plugin-cri edges");
    assert!(direct.contains(CORE), "plugin-cri -> core edge not seen");
    assert!(direct.contains(CRI), "plugin-cri -> cri edge not seen");
    assert!(
        closure(&graph, PLUGIN_CRI).contains_key(CORE),
        "plugin-cri closure lacks core"
    );
}
