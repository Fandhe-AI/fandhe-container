//! PoC-14 実測値との一致検証の結合試験（TASK-126.4・GPU-1・MS-10・REPAIR-12）。
//!
//! NVIDIA Container Toolkit が生成した CDI spec を `parse_cdi_spec` → `aggregate_container_edits`
//! （→ `normalize_cdi_spec_paths`）の公開 API だけで通し、PoC-14（gpu-passthrough-cdi。node4〔aarch64〕・
//! dev-box02〔x86_64〕）の実測値と deviceNodes・mounts・env の件数が完全一致し、未知フィールドが
//! 0 件であることを具体値で機械照合する。
//!
//! fixture（`tests/fixtures/poc14-*.json`）は元の `nvidia.yaml`（成果物には sha256 のみ残る）ではなく、
//! PoC の `03-poc/gpu-passthrough-cdi/results/{node4,devbox02}-cdi_merged.json`（デバイス `all` と
//! トップレベルのマージ結果）と `*-cdi_parse_result.json`（件数）から再構成した CDI spec である
//! （元ファイルと sha256 は一致しない）。GPU の UUID 名は成果物で伏字のため合成値を置いた。
//! `poc14-devbox02-mount-paths-spec*.txt` は `devbox02-cdi_mount_paths_spec{,_normalized}.txt` の写し。
//! 期待値は fixture と独立に、PoC の実測値をリテラルで書く。

use std::collections::BTreeSet;

use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{PathLayouts, UsrMergeLayout, normalize_cdi_spec_paths};
use fandhe_container_gpu::cdi_spec::{CdiSpec, CdiSpecErrorCode, parse_cdi_spec};

const NODE4: &str = include_str!("fixtures/poc14-node4.json");
const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");
const DEVBOX02_PATHS_SPEC: &str = include_str!("fixtures/poc14-devbox02-mount-paths-spec.txt");
const DEVBOX02_PATHS_NORMALIZED: &str =
    include_str!("fixtures/poc14-devbox02-mount-paths-spec-normalized.txt");

/// PoC の `uniqueDeviceNodePaths`（両機で同一の 7 件）。
const POC14_DEVICE_NODES: [&str; 7] = [
    "/dev/dri/card0",
    "/dev/dri/renderD128",
    "/dev/nvidia-modeset",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia0",
    "/dev/nvidiactl",
];
/// 集計順（トップレベル 4 件 → デバイス 3 件。GPU-1・#1888）の deviceNodes。
const POC14_DEVICE_NODES_ORDERED: [&str; 7] = [
    "/dev/nvidia-modeset",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidiactl",
    "/dev/nvidia0",
    "/dev/dri/card0",
    "/dev/dri/renderD128",
];
const POC14_HOOK_SUBCOMMANDS: [&str; 7] = [
    "create-symlinks",
    "create-symlinks",
    "enable-cuda-compat",
    "update-ldcache",
    "disable-device-node-modification",
    "update-application-profile",
    "create-symlinks",
];
const POC14_NODE4_MOUNTS: usize = 47;
const POC14_DEVBOX02_MOUNTS: usize = 54;
const POC14_ENV: usize = 2;
const UUID_NAME: &str = "GPU-00000000-0000-0000-0000-000000000000";

fn parse(src: &str) -> CdiSpec {
    parse_cdi_spec(src).unwrap()
}

fn lines(src: &str) -> Vec<&str> {
    src.lines().collect()
}

fn assert_spec_shape(spec: &CdiSpec, mounts: usize) {
    assert_eq!(spec.cdi_version, "0.7.0");
    assert_eq!(spec.kind, "nvidia.com/gpu");
    let names: Vec<&str> = spec.devices.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["0", UUID_NAME, "all"]);
    for d in &spec.devices {
        let e = &d.container_edits;
        assert_eq!(e.device_nodes.len(), 3);
        assert_eq!(e.hooks.len(), 1);
        assert_eq!(e.additional_gids.len(), 2);
        assert_eq!(e.mounts.len(), 0);
        assert_eq!(e.env.len(), 0);
    }
    let t = &spec.container_edits;
    assert_eq!(t.device_nodes.len(), 4);
    assert_eq!(t.env.len(), POC14_ENV);
    assert_eq!(t.hooks.len(), 6);
    assert_eq!(t.mounts.len(), mounts);
    assert_eq!(t.additional_gids.len(), 0);
}

/// 集計結果を PoC の実測値と照合する共通部。`env` は `Debug` が伏字のため `iter()` で比べる。
fn assert_aggregate(spec: &CdiSpec, mounts: usize, gids: &[u32], env: [&str; 2]) {
    let a = aggregate_container_edits(spec, &["all"]).unwrap();
    let nodes: Vec<&str> = a.device_nodes().iter().map(|n| n.path.as_str()).collect();
    assert_eq!(nodes, POC14_DEVICE_NODES_ORDERED);
    let got: BTreeSet<&str> = nodes.iter().copied().collect();
    let want: BTreeSet<&str> = POC14_DEVICE_NODES.iter().copied().collect();
    let diff: Vec<&&str> = got.symmetric_difference(&want).collect();
    assert_eq!(diff.len(), 0, "deviceNodes diff: {diff:?}");

    assert_eq!(a.mounts().len(), mounts);
    let uniq: BTreeSet<&str> = a
        .mounts()
        .iter()
        .map(|m| m.container_path.as_str())
        .collect();
    assert_eq!(uniq.len(), mounts);

    assert_eq!(a.env().len(), POC14_ENV);
    let got_env: Vec<&str> = a.env().iter().map(String::as_str).collect();
    assert_eq!(got_env, env);

    assert_eq!(a.hooks().len(), 7);
    assert!(a.hooks().iter().all(|h| h.hook_name == "createContainer"));
    let subs: Vec<&str> = a
        .hooks()
        .iter()
        .map(|h| h.args.get(1).map_or("", String::as_str))
        .collect();
    assert_eq!(subs, POC14_HOOK_SUBCOMMANDS);
    assert_eq!(a.additional_gids(), gids);

    // 各デバイスの edits は同一で、`all` は自動展開されない（通常の名前）。
    let zero = aggregate_container_edits(spec, &["0"]).unwrap();
    assert_eq!(zero.device_nodes(), a.device_nodes());
    assert_eq!(zero.mounts(), a.mounts());
}

/// GPU-1: node4（aarch64）の spec が未知フィールド 0 件で読め、構造の件数が PoC と一致する。
#[test]
fn gpu1_poc14_node4_spec_parses_with_zero_unknown_fields() {
    assert_spec_shape(&parse(NODE4), POC14_NODE4_MOUNTS);
}

/// GPU-1: node4 の集計結果の件数・内容が Docker 観測（deviceNodes 7・mounts 47・env 2）と一致する。
#[test]
fn gpu1_poc14_node4_aggregate_matches_observed_counts() {
    assert_aggregate(
        &parse(NODE4),
        POC14_NODE4_MOUNTS,
        &[44, 993],
        [
            "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/aarch64-linux-gnu",
            "NVIDIA_VISIBLE_DEVICES=void",
        ],
    );
}

/// GPU-1: dev-box02（x86_64）の spec が未知フィールド 0 件で読め、構造の件数が PoC と一致する。
#[test]
fn gpu1_poc14_devbox02_spec_parses_with_zero_unknown_fields() {
    assert_spec_shape(&parse(DEVBOX02), POC14_DEVBOX02_MOUNTS);
}

/// GPU-1: dev-box02 の集計結果の件数・内容が Docker 観測（deviceNodes 7・mounts 54・env 2）と一致する。
#[test]
fn gpu1_poc14_devbox02_aggregate_matches_observed_counts() {
    assert_aggregate(
        &parse(DEVBOX02),
        POC14_DEVBOX02_MOUNTS,
        &[44, 990],
        [
            "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu",
            "NVIDIA_VISIBLE_DEVICES=void",
        ],
    );
}

fn container_paths(spec: &CdiSpec) -> Vec<String> {
    aggregate_container_edits(spec, &["all"])
        .unwrap()
        .mounts()
        .iter()
        .map(|m| m.container_path.clone())
        .collect()
}

fn assert_same_set(got: &[String], want: &[&str]) {
    let g: BTreeSet<&str> = got.iter().map(String::as_str).collect();
    let w: BTreeSet<&str> = want.iter().copied().collect();
    assert_eq!(g.len(), got.len(), "duplicate containerPath");
    assert_eq!(w.len(), want.len(), "duplicate expected path");
    let missing: Vec<&&str> = w.difference(&g).collect();
    let extra: Vec<&&str> = g.difference(&w).collect();
    assert_eq!(
        (missing.len(), extra.len()),
        (0, 0),
        "missing={missing:?} extra={extra:?}"
    );
}

/// GPU-1: dev-box02 は usr-merge 正規化後に PoC の正規化後一覧（54 件）と完全一致し、
/// 分離レイアウトでは正規化前一覧と一致する。deviceNodes・env は正規化で変わらない。
#[test]
fn gpu1_poc14_devbox02_usr_merge_normalized_mounts_match() {
    let normalized = lines(DEVBOX02_PATHS_NORMALIZED);
    let original = lines(DEVBOX02_PATHS_SPEC);
    assert_eq!(normalized.len(), POC14_DEVBOX02_MOUNTS);
    assert_eq!(original.len(), POC14_DEVBOX02_MOUNTS);

    let mut merged = parse(DEVBOX02);
    normalize_cdi_spec_paths(
        &mut merged,
        &PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::merged()),
    );
    let got = container_paths(&merged);
    assert_eq!(got.len(), POC14_DEVBOX02_MOUNTS);
    assert_same_set(&got, &normalized);
    for p in [
        "/usr/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin",
        "/usr/lib/firmware/nvidia/595.91.07/gsp_tu10x.bin",
    ] {
        assert!(got.iter().any(|g| g == p), "missing {p}");
    }
    let a = aggregate_container_edits(&merged, &["all"]).unwrap();
    assert_eq!(a.device_nodes().len(), 7);
    assert_eq!(a.env().len(), POC14_ENV);

    let mut split = parse(DEVBOX02);
    normalize_cdi_spec_paths(
        &mut split,
        &PathLayouts::new(UsrMergeLayout::split(), UsrMergeLayout::split()),
    );
    let got = container_paths(&split);
    assert_eq!(got.len(), POC14_DEVBOX02_MOUNTS);
    assert_same_set(&got, &original);
}

/// GPU-1: node4 も firmware 2 件だけが `/usr/lib/firmware/...` へ写り、件数 47・重複なしは変わらない。
#[test]
fn gpu1_poc14_node4_usr_merge_keeps_mount_count() {
    let before = container_paths(&parse(NODE4));
    let mut spec = parse(NODE4);
    normalize_cdi_spec_paths(
        &mut spec,
        &PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::merged()),
    );
    let after = container_paths(&spec);
    assert_eq!(after.len(), POC14_NODE4_MOUNTS);
    assert_eq!(
        after.iter().collect::<BTreeSet<_>>().len(),
        POC14_NODE4_MOUNTS
    );
    let rewritten: Vec<&str> = before
        .iter()
        .zip(after.iter())
        .filter(|(b, a)| b != a)
        .map(|(_, a)| a.as_str())
        .collect();
    assert_eq!(
        rewritten,
        [
            "/usr/lib/firmware/nvidia/580.173.02/gsp_ga10x.bin",
            "/usr/lib/firmware/nvidia/580.173.02/gsp_tu10x.bin"
        ]
    );
}

/// GPU-1: 未知フィールド 0 件の確認が空疎でないことの対照。各階層へ未知キーを足すと拒否される。
#[test]
fn gpu1_poc14_unknown_field_is_detected() {
    let anchors = [
        ("\"kind\": \"nvidia.com/gpu\",", "top-level"),
        ("\"containerEdits\": {", "containerEdits"),
        ("\"deviceNodes\": [\n   {", "deviceNodes[]"),
        ("\"mounts\": [\n   {", "mounts[]"),
    ];
    for (anchor, label) in anchors {
        let injected = NODE4.replacen(anchor, &format!("{anchor} \"unknownKey\": 1,"), 1);
        assert_ne!(injected, NODE4, "anchor not found: {label}");
        let e = parse_cdi_spec(&injected).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{label}");
        assert_eq!(e.message(), "CDI spec has an unknown field", "{label}");
    }
}
