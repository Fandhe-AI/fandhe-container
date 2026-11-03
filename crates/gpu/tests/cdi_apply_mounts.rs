//! CDI mounts の bind 指定への変換の結合試験（TASK-127.2・GPU-2・MS-10・REPAIR-12）。
//!
//! PoC-14 の fixture を `parse_cdi_spec` → `normalize_cdi_spec_paths` → `aggregate_container_edits`
//! → `cdi_bind_mounts` の公開 API だけで通し、件数・オプション・宛先を具体値で照合する。
//! 実 namespace の mountinfo での反映確認は配線（#2774）と実機試験（#552）の範囲。

use std::collections::BTreeSet;

use fandhe_container_gpu::cdi_apply::mounts::{CdiBindMount, CdiBindPropagation, cdi_bind_mounts};
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{PathLayouts, UsrMergeLayout, normalize_cdi_spec_paths};
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

const NODE4: &str = include_str!("fixtures/poc14-node4.json");
const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");
const DEVBOX02_NORMALIZED: &str =
    include_str!("fixtures/poc14-devbox02-mount-paths-spec-normalized.txt");

fn convert(src: &str) -> Vec<CdiBindMount> {
    let mut spec = parse_cdi_spec(src).unwrap();
    normalize_cdi_spec_paths(
        &mut spec,
        &PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::merged()),
    );
    let edits = aggregate_container_edits(&spec, &["all"]).unwrap();
    cdi_bind_mounts(&edits).unwrap()
}

fn check_common(mounts: &[CdiBindMount], total: usize) {
    assert_eq!(mounts.len(), total);
    // fixture は 1 件だけ noexec（rw）、残りは ro。全件 rbind / rprivate / nosuid / nodev。
    assert_eq!(mounts.iter().filter(|m| m.noexec()).count(), 1);
    assert_eq!(mounts.iter().filter(|m| m.read_only()).count(), total - 1);
    for m in mounts {
        assert!(m.recursive() && m.nosuid() && m.nodev());
        assert_eq!(m.propagation(), CdiBindPropagation::Private);
        assert_eq!(m.oci_type(), "bind");
        let o = m.oci_options();
        assert_eq!(o[0], "rbind");
        assert_eq!(o[1], if m.read_only() { "ro" } else { "rw" });
        assert_eq!(o[2..4], ["nosuid", "nodev"]);
        assert_eq!(o[4], if m.noexec() { "noexec" } else { "exec" });
        assert_eq!(o[5], "rprivate");
    }
}

/// GPU-2: node4 の 47 件がオプションを落とさず変換される。
#[test]
fn gpu2_task127_2_node4_options_preserved() {
    check_common(&convert(NODE4), 47);
}

/// GPU-2: dev-box02 の 54 件が変換され、宛先が正規化済みの一覧と一致する。
#[test]
fn gpu2_task127_2_devbox02_options_and_destinations() {
    let mounts = convert(DEVBOX02);
    check_common(&mounts, 54);
    let got: BTreeSet<&str> = mounts.iter().map(|m| m.destination()).collect();
    let want: BTreeSet<&str> = DEVBOX02_NORMALIZED.lines().collect();
    assert_eq!(got, want);
    let nvsmi = mounts
        .iter()
        .find(|m| m.destination() == "/usr/bin/nvidia-smi")
        .unwrap();
    assert_eq!(
        nvsmi.oci_options(),
        ["rbind", "ro", "nosuid", "nodev", "exec", "rprivate"]
    );
}
