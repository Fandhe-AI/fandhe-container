//! `devices[].containerEdits` とトップレベル `containerEdits` の集計（TASK-126.2・GPU-1・MS-10）。
//!
//! [`crate::cdi_spec::CdiSpec`]（TASK-126.1 が読み込んだ値）から、指定デバイス群の edits を 1 つの
//! [`AggregatedEdits`] にまとめる純粋関数の層。結果は TASK-126.3（usr-merge パス正規化）、
//! TASK-126.4（PoC-14 実測値との一致検証）、TASK-127（OCI spec への適用）が入力として使う。
//!
//! 集計規則（CDI 参照実装の InjectDevices に倣う。hooks の実行順の前提になる）:
//! - 要求デバイス順に各デバイスの edits を連結し、その後ろにトップレベル edits を 1 回だけ連結する。
//! - `deviceNodes` は `path`、`mounts` は `containerPath`、`env` は `=` より前のキーで同一性を判定する。
//!   完全に同一なら先勝ちで 1 件に畳み、同一キーで内容が異なれば黙って上書きせず `InvalidArgument`
//!   で拒否する（fail-closed）。
//! - `hooks` は完全一致のものだけ畳み、それ以外は順序を保って全て残す。
//! - `additionalGids` は値の重複を除き初出順。`intelRdt` は 1 つだけ採用し、内容が異なる複数は拒否する。
//!
//! 責務境界（将来仕様。REPAIR-3）: `all` の展開やセレクタ（`vendor/class=name`）の分解、パス正規化
//! （TASK-126.3）、パスの組み立て・hooks の実行（TASK-127）は行わない。値は文字列のまま保持する。
//! エラーの `message` は固定文言で、`env` の値などの内容を含めない。

use std::collections::{BTreeMap, BTreeSet};

use crate::cdi_spec::{
    CdiSpec, CdiSpecError, CdiSpecErrorCode, ContainerEdits, DeviceNode, EnvList, Hook, IntelRdt,
    Mount,
};

/// 集計済みの edits（`#[non_exhaustive]`。フィールドは参照アクセサで読む）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AggregatedEdits {
    device_nodes: Vec<DeviceNode>,
    mounts: Vec<Mount>,
    env: EnvList,
    hooks: Vec<Hook>,
    additional_gids: Vec<u32>,
    intel_rdt: Option<IntelRdt>,
}

impl AggregatedEdits {
    /// 重複除去済みのデバイスノード（デバイス順 → トップレベル順）。
    pub fn device_nodes(&self) -> &[DeviceNode] {
        &self.device_nodes
    }

    /// 重複除去済みのマウント。
    pub fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// 重複除去済みの環境変数（値は `Debug` に出ない）。
    pub fn env(&self) -> &EnvList {
        &self.env
    }

    /// フック（完全一致のみ除去。実行順 = 並び順）。
    pub fn hooks(&self) -> &[Hook] {
        &self.hooks
    }

    /// 重複除去済みの追加 GID。
    pub fn additional_gids(&self) -> &[u32] {
        &self.additional_gids
    }

    /// 採用された Intel RDT 設定。
    pub fn intel_rdt(&self) -> Option<&IntelRdt> {
        self.intel_rdt.as_ref()
    }
}

fn err(code: CdiSpecErrorCode, message: &str) -> CdiSpecError {
    CdiSpecError::new(code, message)
}

/// 同一キーの要素を先勝ちで畳み、内容が異なれば `conflict` で拒否する。計算量は O(n log n)。
fn merge_keyed<'a, T: PartialEq + Clone + 'a>(
    items: impl Iterator<Item = &'a T>,
    key: impl Fn(&T) -> String,
    conflict: &str,
) -> Result<Vec<T>, CdiSpecError> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut out: Vec<T> = Vec::new();
    for item in items {
        let k = key(item);
        match seen.get(&k).and_then(|i| out.get(*i)) {
            Some(prev) if prev == item => {}
            Some(_) => return Err(err(CdiSpecErrorCode::InvalidArgument, conflict)),
            None => {
                seen.insert(k, out.len());
                out.push(item.clone());
            }
        }
    }
    Ok(out)
}

fn merge_device_nodes(all: &[&ContainerEdits]) -> Result<Vec<DeviceNode>, CdiSpecError> {
    merge_keyed(
        all.iter().flat_map(|e| e.device_nodes.iter()),
        |n| n.path.clone(),
        "conflicting deviceNodes entries for the same path",
    )
}

fn merge_mounts(all: &[&ContainerEdits]) -> Result<Vec<Mount>, CdiSpecError> {
    merge_keyed(
        all.iter().flat_map(|e| e.mounts.iter()),
        |m| m.container_path.clone(),
        "conflicting mounts entries for the same containerPath",
    )
}

fn merge_env(all: &[&ContainerEdits]) -> Result<EnvList, CdiSpecError> {
    let entries: Vec<String> = merge_keyed(
        all.iter().flat_map(|e| e.env.iter()),
        |s| s.split('=').next().unwrap_or_default().to_string(),
        "conflicting env entries for the same key",
    )?;
    Ok(EnvList::from_entries(entries))
}

fn merge_hooks(all: &[&ContainerEdits]) -> Vec<Hook> {
    let mut out: Vec<Hook> = Vec::new();
    for h in all.iter().flat_map(|e| e.hooks.iter()) {
        if !out.contains(h) {
            out.push(h.clone());
        }
    }
    out
}

fn merge_gids(all: &[&ContainerEdits]) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    all.iter()
        .flat_map(|e| e.additional_gids.iter().copied())
        .filter(|g| seen.insert(*g))
        .collect()
}

fn merge_intel_rdt(all: &[&ContainerEdits]) -> Result<Option<IntelRdt>, CdiSpecError> {
    let mut chosen: Option<&IntelRdt> = None;
    for r in all.iter().filter_map(|e| e.intel_rdt.as_ref()) {
        match chosen {
            Some(prev) if prev != r => {
                return Err(err(
                    CdiSpecErrorCode::InvalidArgument,
                    "conflicting intelRdt entries",
                ));
            }
            Some(_) => {}
            None => chosen = Some(r),
        }
    }
    Ok(chosen.cloned())
}

/// 指定デバイス群の `containerEdits` とトップレベル `containerEdits` を集計する（GPU-1）。
///
/// - `device_names` が空なら `InvalidArgument`、spec に無い名前は `NotFound`、spec 内に同名デバイスが
///   複数あれば曖昧なため `InvalidArgument`。要求名の重複は除いて扱う（冪等）。
/// - `all` は通常のデバイス名として扱い、自動展開しない。
///
/// 集計順序と衝突の扱いはモジュール doc を参照。パニックしない。
pub fn aggregate_container_edits(
    spec: &CdiSpec,
    device_names: &[&str],
) -> Result<AggregatedEdits, CdiSpecError> {
    if device_names.is_empty() {
        return Err(err(
            CdiSpecErrorCode::InvalidArgument,
            "no CDI device name was requested",
        ));
    }
    let mut requested: Vec<&str> = Vec::new();
    for n in device_names {
        if !requested.contains(n) {
            requested.push(n);
        }
    }
    let mut all: Vec<&ContainerEdits> = Vec::with_capacity(requested.len() + 1);
    for name in &requested {
        let mut matches = spec.devices.iter().filter(|d| d.name == *name);
        let Some(device) = matches.next() else {
            return Err(err(
                CdiSpecErrorCode::NotFound,
                "requested CDI device not found in spec",
            ));
        };
        if matches.next().is_some() {
            return Err(err(
                CdiSpecErrorCode::InvalidArgument,
                "CDI spec has duplicate device names",
            ));
        }
        all.push(&device.container_edits);
    }
    all.push(&spec.container_edits);

    Ok(AggregatedEdits {
        device_nodes: merge_device_nodes(&all)?,
        mounts: merge_mounts(&all)?,
        env: merge_env(&all)?,
        hooks: merge_hooks(&all),
        additional_gids: merge_gids(&all),
        intel_rdt: merge_intel_rdt(&all)?,
    })
}

#[cfg(test)]
mod tests {
    //! GPU-1（TASK-126.2）の集計規則を具体値で確認する。
    use super::*;
    use crate::cdi_spec::parse_cdi_spec;

    const DEV_BLOCK: &str = "    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
        - path: /dev/dri/card0
        - path: /dev/dri/renderD128
      hooks:
        - hookName: createContainer
          path: /usr/bin/nvidia-cdi-hook
          args: [nvidia-cdi-hook, create-symlinks, --link, a::b]
";

    fn poc_like() -> String {
        let mut y = String::from("cdiVersion: 0.5.0\nkind: nvidia.com/gpu\ndevices:\n");
        for n in ["\"0\"", "GPU-00000000-0000-0000-0000-000000000000", "all"] {
            y.push_str(&format!("  - name: {n}\n{DEV_BLOCK}"));
        }
        y.push_str(
            "containerEdits:
  env:
    - NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu
    - NVIDIA_VISIBLE_DEVICES=void
  deviceNodes:
    - path: /dev/nvidiactl
    - path: /dev/nvidia-uvm
    - path: /dev/nvidia-uvm-tools
    - path: /dev/nvidia-modeset
  hooks:
",
        );
        for i in 1..=5 {
            y.push_str(&format!(
                "    - {{hookName: createContainer, path: /usr/bin/nvidia-cdi-hook, args: [c{i}]}}\n"
            ));
        }
        y.push_str(
            "    - {hookName: createContainer, path: /usr/bin/nvidia-cdi-hook, args: [update-ldcache]}
  mounts:
    - {hostPath: /usr/lib/libcuda.so.1, containerPath: /usr/lib/libcuda.so.1, options: [ro, bind]}
    - {hostPath: /usr/lib/libnvidia-ml.so.1, containerPath: /usr/lib/libnvidia-ml.so.1}
    - {hostPath: /usr/bin/nvidia-smi, containerPath: /usr/bin/nvidia-smi}
",
        );
        y
    }

    fn spec(y: &str) -> CdiSpec {
        parse_cdi_spec(y).expect("fixture parses")
    }

    fn two_part(dev: &str, top: &str) -> CdiSpec {
        spec(&format!(
            "cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n  - name: a\n    containerEdits:\n      {dev}\ncontainerEdits:\n  {top}\n"
        ))
    }

    #[test]
    fn gpu1_all_device_counts_match_poc_shape() {
        let a = aggregate_container_edits(&spec(&poc_like()), &["all"]).unwrap();
        assert_eq!(a.device_nodes().len(), 7);
        assert_eq!(a.env().len(), 2);
        assert_eq!(a.hooks().len(), 7);
        assert_eq!(a.mounts().len(), 3);
    }

    #[test]
    fn gpu1_two_devices_fold_common_hook_and_apply_top_level_once() {
        let s = spec(&poc_like());
        let a = aggregate_container_edits(&s, &["0", "GPU-00000000-0000-0000-0000-000000000000"])
            .unwrap();
        assert_eq!(a.hooks().len(), 7);
        assert_eq!(a.device_nodes().len(), 7);
        assert_eq!(a.env().len(), 2);
    }

    #[test]
    fn gpu1_device_edits_precede_top_level() {
        let a = aggregate_container_edits(&spec(&poc_like()), &["all", "0"]).unwrap();
        let paths: Vec<&str> = a.device_nodes().iter().map(|n| n.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/dev/nvidia0",
                "/dev/dri/card0",
                "/dev/dri/renderD128",
                "/dev/nvidiactl",
                "/dev/nvidia-uvm",
                "/dev/nvidia-uvm-tools",
                "/dev/nvidia-modeset"
            ]
        );
        let first_hook_arg = a.hooks().first().and_then(|h| h.args.last()).cloned();
        assert_eq!(first_hook_arg.as_deref(), Some("a::b"));
    }

    #[test]
    fn gpu1_identical_duplicates_fold_and_conflicts_are_rejected() {
        let ok = two_part(
            "mounts: [{hostPath: /h, containerPath: /c}]",
            "mounts: [{hostPath: /h, containerPath: /c}]",
        );
        assert_eq!(
            aggregate_container_edits(&ok, &["a"])
                .unwrap()
                .mounts()
                .len(),
            1
        );

        let bad_mount = two_part(
            "mounts: [{hostPath: /h1, containerPath: /c}]",
            "mounts: [{hostPath: /h2, containerPath: /c}]",
        );
        let e = aggregate_container_edits(&bad_mount, &["a"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);

        let bad_node = two_part(
            "deviceNodes: [{path: /dev/x, major: 1}]",
            "deviceNodes: [{path: /dev/x, major: 2}]",
        );
        assert_eq!(
            aggregate_container_edits(&bad_node, &["a"])
                .unwrap_err()
                .code(),
            CdiSpecErrorCode::InvalidArgument
        );
    }

    #[test]
    fn gpu1_env_same_key_conflict_rejected_without_leaking_values() {
        let conflict = two_part(
            "env: [TOKEN=DUMMY_SECRET_TOKEN_12345]",
            "env: [TOKEN=DUMMY_SECRET_OTHER_67890]",
        );
        let e = aggregate_container_edits(&conflict, &["a"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
        assert!(!e.to_string().contains("DUMMY_SECRET"));

        let same = two_part(
            "env: [TOKEN=DUMMY_SECRET_TOKEN_12345]",
            "env: [TOKEN=DUMMY_SECRET_TOKEN_12345]",
        );
        let a = aggregate_container_edits(&same, &["a"]).unwrap();
        assert_eq!(a.env().len(), 1);
        assert!(!format!("{a:?}").contains("DUMMY_SECRET"));
    }

    #[test]
    fn gpu1_hooks_differing_only_in_args_are_both_kept() {
        let s = two_part(
            "hooks: [{hookName: createContainer, path: /h, args: [x]}]",
            "hooks: [{hookName: createContainer, path: /h, args: [y]}]",
        );
        assert_eq!(
            aggregate_container_edits(&s, &["a"]).unwrap().hooks().len(),
            2
        );
    }

    #[test]
    fn gpu1_gids_dedup_in_first_seen_order_and_intel_rdt_rules() {
        let s = two_part(
            "additionalGids: [5, 3]\n      intelRdt: {closID: c1}",
            "additionalGids: [3, 7]\n  intelRdt: {closID: c1}",
        );
        let a = aggregate_container_edits(&s, &["a"]).unwrap();
        assert_eq!(a.additional_gids(), [5, 3, 7]);
        assert_eq!(a.intel_rdt().and_then(|r| r.clos_id.as_deref()), Some("c1"));

        let bad = two_part("intelRdt: {closID: c1}", "intelRdt: {closID: c2}");
        assert_eq!(
            aggregate_container_edits(&bad, &["a"]).unwrap_err().code(),
            CdiSpecErrorCode::InvalidArgument
        );
    }

    #[test]
    fn gpu1_request_errors() {
        let s = spec(&poc_like());
        assert_eq!(
            aggregate_container_edits(&s, &[]).unwrap_err().code(),
            CdiSpecErrorCode::InvalidArgument
        );
        assert_eq!(
            aggregate_container_edits(&s, &["nope"]).unwrap_err().code(),
            CdiSpecErrorCode::NotFound
        );
        let dup = spec(
            "cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n  - name: a\n    containerEdits: {}\n  - name: a\n    containerEdits: {}\n",
        );
        assert_eq!(
            aggregate_container_edits(&dup, &["a"]).unwrap_err().code(),
            CdiSpecErrorCode::InvalidArgument
        );
        let once = aggregate_container_edits(&s, &["all"]).unwrap();
        let twice = aggregate_container_edits(&s, &["all", "all"]).unwrap();
        assert_eq!(once, twice);
    }
}
