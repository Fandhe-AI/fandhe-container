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
//!
//! 資源上限（`AGENTS.md`「リソース上限」・`coding-rust.md`）: 要求デバイス名は spec とは別経路の外部入力
//! （CLI 引数・CRI のデバイス指定など）で、[`crate::cdi_spec::parse_cdi_spec`] の入力上限が及ばない。
//! そのため件数（[`CDI_EDITS_MAX_REQUESTED_DEVICES`]）と各名前の長さ（[`CDI_EDITS_MAX_DEVICE_NAME_BYTES`]）を、
//! 確保・重複除去・存在確認のどれよりも前に検証し、超過は `ResourceExhausted` で拒否する。
//! 検証後の計算量は、要求件数 R・spec のデバイス数 D・集計対象の要素数 N に対して
//! O((R + D) log R + N log N) 回の比較で、二乗時間の処理を持たない。各デバイスの edits は高々 1 回しか
//! 連結しない（要求名の重複は畳む）ため、出力の要素数は呼び出し側がすでに保持している spec の要素数を
//! 超えない。

use std::collections::{BTreeMap, BTreeSet};

use crate::cdi_spec::{
    CdiSpec, CdiSpecError, CdiSpecErrorCode, ContainerEdits, DeviceNode, EnvList, Hook, IntelRdt,
    Mount,
};

/// 1 回の集計で要求できるデバイス名の最大件数（重複を除く前の件数で数える）。
///
/// 根拠: 実際の nvidia.yaml のデバイスは GPU ごとの index 名・UUID 名と `all` で、GPU 16 基を MIG で
/// 7 分割し index 名・UUID 名の両方を列挙しても 16 * 2 + 16 * 7 * 2 + 1 = 257 件に収まる。その約 4 倍を
/// 上限とする。spec に載せられるデバイス数は `parse_cdi_spec` の入力上限
/// （[`crate::cdi_spec::CDI_SPEC_MAX_INPUT_BYTES`] とノード数上限）から数万件が上界で、本上限はそれより
/// 小さい（spec に載せられる数を超える要求を許す値ではない）。
pub const CDI_EDITS_MAX_REQUESTED_DEVICES: usize = 1024;

/// 要求デバイス名 1 件の最大バイト数（UTF-8 のバイト長）。
///
/// 根拠: 実際の名前は index（`0`）・UUID 名（`GPU-` + 36 文字 = 40 バイト）・MIG の UUID 名・`all` で
/// 数十バイトに収まる。名前は借用のまま扱い複製しないが、重複除去と spec との照合の比較コストが名前の
/// 長さに比例するため、[`CDI_EDITS_MAX_REQUESTED_DEVICES`] と合わせて比較の総量を有界にする。
/// これより長い名前のデバイスが spec にあっても本関数からは要求できない（`ResourceExhausted`）。
pub const CDI_EDITS_MAX_DEVICE_NAME_BYTES: usize = 256;

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
///
/// キーは要素から借用し、複製しない（追加の確保は索引と出力だけで、どちらも入力の要素数以下）。
fn merge_keyed<'a, T: PartialEq + Clone + 'a>(
    items: impl Iterator<Item = &'a T>,
    key: impl Fn(&'a T) -> &'a str,
    conflict: &str,
) -> Result<Vec<T>, CdiSpecError> {
    let mut seen: BTreeMap<&'a str, usize> = BTreeMap::new();
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
        |n| n.path.as_str(),
        "conflicting deviceNodes entries for the same path",
    )
}

fn merge_mounts(all: &[&ContainerEdits]) -> Result<Vec<Mount>, CdiSpecError> {
    merge_keyed(
        all.iter().flat_map(|e| e.mounts.iter()),
        |m| m.container_path.as_str(),
        "conflicting mounts entries for the same containerPath",
    )
}

fn merge_env(all: &[&ContainerEdits]) -> Result<EnvList, CdiSpecError> {
    let entries: Vec<String> = merge_keyed(
        all.iter().flat_map(|e| e.env.iter()),
        |s| s.split('=').next().unwrap_or_default(),
        "conflicting env entries for the same key",
    )?;
    Ok(EnvList::from_entries(entries))
}

/// フックの同一性の比較キー（全フィールドの借用）。`Hook` の `PartialEq` と同じ同値関係を与える。
type HookIdentity<'a> = (&'a str, &'a str, &'a [String], &'a [String], Option<i64>);

/// [`HookIdentity`] を組み立てる。
///
/// 全フィールドを分解束縛しているのは、`Hook` にフィールドが増えたときにここがコンパイルエラーになり、
/// 増えたフィールドを無視して別物のフックを同一と畳む退行を防ぐため。
fn hook_identity(hook: &Hook) -> HookIdentity<'_> {
    let Hook {
        hook_name,
        path,
        args,
        env,
        timeout,
    } = hook;
    (hook_name, path, args, env.iter().as_slice(), *timeout)
}

/// 完全一致のフックだけを先勝ちで畳み、順序を保つ。計算量は O(n log n)（線形探索の二乗時間にしない）。
fn merge_hooks(all: &[&ContainerEdits]) -> Vec<Hook> {
    let mut seen: BTreeSet<HookIdentity<'_>> = BTreeSet::new();
    all.iter()
        .flat_map(|e| e.hooks.iter())
        .filter(|h| seen.insert(hook_identity(h)))
        .cloned()
        .collect()
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

/// 要求名 1 件を spec のデバイスと突き合わせた結果（[`aggregate_container_edits`] の内部状態）。
#[derive(Clone, Copy)]
enum DeviceLookup<'a> {
    /// spec に該当するデバイスが無い。
    Missing,
    /// ちょうど 1 件該当した。
    Unique(&'a ContainerEdits),
    /// 同名のデバイスが複数あり、どれを指すか決められない。
    Ambiguous,
}

/// 指定デバイス群の `containerEdits` とトップレベル `containerEdits` を集計する（GPU-1）。
///
/// - `device_names` が空なら `InvalidArgument`。件数が [`CDI_EDITS_MAX_REQUESTED_DEVICES`] を超える、
///   またはいずれかの名前が [`CDI_EDITS_MAX_DEVICE_NAME_BYTES`] を超えるなら `ResourceExhausted`
///   （重複除去・存在確認より前に検証し、何も確保せずに拒否する。存在しない名前でも同じ）。
/// - spec に無い名前は `NotFound`、要求された名前のデバイスが spec 内に複数あれば曖昧なため
///   `InvalidArgument`（要求順で最初に該当した名前のエラーを返す）。要求名の重複は除いて扱う（冪等）。
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
    // 上限の検証は確保・重複除去・存在確認より前に行う（ここまで何も確保しない）。
    if device_names.len() > CDI_EDITS_MAX_REQUESTED_DEVICES {
        return Err(err(
            CdiSpecErrorCode::ResourceExhausted,
            "too many CDI device names were requested",
        ));
    }
    if device_names
        .iter()
        .any(|n| n.len() > CDI_EDITS_MAX_DEVICE_NAME_BYTES)
    {
        return Err(err(
            CdiSpecErrorCode::ResourceExhausted,
            "requested CDI device name is too long",
        ));
    }

    // 要求名 → 要求順の位置（重複は初出の位置へ畳む）。件数は上限検証済みで、O(R log R)。
    let mut slot_of: BTreeMap<&str, usize> = BTreeMap::new();
    for name in device_names {
        let next = slot_of.len();
        slot_of.entry(name).or_insert(next);
    }
    // spec のデバイスを 1 回だけ走査して要求名と突き合わせる（O(D log R)）。要求されていない名前の
    // 重複は見ない（従来どおり、要求された名前が曖昧なときだけ拒否する）。
    let mut lookups: Vec<DeviceLookup<'_>> = vec![DeviceLookup::Missing; slot_of.len()];
    for device in &spec.devices {
        let Some(lookup) = slot_of
            .get(device.name.as_str())
            .and_then(|slot| lookups.get_mut(*slot))
        else {
            continue;
        };
        *lookup = match lookup {
            DeviceLookup::Missing => DeviceLookup::Unique(&device.container_edits),
            DeviceLookup::Unique(_) | DeviceLookup::Ambiguous => DeviceLookup::Ambiguous,
        };
    }
    let mut all: Vec<&ContainerEdits> = Vec::with_capacity(lookups.len().saturating_add(1));
    for lookup in &lookups {
        match lookup {
            DeviceLookup::Unique(edits) => all.push(edits),
            DeviceLookup::Missing => {
                return Err(err(
                    CdiSpecErrorCode::NotFound,
                    "requested CDI device not found in spec",
                ));
            }
            DeviceLookup::Ambiguous => {
                return Err(err(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI spec has duplicate device names",
                ));
            }
        }
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

    /// `d0`..`d{count-1}` の `count` 件のデバイス（各 1 ノード `/dev/n{i}`）を持つ spec。
    fn many_devices(count: usize) -> CdiSpec {
        let mut y = String::from("cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n");
        for i in 0..count {
            y.push_str(&format!(
                "  - name: d{i}\n    containerEdits:\n      deviceNodes: [{{path: /dev/n{i}}}]\n"
            ));
        }
        spec(&y)
    }

    /// GPU-1・「リソース上限」: 上限値そのものを具体値で固定する（黙って緩めた変更を検出する）。
    #[test]
    fn gpu1_request_limits_have_documented_values() {
        assert_eq!(CDI_EDITS_MAX_REQUESTED_DEVICES, 1024);
        assert_eq!(CDI_EDITS_MAX_DEVICE_NAME_BYTES, 256);
    }

    /// GPU-1・「リソース上限」: 上限ちょうどの件数（すべて異なる実在名）は受理し、要求順を保つ。
    #[test]
    fn gpu1_request_count_at_limit_is_accepted() {
        let s = many_devices(CDI_EDITS_MAX_REQUESTED_DEVICES);
        let names: Vec<String> = (0..CDI_EDITS_MAX_REQUESTED_DEVICES)
            .rev()
            .map(|i| format!("d{i}"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(refs.len(), 1024);
        let a = aggregate_container_edits(&s, &refs).unwrap();
        assert_eq!(a.device_nodes().len(), 1024);
        assert_eq!(
            a.device_nodes().first().map(|n| n.path.as_str()),
            Some("/dev/n1023")
        );
        assert_eq!(
            a.device_nodes().last().map(|n| n.path.as_str()),
            Some("/dev/n0")
        );
    }

    /// GPU-1・「リソース上限」: 上限 +1 件は、名前が実在しても・重複でも・不存在でも、存在確認より前に
    /// `ResourceExhausted` で拒否する（不存在名の大量指定で `NotFound` まで処理を進めない）。
    #[test]
    fn gpu1_request_count_over_limit_is_rejected_before_lookup() {
        const MESSAGE: &str = "too many CDI device names were requested";
        let s = many_devices(CDI_EDITS_MAX_REQUESTED_DEVICES + 1);

        let existing: Vec<String> = (0..=CDI_EDITS_MAX_REQUESTED_DEVICES)
            .map(|i| format!("d{i}"))
            .collect();
        let existing: Vec<&str> = existing.iter().map(String::as_str).collect();
        assert_eq!(existing.len(), 1025);
        let e = aggregate_container_edits(&s, &existing).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
        assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
        assert_eq!(e.message(), MESSAGE);
        assert_eq!(e.to_string(), format!("RESOURCE_EXHAUSTED: {MESSAGE}"));

        let small = spec(&poc_like());
        let missing: Vec<String> = (0..=CDI_EDITS_MAX_REQUESTED_DEVICES)
            .map(|i| format!("missing-{i}"))
            .collect();
        let missing: Vec<&str> = missing.iter().map(String::as_str).collect();
        let e = aggregate_container_edits(&small, &missing).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
        assert_eq!(e.message(), MESSAGE);
        // 上限ちょうどの不存在名は上限検証を通り、存在確認で NotFound になる。
        let e =
            aggregate_container_edits(&small, missing.get(..1024).unwrap_or_default()).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::NotFound);
        assert_eq!(e.message(), "requested CDI device not found in spec");

        // 件数は重複を除く前の数で数える: 同じ実在名でも 1025 件は拒否、1024 件は 1 件に畳んで受理。
        let repeated = vec!["all"; CDI_EDITS_MAX_REQUESTED_DEVICES + 1];
        let e = aggregate_container_edits(&small, &repeated).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
        assert_eq!(e.message(), MESSAGE);
        let at_limit = aggregate_container_edits(&small, repeated.get(..1024).unwrap_or_default());
        assert_eq!(at_limit, aggregate_container_edits(&small, &["all"]));
        assert_eq!(at_limit.map(|a| a.device_nodes().len()), Ok(7));
    }

    /// GPU-1・「リソース上限」: 名前の長さは上限ちょうど（256 バイト）を受理し、+1 バイトを拒否する。
    #[test]
    fn gpu1_request_name_length_limit() {
        let at_limit = "n".repeat(CDI_EDITS_MAX_DEVICE_NAME_BYTES);
        assert_eq!(at_limit.len(), 256);
        let s = spec(&format!(
            "cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n  - name: {at_limit}\n    containerEdits:\n      deviceNodes: [{{path: /dev/long}}]\n  - name: {at_limit}n\n    containerEdits: {{}}\n"
        ));
        let a = aggregate_container_edits(&s, &[at_limit.as_str()]).unwrap();
        assert_eq!(
            a.device_nodes().first().map(|n| n.path.as_str()),
            Some("/dev/long")
        );

        // spec に実在する名前でも、上限を 1 バイト超えれば照合せずに拒否する。
        let over = format!("{at_limit}n");
        assert_eq!(over.len(), 257);
        let e = aggregate_container_edits(&s, &[at_limit.as_str(), over.as_str()]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "requested CDI device name is too long");
        assert_eq!(
            e.to_string(),
            "RESOURCE_EXHAUSTED: requested CDI device name is too long"
        );

        // 長さはバイト数で数える: 3 バイト文字 86 個は 258 バイトで拒否、85 個（255 バイト）は不存在で NotFound。
        let wide_over = "\u{3042}".repeat(86);
        assert_eq!(wide_over.len(), 258);
        assert_eq!(
            aggregate_container_edits(&s, &[wide_over.as_str()])
                .unwrap_err()
                .code(),
            CdiSpecErrorCode::ResourceExhausted
        );
        let wide_ok = "\u{3042}".repeat(85);
        assert_eq!(
            aggregate_container_edits(&s, &[wide_ok.as_str()])
                .unwrap_err()
                .code(),
            CdiSpecErrorCode::NotFound
        );
    }

    /// GPU-1: 要求順で最初に該当した名前のエラーを返す（不存在が先なら NotFound、曖昧が先なら
    /// InvalidArgument）。要求していない名前が spec 内で重複していても拒否しない。
    #[test]
    fn gpu1_lookup_error_follows_request_order_and_ignores_unrequested_duplicates() {
        let s = spec(
            "cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n  - name: a\n    containerEdits: {}\n  - name: a\n    containerEdits: {}\n  - name: b\n    containerEdits:\n      deviceNodes: [{path: /dev/b}]\n",
        );
        let e = aggregate_container_edits(&s, &["nope", "a"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::NotFound);
        let e = aggregate_container_edits(&s, &["a", "nope"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
        assert_eq!(e.message(), "CDI spec has duplicate device names");
        let a = aggregate_container_edits(&s, &["b"]).unwrap();
        assert_eq!(a.device_nodes().len(), 1);
    }

    /// GPU-1: フックの重複除去は全フィールドの完全一致だけを畳み、初出順を保つ（`env`・`timeout` だけが
    /// 違うフックは別物として残す）。
    #[test]
    fn gpu1_hooks_fold_only_exact_duplicates_in_first_seen_order() {
        let s = two_part(
            "hooks: [{hookName: createContainer, path: /h, args: [x]}, {hookName: createContainer, path: /h, args: [x], timeout: 5}, {hookName: createContainer, path: /h, args: [x], env: [K=1]}]",
            "hooks: [{hookName: createContainer, path: /h, args: [x], env: [K=2]}, {hookName: createContainer, path: /h, args: [x], timeout: 5}, {hookName: poststop, path: /h, args: [x]}, {hookName: createContainer, path: /h, args: [x]}]",
        );
        let a = aggregate_container_edits(&s, &["a"]).unwrap();
        let seen: Vec<(&str, Option<i64>, Vec<&str>)> = a
            .hooks()
            .iter()
            .map(|h| {
                (
                    h.hook_name.as_str(),
                    h.timeout,
                    h.env.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("createContainer", None, vec![]),
                ("createContainer", Some(5), vec![]),
                ("createContainer", None, vec!["K=1"]),
                ("createContainer", None, vec!["K=2"]),
                ("poststop", None, vec![]),
            ]
        );
    }

    /// GPU-1: 互いに異なる 5000 件のフックをデバイス側とトップレベル側の両方に置いても、完全一致だけを
    /// 畳んで初出順を保つ（集合による重複除去の件数・順序の確認。所要時間は照合しない）。
    #[test]
    fn gpu1_many_distinct_hooks_keep_order() {
        const HOOKS: usize = 5000;
        let mut y = String::from(
            "cdiVersion: '0.5.0'\nkind: v/c\ndevices:\n  - name: a\n    containerEdits:\n      hooks:\n",
        );
        for i in 0..HOOKS {
            y.push_str(&format!(
                "        - {{hookName: createContainer, path: /h, args: [a{i}]}}\n"
            ));
        }
        y.push_str("containerEdits:\n  hooks:\n");
        for i in 0..HOOKS {
            y.push_str(&format!(
                "    - {{hookName: createContainer, path: /h, args: [a{i}]}}\n"
            ));
        }
        let a = aggregate_container_edits(&spec(&y), &["a"]).unwrap();
        assert_eq!(a.hooks().len(), 5000);
        let arg = |i: usize| {
            a.hooks()
                .get(i)
                .and_then(|h| h.args.first())
                .map(String::as_str)
        };
        assert_eq!(arg(0), Some("a0"));
        assert_eq!(arg(4999), Some("a4999"));
    }
}
