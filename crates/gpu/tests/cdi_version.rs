//! `cdiVersion` の検証と v1.1.0 の `intelRdt` の結合試験（GPU-1・REPAIR-3・#2597）。
//!
//! 受ける版の集合と、使っているフィールドごとの最小の版を、公開 API だけで具体値で照合する。
//! 出典は cncf-tags/container-device-interface v1.1.1 `cb98bcf66dc68530012483bd56e33e14d815e167` の
//! `specs-go/version.go`（`cdi_spec` のモジュール doc 参照）。

use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_spec::{
    CDI_SPEC_LATEST_SUPPORTED_VERSION, CdiSpec, CdiSpecErrorCode, parse_cdi_spec,
};

const UNSUPPORTED: &str =
    "CDI spec has an unsupported cdiVersion (supported: 0.3.0 to 1.1.0; earliest supported 0.3.0)";

fn minimal(version: &str) -> String {
    format!("cdiVersion: \"{version}\"\nkind: v/c\n")
}

/// 最小の spec に `body`（トップレベル直下のキー）を足したもの。
fn with(version: &str, body: &str) -> String {
    format!("{}{body}", minimal(version))
}

fn rejected(y: &str) -> String {
    let e = parse_cdi_spec(y).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{y}");
    e.message().to_string()
}

#[test]
fn gpu1_accepts_exactly_the_known_versions() {
    assert_eq!(CDI_SPEC_LATEST_SUPPORTED_VERSION, "1.1.0");
    for v in [
        "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.8.0", "1.0.0", "1.1.0",
    ] {
        assert!(parse_cdi_spec(&minimal(v)).is_ok(), "{v}");
        assert!(parse_cdi_spec(&minimal(&format!("v{v}"))).is_ok(), "v{v}");
    }
}

#[test]
fn gpu1_rejects_unknown_versions_with_fixed_message() {
    for v in [
        "0.1.0",
        "0.2.0",
        "1.1.1",
        "1.2.0",
        "2.0.0",
        "1",
        "1.1",
        "01.1.0",
        "1.1.0-rc1",
        "1.1.0+x",
        "vv1.1.0",
        "",
    ] {
        assert_eq!(rejected(&minimal(v)), UNSUPPORTED, "{v:?}");
    }
}

/// 版 × フィールド: (YAML の追加部分, 要る最小の版, 1 つ前の版, メッセージ中の feature)。
#[test]
fn gpu1_minimum_version_per_field() {
    let cases: [(&str, &str, &str, &str); 14] = [
        (
            "containerEdits:\n  intelRdt:\n    schemata: [\"L3:0=f\"]\n",
            "1.1.0",
            "1.0.0",
            "intelRdt schemata",
        ),
        (
            "containerEdits:\n  intelRdt:\n    schemata: []\n",
            "1.1.0",
            "1.0.0",
            "intelRdt schemata",
        ),
        (
            "containerEdits:\n  intelRdt:\n    enableMonitoring: true\n",
            "1.1.0",
            "1.0.0",
            "intelRdt enableMonitoring",
        ),
        (
            "containerEdits:\n  netDevices: [{hostInterfaceName: eth1, name: n1}]\n",
            "1.1.0",
            "1.0.0",
            "netDevices",
        ),
        (
            "containerEdits:\n  intelRdt:\n    closID: c\n",
            "0.7.0",
            "0.6.0",
            "intelRdt",
        ),
        (
            "containerEdits:\n  additionalGids: [5]\n",
            "0.7.0",
            "0.6.0",
            "additionalGids",
        ),
        (
            "devices:\n  - name: a\n    containerEdits:\n      additionalGids: [5]\n",
            "0.7.0",
            "0.6.0",
            "additionalGids",
        ),
        ("annotations:\n  k: v\n", "0.6.0", "0.5.0", "annotations"),
        (
            "devices:\n  - name: a\n    annotations:\n      k: v\n    containerEdits: {}\n",
            "0.6.0",
            "0.5.0",
            "annotations",
        ),
        (
            "devices:\n  - name: \"0\"\n    containerEdits: {}\n",
            "0.5.0",
            "0.4.0",
            "device name starting with a digit",
        ),
        (
            "containerEdits:\n  deviceNodes:\n    - path: /dev/a\n      hostPath: /dev/b\n",
            "0.5.0",
            "0.4.0",
            "deviceNodes hostPath",
        ),
        (
            "containerEdits:\n  mounts:\n    - hostPath: /a\n      containerPath: /b\n      type: bind\n",
            "0.4.0",
            "0.3.0",
            "mounts type",
        ),
        (
            "devices:\n  - name: a\n    containerEdits:\n      mounts:\n        - hostPath: /a\n          containerPath: /b\n          type: bind\n",
            "0.4.0",
            "0.3.0",
            "mounts type",
        ),
        // 0.3.0 の既定: どれにも当てはまらなければ最も古い版で受かる。
        (
            "containerEdits:\n  env: [A=1]\n",
            "0.3.0",
            "0.3.0",
            "default",
        ),
    ];
    // netDevices は版の検査を通ったあと適用未実装の `Unimplemented` になる（版の検査の外）。
    let passes_version = |y: &str| match parse_cdi_spec(y) {
        Ok(_) => true,
        Err(e) => e.code() == CdiSpecErrorCode::Unimplemented,
    };
    for (body, need, below, feature) in cases {
        assert!(passes_version(&with(need, body)), "{need} {body}");
        assert!(passes_version(&with("1.1.0", body)), "{body}");
        if need != "0.3.0" {
            assert_eq!(
                rejected(&with(below, body)),
                format!("CDI {feature} requires cdiVersion {need} or later"),
                "{below} {body}"
            );
        }
    }
}

/// kind の class に `.` を含むと 0.6.0 が要る（vendor 側の `.` は関係しない）。
#[test]
fn gpu1_kind_class_with_dot_requires_0_6_0() {
    let y = |v: &str, kind: &str| format!("cdiVersion: \"{v}\"\nkind: {kind}\n");
    assert!(parse_cdi_spec(&y("0.5.0", "nvidia.com/gpu")).is_ok());
    assert!(parse_cdi_spec(&y("0.6.0", "v/c.d")).is_ok());
    assert_eq!(
        rejected(&y("0.5.0", "v/c.d")),
        "CDI kind class containing '.' requires cdiVersion 0.6.0 or later"
    );
}

/// 上流のゼロ値と同じ扱い: 空文字・false は「無い」と同じで、古い版でも受かる。
#[test]
fn gpu1_zero_values_do_not_raise_the_minimum() {
    let ok = |v: &str, body: &str| {
        assert!(parse_cdi_spec(&with(v, body)).is_ok(), "{v} {body}");
    };
    ok(
        "0.3.0",
        "containerEdits:\n  deviceNodes:\n    - path: /dev/a\n      hostPath: \"\"\n",
    );
    ok(
        "0.3.0",
        "containerEdits:\n  mounts:\n    - hostPath: /a\n      containerPath: /b\n      type: \"\"\n",
    );
    ok(
        "0.7.0",
        "containerEdits:\n  intelRdt:\n    enableMonitoring: false\n",
    );
    ok(
        "0.3.0",
        "containerEdits:\n  netDevices: []\n  additionalGids: []\n",
    );
}

/// 複数の要件に当てはまるときは新しい版の要件のメッセージになる。
#[test]
fn gpu1_message_names_the_newest_requirement() {
    let body = "annotations:\n  k: v\ncontainerEdits:\n  intelRdt:\n    closID: c\n";
    assert_eq!(
        rejected(&with("0.5.0", body)),
        "CDI intelRdt requires cdiVersion 0.7.0 or later"
    );
    assert!(parse_cdi_spec(&with("0.7.0", body)).is_ok());
}

#[test]
fn gpu1_intel_rdt_v1_1_0_fields() {
    let y = with(
        "1.1.0",
        "containerEdits:\n  intelRdt:\n    closID: c1\n    l3CacheSchema: L3\n    memBwSchema: MB\n    schemata: [\"L3:0=f\", \"MB:0=50\"]\n    enableMonitoring: true\n",
    );
    let r = parse_cdi_spec(&y)
        .unwrap()
        .container_edits
        .intel_rdt
        .unwrap();
    assert_eq!(r.clos_id.as_deref(), Some("c1"));
    assert_eq!(r.l3_cache_schema.as_deref(), Some("L3"));
    assert_eq!(r.mem_bw_schema.as_deref(), Some("MB"));
    assert_eq!(
        r.schemata,
        Some(vec!["L3:0=f".to_string(), "MB:0=50".to_string()])
    );
    assert_eq!(r.enable_monitoring, Some(true));
}

/// v0.7.0 の enableCMT / enableMBM は版に関係なく未知フィールド（REPAIR-3。上流 v1.1.x と同じ）。
#[test]
fn gpu1_removed_intel_rdt_fields_are_unknown_in_every_version() {
    for v in ["0.7.0", "1.0.0", "1.1.0"] {
        for key in ["enableCMT", "enableMBM"] {
            let y = with(
                v,
                &format!("containerEdits:\n  intelRdt:\n    {key}: true\n"),
            );
            let e = parse_cdi_spec(&y).unwrap_err();
            assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{v} {key}");
            assert_eq!(e.message(), "CDI spec has an unknown field", "{v} {key}");
            assert!(e.line().is_some(), "{v} {key}");
        }
    }
}

/// parse を通らずに作られた CdiSpec も集計が版を検査する。
#[test]
fn gpu1_aggregate_validates_version_of_hand_built_specs() {
    let good = parse_cdi_spec(&with(
        "0.5.0",
        "devices:\n  - name: a\n    containerEdits: {}\n",
    ))
    .unwrap();
    assert!(aggregate_container_edits(&good, &["a"]).is_ok());
    for v in ["9.9.9", "1.2.0", ""] {
        let mut bad: CdiSpec = good.clone();
        bad.cdi_version = v.to_string();
        let e = aggregate_container_edits(&bad, &["a"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{v:?}");
        assert_eq!(e.message(), UNSUPPORTED, "{v:?}");
        // 存在しない名前でも版の検査が先。
        let e = aggregate_container_edits(&bad, &["zzz"]).unwrap_err();
        assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument, "{v:?}");
    }
}
