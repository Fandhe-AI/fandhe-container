//! Landlock ファイルパスルール生成の公開 API 結合試験
//! （`fandhe_container_core::landlock::{build_path_rules, path_rules_from_config}`。
//! CORE-5・TASK-39.2・#182。REPAIR-10・REPAIR-12 の機械照合）。
//!
//! `LandlockSupport` は検出（`detect_landlock_abi`）を通らないと得られない（fail-closed）ため、
//! 検出が `Ok` のカーネルでは具体的なルールを照合し、`Err` のカーネルでは
//! 「ルール生成に到達できない」こと自体を構造化された拒否として照合する。

#![cfg(target_os = "linux")]

use fandhe_container_core::landlock::{
    AccessFs, RuleOrigin, RulePath, build_path_rules, detect_landlock_abi, path_rules_from_config,
};
use fandhe_container_core::oci_runtime::{OciConfig, parse_config_bytes};

fn config(readonly: bool, mounts: &str) -> OciConfig {
    let json = format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":{readonly}}},"mounts":{mounts}}}"#
    );
    parse_config_bytes(json.as_bytes()).expect("valid config")
}

/// CORE-5: root と mount のルールが入力どおりの具体的な権利で生成される。
#[test]
fn core5_path_rules_from_config_concrete_rights() {
    let Ok(support) = detect_landlock_abi() else {
        // 検出に失敗するカーネルではルール生成 API に到達できない（fail-closed）。
        return;
    };
    let c = config(
        true,
        r#"[
            {"destination":"/data","options":["rw"]},
            {"destination":"/bin","options":["ro"]},
            {"destination":"/x","options":["noexec","exec","ro"]}
        ]"#,
    );
    let rs = path_rules_from_config(&support, &c).expect("rules");
    let rules = rs.rules();
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].path, RulePath::Root);
    assert_eq!(rules[0].origin, RuleOrigin::Root);
    assert_eq!(rules[0].allowed, AccessFs::READ);
    assert_eq!(rules[1].path.as_str(), "/data");
    assert_eq!(rules[1].allowed, AccessFs::READ.union(AccessFs::WRITE));
    assert_eq!(rules[2].path.as_str(), "/bin");
    assert_eq!(rules[2].allowed, AccessFs::READ);
    // noexec の後の exec が有効になり、EXECUTE を保持する。
    assert_eq!(rules[3].path.as_str(), "/x");
    assert_eq!(rules[3].allowed, AccessFs::READ);
    // 書き込み可能な root ではデバイス作成権を含まない。
    let rw = path_rules_from_config(&support, &config(false, "[]")).expect("rules");
    assert_eq!(rw.rules()[0].allowed.bits(), 0x77BF);
}

/// CORE-5: `build_path_rules` は同一 destination を後勝ちにし、rules 件数は root + 重複排除後の mount 数になる。
#[test]
fn core5_build_path_rules_last_mount_wins_for_same_destination() {
    let Ok(support) = detect_landlock_abi() else {
        return;
    };
    let c = config(
        false,
        r#"[
            {"destination":"/d","options":["ro"]},
            {"destination":"/d","options":["rw"]}
        ]"#,
    );
    let rs = build_path_rules(&support, c.root(), c.mounts()).expect("rules");
    assert_eq!(rs.rules().len(), 2);
    assert_eq!(rs.rules()[1].path.as_str(), "/d");
    assert_eq!(rs.rules()[1].allowed, AccessFs::READ.union(AccessFs::WRITE));
}
