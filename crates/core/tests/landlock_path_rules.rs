//! Landlock ファイルパスルール生成の公開 API 結合試験
//! （`fandhe_container_core::landlock::{build_path_rules, path_rules_from_config}`。
//! CORE-5・TASK-39.2・#182。REPAIR-10・REPAIR-12 の機械照合）。
//!
//! `LandlockSupport` は検出（`detect_landlock_abi`）を通らないと得られない（fail-closed）。
//! 既定のテスト集合では、検出が `Ok` のカーネルなら具体的なルールを照合し、`Err` のカーネルなら
//! ルール生成に到達できないこと自体を構造化された拒否（コード・理由・文字列表現）として照合する。
//! どちらの分岐も何かを照合し、検証せずに成功する分岐は持たない。
//! ABI 6 以上を要求してルールを必ず照合する実機前提テストは `-- --ignored` 指定時のみ実行する
//! （ci.md「実機前提テスト」。`landlock_detect.rs` の `core5_detect_succeeds_on_abi6_host` と同じ条件）。

#![cfg(target_os = "linux")]

use fandhe_container_core::dev_mounts::{ImplicitDevMount, ImplicitDevMounts};
use fandhe_container_core::landlock::{
    AccessFs, LandlockError, LandlockRuleErrorKind, LandlockSupport, RuleOrigin, RulePath,
    build_path_rules_with_dev, detect_landlock_abi, path_rules_from_config,
};
use fandhe_container_core::oci_runtime::{OciConfig, parse_config_bytes};
use fandhe_container_core::traits::ErrorCode;

fn config(readonly: bool, mounts: &str) -> OciConfig {
    let json = format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":{readonly}}},"mounts":{mounts}}}"#
    );
    parse_config_bytes(json.as_bytes()).expect("valid config")
}

/// 読み書き（実行を含む）の権利。書き込み可能な root・`rw` mount の既定値。
fn rw() -> AccessFs {
    AccessFs::READ.union(AccessFs::WRITE)
}

/// ルール列を（パス・由来・権利ビット）の具体値に写す。
fn summary(rules: &[fandhe_container_core::landlock::PathRule]) -> Vec<(String, RuleOrigin, u64)> {
    rules
        .iter()
        .map(|r| (r.path.as_str().to_string(), r.origin, r.allowed.bits()))
        .collect()
}

/// 検出失敗は ABI 不足等の前提条件違反として構造化された拒否になる（fail-closed）。
fn assert_structured_rejection(e: &LandlockError) {
    assert!(
        matches!(
            e.code,
            ErrorCode::FailedPrecondition | ErrorCode::Internal | ErrorCode::Unimplemented
        ),
        "unexpected code {:?}",
        e.code
    );
    assert!(!e.reason.as_str().is_empty());
    assert!(!e.message.is_empty());
    let text = e.to_string();
    assert!(
        text.starts_with(&format!("{}: ", e.code.as_str())),
        "{text}"
    );
    assert!(
        text.ends_with(&format!("({})", e.reason.as_str())),
        "{text}"
    );
}

/// CORE-5: `path_rules_from_config` が root と mount のルールを入力どおりの具体的な権利で生成する。
fn check_path_rules_from_config(support: &LandlockSupport) {
    let c = config(
        true,
        r#"[
            {"destination":"/data","options":["rw"]},
            {"destination":"/bin","options":["ro"]},
            {"destination":"/x","options":["exec","noexec"]},
            {"destination":"/y","options":["noexec","exec","ro"]},
            {"destination":"/dev/a","options":["nodev","dev"]},
            {"destination":"/dev/b","options":["dev","nodev"]}
        ]"#,
    );
    let rs = path_rules_from_config(support, &c).expect("rules");
    assert_eq!(rs.handled_access_fs(), AccessFs::ALL);
    let rules = rs.rules();
    assert_eq!(rules.first().map(|r| &r.path), Some(&RulePath::Root));
    assert_eq!(
        summary(rules),
        vec![
            ("/".to_string(), RuleOrigin::Root, 0x000D),
            // 暗黙の固定集合（#1657）。実マウントの属性から導いた権利が root の次に入る。
            (
                "/dev".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::Dev
                },
                0xF7BF
            ),
            (
                "/dev/pts".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::DevPts
                },
                0xF7BE
            ),
            (
                "/dev/shm".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::DevShm
                },
                0x77BE
            ),
            ("/data".to_string(), RuleOrigin::Mount { index: 0 }, 0x77BF),
            ("/bin".to_string(), RuleOrigin::Mount { index: 1 }, 0x000D),
            // 後の noexec が勝ち、EXECUTE だけを除く。
            ("/x".to_string(), RuleOrigin::Mount { index: 2 }, 0x77BE),
            // noexec の後の exec が勝ち、ro で書き込みを除く。
            ("/y".to_string(), RuleOrigin::Mount { index: 3 }, 0x000D),
            // nodev の後の dev が勝ち、/dev 配下で IOCTL_DEV を許可する。
            ("/dev/a".to_string(), RuleOrigin::Mount { index: 4 }, 0xF7BF),
            ("/dev/b".to_string(), RuleOrigin::Mount { index: 5 }, 0x77BF),
        ]
    );
    assert_eq!(rw().bits(), 0x77BF);
    // 書き込み可能な root ではデバイス作成権（MAKE_CHAR / MAKE_BLOCK）と IOCTL_DEV を含まない。
    let writable = path_rules_from_config(support, &config(false, "[]")).expect("rules");
    assert_eq!(
        summary(writable.rules()),
        vec![
            ("/".to_string(), RuleOrigin::Root, 0x77BF),
            (
                "/dev".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::Dev
                },
                0xF7BF
            ),
            (
                "/dev/pts".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::DevPts
                },
                0xF7BE
            ),
            (
                "/dev/shm".to_string(),
                RuleOrigin::Implicit {
                    mount: ImplicitDevMount::DevShm
                },
                0x77BE
            ),
        ]
    );
}

/// CORE-5: `build_path_rules` は同一 destination と、後の親マウントに隠れた子マウントのルールを除き、
/// 実行権だけが祖先で広がる箇所は shadowed に記録する。
fn check_build_path_rules_hidden_mounts(support: &LandlockSupport) {
    let c = config(
        true,
        r#"[
            {"destination":"/d","options":["ro"]},
            {"destination":"/x/y","options":["rw"]},
            {"destination":"/d","options":["rw"]},
            {"destination":"/x","options":["rw"]},
            {"destination":"/x/e","options":["noexec"]}
        ]"#,
    );
    // 暗黙の `/dev` 系（#1657）は含めず、`mounts[]` の除外規則だけを照合する。
    let rs = build_path_rules_with_dev(support, c.root(), c.mounts(), ImplicitDevMounts::None)
        .expect("rules");
    assert_eq!(
        summary(rs.rules()),
        vec![
            ("/".to_string(), RuleOrigin::Root, 0x000D),
            ("/d".to_string(), RuleOrigin::Mount { index: 2 }, 0x77BF),
            ("/x".to_string(), RuleOrigin::Mount { index: 3 }, 0x77BF),
            ("/x/e".to_string(), RuleOrigin::Mount { index: 4 }, 0x77BE),
        ]
    );
    // 実行権は VFS の noexec が保護するため、拒否せず shadowed に記録する。
    let shadowed: Vec<(&str, u64, u64)> = rs
        .shadowed()
        .iter()
        .map(|s| (s.path.as_str(), s.intended.bits(), s.effective.bits()))
        .collect();
    assert_eq!(shadowed, vec![("/x/e", 0x77BE, 0x77BF)]);
}

/// CORE-5: 書き込み制限が祖先ルールで無効になる構成は構造化エラーで拒否する（fail-closed）。
fn check_write_restriction_shadowed_is_rejected(support: &LandlockSupport) {
    let c = config(
        false,
        r#"[{"destination":"/data"},{"destination":"/proc","type":"proc"}]"#,
    );
    let e = path_rules_from_config(support, &c).expect_err("rejected");
    assert_eq!(
        e.kind,
        LandlockRuleErrorKind::WriteRestrictionShadowed {
            index: 1,
            granted: AccessFs::WRITE,
        }
    );
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(
        e.to_string(),
        "INVALID_ARGUMENT: mounts[1] denies write access 0x77b2 that an ancestor Landlock rule \
         grants; use a read-only root or a writable parent mount"
    );
}

/// CORE-5: 検出が `Ok` なら `path_rules_from_config` の生成結果を、`Err` なら構造化された拒否を照合する。
#[test]
fn core5_path_rules_from_config_or_structured_rejection() {
    match detect_landlock_abi() {
        Ok(support) => check_path_rules_from_config(&support),
        Err(e) => assert_structured_rejection(&e),
    }
}

/// CORE-5: 検出が `Ok` なら `build_path_rules` の隠れたマウントの除外を、`Err` なら構造化された拒否を照合する。
#[test]
fn core5_build_path_rules_hidden_mounts_or_structured_rejection() {
    match detect_landlock_abi() {
        Ok(support) => check_build_path_rules_hidden_mounts(&support),
        Err(e) => assert_structured_rejection(&e),
    }
}

/// CORE-5: 検出が `Ok` なら書き込み制限の無効化の拒否を、`Err` なら構造化された拒否を照合する。
#[test]
fn core5_write_restriction_shadowed_rejected_or_structured_rejection() {
    match detect_landlock_abi() {
        Ok(support) => check_write_restriction_shadowed_is_rejected(&support),
        Err(e) => assert_structured_rejection(&e),
    }
}

/// CORE-5: 実機（Linux 6.12+・ABI 6+）では検出を通過し、公開 API のルール生成を必ず照合する。
#[test]
#[ignore = "requires Landlock ABI >= 6 (Linux 6.12+). CORE-5"]
fn core5_path_rules_on_abi6_host() {
    let support = detect_landlock_abi().expect("Landlock ABI >= 6 required");
    check_path_rules_from_config(&support);
    check_build_path_rules_hidden_mounts(&support);
    check_write_restriction_shadowed_is_rejected(&support);
}
