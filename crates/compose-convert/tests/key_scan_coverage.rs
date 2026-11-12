//! 合成フィクスチャで `unrecognized` 0 件と 4 分類の網羅を機械照合する結合試験
//! （STACK-3・TASK-151.6・#601・REPAIR-12）。`docs/spec` は参照しない。
//!
//! 走査器 `key_scan` → `KeyOccurrences` → `FileConversionReport` の経路を外から呼ぶ。

use std::collections::BTreeSet;

use fandhe_container_compose_convert::classify::{KeyClass, classify_key_path};
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::{
    ErrorFreeBlocker, FileConversionReport, KeyOccurrences,
};

const COVERAGE: &str = include_str!("fixtures/key_coverage.yaml");
const CLEAN: &str = include_str!("fixtures/key_clean.yaml");
const SPEC_CATALOG: &str = include_str!("fixtures/key_spec_catalog.yaml");
const CORPUS_LIKE: &str = include_str!("fixtures/corpus_like.yaml");

fn scan(yaml: &str) -> KeyOccurrences {
    collect_key_occurrences(&parse_compose_yaml(yaml).expect("fixture parses"))
}

fn unrecognized_paths(o: &KeyOccurrences) -> Vec<String> {
    o.iter()
        .filter(|(_, e)| e.class == KeyClass::Unrecognized)
        .map(|(p, _)| p.to_string())
        .collect()
}

/// STACK-3: 合成フィクスチャの集合で分類表に一致しないキーが 0 件。
#[test]
fn stack3_synthetic_fixtures_have_zero_unrecognized() {
    for (name, text) in [("key_coverage", COVERAGE), ("key_clean", CLEAN)] {
        let o = scan(text);
        assert!(!o.overflowed(), "{name}: overflowed");
        assert_eq!(
            o.unrecognized_count(),
            0,
            "{name}: unrecognized paths {:?}",
            unrecognized_paths(&o)
        );
    }
}

/// STACK-3: 4 分類がすべてフィクスチャに現れ、Unrecognized は現れない。
#[test]
fn stack3_synthetic_fixtures_cover_four_classes() {
    let mut seen = BTreeSet::new();
    for text in [COVERAGE, CLEAN] {
        for (_, e) in scan(text).iter() {
            seen.insert(e.class.as_str());
        }
    }
    let want: BTreeSet<&str> = [
        "convert",
        "warning",
        "error-incompatible",
        "error-unsupported-yet",
    ]
    .into_iter()
    .collect();
    assert_eq!(seen, want);
}

/// STACK-3・D-16: 代表的なパスの分類と出現数を具体値で照合する。
#[test]
fn stack3_key_paths_spot_check() {
    let o = scan(COVERAGE);
    let cases: [(&str, KeyClass, u64); 13] = [
        ("services.*", KeyClass::Convert, 2),
        ("services.*.image", KeyClass::Convert, 2),
        ("services.*.network_mode", KeyClass::ErrorIncompatible, 2),
        ("services.*.volumes", KeyClass::ErrorIncompatible, 1),
        ("x-common", KeyClass::Warning, 1),
        ("version", KeyClass::Warning, 1),
        ("profiles", KeyClass::ErrorUnsupportedYet, 1),
        ("services.*.container_name", KeyClass::Convert, 1),
        ("services.*.cap_drop", KeyClass::Convert, 1),
        ("services.*.tty", KeyClass::Convert, 1),
        ("services.*.cap_add", KeyClass::ErrorUnsupportedYet, 1),
        (
            "services.*.deploy.resources.reservations.devices",
            KeyClass::Convert,
            1,
        ),
        (
            "services.*.deploy.placement",
            KeyClass::ErrorIncompatible,
            1,
        ),
    ];
    for (path, class, n) in cases {
        let e = o.get(path).unwrap_or_else(|| panic!("{path} not recorded"));
        assert_eq!((e.class, e.occurrences), (class, n), "{path}");
    }
    // 降りない段のキーは記録されない。
    for path in [
        "services.*.healthcheck.test",
        "services.*.deploy.resources.limits.cpus",
        "x-common.restart",
        "services.*.environment.ENVMARKER_NAME",
    ] {
        assert!(o.get(path).is_none(), "{path} must not be recorded");
    }
}

/// STACK-3: error-incompatible の 3 行（build・privileged・deploy.placement）がフィクスチャに現れる。
#[test]
fn stack3_incompatible_table_rows_exercised() {
    let o = scan(COVERAGE);
    for path in [
        "services.*.build",
        "services.*.privileged",
        "services.*.deploy.placement",
    ] {
        assert_eq!(
            o.get(path).map(|e| e.class),
            Some(KeyClass::ErrorIncompatible),
            "{path}"
        );
    }
}

/// STACK-3: convert と warning だけのフィクスチャは error_free と判定される。
#[test]
fn stack3_clean_fixture_is_error_free() {
    let doc = parse_compose_yaml(CLEAN).expect("fixture parses");
    let mut drops = ValueDrops::new();
    let _ = convert_top_level(&doc, &mut drops);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    let verdict = report.error_free();
    assert!(verdict.is_error_free(), "{:?}", verdict.blockers());
    assert!(verdict.blockers().is_empty());
}

/// REPAIR-12: 表に無いキーは検出される（0 件の確認が判別力を持つことの陽性対照）。
#[test]
fn stack3_unknown_key_is_detected() {
    let doc = parse_compose_yaml(
        "services:\n  a:\n    image: x\n    no_such_key: 1\nx-common:\n  foo: 1\n",
    )
    .expect("parses");
    let o = collect_key_occurrences(&doc);
    assert_eq!(o.unrecognized_count(), 1);
    assert!(o.get("x-common.foo").is_none());
    let report = FileConversionReport::from_parsed(o, ValueDrops::new());
    let verdict = report.error_free();
    assert!(!verdict.is_error_free());
    assert!(verdict.blockers().iter().any(|b| matches!(
        b,
        ErrorFreeBlocker::ErrorClassKey { key_path, class: KeyClass::Unrecognized, occurrences: 1, .. }
            if key_path == "services.*.no_such_key"
    )));
}

/// STACK-7・D-16: 網羅フィクスチャの build とソケット bind は案内つき、privileged は案内なし。
#[test]
fn stack7_coverage_fixture_guidance() {
    use fandhe_container_compose_convert::classify::IncompatibleGuidance;
    let report = FileConversionReport::from_parsed(scan(COVERAGE), ValueDrops::new());
    let verdict = report.error_free();
    let guidance_of = |path: &str| {
        verdict
            .blockers()
            .iter()
            .find_map(|b| match b {
                ErrorFreeBlocker::ErrorClassKey {
                    key_path, guidance, ..
                } if key_path == path => Some(*guidance),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no blocker for {path}"))
    };
    assert_eq!(
        guidance_of("services.*.build"),
        Some(IncompatibleGuidance::ExternalBuild)
    );
    assert_eq!(
        guidance_of("services.*.volumes"),
        Some(IncompatibleGuidance::DockerSocket)
    );
    assert_eq!(guidance_of("services.*.privileged"), None);
}

/// SEC: 記録したパスと判定にユーザー定義名・環境変数名が混ざらない。
#[test]
fn stack3_key_paths_do_not_contain_user_names() {
    let doc = parse_compose_yaml(COVERAGE).expect("parses");
    let o = collect_key_occurrences(&doc);
    let verdict_dbg = format!(
        "{:?}",
        FileConversionReport::from_parsed(o.clone(), ValueDrops::new()).error_free()
    );
    for marker in ["svcmarker", "ENVMARKER_NAME", "front", "token"] {
        assert!(o.iter().all(|(p, _)| !p.contains(marker)), "{marker}");
        assert!(!verdict_dbg.contains(marker), "{marker}");
    }
}

/// compose-spec の走査段（トップレベル・`services.*`・`networks.*`・`volumes.*`・`secrets.*`・`configs.*`・
/// `services.*.deploy`・`services.*.deploy.resources.reservations`）の既知キーパス。
/// 出典: compose-spec/compose-spec の `schema/compose-spec.json`（commit `COMPOSE_SPEC_COMMIT`）。
/// service は `container_spec`・`workload_spec`・`service` の properties の和集合。
/// `docs/spec` は参照しない。
const COMPOSE_SPEC_KEY_PATHS: [&str; 152] = [
    "configs",
    "configs.*",
    "configs.*.content",
    "configs.*.environment",
    "configs.*.external",
    "configs.*.file",
    "configs.*.labels",
    "configs.*.name",
    "configs.*.template_driver",
    "include",
    "jobs",
    "models",
    "name",
    "networks",
    "networks.*",
    "networks.*.attachable",
    "networks.*.driver",
    "networks.*.driver_opts",
    "networks.*.enable_ipv4",
    "networks.*.enable_ipv6",
    "networks.*.external",
    "networks.*.internal",
    "networks.*.ipam",
    "networks.*.labels",
    "networks.*.name",
    "secrets",
    "secrets.*",
    "secrets.*.driver",
    "secrets.*.driver_opts",
    "secrets.*.environment",
    "secrets.*.external",
    "secrets.*.file",
    "secrets.*.labels",
    "secrets.*.name",
    "secrets.*.template_driver",
    "services",
    "services.*",
    "services.*.annotations",
    "services.*.attach",
    "services.*.blkio_config",
    "services.*.build",
    "services.*.cap_add",
    "services.*.cap_drop",
    "services.*.cgroup",
    "services.*.cgroup_parent",
    "services.*.command",
    "services.*.configs",
    "services.*.container_name",
    "services.*.cpu_count",
    "services.*.cpu_percent",
    "services.*.cpu_period",
    "services.*.cpu_quota",
    "services.*.cpu_rt_period",
    "services.*.cpu_rt_runtime",
    "services.*.cpu_shares",
    "services.*.cpus",
    "services.*.cpuset",
    "services.*.credential_spec",
    "services.*.depends_on",
    "services.*.deploy",
    "services.*.deploy.endpoint_mode",
    "services.*.deploy.labels",
    "services.*.deploy.mode",
    "services.*.deploy.placement",
    "services.*.deploy.replicas",
    "services.*.deploy.resources",
    "services.*.deploy.resources.reservations.cpus",
    "services.*.deploy.resources.reservations.devices",
    "services.*.deploy.resources.reservations.generic_resources",
    "services.*.deploy.resources.reservations.memory",
    "services.*.deploy.restart_policy",
    "services.*.deploy.rollback_config",
    "services.*.deploy.update_config",
    "services.*.develop",
    "services.*.device_cgroup_rules",
    "services.*.devices",
    "services.*.dns",
    "services.*.dns_opt",
    "services.*.dns_search",
    "services.*.domainname",
    "services.*.entrypoint",
    "services.*.env_file",
    "services.*.environment",
    "services.*.expose",
    "services.*.extends",
    "services.*.external_links",
    "services.*.extra_hosts",
    "services.*.gpus",
    "services.*.group_add",
    "services.*.healthcheck",
    "services.*.hostname",
    "services.*.image",
    "services.*.init",
    "services.*.ipc",
    "services.*.isolation",
    "services.*.label_file",
    "services.*.labels",
    "services.*.links",
    "services.*.logging",
    "services.*.mac_address",
    "services.*.mem_limit",
    "services.*.mem_reservation",
    "services.*.mem_swappiness",
    "services.*.memswap_limit",
    "services.*.models",
    "services.*.network_mode",
    "services.*.networks",
    "services.*.oom_kill_disable",
    "services.*.oom_score_adj",
    "services.*.pid",
    "services.*.pids_limit",
    "services.*.platform",
    "services.*.ports",
    "services.*.post_start",
    "services.*.pre_start",
    "services.*.pre_stop",
    "services.*.privileged",
    "services.*.profiles",
    "services.*.provider",
    "services.*.pull_policy",
    "services.*.pull_refresh_after",
    "services.*.read_only",
    "services.*.restart",
    "services.*.runtime",
    "services.*.scale",
    "services.*.secrets",
    "services.*.security_opt",
    "services.*.shm_size",
    "services.*.stdin_open",
    "services.*.stop_grace_period",
    "services.*.stop_signal",
    "services.*.storage_opt",
    "services.*.sysctls",
    "services.*.tmpfs",
    "services.*.tty",
    "services.*.ulimits",
    "services.*.umask",
    "services.*.use_api_socket",
    "services.*.user",
    "services.*.userns_mode",
    "services.*.uts",
    "services.*.volumes",
    "services.*.volumes_from",
    "services.*.working_dir",
    "version",
    "volumes",
    "volumes.*",
    "volumes.*.driver",
    "volumes.*.driver_opts",
    "volumes.*.external",
    "volumes.*.labels",
    "volumes.*.name",
];
/// #3614 で分類表へ足したキーパス（すべて ErrorUnsupportedYet の葉）。
const ADDED_3614: [&str; 57] = [
    "configs.*.content",
    "configs.*.environment",
    "configs.*.labels",
    "configs.*.name",
    "configs.*.template_driver",
    "jobs",
    "models",
    "networks.*.attachable",
    "networks.*.driver_opts",
    "networks.*.enable_ipv4",
    "networks.*.enable_ipv6",
    "networks.*.internal",
    "networks.*.ipam",
    "networks.*.labels",
    "networks.*.name",
    "secrets.*.driver",
    "secrets.*.driver_opts",
    "secrets.*.environment",
    "secrets.*.labels",
    "secrets.*.name",
    "secrets.*.template_driver",
    "services.*.annotations",
    "services.*.attach",
    "services.*.cgroup",
    "services.*.cpu_count",
    "services.*.cpu_percent",
    "services.*.cpu_period",
    "services.*.cpu_quota",
    "services.*.cpu_rt_period",
    "services.*.cpu_rt_runtime",
    "services.*.cpuset",
    "services.*.credential_spec",
    "services.*.deploy.mode",
    "services.*.deploy.resources.reservations.cpus",
    "services.*.deploy.resources.reservations.generic_resources",
    "services.*.deploy.resources.reservations.memory",
    "services.*.deploy.rollback_config",
    "services.*.develop",
    "services.*.gpus",
    "services.*.label_file",
    "services.*.mem_swappiness",
    "services.*.memswap_limit",
    "services.*.models",
    "services.*.pids_limit",
    "services.*.post_start",
    "services.*.pre_start",
    "services.*.pre_stop",
    "services.*.provider",
    "services.*.pull_refresh_after",
    "services.*.runtime",
    "services.*.storage_opt",
    "services.*.umask",
    "services.*.use_api_socket",
    "services.*.userns_mode",
    "volumes.*.driver_opts",
    "volumes.*.labels",
    "volumes.*.name",
];
/// 出典 commit（`COMPOSE_SPEC_KEY_PATHS` の導出元。NOTICE に帰属を記す）。
const COMPOSE_SPEC_COMMIT: &str = "3a4a6995e4a971f6173dff9130cb3e38e6738651";

/// #3614・STACK-3: compose-spec の走査段の既知キーがすべて分類表に当たる（Unrecognized が 0 件）。
#[test]
fn stack3_3614_compose_spec_known_keys_are_classified() {
    assert_eq!(COMPOSE_SPEC_COMMIT.len(), 40);
    assert!(COMPOSE_SPEC_KEY_PATHS.len() >= 140);
    let missing: Vec<&str> = COMPOSE_SPEC_KEY_PATHS
        .iter()
        .copied()
        .filter(|p| classify_key_path(p) == KeyClass::Unrecognized)
        .collect();
    assert!(missing.is_empty(), "unclassified spec keys: {missing:?}");
}

/// #3614・STACK-3: 追加した 57 キーは ErrorUnsupportedYet で、spec の既知キーに実在する。
#[test]
fn stack3_3614_added_keys_are_unsupported_yet() {
    assert_eq!(ADDED_3614.len(), 57);
    for p in ADDED_3614 {
        assert_eq!(classify_key_path(p), KeyClass::ErrorUnsupportedYet, "{p}");
        assert!(COMPOSE_SPEC_KEY_PATHS.contains(&p), "{p} is not a spec key");
    }
}

/// #3614・STACK-3・STACK-10: 57 キーを含む合成フィクスチャで unrecognized が 0 件、
/// 各キーが 1 回ずつ記録され、葉の先（子の目印）へは降りない。
#[test]
fn stack3_3614_spec_catalog_fixture_has_zero_unrecognized() {
    let o = scan(SPEC_CATALOG);
    assert!(!o.overflowed());
    assert_eq!(o.unrecognized_count(), 0, "{:?}", unrecognized_paths(&o));
    for p in ADDED_3614 {
        let e = o.get(p).unwrap_or_else(|| panic!("{p} not recorded"));
        assert_eq!(
            (e.class, e.occurrences),
            (KeyClass::ErrorUnsupportedYet, 1),
            "{p}"
        );
    }
    for p in [
        "networks.*.ipam.config",
        "models.*",
        "jobs.*",
        "services.*.develop.watch",
        "services.*.post_start.command",
        "services.*.deploy.rollback_config.parallelism",
        "services.*.deploy.resources.reservations.generic_resources.discrete_resource_spec",
    ] {
        assert!(o.get(p).is_none(), "{p} must not be recorded");
    }
}

/// #3614・STACK-3・STACK-10: local-server・ideas の形を模した合成フィクスチャで unrecognized が 0 件。
/// 実コーパスそのものの計測は #607（人間担当）。
#[test]
fn stack3_3614_corpus_like_fixture_has_zero_unrecognized() {
    let o = scan(CORPUS_LIKE);
    assert!(!o.overflowed());
    assert_eq!(o.unrecognized_count(), 0, "{:?}", unrecognized_paths(&o));
    let cases: [(&str, KeyClass, u64); 9] = [
        ("services.*", KeyClass::Convert, 2),
        ("services.*.build", KeyClass::ErrorIncompatible, 1),
        ("services.*.pull_policy", KeyClass::ErrorUnsupportedYet, 2),
        ("networks.*.name", KeyClass::ErrorUnsupportedYet, 1),
        ("networks.*.ipam", KeyClass::ErrorUnsupportedYet, 1),
        ("networks.*.internal", KeyClass::ErrorUnsupportedYet, 1),
        ("volumes.*.name", KeyClass::ErrorUnsupportedYet, 1),
        ("secrets.*.name", KeyClass::ErrorUnsupportedYet, 1),
        ("x-common", KeyClass::Warning, 1),
    ];
    for (path, class, n) in cases {
        let e = o.get(path).unwrap_or_else(|| panic!("{path} not recorded"));
        assert_eq!((e.class, e.occurrences), (class, n), "{path}");
    }
}

/// SEC: 新しいフィクスチャのユーザー定義名がパスにも判定にも混ざらない。
#[test]
fn stack3_3614_new_fixture_paths_do_not_contain_user_names() {
    for (text, markers) in [
        (
            SPEC_CATALOG,
            &[
                "mdlmarker",
                "jobmarker",
                "svcmarker",
                "netmarker",
                "volmarker",
                "secmarker",
                "cfgmarker",
                "watchmarker",
            ][..],
        ),
        (
            CORPUS_LIKE,
            &[
                "appmarker",
                "dbmarker",
                "backmarker",
                "pgdata",
                "tokenmarker",
                "DB_ENVMARKER",
            ][..],
        ),
    ] {
        let o = scan(text);
        let dbg = format!(
            "{:?}",
            FileConversionReport::from_parsed(o.clone(), ValueDrops::new()).error_free()
        );
        for m in markers {
            assert!(o.iter().all(|(p, _)| !p.contains(m)), "{m}");
            assert!(!dbg.contains(m), "{m}");
        }
    }
}

/// REPAIR-12: 旧形式・表に無いキーは新しい行の後も Unrecognized として 1 件ずつ検出される（陽性対照）。
#[test]
fn stack3_3614_unknown_keys_still_detected() {
    let o = scan(
        "services:\n  a:\n    image: x\n    volume_driver: y\nnetworks:\n  n:\n    no_such_key: 1\n",
    );
    assert_eq!(o.unrecognized_count(), 2);
    for p in ["services.*.volume_driver", "networks.*.no_such_key"] {
        let e = o.get(p).unwrap_or_else(|| panic!("{p} not recorded"));
        assert_eq!((e.class, e.occurrences), (KeyClass::Unrecognized, 1), "{p}");
    }
}
