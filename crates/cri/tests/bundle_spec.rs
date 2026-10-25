//! CRI の設定から `config.json` への変換の試験（CRI-1・CRI-2・ERR-3・OCI-4・SEC-1・SEC-5・REPAIR-12。#2395）。
//!
//! 生成物を core の `oci_runtime::parse_config_bytes` で読み戻し、具体値で照合する。

use fandhe_container_core::oci_runtime::{self, NamespaceKind};
use fandhe_container_cri::bundle::spec::{
    MAX_ARGS, MAX_CONFIG_BYTES, MAX_ENV, MAX_HOSTNAME_BYTES, MAX_MOUNTS, MAX_PATH_BYTES,
    MAX_PROTECTED_PATHS, MAX_STRING_BYTES,
};
use fandhe_container_cri::bundle::{ImageDefaults, build_runtime_config, validate_config};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime::v1::{
    Capability, ContainerConfig, ContainerMetadata, ImageSpec, Int64Value, KeyValue,
    LinuxContainerConfig, LinuxContainerResources, LinuxContainerSecurityContext,
    LinuxPodSandboxConfig, LinuxSandboxSecurityContext, Mount, MountPropagation, NamespaceMode,
    NamespaceOption, PodSandboxConfig, PodSandboxMetadata, SecurityProfile, UserNamespace,
    security_profile::ProfileType,
};
use serde_json::Value;

fn pod() -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "crictl-smoke-pod".into(),
            namespace: "crictl-smoke".into(),
            uid: "crictl-smoke-uid-0001".into(),
            attempt: 0,
        }),
        ..Default::default()
    }
}

fn ctr() -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "crictl-smoke-ctr".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "docker.io/library/alpine:3.20".into(),
            ..Default::default()
        }),
        command: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        ..Default::default()
    }
}

fn with_sc(f: impl FnOnce(&mut LinuxContainerSecurityContext)) -> ContainerConfig {
    let mut sc = LinuxContainerSecurityContext::default();
    f(&mut sc);
    let mut c = ctr();
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(sc),
        ..Default::default()
    });
    c
}

fn build(p: &PodSandboxConfig, c: &ContainerConfig) -> Value {
    let json = build_runtime_config(p, c, &ImageDefaults::default()).expect("build");
    serde_json::from_slice(json.as_bytes()).expect("json")
}

fn code(p: &PodSandboxConfig, c: &ContainerConfig) -> CriErrorCode {
    build_runtime_config(p, c, &ImageDefaults::default())
        .expect_err("must be rejected")
        .code()
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

/// CRI-1: crictl 疎通確認の fixture（scripts/testdata/cri/{pod,container}.json と同内容）が core の parser に通る。
#[test]
fn cri_1_crictl_smoke_fixture_round_trip() {
    let json = build_runtime_config(&pod(), &ctr(), &ImageDefaults::default()).expect("build");
    let cfg = oci_runtime::parse_config_bytes(json.as_bytes()).expect("core parses it");
    assert!(
        cfg.unapplied_fields().is_empty(),
        "{:?}",
        cfg.unapplied_fields()
    );
    let proc = cfg.process().expect("process");
    assert_eq!(proc.args(), ["/bin/sh", "-c", "sleep 30"]);
    assert_eq!(proc.cwd().to_str(), Some("/"));
    assert_eq!((proc.user().uid(), proc.user().gid()), (0, 0));
    assert_eq!(cfg.root().path().to_str(), Some("rootfs"));
    assert!(cfg.mounts().is_empty());
    assert_eq!(cfg.hostname(), None);
    let kinds: Vec<NamespaceKind> = cfg.namespaces().iter().map(|n| n.kind()).collect();
    assert_eq!(
        kinds,
        [
            NamespaceKind::Pid,
            NamespaceKind::Ipc,
            NamespaceKind::Mount,
            NamespaceKind::Uts,
            NamespaceKind::User,
            NamespaceKind::Network,
        ]
    );
    assert!(cfg.namespaces().iter().all(|n| n.path().is_none()));
}

/// 本モジュールが持つ上限は core の `CONFIG_MAX_*` と同値（cri が core の config 型へ依存しないための複製の照合）。
#[test]
fn limits_match_core_constants() {
    assert_eq!(MAX_CONFIG_BYTES, oci_runtime::CONFIG_MAX_BYTES);
    assert_eq!(MAX_ARGS, oci_runtime::CONFIG_MAX_ARGS);
    assert_eq!(MAX_ENV, oci_runtime::CONFIG_MAX_ENV);
    assert_eq!(MAX_STRING_BYTES, oci_runtime::CONFIG_MAX_STRING_BYTES);
    assert_eq!(MAX_PATH_BYTES, oci_runtime::CONFIG_MAX_PATH_BYTES);
    assert_eq!(MAX_MOUNTS, oci_runtime::CONFIG_MAX_MOUNTS);
    assert_eq!(MAX_PROTECTED_PATHS, oci_runtime::CONFIG_MAX_MASKED_PATHS);
    assert_eq!(MAX_PROTECTED_PATHS, oci_runtime::CONFIG_MAX_READONLY_PATHS);
    assert_eq!(MAX_HOSTNAME_BYTES, oci_runtime::CONFIG_MAX_HOSTNAME_BYTES);
}

#[test]
fn args_resolution_follows_kubernetes_rules() {
    let img = ImageDefaults {
        entrypoint: vec!["/ep".into()],
        cmd: vec!["cmd1".into()],
        ..Default::default()
    };
    let run = |command: &[&str], args: &[&str]| {
        let mut c = ctr();
        c.command = command.iter().map(|s| s.to_string()).collect();
        c.args = args.iter().map(|s| s.to_string()).collect();
        build_runtime_config(&pod(), &c, &img).map(|j| {
            let v: Value = serde_json::from_slice(j.as_bytes()).unwrap();
            v["process"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(run(&["/c"], &[]).unwrap(), ["/c"]);
    assert_eq!(run(&["/c"], &["a"]).unwrap(), ["/c", "a"]);
    assert_eq!(run(&[], &["a"]).unwrap(), ["/ep", "a"]);
    assert_eq!(run(&[], &[]).unwrap(), ["/ep", "cmd1"]);
    let mut c = ctr();
    c.command.clear();
    let e = build_runtime_config(&pod(), &c, &ImageDefaults::default()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(e.message(), "no command to run");
}

#[test]
fn env_merge_is_deterministic_and_container_overrides_image() {
    let img = ImageDefaults {
        env: vec!["A=img".into(), "B=img".into()],
        ..Default::default()
    };
    let mut c = ctr();
    c.envs = vec![
        KeyValue {
            key: "B".into(),
            value: b"ctr".to_vec(),
        },
        KeyValue {
            key: "C".into(),
            value: b"x=y".to_vec(),
        },
    ];
    let json = build_runtime_config(&pod(), &c, &img).unwrap();
    let v: Value = serde_json::from_slice(json.as_bytes()).unwrap();
    assert_eq!(
        v["process"]["env"],
        serde_json::json!(["A=img", "B=ctr", "C=x=y"])
    );
}

/// CRI-2・CORE-4（#2672）: `linux.cgroup_parent` は判断が出るまで `UNIMPLEMENTED`。固定文言で、値を message に含めない。
/// 空文字列（未指定）は拒否しない。
#[test]
fn cri2_core4_cgroup_parent_is_rejected_with_fixed_message() {
    let long = "a".repeat(4097);
    let cases: [(&str, &str); 5] = [
        ("kubepods", "kubepods"),
        ("/kubepods/burstable/pod-abc", "pod-abc"),
        ("kubepods-burstable-pod_abc.slice", "pod_abc"),
        ("../escape", "escape"),
        (long.as_str(), "aaaa"),
    ];
    for (value, leak) in cases {
        let mut p = pod();
        p.linux = Some(LinuxPodSandboxConfig {
            cgroup_parent: value.into(),
            ..Default::default()
        });
        let e = build_runtime_config(&p, &ctr(), &ImageDefaults::default()).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::Unimplemented, "{value}");
        assert_eq!(e.message(), "linux.cgroup_parent is not supported");
        assert!(!e.message().contains(leak), "{}", e.message());
        let e = validate_config(&p, &ctr()).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::Unimplemented, "{value}");
        assert_eq!(e.message(), "linux.cgroup_parent is not supported");
    }
    let mut p = pod();
    p.linux = Some(LinuxPodSandboxConfig::default());
    build_runtime_config(&p, &ctr(), &ImageDefaults::default())
        .expect("empty cgroup_parent is accepted");
}

#[test]
fn invalid_env_is_rejected_without_leaking_values() {
    let secret = "SUPER-SECRET-VALUE-123";
    for (k, v) in [
        ("", secret.to_owned()),
        ("A=B", secret.to_owned()),
        ("A\0B", secret.to_owned()),
        ("K", format!("{secret}\0")),
    ] {
        let mut c = ctr();
        c.envs = vec![KeyValue {
            key: k.into(),
            value: v.into_bytes(),
        }];
        let e = build_runtime_config(&pod(), &c, &ImageDefaults::default()).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert!(!e.message().contains(secret), "{}", e.message());
    }
    let mut c = ctr();
    c.envs = vec![KeyValue {
        key: "K".into(),
        value: vec![0xff, 0xfe],
    }];
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

#[test]
fn user_mapping() {
    let u = |v: i64| Some(Int64Value { value: v });
    let img = ImageDefaults {
        user: Some((1000, 2000)),
        ..Default::default()
    };
    let ids = |c: &ContainerConfig, img: &ImageDefaults| {
        build_runtime_config(&pod(), c, img).map(|j| {
            let v: Value = serde_json::from_slice(j.as_bytes()).unwrap();
            (
                v["process"]["user"]["uid"].as_u64().unwrap(),
                v["process"]["user"]["gid"].as_u64().unwrap(),
            )
        })
    };
    assert_eq!(ids(&ctr(), &img).unwrap(), (1000, 2000));
    assert_eq!(ids(&ctr(), &ImageDefaults::default()).unwrap(), (0, 0));
    let c = with_sc(|sc| sc.run_as_user = u(33));
    assert_eq!(ids(&c, &img).unwrap(), (33, 0));
    let c = with_sc(|sc| {
        sc.run_as_user = u(33);
        sc.run_as_group = u(44);
    });
    assert_eq!(ids(&c, &img).unwrap(), (33, 44));
    for bad in [-1, i64::from(u32::MAX) + 1] {
        let c = with_sc(|sc| sc.run_as_user = u(bad));
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    }
    let c = with_sc(|sc| sc.run_as_group = u(44));
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

/// CRI-2・SEC-1（#2666）: drop_capabilities は OCI 既定集合から除いた集合を 3 集合へ書き、core で読み戻せる。
#[test]
fn cri2_drop_capabilities_acceptance() {
    let caps = |names: &[&str]| {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        with_sc(|sc| {
            sc.capabilities = Some(Capability {
                drop_capabilities: names,
                ..Default::default()
            });
        })
    };
    let read_back = |c: &ContainerConfig| {
        let json = build_runtime_config(&pod(), c, &ImageDefaults::default()).expect("build");
        let v: Value = serde_json::from_slice(json.as_bytes()).unwrap();
        let cfg = oci_runtime::parse_config_bytes(json.as_bytes()).expect("core parses it");
        assert!(
            cfg.unapplied_fields().is_empty(),
            "{:?}",
            cfg.unapplied_fields()
        );
        let core: Vec<&str> = cfg.capabilities().iter().map(|c| c.as_str()).collect();
        (v, core)
    };
    let names_of = |v: &Value, key: &str| -> Vec<String> {
        v["process"]["capabilities"][key]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect()
    };
    // 指定なしは capabilities を書かない（core の既定の 14 個）。
    assert!(
        build(&pod(), &ctr())["process"]
            .get("capabilities")
            .is_none()
    );

    // NET_RAW だけ drop: 既定 14 個から 13 個。
    let (v, core) = read_back(&caps(&["NET_RAW"]));
    let want = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
        "CAP_SETFCAP",
    ];
    for key in ["bounding", "effective", "permitted"] {
        assert_eq!(names_of(&v, key), want, "{key}");
    }
    assert!(v["process"]["capabilities"].get("ambient").is_none());
    assert!(v["process"]["capabilities"].get("inheritable").is_none());
    assert_eq!(core, want);

    // 小文字・CAP_ 接頭辞つき・重複は同じ扱い。MKNOD も落ちて 12 個。
    let (_, core) = read_back(&caps(&["cap_net_raw", "CAP_MKNOD", "net_raw"]));
    assert_eq!(core.len(), 12);
    assert!(!core.contains(&"CAP_NET_RAW") && !core.contains(&"CAP_MKNOD"));

    // ALL は全 drop（3 集合とも空）。
    let (v, core) = read_back(&caps(&["ALL"]));
    assert!(names_of(&v, "bounding").is_empty() && names_of(&v, "permitted").is_empty());
    assert!(core.is_empty());

    // 既定に無い capability の drop は no-op（14 個のまま）。
    let (_, core) = read_back(&caps(&["SYS_ADMIN"]));
    assert_eq!(core.len(), 14);

    // 未知名・空・長すぎる名前・非 ASCII は INVALID_ARGUMENT で、名前をエラーに載せない。
    for bad in ["NOPE", "", "CAP_", "A".repeat(33).as_str(), "ＫＩＬＬ"] {
        let e = build_runtime_config(&pod(), &caps(&[bad]), &ImageDefaults::default())
            .expect_err("must be rejected");
        assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{bad:?}");
        if !bad.is_empty() {
            assert!(!e.to_string().contains(bad), "{bad:?}");
        }
    }
    // 検証段（validate_config）でも同じく拒否する。
    assert!(validate_config(&pod(), &caps(&["NOPE"])).is_err());
    assert!(validate_config(&pod(), &caps(&["NET_RAW"])).is_ok());
}

/// CRI-2・SEC-5（#2664）: run_as_username は解決済みの (uid, gid) を採り、形式・相互排他・未解決を拒否する。
#[test]
fn run_as_username_acceptance() {
    let u = |v: i64| Some(Int64Value { value: v });
    let resolved = ImageDefaults {
        resolved_run_as_username: Some((1000, 1001)),
        ..Default::default()
    };
    let ids = |c: &ContainerConfig, img: &ImageDefaults| {
        build_runtime_config(&pod(), c, img).map(|j| {
            let v: Value = serde_json::from_slice(j.as_bytes()).unwrap();
            (
                v["process"]["user"]["uid"].as_u64().unwrap(),
                v["process"]["user"]["gid"].as_u64().unwrap(),
            )
        })
    };
    let named = with_sc(|sc| sc.run_as_username = "app".into());
    assert_eq!(ids(&named, &resolved).unwrap(), (1000, 1001));
    let with_group = with_sc(|sc| {
        sc.run_as_username = "app".into();
        sc.run_as_group = u(44);
    });
    assert_eq!(ids(&with_group, &resolved).unwrap(), (1000, 44));
    // イメージの User より username が勝つ。
    let img = ImageDefaults {
        user: Some((7, 8)),
        ..resolved.clone()
    };
    assert_eq!(ids(&named, &img).unwrap(), (1000, 1001));
    // イメージの User が未解決でも username が解決済みなら成功する。
    let img = ImageDefaults {
        user_unresolved: true,
        ..resolved.clone()
    };
    assert_eq!(ids(&named, &img).unwrap(), (1000, 1001));
    // 解決結果が無い（解決要求を無視する実装）ときは build が UNIMPLEMENTED。validate は通る。
    assert_eq!(code(&pod(), &named), CriErrorCode::Unimplemented);
    validate_config(&pod(), &named).expect("validate does not need the resolution");
    // run_as_user との同時指定は両段で INVALID_ARGUMENT。
    let both = with_sc(|sc| {
        sc.run_as_user = u(33);
        sc.run_as_username = "app".into();
    });
    assert_eq!(code(&pod(), &both), CriErrorCode::InvalidArgument);
    assert_eq!(
        validate_config(&pod(), &both).unwrap_err().code(),
        CriErrorCode::InvalidArgument
    );
    // 形式不正は両段で INVALID_ARGUMENT。
    for bad in ["1000", "a:b", "a/b", "a\0b", "a\nb", &"a".repeat(257)] {
        let c = with_sc(|sc| sc.run_as_username = bad.into());
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument, "{bad:?}");
        assert_eq!(
            validate_config(&pod(), &c).unwrap_err().code(),
            CriErrorCode::InvalidArgument,
            "{bad:?}"
        );
    }
    // 256 バイトちょうどは形式として受ける。
    let c = with_sc(|sc| sc.run_as_username = "a".repeat(256));
    validate_config(&pod(), &c).expect("256 bytes");
    // run_as_group 単独は従来どおり INVALID_ARGUMENT。
    let c = with_sc(|sc| sc.run_as_group = u(44));
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

#[test]
fn working_dir_and_hostname() {
    let mut c = ctr();
    c.working_dir = "/srv/app".into();
    let mut p = pod();
    p.hostname = "pod-1".into();
    let v = build(&p, &c);
    assert_eq!(s(&v["process"]["cwd"]), "/srv/app");
    assert_eq!(s(&v["hostname"]), "pod-1");
    let img = ImageDefaults {
        working_dir: Some("/img".into()),
        ..Default::default()
    };
    let j = build_runtime_config(&pod(), &ctr(), &img).unwrap();
    let v: Value = serde_json::from_slice(j.as_bytes()).unwrap();
    assert_eq!(s(&v["process"]["cwd"]), "/img");
    for bad in ["rel", "/a/../b", "/a\0b", "/a//b", "/a/"] {
        let mut c = ctr();
        c.working_dir = bad.into();
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument, "{bad:?}");
    }
    for bad in ["a/b", "a\nb", &"h".repeat(MAX_HOSTNAME_BYTES + 1)] {
        let mut p = pod();
        p.hostname = bad.into();
        assert_eq!(code(&p, &ctr()), CriErrorCode::InvalidArgument);
    }
}

type MountTweak = Box<dyn Fn(&mut Mount)>;
type ScTweak = Box<dyn Fn(&mut LinuxContainerSecurityContext)>;

fn mount(host: &str, ctr_path: &str, ro: bool) -> Mount {
    Mount {
        container_path: ctr_path.into(),
        host_path: host.into(),
        readonly: ro,
        ..Default::default()
    }
}

#[test]
fn mounts_map_to_bind_with_ro_rw_options() {
    let mut c = ctr();
    c.mounts = vec![
        mount("/srv/a", "/data", true),
        mount("/srv/b", "/work", false),
    ];
    let v = build(&pod(), &c);
    assert_eq!(
        v["mounts"],
        serde_json::json!([
            {"destination": "/data", "type": "bind", "source": "/srv/a",
             "options": ["rbind", "rprivate", "nosuid", "nodev", "ro"]},
            {"destination": "/work", "type": "bind", "source": "/srv/b",
             "options": ["rbind", "rprivate", "nosuid", "nodev", "rw"]},
        ])
    );
    let json = build_runtime_config(&pod(), &c, &ImageDefaults::default()).unwrap();
    let cfg = oci_runtime::parse_config_bytes(json.as_bytes()).unwrap();
    assert_eq!(cfg.mounts().len(), 2);
}

/// CRI-2・OCI-4（#2669）: HOST_TO_CONTAINER は `rslave` で書く。`rootfsPropagation` は出さず、core が受ける。
#[test]
fn mount_host_to_container_maps_to_rslave() {
    let mut c = ctr();
    let mut ro = mount("/srv/a", "/data", true);
    ro.propagation = MountPropagation::PropagationHostToContainer as i32;
    let mut rw = mount("/srv/b", "/work", false);
    rw.propagation = MountPropagation::PropagationHostToContainer as i32;
    c.mounts = vec![ro, rw];
    let v = build(&pod(), &c);
    assert_eq!(
        v["mounts"],
        serde_json::json!([
            {"destination": "/data", "type": "bind", "source": "/srv/a",
             "options": ["rbind", "rslave", "nosuid", "nodev", "ro"]},
            {"destination": "/work", "type": "bind", "source": "/srv/b",
             "options": ["rbind", "rslave", "nosuid", "nodev", "rw"]},
        ])
    );
    assert!(
        v["linux"].get("rootfsPropagation").is_none(),
        "{}",
        v["linux"]
    );
    let json = build_runtime_config(&pod(), &c, &ImageDefaults::default()).unwrap();
    let cfg = oci_runtime::parse_config_bytes(json.as_bytes()).unwrap();
    let set = oci_runtime::BindMountSet::from_mounts(cfg.mounts()).expect("core accepts rslave");
    assert!(set.has_host_slave());
    assert_eq!(set.len(), 2);
}

#[test]
fn mount_rejections() {
    let bad_paths = [
        ("rel", "/d"),
        ("/h", "rel"),
        ("/a/../b", "/d"),
        ("/h", "/a\0b"),
        ("/", "/d"),
        ("/h", "/"),
        ("", "/d"),
        // core の BindMountSet / normalize_container_path が拒否する形（OCI-4）。
        ("/h", "/data//x"),
        ("/h", "/a/./b"),
        ("/h", "/a/"),
        ("/h", "/a\\b"),
        ("/a/./h", "/d"),
        ("/h//x", "/d"),
        ("/h\\x", "/d"),
        ("/h", "/dev/shm"),
        ("/h", "/proc/x"),
        ("/h", "/sys"),
    ];
    for (h, d) in bad_paths {
        let mut c = ctr();
        c.mounts = vec![mount(h, d, false)];
        assert_eq!(
            code(&pod(), &c),
            CriErrorCode::InvalidArgument,
            "{h:?} {d:?}"
        );
    }
    let tweaks: Vec<MountTweak> = vec![
        Box::new(|m| m.propagation = MountPropagation::PropagationBidirectional as i32),
        Box::new(|m| m.propagation = 7),
        Box::new(|m| m.selinux_relabel = true),
        Box::new(|m| m.recursive_read_only = true),
        Box::new(|m| m.image = Some(ImageSpec::default())),
        Box::new(|m| m.mount_options = vec!["noexec".into()]),
        Box::new(|m| {
            m.uid_mappings = vec![fandhe_container_cri::runtime::v1::IdMapping::default()];
        }),
    ];
    for t in tweaks {
        let mut m = mount("/h", "/d", false);
        t(&mut m);
        let mut c = ctr();
        c.mounts = vec![m];
        assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
    }
}

#[test]
fn resources_map_to_linux_resources() {
    let mut c = ctr();
    c.linux = Some(LinuxContainerConfig {
        resources: Some(LinuxContainerResources {
            memory_limit_in_bytes: 268_435_456,
            memory_swap_limit_in_bytes: 536_870_912,
            cpu_period: 100_000,
            cpu_quota: 50_000,
            ..Default::default()
        }),
        ..Default::default()
    });
    let v = build(&pod(), &c);
    assert_eq!(
        v["linux"]["resources"],
        serde_json::json!({
            "memory": {"limit": 268_435_456_i64, "swap": 536_870_912_i64},
            "cpu": {"period": 100_000, "quota": 50_000}
        })
    );
    let json = build_runtime_config(&pod(), &c, &ImageDefaults::default()).unwrap();
    let cfg = oci_runtime::parse_config_bytes(json.as_bytes()).unwrap();
    assert!(cfg.linux_resources().is_some());
    assert!(cfg.unapplied_fields().is_empty());
}

#[test]
fn resources_rejections() {
    let mut cases: Vec<(LinuxContainerResources, CriErrorCode)> = vec![
        (
            LinuxContainerResources {
                memory_limit_in_bytes: -1,
                ..Default::default()
            },
            CriErrorCode::InvalidArgument,
        ),
        (
            LinuxContainerResources {
                cpu_period: -5,
                ..Default::default()
            },
            CriErrorCode::InvalidArgument,
        ),
        (
            LinuxContainerResources {
                cpu_shares: 2,
                ..Default::default()
            },
            CriErrorCode::Unimplemented,
        ),
        (
            LinuxContainerResources {
                oom_score_adj: 1,
                ..Default::default()
            },
            CriErrorCode::Unimplemented,
        ),
        (
            LinuxContainerResources {
                cpuset_cpus: "0".into(),
                ..Default::default()
            },
            CriErrorCode::Unimplemented,
        ),
    ];
    let mut with_unified = LinuxContainerResources::default();
    with_unified.unified.insert("k".into(), "v".into());
    cases.push((with_unified, CriErrorCode::Unimplemented));
    for (r, want) in cases {
        let mut c = ctr();
        c.linux = Some(LinuxContainerConfig {
            resources: Some(r),
            ..Default::default()
        });
        assert_eq!(code(&pod(), &c), want);
    }
}

#[test]
fn protected_paths_pass_through_and_are_bounded() {
    let c = with_sc(|sc| {
        sc.masked_paths = vec!["/proc/kcore".into()];
        sc.readonly_paths = vec!["/proc/sys".into(), "/proc/bus".into()];
    });
    let v = build(&pod(), &c);
    assert_eq!(
        v["linux"]["maskedPaths"],
        serde_json::json!(["/proc/kcore"])
    );
    assert_eq!(
        v["linux"]["readonlyPaths"],
        serde_json::json!(["/proc/sys", "/proc/bus"])
    );
    let c = with_sc(|sc| sc.masked_paths = vec!["rel".into()]);
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    let c = with_sc(|sc| sc.readonly_paths = vec!["/a".into(); MAX_PROTECTED_PATHS]);
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("at the limit");
    let c = with_sc(|sc| sc.readonly_paths = vec!["/a".into(); MAX_PROTECTED_PATHS + 1]);
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

fn ns(network: NamespaceMode, pid: NamespaceMode, ipc: NamespaceMode) -> NamespaceOption {
    NamespaceOption {
        network: network as i32,
        pid: pid as i32,
        ipc: ipc as i32,
        ..Default::default()
    }
}

fn kinds(v: &Value) -> Vec<String> {
    v["linux"]["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| s(&n["type"]).to_owned())
        .collect()
}

#[test]
fn namespace_mapping() {
    // container 側の指定が sandbox 側より優先される。
    let c = with_sc(|sc| {
        sc.namespace_options = Some(ns(
            NamespaceMode::Node,
            NamespaceMode::Container,
            NamespaceMode::Pod,
        ));
    });
    assert_eq!(
        kinds(&build(&pod(), &c)),
        ["pid", "ipc", "mount", "uts", "user"]
    );
    // container の指定が無ければ sandbox 側を使う。
    let mut p = pod();
    p.linux = Some(LinuxPodSandboxConfig {
        security_context: Some(LinuxSandboxSecurityContext {
            namespace_options: Some(ns(
                NamespaceMode::Node,
                NamespaceMode::Pod,
                NamespaceMode::Pod,
            )),
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_eq!(
        kinds(&build(&p, &ctr())),
        ["pid", "ipc", "mount", "uts", "user"]
    );
    // network が POD / CONTAINER なら network namespace を出す。
    assert_eq!(
        kinds(&build(&pod(), &ctr())),
        ["pid", "ipc", "mount", "uts", "user", "network"]
    );
    // pid・ipc の NODE / TARGET は必須 namespace を外す・join 未対応のため拒否する（SEC-1）。
    for bad in [NamespaceMode::Node, NamespaceMode::Target] {
        let c = with_sc(|sc| {
            sc.namespace_options = Some(ns(NamespaceMode::Pod, bad, NamespaceMode::Pod));
        });
        assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
        let c = with_sc(|sc| {
            sc.namespace_options = Some(ns(NamespaceMode::Pod, NamespaceMode::Pod, bad));
        });
        assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
    }
    let c = with_sc(|sc| {
        sc.namespace_options = Some(ns(
            NamespaceMode::Target,
            NamespaceMode::Pod,
            NamespaceMode::Pod,
        ));
    });
    assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
    // 未知の enum 値は不正な引数。
    let c = with_sc(|sc| {
        sc.namespace_options = Some(NamespaceOption {
            pid: 99,
            ..Default::default()
        });
    });
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

#[test]
fn userns_mappings_are_rejected_but_node_mode_still_gets_a_user_namespace() {
    let mut o = NamespaceOption {
        userns_options: Some(UserNamespace {
            mode: NamespaceMode::Node as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let c = with_sc(|sc| sc.namespace_options = Some(o.clone()));
    assert!(kinds(&build(&pod(), &c)).contains(&"user".to_owned()));
    o.userns_options = Some(UserNamespace {
        mode: NamespaceMode::Pod as i32,
        uids: vec![fandhe_container_cri::runtime::v1::IdMapping::default()],
        ..Default::default()
    });
    let c = with_sc(|sc| sc.namespace_options = Some(o));
    assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
}

fn profile(t: ProfileType) -> Option<SecurityProfile> {
    Some(SecurityProfile {
        profile_type: t as i32,
        localhost_ref: String::new(),
    })
}

/// 拒否表（モジュール doc）の 1 行ごとに 1 ケース。
#[test]
fn rejection_table_is_unimplemented() {
    let mut cases: Vec<(&str, PodSandboxConfig, ContainerConfig)> = Vec::new();
    let mut add = |name, f: &dyn Fn(&mut PodSandboxConfig, &mut ContainerConfig)| {
        let (mut p, mut c) = (pod(), ctr());
        f(&mut p, &mut c);
        cases.push((name, p, c));
    };
    add("tty", &|_, c| c.tty = true);
    add("stdin", &|_, c| c.stdin = true);
    add("stdin_once", &|_, c| c.stdin_once = true);
    add("devices", &|_, c| {
        c.devices = vec![fandhe_container_cri::runtime::v1::Device::default()];
    });
    add("cdi", &|_, c| {
        c.cdi_devices = vec![fandhe_container_cri::runtime::v1::CdiDevice::default()];
    });
    add("log_path", &|_, c| c.log_path = "a.log".into());
    add("log_directory", &|p, _| p.log_directory = "/var/log".into());
    add("windows ctr", &|_, c| {
        c.windows = Some(Default::default());
    });
    add("windows pod", &|p, _| {
        p.windows = Some(Default::default());
    });
    add("dns", &|p, _| p.dns_config = Some(Default::default()));
    add("ports", &|p, _| {
        p.port_mappings = vec![fandhe_container_cri::runtime::v1::PortMapping::default()];
    });
    add("cgroup_parent", &|p, _| {
        p.linux = Some(LinuxPodSandboxConfig {
            cgroup_parent: "kubepods".into(),
            ..Default::default()
        });
    });
    add("pod sysctls", &|p, _| {
        let mut l = LinuxPodSandboxConfig::default();
        l.sysctls.insert("net.x".into(), "1".into());
        p.linux = Some(l);
    });
    add("pod resources", &|p, _| {
        p.linux = Some(LinuxPodSandboxConfig {
            resources: Some(Default::default()),
            ..Default::default()
        });
    });
    add("pod privileged", &|p, _| {
        p.linux = Some(LinuxPodSandboxConfig {
            security_context: Some(LinuxSandboxSecurityContext {
                privileged: true,
                ..Default::default()
            }),
            ..Default::default()
        });
    });
    add("pod seccomp unconfined", &|p, _| {
        p.linux = Some(LinuxPodSandboxConfig {
            security_context: Some(LinuxSandboxSecurityContext {
                seccomp: profile(ProfileType::Unconfined),
                ..Default::default()
            }),
            ..Default::default()
        });
    });
    for (name, p, c) in cases {
        assert_eq!(code(&p, &c), CriErrorCode::Unimplemented, "{name}");
    }

    let sc_cases: Vec<(&str, ScTweak)> = vec![
        ("privileged", Box::new(|sc| sc.privileged = true)),
        (
            "add caps",
            Box::new(|sc| {
                sc.capabilities = Some(Capability {
                    add_capabilities: vec!["SYS_ADMIN".into()],
                    ..Default::default()
                });
            }),
        ),
        (
            "add caps with drop",
            Box::new(|sc| {
                sc.capabilities = Some(Capability {
                    add_capabilities: vec!["SYS_ADMIN".into()],
                    drop_capabilities: vec!["ALL".into()],
                    ..Default::default()
                });
            }),
        ),
        (
            "ambient caps",
            Box::new(|sc| {
                sc.capabilities = Some(Capability {
                    add_ambient_capabilities: vec!["NET_BIND_SERVICE".into()],
                    ..Default::default()
                });
            }),
        ),
        ("readonly_rootfs", Box::new(|sc| sc.readonly_rootfs = true)),
        (
            "supplemental",
            Box::new(|sc| sc.supplemental_groups = vec![10]),
        ),
        (
            "selinux",
            Box::new(|sc| sc.selinux_options = Some(Default::default())),
        ),
        (
            "seccomp unconfined",
            Box::new(|sc| sc.seccomp = profile(ProfileType::Unconfined)),
        ),
        (
            "seccomp localhost",
            Box::new(|sc| sc.seccomp = profile(ProfileType::Localhost)),
        ),
        (
            "apparmor unconfined",
            Box::new(|sc| sc.apparmor = profile(ProfileType::Unconfined)),
        ),
        (
            "legacy seccomp path",
            Box::new(|sc| {
                #[allow(deprecated)]
                {
                    sc.seccomp_profile_path = "unconfined".into();
                }
            }),
        ),
    ];
    for (name, f) in sc_cases {
        assert_eq!(
            code(&pod(), &with_sc(f)),
            CriErrorCode::Unimplemented,
            "{name}"
        );
    }
    // seccomp の RuntimeDefault は受ける（core の既定 seccomp が常に適用される）。
    let c = with_sc(|sc| sc.seccomp = profile(ProfileType::RuntimeDefault));
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("runtime default");
    // AppArmor は適用処理が無いため RuntimeDefault も拒否する（SEC-1・fail-closed）。
    let c = with_sc(|sc| sc.apparmor = profile(ProfileType::RuntimeDefault));
    assert_eq!(code(&pod(), &c), CriErrorCode::Unimplemented);
}

#[test]
fn limits_are_inclusive_at_the_boundary() {
    // env 件数
    let mut c = ctr();
    c.envs = (0..MAX_ENV)
        .map(|i| KeyValue {
            key: format!("K{i}"),
            value: b"v".to_vec(),
        })
        .collect();
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("MAX_ENV");
    c.envs.push(KeyValue {
        key: "EXTRA".into(),
        value: b"v".to_vec(),
    });
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    // args 件数
    let mut c = ctr();
    c.command = vec!["/a".into()];
    c.args = vec!["x".into(); MAX_ARGS - 1];
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("MAX_ARGS");
    c.args.push("x".into());
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    // 1 要素の長さ
    let mut c = ctr();
    c.command = vec!["/".to_owned() + &"a".repeat(MAX_STRING_BYTES - 1)];
    // 4 MiB の総量上限には収まる。
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("MAX_STRING_BYTES");
    c.command = vec!["/".to_owned() + &"a".repeat(MAX_STRING_BYTES)];
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    // mounts 件数
    let mut c = ctr();
    c.mounts = (0..=MAX_MOUNTS)
        .map(|i| mount("/h", &format!("/d{i}"), false))
        .collect();
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    // パスの長さ
    let mut c = ctr();
    c.working_dir = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("MAX_PATH_BYTES");
    c.working_dir = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

#[test]
fn total_size_is_bounded() {
    // 1 要素は上限以下でも、合計が 4 MiB を超える入力は拒否する。
    let mut c = ctr();
    c.command = vec!["/a".into()];
    c.args = vec!["x".repeat(MAX_STRING_BYTES); 33];
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
}

#[test]
fn validate_config_does_not_require_a_command() {
    let mut c = ctr();
    c.command.clear();
    validate_config(&pod(), &c).expect("image may supply the command");
    c.tty = true;
    assert_eq!(
        validate_config(&pod(), &c).unwrap_err().code(),
        CriErrorCode::Unimplemented
    );
}
#[test]
fn issue_2554_review_rejections() {
    // sandbox の supplemental_groups・cpu_quota の不正な負値・swap の不整合・保護パスの `/`（CRI-1・SEC-1）。
    let mut p = pod();
    p.linux = Some(LinuxPodSandboxConfig {
        security_context: Some(LinuxSandboxSecurityContext {
            supplemental_groups: vec![1000],
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_eq!(
        validate_config(&p, &ctr()).unwrap_err().code(),
        CriErrorCode::Unimplemented
    );
    let res = |f: fn(&mut LinuxContainerResources)| {
        let mut r = LinuxContainerResources::default();
        f(&mut r);
        let mut c = ctr();
        c.linux = Some(LinuxContainerConfig {
            resources: Some(r),
            ..Default::default()
        });
        validate_config(&pod(), &c)
    };
    assert_eq!(
        res(|r| r.cpu_quota = -5).unwrap_err().code(),
        CriErrorCode::InvalidArgument
    );
    assert!(res(|r| r.cpu_quota = -1).is_ok());
    assert_eq!(
        res(|r| r.memory_swap_limit_in_bytes = 100)
            .unwrap_err()
            .code(),
        CriErrorCode::InvalidArgument
    );
    assert_eq!(
        res(|r| {
            r.memory_limit_in_bytes = 200;
            r.memory_swap_limit_in_bytes = 100;
        })
        .unwrap_err()
        .code(),
        CriErrorCode::InvalidArgument
    );
    let c = with_sc(|s| s.masked_paths = vec!["/".into()]);
    assert_eq!(
        validate_config(&pod(), &c).unwrap_err().code(),
        CriErrorCode::InvalidArgument
    );
    let c = with_sc(|s| s.readonly_paths = vec!["/".into()]);
    assert_eq!(
        validate_config(&pod(), &c).unwrap_err().code(),
        CriErrorCode::InvalidArgument
    );
}

#[test]
fn nested_duplicate_and_protected_overlapping_mounts_are_rejected() {
    // 入れ子・重複するマウント先（OCI-4）。
    for dests in [["/a", "/a/b"], ["/a/b", "/a"], ["/a", "/a"]] {
        let mut c = ctr();
        c.mounts = vec![mount("/h1", dests[0], false), mount("/h2", dests[1], false)];
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument, "{dests:?}");
    }
    // 兄弟（接頭辞だけ共通）は受ける。
    let mut c = ctr();
    c.mounts = vec![mount("/h1", "/a/b", false), mount("/h2", "/a/bc", false)];
    build_runtime_config(&pod(), &c, &ImageDefaults::default()).expect("siblings");
    // 保護パスと重なるマウント先。
    let mut c = ctr();
    c.mounts = vec![mount("/h", "/secret/x", false)];
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            masked_paths: vec!["/secret".into()],
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    // 保護パスの非正規形（core の ProtectedPath が拒否する）。
    for bad in ["/.", "/a//b", "/a\\b", "/a/"] {
        let mut c = ctr();
        c.linux = Some(LinuxContainerConfig {
            security_context: Some(LinuxContainerSecurityContext {
                masked_paths: vec![bad.into()],
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument, "{bad:?}");
    }
}

/// CRI-2（#2668）: stop_signal は受け入れる（config.json には出さず、停止時に StopRequest で運ぶ）。
#[test]
fn cri2_stop_signal_is_accepted() {
    use fandhe_container_cri::runtime::v1::Signal;
    for sig in [Signal::Sigint, Signal::Sigkill, Signal::RuntimeDefault] {
        let mut c = ctr();
        c.stop_signal = sig as i32;
        build(&pod(), &c);
    }
}

/// CRI-2（#2668）: 未知の stop_signal は `INVALID_ARGUMENT`。
#[test]
fn cri2_stop_signal_unknown_value_is_invalid_argument() {
    for v in [66, -1] {
        let mut c = ctr();
        c.stop_signal = v;
        assert_eq!(code(&pod(), &c), CriErrorCode::InvalidArgument);
    }
}
