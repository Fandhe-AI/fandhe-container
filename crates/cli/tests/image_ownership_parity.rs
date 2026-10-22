//! pull 時の展開の所有者と start の写像が、同じ所有者の解決から同じ行・同じ拒否になることの照合
//! （SEC-5・CORE-6・#2389。REPAIR-12）。
//!
//! start 側は supervisor の `resolve_rootless_id_source` → core の `resolve_id_maps`（本番 launcher が呼ぶ経路）、
//! pull 側は cli の `image_ownership` を、同じ一時ファイルの入力に対して呼んで比べる。
#![cfg(target_os = "linux")]

use std::path::PathBuf;

use fandhe_container_cli::image_ownership::{
    ExtractChownMode, extract_ownership_for, resolve_extract_ownership,
};
use fandhe_container_core::rootless::{IdMapSet, single_id_mapping};
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_oci::layer::extract::OwnershipPolicy;
use fandhe_container_oci::layer::idmap::IdMap;
use fandhe_container_supervisor::id_model::{RootlessIdResolution, resolve_rootless_id_source};

const ALICE: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n";
const MODES: [ExtractChownMode; 2] = [
    ExtractChownMode::InitialNamespace,
    ExtractChownMode::InUserNamespace,
];

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str, passwd: &str, subuid: Option<&str>, subgid: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!("fc-imgown-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("passwd"), passwd).unwrap();
        for (n, b) in [("subuid", subuid), ("subgid", subgid)] {
            if let Some(b) = b {
                std::fs::write(dir.join(n), b).unwrap();
            }
        }
        Self { dir }
    }

    fn resolution(&self, uid: u32) -> Result<RootlessIdResolution, ErrorCode> {
        resolve_rootless_id_source(
            uid,
            uid,
            &self.dir.join("passwd"),
            &self.dir.join("subuid"),
            &self.dir.join("subgid"),
        )
        .map_err(|e| e.code())
    }

    /// start 側の写像（launcher と同じ経路。1 対 1 は `single_id_mapping`）。
    fn start_maps(&self, uid: u32, gid: u32) -> Result<(IdMapSet, IdMapSet), ErrorCode> {
        match self.resolution(uid)? {
            RootlessIdResolution::SingleId => Ok((
                single_id_mapping(uid).map_err(|e| e.code)?,
                single_id_mapping(gid).map_err(|e| e.code)?,
            )),
            RootlessIdResolution::SubordinateIds(src) => {
                let m = src.resolve_id_maps(uid, gid).map_err(|e| e.code())?;
                Ok((m.uid().clone(), m.gid().clone()))
            }
        }
    }

    fn pull(
        &self,
        uid: u32,
        gid: u32,
        mode: ExtractChownMode,
    ) -> Result<OwnershipPolicy, ErrorCode> {
        resolve_extract_ownership(
            uid,
            uid,
            gid,
            &self.dir.join("passwd"),
            &self.dir.join("subuid"),
            &self.dir.join("subgid"),
            mode,
        )
        .map_err(|e| e.code())
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

type Rows = Vec<(u32, u32, u32)>;

fn core_rows(s: &IdMapSet) -> Rows {
    s.entries()
        .iter()
        .map(|e| (e.container_id, e.host_id, e.count))
        .collect()
}

fn oci_rows(m: &IdMap) -> Rows {
    m.lines()
        .iter()
        .map(|l| (l.container_id, l.host_id, l.count))
        .collect()
}

fn maps_of(p: &OwnershipPolicy) -> (&IdMap, &IdMap) {
    match p {
        OwnershipPolicy::ChownMapped { uid, gid }
        | OwnershipPolicy::ChownInUserNamespace { uid, gid } => (uid, gid),
        other => panic!("unexpected policy: {other:?}"),
    }
}

const PROBES: [u32; 9] = [0, 1, 2, 65535, 65536, 65537, 99999, 100000, u32::MAX];

/// 両側の行が一致し、探索点の写像先も一致する。
fn assert_same(
    env: &Env,
    uid: u32,
    gid: u32,
    want_uid: &[(u32, u32, u32)],
    want_gid: &[(u32, u32, u32)],
) {
    let (su, sg) = env.start_maps(uid, gid).expect("start maps");
    assert_eq!(core_rows(&su), want_uid);
    assert_eq!(core_rows(&sg), want_gid);
    for mode in MODES {
        let policy = env.pull(uid, gid, mode).expect("pull policy");
        let kind_ok = matches!(
            (mode, &policy),
            (
                ExtractChownMode::InitialNamespace,
                OwnershipPolicy::ChownMapped { .. }
            ) | (
                ExtractChownMode::InUserNamespace,
                OwnershipPolicy::ChownInUserNamespace { .. }
            )
        );
        assert!(kind_ok, "mode {mode:?} produced {policy:?}");
        let (pu, pg) = maps_of(&policy);
        assert_eq!(oci_rows(pu), want_uid);
        assert_eq!(oci_rows(pg), want_gid);
        for i in PROBES {
            assert_eq!(su.host_id_of(i), pu.map_to_host(i), "uid probe {i}");
            assert_eq!(sg.host_id_of(i), pg.map_to_host(i), "gid probe {i}");
        }
        // コンテナ内 0 の写像先は start する利用者本人。
        assert_eq!(pu.map_to_host(0), Some(uid));
        assert_eq!(pg.map_to_host(0), Some(gid));
    }
}

/// SEC-5・CORE-6: 名前で書かれた範囲写像は、start と pull で同じ行になる。
#[test]
fn sec5_core6_ranged_mapping_is_identical_for_start_and_pull() {
    let env = Env::new(
        "ranged",
        ALICE,
        Some("alice:100000:65536\n"),
        Some("alice:200000:65536\n"),
    );
    assert_same(
        &env,
        1000,
        1000,
        &[(0, 1000, 1), (1, 100000, 65536)],
        &[(0, 1000, 1), (1, 200000, 65536)],
    );
}

/// CORE-6: passwd に載らない利用者でも、数値 uid の行で両側が一致する。
#[test]
fn core6_numeric_uid_rows_match_without_passwd_entry() {
    let env = Env::new(
        "numeric",
        "root:x:0:0::/root:/bin/sh\n",
        Some("1000:300000:1000\n"),
        Some("1000:400000:1000\n"),
    );
    assert_same(
        &env,
        1000,
        1000,
        &[(0, 1000, 1), (1, 300000, 1000)],
        &[(0, 1000, 1), (1, 400000, 1000)],
    );
}

/// CORE-6: 設定が無いホストでは、両側とも 1 対 1。
#[test]
fn core6_unconfigured_host_is_single_id_on_both_sides() {
    let env = Env::new("single", ALICE, None, None);
    assert_same(&env, 1000, 1000, &[(0, 1000, 1)], &[(0, 1000, 1)]);
}

/// SEC-5: 片側だけの設定は、両側とも同じ code で拒否し、1 対 1 へ縮退しない。
#[test]
fn sec5_partial_configuration_is_refused_on_both_sides() {
    let env = Env::new("partial", ALICE, Some("alice:100000:65536\n"), None);
    assert_eq!(
        env.start_maps(1000, 1000).unwrap_err(),
        ErrorCode::FailedPrecondition
    );
    for mode in MODES {
        assert_eq!(
            env.pull(1000, 1000, mode).unwrap_err(),
            ErrorCode::FailedPrecondition
        );
    }
}

/// SEC-5: ホスト ID 0 を含む範囲は、両側とも `PermissionDenied`。
#[test]
fn sec5_host_root_range_is_refused_on_both_sides() {
    let env = Env::new(
        "hostroot",
        ALICE,
        Some("alice:0:65536\n"),
        Some("alice:200000:65536\n"),
    );
    assert_eq!(
        env.start_maps(1000, 1000).unwrap_err(),
        ErrorCode::PermissionDenied
    );
    for mode in MODES {
        assert_eq!(
            env.pull(1000, 1000, mode).unwrap_err(),
            ErrorCode::PermissionDenied
        );
    }
}

/// SEC-5: uid 0 の利用者は、範囲写像でも 1 対 1 でも両側とも `PermissionDenied`。
#[test]
fn sec5_uid_zero_owner_is_refused_on_both_sides() {
    for (tag, sub) in [("root-ranged", true), ("root-single", false)] {
        let env = Env::new(
            tag,
            "root:x:0:0::/root:/bin/sh\n",
            sub.then_some("root:100000:65536\n"),
            sub.then_some("root:100000:65536\n"),
        );
        assert_eq!(
            env.start_maps(0, 0).unwrap_err(),
            ErrorCode::PermissionDenied,
            "{tag}"
        );
        assert_eq!(
            env.pull(0, 0, ExtractChownMode::InUserNamespace)
                .unwrap_err(),
            ErrorCode::PermissionDenied,
            "{tag}"
        );
    }
}

/// SEC-5: 所有者の行の解析不正は、両側とも 1 対 1 へ縮退せず拒否する。
#[test]
fn sec5_malformed_owner_rows_are_refused_on_both_sides() {
    let env = Env::new(
        "malformed",
        ALICE,
        Some("alice:notanumber:65536\n"),
        Some("alice:200000:65536\n"),
    );
    assert_eq!(
        env.start_maps(1000, 1000).unwrap_err(),
        ErrorCode::FailedPrecondition
    );
    assert_eq!(
        env.pull(1000, 1000, ExtractChownMode::InitialNamespace)
            .unwrap_err(),
        ErrorCode::FailedPrecondition
    );
}

/// 解決済みの値から作る入口も、同じ行になる。
#[test]
fn core6_extract_ownership_for_matches_resolved_source() {
    let env = Env::new(
        "for",
        ALICE,
        Some("alice:100000:65536\n"),
        Some("alice:200000:65536\n"),
    );
    let r = env.resolution(1000).expect("resolution");
    let p = extract_ownership_for(&r, 1000, 1000, ExtractChownMode::InitialNamespace).unwrap();
    let (u, g) = maps_of(&p);
    assert_eq!(oci_rows(u), vec![(0, 1000, 1), (1, 100000, 65536)]);
    assert_eq!(oci_rows(g), vec![(0, 1000, 1), (1, 200000, 65536)]);
}
