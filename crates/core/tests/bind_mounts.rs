//! `mounts[]` の bind mount 検証 API の結合試験（CORE-2・OCI-4・CORE-5・SEC-1・SEC-4・TASK-29 追補・#1911）。
//!
//! 公開 API だけを crate の外から呼ぶ。`parse_config_bytes` → `BindMountSet::from_mounts` → 各 `check_against_*`
//! → `audit_bind_mount_error` の経路を具体値で照合する。実機権限は不要で 3 OS の既定のテスト集合で動く。
//! 実マウントへの接続（#1912〜#1915。`start` と本番 launcher への結線は済み）は本試験の範囲外で、
//! 通しの確認は `tests/production_launcher.rs` のシナリオ D（実機前提）が担う。

use std::sync::Mutex;

use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
use fandhe_container_core::injected_files::{
    InjectedContent, InjectedFileMode, InjectedFileSet, InjectedFileSpec,
};
use fandhe_container_core::oci_runtime::{
    BindMountErrorKind, BindMountSet, BindPropagation, OciConfig, audit_bind_mount_error,
    parse_config_bytes,
};
use fandhe_container_core::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// テスト用 sink。
struct VecSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for VecSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.0
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?
            .push(record.clone());
        Ok(())
    }
}

fn config(mounts: &str, linux: &str) -> OciConfig {
    let json = format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},"mounts":{mounts},"linux":{linux}}}"#
    );
    parse_config_bytes(json.as_bytes()).expect("valid config")
}

/// OCI-4・CORE-2・SEC-1: config.json のバイト列から検証済みの型への変換結果を具体値で照合する。
#[test]
fn core2_oci4_parse_config_to_bind_mount_set() {
    let c = config(
        r#"[
        {"destination":"/mnt/a","type":"bind","source":"/data/a","options":["ro","noexec"]},
        {"destination":"/mnt/b","type":"none","source":"/data/b","options":["rbind"]}
    ]"#,
        "{}",
    );
    let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");
    assert_eq!(s.len(), 2);
    let m = s.mounts();
    assert_eq!(m[0].destination().as_str(), "/mnt/a");
    assert_eq!(m[0].source(), "/data/a");
    assert_eq!(
        (m[0].read_only(), m[0].noexec(), m[0].recursive()),
        (true, true, false)
    );
    assert_eq!(m[1].index(), 1);
    assert_eq!(
        (m[1].read_only(), m[1].noexec(), m[1].recursive()),
        (false, false, true)
    );
    // SEC-1: nosuid / nodev は指定が無くても常に付く。
    assert!(m.iter().all(|x| x.nosuid() && x.nodev()));
}

/// OCI-4・CRI-2・SEC-1（#2669）: `rslave` は受け、伝播は `HostSlave`。指定が無ければ `Private`。
#[test]
fn oci4_cri2_rslave_is_accepted_as_host_slave() {
    let c = config(
        r#"[
        {"destination":"/mnt/a","type":"bind","source":"/data/a","options":["rbind","rslave","nosuid","nodev"]},
        {"destination":"/mnt/b","type":"bind","source":"/data/b","options":["rbind","rprivate"]},
        {"destination":"/mnt/c","type":"bind","source":"/data/c","options":["bind"]}
    ]"#,
        "{}",
    );
    let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");
    let got: Vec<_> = s
        .mounts()
        .iter()
        .map(|m| (m.recursive(), m.propagation()))
        .collect();
    assert_eq!(
        got,
        [
            (true, BindPropagation::HostSlave),
            (true, BindPropagation::Private),
            (false, BindPropagation::Private),
        ]
    );
    assert!(s.has_host_slave());
}

/// CORE-5・SEC-1: 拒否の種類・位置・エラーコード・固定英文メッセージ（#2063 の決定 (a): bind と rbind の併記を含む）。
#[test]
fn core5_sec1_rejections_have_kind_index_and_message() {
    let cases = [
        (r#"["bind","suid"]"#, BindMountErrorKind::RestrictionLifting),
        (r#"["bind","rshared"]"#, BindMountErrorKind::Propagation),
        (r#"["bind","shared"]"#, BindMountErrorKind::Propagation),
        (r#"["bind","slave"]"#, BindMountErrorKind::Propagation),
        (r#"["bind","unbindable"]"#, BindMountErrorKind::Propagation),
        (
            r#"["rbind","rslave","rprivate"]"#,
            BindMountErrorKind::ConflictingPropagation,
        ),
        (r#"["bind","idmap"]"#, BindMountErrorKind::UnsupportedOption),
        (
            r#"["bind","rbind"]"#,
            BindMountErrorKind::ConflictingBindKind,
        ),
    ];
    for (opts, kind) in cases {
        let c = config(
            &format!(
                r#"[{{"destination":"/ok","type":"bind","source":"/d/ok"}},
                {{"destination":"/x","type":"bind","source":"/secret-host-dir","options":{opts}}}]"#
            ),
            "{}",
        );
        let e = BindMountSet::from_mounts(c.mounts()).expect_err(opts);
        assert_eq!(*e.kind(), kind, "{opts}");
        assert_eq!(e.index(), Some(1));
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(!e.message().contains("secret-host-dir"));
    }
    let c = config(
        r#"[{"destination":"/t","type":"tmpfs","source":"tmpfs"}]"#,
        "{}",
    );
    let e = BindMountSet::from_mounts(c.mounts()).expect_err("not bind");
    assert_eq!(*e.kind(), BindMountErrorKind::NotBind);
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}

/// CORE-2: 予約先・重複・入れ子の拒否（#2063 の決定 (c)）。
#[test]
fn core2_destination_rules() {
    let m = |d: &str| format!(r#"{{"destination":"{d}","type":"bind","source":"/data"}}"#);
    let kind = |list: String| {
        let c = config(&format!("[{list}]"), "{}");
        let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
        (e.kind().clone(), e.index())
    };
    assert_eq!(
        kind(m("/sys/fs")),
        (BindMountErrorKind::ReservedDestination, Some(0))
    );
    assert_eq!(
        kind(format!("{},{}", m("/a"), m("/a"))),
        (
            BindMountErrorKind::DuplicateDestination { other: 0 },
            Some(1)
        )
    );
    assert_eq!(
        kind(format!("{},{}", m("/a"), m("/a/b"))),
        (BindMountErrorKind::NestedDestination { other: 0 }, Some(1))
    );
}

/// SEC-1・OCI-4: #2063 の決定 (d)。rootfs・bundle の配下の元は受け、同じ元でも状態ルートとして渡せば拒否する。
#[test]
fn sec1_oci4_host_paths_accept_bundle_and_rootfs_descendants() {
    let c = config(
        r#"[{"destination":"/sub","type":"bind","source":"/srv/b/rootfs/sub"},
        {"destination":"/data","type":"bind","source":"/srv/b/data"}]"#,
        "{}",
    );
    let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");
    s.check_against_host_paths(&["/srv/b/rootfs", "/srv/b"])
        .expect("descendants of rootfs and bundle are accepted");
    let e = s
        .check_against_protected_trees(&["/srv/b"])
        .expect_err("descendant of state root");
    assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
    assert_eq!(e.index(), Some(0));
}

/// SEC-1・OCI-4（#1915）: 状態ルートは同一・祖先・子孫のいずれの元も拒否する（#2063 の決定 (d)。OS 非依存の Linux 形式入力）。
#[test]
fn sec1_protected_trees_reject_both_directions() {
    let cases = [
        ("/var/lib/fandhe", true),
        ("/var/lib", true),
        ("/var/lib/fandhe/ctr-1", true),
        ("/var/lib/fandhe-other", false),
        ("/srv/data", false),
    ];
    for (source, rejected) in cases {
        let c = config(
            &format!(r#"[{{"destination":"/data","type":"bind","source":"{source}"}}]"#),
            "{}",
        );
        let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");
        let r = s.check_against_protected_trees(&["/var/lib/fandhe"]);
        assert_eq!(r.is_err(), rejected, "source {source}");
        if let Err(e) = r {
            assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
            assert_eq!(e.index(), Some(0));
        }
    }
    // 実体解決後の元が保護対象に重なる場合（symlink 経由）も拒否し、解決できない元は対象外。
    let c = config(
        r#"[{"destination":"/data","type":"bind","source":"/srv/link"}]"#,
        "{}",
    );
    let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");
    let e = s
        .check_resolved_sources_against_protected_trees(&["/var/lib/fandhe"], |_| {
            Some("/var/lib/fandhe/x".to_owned())
        })
        .expect_err("resolved overlap");
    assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
    assert!(
        s.check_resolved_sources_against_protected_trees(&["/var/lib/fandhe"], |_| None)
            .is_ok()
    );
}

/// CORE-2: tmpfs・注入ファイル・保護パス・ホストパスとの交差検査。
#[test]
fn core2_cross_checks() {
    let c = config(
        r#"[{"destination":"/scratch","type":"bind","source":"/var/lib/y"}]"#,
        r#"{"readonlyPaths":["/scratch/ro"],"maskedPaths":["/m/y"]}"#,
    );
    let s = BindMountSet::from_mounts(c.mounts()).expect("accepted");

    let mut t = TmpfsMountSet::new();
    t.push(TmpfsMountSpec::new("/scratch/t", None).expect("tmpfs"))
        .expect("push");
    let e = s.check_against_tmpfs(&t).expect_err("tmpfs");
    assert_eq!(*e.kind(), BindMountErrorKind::OverlapsTmpfs);
    assert_eq!(e.index(), Some(0));
    assert!(s.check_against_tmpfs(&TmpfsMountSet::new()).is_ok());

    let mut inj = InjectedFileSet::new();
    inj.push(
        InjectedFileSpec::new(
            "/scratch/secret",
            InjectedContent::from_bytes(b"x".to_vec()).expect("content"),
            InjectedFileMode::DEFAULT,
        )
        .expect("spec"),
    )
    .expect("push");
    let e = s.check_against_injected(&inj).expect_err("injected");
    assert_eq!(*e.kind(), BindMountErrorKind::OverlapsInjected);

    let e = s
        .check_against_protected_paths(c.readonly_paths(), c.masked_paths())
        .expect_err("protected");
    assert_eq!(*e.kind(), BindMountErrorKind::OverlapsProtectedPath);

    let e = s
        .check_against_host_paths(&["/var/lib/y/rootfs"])
        .expect_err("host");
    assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
    assert!(s.check_against_host_paths(&["/srv/other"]).is_ok());
}

/// SEC-4: 変換拒否は Mount レイヤーの監査レコードになり、宛先のみ載せてマウント元は載せない。
#[test]
fn sec4_rejection_is_audited_with_destination_only() {
    let c = config(
        r#"[{"destination":"/mnt/two","type":"bind","source":"/secret-host-dir","options":["suid"]}]"#,
        "{}",
    );
    let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
    let sink = VecSink(Mutex::new(Vec::new()));
    let r = audit_bind_mount_error(e, c.mounts(), None, &sink);
    assert_eq!(r.delivery, AuditDelivery::Recorded);
    assert_eq!(r.error.code(), ErrorCode::InvalidArgument);
    let g = sink.0.lock().expect("lock");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].layer(), AuditLayer::Mount);
    assert_eq!(
        g[0].path().map(|p| p.to_string_lossy().into_owned()),
        Some("/mnt/two".to_owned())
    );
    assert!(!format!("{:?}", g[0]).contains("secret-host-dir"));
}
