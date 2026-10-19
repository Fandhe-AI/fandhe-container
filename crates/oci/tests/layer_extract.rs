//! レイヤー tar 展開の公開 API 結合試験（TASK-52.3・OCI-1・#409）。
//! digest 検証（TASK-52.1）→ gzip 展開（TASK-52.2）→ tar 展開の連結を、外向き通信なしで具体値で確認する。

use std::fmt::Write as _;
use std::io::Write;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::{ExtractLimits, extract_layer_blob};
use fandhe_container_oci::layer::verify_blob_digest;
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

fn layer_gz() -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("etc/os-release", &b"ID=test\n"[..]),
        ("bin/sh", &b"#!"[..]),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    }
    let tar_bytes = b.into_inner().unwrap();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar_bytes).unwrap();
    e.finish().unwrap()
}

/// 一時 base を排他的に作る。共有 /tmp 上の推測可能な固定名を削除・再利用すると、競合で置かれた symlink を
/// root が辿りうる（#2324・SEC-2）。PID・時刻・試行番号の一意名を `create_dir` で作り、既存パスは採用しない。
fn exclusive_base(prefix: &str) -> std::path::PathBuf {
    let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    for attempt in 0..16u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = tmp.join(format!("{prefix}-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                return path;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("exclusively create {}: {e}", path.display()),
        }
    }
    panic!("could not exclusively create a temp dir for {prefix}");
}

/// OCI-1: 検証済み blob を展開でき、内容と件数が一致する。上限超過は ResourceExhausted。
#[test]
fn oci1_verify_then_extract() {
    let z = layer_gz();
    let base = exclusive_base("fc-oci-tar-it");
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();
    let blob = base.join("layer.tar.gz");
    std::fs::write(&blob, &z).unwrap();

    verify_blob_digest(&blob, &sha(&z), 1 << 20).unwrap();
    let r = extract_layer_blob(
        &blob,
        &root,
        1 << 20,
        ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
    )
    .unwrap();
    assert_eq!((r.entries, r.bytes), (2, 10));
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        b"ID=test\n"
    );
    assert_eq!(std::fs::read(root.join("bin/sh")).unwrap(), b"#!");

    let root2 = base.join("root2");
    std::fs::create_dir(&root2).unwrap();
    let e = extract_layer_blob(
        &blob,
        &root2,
        1 << 20,
        ExtractLimits::new(1, 100, 1 << 30, 1 << 20),
    )
    .unwrap_err();
    assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    std::fs::remove_dir_all(&base).unwrap();
}

/// SEC-5・OCI-1・#1810: 公開 API（`extract_layers_with_policy`）と実際の所有者取得を通して、
/// 実際の所有者から組んだ写像に収まるファイルは setuid / setgid を残し、写像外は落とし、件数を具体値で照合する。
#[cfg(target_os = "linux")]
#[test]
fn sec5_special_bits_via_public_api_with_real_owner() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        IdRange, SpecialBitsDecision, SpecialBitsPolicy, extract_layers_with_policy,
    };

    let base = exclusive_base("fc-oci-sec5-it");
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    // 展開物の実際の所有者（このプロセスの euid / egid）を、root 配下に作ったプローブから得る。
    let probe = root.join(".probe");
    std::fs::write(&probe, b"").unwrap();
    let md = std::fs::metadata(&probe).unwrap();
    let (uid, gid) = (md.uid(), md.gid());
    std::fs::remove_file(&probe).unwrap();

    let mut b = tar::Builder::new(Vec::new());
    for (name, mode, u, g) in [
        ("mapped", 0o6755, 0, 0),
        ("other_uid", 0o4755, 100, 0),
        ("other_gid", 0o2755, 0, 100),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(mode);
        h.set_uid(u);
        h.set_gid(g);
        h.set_size(1);
        h.set_cksum();
        b.append_data(&mut h, name, &b"x"[..]).unwrap();
    }
    let tar_bytes = b.into_inner().unwrap();

    let r = extract_layers_with_policy(
        &NoopOciOpRecorder,
        [std::io::Cursor::new(tar_bytes)],
        &root,
        ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        SpecialBitsPolicy::PreserveIfOwnerMapped {
            uid: IdRange {
                container_id: 0,
                host_id: uid,
                count: 1,
            },
            gid: IdRange {
                container_id: 0,
                host_id: gid,
                count: 1,
            },
        },
    )
    .unwrap();
    let r = &r[0];
    assert_eq!(r.special_bits.decision, SpecialBitsDecision::Evaluated);
    let mode = |n: &str| {
        std::fs::metadata(root.join(n))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    // special_bits_to_keep は setuid / setgid を独立に判定する（所有者が host root のビットだけ落ちる）。
    let mut expected_mapped = 0o755;
    if uid != 0 {
        expected_mapped |= 0o4000;
    }
    if gid != 0 {
        expected_mapped |= 0o2000;
    }
    // preserved_files は要求した特殊ビットをすべて保持したファイルだけを数える（一部でも落ちれば除去側）。
    let mapped_kept = expected_mapped == 0o6755;
    let mapped_stripped = !mapped_kept;
    assert_eq!(r.special_bits.preserved_files, u64::from(mapped_kept));
    assert_eq!(
        r.files_with_stripped_special_bits,
        2 + u64::from(mapped_stripped)
    );
    assert_eq!(mode("mapped"), expected_mapped);
    assert_eq!(mode("other_uid"), 0o755);
    assert_eq!(mode("other_gid"), 0o755);
    std::fs::remove_dir_all(&base).unwrap();
}
/// 公開 API 経由の chown 試験で使う、uid / gid を持つ tar（通常ファイル・ディレクトリ・symlink）。
#[cfg(target_os = "linux")]
fn owned_tar(uid: u64, gid: u64, file_mode: u32) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_mode(0o755);
    h.set_uid(uid);
    h.set_gid(gid);
    h.set_size(0);
    h.set_cksum();
    b.append_data(&mut h, "d/", &b""[..]).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(file_mode);
    h.set_uid(uid);
    h.set_gid(gid);
    h.set_size(1);
    h.set_cksum();
    b.append_data(&mut h, "d/f", &b"x"[..]).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_mode(0o777);
    h.set_uid(uid);
    h.set_gid(gid);
    h.set_size(0);
    h.set_cksum();
    b.append_link(&mut h, "l", "d/f").unwrap();
    b.into_inner().unwrap()
}

/// 一時ディレクトリの (base, root, euid, egid) を返す。root は 0700。
#[cfg(target_os = "linux")]
fn chown_sandbox(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, u32, u32) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let base = exclusive_base(&format!("fc-oci-{tag}"));
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let md = std::fs::metadata(&root).unwrap();
    (base, root, md.uid(), md.gid())
}

/// SEC-5・OCI-1・#2225: 公開 API（`extract_layers_with_options`）が実際の `chown` で tar の uid / gid を写像先の ID にする。
/// 権限なしでも成り立つよう、コンテナ内 0 を自分の ID（root で動くときは 65534）へ写す 1 行の写像で照合する。
#[cfg(target_os = "linux")]
#[test]
fn sec5_chown_via_public_api_with_real_syscalls() {
    use std::os::unix::fs::MetadataExt as _;

    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        ExtractOptions, IdMap, IdRange, OwnershipDecision, OwnershipPolicy,
        extract_layers_with_options,
    };

    let (base, root, uid, gid) = chown_sandbox("chown-ok");
    let (hu, hg) = if uid == 0 { (65534, 65534) } else { (uid, gid) };
    let one = |h| {
        IdMap::new(vec![IdRange {
            container_id: 0,
            host_id: h,
            count: 1,
        }])
        .unwrap()
    };
    let options = ExtractOptions::new().with_ownership(OwnershipPolicy::ChownMapped {
        uid: one(hu),
        gid: one(hg),
    });
    let r = extract_layers_with_options(
        &NoopOciOpRecorder,
        [std::io::Cursor::new(owned_tar(0, 0, 0o644))],
        &root,
        ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        &options,
    )
    .unwrap();
    let r = &r[0];
    assert_eq!(r.ownership.decision, OwnershipDecision::Applied);
    // d/f・l・d・root の 4 ノード。
    assert_eq!(r.ownership.chowned_entries, 4);
    for p in ["d", "d/f", "l"] {
        let m = std::fs::symlink_metadata(root.join(p)).unwrap();
        assert_eq!((m.uid(), m.gid()), (hu, hg), "{p}");
    }
    let m = std::fs::symlink_metadata(&root).unwrap();
    assert_eq!((m.uid(), m.gid()), (hu, hg));
    std::fs::remove_dir_all(&base).unwrap();
}

/// SEC-5・#2225: 写像に無い tar の uid は PermissionDenied で、何も書く前に拒否する。権限が無いまま自分以外の ID へ
/// `chown` する展開も PermissionDenied（fail-closed。root で動くときは成功することを照合する）。
#[cfg(target_os = "linux")]
#[test]
fn sec5_chown_outside_map_and_without_privilege_fail_closed() {
    use std::os::unix::fs::MetadataExt as _;

    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        ExtractOptions, IdMap, IdRange, OwnershipPolicy, extract_layers_with_options,
    };

    let (base, root, uid, gid) = chown_sandbox("chown-deny");
    let limits = ExtractLimits::new(10, 100, 1 << 30, 1 << 20);
    let map_to = |h| {
        IdMap::new(vec![IdRange {
            container_id: 0,
            host_id: h,
            count: 1,
        }])
        .unwrap()
    };
    let opts = |hu, hg| {
        ExtractOptions::new().with_ownership(OwnershipPolicy::ChownMapped {
            uid: map_to(hu),
            gid: map_to(hg),
        })
    };

    // 範囲外の uid（5）は、権限に依らず書き込み前に拒否する。
    let e = extract_layers_with_options(
        &NoopOciOpRecorder,
        [std::io::Cursor::new(owned_tar(5, 0, 0o644))],
        &root,
        limits,
        &opts(uid.max(1), gid.max(1)),
    )
    .unwrap_err();
    assert_eq!(e.code(), OciErrorCode::PermissionDenied);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);

    // 自分以外の ID への chown。
    let (tu, tg) = (uid + 1, gid + 1);
    let res = extract_layers_with_options(
        &NoopOciOpRecorder,
        [std::io::Cursor::new(owned_tar(0, 0, 0o644))],
        &root,
        limits,
        &opts(tu, tg),
    );
    if uid == 0 {
        res.unwrap();
        let m = std::fs::symlink_metadata(root.join("d/f")).unwrap();
        assert_eq!((m.uid(), m.gid()), (tu, tg));
    } else {
        assert_eq!(res.unwrap_err().code(), OciErrorCode::PermissionDenied);
    }
    std::fs::remove_dir_all(&base).unwrap();
}

/// 実機前提（Linux・root 権限が必要）。SEC-5・SEC-1・OCI-1・#2225: subuid 風の複数行の写像（0 → 100000 × 1、
/// 1 → 100001 × 65535）で root が展開し、所有者が写像先になり、`PreserveIfChowned` で setuid が残ることを照合する。
/// 実行: `cargo test -p fandhe-container-oci --test layer_extract -- --ignored sec5_chown_subuid_range_as_root`
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root (CAP_CHOWN) on Linux; SEC-5 #2225"]
fn sec5_chown_subuid_range_as_root() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use fandhe_container_oci::instrument::NoopOciOpRecorder;
    use fandhe_container_oci::layer::extract::{
        ExtractOptions, IdMap, IdRange, OwnershipPolicy, SpecialBitsPolicy,
        extract_layers_with_options,
    };

    let (base, root, uid, _gid) = chown_sandbox("chown-root");
    assert_eq!(uid, 0, "this test must run as root");
    let map = || {
        IdMap::new(vec![
            IdRange {
                container_id: 0,
                host_id: 100_000,
                count: 1,
            },
            IdRange {
                container_id: 1,
                host_id: 100_001,
                count: 65_535,
            },
        ])
        .unwrap()
    };
    let options = ExtractOptions::new()
        .with_ownership(OwnershipPolicy::ChownMapped {
            uid: map(),
            gid: map(),
        })
        .with_special_bits(SpecialBitsPolicy::PreserveIfChowned);
    let r = extract_layers_with_options(
        &NoopOciOpRecorder,
        [std::io::Cursor::new(owned_tar(33, 33, 0o4755))],
        &root,
        ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        &options,
    )
    .unwrap();
    assert_eq!(r[0].special_bits.preserved_files, 1);
    let m = std::fs::symlink_metadata(root.join("d/f")).unwrap();
    assert_eq!((m.uid(), m.gid()), (100_033, 100_033));
    assert_eq!(m.permissions().mode() & 0o7777, 0o4755);
    let m = std::fs::symlink_metadata(root.join("l")).unwrap();
    assert_eq!((m.uid(), m.gid()), (100_033, 100_033));
    let m = std::fs::symlink_metadata(&root).unwrap();
    assert_eq!((m.uid(), m.gid()), (100_000, 100_000));
    std::fs::remove_dir_all(&base).unwrap();
}

/// SEC-5・#2225: chown の「変更なし」指定 u32::MAX をホスト範囲に含む写像は、`ChownMapped` に渡す前（展開・chown の前）に
/// `IdMap::new` が InvalidArgument で拒否する。末尾が u32::MAX - 1 までは受理する。
#[cfg(target_os = "linux")]
#[test]
fn sec5_chown_mapped_rejects_host_u32_max_before_extract() {
    use fandhe_container_oci::layer::extract::{IdMap, IdRange};

    let r = |h, n| {
        IdMap::new(vec![IdRange {
            container_id: 0,
            host_id: h,
            count: n,
        }])
    };
    assert_eq!(
        r(u32::MAX, 1).unwrap_err().code(),
        OciErrorCode::InvalidArgument
    );
    assert_eq!(
        r(u32::MAX - 1, 2).unwrap_err().code(),
        OciErrorCode::InvalidArgument
    );
    assert!(r(u32::MAX - 1, 1).is_ok());
}
