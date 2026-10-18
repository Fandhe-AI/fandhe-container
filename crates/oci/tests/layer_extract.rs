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

/// OCI-1: 検証済み blob を展開でき、内容と件数が一致する。上限超過は ResourceExhausted。
#[test]
fn oci1_verify_then_extract() {
    let z = layer_gz();
    let base = std::env::temp_dir().join(format!("fc-oci-tar-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
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
    std::fs::create_dir_all(&root2).unwrap();
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

    let base = std::env::temp_dir().join(format!("fc-oci-sec5-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
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
    if uid == 0 || gid == 0 {
        // host root 所有の setuid / setgid は残さない（SEC-1）。
        assert_eq!(r.special_bits.preserved_files, 0);
        assert_eq!(r.files_with_stripped_special_bits, 3);
        assert_eq!(mode("mapped"), 0o755);
    } else {
        assert_eq!(r.special_bits.preserved_files, 1);
        assert_eq!(r.files_with_stripped_special_bits, 2);
        assert_eq!(mode("mapped"), 0o6755);
        assert_eq!(mode("other_uid"), 0o755);
        assert_eq!(mode("other_gid"), 0o755);
    }
    std::fs::remove_dir_all(&base).unwrap();
}
