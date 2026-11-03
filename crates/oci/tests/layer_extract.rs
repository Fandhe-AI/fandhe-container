//! レイヤー tar 展開の公開 API 結合試験（TASK-52.3・OCI-1・#409）。
//! digest 検証（TASK-52.1）→ gzip 展開（TASK-52.2）→ tar 展開の連結を、外向き通信なしで具体値で確認する。

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use fandhe_container_oci::error::{OciError, OciErrorCode};
#[cfg(unix)]
use fandhe_container_oci::layer::VerifiedLayerBlob;
#[cfg(not(unix))]
use fandhe_container_oci::layer::decompress_layer_to_writer;
#[cfg(not(unix))]
use fandhe_container_oci::layer::extract::extract_layers;
use fandhe_container_oci::layer::extract::{ExtractLimits, ExtractedLayer};
#[cfg(unix)]
use fandhe_container_oci::layer::extract::{ImageLayer, extract_image_layers};
#[cfg(not(unix))]
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

/// gzip の tar を gunzip する（blob の diff_id = 展開後 tar の sha256 を計算するため）。
#[cfg(unix)]
fn gunzip(gz: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// digest 検証済みの gzip blob を、下位から上位の順に `root` へ重ねて展開する（パスで開く旧入口の代わり。#2535・OCI-1）。
///
/// Unix（Linux・macOS）は本番と同じ検証済みハンドル版（`VerifiedLayerBlob` → `extract_image_layers`）を通す。
/// blob は 0600 にして umask に依らず信頼条件を満たす。Windows は `VerifiedLayerBlob` を作れない（`Unimplemented`）ため、
/// 検証 → gzip 展開 → ストリーム展開（`extract_layers`）の連結で代える。パスを開き直す展開入口は使わず、期待値は 3 OS 共通。
fn extract_blobs(
    blobs: &[&Path],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mut opened = Vec::new();
        for p in blobs {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
            let gz = std::fs::read(p).unwrap();
            let owner = std::fs::metadata(p).unwrap().uid();
            let blob = VerifiedLayerBlob::open(p, &sha(&gz), gz.len() as u64, owner)?;
            opened.push((blob, sha(&gunzip(&gz))));
        }
        let layers: Vec<ImageLayer<'_>> = opened
            .iter()
            .map(|(b, d)| ImageLayer::new(b, "application/vnd.oci.image.layer.v1.tar+gzip", d))
            .collect();
        extract_image_layers(&layers, root, max_uncompressed_bytes, limits)
    }
    #[cfg(not(unix))]
    {
        let mut tars = Vec::new();
        for p in blobs {
            let gz = std::fs::read(p).unwrap();
            verify_blob_digest(p, &sha(&gz), gz.len() as u64)?;
            let mut tar = Vec::new();
            decompress_layer_to_writer(p, max_uncompressed_bytes, &mut tar)?;
            tars.push(std::io::Cursor::new(tar));
        }
        extract_layers(tars, root, limits)
    }
}

/// 作成時から 0700 でディレクトリを作る（Unix は `DirBuilderExt::mode`。umask 000 の root でも chmod までの隙間を作らない）。
fn mkdir_private(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
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
        match mkdir_private(&path) {
            Ok(()) => return path,
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

    // 検証 → gzip 展開 → 展開は `extract_blobs` が連結する（Unix はハンドルで検証し、パスを開き直さない）。
    let r = extract_blobs(
        &[&blob],
        &root,
        1 << 20,
        ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
    )
    .unwrap();
    assert_eq!(r.len(), 1);
    let r = &r[0];
    assert_eq!((r.entries, r.bytes), (2, 10));
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        b"ID=test\n"
    );
    assert_eq!(std::fs::read(root.join("bin/sh")).unwrap(), b"#!");

    let root2 = base.join("root2");
    std::fs::create_dir(&root2).unwrap();
    let e = extract_blobs(
        &[&blob],
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
    // setuid は uid、setgid は uid と gid の両方で判定する（所有 uid が host root なら setgid も落ちる。#2251 P2-1）。
    let mut expected_mapped = 0o755;
    if uid != 0 {
        expected_mapped |= 0o4000;
    }
    if uid != 0 && gid != 0 {
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
    // ビットごとの件数: 残ったビットは preserved_bits、残らなかったビットだけが stripped_bits に数えられる（P2-6）。
    let (kept_uid, kept_gid) = (u64::from(uid != 0), u64::from(uid != 0 && gid != 0));
    let bits = r.special_bits;
    assert_eq!(bits.preserved_bits.setuid, kept_uid);
    assert_eq!(bits.preserved_bits.setgid, kept_gid);
    // 求めたのは setuid・setgid ともに 2 件（mapped と other_*）。
    assert_eq!(bits.stripped_bits.setuid, 2 - kept_uid);
    assert_eq!(bits.stripped_bits.setgid, 2 - kept_gid);
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
