//! ホスト側 `guest_mount`（契約の SSOT）との照合試験（MAC-1・TASK-65.3・REPAIR-12）。
//!
//! guest-init は platform-macos を通常の依存に持たない（静的なゲストバイナリへバックエンドを入れないため）。
//! 規則を二重に持つ代わりに、定数・復号結果・報告行の往復をここで機械照合する。3 OS で走る。

use fandhe_container_guest_init::READY_MARKER;
use fandhe_container_guest_init::directive::{
    Access, DIRECTIVE_KEY, DecodeError, GUEST_MOUNT_BASE, MAX_GUEST_MOUNT_DEPTH,
    MAX_GUEST_MOUNT_ELEMENT_BYTES, MAX_GUEST_MOUNT_POINT_BYTES, MAX_VIRTIOFS_SHARES,
    MAX_VIRTIOFS_TAG_BYTES, Tag, decode_all,
};
use fandhe_container_guest_init::report::{
    Errno, InitStage, MAX_REPORT_LINE_BYTES, REPORT_PREFIX, ReportLine,
};
use fandhe_container_platform_macos::guest_mount as host;
use fandhe_container_platform_macos::guest_mount::{GuestMountOutcome, parse_report_line};
use fandhe_container_platform_macos::virtiofs as host_virtiofs;

#[test]
fn mac1_constants_match_host() {
    assert_eq!(DIRECTIVE_KEY, host::DIRECTIVE_KEY);
    assert_eq!(GUEST_MOUNT_BASE, host::GUEST_MOUNT_BASE);
    assert_eq!(MAX_VIRTIOFS_SHARES, host_virtiofs::MAX_VIRTIOFS_SHARES);
    assert_eq!(
        MAX_VIRTIOFS_TAG_BYTES,
        host_virtiofs::MAX_VIRTIOFS_TAG_BYTES
    );
    assert_eq!(
        MAX_GUEST_MOUNT_POINT_BYTES,
        host::MAX_GUEST_MOUNT_POINT_BYTES
    );
    assert_eq!(
        MAX_GUEST_MOUNT_ELEMENT_BYTES,
        host::MAX_GUEST_MOUNT_ELEMENT_BYTES
    );
    assert_eq!(MAX_GUEST_MOUNT_DEPTH, host::MAX_GUEST_MOUNT_DEPTH);
    assert_eq!(REPORT_PREFIX, host::REPORT_PREFIX);
    assert_eq!(MAX_REPORT_LINE_BYTES, host::MAX_REPORT_LINE_BYTES);
}

fn inputs() -> Vec<String> {
    let tag35 = "t".repeat(35);
    let tag36 = "t".repeat(36);
    let el64 = "e".repeat(64);
    let el65 = "e".repeat(65);
    let long = format!(
        "/mnt/fandhe/{}/{}/{}",
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(40)
    );
    let nine: Vec<String> = (0..9)
        .map(|i| format!("{DIRECTIVE_KEY}t{i}:/mnt/fandhe/m{i}:ro"))
        .collect();
    let eight = nine[..8].join(" ");
    let mut v: Vec<String> = [
        "",
        "console=hvc0 quiet\n",
        "fandhe.virtiofs=a:/mnt/fandhe/a:ro",
        "console=hvc0 fandhe.virtiofs=a:/mnt/fandhe/a:ro quiet fandhe.virtiofs=b:/mnt/fandhe/x/y:rw\n",
        "fandhe.virtiofs=a:/mnt/fandhe/a",
        "fandhe.virtiofs=a:/mnt/fandhe/a:ro:x",
        "fandhe.virtiofs=a:/mnt/fandhe/a:RO",
        "fandhe.virtiofs=:/mnt/fandhe/a:ro",
        "fandhe.virtiofs=a b:/mnt/fandhe/a:ro",
        "fandhe.virtiofs=a:/etc:ro",
        "fandhe.virtiofs=a:/mnt/fandhe:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/../etc:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/./a:ro",
        "fandhe.virtiofs=a:/mnt/fandhe//a:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/a/:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/a/b/c/d:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/a/b/c/d/e:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/proc:rw",
        "fandhe.virtiofs=a:/mnt/fandhe/a%b:ro",
        "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=x",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    v.push(format!("{DIRECTIVE_KEY}{tag35}:/mnt/fandhe/a:rw"));
    v.push(format!("{DIRECTIVE_KEY}{tag36}:/mnt/fandhe/a:rw"));
    v.push(format!("{DIRECTIVE_KEY}a:/mnt/fandhe/{el64}:rw"));
    v.push(format!("{DIRECTIVE_KEY}a:/mnt/fandhe/{el65}:rw"));
    v.push(format!("{DIRECTIVE_KEY}a:{long}:rw"));
    v.push(nine.join(" "));
    v.push(eight);
    v
}

#[test]
fn mac1_decode_matches_host_parse_directives() {
    for cmd in inputs() {
        let ours = decode_all(&cmd);
        let theirs = host::parse_directives(&cmd);
        match (ours, theirs) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.len(), b.len(), "{cmd}");
                for (x, y) in a.iter().zip(b.iter()) {
                    assert_eq!(x.tag.as_str(), y.tag.as_str(), "{cmd}");
                    assert_eq!(x.mount_point.as_str(), y.mount_point.as_str(), "{cmd}");
                    assert_eq!(
                        x.access == Access::ReadOnly,
                        y.access.is_read_only(),
                        "{cmd}"
                    );
                }
            }
            (Err(DecodeError::TooMany), Err(host::DirectiveError::TooMany)) => {}
            (
                Err(DecodeError::Malformed { index: a }),
                Err(host::DirectiveError::Malformed { index: b }),
            ) => assert_eq!(a, b, "{cmd}"),
            (a, b) => panic!("mismatch for {cmd:?}: guest={a:?} host={b:?}"),
        }
    }
}

#[test]
fn mac1_host_encoded_directives_decode_in_guest() {
    use fandhe_container_platform_macos::virtiofs::{ShareAccess, VirtiofsTag};
    for (tag, mp, ro) in [
        ("code", "/mnt/fandhe/code", true),
        ("data.v1_x", "/mnt/fandhe/a/b", false),
    ] {
        let _ = (
            VirtiofsTag::try_new(tag).unwrap(),
            host::GuestMountPoint::try_new(mp).unwrap(),
        );
        let mode = if ro {
            ShareAccess::ReadOnly
        } else {
            ShareAccess::ReadWrite
        };
        let token = format!(
            "{DIRECTIVE_KEY}{tag}:{mp}:{}",
            if mode.is_read_only() { "ro" } else { "rw" }
        );
        let d = decode_all(&token).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].tag.as_str(), tag);
        assert_eq!(d[0].mount_point.as_str(), mp);
        assert_eq!(d[0].access == Access::ReadOnly, ro);
    }
}

#[test]
fn mac1_every_report_line_round_trips_through_host_parser() {
    let tag_str = "t".repeat(35);
    for name in ["a", "code", "data.v1_x-2", tag_str.as_str()] {
        let tag = Tag::try_new(name).unwrap();
        let ok = ReportLine::ok(&tag);
        let item = parse_report_line(ok.as_str().as_bytes()).unwrap().unwrap();
        assert_eq!(item.tag.as_str(), name);
        assert_eq!(item.outcome, GuestMountOutcome::Mounted);
        for raw in [1, 2, 7, 22, 4095, 0, 4096, -1] {
            let errno = Errno::new(raw);
            let err = ReportLine::error(&tag, errno);
            assert!(err.as_str().len() <= host::MAX_REPORT_LINE_BYTES);
            let item = parse_report_line(err.as_str().as_bytes()).unwrap().unwrap();
            assert_eq!(item.tag.as_str(), name);
            assert_eq!(
                item.outcome,
                GuestMountOutcome::Failed { errno: errno.get() }
            );
        }
    }
}

#[test]
fn mac1_marker_and_diagnostics_are_not_reports_for_host() {
    assert!(parse_report_line(READY_MARKER.as_bytes()).is_none());
    let diag = ReportLine::init_error(InitStage::Cmdline, Errno::E2BIG);
    assert!(parse_report_line(diag.as_str().as_bytes()).is_none());
    assert!(parse_report_line(ReportLine::ready().as_str().as_bytes()).is_none());
}
