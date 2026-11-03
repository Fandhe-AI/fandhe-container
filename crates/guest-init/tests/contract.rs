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
use fandhe_container_guest_init::link_probe as link;
use fandhe_container_guest_init::probe::{
    GUEST_MOUNT, ProbePlan, SHARE_TAG, TEST_KEY, TOKEN_VIRTIOFS_IO, TOKEN_VIRTIOFS_LINK, TestMode,
    WRITE_LINE, WRITE_LINES, decode_test_mode, run_virtiofs_io,
};
use fandhe_container_guest_init::report::{
    Errno, InitStage, MAX_PROBE_LINE_BYTES, MAX_REPORT_LINE_BYTES, PROBE_NAMESPACE, PROBE_PREFIX,
    ProbeEntries, ProbeOp, ProbeValue, REPORT_PREFIX, ReportLine,
};
#[cfg(unix)]
use fandhe_container_platform_macos::config as host_config;
use fandhe_container_platform_macos::guest_link_probe as host_link;
use fandhe_container_platform_macos::guest_mount as host;
use fandhe_container_platform_macos::guest_mount::{GuestMountOutcome, parse_report_line};
use fandhe_container_platform_macos::guest_probe as host_probe;
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
    // #2139: panic hook と devtmpfs の検査失敗の診断行も報告行として解釈されない。
    let panic = ReportLine::init_error(InitStage::Panic, Errno::EIO);
    assert!(parse_report_line(panic.as_str().as_bytes()).is_none());
    let busy = ReportLine::init_error(InitStage::Dev, Errno::EBUSY);
    assert!(parse_report_line(busy.as_str().as_bytes()).is_none());
    assert!(parse_report_line(ReportLine::ready().as_str().as_bytes()).is_none());
}

// ---- virtiofs_io のプローブ契約（MAC-1・IO-5・#1876）----

#[test]
fn mac1_io5_probe_constants_match_host() {
    assert_eq!(TEST_KEY, host::GUEST_TEST_KEY);
    assert_eq!(TOKEN_VIRTIOFS_IO, host::GuestTestMode::VirtiofsIo.token());
    assert_eq!(PROBE_NAMESPACE, host_probe::PROBE_NAMESPACE);
    assert_eq!(PROBE_PREFIX, host_probe::PROBE_PREFIX);
    assert_eq!(MAX_PROBE_LINE_BYTES, host_probe::MAX_PROBE_LINE_BYTES);
    assert_eq!(SHARE_TAG, host_probe::SHARE_TAG);
    assert_eq!(GUEST_MOUNT, host_probe::GUEST_MOUNT);
    assert_eq!(WRITE_LINE, host_probe::WRITE_LINE);
    assert_eq!(WRITE_LINES, host_probe::WRITE_LINES);
    // ready マーカーと mount 報告は、プローブの名前空間に属さない。
    assert!(!READY_MARKER.starts_with(host_probe::PROBE_NAMESPACE));
}

#[test]
fn mac1_io5_every_probe_line_round_trips_through_host_parser() {
    use host_probe::{ProbeItem, ProbeLine, parse_probe_line};
    let p = |l: &ReportLine| parse_probe_line(l.as_str().as_bytes());
    let v = ProbeValue::try_new("fandhe-read-abc").unwrap();
    assert_eq!(
        p(&ReportLine::probe_read(&v)),
        ProbeLine::Item(ProbeItem::Read("fandhe-read-abc".into()))
    );
    let names = vec!["a-1".to_string(), "b-1".to_string()];
    assert_eq!(
        p(&ReportLine::probe_readdir(
            &ProbeEntries::try_new(&names).unwrap()
        )),
        ProbeLine::Item(ProbeItem::Readdir("a-1,b-1".into()))
    );
    assert_eq!(
        p(&ReportLine::probe_write_done()),
        ProbeLine::Item(ProbeItem::Write)
    );
    for (op, name) in [
        (ProbeOp::Read, "read"),
        (ProbeOp::Readdir, "readdir"),
        (ProbeOp::Write, "write"),
    ] {
        assert_eq!(
            p(&ReportLine::probe_error(op)),
            ProbeLine::Item(ProbeItem::OpError(name.into()))
        );
    }
    assert_eq!(
        p(&ReportLine::probe_done()),
        ProbeLine::Item(ProbeItem::Done)
    );
    // 行全体がちょうど 256 バイトの値もホストが受理する（257 バイトはゲストが作れない）。
    let head = PROBE_PREFIX.len() + "op=read value=".len();
    let fit = "a".repeat(MAX_PROBE_LINE_BYTES - head);
    let line = ReportLine::probe_read(&ProbeValue::try_new(&fit).unwrap());
    assert_eq!(line.as_str().len(), 256);
    assert_eq!(p(&line), ProbeLine::Item(ProbeItem::Read(fit)));
    // プローブ行は mount 報告の走査に誤認されない。
    assert!(parse_report_line(ReportLine::probe_done().as_str().as_bytes()).is_none());
}

struct Tmp(std::path::PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fandhe-guest-contract-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        // macOS の一時ディレクトリは `/var`（`/private/var` への symlink）配下にある。ホストの共有ディレクトリ検査は
        // 経路上の symlink を拒否する（MAC-1・TASK-65.1）ため、実体パスへ正規化して使う。
        Self(std::fs::canonicalize(&p).unwrap())
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// ゲストが出す順序（mount 報告 → ready → プローブ行）のログ全体を組み立てる。
fn guest_log(plan: ProbePlan, root: &std::path::Path) -> String {
    let tag = Tag::try_new(SHARE_TAG).unwrap();
    let mut log = String::new();
    for l in [ReportLine::ok(&tag), ReportLine::ready()] {
        log.push_str(l.as_str());
        log.push('\n');
    }
    run_virtiofs_io(plan, root, &mut |l| {
        log.push_str(l.as_str());
        log.push('\n');
    });
    log
}

#[test]
fn mac1_io5_real_probe_output_is_accepted_by_host_log_parser() {
    let t = Tmp::new("ok");
    let root = &t.0;
    std::fs::create_dir_all(root.join("in/dir")).unwrap();
    std::fs::create_dir_all(root.join("out")).unwrap();
    std::fs::write(root.join("in/read.txt"), "fandhe-read-1f\n").unwrap();
    let expected: std::collections::BTreeSet<String> = ["a-1f", "b-1f", "c-1f"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for n in &expected {
        std::fs::write(root.join("in/dir").join(n), "x").unwrap();
    }
    let log = guest_log(ProbePlan::Run, root);
    let parsed = host_probe::parse_probe_log(&log);
    assert_eq!(parsed.read.as_deref(), Some("fandhe-read-1f"));
    assert!(parsed.write_done && parsed.done && !parsed.invalid);
    assert!(parsed.errors.is_empty());
    let reported = parsed.readdir.as_deref().unwrap();
    assert_eq!(host_probe::compare_entries(&expected, reported), Ok(()));
    // mount 報告は従来どおりホストの走査で読め、ready とプローブ行は報告として読まれない。
    let reports: Vec<_> = log
        .lines()
        .filter_map(|l| parse_report_line(l.as_bytes()))
        .collect();
    assert_eq!(reports.len(), 1);
    let report = reports[0].as_ref().unwrap();
    assert_eq!(report.tag.as_str(), SHARE_TAG);
    assert_eq!(report.outcome, GuestMountOutcome::Mounted);
    // 書いた内容は、ホストが検証する期待内容と一致する。
    let written = std::fs::read(root.join("out/write.txt")).unwrap();
    assert_eq!(
        written,
        format!("{}\n", host_probe::WRITE_LINE)
            .repeat(host_probe::WRITE_LINES)
            .into_bytes()
    );
}

#[test]
fn mac1_io5_error_probe_output_is_accepted_by_host_log_parser() {
    // 入力が何も無い共有（read / readdir が error）と、mount 不成立（全 op が error）。
    let t = Tmp::new("err");
    std::fs::create_dir_all(t.0.join("out")).unwrap();
    let parsed = host_probe::parse_probe_log(guest_log(ProbePlan::Run, &t.0));
    assert!(parsed.has_error("read") && parsed.has_error("readdir"));
    assert!(parsed.write_done && parsed.done && !parsed.invalid);
    let t = Tmp::new("missing");
    std::fs::create_dir_all(t.0.join("out")).unwrap();
    let parsed = host_probe::parse_probe_log(guest_log(ProbePlan::MountMissing, &t.0));
    assert!(parsed.has_error("read") && parsed.has_error("readdir") && parsed.has_error("write"));
    assert!(parsed.done && !parsed.invalid);
    assert!(!t.0.join("out/write.txt").exists());
}

#[test]
fn mac1_io5_host_effective_cmdline_enables_probe_only_when_requested() {
    use fandhe_container_platform_macos::config::VmConfigSpec;
    use fandhe_container_platform_macos::guest_mount::{GuestMountPoint, GuestTestMode};
    use fandhe_container_platform_macos::virtiofs::{
        ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
    };
    let t = Tmp::new("cmdline");
    let kernel = t.0.join("vmlinux");
    std::fs::write(&kernel, b"k").unwrap();
    let share_dir = t.0.join("share");
    std::fs::create_dir_all(&share_dir).unwrap();
    let shares = VirtiofsSharesSpec::try_new(vec![
        VirtiofsShareSpec::new(
            VirtiofsTag::try_new(SHARE_TAG).unwrap(),
            SharedDirectoryPath::try_new(&share_dir).unwrap(),
            ShareAccess::ReadWrite,
        )
        .with_guest_mount(GuestMountPoint::try_new(GUEST_MOUNT).unwrap()),
    ])
    .unwrap();
    let off = VmConfigSpec::from_parts(&kernel, None, "console=hvc0")
        .unwrap()
        .with_shared_directories(shares);
    let off_cmdline = off.effective_cmdline().unwrap();
    assert_eq!(decode_test_mode(off_cmdline.as_str()), TestMode::Absent);
    let on_cmdline = off
        .with_guest_test(GuestTestMode::VirtiofsIo)
        .effective_cmdline()
        .unwrap();
    assert_eq!(decode_test_mode(on_cmdline.as_str()), TestMode::VirtiofsIo);
    // 指示は従来どおり復号でき、試験キーの追加で件数や内容は変わらない。
    let d = decode_all(on_cmdline.as_str()).unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].tag.as_str(), SHARE_TAG);
    assert_eq!(d[0].mount_point.as_str(), GUEST_MOUNT);
    assert_eq!(d[0].access, Access::ReadWrite);
    // ホストは自分の復号でも同じ指示を得る（試験キーは指示として数えない）。
    assert_eq!(
        host::parse_directives(on_cmdline.as_str()).unwrap().len(),
        1
    );
}

/// MAC-1・TASK-65.1: 共有ディレクトリの経路に symlink があれば、その接頭辞を指して拒否する（OS 非依存の回帰）。
///
/// macOS で一時ディレクトリが `/var` の symlink 配下になり検査が通らなかった失敗（main の CI）を、
/// Linux でも symlink を挟んだディレクトリで再現して捕まえる。
#[cfg(unix)]
#[test]
fn mac1_shared_dir_under_symlinked_ancestor_is_rejected() {
    use fandhe_container_platform_macos::config::ConfigError;
    use fandhe_container_platform_macos::virtiofs::SharedDirectoryPath;
    let t = Tmp::new("symlink-anc");
    let real = t.0.join("real");
    std::fs::create_dir_all(real.join("share")).unwrap();
    let link = t.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        SharedDirectoryPath::try_new(&link.join("share")),
        Err(ConfigError::SharedDirSymlink { path: link })
    );
    assert!(SharedDirectoryPath::try_new(&real.join("share")).is_ok());
}

// ---- virtiofs_link の観測契約（MAC-1・SEC-4・#1877）----

#[test]
fn mac1_sec4_link_constants_match_host() {
    assert_eq!(
        TOKEN_VIRTIOFS_LINK,
        host::GuestTestMode::VirtiofsLink.token()
    );
    assert_eq!(link::LINK_NAMESPACE, host_link::LINK_NAMESPACE);
    assert_eq!(link::LINK_PREFIX, host_link::LINK_PREFIX);
    assert_eq!(link::MAX_LINK_LINE_BYTES, host_link::MAX_LINK_LINE_BYTES);
    assert_eq!(link::MAX_LINK_READ_BYTES, host_link::MAX_LINK_READ_BYTES);
    assert_eq!(link::RO_TAG, host_link::RO_TAG);
    assert_eq!(link::RO_MOUNT, host_link::RO_MOUNT);
    assert_eq!(link::RW_TAG, host_link::RW_TAG);
    assert_eq!(link::RW_MOUNT, host_link::RW_MOUNT);
    assert_eq!(link::RO_LINK_NAMES, host_link::RO_LINK_NAMES);
    assert_eq!(link::RW_SRC_NAME, host_link::RW_SRC_NAME);
    assert_eq!(link::RW_SYM_NAME, host_link::RW_SYM_NAME);
    assert_eq!(link::RW_HARD_NAME, host_link::RW_HARD_NAME);
    assert_eq!(link::RW_SRC_LINE, host_link::RW_SRC_LINE);
}

/// 名前空間・接頭辞・マーカーはどの組み合わせでも前方一致しない（ホストの各パーサが互いの行を誤認しない）。
#[test]
fn mac1_sec4_link_lines_are_not_mistaken_for_other_lines() {
    let ns = [
        REPORT_PREFIX,
        PROBE_NAMESPACE,
        link::LINK_NAMESPACE,
        READY_MARKER,
    ];
    for (i, a) in ns.iter().enumerate() {
        for (j, b) in ns.iter().enumerate() {
            assert!(i == j || !a.starts_with(b), "{a} / {b}");
        }
    }
    let line = format!("{}done", link::LINK_PREFIX);
    assert_eq!(
        host_probe::parse_probe_line(line.as_bytes()),
        host_probe::ProbeLine::Other
    );
    assert_eq!(parse_report_line(line.as_bytes()), None);
    // io のプローブ行・mount 報告・ready は link のパーサに無視される。
    let tag = Tag::try_new(SHARE_TAG).unwrap();
    let mut log = String::new();
    for l in [
        ReportLine::ok(&tag),
        ReportLine::ready(),
        ReportLine::probe_done(),
    ] {
        log.push_str(l.as_str());
        log.push('\n');
    }
    assert_eq!(
        host_link::parse_link_log(&log),
        host_link::LinkLog::default()
    );
}

#[cfg(unix)]
fn link_log(plan: link::LinkPlan, ro: &std::path::Path, rw: &std::path::Path) -> String {
    let mut log = String::new();
    link::run_virtiofs_link(plan, ro, rw, &mut |l| {
        log.push_str(l.as_str());
        log.push('\n');
    });
    log
}

#[cfg(unix)]
const LINK_RUN: link::LinkPlan = link::LinkPlan {
    ro: link::SharePlan::Run,
    rw: link::SharePlan::Run,
};

/// 一時ディレクトリに fixture を作る（ro の 3 リンクと空の rw）。絶対パスの symlink は実体パスを指す。
#[cfg(unix)]
fn link_fixture(t: &Tmp) -> (std::path::PathBuf, std::path::PathBuf) {
    let (ro, rw) = (t.0.join("ro"), t.0.join("rw"));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::create_dir_all(&rw).unwrap();
    std::fs::write(ro.join("inside.txt"), "inside\n").unwrap();
    std::os::unix::fs::symlink("inside.txt", ro.join("inside_link")).unwrap();
    std::os::unix::fs::symlink(ro.join("inside.txt"), ro.join("abs_inside_link")).unwrap();
    std::os::unix::fs::symlink(ro.join("missing"), ro.join("dangling_inside_link")).unwrap();
    (ro, rw)
}

#[cfg(unix)]
fn link_specs(t: &Tmp, ro: &std::path::Path, rw: &std::path::Path) -> host_config::VmConfigSpec {
    use fandhe_container_platform_macos::guest_mount::GuestMountPoint;
    use fandhe_container_platform_macos::virtiofs::{
        ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
    };
    let kernel = t.0.join("vmlinux");
    std::fs::write(&kernel, b"k").unwrap();
    let share = |tag: &str, dir: &std::path::Path, access, mount: &str| {
        VirtiofsShareSpec::new(
            VirtiofsTag::try_new(tag).unwrap(),
            SharedDirectoryPath::try_new(dir).unwrap(),
            access,
        )
        .with_guest_mount(GuestMountPoint::try_new(mount).unwrap())
    };
    let shares = VirtiofsSharesSpec::try_new(vec![
        share(link::RO_TAG, ro, ShareAccess::ReadOnly, link::RO_MOUNT),
        share(link::RW_TAG, rw, ShareAccess::ReadWrite, link::RW_MOUNT),
    ])
    .unwrap();
    host_config::VmConfigSpec::from_parts(&kernel, None, "console=hvc0")
        .unwrap()
        .with_shared_directories(shares)
}

/// 実際に走らせた出力をホストのパーサが受理する（観測 18 行・done・不正なし）。fixture はホストの起動前検査も通る。
#[cfg(unix)]
#[test]
fn mac1_sec4_real_link_output_is_accepted_by_host_log_parser() {
    let t = Tmp::new("link-ok");
    let (ro, rw) = link_fixture(&t);
    // 起動前の検査（範囲内リンクのみ・nlink=1）を通る fixture であること。
    link_specs(&t, &ro, &rw).check_share_conflicts().unwrap();
    let tag = Tag::try_new(link::RO_TAG).unwrap();
    let mut log = String::new();
    for l in [ReportLine::ok(&tag), ReportLine::ready()] {
        log.push_str(l.as_str());
        log.push('\n');
    }
    log.push_str(&link_log(LINK_RUN, &ro, &rw));
    let parsed = host_link::parse_link_log(&log);
    assert!(parsed.done && !parsed.invalid, "{log}");
    assert_eq!(parsed.lines.len(), 18);
    assert_eq!(
        parsed.lines.first().map(String::as_str),
        Some("share=ro name=inside_link op=readlink result=ok value=inside.txt")
    );
    assert_eq!(
        parsed.lines.last().map(String::as_str),
        Some("share=rw name=hard op=lstat result=ok kind=file nlink=2 size=24")
    );
    // 書いた内容は、ホストが観察するときの期待内容と一致する。
    assert_eq!(
        std::fs::read(rw.join(host_link::RW_SRC_NAME)).unwrap(),
        format!("{}\n", host_link::RW_SRC_LINE).into_bytes()
    );
    assert_eq!(
        std::fs::read_link(rw.join(host_link::RW_SYM_NAME)).unwrap(),
        std::path::Path::new(host_link::RW_SRC_NAME)
    );
    // mount 報告は従来どおり読め、link 行は報告として読まれない。
    let reports: Vec<_> = log
        .lines()
        .filter_map(|l| parse_report_line(l.as_bytes()))
        .collect();
    assert_eq!(reports.len(), 1);
}

#[cfg(unix)]
#[test]
fn mac1_sec4_missing_link_output_is_accepted_by_host_log_parser() {
    let t = Tmp::new("link-missing");
    let (ro, rw) = link_fixture(&t);
    let both = link::LinkPlan {
        ro: link::SharePlan::Missing,
        rw: link::SharePlan::Missing,
    };
    let parsed = host_link::parse_link_log(link_log(both, &ro, &rw));
    assert_eq!(
        parsed.lines,
        vec![
            "share=ro op=mount result=missing".to_string(),
            "share=rw op=mount result=missing".to_string(),
        ]
    );
    assert!(parsed.done && !parsed.invalid);
    assert_eq!(std::fs::read_dir(&rw).unwrap().count(), 0);
}

/// ホストが付けた予約キーだけで観測モードが有効になり、付けなければ Absent のまま。io 用のモードとは排他。
#[cfg(unix)]
#[test]
fn mac1_sec4_host_effective_cmdline_enables_link_only_when_requested() {
    use fandhe_container_platform_macos::guest_mount::GuestTestMode;
    let t = Tmp::new("link-cmdline");
    let (ro, rw) = link_fixture(&t);
    let off = link_specs(&t, &ro, &rw);
    let off_cmdline = off.effective_cmdline().unwrap();
    assert_eq!(decode_test_mode(off_cmdline.as_str()), TestMode::Absent);
    let on_cmdline = off
        .with_guest_test(GuestTestMode::VirtiofsLink)
        .effective_cmdline()
        .unwrap();
    assert_eq!(
        decode_test_mode(on_cmdline.as_str()),
        TestMode::VirtiofsLink
    );
    let d = decode_all(on_cmdline.as_str()).unwrap();
    assert_eq!(d.len(), 2);
    assert_eq!(
        (d[0].tag.as_str(), d[0].mount_point.as_str(), d[0].access),
        (link::RO_TAG, link::RO_MOUNT, Access::ReadOnly)
    );
    assert_eq!(
        (d[1].tag.as_str(), d[1].mount_point.as_str(), d[1].access),
        (link::RW_TAG, link::RW_MOUNT, Access::ReadWrite)
    );
    assert_eq!(
        host::parse_directives(on_cmdline.as_str()).unwrap().len(),
        2
    );
}
