//! 試験用の virtiofs プローブ（MAC-1・IO-5・TASK-65.4 追補・#1876）。
//!
//! ホストの結合試験 `platform-macos/tests/virtiofs_io.rs`（macOS 実機）が、ゲストの共有 `/mnt/fandhe/io`
//! （tag `fandhe-io`・RW）への read / readdir / write の疎通を確かめるために、init が hvc0 へ出す行を作る。
//! 行の形・名前空間・順序の SSOT はホスト側 `guest_probe` で、`tests/contract.rs` が往復を照合する。
//! 呼び出し元は `init::run`（ready の後に 1 回）。OS 非依存で、root を引数に取るためホストの一時
//! ディレクトリで 3 OS とも実 FS を使って試験できる。
//!
//! # 起動条件（本番の起動では走らない）
//!
//! 次の両方が成り立つときだけ走らせる。どちらか欠ければ何も出さず、キーが無い起動の出力は従来と同一。
//!
//! 1. コマンドラインに予約キー `fandhe.guest-test=virtiofs-io` のトークンがちょうど 1 個ある。ホストの
//!    `reject_reserved_keys` が `fandhe.` 始まりの利用者指定を拒否するため、利用者は注入できず、有効に
//!    できるのはホストのコードが `VmConfigSpec::with_guest_test` を呼んだときだけ。未知の値・重複は
//!    fail-closed でプローブを走らせない（[`TestMode::Invalid`]）。
//! 2. 指示に tag `fandhe-io`・mount point `/mnt/fandhe/io`・`rw` があり、その mount が実際に成功した
//!    （多重防御。利用者データの共有へ 4096 行を書かないため）。
//!
//! 1 が成り立ち 2 が成り立たないときは、共有へ一切触れず全 op の `result=error` と `done` を出す。
//! ホストが期限切れを待たず、理由の分かる失敗で落ちるようにするため。
//!
//! # 出力順
//!
//! mount 報告 → 起動完了マーカー → プローブ行（read → readdir → write → done）。op ごとに必ず 1 行だけ出す。
//!
//! # 安全性
//!
//! 共有の内容は untrusted。read は 257 バイトまで、readdir は件数上限つきで読み、行は検証済みの型
//! （`ProbeValue`・`ProbeEntries`）でしか作れない。書き込み先は `out/write.txt` の 1 つだけで、
//! `create_new`（`O_EXCL`）で開くため既存のファイルや symlink を辿らない。FS 操作の期限（REPAIR-5）は
//! ホスト側の `FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS` が担う（PID 1 にスレッドを足さない）。
//!
//! # 他のモード
//!
//! symlink・ハードリンクの観測モード `virtiofs-link` は [`TestMode::VirtiofsLink`] で、行の生成は
//! [`crate::link_probe`]（#1877）。両モードは値が排他（トークンは 1 個）で、同時には走らない。

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::directive::Access;
use crate::process::ProcessOutcome;
use crate::report::{MAX_PROBE_LINE_BYTES, ProbeEntries, ProbeOp, ProbeValue, ReportLine};

/// 試験モードの指示トークンのキー（`=` まで）。ホストの `guest_mount::GUEST_TEST_KEY` と同値。
pub const TEST_KEY: &str = "fandhe.guest-test=";
/// virtiofs-io モードの値。ホストの `GuestTestMode::VirtiofsIo.token()` と同値。
pub const TOKEN_VIRTIOFS_IO: &str = "virtiofs-io";
/// virtiofs-link モードの値。ホストの `GuestTestMode::VirtiofsLink.token()` と同値。
pub const TOKEN_VIRTIOFS_LINK: &str = "virtiofs-link";
/// プローブ用の共有タグ。ホストの `guest_probe::SHARE_TAG` と同値。
pub const SHARE_TAG: &str = "fandhe-io";
/// プローブ用共有のゲスト内 mount point。ホストの `guest_probe::GUEST_MOUNT` と同値。
pub const GUEST_MOUNT: &str = "/mnt/fandhe/io";
/// `out/write.txt` に書く 1 行。ホストの `guest_probe::WRITE_LINE` と同値。
pub const WRITE_LINE: &str = "fandhe-virtiofs-write-v1";
/// `out/write.txt` に書く行数。ホストの `guest_probe::WRITE_LINES` と同値。
pub const WRITE_LINES: usize = 4096;
/// read で共有から読む最大バイト数（1 行の上限と同じ。これより大きくは読まない）。
pub const MAX_PROBE_READ_BYTES: usize = MAX_PROBE_LINE_BYTES;
/// readdir で受け付ける最大件数（超えたら error）。
pub const MAX_PROBE_READDIR_ENTRIES: usize = 32;

/// コマンドラインから復号した試験モード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestMode {
    /// キーが無い（本番の起動）。
    Absent,
    /// virtiofs-io のプローブを要求している。
    VirtiofsIo,
    /// virtiofs の symlink・ハードリンクの観測を要求している（[`crate::link_probe`]。#1877）。
    VirtiofsLink,
    /// キーはあるが値が未知、またはトークンが 2 個以上（fail-closed でプローブを走らせない）。
    Invalid,
}

/// コマンドラインの試験モードを復号する（`/proc/cmdline` は untrusted）。
pub fn decode_test_mode(cmdline: &str) -> TestMode {
    let mut values = cmdline
        .split_ascii_whitespace()
        .filter_map(|t| t.strip_prefix(TEST_KEY));
    match (values.next(), values.next()) {
        (None, _) => TestMode::Absent,
        (Some(TOKEN_VIRTIOFS_IO), None) => TestMode::VirtiofsIo,
        (Some(TOKEN_VIRTIOFS_LINK), None) => TestMode::VirtiofsLink,
        _ => TestMode::Invalid,
    }
}

/// プローブの実行計画。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePlan {
    /// 共有が mount 済みで、実際に read / readdir / write を行う。
    Run,
    /// 共有の mount が成立していない。共有へ触れず全 op を error で報告する。
    MountMissing,
}

/// 起動条件（キーと mount の AND）から計画を決める。`None` なら何も出さない。
pub fn probe_plan(mode: TestMode, outcome: &ProcessOutcome) -> Option<ProbePlan> {
    match mode {
        // virtiofs-link の観測は `link_probe::link_plan` が担う（io のプローブは走らせない）。
        TestMode::Absent | TestMode::Invalid | TestMode::VirtiofsLink => None,
        TestMode::VirtiofsIo => {
            let mounted = outcome.mounted_directives.iter().any(|d| {
                d.tag.as_str() == SHARE_TAG
                    && d.mount_point.as_str() == GUEST_MOUNT
                    && d.access == Access::ReadWrite
            });
            Some(if mounted {
                ProbePlan::Run
            } else {
                ProbePlan::MountMissing
            })
        }
    }
}

/// 計画に従ってプローブ行を `emit` へ渡す（op ごとに 1 行・最後に done）。`root` は共有の mount point。
pub fn run_virtiofs_io(plan: ProbePlan, root: &Path, emit: &mut dyn FnMut(ReportLine)) {
    match plan {
        ProbePlan::MountMissing => {
            for op in [ProbeOp::Read, ProbeOp::Readdir, ProbeOp::Write] {
                emit(ReportLine::probe_error(op));
            }
        }
        ProbePlan::Run => {
            emit(probe_read(root));
            emit(probe_readdir(root));
            emit(probe_write(root));
        }
    }
    emit(ReportLine::probe_done());
}

fn probe_read(root: &Path) -> ReportLine {
    read_first_line(&root.join("in").join("read.txt"))
        .and_then(|s| ProbeValue::try_new(&s))
        .map_or_else(
            || ReportLine::probe_error(ProbeOp::Read),
            |v| ReportLine::probe_read(&v),
        )
}

/// 先頭の 1 行を上限つきで読む。改行が無いまま上限を超える場合・非 UTF-8 は `None`。
fn read_first_line(path: &Path) -> Option<String> {
    let mut buf = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_PROBE_READ_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .ok()?;
    let line = match buf.iter().position(|b| *b == b'\n') {
        Some(i) => buf.get(..i)?,
        None if buf.len() <= MAX_PROBE_READ_BYTES => buf.as_slice(),
        None => return None,
    };
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    String::from_utf8(line.to_vec()).ok()
}

fn probe_readdir(root: &Path) -> ReportLine {
    list_names(&root.join("in").join("dir"))
        .and_then(|names| ProbeEntries::try_new(&names))
        .map_or_else(
            || ReportLine::probe_error(ProbeOp::Readdir),
            |e| ReportLine::probe_readdir(&e),
        )
}

/// 名前を辞書順で返す（決定的にする）。件数超過・非 UTF-8 の名前は `None`。
fn list_names(dir: &Path) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for ent in fs::read_dir(dir).ok()?.take(MAX_PROBE_READDIR_ENTRIES + 1) {
        names.push(ent.ok()?.file_name().into_string().ok()?);
    }
    if names.len() > MAX_PROBE_READDIR_ENTRIES {
        return None;
    }
    names.sort();
    Some(names)
}

fn probe_write(root: &Path) -> ReportLine {
    if write_file(&root.join("out").join("write.txt")).is_ok() {
        ReportLine::probe_write_done()
    } else {
        ReportLine::probe_error(ProbeOp::Write)
    }
}

/// 4096 行を書いて `sync_all`（`FUSE_FSYNC`）まで行う。`create_new` で既存・symlink を拒否する。
/// ディレクトリの fsync は行わない（ホストは VM を停止してから検証する）。
fn write_file(path: &Path) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    let data = format!("{WRITE_LINE}\n").repeat(WRITE_LINES);
    f.write_all(data.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive::{Directive, MountPoint, Tag};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// テストごとの一時ディレクトリ（Drop で削除）。
    struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);
    impl Tmp {
        fn new() -> Self {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("fandhe-guest-probe-{}-{n}", std::process::id()));
            Self::at(p)
        }
        /// 指定パスを第 1 候補に排他作成する。残骸は消さず別名で作る（REPAIR-12・#3475）。
        fn at(p: PathBuf) -> Self {
            let root = crate::test_root::test_root_at(p);
            Self(root.to_path_buf(), root)
        }
        fn layout(&self) {
            fs::create_dir_all(self.0.join("in").join("dir")).unwrap();
            fs::create_dir_all(self.0.join("out")).unwrap();
            fs::write(self.0.join("in").join("read.txt"), "tok-1\nsecond\n").unwrap();
            for n in ["b-1", "a-1", "c-1"] {
                fs::write(self.0.join("in").join("dir").join(n), "x").unwrap();
            }
        }
    }
    /// MAC-1・REPAIR-12・#3475: 残骸（古い `out/` の中身）があっても消さず別名で作られ、
    /// drop 後は別名だけが消えて残骸は無傷で残る。
    #[test]
    fn mac1_repair12_tmp_leaves_stale_residue_untouched() {
        let parent = Tmp::new();
        let p = parent.0.join("stale");
        fs::create_dir_all(p.join("out")).unwrap();
        fs::write(p.join("out").join("stale.txt"), "old").unwrap();
        let rp;
        {
            let t = Tmp::at(p.clone());
            rp = t.0.clone();
            assert_ne!(t.0, p);
            assert_eq!(fs::read_dir(&t.0).unwrap().count(), 0);
        }
        assert!(!rp.exists());
        assert_eq!(fs::read(p.join("out").join("stale.txt")).unwrap(), b"old");
    }

    fn run(plan: ProbePlan, root: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        run_virtiofs_io(plan, root, &mut |l| lines.push(l.as_str().to_string()));
        lines
    }

    const P: &str = "fandhe-guest-test: virtiofs-io v1 ";

    /// MAC-1・IO-5・#1876: 正常系の出力行は完全一致し、write は 4096 行を書く。
    #[test]
    fn mac1_io5_probe_run_emits_exact_lines_and_writes_file() {
        let t = Tmp::new();
        t.layout();
        assert_eq!(
            run(ProbePlan::Run, &t.0),
            vec![
                format!("{P}op=read value=tok-1"),
                format!("{P}op=readdir entries=a-1,b-1,c-1"),
                format!("{P}op=write result=done"),
                format!("{P}done"),
            ]
        );
        let written = fs::read(t.0.join("out").join("write.txt")).unwrap();
        assert_eq!(
            written,
            format!("{WRITE_LINE}\n").repeat(WRITE_LINES).into_bytes()
        );
    }

    /// MAC-1・IO-5・#1876: `in/` が無ければ read と readdir が error で、write は独立に成功する。
    #[test]
    fn mac1_io5_probe_missing_input_reports_errors_per_op() {
        let t = Tmp::new();
        fs::create_dir_all(t.0.join("out")).unwrap();
        assert_eq!(
            run(ProbePlan::Run, &t.0),
            vec![
                format!("{P}op=read result=error"),
                format!("{P}op=readdir result=error"),
                format!("{P}op=write result=done"),
                format!("{P}done"),
            ]
        );
    }

    /// MAC-1・IO-5・#1876: 既存の `out/write.txt`・symlink は拒否し、リンク先を書き換えない。
    #[test]
    fn mac1_io5_probe_write_refuses_existing_file_and_symlink() {
        let t = Tmp::new();
        t.layout();
        fs::write(t.0.join("out").join("write.txt"), "old").unwrap();
        let lines = run(ProbePlan::Run, &t.0);
        assert_eq!(
            lines.get(2).map(String::as_str),
            Some(format!("{P}op=write result=error").as_str())
        );
        assert_eq!(fs::read(t.0.join("out").join("write.txt")).unwrap(), b"old");
        #[cfg(unix)]
        {
            let t2 = Tmp::new();
            t2.layout();
            let target = t2.0.join("target.txt");
            fs::write(&target, "keep").unwrap();
            std::os::unix::fs::symlink(&target, t2.0.join("out").join("write.txt")).unwrap();
            let lines = run(ProbePlan::Run, &t2.0);
            assert_eq!(
                lines.get(2).map(String::as_str),
                Some(format!("{P}op=write result=error").as_str())
            );
            assert_eq!(fs::read(&target).unwrap(), b"keep");
        }
    }

    /// MAC-1・IO-5・#1876: read の入力が不正（空・制御文字・上限超過・改行なしの長大）なら error。
    #[test]
    fn mac1_io5_probe_read_rejects_bad_first_line() {
        let long = "a".repeat(300);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty first line", b"\nx\n".to_vec()),
            ("empty file", Vec::new()),
            ("control char", b"a\x1b[2Jb\n".to_vec()),
            ("non utf8", vec![0xff, b'\n']),
            ("too long with newline", format!("{long}\n").into_bytes()),
            ("too long no newline", long.clone().into_bytes()),
        ];
        for (name, bytes) in cases {
            let t = Tmp::new();
            t.layout();
            fs::write(t.0.join("in").join("read.txt"), &bytes).unwrap();
            let lines = run(ProbePlan::Run, &t.0);
            assert_eq!(
                lines.first().map(String::as_str),
                Some(format!("{P}op=read result=error").as_str()),
                "{name}"
            );
        }
        // CRLF と、改行なしで EOF に達する短い値は受理する。
        for (bytes, want) in [(&b"v1\r\nx"[..], "v1"), (&b"v2"[..], "v2")] {
            let t = Tmp::new();
            t.layout();
            fs::write(t.0.join("in").join("read.txt"), bytes).unwrap();
            let lines = run(ProbePlan::Run, &t.0);
            assert_eq!(
                lines.first().map(String::as_str),
                Some(format!("{P}op=read value={want}").as_str())
            );
        }
    }

    /// MAC-1・IO-5・#1876: readdir は件数超過・`,` を含む名前を error にする。
    #[test]
    fn mac1_io5_probe_readdir_rejects_too_many_and_comma() {
        let t = Tmp::new();
        t.layout();
        for i in 0..=MAX_PROBE_READDIR_ENTRIES {
            fs::write(t.0.join("in").join("dir").join(format!("f{i:02}")), "").unwrap();
        }
        let lines = run(ProbePlan::Run, &t.0);
        assert_eq!(
            lines.get(1).map(String::as_str),
            Some(format!("{P}op=readdir result=error").as_str())
        );
        let t = Tmp::new();
        t.layout();
        fs::write(t.0.join("in").join("dir").join("x,y"), "").unwrap();
        let lines = run(ProbePlan::Run, &t.0);
        assert_eq!(
            lines.get(1).map(String::as_str),
            Some(format!("{P}op=readdir result=error").as_str())
        );
    }

    /// MAC-1・IO-5・#1876: mount が成立していなければ共有へ触れず 3 つの error と done を出す。
    #[test]
    fn mac1_io5_probe_mount_missing_never_touches_share() {
        let t = Tmp::new();
        t.layout();
        assert_eq!(
            run(ProbePlan::MountMissing, &t.0),
            vec![
                format!("{P}op=read result=error"),
                format!("{P}op=readdir result=error"),
                format!("{P}op=write result=error"),
                format!("{P}done"),
            ]
        );
        assert!(!t.0.join("out").join("write.txt").exists());
    }

    /// MAC-1・IO-5・#1876: キーが無い・未知の値・トークンが 2 個ならプローブを走らせない。
    #[test]
    fn mac1_io5_decode_test_mode_is_fail_closed() {
        assert_eq!(decode_test_mode(""), TestMode::Absent);
        assert_eq!(decode_test_mode("console=hvc0 quiet\n"), TestMode::Absent);
        assert_eq!(
            decode_test_mode("console=hvc0 fandhe.guest-test=virtiofs-io\n"),
            TestMode::VirtiofsIo
        );
        for bad in [
            "fandhe.guest-test=",
            "fandhe.guest-test=other",
            "fandhe.guest-test=virtiofs-io fandhe.guest-test=virtiofs-io",
            "fandhe.guest-test=virtiofs-io fandhe.guest-test=other",
            "fandhe.guest-test=virtiofs-io2",
            "fandhe.guest-test=virtiofs-io fandhe.guest-test=virtiofs-link",
            "fandhe.guest-test=virtiofs-link fandhe.guest-test=virtiofs-link",
            "fandhe.guest-test=virtiofs-linkx",
        ] {
            assert_eq!(decode_test_mode(bad), TestMode::Invalid, "{bad}");
        }
        assert_eq!(
            decode_test_mode("console=hvc0 fandhe.guest-test=virtiofs-link\n"),
            TestMode::VirtiofsLink
        );
        // キー名の一部だけが似ているトークンは無視する。
        assert_eq!(
            decode_test_mode("xfandhe.guest-test=virtiofs-io"),
            TestMode::Absent
        );
    }

    fn outcome(directives: &[(&str, &str, Access)]) -> ProcessOutcome {
        ProcessOutcome {
            mounted: directives.len(),
            mounted_directives: directives
                .iter()
                .map(|(t, m, a)| Directive {
                    tag: Tag::try_new(t).unwrap(),
                    mount_point: MountPoint::try_new(m).unwrap(),
                    access: *a,
                })
                .collect(),
            failed: 0,
            rejected: None,
            rejected_reports: 0,
        }
    }

    /// MAC-1・IO-5・#1876: 起動条件はキーと mount 成功の AND で、RO・別 mount point・別 tag は不成立。
    #[test]
    fn mac1_io5_probe_plan_requires_key_and_rw_mount() {
        use Access::{ReadOnly, ReadWrite};
        let ok = outcome(&[(SHARE_TAG, GUEST_MOUNT, ReadWrite)]);
        assert_eq!(probe_plan(TestMode::VirtiofsIo, &ok), Some(ProbePlan::Run));
        assert_eq!(probe_plan(TestMode::Absent, &ok), None);
        assert_eq!(probe_plan(TestMode::Invalid, &ok), None);
        assert_eq!(probe_plan(TestMode::VirtiofsLink, &ok), None);
        for bad in [
            outcome(&[]),
            outcome(&[(SHARE_TAG, GUEST_MOUNT, ReadOnly)]),
            outcome(&[(SHARE_TAG, "/mnt/fandhe/other", ReadWrite)]),
            outcome(&[("other", GUEST_MOUNT, ReadWrite)]),
        ] {
            assert_eq!(
                probe_plan(TestMode::VirtiofsIo, &bad),
                Some(ProbePlan::MountMissing)
            );
        }
    }
}
