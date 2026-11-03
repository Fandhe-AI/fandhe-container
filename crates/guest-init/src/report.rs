//! ゲスト → ホストの報告行・診断行・起動完了マーカーの生成（MAC-1・REPAIR-2）。
//!
//! 行は [`ReportLine`] でしか作れず、生の文字列を手で組まない。書式の SSOT はホスト側
//! `guest_mount::parse_report_line`（`tests/contract.rs` が往復を照合する）。出力先は hvc0 で、
//! 呼び出し元は [`crate::process`]・[`crate::probe`] と `init`（Linux）。

use crate::READY_MARKER;
use crate::directive::Tag;

/// 報告行の接頭辞（行頭固定）。
pub const REPORT_PREFIX: &str = "fandhe-guest: virtiofs-mount";
/// プローブ行の名前空間（行頭固定。末尾に空白 1 つ）。ホストの `guest_probe::PROBE_NAMESPACE` と同値。
pub const PROBE_NAMESPACE: &str = "fandhe-guest-test: virtiofs-io ";
/// プローブ行 v1 の接頭辞。ホストの `guest_probe::PROBE_PREFIX` と同値。
pub const PROBE_PREFIX: &str = "fandhe-guest-test: virtiofs-io v1 ";
/// プローブ 1 行の最大バイト数（改行を除く）。ホストの `guest_probe::MAX_PROBE_LINE_BYTES` と同値。
pub const MAX_PROBE_LINE_BYTES: usize = 256;
/// 報告 1 行の最大バイト数（改行を除く）。ホストの `MAX_REPORT_LINE_BYTES` と同値。
pub const MAX_REPORT_LINE_BYTES: usize = 256;

/// 報告に載せる errno（1..=4095。範囲外は `EIO` に丸める）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(u16);

impl Errno {
    /// `E2BIG`（指示の件数超過）。
    pub const E2BIG: Errno = Errno(7);
    /// `EINVAL`（指示の書式不正）。
    pub const EINVAL: Errno = Errno(22);
    /// `ENOTDIR`（mount point が実ディレクトリでない）。
    pub const ENOTDIR: Errno = Errno(20);
    /// `EBUSY`（既に mount 済み。`/dev` の devtmpfs の検査に通らなかった場合の診断に使う）。
    pub const EBUSY: Errno = Errno(16);
    /// `EIO`（errno を取得できない・範囲外の場合の固定値）。
    pub const EIO: Errno = Errno(5);

    /// 生の errno から作る。1..=4095 以外は [`Errno::EIO`] に丸める。
    pub fn new(raw: i32) -> Self {
        match u16::try_from(raw) {
            Ok(n) if (1..=4095).contains(&n) => Self(n),
            _ => Self::EIO,
        }
    }

    /// `std::io::Error` から作る（`raw_os_error` が無ければ `EIO`）。
    pub fn from_io(e: &std::io::Error) -> Self {
        e.raw_os_error().map_or(Self::EIO, Self::new)
    }

    /// 数値。
    pub fn get(self) -> u16 {
        self.0
    }
}

/// 初期化の段階名（診断行に載せる固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStage {
    /// `/dev` の mount。
    Dev,
    /// `/proc` の mount。
    Proc,
    /// `/sys` の mount。
    Sys,
    /// `/proc/cmdline` の読み取り。
    Cmdline,
    /// PID 1 の panic（panic hook が出す。原因は載せない）。
    Panic,
}

impl InitStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Proc => "proc",
            Self::Sys => "sys",
            Self::Cmdline => "cmdline",
            Self::Panic => "panic",
        }
    }
}

/// プローブの操作種別（行の `op=` の固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOp {
    /// `in/read.txt` の読み取り。
    Read,
    /// `in/dir` の列挙。
    Readdir,
    /// `out/write.txt` への書き込み。
    Write,
}

impl ProbeOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Readdir => "readdir",
            Self::Write => "write",
        }
    }
}

/// 行全体が [`MAX_PROBE_LINE_BYTES`] 以下に収まるか（`field` は `value=` / `entries=` の接頭辞）。
fn probe_value_fits(op: ProbeOp, field: &str, value: &str) -> bool {
    let len = PROBE_PREFIX.len() + "op=".len() + op.as_str().len() + 1 + field.len() + value.len();
    len <= MAX_PROBE_LINE_BYTES
}

/// 共有から読んだ値（read の 1 行目）。空・制御文字を含む・行が上限を超える値は作れない。
///
/// 共有の内容は untrusted のため、コンソールへ偽の行や端末制御を注入できない形に限る（REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeValue(String);

impl ProbeValue {
    /// 検証して生成する。不正なら `None`。
    pub fn try_new(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && !s.chars().any(char::is_control)
            && probe_value_fits(ProbeOp::Read, "value=", s);
        ok.then(|| Self(s.to_string()))
    }
}

/// 共有から列挙した名前の並び（readdir）。空・空の名前・`,` や制御文字を含む名前・行が上限を超える並びは作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEntries(String);

impl ProbeEntries {
    /// 検証して生成する（カンマで連結する。並べ替えは呼び出し側が行う）。不正なら `None`。
    pub fn try_new(names: &[String]) -> Option<Self> {
        if names.is_empty()
            || names
                .iter()
                .any(|n| n.is_empty() || n.contains(',') || n.chars().any(char::is_control))
        {
            return None;
        }
        let joined = names.join(",");
        probe_value_fits(ProbeOp::Readdir, "entries=", &joined).then_some(Self(joined))
    }
}

/// 出力する 1 行（改行を含まない、検証済みの文字列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLine(String);

impl ReportLine {
    /// mount 成功の報告。
    pub fn ok(tag: &Tag) -> Self {
        Self(format!("{REPORT_PREFIX} v1 tag={} result=ok", tag.as_str()))
    }

    /// mount 失敗の報告。
    pub fn error(tag: &Tag, errno: Errno) -> Self {
        Self(format!(
            "{REPORT_PREFIX} v1 tag={} result=error errno={}",
            tag.as_str(),
            errno.get()
        ))
    }

    /// 致命的な初期化失敗の診断行（報告行の接頭辞と重ならない）。
    pub fn init_error(stage: InitStage, errno: Errno) -> Self {
        Self(format!(
            "fandhe-guest: init error stage={} errno={}",
            stage.as_str(),
            errno.get()
        ))
    }

    /// 起動完了マーカー。
    pub fn ready() -> Self {
        Self(READY_MARKER.to_string())
    }

    /// プローブ read の成功行。
    pub fn probe_read(value: &ProbeValue) -> Self {
        Self(format!("{PROBE_PREFIX}op=read value={}", value.0))
    }

    /// プローブ readdir の成功行。
    pub fn probe_readdir(entries: &ProbeEntries) -> Self {
        Self(format!("{PROBE_PREFIX}op=readdir entries={}", entries.0))
    }

    /// プローブ write の成功行（sync 後にだけ出す）。
    pub fn probe_write_done() -> Self {
        Self(format!("{PROBE_PREFIX}op=write result=done"))
    }

    /// プローブの失敗行（操作ごとに 1 行だけ出す）。
    pub fn probe_error(op: ProbeOp) -> Self {
        Self(format!("{PROBE_PREFIX}op={} result=error", op.as_str()))
    }

    /// プローブの終端行（全操作の報告後に 1 回だけ出す）。
    pub fn probe_done() -> Self {
        Self(format!("{PROBE_PREFIX}done"))
    }

    /// virtiofs-link の観測行（検証済みの [`crate::link_probe::LinkLine`] から作る。#1877）。
    pub fn from_link(line: crate::link_probe::LinkLine) -> Self {
        Self(line.into_string())
    }

    /// 行の文字列（改行を含まない）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(s: &str) -> Tag {
        Tag::try_new(s).unwrap()
    }

    #[test]
    fn mac1_report_lines_are_exact() {
        assert_eq!(
            ReportLine::ok(&tag("code")).as_str(),
            "fandhe-guest: virtiofs-mount v1 tag=code result=ok"
        );
        assert_eq!(
            ReportLine::error(&tag("code"), Errno::new(2)).as_str(),
            "fandhe-guest: virtiofs-mount v1 tag=code result=error errno=2"
        );
    }

    #[test]
    fn mac1_errno_rounds_out_of_range_to_eio() {
        for raw in [0, -1, 4096, 9999, i32::MAX, i32::MIN] {
            assert_eq!(Errno::new(raw).get(), 5, "{raw}");
        }
        assert_eq!(Errno::new(1).get(), 1);
        assert_eq!(Errno::new(4095).get(), 4095);
        let e = std::io::Error::other("no errno");
        assert_eq!(Errno::from_io(&e).get(), 5);
        assert_eq!(
            Errno::from_io(&std::io::Error::from_raw_os_error(13)).get(),
            13
        );
    }

    #[test]
    fn mac1_longest_line_within_limit() {
        let t = tag(&"t".repeat(35));
        let line = ReportLine::error(&t, Errno::new(4095));
        assert!(line.as_str().len() <= MAX_REPORT_LINE_BYTES);
        assert_eq!(line.as_str().len(), 95);
    }

    /// MAC-1・IO-5・#1876: プローブ行は具体的な文字列で、名前空間・接頭辞と整合する。
    #[test]
    fn mac1_io5_probe_lines_are_exact() {
        let v = ProbeValue::try_new("fandhe-read-1").unwrap();
        assert_eq!(
            ReportLine::probe_read(&v).as_str(),
            "fandhe-guest-test: virtiofs-io v1 op=read value=fandhe-read-1"
        );
        let e = ProbeEntries::try_new(&["a-1".to_string(), "b-1".to_string()]).unwrap();
        assert_eq!(
            ReportLine::probe_readdir(&e).as_str(),
            "fandhe-guest-test: virtiofs-io v1 op=readdir entries=a-1,b-1"
        );
        assert_eq!(
            ReportLine::probe_write_done().as_str(),
            "fandhe-guest-test: virtiofs-io v1 op=write result=done"
        );
        assert_eq!(
            ReportLine::probe_error(ProbeOp::Readdir).as_str(),
            "fandhe-guest-test: virtiofs-io v1 op=readdir result=error"
        );
        assert_eq!(
            ReportLine::probe_done().as_str(),
            "fandhe-guest-test: virtiofs-io v1 done"
        );
        assert!(PROBE_PREFIX.starts_with(PROBE_NAMESPACE));
        assert!(!PROBE_NAMESPACE.starts_with(REPORT_PREFIX));
        assert!(!REPORT_PREFIX.starts_with(PROBE_NAMESPACE));
    }

    /// MAC-1・IO-5・#1876: 行全体がちょうど 256 バイトなら受理し、257 バイトなら拒否する。
    #[test]
    fn mac1_io5_probe_value_boundary_is_256_bytes() {
        let head = PROBE_PREFIX.len() + "op=read value=".len();
        let fit = "a".repeat(MAX_PROBE_LINE_BYTES - head);
        let line = ReportLine::probe_read(&ProbeValue::try_new(&fit).unwrap());
        assert_eq!(line.as_str().len(), 256);
        assert!(ProbeValue::try_new(&format!("{fit}a")).is_none());
        let head = PROBE_PREFIX.len() + "op=readdir entries=".len();
        let fit = "b".repeat(MAX_PROBE_LINE_BYTES - head);
        let line =
            ReportLine::probe_readdir(&ProbeEntries::try_new(std::slice::from_ref(&fit)).unwrap());
        assert_eq!(line.as_str().len(), 256);
        assert!(ProbeEntries::try_new(&[format!("{fit}b")]).is_none());
    }

    /// MAC-1・IO-5・#1876: 空・制御文字・区切りを含む値は行にできない。
    #[test]
    fn mac1_io5_probe_values_reject_empty_and_control() {
        for bad in ["", "a\nb", "a\rb", "a\tb", "a\u{1b}[2J", "\u{7f}"] {
            assert!(ProbeValue::try_new(bad).is_none(), "{bad:?}");
        }
        assert_eq!(
            ProbeValue::try_new("a b").map(|v| v.0),
            Some("a b".to_string())
        );
        assert!(ProbeEntries::try_new(&[]).is_none());
        for bad in ["", "a,b", "a\nb"] {
            assert!(
                ProbeEntries::try_new(&[bad.to_string()]).is_none(),
                "{bad:?}"
            );
        }
        assert!(ProbeEntries::try_new(&["ok".to_string(), String::new()]).is_none());
    }

    #[test]
    fn mac1_init_error_and_ready_do_not_look_like_reports() {
        let diag = ReportLine::init_error(InitStage::Proc, Errno::new(1));
        assert_eq!(diag.as_str(), "fandhe-guest: init error stage=proc errno=1");
        assert!(!diag.as_str().starts_with(REPORT_PREFIX));
        assert!(!ReportLine::ready().as_str().starts_with(REPORT_PREFIX));
    }

    /// MAC-1・#2139: panic と EBUSY の診断行は固定の語彙で、報告行の接頭辞と重ならない。
    #[test]
    fn mac1_panic_and_busy_diagnostics_are_exact() {
        let p = ReportLine::init_error(InitStage::Panic, Errno::EIO);
        assert_eq!(p.as_str(), "fandhe-guest: init error stage=panic errno=5");
        let b = ReportLine::init_error(InitStage::Dev, Errno::EBUSY);
        assert_eq!(b.as_str(), "fandhe-guest: init error stage=dev errno=16");
        assert_eq!(Errno::EBUSY.get(), 16);
        assert!(!p.as_str().starts_with(REPORT_PREFIX));
        assert!(!b.as_str().starts_with(REPORT_PREFIX));
    }
}
