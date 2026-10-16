//! ゲスト → ホストの報告行・診断行・起動完了マーカーの生成（MAC-1・REPAIR-2）。
//!
//! 行は [`ReportLine`] でしか作れず、生の文字列を手で組まない。書式の SSOT はホスト側
//! `guest_mount::parse_report_line`（`tests/contract.rs` が往復を照合する）。出力先は hvc0 で、
//! 呼び出し元は [`crate::process`] と `init`（Linux）。

use crate::READY_MARKER;
use crate::directive::Tag;

/// 報告行の接頭辞（行頭固定）。
pub const REPORT_PREFIX: &str = "fandhe-guest: virtiofs-mount";
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
}

impl InitStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Proc => "proc",
            Self::Sys => "sys",
            Self::Cmdline => "cmdline",
        }
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

    #[test]
    fn mac1_init_error_and_ready_do_not_look_like_reports() {
        let diag = ReportLine::init_error(InitStage::Proc, Errno::new(1));
        assert_eq!(diag.as_str(), "fandhe-guest: init error stage=proc errno=1");
        assert!(!diag.as_str().starts_with(REPORT_PREFIX));
        assert!(!ReportLine::ready().as_str().starts_with(REPORT_PREFIX));
    }
}
