//! 指示の処理（復号 → mount point 作成 → mount → 報告）の段取り（MAC-1・TASK-65.3）。
//!
//! 副作用（ディレクトリ作成・mount・出力）は [`GuestOps`] に切り出し、ホストのテストから fake で駆動する。
//! Linux の実装は `init` が持ち、`sys` の安全なラッパーだけを呼ぶ。呼び出し元は `init::run`。
//!
//! fail-closed: 復号に 1 件でも失敗したら 1 件も mount せず、tag を復元できたものだけ `result=error` を報告する。

use crate::directive::{DecodeError, Directive, MountPoint, decode_all, recoverable_tags};
use crate::report::{Errno, ReportLine};

/// ゲスト固有の副作用の差し替え口。
pub trait GuestOps {
    /// mount point を `/mnt/fandhe` 配下に作る。各要素が実ディレクトリ（symlink でない）であることを保証する。
    fn ensure_mount_point(&mut self, mount_point: &MountPoint) -> Result<(), Errno>;
    /// virtiofs を mount する（tag が source。`ro` は必ず読み取り専用）。
    fn mount_virtiofs(&mut self, directive: &Directive) -> Result<(), Errno>;
    /// 1 行を hvc0 へ出す。失敗は無視してよい（報告先が無く、ホストはタイムアウトで fail-closed になる）。
    fn write_line(&mut self, line: &ReportLine);
}

/// 処理結果の概要（テストと診断用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    /// mount に成功した共有の数。
    pub mounted: usize,
    /// mount に成功した指示（試験用プローブの起動条件の判定に使う。#1876）。
    pub mounted_directives: Vec<Directive>,
    /// mount に失敗した共有の数（復号成功後の失敗）。
    pub failed: usize,
    /// 復号に失敗した場合のエラー（この場合 mount は 0 件）。
    pub rejected: Option<DecodeError>,
    /// 復号失敗後に `result=error` を報告した tag の数。
    pub rejected_reports: usize,
}

/// `cmdline` の指示を処理し、共有ごとに 1 行を報告する。
pub fn process_directives<O: GuestOps>(cmdline: &str, ops: &mut O) -> ProcessOutcome {
    let mut outcome = ProcessOutcome {
        mounted: 0,
        mounted_directives: Vec::new(),
        failed: 0,
        rejected: None,
        rejected_reports: 0,
    };
    match decode_all(cmdline) {
        Ok(directives) => {
            for d in &directives {
                let result = ops
                    .ensure_mount_point(&d.mount_point)
                    .and_then(|()| ops.mount_virtiofs(d));
                match result {
                    Ok(()) => {
                        outcome.mounted += 1;
                        outcome.mounted_directives.push(d.clone());
                        ops.write_line(&ReportLine::ok(&d.tag));
                    }
                    Err(errno) => {
                        outcome.failed += 1;
                        ops.write_line(&ReportLine::error(&d.tag, errno));
                    }
                }
            }
        }
        Err(e) => {
            let errno = match e {
                DecodeError::TooMany => Errno::E2BIG,
                _ => Errno::EINVAL,
            };
            outcome.rejected = Some(e);
            for tag in recoverable_tags(cmdline) {
                ops.write_line(&ReportLine::error(&tag, errno));
                outcome.rejected_reports += 1;
            }
        }
    }
    outcome
}

/// 起動完了マーカーを出す（初期化に成功し、指示の処理を終えた後に 1 回だけ呼ぶ）。
pub fn emit_ready<O: GuestOps>(ops: &mut O) {
    ops.write_line(&ReportLine::ready());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive::Access;

    #[derive(Default)]
    struct Fake {
        events: Vec<String>,
        lines: Vec<String>,
        mount_errno: Option<i32>,
    }

    impl GuestOps for Fake {
        fn ensure_mount_point(&mut self, mp: &MountPoint) -> Result<(), Errno> {
            self.events.push(format!("mkdir {}", mp.as_str()));
            Ok(())
        }
        fn mount_virtiofs(&mut self, d: &Directive) -> Result<(), Errno> {
            let mode = if d.access == Access::ReadOnly {
                "ro"
            } else {
                "rw"
            };
            self.events.push(format!(
                "mount {} {} {mode}",
                d.tag.as_str(),
                d.mount_point.as_str()
            ));
            self.mount_errno.map_or(Ok(()), |e| Err(Errno::new(e)))
        }
        fn write_line(&mut self, line: &ReportLine) {
            self.lines.push(line.as_str().to_string());
        }
    }

    #[test]
    fn mac1_mounts_in_order_and_reports_each() {
        let mut f = Fake::default();
        let out = process_directives(
            "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/b:rw\n",
            &mut f,
        );
        assert_eq!(out.mounted, 2);
        let mounted: Vec<(&str, Access)> = out
            .mounted_directives
            .iter()
            .map(|d| (d.tag.as_str(), d.access))
            .collect();
        assert_eq!(
            mounted,
            vec![("a", Access::ReadOnly), ("b", Access::ReadWrite)]
        );
        assert_eq!(
            f.events,
            vec![
                "mkdir /mnt/fandhe/a",
                "mount a /mnt/fandhe/a ro",
                "mkdir /mnt/fandhe/b",
                "mount b /mnt/fandhe/b rw",
            ]
        );
        assert_eq!(
            f.lines,
            vec![
                "fandhe-guest: virtiofs-mount v1 tag=a result=ok",
                "fandhe-guest: virtiofs-mount v1 tag=b result=ok",
            ]
        );
        emit_ready(&mut f);
        assert_eq!(
            f.lines.last().map(String::as_str),
            Some("fandhe-guest: init ready v1")
        );
    }

    #[test]
    fn mac1_mount_failure_reports_errno() {
        let mut f = Fake {
            mount_errno: Some(2),
            ..Fake::default()
        };
        let out = process_directives("fandhe.virtiofs=a:/mnt/fandhe/a:ro", &mut f);
        assert_eq!((out.mounted, out.failed), (0, 1));
        assert!(out.mounted_directives.is_empty());
        assert_eq!(
            f.lines,
            vec!["fandhe-guest: virtiofs-mount v1 tag=a result=error errno=2"]
        );
    }

    #[test]
    fn mac1_mount_errno_out_of_range_becomes_eio() {
        for raw in [0, 9999] {
            let mut f = Fake {
                mount_errno: Some(raw),
                ..Fake::default()
            };
            process_directives("fandhe.virtiofs=a:/mnt/fandhe/a:ro", &mut f);
            assert_eq!(
                f.lines,
                vec!["fandhe-guest: virtiofs-mount v1 tag=a result=error errno=5"]
            );
        }
    }

    #[test]
    fn mac1_malformed_mounts_nothing_and_reports_recoverable_tags() {
        let mut f = Fake::default();
        // 2 件目が不正。1 件目は妥当でも mount しない（fail-closed）。
        let out = process_directives(
            "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/proc:rw fandhe.virtiofs=!:x",
            &mut f,
        );
        assert!(f.events.is_empty());
        assert_eq!(out.rejected, Some(DecodeError::Malformed { index: 1 }));
        assert_eq!(out.rejected_reports, 2);
        assert_eq!(
            f.lines,
            vec![
                "fandhe-guest: virtiofs-mount v1 tag=a result=error errno=22",
                "fandhe-guest: virtiofs-mount v1 tag=b result=error errno=22",
            ]
        );
    }

    #[test]
    fn mac1_too_many_reports_e2big_for_first_eight_tags() {
        let mut f = Fake::default();
        let cmd: Vec<String> = (0..9)
            .map(|i| format!("fandhe.virtiofs=t{i}:/mnt/fandhe/m{i}:ro"))
            .collect();
        let out = process_directives(&cmd.join(" "), &mut f);
        assert!(f.events.is_empty());
        assert_eq!(out.rejected, Some(DecodeError::TooMany));
        assert_eq!(f.lines.len(), 8);
        assert!(f.lines.iter().all(|l| l.ends_with("result=error errno=7")));
    }

    #[test]
    fn mac1_duplicate_and_overlap_mount_nothing() {
        for cmd in [
            "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=a:/mnt/fandhe/b:ro",
            "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/a/b:ro",
        ] {
            let mut f = Fake::default();
            process_directives(cmd, &mut f);
            assert!(f.events.is_empty(), "{cmd}");
            assert!(f.lines.iter().all(|l| l.ends_with("errno=22")), "{cmd}");
        }
    }

    #[test]
    fn mac1_no_directives_reports_nothing() {
        let mut f = Fake::default();
        let out = process_directives("console=hvc0\n", &mut f);
        assert_eq!((out.mounted, out.failed, out.rejected_reports), (0, 0, 0));
        assert!(f.lines.is_empty() && f.events.is_empty());
    }
}
