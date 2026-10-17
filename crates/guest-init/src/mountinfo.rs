//! `/proc/self/mountinfo` の解析による `/dev` の硬化状態の確認（MAC-1・TASK-64 追補・#2139）。
//!
//! `init`（Linux）が `/dev` への devtmpfs の mount で `EBUSY` を受けたとき（既に mount 済み）に呼ぶ。
//! init が付ける `nosuid`・`noexec` が既存の mount に付いていなければ、成功扱いにせず停止させるための判定で、
//! 解析は OS に依らない純粋関数にして 3 OS の単体テストで照合する。
//!
//! 入力はカーネルの出力だが外部入力として扱い、添字アクセス・`unwrap` を使わない。
//! 行の書式は `id parent maj:min root mountpoint options [optional...] - fstype source superopts`。
//! mount point 中の空白等は `\040` 形式でエスケープされるが、比較対象の `/dev` には現れないため影響しない。

/// 読み取る mountinfo の最大バイト数（確保前に上限で抑える。超過は `E2BIG` で停止）。
pub const MAX_MOUNTINFO_BYTES: u64 = 65536;

/// `/dev` が期待どおりでない理由（真偽値で済ませず拡張できる形にする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevMountCheck {
    /// mount point に一致する行が無い。
    NotFound,
    /// 行の書式が解釈できない（`-` 区切りやフィールドの欠落）。
    Malformed,
    /// fstype が `devtmpfs` でない。
    WrongFsType,
    /// 必須の mount オプション（`nosuid`・`noexec`）が付いていない。
    MissingOption(&'static str),
}

/// `mount_point` の最上位の mount が `devtmpfs` で、`nosuid` と `noexec` を持つか確かめる。
///
/// 同じ mount point に複数の行があるときは最後の行（最上位）を採る。オプションは `,` 区切りの
/// トークンとの完全一致で照合する（`nosuidx` を `nosuid` と数えない）。
pub fn check_dev_hardened(mountinfo: &str, mount_point: &str) -> Result<(), DevMountCheck> {
    let line = mountinfo
        .lines()
        .rfind(|l| l.split(' ').nth(4) == Some(mount_point))
        .ok_or(DevMountCheck::NotFound)?;
    let mut fields = line.split(' ');
    let options = fields.nth(5).ok_or(DevMountCheck::Malformed)?;
    let fstype = fields
        .skip_while(|f| *f != "-")
        .nth(1)
        .ok_or(DevMountCheck::Malformed)?;
    if fstype != "devtmpfs" {
        return Err(DevMountCheck::WrongFsType);
    }
    for required in ["nosuid", "noexec"] {
        if !options.split(',').any(|o| o == required) {
            return Err(DevMountCheck::MissingOption(required));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmdline::{CmdlineError, read_bounded};

    fn line(mp: &str, opts: &str, rest: &str) -> String {
        format!("22 1 0:6 / {mp} {opts} {rest}\n")
    }

    #[test]
    fn mac1_hardened_devtmpfs_is_accepted() {
        let t = line(
            "/dev",
            "rw,nosuid,noexec,relatime",
            "- devtmpfs devtmpfs rw",
        );
        assert_eq!(check_dev_hardened(&t, "/dev"), Ok(()));
    }

    #[test]
    fn mac1_kernel_automount_without_flags_is_rejected() {
        let t = line("/dev", "rw,relatime", "- devtmpfs devtmpfs rw");
        assert_eq!(
            check_dev_hardened(&t, "/dev"),
            Err(DevMountCheck::MissingOption("nosuid"))
        );
        let t = line("/dev", "rw,nosuid,relatime", "- devtmpfs devtmpfs rw");
        assert_eq!(
            check_dev_hardened(&t, "/dev"),
            Err(DevMountCheck::MissingOption("noexec"))
        );
    }

    #[test]
    fn mac1_option_match_is_exact_token() {
        let t = line("/dev", "rw,nosuidx,noexec", "- devtmpfs devtmpfs rw");
        assert_eq!(
            check_dev_hardened(&t, "/dev"),
            Err(DevMountCheck::MissingOption("nosuid"))
        );
    }

    #[test]
    fn mac1_wrong_fstype_is_rejected() {
        let t = line("/dev", "rw,nosuid,noexec", "- tmpfs tmpfs rw");
        assert_eq!(
            check_dev_hardened(&t, "/dev"),
            Err(DevMountCheck::WrongFsType)
        );
    }

    #[test]
    fn mac1_topmost_mount_wins() {
        let good = line("/dev", "rw,nosuid,noexec", "- devtmpfs devtmpfs rw");
        let bad = line("/dev", "rw,nosuid,noexec", "- tmpfs tmpfs rw");
        assert_eq!(
            check_dev_hardened(&format!("{good}{bad}"), "/dev"),
            Err(DevMountCheck::WrongFsType)
        );
        assert_eq!(check_dev_hardened(&format!("{bad}{good}"), "/dev"), Ok(()));
    }

    #[test]
    fn mac1_missing_or_malformed_lines() {
        let other = line("/dev/pts", "rw,nosuid,noexec", "- devpts devpts rw");
        assert_eq!(
            check_dev_hardened(&other, "/dev"),
            Err(DevMountCheck::NotFound)
        );
        assert_eq!(check_dev_hardened("", "/dev"), Err(DevMountCheck::NotFound));
        let no_sep = line("/dev", "rw,nosuid,noexec", "devtmpfs devtmpfs rw");
        assert_eq!(
            check_dev_hardened(&no_sep, "/dev"),
            Err(DevMountCheck::Malformed)
        );
        assert_eq!(
            check_dev_hardened("22 1 0:6 / /dev", "/dev"),
            Err(DevMountCheck::Malformed)
        );
    }

    #[test]
    fn mac1_optional_fields_do_not_confuse_fstype() {
        let t = line(
            "/dev",
            "rw,nosuid,noexec",
            "shared:1 master:2 - devtmpfs devtmpfs rw",
        );
        assert_eq!(check_dev_hardened(&t, "/dev"), Ok(()));
    }

    #[test]
    fn mac1_oversized_mountinfo_maps_to_e2big() {
        let n = usize::try_from(MAX_MOUNTINFO_BYTES).unwrap() + 1;
        let data = vec![b'a'; n];
        let e = read_bounded(&data[..], MAX_MOUNTINFO_BYTES).unwrap_err();
        assert!(matches!(e, CmdlineError::TooLong));
        assert_eq!(e.errno().get(), 7);
    }
}
