//! プロセスの同一性（pid・開始時刻・boot id）の解析と、pidfd を先に取ったうえでの照合
//! （NET-5・NET-7・REPAIR-2・REPAIR-5・SEC-1・#3070。設計は `docs/design/network-wiring.md` の D11）。
//!
//! # 役割と呼び出し文脈
//! `dns_helper::detach` の停止・回収が、記録（`dns-helper`）の pid が「記録した時のプロセス」を指すかを確かめるために
//! 使う。pid は再利用されるため、`/proc/<pid>/stat` の starttime（起動からのクロック数）と
//! `/proc/sys/kernel/random/boot_id`（再起動をまたぐ starttime の衝突を除く）を組にして同一性とする。
//! 解析（[`parse_stat_start_time`]・[`BootId`]）は OS 非依存の純関数で、`/proc` の読み取りと pidfd の照合は
//! Linux 限定。
//!
//! # 安全性
//! 外部入力（`/proc` の中身・ヘルパーが返す識別行・記録ファイル）は、読み込みの上限を超えたら確保の前に拒否し、
//! 添字アクセス・`unwrap` を使わず `get` / `parse` / checked 演算で解析する。

use std::fmt;

use crate::error::{NetError, NetErrorCode};

/// `/proc/<pid>/stat` の読み込み上限（comm は最大 15 バイトで、通常は数百バイト）。
pub const PROC_STAT_MAX_BYTES: usize = 4096;
/// boot id（UUID の文字列表現）の文字数。
pub const BOOT_ID_LEN: usize = 36;

fn bad(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// `/proc/sys/kernel/random/boot_id` の値（小文字 16 進の UUID 文字列。36 文字）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootId(String);

impl BootId {
    /// 検証して作る。長さ 36・ハイフンが 8/13/18/23 文字目・残りが小文字 16 進のものだけを受ける
    /// （末尾の改行は呼び出し側が取り除く）。
    pub fn new(s: &str) -> Result<Self, NetError> {
        let ok = s.len() == BOOT_ID_LEN
            && s.bytes().enumerate().all(|(i, b)| match i {
                8 | 13 | 18 | 23 => b == b'-',
                _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            });
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(bad("malformed boot id"))
        }
    }

    /// 文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// プロセスの同一性（記録の照合に使う組）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// プロセス ID（0 は不可）。
    pub pid: u32,
    /// `/proc/<pid>/stat` の starttime（22 番目のフィールド。クロック数）。
    pub start_time_ticks: u64,
    /// boot id。
    pub boot_id: BootId,
}

/// pidfd の指す先と記録の照合結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    /// 記録と同じプロセスで、まだ終了していない。
    Same,
    /// 別のプロセス（開始時刻か boot id が違う）。何も送らない。
    Different,
    /// 既に終了している（`/proc/<pid>` が無い、または pidfd が可読）。
    Gone,
}

/// `/proc/<pid>/stat` の内容から starttime（全体で 22 番目のフィールド）を取り出す。
///
/// comm（2 番目）は括弧で囲まれ、空白・`)`・改行を含みうるため、最後の `)` の後ろを空白で分けて数える
/// （`)` の後ろは state（3 番目）から始まるので、starttime は 20 番目）。上限超過・形式不正は `None`。
pub fn parse_stat_start_time(stat: &[u8]) -> Option<u64> {
    if stat.len() > PROC_STAT_MAX_BYTES {
        return None;
    }
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(stat.get(close.checked_add(1)?..)?).ok()?;
    rest.split_ascii_whitespace().nth(19)?.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::{AsFd as _, BorrowedFd};
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        BOOT_ID_LEN, BootId, PROC_STAT_MAX_BYTES, ProcessIdentity, Verify, bad,
        parse_stat_start_time,
    };
    use crate::error::{NetError, NetErrorCode};
    use crate::sys::{self, Deadline, Readiness};

    /// ファイルを `max` バイトまで読む。超えたら `DataLoss`（確保の前に拒否する）。`NotFound` はそのまま返す。
    pub(crate) fn read_limited(path: PathBuf, max: usize) -> Result<Vec<u8>, NetError> {
        let f = File::open(&path).map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                NetErrorCode::NotFound
            } else {
                NetErrorCode::Internal
            };
            NetError::new(code, "cannot read process information")
        })?;
        let mut buf = Vec::new();
        let limit = u64::try_from(max).map_or(u64::MAX, |m| m.saturating_add(1));
        f.take(limit).read_to_end(&mut buf).map_err(|_| {
            NetError::new(NetErrorCode::Internal, "cannot read process information")
        })?;
        if buf.len() > max {
            return Err(bad("process information exceeds the size limit"));
        }
        Ok(buf)
    }

    /// 現在の boot id を読む。
    pub fn read_boot_id() -> Result<BootId, NetError> {
        let raw = read_limited(
            PathBuf::from("/proc/sys/kernel/random/boot_id"),
            BOOT_ID_LEN + 1,
        )?;
        let s = std::str::from_utf8(&raw).map_err(|_| bad("malformed boot id"))?;
        BootId::new(s.strip_suffix('\n').unwrap_or(s))
    }

    /// `pid` の starttime を読む。プロセスが無ければ `NotFound`。
    pub fn read_start_time(pid: u32) -> Result<u64, NetError> {
        let raw = read_limited(
            PathBuf::from(format!("/proc/{pid}/stat")),
            PROC_STAT_MAX_BYTES,
        )?;
        parse_stat_start_time(&raw).ok_or_else(|| bad("malformed process stat"))
    }

    /// `pid` の同一性を読む。プロセスが無ければ `NotFound`。
    pub fn read_identity(pid: u32) -> Result<ProcessIdentity, NetError> {
        Ok(ProcessIdentity {
            pid,
            start_time_ticks: read_start_time(pid)?,
            boot_id: read_boot_id()?,
        })
    }

    /// 自プロセスの同一性を読む。
    pub fn read_self_identity() -> Result<ProcessIdentity, NetError> {
        read_identity(std::process::id())
    }

    /// pidfd を先に取った後で、`expected` と照合する。
    ///
    /// 順序: `/proc/<pid>/stat` と boot id を読んで比べ、続けて pidfd の可読性（終了）を期限 0 で確かめる。
    /// 読んでいる間に終了と pid の再利用が起きても、開始時刻が変わるか pidfd が可読になるため `Same` にはならない。
    /// 以降の操作（待機・SIGKILL）は呼び出し側がこの pidfd に対して行う。
    pub fn verify_pidfd_target(
        pidfd: BorrowedFd<'_>,
        expected: &ProcessIdentity,
    ) -> Result<Verify, NetError> {
        let current = match read_identity(expected.pid) {
            Ok(c) => c,
            Err(e) if e.code() == NetErrorCode::NotFound => return Ok(Verify::Gone),
            Err(e) => return Err(e),
        };
        if current != *expected {
            return Ok(Verify::Different);
        }
        match sys::wait_readable(pidfd.as_fd(), &Deadline::after(Duration::ZERO)) {
            Ok(Readiness::TimedOut) => Ok(Verify::Same),
            Ok(Readiness::Readable) => Ok(Verify::Gone),
            Ok(Readiness::Exceptional) | Err(_) => Err(NetError::new(
                NetErrorCode::Internal,
                "cannot poll process descriptor",
            )),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::read_limited;
#[cfg(target_os = "linux")]
pub use linux::{
    read_boot_id, read_identity, read_self_identity, read_start_time, verify_pidfd_target,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_with_comm(comm: &str) -> Vec<u8> {
        // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
        // cutime cstime priority nice num_threads itrealvalue starttime ...
        format!(
            "1234 ({comm}) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 987654321 1000 2 18446744073709551615"
        )
        .into_bytes()
    }

    /// NET-7・#3070: starttime（22 番目）を具体値で取り出す。
    #[test]
    fn net7_3070_parse_start_time() {
        assert_eq!(
            parse_stat_start_time(&stat_with_comm("dns-helper")),
            Some(987_654_321)
        );
    }

    /// NET-7・SEC-1・#3070: comm に `)`・空白・改行が入っていても最後の `)` で切って数える。
    #[test]
    fn net7_3070_parse_start_time_hostile_comm() {
        for comm in ["a) S 1 (b", "x y z", "a\nb", ") ) )", ""] {
            assert_eq!(
                parse_stat_start_time(&stat_with_comm(comm)),
                Some(987_654_321),
                "comm {comm:?}"
            );
        }
    }

    /// NET-7・SEC-1・#3070: 不足・非数値・上限超過は拒否する。
    #[test]
    fn net7_3070_parse_start_time_rejects() {
        assert_eq!(parse_stat_start_time(b""), None);
        assert_eq!(parse_stat_start_time(b"1 (x) S 1 2 3"), None);
        let mut bad_num = stat_with_comm("x");
        let s = String::from_utf8(bad_num.clone())
            .expect("utf8")
            .replace("987654321", "98x654321");
        bad_num = s.into_bytes();
        assert_eq!(parse_stat_start_time(&bad_num), None);
        let mut huge = stat_with_comm("x");
        huge.resize(PROC_STAT_MAX_BYTES + 1, b' ');
        assert_eq!(parse_stat_start_time(&huge), None);
    }

    /// NET-7・#3070: boot id は 36 文字の小文字 16 進 UUID だけを受ける。
    #[test]
    fn net7_3070_boot_id_validation() {
        let ok = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
        assert_eq!(BootId::new(ok).expect("ok").as_str(), ok);
        for bad in [
            "",
            "0A1B2C3D-4E5F-6789-ABCD-EF0123456789",
            "0a1b2c3d-4e5f-6789-abcd-ef012345678",
            "0a1b2c3d-4e5f-6789-abcd-ef01234567890",
            "0a1b2c3d4e5f-6789-abcd-ef0123456789-",
            "0a1b2c3d-4e5f-6789-abcd-ef012345678g",
            "0a1b2c3d-4e5f-6789-abcd-ef0123456789\n",
        ] {
            assert_eq!(
                BootId::new(bad).expect_err(bad).code(),
                NetErrorCode::DataLoss,
                "{bad:?}"
            );
        }
    }

    /// NET-7・#3070: 自プロセスの同一性は読め、開始時刻を変えると別プロセス扱いになる（Linux）。
    #[cfg(target_os = "linux")]
    #[test]
    fn net7_3070_verify_self_and_mismatch() {
        use crate::sys::process::pidfd_open;
        use std::os::fd::AsFd as _;
        let me = read_self_identity().expect("self");
        assert_eq!(me.pid, std::process::id());
        let Ok(fd) = pidfd_open(me.pid) else {
            return; // pidfd 非対応のカーネル
        };
        assert_eq!(
            verify_pidfd_target(fd.as_fd(), &me).expect("verify"),
            Verify::Same
        );
        let mut other = me.clone();
        other.start_time_ticks += 1;
        assert_eq!(
            verify_pidfd_target(fd.as_fd(), &other).expect("verify"),
            Verify::Different
        );
        let mut other_boot = me.clone();
        other_boot.boot_id = BootId::new("00000000-0000-0000-0000-000000000000").expect("boot");
        assert_eq!(
            verify_pidfd_target(fd.as_fd(), &other_boot).expect("verify"),
            Verify::Different
        );
        let mut gone = me;
        gone.pid = 0x7fff_fff0;
        assert_eq!(
            verify_pidfd_target(fd.as_fd(), &gone).expect("verify"),
            Verify::Gone
        );
    }
}
