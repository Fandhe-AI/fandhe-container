//! symlink 非追従 open のフラグ値を、検証済みの形で公開する薄い層（SEC-1・REPAIR-4・REPAIR-5）。
//!
//! `O_DIRECTORY` / `O_NOFOLLOW` の値は Linux でもアーキテクチャごとに異なる（arm64 は asm-generic を
//! 上書きしている）。値の SSOT を core の `sys` の定数に一本化するため、呼び出し側（現状は cli の
//! 計測ログ出力。`fandhe-container-cli` の `create_start`）は数値を持たず、本モジュールの
//! [`NofollowOpenFlags`] から用途別に合成済みの値を受け取る。
//!
//! # 契約
//!
//! - [`NofollowOpenFlags::current`] は Linux かつ値を確認済みのアーキテクチャ（x86_64 / aarch64）でのみ
//!   `Some` を返す。それ以外は `None` で、呼び出し側は open を行わず拒否する（fail-closed）。
//! - 返す値は `std::fs::OpenOptions::custom_flags` へ渡す前提で、`O_CLOEXEC` は std が常に付けるため
//!   含めない。
//! - 本モジュールは定数を返すだけで syscall を呼ばず、`unsafe` を含まない。fd 相対の open 処理自体は
//!   呼び出し側が持つ。

/// 検証済みの open フラグの組（アーキテクチャ別の値を `sys` から取り込み済み）。
///
/// 生の `O_*` を呼び出し側で OR させないため、用途ごとに合成済みの値をアクセサで返す。
/// フィールドは非公開で、[`NofollowOpenFlags::current`] 以外では作れない（0 のフラグで open が進む経路を作らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofollowOpenFlags {
    // 非 Linux では `current` が常に `None` でフィールドが読まれないため dead_code を許可する。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    nonblock: i32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    directory_nofollow_nonblock: i32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    path_nofollow: i32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    file_nofollow_nonblock: i32,
}

impl NofollowOpenFlags {
    /// 現在のターゲットで使えるフラグを返す。非 Linux・対応外アーキテクチャでは `None`（fail-closed）。
    #[cfg(target_os = "linux")]
    pub fn current() -> Option<Self> {
        Some(Self {
            nonblock: crate::sys::nonblock_open_flag()?,
            directory_nofollow_nonblock: crate::sys::directory_nofollow_nonblock_open_flags()?,
            path_nofollow: crate::sys::path_nofollow_open_flags()?,
            file_nofollow_nonblock: crate::sys::nofollow_nonblock_open_flags()?,
        })
    }

    /// 非 Linux では open フラグを提供しない（`None`。fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub fn current() -> Option<Self> {
        None
    }

    /// `O_NONBLOCK`。`/proc/self/fd` 経由の開き直し・FIFO の読み手の open で止まらないために使う。
    pub fn nonblock(self) -> i32 {
        self.nonblock
    }

    /// `O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY`。ディレクトリを 1 要素ずつ symlink 非追従で開く。
    pub fn directory_nofollow_nonblock(self) -> i32 {
        self.directory_nofollow_nonblock
    }

    /// `O_PATH | O_NOFOLLOW`。最終要素を副作用なく固定する。
    pub fn path_nofollow(self) -> i32 {
        self.path_nofollow
    }

    /// `O_NONBLOCK | O_NOFOLLOW`。未存在のファイルを排他作成する。
    pub fn file_nofollow_nonblock(self) -> i32 {
        self.file_nofollow_nonblock
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        not(target_os = "linux")
    ))]
    use super::*;

    /// SEC-1: x86_64 の合成済みフラグの具体値。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn sec1_nofollow_open_flags_exact_x86_64() {
        let f = NofollowOpenFlags::current().expect("supported");
        assert_eq!(f.nonblock(), 0o4_000);
        assert_eq!(f.directory_nofollow_nonblock(), 0o604_000);
        assert_eq!(f.path_nofollow(), 0o10_400_000);
        assert_eq!(f.file_nofollow_nonblock(), 0o404_000);
    }

    /// SEC-1: aarch64 の合成済みフラグの具体値（O_DIRECTORY / O_NOFOLLOW は arm64 固有値）。
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn sec1_nofollow_open_flags_exact_aarch64() {
        let f = NofollowOpenFlags::current().expect("supported");
        assert_eq!(f.nonblock(), 0o4_000);
        assert_eq!(f.directory_nofollow_nonblock(), 0o144_000);
        assert_eq!(f.path_nofollow(), 0o10_100_000);
        assert_eq!(f.file_nofollow_nonblock(), 0o104_000);
    }

    /// SEC-1: 非 Linux ではフラグを提供しない（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_nofollow_open_flags_none_off_linux() {
        assert_eq!(NofollowOpenFlags::current(), None);
    }
}
