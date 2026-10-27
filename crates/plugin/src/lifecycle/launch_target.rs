//! plugin の起動対象 [`PluginLaunchTarget`]（PLUG-11・PLUG-7・REPAIR-1・#1856・TASK-110 追補）。
//!
//! 起動 API（[`super::PluginLaunchSpec`]・[`super::call_once`]・[`super::ResidentPlugin`]・
//! [`super::PluginSession`]）が受け取る唯一の起動対象。パスではなく、信頼性検証（所有者・モード・
//! sha256。TASK-122・PLUG-11）を通した**開いたファイル記述子**を持つ。これにより「検証を通したものだけが
//! 起動される」ことを型で表し、検証から起動までのパス差し替え（TOCTOU）を Linux では防ぐ（#1320 の
//! オーナー判断 2026-10-12）。
//!
//! # 契約
//!
//! - 構築口は [`PluginLaunchTarget::from_verified_file`] のみ。本番で呼んでよいのは core の
//!   `HashVerifiedPluginFile` からの変換 1 か所（#1857。`make check-launch-target`〔`scripts/check-plugin-launch-target-construction.sh`〕が CI で判定する）。
//!   それ以外で呼んでよいのは試験コードだけ。検証そのものは本型では行わない（呼び出し側の責務）。
//!   依存方向（core -> plugin）を保つため、型は本 crate に置き、core 側の型は参照しない。
//! - Linux: 保持した fd の実体を `/proc/self/fd/<N>` 経由で実行する。実行できない場合は
//!   `FailedPrecondition` で失敗し、パスでの起動へ縮退しない（fail-closed）。保持 fd は構築時に必ず
//!   close-on-exec で複製し直す（呼び出し側の fd の状態に依らない）ため、exec 後の plugin には残らない。plugin が見る `argv[0]` は実体の正規パス（`exec_path`）で、
//!   `/proc/<pid>/comm` は fd 番号になる。
//! - Linux 以外の unix（macOS 等）: fd の実体を実行する手段が無いため、実体の正規パス（`exec_path`）で
//!   起動する。ただし spawn の直前（都度起動・常駐の再起動のたび）に、symlink を辿らない `lstat` で
//!   「通常ファイルであり、dev / ino が構築時に保持 fd を `fstat` した値と一致する」ことを確かめる
//!   （#1866）。不一致・不在・非通常ファイル・symlink・stat の失敗はすべて `FailedPrecondition` で、
//!   子は spawn しない（パス起動へ縮退しない）。
//!   - 残余: 確認から `exec` までの短い窓に差し替えられるのは、検証済みの祖先を書き換えられる同じ UID か
//!     root だけで、PLUG-11 の脅威の外である。fd の実体を実行する Linux にはこの窓が無い。
//!   - 保持 fd が元の inode を生かし続けるため、差し替え先が同じ dev / ino を再利用することはない。
//!   - 同一 inode の中身の書き換えは防がない（内容はハッシュ照合の計算時点保証の範囲）。依存する
//!     動的ライブラリがパスで解決される点は Linux と同じで、OS 固有の差ではない。
//! - 非 unix: 起動仕様は構築できるが、listener の bind が `Unimplemented` を返し子は spawn されない。
//! - plugin はネイティブの実行ファイルに限る。`#!` で始まるスクリプトは構築時に拒否する
//!   （解釈系が fd を開き直す経路を作らない）。構築後に同じ inode が `#!` へ書き換えられた場合、
//!   Linux では解釈系が閉じた fd を開けず、`Unavailable`（`plugin exited before connecting`）になる。
//!
//! # 未実装（REPAIR-3）
//!
//! - 検証後の起動と RPC の本番配線（#1869）。

use crate::error::{PluginError, PluginErrorCode};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// 起動対象ファイルの同一性（dev / ino）。構築時に fd を `fstat` して記録する。
/// 起動直前の同一性確認（`checked_exec_path`。#1866）と試験が使う。
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PluginFileIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
impl PluginFileIdentity {
    /// ファイルシステムのデバイス番号。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// inode 番号。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// 検証済みの開いたファイル記述子を持つ plugin の起動対象。
///
/// `Clone` は同じ fd を共有するだけで、新たな構築ではない（常駐の再起動・セッションの再開始で
/// 同じ起動対象を使い回すため）。値の等価比較は持たない（fd の同一性は値の等価ではない）。
#[derive(Debug, Clone)]
pub struct PluginLaunchTarget {
    /// 保持する検証済み fd。実行に使うのは Linux だけ（他は実体のパスで起動するため読まない）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    file: Arc<File>,
    display_path: PathBuf,
    exec_path: PathBuf,
    #[cfg(unix)]
    identity: PluginFileIdentity,
}

fn inspect_failed() -> PluginError {
    PluginError::new(
        PluginErrorCode::Internal,
        "failed to inspect plugin launch target",
    )
}

impl PluginLaunchTarget {
    /// 検証済みのファイルから起動対象を作る。
    ///
    /// `display_path` は検証時のパス（発見時。表示用で開き直さない）、`exec_path` は実体の正規パス
    /// （Linux 以外の unix の起動と `argv[0]` に使う）。いずれも絶対パス必須。
    ///
    /// 本番で呼んでよいのは core の `HashVerifiedPluginFile` からの変換 1 か所（#1857）。それ以外で
    /// 呼んでよいのは試験コードだけ。検証は本関数では行わない（呼び出し側の責務。PLUG-11）。
    ///
    /// 渡す `file` は読み取り専用で開いた fd にすること。保持用の複製は open file description を共有するため、
    /// 書き込み可能だと Linux の exec が `ETXTBSY` で失敗する（fail-closed）。
    ///
    /// 内容の同一性（hash）の確認は呼び出し側の責務。本関数の dev / ino の確認は同一 inode の
    /// 書き換えを防がない（core の変換は `HashVerifiedPluginFile` だけを受ける。許可一覧の読み込みは #1868、本番の配線は #1869）。
    ///
    /// 通常ファイルでないもの・`#!` スクリプトは `InvalidArgument`。fd の検査の失敗は `Internal`。
    /// 固定の英語文言で、パスや内容は含めない。
    pub fn from_verified_file(
        file: File,
        display_path: PathBuf,
        exec_path: PathBuf,
    ) -> Result<Self, PluginError> {
        if !display_path.is_absolute() || !exec_path.is_absolute() {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "plugin launch target path must be absolute",
            ));
        }
        let meta = file.metadata().map_err(|_| inspect_failed())?;
        if !meta.is_file() {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "plugin launch target must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{FileExt, MetadataExt};

            // 先頭 2 バイトだけ pread で読む（オフセットを動かさず、サイズに比例する確保もしない）。
            let mut head = [0u8; 2];
            let mut filled = 0;
            while filled < head.len() {
                let Some(buf) = head.get_mut(filled..) else {
                    return Err(inspect_failed());
                };
                let off = u64::try_from(filled).map_err(|_| inspect_failed())?;
                match file.read_at(buf, off) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(inspect_failed()),
                }
            }
            if head == *b"#!" {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidArgument,
                    "plugin launch target must be a native executable, not a script",
                ));
            }
            // 常に複製して保持する。`sys::dup_cloexec_min3` は `fcntl(F_DUPFD_CLOEXEC, 3)` で複製するため、
            // (1) 元 fd が close-on-exec 無しで渡されても保持 fd は必ず close-on-exec になり（exec 後の
            // plugin に残らず、解釈系が `/proc/self/fd/N` を開き直す経路も作らない）、(2) fd 番号が 3 以上
            // になる（0〜2 は子の stdio の dup2 で上書きされ別ファイルを実行しかねない）。元 fd は閉じる。
            let dup = crate::sys::dup_cloexec_min3(&file).map_err(|_| inspect_failed())?;
            drop(file);
            if dup.as_raw_fd() < 3 {
                return Err(inspect_failed());
            }
            let file = dup;
            Ok(Self {
                file: Arc::new(file),
                display_path,
                exec_path,
                identity: PluginFileIdentity {
                    dev: meta.dev(),
                    ino: meta.ino(),
                },
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                file: Arc::new(file),
                display_path,
                exec_path,
            })
        }
    }

    /// 検証時のパス（表示用。起動には使わない）。
    pub fn display_path(&self) -> &Path {
        &self.display_path
    }

    /// 実体の正規パス（Linux 以外の unix の起動と `argv[0]` に使う）。
    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    /// 構築時に fd を `fstat` した dev / ino。
    #[cfg(unix)]
    pub fn identity(&self) -> PluginFileIdentity {
        self.identity
    }

    /// 保持している fd（crate 内専用。書き込み・seek などの誤用を防ぐため公開しない）。
    #[cfg(target_os = "linux")]
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}

/// Linux で fd の実体を実行するための `/proc/self/fd/<N>` 側のパスを返す。起動前に、その magic link
/// を辿った先の dev / ino が構築時の同一性と一致することを確かめる（fail-closed。失敗・不一致は
/// `FailedPrecondition` で、パスでの起動へ縮退しない）。`proc_fd_dir` は本番では `/proc/self/fd`
/// （試験が別ディレクトリを渡して失敗経路を照合する）。リンク先が削除済み（`(deleted)`）でも stat は
/// 成功するので拒否しない。
#[cfg(target_os = "linux")]
pub(crate) fn linux_fd_exec_path(
    target: &PluginLaunchTarget,
    proc_fd_dir: &Path,
) -> Result<PathBuf, PluginError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let path = proc_fd_dir.join(target.file().as_raw_fd().to_string());
    match std::fs::metadata(&path) {
        Ok(m) if m.dev() == target.identity.dev && m.ino() == target.identity.ino => Ok(path),
        _ => Err(fd_launch_error()),
    }
}

/// fd 経由で実行できないときの構造化エラー。
#[cfg(target_os = "linux")]
pub(crate) fn fd_launch_error() -> PluginError {
    PluginError::new(
        PluginErrorCode::FailedPrecondition,
        "plugin launch target cannot be executed through its file descriptor",
    )
}

/// パスでの起動で、検証したファイルを指していないときの構造化エラー（#1866）。不一致・不在・
/// 非通常ファイル・symlink・stat の失敗を区別せず、パス・errno も含めない固定文言にする。
#[cfg(unix)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) fn path_identity_error() -> PluginError {
    PluginError::new(
        PluginErrorCode::FailedPrecondition,
        "plugin launch target path does not refer to the verified file",
    )
}

/// Linux 以外の unix で、spawn 直前に `exec_path` が検証したファイルを指すことを確かめて返す（#1866・
/// PLUG-11）。`plugin_command`（都度起動・常駐の起動と再起動）から呼ばれる。`lstat` で最終要素の symlink を
/// 辿らず、通常ファイルかつ dev / ino が構築時の同一性と一致するときだけ `Ok`。それ以外は
/// `path_identity_error`（fail-closed。パスでの起動へ縮退しない）。確認から exec までの窓の残余は
/// モジュール doc を参照。Linux では使わない（fd の実体を実行する）が、試験を共通に回すため
/// コンパイルする。
#[cfg(unix)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) fn checked_exec_path(target: &PluginLaunchTarget) -> Result<PathBuf, PluginError> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(target.exec_path()) {
        Ok(m)
            if m.file_type().is_file()
                && m.dev() == target.identity.dev
                && m.ino() == target.identity.ino =>
        {
            Ok(target.exec_path().to_path_buf())
        }
        _ => Err(path_identity_error()),
    }
}

/// 単体試験用: 実行中のテストバイナリ自身の起動対象（試験コードだけが構築口を呼んでよい契約）。
#[cfg(test)]
pub(crate) fn current_exe_target() -> PluginLaunchTarget {
    let p = std::env::current_exe().unwrap();
    PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), p.clone(), p).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn exe_target() -> PluginLaunchTarget {
        current_exe_target()
    }

    #[test]
    fn plug11_relative_paths_are_rejected() {
        let p = std::env::current_exe().unwrap();
        for (d, e) in [
            (PathBuf::from("plugin"), p.clone()),
            (p.clone(), PathBuf::from("plugin")),
        ] {
            let err =
                PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), d, e).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
            assert_eq!(err.message(), "plugin launch target path must be absolute");
        }
    }

    #[cfg(unix)]
    #[test]
    fn plug11_directory_is_rejected() {
        let dir = std::env::temp_dir();
        let err = PluginLaunchTarget::from_verified_file(
            File::open(&dir).unwrap(),
            dir.clone(),
            dir.clone(),
        )
        .unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(err.message(), "plugin launch target must be a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn plug11_script_is_rejected() {
        use std::io::Write;

        let p = std::env::temp_dir().join(format!("launch-target-script-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut f = File::create(&p).unwrap();
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        drop(f);
        let r =
            PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), p.clone(), p.clone());
        let _ = std::fs::remove_file(&p);
        let err = r.unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "plugin launch target must be a native executable, not a script"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_fd_is_at_least_3_and_identity_matches_fstat() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        let t = exe_target();
        assert!(t.file().as_raw_fd() >= 3);
        let m = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(t.identity().dev(), m.dev());
        assert_eq!(t.identity().ino(), m.ino());
        assert_eq!(t.exec_path(), t.display_path());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_fd_exec_path_resolves_through_proc() {
        use std::os::fd::AsRawFd;

        let t = exe_target();
        let got = linux_fd_exec_path(&t, Path::new("/proc/self/fd")).unwrap();
        assert_eq!(
            got,
            PathBuf::from(format!("/proc/self/fd/{}", t.file().as_raw_fd()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_fd_exec_path_fails_closed_on_missing_dir_and_mismatch() {
        use std::os::fd::AsRawFd;

        let t = exe_target();
        let e = linux_fd_exec_path(&t, Path::new("/nonexistent/proc/fd")).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "plugin launch target cannot be executed through its file descriptor"
        );

        // 別ファイルを指すエントリを同じ fd 番号の名前で置く。
        let dir = std::env::temp_dir().join(format!("launch-target-fd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/", dir.join(t.file().as_raw_fd().to_string())).unwrap();
        let r = linux_fd_exec_path(&t, &dir);
        let _ = std::fs::remove_dir_all(&dir);
        let e = r.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
    }

    /// 子を起動し、期限（10 秒）までに終了しなければ kill して回収する（REPAIR-5）。
    #[cfg(target_os = "linux")]
    fn run_with_deadline(
        mut cmd: std::process::Command,
    ) -> std::io::Result<std::process::ExitStatus> {
        let mut child = cmd.spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(st) = child.try_wait()? {
                return Ok(st);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// fd の flags に O_CLOEXEC が立っているか（/proc/self/fdinfo。unsafe を使わない）。
    #[cfg(target_os = "linux")]
    fn fd_is_cloexec(fd: i32) -> bool {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .unwrap()
            .trim();
        u32::from_str_radix(flags, 8).unwrap() & 0o2000000 != 0
    }

    /// PLUG-11: 保持 fd は close-on-exec（構築時に F_DUPFD_CLOEXEC で複製し直すため入力 fd の状態に依らない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_kept_fd_is_cloexec() {
        use std::os::fd::AsRawFd;

        let p = std::env::current_exe().unwrap();
        let t =
            PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), p.clone(), p).unwrap();
        assert!(fd_is_cloexec(t.file().as_raw_fd()));
    }

    /// PLUG-11: exec した子に保持 fd が残らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_kept_fd_does_not_leak_into_exec_child() {
        use std::os::fd::AsRawFd;

        let t = exe_target();
        let n = t.file().as_raw_fd();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("test ! -e /proc/self/fd/{n}"));
        let status = run_with_deadline(cmd).unwrap();
        assert!(status.success(), "kept fd {n} leaked into the exec child");
    }

    /// PLUG-11: 構築後に `#!` スクリプトへ書き換えられても、閉じた fd は解釈系から開けず実行されない。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_rewritten_to_script_is_not_run_via_proc_fd() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("launch-target-rewrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("plugin");
        std::fs::copy("/bin/sh", &p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let t =
            PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), p.clone(), p.clone())
                .unwrap();
        let marker = dir.join("ran");
        std::fs::write(&p, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        let exec = linux_fd_exec_path(&t, Path::new("/proc/self/fd")).unwrap();
        let status = run_with_deadline(std::process::Command::new(&exec));
        let ran = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!ran, "rewritten script must not run through /proc/self/fd");
        assert!(!matches!(status, Ok(s) if s.success()));
    }

    /// 単体試験用の作業ディレクトリに、テストバイナリの複製を起動対象として置く。
    #[cfg(unix)]
    fn copied_target(tag: &str) -> (PathBuf, PathBuf, PluginLaunchTarget) {
        let dir = std::env::temp_dir().join(format!("launch-target-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("plugin");
        let exe = std::env::current_exe().unwrap();
        if std::fs::hard_link(&exe, &p).is_err() {
            std::fs::copy(&exe, &p).unwrap();
        }
        let t =
            PluginLaunchTarget::from_verified_file(File::open(&p).unwrap(), p.clone(), p.clone())
                .unwrap();
        (dir, p, t)
    }

    #[cfg(unix)]
    fn assert_path_rejected(r: Result<PathBuf, PluginError>) {
        let e = r.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "plugin launch target path does not refer to the verified file"
        );
    }

    /// PLUG-11・#1866: 差し替えなしなら実体のパスをそのまま返す。
    #[cfg(unix)]
    #[test]
    fn plug11_1866_checked_exec_path_accepts_unchanged() {
        let (dir, p, t) = copied_target("ok");
        let r = checked_exec_path(&t);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r.unwrap(), p);
    }

    /// PLUG-11・#1866: 別 inode への差し替え（rename）は拒否する。
    #[cfg(unix)]
    #[test]
    fn plug11_1866_checked_exec_path_rejects_replaced_inode() {
        let (dir, p, t) = copied_target("swap");
        let other = dir.join("other");
        std::fs::write(&other, b"other").unwrap();
        std::fs::rename(&other, &p).unwrap();
        let r = checked_exec_path(&t);
        let _ = std::fs::remove_dir_all(&dir);
        assert_path_rejected(r);
    }

    /// PLUG-11・#1866: パスの消失は拒否する。
    #[cfg(unix)]
    #[test]
    fn plug11_1866_checked_exec_path_rejects_missing() {
        let (dir, p, t) = copied_target("gone");
        std::fs::remove_file(&p).unwrap();
        let r = checked_exec_path(&t);
        let _ = std::fs::remove_dir_all(&dir);
        assert_path_rejected(r);
    }

    /// PLUG-11・#1866: 元の実体を指す symlink でも（辿れば同じ inode でも）拒否する。
    #[cfg(unix)]
    #[test]
    fn plug11_1866_checked_exec_path_rejects_symlink_to_same_inode() {
        let (dir, p, t) = copied_target("link");
        let real = dir.join("real");
        std::fs::rename(&p, &real).unwrap();
        std::os::unix::fs::symlink(&real, &p).unwrap();
        let r = checked_exec_path(&t);
        let _ = std::fs::remove_dir_all(&dir);
        assert_path_rejected(r);
    }

    /// PLUG-11・#1866: ディレクトリへの置き換えは拒否する。
    #[cfg(unix)]
    #[test]
    fn plug11_1866_checked_exec_path_rejects_directory() {
        let (dir, p, t) = copied_target("dir");
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        let r = checked_exec_path(&t);
        let _ = std::fs::remove_dir_all(&dir);
        assert_path_rejected(r);
    }
}
