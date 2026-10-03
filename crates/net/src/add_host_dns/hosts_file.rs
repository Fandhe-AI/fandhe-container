//! コンテナの hosts ファイルへの追記本体（Linux 限定。NET-12・TASK-185.2・#345）。
//!
//! 親モジュールの [`super::append_add_hosts`] が件数検証・行の描画を終えた後に呼ぶ。追記先は
//! 「管理ルート（コンテナ状態ディレクトリ）」とそこからの相対パスで指定する。
//!
//! # 境界の守り方（rootfs・マウント境界の P0）
//! - 管理ルートは symlink を含まない絶対パスで受け取り、正規化（`canonicalize`）せずに `/` から 1 要素ずつ
//!   `O_DIRECTORY | O_NOFOLLOW` で辿って開く（管理ルート自身・祖先のどれかが symlink なら辿らず拒否する）。
//!   そのディレクトリ fd を起点に相対パスの途中要素を `openat(O_DIRECTORY | O_NOFOLLOW)`
//!   （`crate::sys` の薄いラッパー）で 1 要素ずつ辿る。途中要素が symlink（検証後の差し替えを含む）なら
//!   `ELOOP` / `ENOTDIR` で失敗するため、パスを再解決する検査と open の間の競合（TOCTOU）で管理外の
//!   ファイルを開くことはない。`..`・絶対パス・`.` は辿る前に拒否する。
//! - 最終要素は `O_PATH | O_NOFOLLOW` で開き（デバイス・FIFO でもドライバの `open()` を呼ばない）、その fd で
//!   通常ファイル・`nlink == 1`・所有者・サイズ・マウントを確かめてから `/proc/self/fd/<fd>` 経由で
//!   読み書き用に開き直す。開き直した fd の (dev, ino) が `O_PATH` の fd と一致することも確かめ、以降の
//!   検証・ロック・追記・巻き戻しはすべて開き直した fd に対して行い、パスは二度と引かない。
//! - 管理ルート内の hosts パス・途中ディレクトリへの bind mount（同一ファイルシステム内でも新しい
//!   マウントになる）は、ルートのディレクトリ fd と hosts ファイル fd の `mnt_id`
//!   （`/proc/self/fdinfo/<fd>`）の不一致で拒否する。
//!
//! hosts ファイルの生成・コンテナへの bind mount は runtime / core 側の責務で、ここは既存の通常ファイルへ
//! 追記するだけ（無ければ作らず `NOT_FOUND`）。tmp + rename は使わない（bind mount 済みの inode を保つため）。

use std::ffi::CString;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{NetError, NetErrorCode};
use crate::sys::{self, SysError};

/// 追記先 hosts ファイルの最大バイト数（実装上限。これを超える既存ファイルへは追記しない）。
pub(super) const MAX_HOSTS_FILE_BYTES: u64 = 1024 * 1024;
/// hosts ファイルの排他ロック取得の待ち上限（REPAIR-5。超過は `TIMEOUT`）。
const HOSTS_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 排他ロックの再試行間隔。
const HOSTS_LOCK_POLL: Duration = Duration::from_millis(10);
/// 同一プロセス内の追記を直列化する（flock はプロセス間用で、同一プロセスの別 fd 同士も
/// 直列化するが、ロック待ちを持たずに済ませるため先にこのミューテックスで順序付ける）。
static HOSTS_APPEND_GUARD: Mutex<()> = Mutex::new(());
/// `/proc/self/fdinfo/<fd>` の読み込み上限（無制限確保の防止。通常は数百バイト）。
const MAX_FDINFO_BYTES: u64 = 64 * 1024;

fn io_err(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::Internal, msg)
}

/// 途中要素を開く `openat` の失敗を分類する（不在は `NOT_FOUND`、symlink・非ディレクトリは
/// `INVALID_ARGUMENT`）。
fn dir_open_error(e: SysError) -> NetError {
    match e {
        SysError::Os(sys::ENOENT) => {
            NetError::new(NetErrorCode::NotFound, "hosts file does not exist")
        }
        SysError::Os(sys::ELOOP | sys::ENOTDIR) => NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path has a non-directory or symlink component",
        ),
        SysError::Os(sys::EACCES | sys::EPERM) => NetError::new(
            NetErrorCode::PermissionDenied,
            "permission denied while opening hosts file",
        ),
        SysError::Unsupported => unsupported(),
        _ => io_err("failed to open hosts file"),
    }
}

/// 最終要素（hosts ファイル）の `O_PATH` での open・開き直しの失敗を分類する（symlink・ディレクトリは
/// `INVALID_ARGUMENT`）。
fn file_open_error(e: SysError) -> NetError {
    match e {
        SysError::Os(sys::ELOOP | sys::EISDIR) => NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path is not a regular file",
        ),
        other => dir_open_error(other),
    }
}

fn unsupported() -> NetError {
    NetError::new(
        NetErrorCode::Unimplemented,
        "appending to hosts file is not supported on this architecture",
    )
}

/// 生のパスに `.` だけの要素が（位置に関わらず）含まれるかを返す。`Path::components` は途中の `.` を
/// 黙って取り除くため、`sub/./hosts` を `sub/hosts` と同一視しないよう区切り `/` で生のバイト列を見る。
fn has_cur_dir_segment(p: &Path) -> bool {
    p.as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .any(|seg| seg == b".")
}

/// 管理ルートの絶対パス `abs` を、symlink を辿らずに `/` から 1 要素ずつ `openat(O_NOFOLLOW |
/// O_DIRECTORY)` で開いてディレクトリ fd を得る。
///
/// 正規化（`canonicalize`）はしない。正規化すると渡されたパス上の symlink を先に辿ってしまい、リンク先
/// （管理外のディレクトリ）を管理ルートとして扱うことになるため。相対パス・`..` / `.`（途中を含む）を含むパスは
/// `INVALID_ARGUMENT`、管理ルート自身・祖先が symlink または非ディレクトリなら `FAILED_PRECONDITION`、
/// 不在なら `NOT_FOUND`。
fn open_abs_dir_nofollow(abs: &Path) -> Result<OwnedFd, NetError> {
    let map = |e: SysError| match e {
        SysError::Os(sys::ENOENT) => {
            NetError::new(NetErrorCode::NotFound, "managed root does not exist")
        }
        SysError::Os(sys::ELOOP | sys::ENOTDIR) => NetError::new(
            NetErrorCode::FailedPrecondition,
            "managed root has a symlink or non-directory component",
        ),
        SysError::Os(sys::EACCES | sys::EPERM) => NetError::new(
            NetErrorCode::PermissionDenied,
            "permission denied while opening managed root",
        ),
        SysError::Unsupported => unsupported(),
        _ => io_err("failed to open managed root"),
    };
    let not_normalized = || {
        NetError::new(
            NetErrorCode::InvalidArgument,
            "managed root must be a normalized absolute path",
        )
    };
    let mut comps = abs.components();
    if has_cur_dir_segment(abs) || comps.next() != Some(Component::RootDir) {
        return Err(not_normalized());
    }
    let mut cur = sys::open_root_dir().map_err(map)?;
    for c in comps {
        let Component::Normal(n) = c else {
            return Err(not_normalized());
        };
        let name =
            CString::new(n.as_bytes()).map_err(|_| io_err("failed to resolve managed root"))?;
        cur = sys::open_dir_nofollow_at(cur.as_fd(), &name).map_err(map)?;
    }
    Ok(cur)
}

/// 管理ルートとその配下の hosts ファイルを、symlink を辿らずに 1 要素ずつ開く。
///
/// 管理ルートは正規化せず、`/` から要素ごとに symlink を辿らずに開く（[`open_abs_dir_nofollow`]）。
///
/// `rel` は空でない相対パスで、全要素が通常の名前であること（絶対パス・`..`・`.`〔途中を含む〕は
/// `INVALID_ARGUMENT`）。戻り値は（管理ルートのディレクトリ fd, hosts ファイルの fd）。
fn open_in_root(managed_root: &Path, rel: &Path) -> Result<(File, File), NetError> {
    if has_cur_dir_segment(rel) {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path must be a plain relative path inside the managed root",
        ));
    }
    let mut names = Vec::new();
    for c in rel.components() {
        let Component::Normal(n) = c else {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "hosts path must be a plain relative path inside the managed root",
            ));
        };
        let n = CString::new(n.as_bytes()).map_err(|_| {
            NetError::new(
                NetErrorCode::InvalidArgument,
                "hosts path must not contain NUL",
            )
        })?;
        names.push(n);
    }
    let Some((last, dirs)) = names.split_last() else {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path must not be empty",
        ));
    };
    let root_fd = open_abs_dir_nofollow(managed_root)?;
    let mut cur: Option<OwnedFd> = None;
    for d in dirs {
        let base = cur.as_ref().unwrap_or(&root_fd).as_fd();
        cur = Some(sys::open_dir_nofollow_at(base, d).map_err(dir_open_error)?);
    }
    let base = cur.as_ref().unwrap_or(&root_fd).as_fd();
    let target = sys::open_path_nofollow_at(base, last).map_err(file_open_error)?;
    Ok((File::from(root_fd), File::from(target)))
}

/// `O_PATH` の fd `target` を検証してから読み書き用（`O_RDWR | O_APPEND`）に開き直す。
///
/// 種別・リンク数・所有者・サイズ・マウントは `O_PATH` の fd で先に確かめる（通常ファイル以外の
/// ドライバ `open()` を走らせない）。開き直しは fd が保持する実体を指す `/proc/self/fd/<fd>` 経由で、
/// 開き直した fd の (dev, ino) が `target` と一致しなければ拒否する（fail-closed）。
fn reopen_verified(root: &File, target: &File) -> Result<File, NetError> {
    verify_hosts_file(target)?;
    verify_same_mount(root, target)?;
    let before = target
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?;
    let file = File::from(sys::reopen_append(target.as_fd()).map_err(file_open_error)?);
    let after = file
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?;
    if (after.dev(), after.ino()) != (before.dev(), before.ino()) {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file changed while reopening",
        ));
    }
    Ok(file)
}

/// 開いた fd（`O_PATH` の fd を含む。`fstat` は `O_PATH` でも使える）が追記してよい hosts ファイルで
/// あることを確認する（fd のみを見る。パスは引かない）。
///
/// 通常ファイル・上限サイズ以下・ハードリンクなし（`nlink == 1`。ハードリンク経由でコンテナ外の
/// ファイルへ追記させない）・実効 UID 所有（他ユーザー所有のファイルへ追記しない）。
fn verify_hosts_file(file: &File) -> Result<(), NetError> {
    let meta = file
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?;
    if !meta.file_type().is_file() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path is not a regular file",
        ));
    }
    if meta.len() > MAX_HOSTS_FILE_BYTES {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "hosts file is too large",
        ));
    }
    if meta.nlink() != 1 {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file has multiple hard links",
        ));
    }
    if meta.uid() != sys::effective_uid() {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file is not owned by the current user",
        ));
    }
    Ok(())
}

/// `/proc/self/fdinfo/<fd>` の本文から `mnt_id:` 行の値を取り出す（OS 呼び出しを含まない純粋関数）。
///
/// 行が無い・数値でない場合は `None`（呼び出し側は fail-closed で拒否する）。`lock:` 等の他の行は無視する。
fn parse_fdinfo_mnt_id(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// 開いた fd が属するマウントの ID を `/proc/self/fdinfo/<fd>` から読む（Linux 3.15 以降）。
fn fd_mount_id(file: &File) -> Result<u64, NetError> {
    use std::os::fd::AsRawFd as _;
    let mut text = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .and_then(|f| f.take(MAX_FDINFO_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| io_err("failed to read fdinfo"))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_FDINFO_BYTES) {
        return Err(io_err("fdinfo is too large"));
    }
    parse_fdinfo_mnt_id(&text).ok_or_else(|| io_err("mount id is missing in fdinfo"))
}

/// 開いた hosts ファイルが管理ルートと同じマウント上にあることを確認する（rootfs / マウント境界の P0）。
///
/// 管理ルート内の hosts パスや途中ディレクトリへ外部ファイルを bind mount されると、symlink を辿らずに
/// 開いても外部ファイルの fd になる。bind mount は同一ファイルシステム内でも新しいマウントになるため、
/// ルートのディレクトリ fd と hosts ファイル fd の `mnt_id` 一致を要求する。読めない場合は拒否する
/// （fail-closed）。
fn verify_same_mount(root: &File, file: &File) -> Result<(), NetError> {
    if fd_mount_id(root)? != fd_mount_id(file)? {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file lives on a mount outside the managed root",
        ));
    }
    Ok(())
}

/// 書き込み失敗後に書き込み前の長さへ戻し、結果に応じたエラーを返す。
///
/// `written` は今回の呼び出しが実際に書けたバイト数。切り詰める前に現在のサイズが `len + written` と
/// 一致することを確かめ、一致しなければ（ロックを守らない他者が書き足した等）他者の内容を消さないよう
/// 切り詰めずに `DATA_LOSS` を返す。巻き戻し（切り詰め + fsync）まで成功した場合のみ通常の `INTERNAL`
/// （ファイルは元の内容）。失敗した場合は不完全な行が残りうるため `DATA_LOSS` で区別する（再試行は
/// その後ろへ追記してしまうため、呼び出し側は hosts ファイルを再生成するなど復旧が必要）。`sync_all`
/// 失敗後の切り詰めも永続化を確認するため再度 fsync する。
fn rollback_after_failure(file: &File, len: u64, written: usize) -> NetError {
    let data_loss = || {
        NetError::new(
            NetErrorCode::DataLoss,
            "failed to write hosts file and failed to roll back; file may be corrupted",
        )
    };
    let expected = u64::try_from(written).ok().and_then(|w| len.checked_add(w));
    match file.metadata() {
        Ok(m) if Some(m.len()) == expected => {}
        _ => return data_loss(),
    }
    if file.set_len(len).and_then(|_| file.sync_all()).is_ok() {
        io_err("failed to write hosts file")
    } else {
        data_loss()
    }
}

/// `buf` を書き切るまで `write` を繰り返し、実際に書けたバイト数と結果を返す（`write_all` と同じ挙動で、
/// 失敗時にも書けた量が分かる。巻き戻しのサイズ照合に使う）。
fn write_all_counted(file: &mut File, buf: &[u8]) -> (usize, std::io::Result<()>) {
    let mut done = 0usize;
    while let Some(rest) = buf.get(done..).filter(|r| !r.is_empty()) {
        match file.write(rest) {
            Ok(0) => return (done, Err(std::io::ErrorKind::WriteZero.into())),
            Ok(n) => done = done.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return (done, Err(e)),
        }
    }
    (done, Ok(()))
}

/// hosts ファイルの排他ロックを期限つきで取得する（プロセス間の直列化。REPAIR-5）。
///
/// `deadline` は呼び出し側が決めた全体の期限で、同一プロセス内ミューテックス待ちと共有する。
fn lock_exclusive_bounded(file: &File, deadline: Instant) -> Result<(), NetError> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for hosts file lock",
                    ));
                }
                std::thread::sleep(HOSTS_LOCK_POLL);
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(io_err("failed to lock hosts file"));
            }
        }
    }
}

/// 同一プロセス内の追記ミューテックスを期限つきで取得する（`try_lock` のポーリング。REPAIR-5）。
///
/// 先行追記が `sync_all` 等で停止しても、後続は `deadline` で `TIMEOUT` を返し無期限には待たない。
fn lock_guard_bounded(deadline: Instant) -> Result<std::sync::MutexGuard<'static, ()>, NetError> {
    loop {
        match HOSTS_APPEND_GUARD.try_lock() {
            Ok(g) => return Ok(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for hosts append lock",
                    ));
                }
                std::thread::sleep(HOSTS_LOCK_POLL);
            }
        }
    }
}

/// 描画済みの hosts 行 `lines` を管理ルート配下の既存 hosts ファイルへ追記する。
///
/// 長さ取得・末尾改行判定・上限判定・追記を 1 つの排他区間（プロセス内ミューテックス + flock）にし、
/// 既存内容の末尾が改行でなければ先頭に改行を補って `O_APPEND` の 1 回の `write_all` にまとめる。
/// 追記後に [`MAX_HOSTS_FILE_BYTES`] を超えるなら書かない。書き込み・fsync の失敗時は同じロック下で
/// 書き込み前の長さへ戻す（[`rollback_after_failure`]）。ロックは `file` の Drop で解放される。
///
/// 前提: 管理ルートはローカルファイルシステム上にあること。`flock` による直列化・`O_APPEND` の追記位置・
/// `/proc/self/fdinfo` の `mnt_id` 照合はローカル FS の意味論に依存し、NFS 等のネットワーク FS では
/// 保証しない（他ホストからの同時更新は直列化されない）。
pub(super) fn append_lines(
    managed_root: &Path,
    hosts_rel: &Path,
    lines: &str,
) -> Result<(), NetError> {
    let (root, target) = open_in_root(managed_root, hosts_rel)?;
    let mut file = reopen_verified(&root, &target)?;
    drop(target);
    let deadline = Instant::now() + HOSTS_LOCK_TIMEOUT;
    let _guard = lock_guard_bounded(deadline)?;
    lock_exclusive_bounded(&file, deadline)?;
    // サイズ・リンク数はロック取得までに変わりうるため、排他区間内で開き直した fd に対して再確認する。
    verify_hosts_file(&file)?;
    verify_same_mount(&root, &file)?;

    let len = file
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?
        .len();
    let mut payload = String::new();
    if len > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))
            .and_then(|_| file.read_exact(&mut last))
            .map_err(|_| io_err("failed to read hosts file"))?;
        if last != *b"\n" {
            payload.push('\n');
        }
    }
    payload.push_str(lines);
    // 追記後のファイルサイズが上限を超える場合は書き込まない（既存 1 MiB ちょうどへの追記も拒否）。
    let new_len = u64::try_from(payload.len())
        .ok()
        .and_then(|p| len.checked_add(p));
    if new_len.is_none_or(|n| n > MAX_HOSTS_FILE_BYTES) {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "hosts file would exceed size limit",
        ));
    }
    // 容量不足等で途中まで書いて失敗すると不完全な行が残り、再試行でその後ろへ追記されてしまう。
    // 排他ロックを保持したまま書き込み前の長さへ戻し、失敗後のファイルを元の状態に保つ。
    let (written, res) = write_all_counted(&mut file, payload.as_bytes());
    if res.and_then(|_| file.sync_all()).is_err() {
        return Err(rollback_after_failure(&file, len, written));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{apply_add_hosts, apply_add_hosts_with_recorder};
    use super::*;
    use crate::instrument::NetOpKind;
    use std::fs::OpenOptions;

    /// ケースごとの一時管理ルート。`.0` は管理ルート配下の hosts ファイルの絶対パス（相対名は `hosts`）。
    struct TmpFile {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
    }
    impl TmpFile {
        fn new(case: &str, content: Option<&str>) -> Self {
            let root =
                std::env::temp_dir().join(format!("fc-addhost-{}-{case}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            // 管理ルートは symlink を含まない絶対パスで渡す契約のため、一時ディレクトリの祖先の
            // symlink（環境依存）を正規化で除いておく。
            let root = std::fs::canonicalize(&root).unwrap();
            let path = root.join("hosts");
            if let Some(c) = content {
                std::fs::write(&path, c).unwrap();
            }
            Self { root, path }
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn run<'a>(f: &TmpFile, raw: impl IntoIterator<Item = &'a str>) -> Result<(), NetError> {
        apply_add_hosts(&f.root, Path::new("hosts"), raw)
    }

    /// NET-12・TASK-185.2: 既存内容の後ろへ追記される。
    #[test]
    fn append_to_existing_file() {
        let f = TmpFile::new("append", Some("127.0.0.1\tlocalhost\n"));
        run(&f, ["web:192.0.2.1", "db:::1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "127.0.0.1\tlocalhost\n192.0.2.1\tweb\n::1\tdb\n"
        );
    }

    /// NET-12: 末尾改行が無い既存内容には改行を補って行の癒着を防ぐ。
    #[test]
    fn append_adds_missing_newline() {
        let f = TmpFile::new("nonl", Some("127.0.0.1\tlocalhost"));
        run(&f, ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "127.0.0.1\tlocalhost\n192.0.2.1\tweb\n"
        );
    }

    /// NET-12: 空ファイルへは改行を補わない。空エントリはファイルを変更しない。
    #[test]
    fn append_empty_file_and_empty_entries() {
        let f = TmpFile::new("empty", Some(""));
        run(&f, ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "192.0.2.1\tweb\n"
        );
        let g = TmpFile::new("noentries", Some("x"));
        run(&g, std::iter::empty()).unwrap();
        assert_eq!(std::fs::read_to_string(&g.path).unwrap(), "x");
    }

    /// NET-12: 追記後に上限を超えるファイルは拒否し、ちょうど上限に収まる場合は許可する。
    #[test]
    fn append_rejects_growth_beyond_size_limit() {
        let line = "192.0.2.1\th\n"; // 12 バイト
        let max = MAX_HOSTS_FILE_BYTES as usize;
        let ok = TmpFile::new("fits", Some(&"a".repeat(max - line.len() - 1)));
        // 末尾改行なし: 改行 1 + 行 12 でちょうど上限。
        run(&ok, ["h:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::metadata(&ok.path).unwrap().len(),
            MAX_HOSTS_FILE_BYTES
        );

        let full = TmpFile::new("full", Some(&"a".repeat(max)));
        let e = run(&full, ["h:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(
            std::fs::metadata(&full.path).unwrap().len(),
            MAX_HOSTS_FILE_BYTES
        );

        let near = TmpFile::new("near", Some(&"a".repeat(max - line.len())));
        let e = run(&near, ["h:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    }

    /// NET-12: 存在しないパスは NOT_FOUND で、ファイルを作らない。
    #[test]
    fn missing_file_is_not_created() {
        let f = TmpFile::new("missing", None);
        let e = run(&f, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert!(!f.path.exists());
    }

    /// NET-12: ディレクトリ（非通常ファイル）は INVALID_ARGUMENT。
    #[test]
    fn directory_is_rejected() {
        let f = TmpFile::new("dir", None);
        std::fs::create_dir(f.root.join("sub")).unwrap();
        let e = apply_add_hosts(&f.root, Path::new("sub"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-12: symlink は拒否し、リンク先を変更しない。
    #[test]
    fn symlink_is_rejected() {
        let target = TmpFile::new("symtarget", Some("orig\n"));
        let link = TmpFile::new("symlink", None);
        std::os::unix::fs::symlink(&target.path, &link.path).unwrap();
        let e = run(&link, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_to_string(&target.path).unwrap(), "orig\n");
    }

    /// NET-12: ハードリンクされたファイルへは追記せず、リンク先も変更しない。
    #[test]
    fn hard_link_is_rejected() {
        let target = TmpFile::new("hltarget", Some("orig\n"));
        let link = TmpFile::new("hllink", None);
        std::fs::hard_link(&target.path, &link.path).unwrap();
        let e = run(&link, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(std::fs::read_to_string(&target.path).unwrap(), "orig\n");
    }

    /// NET-12・P0: 管理ルート外を指す相対パス（`..`・絶対パス・`.`・空）は拒否し、ファイルを変更しない。
    #[test]
    fn paths_escaping_managed_root_are_rejected() {
        let outside = TmpFile::new("outside", Some("orig\n"));
        let f = TmpFile::new("inside", Some("in\n"));
        let up = Path::new("..")
            .join(outside.root.file_name().unwrap())
            .join("hosts");
        for rel in [
            up.as_path(),
            outside.path.as_path(), // 絶対パス（管理ルート外）
            Path::new("./hosts"),
            Path::new(""),
        ] {
            let e = apply_add_hosts(&f.root, rel, ["web:192.0.2.1"]).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{rel:?}");
        }
        assert_eq!(std::fs::read_to_string(&outside.path).unwrap(), "orig\n");
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), "in\n");
    }

    /// NET-12・P0: 管理ルート配下でも途中ディレクトリが管理外への symlink なら拒否する。
    #[test]
    fn symlinked_directory_component_is_rejected() {
        let outside = TmpFile::new("symdir-out", Some("orig\n"));
        let f = TmpFile::new("symdir-in", None);
        std::os::unix::fs::symlink(&outside.root, f.root.join("link")).unwrap();
        let e = apply_add_hosts(&f.root, Path::new("link/hosts"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_to_string(&outside.path).unwrap(), "orig\n");
    }

    /// NET-12: 管理ルート配下のサブディレクトリの hosts ファイルには追記できる。
    #[test]
    fn nested_relative_path_inside_root_is_accepted() {
        let f = TmpFile::new("nested", None);
        std::fs::create_dir(f.root.join("c1")).unwrap();
        std::fs::write(f.root.join("c1").join("hosts"), "a\n").unwrap();
        apply_add_hosts(&f.root, Path::new("c1/hosts"), ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(f.root.join("c1").join("hosts")).unwrap(),
            "a\n192.0.2.1\tweb\n"
        );
    }

    /// NET-12・TASK-185.2（P0）: fdinfo の `mnt_id:` 行だけを数値で取り出し、無い・壊れた値は `None`。
    #[test]
    fn fdinfo_mnt_id_is_parsed_strictly() {
        let text = "pos:\t0\nflags:\t02102002\nmnt_id:\t39\nino:\t5\n\
                    lock:\t1: FLOCK  ADVISORY  WRITE 1234 00:2a:5 0 EOF\n";
        assert_eq!(parse_fdinfo_mnt_id(text), Some(39));
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\nflags:\t0100000\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\tabc\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\t-1\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(""), None);
    }

    /// NET-12・TASK-185.2（P0）: 管理ルートと同じマウント上のファイルは通す。
    #[test]
    fn same_mount_file_is_accepted() {
        let f = TmpFile::new("same-mount", Some("a\n"));
        let root = File::open(&f.root).unwrap();
        let file = File::open(&f.path).unwrap();
        assert_eq!(verify_same_mount(&root, &file), Ok(()));
    }

    /// NET-12・TASK-185.2（P0）: 管理ルートと別マウント上の fd（bind mount で差し込まれた外部ファイル相当）
    /// は `FAILED_PRECONDITION` で拒否する。root 権限なしで「別マウントの fd」を用意するため procfs 上の
    /// ファイルを使う。
    #[test]
    fn foreign_mount_file_is_rejected() {
        let f = TmpFile::new("foreign-mount", Some("a\n"));
        let root = File::open(&f.root).unwrap();
        let foreign = File::open("/proc/self/status").unwrap();
        let e = verify_same_mount(&root, &foreign).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "hosts file lives on a mount outside the managed root"
        );
    }

    /// NET-12・TASK-185.2（P0）: 最終要素が管理ルート内の別ファイルへの symlink でも追従せず拒否し、
    /// どちらのファイルも変更しない（symlink を辿る経路が無いこと）。
    #[test]
    fn symlink_to_file_inside_root_is_rejected() {
        let f = TmpFile::new("inner-symlink", Some("orig\n"));
        std::os::unix::fs::symlink(&f.path, f.root.join("alias")).unwrap();
        let e = apply_add_hosts(&f.root, Path::new("alias"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), "hosts path is not a regular file");
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), "orig\n");
    }

    /// NET-12・TASK-185.2（P0）: 管理ルートは正規化せず `/` から 1 要素ずつ辿る。管理ルート自身・祖先が
    /// 管理外ディレクトリへの symlink なら `FAILED_PRECONDITION` で拒否し、リンク先の hosts を変更しない。
    /// 相対パス・`..` を含むパスは `INVALID_ARGUMENT`、不在は `NOT_FOUND`。
    #[test]
    fn managed_root_symlink_is_rejected_without_following() {
        let real = TmpFile::new("root-real", Some("orig\n"));
        let alias = TmpFile::new("root-alias", None);
        let real_root = real.root.clone();
        let alias_root = alias.root.clone();
        let link = alias_root.join("lnk");
        std::os::unix::fs::symlink(&real_root, &link).unwrap();
        std::fs::create_dir(alias_root.join("d")).unwrap();
        std::os::unix::fs::symlink(&real_root, alias_root.join("d").join("lnk")).unwrap();

        // 管理ルート自身が symlink（正規化すればリンク先の hosts へ追記できてしまう経路）。
        let e = apply_add_hosts(&link, Path::new("hosts"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "managed root has a symlink or non-directory component"
        );
        // 祖先が symlink（`lnk/..` 経由で実ディレクトリへ戻る形も含めて辿らない）。
        let e = open_abs_dir_nofollow(&link.join("x")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let e = apply_add_hosts(
            &alias_root.join("d").join("lnk"),
            Path::new("hosts"),
            ["web:192.0.2.1"],
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(std::fs::read_to_string(&real.path).unwrap(), "orig\n");

        for bad in [Path::new("relative/root"), &alias_root.join("..").join("x")] {
            let e = open_abs_dir_nofollow(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad:?}");
            assert_eq!(
                e.message(),
                "managed root must be a normalized absolute path"
            );
        }
        let e = open_abs_dir_nofollow(&alias_root.join("none")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        // 正規化済みの実ディレクトリなら追記できる。
        apply_add_hosts(&real_root, Path::new("hosts"), ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&real.path).unwrap(),
            "orig\n192.0.2.1\tweb\n"
        );
    }

    /// NET-12・TASK-185.2（P0）: 途中要素が通常ファイルなら辿らず `INVALID_ARGUMENT`、途中が不在なら
    /// `NOT_FOUND`（いずれも何も作らない）。
    #[test]
    fn non_directory_or_missing_component_is_rejected() {
        let f = TmpFile::new("nondir", Some("orig\n"));
        let e = apply_add_hosts(&f.root, Path::new("hosts/x"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "hosts path has a non-directory or symlink component"
        );
        let e = apply_add_hosts(&f.root, Path::new("nodir/hosts"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert!(!f.root.join("nodir").exists());
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), "orig\n");
    }

    /// NET-12・P1: 巻き戻しに失敗したら `DATA_LOSS`（復旧不能）で区別して返す。
    #[test]
    fn rollback_failure_is_reported_as_data_loss() {
        let f = TmpFile::new("rollback-fail", Some("abc\n"));
        // 読み取り専用 fd では set_len が失敗する。
        let ro = File::open(&f.path).unwrap();
        let e = rollback_after_failure(&ro, 0, 4);
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"abc\n");
    }

    /// NET-12・P1: 巻き戻しに成功したら元の長さに戻り、通常の `INTERNAL` を返す。
    #[test]
    fn rollback_success_restores_length_and_is_internal() {
        let f = TmpFile::new("rollback-ok", Some("abc\npartial"));
        let rw = OpenOptions::new().write(true).open(&f.path).unwrap();
        let e = rollback_after_failure(&rw, 4, 7);
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"abc\n");
    }

    /// NET-12・P2: 現在のサイズが「書き込み前の長さ + 書けた量」と一致しなければ（他者が書き足した等）
    /// 切り詰めずに `DATA_LOSS` を返し、ファイルの内容を変えない。
    #[test]
    fn rollback_with_unexpected_size_does_not_truncate() {
        let f = TmpFile::new("rollback-mismatch", Some("abc\npartial+other"));
        let rw = OpenOptions::new().write(true).open(&f.path).unwrap();
        let e = rollback_after_failure(&rw, 4, 7);
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"abc\npartial+other");
    }

    /// NET-12・P2: 書けた量を数えながら書き切る（全量・空バッファの具体値）。
    #[test]
    fn write_all_counted_reports_written_bytes() {
        let f = TmpFile::new("counted", Some("a\n"));
        let mut w = OpenOptions::new().append(true).open(&f.path).unwrap();
        let (n, r) = write_all_counted(&mut w, b"bc\n");
        assert_eq!((n, r.is_ok()), (3, true));
        let (n, r) = write_all_counted(&mut w, b"");
        assert_eq!((n, r.is_ok()), (0, true));
        assert_eq!(std::fs::read(&f.path).unwrap(), b"a\nbc\n");
        // 読み取り専用 fd では 1 バイトも書けずに失敗し、書けた量は 0。
        let mut ro = File::open(&f.path).unwrap();
        let (n, r) = write_all_counted(&mut ro, b"x");
        assert_eq!((n, r.is_err()), (0, true));
    }

    /// NET-12・P2: 通常ファイル以外（UNIX ソケット）は `O_PATH` の fd で種別を判定して拒否し、
    /// 読み書き用には開かない。
    #[test]
    fn non_regular_file_is_rejected_before_reopen() {
        let f = TmpFile::new("socket", None);
        let _l = std::os::unix::net::UnixListener::bind(&f.path).unwrap();
        let e = run(&f, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), "hosts path is not a regular file");
    }

    /// NET-12・TASK-185.2 受け入れ基準: 検証失敗時に hosts ファイルは 1 バイトも変わらない。
    #[test]
    fn validation_failure_leaves_file_untouched() {
        let init = "127.0.0.1\tlocalhost\n";
        let f = TmpFile::new("untouched", Some(init));
        let cases: [&[&str]; 6] = [
            &["bad host:192.0.2.2", "ok:192.0.2.1"],
            &["ok:192.0.2.1", "bad host:192.0.2.2"],
            &["ok:192.0.2.1", "nosep", "ok2:192.0.2.3"],
            &["ok:192.0.2.1", "h:999.1.1.1"],
            &["ok:192.0.2.1", "h:1.2.3.4\nevil"],
            &["ok:192.0.2.1", "h:"],
        ];
        for c in cases {
            let e = run(&f, c.iter().copied()).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{c:?}");
            assert_eq!(std::fs::read(&f.path).unwrap(), init.as_bytes(), "{c:?}");
        }
    }

    /// REPAIR-4: 成功・失敗（検証失敗）が `AddHostsApply` として 1 件ずつ記録される。
    #[test]
    fn apply_records_success_and_failure() {
        use crate::instrument::NetOpOutcome;
        use crate::instrument::testing::Collect;
        let f = TmpFile::new("record", Some("127.0.0.1\tlocalhost\n"));
        let c = Collect::default();
        apply_add_hosts_with_recorder(&f.root, Path::new("hosts"), ["web:192.0.2.1"], &c).unwrap();
        apply_add_hosts_with_recorder(&f.root, Path::new("hosts"), ["bad host:192.0.2.1"], &c)
            .unwrap_err();
        assert_eq!(
            c.kinds(),
            vec![
                (NetOpKind::AddHostsApply, NetOpOutcome::Success),
                (NetOpKind::AddHostsApply, NetOpOutcome::Failure),
            ]
        );
    }

    /// NET-12: 並行追記でも上限を超えず、各行が欠落・混在せずちょうど 1 回ずつ入る。
    #[test]
    fn concurrent_appends_are_serialized() {
        let f = TmpFile::new("concurrent", Some(""));
        let path = f.path.clone();
        let root = f.root.clone();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = root.clone();
                std::thread::spawn(move || {
                    let v = format!("h{i}:192.0.2.{i}");
                    apply_add_hosts(&p, Path::new("hosts"), [v.as_str()]).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let got = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = got.lines().collect();
        lines.sort_unstable();
        let want: Vec<String> = (0..8).map(|i| format!("192.0.2.{i}\th{i}")).collect();
        assert_eq!(lines, want.iter().map(String::as_str).collect::<Vec<_>>());
    }
}
