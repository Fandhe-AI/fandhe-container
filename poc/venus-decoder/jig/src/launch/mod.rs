//! 試験治具の起動入口（UDS の bind・期限つき accept・ログのファイル出力。GPU-6・REPAIR-5・TASK-172 F4・#1598）。Linux 限定。
//!
//! 呼び出し元は bin（`src/bin/venus-jig.rs`）と結合試験。`session::run` に渡す accept 済みの接続を作り、
//! `log::LogSink` でログを `create_new` + `0600` のファイルへ書く。1 接続を最後まで処理して終わる PoC 用の入口で、
//! 実機での疎通（治具 VMM = crosvm 等の vhost-user frontend との接続）は #725（人間担当）。
//!
//! 処理の順序: 引数解析 → パス検証 → UID 取得 → ソケットディレクトリの検証・作成 → 既存パスの検査 → ログファイル作成 →
//! bind → 期限つき accept → `session::run` → 後始末。検証で拒否した場合はログファイルを作らず、既存のパスは消さない。
//!
//! 接続元の認証（PLUG-12 相当）: accept 直後、セッションに入る前に `sys::peer_uid`（`SO_PEERCRED`）で接続元 UID を
//! effective UID と照合し、不一致・取得失敗は `PEER_REJECTED` で拒否する（`session::run` を呼ばない）。加えてソケット
//! ディレクトリを自 UID 所有・`0700` に限り、`/` までの祖先を全て検査する。ログの置き場所（親〜`/`）も同じ規則で検査する
//! （symlink・自 UID でも root でもない所有者・グループ／他者が書けて sticky でないディレクトリがあれば拒否。別 UID が
//! 祖先を rename で差し替えて bind・chmod・削除・ログ作成を未検証の場所へ向けるのを防ぐ。祖先に symlink がある環境、
//! 例えば `/var/run` 経由は拒否される）。限界: (1) 同じ UID の別プロセスと root は接続できる（UID 一致のため）。
//! (2) 検査と bind の間の TOCTOU は、祖先が他 UID に差し替え不能であることと、所有者が自分で `0700` のディレクトリで
//! あることで抑える（同じ UID と root は差し替えられる）。
//!
//! accept は非ブロックの sleep ループで待つ（`sys::wait_fd` の別用途の呼び出しは承認範囲外のため。設計書 10.9）。
//! 1 接続を受けたらただちに listener を閉じてソケットファイルを消し、2 本目の接続は受けない。

mod error;

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub use error::{LaunchError, LaunchErrorCode};

use crate::log::LogSink;
use crate::session::{SessionEnd, SessionLimits, run as run_session};
use crate::sys;

/// `sun_path` に入るバイト数の上限（`UNIX_PATH_MAX` = 108 から終端 NUL を除いた値）。
/// 出典: Linux の `linux/un.h`（`#define UNIX_PATH_MAX 108`。2026-10-09 にローカルのヘッダで確認）。
pub const SUN_PATH_MAX: usize = 107;
/// 引数の個数の上限。
pub const MAX_ARGS: usize = 32;
const DEFAULT_MESSAGE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_ACCEPT_TIMEOUT_MS: u64 = 60_000;
const MAX_ACCEPT_TIMEOUT: Duration = Duration::from_secs(3600);
const ACCEPT_SLEEP: Duration = Duration::from_millis(10);
const MAX_PROC_STATUS_BYTES: u64 = 64 * 1024;

/// 検証済みの起動設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// bind するソケットの絶対パス（VMM 側から指定するパス）。
    pub socket: PathBuf,
    /// 作成するログファイルの絶対パス。
    pub log: PathBuf,
    /// セッションの時間制限。
    pub limits: SessionLimits,
    /// accept の期限。
    pub accept_timeout: Duration,
}

fn invalid() -> LaunchError {
    LaunchError::new(LaunchErrorCode::InvalidArgument)
}

fn parse_ms(v: &OsStr) -> Result<Duration, LaunchError> {
    let n: u64 = v
        .to_str()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok(Duration::from_millis(n))
}

/// コマンドライン引数（プログラム名を除く）を解析して検証する。
///
/// 必須: `--socket <絶対パス>`・`--log <絶対パス>`。任意: `--message-timeout-ms`（既定 5000）・`--idle-timeout-ms`
/// （既定 60000）・`--poll-slice-ms`・`--accept-timeout-ms`（既定 60000）。未知・重複・値の欠落・範囲外は
/// `INVALID_ARGUMENT`。パスの形式（絶対・成分・長さ）もここで検証する。
pub fn parse_args(args: &[OsString]) -> Result<Config, LaunchError> {
    if args.len() > MAX_ARGS || !args.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let (mut socket, mut logp) = (None, None);
    let (mut msg, mut idle, mut slice, mut acc) = (None, None, None, None);
    for pair in args.chunks(2) {
        let (Some(k), Some(v)) = (pair.first(), pair.get(1)) else {
            return Err(invalid());
        };
        let key = k.to_str().ok_or_else(invalid)?;
        let dup = match key {
            "--socket" => socket.replace(PathBuf::from(v)).is_some(),
            "--log" => logp.replace(PathBuf::from(v)).is_some(),
            "--message-timeout-ms" => msg.replace(parse_ms(v)?).is_some(),
            "--idle-timeout-ms" => idle.replace(parse_ms(v)?).is_some(),
            "--poll-slice-ms" => slice.replace(parse_ms(v)?).is_some(),
            "--accept-timeout-ms" => acc.replace(parse_ms(v)?).is_some(),
            _ => return Err(invalid()),
        };
        if dup {
            return Err(invalid());
        }
    }
    let socket = socket.ok_or_else(invalid)?;
    let log = logp.ok_or_else(invalid)?;
    let mut limits = SessionLimits::new(
        msg.unwrap_or(Duration::from_millis(DEFAULT_MESSAGE_TIMEOUT_MS)),
        idle.unwrap_or(Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS)),
    )
    .map_err(|_| invalid())?;
    if let Some(s) = slice {
        limits = limits.with_poll_slice(s).map_err(|_| invalid())?;
    }
    let accept_timeout = acc.unwrap_or(Duration::from_millis(DEFAULT_ACCEPT_TIMEOUT_MS));
    validate_accept_timeout(accept_timeout)?;
    validate_path(&socket)?;
    validate_path(&log)?;
    if socket.as_os_str().len() > SUN_PATH_MAX {
        return Err(LaunchError::new(LaunchErrorCode::PathTooLong));
    }
    check_path_collision(&socket, &log)?;
    Ok(Config {
        socket,
        log,
        limits,
        accept_timeout,
    })
}

/// accept の期限が 0 より大きく 1 時間以下であること（`Instant` の加算が panic しない範囲）。
/// `parse_args` と、公開フィールドから直接組み立てた `Config` を受ける `run` の両方で検証する。
fn validate_accept_timeout(t: Duration) -> Result<(), LaunchError> {
    if t.is_zero() || t > MAX_ACCEPT_TIMEOUT {
        return Err(invalid());
    }
    Ok(())
}

/// 絶対パスで、成分が `/` と通常の名前だけ（`.` / `..` なし）、NUL なし、ファイル名ありであること。
fn validate_path(p: &Path) -> Result<(), LaunchError> {
    if !p.is_absolute() {
        return Err(LaunchError::new(LaunchErrorCode::PathNotAbsolute));
    }
    // `Path::components` は `.` と連続する `/` を黙って正規化するため、生のバイト列を `/` で割って検査する。
    let raw = p.as_os_str().as_encoded_bytes();
    let bad = raw.contains(&0)
        || p.file_name().is_none()
        || raw
            .split(|b| *b == b'/')
            .skip(1)
            .any(|seg| seg.is_empty() || seg == b"." || seg == b"..")
        || p.components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)));
    if bad {
        return Err(LaunchError::new(LaunchErrorCode::PathInvalid));
    }
    Ok(())
}

/// 実行ユーザーの effective UID。std に `getuid` が無いので `/proc/self/status` の `Uid:` 行（2 番目の値）を読む。
fn effective_uid() -> Result<u32, LaunchError> {
    let err = || LaunchError::new(LaunchErrorCode::UidUnavailable);
    let mut text = String::new();
    File::open("/proc/self/status")
        .map_err(|_| err())?
        .take(MAX_PROC_STATUS_BYTES)
        .read_to_string(&mut text)
        .map_err(|_| err())?;
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or_else(err)?;
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .ok_or_else(err)
}

/// ソケットディレクトリ（ソケットパスの親）の検証。無ければ 1 段だけ `0700` で作る（再帰しない・umask の FFI なし）。
fn check_socket_dir(socket: &Path, uid: u32) -> Result<(), LaunchError> {
    let dir = socket
        .parent()
        .ok_or_else(|| LaunchError::new(LaunchErrorCode::PathInvalid))?;
    check_ancestors(dir, uid, false, LaunchErrorCode::SocketDirAncestorUnsafe)?;
    let mut meta = fs::symlink_metadata(dir);
    if matches!(&meta, Err(e) if e.kind() == ErrorKind::NotFound) {
        let grand_ok = dir.parent().is_some_and(|g| g.is_dir());
        if !grand_ok {
            return Err(LaunchError::new(LaunchErrorCode::SocketDirCreateFailed));
        }
        DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(|_| LaunchError::new(LaunchErrorCode::SocketDirCreateFailed))?;
        meta = fs::symlink_metadata(dir);
    }
    let meta = meta.map_err(|_| LaunchError::new(LaunchErrorCode::SocketDirNotDirectory))?;
    if meta.file_type().is_symlink() {
        return Err(LaunchError::new(LaunchErrorCode::SocketDirSymlink));
    }
    if !meta.file_type().is_dir() {
        return Err(LaunchError::new(LaunchErrorCode::SocketDirNotDirectory));
    }
    if meta.uid() != uid {
        return Err(LaunchError::new(LaunchErrorCode::SocketDirNotOwned));
    }
    if meta.mode() & 0o7777 != 0o700 {
        return Err(LaunchError::new(LaunchErrorCode::SocketDirNotPrivate));
    }
    Ok(())
}

/// `dir` の祖先（`/` まで。`include_self` が真なら `dir` 自身も）が、別 UID に差し替えられないことを検査する。
///
/// 各祖先は symlink でなく、自 UID または root 所有で、グループ／他者が書ける場合は sticky が立っていること
/// （sticky なら他ユーザーは自分の所有でない子を rename・削除できない）。存在しない祖先（`NotFound`）は差し替え対象が
/// 無いので飛ばす（作成の可否は呼び出し側が判断する）。それ以外の取得失敗は `unsafe_code` で拒否する。
fn check_ancestors(
    dir: &Path,
    uid: u32,
    include_self: bool,
    unsafe_code: LaunchErrorCode,
) -> Result<(), LaunchError> {
    let bad = || LaunchError::new(unsafe_code);
    for anc in dir.ancestors().skip(usize::from(!include_self)) {
        let meta = match fs::symlink_metadata(anc) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(bad()),
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(bad());
        }
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(bad());
        }
        let mode = meta.mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(bad());
        }
    }
    Ok(())
}

/// ログファイルの置き場所（親〜`/`）を検査する。ソケットと同じく別 UID が差し替えられる場所には作らない。
fn check_log_dir(log: &Path, uid: u32) -> Result<(), LaunchError> {
    let dir = log
        .parent()
        .ok_or_else(|| LaunchError::new(LaunchErrorCode::PathInvalid))?;
    check_ancestors(dir, uid, true, LaunchErrorCode::LogDirUnsafe)
}

/// ソケットとログのパスの衝突（同一パス）を拒否する。`parse_args` と、公開フィールドから組み立てた `Config` を受ける `run` の両方で使う。
fn check_path_collision(config_socket: &Path, config_log: &Path) -> Result<(), LaunchError> {
    if config_socket == config_log {
        return Err(LaunchError::new(LaunchErrorCode::PathInvalid));
    }
    Ok(())
}

/// 自分で bind したソケットだけを終了時に消す。既存のパスは消さない。
struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn open_log(path: &Path) -> Result<File, LaunchError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                LaunchError::new(LaunchErrorCode::LogPathExists)
            } else {
                LaunchError::new(LaunchErrorCode::LogOpenFailed)
            }
        })
}

/// 非ブロックの accept を期限まで試し直す。
fn accept_with_deadline(
    listener: &UnixListener,
    timeout: Duration,
) -> Result<std::os::unix::net::UnixStream, LaunchError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| LaunchError::new(LaunchErrorCode::AcceptFailed))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(LaunchError::new(LaunchErrorCode::AcceptTimeout));
                }
                thread::sleep(ACCEPT_SLEEP.min(left));
            }
            Err(_) => return Err(LaunchError::new(LaunchErrorCode::AcceptFailed)),
        }
    }
}

/// 起動して 1 接続を最後まで処理する。
pub fn run(config: &Config) -> Result<SessionEnd, LaunchError> {
    // `Config` は公開フィールドなので `parse_args` を経ない値が来うる。副作用の前に範囲を再検証する。
    validate_accept_timeout(config.accept_timeout)?;
    validate_path(&config.socket)?;
    validate_path(&config.log)?;
    if config.socket.as_os_str().len() > SUN_PATH_MAX {
        return Err(LaunchError::new(LaunchErrorCode::PathTooLong));
    }
    // 副作用（ディレクトリ作成・ログ作成）の前に衝突を拒否する。
    check_path_collision(&config.socket, &config.log)?;
    let uid = effective_uid()?;
    check_log_dir(&config.log, uid)?;
    check_socket_dir(&config.socket, uid)?;
    if fs::symlink_metadata(&config.socket).is_ok() {
        return Err(LaunchError::new(LaunchErrorCode::SocketPathExists));
    }
    let file = open_log(&config.log)?;
    let mut sink = LogSink::new(file);
    let result = serve(config, uid, &mut sink);
    if let Err(e) = &result {
        sink.write_line(&format!(
            "venus_jig event=launch_error code={}",
            e.code.as_str()
        ));
    }
    let (file, write_err) = sink.into_inner();
    let sync_failed = file.sync_all().is_err();
    if write_err.is_some() || sync_failed {
        return Err(LaunchError::new(LaunchErrorCode::LogWriteFailed));
    }
    result
}

fn serve(config: &Config, uid: u32, sink: &mut LogSink<File>) -> Result<SessionEnd, LaunchError> {
    let listener = UnixListener::bind(&config.socket)
        .map_err(|_| LaunchError::new(LaunchErrorCode::BindFailed))?;
    let guard = SocketGuard(config.socket.clone());
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| LaunchError::new(LaunchErrorCode::BindFailed))?;
    let stream = accept_with_deadline(&listener, config.accept_timeout)?;
    // 2 本目の接続は受けない（PoC の割り切り）。listener を閉じてソケットファイルを消す。
    drop(listener);
    drop(guard);
    stream
        .set_nonblocking(false)
        .map_err(|_| LaunchError::new(LaunchErrorCode::AcceptFailed))?;
    // 接続元の認証（PLUG-12 相当）: セッションに入る前に peer の UID を effective UID と照合する。不一致・取得失敗は拒否。
    match sys::peer_uid(stream.as_fd()) {
        Ok(peer) if peer == uid => {}
        _ => return Err(LaunchError::new(LaunchErrorCode::PeerRejected)),
    }
    sink.write_line("venus_jig event=accepted");
    let outcome = run_session(&stream, &config.limits, &mut |l| sink.write_line(l));
    outcome.map_err(|e| LaunchError {
        code: LaunchErrorCode::SessionFailed,
        cause: Some(e.code.as_str()),
    })
}

#[cfg(test)]
mod tests;
