//! containerd shim v2 バイナリのブートストラップ手順（start / delete / serve。CRI-5・TASK-62.7.1・MS-7・#872）。
//!
//! containerd は `containerd-shim-<name>-v2` を exec し、次の規約で shim を起動する
//! （containerd v2.1.4 の `core/runtime/v2/binary.go`・`pkg/shim/shim.go` で確認）。
//!
//! - `start`: argv は `-namespace <ns> -address <containerd.sock> -publish-binary <path> -id <id> [-debug] start`。
//!   containerd は stdout と stderr を 1 本にまとめて読み、全体をアドレス文字列（ttrpc の version 2）として扱う。
//!   このため成功時は stdout に改行なしの `unix://<path>` だけを書き、stderr へは何も書かない。
//!   常駐する子が containerd の出力 pipe を継承すると containerd の待ちが戻らなくなるため、子の stderr は null にする
//! - `delete`: argv は `-namespace -address -publish-binary -id <id> -bundle <path> [-debug] delete`。
//!   stdout は protobuf の `DeleteResponse` として復号される
//! - action なし: 本モジュール固有の内部モード（デーモン本体）。`start` が起動し、listener を stdin で受け取る
//!
//! 呼び出し元: `src/bin/shim_v2_main.rs` の薄い main。サービスの登録簿は呼び出し側が [`run`] に注入する。
//! 本番の `ContainerRuntime`（`CoreLifecycleRuntime`）は plugin-cri にしか無く、cri から plugin-cri への依存は
//! `tests/dependency_direction.rs` が禁じているため、cri の bin が登録できるのは `EmptyTaskService` だけになる
//! （`docs/architecture.md` は cri を「plugin バイナリから呼ばれる実装ライブラリ」としている。REPAIR-3）。
//!
//! 出力形式: 従来形式の `unix://<path>` を採る。JSON の BootstrapParams（version 3）は task API の版の決定（#669）に
//! 結びつくため採らない。
//!
//! socket の置き場所と権限: `FANDHE_CONTAINER_SHIM_SOCKET_DIR`（containerd から継承する環境変数で、containerd と
//! 同じ信頼度。主に試験用）か、既定の状態ルートの兄弟 `fandhe-container-shim`（rootful は `/run/fandhe-container-shim`）。
//! 状態ルートの中には置かない（`FileStateStore::open` は `@revision` 以外のエントリがあると新規ではないと判定するため）。
//! ディレクトリは 0700、socket は 0600。symlink・通常ファイル・緩い権限は fail-closed で拒否する。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
//! - peer UID の照合（SO_PEERCRED）。同じ uid と root からの接続は受ける
//! - State / Kill / Shutdown（#873）。デーモンの寿命は暫定で socket の `(dev, ino)` の生存確認（1 秒間隔）に結びつけ、
//!   #873 で Shutdown RPC に置き換えるか併用する
//! - delete での実行層のコンテナの後始末（本番の runtime の結線後）
//! - stdin の options・`-publish-binary` のイベント publish・デーモンのログ（`<bundle>/log`）・grouping
//! - Windows。`run` は `UNIMPLEMENTED`

use std::ffi::OsString;
use std::path::PathBuf;

use fandhe_container_oci::reference::Digest;

use super::service::ServiceRegistry;
use crate::error::CriError;

/// 起動バイナリ名。containerd の runtime_type `io.containerd.fandhe-container.v2` に対応する。
pub const SHIM_BINARY_NAME: &str = "containerd-shim-fandhe-container-v2";
/// socket 置き場所の上書き用の環境変数。
pub const SOCKET_DIR_ENV: &str = "FANDHE_CONTAINER_SHIM_SOCKET_DIR";
/// 既定の置き場所のディレクトリ名（状態ルートの兄弟）。
pub const SOCKET_DIR_NAME: &str = "fandhe-container-shim";
/// デーモンが準備完了を親へ知らせる固定行。
pub const READY_LINE: &str = "fandhe-container-shim-ready\n";
/// start が準備完了を待つ上限（REPAIR-5）。
pub const START_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// namespace / id の最大長（containerd の identifier 規則）。
const IDENTIFIER_MAX_LEN: usize = 76;
/// address の最大バイト数。
const ADDRESS_MAX_LEN: usize = 4096;
/// delete が返す終了コード（128 + SIGKILL。runc shim と同じ）。
const DELETE_EXIT_STATUS: u32 = 137;

/// containerd の identifier 規則（`^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$`、76 文字以内）を満たす検証済みの文字列。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimIdentifier(String);

impl ShimIdentifier {
    /// 検証して作る。違反は `INVALID_ARGUMENT`。
    pub fn parse(s: &str) -> Result<Self, CriError> {
        let bad = || CriError::invalid_argument("invalid identifier");
        if s.is_empty() || s.len() > IDENTIFIER_MAX_LEN {
            return Err(bad());
        }
        let mut prev_sep = true; // 先頭の区切り文字を拒否する
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() {
                prev_sep = false;
            } else if matches!(b, b'.' | b'_' | b'-') {
                if prev_sep {
                    return Err(bad());
                }
                prev_sep = true;
            } else {
                return Err(bad());
            }
        }
        if prev_sep {
            return Err(bad());
        }
        Ok(Self(s.to_owned()))
    }

    /// 文字列として返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 実行する操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShimAction {
    /// `start`: socket を作ってデーモンを起動し、アドレスを返す。
    Start,
    /// `delete`: socket を片付け、`DeleteResponse` を返す。
    Delete,
    /// action なし: デーモン本体（内部モード）。
    Serve,
    /// `-v`: 版を出力する。
    Version,
    /// `-info`: 未対応。
    Info,
}

/// 解釈済みの起動引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimInvocation {
    /// 操作。
    pub action: ShimAction,
    /// containerd の namespace。
    pub namespace: Option<ShimIdentifier>,
    /// shim の id。
    pub id: Option<ShimIdentifier>,
    /// containerd の ttrpc アドレス（絶対パス）。
    pub address: Option<PathBuf>,
    /// bundle のパス（delete のみ。絶対パスであることだけを検証し使わない）。
    pub bundle: Option<PathBuf>,
    /// `-debug`。
    pub debug: bool,
}

fn invalid(msg: &'static str) -> CriError {
    CriError::invalid_argument(msg)
}

/// Go の `strconv.ParseBool` と同じ語彙。
fn parse_bool(s: &str) -> Result<bool, CriError> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(invalid("invalid boolean flag value")),
    }
}

fn abs_path(s: &str, max: usize) -> Result<PathBuf, CriError> {
    let p = PathBuf::from(s);
    if !p.is_absolute() || s.len() > max || s.contains('\0') {
        return Err(invalid("path must be absolute and bounded"));
    }
    Ok(p)
}

/// Go の `flag` 互換で引数を解釈する（`-x v`・`-x=v`・`--x`・`--` を受ける。未知のフラグは拒否）。
///
/// `args` は argv[0] を除いたもの。
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<ShimInvocation, CriError> {
    let mut list = Vec::new();
    for a in args {
        list.push(
            a.into_string()
                .map_err(|_| invalid("argument is not valid UTF-8"))?,
        );
    }
    let mut namespace = None;
    let mut id = None;
    let mut address = None;
    let mut bundle = None;
    let (mut debug, mut version, mut info) = (false, false, false);
    let mut i = 0;
    while i < list.len() {
        let arg = &list[i];
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        i += 1;
        if arg == "--" {
            break;
        }
        let body = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .unwrap_or(arg);
        if body.is_empty() || body.starts_with('-') || body.starts_with('=') {
            return Err(invalid("bad flag syntax"));
        }
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (body, None),
        };
        match name {
            "debug" | "v" | "info" => {
                let val = match &inline {
                    Some(v) => parse_bool(v)?,
                    None => true,
                };
                match name {
                    "debug" => debug = val,
                    "v" => version = val,
                    _ => info = val,
                }
            }
            "namespace" | "id" | "address" | "publish-binary" | "bundle" => {
                let val = match inline {
                    Some(v) => v,
                    None => {
                        let v = list
                            .get(i)
                            .ok_or_else(|| invalid("flag needs a value"))?
                            .clone();
                        i += 1;
                        v
                    }
                };
                match name {
                    "namespace" => namespace = Some(ShimIdentifier::parse(&val)?),
                    "id" => id = Some(ShimIdentifier::parse(&val)?),
                    "address" => address = Some(abs_path(&val, ADDRESS_MAX_LEN)?),
                    "bundle" => bundle = Some(abs_path(&val, ADDRESS_MAX_LEN)?),
                    // publish-binary はイベント publish が範囲外のため受けて捨てる。
                    _ => {}
                }
            }
            _ => return Err(invalid("unknown flag")),
        }
    }
    let positional = &list[i..];
    let action = if version {
        ShimAction::Version
    } else if info {
        ShimAction::Info
    } else {
        match positional {
            [] => ShimAction::Serve,
            [w] if w == "start" => ShimAction::Start,
            [w] if w == "delete" => ShimAction::Delete,
            _ => return Err(invalid("unknown action")),
        }
    };
    if matches!(
        action,
        ShimAction::Start | ShimAction::Delete | ShimAction::Serve
    ) && (namespace.is_none() || id.is_none() || address.is_none())
    {
        return Err(invalid("namespace, id and address are required"));
    }
    Ok(ShimInvocation {
        action,
        namespace,
        id,
        address,
        bundle,
        debug,
    })
}

/// socket のファイル名（64 桁の hex）。`address`・`namespace`・`id` から決まる。
pub fn socket_file_name(inv: &ShimInvocation) -> Option<String> {
    let key = format!(
        "{}\0{}\0{}",
        inv.address.as_ref()?.to_str()?,
        inv.namespace.as_ref()?.as_str(),
        inv.id.as_ref()?.as_str()
    );
    let d = Digest::sha256_of(key.as_bytes());
    Some(d.as_str().strip_prefix("sha256:")?.to_owned())
}

/// 既定の置き場所: 状態ルートの兄弟ディレクトリ。
pub fn default_socket_dir(state_root: &std::path::Path) -> PathBuf {
    state_root.with_file_name(SOCKET_DIR_NAME)
}

/// 置き場所を解決する。上書き値は絶対パスで `.`・`..` の要素を含まないこと。
pub fn resolve_socket_dir(override_dir: Option<OsString>) -> Result<PathBuf, CriError> {
    match override_dir.filter(|v| !v.is_empty()) {
        Some(v) => {
            let p = PathBuf::from(v);
            // `Path::components` は途中の `.` を畳むため、字面で `.`・`..` の要素を拒否する。
            let ok = p.is_absolute()
                && p.to_str()
                    .is_some_and(|s| s.split('/').all(|e| e != "." && e != ".."));
            if !ok {
                return Err(invalid("socket dir override must be a clean absolute path"));
            }
            Ok(p)
        }
        None => {
            let root = fandhe_container_core::state_store::StateRoot::resolve(None)
                .map_err(|e| CriError::from(&e))?;
            Ok(default_socket_dir(root.path()))
        }
    }
}

/// `DeleteResponse` を符号化したバイト列（stdout へ書く）。
pub fn encode_delete_response() -> Vec<u8> {
    use prost::Message;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    super::task_api::DeleteResponse {
        pid: 0,
        exit_status: DELETE_EXIT_STATUS,
        exited_at: Some(super::task_api::Timestamp {
            seconds: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(now.subsec_nanos()).unwrap_or(0),
        }),
    }
    .encode_to_vec()
}

fn version_text() -> Vec<u8> {
    format!(
        "{SHIM_BINARY_NAME}:\n  Version: {}\n",
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

/// 操作を実行し、stdout へ書くバイト列を返す（serve は終了まで戻らず空を返す）。
///
/// `make_registry` は serve だけが呼ぶ（サービスの注入口。本モジュールの doc を参照）。
#[cfg(unix)]
pub fn run<F>(inv: ShimInvocation, make_registry: F) -> Result<Vec<u8>, CriError>
where
    F: FnOnce() -> Result<ServiceRegistry, CriError>,
{
    match inv.action {
        ShimAction::Version => Ok(version_text()),
        ShimAction::Info => Err(CriError::unimplemented("info is not supported")),
        ShimAction::Start => {
            let dir = resolve_socket_dir(std::env::var_os(SOCKET_DIR_ENV))?;
            unix_impl::run_start(&inv, &dir).map(String::into_bytes)
        }
        ShimAction::Delete => {
            let dir = resolve_socket_dir(std::env::var_os(SOCKET_DIR_ENV))?;
            unix_impl::run_delete(&inv, &dir)
        }
        ShimAction::Serve => {
            let dir = resolve_socket_dir(std::env::var_os(SOCKET_DIR_ENV))?;
            unix_impl::run_serve(&inv, &dir, make_registry).map(|()| Vec::new())
        }
    }
}

/// unix 以外では未実装（REPAIR-3）。
#[cfg(not(unix))]
pub fn run<F>(inv: ShimInvocation, _make_registry: F) -> Result<Vec<u8>, CriError>
where
    F: FnOnce() -> Result<ServiceRegistry, CriError>,
{
    match inv.action {
        ShimAction::Version => Ok(version_text()),
        _ => Err(CriError::unimplemented(
            "shim v2 bootstrap is available only on unix",
        )),
    }
}

#[cfg(unix)]
pub use unix_impl::{prepare_socket_dir, socket_path};

#[cfg(unix)]
mod unix_impl {
    use std::fs::{self, DirBuilder};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        READY_LINE, START_READY_TIMEOUT, ShimInvocation, encode_delete_response, socket_file_name,
    };
    use crate::error::{CriError, CriErrorCode};
    use crate::shim_v2::server::{ServerConfig, TtrpcServer};
    use crate::shim_v2::service::ServiceRegistry;

    /// sun_path の上限（NUL を除く）。
    #[cfg(target_os = "linux")]
    const SUN_PATH_MAX: usize = 107;
    #[cfg(not(target_os = "linux"))]
    const SUN_PATH_MAX: usize = 103;

    /// 既存 socket への接続試行の上限。
    const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
    /// 子の回収を待つ上限。
    const REAP_TIMEOUT: Duration = Duration::from_secs(5);
    /// デーモンが socket の生存を確かめる間隔。
    const WATCH_INTERVAL: Duration = Duration::from_secs(1);

    fn failed(msg: &'static str) -> CriError {
        CriError::failed_precondition(msg)
    }

    fn internal(msg: &'static str) -> CriError {
        CriError::internal(msg)
    }

    /// 置き場所のディレクトリを末尾 1 段だけ 0700 で作り、symlink でない・ディレクトリ・グループ/その他の権限なしを確かめる。
    pub fn prepare_socket_dir(dir: &Path) -> Result<(), CriError> {
        match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(failed("socket dir parent does not exist"));
            }
            Err(_) => return Err(internal("cannot create socket dir")),
        }
        let meta = fs::symlink_metadata(dir).map_err(|_| internal("cannot stat socket dir"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(failed("socket dir is not a plain directory"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(failed("socket dir permissions are too open"));
        }
        Ok(())
    }

    /// socket のパスを計算し、sun_path の長さを検査する。
    pub fn socket_path(dir: &Path, inv: &ShimInvocation) -> Result<PathBuf, CriError> {
        use std::os::unix::ffi::OsStrExt;
        let name =
            socket_file_name(inv).ok_or_else(|| CriError::invalid_argument("missing identity"))?;
        let p = dir.join(name);
        if p.as_os_str().as_bytes().len() > SUN_PATH_MAX {
            return Err(failed("socket path is too long"));
        }
        Ok(p)
    }

    enum Existing {
        None,
        Live,
        Stale,
    }

    /// 既存のパスを調べる。socket 以外は拒否し、残骸は `Stale`。
    fn inspect_existing(path: &Path) -> Result<Existing, CriError> {
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::None),
            Err(_) => return Err(internal("cannot stat socket path")),
        };
        if !meta.file_type().is_socket() {
            return Err(failed("socket path exists and is not a socket"));
        }
        let (tx, rx) = mpsc::channel();
        let p = path.to_path_buf();
        thread::spawn(move || {
            let _ = tx.send(UnixStream::connect(p).map(drop));
        });
        match rx.recv_timeout(PROBE_TIMEOUT) {
            Ok(Ok(())) => Ok(Existing::Live),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(Existing::Stale),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(Existing::None),
            _ => Err(CriError::unavailable("cannot probe existing socket")),
        }
    }

    fn reap(child: &mut Child) {
        let _ = child.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// start の本体。`unix://<path>` を返す。
    pub fn run_start(inv: &ShimInvocation, dir: &Path) -> Result<String, CriError> {
        prepare_socket_dir(dir)?;
        let path = socket_path(dir, inv)?;
        let address = format!("unix://{}", path.display());
        match inspect_existing(&path)? {
            Existing::Live => return Ok(address),
            Existing::Stale => {
                fs::remove_file(&path).map_err(|_| internal("cannot remove stale socket"))?;
            }
            Existing::None => {}
        }
        let listener = UnixListener::bind(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                CriError::already_exists("socket already exists")
            } else {
                internal("cannot bind socket")
            }
        })?;
        match spawn_daemon(inv, &path, listener) {
            Ok(()) => Ok(address),
            Err(e) => {
                let _ = fs::remove_file(&path);
                Err(e)
            }
        }
    }

    fn spawn_daemon(
        inv: &ShimInvocation,
        path: &Path,
        listener: UnixListener,
    ) -> Result<(), CriError> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| internal("cannot set socket permissions"))?;
        // socket は自分が作ったので所有者は euid。ディレクトリの所有者と照合する（geteuid の FFI を使わない）。
        let sock_uid = fs::symlink_metadata(path)
            .map_err(|_| internal("cannot stat socket"))?
            .uid();
        let dir_uid = path
            .parent()
            .and_then(|d| fs::symlink_metadata(d).ok())
            .map(|m| m.uid());
        if dir_uid != Some(sock_uid) {
            return Err(failed("socket owner differs from socket dir owner"));
        }
        let exe = std::env::current_exe().map_err(|_| internal("cannot resolve own executable"))?;
        let mut cmd = Command::new(exe);
        // 検証済みの値から組み直す（生の argv は中継しない）。
        let (Some(ns), Some(id), Some(addr)) = (&inv.namespace, &inv.id, &inv.address) else {
            return Err(CriError::invalid_argument("missing identity"));
        };
        cmd.arg("-namespace").arg(ns.as_str());
        cmd.arg("-id").arg(id.as_str());
        cmd.arg("-address").arg(addr);
        if inv.debug {
            cmd.arg("-debug");
        }
        cmd.stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|_| internal("cannot spawn shim daemon"))?;
        drop(cmd);
        let Some(stdout) = child.stdout.take() else {
            reap(&mut child);
            return Err(internal("daemon stdout is unavailable"));
        };
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = Vec::new();
            let r = BufReader::new(stdout.take(64)).read_until(b'\n', &mut line);
            let _ = tx.send(r.map(|_| line));
        });
        match rx.recv_timeout(START_READY_TIMEOUT) {
            Ok(Ok(line)) if line == READY_LINE.as_bytes() => Ok(()),
            Err(_) => {
                reap(&mut child);
                Err(CriError::timeout("shim daemon did not become ready"))
            }
            _ => {
                reap(&mut child);
                Err(internal("shim daemon exited before becoming ready"))
            }
        }
    }

    /// delete の本体。`DeleteResponse` のバイト列を返す。冪等。
    pub fn run_delete(inv: &ShimInvocation, dir: &Path) -> Result<Vec<u8>, CriError> {
        let path = socket_path(dir, inv)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                fs::remove_file(&path).map_err(|_| internal("cannot remove socket"))?;
            }
            Ok(_) => return Err(failed("socket path exists and is not a socket")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(internal("cannot stat socket path")),
        }
        Ok(encode_delete_response())
    }

    /// デーモン本体。stdin の listener を検証して serve し、socket が消えたら終わる。
    pub fn run_serve<F>(inv: &ShimInvocation, dir: &Path, make_registry: F) -> Result<(), CriError>
    where
        F: FnOnce() -> Result<ServiceRegistry, CriError>,
    {
        let expected = socket_path(dir, inv)?;
        let owned = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| internal("cannot duplicate stdin"))?;
        let listener = UnixListener::from(owned);
        let addr = listener
            .local_addr()
            .map_err(|_| failed("stdin is not a unix socket"))?;
        if addr.as_pathname() != Some(expected.as_path()) {
            return Err(failed("stdin socket does not match the expected path"));
        }
        let ident = |p: &Path| fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()));
        let first = ident(&expected).ok_or_else(|| failed("socket path is missing"))?;
        let registry = make_registry()?;
        let handle = TtrpcServer::new(registry, ServerConfig::default())
            .serve(listener)
            .map_err(|_| internal("cannot start ttrpc server"))?;
        {
            let mut out = std::io::stdout();
            out.write_all(READY_LINE.as_bytes())
                .and_then(|()| out.flush())
                .map_err(|_| internal("cannot signal readiness"))?;
        }
        while ident(&expected) == Some(first) {
            thread::sleep(WATCH_INTERVAL);
        }
        handle
            .shutdown()
            .map_err(|_| CriError::new(CriErrorCode::Timeout, "server shutdown timed out"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn code(r: Result<ShimInvocation, CriError>) -> CriErrorCode {
        r.unwrap_err().code()
    }

    /// CRI-5・#872: containerd の実際の start の argv を解釈できる。
    #[test]
    fn cri5_872_parse_containerd_start_argv() {
        let inv = parse_args(args(&[
            "-namespace",
            "k8s.io",
            "-address",
            "/run/containerd/containerd.sock",
            "-publish-binary",
            "/usr/bin/containerd",
            "-id",
            "abc123",
            "-debug",
            "start",
        ]))
        .unwrap();
        assert_eq!(inv.action, ShimAction::Start);
        assert_eq!(inv.namespace.unwrap().as_str(), "k8s.io");
        assert_eq!(inv.id.unwrap().as_str(), "abc123");
        assert_eq!(
            inv.address.unwrap(),
            PathBuf::from("/run/containerd/containerd.sock")
        );
        assert!(inv.debug);
    }

    /// CRI-5・#872: delete の argv（-bundle つき）。
    #[test]
    fn cri5_872_parse_containerd_delete_argv() {
        let inv = parse_args(args(&[
            "-namespace",
            "default",
            "-address",
            "/a.sock",
            "-publish-binary",
            "/p",
            "-id",
            "c1",
            "-bundle",
            "/b",
            "delete",
        ]))
        .unwrap();
        assert_eq!(inv.action, ShimAction::Delete);
        assert_eq!(inv.bundle.unwrap(), PathBuf::from("/b"));
    }

    /// CRI-5・#872: Go の flag の書き方（`=`・`--`・bool の値・`--` 終端）。
    #[test]
    fn cri5_872_parse_flag_styles() {
        let inv = parse_args(args(&[
            "--namespace=ns",
            "-id=x",
            "--address",
            "/s",
            "-debug=false",
            "--",
            "start",
        ]))
        .unwrap();
        assert_eq!(inv.action, ShimAction::Start);
        assert!(!inv.debug);
        assert_eq!(inv.id.unwrap().as_str(), "x");
    }

    /// CRI-5・#872: 未知のフラグ・値の欠落・未知の action・位置引数 2 個・必須欠落を拒否する。
    #[test]
    fn cri5_872_parse_rejects_bad_input() {
        let base = ["-namespace", "n", "-id", "i", "-address", "/s"];
        let with = |extra: &[&str]| {
            let mut v: Vec<&str> = base.to_vec();
            v.extend_from_slice(extra);
            args(&v)
        };
        let inv = CriErrorCode::InvalidArgument;
        assert_eq!(code(parse_args(with(&["-bogus", "start"]))), inv);
        assert_eq!(code(parse_args(with(&["-bundle"]))), inv);
        assert_eq!(code(parse_args(with(&["stop"]))), inv);
        assert_eq!(code(parse_args(with(&["start", "delete"]))), inv);
        assert_eq!(code(parse_args(with(&["-debug=maybe", "start"]))), inv);
        assert_eq!(code(parse_args(args(&["-id", "i", "start"]))), inv);
        assert_eq!(
            code(parse_args(args(&[
                "-namespace",
                "n",
                "-id",
                "i",
                "-address",
                "rel",
                "start"
            ]))),
            inv
        );
    }

    /// CRI-5・#872: identifier の境界値。
    #[test]
    fn cri5_872_identifier_bounds() {
        assert!(ShimIdentifier::parse(&"a".repeat(76)).is_ok());
        assert!(ShimIdentifier::parse(&"a".repeat(77)).is_err());
        for bad in ["", "a..b", "-a", "a-", "a/b", "a b", ".a"] {
            assert!(ShimIdentifier::parse(bad).is_err(), "{bad}");
        }
        for ok in ["a", "k8s.io", "a_b-c.d", "A1"] {
            assert!(ShimIdentifier::parse(ok).is_ok(), "{ok}");
        }
    }

    /// CRI-5・#872: `-v` と `-info`。
    #[test]
    fn cri5_872_version_and_info() {
        assert_eq!(
            parse_args(args(&["-v"])).unwrap().action,
            ShimAction::Version
        );
        assert_eq!(
            parse_args(args(&["-info"])).unwrap().action,
            ShimAction::Info
        );
        let out = run(parse_args(args(&["-v"])).unwrap(), || {
            Ok(ServiceRegistry::new())
        })
        .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with(SHIM_BINARY_NAME)
        );
    }

    fn start_inv(id: &str) -> ShimInvocation {
        parse_args(args(&[
            "-namespace",
            "n",
            "-id",
            id,
            "-address",
            "/s",
            "start",
        ]))
        .unwrap()
    }

    /// CRI-5・#872: socket 名は 64 桁の hex で決定的。
    #[test]
    fn cri5_872_socket_name_is_stable_hex() {
        let a = socket_file_name(&start_inv("i")).unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, socket_file_name(&start_inv("i")).unwrap());
        assert_ne!(a, socket_file_name(&start_inv("j")).unwrap());
    }

    /// CRI-5・#872: 置き場所の解決（上書きの検証と既定の兄弟配置）。
    #[test]
    fn cri5_872_socket_dir_resolution() {
        assert_eq!(
            resolve_socket_dir(Some("/tmp/x".into())).unwrap(),
            PathBuf::from("/tmp/x")
        );
        for bad in ["rel/x", "/tmp/../x", "/tmp/./x"] {
            assert_eq!(
                resolve_socket_dir(Some(bad.into())).unwrap_err().code(),
                CriErrorCode::InvalidArgument,
                "{bad}"
            );
        }
        assert_eq!(
            default_socket_dir(std::path::Path::new("/run/fandhe-container")),
            PathBuf::from("/run/fandhe-container-shim")
        );
    }

    /// CRI-5・#872: delete の応答は pid=0・exit_status=137・exited_at あり。
    #[test]
    fn cri5_872_delete_response_encoding() {
        use prost::Message;
        let r = crate::shim_v2::DeleteResponse::decode(&encode_delete_response()[..]).unwrap();
        assert_eq!((r.pid, r.exit_status), (0, 137));
        assert!(r.exited_at.is_some());
    }

    /// CRI-5・#872: パス長の上限（unix）。
    #[cfg(unix)]
    #[test]
    fn cri5_872_socket_path_length_limit() {
        let inv = start_inv("i");
        let ok = PathBuf::from(format!("/{}", "d".repeat(20)));
        assert!(socket_path(&ok, &inv).is_ok());
        let long = PathBuf::from(format!("/{}", "d".repeat(60)));
        assert_eq!(
            socket_path(&long, &inv).unwrap_err().code(),
            CriErrorCode::FailedPrecondition
        );
    }
}
