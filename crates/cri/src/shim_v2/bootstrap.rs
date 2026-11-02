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
//! ディレクトリは 0700、socket は 0600。symlink・通常ファイル・緩い権限・実効 uid と異なる所有者は fail-closed で拒否する
//! （bind・再利用・delete のいずれの前にも検査する。PLUG-12）。
//!
//! 排他（REPAIR-5）: 同一 id の `start` / `delete` は `<socket 名>.lock` への `flock`（期限つきの `try_lock` 再試行）で
//! 直列化し、stale 判定・削除・bind・READY 確認をプロセス間で排他する。失敗時に消すのは自分が bind した socket だけ。
//!
//! peer UID（PLUG-12）: デーモンは accept 直後に `SO_PEERCRED` / `getpeereid` で接続元を照合し、
//! 実効 uid と root（0）以外を切断する。拒否は理由（許可外 uid・uid 取得失敗）を区別して、状態ルート直下の
//! `@audit.log`（Linux は core の `FileAuditSink` を包んだ `ControlAuditRelay` 経由。単一スレッドの間に作る）へ
//! 監査レコードとして届ける（SEC-4）。置き場所の上書き（試験用）があるときだけ、状態ルートを開けなくても起動する。
//! 非 Linux は記録先を持たない（plugin-cri の main と同じ。#2430）。
//!
//! 計測（REPAIR-4）: `start` / `delete` / デーモンの ttrpc は、結果と所要時間を置き場所の `ops.log`
//! （0600・JSON Lines・1 MiB で `ops.log.1` へ回す）へ追記する。stdout / stderr は汚さない。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
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
/// `args` は `argv[0]` を除いたもの。
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

/// 字面で要素を分ける区切り文字。Windows は `\\` も区切りのため、`C:\\tmp\\..\\x` を見逃さない（PLUG-12・#872）。
#[cfg(windows)]
const SEPARATORS: [char; 2] = ['/', '\\'];
/// Unix では `\\` はファイル名の一部なので `/` のみで分ける。
#[cfg(not(windows))]
const SEPARATORS: [char; 1] = ['/'];

/// 置き場所を解決する。上書き値は絶対パスで `.`・`..` の要素を含まないこと。
pub fn resolve_socket_dir(override_dir: Option<OsString>) -> Result<PathBuf, CriError> {
    match override_dir.filter(|v| !v.is_empty()) {
        Some(v) => {
            let p = PathBuf::from(v);
            // `Path::components` は途中の `.` を畳むため、字面で `.`・`..` の要素を拒否する。
            let ok = p.is_absolute()
                && p.to_str()
                    .is_some_and(|s| s.split(SEPARATORS).all(|e| e != "." && e != ".."));
            if !ok {
                return Err(invalid("socket dir override must be a clean absolute path"));
            }
            // 要素から組み直して末尾・重複した区切り文字を取り除く。`link/` のような末尾の区切り文字があると
            // `lstat` は最終要素の symlink を辿り、`check_socket_dir` の symlink 検査をすり抜けるため
            // （PLUG-12。core の `StateRoot::from_override` と同じ対処）。
            Ok(p.components().collect())
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
            unix_impl::start_recorded(&inv, &dir).map(String::into_bytes)
        }
        ShimAction::Delete => {
            let dir = resolve_socket_dir(std::env::var_os(SOCKET_DIR_ENV))?;
            unix_impl::delete_recorded(&inv, &dir)
        }
        ShimAction::Serve => {
            let over = std::env::var_os(SOCKET_DIR_ENV);
            let overridden = over.as_ref().is_some_and(|v| !v.is_empty());
            let dir = resolve_socket_dir(over)?;
            let audit = unix_impl::open_audit_sink(overridden)?;
            unix_impl::run_serve(&inv, &dir, audit, make_registry).map(|()| Vec::new())
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
    use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{
        DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        READY_LINE, START_READY_TIMEOUT, ShimInvocation, encode_delete_response, socket_file_name,
    };
    use crate::error::{CriError, CriErrorCode};
    use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
    use crate::shim_v2::server::{ServerConfig, TtrpcServer};
    use crate::shim_v2::service::ServiceRegistry;
    use fandhe_container_core::audit_log::AuditSink;
    #[cfg(target_os = "linux")]
    use fandhe_container_core::audit_log::{ControlAuditRelay, FileAuditSink};

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
    /// 同一 id の排他ロックを待つ上限（REPAIR-5）。
    const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
    /// ロックの再試行間隔。
    const LOCK_RETRY: Duration = Duration::from_millis(20);
    /// 計測ログの回転サイズ。
    const OPS_LOG_MAX_BYTES: u64 = 1024 * 1024;
    /// 計測ログのロックを待つ上限（REPAIR-5）。
    const OPS_LOG_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
    /// 計測ログのファイル名。
    const OPS_LOG_NAME: &str = "ops.log";

    fn failed(msg: &'static str) -> CriError {
        CriError::failed_precondition(msg)
    }

    fn internal(msg: &'static str) -> CriError {
        CriError::internal(msg)
    }

    /// 置き場所のディレクトリを末尾 1 段だけ 0700 で作り、symlink でない・ディレクトリ・グループ/その他の権限なしを確かめる。
    ///
    /// 未作成のときは、**作成より前に**親と全祖先の信頼性を検査する(`check_ancestors` の `pending` 経路)。作成後の検査だけだと、
    /// 祖先が別ユーザーの symlink のとき、参照先にディレクトリを作ってから拒否することになり、生成物が残る(root 実行では
    /// 作成先を誘導できる。SEC-1・PLUG-12)。検査を通った祖先は現在のユーザーと root しか rename・差し替えできない
    /// (スティッキーの例外も子が自分の所有の場合のみ)ため、検査から `create` までの間に別ユーザーが経路を変えられず、
    /// fd 基準の `mkdirat` を足さなくても検査と作成の間の差し替えは閉じる(後続の lock・socket の操作も同じ前提)。
    pub fn prepare_socket_dir(dir: &Path) -> Result<(), CriError> {
        match fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => check_ancestors(dir, true)?,
            Err(_) => return Err(internal("cannot stat socket dir")),
        }
        match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(failed("socket dir parent does not exist"));
            }
            Err(_) => return Err(internal("cannot create socket dir")),
        }
        check_socket_dir(dir)
    }

    /// 既存のディレクトリが symlink でない・ディレクトリ・グループ/その他の権限なしであることを確かめる。
    fn check_socket_dir(dir: &Path) -> Result<(), CriError> {
        let meta = fs::symlink_metadata(dir).map_err(|_| internal("cannot stat socket dir"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(failed("socket dir is not a plain directory"));
        }
        if meta.uid() != crate::sys::effective_uid() {
            return Err(failed("socket dir is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(failed("socket dir permissions are too open"));
        }
        // 最終ディレクトリ自身の拡張 ACL（macOS。mode 0700 でも別ユーザーへ変更権限を与えられる）。
        reject_extended_acl(dir)?;
        check_ancestors(dir, false)
    }

    /// 祖先ディレクトリの信頼性を確かめる（PLUG-12・SEC-1）。最終要素だけの検査では、祖先を持つ別ユーザーが
    /// 検証後にディレクトリを rename して差し替え、後続の lock・socket・ops.log の操作（パスの再解決）を別の場所へ
    /// 向けられるため、パスを変更できる主体を現在のユーザーと root に限る。
    ///
    /// 方式の選択（P0-2）: 後続処理は元の `dir` を再解決するので、解決後の正規パスだけを検査すると、
    /// 「別ユーザー所有の親の中にある root 所有の symlink」が信頼できる場所を指す構成を通してしまい、親の所有者が
    /// symlink を rename・置換して操作先を差し替えられる。検証済み正規パスを固定して使う案（b）は lock・socket・
    /// ops.log・子プロセスへ渡す経路の全てを書き換える必要があり漏れが残りうるため、より閉じる案（a）として
    /// 元の経路の全祖先にも同じ検査（所有者・書き込み権限・ACL）を適用する。
    /// - 元のパスの祖先の symlink は root 所有のもの（macOS の `/tmp` → `/private/tmp` 等）だけ許す
    /// - 元のパスの symlink でない祖先と解決後の祖先は、所有者が現在のユーザーか root であること
    /// - 他ユーザーが書ける祖先は、スティッキーかつ経路上の子が現在のユーザー所有（他人が rename・削除できない）の場合だけ許す
    /// - macOS では拡張 ACL を持つ祖先・判定できない祖先も拒否する（mode bits を迂回して変更権限を与えうる）
    ///
    /// `pending` が true のときは `dir` がまだ無く、これから現在のユーザーの所有で作る(作成前の検査)。`dir` の存在を
    /// 前提にせず、`dir` を現在のユーザー所有の子として扱い、正規パスは親の正規化に `dir` の名前を足して組む。
    fn check_ancestors(dir: &Path, pending: bool) -> Result<(), CriError> {
        let euid = crate::sys::effective_uid();
        let owned_by_us = |p: &Path| {
            (pending && p == dir) || fs::symlink_metadata(p).is_ok_and(|c| c.uid() == euid)
        };
        let mut lexical_child = dir;
        for a in dir.ancestors().skip(1) {
            // 相対パスの終端（空の祖先）は正規パス側の検査（カレントディレクトリ以上）が担う。
            if a.as_os_str().is_empty() {
                break;
            }
            let m = match fs::symlink_metadata(a) {
                Ok(m) => m,
                Err(e) if pending && e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(failed("socket dir parent does not exist"));
                }
                Err(_) => return Err(internal("cannot stat socket dir ancestor")),
            };
            if m.file_type().is_symlink() {
                if m.uid() != 0 {
                    return Err(failed("socket dir ancestor is a symlink not owned by root"));
                }
            } else {
                check_ancestor_dir(&m, a, euid, owned_by_us(lexical_child))?;
            }
            lexical_child = a;
        }
        let canon = if pending {
            let parent = match dir.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            let name = dir
                .file_name()
                .ok_or_else(|| failed("socket dir has no final component"))?;
            fs::canonicalize(parent)
                .map_err(|_| internal("cannot resolve socket dir"))?
                .join(name)
        } else {
            fs::canonicalize(dir).map_err(|_| internal("cannot resolve socket dir"))?
        };
        let pending_path = canon.as_path();
        let owned_canon = |p: &Path| {
            (pending && p == pending_path) || fs::symlink_metadata(p).is_ok_and(|c| c.uid() == euid)
        };
        let mut child = pending_path;
        for a in canon.ancestors().skip(1) {
            let m =
                fs::symlink_metadata(a).map_err(|_| internal("cannot stat socket dir ancestor"))?;
            check_ancestor_dir(&m, a, euid, owned_canon(child))?;
            child = a;
        }
        Ok(())
    }

    /// 祖先ディレクトリ 1 つの検査（種別・所有者・他者の書き込み権限・拡張 ACL）。
    /// `child_owned` は経路上の子が現在のユーザー所有か（スティッキーの許可条件）。
    fn check_ancestor_dir(
        m: &fs::Metadata,
        path: &Path,
        euid: u32,
        child_owned: bool,
    ) -> Result<(), CriError> {
        ancestor_mode_verdict(m.is_dir(), m.uid(), m.mode(), euid, child_owned).map_err(failed)?;
        reject_extended_acl(path)
    }

    /// 祖先ディレクトリの mode・所有者の判定（純粋関数。PLUG-12・SEC-1）。
    pub(super) fn ancestor_mode_verdict(
        is_dir: bool,
        uid: u32,
        mode: u32,
        euid: u32,
        child_owned: bool,
    ) -> Result<(), &'static str> {
        if !is_dir {
            return Err("socket dir ancestor is not a directory");
        }
        if uid != euid && uid != 0 {
            return Err("socket dir ancestor is owned by another user");
        }
        if mode & 0o022 != 0 && (mode & 0o1000 == 0 || !child_owned) {
            return Err("socket dir ancestor is writable by other users");
        }
        Ok(())
    }

    /// macOS の拡張 ACL（mode bits を迂回して他ユーザーへ変更権限を与えられる）が付いていたら拒否する。
    /// 中身は解釈せず、付いているだけ・判定できないときも拒否する（fail-closed。PLUG-12・SEC-1）。
    #[cfg(target_os = "macos")]
    fn reject_extended_acl(path: &Path) -> Result<(), CriError> {
        match crate::sys::has_extended_acl(path) {
            Ok(false) => Ok(()),
            Ok(true) => Err(failed("socket dir or ancestor has an extended ACL")),
            Err(()) => Err(internal("cannot inspect the ACL of the socket dir")),
        }
    }

    /// macOS 以外では対象外（Linux は mode bits と所有者で判定する）。
    #[cfg(not(target_os = "macos"))]
    fn reject_extended_acl(_path: &Path) -> Result<(), CriError> {
        Ok(())
    }

    /// 同一 id の排他ロック。Drop で解放する。
    struct IdLock {
        _file: File,
        path: PathBuf,
    }

    /// `<socket 名>.lock` を `flock` で取る。期限（`LOCK_TIMEOUT`）内に取れなければ `TIMEOUT`。
    /// 取得後にパスの `(dev, ino)` が開いた fd と一致することを確かめ、delete が消した lock を掴んだ場合は取り直す。
    fn acquire_lock(dir: &Path, inv: &ShimInvocation) -> Result<IdLock, CriError> {
        let name =
            socket_file_name(inv).ok_or_else(|| CriError::invalid_argument("missing identity"))?;
        let path = dir.join(format!("{name}.lock"));
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(|_| internal("cannot open lock file"))?;
            let meta = file
                .metadata()
                .map_err(|_| internal("cannot stat lock file"))?;
            if !meta.is_file() || meta.uid() != crate::sys::effective_uid() {
                return Err(failed(
                    "lock file is not a regular file owned by the current user",
                ));
            }
            match file.try_lock() {
                Ok(()) => {
                    let same = fs::symlink_metadata(&path)
                        .is_ok_and(|m| (m.dev(), m.ino()) == (meta.dev(), meta.ino()));
                    if same {
                        return Ok(IdLock { _file: file, path });
                    }
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(_)) => return Err(internal("cannot lock the shim id")),
            }
            if Instant::now() >= deadline {
                return Err(CriError::timeout("timed out waiting for the shim lock"));
            }
            thread::sleep(LOCK_RETRY);
        }
    }

    /// `(dev, ino)`。自分が作ったパスの同一性確認に使う。
    fn ident_of(p: &Path) -> Option<(u64, u64)> {
        fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()))
    }

    /// 計測の記録先（`ops.log` への JSON Lines 追記。REPAIR-4）。失敗は握りつぶし、本来の操作結果を変えない。
    /// 行の語彙は固定で、パス・id・要求の中身は書かない。
    pub struct OpLogRecorder {
        path: PathBuf,
    }

    impl OpLogRecorder {
        /// 置き場所のディレクトリを指定して作る（ファイルは記録時に開く）。
        pub fn new(dir: &Path) -> Self {
            Self {
                path: dir.join(OPS_LOG_NAME),
            }
        }

        fn append(&self, line: &str) -> std::io::Result<()> {
            // 置き場所が検証に通らない（symlink・他人の所有・広い権限）ときは、そのパスへ書かない（PLUG-12）。
            if let Some(dir) = self.path.parent() {
                check_socket_dir(dir).map_err(|_| std::io::Error::other("unsafe ops log dir"))?;
            }
            // 回転判定から追記までをプロセス間で直列化する（共有ログの上書きによる記録の欠落を防ぐ。REPAIR-4）。
            let _guard = self.lock()?;
            if let Ok(m) = fs::symlink_metadata(&self.path) {
                if !m.file_type().is_file() || m.uid() != crate::sys::effective_uid() {
                    return Err(std::io::Error::other("unsafe ops log"));
                }
                if m.len() >= OPS_LOG_MAX_BYTES {
                    let mut rotated = self.path.clone().into_os_string();
                    rotated.push(".1");
                    fs::rename(&self.path, rotated)?;
                }
            }
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)?;
            f.write_all(line.as_bytes())
        }

        /// `ops.log.lock` への `flock`（期限つきの `try_lock` 再試行。REPAIR-5）。取れなければ記録を諦める。
        fn lock(&self) -> std::io::Result<File> {
            let mut name = self.path.clone().into_os_string();
            name.push(".lock");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(PathBuf::from(name))?;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.uid() != crate::sys::effective_uid() {
                return Err(std::io::Error::other("unsafe ops log lock"));
            }
            let deadline = Instant::now() + OPS_LOG_LOCK_TIMEOUT;
            loop {
                match file.try_lock() {
                    Ok(()) => return Ok(file),
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Error(e)) => return Err(e),
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::other("ops log lock timed out"));
                }
                thread::sleep(LOCK_RETRY);
            }
        }
    }

    impl CriOpRecorder for OpLogRecorder {
        fn record_cri_op(&self, sample: &CriOpSample) {
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let line = format!(
                "{{\"ts\":{at},\"op\":\"{}\",\"outcome\":\"{}\",\"code\":\"{:?}\",\"latency_us\":{}}}\n",
                sample.kind().as_str(),
                sample.outcome().as_str(),
                sample.code(),
                sample.latency().as_micros()
            );
            let _ = self.append(&line);
        }
    }

    /// 操作の結果と所要時間を記録する。
    fn record<T>(dir: &Path, kind: CriOpKind, r: &Result<T, CriError>, started: Instant) {
        let code = match r {
            Ok(_) => tonic::Code::Ok,
            Err(e) => e.code().grpc_code(),
        };
        let sample = CriOpSample::new(kind, code, started.elapsed());
        OpLogRecorder::new(dir).record_cri_op(&sample);
    }

    /// `start` を計測つきで実行する。
    pub fn start_recorded(inv: &ShimInvocation, dir: &Path) -> Result<String, CriError> {
        let started = Instant::now();
        let r = run_start(inv, dir);
        record(dir, CriOpKind::ShimV2Start, &r, started);
        r
    }

    /// `delete` を計測つきで実行する。
    pub fn delete_recorded(inv: &ShimInvocation, dir: &Path) -> Result<Vec<u8>, CriError> {
        let started = Instant::now();
        let r = run_delete(inv, dir);
        record(dir, CriOpKind::ShimV2Delete, &r, started);
        r
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
        if meta.uid() != crate::sys::effective_uid() {
            return Err(failed("socket is not owned by the current user"));
        }
        let (tx, rx) = mpsc::channel();
        let p = path.to_path_buf();
        // スレッドを作れない資源不足は panic させず、呼び出し側へエラーで返す。
        thread::Builder::new()
            .name("shim-probe".into())
            .spawn(move || {
                let _ = tx.send(UnixStream::connect(p).map(drop));
            })
            .map_err(|_| internal("cannot spawn socket probe thread"))?;
        match rx.recv_timeout(PROBE_TIMEOUT) {
            Ok(Ok(())) => {
                // 再利用する socket は 0600 であること（残骸の置き換えは権限を問わない）。
                if meta.mode() & 0o077 != 0 {
                    return Err(failed("live socket permissions are too open"));
                }
                Ok(Existing::Live)
            }
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
        let _lock = acquire_lock(dir, inv)?;
        match inspect_existing(&path)? {
            Existing::Live => return Ok(address),
            Existing::Stale => {
                fs::remove_file(&path).map_err(|_| internal("cannot remove stale socket"))?;
            }
            Existing::None => {}
        }
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // 同一 id の start が同時に走った場合は、先発が生きていれば冪等に同じ address を返す。
                return match inspect_existing(&path)? {
                    Existing::Live => Ok(address),
                    _ => Err(CriError::already_exists("socket already exists")),
                };
            }
            Err(_) => return Err(internal("cannot bind socket")),
        };
        let mine = ident_of(&path);
        match spawn_daemon(inv, &path, listener) {
            Ok(()) => Ok(address),
            Err(e) => {
                // 自分が bind した socket だけを消す（別の実体に置き換わっていたら触らない）。
                if mine.is_some() && ident_of(&path) == mine {
                    let _ = fs::remove_file(&path);
                }
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
        if dir_uid != Some(sock_uid) || sock_uid != crate::sys::effective_uid() {
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
        // 起動済みのデーモンがあるので、スレッドを作れなければ回収してからエラーで返す
        // （panic で reap と socket の後始末を迂回しない）。
        let spawned = thread::Builder::new()
            .name("shim-ready".into())
            .spawn(move || {
                let mut line = Vec::new();
                let r = BufReader::new(stdout.take(64)).read_until(b'\n', &mut line);
                let _ = tx.send(r.map(|_| line));
            });
        if spawned.is_err() {
            reap(&mut child);
            return Err(internal("cannot spawn daemon ready reader thread"));
        }
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
        // start と対称にディレクトリを検査する（作成はしない。無ければ消すものも無い）。
        match fs::symlink_metadata(dir) {
            Ok(_) => check_socket_dir(dir)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(encode_delete_response());
            }
            Err(_) => return Err(internal("cannot stat socket dir")),
        }
        let path = socket_path(dir, inv)?;
        let lock = acquire_lock(dir, inv)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                if m.uid() != crate::sys::effective_uid() {
                    return Err(failed("socket is not owned by the current user"));
                }
                fs::remove_file(&path).map_err(|_| internal("cannot remove socket"))?;
            }
            Ok(_) => return Err(failed("socket path exists and is not a socket")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(internal("cannot stat socket path")),
        }
        // ロックを持ったまま消す（取得側が inode を照合して取り直す）。
        let _ = fs::remove_file(&lock.path);
        Ok(encode_delete_response())
    }

    /// 本番の監査の記録先を開く(状態ルート直下の `@audit.log`。SEC-4・PLUG-12・REPAIR-5)。
    ///
    /// Linux では `FileAuditSink` を `ControlAuditRelay`(監査専用の helper プロセス)で包んで返す。`FileAuditSink`
    /// の主経路は呼び出しプロセスが単一スレッドのときしか fork できず、serve 後は accept・接続・監査のスレッドが
    /// 並ぶため、そのまま渡すと rootless では記録も失敗通知も残らない(daemon の stderr は /dev/null)。
    /// relay は plugin-cri の `open_audit_relay_in` と同じ組み立て(spawn → probe)で、**単一スレッドの間に**呼ぶこと
    /// (`run` の Serve 経路は、本関数の前にスレッドも runtime も作らない。listener は stdin の継承で、helper は fd 3
    /// 以上を閉じるため影響しない)。
    ///
    /// peer UID の拒否の記録先なので、relay の構築・probe に失敗したら起動しない(fail-closed。plugin-cri と同じ)。
    /// 状態ルートを開けない場合だけ、置き場所を環境変数で上書きしている(`overridden`。主に試験用)ときは
    /// 既定の状態ルートが無い環境でも動かせるよう、記録先なし(`None`)で続ける。
    ///
    /// 非 Linux は relay が無く(`ControlAuditRelay` は Linux のみ)、plugin-cri の main と同じく記録先を持たず
    /// 拒否を記録しない(`None`。REPAIR-3: 非 Linux の監査経路は #2430 の判断待ち)。
    #[cfg(target_os = "linux")]
    pub fn open_audit_sink(overridden: bool) -> Result<Option<Arc<dyn AuditSink>>, CriError> {
        let sink = match FileAuditSink::open_in_state_root(None) {
            Ok(sink) => sink,
            Err(_) if overridden => return Ok(None),
            Err(_) => return Err(internal("cannot open audit log")),
        };
        let relay = ControlAuditRelay::spawn_ignoring_stop_signals(sink)
            .map_err(|_| internal("cannot start audit relay"))?;
        relay
            .probe()
            .map_err(|_| internal("cannot open audit log"))?;
        Ok(Some(Arc::new(relay)))
    }

    /// 非 Linux では記録先を持たない(上の Linux 版の doc を参照。#2430)。
    #[cfg(not(target_os = "linux"))]
    pub fn open_audit_sink(_overridden: bool) -> Result<Option<Arc<dyn AuditSink>>, CriError> {
        Ok(None)
    }

    /// デーモン本体。stdin の listener を検証して serve し、socket が消えたら終わる。
    pub fn run_serve<F>(
        inv: &ShimInvocation,
        dir: &Path,
        audit: Option<Arc<dyn AuditSink>>,
        make_registry: F,
    ) -> Result<(), CriError>
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
        // inode の再利用（delete 直後の再 start）を見分けるため、mtime（bind 時刻）も併用する。
        let ident = |p: &Path| {
            fs::symlink_metadata(p)
                .ok()
                .map(|m| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec()))
        };
        let first = ident(&expected).ok_or_else(|| failed("socket path is missing"))?;
        let registry = make_registry()?;
        let euid = crate::sys::effective_uid();
        let config = ServerConfig {
            // 同じ uid と root だけを受ける（PLUG-12）。
            allowed_peer_uids: Some(if euid == 0 { vec![0] } else { vec![euid, 0] }),
            ..ServerConfig::default()
        };
        let recorder: Arc<dyn CriOpRecorder> = Arc::new(OpLogRecorder::new(dir));
        let mut server = TtrpcServer::with_recorder(registry, config, recorder);
        if let Some(sink) = audit {
            server = server.with_audit_sink(sink);
        }
        let handle = server
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

    /// 3 OS で絶対パスになる文字列にする。Windows では `C:` を前置し区切りを `\\` にする
    /// （task_service.rs の試験の `abs()` と同じ。CRI-5・PLUG-12・#872）。
    fn abs(unix_style: &str) -> String {
        if cfg!(windows) {
            format!("C:{}", unix_style.replace('/', "\\"))
        } else {
            unix_style.to_string()
        }
    }

    fn pb(unix_style: &str) -> PathBuf {
        PathBuf::from(abs(unix_style))
    }

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
            &abs("/run/containerd/containerd.sock"),
            "-publish-binary",
            &abs("/usr/bin/containerd"),
            "-id",
            "abc123",
            "-debug",
            "start",
        ]))
        .unwrap();
        assert_eq!(inv.action, ShimAction::Start);
        assert_eq!(inv.namespace.unwrap().as_str(), "k8s.io");
        assert_eq!(inv.id.unwrap().as_str(), "abc123");
        assert_eq!(inv.address.unwrap(), pb("/run/containerd/containerd.sock"));
        assert!(inv.debug);
    }

    /// CRI-5・#872: delete の argv（-bundle つき）。
    #[test]
    fn cri5_872_parse_containerd_delete_argv() {
        let inv = parse_args(args(&[
            "-namespace",
            "default",
            "-address",
            &abs("/a.sock"),
            "-publish-binary",
            &abs("/p"),
            "-id",
            "c1",
            "-bundle",
            &abs("/b"),
            "delete",
        ]))
        .unwrap();
        assert_eq!(inv.action, ShimAction::Delete);
        assert_eq!(inv.bundle.unwrap(), pb("/b"));
    }

    /// CRI-5・#872: Go の flag の書き方（`=`・`--`・bool の値・`--` 終端）。
    #[test]
    fn cri5_872_parse_flag_styles() {
        let inv = parse_args(args(&[
            "--namespace=ns",
            "-id=x",
            "--address",
            &abs("/s"),
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
            &abs("/s"),
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
    fn plug12_872_socket_dir_trailing_separator_is_normalized() {
        assert_eq!(
            resolve_socket_dir(Some(abs("/tmp/link/").into())).unwrap(),
            pb("/tmp/link")
        );
        assert_eq!(
            resolve_socket_dir(Some(abs("/tmp//link//").into())).unwrap(),
            pb("/tmp/link")
        );
        // Windows の区切りでも末尾・重複が畳まれる（`\` は Windows のみ区切り）。
        #[cfg(windows)]
        assert_eq!(
            resolve_socket_dir(Some("C:\\tmp\\\\link\\".into())).unwrap(),
            PathBuf::from("C:\\tmp\\link")
        );
    }

    #[test]
    fn cri5_872_socket_dir_resolution() {
        assert_eq!(
            resolve_socket_dir(Some(abs("/tmp/x").into())).unwrap(),
            pb("/tmp/x")
        );
        for bad in ["rel/x".to_string(), abs("/tmp/../x"), abs("/tmp/./x")] {
            assert_eq!(
                resolve_socket_dir(Some(bad.as_str().into()))
                    .unwrap_err()
                    .code(),
                CriErrorCode::InvalidArgument,
                "{bad}"
            );
        }
        assert_eq!(
            default_socket_dir(std::path::Path::new(&abs("/run/fandhe-container"))),
            pb("/run/fandhe-container-shim")
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

    /// PLUG-12・SEC-1・#872: 祖先の mode・所有者の判定を具体値で照合する（P0-2）。
    #[cfg(unix)]
    #[test]
    fn plug12_872_ancestor_mode_verdict() {
        use unix_impl::ancestor_mode_verdict as v;
        // (is_dir, uid, mode, euid, child_owned)
        assert_eq!(v(true, 1000, 0o755, 1000, true), Ok(()));
        assert_eq!(v(true, 0, 0o755, 1000, false), Ok(()));
        assert_eq!(
            v(true, 2000, 0o755, 1000, true),
            Err("socket dir ancestor is owned by another user")
        );
        assert_eq!(
            v(true, 1000, 0o777, 1000, true),
            Err("socket dir ancestor is writable by other users")
        );
        assert_eq!(v(true, 0, 0o1777, 1000, true), Ok(()));
        assert_eq!(
            v(true, 0, 0o1777, 1000, false),
            Err("socket dir ancestor is writable by other users")
        );
        assert_eq!(
            v(false, 1000, 0o755, 1000, true),
            Err("socket dir ancestor is not a directory")
        );
    }

    /// 排他作成した試験用の作業ディレクトリ。Drop で自分が作ったパスだけを消す(PLUG-12・SEC-1・#872)。
    #[cfg(unix)]
    struct Scratch(PathBuf);

    #[cfg(unix)]
    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    #[cfg(unix)]
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `temp_dir()` 直下に、ランダムな名前で非再帰に排他作成する(mode 0700)。予測できる名前を消して作り直す
    /// 方式は、その隙に別ユーザーが symlink を置けるうえ、他の実行の残骸にも触れるため採らない。
    /// 既存の名前(symlink を含む)は辿らず消さず、`AlreadyExists` なら別の名前で再試行する(上限 16 回)。
    #[cfg(unix)]
    fn scratch(tag: &str) -> Scratch {
        use std::hash::{BuildHasher, Hasher};
        use std::os::unix::fs::DirBuilderExt;
        for _ in 0..16 {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u128(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
            );
            let p = std::env::temp_dir().join(format!(
                "fc-872-{tag}-{}-{:016x}",
                std::process::id(),
                h.finish()
            ));
            match std::fs::DirBuilder::new()
                .recursive(false)
                .mode(0o700)
                .create(&p)
            {
                Ok(()) => return Scratch(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("mkdir scratch {}: {e}", p.display()),
            }
        }
        panic!("no free scratch name for {tag}");
    }

    /// PLUG-12・SEC-1・#872: 元の経路の祖先が他者に書き込み可（非スティッキー）なら拒否する（P0-2）。
    #[cfg(unix)]
    #[test]
    fn plug12_872_rejects_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("wwanc");
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = prepare_socket_dir(&open.join("sock")).unwrap_err();
        assert_eq!(err.code(), CriErrorCode::FailedPrecondition);
    }

    /// PLUG-12・SEC-1・#872: 現在のユーザー所有の symlink は祖先に置けない（P0-2。元の経路の検査）。
    #[cfg(unix)]
    #[test]
    fn plug12_872_rejects_user_owned_symlink_ancestor() {
        let base = scratch("symanc");
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        let err = prepare_socket_dir(&base.join("link").join("sock")).unwrap_err();
        assert_eq!(err.code(), CriErrorCode::FailedPrecondition);
    }

    /// PLUG-12・SEC-1・#872: 拡張 ACL が付いた最終ディレクトリ・祖先は mode 0700 でも拒否する（P0-1。macOS のみ）。
    #[cfg(target_os = "macos")]
    #[test]
    fn plug12_872_rejects_extended_acl_dir_and_ancestor() {
        let add_acl = |p: &std::path::Path| {
            crate::sys::set_everyone_acl_for_test(p)
                .unwrap_or_else(|errno| panic!("set ACL on {}: errno {errno}", p.display()))
        };
        let base = scratch("acl");
        let ok = base.join("ok");
        prepare_socket_dir(&ok).unwrap();
        // 最終ディレクトリ。
        add_acl(&ok);
        assert_eq!(
            prepare_socket_dir(&ok).unwrap_err().code(),
            CriErrorCode::FailedPrecondition
        );
        // 祖先。
        let anc = base.join("anc");
        std::fs::create_dir(&anc).unwrap();
        add_acl(&anc);
        assert_eq!(
            prepare_socket_dir(&anc.join("sock")).unwrap_err().code(),
            CriErrorCode::FailedPrecondition
        );
    }
}
