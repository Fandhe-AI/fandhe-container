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
//! 呼び出し元: `fandhe-container-plugin-cri` の bin `containerd-shim-fandhe-container-v2`（`src/bin/containerd_shim_v2.rs`。
//! #3684・TASK-62.6）の薄い main が [`run_cli_with_context`] を呼ぶ。サービスの登録簿は呼び出し側が注入する。
//! 本番の `ContainerRuntime`（`CoreLifecycleRuntime`）は plugin-cri にしか無く、cri から plugin-cri への依存は
//! `tests/dependency_direction.rs` が禁じている（CRI-7・PLUG-1）。そのため bin の置き場所を plugin-cri にし、cri は
//! 引数の解析・start / delete / serve の手順・ttrpc サーバーという共有部品だけを持つ
//! （判断は `docs/design/shim-v2-production-binary.md`。`docs/architecture.md` は cri を「plugin バイナリから呼ばれる実装ライブラリ」としている）。
//! 非 Linux の plugin-cri の bin は本番の runtime を結線できず Shutdown だけの `EmptyTaskService` を登録する（REPAIR-3）。
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
//! 監査レコードとして届ける（SEC-4）。記録先を確保できなければ起動しない（置き場所の上書きでも縮退しない。試験は
//! `XDG_RUNTIME_DIR` で状態ルートを隔離する）。デーモンの stderr（監査の失敗通知を含む）は置き場所の `daemon.log`
//! （0600・追記。開く時に 1 MiB 以上なら `daemon.log.1` へ回す）へ向ける。
//! 非 Linux は記録先を持たない（plugin-cri の main と同じ。#2430）。
//!
//! `-publish-binary` は検証して [`ServeContext`] に保持し（#4154）、[`super::publish`] が TaskCreate・TaskStart・TaskDelete・TaskExit を送る（#4155・#4156）。
//! 呼び出し形・送る種別は `docs/design/shim-v2-production-binary.md` の「イベントの publish」を参照。
//!
//! 計測（REPAIR-4）: `start` / `delete` / デーモンの ttrpc は、結果と所要時間を置き場所の `ops.log`
//! （0600・JSON Lines・1 MiB で `ops.log.1` へ回す）へ追記する。stdout / stderr は汚さない。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
//! - デーモンの寿命は Shutdown RPC（[`ShutdownSignal`]。TASK-62.7.2・#873）と socket の `(dev, ino, mtime)` の生存確認（1 秒間隔。
//!   delete 経路用）の併用。Shutdown で抜けたときは応答を流し切る有界な猶予（`SHUTDOWN_RESPONSE_GRACE`）の後にサーバーを止め、
//!   ロック保持下で自分が bind した socket と lock を片付ける（取れなければ固定語彙を `daemon.log` へ出して残す）
//! - delete での実行層のコンテナの後始末は注入口 [`run_with_hooks`] の前段で plugin-cri が行う（入口の `-id`・`-bundle` の検証と
//!   状態ルートの記録の照合は #4151、残ったコンテナの停止・回収と終了状態の応答は #4152。この module 自体は実行層に触れない）
//! - stdin の options・デーモンのログ（`<bundle>/log`）・grouping
//! - Windows。`run` は `UNIMPLEMENTED`

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fandhe_container_oci::reference::Digest;

use super::service::ServiceRegistry;
use super::shutdown::ShutdownSignal;
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

/// delete action 全体の絶対期限の長さ（REPAIR-5・CRI-5・#4152）。containerd は shim の delete を 5 秒
/// （`io.containerd.timeout.shim.cleanup`）で kill するため、プロセスの起動と応答の書き出しの余裕を引いた値にする。
/// `delete_recorded` が開始時刻から数え、前段（`before_delete`）と `run_delete` の socket・lock の待ちが同じ期限を共有する。
pub const SHIM_DELETE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(4);

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
    /// `-publish-binary`（containerd の実行ファイル。字面だけ検証済みで、実体の検査は `PublishBinary::verify`。#4154）。
    pub publish_binary: Option<PathBuf>,
    /// `-debug`。
    pub debug: bool,
}

/// 実体を検査した `-publish-binary`（containerd がイベント publish に使う実行ファイル。CRI-5・SEC-1・#4154）。
///
/// 作れるのは `PublishBinary::verify`（unix のみ）だけで、symlink・通常ファイル以外・実行ビットなし・
/// other 書き込み可を fail-closed で拒否した値を運ぶ。start / デーモンの起動時に検査し、送信側（#4155・#4156）は
/// [`ServeContext::publish_binary`] から受け取る。検査から exec までの差し替え（TOCTOU）は残余で、doc に記す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBinary(PathBuf);

impl PublishBinary {
    /// 検査済みのパス。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// 実体を `lstat` で検査して作る（symlink は辿らず拒否）。無い・症状の違いは理由別の固定メッセージ（`FAILED_PRECONDITION`）。
    #[cfg(unix)]
    pub fn verify(path: &Path) -> Result<Self, CriError> {
        use std::os::unix::fs::PermissionsExt;
        let bad = |m: &'static str| CriError::failed_precondition(m);
        let md = std::fs::symlink_metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                bad("publish binary not found")
            } else {
                bad("cannot stat publish binary")
            }
        })?;
        if md.file_type().is_symlink() {
            return Err(bad("publish binary must not be a symlink"));
        }
        if !md.is_file() {
            return Err(bad("publish binary must be a regular file"));
        }
        let mode = md.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(bad("publish binary must be executable"));
        }
        if mode & 0o002 != 0 {
            return Err(bad("publish binary must not be world writable"));
        }
        Ok(Self(path.to_path_buf()))
    }
}

/// `-publish-binary` の字面の検査（絶対・長さ・NUL・`.`/`..` 要素なし。3 OS 共通）。
fn clean_abs_path(s: &str) -> Result<PathBuf, CriError> {
    let p = abs_path(s, ADDRESS_MAX_LEN)
        .map_err(|_| invalid("publish binary must be a clean absolute path"))?;
    if s.split(SEPARATORS).any(|e| e == "." || e == "..") {
        return Err(invalid("publish binary must be a clean absolute path"));
    }
    Ok(p)
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
    let mut publish_binary = None;
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
                    // 実体の検査は unix の start / serve が `PublishBinary::verify` で行う（#4154）。
                    _ => publish_binary = Some(clean_abs_path(&val)?),
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
        publish_binary,
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
        exited_at: Some(super::task_api::Timestamp::from_unix_duration(now)),
    }
    .encode_to_vec()
}

/// delete action が回収した結果の終了状態（CRI-5・TASK-62.6・REPAIR-3・#4152）。
///
/// 注入口の前段（plugin-cri の回収）が作り、[`encode_delete_response_for`] が containerd へ返す `DeleteResponse` にする。
/// 変換規則は Task サービスの Delete と同じ（終了コード不明・負値は 255、`exited_at` は Stopped で記録があるときだけ。
/// 値を捏造しない）。規則は `task_service` の関数を使い、複製しない（REPAIR-1）。
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ShimDeleteExit {
    pid: u32,
    exit_status: u32,
    exited_at: Option<super::task_api::Timestamp>,
}

impl ShimDeleteExit {
    /// 回収の結果の core の状態から作る。`before_pid` は回収前の記録の init の pid（無ければ 0 を返す）。
    pub fn from_core_status(
        before_pid: Option<std::num::NonZeroU32>,
        status: &fandhe_container_core::traits::ContainerStatus,
    ) -> Self {
        let rt = crate::adapter::RuntimeContainerStatus::from(status);
        Self {
            pid: before_pid.map_or(0, std::num::NonZeroU32::get),
            exit_status: super::task_service::exit_status_of(&rt),
            exited_at: super::task_service::exited_at_of(&rt),
        }
    }

    /// 回収前の init の pid（不明は 0）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// containerd へ返す終了コード。
    pub fn exit_status(&self) -> u32 {
        self.exit_status
    }

    /// 終了検知時刻（未記録は `None`）。
    pub fn exited_at(&self) -> Option<&super::task_api::Timestamp> {
        self.exited_at.as_ref()
    }
}

/// 回収した終了状態から `DeleteResponse` を符号化したバイト列（stdout へ書く。#4152）。
pub fn encode_delete_response_for(exit: &ShimDeleteExit) -> Vec<u8> {
    use prost::Message;
    super::task_api::DeleteResponse {
        pid: exit.pid,
        exit_status: exit.exit_status,
        exited_at: exit.exited_at.clone(),
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

/// serve のサービス注入口に渡す文脈（#3684・SEC-4）。終了要求の口と、デーモンが持つ監査の記録先を運ぶ。
///
/// 監査の記録先（Linux の `ControlAuditRelay`）は単一スレッドの間にしか作れないため、デーモンが作ったものを
/// 注入側（plugin-cri の本番の runtime）と共有し、create の `mounts[].destination` の拒否を peer UID の拒否と
/// 同じ `@audit.log` へ残す。
pub struct ServeContext {
    shutdown: ShutdownSignal,
    audit: Option<std::sync::Arc<dyn fandhe_container_core::audit_log::AuditSink>>,
    namespace: Option<ShimIdentifier>,
    address: Option<PathBuf>,
    publish_binary: Option<PublishBinary>,
}

impl ServeContext {
    /// 文脈を作る（デーモンと試験が使う）。
    pub fn new(
        shutdown: ShutdownSignal,
        audit: Option<std::sync::Arc<dyn fandhe_container_core::audit_log::AuditSink>>,
    ) -> Self {
        Self {
            shutdown,
            audit,
            namespace: None,
            address: None,
            publish_binary: None,
        }
    }

    /// 検査済みの `-publish-binary` を足す（イベント publish の送信側が使う。CRI-5・#4154）。
    pub fn with_publish_binary(mut self, publish_binary: Option<PublishBinary>) -> Self {
        self.publish_binary = publish_binary;
        self
    }

    /// 検査済みの `-publish-binary`。containerd が渡さなかったときは `None`。
    pub fn publish_binary(&self) -> Option<&PublishBinary> {
        self.publish_binary.as_ref()
    }

    /// 呼び出しの containerd の namespace と ttrpc アドレスを足す（状態の分離キー。CRI-5・#3684）。
    pub fn with_origin(
        mut self,
        namespace: Option<ShimIdentifier>,
        address: Option<PathBuf>,
    ) -> Self {
        self.namespace = namespace;
        self.address = address;
        self
    }

    /// containerd の namespace（`-namespace`）。
    pub fn namespace(&self) -> Option<&ShimIdentifier> {
        self.namespace.as_ref()
    }

    /// containerd の ttrpc アドレス（`-address`）。
    pub fn address(&self) -> Option<&Path> {
        self.address.as_deref()
    }

    /// Task サービスの `with_shutdown` に差し込む終了要求の口。
    pub fn shutdown(&self) -> &ShutdownSignal {
        &self.shutdown
    }

    /// 監査の記録先。記録先を持たない OS（非 Linux）では `None`。
    pub fn audit_sink(
        &self,
    ) -> Option<std::sync::Arc<dyn fandhe_container_core::audit_log::AuditSink>> {
        self.audit.as_ref().map(std::sync::Arc::clone)
    }
}

/// 操作を実行し、stdout へ書くバイト列を返す（serve は終了まで戻らず空を返す）。
///
/// `make_registry` は serve だけが呼ぶ（サービスの注入口。本モジュールの doc を参照）。渡される [`ShutdownSignal`] を
/// Task サービスの `with_shutdown` に差し込むと、Shutdown RPC でデーモンが終了する（TASK-62.7.2）。
/// 監査の記録先も要るときは [`run_with_context`] を使う。
pub fn run<F>(inv: ShimInvocation, make_registry: F) -> Result<Vec<u8>, CriError>
where
    F: FnOnce(ShutdownSignal) -> Result<ServiceRegistry, CriError>,
{
    run_with_context(inv, move |ctx| make_registry(ctx.shutdown().clone()))
}

/// [`run`] の、注入口が [`ServeContext`] を受ける版（#3684）。delete の前段は持たない（常に通す）。
pub fn run_with_context<F>(inv: ShimInvocation, make_registry: F) -> Result<Vec<u8>, CriError>
where
    F: FnOnce(ServeContext) -> Result<ServiceRegistry, CriError>,
{
    run_with_hooks(inv, make_registry, |_, _| Ok(None))
}

/// [`run_with_context`] に、delete action の前段 `before_delete` を足した版（CRI-5・TASK-62.6・#4151）。
///
/// `before_delete` は `delete` のときだけ、socket・lock に触れる前（`run_delete` の前）に 1 回呼ばれる。第 2 引数は delete 全体の
/// 絶対期限（[`SHIM_DELETE_DEADLINE`] を開始時刻から数えた `Instant`。REPAIR-5）で、前段の待ちはこれを超えない。
/// `Err` なら実行層の後始末にも socket の掃除にも進まず、そのエラーを返す（`ops.log` の `ShimV2Delete` には失敗として残る。REPAIR-4）。
/// plugin-cri が `-id`・`-bundle` の検証、状態ルートの記録の照合、残ったコンテナの停止・回収を差し込む（cri から plugin-cri への依存は
/// `tests/dependency_direction.rs` が禁じるため、注入口にした。PLUG-1）。戻り値の `Some(exit)` は回収した終了状態で、
/// [`encode_delete_response_for`] で `DeleteResponse` にする。`None` は回収なし（記録なし・回収済み）で固定の応答
/// （[`encode_delete_response`]）を返す（#4152）。`start`・`serve` では呼ばれない。
#[cfg(unix)]
pub fn run_with_hooks<F, D>(
    inv: ShimInvocation,
    make_registry: F,
    before_delete: D,
) -> Result<Vec<u8>, CriError>
where
    F: FnOnce(ServeContext) -> Result<ServiceRegistry, CriError>,
    D: FnOnce(&ShimInvocation, std::time::Instant) -> Result<Option<ShimDeleteExit>, CriError>,
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
            unix_impl::delete_recorded(&inv, &dir, before_delete)
        }
        ShimAction::Serve => {
            let dir = resolve_socket_dir(std::env::var_os(SOCKET_DIR_ENV))?;
            unix_impl::run_daemon(&inv, &dir, make_registry).map(|()| Vec::new())
        }
    }
}

/// unix 以外では未実装（REPAIR-3）。前段は呼ばない（`Version` 以外は `UNIMPLEMENTED`）。
#[cfg(not(unix))]
pub fn run_with_hooks<F, D>(
    inv: ShimInvocation,
    _make_registry: F,
    _before_delete: D,
) -> Result<Vec<u8>, CriError>
where
    F: FnOnce(ServeContext) -> Result<ServiceRegistry, CriError>,
    D: FnOnce(&ShimInvocation, std::time::Instant) -> Result<Option<ShimDeleteExit>, CriError>,
{
    match inv.action {
        ShimAction::Version => Ok(version_text()),
        _ => Err(CriError::unimplemented(
            "shim v2 bootstrap is available only on unix",
        )),
    }
}

/// shim バイナリの main の本体。引数を解析して [`run_with_context`] を呼び、結果を出力と終了コードへ写す。
///
/// 成功は stdout へバイト列だけ（start のアドレス・delete の応答。start は stderr へ何も書かない。delete の回収の後始末の警告行は
/// stderr へ出うるが、containerd は delete の成功時の stderr を warn として記録するだけで stdout の応答を汚さない。#4152）。
/// 失敗は stdout へ何も書かず、stderr へ `{"code":"<CODE>","message":"<message>"}` の 1 行（JSON）を出して終了コード 1（ERR 系）。
/// JSON の組み立てをここに置くのは、bin を持つ plugin-cri に serde_json の依存を足さないため（依存は承認制）。
pub fn run_cli_with_context<F>(make_registry: F) -> std::process::ExitCode
where
    F: FnOnce(ServeContext) -> Result<ServiceRegistry, CriError>,
{
    run_cli_with_hooks(make_registry, |_, _| Ok(None))
}

/// [`run_cli_with_context`] に delete の前段（[`run_with_hooks`]）を足した版（CRI-5・TASK-62.6・#4151）。
pub fn run_cli_with_hooks<F, D>(make_registry: F, before_delete: D) -> std::process::ExitCode
where
    F: FnOnce(ServeContext) -> Result<ServiceRegistry, CriError>,
    D: FnOnce(&ShimInvocation, std::time::Instant) -> Result<Option<ShimDeleteExit>, CriError>,
{
    use std::io::Write;
    let result = parse_args(std::env::args_os().skip(1))
        .and_then(|inv| run_with_hooks(inv, make_registry, before_delete));
    match result {
        Ok(bytes) => {
            let mut out = std::io::stdout();
            if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                return std::process::ExitCode::FAILURE;
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            let line = serde_json::json!({
                "code": e.code().as_str(),
                "message": e.message(),
            });
            eprintln!("{line}");
            std::process::ExitCode::FAILURE
        }
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
        PublishBinary, READY_LINE, START_READY_TIMEOUT, ShimInvocation, encode_delete_response,
        socket_file_name,
    };
    use crate::error::{CriError, CriErrorCode};
    use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
    use crate::shim_v2::server::{ServerConfig, TtrpcServer};
    use crate::shim_v2::service::ServiceRegistry;
    use crate::shim_v2::shutdown::ShutdownSignal;
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
    /// Shutdown で抜けたあと、処理中の要求（Shutdown 自身の応答を含む）を流し切るのを待つ上限（REPAIR-5）。
    const SHUTDOWN_RESPONSE_GRACE: Duration = Duration::from_secs(1);
    /// 同一 id の排他ロックを待つ上限（REPAIR-5）。
    const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
    /// ロックの再試行間隔。
    const LOCK_RETRY: Duration = Duration::from_millis(20);
    /// delete の計測の記録に、全体期限の後に許す余裕（containerd の 5 秒までに収める）。
    const DELETE_RECORD_GRACE: Duration = Duration::from_millis(500);
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
        check_ancestors_with(dir, pending, |uid| uid == 0)
    }

    /// 解決途中の symlink の展開回数の上限(`ELOOP` 相当。Linux の上限 40 と同じ)。
    const MAX_SYMLINK_FOLLOWS: usize = 40;

    /// 解決の 1 手順(パスの要素)。
    enum Step {
        Root,
        Parent,
        Name(std::ffi::OsString),
    }

    fn steps_of(p: &Path, out: &mut std::collections::VecDeque<Step>, front: bool) {
        use std::path::Component;
        let items: Vec<Step> = p
            .components()
            .filter_map(|c| match c {
                Component::RootDir => Some(Step::Root),
                Component::ParentDir => Some(Step::Parent),
                Component::Normal(n) => Some(Step::Name(n.to_os_string())),
                // `.` は何もしない。Windows の接頭辞は unix では現れない。
                Component::CurDir | Component::Prefix(_) => None,
            })
            .collect();
        if front {
            for st in items.into_iter().rev() {
                out.push_front(st);
            }
        } else {
            out.extend(items);
        }
    }

    /// `check_ancestors` の本体。`link_ok` は途中の symlink の所有者として許す uid(本番は root だけ。試験は差し替える)。
    ///
    /// パスを 1 要素ずつ自前で解決し(`symlink_metadata`・`read_link`)、**通る全てのディレクトリ**と**全ての symlink**を
    /// 検査する(PLUG-12・SEC-1)。`canonicalize` 後の経路だけを見ると、root 所有の symlink が他ユーザーの
    /// ディレクトリ(例: `/safe/link` → `/home/other/redirect` → `/run/...`)を経由して解決される構成の「解決の途中」を
    /// 見逃し、その所有者が差し替えで後続の mkdir・bind・ログ追記の先を誘導できる。相対リンクはリンクのあるディレクトリ
    /// 基準で解決する。展開は `MAX_SYMLINK_FOLLOWS` 回まで。
    ///
    /// ディレクトリは「次の要素へ進む(離れる)」時点で検査する。スティッキーの例外に使う `child_owned` は、次に進む
    /// 要素が現在のユーザー所有かで決める(`..` で戻るときは false = 保守側)。`pending` のときは最後の要素が未作成で、
    /// その親までを検査する(最後の要素はこれから自分の所有で作る子)。`pending` でなければ最後の要素(`dir` 自身)は
    /// 祖先ではないので `check_socket_dir` 側の検査に任せる。
    pub(super) fn check_ancestors_with(
        dir: &Path,
        pending: bool,
        link_ok: impl Fn(u32) -> bool,
    ) -> Result<(), CriError> {
        use std::collections::VecDeque;
        let euid = crate::sys::effective_uid();
        let leave = |at: &Path, child_owned: bool| -> Result<(), CriError> {
            let m = fs::symlink_metadata(at)
                .map_err(|_| internal("cannot stat socket dir ancestor"))?;
            check_ancestor_dir(&m, at, euid, child_owned)
        };
        let mut todo: VecDeque<Step> = VecDeque::new();
        if dir.is_relative() {
            let cwd = std::env::current_dir().map_err(|_| internal("cannot resolve socket dir"))?;
            steps_of(&cwd, &mut todo, false);
        }
        steps_of(dir, &mut todo, false);
        let mut cur = PathBuf::from("/");
        let mut follows = 0usize;
        while let Some(step) = todo.pop_front() {
            match step {
                Step::Root => {
                    if cur != Path::new("/") {
                        leave(&cur, false)?;
                    }
                    cur = PathBuf::from("/");
                }
                Step::Parent => {
                    leave(&cur, false)?;
                    cur.pop();
                }
                Step::Name(name) => {
                    let next = cur.join(&name);
                    let m = match fs::symlink_metadata(&next) {
                        Ok(m) => m,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            if pending && todo.is_empty() {
                                return leave(&cur, true);
                            }
                            return Err(if pending {
                                failed("socket dir parent does not exist")
                            } else {
                                internal("cannot stat socket dir ancestor")
                            });
                        }
                        Err(_) => return Err(internal("cannot stat socket dir ancestor")),
                    };
                    if m.file_type().is_symlink() {
                        if !link_ok(m.uid()) {
                            return Err(failed(
                                "socket dir ancestor is a symlink not owned by root",
                            ));
                        }
                        follows += 1;
                        if follows > MAX_SYMLINK_FOLLOWS {
                            return Err(failed("too many symbolic links in socket dir path"));
                        }
                        let target = fs::read_link(&next)
                            .map_err(|_| internal("cannot read socket dir symlink"))?;
                        // 絶対リンクは先頭の `Root` 手順で `/` から再開する。相対リンクは `cur`(リンクのある
                        // ディレクトリ)基準で続ける。
                        steps_of(&target, &mut todo, true);
                    } else {
                        if !m.is_dir() {
                            return Err(failed("socket dir ancestor is not a directory"));
                        }
                        leave(&cur, m.uid() == euid)?;
                        cur = next;
                    }
                }
            }
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
        acquire_lock_until(dir, inv, Instant::now() + LOCK_TIMEOUT)
    }

    /// [`acquire_lock`] の待ちの絶対期限を引数で受ける版（delete の全体期限を超えて待たない。REPAIR-5）。
    fn acquire_lock_until(
        dir: &Path,
        inv: &ShimInvocation,
        deadline: Instant,
    ) -> Result<IdLock, CriError> {
        let name =
            socket_file_name(inv).ok_or_else(|| CriError::invalid_argument("missing identity"))?;
        let path = dir.join(format!("{name}.lock"));
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

    /// 試験用: id の lock を取って返す（解放は戻り値の drop）。
    #[cfg(test)]
    pub fn hold_id_lock_for_test(dir: &Path, inv: &ShimInvocation) -> impl Sized {
        acquire_lock(dir, inv).expect("lock")
    }

    /// `(dev, ino)`。自分が作ったパスの同一性確認に使う。
    fn ident_of(p: &Path) -> Option<(u64, u64)> {
        fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()))
    }

    /// 計測の記録先（`ops.log` への JSON Lines 追記。REPAIR-4）。失敗は握りつぶし、本来の操作結果を変えない。
    /// 行の語彙は固定で、パス・id・要求の中身は書かない。
    pub struct OpLogRecorder {
        path: PathBuf,
        /// ロック待ちの絶対上限（`None` は `OPS_LOG_LOCK_TIMEOUT` だけ）。delete の全体期限が使う。
        lock_until: Option<Instant>,
    }

    impl OpLogRecorder {
        /// 置き場所のディレクトリを指定して作る（ファイルは記録時に開く）。
        pub fn new(dir: &Path) -> Self {
            Self {
                path: dir.join(OPS_LOG_NAME),
                lock_until: None,
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
            let mut deadline = Instant::now() + OPS_LOG_LOCK_TIMEOUT;
            if let Some(until) = self.lock_until {
                deadline = deadline.min(until);
            }
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
        record_until(dir, kind, r, started, None);
    }

    /// [`record`] に、`ops.log` のロック待ちの絶対上限を足した版（delete の全体期限用。REPAIR-5）。
    fn record_until<T>(
        dir: &Path,
        kind: CriOpKind,
        r: &Result<T, CriError>,
        started: Instant,
        until: Option<Instant>,
    ) {
        let code = match r {
            Ok(_) => tonic::Code::Ok,
            Err(e) => e.code().grpc_code(),
        };
        let sample = CriOpSample::new(kind, code, started.elapsed());
        let mut rec = OpLogRecorder::new(dir);
        rec.lock_until = until;
        rec.record_cri_op(&sample);
    }

    /// `start` を計測つきで実行する。
    pub fn start_recorded(inv: &ShimInvocation, dir: &Path) -> Result<String, CriError> {
        let started = Instant::now();
        let r = run_start(inv, dir);
        record(dir, CriOpKind::ShimV2Start, &r, started);
        r
    }

    /// `delete` を計測つきで実行する。
    ///
    /// `before_delete`（plugin-cri の引数検証と記録の照合。#4151）が `Err` なら `run_delete` に進まず、socket にも触れない。
    /// 拒否も計測区間に含め、`ops.log` へ失敗として残す。
    pub fn delete_recorded<D>(
        inv: &ShimInvocation,
        dir: &Path,
        before_delete: D,
    ) -> Result<Vec<u8>, CriError>
    where
        D: FnOnce(&ShimInvocation, Instant) -> Result<Option<super::ShimDeleteExit>, CriError>,
    {
        let started = Instant::now();
        let deadline = started + super::SHIM_DELETE_DEADLINE;
        let r = before_delete(inv, deadline).and_then(|exit| run_delete(inv, dir, exit, deadline));
        // 計測の記録の待ちも containerd の 5 秒までに収める（期限 + 余裕を上限にする）。
        record_until(
            dir,
            CriOpKind::ShimV2Delete,
            &r,
            started,
            Some(deadline + DELETE_RECORD_GRACE),
        );
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
        // 生成物を残さず拒否するため、置き場所を作る前に検査する（#4154）。
        if let Some(p) = &inv.publish_binary {
            PublishBinary::verify(p)?;
        }
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
        if let Some(p) = &inv.publish_binary {
            cmd.arg("-publish-binary").arg(p);
        }
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
    pub fn run_delete(
        inv: &ShimInvocation,
        dir: &Path,
        exit: Option<super::ShimDeleteExit>,
        deadline: Instant,
    ) -> Result<Vec<u8>, CriError> {
        let encode = |exit: &Option<super::ShimDeleteExit>| match exit {
            Some(e) => super::encode_delete_response_for(e),
            None => encode_delete_response(),
        };
        // start と対称にディレクトリを検査する（作成はしない。無ければ消すものも無い）。
        match fs::symlink_metadata(dir) {
            Ok(_) => check_socket_dir(dir)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(encode(&exit));
            }
            Err(_) => return Err(internal("cannot stat socket dir")),
        }
        let path = socket_path(dir, inv)?;
        // lock の待ちは既定の上限と delete の全体期限の早い方（REPAIR-5）。
        let lock = acquire_lock_until(dir, inv, deadline.min(Instant::now() + LOCK_TIMEOUT))?;
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
        Ok(encode(&exit))
    }

    /// 本番の監査の記録先を開く(状態ルート直下の `@audit.log`。SEC-4・PLUG-12・REPAIR-5)。
    ///
    /// Linux では `FileAuditSink` を `ControlAuditRelay`(監査専用の helper プロセス)で包んで返す。`FileAuditSink`
    /// の主経路は呼び出しプロセスが単一スレッドのときしか fork できず、serve 後は accept・接続・監査のスレッドが
    /// 並ぶため、そのまま渡すと rootless では記録も失敗通知も残らない。relay は plugin-cri の
    /// `open_audit_relay_in` と同じ組み立て(spawn → probe)で、**単一スレッドの間に**呼ぶ(`run_daemon` が保証する)。
    /// helper は fd 3 以上を閉じるが fd 0〜2 は継承するため、呼び出し元は先に listen socket を fd 3 以上へ退避して
    /// fd 0 を `/dev/null` に差し替え、stderr を `daemon.log` へ向けておく(`run_daemon`)。
    ///
    /// 記録先を確保できなければ常に起動しない(fail-closed)。置き場所(`FANDHE_CONTAINER_SHIM_SOCKET_DIR`)の上書きでも
    /// 縮退しない(この環境変数は製品バイナリでも効くため、監査が黙って消える。試験は `XDG_RUNTIME_DIR` で状態ルートを
    /// 隔離する)。
    ///
    /// 非 Linux は relay が無く(`ControlAuditRelay` は Linux のみ)、plugin-cri の main と同じく記録先を持たず
    /// 拒否を記録しない(`None`。REPAIR-3: 非 Linux の監査経路は #2430 の判断待ち)。
    #[cfg(target_os = "linux")]
    pub fn open_audit_sink() -> Result<Option<Arc<dyn AuditSink>>, CriError> {
        let sink = FileAuditSink::open_in_state_root(None)
            .map_err(|_| internal("cannot open audit log"))?;
        let relay = ControlAuditRelay::spawn_ignoring_stop_signals(sink)
            .map_err(|_| internal("cannot start audit relay"))?;
        relay
            .probe()
            .map_err(|_| internal("cannot open audit log"))?;
        Ok(Some(Arc::new(relay)))
    }

    /// 非 Linux では記録先を持たない(上の Linux 版の doc を参照。#2430)。
    #[cfg(not(target_os = "linux"))]
    pub fn open_audit_sink() -> Result<Option<Arc<dyn AuditSink>>, CriError> {
        Ok(None)
    }

    /// デーモンの stderr の記録先のファイル名(置き場所の直下。0600・追記)。
    const DAEMON_LOG_NAME: &str = "daemon.log";
    /// `daemon.log` の回転・オープンを直列化するロックファイル名(置き場所の直下。0600)。
    const DAEMON_LOG_LOCK_NAME: &str = "daemon.log.lock";

    /// `daemon.log.lock` の期限つき排他ロックを取る(`daemon.log` の回転とオープンの直列化。P3-3・PLUG-12・#3663)。
    /// ロックファイル自体も symlink でない(`O_NOFOLLOW|O_NONBLOCK`)・通常ファイル・自分の所有・単一リンク・
    /// グループ/その他の権限なしを確かめる。期限は `OPS_LOG_LOCK_TIMEOUT`(REPAIR-5)で、超えたら `Timeout`。
    fn lock_daemon_log(dir: &Path, euid: u32) -> Result<File, CriError> {
        let flags = crate::sys::OPEN_NOFOLLOW_NONBLOCK
            .ok_or_else(|| failed("daemon log is not supported on this platform"))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(flags)
            .open(dir.join(DAEMON_LOG_LOCK_NAME))
            .map_err(|_| internal("cannot open daemon log lock"))?;
        let m = file
            .metadata()
            .map_err(|_| internal("cannot stat daemon log lock"))?;
        if !m.is_file() || m.nlink() != 1 || m.uid() != euid || m.mode() & 0o077 != 0 {
            return Err(failed("daemon log lock is not a private plain file"));
        }
        let deadline = Instant::now() + OPS_LOG_LOCK_TIMEOUT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(_)) => return Err(internal("cannot lock daemon log")),
            }
            if Instant::now() >= deadline {
                return Err(CriError::new(
                    CriErrorCode::Timeout,
                    "daemon log lock timed out",
                ));
            }
            thread::sleep(LOCK_RETRY);
        }
    }

    /// stderr の記録先を開く。置き場所は検証済みの前提で、ファイル自体も symlink でない・通常ファイル・自分の所有・
    /// グループ/その他の権限なしを確かめる(PLUG-12・SEC-1)。`OpenOptions` に `O_NOFOLLOW` の定数を渡す代わりに、
    /// lstat と開いた fd の `(dev, ino)` の一致で差し替えを検出する(置き場所は自分と root しか変更できない)。
    ///
    /// ハードリンク(`nlink != 1`)は拒否する。`daemon.log` は置き場所を共有する全デーモン(id が違っても)で共有されるため、
    /// 「サイズ確認 → 回転 → オープン → 同一性確認」は `daemon.log.lock` への期限つき `flock` で直列化する(並行する
    /// start が同時に回転を判断して rename が NotFound になる、開いた後の `(dev, ino)` 照合が他者の回転で食い違う、を
    /// 防ぐ。P3-3・#3663)。ロックが期限内に取れなければ `Timeout` で起動しない(fail-closed)。ロック外の旧版との混在に
    /// 備え、rename の NotFound は「他者が既に回した」とみなして続行する。既存の書き込みは回転後の `.1` に残り失われない。relay の helper は fd 1(`start` が読む readiness の pipe)と fd 2
    /// を継承し、本体の終了後も最大 `RECORD_WAIT_LIMIT` 保つが、`start` は期限つき(`START_READY_TIMEOUT`)で読む
    /// ため待ち続けない(P3-4)。
    ///
    /// 肥大の上限: 開く時点で `OPS_LOG_MAX_BYTES` 以上なら `daemon.log.1` へ回す(1 世代)。デーモンの稼働中は
    /// fd を差したままなので回さないが、書く行は固定語彙で `server.rs` の `STDERR_NOTICE_LIMIT`(256 行)で打ち切るため、
    /// 1 デーモンあたり約 25 KB に収まる。複数のデーモンが同じファイルへ追記しうる(`O_APPEND`)。
    pub(super) fn open_daemon_log(dir: &Path) -> Result<File, CriError> {
        let path = dir.join(DAEMON_LOG_NAME);
        let euid = crate::sys::effective_uid();
        let _guard = lock_daemon_log(dir, euid)?;
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                if !m.file_type().is_file() || m.uid() != euid {
                    return Err(failed(
                        "daemon log is not a plain file owned by the current user",
                    ));
                }
                if m.len() >= OPS_LOG_MAX_BYTES {
                    let mut rotated = path.clone().into_os_string();
                    rotated.push(".1");
                    match fs::rename(&path, rotated) {
                        Ok(()) => {}
                        // 他者が既に回した(ロック外の旧版との混在への防御)。新しく作り直すので続行する。
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(internal("cannot rotate daemon log")),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(internal("cannot stat daemon log")),
        }
        // O_NOFOLLOW|O_NONBLOCK: lstat と open の間に dangling symlink へ差し替えられてもリンク先に作らず(ELOOP)、
        // FIFO へ差し替えられても無期限に待たない(ENXIO。REPAIR-5)。通常ファイルへの書き込みに O_NONBLOCK は影響しない。
        let flags = crate::sys::OPEN_NOFOLLOW_NONBLOCK
            .ok_or_else(|| failed("daemon log is not supported on this platform"))?;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(flags)
            .open(&path)
            .map_err(|_| internal("cannot open daemon log"))?;
        let fm = f
            .metadata()
            .map_err(|_| internal("cannot stat daemon log"))?;
        let lm = fs::symlink_metadata(&path).map_err(|_| internal("cannot stat daemon log"))?;
        if !fm.is_file()
            || fm.nlink() != 1
            || !lm.file_type().is_file()
            || (lm.dev(), lm.ino()) != (fm.dev(), fm.ino())
            || fm.uid() != euid
            || fm.mode() & 0o077 != 0
        {
            return Err(failed("daemon log is not a private plain file"));
        }
        Ok(f)
    }

    /// stdin の listen socket を fd 3 以上へ複製して取り込み、期待するパスの socket であることを確かめる。
    fn adopt_stdin_listener(expected: &Path) -> Result<UnixListener, CriError> {
        let owned = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| internal("cannot duplicate stdin"))?;
        let listener = UnixListener::from(owned);
        let addr = listener
            .local_addr()
            .map_err(|_| failed("stdin is not a unix socket"))?;
        if addr.as_pathname() != Some(expected) {
            return Err(failed("stdin socket does not match the expected path"));
        }
        Ok(listener)
    }

    /// デーモンの入口。スレッドを作る前の単一スレッドの間に、fd を整えてから監査の relay を fork する。
    ///
    /// 順序(SEC-4・PLUG-12・#3663):
    /// 1. stdin の listener を fd 3 以上へ取り込み、期待するパスか確かめる(失敗は元の stderr に出る)
    /// 2. 置き場所を検証し、stderr を `daemon.log` へ向ける(監査の失敗通知・relay の helper の stderr もここへ残る)
    /// 3. fd 0 を `/dev/null` に差し替える。relay の helper は fd 3 以上しか閉じないため、fd 0 が listen socket の
    ///    ままだと、デーモンが死んでも helper が LISTEN を保ち、`start` が死んだアドレスを生きていると判定し続ける
    /// 4. 監査の relay を作る(`open_audit_sink`)
    /// 5. `run_serve`
    pub fn run_daemon<F>(inv: &ShimInvocation, dir: &Path, make_registry: F) -> Result<(), CriError>
    where
        F: FnOnce(super::ServeContext) -> Result<ServiceRegistry, CriError>,
    {
        let expected = socket_path(dir, inv)?;
        let listener = adopt_stdin_listener(&expected)?;
        check_socket_dir(dir)?;
        let log = open_daemon_log(dir)?;
        crate::sys::replace_std(crate::sys::StdSlot::Stderr, log.as_fd())
            .map_err(|_| internal("cannot redirect stderr"))?;
        drop(log);
        let null = File::open("/dev/null").map_err(|_| internal("cannot open /dev/null"))?;
        crate::sys::replace_std(crate::sys::StdSlot::Stdin, null.as_fd())
            .map_err(|_| internal("cannot redirect stdin"))?;
        drop(null);
        let audit = open_audit_sink()?;
        run_serve(inv, dir, listener, &expected, audit, make_registry)
    }

    /// socket の同一性。inode の再利用（delete 直後の再 start）を見分けるため mtime（bind 時刻）も併用する。
    fn sock_ident(p: &Path) -> Option<(u64, u64, i64, i64)> {
        fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec()))
    }

    /// 片付けの失敗を 1 行の JSON（固定語彙の `code` / `message`）で stderr（`daemon.log`）へ出す（ERR 系・REPAIR-4）。
    fn report_cleanup_failure(code: CriErrorCode, message: &'static str) {
        eprintln!(r#"{{"code":"{}","message":"{message}"}}"#, code.as_str());
    }

    /// Shutdown で抜けたあとの片付け。`held`（終了要求の時点から保持してきた ID ロック）の下で、
    /// 自分が bind した実体（`first` と一致）だけを消す。
    ///
    /// 終了要求から本関数の終わりまで ID ロックを持ち続けるので、並行する `start` は要求後に「生きている」と
    /// 判定して消える socket のアドレスを返さない（PLUG-12・REPAIR-5）。`held` が無いときだけロックを取り直す。
    /// ロックが取れない・別の実体に置き換わっているときは消さず、固定語彙の JSON を 1 行出す
    /// （並行 `start` が返した生きたアドレスを消さない。残った stale は次の `start` が回収する）。
    fn cleanup_after_shutdown(
        inv: &ShimInvocation,
        dir: &Path,
        expected: &Path,
        first: (u64, u64, i64, i64),
        held: Option<IdLock>,
    ) {
        let lock = match held {
            Some(l) => l,
            None => match acquire_lock(dir, inv) {
                Ok(l) => l,
                Err(_) => {
                    report_cleanup_failure(
                        CriErrorCode::Unavailable,
                        "socket left in place after shutdown (lock unavailable)",
                    );
                    return;
                }
            },
        };
        match sock_ident(expected) {
            Some(now) if now == first => {
                if fs::remove_file(expected).is_err() {
                    report_cleanup_failure(
                        CriErrorCode::Internal,
                        "socket left in place after shutdown (remove failed)",
                    );
                    return;
                }
            }
            Some(_) => {
                report_cleanup_failure(
                    CriErrorCode::FailedPrecondition,
                    "socket left in place after shutdown (replaced)",
                );
                return;
            }
            None => {}
        }
        // ロックを持ったまま消す（取得側が inode を照合して取り直す。run_delete と同じ）。
        let _ = fs::remove_file(&lock.path);
    }

    /// デーモン本体。取り込み済みの listener で serve し、Shutdown RPC か socket の消失で終わる（`run_daemon` から呼ばれる）。
    fn run_serve<F>(
        inv: &ShimInvocation,
        dir: &Path,
        listener: UnixListener,
        expected: &Path,
        audit: Option<Arc<dyn AuditSink>>,
        make_registry: F,
    ) -> Result<(), CriError>
    where
        F: FnOnce(super::ServeContext) -> Result<ServiceRegistry, CriError>,
    {
        let first = sock_ident(expected).ok_or_else(|| failed("socket path is missing"))?;
        // Shutdown RPC は要求を立てる前に ID ロックを取り、片付けの終わりまで持つ（並行 start の締め出し）。
        let (gate_dir, gate_inv) = (dir.to_path_buf(), inv.clone());
        let signal = ShutdownSignal::with_gate(Arc::new(move || {
            acquire_lock(&gate_dir, &gate_inv)
                .map(|l| Box::new(l) as Box<dyn std::any::Any + Send>)
                .map_err(|_| ())
        }));
        // start の検査からデーモンの起動までの差し替えの窓を狭めるため、もう一度検査する（#4154）。
        let publish_binary = inv
            .publish_binary
            .as_deref()
            .map(PublishBinary::verify)
            .transpose()?;
        let registry = make_registry(
            super::ServeContext::new(signal.clone(), audit.clone())
                .with_origin(inv.namespace.clone(), inv.address.clone())
                .with_publish_binary(publish_binary),
        )?;
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
        // Shutdown RPC（即時に起きる）と socket の消失（delete 経路。1 秒間隔）のどちらかで抜ける。
        let mut shutdown_requested = false;
        while sock_ident(expected) == Some(first) {
            if signal.wait_timeout(WATCH_INTERVAL) {
                shutdown_requested = true;
                break;
            }
        }
        let held = if shutdown_requested {
            signal
                .take_held()
                .and_then(|b| b.downcast::<IdLock>().ok())
                .map(|b| *b)
        } else {
            None
        };
        if shutdown_requested {
            // 停止フラグは応答の書き込みを打ち切るため、先に Shutdown 自身の応答を流し切る（有界）。
            let _ = handle.wait_idle(SHUTDOWN_RESPONSE_GRACE);
        }
        let result = handle
            .shutdown()
            .map_err(|_| CriError::new(CriErrorCode::Timeout, "server shutdown timed out"));
        if shutdown_requested {
            cleanup_after_shutdown(inv, dir, expected, first, held);
        }
        result
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
        let out = run(parse_args(args(&["-v"])).unwrap(), |_| {
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

    /// CRI-5・TASK-62.6・#4152: 回収した終了状態の符号化。Stopped は記録の終了コードと `exited_at` を、
    /// 終了時刻が未記録なら `exited_at` 未設定を、終了コード不明は 255 を、pid の無い Created は 0 を返す。
    #[test]
    fn cri5_4152_delete_response_for_exit() {
        use fandhe_container_core::traits::{ContainerId, ContainerStatus, ExitTime};
        use prost::Message;
        let id = ContainerId::new("abc").unwrap();
        let pid = std::num::NonZeroU32::new(77);
        let decode = |e: &ShimDeleteExit| {
            crate::shim_v2::DeleteResponse::decode(&encode_delete_response_for(e)[..]).unwrap()
        };

        let at = ExitTime::from_unix_nanos(1_700_000_000_000_000_005);
        let r = decode(&ShimDeleteExit::from_core_status(
            pid,
            &ContainerStatus::stopped_at(id.clone(), Some(3), at),
        ));
        assert_eq!((r.pid, r.exit_status), (77, 3));
        let ts = r.exited_at.expect("exited_at");
        assert_eq!((ts.seconds, ts.nanos), (1_700_000_000, 5));

        let r = decode(&ShimDeleteExit::from_core_status(
            pid,
            &ContainerStatus::stopped_at(id.clone(), Some(3), None),
        ));
        assert_eq!(r.exit_status, 3);
        assert!(r.exited_at.is_none());

        let r = decode(&ShimDeleteExit::from_core_status(
            None,
            &ContainerStatus::stopped(id.clone(), None),
        ));
        assert_eq!((r.pid, r.exit_status), (0, 255));

        let r = decode(&ShimDeleteExit::from_core_status(
            None,
            &ContainerStatus::created(id, None),
        ));
        assert_eq!((r.pid, r.exit_status), (0, 0));
        assert!(r.exited_at.is_none());
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

    /// 排他作成の一時ディレクトリ(0700。Drop で消す)。
    #[cfg(unix)]
    struct Tmp(PathBuf);

    #[cfg(unix)]
    impl Tmp {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::DirBuilderExt;
            use std::sync::atomic::{AtomicU32, Ordering};
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = PathBuf::from(format!("/tmp/fcu{}-{n}-{tag}", std::process::id()));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }

    #[cfg(unix)]
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// PLUG-12・SEC-1・#3663: symlink の解決の途中で通るディレクトリも祖先と同じ基準で検査する。
    /// 自分の所有の symlink を許す差し替え(本番は root 所有のみ)で、`link` → `w/redirect`(`w` は他ユーザー書き込み可)
    /// → 実体、の連鎖を通ると `w` が検査されて拒否される(`canonicalize` 後の経路だけを見ると `w` を見逃す)。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_symlink_resolution_path_is_checked() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let t = Tmp::new("chain");
        let real = t.0.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        let w = t.0.join("w");
        std::fs::DirBuilder::new().mode(0o700).create(&w).unwrap();
        std::os::unix::fs::symlink(&real, w.join("redirect")).unwrap();
        let link = t.0.join("link");
        std::os::unix::fs::symlink(w.join("redirect"), &link).unwrap();
        let own = crate::sys::effective_uid();
        let target = link.join("sock");

        // w が自分だけの書き込みなら、連鎖は(自分の symlink を許す試験の方針で)通る。
        unix_impl::check_ancestors_with(&target, true, |u| u == own || u == 0).unwrap();
        // w を他ユーザー書き込み可にすると、解決の途中の w が拒否される。
        std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o770)).unwrap();
        let e = unix_impl::check_ancestors_with(&target, true, |u| u == own || u == 0).unwrap_err();
        assert!(
            e.message().contains("writable by other users"),
            "{}",
            e.message()
        );
        // 本番の方針(symlink は root 所有のみ)では、自分の所有の連鎖そのものを拒否する。
        let e = unix_impl::check_ancestors_with(&target, true, |u| u == 0 && own != 0);
        assert!(e.is_err());
    }

    /// PLUG-12・#3663: 相対 symlink はリンクのあるディレクトリ基準で解決し、循環は展開回数の上限で拒否する。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_relative_symlink_and_loop() {
        use std::os::unix::fs::DirBuilderExt;
        let t = Tmp::new("rel");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(t.0.join("real"))
            .unwrap();
        std::os::unix::fs::symlink("real", t.0.join("rl")).unwrap();
        let own = crate::sys::effective_uid();
        unix_impl::check_ancestors_with(&t.0.join("rl").join("sock"), true, |u| u == own || u == 0)
            .unwrap();
        // 相対リンクが指す先が無ければ(親が存在しない)失敗する。
        std::os::unix::fs::symlink("nowhere", t.0.join("dangling")).unwrap();
        assert!(
            unix_impl::check_ancestors_with(&t.0.join("dangling").join("sock"), true, |u| u == own
                || u == 0)
            .is_err()
        );
        std::os::unix::fs::symlink("b", t.0.join("a")).unwrap();
        std::os::unix::fs::symlink("a", t.0.join("b")).unwrap();
        let e = unix_impl::check_ancestors_with(&t.0.join("a").join("sock"), true, |u| {
            u == own || u == 0
        })
        .unwrap_err();
        assert!(
            e.message().contains("too many symbolic links"),
            "{}",
            e.message()
        );
    }

    /// PLUG-12・SEC-1・REPAIR-5・#3663: `daemon.log` を開く `O_NOFOLLOW|O_NONBLOCK` は、lstat と open の間に差し替えられた
    /// dangling symlink のリンク先に作らず(`ELOOP`)、読み手の無い FIFO で待たずに失敗する(`ENXIO`)。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_daemon_log_open_flags_refuse_symlink_and_fifo() {
        use std::os::unix::fs::OpenOptionsExt;
        let t = Tmp::new("flags");
        let flags = crate::sys::OPEN_NOFOLLOW_NONBLOCK.expect("supported target");
        let open = |p: &std::path::Path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(flags)
                .open(p)
        };
        let victim = t.0.join("victim");
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(open(&link).is_err());
        assert!(!victim.exists(), "the link target must not be created");
        // FIFO は src から spawn せずに作れないため(CRI 層はプロセスを起動しない。task_59_4)、同じく非ブロックで
        // 拒否される特殊ファイル(UDS)で O_NONBLOCK 経路を確かめる。FIFO の実物は結合試験
        // `plug12_3663_fifo_daemon_log_does_not_hang_start` が固定する。
        let sock = t.0.join("sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let started = std::time::Instant::now();
        assert!(open(&sock).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // 通常ファイルは開けて追記できる(O_NONBLOCK は書き込みに影響しない)。
        let mut f = open(&t.0.join("plain")).unwrap();
        std::io::Write::write_all(&mut f, b"x\n").unwrap();
        assert_eq!(std::fs::read(t.0.join("plain")).unwrap(), b"x\n");
    }

    /// PLUG-12・SEC-1・#3663: 既存の `daemon.log` が FIFO・symlink・ハードリンクなら開かない。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_open_daemon_log_rejects_unsafe_existing_files() {
        let t = Tmp::new("log");
        unix_impl::open_daemon_log(&t.0).unwrap();
        let log = t.0.join("daemon.log");
        std::fs::hard_link(&log, t.0.join("alias")).unwrap();
        let e = unix_impl::open_daemon_log(&t.0).unwrap_err();
        assert!(
            e.message().contains("private plain file"),
            "{}",
            e.message()
        );
        std::fs::remove_file(t.0.join("alias")).unwrap();
        std::fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(t.0.join("victim"), &log).unwrap();
        assert!(unix_impl::open_daemon_log(&t.0).is_err());
        assert!(!t.0.join("victim").exists());
    }

    /// PLUG-12・#3663: 1 MiB 超の `daemon.log` に対し複数スレッドが同時に開いても全件成功し、
    /// 回転は 1 回だけ(`daemon.log.1` が旧 inode・`daemon.log` は新しい inode)で、ロックファイルは 0600。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_concurrent_daemon_log_rotation_all_succeed() {
        use std::os::unix::fs::MetadataExt;
        let t = Tmp::new("rot");
        let log = t.0.join("daemon.log");
        std::fs::write(&log, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        std::fs::set_permissions(&log, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let old_ino = std::fs::metadata(&log).unwrap().ino();
        let started = std::time::Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = t.0.clone();
                std::thread::spawn(move || unix_impl::open_daemon_log(&dir).map(drop))
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        let rotated = t.0.join("daemon.log.1");
        assert_eq!(std::fs::metadata(&rotated).unwrap().ino(), old_ino);
        assert_eq!(std::fs::metadata(&rotated).unwrap().len(), 1024 * 1024 + 1);
        assert_ne!(std::fs::metadata(&log).unwrap().ino(), old_ino);
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 0);
        let lock = std::fs::metadata(t.0.join("daemon.log.lock")).unwrap();
        assert_eq!(lock.mode() & 0o777, 0o600);
    }

    /// PLUG-12・SEC-1・#3663: ロックファイルが symlink なら開かない。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_daemon_log_lock_rejects_symlink() {
        let t = Tmp::new("lk");
        std::os::unix::fs::symlink(t.0.join("victim"), t.0.join("daemon.log.lock")).unwrap();
        assert!(unix_impl::open_daemon_log(&t.0).is_err());
        assert!(!t.0.join("victim").exists());
    }

    /// PLUG-12・REPAIR-5・#3663: ロックを他者が保持し続けると、期限内に `Timeout` で失敗する。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_daemon_log_lock_times_out() {
        let t = Tmp::new("lt");
        use std::os::unix::fs::OpenOptionsExt;
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(t.0.join("daemon.log.lock"))
            .unwrap();
        held.lock().unwrap();
        let e = unix_impl::open_daemon_log(&t.0).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::Timeout);
        assert!(!t.0.join("daemon.log").exists());
    }

    /// PLUG-12・#3663: 祖先として辿る要素が通常ファイルなら、理由を正確に「ディレクトリでない」として拒否する。
    ///
    /// symlink の所有者の判定は本番と同じ root のみにする。macOS の `/tmp` は root 所有の symlink
    /// （実体は `/private/tmp`）で、何も信頼しない判定では目的の要素に届く前にそこで拒否されるため。
    #[cfg(unix)]
    #[test]
    fn plug12_3663_non_directory_ancestor_is_rejected() {
        let t = Tmp::new("file");
        std::fs::write(t.0.join("f"), b"").unwrap();
        let e = unix_impl::check_ancestors_with(&t.0.join("f").join("sock"), true, |u| u == 0)
            .unwrap_err();
        assert!(e.message().contains("not a directory"), "{}", e.message());
    }

    /// CRI-5・SEC-1・#4154: `-publish-binary` の字面の検査。不正は `INVALID_ARGUMENT`、正しい値は保持、省略は `None`。
    #[test]
    fn cri5_4154_publish_binary_syntax() {
        let base = |pb_val: &str| {
            parse_args(args(&[
                "-namespace",
                "k8s.io",
                "-address",
                &abs("/run/containerd/containerd.sock"),
                "-publish-binary",
                pb_val,
                "-id",
                "abc",
                "start",
            ]))
        };
        let long = format!("/{}", "a".repeat(ADDRESS_MAX_LEN));
        for bad in [
            "containerd",
            "bin/containerd",
            &abs("/usr/./bin/containerd"),
            &abs("/usr/../bin/containerd"),
            &long,
            "/usr/bin/con\0tainerd",
        ] {
            let e = base(bad).unwrap_err();
            assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{bad:?}");
            assert_eq!(e.message(), "publish binary must be a clean absolute path");
        }
        let inv = base(&abs("/usr/bin/containerd")).unwrap();
        assert_eq!(inv.publish_binary, Some(pb("/usr/bin/containerd")));
        let none = parse_args(args(&[
            "-namespace",
            "k8s.io",
            "-address",
            &abs("/run/c.sock"),
            "-id",
            "abc",
            "start",
        ]))
        .unwrap();
        assert_eq!(none.publish_binary, None);
    }

    /// CRI-5・SEC-1・#4154: 実体の検査の表。拒否は理由別のメッセージと `FAILED_PRECONDITION`、正しい値は保持される。
    #[cfg(unix)]
    #[test]
    fn cri5_4154_publish_binary_verify_table() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = Tmp::new("pubbin");
        let mk = |name: &str, mode: u32| {
            let p = t.0.join(name);
            std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let good = mk("good", 0o755);
        std::fs::create_dir(t.0.join("dir")).unwrap();
        symlink(&good, t.0.join("link")).unwrap();
        let cases: Vec<(PathBuf, &str)> = vec![
            (t.0.join("missing"), "publish binary not found"),
            (t.0.join("dir"), "publish binary must be a regular file"),
            (t.0.join("link"), "publish binary must not be a symlink"),
            (mk("noexec", 0o644), "publish binary must be executable"),
            (mk("ww", 0o757), "publish binary must not be world writable"),
        ];
        for (path, msg) in cases {
            let e = PublishBinary::verify(&path).unwrap_err();
            assert_eq!(e.code(), CriErrorCode::FailedPrecondition, "{path:?}");
            assert_eq!(e.message(), msg, "{path:?}");
        }
        let ok = PublishBinary::verify(&good).unwrap();
        assert_eq!(ok.as_path(), good.as_path());
    }

    /// CRI-5・#4154: start は不正な `-publish-binary` を、置き場所を作る前に拒否する。
    #[cfg(unix)]
    #[test]
    fn cri5_4154_start_rejects_bad_publish_binary_before_side_effects() {
        let t = Tmp::new("pubstart");
        let dir = t.0.join("sock");
        let mut inv = start_inv("pb1");
        inv.publish_binary = Some(t.0.join("missing"));
        let e = unix_impl::run_start(&inv, &dir).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "publish binary not found");
        assert!(!dir.exists());
    }

    /// CRI-5・#4154: 注入口へ渡す文脈が検査済みの値を保持する。
    #[cfg(unix)]
    #[test]
    fn cri5_4154_serve_context_holds_publish_binary() {
        let ctx = ServeContext::new(ShutdownSignal::new(), None);
        assert!(ctx.publish_binary().is_none());
        let exe = std::env::current_exe().unwrap();
        let pbin = PublishBinary::verify(&exe).unwrap();
        let ctx = ctx.with_publish_binary(Some(pbin.clone()));
        assert_eq!(ctx.publish_binary(), Some(&pbin));
    }

    /// CRI-5・TASK-62.6・REPAIR-4・#4151: delete の前段が `Err` なら socket に触れず `run_delete` に進まず、
    /// そのエラーを返し、`ops.log` に失敗として残る。`Ok` なら従来どおり socket を掃除して応答を返す。
    #[cfg(unix)]
    #[test]
    fn cri5_4151_before_delete_error_skips_run_delete() {
        use std::os::unix::net::UnixListener;
        let t = Tmp::new("bd");
        let dir = t.0.join("s");
        unix_impl::prepare_socket_dir(&dir).unwrap();
        let inv = parse_args(args(&[
            "-namespace",
            "default",
            "-address",
            "/run/c.sock",
            "-id",
            "abc",
            "-bundle",
            "/tmp/x/abc",
            "delete",
        ]))
        .unwrap();
        let sock = unix_impl::socket_path(&dir, &inv).unwrap();
        // bind 後に listener を閉じて、接続を拒む残骸の socket を作る。
        drop(UnixListener::bind(&sock).unwrap());
        assert!(sock.exists());

        let e = unix_impl::delete_recorded(&inv, &dir, |_, _| {
            Err(CriError::invalid_argument("rejected by the front stage"))
        })
        .unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), "rejected by the front stage");
        assert!(
            sock.exists(),
            "socket must stay when the front stage rejects"
        );
        let log = std::fs::read_to_string(dir.join("ops.log")).unwrap();
        assert!(log.contains("cri.shim_v2.delete"), "{log}");

        let ok = unix_impl::delete_recorded(&inv, &dir, |_, _| Ok(None)).unwrap();
        // 応答は終了時刻を含むため、先頭の exit_status(137) だけを具体値で照合する。
        assert_eq!(ok.get(..3), Some(&[0x10, 0x89, 0x01][..]));
        assert!(!sock.exists(), "socket is removed on the normal path");
    }

    /// REPAIR-5・CRI-5・#4152: 他者が id の lock を持っていても、`run_delete` の待ちは delete 全体の絶対期限で打ち切られ、
    /// 既定の 10 秒（`LOCK_TIMEOUT`）を待たずに `TIMEOUT` になる。
    #[cfg(unix)]
    #[test]
    fn repair5_4152_run_delete_lock_wait_follows_overall_deadline() {
        let t = Tmp::new("dl");
        let dir = t.0.join("s");
        unix_impl::prepare_socket_dir(&dir).unwrap();
        let inv = parse_args(args(&[
            "-namespace",
            "default",
            "-address",
            "/run/c.sock",
            "-id",
            "abc",
            "-bundle",
            "/tmp/x/abc",
            "delete",
        ]))
        .unwrap();
        let _held = unix_impl::hold_id_lock_for_test(&dir, &inv);
        let started = std::time::Instant::now();
        let e = unix_impl::run_delete(
            &inv,
            &dir,
            None,
            started + std::time::Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(e.code(), CriErrorCode::Timeout);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
