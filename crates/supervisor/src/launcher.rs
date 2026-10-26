//! 特権ランチャー（`fandhe-container-launcher`）の入口検証と起動処理（SUP-14・SEC-1・CORE-1・REPAIR-5・
//! TASK-171 追補・#1719・MS-9）。
//!
//! # 役割
//! 権限分離の方式（#1454 のオーナー判断 2026-10-10。`docs/design/privilege-separation.md` 9 章）の入口となる bin
//! `src/bin/fandhe-container-launcher.rs` の実体。ランチャーは「入口の検証 → [`crate::privilege::elevate`] →
//! 検証済み fd で supervisor を exec」だけを行い、それ以外の特権操作はしない。新規依存は無い。
//!
//! # 呼び出し元・呼び出し先
//! - 呼び出し元: CLI（#1718）が固定のインストール先から起動する（file capability を持つ非 root の bin〔方式 (c)〕、
//!   または xattr 非対応環境に限る setuid root の bin〔方式 (a)〕。付与は `scripts/install-privileged-launcher.sh`〔#1721〕）
//! - 呼び出し先: [`crate::start_contract::StartArgs::parse`]（引数の検証）、[`crate::privilege::elevate`]（縮退）、
//!   `crate::sys` の `execveat_fd`（検証済み fd の exec）、[`crate::stderr_sink`]（期限つきの報告）
//!
//! # 入口の検証（設計書 7 章）
//! - セッション: 何よりも先に `setsid` で新しいセッションへ移り、標準入出力が端末（pty）でないこと・制御端末が無いこと・
//!   自分がセッションとプロセスグループのリーダーであることを読み戻しで確認する（SUP-14 の要素 (B)。TASK-171.2・#537。
//!   [`crate::privilege::detach_session`]）。`sudo`（`use_pty`）経由の起動は標準入出力が pty になるため拒否される
//! - 引数: supervisor と同じ `StartArgs::parse` で構造検証し、通った列だけをそのまま転送する。`argv[0]` は固定
//! - 環境変数: `std::env` を書き換えず、exec に渡す環境を新規に組み立てる（許可リスト方式。[`sanitize_env`]）。
//!   ambient 付きの exec では AT_SECURE が立たず ld.so が `LD_PRELOAD` 等を除去しないことがあるため、
//!   ランチャーが確実に落とす
//! - supervisor のパス: ランチャー自身の実体パスの親ディレクトリ + 固定のファイル名のみ。`PATH` 探索も呼び出し元が
//!   与えるパスも受け付けない（[`supervisor_path_beside`]）
//! - 実体: パスの全要素を辿って root 所有・他者書き込み不可を確かめ（[`verify_install_chain`]）、`open` した fd に
//!   `fstat` をかけて同じ条件を確かめ、検証した同じ fd を `execveat(AT_EMPTY_PATH)` で exec する（TOCTOU 回避）
//! - 継承 fd・cwd・ダンプ: fd 0〜2 が開いていることを確認し、fd 3 以降を閉じ（supervisor の入口でも同じ処理を行う。#2070）、cwd を `/` にし、
//!   `PR_SET_DUMPABLE=0` を `elevate` の前に設定する（設計書 7 章の「実装時に決める」項目をここで確定した）
//!
//! # 起動側（呼び出し元）への契約（#537）
//! - ランチャーを `process_group(0)` で起動しない。ランチャーがプロセスグループのリーダーだと `setsid` が `EPERM` に
//!   なり拒否される（ランチャーの `setsid` が新しいセッションとプロセスグループを作るので代わりになる）。CLI が
//!   ランチャーを選ぶ規則を入れる際の前提とする（CLI の選択の規則は `start_client`。#2442）
//! - 標準入出力に端末（pty）を渡さない（pipe・`/dev/null`・ファイルを渡す）
//!
//! # supervisor 側の不変条件: 端末の `open` に `O_NOCTTY`（SUP-14・TASK-171.2・#537・#2426）
//! - exec 後の supervisor（とその中で動くコード）が、端末になりうる対象を `open` するときは常に `O_NOCTTY` を付ける。
//!   端末になりうる対象とは、端末デバイスそのもの・利用者が指定するパス・open 前の確認と open の間に差し替えられうる
//!   パスをいう
//! - 理由: ランチャーは fork せずに `setsid` してから supervisor を exec するため、supervisor は生涯セッションリーダーで
//!   制御端末を持たない。Linux ではこの状態で `O_NOCTTY` なしに端末を開くとそれが制御端末になり、`TIOCSTI` による
//!   入力注入や hangup 時の SIGHUP の波及という、#537 で断った経路が再発する
//! - 対象になりうる将来の箇所: tty 対応（attach 等）・healthcheck の exec（#2441）・ログや env ファイル等の外部指定パスの open
//! - 先例: core の `exec/process.rs`（setsid 後の fd の開き直し）と core の `sys.rs` の `O_NOCTTY`
//! - 現状の担保: 外部指定パスを開く 2 つのヘルパー（`container_options::env::open_nonblocking`・
//!   `logs::rotating::open_read_nofollow_nonblocking`）が `O_NOCTTY` を付け、単体テストでフラグを照合する。
//!   対象外の open（`/proc/self/*`・ディレクトリ・新規作成のほか、`/etc` 配下の root 管理ファイル〔nsswitch.conf・
//!   passwd 等。`user_db`・`id_model`〕と導入経路を検証済みの実行ファイル〔ランチャーの supervisor 検証〕）は、
//!   利用者が端末へ差し替えられない経路のため `O_NOCTTY` を付けない。これらの経路を利用者指定パスへ広げるときは
//!   端末になりうる対象に当たるので `O_NOCTTY` を付ける
//!
//! # 失敗時の契約（fail-closed）
//! 昇格できない場合（file capability も setuid も無い・`nosuid`・`no_new_privs`）は構造化エラーで非ゼロ終了し、
//! `sudo` へ黙って戻らない。`elevate` が `Err` を返した後は exec も特権操作もしない。結果は stdout（結果チャネル）に
//! `FCSUP1 ERR ...` の 1 行（[`crate::start_contract::StartReport`]）、stderr に構造化 JSON を 1 行出す。
//! ランチャーは待機をしない（exec で置き換わる）ため、タイムアウトの対象は報告の書き込みだけで、
//! 読み手が止まっていても期限（1 秒）で終了する（REPAIR-5）。報告用スレッドは `elevate`（単一スレッドを要求する）が
//! 終わった後にだけ作る。
//!
//! # 未実装・範囲外（REPAIR-3。実装済みを装わない）
//! - hash / 署名による supervisor の照合: 今回は行わない。信頼の根拠はファイルシステムの所有権と書き込み権限のみ
//!   （PLUG-11 との整合は設計書 12 章に未確認として残す）
//! - ambient capability は exec 後の子孫へ引き継がれる。子で落とす箇所は 2 つ: (1) コンテナの子は core の制限段
//!   （`fandhe_container_core::exec` の capability 段。ambient を全消去してから bounding / capset）。(2) supervisor の
//!   healthcheck コマンド実行は未実装（TASK-161.2・#2441）で、実装時に子で ambient を落としてから exec する要件を
//!   #2441 へ記録する（設計書 5 章 5・10 章）。取りこぼしがないことの確認は実機検証（#538・#539。人間担当）
//! - setcap / setuid の付与（`scripts/install-privileged-launcher.sh`。#1721 で実装済み）・CLI `setup` の表示（#1722）
//!   （`setsid` と pty 非経由の確認〔#537〕は実装済み。実機での確認は #539）

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
use fandhe_container_core::traits::{ErrorCode, TraitError};

use crate::privilege::{PrivilegeError, PrivilegeMethod, UidSet};

/// 同じディレクトリに置く supervisor の固定のファイル名。
pub const SUPERVISOR_FILE_NAME: &str = "fandhe-container-supervisor";
/// 特権ランチャーの固定のファイル名（`[[bin]]` 名・`scripts/install-privileged-launcher.sh` の `LAUNCHER_NAME` と一致。
/// CLI の `start` が実体の隣にこれを見つけたら rootful のインストールとみなす。#2442）。
pub const LAUNCHER_FILE_NAME: &str = "fandhe-container-launcher";
/// supervisor へ渡す `argv[0]`（固定）。
pub const SUPERVISOR_ARGV0: &str = SUPERVISOR_FILE_NAME;
/// supervisor へ渡す環境の `PATH`（固定。呼び出し元の `PATH` は渡さない）。
pub const FIXED_PATH_ENV: &str = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
/// 呼び出し元の環境から通す変数名の許可リスト。supervisor は契約の値を環境から読まない
/// （`start_contract` は環境変数を契約に含めない）ため空。`LD_` 始まりと `PATH` は入れない
/// （定数の単体テストで機械照合する）。
pub const PASSTHROUGH_ENV: &[&str] = &[];
/// 通す環境変数の値の最大バイト数（無制限確保の防止）。
pub const MAX_ENV_VALUE_LEN: usize = 4096;
/// 検証するパスの最大バイト数。
pub const MAX_PATH_LEN: usize = 4096;
/// 検証中に辿る symlink の最大数。
pub const MAX_SYMLINK_DEPTH: u32 = 8;
/// 報告の書き込みを待つ上限（REPAIR-5）。
pub const REPORT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

/// 失敗の理由分類（機械可読）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LauncherErrorReason {
    /// 引数が supervisor の契約に合わない。
    InvalidArguments,
    /// fd 0・1・2 のいずれかが閉じている。
    StdioNotOpen,
    /// ランチャー自身の実体パスを得られない（`/proc` が読めない等）。
    SelfPathUnresolvable,
    /// パスが絶対でない・`..` を含む・長すぎる。
    PathNotAbsolute,
    /// パスの途中を調べられない、または信頼できない。
    PathUntrusted,
    /// symlink の所有者が root でない。
    SymlinkNotRootOwned,
    /// symlink の段数が上限を超えた。
    TooManySymlinks,
    /// 通常ファイルでない。
    NotRegularFile,
    /// setuid / setgid ビットが付いている。
    SetidBitsPresent,
    /// group / other が書き込める。
    WritableByGroupOrOther,
    /// 所有者が root でない。
    OwnerNotRoot,
    /// 親ディレクトリ（または symlink の先）が root 所有・他者書き込み不可でない。
    AncestorNotTrusted,
    /// 権限昇格に失敗した（昇格手段が無い場合を含む）。
    Elevation,
    /// 昇格後の exec に失敗した。
    ExecFailed,
    /// 新しいセッションへ切り離せなかった、または pty 経由の起動だった（標準入出力が端末・制御端末の残存・
    /// プロセスグループのリーダーとして起動された。SUP-14・TASK-171.2・#537）。
    SessionNotDetached,
    /// 事前処理（fd の整理・dumpable・cwd）に失敗した。
    SetupFailed,
    /// この OS / アーキテクチャでは未対応。
    Unsupported,
}

/// ランチャーの失敗（機械可読な `code` と英語の `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LauncherError {
    /// 機械可読なエラーコード。
    pub code: ErrorCode,
    /// 理由分類。
    pub reason: LauncherErrorReason,
    /// 人間向けの説明（英語）。
    pub message: String,
}

impl LauncherError {
    fn new(code: ErrorCode, reason: LauncherErrorReason, message: impl Into<String>) -> Self {
        Self {
            code,
            reason,
            message: message.into(),
        }
    }

    fn denied(reason: LauncherErrorReason, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, reason, message)
    }

    /// 結果チャネルと stderr の報告に使う `OciRuntimeError`（`LifecycleOp::Start`）へ変換する。
    pub fn to_oci_error(&self) -> OciRuntimeError {
        OciRuntimeError::new(LifecycleOp::Start, self.code, &self.message)
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for LauncherError {}

impl From<PrivilegeError> for LauncherError {
    fn from(e: PrivilegeError) -> Self {
        Self::new(
            e.code,
            LauncherErrorReason::Elevation,
            format!("privilege elevation failed: {}", e.message),
        )
    }
}

/// セッション切り離し（[`crate::privilege::detach_session`]）の失敗を `SessionNotDetached` に写す。
/// コードは検証の拒否が `FAILED_PRECONDITION`、syscall の失敗が `INTERNAL` で、`PrivilegeError` のものをそのまま引き継ぐ。
#[cfg(any(target_os = "linux", test))]
fn session_error(e: PrivilegeError) -> LauncherError {
    LauncherError::new(
        e.code,
        LauncherErrorReason::SessionNotDetached,
        format!("session detach failed: {}", e.message),
    )
}

impl From<TraitError> for LauncherError {
    fn from(e: TraitError) -> Self {
        Self::new(
            e.code(),
            LauncherErrorReason::InvalidArguments,
            e.message().to_owned(),
        )
    }
}

/// exec に渡す環境を組み立てる（許可リスト方式）。固定の `PATH` だけを先頭に置き、[`PASSTHROUGH_ENV`] に載った名前で
/// 値が UTF-8・NUL 無し・[`MAX_ENV_VALUE_LEN`] 以下のものだけを残す。他はすべて捨てる。
pub fn sanitize_env<I, K, V>(vars: I) -> Vec<String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    sanitize_env_with(PASSTHROUGH_ENV, vars)
}

fn sanitize_env_with<I, K, V>(allow: &[&str], vars: I) -> Vec<String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let mut out = vec![FIXED_PATH_ENV.to_owned()];
    for (k, v) in vars {
        let (Some(k), Some(v)) = (k.as_ref().to_str(), v.as_ref().to_str()) else {
            continue;
        };
        if allow.contains(&k) && !v.contains('\0') && v.len() <= MAX_ENV_VALUE_LEN {
            out.push(format!("{k}={v}"));
        }
    }
    out
}

/// パス上のノードの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// ディレクトリ。
    Dir,
    /// 通常ファイル。
    File,
    /// symlink（`lstat` の結果）。
    Symlink,
    /// それ以外（FIFO・ソケット・デバイス等）。
    Other,
}

/// 検証に使うノードのメタデータ（`lstat` / `fstat` の写し）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeMeta {
    /// 種別。
    pub kind: NodeKind,
    /// 所有者の uid。
    pub uid: u32,
    /// `st_mode & 0o7777`（種別ビットを含まない）。
    pub mode: u32,
}

/// パス検証のためのファイルシステム参照（実装は Linux の実 FS、試験では偽物）。
pub trait PathProbe {
    /// symlink を辿らない `lstat`。
    fn lstat(&self, path: &Path) -> io::Result<NodeMeta>;
    /// symlink の先の文字列。
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
}

fn untrusted(path: &Path, what: &str, err: &io::Error) -> LauncherError {
    LauncherError::denied(
        LauncherErrorReason::PathUntrusted,
        format!("cannot inspect {what} {}: {}", path.display(), err.kind()),
    )
}

/// ディレクトリの信頼条件: ディレクトリで、root 所有で、group / other が書き込めない（sticky でも免除しない）。
fn check_trusted_dir(path: &Path, meta: &NodeMeta) -> Result<(), LauncherError> {
    if meta.kind != NodeKind::Dir {
        return Err(LauncherError::denied(
            LauncherErrorReason::AncestorNotTrusted,
            format!("path component {} is not a directory", path.display()),
        ));
    }
    if meta.uid != 0 {
        return Err(LauncherError::denied(
            LauncherErrorReason::AncestorNotTrusted,
            format!(
                "directory {} is owned by uid {}, not root",
                path.display(),
                meta.uid
            ),
        ));
    }
    if meta.mode & 0o022 != 0 {
        return Err(LauncherError::denied(
            LauncherErrorReason::AncestorNotTrusted,
            format!(
                "directory {} is writable by group or other (mode {:04o})",
                path.display(),
                meta.mode
            ),
        ));
    }
    Ok(())
}

/// 最終ファイルの信頼条件。最初に失敗した理由を返す検査順は固定:
/// 通常ファイル → setuid / setgid 無し → group / other 書き込み不可 → root 所有。
pub fn check_final_file(path: &Path, meta: &NodeMeta) -> Result<(), LauncherError> {
    if meta.kind != NodeKind::File {
        return Err(LauncherError::denied(
            LauncherErrorReason::NotRegularFile,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.mode & 0o6000 != 0 {
        return Err(LauncherError::denied(
            LauncherErrorReason::SetidBitsPresent,
            format!(
                "{} has setuid or setgid bits (mode {:04o})",
                path.display(),
                meta.mode
            ),
        ));
    }
    if meta.mode & 0o022 != 0 {
        return Err(LauncherError::denied(
            LauncherErrorReason::WritableByGroupOrOther,
            format!(
                "{} is writable by group or other (mode {:04o})",
                path.display(),
                meta.mode
            ),
        ));
    }
    if meta.uid != 0 {
        return Err(LauncherError::denied(
            LauncherErrorReason::OwnerNotRoot,
            format!("{} is owned by uid {}, not root", path.display(), meta.uid),
        ));
    }
    Ok(())
}

/// `path`（絶対・`..` 無し）を字句どおりに辿り、根から親までのすべてのディレクトリと、途中の symlink（所有者が
/// root のものに限る）の先、最終ファイルが信頼条件を満たすか検証する。symlink は自前で解決し、解決後の実体パス
/// （symlink を含まない）を返す。深さは [`MAX_SYMLINK_DEPTH`] まで。
///
/// 検証は `elevate` より前に行い、失敗しても権限を縮退させない。呼び出し側は返された実体パスを `open` し、
/// その fd の `fstat` を [`check_final_file`] で再検査してから exec する。
pub fn verify_install_chain(probe: &dyn PathProbe, path: &Path) -> Result<PathBuf, LauncherError> {
    if !path.has_root() || path.as_os_str().len() > MAX_PATH_LEN {
        return Err(LauncherError::denied(
            LauncherErrorReason::PathNotAbsolute,
            "path must be absolute and at most 4096 bytes",
        ));
    }
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => pending.push_back(n.to_owned()),
            _ => {
                return Err(LauncherError::denied(
                    LauncherErrorReason::PathNotAbsolute,
                    "path must not contain '..' components",
                ));
            }
        }
    }
    let root = Path::new("/");
    let meta = probe
        .lstat(root)
        .map_err(|e| untrusted(root, "directory", &e))?;
    check_trusted_dir(root, &meta)?;
    let mut resolved = PathBuf::from("/");
    let mut links = 0u32;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            // symlink の先に含まれる `..`。検証済みの親ディレクトリへ戻るだけ（根より上へは行かない）。
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&name);
        let meta = probe
            .lstat(&candidate)
            .map_err(|e| untrusted(&candidate, "component", &e))?;
        match meta.kind {
            NodeKind::Symlink => {
                if meta.uid != 0 {
                    return Err(LauncherError::denied(
                        LauncherErrorReason::SymlinkNotRootOwned,
                        format!(
                            "symlink {} is owned by uid {}, not root",
                            candidate.display(),
                            meta.uid
                        ),
                    ));
                }
                links += 1;
                if links > MAX_SYMLINK_DEPTH {
                    return Err(LauncherError::denied(
                        LauncherErrorReason::TooManySymlinks,
                        format!("more than {MAX_SYMLINK_DEPTH} symlinks while resolving the path"),
                    ));
                }
                let target = probe
                    .read_link(&candidate)
                    .map_err(|e| untrusted(&candidate, "symlink", &e))?;
                if target.as_os_str().len() > MAX_PATH_LEN {
                    return Err(LauncherError::denied(
                        LauncherErrorReason::PathNotAbsolute,
                        "symlink target is too long",
                    ));
                }
                if target.has_root() {
                    resolved = PathBuf::from("/");
                }
                // 先頭から順に処理するため、先の要素を pending の前へ積む。
                let mut expanded: Vec<std::ffi::OsString> = Vec::new();
                for c in target.components() {
                    match c {
                        Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
                        Component::ParentDir => expanded.push("..".into()),
                        Component::Normal(n) => expanded.push(n.to_owned()),
                    }
                }
                for n in expanded.into_iter().rev() {
                    pending.push_front(n);
                }
            }
            NodeKind::Dir if !pending.is_empty() => {
                check_trusted_dir(&candidate, &meta)?;
                resolved = candidate;
            }
            _ if pending.is_empty() => {
                check_final_file(&candidate, &meta)?;
                return Ok(candidate);
            }
            _ => {
                return Err(LauncherError::denied(
                    LauncherErrorReason::AncestorNotTrusted,
                    format!("path component {} is not a directory", candidate.display()),
                ));
            }
        }
    }
    Err(LauncherError::denied(
        LauncherErrorReason::NotRegularFile,
        format!("{} does not name a file", path.display()),
    ))
}

/// ランチャー自身の実体パス（`/proc/self/exe` の解決結果）から、同じディレクトリの固定名の supervisor のパスを作る。
/// `PATH` 探索も呼び出し元のパスも使わない。
pub fn supervisor_path_beside(launcher_exe: &Path) -> Result<PathBuf, LauncherError> {
    let dir = launcher_exe
        .parent()
        .filter(|d| d.has_root())
        .ok_or_else(|| {
            LauncherError::new(
                ErrorCode::FailedPrecondition,
                LauncherErrorReason::SelfPathUnresolvable,
                "launcher path has no absolute parent directory",
            )
        })?;
    Ok(dir.join(SUPERVISOR_FILE_NAME))
}

/// 現在の uid から方式を選ぶ。real が非 root で effective が 0 なら setuid root の代替（方式 (a)）、
/// それ以外は file capability + ambient（方式 (c)）。root 直起動などの不整合は `elevate` が `MethodMismatch` 等で拒否する。
pub fn select_method(uid: &UidSet) -> PrivilegeMethod {
    if uid.real != 0 && uid.effective == 0 {
        PrivilegeMethod::SetuidRoot
    } else {
        PrivilegeMethod::LauncherAmbient
    }
}

#[cfg(target_os = "linux")]
pub use linux::{RealProbe, run_main};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::process::ExitCode;

    use crate::privilege::{elevate, parse_proc_status};
    use crate::start_contract::{StartArgs, StartReport};
    use crate::stderr_sink::{StderrSink, stderr};

    /// 実 FS を参照する [`PathProbe`]。
    pub struct RealProbe;

    fn meta_of(m: &std::fs::Metadata) -> NodeMeta {
        let ft = m.file_type();
        let kind = if ft.is_dir() {
            NodeKind::Dir
        } else if ft.is_file() {
            NodeKind::File
        } else if ft.is_symlink() {
            NodeKind::Symlink
        } else {
            NodeKind::Other
        };
        NodeMeta {
            kind,
            uid: m.uid(),
            mode: m.mode() & 0o7777,
        }
    }

    impl PathProbe for RealProbe {
        fn lstat(&self, path: &Path) -> io::Result<NodeMeta> {
            std::fs::symlink_metadata(path).map(|m| meta_of(&m))
        }
        fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
            std::fs::read_link(path)
        }
    }

    fn setup_failed(what: &str, e: &io::Error) -> LauncherError {
        LauncherError::new(
            ErrorCode::Internal,
            LauncherErrorReason::SetupFailed,
            format!("{what} failed: {}", e.kind()),
        )
    }

    /// 結果チャネル（stdout）と stderr へ失敗を報告し、終了コードを返す。`elevate` の後にだけ呼ぶ
    /// （報告用スレッドを作るため）。書き込みは期限つき（REPAIR-5）。
    fn report_failure(err: &LauncherError) -> ExitCode {
        let oci = err.to_oci_error();
        let report = StartReport::failed(&oci).encode().into_bytes();
        if let Some(file) = dup_stdout() {
            let sink = StderrSink::spawn(file, 4);
            let _ = sink.emit_and_wait(report, REPORT_DEADLINE);
        }
        let mut line = Vec::new();
        if oci.write_json_line(&mut line).is_ok() {
            let _ = stderr().emit_and_wait(line, REPORT_DEADLINE);
        }
        ExitCode::from(oci.exit_code().get())
    }

    fn dup_stdout() -> Option<File> {
        use std::os::fd::AsFd;
        std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from)
    }

    /// `/proc/self/status` を上限つきで読む。
    fn read_self_status() -> io::Result<String> {
        let mut buf = String::new();
        File::open("/proc/self/status")?
            .take(crate::privilege::MAX_STATUS_BYTES as u64 + 1)
            .read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn to_cstrings<I: IntoIterator<Item = Vec<u8>>>(
        items: I,
    ) -> Result<Vec<CString>, LauncherError> {
        items
            .into_iter()
            .map(|b| {
                CString::new(b).map_err(|_| {
                    LauncherError::new(
                        ErrorCode::InvalidArgument,
                        LauncherErrorReason::InvalidArguments,
                        "value contains a NUL byte",
                    )
                })
            })
            .collect()
    }

    /// 入口の検証と昇格と exec。成功時は戻らない（`Err` は exec に至らなかった理由）。
    fn launch(
        args: Vec<OsString>,
        vars: Vec<(OsString, OsString)>,
    ) -> Result<std::convert::Infallible, LauncherError> {
        // セッションの切り離し（SUP-14 の要素 (B)。#537）。pty 経由の起動・制御端末の残存・プロセスグループの
        // リーダーとしての起動はここで拒否する。何よりも先に行い、拒否時は昇格にも exec にも進まない。
        crate::privilege::detach_session().map_err(session_error)?;
        // 継承 fd・cwd の整理。
        crate::sys::close_fds_from(crate::start_contract::FIRST_INHERITED_FD)
            .map_err(|e| setup_failed("closing inherited fds", &e))?;
        std::env::set_current_dir("/").map_err(|e| setup_failed("chdir to /", &e))?;
        // 引数: supervisor と同じ契約で検証し、通った列をそのまま転送する。
        StartArgs::parse(args.iter().cloned())?;
        let envp = to_cstrings(sanitize_env(vars).into_iter().map(String::into_bytes))?;
        let mut argv_bytes = vec![SUPERVISOR_ARGV0.as_bytes().to_vec()];
        argv_bytes.extend(args.iter().map(|a| a.as_bytes().to_vec()));
        let argv = to_cstrings(argv_bytes)?;
        // supervisor の実体: 自身と同じディレクトリの固定名。
        let exe = std::fs::read_link("/proc/self/exe").map_err(|e| {
            LauncherError::new(
                ErrorCode::FailedPrecondition,
                LauncherErrorReason::SelfPathUnresolvable,
                format!("cannot resolve the launcher path: {}", e.kind()),
            )
        })?;
        let wanted = supervisor_path_beside(&exe)?;
        let resolved = verify_install_chain(&RealProbe, &wanted)?;
        let file = File::open(&resolved).map_err(|e| untrusted(&resolved, "supervisor", &e))?;
        let meta = file
            .metadata()
            .map_err(|e| untrusted(&resolved, "supervisor", &e))?;
        check_final_file(&resolved, &meta_of(&meta))?;
        // 方式の選択（資格情報は /proc/self/status から。上限つき）。
        let status = read_self_status().map_err(|e| setup_failed("reading process status", &e))?;
        let snapshot = parse_proc_status(&status)?;
        let method = select_method(&snapshot.uid);
        // 昇格中の窓でダンプ・ptrace を受けない。
        crate::sys::set_dumpable(false).map_err(|e| setup_failed("PR_SET_DUMPABLE", &e))?;
        // 昇格。Err なら exec も特権操作もしない。
        elevate(method).map_err(LauncherError::from)?;
        // 検証済みの同じ fd を exec する。戻るのは失敗のときだけ。
        let e = match crate::sys::execveat_fd(file.as_raw_fd(), &argv, &envp) {
            Ok(()) => {
                return Err(LauncherError::new(
                    ErrorCode::Internal,
                    LauncherErrorReason::ExecFailed,
                    "exec returned unexpectedly",
                ));
            }
            Err(e) => e,
        };
        if e.kind() == io::ErrorKind::Unsupported {
            return Err(LauncherError::new(
                ErrorCode::Unimplemented,
                LauncherErrorReason::Unsupported,
                "exec by file descriptor is not supported on this architecture",
            ));
        }
        Err(LauncherError::new(
            ErrorCode::Internal,
            LauncherErrorReason::ExecFailed,
            format!("exec of the supervisor failed: {}", e.kind()),
        ))
    }

    /// ランチャー bin の入口（`src/bin/fandhe-container-launcher.rs` から呼ぶ）。`args` はプログラム名を除いた argv。
    pub fn run_main<A, E>(args: A, vars: E) -> ExitCode
    where
        A: IntoIterator<Item = OsString>,
        E: IntoIterator<Item = (OsString, OsString)>,
    {
        // fd 0〜2 が閉じていると後続の open が fd 1 などに割り当たり、結果チャネルを乗っ取れる。閉じていれば
        // 報告先が無いので、stderr（開いていれば）の JSON だけで終わる。
        if !(0..=2).all(crate::sys::fd_is_open) {
            let err = LauncherError::new(
                ErrorCode::FailedPrecondition,
                LauncherErrorReason::StdioNotOpen,
                "stdin, stdout and stderr must be open",
            );
            let oci = err.to_oci_error();
            let mut line = Vec::new();
            if oci.write_json_line(&mut line).is_ok() {
                // 昇格前の早期拒否。stderr が満杯 pipe でも期限で終わる（REPAIR-5）。
                let _ = stderr().emit_and_wait(line, REPORT_DEADLINE);
            }
            return ExitCode::from(oci.exit_code().get());
        }
        match launch(args.into_iter().collect(), vars.into_iter().collect()) {
            Ok(never) => match never {},
            Err(err) => report_failure(&err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeFs {
        nodes: HashMap<PathBuf, NodeMeta>,
        links: HashMap<PathBuf, PathBuf>,
    }

    impl FakeFs {
        fn dir(mut self, p: &str, uid: u32, mode: u32) -> Self {
            self.nodes.insert(
                p.into(),
                NodeMeta {
                    kind: NodeKind::Dir,
                    uid,
                    mode,
                },
            );
            self
        }
        fn file(mut self, p: &str, uid: u32, mode: u32) -> Self {
            self.nodes.insert(
                p.into(),
                NodeMeta {
                    kind: NodeKind::File,
                    uid,
                    mode,
                },
            );
            self
        }
        fn kind(mut self, p: &str, kind: NodeKind) -> Self {
            self.nodes.insert(
                p.into(),
                NodeMeta {
                    kind,
                    uid: 0,
                    mode: 0o755,
                },
            );
            self
        }
        fn link(mut self, p: &str, uid: u32, to: &str) -> Self {
            self.nodes.insert(
                p.into(),
                NodeMeta {
                    kind: NodeKind::Symlink,
                    uid,
                    mode: 0o777,
                },
            );
            self.links.insert(p.into(), to.into());
            self
        }
        /// `/`・`/opt`・`/opt/fandhe` を root 所有 0o755 にした基本形。
        fn base() -> Self {
            Self::default()
                .dir("/", 0, 0o755)
                .dir("/opt", 0, 0o755)
                .dir("/opt/fandhe", 0, 0o755)
        }
    }

    impl PathProbe for FakeFs {
        fn lstat(&self, path: &Path) -> io::Result<NodeMeta> {
            self.nodes
                .get(path)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
        fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
            self.links
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        }
    }

    const SUP: &str = "/opt/fandhe/fandhe-container-supervisor";

    fn verify(fs: &FakeFs, p: &str) -> Result<PathBuf, LauncherError> {
        verify_install_chain(fs, Path::new(p))
    }

    fn err_of(fs: &FakeFs, p: &str) -> (ErrorCode, LauncherErrorReason, String) {
        let e = verify(fs, p).unwrap_err();
        (e.code, e.reason, e.message)
    }

    /// エラーメッセージに埋まるパスの表示（期待値の組み立て用）。
    ///
    /// [`verify_install_chain`] は検証中のパスを `PathBuf::from("/")` へ要素を 1 つずつ `join` して作り、
    /// `display()` でメッセージへ埋める。パスはホスト OS の `Path` として扱う設計のため、区切りはホスト OS の
    /// ものになる（Linux・macOS では入力と同じ文字列、Windows では 2 要素目以降の前が `\`。CLI-1）。
    /// 期待値を `/` 固定の文字列にすると Windows でだけ食い違うため、実装と同じ手順で組み立てる。
    /// 具体値は `sup14_task1719_message_paths_use_host_separator` で OS ごとに固定する。
    fn shown(p: &str) -> String {
        let mut out = PathBuf::from("/");
        for c in Path::new(p).components() {
            if let Component::Normal(n) = c {
                out.push(n);
            }
        }
        out.display().to_string()
    }

    // ---- 環境 ----

    /// SUP-14・SEC-1: 危険な環境変数は残らず、固定の PATH だけが渡る。
    #[test]
    fn sup14_task1719_sanitize_env_drops_everything() {
        let vars = [
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("LD_AUDIT", "/tmp/a.so"),
            ("PATH", "/tmp/bin"),
            ("HOME", "/home/x"),
            ("GCONV_PATH", "/tmp"),
            ("LOCPATH", "/tmp"),
            ("NLSPATH", "/tmp"),
            ("MALLOC_PERTURB_", "1"),
            ("TMPDIR", "/tmp"),
        ];
        assert_eq!(
            sanitize_env(vars),
            vec!["PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_owned()]
        );
    }

    #[test]
    fn sup14_task1719_passthrough_list_is_safe() {
        for name in PASSTHROUGH_ENV {
            assert!(!name.starts_with("LD_"), "{name}");
            assert_ne!(*name, "PATH");
        }
        assert_eq!(FIXED_PATH_ENV, "PATH=/usr/sbin:/usr/bin:/sbin:/bin");
    }

    #[test]
    fn sup14_task1719_sanitize_env_allowlist_validates_values() {
        let long = "x".repeat(MAX_ENV_VALUE_LEN + 1);
        let ok = "y".repeat(MAX_ENV_VALUE_LEN);
        let vars = [
            ("KEEP", "v"),
            ("NUL", "a\0b"),
            ("LONG", long.as_str()),
            ("EDGE", ok.as_str()),
            ("OTHER", "z"),
        ];
        let out = sanitize_env_with(&["KEEP", "NUL", "LONG", "EDGE"], vars);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], FIXED_PATH_ENV);
        assert_eq!(out[1], "KEEP=v");
        assert_eq!(out[2], format!("EDGE={ok}"));
    }

    // ---- パス検証 ----

    /// SUP-14・CLI-1: メッセージへ埋まるパスの表示の具体値を OS ごとに固定する。Linux・macOS では入力の文字列
    /// そのもの（プログラムの出力は `/` 区切り）で、Windows では `Path::join` が足す区切りだけが `\` になる
    /// （根の直後は `/` のまま）。ランチャーの実 FS 参照と起動は Linux 限定で、Windows では純ロジックの試験だけが走る。
    #[test]
    fn sup14_task1719_message_paths_use_host_separator() {
        let (sup, dir) = if cfg!(windows) {
            (r"/opt\fandhe\fandhe-container-supervisor", r"/opt\fandhe")
        } else {
            ("/opt/fandhe/fandhe-container-supervisor", "/opt/fandhe")
        };
        assert_eq!(shown(SUP), sup);
        assert_eq!(shown("/opt/fandhe"), dir);
        assert_eq!(shown("/opt"), "/opt");
        assert_eq!(shown("/"), "/");
        // 実装が組み立てて返す実体パスの表示と一致する。
        let fs = FakeFs::base().file(SUP, 0, 0o755);
        assert_eq!(verify(&fs, SUP).unwrap().display().to_string(), sup);
    }

    #[test]
    fn sup14_task1719_accepts_root_owned_chain() {
        for mode in [0o755, 0o555, 0o750, 0o500] {
            let fs = FakeFs::base().file(SUP, 0, mode);
            assert_eq!(verify(&fs, SUP).unwrap(), PathBuf::from(SUP));
        }
    }

    #[test]
    fn sup14_task1719_rejects_writable_files() {
        let fs = FakeFs::base().file(SUP, 0, 0o666);
        let (code, reason, msg) = err_of(&fs, SUP);
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert_eq!(reason, LauncherErrorReason::WritableByGroupOrOther);
        assert_eq!(
            msg,
            format!("{} is writable by group or other (mode 0666)", shown(SUP))
        );
        let fs = FakeFs::base().file(SUP, 0, 0o664);
        assert_eq!(
            err_of(&fs, SUP).1,
            LauncherErrorReason::WritableByGroupOrOther
        );
        let fs = FakeFs::base().file(SUP, 0, 0o757);
        assert_eq!(
            err_of(&fs, SUP).1,
            LauncherErrorReason::WritableByGroupOrOther
        );
    }

    #[test]
    fn sup14_task1719_rejects_setid_and_non_regular_and_non_root_owner() {
        let fs = FakeFs::base().file(SUP, 0, 0o4755);
        let (_, reason, msg) = err_of(&fs, SUP);
        assert_eq!(reason, LauncherErrorReason::SetidBitsPresent);
        assert!(msg.ends_with("(mode 4755)"), "{msg}");
        let fs = FakeFs::base().file(SUP, 0, 0o2755);
        assert_eq!(err_of(&fs, SUP).1, LauncherErrorReason::SetidBitsPresent);
        for k in [NodeKind::Dir, NodeKind::Other] {
            let fs = FakeFs::base().kind(SUP, k);
            assert_eq!(err_of(&fs, SUP).1, LauncherErrorReason::NotRegularFile);
        }
        let fs = FakeFs::base().file(SUP, 1000, 0o755);
        let (code, reason, msg) = err_of(&fs, SUP);
        assert_eq!(
            (code, reason),
            (
                ErrorCode::PermissionDenied,
                LauncherErrorReason::OwnerNotRoot
            )
        );
        assert_eq!(
            msg,
            format!("{} is owned by uid 1000, not root", shown(SUP))
        );
    }

    #[test]
    fn sup14_task1719_rejects_untrusted_ancestors() {
        // 親ディレクトリが root 以外の所有。
        let fs = FakeFs::default()
            .dir("/", 0, 0o755)
            .dir("/opt", 0, 0o755)
            .dir("/opt/fandhe", 1000, 0o755)
            .file(SUP, 0, 0o755);
        let (code, reason, msg) = err_of(&fs, SUP);
        assert_eq!(
            (code, reason),
            (
                ErrorCode::PermissionDenied,
                LauncherErrorReason::AncestorNotTrusted
            )
        );
        assert_eq!(
            msg,
            format!(
                "directory {} is owned by uid 1000, not root",
                shown("/opt/fandhe")
            )
        );
        // 親ディレクトリが 0o777。
        let fs = FakeFs::default()
            .dir("/", 0, 0o755)
            .dir("/opt", 0, 0o755)
            .dir("/opt/fandhe", 0, 0o777)
            .file(SUP, 0, 0o755);
        let (_, reason, msg) = err_of(&fs, SUP);
        assert_eq!(reason, LauncherErrorReason::AncestorNotTrusted);
        assert_eq!(
            msg,
            format!(
                "directory {} is writable by group or other (mode 0777)",
                shown("/opt/fandhe")
            )
        );
        // 深い祖先の 1 要素だけが不正（sticky でも免除しない: /tmp 相当）。
        let fs = FakeFs::default()
            .dir("/", 0, 0o755)
            .dir("/opt", 0, 0o1777)
            .dir("/opt/fandhe", 0, 0o755)
            .file(SUP, 0, 0o755);
        let (_, reason, msg) = err_of(&fs, SUP);
        assert_eq!(reason, LauncherErrorReason::AncestorNotTrusted);
        assert!(msg.starts_with("directory /opt is writable"), "{msg}");
        assert!(msg.ends_with("(mode 1777)"), "{msg}");
        // 根自体が不正。
        let fs = FakeFs::default()
            .dir("/", 1000, 0o755)
            .dir("/opt", 0, 0o755)
            .dir("/opt/fandhe", 0, 0o755)
            .file(SUP, 0, 0o755);
        assert_eq!(err_of(&fs, SUP).1, LauncherErrorReason::AncestorNotTrusted);
    }

    #[test]
    fn sup14_task1719_rejects_bad_paths() {
        let fs = FakeFs::base().file(SUP, 0, 0o755);
        for p in [
            "opt/fandhe/fandhe-container-supervisor",
            "/opt/../opt/fandhe/fandhe-container-supervisor",
        ] {
            assert_eq!(
                err_of(&fs, p).1,
                LauncherErrorReason::PathNotAbsolute,
                "{p}"
            );
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(err_of(&fs, &long).1, LauncherErrorReason::PathNotAbsolute);
        // 存在しない要素は途中を調べられず拒否。
        assert_eq!(
            err_of(&fs, "/opt/missing/x").1,
            LauncherErrorReason::PathUntrusted
        );
    }

    #[test]
    fn sup14_task1719_symlink_rules() {
        // root 所有の symlink を辿る。解決後の実体パスが返る。
        let fs = FakeFs::base()
            .dir("/usr", 0, 0o755)
            .dir("/usr/lib", 0, 0o755)
            .file("/usr/lib/sup", 0, 0o755)
            .link("/opt/fandhe/fandhe-container-supervisor", 0, "/usr/lib/sup");
        assert_eq!(verify(&fs, SUP).unwrap(), PathBuf::from("/usr/lib/sup"));
        // 相対 symlink と `..`。
        let fs = FakeFs::base()
            .dir("/usr", 0, 0o755)
            .file("/usr/sup", 0, 0o755)
            .link(
                "/opt/fandhe/fandhe-container-supervisor",
                0,
                "../../usr/sup",
            );
        assert_eq!(verify(&fs, SUP).unwrap(), PathBuf::from("/usr/sup"));
        // symlink が root 以外の所有。
        let fs = FakeFs::base().file("/usr/sup", 0, 0o755).link(
            "/opt/fandhe/fandhe-container-supervisor",
            1000,
            "/usr/sup",
        );
        let (code, reason, msg) = err_of(&fs, SUP);
        assert_eq!(
            (code, reason),
            (
                ErrorCode::PermissionDenied,
                LauncherErrorReason::SymlinkNotRootOwned
            )
        );
        assert_eq!(
            msg,
            format!("symlink {} is owned by uid 1000, not root", shown(SUP))
        );
        // 先の実体が不正。
        let fs = FakeFs::base()
            .dir("/usr", 0, 0o755)
            .file("/usr/sup", 0, 0o666)
            .link("/opt/fandhe/fandhe-container-supervisor", 0, "/usr/sup");
        assert_eq!(
            err_of(&fs, SUP).1,
            LauncherErrorReason::WritableByGroupOrOther
        );
        // 先の親ディレクトリが不正。
        let fs = FakeFs::base()
            .dir("/usr", 0, 0o777)
            .file("/usr/sup", 0, 0o755)
            .link("/opt/fandhe/fandhe-container-supervisor", 0, "/usr/sup");
        assert_eq!(err_of(&fs, SUP).1, LauncherErrorReason::AncestorNotTrusted);
        // 段数超過（自己参照のループ）。
        let fs = FakeFs::base().link("/opt/fandhe/fandhe-container-supervisor", 0, SUP);
        let (_, reason, msg) = err_of(&fs, SUP);
        assert_eq!(reason, LauncherErrorReason::TooManySymlinks);
        assert_eq!(msg, "more than 8 symlinks while resolving the path");
    }

    // ---- パス構築・方式 ----

    #[test]
    fn sup14_task1719_supervisor_path_is_fixed_beside_launcher() {
        assert_eq!(
            supervisor_path_beside(Path::new("/opt/fandhe/fandhe-container-launcher")).unwrap(),
            PathBuf::from(SUP)
        );
        let e = supervisor_path_beside(Path::new("fandhe-container-launcher")).unwrap_err();
        assert_eq!(e.reason, LauncherErrorReason::SelfPathUnresolvable);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
    }

    fn uids(real: u32, effective: u32) -> UidSet {
        UidSet {
            real,
            effective,
            saved: effective,
            fs: effective,
        }
    }

    #[test]
    fn sup14_task1719_select_method() {
        assert_eq!(
            select_method(&uids(1000, 1000)),
            PrivilegeMethod::LauncherAmbient
        );
        assert_eq!(select_method(&uids(1000, 0)), PrivilegeMethod::SetuidRoot);
        // root 直起動は (c) を選び、elevate が MethodMismatch で拒否する。
        assert_eq!(select_method(&uids(0, 0)), PrivilegeMethod::LauncherAmbient);
    }

    // ---- エラー変換・報告 ----

    #[test]
    fn sup14_task1719_report_round_trips_through_contract() {
        use crate::start_contract::StartReport;
        let e = LauncherError::denied(
            LauncherErrorReason::OwnerNotRoot,
            format!("{SUP} is owned by uid 1000, not root"),
        );
        let bytes = StartReport::failed(&e.to_oci_error()).encode();
        let exit = fandhe_container_core::oci_runtime::exit_code_for(ErrorCode::PermissionDenied);
        assert_eq!(
            bytes,
            format!("FCSUP1 ERR PERMISSION_DENIED {exit} {SUP} is owned by uid 1000, not root\n")
        );
        let decoded = StartReport::decode(bytes.as_bytes()).unwrap();
        assert_eq!(decoded, StartReport::failed(&e.to_oci_error()));
    }

    #[test]
    fn sup14_task1719_privilege_error_maps_to_elevation() {
        use crate::privilege::PrivilegeErrorReason;
        let pe = PrivilegeError {
            code: ErrorCode::PermissionDenied,
            reason: PrivilegeErrorReason::MissingCapabilities,
            message: "no capabilities".to_owned(),
        };
        let le = LauncherError::from(pe);
        assert_eq!(le.code, ErrorCode::PermissionDenied);
        assert_eq!(le.reason, LauncherErrorReason::Elevation);
        assert_eq!(le.message, "privilege elevation failed: no capabilities");
    }

    /// SUP-14・TASK-171.2・#537: セッション切り離しの失敗は `SessionNotDetached` と固有の接頭辞に写る（`Elevation` ではない）。
    #[test]
    fn sup14_task171_2_session_error_maps_to_session_not_detached() {
        use crate::privilege::PrivilegeErrorReason;
        let pe = PrivilegeError {
            code: ErrorCode::FailedPrecondition,
            reason: PrivilegeErrorReason::StdioIsTerminal,
            message: "stdio is a terminal".to_owned(),
        };
        let le = session_error(pe);
        assert_eq!(le.code, ErrorCode::FailedPrecondition);
        assert_eq!(le.reason, LauncherErrorReason::SessionNotDetached);
        assert_eq!(le.message, "session detach failed: stdio is a terminal");
    }

    #[test]
    fn sup14_task1719_invalid_arguments_map_to_invalid_argument() {
        use std::ffi::OsString;
        let bad: Vec<Vec<&str>> = vec![
            vec![],
            vec!["start", "--root", "relative", "c1"],
            vec!["start", "--bogus", "c1"],
            vec!["start", "--root", "/r", "--root", "/r", "c1"],
            vec!["start", "--root", "/r"],
        ];
        for argv in bad {
            let r = crate::start_contract::StartArgs::parse(argv.iter().map(OsString::from));
            let le = LauncherError::from(r.unwrap_err());
            assert_eq!(le.code, ErrorCode::InvalidArgument, "{argv:?}");
            assert_eq!(le.reason, LauncherErrorReason::InvalidArguments);
        }
    }

    /// CRI-2・SUP-4・#2671: `--cri-log-path` 付きの argv は検証を通って転送され、不正な値は InvalidArgument で拒否される。
    /// 転送後の supervisor は ambient capability つきでは CRI ログを開かず拒否する（`logs::cri::deny_elevated_capabilities`）。
    #[test]
    fn cri2_launcher_validates_cri_log_path_argument() {
        use std::ffi::OsString;
        let parse = |argv: &[&str]| {
            crate::start_contract::StartArgs::parse(argv.iter().map(OsString::from))
        };
        let ok = parse(&[
            "start",
            "--root",
            "/r",
            "--cri-log-path",
            "/l/c/0.log",
            "c1",
        ])
        .expect("accepted");
        assert_eq!(ok.cri_log_path.expect("path").as_str(), "/l/c/0.log");
        let e = parse(&["start", "--root", "/r", "--cri-log-path", "../x", "c1"])
            .expect_err("rejected");
        let le = LauncherError::from(e);
        assert_eq!(le.code, ErrorCode::InvalidArgument);
        assert_eq!(le.reason, LauncherErrorReason::InvalidArguments);
    }
}
