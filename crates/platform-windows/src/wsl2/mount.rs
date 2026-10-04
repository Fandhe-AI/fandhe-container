//! virtiofs 共有マウントとコンテナ起動前の検証シーケンス（TASK-67.4・#375。WIN-1・WIN-2・ERR-1・REPAIR-2/3/4/5）。
//!
//! Windows のホストディレクトリを WSL2 ディストリ内の固定の基底（[`GUEST_MOUNT_BASE`]）配下へマウントし、
//! マウントが virtiofs で成立していることを確認してから、呼び出し側が渡す起動ステップへ進む。
//! 呼び出し元は `fandhe-container-plugin-windows`（TASK-116）。検証・マウントのどこかで失敗した場合は
//! 起動ステップを呼ばずに構造化エラー（`code` / `message`。ERR-1）を返す（fail-closed）。
//!
//! 構成:
//! - 入力の検証済み newtype（[`HostDir`]・[`MountName`]・[`DistroName`]・[`SharedMount`]・[`LaunchRequest`]）。
//!   生の文字列を `wsl.exe` の引数へ直接連結せず、型で「壊れた値を表現できない」ようにする（REPAIR-2）。
//! - 純粋関数（事前判定・argv 組み立て・`/proc/self/mountinfo` 解析）。全 OS でユニットテストする。
//! - 実行部（`run::run_capture` 経由。各呼び出しにタイムアウトを適用する。REPAIR-5）。
//!
//! 検証の本体はマウント後の fstype 確認である。`.wslconfig` の `virtiofs=true` はファイル上の設定に過ぎず、
//! `wsl --shutdown` までは稼働中の VM に反映されないため、設定の確認だけでは virtiofs の成立を保証できない。
//! 9P のまま成立した場合も `FAILED_PRECONDITION` で拒否し、暗黙に降格しない（9P へのフォールバックは
//! TASK-67.5・#376 の担当）。
//!
//! # 未実装範囲・前提（REPAIR-3）
//!
//! - ゲスト内のコンテナランタイム本体の常駐起動・監視は TASK-116 の担当。本モジュールは検証済みマウントを
//!   証明する [`PreparedLaunch`] と、それを受け取る起動ステップを注入する [`launch_with`] までを提供する。
//! - `mount -t drvfs <Windows パス> <マウント先>` が `virtiofs=true` 有効時に virtiofs で成立するという
//!   前提、およびマウントオプション `nosuid,nodev` の受理は実機で未検証（PoC-4 は机上調査のみ。WIN-2 の再検証
//!   条件）。コマンドの組み立ては `mount_argv` に集約しており、実機確認は TASK-67.6（#377）で行う。
//! - `wsl.exe` を差し替える結合試験（偽 `wsl.exe` のマウント系モード）は未整備。実行部は模擬実行器による
//!   ユニットテストで検証している。
//! - 暫定の `WinError` → `Wsl2Error` 変換（`win_error_to_wsl2`）は TASK-67.5（#376）でエラー型を共通化する際に
//!   置き換える。
//!
//! # 権限
//!
//! `--user root` は WSL2 ゲスト VM 内の root であり、Windows の管理者権限は要求も取得もしない。
//!
//! # 機微情報
//!
//! エラーメッセージには英語の固定文言と数値だけを載せる。ホストパス・ユーザー名・`.wslconfig` の内容・
//! `wsl.exe` の生出力は載せない。

use std::path::Path;
use std::time::Duration;

use super::{
    DistroState, MAX_OUTPUT_BYTES, Wsl2Error, Wsl2ErrorCode, Wsl2Status, check_timeout,
    detect_with_program, run, wsl_exe_path,
};
use crate::error::{WinError, WinErrorCode};
use crate::instrument::{NoopWinOpRecorder, WinOpKind, WinOpRecorder, record_win_op};
use crate::wslconfig::{self, VirtiofsState};

/// ゲスト内のマウント先の基底。マウント先は常に `<基底>/<MountName>`（任意パスへの上書きマウントを不可能にする）。
pub const GUEST_MOUNT_BASE: &str = "/mnt/fandhe";
/// 1 回の起動で指定できる共有マウント数の上限（`wsl.exe` の呼び出し回数を有界にする。REPAIR-5）。
pub const MAX_SHARED_MOUNTS: usize = 16;
/// ホストディレクトリ文字列の最大文字数（Unicode スカラー値単位。WIN-4 の推奨パス長 260 に合わせる）。
pub const MAX_HOST_DIR_LEN: usize = 260;
/// [`MountName`] の最大バイト数。
pub const MAX_MOUNT_NAME_LEN: usize = 64;
/// [`DistroName`] の最大文字数（Unicode スカラー値単位。`list_distros` の解析上限 128 文字と揃える）。
pub const MAX_DISTRO_NAME_LEN: usize = 128;
/// `/proc/self/mountinfo` として受け付ける最大バイト数（多数マウントのディストリで 64 KiB を超えうるため専用）。
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
/// `/proc/self/mountinfo` として受け付ける最大行数。
const MAX_MOUNTINFO_LINES: usize = 4096;
/// `/proc/self/mountinfo` の 1 行の最大バイト数。
const MAX_MOUNTINFO_LINE_LEN: usize = 4096;
/// マウントに必須の fstype。
const VIRTIOFS_FSTYPE: &str = "virtiofs";

/// Windows の予約デバイス名（拡張子付きでも予約される）。
const RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn invalid(msg: &str) -> Wsl2Error {
    Wsl2Error::new(Wsl2ErrorCode::InvalidArgument, msg)
}

fn precondition(msg: impl Into<String>) -> Wsl2Error {
    Wsl2Error::new(Wsl2ErrorCode::FailedPrecondition, msg)
}

/// 検証済みの Windows ホストディレクトリ（`X:\dir\sub` 形式のドライブレター絶対パスのみ）。
///
/// Linux の CI でも規則を検証できるよう、`Path` ではなく文字列で判定する。UNC・デバイスパス・相対・
/// `.` / `..`・代替データストリーム・ワイルドカード・制御文字・予約デバイス名・ドライブ直下そのものを拒否する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDir(String);

impl HostDir {
    /// 文字列を検証して作る。違反は `INVALID_ARGUMENT`（メッセージに入力は含めない）。
    pub fn parse(s: &str) -> Result<Self, Wsl2Error> {
        if s.chars().count() > MAX_HOST_DIR_LEN {
            return Err(invalid("host directory path is too long"));
        }
        let b = s.as_bytes();
        let drive_ok = matches!(b.first(), Some(c) if c.is_ascii_alphabetic())
            && b.get(1) == Some(&b':')
            && b.get(2) == Some(&b'\\');
        if !drive_ok {
            return Err(invalid(
                "host directory must be an absolute path starting with a drive letter, e.g. C:\\dir",
            ));
        }
        let rest = s.get(3..).unwrap_or_default();
        if rest.is_empty() {
            return Err(invalid("host directory must not be a drive root"));
        }
        if rest
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '<' | '>' | '|' | '/' | ':'))
        {
            return Err(invalid("host directory contains a forbidden character"));
        }
        for comp in rest.split('\\') {
            if comp.is_empty() || comp == "." || comp == ".." {
                return Err(invalid(
                    "host directory contains an empty or relative component",
                ));
            }
            if comp.starts_with(' ') || comp.ends_with(' ') || comp.ends_with('.') {
                return Err(invalid(
                    "host directory component has a leading or trailing space or dot",
                ));
            }
            let stem = comp
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if RESERVED_NAMES.contains(&stem.as_str()) {
                return Err(invalid("host directory contains a reserved device name"));
            }
        }
        Ok(Self(s.to_string()))
    }

    /// 検証済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 検証済みのゲスト内マウント名（`[A-Za-z0-9._-]`・1〜64 バイト・`.` / `..` / 先頭 `-` 不可）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountName(String);

impl MountName {
    /// 文字列を検証して作る。
    pub fn parse(s: &str) -> Result<Self, Wsl2Error> {
        let ok = !s.is_empty()
            && s.len() <= MAX_MOUNT_NAME_LEN
            && s != "."
            && s != ".."
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(invalid(
                "mount name must be 1-64 characters of [A-Za-z0-9._-], not '.', '..' or starting with '-'",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// 検証済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 検証済みのディストリ名（`wsl.exe` のオプションと誤認される先頭 `-`・制御文字・空・過長を拒否）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroName(String);

impl DistroName {
    /// 文字列を検証して作る。
    pub fn parse(s: &str) -> Result<Self, Wsl2Error> {
        let ok = !s.is_empty()
            && s.chars().count() <= MAX_DISTRO_NAME_LEN
            && !s.starts_with('-')
            && s.trim() == s
            && !s.chars().any(char::is_control);
        if !ok {
            return Err(invalid(
                "distribution name is empty, too long, or contains forbidden characters",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// 検証済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 共有マウント 1 件（ホストディレクトリ・ゲスト内の名前・読み取り専用か）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SharedMount {
    /// ホスト側ディレクトリ。
    pub host: HostDir,
    /// ゲスト内の名前（マウント先は `<GUEST_MOUNT_BASE>/<name>`）。
    pub name: MountName,
    /// 読み取り専用でマウントするか。
    pub read_only: bool,
}

impl SharedMount {
    /// 検証済みの部品から作る。
    pub fn new(host: HostDir, name: MountName, read_only: bool) -> Self {
        Self {
            host,
            name,
            read_only,
        }
    }

    /// ゲスト内のマウント先（固定の基底配下）。
    pub fn guest_path(&self) -> String {
        format!("{GUEST_MOUNT_BASE}/{}", self.name.as_str())
    }
}

/// 起動要求（ディストリと共有マウント一覧）。件数上限と、名前・ホストディレクトリの重複を拒否する。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchRequest {
    distro: DistroName,
    mounts: Vec<SharedMount>,
}

impl LaunchRequest {
    /// 要求を作る。件数超過・名前重複・ホストディレクトリ重複（大文字小文字非区別）は `INVALID_ARGUMENT`。
    pub fn new(distro: DistroName, mounts: Vec<SharedMount>) -> Result<Self, Wsl2Error> {
        if mounts.len() > MAX_SHARED_MOUNTS {
            return Err(invalid("too many shared mounts"));
        }
        for (i, a) in mounts.iter().enumerate() {
            for b in mounts.iter().skip(i + 1) {
                if a.name == b.name {
                    return Err(invalid("duplicate mount name"));
                }
                if a.host.as_str().to_lowercase() == b.host.as_str().to_lowercase() {
                    return Err(invalid("duplicate host directory"));
                }
            }
        }
        Ok(Self { distro, mounts })
    }

    /// 対象ディストリ。
    pub fn distro(&self) -> &DistroName {
        &self.distro
    }

    /// 共有マウント（0〜[`MAX_SHARED_MOUNTS`] 件）。フィールドを非公開にして `new` の検証
    /// （件数上限・重複拒否）を迂回できないようにしている。変更は検証済みの新しい要求を作り直す。
    pub fn mounts(&self) -> &[SharedMount] {
        &self.mounts
    }
}

/// 共有の輸送方式。現状は virtiofs のみ（9P は TASK-67.5・#376 が追加する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedTransport {
    /// virtiofs。
    Virtiofs,
}

/// 検証済みマウント 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreparedMount {
    /// ゲスト内のマウント先。
    pub guest_path: String,
    /// 読み取り専用か。
    pub read_only: bool,
}

/// 事前判定・マウント・fstype 確認がすべて成功したことの証明（フィールド非公開で外部から構築できない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLaunch {
    distro: DistroName,
    mounts: Vec<PreparedMount>,
    transport: SharedTransport,
}

impl PreparedLaunch {
    /// 対象ディストリ。
    pub fn distro(&self) -> &DistroName {
        &self.distro
    }

    /// マウント済みの一覧。
    pub fn mounts(&self) -> &[PreparedMount] {
        &self.mounts
    }

    /// 成立した輸送方式。
    pub fn transport(&self) -> SharedTransport {
        self.transport
    }
}

// ---- 純粋関数 ----

/// 事前判定（WSL2 のディストリ状態と `.wslconfig` の virtiofs opt-in。WIN-1・WIN-2）。
fn preflight(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
) -> Result<(), Wsl2Error> {
    let Some(d) = status
        .distros
        .iter()
        // `wsl --distribution` は大文字小文字を区別しないため、検索も合わせる。
        .find(|d| d.name.to_lowercase() == req.distro.as_str().to_lowercase())
    else {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::NotFound,
            "the requested WSL distribution was not found",
        ));
    };
    if !d.is_usable_wsl2() {
        let why = match d.state {
            DistroState::Running | DistroState::Stopped => "it is not a WSL2 distribution",
            _ => "it is not in a startable state",
        };
        return Err(precondition(format!(
            "the requested WSL distribution cannot be used: {why}"
        )));
    }
    if virtiofs != VirtiofsState::Enabled {
        return Err(precondition(
            "virtiofs is not enabled. Set 'virtiofs=true' under [wsl2] in .wslconfig and run 'wsl --shutdown' to apply it",
        ));
    }
    Ok(())
}

/// `wsl.exe` へ渡す引数: ゲスト内 root でシェルを介さず `cmd` を直接実行する。
fn exec_argv(distro: &DistroName, cmd: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = [
        "--distribution",
        distro.as_str(),
        "--user",
        "root",
        "--exec",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    v.extend(cmd.iter().map(|s| (*s).to_string()));
    v
}

/// 非再帰の `mkdir`（既存なら失敗する。`-p` は途中の symlink を辿るため使わない）。
fn mkdir_argv(distro: &DistroName, path: &str) -> Vec<String> {
    exec_argv(distro, &["mkdir", "-m", "755", "--", path])
}

/// symlink を辿らない `stat`（種別・UID・8 進パーミッション）。
fn stat_argv(distro: &DistroName, path: &str) -> Vec<String> {
    exec_argv(distro, &["stat", "-c", "%F %u %a", "--", path])
}

/// マウントコマンドの組み立て。`-t drvfs` が virtiofs で成立するかは実機未検証（TASK-67.6・#377。REPAIR-3）。
fn mount_argv(distro: &DistroName, m: &SharedMount) -> Vec<String> {
    let opts = if m.read_only {
        "nosuid,nodev,ro"
    } else {
        "nosuid,nodev"
    };
    exec_argv(
        distro,
        &[
            "mount",
            "-t",
            "drvfs",
            "-o",
            opts,
            m.host.as_str(),
            &m.guest_path(),
        ],
    )
}

fn umount_argv(distro: &DistroName, guest_path: &str) -> Vec<String> {
    exec_argv(distro, &["umount", guest_path])
}

fn mountinfo_argv(distro: &DistroName) -> Vec<String> {
    exec_argv(distro, &["cat", "/proc/self/mountinfo"])
}

/// `/proc/self/mountinfo` の 1 エントリ（マウント先と fstype だけ）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    mount_point: String,
    fstype: String,
}

/// mountinfo のマウント先の 8 進エスケープ（`\040` 等）を復号する。
fn unescape_mountinfo(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'\\' {
            let digits = b.get(i + 1..i + 4)?;
            if !digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                return None;
            }
            let v = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `/proc/self/mountinfo` を解析する。形式不明は `DATA_LOSS`、行数・行長の超過は `RESOURCE_EXHAUSTED`。
fn parse_mountinfo(text: &str) -> Result<Vec<MountEntry>, Wsl2Error> {
    let bad = || Wsl2Error::new(Wsl2ErrorCode::DataLoss, "unrecognized mountinfo format");
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if n >= MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_LEN {
            return Err(Wsl2Error::new(
                Wsl2ErrorCode::ResourceExhausted,
                "mountinfo exceeds the line count or line length limit",
            ));
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let sep = f.iter().position(|t| *t == "-").ok_or_else(bad)?;
        if sep < 6 {
            return Err(bad());
        }
        let mp = f.get(4).ok_or_else(bad)?;
        let fstype = f.get(sep + 1).ok_or_else(bad)?;
        entries.push(MountEntry {
            mount_point: unescape_mountinfo(mp).ok_or_else(bad)?,
            fstype: (*fstype).to_string(),
        });
    }
    if entries.is_empty() {
        return Err(bad());
    }
    Ok(entries)
}

/// 同一マウント先が複数ある場合は最後（最上位）のエントリを返す。
fn find_mount<'a>(entries: &'a [MountEntry], guest_path: &str) -> Option<&'a MountEntry> {
    entries.iter().rev().find(|e| e.mount_point == guest_path)
}

/// 暫定の `WinError` → `Wsl2Error` 変換。TASK-67.5（#376）でエラー型を共通化する際に置き換える（REPAIR-3）。
fn win_error_to_wsl2(e: &WinError) -> Wsl2Error {
    let code = match e.code() {
        WinErrorCode::InvalidArgument => Wsl2ErrorCode::InvalidArgument,
        WinErrorCode::NotFound => Wsl2ErrorCode::NotFound,
        WinErrorCode::PermissionDenied => Wsl2ErrorCode::PermissionDenied,
        WinErrorCode::ResourceExhausted => Wsl2ErrorCode::ResourceExhausted,
        WinErrorCode::Unimplemented => Wsl2ErrorCode::Unimplemented,
        _ => Wsl2ErrorCode::Internal,
    };
    Wsl2Error::new(code, e.message())
}

// ---- シーケンス（実行器を差し替え可能にした本体） ----

/// `wsl.exe` 相当の実行器: 引数列と stdout/stderr の上限バイト数を受け取り、タイムアウト付きで実行する。
type Exec<'a> = &'a mut dyn FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error>;

fn step_failed(what: &str, out: &run::Captured) -> Wsl2Error {
    let code = out
        .code
        .map_or_else(|| "none".to_string(), |c| c.to_string());
    precondition(format!(
        "{what} failed in the distribution (exit code {code})"
    ))
}

fn read_mountinfo(distro: &DistroName, exec: Exec<'_>) -> Result<Vec<MountEntry>, Wsl2Error> {
    let out = exec(&mountinfo_argv(distro), MAX_MOUNTINFO_BYTES)?;
    if !out.success {
        return Err(step_failed("reading mountinfo", &out));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| Wsl2Error::new(Wsl2ErrorCode::DataLoss, "mountinfo is not valid UTF-8"))?;
    parse_mountinfo(&text)
}

/// 本呼び出しでマウントを試みた分を逆順に best-effort で外す。失敗件数を返す。
fn rollback(distro: &DistroName, attempted: &[String], exec: Exec<'_>) -> usize {
    let mut failures = 0;
    for p in attempted.iter().rev() {
        let ok = matches!(exec(&umount_argv(distro, p), MAX_OUTPUT_BYTES), Ok(o) if o.success);
        if !ok {
            failures += 1;
        }
    }
    failures
}

fn with_rollback_note(e: Wsl2Error, failures: usize) -> Wsl2Error {
    if failures == 0 {
        return e;
    }
    Wsl2Error::new(
        e.code(),
        format!(
            "{} ({failures} rollback unmount(s) also failed)",
            e.message()
        ),
    )
}

/// `path` が「root 所有・他者書き込み不可の実ディレクトリ（symlink でない）」なら `Some(())`、
/// 存在しなければ `None`。それ以外（symlink・他者所有・書き込み可）は `FAILED_PRECONDITION`。
fn check_guest_dir(
    distro: &DistroName,
    path: &str,
    exec: Exec<'_>,
) -> Result<Option<()>, Wsl2Error> {
    let out = exec(&stat_argv(distro, path), MAX_OUTPUT_BYTES)?;
    if !out.success {
        return Ok(None);
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| Wsl2Error::new(Wsl2ErrorCode::DataLoss, "stat output is not valid UTF-8"))?;
    let t: Vec<&str> = text.split_whitespace().collect();
    let safe = matches!(t.as_slice(), ["directory", "0", mode]
        if u32::from_str_radix(mode, 8).is_ok_and(|m| m & 0o022 == 0));
    if safe {
        Ok(Some(()))
    } else {
        Err(precondition(
            "a mount path component is not a root-owned, non-writable directory (symlinks are rejected)",
        ))
    }
}

/// ゲスト内ディレクトリを symlink 非追従で検証し、無ければ作成して再検証する（root で実行するため）。
fn ensure_guest_dir(distro: &DistroName, path: &str, exec: Exec<'_>) -> Result<(), Wsl2Error> {
    if check_guest_dir(distro, path, exec)?.is_some() {
        return Ok(());
    }
    let out = exec(&mkdir_argv(distro, path), MAX_OUTPUT_BYTES)?;
    if !out.success {
        return Err(step_failed("creating the mount target", &out));
    }
    check_guest_dir(distro, path, exec)?
        .ok_or_else(|| precondition("the mount target is missing after creation"))
}

/// 1 件のマウント（mount）。試行した時点で `attempted` に積む。ディレクトリは事前に検証済みであること。
fn mount_one(
    distro: &DistroName,
    m: &SharedMount,
    attempted: &mut Vec<String>,
    exec: Exec<'_>,
) -> Result<(), Wsl2Error> {
    // 応答なし等でも反映済みの可能性があるため、試行した時点でロールバック対象にする。
    attempted.push(m.guest_path());
    let out = exec(&mount_argv(distro, m), MAX_OUTPUT_BYTES)?;
    if !out.success {
        return Err(step_failed("mounting the shared directory", &out));
    }
    Ok(())
}

/// 全マウントの fstype が virtiofs であることを確認する。
fn verify_virtiofs(req: &LaunchRequest, exec: Exec<'_>) -> Result<(), Wsl2Error> {
    let after = read_mountinfo(&req.distro, exec)?;
    for m in &req.mounts {
        match find_mount(&after, &m.guest_path()) {
            Some(e) if e.fstype == VIRTIOFS_FSTYPE => {}
            _ => {
                return Err(precondition(
                    "a shared mount is not backed by virtiofs; the setting may not be applied to the running VM, run 'wsl --shutdown' and retry",
                ));
            }
        }
    }
    Ok(())
}

/// 事前判定・マウント・fstype 確認までを行う。成功時のみ [`PreparedLaunch`] を返す。
fn prepare_with_exec(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
) -> Result<PreparedLaunch, Wsl2Error> {
    preflight(status, virtiofs, req)?;
    let distro = &req.distro;
    // root で mkdir / mount するため、基底・マウント先を symlink 非追従で検証してから進む。
    // 基底が実ディレクトリ（root 所有）と確定した後は、マウント先は基底の直下で一意に解決される。
    if !req.mounts.is_empty() {
        ensure_guest_dir(distro, GUEST_MOUNT_BASE, exec)?;
        for m in &req.mounts {
            ensure_guest_dir(distro, &m.guest_path(), exec)?;
        }
    }
    // 自分が作っていないマウントは外さないため、既存のマウントがあれば何もせず拒否する
    // （検証済みで symlink を含まないため、guest_path が実際に解決されるパスと一致する）。
    let before = read_mountinfo(distro, exec)?;
    for m in &req.mounts {
        if find_mount(&before, &m.guest_path()).is_some() {
            return Err(precondition("a shared mount target is already mounted"));
        }
    }
    let mut attempted: Vec<String> = Vec::new();
    for m in &req.mounts {
        if let Err(e) = mount_one(distro, m, &mut attempted, exec) {
            return Err(with_rollback_note(e, rollback(distro, &attempted, exec)));
        }
    }
    if let Err(e) = verify_virtiofs(req, exec) {
        return Err(with_rollback_note(e, rollback(distro, &attempted, exec)));
    }
    Ok(PreparedLaunch {
        distro: req.distro.clone(),
        mounts: req
            .mounts
            .iter()
            .map(|m| PreparedMount {
                guest_path: m.guest_path(),
                read_only: m.read_only,
            })
            .collect(),
        transport: SharedTransport::Virtiofs,
    })
}

/// `wsl.exe` 相当の実行器を `program` から作る（各呼び出しにタイムアウトと出力上限を適用。REPAIR-5）。
fn program_exec(
    program: &Path,
    timeout: Duration,
) -> impl FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error> + '_ {
    move |args: &[String], max: usize| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run::run_capture(program, &refs, &[("WSL_UTF8", "1")], timeout, max)
    }
}

/// `wsl.exe` のパスと `.wslconfig` の virtiofs 状態を解決する。
fn resolve_environment(
    timeout: Duration,
) -> Result<(std::path::PathBuf, VirtiofsState), Wsl2Error> {
    check_timeout(timeout)?;
    let program = wsl_exe_path()?;
    let path = wslconfig::default_path().map_err(|e| win_error_to_wsl2(&e))?;
    let state = wslconfig::load(&path)
        .map_err(|e| win_error_to_wsl2(&e))?
        .map_or(VirtiofsState::Unset, |c| c.virtiofs_state());
    Ok((program, state))
}

/// `program` を `wsl.exe` として使い、`.wslconfig` の状態を `virtiofs` で与えて準備する。
fn prepare_with_program(
    program: &Path,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    timeout: Duration,
) -> Result<PreparedLaunch, Wsl2Error> {
    check_timeout(timeout)?;
    let status = detect_with_program(program, timeout)?;
    let mut exec = program_exec(program, timeout);
    prepare_with_exec(&status, virtiofs, req, &mut exec)
}

/// virtiofs 共有マウントを準備する。`timeout` は各 `wsl.exe` 呼び出しに適用する（REPAIR-5）。
///
/// 成功時は全マウントが virtiofs で成立している。失敗時は本呼び出しで作ったマウントを後始末して `Err`。
/// 成功後のマウントの所有者は呼び出し側で、不要になったら [`release_virtiofs_launch`] で解除する。
pub fn prepare_virtiofs_launch(
    req: &LaunchRequest,
    timeout: Duration,
) -> Result<PreparedLaunch, Wsl2Error> {
    prepare_virtiofs_launch_with_recorder(req, timeout, &NoopWinOpRecorder)
}

/// [`prepare_virtiofs_launch`] の計装版（全体の成否と所要時間を 1 件記録する。REPAIR-4）。
pub fn prepare_virtiofs_launch_with_recorder(
    req: &LaunchRequest,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
) -> Result<PreparedLaunch, Wsl2Error> {
    record_win_op(recorder, WinOpKind::Wsl2MountShared, || {
        let (program, state) = resolve_environment(timeout)?;
        prepare_with_program(&program, state, req, timeout)
    })
}

/// 準備済みマウントを逆順に best-effort で解除する。失敗件数を返す。
fn release_with_exec(prepared: &PreparedLaunch, exec: Exec<'_>) -> usize {
    let paths: Vec<String> = prepared
        .mounts
        .iter()
        .map(|m| m.guest_path.clone())
        .collect();
    rollback(&prepared.distro, &paths, exec)
}

/// [`prepare_virtiofs_launch`] で成立させたマウントを解除する（コンテナ停止後の後始末用）。
///
/// 解除に失敗したマウントがあれば `FAILED_PRECONDITION`（件数のみをメッセージに載せる）。
pub fn release_virtiofs_launch(
    prepared: &PreparedLaunch,
    timeout: Duration,
) -> Result<(), Wsl2Error> {
    check_timeout(timeout)?;
    let program = wsl_exe_path()?;
    let mut exec = program_exec(&program, timeout);
    match release_with_exec(prepared, &mut exec) {
        0 => Ok(()),
        n => Err(precondition(format!("{n} unmount(s) failed"))),
    }
}

/// 準備成功後に `start` を呼び、`start` が失敗したら準備済みマウントを解除して返す（ロールバック）。
fn launch_with_exec<T>(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<T, Wsl2Error> {
    let prepared = prepare_with_exec(status, virtiofs, req, exec)?;
    match start(&prepared) {
        Ok(v) => Ok(v),
        Err(e) => {
            let failures = release_with_exec(&prepared, exec);
            Err(with_rollback_note(e, failures))
        }
    }
}

/// 準備（事前判定・マウント・fstype 確認）に成功した場合に限り `start` を呼ぶ。
///
/// 準備失敗時は `start` を呼ばずに `Err` を返す。`start` が `Err` を返した場合は準備済みマウントを
/// 解除してから `Err` を返す。`start` が `Ok` の場合マウントは呼び出し側（TASK-116）の所有となり、
/// 停止時に [`release_virtiofs_launch`] で解除する。`start` の中身（ゲスト内のコンテナランタイム起動）は
/// TASK-116 が注入する。
pub fn launch_with<T>(
    req: &LaunchRequest,
    timeout: Duration,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<T, Wsl2Error> {
    let (program, state) = resolve_environment(timeout)?;
    let status = detect_with_program(&program, timeout)?;
    let mut exec = program_exec(&program, timeout);
    launch_with_exec(&status, state, req, &mut exec, start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wsl2::{WslDistro, WslMajorVersion, WslVersionInfo};

    fn host(s: &str) -> HostDir {
        HostDir::parse(s).expect("valid host dir")
    }

    fn distro_name() -> DistroName {
        DistroName::parse("Ubuntu").expect("valid distro")
    }

    fn sm(h: &str, n: &str, ro: bool) -> SharedMount {
        SharedMount::new(host(h), MountName::parse(n).expect("name"), ro)
    }

    fn status(version: WslMajorVersion, state: DistroState) -> Wsl2Status {
        Wsl2Status {
            version: WslVersionInfo {
                wsl_version: "2.1.5.0".into(),
                kernel_version: "5.15".into(),
                windows_version: None,
            },
            distros: vec![WslDistro {
                name: "Ubuntu".into(),
                state,
                version,
                is_default: true,
            }],
        }
    }

    fn ok_status() -> Wsl2Status {
        status(WslMajorVersion::V2, DistroState::Running)
    }

    fn req(mounts: Vec<SharedMount>) -> LaunchRequest {
        LaunchRequest::new(distro_name(), mounts).expect("valid request")
    }

    /// WIN-4・REPAIR-2: ドライブレター絶対パスは受理し、危険な形式は具体的に拒否する。
    #[test]
    fn host_dir_accepts_and_rejects() {
        for ok in ["C:\\work", "d:\\a b\\c.d", "C:\\Users\\x\\プロジェクト"] {
            assert_eq!(HostDir::parse(ok).expect(ok).as_str(), ok);
        }
        let bad = [
            "",
            "C:\\",
            "C:work",
            "work",
            "\\\\server\\share\\x",
            "\\\\?\\C:\\x",
            "\\\\.\\pipe\\x",
            "C:/work",
            "C:\\a\\..\\b",
            "C:\\a\\.\\b",
            "C:\\a\\\\b",
            "C:\\a\\",
            "C:\\a\0b",
            "C:\\a\"b",
            "C:\\a*",
            "C:\\a:stream",
            "C:\\a|b",
            "C:\\NUL",
            "C:\\con.txt",
            "C:\\a \\b",
            "C:\\a.\\b",
            "C:\\a\nb",
        ];
        for s in bad {
            let e = HostDir::parse(s).expect_err(s);
            assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument, "{s:?}");
        }
    }

    /// WIN-4: 長さ上限の境界値（260 は可、261 は不可）。
    #[test]
    fn host_dir_length_boundary() {
        let pad = |n: usize| format!("C:\\{}", "a".repeat(n - 3));
        assert!(HostDir::parse(&pad(MAX_HOST_DIR_LEN)).is_ok());
        assert_eq!(
            HostDir::parse(&pad(MAX_HOST_DIR_LEN + 1))
                .unwrap_err()
                .code(),
            Wsl2ErrorCode::InvalidArgument
        );
    }

    /// REPAIR-2: マウント名・ディストリ名の検証。
    #[test]
    fn names_are_validated() {
        for ok in ["data", "a.b_c-1", &"x".repeat(64)] {
            assert!(MountName::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "-x", "a/b", "a b", "é", &"x".repeat(65)] {
            assert!(MountName::parse(bad).is_err(), "{bad}");
        }
        for ok in ["Ubuntu", "Ubuntu-22.04", "my distro"] {
            assert!(DistroName::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-d", " x", "x ", "a\nb", &"x".repeat(129)] {
            assert!(DistroName::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// REPAIR-5: 件数上限・名前重複・ホスト重複（大文字小文字非区別）を拒否する。
    #[test]
    fn launch_request_rejects_duplicates_and_overflow() {
        let a = sm("C:\\a", "a", false);
        let dup_name = sm("C:\\b", "a", false);
        let dup_host = sm("c:\\A", "b", false);
        assert!(LaunchRequest::new(distro_name(), vec![a.clone(), dup_name]).is_err());
        assert!(LaunchRequest::new(distro_name(), vec![a.clone(), dup_host]).is_err());
        let many: Vec<_> = (0..=MAX_SHARED_MOUNTS)
            .map(|i| sm(&format!("C:\\d{i}"), &format!("n{i}"), false))
            .collect();
        assert!(LaunchRequest::new(distro_name(), many).is_err());
        assert_eq!(a.guest_path(), "/mnt/fandhe/a");
    }

    /// WIN-1・WIN-2: 事前判定の各分岐。
    #[test]
    fn preflight_cases() {
        let r = req(vec![sm("C:\\a", "a", false)]);
        assert!(preflight(&ok_status(), VirtiofsState::Enabled, &r).is_ok());
        for s in [
            VirtiofsState::Unset,
            VirtiofsState::Disabled,
            VirtiofsState::Other,
        ] {
            let e = preflight(&ok_status(), s, &r).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
            assert!(e.message().contains("virtiofs=true"), "{}", e.message());
        }
        let v1 = status(WslMajorVersion::V1, DistroState::Running);
        assert_eq!(
            preflight(&v1, VirtiofsState::Enabled, &r)
                .unwrap_err()
                .code(),
            Wsl2ErrorCode::FailedPrecondition
        );
        let inst = status(WslMajorVersion::V2, DistroState::Installing);
        assert_eq!(
            preflight(&inst, VirtiofsState::Enabled, &r)
                .unwrap_err()
                .code(),
            Wsl2ErrorCode::FailedPrecondition
        );
        let other = LaunchRequest::new(DistroName::parse("Debian").unwrap(), vec![]).unwrap();
        assert_eq!(
            preflight(&ok_status(), VirtiofsState::Enabled, &other)
                .unwrap_err()
                .code(),
            Wsl2ErrorCode::NotFound
        );
    }

    /// WIN-2: argv の具体値（シェルを介さず、ro の有無でオプションが変わる）。
    #[test]
    fn argv_values() {
        let d = distro_name();
        let rw = sm("C:\\a b", "data", false);
        let ro = sm("C:\\a b", "data", true);
        assert_eq!(
            mkdir_argv(&d, &rw.guest_path()),
            [
                "--distribution",
                "Ubuntu",
                "--user",
                "root",
                "--exec",
                "mkdir",
                "-m",
                "755",
                "--",
                "/mnt/fandhe/data"
            ]
        );
        assert_eq!(
            mount_argv(&d, &rw),
            [
                "--distribution",
                "Ubuntu",
                "--user",
                "root",
                "--exec",
                "mount",
                "-t",
                "drvfs",
                "-o",
                "nosuid,nodev",
                "C:\\a b",
                "/mnt/fandhe/data"
            ]
        );
        assert_eq!(
            mount_argv(&d, &ro).get(9).map(String::as_str),
            Some("nosuid,nodev,ro")
        );
        assert_eq!(
            umount_argv(&d, "/mnt/fandhe/data")
                .last()
                .map(String::as_str),
            Some("/mnt/fandhe/data")
        );
        assert_eq!(
            mountinfo_argv(&d)[5..],
            ["cat".to_string(), "/proc/self/mountinfo".to_string()]
        );
    }

    /// WIN-2: mountinfo の解析（8 進エスケープ・virtiofs・9p）と異常系。
    #[test]
    fn mountinfo_parsing() {
        let text = "22 1 0:20 / /mnt/fandhe/my\\040dir rw,nosuid shared:1 - virtiofs C:\\\\ rw\n\
                    23 1 0:21 / /mnt/fandhe/b rw - 9p drvfs rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(
            e,
            vec![
                MountEntry {
                    mount_point: "/mnt/fandhe/my dir".into(),
                    fstype: "virtiofs".into()
                },
                MountEntry {
                    mount_point: "/mnt/fandhe/b".into(),
                    fstype: "9p".into()
                },
            ]
        );
        assert_eq!(
            find_mount(&e, "/mnt/fandhe/b").map(|m| m.fstype.as_str()),
            Some("9p")
        );
        assert!(find_mount(&e, "/nope").is_none());
        for bad in [
            "",
            "garbage line",
            "1 2 3 4 5 6 7 8",
            "1 2 3 4 /a\\9 rw - x y",
        ] {
            assert_eq!(
                parse_mountinfo(bad).unwrap_err().code(),
                Wsl2ErrorCode::DataLoss,
                "{bad}"
            );
        }
        let long = format!("1 2 3:4 / /{} rw - x y", "a".repeat(MAX_MOUNTINFO_LINE_LEN));
        assert_eq!(
            parse_mountinfo(&long).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
        let many = "1 2 3:4 / /a rw - x y\n".repeat(MAX_MOUNTINFO_LINES + 1);
        assert_eq!(
            parse_mountinfo(&many).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
    }

    /// 暫定変換の code 写像（#376 で共通化するまで）。
    #[test]
    fn win_error_mapping() {
        let cases = [
            (
                WinErrorCode::InvalidArgument,
                Wsl2ErrorCode::InvalidArgument,
            ),
            (WinErrorCode::NotFound, Wsl2ErrorCode::NotFound),
            (
                WinErrorCode::PermissionDenied,
                Wsl2ErrorCode::PermissionDenied,
            ),
            (
                WinErrorCode::ResourceExhausted,
                Wsl2ErrorCode::ResourceExhausted,
            ),
            (WinErrorCode::Unimplemented, Wsl2ErrorCode::Unimplemented),
            (WinErrorCode::Internal, Wsl2ErrorCode::Internal),
        ];
        for (w, s) in cases {
            let e = win_error_to_wsl2(&WinError::new(w, "m"));
            assert_eq!((e.code(), e.message()), (s, "m"));
        }
    }

    /// ゲストの模擬: mountinfo を保持し、mount/umount/mkdir に応答する。
    struct Guest {
        mounts: Vec<(String, String)>,
        mount_fstype: &'static str,
        fail_mount_nth: Option<usize>,
        mount_calls: usize,
        umounts: Vec<String>,
        /// 既存パス → `stat -c '%F %u %a'` の応答（mkdir が追加する）。
        paths: std::collections::HashMap<String, String>,
    }

    impl Guest {
        fn new(fstype: &'static str) -> Self {
            Self {
                mounts: vec![("/".into(), "ext4".into())],
                mount_fstype: fstype,
                fail_mount_nth: None,
                mount_calls: 0,
                umounts: vec![],
                paths: std::collections::HashMap::new(),
            }
        }

        fn run(&mut self, args: &[String], _max: usize) -> Result<run::Captured, Wsl2Error> {
            let cmd: Vec<&str> = args.iter().skip(5).map(String::as_str).collect();
            let ok = |stdout: String| {
                Ok(run::Captured {
                    success: true,
                    code: Some(0),
                    stdout: stdout.into_bytes(),
                    stderr: vec![],
                })
            };
            match cmd.as_slice() {
                ["cat", _] => ok(self
                    .mounts
                    .iter()
                    .enumerate()
                    .map(|(i, (p, t))| format!("{i} 1 0:{i} / {p} rw - {t} src rw\n"))
                    .collect()),
                ["stat", _, _, _, path] => match self.paths.get(*path) {
                    Some(r) => ok(format!("{r}\n")),
                    None => Ok(run::Captured {
                        success: false,
                        code: Some(1),
                        stdout: vec![],
                        stderr: vec![],
                    }),
                },
                ["mkdir", _, _, _, path] => {
                    self.paths
                        .insert((*path).to_string(), "directory 0 755".to_string());
                    ok(String::new())
                }
                ["mount", .., target] => {
                    self.mount_calls += 1;
                    if self.fail_mount_nth == Some(self.mount_calls) {
                        return Ok(run::Captured {
                            success: false,
                            code: Some(32),
                            stdout: vec![],
                            stderr: b"secret C:\\Users\\bob".to_vec(),
                        });
                    }
                    self.mounts
                        .push(((*target).to_string(), self.mount_fstype.to_string()));
                    ok(String::new())
                }
                ["umount", target] => {
                    self.umounts.push((*target).to_string());
                    self.mounts.retain(|(p, _)| p != target);
                    ok(String::new())
                }
                _ => Err(Wsl2Error::new(Wsl2ErrorCode::Internal, "unexpected")),
            }
        }
    }

    fn drive(
        g: &mut Guest,
        r: &LaunchRequest,
        v: VirtiofsState,
    ) -> Result<PreparedLaunch, Wsl2Error> {
        prepare_with_exec(&ok_status(), v, r, &mut |a, m| g.run(a, m))
    }

    /// WIN-2: virtiofs で成立した場合のみ PreparedLaunch が返る。
    #[test]
    fn prepare_succeeds_with_virtiofs() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", true)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(p.transport(), SharedTransport::Virtiofs);
        assert_eq!(p.distro().as_str(), "Ubuntu");
        assert_eq!(
            p.mounts(),
            [
                PreparedMount {
                    guest_path: "/mnt/fandhe/a".into(),
                    read_only: false
                },
                PreparedMount {
                    guest_path: "/mnt/fandhe/b".into(),
                    read_only: true
                },
            ]
        );
        assert!(g.umounts.is_empty());
    }

    /// WIN-2: 9P で成立した場合はロールバックして FAILED_PRECONDITION（暗黙に降格しない）。
    #[test]
    fn prepare_rejects_9p_and_rolls_back() {
        let mut g = Guest::new("9p");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("wsl --shutdown"));
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);
    }

    /// REPAIR-5・ERR-1: 途中失敗では試行済み分だけを逆順に外し、生出力をメッセージに載せない。
    #[test]
    fn prepare_rolls_back_on_midway_failure() {
        let mut g = Guest::new("virtiofs");
        g.fail_mount_nth = Some(3);
        let r = req(vec![
            sm("C:\\a", "a", false),
            sm("C:\\b", "b", false),
            sm("C:\\c", "c", false),
        ]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "mounting the shared directory failed in the distribution (exit code 32)"
        );
        assert!(!e.message().contains("bob"));
        assert_eq!(
            g.umounts,
            ["/mnt/fandhe/c", "/mnt/fandhe/b", "/mnt/fandhe/a"]
        );
        assert_eq!(g.mounts.len(), 1);
    }

    /// 既存マウントがあれば何も外さずエラー、virtiofs 未設定ならマウントを試みない。
    #[test]
    fn prepare_refuses_existing_mount_and_disabled() {
        let mut g = Guest::new("virtiofs");
        g.mounts.push(("/mnt/fandhe/a".into(), "ext4".into()));
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(g.umounts.is_empty());
        assert_eq!(g.mount_calls, 0);
        let mut g2 = Guest::new("virtiofs");
        assert!(drive(&mut g2, &r, VirtiofsState::Unset).is_err());
        assert_eq!(g2.mount_calls, 0);
    }

    /// AC2: 準備に失敗したら起動ステップは呼ばれない（Windows 以外は UNIMPLEMENTED）。
    #[cfg(not(windows))]
    #[test]
    fn launch_with_does_not_start_on_failure() {
        let r = req(vec![]);
        let mut called = false;
        let e = launch_with(&r, Duration::from_secs(1), |_| {
            called = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!called);
        assert_eq!(e.code(), Wsl2ErrorCode::Unimplemented);
        let e = launch_with(&r, Duration::ZERO, |_| Ok(())).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument);
    }

    /// 手順 REPAIR-2: 長さ上限は文字数単位（日本語パス・Unicode ディストロ名を誤拒否しない）。
    #[test]
    fn length_limits_count_chars_not_bytes() {
        let host = format!("C:\\{}", "あ".repeat(MAX_HOST_DIR_LEN - 3));
        assert!(HostDir::parse(&host).is_ok());
        assert!(HostDir::parse(&format!("{host}あ")).is_err());
        assert!(DistroName::parse(&"あ".repeat(MAX_DISTRO_NAME_LEN)).is_ok());
        assert!(DistroName::parse(&"あ".repeat(MAX_DISTRO_NAME_LEN + 1)).is_err());
    }

    /// WIN-1: ディストリ名の照合は大文字小文字を区別しない（`wsl --distribution` と同じ）。
    #[test]
    fn preflight_matches_distro_case_insensitively() {
        let r = LaunchRequest::new(DistroName::parse("ubuntu").expect("name"), vec![])
            .expect("request");
        assert!(preflight(&ok_status(), VirtiofsState::Enabled, &r).is_ok());
    }

    /// SEC: 基底・マウント先が symlink / 他者所有 / 書き込み可なら mount せず拒否する。
    #[test]
    fn prepare_rejects_unsafe_guest_dirs() {
        for bad in [
            "symbolic link 0 777",
            "directory 1000 755",
            "directory 0 777",
            "directory 0 775",
        ] {
            for victim in ["/mnt/fandhe", "/mnt/fandhe/a"] {
                let mut g = Guest::new("virtiofs");
                g.paths
                    .insert("/mnt/fandhe".into(), "directory 0 755".into());
                g.paths.insert(victim.into(), bad.into());
                let r = req(vec![sm("C:\\a", "a", false)]);
                let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
                assert_eq!(
                    e.code(),
                    Wsl2ErrorCode::FailedPrecondition,
                    "{bad} {victim}"
                );
                assert_eq!(g.mount_calls, 0, "{bad} {victim}");
            }
        }
    }

    /// 起動ステップが失敗したら準備済みマウントを逆順に解除する。成功時は解除しない。
    #[test]
    fn launch_rolls_back_mounts_when_start_fails() {
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let mut g = Guest::new("virtiofs");
        let e = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            |_| Err::<(), _>(Wsl2Error::new(Wsl2ErrorCode::Internal, "start failed")),
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Internal);
        assert_eq!(e.message(), "start failed");
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);

        let mut g = Guest::new("virtiofs");
        let v = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            |p| Ok(p.mounts().len()),
        )
        .unwrap();
        assert_eq!(v, 2);
        assert!(g.umounts.is_empty());
    }
}
