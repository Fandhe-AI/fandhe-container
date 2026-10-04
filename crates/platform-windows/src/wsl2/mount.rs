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
/// 結果が不確定な操作（mount のタイムアウト・mount 後の mountinfo 読み取り失敗・umount の失敗）の後で、
/// 状態を確かめるために mountinfo を読み直す最大回数。各回は `wsl.exe` 呼び出し 1 回で、呼び出しごとの
/// タイムアウトが適用されるため、回復に要する時間は最大でこの回数 × タイムアウトに収まる（REPAIR-5）。
const MAX_RECOVERY_READS: usize = 3;

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
    /// 本呼び出しが成立させたマウントのカーネルのマウント ID。解除時に所有確認へ使う。
    pub mount_id: u32,
    /// 読み取り専用か。
    pub read_only: bool,
    /// ゲスト内の所有の記録（`/run/fandhe/<nonce>`）の nonce。解除に成功したら記録を消すために使う。
    nonce: String,
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

/// ゲスト内で「パス検証 → 必要ならディレクトリ作成 → 再検証 → mount → 自分のマウントの特定と記録」を
/// 1 つの `sh` プロセスで行うスクリプト。
///
/// 検証とマウントを別々の `wsl.exe` 呼び出しに分けると、その隙間に別プロセスが親やマウント先を symlink へ
/// 差し替えて検証外の場所へ root でマウントさせられる（TOCTOU）。そのため全工程を単一プロセスに拘束し、
/// 検証から `mount` までの窓を最小にする。位置引数は `$1`=ホストディレクトリ・`$2`=マウント名・`$3`=オプション・
/// `$4`=呼び出しごとの nonce（固定スクリプトに値を埋め込まず引数で渡すため、シェルのインジェクションは起きない。
/// 入力は検証済み newtype と 16 進の nonce）。
///
/// 所有の証拠: `mount` の直前と直後に同じプロセス内でマウント先のマウント ID を読み、新しく現れたものが
/// ちょうど 1 件ならそれを自分のマウントとして標準出力へ書き（`mount` 自身の標準出力は標準エラーへ回し、
/// 標準出力にはマウント ID の 1 行だけが載るようにする）、`/run/fandhe/<nonce>`（root 所有・`0700` のディレクトリ） にも記録する。`mount` の
/// 終了コードによらず記録する（`mount(8)` はマウント成立後の処理でも失敗を返しうるため）。`wsl.exe` の待機が
/// タイムアウトして標準出力を失っても、呼び出し側は記録を読んで自分のマウントを特定できる。新しいマウントが
/// 0 件・複数件なら記録しない（呼び出し側は所有を確認できないものとして扱い、外さない）。残る窓（同一プロセス内の
/// `mount` の前後の読み取りの間）に同じマウント先へマウントできるのはゲスト内の root（CAP_SYS_ADMIN）に限られる。
///
/// ディレクトリの作成は、並行する別の準備が先に作った場合（`EEXIST`）も成功として扱い、直後の検証で安全性を
/// 確かめる（`/run` は tmpfs で WSL の再起動ごとに消えるため、記録ディレクトリの同時作成は起こりうる）。
///
/// 終了コード: 200=`/`・`/mnt`・`/run` が root 所有の他者書き込み不可な実ディレクトリでない・201=ディレクトリ作成
/// 失敗・202=パス要素が symlink / 非 root 所有 / 他者書き込み可。それ以外は `mount` の終了コードをそのまま返す。
/// `mount(8)` の終了コードは 1〜64 のビットの論理和（0〜127）で、シグナル終了は 128+シグナル番号（192 以下）に
/// なるため、スクリプト固有のコードは両者と重ならない 200 番台に置く（`mount` 後の失敗を検証失敗と誤認しない）。
/// 検証は symlink 非追従（`-L`）と `stat` の生モード（`%f`。ロケール非依存）で行う。
///
/// `/` からマウント先までの全要素が「root 所有・group / other 書き込み不可・symlink でない」ことを確かめるため、
/// 検証後に要素を差し替えられる（rename・symlink への置換）のはゲスト内の root（uid 0）に限られる。ゲスト内 root は
/// マウントの付け外しやこのシェルへの介入も自由にできる信頼境界の内側であり、本スクリプトが防ぐ対象は非特権の
/// プロセスによる差し替えである。ディレクトリをハンドル（fd・cwd）で固定してマウントする方式は、WSL の
/// `mount.drvfs` ヘルパーの挙動が実機未検証のため採らない（TASK-67.6・#377 で再検討する。REPAIR-3）。
const MOUNT_SCRIPT: &str = concat!(
    "set -eu; B=/mnt/fandhe; R=/run/fandhe; ",
    "chk() { [ ! -L \"$1\" ] && [ -d \"$1\" ] || return 1; ",
    "set -- $(stat -c '%u %f' -- \"$1\"); ",
    "[ \"$1\" = 0 ] && [ $((0x$2 & 18)) -eq 0 ]; }; ",
    "ids() { while read -r id _ _ _ mp _; do if [ \"$mp\" = \"$1\" ]; then printf '%s ' \"$id\"; fi; ",
    "done < /proc/self/mountinfo; }; ",
    "chk / || exit 200; ",
    "chk /mnt || exit 200; ",
    "chk /run || exit 200; ",
    "[ -L \"$R\" ] || [ -e \"$R\" ] || mkdir -m 700 -- \"$R\" 2>/dev/null || [ -d \"$R\" ] || exit 201; ",
    "chk \"$R\" || exit 202; ",
    "[ -L \"$B\" ] || [ -e \"$B\" ] || mkdir -m 755 -- \"$B\" 2>/dev/null || [ -d \"$B\" ] || exit 201; ",
    "chk \"$B\" || exit 202; ",
    "T=\"$B/$2\"; ",
    "[ -L \"$T\" ] || [ -e \"$T\" ] || mkdir -m 755 -- \"$T\" 2>/dev/null || [ -d \"$T\" ] || exit 201; ",
    "chk \"$T\" || exit 202; ",
    "pre=$(ids \"$T\"); rc=0; ",
    "mount -t drvfs -o \"$3\" \"$1\" \"$T\" >&2 || rc=$?; ",
    "new=; n=0; for i in $(ids \"$T\"); do case \" $pre \" in *\" $i \"*) ;; *) new=$i; n=$((n + 1)) ;; esac; done; ",
    "if [ \"$n\" = 1 ]; then printf '%s\\n' \"$new\" > \"$R/$4\" || :; printf '%s\\n' \"$new\"; fi; ",
    "exit \"$rc\""
);
/// [`MOUNT_SCRIPT`] の終了コード（`/`・`/mnt`・`/run` 不正 / ディレクトリ作成失敗 / パス要素が危険）。
const EXIT_PARENT_BAD: i32 = 200;
const EXIT_MKDIR_FAILED: i32 = 201;
const EXIT_PATH_UNSAFE: i32 = 202;

/// 呼び出しごとの nonce（[`MOUNT_SCRIPT`] の記録ファイル名）。16 進のみ（パス要素・シェル引数として安全）。
///
/// 同一プロセス内の連番・プロセス ID・現在時刻を連結し、同時に動く他の呼び出し（他プロセスを含む）と
/// 衝突しないようにする。秘密ではない（所有の証拠は root 専用ディレクトリに置くことで守る）。
fn new_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:08x}{seq:016x}{nanos:032x}", std::process::id())
}

/// 検証込みマウントコマンドの組み立て。`-t drvfs` が virtiofs で成立するかは実機未検証（TASK-67.6・#377。REPAIR-3）。
fn mount_argv(distro: &DistroName, m: &SharedMount, nonce: &str) -> Vec<String> {
    let opts = if m.read_only {
        "nosuid,nodev,ro"
    } else {
        "nosuid,nodev"
    };
    exec_argv(
        distro,
        &[
            "sh",
            "-c",
            MOUNT_SCRIPT,
            "sh",
            m.host.as_str(),
            m.name.as_str(),
            opts,
            nonce,
        ],
    )
}

/// ゲスト内で `/run/fandhe/<nonce>`（root 所有・`0700` のディレクトリ）（[`MOUNT_SCRIPT`] の記録）を読むスクリプト。`$1`=nonce。
/// 記録が無ければ終了コード 204（`cat` の失敗・シグナル終了と重ならない値）。
const RECORD_SCRIPT: &str = "[ -e \"/run/fandhe/$1\" ] || exit 204; exec cat -- \"/run/fandhe/$1\"";
/// [`RECORD_SCRIPT`] の終了コード（記録が無い）。
const EXIT_NO_RECORD: i32 = 204;

fn record_argv(distro: &DistroName, nonce: &str) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", RECORD_SCRIPT, "sh", nonce])
}

/// ゲスト内で「マウント先の最上位のマウント ID が記録値と一致するか確認 → umount → 記録の削除」を 1 つの `sh`
/// プロセスで行うスクリプト。
///
/// 確認と `umount` を別々の `wsl.exe` 呼び出しに分けると、その隙間に別のマウントが同じマウント先へ積まれ、
/// 確認した自分のマウントではなく他者のマウントを外しうる。そのため [`MOUNT_SCRIPT`] と同様に単一プロセスへ拘束し、
/// 窓を最小にする。位置引数は `$1`=マウント先（固定基底配下の検証済み名で、mountinfo の 8 進エスケープを含まない）・
/// `$2`=記録したマウント ID・`$3`=nonce。mountinfo の 1 列目（マウント ID）・2 列目（親のマウント ID）・5 列目
/// （マウント先）だけを `read` で読む（awk 等に依存しない）。最上位は [`find_mount`] と同じく行順でなくマウント階層で
/// 決める（同じマウント先の他のエントリから親として参照されていないものがちょうど 1 件）。`umount` に成功したら
/// [`MOUNT_SCRIPT`] の記録を消す。終了コード 203=最上位を確定できない・最上位が記録したマウントでない（外さない）。
/// それ以外は `umount` の終了コード（[`MOUNT_SCRIPT`] と同じ理由で、`umount(8)` の終了コード・シグナル終了と
/// 重ならない 200 番台に置く）。残る窓（同一プロセス内の確認から `umount` まで）に同じマウント先へマウントできるのは
/// ゲスト内の root（CAP_SYS_ADMIN）に限られ、[`MOUNT_SCRIPT`] と同じく信頼境界の内側として扱う。
const UMOUNT_SCRIPT: &str = concat!(
    "set -u; ids=; pars=; ",
    "while read -r id par _ _ mp _; do if [ \"$mp\" = \"$1\" ]; then ids=\"$ids $id\"; pars=\"$pars $par\"; fi; ",
    "done < /proc/self/mountinfo; ",
    "top=; n=0; for i in $ids; do case \" $pars \" in *\" $i \"*) ;; *) top=$i; n=$((n + 1)) ;; esac; done; ",
    "[ \"$n\" = 1 ] && [ \"$top\" = \"$2\" ] || exit 203; ",
    "umount \"$1\" || exit $?; rm -f -- \"/run/fandhe/$3\"; exit 0"
);

fn umount_argv(distro: &DistroName, guest_path: &str, mount_id: u32, nonce: &str) -> Vec<String> {
    let id = mount_id.to_string();
    exec_argv(
        distro,
        &[
            "sh",
            "-c",
            UMOUNT_SCRIPT,
            "sh",
            guest_path,
            id.as_str(),
            nonce,
        ],
    )
}

fn mountinfo_argv(distro: &DistroName) -> Vec<String> {
    exec_argv(distro, &["cat", "/proc/self/mountinfo"])
}

/// `/proc/self/mountinfo` の 1 エントリ（マウント ID・親のマウント ID・マウント先・マウントオプション・fstype）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    /// カーネルが割り当てるマウント ID（マウントインスタンスごとに一意。所有確認に使う）。
    mount_id: u32,
    /// 親のマウント ID（mountinfo の 2 番目のフィールド）。同じマウント先に積まれたマウントの親は、
    /// その直下のマウントになる（[`find_mount`] の最上位判定に使う）。
    parent_id: u32,
    mount_point: String,
    /// マウントごとのオプション（mountinfo の 6 番目のフィールド。`ro` / `rw` を含む）。
    options: String,
    fstype: String,
}

impl MountEntry {
    /// マウントオプションに `ro` が含まれるか。
    fn is_read_only(&self) -> bool {
        self.has_option("ro")
    }

    /// マウントオプションに `opt` が単独のトークンとして含まれるか。
    fn has_option(&self, opt: &str) -> bool {
        self.options.split(',').any(|o| o == opt)
    }
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
        let options = f.get(5).ok_or_else(bad)?;
        let id_at = |i: usize| f.get(i).and_then(|t| t.parse::<u32>().ok());
        let mount_id = id_at(0).ok_or_else(bad)?;
        let parent_id = id_at(1).ok_or_else(bad)?;
        entries.push(MountEntry {
            mount_id,
            parent_id,
            mount_point: unescape_mountinfo(mp).ok_or_else(bad)?,
            options: (*options).to_string(),
            fstype: (*fstype).to_string(),
        });
    }
    if entries.is_empty() {
        return Err(bad());
    }
    Ok(entries)
}

/// マウント先 `guest_path` の最上位のエントリを返す（パスの解決で到達するマウント。`umount` が外す対象）。
///
/// mountinfo の行順は最上位判定の契約ではないため、行順に頼らずマウント階層で決める。同じマウント先に
/// 積まれたマウントの親はその直下のマウントなので、同じマウント先のエントリのうち、同じマウント先の他の
/// エントリから親として参照されていないものが最上位である。該当がちょうど 1 件でなければ（同じパス文字列が
/// 別々の親の下に見える等）最上位を確定できないため `None` を返す（呼び出し側は所有を確認できないものとして
/// 扱い、外さない。fail-closed）。[`UMOUNT_SCRIPT`] もゲスト内で同じ基準で照合する。
fn find_mount<'a>(entries: &'a [MountEntry], guest_path: &str) -> Option<&'a MountEntry> {
    let at: Vec<&MountEntry> = entries
        .iter()
        .filter(|e| e.mount_point == guest_path)
        .collect();
    let mut tops = at
        .iter()
        .filter(|e| !at.iter().any(|o| o.parent_id == e.mount_id));
    match (tops.next(), tops.next()) {
        (Some(top), None) => Some(top),
        _ => None,
    }
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

/// [`read_mountinfo`] を最大 [`MAX_RECOVERY_READS`] 回試み、最初に成功した結果を返す（全回失敗なら `None`）。
///
/// 結果が不確定な操作の後で状態を確かめる回復経路専用。一過性の失敗（`wsl.exe` の遅延によるタイムアウト等）で
/// 所有確認を諦めないための再試行で、回数と呼び出しごとのタイムアウトで所要時間を有界にする（REPAIR-5）。
fn read_mountinfo_bounded(distro: &DistroName, exec: Exec<'_>) -> Option<Vec<MountEntry>> {
    (0..MAX_RECOVERY_READS).find_map(|_| read_mountinfo(distro, exec).ok())
}

/// 本呼び出しのマウントの所有の証拠（[`MOUNT_SCRIPT`] が mount と同じプロセス内で特定したマウント ID）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// [`MOUNT_SCRIPT`] の標準出力または記録にあったマウント ID（本呼び出しのマウント）。
    Mine(u32),
    /// 証拠が無い（mount が成立していない、または新しいマウントを 1 件に特定できなかった）。
    Missing,
    /// 記録を上限回数まで読めなかった。
    Unreadable,
}

/// [`MOUNT_SCRIPT`] の標準出力・記録の中身（10 進のマウント ID 1 行）を解析する。それ以外は `None`。
fn parse_recorded_id(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `wsl.exe` の待機タイムアウト等で [`MOUNT_SCRIPT`] の標準出力を失ったときに、ゲスト内の記録
/// （`/run/fandhe/<nonce>`）を最大 [`MAX_RECOVERY_READS`] 回読む（呼び出しごとのタイムアウトで有界。REPAIR-5）。
fn read_record(distro: &DistroName, nonce: &str, exec: Exec<'_>) -> Evidence {
    for _ in 0..MAX_RECOVERY_READS {
        match exec(&record_argv(distro, nonce), MAX_OUTPUT_BYTES) {
            Ok(out) if out.success => {
                return parse_recorded_id(&out.stdout).map_or(Evidence::Unreadable, Evidence::Mine);
            }
            Ok(out) if out.code == Some(EXIT_NO_RECORD) => return Evidence::Missing,
            _ => {}
        }
    }
    Evidence::Unreadable
}

/// mount 前に無かったマウント ID のエントリがマウント先 `guest_path` に何件あるか（読めなければ `None`）。
/// 所有の証拠が無い失敗の後で、残置されたかもしれないマウントの有無を報告するためだけに使う（帰属には使わない）。
fn count_fresh_mounts(
    distro: &DistroName,
    guest_path: &str,
    before_ids: &[u32],
    exec: Exec<'_>,
) -> Option<usize> {
    let entries = read_mountinfo_bounded(distro, exec)?;
    Some(
        entries
            .iter()
            .filter(|e| e.mount_point == guest_path && !before_ids.contains(&e.mount_id))
            .count(),
    )
}

/// 本呼び出しが成立させたマウント 1 件（マウント先・カーネルのマウント ID・[`MOUNT_SCRIPT`] の記録の nonce）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedMount {
    guest_path: String,
    mount_id: u32,
    nonce: String,
}

/// 本呼び出しが成立させたマウントを逆順に best-effort で外す。失敗件数を返す。
///
/// 解除の直前に mountinfo を読み直し、マウント先の最上位エントリが記録したマウント ID と一致する場合に限り
/// `umount` する。`umount` は [`UMOUNT_SCRIPT`] がゲスト内で同じ照合をやり直してから行う（照合と解除の間に
/// 積まれた他者のマウントを外さない。不一致の終了コード 203 は `umount` の失敗と同様に読み直して判定する）。
/// 一致しない（他プロセスが差し替えた・既に外れている）場合は他者のマウントを外さないよう何もしない。
/// mountinfo を読めない場合は所有を確認できないため外さず、失敗として数える。
/// 記録したマウント ID がマウント先の最上位でなくても mountinfo のどこか（他者が移動した別のマウント先を含む）に
/// 残っている場合は、他者のマウントを外せず自分のマウントが残置されるため、未解除として失敗に数える
/// （呼び出し側が後始末を追跡できるようにする）。記録したマウント ID が mountinfo のどこにも存在しなければ
/// （外れている）解除済みとして扱う。
///
/// mountinfo の読み取りは [`read_mountinfo_bounded`] で有界に再試行する。`umount` が失敗・タイムアウトした
/// 場合は結果が不確定なため mountinfo を読み直し、記録したマウント ID がどこにも無ければ解除済みとして扱う
/// （残っている・読めない場合は失敗に数える。再度の `umount` はしない）。
fn rollback(distro: &DistroName, owned: &[OwnedMount], exec: Exec<'_>) -> usize {
    let mut failures = 0;
    for o in owned.iter().rev() {
        let Some(entries) = read_mountinfo_bounded(distro, exec) else {
            failures += 1;
            continue;
        };
        match find_mount(&entries, &o.guest_path) {
            Some(e) if e.mount_id == o.mount_id => {
                let ok = matches!(
                    exec(
                        &umount_argv(distro, &o.guest_path, o.mount_id, &o.nonce),
                        MAX_OUTPUT_BYTES
                    ),
                    Ok(out) if out.success
                );
                let gone = ok
                    || read_mountinfo_bounded(distro, exec)
                        .is_some_and(|after| after.iter().all(|e| e.mount_id != o.mount_id));
                if !gone {
                    failures += 1;
                }
            }
            _ => {
                // マウント先に無くても、記録したマウント ID が別のマウント先へ移されて残っていれば未解除。
                let still_mounted = entries.iter().any(|e| e.mount_id == o.mount_id);
                if still_mounted {
                    failures += 1;
                }
            }
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

/// 1 件のマウント（mount）。[`MOUNT_SCRIPT`] が同じプロセス内で特定したマウント ID を所有の証拠として
/// `owned` に積む。パス検証・ディレクトリ作成・mount・特定は [`MOUNT_SCRIPT`] が 1 プロセスで行う（TOCTOU 防止）。
///
/// 所有の判定には、mount を実行したプロセス自身が作った証拠（標準出力、または `wsl.exe` の待機タイムアウト等で
/// 標準出力を失った場合はゲスト内の記録 `/run/fandhe/<nonce>`）だけを使い、別の `wsl.exe` 呼び出しでの
/// mountinfo の差分からは推定しない（他者のマウントを自分のものとみなさない）。
///
/// mount の結果ごとの扱い:
/// - [`MOUNT_SCRIPT`] の検証失敗（200〜202）: `mount` を実行する前に終了しているので、そのまま返す。
/// - 成功: 証拠のマウント ID を記録する。証拠が無ければ（新しいマウントを 1 件に特定できない）記録せず、
///   `ownership unconfirmed` の失敗を返す（fail-closed）。
/// - それ以外の失敗（`mount(8)` の終了コード・`wsl.exe` のタイムアウト・出力読み取り失敗・`wsl.exe` 自身の異常値）:
///   `mount(8)` はマウント成立後の処理でも失敗を返しうるため、終了コードだけで未成立と決めない。証拠があれば
///   `owned` に積んで元のエラーを返し、呼び出し側の [`rollback`] がマウント ID を再確認して外す。証拠が無ければ
///   外さず、マウント先に mount 前に無かったマウントが残っていれば（または確認できなければ）
///   `ownership unconfirmed` を付けて返す。記録・mountinfo の読み直しは [`MAX_RECOVERY_READS`] 回 ×
///   呼び出しごとのタイムアウトで有界（REPAIR-5）。
///
/// タイムアウト後にゲスト内で遅れて成立したマウントは、読み直しの後であれば検出できない（実機での挙動確認は
/// TASK-67.6・#377。REPAIR-3）。
fn mount_one(
    distro: &DistroName,
    m: &SharedMount,
    before_ids: &[u32],
    owned: &mut Vec<OwnedMount>,
    exec: Exec<'_>,
) -> Result<(), Wsl2Error> {
    let nonce = new_nonce();
    let (failure, evidence) = match exec(&mount_argv(distro, m, &nonce), MAX_OUTPUT_BYTES) {
        Ok(out) => {
            // 200〜202 は MOUNT_SCRIPT が `mount` の前に返す（`mount(8)`・シグナル終了のコードと重ならない）。
            let failure = match out.code {
                _ if out.success => None,
                Some(EXIT_PARENT_BAD) => {
                    return Err(precondition(
                        "the mount base parent directory is missing or unsafe",
                    ));
                }
                Some(EXIT_MKDIR_FAILED) => {
                    return Err(step_failed("creating the mount target", &out));
                }
                Some(EXIT_PATH_UNSAFE) => {
                    return Err(precondition(
                        "a mount path component is not a root-owned, non-writable directory (symlinks are rejected)",
                    ));
                }
                _ => Some(step_failed("mounting the shared directory", &out)),
            };
            // 標準出力から読めなければ（想定外の出力が混ざった等）、ゲスト内の記録で確かめる。
            let evidence = match parse_recorded_id(&out.stdout) {
                Some(id) => Evidence::Mine(id),
                None => read_record(distro, &nonce, exec),
            };
            (failure, evidence)
        }
        // 標準出力を失ったので、MOUNT_SCRIPT がゲスト内に残した記録を読む。
        Err(e) => (Some(e), read_record(distro, &nonce, exec)),
    };
    let guest_path = m.guest_path();
    let unconfirmed = |e: Wsl2Error| {
        Wsl2Error::new(
            e.code(),
            format!(
                "{} (mount ownership unconfirmed; the mount may have been left in place)",
                e.message()
            ),
        )
    };
    match (evidence, failure) {
        (Evidence::Mine(mount_id), failure) => {
            owned.push(OwnedMount {
                guest_path,
                mount_id,
                nonce,
            });
            failure.map_or(Ok(()), Err)
        }
        (Evidence::Missing | Evidence::Unreadable, None) => Err(unconfirmed(precondition(
            "the shared mount could not be uniquely identified after mounting",
        ))),
        (Evidence::Unreadable, Some(e)) => Err(unconfirmed(e)),
        (Evidence::Missing, Some(e)) => {
            match count_fresh_mounts(distro, &guest_path, before_ids, exec) {
                Some(0) => Err(e),
                _ => Err(unconfirmed(e)),
            }
        }
    }
}

/// 全マウントが「自分が成立させたマウント ID の最上位エントリ」かつ virtiofs で、読み取り専用か否かが要求と
/// 一致する（ro 要求なら ro・読み書き要求なら ro でない）ことを確認する。`owned` は `req.mounts` と同順・同数。
fn verify_virtiofs(
    req: &LaunchRequest,
    owned: &[OwnedMount],
    exec: Exec<'_>,
) -> Result<(), Wsl2Error> {
    if owned.len() != req.mounts.len() {
        return Err(precondition("the shared mount records are inconsistent"));
    }
    let Some(after) = read_mountinfo_bounded(&req.distro, exec) else {
        return Err(precondition("reading mountinfo after mounting failed"));
    };
    for (m, o) in req.mounts.iter().zip(owned) {
        match find_mount(&after, &o.guest_path) {
            Some(e) if e.mount_id != o.mount_id => {
                return Err(precondition(
                    "a shared mount was replaced by another mount after mounting",
                ));
            }
            Some(e) if e.fstype != VIRTIOFS_FSTYPE => {
                return Err(precondition(
                    "a shared mount is not backed by virtiofs; the setting may not be applied to the running VM, run 'wsl --shutdown' and retry",
                ));
            }
            Some(e) if !e.has_option("nosuid") || !e.has_option("nodev") => {
                return Err(precondition(
                    "a shared mount is missing the nosuid or nodev option",
                ));
            }
            Some(e) if m.read_only && !e.is_read_only() => {
                return Err(precondition(
                    "a read-only shared mount is not mounted read-only",
                ));
            }
            // 読み書き要求なのに ro で成立した場合も、呼び出し側が書き込み可能と誤認しないよう拒否する。
            Some(e) if !m.read_only && e.is_read_only() => {
                return Err(precondition(
                    "a read-write shared mount is mounted read-only",
                ));
            }
            Some(_) => {}
            None => {
                return Err(precondition(
                    "the shared mount is missing or its topmost mount cannot be determined after mounting",
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
    // 共有マウントが 0 件ならゲスト内で検証すべきものが無いため、mountinfo も読まず空の結果を返す。
    if req.mounts.is_empty() {
        return Ok(PreparedLaunch {
            distro: req.distro.clone(),
            mounts: Vec::new(),
            transport: SharedTransport::Virtiofs,
        });
    }
    // 基底・マウント先の symlink 非追従検証とディレクトリ作成は mount と同じゲスト内プロセスで行う
    // （mount_one / MOUNT_SCRIPT。検証と mount を別呼び出しにすると差し替え競合が起きる）。
    // 自分が作っていないマウントは外さないため、既存のマウントがあれば何もせず拒否する
    // （mountinfo は論理パスで照合する。symlink を含むパスは MOUNT_SCRIPT が mount 前に拒否する）。
    let before = read_mountinfo(distro, exec)?;
    for m in &req.mounts {
        let target = m.guest_path();
        if before.iter().any(|e| e.mount_point == target) {
            return Err(precondition("a shared mount target is already mounted"));
        }
    }
    let before_ids: Vec<u32> = before.iter().map(|e| e.mount_id).collect();
    let mut owned: Vec<OwnedMount> = Vec::new();
    for m in &req.mounts {
        if let Err(e) = mount_one(distro, m, &before_ids, &mut owned, exec) {
            return Err(with_rollback_note(e, rollback(distro, &owned, exec)));
        }
    }
    if let Err(e) = verify_virtiofs(req, &owned, exec) {
        return Err(with_rollback_note(e, rollback(distro, &owned, exec)));
    }
    Ok(PreparedLaunch {
        distro: req.distro.clone(),
        mounts: req
            .mounts
            .iter()
            .zip(&owned)
            .map(|(m, o)| PreparedMount {
                guest_path: o.guest_path.clone(),
                mount_id: o.mount_id,
                read_only: m.read_only,
                nonce: o.nonce.clone(),
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
pub(super) fn prepare_with_program(
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
/// mount がタイムアウトした等で結果が不確定な場合も、mount したゲスト内プロセスの記録（所有の証拠）で
/// 自分のマウントを特定して外す。自分のものと確認できないマウントは外さず、メッセージに
/// `mount ownership unconfirmed` を含めて返す。
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

/// 準備済みマウントを逆順に best-effort で解除する（マウント ID が一致するものだけ）。失敗件数を返す。
fn release_with_exec(prepared: &PreparedLaunch, exec: Exec<'_>) -> usize {
    let owned: Vec<OwnedMount> = prepared
        .mounts
        .iter()
        .map(|m| OwnedMount {
            guest_path: m.guest_path.clone(),
            mount_id: m.mount_id,
            nonce: m.nonce.clone(),
        })
        .collect();
    rollback(&prepared.distro, &owned, exec)
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
    release_with_program(&program, prepared, timeout)
}

/// `program` を `wsl.exe` として使う [`release_virtiofs_launch`] の本体。
pub(super) fn release_with_program(
    program: &Path,
    prepared: &PreparedLaunch,
    timeout: Duration,
) -> Result<(), Wsl2Error> {
    check_timeout(timeout)?;
    let mut exec = program_exec(program, timeout);
    match release_with_exec(prepared, &mut exec) {
        0 => Ok(()),
        n => Err(precondition(format!("{n} unmount(s) failed"))),
    }
}

/// [`launch_with`] の成功時の結果: 起動ステップの戻り値と、解除に使う準備済みマウント。
///
/// マウントは呼び出し側（TASK-116）の所有になるため、停止時に `prepared` を [`release_virtiofs_launch`] へ
/// 渡して解除する（解除に必要な所有情報〔マウント先・マウント ID〕を戻り値で明示的に引き渡す）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Launched<T> {
    /// 起動ステップ `start` の戻り値。
    pub value: T,
    /// 起動ステップに渡した準備済みマウント（解除時に [`release_virtiofs_launch`] へ渡す）。
    pub prepared: PreparedLaunch,
}

/// 準備成功後に `start` を呼び、`start` が失敗したら準備済みマウントを解除して返す（ロールバック）。
fn launch_with_exec<T>(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, Wsl2Error> {
    let prepared = prepare_with_exec(status, virtiofs, req, exec)?;
    match start(&prepared) {
        Ok(value) => Ok(Launched { value, prepared }),
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
/// 戻り値の [`Launched::prepared`] を停止時に [`release_virtiofs_launch`] へ渡して解除する。`start` の中身（ゲスト内のコンテナランタイム起動）は
/// TASK-116 が注入する。
pub fn launch_with<T>(
    req: &LaunchRequest,
    timeout: Duration,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, Wsl2Error> {
    let (program, state) = resolve_environment(timeout)?;
    launch_with_program(&program, state, req, timeout, start)
}

/// `program` を `wsl.exe` として使い、`.wslconfig` の状態を `virtiofs` で与える [`launch_with`] の本体。
pub(super) fn launch_with_program<T>(
    program: &Path,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    timeout: Duration,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, Wsl2Error> {
    check_timeout(timeout)?;
    let status = detect_with_program(program, timeout)?;
    let mut exec = program_exec(program, timeout);
    launch_with_exec(&status, virtiofs, req, &mut exec, start)
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
        let script_args = |m: &SharedMount| {
            let v = mount_argv(&d, m, "00ff");
            (
                v.get(..7).map(<[String]>::to_vec),
                v.get(8..).map(<[String]>::to_vec),
            )
        };
        let head: Vec<String> = [
            "--distribution",
            "Ubuntu",
            "--user",
            "root",
            "--exec",
            "sh",
            "-c",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let (h, t) = script_args(&rw);
        assert_eq!(h, Some(head.clone()));
        assert_eq!(
            t,
            Some(vec![
                "sh".to_string(),
                "C:\\a b".to_string(),
                "data".to_string(),
                "nosuid,nodev".to_string(),
                "00ff".to_string()
            ])
        );
        let (h, t) = script_args(&ro);
        assert_eq!(h, Some(head));
        assert_eq!(
            t.and_then(|v| v.get(3).cloned()).as_deref(),
            Some("nosuid,nodev,ro")
        );
        // 検証・mount・所有の特定と記録が同一スクリプト内にあること（TOCTOU 防止・所有の証拠）。
        assert!(MOUNT_SCRIPT.contains(
            "chk \"$T\" || exit 202; pre=$(ids \"$T\"); rc=0; mount -t drvfs -o \"$3\" \"$1\" \"$T\" >&2 || rc=$?; "
        ));
        // 並行する準備が先にディレクトリを作っても失敗しない（作成後に chk で安全性を確かめる）。
        assert!(MOUNT_SCRIPT.contains(
            "mkdir -m 700 -- \"$R\" 2>/dev/null || [ -d \"$R\" ] || exit 201; chk \"$R\" || exit 202; "
        ));
        assert!(MOUNT_SCRIPT.contains(
            "if [ \"$n\" = 1 ]; then printf '%s\\n' \"$new\" > \"$R/$4\" || :; printf '%s\\n' \"$new\"; fi; exit \"$rc\""
        ));
        // / からの全要素と記録ディレクトリを検証すること・ID の照合と umount が同一スクリプト内にあること。
        assert!(
            MOUNT_SCRIPT
                .contains("chk / || exit 200; chk /mnt || exit 200; chk /run || exit 200; ")
        );
        assert!(UMOUNT_SCRIPT.contains(
            "[ \"$n\" = 1 ] && [ \"$top\" = \"$2\" ] || exit 203; umount \"$1\" || exit $?; rm -f -- \"/run/fandhe/$3\"; exit 0"
        ));
        assert_eq!(
            record_argv(&d, "00ff").get(5..),
            Some(
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    RECORD_SCRIPT.to_string(),
                    "sh".to_string(),
                    "00ff".to_string()
                ][..]
            )
        );
        assert_eq!(
            umount_argv(&d, "/mnt/fandhe/data", 123, "00ff").get(5..),
            Some(
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    UMOUNT_SCRIPT.to_string(),
                    "sh".to_string(),
                    "/mnt/fandhe/data".to_string(),
                    "123".to_string(),
                    "00ff".to_string()
                ][..]
            )
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
                    mount_id: 22,
                    parent_id: 1,
                    mount_point: "/mnt/fandhe/my dir".into(),
                    options: "rw,nosuid".into(),
                    fstype: "virtiofs".into()
                },
                MountEntry {
                    mount_id: 23,
                    parent_id: 1,
                    mount_point: "/mnt/fandhe/b".into(),
                    options: "rw".into(),
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
            "1 x 3:4 / /a rw - x y",
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
        /// `mounts` と同じ添字のマウント ID。
        ids: Vec<u32>,
        /// `mounts` と同じ添字のマウントオプション。
        opts: Vec<String>,
        next_id: u32,
        mount_fstype: &'static str,
        fail_mount_nth: Option<usize>,
        mount_calls: usize,
        umounts: Vec<String>,
        /// 既存パス → `"<16進の生モード> <UID>"`（MOUNT_SCRIPT の模擬が作成する）。
        paths: std::collections::HashMap<String, String>,
        /// true なら mount 成功後の mountinfo 読み取りを失敗させる。
        fail_cat_after_mount: bool,
        /// true なら `ro` を無視して rw でマウントする（ro 不成立の模擬）。
        ignore_ro: bool,
        /// true なら `ro` を要求しなくても ro でマウントする（読み書き要求の不成立の模擬）。
        force_ro: bool,
        /// true なら mountinfo の行を逆順で出力する（行順が最上位判定の契約でないことの模擬）。
        reverse_mountinfo: bool,
        /// ゲスト内の所有の記録（nonce → マウント ID）。
        records: std::collections::HashMap<String, u32>,
        /// 記録の読み取り回数。
        record_reads: usize,
        /// true なら記録の読み取りを `TIMEOUT` にする。
        fail_record_read: bool,
        /// true なら MOUNT_SCRIPT が記録を書けなかった（標準出力には書く）ことにする。
        drop_record: bool,
        /// true なら MOUNT_SCRIPT の読み取りの後に、同じマウント先へ他者のマウントが現れる。
        foreign_after_script: bool,
        /// true なら MOUNT_SCRIPT の標準出力の先頭に想定外の 1 行が混ざる。
        noisy_stdout: bool,
        /// true なら mount のたびに同じマウント先へ別プロセスのマウントも積む（競合の模擬）。
        extra_on_mount: bool,
        /// true なら nosuid,nodev を無視してマウントする（オプション不成立の模擬）。
        drop_nosuid: bool,
        /// n 回目の mount 呼び出しを `TIMEOUT` にする（`wsl.exe` の待機タイムアウトの模擬）。
        timeout_mount_nth: Option<usize>,
        /// true なら `timeout_mount_nth` のタイムアウト前にゲスト内の mount が成立している。
        timeout_mount_lands: bool,
        /// mount 後の mountinfo 読み取りを先頭から何回失敗させるか（一過性の失敗の模擬）。
        fail_cat_times: usize,
        /// mountinfo 読み取りの呼び出し回数。
        cat_calls: usize,
        /// `Some(landed)` なら umount を `TIMEOUT` にする。`landed` が true なら解除自体は成立している。
        umount_timeout: Option<bool>,
        /// true なら UMOUNT_SCRIPT の照合直前に同じマウント先へ他者のマウントが積まれる（照合と解除の競合の模擬）。
        stack_before_umount: bool,
        /// `Some(code)` なら mount を成立させたうえで終了コード `code` の失敗を返す（16 等の不確定な失敗の模擬）。
        landed_exit_code: Option<i32>,
    }

    impl Guest {
        fn new(fstype: &'static str) -> Self {
            Self {
                mounts: vec![("/".into(), "ext4".into())],
                ids: vec![1],
                opts: vec!["rw".into()],
                next_id: 100,
                mount_fstype: fstype,
                fail_mount_nth: None,
                mount_calls: 0,
                umounts: vec![],
                paths: std::collections::HashMap::from([
                    ("/".to_string(), "41ed 0".to_string()),
                    ("/mnt".to_string(), "41ed 0".to_string()),
                    ("/run".to_string(), "41ed 0".to_string()),
                ]),
                fail_cat_after_mount: false,
                ignore_ro: false,
                force_ro: false,
                reverse_mountinfo: false,
                records: std::collections::HashMap::new(),
                record_reads: 0,
                fail_record_read: false,
                drop_record: false,
                foreign_after_script: false,
                noisy_stdout: false,
                extra_on_mount: false,
                drop_nosuid: false,
                timeout_mount_nth: None,
                timeout_mount_lands: false,
                fail_cat_times: 0,
                cat_calls: 0,
                umount_timeout: None,
                landed_exit_code: None,
                stack_before_umount: false,
            }
        }

        fn timeout() -> Result<run::Captured, Wsl2Error> {
            Err(Wsl2Error::new(
                Wsl2ErrorCode::Timeout,
                "wsl.exe did not finish before the deadline",
            ))
        }

        fn run(&mut self, args: &[String], _max: usize) -> Result<run::Captured, Wsl2Error> {
            let cmd: Vec<&str> = args.iter().skip(5).map(String::as_str).collect();
            if matches!(cmd.as_slice(), ["cat", _]) {
                self.cat_calls += 1;
            }
            let fail_cat = |code| {
                Ok(run::Captured {
                    success: false,
                    code: Some(code),
                    stdout: vec![],
                    stderr: vec![],
                })
            };
            let ok = |stdout: String| {
                Ok(run::Captured {
                    success: true,
                    code: Some(0),
                    stdout: stdout.into_bytes(),
                    stderr: vec![],
                })
            };
            match cmd.as_slice() {
                ["cat", _] if self.fail_cat_after_mount && self.mount_calls > 0 => fail_cat(1),
                ["cat", _] if self.fail_cat_times > 0 && self.mount_calls > 0 => {
                    self.fail_cat_times -= 1;
                    fail_cat(1)
                }
                ["cat", _] => {
                    // 親のマウント ID: 同じマウント先に先に積まれたマウントがあればそれ、無ければ `/`（ID 1）。
                    let mut lines: Vec<String> = self
                        .mounts
                        .iter()
                        .enumerate()
                        .map(|(i, (p, t))| {
                            let id = self.ids.get(i).copied().unwrap_or(0);
                            let parent = self
                                .mounts
                                .iter()
                                .take(i)
                                .rposition(|(q, _)| q == p)
                                .and_then(|j| self.ids.get(j).copied())
                                .unwrap_or(if i == 0 { 0 } else { 1 });
                            let o = self.opts.get(i).map_or("rw", String::as_str);
                            format!("{id} {parent} 0:{i} / {p} {o} - {t} src rw\n")
                        })
                        .collect();
                    if self.reverse_mountinfo {
                        lines.reverse();
                    }
                    ok(lines.concat())
                }
                ["sh", "-c", script, "sh", _host, name, opts, nonce] if *script == MOUNT_SCRIPT => {
                    // MOUNT_SCRIPT の模擬: / → /mnt → /run → 記録ディレクトリ → 基底 → マウント先を検証し
                    // （無ければ作成）、mount の前後の差分で自分のマウントを特定して標準出力と記録に書く。
                    let fail = |code: i32| {
                        Ok(run::Captured {
                            success: false,
                            code: Some(code),
                            stdout: vec![],
                            stderr: vec![],
                        })
                    };
                    let safe = |r: &str| {
                        let t: Vec<&str> = r.split_whitespace().collect();
                        matches!(t.as_slice(), [mode, "0"]
                            if u32::from_str_radix(mode, 16)
                                .is_ok_and(|m| m & 0o170_000 == 0o040_000 && m & 0o022 == 0))
                    };
                    let target = format!("/mnt/fandhe/{name}");
                    for dir in ["/", "/mnt", "/run"] {
                        match self.paths.get(dir) {
                            Some(r) if safe(r) => {}
                            _ => return fail(EXIT_PARENT_BAD),
                        }
                    }
                    for dir in ["/run/fandhe", "/mnt/fandhe", target.as_str()] {
                        match self.paths.get(dir) {
                            Some(r) if safe(r) => {}
                            Some(_) => return fail(EXIT_PATH_UNSAFE),
                            None => {
                                self.paths.insert(dir.to_string(), "41ed 0".to_string());
                            }
                        }
                    }
                    let target = target.as_str();
                    let ids_at = |g: &Self| -> Vec<u32> {
                        g.mounts
                            .iter()
                            .zip(&g.ids)
                            .filter(|((p, _), _)| p == target)
                            .map(|(_, id)| *id)
                            .collect()
                    };
                    let pre = ids_at(self);
                    self.mount_calls += 1;
                    let timed_out = self.timeout_mount_nth == Some(self.mount_calls);
                    if timed_out && !self.timeout_mount_lands {
                        return Self::timeout();
                    }
                    let failed = self.fail_mount_nth == Some(self.mount_calls);
                    if !failed {
                        self.mounts
                            .push((target.to_string(), self.mount_fstype.to_string()));
                        self.ids.push(self.next_id);
                        let ro = (opts.split(',').any(|o| o == "ro") && !self.ignore_ro)
                            || self.force_ro;
                        let base = if ro { "ro" } else { "rw" };
                        self.opts.push(if self.drop_nosuid {
                            base.to_string()
                        } else {
                            format!("{base},nosuid,nodev")
                        });
                        self.next_id += 1;
                        if self.extra_on_mount {
                            self.mounts
                                .push((target.to_string(), self.mount_fstype.to_string()));
                            self.ids.push(self.next_id);
                            self.opts.push("rw".into());
                            self.next_id += 1;
                        }
                    }
                    let fresh: Vec<u32> = ids_at(self)
                        .into_iter()
                        .filter(|id| !pre.contains(id))
                        .collect();
                    let mut stdout = String::new();
                    if let [mine] = fresh.as_slice() {
                        if !self.drop_record {
                            self.records.insert((*nonce).to_string(), *mine);
                        }
                        stdout = format!("{mine}\n");
                    }
                    if self.noisy_stdout {
                        stdout = format!("unexpected helper message\n{stdout}");
                    }
                    if self.foreign_after_script {
                        // スクリプトの読み取りの後に他者のマウントが現れた（証拠には含まれない）。
                        self.mounts.push((target.to_string(), "tmpfs".to_string()));
                        self.ids.push(self.next_id);
                        self.opts.push("rw".into());
                        self.next_id += 1;
                    }
                    if timed_out {
                        return Self::timeout();
                    }
                    let code = if failed {
                        Some(32)
                    } else {
                        self.landed_exit_code
                    };
                    Ok(run::Captured {
                        success: code.is_none(),
                        code: Some(code.unwrap_or(0)),
                        stdout: stdout.into_bytes(),
                        stderr: if failed {
                            b"secret C:\\Users\\bob".to_vec()
                        } else {
                            vec![]
                        },
                    })
                }
                ["sh", "-c", script, "sh", nonce] if *script == RECORD_SCRIPT => {
                    // RECORD_SCRIPT の模擬: 記録があれば ID を出力、無ければ 204。
                    self.record_reads += 1;
                    if self.fail_record_read {
                        return Self::timeout();
                    }
                    match self.records.get(*nonce) {
                        Some(id) => ok(format!("{id}\n")),
                        None => fail_cat(EXIT_NO_RECORD),
                    }
                }
                ["sh", "-c", script, "sh", target, id, nonce] if *script == UMOUNT_SCRIPT => {
                    // UMOUNT_SCRIPT の模擬: 最上位のマウント ID が記録値と一致するときだけ外す（不一致は 203）。
                    self.umounts.push((*target).to_string());
                    if self.stack_before_umount {
                        self.mounts
                            .push(((*target).to_string(), "tmpfs".to_string()));
                        self.ids.push(self.next_id);
                        self.opts.push("rw".into());
                        self.next_id += 1;
                    }
                    let top = self
                        .mounts
                        .iter()
                        .rposition(|(p, _)| p == target)
                        .and_then(|i| self.ids.get(i))
                        .map(u32::to_string);
                    if top.as_deref() != Some(*id) {
                        return fail_cat(203);
                    }
                    if self.umount_timeout == Some(false) {
                        return Self::timeout();
                    }
                    if let Some(i) = self.mounts.iter().rposition(|(p, _)| p == target) {
                        self.mounts.remove(i);
                        self.ids.remove(i);
                        self.opts.remove(i);
                    }
                    self.records.remove(*nonce);
                    if self.umount_timeout == Some(true) {
                        return Self::timeout();
                    }
                    ok(String::new())
                }
                _ => Err(Wsl2Error::new(Wsl2ErrorCode::Internal, "unexpected")),
            }
        }
    }

    /// 準備済みマウントの (マウント先・マウント ID・読み取り専用か)。
    fn summary(p: &PreparedLaunch) -> Vec<(&str, u32, bool)> {
        p.mounts()
            .iter()
            .map(|m| (m.guest_path.as_str(), m.mount_id, m.read_only))
            .collect()
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
            summary(&p),
            [("/mnt/fandhe/a", 100, false), ("/mnt/fandhe/b", 101, true)]
        );
        assert!(g.umounts.is_empty());
        // 所有の記録は呼び出しごとの nonce で、解除するまで残る。
        let mut recorded: Vec<u32> = g.records.values().copied().collect();
        recorded.sort_unstable();
        assert_eq!(recorded, [100, 101]);
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)), 0);
        assert!(g.records.is_empty());
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
        // 失敗した c は成立していない（他者のマウントかもしれない）ので外さず、成立済みの b・a だけを外す。
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);
        assert_eq!(g.mounts.len(), 1);
    }

    /// 既存マウントがあれば何も外さずエラー、virtiofs 未設定ならマウントを試みない。
    #[test]
    fn prepare_refuses_existing_mount_and_disabled() {
        let mut g = Guest::new("virtiofs");
        g.mounts.push(("/mnt/fandhe/a".into(), "ext4".into()));
        g.ids.push(7);
        g.opts.push("rw".into());
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
            // 生モード（16 進）: symlink 0o120777・他者所有・group/other 書き込み可・通常ファイル。
            "a1ff 0",
            "41ed 1000",
            "41ff 0",
            "41fd 0",
            "81a4 0",
        ] {
            for victim in ["/", "/mnt", "/mnt/fandhe", "/mnt/fandhe/a"] {
                let mut g = Guest::new("virtiofs");
                g.paths.insert("/mnt/fandhe".into(), "41ed 0".into());
                g.paths.insert(victim.into(), bad.into());
                let r = req(vec![sm("C:\\a", "a", false)]);
                let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
                assert_eq!(
                    e.code(),
                    Wsl2ErrorCode::FailedPrecondition,
                    "{bad} {victim}"
                );
                assert_eq!(g.mount_calls, 0, "{bad} {victim}");
                assert!(g.mounts.len() == 1, "{bad} {victim}");
                // exec mount 前の検証失敗（200〜202）は回復の読み直しをしない（mount 前の 1 回のみ）。
                assert_eq!(g.cat_calls, 1, "{bad} {victim}");
            }
        }
    }

    /// SEC: mount 後に mountinfo を読めず最上位を確認できない場合は、自分のマウントでも外さず、
    /// 未解除として失敗に数えて返す。
    #[test]
    fn prepare_does_not_unmount_when_mountinfo_unreadable() {
        let mut g = Guest::new("virtiofs");
        g.fail_cat_after_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "reading mountinfo after mounting failed (1 rollback unmount(s) also failed)"
        );
        assert!(g.umounts.is_empty());
        // REPAIR-5: 読み直しは上限回数で打ち切る（mount 前の 1 回 + 検証・ロールバックで各 MAX_RECOVERY_READS 回）。
        assert_eq!(g.cat_calls, 1 + 2 * MAX_RECOVERY_READS);
    }

    /// SEC: 同じマウント先へ別マウントが積まれて一意に特定できない場合は解除せず失敗する。
    #[test]
    fn prepare_fails_closed_when_mount_not_unique() {
        let mut g = Guest::new("virtiofs");
        g.extra_on_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("ownership unconfirmed"));
        assert!(g.umounts.is_empty());
    }

    /// SEC: 読み取り専用要求なのに ro でマウントされていなければ解除してエラーにする。
    #[test]
    fn prepare_rejects_read_only_not_applied() {
        let mut g = Guest::new("virtiofs");
        g.ignore_ro = true;
        let r = req(vec![sm("C:\\a", "a", true)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("read-only"));
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
    }

    /// WIN-2: 読み書き要求なのに ro で成立した場合も、解除して FAILED_PRECONDITION にする。
    #[test]
    fn prepare_rejects_read_write_mounted_read_only() {
        let mut g = Guest::new("virtiofs");
        g.force_ro = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "a read-write shared mount is mounted read-only"
        );
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.mounts.len(), 1);
    }

    /// SEC: nosuid / nodev が成立していなければ解除してエラーにする。
    #[test]
    fn prepare_rejects_missing_nosuid_nodev() {
        let mut g = Guest::new("virtiofs");
        g.drop_nosuid = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("nosuid"));
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
    }

    /// 共有マウント 0 件なら mountinfo を読まず空の PreparedLaunch を返す。
    #[test]
    fn prepare_with_no_mounts_skips_mountinfo() {
        let r = req(vec![]);
        let mut calls = 0;
        let p = prepare_with_exec(&ok_status(), VirtiofsState::Enabled, &r, &mut |_, _| {
            calls += 1;
            Err(Wsl2Error::new(Wsl2ErrorCode::Internal, "unexpected"))
        })
        .unwrap();
        assert!(p.mounts().is_empty());
        assert_eq!(calls, 0);
    }

    /// SEC: 自分のマウントの上に他者のマウントが積まれたら、外さず未解除として失敗に数える。
    #[test]
    fn release_counts_failure_when_covered_by_others() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        g.mounts.push(("/mnt/fandhe/a".into(), "tmpfs".into()));
        g.ids.push(777);
        g.opts.push("rw".into());
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m));
        assert_eq!(failures, 1);
        assert!(g.umounts.is_empty());
    }

    /// SEC: 検証時に最上位のマウント ID が記録値と異なれば、差し替えられたマウントは外さず失敗する。
    #[test]
    fn verify_rejects_replaced_mount_id() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let owned = vec![OwnedMount {
            guest_path: "/mnt/fandhe/a".into(),
            mount_id: 100,
            nonce: "00ff".into(),
        }];
        g.mounts.push(("/mnt/fandhe/a".into(), "virtiofs".into()));
        g.ids.push(555);
        g.opts.push("rw".into());
        let e = verify_virtiofs(&r, &owned, &mut |a, m| g.run(a, m)).unwrap_err();
        assert!(e.message().contains("replaced"));
        assert!(g.umounts.is_empty());
    }

    /// SEC: 解除前にマウント ID を再確認し、他プロセスが差し替えたマウントは外さない。
    #[test]
    fn release_skips_mount_replaced_by_others() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        // a を他者が別のマウントへ差し替えた状態にする（ID が変わる）。
        let i = g
            .mounts
            .iter()
            .position(|(m, _)| m == "/mnt/fandhe/a")
            .unwrap();
        g.ids[i] = 9999;
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m));
        assert_eq!(failures, 0);
        assert_eq!(g.umounts, ["/mnt/fandhe/b"]);
        assert!(g.mounts.iter().any(|(m, _)| m == "/mnt/fandhe/a"));
    }

    /// SEC: 記録したマウント ID が別のマウント先へ移されて残っている場合は、解除失敗として数える。
    #[test]
    fn release_counts_failure_when_mount_moved_elsewhere() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        let i = g
            .mounts
            .iter()
            .position(|(m, _)| m == "/mnt/fandhe/a")
            .unwrap();
        g.mounts[i].0 = "/elsewhere".into();
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m));
        assert_eq!(failures, 1);
        assert!(g.umounts.is_empty());
        // どこにも残っていなければ解除済みとして成功扱い。
        g.mounts.remove(i);
        g.ids.remove(i);
        g.opts.remove(i);
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)), 0);
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
        assert_eq!(v.value, 2);
        assert!(g.umounts.is_empty());
        // 成功時は解除に使う準備済みマウントが戻り値で渡され、それで逆順に解除できる。
        let ids: Vec<u32> = v.prepared.mounts().iter().map(|m| m.mount_id).collect();
        assert_eq!(ids, [100, 101]);
        assert_eq!(release_with_exec(&v.prepared, &mut |a, m| g.run(a, m)), 0);
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);
    }

    /// SEC・REPAIR-5: mount 成立後に `wsl.exe` の待機がタイムアウトしても、mountinfo を読み直して
    /// 自分のマウントを特定し、ロールバックで外す（元のタイムアウトのエラーを返す）。
    #[test]
    fn prepare_recovers_and_rolls_back_mount_after_timeout() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        g.timeout_mount_lands = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.mounts, [("/".to_string(), "ext4".to_string())]);
    }

    /// REPAIR-5: タイムアウトしたがマウントが成立していなければ、何も外さず元のエラーを返す。
    #[test]
    fn prepare_timeout_without_mount_unmounts_nothing() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
        assert!(g.umounts.is_empty());
        assert_eq!(g.mounts.len(), 1);
        // mount 前の 1 回 + 回復の 1 回（読めたので再試行しない）。
        assert_eq!(g.cat_calls, 2);
    }

    /// SEC: タイムアウト後に新規マウントが複数あって自分のものを特定できなければ、外さず未確認として返す。
    #[test]
    fn prepare_timeout_with_ambiguous_mounts_fails_closed() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        g.timeout_mount_lands = true;
        g.extra_on_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(
            e.message(),
            "wsl.exe did not finish before the deadline (mount ownership unconfirmed; the mount may have been left in place)"
        );
        assert!(g.umounts.is_empty());
        assert_eq!(g.mounts.len(), 3);
    }

    /// SEC・REPAIR-5: タイムアウト後に所有の記録を上限回数まで読めなければ、外さず未確認として返す。
    #[test]
    fn prepare_timeout_with_unreadable_record_fails_closed() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        g.timeout_mount_lands = true;
        g.fail_record_read = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert!(
            e.message().contains("ownership unconfirmed"),
            "{}",
            e.message()
        );
        assert!(g.umounts.is_empty());
        assert_eq!(g.record_reads, MAX_RECOVERY_READS);
        assert_eq!(g.cat_calls, 1);
    }

    /// SEC: 2 件目の mount がタイムアウトしても、回復した 2 件目と成立済みの 1 件目を逆順に外す。
    #[test]
    fn prepare_timeout_midway_rolls_back_all_owned_mounts() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(2);
        g.timeout_mount_lands = true;
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);
        assert_eq!(g.mounts.len(), 1);
    }

    /// REPAIR-5: mount 後の mountinfo 読み取りが一過性に失敗しても、再試行で所有を確認して準備を続ける。
    #[test]
    fn prepare_retries_transient_mountinfo_failure() {
        let mut g = Guest::new("virtiofs");
        g.fail_cat_times = 1;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(summary(&p), [("/mnt/fandhe/a", 100, false)]);
        assert!(g.umounts.is_empty());
        // mount 前 1 回 + 検証 2 回（1 回失敗。所有は MOUNT_SCRIPT の標準出力で確定するので読まない）。
        assert_eq!(g.cat_calls, 3);
    }

    /// SEC: mount(8) が失敗コード（2=システムエラー・16・32=マウント失敗・ビットの組み合わせの 70〜72）を
    /// 返しても成立していた場合は、終了コードだけで未成立と決めず、読み直して成立分を外す。
    #[test]
    fn prepare_rolls_back_mount_that_landed_despite_failure_code() {
        for code in [2, 16, 32, 70, 71, 72] {
            let mut g = Guest::new("virtiofs");
            g.landed_exit_code = Some(code);
            let r = req(vec![sm("C:\\a", "a", false)]);
            let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition, "{code}");
            assert_eq!(
                e.message(),
                format!(
                    "mounting the shared directory failed in the distribution (exit code {code})"
                )
            );
            assert_eq!(g.umounts, ["/mnt/fandhe/a"], "{code}");
            assert_eq!(g.mounts.len(), 1, "{code}");
        }
    }

    /// REPAIR-5: umount がタイムアウトしても、読み直して自分のマウント ID が消えていれば解除済みとし、
    /// 残っていれば失敗に数える。
    #[test]
    fn release_rechecks_after_umount_timeout() {
        let r = req(vec![sm("C:\\a", "a", false)]);
        for (landed, want) in [(true, 0), (false, 1)] {
            let mut g = Guest::new("virtiofs");
            let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
            g.umount_timeout = Some(landed);
            let failures = release_with_exec(&p, &mut |a, m| g.run(a, m));
            assert_eq!(failures, want, "landed={landed}");
            assert_eq!(g.umounts, ["/mnt/fandhe/a"], "landed={landed}");
        }
    }

    /// SEC: 照合後・umount 前に同じマウント先へ他者のマウントが積まれても、ゲスト内の再照合で外さず
    /// 未解除として失敗に数える（他者のマウントも自分のマウントも残る）。
    #[test]
    fn release_does_not_unmount_mount_stacked_before_umount() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        g.stack_before_umount = true;
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m));
        assert_eq!(failures, 1);
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.ids, [1, 100, 101]);
    }

    /// SEC: 最上位はマウント階層（親のマウント ID）で決め、mountinfo の行順に頼らない。
    /// 同じパス文字列の最上位候補が複数あって確定できなければ `None`（所有を確認できないものとして扱う）。
    #[test]
    fn find_mount_uses_hierarchy_not_line_order() {
        // 102 が 100 の上に積まれているが、行は逆順。
        let text = "102 100 0:4 / /mnt/fandhe/a rw - tmpfs x rw\n\
                    1 0 0:1 / / rw - ext4 x rw\n\
                    100 1 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(
            find_mount(&e, "/mnt/fandhe/a").map(|m| m.mount_id),
            Some(102)
        );
        // 別々の親の下に同じパス文字列が 2 つ見える場合は確定できない。
        let text = "100 50 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n\
                    101 60 0:3 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(find_mount(&e, "/mnt/fandhe/a"), None);
        // UMOUNT_SCRIPT も行順でなく親子関係で最上位を数える。
        assert!(UMOUNT_SCRIPT.contains("while read -r id par _ _ mp _;"));
        assert!(UMOUNT_SCRIPT.contains("[ \"$n\" = 1 ] && [ \"$top\" = \"$2\" ] || exit 203; "));
    }

    /// SEC: mountinfo の行が逆順でも、準備・解除と、他者に覆われたマウントを外さない判定が変わらない。
    #[test]
    fn prepare_and_release_do_not_depend_on_mountinfo_order() {
        let mut g = Guest::new("virtiofs");
        g.reverse_mountinfo = true;
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        let ids: Vec<u32> = p.mounts().iter().map(|m| m.mount_id).collect();
        assert_eq!(ids, [100, 101]);
        // a の上に他者のマウントを積む（行は逆順で出力される）。
        g.mounts.push(("/mnt/fandhe/a".into(), "tmpfs".into()));
        g.ids.push(777);
        g.opts.push("rw".into());
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)), 1);
        assert_eq!(g.umounts, ["/mnt/fandhe/b"]);
        assert_eq!(g.ids, [1, 100, 777]);
    }

    /// SEC: タイムアウト後、マウント先に mount 前に無かったマウントが 1 件あっても、mount を実行した
    /// プロセスの記録（所有の証拠）が無ければ自分のものとみなさず、外さずに未確認として返す。
    #[test]
    fn prepare_timeout_without_record_does_not_unmount() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        g.timeout_mount_lands = true;
        g.drop_record = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(
            e.message(),
            "wsl.exe did not finish before the deadline (mount ownership unconfirmed; the mount may have been left in place)"
        );
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100]);
        assert_eq!(g.record_reads, 1);
    }

    /// SEC: mount(8) が失敗し、その後に他者のマウントが同じマウント先へ現れても、証拠が無いので外さない
    /// （mountinfo の差分だけで所有を推定しない）。
    #[test]
    fn prepare_failure_with_foreign_mount_does_not_unmount() {
        let mut g = Guest::new("virtiofs");
        g.fail_mount_nth = Some(1);
        g.foreign_after_script = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "mounting the shared directory failed in the distribution (exit code 32) (mount ownership unconfirmed; the mount may have been left in place)"
        );
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100]);
    }

    /// REPAIR-5: タイムアウトから回復して外したマウントの記録も消える。
    #[test]
    fn rollback_after_timeout_removes_record() {
        let mut g = Guest::new("virtiofs");
        g.timeout_mount_nth = Some(1);
        g.timeout_mount_lands = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert!(g.records.is_empty());
        assert_eq!(g.record_reads, 1);
    }

    /// 所有の記録・標準出力の解析は 10 進のマウント ID 1 行だけを受け付ける（それ以外は証拠にしない）。
    #[test]
    fn recorded_id_parsing_and_nonce_format() {
        assert_eq!(parse_recorded_id(b"123\n"), Some(123));
        assert_eq!(parse_recorded_id(b"4294967295"), Some(u32::MAX));
        for bad in [
            &b""[..],
            b"\n",
            b"12 13\n",
            b"-1",
            b"abc",
            b"4294967296",
            b"00000000001",
        ] {
            assert_eq!(parse_recorded_id(bad), None, "{bad:?}");
        }
        let (a, b) = (new_nonce(), new_nonce());
        assert_ne!(a, b);
        assert_eq!(a.len(), 56);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
    }

    /// 標準出力に想定外の行が混ざってマウント ID を読めなくても、ゲスト内の記録で所有を確かめて続行する。
    #[test]
    fn prepare_falls_back_to_record_when_stdout_is_noisy() {
        let mut g = Guest::new("virtiofs");
        g.noisy_stdout = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(summary(&p), [("/mnt/fandhe/a", 100, false)]);
        assert_eq!(g.record_reads, 1);
        assert!(g.umounts.is_empty());
    }
}
