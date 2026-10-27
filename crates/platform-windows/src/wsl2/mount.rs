//! virtiofs 共有マウントとコンテナ起動前の検証シーケンス（TASK-67.4・#375。WIN-1・WIN-2・ERR-1・REPAIR-2/3/4/5）。
//!
//! Windows のホストディレクトリを WSL2 ディストリ内の固定の基底（[`GUEST_MOUNT_BASE`]）配下へマウントし、
//! マウントが virtiofs で成立していることを確認してから、呼び出し側が渡す起動ステップへ進む。
//! 呼び出し元は `fandhe-container-plugin-windows`（TASK-116）。検証・マウントのどこかで失敗した場合は
//! 起動ステップを呼ばずに構造化エラー（[`MountError`]。`code` / `message`〔ERR-1〕と、後始末で外せなかった
//! マウントの所有情報）を返す（fail-closed）。
//!
//! 構成:
//! - 入力の検証済み newtype（[`HostDir`]・[`MountName`]・[`DistroName`]・[`SharedMount`]・[`LaunchRequest`]）。
//!   生の文字列を `wsl.exe` の引数へ直接連結せず、型で「壊れた値を表現できない」ようにする（REPAIR-2）。
//! - 純粋関数（事前判定・argv 組み立て・`/proc/self/mountinfo` 解析）。全 OS でユニットテストする。
//! - 実行部（`run::run_capture` 経由。各呼び出しには操作ごとの合計期限の残り時間を渡す。REPAIR-5）。
//!
//! 後始末の追跡の前提: ゲスト内の root は信頼境界の内側として扱い、root や WSL がゲスト内プロセスを強制終了した
//! 場合の後始末は対象外とする。`/run/fandhe` の残留物（柵の claim・ロックファイル・未回収の記録）は tmpfs 上にあり
//! WSL の再起動で消える。取り下げた mount とゲスト内で外せなかった mount は、記録の nonce を
//! [`MountError::unreleased`]（マウント ID 未確定）で返し、既存の [`release_virtiofs_launch`] で回収する。
//!
//! 別プロセスからの回収（#1412・WIN-1・WIN-2・PLUG-7）: [`LaunchRequest::with_owner`] でコンテナ ID を付けて準備すると、
//! ゲスト内の記録に ID とマウント先が残る。[`release_container_mounts`] は同じディストリとコンテナ ID だけを手がかりに、
//! 記録を検証して（改ざんがあれば何も外さず）自分のマウントだけを外す。呼び出し側（plugin の stop・起動役の delete）
//! への接続は `docs/design/windows-execution-layout.md` の論点 4（#2230）の承認待ちで未実装（REPAIR-3）。
//!
//! mountinfo のパス文字列による行選択の点検（#2908・SEC-1・NET-1・IO-5。core の #2853 と同じ観点）:
//! 実行環境は、ホスト側（Windows 上の Rust。`wsl.exe ... cat /proc/self/mountinfo` の出力を解析する。fd は持てない）、
//! ゲスト側（WSL2 ディストリ内の初期 mount namespace で root として動く `sh` スクリプト）、純粋関数（全 OS で試験）の 3 つ。
//!
//! | 箇所 | 判定 |
//! | ---- | ---- |
//! | `verify_shared`・`rollback`・`record_matches_mounts`（ホスト） | 祖先の overmount で隠れた行を「最上位」と取り違えうるため、[`find_reachable_mount`]（ID の親子関係で `/` から降りる到達判定）へ変更。隠れていれば `None` で既存の拒否・未解除報告・矛盾扱いに入る |
//! | 事前検査の `e.mount_point == target`・`count_fresh_mounts` | 変更不要。拒否と件数報告にだけ使い、隠れた行も数える保守側 |
//! | ID による照合（`entries.iter().any(\|e\| e.mount_id == id)`） | 変更不要。実体照合 |
//! | `unescape_mountinfo`・`parse_mountinfo` | 変更不要。復号と解析のみ。[`MountName`] は ASCII 英数字と `.`・`_`・`-` だけで、マウント先に 8 進エスケープ対象が現れないためゲストの生の文字列とホストの復号後の文字列の判定は一致する |
//! | ゲストの [`MOUNT_SCRIPT`] の ID 列挙（208 判定・mount 前後の差分） | 変更不要。208 は拒否側で、帰属は flock の下の ID の差分のため隠れた行で誤帰属しない |
//! | ゲストの [`UMOUNT_SCRIPT`]・[`MOUNT_SCRIPT`] 自己後始末の最上位照合と、パス指定の `umount` | 対応済み（#2973）。mountinfo の最上位照合に加え、`umount` の直前にパスを開いた fd の `mnt_id`（`/proc/self/fdinfo/<fd>`）を記録値と照合する。不一致・読み取り不能は [`UMOUNT_SCRIPT`] で 214、自己後始末で 210（外さない。fail-closed） |
//!
//! 残る窓は、ゲスト内で fd を閉じてから `umount` するまでの間（fd を開いたままだと `umount` が EBUSY になるため閉じる
//! 構成は避けられない）に、祖先（`/`・`/mnt`・`/mnt/fandhe`。root 所有で他者は書き込めないことを検査済み）へ
//! overmount できるゲスト内 root だけが起こせる（信頼境界の内側。非特権 userns 内のマウントは初期 namespace へ伝播しない）。
//! ゲストで動く前提は既定ディストリ（Ubuntu）の `/bin/sh`（dash）・util-linux・coreutils・fdinfo の `mnt_id:` 行
//! （Linux 3.15 以降）で、busybox 系は未検証（REPAIR-3）。実 WSL2 での確認は人間担当の #1629 で行う。
//!
//! 検証の本体はマウント後の fstype 確認である。`.wslconfig` の `virtiofs=true` はファイル上の設定に過ぎず、
//! `wsl --shutdown` までは稼働中の VM に反映されないため、設定の確認だけでは virtiofs の成立を保証できない。
//!
//! 輸送方式は [`TransportPolicy`] で選ぶ（TASK-67.5・#376。WIN-2）。既定の [`TransportPolicy::PreferVirtiofs`]
//! は virtiofs を優先し、使えない環境（設定が未有効・稼働中の VM に未反映・カーネルが非対応）では 9P で成立した
//! 共有を受理して起動を続け、降格を [`WinWarning`]（[`PreparedLaunch::warning`]・
//! [`WinOpRecorder::record_win_warning`]）で必ず通知する（暗黙に降格しない）。[`TransportPolicy::RequireVirtiofs`]
//! は virtiofs 以外を `FAILED_PRECONDITION` で拒否する。許可する fstype は `virtiofs` と `9p` だけで、未知の
//! fstype はポリシーによらず拒否する（fail-closed）。所有確認・`nosuid`/`nodev`・ro/rw の検査は 9P でも緩めない。
//!
//! # 未実装範囲・前提（REPAIR-3）
//!
//! - ゲスト内のコンテナランタイム本体の常駐起動・監視は TASK-116 の担当。本モジュールは検証済みマウントを
//!   証明する [`PreparedLaunch`] と、それを受け取る起動ステップを注入する [`launch_with`] までを提供する。
//! - `mount -t drvfs <Windows パス> <マウント先>` が `virtiofs=true` 有効時に virtiofs で成立するという
//!   前提、およびマウントオプション `nosuid,nodev` の受理は実機で未検証（PoC-4 は机上調査のみ。WIN-2 の再検証
//!   条件）。コマンドの組み立ては `mount_argv` に集約しており、実機確認は #353（TASK-22。`win1_win2_shared_mount_on_real_wsl2` の virtiofs の回）で行う。
//! - 9P フォールバック（TASK-67.5）で、WSL2 の drvfs 共有が `/proc/self/mountinfo` 上で fstype `9p` になること、
//!   9P 経路で `nosuid,nodev,ro` が受理されることも実機で未検証（偽 `wsl.exe` は `9p` を返す前提）。#353（TASK-22。
//!   `win1_win2_shared_mount_on_real_wsl2` の 9p の回）で実機確認する。
//! - 結合試験 `tests/wsl2_mount.rs`（feature `wsl2-test-support`）は、偽 `wsl.exe`（`tests/bin/fake_wsl.rs` の
//!   マウント系モード）を子プロセスとして起動し、公開 API と同じ経路（検出 → mount → mountinfo によるマウント
//!   ID・fstype の確認 → 起動ステップ → 解除）と argv の受け渡しを検証する。偽 `wsl.exe` はゲスト内スクリプトを
//!   解釈しないため、スクリプトの振る舞い（ロック・claim・記録・取り下げ・タイムアウトからの回復）は模擬ゲストの
//!   ユニットテストで検証し、本物の WSL2 ゲストでの挙動（`flock`・`/run`・`mount.drvfs`）は #353 の実機試験がこの経路を通る
//!   （挙動そのものの観測は受け入れ条件に無く追跡は #3137。REPAIR-3）。
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
use std::time::{Duration, Instant};

use super::{
    DistroState, MAX_OUTPUT_BYTES, Wsl2Error, Wsl2ErrorCode, Wsl2Status, check_timeout,
    detect_with_program, remaining_until, run, wsl_exe_path,
};
use crate::instrument::{
    NoopWinOpRecorder, WinOpKind, WinOpRecorder, WinOpTimer, WinWarning, WinWarningCode,
    record_win_op,
};
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
/// 9P フォールバックで受理するもう一方の fstype（WSL2 の drvfs 既定共有。WIN-2）。
const NINEP_FSTYPE: &str = "9p";
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

/// コンテナ ID（[`OwnerId`]）の最大バイト数。
pub const MAX_OWNER_ID_LEN: usize = 255;

/// ゲスト内の記録で「所有するコンテナ ID が無い」ことを表す印。コンテナ ID の規則（[`OwnerId::parse`]）が
/// `.` 単独を拒否するため、実在の ID と衝突しない。
const NO_OWNER_MARK: &str = ".";

/// 検証済みのコンテナ ID（共有マウントの所有者。ゲスト内の記録に書き、後から ID だけで引くための鍵。
/// WIN-1・WIN-2・PLUG-7・#1412）。
///
/// 規則は core の `ContainerId::new` と `fandhe-container-plugin-windows` の ID 検証と同じ
/// （`[A-Za-z0-9._-]`・1〜[`MAX_OWNER_ID_LEN`] バイト・`.` / `..` 不可）。本 crate は core に依存しない
/// ため同じ規則を自前で持つ。ゲスト内のシェルスクリプトへは位置引数としてのみ渡し、値は文字種が限られるので
/// 記録の行区切りや空白を含められない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerId(String);

impl OwnerId {
    /// 文字列を検証して作る。違反は `INVALID_ARGUMENT`（メッセージに入力は含めない）。
    pub fn parse(s: &str) -> Result<Self, Wsl2Error> {
        let ok = !s.is_empty()
            && s.len() <= MAX_OWNER_ID_LEN
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(invalid(
                "owner id must be 1-255 characters of [A-Za-z0-9._-], not '.' or '..'",
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

/// 共有の輸送方式の選択方針（WIN-2・TASK-67.5）。
///
/// WIN-2 は 9P を既定の輸送とし virtiofs を opt-in とするため、既定は virtiofs 優先・9P へのフォールバック許可。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TransportPolicy {
    /// virtiofs を優先し、使えなければ警告つきで 9P にフォールバックして起動を続ける（既定）。
    #[default]
    PreferVirtiofs,
    /// virtiofs 以外（未有効・9P で成立）を `FAILED_PRECONDITION` で拒否する（TASK-67.4 の厳格動作）。
    RequireVirtiofs,
}

/// 起動要求（ディストリと共有マウント一覧）。件数上限と、名前・ホストディレクトリの重複を拒否する。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchRequest {
    distro: DistroName,
    mounts: Vec<SharedMount>,
    policy: TransportPolicy,
    owner: Option<OwnerId>,
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
        Ok(Self {
            distro,
            mounts,
            policy: TransportPolicy::default(),
            owner: None,
        })
    }

    /// 共有マウントの所有者（コンテナ ID）を設定した要求を返す。
    ///
    /// 設定すると、ゲスト内の記録（`/run/fandhe/<nonce>`）にコンテナ ID とマウント先が書かれ、作成したプロセスと
    /// 別のプロセスでも [`release_container_mounts`] でコンテナ ID だけを手がかりに回収できる
    /// （WIN-1・WIN-2・PLUG-7・#1412）。未設定の記録は ID で引けない（fail-closed。回収は
    /// [`release_virtiofs_launch`] に [`PreparedLaunch`] を渡す経路のみ）。
    #[must_use]
    pub fn with_owner(mut self, owner: OwnerId) -> Self {
        self.owner = Some(owner);
        self
    }

    /// 設定された所有者（コンテナ ID）。
    pub fn owner(&self) -> Option<&OwnerId> {
        self.owner.as_ref()
    }

    /// 輸送方式の方針を差し替えた要求を返す（既定は [`TransportPolicy::PreferVirtiofs`]）。
    #[must_use]
    pub fn with_transport_policy(mut self, policy: TransportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// 輸送方式の方針。
    pub fn transport_policy(&self) -> TransportPolicy {
        self.policy
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

/// 共有の輸送方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedTransport {
    /// virtiofs。
    Virtiofs,
    /// 9P（virtiofs が使えない環境へのフォールバック。性能は低い。TASK-67.5・WIN-2）。
    NineP,
}

impl SharedTransport {
    /// 機械可読な名前（`"virtiofs"` / `"9p"`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Virtiofs => VIRTIOFS_FSTYPE,
            Self::NineP => NINEP_FSTYPE,
        }
    }
}

/// 検証済みマウント 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreparedMount {
    /// ゲスト内のマウント先。
    pub guest_path: String,
    /// 本呼び出しが成立させたマウントのカーネルのマウント ID。解除時に所有確認へ使う。
    ///
    /// `None` は「未確定」: mount を取り下げた・記録を確定できなかったため、ゲスト内の記録
    /// （`/run/fandhe/<nonce>`）からしか所有を確かめられないもの。[`MountError::unreleased`] にだけ現れ、
    /// [`release_virtiofs_launch`] が記録を読み直して確定したものだけを外す。準備に成功した [`PreparedLaunch`] では
    /// 常に `Some`。
    pub mount_id: Option<u32>,
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
    /// fstype を観測できたときだけ `Some`（共有マウント 0 件・失敗時の未解除情報では `None`）。
    transport: Option<SharedTransport>,
    warning: Option<WinWarning>,
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

    /// ゲスト内の fstype を観測して確定した輸送方式。
    ///
    /// 共有マウントが 0 件、または本値が失敗時の未解除情報（[`MountError::unreleased`]）の場合は
    /// 何も観測していないため `None`（設定状態からの推測値を確定値として返さない。WIN-2）。
    pub fn transport(&self) -> Option<SharedTransport> {
        self.transport
    }

    /// 9P へフォールバックした場合の警告（virtiofs で成立した場合・共有マウントが 0 件の場合は `None`）。
    pub fn warning(&self) -> Option<WinWarning> {
        self.warning
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
    if req.policy == TransportPolicy::RequireVirtiofs && virtiofs != VirtiofsState::Enabled {
        return Err(precondition(
            "virtiofs is not enabled. Set 'virtiofs=true' under [wsl2] in .wslconfig and run 'wsl --shutdown' to apply it",
        ));
    }
    Ok(())
}

/// マウント後に観測した fstype 1 件を方針に照らして検査する（許可リスト。未知の fstype は常に拒否）。
fn check_fstype(policy: TransportPolicy, fstype: &str) -> Result<(), Wsl2Error> {
    match fstype {
        VIRTIOFS_FSTYPE => Ok(()),
        NINEP_FSTYPE if policy == TransportPolicy::PreferVirtiofs => Ok(()),
        NINEP_FSTYPE => Err(precondition(
            "a shared mount is not backed by virtiofs; the setting may not be applied to the running VM, run 'wsl --shutdown' and retry",
        )),
        _ => Err(precondition(
            "a shared mount is backed by an unsupported filesystem type",
        )),
    }
}

/// 観測した fstype 一覧から輸送方式と警告を決める（純粋関数。WIN-2・TASK-67.5）。
///
/// 全て virtiofs なら `Virtiofs`（設定が未有効でも実際に成立していれば警告なし）。1 件でも 9P なら性能の低い側の
/// `NineP` とし、設定が `Enabled` 以外なら `VirtiofsNotEnabled`、`Enabled` なら `VirtiofsNotApplied` を添える。
/// 許可リスト外の fstype・厳格方針での 9P は `FAILED_PRECONDITION`。
fn decide_transport(
    policy: TransportPolicy,
    virtiofs: VirtiofsState,
    fstypes: &[&str],
) -> Result<(SharedTransport, Option<WinWarning>), Wsl2Error> {
    for t in fstypes {
        check_fstype(policy, t)?;
    }
    if fstypes.iter().all(|t| *t == VIRTIOFS_FSTYPE) {
        return Ok((SharedTransport::Virtiofs, None));
    }
    let code = if virtiofs == VirtiofsState::Enabled {
        WinWarningCode::VirtiofsNotApplied
    } else {
        WinWarningCode::VirtiofsNotEnabled
    };
    Ok((SharedTransport::NineP, Some(WinWarning::new(code))))
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

/// ゲスト用スクリプトの共有断片: `mid <dir>` は、パス `<dir>` を実際に開いた fd の `mnt_id`
/// （`/proc/self/fdinfo/<fd>`）を標準出力へ 10 進で書く。ディレクトリでない・symlink・open 失敗・`mnt_id:` 行が
/// 無い場合は何も書かず非 0 で戻る（fail-closed）。
///
/// [`UMOUNT_SCRIPT`] と [`MOUNT_SCRIPT`] の自己後始末が、パス指定の `umount` の直前に「パス解決の先のマウント」が
/// 記録した ID と同じ実体であることを確かめるために使う（照合の実装を 1 か所にまとめる。#2973・SEC-1・WIN-1・NET-1）。
/// 祖先（`/mnt`・`/mnt/fandhe`）が overmount されて対象の行が隠れていても、fd はカーネルのパス解決と同じ先を開く
/// ので、mountinfo の文字列照合では見えない取り違えを検出できる。
///
/// 前提: POSIX `sh`（既定ディストリ Ubuntu の dash で動作。bash でも動く）・`/proc/<pid>/fdinfo` の `mnt_id:` 行
/// （Linux 3.15 以降。WSL2 のカーネルは満たす）。busybox 系は未検証（REPAIR-3）。サブシェルで fd 8 を開くので、
/// スクリプト本体の fd は増えず、`umount` が EBUSY になる原因（開いたままの fd）も残らない。`/proc/self` は
/// サブシェル自身を指す（`$$` は親を指して fd 8 を持たないため使わない）。fifo 等で open がブロックしないよう、
/// 先にディレクトリかつ非 symlink を確かめる。
macro_rules! mnt_id_sh {
    () => {
        concat!(
            "mid() { [ -d \"$1\" ] && [ ! -L \"$1\" ] || return 1; ( exec 8< \"$1\" || exit 1; ",
            "while read -r k v; do if [ \"$k\" = mnt_id: ]; then printf '%s' \"$v\"; exit 0; fi; ",
            "done < /proc/self/fdinfo/8; exit 1 ) 2>/dev/null; }; "
        )
    };
}

/// 試験から `mnt_id_sh!` の断片を単体で実 `sh` に流すための文字列。
#[cfg(test)]
const MNT_ID_SH: &str = mnt_id_sh!();

/// ゲスト内で「パス検証 → 必要ならディレクトリ作成 → 再検証 → mount → 自分のマウントの特定と記録」を
/// 1 つの `sh` プロセスで行うスクリプト。
///
/// 検証とマウントを別々の `wsl.exe` 呼び出しに分けると、その隙間に別プロセスが親やマウント先を symlink へ
/// 差し替えて検証外の場所へ root でマウントさせられる（TOCTOU）。そのため全工程を単一プロセスに拘束し、
/// 検証から `mount` までの窓を最小にする。位置引数は `$1`=ホストディレクトリ・`$2`=マウント名・`$3`=オプション・
/// `$4`=呼び出しごとの nonce（固定スクリプトに値を埋め込まず引数で渡すため、シェルのインジェクションは起きない。
/// 入力は検証済み newtype と 16 進の nonce）。`$5`=所有者のコンテナ ID（[`OwnerId`]。無ければ印 `.`）。
///
/// 所有の証拠: `mount` の直前と直後に同じプロセス内でマウント先のマウント ID を読み、新しく現れたものが
/// ちょうど 1 件ならそれを自分のマウントとして標準出力へ書く（`mount` 自身の標準出力は標準エラーへ回し、
/// 標準出力にはマウント ID の 1 行だけが載るようにする）。あわせて root 専用の記録 `/run/fandhe/<nonce>` に
/// マウント ID（特定できなければ `none`）を一時ファイル経由の rename で書く。`mount` の終了コードによらず記録する
/// （`mount(8)` はマウント成立後の処理でも失敗を返しうるため）。`wsl.exe` の待機がタイムアウトして標準出力を
/// 失っても、呼び出し側は記録（[`RECORD_SCRIPT`]）で自分のマウントを特定できる。`none` なら呼び出し側は所有を
/// 確認できないものとして扱い、外さない。記録は 3 行で、1 行目がマウント ID（または `none`）、2 行目がマウント先
/// （`/mnt/fandhe/<名前>`）、3 行目が `$5`（コンテナ ID または印 `.`）。既存の読み手は 1 行目だけを読む。2・3 行目は
/// [`LOOKUP_SCRIPT`] がコンテナ ID から記録を引くために使う（別プロセスからの回収。#1412）。残る窓（同一プロセス内の `mount` の前後の読み取りの間）に同じマウント先へ
/// マウントできるのはゲスト内の root（CAP_SYS_ADMIN）に限られる。
///
/// 遅れての成立の防止: `mount` の直前に `mkdir /run/fandhe/<nonce>.claim` で実行権を確保する（`mkdir` は原子的）。
/// 呼び出し側がタイムアウト後に [`RECORD_SCRIPT`] で同じ claim を先に取れば、本スクリプトは確保に失敗して
/// `mount` せずに終わる（205）。これにより、待機をあきらめた後でゲスト内の処理が遅れて動き出してもマウントは
/// 成立しない。claim を本スクリプトが先に取っていれば、記録が確定するまで呼び出し側が有界に待つ。
///
/// マウント先ごとの排他: 既存マウントの確認から記録の確定までを、マウント先ごとのロックファイル
/// `/run/fandhe/lock.<名前>` の `flock`（fd 9）で直列化する。同じマウント先への並行する準備が互いの新しい
/// マウントを差分に含めて両方とも所有を確定できなくなるのを防ぐ。ロックは `flock -n` を 0.1 秒間隔で最大 100 回
/// 試み（約 10 秒で打ち切り。REPAIR-5）、取れなければ 207。ロックの下でマウント先に既存のマウントがあれば 208。
/// `flock` のロックはプロセスの終了で必ず外れる（強制終了でも残らない）。`flock` コマンドが無い環境でも 207 で
/// 止まり、排他なしには進まない（fail-closed）。`mount` には fd 9 を渡さない（`9>&-`）。
///
/// 取り下げへの追従: 記録を書いた後に `mkdir /run/fandhe/<nonce>.done` で完了を確定する。呼び出し側が
/// 待ちきれずに [`ABANDON_SCRIPT`] で先に `.done` を取った（取り下げた）場合や、記録を書けなかった場合は、
/// 呼び出し側が所有 ID を受け取れないので、本スクリプト自身が自分のマウント（同一プロセス内で特定した ID が
/// マウント先の最上位であるもの）を外し、記録・claim・`.done` を消して終わる（209。新しいマウントが無かった
/// 場合も 209）。外せなかった場合や、新しいマウントが複数あって自分のものを特定できなかった場合は 210 で、記録
/// （マウント ID または `none`）と `.done` を残して終わる。呼び出し側は未確定の記録として
/// [`MountError::unreleased`] に載せ、後の [`release_virtiofs_launch`] が [`STATUS_SCRIPT`] で記録を読み直して
/// 回収する（記録が無ければ 209 で外し終えたとみなす）。自分のマウントを外す前には、最上位の照合に加えて
/// `mid`（パスを開いた fd の `mnt_id`。祖先の overmount で別のマウントへ解決されないことの確認）も ID と照合し、
/// 一致しなければ外さず 210 とする（#2973・SEC-1）。
///
/// ディレクトリの作成は、並行する別の準備が先に作った場合（`EEXIST`）も成功として扱い、直後の検証で安全性を
/// 確かめる（`/run` は tmpfs で WSL の再起動ごとに消えるため、記録ディレクトリの同時作成は起こりうる）。
///
/// 終了コード: 200=`/`・`/mnt`・`/run` が root 所有の他者書き込み不可な実ディレクトリでない・201=ディレクトリ作成
/// 失敗・202=パス要素が symlink / 非 root 所有 / 他者書き込み可・205=実行権（claim）を確保できない（呼び出し側が
/// 先に取消した等。`mount` しない）・207=マウント先のロックを取れない・208=ロックの下でマウント先が既にマウント
/// 済み・209=記録を確定できず（取り下げを含む）自分のマウントを外した・210=同じく外せなかった。
/// それ以外は `mount` の終了コードをそのまま返す。
/// `mount(8)` の終了コードは 1〜64 のビットの論理和（0〜127）で、シグナル終了は 128+シグナル番号（192 以下）に
/// なるため、スクリプト固有のコードは両者と重ならない 200 番台に置く（`mount` 後の失敗を検証失敗と誤認しない）。
/// 検証は symlink 非追従（`-L`）と `stat` の生モード（`%f`。ロケール非依存）で行う。
///
/// `/` からマウント先までの全要素が「root 所有・group / other 書き込み不可・symlink でない」ことを確かめるため、
/// 検証後に要素を差し替えられる（rename・symlink への置換）のはゲスト内の root（uid 0）に限られる。ゲスト内 root は
/// マウントの付け外しやこのシェルへの介入も自由にできる信頼境界の内側であり、本スクリプトが防ぐ対象は非特権の
/// プロセスによる差し替えである。ディレクトリをハンドル（fd・cwd）で固定してマウントする方式は、WSL の
/// `mount.drvfs` ヘルパーの挙動が実機未検証のため採らない（#353 の実機記録を踏まえて再検討する。追跡は #3137。REPAIR-3）。
const MOUNT_SCRIPT: &str = concat!(
    "set -eu; B=/mnt/fandhe; R=/run/fandhe; ",
    mnt_id_sh!(),
    "chk() { [ ! -L \"$1\" ] && [ -d \"$1\" ] || return 1; ",
    "set -- $(stat -c '%u %f' -- \"$1\"); ",
    "[ \"$1\" = 0 ] && [ $((0x$2 & 18)) -eq 0 ]; }; ",
    "ids() { while read -r id _ _ _ mp _; do if [ \"$mp\" = \"$1\" ]; then printf '%s ' \"$id\"; fi; ",
    "done < /proc/self/mountinfo; }; ",
    "top() { ti=; tp=; while read -r id par _ _ mp _; do if [ \"$mp\" = \"$1\" ]; then ti=\"$ti $id\"; tp=\"$tp $par\"; fi; ",
    "done < /proc/self/mountinfo; tt=; tn=0; ",
    "for i in $ti; do case \" $tp \" in *\" $i \"*) ;; *) tt=$i; tn=$((tn + 1)) ;; esac; done; ",
    "if [ \"$tn\" = 1 ]; then printf '%s' \"$tt\"; fi; }; ",
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
    "command -v flock > /dev/null || exit 207; exec 9> \"$R/lock.$2\"; w=0; ",
    "until flock -n 9; do w=$((w + 1)); [ \"$w\" -le 100 ] || exit 207; sleep 0.1; done; ",
    "[ -z \"$(ids \"$T\")\" ] || exit 208; ",
    "mkdir -- \"$R/$4.claim\" 2>/dev/null || exit 205; ",
    "pre=$(ids \"$T\"); rc=0; ",
    "mount -t drvfs -o \"$3\" \"$1\" \"$T\" >&2 9>&- || rc=$?; ",
    "umask 077; ",
    "new=; n=0; for i in $(ids \"$T\"); do case \" $pre \" in *\" $i \"*) ;; *) new=$i; n=$((n + 1)) ;; esac; done; ",
    "[ \"$n\" = 1 ] || new=none; ",
    "if printf '%s\\n%s\\n%s\\n' \"$new\" \"$T\" \"$5\" > \"$R/$4.tmp\" && mv -f -- \"$R/$4.tmp\" \"$R/$4\" ",
    "&& mkdir -- \"$R/$4.done\" 2>/dev/null; then ",
    "[ \"$new\" = none ] || printf '%s\\n' \"$new\"; exit \"$rc\"; fi; ",
    "x=209; if [ \"$n\" = 1 ]; then ",
    "if [ \"$(top \"$T\")\" = \"$new\" ] && [ \"$(mid \"$T\")\" = \"$new\" ]; then umount \"$T\" >&2 9>&- || x=210; else x=210; fi; ",
    "elif [ \"$n\" != 0 ]; then x=210; fi; ",
    "if [ \"$x\" = 209 ]; then rm -f -- \"$R/$4\" \"$R/$4.tmp\"; rmdir -- \"$R/$4.claim\" \"$R/$4.done\" 2>/dev/null || :; ",
    "else printf '%s\\n%s\\n%s\\n' \"$new\" \"$T\" \"$5\" > \"$R/$4.tmp\" && mv -f -- \"$R/$4.tmp\" \"$R/$4\" || :; mkdir -- \"$R/$4.done\" 2>/dev/null || :; fi; ",
    "exit \"$x\""
);
/// [`MOUNT_SCRIPT`] の終了コード（`/`・`/mnt`・`/run` 不正 / ディレクトリ作成失敗 / パス要素が危険 /
/// 実行権を確保できない）。
const EXIT_PARENT_BAD: i32 = 200;
const EXIT_MKDIR_FAILED: i32 = 201;
const EXIT_PATH_UNSAFE: i32 = 202;
const EXIT_CLAIM_FAILED: i32 = 205;
const EXIT_LOCK_BUSY: i32 = 207;
const EXIT_ALREADY_MOUNTED: i32 = 208;
const EXIT_ROLLED_BACK_IN_GUEST: i32 = 209;
const EXIT_GUEST_ROLLBACK_FAILED: i32 = 210;

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

/// 検証込みマウントコマンドの組み立て。`-t drvfs` が virtiofs で成立するかは実機未検証（#353 の virtiofs の回で確認する。REPAIR-3）。
fn mount_argv(
    distro: &DistroName,
    m: &SharedMount,
    nonce: &str,
    owner: Option<&OwnerId>,
) -> Vec<String> {
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
            owner.map_or(NO_OWNER_MARK, OwnerId::as_str),
        ],
    )
}

/// ゲスト内で [`MOUNT_SCRIPT`] の実行権（`/run/fandhe/<nonce>.claim`）の確保を試み、取れなければ記録
/// `/run/fandhe/<nonce>` を読むスクリプト（`wsl.exe` の待機タイムアウト後の回復用）。`$1`=nonce。
///
/// claim を本スクリプトが取れた場合は、[`MOUNT_SCRIPT`] がまだ `mount` に達しておらず、以後も `mount` しない
/// （確保に失敗して終わる）ことが確定するので終了コード 204（マウントは成立しない）。claim が既にあり記録が
/// まだ無ければ `mount` の途中なので 206（呼び出し側が有界に読み直す）。記録があればその中身（マウント ID または
/// `none`）を出力する。記録ディレクトリは [`MOUNT_SCRIPT`] と同じ検証（root 所有・他者書き込み不可・symlink で
/// ない）をしてから使う。終了コードは `cat`・シグナル終了と重ならない 200 番台。
const RECORD_SCRIPT: &str = concat!(
    "set -u; R=/run/fandhe; ",
    "chk() { [ ! -L \"$1\" ] && [ -d \"$1\" ] || return 1; ",
    "set -- $(stat -c '%u %f' -- \"$1\"); ",
    "[ \"$1\" = 0 ] && [ $((0x$2 & 18)) -eq 0 ]; }; ",
    "chk / || exit 200; chk /run || exit 200; ",
    "[ -L \"$R\" ] || [ -e \"$R\" ] || mkdir -m 700 -- \"$R\" 2>/dev/null || [ -d \"$R\" ] || exit 201; ",
    "chk \"$R\" || exit 202; ",
    "if mkdir -- \"$R/$1.claim\" 2>/dev/null; then exit 204; fi; ",
    "[ -e \"$R/$1\" ] || exit 206; ",
    "exec cat -- \"$R/$1\""
);
/// [`RECORD_SCRIPT`] の終了コード（claim を先に取った: [`MOUNT_SCRIPT`] のマウントは成立しない）。
const EXIT_NO_RECORD: i32 = 204;

fn record_argv(distro: &DistroName, nonce: &str) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", RECORD_SCRIPT, "sh", nonce])
}

/// ゲスト内で [`MOUNT_SCRIPT`] の完了（`/run/fandhe/<nonce>.done`）を先に取って取り下げるか、既に完了していれば
/// 記録を読むスクリプト（`$1`=nonce）。[`RECORD_SCRIPT`] の読み直しが上限に達しても `mount` の途中（206）の
/// ままのときに使う。
///
/// `.done` を本スクリプトが取れたら 211（取り下げ成立: [`MOUNT_SCRIPT`] は `mount` から戻った時点で自分の
/// マウントを外して終わるので、呼び出し側は所有しない）。取れなければ [`MOUNT_SCRIPT`] は記録を書き終えて
/// いるので、記録を出力する（無ければ 206）。`mkdir` の原子性で、どちらが後始末をするかが必ず一方に決まる。
const ABANDON_SCRIPT: &str = concat!(
    "if mkdir -- \"/run/fandhe/$1.done\" 2>/dev/null; then exit 211; fi; ",
    "[ -e \"/run/fandhe/$1\" ] || exit 206; exec cat -- \"/run/fandhe/$1\""
);
/// [`ABANDON_SCRIPT`] の終了コード（取り下げ成立）。
const EXIT_ABANDONED: i32 = 211;

/// 取り下げた（または記録を確定できなかった）[`MOUNT_SCRIPT`] の状態を、何も作らずに読むスクリプト（`$1`=nonce）。
/// [`release_virtiofs_launch`] が未確定の記録（マウント ID が `None` の [`PreparedMount`]）を回収するときに使う。
///
/// 記録があればその中身（マウント ID または `none`）を出力する。記録が無く claim があれば `mount` の途中なので
/// 206。どちらも無ければ [`MOUNT_SCRIPT`] が自分のマウントを外して後始末を終えた（209）ので 212。
const STATUS_SCRIPT: &str = concat!(
    "if [ -e \"/run/fandhe/$1\" ]; then exec cat -- \"/run/fandhe/$1\"; fi; ",
    "if [ -d \"/run/fandhe/$1.claim\" ]; then exit 206; fi; exit 212"
);
/// [`STATUS_SCRIPT`] の終了コード（記録が確定していない: `mount` の途中）。
const EXIT_PENDING: i32 = 206;
/// [`STATUS_SCRIPT`] の終了コード（ゲスト内で後始末済み）。
const EXIT_GONE: i32 = 212;

fn status_argv(distro: &DistroName, nonce: &str) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", STATUS_SCRIPT, "sh", nonce])
}

fn abandon_argv(distro: &DistroName, nonce: &str) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", ABANDON_SCRIPT, "sh", nonce])
}

/// ゲスト内で [`MOUNT_SCRIPT`] の記録・一時ファイル・claim を消すスクリプト（`$1`=nonce）。
///
/// [`MOUNT_SCRIPT`] が終了済みと分かっている場合（記録が確定している・マウントが解除済み）にだけ使う。実行中かも
/// しれない場合に claim を消すと、遅れて動き出した処理が claim を取り直して mount しうるため使わない
/// （回復時に [`RECORD_SCRIPT`] が取った claim は柵として残す。`/run` は tmpfs で WSL の再起動時に消える）。
const CLEAR_SCRIPT: &str = concat!(
    "rm -f -- \"/run/fandhe/$1\" \"/run/fandhe/$1.tmp\" || exit 213; ",
    "for d in \"/run/fandhe/$1.claim\" \"/run/fandhe/$1.done\"; do ",
    "rmdir -- \"$d\" 2>/dev/null || [ ! -e \"$d\" ] && [ ! -L \"$d\" ] || exit 213; done; exit 0"
);

fn clear_argv(distro: &DistroName, nonce: &str) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", CLEAR_SCRIPT, "sh", nonce])
}

/// [`CLEAR_SCRIPT`] を 1 回実行し、削除を確認できたか（実行が成功終了したか）を返す。
///
/// 失敗してもマウントの安全性には影響しないが（スクリプトは削除失敗を 213 で伝える）、記録が残ったまま「回収済み」と報告しないよう、
/// 呼び出し側（[`rollback`]）は `false` を未完了として数える（期限切れは実行器の結果として呼び出し側に伝わる）。
fn clear_record(distro: &DistroName, nonce: &str, exec: Exec<'_>) -> bool {
    matches!(
        exec(&clear_argv(distro, nonce), MAX_OUTPUT_BYTES),
        Ok(out) if out.success
    )
}

/// ゲスト内で「マウント先の最上位のマウント ID が記録値と一致するか確認 → umount → 記録の削除」を 1 つの `sh`
/// プロセスで行うスクリプト。
///
/// 確認と `umount` を別々の `wsl.exe` 呼び出しに分けると、その隙間に別のマウントが同じマウント先へ積まれ、
/// 確認した自分のマウントではなく他者のマウントを外しうる。そのため [`MOUNT_SCRIPT`] と同様に単一プロセスへ拘束し、
/// 窓を最小にする。位置引数は `$1`=マウント先（固定基底配下の検証済み名で、mountinfo の 8 進エスケープを含まない）・
/// `$2`=記録したマウント ID・`$3`=nonce。mountinfo の 1 列目（マウント ID）・2 列目（親のマウント ID）・5 列目
/// （マウント先）だけを `read` で読む（awk 等に依存しない）。最上位は行順でなくマウント階層で
/// 決める（同じマウント先の他のエントリから親として参照されていないものがちょうど 1 件）。`umount` に成功したら
/// [`MOUNT_SCRIPT`] の記録と claim を消す。終了コード 203=最上位を確定できない・最上位が記録したマウントでない（外さない）。
/// 214=パスを開いた fd の `mnt_id`（`mid`。祖先の overmount で隠れた行があるとパス解決の先は別のマウントになる）が
/// 記録値と一致しない、または読めない（外さず、記録も消さない。#2973・SEC-1・WIN-1）。
/// それ以外は `umount` の終了コード（[`MOUNT_SCRIPT`] と同じ理由で、`umount(8)` の終了コード・シグナル終了と
/// 重ならない 200 番台に置く）。ゲストの前提は既定ディストリ（Ubuntu）の `/bin/sh`（dash）・util-linux の `flock`・
/// `umount`・fdinfo の `mnt_id:` 行（Linux 3.15 以降。busybox 系は未検証）。残る窓（`mid` の fd を閉じてから `umount` まで）に同じマウント先へマウントできるのは
/// ゲスト内の root（CAP_SYS_ADMIN）に限られ、[`MOUNT_SCRIPT`] と同じく信頼境界の内側として扱う。
/// 照合と `umount` は [`MOUNT_SCRIPT`] と同じマウント先ごとのロック（`/run/fandhe/lock.<名前>` の `flock`）の下で
/// 行い、取り下げられた [`MOUNT_SCRIPT`] 自身の後始末と同時に同じマウント先を外さない（ロックを取れなければ 207 で
/// 外さずに終え、呼び出し側は未解除として扱う）。
const UMOUNT_SCRIPT: &str = concat!(
    "set -u; ",
    mnt_id_sh!(),
    "command -v flock > /dev/null || exit 207; exec 9> \"/run/fandhe/lock.${1##*/}\"; w=0; ",
    "until flock -n 9; do w=$((w + 1)); [ \"$w\" -le 100 ] || exit 207; sleep 0.1; done; ",
    "ids=; pars=; ",
    "while read -r id par _ _ mp _; do if [ \"$mp\" = \"$1\" ]; then ids=\"$ids $id\"; pars=\"$pars $par\"; fi; ",
    "done < /proc/self/mountinfo; ",
    "top=; n=0; for i in $ids; do case \" $pars \" in *\" $i \"*) ;; *) top=$i; n=$((n + 1)) ;; esac; done; ",
    "[ \"$n\" = 1 ] && [ \"$top\" = \"$2\" ] || exit 203; ",
    "[ \"$(mid \"$1\")\" = \"$2\" ] || exit 214; ",
    "umount \"$1\" || exit $?; rm -f -- \"/run/fandhe/$3\" || exit 213; ",
    "for d in \"/run/fandhe/$3.claim\" \"/run/fandhe/$3.done\"; do ",
    "rmdir -- \"$d\" 2>/dev/null || [ ! -e \"$d\" ] && [ ! -L \"$d\" ] || exit 213; done; exit 0"
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
    let mut tops = at.iter().filter(|e| {
        !at.iter()
            .any(|o| o.parent_id == e.mount_id && o.mount_id != e.mount_id)
    });
    match (tops.next(), tops.next()) {
        (Some(top), None) => Some(top),
        _ => None,
    }
}

/// `guest_path` へパス解決で実際に到達するマウントを、マウント ID と親のマウント ID の木を `/` から降りて返す。
///
/// [`find_mount`] は同じパス文字列の行だけで最上位を決めるため、祖先のマウント先へ別のマウントが重ねられ
/// （overmount）、`guest_path` の行がその下に隠れていても、その行を「最上位」として返してしまう。本関数は
/// `/` の最上位から `guest_path` の要素ごとの接頭辞を順に降り、親が現在のマウントである行だけを辿る。
/// 同じマウント先に積まれたマウントは親子の連鎖で最上位まで進む。隠れた行は辿れないので `None` になる
/// （#2908・SEC-1・NET-1。mountinfo は fd を持てないホスト側の近似で、カーネルのパス解決と同じ親子関係を模す）。
///
/// `None` を返す場合: `/` の最上位を確定できない・同じ親の下に同じマウント先が複数ある・`guest_path` に
/// 到達しない（隠れている・マウント先でない）・親子関係が循環している。呼び出し側は所有を確認できない
/// ものとして扱い、外さない（fail-closed）。`guest_path` は `/` 始まりの正規形（固定基底配下の検証済み名）を前提にする。
fn find_reachable_mount<'a>(entries: &'a [MountEntry], guest_path: &str) -> Option<&'a MountEntry> {
    let mut cur = find_mount(entries, "/")?;
    // 親子の連鎖を辿る総回数の上限（行数。循環した親子関係で止まらなくなるのを防ぐ。REPAIR-5）。
    let mut budget = entries.len().saturating_add(1);
    let mut prefix = String::new();
    for part in guest_path.split('/').filter(|p| !p.is_empty()) {
        prefix.push('/');
        prefix.push_str(part);
        loop {
            let mut next = entries.iter().filter(|e| {
                e.mount_point == prefix && e.parent_id == cur.mount_id && e.mount_id != cur.mount_id
            });
            match (next.next(), next.next()) {
                (None, _) => break,
                (Some(c), None) => {
                    budget = budget.checked_sub(1)?;
                    cur = c;
                }
                _ => return None,
            }
        }
    }
    (cur.mount_point == guest_path).then_some(cur)
}

// ---- シーケンス（実行器を差し替え可能にした本体） ----

/// `wsl.exe` 相当の実行器: 引数列と stdout/stderr の上限バイト数を受け取り、タイムアウト付きで実行する。
type Exec<'a> = &'a mut dyn FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error>;

/// 回復・後始末用の実行器を選ぶ（専用の実行器があればそれ、なければ通常の実行器）。
///
/// 通常の実行器の合計期限が mount の待機で尽きても、所有の確認・取り下げ・ロールバックの `wsl.exe` 呼び出しが
/// 即 Timeout でスキップされないよう、呼び出し側（`launch_with` 等）は独立した有界期限の実行器を渡す
/// （REPAIR-5・WIN-2）。専用の実行器を持たない模擬実行器（ユニットテスト）では通常の実行器を共用する。
fn pick_recovery<'a>(recovery: &'a mut Option<Exec<'_>>, exec: Exec<'a>) -> Exec<'a> {
    match recovery {
        Some(r) => &mut **r,
        None => exec,
    }
}

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
    /// 証拠が無い（[`MOUNT_SCRIPT`] は終了済みで、mount が成立していないか新しいマウントを 1 件に特定できなかった。
    /// 記録は `none`）。
    Missing,
    /// 回復時に [`RECORD_SCRIPT`] が claim を先に取った（本呼び出しの mount は成立しておらず、以後もしない）。
    Fenced,
    /// `mount` の途中のまま確定しなかったので [`ABANDON_SCRIPT`] で取り下げた（[`MOUNT_SCRIPT`] が `mount` から
    /// 戻った時点で自分のマウントを外す。本呼び出しは所有しない）。
    Abandoned,
    /// 記録を上限回数まで読めず、取り下げもできなかった。
    Unreadable,
}

/// [`MOUNT_SCRIPT`] の標準出力・記録の中身（10 進のマウント ID 1 行）を解析する。それ以外は `None`。
///
/// 記録は 3 行（マウント ID・マウント先・コンテナ ID）になったため、最初の改行までだけを読む
/// （2 行目以降は [`parse_lookup_output`] の経路が扱う）。
fn parse_recorded_id(bytes: &[u8]) -> Option<u32> {
    let text = first_line(bytes)?.trim();
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// 記録・標準出力の最初の行（UTF-8 でなければ `None`）。
fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()?.split('\n').next()
}

/// 記録の 1 行目が `none`（自分のマウントを特定できなかった）か。
fn is_none_record(bytes: &[u8]) -> bool {
    first_line(bytes).is_some_and(|t| t.trim() == "none")
}

/// [`MOUNT_SCRIPT`] の標準出力からマウント ID を読めなかったとき（`wsl.exe` の待機タイムアウト等）に、
/// [`RECORD_SCRIPT`] で実行権の取消を兼ねてゲスト内の記録を最大 [`MAX_RECOVERY_READS`] 回読む（呼び出しごとの
/// タイムアウトで有界。REPAIR-5）。
///
/// 204（claim を先に取った）は「本呼び出しのマウントは成立しておらず、以後も成立しない」ことの確定なので
/// `Fenced`。記録が `none` なら [`MOUNT_SCRIPT`] は新しいマウントを特定できなかったので `Missing`。206（`mount` の
/// 途中）・読み取り失敗は読み直す。上限に達したら [`ABANDON_SCRIPT`] で取り下げを最大 [`MAX_RECOVERY_READS`] 回
/// 試みる（その間に完了していれば記録を読む）。取り下げが成立すれば `Abandoned`（以後の後始末はゲスト内の
/// [`MOUNT_SCRIPT`] が担う）、それもできなければ `Unreadable`（所有を確認できない）。
fn read_record(distro: &DistroName, nonce: &str, exec: Exec<'_>) -> Evidence {
    let from_record = |stdout: &[u8]| {
        if is_none_record(stdout) {
            Evidence::Missing
        } else {
            parse_recorded_id(stdout).map_or(Evidence::Unreadable, Evidence::Mine)
        }
    };
    for _ in 0..MAX_RECOVERY_READS {
        match exec(&record_argv(distro, nonce), MAX_OUTPUT_BYTES) {
            Ok(out) if out.success => return from_record(&out.stdout),
            Ok(out) if out.code == Some(EXIT_NO_RECORD) => return Evidence::Fenced,
            _ => {}
        }
    }
    for _ in 0..MAX_RECOVERY_READS {
        match exec(&abandon_argv(distro, nonce), MAX_OUTPUT_BYTES) {
            Ok(out) if out.success => return from_record(&out.stdout),
            Ok(out) if out.code == Some(EXIT_ABANDONED) => return Evidence::Abandoned,
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
    /// `None` は未確定（[`PreparedMount::mount_id`] と同じ意味）。
    mount_id: Option<u32>,
    nonce: String,
    /// 読み取り専用で要求したか（未解除として返す [`PreparedMount`] に引き継ぐ）。
    read_only: bool,
}

impl OwnedMount {
    fn to_prepared(&self) -> PreparedMount {
        PreparedMount {
            guest_path: self.guest_path.clone(),
            mount_id: self.mount_id,
            read_only: self.read_only,
            nonce: self.nonce.clone(),
        }
    }
}

/// [`MountError::unreleased`] に載せる未解除マウントの最大件数（1 回の要求の共有マウント数の上限と同じ。
/// 未解除になりうるのは本呼び出しが成立させたマウントだけなので、これを超えることはない。REPAIR-5）。
pub const MAX_UNRELEASED_MOUNTS: usize = MAX_SHARED_MOUNTS;

/// 後始末（[`rollback`]）の結果: やり直せる未解除のマウントと、所有を確かめられず外さなかった件数。
#[derive(Debug, Default)]
struct RollbackOutcome {
    /// 外せなかった・まだ確定していないマウント（[`MountError::unreleased`] に載せ、後から解除をやり直せる）。
    retry: Vec<OwnedMount>,
    /// 記録が `none` で自分のマウントを特定できず、外さなかった件数（やり直しても所有を確かめられない）。
    unconfirmed: usize,
}

impl RollbackOutcome {
    /// 後始末が完了しなかった件数。
    fn failures(&self) -> usize {
        self.retry.len() + self.unconfirmed
    }
}

/// 未解除のマウントを、そのまま [`release_virtiofs_launch`] に渡せる [`PreparedLaunch`] にまとめる（無ければ `None`）。
fn unreleased_launch(
    distro: &DistroName,
    failed: &[OwnedMount],
    transport: Option<SharedTransport>,
) -> Option<PreparedLaunch> {
    if failed.is_empty() {
        return None;
    }
    Some(PreparedLaunch {
        distro: distro.clone(),
        mounts: failed
            .iter()
            .take(MAX_UNRELEASED_MOUNTS)
            .map(OwnedMount::to_prepared)
            .collect(),
        transport,
        warning: None,
    })
}

/// 共有マウントの準備・起動・解除の失敗（構造化エラーと、解除できずに残ったマウントの所有情報）。
///
/// 後始末（ロールバック・解除）で外せなかったマウントがあれば [`MountError::unreleased`] に載せる。これは
/// そのまま [`release_virtiofs_launch`] に渡して後始末をやり直せる（マウント先・マウント ID・記録の nonce を持つ。
/// 件数は [`MAX_UNRELEASED_MOUNTS`] 以下）。取り下げた mount・記録を確定できなかった mount は、マウント ID が
/// 未確定（`None`）のまま載せ、[`release_virtiofs_launch`] がゲスト内の記録で所有を確かめてから回収する。
/// 記録の無い（mount したプロセスの証拠が無い）マウント（`mount ownership unconfirmed`）は自分のものと
/// 確定できないため載せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountError {
    error: Wsl2Error,
    unreleased: Option<PreparedLaunch>,
    /// 9P 降格の警告の分類（サイズを抑えるため分類のみ保持し、固定文言は取得時に復元する）。
    warning: Option<WinWarningCode>,
}

impl MountError {
    /// 機械可読なエラーコード（ERR-1）。
    pub fn code(&self) -> Wsl2ErrorCode {
        self.error.code()
    }

    /// 英語の説明（ホストパス・生出力は含まない）。
    pub fn message(&self) -> &str {
        self.error.message()
    }

    /// 構造化エラー本体。
    pub fn error(&self) -> &Wsl2Error {
        &self.error
    }

    /// 解除できずに残ったマウント（[`release_virtiofs_launch`] に渡して後始末をやり直せる）。
    pub fn unreleased(&self) -> Option<&PreparedLaunch> {
        self.unreleased.as_ref()
    }

    /// 起動ステップの失敗時に、9P へ降格していた事実を示す警告（WIN-2）。
    ///
    /// 準備が 9P で成立した後に起動ステップが失敗した場合に限り `Some` になる。既定 API
    /// （[`launch_with`]。記録先なし）でも、失敗結果から降格を確認できる。
    pub fn warning(&self) -> Option<WinWarning> {
        self.warning.map(WinWarning::new)
    }

    /// 9P 降格の警告を失敗結果に保持させる。
    fn with_warning(mut self, warning: Option<WinWarning>) -> Self {
        self.warning = warning.map(|w| w.code());
        self
    }

    /// 構造化エラー・未解除のマウント・9P 降格の警告に分解する（消費後も警告を失わない。WIN-2）。
    pub fn into_parts(self) -> (Wsl2Error, Option<PreparedLaunch>, Option<WinWarning>) {
        let warning = self.warning.map(WinWarning::new);
        (self.error, self.unreleased, warning)
    }

    /// 後始末の失敗件数を `error` のメッセージに添えて、未解除のマウントとともに返す。
    fn with_unreleased(
        error: Wsl2Error,
        distro: &DistroName,
        outcome: &RollbackOutcome,
        transport: Option<SharedTransport>,
    ) -> Self {
        Self {
            error: with_rollback_note(error, outcome),
            unreleased: unreleased_launch(distro, &outcome.retry, transport),
            warning: None,
        }
    }
}

impl From<Wsl2Error> for MountError {
    fn from(error: Wsl2Error) -> Self {
        Self {
            error,
            unreleased: None,
            warning: None,
        }
    }
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for MountError {}

/// 本呼び出しが成立させたマウントを逆順に best-effort で外す。外せなかったマウント（`owned` と同じ順）を返す。
///
/// 解除の直前に mountinfo を読み直し、マウント先の最上位エントリが記録したマウント ID と一致する場合に限り
/// `umount` する。`umount` は [`UMOUNT_SCRIPT`] がゲスト内で同じ照合をやり直してから行う（照合と解除の間に
/// 積まれた他者のマウントを外さない。不一致の終了コード 203 と、パス解決先の `mnt_id` の不一致 214 は
/// `umount` の失敗と同様に読み直して判定する）。
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
///
/// マウント ID が未確定（`None`）のものは、先に [`resolve_pending`] でゲスト内の記録を読み直す。記録の ID で
/// 所有を確かめられたものだけを上と同じ手順で外し、ゲスト内で後始末済み（209）なら完了、まだ `mount` の途中・
/// 読めないなら未確定のまま `retry` に残す。記録が `none` なら外さず `unconfirmed` に数える（fail-closed）。
fn rollback(distro: &DistroName, owned: &[OwnedMount], exec: Exec<'_>) -> RollbackOutcome {
    let mut out = RollbackOutcome::default();
    for o in owned.iter().rev() {
        let id = match o.mount_id {
            Some(id) => id,
            None => match resolve_pending(distro, &o.nonce, exec) {
                Pending::Recorded(id) => id,
                Pending::Gone => continue,
                Pending::NotAttributed => {
                    // 所有を確認できないので、マウントは外さず記録も消さない。記録を消すと、マウントが残っていても
                    // 同じ ID の再試行が「記録なし」（Gone / found=0）になり残置を検出できなくなる。解除を確認できる
                    // まで記録を保持し、再試行でも未完了（unconfirmed）として報告する（fail-closed）。
                    out.unconfirmed += 1;
                    continue;
                }
                Pending::Unresolved => {
                    out.retry.push(o.clone());
                    continue;
                }
            },
        };
        let o = OwnedMount {
            mount_id: Some(id),
            ..o.clone()
        };
        let Some(entries) = read_mountinfo_bounded(distro, exec) else {
            out.retry.push(o);
            continue;
        };
        match find_reachable_mount(&entries, &o.guest_path) {
            Some(e) if e.mount_id == id => {
                let ok = matches!(
                    exec(
                        &umount_argv(distro, &o.guest_path, id, &o.nonce),
                        MAX_OUTPUT_BYTES
                    ),
                    Ok(out) if out.success
                );
                let gone = ok
                    || read_mountinfo_bounded(distro, exec)
                        .is_some_and(|after| after.iter().all(|e| e.mount_id != id));
                if !gone {
                    out.retry.push(o);
                } else if !ok && !clear_record(distro, &o.nonce, exec) {
                    // UMOUNT_SCRIPT が記録を消す前に終わったが、マウントは外れている。記録を消せなければ未完了。
                    out.retry.push(o);
                }
            }
            _ => {
                // マウント先に無くても、記録したマウント ID が別のマウント先へ移されて残っていれば未解除。
                let still_mounted = entries.iter().any(|e| e.mount_id == id);
                if still_mounted {
                    out.retry.push(o);
                } else {
                    // 既に外れている（解除済み）ので記録も消す。消せなければ未完了として数える。
                    if !clear_record(distro, &o.nonce, exec) {
                        out.retry.push(o);
                    }
                }
            }
        }
    }
    out.retry.reverse();
    out
}

/// 未確定の記録（[`STATUS_SCRIPT`]）を読み直した結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    /// 記録にマウント ID がある（本呼び出しのマウント。外してよい）。
    Recorded(u32),
    /// 記録が `none`（自分のマウントを特定できなかった。外さない）。
    NotAttributed,
    /// 記録も claim も無い（ゲスト内の [`MOUNT_SCRIPT`] が自分のマウントを外して後始末を終えた）。
    Gone,
    /// まだ `mount` の途中、または読めない（未確定のまま残す）。
    Unresolved,
}

/// 未確定の記録を最大 [`MAX_RECOVERY_READS`] 回読み直す（呼び出しごとのタイムアウトで有界。REPAIR-5）。
fn resolve_pending(distro: &DistroName, nonce: &str, exec: Exec<'_>) -> Pending {
    for _ in 0..MAX_RECOVERY_READS {
        match exec(&status_argv(distro, nonce), MAX_OUTPUT_BYTES) {
            Ok(out) if out.success => {
                if is_none_record(&out.stdout) {
                    return Pending::NotAttributed;
                }
                return parse_recorded_id(&out.stdout)
                    .map_or(Pending::Unresolved, Pending::Recorded);
            }
            Ok(out) if out.code == Some(EXIT_GONE) => return Pending::Gone,
            // 206（mount の途中）・読み取り失敗は、次の読み取りで確定しうるので上限まで読み直す。
            Ok(out) if out.code == Some(EXIT_PENDING) => {}
            _ => {}
        }
    }
    Pending::Unresolved
}

fn with_rollback_note(e: Wsl2Error, outcome: &RollbackOutcome) -> Wsl2Error {
    let mut message = e.message().to_string();
    let failed = outcome.retry.len();
    if failed > 0 {
        message.push_str(&format!(" ({failed} rollback unmount(s) also failed)"));
    }
    if outcome.unconfirmed > 0 {
        message.push_str(&format!(
            " ({} mount(s) could not be attributed and may have been left in place)",
            outcome.unconfirmed
        ));
    }
    Wsl2Error::new(e.code(), message)
}

/// 1 件のマウント（mount）。[`MOUNT_SCRIPT`] が同じプロセス内で特定したマウント ID を所有の証拠として
/// `owned` に積む。パス検証・ディレクトリ作成・mount・特定は [`MOUNT_SCRIPT`] が 1 プロセスで行う（TOCTOU 防止）。
///
/// 所有の判定には、mount を実行したプロセス自身が作った証拠（標準出力、または `wsl.exe` の待機タイムアウト等で
/// 標準出力を失った場合はゲスト内の記録 `/run/fandhe/<nonce>`）だけを使い、別の `wsl.exe` 呼び出しでの
/// mountinfo の差分からは推定しない（他者のマウントを自分のものとみなさない）。
///
/// mount の結果ごとの扱い:
/// - [`MOUNT_SCRIPT`] の検証失敗・実行権の確保失敗・マウント先のロック待ちの打ち切り・ロック下での既存マウント
///   （200〜202・205・207・208）: `mount` を実行する前に終了しているので、そのまま返す。記録を確定できずゲスト内で
///   自分のマウントを外した（209）・外せなかった（210）場合も、所有せずにそのまま返す。
/// - 成功: 証拠のマウント ID を記録する。証拠が無ければ（新しいマウントを 1 件に特定できない）記録せず、
///   `ownership unconfirmed` の失敗を返す（fail-closed）。
/// - それ以外の失敗（`mount(8)` の終了コード・`wsl.exe` のタイムアウト・出力読み取り失敗・`wsl.exe` 自身の異常値）:
///   `mount(8)` はマウント成立後の処理でも失敗を返しうるため、終了コードだけで未成立と決めない。証拠があれば
///   `owned` に積んで元のエラーを返し、呼び出し側の [`rollback`] がマウント ID を再確認して外す。証拠が無ければ
///   外さず、マウント先に mount 前に無かったマウントが残っていれば（または確認できなければ）
///   `ownership unconfirmed` を付けて返す。記録・mountinfo の読み直しは [`MAX_RECOVERY_READS`] 回 ×
///   呼び出しごとのタイムアウトで有界（REPAIR-5）。
///
/// タイムアウト後にゲスト内の処理が遅れて動き出しても、[`RECORD_SCRIPT`] が実行権（claim）を先に取るので
/// マウントは成立しない。`mount` の途中で上限まで記録が確定しなければ（`mount(2)` が戻らない等）、
/// [`ABANDON_SCRIPT`] で取り下げ、`mount` が戻った時点でゲスト内の [`MOUNT_SCRIPT`] が自分のマウントを外す。
/// 取り下げもできなければ `ownership unconfirmed` として返す。ゲスト内のプロセス自体が外部から強制終了された
/// 場合の後始末は対象外（実機での挙動確認は未実施で追跡は #3137。REPAIR-3）。
fn mount_one(
    distro: &DistroName,
    m: &SharedMount,
    owner: Option<&OwnerId>,
    before_ids: &[u32],
    owned: &mut Vec<OwnedMount>,
    exec: Exec<'_>,
    mut recovery: Option<Exec<'_>>,
) -> Result<(), Wsl2Error> {
    let nonce = new_nonce();
    let (failure, evidence) = match exec(&mount_argv(distro, m, &nonce, owner), MAX_OUTPUT_BYTES) {
        Ok(out) => {
            // 200〜202・205・207・208 は MOUNT_SCRIPT が `mount` の前に返し、209・210 は記録を確定できずゲスト内で
            // 後始末を終えた結果（いずれも `mount(8)`・シグナル終了のコードと重ならない）。
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
                Some(EXIT_CLAIM_FAILED) => {
                    return Err(precondition("the mount record could not be claimed"));
                }
                Some(EXIT_LOCK_BUSY) => {
                    return Err(precondition(
                        "another operation on the same shared mount target is in progress, or flock is unavailable in the distribution",
                    ));
                }
                Some(EXIT_ALREADY_MOUNTED) => {
                    return Err(precondition("a shared mount target is already mounted"));
                }
                // 記録を確定できなかったので、ゲスト内で自分のマウントを外して終えた（所有しない）。
                Some(EXIT_ROLLED_BACK_IN_GUEST) => {
                    return Err(precondition(
                        "the shared mount could not be recorded and was rolled back in the distribution",
                    ));
                }
                // 記録を確定できず、ゲスト内でも外せなかった。MOUNT_SCRIPT は記録（ID または none）を残して
                // 終わるので、未確定として積み、rollback / release_virtiofs_launch が読み直して回収する。
                Some(EXIT_GUEST_ROLLBACK_FAILED) => {
                    owned.push(OwnedMount {
                        guest_path: m.guest_path(),
                        mount_id: None,
                        nonce: nonce.clone(),
                        read_only: m.read_only,
                    });
                    return Err(precondition(
                        "the shared mount could not be recorded and was not rolled back in the distribution",
                    ));
                }
                _ => Some(step_failed("mounting the shared directory", &out)),
            };
            // 標準出力から読めなければ（想定外の出力が混ざった等）、ゲスト内の記録で確かめる。
            let evidence = match parse_recorded_id(&out.stdout) {
                Some(id) => Evidence::Mine(id),
                None => read_record(distro, &nonce, pick_recovery(&mut recovery, &mut *exec)),
            };
            (failure, evidence)
        }
        // 標準出力を失ったので、MOUNT_SCRIPT がゲスト内に残した記録を読む。
        Err(e) => (
            Some(e),
            read_record(distro, &nonce, pick_recovery(&mut recovery, &mut *exec)),
        ),
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
    let not_identified =
        || precondition("the shared mount could not be uniquely identified after mounting");
    match evidence {
        Evidence::Mine(mount_id) => {
            owned.push(OwnedMount {
                guest_path,
                mount_id: Some(mount_id),
                nonce,
                read_only: m.read_only,
            });
            failure.map_or(Ok(()), Err)
        }
        Evidence::Unreadable => Err(unconfirmed(failure.unwrap_or_else(not_identified))),
        Evidence::Abandoned => {
            // 取り下げた mount は、ゲスト内の MOUNT_SCRIPT が mount から戻った時点で外す（209）。外せなかった
            // 場合（210）は記録が残るので、未確定（マウント ID なし）として積み、rollback / release_virtiofs_launch
            // が記録を読み直して回収する。
            owned.push(OwnedMount {
                guest_path,
                mount_id: None,
                nonce,
                read_only: m.read_only,
            });
            let e = failure.unwrap_or_else(not_identified);
            Err(Wsl2Error::new(
                e.code(),
                format!("{} (the in-flight mount was abandoned)", e.message()),
            ))
        }
        Evidence::Missing | Evidence::Fenced => {
            let fresh = match &failure {
                // mount が成功を返したのに特定できなかった: マウントは残っている。
                None => None,
                Some(_) => count_fresh_mounts(
                    distro,
                    &guest_path,
                    before_ids,
                    pick_recovery(&mut recovery, &mut *exec),
                ),
            };
            if evidence == Evidence::Missing && fresh == Some(0) {
                // MOUNT_SCRIPT は終了済みで本呼び出しのマウントが残っていないと確認できたので、記録と claim を消す
                // （Fenced の claim は遅れて動き出す処理を止める柵なので残す）。マウントが残りうる間（新しい
                // マウントがある・確認できない）は `none` の記録を保持し、by-owner の回収が残置を検出できるようにする。
                let _ = clear_record(distro, &nonce, pick_recovery(&mut recovery, &mut *exec));
            }
            match failure {
                None => Err(unconfirmed(not_identified())),
                Some(e) => match fresh {
                    Some(0) => Err(e),
                    _ => Err(unconfirmed(e)),
                },
            }
        }
    }
}

/// 全マウントが「自分が成立させたマウント ID の最上位エントリ」かつ許可リストの fstype（virtiofs、方針が許せば
/// 9P）で、`nosuid`/`nodev` を持ち、読み取り専用か否かが要求と一致する（ro 要求なら ro・読み書き要求なら ro で
/// ない）ことを確認し、輸送方式と警告を決めて返す。`owned` は `req.mounts` と同順・同数。9P でも検査は緩めない。
fn verify_shared(
    req: &LaunchRequest,
    virtiofs: VirtiofsState,
    owned: &[OwnedMount],
    exec: Exec<'_>,
) -> Result<(SharedTransport, Option<WinWarning>), Wsl2Error> {
    if owned.len() != req.mounts.len() {
        return Err(precondition("the shared mount records are inconsistent"));
    }
    let Some(after) = read_mountinfo_bounded(&req.distro, exec) else {
        return Err(precondition("reading mountinfo after mounting failed"));
    };
    let mut fstypes: Vec<&str> = Vec::with_capacity(owned.len());
    for (m, o) in req.mounts.iter().zip(owned) {
        match find_reachable_mount(&after, &o.guest_path) {
            Some(e) if Some(e.mount_id) != o.mount_id => {
                return Err(precondition(
                    "a shared mount was replaced by another mount after mounting",
                ));
            }
            Some(e) if check_fstype(req.policy, &e.fstype).is_err() => {
                // ガード側で Err と確認済み。理論上到達しない `None` 側も fail-closed の拒否にする。
                return Err(check_fstype(req.policy, &e.fstype)
                    .err()
                    .unwrap_or_else(|| {
                        precondition("a shared mount has an unsupported filesystem type")
                    }));
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
            Some(e) => fstypes.push(e.fstype.as_str()),
            None => {
                return Err(precondition(
                    "the shared mount is missing or its topmost mount cannot be determined after mounting",
                ));
            }
        }
    }
    decide_transport(req.policy, virtiofs, &fstypes)
}

/// 事前判定・マウント・fstype 確認までを行う。成功時のみ [`PreparedLaunch`] を返す。
fn prepare_with_exec(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
    recovery: Option<Exec<'_>>,
) -> Result<PreparedLaunch, MountError> {
    prepare_with_exec_cancel(status, virtiofs, req, exec, recovery, &|| false)
}

/// 停止要求により起動を打ち切ったときの失敗（WIN-2。呼び出し側の SIGTERM 等。TASK-116.5）。
fn cancelled() -> Wsl2Error {
    precondition("the launch was cancelled by a shutdown request")
}

/// [`prepare_with_exec`] に打ち切り判定 `cancel` を加えたもの。
///
/// `cancel` は実行中の `wsl.exe` を中断せず、安全な境界（mountinfo の読み取り前・各マウントの着手前・
/// fstype 確認前）でだけ確認する。打ち切った場合は、それまでに所有したマウントを通常の失敗と同じ経路で
/// 巻き戻し、解除できなかったものは `unreleased` に載せる（呼び出し側が停止時の解除へ進めるようにする。
/// WIN-2・REPAIR-5）。
fn prepare_with_exec_cancel(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
    mut recovery: Option<Exec<'_>>,
    cancel: &dyn Fn() -> bool,
) -> Result<PreparedLaunch, MountError> {
    preflight(status, virtiofs, req)?;
    let distro = &req.distro;
    // 共有マウントが 0 件ならゲスト内で検証すべきものが無いため、mountinfo も読まず空の結果を返す。
    if req.mounts.is_empty() {
        return Ok(PreparedLaunch {
            distro: req.distro.clone(),
            mounts: Vec::new(),
            transport: None,
            warning: None,
        });
    }
    // 基底・マウント先の symlink 非追従検証とディレクトリ作成は mount と同じゲスト内プロセスで行う
    // （mount_one / MOUNT_SCRIPT。検証と mount を別呼び出しにすると差し替え競合が起きる）。
    // 自分が作っていないマウントは外さないため、既存のマウントがあれば何もせず拒否する
    // （mountinfo は論理パスで照合する。symlink を含むパスは MOUNT_SCRIPT が mount 前に拒否する）。
    if cancel() {
        return Err(cancelled().into());
    }
    let before = read_mountinfo(distro, &mut *exec)?;
    for m in &req.mounts {
        let target = m.guest_path();
        if before.iter().any(|e| e.mount_point == target) {
            return Err(precondition("a shared mount target is already mounted").into());
        }
    }
    let before_ids: Vec<u32> = before.iter().map(|e| e.mount_id).collect();
    let mut owned: Vec<OwnedMount> = Vec::new();
    for m in &req.mounts {
        if cancel() {
            let failed = rollback(distro, &owned, pick_recovery(&mut recovery, &mut *exec));
            return Err(MountError::with_unreleased(
                cancelled(),
                distro,
                &failed,
                None,
            ));
        }
        if let Err(e) = mount_one(
            distro,
            m,
            req.owner.as_ref(),
            &before_ids,
            &mut owned,
            &mut *exec,
            recovery.as_mut().map(|r| &mut **r as Exec<'_>),
        ) {
            let failed = rollback(distro, &owned, pick_recovery(&mut recovery, &mut *exec));
            return Err(MountError::with_unreleased(e, distro, &failed, None));
        }
    }
    if cancel() {
        let failed = rollback(distro, &owned, pick_recovery(&mut recovery, &mut *exec));
        return Err(MountError::with_unreleased(
            cancelled(),
            distro,
            &failed,
            None,
        ));
    }
    let (transport, warning) = match verify_shared(req, virtiofs, &owned, &mut *exec) {
        Ok(decided) => decided,
        Err(e) => {
            let failed = rollback(distro, &owned, pick_recovery(&mut recovery, &mut *exec));
            return Err(MountError::with_unreleased(e, distro, &failed, None));
        }
    };
    Ok(PreparedLaunch {
        distro: req.distro.clone(),
        mounts: owned.iter().map(OwnedMount::to_prepared).collect(),
        transport: Some(transport),
        warning,
    })
}

/// `wsl.exe` 相当の実行器を `program` から作る（出力上限と、全呼び出しで共有する合計期限 `timeout` を適用。
/// 個々の呼び出しには残り時間だけを渡し、複数マウントの処理でも合計が `timeout` を超えない。REPAIR-5）。
fn program_exec(
    program: &Path,
    timeout: Duration,
) -> impl FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error> + '_ {
    program_exec_from(program, timeout, Some(Instant::now() + timeout))
}

/// [`program_exec`] と同じだが、合計期限を呼び出し側が決めた時刻 `deadline` にする（検出と準備で 1 つの
/// 期限を共有するため。REPAIR-5）。
fn program_exec_until(
    program: &Path,
    deadline: Instant,
) -> impl FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error> + '_ {
    // 期限が確定しているため `timeout`（遅延起点用）は使われない。
    program_exec_from(program, Duration::ZERO, Some(deadline))
}

/// [`program_exec`] と同じだが、合計期限の起点を最初の呼び出し時にする（起動ステップ後のロールバック用。
/// 起動ステップの所要時間でロールバックの持ち時間を削らない）。
fn program_exec_lazy(
    program: &Path,
    timeout: Duration,
) -> impl FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error> + '_ {
    program_exec_from(program, timeout, None)
}

fn program_exec_from(
    program: &Path,
    timeout: Duration,
    mut deadline: Option<Instant>,
) -> impl FnMut(&[String], usize) -> Result<run::Captured, Wsl2Error> + '_ {
    move |args: &[String], max: usize| {
        let deadline = *deadline.get_or_insert_with(|| Instant::now() + timeout);
        let left = remaining_until(deadline)?;
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run::run_capture(program, &refs, &[("WSL_UTF8", "1")], left, max)
    }
}

/// `wsl.exe` のパスと `.wslconfig` の virtiofs 状態を解決する。
fn resolve_environment(
    timeout: Duration,
) -> Result<(std::path::PathBuf, VirtiofsState), Wsl2Error> {
    check_timeout(timeout)?;
    let program = wsl_exe_path()?;
    let path = wslconfig::default_path()?;
    let state = wslconfig::load(&path)?.map_or(VirtiofsState::Unset, |c| c.virtiofs_state());
    Ok((program, state))
}

/// `program` を `wsl.exe` として使い、`.wslconfig` の状態を `virtiofs` で与えて準備する。
pub(super) fn prepare_with_program(
    program: &Path,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    timeout: Duration,
) -> Result<PreparedLaunch, MountError> {
    check_timeout(timeout)?;
    // 検出と準備は 1 つの合計期限 `timeout` を共有する（検出が長引けば準備は残り時間だけで行い、
    // 足りなければマウント前に Timeout で fail-closed。呼び出し全体を要求元の期限に収めるため。REPAIR-5）。
    // 回復・ロールバックには準備とは別の有界期限を割り当てる（準備で期限を使い切っても解除の機会を失わない）。
    let deadline = Instant::now() + timeout;
    let status = detect_with_program(program, remaining_until(deadline)?)?;
    let mut exec = program_exec_until(program, deadline);
    let mut recovery = program_exec_lazy(program, timeout);
    prepare_with_exec(&status, virtiofs, req, &mut exec, Some(&mut recovery))
}

/// 共有マウントを準備する（関数名は TASK-67.4 からの互換。既定の [`TransportPolicy::PreferVirtiofs`] では
/// virtiofs が使えない場合に 9P へフォールバックする）。
///
/// `timeout` は WSL2 の検出とマウント準備（全マウント）で共有する合計期限。失敗時の所有確認・取り下げ・
/// ロールバックには別に同じ長さの期限を割り当てるため、呼び出し全体は `2 * timeout` 以内に収まる
/// （期限切れの `wsl.exe` を kill して回収する猶予を除く。REPAIR-5・WIN-2）。
///
/// 成功時は全マウントが virtiofs（方針が許せば 9P。[`PreparedLaunch::transport`]・[`PreparedLaunch::warning`]）で
/// 成立している。失敗時は本呼び出しで作ったマウントを後始末して `Err`。
/// mount がタイムアウトした等で結果が不確定な場合も、mount したゲスト内プロセスの記録（所有の証拠）で
/// 自分のマウントを特定して外す。自分のものと確認できないマウントは外さず、メッセージに
/// `mount ownership unconfirmed` を含めて返す。後始末で外せなかったマウントは [`MountError::unreleased`] に
/// 載せるので、呼び出し側はそれを [`release_virtiofs_launch`] へ渡して後始末をやり直せる。
/// 成功後のマウントの所有者は呼び出し側で、不要になったら [`release_virtiofs_launch`] で解除する。
pub fn prepare_virtiofs_launch(
    req: &LaunchRequest,
    timeout: Duration,
) -> Result<PreparedLaunch, MountError> {
    prepare_virtiofs_launch_with_recorder(req, timeout, &NoopWinOpRecorder)
}

/// [`prepare_virtiofs_launch`] の計装版（全体の成否と所要時間を 1 件記録する。REPAIR-4）。
pub fn prepare_virtiofs_launch_with_recorder(
    req: &LaunchRequest,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
) -> Result<PreparedLaunch, MountError> {
    let prepared = record_win_op(recorder, WinOpKind::Wsl2MountShared, || {
        let (program, state) = resolve_environment(timeout)?;
        prepare_with_program(&program, state, req, timeout)
    })?;
    emit_warning(&prepared, recorder);
    Ok(prepared)
}

/// 準備に成功した結果に警告（9P フォールバック）があれば記録先へちょうど 1 回渡す（TASK-67.5・WIN-2）。
fn emit_warning(prepared: &PreparedLaunch, recorder: &dyn WinOpRecorder) {
    if let Some(w) = prepared.warning {
        recorder.record_win_warning(&w);
    }
}

/// 準備済みマウントを逆順に best-effort で解除する（マウント ID が一致するもの・未確定の記録で所有を確かめられた
/// ものだけ）。後始末の結果を返す。
fn release_with_exec(prepared: &PreparedLaunch, exec: Exec<'_>) -> RollbackOutcome {
    let owned: Vec<OwnedMount> = prepared
        .mounts
        .iter()
        .map(|m| OwnedMount {
            guest_path: m.guest_path.clone(),
            mount_id: m.mount_id,
            nonce: m.nonce.clone(),
            read_only: m.read_only,
        })
        .collect();
    rollback(&prepared.distro, &owned, exec)
}

/// [`prepare_virtiofs_launch`] で成立させたマウントを解除する（コンテナ停止後の後始末用）。
///
/// 解除に失敗したマウントがあれば `FAILED_PRECONDITION`（件数のみをメッセージに載せる）。外せなかった
/// マウント・まだ確定していない記録は [`MountError::unreleased`] に載せて返すので、それを再び本関数へ渡して
/// 後始末をやり直せる（件数は [`MAX_UNRELEASED_MOUNTS`] 以下）。未確定の記録（マウント ID が `None`）は
/// ゲスト内の記録を読み直し、記録の ID で所有を確かめられたものだけを外す。ゲスト内で既に外し終えていれば
/// 完了として扱い、記録が `none`（自分のマウントを特定できない）なら外さずに件数だけを報告する（fail-closed）。
///
/// `timeout` は全マウントの解除で共有する合計期限（REPAIR-5）。
pub fn release_virtiofs_launch(
    prepared: &PreparedLaunch,
    timeout: Duration,
) -> Result<(), MountError> {
    release_virtiofs_launch_with_recorder(prepared, timeout, &NoopWinOpRecorder)
}

/// [`release_virtiofs_launch`] の計装版（解除全体の成否と所要時間を [`WinOpKind::Wsl2UnmountShared`] として
/// 1 件記録する。REPAIR-4）。
pub fn release_virtiofs_launch_with_recorder(
    prepared: &PreparedLaunch,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
) -> Result<(), MountError> {
    record_win_op(recorder, WinOpKind::Wsl2UnmountShared, || {
        check_timeout(timeout)?;
        let program = wsl_exe_path()?;
        release_with_program(&program, prepared, timeout)
    })
}

/// `program` を `wsl.exe` として使う [`release_virtiofs_launch`] の本体。
pub(super) fn release_with_program(
    program: &Path,
    prepared: &PreparedLaunch,
    timeout: Duration,
) -> Result<(), MountError> {
    check_timeout(timeout)?;
    let mut exec = program_exec(program, timeout);
    let outcome = release_with_exec(prepared, &mut exec);
    if outcome.failures() == 0 {
        return Ok(());
    }
    Err(release_failure(
        &prepared.distro,
        &outcome,
        prepared.transport,
    ))
}

/// 解除の失敗（外せなかった件数と所有を確かめられなかった件数のみをメッセージに載せ、やり直せるマウントを
/// [`MountError::unreleased`] に載せる）。[`release_with_program`] と [`recover_with_exec`] で共有する。
fn release_failure(
    distro: &DistroName,
    outcome: &RollbackOutcome,
    transport: Option<SharedTransport>,
) -> MountError {
    let mut message = format!("{} unmount(s) failed", outcome.retry.len());
    if outcome.unconfirmed > 0 {
        message.push_str(&format!(
            " ({} mount(s) could not be attributed and may have been left in place)",
            outcome.unconfirmed
        ));
    }
    MountError {
        error: precondition(message),
        unreleased: unreleased_launch(distro, &outcome.retry, transport),
        warning: None,
    }
}

/// [`release_with_exec`] を [`WinOpKind::Wsl2UnmountShared`] として 1 件記録する（1 件でも解除できなければ失敗）。
fn release_recorded(
    prepared: &PreparedLaunch,
    exec: Exec<'_>,
    recorder: &dyn WinOpRecorder,
) -> RollbackOutcome {
    let timer = WinOpTimer::start(recorder, WinOpKind::Wsl2UnmountShared);
    let outcome = release_with_exec(prepared, exec);
    timer.finish_with(&if outcome.failures() == 0 {
        Ok(())
    } else {
        Err(())
    });
    outcome
}

// ---- コンテナ ID からの回収（別プロセスから。#1412） ----

/// ゲスト内で、コンテナ ID（`$1`）を所有者とする記録（`/run/fandhe/<nonce>`）だけを列挙するスクリプト。
///
/// [`prepare_virtiofs_launch`] を呼んだプロセスが解除に失敗したまま終わっても、別のプロセスが同じディストリと
/// コンテナ ID だけを手がかりに自分のマウントを見つけられるようにする（WIN-1・WIN-2・PLUG-7・#1412）。所有情報を
/// ホスト側に置かず、ゲスト内の記録を正とする（VM の再起動で記録ごと消えるため、古い記録で別のマウントを外さない）。
///
/// 読む前に `/`・`/run`・`/run/fandhe` が root 所有・他者書き込み不可・symlink でないことを [`MOUNT_SCRIPT`] と同じ
/// 基準で確かめる（`/run/fandhe` が無ければ記録は無い）。対象は名前が 16 進の nonce だけのエントリで、
/// `lock.*`・`*.tmp`・`*.claim`・`*.done` は読まない。各エントリは symlink でない通常ファイルで root 所有・
/// 他者書き込み不可のものだけを読む。所有者で絞る前に、全エントリについて「512 バイト未満で、空でない
/// ちょうど 3 行（`read` がすべて成功し 4 行目が無い）」を検証し、行の欠落・余分な行・上限での切り詰め・読み取り
/// 失敗は `bad <nonce>` で報告する（所有者が別でも形式違反は黙って落とさない。#1412）。ただし、旧形式の記録
/// （マウント ID の 10 進または `none` だけの 1 行。WSL を再起動せずに更新すると残る）は所有者を持たないため
/// `old <nonce>` で報告して読み飛ばす（`bad` にしない。他のコンテナの回収を止めない）。形式を満たし 3 行目
/// （所有者）が `$1` と一致するものを `rec <nonce> <マウント ID|none> <マウント先>` の 1 行で出力する。基準を満たさないエントリは読まずに
/// `bad <nonce>` の行で報告する（ホスト側 [`parse_lookup_output`] が改ざんとして扱い、何も外さない）。
///
/// 終了コード: 200=`/`・`/run` が不正・202=`/run/fandhe` が不正・215=走査するエントリ数が上限（4096）超過。
/// それ以外の失敗はシェルや `head` の終了コード。
const LOOKUP_SCRIPT: &str = concat!(
    "set -u; O=$1; R=/run/fandhe; ",
    "chk() { [ ! -L \"$1\" ] && [ -d \"$1\" ] || return 1; ",
    "set -- $(stat -c '%u %f' -- \"$1\"); ",
    "[ \"$1\" = 0 ] && [ $((0x$2 & 18)) -eq 0 ]; }; ",
    "fchk() { [ ! -L \"$1\" ] && [ -f \"$1\" ] || return 1; ",
    "set -- $(stat -c '%u %f' -- \"$1\"); ",
    "[ \"$1\" = 0 ] && [ $((0x$2 & 18)) -eq 0 ]; }; ",
    "chk / || exit 200; chk /run || exit 200; ",
    "[ -L \"$R\" ] || [ -e \"$R\" ] || exit 0; ",
    "chk \"$R\" || exit 202; ",
    "n=0; for f in \"$R\"/*; do ",
    "[ -e \"$f\" ] || [ -L \"$f\" ] || continue; ",
    "b=${f##*/}; case \"$b\" in *[!0-9a-f]*) continue ;; esac; ",
    "n=$((n + 1)); [ \"$n\" -le 4096 ] || exit 215; ",
    "if ! fchk \"$f\"; then printf 'bad %s\\n' \"$b\"; continue; fi; ",
    "[ \"$(stat -c %s -- \"$f\")\" -lt 512 ] || { printf 'bad %s\\n' \"$b\"; continue; }; ",
    "if { IFS= read -r a && t= && ! IFS= read -r t && [ -z \"$t\" ]; } < \"$f\" 2>/dev/null && ",
    "{ [ \"$a\" = none ] || case \"$a\" in \"\"|*[!0-9]*) false ;; *) true ;; esac; }; then ",
    "printf 'old %s\\n' \"$b\"; continue; fi; ",
    "x=; if { IFS= read -r a && IFS= read -r t && IFS= read -r o && ! IFS= read -r x ",
    "&& [ -z \"$x\" ] && [ -n \"$a\" ] && [ -n \"$t\" ] && [ -n \"$o\" ]; } < \"$f\" 2>/dev/null; then ",
    "if [ \"$o\" = \"$O\" ]; then printf 'rec %s %s %s\\n' \"$b\" \"$a\" \"$t\"; fi; ",
    "else printf 'bad %s\\n' \"$b\"; fi; ",
    "done; exit 0"
);
/// [`LOOKUP_SCRIPT`] の終了コード（走査するエントリ数が上限を超えた）。
const EXIT_TOO_MANY_RECORDS: i32 = 215;
/// [`LOOKUP_SCRIPT`] の出力として受け付ける最大行数（[`MAX_OUTPUT_BYTES`] と二重の有界化。REPAIR-5）。
const MAX_LOOKUP_LINES: usize = 4096;
/// 記録の nonce として受け付ける最大文字数（[`new_nonce`] は 56 文字）。
const MAX_NONCE_LEN: usize = 64;

fn lookup_argv(distro: &DistroName, owner: &OwnerId) -> Vec<String> {
    exec_argv(distro, &["sh", "-c", LOOKUP_SCRIPT, "sh", owner.as_str()])
}

/// [`LOOKUP_SCRIPT`] が報告した、検証前の記録 1 件（マウント先は [`GUEST_MOUNT_BASE`] 配下の検証済みの形）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredRecord {
    nonce: String,
    /// `None` は記録が `none`（自分のマウントを特定できなかった。外さない）。
    mount_id: Option<u32>,
    guest_path: String,
}

/// [`parse_lookup_output`] の結果: 形式を満たした記録と、満たさなかった行の件数。
#[derive(Debug, Default, PartialEq, Eq)]
struct LookupOutput {
    records: Vec<RecoveredRecord>,
    /// `bad` の行・形式違反・マウント先が固定基底配下の検証済み名でないもの・重複の件数。1 件でもあれば何も外さない。
    rejected: usize,
    /// `old` の行（旧形式 1 行の正常な記録）の件数。所有者を持たないので回収の対象外で、触れない。
    legacy: usize,
}

/// 記録のマウント先が `<GUEST_MOUNT_BASE>/<MountName>` の形（`..`・`/`・基底の外を含まない）か。
///
/// [`UMOUNT_SCRIPT`] はマウント先の末尾要素でロック名を決めるため、改ざんされた記録のマウント先を通すと別の
/// ロックや別のパスに作用しうる。ここで固定基底の完全一致の接頭辞と [`MountName`] の規則を必須にして防ぐ。
fn parse_record_target(target: &str) -> Option<String> {
    let name = target.strip_prefix(GUEST_MOUNT_BASE)?.strip_prefix('/')?;
    MountName::parse(name).ok()?;
    Some(target.to_string())
}

/// [`LOOKUP_SCRIPT`] の出力を解析する（ゲストの出力は untrusted。上限を超える行数は `RESOURCE_EXHAUSTED`、UTF-8
/// でなければ `DATA_LOSS`、記録の件数が [`MAX_SHARED_MOUNTS`] を超えても `RESOURCE_EXHAUSTED`）。
fn parse_lookup_output(bytes: &[u8]) -> Result<LookupOutput, Wsl2Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Wsl2Error::new(
            Wsl2ErrorCode::DataLoss,
            "guest mount record listing is not valid UTF-8",
        )
    })?;
    let mut out = LookupOutput::default();
    for (n, line) in text.lines().enumerate() {
        if n >= MAX_LOOKUP_LINES {
            return Err(Wsl2Error::new(
                Wsl2ErrorCode::ResourceExhausted,
                "guest mount record listing exceeds the line limit",
            ));
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let rec = match fields.as_slice() {
            ["old", nonce] if parse_nonce(nonce) => {
                out.legacy += 1;
                continue;
            }
            ["rec", nonce, id, target] => parse_record(nonce, id, target),
            _ => None,
        };
        match rec {
            Some(r)
                if !out
                    .records
                    .iter()
                    .any(|o| o.nonce == r.nonce || o.guest_path == r.guest_path) =>
            {
                if out.records.len() >= MAX_SHARED_MOUNTS {
                    return Err(Wsl2Error::new(
                        Wsl2ErrorCode::ResourceExhausted,
                        "too many guest mount records for one owner",
                    ));
                }
                out.records.push(r);
            }
            _ => out.rejected += 1,
        }
    }
    Ok(out)
}

fn parse_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_LEN
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parse_record(nonce: &str, id: &str, target: &str) -> Option<RecoveredRecord> {
    if !parse_nonce(nonce) {
        return None;
    }
    let mount_id = if id == "none" {
        None
    } else {
        Some(parse_recorded_id(id.as_bytes())?)
    };
    Some(RecoveredRecord {
        nonce: nonce.to_string(),
        mount_id,
        guest_path: parse_record_target(target)?,
    })
}

/// 記録がゲストの現在のマウント状態と矛盾しないか（改ざん・差し替えの検出）。
///
/// マウント ID が確定している記録は、マウント先の最上位のマウント ID が記録と一致するか、マウント先にも
/// マウント ID にも対応するマウントがどこにも無い（外れ済みの古い記録。後始末で記録だけを消す）ときに限り
/// 矛盾なしとする。他者のマウントが積まれている・マウント先を確定できない・記録のマウント ID が別の場所に
/// ある場合は矛盾として扱い、何も外さない（fail-closed）。`none` の記録は外さないので常に矛盾なし。
fn record_matches_mounts(rec: &RecoveredRecord, entries: &[MountEntry]) -> bool {
    let Some(id) = rec.mount_id else {
        return true;
    };
    match find_reachable_mount(entries, &rec.guest_path) {
        Some(top) => top.mount_id == id,
        None => {
            !entries.iter().any(|e| e.mount_point == rec.guest_path)
                && !entries.iter().any(|e| e.mount_id == id)
        }
    }
}

fn lookup_failed(out: &run::Captured) -> Wsl2Error {
    match out.code {
        Some(EXIT_PARENT_BAD) => {
            precondition("the mount base parent directory is missing or unsafe")
        }
        Some(EXIT_PATH_UNSAFE) => precondition(
            "a mount path component is not a root-owned, non-writable directory (symlinks are rejected)",
        ),
        Some(EXIT_TOO_MANY_RECORDS) => Wsl2Error::new(
            Wsl2ErrorCode::ResourceExhausted,
            "too many guest mount records to scan",
        ),
        _ => step_failed("looking up mount records", out),
    }
}

/// [`release_container_mounts`] の結果（拡張できる構造。真偽値だけにしない）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryReport {
    /// コンテナ ID に対応する、検証を通った記録の件数（0 なら回収するものが無かった）。
    pub found: usize,
    /// そのうち解除（外れ済みの記録の掃除を含む）を完了した件数。`Ok` のときは `found` と等しい。
    pub released: usize,
}

/// 検証つきの回収の本体（実行器を差し替え可能にしたもの）。
///
/// 手順: ① [`LOOKUP_SCRIPT`] でコンテナ ID の記録を引く ② 形式・マウント先を検証（1 件でも改ざんがあれば何も外さず
/// `FAILED_PRECONDITION`）③ mountinfo と照合（矛盾があれば同様に何も外さない）④ 検証を通った記録だけを、
/// [`release_virtiofs_launch`] と同じ [`rollback`]（`UMOUNT_SCRIPT` がロックの下でマウント ID を再照合する 1 本の
/// 経路）で解除する。umount の経路は増やさない。`exec` の合計期限は検索・mountinfo・各 umount で共有する
/// （REPAIR-5）。[`PreparedLaunch`] は組み立てず、crate 内の [`OwnedMount`] から直接解除する。
fn recover_with_exec(
    distro: &DistroName,
    owner: &OwnerId,
    exec: Exec<'_>,
) -> Result<RecoveryReport, MountError> {
    let out = exec(&lookup_argv(distro, owner), MAX_OUTPUT_BYTES)?;
    if !out.success {
        return Err(lookup_failed(&out).into());
    }
    let parsed = parse_lookup_output(&out.stdout)?;
    if parsed.rejected > 0 {
        return Err(precondition(format!(
            "{} guest mount record(s) failed validation; nothing was released",
            parsed.rejected
        ))
        .into());
    }
    if parsed.records.is_empty() {
        return Ok(RecoveryReport::default());
    }
    let entries = read_mountinfo(distro, &mut *exec)?;
    let mismatched = parsed
        .records
        .iter()
        .filter(|r| !record_matches_mounts(r, &entries))
        .count();
    if mismatched > 0 {
        return Err(precondition(format!(
            "{mismatched} guest mount record(s) do not match the mounted state; nothing was released"
        ))
        .into());
    }
    let owned: Vec<OwnedMount> = parsed
        .records
        .iter()
        .map(|r| OwnedMount {
            guest_path: r.guest_path.clone(),
            mount_id: r.mount_id,
            nonce: r.nonce.clone(),
            // 記録は読み取り専用かを持たない。未解除として返す情報にだけ使う値で、解除の判断には使わない。
            read_only: false,
        })
        .collect();
    // 解除段階で期限切れ（`wsl.exe` のタイムアウト）があったかを実行器の結果から拾う（REPAIR-5・ERR-1）。
    let mut timed_out = false;
    let outcome = rollback(distro, &owned, &mut |argv, max| {
        let r = exec(argv, max);
        if matches!(&r, Err(e) if e.code() == Wsl2ErrorCode::Timeout) {
            timed_out = true;
        }
        r
    });
    if outcome.failures() == 0 {
        return Ok(RecoveryReport {
            found: owned.len(),
            released: owned.len(),
        });
    }
    let mut failure = release_failure(distro, &outcome, None);
    if timed_out {
        // 公開 API の約束どおり期限切れは `TIMEOUT` のまま返す。未解除の情報とメッセージは保つ。
        failure.error = Wsl2Error::new(Wsl2ErrorCode::Timeout, failure.error.message());
    }
    Err(failure)
}

/// `program` を `wsl.exe` として使う [`release_container_mounts`] の本体（結合試験用の `wsl2::test_support` から使う）。
pub(super) fn recover_with_program(
    program: &Path,
    distro: &DistroName,
    owner: &OwnerId,
    timeout: Duration,
) -> Result<RecoveryReport, MountError> {
    check_timeout(timeout)?;
    let mut exec = program_exec(program, timeout);
    recover_with_exec(distro, owner, &mut exec)
}

/// コンテナ ID `owner` が所有する共有マウントを、作成したプロセスとは別のプロセスから検証つきで回収する
/// （WIN-1・WIN-2・PLUG-7・REPAIR-5・#1412）。
///
/// [`LaunchRequest::with_owner`] で ID を付けて準備したマウントは、ゲスト内の記録にコンテナ ID とマウント先が
/// 残る。[`PreparedLaunch`] を失った（作成したプロセスが解除に失敗したまま終わった等）場合でも、同じ `distro` と
/// `owner` だけを手がかりに、記録を検証してから自分のマウントだけを外す。別のコンテナ ID のマウントと記録には
/// 触れない。起動時の一括解除はしない。
///
/// - 記録が 1 件も無い: `Ok`（[`RecoveryReport::found`] が 0。呼び出し側が「回収するものが無い」と判断できる）。
/// - 記録が改ざんされている（symlink・root 以外の所有・不正なマウント先・形式違反・マウント ID の不一致）:
///   `FAILED_PRECONDITION`。どれが正しいか分からない状態で部分的に解除しないため、同じ ID の他の記録も外さない。
///   同じ nonce・同じマウント先を主張する重複した記録も改ざんとして扱う（古い記録と新しい記録が同じマウント先に
///   並ぶ場合は手動で片方を消すまで回収できない。fail-closed）。
/// - 解除に失敗: `FAILED_PRECONDITION`（件数のみ）。外せなかったマウントは [`MountError::unreleased`] に載せる。
/// - 期限切れ: `TIMEOUT`。`timeout` は検索・mountinfo の読み取り・各 umount で共有する合計期限。解除段階で
///   期限切れになった場合も `TIMEOUT` のまま返し、未解除のマウントは [`MountError::unreleased`] に載せる。
///
/// # 未実装範囲（REPAIR-3）
///
/// 本関数の呼び出し側（`fandhe-container-plugin-windows` の stop、または起動役の delete）への接続は未実装。
/// 回収の主体の決定は `docs/design/windows-execution-layout.md` の論点 4（#2230・オーナー承認待ち）にあり、
/// 承認後の別 issue で接続する。ID を付けずに準備したマウントは本関数では引けない。
pub fn release_container_mounts(
    distro: &DistroName,
    owner: &OwnerId,
    timeout: Duration,
) -> Result<RecoveryReport, MountError> {
    release_container_mounts_with_recorder(distro, owner, timeout, &NoopWinOpRecorder)
}

/// [`release_container_mounts`] の計装版（全体の成否と所要時間を [`WinOpKind::Wsl2UnmountShared`] として 1 件記録する。
/// REPAIR-4）。
pub fn release_container_mounts_with_recorder(
    distro: &DistroName,
    owner: &OwnerId,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
) -> Result<RecoveryReport, MountError> {
    record_win_op(recorder, WinOpKind::Wsl2UnmountShared, || {
        check_timeout(timeout)?;
        let program = wsl_exe_path()?;
        recover_with_program(&program, distro, owner, timeout)
    })
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

/// 準備の結果で計測を確定し、成功なら `start` を呼ぶ。`start` が失敗したら準備済みマウントを解除して返す
/// （ロールバック。解除は [`WinOpKind::Wsl2UnmountShared`] として記録する）。
fn finish_launch<T>(
    prepared: Result<PreparedLaunch, MountError>,
    timer: WinOpTimer<'_>,
    exec: Exec<'_>,
    recorder: &dyn WinOpRecorder,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    timer.finish_with(&prepared);
    let prepared = prepared?;
    // 9P フォールバックの警告は start の成否によらず起動前に 1 回通知する（起動は継続する。WIN-2）。
    emit_warning(&prepared, recorder);
    match start(&prepared) {
        Ok(value) => Ok(Launched { value, prepared }),
        Err(e) => {
            let failed = release_recorded(&prepared, exec, recorder);
            Err(
                MountError::with_unreleased(e, &prepared.distro, &failed, prepared.transport)
                    .with_warning(prepared.warning),
            )
        }
    }
}

/// 模擬実行器で [`launch_with_recorder`] と同じ流れを通す（ユニットテスト用）。
#[cfg(test)]
fn launch_with_exec<T>(
    status: &Wsl2Status,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    exec: Exec<'_>,
    recorder: &dyn WinOpRecorder,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    let timer = WinOpTimer::start(recorder, WinOpKind::Wsl2MountShared);
    let prepared = prepare_with_exec(status, virtiofs, req, &mut *exec, None);
    finish_launch(prepared, timer, exec, recorder, start)
}

/// 準備（事前判定・マウント・fstype 確認）に成功した場合に限り `start` を呼ぶ。
///
/// 準備失敗時は `start` を呼ばずに `Err` を返す。`start` が `Err` を返した場合は準備済みマウントを
/// 解除してから `Err` を返す（外せなかったマウントは [`MountError::unreleased`] に載せる）。`start` が `Ok` の場合
/// マウントは呼び出し側（TASK-116）の所有となり、
/// 戻り値の [`Launched::prepared`] を停止時に [`release_virtiofs_launch`] へ渡して解除する。`start` の中身
/// （ゲスト内のコンテナランタイム起動）は TASK-116 が注入する。
///
/// 記録先を持たないため、9P 降格の警告（WIN-2）は成功時は [`PreparedLaunch::warning`]、
/// `start` 失敗時は [`MountError::warning`] から確認する。
///
/// `timeout` は WSL2 の検出とマウント準備で共有する合計期限。準備失敗時の回復と `start` 失敗時の
/// ロールバックには別に同じ長さの期限を割り当てるため、`start` の所要時間を除く合計は `2 * timeout` 以内
/// （期限切れの `wsl.exe` を kill して回収する猶予を除く。REPAIR-5・WIN-2）。`start` 自体の期限は
/// 呼び出し側が持つ。
pub fn launch_with<T>(
    req: &LaunchRequest,
    timeout: Duration,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    launch_with_recorder(req, timeout, &NoopWinOpRecorder, start)
}

/// [`launch_with`] の計装版（REPAIR-4）。準備（環境の解決を含む）を [`WinOpKind::Wsl2MountShared`]、
/// 起動ステップ失敗時のロールバックを [`WinOpKind::Wsl2UnmountShared`] としてそれぞれ 1 件記録する
/// （起動ステップ自体は記録しない）。
pub fn launch_with_recorder<T>(
    req: &LaunchRequest,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    launch_cancellable_with_recorder(req, timeout, recorder, &|| false, start)
}

/// [`launch_with_recorder`] に打ち切り判定 `cancel` を加えたもの（TASK-116.5・WIN-2・REPAIR-5）。
///
/// `cancel` が `true` を返すと、検出前・各マウントの着手前・fstype 確認前・`start` 呼び出し前の
/// 安全な境界で起動を打ち切り、所有済みのマウントを巻き戻す（解除できなければ [`MountError::unreleased`]）。
/// 実行中の `wsl.exe` 呼び出しは中断しない。SIGTERM を受けた plugin が、終了猶予内に解除へ進むために使う。
pub fn launch_cancellable_with_recorder<T>(
    req: &LaunchRequest,
    timeout: Duration,
    recorder: &dyn WinOpRecorder,
    cancel: &dyn Fn() -> bool,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    let timer = WinOpTimer::start(recorder, WinOpKind::Wsl2MountShared);
    // 環境の解決に失敗した場合は timer の Drop が Failure を記録する。
    let (program, state) = resolve_environment(timeout)?;
    launch_with_program_timed(
        (&program, state),
        req,
        timeout,
        recorder,
        timer,
        cancel,
        start,
    )
}

/// `program` を `wsl.exe` として使い、`.wslconfig` の状態を `virtiofs` で与える [`launch_with`]
/// （結合試験用の `wsl2::test_support` からのみ使う。計測はしない）。
#[cfg(feature = "wsl2-test-support")]
pub(super) fn launch_with_program<T>(
    program: &Path,
    virtiofs: VirtiofsState,
    req: &LaunchRequest,
    timeout: Duration,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    let recorder = &NoopWinOpRecorder;
    let timer = WinOpTimer::start(recorder, WinOpKind::Wsl2MountShared);
    launch_with_program_timed(
        (program, virtiofs),
        req,
        timeout,
        recorder,
        timer,
        &|| false,
        start,
    )
}

fn launch_with_program_timed<'r, T>(
    (program, virtiofs): (&Path, VirtiofsState),
    req: &LaunchRequest,
    timeout: Duration,
    recorder: &'r dyn WinOpRecorder,
    timer: WinOpTimer<'r>,
    cancel: &dyn Fn() -> bool,
    start: impl FnOnce(&PreparedLaunch) -> Result<T, Wsl2Error>,
) -> Result<Launched<T>, MountError> {
    // 検出と準備は 1 つの合計期限 `timeout` を共有する（検出が長引けば準備は残り時間だけで行い、
    // 足りなければマウント前に Timeout で fail-closed。呼び出し全体を要求元の期限に収めるため）。
    // 回復・ロールバックには準備とは別に `timeout` を割り当て、起点は最初の回復系呼び出し時にする
    // （準備で期限を使い切っても所有確認・取り下げ・解除の機会を失わない。解除できなければ
    // `MountError::unreleased` で呼び出し側へ返る。起動ステップ失敗時のロールバックも同じ実行器を使う。
    // REPAIR-5・WIN-2）。
    let deadline = Instant::now() + timeout;
    let mut exec = program_exec_until(program, deadline);
    let mut rollback_exec = program_exec_lazy(program, timeout);
    let prepared = (|| -> Result<PreparedLaunch, MountError> {
        check_timeout(timeout)?;
        if cancel() {
            return Err(cancelled().into());
        }
        let status = detect_with_program(program, remaining_until(deadline)?)?;
        prepare_with_exec_cancel(
            &status,
            virtiofs,
            req,
            &mut exec,
            Some(&mut rollback_exec),
            cancel,
        )
    })();
    // 準備後・ゲスト起動前の境界でも打ち切る（起動失敗と同じ経路で準備済みマウントを巻き戻す）。
    finish_launch(prepared, timer, &mut rollback_exec, recorder, |p| {
        if cancel() {
            return Err(cancelled());
        }
        start(p)
    })
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

    /// virtiofs 必須（フォールバックなし）の要求。TASK-67.4 の厳格動作を確かめるテストで使う。
    fn req_strict(mounts: Vec<SharedMount>) -> LaunchRequest {
        req(mounts).with_transport_policy(TransportPolicy::RequireVirtiofs)
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
            // 既定（PreferVirtiofs）は未有効でも通す。厳格方針では拒否する。
            assert!(preflight(&ok_status(), s, &r).is_ok());
            let rs = req_strict(vec![sm("C:\\a", "a", false)]);
            let e = preflight(&ok_status(), s, &rs).unwrap_err();
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
            let v = mount_argv(&d, m, "00ff", None);
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
                "00ff".to_string(),
                ".".to_string()
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
            "mkdir -- \"$R/$4.claim\" 2>/dev/null || exit 205; pre=$(ids \"$T\"); rc=0; mount -t drvfs -o \"$3\" \"$1\" \"$T\" >&2 9>&- || rc=$?; "
        ));
        // マウント先ごとのロック（flock）の下で既存マウントを確かめてから claim・mount する（並行準備の直列化）。
        assert!(MOUNT_SCRIPT.contains(
            "chk \"$T\" || exit 202; command -v flock > /dev/null || exit 207; exec 9> \"$R/lock.$2\"; w=0; until flock -n 9; do w=$((w + 1)); [ \"$w\" -le 100 ] || exit 207; sleep 0.1; done; [ -z \"$(ids \"$T\")\" ] || exit 208; mkdir -- \"$R/$4.claim\""
        ));
        // 並行する準備が先にディレクトリを作っても失敗しない（作成後に chk で安全性を確かめる）。
        assert!(MOUNT_SCRIPT.contains(
            "mkdir -m 700 -- \"$R\" 2>/dev/null || [ -d \"$R\" ] || exit 201; chk \"$R\" || exit 202; "
        ));
        // 記録はゲストの umask に依らず他者書き込み不可で作る（LOOKUP_SCRIPT の検査と契約を揃える）。
        assert!(MOUNT_SCRIPT.contains("|| rc=$?; umask 077; new=; "));
        assert!(MOUNT_SCRIPT.contains(
            "[ \"$n\" = 1 ] || new=none; if printf '%s\\n%s\\n%s\\n' \"$new\" \"$T\" \"$5\" > \"$R/$4.tmp\" && mv -f -- \"$R/$4.tmp\" \"$R/$4\" && mkdir -- \"$R/$4.done\" 2>/dev/null; then [ \"$new\" = none ] || printf '%s\\n' \"$new\"; exit \"$rc\"; fi; "
        ));
        // 記録を確定できない（取り下げを含む）ときは、自分のマウントが最上位なら自分で外して終える。
        assert!(MOUNT_SCRIPT.contains(
            "x=209; if [ \"$n\" = 1 ]; then if [ \"$(top \"$T\")\" = \"$new\" ] && [ \"$(mid \"$T\")\" = \"$new\" ]; then umount \"$T\" >&2 9>&- || x=210; else x=210; fi; elif [ \"$n\" != 0 ]; then x=210; fi; "
        ));
        // 210 では記録（ID または none）と .done を残し、後の release が STATUS_SCRIPT で回収できるようにする。
        assert!(MOUNT_SCRIPT.contains(
            "else printf '%s\\n%s\\n%s\\n' \"$new\" \"$T\" \"$5\" > \"$R/$4.tmp\" && mv -f -- \"$R/$4.tmp\" \"$R/$4\" || :; mkdir -- \"$R/$4.done\" 2>/dev/null || :; fi; exit \"$x\""
        ));
        assert!(
            STATUS_SCRIPT
                .ends_with("if [ -d \"/run/fandhe/$1.claim\" ]; then exit 206; fi; exit 212")
        );
        assert!(UMOUNT_SCRIPT.starts_with("set -u; "));
        assert!(UMOUNT_SCRIPT.contains(
            "command -v flock > /dev/null || exit 207; exec 9> \"/run/fandhe/lock.${1##*/}\"; "
        ));
        // #2973: パス解決先の mnt_id の照合（mid）が両スクリプトにあり、UMOUNT_SCRIPT では 203 の後・umount の前。
        assert!(UMOUNT_SCRIPT.contains(mnt_id_sh!()) && MOUNT_SCRIPT.contains(mnt_id_sh!()));
        assert!(UMOUNT_SCRIPT.contains(
            "|| exit 203; [ \"$(mid \"$1\")\" = \"$2\" ] || exit 214; umount \"$1\" || exit $?; "
        ));
        assert_eq!(UMOUNT_SCRIPT.matches("exit 214").count(), 1);
        // 試験用の参照が製品の断片と食い違わない（実 `sh` での試験は Linux のみ）。
        assert_eq!(MNT_ID_SH, mnt_id_sh!());
        assert_eq!(
            status_argv(&d, "00ff").get(9).map(String::as_str),
            Some("00ff")
        );
        assert!(
            ABANDON_SCRIPT.starts_with(
                "if mkdir -- \"/run/fandhe/$1.done\" 2>/dev/null; then exit 211; fi; "
            )
        );
        assert_eq!(
            abandon_argv(&d, "00ff").get(8).map(String::as_str),
            Some("sh")
        );
        assert_eq!(
            abandon_argv(&d, "00ff").get(9).map(String::as_str),
            Some("00ff")
        );
        assert_eq!(
            clear_argv(&d, "00ff").get(5..),
            Some(
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    CLEAR_SCRIPT.to_string(),
                    "sh".to_string(),
                    "00ff".to_string()
                ][..]
            )
        );
        // 回復時は claim を先に取って遅れての mount を止め、取れなければ記録を読む。
        assert!(RECORD_SCRIPT.contains(
            "chk \"$R\" || exit 202; if mkdir -- \"$R/$1.claim\" 2>/dev/null; then exit 204; fi; [ -e \"$R/$1\" ] || exit 206; exec cat -- \"$R/$1\""
        ));
        // / からの全要素と記録ディレクトリを検証すること・ID の照合と umount が同一スクリプト内にあること。
        assert!(
            MOUNT_SCRIPT
                .contains("chk / || exit 200; chk /mnt || exit 200; chk /run || exit 200; ")
        );
        assert!(UMOUNT_SCRIPT.contains(
            "[ \"$n\" = 1 ] && [ \"$top\" = \"$2\" ] || exit 203; [ \"$(mid \"$1\")\" = \"$2\" ] || exit 214; umount \"$1\" || exit $?; rm -f -- \"/run/fandhe/$3\" || exit 213; "
        ));
        // 記録の削除失敗は成功に丸めず非ゼロ（213）で伝える（呼び出し側が未完了として保持する）。
        assert!(UMOUNT_SCRIPT.ends_with("|| exit 213; done; exit 0"));
        assert!(
            CLEAR_SCRIPT
                .starts_with("rm -f -- \"/run/fandhe/$1\" \"/run/fandhe/$1.tmp\" || exit 213; ")
        );
        assert!(CLEAR_SCRIPT.ends_with("|| exit 213; done; exit 0"));
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
        /// ゲスト内の所有の記録（nonce → マウント ID または `none`）。
        records: std::collections::HashMap<String, String>,
        /// 記録の 2・3 行目（nonce → (マウント先, 所有者のコンテナ ID または印 `.`)）。`records` に記録がある
        /// nonce にだけ意味がある（読み手は 1 行目だけを読む既存経路と、LOOKUP_SCRIPT の模擬が使う）。
        meta: std::collections::HashMap<String, (String, String)>,
        /// LOOKUP_SCRIPT の模擬が `bad <nonce>` で報告する nonce（symlink・root 以外の所有の記録の模擬）。
        lookup_bad: Vec<String>,
        /// 検索が `old <nonce>`（旧形式 1 行の記録）として報告する nonce。
        lookup_old: Vec<String>,
        /// `Some(code)` なら LOOKUP_SCRIPT の模擬がその終了コードで失敗する。
        lookup_exit: Option<i32>,
        /// LOOKUP_SCRIPT の呼び出し回数。
        lookups: usize,
        /// ゲスト内の実行権（claim）を確保済みの nonce。
        claims: std::collections::HashSet<String>,
        /// true なら mount 呼び出しをゲスト内で実行しないまま `TIMEOUT` にし、引数を `deferred` に残す
        /// （待機をあきらめた後で処理が遅れて動き出す模擬）。
        defer_mount: bool,
        /// `defer_mount` で残した mount 呼び出しの引数。
        deferred: Option<Vec<String>>,
        /// CLEAR_SCRIPT の呼び出し回数。
        clears: usize,
        /// true なら CLEAR_SCRIPT が記録を消せず 213 で失敗する（`/run` が読み取り専用の模擬）。
        clear_fails: bool,
        /// true なら UMOUNT_SCRIPT は umount に成功するが記録を消せず 213 で終わる。
        umount_record_rm_fails: bool,
        /// 記録の読み取り回数。
        record_reads: usize,
        /// true なら記録の読み取り・取り下げを `TIMEOUT` にする。
        fail_record_read: bool,
        /// 完了（`.done`）を確定済みの nonce。
        dones: std::collections::HashSet<String>,
        /// true ならマウント先のロックを取れない（並行する準備がロックを持っている）。
        lock_busy: bool,
        /// true ならロックを取る直前に、同じマウント先へ他者のマウントが現れる。
        appear_before_lock: bool,
        /// true なら claim の後で mount が戻らないまま `TIMEOUT` にする（`pending` に残す）。
        hang_mount: bool,
        /// `hang_mount` で戻らなかった mount（nonce・マウント先・オプション）。
        pending: Option<(String, String, String)>,
        /// true なら取り下げの直前に `pending` の mount が完了する。
        complete_before_abandon: bool,
        /// true なら MOUNT_SCRIPT が記録を書けない（最初の書き込みだけ失敗し、210 での書き直しは成功する）。
        fail_record_write: bool,
        /// true なら取り下げ・記録失敗の後でゲスト内の自分のマウントを外せない（210）。
        self_umount_fails: bool,
        /// STATUS_SCRIPT の呼び出し回数。
        status_reads: usize,
        /// 取り下げ（ABANDON_SCRIPT）の呼び出し回数。
        abandon_calls: usize,
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
        /// `Some(祖先のパス)` なら UMOUNT_SCRIPT の照合の前に、その祖先へ tmpfs が overmount される
        /// （対象の行は mountinfo に残るが、パス解決では隠れる。#2973）。
        overmount_before_umount: Option<&'static str>,
        /// `Some(祖先のパス)` なら MOUNT_SCRIPT の自己後始末の前に、その祖先へ tmpfs が overmount される（#2973）。
        overmount_before_self_umount: Option<&'static str>,
        /// 親のマウント ID の明示（マウント ID → 親）。無い行は同じマウント先の直前のマウント、無ければ `/`。
        parent_override: std::collections::HashMap<u32, u32>,
        /// 直近の UMOUNT_SCRIPT の模擬の終了コード（203・214・0。#2973）。
        last_umount_exit: Option<i32>,
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
                meta: std::collections::HashMap::new(),
                lookup_bad: vec![],
                lookup_old: vec![],
                lookup_exit: None,
                lookups: 0,
                claims: std::collections::HashSet::new(),
                defer_mount: false,
                deferred: None,
                clears: 0,
                clear_fails: false,
                umount_record_rm_fails: false,
                record_reads: 0,
                fail_record_read: false,
                dones: std::collections::HashSet::new(),
                lock_busy: false,
                appear_before_lock: false,
                hang_mount: false,
                pending: None,
                complete_before_abandon: false,
                fail_record_write: false,
                self_umount_fails: false,
                status_reads: 0,
                abandon_calls: 0,
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
                overmount_before_umount: None,
                overmount_before_self_umount: None,
                parent_override: std::collections::HashMap::new(),
                last_umount_exit: None,
            }
        }

        /// 添字 `i` の行の親のマウント ID（明示があればそれ、無ければ同じマウント先の直前のマウント、無ければ `/`）。
        fn parent_of(&self, i: usize) -> u32 {
            let id = self.ids.get(i).copied().unwrap_or(0);
            if let Some(p) = self.parent_override.get(&id) {
                return *p;
            }
            self.mounts
                .iter()
                .take(i)
                .rposition(|(q, _)| Some(q) == self.mounts.get(i).map(|(p, _)| p))
                .and_then(|j| self.ids.get(j).copied())
                .unwrap_or(if i == 0 { 0 } else { 1 })
        }

        /// 祖先 `path` へ tmpfs を積む（overmount。ID を返す）。
        fn push_tmpfs(&mut self, path: &str) -> u32 {
            let id = self.next_id;
            self.mounts.push((path.to_string(), "tmpfs".to_string()));
            self.ids.push(id);
            self.opts.push("rw".into());
            self.next_id += 1;
            id
        }

        /// ゲストのパス解決の模擬: `/` から要素ごとの接頭辞を、親が現在のマウントである行だけ辿って降り、最後に
        /// 到達したマウントの ID を返す（`path` がマウント先でなくても、含むマウントの ID。fd の `mnt_id` に相当）。
        /// 製品の `find_reachable_mount` を呼ばない独立の実装（自己照合を避ける）。
        fn resolve_id(&self, path: &str) -> Option<u32> {
            let mut cur = *self.ids.first()?;
            let mut prefix = String::new();
            for part in path.split('/').filter(|p| !p.is_empty()) {
                prefix.push('/');
                prefix.push_str(part);
                while let Some(next) = (0..self.mounts.len()).find(|&i| {
                    self.mounts.get(i).is_some_and(|(p, _)| *p == prefix)
                        && self.parent_of(i) == cur
                        && self.ids.get(i) != Some(&cur)
                }) {
                    cur = *self.ids.get(next)?;
                }
            }
            Some(cur)
        }

        fn ids_at(&self, target: &str) -> Vec<u32> {
            self.mounts
                .iter()
                .zip(&self.ids)
                .filter(|((p, _), _)| p == target)
                .map(|(_, id)| *id)
                .collect()
        }

        /// 記録ファイルの中身（3 行: マウント ID または `none`・マウント先・所有者）。
        fn record_text(&self, nonce: &str) -> Option<String> {
            let id = self.records.get(nonce)?;
            let (target, owner) = self
                .meta
                .get(nonce)
                .cloned()
                .unwrap_or_else(|| (String::new(), ".".to_string()));
            Some(format!("{id}\n{target}\n{owner}\n"))
        }

        /// マウントを積む（`extra_on_mount` なら他者のマウントも積む）。
        fn land(&mut self, target: &str, opts: &str) {
            self.mounts
                .push((target.to_string(), self.mount_fstype.to_string()));
            self.ids.push(self.next_id);
            let ro = (opts.split(',').any(|o| o == "ro") && !self.ignore_ro) || self.force_ro;
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

        /// MOUNT_SCRIPT の後半の模擬: 記録を書いて `.done` を取る。取れない（取り下げ済み）・記録を書けない
        /// ときは、自分のマウントが最上位なら外して記録・claim を消し、209（外せなければ 210）を返す。
        fn finalize(&mut self, nonce: &str, target: &str, fresh: &[u32]) -> Result<String, i32> {
            let mine = match fresh {
                [m] => Some(*m),
                _ => None,
            };
            if !self.fail_record_write && self.dones.insert(nonce.to_string()) {
                let record = mine.map_or_else(|| "none".to_string(), |m| m.to_string());
                self.records.insert(nonce.to_string(), record);
                return Ok(mine.map_or_else(String::new, |m| format!("{m}\n")));
            }
            let mut code = if fresh.len() > 1 { 210 } else { 209 };
            if let Some(m) = mine {
                if let Some(anc) = self.overmount_before_self_umount {
                    self.push_tmpfs(anc);
                }
                match self.mounts.iter().rposition(|(p, _)| p == target) {
                    // 最上位の文字列照合に加え、パス解決先の mnt_id（mid）も一致するときだけ外す（#2973）。
                    Some(i)
                        if self.ids.get(i) == Some(&m)
                            && self.resolve_id(target) == Some(m)
                            && !self.self_umount_fails =>
                    {
                        self.mounts.remove(i);
                        self.ids.remove(i);
                        self.opts.remove(i);
                    }
                    _ => code = 210,
                }
            }
            if code == 209 {
                self.records.remove(nonce);
                self.claims.remove(nonce);
                self.dones.remove(nonce);
            } else {
                // 210: 記録（ID または none）を書き直し、.done を残す（記録の書き込みの失敗は最初の 1 回だけ）。
                let record = mine.map_or_else(|| "none".to_string(), |m| m.to_string());
                self.records.insert(nonce.to_string(), record);
                self.dones.insert(nonce.to_string());
            }
            Err(code)
        }

        /// `hang_mount` で戻らなかった mount が遅れて完了したことにする（MOUNT_SCRIPT の終了コードを返す）。
        fn finish_pending(&mut self) -> Option<i32> {
            let (nonce, target, opts) = self.pending.take()?;
            self.land(&target, &opts);
            let fresh = self.ids_at(&target);
            Some(self.finalize(&nonce, &target, &fresh).err().unwrap_or(0))
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
                            let parent = self.parent_of(i);
                            let o = self.opts.get(i).map_or("rw", String::as_str);
                            format!("{id} {parent} 0:{i} / {p} {o} - {t} src rw\n")
                        })
                        .collect();
                    if self.reverse_mountinfo {
                        lines.reverse();
                    }
                    ok(lines.concat())
                }
                ["sh", "-c", script, "sh", _host, name, opts, nonce, owner]
                    if *script == MOUNT_SCRIPT =>
                {
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
                    if self.defer_mount {
                        self.defer_mount = false;
                        self.deferred = Some(args.to_vec());
                        return Self::timeout();
                    }
                    if self.lock_busy {
                        return fail(EXIT_LOCK_BUSY);
                    }
                    if self.appear_before_lock {
                        self.mounts.push((target.to_string(), "tmpfs".to_string()));
                        self.ids.push(self.next_id);
                        self.opts.push("rw".into());
                        self.next_id += 1;
                    }
                    if !self.ids_at(target).is_empty() {
                        return fail(EXIT_ALREADY_MOUNTED);
                    }
                    let pre = self.ids_at(target);
                    self.mount_calls += 1;
                    let timed_out = self.timeout_mount_nth == Some(self.mount_calls);
                    if timed_out && !self.timeout_mount_lands {
                        return Self::timeout();
                    }
                    if !self.claims.insert((*nonce).to_string()) {
                        return fail(EXIT_CLAIM_FAILED);
                    }
                    self.meta.insert(
                        (*nonce).to_string(),
                        (target.to_string(), (*owner).to_string()),
                    );
                    if self.hang_mount {
                        self.pending = Some((
                            (*nonce).to_string(),
                            target.to_string(),
                            (*opts).to_string(),
                        ));
                        return Self::timeout();
                    }
                    let failed = self.fail_mount_nth == Some(self.mount_calls);
                    if !failed {
                        self.land(target, opts);
                    }
                    let fresh: Vec<u32> = self
                        .ids_at(target)
                        .into_iter()
                        .filter(|id| !pre.contains(id))
                        .collect();
                    let mut stdout = match self.finalize(nonce, target, &fresh) {
                        Ok(out) => out,
                        Err(code) => return fail(code),
                    };
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
                    // RECORD_SCRIPT の模擬: claim を先に取れたら 204、記録がまだ無ければ 206、あれば中身を出力。
                    // （ABANDON_SCRIPT は下の腕）
                    self.record_reads += 1;
                    if self.fail_record_read {
                        return Self::timeout();
                    }
                    if self.claims.insert((*nonce).to_string()) {
                        return fail_cat(EXIT_NO_RECORD);
                    }
                    match self.record_text(nonce) {
                        Some(v) => ok(v),
                        None => fail_cat(206),
                    }
                }
                ["sh", "-c", script, "sh", nonce] if *script == ABANDON_SCRIPT => {
                    // ABANDON_SCRIPT の模擬: `.done` を先に取れたら 211、取れなければ記録を出力（無ければ 206）。
                    self.abandon_calls += 1;
                    if self.fail_record_read {
                        return Self::timeout();
                    }
                    if self.complete_before_abandon {
                        self.finish_pending();
                    }
                    if self.dones.insert((*nonce).to_string()) {
                        return fail_cat(EXIT_ABANDONED);
                    }
                    match self.record_text(nonce) {
                        Some(v) => ok(v),
                        None => fail_cat(206),
                    }
                }
                ["sh", "-c", script, "sh", nonce] if *script == STATUS_SCRIPT => {
                    // STATUS_SCRIPT の模擬: 記録があれば中身、claim だけなら 206、どちらも無ければ 212。
                    self.status_reads += 1;
                    match self.record_text(nonce) {
                        Some(v) => ok(v),
                        None if self.claims.contains(*nonce) => fail_cat(EXIT_PENDING),
                        None => fail_cat(EXIT_GONE),
                    }
                }
                ["sh", "-c", script, "sh", owner] if *script == LOOKUP_SCRIPT => {
                    // LOOKUP_SCRIPT の模擬: 所有者が一致する記録を `rec <nonce> <ID|none> <マウント先>` で、
                    // 基準を満たさないエントリを `bad <nonce>` で出力する（nonce の昇順）。
                    self.lookups += 1;
                    if let Some(code) = self.lookup_exit {
                        return fail_cat(code);
                    }
                    let mut nonces: Vec<&String> = self.records.keys().collect();
                    nonces.sort();
                    let mut text = String::new();
                    for n in nonces {
                        if let Some((target, _)) = self.meta.get(n).filter(|(_, o)| o == owner) {
                            let id = self.records.get(n).map_or("none", String::as_str);
                            text.push_str(&format!("rec {n} {id} {target}\n"));
                        }
                    }
                    for n in &self.lookup_bad {
                        text.push_str(&format!("bad {n}\n"));
                    }
                    for n in &self.lookup_old {
                        text.push_str(&format!("old {n}\n"));
                    }
                    ok(text)
                }
                ["sh", "-c", script, "sh", nonce] if *script == CLEAR_SCRIPT => {
                    // CLEAR_SCRIPT の模擬: 記録・claim・done を消す。
                    self.clears += 1;
                    if self.clear_fails {
                        return fail_cat(213);
                    }
                    self.records.remove(*nonce);
                    self.claims.remove(*nonce);
                    self.dones.remove(*nonce);
                    ok(String::new())
                }
                ["sh", "-c", script, "sh", target, id, nonce] if *script == UMOUNT_SCRIPT => {
                    // UMOUNT_SCRIPT の模擬: 最上位のマウント ID が記録値と一致するときだけ外す（不一致は 203）。
                    self.umounts.push((*target).to_string());
                    if let Some(anc) = self.overmount_before_umount {
                        self.push_tmpfs(anc);
                    }
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
                        self.last_umount_exit = Some(203);
                        return fail_cat(203);
                    }
                    // パスを開いた fd の mnt_id（mid）の照合: 祖先の overmount で解決先が変われば外さない（#2973）。
                    if self.resolve_id(target).map(|v| v.to_string()).as_deref() != Some(*id) {
                        self.last_umount_exit = Some(214);
                        return fail_cat(214);
                    }
                    self.last_umount_exit = Some(0);
                    if self.umount_timeout == Some(false) {
                        return Self::timeout();
                    }
                    if let Some(i) = self.mounts.iter().rposition(|(p, _)| p == target) {
                        self.mounts.remove(i);
                        self.ids.remove(i);
                        self.opts.remove(i);
                    }
                    if self.umount_record_rm_fails {
                        return fail_cat(213);
                    }
                    self.records.remove(*nonce);
                    self.claims.remove(*nonce);
                    self.dones.remove(*nonce);
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
    fn summary(p: &PreparedLaunch) -> Vec<(&str, Option<u32>, bool)> {
        p.mounts()
            .iter()
            .map(|m| (m.guest_path.as_str(), m.mount_id, m.read_only))
            .collect()
    }

    fn drive(
        g: &mut Guest,
        r: &LaunchRequest,
        v: VirtiofsState,
    ) -> Result<PreparedLaunch, MountError> {
        prepare_with_exec(&ok_status(), v, r, &mut |a, m| g.run(a, m), None)
    }

    /// TASK-116.5・WIN-2・REPAIR-5: 打ち切り判定が 2 件目のマウント着手前に真になると、成立済みの 1 件目だけを
    /// 巻き戻して失敗を返し、2 件目には着手しない（所有情報・記録は残らない）。
    #[test]
    fn prepare_cancel_between_mounts_rolls_back_owned_only() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let calls = std::cell::Cell::new(0u32);
        // 1 回目: mountinfo 前、2 回目: a の着手前、3 回目: b の着手前。
        let cancel = || {
            calls.set(calls.get() + 1);
            calls.get() >= 3
        };
        let e = prepare_with_exec_cancel(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            None,
            &cancel,
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "the launch was cancelled by a shutdown request"
        );
        assert!(e.unreleased().is_none());
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        // Guest の初期マウント 1 件だけが残る（a は外れ、b には着手していない）。
        assert_eq!(g.mounts.len(), 1);
        assert!(g.records.is_empty() && g.claims.is_empty());
    }

    /// WIN-2: virtiofs で成立した場合のみ PreparedLaunch が返る。
    #[test]
    fn prepare_succeeds_with_virtiofs() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", true)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(p.transport(), Some(SharedTransport::Virtiofs));
        assert_eq!(p.distro().as_str(), "Ubuntu");
        assert_eq!(
            summary(&p),
            [
                ("/mnt/fandhe/a", Some(100), false),
                ("/mnt/fandhe/b", Some(101), true)
            ]
        );
        assert!(g.umounts.is_empty());
        // 所有の記録と claim は呼び出しごとの nonce で、解除するまで残る。
        let mut recorded: Vec<&str> = g.records.values().map(String::as_str).collect();
        recorded.sort_unstable();
        assert_eq!(recorded, ["100", "101"]);
        assert_eq!(g.claims.len(), 2);
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 0);
        assert!(g.records.is_empty());
        assert!(g.claims.is_empty());
    }

    /// WIN-2: 9P で成立した場合はロールバックして FAILED_PRECONDITION（暗黙に降格しない）。
    #[test]
    fn prepare_rejects_9p_and_rolls_back() {
        let mut g = Guest::new("9p");
        let r = req_strict(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
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
        // 解除した a・b の記録も、マウントが残っていないと確認できた c の記録（none）も残らない。
        assert!(g.records.is_empty() && g.claims.is_empty());
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
        let rs = req_strict(vec![sm("C:\\a", "a", false)]);
        assert!(drive(&mut g2, &rs, VirtiofsState::Unset).is_err());
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

    /// REPAIR-4: 公開の起動・解除経路も環境の解決に失敗した場合を含めて 1 件ずつ記録する
    /// （Windows 以外は `wsl.exe` を解決できず UNIMPLEMENTED）。
    #[cfg(not(windows))]
    #[test]
    fn public_launch_and_release_paths_are_instrumented() {
        use crate::instrument::WinOpOutcome::Failure;
        use crate::instrument::testing::Collect;
        let rec = Collect::default();
        let e = launch_with_recorder(&req(vec![]), Duration::from_secs(1), &rec, |_| Ok(()))
            .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Unimplemented);
        assert_eq!(rec.kinds(), [(WinOpKind::Wsl2MountShared, Failure)]);

        let mut g = Guest::new("virtiofs");
        let p = drive(
            &mut g,
            &req(vec![sm("C:\\a", "a", false)]),
            VirtiofsState::Enabled,
        )
        .unwrap();
        let rec = Collect::default();
        let e =
            release_virtiofs_launch_with_recorder(&p, Duration::from_secs(1), &rec).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Unimplemented);
        assert_eq!(rec.kinds(), [(WinOpKind::Wsl2UnmountShared, Failure)]);
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
        // 所有を確認できない（記録は none）ので、マウントが残りうる間は記録を消さない。
        assert_eq!(g.clears, 0);
        assert_eq!(g.records.len(), 1);
        assert!(g.records.values().all(|v| v == "none"));
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
        let p = prepare_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |_, _| {
                calls += 1;
                Err(Wsl2Error::new(Wsl2ErrorCode::Internal, "unexpected"))
            },
            None,
        )
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
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m)).failures();
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
            mount_id: Some(100),
            nonce: "00ff".into(),
            read_only: false,
        }];
        g.mounts.push(("/mnt/fandhe/a".into(), "virtiofs".into()));
        g.ids.push(555);
        g.opts.push("rw".into());
        let e =
            verify_shared(&r, VirtiofsState::Enabled, &owned, &mut |a, m| g.run(a, m)).unwrap_err();
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
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m)).failures();
        assert_eq!(failures, 0);
        assert_eq!(g.umounts, ["/mnt/fandhe/b"]);
        assert!(g.mounts.iter().any(|(m, _)| m == "/mnt/fandhe/a"));
        // 自分のマウントはどちらも残っていないので、記録も残らない。
        assert!(g.records.is_empty() && g.claims.is_empty());
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
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m)).failures();
        assert_eq!(failures, 1);
        assert!(g.umounts.is_empty());
        // どこにも残っていなければ解除済みとして成功扱い。
        g.mounts.remove(i);
        g.ids.remove(i);
        g.opts.remove(i);
        assert_eq!(g.records.len(), 1);
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 0);
        assert!(g.records.is_empty() && g.claims.is_empty());
    }

    /// 起動ステップが失敗したら準備済みマウントを逆順に解除する。成功時は解除しない。
    /// REPAIR-4: 準備と（起動ステップ失敗時の）解除をそれぞれ 1 件記録する。
    #[test]
    fn launch_rolls_back_mounts_when_start_fails() {
        use crate::instrument::WinOpOutcome::{Failure, Success};
        use crate::instrument::testing::Collect;
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let mut g = Guest::new("virtiofs");
        let rec = Collect::default();
        let e = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |_| Err::<(), _>(Wsl2Error::new(Wsl2ErrorCode::Internal, "start failed")),
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Internal);
        assert_eq!(e.message(), "start failed");
        assert_eq!(g.umounts, ["/mnt/fandhe/b", "/mnt/fandhe/a"]);
        assert_eq!(
            rec.kinds(),
            [
                (WinOpKind::Wsl2MountShared, Success),
                (WinOpKind::Wsl2UnmountShared, Success)
            ]
        );

        // 準備に失敗したら起動ステップを呼ばず、準備の失敗だけを 1 件記録する。
        let mut g = Guest::new("9p");
        let rec = Collect::default();
        let mut called = false;
        let rs = req_strict(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &rs,
            &mut |a, m| g.run(a, m),
            &rec,
            |_| {
                called = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!called);
        assert_eq!(rec.kinds(), [(WinOpKind::Wsl2MountShared, Failure)]);

        let mut g = Guest::new("virtiofs");
        let rec = Collect::default();
        let v = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |p| Ok(p.mounts().len()),
        )
        .unwrap();
        assert_eq!(v.value, 2);
        assert!(g.umounts.is_empty());
        assert_eq!(rec.kinds(), [(WinOpKind::Wsl2MountShared, Success)]);
        // 成功時は解除に使う準備済みマウントが戻り値で渡され、それで逆順に解除できる。
        let ids: Vec<u32> = v
            .prepared
            .mounts()
            .iter()
            .filter_map(|m| m.mount_id)
            .collect();
        assert_eq!(ids, [100, 101]);
        assert_eq!(
            release_with_exec(&v.prepared, &mut |a, m| g.run(a, m)).failures(),
            0
        );
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

    /// SEC・REPAIR-5: 通常の実行器の期限が mount の待機で尽きても、専用の回復実行器があれば所有確認と
    /// ロールバックの `wsl.exe` 呼び出しがスキップされず、成立したマウントを外す。
    #[test]
    fn prepare_recovery_uses_separate_executor_after_deadline_exhausted() {
        use std::cell::RefCell;
        let g = RefCell::new(Guest::new("virtiofs"));
        {
            let mut gm = g.borrow_mut();
            gm.timeout_mount_nth = Some(1);
            gm.timeout_mount_lands = true;
        }
        let r = req(vec![sm("C:\\a", "a", false)]);
        let mut calls = 0;
        // 通常の実行器: mountinfo 読み取りと mount の 2 回まで通し、以降は期限切れとして即 Timeout を返す。
        let mut exec = |a: &[String], m: usize| {
            calls += 1;
            if calls > 2 {
                return Err(Wsl2Error::new(
                    Wsl2ErrorCode::Timeout,
                    "wsl.exe did not finish before the deadline",
                ));
            }
            g.borrow_mut().run(a, m)
        };
        let mut recovery = |a: &[String], m: usize| g.borrow_mut().run(a, m);
        let e = prepare_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut exec,
            Some(&mut recovery),
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
        assert_eq!(g.borrow().umounts, ["/mnt/fandhe/a"]);
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
        // 取り下げも上限回数で打ち切る（REPAIR-5）。
        assert_eq!(g.abandon_calls, MAX_RECOVERY_READS);
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
        assert_eq!(summary(&p), [("/mnt/fandhe/a", Some(100), false)]);
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
            let failures = release_with_exec(&p, &mut |a, m| g.run(a, m)).failures();
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
        let failures = release_with_exec(&p, &mut |a, m| g.run(a, m)).failures();
        assert_eq!(failures, 1);
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.ids, [1, 100, 101]);
    }

    /// 準備直後の `/mnt/fandhe/a`（ID 100）の祖先 `/mnt/fandhe` へ tmpfs（ID 101）を overmount した状態の模擬ゲストと
    /// 準備結果（#2973）。
    fn guest_with_hidden_mount() -> (Guest, PreparedLaunch) {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(g.push_tmpfs("/mnt/fandhe"), 101);
        (g, p)
    }

    /// 祖先の overmount の中に、同じパス文字列の別のマウント（ID 102、親は overmount の 101）を置く（#2973）。
    fn add_mount_inside_overmount(g: &mut Guest) {
        g.mounts
            .push(("/mnt/fandhe/a".to_string(), "virtiofs".to_string()));
        g.ids.push(102);
        g.opts.push("rw,nosuid,nodev".into());
        g.parent_override.insert(102, 101);
        g.next_id = 103;
    }

    fn owned_a() -> Vec<OwnedMount> {
        vec![OwnedMount {
            guest_path: "/mnt/fandhe/a".to_string(),
            mount_id: Some(100),
            nonce: "00ff".to_string(),
            read_only: false,
        }]
    }

    /// #2973・SEC-1・WIN-1: 祖先の overmount で隠れた記録のマウントは、`verify_shared` が「最上位を確定できない」で拒否する。
    #[test]
    fn sec1_2973_verify_shared_rejects_hidden_mount() {
        let (mut g, _p) = guest_with_hidden_mount();
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = verify_shared(&r, VirtiofsState::Enabled, &owned_a(), &mut |a, m| {
            g.run(a, m)
        })
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "the shared mount is missing or its topmost mount cannot be determined after mounting"
        );
        assert!(g.umounts.is_empty());
    }

    /// #2973: overmount の中に別の `/mnt/fandhe/a`（ID 102）があれば、それが到達するので「別のマウントに差し替わった」で拒否する。
    #[test]
    fn sec1_2973_verify_shared_rejects_mount_inside_overmount() {
        let (mut g, _p) = guest_with_hidden_mount();
        add_mount_inside_overmount(&mut g);
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = verify_shared(&r, VirtiofsState::Enabled, &owned_a(), &mut |a, m| {
            g.run(a, m)
        })
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "a shared mount was replaced by another mount after mounting"
        );
        assert!(g.umounts.is_empty());
    }

    /// #2973: 隠れたマウントを `release` は外さず（`UMOUNT_SCRIPT` も呼ばない）、未解除 1 件として記録を残す。
    #[test]
    fn sec1_2973_release_does_not_unmount_hidden_mount() {
        let (mut g, p) = guest_with_hidden_mount();
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 1);
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100, 101]);
        assert_eq!(
            g.records.values().map(String::as_str).collect::<Vec<_>>(),
            ["100"]
        );
        assert_eq!(g.clears, 0);
    }

    /// #2973: overmount の中の別のマウント（ID 102）を取り違えて外さず、隠れた自分のマウント（ID 100）も外さない。
    #[test]
    fn sec1_2973_release_does_not_unmount_mount_inside_overmount() {
        let (mut g, p) = guest_with_hidden_mount();
        add_mount_inside_overmount(&mut g);
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 1);
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100, 101, 102]);
        assert_eq!(g.clears, 0);
    }

    /// #2973・A1: ホストの照合を通った後でパス解決先が変わる（祖先の overmount）と、`UMOUNT_SCRIPT` は 214 で
    /// 外さず、記録も消さない。ホストは mountinfo の読み直しで ID の残存を見て未解除（retry）にする。
    #[test]
    fn sec1_2973_umount_script_refuses_when_path_resolves_elsewhere() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        g.overmount_before_umount = Some("/mnt/fandhe");
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 1);
        assert_eq!(g.last_umount_exit, Some(214));
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.ids, [1, 100, 101]);
        assert_eq!(
            g.records.values().map(String::as_str).collect::<Vec<_>>(),
            ["100"]
        );
        assert_eq!(g.clears, 0);
    }

    /// #2973・A1: 記録を確定できずゲスト内で自分のマウントを外す経路（MOUNT_SCRIPT の自己後始末）でも、パス解決先が
    /// 変わっていれば外さず 210 で終え、記録（ID）と `.done` を残す。
    #[test]
    fn sec1_2973_guest_self_cleanup_keeps_mount_when_path_resolves_elsewhere() {
        let mut g = Guest::new("virtiofs");
        g.fail_record_write = true;
        g.overmount_before_self_umount = Some("/mnt/fandhe");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "the shared mount could not be recorded and was not rolled back in the distribution (1 rollback unmount(s) also failed)"
        );
        let left = e.unreleased().unwrap();
        assert_eq!(summary(left), [("/mnt/fandhe/a", Some(100), false)]);
        assert_eq!(g.ids, [1, 100, 101]);
        assert_eq!(
            g.records.values().map(String::as_str).collect::<Vec<_>>(),
            ["100"]
        );
        assert_eq!(g.dones.len(), 1);
    }

    /// #2973・A1・A2: 実 `sh` で `mid` の断片を回す。`/` の `mnt_id` は mountinfo の `/` の ID と一致し、記録値と
    /// 違う・存在しない・ディレクトリでないパスでは出力が空（不一致）になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_2973_mnt_id_snippet_matches_mountinfo_on_real_sh() {
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let entries = parse_mountinfo(&text).unwrap();
        let root_id = find_reachable_mount(&entries, "/").unwrap().mount_id;
        let script = concat!(
            mnt_id_sh!(),
            "if [ \"$(mid \"$1\")\" = \"$2\" ]; then printf match; else printf nomatch; fi"
        );
        let run = |path: &str, id: u32| {
            let out = run_sh_args_with_deadline(
                script,
                &[path, &id.to_string()],
                Duration::from_secs(20),
            );
            assert!(out.status.success(), "{out:?}");
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run("/", root_id), "match");
        assert_eq!(run("/", root_id + 1), "nomatch");
        let missing = format!("/nonexistent-{}", std::process::id());
        assert_eq!(run(&missing, root_id), "nomatch");
        let file = std::env::temp_dir().join(format!("fandhe-mid-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let on_file = run(file.to_str().unwrap(), root_id);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(on_file, "nomatch");
        // 生の出力は 10 進の ID と完全一致する。
        let raw = run_sh_args_with_deadline(
            concat!(mnt_id_sh!(), "mid \"$1\""),
            &["/"],
            Duration::from_secs(20),
        );
        assert_eq!(String::from_utf8(raw.stdout).unwrap(), root_id.to_string());
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

    /// #2908・SEC-1・NET-1: 祖先の overmount で隠れたマウントは到達判定で `None`、文字列照合は取り違える。
    #[test]
    fn sec1_2908_hidden_mount_is_not_reachable() {
        let base = "1 0 0:1 / / rw - ext4 x rw\n\
                    10 1 0:2 / /mnt rw - tmpfs x rw\n\
                    100 10 0:3 / /mnt/fandhe/a rw - virtiofs x rw\n\
                    200 10 0:4 / /mnt/fandhe rw - tmpfs x rw\n";
        let e = parse_mountinfo(base).unwrap();
        // 文字列だけの照合は隠れた 100 を返す（旧挙動）。
        assert_eq!(
            find_mount(&e, "/mnt/fandhe/a").map(|m| m.mount_id),
            Some(100)
        );
        assert_eq!(find_reachable_mount(&e, "/mnt/fandhe/a"), None);
        // overmount の中に別のマウントがあれば、それが到達する。
        let text = format!("{base}201 200 0:5 / /mnt/fandhe/a rw - tmpfs x rw\n");
        let e = parse_mountinfo(&text).unwrap();
        assert_eq!(
            find_reachable_mount(&e, "/mnt/fandhe/a").map(|m| m.mount_id),
            Some(201)
        );
    }

    /// #2908: 到達判定の積み重ね・兄弟・`/` の扱い。
    #[test]
    fn sec1_2908_reachable_mount_stack_and_roots() {
        let text = "102 100 0:4 / /mnt/fandhe/a rw - tmpfs x rw\n\
                    1 1 0:1 / / rw - ext4 x rw\n\
                    100 1 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(
            find_reachable_mount(&e, "/mnt/fandhe/a").map(|m| m.mount_id),
            Some(102)
        );
        // 同じ親の下に同じマウント先が 2 件: 確定できない。
        let text = "1 0 0:1 / / rw - ext4 x rw\n\
                    100 1 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n\
                    101 1 0:3 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(find_reachable_mount(&e, "/mnt/fandhe/a"), None);
        // `/` の行が無ければ到達を確定できない。
        let text = "100 1 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(find_reachable_mount(&e, "/mnt/fandhe/a"), None);
        // 循環した親子関係でも止まる。
        let text = "1 0 0:1 / / rw - ext4 x rw\n\
                    100 101 0:2 / /mnt/fandhe/a rw - virtiofs x rw\n\
                    101 100 0:3 / /mnt/fandhe/a rw - virtiofs x rw\n";
        let e = parse_mountinfo(text).unwrap();
        assert_eq!(find_reachable_mount(&e, "/mnt/fandhe/a"), None);
    }

    /// #2908: 隠れたマウントは `record_matches_mounts` で矛盾とする（`verify_shared`・`rollback` は同じ到達判定が `None` を返して
    /// 既存の拒否・未解除報告の分岐に入る）。
    #[test]
    fn sec1_2908_hidden_mount_is_a_record_mismatch() {
        let text = "1 0 0:1 / / rw - ext4 x rw\n\
                    10 1 0:2 / /mnt rw - tmpfs x rw\n\
                    100 10 0:3 / /mnt/fandhe/a rw - virtiofs x rw\n\
                    200 10 0:4 / /mnt/fandhe rw - tmpfs x rw\n";
        let entries = parse_mountinfo(text).unwrap();
        let rec = RecoveredRecord {
            nonce: "n".to_string(),
            mount_id: Some(100),
            guest_path: "/mnt/fandhe/a".to_string(),
        };
        assert!(!record_matches_mounts(&rec, &entries));
        assert!(find_reachable_mount(&entries, &rec.guest_path).is_none());
    }

    /// SEC: mountinfo の行が逆順でも、準備・解除と、他者に覆われたマウントを外さない判定が変わらない。
    #[test]
    fn prepare_and_release_do_not_depend_on_mountinfo_order() {
        let mut g = Guest::new("virtiofs");
        g.reverse_mountinfo = true;
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        let ids: Vec<u32> = p.mounts().iter().filter_map(|m| m.mount_id).collect();
        assert_eq!(ids, [100, 101]);
        // a の上に他者のマウントを積む（行は逆順で出力される）。
        g.mounts.push(("/mnt/fandhe/a".into(), "tmpfs".into()));
        g.ids.push(777);
        g.opts.push("rw".into());
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 1);
        assert_eq!(g.umounts, ["/mnt/fandhe/b"]);
        assert_eq!(g.ids, [1, 100, 777]);
    }

    /// SEC・REPAIR-5: claim の後で mount が戻らず記録が確定しなければ、上限回数で読み直しを打ち切って取り下げる。
    /// その後で mount が成立しても、ゲスト内の MOUNT_SCRIPT が自分のマウントを外し、記録も残さない。
    #[test]
    fn prepare_abandons_hung_mount_and_guest_rolls_it_back() {
        let mut g = Guest::new("virtiofs");
        g.hang_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(
            e.message(),
            "wsl.exe did not finish before the deadline (the in-flight mount was abandoned) (1 rollback unmount(s) also failed)"
        );
        assert_eq!(g.record_reads, MAX_RECOVERY_READS);
        assert_eq!(g.abandon_calls, 1);
        assert!(g.umounts.is_empty());
        // 取り下げた mount はマウント ID 未確定（None）の記録として返る。
        let left = e.unreleased().unwrap().clone();
        assert_eq!(summary(&left), [("/mnt/fandhe/a", None, false)]);
        // まだ mount の途中なら、release は何も外さず未確定のまま返す。
        let before = g.status_reads;
        let out = release_with_exec(&left, &mut |a, m| g.run(a, m));
        assert_eq!((out.retry.len(), out.unconfirmed), (1, 0));
        assert_eq!(out.retry.first().map(|o| o.mount_id), Some(None));
        assert!(g.umounts.is_empty());
        // REPAIR-5: 206 の間は上限回数まで読み直してから未確定として返す。
        assert_eq!(g.status_reads - before, MAX_RECOVERY_READS);
        // 遅れて mount が成立 → 取り下げ済みなのでゲスト内で自分のマウントを外して 209 で終わる。
        assert_eq!(g.finish_pending(), Some(EXIT_ROLLED_BACK_IN_GUEST));
        assert_eq!(g.ids, [1]);
        assert!(g.records.is_empty() && g.claims.is_empty() && g.dones.is_empty());
        // ゲスト内で後始末済みなら、返された記録の release は成功として扱う。
        assert_eq!(
            release_with_exec(&left, &mut |a, m| g.run(a, m)).failures(),
            0
        );
        assert!(g.umounts.is_empty());
    }

    /// 取り下げ後にゲスト内で自分のマウントを外せなかった（210）場合も、記録に残った ID で、返された未確定の
    /// 記録を既存の release に渡して回収できる。
    #[test]
    fn release_recovers_abandoned_mount_left_by_guest() {
        let mut g = Guest::new("virtiofs");
        g.hang_mount = true;
        g.self_umount_fails = true;
        let r = req(vec![sm("C:\\a", "a", true)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        let left = e.unreleased().unwrap().clone();
        assert_eq!(summary(&left), [("/mnt/fandhe/a", None, true)]);
        assert_eq!(g.finish_pending(), Some(EXIT_GUEST_ROLLBACK_FAILED));
        assert_eq!(g.ids, [1, 100]);
        assert_eq!(
            g.records.values().map(String::as_str).collect::<Vec<_>>(),
            ["100"]
        );
        let out = release_with_exec(&left, &mut |a, m| g.run(a, m));
        assert_eq!(out.failures(), 0);
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.ids, [1]);
        assert!(g.records.is_empty() && g.claims.is_empty() && g.dones.is_empty());
        // 準備のロールバック中は 206 のまま上限まで読み、release では 1 回目で記録の ID を得る。
        assert_eq!(g.status_reads, MAX_RECOVERY_READS + 1);
    }

    /// 取り下げの直前に mount が完了していれば、取り下げは成立せず記録の ID で所有してロールバックで外す。
    #[test]
    fn prepare_owns_mount_completed_just_before_abandon() {
        let mut g = Guest::new("virtiofs");
        g.hang_mount = true;
        g.complete_before_abandon = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert_eq!(g.ids, [1]);
        assert!(g.records.is_empty() && g.claims.is_empty() && g.dones.is_empty());
    }

    /// SEC: 同じマウント先への並行する準備はゲスト内のロックで直列化し、ロックを取れなければ mount しない。
    #[test]
    fn prepare_fails_when_same_target_is_locked() {
        let mut g = Guest::new("virtiofs");
        g.lock_busy = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("in progress"), "{}", e.message());
        assert_eq!(g.mount_calls, 0);
        assert!(g.claims.is_empty() && g.umounts.is_empty());
    }

    /// SEC: 事前確認の後でマウント先が埋まった場合は、ロックの下で検出して mount せず、他者のマウントも外さない。
    #[test]
    fn prepare_rejects_target_mounted_before_lock() {
        let mut g = Guest::new("virtiofs");
        g.appear_before_lock = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "a shared mount target is already mounted");
        assert_eq!(g.mount_calls, 0);
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100]);
    }

    /// SEC: 記録を書けなければ、MOUNT_SCRIPT 自身が自分のマウントを外して 209 で終え、所有しない。
    #[test]
    fn prepare_rolls_back_in_guest_when_record_cannot_be_written() {
        let mut g = Guest::new("virtiofs");
        g.fail_record_write = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "the shared mount could not be recorded and was rolled back in the distribution"
        );
        assert_eq!(g.ids, [1]);
        assert!(g.umounts.is_empty());
        assert!(g.records.is_empty() && g.claims.is_empty());
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

    /// REPAIR-5: 実行器の期限は全呼び出しで共有する合計期限で、使い切った後は wsl.exe を起動せず Timeout を返す。
    #[test]
    fn program_exec_deadline_is_shared_across_calls() {
        let mut exec = program_exec(Path::new("unused-wsl.exe"), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        let e = exec(&[], 16).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
    }

    /// REPAIR-5: 呼び出し側が決めた期限（検出と共有する合計期限）を過ぎていれば、wsl.exe を起動せず
    /// Timeout を返す。
    #[test]
    fn program_exec_until_rejects_calls_after_the_shared_deadline() {
        let mut exec = program_exec_until(Path::new("unused-wsl.exe"), Instant::now());
        std::thread::sleep(Duration::from_millis(20));
        let e = exec(&[], 16).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
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
        assert!(g.claims.is_empty());
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
        assert_eq!(summary(&p), [("/mnt/fandhe/a", Some(100), false)]);
        assert_eq!(g.record_reads, 1);
        assert!(g.umounts.is_empty());
    }

    /// SEC・REPAIR-5: 待機をあきらめた後でゲスト内の mount 処理が遅れて動き出しても、回復時に実行権（claim）を
    /// 先に取っているので mount せずに終わる（マウントが後から成立して残置されない）。
    #[test]
    fn deferred_mount_after_timeout_cannot_land() {
        let mut g = Guest::new("virtiofs");
        g.defer_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "wsl.exe did not finish before the deadline");
        assert_eq!(g.record_reads, 1);
        let late = g.deferred.take().unwrap();
        let out = g.run(&late, MAX_OUTPUT_BYTES).unwrap();
        assert_eq!(out.code, Some(EXIT_CLAIM_FAILED));
        assert_eq!(g.ids, [1]);
        assert!(g.umounts.is_empty());
        // 回復時に取った claim は柵として残し（消すと遅れた処理が取り直せる）、記録は作られない。
        assert_eq!(g.claims.len(), 1);
        assert!(g.records.is_empty());
        assert_eq!(g.clears, 0);
    }

    /// SEC: 記録を書けず、新しいマウントが複数あって自分のものを特定できない場合は外さず 210 で終え、
    /// 呼び出し側は残置の可能性（ownership unconfirmed）として返す。
    #[test]
    fn prepare_reports_ambiguous_mount_when_record_cannot_be_written() {
        let mut g = Guest::new("virtiofs");
        g.fail_record_write = true;
        g.extra_on_mount = true;
        let r = req(vec![sm("C:\\a", "a", false)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        // 210 の記録は none（自分のマウントを特定できない）なので、外さず件数だけを報告し、やり直し対象にもしない。
        assert_eq!(
            e.message(),
            "the shared mount could not be recorded and was not rolled back in the distribution (1 mount(s) could not be attributed and may have been left in place)"
        );
        assert_eq!(e.unreleased(), None);
        assert!(g.umounts.is_empty());
        assert_eq!(g.ids, [1, 100, 101]);
        // 所有を確認できないので記録は保持される（消すと再試行で残置を検出できない）。
        assert!(g.records.values().all(|v| v == "none"));
    }

    /// WIN-2: `decide_transport` の表（ポリシー × 設定状態 × fstype）。期待値は具体値で照合する。
    #[test]
    fn win2_decide_transport_table() {
        use crate::wslconfig::VirtiofsState as V;
        use WinWarningCode::{VirtiofsNotApplied as NA, VirtiofsNotEnabled as NE};
        let prefer = TransportPolicy::PreferVirtiofs;
        let strict = TransportPolicy::RequireVirtiofs;
        let vf = SharedTransport::Virtiofs;
        let np = SharedTransport::NineP;
        // 理由: 表の 1 行（方針・設定状態・fstype 列・期待輸送・期待警告）を型で名付けても読みやすさが
        // 増えず、この 1 テスト内でしか使わないため、clippy::type_complexity を局所的に許可する。
        #[allow(clippy::type_complexity)]
        let ok_cases: Vec<(
            TransportPolicy,
            V,
            &[&str],
            SharedTransport,
            Option<WinWarningCode>,
        )> = vec![
            (prefer, V::Enabled, &["virtiofs", "virtiofs"], vf, None),
            (prefer, V::Unset, &["virtiofs"], vf, None),
            (strict, V::Enabled, &["virtiofs"], vf, None),
            (prefer, V::Enabled, &["9p", "9p"], np, Some(NA)),
            (prefer, V::Unset, &["9p"], np, Some(NE)),
            (prefer, V::Disabled, &["9p"], np, Some(NE)),
            (prefer, V::Other, &["9p"], np, Some(NE)),
            (prefer, V::Enabled, &["virtiofs", "9p"], np, Some(NA)),
            (prefer, V::Unset, &["9p", "virtiofs"], np, Some(NE)),
        ];
        for (policy, state, types, want_t, want_w) in ok_cases {
            let (t, w) = decide_transport(policy, state, types).unwrap();
            assert_eq!(t, want_t, "{policy:?} {state:?} {types:?}");
            assert_eq!(
                w.map(|w| w.code()),
                want_w,
                "{policy:?} {state:?} {types:?}"
            );
        }
        // 厳格方針での 9P と、未知の fstype（方針によらず）は FAILED_PRECONDITION。
        let err_cases: [(TransportPolicy, &[&str]); 4] = [
            (strict, &["9p"]),
            (strict, &["virtiofs", "9p"]),
            (prefer, &["ext4"]),
            (prefer, &["virtiofs", "tmpfs"]),
        ];
        for (policy, types) in err_cases {
            let e = decide_transport(policy, V::Enabled, types).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition, "{types:?}");
        }
    }

    /// WIN-2・ERR-1: 既定方針では 9P で成立した共有を受理し、警告つきで起動を続けられる（マウントは残る）。
    #[test]
    fn win2_prepare_falls_back_to_9p_with_warning() {
        let mut g = Guest::new("9p");
        let r = req(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", true)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        assert_eq!(p.transport(), Some(SharedTransport::NineP));
        assert_eq!(p.transport().map(SharedTransport::as_str), Some("9p"));
        assert_eq!(
            p.warning().map(|w| w.code()),
            Some(WinWarningCode::VirtiofsNotApplied)
        );
        assert_eq!(
            summary(&p),
            [
                ("/mnt/fandhe/a", Some(100), false),
                ("/mnt/fandhe/b", Some(101), true)
            ]
        );
        assert!(g.umounts.is_empty());
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 0);
        assert_eq!(g.ids, [1]);

        // 設定が未有効のときは VIRTIOFS_NOT_ENABLED。
        let mut g = Guest::new("9p");
        let p = drive(&mut g, &r, VirtiofsState::Unset).unwrap();
        assert_eq!(p.transport(), Some(SharedTransport::NineP));
        assert_eq!(
            p.warning().map(|w| w.code()),
            Some(WinWarningCode::VirtiofsNotEnabled)
        );
        assert!(g.umounts.is_empty());
    }

    /// WIN-2: 設定が未有効でも実際に virtiofs で成立していれば警告なし。9P でも所有確認・オプション検査は緩めない。
    #[test]
    fn win2_fallback_keeps_verification_strict() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Unset).unwrap();
        assert_eq!(p.transport(), Some(SharedTransport::Virtiofs));
        assert_eq!(p.warning(), None);

        // 未知の fstype は既定方針でもロールバックして拒否する（fail-closed）。
        let mut g = Guest::new("ext4");
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("unsupported filesystem type"));
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);

        // 9P でも nosuid/nodev の欠落は拒否する。
        let mut g = Guest::new("9p");
        g.mounts.push(("/mnt/fandhe/a".into(), "9p".into()));
        let owned = vec![OwnedMount {
            guest_path: "/mnt/fandhe/a".into(),
            mount_id: Some(100),
            nonce: "00ff".into(),
            read_only: false,
        }];
        g.ids.push(100);
        g.opts.push("rw".into());
        let e =
            verify_shared(&r, VirtiofsState::Enabled, &owned, &mut |a, m| g.run(a, m)).unwrap_err();
        assert!(e.message().contains("nosuid or nodev"), "{}", e.message());
    }

    /// WIN-2: 共有マウントが 0 件のとき、ゲスト内を観測しないため輸送方式は未確認（`None`）で、警告も出さない。
    #[test]
    fn win2_zero_mounts_transport_follows_setting() {
        let r = req(vec![]);
        for state in [VirtiofsState::Enabled, VirtiofsState::Unset] {
            let mut g = Guest::new("virtiofs");
            let p = drive(&mut g, &r, state).unwrap();
            assert_eq!(p.transport(), None);
            assert_eq!(p.warning(), None);
            assert_eq!(g.mount_calls, 0);
        }
    }

    /// WIN-2・REPAIR-4: フォールバック時は警告がちょうど 1 件、start が呼ばれ（失敗時も警告は 1 件）、
    /// virtiofs 成功時と準備失敗時は 0 件。
    #[test]
    fn win2_launch_emits_single_warning_and_continues() {
        use crate::instrument::testing::Collect;
        let r = req(vec![sm("C:\\a", "a", false)]);

        let mut g = Guest::new("9p");
        let rec = Collect::default();
        let v = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |p| Ok(p.transport()),
        )
        .unwrap();
        assert_eq!(v.value, Some(SharedTransport::NineP));
        assert_eq!(rec.warning_codes(), [WinWarningCode::VirtiofsNotApplied]);
        assert!(g.umounts.is_empty());

        let mut g = Guest::new("9p");
        let rec = Collect::default();
        let e = launch_with_exec(
            &ok_status(),
            VirtiofsState::Unset,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |_| Err::<(), _>(Wsl2Error::new(Wsl2ErrorCode::Internal, "start failed")),
        )
        .unwrap_err();
        assert_eq!(e.message(), "start failed");
        assert_eq!(rec.warning_codes(), [WinWarningCode::VirtiofsNotEnabled]);
        // 記録先なしの既定 API でも、失敗結果から 9P 降格を確認できる。
        assert_eq!(
            e.warning(),
            Some(WinWarning::new(WinWarningCode::VirtiofsNotEnabled))
        );
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);

        let mut g = Guest::new("virtiofs");
        let rec = Collect::default();
        launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |_| Ok(()),
        )
        .unwrap();
        assert!(rec.warning_codes().is_empty());

        let mut g = Guest::new("ext4");
        let rec = Collect::default();
        launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| g.run(a, m),
            &rec,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(rec.warning_codes().is_empty());
    }

    /// 後始末（ロールバック）で外せなかったマウントは、マウント先・ID・nonce を持つ PreparedLaunch として
    /// エラーに載り、そのまま解除をやり直せる。外せた場合は載らない。
    #[test]
    fn prepare_returns_unreleased_mounts_for_retry() {
        let mut g = Guest::new("9p");
        g.umount_timeout = Some(false);
        let r = req_strict(vec![sm("C:\\a", "a", false), sm("C:\\b", "b", true)]);
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(
            e.message().ends_with("(2 rollback unmount(s) also failed)"),
            "{}",
            e.message()
        );
        let left = e.unreleased().unwrap();
        assert_eq!(left.distro().as_str(), "Ubuntu");
        assert_eq!(
            summary(left),
            [
                ("/mnt/fandhe/a", Some(100), false),
                ("/mnt/fandhe/b", Some(101), true)
            ]
        );
        // 原因が解消すれば、返された情報でそのまま後始末をやり直せる。
        g.umount_timeout = None;
        assert_eq!(
            release_with_exec(left, &mut |a, m| g.run(a, m)).failures(),
            0
        );
        assert_eq!(g.ids, [1]);
        assert!(g.records.is_empty() && g.claims.is_empty());

        // 外せた場合は未解除の情報を載せない。
        let mut g = Guest::new("9p");
        let e = drive(&mut g, &r, VirtiofsState::Enabled).unwrap_err();
        assert_eq!(e.unreleased(), None);
        let (err, left, warn) = e.into_parts();
        assert_eq!(warn, None);
        assert_eq!(err.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(left.is_none());
    }

    /// REPAIR-5: 未解除として返す件数は MAX_UNRELEASED_MOUNTS（= 共有マウント数の上限 16）以下で、
    /// 上限ちょうどの 16 件すべてが残っても欠けずに返る。
    #[test]
    fn unreleased_mounts_are_bounded() {
        assert_eq!(MAX_UNRELEASED_MOUNTS, 16);
        let mut g = Guest::new("9p");
        g.umount_timeout = Some(false);
        let mounts: Vec<_> = (0..MAX_SHARED_MOUNTS)
            .map(|i| sm(&format!("C:\\d{i}"), &format!("n{i}"), false))
            .collect();
        let e = drive(&mut g, &req_strict(mounts), VirtiofsState::Enabled).unwrap_err();
        assert!(
            e.message()
                .ends_with("(16 rollback unmount(s) also failed)")
        );
        let left = e.unreleased().unwrap();
        assert_eq!(left.mounts().len(), MAX_UNRELEASED_MOUNTS);
        assert_eq!(left.mounts().first().map(|m| m.mount_id), Some(Some(100)));
        assert_eq!(left.mounts().last().map(|m| m.mount_id), Some(Some(115)));
        // 上限を超える入力が来ても切り詰める（呼び出し側の PreparedLaunch は上限以下しか作れない）。
        let many: Vec<OwnedMount> = (0..20)
            .map(|i| OwnedMount {
                guest_path: format!("/mnt/fandhe/x{i}"),
                mount_id: Some(200 + i),
                nonce: "00ff".into(),
                read_only: false,
            })
            .collect();
        let capped =
            unreleased_launch(&distro_name(), &many, Some(SharedTransport::Virtiofs)).unwrap();
        assert_eq!(capped.mounts().len(), MAX_UNRELEASED_MOUNTS);
        assert_eq!(
            unreleased_launch(&distro_name(), &[], Some(SharedTransport::Virtiofs)),
            None
        );
    }

    /// 起動ステップ失敗時の解除で外せなかったマウントも、エラーに載せて返す。
    #[test]
    fn launch_returns_unreleased_mounts_when_rollback_fails() {
        use crate::instrument::testing::Collect;
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let rec = Collect::default();
        let start_failed = std::cell::Cell::new(false);
        let e = launch_with_exec(
            &ok_status(),
            VirtiofsState::Enabled,
            &r,
            &mut |a, m| {
                // 起動ステップの失敗後は umount（UMOUNT_SCRIPT）がタイムアウトし、マウントが残る。
                let is_umount = a.get(7).map(String::as_str) == Some(UMOUNT_SCRIPT);
                if start_failed.get() && is_umount {
                    return Err(Wsl2Error::new(Wsl2ErrorCode::Timeout, "slow"));
                }
                g.run(a, m)
            },
            &rec,
            |_| {
                start_failed.set(true);
                Err::<(), _>(Wsl2Error::new(Wsl2ErrorCode::Internal, "start failed"))
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Internal);
        assert_eq!(
            e.message(),
            "start failed (1 rollback unmount(s) also failed)"
        );
        assert_eq!(
            e.unreleased().map(summary),
            Some(vec![("/mnt/fandhe/a", Some(100), false)])
        );
    }
    // ---- コンテナ ID からの回収（#1412。WIN-1・WIN-2・PLUG-7・REPAIR-5） ----

    fn owner(s: &str) -> OwnerId {
        OwnerId::parse(s).expect("valid owner id")
    }

    /// ID 付きで準備する（返った `PreparedLaunch` は呼び出し側が捨てる前提で、模擬ゲストの状態だけが残る）。
    fn prepare_owned(g: &mut Guest, id: &str, mounts: Vec<SharedMount>) -> PreparedLaunch {
        let r = req(mounts).with_owner(owner(id));
        drive(g, &r, VirtiofsState::Enabled).expect("prepare")
    }

    /// 別プロセスからの回収（`PreparedLaunch` を持たず、ディストリとコンテナ ID だけを渡す）。
    fn recover(g: &mut Guest, id: &str) -> Result<RecoveryReport, MountError> {
        recover_with_exec(&distro_name(), &owner(id), &mut |a, m| g.run(a, m))
    }

    /// 検証失敗・不一致のメッセージ（件数だけ。パス・ID・生出力を含めない）。
    fn failed_validation(n: usize) -> String {
        format!("{n} guest mount record(s) failed validation; nothing was released")
    }

    /// WIN-2・REPAIR-2: コンテナ ID は `[A-Za-z0-9._-]` の 1〜255 バイトで、`.` / `..` を含め危険な値は拒否する。
    #[test]
    fn owner_id_accepts_and_rejects() {
        let long = "x".repeat(MAX_OWNER_ID_LEN);
        for ok in ["web", "a.b_c-1", "0", "-", "..a", long.as_str()] {
            assert_eq!(OwnerId::parse(ok).unwrap().as_str(), ok);
        }
        let too_long = "x".repeat(MAX_OWNER_ID_LEN + 1);
        for bad in [
            "",
            ".",
            "..",
            "a b",
            "a/b",
            "a\nb",
            "a$(id)",
            "コンテナ",
            too_long.as_str(),
        ] {
            let e = OwnerId::parse(bad).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument, "{bad:?}");
            assert_eq!(
                e.message(),
                "owner id must be 1-255 characters of [A-Za-z0-9._-], not '.' or '..'"
            );
        }
    }

    /// #1412: コンテナ ID は mount スクリプトの `$5` に渡り、未設定は印 `.`（実在の ID と衝突しない）。
    #[test]
    fn mount_argv_passes_owner_as_fifth_positional() {
        let d = distro_name();
        let m = sm("C:\\a", "data", false);
        let with = mount_argv(&d, &m, "00ff", Some(&owner("web")));
        assert_eq!(with.last().map(String::as_str), Some("web"));
        assert_eq!(with.len(), 14);
        let without = mount_argv(&d, &m, "00ff", None);
        assert_eq!(without.last().map(String::as_str), Some("."));
        assert_eq!(
            lookup_argv(&d, &owner("web")).get(5..),
            Some(
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    LOOKUP_SCRIPT.to_string(),
                    "sh".to_string(),
                    "web".to_string()
                ][..]
            )
        );
        // 記録は 3 行（ID・マウント先・コンテナ ID）で書き、検索は名前が 16 進の nonce のエントリだけを読む。
        assert!(MOUNT_SCRIPT.contains("printf '%s\\n%s\\n%s\\n' \"$new\" \"$T\" \"$5\""));
        assert!(LOOKUP_SCRIPT.contains("*[!0-9a-f]*) continue"));
        // 所有者で絞る前に 3 行構造・読み取りの成功・512 バイト未満を検証し、違反は `bad` で報告する。
        assert!(LOOKUP_SCRIPT.contains("! IFS= read -r x"));
        assert!(LOOKUP_SCRIPT.contains("-lt 512 ] || { printf 'bad %s\\n'"));
        assert!(LOOKUP_SCRIPT.contains("else printf 'bad %s\\n' \"$b\"; fi"));
    }

    /// `sh -c script sh arg` を期限つきで実行して出力を返す（超過時は kill して回収し panic する。REPAIR-5）。
    #[cfg(target_os = "linux")]
    fn run_sh_with_deadline(script: &str, arg: &str, limit: Duration) -> std::process::Output {
        run_sh_args_with_deadline(script, &[arg], limit)
    }

    /// [`run_sh_with_deadline`] の位置引数を複数取れる版（`sh -c script sh args...`）。
    #[cfg(target_os = "linux")]
    fn run_sh_args_with_deadline(
        script: &str,
        args: &[&str],
        limit: Duration,
    ) -> std::process::Output {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut child = Command::new("sh")
            .args(["-c", script, "sh"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let _ = stdout.read_to_end(&mut o);
            let _ = stderr.read_to_end(&mut e);
            (o, e)
        });
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if start.elapsed() >= limit {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sh did not finish before the deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stderr) = reader.join().unwrap();
        std::process::Output {
            status,
            stdout,
            stderr,
        }
    }

    /// #1412: 実際の `sh` で LOOKUP_SCRIPT の記録の選別を回す（所有者・root 検査だけを一時ディレクトリ向けに外す）。
    /// 所有者行の欠落・余分な行・空行・512 バイト以上は、所有者が別でも `bad`、正常な記録だけが `rec` になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn lookup_script_reports_malformed_records_as_bad() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fandhe-lookup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // umask に依らず他者書き込み不可にする（スクリプトの基準）。
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.join("aa1"), "none\n/mnt/fandhe/a\nweb\n").unwrap();
        fs::write(dir.join("bb2"), "none\n/mnt/fandhe/b\n").unwrap();
        fs::write(dir.join("cc3"), "none\n/mnt/fandhe/c\nweb\nextra\n").unwrap();
        fs::write(dir.join("dd4"), "none\n/mnt/fandhe/d\nweb\n\n").unwrap();
        fs::write(dir.join("ee5"), "none\n/mnt/fandhe/e\nother\n").unwrap();
        fs::write(dir.join("ff6"), "").unwrap();
        fs::write(dir.join("0a7"), "a".repeat(600)).unwrap();
        // 改行なしの余分な末尾データ（4 回目の read は失敗するが x に残る）も形式違反。
        fs::write(dir.join("9a8"), "100\n/mnt/fandhe/g\nweb\nextra").unwrap();
        // 改行なしの 2 行目だけの壊れた記録は旧形式として読み飛ばさない（fail-closed）。
        fs::write(dir.join("1b9"), "100\n/mnt/fandhe/a").unwrap();
        // 正常な旧形式 1 行の記録は読み飛ばす。
        fs::write(dir.join("2c0"), "100\n").unwrap();
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let from = "R=/run/fandhe;";
        let skip = "chk / || exit 200; chk /run || exit 200; ";
        assert!(LOOKUP_SCRIPT.contains(from) && LOOKUP_SCRIPT.contains(skip));
        let script = LOOKUP_SCRIPT
            .replace(from, &format!("R={};", dir.display()))
            .replace(skip, "")
            .replace("[ \"$1\" = 0 ] && ", "");
        // 期限つきで実行する（ハング時は kill して回収する。REPAIR-5）。
        let out = run_sh_with_deadline(&script, "web", Duration::from_secs(20));
        fs::remove_dir_all(&dir).unwrap();
        assert!(out.status.success(), "{out:?}");
        let mut lines: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        assert_eq!(
            lines,
            [
                "bad 0a7",
                "bad 1b9",
                "bad 9a8",
                "bad bb2",
                "bad cc3",
                "bad dd4",
                "bad ff6",
                "old 2c0",
                "rec aa1 none /mnt/fandhe/a"
            ]
        );
    }

    /// #1412: 記録は 3 行になっても、1 行目だけを読む既存の読み手はマウント ID を取り出せる。
    #[test]
    fn record_is_three_lines_and_first_line_readers_still_work() {
        let mut g = Guest::new("virtiofs");
        let p = prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]);
        let nonce = p.mounts().first().map(|m| m.nonce.clone()).unwrap();
        let text = g.record_text(&nonce).unwrap();
        assert_eq!(text, "100\n/mnt/fandhe/a\nweb\n");
        assert_eq!(parse_recorded_id(text.as_bytes()), Some(100));
        assert!(!is_none_record(text.as_bytes()));
        assert!(is_none_record(b"none\n/mnt/fandhe/a\n.\n"));
        assert!(is_none_record(b"none\n"));
        assert_eq!(parse_recorded_id(b"12 13\n/mnt/fandhe/a\n.\n"), None);
        // 通常の解除（PreparedLaunch 経路）も 3 行の記録で従来どおり動く。
        assert_eq!(release_with_exec(&p, &mut |a, m| g.run(a, m)).failures(), 0);
        assert!(g.records.is_empty());
        // ID なしの準備は印 `.` を書く。
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let p = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        let nonce = p.mounts().first().map(|m| m.nonce.clone()).unwrap();
        assert_eq!(
            g.record_text(&nonce).as_deref(),
            Some("100\n/mnt/fandhe/a\n.\n")
        );
    }

    /// WIN-2・PLUG-7・REPAIR-5（A1・A2）: 作成したプロセスの `PreparedLaunch` を失っても、別の実行器が
    /// コンテナ ID だけで自分のマウントを外す。別の ID のマウントと記録には触れない。
    #[test]
    fn recover_releases_only_the_requested_owner() {
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        drop(prepare_owned(&mut g, "api", vec![sm("C:\\b", "b", true)]));
        assert_eq!(g.records.len(), 2);

        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);
        assert!(g.mounts.iter().all(|(p, _)| p != "/mnt/fandhe/a"));
        assert!(g.mounts.iter().any(|(p, _)| p == "/mnt/fandhe/b"));
        // 残る記録は api のものだけ。
        let left: Vec<&(String, String)> = g
            .meta
            .iter()
            .filter_map(|(n, v)| g.records.get(n).map(|_| v))
            .collect();
        assert_eq!(left, [&("/mnt/fandhe/b".to_string(), "api".to_string())]);

        // 二重回収は何もしない（記録が無い）。
        assert_eq!(recover(&mut g, "web").unwrap(), RecoveryReport::default());
        assert_eq!(g.umounts, ["/mnt/fandhe/a"]);

        let report = recover(&mut g, "api").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert_eq!(g.umounts, ["/mnt/fandhe/a", "/mnt/fandhe/b"]);
        assert!(g.records.is_empty() && g.claims.is_empty());
    }

    /// #1412: 1 つのコンテナ ID に複数の共有マウントがあれば、全部を外す（検索 1 回・mountinfo 1 回・umount 各 1 回）。
    #[test]
    fn recover_releases_every_mount_of_the_owner() {
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(
            &mut g,
            "web",
            vec![sm("C:\\a", "a", false), sm("C:\\b", "b", true)],
        ));
        let cats = g.cat_calls;
        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (2, 2));
        assert_eq!(g.lookups, 1);
        assert_eq!(g.umounts.len(), 2);
        assert!(g.umounts.contains(&"/mnt/fandhe/a".to_string()));
        assert!(g.umounts.contains(&"/mnt/fandhe/b".to_string()));
        assert!(g.records.is_empty());
        assert!(g.cat_calls > cats);
    }

    /// #1412: 記録が 1 件も無ければ `Ok`（found 0）。mountinfo も読まず何も外さない。ID なしで準備した
    /// マウントは ID では引けず、触れない（fail-closed）。
    #[test]
    fn recover_with_no_records_does_nothing() {
        let mut g = Guest::new("virtiofs");
        let r = req(vec![sm("C:\\a", "a", false)]);
        let _ = drive(&mut g, &r, VirtiofsState::Enabled).unwrap();
        let cats = g.cat_calls;
        assert_eq!(recover(&mut g, "web").unwrap(), RecoveryReport::default());
        assert_eq!(g.cat_calls, cats);
        assert!(g.umounts.is_empty());
        assert!(g.mounts.iter().any(|(p, _)| p == "/mnt/fandhe/a"));
        assert_eq!(g.records.len(), 1);
    }

    /// #1412: 旧形式 1 行の記録（`old` の報告）は所有者を持たないので読み飛ばし、別コンテナの回収を止めない。
    /// 壊れた記録（`bad`）は従来どおり拒否する。
    #[test]
    fn recover_skips_legacy_records_but_rejects_bad_ones() {
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        g.lookup_old.push("00aa".to_string());
        assert_eq!(recover(&mut g, "web").unwrap().released, 1);
        assert!(g.umounts.contains(&"/mnt/fandhe/a".to_string()));

        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        g.lookup_old.push("00aa".to_string());
        g.lookup_bad.push("00ff".to_string());
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), failed_validation(1));
        assert!(g.umounts.is_empty());

        let out = parse_lookup_output(b"old 00aa\nold zz\n").unwrap();
        assert_eq!((out.legacy, out.rejected), (1, 1));
    }

    /// SEC・WIN-2（A3）: 改ざんされた記録（`bad` の報告・不正なマウント先・形式違反）が 1 件でもあれば、
    /// 構造化エラーを返して何も外さない。同じ ID の他の正しい記録も外さない。
    #[test]
    fn recover_refuses_tampered_records_and_releases_nothing() {
        // ゲスト側の基準違反（symlink・root 以外の所有・他者書き込み可）は `bad` の行で報告される。
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        g.lookup_bad.push("00ff".to_string());
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), failed_validation(1));
        assert!(e.unreleased().is_none());
        assert!(g.umounts.is_empty());
        assert_eq!(g.records.len(), 1);

        // 固定基底の外・`..`・深い階層・基底そのもの・名前規則違反のマウント先。
        for bad_target in [
            "/etc",
            "/mnt/fandhe/../x",
            "/mnt/fandhe/a/b",
            "/mnt/fandhe/",
            "/mnt/fandhe",
            "/mnt/fandhe2/a",
            "/mnt/fandhe/-a",
            "/mnt/fandhe/a b",
        ] {
            let mut g = Guest::new("virtiofs");
            drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
            for v in g.meta.values_mut() {
                v.0 = bad_target.to_string();
            }
            let e = recover(&mut g, "web").unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition, "{bad_target}");
            assert_eq!(e.message(), failed_validation(1), "{bad_target}");
            assert!(g.umounts.is_empty(), "{bad_target}");
            assert_eq!(g.records.len(), 1, "{bad_target}");
        }

        // 同じ ID の 2 件のうち 1 件が改ざんされていたら、正しい方も外さない。
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(
            &mut g,
            "web",
            vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)],
        ));
        let victim = g
            .meta
            .iter()
            .find(|(_, v)| v.0 == "/mnt/fandhe/b")
            .map(|(n, _)| n.clone())
            .unwrap();
        g.meta.get_mut(&victim).unwrap().0 = "/root".to_string();
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.message(), failed_validation(1));
        assert!(g.umounts.is_empty());
        assert_eq!(g.records.len(), 2);
    }

    /// SEC・WIN-2（A3）: 記録のマウント ID がマウント先の最上位と一致しない（記録の差し替え・他者のマウントが
    /// 積まれている）ときは、何も外さず `FAILED_PRECONDITION`。
    #[test]
    fn recover_refuses_records_that_do_not_match_mountinfo() {
        // 記録のマウント ID をずらす。
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        for v in g.records.values_mut() {
            *v = "150".to_string();
        }
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "1 guest mount record(s) do not match the mounted state; nothing was released"
        );
        assert!(g.umounts.is_empty());
        assert_eq!(g.records.len(), 1);

        // 他者のマウントが最上位に積まれた。
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        g.mounts.push(("/mnt/fandhe/a".into(), "tmpfs".into()));
        g.ids.push(777);
        g.opts.push("rw".into());
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(g.umounts.is_empty());
        assert_eq!(g.mounts.len(), 3);

        // 記録のマウント ID が別のマウント先に存在する（マウント先の書き換え）。
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(
            &mut g,
            "web",
            vec![sm("C:\\a", "a", false), sm("C:\\b", "b", false)],
        ));
        let rec_a = g
            .meta
            .iter()
            .find(|(_, v)| v.0 == "/mnt/fandhe/a")
            .map(|(n, _)| n.clone())
            .unwrap();
        g.meta.get_mut(&rec_a).unwrap().0 = "/mnt/fandhe/c".to_string();
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(g.umounts.is_empty());
    }

    /// WIN-2: 外れ済みの古い記録（マウントも ID も mountinfo に無い）は、記録だけを消して完了とする。
    #[test]
    fn recover_cleans_a_stale_record_without_unmounting() {
        let mut g = Guest::new("virtiofs");
        g.records.insert("00ab".into(), "150".into());
        g.claims.insert("00ab".into());
        g.meta
            .insert("00ab".into(), ("/mnt/fandhe/a".into(), "web".into()));
        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert!(g.umounts.is_empty());
        assert!(g.records.is_empty() && g.claims.is_empty());
    }

    /// WIN-2・#1412: `none` の記録は消さないので、再試行しても残置を検出して未完了のまま報告する（found=0 にならない）。
    #[test]
    fn recover_keeps_unattributed_record_and_reports_again_on_retry() {
        let mut g = Guest::new("virtiofs");
        g.mounts.push(("/mnt/fandhe/a".into(), "virtiofs".into()));
        g.ids.push(300);
        g.opts.push("rw,nosuid,nodev".into());
        g.records.insert("00ab".into(), "none".into());
        g.claims.insert("00ab".into());
        g.meta
            .insert("00ab".into(), ("/mnt/fandhe/a".into(), "web".into()));
        for _ in 0..2 {
            let e = recover(&mut g, "web").unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
            assert_eq!(g.records.get("00ab").map(String::as_str), Some("none"));
            assert_eq!(g.clears, 0);
        }
    }

    /// REPAIR-5・#1412: 記録の削除に失敗（`/run` が読み取り専用等）したら `Ok(released)` にせず未完了として保持する。
    #[test]
    fn recover_reports_incomplete_when_stale_record_cannot_be_removed() {
        let mut g = Guest::new("virtiofs");
        g.records.insert("00ab".into(), "150".into());
        g.claims.insert("00ab".into());
        g.meta
            .insert("00ab".into(), ("/mnt/fandhe/a".into(), "web".into()));
        g.clear_fails = true;
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(g.records.contains_key("00ab"));
        // 直ってからの再試行で完了する。
        g.clear_fails = false;
        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert!(g.records.is_empty());
    }

    /// REPAIR-5・#1412: umount は成功したが UMOUNT_SCRIPT が記録を消せなかった（213）場合も、完了にせず保持する。
    #[test]
    fn recover_reports_incomplete_when_umount_script_cannot_remove_record() {
        let mut g = Guest::new("virtiofs");
        prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]);
        g.umount_record_rm_fails = true;
        g.clear_fails = true;
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(g.records.len(), 1);
        g.umount_record_rm_fails = false;
        g.clear_fails = false;
        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert!(g.records.is_empty());
    }

    /// WIN-2: 自分のマウントを特定できなかった記録（`none`）は外さず、件数だけを報告する（fail-closed）。
    #[test]
    fn recover_does_not_unmount_unattributed_records() {
        let mut g = Guest::new("virtiofs");
        g.mounts.push(("/mnt/fandhe/a".into(), "virtiofs".into()));
        g.ids.push(300);
        g.opts.push("rw,nosuid,nodev".into());
        g.records.insert("00ab".into(), "none".into());
        g.claims.insert("00ab".into());
        g.meta
            .insert("00ab".into(), ("/mnt/fandhe/a".into(), "web".into()));
        let e = recover(&mut g, "web").unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "0 unmount(s) failed (1 mount(s) could not be attributed and may have been left in place)"
        );
        assert!(g.umounts.is_empty());
        assert!(g.mounts.iter().any(|(p, _)| p == "/mnt/fandhe/a"));
    }

    /// REPAIR-5・WIN-2: 外せなかったマウントは `MountError::unreleased` に載せ、同じ関数で再試行できる。
    #[test]
    fn recover_returns_unreleased_mounts_and_can_retry() {
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        g.umount_timeout = Some(false);
        let e = recover(&mut g, "web").unwrap_err();
        // 解除段階の期限切れは `TIMEOUT` のまま返り、未解除の情報も残る（REPAIR-5・ERR-1）。
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert_eq!(e.message(), "1 unmount(s) failed");
        assert_eq!(
            e.unreleased().map(summary),
            Some(vec![("/mnt/fandhe/a", Some(100), false)])
        );
        assert_eq!(g.records.len(), 1);
        g.umount_timeout = None;
        let report = recover(&mut g, "web").unwrap();
        assert_eq!((report.found, report.released), (1, 1));
        assert!(g.records.is_empty());
    }

    /// REPAIR-5・ERR-1: 検索・mountinfo の読み取りが期限切れ（`wsl.exe` のタイムアウト）なら `TIMEOUT` で止まり、
    /// 何も外さない。検索のスクリプトの失敗は終了コードごとの固定文言になる。
    #[test]
    fn recover_maps_timeouts_and_script_failures() {
        let timeout = || Err(Wsl2Error::new(Wsl2ErrorCode::Timeout, "slow"));
        let mut g = Guest::new("virtiofs");
        drop(prepare_owned(&mut g, "web", vec![sm("C:\\a", "a", false)]));
        // 検索が期限切れ。
        let e = recover_with_exec(&distro_name(), &owner("web"), &mut |a, m| {
            if a.get(7).map(String::as_str) == Some(LOOKUP_SCRIPT) {
                return timeout();
            }
            g.run(a, m)
        })
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        // 検索の後の mountinfo の読み取りが期限切れ。
        let e = recover_with_exec(&distro_name(), &owner("web"), &mut |a, m| {
            if a.get(5).map(String::as_str) == Some("cat") {
                return timeout();
            }
            g.run(a, m)
        })
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert!(g.umounts.is_empty());
        assert_eq!(g.records.len(), 1);

        for (code, expected, message) in [
            (
                200,
                Wsl2ErrorCode::FailedPrecondition,
                "the mount base parent directory is missing or unsafe",
            ),
            (
                202,
                Wsl2ErrorCode::FailedPrecondition,
                "a mount path component is not a root-owned, non-writable directory (symlinks are rejected)",
            ),
            (
                215,
                Wsl2ErrorCode::ResourceExhausted,
                "too many guest mount records to scan",
            ),
            (
                1,
                Wsl2ErrorCode::FailedPrecondition,
                "looking up mount records failed in the distribution (exit code 1)",
            ),
        ] {
            g.lookup_exit = Some(code);
            let e = recover(&mut g, "web").unwrap_err();
            assert_eq!((e.code(), e.message()), (expected, message), "{code}");
        }
        assert!(g.umounts.is_empty());
    }

    /// REPAIR-2・REPAIR-5: 検索の出力はゲスト由来の untrusted として、形式・マウント先・件数・重複を検証する。
    #[test]
    fn lookup_output_parsing() {
        let ok = parse_lookup_output(b"rec 00ff 100 /mnt/fandhe/a\nrec 0a none /mnt/fandhe/b-1\n")
            .unwrap();
        assert_eq!(ok.rejected, 0);
        assert_eq!(
            ok.records,
            vec![
                RecoveredRecord {
                    nonce: "00ff".into(),
                    mount_id: Some(100),
                    guest_path: "/mnt/fandhe/a".into()
                },
                RecoveredRecord {
                    nonce: "0a".into(),
                    mount_id: None,
                    guest_path: "/mnt/fandhe/b-1".into()
                },
            ]
        );
        assert_eq!(parse_lookup_output(b"").unwrap(), LookupOutput::default());

        for bad in [
            "bad 00ff",
            "rec 00FF 100 /mnt/fandhe/a",
            "rec 00ff 100",
            "rec 00ff 100 /mnt/fandhe/a extra",
            "rec 00ff x1 /mnt/fandhe/a",
            "rec 00ff 4294967296 /mnt/fandhe/a",
            "rec 00ff -1 /mnt/fandhe/a",
            "rec  100 /mnt/fandhe/a",
            "rec 00ff 100 /mnt/fandhe/../etc",
            "rec 00ff 100 /mnt/fandhe/a/b",
            "rec 00ff 100 relative",
            "garbage",
            "rec 00ff 100  /mnt/fandhe/a",
        ] {
            let got = parse_lookup_output(bad.as_bytes()).unwrap();
            assert_eq!((got.records.len(), got.rejected), (0, 1), "{bad}");
        }
        let long_nonce = format!("rec {} 1 /mnt/fandhe/a", "a".repeat(MAX_NONCE_LEN + 1));
        assert_eq!(
            parse_lookup_output(long_nonce.as_bytes()).unwrap().rejected,
            1
        );

        // 同じ nonce・同じマウント先を二重に主張する記録は拒否する。
        let dup = parse_lookup_output(
            b"rec 00ff 100 /mnt/fandhe/a\nrec 00ff 101 /mnt/fandhe/b\nrec 00fe 102 /mnt/fandhe/a\n",
        )
        .unwrap();
        assert_eq!((dup.records.len(), dup.rejected), (1, 2));

        assert_eq!(
            parse_lookup_output(&[0xff, 0xfe]).unwrap_err().code(),
            Wsl2ErrorCode::DataLoss
        );
        let many: String = (0..=MAX_SHARED_MOUNTS)
            .map(|i| format!("rec {i:02x} {i} /mnt/fandhe/m{i}\n"))
            .collect();
        assert_eq!(
            parse_lookup_output(many.as_bytes()).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
        let lines = "bad 00\n".repeat(MAX_LOOKUP_LINES + 1);
        assert_eq!(
            parse_lookup_output(lines.as_bytes()).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
    }

    /// WIN-2: 記録と mountinfo の照合規則（最上位の ID 一致・外れ済みの掃除・矛盾の拒否）。
    #[test]
    fn record_matches_mounts_cases() {
        let entry = |id: u32, parent: u32, mp: &str| MountEntry {
            mount_id: id,
            parent_id: parent,
            mount_point: mp.into(),
            options: "rw".into(),
            fstype: "virtiofs".into(),
        };
        let rec = |id: Option<u32>| RecoveredRecord {
            nonce: "00ff".into(),
            mount_id: id,
            guest_path: "/mnt/fandhe/a".into(),
        };
        let base = vec![entry(1, 0, "/")];
        // 外れ済み（どこにも無い）は一致扱い。
        assert!(record_matches_mounts(&rec(Some(5)), &base));
        // `none` は外さないので常に矛盾なし。
        assert!(record_matches_mounts(&rec(None), &base));
        let mounted = vec![entry(1, 0, "/"), entry(5, 1, "/mnt/fandhe/a")];
        assert!(record_matches_mounts(&rec(Some(5)), &mounted));
        assert!(!record_matches_mounts(&rec(Some(6)), &mounted));
        // 他者のマウントが積まれている（最上位は 6）。
        let stacked = vec![
            entry(1, 0, "/"),
            entry(5, 1, "/mnt/fandhe/a"),
            entry(6, 5, "/mnt/fandhe/a"),
        ];
        assert!(!record_matches_mounts(&rec(Some(5)), &stacked));
        // マウント先に無いが、記録の ID は別の場所にある。
        let moved = vec![entry(1, 0, "/"), entry(5, 1, "/mnt/fandhe/z")];
        assert!(!record_matches_mounts(&rec(Some(5)), &moved));
        // マウント先に別のマウントがあり、記録の ID は無い。
        let replaced = vec![entry(1, 0, "/"), entry(9, 1, "/mnt/fandhe/a")];
        assert!(!record_matches_mounts(&rec(Some(5)), &replaced));
    }

    /// REPAIR-4: 公開の計装版は回収全体を `wsl2.unmount_shared` として 1 件記録する（`wsl.exe` が無い環境では
    /// 実行器に到達する前の失敗として記録される）。
    #[test]
    fn release_container_mounts_is_instrumented() {
        use crate::instrument::testing::Collect;
        let rec = Collect::default();
        let r = release_container_mounts_with_recorder(
            &distro_name(),
            &owner("web"),
            Duration::ZERO,
            &rec,
        );
        assert_eq!(r.unwrap_err().code(), Wsl2ErrorCode::InvalidArgument);
        assert_eq!(
            rec.kinds(),
            [(
                WinOpKind::Wsl2UnmountShared,
                crate::instrument::WinOpOutcome::Failure
            )]
        );
    }
}
