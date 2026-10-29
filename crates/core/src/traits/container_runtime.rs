//! `ContainerRuntime` 拡張点トレイト（TASK-4.1・CRI-7・PLUG-1・MS-0）。
//!
//! CRI サーバー層（`fandhe-container-cri`）・将来の containerd shim v2（CRI-5）は、
//! この内部トレイトを呼ぶアダプタとなる想定（PoC-7 の原案）。実装は本 crate には置かず、
//! 別プロセス plugin（`fandhe-container-plugin-cri` 等は TASK-114、バックエンド plugin は #1869 の設計〔docs/design/plugin-backend-wiring.md。承認と実装 issue の起票は #2232〕）が担い、core 側の
//! proxy（G8・TASK-107。バックエンド plugin 向けは #1869 の設計の 4.1・4.3）が UDS＋長さ接頭辞フレームの RPC へ変換して
//! `Box<dyn ContainerRuntime>` として呼び出し側へ渡す（PLUG-1）。
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない。

use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::state_store::Annotations;
use super::types::{ContainerId, ErrorCode, TraitError};

/// コンテナのライフサイクル（create/start/kill/stop/delete/state）を抽象化する拡張点。
///
/// # 契約
/// 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）。
/// 2. 相手の応答を待つ処理（plugin RPC・子プロセスの起動確認等）は無期限に待たず、
///    上限時間を超えたら [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の
///    決定は proxy 実装（G8・TASK-107/114）の責務であり、本トレイトは契約のみを定める。
/// 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn ContainerRuntime>` として複数スレッド
///    から共有できることを前提にしてよい。
/// 4. 本 crate（core）にはこのトレイトの実装を置かない。実装は plugin 側にある
///    （PLUG-1・#1869 の設計・TASK-114）。「実装済みを装わない」という REPAIR-3 の方針に基づく。
/// 5. plugin の信頼境界（UDS の所有者・権限検証、別 UID からの接続切断等。PLUG-11・PLUG-12）
///    はこのトレイトの外側、境界機構（`fandhe-container-plugin`）の責務であり、
///    `ContainerRuntime` の呼び出し側はそれらが検証済みであることを前提にしてよい。
///
/// メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。
/// CRI-7 の呼び出し側はトレイト境界だけを通って `Box<dyn ContainerRuntime>` を扱うため、
/// dyn 互換（object safety）を保つ必要がある。async ランタイムへの依存を追加しない
/// （依存最小方針。dependency-policy.md）。
pub trait ContainerRuntime: Send + Sync {
    /// OCI bundle からコンテナを作成する（状態は [`ContainerState::Created`] になる）。
    ///
    /// 前提: 同じ [`ContainerId`] のコンテナが存在しないこと。存在する場合は
    /// [`ErrorCode::AlreadyExists`] を返す。対応: CORE-2・ERR-2。
    fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError>;

    /// `created` 状態のコンテナでユーザープロセスを開始する（状態は `Running` になる）。
    ///
    /// 前提: 対象コンテナが `created` 状態であること。そうでなければ
    /// [`ErrorCode::FailedPrecondition`] を返す。対応: CORE-2・ERR-2。
    fn start(&self, req: &StartRequest) -> Result<ContainerStatus, TraitError>;

    /// 実行中のコンテナへシグナルを送る。プロセスの終了は待たない。
    ///
    /// 前提: 対象コンテナが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// 対応: CORE-2・ERR-2。
    fn kill(&self, req: &KillRequest) -> Result<ContainerStatus, TraitError>;

    /// [`StopRequest::signal`]（既定 SIGTERM）を停止の意図つきで 1 回送り、猶予時間
    /// （[`StopRequest::grace`]）を過ぎたら SIGKILL で強制停止する。
    ///
    /// CLI の `stop` サブコマンド（CLI-1）と CRI `StopContainer` に対応する。
    /// 猶予は呼び出し側が明示し、無期限には待たない（REPAIR-5）。
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError>;

    /// 停止済みコンテナの資源を解放する。`force` 指定時は実行中でも停止してから削除する。
    ///
    /// 前提: `force` が false の場合、対象コンテナが停止済みであること。実行中であれば
    /// [`ErrorCode::FailedPrecondition`] を返す。対応: CORE-2・ERR-2。
    ///
    /// 後始末（core が作った rootfs・ログ等）の失敗は `Err` にせず、`Ok(DeleteResponse)` の該当欄に
    /// `Kept { code }` で載せる。`Err` は状態を消していない（再試行できる）失敗に限る（OCI-7・REPAIR-4）。
    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError>;

    /// コンテナの現在状態を照会する。
    ///
    /// 前提: 対象コンテナが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// 対応: CORE-2・ERR-2。
    fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError>;
}

/// Linux のシグナル番号（`kill`/`stop` で使う）。
///
/// Linux の番号体系をそのまま使う。macOS / Windows ホストでも、コンテナ本体はゲストの
/// Linux VM 内で動作する前提のため（OCI-5 の (4)）、シグナル番号は OS 分岐を持たない。
/// `SIGTERM`（15）・`SIGKILL`（9）は x86_64 / aarch64 で共通の値である。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signal(NonZeroU8);

impl Signal {
    /// プロセスの正常終了を要求するシグナル（15）。
    pub const SIGTERM: Signal = Signal(NonZeroU8::new(15).expect("15 is nonzero"));
    /// プロセスを即座に強制終了させるシグナル（9）。
    pub const SIGKILL: Signal = Signal(NonZeroU8::new(9).expect("9 is nonzero"));

    /// シグナル番号を検証して作る。`0` および Linux の実時間シグナル上限を超える
    /// `65` 以上の値は [`ErrorCode::InvalidArgument`] で拒否する。
    pub fn new(value: u8) -> Result<Self, TraitError> {
        if value == 0 || value > 64 {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "signal number must be in 1..=64",
            ));
        }
        // 直前の範囲検査により 1..=64 であることが保証されるため NonZeroU8 化は必ず成功する。
        Ok(Self(NonZeroU8::new(value).unwrap_or(NonZeroU8::MIN)))
    }

    /// シグナル番号を `u8` として返す。
    pub fn as_u8(&self) -> u8 {
        self.0.get()
    }

    /// Docker の `--signal` / `STOPSIGNAL` と同じ表記（番号または名前）を解釈する
    /// （CLI-1・ERR-1。CLI の `stop --signal` が使う。moby の `ParseSignal` の語彙）。
    ///
    /// - 数字だけなら Linux の番号（1..=64。glibc が予約する 32・33 は拒否する）
    /// - それ以外は ASCII の大文字小文字を区別しない名前で、`SIG` 接頭辞は任意
    ///   （`RTMIN`・`RTMIN+1..=15`・`RTMAX-14..=-1`・`RTMAX`。オフセットは先頭 0 なしの 1〜2 桁で moby の `SignalMap` と同じ。別名の `IOT`・`CLD`・`POLL` を含む）
    /// - 空・長さ上限（64 バイト）超え・非 ASCII・符号つき数字・空白は拒否する。長さは解釈の前に検査する
    ///
    /// エラーは [`ErrorCode::InvalidArgument`] で、固定の英語文言にし入力値を含めない。
    pub fn parse_notation(text: &str) -> Result<Self, TraitError> {
        let invalid = || TraitError::new(ErrorCode::InvalidArgument, "signal is invalid");
        if text.is_empty() || text.len() > MAX_SIGNAL_NOTATION_BYTES || !text.is_ascii() {
            return Err(invalid());
        }
        let number = if text.bytes().all(|b| b.is_ascii_digit()) {
            text.parse::<u32>().map_err(|_| invalid())?
        } else {
            signal_number_of_name(&text.to_ascii_uppercase()).ok_or_else(invalid)?
        };
        // 32・33 は glibc が予約する番号（実時間シグナルの先頭は 34）。
        if number == 32 || number == 33 {
            return Err(invalid());
        }
        let value = u8::try_from(number).map_err(|_| invalid())?;
        Self::new(value).map_err(|_| invalid())
    }
}

/// [`Signal::parse_notation`] が受ける文字列の長さの上限（バイト）。
const MAX_SIGNAL_NOTATION_BYTES: usize = 64;

/// 大文字化済みの名前を Linux のシグナル番号へ写す（x86_64 / aarch64 共通の体系）。
fn signal_number_of_name(upper: &str) -> Option<u32> {
    let name = upper.strip_prefix("SIG").unwrap_or(upper);
    let fixed = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" | "CLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        "RTMIN" => 34,
        "RTMAX" => 64,
        _ => 0,
    };
    if fixed != 0 {
        return Some(fixed);
    }
    if let Some(n) = name.strip_prefix("RTMIN+") {
        let n = parse_small_decimal(n)?;
        return (1..=15).contains(&n).then_some(34 + n);
    }
    if let Some(n) = name.strip_prefix("RTMAX-") {
        let n = parse_small_decimal(n)?;
        return (1..=14).contains(&n).then_some(64 - n);
    }
    None
}

/// 1〜2 桁の ASCII 数字だけの文字列を数にする（符号・空白・長い桁は `None`）。
fn parse_small_decimal(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 2 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // moby の `SignalMap` に先頭 0 のキー（`RTMIN+01` 等）は無い。イメージ由来の入力の受理範囲を広げない。
    if text.len() == 2 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

/// [`ContainerRuntime::create`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateRequest {
    id: ContainerId,
    bundle: PathBuf,
    annotations: Annotations,
}

impl CreateRequest {
    /// コンテナ ID と OCI bundle の絶対パスから要求を作る。
    ///
    /// `bundle` が絶対パスでない場合は [`ErrorCode::InvalidArgument`] を返す。plugin
    /// プロセスは呼び出し元と作業ディレクトリが異なるため、相対パスは解決先が曖昧になる
    /// （fail-closed）。rootfs の外を指していないか等の詳しい検証は実装側（#1869 の設計・TASK-114・G3）の
    /// 責務であり、本トレイトは形式検証のみを行う。
    pub fn new(id: ContainerId, bundle: PathBuf) -> Result<Self, TraitError> {
        if !bundle.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bundle path must be absolute",
            ));
        }
        Ok(Self {
            id,
            bundle,
            annotations: Annotations::default(),
        })
    }

    /// `state.json` へ記録する label(`--label`。検証済みの [`Annotations`]。SUP-12・CLI-1・#2713)。既定は空。
    ///
    /// core の `create` が [`CreateStateRequest::with_annotations`](super::state_store::CreateStateRequest::with_annotations)
    /// へそのまま渡す。plugin 境界のワイヤー(`CreateRequest` の符号化)は label を運ばないため、plugin 経由の
    /// backend では無視される(REPAIR-3。Linux の CLI は core を直接呼ぶので影響しない)。
    #[must_use]
    pub fn with_annotations(mut self, annotations: Annotations) -> Self {
        self.annotations = annotations;
        self
    }

    /// 記録する label を返す(未指定なら空)。
    pub fn annotations(&self) -> &Annotations {
        &self.annotations
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// OCI bundle の絶対パスを返す。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }
}

/// [`ContainerRuntime::start`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartRequest {
    id: ContainerId,
    log_path: Option<ContainerLogPath>,
}

impl StartRequest {
    /// 対象コンテナの ID から要求を作る（CRI ログの書き先なし）。
    pub fn new(id: ContainerId) -> Self {
        Self { id, log_path: None }
    }

    /// CRI ログの書き先（`log_directory/log_path` を結合・検証済みの絶対パス）を付ける
    /// （CRI-2・SUP-4・#2671）。supervisor はコンテナ出力を CRI ログ形式でこのパスへ書く。
    #[must_use]
    pub fn with_log_path(mut self, log_path: ContainerLogPath) -> Self {
        self.log_path = Some(log_path);
        self
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// CRI ログの書き先を返す。`None` は CRI ログなし（従来どおり）。
    pub fn log_path(&self) -> Option<&ContainerLogPath> {
        self.log_path.as_ref()
    }
}

/// [`ContainerLogPath::new`] が受理するバイト長の上限（argv の 1 要素の上限と同じ 4096）。
pub const CONTAINER_LOG_PATH_MAX_BYTES: usize = 4096;

/// CRI ログの書き先パス（検証済みの絶対 POSIX パス。CRI-2・SUP-4・#2671）。
///
/// CRI の `log_directory` と `log_path` を cri crate が結合した結果を、
/// [`StartRequest`] 経由で plugin-cri → supervisor の argv（`--cri-log-path`）へ運ぶ。
/// supervisor 側でも外部入力として同じ検証を再度通す。
///
/// ログのパスは Linux の supervisor ホスト上のパスであり、[`Signal`] が Linux の番号体系を使うのと
/// 同じ理由で、ホストの `Path` の意味（Windows の `is_absolute` 等）に依らない POSIX 文字列として
/// 検証する（3 OS で同じ結果になる）。
///
/// 不変条件: 先頭が `/`、`/` 区切りの各要素が空でなく `.`・`..` でもない（連続する `/`・末尾の `/` は拒否）、
/// NUL と制御文字を含まない、2〜[`CONTAINER_LOG_PATH_MAX_BYTES`] バイト。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerLogPath(String);

impl ContainerLogPath {
    /// 文字列を検証して作る。違反は [`ErrorCode::InvalidArgument`]（メッセージに値を含めない）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        let invalid = || {
            TraitError::new(
                ErrorCode::InvalidArgument,
                "container log path must be a normalized absolute path",
            )
        };
        if value.len() < 2 || value.len() > CONTAINER_LOG_PATH_MAX_BYTES {
            return Err(invalid());
        }
        let Some(rest) = value.strip_prefix('/') else {
            return Err(invalid());
        };
        if value.chars().any(char::is_control) {
            return Err(invalid());
        }
        if rest
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(invalid());
        }
        Ok(Self(value))
    }

    /// 検証済みのパス文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// [`ContainerRuntime::state`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateRequest {
    id: ContainerId,
}

impl StateRequest {
    /// 対象コンテナの ID から要求を作る。
    pub fn new(id: ContainerId) -> Self {
        Self { id }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }
}

/// [`ContainerRuntime::kill`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KillRequest {
    id: ContainerId,
    signal: Signal,
}

impl KillRequest {
    /// 対象コンテナの ID と送るシグナルから要求を作る。
    pub fn new(id: ContainerId, signal: Signal) -> Self {
        Self { id, signal }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 送るシグナルを返す。
    pub fn signal(&self) -> Signal {
        self.signal
    }
}

/// [`StopRequest::new`] が受理する猶予時間の上限（REPAIR-5）。
///
/// `Duration::MAX` 相当の実質無期限の値を渡すと、SIGKILL への切り替えが
/// 無期限待ちになり得る（REPAIR-5 のタイムアウト必須方針に反する）ため、
/// 型のレベルで上限を強制する。具体的な既定タイムアウト値の決定は
/// proxy 実装（G8・TASK-107/114）の責務であり、ここでは「無期限を許さない」
/// という契約のみを表現する暫定値として 24 時間を採用する
/// （人間のアーキテクチャレビュー #19・TASK-4.h1 で確定させる）。
const STOP_GRACE_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// [`ContainerRuntime::stop`] の要求。
///
/// 実装は [`StopRequest::signal`]（既定 SIGTERM）を停止の意図つきで 1 回送り、
/// [`StopRequest::grace`] を過ぎても止まらなければ、シグナルが何であっても無条件に
/// SIGKILL へ切り替える（全体の待ちは有界のまま。REPAIR-5）。CRI の `stop_signal`
/// （CRI-2。#2668）を運ぶための欄で、番号は Linux の体系（[`Signal`] の doc 参照）。
/// 対応: PLUG-1。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StopRequest {
    id: ContainerId,
    grace: Duration,
    signal: Signal,
}

impl StopRequest {
    /// 対象コンテナの ID と SIGKILL までの猶予時間から要求を作る。
    ///
    /// 猶予は呼び出し側が明示する必要があり（無期限を許さない。REPAIR-5）、
    /// 実装は猶予経過後に SIGKILL へ切り替える。`grace` が 24 時間を
    /// 超える場合は実質無期限の値とみなし [`ErrorCode::InvalidArgument`] を返す。
    pub fn new(id: ContainerId, grace: Duration) -> Result<Self, TraitError> {
        if grace > STOP_GRACE_MAX {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("grace must not exceed {STOP_GRACE_MAX:?}"),
            ));
        }
        Ok(Self {
            id,
            grace,
            signal: Signal::SIGTERM,
        })
    }

    /// 猶予の間に最初に送るシグナルを指定する（既定は SIGTERM）。
    #[must_use]
    pub fn with_signal(mut self, signal: Signal) -> Self {
        self.signal = signal;
        self
    }

    /// 最初に送るシグナル（既定 SIGTERM）を返す。
    pub fn signal(&self) -> Signal {
        self.signal
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// SIGKILL までの猶予時間を返す。
    pub fn grace(&self) -> Duration {
        self.grace
    }
}

/// [`ContainerRuntime::delete`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteRequest {
    id: ContainerId,
    force: bool,
}

impl DeleteRequest {
    /// 対象コンテナの ID から要求を作る（`force` は既定で false）。
    pub fn new(id: ContainerId) -> Self {
        Self { id, force: false }
    }

    /// `force` を指定したビルダ。true の場合、実行中でも停止してから削除する。
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 強制削除が指定されているかを返す。
    pub fn force(&self) -> bool {
        self.force
    }
}

/// コンテナの状態（OCI Runtime Spec の state 文字列に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContainerState {
    /// 作成処理の途中。
    Creating,
    /// 作成済みでまだユーザープロセスを開始していない。
    Created,
    /// ユーザープロセスが実行中。
    Running,
    /// ユーザープロセスが終了済み。
    Stopped,
}

impl ContainerState {
    /// OCI Runtime Spec の state 文字列（小文字）を返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// コンテナの状態照会結果。真偽値やフラットな文字列ではなく、将来の拡張
/// （リソース使用量等）に備えて構造化された型にする（coding-rust.md）。
///
/// `pid` は [`ContainerState::Created`]・[`ContainerState::Running`] のときに
/// 意味を持ち（OCI の `created` コンテナは runtime create 完了時点で init
/// プロセスを既に fork 済みのため、CRI / shim アダプタがその PID を state から
/// 参照できる必要がある。Bugbot 指摘・PR #1074 discussion_r4112017709）、
/// `exit_code` は [`ContainerState::Stopped`] のときにのみ意味を持つ。以前は
/// 状態と無関係に `with_pid` / `with_exit_code` を呼べるビルダだったため、
/// `Created` に終了コードを付与する等の矛盾した値を公開 API から作れて
/// しまっていた（codex レビュー指摘・PR #1074）。状態ごとに対応する
/// コンストラクタ（[`Self::creating`]・[`Self::created`]・[`Self::running`]・
/// [`Self::stopped`]）に限定し、組み合わせを型で制限する。
///
/// `Stopped` の `exit_code` は `Option<i32>` にする。作成途中の失敗・シグナルに
/// よる異常終了等、実装側が終了コードを取得できないまま「停止済み」の事実
/// だけは確認できるケースがあり、`i32` 必須では実装が値を捏造するか
/// 停止状態そのものを返せなくなってしまう（codex レビュー指摘・PR #1074）。
///
/// `termination` は [`ContainerState::Stopped`] のときにのみ意味を持つ「特別な終了理由」で、
/// 終了コードとは独立に報告する（OOM による kill は終了コードだけでは見分けられないため。
/// CRI-2・CORE-4）。`None` は「特別な理由を報告していない」であり、「OOM ではない」と
/// 「検出していない」を区別しない。報告経路は supervisor が終了検知時に cgroup v2 の
/// `memory.events` の `oom_kill` の増分を読んで [`Self::stopped_with_reason`] で記録する設計で、
/// 検出側の実装は本型の追加より後続の分割 issue（TASK-59 追補・CRI-2・CORE-4・SUP-1）で行う
/// （現状は読み取りが未実装のため、既存の実装は常に `None` を返す。REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerStatus {
    id: ContainerId,
    state: ContainerState,
    pid: Option<NonZeroU32>,
    exit_code: Option<i32>,
    termination: Option<TerminationReason>,
}

/// コンテナの終了に付く特別な理由（CRI の `ContainerStatus.reason` の `OOMKilled` の元。CRI-2・CORE-4）。
///
/// 終了コードと独立に報告される。将来、起動失敗等の理由を足せるよう `#[non_exhaustive]` にする。
/// state.json には [`Self::as_str`] の固定文字列で永続化する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminationReason {
    /// cgroup の OOM killer がコンテナ内のプロセスを kill した（`memory.events` の `oom_kill` の増分）。
    OomKilled,
}

impl TerminationReason {
    /// 状態ファイル・ログで使う固定の文字列表現を返す。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OomKilled => "oomKilled",
        }
    }

    /// [`Self::as_str`] の逆変換。未知の文字列（大文字小文字違いを含む）は `None`。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oomKilled" => Some(Self::OomKilled),
            _ => None,
        }
    }
}

impl ContainerStatus {
    /// 内部専用の共通コンストラクタ。公開コンストラクタから状態ごとの
    /// 組み合わせ（`pid`・`exit_code` の有無）を固定して呼ぶ。
    fn build(
        id: ContainerId,
        state: ContainerState,
        pid: Option<NonZeroU32>,
        exit_code: Option<i32>,
    ) -> Self {
        Self {
            id,
            state,
            pid,
            exit_code,
            termination: None,
        }
    }

    /// 作成処理中の状態を作る（`pid`・`exit_code` は持たない）。
    pub fn creating(id: ContainerId) -> Self {
        Self::build(id, ContainerState::Creating, None, None)
    }

    /// 作成済みでまだ未開始の状態を作る。`pid` は init プロセスの PID が
    /// 判明していれば渡す（OCI の `created` コンテナは既に init プロセスを
    /// 持つため）。`exit_code` は持たない。
    pub fn created(id: ContainerId, pid: Option<NonZeroU32>) -> Self {
        Self::build(id, ContainerState::Created, pid, None)
    }

    /// 実行中の状態を作る。`pid` は判明していれば渡す（`exit_code` は持たない）。
    pub fn running(id: ContainerId, pid: Option<NonZeroU32>) -> Self {
        Self::build(id, ContainerState::Running, pid, None)
    }

    /// 終了済みの状態を作る。`exit_code` は判明していれば渡す（`pid` は持たない）。
    ///
    /// 作成途中の失敗やシグナルによる異常終了等、終了コードを取得できない
    /// まま停止状態だけが確認できるケースがあるため `Option<i32>` を受ける。
    pub fn stopped(id: ContainerId, exit_code: Option<i32>) -> Self {
        Self::build(id, ContainerState::Stopped, None, exit_code)
    }

    /// 特別な終了理由つきの終了済み状態を作る（CRI-2・CORE-4）。
    ///
    /// OOM による終了のように、終了コードと独立に理由を報告したいときに使う。
    /// `Stopped` 以外は理由を持てない（矛盾した組み合わせを作らせない）。
    pub fn stopped_with_reason(
        id: ContainerId,
        exit_code: Option<i32>,
        reason: TerminationReason,
    ) -> Self {
        let mut status = Self::stopped(id, exit_code);
        status.termination = Some(reason);
        status
    }

    /// コンテナ ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 現在の状態を返す。
    pub fn state(&self) -> ContainerState {
        self.state
    }

    /// init プロセスの PID（`Created` または `Running` で判明していれば返す。
    /// それ以外の状態、または未設定なら `None`）を返す。
    pub fn pid(&self) -> Option<NonZeroU32> {
        self.pid
    }

    /// 終了コード（未設定なら `None`）を返す。
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// 特別な終了理由（報告が無ければ `None`。`Stopped` 以外は常に `None`）を返す。
    pub fn termination_reason(&self) -> Option<TerminationReason> {
        self.termination
    }
}

/// delete の後始末 1 件の結果（OCI-7・SUP-7・REPAIR-4）。
///
/// 後始末の失敗は delete の成否を変えない（状態は既に消えており、`Err` を返すと再実行が
/// `NotFound` になる）。残した資源は [`Self::Kept`] で呼び出し元へ伝える。
/// パス・errno は含めず、分類コードだけを持つ（ERR-1・ERR-2）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupOutcome {
    /// この層では対象が無い（記録の無い rootfs・この層の担当外のログ等）。既定値。
    #[default]
    NotApplicable,
    /// 消した（期限内に作業を終えた best effort を含む）。
    Removed,
    /// 既に無かった（冪等な再実行）。
    AlreadyAbsent,
    /// 同じ ID が再作成済みで、新しいインスタンスの資源として消さずに残した（SUP-7・REPAIR-4・#3143）。
    ///
    /// 失敗ではないため警告しない（[`DeleteResponse::kept`] にも載せない）。ロック保持中の確認（guard）が
    /// 偽だったときだけで、ファイルが無くて 0 件だった成功は [`Self::Removed`] のまま。
    Superseded,
    /// 消せずに残した。`code` は理由の分類。
    Kept {
        /// 残した理由の機械可読な分類。
        code: ErrorCode,
    },
}

/// delete の後始末の対象（[`DeleteResponse::kept`] の識別に使う。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupTarget {
    /// core が `create_with_image` で作った rootfs（OCI-7）。
    ImageRootfs,
    /// supervisor ログ（SUP-7）。
    SupervisorLog,
    /// コンテナログ（CRI-2）。
    ContainerLog,
    /// イメージストア側のコンテナ参照（OCI-7。使用中イメージの保護）。
    ImageRef,
}

impl CleanupTarget {
    /// 安定した snake_case 名（構造化ログのキー値に使う）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ImageRootfs => "image_rootfs",
            Self::SupervisorLog => "supervisor_log",
            Self::ContainerLog => "container_log",
            Self::ImageRef => "image_ref",
        }
    }
}

/// [`ContainerRuntime::delete`] の応答。delete の後始末（rootfs・ログ）の結果を載せる
/// （OCI-7・CRI-2・SUP-7・REPAIR-4。#2633）。
///
/// 各欄は既定で [`CleanupOutcome::NotApplicable`]。埋める層は欄ごとに異なる:
/// - `image_rootfs`: core の delete（記録の無い rootfs は `NotApplicable`）
/// - `image_ref`: イメージ参照の解除つき delete（`delete_releasing_image_ref`。OCI-7。通常の delete は `NotApplicable`）
/// - `supervisor_log`・`container_log`: ログを消す層（`fandhe-container-plugin-cri`・CLI の `delete`）。
///   CLI も `finish_delete` で埋める（警告の 1 行 JSON は CLI 自前の形式。#2698）
///
/// 後始末の失敗は `Err` にせず `Kept` として載せる。RPC 境界（#1869 の設計。承認と実装 issue の起票は #2232）の DTO への追加は未実装。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteResponse {
    image_rootfs: CleanupOutcome,
    supervisor_log: CleanupOutcome,
    container_log: CleanupOutcome,
    image_ref: CleanupOutcome,
}

impl DeleteResponse {
    /// 全欄 `NotApplicable` の応答を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// イメージ由来 rootfs の後始末の結果を設定する。
    pub fn with_image_rootfs(mut self, outcome: CleanupOutcome) -> Self {
        self.image_rootfs = outcome;
        self
    }

    /// supervisor ログの後始末の結果を設定する。
    pub fn with_supervisor_log(mut self, outcome: CleanupOutcome) -> Self {
        self.supervisor_log = outcome;
        self
    }

    /// コンテナログの後始末の結果を設定する。
    pub fn with_container_log(mut self, outcome: CleanupOutcome) -> Self {
        self.container_log = outcome;
        self
    }

    /// イメージストア側のコンテナ参照の解除の結果を設定する（OCI-7・REPAIR-4）。
    pub fn with_image_ref(mut self, outcome: CleanupOutcome) -> Self {
        self.image_ref = outcome;
        self
    }

    /// イメージ由来 rootfs の後始末の結果。
    pub fn image_rootfs(&self) -> CleanupOutcome {
        self.image_rootfs
    }

    /// supervisor ログの後始末の結果。
    pub fn supervisor_log(&self) -> CleanupOutcome {
        self.supervisor_log
    }

    /// コンテナログの後始末の結果。
    pub fn container_log(&self) -> CleanupOutcome {
        self.container_log
    }

    /// イメージストア側のコンテナ参照の解除の結果。解除つき delete だけが埋める。
    pub fn image_ref(&self) -> CleanupOutcome {
        self.image_ref
    }

    /// 残した資源を固定順（rootfs・supervisor ログ・コンテナログ・イメージ参照）で返す。
    pub fn kept(&self) -> impl Iterator<Item = (CleanupTarget, ErrorCode)> {
        [
            (CleanupTarget::ImageRootfs, self.image_rootfs),
            (CleanupTarget::SupervisorLog, self.supervisor_log),
            (CleanupTarget::ContainerLog, self.container_log),
            (CleanupTarget::ImageRef, self.image_ref),
        ]
        .into_iter()
        .filter_map(|(t, o)| match o {
            CleanupOutcome::Kept { code } => Some((t, code)),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// CRI-2・SUP-4（#2671）: `ContainerLogPath` の受理と拒否。
    #[test]
    fn container_log_path_validation() {
        let ok = ContainerLogPath::new("/var/log/pods/ns_p_uid/c/0.log").expect("ok");
        assert_eq!(ok.as_str(), "/var/log/pods/ns_p_uid/c/0.log");
        let long_ok = format!("/{}", "a".repeat(CONTAINER_LOG_PATH_MAX_BYTES - 1));
        assert!(ContainerLogPath::new(long_ok).is_ok());
        let too_long = format!("/{}", "a".repeat(CONTAINER_LOG_PATH_MAX_BYTES));
        for bad in [
            "",
            "/",
            "rel/x.log",
            "/a/../b",
            "/a/./b",
            "/a//b",
            "/a/b/",
            "/a/\0b",
            "/a/\nb",
            "/a/\rb",
            too_long.as_str(),
        ] {
            let e = ContainerLogPath::new(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad:?}");
        }
    }

    /// CRI-2・SUP-4（#2671）: `StartRequest` は既定で書き先なし、付けると返す。
    #[test]
    fn start_request_log_path_roundtrip() {
        let id = sample_id();
        assert!(StartRequest::new(id.clone()).log_path().is_none());
        let lp = ContainerLogPath::new("/l/c/0.log").expect("ok");
        let req = StartRequest::new(id).with_log_path(lp.clone());
        assert_eq!(req.log_path(), Some(&lp));
    }

    /// テスト用のスタブ実装。dyn 互換性と各メソッドの戻り値を確認するためのみに使う。
    struct StubRuntime;

    impl ContainerRuntime for StubRuntime {
        fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::created(req.id().clone(), None))
        }

        fn start(&self, req: &StartRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::running(
                req.id().clone(),
                Some(NonZeroU32::new(42).expect("42 is nonzero")),
            ))
        }

        fn kill(&self, req: &KillRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::running(req.id().clone(), None))
        }

        fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::stopped(req.id().clone(), Some(0)))
        }

        fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            if !req.force() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is still running",
                ));
            }
            Ok(DeleteResponse::new())
        }

        fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::running(req.id().clone(), None))
        }
    }

    /// CRI-2・REPAIR-3: OOM の停止は終了コードと独立に理由を持ち、他の状態は持たない。
    #[test]
    fn cri_2_stopped_with_reason_carries_oom() {
        let s = ContainerStatus::stopped_with_reason(
            sample_id(),
            Some(137),
            TerminationReason::OomKilled,
        );
        assert_eq!(s.state(), ContainerState::Stopped);
        assert_eq!(s.exit_code(), Some(137));
        assert_eq!(s.termination_reason(), Some(TerminationReason::OomKilled));
        assert_eq!(
            ContainerStatus::stopped(sample_id(), Some(0)).termination_reason(),
            None
        );
        assert_eq!(
            ContainerStatus::running(sample_id(), None).termination_reason(),
            None
        );
    }

    /// CRI-2: 終了理由の文字列表現は往復し、未知の値は拒否する。
    #[test]
    fn cri_2_termination_reason_str_roundtrip() {
        assert_eq!(TerminationReason::OomKilled.as_str(), "oomKilled");
        assert_eq!(
            TerminationReason::parse("oomKilled"),
            Some(TerminationReason::OomKilled)
        );
        assert_eq!(TerminationReason::parse("OOMKilled"), None);
        assert_eq!(TerminationReason::parse(""), None);
    }

    fn sample_id() -> ContainerId {
        ContainerId::new("sample-container").expect("valid id")
    }

    #[cfg(unix)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from("/run/x")
    }

    #[cfg(windows)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from(r"C:\x")
    }

    /// CRI-7: `ContainerRuntime` は dyn 互換で、`Box`/`Arc` に収めて各メソッドを呼べる。
    #[test]
    fn cri7_container_runtime_is_dyn_compatible() {
        let boxed: Box<dyn ContainerRuntime> = Box::new(StubRuntime);
        let req = CreateRequest::new(sample_id(), sample_bundle()).expect("absolute bundle");
        let status = boxed.create(&req).expect("create succeeds");
        assert_eq!(status.state(), ContainerState::Created);

        let shared: Arc<dyn ContainerRuntime> = Arc::new(StubRuntime);
        let start_status = shared
            .start(&StartRequest::new(sample_id()))
            .expect("start succeeds");
        assert_eq!(start_status.state(), ContainerState::Running);
        assert_eq!(start_status.pid().map(NonZeroU32::get), Some(42));
    }

    /// CRI-7: スタブの `state` が `ContainerState::Running` を返し、`as_str()` が "running"。
    #[test]
    fn cri7_state_as_str_is_running() {
        let runtime = StubRuntime;
        let status = runtime
            .state(&StateRequest::new(sample_id()))
            .expect("state succeeds");
        assert_eq!(status.state().as_str(), "running");
    }

    /// CRI-7: `CreateRequest::new` は相対パスを拒否し、絶対パスは受理する。
    #[test]
    fn cri7_create_request_rejects_relative_bundle() {
        let err = CreateRequest::new(sample_id(), PathBuf::from("bundle"))
            .expect_err("relative path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        assert!(CreateRequest::new(sample_id(), sample_bundle()).is_ok());
    }

    /// CRI-7: `Signal::new` は 0 と 65 以上を拒否し、`SIGTERM`/`SIGKILL` の値が正しい。
    #[test]
    fn cri7_signal_new_validates_range() {
        assert!(Signal::new(0).is_err());
        assert!(Signal::new(65).is_err());
        assert_eq!(Signal::new(15).unwrap(), Signal::SIGTERM);
        assert_eq!(Signal::SIGKILL.as_u8(), 9);
    }

    /// CRI-7: 前提条件違反時に返るエラーコードが具体文字列と一致する。
    #[test]
    fn cri7_delete_without_force_returns_failed_precondition() {
        let runtime = StubRuntime;
        let err = runtime
            .delete(&DeleteRequest::new(sample_id()))
            .expect_err("must fail without force");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");

        let ok = runtime
            .delete(&DeleteRequest::new(sample_id()).with_force(true))
            .expect("force delete succeeds");
        assert_eq!(ok, DeleteResponse::new());
    }

    /// CLI-1: Docker 表記のシグナルを具体値で解釈する。
    #[test]
    fn cli1_signal_parse_notation_accepts() {
        for (text, want) in [
            ("SIGKILL", 9),
            ("kill", 9),
            ("TERM", 15),
            ("sigusr1", 10),
            ("SIGRTMIN", 34),
            ("rtmin+1", 35),
            ("RTMIN+15", 49),
            ("SIGRTMAX-1", 63),
            ("RTMAX-14", 50),
            ("SIGRTMAX", 64),
            ("IOT", 6),
            ("CLD", 17),
            ("POLL", 29),
            ("10", 10),
            ("1", 1),
            ("64", 64),
        ] {
            assert_eq!(
                Signal::parse_notation(text).unwrap().as_u8(),
                want,
                "{text}"
            );
        }
    }

    /// CLI-1・ERR-1: 範囲外・予約・不正な表記は固定文言の `InvalidArgument` で拒否する。
    #[test]
    fn cli1_signal_parse_notation_rejects() {
        let long = "S".repeat(65);
        for text in [
            "",
            "0",
            "32",
            "33",
            "65",
            "256",
            "99999999999",
            "+15",
            "-1",
            " SIGTERM",
            "SIGTERM ",
            "SIGFOO",
            "SIG",
            "RTMIN+0",
            "RTMIN+16",
            "RTMAX-15",
            "RTMAX-0",
            "RTMIN+01",
            "RTMAX-01",
            "SIGRTMIN+09",
            "RTMIN+",
            "SIGNAL_SIGTERM",
            "ＳＩＧＫＩＬＬ",
            long.as_str(),
        ] {
            let err = Signal::parse_notation(text).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{text}");
            assert_eq!(err.message(), "signal is invalid", "{text}");
        }
    }

    /// REPAIR-5: `Signal::new` は境界値 1・64 を受理し、値が一致する。
    #[test]
    fn cri7_signal_new_accepts_boundary_values() {
        assert_eq!(Signal::new(1).expect("1 is valid").as_u8(), 1);
        assert_eq!(Signal::new(64).expect("64 is valid").as_u8(), 64);
    }

    /// REPAIR-5: `StopRequest::new` は `STOP_GRACE_MAX` 以下を受理し、
    /// それを超える猶予（`Duration::MAX` 相当の実質無期限値を含む）は
    /// `INVALID_ARGUMENT` として拒否する。
    #[test]
    fn cri7_stop_request_rejects_grace_beyond_max() {
        let ok = StopRequest::new(sample_id(), STOP_GRACE_MAX).expect("max grace is valid");
        assert_eq!(ok.grace(), STOP_GRACE_MAX);

        let err = StopRequest::new(sample_id(), STOP_GRACE_MAX + Duration::from_secs(1))
            .expect_err("beyond max must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let err_max = StopRequest::new(sample_id(), Duration::MAX)
            .expect_err("Duration::MAX must be rejected");
        assert_eq!(err_max.code().as_str(), "INVALID_ARGUMENT");
    }

    /// PLUG-1・CRI-2: `StopRequest` の停止シグナルの既定は SIGTERM。
    #[test]
    fn plug1_stop_request_default_signal_is_sigterm() {
        let req = StopRequest::new(sample_id(), Duration::from_secs(5)).expect("valid grace");
        assert_eq!(req.signal(), Signal::SIGTERM);
    }

    /// PLUG-1・CRI-2: `with_signal` は signal だけを差し替え、id と grace を保つ。
    #[test]
    fn plug1_stop_request_with_signal_round_trips() {
        let req = StopRequest::new(sample_id(), Duration::from_secs(5))
            .expect("valid grace")
            .with_signal(Signal::new(2).expect("2 is valid"));
        assert_eq!(req.signal().as_u8(), 2);
        assert_eq!(req.grace(), Duration::from_secs(5));
        assert_eq!(req.id(), &sample_id());
    }

    /// OCI Runtime Spec: `ContainerState::as_str` が全バリアントで規定の小文字文字列を返す。
    #[test]
    fn cri7_container_state_as_str_matches_all_variants() {
        assert_eq!(ContainerState::Creating.as_str(), "creating");
        assert_eq!(ContainerState::Created.as_str(), "created");
        assert_eq!(ContainerState::Running.as_str(), "running");
        assert_eq!(ContainerState::Stopped.as_str(), "stopped");
    }

    /// codex レビュー指摘（PR #1074）: `ContainerStatus` は状態ごとのコンストラクタに
    /// 限定されており、`Creating` に `pid`・`exit_code` が付かず、`Running`/`Stopped`
    /// に `exit_code`/`pid` が付かないことを固定する。
    #[test]
    fn cri7_container_status_constructors_restrict_field_combinations() {
        let creating = ContainerStatus::creating(sample_id());
        assert_eq!(creating.state(), ContainerState::Creating);
        assert_eq!(creating.pid(), None);
        assert_eq!(creating.exit_code(), None);

        let created = ContainerStatus::created(sample_id(), None);
        assert_eq!(created.state(), ContainerState::Created);
        assert_eq!(created.pid(), None);
        assert_eq!(created.exit_code(), None);

        let pid = NonZeroU32::new(7).expect("7 is nonzero");
        let running = ContainerStatus::running(sample_id(), Some(pid));
        assert_eq!(running.state(), ContainerState::Running);
        assert_eq!(running.pid(), Some(pid));
        assert_eq!(running.exit_code(), None);

        let stopped = ContainerStatus::stopped(sample_id(), Some(1));
        assert_eq!(stopped.state(), ContainerState::Stopped);
        assert_eq!(stopped.pid(), None);
        assert_eq!(stopped.exit_code(), Some(1));
    }

    /// codex レビュー指摘（PR #1074・P2）: 作成途中の失敗や異常終了等で終了コードを
    /// 取得できないまま停止状態だけが確認できるケースを、`exit_code: None` の
    /// `Stopped` として表現できることを固定する。
    #[test]
    fn cri7_container_status_stopped_can_have_unknown_exit_code() {
        let stopped = ContainerStatus::stopped(sample_id(), None);
        assert_eq!(stopped.state(), ContainerState::Stopped);
        assert_eq!(stopped.pid(), None);
        assert_eq!(stopped.exit_code(), None);
    }

    /// Bugbot 指摘（PR #1074 discussion_r4112017709）: OCI の `created` コンテナは
    /// runtime create 完了時点で init プロセスを既に fork 済みのため、
    /// `ContainerStatus::created` はその PID を保持でき、`state()` 経由で
    /// CRI / shim アダプタへ渡せることを固定する。
    #[test]
    fn cri7_container_status_created_can_carry_pid() {
        let pid = NonZeroU32::new(11).expect("11 is nonzero");
        let created = ContainerStatus::created(sample_id(), Some(pid));
        assert_eq!(created.state(), ContainerState::Created);
        assert_eq!(created.pid(), Some(pid));
        assert_eq!(created.exit_code(), None);
    }

    /// REPAIR-4: 既定の応答は全欄 `NotApplicable` で `kept()` が空。
    #[test]
    fn repair4_delete_response_defaults_to_not_applicable() {
        let r = DeleteResponse::new();
        assert_eq!(r, DeleteResponse::default());
        assert_eq!(r.image_rootfs(), CleanupOutcome::NotApplicable);
        assert_eq!(r.supervisor_log(), CleanupOutcome::NotApplicable);
        assert_eq!(r.container_log(), CleanupOutcome::NotApplicable);
        assert_eq!(r.image_ref(), CleanupOutcome::NotApplicable);
        assert_eq!(r.kept().count(), 0);
    }

    /// REPAIR-4: `with_*` の値が各 accessor に出て、`kept()` は `Kept` だけを固定順で返す。
    #[test]
    fn repair4_delete_response_builders_set_each_field() {
        let r = DeleteResponse::new()
            .with_container_log(CleanupOutcome::Kept {
                code: ErrorCode::FailedPrecondition,
            })
            .with_supervisor_log(CleanupOutcome::Removed)
            .with_image_ref(CleanupOutcome::Kept {
                code: ErrorCode::Internal,
            })
            .with_image_rootfs(CleanupOutcome::Kept {
                code: ErrorCode::Unimplemented,
            });
        assert_eq!(r.supervisor_log(), CleanupOutcome::Removed);
        let kept: Vec<_> = r.kept().collect();
        assert_eq!(
            kept,
            vec![
                (CleanupTarget::ImageRootfs, ErrorCode::Unimplemented),
                (CleanupTarget::ContainerLog, ErrorCode::FailedPrecondition),
                (CleanupTarget::ImageRef, ErrorCode::Internal),
            ]
        );
    }

    /// REPAIR-4: `CleanupTarget::as_str` は安定した名前を返す。
    #[test]
    fn repair4_cleanup_target_names_are_stable() {
        assert_eq!(CleanupTarget::ImageRootfs.as_str(), "image_rootfs");
        assert_eq!(CleanupTarget::SupervisorLog.as_str(), "supervisor_log");
        assert_eq!(CleanupTarget::ContainerLog.as_str(), "container_log");
        assert_eq!(CleanupTarget::ImageRef.as_str(), "image_ref");
    }
}
