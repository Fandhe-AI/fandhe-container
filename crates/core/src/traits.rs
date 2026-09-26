//! core が定義する拡張点トレイト群の置き場（CRI-7・PLUG-1）。
//!
//! `ContainerRuntime`・`StateStore`・`NetworkPlugin`・`VolumeProvider` の
//! 4 トレイトをここに定義し、上位 crate（cli・oci・cri 等）は具象型ではなく
//! これらのトレイト境界だけを通して呼び合う（TASK-4）。
//!
//! 本ファイルは TASK-4.2（`StateStore`）の範囲のみを実装する。他 3 トレイトは
//! 兄弟 issue（`ContainerRuntime`・`NetworkPlugin`・`VolumeProvider`）で追加される。
//! シグネチャは TASK-4.h1（アーキテクチャレビュー）の承認前であり、確定ではない。

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

/// `StateStore` が扱うコンテナ ID。
///
/// OCI-5 の状態ファイルパス（例: `/run/fandhe-container/<id>/state.json`）の
/// パス要素として使われるため、生成時に検証してパストラバーサル・不正値を
/// 型で排除する（security.md「パス要素は検証・正規化してからルート配下で
/// あることを確認する」・REPAIR-2「壊れた値を表現できない型」）。
///
/// 3 OS 一級対応（coding-rust.md「大文字小文字非区別・長パス・Unicode 正規化の
/// 差を考慮する」IO-5）のため、`new` で以下も保証する:
///
/// - ASCII 英数字を小文字へ正規化して保持する（macOS 既定 FS・Windows は
///   大文字小文字非区別のため、`"Foo"` と `"foo"` が異なるディレクトリへ
///   解決される Linux 側の前提のまま TASK-31 のパス要素へ使うと、同一ファイル
///   への衝突・状態の混線を招く）
/// - Windows 予約デバイス名（`con`/`nul`/`aux`/`prn`/`com1`-`com9`/
///   `lpt1`-`lpt9`。拡張子付き・大文字小文字を問わない）を拒否する
///   （該当パスは Windows 上でディレクトリ作成自体に失敗するため）
/// - 末尾が `.` で終わる値を拒否する（Win32 のパス正規化で末尾の `.` が
///   剥離され、想定と異なるパスに解決されるため）
///
/// 上記はパス要素として安全な範囲に限定した検証であり、Unicode 正規化
/// （NFC/NFD 差異）を伴う ID は現状 ASCII 英数字と `_-.+` のみ許可することで
/// 範囲外としている（未対応。将来 Unicode ID を許可する場合は別途対応する）。
///
/// 長さ上限（128 バイト）は暫定値。TASK-31（ファイルベース既定実装）で
/// 実際のパス長制約に合わせて見直してよい。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    /// コンテナ ID の長さ上限（バイト）。TASK-31 で見直す可能性がある暫定値。
    pub const MAX_LEN: usize = 128;

    /// Windows 予約デバイス名（拡張子を除いた先頭部分・小文字比較）。
    /// これらをパス要素にすると Windows 上でファイル / ディレクトリ操作が
    /// 失敗する（例: `CreateFileW` が `ERROR_INVALID_NAME` 相当を返す）。
    const WINDOWS_RESERVED_NAMES: &'static [&'static str] = &[
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];

    /// 文字列からコンテナ ID を検証付きで生成する。
    ///
    /// 受理: 空でない・`Self::MAX_LEN` バイト以下・ASCII 英数字と
    /// `_` `-` `.` `+` のみで構成される・`.`/`..` そのものではない・
    /// 末尾が `.` でない・Windows 予約デバイス名（拡張子付き・大文字小文字を
    /// 問わない）でない。上記を満たさない場合は `StateStoreError::InvalidId`
    /// を返す。受理された値は ASCII 英数字を小文字へ正規化して保持する
    /// （3 OS でのファイルシステム衝突を防ぐため。型ドキュメント参照）。
    pub fn new(id: impl Into<String>) -> Result<Self, StateStoreError> {
        let id = id.into();

        if id.is_empty() {
            return Err(StateStoreError::InvalidId {
                reason: "container id must not be empty".to_string(),
            });
        }
        if id.len() > Self::MAX_LEN {
            return Err(StateStoreError::InvalidId {
                reason: format!("container id must be at most {} bytes", Self::MAX_LEN),
            });
        }
        if id == "." || id == ".." {
            return Err(StateStoreError::InvalidId {
                reason: "container id must not be \".\" or \"..\"".to_string(),
            });
        }
        if id.ends_with('.') {
            return Err(StateStoreError::InvalidId {
                reason: "container id must not end with '.'".to_string(),
            });
        }
        let is_valid_char =
            |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+');
        if !id.chars().all(is_valid_char) {
            return Err(StateStoreError::InvalidId {
                reason: "container id must contain only ASCII alphanumerics, '_', '-', '.', '+'"
                    .to_string(),
            });
        }

        let normalized = id.to_ascii_lowercase();
        let stem = normalized.split('.').next().unwrap_or(normalized.as_str());
        if Self::WINDOWS_RESERVED_NAMES.contains(&stem) {
            return Err(StateStoreError::InvalidId {
                reason: format!("container id must not be a Windows reserved device name: {stem}"),
            });
        }

        Ok(Self(normalized))
    }

    /// 内部の文字列表現を借用で返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// コンテナのライフサイクル状態。OCI Runtime Specification の state status に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    /// 生成処理中（`create` 呼び出しの途中）。
    Creating,
    /// 生成済みで未起動。
    Created,
    /// 実行中。
    Running,
    /// 終了済み。
    Stopped,
}

/// supervisor（コンテナごとの軽量監視プロセス）から見たコンテナの健全性。
///
/// `docs/design/crate-naming.md` 決定 6 に基づき、`state.json` の形式・
/// supervisor が使う項目（`supervisor_pid`・`health`・`restart_count`）を
/// core の状態型（`ContainerState`）に含める。判定ロジック（ヘルスチェックの
/// 実行方法・間隔等）は TASK-157 の範囲であり、本トレイトは値の置き場のみを
/// 定義する（REPAIR-3: 未実装範囲の明示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthStatus {
    /// 未判定（supervisor がまだヘルスチェックを実行していない、または
    /// ヘルスチェックが設定されていないコンテナの既定値）。
    #[default]
    Unknown,
    /// 健全。
    Healthy,
    /// 不健全（supervisor の再起動判断に使われる。TASK-157）。
    Unhealthy,
}

/// `StateStore` が永続化・取得するコンテナ状態の 1 レコード。
///
/// 永続化形式（JSON 等）はこのトレイトの契約に含めない。ファイルベース
/// 既定実装の形式決定は TASK-31（OCI-5）の責務。
///
/// フィールドは非公開とし、`new` の検証を経ないと値を作れない（「壊れた値を
/// 表現できない型」。coding-rust.md・REPAIR-2）。`create`/`update`（`&dyn
/// StateStore` 経由の plugin 実装を含む）は `ContainerState` を受け取る時点で
/// 既にライフサイクル整合性が保証されるため、トレイト実装側で個別に
/// pid / status / bundle の整合性を再検証する必要はない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    /// 対象とする OCI Runtime Specification のバージョン文字列。
    oci_version: String,
    /// コンテナ ID。
    id: ContainerId,
    /// ライフサイクル状態。
    status: ContainerStatus,
    /// コンテナプロセスの PID。`Running` のときは必ず `Some`、`Creating`/
    /// `Stopped` のときは必ず `None`（`Created` はプロセスが未起動なら
    /// `None`、fork 済みなら `Some` のどちらも許容する）。
    pid: Option<u32>,
    /// バンドルディレクトリの絶対パス。
    bundle: PathBuf,
    /// 任意のアノテーション。
    annotations: BTreeMap<String, String>,
    /// supervisor（コンテナごとの監視プロセス）自身の PID。supervisor が
    /// 未起動、またはこの状態を扱う実装が supervisor と無関係な場合は
    /// `None`（決定 6・TASK-157）。
    supervisor_pid: Option<u32>,
    /// supervisor が判定したヘルスチェック結果（決定 6・TASK-157）。
    health: HealthStatus,
    /// supervisor によるコンテナプロセスの再起動回数（決定 6・TASK-157）。
    restart_count: u32,
}

impl ContainerState {
    /// `oci_version` の長さ上限（バイト）。OCI Runtime Specification の
    /// バージョン文字列（例: `"1.0.2"`）を想定した暫定値で、TASK-31 で
    /// 見直してよい。
    pub const MAX_OCI_VERSION_LEN: usize = 32;
    /// `bundle` パスの長さ上限（バイト）。Linux の一般的な `PATH_MAX`
    /// （4096 バイト）に合わせた暫定値。3 OS 対応の長パス方針（IO-5）は
    /// TASK-31 で見直す。
    pub const MAX_BUNDLE_LEN: usize = 4096;
    /// `annotations` の件数上限。無制限確保による DoS を防ぐ
    /// （security.md「長さ・件数を上限検証してからアロケーションに使う」）。
    pub const MAX_ANNOTATION_COUNT: usize = 256;
    /// アノテーション 1 件あたりのキーの長さ上限（バイト）。
    pub const MAX_ANNOTATION_KEY_LEN: usize = 256;
    /// アノテーション 1 件あたりの値の長さ上限（バイト）。
    pub const MAX_ANNOTATION_VALUE_LEN: usize = 4096;

    /// 検証済みの `ContainerState` を生成する。
    ///
    /// 検証項目（違反時は `StateStoreError::InvalidState` を返す）:
    /// - `status` が `Running` のとき `pid` は `Some` でなければならず、
    ///   `0` はコンテナプロセスを指せないため許容しない
    /// - `status` が `Creating`/`Stopped` のとき `pid` は `None` でなければ
    ///   ならない（`Created` は制約なし）
    /// - `bundle` は絶対パスでなければならない（相対パスは OCI-5 の状態
    ///   ファイルからの再構成時に基準ディレクトリへ依存し曖昧になるため）
    /// - `oci_version` は `Self::MAX_OCI_VERSION_LEN` バイト以下・空でない・
    ///   `<数字>(.<数字>)*`（1 個以上のドット区切り数字列）の形式であること
    /// - `bundle` は `Self::MAX_BUNDLE_LEN` バイト以下であること
    /// - `annotations` は `Self::MAX_ANNOTATION_COUNT` 件以下、各キーは
    ///   `Self::MAX_ANNOTATION_KEY_LEN` バイト以下、各値は
    ///   `Self::MAX_ANNOTATION_VALUE_LEN` バイト以下であること
    ///
    /// 外部入力（イメージ・CRI リクエスト等）から状態を構築する経路で
    /// 巨大な値を無制限に受け入れないための検証（security.md・
    /// coding-rust.md「長さ・件数を上限検証してからアロケーションに使う」）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        oci_version: impl Into<String>,
        id: ContainerId,
        status: ContainerStatus,
        pid: Option<u32>,
        bundle: PathBuf,
        annotations: BTreeMap<String, String>,
        supervisor_pid: Option<u32>,
        health: HealthStatus,
        restart_count: u32,
    ) -> Result<Self, StateStoreError> {
        let oci_version = oci_version.into();

        match (status, pid) {
            (ContainerStatus::Running, None) => {
                return Err(StateStoreError::InvalidState {
                    reason: "pid must be Some when status is Running".to_string(),
                });
            }
            (ContainerStatus::Running, Some(0)) => {
                return Err(StateStoreError::InvalidState {
                    reason: "pid must not be 0 when status is Running".to_string(),
                });
            }
            (ContainerStatus::Creating, Some(_)) => {
                return Err(StateStoreError::InvalidState {
                    reason: "pid must be None when status is Creating".to_string(),
                });
            }
            (ContainerStatus::Stopped, Some(_)) => {
                return Err(StateStoreError::InvalidState {
                    reason: "pid must be None when status is Stopped".to_string(),
                });
            }
            _ => {}
        }
        if !bundle.is_absolute() {
            return Err(StateStoreError::InvalidState {
                reason: "bundle must be an absolute path".to_string(),
            });
        }
        let bundle_len = bundle.as_os_str().len();
        if bundle_len > Self::MAX_BUNDLE_LEN {
            return Err(StateStoreError::InvalidState {
                reason: format!("bundle must be at most {} bytes", Self::MAX_BUNDLE_LEN),
            });
        }
        Self::validate_oci_version(&oci_version)?;
        if annotations.len() > Self::MAX_ANNOTATION_COUNT {
            return Err(StateStoreError::InvalidState {
                reason: format!(
                    "annotations must contain at most {} entries",
                    Self::MAX_ANNOTATION_COUNT
                ),
            });
        }
        for (key, value) in &annotations {
            if key.len() > Self::MAX_ANNOTATION_KEY_LEN {
                return Err(StateStoreError::InvalidState {
                    reason: format!(
                        "annotation key must be at most {} bytes",
                        Self::MAX_ANNOTATION_KEY_LEN
                    ),
                });
            }
            if value.len() > Self::MAX_ANNOTATION_VALUE_LEN {
                return Err(StateStoreError::InvalidState {
                    reason: format!(
                        "annotation value must be at most {} bytes",
                        Self::MAX_ANNOTATION_VALUE_LEN
                    ),
                });
            }
        }

        Ok(Self {
            oci_version,
            id,
            status,
            pid,
            bundle,
            annotations,
            supervisor_pid,
            health,
            restart_count,
        })
    }

    /// `oci_version` が OCI Runtime Specification のバージョン文字列として
    /// 妥当な形式（空でない・`Self::MAX_OCI_VERSION_LEN` バイト以下・
    /// 1 個以上のドット区切り数字列。例: `"1.0.2"`）かを検証する。
    fn validate_oci_version(oci_version: &str) -> Result<(), StateStoreError> {
        if oci_version.is_empty() {
            return Err(StateStoreError::InvalidState {
                reason: "oci_version must not be empty".to_string(),
            });
        }
        if oci_version.len() > Self::MAX_OCI_VERSION_LEN {
            return Err(StateStoreError::InvalidState {
                reason: format!(
                    "oci_version must be at most {} bytes",
                    Self::MAX_OCI_VERSION_LEN
                ),
            });
        }
        let is_valid = oci_version
            .split('.')
            .all(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()));
        if !is_valid {
            return Err(StateStoreError::InvalidState {
                reason: "oci_version must be a dot-separated numeric version (e.g. \"1.0.2\")"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// 対象とする OCI Runtime Specification のバージョン文字列。
    pub fn oci_version(&self) -> &str {
        &self.oci_version
    }

    /// コンテナ ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// ライフサイクル状態。
    pub fn status(&self) -> ContainerStatus {
        self.status
    }

    /// コンテナプロセスの PID（`new` の検証によりステータスとの整合性が
    /// 保証されている。型ドキュメント参照）。
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// バンドルディレクトリの絶対パス。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    /// 任意のアノテーション。
    pub fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }

    /// supervisor 自身の PID（決定 6・TASK-157）。
    pub fn supervisor_pid(&self) -> Option<u32> {
        self.supervisor_pid
    }

    /// supervisor が判定したヘルスチェック結果（決定 6・TASK-157）。
    pub fn health(&self) -> HealthStatus {
        self.health
    }

    /// supervisor によるコンテナプロセスの再起動回数（決定 6・TASK-157）。
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }
}

/// `StateStore` の操作が失敗した理由。
///
/// バリアントは今後追加され得るため `#[non_exhaustive]` とし、
/// 呼び出し側は `_` アームでの網羅を必須にする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateStoreError {
    /// `ContainerId` の検証に失敗した。
    InvalidId {
        /// 検証に失敗した理由（英語・資格情報やホスト固有情報を含まない）。
        reason: String,
    },
    /// `ContainerState::new` の検証に失敗した（status と pid の不整合・
    /// `bundle` が相対パス等）。
    InvalidState {
        /// 検証に失敗した理由（英語）。
        reason: String,
    },
    /// 指定した ID のコンテナ状態が見つからない。
    NotFound {
        /// 見つからなかったコンテナ ID。
        id: ContainerId,
    },
    /// `create` 対象の ID が既に存在する（OCI-4 の既存チェック）。
    AlreadyExists {
        /// 既に存在するコンテナ ID。
        id: ContainerId,
    },
    /// 永続化されたデータが破損しており復元できない。
    Corrupted {
        /// 破損が見つかったコンテナ ID。
        id: ContainerId,
        /// 破損の理由（英語）。
        reason: String,
    },
    /// I/O エラー。資格情報や完全なホストパスは含めない。
    Io {
        /// エラーの理由（英語）。
        reason: String,
    },
    /// 応答待ちがタイムアウトした（plugin 越しの実装等。REPAIR-5）。
    Timeout,
    /// バックエンドが一時的に利用できない。
    Unavailable {
        /// 利用できない理由（英語）。
        reason: String,
    },
}

impl StateStoreError {
    /// 機械可読なエラーコードを返す（ERR-1。ログ・CLI 終了コードとの対応付けに使う）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidId { .. } => "INVALID_ID",
            Self::InvalidState { .. } => "INVALID_STATE",
            Self::NotFound { .. } => "NOT_FOUND",
            Self::AlreadyExists { .. } => "ALREADY_EXISTS",
            Self::Corrupted { .. } => "CORRUPTED",
            Self::Io { .. } => "IO",
            Self::Timeout => "TIMEOUT",
            Self::Unavailable { .. } => "UNAVAILABLE",
        }
    }
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { reason } => write!(f, "invalid container id: {reason}"),
            Self::InvalidState { reason } => write!(f, "invalid container state: {reason}"),
            Self::NotFound { id } => write!(f, "container state not found: {id}"),
            Self::AlreadyExists { id } => write!(f, "container state already exists: {id}"),
            Self::Corrupted { id, reason } => {
                write!(f, "container state corrupted for {id}: {reason}")
            }
            Self::Io { reason } => write!(f, "state store io error: {reason}"),
            Self::Timeout => write!(f, "state store operation timed out"),
            Self::Unavailable { reason } => write!(f, "state store unavailable: {reason}"),
        }
    }
}

impl Error for StateStoreError {}

/// `StateStore::list` が 1 回の呼び出しで返す最大件数。
///
/// 無制限確保による DoS を防ぐための上限（security.md「長さ・件数を上限
/// 検証してからアロケーションに使う」）。実装はこれを超える件数を 1 ページ
/// に詰め込んではならない。
pub const LIST_PAGE_LIMIT: usize = 1024;

/// `StateStore::list` の 1 ページ分の結果。
///
/// `next_cursor` が `Some` の場合はまだ残りがあることを示し、続きは
/// `list(next_cursor.as_ref())` で取得できる。`None` は末尾まで返し終えた
/// ことを示す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerIdPage {
    /// このページに含まれるコンテナ ID（`LIST_PAGE_LIMIT` 件以下）。
    pub ids: Vec<ContainerId>,
    /// 次ページの開始位置。末尾まで返し終えた場合は `None`。
    pub next_cursor: Option<ContainerId>,
}

/// コンテナ状態の永続化・取得を抽象化するトレイト（CRI-7・PLUG-1）。
///
/// 境界の配置（2026-09-26 決定。`docs/design/crate-naming.md` 決定 6・
/// spec の `plugin-system.md` 境界表・PLUG-1・OCI-5 に基づく。Issue #16 本文は
/// 「実装は plugin 側」と書いているが、上記 SSOT が優先されるためここでは
/// 以下の 3 点で扱う）:
///
/// - トレイト定義: 本 crate（core。CRI-7・PLUG-1）
/// - ファイルベースの既定実装: 本 crate（core。OCI-5・TASK-31。常駐デーモンを
///   持たない CORE-1 と整合させるため、CLI・supervisor・`create`/`delete` の
///   全経路がこの既定実装を使う）
/// - 別実装（分散ストア等）: plugin として差し替え可能（PLUG-1・TASK-114）
///
/// データパス（コンテナのファイル I/O）ではなく制御面の境界を表す（PoC-13）。
///
/// このトレイトは object-safe であり、`Box<dyn StateStore>` / `&dyn StateStore`
/// 経由で plugin 実装へ差し替えられる想定（PLUG-1）。プロセス境界を越える
/// 実装は応答待ちに必ずタイムアウトを設け、`StateStoreError::Timeout` を
/// 返すこと（REPAIR-5）。`create`/`delete` の原子性・排他の詳細は既定実装
/// （TASK-31）が決める。
///
/// 現時点ではコンテナ単位の状態のみを扱い、CRI の Pod サンドボックス状態は
/// 対象外（将来拡張。TASK-114・CRI-7 で扱う。REPAIR-3 に基づきスタブ範囲を
/// 明示する）。ファイルベースの既定実装自体は未提供（TASK-31 で実装する）。
pub trait StateStore: Send + Sync {
    /// 新しいコンテナ状態を永続化する（OCI-4 の生成時チェックに対応）。
    ///
    /// `state.id` が既に存在する場合は `StateStoreError::AlreadyExists` を返す。
    fn create(&self, state: &ContainerState) -> Result<(), StateStoreError>;

    /// 指定した ID のコンテナ状態を取得する。
    ///
    /// 見つからない場合は `StateStoreError::NotFound` を返す。
    fn load(&self, id: &ContainerId) -> Result<ContainerState, StateStoreError>;

    /// 既存のコンテナ状態を更新する。
    ///
    /// `state.id` が存在しない場合は `StateStoreError::NotFound` を返す。
    fn update(&self, state: &ContainerState) -> Result<(), StateStoreError>;

    /// 指定した ID のコンテナ状態を削除する（OCI-6 の削除処理に対応）。
    ///
    /// 見つからない場合は `StateStoreError::NotFound` を返す。
    fn delete(&self, id: &ContainerId) -> Result<(), StateStoreError>;

    /// 永続化されているコンテナ ID を 1 ページ分列挙する。
    ///
    /// `after` に前回取得した `ContainerIdPage::next_cursor` を渡すと、その
    /// 続き（`after` より後の ID）から返す。`None` は先頭から返す。
    /// 実装は 1 回の呼び出しで返す件数を `LIST_PAGE_LIMIT` 以下に制限し
    /// （無制限確保による DoS を防ぐ。security.md）、上限に達してもまだ
    /// 残りがある場合は `next_cursor` に次ページの開始位置（`Some`）を
    /// 設定する。全件を取りこぼさず列挙するには、呼び出し側が
    /// `next_cursor` が `None` になるまでループする必要がある
    /// （全件列挙の契約は「1 回の呼び出し」ではなく「ページングの完了」で
    /// 満たされる）。破損したエントリを読んでも panic しないこと。
    fn list(&self, after: Option<&ContainerId>) -> Result<ContainerIdPage, StateStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as StdBTreeMap;
    use std::sync::Mutex;

    /// テスト専用の in-memory `StateStore` 二重体。
    ///
    /// TASK-31 のファイルベース既定実装とは別物であり、本テストの
    /// トレイト契約検証にのみ使う。
    struct InMemoryStateStore {
        entries: Mutex<StdBTreeMap<ContainerId, ContainerState>>,
    }

    impl InMemoryStateStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(StdBTreeMap::new()),
            }
        }
    }

    impl StateStore for InMemoryStateStore {
        fn create(&self, state: &ContainerState) -> Result<(), StateStoreError> {
            let mut entries = self.entries.lock().expect("test mutex poisoned");
            if entries.contains_key(state.id()) {
                return Err(StateStoreError::AlreadyExists {
                    id: state.id().clone(),
                });
            }
            entries.insert(state.id().clone(), state.clone());
            Ok(())
        }

        fn load(&self, id: &ContainerId) -> Result<ContainerState, StateStoreError> {
            let entries = self.entries.lock().expect("test mutex poisoned");
            entries
                .get(id)
                .cloned()
                .ok_or_else(|| StateStoreError::NotFound { id: id.clone() })
        }

        fn update(&self, state: &ContainerState) -> Result<(), StateStoreError> {
            let mut entries = self.entries.lock().expect("test mutex poisoned");
            if !entries.contains_key(state.id()) {
                return Err(StateStoreError::NotFound {
                    id: state.id().clone(),
                });
            }
            entries.insert(state.id().clone(), state.clone());
            Ok(())
        }

        fn delete(&self, id: &ContainerId) -> Result<(), StateStoreError> {
            let mut entries = self.entries.lock().expect("test mutex poisoned");
            entries
                .remove(id)
                .map(|_| ())
                .ok_or_else(|| StateStoreError::NotFound { id: id.clone() })
        }

        fn list(&self, after: Option<&ContainerId>) -> Result<ContainerIdPage, StateStoreError> {
            let entries = self.entries.lock().expect("test mutex poisoned");
            let range = match after {
                Some(cursor) => entries.range((
                    std::ops::Bound::Excluded(cursor.clone()),
                    std::ops::Bound::Unbounded,
                )),
                None => entries.range(..),
            };

            // `next_cursor` は「実際にこのページへ積んだ最後の ID」でなければ
            // ならない。先読みした（ページに積まなかった）ID を cursor にすると、
            // その ID は次ページでも Excluded 側の境界に消費され、どのページにも
            // 現れないまま失われる（このバグは修正前に発生していた）。
            let mut iter = range.peekable();
            let mut ids = Vec::new();
            while ids.len() < LIST_PAGE_LIMIT {
                match iter.next() {
                    Some((id, _)) => ids.push(id.clone()),
                    None => break,
                }
            }
            let next_cursor = if iter.peek().is_some() {
                ids.last().cloned()
            } else {
                None
            };
            Ok(ContainerIdPage { ids, next_cursor })
        }
    }

    /// テスト用の絶対パスのバンドルディレクトリ。`ContainerState::new` は
    /// `Path::is_absolute()` で判定するため、Windows では Unix 形式の
    /// パス（ドライブプレフィックスなし）が相対パス扱いになり検証に失敗する
    /// （3 OS 一級対応。IO-5）。OS ごとに絶対パスとして解決される値を返す。
    fn test_bundle_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\fandhe-container\bundle")
        } else {
            PathBuf::from("/run/fandhe-container/bundle")
        }
    }

    fn sample_state(id: &str) -> ContainerState {
        ContainerState::new(
            "1.0.2",
            ContainerId::new(id).expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            test_bundle_path(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect("valid state in test fixture")
    }

    /// `list` の全ページを走査し、全コンテナ ID を昇順で返すテストヘルパー。
    fn list_all(store: &dyn StateStore) -> Vec<ContainerId> {
        let mut ids = Vec::new();
        let mut cursor: Option<ContainerId> = None;
        loop {
            let page = store.list(cursor.as_ref()).expect("list should succeed");
            let reached_end = page.next_cursor.is_none();
            ids.extend(page.ids);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => {
                    assert!(reached_end);
                    break;
                }
            }
        }
        ids
    }

    // object safety の確認（PLUG-1: `&dyn StateStore` として plugin アダプタに
    // 差し替えられることを保証する）。
    fn assert_obj(_: &dyn StateStore) {}

    fn assert_send_sync<T: Send + Sync + ?Sized>() {}

    #[test]
    fn cri7_state_store_is_object_safe_and_send_sync() {
        let store = InMemoryStateStore::new();
        assert_obj(&store);
        assert_send_sync::<dyn StateStore>();
    }

    #[test]
    fn cri7_create_then_load_returns_same_value() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let state = sample_state("abc123");
        store.create(&state).expect("create should succeed");
        let loaded = store.load(state.id()).expect("load should succeed");
        assert_eq!(loaded, state);
    }

    #[test]
    fn cri7_create_twice_returns_already_exists() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let state = sample_state("abc123");
        store.create(&state).expect("first create should succeed");
        let err = store.create(&state).expect_err("second create should fail");
        assert_eq!(err.code(), "ALREADY_EXISTS");
    }

    #[test]
    fn oci5_load_missing_id_returns_not_found() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let id = ContainerId::new("missing").expect("valid id in test fixture");
        let err = store.load(&id).expect_err("load should fail");
        assert_eq!(err.code(), "NOT_FOUND");
    }

    #[test]
    fn oci5_update_missing_id_returns_not_found() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let state = sample_state("missing");
        let err = store.update(&state).expect_err("update should fail");
        assert_eq!(err.code(), "NOT_FOUND");
    }

    #[test]
    fn oci6_delete_missing_id_returns_not_found() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let id = ContainerId::new("missing").expect("valid id in test fixture");
        let err = store.delete(&id).expect_err("delete should fail");
        assert_eq!(err.code(), "NOT_FOUND");
    }

    #[test]
    fn oci6_list_is_empty_after_delete() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let state = sample_state("abc123");
        store.create(&state).expect("create should succeed");
        store.delete(state.id()).expect("delete should succeed");
        let page = store.list(None).expect("list should succeed");
        assert_eq!(page.ids, Vec::<ContainerId>::new());
        assert_eq!(page.next_cursor, None);
    }

    /// CRI-7: `list` は 1 ページの上限（`LIST_PAGE_LIMIT`）を超える件数を
    /// 1 回の呼び出しで返さず、`next_cursor` で残りを示す。呼び出し側が
    /// `next_cursor` を使って全ページを辿ればコンテナを見落とさない
    /// （全件列挙の契約とページングの両立）。
    #[test]
    fn cri7_list_paginates_beyond_page_limit() {
        let store: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        let total = LIST_PAGE_LIMIT + 5;
        for i in 0..total {
            let state = sample_state(&format!("c{i:05}"));
            store.create(&state).expect("create should succeed");
        }

        let first_page = store.list(None).expect("list should succeed");
        assert_eq!(first_page.ids.len(), LIST_PAGE_LIMIT);
        assert!(first_page.next_cursor.is_some());

        let all_ids = list_all(store.as_ref());
        assert_eq!(all_ids.len(), total);
        let mut sorted = all_ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            total,
            "list_all must not miss or duplicate ids"
        );
    }

    #[test]
    fn container_id_accepts_valid_values() {
        assert!(ContainerId::new("abc123").is_ok());
        assert!(ContainerId::new("my-app_1.0").is_ok());
        assert!(ContainerId::new("a".repeat(ContainerId::MAX_LEN)).is_ok());
    }

    #[test]
    fn container_id_rejects_invalid_values() {
        let cases = ["", ".", "..", "a/b", "a\\b", "a\0b", "a b", "コンテナ"];
        for case in cases {
            let err = ContainerId::new(case).expect_err("value must be rejected");
            assert_eq!(err.code(), "INVALID_ID", "case: {case:?}");
        }
        let too_long = "a".repeat(ContainerId::MAX_LEN + 1);
        let err = ContainerId::new(too_long).expect_err("too long value must be rejected");
        assert_eq!(err.code(), "INVALID_ID");
    }

    /// IO-5（3 OS 一級対応。大文字小文字非区別の考慮）: 異なる大文字小文字の
    /// 入力が同一の正規化済み ID（小文字）へ解決されることを確認する。
    /// macOS 既定 FS・Windows はファイルシステムが大文字小文字非区別のため、
    /// 正規化せずに TASK-31 のパス要素へ使うと衝突する。
    #[test]
    fn container_id_normalizes_ascii_case() {
        let upper = ContainerId::new("Foo-Bar").expect("valid id in test fixture");
        let lower = ContainerId::new("foo-bar").expect("valid id in test fixture");
        assert_eq!(upper, lower);
        assert_eq!(upper.as_str(), "foo-bar");
    }

    /// IO-5: Windows 予約デバイス名（拡張子付き・大文字小文字を問わない）を
    /// パス要素として使うと Windows 上でディレクトリ作成が失敗するため拒否する。
    #[test]
    fn container_id_rejects_windows_reserved_device_names() {
        let cases = ["con", "CON", "Con.txt", "nul", "com1", "COM1.log", "lpt9"];
        for case in cases {
            let err = ContainerId::new(case).expect_err("value must be rejected");
            assert_eq!(err.code(), "INVALID_ID", "case: {case:?}");
        }
    }

    /// IO-5: Win32 のパス正規化で末尾の `.` が剥離されるため、末尾が `.` の
    /// 値は生成時に拒否する。
    #[test]
    fn container_id_rejects_trailing_dot() {
        let err = ContainerId::new("foo.").expect_err("value must be rejected");
        assert_eq!(err.code(), "INVALID_ID");
    }

    #[test]
    fn state_store_error_code_covers_all_variants() {
        let id = ContainerId::new("abc123").expect("valid id in test fixture");
        assert_eq!(
            StateStoreError::InvalidId {
                reason: "x".to_string()
            }
            .code(),
            "INVALID_ID"
        );
        assert_eq!(
            StateStoreError::InvalidState {
                reason: "x".to_string()
            }
            .code(),
            "INVALID_STATE"
        );
        assert_eq!(
            StateStoreError::NotFound { id: id.clone() }.code(),
            "NOT_FOUND"
        );
        assert_eq!(
            StateStoreError::AlreadyExists { id: id.clone() }.code(),
            "ALREADY_EXISTS"
        );
        assert_eq!(
            StateStoreError::Corrupted {
                id: id.clone(),
                reason: "x".to_string()
            }
            .code(),
            "CORRUPTED"
        );
        assert_eq!(
            StateStoreError::Io {
                reason: "x".to_string()
            }
            .code(),
            "IO"
        );
        assert_eq!(StateStoreError::Timeout.code(), "TIMEOUT");
        assert_eq!(
            StateStoreError::Unavailable {
                reason: "x".to_string()
            }
            .code(),
            "UNAVAILABLE"
        );
    }

    /// CRI-7: `Running` は `pid: Some` を要求し（`0` は不可）、
    /// `Creating`/`Stopped` は `pid: None` を要求する。`Created` は制約なし
    /// （両方許容）。
    #[test]
    fn container_state_new_enforces_pid_status_invariant() {
        let id = || ContainerId::new("abc123").expect("valid id in test fixture");
        let bundle = test_bundle_path;

        // 妥当な組み合わせ。
        assert!(
            ContainerState::new(
                "1.0.2",
                id(),
                ContainerStatus::Creating,
                None,
                bundle(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .is_ok()
        );
        assert!(
            ContainerState::new(
                "1.0.2",
                id(),
                ContainerStatus::Created,
                None,
                bundle(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .is_ok()
        );
        assert!(
            ContainerState::new(
                "1.0.2",
                id(),
                ContainerStatus::Created,
                Some(123),
                bundle(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .is_ok()
        );
        assert!(
            ContainerState::new(
                "1.0.2",
                id(),
                ContainerStatus::Running,
                Some(123),
                bundle(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .is_ok()
        );
        assert!(
            ContainerState::new(
                "1.0.2",
                id(),
                ContainerStatus::Stopped,
                None,
                bundle(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .is_ok()
        );

        // 不正な組み合わせ: Running で pid: None。
        let err = ContainerState::new(
            "1.0.2",
            id(),
            ContainerStatus::Running,
            None,
            bundle(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("Running with pid: None must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");

        // 不正な組み合わせ: Running で pid: Some(0)（PID 0 はコンテナ
        // プロセスを指せないため拒否する）。
        let err = ContainerState::new(
            "1.0.2",
            id(),
            ContainerStatus::Running,
            Some(0),
            bundle(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("Running with pid: Some(0) must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");

        // 不正な組み合わせ: Stopped で pid: Some。
        let err = ContainerState::new(
            "1.0.2",
            id(),
            ContainerStatus::Stopped,
            Some(123),
            bundle(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("Stopped with pid: Some must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");

        // 不正な組み合わせ: Creating で pid: Some。
        let err = ContainerState::new(
            "1.0.2",
            id(),
            ContainerStatus::Creating,
            Some(123),
            bundle(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("Creating with pid: Some must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// CRI-7: `bundle` は絶対パスでなければならない。相対パスは OCI-5 の
    /// 状態ファイルからの再構成時に基準ディレクトリへ依存し曖昧になるため
    /// 構築時に拒否する。
    #[test]
    fn container_state_new_rejects_relative_bundle() {
        let err = ContainerState::new(
            "1.0.2",
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            PathBuf::from("relative/bundle"),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("relative bundle must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// CRI-7: `oci_version` は空文字列を許容しない。
    #[test]
    fn container_state_new_rejects_empty_oci_version() {
        let err = ContainerState::new(
            "",
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            test_bundle_path(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("empty oci_version must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// CRI-7: `oci_version` はドット区切り数字列のみを受理し、非数字を含む
    /// 値・長さ超過の値は拒否する。
    #[test]
    fn container_state_new_rejects_malformed_oci_version() {
        let cases = [
            "v1.0.2",
            "1.0.2-rc1",
            "1..2",
            ".1.0",
            "1.0.",
            "not-a-version",
        ];
        for case in cases {
            let err = ContainerState::new(
                case,
                ContainerId::new("abc123").expect("valid id in test fixture"),
                ContainerStatus::Created,
                None,
                test_bundle_path(),
                BTreeMap::new(),
                None,
                HealthStatus::Unknown,
                0,
            )
            .expect_err("malformed oci_version must be rejected");
            assert_eq!(err.code(), "INVALID_STATE", "case: {case:?}");
        }

        let too_long = "1.".repeat(ContainerState::MAX_OCI_VERSION_LEN);
        let err = ContainerState::new(
            too_long,
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            test_bundle_path(),
            BTreeMap::new(),
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("too long oci_version must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// security.md: `annotations` の件数上限（`MAX_ANNOTATION_COUNT`）を
    /// 超える入力は拒否する（無制限確保による DoS を防ぐ）。
    #[test]
    fn container_state_new_rejects_too_many_annotations() {
        let mut annotations = BTreeMap::new();
        for i in 0..=ContainerState::MAX_ANNOTATION_COUNT {
            annotations.insert(format!("key{i}"), "value".to_string());
        }
        let err = ContainerState::new(
            "1.0.2",
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            test_bundle_path(),
            annotations,
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("too many annotations must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// security.md: アノテーション 1 件あたりのキー・値の長さ上限を超える
    /// 入力は拒否する。
    #[test]
    fn container_state_new_rejects_oversized_annotation_value() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            "key".to_string(),
            "v".repeat(ContainerState::MAX_ANNOTATION_VALUE_LEN + 1),
        );
        let err = ContainerState::new(
            "1.0.2",
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Created,
            None,
            test_bundle_path(),
            annotations,
            None,
            HealthStatus::Unknown,
            0,
        )
        .expect_err("oversized annotation value must be rejected");
        assert_eq!(err.code(), "INVALID_STATE");
    }

    /// 決定 6（`docs/design/crate-naming.md`）: supervisor が使う
    /// `supervisor_pid`・`health`・`restart_count` は core の `ContainerState`
    /// に保持され、`new`/アクセサを経由して読み書きできる。
    #[test]
    fn container_state_retains_supervisor_fields() {
        let state = ContainerState::new(
            "1.0.2",
            ContainerId::new("abc123").expect("valid id in test fixture"),
            ContainerStatus::Running,
            Some(123),
            test_bundle_path(),
            BTreeMap::new(),
            Some(456),
            HealthStatus::Healthy,
            3,
        )
        .expect("valid state in test fixture");

        assert_eq!(state.supervisor_pid(), Some(456));
        assert_eq!(state.health(), HealthStatus::Healthy);
        assert_eq!(state.restart_count(), 3);
    }
}
