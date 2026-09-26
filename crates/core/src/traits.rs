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
use std::path::PathBuf;

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

/// `StateStore` が永続化・取得するコンテナ状態の 1 レコード。
///
/// 永続化形式（JSON 等）はこのトレイトの契約に含めない。ファイルベース
/// 既定実装の形式決定は TASK-31（OCI-5）の責務。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    /// 対象とする OCI Runtime Specification のバージョン文字列。
    pub oci_version: String,
    /// コンテナ ID。
    pub id: ContainerId,
    /// ライフサイクル状態。
    pub status: ContainerStatus,
    /// コンテナプロセスの PID。`Created`/`Running` のときのみ `Some`。
    pub pid: Option<u32>,
    /// バンドルディレクトリの絶対パス。
    pub bundle: PathBuf,
    /// 任意のアノテーション。
    pub annotations: BTreeMap<String, String>,
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

    /// 永続化されている全コンテナ ID を列挙する。
    ///
    /// 実装は返却件数に上限を設け、破損したエントリを読んでも panic しない
    /// こと（無制限確保による DoS を防ぐ。security.md）。
    fn list(&self) -> Result<Vec<ContainerId>, StateStoreError>;
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
            if entries.contains_key(&state.id) {
                return Err(StateStoreError::AlreadyExists {
                    id: state.id.clone(),
                });
            }
            entries.insert(state.id.clone(), state.clone());
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
            if !entries.contains_key(&state.id) {
                return Err(StateStoreError::NotFound {
                    id: state.id.clone(),
                });
            }
            entries.insert(state.id.clone(), state.clone());
            Ok(())
        }

        fn delete(&self, id: &ContainerId) -> Result<(), StateStoreError> {
            let mut entries = self.entries.lock().expect("test mutex poisoned");
            entries
                .remove(id)
                .map(|_| ())
                .ok_or_else(|| StateStoreError::NotFound { id: id.clone() })
        }

        fn list(&self) -> Result<Vec<ContainerId>, StateStoreError> {
            let entries = self.entries.lock().expect("test mutex poisoned");
            Ok(entries.keys().cloned().collect())
        }
    }

    fn sample_state(id: &str) -> ContainerState {
        ContainerState {
            oci_version: "1.0.2".to_string(),
            id: ContainerId::new(id).expect("valid id in test fixture"),
            status: ContainerStatus::Created,
            pid: None,
            bundle: PathBuf::from("/run/fandhe-container/bundle"),
            annotations: BTreeMap::new(),
        }
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
        let loaded = store.load(&state.id).expect("load should succeed");
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
        store.delete(&state.id).expect("delete should succeed");
        let ids = store.list().expect("list should succeed");
        assert_eq!(ids, Vec::<ContainerId>::new());
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
}
