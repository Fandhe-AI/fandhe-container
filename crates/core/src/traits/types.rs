//! 拡張点トレイト（`ContainerRuntime`・`StateStore`・`NetworkPlugin`・`VolumeProvider`）が
//! 共有する型（TASK-4・CRI-7・MS-0）。
//!
//! `ContainerId` は OCI-5 の状態パス（`/run/fandhe-container/<id>/state.json` 等）の
//! 1 パス要素になるため、外部入力（CLI・CRI・MCP リクエスト）から作る際にここで検証し、
//! 検証済みでない値を型として表現できないようにする。`TraitError` は 4 トレイト共通の
//! 構造化エラー型（ERR-1: 機械可読な `code` / `message`）。

use std::error::Error;
use std::fmt;

/// コンテナ ID の許容文字数の上限（NAME_MAX 相当。多くの Linux ファイルシステムの
/// ファイル名長上限に合わせ、状態ファイルのパス要素として安全な範囲に収める）。
const CONTAINER_ID_MAX_LEN: usize = 255;

/// 検証済みのコンテナ識別子。
///
/// `ContainerRuntime`・`StateStore` 等がパス要素（状態ファイル名・ネットワーク namespace
/// 名等）として使うため、パストラバーサル（`.`・`..`・区切り文字）や NUL・非 ASCII 制御文字を
/// 型のレベルで排除する。生成は [`ContainerId::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    /// 入力文字列を検証してコンテナ ID を作る。
    ///
    /// 拒否条件（いずれかに該当すると `ErrorCode::InvalidArgument`）:
    /// - 空文字列、`.`、`..`
    /// - 長さが `CONTAINER_ID_MAX_LEN`（255 バイト）を超える
    /// - `[A-Za-z0-9._-]` 以外の文字を含む（`/`・`\`・NUL・空白・非 ASCII を含む）
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() || value == "." || value == ".." {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id must not be empty, \".\", or \"..\"",
            ));
        }
        if value.len() > CONTAINER_ID_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("container id must be at most {CONTAINER_ID_MAX_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id must match [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for ContainerId {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for ContainerId {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// 拡張点トレイトの応答が返す機械可読なエラー分類（ERR-1・ERR-3・ERR-5 の体系）。
///
/// `#[non_exhaustive]` により、core の外の `match` は将来のバリアント追加に備えて
/// `_` 分岐を持つ必要がある。
///
/// # code ごとの表の書き方（REPAIR-1・ERR-1）
///
/// 外部 crate で「code ごとの文言・写像」の表が要るときは、`_` 腕に `Internal` 等を吸収させず、
/// 全 variant（`Internal` を含む）を明示した `const` の表（`[(ErrorCode, X); N]`）と `find` で書き、
/// 表の外（将来の variant）の倒し先を別に決める。試験で `表.len() == ErrorCode::ALL.len()`・
/// `ALL` の全要素が表にあること・キーに重複が無いことを照合すると、variant の追加を検出できる。
///
/// # 未知の code の扱い（fail-closed）
///
/// 文字列から code へ戻すのは [`ErrorCode::from_name`] だけとし、`None`（未知）を受けたら、
/// それを含む行・報告・メッセージ全体を不正（malformed）として固定文言の構造化エラーで拒否する。
/// 既知の variant（`Internal` 等）へ黙って置き換えて復号を続けない。未知の文字列そのものと、
/// 同じ行に付いた untrusted な message は出力へ反射しない。plugin 等の他 crate の enum
/// （`PluginErrorCode` ほか）の逆写像も同じ方針に従う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// 引数が不正（形式・範囲・検証違反）。
    InvalidArgument,
    /// 対象が見つからない。
    NotFound,
    /// 対象がすでに存在する（例: 同一 ID での二重作成）。
    AlreadyExists,
    /// 現在の状態では実行できない前提条件違反（例: 未作成のコンテナへの start）。
    FailedPrecondition,
    /// 未実装。
    Unimplemented,
    /// 内部エラー。
    Internal,
    /// 権限不足。
    PermissionDenied,
    /// 相手の応答待ちが上限時間を超えた（REPAIR-5）。
    Timeout,
    /// plugin プロセスに到達できない、または通信が切断された。
    ///
    /// ERR-1/3/5 の既定表にはない追加コードである。`ContainerRuntime` 等の実装は
    /// 別プロセス plugin（PLUG-1）であり、境界機構（UDS）の接続断・プロセス未起動を
    /// 表す分類が必要なため設ける。spec（error-format.md）への反映要否は別途ユーザーへ
    /// 報告する（本 crate では拡張済みの分類として扱う）。
    Unavailable,
    /// 資源の上限（追跡枠・件数・走査量など）に達して新しい処理を受けられない。
    ///
    /// 既存の資源が解放されるまで再試行しても解けない点で、接続し直せば回復し得る
    /// [`Self::Unavailable`] と区別する（CRI では gRPC `RESOURCE_EXHAUSTED`）。
    /// `PluginErrorCode`・`OciErrorCode`・`NetErrorCode`・`CriErrorCode` の同名コードと対応する
    /// （PLUG-1・CRI-2・REPAIR-4）。ERR-1/3/5 の既定表にはない追加コードで、spec への反映要否は
    /// 別途ユーザーへ報告する。
    ResourceExhausted,
}

impl ErrorCode {
    /// エラーコードを ERR-1 の機械可読文字列表現に変換する。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Timeout => "TIMEOUT",
            Self::Unavailable => "UNAVAILABLE",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
        }
    }

    /// 全 variant の一覧（宣言順）。`from_name` と、各 crate の一覧の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら `err1_error_code_all_covers_every_variant` が検出する。
    pub const ALL: [ErrorCode; 10] = [
        Self::InvalidArgument,
        Self::NotFound,
        Self::AlreadyExists,
        Self::FailedPrecondition,
        Self::Unimplemented,
        Self::Internal,
        Self::PermissionDenied,
        Self::Timeout,
        Self::Unavailable,
        Self::ResourceExhausted,
    ];

    /// [`Self::as_str`] の逆写像。完全一致だけを受け、未知の文字列は `None` を返す。
    ///
    /// 大文字小文字の畳み込みも前後の空白の除去もしない。子プロセス・worker・supervisor・CLI
    /// の報告行など untrusted な入力の経路で使う。`None`（未知）を受けた呼び出し側は、
    /// 既定の variant へ倒さず、行・報告全体を malformed として固定文言で拒否する
    /// （fail-closed。方針は [`ErrorCode`] の doc。REPAIR-1・ERR-1）。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// 拡張点トレイト（`ContainerRuntime` 等）が返す構造化エラー。
///
/// `code` は機械可読な分類、`message` は人間可読な説明（ERR-1）。plugin からの応答は
/// untrusted な外部入力であるため、[`TraitError::new`] が `message` を
/// [`TRAIT_ERROR_MESSAGE_MAX_BYTES`] バイト以下に UTF-8 文字境界で切り詰めて保持する
/// （呼び出し側での上限検証は不要）。切り詰めの有無は [`TraitError::message_truncated`] で
/// 分かり、`message` 自体には `...` 等の印を足さない。レジストリ資格情報等の秘密情報を
/// `message` に含めない（security.md）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TraitError {
    code: ErrorCode,
    message: String,
    message_truncated: bool,
}

/// [`TraitError`] が保持する `message` の最大バイト数（ERR-2・REPAIR-4・TASK-96.1・MS-6）。
///
/// OCI Runtime エラー応答の上限（`oci_runtime::OCI_ERROR_MESSAGE_MAX_BYTES`）と同値で、
/// `OciRuntimeError::from_trait_error` で再度切り詰められない大きさに揃える。
pub const TRAIT_ERROR_MESSAGE_MAX_BYTES: usize = 4096;

impl TraitError {
    /// エラーコードとメッセージから構造化エラーを作る。
    ///
    /// `message` が [`TRAIT_ERROR_MESSAGE_MAX_BYTES`] を超える場合は UTF-8 文字境界で
    /// 切り詰め、[`TraitError::message_truncated`] を `true` にする。
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        let message_truncated = message.len() > TRAIT_ERROR_MESSAGE_MAX_BYTES;
        if message_truncated {
            let mut end = TRAIT_ERROR_MESSAGE_MAX_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        // `truncate` は容量を縮めず、`String::with_capacity(大) + 短い文字列` のように
        // 長さが上限以下でも巨大な確保が残り得る。切り詰めの有無と独立に、確保量が上限を
        // 超えていれば縮めて、error の寿命の間に保持する確保量を上限内に収める。
        if message.capacity() > TRAIT_ERROR_MESSAGE_MAX_BYTES {
            message.shrink_to_fit();
        }
        Self {
            code,
            message,
            message_truncated,
        }
    }

    /// `new` に渡されたメッセージが上限を超え、切り詰められたかを返す。
    pub fn message_truncated(&self) -> bool {
        self.message_truncated
    }

    /// 機械可読なエラーコードを返す。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 人間可読なエラーメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TraitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for TraitError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: ErrorCode) -> usize {
        match code {
            ErrorCode::InvalidArgument => 0,
            ErrorCode::NotFound => 1,
            ErrorCode::AlreadyExists => 2,
            ErrorCode::FailedPrecondition => 3,
            ErrorCode::Unimplemented => 4,
            ErrorCode::Internal => 5,
            ErrorCode::PermissionDenied => 6,
            ErrorCode::Timeout => 7,
            ErrorCode::Unavailable => 8,
            ErrorCode::ResourceExhausted => 9,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err1_error_code_all_covers_every_variant() {
        for (i, c) in ErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(ErrorCode::ALL.len(), 10);
        let set: std::collections::HashSet<_> = ErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 10);
    }

    /// REPAIR-1・ERR-1: `from_name` は `as_str` の完全一致の逆写像。
    #[test]
    fn err1_error_code_from_name_roundtrips() {
        for c in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_name(c.as_str()), Some(c));
        }
        assert_eq!(
            ErrorCode::from_name("RESOURCE_EXHAUSTED"),
            Some(ErrorCode::ResourceExhausted)
        );
        assert_eq!(ErrorCode::from_name("INTERNAL"), Some(ErrorCode::Internal));
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(ErrorCode::from_name(bad), None, "{bad:?}");
        }
    }

    /// ERR-1: ワイヤーへ出す英語の code 名は `ALL` の順で固定（変えると互換が壊れる）。
    #[test]
    fn err1_error_code_wire_names_are_fixed() {
        let names: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "INVALID_ARGUMENT",
                "NOT_FOUND",
                "ALREADY_EXISTS",
                "FAILED_PRECONDITION",
                "UNIMPLEMENTED",
                "INTERNAL",
                "PERMISSION_DENIED",
                "TIMEOUT",
                "UNAVAILABLE",
                "RESOURCE_EXHAUSTED",
            ]
        );
    }

    /// PLUG-1・ERR-1: core と plugin の code 名の対応。plugin にだけある名前は `DATA_LOSS`、
    /// core にだけある名前は無く、core の全 code が plugin へ無損失に写る。
    #[cfg(feature = "plugin")]
    #[test]
    fn err1_plugin_error_code_names_correspond_to_core() {
        use fandhe_container_plugin::PluginErrorCode;
        for c in ErrorCode::ALL {
            let p = PluginErrorCode::from_code_str(c.as_str());
            assert_eq!(p.map(|p| p.as_str()), Some(c.as_str()), "{c:?}");
        }
        let plugin_only: Vec<&str> = PluginErrorCode::ALL
            .iter()
            .map(|p| p.as_str())
            .filter(|n| ErrorCode::from_name(n).is_none())
            .collect();
        assert_eq!(plugin_only, ["DATA_LOSS"]);
    }

    /// CRI-7: 受理される ContainerId の例（英数字・区切り記号・境界長）。
    #[test]
    fn cri7_container_id_accepts_valid_values() {
        assert_eq!(ContainerId::new("abc").unwrap().as_str(), "abc");
        assert_eq!(ContainerId::new("a-b_c.1").unwrap().as_str(), "a-b_c.1");
        let hex64 = "a".repeat(64);
        assert!(ContainerId::new(hex64).is_ok());
        let max_len = "a".repeat(255);
        assert!(ContainerId::new(max_len).is_ok());
    }

    /// CRI-7: 拒否される ContainerId の例（空・トラバーサル・区切り文字・NUL・非 ASCII・長さ超過）。
    #[test]
    fn cri7_container_id_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            ".".to_string(),
            "..".to_string(),
            "a/b".to_string(),
            "a\\b".to_string(),
            "a b".to_string(),
            "a\0b".to_string(),
            "é".to_string(),
            "a".repeat(256),
        ];
        for case in cases {
            let err = ContainerId::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// CRI-7: ErrorCode の全バリアントが ERR-1 の機械可読文字列と一致する。
    #[test]
    fn cri7_error_code_as_str_matches_err1_strings() {
        assert_eq!(ErrorCode::InvalidArgument.as_str(), "INVALID_ARGUMENT");
        assert_eq!(ErrorCode::NotFound.as_str(), "NOT_FOUND");
        assert_eq!(ErrorCode::AlreadyExists.as_str(), "ALREADY_EXISTS");
        assert_eq!(
            ErrorCode::FailedPrecondition.as_str(),
            "FAILED_PRECONDITION"
        );
        assert_eq!(ErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
        assert_eq!(ErrorCode::Internal.as_str(), "INTERNAL");
        assert_eq!(ErrorCode::PermissionDenied.as_str(), "PERMISSION_DENIED");
        assert_eq!(ErrorCode::Timeout.as_str(), "TIMEOUT");
        assert_eq!(ErrorCode::Unavailable.as_str(), "UNAVAILABLE");
        assert_eq!(ErrorCode::ResourceExhausted.as_str(), "RESOURCE_EXHAUSTED");
    }

    /// CRI-7: TraitError の Display が "<CODE>: <message>" 形式になる。
    #[test]
    fn cri7_trait_error_display_format() {
        let err = TraitError::new(ErrorCode::NotFound, "container not found");
        assert_eq!(err.to_string(), "NOT_FOUND: container not found");
    }

    /// ERR-2・REPAIR-4・TASK-96.1・MS-6: 上限ちょうどは保持、1 バイト超は切り詰め、マルチバイト文字の途中は境界まで戻す。
    #[test]
    fn err2_trait_error_message_is_capped_at_char_boundary() {
        let max = TRAIT_ERROR_MESSAGE_MAX_BYTES;
        assert_eq!(max, 4096);

        let exact = TraitError::new(ErrorCode::Internal, "a".repeat(max));
        assert_eq!(exact.message().len(), 4096);
        assert!(!exact.message_truncated());

        let over = TraitError::new(ErrorCode::Internal, "a".repeat(max + 1));
        assert_eq!(over.message().len(), 4096);
        assert!(over.message_truncated());

        // 3 バイト文字が 4095 バイト目から始まる: 途中で切らず 4095 バイトへ戻す。
        let mut s = "a".repeat(max - 1);
        s.push('あ');
        let mb = TraitError::new(ErrorCode::Internal, s);
        assert_eq!(mb.message().len(), 4095);
        assert!(mb.message_truncated());

        let huge = TraitError::new(ErrorCode::Internal, "あ".repeat(100_000));
        assert_eq!(huge.message().len(), 4095);
        assert!(
            huge.message.capacity() <= max,
            "stored allocation must stay within the cap"
        );
        assert!(huge.to_string().len() <= max + "INTERNAL: ".len());
    }

    /// ERR-2・REPAIR-4・TASK-96.1・MS-6: 長さが上限以下でも過大な確保量は上限内へ縮める。
    #[test]
    fn err2_trait_error_shrinks_oversized_capacity_without_truncation() {
        let mut s = String::with_capacity(1_000_000);
        s.push_str("short");
        let err = TraitError::new(ErrorCode::Internal, s);
        assert_eq!(err.message(), "short");
        assert!(!err.message_truncated());
        assert!(err.message.capacity() <= TRAIT_ERROR_MESSAGE_MAX_BYTES);

        // 呼び出し側が事前に truncate 済みで容量だけ巨大なケース。
        let mut pre = "a".repeat(100_000);
        pre.truncate(10);
        let err = TraitError::new(ErrorCode::Internal, pre);
        assert_eq!(err.message().len(), 10);
        assert!(!err.message_truncated());
        assert!(err.message.capacity() <= TRAIT_ERROR_MESSAGE_MAX_BYTES);
    }

    /// CRI-7: `TryFrom<&str>` は `ContainerId::new` と同じ検証結果を返す。
    #[test]
    fn cri7_container_id_try_from_str_matches_new() {
        let id = ContainerId::try_from("abc").expect("valid id");
        assert_eq!(id.as_str(), "abc");

        let err = ContainerId::try_from("a/b").expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// CRI-7: `TryFrom<String>` は `ContainerId::new` と同じ検証結果を返す。
    #[test]
    fn cri7_container_id_try_from_string_matches_new() {
        let id = ContainerId::try_from("a-b_c.1".to_string()).expect("valid id");
        assert_eq!(id.as_str(), "a-b_c.1");

        let err = ContainerId::try_from("..".to_string()).expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }
}
