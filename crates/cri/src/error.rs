//! CRI の統一エラー型と gRPC ステータスコードの対応（ERR-3・TASK-97.1・#449）。
//!
//! 各 RPC ハンドラが返す失敗を [`CriError`]（区分 [`CriErrorCode`] と英語のメッセージ）に集約し、
//! `?` で `tonic::Status` へ変換できるようにする。区分から gRPC コードへの写像はここ 1 か所に置く。
//! ハンドラ（`runtime_service`・`image_service`）は内部を [`CriError`] で組み立て、tonic トレイトの境界で
//! `Status` へ変換する。`adapter::trait_error_to_status` と `image_pull` の `From<PullError> for Status` も
//! この型へ委譲する薄いラッパーである（TASK-97.2・#450 で適用済み）。
//!
//! メッセージには要求の中身（config・labels・annotations）や資格情報を含めない。この型は
//! 受け取った文字列を素通しするだけで、要求データを自分から付け足さない。
//!
//! `PermissionDenied`・`ResourceExhausted` は既存の CRI 実装が返しているが ERR-3 の表に無い拡張で、
//! spec への反映要否は報告事項とする。
//!
//! ## レジストリの HTTP 状態の運び方（#2898・CRI-3・OCI-1・REPAIR-4・ERR-1）
//!
//! 1. gRPC コードは oci の分類（`code_for_http_status`）を `From<PullError>` の表で写して決まる。
//!    401/403 は `PERMISSION_DENIED`、404 は `NOT_FOUND`、408 は `DEADLINE_EXCEEDED`、
//!    429 と 5xx は `UNAVAILABLE`、その他の 4xx は `INVALID_ARGUMENT`。
//! 2. HTTP 状態は message に入れず、トレーラーのメタデータ [`REGISTRY_HTTP_STATUS_METADATA_KEY`]
//!    （10 進。範囲は 100..=599）でだけ運ぶ。範囲外は付けない。
//! 3. message は分類ごとの固定の英語文言（URL・応答本文・資格情報を含めない）。429 だけが専用の固定文言
//!    `registry rate limit exceeded` を持つ（メタデータを捨てる経路でも見分けるため）。
//! 4. 付けるのはレジストリ由来の失敗（`PullError::from_oci`）だけで、ストア・展開・config 由来には付けない。
//! 5. plugin 境界の `PluginError` はメタデータを運ばない（対象外）。`ErrorInfo`（details）は新規依存が要るため採らない。
//! 6. 読み手は [`registry_http_status_from_metadata`] だけ（書き手 `From<CriError> for Status` と対）。
//!    操作記録（`crate::instrument::CriOpTimer`。#2966）と実機前提試験の失敗表示が使う。区分の語彙は
//!    `crate::instrument::RegistryHttpClass`。
//!
//! `PullError` の `AlreadyExists` は意図して `INTERNAL` に写す（`ALREADY_EXISTS` にしない。
//! 理由は `From<PullError> for CriError` の doc。ERR-3・TASK-97・#2321）。

use std::fmt;

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_oci::error::OciErrorCode;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Status};

use crate::image_pull::PullError;
use crate::instrument::code_name;

/// レジストリの HTTP 状態を運ぶトレーラーメタデータのキー（値は 10 進の ASCII。例: `429`）。
pub const REGISTRY_HTTP_STATUS_METADATA_KEY: &str = "fandhe-registry-http-status";

/// `Status` のメタデータから [`REGISTRY_HTTP_STATUS_METADATA_KEY`] の値を厳格に読む（#2966・CRI-3・REPAIR-4）。
///
/// 書き手（`From<CriError> for Status`）と対になる唯一の読み手。ちょうど 3 桁の ASCII 数字で
/// 100..=599 に入るときだけ `Some`、それ以外（キー無し・空白・先頭 0 の 4 桁・範囲外）は `None`
/// （fail-closed。アロケーションしない）。
pub fn registry_http_status_from_metadata(md: &MetadataMap) -> Option<u16> {
    let text = md.get(REGISTRY_HTTP_STATUS_METADATA_KEY)?.to_str().ok()?;
    if text.len() != 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u16 = text.parse().ok()?;
    (100..=599).contains(&value).then_some(value)
}

/// `Status` のメッセージ上限（バイト）。plugin・レジストリ由来の文字列で応答が肥大化するのを防ぐ。
pub(crate) const STATUS_MESSAGE_MAX_BYTES: usize = 4096;

/// CRI エラーの区分（ERR-3 の対応表）。
///
/// crate 内の `match` は網羅的に書き、区分を足して写像を書き忘れるとコンパイルが通らないようにする（REPAIR-12）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CriErrorCode {
    /// 入力検証の失敗（`INVALID_ARGUMENT`）。
    InvalidArgument,
    /// 対象が存在しない（`NOT_FOUND`）。
    NotFound,
    /// 同一 ID が既に存在する（`ALREADY_EXISTS`）。
    AlreadyExists,
    /// 状態遷移が不正（`FAILED_PRECONDITION`）。
    FailedPrecondition,
    /// 未実装の機能（`UNIMPLEMENTED`）。
    Unimplemented,
    /// 整合性検証の失敗（`DATA_LOSS`）。
    DataLoss,
    /// 時間切れ。gRPC では `DEADLINE_EXCEEDED` で返す（ERR-1 の `TIMEOUT` 表記との差）。
    Timeout,
    /// 一時的に利用できない（`UNAVAILABLE`）。
    Unavailable,
    /// 権限不足（`PERMISSION_DENIED`）。ERR-3 の表に無い拡張。
    PermissionDenied,
    /// 資源上限超過（`RESOURCE_EXHAUSTED`）。ERR-3 の表に無い拡張。
    ResourceExhausted,
    /// 想定外の内部エラー（`INTERNAL`）。未知の区分もここへ倒す。
    Internal,
}

impl CriErrorCode {
    /// 対応する gRPC ステータスコード。
    pub fn grpc_code(self) -> Code {
        match self {
            Self::InvalidArgument => Code::InvalidArgument,
            Self::NotFound => Code::NotFound,
            Self::AlreadyExists => Code::AlreadyExists,
            Self::FailedPrecondition => Code::FailedPrecondition,
            Self::Unimplemented => Code::Unimplemented,
            Self::DataLoss => Code::DataLoss,
            Self::Timeout => Code::DeadlineExceeded,
            Self::Unavailable => Code::Unavailable,
            Self::PermissionDenied => Code::PermissionDenied,
            Self::ResourceExhausted => Code::ResourceExhausted,
            Self::Internal => Code::Internal,
        }
    }

    /// 機械可読な区分名（gRPC の正式名。文字列表は `instrument::code_name` に一本化）。
    pub fn as_str(self) -> &'static str {
        code_name(self.grpc_code())
    }

    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら単体試験が検出する。
    pub const ALL: [CriErrorCode; 11] = [
        Self::InvalidArgument,
        Self::NotFound,
        Self::AlreadyExists,
        Self::FailedPrecondition,
        Self::Unimplemented,
        Self::DataLoss,
        Self::Timeout,
        Self::Unavailable,
        Self::PermissionDenied,
        Self::ResourceExhausted,
        Self::Internal,
    ];

    /// [`Self::as_str`] の逆写像。完全一致だけを受け、未知の文字列は `None`（呼び出し側は fail-closed で扱う）。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// CRI の失敗（区分とメッセージ）。`tonic::Status` へは [`From`] で変換する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriError {
    code: CriErrorCode,
    message: String,
    registry_http_status: Option<u16>,
}

impl CriError {
    /// 区分とメッセージからエラーを作る。メッセージは 4096 バイト以内（文字境界）に切り詰める。
    pub fn new(code: CriErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > STATUS_MESSAGE_MAX_BYTES {
            let mut end = STATUS_MESSAGE_MAX_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self {
            code,
            message,
            registry_http_status: None,
        }
    }

    /// レジストリ由来の HTTP 状態（`PullError` 経由のときだけ入る）。
    pub fn registry_http_status(&self) -> Option<u16> {
        self.registry_http_status
    }

    /// `INVALID_ARGUMENT` のエラーを作る。
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::InvalidArgument, message)
    }

    /// `NOT_FOUND` のエラーを作る。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::NotFound, message)
    }

    /// `ALREADY_EXISTS` のエラーを作る。
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::AlreadyExists, message)
    }

    /// `FAILED_PRECONDITION` のエラーを作る。
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::FailedPrecondition, message)
    }

    /// `UNIMPLEMENTED` のエラーを作る。
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::Unimplemented, message)
    }

    /// 時間切れ（gRPC では `DEADLINE_EXCEEDED`）のエラーを作る。
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::Timeout, message)
    }

    /// `UNAVAILABLE` のエラーを作る。
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::Unavailable, message)
    }

    /// `RESOURCE_EXHAUSTED` のエラーを作る（ERR-3 の表に無い拡張）。
    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::ResourceExhausted, message)
    }

    /// `INTERNAL` のエラーを作る。
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(CriErrorCode::Internal, message)
    }

    /// 区分。
    pub fn code(&self) -> CriErrorCode {
        self.code
    }

    /// メッセージ（切り詰め済み）。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CriError {}

impl From<CriError> for Status {
    fn from(err: CriError) -> Self {
        match err.registry_http_status {
            Some(status) => {
                let mut metadata = MetadataMap::new();
                metadata.insert(
                    REGISTRY_HTTP_STATUS_METADATA_KEY,
                    MetadataValue::from(status),
                );
                Status::with_metadata(err.code.grpc_code(), err.message, metadata)
            }
            None => Status::new(err.code.grpc_code(), err.message),
        }
    }
}

/// core の `ErrorCode` から `CriErrorCode` への表（`ErrorCode::ALL` と同数。`Internal` も明示。
/// 試験が網羅と重複なしを照合する。REPAIR-1・ERR-3）。
const TRAIT_ERROR_TABLE: [(ErrorCode, CriErrorCode); 10] = [
    (ErrorCode::InvalidArgument, CriErrorCode::InvalidArgument),
    (ErrorCode::NotFound, CriErrorCode::NotFound),
    (ErrorCode::AlreadyExists, CriErrorCode::AlreadyExists),
    (
        ErrorCode::FailedPrecondition,
        CriErrorCode::FailedPrecondition,
    ),
    (ErrorCode::Unimplemented, CriErrorCode::Unimplemented),
    (ErrorCode::Internal, CriErrorCode::Internal),
    (ErrorCode::PermissionDenied, CriErrorCode::PermissionDenied),
    (ErrorCode::Timeout, CriErrorCode::Timeout),
    (ErrorCode::Unavailable, CriErrorCode::Unavailable),
    (
        ErrorCode::ResourceExhausted,
        CriErrorCode::ResourceExhausted,
    ),
];

/// core の `ContainerRuntime` のエラーを写す。表に無い区分（`#[non_exhaustive]` の将来の variant）は
/// fail-closed で `Internal`。
impl From<&TraitError> for CriError {
    fn from(err: &TraitError) -> Self {
        let code = TRAIT_ERROR_TABLE
            .iter()
            .find(|(c, _)| *c == err.code())
            .map_or(CriErrorCode::Internal, |(_, cri)| *cri);
        Self::new(code, err.message())
    }
}

/// image pull の失敗を写す。未知の区分は fail-closed で `Internal`。
///
/// `OciErrorCode::AlreadyExists` は意図して `Internal`（gRPC `INTERNAL`）に写す（ERR-3・CRI-3・TASK-97・#2321）。
/// ERR-3 の `ALREADY_EXISTS` は Create 系の同一コンテナ・同一 Pod サンドボックス専用で、CRI の
/// `PullImage` は冪等（取得済みでも成功）なため当たらない。`ALREADY_EXISTS` を返すと
/// 「既にある＝成功」と取り違えられる余地も生じる。将来の発生源（レイヤー展開の IO-5 名前衝突、
/// `image_management` のリース・manifest 衝突。TASK-183・OCI-7）はイメージ内容の不整合かランタイム内部の
/// 整合性の問題で、`INVALID_ARGUMENT` にも `FAILED_PRECONDITION` にも当たらず、ERR-3 の
/// 「いずれにも分類されない内部エラー」に属する。別の区分が要る発生源は、oci 側か配線する側で
/// 区分を変換してから渡す（`registry.rs` が io の `AlreadyExists` を `FailedPrecondition` へ
/// 変換する先例と同様）。
impl From<PullError> for CriError {
    fn from(err: PullError) -> Self {
        let code = match err.code() {
            OciErrorCode::InvalidArgument => CriErrorCode::InvalidArgument,
            OciErrorCode::Unimplemented => CriErrorCode::Unimplemented,
            OciErrorCode::Unavailable => CriErrorCode::Unavailable,
            OciErrorCode::Timeout => CriErrorCode::Timeout,
            OciErrorCode::PermissionDenied => CriErrorCode::PermissionDenied,
            OciErrorCode::NotFound => CriErrorCode::NotFound,
            OciErrorCode::DataLoss => CriErrorCode::DataLoss,
            OciErrorCode::ResourceExhausted => CriErrorCode::ResourceExhausted,
            OciErrorCode::FailedPrecondition => CriErrorCode::FailedPrecondition,
            OciErrorCode::AlreadyExists => CriErrorCode::Internal,
            _ => CriErrorCode::Internal,
        };
        let mut out = Self::new(code, err.message());
        out.registry_http_status = err.http_status();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_oci::error::OciError;

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: CriErrorCode) -> usize {
        match code {
            CriErrorCode::InvalidArgument => 0,
            CriErrorCode::NotFound => 1,
            CriErrorCode::AlreadyExists => 2,
            CriErrorCode::FailedPrecondition => 3,
            CriErrorCode::Unimplemented => 4,
            CriErrorCode::DataLoss => 5,
            CriErrorCode::Timeout => 6,
            CriErrorCode::Unavailable => 7,
            CriErrorCode::PermissionDenied => 8,
            CriErrorCode::ResourceExhausted => 9,
            CriErrorCode::Internal => 10,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err3_cri_error_code_all_covers_every_variant() {
        for (i, c) in CriErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(CriErrorCode::ALL.len(), 11);
        let set: std::collections::HashSet<_> = CriErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 11);
    }

    /// ERR-1: ワイヤーへ出す code 名は固定（変えると互換が壊れる）。`from_name` は完全一致の逆写像。
    #[test]
    fn err3_cri_error_code_wire_names_are_fixed_and_roundtrip() {
        let table = [
            (CriErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (CriErrorCode::NotFound, "NOT_FOUND"),
            (CriErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (CriErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (CriErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (CriErrorCode::DataLoss, "DATA_LOSS"),
            (CriErrorCode::Timeout, "DEADLINE_EXCEEDED"),
            (CriErrorCode::Unavailable, "UNAVAILABLE"),
            (CriErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (CriErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (CriErrorCode::Internal, "INTERNAL"),
        ];
        assert_eq!(table.len(), CriErrorCode::ALL.len());
        for (i, (code, name)) in table.into_iter().enumerate() {
            assert_eq!(CriErrorCode::ALL[i], code);
            assert_eq!(code.as_str(), name);
            assert_eq!(CriErrorCode::from_name(name), Some(code));
        }
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(CriErrorCode::from_name(bad), None, "{bad:?}");
        }
    }
    use crate::adapter::trait_error_to_status;

    fn code_of(e: CriError) -> Code {
        Status::from(e).code()
    }

    /// ERR-3: INVALID_ARGUMENT。
    #[test]
    fn task_97_1_err3_invalid_argument_maps_to_invalid_argument() {
        let st = Status::from(CriError::invalid_argument("m"));
        assert_eq!(st.code(), Code::InvalidArgument);
        assert_eq!(st.message(), "m");
    }

    /// ERR-3: NOT_FOUND。
    #[test]
    fn task_97_1_err3_not_found_maps_to_not_found() {
        assert_eq!(code_of(CriError::not_found("m")), Code::NotFound);
    }

    /// ERR-3: ALREADY_EXISTS。
    #[test]
    fn task_97_1_err3_already_exists_maps_to_already_exists() {
        assert_eq!(code_of(CriError::already_exists("m")), Code::AlreadyExists);
    }

    /// ERR-3: FAILED_PRECONDITION。
    #[test]
    fn task_97_1_err3_failed_precondition_maps_to_failed_precondition() {
        assert_eq!(
            code_of(CriError::failed_precondition("m")),
            Code::FailedPrecondition
        );
    }

    /// ERR-3: UNIMPLEMENTED。
    #[test]
    fn task_97_1_err3_unimplemented_maps_to_unimplemented() {
        assert_eq!(code_of(CriError::unimplemented("m")), Code::Unimplemented);
    }

    /// ERR-3: INTERNAL。
    #[test]
    fn task_97_1_err3_internal_maps_to_internal() {
        assert_eq!(code_of(CriError::internal("m")), Code::Internal);
    }

    /// ERR-3 の残り 3 区分と拡張 2 区分。
    #[test]
    fn task_97_1_err3_remaining_and_extension_codes() {
        let cases = [
            (CriErrorCode::DataLoss, Code::DataLoss, "DATA_LOSS"),
            (
                CriErrorCode::Timeout,
                Code::DeadlineExceeded,
                "DEADLINE_EXCEEDED",
            ),
            (CriErrorCode::Unavailable, Code::Unavailable, "UNAVAILABLE"),
            (
                CriErrorCode::PermissionDenied,
                Code::PermissionDenied,
                "PERMISSION_DENIED",
            ),
            (
                CriErrorCode::ResourceExhausted,
                Code::ResourceExhausted,
                "RESOURCE_EXHAUSTED",
            ),
            (
                CriErrorCode::InvalidArgument,
                Code::InvalidArgument,
                "INVALID_ARGUMENT",
            ),
        ];
        for (c, g, s) in cases {
            assert_eq!(c.grpc_code(), g);
            assert_eq!(c.as_str(), s);
            assert_eq!(code_of(CriError::new(c, "m")), g);
        }
    }

    /// ERR-3 拡張区分（timeout・unavailable・resource_exhausted）のコンストラクタが対応する gRPC コードへ写ることを確認する。
    #[test]
    fn task_97_2_err3_extension_constructors() {
        let cases = [
            (CriError::timeout("t"), Code::DeadlineExceeded),
            (CriError::unavailable("u"), Code::Unavailable),
            (CriError::resource_exhausted("r"), Code::ResourceExhausted),
        ];
        for (e, code) in cases {
            let msg = e.message().to_owned();
            let st = Status::from(e);
            assert_eq!(st.code(), code);
            assert_eq!(st.message(), msg);
        }
    }

    /// メッセージは 4096 バイト・文字境界で切り詰める。
    #[test]
    fn task_97_1_message_truncation() {
        let exact = "a".repeat(4096);
        assert_eq!(CriError::internal(exact.clone()).message(), exact);
        assert_eq!(CriError::internal("a".repeat(4097)).message().len(), 4096);
        // 4095 バイトの後に 3 バイト文字: 4096 は文字の途中なので 4095 に戻る。
        let multi = format!("{}あ", "a".repeat(4095));
        let e = CriError::internal(multi);
        assert_eq!(e.message().len(), 4095);
        assert!(std::str::from_utf8(e.message().as_bytes()).is_ok());
    }

    /// core の各区分が期待どおりに写り、既存の `trait_error_to_status` と一致する。
    #[test]
    fn task_97_1_trait_error_mapping_matches_adapter() {
        let cases = [
            (ErrorCode::InvalidArgument, Code::InvalidArgument),
            (ErrorCode::NotFound, Code::NotFound),
            (ErrorCode::AlreadyExists, Code::AlreadyExists),
            (ErrorCode::FailedPrecondition, Code::FailedPrecondition),
            (ErrorCode::Unimplemented, Code::Unimplemented),
            (ErrorCode::PermissionDenied, Code::PermissionDenied),
            (ErrorCode::Timeout, Code::DeadlineExceeded),
            (ErrorCode::Unavailable, Code::Unavailable),
            (ErrorCode::ResourceExhausted, Code::ResourceExhausted),
            (ErrorCode::Internal, Code::Internal),
        ];
        assert_eq!(cases.len(), ErrorCode::ALL.len());
        for c in ErrorCode::ALL {
            assert!(cases.iter().any(|(k, _)| *k == c), "{}", c.as_str());
        }
        for (ec, expected) in cases {
            let te = TraitError::new(ec, "msg");
            let st = Status::from(CriError::from(&te));
            assert_eq!(st.code(), expected);
            assert_eq!(st.message(), "msg");
            assert_eq!(st.code(), trait_error_to_status(&te).code());
        }
    }

    /// CRI-3・OCI-1・ERR-3: 429・503・状態なしは同じ `UNAVAILABLE` のまま、メタデータ（と 429 の固定文言）で区別できる。
    #[test]
    fn cri3_registry_http_status_is_carried_in_metadata() {
        let to_status = |http: Option<u16>| {
            let mut e = OciError::new(OciErrorCode::Unavailable, "upstream detail token=dummy");
            if let Some(h) = http {
                e = e.with_http_status(h);
            }
            let ce = CriError::from(PullError::from_oci(&e));
            assert_eq!(ce.registry_http_status(), http);
            Status::from(ce)
        };
        let st = to_status(Some(429));
        assert_eq!(st.code(), Code::Unavailable);
        assert_eq!(st.message(), "registry rate limit exceeded");
        assert_eq!(
            st.metadata()
                .get(REGISTRY_HTTP_STATUS_METADATA_KEY)
                .map(|v| v.to_str().unwrap()),
            Some("429")
        );
        for leaked in ["429", "token=", "upstream"] {
            assert!(!st.message().contains(leaked));
        }
        let st = to_status(Some(503));
        assert_eq!(st.code(), Code::Unavailable);
        assert_eq!(st.message(), "registry is unavailable");
        assert_eq!(
            st.metadata()
                .get(REGISTRY_HTTP_STATUS_METADATA_KEY)
                .map(|v| v.to_str().unwrap()),
            Some("503")
        );
        let st = to_status(None);
        assert_eq!(st.code(), Code::Unavailable);
        assert_eq!(st.message(), "registry is unavailable");
        assert!(
            st.metadata()
                .get(REGISTRY_HTTP_STATUS_METADATA_KEY)
                .is_none()
        );
    }

    /// CRI-3・REPAIR-4（#2966）: メタデータの読み手は 3 桁・範囲内だけを受け、書き手と往復一致する。
    #[test]
    fn cri3_registry_http_status_from_metadata_is_strict() {
        let md_of = |v: &str| {
            let mut md = MetadataMap::new();
            md.insert(
                REGISTRY_HTTP_STATUS_METADATA_KEY,
                v.parse::<MetadataValue<_>>().unwrap(),
            );
            md
        };
        for (raw, expected) in [
            ("429", Some(429)),
            ("100", Some(100)),
            ("599", Some(599)),
            ("099", None),
            ("600", None),
            ("0429", None),
            (" 429", None),
            ("42", None),
            ("abc", None),
            ("", None),
        ] {
            assert_eq!(
                registry_http_status_from_metadata(&md_of(raw)),
                expected,
                "raw={raw:?}"
            );
        }
        assert_eq!(
            registry_http_status_from_metadata(&MetadataMap::new()),
            None
        );
        for http in [401u16, 429, 503] {
            let ce = CriError::from(PullError::from_oci(
                &OciError::new(OciErrorCode::Unavailable, "x").with_http_status(http),
            ));
            let st = Status::from(ce);
            assert_eq!(
                registry_http_status_from_metadata(st.metadata()),
                Some(http)
            );
        }
    }

    /// CRI-3・OCI-1: HTTP 状態ごとの gRPC コードとメタデータ値（余計なキーは付かない）。
    #[test]
    fn cri3_registry_http_status_table() {
        let cases = [
            (
                401u16,
                OciErrorCode::PermissionDenied,
                Code::PermissionDenied,
            ),
            (403, OciErrorCode::PermissionDenied, Code::PermissionDenied),
            (404, OciErrorCode::NotFound, Code::NotFound),
            (408, OciErrorCode::Timeout, Code::DeadlineExceeded),
            (500, OciErrorCode::Unavailable, Code::Unavailable),
            (400, OciErrorCode::InvalidArgument, Code::InvalidArgument),
        ];
        for (http, oci, want) in cases {
            let e = OciError::new(oci, "m").with_http_status(http);
            let st = Status::from(CriError::from(PullError::from_oci(&e)));
            assert_eq!(st.code(), want, "{http}");
            assert_eq!(st.metadata().len(), 1, "{http}");
            let v = st
                .metadata()
                .get(REGISTRY_HTTP_STATUS_METADATA_KEY)
                .unwrap();
            assert_eq!(v.to_str().unwrap(), http.to_string());
        }
    }

    /// oci の各区分が期待どおりに写り、既存の `From<PullError> for Status` と一致する。
    #[test]
    fn task_97_1_pull_error_mapping_matches_image_pull() {
        let cases = [
            (OciErrorCode::InvalidArgument, Code::InvalidArgument),
            (OciErrorCode::Unimplemented, Code::Unimplemented),
            (OciErrorCode::Unavailable, Code::Unavailable),
            (OciErrorCode::Timeout, Code::DeadlineExceeded),
            (OciErrorCode::PermissionDenied, Code::PermissionDenied),
            (OciErrorCode::NotFound, Code::NotFound),
            (OciErrorCode::DataLoss, Code::DataLoss),
            (OciErrorCode::ResourceExhausted, Code::ResourceExhausted),
            (OciErrorCode::FailedPrecondition, Code::FailedPrecondition),
            (OciErrorCode::AlreadyExists, Code::Internal),
            (OciErrorCode::Internal, Code::Internal),
        ];
        for (oc, expected) in cases {
            let pe = PullError::new(oc, "msg");
            let st = Status::from(CriError::from(pe));
            assert_eq!(st.code(), expected);
            assert_eq!(st.message(), "msg");
            assert_eq!(st.code(), Status::from(pe).code());
        }
    }

    /// REPAIR-1・ERR-3: core の `ErrorCode::ALL` の全件が表にあり、同名の区分へ写る
    /// （名前が食い違うのは `Timeout` の gRPC 名だけ）。core の像に入らない区分は `DataLoss` だけ。
    #[test]
    fn err3_trait_error_table_covers_all() {
        assert_eq!(TRAIT_ERROR_TABLE.len(), ErrorCode::ALL.len());
        let mut image = Vec::new();
        for (i, code) in ErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(TRAIT_ERROR_TABLE[i].0, code);
            let cri = CriError::from(&TraitError::new(code, "m")).code();
            assert_eq!(cri, TRAIT_ERROR_TABLE[i].1);
            if code == ErrorCode::Timeout {
                assert_eq!(
                    (code.as_str(), cri.as_str()),
                    ("TIMEOUT", "DEADLINE_EXCEEDED")
                );
            } else {
                assert_eq!(cri.as_str(), code.as_str());
            }
            image.push(cri);
        }
        let outside: Vec<_> = CriErrorCode::ALL
            .into_iter()
            .filter(|c| !image.contains(c))
            .collect();
        assert_eq!(outside, [CriErrorCode::DataLoss]);
    }

    /// REPAIR-1・ERR-3: `OciErrorCode::ALL` の全件が写り、`AlreadyExists` と `Internal` だけが
    /// `Internal`（#2321）。それ以外は同名の gRPC 区分。
    #[test]
    fn err3_pull_error_mapping_covers_all_oci_codes() {
        for oc in OciErrorCode::ALL {
            let cri = CriError::from(PullError::new(oc, "m")).code();
            match oc {
                OciErrorCode::AlreadyExists | OciErrorCode::Internal => {
                    assert_eq!(cri, CriErrorCode::Internal, "{oc:?}")
                }
                _ => {
                    let expected = if oc == OciErrorCode::Timeout {
                        "DEADLINE_EXCEEDED"
                    } else {
                        oc.as_str()
                    };
                    assert_eq!(cri.as_str(), expected, "{oc:?}");
                }
            }
        }
    }
}
