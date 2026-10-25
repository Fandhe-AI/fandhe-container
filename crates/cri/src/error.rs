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
//! `PullError` の `AlreadyExists` は意図して `INTERNAL` に写す（`ALREADY_EXISTS` にしない。
//! 理由は `From<PullError> for CriError` の doc。ERR-3・TASK-97・#2321）。

use std::fmt;

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_oci::error::OciErrorCode;
use tonic::{Code, Status};

use crate::image_pull::PullError;
use crate::instrument::code_name;

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
}

/// CRI の失敗（区分とメッセージ）。`tonic::Status` へは [`From`] で変換する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriError {
    code: CriErrorCode,
    message: String,
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
        Self { code, message }
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
        Status::new(err.code.grpc_code(), err.message)
    }
}

/// core の `ContainerRuntime` のエラーを写す。未知の区分（`#[non_exhaustive]`）は fail-closed で `Internal`。
impl From<&TraitError> for CriError {
    fn from(err: &TraitError) -> Self {
        let code = match err.code() {
            ErrorCode::InvalidArgument => CriErrorCode::InvalidArgument,
            ErrorCode::NotFound => CriErrorCode::NotFound,
            ErrorCode::AlreadyExists => CriErrorCode::AlreadyExists,
            ErrorCode::FailedPrecondition => CriErrorCode::FailedPrecondition,
            ErrorCode::Unimplemented => CriErrorCode::Unimplemented,
            ErrorCode::PermissionDenied => CriErrorCode::PermissionDenied,
            ErrorCode::Timeout => CriErrorCode::Timeout,
            ErrorCode::Unavailable => CriErrorCode::Unavailable,
            ErrorCode::ResourceExhausted => CriErrorCode::ResourceExhausted,
            _ => CriErrorCode::Internal,
        };
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
        Self::new(code, err.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        ];
        for (oc, expected) in cases {
            let pe = PullError::new(oc, "msg");
            let st = Status::from(CriError::from(pe));
            assert_eq!(st.code(), expected);
            assert_eq!(st.message(), "msg");
            assert_eq!(st.code(), Status::from(pe).code());
        }
    }
}
