//! OCI Runtime ライフサイクル操作の失敗を表すエラー型と終了コード対応表（ERR-2・TASK-96.1）。
//!
//! create / start / kill / delete の失敗を、操作種別 `op`・機械可読な `code`・人間可読な `message`
//! の 3 点組で保持し、プロセス終了コードへ写像する。OCI Runtime Spec は「失敗時は非ゼロ終了＋
//! エラー報告」のみを要求し具体値を規定しないため、終了コードの数値は本プロジェクトの設計決定である。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! 本モジュールは型と対応表の定義のみ。各操作の失敗経路への結線と標準エラー出力への書き出しは
//! TASK-96.2（create / start）・TASK-96.3（kill / delete）で実装する。標準エラー出力の構造化形式の
//! フィールド名は `op` / `code` / `message` に固定する（`code` は [`ErrorCode::as_str`] の文字列で
//! ERR-1 と同一体系）。CLI 層（TASK-95）の終了コードも二重の表を持たず [`exit_code_for`] を再利用する。
//!
//! # 終了コード対応表（ERR-2）
//!
//! | `ErrorCode` | `code` 文字列 | 終了コード |
//! | ----------- | ------------- | ---------- |
//! | `Internal` | `INTERNAL` | 1 |
//! | `InvalidArgument` | `INVALID_ARGUMENT` | 2 |
//! | `NotFound` | `NOT_FOUND` | 3 |
//! | `AlreadyExists` | `ALREADY_EXISTS` | 4 |
//! | `FailedPrecondition` | `FAILED_PRECONDITION` | 5 |
//! | `PermissionDenied` | `PERMISSION_DENIED` | 6 |
//! | `Timeout` | `TIMEOUT` | 7 |
//! | `Unimplemented` | `UNIMPLEMENTED` | 8 |
//! | `Unavailable` | `UNAVAILABLE` | 9 |
//!
//! 1 は runc 互換の汎用失敗、2 以降は分類ごとに一意とし、標準エラー出力を解析せずに分類できるようにする。
//! 125〜127 はコンテナ子プロセス用（`exec/process.rs` の `EXIT_SETUP_FAILED`・`EXIT_EXEC_NOT_EXECUTABLE`・
//! `EXIT_EXEC_NOT_FOUND`。runc 慣例）、128 以上はシグナル終了の慣例と衝突するため、値域は 1..=124 とする。

use std::error::Error;
use std::fmt;
use std::num::NonZeroU8;

use crate::traits::{ErrorCode, TraitError};

/// `message` の最大バイト数。超過分は UTF-8 文字境界で切り詰める（無制限出力の防止）。
pub const OCI_ERROR_MESSAGE_MAX_BYTES: usize = 4096;

/// 定数から `NonZeroU8` を作る。0 を渡すとコンパイル時（const 評価）に失敗する。
const fn nz(n: u8) -> NonZeroU8 {
    match NonZeroU8::new(n) {
        Some(v) => v,
        None => panic!("exit code must be non-zero"),
    }
}

/// [`ErrorCode::Internal`] の終了コード（1）。
pub const OCI_EXIT_INTERNAL: NonZeroU8 = nz(1);
/// [`ErrorCode::InvalidArgument`] の終了コード（2）。
pub const OCI_EXIT_INVALID_ARGUMENT: NonZeroU8 = nz(2);
/// [`ErrorCode::NotFound`] の終了コード（3）。
pub const OCI_EXIT_NOT_FOUND: NonZeroU8 = nz(3);
/// [`ErrorCode::AlreadyExists`] の終了コード（4）。
pub const OCI_EXIT_ALREADY_EXISTS: NonZeroU8 = nz(4);
/// [`ErrorCode::FailedPrecondition`] の終了コード（5）。
pub const OCI_EXIT_FAILED_PRECONDITION: NonZeroU8 = nz(5);
/// [`ErrorCode::PermissionDenied`] の終了コード（6）。
pub const OCI_EXIT_PERMISSION_DENIED: NonZeroU8 = nz(6);
/// [`ErrorCode::Timeout`] の終了コード（7）。
pub const OCI_EXIT_TIMEOUT: NonZeroU8 = nz(7);
/// [`ErrorCode::Unimplemented`] の終了コード（8）。
pub const OCI_EXIT_UNIMPLEMENTED: NonZeroU8 = nz(8);
/// [`ErrorCode::Unavailable`] の終了コード（9）。
pub const OCI_EXIT_UNAVAILABLE: NonZeroU8 = nz(9);

/// [`ErrorCode`] を終了コードへ写像する（対応表はモジュール doc を参照。ERR-2）。
///
/// `_` 分岐を持たない網羅的 `match` である。`#[non_exhaustive]` は他 crate のみを制約するため、
/// `ErrorCode` にバリアントが追加されるとここがコンパイルエラーになり、写像漏れを防ぐ。
pub const fn exit_code_for(code: ErrorCode) -> NonZeroU8 {
    match code {
        ErrorCode::Internal => OCI_EXIT_INTERNAL,
        ErrorCode::InvalidArgument => OCI_EXIT_INVALID_ARGUMENT,
        ErrorCode::NotFound => OCI_EXIT_NOT_FOUND,
        ErrorCode::AlreadyExists => OCI_EXIT_ALREADY_EXISTS,
        ErrorCode::FailedPrecondition => OCI_EXIT_FAILED_PRECONDITION,
        ErrorCode::PermissionDenied => OCI_EXIT_PERMISSION_DENIED,
        ErrorCode::Timeout => OCI_EXIT_TIMEOUT,
        ErrorCode::Unimplemented => OCI_EXIT_UNIMPLEMENTED,
        ErrorCode::Unavailable => OCI_EXIT_UNAVAILABLE,
    }
}

/// 失敗した OCI Runtime ライフサイクル操作の種別。
///
/// 文字列表現は各操作の `OpRecorder` 操作名（`create`・`start`・`kill`・`delete`）と同一。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LifecycleOp {
    /// `create`（TASK-29.2）。
    Create,
    /// `start`（TASK-29.3）。
    Start,
    /// `kill`（TASK-30.1）。
    Kill,
    /// `delete`（TASK-30.2）。
    Delete,
}

impl LifecycleOp {
    /// 操作名の文字列表現を返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Kill => "kill",
            Self::Delete => "delete",
        }
    }
}

/// OCI Runtime ライフサイクル操作の失敗（ERR-2）。
///
/// 操作種別 `op`・機械可読な `code`・人間可読な `message` を持ち、[`OciRuntimeError::exit_code`] で
/// 非ゼロの終了コードへ写像できる。`message` に資格情報などの秘密情報を含めてはならない
/// （[`TraitError`] と同じ契約）。`message` は plugin 応答由来の untrusted な値になり得るため、
/// [`OciRuntimeError::new`] で制御文字を空白へ置換し、[`OCI_ERROR_MESSAGE_MAX_BYTES`] で切り詰める
/// （行指向出力への行注入・端末制御シーケンス注入・巨大出力の防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciRuntimeError {
    op: LifecycleOp,
    code: ErrorCode,
    message: String,
}

/// 表示を乱しうる非制御の書式文字（行・段落区切り、双方向制御、ゼロ幅文字、BOM）か判定する。
fn is_unsafe_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{2028}' | '\u{2029}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

impl OciRuntimeError {
    /// エラーを構築する。`message` はサニタイズ（制御文字の置換・長さ上限での切り詰め）して保持する。
    pub fn new(op: LifecycleOp, code: ErrorCode, message: impl AsRef<str>) -> Self {
        // `AsRef<str>` で借用のまま受け取り、入力全体を `String` へ複製しない
        // （`&str` を `Into<String>` で受けると全量確保になるため）。
        let raw: &str = message.as_ref();
        // 全量を複製せず、出力が上限に達するまでだけサニタイズして収集する
        // （untrusted な巨大メッセージによるメモリ・CPU の浪費を防ぐ）。
        let mut message = String::with_capacity(raw.len().min(OCI_ERROR_MESSAGE_MAX_BYTES));
        for c in raw.chars() {
            // `is_control()` は U+2028 / U+2029（行・段落区切り）や双方向テキスト制御文字
            // （U+202E 等。表示順を操作してエラー内容を偽装できる）を含まないため明示的に置換する。
            let c = if c.is_control() || is_unsafe_format_char(c) {
                ' '
            } else {
                c
            };
            if message.len() + c.len_utf8() > OCI_ERROR_MESSAGE_MAX_BYTES {
                break;
            }
            message.push(c);
        }
        Self { op, code, message }
    }

    /// 既存の [`TraitError`] の `code` / `message` を引き継いで操作種別を付与する。
    pub fn from_trait_error(op: LifecycleOp, err: TraitError) -> Self {
        Self::new(op, err.code(), err.message())
    }

    /// 失敗した操作の種別を返す。
    pub fn op(&self) -> LifecycleOp {
        self.op
    }

    /// 機械可読なエラー分類を返す。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 人間可読な説明（サニタイズ済み）を返す。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// プロセス終了コードを返す（非ゼロ。対応表はモジュール doc を参照）。
    pub fn exit_code(&self) -> NonZeroU8 {
        exit_code_for(self.code)
    }
}

impl fmt::Display for OciRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.op.as_str(),
            self.code.as_str(),
            self.message
        )
    }
}

impl Error for OciRuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [(ErrorCode, u8); 9] = [
        (ErrorCode::Internal, 1),
        (ErrorCode::InvalidArgument, 2),
        (ErrorCode::NotFound, 3),
        (ErrorCode::AlreadyExists, 4),
        (ErrorCode::FailedPrecondition, 5),
        (ErrorCode::PermissionDenied, 6),
        (ErrorCode::Timeout, 7),
        (ErrorCode::Unimplemented, 8),
        (ErrorCode::Unavailable, 9),
    ];

    /// ERR-2: 各 ErrorCode が対応表どおりの終了コードになる。
    #[test]
    fn err2_exit_code_per_error_code() {
        for (code, expected) in ALL {
            assert_eq!(exit_code_for(code).get(), expected, "{}", code.as_str());
        }
    }

    /// ERR-2: 終了コードは 1..=124 で相互に重複せず、125〜127 と衝突しない。
    #[test]
    fn err2_exit_codes_are_distinct_nonzero_and_below_125() {
        let mut seen = std::collections::HashSet::new();
        for (code, _) in ALL {
            let n = exit_code_for(code).get();
            assert!((1..=124).contains(&n));
            assert!(seen.insert(n));
        }
        assert_eq!(seen.len(), 9);
    }

    /// ERR-2: 操作名は OpRecorder の操作名と一致する。
    #[test]
    fn err2_lifecycle_op_as_str() {
        assert_eq!(LifecycleOp::Create.as_str(), "create");
        assert_eq!(LifecycleOp::Start.as_str(), "start");
        assert_eq!(LifecycleOp::Kill.as_str(), "kill");
        assert_eq!(LifecycleOp::Delete.as_str(), "delete");
    }

    /// ERR-2: TraitError の code / message を保持する。
    #[test]
    fn err2_from_trait_error_preserves_code_and_message() {
        let e = OciRuntimeError::from_trait_error(
            LifecycleOp::Start,
            TraitError::new(ErrorCode::NotFound, "container not found"),
        );
        assert_eq!(e.op(), LifecycleOp::Start);
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert_eq!(e.message(), "container not found");
        assert_eq!(e.exit_code().get(), 3);
    }

    /// ERR-2: Display は `<op>: <CODE>: <message>`。
    #[test]
    fn err2_display_format() {
        let e = OciRuntimeError::new(
            LifecycleOp::Kill,
            ErrorCode::Timeout,
            "signaler did not respond",
        );
        assert_eq!(e.to_string(), "kill: TIMEOUT: signaler did not respond");
    }

    /// ERR-2: 制御文字は空白へ置換される。
    #[test]
    fn err2_message_control_chars_are_replaced() {
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a\nb\r\x1b[31mc\0",
        );
        assert_eq!(e.message(), "a b  [31mc ");
    }

    /// ERR-2: U+2028 / U+2029（行・段落区切り）も空白へ置換される。
    #[test]
    fn err2_message_unicode_line_separators_are_replaced() {
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a\u{2028}b\u{2029}c",
        );
        assert_eq!(e.message(), "a b c");
    }

    /// ERR-2: 双方向テキスト制御文字（U+202E 等）やゼロ幅文字も空白へ置換される。
    #[test]
    fn err2_message_bidi_controls_are_replaced() {
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a\u{202E}b\u{2066}c\u{2069}d\u{200F}e\u{061C}f\u{FEFF}g",
        );
        assert_eq!(e.message(), "a b c d e f g");
    }

    /// ERR-2: U+2060（WORD JOINER）・U+206A-U+206F（非推奨の書式制御）も空白へ置換される。
    #[test]
    fn err2_message_word_joiner_and_deprecated_format_chars_are_replaced() {
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a\u{2060}b\u{206A}c\u{206F}d",
        );
        assert_eq!(e.message(), "a b c d");
    }

    /// ERR-2: 上限超過は文字境界で切り詰められる。
    #[test]
    fn err2_message_is_truncated_at_char_boundary() {
        let max = OCI_ERROR_MESSAGE_MAX_BYTES;
        let exact = "a".repeat(max);
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, exact.clone());
        assert_eq!(e.message(), exact);
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a".repeat(max + 1),
        );
        assert_eq!(e.message().len(), max);
        // 「あ」は 3 バイト。4096 は 3 の倍数でないため境界は文字の途中に来る。
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, "あ".repeat(max));
        assert_eq!(e.message().len(), 4095);
        assert!(e.message().ends_with('あ'));
    }

    /// ERR-2: `dyn Error` として扱える。
    #[test]
    fn err2_error_trait_object() {
        let e = OciRuntimeError::new(LifecycleOp::Delete, ErrorCode::NotFound, "gone");
        let expected = e.to_string();
        let boxed: Box<dyn Error> = Box::new(e);
        assert_eq!(boxed.to_string(), expected);
        assert_eq!(expected, "delete: NOT_FOUND: gone");
    }
}
