//! OCI Runtime ライフサイクル操作の失敗を表すエラー型と終了コード対応表（ERR-2・TASK-96.1）。
//!
//! create / start / kill / delete の失敗を、操作種別 `op`・機械可読な `code`・人間可読な `message`
//! の 3 点組で保持し、プロセス終了コードへ写像する。OCI Runtime Spec は「失敗時は非ゼロ終了＋
//! エラー報告」のみを要求し具体値を規定しないため、終了コードの数値は本プロジェクトの設計決定である。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! create / start（TASK-96.2）・kill / delete（TASK-96.3）の失敗経路への結線は済み（4 操作の公開関数の
//! 戻り値が [`OciRuntimeError`]）。標準エラー向けの構造化 1 行は
//! [`OciRuntimeError::write_json_line`] が任意の `Write` へ書く。キーは `op` / `code` / `message` の
//! 3 つ固定（`code` は [`ErrorCode::as_str`] の文字列で ERR-1 と同一体系）。共通ヘッダ（`event`・
//! タイムスタンプ等）は付けない（形式統一は TASK-98・ERR-4）。
//!
//! 実際に `stderr` へ書きプロセスを [`OciRuntimeError::exit_code`] で終了させるのは呼び出し元
//! （CLI〔TASK-79・TASK-95〕・plugin 側 `ContainerRuntime` 実装）の責務で、CLI は現状雛形のため未結線
//! である（REPAIR-3）。本モジュールは `stderr` へ直接書かず `std::process::exit` も呼ばない。
//! CLI 層の終了コードも二重の表を持たず [`exit_code_for`] を再利用する。
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
use std::io::Write;
use std::num::NonZeroU8;

use serde::Serialize;

use crate::sanitize::push_sanitized_bounded;
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
/// [`OciRuntimeError::new`] で Unicode 一般カテゴリ Cc・Cf・Zl・Zp の文字を空白へ置換し、
/// [`OCI_ERROR_MESSAGE_MAX_BYTES`] で切り詰める（行指向出力への行注入・端末制御シーケンス注入・
/// 双方向制御による表示偽装・巨大出力の防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OciRuntimeError {
    op: LifecycleOp,
    code: ErrorCode,
    message: String,
}

impl OciRuntimeError {
    /// エラーを構築する。`message` はサニタイズ（表示を乱す文字の置換・長さ上限での切り詰め）して保持する。
    pub fn new(op: LifecycleOp, code: ErrorCode, message: impl AsRef<str>) -> Self {
        // `AsRef<str>` で借用のまま受け取り、入力全体を `String` へ複製しない
        // （`&str` を `Into<String>` で受けると全量確保になるため）。
        let raw: &str = message.as_ref();
        // 置換後の空白（1 バイト）は元の文字のバイト長以下なので、出力長は
        // min(入力長, 上限) を超えない。よって初回確保のみで再確保は起きず、
        // 確保量も上限で頭打ちになる。
        let mut message = String::with_capacity(raw.len().min(OCI_ERROR_MESSAGE_MAX_BYTES));
        push_sanitized_bounded(&mut message, raw.chars(), OCI_ERROR_MESSAGE_MAX_BYTES);
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

/// 標準エラー向け 1 行 JSON の固定スキーマ（キー順は宣言順。ERR-2・TASK-96.2）。
#[derive(Serialize)]
struct StderrLine<'a> {
    op: &'static str,
    code: &'static str,
    message: &'a str,
}

impl OciRuntimeError {
    /// 標準エラー向けの構造化 1 行（`{"op":..,"code":..,"message":..}` + LF）を `out` へ書く（ERR-2）。
    ///
    /// CLI・plugin 側 `ContainerRuntime` 実装が `stderr` を渡す想定。JSON は `serde_json` で組み、
    /// `message` 内の `"` と `\` をエスケープする。`message` は構築時にサニタイズ・長さ上限済みのため
    /// 行は有界で LF は行末の 1 個のみ。他の出力との行混在を避けるため 1 回の `write_all` で書く。
    /// 書き込みに失敗しても呼び出し元は [`Self::exit_code`] で終了すること（終了コードを書き込みの
    /// 成否に依存させない）。
    pub fn write_json_line(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let line = StderrLine {
            op: self.op.as_str(),
            code: self.code.as_str(),
            message: &self.message,
        };
        let mut buf = serde_json::to_vec(&line).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        out.write_all(&buf)
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

    /// ERR-2: 規則（Cc・Cf・Zl・Zp）の各カテゴリの代表と Cf 範囲の両端が空白へ置換され、
    /// 書式文字ブロック内の予約位置 U+2065 も置換される。範囲の直外（U+00AC・U+2070・U+E0080）や
    /// 結合文字・通常の文字は保持される。
    #[test]
    fn err2_message_general_category_rule() {
        // Cc（U+007F・U+0085）・Zl・Zp・U+2065・各 Cf 範囲の両端。
        let mut unsafe_chars = vec!['\u{007F}', '\u{0085}', '\u{2028}', '\u{2029}', '\u{2065}'];
        for (lo, hi) in crate::sanitize::FORMAT_CHAR_RANGES {
            unsafe_chars.push(lo);
            unsafe_chars.push(hi);
        }
        for c in unsafe_chars {
            let input = format!("a{c}b");
            let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, &input);
            assert_eq!(e.message(), "a b", "U+{:04X}", u32::from(c));
        }
        let kept = "\u{00AC}\u{2070}\u{E0080}e\u{0301}é漢字 x";
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, kept);
        assert_eq!(e.message(), "\u{00AC}\u{2070}\u{E0080}e\u{0301}é漢字 x");
    }

    /// ERR-2: 巨大な入力（1 MiB）でも保持する `message` の確保量は上限（4096 バイト）で、
    /// 短い入力では入力長と同じ（置換で伸びないため再確保しない）。
    #[test]
    fn err2_message_allocation_is_capped_at_limit() {
        let huge = "x".repeat(1024 * 1024);
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, huge.as_str());
        assert_eq!(e.message.len(), 4096);
        assert_eq!(e.message.capacity(), 4096);

        let huge_err = TraitError::new(ErrorCode::Unavailable, "\u{202E}".repeat(1024 * 1024));
        let e = OciRuntimeError::from_trait_error(LifecycleOp::Kill, huge_err);
        // TraitError::new が 4096 バイト以下（3 バイト文字の境界で 4095）に切り詰め済み。
        assert_eq!(e.message.len(), 1365);
        assert_eq!(e.message.capacity(), 4095);
        assert_eq!(e.message, " ".repeat(1365));

        // U+202E・U+2028（各 3 バイト）を 1 バイトの空白へ置換しても入力長 8 の確保を超えない。
        let e = OciRuntimeError::new(
            LifecycleOp::Create,
            ErrorCode::Internal,
            "a\u{202E}b\u{2028}",
        );
        assert_eq!(e.message.as_str(), "a b ");
        assert_eq!(e.message.capacity(), 8);
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

    /// ERR-2: 標準エラー向け 1 行がバイト単位で固定の形式になる。
    #[test]
    fn err2_write_json_line_exact_bytes() {
        let e = OciRuntimeError::new(LifecycleOp::Start, ErrorCode::FailedPrecondition, "x");
        let mut out = Vec::new();
        e.write_json_line(&mut out).unwrap();
        assert_eq!(
            out,
            b"{\"op\":\"start\",\"code\":\"FAILED_PRECONDITION\",\"message\":\"x\"}\n"
        );
    }

    /// ERR-2: 引用符とバックスラッシュは JSON エスケープされ、読み戻すと元の 3 値に一致する。
    #[test]
    fn err2_write_json_line_escapes_and_roundtrips() {
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::NotFound, "a\"b\\c");
        let mut out = Vec::new();
        e.write_json_line(&mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["op"], "create");
        assert_eq!(v["code"], "NOT_FOUND");
        assert_eq!(v["message"], "a\"b\\c");
    }

    /// ERR-2: 改行を含む入力でも LF は行末の 1 個だけ（行注入されない）。
    #[test]
    fn err2_write_json_line_single_line() {
        let e = OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, "a\nb\r\nc");
        let mut out = Vec::new();
        e.write_json_line(&mut out).unwrap();
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(out.last(), Some(&b'\n'));
    }

    /// ERR-2: 上限長の `message` でも 1 行で出る。
    #[test]
    fn err2_write_json_line_max_length_message() {
        let e = OciRuntimeError::new(
            LifecycleOp::Delete,
            ErrorCode::Internal,
            "m".repeat(OCI_ERROR_MESSAGE_MAX_BYTES * 2),
        );
        let mut out = Vec::new();
        e.write_json_line(&mut out).unwrap();
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["message"].as_str().unwrap().len(), 4096);
    }

    /// ERR-2: 書き込み先が失敗しても `Err` を返し panic しない（終了コードは書き込みに依存しない）。
    #[test]
    fn err2_write_json_line_write_failure_is_err() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let e = OciRuntimeError::new(LifecycleOp::Kill, ErrorCode::Internal, "x");
        assert!(e.write_json_line(&mut Failing).is_err());
        assert_eq!(e.exit_code().get(), 1);
    }
}
