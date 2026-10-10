//! plugin 信頼検証の拒否を error-format 準拠の構造化エラーと監査レコードにする（PLUG-11・ERR-1・SEC-4・TASK-122.5・#283）。
//!
//! # 役割と呼び出し元
//!
//! 親モジュール `plugin_trust` が返す [`PluginTrustError`] に、拒否理由ごとに一意な安定トークン
//! （[`PluginTrustError::reason`]）・静的英語 message・ERR-1 の `code` を与える。将来のレジストリ配線 /
//! CLI が、拒否を stderr の 1 行 JSON（[`PluginTrustError::write_json_line`]）と監査ログ
//! （[`record_plugin_trust_rejection`]）へ出すために使う。
//!
//! # 契約
//!
//! - `code` は既存の `From<PluginTrustError> for TraitError` と同じ写像（ERR-1 の `ErrorCode`）。理由の区別は
//!   `reason` トークンで行い、`ErrorCode` 自体は増やさない
//! - `message` は kind ごとの静的英語で、パス等の入力値を含めない。パスは別フィールド `path` に分離する
//! - 監査は拒否 1 回につき 1 レコード。記録の成否で拒否を覆さない（fail-closed。[`AuditedRejection`]）
//!
//! # 未実装（REPAIR-3）
//!
//! レジストリ登録経路・本番の `AuditSink`・CLI の終了コード処理への配線は後続。現時点で本番経路からは
//! 呼ばれない。[`verify_candidate_audited`] は検証方式の切替点
//! （[`PluginVerificationMethod::verify`]）を通す。

use std::io::Write;

use serde::Serialize;

use crate::audit_log::mount::deliver;
use crate::audit_log::{
    AUDIT_PATH_MAX_BYTES, AuditEvent, AuditPath, AuditReason, AuditSink, AuditedRejection,
};
use crate::plugin_discovery::PluginCandidate;
use crate::traits::ErrorCode;

use super::{
    HashVerifiedPluginFile, PluginTrustError, PluginTrustErrorKind, PluginVerificationMethod,
    TrustTarget, verify_candidate,
};

impl PluginTrustErrorKind {
    /// 拒否理由ごとに一意な安定トークン（小文字 snake_case の ASCII）。
    ///
    /// match は網羅必須（kind の追加時にコンパイルエラーで追随漏れを検出する）。
    pub const fn as_str(self) -> &'static str {
        match self {
            PluginTrustErrorKind::UntrustedOwner => "untrusted_owner",
            PluginTrustErrorKind::GroupOrOtherWritable => "group_or_other_writable",
            PluginTrustErrorKind::NotRegularFile => "not_regular_file",
            PluginTrustErrorKind::NotDirectory => "not_directory",
            PluginTrustErrorKind::InvalidPath => "invalid_path",
            PluginTrustErrorKind::Io => "io",
            PluginTrustErrorKind::SymlinkLoop => "symlink_loop",
            PluginTrustErrorKind::Unsupported => "unsupported",
            PluginTrustErrorKind::HashMismatch => "hash_mismatch",
            PluginTrustErrorKind::TooLarge => "too_large",
            PluginTrustErrorKind::VerificationMethodNotImplemented => {
                "verification_method_not_implemented"
            }
        }
    }

    /// 人間向け説明（静的英語。入力値は含めない）。
    pub const fn message(self) -> &'static str {
        match self {
            PluginTrustErrorKind::UntrustedOwner => {
                "plugin owner is neither root nor the effective user"
            }
            PluginTrustErrorKind::GroupOrOtherWritable => "plugin is writable by group or other",
            PluginTrustErrorKind::NotRegularFile => "plugin is not a regular file",
            PluginTrustErrorKind::NotDirectory => {
                "plugin directory is not a directory or is a symlink"
            }
            PluginTrustErrorKind::InvalidPath => "plugin path is invalid",
            PluginTrustErrorKind::Io => "failed to open or stat the plugin path",
            PluginTrustErrorKind::SymlinkLoop => "plugin symlink loops or the chain is too long",
            PluginTrustErrorKind::Unsupported => {
                "plugin trust verification is not supported on this platform"
            }
            PluginTrustErrorKind::HashMismatch => {
                "plugin sha256 digest is not in the allowed hash list"
            }
            PluginTrustErrorKind::TooLarge => "plugin file exceeds the maximum allowed size",
            PluginTrustErrorKind::VerificationMethodNotImplemented => {
                "requested plugin verification method is not implemented"
            }
        }
    }

    /// ERR-1 の `ErrorCode`（`From<PluginTrustError> for TraitError` と同じ写像）。
    const fn code(self) -> ErrorCode {
        match self {
            PluginTrustErrorKind::UntrustedOwner
            | PluginTrustErrorKind::GroupOrOtherWritable
            | PluginTrustErrorKind::HashMismatch => ErrorCode::PermissionDenied,
            PluginTrustErrorKind::NotRegularFile
            | PluginTrustErrorKind::NotDirectory
            | PluginTrustErrorKind::SymlinkLoop
            | PluginTrustErrorKind::TooLarge
            | PluginTrustErrorKind::InvalidPath => ErrorCode::InvalidArgument,
            PluginTrustErrorKind::Io => ErrorCode::Internal,
            PluginTrustErrorKind::Unsupported
            | PluginTrustErrorKind::VerificationMethodNotImplemented => ErrorCode::Unimplemented,
        }
    }
}

/// 標準エラー向けワイヤー表現（非公開 DTO）。キー順はフィールド宣言順。
#[derive(Serialize)]
struct ErrorLineDto<'a> {
    code: &'static str,
    message: &'static str,
    reason: &'static str,
    target: &'static str,
    path: &'a str,
}

impl PluginTrustError {
    /// ERR-1 の `code`。
    pub fn code(&self) -> ErrorCode {
        self.kind.code()
    }

    /// 拒否理由の安定トークン（受入基準: 理由ごとに区別可能）。
    pub fn reason(&self) -> &'static str {
        self.kind.as_str()
    }

    /// 静的英語の説明（パスを含まない）。
    pub fn message(&self) -> &'static str {
        self.kind.message()
    }

    /// 構造化 1 行（`{"code":..,"message":..,"reason":..,"target":..,"path":..}` + LF）を `out` へ書く（ERR-1）。
    ///
    /// `path` は JSON エスケープ後のバイト長が [`AUDIT_PATH_MAX_BYTES`]（4096）以下になるよう、
    /// `to_string_lossy` 後に文字境界で切り詰める（制御文字は最大 6 バイトに膨らむため直列化後基準）。JSON は `serde_json` で
    /// 組むため改行・引用符・制御文字はエスケープされ、LF は行末の 1 個のみ。1 回の `write_all` で書く。
    /// stderr への出力と終了コード決定は呼び出し元の責務で、書き込み失敗を終了コードに影響させないこと。
    pub fn write_json_line(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let lossy = self.path().to_string_lossy();
        let path = truncate_for_json(&lossy, AUDIT_PATH_MAX_BYTES);
        let dto = ErrorLineDto {
            code: self.code().as_str(),
            message: self.message(),
            reason: self.reason(),
            target: match self.target {
                TrustTarget::Directory => "directory",
                TrustTarget::File => "file",
            },
            path,
        };
        let mut buf = serde_json::to_vec(&dto).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        out.write_all(&buf)
    }
}

/// JSON 文字列リテラルとして直列化したときの 1 文字分のバイト長（`serde_json` のエスケープ規則）。
fn json_escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// エスケープ後の直列化バイト長が `max` 以下になる最長の文字境界接頭辞を返す。
fn truncate_for_json(s: &str, max: usize) -> &str {
    let mut used = 0usize;
    for (i, c) in s.char_indices() {
        used += json_escaped_len(c);
        if used > max {
            return s.get(..i).unwrap_or("");
        }
    }
    s
}

/// 拒否 `error` を `PluginTrust` 監査レコードとして 1 件記録し、`error` をそのまま返す（SEC-4）。
///
/// 記録の成否で拒否を覆さない（fail-closed）。結果は `delivery` に載り黙って捨てない。
pub fn record_plugin_trust_rejection(
    error: PluginTrustError,
    sink: &dyn AuditSink,
) -> AuditedRejection<PluginTrustError> {
    let event = AuditEvent::PluginTrust {
        path: AuditPath::new(error.path()),
        reason: AuditReason::new(error.reason()),
    };
    // plugin の信頼検証は特定のコンテナに属さないため container_id は載せない（#1618）。
    let delivery = deliver(event, None, sink);
    AuditedRejection { error, delivery }
}

/// 候補 1 件を所有者・モード・ハッシュの順に検証し、どの段の拒否も監査へ記録して返す（PLUG-11・SEC-4）。
///
/// 検証自体は [`verify_candidate`] → [`PluginVerificationMethod::verify`]（方式の唯一の切替点。保持 fd 経由。
/// 緩めない）を通す。未実装方式（署名）の `VerificationMethodNotImplemented` 拒否も他の拒否と同様に監査へ記録する。
pub fn verify_candidate_audited(
    candidate: &PluginCandidate,
    method: &PluginVerificationMethod,
    sink: &dyn AuditSink,
) -> Result<HashVerifiedPluginFile, AuditedRejection<PluginTrustError>> {
    let file = verify_candidate(candidate).map_err(|e| record_plugin_trust_rejection(e, sink))?;
    verify_method_audited(file, method, sink)
}

/// 所有者・モード検証済みの `file` を `method` で検証し、拒否を監査へ記録する（[`verify_candidate_audited`] の後段）。
///
/// 未実装方式の拒否（`VerificationMethodNotImplemented`）もここで 1 件記録される。
pub(crate) fn verify_method_audited(
    file: super::VerifiedPluginFile,
    method: &PluginVerificationMethod,
    sink: &dyn AuditSink,
) -> Result<HashVerifiedPluginFile, AuditedRejection<PluginTrustError>> {
    method
        .verify(file)
        .map_err(|e| record_plugin_trust_rejection(e, sink))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::mount::tests::VecSink;
    use crate::audit_log::{AuditDelivery, AuditLayer};
    use crate::traits::TraitError;
    use std::path::Path;

    const ALL: [PluginTrustErrorKind; 11] = [
        PluginTrustErrorKind::UntrustedOwner,
        PluginTrustErrorKind::GroupOrOtherWritable,
        PluginTrustErrorKind::NotRegularFile,
        PluginTrustErrorKind::NotDirectory,
        PluginTrustErrorKind::InvalidPath,
        PluginTrustErrorKind::Io,
        PluginTrustErrorKind::SymlinkLoop,
        PluginTrustErrorKind::Unsupported,
        PluginTrustErrorKind::HashMismatch,
        PluginTrustErrorKind::TooLarge,
        PluginTrustErrorKind::VerificationMethodNotImplemented,
    ];

    fn err(kind: PluginTrustErrorKind, path: &str) -> PluginTrustError {
        PluginTrustError::new(kind, TrustTarget::File, Path::new(path))
    }

    /// 受入基準 A: reason は全 kind で相互に異なり、小文字 snake_case。
    #[test]
    fn plug11_task122_5_reasons_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for k in ALL {
            let r = k.as_str();
            assert!(!r.is_empty());
            assert!(
                r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{r}"
            );
            assert!(seen.insert(r), "duplicate reason {r}");
        }
        assert_eq!(seen.len(), 11);
    }

    /// 受入基準 B: message は英語 ASCII で、パスを含まない。代表 3 種は具体値で照合する。
    #[test]
    fn plug11_task122_5_messages_are_static_english() {
        for k in ALL {
            let e = err(k, "/secret/dir/fandhe-container-plugin-x");
            assert!(e.message().is_ascii() && !e.message().is_empty());
            assert!(!e.message().contains("/secret"));
        }
        assert_eq!(
            PluginTrustErrorKind::UntrustedOwner.message(),
            "plugin owner is neither root nor the effective user"
        );
        assert_eq!(
            PluginTrustErrorKind::GroupOrOtherWritable.message(),
            "plugin is writable by group or other"
        );
        assert_eq!(
            PluginTrustErrorKind::HashMismatch.message(),
            "plugin sha256 digest is not in the allowed hash list"
        );
    }

    /// code は既存の TraitError 変換と全 kind で一致する（写像の不変）。
    #[test]
    fn plug11_task122_5_code_matches_trait_error_mapping() {
        for k in ALL {
            let e = err(k, "/x");
            let t: TraitError = e.clone().into();
            assert_eq!(e.code(), t.code(), "{k:?}");
        }
        assert_eq!(
            err(PluginTrustErrorKind::HashMismatch, "/x").code(),
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn plug11_task122_5_json_line_exact() {
        let e = err(
            PluginTrustErrorKind::HashMismatch,
            "/x/fandhe-container-plugin-a",
        );
        let mut buf = Vec::new();
        e.write_json_line(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "{\"code\":\"PERMISSION_DENIED\",\"message\":\"plugin sha256 digest is not in the allowed hash list\",\"reason\":\"hash_mismatch\",\"target\":\"file\",\"path\":\"/x/fandhe-container-plugin-a\"}\n"
        );
    }

    #[test]
    fn plug11_task122_5_json_line_is_single_line_and_bounded() {
        let hostile = format!("/a\n\"b\u{1}{}", "x".repeat(10_000));
        let e = PluginTrustError::new(
            PluginTrustErrorKind::UntrustedOwner,
            TrustTarget::Directory,
            Path::new(&hostile),
        );
        let mut buf = Vec::new();
        e.write_json_line(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.matches('\n').count(), 1);
        assert!(s.ends_with("}\n"));
        assert!(s.contains("\"target\":\"directory\""));
        assert!(s.len() < 4096 + 512);
    }

    /// 制御文字だらけのパスでも直列化後の `path` 値が 4096 バイト以下（Codex P2）。
    #[test]
    fn plug11_task122_5_json_path_bound_holds_after_escaping() {
        let hostile = format!("/{}", "\u{1}".repeat(4000));
        let e = PluginTrustError::new(
            PluginTrustErrorKind::UntrustedOwner,
            TrustTarget::File,
            Path::new(&hostile),
        );
        let mut buf = Vec::new();
        e.write_json_line(&mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let path = v["path"].as_str().unwrap();
        let ser = serde_json::to_string(path).unwrap();
        assert!(ser.len() - 2 <= 4096, "len={}", ser.len() - 2);
        assert_eq!(path.chars().count(), 1 + (4096 - 1) / 6);
    }

    /// 受入基準 C: 所有者・モード・ハッシュの 3 種がそれぞれ理由つきで 1 件記録される。
    #[test]
    fn plug11_task122_5_records_one_audit_record_per_rejection() {
        for (k, token) in [
            (PluginTrustErrorKind::UntrustedOwner, "untrusted_owner"),
            (
                PluginTrustErrorKind::GroupOrOtherWritable,
                "group_or_other_writable",
            ),
            (PluginTrustErrorKind::HashMismatch, "hash_mismatch"),
        ] {
            let sink = VecSink::new(false);
            let r = record_plugin_trust_rejection(err(k, "/p/plugin"), &sink);
            assert_eq!(r.error, err(k, "/p/plugin"));
            assert_eq!(r.delivery, AuditDelivery::Recorded);
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::PluginTrust);
            assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
            assert_eq!(recs[0].path(), Some(Path::new("/p/plugin")));
        }
    }

    /// fail-closed: sink が失敗しても拒否エラーは不変。
    #[test]
    fn plug11_task122_5_sink_failure_keeps_rejection() {
        let sink = VecSink::new(true);
        let e = err(PluginTrustErrorKind::HashMismatch, "/p/plugin");
        let r = record_plugin_trust_rejection(e.clone(), &sink);
        assert_eq!(r.error, e);
        assert!(matches!(r.delivery, AuditDelivery::SinkFailed(_)));
        assert!(sink.snapshot().is_empty());
    }
}
