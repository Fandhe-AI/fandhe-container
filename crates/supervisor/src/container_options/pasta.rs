//! 文書に記録された pasta の起動時の再検証（NET-9・PLUG-11・SEC-4・SUP-12・#3199）。
//!
//! `docs/design/rootless-network.md` 12.4 の「起動時の再検証は supervisor が行う」の窓口。文書の復号
//! （[`ContainerOptionsDocument::decode`]）は本文の形だけを検証して副作用を持たないため、バイナリの辿り直し・
//! `--version` の実行・記録した識別との照合は本関数が起動の直前に行う。exec に使えるのは返り値の
//! `PastaBinary` だけで、記録の本文からパスを取り出して実行する経路は無い。
//!
//! # 将来仕様・残余（REPAIR-3）
//!
//! - start の経路（`start_entry`）からの呼び出しは #1940 が結線する。現状は `NetworkSelection::Named` が
//!   `Unimplemented` で拒否されるため、本関数は本番経路から呼ばれない。
//! - SEC-4 の監査の記録（識別の不一致と `PermissionDenied`）は #1940。core の `AuditLayer` に pasta 用の語彙が
//!   無いため、本関数は分類（[`PastaReverifyError::tamper_suspected`]）だけを返し、記録は呼び出し側の責務とする。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::pasta::binary::PastaBinary;
use fandhe_container_net::pasta::record::{MSG_RECORD_CHANGED, PastaRecord};

use super::document::ContainerOptionsDocument;

/// 再検証の失敗（コードを保ったまま `TraitError` へ写せる。net のコードを `Internal` に潰さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastaReverifyError {
    code: NetErrorCode,
    message: String,
}

impl PastaReverifyError {
    /// 呼び出し元のエラー型へ写す（固定の英文のまま。コードは保つ。未知のコードは `Internal`）。
    pub fn trait_error(&self) -> TraitError {
        let code = match self.code {
            NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
            NetErrorCode::NotFound => ErrorCode::NotFound,
            NetErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
            NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
            NetErrorCode::Timeout => ErrorCode::Timeout,
            NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
            NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
            _ => ErrorCode::Internal,
        };
        TraitError::new(code, self.message.clone())
    }

    /// 改ざんの疑い（識別の不一致と祖先・バイナリの権限違反）か。SEC-4 の監査に記録する対象の判定材料。
    pub fn tamper_suspected(&self) -> bool {
        self.code == NetErrorCode::PermissionDenied
            || (self.code == NetErrorCode::FailedPrecondition && self.message == MSG_RECORD_CHANGED)
    }
}

impl From<NetError> for PastaReverifyError {
    fn from(e: NetError) -> Self {
        Self {
            code: e.code(),
            message: e.message().to_owned(),
        }
    }
}

/// 文書に `pasta` の記録があれば、バイナリを検証し直して記録と照合する（記録が無ければ `Ok(None)`）。
///
/// 本文は未信頼の入力として毎回 [`PastaRecord::parse_body`] で形を検証し直す。`FailedPrecondition` は
/// 作成時から変わったことを表す（12.4）。
pub fn reverify_recorded_pasta(
    doc: &ContainerOptionsDocument,
) -> Result<Option<PastaBinary>, PastaReverifyError> {
    let Some(body) = doc.pasta() else {
        return Ok(None);
    };
    let record = PastaRecord::parse_body(body)?;
    Ok(Some(record.reverify()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: NetErrorCode, msg: &str) -> PastaReverifyError {
        NetError::new(code, msg.to_owned()).into()
    }

    /// NET-9・SEC-4: コードを保って写し、改ざんの疑いを分類する。
    #[test]
    fn net9_sec4_reverify_maps_codes_and_tamper() {
        let cases = [
            (NetErrorCode::NotFound, ErrorCode::NotFound, false),
            (
                NetErrorCode::PermissionDenied,
                ErrorCode::PermissionDenied,
                true,
            ),
            (NetErrorCode::Timeout, ErrorCode::Timeout, false),
            (
                NetErrorCode::InvalidArgument,
                ErrorCode::InvalidArgument,
                false,
            ),
            (NetErrorCode::Unimplemented, ErrorCode::Unimplemented, false),
            (
                NetErrorCode::ResourceExhausted,
                ErrorCode::ResourceExhausted,
                false,
            ),
            (NetErrorCode::Internal, ErrorCode::Internal, false),
        ];
        for (n, t, tamper) in cases {
            let e = err(n, "fixed");
            assert_eq!(e.trait_error().code(), t, "{n:?}");
            assert_eq!(e.trait_error().message(), "fixed");
            assert_eq!(e.tamper_suspected(), tamper, "{n:?}");
        }
        let changed = err(NetErrorCode::FailedPrecondition, MSG_RECORD_CHANGED);
        assert_eq!(changed.trait_error().code(), ErrorCode::FailedPrecondition);
        assert!(changed.tamper_suspected());
        let other = err(
            NetErrorCode::FailedPrecondition,
            "pasta binary is not executable",
        );
        assert!(!other.tamper_suspected());
    }

    /// NET-9: 記録の無い文書は何も検証しない。
    #[test]
    fn net9_reverify_without_record_is_none() {
        let doc = ContainerOptionsDocument::default();
        assert!(reverify_recorded_pasta(&doc).expect("none").is_none());
    }
}
