//! `NetError` を core の `TraitError` へ写す、コードを保つ写像の唯一の実装（REPAIR-1・ERR-1・NET-6・NET-9）。
//!
//! `fandhe-container-net` は core に依存しないため、`NetErrorCode` から `ErrorCode` への写像は net 側に置けない。
//! core と net の両方に依存する最下位の crate がこの supervisor で、cli（`create_pasta`・`network`）と
//! plugin-cri（`netsetup`）はどちらも supervisor に依存済みのため、ここへ集約する。
//!
//! # 使い分け
//!
//! - 本モジュール: 同名の 8 コード（`InvalidArgument`・`NotFound`・`AlreadyExists`・`PermissionDenied`・
//!   `FailedPrecondition`・`Timeout`・`ResourceExhausted`・`Unimplemented`）を保つ。呼び出し元が分類で
//!   分岐する経路（pasta の解決・ネットワーク定義の操作・CRI の netsetup・holder の起動）が使う
//! - `container_options::network::net_error_to_trait`: 入力検証（FCOPT1 の再検証・cli `create` の
//!   `--network` / `--add-host` / `--dns`）と `start --network host` の netns 照合用の **別の契約**。
//!   利用者へ返すコードを 4 種（`InvalidArgument`・`Unimplemented`・`ResourceExhausted`・
//!   `FailedPrecondition`）に絞り、残りは `Internal` に畳む。その出力は試験 `net12_error_mapping` が固定しており、
//!   本写像へ広げると `HostNetns::detect` の `NotFound`・`PermissionDenied` の出力が変わるため統合しない
//!
//! # 同名の `ErrorCode` が無いコード
//!
//! `DataLoss` と将来追加されるコード（`NetErrorCode` は `#[non_exhaustive]`）は `Internal` に畳む
//! （fail-closed。成功や前提違反と取り違えさせない）。[`net_error_to_trait_keeping_code`] は元の分類を
//! `message` の先頭へ `<NAME>: ` で残す。

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_net::error::{NetError, NetErrorCode};

/// `NetErrorCode` を `ErrorCode` へ同名で写す。`DataLoss` と未知のコードだけ `Internal`。
pub fn net_code_to_trait(code: NetErrorCode) -> ErrorCode {
    match code {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::NotFound => ErrorCode::NotFound,
        NetErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        NetErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        NetErrorCode::Timeout => ErrorCode::Timeout,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        _ => ErrorCode::Internal,
    }
}

/// `NetError` をコードを保ったまま `TraitError` へ写す（message は net の固定の英文で入力値を含まない）。
///
/// `DataLoss` は `ErrorCode` に対応が無いため `Internal` にし、元のコード名を `message` の先頭へ残す。
pub fn net_error_to_trait_keeping_code(e: &NetError) -> TraitError {
    if e.code() == NetErrorCode::DataLoss {
        return TraitError::new(
            ErrorCode::Internal,
            format!("{}: {}", e.code().as_str(), e.message()),
        );
    }
    TraitError::new(net_code_to_trait(e.code()), e.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ERR-1: 全 `NetErrorCode` が `ErrorCode` へ写り、同名があれば名前が一致し、無いのは `DataLoss` だけ。
    #[test]
    fn err1_keeping_code_covers_all_net_codes() {
        for nc in NetErrorCode::ALL {
            let t = net_error_to_trait_keeping_code(&NetError::new(nc, "m"));
            match ErrorCode::from_name(nc.as_str()) {
                Some(ec) => {
                    assert_eq!(t.code(), ec, "{nc:?}");
                    assert_eq!(t.message(), "m");
                }
                None => {
                    assert_eq!(nc, NetErrorCode::DataLoss);
                    assert_eq!(t.code(), ErrorCode::Internal);
                    assert_eq!(t.message(), "DATA_LOSS: m");
                }
            }
        }
        let core_only: Vec<&str> = ErrorCode::ALL
            .iter()
            .map(|c| c.as_str())
            .filter(|n| !NetErrorCode::ALL.iter().any(|nc| nc.as_str() == *n))
            .collect();
        assert_eq!(core_only, ["UNAVAILABLE"]);
    }

    /// ERR-1: 具体値の固定。
    #[test]
    fn err1_net_code_to_trait_concrete_values() {
        for (n, t) in [
            (NetErrorCode::InvalidArgument, ErrorCode::InvalidArgument),
            (NetErrorCode::NotFound, ErrorCode::NotFound),
            (NetErrorCode::AlreadyExists, ErrorCode::AlreadyExists),
            (NetErrorCode::PermissionDenied, ErrorCode::PermissionDenied),
            (
                NetErrorCode::FailedPrecondition,
                ErrorCode::FailedPrecondition,
            ),
            (NetErrorCode::Timeout, ErrorCode::Timeout),
            (
                NetErrorCode::ResourceExhausted,
                ErrorCode::ResourceExhausted,
            ),
            (NetErrorCode::Unimplemented, ErrorCode::Unimplemented),
            (NetErrorCode::DataLoss, ErrorCode::Internal),
        ] {
            assert_eq!(net_code_to_trait(n), t, "{n:?}");
        }
    }
}
