//! DNS ヘルパーの制御 UDS（再読込の ack・停止要求）と、記録からの名前の読み込み
//! （NET-5・PLUG-12・REPAIR-2・REPAIR-5・SEC-1・#3071。設計は `docs/design/network-wiring.md` の D11・D14・D15）。
//!
//! # 役割と呼び出し文脈
//! CORE-1 により、ヘルパーの起動・停止・名前の更新は別々のプロセスで起きる。ヘルパーのプロセスの外から名前を
//! 伝える経路として、ネットワークごとの制御 UDS `<state_root>/@networks/<name>/dns.ctl`（0600）を持つ。
//! - ヘルパー側（段 2）: 起動時に bind し、`Reload{generation}` を受けたらメンバー記録（`members/<id>`）を読み直して
//!   レジストリを一括に差し替え、`Loaded{generation}` を返す。`Stop` を受けたら停止フラグを立てる。
//!   接続してきた相手の uid を `SO_PEERCRED` で照合し、実効 uid と違えばフレームを読まずに切断する（PLUG-12）
//! - 送り手側: 記録を書いた側（`network::recorded` の attach）が `reload_dns_helper` で `Reload` を送り、`Loaded` を
//!   [`DNS_RELOAD_ACK_TIMEOUT`]（2 秒。D15）まで待つ。来なければ attach を失敗にする。停止は
//!   `ControlStopRequest` が `DnsHelperStopRequest` として `stop_recorded_dns_helper` に渡る
//! - 呼び出し元の配線（0→1 の起動・1→0 の停止の呼び出し）は #3074・#3075。上流転送（`--dns`）は #3072
//!
//! # 構成
//! - [`frame`]: 型付きの長さ接頭辞フレーム（OS 非依存）
//! - [`authorize_peer`]: 接続の uid 判定（純関数）
//! - `os`（Linux）: ヘルパー側のサーバーと送り手
//!
//! # 安全性
//! - ソケットは 0700 のネットワークのディレクトリの下の 0600。送り手は connect の前に lstat（socket・所有者・
//!   0600・nlink 1）、connect の後に peer の uid と pid（記録の pid）を照合する（双方向。SEC-1）
//! - フレームは固定ヘッダーと 8 バイト以下のペイロードで、長さを検証してから固定長の配列へ読む（確保なし）
//! - 待ちはすべて期限つき（REPAIR-5）: 送り手の全体 2 秒・ヘルパー側の 1 接続の読み取り 2 秒（絶対期限）・
//!   connect は非ブロッキング。接続は 1 つずつ直列に処理する
//! - エラー文言・stderr に pid・ネットワーク名・アドレス・コンテナ名を載せない
//!
//! # 未実装（REPAIR-3）
//! detach の後の `Reload` は送らない（古い名前は次の attach の `Reload` か 1→0 の停止で消える。残余は
//! `network::recorded` の doc を参照）。

use std::time::Duration;

use crate::error::{NetError, NetErrorCode};

pub mod frame;

#[cfg(target_os = "linux")]
mod os;
#[cfg(target_os = "linux")]
pub use os::{ControlStopRequest, reload_dns_helper};
#[cfg(target_os = "linux")]
pub(crate) use os::{HelperControl, prepare_helper_control};

/// 制御 UDS のファイル名（ネットワークのディレクトリ直下）。
pub const CONTROL_SOCKET_NAME: &str = "dns.ctl";
/// `Reload` を送ってから `Loaded` を受けるまでの全体の期限（D15）。超えたら attach を失敗にする。
pub const DNS_RELOAD_ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// ヘルパー側が 1 接続からフレームを読み切るまでの絶対期限（REPAIR-5）。
pub const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// `reload_dns_helper` の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReloadOutcome {
    /// ヘルパーが起動していない（`dns-helper` の記録が無い）。送るものがなく、失敗ではない。
    NotRunning,
    /// ヘルパーが `Loaded` を返した。
    Loaded,
}

/// 接続してきた相手の uid が期待する uid（ヘルパー自身の実効 uid）と一致するかを判定する（純関数。PLUG-12）。
///
/// 違えば `PermissionDenied`。呼び出し元（ヘルパー側のサーバー）は、違った接続からフレームを読まずに切断する。
/// root（uid 0）も例外にしない（ヘルパーと同じ uid の記録の読み手だけが名前を更新できる）。
pub fn authorize_peer(peer_uid: u32, expected_uid: u32) -> Result<(), NetError> {
    if peer_uid == expected_uid {
        Ok(())
    } else {
        Err(NetError::new(
            NetErrorCode::PermissionDenied,
            "dns control peer uid mismatch",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-12・NET-5・#3071: 同じ uid だけを通す（root も別 uid は拒否）。
    #[test]
    fn plug12_3071_authorize_peer_table() {
        assert!(authorize_peer(1000, 1000).is_ok());
        for peer in [0, 1001, 65534] {
            let e = authorize_peer(peer, 1000).expect_err("mismatch");
            assert_eq!(e.code(), NetErrorCode::PermissionDenied, "peer {peer}");
        }
        assert_eq!(
            authorize_peer(1000, 0)
                .expect_err("non-root peer to root")
                .code(),
            NetErrorCode::PermissionDenied
        );
    }

    /// D15・REPAIR-5・#3071: 期限は 2 秒の具体値。
    #[test]
    fn net5_3071_timeout_constants() {
        assert_eq!(DNS_RELOAD_ACK_TIMEOUT, Duration::from_secs(2));
        assert_eq!(CONTROL_READ_TIMEOUT, Duration::from_secs(2));
        assert_eq!(CONTROL_SOCKET_NAME, "dns.ctl");
    }
}
