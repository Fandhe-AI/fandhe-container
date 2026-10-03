//! コンテナのネットワークモード選択（NET-6・TASK-143.1・#326・MS-8）。
//!
//! bridge（既定の隔離接続。`network` モジュール）・host（ホストの network namespace 共有。
//! `host` サブモジュール）・none（`lo` のみ。#327・TASK-143.2 で実装）を互いに排他な
//! [`NetworkMode`] として表す。runtime / CLI / stack（TASK-146・#347）が「どのセットアップ経路へ
//! 進むか」を判定する入口で、OS 非依存（3 OS でコンパイルされる）。host の検証本体は Linux のみ。
//!
//! 暗黙の既定値は置かない（host を既定にしない）。モード文字列は完全一致のホワイトリストで、
//! `container:<id>` 等の他コンテナ参照形式は受け付けない（fail-closed）。

use crate::error::{NetError, NetErrorCode};

#[cfg(target_os = "linux")]
pub mod host;

/// モード文字列の最大バイト長（外部入力の上限検証。coding-rust）。
const MODE_MAX_LEN: usize = 16;

/// ネットワークモード（NET-6）。互いに排他。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetworkMode {
    /// bridge + veth + netns の隔離接続（NET-1）。
    Bridge,
    /// ホストの network namespace をそのまま共有する（分離を意図的に緩める。NET-6）。
    Host,
    /// `lo` のみを持つ専用 netns。選択子だけを置き、セットアップ本体は #327（TASK-143.2）で実装する（未実装）。
    None,
}

/// モードが要求する netns の扱い（OCI `linux.namespaces` の network をどうするかの判定材料）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetnsPolicy {
    /// 新しい netns を作らず、ホスト netns を引き継ぐ。
    ShareHost,
    /// コンテナ専用の netns を作る。
    Isolated,
}

impl NetworkMode {
    /// `bridge` / `host` / `none` の完全一致だけを受け付ける。それ以外は `InvalidArgument`（ERR-1）。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        if s.len() > MODE_MAX_LEN {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "network mode string is too long",
            ));
        }
        match s {
            "bridge" => Ok(Self::Bridge),
            "host" => Ok(Self::Host),
            "none" => Ok(Self::None),
            _ => Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "unknown network mode (expected bridge, host or none)",
            )),
        }
    }

    /// `parse` と往復する正規の文字列を返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Host => "host",
            Self::None => "none",
        }
    }

    /// このモードが要求する netns の扱いを返す。
    ///
    /// host は `ShareHost`。bridge と none は専用 netns を作るため `Isolated`。
    pub fn netns_policy(&self) -> NetnsPolicy {
        match self {
            Self::Host => NetnsPolicy::ShareHost,
            Self::Bridge | Self::None => NetnsPolicy::Isolated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-6: 3 値の往復。
    #[test]
    fn net6_parse_roundtrip() {
        for (s, m) in [
            ("bridge", NetworkMode::Bridge),
            ("host", NetworkMode::Host),
            ("none", NetworkMode::None),
        ] {
            assert_eq!(NetworkMode::parse(s).unwrap(), m);
            assert_eq!(m.as_str(), s);
        }
    }

    /// NET-6: 完全一致以外は INVALID_ARGUMENT（他コンテナ参照形式・大文字・空白・制御文字を含む）。
    #[test]
    fn net6_parse_rejects_non_exact() {
        let long = "x".repeat(MODE_MAX_LEN + 1);
        for s in [
            "",
            "Host",
            "HOST",
            " host",
            "host ",
            "none\n",
            "container:abc",
            "service:db",
            "host\0",
            "bridge,host",
            long.as_str(),
        ] {
            let e = NetworkMode::parse(s).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "input {s:?}");
            assert_eq!(e.code().as_str(), "INVALID_ARGUMENT");
        }
    }

    /// NET-6: モードごとの netns 方針。
    #[test]
    fn net6_netns_policy() {
        assert_eq!(NetworkMode::Bridge.netns_policy(), NetnsPolicy::Isolated);
        assert_eq!(NetworkMode::Host.netns_policy(), NetnsPolicy::ShareHost);
        assert_eq!(NetworkMode::None.netns_policy(), NetnsPolicy::Isolated);
    }
}
