//! コンテナのネットワークモード選択（NET-6・TASK-143.1・#326・MS-8）。
//!
//! bridge（既定の隔離接続。`network` モジュール）・host（ホストの network namespace 共有。
//! `host` サブモジュール）・none（`lo` のみ。`none` サブモジュール。TASK-143.2・#327）を互いに排他な
//! [`NetworkMode`] として表す。runtime / CLI / stack（TASK-146・#347）が「どのセットアップ経路へ
//! 進むか」を判定する入口で、OS 非依存（3 OS でコンパイルされる）。host の検証本体は Linux のみ。
//!
//! 暗黙の既定値は置かない（host を既定にしない）。モード文字列は完全一致のホワイトリストで、
//! `container:<id>` 等の他コンテナ参照形式は受け付けない（fail-closed）。

use crate::error::{NetError, NetErrorCode};
use crate::network::NetworkName;
use crate::network_store::definition::is_reserved_network_name;

#[cfg(target_os = "linux")]
pub mod host;

pub mod none;

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
    /// `lo` のみを持つ専用 netns。セットアップ本体は `none` サブモジュール（TASK-143.2・#327）。
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

/// コンテナの `--network` の値の分類（NET-6・D1・REPAIR-1）。
///
/// CLI の create 検証（`create_network.rs`）と supervisor の `FCOPT1` 再検証（`container_options/network.rs`）が
/// 共有する**唯一の規則**。両者が別々に持つと片方だけ変わるずれが生じるため、ここに 1 か所だけ置く。
/// [`NetworkMode`]（セットアップ経路の選択）とは別の入口で、`container:` 始まりやユーザー定義名も分類する。
///
/// `#[non_exhaustive]` にしないのは、variant が増えたとき呼び出し側の `match` をコンパイルエラーにして
/// 更新を強いるため。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkChoice {
    /// `none`。
    None,
    /// `host`。
    Host,
    /// ユーザー定義名（検証済み）。
    Named(NetworkName),
    /// `container:` 始まり（参照先は未検証。受理の可否は呼び出し側が決める）。
    ContainerRef,
}

impl NetworkChoice {
    /// 判定順は `none` → `host` → 予約名（`InvalidArgument`）→ `container:` → `NetworkName::new`。
    /// エラー文言は固定の英語で、入力値を含めない。
    pub fn parse(value: &str) -> Result<Self, NetError> {
        match value {
            "none" => Ok(Self::None),
            "host" => Ok(Self::Host),
            n if is_reserved_network_name(n) => Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "reserved network name",
            )),
            n if n.starts_with("container:") => Ok(Self::ContainerRef),
            n => NetworkName::new(n).map(Self::Named),
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

    /// NET-6・D1: `--network` の分類の判定表。
    #[test]
    fn net6_network_choice_decision_table() {
        assert_eq!(NetworkChoice::parse("none").unwrap(), NetworkChoice::None);
        assert_eq!(NetworkChoice::parse("host").unwrap(), NetworkChoice::Host);
        for n in ["bridge", "default"] {
            let e = NetworkChoice::parse(n).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(e.message(), "reserved network name");
        }
        for n in ["container:x", "container:"] {
            assert_eq!(
                NetworkChoice::parse(n).unwrap(),
                NetworkChoice::ContainerRef
            );
        }
        match NetworkChoice::parse("web").unwrap() {
            NetworkChoice::Named(n) => assert_eq!(n.as_str(), "web"),
            other => panic!("unexpected {other:?}"),
        }
        let long = "a".repeat(64);
        assert!(matches!(
            NetworkChoice::parse(&long).unwrap(),
            NetworkChoice::Named(_)
        ));
        for bad in ["Web", ".x", "", &"a".repeat(65)] {
            let e = NetworkChoice::parse(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            if !bad.is_empty() {
                assert!(!e.message().contains(bad));
            }
        }
    }
}
