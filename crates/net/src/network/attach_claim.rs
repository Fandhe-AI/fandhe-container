//! attach の巻き戻しで取り残した資源の回収用の請求書（NET-1・REPAIR-5・#2681）。
//!
//! `attach_container` が失敗して `ContainerAttachError::rollback` の `leftover` が残ったとき、その資源が
//! 「この接続が作ったもの」だと後から証明するための情報（ネットワーク名・bridge の所有トークン・endpoint）を
//! 固定テキストの記録へ符号化・復号する。作成失敗の請求書（`FailedCreateClaim`）と同じ厳密さで、
//! 呼び出し側 plugin-cri の `ReclaimStore` が `<状態ルート>/.cri/net/pending-reclaim/attach/` に永続化し、
//! 再起動後は `network::reclaim_failed_attach`（Linux のみ）が所有を確かめてから回収する。
//! 置き場所・排他は呼び出し側の責務（`docs/design/network-reclaim-persistence.md`）。
//!
//! 記録は信頼しない入力として扱い、最終的な所有の判定はカーネル側の別名（`host_owner_token`）と
//! master の一致で行う。netns の pin の置き場は記録に載せず、呼び出し側の固定設定から受ける。

use crate::error::NetError;

use super::{
    AttachResource, CLAIM_RECORD_MAX_LEN, CLAIM_TOKEN_MAX_LEN, ContainerAttachError, EndpointId,
    NetworkName, invalid, is_valid_generation, parse_flag, token_names_network,
};

/// 記録の先頭行（版）。
const ATTACH_RECORD_VERSION_LINE: &str = "fandhe-net-attach-claim v1";

/// attach の巻き戻しで取り残した資源の請求書。
///
/// フィールドは非公開で、構築口は `ContainerAttachError::reclaim_claim`・[`FailedAttachClaim::from_record`]
/// だけ。トークンを返す公開アクセサは置かない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FailedAttachClaim {
    network: NetworkName,
    token: String,
    endpoint: EndpointId,
    /// この接続の世代識別子。veth の所有トークンに含まれ、再接続した別の接続と区別する。
    generation: String,
    veth: bool,
    netns: bool,
    quarantine: bool,
}

impl FailedAttachClaim {
    /// 取り残しの請求書を組む（`ContainerAttachError::reclaim_claim` から）。取り残しが無ければ `None`。
    pub(super) fn from_error(
        network: &NetworkName,
        token: &str,
        endpoint: &EndpointId,
        generation: &str,
        err: &ContainerAttachError,
    ) -> Option<Self> {
        let has = |f: fn(&AttachResource) -> bool| err.rollback.leftover.iter().any(|(r, _)| f(r));
        let veth = has(|r| matches!(r, AttachResource::Veth(_)));
        let netns = has(|r| matches!(r, AttachResource::Netns(_)));
        let quarantine = has(|r| {
            matches!(
                r,
                AttachResource::Address(_)
                    | AttachResource::PortRules(_)
                    | AttachResource::PortReservation(..)
            )
        });
        (veth || netns || quarantine).then(|| Self {
            network: network.clone(),
            token: token.to_owned(),
            endpoint: endpoint.clone(),
            generation: generation.to_owned(),
            veth,
            netns,
            quarantine,
        })
    }

    /// 永続化記録（固定のテキスト。LF・ASCII）へ符号化する。
    pub fn to_record(&self) -> String {
        format!(
            "{ATTACH_RECORD_VERSION_LINE}\nnetwork={}\nendpoint={}\ntoken={}\ngeneration={}\nveth={}\nnetns={}\nquarantine={}\n",
            self.network.as_str(),
            self.endpoint.as_str(),
            self.token,
            self.generation,
            u8::from(self.veth),
            u8::from(self.netns),
            u8::from(self.quarantine),
        )
    }

    /// [`FailedAttachClaim::to_record`] の記録を復号する。版・キーの順序・名前・トークン形式・フラグを
    /// 厳密に検証し、違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn from_record(record: &str) -> Result<Self, NetError> {
        if record.len() > CLAIM_RECORD_MAX_LEN {
            return Err(invalid("attach claim record too long"));
        }
        let mut lines = record.strip_suffix('\n').unwrap_or("").split('\n');
        if !record.ends_with('\n') || lines.next() != Some(ATTACH_RECORD_VERSION_LINE) {
            return Err(invalid("attach claim record version mismatch"));
        }
        let mut field = |key: &str| -> Result<&str, NetError> {
            lines
                .next()
                .and_then(|l| l.strip_prefix(key))
                .and_then(|l| l.strip_prefix('='))
                .ok_or_else(|| invalid("attach claim record malformed"))
        };
        let network = NetworkName::new(field("network")?)?;
        let endpoint = EndpointId::new(field("endpoint")?)?;
        let token = field("token")?;
        let generation = field("generation")?;
        let veth = parse_flag(field("veth")?)?;
        let netns = parse_flag(field("netns")?)?;
        let quarantine = parse_flag(field("quarantine")?)?;
        if lines.next().is_some() {
            return Err(invalid("attach claim record malformed"));
        }
        if token.len() > CLAIM_TOKEN_MAX_LEN
            || !token.bytes().all(|b| b.is_ascii_graphic())
            || !token_names_network(token, &network)
        {
            return Err(invalid("attach claim record token invalid"));
        }
        if !is_valid_generation(generation) {
            return Err(invalid("attach claim record generation invalid"));
        }
        if !(veth || netns || quarantine) {
            return Err(invalid("attach claim record names no resource"));
        }
        Ok(Self {
            network,
            token: token.to_owned(),
            endpoint,
            generation: generation.to_owned(),
            veth,
            netns,
            quarantine,
        })
    }

    /// 対象のネットワーク名。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象の endpoint。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// host 側 veth を回収対象に含むか。
    pub fn includes_veth(&self) -> bool {
        self.veth
    }

    /// netns の pin を回収対象に含むか。
    pub fn includes_netns(&self) -> bool {
        self.netns
    }

    /// プロセス内にだけ残る quarantine（アドレス・DNAT ルール・ポート予約）を含むか。カーネル側で個別に
    /// 回収する対象は無く、解放は `delete_network` が行う。
    pub fn includes_quarantine(&self) -> bool {
        self.quarantine
    }

    /// カーネル側の資源（veth・netns の pin）を除いた、プロセス内の保持（quarantine）だけの請求書。
    /// veth・netns の回収を確認した後も quarantine が残る間の記録に使う（`delete_network` が解放する）。
    pub fn quarantine_only(&self) -> Option<Self> {
        self.quarantine.then(|| Self {
            veth: false,
            netns: false,
            ..self.clone()
        })
    }

    /// 回収側（`delete.rs`）が所有の証明に使う接続の世代識別子。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    /// 回収側（`delete.rs`）が所有の証明に使う bridge のトークン。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// テスト用の組み立て。
    #[cfg(test)]
    pub(crate) fn for_test(
        network: NetworkName,
        endpoint: EndpointId,
        token: &str,
        generation: &str,
        veth: bool,
        netns: bool,
        quarantine: bool,
    ) -> Self {
        Self {
            network,
            token: token.to_owned(),
            endpoint,
            generation: generation.to_owned(),
            veth,
            netns,
            quarantine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetErrorCode;

    const GEN: &str = "0123456789abcdef0123456789abcdef";

    fn n(s: &str) -> NetworkName {
        NetworkName::new(s).unwrap()
    }
    fn e(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    /// NET-1・#2681: 記録の文字列は固定で、往復で等しくなる。
    #[test]
    fn net1_attach_claim_record_roundtrip() {
        let c = FailedAttachClaim::for_test(
            n("web"),
            e("c1"),
            "fandhe-net:web:1:2:3",
            GEN,
            true,
            false,
            true,
        );
        let rec = c.to_record();
        assert_eq!(
            rec,
            "fandhe-net-attach-claim v1\nnetwork=web\nendpoint=c1\ntoken=fandhe-net:web:1:2:3\ngeneration=0123456789abcdef0123456789abcdef\nveth=1\nnetns=0\nquarantine=1\n"
        );
        assert_eq!(FailedAttachClaim::from_record(&rec), Ok(c));
    }

    /// NET-1・#2681: 不正な記録は `InvalidArgument` で拒否する。
    #[test]
    fn net1_attach_claim_record_rejects_malformed() {
        let ok = "fandhe-net-attach-claim v1\nnetwork=web\nendpoint=c1\ntoken=fandhe-net:web:1:2:3\ngeneration=0123456789abcdef0123456789abcdef\nveth=1\nnetns=0\nquarantine=0\n";
        assert!(FailedAttachClaim::from_record(ok).is_ok());
        let long_token = ok.replace(
            "token=fandhe-net:web:1:2:3",
            &format!("token=fandhe-net:web:{}", "a".repeat(250)),
        );
        let cases: Vec<String> = vec![
            ok.replace("v1", "v2"),
            ok.replace("network=web\nendpoint=c1", "endpoint=c1\nnetwork=web"),
            ok.replace('\n', "\r\n"),
            format!("{ok}extra=1\n"),
            ok.trim_end().to_owned(),
            ok.replace("token=fandhe-net:web:", "token=fandhe-net:other:"),
            ok.replace("token=fandhe-net:web:1:2:3", "token=fandhe-net:web:1 2"),
            ok.replace("veth=1", "veth=0"),
            ok.replace("veth=1", "veth=2"),
            ok.replace("endpoint=c1", "endpoint=../c1"),
            ok.replace("endpoint=c1", "endpoint=C1"),
            long_token,
            format!("{ok}{}", "x".repeat(1025)),
        ];
        for r in cases {
            let err = FailedAttachClaim::from_record(&r).unwrap_err();
            assert_eq!(err.code(), NetErrorCode::InvalidArgument, "{r:?}");
        }
    }
}
