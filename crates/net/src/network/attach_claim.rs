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

/// netns の pin の実体の識別子（作成時の `st_dev`・`st_ino` と、プロセス内で単調増加する作成の連番）。
///
/// 請求書がどの接続世代の pin を指すかを固定する。inode 番号は解除後に再利用されうるため、連番を併せて持ち、
/// 同じ endpoint・置き場に作り直された新しい pin を古い請求書で解除しないために使う（NET-1・#2681）。
/// 連番は現在時刻（ns）を下限に単調増加するため、再起動をまたいでも別世代と衝突しない。再起動後は、
/// 置き場の `.owned/<endpoint>` に永続化した所有記録（#2824）と照合し、一致して初めて解除される。
/// 所有記録の無い旧い請求書の pin は照合できず、解除自体が拒否される（手動回収）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) serial: u64,
}

impl PinIdentity {
    fn encode(self) -> String {
        format!("{}:{}:{}", self.dev, self.ino, self.serial)
    }

    fn decode(s: &str) -> Result<Self, NetError> {
        let bad = || invalid("attach claim record pin invalid");
        let mut it = s.split(':');
        let mut num = || -> Result<u64, NetError> {
            let t = it.next().ok_or_else(bad)?;
            if t.is_empty() || t.len() > 20 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            t.parse().map_err(|_| bad())
        };
        let id = Self {
            dev: num()?,
            ino: num()?,
            serial: num()?,
        };
        if it.next().is_some() {
            return Err(bad());
        }
        Ok(id)
    }
}

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
    /// netns の pin の実体の識別子。`netns` を含む請求書で、作成した pin を特定できたときだけ持つ。
    pin: Option<PinIdentity>,
    quarantine: bool,
}

impl FailedAttachClaim {
    /// 取り残しの請求書を組む（`ContainerAttachError::reclaim_claim` から）。取り残しが無ければ `None`。
    pub(super) fn from_error(
        network: &NetworkName,
        token: &str,
        endpoint: &EndpointId,
        generation: &str,
        pin: Option<PinIdentity>,
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
        // pin の識別子は失敗した接続の時点（`attach_container` の失敗構築時）で固定済みのものを使う。
        // 呼出時点のパスから採り直すと、再接続された別の pin を取り込んでしまう（世代保護。NET-1）。
        (veth || netns || quarantine).then(|| Self {
            network: network.clone(),
            token: token.to_owned(),
            endpoint: endpoint.clone(),
            generation: generation.to_owned(),
            veth,
            netns,
            pin,
            quarantine,
        })
    }

    /// 永続化記録（固定のテキスト。LF・ASCII）へ符号化する。
    pub fn to_record(&self) -> String {
        format!(
            "{ATTACH_RECORD_VERSION_LINE}\nnetwork={}\nendpoint={}\ntoken={}\ngeneration={}\nveth={}\nnetns={}\npin={}\nquarantine={}\n",
            self.network.as_str(),
            self.endpoint.as_str(),
            self.token,
            self.generation,
            u8::from(self.veth),
            u8::from(self.netns),
            self.pin.map_or_else(|| "-".to_owned(), PinIdentity::encode),
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
        let pin = match field("pin")? {
            "-" => None,
            v => Some(PinIdentity::decode(v)?),
        };
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
        if pin.is_some() && !netns {
            return Err(invalid("attach claim record pin without netns"));
        }
        Ok(Self {
            network,
            token: token.to_owned(),
            endpoint,
            generation: generation.to_owned(),
            veth,
            netns,
            pin,
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
            pin: None,
            ..self.clone()
        })
    }

    /// 回収側（`delete.rs`）が所有の証明に使う接続の世代識別子。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    /// 回収側（`delete.rs`）が接続世代の照合に使う netns の pin の識別子。控えられなかった請求書は `None`。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn pin(&self) -> Option<PinIdentity> {
        self.pin
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
            pin: netns.then_some(TEST_PIN),
            quarantine,
        }
    }

    /// テスト用: pin の識別子を差し替える。
    #[cfg(test)]
    pub(crate) fn with_pin_for_test(mut self, pin: Option<PinIdentity>) -> Self {
        self.pin = pin;
        self
    }
}

/// テストの請求書が持つ pin の識別子。
#[cfg(test)]
pub(crate) const TEST_PIN: PinIdentity = PinIdentity {
    dev: 1,
    ino: 2,
    serial: 3,
};

/// 請求書の記録の `pin=` 行の値（特定できなければ `-`）。
pub(super) fn pin_record_value(path: &std::path::Path) -> String {
    pin_identity_of(path).map_or_else(|| "-".to_owned(), PinIdentity::encode)
}

/// 取り残した pin のパスから、作成した pin の識別子を控える（Linux のみ。他 OS は常に `None`）。
#[cfg(target_os = "linux")]
pub(super) fn pin_identity_of(path: &std::path::Path) -> Option<PinIdentity> {
    crate::netns::pin_identity(path).ok().flatten()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn pin_identity_of(_path: &std::path::Path) -> Option<PinIdentity> {
    None
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
            "fandhe-net-attach-claim v1\nnetwork=web\nendpoint=c1\ntoken=fandhe-net:web:1:2:3\ngeneration=0123456789abcdef0123456789abcdef\nveth=1\nnetns=0\npin=-\nquarantine=1\n"
        );
        assert_eq!(FailedAttachClaim::from_record(&rec), Ok(c));
    }

    /// NET-1・#2681: pin の識別子は記録に載り、往復で等しくなる。
    #[test]
    fn net1_attach_claim_pin_identity_roundtrip() {
        let c = FailedAttachClaim::for_test(
            n("web"),
            e("c1"),
            "fandhe-net:web:1:2:3",
            GEN,
            false,
            true,
            false,
        );
        assert_eq!(c.pin(), Some(TEST_PIN));
        let rec = c.to_record();
        assert!(rec.contains("netns=1\npin=1:2:3\n"), "{rec}");
        assert_eq!(FailedAttachClaim::from_record(&rec), Ok(c.clone()));
        assert_eq!(c.quarantine_only(), None);
    }

    /// NET-1・#2681: 不正な記録は `InvalidArgument` で拒否する。
    #[test]
    fn net1_attach_claim_record_rejects_malformed() {
        let ok = "fandhe-net-attach-claim v1\nnetwork=web\nendpoint=c1\ntoken=fandhe-net:web:1:2:3\ngeneration=0123456789abcdef0123456789abcdef\nveth=1\nnetns=0\npin=-\nquarantine=0\n";
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
            ok.replace("pin=-", "pin=1:2"),
            ok.replace("pin=-", "pin=1:2:x"),
            ok.replace("pin=-", "pin=1:2:3:4"),
            ok.replace("pin=-", "pin=1:2:3"),
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
