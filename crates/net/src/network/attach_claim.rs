//! attach の巻き戻しで取り残した資源の回収用の請求書（NET-1・REPAIR-5・#2681）。
//!
//! `attach_container` が失敗して `ContainerAttachError::rollback` の `leftover` が残ったとき、その資源が
//! 「この接続が作ったもの」だと後から証明するための情報（ネットワーク名・bridge の所有トークン・endpoint）を
//! 固定テキストの記録へ符号化・復号する。作成失敗の請求書（`FailedCreateClaim`）と同じ厳密さで、
//! 呼び出し側 plugin-cri の `ReclaimStore` が `<状態ルート>/.cri/net/pending-reclaim/attach/` に永続化し、
//! 再起動後は `network::reclaim_failed_attach`（Linux のみ）が所有を確かめてから回収する。
//! 置き場所・排他は呼び出し側の責務（`docs/design/network-reclaim-persistence.md`）。
//!
//! # 記録の版（#3285）
//!
//! - v1: 資源のフラグ（veth・netns の pin・quarantine）だけ。DNAT ルールを持たない請求書は常に v1 で符号化し、
//!   保存済みの v1 を復号して再び符号化してもバイト単位で同じになる（内容照合の削除・比較交換を壊さない）。
//! - v2: v1 の 9 行に、`table-handle=`（DNAT ルールを投入した専用テーブルのハンドル）と `rule=`（公開 1 件の
//!   受け口と `prerouting`・`output` のルールハンドル。1〜`MAX_PORT_PUBLISHES` 行）を足す。`detach_container` の
//!   公開の個別解除が失敗して DNAT ルールが残りうるときだけ載り、再起動後も `reclaim_failed_attach` が
//!   テーブルの所有と実体の同一性を確かめてからハンドル指定で消す。旧バイナリは v2 を版の不一致として拒否する
//!   （fail-closed。v2 から v1 への引き戻しは非対応）。
//!
//! 記録は信頼しない入力として扱い、最終的な所有の判定はカーネル側の別名（`host_owner_token`）と
//! master の一致で行う。netns の pin の置き場は記録に載せず、呼び出し側の固定設定から受ける。

use crate::error::NetError;
use crate::network_store::member::{RecordedPublish, check_publishes};
use crate::nftables_batch::NftTableHandle;

use super::{
    AttachResource, CLAIM_RECORD_MAX_LEN, CLAIM_TOKEN_MAX_LEN, ContainerAttachError, EndpointId,
    MAX_PORT_PUBLISHES, NetworkName, invalid, is_valid_generation, parse_flag, token_names_network,
};

/// 記録の先頭行（版）。
const ATTACH_RECORD_VERSION_LINE: &str = "fandhe-net-attach-claim v1";
/// DNAT ルールのハンドルを持つ記録の先頭行（版。#3285）。
const ATTACH_RECORD_VERSION_LINE_V2: &str = "fandhe-net-attach-claim v2";

/// 請求書が指す、取り残した DNAT ルール（公開 1 件ごとの受け口とルールハンドル）と、それを投入した専用
/// テーブルのハンドル（NET-1・NET-3・#3285）。
///
/// 回収側（`reclaim_failed_attach`）は、テーブルの所有（`NFTA_TABLE_USERDATA` が請求書のトークンと一致）と
/// 実体の同一性（生きたテーブルのハンドルが `table` と一致）を確かめてから、`ports` のハンドルを DELRULE する。
/// `ports` は空にならず、受け口・ルールハンドルは重複しない（`new` が保つ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimedRules {
    pub(crate) table: NftTableHandle,
    pub(crate) ports: Vec<RecordedPublish>,
}

impl ClaimedRules {
    /// 組み立てる。空・上限超過・整合違反（受け口やハンドルの重複、解除の印つき）は `None`
    /// （呼び出し側は規則なしの請求書として扱い、quarantine と手動回収に委ねる）。
    pub(crate) fn new(table: NftTableHandle, ports: Vec<RecordedPublish>) -> Option<Self> {
        let sound = !ports.is_empty()
            && ports.len() <= MAX_PORT_PUBLISHES
            && !ports.iter().any(RecordedPublish::unpublishing)
            && check_publishes(&ports).is_ok();
        sound.then_some(Self { table, ports })
    }
}

/// `table-handle=` の値（先頭の 0 なしの非 0 の 10 進。1〜20 桁）。
fn decode_table_handle(v: &str) -> Result<NftTableHandle, NetError> {
    let bad = || invalid("attach claim record table handle invalid");
    if v.is_empty() || v.len() > 20 || v.starts_with('0') || !v.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    NftTableHandle::new(v.parse().map_err(|_| bad())?).map_err(|_| bad())
}

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
    /// 取り残した DNAT ルール（`detach_container` の公開の解除の失敗だけが載せる。あれば `quarantine` は真。#3285）。
    rules: Option<ClaimedRules>,
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
            rules: None,
        })
    }

    /// 単体の切り離し（`detach_container`）の取り残しから請求書を組む（NET-1・NET-3・#3062）。
    ///
    /// 世代は veth の所有トークン `host_token` の末尾 `/g/<世代>` から取る（入力検証で `host_token_is_for` を
    /// 通した値だけを渡す）。取れない・3 つのフラグがすべて偽なら `None`（`from_record` が資源なしの記録を
    /// 拒否する規則と揃える）。`pin` は `netns` のときだけ持つ。`rules` があれば DNAT ルールが残りうるので
    /// `quarantine` を真にする（#3285）。
    // 呼び出し元の `detach_container_with` は OS 非依存だが、実機の呼び出しは Linux 限定。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_detach(
        network: &NetworkName,
        token: &str,
        endpoint: &EndpointId,
        host_token: &str,
        pin: Option<PinIdentity>,
        veth: bool,
        netns: bool,
        quarantine: bool,
        rules: Option<ClaimedRules>,
    ) -> Option<Self> {
        let quarantine = quarantine || rules.is_some();
        if !(veth || netns || quarantine) {
            return None;
        }
        let generation = host_token
            .rfind("/g/")
            .map(|i| &host_token[i + 3..])
            .filter(|g| is_valid_generation(g))?;
        Some(Self {
            network: network.clone(),
            token: token.to_owned(),
            endpoint: endpoint.clone(),
            generation: generation.to_owned(),
            veth,
            netns,
            pin: if netns { pin } else { None },
            quarantine,
            rules,
        })
    }

    /// 永続化記録（固定のテキスト。LF・ASCII）へ符号化する。
    ///
    /// DNAT ルールを持たない請求書は v1、持つ請求書だけ v2（モジュール doc）。
    pub fn to_record(&self) -> String {
        let version = if self.rules.is_some() {
            ATTACH_RECORD_VERSION_LINE_V2
        } else {
            ATTACH_RECORD_VERSION_LINE
        };
        let mut out = format!(
            "{version}\nnetwork={}\nendpoint={}\ntoken={}\ngeneration={}\nveth={}\nnetns={}\npin={}\nquarantine={}\n",
            self.network.as_str(),
            self.endpoint.as_str(),
            self.token,
            self.generation,
            u8::from(self.veth),
            u8::from(self.netns),
            self.pin.map_or_else(|| "-".to_owned(), PinIdentity::encode),
            u8::from(self.quarantine),
        );
        if let Some(rules) = &self.rules {
            out.push_str(&format!("table-handle={}\n", rules.table.get()));
            for p in &rules.ports {
                out.push_str(&format!("rule={}\n", p.encode()));
            }
        }
        out
    }

    /// [`FailedAttachClaim::to_record`] の記録を復号する。版・キーの順序・名前・トークン形式・フラグを
    /// 厳密に検証し、違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn from_record(record: &str) -> Result<Self, NetError> {
        if record.len() > CLAIM_RECORD_MAX_LEN {
            return Err(invalid("attach claim record too long"));
        }
        let mut lines = record.strip_suffix('\n').unwrap_or("").split('\n');
        let v2 = match lines.next() {
            Some(ATTACH_RECORD_VERSION_LINE) if record.ends_with('\n') => false,
            Some(ATTACH_RECORD_VERSION_LINE_V2) if record.ends_with('\n') => true,
            _ => return Err(invalid("attach claim record version mismatch")),
        };
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
        let table_handle = if v2 {
            Some(decode_table_handle(field("table-handle")?)?)
        } else {
            None
        };
        let rules = match table_handle {
            None => {
                if lines.next().is_some() {
                    return Err(invalid("attach claim record malformed"));
                }
                None
            }
            Some(table) => {
                let mut ports = Vec::new();
                for line in lines {
                    let v = line
                        .strip_prefix("rule=")
                        .ok_or_else(|| invalid("attach claim record malformed"))?;
                    if ports.len() >= MAX_PORT_PUBLISHES {
                        return Err(invalid("attach claim record has too many rules"));
                    }
                    let p = RecordedPublish::decode(v)
                        .map_err(|_| invalid("attach claim record rule invalid"))?;
                    ports.push(p);
                }
                // 空・重複・解除の印つき・quarantine なしは拒否する（正準形を 1 つに保つ）。
                let rules = ClaimedRules::new(table, ports)
                    .ok_or_else(|| invalid("attach claim record rules invalid"))?;
                if !quarantine {
                    return Err(invalid("attach claim record rules without quarantine"));
                }
                Some(rules)
            }
        };
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
            rules,
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

    /// quarantine（アドレス・ポート予約と、ルールのハンドルを持てなかった DNAT ルール）を含むか。解放は
    /// `delete_network` が行う。ハンドルを請求書に載せた DNAT ルールは `reclaim_failed_attach` が消す（#3285）。
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
            rules: None,
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

    /// 回収側（`delete.rs`）が消す DNAT ルール（無ければ `None`。#3285）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn port_rules(&self) -> Option<&ClaimedRules> {
        self.rules.as_ref()
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
            rules: None,
        }
    }

    /// テスト用: DNAT ルールを持たせる（`quarantine` も真にする）。
    #[cfg(test)]
    pub(crate) fn with_rules_for_test(mut self, rules: ClaimedRules) -> Self {
        self.quarantine = true;
        self.rules = Some(rules);
        self
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

    fn rp(host_port: u16, pre: u64, out: u64) -> RecordedPublish {
        use crate::network::{PortProtocol, PortPublish};
        use crate::nftables_rules::NftRuleHandle;
        RecordedPublish::new(
            PortPublish::new(
                PortProtocol::Tcp,
                std::net::Ipv4Addr::new(192, 0, 2, 10),
                host_port,
                80,
            )
            .unwrap(),
            NftRuleHandle::new(pre).unwrap(),
            NftRuleHandle::new(out).unwrap(),
        )
    }

    fn th(h: u64) -> NftTableHandle {
        NftTableHandle::new(h).unwrap()
    }

    fn v2_claim() -> FailedAttachClaim {
        FailedAttachClaim::for_test(
            n("web"),
            e("c1"),
            "fandhe-net:web:1:2:3",
            GEN,
            false,
            false,
            true,
        )
        .with_rules_for_test(
            ClaimedRules::new(th(99), vec![rp(8080, 2, 3), rp(8081, 4, 5)]).unwrap(),
        )
    }

    const V2_REC: &str = "fandhe-net-attach-claim v2\nnetwork=web\nendpoint=c1\ntoken=fandhe-net:web:1:2:3\ngeneration=0123456789abcdef0123456789abcdef\nveth=0\nnetns=0\npin=-\nquarantine=1\ntable-handle=99\nrule=tcp 192.0.2.10:8080 80 2 3\nrule=tcp 192.0.2.10:8081 80 4 5\n";

    /// NET-1・#3285: DNAT ルールを持つ請求書は v2 で符号化され、完全一致し、往復で等しくなる。
    #[test]
    fn net1_3285_attach_claim_v2_record_roundtrip() {
        let c = v2_claim();
        let rec = c.to_record();
        assert_eq!(rec, V2_REC);
        let back = FailedAttachClaim::from_record(&rec).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.to_record(), rec);
        assert_eq!(back.port_rules().unwrap().table, th(99));
        assert_eq!(back.port_rules().unwrap().ports.len(), 2);
    }

    /// NET-1・#3285: 規則を持たない請求書は従来どおり v1 のままで、`quarantine_only` は規則を落として v1 を返す。
    #[test]
    fn net1_3285_attach_claim_v1_unchanged_and_quarantine_only_drops_rules() {
        let c = FailedAttachClaim::for_test(
            n("web"),
            e("c1"),
            "fandhe-net:web:1:2:3",
            GEN,
            false,
            false,
            true,
        );
        assert!(c.to_record().starts_with("fandhe-net-attach-claim v1\n"));
        let q = v2_claim().quarantine_only().unwrap();
        assert_eq!(q.port_rules(), None);
        assert_eq!(q.to_record(), c.to_record());
    }

    /// NET-1・SEC-1・#3285: 不正な v2 の記録は `InvalidArgument` で拒否する。
    #[test]
    fn net1_3285_attach_claim_v2_rejects_malformed() {
        let r1 = "rule=tcp 192.0.2.10:8080 80 2 3\n";
        let r2 = "rule=tcp 192.0.2.10:8081 80 4 5\n";
        let head = V2_REC.split("table-handle=").next().unwrap().to_owned();
        let many = |k: usize| {
            (0..k)
                .map(|i| {
                    format!(
                        "rule=tcp 192.0.2.10:{} 80 {} {}\n",
                        1000 + i,
                        10 + 2 * i,
                        11 + 2 * i
                    )
                })
                .collect::<String>()
        };
        let cases: Vec<String> = vec![
            // 規則が空。
            format!("{head}table-handle=99\n"),
            // quarantine=0。
            format!(
                "{}table-handle=99\n{r1}",
                head.replace("quarantine=1", "quarantine=0")
            ),
            // table-handle の欠落・0・先頭の 0・21 桁・非数字。
            format!("{head}{r1}"),
            format!("{head}table-handle=0\n{r1}"),
            format!("{head}table-handle=099\n{r1}"),
            format!("{head}table-handle=123456789012345678901\n{r1}"),
            format!("{head}table-handle=9x\n{r1}"),
            // 規則が非正準・解除の印・pre と out が同じ。
            format!("{head}table-handle=99\nrule=tcp 192.0.2.10:8080 80 02 3\n"),
            format!("{head}table-handle=99\nrule=tcp 192.0.2.10:8080 80 2 3 unpublishing\n"),
            format!("{head}table-handle=99\nrule=tcp 192.0.2.10:8080 80 2 2\n"),
            // 受け口の重複・ハンドルの重複。
            format!("{head}table-handle=99\n{r1}{r1}"),
            format!("{head}table-handle=99\n{r1}rule=tcp 192.0.2.10:8081 80 3 9\n"),
            // 65 件。
            format!("{head}table-handle=99\n{}", many(65)),
            // 余分な行・順序違い・CRLF。
            format!("{head}table-handle=99\n{r1}{r2}extra=1\n"),
            format!("{head}{r1}table-handle=99\n"),
            V2_REC.replace('\n', "\r\n"),
        ];
        for r in cases {
            let err = FailedAttachClaim::from_record(&r).unwrap_err();
            assert_eq!(err.code(), NetErrorCode::InvalidArgument, "{r:?}");
        }
        // 64 件は受理され、往復で一致する。
        let ok = format!("{head}table-handle=99\n{}", many(64));
        assert_eq!(FailedAttachClaim::from_record(&ok).unwrap().to_record(), ok);
    }

    /// NET-1・REPAIR-12・#3285: 最悪値の v2 の記録が `CLAIM_RECORD_MAX_LEN` に収まり、復号できる。
    #[test]
    fn net1_3285_attach_claim_worst_case_fits() {
        use crate::network::{CLAIM_RECORD_MAX_LEN, PortProtocol, PortPublish};
        let name = "a".repeat(64);
        let endpoint = "b".repeat(64);
        // トークンは `token_names_network` を満たす最長（256 バイト）。
        let prefix = format!("fandhe-net:{name}:");
        let token = format!("{prefix}{}", "1".repeat(256 - prefix.len()));
        assert_eq!(token.len(), 256);
        let max = u64::MAX;
        let ports: Vec<RecordedPublish> = (0..64u64)
            .map(|i| {
                RecordedPublish::new(
                    PortPublish::new(
                        PortProtocol::Udp,
                        std::net::Ipv4Addr::new(223, 255, 255, 255),
                        65000 + i as u16,
                        65535,
                    )
                    .unwrap(),
                    crate::nftables_rules::NftRuleHandle::new(max - 2 * i).unwrap(),
                    crate::nftables_rules::NftRuleHandle::new(max - 2 * i - 1).unwrap(),
                )
            })
            .collect();
        let mut c =
            FailedAttachClaim::for_test(n(&name), e(&endpoint), &token, GEN, true, true, true)
                .with_rules_for_test(ClaimedRules::new(th(max), ports).unwrap());
        c.pin = Some(PinIdentity {
            dev: max,
            ino: max,
            serial: max,
        });
        let rec = c.to_record();
        assert!(rec.len() <= CLAIM_RECORD_MAX_LEN, "{}", rec.len());
        assert_eq!(rec.len(), 5666, "最悪値の長さ（上限の根拠の確認）");
        assert_eq!(FailedAttachClaim::from_record(&rec), Ok(c));
    }
}
