//! DNS ヘルパーの記録（`dns-helper`: FCDNSH1）と起動窓の意図記録（`dns-helper.intent`: FCDNSI1）の符号化
//! （NET-5・NET-7・REPAIR-2・REPAIR-3・SEC-1・#3070。設計は `docs/design/network-wiring.md` の D11・D14）。
//!
//! # 役割と呼び出し文脈
//! `network_store` の `<state_root>/@networks/<name>/` に置く 2 種類の小さな文書の形式を、「壊れた値を表現できない」
//! 型（[`DnsHelperRecord`]・[`DnsHelperIntent`]・[`HelperNonce`]）と正準形だけを受ける復号で固定する。OS 非依存で
//! ファイルには触れない（置き場の検査・排他・fsync は `network_store` 側）。`dns_helper::detach` が書き、読む。
//!
//! # 形式
//! ```text
//! FCDNSH1\n                     FCDNSI1\n
//! pid <10 進>\n                 network <ネットワーク名>\n
//! start <10 進>\n               nonce <32 桁の小文字 16 進>\n
//! boot <36 文字の UUID>\n       listen <a.b.c.d:port>\n
//! nonce <32 桁の小文字 16 進>\n  [pid <10 進>\n start <10 進>\n boot <UUID>\n]
//! listen <a.b.c.d:port>\n
//! ```
//! 意図記録の末尾の `pid`・`start`・`boot` の 3 行は任意で、3 行そろうか、どれも無いかのどちらか
//! （識別行の照合後に追記する同一性。#3344）。magic は据え置く（FCDNSI1 は出荷前で、3 行なしの旧形式も読める）。
//! 並びは固定で、正準形だけを受ける。復号は値を読み取った後に符号化し直し、入力とバイト単位で一致しなければ
//! `DataLoss` にする（重複・未知の kind・順序違い・欠落・先頭 0・末尾のごみを一括で拒否）。文書全体は
//! [`RECORD_MAX_BYTES`] 以下で、解析の前にサイズで拒否する（無制限確保の防止）。
//!
//! # nonce について
//! nonce は起動のたびに作る 128 ビットの乱数で、ヘルパーの起動引数（`/proc/<pid>/cmdline`）に載る。秘密ではなく、
//! 意図記録と生存プロセスを結ぶ照合用の値である（起動窓の回収で、ネットワークの cgroup 内のプロセスのうち
//! この nonce を持つものだけを停止の対象にする）。
//!
//! # 意図記録の同一性（#3344）
//! 回収の前に段 2 が終了して subreaper の子のゾンビになると、`/proc/<pid>/cmdline` が空で nonce では帰属できず、
//! cgroup v2 ではゾンビが `cgroup.procs` にも現れない。そこで識別行の照合後、`dns-helper` を書く前に、意図記録へ
//! 同一性（pid・開始時刻・boot id）を原子的に追記する。回収はこの同一性で pidfd を取って照合する。

use std::fmt;
use std::net::SocketAddrV4;

use super::DnsListenAddr;
use super::identity::{BootId, ProcessIdentity};
use crate::error::{NetError, NetErrorCode};
use crate::network::NetworkName;

/// 記録 1 件の最大バイト数（解析の前にサイズで拒否する）。
pub const RECORD_MAX_BYTES: usize = 4096;

const HELPER_MAGIC: &str = "FCDNSH1\n";
const INTENT_MAGIC: &str = "FCDNSI1\n";
const NONCE_LEN: usize = 32;

fn data_loss(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// 起動のたびに作る照合用の nonce（32 桁の小文字 16 進）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperNonce(String);

impl HelperNonce {
    /// 検証して作る（長さ 32・小文字 16 進のみ）。
    pub fn new(s: &str) -> Result<Self, NetError> {
        let ok = s.len() == NONCE_LEN
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "nonce must be 32 lowercase hex digits",
            ))
        }
    }

    /// `/dev/urandom` から 16 バイトを読んで作る（Linux のみ。他 OS は `Unimplemented`）。
    pub fn generate() -> Result<Self, NetError> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read as _;
            let mut bytes = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut bytes))
                .map_err(|_| NetError::new(NetErrorCode::Internal, "cannot read random bytes"))?;
            let mut s = String::with_capacity(NONCE_LEN);
            for b in bytes {
                s.push_str(&format!("{b:02x}"));
            }
            Self::new(&s)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NetError::new(
                NetErrorCode::Unimplemented,
                "dns helper nonce is supported only on Linux",
            ))
        }
    }

    /// 文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HelperNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 起動済みヘルパーの記録（`dns-helper`。FCDNSH1）。停止時の同一性の照合に使う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHelperRecord {
    identity: ProcessIdentity,
    nonce: HelperNonce,
    listen: DnsListenAddr,
}

impl DnsHelperRecord {
    /// 作る。pid 0 は拒否する（`pidfd_open(0)` は呼び出し元自身を指さないが、記録としては無意味なため）。
    pub fn new(
        identity: ProcessIdentity,
        nonce: HelperNonce,
        listen: DnsListenAddr,
    ) -> Result<Self, NetError> {
        if identity.pid == 0 {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "pid must be positive",
            ));
        }
        Ok(Self {
            identity,
            nonce,
            listen,
        })
    }

    /// 同一性（pid・開始時刻・boot id）。
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// 起動時の nonce。
    pub fn nonce(&self) -> &HelperNonce {
        &self.nonce
    }

    /// 起動時に指定した待受アドレス（port 0 指定なら 0 のまま）。
    pub fn listen(&self) -> DnsListenAddr {
        self.listen
    }

    /// 正準形へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "{HELPER_MAGIC}pid {}\nstart {}\nboot {}\nnonce {}\nlisten {}\n",
            self.identity.pid,
            self.identity.start_time_ticks,
            self.identity.boot_id,
            self.nonce,
            self.listen
        )
        .into_bytes()
    }

    /// 正準形だけを受けて復号する（`DataLoss` で拒否）。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let text = checked_text(bytes)?;
        let mut lines = text
            .strip_prefix(HELPER_MAGIC)
            .ok_or_else(|| data_loss("bad dns helper record magic"))?
            .split('\n');
        let pid: u32 = field(&mut lines, "pid")?
            .parse()
            .map_err(|_| data_loss("bad pid"))?;
        let start: u64 = field(&mut lines, "start")?
            .parse()
            .map_err(|_| data_loss("bad start time"))?;
        let boot = BootId::new(field(&mut lines, "boot")?)?;
        let nonce =
            HelperNonce::new(field(&mut lines, "nonce")?).map_err(|_| data_loss("bad nonce"))?;
        let listen = parse_listen(field(&mut lines, "listen")?)?;
        let rec = Self::new(
            ProcessIdentity {
                pid,
                start_time_ticks: start,
                boot_id: boot,
            },
            nonce,
            listen,
        )
        .map_err(|_| data_loss("bad dns helper record"))?;
        if rec.encode() != bytes {
            return Err(data_loss("dns helper record is not canonical"));
        }
        Ok(rec)
    }
}

/// 起動窓の意図記録（`dns-helper.intent`。FCDNSI1）。起動の前に fsync して書き、記録の確定後に消す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHelperIntent {
    network: NetworkName,
    nonce: HelperNonce,
    listen: DnsListenAddr,
    /// 識別行の照合後に追記する同一性（無ければ起動窓のうち照合前）。
    identity: Option<ProcessIdentity>,
}

impl DnsHelperIntent {
    /// 作る。
    pub fn new(network: NetworkName, nonce: HelperNonce, listen: DnsListenAddr) -> Self {
        Self {
            network,
            nonce,
            listen,
            identity: None,
        }
    }

    /// 識別行の照合後の同一性を足す。pid 0 は拒否する。
    pub fn with_identity(mut self, identity: ProcessIdentity) -> Result<Self, NetError> {
        if identity.pid == 0 {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "pid must be positive",
            ));
        }
        self.identity = Some(identity);
        Ok(self)
    }

    /// 追記済みの同一性（照合前なら `None`）。
    pub fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// ネットワーク名。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 起動の nonce。
    pub fn nonce(&self) -> &HelperNonce {
        &self.nonce
    }

    /// 起動しようとした待受アドレス。
    pub fn listen(&self) -> DnsListenAddr {
        self.listen
    }

    /// 正準形へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!(
            "{INTENT_MAGIC}network {}\nnonce {}\nlisten {}\n",
            self.network.as_str(),
            self.nonce,
            self.listen
        );
        if let Some(id) = &self.identity {
            out.push_str(&format!(
                "pid {}\nstart {}\nboot {}\n",
                id.pid, id.start_time_ticks, id.boot_id
            ));
        }
        out.into_bytes()
    }

    /// 正準形だけを受けて復号する（`DataLoss` で拒否）。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let text = checked_text(bytes)?;
        let mut lines = text
            .strip_prefix(INTENT_MAGIC)
            .ok_or_else(|| data_loss("bad dns helper intent magic"))?
            .split('\n');
        let network = NetworkName::new(field(&mut lines, "network")?)
            .map_err(|_| data_loss("bad network name"))?;
        let nonce =
            HelperNonce::new(field(&mut lines, "nonce")?).map_err(|_| data_loss("bad nonce"))?;
        let listen = parse_listen(field(&mut lines, "listen")?)?;
        let mut rec = Self::new(network, nonce, listen);
        // 残りが空（"" 1 要素）でなければ、同一性の 3 行を順に読む（部分的な追記は正準形の照合で拒否）。
        if lines.clone().next().is_some_and(|l| !l.is_empty()) {
            let pid: u32 = field(&mut lines, "pid")?
                .parse()
                .map_err(|_| data_loss("bad pid"))?;
            let start: u64 = field(&mut lines, "start")?
                .parse()
                .map_err(|_| data_loss("bad start time"))?;
            let boot = BootId::new(field(&mut lines, "boot")?)?;
            rec = rec
                .with_identity(ProcessIdentity {
                    pid,
                    start_time_ticks: start,
                    boot_id: boot,
                })
                .map_err(|_| data_loss("bad dns helper intent"))?;
        }
        if rec.encode() != bytes {
            return Err(data_loss("dns helper intent is not canonical"));
        }
        Ok(rec)
    }
}

fn checked_text(bytes: &[u8]) -> Result<&str, NetError> {
    if bytes.len() > RECORD_MAX_BYTES {
        return Err(data_loss("record exceeds the size limit"));
    }
    std::str::from_utf8(bytes).map_err(|_| data_loss("record is not UTF-8"))
}

/// 次の行を `<key> <value>` として読む。key の不一致・値の欠落は `DataLoss`。
fn field<'a>(lines: &mut std::str::Split<'a, char>, key: &str) -> Result<&'a str, NetError> {
    let line = lines
        .next()
        .ok_or_else(|| data_loss("record is truncated"))?;
    let value = line
        .strip_prefix(key)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or_else(|| data_loss("unexpected record field"))?;
    if value.is_empty() {
        return Err(data_loss("empty record value"));
    }
    Ok(value)
}

fn parse_listen(s: &str) -> Result<DnsListenAddr, NetError> {
    let a: SocketAddrV4 = s.parse().map_err(|_| data_loss("bad listen address"))?;
    DnsListenAddr::new(*a.ip(), a.port()).map_err(|_| data_loss("bad listen address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const BOOT: &str = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn record() -> DnsHelperRecord {
        DnsHelperRecord::new(
            ProcessIdentity {
                pid: 4242,
                start_time_ticks: 987_654,
                boot_id: BootId::new(BOOT).expect("boot"),
            },
            HelperNonce::new(NONCE).expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::new(10, 89, 0, 1), 53).expect("listen"),
        )
        .expect("record")
    }

    fn intent() -> DnsHelperIntent {
        DnsHelperIntent::new(
            NetworkName::new("web").expect("name"),
            HelperNonce::new(NONCE).expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::new(10, 89, 0, 1), 53).expect("listen"),
        )
    }

    /// NET-7・REPAIR-2・#3070: 記録の符号化は固定の正準形で、往復で同じ値に戻る。
    #[test]
    fn net7_3070_record_roundtrip_exact_bytes() {
        let want = format!(
            "FCDNSH1\npid 4242\nstart 987654\nboot {BOOT}\nnonce {NONCE}\nlisten 10.89.0.1:53\n"
        );
        assert_eq!(record().encode(), want.as_bytes());
        assert_eq!(
            DnsHelperRecord::decode(want.as_bytes()).expect("decode"),
            record()
        );
    }

    /// NET-7・D14・#3070: 意図記録の符号化も固定の正準形で往復する。
    #[test]
    fn net7_3070_intent_roundtrip_exact_bytes() {
        let want = format!("FCDNSI1\nnetwork web\nnonce {NONCE}\nlisten 10.89.0.1:53\n");
        assert_eq!(intent().encode(), want.as_bytes());
        assert_eq!(
            DnsHelperIntent::decode(want.as_bytes()).expect("decode"),
            intent()
        );
    }

    /// REPAIR-2・SEC-1・#3070: 重複・順序違い・未知の kind・欠落・先頭 0・末尾のごみ・空値は `DataLoss`。
    #[test]
    fn net7_3070_record_rejects_noncanonical() {
        let good = String::from_utf8(record().encode()).expect("utf8");
        let cases = [
            good.replace("pid 4242", "pid 04242"),
            good.replace("pid 4242\n", "pid 4242\npid 4242\n"),
            good.replace("start 987654\nboot", "boot"),
            good.replace("pid", "uid"),
            format!("{good}extra\n"),
            good.trim_end_matches('\n').to_owned(),
            good.replace("pid 4242", "pid "),
            good.replace("pid 4242", "pid 0"),
            good.replace("FCDNSH1", "FCDNSH2"),
            good.replace("listen 10.89.0.1:53", "listen 0.0.0.0:53"),
            good.replace(NONCE, &NONCE.to_uppercase()),
        ];
        for c in cases {
            assert_eq!(
                DnsHelperRecord::decode(c.as_bytes()).expect_err(&c).code(),
                NetErrorCode::DataLoss,
                "{c:?}"
            );
        }
        let swapped = good.replace("pid 4242\nstart 987654\n", "start 987654\npid 4242\n");
        assert_eq!(
            DnsHelperRecord::decode(swapped.as_bytes())
                .expect_err("order")
                .code(),
            NetErrorCode::DataLoss
        );
    }

    /// REPAIR-2・SEC-1・#3070: 4096 バイトまでは解析し、4097 バイトは解析の前に拒否する。
    #[test]
    fn net7_3070_record_size_limit() {
        let e = DnsHelperRecord::decode(&vec![b'a'; RECORD_MAX_BYTES + 1]).expect_err("size");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.message(), "record exceeds the size limit");
        let e = DnsHelperIntent::decode(&vec![b'a'; RECORD_MAX_BYTES + 1]).expect_err("size");
        assert_eq!(e.message(), "record exceeds the size limit");
    }

    /// NET-7・#3070: 意図記録の不正（予約文字を含む名前・nonce 長違い）は拒否する。
    #[test]
    fn net7_3070_intent_rejects_bad_values() {
        let good = String::from_utf8(intent().encode()).expect("utf8");
        for c in [
            good.replace("network web", "network Web"),
            good.replace("network web", "network web/x"),
            good.replace(NONCE, "abc"),
            good.replace("FCDNSI1", "FCDNSH1"),
        ] {
            assert_eq!(
                DnsHelperIntent::decode(c.as_bytes()).expect_err(&c).code(),
                NetErrorCode::DataLoss,
                "{c:?}"
            );
        }
    }

    /// NET-7・#3070: nonce は 32 桁の小文字 16 進だけを受け、生成値もその形になる（Linux）。
    #[test]
    fn net7_3070_nonce_validation_and_generate() {
        assert!(HelperNonce::new(NONCE).is_ok());
        for bad in ["", "abc", &NONCE.to_uppercase(), &format!("{NONCE}0")] {
            assert_eq!(
                HelperNonce::new(bad).expect_err(bad).code(),
                NetErrorCode::InvalidArgument
            );
        }
        #[cfg(target_os = "linux")]
        {
            let a = HelperNonce::generate().expect("a");
            let b = HelperNonce::generate().expect("b");
            assert_eq!(a.as_str().len(), 32);
            assert_ne!(a, b);
        }
    }

    fn identity_of(pid: u32, start: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ticks: start,
            boot_id: BootId::new(BOOT).expect("boot"),
        }
    }

    /// NET-7・REPAIR-2・#3344: 同一性つきの意図記録は固定の正準形で往復し、旧形式（3 行なし）も読める。
    #[test]
    fn net7_3344_intent_identity_roundtrip() {
        let with = intent()
            .with_identity(identity_of(4242, 987_654))
            .expect("id");
        let want = format!(
            "FCDNSI1\nnetwork web\nnonce {NONCE}\nlisten 10.89.0.1:53\npid 4242\nstart 987654\nboot {BOOT}\n"
        );
        assert_eq!(with.encode(), want.as_bytes());
        let back = DnsHelperIntent::decode(want.as_bytes()).expect("decode");
        assert_eq!(back, with);
        assert_eq!(back.identity(), Some(&identity_of(4242, 987_654)));
        let old = format!("FCDNSI1\nnetwork web\nnonce {NONCE}\nlisten 10.89.0.1:53\n");
        assert_eq!(
            DnsHelperIntent::decode(old.as_bytes())
                .expect("old")
                .identity(),
            None
        );
    }

    /// REPAIR-2・SEC-1・#3344: 部分的な同一性・順序違い・pid 0・先頭 0・末尾のごみ・サイズ超過は `DataLoss`。
    #[test]
    fn net7_3344_intent_identity_rejects_noncanonical() {
        let head = format!("FCDNSI1\nnetwork web\nnonce {NONCE}\nlisten 10.89.0.1:53\n");
        let cases = [
            format!("{head}pid 4242\n"),
            format!("{head}pid 4242\nstart 987654\n"),
            format!("{head}start 987654\npid 4242\nboot {BOOT}\n"),
            format!("{head}pid 0\nstart 987654\nboot {BOOT}\n"),
            format!("{head}pid 4242\nstart 0987654\nboot {BOOT}\n"),
            format!("{head}pid 4242\nstart 987654\nboot {BOOT}\nextra\n"),
            format!("{head}\npid 4242\nstart 987654\nboot {BOOT}\n"),
        ];
        for c in cases {
            assert_eq!(
                DnsHelperIntent::decode(c.as_bytes()).expect_err(&c).code(),
                NetErrorCode::DataLoss,
                "{c:?}"
            );
        }
        assert_eq!(
            intent()
                .with_identity(identity_of(0, 1))
                .expect_err("pid0")
                .code(),
            NetErrorCode::InvalidArgument
        );
    }
}
