//! 起動オプション文書(`FCOPT1`)の符号化と復号(SUP-12・CLI-1・SEC-1・REPAIR-2・#2713)。
//!
//! # 役割と呼び出し文脈
//!
//! CLI の `create` が検証した `--ulimit`・`--env`(`--env-file` の展開後)・`--ipc`・`--shm-size`・`--tmpfs`・`--cap-drop` を、
//! 状態ルート配下の 0600 のファイル([`store`](super::store))経由で supervisor の `start` へ渡すためのバイト列の形。
//! argv・環境変数・継承 fd は supervisor の起動契約([`crate::start_contract`])で使えず(入口と特権ランチャーが
//! fd 3 以降を閉じ、env を契約に含めない)、制御チャネルは launch の後に作られるため間に合わない。このため
//! ディスク上の私的な文書を `start_entry` の手順 2c が読み、[`ContainerOptionsDocument::to_container_options`] の
//! 結果を `ProductionStartDeps::with_container_options` へ渡す。label は文書に載せない(create 時に core の状態記録へ
//! 直接書く)。secrets / configs も載せない(ホストのパスを特権の supervisor が読むと confused deputy になるため、
//! 別の設計が要る。REPAIR-3)。
//!
//! # 形式
//!
//! ```text
//! FCOPT1\n
//! <kind> <len>\n<len バイトの UTF-8>\n     (繰り返し)
//! ```
//!
//! `kind` は閉じた語彙 `ulimit`・`env`・`ipc`・`shm-size`・`tmpfs`・`cap-drop`・`read-only`・`network`・`add-host`・`dns`・`pasta`・`publish`(+ 作成世代の `gen`)。`len` は 10 進(先頭 0 と `+` は不可)。
//! 中身は Docker 構文の生の文字列で、復号のたびに既存のパーサ([`Ulimit::parse`] 等)へ通し直す(未信頼の入力として
//! 検証する。値の改行を許すため、行区切りではなく長さ接頭辞にする)。符号化と復号を同じ型に置き、壊れた文書を
//! 作れないようにする(REPAIR-2)。
//!
//! `cap-drop` は #2775(CLI-1・SEC-1)で足した kind で、版(`FCOPT1`)は上げない。CLI と supervisor は同じディレクトリから
//! 配布され、未知の kind は旧 supervisor が拒否する(fail-closed)ため、版を上げる利点が無い。
//! `read-only` も #2828(CLI-1・SUP-12)で足した kind で、本体は固定値 `true` だけを受ける(`false` や空は拒否。
//! `--read-only` は狭める方向だけで、書き込み可能へ戻す表現を持たない)。重複は拒否する。版は同じ理由で上げない。
//!
//! `network`・`add-host`・`dns` は #3065(NET-6・NET-12・network-wiring.md D4)で足した kind で、版は上げない(同じ理由)。
//! `network` は 1 レコード(64 バイト以下)、`add-host` は 256 件以下(1 件 299 バイト以下)、`dns` は 32 件以下
//! (1 件 45 バイト以下)。復号のたびに net のパーサで再検証し([`NetworkOptions`])、`network` が無ければ
//! core の `LaunchNetworkMode::FromConfig`(従来の挙動)になる。CLI が書く処理と既定の `none` は #1873(PR #3322)で実装済み。
//!
//! `pasta` は #3199(NET-9・CLI-1・PLUG-11・SUP-12・rootless-network.md 12.4)で足した kind で、版は上げない(同じ理由)。
//! 作成時に検証した pasta の実体の記録(net の `PastaRecord` の本文。4096 バイト以下・重複は拒否)で、`network` が
//! ユーザー定義名のときだけ置ける(違えば `InvalidArgument`)。復号では本文の形だけを検証し(副作用なし)、バイナリの
//! 再検証は [`super::pasta::reverify_recorded_pasta`] が起動の直前に行う(start 経路への結線は #1940 で実装済み。監査の記録は start の入口が行う。#3330 で実装済み)。
//! CLI が書く処理は rootless のユーザー定義名の `--network` で有効(#3329)。rootful・非 Linux は作成前に `UNIMPLEMENTED` で書かれない。
//! `publish` は #3200(NET-9・NET-3)で足した kind で、版は上げない(同じ理由)。`-p` / `--publish` の生の文字列
//! (`[<ipv4>:]<host>:<container>[/tcp|udp]`)を 1 件 64 バイト以下・`MAX_PORT_PUBLISHES` 件以下で持ち、復号のたびに
//! net の `PastaPortForwards::parse_all` で検証し直す。ユーザー定義名の `network` と組でなければ拒否する
//! (rootless の pasta のみ。rootful は CLI が `UNIMPLEMENTED` にする。D13)。
//!
//! # 外部入力の扱い
//!
//! ファイル全体・レコード数・1 レコードの長さを、確保の前に上限と照合する。エラーは固定の英語文言で、値を含めない。
//! `Debug` は env の値を伏せる(秘密情報を含み得る)。

use fandhe_container_core::capabilities::{MAX_DROP_NAME_BYTES, MAX_DROP_NAMES, parse_drop_list};
use fandhe_container_core::tmpfs::TMPFS_MAX_MOUNTS;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::env::{ENV_MAX_ENTRIES, ENV_MAX_ENTRY_BYTES, ENV_MAX_TOTAL_BYTES, EnvSet, EnvVar};
use super::mounts::{MountOptions, ShmSize, TmpfsOption};
use super::network::{NetworkOptions, NetworkSelection};
use super::{ContainerOptions, IpcMode, Ulimit};
use fandhe_container_net::add_host_dns::resolv_conf::MAX_DNS_SERVERS;
use fandhe_container_net::add_host_dns::{MAX_ADD_HOST_ENTRIES, MAX_ADD_HOST_LEN, MAX_IP_TEXT_LEN};
use fandhe_container_net::network::{MAX_PORT_PUBLISHES, NAME_MAX_LEN};
use fandhe_container_net::pasta::MAX_PORT_FORWARD_SPEC_LEN;
use fandhe_container_net::pasta::record::{PASTA_RECORD_MAX_BYTES, PastaRecord};

/// 文書の先頭行(版つき。版が変わる形式変更ではこの値を上げる)。
pub const OPTIONS_DOC_MAGIC: &[u8] = b"FCOPT1\n";

/// 文書全体の最大バイト数(env の合計上限に、ulimit・tmpfs・見出し行の余裕を足した値)。
pub const OPTIONS_DOC_MAX_BYTES: usize = ENV_MAX_TOTAL_BYTES + 256 * 1024;

/// `--ulimit` の最大件数(rlimit の種別は 16 種で、重複は拒否される)。
pub const OPTIONS_MAX_ULIMITS: usize = 16;

const ULIMIT_RECORD_MAX: usize = 64;
const IPC_RECORD_MAX: usize = 32;
const SHM_RECORD_MAX: usize = 64;
const TMPFS_RECORD_MAX: usize = 4096;
const CAP_DROP_RECORD_MAX: usize = MAX_DROP_NAME_BYTES;
/// 作成世代の識別子の最大バイト数(#2713)。
pub const GENERATION_MAX: usize = 64;
/// 作成世代の記録(`gen <len>\n<値>\n`)の最大バイト数(後から足す分を、全体の上限の検査で確保する)。
const GENERATION_RECORD_RESERVE: usize = 4 + 1 + 2 + 1 + GENERATION_MAX + 1;
/// `read-only` の本文の最大バイト数(固定値 `true` の 4)。
const READ_ONLY_RECORD_MAX: usize = 4;
/// `network` の本文の最大バイト数(net のネットワーク名の上限。D4)。
const NETWORK_RECORD_MAX: usize = NAME_MAX_LEN;
/// `add-host` 1 件の最大バイト数(net の `MAX_ADD_HOST_LEN`。D4)。
const ADD_HOST_RECORD_MAX: usize = MAX_ADD_HOST_LEN;
/// `dns` 1 件の最大バイト数(IP 文字列の上限。D4)。
const DNS_RECORD_MAX: usize = MAX_IP_TEXT_LEN;
/// `pasta` の本文の最大バイト数(net の `PASTA_RECORD_MAX_BYTES`。4 KiB)。
const PASTA_RECORD_MAX: usize = PASTA_RECORD_MAX_BYTES;
/// `publish` 1 件の最大バイト数(net の `MAX_PORT_FORWARD_SPEC_LEN`。#3200)。
const PUBLISH_RECORD_MAX: usize = MAX_PORT_FORWARD_SPEC_LEN;
/// 見出し行(`<kind> <len>`)の最大バイト数(最長の kind `shm-size` と 10 進 7 桁に十分な余裕)。
const HEADER_LINE_MAX: usize = 24;
/// `len` の最大桁数(`OPTIONS_DOC_MAX_BYTES` は 7 桁に収まる)。
const LEN_DIGITS_MAX: usize = 7;

fn invalid(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

/// 検証済みの起動オプション文書(各フィールドは Docker 構文の生の文字列。構築時に既存のパーサで検証済み)。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ContainerOptionsDocument {
    ulimits: Vec<String>,
    env: Vec<String>,
    ipc: Option<String>,
    shm_size: Option<String>,
    tmpfs: Vec<String>,
    /// `--cap-drop` の生の名前(構築時に core の `parse_drop_list` で検証済み。#2775)。
    cap_drop: Vec<String>,
    /// `--read-only`(true のとき `root.readonly` を実効的に true にする。#2828)。
    read_only: bool,
    /// `--network` の生の文字列(構築時に net のパーサで検証済み。NET-6・#3065)。
    network: Option<String>,
    /// `--add-host` の生の文字列(`<host>:<ip>`。検証済み。NET-12・#3065)。
    add_hosts: Vec<String>,
    /// `--dns` の生の文字列(IP。検証済み。NET-12・#3065)。
    dns: Vec<String>,
    /// pasta の実体の記録の本文(net の `PastaRecord`。形は検証済み。`network` がユーザー定義名のときだけ。NET-9・#3199)。
    pasta: Option<String>,
    /// `--publish` の生の文字列(検証済み。NET-9・#3200)。
    publish: Vec<String>,
    /// 作成世代の識別子(状態記録の annotations と照合する。別の世代の残骸を適用しないため。#2713)。
    generation: Option<String>,
}

impl std::fmt::Debug for ContainerOptionsDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // env の値は秘密情報を含み得るため、キーだけを出す。
        let keys: Vec<&str> = self
            .env
            .iter()
            .map(|e| e.split_once('=').map_or("", |(k, _)| k))
            .collect();
        f.debug_struct("ContainerOptionsDocument")
            .field("ulimits", &self.ulimits)
            .field("env_keys", &keys)
            .field("ipc", &self.ipc)
            .field("shm_size", &self.shm_size)
            .field("tmpfs", &self.tmpfs)
            .field("cap_drop", &self.cap_drop)
            .field("read_only", &self.read_only)
            .field("network", &self.network)
            .field("add_hosts", &self.add_hosts)
            .field("dns", &self.dns)
            .field("pasta", &self.pasta)
            .field("publish", &self.publish)
            .field("generation", &self.generation)
            .finish()
    }
}

impl ContainerOptionsDocument {
    /// 生の指定から作る。件数・長さの上限、各パーサの検証、指定同士の矛盾(`--ipc=host` と `--shm-size` 等・
    /// ulimit の種別重複)を、ここで一度に検証する(CLI の create と supervisor の復号が同じ関門を通る)。
    pub fn new(
        ulimits: Vec<String>,
        env: Vec<String>,
        ipc: Option<String>,
        shm_size: Option<String>,
        tmpfs: Vec<String>,
    ) -> Result<Self, TraitError> {
        if ulimits.len() > OPTIONS_MAX_ULIMITS {
            return Err(invalid("too many ulimit records"));
        }
        if env.len() > ENV_MAX_ENTRIES {
            return Err(invalid("too many env records"));
        }
        if tmpfs.len() > TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs records"));
        }
        let doc = Self {
            ulimits,
            env,
            ipc,
            shm_size,
            tmpfs,
            cap_drop: Vec::new(),
            read_only: false,
            network: None,
            add_hosts: Vec::new(),
            dns: Vec::new(),
            pasta: None,
            publish: Vec::new(),
            generation: None,
        };
        doc.check_record_lengths()?;
        // 符号化後の文書全体(見出し・区切りを含む)が、supervisor の読み取りの上限に作成世代の記録の分を足しても
        // 収まることを確かめる。create が書けても start の読み取りが拒否する文書を作らない(REPAIR-2・#2713)。
        if doc.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        // 変換に通して検証する(変換結果は捨てる。保持するのは生の文字列)。
        doc.to_container_options()?;
        Ok(doc)
    }

    fn check_record_lengths(&self) -> Result<(), TraitError> {
        let too_long = || invalid("an options record is too long");
        if self.ulimits.iter().any(|s| s.len() > ULIMIT_RECORD_MAX)
            || self.env.iter().any(|s| s.len() > ENV_MAX_ENTRY_BYTES)
            || self.ipc.as_ref().is_some_and(|s| s.len() > IPC_RECORD_MAX)
            || self
                .shm_size
                .as_ref()
                .is_some_and(|s| s.len() > SHM_RECORD_MAX)
            || self.tmpfs.iter().any(|s| s.len() > TMPFS_RECORD_MAX)
        {
            return Err(too_long());
        }
        Ok(())
    }

    /// `--cap-drop` の名前を持たせる(CLI-1・SEC-1・#2775)。件数・1 件の長さの上限と名前の語彙を core の
    /// `parse_drop_list` で検証する(復号でも同じ関門を通る)。文書全体の上限も再検査する。
    pub fn with_cap_drop(mut self, cap_drop: Vec<String>) -> Result<Self, TraitError> {
        if cap_drop.len() > MAX_DROP_NAMES {
            return Err(invalid("too many cap-drop records"));
        }
        if cap_drop.iter().any(|s| s.len() > CAP_DROP_RECORD_MAX) {
            return Err(invalid("an options record is too long"));
        }
        parse_drop_list(&cap_drop).map_err(|_| invalid("a cap-drop record is invalid"))?;
        self.cap_drop = cap_drop;
        if self.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        Ok(self)
    }

    /// `--read-only` を持たせる(CLI-1・SUP-12・#2828)。false は「指定なし」で、config の値に従う。
    /// `read-only` の記録を足した後の文書全体の上限を、`new` / `with_cap_drop` と同じ基準(作成世代の記録の分を
    /// 含む)で再検査する。create が書けても start の読み取りが拒否する文書を作らない(REPAIR-2)。
    pub fn with_read_only(mut self, read_only: bool) -> Result<Self, TraitError> {
        self.read_only = read_only;
        if self.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        Ok(self)
    }

    /// `--network`・`--add-host`・`--dns` を持たせる(NET-6・NET-12・SUP-12・#3065)。
    ///
    /// 件数 → 1 件の長さ → net のパーサ(`NetworkOptions::parse`。復号でも同じ関門を通る)の順に検証し、
    /// 文書全体の上限を `with_cap_drop` と同じ基準で再検査する。
    pub fn with_network(
        mut self,
        network: Option<String>,
        add_hosts: Vec<String>,
        dns: Vec<String>,
    ) -> Result<Self, TraitError> {
        if add_hosts.len() > MAX_ADD_HOST_ENTRIES {
            return Err(invalid("too many add-host records"));
        }
        if dns.len() > MAX_DNS_SERVERS {
            return Err(invalid("too many dns records"));
        }
        if network
            .as_ref()
            .is_some_and(|s| s.len() > NETWORK_RECORD_MAX)
            || add_hosts.iter().any(|s| s.len() > ADD_HOST_RECORD_MAX)
            || dns.iter().any(|s| s.len() > DNS_RECORD_MAX)
        {
            return Err(invalid("an options record is too long"));
        }
        NetworkOptions::parse(network.as_deref(), &add_hosts, &dns, &self.publish)?;
        self.network = network;
        self.add_hosts = add_hosts;
        self.dns = dns;
        // pasta の記録があるのにユーザー定義名でなくなる変更は、encode できても decode で拒否されるため、ここで拒否する(REPAIR-2)。
        self.check_pasta_network()?;
        if self.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        Ok(self)
    }

    /// pasta の実体の記録の本文を持たせる(NET-9・SUP-12・#3199)。`with_network` の後に呼ぶ。
    ///
    /// 長さ → net の `PastaRecord::parse_body`(形のみ。副作用なし)→ `network` がユーザー定義名であることの順に
    /// 検証し、文書全体の上限を `with_cap_drop` と同じ基準で再検査する。
    pub fn with_pasta(mut self, pasta: Option<String>) -> Result<Self, TraitError> {
        if let Some(body) = &pasta {
            if body.len() > PASTA_RECORD_MAX {
                return Err(invalid("an options record is too long"));
            }
            PastaRecord::parse_body(body).map_err(|_| invalid("a pasta record is invalid"))?;
        }
        self.pasta = pasta;
        self.check_pasta_network()?;
        if self.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        Ok(self)
    }

    /// `-p` / `--publish` を持たせる(NET-9・NET-3・SUP-12・#3200)。
    ///
    /// `with_network` の後に呼ぶ(順序に依らず安全にするため、両方が保持済みの `network` と `publish` を
    /// `NetworkOptions::parse` で照合する)。件数 → 1 件の長さ → net のパーサの順に検証し、文書全体の上限を再検査する。
    pub fn with_publish(mut self, publish: Vec<String>) -> Result<Self, TraitError> {
        if publish.len() > MAX_PORT_PUBLISHES {
            return Err(invalid("too many publish records"));
        }
        if publish.iter().any(|s| s.len() > PUBLISH_RECORD_MAX) {
            return Err(invalid("an options record is too long"));
        }
        NetworkOptions::parse(
            self.network.as_deref(),
            &self.add_hosts,
            &self.dns,
            &publish,
        )?;
        self.publish = publish;
        if self.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        Ok(self)
    }

    /// `pasta` があるなら `network` はユーザー定義名でなければならない(それ以外では pasta を使わない)。
    fn check_pasta_network(&self) -> Result<(), TraitError> {
        if self.pasta.is_none() {
            return Ok(());
        }
        let named = NetworkOptions::parse(
            self.network.as_deref(),
            &self.add_hosts,
            &self.dns,
            &self.publish,
        )
        .is_ok_and(|n| matches!(n.selection(), Some(NetworkSelection::Named(_))));
        if named {
            Ok(())
        } else {
            Err(invalid("a pasta record requires a user-defined network"))
        }
    }

    /// pasta の実体の記録の本文(形は検証済み)。
    pub fn pasta(&self) -> Option<&str> {
        self.pasta.as_deref()
    }

    /// `-p` / `--publish` の生の指定。
    pub fn publish(&self) -> &[String] {
        &self.publish
    }

    /// `--network` の生の指定。
    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    /// `--add-host` の生の指定(`<host>:<ip>`)。
    pub fn add_hosts(&self) -> &[String] {
        &self.add_hosts
    }

    /// `--dns` の生の指定(IP)。
    pub fn dns(&self) -> &[String] {
        &self.dns
    }

    /// `--read-only` が指定されたか。
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// `--cap-drop` の生の名前。
    pub fn cap_drop(&self) -> &[String] {
        &self.cap_drop
    }

    /// 作成世代の識別子を持たせる(英数字・`-`・`_` のみ、1〜[`GENERATION_MAX`] バイト。#2713)。
    ///
    /// CLI の create が、同じ値を状態記録の annotations(`store::GENERATION_ANNOTATION`)にも書く。supervisor は両者が
    /// 一致する文書だけを適用する(同じ ID の前のコンテナの残骸を、次のコンテナに適用しない。fail-closed)。
    pub fn with_generation(mut self, generation: String) -> Result<Self, TraitError> {
        let ok = !generation.is_empty()
            && generation.len() <= GENERATION_MAX
            && generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(invalid("the options generation is invalid"));
        }
        self.generation = Some(generation);
        Ok(self)
    }

    /// 作成世代の識別子。
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    /// 何も指定していない文書か(空なら CLI は文書を書かない)。
    pub fn is_empty(&self) -> bool {
        self.ulimits.is_empty()
            && self.env.is_empty()
            && self.ipc.is_none()
            && self.shm_size.is_none()
            && self.tmpfs.is_empty()
            && self.cap_drop.is_empty()
            && !self.read_only
            && self.network.is_none()
            && self.add_hosts.is_empty()
            && self.dns.is_empty()
            && self.pasta.is_none()
            && self.publish.is_empty()
    }

    /// 検証済みの [`ContainerOptions`] へ変換する(label・secrets・configs は含まない)。
    ///
    /// env の件数・合計長は [`EnvSet::resolve`] が、`--ipc=host` と `/dev/shm` の矛盾は `tmpfs_set` が拒否する。
    pub fn to_container_options(&self) -> Result<ContainerOptions, TraitError> {
        let ulimits = self
            .ulimits
            .iter()
            .map(|s| Ulimit::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let vars = self
            .env
            .iter()
            .map(|s| EnvVar::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut mounts = MountOptions::default();
        if let Some(size) = &self.shm_size {
            mounts = mounts.with_shm_size(ShmSize::parse(size)?);
        }
        for t in &self.tmpfs {
            mounts = mounts.with_tmpfs(TmpfsOption::parse(t)?)?;
        }
        let mut options = ContainerOptions::new()
            .with_ulimits(ulimits)?
            .with_env(EnvSet::resolve(&[], &[], &vars)?)
            .with_mounts(mounts);
        if let Some(ipc) = &self.ipc {
            options = options.with_ipc_mode(IpcMode::parse(ipc)?);
        }
        let cap_drop =
            parse_drop_list(&self.cap_drop).map_err(|_| invalid("a cap-drop record is invalid"))?;
        // network 系は復号のたびに net のパーサで再検証する(未信頼の入力。NET-6・NET-12・#3065)。
        let network = NetworkOptions::parse(
            self.network.as_deref(),
            &self.add_hosts,
            &self.dns,
            &self.publish,
        )?;
        options = options
            .with_cap_drop(cap_drop)
            .with_read_only(self.read_only)
            .with_network(network);
        self.check_pasta_network()?;
        // 矛盾する指定(ファイルを読まない検査)をここで拒否する。
        options.tmpfs_set()?;
        Ok(options)
    }

    /// `--ulimit` の生の指定。
    pub fn ulimits(&self) -> &[String] {
        &self.ulimits
    }

    /// `--env` の生の指定(`KEY=VALUE`)。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// バイト列へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(OPTIONS_DOC_MAGIC);
        let mut put = |kind: &str, body: &str| {
            out.extend_from_slice(kind.as_bytes());
            out.push(b' ');
            out.extend_from_slice(body.len().to_string().as_bytes());
            out.push(b'\n');
            out.extend_from_slice(body.as_bytes());
            out.push(b'\n');
        };
        for s in &self.ulimits {
            put("ulimit", s);
        }
        for s in &self.env {
            put("env", s);
        }
        if let Some(s) = &self.ipc {
            put("ipc", s);
        }
        if let Some(s) = &self.shm_size {
            put("shm-size", s);
        }
        for s in &self.tmpfs {
            put("tmpfs", s);
        }
        for s in &self.cap_drop {
            put("cap-drop", s);
        }
        if self.read_only {
            put("read-only", "true");
        }
        if let Some(s) = &self.network {
            put("network", s);
        }
        for s in &self.add_hosts {
            put("add-host", s);
        }
        for s in &self.dns {
            put("dns", s);
        }
        if let Some(s) = &self.pasta {
            put("pasta", s);
        }
        for s in &self.publish {
            put("publish", s);
        }
        if let Some(s) = &self.generation {
            put("gen", s);
        }
        out
    }

    /// バイト列から復号する。マジック違い・桁あふれ・未知の kind・切れ・余剰・上限超過・非 UTF-8・
    /// `ipc` / `shm-size` の重複・各パーサの拒否は `InvalidArgument`(固定文言)。
    pub fn decode(bytes: &[u8]) -> Result<Self, TraitError> {
        if bytes.len() > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        let mut rest = bytes
            .strip_prefix(OPTIONS_DOC_MAGIC)
            .ok_or_else(|| invalid("options document has an unknown header"))?;
        let (mut ulimits, mut env, mut tmpfs) = (Vec::new(), Vec::new(), Vec::new());
        let mut cap_drop: Vec<String> = Vec::new();
        let mut read_only = false;
        let mut network: Option<String> = None;
        let (mut add_hosts, mut dns): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        let mut publish: Vec<String> = Vec::new();
        let (mut ipc, mut shm_size): (Option<String>, Option<String>) = (None, None);
        let mut pasta: Option<String> = None;
        let mut generation: Option<String> = None;
        // 全体の上限があるため、レコード数は `new` の件数検査と合わせて有限。
        while !rest.is_empty() {
            let line_end = rest
                .iter()
                .take(HEADER_LINE_MAX)
                .position(|b| *b == b'\n')
                .ok_or_else(|| invalid("options record header is malformed"))?;
            let line = rest
                .get(..line_end)
                .ok_or_else(|| invalid("options record header is malformed"))?;
            let (kind, len) = split_header(line)?;
            let body_start = line_end + 1;
            let body_end = body_start
                .checked_add(len)
                .ok_or_else(|| invalid("options record is truncated"))?;
            let body = rest
                .get(body_start..body_end)
                .ok_or_else(|| invalid("options record is truncated"))?;
            if rest.get(body_end) != Some(&b'\n') {
                return Err(invalid("options record is truncated"));
            }
            rest = rest
                .get(body_end + 1..)
                .ok_or_else(|| invalid("options record is truncated"))?;
            let max = match kind {
                "ulimit" => ULIMIT_RECORD_MAX,
                "env" => ENV_MAX_ENTRY_BYTES,
                "ipc" => IPC_RECORD_MAX,
                "shm-size" => SHM_RECORD_MAX,
                "tmpfs" => TMPFS_RECORD_MAX,
                "cap-drop" => CAP_DROP_RECORD_MAX,
                "read-only" => READ_ONLY_RECORD_MAX,
                "network" => NETWORK_RECORD_MAX,
                "add-host" => ADD_HOST_RECORD_MAX,
                "dns" => DNS_RECORD_MAX,
                "pasta" => PASTA_RECORD_MAX,
                "publish" => PUBLISH_RECORD_MAX,
                "gen" => GENERATION_MAX,
                _ => return Err(invalid("options record has an unknown kind")),
            };
            if len > max {
                return Err(invalid("an options record is too long"));
            }
            let text = std::str::from_utf8(body)
                .map_err(|_| invalid("an options record is not valid UTF-8"))?
                .to_owned();
            match kind {
                "ulimit" => ulimits.push(text),
                "env" => env.push(text),
                "tmpfs" => tmpfs.push(text),
                "cap-drop" => cap_drop.push(text),
                "read-only" => {
                    if text != "true" {
                        return Err(invalid("a read-only record is invalid"));
                    }
                    if std::mem::replace(&mut read_only, true) {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                "add-host" => add_hosts.push(text),
                "dns" => dns.push(text),
                "publish" => publish.push(text),
                "network" => {
                    if network.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                "pasta" => {
                    if pasta.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                "gen" => {
                    if generation.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                "ipc" | "shm-size" => {
                    let slot = if kind == "ipc" {
                        &mut ipc
                    } else {
                        &mut shm_size
                    };
                    if slot.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                _ => return Err(invalid("options record has an unknown kind")),
            }
            // 件数の暴走を確保の前に止める(`new` と同じ上限)。
            if ulimits.len() > OPTIONS_MAX_ULIMITS
                || env.len() > ENV_MAX_ENTRIES
                || tmpfs.len() > TMPFS_MAX_MOUNTS
                || cap_drop.len() > MAX_DROP_NAMES
                || add_hosts.len() > MAX_ADD_HOST_ENTRIES
                || dns.len() > MAX_DNS_SERVERS
                || publish.len() > MAX_PORT_PUBLISHES
            {
                return Err(invalid("too many options records"));
            }
        }
        // publish の規則(user-defined network が要る等)を `with_network` の Unimplemented より先に適用する
        // (`NetworkOptions::parse` と CLI 経路と同じ順序。NET-9・#3200)。
        NetworkOptions::parse(network.as_deref(), &add_hosts, &dns, &publish)?;
        let doc = Self::new(ulimits, env, ipc, shm_size, tmpfs)?
            .with_cap_drop(cap_drop)?
            .with_read_only(read_only)?
            .with_network(network, add_hosts, dns)?
            .with_pasta(pasta)?
            .with_publish(publish)?;
        match generation {
            Some(g) => doc.with_generation(g),
            None => Ok(doc),
        }
    }
}

/// `<kind> <len>` を分ける。`len` は数字だけ・先頭 0 不可(`0` 自体は可)・桁数上限つき。
fn split_header(line: &[u8]) -> Result<(&str, usize), TraitError> {
    let bad = || invalid("options record header is malformed");
    let text = std::str::from_utf8(line).map_err(|_| bad())?;
    let (kind, len) = text.split_once(' ').ok_or_else(bad)?;
    let canonical = !len.is_empty()
        && len.len() <= LEN_DIGITS_MAX
        && len.bytes().all(|b| b.is_ascii_digit())
        && (len == "0" || !len.starts_with('0'));
    if !canonical {
        return Err(bad());
    }
    Ok((kind, len.parse::<usize>().map_err(|_| bad())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> ContainerOptionsDocument {
        ContainerOptionsDocument::new(
            vec!["nofile=1024:2048".into()],
            vec!["A=1".into(), "MULTI=line1\nline2".into()],
            Some("private".into()),
            Some("128m".into()),
            vec!["/run:rw,noexec".into()],
        )
        .expect("document")
    }

    /// SUP-12・CLI-1: 符号化のバイト列が具体値で一致し、復号で元に戻る(値の改行も保つ)。
    #[test]
    fn sup12_options_document_encode_exact_and_round_trip() {
        let d = doc();
        let bytes = d.encode();
        let expected: &[u8] = b"FCOPT1\n\
ulimit 16\nnofile=1024:2048\n\
env 3\nA=1\n\
env 17\nMULTI=line1\nline2\n\
ipc 7\nprivate\n\
shm-size 4\n128m\n\
tmpfs 14\n/run:rw,noexec\n";
        assert_eq!(bytes, expected);
        assert_eq!(ContainerOptionsDocument::decode(&bytes).expect("decode"), d);
    }

    /// SUP-12: 空の文書は空の指定に戻り、`to_container_options` は既定と同じ。
    #[test]
    fn sup12_options_document_empty_round_trip() {
        let d = ContainerOptionsDocument::default();
        assert!(d.is_empty());
        assert_eq!(d.encode(), OPTIONS_DOC_MAGIC);
        let back = ContainerOptionsDocument::decode(OPTIONS_DOC_MAGIC).expect("decode");
        assert_eq!(
            back.to_container_options().expect("opts"),
            ContainerOptions::new()
        );
    }

    /// SUP-12・CLI-1: 変換後のオプションが指定値を具体値で持つ。
    #[test]
    fn sup12_options_document_converts_to_container_options() {
        let o = doc().to_container_options().expect("opts");
        let nofile: Vec<_> = o
            .rlimits()
            .iter()
            .map(|r| (r.kind().as_oci_name(), r.soft(), r.hard()))
            .collect();
        assert_eq!(nofile, vec![("RLIMIT_NOFILE", 1024, 2048)]);
        assert_eq!(o.env().to_env_strings(), vec!["A=1", "MULTI=line1\nline2"]);
        assert_eq!(o.mounts().shm_size().map(|s| s.bytes()), Some(128 << 20));
    }

    /// CLI-1・SEC-1(#2775): `cap-drop` は符号化の具体値・往復・変換後の集合が一致し、旧形式(kind なし)も読める。
    #[test]
    fn cli1_cap_drop_record_round_trips_and_converts() {
        use fandhe_container_core::capabilities::{Capability, CapabilitySet};
        let d = ContainerOptionsDocument::default()
            .with_cap_drop(vec!["chown".into(), "CAP_NET_RAW".into()])
            .expect("cap-drop");
        assert!(!d.is_empty());
        let bytes = d.encode();
        assert_eq!(
            bytes,
            b"FCOPT1\ncap-drop 5\nchown\ncap-drop 11\nCAP_NET_RAW\n".to_vec()
        );
        let back = ContainerOptionsDocument::decode(&bytes).expect("decode");
        assert_eq!(back, d);
        let want = CapabilitySet::empty()
            .with(Capability::Chown)
            .with(Capability::NetRaw);
        let opts = back.to_container_options().expect("opts");
        assert_eq!(opts.cap_drop(), want);
        assert_eq!(
            opts.launch_options().expect("launch").capability_drop(),
            want
        );
        // 旧形式(cap-drop なし)は従来どおり読め、集合は空。
        let old = ContainerOptionsDocument::decode(b"FCOPT1\nipc 7\nprivate\n").expect("old");
        assert!(old.cap_drop().is_empty());
        assert_eq!(
            old.to_container_options().expect("opts").cap_drop(),
            CapabilitySet::empty()
        );
    }

    /// CLI-1・SUP-12(#2828): `with_read_only(true)` は記録を足した後の文書が上限(作成世代の記録の分を含む)に
    /// ちょうど収まれば成功し、1 バイト超えれば固定文言で拒否する。
    #[test]
    fn sup12_options_document_read_only_checks_size_boundary() {
        let with_ipc = |n: usize| ContainerOptionsDocument {
            ipc: Some("x".repeat(n)),
            ..ContainerOptionsDocument::default()
        };
        let total = |n: usize| {
            let mut d = with_ipc(n);
            d.read_only = true;
            d.encode().len() + GENERATION_RECORD_RESERVE
        };
        let mut n = OPTIONS_DOC_MAX_BYTES - 1024;
        while total(n) < OPTIONS_DOC_MAX_BYTES {
            n += 1;
        }
        assert_eq!(total(n), OPTIONS_DOC_MAX_BYTES);
        assert!(with_ipc(n).with_read_only(true).is_ok());
        let err = with_ipc(n + 1)
            .with_read_only(true)
            .expect_err("over the limit");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "options document is too large");
    }

    /// CLI-1・SEC-1(#2775): 未知名・空・長すぎる名前・件数超過を含む文書は復号・構築とも固定文言で拒否する。
    #[test]
    fn cli1_cap_drop_record_rejects_invalid() {
        let bad = ContainerOptionsDocument::decode(b"FCOPT1\ncap-drop 9\nCAP_BOGUS\n")
            .expect_err("unknown name");
        assert_eq!(bad.code(), ErrorCode::InvalidArgument);
        assert_eq!(bad.message(), "a cap-drop record is invalid");
        assert!(ContainerOptionsDocument::decode(b"FCOPT1\ncap-drop 0\n\n").is_err());
        let long = "A".repeat(33);
        assert!(
            ContainerOptionsDocument::default()
                .with_cap_drop(vec![long])
                .is_err()
        );
        let many = vec!["chown".to_owned(); MAX_DROP_NAMES + 1];
        assert!(
            ContainerOptionsDocument::default()
                .with_cap_drop(many)
                .is_err()
        );
    }

    /// CLI-1・SUP-12(#2828): `read-only` は符号化の具体値・往復・変換後の `launch_options` が一致し、旧形式は false。
    /// 本体が `true` 以外・空・重複は固定文言で拒否する。
    #[test]
    fn sup12_options_document_read_only_round_trip() {
        let d = ContainerOptionsDocument::default()
            .with_read_only(true)
            .expect("read-only");
        assert!(!d.is_empty());
        let bytes = d.encode();
        assert_eq!(bytes, b"FCOPT1\nread-only 4\ntrue\n".to_vec());
        let back = ContainerOptionsDocument::decode(&bytes).expect("decode");
        assert_eq!(back, d);
        assert!(back.read_only());
        let opts = back.to_container_options().expect("opts");
        assert!(opts.read_only());
        assert!(opts.launch_options().expect("launch").root_readonly());
        let old = ContainerOptionsDocument::decode(b"FCOPT1\nipc 7\nprivate\n").expect("old");
        assert!(!old.read_only());
        assert!(
            !old.to_container_options()
                .expect("opts")
                .launch_options()
                .expect("launch")
                .root_readonly()
        );
        assert!(ContainerOptionsDocument::default().is_empty());
        for bad in [
            &b"FCOPT1\nread-only 5\nfalse\n"[..],
            b"FCOPT1\nread-only 0\n\n",
        ] {
            let e = ContainerOptionsDocument::decode(bad).expect_err("rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
        let dup =
            ContainerOptionsDocument::decode(b"FCOPT1\nread-only 4\ntrue\nread-only 4\ntrue\n")
                .expect_err("dup");
        assert_eq!(dup.message(), "an options record is duplicated");
    }

    fn decode_err(bytes: &[u8]) -> TraitError {
        ContainerOptionsDocument::decode(bytes).expect_err("must be rejected")
    }

    /// SUP-12・SEC-1: 壊れた文書は固定文言の `InvalidArgument` で拒否する(値を含めない)。
    #[test]
    fn sup12_options_document_rejections() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                b"FCOPT2\n".to_vec(),
                "options document has an unknown header",
            ),
            (b"".to_vec(), "options document has an unknown header"),
            (
                b"FCOPT1\nenv 99999999\nx".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv 03\nA=1\n".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv +3\nA=1\n".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nwat 3\nA=1\n".to_vec(),
                "options record has an unknown kind",
            ),
            (
                b"FCOPT1\nenv 3\nA=1".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 9\nA=1\n".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 3\nA=1X".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 3".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv 2\n\xff\xfe\n".to_vec(),
                "an options record is not valid UTF-8",
            ),
            (
                b"FCOPT1\nipc 4\nhost\nipc 7\nprivate\n".to_vec(),
                "an options record is duplicated",
            ),
            (
                b"FCOPT1\nipc 4\nhost\nshm-size 4\n128m\n".to_vec(),
                "--shm-size cannot be combined with --ipc=host",
            ),
            (
                b"FCOPT1\nulimit 9\nnofile=1\nulimit 9\nnofile=2\n".to_vec(),
                "duplicate rlimit kind",
            ),
        ];
        for (bytes, message) in cases {
            let e = decode_err(&bytes);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{message}");
            // 重複 ulimit の文言は core 側の固定文言なので、コードのみ確かめる。
            if message != "duplicate rlimit kind" {
                assert_eq!(e.message(), message);
            }
        }
    }

    /// SUP-12・SEC-1: 上限超過(全体・件数・1 レコード)は確保の前に拒否する。
    #[test]
    fn sup12_options_document_limits() {
        let huge = vec![b'x'; OPTIONS_DOC_MAX_BYTES + 1];
        assert_eq!(decode_err(&huge).message(), "options document is too large");
        let mut many = Vec::from(OPTIONS_DOC_MAGIC);
        for _ in 0..=OPTIONS_MAX_ULIMITS {
            many.extend_from_slice(b"ulimit 8\nnofile=1\n");
        }
        assert_eq!(decode_err(&many).message(), "too many options records");
        let mut long = Vec::from(OPTIONS_DOC_MAGIC);
        long.extend_from_slice(b"ulimit 65\n");
        long.extend_from_slice(&[b'a'; 65]);
        long.push(b'\n');
        assert_eq!(decode_err(&long).message(), "an options record is too long");
    }

    /// SEC-1: `Debug` は env の値を出さずキーだけを出す。
    #[test]
    fn sec1_options_document_debug_redacts_env_values() {
        let d = ContainerOptionsDocument::new(
            vec![],
            vec!["TOKEN=TOPSECRETVALUE".into()],
            None,
            None,
            vec![],
        )
        .expect("doc");
        let text = format!("{d:?}");
        assert!(!text.contains("TOPSECRETVALUE"), "{text}");
        assert!(text.contains("TOKEN"), "{text}");
    }

    /// SUP-12・SEC-1(#2713): 作成世代は符号化・復号で保たれ、不正な値と重複は拒否する。
    #[test]
    fn sup12_options_document_generation_round_trip_and_rejects() {
        let d = doc().with_generation("abc-123_X".into()).expect("gen");
        let back = ContainerOptionsDocument::decode(&d.encode()).expect("decode");
        assert_eq!(back.generation(), Some("abc-123_X"));
        assert_eq!(back, d);
        assert!(doc().with_generation(String::new()).is_err());
        assert!(doc().with_generation("a b".into()).is_err());
        assert!(
            doc()
                .with_generation("x".repeat(GENERATION_MAX + 1))
                .is_err()
        );
        let mut bytes = d.encode();
        bytes.extend_from_slice(b"gen 1\nz\n");
        assert!(ContainerOptionsDocument::decode(&bytes).is_err());
    }

    fn net_doc(
        network: Option<&str>,
        hosts: &[&str],
        dns: &[&str],
    ) -> Result<ContainerOptionsDocument, TraitError> {
        ContainerOptionsDocument::default().with_network(
            network.map(str::to_owned),
            hosts.iter().map(|s| (*s).to_owned()).collect(),
            dns.iter().map(|s| (*s).to_owned()).collect(),
        )
    }

    /// NET-6・NET-12(#3065): 符号化の具体値・往復。
    #[test]
    fn net6_options_document_network_records_encode_exact_and_round_trip() {
        let d = net_doc(Some("none"), &["web:192.0.2.1"], &["127.0.0.1"]).expect("doc");
        assert!(!d.is_empty());
        let bytes = d.encode();
        assert_eq!(
            bytes,
            b"FCOPT1\nnetwork 4\nnone\nadd-host 13\nweb:192.0.2.1\ndns 9\n127.0.0.1\n".to_vec()
        );
        assert_eq!(ContainerOptionsDocument::decode(&bytes).expect("decode"), d);
    }

    /// NET-6(#3065): `network` が無い文書(空・旧形式)は `FromConfig` になる。
    #[test]
    fn net6_options_document_without_network_is_from_config() {
        use fandhe_container_core::oci_runtime::LaunchNetworkMode;
        for bytes in [OPTIONS_DOC_MAGIC, b"FCOPT1\nipc 7\nprivate\n"] {
            let o = ContainerOptionsDocument::decode(bytes)
                .expect("decode")
                .to_container_options()
                .expect("opts")
                .launch_options()
                .expect("launch");
            assert_eq!(o.network(), LaunchNetworkMode::FromConfig);
        }
    }

    /// NET-6(#3065): `host` / `none` は LaunchOptions のモードに届く。
    #[test]
    fn net6_options_document_modes_reach_launch_options() {
        use fandhe_container_core::oci_runtime::LaunchNetworkMode;
        let mode = |b: &[u8]| {
            ContainerOptionsDocument::decode(b)
                .expect("decode")
                .to_container_options()
                .expect("opts")
                .launch_options()
                .expect("launch")
                .network()
        };
        assert_eq!(mode(b"FCOPT1\nnetwork 4\nhost\n"), LaunchNetworkMode::Host);
        assert_eq!(
            mode(b"FCOPT1\nnetwork 4\nnone\n"),
            LaunchNetworkMode::Loopback
        );
    }

    /// NET-12(#3065・A1): 件数と 1 レコードの長さの境界を具体値で照合する。
    #[test]
    fn net12_options_document_network_limits() {
        // add-host: 256 件は可、257 件は拒否(builder と復号)。
        let h: Vec<String> = vec!["web:192.0.2.1".to_owned(); 256];
        assert!(
            ContainerOptionsDocument::default()
                .with_network(Some("host".into()), h.clone(), vec![])
                .is_ok()
        );
        let mut h257 = h.clone();
        h257.push("web:192.0.2.1".into());
        assert_eq!(
            ContainerOptionsDocument::default()
                .with_network(Some("host".into()), h257, vec![])
                .expect_err("257")
                .message(),
            "too many add-host records"
        );
        let mut raw = Vec::from(&b"FCOPT1\nnetwork 4\nhost\n"[..]);
        for _ in 0..257 {
            raw.extend_from_slice(b"add-host 13\nweb:192.0.2.1\n");
        }
        assert_eq!(decode_err(&raw).message(), "too many options records");
        // dns: 32 件は可、33 件は拒否。
        let d32: Vec<String> = vec!["192.0.2.1".to_owned(); 32];
        assert!(
            ContainerOptionsDocument::default()
                .with_network(Some("host".into()), vec![], d32.clone())
                .is_ok()
        );
        let mut d33 = d32;
        d33.push("192.0.2.1".into());
        assert_eq!(
            ContainerOptionsDocument::default()
                .with_network(Some("host".into()), vec![], d33)
                .expect_err("33")
                .message(),
            "too many dns records"
        );
        let mut raw = Vec::from(&b"FCOPT1\nnetwork 4\nhost\n"[..]);
        for _ in 0..33 {
            raw.extend_from_slice(b"dns 9\n192.0.2.1\n");
        }
        assert_eq!(decode_err(&raw).message(), "too many options records");
        // add-host 299 バイト(253 + 1 + 45)は長さ検査を通り、300 バイトは拒否。
        let host253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61)
        );
        assert_eq!(host253.len(), 253);
        let ip45 = "0000:0000:0000:0000:0000:ffff:192.168.100.228";
        assert_eq!(ip45.len(), 45);
        let ok299 = format!("{host253}:{ip45}");
        assert_eq!(ok299.len(), 299);
        assert!(net_doc(Some("host"), &[&ok299], &[]).is_ok());
        let long300 = format!("{ok299}0");
        assert_eq!(
            net_doc(Some("host"), &[&long300], &[])
                .expect_err("300")
                .message(),
            "an options record is too long"
        );
        // dns 45 / 46 バイト。
        assert!(net_doc(Some("host"), &[], &[ip45]).is_ok());
        let ip46 = format!("{ip45}0");
        assert_eq!(
            net_doc(Some("host"), &[], &[&ip46])
                .expect_err("46")
                .message(),
            "an options record is too long"
        );
        // network 64 / 65 バイト。
        let n64 = "a".repeat(64);
        assert!(net_doc(Some(&n64), &[], &[]).is_ok());
        let n65 = "a".repeat(65);
        assert_eq!(
            net_doc(Some(&n65), &[], &[]).expect_err("65").message(),
            "an options record is too long"
        );
        // 復号側の 1 レコードの長さ検査。
        let mut raw = Vec::from(&b"FCOPT1\nnetwork 65\n"[..]);
        raw.extend_from_slice(n65.as_bytes());
        raw.push(b'\n');
        assert_eq!(decode_err(&raw).message(), "an options record is too long");
    }

    /// NET-6(#3065): `network` の重複は拒否する。
    #[test]
    fn net6_options_document_network_duplicate_rejected() {
        let e = decode_err(b"FCOPT1\nnetwork 4\nnone\nnetwork 4\nhost\n");
        assert_eq!(e.message(), "an options record is duplicated");
    }

    /// NET-12(#3065): 復号は net のパーサで再検証し、不正な値を拒否する。
    #[test]
    fn net12_options_document_network_invalid_rejected() {
        let cases: Vec<(&[u8], ErrorCode)> = vec![
            (b"FCOPT1\nnetwork 3\nWeb\n", ErrorCode::InvalidArgument),
            (b"FCOPT1\nnetwork 6\nbridge\n", ErrorCode::InvalidArgument),
            (
                b"FCOPT1\nnetwork 4\nnone\ndns 7\n8.8.8.8\n",
                ErrorCode::InvalidArgument,
            ),
            (
                b"FCOPT1\nnetwork 11\ncontainer:x\n",
                ErrorCode::Unimplemented,
            ),
            (
                b"FCOPT1\nadd-host 13\nweb:192.0.2.1\n",
                ErrorCode::InvalidArgument,
            ),
        ];
        for (bytes, code) in cases {
            assert_eq!(decode_err(bytes).code(), code, "{bytes:?}");
        }
    }

    const PASTA_BODY: &str =
        "20260120 2049 131074 1234567 1760000000 123456789 -5 0 0 755\n/usr/bin/pasta";

    fn pasta_doc(network: &str, body: &str) -> Result<ContainerOptionsDocument, TraitError> {
        net_doc(Some(network), &[], &[])
            .expect("net")
            .with_pasta(Some(body.to_owned()))
    }

    /// NET-9・SUP-12(#3199): `pasta` の符号化の具体値と往復。
    #[test]
    fn sup12_net9_pasta_record_encode_exact_and_round_trip() {
        let d = pasta_doc("web", PASTA_BODY).expect("doc");
        assert!(!d.is_empty());
        assert_eq!(d.pasta(), Some(PASTA_BODY));
        let bytes = d.encode();
        let expected = format!(
            "FCOPT1\nnetwork 3\nweb\npasta {}\n{PASTA_BODY}\n",
            PASTA_BODY.len()
        );
        assert_eq!(bytes, expected.into_bytes());
        assert_eq!(ContainerOptionsDocument::decode(&bytes).expect("decode"), d);
        assert!(ContainerOptionsDocument::default().pasta().is_none());
        assert!(
            !ContainerOptionsDocument::default()
                .with_network(Some("web".into()), vec![], vec![])
                .expect("net")
                .is_empty()
        );
    }

    /// NET-9・SUP-12(#3199): 上限・重複・形の不正は固定文言で拒否する。
    #[test]
    fn sup12_net9_pasta_record_limits() {
        let long_path = format!("/{}", "a".repeat(3071));
        let max_body = format!("20260120 2049 131074 1234567 1760000000 1 5 1 0 755\n{long_path}");
        assert!(max_body.len() <= 4096);
        pasta_doc("web", &max_body).expect("max body is accepted");
        let e = pasta_doc("web", &"a".repeat(4097)).expect_err("too long");
        assert_eq!(e.message(), "an options record is too long");
        let e = pasta_doc("web", "garbage").expect_err("malformed");
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::InvalidArgument, "a pasta record is invalid")
        );
        let mut raw = pasta_doc("web", PASTA_BODY).expect("doc").encode();
        let again = raw.clone();
        raw.extend_from_slice(&again[again.windows(5).position(|w| w == b"pasta").unwrap_or(0)..]);
        assert_eq!(
            decode_err(&raw).message(),
            "an options record is duplicated"
        );
        let over = format!("FCOPT1\nnetwork 3\nweb\npasta 4097\n{}\n", "a".repeat(4097));
        assert_eq!(
            decode_err(over.as_bytes()).message(),
            "an options record is too long"
        );
    }

    /// NET-9・REPAIR-2(#3199): `pasta` を持つ文書の `network` を後から非ユーザー定義名へ変える呼び出しは、その場で拒否する。
    /// 構築に成功した文書は必ず復号できる(往復)。
    #[test]
    fn sup12_net9_pasta_then_network_change_is_rejected_and_round_trips() {
        let msg = "a pasta record requires a user-defined network";
        for (net, hosts) in [
            (Some("none"), vec![]),
            (Some("host"), vec![]),
            (None, vec![]),
        ] {
            let e = pasta_doc("web", PASTA_BODY)
                .expect("doc")
                .with_network(net.map(str::to_owned), hosts, vec![])
                .expect_err("must reject");
            assert_eq!((e.code(), e.message()), (ErrorCode::InvalidArgument, msg));
        }
        // 別のユーザー定義名への変更は整合するので成功し、往復できる。
        let ok = pasta_doc("web", PASTA_BODY)
            .expect("doc")
            .with_network(Some("db".into()), vec![], vec![])
            .expect("named stays valid");
        assert_eq!(
            ContainerOptionsDocument::decode(&ok.encode()).expect("decode"),
            ok
        );
        // publish と組の network も同様(publish が要るユーザー定義名を外す変更は拒否される)。
        let with_pub = pasta_doc("web", PASTA_BODY)
            .expect("doc")
            .with_publish(vec!["8080:80".into()])
            .expect("publish");
        assert!(
            with_pub
                .clone()
                .with_network(Some("none".into()), vec![], vec![])
                .is_err()
        );
        assert_eq!(
            ContainerOptionsDocument::decode(&with_pub.encode()).expect("decode"),
            with_pub
        );
    }

    /// NET-9(#3199): `pasta` は `network` がユーザー定義名のときだけ置ける(復号でも同じ)。
    #[test]
    fn sup12_net9_pasta_requires_named_network() {
        for network in ["none", "host"] {
            let e = pasta_doc(network, PASTA_BODY).expect_err(network);
            assert_eq!(
                (e.code(), e.message()),
                (
                    ErrorCode::InvalidArgument,
                    "a pasta record requires a user-defined network"
                )
            );
        }
        let e = ContainerOptionsDocument::default()
            .with_pasta(Some(PASTA_BODY.to_owned()))
            .expect_err("no network");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        for head in ["", "network 4\nnone\n", "network 4\nhost\n"] {
            let raw = format!("FCOPT1\n{head}pasta {}\n{PASTA_BODY}\n", PASTA_BODY.len());
            assert_eq!(
                decode_err(raw.as_bytes()).code(),
                ErrorCode::InvalidArgument
            );
        }
    }

    fn pub_doc(publish: &[&str]) -> Result<ContainerOptionsDocument, TraitError> {
        net_doc(Some("web"), &[], &[])?
            .with_publish(publish.iter().map(|s| (*s).to_owned()).collect())
    }

    /// NET-9・NET-3(#3200): `publish` の符号化の具体値・往復・入力順の保持。
    #[test]
    fn net9_publish_round_trip() {
        let d = pub_doc(&["8080:80", "0.0.0.0:53:53/udp"]).expect("doc");
        assert!(!d.is_empty());
        let bytes = d.encode();
        assert_eq!(
            bytes,
            b"FCOPT1\nnetwork 3\nweb\npublish 7\n8080:80\npublish 17\n0.0.0.0:53:53/udp\n".to_vec()
        );
        let back = ContainerOptionsDocument::decode(&bytes).expect("decode");
        assert_eq!(back.publish(), ["8080:80", "0.0.0.0:53:53/udp"]);
        assert_eq!(back, d);
        let o = back.to_container_options().expect("options");
        assert_eq!(o.network().publish().len(), 2);
    }

    /// NET-9(#3200): 1 件 64 バイト以下・件数上限。
    #[test]
    fn net9_publish_limits() {
        // 64 バイトちょうどの正しい指定は作れないので、長さの検査だけを見る(65 は長さで先に拒否)。
        let long = "1".repeat(65);
        let e = pub_doc(&[long.as_str()]).expect_err("long");
        assert_eq!(e.message(), "an options record is too long");
        let mut raw = Vec::from(&b"FCOPT1\nnetwork 3\nweb\npublish 65\n"[..]);
        raw.extend_from_slice(long.as_bytes());
        raw.push(b'\n');
        assert_eq!(decode_err(&raw).message(), "an options record is too long");
        let over: Vec<String> = (0..=MAX_PORT_PUBLISHES)
            .map(|i| format!("{}:80", 1000 + i))
            .collect();
        let e = net_doc(Some("web"), &[], &[])
            .expect("doc")
            .with_publish(over.clone())
            .expect_err("count");
        assert_eq!(e.message(), "too many publish records");
        let mut raw = Vec::from(&b"FCOPT1\nnetwork 3\nweb\n"[..]);
        for s in &over {
            raw.extend_from_slice(format!("publish {}\n{s}\n", s.len()).as_bytes());
        }
        assert_eq!(decode_err(&raw).message(), "too many options records");
    }

    /// NET-9(#3200): ユーザー定義名の `network` が無い `publish` は、構築順に依らず拒否する。
    #[test]
    fn net9_publish_requires_named_network() {
        let msg = "publish records require a user-defined network";
        for n in [None, Some("none"), Some("host")] {
            let d = net_doc(n, &[], &[]).expect("doc");
            assert_eq!(
                d.with_publish(vec!["8080:80".into()])
                    .expect_err("p")
                    .message(),
                msg
            );
        }
        let e = ContainerOptionsDocument::default()
            .with_publish(vec!["8080:80".into()])
            .expect_err("no network");
        assert_eq!(e.message(), msg);
        assert_eq!(decode_err(b"FCOPT1\npublish 7\n8080:80\n").message(), msg);
        assert_eq!(
            decode_err(b"FCOPT1\nnetwork 4\nnone\npublish 7\n8080:80\n").message(),
            msg
        );
    }

    /// NET-9(#3200): 復号のたびに net のパーサで検証し直す(IPv6・ポート 0・重複・wildcard との重なり)。
    #[test]
    fn net9_publish_revalidated_on_decode() {
        let head = b"FCOPT1\nnetwork 3\nweb\n";
        let cases: [&[&str]; 4] = [
            &["[::1]:80:80"],
            &["0:80"],
            &["8080:80", "8080:81"],
            &["0.0.0.0:8080:80", "127.0.0.1:8080:81"],
        ];
        for specs in cases {
            let mut raw = Vec::from(&head[..]);
            for s in specs {
                raw.extend_from_slice(format!("publish {}\n{s}\n", s.len()).as_bytes());
            }
            let e = decode_err(&raw);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{specs:?}");
            assert!(!e.message().contains("8080"), "{}", e.message());
        }
    }

    /// NET-9(#3200): `container:` ネットワークと publish の組は、復号でも publish の規則(InvalidArgument)を先に返す。
    #[test]
    fn net9_decode_publish_rule_precedes_container_network() {
        let e = decode_err(b"FCOPT1\nnetwork 11\ncontainer:x\npublish 7\n8080:80\n");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "publish records require a user-defined network"
        );
    }
}
