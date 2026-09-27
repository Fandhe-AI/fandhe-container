//! `NetworkPlugin` 拡張点トレイト（TASK-4.3・CRI-7・PLUG-1・MS-0）。
//!
//! ネットワーク設定の制御面（bridge・veth・netns・ポート公開・DNAT の作成/削除）を
//! 抽象化する拡張点。データパス（パケット転送そのもの）ではなく制御面の RPC なので、
//! plugin 境界を越えるコストは許容範囲になる（PoC-13）。トレイト定義は本 crate（core）に
//! 置くが、実装は本 crate には置かず、別プロセス plugin（`fandhe-container-plugin-net` 等。
//! TASK-114）が担う。core 側の proxy（G8・TASK-107/114）が UDS＋長さ接頭辞フレームの
//! RPC へ変換し、`Box<dyn NetworkPlugin>` として呼び出し側へ渡す（PLUG-1）。
//!
//! # netsetup（PoC-15）粒度との対応
//!
//! CRI-7 の 2026-09-23 追記により、メソッド分割は PoC-15 の `netsetup` の操作粒度
//! （`net-create`・`netns-create`・`veth-attach`・`publish-port`・`net-delete`）に
//! そのまま対応づけられることが実機で確認されている。
//!
//! | netsetup（PoC-15） | メソッド | 単位 | 主な責務 | CRI 対応 |
//! | ------------------ | -------- | ---- | -------- | -------- |
//! | `net-create` | [`NetworkPlugin::create_network`] | ネットワーク | bridge・専用 nft テーブル（masquerade）・DNS ヘルパー | `SetUpPod` 相当 |
//! | `netns-create` | [`NetworkPlugin::create_netns`] | コンテナ | 専用 netns の作成（lo の up を含む）。所属ネットワークを受け取り `net-delete` の追跡対象に加える | `SetUpPod` の一部 |
//! | `veth-attach` | [`NetworkPlugin::attach`] | コンテナ | veth ペアの作成、bridge / netns への接続、アドレス・default route の設定 | `SetUpPod` の一部 |
//! | `publish-port` | [`NetworkPlugin::publish_port`] | コンテナ | ポート公開（nft DNAT） | PortMapping |
//! | `net-delete` | [`NetworkPlugin::delete_network`] | ネットワーク | bridge・nft テーブル・関連 netns の一括削除 | `TearDownPod` 相当 |
//!
//! 分割の理由: ネットワーク単位とコンテナ単位のライフサイクルが異なるため、
//! 単一メソッドに畳み込まずライフサイクル単位ごとに分ける。PoC-15 の実機実証で、
//! この粒度でロールバックと冪等性の境界が引けることを確認している（CRI-7 追記）。
//! DNS ヘルパーの起動・終了と `/etc/resolv.conf` の設定は `create_network` /
//! `delete_network`（`SetUpPod` / `TearDownPod` 相当）に含まれ、DNS レジストリの更新は
//! コンテナのライフサイクルイベント（`ContainerRuntime` 側の create/delete）にフックする
//! 設計である。関連ビヘイビア: NET-1〜NET-5（bridge・veth・nft・DNS ヘルパー）。
//! NET-11（netlink / nftables の自前実装）は plugin 実装側の関心事であり、本トレイトは
//! 実装方式（netlink 直叩き・nft コマンド呼び出し等）に依存しない。
//!
//! # 未対応（スコープ外。#19・TASK-4.h1 と後続タスクへ引き継ぐ）
//!
//! - NET-6 の host / none モード（netsetup の操作を経由しない経路の扱いは #19 で確定する）
//! - コンテナ単位の detach・netns 単独の削除（コンテナ削除時の後始末）。将来は
//!   既定実装付きメソッドとして追加できる
//! - DNS ヘルパーのライフサイクルとレジストリ更新の詳細（NET-5・NET-7）、
//!   `--add-host` / `--dns`（NET-12）、rootless ネットワーク（NET-9・検討中）、
//!   ホスト側 bind IP の指定
//! - 実装（TASK-114・G7 の net crate）と proxy（G8・TASK-107/114）
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない（REPAIR-3）。

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

use super::types::{ContainerId, ErrorCode, TraitError};

/// ネットワーク設定の制御面（bridge・veth・netns・ポート公開）を抽象化する拡張点。
///
/// # 契約
/// 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）。
/// 2. 相手の応答を待つ処理（plugin RPC）は無期限に待たず、上限時間を超えたら
///    [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の決定は
///    proxy 実装（G8・TASK-107/114）の責務であり、本トレイトは契約のみを定める。
/// 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn NetworkPlugin>` として複数スレッド
///    から共有できることを前提にしてよい。
/// 4. 本 crate（core）にはこのトレイトの実装を置かない。実装は plugin 側にある
///    （PLUG-1・TASK-114）。「実装済みを装わない」という REPAIR-3 の方針に基づく。
/// 5. plugin の信頼境界（UDS の所有者・権限検証、別 UID からの接続切断等。
///    PLUG-11・PLUG-12）はこのトレイトの外側、境界機構（`fandhe-container-plugin`）の
///    責務であり、`NetworkPlugin` の呼び出し側はそれらが検証済みであることを
///    前提にしてよい。
/// 6. **部分失敗時のロールバック**: [`Self::create_network`]・[`Self::create_netns`]・
///    [`Self::attach`]・[`Self::publish_port`] が途中で失敗した場合、実装は作成済みの
///    リソース（bridge・veth・nft テーブル・netns・DNAT ルール）を逆順に削除してから
///    `Err` を返す（PoC-15 の 2026-09-24 修正に準拠）。[`Self::create_netns`] は netns
///    作成後に lo の up を行うため、lo 設定が失敗した場合は作成済みの netns 自体を
///    削除してから `Err` を返す。[`Self::publish_port`] は DNAT ルール追加後に失敗
///    した場合、追加済みのルールを撤回してから `Err` を返す。撤回にも失敗した場合は
///    [`ErrorCode::Internal`] を返し、`message` に残存資源を含める（fail-closed。
///    呼び出し側はポート公開が残っている可能性があるものとして扱う）。ロールバックせず
///    netns を残したまま `Err` を返すと、同じコンテナへの再試行が
///    [`ErrorCode::AlreadyExists`]（契約 7）により恒久的に失敗するため、ロールバックは
///    再試行可能性の前提でもある。
/// 7. **二重作成の拒否**: 同名のネットワークや同じコンテナの netns が既にあれば
///    [`ErrorCode::AlreadyExists`] を返す。前回の残骸を黙って再利用しない。
/// 8. **前提違反**: 存在しないネットワークへの [`Self::create_netns`] / [`Self::attach`] /
///    [`Self::publish_port`]、netns 未作成のコンテナへの [`Self::attach`]、
///    未 attach のコンテナへの [`Self::publish_port`] は [`ErrorCode::NotFound`] を返す。
///    加えて [`Self::attach`] は、対象コンテナの netns が [`Self::create_netns`] で
///    紐付けられたネットワーク（`CreateNetnsRequest::network`）と `req.network()` が
///    一致しない場合、[`ErrorCode::FailedPrecondition`] を返す（異なるネットワークへの
///    越境接続を拒否し、[`Self::delete_network`] の追跡対象と実際の接続先の食い違いを
///    防ぐ）。同様に [`Self::publish_port`] は、対象コンテナが [`Self::attach`] された
///    際のネットワーク（`AttachRequest::network`）と `req.network()` が一致しない場合、
///    [`ErrorCode::FailedPrecondition`] を返す（別ネットワークに属するコンテナ ID を
///    渡して越境 DNAT を設定させないため）。
/// 9. **削除はベストエフォートで続行**: [`Self::delete_network`] は個々の削除に失敗しても
///    残りの削除を続け、1 件でも失敗があれば `Err`（[`ErrorCode::Internal`]。`message`
///    に残存資源を含める。契約 6 の [`Self::publish_port`] と同じ fail-closed の表現）
///    を返す（PoC-15 の `net-delete` に準拠）。
///
/// メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。
/// dyn 互換（object safety）を保ち、async ランタイムへの依存を追加しない
/// （依存最小方針。dependency-policy.md）。
pub trait NetworkPlugin: Send + Sync {
    /// ネットワーク（bridge・専用 nft テーブル・DNS ヘルパー）を作成する。
    ///
    /// netsetup の `net-create` に対応し、CRI の `SetUpPod` 相当。前提: 同名の
    /// ネットワークが存在しないこと。存在する場合は [`ErrorCode::AlreadyExists`] を
    /// 返す（契約 7）。途中で失敗した場合は作成済みリソースを逆順に削除する（契約 6）。
    /// 対応: NET-1〜NET-3。
    fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError>;

    /// コンテナ専用の netns を作成する（lo の up を含む）。
    ///
    /// netsetup の `netns-create` に対応し、`SetUpPod` の一部。前提: `req.network()` が
    /// [`Self::create_network`] 済みであること（未作成なら [`ErrorCode::NotFound`]。
    /// 作成済みネットワークにのみ netns を紐付けることで、[`Self::delete_network`] が
    /// 存在しないネットワーク名を回収対象として追跡する事態や、孤立した netns が
    /// 残る事態を防ぐ）。加えて、同じコンテナの netns が既に存在しないこと。
    /// 存在する場合は [`ErrorCode::AlreadyExists`] を返す（契約 7）。`req.network()` が
    /// 指すネットワークに属するものとして実装側が追跡し、[`Self::delete_network`] の
    /// 削除対象に含める（`attach` 未実施でも回収できるようにするため）。lo の up に
    /// 失敗した場合は作成済みの netns を削除してから `Err` を返す（契約 6）。
    /// 対応: NET-1。
    fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError>;

    /// veth ペアを作成し、bridge / netns へ接続してアドレス・default route を設定する。
    ///
    /// netsetup の `veth-attach` に対応し、`SetUpPod` の一部。前提: `req.network()` が
    /// [`Self::create_network`] 済みであること（未作成なら [`ErrorCode::NotFound`]）、
    /// 対象コンテナの netns が [`Self::create_netns`] 済みであること（未作成なら、
    /// `create_network` 未作成時と同じ扱いとして [`ErrorCode::NotFound`]）。さらに、
    /// その netns が [`Self::create_netns`] 呼び出し時に紐付けられたネットワーク
    /// （`CreateNetnsRequest::network`）が `req.network()` と一致すること（不一致なら
    /// [`ErrorCode::FailedPrecondition`]）。異なるネットワークに属する netns への接続を
    /// 許すと、実際の接続先ネットワークと [`Self::delete_network`] が追跡する削除対象
    /// ネットワークが食い違い、分離・後始末の契約が崩れるため。途中で失敗した場合は
    /// 作成済みリソースを逆順に削除する（契約 6）。対応: NET-1・NET-2。
    fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError>;

    /// コンテナのポートをホスト側へ公開する（nft DNAT）。
    ///
    /// netsetup の `publish-port` に対応する。前提: `req.network()` が
    /// [`Self::create_network`] 済みで、対象コンテナが [`Self::attach`] 済みであること
    /// （いずれも未作成なら [`ErrorCode::NotFound`]）。加えて、対象コンテナが
    /// [`Self::attach`] された際のネットワーク（`AttachRequest::network`）が
    /// `req.network()` と一致すること（不一致なら [`ErrorCode::FailedPrecondition`]）。
    /// 一致を要求しないと、別ネットワークに属するコンテナ ID を渡されても実装が
    /// そのアドレスへ DNAT を設定でき、ネットワーク間の分離と [`Self::delete_network`]
    /// が追跡する削除対象の食い違いを招く（[`Self::attach`] の契約 8 と同じ理由）。
    /// 宛先は生の IP アドレスではなく [`ContainerId`] で指定し、実装（plugin 側）が
    /// attach 済みのアドレスへ解決する。これは PoC-15 との差分であり、ネットワーク外の
    /// 任意ホストへ DNAT させる経路をトレイト境界で作らないための設計である
    /// （#19 で確認する）。DNAT ルール追加後に失敗した場合は追加済みのルールを撤回して
    /// から `Err` を返し、撤回にも失敗すれば [`ErrorCode::Internal`] を返す（契約 6）。
    /// 対応: NET-4。
    fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError>;

    /// ネットワーク（bridge・nft テーブル・関連 netns）を一括削除する。
    ///
    /// netsetup の `net-delete` に対応し、CRI の `TearDownPod` 相当。削除対象の netns
    /// 一覧は呼び出し側から受け取らず、そのネットワークに [`Self::create_netns`]（`req.network()`
    /// で紐付け）・[`Self::attach`] のいずれかで関連付けたものを実装（plugin 側）が追跡して
    /// 決める（上限のない `Vec` を境界へ持ち込まないため）。`attach` 前に失敗した netns も
    /// `create_netns` の時点で追跡対象に入っているため回収できる。個々の削除に失敗しても
    /// 残りの削除を続け、1 件でも失敗があれば `Err` を返す（契約 9）。対応: NET-3・NET-5。
    fn delete_network(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError>;
}

/// ネットワーク名・netns 名の許容文字数の上限（暫定値）。
///
/// plugin はインターフェース名の制約（`IFNAMSIZ` 由来。PoC-17 で bridge の接頭辞込みで
/// 8 文字が `ERANGE` になった事例）により、さらに厳しい上限を [`ErrorCode::InvalidArgument`]
/// で課してよい。この値の確定は人間のアーキテクチャレビュー（#19・TASK-4.h1）で行う。
const IDENTIFIER_MAX_LEN: usize = 64;

/// [`NetworkName`]・[`NetnsName`] に共通する検証本体。
///
/// bridge・nft テーブル・netns の名前として実装側が使うため、パス区切り文字・NUL・
/// 非 ASCII・制御文字・空白を型のレベルで排除する（PoC-15 で名前が nft スクリプトや
/// インターフェース名へ埋め込まれていたため、境界の型の時点で制限する。security.md）。
/// `kind` はエラーメッセージに出す名詞（"network name" / "netns name"）。
///
/// 拒否条件（いずれかに該当すると [`ErrorCode::InvalidArgument`]）:
/// - 空文字列
/// - 長さが `IDENTIFIER_MAX_LEN`（64 バイト）を超える
/// - 先頭が ASCII 英数字でない
/// - 2 文字目以降に `[A-Za-z0-9-]` 以外の文字を含む
fn validate_identifier(value: &str, kind: &str) -> Result<(), TraitError> {
    if value.is_empty() {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must not be empty"),
        ));
    }
    if value.len() > IDENTIFIER_MAX_LEN {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must be at most {IDENTIFIER_MAX_LEN} bytes"),
        ));
    }
    let mut bytes = value.bytes();
    // `is_empty()` チェック済みのため `next()` は必ず `Some` を返す。
    let first = bytes.next().unwrap_or(b'\0');
    if !first.is_ascii_alphanumeric() {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must start with an ASCII alphanumeric character"),
        ));
    }
    if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must match [A-Za-z0-9][A-Za-z0-9-]*"),
        ));
    }
    Ok(())
}

/// 検証済みのネットワーク名。
///
/// 生成は [`NetworkName::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// 入力文字列を検証してネットワーク名を作る（検証条件は [`validate_identifier`]）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        validate_identifier(&value, "network name")?;
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for NetworkName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for NetworkName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// 検証済みの netns 識別子。
///
/// netns の実体（パス・fd）は本トレイトの型に含めない（下記 [`NetnsStatus`] の doc）。
/// この型は plugin が [`ContainerId`] から導出し応答する netns の「名前」のみを表し、
/// [`NetworkName`] と同じ文字集合・長さ制約を [`validate_identifier`] で共有する。
/// 生成は [`NetnsName::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetnsName(String);

impl NetnsName {
    /// 入力文字列を検証して netns 名を作る（検証条件は [`validate_identifier`]）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        validate_identifier(&value, "netns name")?;
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for NetnsName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for NetnsName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// IPv4 / IPv6 アドレスと prefix 長の組（CIDR 表記）。
///
/// prefix 長はアドレスファミリごとの上限（IPv4: 32・IPv6: 128）を超えられない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// アドレスと prefix 長から CIDR を作る。
    ///
    /// `prefix_len` がアドレスファミリの上限（IPv4: 32・IPv6: 128）を超える場合は
    /// [`ErrorCode::InvalidArgument`] を返す。
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, TraitError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("prefix length must be at most {max} for this address family"),
            ));
        }
        Ok(Self { addr, prefix_len })
    }

    /// アドレスを返す。
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// prefix 長を返す。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// ポート公開のトランスポートプロトコル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
    /// TCP。
    Tcp,
    /// UDP。
    Udp,
}

impl Protocol {
    /// プロトコル名を小文字文字列で返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// [`NetworkPlugin::create_network`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CreateNetworkRequest {
    name: NetworkName,
    subnet: IpCidr,
}

impl CreateNetworkRequest {
    /// ネットワーク名と bridge 側のアドレス・prefix（サブネット）から要求を作る。
    pub fn new(name: NetworkName, subnet: IpCidr) -> Self {
        Self { name, subnet }
    }

    /// ネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// bridge 側のサブネット（アドレス・prefix）を返す。
    pub fn subnet(&self) -> IpCidr {
        self.subnet
    }
}

/// [`NetworkPlugin::create_network`] の応答。
///
/// 将来の拡張（DNS ヘルパーのアドレス等）に備えて構造体にする（coding-rust.md）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetworkStatus {
    name: NetworkName,
    subnet: IpCidr,
}

impl NetworkStatus {
    /// ネットワーク名とサブネットから状態を作る。
    pub fn new(name: NetworkName, subnet: IpCidr) -> Self {
        Self { name, subnet }
    }

    /// ネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// bridge 側のサブネット（アドレス・prefix）を返す。
    pub fn subnet(&self) -> IpCidr {
        self.subnet
    }
}

/// [`NetworkPlugin::create_netns`] の要求。
///
/// `network` は、この netns がどのネットワークに属するかを実装（plugin 側）へ伝える。
/// [`Self::network`] 経由の `attach` 前に本呼び出しが失敗しても、実装はこの時点で
/// 受け取ったネットワーク名に紐付けて netns を追跡でき、その後の
/// [`NetworkPlugin::delete_network`] が `attach` 未実施の netns も含めて回収できる
/// （残存孤児 netns の防止）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CreateNetnsRequest {
    network: NetworkName,
    container: ContainerId,
}

impl CreateNetnsRequest {
    /// 所属先ネットワーク名と対象コンテナの ID から要求を作る。netns の名前は検証済みの
    /// [`ContainerId`] から実装側が導出する（パストラバーサル対策。security.md）。
    pub fn new(network: NetworkName, container: ContainerId) -> Self {
        Self { network, container }
    }

    /// 所属先ネットワーク名を返す。実装（plugin 側）はこれを使って
    /// [`NetworkPlugin::delete_network`] の追跡対象にこの netns を含める。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }
}

/// [`NetworkPlugin::create_netns`] の応答。
///
/// 保持するのは対象コンテナの ID と、実装（plugin 側）が [`ContainerId`] から
/// 導出して報告する検証済みの netns 名（[`NetnsName`]）のみである。netns の実体
/// （パス・fd）の解決と、それに対する配下性・種別・TOCTOU の検証は本トレイトの型に
/// 含めない。それらは untrusted な plugin 応答を受け取る境界機構
/// （`fandhe-container-plugin`。PLUG-11・PLUG-12）と runtime 側の実装（TASK-114）の
/// 責務であり、本 crate（core）のトレイト定義には実装を置かない（契約 4）。
/// runtime が netns の fd をどう受け取るか（UDS 越しの fd 受け渡し等）は
/// 人間のアーキテクチャレビュー（#19・TASK-4.h1）でシグネチャとあわせて決める
/// （REPAIR-3: 実装済みを装わない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetnsStatus {
    container: ContainerId,
    name: NetnsName,
}

impl NetnsStatus {
    /// 対象コンテナの ID と検証済みの netns 名から応答を作る。
    ///
    /// 両引数はすでに検証済みの型（[`ContainerId`]・[`NetnsName`]）であるため、
    /// この関数自体は失敗しない。
    pub fn new(container: ContainerId, name: NetnsName) -> Self {
        Self { container, name }
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// netns 名を返す。
    pub fn name(&self) -> &NetnsName {
        &self.name
    }
}

/// [`NetworkPlugin::attach`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttachRequest {
    network: NetworkName,
    container: ContainerId,
    address: Option<IpCidr>,
}

impl AttachRequest {
    /// 接続先ネットワークと対象コンテナから要求を作る（アドレスは未指定）。
    pub fn new(network: NetworkName, container: ContainerId) -> Self {
        Self {
            network,
            container,
            address: None,
        }
    }

    /// 静的 IPAM（NET-1）で使う固定アドレスを指定するビルダ。
    ///
    /// 指定しない場合、実装（plugin 側）が動的に IPAM を行う。
    pub fn with_address(mut self, address: IpCidr) -> Self {
        self.address = Some(address);
        self
    }

    /// 接続先ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// 指定された固定アドレス（未指定なら `None`）を返す。
    pub fn address(&self) -> Option<IpCidr> {
        self.address
    }
}

/// [`NetworkPlugin::attach`] の応答。実際に割り当てられたアドレスとゲートウェイを返す。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttachResponse {
    network: NetworkName,
    container: ContainerId,
    address: IpCidr,
    gateway: Option<IpAddr>,
}

impl AttachResponse {
    /// 接続先ネットワーク・対象コンテナ・割り当てアドレス・ゲートウェイから応答を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        address: IpCidr,
        gateway: Option<IpAddr>,
    ) -> Self {
        Self {
            network,
            container,
            address,
            gateway,
        }
    }

    /// 接続先ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// 実際に割り当てられたアドレス（CIDR）を返す。
    pub fn address(&self) -> IpCidr {
        self.address
    }

    /// default route のゲートウェイ（判明していれば）を返す。
    pub fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
}

/// [`NetworkPlugin::publish_port`] の要求。
///
/// 宛先は生の IP アドレスではなく [`ContainerId`] で指定する。実装（plugin 側）が
/// [`NetworkPlugin::attach`] 済みのアドレスへ解決する（トレイト doc の契約参照）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PublishPortRequest {
    network: NetworkName,
    container: ContainerId,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
    protocol: Protocol,
}

impl PublishPortRequest {
    /// ネットワーク名・対象コンテナ・ホスト側ポート・コンテナ側ポート・プロトコルから
    /// 要求を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        host_port: NonZeroU16,
        container_port: NonZeroU16,
        protocol: Protocol,
    ) -> Self {
        Self {
            network,
            container,
            host_port,
            container_port,
            protocol,
        }
    }

    /// 対象ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 宛先コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// ホスト側の公開ポートを返す。
    pub fn host_port(&self) -> NonZeroU16 {
        self.host_port
    }

    /// コンテナ側の待受ポートを返す。
    pub fn container_port(&self) -> NonZeroU16 {
        self.container_port
    }

    /// トランスポートプロトコルを返す。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// [`NetworkPlugin::publish_port`] の応答。要求と同じ内容を実施結果として返す。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PortMapping {
    network: NetworkName,
    container: ContainerId,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
    protocol: Protocol,
}

impl PortMapping {
    /// ネットワーク名・対象コンテナ・ホスト側ポート・コンテナ側ポート・プロトコルから
    /// マッピング結果を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        host_port: NonZeroU16,
        container_port: NonZeroU16,
        protocol: Protocol,
    ) -> Self {
        Self {
            network,
            container,
            host_port,
            container_port,
            protocol,
        }
    }

    /// 対象ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 宛先コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// ホスト側の公開ポートを返す。
    pub fn host_port(&self) -> NonZeroU16 {
        self.host_port
    }

    /// コンテナ側の待受ポートを返す。
    pub fn container_port(&self) -> NonZeroU16 {
        self.container_port
    }

    /// トランスポートプロトコルを返す。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// [`NetworkPlugin::delete_network`] の要求。
///
/// 削除対象の netns 一覧はここでは受け取らない。そのネットワークで作成・接続した
/// netns は実装（plugin 側）が追跡して決める（上限のない `Vec` を境界へ持ち込まない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DeleteNetworkRequest {
    name: NetworkName,
}

impl DeleteNetworkRequest {
    /// 削除対象のネットワーク名から要求を作る。
    pub fn new(name: NetworkName) -> Self {
        Self { name }
    }

    /// 削除対象のネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }
}

/// [`NetworkPlugin::delete_network`] の応答。当面は空だが、将来の拡張
/// （解放した資源の情報等）に備えて構造体にする（[`super::container_runtime::DeleteResponse`]
/// と同じ形）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteNetworkResponse {}

impl DeleteNetworkResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// テスト専用の契約検証スタブ実装（dyn 互換性・契約 6〜9 の失敗条件を確認するため
    /// のみに使う）。トレイト doc の契約 4「本 crate にはこのトレイトの実装を置かない」
    /// は本番実装を core に置かないという方針であり、`#[cfg(test)]` 配下のみに存在する
    /// 契約チェック用スタブはその対象外である。
    ///
    /// ネットワーク作成状況・netns の所属ネットワーク・attach 済みネットワークを状態と
    /// して保持し、トレイト doc の契約 6〜9・各メソッド doc が定める前提違反を実際に
    /// 検出する。
    struct StubNetworkPlugin {
        networks: Mutex<HashSet<NetworkName>>,
        netns: Mutex<HashMap<ContainerId, NetworkName>>,
        attached: Mutex<HashMap<ContainerId, NetworkName>>,
        fail_delete: AtomicBool,
        fail_publish_port: AtomicBool,
    }

    impl StubNetworkPlugin {
        fn new() -> Self {
            Self {
                networks: Mutex::new(HashSet::new()),
                netns: Mutex::new(HashMap::new()),
                attached: Mutex::new(HashMap::new()),
                fail_delete: AtomicBool::new(false),
                fail_publish_port: AtomicBool::new(false),
            }
        }

        /// [`NetworkPlugin::delete_network`] の次回呼び出しを契約 9 の
        /// 「1 件でも失敗があれば `Err`」経路へ強制するためのスイッチ。
        fn set_fail_delete(&self, fail: bool) {
            self.fail_delete.store(fail, Ordering::SeqCst);
        }

        /// [`NetworkPlugin::publish_port`] の次回呼び出しを契約 6 の
        /// 「DNAT ルール追加後に失敗し、撤回にも失敗する」経路へ強制するためのスイッチ。
        fn set_fail_publish_port(&self, fail: bool) {
            self.fail_publish_port.store(fail, Ordering::SeqCst);
        }
    }

    impl NetworkPlugin for StubNetworkPlugin {
        fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
            let mut networks = self.networks.lock().expect("lock networks");
            if !networks.insert(req.name().clone()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "network already exists",
                ));
            }
            Ok(NetworkStatus::new(req.name().clone(), req.subnet()))
        }

        fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let mut netns = self.netns.lock().expect("lock netns");
            if netns.contains_key(req.container()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "netns already exists for this container",
                ));
            }
            netns.insert(req.container().clone(), req.network().clone());
            let name = NetnsName::new(format!("netns-{}", req.container().as_str()))
                .expect("stub container ids are valid netns name suffixes");
            Ok(NetnsStatus::new(req.container().clone(), name))
        }

        fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let netns = self.netns.lock().expect("lock netns");
            let bound_network = netns
                .get(req.container())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "netns not created"))?;
            if bound_network != req.network() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "netns is bound to a different network",
                ));
            }
            let address = req
                .address()
                .unwrap_or_else(|| IpCidr::new(sample_attach_addr(), 24).expect("valid cidr"));
            self.attached
                .lock()
                .expect("lock attached")
                .insert(req.container().clone(), req.network().clone());
            Ok(AttachResponse::new(
                req.network().clone(),
                req.container().clone(),
                address,
                Some(sample_gateway()),
            ))
        }

        fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let attached = self.attached.lock().expect("lock attached");
            let bound_network = attached
                .get(req.container())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "container not attached"))?;
            if bound_network != req.network() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is attached to a different network",
                ));
            }
            // 契約 6: DNAT ルール追加後に失敗した場合は追加済みのルールを撤回してから
            // `Err` を返し、撤回にも失敗すれば `Internal` を返す。このスタブは
            // `set_fail_publish_port` が立っている間、ルールを積まずに撤回済み相当の
            // 状態のまま `Internal` を返すことでその経路を模擬する。
            if self.fail_publish_port.load(Ordering::SeqCst) {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to add DNAT rule and rollback also failed",
                ));
            }
            Ok(PortMapping::new(
                req.network().clone(),
                req.container().clone(),
                req.host_port(),
                req.container_port(),
                req.protocol(),
            ))
        }

        fn delete_network(
            &self,
            req: &DeleteNetworkRequest,
        ) -> Result<DeleteNetworkResponse, TraitError> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to delete one or more tracked resources",
                ));
            }
            self.networks
                .lock()
                .expect("lock networks")
                .remove(req.name());
            Ok(DeleteNetworkResponse::new())
        }
    }

    fn sample_network_name() -> NetworkName {
        NetworkName::new("front-end").expect("valid network name")
    }

    fn other_network_name() -> NetworkName {
        NetworkName::new("back-end").expect("valid network name")
    }

    fn sample_container_id() -> ContainerId {
        ContainerId::new("sample-container").expect("valid id")
    }

    fn sample_subnet() -> IpCidr {
        IpCidr::new(IpAddr::from([10, 250, 11, 1]), 24).expect("valid cidr")
    }

    fn sample_attach_addr() -> IpAddr {
        IpAddr::from([10, 250, 11, 2])
    }

    fn sample_gateway() -> IpAddr {
        IpAddr::from([10, 250, 11, 1])
    }

    /// CRI-7: `NetworkPlugin` は dyn 互換で、`Box`/`Arc` に収めて 5 メソッドを順に呼べる。
    #[test]
    fn cri7_network_plugin_is_dyn_compatible() {
        let boxed: Box<dyn NetworkPlugin> = Box::new(StubNetworkPlugin::new());
        let net_req = CreateNetworkRequest::new(sample_network_name(), sample_subnet());
        let net_status = boxed.create_network(&net_req).expect("create succeeds");
        assert_eq!(net_status.subnet().to_string(), "10.250.11.1/24");

        let netns_status = boxed
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("network is created so create_netns succeeds");
        assert_eq!(netns_status.container(), &sample_container_id());
        assert_eq!(netns_status.name().as_str(), "netns-sample-container");

        let attach_resp = boxed
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach succeeds");
        assert_eq!(attach_resp.address().to_string(), "10.250.11.2/24");

        let mapping = boxed
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("publish_port succeeds");
        assert_eq!(mapping.protocol().as_str(), "tcp");

        let shared: Arc<dyn NetworkPlugin> = Arc::new(StubNetworkPlugin::new());
        let delete_resp = shared
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect("delete_network succeeds");
        assert_eq!(delete_resp, DeleteNetworkResponse::new());
    }

    /// PLUG-1: 実装のエラーコードが ERR-1 の機械可読文字列（`code().as_str()`）へ
    /// そのまま伝播する（二重の `create_network` は `ALREADY_EXISTS`）。
    #[test]
    fn plug1_network_plugin_error_propagates_code() {
        let plugin = StubNetworkPlugin::new();
        let req = CreateNetworkRequest::new(sample_network_name(), sample_subnet());
        assert!(plugin.create_network(&req).is_ok());
        let err = plugin
            .create_network(&req)
            .expect_err("second create must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// NET-1: 受理されるネットワーク名の例（英数字始まり・ハイフン・境界長）。
    #[test]
    fn net1_network_name_accepts_valid_values() {
        assert_eq!(NetworkName::new("n1").expect("valid").as_str(), "n1");
        assert_eq!(
            NetworkName::new("front-end").expect("valid").as_str(),
            "front-end"
        );
        let max_len = "a".repeat(64);
        assert!(NetworkName::new(max_len).is_ok());
    }

    /// NET-1: 拒否されるネットワーク名の例（空・記号先頭・区切り文字・NUL・非 ASCII・長さ超過）。
    #[test]
    fn net1_network_name_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            "-a".to_string(),
            "a_b".to_string(),
            "a.b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
            "a\0b".to_string(),
            "é".to_string(),
            "a".repeat(65),
        ];
        for case in cases {
            let err = NetworkName::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// NET-1: `TryFrom<&str>` / `TryFrom<String>` が `new` と同じ検証結果を返す。
    #[test]
    fn net1_network_name_try_from_matches_new() {
        let name = NetworkName::try_from("front-end").expect("valid");
        assert_eq!(name.as_str(), "front-end");

        let name = NetworkName::try_from("front-end".to_string()).expect("valid");
        assert_eq!(name.as_str(), "front-end");

        let err = NetworkName::try_from("-a").expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// CRI-7: 受理される netns 名の例（[`NetworkName`] と同じ文字集合・境界長）。
    #[test]
    fn cri7_netns_name_accepts_valid_values() {
        assert_eq!(NetnsName::new("n1").expect("valid").as_str(), "n1");
        assert_eq!(
            NetnsName::new("netns-sample").expect("valid").as_str(),
            "netns-sample"
        );
        let max_len = "a".repeat(64);
        assert!(NetnsName::new(max_len).is_ok());
    }

    /// CRI-7: 拒否される netns 名の例（[`NetworkName`] と同じ検証を共有する）。
    #[test]
    fn cri7_netns_name_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            "-a".to_string(),
            "a_b".to_string(),
            "a.b".to_string(),
            "a/b".to_string(),
            "a\0b".to_string(),
            "a".repeat(65),
        ];
        for case in cases {
            let err = NetnsName::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// CRI-7: `TryFrom<&str>` / `TryFrom<String>` が `NetnsName::new` と同じ検証結果を返す。
    #[test]
    fn cri7_netns_name_try_from_matches_new() {
        let name = NetnsName::try_from("netns-a").expect("valid");
        assert_eq!(name.as_str(), "netns-a");

        let name = NetnsName::try_from("netns-a".to_string()).expect("valid");
        assert_eq!(name.as_str(), "netns-a");

        let err = NetnsName::try_from("-a").expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// CRI-7: `NetnsStatus` は識別子のみを保持する値型で、同一入力から作った 2 つの
    /// インスタンスが `Eq` で等しく、コンテナ ID・netns 名を具体値で参照できる。
    #[test]
    fn cri7_netns_status_holds_container_and_name() {
        let container = sample_container_id();
        let name = NetnsName::new("netns-sample").expect("valid");
        let status = NetnsStatus::new(container.clone(), name.clone());
        assert_eq!(status.container(), &container);
        assert_eq!(status.name(), &name);
        assert_eq!(status.clone(), NetnsStatus::new(container, name));
    }

    /// NET-1: `IpCidr::new` はアドレスファミリごとの prefix 上限を検証し、
    /// `Display` が "10.250.11.1/24" 形式になる。
    #[test]
    fn net1_ip_cidr_validates_prefix_by_family() {
        let v4 = IpAddr::from([10, 250, 11, 1]);
        assert!(IpCidr::new(v4, 0).is_ok());
        assert!(IpCidr::new(v4, 32).is_ok());
        let err = IpCidr::new(v4, 33).expect_err("v4 prefix must be <= 32");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let v6 = IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]);
        assert!(IpCidr::new(v6, 128).is_ok());
        let err = IpCidr::new(v6, 129).expect_err("v6 prefix must be <= 128");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let cidr = IpCidr::new(v4, 24).expect("valid cidr");
        assert_eq!(cidr.to_string(), "10.250.11.1/24");
    }

    /// NET-4: `Protocol::as_str` が全バリアントで小文字文字列を返す。
    #[test]
    fn net1_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
    }

    /// `CreateNetnsRequest` は所属先ネットワーク名を保持し、`network()` で参照できる
    /// （`delete_network` の追跡対象決定に使うため）。
    #[test]
    fn cri7_create_netns_request_returns_network() {
        let req = CreateNetnsRequest::new(sample_network_name(), sample_container_id());
        assert_eq!(req.network(), &sample_network_name());
        assert_eq!(req.container(), &sample_container_id());
    }

    /// NET-1: `AttachRequest` は `new` 直後に `address()` が `None`、
    /// `with_address` の後は `Some`（具体値で一致）になる。
    #[test]
    fn net1_attach_request_address_is_optional() {
        let req = AttachRequest::new(sample_network_name(), sample_container_id());
        assert_eq!(req.address(), None);

        let addr = IpCidr::new(sample_attach_addr(), 24).expect("valid cidr");
        let req = req.with_address(addr);
        assert_eq!(req.address(), Some(addr));
    }

    /// 契約 8: 存在しないネットワークへの `create_netns` は `NotFound`。
    #[test]
    fn net1_create_netns_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 7: 同じコンテナの netns を二重に作成すると `AlreadyExists`。
    #[test]
    fn net1_create_netns_duplicate_container_is_already_exists() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let req = CreateNetnsRequest::new(sample_network_name(), sample_container_id());
        plugin.create_netns(&req).expect("first create succeeds");
        let err = plugin
            .create_netns(&req)
            .expect_err("second create for same container must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// 契約 8: 存在しないネットワークへの `attach` は `NotFound`。
    #[test]
    fn net1_attach_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: netns 未作成のコンテナへの `attach` は、`create_network` 未作成時と
    /// 同じ扱いで `NotFound`（メソッド doc の記述を契約一覧に合わせて統一）。
    #[test]
    fn net1_attach_without_netns_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let err = plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns was never created for this container");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: netns が別ネットワークに紐付いている場合の `attach` は
    /// `FailedPrecondition`（越境接続の拒否）。
    #[test]
    fn net2_attach_netns_bound_to_other_network_is_failed_precondition() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns bound to front-end");
        let err = plugin
            .attach(&AttachRequest::new(
                other_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns is bound to a different network");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// 契約 8: 存在しないネットワークへの `publish_port` は `NotFound`。
    #[test]
    fn net4_publish_port_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: 未 attach のコンテナへの `publish_port` は `NotFound`。
    #[test]
    fn net4_publish_port_without_attach_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("container was never attached");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: attach 済みのネットワークと異なるネットワークを指定した `publish_port` は
    /// `FailedPrecondition`（越境 DNAT の拒否）。
    #[test]
    fn net4_publish_port_attached_to_other_network_is_failed_precondition() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach to front-end");
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                other_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("container is attached to a different network");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// 契約 9: `delete_network` は個々の削除に 1 件でも失敗すれば `Internal` を返す
    /// （ベストエフォートで残りの削除を続ける契約であり、部分失敗も `Err` 扱い）。
    #[test]
    fn net3_delete_network_partial_failure_is_internal() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin.set_fail_delete(true);
        let err = plugin
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect_err("a partial failure must surface as Err");
        assert_eq!(err.code().as_str(), "INTERNAL");
    }

    /// 契約 6: `publish_port` は DNAT ルール追加後に失敗した場合、撤回にも失敗すれば
    /// `Internal` を返す。
    #[test]
    fn net4_publish_port_partial_failure_rolls_back() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin.set_fail_publish_port(true);
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("DNAT rule addition and its rollback both fail");
        assert_eq!(err.code().as_str(), "INTERNAL");
    }
}
