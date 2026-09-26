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
use std::path::{Path, PathBuf};

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
///    [`Self::attach`] が途中で失敗した場合、実装は作成済みのリソース
///    （bridge・veth・nft テーブル・netns）を逆順に削除してから `Err` を返す
///    （PoC-15 の 2026-09-24 修正に準拠）。[`Self::create_netns`] は netns 作成後に
///    lo の up を行うため、lo 設定が失敗した場合は作成済みの netns 自体を削除して
///    から `Err` を返す（codex/review 指摘 P1）。ロールバックせず netns を残したまま
///    `Err` を返すと、同じコンテナへの再試行が [`ErrorCode::AlreadyExists`]（契約 7）に
///    より恒久的に失敗するため、ロールバックは再試行可能性の前提でもある。
/// 7. **二重作成の拒否**: 同名のネットワークや同じコンテナの netns が既にあれば
///    [`ErrorCode::AlreadyExists`] を返す。前回の残骸を黙って再利用しない。
/// 8. **前提違反**: 存在しないネットワークへの [`Self::create_netns`] / [`Self::attach`] /
///    [`Self::publish_port`]、netns 未作成のコンテナへの [`Self::attach`]、
///    未 attach のコンテナへの [`Self::publish_port`] は [`ErrorCode::NotFound`] を返す。
///    加えて [`Self::attach`] は、対象コンテナの netns が [`Self::create_netns`] で
///    紐付けられたネットワーク（`CreateNetnsRequest::network`）と `req.network()` が
///    一致しない場合、[`ErrorCode::FailedPrecondition`] を返す（異なるネットワークへの
///    越境接続を拒否し、[`Self::delete_network`] の追跡対象と実際の接続先の食い違いを
///    防ぐ。codex/review 指摘 P1）。同様に [`Self::publish_port`] は、対象コンテナが
///    [`Self::attach`] された際のネットワーク（`AttachRequest::network`）と
///    `req.network()` が一致しない場合、[`ErrorCode::FailedPrecondition`] を返す
///    （別ネットワークに属するコンテナ ID を渡して越境 DNAT を設定させないため。
///    codex/review 指摘 P1）。
/// 9. **削除はベストエフォートで続行**: [`Self::delete_network`] は個々の削除に失敗しても
///    残りの削除を続け、1 件でも失敗があれば `Err`（[`ErrorCode::Internal`]）を返す
///    （PoC-15 の `net-delete` に準拠）。
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
    /// 残る事態を防ぐ。codex/review 指摘 P1）。加えて、同じコンテナの netns が既に
    /// 存在しないこと。存在する場合は [`ErrorCode::AlreadyExists`] を返す（契約 7）。
    /// `req.network()` が指すネットワークに属するものとして実装側が追跡し、
    /// [`Self::delete_network`] の削除対象に含める（`attach` 未実施でも回収
    /// できるようにするため。codex/review 指摘 P1）。lo の up に失敗した場合は
    /// 作成済みの netns を削除してから `Err` を返す（契約 6）。対応: NET-1。
    fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError>;

    /// veth ペアを作成し、bridge / netns へ接続してアドレス・default route を設定する。
    ///
    /// netsetup の `veth-attach` に対応し、`SetUpPod` の一部。前提: `req.network()` が
    /// [`Self::create_network`] 済みであること（未作成なら [`ErrorCode::NotFound`]）、
    /// 対象コンテナの netns が [`Self::create_netns`] 済みであること（未作成なら
    /// [`ErrorCode::FailedPrecondition`]）。さらに、その netns が [`Self::create_netns`]
    /// 呼び出し時に紐付けられたネットワーク（`CreateNetnsRequest::network`）が
    /// `req.network()` と一致すること（不一致なら [`ErrorCode::FailedPrecondition`]）。
    /// 異なるネットワークに属する netns への接続を許すと、実際の接続先ネットワークと
    /// [`Self::delete_network`] が追跡する削除対象ネットワークが食い違い、分離・
    /// 後始末の契約が崩れるため（codex/review 指摘 P1）。途中で失敗した場合は
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
    /// が追跡する削除対象の食い違いを招く（[`Self::attach`] の契約 8 と同じ理由。
    /// codex/review 指摘 P1）。宛先は生の IP アドレスではなく [`ContainerId`] で
    /// 指定し、実装（plugin 側）が attach 済みのアドレスへ解決する。これは PoC-15
    /// との差分であり、ネットワーク外の任意ホストへ DNAT させる経路をトレイト境界で
    /// 作らないための設計である（#19 で確認する）。対応: NET-4。
    fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError>;

    /// ネットワーク（bridge・nft テーブル・関連 netns）を一括削除する。
    ///
    /// netsetup の `net-delete` に対応し、CRI の `TearDownPod` 相当。削除対象の netns
    /// 一覧は呼び出し側から受け取らず、そのネットワークに [`Self::create_netns`]（`req.network()`
    /// で紐付け）・[`Self::attach`] のいずれかで関連付けたものを実装（plugin 側）が追跡して
    /// 決める（上限のない `Vec` を境界へ持ち込まないため）。`attach` 前に失敗した netns も
    /// `create_netns` の時点で追跡対象に入っているため回収できる（codex/review 指摘 P1）。
    /// 個々の削除に失敗しても残りの削除を続け、1 件でも失敗があれば `Err` を返す
    /// （契約 9）。対応: NET-3・NET-5。
    fn delete_network(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError>;
}

/// ネットワーク名の許容文字数の上限（暫定値）。
///
/// plugin はインターフェース名の制約（`IFNAMSIZ` 由来。PoC-17 で bridge の接頭辞込みで
/// 8 文字が `ERANGE` になった事例）により、さらに厳しい上限を [`ErrorCode::InvalidArgument`]
/// で課してよい。この値の確定は人間のアーキテクチャレビュー（#19・TASK-4.h1）で行う。
const NETWORK_NAME_MAX_LEN: usize = 64;

/// 検証済みのネットワーク名。
///
/// bridge・nft テーブル・netns の名前として実装側が使うため、パス区切り文字・NUL・
/// 非 ASCII・制御文字・空白を型のレベルで排除する（PoC-15 で名前が nft スクリプトや
/// インターフェース名へ埋め込まれていたため、境界の型の時点で制限する。security.md）。
/// 生成は [`NetworkName::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// 入力文字列を検証してネットワーク名を作る。
    ///
    /// 拒否条件（いずれかに該当すると [`ErrorCode::InvalidArgument`]）:
    /// - 空文字列
    /// - 長さが `NETWORK_NAME_MAX_LEN`（64 バイト）を超える
    /// - 先頭が ASCII 英数字でない
    /// - 2 文字目以降に `[A-Za-z0-9-]` 以外の文字を含む
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "network name must not be empty",
            ));
        }
        if value.len() > NETWORK_NAME_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("network name must be at most {NETWORK_NAME_MAX_LEN} bytes"),
            ));
        }
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "network name must not be empty",
            ));
        };
        if !first.is_ascii_alphanumeric() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "network name must start with an ASCII alphanumeric character",
            ));
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "network name must match [A-Za-z0-9][A-Za-z0-9-]*",
            ));
        }
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
/// `network` は、この netns がどのネットワークに属するかを実装（plugin 側）へ伝える
/// （codex/review 指摘 P1）。[`Self::network`] 経由の `attach` 前に本呼び出しが失敗しても、
/// 実装はこの時点で受け取ったネットワーク名に紐付けて netns を追跡でき、その後の
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
/// `path` は診断・ログ用途の実体パス（canonicalize 後）に過ぎず、`handle` が指す
/// オブジェクトとの同一性を runtime 側が改めて保証する手段ではない。netns への
/// join 等、実際の利用は必ず [`Self::handle`] が返すオープン済みのファイル
/// ディスクリプタ経由で行い、`path()` を使って再度開き直さない契約とする
/// （codex/review 指摘 P1・TOCTOU 対策）。`File` は `Clone`/`PartialEq`/`Eq`/`Hash` を
/// 実装しないため、それらの derive は落としてある。
#[derive(Debug)]
#[non_exhaustive]
pub struct NetnsStatus {
    container: ContainerId,
    path: PathBuf,
    handle: std::fs::File,
}

impl NetnsStatus {
    /// 対象コンテナの ID・netns の絶対パス・許可された netns 配下ディレクトリ
    /// （`allowed_root`）から応答を作る。
    ///
    /// plugin からの応答は untrusted な外部入力であり、`path` を字句上の判定
    /// （`is_absolute()`・[`Path::strip_prefix`] 等）だけで受理すると、`allowed_root`
    /// 配下にある symlink が外部（`/etc/passwd` 等）を指す場合にも通ってしまい、
    /// runtime がその symlink をそのまま辿る経路になる（codex/review 指摘 P0・
    /// security.md「plugin からの入力は untrusted として検証する」「パス要素は
    /// 検証・正規化してからルート配下であることを確認する」）。そのため本関数は
    /// 字句上の検証に加えて `std::fs::canonicalize` で symlink を実際に解決してから
    /// 配下判定を行う（`StateStore` の既定実装が core に置かれるのと同様、fs アクセスは
    /// 本 crate の関心事から外れない。coding-rust.md）。
    ///
    /// 検証手順（fail-closed）:
    /// 1. `path`・`allowed_root` がともに絶対パスであること（相対パスは cwd に依存し
    ///    `canonicalize` の意味が呼び出し文脈で変わるため、先に弾く）。
    /// 2. `path` が `.`・`..` コンポーネントを含まないこと（字句上のトラバーサル拒否。
    ///    canonicalize で `..` は解決されるが、明らかな不正入力を早期に弾くため残す）。
    /// 3. `path`・`allowed_root` の双方を `canonicalize` し、symlink・`..`・冗長な
    ///    区切り文字を解決した実体パスにする。**両方**を canonicalize するのは、
    ///    片方だけだと macOS の `/tmp` → `/private/tmp` のような実体パスの差異や、
    ///    Windows の `\\?\` verbose prefix の有無で [`Path::strip_prefix`] が誤って
    ///    不一致になる（＝正当な netns まで拒否する）ためである。
    /// 4. canonicalize 後の `path` が canonicalize 後の `allowed_root` の
    ///    **コンポーネント単位**の配下にあることを [`Path::strip_prefix`] で検証する。
    ///    文字列の前方一致（`starts_with`）を使わないのは、`/run/netns-evil/x` の
    ///    ような紛らわしい兄弟ディレクトリを `/run/netns` への前方一致で誤って
    ///    許可しないためである。
    ///
    /// 呼び出し側（境界機構・proxy。PLUG-11・PLUG-12）は、plugin から受け取った生の
    /// パスをそのまま渡してよい。symlink 解決はこの関数が行うため、呼び出し側で
    /// 事前に正規化する契約には依存しない。
    ///
    /// # netns であることの確認（codex/review 指摘 P1）
    ///
    /// 配下判定（手順 4）だけでは、`allowed_root` 配下に置かれた「netns を装った
    /// 通常ファイル」を untrusted な plugin 応答がそのまま主張しても検出できない
    /// （security.md「plugin からの入力は untrusted として検証する」）。そのため
    /// canonicalize 後、実際に `canonical_path` を開いて Linux の `/proc/self/fd/<fd>`
    /// が `net:[<inode>]` 形式（`proc(5)`。ネットワーク namespace 以外の namespace
    /// 種別や通常ファイルはこの形式にならない）を指すことを確認する
    /// （[`verify_is_netns`]）。`libc` / `nix` 等の追加依存やコード内 `unsafe` を
    /// 増やさない方針（dependency-policy.md・coding-rust.md）のため、`setns(2)` 等の
    /// syscall 直叩きではなく `std::fs`（`File::open`・`read_link`）のみで検証する。
    /// Linux 以外（NET-1〜5 は Linux カーネルの netns 機能が前提）では常に拒否する。
    ///
    /// # TOCTOU 対策（codex/review 指摘 P1）
    ///
    /// 検証と利用の間で対象が差し替えられる（TOCTOU）と、canonicalize 後の
    /// パス文字列だけを渡す契約では runtime が後で別の対象を開いてしまう。
    /// 本関数は canonicalize 直後に一度だけ `File::open` した結果（`handle`）を
    /// そのまま [`NetnsStatus`] に保持して返し、netns であることの確認
    /// （上記）もこの同じハンドルに対して行う。runtime 側は [`Self::handle`] の
    /// ハンドルをそのまま使い（将来の `setns(2)` 実装は fd を直接渡す）、
    /// [`Self::path`] を再度開き直さない契約とすることで、確認した対象と
    /// 利用する対象の同一性を保証する。`canonicalize` から `File::open` までの
    /// 間（本関数内の数マイクロ秒）に限っては fs 操作自体の原子性が std だけでは
    /// 保証できず残存するが、「runtime が任意のタイミングで再度パスを開き直す」
    /// という従来の無期限な TOCTOU 窓は本関数内の 1 回の open へ縮小される。
    ///
    /// `allowed_root` が絶対パスでない、`path` が絶対パスでない、`path` が `.`・`..`
    /// を含む、`path` / `allowed_root` の実体が存在せず canonicalize に失敗する、
    /// canonicalize 後の `path` が canonicalize 後の `allowed_root` 配下にない、
    /// 対象を開けない、または対象がネットワーク namespace であることを確認できない
    /// 場合は [`ErrorCode::InvalidArgument`] を返す。
    pub fn new(
        container: ContainerId,
        path: PathBuf,
        allowed_root: &Path,
    ) -> Result<Self, TraitError> {
        if !allowed_root.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "netns allowed root must be absolute",
            ));
        }
        if !path.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "netns path must be absolute",
            ));
        }
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "netns path must not contain \".\" or \"..\" components",
            ));
        }
        // symlink・`..`・冗長区切りを解決した実体パスへ正規化する。plugin から
        // 渡された生のパスが `allowed_root` 配下の symlink 経由で外部を指す場合
        // でも、ここで実体パスに解決してから配下判定を行うため通らない
        // （codex/review 指摘 P0）。
        let canonical_path = path.canonicalize().map_err(|e| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                format!("netns path could not be resolved (canonicalize failed): {e}"),
            )
        })?;
        let canonical_root = allowed_root.canonicalize().map_err(|e| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                format!("netns allowed root could not be resolved (canonicalize failed): {e}"),
            )
        })?;
        if canonical_path.strip_prefix(&canonical_root).is_err() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "netns path must be under the allowed netns root",
            ));
        }
        // codex/review 指摘 P1（TOCTOU）: ここで一度だけ開いたハンドルを、
        // 直後の netns 種別確認（P1 その 1）にも、返り値として runtime に渡す
        // ハンドルにも共用する。runtime が後から path() を再度開き直す経路を
        // 作らないことで、確認対象と利用対象の同一性を保証する。
        let handle = std::fs::File::open(&canonical_path).map_err(|e| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                format!("netns path could not be opened: {e}"),
            )
        })?;
        verify_is_netns(&handle)?;
        Ok(Self {
            container,
            path: canonical_path,
            handle,
        })
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// netns のオープン済みハンドルを返す。
    ///
    /// runtime（`ContainerRuntime` 実装）はこのハンドルを使って netns に join する
    /// （将来の `setns(2)` 実装は本ハンドルの fd を直接渡す想定。TASK-4.h1）。
    /// [`Self::path`] を使って再度開き直すと、[`Self::new`] が検証した対象との
    /// 同一性が保証されなくなる（codex/review 指摘 P1・TOCTOU）。
    pub fn handle(&self) -> &std::fs::File {
        &self.handle
    }

    /// netns の絶対パス（canonicalize 後の実体パス）を返す。
    ///
    /// 診断・ログ用途のみに使う。実際に netns を利用する経路は必ず
    /// [`Self::handle`] を使う（codex/review 指摘 P1・TOCTOU 対策）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// [`NetnsStatus::new`] が開いたハンドルが実際にネットワーク namespace であることを
/// 確認する（codex/review 指摘 P1）。
///
/// `file` の指す対象が Linux の nsfs 上のネットワーク namespace であれば `Ok`、
/// 通常ファイル・他の namespace 種別（uts・mnt・pid 等）・非対応プラットフォームでは
/// `Err`（[`ErrorCode::InvalidArgument`]）を返す。`libc` / `nix` 等の追加依存や
/// `unsafe` を増やさない方針（dependency-policy.md・coding-rust.md）のため、
/// `statfs(2)` / `setns(2)` 直叩きではなく `std::fs::read_link` による
/// `/proc/self/fd/<fd>` の内容確認のみで判定する。
#[cfg(target_os = "linux")]
fn verify_is_netns(file: &std::fs::File) -> Result<(), TraitError> {
    use std::os::unix::io::AsRawFd;

    let fd_path = Path::new("/proc/self/fd").join(file.as_raw_fd().to_string());
    let target = std::fs::read_link(&fd_path).map_err(|e| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            format!("netns handle could not be inspected via procfs: {e}"),
        )
    })?;
    // nsfs 上の namespace ファイルは proc(5) の規定により `readlink` が
    // `<種別>:[<inode番号>]`（例: `net:[4026531840]`）を返す。ネットワーク
    // namespace 以外（`uts:[...]` 等）や通常ファイル（実パスになる）はこの形式に
    // ならないため拒否する。
    let target_str = target.to_string_lossy();
    if target_str.starts_with("net:[") && target_str.ends_with(']') {
        Ok(())
    } else {
        Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "netns path does not refer to a network namespace",
        ))
    }
}

/// Linux 以外では netns 機能自体が存在しない（NET-1〜5 は Linux カーネル前提）ため
/// 常に拒否する。3 OS 一級対応（coding-rust.md）のためのプラットフォーム分岐であり、
/// macOS / Windows 向けの netns 実装は本トレイトのスコープ外（#19・TASK-4.h1）。
#[cfg(not(target_os = "linux"))]
fn verify_is_netns(_file: &std::fs::File) -> Result<(), TraitError> {
    Err(TraitError::new(
        ErrorCode::InvalidArgument,
        "netns is only supported on Linux",
    ))
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
    use std::sync::Arc;

    /// `NetnsStatus::new`（P0 の symlink 解決検証）用の一時ディレクトリ管理。
    ///
    /// `NetnsStatus::new` が `std::fs::canonicalize` で実体パスを解決する契約
    /// （codex/review 指摘 P0）になったため、テストも実在するパスを用意する
    /// 必要がある。`base` 配下に allowed_root・その外側のディレクトリ・symlink を
    /// 作り、`Drop` で後始末する。
    struct NetnsTestFixture {
        base: PathBuf,
    }

    impl NetnsTestFixture {
        /// `tag`（テストごとに異なる文字列）とプロセス ID・連番から一意な一時
        /// ディレクトリを作る。並列実行される他のテストと衝突しない。
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let base = std::env::temp_dir().join(format!(
                "fandhe-container-network-plugin-test-{tag}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&base).expect("create fixture base dir");
            Self { base }
        }

        /// フィクスチャのベースディレクトリ（`allowed_root` の外側にも使う）。
        fn base(&self) -> &Path {
            &self.base
        }

        /// `allowed_root` として使うディレクトリを作って返す。
        fn allowed_root(&self) -> PathBuf {
            let root = self.base.join("root");
            std::fs::create_dir_all(&root).expect("create allowed root");
            root
        }

        /// `dir` 配下に空ファイル `name` を作り、そのパスを返す（`dir` も必要なら作る）。
        fn file_under(&self, dir: &Path, name: &str) -> PathBuf {
            std::fs::create_dir_all(dir).expect("create parent dir");
            let file = dir.join(name);
            std::fs::write(&file, b"").expect("create fixture file");
            file
        }
    }

    impl Drop for NetnsTestFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// テスト用のスタブ実装。dyn 互換性と各メソッドの戻り値を確認するためのみに使う。
    struct StubNetworkPlugin {
        network_created: std::sync::atomic::AtomicBool,
        netns_fixture: NetnsTestFixture,
    }

    impl StubNetworkPlugin {
        fn new() -> Self {
            Self {
                network_created: std::sync::atomic::AtomicBool::new(false),
                netns_fixture: NetnsTestFixture::new("stub"),
            }
        }
    }

    impl NetworkPlugin for StubNetworkPlugin {
        fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
            if self
                .network_created
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "network already exists",
                ));
            }
            Ok(NetworkStatus::new(req.name().clone(), req.subnet()))
        }

        fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
            let allowed_root = self.netns_fixture.allowed_root();
            let path = self.netns_fixture.file_under(&allowed_root, "x");
            NetnsStatus::new(req.container().clone(), path, &allowed_root)
        }

        fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError> {
            let address = req
                .address()
                .unwrap_or_else(|| IpCidr::new(sample_attach_addr(), 24).expect("valid cidr"));
            Ok(AttachResponse::new(
                req.network().clone(),
                req.container().clone(),
                address,
                Some(sample_gateway()),
            ))
        }

        fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
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
            _req: &DeleteNetworkRequest,
        ) -> Result<DeleteNetworkResponse, TraitError> {
            Ok(DeleteNetworkResponse::new())
        }
    }

    fn sample_network_name() -> NetworkName {
        NetworkName::new("front-end").expect("valid network name")
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

    /// [`NetnsStatus::new`] の字句上のトラバーサル拒否テストへ渡す、実在しなくてよい
    /// 許可済み netns 配下ディレクトリ（絶対パスであること以外は検証されない経路）。
    #[cfg(unix)]
    fn nonexistent_allowed_root() -> PathBuf {
        PathBuf::from("/run/netns")
    }

    #[cfg(windows)]
    fn nonexistent_allowed_root() -> PathBuf {
        PathBuf::from(r"C:\netns")
    }

    /// CRI-7: `NetworkPlugin` は dyn 互換で、`Box`/`Arc` に収めて 5 メソッドを順に呼べる。
    #[test]
    fn cri7_network_plugin_is_dyn_compatible() {
        let boxed: Box<dyn NetworkPlugin> = Box::new(StubNetworkPlugin::new());
        let net_req = CreateNetworkRequest::new(sample_network_name(), sample_subnet());
        let net_status = boxed.create_network(&net_req).expect("create succeeds");
        assert_eq!(net_status.subnet().to_string(), "10.250.11.1/24");

        // `StubNetworkPlugin::create_netns` は fixture の通常ファイルを渡すため、
        // 特権なしでは本物の netns を用意できず [`NetnsStatus::new`] の netns 種別
        // 確認（codex/review 指摘 P1）で必ず拒否される。dyn dispatch 経由で
        // `Result<NetnsStatus, TraitError>` が正しく返ってくることの確認が本テストの
        // 目的であり、実際の netns 検証は `p1_netns_status_rejects_non_netns_file`
        // が担う。
        let netns_err = boxed
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("stub does not provide a real netns");
        assert_eq!(netns_err.code().as_str(), "INVALID_ARGUMENT");

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

    /// CRI-7: `NetnsStatus::new` は相対パスを拒否する。
    #[test]
    fn cri7_netns_status_rejects_relative_path() {
        let fixture = NetnsTestFixture::new("relative");
        let allowed_root = fixture.allowed_root();
        let err = NetnsStatus::new(sample_container_id(), PathBuf::from("netns"), &allowed_root)
            .expect_err("relative path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P1: `NetnsStatus::new` は `allowed_root` 配下にあり
    /// 字句上・symlink 解決後の配下判定を通る実在パスであっても、それが実際には
    /// netns ではない通常ファイルであれば拒否する（untrusted な plugin 応答が
    /// 「netns を装った通常ファイル」を主張するケースの再現。配下判定だけでは
    /// 通ってしまっていた元の不具合）。
    #[test]
    fn p1_netns_status_rejects_non_netns_file() {
        let fixture = NetnsTestFixture::new("non-netns");
        let allowed_root = fixture.allowed_root();
        let path = fixture.file_under(&allowed_root, "x");
        let err = NetnsStatus::new(sample_container_id(), path, &allowed_root)
            .expect_err("a regular file must not be accepted as a netns");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P1: netns 種別確認の核となる述語（`verify_is_netns`）は、
    /// 特権なしで開ける実在のネットワーク namespace（自プロセスの
    /// `/proc/self/ns/net`）を正しく受理する。`NetnsStatus::new` 全体（配下判定＋
    /// canonicalize）を経由する結合テストは、`allowed_root` 配下に本物の netns を
    /// 非特権で用意する手段がない（`ip netns add` 相当のビルドマウントには
    /// `CAP_SYS_ADMIN` が要る）ため、述語単体をここで直接検証する。
    #[cfg(target_os = "linux")]
    #[test]
    fn p1_verify_is_netns_accepts_real_network_namespace() {
        let file = std::fs::File::open("/proc/self/ns/net")
            .expect("this process always has a network namespace");
        verify_is_netns(&file).expect("own netns must be recognized as a netns");
    }

    /// codex/review 指摘 P1: netns 種別確認の述語は、netns ではない通常ファイルを
    /// 拒否する（Linux で `/proc/self/fd/<fd>` の readlink が `net:[...]` 形式に
    /// ならないケース）。
    #[cfg(target_os = "linux")]
    #[test]
    fn p1_verify_is_netns_rejects_regular_file() {
        let fixture = NetnsTestFixture::new("predicate");
        let path = fixture.file_under(fixture.base(), "not-a-netns");
        let file = std::fs::File::open(&path).expect("open fixture file");
        let err = verify_is_netns(&file).expect_err("a regular file must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P0: `NetnsStatus::new` は untrusted な plugin 応答が
    /// 任意の実在パスを主張しても、`allowed_root` 配下でなければ拒否する
    /// （文字列前方一致ではなくコンポーネント単位で判定するため、紛らわしい兄弟
    /// ディレクトリも通さない）。
    #[test]
    fn p0_netns_status_rejects_path_outside_allowed_root() {
        let fixture = NetnsTestFixture::new("outside");
        let allowed_root = fixture.allowed_root();

        // allowed_root と無関係な実在パス（任意ファイルへの誘導）。
        let outside = fixture.file_under(&fixture.base().join("outside"), "secret");
        let err = NetnsStatus::new(sample_container_id(), outside, &allowed_root)
            .expect_err("path outside allowed root must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        // 文字列の前方一致では通ってしまう紛らわしい兄弟ディレクトリ
        // （`root-evil` は `root` に前方一致するが配下ではない）。
        let lookalike_dir = {
            let mut dir = allowed_root.clone();
            dir.set_file_name("root-evil");
            dir
        };
        let lookalike = fixture.file_under(&lookalike_dir, "x");
        let err = NetnsStatus::new(sample_container_id(), lookalike, &allowed_root)
            .expect_err("string-prefix lookalike must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P0: `NetnsStatus::new` は `allowed_root` の symlink を
    /// 実際に解決し、`allowed_root` 配下にある symlink が外部を指す場合は拒否する
    /// （字句上の判定だけでは通ってしまう経路。symlink 解決検証が本体）。
    #[test]
    fn p0_netns_status_rejects_symlink_escaping_allowed_root() {
        let fixture = NetnsTestFixture::new("symlink");
        let allowed_root = fixture.allowed_root();

        let outside_dir = fixture.base().join("outside");
        let target = fixture.file_under(&outside_dir, "secret");

        let link = allowed_root.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).expect("create symlink");

        let err = NetnsStatus::new(sample_container_id(), link, &allowed_root)
            .expect_err("symlink escaping allowed_root must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P0: `NetnsStatus::new` は `allowed_root` 配下でも
    /// `..` コンポーネントを含む字句上のトラバーサルを拒否する（実在パスの有無に
    /// 関わらず、この字句チェックは canonicalize より先に走る）。
    #[test]
    fn p0_netns_status_rejects_parent_dir_traversal() {
        let allowed_root = nonexistent_allowed_root();

        #[cfg(unix)]
        let traversal = PathBuf::from("/run/netns/../../etc/passwd");
        #[cfg(windows)]
        let traversal = PathBuf::from(r"C:\netns\..\..\Windows\win.ini");
        let err = NetnsStatus::new(sample_container_id(), traversal, &allowed_root)
            .expect_err("parent-dir traversal must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P0: `allowed_root` 自体が絶対パスでなければ拒否する
    /// （呼び出し側の設定ミスを fail-closed で検出する。canonicalize の前に弾くため
    /// 実在パスは不要）。
    #[test]
    fn p0_netns_status_rejects_relative_allowed_root() {
        let allowed_root = PathBuf::from("netns");
        let err = NetnsStatus::new(
            sample_container_id(),
            PathBuf::from("/run/netns/x"),
            &allowed_root,
        )
        .expect_err("relative allowed root must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P0: `path` / `allowed_root` の実体が存在しない場合は
    /// canonicalize が失敗し `InvalidArgument` になる（存在確認なしに受理しない）。
    #[test]
    fn p0_netns_status_rejects_nonexistent_path() {
        let fixture = NetnsTestFixture::new("nonexistent");
        let allowed_root = fixture.allowed_root();
        let err = NetnsStatus::new(
            sample_container_id(),
            allowed_root.join("does-not-exist"),
            &allowed_root,
        )
        .expect_err("nonexistent path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// codex/review 指摘 P1: `CreateNetnsRequest` は所属先ネットワーク名を保持し、
    /// `network()` で参照できる（`delete_network` の追跡対象決定に使うため）。
    #[test]
    fn p1_create_netns_request_returns_network() {
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
}
