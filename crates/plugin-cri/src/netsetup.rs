//! `NetworkPlugin` の実装を PoC-15 netsetup の操作単位へ対応づけ、`fandhe-container-net` の統合 API
//! （TASK-139。`create_network`・`attach_container`・`delete_network`）へ委ねる層
//! （TASK-114.4・#460・MS-4・PLUG-1・CRI-2・CRI-7。ネットワーク側は NET-1〜NET-4・TASK-139・MS-8）。
//!
//! 呼び出し元: [`crate::adapter::CriPluginBackends::production`] が Linux のときだけ
//! [`NetsetupNetwork`]（`LinuxNetsetup` 付き）を `NetworkPlugin` として差す。Pod 単位の呼び出し順は
//! [`crate::pod_network`] が `NetworkPlugin` の呼び出しへ写す。呼び出し先は `fandhe-container-net` の公開 API だけで、
//! 本モジュールは `unsafe` を持たない。
//!
//! # 対応表（netsetup → メソッド → net の API）
//!
//! | netsetup | メソッド | net の API |
//! | -------- | -------- | ---------- |
//! | `net-create` | `create_network` | `network::create_network` と `StaticIpam::for_network` |
//! | `netns-create` | `create_netns` | `network::create_container_netns`（netns の作成と pin。#2675） |
//! | `veth-attach` | `attach` | `network::attach_prepared_container`（事前作成の netns へ接続） |
//! | `publish-port` | `publish_port` | `network::publish_container_ports`（attach 済みコンテナへ DNAT を追加。#2676）。投入ルールのハンドル（echo 応答。#2839）はネットワークのハンドルに保持する |
//! | （なし） | `unpublish_port` | `network::unpublish_container_port`（保持したハンドルで DNAT 2 件を個別に削除し、予約を戻す。#2839・NET-3） |
//! | （なし） | `detach` | 未 attach の記録の取り消しと事前作成 netns の解放（`network::release_container_netns`）、attach の取り残しの回収（`network::reclaim_failed_attach`）。attach 済みは `Unimplemented` |
//! | `net-delete` | `delete_network` | `network::delete_network` |
//!
//! # 契約との対応（`NetworkPlugin` の doc の契約番号）
//!
//! - 契約 6: カーネル資源の巻き戻しは net が行う。取り残しがあれば件数を `message` に載せた `Internal` を返し、
//!   ネットワークを回収待ちとして保持する。`delete_network` は net の `network::reclaim_failed_create`
//!   （名前の再導出と所有トークンの一致で証明した bridge・nft テーブルだけを消す。#2467）で回収し、成功したときだけ
//!   記録を外す
//! - 契約 7・8・12: 本モジュールのレジストリで判定する。`attach` は契約 12 を最初に判定し、続けて
//!   ネットワーク未作成、netns 未登録（いずれも `NotFound`）、紐付けネットワーク不一致（`FailedPrecondition`）の順
//! - 契約 9: `delete_network` は net が残りを続行する。失敗時は再試行用のハンドルをレジストリへ戻し、
//!   ネットワークを削除中として印を残す（完了まで `create_netns`・`attach` は `FailedPrecondition`。再試行の `delete_network` は可）。
//!   attach の巻き戻しで取り残したコンテナに請求書（net の `FailedAttachClaim`）があれば、bridge を解放する前に
//!   `reclaim_failed_attach`（別名と master の一致を確かめた veth と、請求書・永続の所有記録に一致する pin だけを消す）で回収し、
//!   成功したものから記録ファイルと記録を外す（`detach` も同じ回収をする。#2681）。請求書が無い・回収に失敗した取り残しは
//!   記録を保持して `delete_network` を拒否し、取り残しのあるネットワークへの `create_netns`・`attach` は
//!   `FailedPrecondition`
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - netns の作成時点（#2675）: `create_netns` は net の `create_container_netns` で netns を作って pin し、
//!   attach 前のハンドルをバックエンド（`LinuxNetsetup`）が保持する。`lo` は作成時点で up にする
//!   （失敗したら net が netns を unpin して回収する）。attach の失敗では veth・アドレスを戻すが
//!   netns は unpin せず保持し、`detach`・`delete_network` が解放する。バックエンドの `create_netns` が
//!   成功したときだけ契約 7・8 の記録を作る。作成途中の取り残した pin は件数入りの `Internal` で報告し、
//!   回収待ち（`unreclaimed`）の記録として保持する（`delete_network` は手動回収まで成功を返さない）
//! - コンテナがこの netns へ入る側（core の `linux.namespaces[].path` の受け入れ）は未実装で、本層の呼び出し元は
//!   cri の `PodNetworkProvider`（[`crate::pod_network::NetsetupPodNetwork`]）だけ。本番へは注入しない
//!   （`docs/design/cri-config-acceptance.md` の順 13）
//! - 作成失敗の回収（#2467）: 手動回収のまま残るのは、所有トークンを刻む前の失敗で残った bridge（請求書が無い、
//!   または別名が空で証明できない）、他者の同名資源が残っている場合、置き場に記録できなかった・壊れた記録の場合。
//!   いずれも記録を保持して `FailedPrecondition`（または件数入りの `Internal`）を返す。請求書は
//!   [`ReclaimStore`]（`<状態ルート>/.cri/net/pending-reclaim/<名前>.claim`）に永続化し、plugin の再起動後に
//!   読み込んで `delete_network` で回収する（#2604。`docs/design/network-reclaim-persistence.md`、手動の手順は
//!   `docs/setup/network-reclaim-recovery.md`）。置き場を差さない構成（`new`・`with_recorder`）はメモリだけ
//! - `publish_port`（#2676・NET-4）: attach 済みコンテナへ DNAT を追加する。ホスト側 bind IP（`host_ip`）は
//!   明示した IPv4 だけ受け、未指定・IPv6 は `Unimplemented`（全アドレスへの公開を黙って作らない）。契約 11 は
//!   全ネットワーク共通の `(host_port, protocol)` で本層が判定する（net の予約表はネットワークごとのため）。
//!   公開 1 件の個別解除は `NetworkPlugin::unpublish_port`（#2904・NET-3・契約 13。net の
//!   `unpublish_container_port`）で行う。CRI の経路で使うのは `set_up_sandbox` の公開途中の失敗の巻き戻しだけで、
//!   通常の `StopPodSandbox` / `RemovePodSandbox` は pod 専用ネットワークを `delete_network` で一括解放する。
//!   結果不明で記録した公開（ハンドルを持たない）は個別に解除できず `FailedPrecondition` で、`delete_network` が
//!   解放する。attach 済みコンテナの `detach`（共有ネットワークを使う CLI / stack）は後続事項。保持したハンドルは
//!   プロセスのメモリ上だけで、再起動後は `delete_network` の一括解放に頼る。他プロセスとの受け口の衝突は検出しない
//! - `detach`: net にコンテナ単体の切り離しが無いため、attach 済みは `Unimplemented`
//! - 静的アドレス（`AttachRequest::address`）: net の `attach_container` は内部で動的割り当てを行い、事前予約と
//!   併用できないため `Unimplemented`（契約 10。カーネル操作の前に判定する）
//! - attach の取り残しの回収（#2681）: 請求書は [`ReclaimStore`] の `attach/<endpoint>.attach` に永続化し、再起動後に
//!   読み込む。作成に成功したネットワークの記録（`CreatedNetwork`・IPAM）は永続化されていないため、再起動後は
//!   「attach の記録だけから復元したネットワーク」となり、回収できるのは veth（所有確認つき）だけで、bridge・nft テーブルは
//!   自動回収しない。netns の pin は、請求書の識別子と置き場の永続の所有記録（`.owned/<endpoint>`。#2824）に
//!   一致するものだけ再起動後も解除でき、照合できない pin（旧い請求書など）は手動回収に残る。
//!   復元したネットワークの `delete_network` は取り残しを回収し終えたら記録を外し、ネットワーク本体は手動回収と
//!   [`MSG_RECOVERED_NETWORK_UNTRACKED`] の `FailedPrecondition` で知らせる（成功を装わない）。壊れた記録はファイルを残して
//!   登録せず、同じコンテナの再 attach はカーネルの `AlreadyExists` で拒否される。write-ahead（作成・attach 前の記録）は
//!   採らない（#1870 の後に再検討。`docs/design/network-reclaim-persistence.md`）
//! - 状態（作成に成功したネットワーク・IPAM・pin・削除中の印）はプロセスのメモリにだけあり、plugin プロセスの
//!   再起動で失われる（永続化するのは作成失敗と attach の取り残しの回収待ちの記録だけ。残りは #1870 の設計の後続）
//! - DNS ヘルパーの起動・停止（NET-5・NET-7）は行わない
//! - ネットワーク名は net の規則（小文字のみ、`_`・`.` を許す）に合わせて検査するため、トレイトの規則では有効な
//!   大文字入りの名前は `InvalidArgument` になる。サブネットは IPv4 の `/1`〜`/30` のみ
//!
//! # 実行環境
//!
//! Linux のカーネル操作は `CAP_NET_ADMIN`（netlink）と `CAP_SYS_ADMIN`（netns の pin の bind mount）を要し、
//! 本 crate は権限を上げない。権限が無ければ `PermissionDenied` をそのまま返す（fail-closed）。netns の pin の置き場は
//! 状態ルート配下の固定の場所（`<状態ルート>/.netns`）で、要求の入力からは受けない。置き場は private な mount に
//! しておく前提で、`shared` は net が拒否する。

mod reclaim_store;

pub use reclaim_store::{LoadReport, RECLAIM_DIR, ReclaimStore, StoredClaim};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, MutexGuard};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::traits::{
    AttachRequest, AttachResponse, ContainerId, CreateNetnsRequest, CreateNetworkRequest,
    DeleteNetworkRequest, DeleteNetworkResponse, DetachRequest, DetachResponse, ErrorCode, IpCidr,
    NetnsName, NetnsStatus, NetworkName, NetworkPlugin, NetworkStatus, PortMapping, Protocol,
    PublishPortRequest, TraitError, UnpublishPortRequest, UnpublishPortResponse,
};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{
    EndpointId, MAX_PORT_PUBLISHES, NetworkName as NetName, PortProtocol, PortPublish,
};

/// 1 つの plugin プロセスが保持するネットワークの上限（信頼できない入力で状態が増え続けないようにする）。
pub const MAX_NETWORKS: usize = 128;
/// 1 つのネットワークが保持するコンテナの上限。
pub const MAX_CONTAINERS_PER_NETWORK: usize = 256;

/// `publish_port` にホスト側 bind IP が無いときの未実装文言（固定。入力を含めない）。
pub const MSG_PUBLISH_PORT_HOST_IP_REQUIRED: &str =
    "publish_port requires an explicit IPv4 host_ip: publishing on all addresses is not supported";
/// `publish_port` の IPv6 のホスト側 bind IP の未実装文言。
pub const MSG_PUBLISH_PORT_IPV6_UNSUPPORTED: &str =
    "publish_port supports IPv4 host_ip only: IPv6 publishing is not supported";
/// `publish_port` の SCTP 等の未対応プロトコルの文言。
pub const MSG_PUBLISH_PORT_PROTOCOL_UNSUPPORTED: &str = "publish_port supports tcp and udp only";
/// 結果不明で記録した公開は個別に解除できない（ハンドルを持たない）ことの文言。解放は `delete_network` だけ。
pub const MSG_UNPUBLISH_PORT_RESULT_UNKNOWN: &str =
    "published port has an unknown result and is released only by delete_network";
/// 記録に無い公開の個別解除の文言。
const MSG_UNPUBLISH_PORT_NOT_RECORDED: &str = "published port is not recorded";
/// attach 済みコンテナの切り離しの未実装文言。
pub const MSG_DETACH_UNAVAILABLE: &str =
    "detach of an attached container is not available yet: net has no per-container teardown";
/// 事前作成した netns が見つからないときの文言（Linux バックエンド。attach は `create_netns` を前提とする）。
pub const MSG_NETNS_NOT_PREPARED: &str = "netns was not prepared for the container";
/// 静的アドレスの未実装文言。
pub const MSG_STATIC_ADDRESS_UNAVAILABLE: &str =
    "static container addresses are not available yet: net allocates addresses at attach time";

/// net のエラーをトレイトのエラーへ写す（同名のコードはそのまま。net のメッセージは入力値を含まない）。
///
/// `ResourceExhausted` は `ErrorCode::ResourceExhausted` へ写す（#2609）。`DataLoss` は `ErrorCode` に
/// 対応が無いため `Internal` にし、元のコードを `message` の先頭へ残す。
pub fn net_error_to_trait(e: &NetError) -> TraitError {
    let code = match e.code() {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::Timeout => ErrorCode::Timeout,
        NetErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        NetErrorCode::NotFound => ErrorCode::NotFound,
        NetErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        NetErrorCode::DataLoss => {
            return TraitError::new(
                ErrorCode::Internal,
                format!("{}: {}", e.code().as_str(), e.message()),
            );
        }
        _ => ErrorCode::Internal,
    };
    TraitError::new(code, e.message())
}

/// 取り残しの件数を載せたエラー（契約 6・9 の fail-closed の表現。残存資源の詳細は入力値を含み得るため載せない）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn with_leftover(base: TraitError, leftover: usize) -> TraitError {
    if leftover == 0 {
        return base;
    }
    TraitError::new(
        // 取り残しがあるときは分類を問わず Internal にして、成功や前提違反と取り違えさせない。
        ErrorCode::Internal,
        format!(
            "{} ({}); {leftover} resource(s) left behind",
            base.message(),
            base.code().as_str()
        ),
    )
}

/// 公開・解除の要求値を検証して `PortPublish` にする（`publish_port` と `unpublish_port` で共通。バックエンドを
/// 呼ぶ前の検証）。ホスト側 bind IP は明示した IPv4 だけ受け、tcp / udp 以外は `Unimplemented`。
fn port_publish_from(
    host_ip: Option<IpAddr>,
    protocol: Protocol,
    host_port: u16,
    container_port: u16,
) -> Result<PortPublish, TraitError> {
    let host_ip = match host_ip {
        Some(IpAddr::V4(ip)) => ip,
        Some(IpAddr::V6(_)) => {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_PUBLISH_PORT_IPV6_UNSUPPORTED,
            ));
        }
        None => {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_PUBLISH_PORT_HOST_IP_REQUIRED,
            ));
        }
    };
    let protocol = match protocol {
        Protocol::Tcp => PortProtocol::Tcp,
        Protocol::Udp => PortProtocol::Udp,
        _ => {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_PUBLISH_PORT_PROTOCOL_UNSUPPORTED,
            ));
        }
    };
    PortPublish::new(protocol, host_ip, host_port, container_port)
        .map_err(|e| net_error_to_trait(&e))
}

/// トレイトのネットワーク名を net の名前へ変換する（違反は `InvalidArgument`）。
fn to_net_name(name: &NetworkName) -> Result<NetName, TraitError> {
    NetName::new(name.as_str()).map_err(|e| net_error_to_trait(&e))
}

/// コンテナ ID を net のエンドポイント ID へ変換する（違反は `InvalidArgument`）。
fn to_endpoint(container: &ContainerId) -> Result<EndpointId, TraitError> {
    EndpointId::new(container.as_str()).map_err(|e| net_error_to_trait(&e))
}

/// コンテナ ID から netns 名を導出する。
///
/// net の pin 先は `<netns_dir>/<エンドポイント ID>`（`ContainerAttachSpec::netns_path`）で、返す名前をその
/// ファイル名と一致させるため ID をそのまま使う（接頭辞・置換・切り詰めは対応を壊し衝突するため行わない）。
/// `NetnsName` が受けない文字（`.`・`_`）を含む ID は `InvalidArgument`（fail-closed）。
fn derive_netns_name(container: &ContainerId) -> Result<NetnsName, TraitError> {
    NetnsName::new(container.as_str())
}

/// サブネットから gateway（ネットワークアドレス + 1、prefix 長は同じ）を導出する。IPv4 の `/1`〜`/30` のみ。
fn gateway_for(subnet: IpCidr) -> Result<IpPrefix, TraitError> {
    let IpAddr::V4(network) = subnet.network_address() else {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "only IPv4 subnets are supported",
        ));
    };
    let len = subnet.prefix_len();
    if !(1..=30).contains(&len) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "subnet prefix length must be 1 to 30",
        ));
    }
    let gateway = Ipv4Addr::from(u32::from(network).saturating_add(1));
    IpPrefix::new(IpAddr::V4(gateway), len).map_err(|e| net_error_to_trait(&e))
}

/// attach 済みコンテナのハンドル（net の `AttachedContainer`）から、レジストリが引くための ID を取り出す口。
pub trait NetsetupContainer {
    /// エンドポイント ID（`ContainerId` と同じ文字列）。
    fn endpoint_id(&self) -> &str;
}

/// [`NetsetupBackend::publish_port`] の失敗。
#[derive(Debug)]
pub struct PublishFailure {
    /// 失敗の原因。
    pub error: TraitError,
    /// DNAT ルールが入っている可能性がある（結果不明）。真のとき受け口の記録を保持する。
    pub rules_unknown: bool,
}

/// [`NetsetupBackend::attach`] の成功結果。
#[derive(Debug)]
pub struct AttachOutcome<C> {
    /// attach 済みコンテナのハンドル（削除時に net へ返す）。
    pub container: C,
    /// 払い出されたアドレス。
    pub address: IpPrefix,
}

/// [`NetsetupBackend::attach`] の失敗。巻き戻しで取り残した資源の件数を握りつぶさず運ぶ（契約 6・SEC 後始末）。
#[derive(Debug)]
pub struct AttachFailure<A = ()> {
    /// 失敗の原因（取り残しがあれば件数入りの `Internal`）。
    pub error: TraitError,
    /// 巻き戻しで回収できずカーネルに残った資源の件数（0 なら回収済み）。
    pub leftover: usize,
    /// `create_netns` の失敗で、回収できなかった netns のハンドルをバックエンドが保持している印。
    /// 立っていればレジストリは記録を残し、`detach`・`delete_network` が `release_netns` で再試行する
    /// （ハンドルを捨てて回収不能にしない。#2675）。`create_netns` 以外では常に false。
    pub netns_retained: bool,
    /// 取り残しを所有確認つきで回収するための請求書（Linux は net の `FailedAttachClaim`）。
    /// 所有を証明できない取り残しでは `None`（手動回収。NET-1・#2681）。
    pub reclaim: Option<A>,
}

impl<A> From<TraitError> for AttachFailure<A> {
    /// 取り残しなしの失敗。
    fn from(error: TraitError) -> Self {
        Self {
            error,
            leftover: 0,
            netns_retained: false,
            reclaim: None,
        }
    }
}

/// [`NetsetupBackend::create_network`] の失敗。作成途中の取り残し・結果不明の資源の件数を握りつぶさず運ぶ
/// （契約 6・特権操作の後始末。レジストリが回収待ちとして保持し、上限に数える）。
#[derive(Debug)]
pub struct CreateFailure<F = ()> {
    /// 失敗の原因（取り残しがあれば件数入りの `Internal`）。
    pub error: TraitError,
    /// 巻き戻しで回収できず残った・結果不明で削除しなかった資源の件数（0 なら何も残らない）。
    pub leftover: usize,
    /// 取り残しを所有確認つきで回収するための請求書（Linux は net の `FailedCreateClaim`）。
    /// 所有を証明できない取り残しでは `None`（手動回収。#2467）。
    pub reclaim: Option<F>,
}

impl<F> From<TraitError> for CreateFailure<F> {
    /// 取り残しなしの失敗。
    fn from(error: TraitError) -> Self {
        Self {
            error,
            leftover: 0,
            reclaim: None,
        }
    }
}

/// [`NetsetupBackend::delete_network`] の失敗。解放を完了できなかったハンドルを手放さずに返す。
#[derive(Debug)]
pub struct DeleteFailure<C> {
    /// 失敗の原因。
    pub error: TraitError,
    /// 再試行に使うハンドル（これ以外は解放済み）。
    pub retry: Vec<C>,
}

/// カーネル操作の差し込み口。Linux では `LinuxNetsetup`（net の統合 API）、試験では fake を差す。
///
/// net の内部の差し替え口は crate 内限定のため、plugin-cri 側にこの口を置く（TASK-114.4）。
pub trait NetsetupBackend: Send + Sync {
    /// 作成済みネットワークのハンドル（net の `CreatedNetwork` と IPAM）。
    type Network: Send;
    /// attach 済みコンテナのハンドル。
    type Container: NetsetupContainer + Send;
    /// 作成失敗の回収に使う請求書（Linux は net の `FailedCreateClaim`。#2467）。回収待ちの記録が保持し、
    /// [`reclaim_failed_create`](Self::reclaim_failed_create) へそのまま返す。
    type FailedCreate: Send;
    /// attach の巻き戻しで取り残した資源の請求書（Linux は net の `FailedAttachClaim`。#2681）。
    /// コンテナの記録が保持し、[`reclaim_failed_attach`](Self::reclaim_failed_attach) へそのまま返す。
    type FailedAttach: Send;

    /// ネットワークを作る。失敗時の巻き戻しは実装が行う（契約 6）。
    fn create_network(
        &self,
        name: &NetName,
        gateway: IpPrefix,
    ) -> Result<Self::Network, CreateFailure<Self::FailedCreate>>;

    /// 作成失敗で取り残した（または結果不明の）資源を、所有を確認したうえで回収する。成功は回収の確認済み。
    ///
    /// `claim` は同じ作成の失敗が返した請求書。既定は回収せず `FailedPrecondition`（成功を装わない）。
    /// Linux バックエンドは net の `network::reclaim_failed_create` で、所有トークンの一致を確かめた
    /// bridge・nft テーブルだけを消す。所有を証明できない資源は残り、手動回収になる（REPAIR-3）。
    fn reclaim_failed_create(
        &self,
        _name: &NetName,
        _claim: &Self::FailedCreate,
    ) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "network creation left resources behind that cannot be reclaimed automatically; \
             manual reclaim required",
        ))
    }

    /// 請求書を永続化記録へ符号化する（plugin の再起動をまたいで回収するため。NET-1・#2604）。
    /// 既定は `None`（永続化しない。再起動で請求書を失い、手動回収になる）。
    fn encode_claim(&self, _claim: &Self::FailedCreate) -> Option<String> {
        None
    }

    /// [`encode_claim`](Self::encode_claim) の記録を請求書へ復号する。記録は信頼しない入力として検証し、
    /// 不正なら `InvalidArgument`。ネットワーク名が記録と食い違う場合も拒否する。既定は復号しない
    /// （`FailedPrecondition`）。
    fn decode_claim(
        &self,
        _name: &NetName,
        _record: &str,
    ) -> Result<Self::FailedCreate, TraitError> {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "reclaim records are not supported by this backend",
        ))
    }

    /// attach の取り残しの請求書を永続化記録へ符号化する（plugin の再起動をまたいで回収するため。NET-1・#2681）。
    /// 既定は `None`（永続化しない。再起動で請求書を失い、手動回収になる）。
    fn encode_attach_claim(&self, _claim: &Self::FailedAttach) -> Option<String> {
        None
    }

    /// [`encode_attach_claim`](Self::encode_attach_claim) の記録を、属するネットワーク名と請求書へ復号する。
    /// 記録は信頼しない入力として検証し、不正なら `InvalidArgument`。endpoint が記録と食い違う場合も拒否する。
    /// 既定は復号しない（`FailedPrecondition`）。
    fn decode_attach_claim(
        &self,
        _endpoint: &EndpointId,
        _record: &str,
    ) -> Result<(NetName, Self::FailedAttach), TraitError> {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "attach reclaim records are not supported by this backend",
        ))
    }

    /// attach の巻き戻しで取り残した資源を、所有を確認したうえで回収する。成功は回収の確認済み。
    ///
    /// 既定は回収せず `FailedPrecondition`（成功を装わない）。Linux バックエンドは net の
    /// `network::reclaim_failed_attach` で、別名と master の一致を確かめた veth と、請求書・永続の所有記録に一致する pin だけを消す。
    /// 所有を証明できない資源は残り、手動回収になる（REPAIR-3）。
    fn reclaim_failed_attach(&self, _claim: &Self::FailedAttach) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "attach left resources behind that cannot be reclaimed automatically; \
             manual reclaim required",
        ))
    }

    /// 取り残しの請求書がプロセス内の保持（IPAM のアドレス・DNAT ルール・ポート予約。quarantine）を含むとき、
    /// カーネル側の資源（veth・netns の pin）を除いた残りの請求書を返す。含まなければ `None`（既定）。
    ///
    /// quarantine は `reclaim_failed_attach` では解放されず、`delete_network` がネットワークごと解放する。
    /// カーネル側の回収が済んでも quarantine が残る間は、detach を成功させず登録を保持して、同じ endpoint の
    /// 再 attach がアドレスの二重払い出し（`AlreadyExists`）で失敗するのを防ぐ（NET-1・#2681）。
    fn attach_claim_quarantine_remainder(
        &self,
        _claim: &Self::FailedAttach,
    ) -> Option<Self::FailedAttach> {
        None
    }

    /// コンテナ専用の netns を作る。既定は何もしない成功（カーネル資源を作らない試験用 fake 向け）。
    ///
    /// Linux バックエンドは net の `create_container_netns` で作って pin し、ハンドルを `attach` まで保持する
    /// （#2675）。実体を作れないバックエンドは、成功を装わず `Unimplemented` を返すこと（契約 3・REPAIR-3）。
    fn create_netns(
        &self,
        _network: &mut Self::Network,
        _endpoint: &EndpointId,
    ) -> Result<(), AttachFailure> {
        Ok(())
    }

    /// 未 attach のまま不要になった netns を解放する（`detach`・`delete_network` が呼ぶ。#2675）。
    ///
    /// 冪等で、`create_netns` が資源を保持していなければ成功する（既定）。失敗時は資源を保持したまま
    /// エラーを返し、呼び出し側は記録を残して再試行できる。
    fn release_netns(&self, _endpoint: &EndpointId) -> Result<(), TraitError> {
        Ok(())
    }

    /// コンテナを接続する。失敗時の巻き戻しは実装が行う（契約 6）。
    fn attach(
        &self,
        network: &mut Self::Network,
        endpoint: &EndpointId,
    ) -> Result<AttachOutcome<Self::Container>, AttachFailure<Self::FailedAttach>>;

    /// attach 済みコンテナへ DNAT で受け口を 1 件公開する（NET-4・#2676）。既定は `Unimplemented`
    /// （未対応のバックエンドが成功を装わないため）。
    ///
    /// 結果が不明（DNAT ルールが入っている可能性がある）なら `rules_unknown` を立てて返す。呼び出し側は
    /// 契約 11 の記録を保持し、解放は `delete_network` に任せる。
    fn publish_port(
        &self,
        _network: &mut Self::Network,
        _container: &Self::Container,
        _publish: &PortPublish,
    ) -> Result<(), PublishFailure> {
        Err(PublishFailure {
            error: TraitError::new(
                ErrorCode::Unimplemented,
                "publish_port is not supported by this backend",
            ),
            rules_unknown: false,
        })
    }

    /// 公開済みの受け口 1 件を個別に解除する（DNAT ルールの削除と受け口の予約の解放。NET-3・#2839）。
    /// 既定は `Unimplemented`（未対応のバックエンドが成功を装わないため）。
    ///
    /// 結果が不明なら `rules_unknown` を立てて返す。呼び出し側は受け口の記録を保持し、解放は `delete_network` に
    /// 任せる（`publish_port` と同じ）。`NetworkPlugin::unpublish_port`（#2904）の実装が呼ぶ。
    fn unpublish_port(
        &self,
        _network: &mut Self::Network,
        _container: &Self::Container,
        _publish: &PortPublish,
    ) -> Result<(), PublishFailure> {
        Err(PublishFailure {
            error: TraitError::new(
                ErrorCode::Unimplemented,
                "unpublish_port is not supported by this backend",
            ),
            rules_unknown: false,
        })
    }

    /// ネットワークと、渡した attach 済みコンテナを解放する（契約 9）。
    fn delete_network(
        &self,
        network: &mut Self::Network,
        containers: Vec<Self::Container>,
    ) -> Result<(), DeleteFailure<Self::Container>>;
}

/// `create_netns` で登録されたコンテナ 1 件の記録。
struct ContainerEntry<C, A> {
    /// 紐付けたネットワーク名（`CreateNetnsRequest::network`）。
    network: String,
    endpoint: EndpointId,
    /// attach 済みならハンドル（未 attach ならカーネル資源は無い）。
    attached: Option<C>,
    /// attach の巻き戻しで資源を取り残した印。立っている間は記録を消さず、attach・ネットワーク削除を
    /// fail-closed で拒否する。`claim` があれば detach・`delete_network` が所有確認つきで回収し、成功したときだけ
    /// 印と記録を外す（#2681）。作成失敗の回収（#2467）とは別。
    unreclaimed: bool,
    /// `create_netns` が `lo` の up に失敗して unpin もできず、バックエンドが netns を保持している印。
    /// attach は拒否し、`detach`・`delete_network` が `release_netns` で回収する（#2675）。
    netns_retained: bool,
    /// カーネル側の資源の回収は済んだが、プロセス内の保持（quarantine）が生きたネットワークに残っている印。
    /// `unreclaimed` と併せて立ち、detach では外さず（`delete_network` がネットワークごと解放する）、
    /// `delete_network` の回収待ちの数には含めない（#2681）。
    quarantine_held: bool,
    /// 取り残しを所有確認つきで回収するための請求書。`None` は所有を証明できない取り残しで、手動回収。
    claim: Option<A>,
    /// このコンテナが公開した受け口（契約 11 の判定キー。結果不明の公開を含む）。コンテナの記録と一緒に消える
    /// （`delete_network` の成功で記録ごと外れ、受け口は再公開できる）。件数は `MAX_PORT_PUBLISHES` で有界。
    published: Vec<(u16, Protocol)>,
    /// `published` のうち、結果不明（DNAT ルールが入っている可能性がある）で記録したもの。ハンドルを持たない
    /// ため `unpublish_port` では解除できず、`delete_network` だけが解放する（NET-3・#2904）。
    /// 件数は `MAX_PORT_PUBLISHES` で有界。
    unknown_published: Vec<(u16, Protocol)>,
}

/// 作成済みネットワーク 1 件の記録。
struct NetworkEntry<N, F> {
    /// 削除を始めたら立てる。完了（記録の除去）まで下ろさず、その間の新規登録・接続を拒否する（契約 9）。
    deleting: bool,
    /// バックエンドでのネットワーク解放が完了した印。取り残しの記録だけが残って再試行されるとき、
    /// 解放済みのネットワークへ二重に解放を要求しないために使う。
    backend_deleted: bool,
    /// 作成に成功したネットワークの gateway。回収待ちの記録（再起動後に読み込んだものを含む）では持たない。
    gateway: Option<IpPrefix>,
    /// 作成に成功したときのハンドル。作成失敗で取り残した回収待ちの記録（`leaked` が `Some`）では無い。
    handle: Option<N>,
    /// 作成失敗で取り残した・結果不明の資源の件数。`Some` の間は回収待ちとして上限に数え、
    /// 接続系の操作を拒否し、`delete_network` で回収を再試行する（回収確認まで記録を保持する）。
    leaked: Option<LeakedCreate<F>>,
    /// plugin の再起動後に、attach の取り残しの記録だけから復元したネットワーク（#2681）。作成に成功した
    /// ネットワークの記録（`CreatedNetwork`・IPAM）は永続化されていない（#1870）ため `handle` は無く、bridge・nft
    /// テーブルは自動回収しない。取り残した veth・pin の回収に使い、回収し終えたら外す。
    recovered: bool,
    /// delete_network の部分失敗でコンテナの記録を外したあとも、専用 nft テーブル（DNAT）が残りうる受け口。
    /// テーブルの削除を確認してネットワークの記録ごと外れるまで契約 11 の衝突判定に使う（fail-closed）。
    orphan_published: Vec<(u16, Protocol)>,
}

/// 作成失敗で取り残した資源の回収待ちの記録。
struct LeakedCreate<F> {
    /// 所有確認つきの回収に使う請求書。`None` は所有を証明できない取り残しで、手動回収。
    claim: Option<F>,
}

struct Registry<N, C, F, A> {
    networks: HashMap<String, NetworkEntry<N, F>>,
    /// コンテナ ID（文字列）→ 記録。同じコンテナはネットワークを問わず 1 件だけ（契約 7・8）。
    containers: HashMap<String, ContainerEntry<C, A>>,
}

/// バックエンド `B` のハンドル型で具体化したレジストリ。
type BackendRegistry<B> = Registry<
    <B as NetsetupBackend>::Network,
    <B as NetsetupBackend>::Container,
    <B as NetsetupBackend>::FailedCreate,
    <B as NetsetupBackend>::FailedAttach,
>;

/// `NetworkPlugin` を netsetup の操作単位で実装する（CRI-7・PLUG-1）。
///
/// 状態は 1 つの `Mutex` に持ち、メソッドごとに直列化する（netlink の要求は期限つきで短いため許容。REPAIR-5）。
/// ロックの poisoning は panic させず `Internal` を返す。
pub struct NetsetupNetwork<B: NetsetupBackend> {
    backend: B,
    state: Mutex<BackendRegistry<B>>,
    /// 公開操作（入力拒否を含む）の成功・失敗件数とレイテンシの記録先（REPAIR-4）。
    recorder: Option<Arc<OpRecorder>>,
    /// 回収待ちの記録の置き場。`None` ではメモリだけで保持し、再起動で失う。
    store: Option<ReclaimStore>,
}

impl<B: NetsetupBackend> std::fmt::Debug for NetsetupNetwork<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetsetupNetwork").finish_non_exhaustive()
    }
}

impl<B: NetsetupBackend> NetsetupNetwork<B> {
    /// バックエンドを差して空のレジストリで始める。
    pub fn new(backend: B) -> Self {
        Self::build(backend, None)
    }

    /// 共有の記録器を差して作る。各公開操作の結果（入力拒否を含む）を `net.<操作名>` で記録する（REPAIR-4）。
    pub fn with_recorder(backend: B, recorder: Arc<OpRecorder>) -> Self {
        Self::build(backend, Some(recorder))
    }

    /// 回収待ちの記録の置き場を差して作る。置き場の記録を読み込み、作成失敗の回収待ちとして登録する
    /// （plugin の再起動後に `delete_network` で回収できる。NET-1・REPAIR-3・#2604）。
    ///
    /// 復号できない記録（壊れた・名前が食い違う）はファイルを残したまま、請求書なしの回収待ち（手動回収）として
    /// 登録し、同じ名前の再作成を防ぐ。件数は記録器の `net.reclaim_store_load` の失敗件数と固定語彙の
    /// stderr 1 行で出す（ファイル名・トークンは出さない。REPAIR-4）。読み込み自体の失敗は fail-closed で返す。
    pub fn with_reclaim_store(
        backend: B,
        store: ReclaimStore,
        recorder: Option<Arc<OpRecorder>>,
    ) -> Result<Self, TraitError> {
        let report = store.load()?;
        let mut networks = HashMap::new();
        let mut broken = report.unrecognized;
        for stored in report.claims {
            let claim = NetName::new(&stored.name)
                .ok()
                .zip(stored.record.as_deref())
                .and_then(|(n, rec)| backend.decode_claim(&n, rec).ok());
            if claim.is_none() {
                broken = broken.saturating_add(1);
            }
            networks.insert(
                stored.name,
                NetworkEntry {
                    deleting: false,
                    backend_deleted: false,
                    gateway: None,
                    handle: None,
                    leaked: Some(LeakedCreate { claim }),
                    recovered: false,
                    orphan_published: Vec::new(),
                },
            );
        }
        // attach の取り残しの記録。ネットワークの記録が無ければ「復元したネットワーク」として作る（#2681）。
        // 件数の上限を超える場合は fail-closed で起動を失敗させる（記録を捨てて資源を忘れない）。
        let mut containers: HashMap<String, ContainerEntry<B::Container, B::FailedAttach>> =
            HashMap::new();
        for stored in report.attach_claims {
            let decoded = EndpointId::new(&stored.name)
                .ok()
                .zip(stored.record.as_deref())
                .and_then(|(ep, rec)| backend.decode_attach_claim(&ep, rec).ok().map(|d| (ep, d)));
            let Some((endpoint, (net_name, claim))) = decoded else {
                broken = broken.saturating_add(1);
                continue;
            };
            let key = net_name.as_str().to_owned();
            if !networks.contains_key(&key) {
                if networks.len() >= MAX_NETWORKS {
                    return Err(TraitError::new(
                        ErrorCode::ResourceExhausted,
                        "reclaim store holds too many networks",
                    ));
                }
                networks.insert(
                    key.clone(),
                    NetworkEntry {
                        deleting: false,
                        backend_deleted: false,
                        gateway: None,
                        handle: None,
                        leaked: None,
                        recovered: true,
                        orphan_published: Vec::new(),
                    },
                );
            }
            if containers.values().filter(|c| c.network == key).count()
                >= MAX_CONTAINERS_PER_NETWORK
            {
                return Err(TraitError::new(
                    ErrorCode::ResourceExhausted,
                    "reclaim store holds too many containers for a network",
                ));
            }
            containers.insert(
                stored.name,
                ContainerEntry {
                    network: key,
                    endpoint,
                    attached: None,
                    unreclaimed: true,
                    quarantine_held: false,
                    claim: Some(claim),
                    // 再起動前のハンドルはプロセスと一緒に失われている（pin は手動回収。#2675）。
                    netns_retained: false,
                    published: Vec::new(),
                    unknown_published: Vec::new(),
                },
            );
        }
        broken = broken.saturating_add(report.attach_unrecognized);
        if let (Some(r), Ok(op)) = (&recorder, OpName::new("net.reclaim_store_load")) {
            for _ in 0..broken {
                r.start(op.clone()).failure();
            }
        }
        if broken > 0 {
            eprintln!("fandhe-container-plugin-cri: {broken} unusable pending-reclaim record(s)");
        }
        Ok(Self {
            backend,
            state: Mutex::new(Registry {
                networks,
                containers,
            }),
            recorder,
            store: Some(store),
        })
    }

    fn build(backend: B, recorder: Option<Arc<OpRecorder>>) -> Self {
        Self {
            backend,
            state: Mutex::new(Registry {
                networks: HashMap::new(),
                containers: HashMap::new(),
            }),
            recorder,
            store: None,
        }
    }

    /// 記録器があれば `name` で計測して実行する。操作名が不正なら計測せず実行だけする。
    fn timed<T>(
        &self,
        name: &str,
        f: impl FnOnce() -> Result<T, TraitError>,
    ) -> Result<T, TraitError> {
        match (&self.recorder, OpName::new(name)) {
            (Some(r), Ok(n)) => r.record_op(&n, f),
            _ => f(),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, BackendRegistry<B>>, TraitError> {
        self.state
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "network state is poisoned"))
    }
}

fn not_found_network() -> TraitError {
    TraitError::new(ErrorCode::NotFound, "network does not exist")
}

fn not_found_netns() -> TraitError {
    TraitError::new(
        ErrorCode::NotFound,
        "netns does not exist for the container",
    )
}

/// 取り残しがある間はネットワーク削除を拒否する失敗（契約 9。bridge による所有証明を保つ）。
fn delete_blocked_by_unreclaimed() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "network has containers with unreclaimed resources from a failed attach; \
         the network is kept so they stay provably owned; manual reclaim required",
    )
}

/// ネットワーク削除でほかの資源は解放したが、取り残しの記録が残るときの失敗（契約 9）。
fn delete_incomplete(count: usize) -> TraitError {
    TraitError::new(
        ErrorCode::Internal,
        format!(
            "network resources were released except {count} container(s) with unreclaimed resources; manual reclaim required"
        ),
    )
}

/// 保持中の netns の解放が済んでいないコンテナへの操作の拒否（#2675）。
fn netns_pending_release() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container netns is pending release after a failed create; detach it first",
    )
}

/// attach の巻き戻しで取り残した資源が残っているコンテナへの操作の拒否（記録を消して成功を装わない）。
fn quarantine_held() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container resources were reclaimed but its address and port reservations are released only when the network is deleted; the container stays registered",
    )
}

fn unreclaimed() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container has unreclaimed network resources from a failed attach; manual reclaim required",
    )
}

/// plugin の再起動後に attach の取り残しの記録だけから復元したネットワークへの操作の拒否・回収後の削除の応答
/// （ネットワーク本体の記録は永続化されておらず、bridge・nft テーブルは手動回収。#1870・#2681）。
pub const MSG_RECOVERED_NETWORK_UNTRACKED: &str = "attach leftovers were reclaimed; the network itself was not tracked across the plugin restart and needs manual reclaim";

fn recovered_network() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        MSG_RECOVERED_NETWORK_UNTRACKED,
    )
}

/// 取り残しの記録を永続化できなかった失敗（メモリの記録は保持している）。元のエラーを残して件を足す。
fn with_persist_failure(e: TraitError) -> TraitError {
    TraitError::new(
        ErrorCode::Internal,
        format!(
            "{} ({}); the reclaim record could not be persisted",
            e.message(),
            e.code().as_str()
        ),
    )
}

/// 作成失敗で取り残した資源の回収待ちのネットワークへの操作の拒否（`delete_network` で回収を再試行する）。
fn leaked_network() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "network creation failed and left resources behind; retry delete_network to reclaim them",
    )
}

/// 所有を証明できない取り残し（トークンを刻む前の失敗等）の回収の拒否。記録は保持する。
fn manual_reclaim_required() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "network creation left resources behind that cannot be reclaimed automatically; \
         manual reclaim required",
    )
}

fn network_deleting() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "network deletion is in progress or incomplete; retry delete_network",
    )
}

fn not_attached() -> TraitError {
    TraitError::new(ErrorCode::NotFound, "container is not attached")
}

fn network_mismatch() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container netns belongs to a different network",
    )
}

impl<B: NetsetupBackend> NetsetupNetwork<B> {
    fn create_network_impl(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
        let name = to_net_name(req.name())?;
        let gateway = gateway_for(req.subnet())?;
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        if reg.networks.contains_key(req.name().as_str()) {
            return Err(TraitError::new(
                ErrorCode::AlreadyExists,
                "network already exists",
            ));
        }
        if reg.networks.len() >= MAX_NETWORKS {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "network limit reached",
            ));
        }
        let (handle, leaked, mut result) = match self.backend.create_network(&name, gateway) {
            Ok(h) => (Some(h), None, Ok(())),
            Err(f) if f.leftover > 0 => {
                (None, Some(LeakedCreate { claim: f.reclaim }), Err(f.error))
            }
            Err(f) => return Err(f.error),
        };
        // 回収待ちは再起動をまたいで残す。書けなくてもメモリの記録は保持し、成功を装わず失敗を足す（NET-1・#2604）。
        if let (Some(store), Some(claim)) = (
            &self.store,
            leaked
                .as_ref()
                .and_then(|l: &LeakedCreate<_>| l.claim.as_ref()),
        ) && let Some(record) = self.backend.encode_claim(claim)
            && store.save(req.name().as_str(), &record).is_err()
            && let Err(e) = &result
        {
            result = Err(TraitError::new(
                ErrorCode::Internal,
                format!(
                    "{} ({}); the reclaim record could not be persisted",
                    e.message(),
                    e.code().as_str()
                ),
            ));
        }
        // 取り残し・結果不明は回収を確認できるまで記録を保持し、MAX_NETWORKS に数える。
        reg.networks.insert(
            req.name().as_str().to_owned(),
            NetworkEntry {
                deleting: false,
                backend_deleted: false,
                gateway: handle.as_ref().map(|_| gateway),
                handle,
                leaked,
                recovered: false,
                orphan_published: Vec::new(),
            },
        );
        result?;
        Ok(NetworkStatus::new(req.name().clone(), req.subnet()))
    }

    fn create_netns_impl(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
        let endpoint = to_endpoint(req.container())?;
        let netns = derive_netns_name(req.container())?;
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        match reg.networks.get(req.network().as_str()) {
            None => return Err(not_found_network()),
            Some(n) if n.leaked.is_some() => return Err(leaked_network()),
            Some(n) if n.recovered => return Err(recovered_network()),
            Some(n) if n.deleting => return Err(network_deleting()),
            Some(_) => {}
        }
        // 取り残しのあるネットワークへは資源を増やさない（回収できない資源が増え続けるのを防ぐ）。
        if network_has_unreclaimed(&reg.containers, req.network().as_str()) {
            return Err(unreclaimed());
        }
        if reg.containers.contains_key(req.container().as_str()) {
            return Err(TraitError::new(
                ErrorCode::AlreadyExists,
                "netns already exists for the container",
            ));
        }
        let in_network = reg
            .containers
            .values()
            .filter(|c| c.network == req.network().as_str())
            .count();
        if in_network >= MAX_CONTAINERS_PER_NETWORK {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container limit reached for the network",
            ));
        }
        let handle = reg
            .networks
            .get_mut(req.network().as_str())
            .and_then(|n| n.handle.as_mut())
            .ok_or_else(not_found_network)?;
        if let Err(f) = self.backend.create_netns(handle, &endpoint) {
            if f.leftover > 0 || f.netns_retained {
                // 取り残した pin を追跡から落とさない（契約 6・9。#2675）。バックエンドがハンドルを保持して
                // いれば `release_netns` で回収できる記録として、保持していなければ手動回収待ち
                // （unreclaimed）の記録として残す。
                reg.containers.insert(
                    req.container().as_str().to_owned(),
                    ContainerEntry {
                        network: req.network().as_str().to_owned(),
                        endpoint,
                        attached: None,
                        unreclaimed: !f.netns_retained,
                        netns_retained: f.netns_retained,
                        // create_netns の取り残しは net の請求書の対象外（attach の取り残しだけ。#2681）。
                        quarantine_held: false,
                        claim: None,
                        published: Vec::new(),
                        unknown_published: Vec::new(),
                    },
                );
            }
            return Err(f.error);
        }
        reg.containers.insert(
            req.container().as_str().to_owned(),
            ContainerEntry {
                network: req.network().as_str().to_owned(),
                endpoint,
                attached: None,
                unreclaimed: false,
                netns_retained: false,
                quarantine_held: false,
                claim: None,
                published: Vec::new(),
                unknown_published: Vec::new(),
            },
        );
        Ok(NetnsStatus::new(req.container().clone(), netns))
    }

    fn attach_impl(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError> {
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        // 契約 12: attach 済みなら対象ネットワークを問わず最初に AlreadyExists。
        if reg
            .containers
            .get(req.container().as_str())
            .is_some_and(|c| c.attached.is_some())
        {
            return Err(TraitError::new(
                ErrorCode::AlreadyExists,
                "container is already attached",
            ));
        }
        // 契約 8: ネットワーク未作成 → netns 未登録 → 紐付けネットワーク不一致。
        if reg
            .containers
            .get(req.container().as_str())
            .is_some_and(|c| c.unreclaimed)
        {
            return Err(unreclaimed());
        }
        let network = reg
            .networks
            .get_mut(req.network().as_str())
            .ok_or_else(not_found_network)?;
        if network.leaked.is_some() {
            return Err(leaked_network());
        }
        if network.recovered {
            return Err(recovered_network());
        }
        if network.deleting {
            return Err(network_deleting());
        }
        if network_has_unreclaimed(&reg.containers, req.network().as_str()) {
            return Err(unreclaimed());
        }
        let container = reg
            .containers
            .get_mut(req.container().as_str())
            .ok_or_else(not_found_netns)?;
        if container.network != req.network().as_str() {
            return Err(network_mismatch());
        }
        if req.address().is_some() {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_STATIC_ADDRESS_UNAVAILABLE,
            ));
        }
        if container.netns_retained {
            return Err(netns_pending_release());
        }
        let handle = network.handle.as_mut().ok_or_else(leaked_network)?;
        let outcome = match self.backend.attach(handle, &container.endpoint) {
            Ok(o) => o,
            Err(f) => {
                if f.leftover == 0 {
                    return Err(f.error);
                }
                container.unreclaimed = true;
                // veth・ポートの取り残しと別に、バックエンドが準備済み netns を保持していれば、
                // detach・delete_network が取り残しの回収待ちでも `release_netns` に届くよう印を持つ（#2675）。
                container.netns_retained = f.netns_retained;
                container.claim = f.reclaim;
                // 取り残しの記録は再起動をまたいで残す。書けなくてもメモリの記録は保持し、成功を装わず失敗を足す
                // （NET-1・#2681）。
                let persisted = match (&self.store, container.claim.as_ref()) {
                    (Some(store), Some(claim)) => self
                        .backend
                        .encode_attach_claim(claim)
                        .map(|rec| store.save_attach(container.endpoint.as_str(), &rec)),
                    _ => None,
                };
                return Err(if matches!(persisted, Some(Err(_))) {
                    with_persist_failure(f.error)
                } else {
                    f.error
                });
            }
        };
        let address = IpCidr::new(outcome.address.addr(), outcome.address.prefix_len())?;
        container.attached = Some(outcome.container);
        Ok(AttachResponse::new(
            req.network().clone(),
            req.container().clone(),
            address,
            network.gateway.map(|g| g.addr()),
        ))
    }

    fn publish_port_impl(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
        // 入力の検証（バックエンドを呼ぶ前）。
        let publish = port_publish_from(
            req.host_ip(),
            req.protocol(),
            req.host_port().get(),
            req.container_port().get(),
        )?;
        let host_ip = publish.host_addr();

        let mut guard = self.lock()?;
        let reg = &mut *guard;
        let orphan_key = (req.host_port().get(), req.protocol());
        let orphan_conflict = reg
            .networks
            .values()
            .any(|n| n.orphan_published.contains(&orphan_key));
        let network = reg
            .networks
            .get_mut(req.network().as_str())
            .ok_or_else(not_found_network)?;
        if network.leaked.is_some() {
            return Err(leaked_network());
        }
        if network.recovered {
            return Err(recovered_network());
        }
        if network.deleting {
            return Err(network_deleting());
        }
        let container = reg
            .containers
            .get(req.container().as_str())
            .ok_or_else(not_found_netns)?;
        if container.unreclaimed {
            return Err(unreclaimed());
        }
        if container.attached.is_none() {
            return Err(not_attached());
        }
        if container.network != req.network().as_str() {
            return Err(network_mismatch());
        }
        // 契約 11: 全ネットワーク・全コンテナで `(host_port, protocol)` の重複を拒否する。
        let key = (req.host_port().get(), req.protocol());
        if orphan_conflict || reg.containers.values().any(|c| c.published.contains(&key)) {
            return Err(TraitError::new(
                ErrorCode::AlreadyExists,
                "host port is already published",
            ));
        }
        if container.published.len() >= MAX_PORT_PUBLISHES {
            return Err(TraitError::new(
                ErrorCode::ResourceExhausted,
                "too many published ports for the container",
            ));
        }
        let handle = network.handle.as_mut().ok_or_else(leaked_network)?;
        let attached = container.attached.as_ref().ok_or_else(not_attached)?;
        let result = self.backend.publish_port(handle, attached, &publish);
        let record = |reg: &mut BackendRegistry<B>| {
            if let Some(c) = reg.containers.get_mut(req.container().as_str()) {
                c.published.push(key);
            }
        };
        match result {
            Ok(()) => {
                record(reg);
                Ok(PortMapping::new(
                    req.network().clone(),
                    req.container().clone(),
                    req.host_port(),
                    req.container_port(),
                    req.protocol(),
                )
                .with_host_ip(IpAddr::V4(host_ip)))
            }
            Err(f) if f.rules_unknown => {
                // DNAT ルールが残っている可能性がある。受け口の記録を保持し（別のコンテナへ同じ受け口を
                // 渡さない）、解放は delete_network に任せる。残りの件数を載せて成功を装わない。
                // ハンドルを持たないため、個別解除（unpublish_port）の対象外として印を付ける（#2904）。
                record(reg);
                if let Some(c) = reg.containers.get_mut(req.container().as_str()) {
                    c.unknown_published.push(key);
                }
                Err(with_leftover(f.error, 1))
            }
            Err(f) => Err(f.error),
        }
    }

    /// 公開 1 件の個別解除（NET-3・CRI-2・#2904）。前提の判定順は契約 13。記録を外すのはバックエンドの
    /// 解除が成功したときだけで、確定的な失敗・結果不明のどちらでも記録を保持する（fail-closed）。
    fn unpublish_port_impl(
        &self,
        req: &UnpublishPortRequest,
    ) -> Result<UnpublishPortResponse, TraitError> {
        // 入力の検証（バックエンドを呼ぶ前）。
        let publish = port_publish_from(
            req.host_ip(),
            req.protocol(),
            req.host_port().get(),
            req.container_port().get(),
        )?;

        let mut guard = self.lock()?;
        let reg = &mut *guard;
        let network = reg
            .networks
            .get_mut(req.network().as_str())
            .ok_or_else(not_found_network)?;
        if network.leaked.is_some() {
            return Err(leaked_network());
        }
        if network.recovered {
            return Err(recovered_network());
        }
        if network.deleting {
            return Err(network_deleting());
        }
        let container = reg
            .containers
            .get(req.container().as_str())
            .ok_or_else(not_found_netns)?;
        if container.unreclaimed {
            return Err(unreclaimed());
        }
        if container.attached.is_none() {
            return Err(not_attached());
        }
        if container.network != req.network().as_str() {
            return Err(network_mismatch());
        }
        let key = (req.host_port().get(), req.protocol());
        if !container.published.contains(&key) {
            return Err(TraitError::new(
                ErrorCode::NotFound,
                MSG_UNPUBLISH_PORT_NOT_RECORDED,
            ));
        }
        if container.unknown_published.contains(&key) {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                MSG_UNPUBLISH_PORT_RESULT_UNKNOWN,
            ));
        }
        let handle = network.handle.as_mut().ok_or_else(leaked_network)?;
        let attached = container.attached.as_ref().ok_or_else(not_attached)?;
        match self.backend.unpublish_port(handle, attached, &publish) {
            Ok(()) => {
                if let Some(c) = reg.containers.get_mut(req.container().as_str())
                    && let Some(pos) = c.published.iter().position(|k| *k == key)
                {
                    c.published.remove(pos);
                }
                Ok(UnpublishPortResponse::new())
            }
            // 結果不明: 記録（受け口の予約）を保持し、解放は delete_network に任せる。
            Err(f) if f.rules_unknown => Err(with_leftover(f.error, 1)),
            // 確定的な失敗（ルールが残っている・予約の解放に失敗・未対応等）: 記録を保持して再試行できる。
            Err(f) => Err(f.error),
        }
    }

    fn detach_impl(&self, req: &DetachRequest) -> Result<DetachResponse, TraitError> {
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        if !reg.networks.contains_key(req.network().as_str()) {
            return Err(not_found_network());
        }
        let container = reg
            .containers
            .get_mut(req.container().as_str())
            .ok_or_else(not_found_netns)?;
        if container.network != req.network().as_str() {
            return Err(network_mismatch());
        }
        if container.unreclaimed {
            // 取り残しの回収待ちでも、保持中の netns（pin・fd）は先に解放する。解放に失敗したら
            // その旨のエラーを返し、成功すれば印を外して取り残しの拒否を返す（#2675）。
            if container.netns_retained {
                self.backend.release_netns(&container.endpoint)?;
                container.netns_retained = false;
            }
            // 請求書があれば所有を確認して回収する。成功したときだけ記録を外す（#2681）。無ければ手動回収。
            if container.claim.is_none() {
                return Err(unreclaimed());
            }
            let live = quarantine_live(reg.networks.get(req.network().as_str()));
            match self.reclaim_attach_entry(&mut reg.containers, req.container().as_str(), live)? {
                AttachReclaim::Removed => {}
                // カーネル側は回収済みだが、アドレス・ポート予約はネットワークごとの解放まで残る。成功を装わない。
                AttachReclaim::QuarantineHeld => return Err(quarantine_held()),
                // detach は回収の前に保持中の netns を解放する（失敗なら上で返る）ため通常は届かない。届いたら記録を
                // 保持したまま成功を装わない（#2675）。
                AttachReclaim::NetnsPending => return Err(netns_pending_release()),
            }
            forget_recovered_if_empty(reg, req.network().as_str());
            return Ok(DetachResponse::new());
        }
        if container.attached.is_some() {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_DETACH_UNAVAILABLE,
            ));
        }
        // 未 attach は事前作成した netns があれば解放してから記録を消す。解放に失敗したら記録を保持して
        // エラーを返す（pin を取り残したまま追跡を失わない。#2675）。
        self.backend.release_netns(&container.endpoint)?;
        reg.containers.remove(req.container().as_str());
        Ok(DetachResponse::new())
    }

    fn delete_network_impl(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError> {
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        let name = req.name().as_str();
        let network = reg.networks.get_mut(name).ok_or_else(not_found_network)?;
        // attach 失敗で取り残しがあっても、保持中の netns（pin・fd）の解放は取り残しの拒否と請求書による回収より前に試みる
        // （回収が記録を外すと、バックエンドが保持する netns に届かなくなるため）。
        // 失敗は握りつぶさず最初のエラーとして覚え、記録は保持する（#2675）。
        let mut early_error = None;
        for c in reg.containers.values_mut() {
            if c.network == name && c.unreclaimed && c.netns_retained {
                match self.backend.release_netns(&c.endpoint) {
                    Ok(()) => c.netns_retained = false,
                    Err(e) => {
                        early_error.get_or_insert(e);
                    }
                }
            }
        }
        // attach の取り残しは bridge がある間に先に回収する（veth の所有の証明は bridge への所属。bridge を消すと
        // 証明を失う）。バックエンドでの解放後は bridge が無く証明できないため試みない（手動。#2681）。
        let mut reclaim_error = None;
        let live = quarantine_live(Some(&*network));
        if !network.backend_deleted {
            reclaim_error = self.reclaim_network_attach_leftovers(&mut reg.containers, name, live);
        }
        // quarantine だけが残るコンテナ（カーネル側は回収済み）は、バックエンドのネットワーク解放が片付けるので
        // 回収待ちに数えない。
        let remaining = network_has_kernel_unreclaimed(&reg.containers, name);
        let network = reg.networks.get_mut(name).ok_or_else(not_found_network)?;
        if network.recovered {
            // 復元したネットワークは、取り残しを回収し終えたら記録を外す。ネットワーク本体は手動回収。
            if remaining {
                return Err(reclaim_error.unwrap_or_else(delete_blocked_by_unreclaimed));
            }
            reg.networks.remove(name);
            return Err(recovered_network());
        }
        if network.leaked.is_some() && remaining {
            return Err(reclaim_error.unwrap_or_else(delete_blocked_by_unreclaimed));
        }
        // 作成失敗で取り残した資源の回収待ち: 回収を確認できたときだけ記録を外す（失敗なら保持して再試行）。
        if let Some(leaked) = &network.leaked {
            // 請求書が無い（所有を証明できない）取り残しは、バックエンドを呼ばず手動回収を求める。
            let claim = leaked.claim.as_ref().ok_or_else(manual_reclaim_required)?;
            let net_name = to_net_name(req.name())?;
            self.backend.reclaim_failed_create(&net_name, claim)?;
            // 回収を確認した後、記録ファイルを先に消す。消せなければメモリの記録も残し、同じ呼び出しの再試行で
            // 再回収（冪等）と記録の削除をやり直せる（メモリだけ消えてファイルが残る食い違いを作らない）。
            // 条件付きで消す: 別プロセスが先に回収して同名を再作成した新しい請求書は消さない（NET-1・#2604）。
            if let (Some(store), Some(record)) = (&self.store, self.backend.encode_claim(claim)) {
                store.remove_if_matches(name, &record)?;
            }
            reg.networks.remove(name);
            return Ok(DeleteNetworkResponse::new());
        }
        let handle = network.handle.as_mut().ok_or_else(not_found_network)?;
        // 取り残しの veth は bridge への master で自分のものと証明される。bridge を消すと証明を失い
        // 二度と回収できないため、取り残しが残る間はバックエンドを呼ばず何も解放しない（記録も保持）。
        if !network.backend_deleted && remaining {
            return Err(early_error
                .or(reclaim_error)
                .unwrap_or_else(delete_blocked_by_unreclaimed));
        }
        // 以降は成功して記録ごと消えるまで、失敗しても deleting を保つ（部分削除済みのまま再利用させない）。
        network.deleting = true;
        let linked: Vec<String> = reg
            .containers
            .iter()
            .filter(|(_, c)| c.network == name)
            .map(|(id, _)| id.clone())
            .collect();
        // 取り残しのあるコンテナはハンドルを持たず回収できないため、記録を保持したまま、
        // 所有を確認できる残りの資源の解放は続行する（契約 9: 個々の失敗で残りを止めない）。
        let unreclaimed_count = linked
            .iter()
            .filter(|id| {
                reg.containers
                    .get(*id)
                    .is_some_and(|c| c.unreclaimed && !c.quarantine_held)
            })
            .count();
        // 未 attach で事前作成の netns を持つコンテナは、attach 済みのハンドルを取り出す前に解放する。
        // 1 件の失敗で残りを止めない（契約 9）: 失敗した記録は保持し、最初のエラーを覚えたまま
        // attach 済みの資源の解放を続け、最後にそのエラーを返す（deleting は保たれ、再試行で解放をやり直せる。#2675）。
        // バックエンドのネットワーク解放済みでも再試行で解放できるよう、常に試みる（冪等）。
        let mut first_error = early_error;
        let mut release_failed: Vec<String> = Vec::new();
        for id in &linked {
            if let Some(c) = reg.containers.get_mut(id)
                && c.attached.is_none()
                && !c.unreclaimed
            {
                match self.backend.release_netns(&c.endpoint) {
                    Ok(()) => c.netns_retained = false,
                    Err(e) => {
                        first_error.get_or_insert(e);
                        release_failed.push(id.clone());
                    }
                }
            }
        }
        let mut handles = Vec::new();
        let mut attached_ids: Vec<String> = Vec::new();
        for id in &linked {
            if let Some(h) = reg.containers.get_mut(id).and_then(|c| c.attached.take()) {
                handles.push(h);
                attached_ids.push(id.clone());
            }
        }
        let result = if network.backend_deleted {
            Ok(())
        } else {
            self.backend.delete_network(handle, handles)
        };
        match result {
            Ok(()) => {
                network.backend_deleted = true;
                let mut store_error = None;
                for id in &linked {
                    let Some(c) = reg.containers.get(id) else {
                        continue;
                    };
                    if c.unreclaimed && !c.quarantine_held {
                        continue;
                    }
                    // 解放できていない netns を持つ記録は外さない（quarantine だけの保持で取り残しの解放に失敗したものを
                    // 含む。`first_error` が立っているため成功は返らない。#2675）。
                    if release_failed.contains(id) || c.netns_retained {
                        continue;
                    }
                    // quarantine だけの保持は、ネットワークの解放で片付いた。記録ファイルも外す（失敗なら保持して再試行）。
                    if c.quarantine_held
                        && let (Some(store), Some(record)) = (
                            &self.store,
                            c.claim
                                .as_ref()
                                .and_then(|cl| self.backend.encode_attach_claim(cl)),
                        )
                        && let Err(e) = store.remove_attach_if_matches(c.endpoint.as_str(), &record)
                    {
                        store_error.get_or_insert(e);
                        continue;
                    }
                    reg.containers.remove(id);
                }
                if let Some(e) = first_error {
                    return Err(e);
                }
                if unreclaimed_count > 0 {
                    return Err(delete_incomplete(unreclaimed_count));
                }
                if let Some(e) = store_error {
                    return Err(e);
                }
                reg.networks.remove(name);
                Ok(DeleteNetworkResponse::new())
            }
            Err(failure) => {
                // 再試行用のハンドルだけを戻し、解放済みの attach 済みコンテナは記録から外す（契約 9）。
                // 未 attach の記録（カーネル資源なし）は、再試行の delete_network が回収するため残す。
                let mut kept: Vec<String> = Vec::new();
                for h in failure.retry {
                    let id = h.endpoint_id().to_owned();
                    if let Some(c) = reg.containers.get_mut(&id) {
                        c.attached = Some(h);
                        kept.push(id);
                    }
                }
                for id in attached_ids.iter().filter(|id| !kept.contains(id)) {
                    // テーブルの削除が確認できていないため、公開した受け口はネットワークに引き継ぐ（契約 11）。
                    if let Some(c) = reg.containers.remove(id)
                        && let Some(n) = reg.networks.get_mut(name)
                    {
                        for k in c.published {
                            if !n.orphan_published.contains(&k) {
                                n.orphan_published.push(k);
                            }
                        }
                    }
                }
                Err(first_error.unwrap_or(failure.error))
            }
        }
    }
}

/// ネットワークに、attach の巻き戻しで資源を取り残したコンテナがあるか。
fn network_has_unreclaimed<C, A>(
    containers: &HashMap<String, ContainerEntry<C, A>>,
    name: &str,
) -> bool {
    containers
        .values()
        .any(|c| c.network == name && c.unreclaimed)
}

/// カーネル側の資源（veth・pin）の取り残しがあるコンテナが残っているか。quarantine だけの保持は含めない。
fn network_has_kernel_unreclaimed<C, A>(
    containers: &HashMap<String, ContainerEntry<C, A>>,
    name: &str,
) -> bool {
    containers
        .values()
        .any(|c| c.network == name && c.unreclaimed && !c.quarantine_held)
}

/// ネットワークが、プロセス内の保持（IPAM・ポート予約）を持つ生きたハンドルを持つか。復元したネットワーク・
/// 解放済みのネットワーク・無いものは `false`。
fn quarantine_live<N, F>(network: Option<&NetworkEntry<N, F>>) -> bool {
    network.is_some_and(|n| n.handle.is_some() && !n.recovered && !n.backend_deleted)
}

/// `reclaim_attach_entry` の結果。
enum AttachReclaim {
    /// 回収し、記録を外した。
    Removed,
    /// カーネル側は回収したが、quarantine が生きたネットワークに残るため記録を保持した。
    QuarantineHeld,
    /// カーネル側の取り残しは回収したが、バックエンドが保持する netns（`netns_retained`）の解放が済んでいないため、
    /// 請求書だけ外して記録を保持した（`release_netns` の成功まで追跡を失わない。#2675・NET-1）。
    NetnsPending,
}

/// 復元したネットワーク（`recovered`）で、コンテナの記録が無くなったら外す（#2681）。
fn forget_recovered_if_empty<N, C, F, A>(reg: &mut Registry<N, C, F, A>, name: &str) {
    let recovered = reg.networks.get(name).is_some_and(|n| n.recovered);
    if recovered && !reg.containers.values().any(|c| c.network == name) {
        reg.networks.remove(name);
    }
}

impl<B: NetsetupBackend> NetsetupNetwork<B> {
    /// 取り残したコンテナ 1 件を、所有確認つきで回収する。成功したときだけ記録ファイル → メモリの順に外す
    /// （失敗なら両方保持して再試行できる。記録の削除は中身が一致するときだけ。NET-1・#2681）。
    ///
    /// 請求書にプロセス内の保持（quarantine）が含まれ、かつ生きたネットワークの上なら、カーネル側の回収後も
    /// 記録を外さず quarantine だけの請求書へ置き換えて保持する（[`AttachReclaim::QuarantineHeld`]）。
    /// アドレス・DNAT ルール・ポート予約はここでは解放できず、解放前に記録を外すと同じ endpoint の再 attach が
    /// `AlreadyExists` で失敗し、`network_has_unreclaimed` の防御も外れるため。`quarantine_live` はその
    /// ネットワークが生きている（`handle` があり、復元でも解放済みでもない）か。
    fn reclaim_attach_entry(
        &self,
        containers: &mut HashMap<String, ContainerEntry<B::Container, B::FailedAttach>>,
        id: &str,
        quarantine_live: bool,
    ) -> Result<AttachReclaim, TraitError> {
        let entry = containers.get(id).ok_or_else(not_found_netns)?;
        let claim = entry.claim.as_ref().ok_or_else(unreclaimed)?;
        self.backend.reclaim_failed_attach(claim)?;
        if quarantine_live && let Some(rest) = self.backend.attach_claim_quarantine_remainder(claim)
        {
            // 更新は、読み出した元の請求書と一致するときだけ（比較交換）。回収の間に別プロセスが同じ endpoint の
            // 新しい世代の請求書を保存していても、旧世代の更新で上書きしない（NET-1・#2681）。
            if !entry.quarantine_held
                && let (Some(store), Some(original), Some(record)) = (
                    &self.store,
                    self.backend.encode_attach_claim(claim),
                    self.backend.encode_attach_claim(&rest),
                )
            {
                store.update_attach_if_matches(entry.endpoint.as_str(), &original, &record)?;
            }
            let entry = containers.get_mut(id).ok_or_else(not_found_netns)?;
            entry.claim = Some(rest);
            entry.quarantine_held = true;
            return Ok(AttachReclaim::QuarantineHeld);
        }
        if let (Some(store), Some(record)) = (&self.store, self.backend.encode_attach_claim(claim))
        {
            store.remove_attach_if_matches(entry.endpoint.as_str(), &record)?;
        }
        if entry.netns_retained {
            // 保持中の netns は請求書の回収の対象外。記録を外すと `release_netns` に届かなくなるため、取り残しの印と
            // 請求書だけ外して未 attach の記録として残す（detach・delete_network の解放で記録ごと外れる）。
            let entry = containers.get_mut(id).ok_or_else(not_found_netns)?;
            entry.unreclaimed = false;
            entry.quarantine_held = false;
            entry.claim = None;
            return Ok(AttachReclaim::NetnsPending);
        }
        containers.remove(id);
        Ok(AttachReclaim::Removed)
    }

    /// ネットワークの取り残し全件の回収を試みる（請求書の無いものは触れない）。1 件の失敗で残りを止めず、
    /// 最初のエラーを返す（ERR-1）。
    fn reclaim_network_attach_leftovers(
        &self,
        containers: &mut HashMap<String, ContainerEntry<B::Container, B::FailedAttach>>,
        name: &str,
        quarantine_live: bool,
    ) -> Option<TraitError> {
        let mut ids: Vec<String> = containers
            .iter()
            .filter(|(_, c)| {
                c.network == name && c.unreclaimed && !c.quarantine_held && c.claim.is_some()
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort_unstable();
        let mut first = None;
        for id in ids {
            // quarantine だけが残った（QuarantineHeld）ものは、このあとの backend の delete_network が解放する。
            if let Err(e) = self.reclaim_attach_entry(containers, &id, quarantine_live) {
                first.get_or_insert(e);
            }
        }
        first
    }
}

impl<B: NetsetupBackend> NetworkPlugin for NetsetupNetwork<B> {
    fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
        self.timed("net.create_network", || self.create_network_impl(req))
    }

    fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
        self.timed("net.create_netns", || self.create_netns_impl(req))
    }

    fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError> {
        self.timed("net.attach", || self.attach_impl(req))
    }

    fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
        self.timed("net.publish_port", || self.publish_port_impl(req))
    }

    fn unpublish_port(
        &self,
        req: &UnpublishPortRequest,
    ) -> Result<UnpublishPortResponse, TraitError> {
        self.timed("net.unpublish_port", || self.unpublish_port_impl(req))
    }

    fn detach(&self, req: &DetachRequest) -> Result<DetachResponse, TraitError> {
        self.timed("net.detach", || self.detach_impl(req))
    }

    fn delete_network(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError> {
        self.timed("net.delete_network", || self.delete_network_impl(req))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{LinuxNetsetup, NETSETUP_REQUEST_TIMEOUT};

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use fandhe_container_net::instrument::{NetOpRecorder, NoopNetOpRecorder};
    use fandhe_container_net::netlink_route::NetlinkRouteSocket;
    use fandhe_container_net::netns::ContainerNetns;
    use fandhe_container_net::network::{
        AttachedContainer, ContainerAttachSpec, CreatedNetwork, FailedAttachClaim,
        FailedCreateClaim, NetworkCreateSpec, PortRegistry, PreparedNetns, PublishedPort,
        StaticIpam, UnpublishRules, attach_prepared_container, create_container_netns,
        create_network, delete_network, publish_container_ports, reclaim_failed_attach,
        reclaim_failed_create, release_container_netns, unpublish_container_port,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    use super::*;

    /// netlink の 1 要求ごとの期限（REPAIR-5。トレイトの契約 2）。
    pub const NETSETUP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

    impl NetsetupContainer for AttachedContainer<ContainerNetns> {
        fn endpoint_id(&self) -> &str {
            self.endpoint.as_str()
        }
    }

    /// Linux のネットワークのハンドル（作成結果・IPAM・ポート予約）。
    pub struct LinuxNetwork {
        created: CreatedNetwork,
        ipam: StaticIpam,
        ports: PortRegistry,
        /// 公開済みの受け口のルールハンドル（`publish_port` が積み、`unpublish_port` が外す）。件数は
        /// レジストリの公開件数の上限で有界。プロセス再起動後は失われ、解放は `delete_network` に頼る。
        published: Vec<PublishedPort>,
    }

    /// net の統合 API を呼ぶバックエンド。ソケットは呼び出しごとに開く（起動時に `CAP_NET_ADMIN` が
    /// 無くても `production()` を失敗させないため）。
    #[derive(Clone)]
    pub struct LinuxNetsetup {
        netns_dir: PathBuf,
        /// netlink / nftables ソケットの計測先（REPAIR-4）。
        recorder: Arc<dyn NetOpRecorder>,
        /// `create_netns` で作って attach 前の netns（エンドポイント ID → ハンドル）。件数はレジストリの
        /// 上限（`MAX_NETWORKS` × `MAX_CONTAINERS_PER_NETWORK`）で有界。`Clone` した複製とも共有する。
        prepared: Arc<Mutex<HashMap<String, PreparedNetns<ContainerNetns>>>>,
    }

    impl std::fmt::Debug for LinuxNetsetup {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxNetsetup").finish_non_exhaustive()
        }
    }

    impl LinuxNetsetup {
        /// netns の pin の置き場（絶対パス。状態ルート配下の固定の場所）を指定して作る。
        pub fn new(netns_dir: PathBuf) -> Self {
            Self::with_recorder(netns_dir, Arc::new(NoopNetOpRecorder))
        }

        /// 置き場と、ソケットの計測先を指定して作る（REPAIR-4）。
        pub fn with_recorder(netns_dir: PathBuf, recorder: Arc<dyn NetOpRecorder>) -> Self {
            Self {
                netns_dir,
                recorder,
                prepared: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn lock_prepared(
            &self,
        ) -> Result<
            std::sync::MutexGuard<'_, HashMap<String, PreparedNetns<ContainerNetns>>>,
            TraitError,
        > {
            self.prepared.lock().map_err(|_| {
                TraitError::new(ErrorCode::Internal, "prepared netns state is poisoned")
            })
        }

        fn open_sockets(&self) -> Result<(NetlinkRouteSocket, NetlinkNetfilterSocket), TraitError> {
            let route = NetlinkRouteSocket::open_with_recorder(Arc::clone(&self.recorder))
                .map_err(|e| net_error_to_trait(&e))?;
            let nft = NetlinkNetfilterSocket::open_with_recorder(Arc::clone(&self.recorder))
                .map_err(|e| net_error_to_trait(&e))?;
            Ok((route, nft))
        }

        fn ensure_netns_dir(&self) -> Result<(), TraitError> {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.netns_dir)
                .map_err(|_| {
                    TraitError::new(ErrorCode::Internal, "failed to prepare the netns directory")
                })
        }
    }

    impl NetsetupBackend for LinuxNetsetup {
        type Network = LinuxNetwork;
        type Container = AttachedContainer<ContainerNetns>;
        type FailedCreate = FailedCreateClaim;
        type FailedAttach = FailedAttachClaim;

        fn create_network(
            &self,
            name: &NetName,
            gateway: IpPrefix,
        ) -> Result<Self::Network, CreateFailure<Self::FailedCreate>> {
            let spec = NetworkCreateSpec::new(name.clone(), gateway)
                .map_err(|e| net_error_to_trait(&e))?;
            let (route, nft) = self.open_sockets()?;
            let created =
                create_network(&route, &nft, &spec, NETSETUP_REQUEST_TIMEOUT).map_err(|e| {
                    let leftover = e.rollback.leftover.len();
                    CreateFailure {
                        error: with_leftover(net_error_to_trait(&e.error), leftover),
                        leftover,
                        reclaim: e.reclaim_claim(),
                    }
                })?;
            // 作成は成功済みで、ここで失敗すると bridge と nft テーブル（2 件）をハンドルなしで残す。
            let ipam = StaticIpam::for_network(&created).map_err(|e| CreateFailure {
                error: with_leftover(net_error_to_trait(&e), 2),
                leftover: 2,
                reclaim: Some(FailedCreateClaim::from_created(&created)),
            })?;
            Ok(LinuxNetwork {
                created,
                ipam,
                ports: PortRegistry::new(),
                published: Vec::new(),
            })
        }

        fn encode_claim(&self, claim: &Self::FailedCreate) -> Option<String> {
            Some(claim.to_record())
        }

        fn decode_claim(
            &self,
            name: &NetName,
            record: &str,
        ) -> Result<Self::FailedCreate, TraitError> {
            let claim =
                FailedCreateClaim::from_record(record).map_err(|e| net_error_to_trait(&e))?;
            if claim.network() != name {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "reclaim record does not belong to the network",
                ));
            }
            Ok(claim)
        }

        fn reclaim_failed_create(
            &self,
            name: &NetName,
            claim: &Self::FailedCreate,
        ) -> Result<(), TraitError> {
            // 防御的な照合。請求書は作成時のものをそのまま保持するはずで、食い違いは記録の破損なので触れない。
            if claim.network() != name {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "reclaim claim does not belong to the network",
                ));
            }
            let (route, nft) = self.open_sockets()?;
            match reclaim_failed_create(&route, &nft, claim, NETSETUP_REQUEST_TIMEOUT) {
                Ok(_) => Ok(()),
                Err(e) => Err(with_leftover(
                    net_error_to_trait(&e.error),
                    e.report.leftover.len(),
                )),
            }
        }

        fn encode_attach_claim(&self, claim: &Self::FailedAttach) -> Option<String> {
            Some(claim.to_record())
        }

        fn decode_attach_claim(
            &self,
            endpoint: &EndpointId,
            record: &str,
        ) -> Result<(NetName, Self::FailedAttach), TraitError> {
            let claim =
                FailedAttachClaim::from_record(record).map_err(|e| net_error_to_trait(&e))?;
            if claim.endpoint() != endpoint {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "reclaim record does not belong to the endpoint",
                ));
            }
            Ok((claim.network().clone(), claim))
        }

        fn attach_claim_quarantine_remainder(
            &self,
            claim: &Self::FailedAttach,
        ) -> Option<Self::FailedAttach> {
            claim.quarantine_only()
        }

        fn reclaim_failed_attach(&self, claim: &Self::FailedAttach) -> Result<(), TraitError> {
            let (route, nft) = self.open_sockets()?;
            // pin の置き場は記録からではなく、この plugin の固定設定から受ける。
            match reclaim_failed_attach(
                &route,
                &nft,
                claim,
                &self.netns_dir,
                NETSETUP_REQUEST_TIMEOUT,
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(with_leftover(
                    net_error_to_trait(&e.error),
                    e.report.leftover.len(),
                )),
            }
        }

        fn create_netns(
            &self,
            _network: &mut Self::Network,
            endpoint: &EndpointId,
        ) -> Result<(), AttachFailure> {
            self.ensure_netns_dir()?;
            if self.lock_prepared()?.contains_key(endpoint.as_str()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "netns already exists for the container",
                )
                .into());
            }
            let (route, _nft) = self.open_sockets()?;
            let prepared =
                create_container_netns(&route, &self.netns_dir, endpoint, NETSETUP_REQUEST_TIMEOUT)
                    .map_err(|e| {
                        // 取り残した pin があれば件数 1 として報告し、レジストリが回収待ちとして保持する。
                        let leftover = usize::from(e.leftover.is_some());
                        let error = with_leftover(net_error_to_trait(&e.error), leftover);
                        // unpin できなかった netns は保持し、`release_netns` で再試行できるようにする（#2675）。
                        let netns_retained = match e.retained {
                            Some(netns) => match self.lock_prepared() {
                                Ok(mut p) => {
                                    p.insert(endpoint.as_str().to_owned(), *netns);
                                    true
                                }
                                Err(_) => false,
                            },
                            None => false,
                        };
                        AttachFailure {
                            error,
                            leftover,
                            netns_retained,
                            reclaim: None,
                        }
                    })?;
            self.lock_prepared()?
                .insert(endpoint.as_str().to_owned(), prepared);
            Ok(())
        }

        fn release_netns(&self, endpoint: &EndpointId) -> Result<(), TraitError> {
            let Some(prepared) = self.lock_prepared()?.remove(endpoint.as_str()) else {
                return Ok(());
            };
            let (route, nft) = match self.open_sockets() {
                Ok(s) => s,
                Err(e) => {
                    self.lock_prepared()?
                        .insert(endpoint.as_str().to_owned(), prepared);
                    return Err(e);
                }
            };
            match release_container_netns(&route, &nft, prepared, NETSETUP_REQUEST_TIMEOUT) {
                Ok(()) => Ok(()),
                Err(e) => {
                    // 解除できなかった netns は保持して、再試行できるようにする。
                    let error = net_error_to_trait(&e.error);
                    self.lock_prepared()?
                        .insert(endpoint.as_str().to_owned(), e.netns);
                    Err(error)
                }
            }
        }

        fn attach(
            &self,
            network: &mut Self::Network,
            endpoint: &EndpointId,
        ) -> Result<AttachOutcome<Self::Container>, AttachFailure<Self::FailedAttach>> {
            self.ensure_netns_dir()?;
            let spec = ContainerAttachSpec::new(
                endpoint.clone(),
                &network.created,
                self.netns_dir.clone(),
            )
            .map_err(|e| net_error_to_trait(&e))?;
            let prepared = self
                .lock_prepared()?
                .remove(endpoint.as_str())
                .ok_or_else(|| {
                    TraitError::new(ErrorCode::FailedPrecondition, MSG_NETNS_NOT_PREPARED)
                })?;
            let (route, nft) = match self.open_sockets() {
                Ok(s) => s,
                Err(e) => {
                    self.lock_prepared()?
                        .insert(endpoint.as_str().to_owned(), prepared);
                    return Err(e.into());
                }
            };
            let attached = match attach_prepared_container(
                &route,
                &nft,
                &spec,
                prepared,
                &mut network.ipam,
                &mut network.ports,
                NETSETUP_REQUEST_TIMEOUT,
            ) {
                Ok(a) => a,
                Err(e) => {
                    // netns は unpin されずに返る。保持して detach・delete_network に解放を任せる。
                    let retained = e.netns.is_some();
                    if let Some(netns) = e.netns {
                        self.lock_prepared()?
                            .insert(endpoint.as_str().to_owned(), netns);
                    }
                    let leftover = e.error.rollback.leftover.len();
                    return Err(AttachFailure {
                        error: with_leftover(net_error_to_trait(&e.error.error), leftover),
                        leftover,
                        netns_retained: leftover > 0 && retained,
                        reclaim: e.error.reclaim_claim(),
                    });
                }
            };
            Ok(AttachOutcome {
                address: attached.address,
                container: attached,
            })
        }

        fn publish_port(
            &self,
            network: &mut Self::Network,
            container: &Self::Container,
            publish: &PortPublish,
        ) -> Result<(), PublishFailure> {
            let nft = NetlinkNetfilterSocket::open_with_recorder(Arc::clone(&self.recorder))
                .map_err(|e| PublishFailure {
                    error: net_error_to_trait(&e),
                    rules_unknown: false,
                })?;
            let published = publish_container_ports(
                &nft,
                &network.created,
                container,
                std::slice::from_ref(publish),
                &mut network.ports,
                NETSETUP_REQUEST_TIMEOUT,
            )
            .map_err(|e| PublishFailure {
                error: net_error_to_trait(&e.error),
                rules_unknown: e.rules_unknown,
            })?;
            network.published.extend(published);
            Ok(())
        }

        fn unpublish_port(
            &self,
            network: &mut Self::Network,
            container: &Self::Container,
            publish: &PortPublish,
        ) -> Result<(), PublishFailure> {
            let Some(pos) = network
                .published
                .iter()
                .position(|p| p.endpoint() == &container.endpoint && p.publish() == publish)
            else {
                return Err(PublishFailure {
                    error: TraitError::new(ErrorCode::NotFound, "published port is not recorded"),
                    rules_unknown: false,
                });
            };
            let nft = NetlinkNetfilterSocket::open_with_recorder(Arc::clone(&self.recorder))
                .map_err(|e| PublishFailure {
                    error: net_error_to_trait(&e),
                    rules_unknown: false,
                })?;
            let record = network.published.remove(pos);
            unpublish_container_port(
                &nft,
                &network.created,
                record,
                &mut network.ports,
                NETSETUP_REQUEST_TIMEOUT,
            )
            .map_err(|e| {
                // ルールが残っている可能性がある間は記録を戻し、再試行できるようにする。
                let rules_unknown = e.rules == UnpublishRules::Unknown;
                if let Some(back) = e.published {
                    network.published.push(*back);
                }
                PublishFailure {
                    error: net_error_to_trait(&e.error),
                    rules_unknown,
                }
            })
        }

        fn delete_network(
            &self,
            network: &mut Self::Network,
            containers: Vec<Self::Container>,
        ) -> Result<(), DeleteFailure<Self::Container>> {
            let (route, nft) = match self.open_sockets() {
                Ok(s) => s,
                Err(error) => {
                    return Err(DeleteFailure {
                        error,
                        retry: containers,
                    });
                }
            };
            match delete_network(
                &route,
                &nft,
                &network.created,
                containers,
                &mut network.ipam,
                &mut network.ports,
                NETSETUP_REQUEST_TIMEOUT,
            ) {
                Ok(_) => Ok(()),
                Err(e) => {
                    let error =
                        with_leftover(net_error_to_trait(&e.error), e.report.leftover.len());
                    Err(DeleteFailure {
                        error,
                        retry: e.retry,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-1・ERR-1: `NetErrorCode::ALL` の全件を照合する。net にだけある名前は `DATA_LOSS`
    /// （`Internal` に写り message の先頭へ残る）、core にだけある名前は `UNAVAILABLE`。
    #[test]
    fn err1_net_error_to_trait_covers_all_net_codes() {
        for nc in NetErrorCode::ALL {
            let t = net_error_to_trait(&NetError::new(nc, "m"));
            match ErrorCode::from_name(nc.as_str()) {
                Some(ec) => {
                    assert_eq!(t.code(), ec, "{nc:?}");
                    assert_eq!(t.message(), "m");
                }
                None => {
                    assert_eq!(nc, NetErrorCode::DataLoss);
                    assert_eq!(t.code(), ErrorCode::Internal);
                    assert_eq!(t.message(), "DATA_LOSS: m");
                }
            }
        }
        let core_only: Vec<&str> = ErrorCode::ALL
            .iter()
            .map(|c| c.as_str())
            .filter(|n| !NetErrorCode::ALL.iter().any(|nc| nc.as_str() == *n))
            .collect();
        assert_eq!(core_only, ["UNAVAILABLE"]);
    }

    fn cidr(a: [u8; 4], len: u8) -> IpCidr {
        IpCidr::new(IpAddr::V4(Ipv4Addr::from(a)), len).expect("cidr")
    }

    /// NET-1: gateway はネットワークアドレス + 1 で prefix 長は同じ（具体値）。
    #[test]
    fn net1_gateway_is_network_address_plus_one() {
        let gw = gateway_for(cidr([10, 89, 0, 77], 24)).expect("gateway");
        assert_eq!(gw.addr(), IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)));
        assert_eq!(gw.prefix_len(), 24);
    }

    /// NET-1: IPv6 と範囲外の prefix 長は InvalidArgument。
    #[test]
    fn net1_gateway_rejects_ipv6_and_bad_prefix() {
        let v6 = IpCidr::new("fd00::".parse().expect("v6"), 64).expect("cidr");
        assert_eq!(
            gateway_for(v6).expect_err("v6").code(),
            ErrorCode::InvalidArgument
        );
        for len in [0u8, 31, 32] {
            assert_eq!(
                gateway_for(cidr([10, 0, 0, 0], len))
                    .expect_err("len")
                    .code(),
                ErrorCode::InvalidArgument,
                "prefix {len}"
            );
        }
    }

    /// ERR-1: 同名コードはそのまま写し、ResourceExhausted も同名で写し（#2609）、DataLoss は Internal で元のコードを残す。
    #[test]
    fn err1_net_error_mapping() {
        let t = net_error_to_trait(&NetError::new(NetErrorCode::NotFound, "gone"));
        assert_eq!((t.code(), t.message()), (ErrorCode::NotFound, "gone"));
        let t = net_error_to_trait(&NetError::new(NetErrorCode::ResourceExhausted, "full"));
        assert_eq!(
            (t.code(), t.message()),
            (ErrorCode::ResourceExhausted, "full")
        );
        let t = net_error_to_trait(&NetError::new(NetErrorCode::DataLoss, "bad"));
        assert_eq!(t.code(), ErrorCode::Internal);
        assert_eq!(t.message(), "DATA_LOSS: bad");
    }

    /// 取り残しが 1 件でもあれば分類を問わず Internal になり、件数が載る。
    #[test]
    fn err1_leftover_forces_internal_with_count() {
        let base = TraitError::new(ErrorCode::AlreadyExists, "boom");
        let e = with_leftover(base.clone(), 2);
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(e.message().contains("2 resource(s) left behind"));
        assert_eq!(with_leftover(base.clone(), 0), base);
    }

    /// netns 名の導出: pin のファイル名（コンテナ ID）と一致し、別 ID は別名になる（衝突しない）。
    /// `NetnsName` が受けない文字を含む ID は拒否する。
    #[test]
    fn netns_name_matches_pin_file_name() {
        let id = ContainerId::new("web-1-a").expect("id");
        assert_eq!(derive_netns_name(&id).expect("name").as_str(), "web-1-a");
        // 58 文字 ID と、その先頭に netns- を付けた 64 文字 ID は別名のまま。
        let short = ContainerId::new("a".repeat(58)).expect("id");
        let long = ContainerId::new(format!("netns-{}", "a".repeat(58))).expect("id");
        assert_ne!(
            derive_netns_name(&short).expect("short").as_str(),
            derive_netns_name(&long).expect("long").as_str()
        );
        let dotted = ContainerId::new("web_1.a").expect("id");
        assert_eq!(
            derive_netns_name(&dotted).expect_err("dotted").code(),
            ErrorCode::InvalidArgument
        );
    }
}
