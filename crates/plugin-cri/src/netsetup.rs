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
//! | `netns-create` | `create_netns` | Linux バックエンドは `Unimplemented`（下記「netns の作成時点」） |
//! | `veth-attach` | `attach` | `network::attach_container`（netns の作成と pin を含む） |
//! | `publish-port` | `publish_port` | 未実装（`Unimplemented`） |
//! | （なし） | `detach` | 未 attach の記録の取り消しのみ。attach 済みは `Unimplemented` |
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
//!   attach の巻き戻しで取り残した記録があっても、所有を確認できる資源の解放は続行し、取り残しの記録は保持して
//!   最後に `Internal` を返す。取り残しのあるネットワークへの `create_netns`・`attach` は `FailedPrecondition`
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - netns の作成時点: トレイトの `create_netns` は「netns の作成（lo の up を含む）」だが、net の
//!   `attach_container` は netns の作成と pin から veth・アドレス設定までを 1 回で行い、先に netns を作ると
//!   同じ pin パスで `AlreadyExists` になる。そのため Linux バックエンド（`LinuxNetsetup`）の `create_netns` は
//!   メモリ上の登録だけで成功を装わず `Unimplemented` を返す（実 netns の事前作成は net の API 分割の後続作業）。
//!   バックエンドの `create_netns` が成功したときだけ契約 7・8 の記録を作る
//! - 作成失敗の回収（#2467）: 手動回収のまま残るのは、所有トークンを刻む前の失敗で残った bridge（請求書が無い、
//!   または別名が空で証明できない）、他者の同名資源が残っている場合、置き場に記録できなかった・壊れた記録の場合。
//!   いずれも記録を保持して `FailedPrecondition`（または件数入りの `Internal`）を返す。請求書は
//!   [`ReclaimStore`]（`<状態ルート>/.cri/net/pending-reclaim/<名前>.claim`）に永続化し、plugin の再起動後に
//!   読み込んで `delete_network` で回収する（#2604。`docs/design/network-reclaim-persistence.md`、手動の手順は
//!   `docs/setup/network-reclaim-recovery.md`）。置き場を差さない構成（`new`・`with_recorder`）はメモリだけ
//! - `publish_port`: net はポート公開を attach 時の `ContainerAttachSpec::with_port_publishes` でしか受けず、
//!   コンテナ単位の公開・解除が未実装のため `Unimplemented`（NET-4）
//! - `detach`: net にコンテナ単体の切り離しが無いため、attach 済みは `Unimplemented`
//! - 静的アドレス（`AttachRequest::address`）: net の `attach_container` は内部で動的割り当てを行い、事前予約と
//!   併用できないため `Unimplemented`（契約 10。カーネル操作の前に判定する）
//! - 状態（作成に成功したネットワーク・IPAM・pin・削除中の印）はプロセスのメモリにだけあり、plugin プロセスの
//!   再起動で失われる（永続化するのは作成失敗の回収待ちの記録だけ。残りは #1870 の設計の後続）
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
    NetnsName, NetnsStatus, NetworkName, NetworkPlugin, NetworkStatus, PortMapping,
    PublishPortRequest, TraitError,
};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName as NetName};

/// 1 つの plugin プロセスが保持するネットワークの上限（信頼できない入力で状態が増え続けないようにする）。
pub const MAX_NETWORKS: usize = 128;
/// 1 つのネットワークが保持するコンテナの上限。
pub const MAX_CONTAINERS_PER_NETWORK: usize = 256;

/// 未実装文言（固定。入力を含めない）。
pub const MSG_PUBLISH_PORT_UNAVAILABLE: &str =
    "publish_port is not available yet: net accepts port publishes only at attach time";
/// attach 済みコンテナの切り離しの未実装文言。
pub const MSG_DETACH_UNAVAILABLE: &str =
    "detach of an attached container is not available yet: net has no per-container teardown";
/// netns の事前作成の未実装文言（Linux バックエンド）。
pub const MSG_NETNS_CREATE_UNAVAILABLE: &str =
    "netns pre-creation is not available yet: net creates the netns inside attach";
/// 静的アドレスの未実装文言。
pub const MSG_STATIC_ADDRESS_UNAVAILABLE: &str =
    "static container addresses are not available yet: net allocates addresses at attach time";

/// net のエラーをトレイトのエラーへ写す（同名のコードはそのまま。net のメッセージは入力値を含まない）。
///
/// `DataLoss`・`ResourceExhausted` は `ErrorCode` に対応が無いため `Internal` にし、元のコードを
/// `message` の先頭へ残す。
pub fn net_error_to_trait(e: &NetError) -> TraitError {
    let code = match e.code() {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::Timeout => ErrorCode::Timeout,
        NetErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        NetErrorCode::NotFound => ErrorCode::NotFound,
        NetErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        NetErrorCode::DataLoss | NetErrorCode::ResourceExhausted => {
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
pub struct AttachFailure {
    /// 失敗の原因（取り残しがあれば件数入りの `Internal`）。
    pub error: TraitError,
    /// 巻き戻しで回収できずカーネルに残った資源の件数（0 なら回収済み）。
    pub leftover: usize,
}

impl From<TraitError> for AttachFailure {
    /// 取り残しなしの失敗。
    fn from(error: TraitError) -> Self {
        Self { error, leftover: 0 }
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

    /// コンテナ専用の netns を（lo の up を含めて）作る。既定は何もしない成功（試験用 fake 向け）。
    ///
    /// net の `attach_container` は netns の作成と pin から veth の設定までを 1 回で行い、先に netns を作ると
    /// 同じ pin パスで `AlreadyExists` になる。実体を作れないバックエンドは、成功を装わず `Unimplemented` を
    /// 返すこと（契約 3・REPAIR-3。実 netns を先に作れるよう net の API を分割する作業は後続）。
    fn create_netns(
        &self,
        _network: &mut Self::Network,
        _endpoint: &EndpointId,
    ) -> Result<(), TraitError> {
        Ok(())
    }

    /// コンテナを接続する。失敗時の巻き戻しは実装が行う（契約 6）。
    fn attach(
        &self,
        network: &mut Self::Network,
        endpoint: &EndpointId,
    ) -> Result<AttachOutcome<Self::Container>, AttachFailure>;

    /// ネットワークと、渡した attach 済みコンテナを解放する（契約 9）。
    fn delete_network(
        &self,
        network: &mut Self::Network,
        containers: Vec<Self::Container>,
    ) -> Result<(), DeleteFailure<Self::Container>>;
}

/// `create_netns` で登録されたコンテナ 1 件の記録。
struct ContainerEntry<C> {
    /// 紐付けたネットワーク名（`CreateNetnsRequest::network`）。
    network: String,
    endpoint: EndpointId,
    /// attach 済みならハンドル（未 attach ならカーネル資源は無い）。
    attached: Option<C>,
    /// attach の巻き戻しで資源を取り残した印。立っている間は記録を消さず、attach・detach・
    /// ネットワーク削除を fail-closed で拒否する（net に所有確認つきの個別回収 API が入るまでの保持）。
    /// 作成失敗の回収（#2467）とは別で、attach 側の回収は未実装。
    unreclaimed: bool,
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
}

/// 作成失敗で取り残した資源の回収待ちの記録。
struct LeakedCreate<F> {
    /// 所有確認つきの回収に使う請求書。`None` は所有を証明できない取り残しで、手動回収。
    claim: Option<F>,
}

struct Registry<N, C, F> {
    networks: HashMap<String, NetworkEntry<N, F>>,
    /// コンテナ ID（文字列）→ 記録。同じコンテナはネットワークを問わず 1 件だけ（契約 7・8）。
    containers: HashMap<String, ContainerEntry<C>>,
}

/// バックエンド `B` のハンドル型で具体化したレジストリ。
type BackendRegistry<B> = Registry<
    <B as NetsetupBackend>::Network,
    <B as NetsetupBackend>::Container,
    <B as NetsetupBackend>::FailedCreate,
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
                },
            );
        }
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
                containers: HashMap::new(),
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

/// attach の巻き戻しで取り残した資源が残っているコンテナへの操作の拒否（記録を消して成功を装わない）。
fn unreclaimed() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container has unreclaimed network resources from a failed attach; manual reclaim required",
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
        self.backend.create_netns(handle, &endpoint)?;
        reg.containers.insert(
            req.container().as_str().to_owned(),
            ContainerEntry {
                network: req.network().as_str().to_owned(),
                endpoint,
                attached: None,
                unreclaimed: false,
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
        let handle = network.handle.as_mut().ok_or_else(leaked_network)?;
        let outcome = match self.backend.attach(handle, &container.endpoint) {
            Ok(o) => o,
            Err(f) => {
                if f.leftover > 0 {
                    container.unreclaimed = true;
                }
                return Err(f.error);
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

    fn detach_impl(&self, req: &DetachRequest) -> Result<DetachResponse, TraitError> {
        let mut guard = self.lock()?;
        let reg = &mut *guard;
        if !reg.networks.contains_key(req.network().as_str()) {
            return Err(not_found_network());
        }
        let container = reg
            .containers
            .get(req.container().as_str())
            .ok_or_else(not_found_netns)?;
        if container.network != req.network().as_str() {
            return Err(network_mismatch());
        }
        if container.unreclaimed {
            return Err(unreclaimed());
        }
        if container.attached.is_some() {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_DETACH_UNAVAILABLE,
            ));
        }
        // 未 attach（記録だけ）はカーネル資源が無いので記録を消すだけで解放が済む。
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
        if !network.backend_deleted && network_has_unreclaimed(&reg.containers, name) {
            return Err(delete_blocked_by_unreclaimed());
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
            .filter(|id| reg.containers.get(*id).is_some_and(|c| c.unreclaimed))
            .count();
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
                for id in &linked {
                    if !reg.containers.get(id).is_some_and(|c| c.unreclaimed) {
                        reg.containers.remove(id);
                    }
                }
                if unreclaimed_count > 0 {
                    return Err(delete_incomplete(unreclaimed_count));
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
                    reg.containers.remove(id);
                }
                Err(failure.error)
            }
        }
    }
}

/// ネットワークに、attach の巻き戻しで資源を取り残したコンテナがあるか。
fn network_has_unreclaimed<C>(containers: &HashMap<String, ContainerEntry<C>>, name: &str) -> bool {
    containers
        .values()
        .any(|c| c.network == name && c.unreclaimed)
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

    fn publish_port(&self, _req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
        self.timed("net.publish_port", || {
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_PUBLISH_PORT_UNAVAILABLE,
            ))
        })
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
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use fandhe_container_net::instrument::{NetOpRecorder, NoopNetOpRecorder};
    use fandhe_container_net::netlink_route::NetlinkRouteSocket;
    use fandhe_container_net::netns::ContainerNetns;
    use fandhe_container_net::network::{
        AttachedContainer, ContainerAttachSpec, CreatedNetwork, FailedCreateClaim,
        NetworkCreateSpec, PortRegistry, StaticIpam, attach_container, create_network,
        delete_network, reclaim_failed_create,
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
    }

    /// net の統合 API を呼ぶバックエンド。ソケットは呼び出しごとに開く（起動時に `CAP_NET_ADMIN` が
    /// 無くても `production()` を失敗させないため）。
    #[derive(Clone)]
    pub struct LinuxNetsetup {
        netns_dir: PathBuf,
        /// netlink / nftables ソケットの計測先（REPAIR-4）。
        recorder: Arc<dyn NetOpRecorder>,
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
            }
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

        fn create_netns(
            &self,
            _network: &mut Self::Network,
            _endpoint: &EndpointId,
        ) -> Result<(), TraitError> {
            // net の attach_container が netns の作成と pin を含み、先に作ると AlreadyExists になる。
            // メモリ上の登録だけで成功を装わない（契約 3・REPAIR-3）。
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                MSG_NETNS_CREATE_UNAVAILABLE,
            ))
        }

        fn attach(
            &self,
            network: &mut Self::Network,
            endpoint: &EndpointId,
        ) -> Result<AttachOutcome<Self::Container>, AttachFailure> {
            self.ensure_netns_dir()?;
            let spec = ContainerAttachSpec::new(
                endpoint.clone(),
                &network.created,
                self.netns_dir.clone(),
            )
            .map_err(|e| net_error_to_trait(&e))?;
            let (route, nft) = self.open_sockets()?;
            let attached = attach_container(
                &route,
                &nft,
                &spec,
                &mut network.ipam,
                &mut network.ports,
                NETSETUP_REQUEST_TIMEOUT,
            )
            .map_err(|e| {
                let leftover = e.rollback.leftover.len();
                AttachFailure {
                    error: with_leftover(net_error_to_trait(&e.error), leftover),
                    leftover,
                }
            })?;
            Ok(AttachOutcome {
                address: attached.address,
                container: attached,
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

    /// ERR-1: 同名コードはそのまま写し、DataLoss・ResourceExhausted は Internal で元のコードを残す。
    #[test]
    fn err1_net_error_mapping() {
        let t = net_error_to_trait(&NetError::new(NetErrorCode::NotFound, "gone"));
        assert_eq!((t.code(), t.message()), (ErrorCode::NotFound, "gone"));
        let t = net_error_to_trait(&NetError::new(NetErrorCode::ResourceExhausted, "full"));
        assert_eq!(t.code(), ErrorCode::Internal);
        assert_eq!(
            t.message(),
            format!("{}: full", NetErrorCode::ResourceExhausted.as_str())
        );
        let t = net_error_to_trait(&NetError::new(NetErrorCode::DataLoss, "bad"));
        assert_eq!(t.code(), ErrorCode::Internal);
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
