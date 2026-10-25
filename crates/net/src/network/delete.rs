//! ネットワーク削除処理（bridge・veth・netns・専用 nft テーブルの一括解放。TASK-139.4・#317・NET-1・MS-8）。
//!
//! 親モジュール `network` の `create_network` と `attach_container` が作った資源を、名前を再導出して
//! 解放する統合層で、PoC-15 `netsetup` の `net-delete` に相当する。将来 `NetworkPlugin` 境界（TASK-114）の
//! `TearDownPod` 相当から呼ばれる想定で、現状の呼び出し元は結合テストのみ。
//!
//! # 参加中のコンテナの扱い
//!
//! 「明示的な解放」と「渡されていない生存コンテナの拒否」を組み合わせる。呼び出し側はネットワークに接続中の
//! コンテナ（[`AttachedContainer`]）を `containers` で渡し、渡されたものの veth と netns の pin を解放する。
//! IPAM に払い出しがあるのに渡されていない endpoint は、veth が存在する（または有無を判定できない）場合に
//! 何も変更せず `FailedPrecondition` で拒否する（fail-closed。生存コンテナの veth を bridge から外したまま
//! 孤児にしない）。veth が無いと確認できた endpoint（quarantine 中のアドレス等）は削除を続けるが、
//! netns の pin が残っている、または有無を判定できない場合は、アドレスを解放せず保持して取り残しに載せる。
//!
//! # pin の置き場の照合
//!
//! 渡されていない endpoint の pin は、呼び出し側が渡すパスではなく、接続処理が払い出しと同時に IPAM へ
//! 記録した置き場（パスと、接続時に開いたディレクトリの識別子 (st_dev, st_ino)。`ipam::NetnsDirRecord`）の
//! 直下で確認する。別の空ディレクトリを渡されて残存 pin を見落とし、生存する netns のアドレスを
//! 再払い出ししないため。置き場が消えた・移動した・別のディレクトリに差し替わった・作成時の検査
//! （symlink でない・group / other 書き込み不可・実効 UID 所有）を満たさなくなった場合は、接続時の置き場と
//! 証明できないので、何も変更せずに `Preflight` で拒否する（fail-closed）。記録の無い払い出し
//! （`StaticIpam::reserve` で復元したもの）は pin の有無を判定できないため、アドレスを保持して
//! `Unknown` で報告する。渡されたコンテナは、`netns_path` が記録の置き場直下でなければ入力検証で拒否する。
//!
//! # 順序
//!
//! 入力検証 → 渡されていない endpoint の preflight（veth と pin の確認。ここまで何も変更しない）→ コンテナごとの veth の所有確認と削除・netns の unpin →
//! bridge の所有確認 → 専用 nft テーブルの所有確認と削除（配下の chain と DNAT ルールも消える）→ bridge の削除 →
//! 予約の解放。
//! 各段を可能な限り試し（best-effort）、取り残しを [`NetworkDeleteReport::leftover`] にまとめて `Err` で
//! 返す。最初のエラーは後続の失敗で上書きしない（ERR-1）。各段は「すでに無い」（`NotFound`）を完了扱いにする。
//! veth の削除に失敗したコンテナは unpin せず、unpin に失敗したコンテナと同様に netns ハンドルごと [`NetworkDeleteError::retry`] で返すので、取り残しを
//! 片付けてから（`retry` を `containers` に渡して）再実行すれば成功に収束する。
//!
//! IPAM のアドレスとポート予約は、専用テーブルが消えたと確認できた場合にだけ解放する（残った DNAT ルールが
//! 再払い出し先へ転送しないための quarantine を維持する）。アドレスはさらに、その endpoint の veth と netns が
//! 解放済みの場合に限る。
//!
//! # nft テーブルの所有
//!
//! テーブル名はネットワーク名からの導出で、名前だけでは所有を証明できない。そのため作成時にテーブルへ
//! 所有トークン（bridge と共通。`NFTA_TABLE_USERDATA`）を載せ、削除前に `NFT_MSG_GETTABLE` で照会して
//! トークンの一致を確認する。削除は照会で得たハンドル（`NFTA_TABLE_HANDLE`。カーネルが採番し再利用しない）
//! 指定で行い、確認後に同名の別テーブルへ差し替えられても巻き込まない。トークンやハンドルが無い（旧版で
//! 作ったテーブル等）・不一致・照会できない場合はテーブルに触れず `Unknown` で報告して予約を保持し、
//! 手動での確認・解放に委ねる（fail-closed）。照会でテーブルが無いと確認できれば、前回の削除で解放済みとして
//! 成功扱いにする（冪等）。bridge の所有確認（`IFLA_IFALIAS`）はテーブルとは独立で、bridge の削除にだけ使う。
//! bridge はテーブルの削除を確認してから消す（テーブルの削除に失敗したら bridge を残す）。
//!
//! # 作成失敗の回収（#2467）
//!
//! 作成（`create_network`）が資源を残して失敗したとき（`NetworkCreateError::rollback` の `leftover`）、
//! `NetworkCreateError::reclaim_claim` の請求書（[`FailedCreateClaim`]）で `reclaim_failed_create`
//! （Linux のみ）を呼ぶと、取り残した資源を所有の証明つきで回収できる。名前は請求書のネットワーク名から
//! 再導出し、請求書のトークンがそのネットワークの発行形式でなければ ops を呼ぶ前に `Validate` で拒否する。
//! nft テーブル → bridge の順に、請求書に載った資源だけを独立に照会する（載っていない資源、たとえば他者の
//! 同名テーブルとの衝突で作れなかったテーブルは照会もしない）。`delete_network` が bridge の削除を
//! テーブルの後まで待つのは veth の所有の証明（bridge への所属）を残すためだが、作成失敗には veth が無く、
//! テーブルの所有は自分の userdata で独立に証明できるため、ここでは待たない。「すでに無い」は成功扱い。
//! 確認から削除までの窓は `rollback_bridge` の doc と同じ残余リスクで、ここでは繰り返さない。
//!
//! 残余リスク（REPAIR-3）: 所有トークンを刻む前に失敗した bridge（`CreateBridge` の結果不明・`ResolveIndex`・
//! `SetOwnerToken` の失敗）は別名が空のため証明できず、回収は成功しない（手動回収）。他者の同名資源が
//! 残っている場合も同様。請求書の永続化は呼び出し側 plugin-cri の責務（#2604）。
//!
//! # attach の取り残しの回収（#2681）
//!
//! `attach_container` が資源を残して失敗したとき（`ContainerAttachError::rollback` の `leftover`）、
//! `ContainerAttachError::reclaim_claim` の請求書（[`FailedAttachClaim`]）で `reclaim_failed_attach`
//! （Linux のみ）を呼ぶと、host 側 veth と netns の pin を回収できる。veth は、別名が endpoint のトークン
//! （`host_owner_token`）に一致し、master が所有を確かめた bridge（`owned_bridge_index`）の ifindex に一致する
//! ときだけ、照会で得た ifindex で削除する。bridge が無い・不一致のときは veth の所属を証明できないため
//! `Unknown` のまま触れない。netns の pin は `netns::unpin_path` で外し、このプロセスの所有記録に照合できない
//! pin（再起動後のもの）は拒否されて取り残しになり、手動回収に回る（pin の実体の識別子を永続化して
//! プロセスをまたいで外す設計は未実装。担当 Issue 未確定）。quarantine（アドレス・DNAT ルール・ポート予約）は
//! プロセス内の保持で、解放は `delete_network` が行う。pin の置き場 `netns_dir` は請求書ではなく呼び出し側の
//! 固定設定から受ける。
//!
//! # veth の所有
//!
//! ifindex は削除後に再利用されうるため、ifindex だけでは veth の所有を証明できない。接続時に host 側
//! veth の `IFLA_IFALIAS` へ、接続ごとの世代（再接続で変わる）を含む所有トークンを刻み（`AttachedContainer::host_token`。形式は `host_owner_token`）、削除の直前に名前から
//! ifindex・別名・所属先 master を引き直して、ifindex が記録と一致し、別名がトークンと一致し、かつ master が
//! このネットワークの bridge であることを確認する。いずれかを満たさない link は元の veth と証明できないため
//! 削除せず `Unknown` で報告する。ifindex が記録と異なり別名もトークンと異なる場合は、同名の別 link への
//! 差し替えとみなし、元の veth は消失済みとして扱う。ifindex だけが異なりトークンが一致する場合は記録と実体の
//! 食い違いとして `Unknown` で報告する（生存 veth を消失済みとみなして unpin・アドレス解放に進まない）。
//!
//! `AttachedContainer` のフィールドは公開されていて呼び出し側が書き換えうるため、照合に使うトークンは
//! 入力検証でネットワークのトークンと endpoint から再導出した値（`host_owner_token`）と一致することを確かめる。
//! peer 名・pin のパスも同様に再導出・記録した値と照合し、食い違えば何も変更せずに拒否する。
//!
//! コンテナ側の資源（veth・netns pin）が残るあいだは bridge を削除しない。bridge が消えると veth の所有の
//! 証明（bridge への所属）を失い、再実行で残りを片付けられなくなるため（テーブルは先に削除してよい。
//! 再実行は `NotFound` を完了扱いにする）。
//!
//! # 残余リスクと未実装（REPAIR-3）
//!
//! - テーブルの所有トークンは `NFTA_TABLE_USERDATA` を保持するカーネルを前提とする。保持しない
//!   カーネルではトークンが読み戻せず、削除は拒否される（手動解放）
//! - link の dump API が無いため、IPAM に記録されていない孤児 veth は回収しない。担当 Issue 未確定
//! - コンテナ単体の切り離しと、プロセスをまたぐ残置 pin の清掃は未実装（attach の取り残しの veth は #2681 で回収できるが、
//!   pin は同じプロセス内に限る）。担当 Issue 未確定
//! - pin 置き場の記録は IPAM のメモリ上の状態で、永続化（IPAM 状態の永続化と同じく未実装・担当 Issue 未確定）
//!   されるまでは、復元した払い出しの pin を照合できない（上記のとおりアドレスを保持する）

use std::collections::HashSet;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
#[cfg(target_os = "linux")]
use crate::netlink_route::{LinkDelete, NetlinkRouteSocket};
#[cfg(target_os = "linux")]
use crate::netns::{self, ContainerNetns};
#[cfg(target_os = "linux")]
use crate::nftables_batch::{NetlinkNetfilterSocket, NftFamily, TableDelete, TableGet};
use crate::nftables_batch::{NftBatchOutcome, NftName, TableInfo};

#[cfg(target_os = "linux")]
use super::link_ref;
use super::{
    AttachedContainer, CreatedNetwork, EndpointId, FailedAttachClaim, FailedCreateClaim,
    NetnsDirRecord, NetworkName, NetworkResourceNames, NftApplyFailure, PortRegistry,
    ResourceState, StaticIpam, UnpinFailure, VethNames, host_owner_token, host_token_is_for,
    is_indeterminate, token_names_network,
};

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteStep {
    /// 入力の検証（何も変更しない）。
    Validate,
    /// 渡されていない endpoint の生存確認（何も変更しない）。
    Preflight,
    /// veth の削除。
    DeleteVeth,
    /// netns の pin 解除。
    UnpinNetns,
    /// 専用 nft テーブルの削除。
    DeleteNftTable,
    /// bridge の削除。
    DeleteBridge,
    /// IPAM・ポート予約の解放。
    ReleaseReservations,
}

/// 削除対象のリソース。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteResource {
    /// bridge。
    Bridge(IfName),
    /// 専用 nft テーブル。
    NftTable(NftName),
    /// veth ペア（host 側の名前）。
    Veth(IfName),
    /// pin 済みの netns（pin 先パス）。
    Netns(PathBuf),
    /// IPAM のアドレス。
    Address(EndpointId, IpPrefix),
    /// ポート予約（ネットワーク単位）。
    PortReservation(NetworkName),
}

/// ネットワーク削除の結果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkDeleteReport {
    /// 解放できたリソース。「すでに無かった」ものも含む。
    pub removed: Vec<DeleteResource>,
    /// 取り残したリソースとその状態（結果不明は fail-closed で `Unknown`）。
    pub leftover: Vec<(DeleteResource, ResourceState)>,
}

/// ネットワーク削除の失敗（最初の原因・失敗手順・解放の結果。ERR-1）。
#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkDeleteError<N = ()> {
    /// 最初の失敗の原因（後続の失敗で上書きしない）。
    pub error: NetError,
    /// 最初に失敗した手順。
    pub step: DeleteStep,
    /// ここまでに解放できたものと取り残し。
    pub report: NetworkDeleteReport,
    /// 解放を完了できなかったコンテナ（netns ハンドルを手放さずに返す）。入力検証・preflight の失敗では
    /// 渡された `containers` の全件が返る。`containers` にそのまま渡して再実行すると veth 削除と unpin を
    /// 再試行できる（ハンドルを drop すると fd が閉じ、再試行の経路を失うため）。
    pub retry: Vec<AttachedContainer<N>>,
}

impl<N> NetworkDeleteError<N> {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl<N> std::fmt::Display for NetworkDeleteError<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl<N: std::fmt::Debug> std::error::Error for NetworkDeleteError<N> {}

/// 削除手順が使うカーネル操作の境界。Linux 実装とテストの fake を差し替えるための crate 内部トレイトで、
/// 公開の拡張点（PLUG-1）ではない。作成・接続の trait とは独立。
pub(crate) trait DeleteOps {
    /// netns ハンドル（Linux では fd と pin パス）。
    type Netns;
    /// 名前から ifindex を引く。
    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError>;
    /// 名前から ifindex・所属先 master（bridge）の ifindex・別名（所有トークン）を引く。veth の所有確認に使う。
    fn link_attachment(&self, name: &IfName) -> Result<LinkAttachment, NetError>;
    /// bridge の名前から ifindex を引く。`IFLA_IFALIAS` が `token` と一致しなければ `FailedPrecondition`。
    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError>;
    /// ifindex 指定で link を削除する（veth は peer も消える）。
    fn delete_link(&self, link: IfIndex) -> Result<(), NetError>;
    /// pin を外す。失敗時はハンドルを返す。
    fn unpin_netns(&self, ns: Self::Netns) -> Result<(), UnpinFailure<Self::Netns>>;
    /// ハンドルを持たない pin をパスで外す（attach の取り残しの回収。#2681）。同じプロセスの所有記録に
    /// 照合できない pin は `FailedPrecondition` で拒否される（`netns::unpin_path`）。
    fn unpin_path(&self, pin: &Path) -> Result<(), NetError>;
    /// 接続時に記録した置き場 `dir` の直下に `endpoint` 名の pin が残っているか（`NotFound` だけが `Ok(false)`）。
    /// 置き場が記録と同じ実体と確認できなければ [`PinCheckError::Dir`]。何も変更しない。
    fn pin_exists(
        &self,
        dir: &NetnsDirRecord,
        endpoint: &EndpointId,
    ) -> Result<bool, PinCheckError>;
    /// 専用テーブルのハンドルとユーザーデータ（所有トークン）を引く（読み取り専用の照会）。無ければ `NotFound`。
    fn table_info(&self, table: &NftName) -> Result<TableInfo, NetError>;
    /// 専用テーブルをハンドル指定で削除する（配下の chain・ルールも消える）。名前では消さない。
    fn delete_table(&self, table: &NftName, handle: u64) -> Result<(), NftApplyFailure>;
}

/// 渡されていない endpoint の pin の残存確認の失敗。
// 構築するのは Linux 実装（`netns::pin_exists_in`）とテストの fake だけ。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum PinCheckError {
    /// 置き場が接続時に記録したものと同じ実体と確認できない（消失・移動・差し替え・検査違反）。
    /// 残存 pin を見落としうるので、削除は何も変更せずに拒否する。
    Dir(NetError),
    /// 置き場は記録どおりだが、pin の有無を判定できない。アドレスを保持して `Unknown` で報告する。
    Pin(NetError),
}

/// 名前で引いた link の所有確認用の属性。
pub(crate) struct LinkAttachment {
    pub(crate) index: IfIndex,
    pub(crate) master: Option<IfIndex>,
    /// `IFLA_IFALIAS`（所有トークン）。
    pub(crate) alias: Option<String>,
}

fn precondition(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, msg)
}

fn state_of(code: NetErrorCode) -> ResourceState {
    if is_indeterminate(code) {
        ResourceState::Unknown
    } else {
        ResourceState::Present
    }
}

/// 最初のエラーだけを保持する記録（ERR-1）。
#[derive(Default)]
struct Failures {
    first: Option<(NetError, DeleteStep)>,
}

impl Failures {
    fn note(&mut self, error: NetError, step: DeleteStep) {
        if self.first.is_none() {
            self.first = Some((error, step));
        }
    }
}

/// 何も変更せずに失敗する場合のエラーを作る。渡された `containers` は netns ハンドルごと `retry` へ返し、
/// 呼び出し側が pin 解除の経路を失わないようにする。
fn fail<N>(
    error: NetError,
    step: DeleteStep,
    report: NetworkDeleteReport,
    containers: Vec<AttachedContainer<N>>,
) -> NetworkDeleteError<N> {
    NetworkDeleteError {
        error,
        step,
        report,
        retry: containers,
    }
}

/// bridge の所有確認の結果。nft テーブルの所有の証明にも使う（モジュール doc「nft テーブルの所有」）。
/// `Gone` は証明にならない。
enum BridgeProof {
    /// 所有トークンと ifindex が一致した（このネットワークの bridge が生きている）。
    Owned,
    /// bridge が無い（前回の削除で解放済み）。
    Gone,
    /// 別 link への差し替え・判定不能。
    Unproven(NetError),
}

fn prove_bridge<O: DeleteOps>(ops: &O, network: &CreatedNetwork) -> BridgeProof {
    match ops.owned_bridge_index(&network.bridge, &network.bridge_token) {
        Ok(now) if now == network.bridge_index => BridgeProof::Owned,
        Ok(_) => BridgeProof::Unproven(precondition("bridge ifindex changed (link was replaced)")),
        Err(e) if e.code() == NetErrorCode::NotFound => BridgeProof::Gone,
        Err(e) => BridgeProof::Unproven(e),
    }
}

/// 専用 nft テーブルの所有確認の結果。作成時に `NFTA_TABLE_USERDATA` へ載せたトークンの一致で証明する。
enum TableProof {
    /// トークンが一致した。削除に使うハンドル。
    Owned(u64),
    /// テーブルが無い（前回の削除で解放済み）。
    Absent,
    /// 別者のテーブルへの差し替え・判定不能。
    Unproven(NetError),
}

fn prove_table<O: DeleteOps>(ops: &O, network: &CreatedNetwork) -> TableProof {
    prove_table_token(ops, &network.table, &network.bridge_token)
}

/// `table` の所有を、`token` と `NFTA_TABLE_USERDATA` の一致で証明する（作成失敗の回収でも共用。#2467）。
fn prove_table_token<O: DeleteOps>(ops: &O, table: &NftName, token: &str) -> TableProof {
    match ops.table_info(table) {
        Err(e) if e.code() == NetErrorCode::NotFound => TableProof::Absent,
        Err(e) => TableProof::Unproven(e),
        Ok(info) => match (info.handle(), info.userdata()) {
            (Some(handle), Some(data)) if data == token.as_bytes() => TableProof::Owned(handle),
            _ => TableProof::Unproven(precondition(
                "nft table ownership token mismatch (table was replaced or has no token)",
            )),
        },
    }
}

/// 削除手順本体（OS 非依存。`ops` を差し替えて 3 OS で単体テストできる）。手順と方針はモジュール doc。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn delete_network_with<O: DeleteOps>(
    ops: &O,
    network: &CreatedNetwork,
    containers: Vec<AttachedContainer<O::Netns>>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    let mut report = NetworkDeleteReport::default();

    // 0. 入力検証（何も変更しない）。`CreatedNetwork` も公開フィールドのため、bridge・テーブル名と
    //    所有トークンがネットワーク名から導出したものと食い違っていないことを確かめる。
    let consistent = NetworkResourceNames::derive(&network.name).is_ok_and(|n| {
        n.bridge() == &network.bridge
            && n.table() == &network.table
            && token_names_network(&network.bridge_token, &network.name)
    });
    if !consistent {
        return Err(fail(
            precondition("network handle is inconsistent with its name"),
            DeleteStep::Validate,
            report,
            containers,
        ));
    }
    if ipam.network() != &network.name || ipam.gateway() != network.gateway {
        return Err(fail(
            precondition("ipam does not belong to the network"),
            DeleteStep::Validate,
            report,
            containers,
        ));
    }
    let mut passed: HashSet<EndpointId> = HashSet::new();
    let mut invalid: Option<NetError> = None;
    for c in &containers {
        if !passed.insert(c.endpoint.clone()) {
            invalid = Some(NetError::new(
                NetErrorCode::InvalidArgument,
                "duplicate endpoint in containers",
            ));
            break;
        }
        match VethNames::derive(&c.endpoint) {
            Err(e) => {
                invalid = Some(e);
                break;
            }
            Ok(names) => {
                // 公開フィールドは呼び出し側が書き換えうるため、所有の判断に使う値はすべてネットワークと
                // IPAM から再導出した値と照合する。veth の所有トークンは bridge のトークンと endpoint から、
                // pin のパスは接続時に記録した置き場（記録があれば）から導く。
                let pin_mismatch = ipam
                    .netns_dir_of(&c.endpoint)
                    .is_some_and(|d| d.path().join(c.endpoint.as_str()) != c.netns_path);
                if ipam.address_of(&c.endpoint) != Some(c.address)
                    || names.host() != &c.host_veth
                    || names.peer() != &c.peer_veth
                    || !host_token_is_for(&network.bridge_token, &c.endpoint, &c.host_token)
                    || pin_mismatch
                {
                    invalid = Some(precondition("container does not belong to the network"));
                    break;
                }
            }
        }
    }
    if let Some(error) = invalid {
        return Err(fail(error, DeleteStep::Validate, report, containers));
    }

    // 1. preflight。渡されていない endpoint の veth が存在する（判定できない）なら何も触らず拒否する。
    let unpassed: Vec<EndpointId> = ipam
        .endpoints()
        .filter(|(e, _)| !passed.contains(*e))
        .map(|(e, _)| e.clone())
        .collect();
    // アドレスを解放してよい endpoint（veth・netns とも解放済み）。
    let mut releasable: Vec<EndpointId> = Vec::new();
    // veth は無いが pin が残っている（または判定できない）endpoint。アドレスを保持して報告する。
    let mut pin_kept: Vec<(DeleteResource, ResourceState, NetError)> = Vec::new();
    for endpoint in unpassed {
        let names = match VethNames::derive(&endpoint) {
            Ok(n) => n,
            Err(e) => {
                return Err(fail(
                    e,
                    DeleteStep::Preflight,
                    NetworkDeleteReport::default(),
                    containers,
                ));
            }
        };
        match ops.link_index(names.host()) {
            Err(e) if e.code() == NetErrorCode::NotFound => {
                // veth が無くても netns の pin が残っていれば、中のコンテナは生きているかもしれない。
                // pin は接続時に記録した置き場で確認する（モジュール doc「pin の置き場の照合」）。
                let Some(dir) = ipam.netns_dir_of(&endpoint) else {
                    // 置き場の記録が無い（`reserve` で復元した払い出し）。pin の有無を判定できない。
                    let address = ipam.address_of(&endpoint);
                    if let Some(address) = address {
                        pin_kept.push((
                            DeleteResource::Address(endpoint, address),
                            ResourceState::Unknown,
                            precondition("netns directory of an unpassed endpoint is not recorded"),
                        ));
                    }
                    continue;
                };
                let pin = DeleteResource::Netns(dir.path().join(endpoint.as_str()));
                match ops.pin_exists(dir, &endpoint) {
                    Ok(false) => releasable.push(endpoint),
                    Ok(true) => pin_kept.push((
                        pin,
                        ResourceState::Present,
                        precondition("netns pin of an unpassed endpoint remains"),
                    )),
                    Err(PinCheckError::Pin(e)) => pin_kept.push((pin, ResourceState::Unknown, e)),
                    Err(PinCheckError::Dir(e)) => {
                        // 接続時の置き場と証明できない。残存 pin を見落としうるので何も変更せずに拒否する。
                        return Err(fail(
                            e,
                            DeleteStep::Preflight,
                            NetworkDeleteReport::default(),
                            containers,
                        ));
                    }
                }
            }
            _ => {
                return Err(fail(
                    precondition("a live container is attached but not passed to delete"),
                    DeleteStep::Preflight,
                    report,
                    containers,
                ));
            }
        }
    }

    let mut failures = Failures::default();
    // コンテナ側の資源（veth・netns pin）がすべて解放済みか。残るあいだは bridge を消さず、
    // 再実行で所有の証明を再利用できるようにする。
    let mut containers_clear = pin_kept.is_empty();
    for (resource, state, error) in pin_kept {
        report.leftover.push((resource, state));
        failures.note(error, DeleteStep::Preflight);
    }
    let mut retry: Vec<AttachedContainer<O::Netns>> = Vec::new();

    // 2. コンテナ側の解放。veth を ifindex 指定で消してから pin を外す。
    for c in containers {
        let AttachedContainer {
            endpoint,
            host_veth,
            host_index,
            host_token,
            peer_veth,
            netns_path,
            address,
            netns,
        } = c;
        let veth_gone = delete_veth(
            ops,
            &host_veth,
            host_index,
            &host_token,
            network.bridge_index,
            &mut report,
            &mut failures,
        );
        // veth が残っているなら unpin しない。ハンドルを消費すると再試行で veth を消す経路を失い、
        // 残った veth が IPAM 上の生存 endpoint として次回の preflight に拒否され続ける。
        let unpinned = if !veth_gone {
            report.leftover.push((
                DeleteResource::Netns(netns_path.clone()),
                ResourceState::Present,
            ));
            retry.push(AttachedContainer {
                endpoint: endpoint.clone(),
                host_veth,
                host_index,
                host_token,
                peer_veth,
                netns_path,
                address,
                netns,
            });
            false
        } else {
            match ops.unpin_netns(netns) {
                Ok(()) => {
                    report.removed.push(DeleteResource::Netns(netns_path));
                    true
                }
                Err(UnpinFailure { error, netns }) => {
                    report.leftover.push((
                        DeleteResource::Netns(netns_path.clone()),
                        state_of(error.code()),
                    ));
                    failures.note(error, DeleteStep::UnpinNetns);
                    // ハンドルを手放さず呼び出し側へ返し、再試行の経路を保つ。
                    retry.push(AttachedContainer {
                        endpoint: endpoint.clone(),
                        host_veth,
                        host_index,
                        host_token,
                        peer_veth,
                        netns_path,
                        address,
                        netns,
                    });
                    false
                }
            }
        };
        if veth_gone && unpinned {
            releasable.push(endpoint);
        }
    }

    containers_clear &= retry.is_empty();

    // 3. 専用 nft テーブル。作成時に載せた所有トークン（NFTA_TABLE_USERDATA）の一致を確認し、確認した個体を
    //    ハンドル指定で削除する（確認後に同名の別テーブルへ差し替えられても巻き込まない）。証明できなければ触れない。
    let proof = prove_bridge(ops, network);
    let table_gone = match prove_table(ops, network) {
        TableProof::Absent => true,
        TableProof::Unproven(e) => {
            report.leftover.push((
                DeleteResource::NftTable(network.table.clone()),
                ResourceState::Unknown,
            ));
            failures.note(e, DeleteStep::DeleteNftTable);
            false
        }
        TableProof::Owned(handle) => match ops.delete_table(&network.table, handle) {
            Ok(()) => true,
            // `Aborted` + `NotFound` は「すでに無い」（冪等）。
            Err(f)
                if f.outcome == NftBatchOutcome::Aborted
                    && f.error.code() == NetErrorCode::NotFound =>
            {
                true
            }
            Err(f) => {
                let state = if f.outcome == NftBatchOutcome::Unknown {
                    ResourceState::Unknown
                } else {
                    ResourceState::Present
                };
                report
                    .leftover
                    .push((DeleteResource::NftTable(network.table.clone()), state));
                failures.note(f.error, DeleteStep::DeleteNftTable);
                false
            }
        },
    };
    if table_gone {
        report
            .removed
            .push(DeleteResource::NftTable(network.table.clone()));
    }

    // 4. bridge。テーブルが消えたと確認できてから ifindex 指定で消す（失敗時に所有の証明を残し、再実行で収束させる）。
    delete_bridge(
        ops,
        network,
        proof,
        table_gone && containers_clear,
        &mut report,
        &mut failures,
    );

    // 5. 予約の解放。テーブルが消えたと確認できた場合だけ。
    if table_gone {
        match ports.release_network(&network.name) {
            Ok(_) => report
                .removed
                .push(DeleteResource::PortReservation(network.name.clone())),
            Err(e) => {
                report.leftover.push((
                    DeleteResource::PortReservation(network.name.clone()),
                    ResourceState::Present,
                ));
                failures.note(e, DeleteStep::ReleaseReservations);
            }
        }
        for endpoint in releasable {
            if let Ok(addr) = ipam.release(&endpoint) {
                report.removed.push(DeleteResource::Address(endpoint, addr));
            }
        }
    }

    match failures.first {
        None => Ok(report),
        Some((error, step)) => Err(NetworkDeleteError {
            error,
            step,
            report,
            retry,
        }),
    }
}

/// 作成失敗で取り残した bridge・nft テーブルを、所有を証明してから回収する本体（OS 非依存。#2467）。
/// 手順と方針はモジュール doc「作成失敗の回収」。各資源は独立に扱い、最初のエラーだけを保持する（ERR-1）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn reclaim_failed_create_with<O: DeleteOps>(
    ops: &O,
    claim: &FailedCreateClaim,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    let mut report = NetworkDeleteReport::default();
    let mut failures = Failures::default();
    let token = claim.token();

    // 1. 入力検証（カーネル I/O の前）。名前は請求書のネットワーク名から再導出し、トークンがそのネット
    //    ワークの発行形式でなければ（空・別ネットワーク）何も触れずに拒否する。
    let names = match NetworkResourceNames::derive(claim.network()) {
        Ok(n) if token_names_network(token, claim.network()) => n,
        Ok(_) => {
            return Err(fail(
                precondition("reclaim token does not belong to the network"),
                DeleteStep::Validate,
                report,
                Vec::new(),
            ));
        }
        Err(e) => return Err(fail(e, DeleteStep::Validate, report, Vec::new())),
    };

    // 2. nft テーブル（請求書に載った場合だけ照会する）。
    if claim.includes_table() {
        let table = names.table();
        let res = DeleteResource::NftTable(table.clone());
        match prove_table_token(ops, table, token) {
            TableProof::Absent => report.removed.push(res),
            TableProof::Unproven(e) => {
                report.leftover.push((res, ResourceState::Unknown));
                failures.note(e, DeleteStep::DeleteNftTable);
            }
            TableProof::Owned(handle) => match ops.delete_table(table, handle) {
                Ok(()) => report.removed.push(res),
                Err(f)
                    if f.outcome == NftBatchOutcome::Aborted
                        && f.error.code() == NetErrorCode::NotFound =>
                {
                    report.removed.push(res);
                }
                Err(f) => {
                    let state = if f.outcome == NftBatchOutcome::Unknown {
                        ResourceState::Unknown
                    } else {
                        ResourceState::Present
                    };
                    report.leftover.push((res, state));
                    failures.note(f.error, DeleteStep::DeleteNftTable);
                }
            },
        }
    }

    // 3. bridge（請求書に載った場合だけ）。別名がトークンと一致するときだけ、照会で得た ifindex で消す。
    if claim.includes_bridge() {
        let bridge = names.bridge();
        let res = DeleteResource::Bridge(bridge.clone());
        match ops.owned_bridge_index(bridge, token) {
            Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
            Err(e) => {
                // 別名の不一致・空（トークン未付与の bridge を含む）・判定不能。触れない。
                report.leftover.push((res, ResourceState::Unknown));
                failures.note(e, DeleteStep::DeleteBridge);
            }
            Ok(index) => match ops.delete_link(index) {
                Ok(()) => report.removed.push(res),
                Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
                Err(e) => {
                    report.leftover.push((res, state_of(e.code())));
                    failures.note(e, DeleteStep::DeleteBridge);
                }
            },
        }
    }

    match failures.first {
        None => Ok(report),
        Some((error, step)) => Err(fail(error, step, report, Vec::new())),
    }
}

/// attach の巻き戻しで取り残した veth・netns の pin を、所有を証明してから回収する本体（OS 非依存。#2681）。
/// 手順と方針はモジュール doc「attach の取り残しの回収」。各資源は独立に扱い、最初のエラーだけを保持する（ERR-1）。
/// `netns_dir` は呼び出し側の固定設定で、請求書の内容からは受けない。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn reclaim_failed_attach_with<O: DeleteOps>(
    ops: &O,
    claim: &FailedAttachClaim,
    netns_dir: &Path,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    let mut report = NetworkDeleteReport::default();
    let mut failures = Failures::default();
    let token = claim.token();

    // 1. 入力検証（カーネル I/O の前）。名前は請求書から再導出し、トークンがそのネットワークの発行形式で
    //    なければ何も触れずに拒否する。
    let validated = NetworkResourceNames::derive(claim.network())
        .and_then(|n| VethNames::derive(claim.endpoint()).map(|v| (n, v)));
    let (names, veth_names) = match validated {
        Ok(p) if token_names_network(token, claim.network()) => p,
        Ok(_) => {
            return Err(fail(
                precondition("reclaim token does not belong to the network"),
                DeleteStep::Validate,
                report,
                Vec::new(),
            ));
        }
        Err(e) => return Err(fail(e, DeleteStep::Validate, report, Vec::new())),
    };

    // 2. host 側 veth。別名が endpoint のトークンと一致し、master が所有を確かめた bridge と一致するときだけ、
    //    照会で得た ifindex で消す。名前では消さない。
    if claim.includes_veth() {
        let host = veth_names.host();
        let res = DeleteResource::Veth(host.clone());
        match ops.link_attachment(host) {
            Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
            Err(e) => {
                report.leftover.push((res, ResourceState::Unknown));
                failures.note(e, DeleteStep::DeleteVeth);
            }
            Ok(att) => {
                let want = host_owner_token(token, claim.endpoint(), claim.generation());
                let bridge = ops.owned_bridge_index(names.bridge(), token);
                match bridge {
                    Err(e) => {
                        // bridge が無い・差し替え・判定不能では veth の所属を証明できない。触れない。
                        report.leftover.push((res, ResourceState::Unknown));
                        failures.note(e, DeleteStep::DeleteVeth);
                    }
                    Ok(_) if att.alias.as_deref() != Some(want.as_str()) => {
                        report.leftover.push((res, ResourceState::Unknown));
                        failures.note(
                            precondition("veth ownership token mismatch (ownership not proven)"),
                            DeleteStep::DeleteVeth,
                        );
                    }
                    Ok(b) if att.master != Some(b) => {
                        report.leftover.push((res, ResourceState::Unknown));
                        failures.note(
                            precondition(
                                "veth is not attached to the network bridge (ownership not proven)",
                            ),
                            DeleteStep::DeleteVeth,
                        );
                    }
                    Ok(_) => match ops.delete_link(att.index) {
                        Ok(()) => report.removed.push(res),
                        Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
                        Err(e) => {
                            report.leftover.push((res, state_of(e.code())));
                            failures.note(e, DeleteStep::DeleteVeth);
                        }
                    },
                }
            }
        }
    }

    // 3. netns の pin。プロセスの所有記録に照合できる pin だけを外せる。再起動後の pin は拒否されて
    //    取り残しになり、手動回収に回る（fail-closed）。
    if claim.includes_netns() {
        let pin = netns_dir.join(claim.endpoint().as_str());
        let res = DeleteResource::Netns(pin.clone());
        match ops.unpin_path(&pin) {
            Ok(()) => report.removed.push(res),
            Err(e) => {
                report.leftover.push((res, state_of(e.code())));
                failures.note(e, DeleteStep::UnpinNetns);
            }
        }
    }

    match failures.first {
        None => Ok(report),
        Some((error, step)) => Err(fail(error, step, report, Vec::new())),
    }
}

/// veth を ifindex 指定で削除する。消えている（または今回消せた）なら `true`。
fn delete_veth<O: DeleteOps>(
    ops: &O,
    host: &IfName,
    expected: IfIndex,
    token: &str,
    bridge_index: IfIndex,
    report: &mut NetworkDeleteReport,
    failures: &mut Failures,
) -> bool {
    let res = DeleteResource::Veth(host.clone());
    match ops.link_attachment(host) {
        Err(e) if e.code() == NetErrorCode::NotFound => {
            report.removed.push(res);
            true
        }
        Err(e) => {
            // 存在を確認できない。名前では消さない。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(e, DeleteStep::DeleteVeth);
            false
        }
        Ok(LinkAttachment {
            index: now, alias, ..
        }) if now != expected => {
            if alias.as_deref() == Some(token) {
                // 所有トークンは一致するのに ifindex が記録と異なる。host 側 veth の ifindex は生存中に
                // 変わらないため、渡された記録（`host_index`）が実体と食い違っている。この link を消失済みと
                // 扱うと生存 veth を残したまま unpin とアドレス解放に進むので、削除も unpin もしない（fail-closed）。
                report.leftover.push((res, ResourceState::Unknown));
                failures.note(
                    precondition("veth carries the ownership token but its ifindex differs"),
                    DeleteStep::DeleteVeth,
                );
                return false;
            }
            // 記録した ifindex の link は消えている（同名の別 link に差し替わった）。別 link は巻き込まず、
            // 消失済みとして扱い、pin の解除とアドレス解放に進めるようにする。
            report.removed.push(res);
            true
        }
        Ok(LinkAttachment { alias, .. }) if alias.as_deref() != Some(token) => {
            // 名前と ifindex は一致するが、所有トークンが一致しない。ifindex は再利用されうるため、
            // 元の veth と証明できない（再利用された別 link・トークンの欠落）。削除しない（fail-closed）。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(
                precondition("veth ownership token mismatch (ownership not proven)"),
                DeleteStep::DeleteVeth,
            );
            false
        }
        Ok(LinkAttachment { master, .. }) if master != Some(bridge_index) => {
            // 名前・ifindex・トークンは一致するが、このネットワークの bridge に属していない。元の接続状態と
            // 異なるので削除しない（fail-closed）。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(
                precondition("veth is not attached to the network bridge (ownership not proven)"),
                DeleteStep::DeleteVeth,
            );
            false
        }
        Ok(_) => match ops.delete_link(expected) {
            Ok(()) => {
                report.removed.push(res);
                true
            }
            Err(e) if e.code() == NetErrorCode::NotFound => {
                report.removed.push(res);
                true
            }
            Err(e) => {
                report.leftover.push((res, state_of(e.code())));
                failures.note(e, DeleteStep::DeleteVeth);
                false
            }
        },
    }
}

/// bridge を、確認済みの所有（`proof`）に基づいて削除する。`table_gone`（テーブル削除済みかつコンテナ側の資源が解放済み）でなければ削除しない
/// （テーブルの所有の証明となる bridge を残し、再実行で収束させる）。
fn delete_bridge<O: DeleteOps>(
    ops: &O,
    network: &CreatedNetwork,
    proof: BridgeProof,
    table_gone: bool,
    report: &mut NetworkDeleteReport,
    failures: &mut Failures,
) {
    let res = DeleteResource::Bridge(network.bridge.clone());
    match proof {
        BridgeProof::Gone => report.removed.push(res),
        BridgeProof::Unproven(e) => {
            // トークン不一致・判定不能。別 link を巻き込まない。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(e, DeleteStep::DeleteBridge);
        }
        BridgeProof::Owned if !table_gone => {
            report.leftover.push((res, ResourceState::Present));
        }
        BridgeProof::Owned => match ops.delete_link(network.bridge_index) {
            Ok(()) => report.removed.push(res),
            Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
            Err(e) => {
                report.leftover.push((res, state_of(e.code())));
                failures.note(e, DeleteStep::DeleteBridge);
            }
        },
    }
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
#[cfg(target_os = "linux")]
struct LinuxDeleteOps<'a> {
    route: &'a NetlinkRouteSocket,
    nft: &'a NetlinkNetfilterSocket,
    timeout: Duration,
}

#[cfg(target_os = "linux")]
impl DeleteOps for LinuxDeleteOps<'_> {
    type Netns = ContainerNetns;

    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
        self.route.link_index(name, self.timeout)
    }

    fn link_attachment(&self, name: &IfName) -> Result<LinkAttachment, NetError> {
        let (index, master, alias) = self.route.link_index_master_alias(name, self.timeout)?;
        Ok(LinkAttachment {
            index,
            master,
            alias,
        })
    }

    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
        self.route.link_index_owned(name, token, self.timeout)
    }

    fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
        self.route
            .delete_link(&LinkDelete::new(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn unpin_netns(&self, ns: ContainerNetns) -> Result<(), UnpinFailure<ContainerNetns>> {
        netns::unpin(ns)
    }

    fn unpin_path(&self, pin: &Path) -> Result<(), NetError> {
        netns::unpin_path(pin)
    }

    fn pin_exists(
        &self,
        dir: &NetnsDirRecord,
        endpoint: &EndpointId,
    ) -> Result<bool, PinCheckError> {
        netns::pin_exists_in(dir.path(), dir.dir_id(), endpoint)
    }

    fn table_info(&self, table: &NftName) -> Result<TableInfo, NetError> {
        self.nft
            .table_info(&TableGet::new(NftFamily::Ipv4, table.clone()), self.timeout)
    }

    fn delete_table(&self, table: &NftName, handle: u64) -> Result<(), NftApplyFailure> {
        self.nft
            .send_batch(self.timeout, |batch| {
                batch.push_with(|seq| {
                    TableDelete::by_handle(NftFamily::Ipv4, table.clone(), handle).build(seq)
                })?;
                Ok(())
            })
            .map(|_| ())
            .map_err(|e| NftApplyFailure {
                outcome: e.outcome(),
                error: e.into(),
            })
    }
}

/// ネットワークを削除する（コンテナ側の veth・netns pin → 専用 nft テーブル → bridge → IPAM・ポート予約）。
///
/// `containers` は接続中のコンテナで、渡されたものを明示的に解放する。渡されていない生存コンテナがあれば
/// 何も変更せず `FailedPrecondition` で拒否する（モジュール doc「参加中のコンテナの扱い」）。
/// 取り残しがあれば `Err` で、[`NetworkDeleteError::report`] に解放済みと取り残しを全件載せる。
/// `CAP_NET_ADMIN` と、unpin に必要な `CAP_SYS_ADMIN` は呼び出し側の責務で、本 crate は権限を上げない。
/// 渡されていない endpoint の pin の残存は、接続時に IPAM へ記録した置き場で確認する（呼び出し側はパスを
/// 渡さない。置き場が接続時と同じ実体と確認できなければ何も変更せず拒否する。モジュール doc「pin の置き場の照合」）。
/// pin の解除に失敗したコンテナは [`NetworkDeleteError::retry`] で netns ハンドルごと返る。
/// `timeout` は各カーネル要求の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn delete_network(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    network: &CreatedNetwork,
    containers: Vec<AttachedContainer<ContainerNetns>>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    delete_network_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
        },
        network,
        containers,
        ipam,
        ports,
    )
}

/// 作成失敗で取り残した bridge・nft テーブルを、所有を証明してから回収する（NET-1・NET-4・#2467）。
///
/// `claim` は `NetworkCreateError::reclaim_claim` が返した請求書で、外部入力から作れない。bridge は
/// `IFLA_IFALIAS`、テーブルは `NFTA_TABLE_USERDATA` が作成時のトークンと一致する場合だけ、照会で得た
/// ifindex・ハンドル指定で削除する。不一致・判定不能は触れずに `Unknown` で報告する（fail-closed）。
/// 取り残しがあれば `Err` で、`report` に解放済みと取り残しを載せる。`CAP_NET_ADMIN` は呼び出し側の責務。
/// `timeout` は各カーネル要求の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn reclaim_failed_create(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    claim: &FailedCreateClaim,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    reclaim_failed_create_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
        },
        claim,
    )
}

/// attach の巻き戻しで取り残した veth・netns の pin を、所有を証明してから回収する（NET-1・#2681）。
///
/// `claim` は `ContainerAttachError::reclaim_claim` か、plugin 自身が書いた記録の復号
/// （`FailedAttachClaim::from_record`）で得る。host 側 veth は、別名が endpoint のトークンに一致し、
/// master が所有を確かめた bridge に一致する場合だけ、照会で得た ifindex で削除する。不一致・判定不能は
/// 触れずに `Unknown` で報告する（fail-closed）。netns の pin は、このプロセスが作ったものだけを外せる
/// （再起動後の pin は `FailedPrecondition` で取り残しになる）。`netns_dir` は呼び出し側の固定設定で、
/// 記録からは受けない。取り残しがあれば `Err` で、`report` に解放済みと取り残しを載せる。
/// `CAP_NET_ADMIN`（と unpin の `CAP_SYS_ADMIN`）は呼び出し側の責務。`timeout` は各カーネル要求の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn reclaim_failed_attach(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    claim: &FailedAttachClaim,
    netns_dir: &Path,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    reclaim_failed_attach_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
        },
        claim,
        netns_dir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink_route::IfIndex;
    use crate::network::NetworkResourceNames;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    const TOKEN: &str = "fandhe-net:web:1:0:0";
    /// 接続時に記録した pin 置き場の識別子 (st_dev, st_ino)。
    const DIR_ID: (u64, u64) = (8, 9);

    fn eid(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    fn created() -> CreatedNetwork {
        let names = NetworkResourceNames::derive(&NetworkName::new("web").unwrap()).unwrap();
        CreatedNetwork {
            name: NetworkName::new("web").unwrap(),
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).unwrap(),
            name_resolution: Default::default(),
        }
    }

    fn err(code: NetErrorCode) -> NetError {
        NetError::new(code, "injected")
    }

    /// 呼び出しを記録し、失敗を注入する fake。veth の ifindex は 21 固定。
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        /// veth が存在しない endpoint の host 名に含まれる印は使わず、名前集合で指定する。
        absent_veths: Vec<String>,
        veth_lookup_err: Option<NetErrorCode>,
        veth_index: Option<u32>,
        veth_delete_err: Option<NetErrorCode>,
        unpin_fails: bool,
        /// `unpin_path` の失敗。
        unpin_path_err: Option<NetErrorCode>,
        /// pin が残っている（`Ok(true)`）とみなす endpoint 名。
        pins_present: Vec<PathBuf>,
        pin_check_err: bool,
        /// 置き場の現在の識別子。`None` は接続時と同じ `DIR_ID`。
        dir_id_now: Option<(u64, u64)>,
        /// 置き場を開けない（消失・検査違反）とみなすときのエラー。
        dir_open_err: Option<NetErrorCode>,
        table_err: Option<(NetErrorCode, NftBatchOutcome)>,
        /// 照会（`table_info`）で専用テーブルが存在しない（`NotFound`）とみなすか。
        table_absent: bool,
        /// 照会（`table_info`）の失敗。
        table_query_err: Option<NetErrorCode>,
        /// テーブルのユーザーデータ。`None` は所有トークン（`TOKEN`）。
        table_userdata: Option<Vec<u8>>,
        /// ハンドルを持たない応答にするか。
        table_no_handle: bool,
        /// veth の所属先 master。`None` は bridge（ifindex 7）、`Some(None)` は master なし。
        veth_master: Option<Option<u32>>,
        /// veth の別名（所有トークン）。`None` は名前に対応する endpoint の正しいトークン（`token_of`）、
        /// `Some(None)` は別名なし。
        veth_alias: Option<Option<String>>,
        bridge_lookup_err: Option<NetErrorCode>,
        bridge_index: Option<u32>,
        bridge_delete_err: Option<NetErrorCode>,
    }

    impl Fake {
        fn rec(&self, s: impl Into<String>) {
            self.calls.borrow_mut().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        fn link_index_inner(&self, name: &IfName) -> Result<IfIndex, NetError> {
            if self.absent_veths.iter().any(|n| n == name.as_str()) {
                return Err(err(NetErrorCode::NotFound));
            }
            if let Some(c) = self.veth_lookup_err {
                return Err(err(c));
            }
            IfIndex::new(self.veth_index.unwrap_or(21))
        }
    }

    impl DeleteOps for Fake {
        type Netns = ();

        fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
            self.rec(format!("link_index {}", name.as_str()));
            self.link_index_inner(name)
        }
        fn link_attachment(&self, name: &IfName) -> Result<LinkAttachment, NetError> {
            self.rec(format!("link_attachment {}", name.as_str()));
            let index = self.link_index_inner(name)?;
            let master = self.veth_master.unwrap_or(Some(7));
            Ok(LinkAttachment {
                index,
                master: master.and_then(|m| IfIndex::new(m).ok()),
                alias: self
                    .veth_alias
                    .clone()
                    .unwrap_or_else(|| token_for_host(name)),
            })
        }
        fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
            self.rec(format!("owned_bridge_index {}", name.as_str()));
            if token != TOKEN {
                return Err(err(NetErrorCode::FailedPrecondition));
            }
            if let Some(c) = self.bridge_lookup_err {
                return Err(err(c));
            }
            IfIndex::new(self.bridge_index.unwrap_or(7))
        }
        fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
            self.rec(format!("delete_link {}", link.get()));
            let e = if link.get() == 7 {
                self.bridge_delete_err
            } else {
                self.veth_delete_err
            };
            e.map_or(Ok(()), |c| Err(err(c)))
        }
        fn unpin_path(&self, pin: &Path) -> Result<(), NetError> {
            self.rec(format!("unpin_path {}", pin.display()));
            match self.unpin_path_err {
                Some(c) => Err(err(c)),
                None => Ok(()),
            }
        }
        fn unpin_netns(&self, (): ()) -> Result<(), UnpinFailure<()>> {
            self.rec("unpin_netns");
            if self.unpin_fails {
                Err(UnpinFailure {
                    error: err(NetErrorCode::Internal),
                    netns: (),
                })
            } else {
                Ok(())
            }
        }
        fn pin_exists(
            &self,
            dir: &NetnsDirRecord,
            endpoint: &EndpointId,
        ) -> Result<bool, PinCheckError> {
            let path = dir.path().join(endpoint.as_str());
            self.rec(format!("pin_exists {}", path.display()));
            // Linux 実装（`netns::pin_exists_in`）と同じく、置き場の実体を照合してから pin を見る。
            if let Some(c) = self.dir_open_err {
                return Err(PinCheckError::Dir(err(c)));
            }
            if self.dir_id_now.unwrap_or(DIR_ID) != dir.dir_id() {
                return Err(PinCheckError::Dir(err(NetErrorCode::FailedPrecondition)));
            }
            if self.pin_check_err {
                return Err(PinCheckError::Pin(err(NetErrorCode::Internal)));
            }
            Ok(self.pins_present.iter().any(|p| p == &path))
        }
        fn table_info(&self, table: &NftName) -> Result<TableInfo, NetError> {
            self.rec(format!("table_info {}", table.as_str()));
            if let Some(c) = self.table_query_err {
                return Err(err(c));
            }
            if self.table_absent {
                return Err(err(NetErrorCode::NotFound));
            }
            // nfgenmsg + NFTA_TABLE_HANDLE(4) + NFTA_TABLE_USERDATA(6) の応答を組み、実際の復号を通す。
            let mut p = vec![2u8, 0, 0, 0];
            let mut put = |ty: u16, data: &[u8]| {
                p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
                p.extend_from_slice(&ty.to_ne_bytes());
                p.extend_from_slice(data);
                while p.len() % 4 != 0 {
                    p.push(0);
                }
            };
            if !self.table_no_handle {
                put(4, &99u64.to_be_bytes());
            }
            put(
                6,
                self.table_userdata.as_deref().unwrap_or(TOKEN.as_bytes()),
            );
            TableInfo::decode(&p)
        }
        fn delete_table(&self, table: &NftName, handle: u64) -> Result<(), NftApplyFailure> {
            self.rec(format!("delete_table {} handle={handle}", table.as_str()));
            match self.table_err {
                Some((c, outcome)) => Err(NftApplyFailure {
                    error: err(c),
                    outcome,
                }),
                None => Ok(()),
            }
        }
    }

    fn host_of(id: &str) -> IfName {
        VethNames::derive(&eid(id)).unwrap().host().clone()
    }

    /// テストの接続の世代識別子。
    const GEN: &str = "0123456789abcdef0123456789abcdef";
    /// 取り残しの請求書が別の（古い）接続のものであることを表す世代識別子。
    const OLD_GEN: &str = "fedcba9876543210fedcba9876543210";

    /// 接続処理と同じ導出の、endpoint `id` の veth 所有トークン。
    fn token_of(id: &str) -> String {
        host_owner_token(TOKEN, &eid(id), GEN)
    }

    /// fake が名前から引く veth の別名（テストで使う endpoint のうち host 名が一致するもののトークン）。
    fn token_for_host(name: &IfName) -> Option<String> {
        ["c1", "c2", "c3", "q1"]
            .into_iter()
            .find(|id| host_of(id) == *name)
            .map(token_of)
    }

    fn netns_dir() -> PathBuf {
        std::env::temp_dir().join("fc-netns")
    }

    fn pin(id: &str) -> PathBuf {
        netns_dir().join(id)
    }

    /// `ipam` へ払い出した endpoint を `AttachedContainer` として組む。
    fn attached(ipam: &mut StaticIpam, id: &str) -> AttachedContainer<()> {
        let endpoint = eid(id);
        let address = ipam
            .allocate_pinned(&endpoint, NetnsDirRecord::new(netns_dir(), DIR_ID))
            .unwrap();
        let names = VethNames::derive(&endpoint).unwrap();
        AttachedContainer {
            endpoint,
            host_veth: names.host().clone(),
            host_index: IfIndex::new(21).unwrap(),
            host_token: token_of(id),
            peer_veth: names.peer().clone(),
            netns_path: pin(id),
            address,
            netns: (),
        }
    }

    fn setup() -> (CreatedNetwork, StaticIpam, PortRegistry) {
        let net = created();
        let ipam = StaticIpam::for_network(&net).unwrap();
        (net, ipam, PortRegistry::new())
    }

    fn reserve_port(ports: &mut PortRegistry, id: &str, host_port: u16) {
        use crate::network::{PortProtocol, PortPublish};
        let p = PortPublish::new(
            PortProtocol::Tcp,
            Ipv4Addr::new(192, 0, 2, 10),
            host_port,
            80,
        )
        .unwrap();
        ports
            .reserve(&NetworkName::new("web").unwrap(), &eid(id), &[p])
            .unwrap();
    }

    /// NET-1・TASK-139.4: 正常系は veth → unpin → テーブル → bridge の順に解放し、IPAM と予約が空になる。
    #[test]
    fn net1_delete_success_releases_everything() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let addr = c1.address;
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake::default();
        let report = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap();
        let host = host_of("c1");
        assert_eq!(
            fake.calls(),
            vec![
                format!("link_attachment {}", host.as_str()),
                "delete_link 21".to_owned(),
                "unpin_netns".to_owned(),
                format!("owned_bridge_index {}", net.bridge.as_str()),
                format!("table_info {}", net.table.as_str()),
                format!("delete_table {} handle=99", net.table.as_str()),
                "delete_link 7".to_owned(),
            ]
        );
        assert_eq!(
            report.removed,
            vec![
                DeleteResource::Veth(host),
                DeleteResource::Netns(pin("c1")),
                DeleteResource::NftTable(net.table.clone()),
                DeleteResource::Bridge(net.bridge.clone()),
                DeleteResource::PortReservation(net.name.clone()),
                DeleteResource::Address(eid("c1"), addr),
            ]
        );
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
        assert!(ports.is_empty());
    }

    /// NET-1・TASK-139.4: 渡されていない endpoint の veth が存在すると、何も変更せず拒否する。
    #[test]
    fn net1_delete_rejects_unpassed_live_endpoint() {
        let (net, mut ipam, mut ports) = setup();
        let _unpassed = attached(&mut ipam, "c1");
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.step, DeleteStep::Preflight);
        assert_eq!(
            fake.calls(),
            vec![format!("link_index {}", host_of("c1").as_str())]
        );
        assert_eq!(ipam.allocated_count(), 1);
    }

    /// NET-1・TASK-139.4: preflight で veth の有無を判定できない（`Timeout`）場合も拒否する。
    #[test]
    fn net1_delete_preflight_timeout_rejects() {
        let (net, mut ipam, mut ports) = setup();
        let _unpassed = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_lookup_err: Some(NetErrorCode::Timeout),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.step, DeleteStep::Preflight);
        assert_eq!(fake.calls().len(), 1);
    }

    /// NET-1・TASK-139.4: 渡されていない endpoint の veth が無ければ（quarantine 中のアドレス）、
    /// テーブルの削除後に IPAM と予約を解放する。
    #[test]
    fn net1_delete_releases_quarantined_endpoint() {
        let (net, mut ipam, mut ports) = setup();
        let _q = attached(&mut ipam, "c1");
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            ..Fake::default()
        };
        let report = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
        assert!(ports.is_empty());
    }

    /// NET-1・TASK-139.4: 検証違反は何も呼ばずに失敗する（IPAM 不一致・アドレス不一致・重複）。
    #[test]
    fn net1_delete_validation_touches_nothing() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake::default();

        // 別ネットワークの IPAM。
        let mut other = StaticIpam::new(
            &NetworkName::new("db").unwrap(),
            IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 90, 0, 1)), 24).unwrap(),
        )
        .unwrap();
        let e = delete_network_with(&fake, &net, vec![], &mut other, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Validate)
        );

        // アドレス不一致。
        let mut bad = attached(&mut ipam, "c2");
        bad.address = c1.address;
        let e = delete_network_with(&fake, &net, vec![bad], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Validate)
        );
        assert_eq!(e.retry.len(), 1);

        // host_veth 不一致。
        let mut bad = attached(&mut ipam, "c3");
        bad.host_veth = host_of("zzz");
        let e = delete_network_with(&fake, &net, vec![bad], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);

        // endpoint の重複。
        let dup = AttachedContainer {
            endpoint: c1.endpoint.clone(),
            host_veth: c1.host_veth.clone(),
            host_index: c1.host_index,
            host_token: c1.host_token.clone(),
            peer_veth: c1.peer_veth.clone(),
            netns_path: c1.netns_path.clone(),
            address: c1.address,
            netns: (),
        };
        let e = delete_network_with(&fake, &net, vec![c1, dup], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::InvalidArgument, DeleteStep::Validate)
        );
        // 検証エラーでも渡した containers（netns ハンドル）は retry で返る。
        assert_eq!(e.retry.len(), 2);
        assert!(fake.calls().is_empty());
        assert_eq!(ipam.allocated_count(), 3);
    }

    /// NET-1・TASK-139.4: veth の ifindex が変わっていたら元の veth は消失済み。別 link は削除せず、unpin とアドレス解放に進む。
    #[test]
    fn net1_delete_veth_index_mismatch_is_treated_as_gone() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        // 同名で作り直された別 link（ifindex も別名も異なる）。
        let fake = Fake {
            veth_index: Some(99),
            veth_alias: Some(Some("someone-else".to_owned())),
            ..Fake::default()
        };
        let report = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert!(
            report
                .removed
                .contains(&DeleteResource::Veth(host_of("c1")))
        );
        assert!(fake.calls().contains(&"unpin_netns".to_owned()));
        assert!(!fake.calls().contains(&"delete_link 99".to_owned()));
        assert!(fake.calls().contains(&"delete_link 7".to_owned()));
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4・P0: 所有トークンが一致するのに ifindex だけが記録と異なる（渡された `host_index` が
    /// 実体と食い違う）場合は、生存 veth を消失済みとみなさず、削除も unpin もせずにアドレスを保持する。
    #[test]
    fn net1_delete_refuses_token_match_with_index_mismatch() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_index: Some(99),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::DeleteVeth)
        );
        assert_eq!(
            e.message(),
            "veth carries the ownership token but its ifindex differs"
        );
        assert!(
            e.report
                .leftover
                .contains(&(DeleteResource::Veth(host_of("c1")), ResourceState::Unknown))
        );
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
        assert!(!fake.calls().iter().any(|c| c == "unpin_netns"));
        assert_eq!(e.retry.len(), 1);
        assert_eq!(ipam.allocated_count(), 1);
    }

    /// NET-1・TASK-139.4・P0: `CreatedNetwork` の bridge 名・テーブル名・所有トークンがネットワーク名と
    /// 食い違えば（別ネットワークの値の組み合わせ）、何も呼ばずに入力検証で拒否する。
    #[test]
    fn net1_delete_rejects_inconsistent_network_handle() {
        let other = NetworkResourceNames::derive(&NetworkName::new("db").unwrap()).unwrap();
        for forge in ["bridge", "table", "token"] {
            let (mut net, mut ipam, mut ports) = setup();
            let c1 = attached(&mut ipam, "c1");
            match forge {
                "bridge" => net.bridge = other.bridge().clone(),
                "table" => net.table = other.table().clone(),
                _ => net.bridge_token = "fandhe-net:db:1:0:0".to_owned(),
            }
            let fake = Fake::default();
            let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(
                (e.code(), e.step),
                (NetErrorCode::FailedPrecondition, DeleteStep::Validate),
                "{forge}"
            );
            assert_eq!(e.message(), "network handle is inconsistent with its name");
            assert!(fake.calls().is_empty(), "{forge}");
            assert_eq!(e.retry.len(), 1);
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4・P0: 渡したコンテナの所有トークン・peer 名がネットワークと endpoint から再導出した
    /// 値と異なれば、何も呼ばずに入力検証で拒否する（書き換えたトークンを所有の証明に使わせない）。
    #[test]
    fn net1_delete_rejects_forged_host_token_or_peer() {
        for forge in ["token", "peer"] {
            let (net, mut ipam, mut ports) = setup();
            let mut c1 = attached(&mut ipam, "c1");
            match forge {
                "token" => {
                    c1.host_token =
                        "fandhe-net:other:9:9:9/ep/c1/g/0123456789abcdef0123456789abcdef".to_owned()
                }
                _ => c1.peer_veth = VethNames::derive(&eid("zzz")).unwrap().peer().clone(),
            }
            let fake = Fake {
                veth_alias: Some(Some(
                    "fandhe-net:other:9:9:9/ep/c1/g/0123456789abcdef0123456789abcdef".to_owned(),
                )),
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(
                (e.code(), e.step),
                (NetErrorCode::FailedPrecondition, DeleteStep::Validate),
                "{forge}"
            );
            assert_eq!(e.message(), "container does not belong to the network");
            assert!(fake.calls().is_empty(), "{forge}");
            assert_eq!(e.retry.len(), 1);
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4・P1: ifindex が一致しても、所有トークンが無い・異なる link（ifindex の再利用）は
    /// 元の veth と証明できず、削除しない（unpin もしない）。
    #[test]
    fn net1_delete_refuses_veth_with_reused_ifindex_token_mismatch() {
        for alias in [None, Some("other".to_owned())] {
            let (net, mut ipam, mut ports) = setup();
            let c1 = attached(&mut ipam, "c1");
            let fake = Fake {
                veth_alias: Some(alias),
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(
                (e.code(), e.step),
                (NetErrorCode::FailedPrecondition, DeleteStep::DeleteVeth)
            );
            assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
            assert!(!fake.calls().iter().any(|c| c == "unpin_netns"));
            assert_eq!(e.retry.len(), 1);
        }
    }

    /// NET-1・TASK-139.4: veth がすでに無ければ完了扱い（冪等）。
    #[test]
    fn net1_delete_veth_not_found_is_idempotent() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            ..Fake::default()
        };
        let report = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::Veth(host_of("c1")))
        );
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4: veth 削除の `Timeout` は `Unknown`、`Internal` は `Present`。アドレスは保持する。
    #[test]
    fn net1_delete_veth_delete_errors() {
        for (code, state) in [
            (NetErrorCode::Timeout, ResourceState::Unknown),
            (NetErrorCode::Internal, ResourceState::Present),
        ] {
            let (net, mut ipam, mut ports) = setup();
            let c1 = attached(&mut ipam, "c1");
            let fake = Fake {
                veth_delete_err: Some(code),
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(e.code(), code);
            assert_eq!(
                e.report.leftover,
                vec![
                    (DeleteResource::Veth(host_of("c1")), state),
                    (DeleteResource::Netns(pin("c1")), ResourceState::Present),
                    // コンテナ側の資源が残るので bridge は削除しない。
                    (
                        DeleteResource::Bridge(net.bridge.clone()),
                        ResourceState::Present
                    )
                ]
            );
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4: unpin の失敗は pin パスを `Present` で報告し、アドレスは保持する。
    #[test]
    fn net1_delete_unpin_failure_reports_pin_path() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            unpin_fails: true,
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Internal, DeleteStep::UnpinNetns)
        );
        assert_eq!(
            e.report.leftover,
            vec![
                (DeleteResource::Netns(pin("c1")), ResourceState::Present),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                )
            ]
        );
        assert_eq!(ipam.allocated_count(), 1);
        // テーブルが消えたので予約は解放される。
        assert!(
            e.report
                .removed
                .contains(&DeleteResource::PortReservation(net.name.clone()))
        );
    }

    /// NET-1・TASK-139.4: テーブルがすでに無い（`Aborted` + `NotFound`）なら完了扱い。
    #[test]
    fn net1_delete_table_not_found_is_idempotent() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let report = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::NftTable(net.table.clone()))
        );
    }

    /// NET-1・TASK-139.4: テーブル削除の結果が不明なら、bridge は試すが IPAM・予約は一切解放しない。
    #[test]
    fn net1_delete_table_unknown_keeps_reservations() {
        let (net, mut ipam, mut ports) = setup();
        let _q = attached(&mut ipam, "c1");
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            table_err: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Timeout, DeleteStep::DeleteNftTable)
        );
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Unknown
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                ),
            ]
        );
        // テーブルが消えたと確認できないので bridge は残す（再実行で所有の証明を使えるように）。
        assert!(!fake.calls().contains(&"delete_link 7".to_owned()));
        assert_eq!(ipam.allocated_count(), 1);
        assert_eq!(ports.len(), 1);
    }

    /// NET-1・TASK-139.4: テーブルが拒否された（`Aborted` + `PermissionDenied`）なら `Present`。
    #[test]
    fn net1_delete_table_rejected_is_present() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            table_err: Some((NetErrorCode::PermissionDenied, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Present
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                ),
            ]
        );
    }

    /// NET-1・TASK-139.4: 所有トークンが一致しない bridge は削除せず `Unknown`。
    #[test]
    fn net1_delete_bridge_token_mismatch_not_deleted() {
        let (mut net, mut ipam, mut ports) = setup();
        // 形式は正しい（同じネットワーク名）が、カーネル上の bridge の別名（`TOKEN`）とは異なるトークン。
        net.bridge_token = "fandhe-net:web:2:0:0".to_owned();
        // テーブルのトークンは一致する（テーブルの所有は bridge と独立に証明される）。
        let fake = Fake {
            table_userdata: Some(b"fandhe-net:web:2:0:0".to_vec()),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::DeleteBridge)
        );
        assert_eq!(
            e.report.leftover,
            vec![(
                DeleteResource::Bridge(net.bridge.clone()),
                ResourceState::Unknown
            )]
        );
        // 所有を証明できない bridge には触れない（P0）。
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
    }

    /// NET-1・TASK-139.4: bridge がすでに無ければ完了扱い。ifindex 不一致は削除しない。
    #[test]
    fn net1_delete_bridge_not_found_and_index_mismatch() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            ..Fake::default()
        };
        // bridge が無くても、テーブルは自分のトークンで所有を証明できれば削除して完了する。
        let report = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::Bridge(net.bridge.clone()))
        );
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));

        let fake = Fake {
            bridge_index: Some(8),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteBridge);
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
    }

    /// NET-1・TASK-139.4・ERR-1: 最初のエラーを後続の失敗で上書きしない。
    #[test]
    fn net1_delete_keeps_first_error() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_delete_err: Some(NetErrorCode::Internal),
            table_err: Some((NetErrorCode::PermissionDenied, NftBatchOutcome::Aborted)),
            bridge_delete_err: Some(NetErrorCode::ResourceExhausted),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Internal, DeleteStep::DeleteVeth)
        );
        assert_eq!(e.report.leftover.len(), 4);
    }

    /// NET-1・TASK-139.4: 取り残しを片付けた後、`containers` を空にして再実行すると成功に収束する。
    #[test]
    fn net1_delete_retry_converges() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            bridge_delete_err: Some(NetErrorCode::Internal),
            ..Fake::default()
        };
        let e = delete_network_with(&failing, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteBridge);
        assert_eq!(ipam.allocated_count(), 0);
        // 再実行では veth・テーブルがすでに無く、bridge は所有を証明できる状態で残っている。
        let gone = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let report = delete_network_with(&gone, &net, vec![], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
    }

    /// NET-1・TASK-139.4: unpin に失敗したコンテナは netns ハンドルごとエラーで返り、再実行に渡せる。
    #[test]
    fn net1_delete_unpin_failure_returns_handle_for_retry() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            unpin_fails: true,
            ..Fake::default()
        };
        let mut e =
            delete_network_with(&failing, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.retry.len(), 1);
        let kept = e.retry.pop().unwrap();
        assert_eq!(
            (kept.endpoint.clone(), kept.netns_path.clone()),
            (eid("c1"), pin("c1"))
        );
        // 返されたコンテナを渡して再実行すると、unpin が成功して収束する。
        let ok = Fake::default();
        let report = delete_network_with(&ok, &net, vec![kept], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4: veth が無くても pin が残る（または判定できない）未指定 endpoint のアドレスは保持する。
    #[test]
    fn net1_delete_keeps_address_when_unpassed_pin_remains() {
        for (present, check_err, state) in [
            (true, false, ResourceState::Present),
            (false, true, ResourceState::Unknown),
        ] {
            let (net, mut ipam, mut ports) = setup();
            let _q = attached(&mut ipam, "c1");
            let fake = Fake {
                absent_veths: vec![host_of("c1").as_str().to_owned()],
                pins_present: if present { vec![pin("c1")] } else { vec![] },
                pin_check_err: check_err,
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(e.step, DeleteStep::Preflight);
            assert_eq!(
                e.report.leftover,
                vec![
                    (DeleteResource::Netns(pin("c1")), state),
                    (
                        DeleteResource::Bridge(net.bridge.clone()),
                        ResourceState::Present
                    )
                ]
            );
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4・P1: 未指定 endpoint の pin 置き場が接続時に記録したものと同じ実体と確認できない
    /// （差し替え・移動・消失）場合は、pin の残存を見落としうるので何も変更せずに `Preflight` で拒否する。
    /// 渡したコンテナの veth も消さず、netns ハンドルは `retry` で返る。
    #[test]
    fn net1_delete_rejects_when_pin_dir_differs_from_attach() {
        for (dir_id_now, dir_open_err, code) in [
            (Some((8, 10)), None, NetErrorCode::FailedPrecondition),
            (None, Some(NetErrorCode::NotFound), NetErrorCode::NotFound),
        ] {
            let (net, mut ipam, mut ports) = setup();
            let _q = attached(&mut ipam, "q1");
            let c2 = attached(&mut ipam, "c2");
            reserve_port(&mut ports, "q1", 8080);
            let fake = Fake {
                absent_veths: vec![host_of("q1").as_str().to_owned()],
                pins_present: vec![pin("q1")],
                dir_id_now,
                dir_open_err,
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c2], &mut ipam, &mut ports).unwrap_err();
            assert_eq!((e.code(), e.step), (code, DeleteStep::Preflight));
            assert_eq!(
                fake.calls(),
                vec![
                    format!("link_index {}", host_of("q1").as_str()),
                    format!("pin_exists {}", pin("q1").display()),
                ]
            );
            assert_eq!(e.report, NetworkDeleteReport::default());
            assert_eq!(e.retry.len(), 1);
            assert_eq!(e.retry[0].endpoint, eid("c2"));
            assert_eq!(ipam.allocated_count(), 2);
            assert_eq!(ports.len(), 1);
        }
    }

    /// NET-1・TASK-139.4: pin 置き場の記録が無い払い出し（`reserve` で復元）は pin の有無を判定できないため、
    /// アドレスを保持して `Unknown` で報告し、bridge も残す（fail-closed）。
    #[test]
    fn net1_delete_keeps_address_without_pin_dir_record() {
        let (net, mut ipam, mut ports) = setup();
        let addr = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 5)), 24).unwrap();
        ipam.reserve(&eid("r1"), addr).unwrap();
        let fake = Fake {
            absent_veths: vec![host_of("r1").as_str().to_owned()],
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Preflight)
        );
        assert_eq!(
            e.message(),
            "netns directory of an unpassed endpoint is not recorded"
        );
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::Address(eid("r1"), addr),
                    ResourceState::Unknown
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                ),
            ]
        );
        assert!(!fake.calls().iter().any(|c| c.starts_with("pin_exists")));
        assert!(!fake.calls().iter().any(|c| c == "delete_link 7"));
        assert_eq!(ipam.address_of(&eid("r1")), Some(addr));
    }

    /// NET-1・TASK-139.4: 渡したコンテナの `netns_path` が接続時に記録した置き場の直下でなければ、
    /// 何も呼ばずに入力検証で拒否する。
    #[test]
    fn net1_delete_rejects_container_with_foreign_netns_path() {
        let (net, mut ipam, mut ports) = setup();
        let mut c1 = attached(&mut ipam, "c1");
        c1.netns_path = std::env::temp_dir().join("elsewhere").join("c1");
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Validate)
        );
        assert_eq!(e.message(), "container does not belong to the network");
        assert!(fake.calls().is_empty());
        assert_eq!(e.retry.len(), 1);
        assert_eq!(ipam.allocated_count(), 1);
    }

    /// NET-1・TASK-139.4・P0: テーブルの所有トークンが一致しない（別者の同名テーブル）・ハンドルが無い場合は
    /// 削除せず、予約・アドレスを保持する。bridge の所有確認が通っていても同じ。
    #[test]
    fn net1_delete_refuses_table_without_ownership_token() {
        for fake in [
            Fake {
                table_userdata: Some(b"someone-else".to_vec()),
                ..Fake::default()
            },
            Fake {
                table_no_handle: true,
                ..Fake::default()
            },
            Fake {
                bridge_lookup_err: Some(NetErrorCode::NotFound),
                table_userdata: Some(b"someone-else".to_vec()),
                ..Fake::default()
            },
        ] {
            let (net, mut ipam, mut ports) = setup();
            reserve_port(&mut ports, "c1", 8080);
            let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(
                (e.code(), e.step),
                (NetErrorCode::FailedPrecondition, DeleteStep::DeleteNftTable)
            );
            assert_eq!(
                e.report.leftover.first(),
                Some(&(
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Unknown
                ))
            );
            assert!(!fake.calls().iter().any(|c| c.starts_with("delete_")));
            assert_eq!(ports.len(), 1);
        }
    }

    /// NET-1・TASK-139.4: 所有を確認したテーブルは、照会で得たハンドル指定で削除する（名前では消さない）。
    #[test]
    fn net1_delete_table_by_proven_handle() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake::default();
        delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap();
        let calls = fake.calls();
        let q = calls.iter().position(|c| c.starts_with("table_info"));
        let d = calls
            .iter()
            .position(|c| c == &format!("delete_table {} handle=99", net.table.as_str()));
        assert!(q.is_some() && d.is_some() && q < d, "{calls:?}");
    }

    /// NET-1・TASK-139.4・P0: 名前と ifindex が一致しても bridge に属していない link は元の veth と証明できず、
    /// 削除しない（unpin もしない）。
    #[test]
    fn net1_delete_refuses_veth_not_attached_to_bridge() {
        for master in [None, Some(8)] {
            let (net, mut ipam, mut ports) = setup();
            let c1 = attached(&mut ipam, "c1");
            let fake = Fake {
                veth_master: Some(master),
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
            assert_eq!(
                (e.code(), e.step),
                (NetErrorCode::FailedPrecondition, DeleteStep::DeleteVeth)
            );
            assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
            assert!(!fake.calls().iter().any(|c| c == "unpin_netns"));
            assert_eq!(e.retry.len(), 1);
        }
    }

    /// NET-1・TASK-139.4: 削除成功後の再実行（bridge もテーブルも無い）は成功に収束する（冪等）。
    #[test]
    fn net1_delete_rerun_after_success_is_idempotent() {
        let (net, mut ipam, mut ports) = setup();
        let first = Fake::default();
        delete_network_with(&first, &net, vec![], &mut ipam, &mut ports).unwrap();
        let rerun = Fake {
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            table_absent: true,
            ..Fake::default()
        };
        let report = delete_network_with(&rerun, &net, vec![], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert!(
            report
                .removed
                .contains(&DeleteResource::NftTable(net.table.clone()))
        );
        assert!(!rerun.calls().iter().any(|c| c.starts_with("delete_")));
    }

    /// NET-1・TASK-139.4: bridge が無く、テーブルの有無も確認できない場合は fail-closed（`Unknown`）。
    #[test]
    fn net1_delete_bridge_gone_table_query_failure_is_unknown() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            table_query_err: Some(NetErrorCode::Timeout),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Timeout, DeleteStep::DeleteNftTable)
        );
        assert_eq!(
            e.report.leftover,
            vec![(
                DeleteResource::NftTable(net.table.clone()),
                ResourceState::Unknown
            )]
        );
    }

    /// NET-1・TASK-139.4: veth 削除失敗や unpin 失敗、未指定 pin の残存があるあいだは bridge を削除せず、
    /// 再実行で所有を証明して収束できる。
    #[test]
    fn net1_delete_keeps_bridge_while_container_resources_remain() {
        // veth 削除失敗。
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            veth_delete_err: Some(NetErrorCode::Internal),
            ..Fake::default()
        };
        let mut e =
            delete_network_with(&failing, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert!(!failing.calls().iter().any(|c| c == "delete_link 7"));
        assert!(e.report.leftover.contains(&(
            DeleteResource::Bridge(net.bridge.clone()),
            ResourceState::Present
        )));
        // 再実行: bridge の所有を証明でき、テーブルはすでに無く、全体が収束する。
        let kept = e.retry.pop().unwrap();
        let ok = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let report = delete_network_with(&ok, &net, vec![kept], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert!(ok.calls().iter().any(|c| c == "delete_link 7"));
        assert_eq!(ipam.allocated_count(), 0);

        // unpin 失敗。
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            unpin_fails: true,
            ..Fake::default()
        };
        let e = delete_network_with(&failing, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert!(!failing.calls().iter().any(|c| c == "delete_link 7"));
        assert_eq!(e.retry.len(), 1);

        // 未指定 endpoint の pin が残る。
        let (net, mut ipam, mut ports) = setup();
        let _q = attached(&mut ipam, "c1");
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            pins_present: vec![pin("c1")],
            ..Fake::default()
        };
        let _ = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert!(!fake.calls().iter().any(|c| c == "delete_link 7"));
    }

    /// NET-1・TASK-139.4: veth の削除に失敗したら unpin せずハンドルを返し、再実行で収束する。
    #[test]
    fn net1_delete_veth_failure_keeps_handle_for_retry() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            veth_delete_err: Some(NetErrorCode::Internal),
            ..Fake::default()
        };
        let mut e =
            delete_network_with(&failing, &net, vec![c1], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteVeth);
        assert!(!failing.calls().iter().any(|c| c == "unpin_netns"));
        assert_eq!(e.retry.len(), 1);
        assert_eq!(ipam.allocated_count(), 1);
        let kept = e.retry.pop().unwrap();
        let ok = Fake::default();
        let report = delete_network_with(&ok, &net, vec![kept], &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4: 共有予約ファイルの解放に失敗したら `PortReservation` を `Present` で報告する。
    #[test]
    fn net1_delete_reservation_release_failure_is_reported() {
        let dir = std::env::temp_dir().join(format!("fc-delete-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // ファイルの代わりにディレクトリを共有パスに指定し、ロックの open を失敗させる。
        let path = dir.join("ports.reg");
        std::fs::create_dir_all(&path).unwrap();
        let (net, mut ipam, _) = setup();
        let mut ports = PortRegistry::with_shared_file(path);
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![], &mut ipam, &mut ports).unwrap_err();
        assert_eq!(e.step, DeleteStep::ReleaseReservations);
        assert_eq!(
            e.report.leftover,
            vec![(
                DeleteResource::PortReservation(net.name.clone()),
                ResourceState::Present
            )]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn claim(bridge: bool, table: bool) -> FailedCreateClaim {
        FailedCreateClaim::for_test(NetworkName::new("web").unwrap(), TOKEN, bridge, table)
    }

    /// NET-1・#2467: 両方トークン一致なら、テーブル → bridge の順に照会して ifindex・ハンドル指定で消す。
    #[test]
    fn net1_reclaim_removes_owned_table_and_bridge() {
        let fake = Fake::default();
        let report = reclaim_failed_create_with(&fake, &claim(true, true)).unwrap();
        let net = created();
        assert_eq!(
            fake.calls(),
            vec![
                format!("table_info {}", net.table.as_str()),
                format!("delete_table {} handle=99", net.table.as_str()),
                format!("owned_bridge_index {}", net.bridge.as_str()),
                "delete_link 7".to_owned(),
            ]
        );
        assert_eq!(
            report.removed,
            vec![
                DeleteResource::NftTable(net.table.clone()),
                DeleteResource::Bridge(net.bridge.clone())
            ]
        );
        assert!(report.leftover.is_empty());
    }

    /// NET-1・#2467: すでに無い資源は成功扱い（冪等）で、削除は 1 回も呼ばない。
    #[test]
    fn net1_reclaim_not_found_is_idempotent() {
        let fake = Fake {
            table_absent: true,
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            ..Fake::default()
        };
        let report = reclaim_failed_create_with(&fake, &claim(true, true)).unwrap();
        assert_eq!(report.removed.len(), 2);
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_")));
    }

    /// NET-1・#2467: bridge の別名が不一致なら bridge に触れず Unknown。テーブルは独立に消える。
    #[test]
    fn net1_reclaim_refuses_bridge_without_token_but_removes_table() {
        let fake = Fake {
            bridge_lookup_err: Some(NetErrorCode::FailedPrecondition),
            ..Fake::default()
        };
        let e = reclaim_failed_create_with(&fake, &claim(true, true)).unwrap_err();
        let net = created();
        assert_eq!(e.step, DeleteStep::DeleteBridge);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.report.leftover,
            vec![(DeleteResource::Bridge(net.bridge), ResourceState::Unknown)]
        );
        assert_eq!(e.report.removed, vec![DeleteResource::NftTable(net.table)]);
        assert!(!fake.calls().iter().any(|c| c == "delete_link 7"));
    }

    /// NET-1・#2467: テーブルの userdata 不一致・ハンドル無しは削除せず Unknown。
    #[test]
    fn net1_reclaim_refuses_unproven_table() {
        for fake in [
            Fake {
                table_userdata: Some(b"other".to_vec()),
                ..Fake::default()
            },
            Fake {
                table_no_handle: true,
                ..Fake::default()
            },
        ] {
            let e = reclaim_failed_create_with(&fake, &claim(false, true)).unwrap_err();
            assert_eq!(e.step, DeleteStep::DeleteNftTable);
            assert_eq!(
                e.report.leftover,
                vec![(
                    DeleteResource::NftTable(created().table),
                    ResourceState::Unknown
                )]
            );
            assert!(!fake.calls().iter().any(|c| c.starts_with("delete_table")));
        }
    }

    /// NET-1・#2467: 請求書に載っていない資源は照会もしない。
    #[test]
    fn net1_reclaim_skips_resources_not_in_claim() {
        let fake = Fake::default();
        reclaim_failed_create_with(&fake, &claim(true, false)).unwrap();
        assert!(!fake.calls().iter().any(|c| c.contains("table")));
        let fake = Fake::default();
        reclaim_failed_create_with(&fake, &claim(false, true)).unwrap();
        assert!(!fake.calls().iter().any(|c| c.contains("bridge")));
    }

    /// NET-1・#2467: 削除の失敗の状態。delete_link の Internal は Present、Timeout は Unknown。
    #[test]
    fn net1_reclaim_delete_failures_are_classified() {
        let net = created();
        for (code, state) in [
            (NetErrorCode::Internal, ResourceState::Present),
            (NetErrorCode::Timeout, ResourceState::Unknown),
        ] {
            let fake = Fake {
                bridge_delete_err: Some(code),
                ..Fake::default()
            };
            let e = reclaim_failed_create_with(&fake, &claim(true, false)).unwrap_err();
            assert_eq!(e.step, DeleteStep::DeleteBridge);
            assert_eq!(
                e.report.leftover,
                vec![(DeleteResource::Bridge(net.bridge.clone()), state)]
            );
        }
        let fake = Fake {
            table_err: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ..Fake::default()
        };
        let e = reclaim_failed_create_with(&fake, &claim(false, true)).unwrap_err();
        assert_eq!(
            e.report.leftover,
            vec![(
                DeleteResource::NftTable(net.table.clone()),
                ResourceState::Unknown
            )]
        );
        let fake = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let report = reclaim_failed_create_with(&fake, &claim(false, true)).unwrap();
        assert_eq!(report.removed, vec![DeleteResource::NftTable(net.table)]);
    }

    /// NET-1・ERR-1・#2467: 2 段とも失敗したとき最初のエラーと手順を保持し、もう一方も試す。
    #[test]
    fn net1_reclaim_keeps_first_error() {
        let fake = Fake {
            table_query_err: Some(NetErrorCode::Timeout),
            bridge_lookup_err: Some(NetErrorCode::FailedPrecondition),
            ..Fake::default()
        };
        let e = reclaim_failed_create_with(&fake, &claim(true, true)).unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteNftTable);
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.report.leftover.len(), 2);
    }

    /// NET-1・#2467: 別ネットワークのトークンや空トークンの請求書は ops を呼ぶ前に拒否する。
    #[test]
    fn net1_reclaim_rejects_foreign_or_empty_token_before_io() {
        for token in ["fandhe-net:other:1:0:0", "", "fandhe-net:web2:1:0:0"] {
            let fake = Fake::default();
            let c =
                FailedCreateClaim::for_test(NetworkName::new("web").unwrap(), token, true, true);
            let e = reclaim_failed_create_with(&fake, &c).unwrap_err();
            assert_eq!(e.step, DeleteStep::Validate);
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
            assert!(fake.calls().is_empty());
        }
    }

    fn attach_claim(veth: bool, netns: bool, quarantine: bool) -> FailedAttachClaim {
        FailedAttachClaim::for_test(
            NetworkName::new("web").unwrap(),
            eid("c1"),
            TOKEN,
            GEN,
            veth,
            netns,
            quarantine,
        )
    }

    /// NET-1・#2681: 別名と master が一致する veth は、照会で得た ifindex で消え、pin はパス指定で外れる。
    #[test]
    fn net1_reclaim_attach_removes_owned_veth_and_pin() {
        let fake = Fake::default();
        let net = created();
        let dir = netns_dir();
        let report =
            reclaim_failed_attach_with(&fake, &attach_claim(true, true, true), &dir).unwrap();
        assert_eq!(
            fake.calls(),
            vec![
                format!("link_attachment {}", host_of("c1").as_str()),
                format!("owned_bridge_index {}", net.bridge.as_str()),
                "delete_link 21".to_owned(),
                format!("unpin_path {}", pin("c1").display()),
            ]
        );
        assert_eq!(
            report.removed,
            vec![
                DeleteResource::Veth(host_of("c1")),
                DeleteResource::Netns(pin("c1"))
            ]
        );
        assert!(report.leftover.is_empty());
    }

    /// NET-1・#2681: veth が既に無ければ回収済みとして成功し、削除は呼ばない（冪等）。
    #[test]
    fn net1_reclaim_attach_gone_veth_is_idempotent() {
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            ..Default::default()
        };
        let report =
            reclaim_failed_attach_with(&fake, &attach_claim(true, false, false), &netns_dir())
                .unwrap();
        assert_eq!(report.removed, vec![DeleteResource::Veth(host_of("c1"))]);
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
    }

    /// NET-1・#2681: 別名の不一致・master の不一致・bridge 無しは Unknown で、削除しない。
    #[test]
    fn net1_reclaim_attach_refuses_unproven_veth() {
        let cases = [
            Fake {
                veth_alias: Some(Some("forged".to_owned())),
                ..Default::default()
            },
            Fake {
                veth_alias: Some(None),
                ..Default::default()
            },
            Fake {
                veth_master: Some(Some(8)),
                ..Default::default()
            },
            Fake {
                veth_master: Some(None),
                ..Default::default()
            },
            Fake {
                bridge_lookup_err: Some(NetErrorCode::NotFound),
                ..Default::default()
            },
        ];
        for fake in cases {
            let e =
                reclaim_failed_attach_with(&fake, &attach_claim(true, false, false), &netns_dir())
                    .unwrap_err();
            assert_eq!(e.step, DeleteStep::DeleteVeth);
            assert_eq!(
                e.report.leftover,
                vec![(DeleteResource::Veth(host_of("c1")), ResourceState::Unknown)]
            );
            assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
        }
    }

    /// NET-1・#2681: トークンが別ネットワークのものなら、ops を呼ばずに Validate で拒否する。
    #[test]
    fn net1_reclaim_attach_rejects_foreign_token_before_io() {
        let fake = Fake::default();
        let claim = FailedAttachClaim::for_test(
            NetworkName::new("web").unwrap(),
            eid("c1"),
            "fandhe-net:other:1:2:3",
            GEN,
            true,
            true,
            false,
        );
        let e = reclaim_failed_attach_with(&fake, &claim, &netns_dir()).unwrap_err();
        assert_eq!(e.step, DeleteStep::Validate);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(fake.calls().is_empty());
    }

    /// NET-1・#2681: pin の解除に失敗したら Netns の取り残しで、veth の回収は続ける。最初のエラーを保持する。
    #[test]
    fn net1_reclaim_attach_unpin_failure_is_leftover() {
        let fake = Fake {
            unpin_path_err: Some(NetErrorCode::FailedPrecondition),
            ..Default::default()
        };
        let e = reclaim_failed_attach_with(&fake, &attach_claim(true, true, false), &netns_dir())
            .unwrap_err();
        assert_eq!(e.step, DeleteStep::UnpinNetns);
        assert_eq!(
            e.report.leftover,
            vec![(DeleteResource::Netns(pin("c1")), ResourceState::Present)]
        );
        assert_eq!(e.report.removed, vec![DeleteResource::Veth(host_of("c1"))]);

        let fake = Fake {
            unpin_path_err: Some(NetErrorCode::Timeout),
            ..Default::default()
        };
        let e = reclaim_failed_attach_with(&fake, &attach_claim(false, true, false), &netns_dir())
            .unwrap_err();
        assert_eq!(
            e.report.leftover,
            vec![(DeleteResource::Netns(pin("c1")), ResourceState::Unknown)]
        );
    }

    /// NET-1・#2681: quarantine だけの請求書は、カーネルに触れずに成功する。
    #[test]
    fn net1_reclaim_attach_quarantine_only_touches_nothing() {
        let fake = Fake::default();
        let report =
            reclaim_failed_attach_with(&fake, &attach_claim(false, false, true), &netns_dir())
                .unwrap();
        assert!(fake.calls().is_empty());
        assert_eq!(report, NetworkDeleteReport::default());
    }

    /// NET-1・#2681: 回収 → 同じ endpoint の再接続 → 古い請求書での回収で、新しい接続の veth は消えない。
    /// 再接続した veth の別名は別の世代のトークンになるため、古い請求書では所有を証明できない。
    #[test]
    fn net1_reclaim_attach_stale_claim_keeps_reconnected_veth() {
        // fake の veth は現在の世代（GEN）のトークンを持つ。請求書は古い接続（OLD_GEN）のもの。
        let fake = Fake::default();
        let stale = FailedAttachClaim::for_test(
            NetworkName::new("web").unwrap(),
            eid("c1"),
            TOKEN,
            OLD_GEN,
            true,
            true,
            false,
        );
        let e = reclaim_failed_attach_with(&fake, &stale, &netns_dir()).unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteVeth);
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
        assert_eq!(
            e.report.leftover.first(),
            Some(&(DeleteResource::Veth(host_of("c1")), ResourceState::Unknown))
        );
        // 同じ世代の請求書なら消える（対照）。
        let fake = Fake::default();
        reclaim_failed_attach_with(&fake, &attach_claim(true, false, false), &netns_dir()).unwrap();
        assert!(fake.calls().iter().any(|c| c.starts_with("delete_link")));
    }

    /// NET-1・#2681: `delete_network` は、世代の形式が正しくない `host_token` を持つ記録を拒否する。
    #[test]
    fn net1_host_token_requires_generation_form() {
        let ep = eid("c1");
        assert!(host_token_is_for(TOKEN, &ep, &token_of("c1")));
        for bad in [
            format!("{TOKEN}/ep/c1"),
            format!("{TOKEN}/ep/c1/g/"),
            format!("{TOKEN}/ep/c1/g/ZZ"),
            format!("{TOKEN}/ep/c1/g/{GEN}0"),
            format!("{TOKEN}/ep/c2/g/{GEN}"),
        ] {
            assert!(!host_token_is_for(TOKEN, &ep, &bad), "{bad}");
        }
    }
}
