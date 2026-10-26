//! Pod 単位のライフサイクルを `NetworkPlugin` の呼び出しへ写す層（TASK-114.4・#460・#2675・MS-4・CRI-7・CRI-2・NET-1）。
//!
//! CRI の POD モードは「netns が sandbox 単位で、配下のコンテナが共有する」ため、sandbox ごとに 1 つのネットワークと
//! 1 つの netns を作る写像（[`set_up_sandbox`]・[`tear_down_pod`]）を主とし、cri の注入点
//! `fandhe_container_cri::adapter::PodNetworkProvider` を [`NetsetupPodNetwork`] が実装する。
//! コンテナ単位の [`set_up_container`] は共有ネットワークへ接続する旧来の写像で、CRI の RPC からは呼ばない
//! （試験だけが呼ぶ。net にコンテナ単位の切り離しが無く、共有ネットワークでは pod ごとの後始末ができないため。REPAIR-3）。
//!
//! 呼び出し元: `RunPodSandbox` / `StopPodSandbox` / `RemovePodSandbox`（cri の `CriRuntimeService::with_pod_network`
//! で注入したときだけ）。**本番（`CriPluginBackends::production`）は注入しない**: core の start が network namespace の
//! join を未実装で拒否するため、注入すると bridge・netns・veth を作るのに start が `UNIMPLEMENTED` で失敗する
//! （`docs/design/cri-config-acceptance.md` の順 13。REPAIR-3）。
//!
//! | CRI の操作 | 関数 | `NetworkPlugin` の呼び出し |
//! | ---------- | ---- | -------------------------- |
//! | `RunPodSandbox`（POD） | [`set_up_sandbox`] | `create_network` → `create_netns` → `attach` → `publish_port`（`port_mappings` の公開指定ごと。#2676）。失敗は逆順に戻す |
//! | `StopPodSandbox` / `RemovePodSandbox` | [`tear_down_pod`] | `delete_network`（pod のネットワークごと一括解放） |
//! | （試験のみ） | [`set_up_pod`]・[`set_up_container`] | `create_network`・`create_netns` → `attach` |

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    AttachRequest, AttachResponse, ContainerId, CreateNetnsRequest, CreateNetworkRequest,
    DeleteNetworkRequest, DeleteNetworkResponse, DetachRequest, ErrorCode, IpCidr, NetnsName,
    NetnsStatus, NetworkName, NetworkPlugin, NetworkStatus, PublishPortRequest, TraitError,
};
use fandhe_container_cri::adapter::{PodNetns, PodNetworkProvider, PodNetworkRequest};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::port_mapping::PodPortPublish;

/// PodSandbox のネットワークを作る（`net-create`）。
pub fn set_up_pod(
    net: &dyn NetworkPlugin,
    name: &NetworkName,
    subnet: IpCidr,
) -> Result<NetworkStatus, TraitError> {
    net.create_network(&CreateNetworkRequest::new(name.clone(), subnet))
}

/// コンテナの netns を用意して接続する（`netns-create` → `veth-attach`）。
///
/// `attach` が失敗したら、`create_netns` で作った記録を `detach` で戻す（再試行が `AlreadyExists` で
/// 恒久的に失敗しないようにする。契約 6）。巻き戻し自体も失敗したら `Internal` を返し、元の attach エラーと detach エラー、
/// 記録が残っている旨をメッセージへ残す（契約 6・9。エラーを握りつぶさない）。
pub fn set_up_container(
    net: &dyn NetworkPlugin,
    name: &NetworkName,
    container: &ContainerId,
) -> Result<AttachResponse, TraitError> {
    net.create_netns(&CreateNetnsRequest::new(name.clone(), container.clone()))?;
    match net.attach(&AttachRequest::new(name.clone(), container.clone())) {
        Ok(resp) => Ok(resp),
        Err(e) => match net.detach(&DetachRequest::new(name.clone(), container.clone())) {
            Ok(_) => Err(reclaimed_error(e)),
            Err(d) => Err(TraitError::new(
                ErrorCode::Internal,
                format!(
                    "attach failed ({}: {}); rollback detach also failed ({}: {}); \
                         the netns record for the container may remain",
                    e.code().as_str(),
                    e.message(),
                    d.code().as_str(),
                    d.message()
                ),
            )),
        },
    }
}

/// 巻き戻しの `detach` が成功したときの attach エラーを整える。
///
/// attach のエラーが「資源が残った」と報告していても、`detach` が請求書で回収済みなら残骸は無い。
/// veth 名は endpoint から決まり再試行で同名の live veth が作られるため、「残っている」と読める文言を
/// 転送すると、運用者や後始末が新しい live veth を消しかねない（NET-1・#2681）。
fn reclaimed_error(e: TraitError) -> TraitError {
    const LEFT: &str = "resource(s) left behind";
    if !e.message().contains(LEFT) {
        return e;
    }
    TraitError::new(
        e.code(),
        e.message()
            .replace(LEFT, "resource(s) reclaimed by the rollback detach"),
    )
}

/// PodSandbox のネットワークを削除する（`net-delete`）。`NetworkPlugin` の応答をそのまま返す。
pub fn tear_down_pod(
    net: &dyn NetworkPlugin,
    name: &NetworkName,
) -> Result<DeleteNetworkResponse, TraitError> {
    net.delete_network(&DeleteNetworkRequest::new(name.clone()))
}
/// [`set_up_sandbox`] の失敗。巻き戻しが完了したか（資源が残らないか）を伝える。
#[derive(Debug)]
pub struct SandboxSetUpError {
    /// 失敗の原因（巻き戻しも失敗したときは両方を載せた `Internal`）。
    pub error: TraitError,
    /// 巻き戻しが完了し、カーネル資源もレジストリの記録も残らないか。偽ならネットワークの記録が残りうるため、
    /// 呼び出し側は [`tear_down_pod`] で回収を再試行する。
    pub rolled_back: bool,
}

/// sandbox の識別子から導く 3 つの名前（ネットワーク名・コンテナ ID・netns 名はすべて同じ文字列）。
fn sandbox_names(sandbox_id: &str) -> Result<(NetworkName, ContainerId, NetnsName), TraitError> {
    Ok((
        NetworkName::new(sandbox_id)?,
        ContainerId::new(sandbox_id)?,
        NetnsName::new(sandbox_id)?,
    ))
}

/// 巻き戻しの失敗を元のエラーへ足す（握りつぶさない。契約 6・9）。
fn with_rollback_errors(orig: TraitError, rollback: &[(&str, TraitError)]) -> TraitError {
    if rollback.is_empty() {
        return orig;
    }
    let mut message = format!("{} ({})", orig.message(), orig.code().as_str());
    for (step, e) in rollback {
        message.push_str(&format!(
            "; rollback {step} failed ({}: {})",
            e.code().as_str(),
            e.message()
        ));
    }
    TraitError::new(ErrorCode::Internal, message)
}

/// sandbox 単位のネットワークと netns を作って接続し、公開指定があれば公開する
/// （`net-create` → `netns-create` → `veth-attach` → `publish-port`）。
///
/// ネットワーク名・コンテナ ID・netns 名は `sandbox_id` を使う。途中で失敗したら逆順に戻す: `attach` の失敗は
/// `detach`（事前作成の netns の解放）→ `delete_network`、`create_netns` の失敗は `delete_network`。
/// `publish_port` の失敗は `delete_network` だけで戻す（attach 済みのコンテナの `detach` は未対応で、専用テーブルの
/// 削除で DNAT ルールと受け口の予約がまとめて消えるため。#2676・NET-4）。
/// `port_mappings` は sandbox 単位で変わらず、`StopPodSandbox` / `RemovePodSandbox` も `delete_network` で一括解放する
/// ため、`delete_network` 以外の公開の個別解除（`NetsetupBackend::unpublish_port`）の契機は現状要らない
/// （将来の候補は公開途中の失敗の巻き戻しだけで、`NetworkPlugin` の拡張を伴う後続事項。#2839・NET-3）。戻しも失敗したら、元のエラーと戻しの
/// エラーを載せた `Internal` を返し、[`SandboxSetUpError::rolled_back`] を偽にする。
///
/// `ports` は cri が検証した公開指定（`host_port > 0` で明示した IPv4）。空なら公開しない。
pub fn set_up_sandbox(
    net: &dyn NetworkPlugin,
    sandbox_id: &str,
    subnet: IpCidr,
    ports: &[PodPortPublish],
) -> Result<NetnsStatus, SandboxSetUpError> {
    let plain = |error| SandboxSetUpError {
        error,
        rolled_back: true,
    };
    let (name, container, _) = sandbox_names(sandbox_id).map_err(plain)?;
    // `Internal` は取り残しの件数入りの失敗（契約 6）を含む。残骸があるのに枠を返すと別 pod に同じサブネットが
    // 渡りうるため、`Internal` は巻き戻し済みとみなさず、`tear_down`（delete_network）の成功まで枠を保持させる。
    // `AlreadyExists` は同名の稼働中ネットワーク（同じ sandbox への set_up の再呼び出し等）が残っている失敗で、
    // ここでは作っていないため戻さない（消すと稼働中の pod を壊す）。資源は残るので巻き戻し済みとはみなさない（NET-1）。
    net.create_network(&CreateNetworkRequest::new(name.clone(), subnet))
        .map_err(|error| SandboxSetUpError {
            rolled_back: !matches!(error.code(), ErrorCode::Internal | ErrorCode::AlreadyExists),
            error,
        })?;
    let mut rollback: Vec<(&str, TraitError)> = Vec::new();
    let failure = match net.create_netns(&CreateNetnsRequest::new(name.clone(), container.clone()))
    {
        Err(e) => e,
        Ok(status) => match net.attach(&AttachRequest::new(name.clone(), container.clone())) {
            Ok(_) => match publish_all(net, &name, &container, ports) {
                Ok(()) => return Ok(status),
                // attach 済みのため detach は呼ばない（未対応）。delete_network だけで戻す。
                Err(e) => e,
            },
            Err(e) => {
                if let Err(d) = net.detach(&DetachRequest::new(name.clone(), container.clone())) {
                    rollback.push(("detach", d));
                }
                e
            }
        },
    };
    if let Err(d) = net.delete_network(&DeleteNetworkRequest::new(name)) {
        rollback.push(("delete_network", d));
    }
    Err(SandboxSetUpError {
        rolled_back: rollback.is_empty(),
        error: with_rollback_errors(failure, &rollback),
    })
}

/// 公開指定を `publish_port` で順に公開する。最初の失敗で止めて返す（残りは公開しない）。
fn publish_all(
    net: &dyn NetworkPlugin,
    name: &NetworkName,
    container: &ContainerId,
    ports: &[PodPortPublish],
) -> Result<(), TraitError> {
    for p in ports {
        net.publish_port(
            &PublishPortRequest::new(
                name.clone(),
                container.clone(),
                p.host_port(),
                p.container_port(),
                p.protocol(),
            )
            .with_host_ip(IpAddr::V4(p.host_ip())),
        )?;
    }
    Ok(())
}

/// pod 用サブネットを払い出す上限件数（親サブネットと pod の prefix 長の差で決まる枠数の上限）。
pub const MAX_POD_SUBNET_SLOTS: u32 = 4096;

/// 親の IPv4 サブネットを pod ごとの小さなサブネットへ分け、空いている枠を払い出す（NET-1・#2675）。
///
/// 払い出しと返却は 1 つの `Mutex` の下で行い、同じ sandbox への二重払い出しは同じ枠を返す（冪等）。枠が尽きたら
/// `ResourceExhausted`。枠の数は [`MAX_POD_SUBNET_SLOTS`] 以下に限る（無制限の確保・走査を防ぐ）。状態はメモリだけで、
/// plugin の再起動で失われる（`NetsetupNetwork` の状態と同じ制約）。
#[derive(Debug)]
pub struct PodSubnetPool {
    base: u32,
    pod_prefix_len: u8,
    slots: u32,
    used: Mutex<BTreeMap<String, u32>>,
}

impl PodSubnetPool {
    /// `parent`（IPv4）を `pod_prefix_len` の長さのサブネットへ分ける。`pod_prefix_len` は親より長く 30 以下
    /// （net が受ける `/1`〜`/30`）で、枠数が [`MAX_POD_SUBNET_SLOTS`] を超える分割は `InvalidArgument`。
    pub fn new(parent: IpCidr, pod_prefix_len: u8) -> Result<Self, TraitError> {
        let IpAddr::V4(network) = parent.network_address() else {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "only IPv4 pod subnets are supported",
            ));
        };
        let parent_len = parent.prefix_len();
        if pod_prefix_len > 30 || pod_prefix_len <= parent_len {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "pod prefix length must be longer than the parent and at most 30",
            ));
        }
        let bits = u32::from(pod_prefix_len - parent_len);
        let slots = 1u32
            .checked_shl(bits)
            .filter(|n| *n <= MAX_POD_SUBNET_SLOTS)
            .ok_or_else(|| {
                TraitError::new(ErrorCode::InvalidArgument, "too many pod subnet slots")
            })?;
        Ok(Self {
            base: u32::from(network),
            pod_prefix_len,
            slots,
            used: Mutex::new(BTreeMap::new()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, u32>>, TraitError> {
        self.used
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "pod subnet pool is poisoned"))
    }

    fn subnet_of(&self, slot: u32) -> Result<IpCidr, TraitError> {
        let size = 1u32 << (32 - u32::from(self.pod_prefix_len));
        let addr = slot
            .checked_mul(size)
            .and_then(|off| self.base.checked_add(off))
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "pod subnet overflow"))?;
        IpCidr::new(IpAddr::V4(Ipv4Addr::from(addr)), self.pod_prefix_len)
    }

    /// `sandbox_id` に枠を払い出す（既に払い出し済みなら同じ枠）。新規か既存の予約かは [`Self::lease`] で区別する。
    pub fn allocate(&self, sandbox_id: &str) -> Result<IpCidr, TraitError> {
        self.lease(sandbox_id).map(|l| l.subnet)
    }

    /// `sandbox_id` に枠を払い出し、今回の呼び出しで新しく払い出したか（[`PodSubnetLease::newly_allocated`]）も返す。
    ///
    /// 既存の予約は別の呼び出し（稼働中の pod・回収待ちの残骸）が持つ枠なので、今回の失敗を理由に返してはならない
    /// （返すと次の sandbox に同じサブネットが渡り、bridge のアドレス・経路が重複する。NET-1）。
    pub fn lease(&self, sandbox_id: &str) -> Result<PodSubnetLease, TraitError> {
        let mut used = self.lock()?;
        if let Some(slot) = used.get(sandbox_id) {
            return Ok(PodSubnetLease {
                subnet: self.subnet_of(*slot)?,
                newly_allocated: false,
            });
        }
        let taken: BTreeSet<u32> = used.values().copied().collect();
        let slot = (0..self.slots)
            .find(|s| !taken.contains(s))
            .ok_or_else(|| {
                TraitError::new(ErrorCode::ResourceExhausted, "pod subnet pool is exhausted")
            })?;
        let subnet = self.subnet_of(slot)?;
        used.insert(sandbox_id.to_owned(), slot);
        Ok(PodSubnetLease {
            subnet,
            newly_allocated: true,
        })
    }

    /// `sandbox_id` の枠を返す（未払い出しは何もしない）。
    pub fn release(&self, sandbox_id: &str) {
        if let Ok(mut used) = self.lock() {
            used.remove(sandbox_id);
        }
    }

    /// 払い出し中の枠の数（試験・計測用）。
    pub fn in_use(&self) -> usize {
        self.lock().map(|u| u.len()).unwrap_or(0)
    }
}

/// [`PodSubnetPool::lease`] の結果（払い出した枠と、今回新しく払い出したか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodSubnetLease {
    /// 払い出した pod 用サブネット。
    pub subnet: IpCidr,
    /// 今回の呼び出しで新しく払い出したか。偽なら既存の予約で、失敗しても呼び出し側が返してはならない。
    pub newly_allocated: bool,
}

/// cri の `PodNetworkProvider` を `NetworkPlugin` の呼び出しへ写す実装（CRI-2・NET-1・PLUG-1・#2675）。
///
/// `set_up` は pod 用サブネットを払い出し、[`set_up_sandbox`] で netns を作って接続し、netns の pin のパス
/// （`<netns 置き場>/<netns 名>`）を返す。`tear_down` は [`tear_down_pod`] で pod のネットワークごと解放する
/// （冪等。未知は成功）。パスは検証済みの名前（`/`・`.` を含まない）と固定の置き場からだけ組み、bundle の
/// `linux.namespaces[].path` へ載る Linux 側のパスなので、ホスト OS によらず `/` で連結する（`PodNetns::new` の契約）。
///
/// 同じ sandbox への `set_up`・`tear_down` は、`NetworkPlugin` の操作とサブネット枠の払い出し・返却をまとめて
/// 直列化する（sandbox 単位の使用中の印。重なった呼び出しは待たずに `FAILED_PRECONDITION`）。`tear_down` の
/// `delete_network` の成功から枠の返却までの間に `set_up` が既存の枠でネットワークを作り直し、その後の返却で
/// 稼働中のネットワークの枠が別 sandbox へ渡るのを防ぐ（NET-1）。別の sandbox どうしは並行できる。
///
/// **未実装・簡易実装（REPAIR-3）**: 本番へは注入されない（モジュール doc）。サブネットのプールの出どころは未決で、
/// 構築時の引数として受けるだけ。
pub struct NetsetupPodNetwork {
    net: Arc<dyn NetworkPlugin>,
    netns_dir: PathBuf,
    pool: PodSubnetPool,
    /// `set_up`・`tear_down` を実行中の sandbox ID（件数は同時に走る呼び出しの数で有界）。
    busy: Mutex<BTreeSet<String>>,
}

/// [`NetsetupPodNetwork`] の sandbox 単位の使用中の印。drop で外す（panic でも外れる）。
struct SandboxOpGuard<'a> {
    busy: &'a Mutex<BTreeSet<String>>,
    sandbox_id: String,
}

impl Drop for SandboxOpGuard<'_> {
    fn drop(&mut self) {
        // poison でも中身は BTreeSet の挿入・削除だけで壊れないため、取り出して外す（印を残すと恒久的に塞ぐ）。
        let mut busy = match self.busy.lock() {
            Ok(b) => b,
            Err(p) => p.into_inner(),
        };
        busy.remove(&self.sandbox_id);
    }
}

impl NetsetupPodNetwork {
    /// `netns_dir` は `LinuxNetsetup` に渡したものと同じ netns の pin の置き場（絶対パス）。
    pub fn new(net: Arc<dyn NetworkPlugin>, netns_dir: PathBuf, pool: PodSubnetPool) -> Self {
        Self {
            net,
            netns_dir,
            pool,
            busy: Mutex::new(BTreeSet::new()),
        }
    }

    /// `sandbox_id` の使用中の印を付ける。既に別の呼び出しが使用中なら `FAILED_PRECONDITION`。
    fn begin(&self, sandbox_id: &str) -> Result<SandboxOpGuard<'_>, CriError> {
        // poison でも中身（BTreeSet の挿入・削除だけ）は壊れないため取り出す（drop 側と揃える）。
        let mut busy = match self.busy.lock() {
            Ok(b) => b,
            Err(p) => p.into_inner(),
        };
        if !busy.insert(sandbox_id.to_owned()) {
            return Err(CriError::failed_precondition(
                "pod network setup or teardown is in progress",
            ));
        }
        Ok(SandboxOpGuard {
            busy: &self.busy,
            sandbox_id: sandbox_id.to_owned(),
        })
    }

    /// netns の pin のパス（Linux 側の表記。`<netns 置き場>/<netns 名>` を `/` で連結）。
    fn netns_path(&self, netns_name: &NetnsName) -> Result<PathBuf, CriError> {
        let dir = self
            .netns_dir
            .to_str()
            .ok_or_else(|| CriError::internal("invalid pod network namespace directory"))?;
        Ok(PathBuf::from(format!(
            "{}/{}",
            dir.trim_end_matches('/'),
            netns_name.as_str()
        )))
    }
}

impl PodNetworkProvider for NetsetupPodNetwork {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        let to_cri = |e: TraitError| CriError::from(&e);
        let (_, _, netns_name) = sandbox_names(req.sandbox_id).map_err(to_cri)?;
        // 資源を作る前にパスを検証する（作った後で拒否して残骸を作らない）。
        let netns = PodNetns::new(self.netns_path(&netns_name)?)?;
        let _op = self.begin(req.sandbox_id)?;
        let lease = self.pool.lease(req.sandbox_id).map_err(to_cri)?;
        match set_up_sandbox(
            self.net.as_ref(),
            req.sandbox_id,
            lease.subnet,
            req.port_publishes(),
        ) {
            Ok(_) => Ok(netns),
            Err(f) => {
                // 今回新しく払い出した枠で、資源が残らないと確認できたときだけ返す。既存の予約（同じ sandbox の
                // 稼働中のネットワーク・回収待ちの残骸）の枠は tear_down の成功まで保持する（NET-1）。
                if lease.newly_allocated && f.rolled_back {
                    self.pool.release(req.sandbox_id);
                }
                Err(to_cri(f.error))
            }
        }
    }

    fn tear_down(&self, sandbox_id: &str) -> Result<(), CriError> {
        let to_cri = |e: TraitError| CriError::from(&e);
        let (name, _, _) = sandbox_names(sandbox_id).map_err(to_cri)?;
        let _op = self.begin(sandbox_id)?;
        match tear_down_pod(self.net.as_ref(), &name) {
            Ok(_) => {}
            // 未作成・解放済みは成功（冪等）。
            Err(e) if e.code() == ErrorCode::NotFound => {}
            Err(e) => return Err(to_cri(e)),
        }
        self.pool.release(sandbox_id);
        Ok(())
    }
}
