//! none モード（NET-6）: `lo` だけを持つコンテナ専用 netns の作成と解放（TASK-143.2・#327）。
//!
//! 後続の runtime（core）が、ここで pin した netns のパス（[`NoneModeContainer::netns_path`]）を
//! `setns` で join してコンテナプロセスを起動する。join 自体は本 crate の責務外。
//! veth・bridge・アドレス・route・nft ルールは一切作らず（IPAM・ポート公開にも関与しない）、
//! 外部・他コンテナへの経路が存在しない状態を作る（fail-closed）。
//!
//! 処理は `netns::create_pinned`（`unshare` + pin。TASK-139.2.1）で netns を作り、その netns に束縛した
//! route ソケットで `lo` を up にするだけである。カーネルは `lo` の up 時に 127.0.0.1/8 を自動で付与する
//! ため、明示的な付与はしない（`AlreadyExists` になる）。fallback tunnel デバイス（`sit0` 等）は
//! 存在しうるが、down かつアドレスなしで通信経路にならない。
//!
//! 権限: `CAP_SYS_ADMIN`（unshare / mount）と、netns 内 netlink のための `CAP_NET_ADMIN` が呼び出し側に
//! 必要。本 crate は権限を上げない。新規の `unsafe` は無く、`sys` の既存ラッパーを使う。
//!
//! 未実装: host モード（TASK-143.1・#326）、`--dns` の loopback 制約（NET-12・TASK-185/186）、
//! プロセスをまたぐ残置 pin の清掃（担当未確定）。

use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
#[cfg(target_os = "linux")]
use crate::instrument::NetOpRecorder;
use crate::netlink_route::{IfIndex, IfName};
#[cfg(target_os = "linux")]
use crate::netlink_route::{LinkSet, NetlinkRouteSocket};
#[cfg(target_os = "linux")]
use crate::netns::{self, ContainerNetns};
#[cfg(target_os = "linux")]
use crate::network::link_ref;
use crate::network::{
    AttachResource, AttachRollbackReport, EndpointId, NetnsFailure, ResourceState, UnpinFailure,
    is_indeterminate,
};

/// none モードの netns 作成の入力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoneModeSpec {
    endpoint: EndpointId,
    netns_dir: PathBuf,
}

impl NoneModeSpec {
    /// `netns_dir` は netns の pin を置くディレクトリの絶対パス（所有者・権限の検査は作成時に
    /// `crate::netns` が行う）。相対パスは `InvalidArgument`。
    pub fn new(endpoint: EndpointId, netns_dir: PathBuf) -> Result<Self, NetError> {
        if !netns_dir.is_absolute() {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "netns directory must be an absolute path",
            ));
        }
        Ok(Self {
            endpoint,
            netns_dir,
        })
    }

    /// エンドポイント ID（pin ファイル名になる）。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// pin 先パス（`netns_dir/<endpoint>`）。
    pub fn netns_path(&self) -> PathBuf {
        self.netns_dir.join(self.endpoint.as_str())
    }
}

/// 作成済みの none モード netns。`N` は netns ハンドル（Linux では `ContainerNetns`）。
#[derive(Debug)]
#[non_exhaustive]
pub struct NoneModeContainer<N> {
    /// エンドポイント ID。
    pub endpoint: EndpointId,
    /// pin 先パス。runtime が `setns` で join し、解放時は `release_none_netns` に渡す。
    pub netns_path: PathBuf,
    /// netns ハンドル（保持している間は fd が開いている）。
    pub netns: N,
}

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoneModeStep {
    /// netns の作成と pin。
    CreateNetns,
    /// netns 内の `lo` の up。
    ConfigureLoopback,
}

/// none モード作成の失敗（元のエラー・失敗手順・ロールバック結果。ERR-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NoneModeError {
    /// 失敗の原因（ロールバック失敗では上書きしない）。
    pub error: NetError,
    /// 失敗した手順。
    pub step: NoneModeStep,
    /// ロールバックの結果（netns の pin のみが対象）。
    pub rollback: AttachRollbackReport,
}

impl NoneModeError {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl fmt::Display for NoneModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for NoneModeError {}

/// 解放の失敗。解除できなかったハンドルを返し、呼び出し側が再試行できるようにする。
///
/// ハンドルを手放した後でも、同じプロセス内なら `NoneModeContainer::netns_path` を
/// `netns::unpin_path`（冪等）へ渡して再試行できる。
#[derive(Debug)]
#[non_exhaustive]
pub struct NoneModeReleaseError<N> {
    /// 失敗の原因。
    pub error: NetError,
    /// 解除できなかったコンテナ（fd と pin パスを保持したまま）。
    pub container: Box<NoneModeContainer<N>>,
}

impl<N> NoneModeReleaseError<N> {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl<N> fmt::Display for NoneModeReleaseError<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<N: fmt::Debug> std::error::Error for NoneModeReleaseError<N> {}

/// none モード作成が使うカーネル操作の境界。Linux 実装とテストの fake を差し替えるための crate 内部
/// トレイトで、公開の拡張点（PLUG-1）ではない。
pub(crate) trait NoneModeOps {
    /// netns ハンドル。
    type Netns;
    /// `dir` 直下に `id` 名で pin した新しい netns を作る（置き場の識別子は none モードでは使わない）。
    fn create_netns(
        &self,
        dir: &Path,
        id: &EndpointId,
    ) -> Result<(Self::Netns, (u64, u64)), NetnsFailure>;
    /// pin を外す。失敗時はハンドルを返す。
    fn unpin_netns(&self, ns: Self::Netns) -> Result<(), UnpinFailure<Self::Netns>>;
    /// `ns` の中で名前から ifindex を引く。
    fn netns_link_index(&self, ns: &Self::Netns, name: &IfName) -> Result<IfIndex, NetError>;
    /// `ns` の中で ifindex 指定で up にする。
    fn netns_set_up(&self, ns: &Self::Netns, link: IfIndex) -> Result<(), NetError>;
    /// 成功時に netns 内の route ソケットを閉じる（fd を常駐させない。CORE-9）。
    fn release_netns_socket(&self, ns: &mut Self::Netns);
}

/// OS 非依存の本体。netns 作成 → `lo` up の順で行い、失敗時は自分が作った pin を戻す。
/// 呼び出し元は Linux 実装の `create_none_netns` とテスト。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn create_none_netns_with<O: NoneModeOps>(
    ops: &O,
    spec: &NoneModeSpec,
) -> Result<NoneModeContainer<O::Netns>, NoneModeError> {
    let pin = spec.netns_path();
    let (mut netns, _dir_id) = match ops.create_netns(&spec.netns_dir, &spec.endpoint) {
        Ok(created) => created,
        Err(f) => {
            let mut rollback = AttachRollbackReport::default();
            if let Some(state) = f.leftover {
                rollback.leftover.push((AttachResource::Netns(pin), state));
            }
            return Err(NoneModeError {
                error: f.error,
                step: NoneModeStep::CreateNetns,
                rollback,
            });
        }
    };

    if let Err(error) = bring_up_loopback(ops, &netns) {
        let mut rollback = AttachRollbackReport::default();
        match ops.unpin_netns(netns) {
            Ok(()) => rollback.removed.push(AttachResource::Netns(pin)),
            // 結果不明（時間切れ等）は fail-closed で `Unknown`。ハンドルは手放すが、pin は同一プロセスの
            // `netns::unpin_path` で解除をやり直せる。
            Err(UnpinFailure { error: e, netns }) => {
                drop(netns);
                let state = if is_indeterminate(e.code()) {
                    ResourceState::Unknown
                } else {
                    ResourceState::Present
                };
                rollback.leftover.push((AttachResource::Netns(pin), state));
            }
        }
        return Err(NoneModeError {
            error,
            step: NoneModeStep::ConfigureLoopback,
            rollback,
        });
    }
    ops.release_netns_socket(&mut netns);

    Ok(NoneModeContainer {
        endpoint: spec.endpoint.clone(),
        netns_path: pin,
        netns,
    })
}

/// `lo` を引いて up にする。127.0.0.1/8 はカーネルが自動付与する。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn bring_up_loopback<O: NoneModeOps>(ops: &O, netns: &O::Netns) -> Result<(), NetError> {
    let lo = IfName::new("lo")?;
    let index = ops.netns_link_index(netns, &lo)?;
    ops.netns_set_up(netns, index)
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
#[cfg(target_os = "linux")]
struct LinuxNoneModeOps<'a> {
    timeout: Duration,
    recorder: &'a Arc<dyn NetOpRecorder>,
}

#[cfg(target_os = "linux")]
impl LinuxNoneModeOps<'_> {
    fn ns_route(ns: &ContainerNetns) -> Result<&NetlinkRouteSocket, NetError> {
        ns.route_socket().ok_or_else(|| {
            NetError::new(
                NetErrorCode::FailedPrecondition,
                "netns route socket is not available",
            )
        })
    }
}

#[cfg(target_os = "linux")]
impl NoneModeOps for LinuxNoneModeOps<'_> {
    type Netns = ContainerNetns;

    fn create_netns(
        &self,
        dir: &Path,
        id: &EndpointId,
    ) -> Result<(ContainerNetns, (u64, u64)), NetnsFailure> {
        netns::create_pinned(dir, id, self.timeout, self.recorder)
    }

    fn unpin_netns(&self, ns: ContainerNetns) -> Result<(), UnpinFailure<ContainerNetns>> {
        netns::unpin(ns)
    }

    fn netns_link_index(&self, ns: &ContainerNetns, name: &IfName) -> Result<IfIndex, NetError> {
        Self::ns_route(ns)?.link_index(name, self.timeout)
    }

    fn netns_set_up(&self, ns: &ContainerNetns, link: IfIndex) -> Result<(), NetError> {
        Self::ns_route(ns)?
            .set_link(&LinkSet::up(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn release_netns_socket(&self, ns: &mut ContainerNetns) {
        ns.release_route_socket();
    }
}

/// `lo` だけを持つコンテナ専用 netns を作って pin する（NET-6 none モード。TASK-143.2）。
///
/// `timeout` は netns 作成スレッドの完了待ちと各 netlink 要求の期限（REPAIR-5）。`recorder` は操作の
/// 計装の記録先（REPAIR-4。不要なら `NoopNetOpRecorder`）。失敗時は自分が作った pin を戻し、結果が
/// 不明なものは削除せず [`NoneModeError::rollback`] に `Unknown` で報告する。
#[cfg(target_os = "linux")]
pub fn create_none_netns(
    spec: &NoneModeSpec,
    timeout: Duration,
    recorder: &Arc<dyn NetOpRecorder>,
) -> Result<NoneModeContainer<ContainerNetns>, NoneModeError> {
    create_none_netns_with(&LinuxNoneModeOps { timeout, recorder }, spec)
}

/// none モードの netns の pin を外す（umount → ファイル削除）。fd は成功時に閉じる。
///
/// 失敗時は [`NoneModeReleaseError`] でハンドルを返す。
#[cfg(target_os = "linux")]
pub fn release_none_netns(
    container: NoneModeContainer<ContainerNetns>,
) -> Result<(), NoneModeReleaseError<ContainerNetns>> {
    let NoneModeContainer {
        endpoint,
        netns_path,
        netns,
    } = container;
    netns::unpin(netns).map_err(|UnpinFailure { error, netns }| NoneModeReleaseError {
        error,
        container: Box::new(NoneModeContainer {
            endpoint,
            netns_path,
            netns,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<String>>,
        create: Option<NetnsFailure>,
        fail_index: Option<NetErrorCode>,
        fail_up: Option<NetErrorCode>,
        fail_unpin: Option<NetErrorCode>,
    }

    impl Fake {
        fn rec(&self, s: impl Into<String>) {
            self.log.borrow_mut().push(s.into());
        }
    }

    fn err(code: NetErrorCode) -> NetError {
        NetError::new(code, "fake failure")
    }

    impl NoneModeOps for Fake {
        type Netns = ();
        fn create_netns(
            &self,
            dir: &Path,
            id: &EndpointId,
        ) -> Result<((), (u64, u64)), NetnsFailure> {
            self.rec(format!("create {} {}", dir.display(), id.as_str()));
            match &self.create {
                Some(f) => Err(f.clone()),
                None => Ok(((), (1, 2))),
            }
        }
        fn unpin_netns(&self, (): ()) -> Result<(), UnpinFailure<()>> {
            self.rec("unpin");
            match self.fail_unpin {
                Some(c) => Err(UnpinFailure {
                    error: err(c),
                    netns: (),
                }),
                None => Ok(()),
            }
        }
        fn netns_link_index(&self, (): &(), name: &IfName) -> Result<IfIndex, NetError> {
            self.rec(format!("index {}", name.as_str()));
            match self.fail_index {
                Some(c) => Err(err(c)),
                None => IfIndex::new(1),
            }
        }
        fn netns_set_up(&self, (): &(), link: IfIndex) -> Result<(), NetError> {
            self.rec(format!("up {}", link.get()));
            self.fail_up.map_or(Ok(()), |c| Err(err(c)))
        }
        fn release_netns_socket(&self, (): &mut ()) {
            self.rec("release_socket");
        }
    }

    fn spec() -> NoneModeSpec {
        NoneModeSpec::new(
            EndpointId::new("ctr1").unwrap(),
            PathBuf::from("/run/fandhe/netns"),
        )
        .unwrap()
    }

    fn pin() -> PathBuf {
        PathBuf::from("/run/fandhe/netns").join("ctr1")
    }

    /// NET-6・TASK-143.2: 正常系は netns 作成 → lo の up → ソケット解放の順で、veth 等を作らない。
    #[test]
    fn net6_none_mode_only_brings_up_loopback() {
        let f = Fake::default();
        let c = create_none_netns_with(&f, &spec()).unwrap();
        assert_eq!(
            *f.log.borrow(),
            vec![
                "create /run/fandhe/netns ctr1",
                "index lo",
                "up 1",
                "release_socket"
            ]
        );
        assert_eq!(c.netns_path, pin());
        assert_eq!(c.endpoint.as_str(), "ctr1");
    }

    /// NET-6: 相対パスの置き場は拒否する。
    #[test]
    fn net6_relative_netns_dir_is_rejected() {
        let e = NoneModeSpec::new(EndpointId::new("a").unwrap(), PathBuf::from("rel")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-6: netns 作成の失敗（残骸なし）は空の報告。
    #[test]
    fn net6_create_failure_without_leftover() {
        let f = Fake {
            create: Some(NetnsFailure {
                error: err(NetErrorCode::PermissionDenied),
                leftover: None,
            }),
            ..Fake::default()
        };
        let e = create_none_netns_with(&f, &spec()).unwrap_err();
        assert_eq!(e.step, NoneModeStep::CreateNetns);
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.rollback, AttachRollbackReport::default());
        assert_eq!(*f.log.borrow(), vec!["create /run/fandhe/netns ctr1"]);
    }

    /// NET-6: netns 作成の結果不明は pin を `Unknown` で報告する。
    #[test]
    fn net6_create_failure_with_unknown_leftover() {
        let f = Fake {
            create: Some(NetnsFailure {
                error: err(NetErrorCode::Timeout),
                leftover: Some(ResourceState::Unknown),
            }),
            ..Fake::default()
        };
        let e = create_none_netns_with(&f, &spec()).unwrap_err();
        assert_eq!(
            e.rollback.leftover,
            vec![(AttachResource::Netns(pin()), ResourceState::Unknown)]
        );
        assert!(e.rollback.removed.is_empty());
    }

    /// NET-6: lo 設定の失敗は pin を戻し、元のエラーを保つ。
    #[test]
    fn net6_loopback_failure_rolls_back_pin() {
        for (idx, up) in [
            (Some(NetErrorCode::NotFound), None),
            (None, Some(NetErrorCode::Internal)),
        ] {
            let f = Fake {
                fail_index: idx,
                fail_up: up,
                ..Fake::default()
            };
            let e = create_none_netns_with(&f, &spec()).unwrap_err();
            assert_eq!(e.step, NoneModeStep::ConfigureLoopback);
            assert_eq!(Some(e.code()), idx.or(up));
            assert_eq!(e.rollback.removed, vec![AttachResource::Netns(pin())]);
            assert!(e.rollback.leftover.is_empty());
            assert_eq!(f.log.borrow().iter().filter(|s| *s == "unpin").count(), 1);
            assert!(!f.log.borrow().contains(&"release_socket".to_owned()));
        }
    }

    /// NET-6: unpin も失敗したら状態を報告し、元のエラーは上書きしない。
    #[test]
    fn net6_unpin_failure_is_reported_without_masking() {
        for (unpin_code, state) in [
            (NetErrorCode::Timeout, ResourceState::Unknown),
            (NetErrorCode::PermissionDenied, ResourceState::Present),
        ] {
            let f = Fake {
                fail_up: Some(NetErrorCode::Internal),
                fail_unpin: Some(unpin_code),
                ..Fake::default()
            };
            let e = create_none_netns_with(&f, &spec()).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::Internal);
            assert!(e.rollback.removed.is_empty());
            assert_eq!(
                e.rollback.leftover,
                vec![(AttachResource::Netns(pin()), state)]
            );
        }
    }
}
