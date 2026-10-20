//! Pod 単位のライフサイクルを `NetworkPlugin` の呼び出しへ写す層（TASK-114.4・#460・CRI-7・CRI-2）。
//!
//! 呼び出し元: 将来は `fandhe-container-cri` の `RunPodSandbox`・`CreateContainer`・`RemovePodSandbox`
//! の配線（#459 以降）が使う。現状は CRI の RPC からの呼び出しが無く、plugin 層で「PodSandbox の作成で
//! ネットワークが作られ、コンテナの作成で netns が用意されて接続され、PodSandbox の削除で資源が解放される」
//! 順序を機械的に照合するための薄い関数である（REPAIR-3）。
//!
//! | CRI の操作 | 関数 | `NetworkPlugin` の呼び出し |
//! | ---------- | ---- | -------------------------- |
//! | `RunPodSandbox` | [`set_up_pod`] | `create_network` |
//! | `CreateContainer` | [`set_up_container`] | `create_netns` → `attach` |
//! | `StopPodSandbox` / `RemovePodSandbox` | [`tear_down_pod`] | `delete_network` |

use fandhe_container_core::traits::{
    AttachRequest, AttachResponse, ContainerId, CreateNetnsRequest, CreateNetworkRequest,
    DeleteNetworkRequest, DetachRequest, ErrorCode, IpCidr, NetworkName, NetworkPlugin,
    NetworkStatus, TraitError,
};

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
            Ok(_) => Err(e),
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

/// PodSandbox のネットワークを削除する（`net-delete`）。
pub fn tear_down_pod(net: &dyn NetworkPlugin, name: &NetworkName) -> Result<(), TraitError> {
    net.delete_network(&DeleteNetworkRequest::new(name.clone()))
        .map(|_| ())
}
