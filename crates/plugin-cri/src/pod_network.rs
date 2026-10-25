//! Pod 単位のライフサイクルを `NetworkPlugin` の呼び出しへ写す層（TASK-114.4・#460・MS-4・CRI-7・CRI-2）。
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
    DeleteNetworkRequest, DeleteNetworkResponse, DetachRequest, ErrorCode, IpCidr, NetworkName,
    NetworkPlugin, NetworkStatus, TraitError,
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
