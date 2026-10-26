//! CRI の `PodSandboxConfig`・`ContainerConfig` から OCI `config.json` への純粋な変換と入力検証
//! （CRI-1・CRI-2・ERR-3・OCI-4・SEC-1・SEC-5・REPAIR-2。#2395）。
//!
//! ファイルシステムにも core にも触れない。呼び出し元は [`super::SpecBundleProvider`]（bundle ディレクトリへ
//! `config.json` を書く）で、出力は core の `oci_runtime::parse_config_bytes` が読む形式である。
//!
//! **fail-closed**: 実行層（core の create・start）が受けない項目、または黙って落とすと要求より分離が弱くなる項目
//! （privileged・capability の追加・seccomp / AppArmor の無効化・NODE の pid / ipc 等）は、黙って落とさず
//! `UNIMPLEMENTED` で拒否する。値域外・形式不正は `INVALID_ARGUMENT`。エラー文言は固定文言と CRI の
//! フィールド名だけにし、値（env の秘密値・パス）を含めない。
//!
//! **上限**: 件数・長さは core の `oci_runtime::config` の上限（`CONFIG_MAX_*`）と同じ値を本モジュールで持つ
//! （cri は core の `traits` だけを参照する境界のため。CRI-7）。一致は試験で core の定数と照合する。
//!
//! **未実装・簡易実装（REPAIR-3）**:
//! - namespace の共有: pid の `POD` は未実装で、コンテナごとの新しい namespace にする（共有の欠落であり、
//!   要求より分離が弱くなる方向ではない。core の PID 1 前提の証跡と両立しないため。#2674 の後続）。ipc の `POD` は
//!   [`PodNamespacePaths`]（pod の保持役が作った user＋ipc namespace のパス）が与えられたときだけ
//!   `linux.namespaces[].path` で join する（core が user＋ipc の組に限って受ける。CRI-2・CORE-3。#2674）。
//!   [`PodNamespacePaths`] は保持役の pid から `/proc/<pid>/ns/{user,ipc}` だけを組み立てる（#2776）。
//!   供給元（保持役）はまだ無く、`CriRuntimeService` は当面 `None` を渡すため、本番では共有されず新しい
//!   namespace になる。`/dev/shm` は共有しない（core がコンテナごとの tmpfs を載せる）。`/proc/<pid>` を
//!   Create の時点で書く方式は pid の再利用で別 pod の namespace へ入り得る（SEC-1）ため採らない。
//! - network namespace: `POD` / `CONTAINER` は `{"type":"network"}` を出す。`POD` で pod の netns のパスを受けたとき
//!   （[`build_runtime_config_with_pod_netns`]。`NetworkPlugin` 経由で作って結線した netns。#2675・NET-1）は
//!   `{"type":"network","path":…}` にする。core の start は network namespace も `linux.namespaces[].path` の
//!   network もまだ受けず `Unimplemented` で拒否する（core の join は後続。`docs/design/cri-config-acceptance.md` の順 13）。`NODE`（host）は
//!   network namespace を出さない（ホストの netns で動く。利用者が明示した場合だけ）。crictl 疎通確認
//!   （#442）の pod.json（`scripts/testdata/cri/pod.json`）は `namespace_options.network = NODE` を明示して揃えてある（#2592）。
//! - user namespace: `userns_options.mode` が `NODE` でも新しい user namespace にする（分離を強める方向。
//!   uid の写像は core の launcher が権限モデルから導く。SEC-5）。`uids` / `gids` の指定は未実装（#2240）。
//! - イメージ config（Entrypoint・Cmd・Env・WorkingDir・User・StopSignal）の解析は [`super::ImageRootfsSource`]（#2433）が行い、
//!   ここでは [`ImageDefaults`] で受ける。イメージの User が名前・uid のみ（`/etc/passwd` の解決が要る形）のときは、
//!   `ImageRootfsSource` が展開後の rootfs の passwd / group を fd 起点で読んで解決する（#2606）。解決できなかった
//!   ときは [`ImageDefaults::user_unresolved`] で受け、CRI の `run_as_user` が無ければ `UNIMPLEMENTED` で拒否する
//!   （root へ黙ってフォールバックしない）。
//! - `run_as_username` は形式を検証し（空でない・256 バイト以下・NUL / `:` / `/` / 改行なし・数字だけは不可）、
//!   `ImageRootfsSource` が展開後の rootfs の passwd で解決した値を [`ImageDefaults::resolved_run_as_username`] で受ける
//!   （#2664・CRI-2・SEC-5）。`run_as_user` との同時指定は `INVALID_ARGUMENT`、`run_as_group` は `run_as_user` か
//!   `run_as_username` があるときだけ有効。解決結果が無ければ `UNIMPLEMENTED`（root へ黙って落とさない）。
//! - `dns_config` は [`resolv_conf::render`] で検証して resolv.conf を作り、`/etc/resolv.conf` への ro の bind を
//!   `mounts[]` の末尾に出す（#2665・CRI-2・NET-5）。ファイル自体は [`super::SpecBundleProvider`] が bundle に書き、
//!   そのパスを [`BundleFiles`] で受ける（本モジュールはファイルに触れない）。ファイルのパスを渡さない入口
//!   （[`build_runtime_config`]）に空でない `dns_config` が来たら `UNIMPLEMENTED`（黙って落とさない）。
//!   現状は core の start が、この ro の bind を拒否する（Landlock の書き込み可能な root 配下の ro は #1917、
//!   状態ルート配下の source の拒否。plugin-cri の bundle は `<state_root>/.cri/bundles`）。cri は受け入れて mount を
//!   出し、start は構造化エラーで止まる（network namespace と同じ形。`docs/design/cri-config-acceptance.md`）。
//! - `capabilities.drop_capabilities` は受け入れ、OCI 既定集合から除いた集合を `process.capabilities` の 3 集合
//!   （bounding / effective / permitted）へ書く（core が drop だけを解釈済みにして launch・exec へ適用する。
//!   #2666・CRI-2・SEC-1）。名前は大文字小文字を区別せず `CAP_` 接頭辞は任意、`ALL` は全 drop、既定に無いものの
//!   drop は no-op、未知名は `INVALID_ARGUMENT`。`add_capabilities` / `add_ambient_capabilities` は `UNIMPLEMENTED`。
//! - `log_path`（コンテナ）と `log_directory`（サンドボックス）は [`resolve_log_path`] で検証して結合し、受け入れる
//!   （CRI-2・SUP-4・#2671）。結合結果は config.json には出さず、StartContainer が supervisor へ渡す。
//! - `supplemental_groups` は受け入れ、`process.user.additionalGids` へ写す（core が launch の fork の前に user namespace の
//!   gid 写像と照合して `setgroups` で適用する。#2667・CRI-2・SEC-5・CORE-6）。各値は 0〜4294967294（負の値と
//!   `u32::MAX` は `INVALID_ARGUMENT`）。`supplemental_groups_policy` は `Merge`（既定。イメージの `/etc/group` の所属グループ
//!   〔[`ImageDefaults::supplementary_gids`]〕に続けて CRI の一覧を並べる）か `Strict`（CRI の一覧だけ）。実効 uid が 0 の
//!   コンテナにはイメージ由来のグループを付けない（単一 ID 写像で使える uid が 0 だけのため。CRI の明示した一覧は付ける）。
//!   主 gid は足さない。合計は [`MAX_ADDITIONAL_GIDS`] まで。sandbox 側の指定は検証だけして適用先が無いため出力しない。
//! - `mounts[].propagation` は PRIVATE を `rprivate`、HOST_TO_CONTAINER を `rslave` で `config.json` の `mounts[].options` へ書く
//!   （core が `rslave` の bind をホストの slave として載せる。BIDIRECTIONAL と未知の値は `UNIMPLEMENTED`。
//!   `linux.rootfsPropagation` は出力しない。#2669・CRI-2・OCI-4）。
//! - `sandbox.linux.sysctls`（pod 単位）は、IPC 系（`kernel.shmmax` 等・`fs.mqueue.*`）だけ受け入れ、各コンテナの
//!   `config.json` の `linux.sysctl` へ写す（core が pivot 前に `rootfs/proc/sys` へ適用する。#2670・CRI-2・CORE-3）。
//!   ipc の `POD` で [`PodNamespacePaths`] へ join するときは共有された pod の IPC namespace へ書く（各コンテナが同じ
//!   pod の値を書く）。供給元（保持役）がまだ無い間は、pod 単位の値を各コンテナ自身の IPC namespace へ適用する近似になる
//!   （containerd も pod の sysctls を各コンテナへ写す）。分類は core の `sysctl::SysctlKey` を使い、規則を二重に持たない:
//!   `net.*`（pod の netns の結線 #2675 が前提）と UTS 系（`kernel.hostname`・`kernel.domainname`）は `UNIMPLEMENTED`、
//!   文法違反・名前空間を持たないキー（`kernel.panic`・`vm.*` 等）・不正な値は `INVALID_ARGUMENT`。
//! - `port_mappings` は検証し（`crate::port_mapping`）、公開する要素（`host_port > 0`）があるときは pod の
//!   netns（`pod_netns`）がある構成だけ受ける（なければ `UNIMPLEMENTED`）。公開そのものは RunPodSandbox の結線
//!   （plugin-cri の `publish_port`）が行い、config.json には何も出さない（#2676・CRI-2・NET-3）。
//! - 本モジュールが `UNIMPLEMENTED` で拒否する CRI 項目（cgroup_parent・
//!   devices・capabilities の add / ambient・propagation の BIDIRECTIONAL 等）の受け入れ順序と担当は
//!   `docs/design/cri-config-acceptance.md`（#2606）にまとめている。
//! - `linux.cgroup_parent` の受け入れ方針（オーナー承認待ち。判断が出るまで `UNIMPLEMENTED`）は
//!   `docs/design/cri-cgroup-parent.md`（#2672・CRI-2・CORE-4）にまとめている。
//! - `devices`・`cdi_devices` の受け入れ方針（オーナー判断待ち。判断が出るまで `UNIMPLEMENTED`）は
//!   `docs/design/cri-devices-cdi.md`（#2673・CRI-2・GPU-1）にまとめている。

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU32;

use serde::Serialize;

use fandhe_container_core::capabilities::{Capability, CapabilitySet, OCI_DEFAULT_CAPABILITIES};
use fandhe_container_core::path_masks::normalize_container_path;
use fandhe_container_core::sysctl::{
    SYSCTL_MAX_ENTRIES, SysctlError, SysctlKey, SysctlNamespace, SysctlValue,
};
use fandhe_container_core::traits::ContainerLogPath;

use super::resolv_conf;
use crate::error::CriError;
use crate::runtime::v1::{
    ContainerConfig, Int64Value, LinuxContainerResources, Mount, MountPropagation, NamespaceMode,
    NamespaceOption, PodSandboxConfig, SecurityProfile, SupplementalGroupsPolicy,
    security_profile::ProfileType,
};

/// `config.json` 全体の上限（core の `CONFIG_MAX_BYTES` と同値）。
pub const MAX_CONFIG_BYTES: usize = 4 << 20;
/// `process.args` / `process.env` の件数上限（core の `CONFIG_MAX_ARGS` / `CONFIG_MAX_ENV` と同値）。
pub const MAX_ARGS: usize = 4096;
/// `process.env` の件数上限。
pub const MAX_ENV: usize = 4096;
/// 文字列 1 要素の長さ上限（core の `CONFIG_MAX_STRING_BYTES` と同値）。
pub const MAX_STRING_BYTES: usize = 131_071;
/// パスの長さ上限（core の `CONFIG_MAX_PATH_BYTES` と同値）。
pub const MAX_PATH_BYTES: usize = 4096;
/// `mounts` の件数上限（core の `CONFIG_MAX_MOUNTS` と同値）。
pub const MAX_MOUNTS: usize = 1024;
/// `maskedPaths` / `readonlyPaths` の件数上限（core の `CONFIG_MAX_MASKED_PATHS` / `CONFIG_MAX_READONLY_PATHS` と同値）。
pub const MAX_PROTECTED_PATHS: usize = 256;
/// hostname の長さ上限（core の `CONFIG_MAX_HOSTNAME_BYTES` と同値）。
pub const MAX_HOSTNAME_BYTES: usize = 64;
/// `process.user.additionalGids` の件数上限（core の `CONFIG_MAX_ADDITIONAL_GIDS` と同値。`NGROUPS_MAX`。#2667）。
pub const MAX_ADDITIONAL_GIDS: usize = 65_536;

/// 生成する `ociVersion`（core は `1.x` 系だけを受ける）。
/// mount 1 件あたりの JSON 構造の概算オーバーヘッド（キー名・options 等）。
const MOUNT_OVERHEAD: usize = 128;
/// 文字列 1 要素あたりの JSON 構造の概算オーバーヘッド（引用符・区切り・エスケープの余裕）。
const ITEM_OVERHEAD: usize = 8;

const OCI_VERSION: &str = "1.2.0";

/// イメージ config 由来の既定値（Entrypoint・Cmd・Env・WorkingDir・User。#2433 が埋める）。
///
/// どの項目も省略でき、`ImageDefaults::default()` なら CRI の設定だけで変換する。外部 crate（#2433 の
/// `RootfsSource` 実装）が構造体式で組み立てられるよう `#[non_exhaustive]` にしない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageDefaults {
    /// イメージの Entrypoint。
    pub entrypoint: Vec<String>,
    /// イメージの Cmd。
    pub cmd: Vec<String>,
    /// イメージの Env（`KEY=VALUE`）。
    pub env: Vec<String>,
    /// イメージの WorkingDir。
    pub working_dir: Option<String>,
    /// イメージの User（uid, gid）。数値の `uid:gid`、または `ImageRootfsSource` が rootfs の passwd / group で解決した値。
    pub user: Option<(u32, u32)>,
    /// イメージの User が名前または uid のみで、解決できていない（passwd / group に無い・読めない等。#2433・#2606）。
    /// 真で CRI の `run_as_user` が無いときは `UNIMPLEMENTED` で拒否する。
    pub user_unresolved: bool,
    /// CRI の `run_as_username` を rootfs の passwd で解決した `(uid, gid)`（#2664・CRI-2・SEC-5）。
    /// `ImageRootfsSource` が [`super::UserResolveRequest`] を受けて埋める。要求があるのに `None` の
    /// ままなら `build_runtime_config` は `UNIMPLEMENTED` で拒否する（root へ黙って落とさない）。
    pub resolved_run_as_username: Option<(u32, u32)>,
    /// 実効ユーザーのイメージの `/etc/group` での所属グループ（`/etc/group` の行順。#2667・CRI-2・SEC-5）。
    /// `ImageRootfsSource` が [`super::UserResolveRequest::image_groups`] が真で実効 uid が 0 でないときだけ埋める
    /// （既定は空 = イメージ由来のグループは付かない。付かない方向は権限が弱くなる側）。
    pub supplementary_gids: Vec<u32>,
    /// イメージ config の `StopSignal` を CRI のシグナルへ解釈した値（空・欠落は `None`。#2771・CRI-2・OCI-1）。
    /// CRI の `stop_signal` が `RUNTIME_DEFAULT` のときだけ使われる（`crate::stop_signal::resolve_stop_signal`）。
    /// 解釈できない値は `ImageRootfsSource` が `INVALID_ARGUMENT` で拒否するため、ここには入らない。
    pub stop_signal: Option<crate::runtime::v1::Signal>,
}

/// `build_inner` の段階。`Validate` は rootfs を触る前の形式検証、`Build` は `config.json` の確定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Validate,
    Build,
}

/// `/etc/resolv.conf` の宛先（利用者の値は宛先にも source にも届かない）。
const RESOLV_CONF_DESTINATION: &str = "/etc/resolv.conf";
/// 検証段（source 未確定）で使う仮の source。出力は捨てられ、重なり検査にだけ宛先が使われる。
const RESOLV_CONF_PLACEHOLDER_SOURCE: &str = "/resolv.conf";

/// bundle の中に provider が生成したファイルのホスト側の絶対パス（本モジュールはファイルシステムに触れない。#2665）。
///
/// 将来 hostname / hosts の生成（NET-12）を同じ構造体に足せるよう `#[non_exhaustive]` にしている。
/// 外部からは [`Self::none`] / [`Self::with_resolv_conf`] で作る。
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BundleFiles<'a> {
    /// 生成した resolv.conf のパス（`dns_config` が空でないときに必要）。
    pub resolv_conf: Option<&'a str>,
}

impl<'a> BundleFiles<'a> {
    /// 生成ファイルなし。
    pub fn none() -> Self {
        Self::default()
    }

    /// 生成した resolv.conf のパスを渡す。
    pub fn with_resolv_conf(path: &'a str) -> Self {
        Self {
            resolv_conf: Some(path),
        }
    }
}

/// `run_as_username` の長さ上限（バイト。passwd の名前の上限。`image_rootfs` の名前上限と同値）。
pub(crate) const MAX_USERNAME_BYTES: usize = 256;

/// `run_as_username` の形式を検証する（空は未指定）。ファイルシステムに触れる前に呼ぶ。
///
/// 数字だけの名前は uid との曖昧さを作るため拒否する（数値は `run_as_user`。containerd は uid 扱いだが、
/// CRI の「passwd に存在すること」を満たさないため採らない。#2664）。
pub(crate) fn check_username(name: &str) -> Result<Option<&str>, CriError> {
    if name.is_empty() {
        return Ok(None);
    }
    if name.len() > MAX_USERNAME_BYTES
        || name.bytes().all(|b| b.is_ascii_digit())
        || name
            .bytes()
            .any(|b| matches!(b, 0 | b':' | b'/' | b'\n' | b'\r'))
    {
        return Err(invalid("run_as_username"));
    }
    Ok(Some(name))
}

/// 検証済みの `config.json` のバイト列（REPAIR-2）。
///
/// [`build_runtime_config`] 以外からは作れない。生の JSON 文字列を手で組んで書き出さないための型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigJson {
    bytes: Vec<u8>,
    user: AppliedUser,
}

impl RuntimeConfigJson {
    /// 直列化済みのバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `process.user` に書いた uid・gid・補助グループ（`ContainerStatus.user` の報告に使う。#2771・CRI-2・SEC-5）。
    ///
    /// バイト列に書いたのと同じ値で、推測や既定値で補わない。
    pub fn process_user(&self) -> &AppliedUser {
        &self.user
    }
}

/// 起動時に適用する識別情報（config.json の `process.user` に書いた値。#2771・CRI-2・SEC-5）。
///
/// `SpecBundleProvider` が `PreparedBundle` に載せて `CriRuntimeService` へ返し、`ContainerStatus.user.linux`
/// （KEP-3619）として報告される。補助グループは重複除去後の最終の集合で、主 gid は自動では含めない
/// （core の launcher が `setgroups(list)` でそのまま適用するため）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppliedUser {
    uid: u32,
    gid: u32,
    additional_gids: Vec<u32>,
}

impl AppliedUser {
    /// 組み立てる（報告する provider 実装と試験用）。
    pub fn new(uid: u32, gid: u32, additional_gids: Vec<u32>) -> Self {
        Self {
            uid,
            gid,
            additional_gids,
        }
    }
    /// 適用する uid。
    pub fn uid(&self) -> u32 {
        self.uid
    }
    /// 適用する主 gid。
    pub fn gid(&self) -> u32 {
        self.gid
    }
    /// 補助グループ（config.json の `additionalGids` と同じ順序・同じ集合）。
    pub fn additional_gids(&self) -> &[u32] {
        &self.additional_gids
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpecOut<'a> {
    oci_version: &'static str,
    root: RootOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    process: ProcessOut,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<MountOut<'a>>,
    linux: LinuxOut<'a>,
}

#[derive(Serialize)]
struct RootOut {
    path: &'static str,
}

#[derive(Serialize)]
struct ProcessOut {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    user: UserOut,
    /// `drop_capabilities` の指定があるときだけ書く（無ければ core が OCI 既定集合を使う）。
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<CapabilitiesOut>,
}

/// `process.capabilities`。3 集合を同じ値にする（core が drop だけを解釈済みにする形。#2666）。
/// `inheritable` / `ambient` は書かない（core は空でない指定を未適用として拒否する）。
#[derive(Serialize)]
struct CapabilitiesOut {
    bounding: Vec<&'static str>,
    effective: Vec<&'static str>,
    permitted: Vec<&'static str>,
}

/// `drop_capabilities` の件数の上限（既知の capability 数の 2 倍。重複を許す）。
const MAX_DROP_CAPABILITIES: usize = 2 * Capability::ALL.len();
/// `drop_capabilities` の名前 1 件の長さの上限（バイト）。
const MAX_CAPABILITY_NAME_BYTES: usize = 32;

/// CRI の `drop_capabilities` を OCI 既定集合から除いた集合へ変換する（CRI-2・SEC-1・#2666）。
///
/// 名前は大文字小文字を区別せず、`CAP_` 接頭辞は任意（containerd と同じ想定）。`ALL` は全 drop。
/// 既定集合に無い capability の drop は no-op として受理する。未知の名前・空・長すぎる名前は
/// `INVALID_ARGUMENT`（指定された名前はエラーに載せない）。drop の指定が無ければ `None`。
fn drop_capabilities(names: &[String]) -> Result<Option<CapabilitiesOut>, CriError> {
    if names.is_empty() {
        return Ok(None);
    }
    if names.len() > MAX_DROP_CAPABILITIES {
        return Err(invalid("drop_capabilities"));
    }
    let mut dropped = CapabilitySet::empty();
    for name in names {
        if name.is_empty() || name.len() > MAX_CAPABILITY_NAME_BYTES || !name.is_ascii() {
            return Err(invalid("drop_capabilities"));
        }
        let upper = name.to_ascii_uppercase();
        if upper == "ALL" {
            dropped = OCI_DEFAULT_CAPABILITIES
                .iter()
                .fold(dropped, |set, c| set.with(*c));
            continue;
        }
        let full = if upper.starts_with("CAP_") {
            upper
        } else {
            format!("CAP_{upper}")
        };
        let cap = Capability::from_name(&full).ok_or_else(|| invalid("drop_capabilities"))?;
        dropped = dropped.with(cap);
    }
    let kept: Vec<&'static str> = OCI_DEFAULT_CAPABILITIES
        .iter()
        .copied()
        .filter(|c| !dropped.contains(*c))
        .map(Capability::as_str)
        .collect();
    // 出力順は `Capability::ALL`（番号順）にそろえる。
    let ordered: Vec<&'static str> = Capability::ALL
        .iter()
        .map(|c| c.as_str())
        .filter(|n| kept.contains(n))
        .collect();
    Ok(Some(CapabilitiesOut {
        bounding: ordered.clone(),
        effective: ordered.clone(),
        permitted: ordered,
    }))
}

#[derive(Serialize)]
struct UserOut {
    uid: u32,
    gid: u32,
    /// 補助グループ。空なら出力しない（core は省略を空として扱う）。
    #[serde(rename = "additionalGids", skip_serializing_if = "Vec::is_empty")]
    additional_gids: Vec<u32>,
}

#[derive(Serialize)]
struct MountOut<'a> {
    destination: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    source: &'a str,
    options: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinuxOut<'a> {
    namespaces: Vec<NamespaceOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<ResourcesOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    masked_paths: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    readonly_paths: Vec<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    sysctl: BTreeMap<&'a str, &'a str>,
}

#[derive(Serialize)]
struct NamespaceOut<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    /// 既存 namespace へ join するパス（pod の ipc 共有のとき user と ipc だけ。#2674）。
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
}

/// pod の保持役が作った user・ipc namespace のパス（CRI-2・CORE-3・SEC-5。#2674・#2776）。
///
/// `SpecBundleProvider::prepare` が `BundleRequest` 経由で受け、ipc の `POD` を join に変える。
/// 公開の構築口は [`PodNamespacePaths::for_holder_pid`] だけで、`/proc/<pid>/ns/user` と
/// `/proc/<同じ pid>/ns/ipc` しか作れない。任意の文字列から作る口は crate の外へ出さない。
///
/// # 保持役を配線するときの契約（#2776）
///
/// - パスは、その sandbox（同じ `sandbox_id`）の記録が持つ保持役の pid からだけ導く。CRI リクエストの値
///   （`ContainerConfig`・annotations・`PodSandboxConfig` の文字列）からは作らない
/// - 別 pod の sandbox の pid を使わない。rootless で supervisor が初期 userns にいると、同じユーザーの別 pod の
///   userns も core の認可（親＝呼び出し側・作成者 uid＝euid）を満たしてしまうため（SEC-5）
/// - 配線の PR は、pod A のコンテナの config に pod B の pid のパスが出ないことと、出たパスの pid が自 sandbox
///   の記録の値と一致することを結合試験で足す
/// - 保持役は Create から Start の間生きている必要がある。pid の再利用の窓は core が start で 1 回だけ開いて
///   fd に固定し、所有者・親子・種別を照合して閉じる。cri の検査は形式だけの二次防御で、認可の正は core
///
/// 供給元（保持役）は未実装のため、`CriRuntimeService` は当面 `None` を渡す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodNamespacePaths {
    user: String,
    ipc: String,
}

/// `/proc/<pid>/ns/<kind>` と完全一致するパスから pid を取り出す。pid は 1 以上 `i32::MAX` 以下の正準な
/// 10 進（先頭ゼロ・符号・空白なし）に限る。`self`・`..`・二重スラッシュ・末尾スラッシュは `None`。
fn holder_pid_of(path: &str, kind: &str) -> Option<u32> {
    let rest = path.strip_prefix("/proc/")?;
    let (seg, tail) = rest.split_once('/')?;
    let mut parts = tail.split('/');
    if parts.next() != Some("ns") || parts.next() != Some(kind) || parts.next().is_some() {
        return None;
    }
    if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pid: u32 = seg.parse().ok()?;
    // 往復一致で先頭ゼロを除く。
    if pid == 0 || pid > i32::MAX as u32 || pid.to_string() != seg {
        return None;
    }
    Some(pid)
}

impl PodNamespacePaths {
    /// 保持役の pid から `/proc/<pid>/ns/user` と `/proc/<同じ pid>/ns/ipc` を組み立てる（#2776）。
    /// `pid_t` の正の上限（`i32::MAX`）を超える値は供給元の誤りなので `INTERNAL`。
    pub fn for_holder_pid(pid: NonZeroU32) -> Result<Self, CriError> {
        let pid = pid.get();
        Self::from_paths(
            &format!("/proc/{pid}/ns/user"),
            &format!("/proc/{pid}/ns/ipc"),
        )
    }

    /// 形式（`/proc/<pid>/ns/{user,ipc}` の完全一致・user と ipc で同じ pid）を検査して作る。不変条件の定義は
    /// ここ 1 か所に置く。違反は供給元の誤りなので、値を含まない固定文言の `INTERNAL`。
    pub(crate) fn from_paths(user: &str, ipc: &str) -> Result<Self, CriError> {
        match (holder_pid_of(user, "user"), holder_pid_of(ipc, "ipc")) {
            (Some(u), Some(i)) if u == i => Ok(Self {
                user: user.to_owned(),
                ipc: ipc.to_owned(),
            }),
            _ => Err(CriError::internal("invalid pod namespace path")),
        }
    }

    /// user namespace のパス。
    pub fn user(&self) -> &str {
        &self.user
    }

    /// ipc namespace のパス。
    pub fn ipc(&self) -> &str {
        &self.ipc
    }
}

#[derive(Serialize)]
struct ResourcesOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<CpuOut>,
}

#[derive(Serialize)]
struct MemoryOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    swap: Option<i64>,
}

#[derive(Serialize)]
struct CpuOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<i64>,
}

/// pod の `sysctls` を core の分類で検証する（#2670）。キー昇順に走査して、複数の不正があっても結果を決定的にする。
/// 受理した組は予算に計上し、`config.json` の `linux.sysctl` へ写す。
fn check_sysctls<'a>(
    sysctls: &'a HashMap<String, String>,
    budget: &mut Budget,
) -> Result<BTreeMap<&'a str, &'a str>, CriError> {
    if sysctls.len() > SYSCTL_MAX_ENTRIES {
        return Err(invalid("linux.sysctls"));
    }
    let sorted: BTreeMap<&str, &str> = sysctls
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for (key, value) in &sorted {
        match SysctlKey::parse(key) {
            Ok(k) if k.namespace() == SysctlNamespace::Ipc => {}
            // net.* は pod の netns の結線（#2675）が前提で未実装。
            Ok(_) | Err(SysctlError::Uts) => return Err(unsupported("linux.sysctls")),
            Err(_) => return Err(invalid("linux.sysctls")),
        }
        SysctlValue::parse(value).map_err(|_| invalid("linux.sysctls"))?;
        budget.spend(
            key.len()
                .saturating_add(value.len())
                .saturating_add(ITEM_OVERHEAD),
        )?;
    }
    Ok(sorted)
}

fn unsupported(field: &'static str) -> CriError {
    CriError::unimplemented(format!("{field} is not supported"))
}

fn invalid(field: &'static str) -> CriError {
    CriError::invalid_argument(format!("{field} is invalid"))
}

/// `additionalGids` 1 件あたりの JSON の大きさの見積もり（10 桁 + 区切り）。
const ADDITIONAL_GID_JSON_BYTES: usize = 11;

/// 補助グループを方針に従って並べる（重複は最初のものを残す。件数は [`MAX_ADDITIONAL_GIDS`] まで。#2667）。
///
/// `Strict` は `image` を使わない。上限超過は黙って切り詰めず `FAILED_PRECONDITION`（core が拒否する件数と同じ）。
fn merge_additional_gids(
    policy: SupplementalGroupsPolicy,
    image: &[u32],
    cri: &[u32],
) -> Result<Vec<u32>, CriError> {
    let image = match policy {
        SupplementalGroupsPolicy::Merge => image,
        SupplementalGroupsPolicy::Strict => &[],
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for g in image.iter().chain(cri) {
        if seen.insert(*g) {
            if out.len() >= MAX_ADDITIONAL_GIDS {
                return Err(CriError::failed_precondition(
                    "supplemental groups exceed the limit",
                ));
            }
            out.push(*g);
        }
    }
    Ok(out)
}

/// 文字列 1 要素の長さと NUL を検証する。
fn check_string(field: &'static str, s: &str) -> Result<(), CriError> {
    if s.len() > MAX_STRING_BYTES || s.contains('\0') {
        return Err(invalid(field));
    }
    Ok(())
}

/// 絶対パス（`/` 始まり・NUL 無し・`..` 無し・空要素無し・長さ上限以下）を検証する。
fn check_abs_path(field: &'static str, p: &str) -> Result<(), CriError> {
    if p.len() > MAX_PATH_BYTES || !p.starts_with('/') || p.contains('\0') {
        return Err(invalid(field));
    }
    if p == "/" {
        return Ok(());
    }
    let rest = p.strip_prefix('/').ok_or_else(|| invalid(field))?;
    for comp in rest.split('/') {
        if comp.is_empty() || comp == ".." {
            return Err(invalid(field));
        }
    }
    Ok(())
}

/// コンテナ内パスを core の `normalize_container_path` と同じ規則で検証する（OCI-4）。
///
/// `\`・`.`・`..`・空要素（`//`・末尾 `/`）を含む値と、正規化で値が変わる値、`/` のみの値は拒否する
/// （core が create / start で拒否または書き換える形を、config 生成の時点で `INVALID_ARGUMENT` にする）。
fn check_canonical_path(field: &'static str, p: &str) -> Result<(), CriError> {
    check_abs_path(field, p)?;
    match normalize_container_path(p, MAX_PATH_BYTES) {
        Some(n) if n == p => Ok(()),
        _ => Err(invalid(field)),
    }
}

/// ホスト側のマウント元を core の `validate_source` と同じ規則で検証する（絶対・`\` 無し・`.`・`..`・空要素無し・`/` 不可）。
pub(crate) fn check_host_source(field: &'static str, p: &str) -> Result<(), CriError> {
    if p.len() > MAX_PATH_BYTES || p.contains('\0') || p.contains('\\') {
        return Err(invalid(field));
    }
    let rest = p.strip_prefix('/').ok_or_else(|| invalid(field))?;
    if rest.is_empty() || rest.split('/').any(|e| matches!(e, "" | "." | "..")) {
        return Err(invalid(field));
    }
    Ok(())
}

/// 要素単位で同一または祖先・子孫の関係か（core の `overlaps` と同じ。`/a/b` と `/a/bc` は無関係）。
fn overlaps(a: &str, b: &str) -> bool {
    let within = |child: &str, parent: &str| {
        child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    a == b || within(a, b) || within(b, a)
}

/// bind mount 間・保護パスとの関係を core の `BindMountSet` と同じ条件で検証する
/// （予約先 `/proc`・`/sys`・`/dev` 配下、重複・入れ子、保護パスとの重なりを拒否。OCI-4・SEC-1）。
fn check_mount_set(
    mounts: &[MountOut<'_>],
    masked: &[&str],
    readonly: &[&str],
) -> Result<(), CriError> {
    const RESERVED: [&str; 3] = ["/proc", "/sys", "/dev"];
    for (i, m) in mounts.iter().enumerate() {
        let d = m.destination;
        if RESERVED
            .iter()
            .any(|r| overlaps(d, r) && d.len() >= r.len())
        {
            return Err(invalid("mounts.container_path"));
        }
        if mounts
            .iter()
            .take(i)
            .any(|prev| overlaps(prev.destination, d))
        {
            return Err(invalid("mounts.container_path"));
        }
        if masked.iter().chain(readonly.iter()).any(|p| overlaps(d, p)) {
            return Err(invalid("mounts.container_path"));
        }
    }
    Ok(())
}

/// `config.json` の総量予算（複製・直列化の前に checked 演算で消費する。REPAIR-5・DoS 防止）。
struct Budget {
    left: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            left: MAX_CONFIG_BYTES,
        }
    }

    /// `n` バイト分を消費する。予算を超える場合は `INVALID_ARGUMENT`。
    fn spend(&mut self, n: usize) -> Result<(), CriError> {
        self.left = self
            .left
            .checked_sub(n)
            .ok_or_else(|| invalid("config size"))?;
        Ok(())
    }
}

/// JSON 出力の上限付き writer（`MAX_CONFIG_BYTES` を超える書き込みを拒否する）。
struct LimitedWriter {
    buf: Vec<u8>,
}

impl std::io::Write for LimitedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf
            .len()
            .checked_add(data.len())
            .filter(|t| *t <= MAX_CONFIG_BYTES)
            .ok_or_else(|| std::io::Error::other("config too large"))?;
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 保護パス（masked / readonly）の検証。core の `ProtectedPath` と同じく root のみ（`/`）は拒否する。
fn check_protected_path(field: &'static str, p: &str) -> Result<(), CriError> {
    check_canonical_path(field, p)
}

/// `supplemental_groups` の各値を検証して `u32` にする（0〜4294967294。`u32::MAX` はカーネルの無効 gid
/// `(gid_t)-1` でどの写像にも入らないため拒否する。#2667）。
fn supplemental_gids(field: &'static str, v: &[i64]) -> Result<Vec<u32>, CriError> {
    check_supplemental_gid_count(v)?;
    v.iter().map(|g| supplemental_gid(field, *g)).collect()
}

/// `supplemental_groups` の件数を確保の前に検証する（重複を畳む前の入力件数。無制限確保を防ぐ。#2667）。
fn check_supplemental_gid_count(v: &[i64]) -> Result<(), CriError> {
    if v.len() > MAX_ADDITIONAL_GIDS {
        return Err(CriError::failed_precondition(
            "supplemental groups exceed the limit",
        ));
    }
    Ok(())
}

/// `supplemental_groups` の 1 値を検証する。
fn supplemental_gid(field: &'static str, g: i64) -> Result<u32, CriError> {
    u32::try_from(g)
        .ok()
        .filter(|g| *g != u32::MAX)
        .ok_or_else(|| invalid(field))
}

/// 値の検証だけを行い、一覧は確保しない（適用先が無い sandbox 側用。#2667）。
fn validate_supplemental_gids(field: &'static str, v: &[i64]) -> Result<(), CriError> {
    check_supplemental_gid_count(v)?;
    v.iter()
        .try_for_each(|g| supplemental_gid(field, *g).map(|_| ()))
}

/// `supplemental_groups_policy` を検証する（`Merge` か `Strict`。それ以外は `INVALID_ARGUMENT`）。
fn supplemental_policy(field: &'static str, v: i32) -> Result<SupplementalGroupsPolicy, CriError> {
    SupplementalGroupsPolicy::try_from(v).map_err(|_| invalid(field))
}

fn nonneg_u32(field: &'static str, v: &Option<Int64Value>) -> Result<Option<u32>, CriError> {
    match v {
        None => Ok(None),
        Some(v) => u32::try_from(v.value).map(Some).map_err(|_| invalid(field)),
    }
}

/// `RuntimeDefault` 以外（Unconfined・Localhost）は拒否する。core の既定 seccomp は常に適用される（CORE-5）。
fn check_profile(field: &'static str, p: &Option<SecurityProfile>) -> Result<(), CriError> {
    match p {
        None => Ok(()),
        Some(p) if p.profile_type == ProfileType::RuntimeDefault as i32 => Ok(()),
        Some(_) => Err(unsupported(field)),
    }
}

/// AppArmor は現状どの指定も受けない（`RuntimeDefault` を含む）。core に AppArmor プロファイルの適用処理が無く、
/// 受理すると明示された分離要求が黙って失われる（fail-closed。適用の実装は未着手。SEC-1）。
fn check_apparmor(field: &'static str, p: &Option<SecurityProfile>) -> Result<(), CriError> {
    match p {
        None => Ok(()),
        Some(_) => Err(unsupported(field)),
    }
}

fn resolve_mode(field: &'static str, v: i32) -> Result<NamespaceMode, CriError> {
    NamespaceMode::try_from(v).map_err(|_| invalid(field))
}

/// コンテナの namespace_options（無ければ sandbox の）を読み、`linux.namespaces` を決める。
///
/// `pod` があり ipc が `POD` のときだけ、ipc と user を既存 namespace への join（`path` 付き）にする。
/// `pod_netns` は `POD` モードの network namespace へ join するパス（pod の netns を `NetworkPlugin` 経由で
/// 作って結線したとき。#2675・CRI-2・NET-1）。`POD` 以外のモードでは使わない。
fn namespaces<'a>(
    opts: Option<&NamespaceOption>,
    pod: Option<&'a PodNamespacePaths>,
    pod_netns: Option<&'a str>,
) -> Result<Vec<NamespaceOut<'a>>, CriError> {
    let default = NamespaceOption::default();
    let o = opts.unwrap_or(&default);
    let mut out = Vec::with_capacity(6);
    // pid・ipc: POD / CONTAINER はコンテナごとの新しい namespace。ipc の POD だけは供給元があれば join。
    // NODE は必須 namespace を外す（SEC-1）ため拒否、TARGET は join 未対応。
    let mut join: Option<&PodNamespacePaths> = None;
    for (kind, field, v) in [
        ("pid", "namespace_options.pid", o.pid),
        ("ipc", "namespace_options.ipc", o.ipc),
    ] {
        match resolve_mode(field, v)? {
            NamespaceMode::Pod if kind == "ipc" && pod.is_some() => {
                join = pod;
                out.push(NamespaceOut {
                    kind,
                    path: pod.map(PodNamespacePaths::ipc),
                });
            }
            NamespaceMode::Pod | NamespaceMode::Container => {
                out.push(NamespaceOut { kind, path: None })
            }
            NamespaceMode::Node | NamespaceMode::Target => return Err(unsupported(field)),
        }
    }
    out.push(NamespaceOut {
        kind: "mount",
        path: None,
    });
    out.push(NamespaceOut {
        kind: "uts",
        path: None,
    });
    // user: 常に新しい namespace（SEC-5）。ipc を join するときは pod の user namespace に入る
    // （非特権では所有する user namespace ごとでなければ ipc に入れない）。写像の指定は未実装（#2240）。
    out.push(NamespaceOut {
        kind: "user",
        path: join.map(PodNamespacePaths::user),
    });
    if let Some(u) = &o.userns_options {
        match resolve_mode("namespace_options.userns_options.mode", u.mode)? {
            NamespaceMode::Pod | NamespaceMode::Node => {}
            // コンテナ単位の userns と pod の ipc 共有は両立しない。
            NamespaceMode::Container if join.is_some() => {
                return Err(unsupported("namespace_options.userns_options.mode"));
            }
            NamespaceMode::Container => {}
            NamespaceMode::Target => {
                return Err(unsupported("namespace_options.userns_options.mode"));
            }
        }
        if !u.uids.is_empty() || !u.gids.is_empty() {
            return Err(unsupported("namespace_options.userns_options mappings"));
        }
    }
    match resolve_mode("namespace_options.network", o.network)? {
        // POD で pod の netns のパスを受けたときだけ join 指定にする。パス無しは従来どおり path なしの
        // 要素で、core の start が `UNIMPLEMENTED` で拒否する（実装済みを装わない。REPAIR-3）。
        NamespaceMode::Pod => out.push(NamespaceOut {
            kind: "network",
            path: pod_netns,
        }),
        NamespaceMode::Container => out.push(NamespaceOut {
            kind: "network",
            path: None,
        }),
        NamespaceMode::Node => {}
        NamespaceMode::Target => return Err(unsupported("namespace_options.network")),
    }
    Ok(out)
}

/// 負の値を拒否して `Some(v)`（0 は未指定として `None`）にする。
fn positive(field: &'static str, v: i64) -> Result<Option<i64>, CriError> {
    match v {
        0 => Ok(None),
        v if v > 0 => Ok(Some(v)),
        _ => Err(invalid(field)),
    }
}

fn resources(r: &LinuxContainerResources) -> Result<Option<ResourcesOut>, CriError> {
    if r.cpu_shares != 0 {
        return Err(unsupported("resources.cpu_shares"));
    }
    if r.oom_score_adj != 0 {
        return Err(unsupported("resources.oom_score_adj"));
    }
    if !r.cpuset_cpus.is_empty() || !r.cpuset_mems.is_empty() {
        return Err(unsupported("resources.cpuset"));
    }
    if !r.hugepage_limits.is_empty() {
        return Err(unsupported("resources.hugepage_limits"));
    }
    if !r.unified.is_empty() {
        return Err(unsupported("resources.unified"));
    }
    let limit = positive("resources.memory_limit_in_bytes", r.memory_limit_in_bytes)?;
    let swap = positive(
        "resources.memory_swap_limit_in_bytes",
        r.memory_swap_limit_in_bytes,
    )?;
    // core は swap を「メモリ＋スワップ」の合計として扱い、メモリ上限が無い・swap がメモリ上限より小さい指定を拒否する。
    if let Some(sw) = swap
        && limit.is_none_or(|l| l > sw)
    {
        return Err(invalid("resources.memory_swap_limit_in_bytes"));
    }
    let period = positive("resources.cpu_period", r.cpu_period)?
        .map(|v| u64::try_from(v).map_err(|_| invalid("resources.cpu_period")))
        .transpose()?;
    // cpu_quota: 0 は未指定、-1 は無制限、正の値は上限。それ以外の負値は core が受けないため拒否する。
    let quota = match r.cpu_quota {
        0 => None,
        q if q == -1 || q > 0 => Some(q),
        _ => return Err(invalid("resources.cpu_quota")),
    };
    let memory = (limit.is_some() || swap.is_some()).then_some(MemoryOut { limit, swap });
    let cpu = (period.is_some() || quota.is_some()).then_some(CpuOut { period, quota });
    Ok((memory.is_some() || cpu.is_some()).then_some(ResourcesOut { memory, cpu }))
}

fn mount_out<'a>(m: &'a Mount, budget: &mut Budget) -> Result<MountOut<'a>, CriError> {
    check_canonical_path("mounts.container_path", &m.container_path)?;
    check_host_source("mounts.host_path", &m.host_path)?;
    budget.spend(
        m.container_path
            .len()
            .saturating_add(m.host_path.len())
            .saturating_add(MOUNT_OVERHEAD),
    )?;
    // PRIVATE は `rprivate`、HOST_TO_CONTAINER は `rslave`（ホストの peer group から受けるだけ。core が受け、元がホスト側で
    // private なら起動を拒否する。#2669・CRI-2・OCI-4）。BIDIRECTIONAL（rshared）は、user namespace の中ではコンテナから
    // ホストへ伝播できないため受けず、未知の値とあわせて `UNIMPLEMENTED`（`docs/design/mount-propagation.md`）。
    let propagation = match MountPropagation::try_from(m.propagation) {
        Ok(MountPropagation::PropagationPrivate) => "rprivate",
        Ok(MountPropagation::PropagationHostToContainer) => "rslave",
        _ => return Err(unsupported("mounts.propagation")),
    };
    if m.selinux_relabel {
        return Err(unsupported("mounts.selinux_relabel"));
    }
    if m.recursive_read_only {
        return Err(unsupported("mounts.recursive_read_only"));
    }
    if !m.uid_mappings.is_empty() || !m.gid_mappings.is_empty() {
        return Err(unsupported("mounts.id_mappings"));
    }
    if m.image.is_some() || !m.image_sub_path.is_empty() {
        return Err(unsupported("mounts.image"));
    }
    if !m.mount_options.is_empty() {
        return Err(unsupported("mounts.mount_options"));
    }
    Ok(MountOut {
        destination: &m.container_path,
        kind: "bind",
        source: &m.host_path,
        options: vec![
            "rbind",
            propagation,
            "nosuid",
            "nodev",
            if m.readonly { "ro" } else { "rw" },
        ],
    })
}

fn paths<'a>(
    field: &'static str,
    v: &'a [String],
    budget: &mut Budget,
) -> Result<Vec<&'a str>, CriError> {
    if v.len() > MAX_PROTECTED_PATHS {
        return Err(invalid(field));
    }
    v.iter()
        .map(|p| {
            check_protected_path(field, p)?;
            budget.spend(p.len().saturating_add(ITEM_OVERHEAD))?;
            Ok(p.as_str())
        })
        .collect()
}

/// `process.args` を Kubernetes の規則（command が Entrypoint を、args が Cmd を置き換える）で決める。
fn build_args(
    c: &ContainerConfig,
    img: &ImageDefaults,
    require_command: bool,
    budget: &mut Budget,
) -> Result<Vec<String>, CriError> {
    let (head, tail): (&[String], &[String]) = if !c.command.is_empty() {
        (&c.command, &c.args)
    } else if !c.args.is_empty() {
        (&img.entrypoint, &c.args)
    } else {
        (&img.entrypoint, &img.cmd)
    };
    let total = head
        .len()
        .checked_add(tail.len())
        .ok_or_else(|| invalid("args"))?;
    if total == 0 && !require_command {
        return Ok(Vec::new());
    }
    if total == 0 {
        return Err(CriError::invalid_argument("no command to run"));
    }
    if total > MAX_ARGS {
        return Err(invalid("args"));
    }
    // 複製の前に、各要素の検証と総量予算の消費を済ませる。
    for a in head.iter().chain(tail) {
        check_string("args", a)?;
        budget.spend(a.len().saturating_add(ITEM_OVERHEAD))?;
    }
    Ok(head.iter().chain(tail).cloned().collect())
}

/// `process.env` を決める。イメージの Env を先に置き、コンテナの `envs` が同じキーを上書きする。
fn build_env(
    c: &ContainerConfig,
    img: &ImageDefaults,
    budget: &mut Budget,
) -> Result<Vec<String>, CriError> {
    if img.env.len() > MAX_ENV || c.envs.len() > MAX_ENV {
        return Err(invalid("envs"));
    }
    // 複製の前に、重複で畳まれる前の総量で予算を消費する（大きい側に倒す）。
    for e in &img.env {
        budget.spend(e.len().saturating_add(ITEM_OVERHEAD))?;
    }
    for kv in &c.envs {
        budget.spend(
            kv.key
                .len()
                .saturating_add(kv.value.len())
                .saturating_add(ITEM_OVERHEAD),
        )?;
    }
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut put = |k: String, v: String| match index.get(&k) {
        Some(&i) => {
            if let Some(slot) = pairs.get_mut(i) {
                slot.1 = v;
            }
        }
        None => {
            index.insert(k.clone(), pairs.len());
            pairs.push((k, v));
        }
    };
    for e in &img.env {
        let (k, v) = e.split_once('=').ok_or_else(|| invalid("image env"))?;
        if k.is_empty() || k.contains('\0') || v.contains('\0') || e.len() > MAX_STRING_BYTES {
            return Err(invalid("image env"));
        }
        put(k.to_owned(), v.to_owned());
    }
    for kv in &c.envs {
        let v = std::str::from_utf8(&kv.value).map_err(|_| invalid("envs"))?;
        if kv.key.is_empty()
            || kv.key.contains('=')
            || kv.key.contains('\0')
            || v.contains('\0')
            || kv.key.len().saturating_add(v.len()).saturating_add(1) > MAX_STRING_BYTES
        {
            return Err(invalid("envs"));
        }
        put(kv.key.clone(), v.to_owned());
    }
    if pairs.len() > MAX_ENV {
        return Err(invalid("envs"));
    }
    Ok(pairs.into_iter().map(|(k, v)| format!("{k}={v}")).collect())
}

fn check_hostname(h: &str) -> Result<Option<&str>, CriError> {
    if h.is_empty() {
        return Ok(None);
    }
    if h.len() > MAX_HOSTNAME_BYTES || h.chars().any(|c| c.is_control() || c == '/') {
        return Err(invalid("hostname"));
    }
    Ok(Some(h))
}

/// CRI の設定から `config.json` を作る。
///
/// 呼び出し元は [`super::SpecBundleProvider`]。`sandbox` は登録済みのサンドボックス設定、`image` はイメージ
/// config 由来の既定値。拒否する項目の一覧はモジュール doc と試験（`tests/bundle_spec.rs`）を参照。
pub fn build_runtime_config(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pod_namespaces(
        sandbox,
        container,
        image,
        &BundleFiles::none(),
        None,
    )
}

/// [`build_runtime_config`] に、pod の network namespace へ join するパスを足した版（#2675・CRI-2・NET-1）。
///
/// `pod_netns` は `NetworkPlugin` 経由で作って結線した netns の絶対パス（`BundleRequest::pod_netns_path`）。
/// `namespace_options.network` が `POD` のときだけ `{"type":"network","path":…}` として出し、他のモードでは
/// 無視する。形の検証（絶対パス・`..` なし・長さ）はここでも行う（多層防御）。
pub fn build_runtime_config_with_pod_netns(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    pod_netns: Option<&str>,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pod_netns(
        sandbox,
        container,
        image,
        &BundleFiles::none(),
        pod_netns,
    )
}

/// [`build_runtime_config`] に、provider が bundle に生成したファイルのパス（[`BundleFiles`]）を渡す版。
///
/// `sandbox.dns_config` が空でなければ `files.resolv_conf` が要る（無ければ `UNIMPLEMENTED`。#2665）。
pub fn build_runtime_config_with_files(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pod_namespaces(sandbox, container, image, files, None)
}

/// [`build_runtime_config_with_files`] と [`build_runtime_config_with_pod_netns`] の両方を受ける版。
pub fn build_runtime_config_with_files_and_pod_netns(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
    pod_netns: Option<&str>,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pods(sandbox, container, image, files, None, pod_netns)
}

/// [`build_runtime_config`] に pod の user・ipc namespace のパスを足した版（CRI-2・CORE-3。#2674）。
///
/// `pod` が `Some` で ipc が `POD` のとき、`linux.namespaces` の ipc と user を join（`path` 付き）にする。
pub fn build_runtime_config_with_pod_namespaces(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    pod: Option<&PodNamespacePaths>,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pod_namespaces(
        sandbox,
        container,
        image,
        &BundleFiles::none(),
        pod,
    )
}

/// ファイル（#2665）と pod の user・ipc namespace のパス（#2674）を渡す版。
pub fn build_runtime_config_with_files_and_pod_namespaces(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
    pod: Option<&PodNamespacePaths>,
) -> Result<RuntimeConfigJson, CriError> {
    build_runtime_config_with_files_and_pods(sandbox, container, image, files, pod, None)
}

/// ファイル・pod の user＋ipc namespace のパス（#2674）・pod の netns のパス（#2675）のすべてを受ける版
/// （`SpecBundleProvider` が使う）。
pub fn build_runtime_config_with_files_and_pods(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
    pod: Option<&PodNamespacePaths>,
    pod_netns: Option<&str>,
) -> Result<RuntimeConfigJson, CriError> {
    if let Some(p) = pod_netns {
        check_host_source("pod netns path", p)?;
    }
    build_inner(
        sandbox,
        container,
        image,
        files,
        pod,
        pod_netns,
        Stage::Build,
    )
}

/// イメージを展開する前に、CRI の設定だけで判定できる拒否・検証を済ませる（不正な要求で bundle を作らない）。
///
/// 実コマンドの有無はイメージ次第のため確認しない（それ以外は [`build_runtime_config`] と同じ判定）。
pub fn validate_config(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
) -> Result<(), CriError> {
    validate_config_with_pod_namespaces(sandbox, container, None)
}

/// [`validate_config`] に pod の namespace のパスを足した版（#2674）。
pub fn validate_config_with_pod_namespaces(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    pod: Option<&PodNamespacePaths>,
) -> Result<(), CriError> {
    validate_config_with_pods(sandbox, container, pod, None)
}

/// [`validate_config_with_pod_namespaces`] に pod の netns パス（`BundleRequest::pod_netns_path`）を足した版。
///
/// 生成時（[`build_runtime_config_with_files_and_pods`]）と同じ条件で `port_mappings` を判定する。
/// 事前検証だけ netns を渡さないと、公開に成功した POD の CreateContainer が `UNIMPLEMENTED` になる（CRI-2・#2676）。
pub fn validate_config_with_pods(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    pod: Option<&PodNamespacePaths>,
    pod_netns: Option<&str>,
) -> Result<(), CriError> {
    build_inner(
        sandbox,
        container,
        &ImageDefaults::default(),
        &BundleFiles::none(),
        pod,
        pod_netns,
        Stage::Validate,
    )
    .map(|_| ())
}

/// `log_path` / `log_directory` の要素（`/` 区切り）が空・`.`・`..` でないことを確かめる。
fn check_log_components(rest: &str) -> bool {
    rest.split('/')
        .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// CRI の `log_directory`（サンドボックス）と `log_path`（コンテナ）を検証し、結合した書き先を返す
/// （CRI-2・SUP-4・#2671）。
///
/// - 両方空: `Ok(None)`（CRI ログなし）
/// - `log_directory` だけ: 形式を検証して `Ok(None)`（そのコンテナは CRI ログなし。containerd と同じ）
/// - `log_path` だけ: `INVALID_ARGUMENT`（相対パスの基点が無い。黙ってログを無効化しない）
/// - 両方: `log_directory` は絶対パス、`log_path` は相対パスで、どちらも `.`・`..`・空要素・制御文字を含まない。
///   `..` を禁じるため、結合結果は構造上 `log_directory` の配下に収まる。
///
/// `validate_config` / `build_runtime_config` と StartContainer の結線が同じ関数を使う（判定の二重管理を避ける）。
/// 純関数でファイルシステムには触れない。
pub fn resolve_log_path(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
) -> Result<Option<ContainerLogPath>, CriError> {
    let dir = sandbox.log_directory.as_str();
    let path = container.log_path.as_str();
    if !dir.is_empty() {
        let ok = dir
            .strip_prefix('/')
            .filter(|_| dir.len() <= MAX_PATH_BYTES)
            .is_some_and(|rest| check_log_components(rest) && !dir.chars().any(char::is_control));
        if !ok {
            return Err(invalid("log_directory"));
        }
    }
    if path.is_empty() {
        return Ok(None);
    }
    if dir.is_empty() {
        return Err(invalid("log_path"));
    }
    if path.starts_with('/') || !check_log_components(path) || path.chars().any(char::is_control) {
        return Err(invalid("log_path"));
    }
    ContainerLogPath::new(format!("{dir}/{path}"))
        .map(Some)
        .map_err(|_| invalid("log_path"))
}

fn build_inner(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
    pod: Option<&PodNamespacePaths>,
    pod_netns: Option<&str>,
    stage: Stage,
) -> Result<RuntimeConfigJson, CriError> {
    // 実行層が受けない・無視すると要求より弱くなる入力を先に拒否する。
    if container.tty || container.stdin || container.stdin_once {
        return Err(unsupported("tty/stdin"));
    }
    // devices・cdi_devices は core の `linux.devices` の適用・device cgroup の許可リスト・gpu の CDI 適用が揃うまで
    // 拒否する。受けて値を捨てると、要求したデバイスが黙って無いコンテナが起動するため（一般デバイスは GPU-9 が
    // 検討中）。docs/design/cri-devices-cdi.md・#2673（CRI-2・GPU-1）。
    if !container.devices.is_empty() {
        return Err(unsupported("devices"));
    }
    if !container.cdi_devices.is_empty() {
        return Err(unsupported("cdi_devices"));
    }
    // stop_signal は config.json に出さない（OCI の config に欄が無い）。停止時に StopRequest で運ぶため、
    // ここでは値域だけを検証する（未知の値は INVALID_ARGUMENT。CRI-2・#2668）。
    crate::stop_signal::linux_stop_signal(container.stop_signal)?;
    // log_path / log_directory は supervisor の CRI ログ書き出しで受け入れる（#2671）。
    // config.json には出さない（書き先は config.json の外の情報。StartContainer が別経路で渡す）。
    resolve_log_path(sandbox, container)?;
    if container.windows.is_some() || sandbox.windows.is_some() {
        return Err(unsupported("windows"));
    }
    // port_mappings は検証し、公開する要素があるときは pod の netns（公開先）が無ければ拒否する。
    // 公開そのものは RunPodSandbox の結線（`publish_port`）が行い、config.json には何も出さない（#2676）。
    let has_publish = !crate::port_mapping::parse_port_mappings(&sandbox.port_mappings)?.is_empty();
    if has_publish && pod_netns.is_none() {
        return Err(unsupported("port_mappings"));
    }
    let hostname = check_hostname(&sandbox.hostname)?;
    let mut budget = Budget::new();

    let sandbox_linux = sandbox.linux.as_ref();
    let sysctls = match sandbox_linux {
        Some(l) => check_sysctls(&l.sysctls, &mut budget)?,
        None => BTreeMap::new(),
    };
    if let Some(l) = sandbox_linux {
        // core は `linux.cgroupsPath` を #2010 の方針で値に関わらず拒否し、コンテナの cgroup を常に委譲スコープ配下の
        // `fc-<id>@<n>` に置く（値を配置に使えない）。受けて値を捨てると kubelet の pod 単位の資源制限が黙って効かない
        // fail-open になるため、判断（docs/design/cri-cgroup-parent.md・#2672）が出るまで拒否する（CRI-2・CORE-4）。
        if !l.cgroup_parent.is_empty() {
            return Err(unsupported("linux.cgroup_parent"));
        }
        if l.overhead.is_some() || l.resources.is_some() {
            return Err(unsupported("linux.resources"));
        }
        if let Some(sc) = &l.security_context {
            if sc.privileged {
                return Err(unsupported("privileged"));
            }
            if sc.selinux_options.is_some() {
                return Err(unsupported("selinux_options"));
            }
            // 適用先が無い（sandbox にプロセスは無い）ため検証だけして出力しない（#2667）。
            validate_supplemental_gids("supplemental_groups", &sc.supplemental_groups)?;
            supplemental_policy("supplemental_groups_policy", sc.supplemental_groups_policy)?;
            check_profile("seccomp", &sc.seccomp)?;
            check_apparmor("apparmor", &sc.apparmor)?;
            // 非推奨の文字列欄も、指定されたまま黙って落とさない（プロファイルの無効化を見逃さない）。
            #[allow(deprecated)]
            if !sc.seccomp_profile_path.is_empty() {
                return Err(unsupported("seccomp_profile_path"));
            }
        }
    }

    let linux = container.linux.as_ref();
    let sc = linux.and_then(|l| l.security_context.as_ref());
    let mut capabilities = None;
    let mut cri_groups = Vec::new();
    let mut policy = SupplementalGroupsPolicy::Merge;
    if let Some(sc) = sc {
        cri_groups = supplemental_gids("supplemental_groups", &sc.supplemental_groups)?;
        policy = supplemental_policy("supplemental_groups_policy", sc.supplemental_groups_policy)?;
        if sc.privileged {
            return Err(unsupported("privileged"));
        }
        // add / ambient は受けない（オーナー判断まで UNIMPLEMENTED）。drop だけ受ける（#2666）。
        if let Some(c) = &sc.capabilities {
            if !c.add_capabilities.is_empty() || !c.add_ambient_capabilities.is_empty() {
                return Err(unsupported("capabilities"));
            }
            capabilities = drop_capabilities(&c.drop_capabilities)?;
        }
        if sc.readonly_rootfs {
            return Err(unsupported("readonly_rootfs"));
        }
        if sc.selinux_options.is_some() {
            return Err(unsupported("selinux_options"));
        }
        check_profile("seccomp", &sc.seccomp)?;
        check_apparmor("apparmor", &sc.apparmor)?;
        // 非推奨の文字列欄も、指定されたまま黙って落とさない。
        #[allow(deprecated)]
        let legacy_profile = !sc.apparmor_profile.is_empty() || !sc.seccomp_profile_path.is_empty();
        if legacy_profile {
            return Err(unsupported("security profile path"));
        }
    }

    let args = build_args(container, image, stage == Stage::Build, &mut budget)?;
    let env = build_env(container, image, &mut budget)?;

    // 複製前に借用のまま長さと形を検証する（巨大な値を拒否する場合でも追加確保しない）。
    let cwd_ref: &str = if !container.working_dir.is_empty() {
        &container.working_dir
    } else {
        image.working_dir.as_deref().unwrap_or("/")
    };
    check_abs_path("working_dir", cwd_ref)?;
    let cwd = cwd_ref.to_owned();
    budget.spend(cwd.len().saturating_add(ITEM_OVERHEAD))?;
    if let Some(h) = hostname {
        budget.spend(h.len().saturating_add(ITEM_OVERHEAD))?;
    }

    let run_as_user = nonneg_u32("run_as_user", &sc.and_then(|s| s.run_as_user))?;
    let username = check_username(sc.map_or("", |s| s.run_as_username.as_str()))?;
    if run_as_user.is_some() && username.is_some() {
        return Err(invalid("run_as_username"));
    }
    let resolved = match (username, stage) {
        (Some(_), Stage::Build) => Some(
            image
                .resolved_run_as_username
                .ok_or_else(|| unsupported("run_as_username"))?,
        ),
        _ => None,
    };
    let explicit_user = run_as_user.is_some() || username.is_some();
    if !explicit_user && image.user_unresolved {
        return Err(unsupported("image user"));
    }
    let run_as_group = nonneg_u32("run_as_group", &sc.and_then(|s| s.run_as_group))?;
    if run_as_group.is_some() && !explicit_user {
        return Err(invalid("run_as_group"));
    }
    let uid = run_as_user
        .or(resolved.map(|r| r.0))
        .or(image.user.map(|u| u.0))
        .unwrap_or(0);
    let gid = run_as_group
        .or(resolved.map(|r| r.1))
        .or_else(|| (!explicit_user).then(|| image.user.map(|u| u.1)).flatten())
        .unwrap_or(0);

    // 補助グループ: Merge はイメージ由来（uid 0 には付けない）→ CRI の順、Strict は CRI だけ。最初に出たものを残す。
    let additional_gids = merge_additional_gids(
        policy,
        if uid == 0 {
            &[]
        } else {
            &image.supplementary_gids
        },
        &cri_groups,
    )?;
    budget.spend(
        additional_gids
            .len()
            .saturating_mul(ADDITIONAL_GID_JSON_BYTES),
    )?;

    if container.mounts.len() > MAX_MOUNTS {
        return Err(invalid("mounts"));
    }
    let mut mounts = container
        .mounts
        .iter()
        .map(|m| mount_out(m, &mut budget))
        .collect::<Result<Vec<_>, _>>()?;
    // dns_config: 内容は両段で検証する。bind の source は Build 段で provider が生成したパスを使い、
    // 無ければ拒否する（要求を黙って落とさない）。Validate 段は仮の source で宛先の重なりだけを見る。
    if let Some(dns) = &sandbox.dns_config
        && resolv_conf::render(dns)?.is_some()
    {
        let source = match (stage, files.resolv_conf) {
            (Stage::Validate, _) => RESOLV_CONF_PLACEHOLDER_SOURCE,
            (Stage::Build, Some(p)) => {
                check_host_source("dns_config", p)?;
                p
            }
            (Stage::Build, None) => return Err(unsupported("dns_config")),
        };
        // 生成する bind を足した総件数でも上限（core の `CONFIG_MAX_MOUNTS`）を守る。
        if mounts.len() >= MAX_MOUNTS {
            return Err(invalid("mounts"));
        }
        budget.spend(
            source
                .len()
                .saturating_add(RESOLV_CONF_DESTINATION.len())
                .saturating_add(MOUNT_OVERHEAD),
        )?;
        mounts.push(MountOut {
            destination: RESOLV_CONF_DESTINATION,
            kind: "bind",
            source,
            options: vec!["bind", "private", "nosuid", "nodev", "noexec", "ro"],
        });
    }

    // 名前空間: コンテナ側の指定を優先し、無ければ sandbox 側。
    let ns_opts = sc.and_then(|s| s.namespace_options.as_ref()).or_else(|| {
        sandbox_linux
            .and_then(|l| l.security_context.as_ref())
            .and_then(|s| s.namespace_options.as_ref())
    });
    // 公開（DNAT）の宛先は pod の netns。コンテナの network が POD 以外だと宛先とコンテナの netns が食い違うため拒否する。
    if has_publish {
        let mode = resolve_mode(
            "namespace_options.network",
            ns_opts.map_or(0, |o| o.network),
        )?;
        if !matches!(mode, NamespaceMode::Pod) {
            return Err(unsupported("port_mappings"));
        }
    }
    let namespaces = namespaces(ns_opts, pod, pod_netns)?;

    let resources = match linux.and_then(|l| l.resources.as_ref()) {
        Some(r) => resources(r)?,
        None => None,
    };
    let (masked, readonly) = match sc {
        Some(s) => (
            paths("masked_paths", &s.masked_paths, &mut budget)?,
            paths("readonly_paths", &s.readonly_paths, &mut budget)?,
        ),
        None => (Vec::new(), Vec::new()),
    };

    check_mount_set(&mounts, &masked, &readonly)?;

    let out = SpecOut {
        oci_version: OCI_VERSION,
        root: RootOut { path: "rootfs" },
        hostname,
        process: ProcessOut {
            args,
            env,
            cwd,
            user: UserOut {
                uid,
                gid,
                additional_gids: additional_gids.clone(),
            },
            capabilities,
        },
        mounts,
        linux: LinuxOut {
            namespaces,
            resources,
            masked_paths: masked,
            readonly_paths: readonly,
            sysctl: sysctls,
        },
    };
    // 上限付き writer へ直列化し、JSON 全体の確保を上限で止める。
    let mut w = LimitedWriter { buf: Vec::new() };
    serde_json::to_writer(&mut w, &out).map_err(|e| {
        if e.is_io() {
            invalid("config size")
        } else {
            CriError::internal("failed to encode config")
        }
    })?;
    Ok(RuntimeConfigJson {
        bytes: w.buf,
        user: AppliedUser::new(uid, gid, additional_gids),
    })
}

#[cfg(test)]
mod tests {
    //! `PodNamespacePaths` の形式検査（CRI-2・CORE-3・SEC-5。#2776）。

    use super::*;
    use crate::error::CriErrorCode;

    #[test]
    fn accepts_canonical_pair() {
        for pid in ["4242", "1", "2147483647"] {
            let (u, i) = (
                format!("/proc/{pid}/ns/user"),
                format!("/proc/{pid}/ns/ipc"),
            );
            let p = PodNamespacePaths::from_paths(&u, &i).expect("canonical");
            assert_eq!((p.user(), p.ipc()), (u.as_str(), i.as_str()));
        }
    }

    #[test]
    fn rejects_malformed_paths_with_internal() {
        let cases: &[(&str, &str)] = &[
            ("/proc/self/ns/user", "/proc/self/ns/ipc"),
            ("/proc/thread-self/ns/user", "/proc/thread-self/ns/ipc"),
            ("/proc/1/ns/../ns/user", "/proc/1/ns/ipc"),
            ("/proc/1/ns/user", "/proc/2/ns/ipc"),
            ("/run/netns/x", "/run/netns/x"),
            ("/proc/1/ns/ipc", "/proc/1/ns/user"),
            ("/proc/0/ns/user", "/proc/0/ns/ipc"),
            ("/proc/042/ns/user", "/proc/042/ns/ipc"),
            ("/proc/+1/ns/user", "/proc/+1/ns/ipc"),
            ("/proc/2147483648/ns/user", "/proc/2147483648/ns/ipc"),
            ("/proc/99999999999/ns/user", "/proc/99999999999/ns/ipc"),
            ("/proc/1/ns/user/", "/proc/1/ns/ipc"),
            ("/proc//1/ns/user", "/proc//1/ns/ipc"),
            ("/proc/1//ns/user", "/proc/1//ns/ipc"),
            ("/proc/1/ns/user\0", "/proc/1/ns/ipc"),
            ("", ""),
            ("/proc/1/ns/mnt", "/proc/1/ns/ipc"),
            ("proc/1/ns/user", "proc/1/ns/ipc"),
        ];
        for (u, i) in cases {
            let e = PodNamespacePaths::from_paths(u, i).expect_err(u);
            assert_eq!(e.code(), CriErrorCode::Internal, "{u} {i}");
        }
    }

    #[test]
    fn for_holder_pid_builds_proc_paths_and_bounds_pid() {
        let p = PodNamespacePaths::for_holder_pid(NonZeroU32::new(4242).expect("nz")).expect("ok");
        assert_eq!(p.user(), "/proc/4242/ns/user");
        assert_eq!(p.ipc(), "/proc/4242/ns/ipc");
        let max = i32::MAX as u32;
        PodNamespacePaths::for_holder_pid(NonZeroU32::new(max).expect("nz")).expect("max");
        for over in [max + 1, u32::MAX] {
            let e = PodNamespacePaths::for_holder_pid(NonZeroU32::new(over).expect("nz"))
                .expect_err("over");
            assert_eq!(e.code(), CriErrorCode::Internal);
        }
    }
}
