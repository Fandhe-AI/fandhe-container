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
//! - namespace の共有（POD の pid / ipc を pod 内で共有する）は未実装で、`POD` もコンテナごとの新しい
//!   namespace にする（共有の欠落であり、要求より分離が弱くなる方向ではない）。
//! - network namespace: `POD` / `CONTAINER` は `{"type":"network"}` を出す。core の start は network namespace を
//!   まだ受けず `Unimplemented` で拒否する（NetworkPlugin の結線〔NET 系。`docs/design/cri-config-acceptance.md` の順 13〕まで）。`NODE`（host）は
//!   network namespace を出さない（ホストの netns で動く。利用者が明示した場合だけ）。crictl 疎通確認
//!   （#442）の pod.json は当面 `namespace_options.network = NODE` を要する。
//! - user namespace: `userns_options.mode` が `NODE` でも新しい user namespace にする（分離を強める方向。
//!   uid の写像は core の launcher が権限モデルから導く。SEC-5）。`uids` / `gids` の指定は未実装（#2240）。
//! - イメージ config（Entrypoint・Cmd・Env・WorkingDir・User）の解析は [`super::ImageRootfsSource`]（#2433）が行い、
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
//! - `sandbox.linux.sysctls`（pod 単位）は、IPC 系（`kernel.shmmax` 等・`fs.mqueue.*`）だけ受け入れ、各コンテナの
//!   `config.json` の `linux.sysctl` へ写す（core が pivot 前に `rootfs/proc/sys` へ適用する。#2670・CRI-2・CORE-3）。
//!   pod の名前空間の共有は未実装のため、pod 単位の値を各コンテナ自身の IPC namespace へ適用する近似になる
//!   （containerd も pod の sysctls を各コンテナへ写す）。分類は core の `sysctl::SysctlKey` を使い、規則を二重に持たない:
//!   `net.*`（pod の netns の結線 #2675 が前提）と UTS 系（`kernel.hostname`・`kernel.domainname`）は `UNIMPLEMENTED`、
//!   文法違反・名前空間を持たないキー（`kernel.panic`・`vm.*` 等）・不正な値は `INVALID_ARGUMENT`。
//! - 本モジュールが `UNIMPLEMENTED` で拒否する CRI 項目（log_path・port_mappings・cgroup_parent・
//!   devices・capabilities の add / ambient・supplemental_groups・propagation 等）の受け入れ順序と担当は
//!   `docs/design/cri-config-acceptance.md`（#2606）にまとめている。
//! - `linux.cgroup_parent` の受け入れ方針（オーナー承認待ち。判断が出るまで `UNIMPLEMENTED`）は
//!   `docs/design/cri-cgroup-parent.md`（#2672・CRI-2・CORE-4）にまとめている。
//! - `devices`・`cdi_devices` の受け入れ方針（オーナー判断待ち。判断が出るまで `UNIMPLEMENTED`）は
//!   `docs/design/cri-devices-cdi.md`（#2673・CRI-2・GPU-1）にまとめている。

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use fandhe_container_core::capabilities::{Capability, CapabilitySet, OCI_DEFAULT_CAPABILITIES};
use fandhe_container_core::path_masks::normalize_container_path;
use fandhe_container_core::sysctl::{
    SYSCTL_MAX_ENTRIES, SysctlError, SysctlKey, SysctlNamespace, SysctlValue,
};

use super::resolv_conf;
use crate::error::CriError;
use crate::runtime::v1::{
    ContainerConfig, Int64Value, LinuxContainerResources, Mount, MountPropagation, NamespaceMode,
    NamespaceOption, PodSandboxConfig, SecurityProfile, security_profile::ProfileType,
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
pub struct RuntimeConfigJson(Vec<u8>);

impl RuntimeConfigJson {
    /// 直列化済みのバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
    namespaces: Vec<NamespaceOut>,
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
struct NamespaceOut {
    #[serde(rename = "type")]
    kind: &'static str,
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
fn check_host_source(field: &'static str, p: &str) -> Result<(), CriError> {
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
fn namespaces(opts: Option<&NamespaceOption>) -> Result<Vec<NamespaceOut>, CriError> {
    let default = NamespaceOption::default();
    let o = opts.unwrap_or(&default);
    let mut out = Vec::with_capacity(6);
    // pid・ipc: POD / CONTAINER はコンテナごとの新しい namespace（共有は未実装。REPAIR-3）。
    // NODE は必須 namespace を外す（SEC-1）ため拒否、TARGET は join 未対応。
    for (kind, field, v) in [
        ("pid", "namespace_options.pid", o.pid),
        ("ipc", "namespace_options.ipc", o.ipc),
    ] {
        match resolve_mode(field, v)? {
            NamespaceMode::Pod | NamespaceMode::Container => out.push(NamespaceOut { kind }),
            NamespaceMode::Node | NamespaceMode::Target => return Err(unsupported(field)),
        }
    }
    out.push(NamespaceOut { kind: "mount" });
    out.push(NamespaceOut { kind: "uts" });
    // user: 常に新しい namespace（SEC-5）。写像の指定は未実装（#2240）。
    out.push(NamespaceOut { kind: "user" });
    if let Some(u) = &o.userns_options {
        match resolve_mode("namespace_options.userns_options.mode", u.mode)? {
            NamespaceMode::Pod | NamespaceMode::Container | NamespaceMode::Node => {}
            NamespaceMode::Target => {
                return Err(unsupported("namespace_options.userns_options.mode"));
            }
        }
        if !u.uids.is_empty() || !u.gids.is_empty() {
            return Err(unsupported("namespace_options.userns_options mappings"));
        }
    }
    match resolve_mode("namespace_options.network", o.network)? {
        NamespaceMode::Pod | NamespaceMode::Container => out.push(NamespaceOut { kind: "network" }),
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
    if m.propagation != MountPropagation::PropagationPrivate as i32 {
        return Err(unsupported("mounts.propagation"));
    }
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
            "rprivate",
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
    build_runtime_config_with_files(sandbox, container, image, &BundleFiles::none())
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
    build_inner(sandbox, container, image, files, Stage::Build)
}

/// イメージを展開する前に、CRI の設定だけで判定できる拒否・検証を済ませる（不正な要求で bundle を作らない）。
///
/// 実コマンドの有無はイメージ次第のため確認しない（それ以外は [`build_runtime_config`] と同じ判定）。
pub fn validate_config(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
) -> Result<(), CriError> {
    build_inner(
        sandbox,
        container,
        &ImageDefaults::default(),
        &BundleFiles::none(),
        Stage::Validate,
    )
    .map(|_| ())
}

fn build_inner(
    sandbox: &PodSandboxConfig,
    container: &ContainerConfig,
    image: &ImageDefaults,
    files: &BundleFiles<'_>,
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
    if !container.log_path.is_empty() || !sandbox.log_directory.is_empty() {
        return Err(unsupported("log_path"));
    }
    if container.windows.is_some() || sandbox.windows.is_some() {
        return Err(unsupported("windows"));
    }
    if !sandbox.port_mappings.is_empty() {
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
            if !sc.supplemental_groups.is_empty() {
                return Err(unsupported("supplemental_groups"));
            }
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
    if let Some(sc) = sc {
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
        if !sc.supplemental_groups.is_empty() {
            return Err(unsupported("supplemental_groups"));
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
    let namespaces = namespaces(ns_opts)?;

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
            user: UserOut { uid, gid },
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
    Ok(RuntimeConfigJson(w.buf))
}
