//! `PodSandboxConfig` のサイズ・件数の検証と、レジストリ保持量の見積もり（TASK-57.1・#429・ERR-3）。
//!
//! 親モジュールの `RunPodSandbox` が、`config` をレジストリへ保持する前に呼ぶ。`config` は CRI クライアント
//! （kubelet・crictl）から届く外部入力で、gRPC の受信上限（リスナー側。TASK-108）は公開トレイトを直接呼ぶ
//! 経路には効かず、累積の保持量も制限しない。そのためサービス自身が次の 3 段で有限の上限を課す。
//!
//! 1. 1 件の総サイズ: protobuf の符号化長が [`MAX_CONFIG_ENCODED_BYTES`] 以下（文字列・map の値を含む
//!    すべての可変長フィールドがこの中に収まる）
//! 2. 可変長要素: metadata の識別子が [`MAX_METADATA_FIELD_BYTES`] 以下、repeated / map フィールドごとの
//!    件数が [`MAX_CONFIG_COLLECTION_ENTRIES`] 以下
//! 3. 累積: 保持量の見積もり（符号化長＋要素数×[`RETAINED_BYTES_PER_ENTRY`]＋[`RETAINED_BYTES_PER_RECORD`]）の
//!    合計を、親モジュールが [`MAX_RETAINED_CONFIG_BYTES`] 以下に保つ
//!
//! 1・2 の超過は値域外として `INVALID_ARGUMENT`（ERR-3）で拒否する。検証はアロケーションなしで行い、
//! 通過した `config` だけを [`BoundedConfig`] が保持用に作り直す（呼び出し元が渡した過大な容量
//! 〔capacity〕を引き継がないため）。
//!
//! **見積もりの位置づけ（REPAIR-3）**: 3 の値はヒープ使用量の保守的な見積もりで、アロケータの実測値では
//! ない。TASK-59 で `StateStore` へ置換する際は、保存形式のサイズで数え直す。

use crate::error::CriError;
use prost::Message;

use crate::runtime::v1::{
    DnsConfig, LinuxContainerResources, LinuxPodSandboxConfig, LinuxSandboxSecurityContext,
    NamespaceOption, PodSandboxConfig, PodSandboxMetadata, UserNamespace,
};

/// 1 件の `PodSandboxConfig` の符号化長（protobuf）の上限: 512 KiB。
///
/// 根拠: Kubernetes は 1 オブジェクトの annotations の合計（キー＋値）を 256 KiB に制限しており
/// （apimachinery の `TotalAnnotationSizeLimitB`）、kubelet は Pod の annotations・labels を
/// サンドボックスの `config` へ写す。正当な最大級の annotations（256 KiB）に、labels・metadata・DNS・
/// ポート・Linux 設定の分として同量の余裕を足した。gRPC の既定の受信上限（tonic の 4 MiB）より小さく、
/// リスナー経由の要求をこの値より大きく絞る必要はない。
pub const MAX_CONFIG_ENCODED_BYTES: usize = 512 * 1024;

/// `metadata` の `name`・`uid`・`namespace` それぞれのバイト長の上限: 253。
///
/// 根拠: Kubernetes の Pod 名は DNS サブドメイン名（最大 253 文字。apimachinery の
/// `DNS1123SubdomainMaxLength`）で、namespace（DNS ラベル・63 文字）と UID（36 文字）はそれより短い。
/// 識別子は後続の RPC（Status/List〔#431〕）が応答・絞り込みに使うため、総サイズとは別に上限を置く。
pub const MAX_METADATA_FIELD_BYTES: usize = 253;

/// repeated / map フィールド 1 つあたりの件数の上限: 1024。
///
/// 対象は `labels`・`annotations`・`port_mappings`・`dns_config` の 3 リスト・`linux.sysctls`・
/// `linux.{overhead,resources}` の `hugepage_limits` / `unified`・`supplemental_groups`・
/// user namespace の `uids` / `gids` の計 14 フィールド。
///
/// 根拠: 符号化長だけでは件数を縛れない（空に近い要素は 2 バイト程度で符号化されるが、メモリ上では
/// 1 件あたり数十〜百数十バイトを占める）。実運用の Pod はどのフィールドも数十件以下で、1024 は
/// その 10 倍以上の余裕になる。
pub const MAX_CONFIG_COLLECTION_ENTRIES: usize = 1024;

/// レジストリが保持する全 `config` の保持量の見積もりの合計の上限: 64 MiB。
///
/// 根拠: 典型的な Pod（符号化長 数 KiB・要素 数十件）の見積もりは 1 件 16 KiB 前後で、件数の上限
/// （`MAX_SANDBOXES` = 1024）まで登録しても 16 MiB 程度に収まる。その 4 倍を上限とし、大きな
/// annotations を持つ Pod が混ざっても件数の上限より先に尽きないようにした。1 件の見積もりの最大は
/// `MAX_CONFIG_ENCODED_BYTES + 14 × MAX_CONFIG_COLLECTION_ENTRIES × RETAINED_BYTES_PER_ENTRY +
/// RETAINED_BYTES_PER_RECORD`（約 4 MiB）で、件数の上限だけでは約 4 GiB まで膨らむため、合計にも上限を置く。
pub const MAX_RETAINED_CONFIG_BYTES: usize = 64 * 1024 * 1024;

/// repeated / map の要素 1 件あたりに見込むメモリ上の上乗せ（符号化長に含まれない分）: 256 バイト。
///
/// 最も大きい要素は map の 1 エントリ（`(String, String)` = 48 バイト）。ハッシュ表は負荷率と倍々の
/// 伸長でエントリ数の 2.3 倍程度までスロットを持ち（約 112 バイト）、キー・値のヒープ領域にアロケータの
/// 管理分（約 32 バイト）が乗る。1 件だけの map は最小 4 スロット（約 212 バイト）を占めるため、
/// その場合も収まる 256 とした。`Vec` の要素（最大は `PortMapping` の 40 バイト。最小容量 4）も収まる。
pub const RETAINED_BYTES_PER_ENTRY: usize = 256;

/// サンドボックス 1 件あたりに見込む固定の上乗せ（`config` 本体の構造体・ID・レジストリのスロット）: 4096 バイト。
///
/// レジストリのハッシュ表がスロットを 2.3 倍程度まで持つことを見込み、`(ID, 記録)` の 3 倍と ID の
/// 文字列（64 バイト）が収まる値にした。構造体のサイズが変わって収まらなくなった場合は親モジュールの
/// ユニットテストが検出する。
pub const RETAINED_BYTES_PER_RECORD: usize = 4096;

/// サイズ・件数の検証を通過し、保持用に作り直した `PodSandboxConfig`。
///
/// [`BoundedConfig::new`] だけが作れるため、未検証の `config` がレジストリへ入る経路はない。
#[derive(Debug)]
pub(super) struct BoundedConfig {
    config: PodSandboxConfig,
    retained_bytes: usize,
}

impl BoundedConfig {
    /// `config` を検証し、保持用に作り直す。上限超過は `INVALID_ARGUMENT`（ERR-3）。
    ///
    /// 作り直し（符号化して復号）は内容を変えない。呼び出し元が確保した余分な容量（長さ 0 で容量だけ
    /// 大きい `String`・`Vec`・`HashMap`）を捨て、保持量を見積もりの前提に揃えるために行う。
    /// 符号化先の確保量は検証済みの符号化長（[`MAX_CONFIG_ENCODED_BYTES`] 以下）に限られる。
    pub(super) fn new(config: PodSandboxConfig) -> Result<Self, CriError> {
        let retained_bytes = retained_bytes(&config)?;
        let encoded = config.encode_to_vec();
        drop(config);
        let config = PodSandboxConfig::decode(encoded.as_slice())
            .map_err(|_| CriError::internal("failed to rebuild sandbox config"))?;
        Ok(Self {
            config,
            retained_bytes,
        })
    }

    /// 保持量の見積もり（レジストリの累積上限の判定に使う）。
    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// 保持用に作り直した `config` の metadata（重複判定キーの組み立て用。ERR-3・TASK-57）。
    pub(super) fn metadata(&self) -> Option<&PodSandboxMetadata> {
        self.config.metadata.as_ref()
    }

    /// 検証済みの `port_mappings`（件数は上限内。値の検証は `crate::port_mapping`。#2676）。
    pub(super) fn port_mappings(&self) -> &[crate::runtime::v1::PortMapping] {
        &self.config.port_mappings
    }

    /// 検証済みの `config` を取り出す。
    pub(super) fn into_config(self) -> PodSandboxConfig {
        self.config
    }
}

/// `config` を検証し、保持量の見積もりを返す（アロケーションなし。演算は checked）。
fn retained_bytes(config: &PodSandboxConfig) -> Result<usize, CriError> {
    let encoded_len = config.encoded_len();
    if encoded_len > MAX_CONFIG_ENCODED_BYTES {
        return Err(CriError::invalid_argument(format!(
            "config is too large: {encoded_len} bytes exceeds the limit of {MAX_CONFIG_ENCODED_BYTES} bytes"
        )));
    }
    if let Some(metadata) = config.metadata.as_ref() {
        check_metadata(metadata)?;
    }
    let mut entries: usize = 0;
    for_each_collection(config, &mut |field, len| {
        if len > MAX_CONFIG_COLLECTION_ENTRIES {
            return Err(CriError::invalid_argument(format!(
                "config.{field} has too many entries: {len} exceeds the limit of {MAX_CONFIG_COLLECTION_ENTRIES}"
            )));
        }
        entries = entries
            .checked_add(len)
            .ok_or_else(|| CriError::invalid_argument("config has too many entries"))?;
        Ok(())
    })?;
    entries
        .checked_mul(RETAINED_BYTES_PER_ENTRY)
        .and_then(|overhead| overhead.checked_add(encoded_len))
        .and_then(|bytes| bytes.checked_add(RETAINED_BYTES_PER_RECORD))
        .ok_or_else(|| CriError::invalid_argument("config is too large"))
}

/// `metadata` の識別子の長さを検証する。
fn check_metadata(metadata: &PodSandboxMetadata) -> Result<(), CriError> {
    let PodSandboxMetadata {
        name,
        uid,
        namespace,
        attempt: _,
    } = metadata;
    for (field, value) in [("name", name), ("uid", uid), ("namespace", namespace)] {
        let len = value.len();
        if len > MAX_METADATA_FIELD_BYTES {
            return Err(CriError::invalid_argument(format!(
                "config.metadata.{field} is too long: {len} bytes exceeds the limit of {MAX_METADATA_FIELD_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

/// `config` から辿れる repeated / map フィールドを、(フィールド名, 件数) で順に `visit` へ渡す。
///
/// 各メッセージを `..` なしで分解している。cri-api の更新でフィールドが増えるとここがコンパイルエラーに
/// なり、新しい可変長フィールドを件数検証に入れ忘れることを防ぐ（REPAIR-12。`tests/generated_build_check.rs`
/// が RPC 一覧を固定しているのと同じ狙い）。ここで中身を読まない型（要素の `PortMapping`・`HugepageLimit`・
/// `IDMapping` と、末端の `SELinuxOption`・`SecurityProfile`・`Int64Value`・Windows 側の設定）が
/// repeated / map を持たないことは本ファイルのユニットテストが固定する。
fn for_each_collection(
    config: &PodSandboxConfig,
    visit: &mut dyn FnMut(&'static str, usize) -> Result<(), CriError>,
) -> Result<(), CriError> {
    let PodSandboxConfig {
        metadata: _,
        hostname: _,
        log_directory: _,
        dns_config,
        port_mappings,
        labels,
        annotations,
        linux,
        // Windows 側（`WindowsPodSandboxConfig` 以下）に repeated / map フィールドはない（ユニットテストが固定する）。
        windows: _,
    } = config;
    if let Some(DnsConfig {
        servers,
        searches,
        options,
    }) = dns_config
    {
        visit("dns_config.servers", servers.len())?;
        visit("dns_config.searches", searches.len())?;
        visit("dns_config.options", options.len())?;
    }
    visit("port_mappings", port_mappings.len())?;
    visit("labels", labels.len())?;
    visit("annotations", annotations.len())?;
    if let Some(LinuxPodSandboxConfig {
        cgroup_parent: _,
        security_context,
        sysctls,
        overhead,
        resources,
    }) = linux
    {
        visit("linux.sysctls", sysctls.len())?;
        if let Some(security_context) = security_context {
            visit_linux_security_context(security_context, visit)?;
        }
        if let Some(overhead) = overhead {
            visit_linux_resources(
                overhead,
                "linux.overhead.hugepage_limits",
                "linux.overhead.unified",
                visit,
            )?;
        }
        if let Some(resources) = resources {
            visit_linux_resources(
                resources,
                "linux.resources.hugepage_limits",
                "linux.resources.unified",
                visit,
            )?;
        }
    }
    Ok(())
}

/// `LinuxSandboxSecurityContext` の repeated フィールドを `visit` へ渡す。
// 非推奨の `seccomp_profile_path` も分解の対象に含める（フィールドの増減を検出するため。値は読まない）。
#[allow(deprecated)]
fn visit_linux_security_context(
    security_context: &LinuxSandboxSecurityContext,
    visit: &mut dyn FnMut(&'static str, usize) -> Result<(), CriError>,
) -> Result<(), CriError> {
    let LinuxSandboxSecurityContext {
        namespace_options,
        selinux_options: _,
        run_as_user: _,
        run_as_group: _,
        readonly_rootfs: _,
        supplemental_groups,
        supplemental_groups_policy: _,
        privileged: _,
        seccomp: _,
        apparmor: _,
        seccomp_profile_path: _,
    } = security_context;
    visit(
        "linux.security_context.supplemental_groups",
        supplemental_groups.len(),
    )?;
    if let Some(NamespaceOption {
        network: _,
        pid: _,
        ipc: _,
        target_id: _,
        userns_options,
    }) = namespace_options
        && let Some(UserNamespace {
            mode: _,
            uids,
            gids,
        }) = userns_options
    {
        visit(
            "linux.security_context.namespace_options.userns_options.uids",
            uids.len(),
        )?;
        visit(
            "linux.security_context.namespace_options.userns_options.gids",
            gids.len(),
        )?;
    }
    Ok(())
}

/// `LinuxContainerResources` の repeated / map フィールドを `visit` へ渡す。
fn visit_linux_resources(
    resources: &LinuxContainerResources,
    hugepage_limits_field: &'static str,
    unified_field: &'static str,
    visit: &mut dyn FnMut(&'static str, usize) -> Result<(), CriError>,
) -> Result<(), CriError> {
    let LinuxContainerResources {
        cpu_period: _,
        cpu_quota: _,
        cpu_shares: _,
        memory_limit_in_bytes: _,
        oom_score_adj: _,
        cpuset_cpus: _,
        cpuset_mems: _,
        hugepage_limits,
        unified,
        memory_swap_limit_in_bytes: _,
    } = resources;
    visit(hugepage_limits_field, hugepage_limits.len())?;
    visit(unified_field, unified.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::v1::{
        HugepageLimit, IdMapping, Int64Value, PortMapping, SeLinuxOption, SecurityProfile,
        WindowsNamespaceOption, WindowsPodSandboxConfig, WindowsSandboxSecurityContext,
    };
    use tonic::Code;

    fn base_config() -> PodSandboxConfig {
        PodSandboxConfig {
            metadata: Some(PodSandboxMetadata {
                name: "p".into(),
                uid: "uid-1".into(),
                namespace: "ns".into(),
                attempt: 0,
            }),
            ..Default::default()
        }
    }

    /// 符号化長がちょうど `target` になるよう `log_directory` を伸ばした config。
    fn config_with_encoded_len(target: usize) -> PodSandboxConfig {
        let mut config = base_config();
        // 長さ 2^14 以上 2^21 未満の文字列フィールドは「タグ 1 バイト＋長さ 3 バイト＋本体」で符号化される。
        let overhead = config.encoded_len() + 4;
        config.log_directory = "d".repeat(target - overhead);
        assert_eq!(config.encoded_len(), target);
        config
    }

    fn rejected(config: PodSandboxConfig) -> (Code, String) {
        let err = BoundedConfig::new(config).expect_err("must be rejected");
        (err.code().grpc_code(), err.message().to_owned())
    }

    /// ERR-3・TASK-57.1: 符号化長は上限ちょうどまで受け付け、1 バイト超えると INVALID_ARGUMENT。
    #[test]
    fn task_57_1_encoded_size_boundary() {
        let at_limit = config_with_encoded_len(MAX_CONFIG_ENCODED_BYTES);
        let bounded = BoundedConfig::new(at_limit.clone()).expect("at the limit");
        assert_eq!(
            bounded.retained_bytes(),
            MAX_CONFIG_ENCODED_BYTES + RETAINED_BYTES_PER_RECORD
        );
        assert_eq!(bounded.into_config(), at_limit);

        let over = config_with_encoded_len(MAX_CONFIG_ENCODED_BYTES + 1);
        assert_eq!(
            rejected(over),
            (
                Code::InvalidArgument,
                "config is too large: 524289 bytes exceeds the limit of 524288 bytes".to_owned()
            )
        );
    }

    /// ERR-3・TASK-57.1: metadata の識別子は 253 バイトまで受け付け、254 バイトで INVALID_ARGUMENT。
    #[test]
    fn task_57_1_metadata_field_boundary() {
        let fill = |field: &str, len: usize| {
            let mut config = base_config();
            let metadata = config.metadata.as_mut().expect("metadata");
            let value = "a".repeat(len);
            match field {
                "name" => metadata.name = value,
                "uid" => metadata.uid = value,
                _ => metadata.namespace = value,
            }
            config
        };
        for field in ["name", "uid", "namespace"] {
            assert!(BoundedConfig::new(fill(field, MAX_METADATA_FIELD_BYTES)).is_ok());
            assert_eq!(
                rejected(fill(field, MAX_METADATA_FIELD_BYTES + 1)),
                (
                    Code::InvalidArgument,
                    format!(
                        "config.metadata.{field} is too long: 254 bytes exceeds the limit of 253 bytes"
                    )
                )
            );
        }
    }

    /// 14 個の repeated / map フィールドそれぞれに `count` 件を入れた config を、フィールド名つきで返す。
    fn configs_with_collection(count: usize) -> Vec<(&'static str, PodSandboxConfig)> {
        let strings = || (0..count).map(|i| i.to_string()).collect::<Vec<_>>();
        let map = || {
            (0..count)
                .map(|i| (i.to_string(), String::new()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let linux = |f: &dyn Fn(&mut LinuxPodSandboxConfig)| {
            let mut config = base_config();
            let mut linux = LinuxPodSandboxConfig::default();
            f(&mut linux);
            config.linux = Some(linux);
            config
        };
        let userns = |f: &dyn Fn(&mut UserNamespace)| {
            linux(&|l| {
                let mut userns = UserNamespace::default();
                f(&mut userns);
                l.security_context = Some(LinuxSandboxSecurityContext {
                    namespace_options: Some(NamespaceOption {
                        userns_options: Some(userns),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
            })
        };
        let dns = |f: &dyn Fn(&mut DnsConfig)| {
            let mut config = base_config();
            let mut dns = DnsConfig::default();
            f(&mut dns);
            config.dns_config = Some(dns);
            config
        };
        let top = |f: &dyn Fn(&mut PodSandboxConfig)| {
            let mut config = base_config();
            f(&mut config);
            config
        };
        vec![
            ("dns_config.servers", dns(&|d| d.servers = strings())),
            ("dns_config.searches", dns(&|d| d.searches = strings())),
            ("dns_config.options", dns(&|d| d.options = strings())),
            (
                "port_mappings",
                top(&|c| c.port_mappings = vec![PortMapping::default(); count]),
            ),
            ("labels", top(&|c| c.labels = map())),
            ("annotations", top(&|c| c.annotations = map())),
            ("linux.sysctls", linux(&|l| l.sysctls = map())),
            (
                "linux.security_context.supplemental_groups",
                linux(&|l| {
                    l.security_context = Some(LinuxSandboxSecurityContext {
                        supplemental_groups: vec![1; count],
                        ..Default::default()
                    });
                }),
            ),
            (
                "linux.security_context.namespace_options.userns_options.uids",
                userns(&|u| u.uids = vec![IdMapping::default(); count]),
            ),
            (
                "linux.security_context.namespace_options.userns_options.gids",
                userns(&|u| u.gids = vec![IdMapping::default(); count]),
            ),
            (
                "linux.overhead.hugepage_limits",
                linux(&|l| {
                    l.overhead = Some(LinuxContainerResources {
                        hugepage_limits: vec![HugepageLimit::default(); count],
                        ..Default::default()
                    });
                }),
            ),
            (
                "linux.overhead.unified",
                linux(&|l| {
                    l.overhead = Some(LinuxContainerResources {
                        unified: map(),
                        ..Default::default()
                    });
                }),
            ),
            (
                "linux.resources.hugepage_limits",
                linux(&|l| {
                    l.resources = Some(LinuxContainerResources {
                        hugepage_limits: vec![HugepageLimit::default(); count],
                        ..Default::default()
                    });
                }),
            ),
            (
                "linux.resources.unified",
                linux(&|l| {
                    l.resources = Some(LinuxContainerResources {
                        unified: map(),
                        ..Default::default()
                    });
                }),
            ),
        ]
    }

    /// ERR-3・TASK-57.1: 14 個の repeated / map フィールドはどれも 1024 件まで受け付け、1025 件で
    /// フィールド名つきの INVALID_ARGUMENT になる。受理時の見積もりは件数ぶんの上乗せを含む。
    #[test]
    fn task_57_1_collection_entries_boundary() {
        let at_limit = configs_with_collection(MAX_CONFIG_COLLECTION_ENTRIES);
        assert_eq!(at_limit.len(), 14);
        for (field, config) in at_limit {
            let encoded_len = config.encoded_len();
            let bounded = BoundedConfig::new(config.clone())
                .unwrap_or_else(|e| panic!("{field} at the limit: {e}"));
            assert_eq!(
                bounded.retained_bytes(),
                encoded_len + 1024 * RETAINED_BYTES_PER_ENTRY + RETAINED_BYTES_PER_RECORD,
                "{field}"
            );
            assert_eq!(bounded.into_config(), config, "{field}");
        }
        for (field, config) in configs_with_collection(MAX_CONFIG_COLLECTION_ENTRIES + 1) {
            assert_eq!(
                rejected(config),
                (
                    Code::InvalidArgument,
                    format!("config.{field} has too many entries: 1025 exceeds the limit of 1024")
                )
            );
        }
    }

    /// TASK-57.1: 見積もりは「符号化長＋要素数×256＋4096」で、複数のフィールドの件数を合算する。
    #[test]
    fn task_57_1_retained_bytes_formula() {
        let mut config = base_config();
        config.labels.insert("k".into(), "v".into()); // BTreeMap は容量を持たないため labels は容量の対象外
        config.annotations.insert("a".into(), "b".into());
        config.annotations.insert("c".into(), "d".into());
        config.port_mappings.push(PortMapping::default());
        let encoded_len = config.encoded_len();
        let bounded = BoundedConfig::new(config).expect("valid");
        assert_eq!(bounded.retained_bytes(), encoded_len + 4 * 256 + 4096);
    }

    /// TASK-57.1: 作り直しは内容を変えず、呼び出し元が確保した過大な容量を引き継がない。
    #[test]
    fn task_57_1_rebuild_drops_excess_capacity() {
        let mut config = base_config();
        config.hostname = String::with_capacity(1 << 20);
        config.hostname.push_str("host");
        config.labels.insert("k".into(), "v".into()); // BTreeMap は容量を持たないため labels は容量の対象外
        config.port_mappings = Vec::with_capacity(1 << 16);
        let expected = config.clone();
        let rebuilt = BoundedConfig::new(config).expect("valid").into_config();
        assert_eq!(rebuilt, expected);
        assert!(rebuilt.hostname.capacity() < 64);
        assert!(rebuilt.port_mappings.capacity() < 16);
    }

    /// 件数検証の対象外にしている要素・末端の型が repeated / map を持たないことを固定する
    /// （`..` なしの分解。cri-api の更新でフィールドが増えるとコンパイルエラーになる。REPAIR-12）。
    #[test]
    fn task_57_1_element_types_have_no_nested_collections() {
        let PortMapping {
            protocol,
            container_port,
            host_port,
            host_ip,
        } = PortMapping::default();
        assert_eq!((protocol, container_port, host_port), (0, 0, 0));
        assert_eq!(host_ip, "");
        let HugepageLimit { page_size, limit } = HugepageLimit::default();
        assert_eq!((page_size.as_str(), limit), ("", 0));
        let IdMapping {
            host_id,
            container_id,
            length,
        } = IdMapping::default();
        assert_eq!((host_id, container_id, length), (0, 0, 0));
        let SeLinuxOption {
            user,
            role,
            r#type,
            level,
        } = SeLinuxOption::default();
        assert_eq!((user, role, r#type, level), Default::default());
        let SecurityProfile {
            profile_type,
            localhost_ref,
        } = SecurityProfile::default();
        assert_eq!((profile_type, localhost_ref.as_str()), (0, ""));
        let Int64Value { value } = Int64Value::default();
        assert_eq!(value, 0);
        let WindowsPodSandboxConfig { security_context } = WindowsPodSandboxConfig::default();
        assert_eq!(security_context, None);
        let WindowsSandboxSecurityContext {
            run_as_username,
            credential_spec,
            host_process,
            namespace_options,
        } = WindowsSandboxSecurityContext::default();
        assert_eq!(
            (run_as_username.as_str(), credential_spec.as_str()),
            ("", "")
        );
        assert_eq!((host_process, namespace_options), (false, None));
        let WindowsNamespaceOption { network } = WindowsNamespaceOption::default();
        assert_eq!(network, 0);
    }
}
