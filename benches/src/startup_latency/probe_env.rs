//! スモーク時に出すホスト環境プローブ（TASK-190。読み取りだけで、何も起動・変更しない）。
//!
//! 「CI で分離込みの起動を測れるか」の根拠を実 runner のログに残すための 1 行を作る
//! （`docs/design/bench-calibration.md`「CI の扱いの決定（TASK-190）」）。値は固定語彙・数値だけで、
//! パス・ホスト名・ユーザー名は出さない。

use fandhe_container_core::cgroups::DelegatedCgroup;
use fandhe_container_core::landlock::detect_landlock_abi;
use std::path::Path;

/// `/proc/self/status` の実効 UID。読めない場合は `None`（呼び出し側は fail-closed にする）。
pub fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn read_trimmed(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().chars().take(16).collect(),
        Err(_) => "absent".to_string(),
    }
}

/// スモークで標準出力へ出す 1 行。
pub fn host_probe_line() -> String {
    let euid = effective_uid();
    let bus_present = euid.is_some_and(|uid| Path::new(&format!("/run/user/{uid}/bus")).exists());
    format!(
        "startup_latency: smoke; apparmor_restrict_unprivileged_userns={} max_user_namespaces={} landlock={} user_bus={} delegated_cgroup={} euid_root={}",
        read_trimmed("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        read_trimmed("/proc/sys/user/max_user_namespaces"),
        if detect_landlock_abi().is_ok() {
            "ok"
        } else {
            "unavailable"
        },
        if bus_present { "present" } else { "absent" },
        if DelegatedCgroup::detect().is_ok() {
            "ok"
        } else {
            "unavailable"
        },
        euid == Some(0),
    )
}

/// ホストの種類の判定に使う読み取り専用の入力（`/proc`・`/sys` の値。プロセスは起動しない）。
/// 読めなかったものは `None`。判定は純関数 `classify_host_kind` が行い、実機に依存しない試験ができる。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostSignals {
    /// `/proc/sys/kernel/osrelease`
    pub osrelease: Option<String>,
    /// `/sys/hypervisor/type`（Xen 等。空でなければ仮想化）
    pub hypervisor_type: Option<String>,
    /// `/sys/class/dmi/id/sys_vendor`
    pub sys_vendor: Option<String>,
    /// `/sys/class/dmi/id/product_name`
    pub product_name: Option<String>,
    /// `/proc/cpuinfo` の flags 行に `hypervisor` があるか。cpuinfo を読めなければ `None`。
    pub cpuinfo_hypervisor_flag: Option<bool>,
}

/// DMI の `sys_vendor`・`product_name` に含まれると仮想化とみなす固定の部分文字列（小文字で照合）。
const VM_DMI_MARKERS: [&str; 11] = [
    "qemu",
    "kvm",
    "vmware",
    "virtualbox",
    "innotek",
    "xen",
    "parallels",
    "amazon ec2",
    "google compute",
    "virtual machine",
    "bochs",
];

/// ホストの種類を `bare-metal` / `vm` / `wsl2` / `unknown` のいずれかにする（REPAIR-8・CORE-10。`bench-check-manual` の語彙）。
/// 根拠がはっきりした場合だけ語彙の値を返し、迷ったら `unknown`（`bare-metal` を既定値にしない。fail-closed）。
/// DMI の文字列そのものは結果に出さず、判定にだけ使う。
pub fn classify_host_kind(sig: &HostSignals, arch: &str) -> &'static str {
    let lower = |o: &Option<String>| o.as_deref().map(str::to_ascii_lowercase);
    if lower(&sig.osrelease).is_some_and(|r| r.contains("microsoft")) {
        return "wsl2";
    }
    let dmi_text = [lower(&sig.sys_vendor), lower(&sig.product_name)];
    // EC2 のベアメタル（`*.metal`）は sys_vendor が Amazon EC2 でも仮想化ではない。
    // その場合は Amazon の印を無視し、hypervisor フラグ等の他の根拠で決める（REPAIR-8）。
    let ec2_metal = lower(&sig.sys_vendor).is_some_and(|v| v.contains("amazon ec2"))
        && lower(&sig.product_name).is_some_and(|p| p.contains(".metal"));
    let dmi_vm = dmi_text.iter().flatten().any(|t| {
        VM_DMI_MARKERS
            .iter()
            .filter(|m| !(ec2_metal && **m == "amazon ec2"))
            .any(|m| t.contains(m))
    });
    let hv_type = sig
        .hypervisor_type
        .as_deref()
        .is_some_and(|t| !t.is_empty());
    if dmi_vm || hv_type || (arch == "x86_64" && sig.cpuinfo_hypervisor_flag == Some(true)) {
        return "vm";
    }
    // 仮想化の根拠が無いときだけ bare-metal。DMI を読めなければ根拠不足（unknown）。
    let dmi_readable = sig.sys_vendor.is_some() || sig.product_name.is_some();
    let flag_known_absent = sig.cpuinfo_hypervisor_flag == Some(false);
    match arch {
        "x86_64" if dmi_readable && flag_known_absent => "bare-metal",
        // aarch64 の cpuinfo には hypervisor フラグ相当が無いため、DMI の確認だけで判断する。
        "aarch64" if dmi_readable => "bare-metal",
        _ => "unknown",
    }
}

/// 長さに上限をつけて先頭だけ読む（巨大ファイル・無限ファイルで止まらない）。
fn read_capped(path: &str, cap: u64) -> Option<String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    f.take(cap).read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn read_small(path: &str) -> Option<String> {
    read_capped(path, 256).map(|s| s.trim().to_string())
}

/// `/proc/cpuinfo` の flags 行に `hypervisor` があるか。先頭 64 KiB だけを見る。
fn cpuinfo_has_hypervisor() -> Option<bool> {
    let text = read_capped("/proc/cpuinfo", 64 * 1024)?;
    let flags = text.lines().find(|l| l.starts_with("flags"))?;
    Some(flags.split_whitespace().any(|w| w == "hypervisor"))
}

/// このホストの種類を判定する（結果 JSON の `host_kind`）。
pub fn detect_host_kind() -> &'static str {
    let sig = HostSignals {
        osrelease: read_small("/proc/sys/kernel/osrelease"),
        hypervisor_type: read_small("/sys/hypervisor/type"),
        sys_vendor: read_small("/sys/class/dmi/id/sys_vendor"),
        product_name: read_small("/sys/class/dmi/id/product_name"),
        cpuinfo_hypervisor_flag: cpuinfo_has_hypervisor(),
    };
    classify_host_kind(&sig, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    /// REPAIR-8: WSL2 は osrelease の microsoft で判定する（大文字小文字は区別しない）。
    #[test]
    fn wsl2_is_detected_from_osrelease() {
        let sig = HostSignals {
            osrelease: s("5.15.153.1-Microsoft-standard-WSL2"),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "wsl2");
    }

    #[test]
    fn qemu_dmi_is_vm() {
        let sig = HostSignals {
            osrelease: s("6.12.0"),
            sys_vendor: s("QEMU"),
            product_name: s("Standard PC (Q35 + ICH9, 2009)"),
            cpuinfo_hypervisor_flag: Some(true),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "vm");
    }

    /// REPAIR-8: EC2 のベアメタル（.metal）は vm と判定しない。フラグ無しなら bare-metal、フラグ不明なら unknown。
    #[test]
    fn ec2_metal_is_not_vm() {
        let mut sig = HostSignals {
            sys_vendor: s("Amazon EC2"),
            product_name: s("m5.metal"),
            cpuinfo_hypervisor_flag: Some(false),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "bare-metal");
        sig.cpuinfo_hypervisor_flag = None;
        assert_eq!(classify_host_kind(&sig, "x86_64"), "unknown");
        sig.product_name = s("m5.large");
        sig.cpuinfo_hypervisor_flag = Some(false);
        assert_eq!(classify_host_kind(&sig, "x86_64"), "vm");
    }

    #[test]
    fn x86_hypervisor_flag_alone_is_vm() {
        let sig = HostSignals {
            sys_vendor: s("Dell Inc."),
            cpuinfo_hypervisor_flag: Some(true),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "vm");
    }

    #[test]
    fn x86_real_vendor_without_flag_is_bare_metal() {
        let sig = HostSignals {
            osrelease: s("6.12.0"),
            sys_vendor: s("Dell Inc."),
            product_name: s("PowerEdge R650"),
            cpuinfo_hypervisor_flag: Some(false),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "bare-metal");
    }

    #[test]
    fn aarch64_without_dmi_is_unknown_and_with_real_dmi_is_bare_metal() {
        assert_eq!(
            classify_host_kind(&HostSignals::default(), "aarch64"),
            "unknown"
        );
        let sig = HostSignals {
            sys_vendor: s("GIGABYTE"),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "aarch64"), "bare-metal");
    }

    #[test]
    fn nothing_readable_is_unknown() {
        assert_eq!(
            classify_host_kind(&HostSignals::default(), "x86_64"),
            "unknown"
        );
        // x86_64 で cpuinfo の hypervisor フラグを確認できなければ bare-metal と断定しない。
        let sig = HostSignals {
            sys_vendor: s("Dell Inc."),
            ..HostSignals::default()
        };
        assert_eq!(classify_host_kind(&sig, "x86_64"), "unknown");
    }

    #[test]
    fn detect_returns_a_value_from_the_closed_set() {
        assert!(["bare-metal", "vm", "wsl2", "unknown"].contains(&detect_host_kind()));
    }
}
