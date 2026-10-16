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
