//! `start` の実処理: supervisor の bin を起動し、結果の 1 行を期限付きで受け取る adapter
//! （TASK-79 追補・#1718・#2434・CLI-1・CORE-1・SUP-1・REPAIR-2・REPAIR-3・REPAIR-5・ERR-1・ERR-2・MS-6）。
//!
//! `create_start::run_start` から呼ばれる薄い層である。起動の実装（契約の argv・環境・stdio・委譲 scope〔`systemd-run`〕・
//! 受信期限 58.9 秒・報告の復号・事前検査）は `fandhe_container_supervisor::start_client` にあり、plugin-cri の `start` と
//! 共有するため CLI の private 実装から移した（#2434・REPAIR-1）。契約・期限・待機中のシグナルの扱い・未実装の一覧は
//! 移設先の module doc を参照する。外部から見える挙動（終了コード・文言・期限）は移設前と変えない。
//!
//! 権限モデルの選択（#2442・SUP-14）: 非 root で実体の隣に信頼できる `fandhe-container-launcher` があれば rootful のインストールと
//! みなしてランチャー経由で起動する（`process_group(0)` なし・pty なし）。無ければ従来の直接経路（rootless）。uid 0 はランチャーの
//! 前提（呼び出し元は非 root）に反し、`RootfulHostRoot` は #2241 の決定どおり `PERMISSION_DENIED` で恒久拒否。規則は共有クライアント側にある。
//!
//! `--audit-policy`(SEC-4・#2761): CLI の `start --audit-policy <best-effort|strict>` を検証した値を、指定されたときだけ
//! supervisor の argv へ渡す(未指定は supervisor の既定 best-effort)。restart の再 launch は supervisor が start で受けた値を使う。
//!
//! CLI に残す責務:
//! - 実行ファイルの基準: CLI 自身の実体パス（`current_exe()`）と同じディレクトリの固定名 `fandhe-container-supervisor`
//!   （`PATH` 探索・環境変数・引数による上書きは作らない。#2068・SUP-14）。
//! - `start` で状態を書かない（#1541）。supervisor は CLI より長く生きるため、戻りの `Child` は wait も kill もせず drop する。
//! - 試験専用 feature `start-test-support` のときだけ、環境変数 `FANDHE_CONTAINER_TEST_SYSTEMD_RUN`（絶対パス）で
//!   systemd-run の解決を差し替えられる（所有者の検証だけを飛ばす。他の検査は飛ばさない）。本番のビルドにはこの環境変数を
//!   読むコードが存在せず、最適化ビルドで feature を有効にするとコンパイルが止まる（`lib.rs`）。
//! - 試験専用 feature `start-status-test-support` のときだけ、環境変数 `FANDHE_CONTAINER_TEST_PROC_STATUS_FILE`（ファイルのパス）の
//!   内容を `/proc/self/status` の代わりに使える（uid 0 の恒久拒否 SEC-5・#4709 の試験用。systemd-run の解決は本番と同じ）。

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use fandhe_container_core::audit_log::AuditCoveragePolicy;
use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
use fandhe_container_core::traits::{ContainerId, ErrorCode};
use fandhe_container_supervisor::start_client::{
    StartOptions, SupervisorLaunch, locate_systemd_run, production_deadline, start_with_options,
};

/// 試験専用: systemd-run の解決を差し替える環境変数（feature `start-test-support` のときだけ読む）。
#[cfg(feature = "start-test-support")]
const TEST_SYSTEMD_RUN_ENV: &str = "FANDHE_CONTAINER_TEST_SYSTEMD_RUN";

/// systemd-run の解決。本番は固定候補だけで、試験専用 feature のときだけ環境変数で差し替えられる。
/// `start` と `exec` の委譲スコープでの再実行（SUP-6）が共有する唯一の解決口。
pub(super) fn locate(euid: u32) -> Result<PathBuf, OciRuntimeError> {
    #[cfg(feature = "start-test-support")]
    if let Some(p) = std::env::var_os(TEST_SYSTEMD_RUN_ENV) {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            return Ok(p);
        }
    }
    locate_systemd_run(euid)
}

/// 本番入口: supervisor を委譲 scope で起動して pid か構造化エラーを期限付きで受け取る。
///
/// `root` は `StateRoot::resolve` で解決した絶対パス。`id` は `ContainerId::new` で検証済みの値。
/// 事前検査（supervisor の実在・rootful・systemd-run・user マネージャ）はすべて spawn の前に行い、失敗は案 B へ落とさず返す。
pub(super) fn start_via_supervisor(
    root: &Path,
    id: &ContainerId,
    audit_policy: Option<AuditCoveragePolicy>,
) -> Result<NonZeroU32, OciRuntimeError> {
    let cli_exe = std::env::current_exe().map_err(|_| {
        OciRuntimeError::new(
            LifecycleOp::Start,
            ErrorCode::FailedPrecondition,
            "cannot resolve the cli executable path",
        )
    })?;
    let launch = resolve_launch(&cli_exe)?;
    let opts = StartOptions::new().with_audit_policy(audit_policy);
    let (result, child) = start_with_options(&launch, root, &opts, id, production_deadline());
    // supervisor は CLI より長く生きる。wait も kill もせずに手放す。
    drop(child);
    result
}

/// 試験専用: `/proc/self/status` の代わりに内容を読むファイルを指す環境変数（feature `start-status-test-support` のときだけ読む。
/// SEC-5・#4709: uid 0 の拒否を非 root の CI で実バイナリ越しに通す）。
#[cfg(feature = "start-status-test-support")]
const TEST_PROC_STATUS_FILE_ENV: &str = "FANDHE_CONTAINER_TEST_PROC_STATUS_FILE";

/// supervisor の解決。本番は `locate` による解決だけで、試験専用 feature のときだけ status の読み取りを差し替えられる。
fn resolve_launch(cli_exe: &Path) -> Result<SupervisorLaunch, OciRuntimeError> {
    #[cfg(feature = "start-status-test-support")]
    if let Some(p) = std::env::var_os(TEST_PROC_STATUS_FILE_ENV) {
        return SupervisorLaunch::resolve_beside_with_status(cli_exe, locate, || {
            status_with_injection(Path::new(&p))
        });
    }
    SupervisorLaunch::resolve_beside_with(cli_exe, locate)
}

/// 試験専用: 権限検査へ渡す status の本文を決める（SEC-5・#4709）。
///
/// 先に実プロセスの `/proc/self/status` を見る。実際の uid に 0 が含まれる・読めない・壊れているときは、その実の本文を
/// そのまま返し、通常経路と同じ拒否（PERMISSION_DENIED / FAILED_PRECONDITION）になる。実の uid が全部非 0 のときだけ
/// 注入ファイルの内容を返す（注入は拒否を足すだけで、実の拒否を外せない）。注入ファイルは通常ファイルだけを
/// `O_NOFOLLOW|O_NONBLOCK` で開き、実の読み取りと同じ上限（`MAX_STATUS_BYTES`）を超えたら読めない扱い（`None`）にする。
#[cfg(feature = "start-status-test-support")]
fn status_with_injection(injected: &Path) -> Option<String> {
    prefer_real_status(crate::user_scope::read_self_status(), || {
        read_injected_status(injected)
    })
}

/// 実の status を先に見る（SEC-5・#4709）。実の uid に 0 がある・読めない・壊れているときは実の本文（または `None`）を
/// そのまま返し、注入は読まない（通常経路と同じ拒否・失敗になる）。実が rootless のときだけ注入の内容を返す。
/// 注入は拒否を足す用途に限り、実の拒否を外せない。
#[cfg(feature = "start-status-test-support")]
fn prefer_real_status(
    real: Option<String>,
    injected: impl FnOnce() -> Option<String>,
) -> Option<String> {
    let real_ok = matches!(
        real.as_deref().map(crate::user_scope::identity_from_status),
        Some(crate::user_scope::Identity::Rootless { .. })
    );
    if !real_ok {
        return real;
    }
    injected()
}

/// 注入ファイルを通常ファイルに限って上限つきで読む（O_NOFOLLOW|O_NONBLOCK・`MAX_STATUS_BYTES`）。
#[cfg(feature = "start-status-test-support")]
fn read_injected_status(injected: &Path) -> Option<String> {
    use fandhe_container_supervisor::privilege::MAX_STATUS_BYTES;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let flags = fandhe_container_core::open_flags::NofollowOpenFlags::current()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.file_nofollow_nonblock())
        .open(injected)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_STATUS_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= MAX_STATUS_BYTES).then_some(text)
}

#[cfg(all(test, feature = "start-status-test-support"))]
mod status_injection_tests {
    use super::prefer_real_status;

    fn status(uid: &str) -> String {
        format!(
            "Name:\tx\nUid:\t{uid}\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nNoNewPrivs:\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"
        )
    }

    /// SEC-5・REPAIR-12・#4709: 実の uid に 0 がある・読めないときは注入を読まず実の本文（`None`）を返す。
    /// 実が rootless のときだけ注入の内容を使う（注入で実の rootful の拒否を外せない）。
    #[test]
    fn sec5_4709_real_rootful_or_unreadable_status_wins_over_injection() {
        for real_uid in [
            "0\t0\t0\t0",
            "0\t1000\t1000\t1000",
            "1000\t0\t1000\t1000",
            "1000\t1000\t0\t1000",
            "1000\t1000\t1000\t0",
        ] {
            let real = status(real_uid);
            let got = prefer_real_status(Some(real.clone()), || {
                panic!("the injection must not be read when the real uid {real_uid} has 0")
            });
            assert_eq!(got.as_deref(), Some(real.as_str()));
        }
        let got = prefer_real_status(None, || panic!("must not read the injection"));
        assert_eq!(got, None);
        let injected = status("0\t0\t0\t0");
        let got = prefer_real_status(Some(status("1000\t1000\t1000\t1000")), || {
            Some(injected.clone())
        });
        assert_eq!(got.as_deref(), Some(injected.as_str()));
    }
}
