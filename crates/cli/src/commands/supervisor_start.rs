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
//! 前提（呼び出し元は非 root）に反し、`RootfulHostRoot`（#2241）の判断待ちのため `UNIMPLEMENTED` のまま。規則は共有クライアント側にある。
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
fn locate(euid: u32) -> Result<PathBuf, OciRuntimeError> {
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
    let launch = SupervisorLaunch::resolve_beside_with(&cli_exe, locate)?;
    let opts = StartOptions::new().with_audit_policy(audit_policy);
    let (result, child) = start_with_options(&launch, root, &opts, id, production_deadline());
    // supervisor は CLI より長く生きる。wait も kill もせずに手放す。
    drop(child);
    result
}
