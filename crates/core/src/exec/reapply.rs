//! exec プロセスへの seccomp / Landlock 再適用（SUP-6・TASK-163.3・#502・CORE-5・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! SUP-6 の exec は「pid1 の namespace へ `setns` → cgroup join → seccomp / Landlock 再適用 → コマンド実行」。
//! `setns` と cgroup join だけを済ませたプロセスは、コンテナ本体（launch 経路のステージ列
//! `NoNewPrivs → Landlock → Seccomp`。`exec/stages.rs`）より弱い制限で動いてしまう。本モジュールは
//! 3 段目の再適用を担い、`fandhe-container-supervisor` の `exec`（`prepare_restrictions` /
//! `reapply_restrictions`）が薄く配線する。#503（TASK-163.4）の exec 専用プロセスが呼ぶ想定。
//!
//! # 契約
//!
//! - 二段階 API（`exec/cgroup_join.rs` の `prepare_cgroup_join` / `join_cgroup` と同型）:
//!   [`prepare_exec_restrictions`] は **`join_namespaces` の前**、[`reapply_restrictions`] は
//!   `join_namespaces` と `join_cgroup` の **後** に呼ぶ。seccomp の既定フィルタは `setns` を拒否するため、
//!   再適用を `setns` の前に置くと namespace 参加が失敗する（cgroup join を seccomp の前に置く既存の順序と一致）
//! - 全体の順序（#503 が守る。exec 専用プロセス内）: `identify_pid1` → `prepare_cgroup_join` →
//!   [`prepare_exec_restrictions`] → `join_namespaces` → `join_cgroup` → [`reapply_restrictions`] →
//!   （#503: fork → `close_range` → execve）。制限（`NO_NEW_PRIVS`・Landlock・seccomp）は fork / execve を
//!   越えて継承されるため、#503 は「適用 → fork → execve」の順にする
//! - 内部の適用順は `PR_SET_NO_NEW_PRIVS` → Landlock → seccomp で固定（`StageKind::ORDER` の相対順と同じ）。
//!   最初の失敗で打ち切り、後続は呼ばない。エラーの `stage` は `NoNewPrivs` / `Landlock` / `Seccomp`
//! - **準備したプロセス自身が適用する**: 保持する `/proc/self/status` の fd は開いたプロセスの情報を返す。
//!   `setns(CLONE_NEWNS)` の後は `/proc` がコンテナ側の procfs になり自プロセスを `/proc/self` で解決できない
//!   ため、事前に開いた fd で適用前後の `Threads: 1` 検査（seccomp・Landlock の既存検査）を行う。fork した
//!   子から使うと親のスレッド数を読むため、準備時の pid を記録し、不一致なら何も適用せず
//!   `FailedPrecondition` にする（best-effort の誤用検知。PID namespace をまたぐ数値衝突は検知できない）
//! - **単一スレッド専用・不可逆**: logs 捕捉スレッドを持つ supervisor 本体からは呼ばない。失敗時は制限が
//!   部分的に載った不定状態のため、呼び出し側は続行せず終了する（巻き戻し不可。`join_cgroup` と同じ）
//! - **fail-closed**: Landlock 未対応カーネル・ルール生成失敗は準備段階で `stage = Landlock` として拒否し、
//!   Landlock 無しで続行する経路を作らない（CORE-5）。値を消費するため二重適用・fd の残留を型で防ぐ
//! - **ルールパスは `setns` の後に解決される**: 準備段階の ruleset が持つのは config の mount destination
//!   （コンテナ内パス。`RulePath`）の正規化済み文字列だけで、準備ではファイルを一切開かない・ホスト側パスへ
//!   解決しない（fd の事前保持もしない）。パスを開く `O_PATH` fd（`landlock_add_rule` 用）は
//!   [`reapply_restrictions`] の中（`join_namespaces` 後 = 参加先 mount namespace のルート `/` 起点・
//!   `O_NOFOLLOW` の 1 要素ずつ）で開かれるため、準備時に固定されたホスト側の対象を指すことはない。
//!   準備時に fd を保持する方式は `setns` 前のホスト mount namespace を指してしまうため採らない
//! - ルールは launcher が実際にマウントした結果ではなく `config.json` から再導出する（launch 時の ruleset は
//!   保存されていない）。Landlock の適用は存在しない・開けないルールパスを拒否するため、config の mount
//!   destination が稼働中の rootfs に無ければ [`reapply_restrictions`] は失敗し exec は拒否される
//!   （fail-closed として正しい挙動）。bundle は supervisor と同じ信頼境界（コンテナから書けない）にある前提
//! - エラーメッセージ・`Debug` 出力にホスト側パス・ルール内容を載せない
//!
//! # 未実装（REPAIR-3）
//!
//! - fork・execve・`close_range`・`setns` を伴う通し試験は #503（TASK-163.4）。**`setns` の後に保持 fd から
//!   スレッド数が実際に読めること** の実機確認もそこで行う（本モジュールのテストは `setns` をしない）
//! - user namespace への参加、exec プロセスの capability 削減・rlimit 適用は未実装
//! - 拒否の監査ログ保存の配線（#839・SEC-4）

use super::landlock::{LandlockAccessProbe, landlock_ruleset_from_config, run_probe};
use super::{ExecError, IsolationStage, ThreadCountSource, no_new_privs};
use crate::landlock::LandlockRuleset;
use crate::oci_runtime::OciConfig;
use crate::sys;
use crate::traits::types::ErrorCode;

// テストでは本物（`Threads: 1` と実 syscall を要する）の代わりに偽物へ差し替える（`stages.rs` と同じ）。
#[cfg(not(test))]
use super::landlock::apply_landlock_stage_with;
#[cfg(test)]
use super::landlock::testing::apply_landlock_stage_with;
#[cfg(not(test))]
use super::seccomp::apply_default_seccomp_with;
#[cfg(test)]
use super::seccomp::testing::apply_default_seccomp_with;

/// [`prepare_exec_restrictions`] が `setns` の前に確保した再適用の材料一式。[`reapply_restrictions`] が消費する。
pub struct ExecRestrictions {
    landlock: LandlockRuleset,
    threads: ThreadCountSource,
    owner_pid: u32,
}

impl std::fmt::Debug for ExecRestrictions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // fd・ルール内容は出さない。
        f.debug_struct("ExecRestrictions")
            .field("owner_pid", &self.owner_pid)
            .finish_non_exhaustive()
    }
}

/// [`reapply_restrictions`] の成功結果（将来拡張できる構造。制限適用の証跡ではない。REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecRestrictionReport {
    /// 追加した Landlock ルール数。
    pub landlock_rules: usize,
    /// 適用した seccomp の BPF 命令数。
    pub seccomp_instructions: usize,
}

/// `config`（コンテナの `config.json`）から Landlock ruleset を作り、自プロセスの status fd を確保する。
///
/// `join_namespaces` の **前** に、再適用を行うプロセス自身が呼ぶ。ABI 検出・ルール生成の失敗
/// （Landlock 未対応カーネルを含む）は `stage = Landlock` で拒否する（fail-closed。CORE-5）。
pub fn prepare_exec_restrictions(config: &OciConfig) -> Result<ExecRestrictions, ExecError> {
    let landlock = landlock_ruleset_from_config(config)?;
    let file = std::fs::File::open("/proc/self/status").map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Landlock,
            "failed to open /proc/self/status",
        )
    })?;
    Ok(ExecRestrictions {
        landlock,
        threads: ThreadCountSource::PreOpened(file),
        owner_pid: std::process::id(),
    })
}

/// `NO_NEW_PRIVS` → Landlock → seccomp を呼び出しプロセスへ不可逆に適用する。
///
/// `join_namespaces` と `join_cgroup` の **後**、準備したプロセス自身から単一スレッドで呼ぶ。
/// 最初の失敗で打ち切る。失敗後の制限は部分的に載った不定状態のため、呼び出し側は続行せず終了すること。
pub fn reapply_restrictions(
    mut restrictions: ExecRestrictions,
) -> Result<ExecRestrictionReport, ExecError> {
    if restrictions.owner_pid != std::process::id() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "restrictions must be reapplied by the process that prepared them",
        ));
    }
    no_new_privs::apply_no_new_privs()?;
    let landlock = apply_landlock_stage_with(&restrictions.landlock, &mut restrictions.threads)
        .map_err(|e| e.at_stage(IsolationStage::Landlock))?;
    let seccomp = apply_default_seccomp_with(&mut restrictions.threads)
        .map_err(|e| e.at_stage(IsolationStage::Seccomp))?;
    Ok(ExecRestrictionReport {
        landlock_rules: landlock.rules_added,
        seccomp_instructions: seccomp.instructions,
    })
}

/// [`observe_exec_restriction_reapply`] の観測結果。errno は成功を `None`、失敗を `Some(errno)`（不明は `-1`）。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecReapplyObservation {
    /// 準備（ABI 検出・ルール生成）の失敗。`Some` なら適用もプローブもしていない（fail-closed）。
    pub prepare_error: Option<ExecError>,
    /// 再適用の失敗。`Some` ならプローブはしていない（exec 拒否に相当）。
    pub reapply_error: Option<ExecError>,
    /// 再適用の成功結果。
    pub report: Option<ExecRestrictionReport>,
    /// 適用前の `/proc/thread-self/status` の `Seccomp:` 値（無制限は `0`）。
    pub seccomp_before: String,
    /// 適用前の `NoNewPrivs:` 値（準備失敗時に「変わっていない」ことを照合する基準）。
    pub no_new_privs_before: String,
    /// 試行後の `Seccomp:` 値（適用に成功すれば filter モードの `2`）。
    pub seccomp_after: String,
    /// 試行後の `NoNewPrivs:` 値（適用に成功すれば `1`）。
    pub no_new_privs_after: String,
    /// 適用前の `unshare(0)`（対照。フラグなしのため通常は成功し `None`）。
    pub unshare_before: Option<i32>,
    /// 適用後の `unshare(0)`（禁止 syscall のため `EPERM`）。適用に失敗した場合は `None`。
    pub unshare_after: Option<i32>,
    /// Landlock プローブ結果（入力順）。再適用に成功した場合のみ入る。
    pub results: Vec<(LandlockAccessProbe, Option<i32>)>,
}

/// 観測 1 回で試せるプローブ数の上限（`exec/landlock.rs` と同じ固定リスト前提の防御）。
const MAX_REAPPLY_PROBES: usize = 32;

/// 本番の準備・再適用の経路をそのまま通し、seccomp と Landlock の遮断を観測する
/// （SUP-6・TASK-163.3・#502・CORE-5。結合試験専用）。
///
/// 結合試験 `tests/exec_restrictions_reapply.rs` の使い捨て子プロセス（単一スレッドの `main`）専用で、
/// 通常の利用者は呼ばない。`setns` は行わないため、Landlock のルールパスはホストの `/` に対して解決される。
/// 準備・再適用のいずれかが失敗したらプローブは実行しない。`unsafe` は追加せず、syscall は既存の
/// `crate::sys` ラッパーに限る。
///
/// # 将来仕様（記録のみ）
///
/// `setns` を伴う通し確認は #503（TASK-163.4）の統合テストで行う（REPAIR-3）。
#[doc(hidden)]
pub fn observe_exec_restriction_reapply(
    config: &OciConfig,
    probes: &[LandlockAccessProbe],
) -> Result<ExecReapplyObservation, ExecError> {
    let internal = |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Validate, m);
    if probes.len() > MAX_REAPPLY_PROBES {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Landlock,
            "too many access probes",
        ));
    }
    let seccomp_before = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    let no_new_privs_before =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    let unshare_before = errno_of(sys::unshare_namespaces(&[]));
    let mut obs = ExecReapplyObservation {
        prepare_error: None,
        reapply_error: None,
        report: None,
        seccomp_before,
        no_new_privs_before,
        seccomp_after: String::new(),
        no_new_privs_after: String::new(),
        unshare_before,
        unshare_after: None,
        results: Vec::new(),
    };
    match prepare_exec_restrictions(config) {
        Err(e) => obs.prepare_error = Some(e),
        Ok(prepared) => match reapply_restrictions(prepared) {
            Ok(report) => obs.report = Some(report),
            Err(e) => obs.reapply_error = Some(e),
        },
    }
    obs.seccomp_after = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    obs.no_new_privs_after =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    if obs.report.is_some() {
        obs.unshare_after = errno_of(sys::unshare_namespaces(&[]));
        for p in probes {
            obs.results.push((p.clone(), run_probe(p)));
        }
    }
    Ok(obs)
}

fn errno_of(r: Result<(), sys::SysError>) -> Option<i32> {
    match r {
        Ok(()) => None,
        Err(sys::SysError::Os(n)) => Some(n),
        Err(_) => Some(-1),
    }
}

/// `/proc/thread-self/status` の指定フィールド値（前後の空白は除く）。
fn status_field(name: &str) -> Option<String> {
    let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(|v| v.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::no_new_privs::testing::{fake, take};
    use crate::sys::SysError;

    fn restrictions(owner_pid: u32) -> ExecRestrictions {
        ExecRestrictions {
            landlock: LandlockRuleset::for_observation(6, Vec::new()),
            threads: ThreadCountSource::ProcSelf,
            owner_pid,
        }
    }

    fn err(code: ErrorCode, stage: IsolationStage) -> ExecError {
        ExecError::new(code, stage, "fake")
    }

    /// SUP-6・TASK-163.3: 適用順は NO_NEW_PRIVS → Landlock → seccomp で固定。
    #[test]
    fn sup6_task163_3_reapply_order_is_nnp_landlock_seccomp() {
        let _ = take();
        let report = reapply_restrictions(restrictions(std::process::id())).expect("ok");
        assert_eq!(take(), vec!["no_new_privs", "landlock", "seccomp"]);
        assert_eq!(
            report,
            ExecRestrictionReport {
                landlock_rules: 0,
                seccomp_instructions: 0,
            }
        );
    }

    /// SUP-6・TASK-163.3: NO_NEW_PRIVS の失敗で Landlock・seccomp を呼ばない（段は NoNewPrivs）。
    #[test]
    fn sup6_task163_3_nnp_failure_stops_before_landlock() {
        let _ = take();
        fake(Err(SysError::Os(1)), Ok(true));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("nnp fails");
        assert_eq!(e.stage, IsolationStage::NoNewPrivs);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(take(), vec!["no_new_privs"]);
    }

    /// SUP-6・TASK-163.3: Landlock の失敗で seccomp を呼ばない（段と code を保つ）。
    #[test]
    fn sup6_task163_3_landlock_failure_stops_before_seccomp() {
        let _ = take();
        crate::exec::landlock::testing::fake_landlock_err(err(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("landlock");
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(take(), vec!["no_new_privs", "landlock"]);
    }

    /// SUP-6・TASK-163.3: seccomp の失敗は段 Seccomp・code を保って返る（Landlock までは適用済み）。
    #[test]
    fn sup6_task163_3_seccomp_failure_reports_seccomp_stage() {
        let _ = take();
        crate::exec::seccomp::testing::fake_seccomp_err(err(
            ErrorCode::Internal,
            IsolationStage::Landlock,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("seccomp");
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(take(), vec!["no_new_privs", "landlock", "seccomp"]);
    }

    /// SUP-6・TASK-163.3: 準備したのと別のプロセスからは何も適用せず FailedPrecondition。
    #[test]
    fn sup6_task163_3_owner_pid_mismatch_applies_nothing() {
        let _ = take();
        let other = std::process::id().wrapping_add(1);
        let e = reapply_restrictions(restrictions(other)).expect_err("mismatch");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message,
            "restrictions must be reapplied by the process that prepared them"
        );
        assert_eq!(take(), Vec::<&str>::new());
    }

    /// SUP-6・TASK-163.3: `Debug` は fd・ルール内容を出さず、pid だけを示す。
    #[test]
    fn sup6_task163_3_debug_hides_internals() {
        let text = format!("{:?}", restrictions(42));
        assert_eq!(text, "ExecRestrictions { owner_pid: 42, .. }");
    }

    fn config(readonly: bool, mounts: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":{readonly}}},"mounts":{mounts}}}"#
        );
        crate::oci_runtime::parse_config_bytes(json.as_bytes()).expect("config")
    }

    /// SUP-6・TASK-163.3・CORE-5: 書き込み制限が祖先ルールで無効になる構成は、準備が `stage = Landlock` で
    /// 拒否する。ABI 検出が通らない環境では検出失敗で拒否される（どちらも fail-closed で成功しない）。
    #[test]
    fn sup6_task163_3_prepare_rejects_shadowed_write_restriction() {
        let c = config(false, r#"[{"destination":"/etc","options":["ro"]}]"#);
        let e = prepare_exec_restrictions(&c).expect_err("must be rejected");
        assert_eq!(e.stage, IsolationStage::Landlock);
        const DETECT: [&str; 6] = [
            "kernel_lacks_landlock",
            "landlock_disabled_at_boot",
            "landlock_abi_too_old",
            "invalid_kernel_response",
            "unsupported_architecture",
            "landlock_probe_failed",
        ];
        if e.message.starts_with("write_restriction_shadowed:") {
            assert_eq!(e.code, ErrorCode::InvalidArgument);
        } else {
            assert!(
                DETECT.iter().any(|r| e.message.starts_with(r)),
                "{}",
                e.message
            );
        }
    }

    /// SUP-6・TASK-163.3: 準備が通れば自 pid を記録し、status fd からスレッド数を読める。
    #[test]
    fn sup6_task163_3_prepare_records_pid_and_reads_threads() {
        let c = config(true, "[]");
        match prepare_exec_restrictions(&c) {
            Ok(mut r) => {
                assert_eq!(r.owner_pid, std::process::id());
                let n = r.threads.count().expect("threads readable");
                assert!(n >= 1, "{n}");
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    /// SUP-6・TASK-163.3・CORE-5: 準備はルールパスを開かず解決もしない。実在しないパスを destination に
    /// 持つ config でも準備は成功し、ruleset はコンテナ内パスの文字列をそのまま保持する
    /// （開く処理は `setns` 後の `reapply_restrictions` 側。fail-closed の拒否もそこで起きる）。
    #[test]
    fn sup6_task163_3_prepare_keeps_container_paths_unresolved() {
        let dest = "/fandhe-nonexistent-reapply-dest/data";
        let c = config(
            true,
            &format!(r#"[{{"destination":"{dest}","options":["ro"]}}]"#),
        );
        match prepare_exec_restrictions(&c) {
            Ok(r) => {
                let paths: Vec<&str> = r
                    .landlock
                    .rules()
                    .iter()
                    .map(|rule| rule.path.as_str())
                    .collect();
                assert_eq!(paths, vec!["/", dest]);
                // 準備（`join_namespaces` 前）でホストへ解決されていないこと: destination は実在しない。
                assert!(!std::path::Path::new(dest).exists());
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    fn tmp_file(content: &[u8]) -> std::fs::File {
        use std::io::{Seek as _, Write as _};
        let mut f = tempfile_in_target();
        f.write_all(content).expect("write");
        f.seek(std::io::SeekFrom::Start(0)).expect("seek");
        f
    }

    /// 使い捨ての無名ファイル（名前を残さない）。`O_TMPFILE` 相当を std だけで作れないため、
    /// 一意名で作成して直ちに unlink する。
    fn tempfile_in_target() -> std::fs::File {
        use std::io::Read as _;
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("urandom");
        let path = std::env::temp_dir().join(format!(
            "fandhe-reapply-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(buf)
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create");
        std::fs::remove_file(&path).expect("unlink");
        f
    }

    /// SUP-6・TASK-163.3: 事前に開いた fd から `Threads:` を読め、同じ fd を再読込しても同じ値になる。
    #[test]
    fn sup6_task163_3_pre_opened_source_parses_and_rereads() {
        let mut src =
            ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\nThreads:\t1\nVmRSS:\t5 kB\n"));
        assert_eq!(src.count(), Some(1));
        assert_eq!(src.count(), Some(1));
    }

    /// SUP-6・TASK-163.3: `Threads:` 行が無い・空の fd は `None`（適用は拒否される。fail-closed）。
    #[test]
    fn sup6_task163_3_pre_opened_source_rejects_unreadable_status() {
        let mut no_line = ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\n"));
        assert_eq!(no_line.count(), None);
        let mut empty = ThreadCountSource::PreOpened(tmp_file(b""));
        assert_eq!(empty.count(), None);
        let mut multi = ThreadCountSource::PreOpened(tmp_file(b"Threads:\t3\n"));
        assert_eq!(multi.count(), Some(3));
    }
}
