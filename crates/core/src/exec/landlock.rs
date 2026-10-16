//! Landlock 適用ステージの入口とエラー写像（CORE-5・TASK-39.4・#184・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）第 4 段「Landlock」の実体への入口。`crate::landlock`
//! （TASK-39.1〜39.3）が持つ ABI 検出・ルール生成・適用を、起動フローの `ExecError`
//! （`stage = Landlock`）へ写像して繋ぐ。呼び出し元は `StagePipeline::with_landlock` が登録する
//! クロージャで、`run_then` が fork 後の単一スレッドの子（pivot 後・capability 削減と
//! `NO_NEW_PRIVS` の後・seccomp の前）で呼ぶ。実行順は `StageKind::ORDER` が固定する。
//!
//! seccomp・capability 削減と違い Landlock はコンテナごとの入力（`OciConfig` 由来の ruleset）を
//! 要するため、引数なしの組み込み段にはせず、ruleset を持つフックとして Landlock 枠へ差し込む。
//!
//! # 契約
//!
//! - ruleset は fork 前に親で [`landlock_ruleset_from_config`] で作る（検出済みの
//!   `LandlockSupport` を要する型経路のため、ABI 未確認の ruleset は作れない。fail-closed）
//! - 適用は不可逆で呼び出しスレッドにしか効かない。`NO_NEW_PRIVS`・単一スレッドの検証は
//!   `crate::landlock::apply_landlock_ruleset` が ruleset 作成前に行う
//! - 写像は `code` を保ち、`stage` を `Landlock` にし、message に機械可読な理由コードを含める。
//!   ホスト側パスは含めない。`violation` は `None`（ABI 不足・適用失敗は分離違反の試行ではない。
//!   監査ログは TASK-41・SEC-4）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 適用結果 [`LandlockApplyReport`] 自体は証跡ではなく捨てる。制限適用の証跡は、`with_landlock` 経由の
//!   適用が `Ok` を返したときに `stages.rs` の `run_then` だけが作る（`LaunchReady`。#1714）
//! - Landlock の組み込み固定段への昇格（`with_hook(Landlock)` の拒否）は後続作業
//! - 本番 launcher（`oci_runtime::ProductionLauncher`）からの `landlock_ruleset_from_config` の呼び出しは実装済み（#1816）

use std::path::PathBuf;

use super::{ExecError, IsolationStage, ThreadCountSource};
use crate::audit_log::{AuditRecord, AuditRecordError, landlock_denial_record_now};
use crate::landlock::handled_for_abi;
use crate::landlock::{
    LandlockApplyError, LandlockApplyReport, LandlockError, LandlockRuleError, LandlockRuleset,
    LandlockSupport, detect_landlock_abi, path_rules_from_config,
};
use crate::launch_isolation::{LaunchIsolationRecord, RootIdentity};
use crate::oci_runtime::{OciConfig, RootfsDir};
use crate::sys;
use crate::traits::types::ErrorCode;

/// 生成済みの ruleset を呼び出しスレッドへ適用する（CORE-5・TASK-39.4）。
///
/// `StagePipeline::with_landlock` のクロージャから、fork 後の子でのみ呼ぶ（不可逆）。
// テストでは `stages.rs` が偽物（`testing`）へ差し替えるため、本物は未使用になる。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_landlock_stage(
    ruleset: &LandlockRuleset,
) -> Result<LandlockApplyReport, ExecError> {
    crate::landlock::apply_landlock_ruleset(ruleset).map_err(from_landlock_apply)
}

/// [`apply_landlock_stage`] のスレッド数取得元とルールパスの起点を差し替える版（SUP-6・TASK-163.3・#502）。
///
/// exec の再適用（`exec/reapply.rs`）から、`setns` の前に開いた status fd と、`setns` の後にコンテナの
/// rootfs と照合した `/` の fd（`root`）を渡して呼ぶ。ルールのパスは `root` を起点に辿る。
#[cfg_attr(test, allow(dead_code))]
pub(super) fn apply_landlock_stage_with(
    ruleset: &LandlockRuleset,
    threads: &mut ThreadCountSource,
    root: std::os::fd::BorrowedFd<'_>,
) -> Result<LandlockApplyReport, ExecError> {
    crate::landlock::apply_landlock_ruleset_with(ruleset, threads, Some(root))
        .map_err(from_landlock_apply)
}

/// `OciConfig` から Landlock ruleset を作る（ABI 検出 → ルール生成。CORE-5・TASK-39.4）。
///
/// fork 前に親で呼び、得た ruleset を `StagePipeline::with_landlock` へ渡す。
/// ABI 不足・生成失敗は `stage = Landlock` の `ExecError` になる（起動拒否。fail-closed）。
///
/// # ABI 6 未満の扱い（CORE-5・#1714・#1314 のオーナー判断 2026-10-10）
///
/// CORE-5 は Landlock ABI 6 以上でパス単位のアクセス制御が有効であることを期待しており、満たさない場合に
/// 縮退して続ける規定は無いので、起動を拒否する（fail-closed）と読む。拒否は段（`run_then`）の手前、fork の前に
/// 行い、コードは `FailedPrecondition`（段 `Landlock`、理由コード `landlock_abi_too_old` 等）。`PermissionDenied` は
/// exec 段での証跡欠落だけを表す。ruleset は検出済みの ABI からしか作れないため、ABI 不足では `with_landlock` も
/// `LaunchReady` も得られない。本番 launcher（`ProductionLauncher`。#1816）はこのエラーをそのまま返して起動を拒否し、Landlock 無しで
/// 続けてはならない。
///
/// # 将来仕様（記録のみ）
///
/// 本番 launcher（`oci_runtime::ProductionLauncher`）が fork 前の親（`Threads: 1`）から呼ぶ（#1816）。
pub(crate) fn landlock_ruleset_from_config(
    config: &OciConfig,
) -> Result<LandlockRuleset, ExecError> {
    ruleset_from_detection(detect_landlock_abi(), config)
}

/// 記録した launch 時の Landlock ルールから ruleset を組み直す（exec の再適用用。CORE-5・SUP-6・TASK-163 追補・
/// #1468）。`config.json` は launch の後に変わりうるため読まない。
///
/// ABI 検出は launch と同じ fail-closed（ABI 6 未満・未対応は拒否）。ルールと handled は **記録のまま** 使い、
/// 今のカーネルの ABI から計算し直さない。記録の handled が今のカーネルの扱える権利を超えるときは、launch
/// より弱いルールに縮退せず `FailedPrecondition`（段 `Landlock`）で拒否する。
pub(crate) fn landlock_ruleset_from_record(
    record: &LaunchIsolationRecord,
) -> Result<LandlockRuleset, ExecError> {
    ruleset_from_recorded_detection(detect_landlock_abi(), record)
}

/// [`landlock_ruleset_from_record`] の ABI 検出結果を差し替えられる版（試験用の継ぎ目）。
fn ruleset_from_recorded_detection(
    detected: Result<LandlockSupport, LandlockError>,
    record: &LaunchIsolationRecord,
) -> Result<LandlockRuleset, ExecError> {
    let support = detected.map_err(from_landlock_unavailable)?;
    let ruleset = record
        .landlock_ruleset()
        .map_err(|e| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, e.message()))?;
    if !ruleset
        .handled_access_fs()
        .is_subset_of(handled_for_abi(support.abi.get()))
    {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Landlock,
            "recorded landlock access exceeds what the kernel supports",
        ));
    }
    Ok(ruleset)
}

/// launch が bundle の rootfs を自分自身へ bind して pivot する構成で、`state.json` へ残す分離の記録を作る
/// （SUP-6・CORE-5・TASK-163 追補・#1468。トレイト契約 12）。
///
/// ルールは `landlock_ruleset_from_config` と同じ関数で `config` から導く（launch が
/// `StagePipeline::with_landlock` へ渡す ruleset と同一の入力・同一の関数で作ること）。`/` の識別子は固定した
/// `rootfs`（`pin_bundle_rootfs`）の `st_dev`・`st_ino`。bind mount は元の inode と `st_dev` を保つため、launch の
/// pivot 後の `/` と一致する。overlay など rootfs を mount namespace の中で組み立てる launcher は本関数ではなく、
/// 子の pivot 後の `/` から [`RootIdentity`] を得て `LaunchIsolationRecord::new` を使う。
///
/// 将来仕様: 本番 launcher からの結線（作った記録を `CreateStateRequest::with_launch_isolation` で書く）は
/// 後続作業（REPAIR-3）。
pub fn launch_isolation_from_bundle(
    config: &OciConfig,
    rootfs: &RootfsDir,
) -> Result<LaunchIsolationRecord, ExecError> {
    let ruleset = landlock_ruleset_from_config(config)?;
    let root = RootIdentity::of_dir_fd(rootfs.as_fd()).ok_or_else(|| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Validate,
            "failed to inspect the rootfs",
        )
    })?;
    LaunchIsolationRecord::new(root, &ruleset)
        .map_err(|e| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, e.message()))
}

/// [`landlock_ruleset_from_config`] の ABI 検出結果を差し替えられる版（試験用の継ぎ目。本番は
/// `detect_landlock_abi()` の結果を渡すだけ）。
pub(crate) fn ruleset_from_detection(
    detected: Result<LandlockSupport, LandlockError>,
    config: &OciConfig,
) -> Result<LandlockRuleset, ExecError> {
    let support = detected.map_err(from_landlock_unavailable)?;
    path_rules_from_config(&support, config).map_err(from_landlock_rule)
}

/// [`observe_landlock_path_access`] が 1 件ずつ試す操作の種別（CORE-5・TASK-39.5・#185）。
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandlockAccessKind {
    /// 既存ファイルの読み取り（成功時は内容も取得する）。
    ReadFile,
    /// ディレクトリの列挙。
    ReadDir,
    /// 既存ファイルを書き込み専用で開く。
    WriteExisting,
    /// 既存ファイルを `O_TRUNC` 付きで開く。
    TruncateOpen,
    /// 新規ファイルの作成。
    CreateFile,
    /// ディレクトリの作成。
    MakeDir,
    /// ファイルの削除。
    RemoveFile,
    /// 文字デバイス（1:3。`/dev/null` と同じ番号）の作成（`mknodat(2)`。親ディレクトリを開いてから最終要素を
    /// 作る）。rootful では `CAP_MKNOD` があり、`/dev` の tmpfs には `nodev` が無いため、拒否するのは Landlock の
    /// `MAKE_CHAR` 不許可だけで、それを通しで確かめるのに使う（#1672 事後監査 P2・CORE-5・SEC-1）。
    MakeCharDevice,
    /// 既存のファイルを読み書きで `O_NOCTTY` 付きで開く（`/dev/ptmx` を制御端末にせずに開けることの確認。
    /// #1672 事後監査 P2）。
    OpenNoCtty,
}

/// 1 件の観測対象（種別とパス）。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockAccessProbe {
    /// 試す操作。
    pub kind: LandlockAccessKind,
    /// 操作対象のパス（呼び出し側が canonicalize 済みで用意する）。
    pub path: PathBuf,
    /// `ReadFile` で読めるはずの内容。`None` なら内容は検査しない（他の種別では無視）。
    /// 不一致は [`LANDLOCK_PROBE_CONTENT_MISMATCH`] で報告する。
    pub expected_content: Option<Vec<u8>>,
}

/// `ReadFile` の内容が `expected_content` と一致しなかったことを示す結果値。
/// errno（正の値）・errno 不明の I/O 失敗（`-1`）のいずれとも衝突しない。
#[doc(hidden)]
pub const LANDLOCK_PROBE_CONTENT_MISMATCH: i32 = -2;

/// [`observe_landlock_path_access`] の観測結果。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockAccessObservation {
    /// 適用前に `NO_NEW_PRIVS` が立っていたか。
    pub no_new_privs_before: bool,
    /// ruleset 生成（ABI 検出・ルール生成）の失敗。`Some` なら適用もプローブもしていない（fail-closed）。
    pub ruleset_error: Option<ExecError>,
    /// 適用の失敗。`Some` ならプローブはしていない（起動拒否に相当）。
    pub apply_error: Option<ExecError>,
    /// 適用に成功したか。
    pub applied: bool,
    /// プローブ結果（入力順）。`None` は成功、`Some(errno)` は失敗（errno 不明は `-1`）。
    pub results: Vec<(LandlockAccessProbe, Option<i32>)>,
    /// `EACCES` になった試行ごとの監査レコード（入力順。SEC-4・TASK-41.3・#194）。適用に成功した場合のみ入る。
    /// `EACCES` は DAC 由来でも返るため Landlock 由来の確定証拠ではない（帰属は #840）。
    pub audit_records: Vec<AuditRecord>,
    /// 監査レコード構築（PID・時刻取得）の失敗。黙殺せず表面化する（最初の 1 件を保持）。
    pub audit_error: Option<AuditRecordError>,
}

/// 観測 1 回で試せるプローブ数の上限（呼び出し側が固定リストで渡す前提の防御）。
const MAX_ACCESS_PROBES: usize = 32;

/// 本番のステージ関数経由で Landlock を適用し、許可パス・許可外パスへの操作結果を観測する
/// （CORE-5・TASK-39.5・#185）。
///
/// 結合試験 `tests/landlock.rs` の使い捨て子プロセス専用。適用は不可逆で呼び出しスレッドにしか
/// 効かない単一スレッド前提のため、通常の利用者は呼ばない。`landlock_ruleset_from_config`
/// （ABI 検出 → ルール生成）→ `apply_landlock_stage` の本番経路をそのまま通し、ruleset 生成・適用の
/// いずれかが失敗したらプローブは実行しない（fail-closed の観測）。`unsafe` は追加せず、
/// syscall は既存の `crate::sys` ラッパーに限る。
///
/// 適用後に `EACCES` となった試行は `crate::audit_log::landlock_denial_record_now` で監査レコード化し
/// `audit_records` に入れる（SEC-4・TASK-41.3・#194）。ワークロードプロセスの拒否の捕捉は #840。
///
/// # 将来仕様（記録のみ）
///
/// exec 許可（制限適用の証跡配線）が入った後は、コンテナのエントリポイント内プローブで検証する
/// 形へ移す（REPAIR-3）。
#[doc(hidden)]
pub fn observe_landlock_path_access(
    config: &OciConfig,
    probes: &[LandlockAccessProbe],
) -> Result<LandlockAccessObservation, ExecError> {
    if probes.len() > MAX_ACCESS_PROBES {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Landlock,
            "too many access probes",
        ));
    }
    let internal = |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, m);
    sys::set_no_new_privs().map_err(|_| internal("failed to set no_new_privs"))?;
    let no_new_privs_before = sys::no_new_privs_enabled().unwrap_or(false);
    let mut obs = LandlockAccessObservation {
        no_new_privs_before,
        ruleset_error: None,
        apply_error: None,
        applied: false,
        results: Vec::new(),
        audit_records: Vec::new(),
        audit_error: None,
    };
    let ruleset = match landlock_ruleset_from_config(config) {
        Ok(r) => r,
        Err(e) => {
            obs.ruleset_error = Some(e);
            return Ok(obs);
        }
    };
    if let Err(e) = apply_landlock_stage(&ruleset) {
        obs.apply_error = Some(e);
        return Ok(obs);
    }
    obs.applied = true;
    for p in probes {
        let r = run_probe(p);
        // 拒否試行は SEC-4 の監査レコードにする（TASK-41.3）。件数はプローブ上限で抑えられる。
        match landlock_denial_record_now(&p.path, r) {
            Ok(Some(rec)) => obs.audit_records.push(rec),
            Ok(None) => {}
            Err(e) => {
                obs.audit_error.get_or_insert(e);
            }
        }
        obs.results.push((p.clone(), r));
    }
    Ok(obs)
}

/// プローブ 1 件を実行し、成功は `None`・失敗は `Some(errno)` で返す。
/// errno が無い I/O 失敗は `-1`、内容不一致は [`LANDLOCK_PROBE_CONTENT_MISMATCH`]。
pub(super) fn run_probe(p: &LandlockAccessProbe) -> Option<i32> {
    use std::fs::OpenOptions;
    let res: std::io::Result<()> = match p.kind {
        LandlockAccessKind::ReadFile => match std::fs::read(&p.path) {
            Ok(b) => match &p.expected_content {
                Some(want) if *want != b => return Some(LANDLOCK_PROBE_CONTENT_MISMATCH),
                _ => Ok(()),
            },
            Err(e) => Err(e),
        },
        LandlockAccessKind::ReadDir => std::fs::read_dir(&p.path).map(|_| ()),
        LandlockAccessKind::WriteExisting => {
            OpenOptions::new().write(true).open(&p.path).map(|_| ())
        }
        LandlockAccessKind::TruncateOpen => OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&p.path)
            .map(|_| ()),
        LandlockAccessKind::CreateFile => OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p.path)
            .map(|_| ()),
        LandlockAccessKind::MakeDir => std::fs::create_dir(&p.path),
        LandlockAccessKind::RemoveFile => std::fs::remove_file(&p.path),
        LandlockAccessKind::MakeCharDevice => return make_char_device_probe(&p.path),
        LandlockAccessKind::OpenNoCtty => {
            use std::os::unix::fs::OpenOptionsExt as _;
            let Some(noctty) = sys::noctty_open_flag() else {
                return Some(-1);
            };
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(noctty)
                .open(&p.path)
                .map(|_| ())
        }
    };
    res.err().map(|e| e.raw_os_error().unwrap_or(-1))
}

/// [`LandlockAccessKind::MakeCharDevice`] の本体。1:3 の文字デバイス（モード 0666）を `path` に作る
/// （`device_probe::make_char_device_errno` の 1:3 固定の呼び出し）。成功は `None`、失敗は `Some(errno)`。
fn make_char_device_probe(path: &std::path::Path) -> Option<i32> {
    super::device_probe::make_char_device_errno(path, 1, 3)
}

fn from_landlock_apply(e: LandlockApplyError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.kind.as_str(), e.message),
    )
}

fn from_landlock_unavailable(e: LandlockError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.reason.as_str(), e.message),
    )
}

fn from_landlock_rule(e: LandlockRuleError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.kind.as_str(), e.message),
    )
}

/// `stages.rs` が `cfg(test)` で差し替える偽物（`seccomp::testing` と同型）。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::Cell;

    use super::{ExecError, LandlockApplyReport, LandlockRuleset, ThreadCountSource};

    thread_local! {
        static LANDLOCK_ERR: Cell<Option<ExecError>> = const { Cell::new(None) };
    }

    /// 次の 1 回だけ、`apply_landlock_stage` の偽物を失敗させる（使うと既定へ戻る）。
    pub(in crate::exec) fn fake_landlock_err(e: ExecError) {
        LANDLOCK_ERR.with(|c| c.set(Some(e)));
    }

    /// `stages.rs` の `with_landlock` が `cfg(test)` で呼ぶ偽物。
    pub(in crate::exec) fn apply_landlock_stage(
        ruleset: &LandlockRuleset,
    ) -> Result<LandlockApplyReport, ExecError> {
        crate::exec::no_new_privs::testing::rec("landlock");
        match LANDLOCK_ERR.with(Cell::take) {
            Some(e) => Err(e),
            None => Ok(LandlockApplyReport {
                rules_added: ruleset.rules().len(),
                file_rules: 0,
                skipped_empty: 0,
                implicit_mounts_verified: 0,
            }),
        }
    }

    /// `exec/reapply.rs` が `cfg(test)` で呼ぶ偽物（取得元・起点は読まない）。
    pub(in crate::exec) fn apply_landlock_stage_with(
        ruleset: &LandlockRuleset,
        _threads: &mut ThreadCountSource,
        _root: std::os::fd::BorrowedFd<'_>,
    ) -> Result<LandlockApplyReport, ExecError> {
        apply_landlock_stage(ruleset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::landlock::{LandlockApplyErrorKind, LandlockRuleErrorKind, LandlockUnavailable};
    use crate::traits::types::ErrorCode;

    /// CORE-5・#1714: ABI 6 未満は段に入る前（ruleset を作る前）に `FailedPrecondition` で起動を拒否し、
    /// 縮退して続けない。ABI 6 なら ruleset が作れる。
    #[test]
    fn core5_abi_below_min_refuses_before_stage() {
        let json = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#;
        let config = crate::oci_runtime::parse_config_bytes(json).expect("config");
        let e = ruleset_from_detection(crate::landlock::evaluate_abi(5), &config)
            .expect_err("abi 5 must be refused");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(
            e.message.starts_with("landlock_abi_too_old"),
            "{}",
            e.message
        );
        assert!(ruleset_from_detection(crate::landlock::evaluate_abi(6), &config).is_ok());
    }

    /// CORE-5・SUP-6・#1468: 記録から組み直す ruleset も ABI 6 未満は拒否し（縮退しない）、ABI 6 なら記録の
    /// handled とルールをそのまま返す（`config.json` を読まない）。
    #[test]
    fn core5_sup6_1468_recorded_ruleset_refuses_old_abi_and_keeps_record() {
        use crate::launch_isolation::{
            RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let landlock =
            RecordedLandlock::new(0x1FFF, vec![RecordedRule::new(RecordedTarget::Root, 0x5)])
                .expect("recorded landlock");
        let record = LaunchIsolationRecord::from_parts(RootIdentity::new(1, 2), landlock);
        let e = ruleset_from_recorded_detection(crate::landlock::evaluate_abi(5), &record)
            .expect_err("abi 5 must be refused");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(
            e.message.starts_with("landlock_abi_too_old"),
            "{}",
            e.message
        );
        let ok = ruleset_from_recorded_detection(crate::landlock::evaluate_abi(6), &record)
            .expect("abi 6");
        assert_eq!(ok.handled_access_fs().bits(), 0x1FFF);
        assert_eq!(ok.rules().len(), 1);
        assert_eq!(ok.rules()[0].allowed.bits(), 0x5);
    }

    /// OCI-4・CORE-5・SEC-1(#1915): Landlock の ruleset は、適用する bind と同じ `mounts[]` から導かれる。
    /// 各 bind の宛先・位置に `Mount` 由来のルールがあり、記録(`LaunchIsolationRecord`)にも同じ宛先で入り、
    /// 記録から組み直した ruleset(`exec/reapply.rs` の再適用の入力)も元とルールが一致する。
    #[test]
    fn oci4_core5_bind_mounts_and_landlock_rules_share_one_mounts_list() {
        use crate::landlock::{RuleOrigin, RulePath};
        use crate::launch_isolation::{RecordedTarget, RootIdentity};
        use crate::oci_runtime::BindMountSet;
        let json = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [
                {"destination": "/data", "type": "bind", "source": "/srv/data", "options": ["bind", "rw"]},
                {"destination": "/cache", "type": "bind", "source": "/srv/cache", "options": ["rbind", "noexec"]}
            ]
        });
        let config =
            crate::oci_runtime::parse_config_bytes(json.to_string().as_bytes()).expect("config");
        let binds = BindMountSet::from_mounts(config.mounts()).expect("binds");
        let ruleset =
            ruleset_from_detection(crate::landlock::evaluate_abi(6), &config).expect("ruleset");
        for b in binds.mounts() {
            let rule = ruleset
                .rules()
                .iter()
                .find(|r| r.origin == (RuleOrigin::Mount { index: b.index() }))
                .expect("a rule for every bind");
            assert_eq!(rule.path.as_str(), b.destination().as_str());
            assert!(matches!(rule.path, RulePath::Beneath(_)));
        }
        let record = LaunchIsolationRecord::new(RootIdentity::new(1, 2), &ruleset).expect("record");
        let recorded: Vec<(usize, String)> = record
            .landlock()
            .rules()
            .iter()
            .filter_map(|r| match r.target() {
                RecordedTarget::Mount { destination, index } => {
                    Some((*index, destination.as_str().to_owned()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            recorded,
            vec![(0, "/data".to_owned()), (1, "/cache".to_owned())]
        );
        let rebuilt = record.landlock_ruleset().expect("rebuilt");
        assert_eq!(rebuilt.rules(), ruleset.rules());
    }

    /// OCI-4・CORE-5(#1915): `ro` の bind は、root が書き込み可能な構成では Landlock が書き込み制限を
    /// 保証できず fork 前に拒否される(`WriteRestrictionShadowed`。#1917 の解消までの想定挙動)。
    #[test]
    fn core5_readonly_bind_is_refused_before_fork_until_1917() {
        let json = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [
                {"destination": "/data", "type": "bind", "source": "/srv/data", "options": ["bind", "ro"]}
            ]
        });
        let config =
            crate::oci_runtime::parse_config_bytes(json.to_string().as_bytes()).expect("config");
        let e = ruleset_from_detection(crate::landlock::evaluate_abi(6), &config)
            .expect_err("ro bind must be refused");
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(
            e.message.contains("write_restriction_shadowed"),
            "{}",
            e.message
        );
    }

    /// CORE-5・TASK-39.5: プローブ件数の上限超過は適用前に InvalidArgument で拒否する。
    #[test]
    fn core5_access_probe_limit_is_rejected_before_apply() {
        let json = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#;
        let config = crate::oci_runtime::parse_config_bytes(json).expect("config");
        let probes = vec![
            LandlockAccessProbe {
                kind: LandlockAccessKind::ReadDir,
                path: PathBuf::from("/"),
                expected_content: None,
            };
            MAX_ACCESS_PROBES + 1
        ];
        let e = observe_landlock_path_access(&config, &probes).expect_err("over limit");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert_eq!(e.message, "too many access probes");
    }

    /// CORE-5・SEC-1（#1672 事後監査 P2）: 追加した 2 種のプローブが、権限や環境に依らない入力で errno を
    /// 具体値で返す（親が無ければ `ENOENT`、既存の通常ファイルは `O_NOCTTY` で開ける）。Landlock の下での
    /// 拒否・許可は結合試験 `tests/landlock_implicit_dev.rs`（実機前提）が照合する。
    #[test]
    fn core5_sec1_mknod_and_noctty_probes_report_errno() {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-landlock-probe-kinds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("file");
        std::fs::write(&file, b"x").expect("file");
        let probe = |kind, path: PathBuf| LandlockAccessProbe {
            kind,
            path,
            expected_content: None,
        };
        let enoent = Some(sys::ENOENT);
        assert_eq!(
            run_probe(&probe(
                LandlockAccessKind::MakeCharDevice,
                dir.join("missing/node")
            )),
            enoent
        );
        assert_eq!(
            run_probe(&probe(
                LandlockAccessKind::MakeCharDevice,
                PathBuf::from("/")
            )),
            Some(-1)
        );
        assert_eq!(
            run_probe(&probe(LandlockAccessKind::OpenNoCtty, file.clone())),
            None
        );
        assert_eq!(
            run_probe(&probe(LandlockAccessKind::OpenNoCtty, dir.join("missing"))),
            enoent
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CORE-5・TASK-39.4: 適用失敗は code を保ち stage を Landlock にする。
    #[test]
    fn core5_apply_error_maps_to_landlock_stage() {
        let e = from_landlock_apply(LandlockApplyError {
            code: ErrorCode::FailedPrecondition,
            kind: LandlockApplyErrorKind::NoNewPrivsNotSet,
            message: "no_new_privs is not set".to_string(),
        });
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.violation.is_none());
        assert!(e.message.contains("no_new_privs_not_set"), "{}", e.message);
    }

    /// CORE-5・TASK-39.4: ABI 不足は FailedPrecondition・理由コード付き。
    #[test]
    fn core5_abi_too_old_maps_to_failed_precondition() {
        let err = LandlockError {
            code: ErrorCode::FailedPrecondition,
            reason: LandlockUnavailable::AbiTooOld {
                detected: 5,
                required: 6,
            },
            message: "too old".to_string(),
        };
        let e = from_landlock_unavailable(err);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.message.contains("landlock_abi_too_old"), "{}", e.message);
    }

    /// CORE-5・TASK-39.4: ルール生成失敗は InvalidArgument のまま Landlock 段へ。
    #[test]
    fn core5_rule_error_maps_to_invalid_argument() {
        let err = LandlockRuleError {
            code: ErrorCode::InvalidArgument,
            kind: LandlockRuleErrorKind::TooManyRules { count: 9, max: 8 },
            message: "too many".to_string(),
        };
        let e = from_landlock_rule(err);
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.message.starts_with("too_many_rules: "), "{}", e.message);
    }
}
