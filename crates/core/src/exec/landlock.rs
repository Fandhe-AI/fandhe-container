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
//! - 本番 launcher（`oci_runtime`）からの本関数の呼び出しは後続

use std::path::PathBuf;

use super::{ExecError, IsolationStage, ThreadCountSource};
use crate::audit_log::{AuditRecord, AuditRecordError, landlock_denial_record_now};
use crate::landlock::{
    LandlockApplyError, LandlockApplyReport, LandlockError, LandlockRuleError, LandlockRuleset,
    LandlockSupport, detect_landlock_abi, path_rules_from_config,
};
use crate::oci_runtime::OciConfig;
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
/// `LaunchReady` も得られない。本番 launcher（#1715）はこのエラーをそのまま返して起動を拒否し、Landlock 無しで
/// 続けてはならない。
///
/// # 将来仕様（記録のみ）
///
/// 本番 launcher（`oci_runtime`）からの呼び出しは後続作業（#1715。REPAIR-3）。
pub(crate) fn landlock_ruleset_from_config(
    config: &OciConfig,
) -> Result<LandlockRuleset, ExecError> {
    ruleset_from_detection(detect_landlock_abi(), config)
}

/// [`landlock_ruleset_from_config`] の ABI 検出結果を差し替えられる版（試験用の継ぎ目。本番は
/// `detect_landlock_abi()` の結果を渡すだけ）。
fn ruleset_from_detection(
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

/// [`LandlockAccessKind::MakeCharDevice`] の本体。親ディレクトリを `O_PATH|O_NOFOLLOW|O_DIRECTORY` で開き、
/// その fd 起点で最終要素に 1:3 の文字デバイス（モード 0666）を作る。成功は `None`、失敗は `Some(errno)`
/// （親・名前が取れない・NUL を含む・対応外アーキテクチャは `-1`）。`O_NOFOLLOW` が効くのは親の最終要素だけで、
/// 親までの中間要素の symlink は辿る（結合試験が固定のリストで渡すパス専用で、外部入力は受けない）。
fn make_char_device_probe(path: &std::path::Path) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt as _;
    let errno = |e: sys::SysError| match e {
        sys::SysError::Os(e) => e,
        _ => -1,
    };
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Some(-1);
    };
    let (Ok(parent), Ok(name)) = (
        std::ffi::CString::new(parent.as_os_str().as_bytes()),
        std::ffi::CString::new(name.as_bytes()),
    ) else {
        return Some(-1);
    };
    let dir = match sys::open_dir_path_nofollow(None, &parent) {
        Ok(fd) => fd,
        Err(e) => return Some(errno(e)),
    };
    sys::make_char_device(std::os::fd::AsFd::as_fd(&dir), &name, 0o666, 1, 3)
        .err()
        .map(errno)
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
