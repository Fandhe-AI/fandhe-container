//! rlimit 適用の組み込みステージ（SUP-12・TASK-169.1・#526・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs` の `StagePipeline`）の第 2 段。`StagePipeline::run_then` が
//! cgroup 参加の後・capability 削減の前に、`StagePipeline::with_rlimits` で渡された
//! [`Rlimits`] を [`apply_rlimits`] で適用する。他の段と違い `StageHook` では差し替えられない
//! 組み込み処理で、集合が未設定・空のときは syscall を呼ばず `Skipped` のままにする。
//!
//! # 順序の根拠
//!
//! - capability 削減より前: OCI 既定の capability マスクに `CAP_SYS_RESOURCE` は含まれず、
//!   削減後は hard limit の引き上げが常に `EPERM` になる
//! - seccomp より前: 既定 allowlist（CORE-5）に `prlimit64` を足さずに済む
//!
//! # 契約（fail-closed）
//!
//! - 各 rlimit を `prlimit(2)` で設定した直後に読み戻し、soft / hard が指定値と一致することを
//!   確認する。不一致は `Internal`。**黙ってクランプしない**
//! - 最初の失敗で打ち切り、後続の種別・後続段・exec に進ませない
//! - rootless（user namespace 内）では hard の引き下げと範囲内の soft 変更は成功し、継承値を超える
//!   hard の引き上げは `EPERM`（`PermissionDenied`）で起動拒否になる
//! - `RLIMIT_NOFILE` 等を極端に下げると後続段（Landlock のパス open・exec）が失敗して起動拒否に
//!   なり得る。これも fail-closed の範囲内の挙動
//! - **制限適用の証跡にはしない**（REPAIR-3）。`process.rs::require_restriction_evidence` は本ステージの
//!   成否によらず従来どおり判定する
//!
//! `cfg(test)` では本物の `prlimit` を呼ばず thread_local の偽物に差し替える（テストプロセス自身の
//! 制限を変えないため。本物の syscall は `sys.rs` のテストで別プロセスに対して確認する）。

use super::{ExecError, IsolationStage};
use crate::rlimits::{RLIMIT_INFINITY, Rlimit, RlimitKind, Rlimits};
use crate::traits::types::ErrorCode;

#[cfg(not(test))]
use crate::sys::{get_rlimit_self, set_rlimit_self};
#[cfg(test)]
use testing::{get_rlimit_self, set_rlimit_self};

/// 集合の各 rlimit を設定し、読み戻して指定値との一致を確認する。
pub(super) fn apply_rlimits(set: &Rlimits) -> Result<(), ExecError> {
    let stage = IsolationStage::Rlimits;
    for r in set.iter() {
        let what = format!("prlimit({})", r.kind().as_oci_name());
        set_rlimit_self(r.kind(), r.soft(), r.hard())
            .map_err(|e| ExecError::from_sys(e, stage, &what))?;
        let (soft, hard) =
            get_rlimit_self(r.kind()).map_err(|e| ExecError::from_sys(e, stage, &what))?;
        if (soft, hard) != (r.soft(), r.hard()) {
            return Err(ExecError::new(
                ErrorCode::Internal,
                stage,
                format!("{what} did not take effect"),
            ));
        }
    }
    Ok(())
}

/// `/proc/<pid>/limits` の行頭ラベルと rlimit 種別の対応（カーネルの `lnx_rlimit` 表の文言。
/// どのラベルも他のラベルの前置にならない）。
const LIMITS_LABELS: [(&str, RlimitKind); 16] = [
    ("Max cpu time", RlimitKind::Cpu),
    ("Max file size", RlimitKind::Fsize),
    ("Max data size", RlimitKind::Data),
    ("Max stack size", RlimitKind::Stack),
    ("Max core file size", RlimitKind::Core),
    ("Max resident set", RlimitKind::Rss),
    ("Max processes", RlimitKind::Nproc),
    ("Max open files", RlimitKind::Nofile),
    ("Max locked memory", RlimitKind::Memlock),
    ("Max address space", RlimitKind::As),
    ("Max file locks", RlimitKind::Locks),
    ("Max pending signals", RlimitKind::Sigpending),
    ("Max msgqueue size", RlimitKind::Msgqueue),
    ("Max nice priority", RlimitKind::Nice),
    ("Max realtime priority", RlimitKind::Rtprio),
    ("Max realtime timeout", RlimitKind::Rttime),
];

/// 対象（pid1）の `/proc/<pid>/limits` の内容から、全 16 種の rlimit 集合を作る（SUP-6・SUP-12・TASK-163.4）。
///
/// exec プロセスへ「コンテナと同じ rlimit」を載せるための材料。`StagePipeline::with_rlimits` が受ける launch の
/// 集合は `state.json` に記録されないため、実行中の pid1 の実効値を読む。外部入力として扱い、全 16 種が
/// ちょうど 1 回ずつ現れること・値が `unlimited` か u64 であること・`soft <= hard` を要求し、満たさなければ
/// 空集合へ落とさず `Internal` で拒否する（fail-closed。緩い制限のまま exec しない）。未知のラベルの行と
/// 見出し行は無視する。値は単位の換算を要さない raw の値（`RLIMIT_*` と同じ単位）。
pub(super) fn parse_proc_limits(text: &str) -> Result<Rlimits, ExecError> {
    let stage = IsolationStage::Rlimits;
    let bad = |what: &'static str| ExecError::new(ErrorCode::Internal, stage, what);
    let mut found: Vec<Rlimit> = Vec::with_capacity(LIMITS_LABELS.len());
    for line in text.lines() {
        let Some((label, kind)) = LIMITS_LABELS
            .iter()
            .find(|(label, _)| line.strip_prefix(label).is_some_and(starts_with_blank))
        else {
            continue;
        };
        let rest = line.get(label.len()..).unwrap_or_default();
        let mut cols = rest.split_whitespace();
        let (Some(soft), Some(hard)) = (cols.next(), cols.next()) else {
            return Err(bad("malformed target limits line"));
        };
        let value = |v: &str| -> Result<u64, ExecError> {
            if v == "unlimited" {
                Ok(RLIMIT_INFINITY)
            } else {
                v.parse::<u64>()
                    .map_err(|_| bad("malformed target limits value"))
            }
        };
        let limit = Rlimit::new(*kind, value(soft)?, value(hard)?)
            .map_err(|_| bad("target limits soft exceeds hard"))?;
        if found.iter().any(|r| r.kind() == *kind) {
            return Err(bad("duplicate target limits line"));
        }
        found.push(limit);
    }
    if found.len() != LIMITS_LABELS.len() {
        return Err(bad("target limits are incomplete"));
    }
    Rlimits::new(found).map_err(|_| bad("invalid target limits"))
}

/// ラベルの直後が空白（列の区切り）であること。`Max file size` が `Max file sizes` に一致しないようにする。
fn starts_with_blank(rest: &str) -> bool {
    rest.starts_with(' ') || rest.starts_with('\t')
}

/// テスト用の偽 syscall。呼び出し記録は `no_new_privs::testing` の記録器と共有する。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::{Cell, RefCell};

    use crate::rlimits::RlimitKind;
    use crate::sys::SysError;

    thread_local! {
        static SET_RESULT: Cell<Result<(), SysError>> = const { Cell::new(Ok(())) };
        static LAST: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
        static GET_OVERRIDE: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
        static SETS: RefCell<Vec<(RlimitKind, u64, u64)>> = const { RefCell::new(Vec::new()) };
    }

    /// 設定の記録を取り出し、偽物を既定（成功・読み戻しは直前の設定値）へ戻す。
    pub(in crate::exec) fn take_sets() -> Vec<(RlimitKind, u64, u64)> {
        SET_RESULT.with(|c| c.set(Ok(())));
        GET_OVERRIDE.with(|c| c.set(None));
        SETS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    /// 設定の結果と、読み戻しの上書き値を指定する。
    pub(in crate::exec) fn fake(set: Result<(), SysError>, get: Option<(u64, u64)>) {
        SET_RESULT.with(|c| c.set(set));
        GET_OVERRIDE.with(|c| c.set(get));
    }

    pub(super) fn set_rlimit_self(kind: RlimitKind, soft: u64, hard: u64) -> Result<(), SysError> {
        super::super::no_new_privs::testing::rec("rlimits");
        SETS.with(|c| c.borrow_mut().push((kind, soft, hard)));
        let r = SET_RESULT.with(Cell::get);
        if r.is_ok() {
            LAST.with(|c| c.set((soft, hard)));
        }
        r
    }

    pub(super) fn get_rlimit_self(_kind: RlimitKind) -> Result<(u64, u64), SysError> {
        Ok(GET_OVERRIDE
            .with(Cell::get)
            .unwrap_or_else(|| LAST.with(Cell::get)))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{fake, take_sets};
    use super::*;
    use crate::exec::no_new_privs::testing::take;
    use crate::rlimits::{Rlimit, RlimitKind};
    use crate::sys::{self, SysError};

    fn set_of(items: &[(RlimitKind, u64, u64)]) -> Rlimits {
        Rlimits::new(
            items
                .iter()
                .map(|&(k, s, h)| Rlimit::new(k, s, h).unwrap())
                .collect(),
        )
        .unwrap()
    }

    /// SUP-12・TASK-169.1: 種別ごとに 1 回ずつ、指定順・指定値で設定される。
    #[test]
    fn sup12_apply_rlimits_sets_each_kind_once_in_order() {
        take();
        take_sets();
        let set = set_of(&[(RlimitKind::Nofile, 256, 512), (RlimitKind::Core, 0, 0)]);
        apply_rlimits(&set).unwrap();
        assert_eq!(
            take_sets(),
            [(RlimitKind::Nofile, 256, 512), (RlimitKind::Core, 0, 0)]
        );
        assert_eq!(take(), ["rlimits", "rlimits"]);
    }

    /// SUP-12・TASK-169.1: errno の写像（EPERM → PermissionDenied、EINVAL → FailedPrecondition、
    /// Unsupported → Unimplemented）と、段が Rlimits であること。
    #[test]
    fn sup12_apply_rlimits_maps_errors() {
        let set = set_of(&[(RlimitKind::Nofile, 1, 2)]);
        for (err, code) in [
            (SysError::Os(sys::EPERM), ErrorCode::PermissionDenied),
            (SysError::Os(sys::EINVAL), ErrorCode::FailedPrecondition),
            (SysError::Unsupported, ErrorCode::Unimplemented),
        ] {
            take();
            take_sets();
            fake(Err(err), None);
            let e = apply_rlimits(&set).unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.stage, IsolationStage::Rlimits);
            assert_eq!(e.violation, None);
        }
        take();
        take_sets();
    }

    /// SUP-12・TASK-169.1: 読み戻しが指定値と違えば Internal（黙ってクランプしない）。
    #[test]
    fn sup12_apply_rlimits_fails_on_readback_mismatch() {
        take();
        take_sets();
        fake(Ok(()), Some((100, 512)));
        let e = apply_rlimits(&set_of(&[(RlimitKind::Nofile, 256, 512)])).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Rlimits);
        take();
        take_sets();
    }

    /// SUP-12・TASK-169.1: 途中の失敗で後続の種別を呼ばない。
    #[test]
    fn sup12_apply_rlimits_stops_at_first_failure() {
        take();
        take_sets();
        fake(Err(SysError::Os(sys::EPERM)), None);
        let set = set_of(&[(RlimitKind::Nofile, 1, 2), (RlimitKind::Core, 0, 0)]);
        assert!(apply_rlimits(&set).is_err());
        assert_eq!(take_sets(), [(RlimitKind::Nofile, 1, 2)]);
        take();
    }

    /// 実カーネルと同じ書式の `/proc/<pid>/limits`（Nice / Rtprio は単位列が空）。
    const LIMITS_FIXTURE: &str = "\
Limit                     Soft Limit           Hard Limit           Units     \n\
Max cpu time              unlimited            unlimited            seconds   \n\
Max file size             unlimited            unlimited            bytes     \n\
Max data size             unlimited            unlimited            bytes     \n\
Max stack size            8388608              unlimited            bytes     \n\
Max core file size        0                    unlimited            bytes     \n\
Max resident set          unlimited            unlimited            bytes     \n\
Max processes             102024               102024               processes \n\
Max open files            1024                 524288               files     \n\
Max locked memory         8388608              8388608              bytes     \n\
Max address space         unlimited            unlimited            bytes     \n\
Max file locks            unlimited            unlimited            locks     \n\
Max pending signals       102024               102024               signals   \n\
Max msgqueue size         819200               819200               bytes     \n\
Max nice priority         0                    0                    \n\
Max realtime priority     0                    0                    \n\
Max realtime timeout      unlimited            unlimited            us\n";

    /// SUP-6・SUP-12・TASK-163.4: 実書式の全 16 行を具体値で読める（`unlimited` は `u64::MAX`）。
    #[test]
    fn sup6_task163_4_parse_proc_limits_reads_all_sixteen_kinds() {
        let set = parse_proc_limits(LIMITS_FIXTURE).expect("parse");
        assert_eq!(set.len(), 16);
        let get = |k: RlimitKind| {
            let r = set.iter().find(|r| r.kind() == k).expect("kind present");
            (r.soft(), r.hard())
        };
        assert_eq!(get(RlimitKind::Cpu), (u64::MAX, u64::MAX));
        assert_eq!(get(RlimitKind::Stack), (8_388_608, u64::MAX));
        assert_eq!(get(RlimitKind::Core), (0, u64::MAX));
        assert_eq!(get(RlimitKind::Nofile), (1024, 524_288));
        assert_eq!(get(RlimitKind::Nproc), (102_024, 102_024));
        assert_eq!(get(RlimitKind::Nice), (0, 0));
        assert_eq!(get(RlimitKind::Rttime), (u64::MAX, u64::MAX));
    }

    /// SUP-6・TASK-163.4: 欠落・重複・不正値・soft > hard・途中で切れた行は、空集合へ落とさず `Internal` で拒否する。
    #[test]
    fn sup6_task163_4_parse_proc_limits_rejects_malformed_input() {
        let without = |label: &str| {
            LIMITS_FIXTURE
                .lines()
                .filter(|l| !l.starts_with(label))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let cases: [(String, &str); 6] = [
            (String::new(), "target limits are incomplete"),
            (without("Max open files"), "target limits are incomplete"),
            (
                format!("{LIMITS_FIXTURE}Max open files 1 2 files\n"),
                "duplicate target limits line",
            ),
            (
                LIMITS_FIXTURE.replace(
                    "102024               102024               processes",
                    "abc 5 processes",
                ),
                "malformed target limits value",
            ),
            (
                LIMITS_FIXTURE.replace(
                    "1024                 524288 ",
                    "9999999              524288 ",
                ),
                "target limits soft exceeds hard",
            ),
            (
                LIMITS_FIXTURE.replace(
                    "Max open files            1024                 524288               files",
                    "Max open files            1024",
                ),
                "malformed target limits line",
            ),
        ];
        for (text, message) in cases {
            let e = parse_proc_limits(&text).expect_err(message);
            assert_eq!(e.code, ErrorCode::Internal, "{message}");
            assert_eq!(e.stage, IsolationStage::Rlimits, "{message}");
            assert_eq!(e.message, message);
        }
    }

    /// SUP-6・TASK-163.4: ラベルは列の区切りまで一致を要する（`Max file sizes` を `Max file size` と取り違えない）。
    #[test]
    fn sup6_task163_4_parse_proc_limits_ignores_unknown_labels() {
        let text = format!("{LIMITS_FIXTURE}Max file sizes 1 2 bytes\nMax future thing 1 2 x\n");
        assert_eq!(parse_proc_limits(&text).expect("parse").len(), 16);
    }

    /// SUP-6・TASK-163.4: 実プロセスの `/proc/self/limits` を読める（書式の前提が本物のカーネルで成り立つ）。
    #[test]
    fn sup6_task163_4_parse_proc_limits_reads_real_self_limits() {
        let text = std::fs::read_to_string("/proc/self/limits").expect("read limits");
        assert_eq!(parse_proc_limits(&text).expect("parse real").len(), 16);
    }
}
