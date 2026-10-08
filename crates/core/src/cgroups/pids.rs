//! コンテナ用子 cgroup の `pids.max`（プロセス数上限）の検証・書き込み・読み戻し（SUP-13・TASK-170.2・MS-9・#533）。
//!
//! # 役割
//! 親モジュール [`super`]（委譲 cgroup 検出・子 cgroup 作成。TASK-32.1）が作った
//! [`ContainerCgroup`] に対し、`pids.max` へ `max` または 10 進数を書く。値は [`PidsMax`]
//! （検証済みの型）でしか表現できないため、範囲外の値はカーネルへ渡らない。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー（`--pids-limit` 相当の受け付けと launcher への結線は TASK-170.3・
//!   TASK-29 / TASK-157 系の担当）。本モジュールは単体の API で、起動フローからはまだ呼ばれない
//! - 前提: 親 cgroup の `cgroup.subtree_control` で `pids` controller が有効化済み
//!   （[`super::DelegatedCgroup::enable_controllers`]）。未有効なら `pids.max` が存在せず `FailedPrecondition`
//! - 書き込み先は保持している O_PATH ディレクトリ fd 起点の `openat`（`O_NOFOLLOW`）で、
//!   パス文字列から cgroup を再解決しない（TOCTOU・symlink 対策。TASK-32.1 と同じ姿勢）
//! - 書き込み後に上限付きで読み戻し、要求値と一致しなければ `FailedPrecondition`（fail-closed）
//! - 読み戻した内容はカーネル応答（外部入力）として `unwrap` / 添字アクセスなしで解析する
//! - `unsafe` は持たない。待機を伴わないファイル I/O のみのためタイムアウトは設けない
//!
//! # `--pids-limit` の写像
//! [`PidsMax::from_pids_limit`]: `-1` は無制限（`max`）、`1..=`[`PIDS_MAX_LIMIT`] はその値、
//! `0` とその他の負数は `InvalidArgument`。Docker 流の「`0` = 無制限」の解釈は呼び出し側
//! （CLI / launcher）の責務で、本モジュールは曖昧な値を黙って無制限にしない。
//!
//! # 未実装（REPAIR-3）
//! OCI `linux.resources.pids` からの反映と launcher への結線（TASK-170.3・TASK-29 / TASK-157 系）。

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use super::{
    CgroupError, CgroupStep, ContainerCgroup, SMALL_FILE_LIMIT, cstring, io_error, read_iface,
    record_cgroup_op, sys_error,
};
use crate::observability::OpRecorder;
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// `pids.max` に設定できる上限。カーネルの `PID_MAX_LIMIT`（64bit では 4194304 = 2^22）。
///
/// カーネルソースでの再確認は未実施の既知値。実機結合試験で照合する。
pub const PIDS_MAX_LIMIT: u64 = 4_194_304;

/// 検証済みの `pids.max` 値。構築は検証付きコンストラクタのみ（不正値を表現できない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidsMax {
    /// `None` は無制限（`max`）。
    limit: Option<u64>,
}

fn invalid(message: String) -> CgroupError {
    CgroupError::new(ErrorCode::InvalidArgument, CgroupStep::SetPidsMax, message)
}

impl PidsMax {
    /// 無制限（`max`）。
    pub fn unlimited() -> Self {
        Self { limit: None }
    }

    /// `1..=`[`PIDS_MAX_LIMIT`] のプロセス数上限。範囲外は `InvalidArgument`（カーネルへは渡さない）。
    pub fn count(n: u64) -> Result<Self, CgroupError> {
        if !(1..=PIDS_MAX_LIMIT).contains(&n) {
            return Err(invalid(format!(
                "pids.max {n} is out of range [1, {PIDS_MAX_LIMIT}]"
            )));
        }
        Ok(Self { limit: Some(n) })
    }

    /// `--pids-limit` 互換の符号付き値。`-1` は無制限、`1..=`[`PIDS_MAX_LIMIT`] はその値、それ以外は `InvalidArgument`。
    pub fn from_pids_limit(limit: i64) -> Result<Self, CgroupError> {
        if limit == -1 {
            return Ok(Self::unlimited());
        }
        match u64::try_from(limit) {
            Ok(n) => Self::count(n),
            Err(_) => Err(invalid(format!("pids limit {limit} is negative"))),
        }
    }

    /// 上限値。無制限なら `None`。
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// カーネルへ書く形式（`max` または 10 進数）。
    fn to_file_content(self) -> String {
        match self.limit {
            None => "max".to_owned(),
            Some(n) => n.to_string(),
        }
    }

    /// 読み戻した `pids.max`（カーネル応答）の解析。形式不正・範囲外は `FailedPrecondition`。
    fn parse(text: &str) -> Result<Self, CgroupError> {
        let bad = |why: &str| {
            CgroupError::precondition(
                CgroupStep::SetPidsMax,
                format!("unexpected pids.max content ({why}): {:?}", text.trim_end()),
            )
        };
        let token = text.trim_end_matches('\n');
        if token == "max" {
            return Ok(Self::unlimited());
        }
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("expected `max` or a decimal number"));
        }
        let n = token.parse::<u64>().map_err(|_| bad("not a number"))?;
        Self::count(n).map_err(|e| bad(&e.message))
    }
}

impl ContainerCgroup {
    /// 子 cgroup の `pids.max` を書き込み、読み戻して検証した値を返す（SUP-13・TASK-170.2）。
    ///
    /// `pids` controller が親で有効化されていない場合は `FailedPrecondition`。
    ///
    /// open・write・読み戻し・事前検証のどこで失敗しても、成功・失敗の件数と所要時間を `recorder` へ
    /// 操作名 `cgroup.set_pids_max` で記録する（REPAIR-4。全終了経路。`set_io_weight` と同じ形）。
    pub fn set_pids_max(
        &self,
        recorder: &OpRecorder,
        limit: &PidsMax,
    ) -> Result<PidsMax, CgroupError> {
        write_pids_max_recorded(self.fd.as_fd(), recorder, limit)
    }
}

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const SET_PIDS_MAX_OP_NAME: &str = "cgroup.set_pids_max";

/// [`write_pids_max_at`] を計測つきで実行する（テスト可能な実体）。
fn write_pids_max_recorded(
    dir: BorrowedFd<'_>,
    recorder: &OpRecorder,
    limit: &PidsMax,
) -> Result<PidsMax, CgroupError> {
    record_cgroup_op(
        recorder,
        SET_PIDS_MAX_OP_NAME,
        CgroupStep::SetPidsMax,
        || write_pids_max_at(dir, limit),
    )
}

/// `dir` 直下の `pids.max` へ書き、読み戻して要求値との一致を確認する（テスト可能な実体）。
fn write_pids_max_at(dir: BorrowedFd<'_>, limit: &PidsMax) -> Result<PidsMax, CgroupError> {
    let step = CgroupStep::SetPidsMax;
    let name = cstring(step, "pids.max")?;
    let wfd = match sys::open_write_at(dir, &name) {
        Ok(fd) => fd,
        Err(SysError::Os(errno)) if errno == sys::ENOENT => {
            return Err(CgroupError::precondition(
                step,
                "pids.max not found: pids controller is not enabled in the parent cgroup.subtree_control",
            ));
        }
        Err(e) => return Err(sys_error(step, "open pids.max", e)),
    };
    File::from(wfd)
        .write_all(limit.to_file_content().as_bytes())
        .map_err(|e| io_error(step, "write pids.max", &e))?;
    let actual = PidsMax::parse(&read_iface(step, dir, "pids.max", SMALL_FILE_LIMIT)?)?;
    if actual != *limit {
        return Err(CgroupError::precondition(
            step,
            format!(
                "pids.max read back as {:?}, expected {:?}",
                actual.to_file_content(),
                limit.to_file_content()
            ),
        ));
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(r: Result<PidsMax, CgroupError>) {
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.step, CgroupStep::SetPidsMax);
    }

    /// SUP-13・TASK-170.2: 件数の境界値。
    #[test]
    fn sup13_task170_2_pids_count_bounds() {
        assert_invalid(PidsMax::count(0));
        assert_eq!(PidsMax::count(1).unwrap().limit(), Some(1));
        assert_eq!(PidsMax::count(4_194_304).unwrap().limit(), Some(4_194_304));
        assert_invalid(PidsMax::count(4_194_305));
        assert_eq!(PidsMax::unlimited().limit(), None);
    }

    /// SUP-13・TASK-170.2: `--pids-limit` 互換の符号付き値の写像。
    #[test]
    fn sup13_task170_2_from_pids_limit() {
        assert_eq!(PidsMax::from_pids_limit(-1).unwrap(), PidsMax::unlimited());
        assert_eq!(PidsMax::from_pids_limit(100).unwrap().limit(), Some(100));
        for v in [0, -2, i64::MIN, i64::MAX] {
            assert_invalid(PidsMax::from_pids_limit(v));
        }
    }

    /// SUP-13・TASK-170.2: カーネルへ書く形式の完全一致。
    #[test]
    fn sup13_task170_2_pids_serialize() {
        assert_eq!(PidsMax::unlimited().to_file_content(), "max");
        assert_eq!(PidsMax::count(100).unwrap().to_file_content(), "100");
    }

    /// SUP-13・TASK-170.2: 読み戻し内容の解析（正常系と異常系）。
    #[test]
    fn sup13_task170_2_pids_parse() {
        assert_eq!(PidsMax::parse("max\n").unwrap(), PidsMax::unlimited());
        assert_eq!(
            PidsMax::parse("100\n").unwrap(),
            PidsMax::count(100).unwrap()
        );
        for bad in [
            "", "\n", "abc", "-1", "100 1", "0", "4194305", "+5", "max max",
        ] {
            let e = PidsMax::parse(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(e.step, CgroupStep::SetPidsMax, "{bad:?}");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("fc-pidsmax-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// SUP-13・TASK-170 追補・REPAIR-4: `set_pids_max` が成功と失敗（pids.max 不在）を
    /// 操作名 `cgroup.set_pids_max` へ具体値で記録し、他 setter の名前は増えない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_pids_max_operations_are_recorded() {
        use crate::observability::OpName;
        let name = OpName::new(SET_PIDS_MAX_OP_NAME).unwrap();
        let rec = OpRecorder::new();
        let ok = scratch("rec-ok");
        std::fs::write(ok.join("pids.max"), b"").unwrap();
        let dir = File::open(&ok).unwrap();
        write_pids_max_recorded(dir.as_fd(), &rec, &PidsMax::count(100).unwrap()).unwrap();
        let ng = scratch("rec-ng");
        let dir2 = File::open(&ng).unwrap();
        write_pids_max_recorded(dir2.as_fd(), &rec, &PidsMax::count(100).unwrap()).unwrap_err();
        let stats = rec.snapshot_op(&name).expect("recorded");
        assert_eq!(stats.name().as_str(), "cgroup.set_pids_max");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
        assert!(
            rec.snapshot_op(&OpName::new("cgroup.set_io_weight").unwrap())
                .is_none()
        );
        std::fs::remove_dir_all(&ok).unwrap();
        std::fs::remove_dir_all(&ng).unwrap();
    }

    /// SUP-13・TASK-170.2: 通常ファイル上で書き込みと読み戻しが具体値で一致する（受け入れ条件の機械照合）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_pids_write_and_read_back() {
        let base = scratch("ok");
        std::fs::write(base.join("pids.max"), b"").unwrap();
        let dir = File::open(&base).unwrap();
        let want = PidsMax::count(100).unwrap();
        assert_eq!(write_pids_max_at(dir.as_fd(), &want), Ok(want));
        assert_eq!(
            std::fs::read_to_string(base.join("pids.max")).unwrap(),
            "100"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: `pids.max` が無い（controller 未有効）場合は `FailedPrecondition`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_pids_missing_file_is_failed_precondition() {
        let base = scratch("missing");
        let dir = File::open(&base).unwrap();
        let e = write_pids_max_at(dir.as_fd(), &PidsMax::count(100).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetPidsMax);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: 読み戻しが要求と食い違えば成功扱いにしない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_pids_read_back_mismatch_fails() {
        let base = scratch("mismatch");
        std::fs::write(base.join("pids.max"), b"99999999").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_pids_max_at(dir.as_fd(), &PidsMax::count(100).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: `pids.max` が symlink なら `O_NOFOLLOW` で拒否され、リンク先へは書かれない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_pids_symlink_is_rejected() {
        let base = scratch("symlink");
        std::fs::write(base.join("target"), b"untouched").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("pids.max")).unwrap();
        let dir = File::open(&base).unwrap();
        assert!(write_pids_max_at(dir.as_fd(), &PidsMax::count(100).unwrap()).is_err());
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "untouched"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
