//! 名前だけの `process.args[0]` を `PATH` で解決するための候補列の組み立てと選択（OCI-1・TASK-55 追補・#2314）。
//!
//! `process::Entrypoint::search_path` が候補列を fork 前に作り（外部入力の検証と上限確認はここ）、
//! pivot 後の子の `process::open_entrypoint` が [`select_candidate`] で 1 件を選ぶ。
//!
//! # 根拠（一次情報）
//!
//! - OCI runtime-spec v1.2.0 `config.md` の `process.args`: 先頭要素は `execvp` の *file* と同じ意味で使う。
//!   `/` を含まない名前は `PATH` で探す
//! - runc v1.2.0 `libcontainer/standard_init_linux.go`: pivot 後に `exec.LookPath(Args[0])` を呼び、見つからなければ
//!   起動を失敗させる。探索の `PATH` は `init_linux.go` が `os.Clearenv()` の後に `process.env` を順に `Setenv`
//!   した結果（同じ KEY は後勝ち）。`PATH` が無ければ既定値を補わず not found
//! - Go `os/exec.LookPath`: 候補ごとに「ディレクトリでなく、実行ビットがある」ものを採り、尽きたら `ErrNotFound`
//!
//! # runc との差（fail-closed 側の差）
//!
//! - 絶対パスでない `PATH` 要素（空・`.`・`bin` 等）は探索しない（Go は `ErrDot` で失敗する。ここでは cwd 相対の
//!   探索経路そのものを作らない）
//! - 実行可否は mode の `0111` で判定する（`eaccess(X_OK)` ではない）。他者にだけ実行ビットがある候補は
//!   `execveat` が `EACCES`（終了コード 126）になり得る
//! - `/` を含む相対パス（`./x`・`bin/app`）は対象外で、`Entrypoint::search_path` が `InvalidArgument` で拒否する
//!   （execvp では cwd 相対だが未対応。REPAIR-3）
//!
//! # 閉じ込め
//!
//! 探索（実ファイルの `openat`）は `pivot_root` 後の子でだけ行う。`/` は rootfs で旧 root は切り離し済みのため、
//! 絶対 symlink・`..` は rootfs の外へ出られない（SEC-1）。

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt as _;

use crate::oci_runtime::CONFIG_MAX_PATH_BYTES;
use crate::traits::types::ErrorCode;

use super::{ExecError, IsolationStage};

/// `PATH` の要素数の上限（確保前に検証する）。
pub(super) const PATH_SEARCH_MAX_DIRS: usize = 256;
/// 探索する名前の上限バイト数（`NAME_MAX`）。
pub(super) const PATH_SEARCH_MAX_NAME_BYTES: usize = 255;

/// 候補 1 件の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateKind {
    /// 通常ファイルで実行ビットがある（採用）。
    Executable,
    /// 通常ファイルだが実行ビットが無い。
    NotExecutable,
    /// 通常ファイルでない（ディレクトリ・デバイス等）。
    NotRegular,
}

fn invalid(msg: &str) -> ExecError {
    ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg)
}

/// 探索する名前が `/` と NUL を含まず、空でなく、上限内であることを確かめる。
pub(super) fn validate_name(name: &OsStr) -> Result<(), ExecError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(invalid("the entrypoint name must not be empty"));
    }
    if bytes.len() > PATH_SEARCH_MAX_NAME_BYTES {
        return Err(invalid("the entrypoint name is too long"));
    }
    if bytes.contains(&b'/') || bytes.contains(&0) {
        return Err(invalid(
            "the entrypoint name to search must not contain '/' or NUL",
        ));
    }
    Ok(())
}

/// `env`（`KEY=VALUE` 形式の列）の最後の `PATH=` から探索候補（`<dir>/<name>`）を作る。
///
/// 絶対パスでない要素は除く。使える要素が 1 件も無ければ `InvalidArgument`（構成の誤り）。
/// 要素数・候補長の上限は確保の前に確かめ、候補長を超えるものは飛ばす。
pub(super) fn candidates_from_env(
    name: &OsStr,
    env: &[CString],
) -> Result<Vec<CString>, ExecError> {
    validate_name(name)?;
    let path_value = env
        .iter()
        .rev()
        .find_map(|var| var.to_bytes().strip_prefix(b"PATH="))
        .ok_or_else(|| invalid("process.env has no PATH to search the entrypoint name in"))?;
    // 上限 + 1 件で打ち切って収集する（巨大な ':' 連続でも確保を上限内に抑える。外部入力の件数上限）。
    let dirs: Vec<&[u8]> = path_value
        .split(|b| *b == b':')
        .take(PATH_SEARCH_MAX_DIRS + 1)
        .collect();
    if dirs.len() > PATH_SEARCH_MAX_DIRS {
        return Err(invalid("PATH has too many elements"));
    }
    let mut out = Vec::new();
    for dir in dirs {
        if dir.first() != Some(&b'/') {
            continue;
        }
        if dir.len() + 1 + name.len() + 1 > CONFIG_MAX_PATH_BYTES {
            continue;
        }
        let mut cand = Vec::with_capacity(dir.len() + 1 + name.len());
        cand.extend_from_slice(dir);
        if !dir.ends_with(b"/") {
            cand.push(b'/');
        }
        cand.extend_from_slice(name.as_bytes());
        if let Ok(c) = CString::new(cand) {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(invalid(
            "PATH has no absolute element to search the entrypoint name in",
        ));
    }
    Ok(out)
}

/// 候補を先頭から `probe` で判定し、最初の [`CandidateKind::Executable`] の添字を返す。
///
/// `probe` が `None` を返す候補（不在・`ENOTDIR`・`ELOOP`・`EACCES` 等）は次へ進む。尽きたら
/// `NotFound`（段 `Exec`。終了コード 127）。実 fd に依らず順序と終端を単体で照合するための継ぎ目。
pub(super) fn select_candidate<F>(candidates: &[CString], mut probe: F) -> Result<usize, ExecError>
where
    F: FnMut(&CStr) -> Option<CandidateKind>,
{
    for (i, cand) in candidates.iter().enumerate() {
        if probe(cand) == Some(CandidateKind::Executable) {
            return Ok(i);
        }
    }
    Err(ExecError::new(
        ErrorCode::NotFound,
        IsolationStage::Exec,
        "the entrypoint name was not found in PATH",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(items: &[&str]) -> Vec<CString> {
        items.iter().map(|s| CString::new(*s).unwrap()).collect()
    }
    fn strs(v: &[CString]) -> Vec<String> {
        v.iter().map(|c| c.to_string_lossy().into_owned()).collect()
    }

    /// OCI-1: redis:alpine の実際の `PATH` から候補列を作る。
    #[test]
    fn oci1_path_search_builds_candidates_from_last_path_entry() {
        let e = env(&[
            "PATH=/stale",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]);
        let got = candidates_from_env(OsStr::new("docker-entrypoint.sh"), &e).unwrap();
        assert_eq!(
            strs(&got),
            vec![
                "/usr/local/sbin/docker-entrypoint.sh",
                "/usr/local/bin/docker-entrypoint.sh",
                "/usr/sbin/docker-entrypoint.sh",
                "/usr/bin/docker-entrypoint.sh",
                "/sbin/docker-entrypoint.sh",
                "/bin/docker-entrypoint.sh",
            ]
        );
        // 空・`.`・相対の要素は探索しない。
        let e = env(&["PATH=:.:bin:/opt/x/"]);
        let got = candidates_from_env(OsStr::new("a"), &e).unwrap();
        assert_eq!(strs(&got), vec!["/opt/x/a"]);
    }

    /// OCI-1: 使えない入力は `InvalidArgument`（段 `Validate`）。
    #[test]
    fn oci1_path_search_rejects_unusable_input() {
        let many = format!("PATH={}", vec!["/a"; PATH_SEARCH_MAX_DIRS + 1].join(":"));
        let long = "x".repeat(PATH_SEARCH_MAX_NAME_BYTES + 1);
        let cases: Vec<(&str, Vec<CString>)> = vec![
            ("a", env(&["HOME=/"])),
            ("a", env(&["PATH="])),
            ("a", env(&["PATH=bin:."])),
            ("", env(&["PATH=/bin"])),
            ("a/b", env(&["PATH=/bin"])),
            (long.as_str(), env(&["PATH=/bin"])),
            ("a", env(&[many.as_str()])),
        ];
        for (name, e) in cases {
            let err = candidates_from_env(OsStr::new(name), &e).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{name:?} {e:?}");
            assert_eq!(err.stage, IsolationStage::Validate, "{name:?}");
        }
        let err = candidates_from_env(OsStr::new("a\0b"), &env(&["PATH=/bin"])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        // 巨大な ':' 連続は上限超過として拒否する（収集は上限 + 1 件で打ち切り）。
        let huge = format!("PATH=/a{}", ":".repeat(130_000));
        let err = candidates_from_env(OsStr::new("a"), &env(&[huge.as_str()])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// OCI-1: 実行ビットの無い候補は飛ばし、2 件目を採る。尽きたら `NotFound`。
    #[test]
    fn oci1_select_candidate_skips_and_exhausts() {
        let c = env(&["/a/x", "/b/x", "/c/x"]);
        let idx = select_candidate(&c, |p| match p.to_bytes() {
            b"/a/x" => Some(CandidateKind::NotExecutable),
            b"/b/x" => Some(CandidateKind::Executable),
            _ => panic!("probed after selection"),
        })
        .unwrap();
        assert_eq!(idx, 1);
        let err = select_candidate(&c, |p| match p.to_bytes() {
            b"/a/x" => None,
            b"/b/x" => Some(CandidateKind::NotRegular),
            _ => Some(CandidateKind::NotExecutable),
        })
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::Exec);
    }
}
