//! エントリポイントの封印した複製の作成（SUP-6・SEC-1・SEC-4・CORE-5・TASK-163 追補・#1531）。
//!
//! # 役割と呼び出し文脈
//!
//! 稼働中コンテナへの exec の子（`process::run_exec_child` が呼ぶ `prepare_exec_child`）が、本体の
//! `(st_dev, st_ino)` の照合を終えた後に呼ぶ。照合に使った open file description の内容を memfd へ複製して
//! 封印し（`F_SEAL_SEAL|SHRINK|GROW|WRITE` = 0x0F）、以後のシェバン・`PT_INTERP` の解析と
//! `execveat(AT_EMPTY_PATH)` をこの複製に対して行わせる。解析した内容と実行する内容が同じバイト列になり、
//! 照合の後・`execveat` の前にコンテナ側が元のファイルを書き換える TOCTOU（`interpreter.rs` の「限界」）を閉じる。
//! 設計と手順の全体は `interpreter.rs` の「封印した複製からの実行（B'）」を参照。launch 経路は対象外
//! （常駐するワークロードのメモリ増を避ける。#1314 の後）。
//!
//! # 契約
//!
//! 手順（順序固定。いずれかの失敗は fail-closed で exec しない）:
//!
//! 0. 元のファイルの実行時ポリシーを複製が迂回しないことを確かめる（[`SealPolicy`]。#1531）。memfd を
//!    `execveat` すると、元のファイルに結び付いたカーネルの exec 時検査（AppArmor のパス結び付きプロファイル・
//!    IMA の `BPRM_CHECK` 評価・Landlock の `EXECUTE`）は働かない。維持できないと判定した環境は、複製せずに
//!    拒否する（fail-closed。照合だけの方式 A へ黙って戻さない）:
//!    - パス結び付きの LSM（AppArmor・TOMOYO・Smack・BPF LSM・IPE）が有効、または IMA の appraisal が有効
//!      （か判定できない）なら `FailedPrecondition`（[`LsmEnvironment::Refuse`]）
//!    - SELinux が有効なら `FailedPrecondition`（元のファイルのラベルに対する `execute`・ドメイン遷移を memfd は
//!      迂回するため、ドメインだけを根拠に通さない。[`LsmEnvironment::Refuse`]）
//!    - Landlock が有効なら `FailedPrecondition`（実行プロセスが起動前から継承した domain の `EXECUTE` 制限は
//!      カーネルに問い合わせられず、内部マウント上の memfd は継承した制限を受けないため、維持を保証できない）
//!    - Landlock が `EXECUTE` を扱う場合、元のファイルの実パスに `EXECUTE` を与えるルールの配下になければ
//!      `PermissionDenied`（`execveat` が元のファイルで返していた `EACCES` と同じ扱い）
//! 1. 元のファイルの実行権限をカーネルに判定させる（`sys::access_exec_via_proc`。実行ビット・`noexec`）。
//!    memfd へ複製すると元のファイルの実行権限はカーネルから見えなくなるため、複製の前に確かめる。
//!    `EACCES` は `PermissionDenied`（違反にしない。今の `execve` の `EACCES` と同じ扱い）
//! 2. `st_size` が [`MAX_SEALED_COPY_BYTES`] を超えたら違反 [`ViolationReason::EntrypointCopyTooLarge`]
//!    （確保の前に判定する。疎なファイルでも `st_size` の段階で拒否される）
//! 3. memfd を作り（名前は固定値）、固定長バッファで複製する。複製したバイト数が `st_size` と一致しない・
//!    終端の先にまだ読めるデータがある（複製中の伸縮）なら `PermissionDenied`（違反にしない。
//!    `open_entrypoint` の「開き直しの間の競合」と同じ根拠）
//! 4. 封印して（`sys::seal_for_exec`）失敗したら違反 [`ViolationReason::EntrypointCopySealUnverified`]
//! 5. 読み取り専用で開き直し、開き直した fd の seal が 0x0F ちょうどであることを再確認する（違反
//!    [`ViolationReason::EntrypointCopySealUnverified`]）。書き込み用の fd はここで閉じる（`ETXTBSY` と
//!    書き込み用 fd の exec 先への継承を避ける）
//!
//! memfd の作成失敗（`ENOSYS`・`EACCES` = `vm.memfd_noexec=2`・`EPERM` = seccomp）は前提不足のシステム
//! エラーで、違反にはせず `FailedPrecondition` で拒否する（照合だけの方式 A へ黙って戻さない）。
//!
//! 限界: 環境の判定（[`SealPolicy::probe`]）はホスト側の securityfs と `/proc/cmdline` に依る。判定できない
//! 入力はすべて拒否に倒す。帰結として、AppArmor・SELinux・Landlock のいずれかが有効なホストでは封印した複製を
//! 使えず exec は拒否される（照合だけの方式 A へは戻さない。採否は所有者の判断事項）。詳細は `interpreter.rs` の
//! 「限界」。

use std::ffi::CStr;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::landlock::{AccessFs, LandlockRuleset};

use crate::sys::{self, SealError, SealSet, SysError};
use crate::traits::types::ErrorCode;

use super::process::keep_above_stdio;
use super::{ExecError, IsolationStage, ViolationReason, describe};

/// 封印した複製を作るエントリポイントの最大サイズ（バイト）。複製は exec した子の cgroup の
/// `memory.max` に計上されるため、巨大なファイルによる exec ごとの確保（DoS）を断つ上限として 256 MiB とする。
pub const MAX_SEALED_COPY_BYTES: u64 = 256 * 1024 * 1024;

/// 複製に使う固定長バッファ（バイト）。子のスタックに置くため小さく保つ。
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// memfd の名前（固定値。外部入力を混ぜない）。`/proc/<pid>/fd/N` のリンク先は
/// `/memfd:fandhe-exec-entrypoint (deleted)` に見える。
const COPY_NAME: &CStr = c"fandhe-exec-entrypoint";

const STAGE: IsolationStage = IsolationStage::Exec;

/// 元のファイルの実行時ポリシーを複製が維持できるかの判定材料（#1531・SEC-1。モジュール doc の手順 0）。
///
/// `prepare_exec_restrictions` が `setns` の **前**（ホスト側の securityfs が見えるうち）に [`SealPolicy::probe`]
/// で作り、`ExecReady` → `spawn_exec_command` → exec の子へ持ち越す。子は [`seal_entrypoint_copy`] の最初に参照する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SealPolicy {
    lsm: LsmEnvironment,
    landlock: LandlockExec,
}

/// LSM の環境の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LsmEnvironment {
    /// 複製が迂回するパス結び付きの LSM 検査がない。
    Unrestricted,
    /// 維持できない（または判定できない）ため複製しない。値は静的な理由。
    Refuse(&'static str),
}

/// Landlock の `EXECUTE` の扱い（exec 用に組み立てたルールセットから導く）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LandlockExec {
    /// `EXECUTE` を扱わない（検査対象外）。
    NotHandled,
    /// `EXECUTE` を扱う。値は `EXECUTE` を与えるルールのコンテナ内パス（この配下のファイルだけ実行できる）。
    Beneath(Vec<String>),
}

impl LandlockExec {
    /// ルールセットから導く。
    pub(super) fn from_ruleset(ruleset: &LandlockRuleset) -> Self {
        if !ruleset.handled_access_fs().contains(AccessFs::EXECUTE) {
            return Self::NotHandled;
        }
        Self::Beneath(
            ruleset
                .rules()
                .iter()
                .filter(|r| r.allowed.contains(AccessFs::EXECUTE))
                .map(|r| r.path.as_str().to_owned())
                .collect(),
        )
    }

    /// `real_path`（元のファイルの実パス。root からの絶対パス）への `EXECUTE` を許すか。
    /// Landlock と同じく、与えられた祖先ルールのいずれかの配下であれば許す（コンポーネント境界で比較する）。
    fn permits(&self, real_path: &Path) -> bool {
        match self {
            Self::NotHandled => true,
            Self::Beneath(paths) => {
                real_path.is_absolute() && paths.iter().any(|p| real_path.starts_with(Path::new(p)))
            }
        }
    }
}

/// [`LsmEnvironment`] の判定に使う、ホスト側で読んだ入力（読み取りの失敗は `Err` のまま渡す）。
pub(super) struct LsmProbeInput {
    /// `/sys/kernel/security/lsm`（有効な LSM のカンマ区切り一覧）。
    pub(super) lsm_list: std::io::Result<String>,
    /// `/proc/cmdline`。
    pub(super) cmdline: std::io::Result<String>,
    /// `/sys/kernel/security/ima/policy`（読めた場合の現行ポリシー）。
    pub(super) ima_policy: std::io::Result<String>,
}

/// 読み取った入力から LSM の環境を判定する（純粋関数。単体テストが具体値で確かめる）。
///
/// 判定できない入力は拒否に倒す（fail-closed）。パス結び付きで元のファイルに働く LSM は複製で再現できない。
pub(super) fn assess_lsm_environment(input: LsmProbeInput) -> LsmEnvironment {
    let list = match input.lsm_list {
        Ok(list) => list,
        Err(_) => return LsmEnvironment::Refuse("the active security modules could not be read"),
    };
    let names: Vec<&str> = list.trim().split(',').map(str::trim).collect();
    for path_bound in ["apparmor", "tomoyo", "smack", "bpf", "ipe"] {
        if names.contains(&path_bound) {
            return LsmEnvironment::Refuse(
                "a path-bound security module is active; its exec-time checks cannot be reproduced for a sealed copy",
            );
        }
    }
    if names.contains(&"ima") {
        let cmdline = match &input.cmdline {
            Ok(text) => text,
            Err(_) => return LsmEnvironment::Refuse("the kernel command line could not be read"),
        };
        for token in cmdline.split_whitespace() {
            let appraise_on = token
                .strip_prefix("ima_appraise=")
                .is_some_and(|v| v != "off");
            if appraise_on || token.starts_with("ima_policy=") {
                return LsmEnvironment::Refuse(
                    "IMA appraisal may be active; its exec-time check cannot be reproduced for a sealed copy",
                );
            }
        }
        match &input.ima_policy {
            Ok(text) if !text.to_ascii_lowercase().contains("appraise") => {}
            Ok(_) => {
                return LsmEnvironment::Refuse(
                    "IMA appraisal is active; its exec-time check cannot be reproduced for a sealed copy",
                );
            }
            Err(_) => {
                return LsmEnvironment::Refuse(
                    "the IMA policy could not be read; appraisal cannot be ruled out",
                );
            }
        }
    }
    if names.contains(&"selinux") {
        // 自プロセスのドメイン（`unconfined_t` 等）は、元のファイルのラベルに対する `execute` 許可や
        // ドメイン遷移の代わりにならない。memfd はそれらを迂回するため拒否する（SEC-1・CORE-5）。
        return LsmEnvironment::Refuse(
            "SELinux is active; the exec-time permission and transition for the original file label cannot be reproduced for a sealed copy",
        );
    }
    if names.contains(&"landlock") {
        // 起動前から継承した Landlock domain の `EXECUTE` 制限は問い合わせられず、内部マウント上の memfd は
        // その制限を受けない。継承 domain がないと保証できないため拒否する（CORE-5・SEC-1）。
        return LsmEnvironment::Refuse(
            "Landlock is active; an inherited EXECUTE restriction cannot be ruled out and would not apply to a sealed copy",
        );
    }
    LsmEnvironment::Unrestricted
}

/// ファイルを `cap` バイトまで読む（巨大ファイルの確保を避ける）。
fn read_capped(path: &str, cap: u64) -> std::io::Result<String> {
    let mut text = String::new();
    File::open(path)?.take(cap).read_to_string(&mut text)?;
    Ok(text)
}

impl SealPolicy {
    /// ルールセットとホスト側の実環境から作る。`setns` の前に呼ぶこと。
    pub(super) fn probe(ruleset: &LandlockRuleset) -> Self {
        let lsm = assess_lsm_environment(LsmProbeInput {
            lsm_list: read_capped("/sys/kernel/security/lsm", 4096),
            cmdline: read_capped("/proc/cmdline", 64 * 1024),
            ima_policy: read_capped("/sys/kernel/security/ima/policy", 1024 * 1024),
        });
        Self {
            lsm,
            landlock: LandlockExec::from_ruleset(ruleset),
        }
    }

    /// 判定材料を直接指定する。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(super) fn new(lsm: LsmEnvironment, landlock: LandlockExec) -> Self {
        Self { lsm, landlock }
    }

    /// 制約なし（`execveat` を行わない観測・単体テスト専用。本番の入口は [`SealPolicy::probe`] だけ）。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(super) fn unrestricted() -> Self {
        Self::new(LsmEnvironment::Unrestricted, LandlockExec::NotHandled)
    }
}

/// `file`（照合済みのエントリポイントを読み取り専用で開いた fd。`meta` はその `fstat`）の封印した複製を作り、
/// 読み取り専用で開き直した fd とその `fstat` を返す。`subject` は違反・拒否の診断に載せるエントリポイントの
/// パス。手順と契約はモジュール doc を参照。
pub(super) fn seal_entrypoint_copy(
    file: &File,
    meta: &Metadata,
    procfs: BorrowedFd<'_>,
    subject: &Path,
    policy: &SealPolicy,
) -> Result<(File, Metadata), ExecError> {
    seal_copy_bounded(
        file,
        meta.len(),
        MAX_SEALED_COPY_BYTES,
        procfs,
        subject,
        policy,
    )
}

/// [`seal_entrypoint_copy`] の本体。`size`（元の `st_size`）と `limit` を引数に取り、単体テストが小さい上限や
/// 食い違うサイズで境界を確かめられるようにする。
pub(super) fn seal_copy_bounded(
    file: &File,
    size: u64,
    limit: u64,
    procfs: BorrowedFd<'_>,
    subject: &Path,
    policy: &SealPolicy,
) -> Result<(File, Metadata), ExecError> {
    check_exec_policy_preserved(policy, file, procfs, subject)?;
    check_executable(file, procfs, subject)?;
    if size > limit {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointCopyTooLarge,
            Some(subject),
            STAGE,
        ));
    }
    let writer = sys::memfd_create_for_exec_copy(COPY_NAME).map_err(|e| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "memfd_create for the executable copy of the entrypoint failed: {}",
                describe(e)
            ),
        )
    })?;
    // 標準 fd が閉じた呼び出し側では memfd が 0〜2 を取り得る。後段の標準入出力の置換で潰されないよう 3 以上へ置く。
    let writer = File::from(keep_above_stdio(writer)?);
    copy_exact(file, &writer, size, subject)?;
    let sealed = sys::seal_for_exec(writer.into()).map_err(|e| seal_violation(&e, subject))?;
    let reopened = sys::reopen_pinned_read(procfs, sealed.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "reopen of the executable copy"))
        .and_then(keep_above_stdio)
        .map(File::from)?;
    // 開き直した fd が付いた seal を持つことを、書き込み用 fd とは別に確かめる。
    let actual = sys::get_seals(reopened.as_fd())
        .map_err(|e| seal_violation(&SealError::Sys(e), subject))?;
    if actual != SealSet::EXEC_COPY {
        return Err(seal_violation(
            &SealError::Unexpected {
                actual: actual.bits(),
            },
            subject,
        ));
    }
    // 書き込み用の fd を閉じる（`ETXTBSY` と、書き込み可能な fd を exec 先へ残さないため）。
    drop(sealed);
    let meta = reopened
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "stat the executable copy"))?;
    if meta.len() != size {
        return Err(changed_while_copying(subject));
    }
    Ok((reopened, meta))
}

/// 手順 0: 元のファイルの実行時ポリシーを複製が迂回しないか。
fn check_exec_policy_preserved(
    policy: &SealPolicy,
    file: &File,
    procfs: BorrowedFd<'_>,
    subject: &Path,
) -> Result<(), ExecError> {
    match policy.lsm {
        LsmEnvironment::Unrestricted => {}
        LsmEnvironment::Refuse(reason) => {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                format!("refusing to run {subject:?} from a sealed copy: {reason}"),
            ));
        }
    }
    check_landlock_execute(&policy.landlock, file, procfs, subject)
}

/// 手順 0（Landlock）: 元のファイルの実パスに `EXECUTE` が許されているか。memfd は Landlock のルール外で
/// 実行できてしまうため、元のファイルについてここで確かめる。許されなければ `execveat` が返していた `EACCES`
/// と同じ `PermissionDenied`（違反にしない）。実パスを確かめられなければ拒否する（fail-closed）。
fn check_landlock_execute(
    landlock: &LandlockExec,
    file: &File,
    procfs: BorrowedFd<'_>,
    subject: &Path,
) -> Result<(), ExecError> {
    if matches!(landlock, LandlockExec::NotHandled) {
        return Ok(());
    }
    let mut buf = vec![0u8; 4097];
    let n = sys::readlink_fd_via_proc(procfs, file.as_fd(), &mut buf)
        .map_err(|e| ExecError::from_sys(e, STAGE, "readlink of the entrypoint"))?;
    let bytes = buf.get(..n).ok_or_else(|| changed_while_copying(subject))?;
    let real = Path::new(std::ffi::OsStr::from_bytes(bytes));
    if !bytes.ends_with(b" (deleted)") && landlock.permits(real) {
        Ok(())
    } else {
        Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!(
                "the entrypoint {subject:?} is not under a path that grants Landlock EXECUTE; refusing to run it from a sealed copy"
            ),
        ))
    }
}

/// 手順 1: 元のファイルをカーネルが実行できると判定するか。
fn check_executable(file: &File, procfs: BorrowedFd<'_>, subject: &Path) -> Result<(), ExecError> {
    sys::access_exec_via_proc(procfs, file.as_fd()).map_err(|e| match e {
        SysError::Os(errno) if errno == sys::EACCES => ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {subject:?} is not executable (execute bit or noexec mount)"),
        ),
        // `faccessat2` を知らないカーネル（5.8 未満）などは前提不足。照合できないまま複製しない。
        SysError::Os(errno) if errno == sys::ENOSYS => ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "faccessat2 is unavailable; cannot check that the entrypoint is executable",
        ),
        other => ExecError::from_sys(other, STAGE, "faccessat2 of the entrypoint"),
    })
}

/// 手順 3: `size` バイトを `src` から `dst` へ複製し、複製中に元が伸縮していないことを確かめる。
fn copy_exact(src: &File, dst: &File, size: u64, subject: &Path) -> Result<(), ExecError> {
    let mut buf = [0u8; COPY_CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < size {
        let want =
            usize::try_from(size - offset).map_or(COPY_CHUNK_BYTES, |n| n.min(COPY_CHUNK_BYTES));
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| changed_while_copying(subject))?;
        let n = match src.read_at(chunk, offset) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExecError::from_io(&e, STAGE, "read of the entrypoint")),
        };
        if n == 0 {
            // `st_size` に届く前に終端: 複製中に縮んだ。
            return Err(changed_while_copying(subject));
        }
        let written = chunk
            .get(..n)
            .ok_or_else(|| changed_while_copying(subject))?;
        dst.write_all_at(written, offset)
            .map_err(|e| ExecError::from_io(&e, STAGE, "write of the executable copy"))?;
        offset += u64::try_from(n).map_err(|_| changed_while_copying(subject))?;
    }
    // 終端の先に読めるデータがあれば複製中に伸びた。
    let mut probe = [0u8; 1];
    loop {
        match src.read_at(&mut probe, size) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(changed_while_copying(subject)),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExecError::from_io(&e, STAGE, "read of the entrypoint")),
        }
    }
}

/// 複製中の伸縮による拒否（違反にしない。開き直しの間の競合と同じ根拠）。
fn changed_while_copying(subject: &Path) -> ExecError {
    ExecError::new(
        ErrorCode::PermissionDenied,
        STAGE,
        format!("the entrypoint {subject:?} changed while it was being copied"),
    )
}

/// 封印を確認できなかった失敗を違反へ写す（理由コードは静的トークン。errno 等の外部由来の文字列は載せない）。
fn seal_violation(_err: &SealError, subject: &Path) -> ExecError {
    ExecError::from_violation_at(
        ViolationReason::EntrypointCopySealUnverified,
        Some(subject),
        STAGE,
    )
}
#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::*;

    fn probe_input(lsm: &str, cmdline: &str, ima: Option<&str>) -> LsmProbeInput {
        LsmProbeInput {
            lsm_list: Ok(lsm.to_owned()),
            cmdline: Ok(cmdline.to_owned()),
            ima_policy: ima.map_or_else(
                || Err(std::io::ErrorKind::PermissionDenied.into()),
                |t| Ok(t.to_owned()),
            ),
        }
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: パス結び付きの LSM（AppArmor 等）が有効な環境は、複製せずに
    /// 拒否する。LSM 一覧を読めない場合も拒否する（fail-closed）。
    #[test]
    fn sup6_sec1_path_bound_lsm_environment_is_refused() {
        for lsm in [
            "lockdown,capability,landlock,yama,apparmor",
            "capability,tomoyo",
            "capability,smack",
            "capability,bpf",
            "capability,ipe",
        ] {
            let got = assess_lsm_environment(probe_input(lsm, "quiet", None));
            assert!(matches!(got, LsmEnvironment::Refuse(_)), "{lsm}: {got:?}");
        }
        let unreadable = LsmProbeInput {
            lsm_list: Err(std::io::ErrorKind::NotFound.into()),
            cmdline: Ok(String::new()),
            ima_policy: Ok(String::new()),
        };
        assert!(matches!(
            assess_lsm_environment(unreadable),
            LsmEnvironment::Refuse(_)
        ));
    }

    /// SUP-6・SEC-1・TASK-163 追補・#1531: IMA は appraisal が有効、または無効と判定できないときに拒否する。
    #[test]
    fn sup6_sec1_ima_appraisal_is_refused_unless_ruled_out() {
        let lsm = "capability,ima,evm";
        for (cmdline, policy) in [
            ("ima_appraise=enforce", Some("")),
            ("ima_appraise=fix", Some("")),
            ("ima_policy=appraise_tcb", Some("")),
            (
                "quiet",
                Some("appraise func=BPRM_CHECK appraise_type=imasig\n"),
            ),
            ("quiet", None),
        ] {
            let got = assess_lsm_environment(probe_input(lsm, cmdline, policy));
            assert!(
                matches!(got, LsmEnvironment::Refuse(_)),
                "{cmdline} {policy:?}: {got:?}"
            );
        }
        // appraisal がないことを確かめられる（`off`・policy に appraise 行なし）なら通す。
        for cmdline in ["quiet", "ima_appraise=off"] {
            let got = assess_lsm_environment(probe_input(
                lsm,
                cmdline,
                Some("measure func=BPRM_CHECK\n"),
            ));
            assert_eq!(got, LsmEnvironment::Unrestricted, "{cmdline}");
        }
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: 対象外の LSM のみの環境は制約なし。SELinux・Landlock が有効な
    /// 環境は（ドメインや自前のルールセットを根拠に通さず）拒否する。
    #[test]
    fn sup6_sec1_unrelated_environment_is_unrestricted_and_selinux_landlock_are_refused() {
        let none = assess_lsm_environment(probe_input("lockdown,capability,yama", "", None));
        assert_eq!(none, LsmEnvironment::Unrestricted);
        for lsm in [
            "capability,landlock,selinux",
            "capability,selinux",
            "capability,landlock",
        ] {
            let got = assess_lsm_environment(probe_input(lsm, "", None));
            assert!(matches!(got, LsmEnvironment::Refuse(_)), "{lsm}: {got:?}");
        }
    }

    /// SUP-6・SEC-1・TASK-163 追補・#1531: Landlock の `EXECUTE` を与えるルールの配下だけを許す
    /// （コンポーネント境界で比較し、`/usr` は `/usr2` を許さない）。
    #[test]
    fn sup6_sec1_landlock_execute_path_membership() {
        let policy = LandlockExec::Beneath(vec!["/usr".to_owned(), "/opt/app".to_owned()]);
        assert!(policy.permits(Path::new("/usr/bin/true")));
        assert!(policy.permits(Path::new("/opt/app")));
        assert!(!policy.permits(Path::new("/usr2/bin/true")));
        assert!(!policy.permits(Path::new("/opt/application")));
        assert!(!policy.permits(Path::new("/tmp/x")));
        assert!(!policy.permits(Path::new("relative/usr/x")));
        assert!(LandlockExec::NotHandled.permits(Path::new("/tmp/x")));
        assert!(!LandlockExec::Beneath(Vec::new()).permits(Path::new("/usr/bin/true")));
    }

    fn ruleset_with(allowed: AccessFs) -> LandlockRuleset {
        use crate::landlock::{PathRule, RuleOrigin, RulePath};
        LandlockRuleset::for_observation(
            6,
            vec![PathRule {
                path: RulePath::Root,
                allowed,
                origin: RuleOrigin::Root,
            }],
        )
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: 読み取りだけを許し `EXECUTE` を許さない Landlock の
    /// ルールセットでは、ルール外の実行を複製が迂回しないよう、元のファイルを複製せず `PermissionDenied`
    /// （違反にしない）で拒否する。`EXECUTE` を与えるルールの配下なら通る。
    #[test]
    fn sup6_sec1_landlock_without_execute_refuses_the_copy() {
        let scratch = Scratch::new("landlock");
        let file = scratch.file("script", b"#!/bin/sh\nexit 0\n", 0o755);
        let procfs = procfs();
        let read_only = SealPolicy::new(
            LsmEnvironment::Unrestricted,
            LandlockExec::from_ruleset(&ruleset_with(
                AccessFs::READ_FILE.union(AccessFs::READ_DIR),
            )),
        );
        let err = seal_copy_bounded(
            &file,
            17,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/script"),
            &read_only,
        )
        .expect_err("EXECUTE is not granted");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(violation_of(&err), None);
        assert_eq!(err.stage, IsolationStage::Exec);
        let granted = SealPolicy::new(
            LsmEnvironment::Unrestricted,
            LandlockExec::from_ruleset(&ruleset_with(AccessFs::READ)),
        );
        let ok = seal_copy_bounded(
            &file,
            17,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/script"),
            &granted,
        );
        assert_eq!(ok.expect("EXECUTE granted at /").1.len(), 17);
    }

    /// SUP-6・SEC-1・TASK-163 追補・#1531: 環境が維持できないと判定された場合、複製の手順に入らず
    /// `FailedPrecondition`（違反にしない）で拒否する。
    #[test]
    fn sup6_sec1_refused_environment_stops_before_copy() {
        let scratch = Scratch::new("refuse-env");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o755);
        let procfs = procfs();
        let policy = SealPolicy::new(LsmEnvironment::Refuse("test"), LandlockExec::NotHandled);
        let err = seal_copy_bounded(
            &file,
            10,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/script"),
            &policy,
        )
        .expect_err("refused");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(violation_of(&err), None);
    }

    /// 試験ごとの作業ディレクトリ（pid とラベルで一意。drop で削除）。
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-sealed-copy-{label}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }

        /// `mode` の通常ファイルを作り、読み取り専用で開いて返す。
        fn file(&self, name: &str, content: &[u8], mode: u32) -> File {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            File::open(&path).expect("open")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn procfs() -> File {
        File::open("/proc").expect("open /proc")
    }

    fn violation_of(err: &ExecError) -> Option<ViolationReason> {
        err.violation.as_ref().map(|v| v.reason)
    }

    /// SUP-6・SEC-1（TASK-163 追補・#1531）: 複製の内容・サイズが元と一致し、開き直した fd の seal が 0x0F ちょうどで、
    /// リンク先が固定名の memfd になる。複製は元とは別の inode で、読み取り専用。
    #[test]
    fn sup6_sec1_task163_copy_is_exact_sealed_and_read_only() {
        let scratch = Scratch::new("exact");
        // 複数の読み取りチャンクにまたがるサイズ（チャンク 64 KiB の 2 倍強）。
        let mut content = b"#!/bin/sh\nexit 0\n".to_vec();
        content.resize(COPY_CHUNK_BYTES * 2 + 123, b'x');
        let file = scratch.file("script", &content, 0o755);
        let size = u64::try_from(content.len()).expect("size");
        let procfs = procfs();
        let (copy, meta) = seal_copy_bounded(
            &file,
            size,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/script"),
            &SealPolicy::unrestricted(),
        )
        .expect("seal_copy_bounded");
        assert_eq!(meta.len(), size);
        let mut read_back = vec![0u8; content.len()];
        copy.read_exact_at(&mut read_back, 0).expect("read copy");
        assert_eq!(read_back, content);
        assert_eq!(sys::get_seals(copy.as_fd()).expect("seals").bits(), 0x0F);
        let link = std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&copy)
        ))
        .expect("readlink");
        assert_eq!(
            link.to_string_lossy(),
            "/memfd:fandhe-exec-entrypoint (deleted)"
        );
        let original = file.metadata().expect("stat");
        assert_ne!((meta.dev(), meta.ino()), (original.dev(), original.ino()));
        // 読み取り専用で開き直した fd への書き込みは拒否される。
        assert!(copy.write_at(b"y", 0).is_err());
    }

    /// SEC-4・SUP-6（#1531）: 上限を超える `st_size` は違反 `entrypoint_copy_too_large`
    /// （`PermissionDenied`・段 `Exec`）。上限ちょうどは通る。
    #[test]
    fn sec4_sup6_task163_oversized_entrypoint_is_a_violation() {
        let scratch = Scratch::new("limit");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        let procfs = procfs();
        let err = seal_copy_bounded(
            &file,
            100,
            99,
            procfs.as_fd(),
            Path::new("/script"),
            &SealPolicy::unrestricted(),
        )
        .expect_err("over the limit");
        assert_eq!(
            violation_of(&err),
            Some(ViolationReason::EntrypointCopyTooLarge)
        );
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        let ok = seal_copy_bounded(
            &file,
            100,
            100,
            procfs.as_fd(),
            Path::new("/script"),
            &SealPolicy::unrestricted(),
        );
        assert_eq!(ok.expect("at the limit").1.len(), 100);
    }

    /// SEC-1（#1531）: 複製中の伸縮（`st_size` が実際より大きい・小さい）は拒否するが、違反にはしない。
    #[test]
    fn sec1_task163_size_mismatch_is_denied_without_violation() {
        let scratch = Scratch::new("mismatch");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        let procfs = procfs();
        for claimed in [101u64, 99] {
            let err = seal_copy_bounded(
                &file,
                claimed,
                MAX_SEALED_COPY_BYTES,
                procfs.as_fd(),
                Path::new("/script"),
                &SealPolicy::unrestricted(),
            )
            .expect_err("size mismatch");
            assert_eq!(violation_of(&err), None, "claimed size {claimed}");
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.stage, IsolationStage::Exec);
        }
    }

    /// SEC-1（#1531）: 実行ビットのないファイルは複製の前に拒否する（memfd は元の mode を引き継がないため、
    /// 照合しないと実行できてしまう）。`PermissionDenied` で、違反にはしない。
    #[test]
    fn sec1_task163_non_executable_file_is_denied_before_copy() {
        let scratch = Scratch::new("noexec-bit");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o644);
        let procfs = procfs();
        let err = seal_copy_bounded(
            &file,
            10,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/s"),
            &SealPolicy::unrestricted(),
        )
        .expect_err("not executable");
        assert_eq!(violation_of(&err), None);
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
    }

    /// SEC-4・SEC-1（#1531）: 封印の失敗（syscall の失敗・期待と異なる seal）は、どちらも違反
    /// `entrypoint_copy_seal_unverified`（`FailedPrecondition`・段 `Exec`）に写る。実 fd での失敗
    /// （memfd でない fd は `Sys`）も同じ違反になる。
    #[test]
    fn sec4_sec1_task163_seal_failures_map_to_the_violation() {
        let real = sys::seal_for_exec(File::open("/dev/null").expect("open").into())
            .expect_err("not a memfd");
        assert!(matches!(real, SealError::Sys(SysError::Os(_))), "{real:?}");
        for err in [
            real,
            SealError::Sys(SysError::Os(sys::EINVAL)),
            SealError::Unexpected { actual: 0x2F },
        ] {
            let mapped = seal_violation(&err, Path::new("/script"));
            assert_eq!(
                violation_of(&mapped),
                Some(ViolationReason::EntrypointCopySealUnverified)
            );
            assert_eq!(mapped.code, ErrorCode::FailedPrecondition);
            assert_eq!(mapped.stage, IsolationStage::Exec);
        }
    }
}
