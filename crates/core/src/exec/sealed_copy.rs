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
//! # 全体の順序（固定。#1531）
//!
//! exec の worker（supervisor の `exec::run_command`）: `prepare_exec_restrictions`（`setns` の前。[`SealPolicy::probe`]
//! もここ）→ `setns` → 子 cgroup への参加 → `reapply_restrictions`（rlimit〔`RLIMIT_FSIZE` は持ち越し〕・capability
//! 削減・`NO_NEW_PRIVS`・Landlock・seccomp）→ fork した exec の子: 継承 fd の後始末 → `setsid` → エントリポイントを開いて
//! ランタイムと照合 → **本モジュール**（下の手順 0〜7）→ 持ち越した `RLIMIT_FSIZE` → インタープリタの照合 →
//! 標準入出力の置換 → 複製の `execveat`。
//!
//! - 複製・封印は Landlock・seccomp の **適用後** に行う。手順 2 の `AT_EXECVE_CHECK` は、実行するときと同じ最終的な
//!   domain（継承した Landlock の層・自前の層・seccomp・LSM）の下で、照合と同じ fd に対して判定させる必要がある
//!   ため（適用前に判定すると、適用される制限を判定に含められない）。照合と判定と複製を同じ子の中で続けて行い、
//!   fd を固定したまま進める
//! - memfd のページは、worker が fork の前に子 cgroup へ参加しているため、コンテナの `memory.max` に計上される
//! - 適用後に呼ぶため、ランタイムの seccomp（deny-list）は `memfd_create`・`fcntl`・`pread64`・`pwrite64`・
//!   `execveat` を拒否しない契約を維持する（`seccomp.rs` のテストが機械照合する）
//!
//! # 手順（順序固定。いずれかの失敗は fail-closed で exec しない）
//!
//! 0. 複製では維持できない LSM の実行時制約がないことを確かめる（[`SealPolicy`] の [`LsmEnvironment`]）。手順 2 の
//!    `AT_EXECVE_CHECK` は「元のファイルの実行が許されるか」を判定するが、memfd を実行したときのプロファイル・
//!    ドメインの遷移（AppArmor のパス結び付きプロファイル・SELinux の exec 遷移）は元のファイルではなく memfd について
//!    決まるため、許可の判定だけでは拘束を維持できない。維持できない環境は複製せずに `FailedPrecondition`
//!    （照合だけの方式 A へ黙って戻さない）:
//!    - パス結び付きの LSM（AppArmor・TOMOYO・Smack・BPF LSM・IPE）が有効、または IMA の appraisal が有効
//!      （か判定できない）。IMA の `BPRM_CHECK` が `AT_EXECVE_CHECK` で評価されるかは一次情報で確かめていないため、
//!      判定に含めず従来どおり拒否に倒す
//!    - SELinux が有効（元のファイルのラベルに対するドメイン遷移を memfd は迂回するため）
//!    - Landlock は対象外（手順 2 がカーネルに判定させる）
//! 1. 元のファイルの fd が開かれているマウントが `noexec` なら違反 [`ViolationReason::EntrypointOnNoexecMount`]
//!    （`sys::mount_flags` = `fstatfs` の `ST_NOEXEC`。パスを再解決せず fd のマウントそのものを見る）。memfd は
//!    内部マウント上にあるため、`execveat` が元のファイルのマウントで行う `noexec` の拒否は複製には働かない。手順 2 も
//!    `noexec` で拒否するが、カーネル版（6.14 未満）に依らず判定でき、違反として監査ログへ区別して残すために先に置く。
//!    `ST_VALID` が立たない（フラグを信用できない）・`fstatfs` の失敗は `FailedPrecondition`（fail-closed）。
//!    複製元は通常ファイルに限る（`open_entrypoint` の種別検査に加え、ここでも `fstat` で `S_IFREG` を確かめる）
//! 2. 元のファイルを実行してよいかを、実行せずにカーネルへ判定させる（`sys::exec_check_fd` =
//!    `execveat(fd, "", .., AT_EMPTY_PATH | AT_EXECVE_CHECK)`。Linux 6.14 以降）。`execveat` と同じ経路で、マウントの
//!    `noexec`・実行ビット（`MAY_EXEC`）・Landlock の `EXECUTE`（継承 domain を含む全層。inode に結び付いた規則のまま）・
//!    `security_bprm_creds_for_exec` まで評価される。`EACCES`・`EPERM` は `PermissionDenied`（違反にしない。今の
//!    `execve` の `EACCES` と同じ扱い）。`AT_EXECVE_CHECK` を知らないカーネル（`EINVAL`）は `FailedPrecondition`
//!    （判定できないまま複製しない）
//! 3. `st_size` が [`MAX_SEALED_COPY_BYTES`] を超えたら違反 [`ViolationReason::EntrypointCopyTooLarge`]
//!    （確保の前に判定する。疎なファイルでも `st_size` の段階で拒否される）
//! 4. memfd を作り（名前は固定値）、固定長バッファの `pread`・`pwrite` で `st_size` バイトちょうどを複製し、終端の先を
//!    1 バイトだけ読んで伸びていないことを確かめる（読み取りは上限 + 1 バイトで止まる。mmap は使わない）。一致しない
//!    （複製中の伸縮）なら `PermissionDenied`（違反にしない。`open_entrypoint` の「開き直しの間の競合」と同じ根拠）
//! 5. 封印して（`sys::seal_for_exec`）失敗したら違反 [`ViolationReason::EntrypointCopySealUnverified`]
//! 6. 読み取り専用で開き直し（`sys::SealedMemfd::reopen_read_only`）、開き直した fd の seal が 0x0F ちょうどで
//!    `(st_dev, st_ino)` が封印した memfd と同じことを確かめた型（`sys::SealedReadOnlyCopy`）にする。失敗は違反
//!    [`ViolationReason::EntrypointCopySealUnverified`]。書き込み用の fd はここで閉じる（`ETXTBSY` と書き込み用 fd の
//!    exec 先への継承を避ける）
//! 7. 開き直した fd のサイズが `st_size` と一致することを確かめる（一致しなければ `PermissionDenied`）
//!
//! memfd の作成失敗（`ENOSYS`・`EACCES` = `vm.memfd_noexec=2`・`EPERM` = seccomp）は前提不足のシステム
//! エラーで、違反にはせず `FailedPrecondition` で拒否する（照合だけの方式 A へ黙って戻さない）。
//!
//! シェバンのインタープリタ・`PT_INTERP` の動的リンカは複製しない（カーネルが元のファイルとして開く）ため、
//! それらの `noexec`・実行権限・Landlock・LSM の検査はカーネルがそのまま行う（本モジュールの対象は本体の複製だけ）。
//!
//! 限界: 手順 0 の環境の判定（[`SealPolicy::probe`]）はホスト側の securityfs と `/proc/cmdline` に依る。判定できない
//! 入力はすべて拒否に倒す。帰結として、AppArmor・SELinux が有効なホストと、Linux 6.14 未満のカーネルでは
//! 封印した複製を使えず exec は拒否される（照合だけの方式 A へは戻さない。採否は所有者の判断事項）。詳細は
//! `interpreter.rs` の「限界」。

use std::ffi::CStr;
use std::fs::{File, FileType, Metadata};
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::sys::{self, SealError, SealedReadOnlyCopy, SysError};
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

/// 封印した複製が元のファイルの実行時ポリシーを迂回しないための判定材料（#1531・SEC-1。モジュール doc の手順 0・2）。
///
/// `prepare_exec_restrictions` が `setns` の **前**（ホスト側の securityfs が見えるうち）に [`SealPolicy::probe`]
/// で作り、`ExecReady` → `spawn_exec_command` → exec の子へ持ち越す。子は [`seal_entrypoint_copy`] の最初に参照する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SealPolicy {
    lsm: LsmEnvironment,
    exec_check: ExecCheck,
}

/// 手順 2（`AT_EXECVE_CHECK`）の扱い。本番の入口（[`SealPolicy::probe`]）は常に [`ExecCheck::Required`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecCheck {
    /// 必須。`AT_EXECVE_CHECK` を知らないカーネル（6.14 未満）は拒否する（fail-closed）。
    Required,
    /// 観測・単体テスト専用: カーネルが `AT_EXECVE_CHECK` を知らない（`EINVAL`）ときだけ判定を省く。判定できた
    /// 場合の拒否は [`ExecCheck::Required`] と同じ。`execveat` を行わない観測（`observe_exec_child_setup`）が、
    /// 6.14 未満の CI でも複製の他の手順を照合できるようにするためで、本番のビルドでは作れない。
    #[cfg(any(test, feature = "exec-test-support"))]
    IfSupported,
}

/// LSM の環境の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LsmEnvironment {
    /// 複製では維持できない LSM の実行時制約がない。
    Unrestricted,
    /// 維持できない（または判定できない）ため複製しない。値は静的な理由。
    Refuse(&'static str),
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
/// 判定できない入力は拒否に倒す（fail-closed）。パス・ラベルに結び付いて実行後の拘束を決める LSM は、複製の
/// 実行では元のファイルについて働かない。
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
            // `ima_policy=` は、計測専用と分かっている組み込みポリシー（`tcb`・`critical_data`）だけを
            // 通し、後続の現行 policy ファイルの判定へ進める。appraise 系・未知の値は拒否する。
            let policy_unknown = token
                .strip_prefix("ima_policy=")
                .is_some_and(|v| !v.split('|').all(is_measure_only_ima_policy));
            if appraise_on || policy_unknown {
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
    // Landlock はここで拒否しない。exec の子は自前の Landlock ルールセットを必ず適用してから `ExecReady` を返す
    // （SUP-6）ため、有効な環境を一律に拒否すると本番の exec が成立しない。元のファイルへの `EXECUTE` は、継承した
    // domain を含む全層を、手順 2 の `AT_EXECVE_CHECK` がカーネルの規則（inode 単位）のまま判定する（CORE-5・SEC-1）。
    LsmEnvironment::Unrestricted
}

/// カーネル組み込みの IMA ポリシー名のうち、appraisal を含まない計測専用のもの。
/// `|` 区切りで複数指定できる（`ima_policy=tcb|critical_data`）。
fn is_measure_only_ima_policy(name: &str) -> bool {
    matches!(name, "tcb" | "critical_data")
}

/// ファイルを `cap` バイトまで読む（巨大ファイルの確保を避ける）。`cap` を超えて続く場合は切り詰めず
/// `InvalidData` で失敗させる（先頭だけを見て判定すると、後続の appraise ルール等を見落として誤って
/// 通すため。呼び出し側は読めなかった入力を拒否に倒す。fail-closed）。
fn read_capped(path: &str, cap: u64) -> std::io::Result<String> {
    read_capped_from(File::open(path)?, cap)
}

fn read_capped_from(reader: impl std::io::Read, cap: u64) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    reader.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > cap) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "security configuration input exceeds the size limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()))
}

impl SealPolicy {
    /// ホスト側の実環境から作る（`AT_EXECVE_CHECK` は必須）。`setns` の前に呼ぶこと。
    pub(super) fn probe() -> Self {
        let lsm = assess_lsm_environment(LsmProbeInput {
            lsm_list: read_capped("/sys/kernel/security/lsm", 4096),
            cmdline: read_capped("/proc/cmdline", 64 * 1024),
            ima_policy: read_capped("/sys/kernel/security/ima/policy", 1024 * 1024),
        });
        Self {
            lsm,
            exec_check: ExecCheck::Required,
        }
    }

    /// 判定材料を直接指定する（単体テスト専用）。
    #[cfg(test)]
    pub(super) fn new(lsm: LsmEnvironment, exec_check: ExecCheck) -> Self {
        Self { lsm, exec_check }
    }

    /// LSM の制約なし・`AT_EXECVE_CHECK` は対応カーネルでだけ行う（`execveat` を行わない観測・単体テスト専用。
    /// 本番の入口は [`SealPolicy::probe`] だけ）。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(super) fn unrestricted() -> Self {
        Self {
            lsm: LsmEnvironment::Unrestricted,
            exec_check: ExecCheck::IfSupported,
        }
    }
}

/// `file`（照合済みのエントリポイントを読み取り専用で開いた fd。`meta` はその `fstat`）の封印した複製を作り、
/// 読み取り専用で開き直して再照合した fd を返す。`subject` は違反・拒否の診断に載せるエントリポイントの
/// パス。手順と契約はモジュール doc を参照。
pub(super) fn seal_entrypoint_copy(
    file: &File,
    meta: &Metadata,
    procfs: BorrowedFd<'_>,
    subject: &Path,
    policy: &SealPolicy,
) -> Result<SealedReadOnlyCopy, ExecError> {
    seal_copy_bounded(
        file,
        meta.file_type(),
        meta.len(),
        MAX_SEALED_COPY_BYTES,
        procfs,
        subject,
        policy,
    )
}

/// [`seal_entrypoint_copy`] の本体。`file_type`・`size`（元の `fstat`）と `limit` を引数に取り、単体テストが小さい
/// 上限や食い違うサイズで境界を確かめられるようにする。
pub(super) fn seal_copy_bounded(
    file: &File,
    file_type: FileType,
    size: u64,
    limit: u64,
    procfs: BorrowedFd<'_>,
    subject: &Path,
    policy: &SealPolicy,
) -> Result<SealedReadOnlyCopy, ExecError> {
    check_lsm_environment(policy.lsm, subject)?;
    if !file_type.is_file() {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {subject:?} is not a regular file; refusing to copy it"),
        ));
    }
    check_not_on_noexec_mount(file, subject)?;
    check_kernel_permits_exec(policy.exec_check, file, subject)?;
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
    // 開き直し・seal 0x0F・`(st_dev, st_ino)` の再照合と、開き直した fd を 3 以上に置くことは `sys` の型が保証する
    // （書き込み用 fd もここで閉じる）。
    let copy = sealed
        .reopen_read_only(procfs)
        .map_err(|e| seal_violation(&e, subject))?;
    if copy.metadata().len() != size {
        return Err(changed_while_copying(subject));
    }
    Ok(copy)
}

/// 手順 0: 複製では維持できない LSM の実行時制約がないか。
fn check_lsm_environment(lsm: LsmEnvironment, subject: &Path) -> Result<(), ExecError> {
    match lsm {
        LsmEnvironment::Unrestricted => Ok(()),
        LsmEnvironment::Refuse(reason) => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("refusing to run {subject:?} from a sealed copy: {reason}"),
        )),
    }
}

/// 手順 1: 元のファイルの fd が開かれているマウントが `noexec` でないか（`fstatfs` の `ST_NOEXEC`）。
///
/// `execveat` は元のファイルのマウントの `noexec` で拒否するが、memfd の複製は内部マウント上にあり拒否されない。
/// パスを再解決せず fd のマウントを見るため、照合した実体と判定の対象がずれない。`noexec` は違反
/// [`ViolationReason::EntrypointOnNoexecMount`]、フラグを確かめられない（`fstatfs` の失敗・`ST_VALID` なし）
/// 場合は拒否する（fail-closed）。
fn check_not_on_noexec_mount(file: &File, subject: &Path) -> Result<(), ExecError> {
    let flags = sys::mount_flags(file.as_fd()).map_err(|e| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "fstatfs of the entrypoint {subject:?} failed: {}; cannot rule out a noexec mount",
                describe(e)
            ),
        )
    })?;
    mount_flags_verdict(flags, subject)
}

/// [`check_not_on_noexec_mount`] の判定部（純関数。単体テストが境界値で確かめる）。
fn mount_flags_verdict(flags: sys::MountFlags, subject: &Path) -> Result<(), ExecError> {
    if !flags.is_valid() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "the mount flags of the entrypoint {subject:?} are not reported (ST_VALID is unset); cannot rule out a noexec mount"
            ),
        ));
    }
    if flags.is_noexec() {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointOnNoexecMount,
            Some(subject),
            STAGE,
        ));
    }
    Ok(())
}

/// 手順 2: 元のファイルを実行してよいかを、実行せずにカーネルへ判定させる（`AT_EXECVE_CHECK`）。
fn check_kernel_permits_exec(
    mode: ExecCheck,
    file: &File,
    subject: &Path,
) -> Result<(), ExecError> {
    exec_check_verdict(mode, sys::exec_check_fd(file.as_fd()), subject)
}

/// [`check_kernel_permits_exec`] の判定部（純関数。単体テストが errno ごとの写像を具体値で確かめる）。
fn exec_check_verdict(
    mode: ExecCheck,
    result: Result<(), SysError>,
    subject: &Path,
) -> Result<(), ExecError> {
    match result {
        Ok(()) => Ok(()),
        Err(SysError::Os(errno)) if errno == sys::EACCES || errno == sys::EPERM => {
            Err(ExecError::new(
                ErrorCode::PermissionDenied,
                STAGE,
                format!(
                    "the kernel does not permit executing the entrypoint {subject:?} (AT_EXECVE_CHECK: {})",
                    describe(SysError::Os(errno))
                ),
            ))
        }
        Err(SysError::Os(errno)) if errno == sys::EINVAL => match mode {
            ExecCheck::Required => Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "AT_EXECVE_CHECK is unavailable (Linux 6.14 or later is required); cannot check that the entrypoint may be executed before copying it",
            )),
            #[cfg(any(test, feature = "exec-test-support"))]
            ExecCheck::IfSupported => Ok(()),
        },
        Err(other) => Err(ExecError::from_sys(
            other,
            STAGE,
            "execveat(AT_EXECVE_CHECK) of the entrypoint",
        )),
    }
}

/// 手順 4: `size` バイトを `src` から `dst` へ複製し、複製中に元が伸縮していないことを確かめる。
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
    // 終端の先に読めるデータがあれば複製中に伸びた（読み取りは `st_size` + 1 バイトで止まる）。
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

/// 封印・開き直しの再照合に失敗した理由を違反へ写す（`SealError` のどの値も同じ違反になる。理由コードは静的
/// トークンで、errno 等の外部由来の文字列は載せない）。
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
    use std::path::Path;

    use super::*;
    use crate::test_support::{TestTempDir, kernel_at_least};

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
            ("ima_policy=tcb|appraise_tcb", Some("")),
            ("ima_policy=unknown_policy", Some("")),
            (
                "quiet",
                Some("appraise func=BPRM_CHECK appraise_type=imasig\n"),
            ),
            ("quiet", None),
            ("ima_policy=tcb", Some("appraise func=BPRM_CHECK\n")),
            ("ima_policy=tcb", None),
        ] {
            let got = assess_lsm_environment(probe_input(lsm, cmdline, policy));
            assert!(
                matches!(got, LsmEnvironment::Refuse(_)),
                "{cmdline} {policy:?}: {got:?}"
            );
        }
        // appraisal がないことを確かめられる（`off`・policy に appraise 行なし）なら通す。
        // 計測専用の組み込みポリシーは後続の policy ファイル判定へ進み、appraise 行がなければ通す（#1579）。
        for cmdline in [
            "quiet",
            "ima_appraise=off",
            "ima_policy=tcb",
            "ima_policy=tcb|critical_data",
        ] {
            let got = assess_lsm_environment(probe_input(
                lsm,
                cmdline,
                Some("measure func=BPRM_CHECK\n"),
            ));
            assert_eq!(got, LsmEnvironment::Unrestricted, "{cmdline}");
        }
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: 対象外の LSM のみの環境は制約なし。SELinux が有効な環境は
    /// （ドメインを根拠に通さず）拒否する。Landlock のみ有効な環境は拒否しない（#1579 の P1。本番 exec が成立する。
    /// `EXECUTE` は `AT_EXECVE_CHECK` がカーネルの規則で判定する）。
    #[test]
    fn sup6_sec1_unrelated_environment_is_unrestricted_and_selinux_is_refused_but_landlock_is_not()
    {
        let none = assess_lsm_environment(probe_input("lockdown,capability,yama", "", None));
        assert_eq!(none, LsmEnvironment::Unrestricted);
        for lsm in ["capability,landlock,selinux", "capability,selinux"] {
            let got = assess_lsm_environment(probe_input(lsm, "", None));
            assert!(matches!(got, LsmEnvironment::Refuse(_)), "{lsm}: {got:?}");
        }
        for lsm in ["capability,landlock", "lockdown,capability,landlock,yama"] {
            let got = assess_lsm_environment(probe_input(lsm, "", None));
            assert_eq!(got, LsmEnvironment::Unrestricted, "{lsm}");
        }
    }

    /// SEC-1・CORE-5・#1531: 上限を超えて続く入力は切り詰めず失敗させる（先頭だけで判定して後続の appraise
    /// ルールを見落とさない）。上限ちょうどは読める。
    #[test]
    fn sec1_core5_read_capped_rejects_input_over_the_cap() {
        assert_eq!(read_capped_from(&b"abcd"[..], 4).expect("at cap"), "abcd");
        let err = read_capped_from(&b"abcde"[..], 4).expect_err("over cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // 先頭が上限内でも、後続に appraise があれば読めない = 拒否に倒れる。
        let mut policy = b"measure func=BPRM_CHECK\n".to_vec();
        policy.resize(1024, b' ');
        policy.extend_from_slice(b"appraise func=BPRM_CHECK\n");
        assert!(read_capped_from(&policy[..], 1024).is_err());
        let refused = assess_lsm_environment(LsmProbeInput {
            lsm_list: Ok("capability,ima".to_owned()),
            cmdline: Ok(String::new()),
            ima_policy: read_capped_from(&policy[..], 1024),
        });
        assert!(matches!(refused, LsmEnvironment::Refuse(_)), "{refused:?}");
    }

    /// 試験ごとの作業ディレクトリ（排他的に作る。drop で削除）。
    struct Scratch(TestTempDir);

    impl Scratch {
        fn new(label: &str) -> Self {
            Self(TestTempDir::new(&format!("sealed-copy-{label}")).expect("temp dir"))
        }

        /// `mode` の通常ファイルを作り、読み取り専用で開いて返す。
        fn file(&self, name: &str, content: &[u8], mode: u32) -> File {
            let path = self.0.path().join(name);
            std::fs::write(&path, content).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            File::open(&path).expect("open")
        }
    }

    fn procfs() -> File {
        File::open("/proc").expect("open /proc")
    }

    fn violation_of(err: &ExecError) -> Option<ViolationReason> {
        err.violation.as_ref().map(|v| v.reason)
    }

    /// 本番と同じ `AT_EXECVE_CHECK` 必須の方針（LSM の制約なし）。
    fn required() -> SealPolicy {
        SealPolicy::new(LsmEnvironment::Unrestricted, ExecCheck::Required)
    }

    /// `file` の種別とサイズで [`seal_copy_bounded`] を呼ぶ。
    fn seal(
        file: &File,
        size: u64,
        limit: u64,
        policy: &SealPolicy,
    ) -> Result<SealedReadOnlyCopy, ExecError> {
        let procfs = procfs();
        let file_type = file.metadata().expect("stat").file_type();
        seal_copy_bounded(
            file,
            file_type,
            size,
            limit,
            procfs.as_fd(),
            Path::new("/script"),
            policy,
        )
    }

    /// SUP-6・SEC-1・TASK-163 追補・#1531: 環境が維持できないと判定された場合、複製の手順に入らず
    /// `FailedPrecondition`（違反にしない）で拒否する。
    #[test]
    fn sup6_sec1_refused_environment_stops_before_copy() {
        let scratch = Scratch::new("refuse-env");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o755);
        let policy = SealPolicy::new(LsmEnvironment::Refuse("test"), ExecCheck::Required);
        let err = seal(&file, 10, MAX_SEALED_COPY_BYTES, &policy).expect_err("refused");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(violation_of(&err), None);
        assert!(err.message.contains("test"), "{}", err.message);
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
        let copy = seal(
            &file,
            size,
            MAX_SEALED_COPY_BYTES,
            &SealPolicy::unrestricted(),
        )
        .expect("seal_copy_bounded");
        assert_eq!(copy.metadata().len(), size);
        let mut read_back = vec![0u8; content.len()];
        copy.file()
            .read_exact_at(&mut read_back, 0)
            .expect("read copy");
        assert_eq!(read_back, content);
        assert_eq!(
            sys::get_seals(copy.file().as_fd()).expect("seals").bits(),
            0x0F
        );
        let link = std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(copy.file())
        ))
        .expect("readlink");
        assert_eq!(
            link.to_string_lossy(),
            "/memfd:fandhe-exec-entrypoint (deleted)"
        );
        let original = file.metadata().expect("stat");
        assert_ne!(
            (copy.metadata().dev(), copy.metadata().ino()),
            (original.dev(), original.ino())
        );
        // 読み取り専用で開き直した fd への書き込みは拒否される。
        assert!(copy.file().write_at(b"y", 0).is_err());
    }

    /// SEC-4・SUP-6（#1531）: 上限を超える `st_size` は違反 `entrypoint_copy_too_large`
    /// （`PermissionDenied`・段 `Exec`）。上限ちょうどは通る。
    #[test]
    fn sec4_sup6_task163_oversized_entrypoint_is_a_violation() {
        let scratch = Scratch::new("limit");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        let err = seal(&file, 100, 99, &SealPolicy::unrestricted()).expect_err("over the limit");
        assert_eq!(
            violation_of(&err),
            Some(ViolationReason::EntrypointCopyTooLarge)
        );
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        let ok = seal(&file, 100, 100, &SealPolicy::unrestricted());
        assert_eq!(ok.expect("at the limit").metadata().len(), 100);
    }

    /// SEC-1（#1531）: 複製中の伸縮（`st_size` が実際より大きい・小さい）は拒否するが、違反にはしない。
    #[test]
    fn sec1_task163_size_mismatch_is_denied_without_violation() {
        let scratch = Scratch::new("mismatch");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        for claimed in [101u64, 99] {
            let err = seal(
                &file,
                claimed,
                MAX_SEALED_COPY_BYTES,
                &SealPolicy::unrestricted(),
            )
            .expect_err("size mismatch");
            assert_eq!(violation_of(&err), None, "claimed size {claimed}");
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.stage, IsolationStage::Exec);
        }
    }

    /// SEC-1・SUP-6・TASK-163 追補（#1531）: `noexec` のマウント上のファイルは、複製せずに違反
    /// `entrypoint_on_noexec_mount`（`PermissionDenied`・段 `Exec`）で拒否する。非特権では `noexec` のマウントを
    /// 作れないため、既存の `noexec` マウントである `/proc`（mountinfo で `noexec` と確かめる。前提が崩れた環境では
    /// skip せず失敗する）上の通常ファイルを使う。`AT_EXECVE_CHECK` の有無・LSM の方針に依らず同じ値になる
    /// （手順 1 は手順 2 より前で、カーネル版に依存しない）。
    #[test]
    fn sec1_sup6_task163_entrypoint_on_noexec_mount_is_a_violation() {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let proc_opts = mountinfo
            .lines()
            .rev()
            .find_map(|line| {
                let mut cols = line.split(' ');
                let point = cols.nth(4)?;
                let opts = cols.next()?;
                (point == "/proc").then_some(opts)
            })
            .expect("/proc is mounted");
        assert!(
            proc_opts.split(',').any(|o| o == "noexec"),
            "/proc must be mounted noexec for this test: {proc_opts}"
        );
        let file = File::open("/proc/self/status").expect("open /proc/self/status");
        for policy in [required(), SealPolicy::unrestricted()] {
            let err = seal(&file, 0, MAX_SEALED_COPY_BYTES, &policy).expect_err("noexec mount");
            assert_eq!(
                violation_of(&err),
                Some(ViolationReason::EntrypointOnNoexecMount)
            );
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.stage, IsolationStage::Exec);
            assert_eq!(
                err.message,
                "the entrypoint is on a noexec mount; refusing to exec it from a sealed copy"
            );
        }
    }

    /// SEC-1・#1531: マウントフラグの判定の境界値。`ST_VALID`（0x20）が無い値は信用せず `FailedPrecondition`、
    /// `ST_NOEXEC`（0x8）は違反、`ST_VALID` だけ（`ST_RDONLY`〔0x1〕・`ST_NOSUID`〔0x2〕が併存しても）は通す。
    #[test]
    fn sec1_task163_mount_flags_verdict_boundaries() {
        let subject = Path::new("/script");
        let err =
            mount_flags_verdict(sys::MountFlags::from_bits(0x8), subject).expect_err("invalid");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(violation_of(&err), None);
        let err = mount_flags_verdict(sys::MountFlags::from_bits(0x20 | 0x8 | 0x2), subject)
            .expect_err("noexec");
        assert_eq!(
            violation_of(&err),
            Some(ViolationReason::EntrypointOnNoexecMount)
        );
        assert_eq!(
            mount_flags_verdict(sys::MountFlags::from_bits(0x20 | 0x1 | 0x2), subject),
            Ok(())
        );
    }

    /// SEC-1・#1531: `AT_EXECVE_CHECK` の結果の写像。`EACCES`・`EPERM` は `PermissionDenied`（違反なし）、
    /// `EINVAL`（6.14 未満）は必須なら `FailedPrecondition`・観測専用の方針なら判定を省いて通す。
    #[test]
    fn sec1_task163_exec_check_verdict_maps_errnos() {
        let subject = Path::new("/script");
        for errno in [sys::EACCES, sys::EPERM] {
            for mode in [ExecCheck::Required, ExecCheck::IfSupported] {
                let err = exec_check_verdict(mode, Err(SysError::Os(errno)), subject)
                    .expect_err("denied");
                assert_eq!(err.code, ErrorCode::PermissionDenied, "{errno}");
                assert_eq!(violation_of(&err), None);
                assert_eq!(err.stage, IsolationStage::Exec);
            }
        }
        let err = exec_check_verdict(ExecCheck::Required, Err(SysError::Os(sys::EINVAL)), subject)
            .expect_err("unsupported");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("Linux 6.14"), "{}", err.message);
        assert_eq!(
            exec_check_verdict(
                ExecCheck::IfSupported,
                Err(SysError::Os(sys::EINVAL)),
                subject
            ),
            Ok(())
        );
        assert_eq!(
            exec_check_verdict(ExecCheck::Required, Ok(()), subject),
            Ok(())
        );
    }

    /// SEC-1（#1531）: 実行ビットのないファイルは複製の前に拒否する（memfd は元の mode を引き継がないため、
    /// 照合しないと実行できてしまう）。Linux 6.14 以降（`AT_EXECVE_CHECK` が判定する）では `PermissionDenied`、
    /// 6.14 未満では必須の判定ができないため `FailedPrecondition`。どちらも違反にはしない。0755 のファイルは 6.14 以降で
    /// 通り、6.14 未満では同じく `FailedPrecondition`（判定できないまま複製しない）。
    #[test]
    fn sec1_task163_kernel_exec_check_gates_the_copy() {
        let scratch = Scratch::new("exec-check");
        let plain = scratch.file("plain", b"#!/bin/sh\n", 0o644);
        let script = scratch.file("script", b"#!/bin/sh\n", 0o755);
        let denied = seal(&plain, 10, MAX_SEALED_COPY_BYTES, &required()).expect_err("0644");
        assert_eq!(violation_of(&denied), None);
        assert_eq!(denied.stage, IsolationStage::Exec);
        let allowed = seal(&script, 10, MAX_SEALED_COPY_BYTES, &required());
        if kernel_at_least(6, 14) {
            assert_eq!(denied.code, ErrorCode::PermissionDenied);
            assert_eq!(allowed.expect("0755").metadata().len(), 10);
        } else {
            assert_eq!(denied.code, ErrorCode::FailedPrecondition);
            assert_eq!(
                allowed.expect_err("unsupported kernel").code,
                ErrorCode::FailedPrecondition
            );
        }
    }

    /// SEC-1（#1531）: 通常ファイルでないもの（ディレクトリ）は複製元にしない。
    #[test]
    fn sec1_task163_non_regular_source_is_refused() {
        let scratch = Scratch::new("dir");
        let dir = File::open(scratch.0.path()).expect("open dir");
        let err = seal(&dir, 0, MAX_SEALED_COPY_BYTES, &SealPolicy::unrestricted())
            .expect_err("directory");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(violation_of(&err), None);
        assert!(
            err.message.contains("not a regular file"),
            "{}",
            err.message
        );
    }

    /// SEC-4・SEC-1（#1531）: 封印・開き直しの再照合の失敗（syscall の失敗・期待と異なる seal・開き直した fd の
    /// 実体の不一致）は、どれも違反 `entrypoint_copy_seal_unverified`（`FailedPrecondition`・段 `Exec`）に写る。
    /// 実 fd での失敗（memfd でない fd は `Sys`）も同じ違反になる。
    #[test]
    fn sec4_sec1_task163_seal_failures_map_to_the_violation() {
        let real = sys::seal_for_exec(File::open("/dev/null").expect("open").into())
            .expect_err("not a memfd");
        assert!(matches!(real, SealError::Sys(SysError::Os(_))), "{real:?}");
        for err in [
            real,
            SealError::Sys(SysError::Os(sys::EINVAL)),
            SealError::Unexpected { actual: 0x2F },
            SealError::IdentityMismatch,
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
