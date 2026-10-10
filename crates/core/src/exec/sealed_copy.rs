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
//!    決まるため、許可の判定だけでは拘束を維持できない。維持できない環境では、`setns` の前の判定
//!    （[`SealPolicy::probe`]・[`decide_entrypoint_mode`]）が封印した複製を選ばず、理由を記録して現行方式（照合した元の
//!    fd をそのまま実行する。#1478）で実行する（オーナー判断 2026-10-09「条件付き切り替え」。`entrypoint_mode.rs`）。
//!    本関数は封印した複製の判定のときだけ呼ばれ、現行方式の判定で呼ばれたら複製せずに `FailedPrecondition` で拒否する。
//!    判定は許可リスト方式で、安全と分かっている LSM（`capability`・`lockdown`・`yama`・`landlock`・`loadpin`・
//!    `safesetid`）以外が有効なら封印した複製を使わない（未知の名前も同じ。一覧が空・`capability` を含まない・securityfs
//!    上に無い場合は一覧として信用せず `lsm_list_unreadable`）:
//!    - パス結び付きの LSM（AppArmor・TOMOYO・Smack・BPF LSM・IPE）が有効
//!    - SELinux が有効（元のファイルのラベルに対するドメイン遷移を memfd は迂回するため）
//!    - 完全性検査系（IMA・EVM・integrity）が有効。計測専用のポリシー（`ima_policy=tcb` 等）でも、memfd からの実行が
//!      計測されない・元のパスで記録されないおそれがあり、`BPRM_CHECK` が `AT_EXECVE_CHECK` で評価されるかも一次情報で
//!      確かめていないため、`/proc/cmdline`・policy の内容に依らず使わない（独立監査 P2-1。一次照合が済めば緩められる）
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
//!    （判定できないまま複製しない）。この判定はカーネルが未知のフラグを `EINVAL` で拒否する挙動（`do_open_execat` のフラグ検査）に依る: フラグを
//!    無視するカーネルでは通常ファイルの元の fd がそのまま実行されてしまうため、方式の判定（`setns` の前）が
//!    ディレクトリへの問い合わせで `EACCES`（対応）を確かめた場合にだけ封印した複製を選ぶ
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
//! エラーで、違反にはせず `FailedPrecondition` で拒否する（子の中で現行方式へは切り替えない。切り替えは `setns` の
//! 前の判定でだけ行い、記録する）。
//!
//! シェバンのインタープリタ・`PT_INTERP` の動的リンカは複製しない（カーネルが元のファイルとして開く）ため、
//! それらの `noexec`・実行権限・Landlock・LSM の検査はカーネルがそのまま行う（本モジュールの対象は本体の複製だけ）。
//!
//! 限界: 手順 0 の環境の判定（[`SealPolicy::probe`]）はホスト側の securityfs（`/sys/kernel/security/lsm`。`fstatfs` で
//! securityfs と確かめてから読む）に依る。判定できない入力はすべて封印した複製を使わない側に倒す。封印した複製を使える
//! （それ以外は現行方式）のは、(a) Linux 6.14 以上（`AT_EXECVE_CHECK`）、かつ (b) 有効な LSM が許可リスト（`capability`・
//! `lockdown`・`yama`・`landlock`・`loadpin`・`safesetid`）に収まる（`apparmor`・`selinux`・`tomoyo`・`smack`・`bpf`・
//! `ipe`・`ima`・`evm`・`integrity` や未知の LSM が無い）ホストだけ。例えば Ubuntu の既定（LSM が
//! `lockdown,capability,landlock,yama,apparmor,ima,evm`）は `lsm_apparmor`、AppArmor を外しても `lsm_ima` で現行方式に
//! なる。これらのホストでは照合と `execveat` の間の書き換え（#1458 の論点）が残余のリスクとして残る。IMA の memfd に
//! 対する挙動を一次情報で確かめられれば、計測専用の環境などは将来緩められる。詳細は `interpreter.rs` の
//! 「方式の切り替え」と「限界」。

use std::ffi::CStr;
use std::fs::{File, FileType, Metadata};
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::sys::{self, SealError, SealedReadOnlyCopy, SysError};
use crate::traits::types::ErrorCode;

use super::entrypoint_mode::{
    EntrypointExecMode, IntegrityLsm, PathBoundLsm, SealedCopyUnavailable,
};
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

/// エントリポイントの実行方式の判定結果と、封印した複製の手順 2 の扱い（#1531・SEC-1。モジュール doc の手順 0・2）。
///
/// `prepare_exec_restrictions` が `setns` の **前**（ホスト側の securityfs が見えるうち）に [`SealPolicy::probe`]
/// で作り、`ExecReady` → `spawn_exec_command` → exec の子へ持ち越す。子は [`SealPolicy::mode`] に従い、封印した複製
/// （[`seal_entrypoint_copy`]）か現行方式（照合した元の fd をそのまま実行する。#1478）で実行する（オーナー判断
/// 2026-10-09「条件付き切り替え」。モジュール doc「方式の切り替え」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SealPolicy {
    mode: EntrypointExecMode,
    exec_check: ExecCheck,
}

/// `AT_EXECVE_CHECK` の有無の判定結果（[`probe_exec_check_support`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecCheckSupport {
    /// カーネルが `AT_EXECVE_CHECK` を知っている（Linux 6.14+）。
    Supported,
    /// 知らない（`EINVAL`）。
    Unsupported,
    /// 判定できなかった（想定外の結果）。
    Unknown,
}

/// 手順 2（`AT_EXECVE_CHECK`）の扱い。本番の入口（[`SealPolicy::probe`]）は常に [`ExecCheck::Required`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecCheck {
    /// 必須。封印した複製の手順 2 で `AT_EXECVE_CHECK` を知らないカーネル（6.14 未満）なら拒否する（fail-closed。
    /// 本番は事前の判定が 6.14 未満で封印した複製を選ばないため、通常はここに来ない）。
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
    /// 維持できない（または判定できない）ため複製しない。値は機械可読な理由。
    Refuse(SealedCopyUnavailable),
}

/// 有効な LSM の一覧（`/sys/kernel/security/lsm` の内容。読み取りの失敗は `Err` のまま渡す）から LSM の環境を判定する
/// （純粋関数。単体テストが具体値で確かめる）。
///
/// 許可リスト方式（fail-closed）: 複製しても exec 後の拘束が変わらないと分かっている名前（[`LSM_SAFE`]）だけを通す。
/// 一覧の順に見て、最初に見つかった許可リスト外の LSM を理由にする（既知のパス・ラベル結び付きの LSM・SELinux・
/// 完全性検査系〔IMA・EVM・integrity〕は理由を区別し、それ以外の未知の名前は `lsm_unrecognized`）。一覧を読めない・
/// 空・`capability`（常に有効な LSM）を含まない場合は、一覧として信用できないため `lsm_list_unreadable`。
///
/// 完全性検査系は、計測専用のポリシー（`ima_policy=tcb` 等）でも、memfd からの実行が計測されない、または元のパスで
/// 記録されないおそれがあるため、`/proc/cmdline`・IMA の policy の内容に依らず封印した複製を使わない（#1579 の独立
/// 監査 P2-1。一次照合が済めば緩められる。[`IntegrityLsm`] の doc）。
pub(super) fn assess_lsm_environment(lsm_list: std::io::Result<String>) -> LsmEnvironment {
    let list = match lsm_list {
        Ok(list) => list,
        Err(_) => return LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable),
    };
    let names: Vec<&str> = list
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    if !names.contains(&"capability") {
        // 空・空白のみ・`capability` を含まない一覧は、securityfs の正しい内容ではない。
        return LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable);
    }
    for name in &names {
        if let Some(lsm) = PathBoundLsm::ALL
            .into_iter()
            .find(|l| l.lsm_name() == *name)
        {
            return LsmEnvironment::Refuse(SealedCopyUnavailable::PathBoundLsm(lsm));
        }
        if *name == "selinux" {
            return LsmEnvironment::Refuse(SealedCopyUnavailable::Selinux);
        }
        if let Some(lsm) = IntegrityLsm::ALL
            .into_iter()
            .find(|l| l.lsm_name() == *name)
        {
            return LsmEnvironment::Refuse(SealedCopyUnavailable::IntegrityLsm(lsm));
        }
        if !LSM_SAFE.contains(name) {
            return LsmEnvironment::Refuse(SealedCopyUnavailable::UnrecognizedLsm);
        }
    }
    // Landlock はここで拒否しない。exec の子は自前の Landlock ルールセットを必ず適用してから `ExecReady` を返す
    // （SUP-6）ため、有効な環境を一律に拒否すると本番の exec が成立しない。元のファイルへの `EXECUTE` は、継承した
    // domain を含む全層を、手順 2 の `AT_EXECVE_CHECK` がカーネルの規則（inode 単位）のまま判定する（CORE-5・SEC-1）。
    LsmEnvironment::Unrestricted
}

/// 複製しても exec の許可・exec 後の拘束が変わらないと分かっている LSM（許可リスト）。`capability`・`yama`・
/// `lockdown`・`loadpin`（カーネルモジュール等の読み込み元を制限）・`safesetid`（UID 遷移の制限）は実行するファイルの
/// パス・ラベルに結び付いた exec 時の判定を持たない。`landlock` の `EXECUTE` は手順 2 の `AT_EXECVE_CHECK` が判定する。
const LSM_SAFE: [&str; 6] = [
    "capability",
    "lockdown",
    "yama",
    "landlock",
    "loadpin",
    "safesetid",
];

/// `AT_EXECVE_CHECK` の有無を、実行され得ないディレクトリ（`/`）の fd への問い合わせで判定する（`setns` の前に呼ぶ）。
///
/// 対応カーネルはディレクトリを実行対象にできず `EACCES`、6.14 未満はフラグを `EINVAL` で拒否する（どちらも何も
/// 実行しない。この問い合わせはディレクトリを渡すため、仮にフラグが無視されても実行は起きない。これはこの問い合わせに
/// だけ成り立つ性質で、exec の子の手順 2 が通常ファイルへ掛ける `AT_EXECVE_CHECK` は、カーネルが未知のフラグを
/// `EINVAL` で拒否する挙動〔`do_open_execat` のフラグ検査〕に依る。手順 2 の doc を参照）。カーネル版の文字列は
/// 解釈しない（ディストリビューションの backport に依らず、実際の挙動で決める）。
fn probe_exec_check_support() -> ExecCheckSupport {
    match File::open("/") {
        Ok(dir) => classify_exec_check_probe(sys::exec_check_fd(dir.as_fd())),
        Err(_) => ExecCheckSupport::Unknown,
    }
}

/// [`probe_exec_check_support`] の判定部（純関数）。`EACCES` だけを対応、`EINVAL` だけを非対応とし、それ以外
/// （成功を含む）は判定不能にする。
fn classify_exec_check_probe(result: Result<(), SysError>) -> ExecCheckSupport {
    match result {
        Err(SysError::Os(errno)) if errno == sys::EACCES => ExecCheckSupport::Supported,
        Err(SysError::Os(errno)) if errno == sys::EINVAL => ExecCheckSupport::Unsupported,
        _ => ExecCheckSupport::Unknown,
    }
}

/// `AT_EXECVE_CHECK` の有無と LSM の環境から実行方式を決める（純関数。単体テストが環境ごとの方式と理由コードを
/// 具体値で照合する）。カーネルの判定を先に見る（6.14 未満では LSM に依らず封印した複製を使えない）。
pub(super) fn decide_entrypoint_mode(
    support: ExecCheckSupport,
    lsm: LsmEnvironment,
) -> EntrypointExecMode {
    let reason = match (support, lsm) {
        (ExecCheckSupport::Unsupported, _) => SealedCopyUnavailable::KernelTooOld,
        (ExecCheckSupport::Unknown, _) => SealedCopyUnavailable::ExecCheckProbeFailed,
        (ExecCheckSupport::Supported, LsmEnvironment::Refuse(reason)) => reason,
        (ExecCheckSupport::Supported, LsmEnvironment::Unrestricted) => {
            return EntrypointExecMode::SealedCopy;
        }
    };
    EntrypointExecMode::PinnedInode { reason }
}

/// securityfs の `statfs.f_type`（include/uapi/linux/magic.h の `SECURITYFS_MAGIC`。アーキテクチャ非依存）。
const SECURITYFS_MAGIC: i64 = 0x7363_6673;

/// `path` を開き、開いた fd のファイルシステムが `magic`（`sys::fs_type`）であることを確かめてから `cap` バイトまで
/// 読む（#1579 の独立監査 P3-2。`/sys/kernel/security` に別の FS が載った環境で、固定の内容を読んで判定を誤らない。
/// 既存の procfs の検証と同じ流儀）。種別が違えば `InvalidData`（呼び出し側は読めなかった入力として拒否に倒す）。
fn read_capped_on(path: &str, magic: i64, cap: u64) -> std::io::Result<String> {
    let file = File::open(path)?;
    if sys::fs_type(file.as_fd()) != Ok(magic) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "security configuration input is not on the expected filesystem",
        ));
    }
    read_capped_from(file, cap)
}

/// `reader` を `cap` バイトまで読む（巨大ファイルの確保を避ける）。`cap` を超えて続く場合は切り詰めず
/// `InvalidData` で失敗させる（先頭だけを見て判定すると、後続の名前を見落として誤って通すため。呼び出し側は
/// 読めなかった入力を拒否に倒す。fail-closed）。
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
    /// ホスト側の実環境から方式を判定して作る（封印した複製の手順 2 の `AT_EXECVE_CHECK` は必須）。`setns` の前に呼ぶこと。
    pub(super) fn probe() -> Self {
        let lsm = assess_lsm_environment(read_capped_on(
            "/sys/kernel/security/lsm",
            SECURITYFS_MAGIC,
            4096,
        ));
        Self {
            mode: decide_entrypoint_mode(probe_exec_check_support(), lsm),
            exec_check: ExecCheck::Required,
        }
    }

    /// 判定した実行方式。
    pub(super) fn mode(&self) -> EntrypointExecMode {
        self.mode
    }

    /// 判定材料を直接指定する（単体テスト専用。LSM が拒否なら現行方式、そうでなければ封印した複製）。
    #[cfg(test)]
    pub(super) fn new(lsm: LsmEnvironment, exec_check: ExecCheck) -> Self {
        Self {
            mode: decide_entrypoint_mode(ExecCheckSupport::Supported, lsm),
            exec_check,
        }
    }

    /// 封印した複製・`AT_EXECVE_CHECK` は対応カーネルでだけ行う（`execveat` を行わない観測・単体テスト専用。
    /// 本番の入口は [`SealPolicy::probe`] だけ）。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(super) fn unrestricted() -> Self {
        Self {
            mode: EntrypointExecMode::SealedCopy,
            exec_check: ExecCheck::IfSupported,
        }
    }

    /// 現行方式を選んだ判定（観測・単体テスト専用。`reason` は記録される理由）。
    #[cfg(any(test, feature = "exec-test-support"))]
    pub(super) fn pinned(reason: SealedCopyUnavailable) -> Self {
        Self {
            mode: EntrypointExecMode::PinnedInode { reason },
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
    check_sealed_mode(policy.mode, subject)?;
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

/// 手順 0: 判定が封印した複製を選んでいるか（現行方式の判定で本関数へ来たら、呼び出し側の誤りとして拒否する。
/// 呼び出し側の `prepare_exec_child` は現行方式なら複製を作らない）。
fn check_sealed_mode(mode: EntrypointExecMode, subject: &Path) -> Result<(), ExecError> {
    match mode {
        EntrypointExecMode::SealedCopy => Ok(()),
        EntrypointExecMode::PinnedInode { reason } => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "refusing to run {subject:?} from a sealed copy: {}",
                reason.message()
            ),
        )),
    }
}

/// 手順 1: 元のファイルの fd が開かれているマウントが `noexec` でないか（`fstatfs` の `ST_NOEXEC`）。
///
/// `execveat` は元のファイルのマウントの `noexec` で拒否するが、memfd の複製は内部マウント上にあり拒否されない。
/// パスを再解決せず fd のマウントを見るため、照合した実体と判定の対象がずれない。`noexec` は違反
/// [`ViolationReason::EntrypointOnNoexecMount`]、フラグを確かめられない（`fstatfs` の失敗・`ST_VALID` なし）
/// 場合は拒否する（fail-closed）。
pub(super) fn check_not_on_noexec_mount(file: &File, subject: &Path) -> Result<(), ExecError> {
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
    use crate::landlock::AccessFs;
    use crate::test_support::{TestTempDir, kernel_at_least, write_file_in_child};

    fn assess(lsm: &str) -> LsmEnvironment {
        assess_lsm_environment(Ok(lsm.to_owned()))
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: パス結び付きの LSM（AppArmor 等）が有効な環境は、封印した複製を
    /// 使わない。LSM 一覧を読めない場合も同じ（fail-closed）。理由コード・文言は具体値。
    #[test]
    fn sup6_sec1_path_bound_lsm_environment_is_refused() {
        for (lsm, which, code) in [
            (
                "lockdown,capability,landlock,yama,apparmor",
                PathBoundLsm::AppArmor,
                "lsm_apparmor",
            ),
            ("capability,tomoyo", PathBoundLsm::Tomoyo, "lsm_tomoyo"),
            ("capability,smack", PathBoundLsm::Smack, "lsm_smack"),
            ("capability,bpf", PathBoundLsm::Bpf, "lsm_bpf"),
            ("capability,ipe", PathBoundLsm::Ipe, "lsm_ipe"),
        ] {
            let reason = SealedCopyUnavailable::PathBoundLsm(which);
            assert_eq!(assess(lsm), LsmEnvironment::Refuse(reason), "{lsm}");
            assert_eq!(reason.as_str(), code);
            assert_eq!(
                reason.message(),
                "a path-bound security module is active; its exec-time checks cannot be reproduced for a sealed copy"
            );
        }
        assert_eq!(
            assess_lsm_environment(Err(std::io::ErrorKind::NotFound.into())),
            LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable)
        );
        assert_eq!(
            SealedCopyUnavailable::LsmListUnreadable.message(),
            "the active security modules could not be read or did not form a valid list"
        );
    }

    /// SEC-1・CORE-5・#1579（独立監査 P3-1）: 空・空白のみ・`capability` を含まない一覧は、securityfs の正しい内容では
    /// ないため `lsm_list_unreadable`（許可リストの名前だけでも `capability` が無ければ通さない）。
    #[test]
    fn sec1_core5_invalid_lsm_list_is_refused() {
        for lsm in ["", " ", "\n", ",,", "landlock,yama", "lockdown,landlock"] {
            assert_eq!(
                assess(lsm),
                LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable),
                "{lsm:?}"
            );
        }
        assert_eq!(assess("capability"), LsmEnvironment::Unrestricted);
    }

    /// SEC-1・CORE-5・#1579（独立監査 P2-1）: 許可リストに無い LSM（未知の名前・将来追加される LSM）が 1 つでも
    /// 有効なら、拒否リストに載っていなくても封印した複製を使わない（fail-closed）。許可リストだけの環境は通す。
    #[test]
    fn sec1_core5_unknown_lsm_is_refused() {
        for lsm in [
            "capability,newlsm",
            "lockdown,capability,landlock,yama,mystery",
            "capability,LANDLOCK",
            "capability,landlock2",
        ] {
            assert_eq!(
                assess(lsm),
                LsmEnvironment::Refuse(SealedCopyUnavailable::UnrecognizedLsm),
                "{lsm}"
            );
        }
        assert_eq!(
            SealedCopyUnavailable::UnrecognizedLsm.as_str(),
            "lsm_unrecognized"
        );
        assert_eq!(
            SealedCopyUnavailable::UnrecognizedLsm.message(),
            "an unrecognized security module is active; its exec-time checks cannot be ruled out for a sealed copy"
        );
        assert_eq!(
            assess("capability,lockdown,yama,landlock,loadpin,safesetid"),
            LsmEnvironment::Unrestricted
        );
        // 末尾の改行・空要素は名前として扱わない。
        assert_eq!(
            assess("capability,landlock,\n"),
            LsmEnvironment::Unrestricted
        );
    }

    /// SEC-1・CORE-5・#1579（独立監査 P2-1）: 完全性検査系の LSM（IMA・EVM・integrity）が有効なら、計測専用の
    /// ポリシーかどうかに依らず封印した複製を使わない（理由 `lsm_ima`・`lsm_evm`・`lsm_integrity`）。一覧の順で最初の
    /// 許可リスト外の LSM が理由になる（Ubuntu の既定は AppArmor が先に現れて `lsm_apparmor`）。
    #[test]
    fn sec1_core5_integrity_lsm_is_refused() {
        for (lsm, which, code) in [
            ("capability,ima", IntegrityLsm::Ima, "lsm_ima"),
            (
                "lockdown,capability,landlock,yama,ima,evm",
                IntegrityLsm::Ima,
                "lsm_ima",
            ),
            ("capability,evm", IntegrityLsm::Evm, "lsm_evm"),
            (
                "capability,integrity",
                IntegrityLsm::Integrity,
                "lsm_integrity",
            ),
        ] {
            let reason = SealedCopyUnavailable::IntegrityLsm(which);
            assert_eq!(assess(lsm), LsmEnvironment::Refuse(reason), "{lsm}");
            assert_eq!(reason.as_str(), code);
            assert_eq!(
                reason.message(),
                "an integrity security module (IMA/EVM) is active; its measurement and appraisal of the original file cannot be guaranteed for a sealed copy"
            );
        }
        assert_eq!(
            assess("lockdown,capability,landlock,yama,apparmor,ima,evm"),
            LsmEnvironment::Refuse(SealedCopyUnavailable::PathBoundLsm(PathBoundLsm::AppArmor))
        );
    }

    /// SUP-6・SEC-1・CORE-5・TASK-163 追補・#1531: 対象外の LSM のみの環境は制約なし。SELinux が有効な環境は
    /// （ドメインを根拠に通さず）封印した複製を使わない。Landlock のみ有効な環境は通す（#1579 の P1。`EXECUTE` は
    /// `AT_EXECVE_CHECK` がカーネルの規則で判定する）。
    #[test]
    fn sup6_sec1_unrelated_environment_is_unrestricted_and_selinux_is_refused_but_landlock_is_not()
    {
        assert_eq!(
            assess("lockdown,capability,yama"),
            LsmEnvironment::Unrestricted
        );
        for lsm in ["capability,landlock,selinux", "capability,selinux"] {
            assert_eq!(
                assess(lsm),
                LsmEnvironment::Refuse(SealedCopyUnavailable::Selinux),
                "{lsm}"
            );
        }
        assert_eq!(SealedCopyUnavailable::Selinux.as_str(), "lsm_selinux");
        assert_eq!(
            SealedCopyUnavailable::Selinux.message(),
            "SELinux is active; the exec-time permission and transition for the original file label cannot be reproduced for a sealed copy"
        );
        for lsm in ["capability,landlock", "lockdown,capability,landlock,yama"] {
            assert_eq!(assess(lsm), LsmEnvironment::Unrestricted, "{lsm}");
        }
    }

    /// SEC-1・CORE-5・#1531: 上限を超えて続く入力は切り詰めず失敗させる（先頭だけで判定して後続の名前を見落とさない）。
    /// 上限ちょうどは読める。上限を超えた一覧は `lsm_list_unreadable` に倒れる。
    #[test]
    fn sec1_core5_read_capped_rejects_input_over_the_cap() {
        assert_eq!(read_capped_from(&b"abcd"[..], 4).expect("at cap"), "abcd");
        let err = read_capped_from(&b"abcde"[..], 4).expect_err("over cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // 先頭が上限内でも、後続にパス結び付きの LSM があれば読めない = 拒否に倒れる。
        let mut list = b"capability,landlock".to_vec();
        list.resize(1024, b' ');
        list.extend_from_slice(b",apparmor");
        assert_eq!(
            assess_lsm_environment(read_capped_from(&list[..], 1024)),
            LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable)
        );
    }

    /// SEC-1・#1579（独立監査 P3-2）: 判定の入力は、期待するファイルシステム上にあることを確かめてから読む。procfs の
    /// `/proc/self/status` は procfs の magic なら読め、securityfs の magic を期待すると `InvalidData` で拒否される。
    #[test]
    fn sec1_read_capped_on_checks_the_filesystem() {
        assert_eq!(SECURITYFS_MAGIC, 0x7363_6673);
        let text = read_capped_on("/proc/self/status", sys::PROC_MAGIC, 64 * 1024).expect("procfs");
        assert!(text.starts_with("Name:"), "{text}");
        let err = read_capped_on("/proc/self/status", SECURITYFS_MAGIC, 64 * 1024)
            .expect_err("not securityfs");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            assess_lsm_environment(read_capped_on("/proc/self/status", SECURITYFS_MAGIC, 4096)),
            LsmEnvironment::Refuse(SealedCopyUnavailable::LsmListUnreadable)
        );
    }

    /// 試験ごとの作業ディレクトリ（排他的に作る。drop で削除）。
    struct Scratch(TestTempDir);

    impl Scratch {
        fn new(label: &str) -> Self {
            Self(TestTempDir::new(&format!("sealed-copy-{label}")).expect("temp dir"))
        }

        /// `mode` の通常ファイルを作り、読み取り専用で開いて返す。書き込みは子プロセスで行い、試験プロセスに
        /// 書き込み用 fd を持たせない（他スレッドの fork が継承して `AT_EXECVE_CHECK` が `ETXTBSY` になるのを防ぐ。#1686）。
        fn file(&self, name: &str, content: &[u8], mode: u32) -> File {
            let path = self.0.path().join(name);
            write_file_in_child(&path, content).expect("write in child");
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
        // `AT_EXECVE_CHECK` は判定中に同一 fs_struct のスレッド生成を EAGAIN にするため、私有 fs のスレッドで
        // 呼ぶ（#1685）。
        crate::test_support::run_with_private_fs(|| {
            seal_copy_bounded(
                file,
                file_type,
                size,
                limit,
                procfs.as_fd(),
                Path::new("/script"),
                policy,
            )
        })
    }

    /// SUP-6・SEC-1・TASK-163 追補・#1531: 環境が維持できないと判定された場合、複製の手順に入らず
    /// `FailedPrecondition`（違反にしない）で拒否する。
    #[test]
    fn sup6_sec1_refused_environment_stops_before_copy() {
        let scratch = Scratch::new("refuse-env");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o755);
        let policy = SealPolicy::new(
            LsmEnvironment::Refuse(SealedCopyUnavailable::UnrecognizedLsm),
            ExecCheck::Required,
        );
        let err = seal(&file, 10, MAX_SEALED_COPY_BYTES, &policy).expect_err("refused");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(violation_of(&err), None);
        assert_eq!(
            err.message,
            "refusing to run \"/script\" from a sealed copy: an unrecognized security module is active; its exec-time checks cannot be ruled out for a sealed copy"
        );
    }

    /// SUP-6・SEC-1・REPAIR-4・#1531（オーナー判断 2026-10-09「条件付き切り替え」）: 環境ごとに選ばれる実行方式と
    /// 理由コードの具体値。6.14 以上・許可リストの LSM のみ・IMA の条件を満たすときだけ封印した複製で、それ以外は
    /// 現行方式と理由（カーネルの判定を LSM より先に見る）。
    #[test]
    fn sup6_repair4_entrypoint_mode_decision_per_environment() {
        let code = |m: EntrypointExecMode| {
            (
                m.as_str(),
                m.fallback_reason()
                    .map_or("-", SealedCopyUnavailable::as_str),
            )
        };
        use ExecCheckSupport::{Supported, Unknown, Unsupported};
        for (support, lsm, expected) in [
            (
                Supported,
                "lockdown,capability,landlock,yama",
                ("sealed_copy", "-"),
            ),
            (
                Supported,
                "capability,lockdown,yama,landlock,loadpin,safesetid",
                ("sealed_copy", "-"),
            ),
            // Ubuntu の既定（監査環境）: 一覧の順で AppArmor が先に現れる。
            (
                Supported,
                "lockdown,capability,landlock,yama,apparmor,ima,evm",
                ("pinned_inode", "lsm_apparmor"),
            ),
            // AppArmor を外しても IMA が有効なら現行方式（計測専用でも。独立監査 P2-1）。
            (
                Supported,
                "lockdown,capability,landlock,yama,ima,evm",
                ("pinned_inode", "lsm_ima"),
            ),
            (Supported, "capability,evm", ("pinned_inode", "lsm_evm")),
            (
                Supported,
                "capability,selinux",
                ("pinned_inode", "lsm_selinux"),
            ),
            (
                Supported,
                "capability,mystery",
                ("pinned_inode", "lsm_unrecognized"),
            ),
            (Supported, "", ("pinned_inode", "lsm_list_unreadable")),
            (
                Supported,
                "landlock,yama",
                ("pinned_inode", "lsm_list_unreadable"),
            ),
            // 6.14 未満は LSM に依らず kernel_too_old（カーネルの判定を先に見る）。
            (
                Unsupported,
                "lockdown,capability,landlock,yama",
                ("pinned_inode", "kernel_too_old"),
            ),
            (
                Unsupported,
                "capability,apparmor",
                ("pinned_inode", "kernel_too_old"),
            ),
            (
                Unknown,
                "capability",
                ("pinned_inode", "exec_check_probe_failed"),
            ),
        ] {
            assert_eq!(
                code(decide_entrypoint_mode(support, assess(lsm))),
                expected,
                "{support:?} {lsm:?}"
            );
        }
        assert_eq!(
            code(decide_entrypoint_mode(
                Supported,
                assess_lsm_environment(Err(std::io::ErrorKind::PermissionDenied.into()))
            )),
            ("pinned_inode", "lsm_list_unreadable")
        );
    }

    /// SUP-6・#1531: `AT_EXECVE_CHECK` の有無の判定。ディレクトリへの問い合わせが `EACCES` なら対応、`EINVAL` なら
    /// 非対応、それ以外（成功を含む）は判定不能。実カーネルでの結果は `/proc/sys/kernel/osrelease` と一致する。
    #[test]
    fn sup6_exec_check_probe_classification() {
        assert_eq!(
            classify_exec_check_probe(Err(SysError::Os(sys::EACCES))),
            ExecCheckSupport::Supported
        );
        assert_eq!(
            classify_exec_check_probe(Err(SysError::Os(sys::EINVAL))),
            ExecCheckSupport::Unsupported
        );
        for other in [
            Ok(()),
            Err(SysError::Os(sys::EPERM)),
            Err(SysError::Unsupported),
        ] {
            assert_eq!(classify_exec_check_probe(other), ExecCheckSupport::Unknown);
        }
        let expected = if kernel_at_least(6, 14) {
            ExecCheckSupport::Supported
        } else {
            ExecCheckSupport::Unsupported
        };
        assert_eq!(probe_exec_check_support(), expected);
    }

    /// SUP-6・#1531: 現行方式の判定で複製の手順へ来たら、複製せずに `FailedPrecondition`（理由の文言つき）で拒否する。
    #[test]
    fn sup6_pinned_mode_never_copies() {
        let scratch = Scratch::new("pinned");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o755);
        let policy = SealPolicy::pinned(SealedCopyUnavailable::KernelTooOld);
        let err = seal(&file, 10, MAX_SEALED_COPY_BYTES, &policy).expect_err("pinned");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(violation_of(&err), None);
        assert_eq!(
            err.message,
            "refusing to run \"/script\" from a sealed copy: AT_EXECVE_CHECK is unavailable (Linux 6.14 or later is required); the original file cannot be checked before copying it"
        );
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
    /// 通り、6.14 未満では同じく `FailedPrecondition`（判定できないまま複製しない）。本試験は封印した複製の手順を直接
    /// 呼ぶ。本番は 6.14 未満なら事前の判定（`decide_entrypoint_mode`）が現行方式を選び（理由 `kernel_too_old`）、
    /// 元の fd の `execveat` が実行ビットのないファイルを拒否するため、この手順には来ない。
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

    /// SEC-1・CORE-5・TASK-163 追補（#1531）: 実カーネルの Landlock の下で、読み取りはできるが `EXECUTE` を許されない
    /// 元のファイルは、`AT_EXECVE_CHECK` により複製の前に `PermissionDenied`（違反なし）で拒否され、`EXECUTE` を許された
    /// 対照は複製できる（memfd 自体は Landlock のルール外で実行できるため、元のファイルへの判定が `EXECUTE` の拒否を
    /// 維持する境界になる）。呼び出し側から継承した domain の拒否も維持されることを、「`allowed/` だけに `EXECUTE` を
    /// 許す層」の上に「`/` 全体に `EXECUTE` を許す層」（exec の子が自前で積む層に相当）を重ねて確かめる。
    ///
    /// Landlock の適用は呼び出したスレッドだけに効き不可逆なため、専用のスレッドを作って適用し、試験の後に捨てる
    /// （`NO_NEW_PRIVS` もスレッド単位）。Linux 6.14 未満（`/proc/sys/kernel/osrelease`）では `AT_EXECVE_CHECK` が
    /// 無く、封印した複製の手順を必須の方針で直接呼ぶ本試験では両方とも `FailedPrecondition` になる（Landlock は
    /// 適用しない。本番は事前の判定で現行方式になり、元の fd の `execveat` がカーネルの規則のまま `EXECUTE` を判定する）。
    /// 6.14 以降で Landlock を使えない環境は skip せず失敗する。
    #[test]
    fn sec1_core5_landlock_execute_denial_survives_the_copy() {
        let scratch = Scratch::new("landlock");
        let root = scratch.0.path().to_path_buf();
        for sub in ["allowed", "denied"] {
            std::fs::create_dir(root.join(sub)).expect("mkdir");
            let path = root.join(sub).join("script");
            write_file_in_child(&path, b"#!/bin/sh\nexit 0\n").expect("write in child");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let supported = kernel_at_least(6, 14);
        let worker = std::thread::spawn(move || {
            if supported {
                let execute = AccessFs::EXECUTE.bits();
                let layer = |beneath: &Path| {
                    let ruleset = sys::landlock_create_ruleset_fs(execute).expect("create ruleset");
                    let dir = File::open(beneath).expect("open rule dir");
                    sys::landlock_add_path_beneath(ruleset.as_fd(), execute, dir.as_fd())
                        .expect("add rule");
                    sys::landlock_restrict_self(ruleset.as_fd()).expect("restrict self");
                };
                sys::set_no_new_privs().expect("no_new_privs");
                // 継承した層（呼び出し側の制限に相当）: `allowed/` の配下だけ `EXECUTE` を許す。
                layer(&root.join("allowed"));
                // 自前の層に相当: `/` 全体に `EXECUTE` を許す（継承した層の拒否を緩められないことを確かめる）。
                layer(Path::new("/"));
            }
            let outcome = |sub: &str| {
                let file = File::open(root.join(sub).join("script")).expect("open script");
                seal(&file, 17, MAX_SEALED_COPY_BYTES, &required())
                    .map(|copy| copy.metadata().len())
                    .map_err(|e| (e.code, violation_of(&e)))
            };
            (outcome("allowed"), outcome("denied"))
        });
        let (allowed, denied) = worker.join().expect("landlock worker thread");
        if supported {
            assert_eq!(allowed, Ok(17));
            assert_eq!(denied, Err((ErrorCode::PermissionDenied, None)));
        } else {
            assert_eq!(allowed, Err((ErrorCode::FailedPrecondition, None)));
            assert_eq!(denied, Err((ErrorCode::FailedPrecondition, None)));
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
