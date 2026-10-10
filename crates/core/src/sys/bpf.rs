//! デバイス cgroup 用の `bpf(2)` の薄いラッパー（`BPF_PROG_LOAD`・`BPF_PROG_ATTACH`・`BPF_PROG_QUERY`。
//! TASK-32 追補・MS-2・#1679・SEC-1・CORE-1・CORE-4。`unsafe` 事前承認の範囲の `sys` 子モジュール）。
//!
//! # 役割と呼び出し文脈
//! `crate::cgroups` が組み立てた封印済みの命令列（`DeviceProgram`。#1678）を、カーネルへロード
//! （[`bpf_prog_load_cgroup_device`]）し、コンテナの cgroup に付け（[`bpf_prog_attach_cgroup_device`]）、
//! 付いたことを問い合わせる（[`bpf_prog_query_cgroup_device`]）低レベル層。`ContainerCgroup` への入口・
//! 事後検証・rootless 判定・`CgroupError` への写像は #1680、起動経路への結線は #1314、GPU の
//! `deviceNodes` 追加（TASK-129・#562）は本ラッパーの再利用側で、現状は未結線（REPAIR-3）。
//! `libbpf` 系の依存は使わず `syscall(2)` から直接呼ぶ（フルスクラッチ。dependency-policy）。
//! コンテナ側の seccomp は `bpf` を拒否する（`DeniedSyscall::Bpf`）ため、cgroup を作る runtime 側の
//! プロセスで呼ぶ前提で、コンテナの子プロセスからは呼ばない。
//!
//! # 一次情報（Linux v6.12 の `kernel/bpf/{syscall,cgroup,log,token}.c`・`kernel/cgroup/cgroup.c`）
//! - `target_fd` は `O_PATH` の fd でよい。`cgroup_get_from_fd` は `fdget_raw` を使い、cgroup2 の
//!   ディレクトリでなければ `EBADF` を返す。`ContainerCgroup::as_fd()` の fd をそのまま渡せる
//! - ロードに要る権限は init user namespace での `CAP_BPF` と `CAP_NET_ADMIN`
//!   （`CGROUP_DEVICE` は `is_net_admin_prog_type`。どちらも `CAP_SYS_ADMIN` で代替可）。BPF token は
//!   使わない（`prog_flags = 0`）ため user namespace 内の capability は効かず、rootless では適用できない
//! - アタッチ自体に capability の検査は無い（`CGROUP_SKB` だけ検査する）。プログラムの fd と cgroup の
//!   fd を持つことで制限される。問い合わせは `CAP_NET_ADMIN` か `CAP_SYS_ADMIN`（`bpf_net_capable`）
//! - `BPF_PROG_ATTACH` は cgroup 側がプログラムの参照を持つため、prog fd を閉じても外れず、cgroup の
//!   解放時に外れる。`BPF_LINK_CREATE` は link の fd を閉じると外れるため使わない（CORE-1。常駐デーモン無し）
//! - attach flags は 0 に固定する（`BPF_F_ALLOW_OVERRIDE`・`BPF_F_ALLOW_MULTI` を付けない）。祖先が
//!   flags 0 でプログラムを持つと子孫への attach は `EPERM` になる。つまり子孫（exec 用の `exec-*`）は
//!   上書きも追加もできない。逆に祖先が既に flags 0 のプログラムを持つ環境では本 attach が `EPERM`
//!   になる（capability 不足の `EPERM` とは別原因）。同じ cgroup に flags 0 のプログラムが既にあると
//!   黙って置き換わる（扱いは #1680 で決める）
//! - verifier のログは `log_level != 0` のときだけ書かれ、切り詰められると検証に成功しても `ENOSPC` で
//!   ロードが失敗する。このため 1 回目はログ無しでロードし、`EINVAL`・`EACCES`（verifier の拒否）のときだけ
//!   固定上限のバッファ付きで再実行して診断ログを取る
//! - `RLIMIT_MEMLOCK` は扱わない（Linux 5.11 以降は memcg で数える。本リポの前提は 6.12 以降）
//! - 属性は渡した `size` だけが複写され、残りはカーネルが 0 で埋める。QUERY は `attach_flags`・
//!   `prog_cnt` を書き戻す
//!
//! エラーは `SysError` のまま返し、縮退しない（`ENOSYS`・`EINVAL`・`EPERM` を区別できる）。

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "#1680 で ContainerCgroup から結線するまで未使用")
)]

use super::{ENOSPC, SysError, consts, last_error, syscall};
use crate::cgroups::{DEVICE_PROGRAM_LICENSE, DeviceProgram};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};

/// verifier ログの固定上限（バイト）。古いカーネルの最小 128 以上、`UINT_MAX >> 2` 以下。
pub(crate) const BPF_VERIFIER_LOG_CAP: usize = 4096;

/// 問い合わせで受けるプログラム ID の固定上限。カーネルの `BPF_CGROUP_MAX_PROGS`（64。非 effective の
/// 問い合わせが返す数の上限）に合わせる。
pub(crate) const BPF_QUERY_MAX_PROG_IDS: usize = 64;

/// アタッチの attach flags。0 固定（`BPF_F_ALLOW_OVERRIDE`・`BPF_F_ALLOW_MULTI` を付けない。SEC-1）。
const DEVICE_ATTACH_FLAGS: u32 = 0;

/// `union bpf_attr` の `BPF_PROG_LOAD` 用の先頭部分（72 バイト）。暗黙のパディングを作らず全バイトを
/// 名前付きで持つ。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// `union bpf_attr` の `BPF_PROG_ATTACH` 用の部分（32 バイト）。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    relative_fd: u32,
    expected_revision: u64,
}

/// `union bpf_attr` の `BPF_PROG_QUERY` 用の部分（64 バイト）。uapi の無名ビットフィールド
/// （`__u32 :32`）は名前付きの `reserved` で明示する。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct BpfProgQueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    reserved: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

/// ロード済みのデバイス cgroup 用プログラムの fd（close-on-exec）。任意の fd をアタッチへ渡せない
/// ようにする newtype（REPAIR-2）。構築子は本モジュールの中だけ。
#[derive(Debug)]
pub(crate) struct CgroupDeviceProgFd(OwnedFd);

impl CgroupDeviceProgFd {
    /// fd の借用。
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// ロード失敗。`cause` は 1 回目の errno、`verifier_log` は verifier が拒否した場合の切り詰め済み
/// ログ（制御文字は置き換え済み）。`SysError` は `Copy` のため文字列は別フィールドで持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BpfProgLoadError {
    /// 失敗理由（`EPERM`・`ENOSYS`・`EINVAL` 等を区別できる）。
    pub(crate) cause: SysError,
    /// verifier のログ（取得できた場合のみ）。
    pub(crate) verifier_log: Option<String>,
}

/// 問い合わせ結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupDeviceQuery {
    attach_flags: u32,
    prog_count: u32,
    prog_ids: [u32; BPF_QUERY_MAX_PROG_IDS],
}

impl CgroupDeviceQuery {
    /// 組み立てる（実機の戻り値からの変換と単体テストで使う）。
    fn new(attach_flags: u32, prog_count: u32, prog_ids: [u32; BPF_QUERY_MAX_PROG_IDS]) -> Self {
        Self {
            attach_flags,
            prog_count,
            prog_ids,
        }
    }

    /// cgroup に付いているプログラムの数。
    pub(crate) fn prog_count(&self) -> u32 {
        self.prog_count
    }

    /// cgroup の attach flags（0 固定で付けた場合は 0）。
    pub(crate) fn attach_flags(&self) -> u32 {
        self.attach_flags
    }

    /// プログラム ID（`min(prog_count, 上限)` 個）。
    pub(crate) fn prog_ids(&self) -> &[u32] {
        let n = usize::try_from(self.prog_count)
            .unwrap_or(BPF_QUERY_MAX_PROG_IDS)
            .min(BPF_QUERY_MAX_PROG_IDS);
        self.prog_ids.get(..n).unwrap_or(&[])
    }
}

fn fd_u32(fd: RawFd) -> Result<u32, SysError> {
    u32::try_from(fd).map_err(|_| SysError::Os(consts::EBADF))
}

/// LOAD 属性を組み立てる。`log` を渡すと `BPF_LOG_LEVEL1` でそのバッファへ verifier ログを書かせる。
fn load_attr(
    program: &DeviceProgram,
    log: Option<&mut [u8; BPF_VERIFIER_LOG_CAP]>,
) -> Result<BpfProgLoadAttr, SysError> {
    let insn_cnt = u32::try_from(program.len()).map_err(|_| SysError::Os(consts::E2BIG))?;
    let (log_level, log_size, log_buf) = match log {
        Some(buf) => (
            consts::BPF_LOG_LEVEL1,
            u32::try_from(BPF_VERIFIER_LOG_CAP).map_err(|_| SysError::Os(consts::E2BIG))?,
            buf.as_mut_ptr() as u64,
        ),
        None => (0, 0, 0),
    };
    Ok(BpfProgLoadAttr {
        prog_type: consts::BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt,
        insns: program.instructions().as_ptr() as u64,
        license: DEVICE_PROGRAM_LICENSE.as_ptr() as u64,
        log_level,
        log_size,
        log_buf,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type: consts::BPF_CGROUP_DEVICE,
    })
}

fn attach_attr(
    cgroup: BorrowedFd<'_>,
    prog: &CgroupDeviceProgFd,
) -> Result<BpfProgAttachAttr, SysError> {
    Ok(BpfProgAttachAttr {
        target_fd: fd_u32(cgroup.as_raw_fd())?,
        attach_bpf_fd: fd_u32(prog.as_fd().as_raw_fd())?,
        attach_type: consts::BPF_CGROUP_DEVICE,
        attach_flags: DEVICE_ATTACH_FLAGS,
        replace_bpf_fd: 0,
        relative_fd: 0,
        expected_revision: 0,
    })
}

fn query_attr(
    cgroup: BorrowedFd<'_>,
    ids: &mut [u32; BPF_QUERY_MAX_PROG_IDS],
) -> Result<BpfProgQueryAttr, SysError> {
    Ok(BpfProgQueryAttr {
        target_fd: fd_u32(cgroup.as_raw_fd())?,
        attach_type: consts::BPF_CGROUP_DEVICE,
        query_flags: 0,
        attach_flags: 0,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: u32::try_from(BPF_QUERY_MAX_PROG_IDS).map_err(|_| SysError::Os(consts::E2BIG))?,
        reserved: 0,
        prog_attach_flags: 0,
        link_ids: 0,
        link_attach_flags: 0,
        revision: 0,
    })
}

/// verifier ログを文字列にする。最初の NUL までを取り、`\n` 以外の制御文字は `?` に置き換える
/// （構造化ログへの注入対策）。空なら `None`。長さは `BPF_VERIFIER_LOG_CAP - 1` 以下。
fn verifier_log_text(buf: &[u8]) -> Option<String> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let end = end.min(BPF_VERIFIER_LOG_CAP - 1);
    let raw = buf.get(..end)?;
    let text: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c != '\n' && c.is_control() { '?' } else { c })
        .collect();
    if text.is_empty() { None } else { Some(text) }
}

/// `BPF_PROG_LOAD` を 1 回発行する。
fn prog_load_raw(attr: &BpfProgLoadAttr) -> Result<OwnedFd, SysError> {
    let nr = consts::SYS_BPF.get()?;
    // SAFETY: `attr` は呼び出しの間生存する `#[repr(C)]` の 72 バイトで、size 引数も同じ大きさ。
    // `insns` は呼び出し元が借用する `DeviceProgram` の命令列（`repr(C)` の 8 バイトで
    // `struct bpf_insn` と同レイアウト）、`license` は静的な NUL 終端文字列、`log_buf` は `log_size`
    // 以下だけカーネルが書くスタック上のバッファ（または 0）を指し、いずれも呼び出し元の関数が
    // 呼び出しの間保持する。`insn_cnt` は実際の命令数に一致する。未使用の領域は 0。ポインタは
    // カーネルが複写するだけで保持しない。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(consts::BPF_PROG_LOAD),
            std::ptr::from_ref(attr),
            std::mem::size_of::<BpfProgLoadAttr>() as u64,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    let fd = i32::try_from(rc).map_err(|_| SysError::Os(consts::EINVAL))?;
    // SAFETY: 成功した `BPF_PROG_LOAD` が返した新しい fd（`O_RDWR | O_CLOEXEC`）で、他に所有者がおらず
    // 二重 close は起きない。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// デバイス cgroup 用プログラムをロードする。入力は封印した `DeviceProgram` だけ（生の命令列は受けない）。
///
/// 1 回目はログ無しでロードし、`EINVAL`・`EACCES` のときだけ `BPF_LOG_LEVEL1`・固定上限のバッファで
/// 再実行してログを取る。再実行が成功しても fd は閉じて 1 回目のエラーを返す（fail-closed・決定的）。
/// それ以外の errno は再試行もログも無しで返す。
pub(crate) fn bpf_prog_load_cgroup_device(
    program: &DeviceProgram,
) -> Result<CgroupDeviceProgFd, BpfProgLoadError> {
    let plain = |cause| BpfProgLoadError {
        cause,
        verifier_log: None,
    };
    if !consts::SUPPORTED {
        return Err(plain(SysError::Unsupported));
    }
    let attr = load_attr(program, None).map_err(plain)?;
    let cause = match prog_load_raw(&attr) {
        Ok(fd) => return Ok(CgroupDeviceProgFd(fd)),
        Err(e) => e,
    };
    if cause != SysError::Os(consts::EINVAL) && cause != SysError::Os(consts::EACCES) {
        return Err(plain(cause));
    }
    let mut log = [0u8; BPF_VERIFIER_LOG_CAP];
    let verifier_log = match load_attr(program, Some(&mut log)) {
        Ok(attr) => {
            // 成功した場合の fd は包んで直ちに drop（close）する。ENOSPC（切り詰め）でもログは使える。
            drop(prog_load_raw(&attr));
            verifier_log_text(&log)
        }
        Err(_) => None,
    };
    Err(BpfProgLoadError {
        cause,
        verifier_log,
    })
}

/// ロード済みプログラムを cgroup にアタッチする（attach flags は 0 固定）。`cgroup` は O_PATH の fd でよい。
pub(crate) fn bpf_prog_attach_cgroup_device(
    cgroup: BorrowedFd<'_>,
    prog: &CgroupDeviceProgFd,
) -> Result<(), SysError> {
    let nr = consts::SYS_BPF.get()?;
    let attr = attach_attr(cgroup, prog)?;
    // SAFETY: `attr` は呼び出しの間生存する `#[repr(C)]` の 32 バイトで、size 引数も同じ大きさ。
    // fd は生存中の借用が指す。ポインタ類を含まず、カーネルは複写するだけで保持しない。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(consts::BPF_PROG_ATTACH),
            std::ptr::from_ref(&attr),
            std::mem::size_of::<BpfProgAttachAttr>() as u64,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_error()) }
}

/// cgroup に付いているデバイス用プログラムを問い合わせる（attach type `BPF_CGROUP_DEVICE`・query flags 0）。
/// カーネルが返した数が上限を超える場合や `ENOSPC` は fail-closed に `Os(ENOSPC)` で返す。
pub(crate) fn bpf_prog_query_cgroup_device(
    cgroup: BorrowedFd<'_>,
) -> Result<CgroupDeviceQuery, SysError> {
    let nr = consts::SYS_BPF.get()?;
    let mut ids = [0u32; BPF_QUERY_MAX_PROG_IDS];
    let mut attr = query_attr(cgroup, &mut ids)?;
    // SAFETY: `attr` は呼び出しの間生存する書き込み可能な `#[repr(C)]` の 64 バイトで、size 引数も同じ
    // 大きさ。`prog_ids` は書き込み可能な `[u32; 64]` を指し、`prog_cnt`（入力値）は配列の長さに一致し、
    // カーネルはその個数以下しか書かない。書き戻しは `attach_flags`・`prog_cnt`（と size が足りるときの
    // `revision`）で、いずれも構造体の内側。`ids` は呼び出しの間生存する。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(consts::BPF_PROG_QUERY),
            std::ptr::from_mut(&mut attr),
            std::mem::size_of::<BpfProgQueryAttr>() as u64,
        )
    };
    if rc != 0 {
        return Err(last_error());
    }
    let max = u32::try_from(BPF_QUERY_MAX_PROG_IDS).map_err(|_| SysError::Os(ENOSPC))?;
    if attr.prog_cnt > max {
        return Err(SysError::Os(ENOSPC));
    }
    Ok(CgroupDeviceQuery::new(
        attr.attach_flags,
        attr.prog_cnt,
        ids,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroups::DeviceAllowList;
    use std::mem::{offset_of, size_of};

    fn default_program() -> DeviceProgram {
        DeviceProgram::from_allow_list(&DeviceAllowList::oci_default()).unwrap()
    }

    /// SEC-1・TASK-32: bpf 関連定数の固定値照合（x86_64）。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn sec1_task32_bpf_consts_are_exact_x86_64() {
        assert_eq!(
            consts::SYS_BPF.get().map(super::super::SyscallNumber::raw),
            Ok(321)
        );
        assert_bpf_common_consts();
    }

    /// SEC-1・TASK-32: bpf 関連定数の固定値照合（aarch64）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn sec1_task32_bpf_consts_are_exact_aarch64() {
        assert_eq!(
            consts::SYS_BPF.get().map(super::super::SyscallNumber::raw),
            Ok(280)
        );
        assert_bpf_common_consts();
    }

    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn assert_bpf_common_consts() {
        assert_eq!(consts::BPF_PROG_LOAD, 5);
        assert_eq!(consts::BPF_PROG_ATTACH, 8);
        assert_eq!(consts::BPF_PROG_QUERY, 16);
        assert_eq!(consts::BPF_PROG_TYPE_CGROUP_DEVICE, 15);
        assert_eq!(consts::BPF_CGROUP_DEVICE, 6);
        assert_eq!(consts::BPF_LOG_LEVEL1, 1);
        assert_eq!(consts::ENOSPC, 28);
    }

    /// SEC-1・TASK-32・REPAIR-2: 属性構造体の大きさと主なオフセットの照合。
    #[test]
    fn sec1_task32_bpf_attr_layouts_are_exact() {
        assert_eq!(size_of::<BpfProgLoadAttr>(), 72);
        assert_eq!(offset_of!(BpfProgLoadAttr, prog_type), 0);
        assert_eq!(offset_of!(BpfProgLoadAttr, insn_cnt), 4);
        assert_eq!(offset_of!(BpfProgLoadAttr, insns), 8);
        assert_eq!(offset_of!(BpfProgLoadAttr, license), 16);
        assert_eq!(offset_of!(BpfProgLoadAttr, log_level), 24);
        assert_eq!(offset_of!(BpfProgLoadAttr, log_size), 28);
        assert_eq!(offset_of!(BpfProgLoadAttr, log_buf), 32);
        assert_eq!(offset_of!(BpfProgLoadAttr, prog_flags), 44);
        assert_eq!(offset_of!(BpfProgLoadAttr, prog_name), 48);
        assert_eq!(offset_of!(BpfProgLoadAttr, expected_attach_type), 68);
        assert_eq!(size_of::<BpfProgAttachAttr>(), 32);
        assert_eq!(offset_of!(BpfProgAttachAttr, target_fd), 0);
        assert_eq!(offset_of!(BpfProgAttachAttr, attach_bpf_fd), 4);
        assert_eq!(offset_of!(BpfProgAttachAttr, attach_type), 8);
        assert_eq!(offset_of!(BpfProgAttachAttr, attach_flags), 12);
        assert_eq!(offset_of!(BpfProgAttachAttr, expected_revision), 24);
        assert_eq!(size_of::<BpfProgQueryAttr>(), 64);
        assert_eq!(offset_of!(BpfProgQueryAttr, target_fd), 0);
        assert_eq!(offset_of!(BpfProgQueryAttr, attach_type), 4);
        assert_eq!(offset_of!(BpfProgQueryAttr, query_flags), 8);
        assert_eq!(offset_of!(BpfProgQueryAttr, attach_flags), 12);
        assert_eq!(offset_of!(BpfProgQueryAttr, prog_ids), 16);
        assert_eq!(offset_of!(BpfProgQueryAttr, prog_cnt), 24);
        assert_eq!(offset_of!(BpfProgQueryAttr, revision), 56);
    }

    /// SEC-1・TASK-32: ロード属性の値（ログ無し・ログ有り）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_task32_load_attr_fields_are_exact() {
        let program = default_program();
        let attr = load_attr(&program, None).unwrap();
        assert_eq!(attr.prog_type, 15);
        assert_eq!(attr.expected_attach_type, 6);
        assert_eq!(attr.insn_cnt as usize, program.len());
        assert_eq!(attr.insns, program.instructions().as_ptr() as u64);
        assert_eq!(attr.license, DEVICE_PROGRAM_LICENSE.as_ptr() as u64);
        assert_eq!(attr.prog_flags, 0);
        assert_eq!(attr.prog_name, [0; 16]);
        assert_eq!((attr.log_level, attr.log_size, attr.log_buf), (0, 0, 0));

        let mut log = [0u8; BPF_VERIFIER_LOG_CAP];
        let ptr = log.as_mut_ptr() as u64;
        let attr = load_attr(&program, Some(&mut log)).unwrap();
        assert_eq!(attr.log_level, 1);
        assert_eq!(attr.log_size, 4096);
        assert_eq!(attr.log_size as usize, BPF_VERIFIER_LOG_CAP);
        assert_eq!(attr.log_buf, ptr);
    }

    /// SEC-1・TASK-32: アタッチの attach flags は 0 固定。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_task32_attach_attr_flags_are_zero() {
        let cg = std::fs::File::open("/dev/null").unwrap();
        let prog = CgroupDeviceProgFd(OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
        let attr = attach_attr(cg.as_fd(), &prog).unwrap();
        assert_eq!(DEVICE_ATTACH_FLAGS, 0);
        assert_eq!(attr.attach_flags, 0);
        assert_eq!(attr.attach_type, 6);
        assert_eq!(attr.replace_bpf_fd, 0);
        assert_eq!(attr.relative_fd, 0);
        assert_eq!(attr.expected_revision, 0);
        assert_eq!(attr.target_fd as i32, cg.as_raw_fd());
        assert_eq!(attr.attach_bpf_fd as i32, prog.as_fd().as_raw_fd());
    }

    /// SEC-1・TASK-32: 問い合わせ属性の値。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_task32_query_attr_fields_are_exact() {
        let cg = std::fs::File::open("/dev/null").unwrap();
        let mut ids = [0u32; BPF_QUERY_MAX_PROG_IDS];
        let ptr = ids.as_mut_ptr() as u64;
        let attr = query_attr(cg.as_fd(), &mut ids).unwrap();
        assert_eq!(attr.attach_type, 6);
        assert_eq!(attr.query_flags, 0);
        assert_eq!(attr.attach_flags, 0);
        assert_eq!(attr.prog_cnt, 64);
        assert_eq!(BPF_QUERY_MAX_PROG_IDS, 64);
        assert_eq!(attr.prog_ids, ptr);
        assert_eq!(attr.reserved, 0);
        assert_eq!(attr.prog_attach_flags, 0);
        assert_eq!(attr.link_ids, 0);
        assert_eq!(attr.link_attach_flags, 0);
        assert_eq!(attr.revision, 0);
    }

    /// SEC-1・TASK-32: verifier ログの切り詰めと制御文字の置き換え。
    #[test]
    fn sec1_task32_verifier_log_text_is_bounded() {
        assert_eq!(verifier_log_text(b""), None);
        assert_eq!(verifier_log_text(b"\0abc"), None);
        assert_eq!(
            verifier_log_text(b"bad insn\0junk").as_deref(),
            Some("bad insn")
        );
        assert_eq!(
            verifier_log_text(b"a\nb\x1b[0m\0").as_deref(),
            Some("a\nb?[0m")
        );
        assert_eq!(verifier_log_text(b"\xffx\0").as_deref(), Some("\u{fffd}x"));
        let full = [b'a'; BPF_VERIFIER_LOG_CAP];
        assert_eq!(verifier_log_text(&full).map(|s| s.len()), Some(4095));
    }

    /// SEC-1・TASK-32: `prog_ids()` は `min(count, 上限)` 個を返す。
    #[test]
    fn sec1_task32_query_prog_ids_are_bounded() {
        let mut ids = [0u32; BPF_QUERY_MAX_PROG_IDS];
        ids[0] = 7;
        ids[1] = 9;
        let q = CgroupDeviceQuery::new(0, 2, ids);
        assert_eq!(q.prog_ids(), &[7, 9]);
        assert_eq!((q.prog_count(), q.attach_flags()), (2, 0));
        assert_eq!(CgroupDeviceQuery::new(0, 0, ids).prog_ids(), &[] as &[u32]);
        assert_eq!(CgroupDeviceQuery::new(0, 1000, ids).prog_ids().len(), 64);
    }

    /// 対応外 arch ではロードは `Unsupported`（fail-closed）。
    #[cfg(not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    #[test]
    fn sec1_task32_load_is_unsupported_on_unsupported_arch() {
        let e = bpf_prog_load_cgroup_device(&default_program()).unwrap_err();
        assert_eq!(e.cause, SysError::Unsupported);
    }

    /// SEC-1・CORE-4・TASK-32 の実機試験: 一時 cgroup でロード → アタッチ → 問い合わせを行い、
    /// プログラム数 1・attach flags 0・prog fd を閉じても 1 のままであることを照合する。
    ///
    /// 必要環境: root（init user namespace の `CAP_BPF`+`CAP_NET_ADMIN` か `CAP_SYS_ADMIN`）・
    /// cgroup v2・`CONFIG_CGROUP_BPF`。親 cgroup は `FANDHE_BPF_TEST_CGROUP_PARENT`（既定 `/sys/fs/cgroup`）。
    /// 祖先が flags 0 のデバイスプログラムを持つ環境では attach が `EPERM` になる。
    /// 実行は人間が担当する（AGENTS.md の実機前提テストの表を参照）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[ignore = "real-machine test: needs root (CAP_BPF+CAP_NET_ADMIN or CAP_SYS_ADMIN in init userns), cgroup v2 and CONFIG_CGROUP_BPF. SEC-1/CORE-4"]
    fn sec1_core4_task32_device_cgroup_bpf_real_attach() {
        use super::super::{fcntl, mkdir_at, open_dir_path_nofollow, remove_dir_at};
        use std::ffi::CString;

        struct Cleanup(OwnedFd, CString);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Err(e) = remove_dir_at(self.0.as_fd(), &self.1) {
                    eprintln!("failed to remove test cgroup {:?}: {e:?}", self.1);
                }
            }
        }

        let parent_path = std::env::var("FANDHE_BPF_TEST_CGROUP_PARENT")
            .unwrap_or_else(|_| "/sys/fs/cgroup".to_owned());
        let parent = open_dir_path_nofollow(None, &CString::new(parent_path).unwrap()).unwrap();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = CString::new(format!("fc-bpftest-{}-{nanos}", std::process::id())).unwrap();
        mkdir_at(parent.as_fd(), &name, 0o755).unwrap();
        let guard = Cleanup(parent, name.clone());
        // O_PATH の fd をそのまま target_fd に渡す（fdget_raw の実機確認を兼ねる）。
        let child = open_dir_path_nofollow(Some(guard.0.as_fd()), &name).unwrap();

        let hint = "EPERM means missing CAP_BPF/CAP_NET_ADMIN (or CAP_SYS_ADMIN) in the init user namespace, \
                    or an ancestor cgroup already holds a flags-0 device program";
        let prog = bpf_prog_load_cgroup_device(&default_program())
            .unwrap_or_else(|e| panic!("load failed: {e:?} ({hint})"));
        // F_GETFD = 1（全 arch 共通）。
        // SAFETY: 生存中の fd に対する副作用の無い `fcntl(F_GETFD)`。
        let fd_flags = unsafe { fcntl(prog.as_fd().as_raw_fd(), 1) };
        assert_eq!(fd_flags & consts::FD_CLOEXEC, consts::FD_CLOEXEC);

        bpf_prog_attach_cgroup_device(child.as_fd(), &prog)
            .unwrap_or_else(|e| panic!("attach failed: {e:?} ({hint})"));
        let q = bpf_prog_query_cgroup_device(child.as_fd()).unwrap();
        assert_eq!(
            (q.prog_count(), q.attach_flags(), q.prog_ids().len()),
            (1, 0, 1)
        );

        drop(prog);
        let q = bpf_prog_query_cgroup_device(child.as_fd()).unwrap();
        assert_eq!(
            q.prog_count(),
            1,
            "attachment must persist after closing the prog fd"
        );
        drop(child);
        drop(guard);
    }
}
