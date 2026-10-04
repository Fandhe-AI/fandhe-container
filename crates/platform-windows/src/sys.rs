//! Windows 向け FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能（呼び出し元はすべて `wsl2` モジュール。TASK-67.3・WIN-1・REPAIR-5）:
//! - [`system_directory`]: `wsl.exe` のパス解決が、環境変数 `SystemRoot`（起動元が自由に書き換えられる）に
//!   頼らず `GetSystemDirectoryW` で OS が保証するシステムディレクトリを得るために使う。
//! - [`Job`]・[`resume_suspended_threads`]: `wsl.exe` とその子孫を Job Object にまとめ、親が先に終了した
//!   後でも子孫（パイプを握ったままのもの）を終了させるために使う（`wsl2::run`）。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数・型のみ（`unsafe fn` を外へ出さない）。
//! - 宣言・構造体レイアウトは承認済みの `windows-sys`（#371・TASK-67.hdep1）のものを使い、手書きしない。
//! - 取得したハンドルは直ちに `std::os::windows::io::OwnedHandle` へ移し、`Drop` で必ず閉じる（RAII）。
//!   継承可能（`bInheritHandle`）なハンドルは作らない。

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::process::Child;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

/// `CommandExt::creation_flags` に渡す `CREATE_SUSPENDED`（初期スレッドを停止状態で作る）。
///
/// [`Job::assign`] より前に子が子孫を作る競合を防ぐため、`wsl2::run` が起動時に指定する。
pub(crate) const CREATE_SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

/// `GetSystemDirectoryW` で Windows のシステムディレクトリ（通常 `C:\Windows\System32`）を返す。
///
/// 失敗・バッファ不足・空・相対パスの結果は `None`（呼び出し側が fail-closed にする）。
pub(crate) fn system_directory() -> Option<PathBuf> {
    const CAP: usize = 1024;
    let mut buf = [0u16; CAP];
    // SAFETY: `buf` は `CAP` 要素の有効な書き込み可能領域で、`uSize` に同じ `CAP` を渡す。
    // 関数はこの範囲を超えて書かない。成功時の戻り値 `len` は書き込み済みの文字数（NUL 除く）、
    // バッファ不足時は必要サイズ（NUL 込み）、失敗時は 0 なので、`len < CAP` を確認してから
    // `buf.get(..len)` で読む。
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), CAP as u32) } as usize;
    if len == 0 || len >= CAP {
        return None;
    }
    let slice = buf.get(..len)?;
    let path = PathBuf::from(OsString::from_wide(slice));
    path.is_absolute().then_some(path)
}

/// 無名の Job Object（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 付き）の所有ハンドル。
///
/// 割り当てたプロセスとその子孫（以後に生成されたものも自動で同じ Job に入る）は、
/// [`Job::terminate`] または本値の破棄（最後のハンドルが閉じる）で終了する。親プロセスが先に
/// 終了していても子孫を終了できる点が、PID 指定の `taskkill /T` と異なる。
/// 入れ子の Job は Windows 8 以降で使える（CI ランナー等、自プロセスが既に Job に属していてもよい）。
#[derive(Debug)]
pub(crate) struct Job(OwnedHandle);

impl Job {
    /// Job Object を作り、ハンドルが閉じたら所属プロセスを終了する制限を設定する。
    pub(crate) fn new_kill_on_close() -> io::Result<Self> {
        // SAFETY: 引数はどちらも NULL（既定のセキュリティ記述子＝継承不可・無名）で、関数は
        // 引数を読まない。失敗時は NULL を返すので検査してから所有権を取る。
        let raw: HANDLE = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` は直前に作られた有効なハンドルで、他に所有者はいない（閉じるのは
        // `OwnedHandle` の `Drop` だけ）。
        let job = Job(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(|_| io::Error::other("job limit structure is too large"))?;
        // SAFETY: ハンドルは `job` が所有する有効な Job。情報クラス
        // `JobObjectExtendedLimitInformation` に対応する構造体 `info`（windows-sys のレイアウト）への
        // 読み取り専用ポインタと、その正確なサイズを渡す。`info` は呼び出し中有効。
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// `child` を Job に割り当てる（以後の子孫も同じ Job に入る）。
    pub(crate) fn assign(&self, child: &Child) -> io::Result<()> {
        // SAFETY: Job ハンドルは `self` が所有し、プロセスハンドルは `child` を借用している間
        // 有効（`Child` が `Drop` まで閉じない）。関数はどちらのハンドルも閉じない。
        let ok = unsafe { AssignProcessToJobObject(self.raw(), child.as_raw_handle()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Job に属するすべてのプロセスを終了させる（完了は待たない。回収は呼び出し側が期限付きで行う）。
    pub(crate) fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: Job ハンドルは `self` が所有する有効なもので、関数はハンドルを閉じない。
        let ok = unsafe { TerminateJobObject(self.raw(), exit_code) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// `CREATE_SUSPENDED` で起動した `child` のスレッドを再開し、再開したスレッド数を返す。
///
/// Toolhelp のスレッドスナップショットから所有プロセス ID が `child` のものを選んで
/// `ResumeThread` する（`NtResumeProcess` 等の非公開 API は使わない）。`child` のプロセスハンドルを
/// 借用している間は PID が再利用されないので、別プロセスのスレッドを再開することはない。
/// 停止状態で作られたプロセスのスレッドは初期スレッド 1 本だけなので、通常は 1 を返す。
pub(crate) fn resume_suspended_threads(child: &Child) -> io::Result<usize> {
    let pid = child.id();
    // SAFETY: フラグと PID（スレッド列挙では無視される）を値で渡すだけ。失敗時は
    // `INVALID_HANDLE_VALUE` を返すので検査してから所有権を取る。
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` は直前に作られた有効なスナップショットハンドルで、他に所有者はいない。
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let entry_size = u32::try_from(std::mem::size_of::<THREADENTRY32>())
        .map_err(|_| io::Error::other("thread entry structure is too large"))?;
    let mut entry = THREADENTRY32 {
        dwSize: entry_size,
        ..THREADENTRY32::default()
    };
    let mut resumed = 0usize;
    // SAFETY: スナップショットハンドルは `snapshot` が所有する有効なもの。`entry` は `dwSize` を
    // 構造体の正確なサイズに設定済みの書き込み可能領域で、関数はその範囲内にだけ書く。
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            resume_thread(entry.th32ThreadID)?;
            resumed = resumed.saturating_add(1);
        }
        // SAFETY: `Thread32First` と同じ（`dwSize` は関数が書き換えず、初回に設定した値のまま）。
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    Ok(resumed)
}

/// スレッド ID `tid` を開いて 1 回 `ResumeThread` する。
fn resume_thread(tid: u32) -> io::Result<()> {
    // SAFETY: 値渡しの引数のみ（`bInheritHandle` は FALSE で継承不可）。失敗時は NULL を返すので
    // 検査してから所有権を取る。
    let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, tid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` は直前に開いた有効なスレッドハンドルで、他に所有者はいない。
    let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: `thread` が所有する有効なハンドル（THREAD_SUSPEND_RESUME 権限）。失敗時は
    // `u32::MAX`（`(DWORD)-1`）を返す。
    let prev = unsafe { ResumeThread(thread.as_raw_handle()) };
    if prev == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
