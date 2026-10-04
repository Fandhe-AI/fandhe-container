//! OS の FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能:
//! - Windows（`windows` モジュール）
//!   - `wsl2`（TASK-67.3・WIN-1・REPAIR-5）: [`system_directory`] で `wsl.exe` のパス解決に OS が保証する
//!     システムディレクトリを得る（環境変数 `SystemRoot` に頼らない）。[`Job`]・[`resume_suspended_threads`] で
//!     `wsl.exe` とその子孫を Job Object にまとめ、親が先に終了しても子孫を終了させる（`wsl2::run`）。
//!   - `wslconfig`（TASK-67.2・WIN-2）: [`copy_security`] で既存 `.wslconfig` の DACL・所有者・整合性ラベルを
//!     一時ファイルへ写し、[`file_id`]・[`security_snapshot`] で置換直前に宛先が読み込み元と同じファイルで
//!     アクセス制御が変わっていないかを確かめ、[`has_audit_sacl`] で監査用 SACL を（観測できる場合）調べる。
//!     置き換わりで `kernelCommandLine` 等が他ユーザーに読まれるのを防ぐ。
//! - unix（`unix` モジュール）: [`has_extended_acl`] で拡張 ACL（Linux の POSIX・NFSv4・richacl・CIFS / SMB3、
//!   macOS の ACL）の有無を調べる。パーミッションだけでは再現できないため、ある場合は置換を拒否する。
//!   `.wslconfig` は Windows のファイルで unix には実運用の用途がない（`default_path` は `UNIMPLEMENTED`）。
//!   書き込み処理を 3 OS の CI で検証するため unix でもビルドし、再現できない属性を持つファイルの置換は
//!   fail-closed で拒否する。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数・型のみ（`unsafe fn` を外へ出さない）。
//! - Windows の `wsl2` 用の宣言・構造体レイアウトは承認済みの `windows-sys`（#371・TASK-67.hdep1）のものを使う。
//!   `wslconfig` 用は `extern "system"` 宣言（windows-sys 0.61.2 と照合済み）。
//! - unix は `libc` クレートに依存せず（dependency-policy「ユーザー承認制」）、std が既にリンクしている libc の
//!   関数を必要最小限の `extern "C"` 宣言で使う。宣言と定数は `libc` 0.2.189 と照合済み（`libc` にない macOS の
//!   `acl_get_fd`・`acl_free` は `sys/acl.h` の宣言に基づき、macOS CI の実行結果を根拠とする）。
//! - 取得したハンドルは直ちに `std::os::windows::io::OwnedHandle` 等の所有者へ移し、`Drop` で必ず閉じる
//!   （RAII）。継承可能（`bInheritHandle`）なハンドルは作らない。

#[cfg(unix)]
pub(crate) use unix::has_extended_acl;
#[cfg(all(
    test,
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    )
))]
pub(crate) use unix::{add_test_acl, add_test_default_acl};
#[cfg(windows)]
pub(crate) use windows::{
    CREATE_SUSPENDED, GENERIC_WRITE, Job, WRITE_DAC, WRITE_OWNER, copy_security, file_id,
    has_audit_sacl, resume_suspended_threads, security_snapshot, system_directory,
};

/// Windows の FFI（`windows-sys`）。前半は `wsl2` 用（TASK-67.3・#1364 由来）、後半は `wslconfig` 用（TASK-67.2）。
#[cfg(windows)]
mod windows {
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
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, ResumeThread, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };

    /// `CommandExt::creation_flags` に渡す `CREATE_SUSPENDED`（初期スレッドを停止状態で作る）。
    ///
    /// [`Job::assign`] より前に子が子孫を作る競合を防ぐため、`wsl2::run` が起動時に指定する。
    pub(crate) const CREATE_SUSPENDED: u32 =
        windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

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
    /// スナップショット取得から `OpenThread` までの間にスレッド ID が再利用される競合に備え、開いた
    /// スレッドの所属プロセスを `GetProcessIdOfThread` で照合し、不一致なら再開せず `Err` にする。
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
        // `th32ThreadID`・`th32OwnerProcessID` を読むのに必要な最小サイズ（両フィールドの終端）。
        // Toolhelp は書き込んだ大きさを `dwSize` に返すため、これ未満のエントリは読まずに飛ばす。
        let min_size = std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID)
            .saturating_add(std::mem::size_of::<u32>());
        let mut resumed = 0usize;
        // SAFETY: スナップショットハンドルは `snapshot` が所有する有効なもの。`entry` は `dwSize` を
        // 構造体の正確なサイズに設定した書き込み可能領域で、関数はその範囲内にだけ書く。
        let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        while more {
            let filled = usize::try_from(entry.dwSize).unwrap_or(0);
            if filled >= min_size && entry.th32OwnerProcessID == pid {
                resume_thread(entry.th32ThreadID, pid)?;
                resumed = resumed.saturating_add(1);
            }
            // Toolhelp は呼び出しのたびに `dwSize` を書き換えうるため、毎回正確なサイズに戻す。
            entry.dwSize = entry_size;
            // SAFETY: スナップショットハンドルは `snapshot` が所有する有効なもの。`entry` は直前に
            // `dwSize` を構造体の正確なサイズへ再設定した書き込み可能領域で、関数はその範囲内にだけ書く。
            more = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        }
        Ok(resumed)
    }

    /// スレッド ID `tid` を開き、所属プロセスが `pid` であることを確かめてから 1 回 `ResumeThread` する。
    ///
    /// スナップショット後に `tid` が別プロセスのスレッドへ再利用されていた場合は再開せず `Err`
    /// （fail-closed。呼び出し側は子を終了させて `INTERNAL` を返す）。
    fn resume_thread(tid: u32, pid: u32) -> io::Result<()> {
        // SAFETY: 値渡しの引数のみ（`bInheritHandle` は FALSE で継承不可）。失敗時は NULL を返すので
        // 検査してから所有権を取る。
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                tid,
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` は直前に開いた有効なスレッドハンドルで、他に所有者はいない。
        let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
        if thread_process_id(&thread)? != pid {
            return Err(io::Error::other(
                "thread id was reused by another process before resume",
            ));
        }
        // SAFETY: `thread` が所有する有効なハンドル（THREAD_SUSPEND_RESUME 権限）。失敗時は
        // `u32::MAX`（`(DWORD)-1`）を返す。
        let prev = unsafe { ResumeThread(thread.as_raw_handle()) };
        if prev == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// スレッドハンドル `thread` が属するプロセスの ID を返す（失敗時は `Err`）。
    fn thread_process_id(thread: &OwnedHandle) -> io::Result<u32> {
        // SAFETY: `thread` が所有する有効なスレッドハンドル（THREAD_QUERY_LIMITED_INFORMATION 権限）を
        // 借用して渡すだけで、関数はハンドルを閉じない。失敗時は 0 を返す（0 は有効な PID ではない）。
        let pid = unsafe { GetProcessIdOfThread(thread.as_raw_handle()) };
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    // ---- `wslconfig` 置換時のアクセス制御の複製・検査（TASK-67.2・WIN-2） ----

    use std::ffi::c_void;
    use std::fs::File;

    /// `SE_OBJECT_TYPE::SE_FILE_OBJECT`（accctrl.h）。
    const SE_FILE_OBJECT: i32 = 1;
    /// `DACL_SECURITY_INFORMATION`（winnt.h）。
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    /// `PROTECTED_DACL_SECURITY_INFORMATION`（winnt.h）。親からの継承 ACE を受け付けない DACL として設定する。
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    /// `UNPROTECTED_DACL_SECURITY_INFORMATION`（winnt.h）。親からの継承 ACE を受け付ける DACL として設定する。
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
    /// `SE_DACL_PROTECTED`（`SECURITY_DESCRIPTOR_CONTROL` のビット。winnt.h）。
    const SE_DACL_PROTECTED: u16 = 0x1000;
    /// `LABEL_SECURITY_INFORMATION`（winnt.h）。SACL のうち整合性ラベル（mandatory label）だけを対象にする。
    const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
    /// `OWNER_SECURITY_INFORMATION`（winnt.h）。
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    /// `SYSTEM_MANDATORY_LABEL_ACE_TYPE`（winnt.h）。整合性ラベルの ACE 種別。
    const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
    /// `SACL_SECURITY_INFORMATION`（winnt.h）。読み書きには ACCESS_SYSTEM_SECURITY（SeSecurityPrivilege）が要る。
    const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
    /// `ACCESS_SYSTEM_SECURITY`（winnt.h）。
    const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    /// `READ_CONTROL`（winnt.h）。
    const READ_CONTROL: u32 = 0x0002_0000;
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`（std の既定の共有モードと同じ）。
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    /// `ERROR_ACCESS_DENIED`。
    const ERROR_ACCESS_DENIED: i32 = 5;
    /// `ERROR_PRIVILEGE_NOT_HELD`。
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    /// 監査・アラームの ACE 種別（winnt.h の SYSTEM_AUDIT / ALARM 系。2・3・7・8・13〜16）。
    const AUDIT_ACE_TYPES: [u8; 8] = [0x02, 0x03, 0x07, 0x08, 0x0d, 0x0e, 0x0f, 0x10];
    /// `ERROR_SUCCESS`。
    const ERROR_SUCCESS: u32 = 0;

    /// `WRITE_DAC`（winnt.h）。[`copy_security`] の宛先ハンドルはこの権限つきで開く必要がある。
    pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
    /// `WRITE_OWNER`（winnt.h）。所有者・整合性ラベルの設定に必要で、[`copy_security`] の宛先ハンドルに要る。
    pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;
    /// `GENERIC_WRITE`（winnt.h）。
    pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        // SAFETY（宣言）: `DWORD GetSecurityInfo(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID*, PSID*,
        // PACL*, PACL*, PSECURITY_DESCRIPTOR*)`（aclapi.h）。成功時は ERROR_SUCCESS を返し、
        // `*ppSecurityDescriptor` に LocalAlloc 済みの自己相対 SD を返す（呼び出し側が LocalFree する）。
        // `*ppDacl` はその SD の内部を指す（SD を解放するまで有効）。
        fn GetSecurityInfo(
            handle: *mut c_void,
            object_type: i32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
        // SAFETY（宣言）: `DWORD SetSecurityInfo(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID,
        // PACL, PACL)`（aclapi.h）。`handle` は WRITE_DAC 権限が必要。成功時は ERROR_SUCCESS。
        fn SetSecurityInfo(
            handle: *mut c_void,
            object_type: i32,
            security_info: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *const c_void,
            sacl: *const c_void,
        ) -> u32;
        // SAFETY（宣言）: `DWORD GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR)`（securitybaseapi.h）。
        // 有効な SD の大きさ（自己相対形式なら内部の SID・ACL を含む全体のバイト数）を返す。
        fn GetSecurityDescriptorLength(security_descriptor: *mut c_void) -> u32;
        // SAFETY（宣言）: `BOOL GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL,
        // LPDWORD)`（securitybaseapi.h）。失敗時は 0（FALSE）。
        fn GetSecurityDescriptorControl(
            security_descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        // SAFETY（宣言）: `HLOCAL LocalFree(HLOCAL)`（winbase.h）。成功時は NULL を返す。
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
        // SAFETY（宣言）: `BOOL GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD)`
        // （fileapi.h / winbase.h）。`info` は `size` バイトの書き込み可能領域で、クラスに対応する構造体を受ける。
        // 失敗時は 0（FALSE）。
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        // SAFETY（宣言）: `HANDLE ReOpenFile(HANDLE, DWORD, DWORD, DWORD)`（winbase.h）。同じファイルオブジェクトを
        // 別のアクセス権で開き直した新しいハンドルを返す（呼び出し側が閉じる）。失敗時は INVALID_HANDLE_VALUE。
        fn ReOpenFile(handle: *mut c_void, access: u32, share: u32, flags: u32) -> *mut c_void;
    }

    /// `FILE_INFO_BY_HANDLE_CLASS::FileIdInfo`（minwinbase.h）。
    const FILE_ID_INFO_CLASS: i32 = 18;

    /// `FILE_ID_INFO`（winbase.h）。`FileId` は ReFS でも一意な 128 bit の識別子。
    #[repr(C)]
    #[derive(Default)]
    struct FileIdInfoRaw {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    /// ボリュームとファイルを一意に識別する値（[`file_id`] の戻り値）。比較にだけ使う。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct FileId {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    /// `file` のボリュームシリアル番号と 128 bit のファイル ID を返す（`GetFileInformationByHandleEx` の
    /// `FileIdInfo`）。`wslconfig` が置換直前に宛先と読み込み元の同一性を確かめるのに使う。
    pub(crate) fn file_id(file: &File) -> std::io::Result<FileId> {
        let mut raw = FileIdInfoRaw::default();
        let size = u32::try_from(std::mem::size_of::<FileIdInfoRaw>())
            .map_err(|_| std::io::Error::other("FILE_ID_INFO size overflow"))?;
        // SAFETY: `file` は生存中の `File` が所有する有効なハンドル。`raw` は `FILE_ID_INFO` と同じレイアウト
        // （repr(C)。u64 と 16 バイト配列）の書き込み可能なローカル変数で、`size` にその大きさを渡すため、
        // 関数はこの範囲を超えて書かない。
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_ID_INFO_CLASS,
                (&mut raw as *mut FileIdInfoRaw).cast::<c_void>(),
                size,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(FileId {
            volume_serial_number: raw.volume_serial_number,
            file_id: raw.file_id,
        })
    }

    /// `GetSecurityInfo` が返した SD を、スコープを抜けるときに必ず `LocalFree` する所有者。
    struct LocalSecurityDescriptor(*mut c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` は `GetSecurityInfo` が成功時に LocalAlloc で返した SD で、本型だけが所有し、
                // 解放はこの 1 回だけ行う。SD の内部を指す ACL ポインタは本型の生存期間内でしか使わない
                // （[`copy_security`] が `SetSecurityInfo` の完了後に本値を落とす）。
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    /// 取得するセキュリティ記述子の部分。
    #[derive(Clone, Copy)]
    enum Part {
        /// 所有者 SID（`OWNER_SECURITY_INFORMATION`）。
        Owner,
        /// DACL（`DACL_SECURITY_INFORMATION`）。
        Dacl,
        /// 整合性ラベルだけを含む SACL（`LABEL_SECURITY_INFORMATION`。READ_CONTROL で読める）。
        Label,
        /// 監査用 SACL（`SACL_SECURITY_INFORMATION`。ACCESS_SYSTEM_SECURITY つきのハンドルが要る）。
        Sacl,
        /// 所有者・DACL・整合性ラベルをまとめた SD 全体（比較用。出力ポインタは使わない）。
        Snapshot,
    }

    /// `src` の SD から `part` を取得する。戻り値のポインタ（SID または ACL）は SD の内部（または NULL）を指し、
    /// 返した [`LocalSecurityDescriptor`] の生存中だけ有効。
    fn get_part(src: &File, part: Part) -> std::io::Result<(LocalSecurityDescriptor, *mut c_void)> {
        let mut out: *mut c_void = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let null = std::ptr::null_mut();
        let (info, owner_out, dacl_out, sacl_out): (
            u32,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
        ) = match part {
            Part::Owner => (OWNER_SECURITY_INFORMATION, &mut out, null, null),
            Part::Dacl => (DACL_SECURITY_INFORMATION, null, &mut out, null),
            Part::Label => (LABEL_SECURITY_INFORMATION, null, null, &mut out),
            Part::Sacl => (SACL_SECURITY_INFORMATION, null, null, &mut out),
            Part::Snapshot => (
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                null,
                null,
                null,
            ),
        };
        // SAFETY: `src` は生存中の `File` が所有する有効なハンドル。出力引数 `owner_out` / `dacl_out` / `sacl_out`
        // のうち要求する 1 つと `sd` は有効なローカル変数を指し、要求しない group と他の出力には NULL を渡す
        // （API 仕様で許容）。`sd` は成功（ERROR_SUCCESS）を確認してから `LocalSecurityDescriptor` に所有させ、
        // 以降は全経路で 1 回だけ解放される。失敗時の `sd` は API が値を保証しないため解放しない（不定値の
        // `LocalFree` よりリーク側に倒す）。
        let rc = unsafe {
            GetSecurityInfo(
                src.as_raw_handle(),
                SE_FILE_OBJECT,
                info,
                owner_out,
                std::ptr::null_mut(),
                dacl_out,
                sacl_out,
                &mut sd,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(win32_error(rc));
        }
        let sd = LocalSecurityDescriptor(sd);
        if sd.0.is_null() {
            return Err(std::io::Error::other(
                "GetSecurityInfo returned no descriptor",
            ));
        }
        Ok((sd, out))
    }

    /// `src` のアクセス制御（DACL と継承保護の有無・所有者・整合性ラベル）を `dst` へ写す。
    ///
    /// `src` は READ_CONTROL を含む権限（`read(true)` の GENERIC_READ）で、`dst` は READ_CONTROL・[`WRITE_DAC`]・
    /// [`WRITE_OWNER`]（所有者・整合性ラベルの設定に必要）を含む権限で開いたハンドルであること（満たさなければ
    /// `Err`）。いずれかを再現できなければ `Err` を返し、呼び出し側は置換を拒否する。
    /// - DACL: NULL DACL（全員にフルアクセス）は NULL DACL のまま写す（元より広げない）。継承保護の有無も揃える。
    ///   `dst` が `src` と同じディレクトリにあれば、親から継承される ACE も同一になり、実効的な DACL は一致する。
    /// - 所有者: 元の所有者 SID を設定する。呼び出し元が所有者にできない SID（別ユーザー等。設定には
    ///   SeRestorePrivilege が要る）なら `Err`（所有者が変わると新しい所有者が DACL を変更できるため）。
    /// - 整合性ラベル: 元のラベル ACL を設定し（元にラベルがなければ設定しない）、設定後の `dst` のラベル
    ///   （ポリシーと整合性レベル）が元と一致することを確かめる。親から別のラベルを継承した場合や、呼び出し元の
    ///   整合性レベルより高いラベルで設定できない場合は `Err`。
    /// - 写さないもの: 監査用 SACL（SeSecurityPrivilege が要り、アクセス可否に影響しない）。
    pub(crate) fn copy_security(src: &File, dst: &File) -> std::io::Result<()> {
        let (dacl_sd, dacl) = get_part(src, Part::Dacl)?;
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `dacl_sd.0` は `get_part` が取得した有効な SD（`dacl_sd` の生存中は解放されない）。
        // 出力引数は有効なローカル変数。
        let ok = unsafe { GetSecurityDescriptorControl(dacl_sd.0, &mut control, &mut revision) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let protection = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: `dst` は生存中の `File` が所有する有効なハンドル。`dacl` は `dacl_sd` の内部（または NULL DACL を
        // 表す NULL）を指し、`dacl_sd` はこの呼び出しの完了後まで解放されない（下の `drop` が呼び出しの後）。
        // owner / group / sacl は変更しないため NULL を渡す（DACL_SECURITY_INFORMATION のみ指定）。
        let rc = unsafe {
            SetSecurityInfo(
                dst.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        drop(dacl_sd);
        if rc != ERROR_SUCCESS {
            return Err(win32_error(rc));
        }

        let (owner_sd, owner) = get_part(src, Part::Owner)?;
        if owner.is_null() {
            return Err(std::io::Error::other("source file has no owner"));
        }
        // SAFETY: `dst` は生存中の `File` が所有する有効なハンドル（WRITE_OWNER つき）。`owner` は `owner_sd` の
        // 内部を指す非 NULL の SID で、`owner_sd` はこの呼び出しの完了後まで解放されない（下の `drop` が呼び出しの
        // 後）。OWNER_SECURITY_INFORMATION のみ指定し、group / dacl / sacl は変更しないため NULL を渡す。
        let rc = unsafe {
            SetSecurityInfo(
                dst.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        drop(owner_sd);
        if rc != ERROR_SUCCESS {
            return Err(win32_error(rc));
        }

        let (label_sd, label) = get_part(src, Part::Label)?;
        if !label.is_null() {
            // SAFETY: `dst` は生存中の `File` が所有する有効なハンドル。`label` は `label_sd` の内部を指す非 NULL の
            // ACL で、`label_sd` はこの呼び出しの完了後まで解放されない（下の `drop` が呼び出しの後）。
            // LABEL_SECURITY_INFORMATION のみ指定し、owner / group / dacl は変更しないため NULL を渡す。
            let rc = unsafe {
                SetSecurityInfo(
                    dst.as_raw_handle(),
                    SE_FILE_OBJECT,
                    LABEL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    label,
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(win32_error(rc));
            }
        }
        drop(label_sd);
        if integrity_label(src)? != integrity_label(dst)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "integrity label could not be reproduced",
            ));
        }
        Ok(())
    }

    fn malformed() -> std::io::Error {
        std::io::Error::other("malformed security descriptor")
    }

    /// `sd`（`GetSecurityInfo` が返した自己相対 SD）の全長。
    fn sd_len(sd: &LocalSecurityDescriptor) -> std::io::Result<usize> {
        // SAFETY: `sd.0` は `get_part` が取得した有効な自己相対 SD（`sd` の生存中は解放されない）。
        usize::try_from(unsafe { GetSecurityDescriptorLength(sd.0) }).map_err(|_| malformed())
    }

    /// `sd` の内部を指す ACL を、SD の全長の内側に収まることを確かめてから `AclSize` バイトだけコピーする。
    fn copy_acl(sd: &LocalSecurityDescriptor, acl: *mut c_void) -> std::io::Result<Vec<u8>> {
        // `GetSecurityInfo` が返す SD は自己相対形式で、ACL はその内部にある。読み取る範囲が SD の内側に
        // 収まることを、SD の全長と ACL の位置から確かめてから読む。
        let acl_off = (acl as usize)
            .checked_sub(sd.0 as usize)
            .ok_or_else(malformed)?;
        let room = sd_len(sd)?.checked_sub(acl_off).ok_or_else(malformed)?;
        if room < 8 {
            return Err(malformed());
        }
        // SAFETY: `acl` は `sd` の内部を指す非 NULL の ACL で、上で `acl` から 8 バイトが SD の内側にあることを
        // 確認した（`sd` は呼び出し側で生存している）。ACL の先頭 8 バイトは ACL ヘッダ（AclRevision u8・
        // Sbz1 u8・AclSize u16・AceCount u16・Sbz2 u16）で、境界合わせを仮定しない `read_unaligned` で読む。
        let size = unsafe { std::ptr::read_unaligned(acl.cast::<u8>().add(2).cast::<u16>()) };
        let size = usize::from(u16::from_le(size));
        if size < 8 || size > room {
            return Err(malformed());
        }
        // SAFETY: `acl` から `size`（AclSize）バイトは、上で SD の全長の内側にあると確認した有効な読み取り可能
        // 領域で、`sd` の生存中に限ってコピーする。
        Ok(unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) }.to_vec())
    }

    /// `file` の整合性ラベル（ポリシーのマスクと整合性レベルの RID）。ラベルがなければ `None`。
    fn integrity_label(file: &File) -> std::io::Result<Option<(u32, u32)>> {
        let (sd, acl) = get_part(file, Part::Label)?;
        if acl.is_null() {
            return Ok(None);
        }
        let bytes = copy_acl(&sd, acl)?;
        drop(sd);
        parse_label_acl(&bytes).ok_or_else(malformed)
    }

    /// `file` の所有者・DACL・整合性ラベルをまとめた自己相対 SD のバイト列（比較用のスナップショット）。
    ///
    /// `wslconfig` が読み込み時と置換直前に同じハンドルで取得して比べ、読み込み後のアクセス制御の変更
    /// （DACL・所有者・ラベル）を検出するのに使う。同じ SD からは同じバイト列が得られる。
    pub(crate) fn security_snapshot(file: &File) -> std::io::Result<Vec<u8>> {
        let (sd, _) = get_part(file, Part::Snapshot)?;
        let len = sd_len(&sd)?;
        if len == 0 {
            return Err(malformed());
        }
        // SAFETY: `sd.0` は有効な自己相対 SD で、`GetSecurityDescriptorLength` が返した `len` バイトはその全体
        // （内部の SID・ACL を含む）。`sd` の生存中に限ってコピーする。
        Ok(unsafe { std::slice::from_raw_parts(sd.0.cast::<u8>(), len) }.to_vec())
    }

    /// `file` の監査用 SACL に監査・アラームの ACE があるか。
    ///
    /// SACL の読み取りには ACCESS_SYSTEM_SECURITY（SeSecurityPrivilege が有効なトークン）が要る。同じファイル
    /// オブジェクトを `ReOpenFile` で開き直して読めれば、監査 ACE の有無を `Some(bool)` で返す（パスを引き直さない）。
    /// 特権がない（`ERROR_PRIVILEGE_NOT_HELD`・`ERROR_ACCESS_DENIED`）場合は観測できないため `None`。それ以外の
    /// 失敗は `Err`。観測できない主体は SACL に制約されず、元ファイルを削除できる（削除で SACL も消える）ため、
    /// 呼び出し側は `None` を置換の拒否理由にしない。
    pub(crate) fn has_audit_sacl(file: &File) -> std::io::Result<Option<bool>> {
        // SAFETY: `file` は生存中の `File` が所有する有効なハンドル。戻り値は下で INVALID_HANDLE_VALUE（-1）
        // と NULL を判定し、有効なら直後に `OwnedHandle` が所有して 1 回だけ閉じる。
        let h = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                ACCESS_SYSTEM_SECURITY | READ_CONTROL,
                FILE_SHARE_ALL,
                0,
            )
        };
        if h.is_null() || h as isize == -1 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(ERROR_PRIVILEGE_NOT_HELD) | Some(ERROR_ACCESS_DENIED) => Ok(None),
                _ => Err(e),
            };
        }
        // SAFETY: `h` は `ReOpenFile` が返した有効なハンドルで、他に所有者はいない（ここで所有権を移す）。
        let reopened = File::from(unsafe { OwnedHandle::from_raw_handle(h) });
        let (sd, sacl) = get_part(&reopened, Part::Sacl)?;
        if sacl.is_null() {
            return Ok(Some(false));
        }
        let bytes = copy_acl(&sd, sacl)?;
        drop(sd);
        acl_ace_types(&bytes)
            .map(|types| Some(types.iter().any(|t| AUDIT_ACE_TYPES.contains(t))))
            .ok_or_else(malformed)
    }

    /// ACL のバイト列の ACE 種別の列。形式が壊れていれば `None`。
    fn acl_ace_types(acl: &[u8]) -> Option<Vec<u8>> {
        let count = u16::from_le_bytes(acl.get(4..6)?.try_into().ok()?);
        let mut types = Vec::with_capacity(usize::from(count));
        let mut off: usize = 8;
        for _ in 0..count {
            let ace_type = *acl.get(off)?;
            let size = usize::from(u16::from_le_bytes(
                acl.get(off.checked_add(2)?..off.checked_add(4)?)?
                    .try_into()
                    .ok()?,
            ));
            let end = off.checked_add(size)?;
            if size < 4 || end > acl.len() {
                return None;
            }
            types.push(ace_type);
            off = end;
        }
        Some(types)
    }

    /// 整合性ラベルの ACL のバイト列から、最初の `SYSTEM_MANDATORY_LABEL_ACE` の（マスク, 整合性レベル RID）を
    /// 取り出す。ラベル ACE がなければ `Some(None)`、形式が壊れていれば `None`。
    fn parse_label_acl(acl: &[u8]) -> Option<Option<(u32, u32)>> {
        let le16 = |off: usize| -> Option<u16> {
            Some(u16::from_le_bytes(
                acl.get(off..off.checked_add(2)?)?.try_into().ok()?,
            ))
        };
        let le32 = |off: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                acl.get(off..off.checked_add(4)?)?.try_into().ok()?,
            ))
        };
        let count = le16(4)?;
        let mut off: usize = 8;
        for _ in 0..count {
            let ace_type = *acl.get(off)?;
            let ace_size = usize::from(le16(off.checked_add(2)?)?);
            if ace_size < 4 {
                return None;
            }
            let ace_end = off.checked_add(ace_size)?;
            if ace_end > acl.len() {
                return None;
            }
            if ace_type == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                let mask = le32(off.checked_add(4)?)?;
                let sid = off.checked_add(8)?;
                let sub_count = usize::from(*acl.get(sid.checked_add(1)?)?);
                let last = sub_count.checked_sub(1)?;
                let rid_off = sid.checked_add(8)?.checked_add(last.checked_mul(4)?)?;
                // RID（最後のサブ権限）が ACE の内側に収まること（隣の ACE や ACL の外を読まない）。
                if rid_off.checked_add(4)? > ace_end {
                    return None;
                }
                return Some(Some((mask, le32(rid_off)?)));
            }
            off = ace_end;
        }
        Some(None)
    }

    /// `GetSecurityInfo` / `SetSecurityInfo` が返す Win32 エラーコードを `io::Error` にする。
    fn win32_error(code: u32) -> std::io::Error {
        // Win32 エラーコードは 0..=0xFFFF の範囲。範囲外（想定外）は汎用エラーにする。
        match i32::try_from(code) {
            Ok(c) => std::io::Error::from_raw_os_error(c),
            Err(_) => std::io::Error::other("unexpected Win32 error code"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::{Path, PathBuf};

        struct TmpDir(PathBuf);
        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// `icacls <name>` を `dir` で実行した出力（相対名で呼ぶため、同名ファイルなら出力を直接比較できる）。
        fn icacls(dir: &Path, args: &[&str]) -> String {
            let out = std::process::Command::new("icacls")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("icacls");
            assert!(out.status.success(), "icacls {args:?} failed: {out:?}");
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// WIN-2・TASK-67.2: 元ファイルの明示 ACE・継承保護・整合性ラベルが宛先へそのまま写る
        /// （icacls の出力が一致する）。
        #[test]
        fn copy_security_reproduces_dacl_and_integrity_label() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-dacl-{}", std::process::id())));
            std::fs::create_dir_all(&d.0).expect("mkdir");
            std::fs::write(d.0.join("src"), b"x").expect("write src");
            std::fs::write(d.0.join("dst"), b"y").expect("write dst");
            // 継承を明示 ACE に変換して保護し、LOCAL SERVICE（S-1-5-19）の読み取りを明示 ACE として加える。
            icacls(&d.0, &["src", "/inheritance:d"]);
            icacls(&d.0, &["src", "/grant", "*S-1-5-19:R"]);
            // 明示の整合性ラベル（Low。どの整合性レベルのプロセスからも設定できる）を付ける。
            icacls(&d.0, &["src", "/setintegritylevel", "L"]);
            let src_acl = icacls(&d.0, &["src"]).replacen("src", "", 1);
            let dst_before = icacls(&d.0, &["dst"]).replacen("dst", "", 1);
            assert_ne!(src_acl, dst_before, "test setup must differ");

            let src = File::open(d.0.join("src")).expect("open src");
            let dst = std::fs::OpenOptions::new()
                .write(true)
                .access_mode(GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
                .open(d.0.join("dst"))
                .expect("open dst");
            copy_security(&src, &dst).expect("copy_security");
            drop(dst);
            let dst_after = icacls(&d.0, &["dst"]).replacen("dst", "", 1);
            assert_eq!(dst_after, src_acl);
        }

        /// WIN-2: 同じファイルを別々に開いたハンドルの `file_id` は一致し、別ファイルとは一致しない。
        #[test]
        fn file_id_identifies_the_same_file() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-fileid-{}", std::process::id())));
            std::fs::create_dir_all(&d.0).expect("mkdir");
            std::fs::write(d.0.join("a"), b"x").expect("write a");
            std::fs::write(d.0.join("b"), b"x").expect("write b");
            let a1 = file_id(&File::open(d.0.join("a")).expect("open a")).expect("id a1");
            let a2 = file_id(&File::open(d.0.join("a")).expect("open a")).expect("id a2");
            let b = file_id(&File::open(d.0.join("b")).expect("open b")).expect("id b");
            assert_eq!(a1, a2);
            assert_ne!(a1, b);
        }

        /// WIN-2: 整合性ラベル ACL のバイト列から（ポリシー, 整合性レベル RID）を取り出す。ラベル ACE が
        /// なければ `Some(None)`、壊れた形式は `None`。
        #[test]
        fn parse_label_acl_extracts_policy_and_level() {
            // ACL ヘッダ（rev 2・AclSize 28・AceCount 1）+ SYSTEM_MANDATORY_LABEL_ACE（size 20・NW・S-1-16-4096）。
            let low: [u8; 28] = [
                2, 0, 28, 0, 1, 0, 0, 0, 0x11, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 16, 0x00,
                0x10, 0, 0,
            ];
            assert_eq!(parse_label_acl(&low), Some(Some((1, 0x1000))));
            assert_eq!(parse_label_acl(&[2, 0, 8, 0, 0, 0, 0, 0]), Some(None));
            assert_eq!(parse_label_acl(low.get(..20).expect("slice")), None);
            // AceSize が SID の途中で終わる（RID が ACE の外にはみ出す）形式は拒否する。
            let mut short = low;
            short[10] = 16;
            short[2] = 24;
            assert_eq!(parse_label_acl(&short), None);
        }

        /// WIN-2（レビュー指摘 P1）: 元ファイルにラベルがなく、宛先が親ディレクトリから別のラベルを継承した場合は
        /// 再現できないため `Err`（PermissionDenied）。
        #[test]
        fn copy_security_rejects_inherited_label_mismatch() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-label-{}", std::process::id())));
            let plain = d.0.join("plain");
            let labeled = d.0.join("labeled");
            std::fs::create_dir_all(&plain).expect("mkdir plain");
            std::fs::create_dir_all(&labeled).expect("mkdir labeled");
            std::fs::write(plain.join("src"), b"x").expect("write src");
            // 新しく作るファイルへ継承される Low ラベルをディレクトリに付けてから宛先を作る。
            icacls(&d.0, &["labeled", "/setintegritylevel", "(OI)(CI)L"]);
            let src = File::open(plain.join("src")).expect("open src");
            let dst = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .access_mode(GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
                .open(labeled.join("dst"))
                .expect("create dst");
            assert_eq!(integrity_label(&src).expect("src label"), None);
            assert_eq!(integrity_label(&dst).expect("dst label"), Some((1, 0x1000)));
            let e = copy_security(&src, &dst).expect_err("must fail");
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        }

        /// WIN-2: 同じファイルの SD スナップショットは一致し、DACL を変えると変わる。
        #[test]
        fn security_snapshot_detects_dacl_change() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-snap-{}", std::process::id())));
            std::fs::create_dir_all(&d.0).expect("mkdir");
            std::fs::write(d.0.join("f"), b"x").expect("write");
            let f = File::open(d.0.join("f")).expect("open");
            let a = security_snapshot(&f).expect("snapshot a");
            assert!(!a.is_empty());
            assert_eq!(security_snapshot(&f).expect("snapshot b"), a);
            icacls(&d.0, &["f", "/grant", "*S-1-5-19:R"]);
            assert_ne!(security_snapshot(&f).expect("snapshot c"), a);
        }

        /// WIN-2: 監査用 SACL の検査は、特権が無効な CI のトークンでは観測できず `None`（監査 ACE のない新規
        /// ファイルを観測できた場合は `Some(false)`）。`Some(true)` の経路は特権の有効化が要るため CI では通らない。
        #[test]
        fn has_audit_sacl_without_audit_entries_is_not_true() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-sacl-{}", std::process::id())));
            std::fs::create_dir_all(&d.0).expect("mkdir");
            std::fs::write(d.0.join("f"), b"x").expect("write");
            let f = File::open(d.0.join("f")).expect("open");
            let r = has_audit_sacl(&f).expect("inspect");
            assert!(matches!(r, None | Some(false)), "{r:?}");
        }

        /// WIN-2: ACE 種別の列挙は ACE と ACL の境界を確かめる。
        #[test]
        fn acl_ace_types_checks_bounds() {
            let audit: [u8; 16] = [2, 0, 16, 0, 1, 0, 0, 0, 0x02, 0x40, 8, 0, 0, 0, 0, 0];
            assert_eq!(acl_ace_types(&audit), Some(vec![0x02]));
            assert_eq!(acl_ace_types(&[2, 0, 8, 0, 0, 0, 0, 0]), Some(vec![]));
            assert_eq!(acl_ace_types(audit.get(..12).expect("slice")), None);
        }

        /// WIN-2: WRITE_DAC なしで開いた宛先には写せず `Err`（失敗を握りつぶさない）。
        #[test]
        fn copy_security_without_write_dac_fails() {
            let d =
                TmpDir(std::env::temp_dir().join(format!("fc-sys-nodac-{}", std::process::id())));
            std::fs::create_dir_all(&d.0).expect("mkdir");
            std::fs::write(d.0.join("src"), b"x").expect("write src");
            std::fs::write(d.0.join("dst"), b"y").expect("write dst");
            let src = File::open(d.0.join("src")).expect("open src");
            let dst = std::fs::OpenOptions::new()
                .write(true)
                .open(d.0.join("dst"))
                .expect("open dst");
            let e = copy_security(&src, &dst).expect_err("must fail");
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        }
    }
}

/// unix の拡張 ACL の検出（Linux は `fgetxattr`、macOS は `acl_get_fd`。いずれも libc の関数で、std が
/// 既にリンクしている）。
#[cfg(unix)]
mod unix {
    use std::fs::File;

    /// `file` に拡張 ACL（パーミッションビットで表せないアクセス制御）があるか。
    ///
    /// Linux は `system.posix_acl_access`（基本エントリだけの ACL は拡張属性として保存されないため、あれば拡張
    /// ACL）と、NFSv4 ACL・richacl・CIFS / SMB3 の ACL を表す拡張属性の有無で判定する（`imp::ACL_XATTRS`）。ファイルシステムが拡張属性に対応しない（`EOPNOTSUPP`）場合は ACL を
    /// 持ちえないので `false`。macOS は `acl_get_fd` が ACL を返せば `true`（`ENOENT` なら `false`）。
    /// それ以外の errno と、判定方法を持たない OS・アーキテクチャは `Err`（呼び出し側は置換を拒否する）。
    pub(crate) fn has_extended_acl(file: &File) -> std::io::Result<bool> {
        imp::has_extended_acl(file)
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod imp {
        use std::ffi::{c_char, c_int, c_void};
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        /// `ENODATA`（Linux の asm-generic errno。x86_64・aarch64 で 61）。
        const ENODATA: i32 = 61;
        /// `EOPNOTSUPP`（= `ENOTSUP`。Linux の x86_64・aarch64 で 95）。
        const EOPNOTSUPP: i32 = 95;

        unsafe extern "C" {
            // SAFETY（宣言）: `ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)`
            // （sys/xattr.h。glibc / musl）。`size` が 0 なら `value` に書かず、属性値の大きさを返す。
            // 失敗時は -1 で errno を設定する。
            fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
        }

        /// アクセス制御を表す拡張属性の名前。POSIX ACL に加え、NFSv4 ACL（NFS クライアント・ZFS 等）・
        /// richacl・CIFS / SMB3 のセキュリティ記述子も対象にする。いずれかがあれば、パーミッションビットだけでは
        /// 再現できないアクセス制御を持つとみなす（NFSv4・CIFS 上のファイルは常に該当し、置換は拒否される）。
        pub(super) const ACL_XATTRS: [&std::ffi::CStr; 6] = [
            c"system.posix_acl_access",
            c"system.nfs4_acl",
            c"system.nfs4_acl_xdr",
            c"system.richacl",
            c"system.cifs_acl",
            c"system.smb3_acl",
        ];

        pub(super) fn has_extended_acl(file: &File) -> std::io::Result<bool> {
            for name in ACL_XATTRS {
                if has_xattr(file, name)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        /// `file` に拡張属性 `name` があるか。ない（`ENODATA`）・ファイルシステムが対応しない（`EOPNOTSUPP`）は
        /// `false`、それ以外の失敗は `Err`（呼び出し側は置換を拒否する）。
        fn has_xattr(file: &File, name: &std::ffi::CStr) -> std::io::Result<bool> {
            // SAFETY: `file` は生存中の `File` が所有する有効な fd。`name` は NUL 終端の文字列で呼び出しの間生存
            // する。`size` に 0 を渡すため `value`（NULL）には書き込まれない。
            let rc = unsafe { fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
            if rc >= 0 {
                return Ok(true);
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(ENODATA) | Some(EOPNOTSUPP) => Ok(false),
                _ => Err(e),
            }
        }

        /// テスト用: `path` に拡張 ACL（`nobody` の読み取り）を `setxattr` で付ける。`name` は
        /// `system.posix_acl_access`（ファイルの ACL）または `system.posix_acl_default`（ディレクトリの default ACL）。
        #[cfg(test)]
        pub(super) fn set_test_acl(
            path: &std::path::Path,
            name: &std::ffi::CStr,
        ) -> std::io::Result<()> {
            use std::os::unix::ffi::OsStrExt;
            unsafe extern "C" {
                // SAFETY（宣言）: `int setxattr(const char *path, const char *name, const void *value,
                // size_t size, int flags)`（sys/xattr.h）。失敗時は -1。
                fn setxattr(
                    path: *const c_char,
                    name: *const c_char,
                    value: *const c_void,
                    size: usize,
                    flags: c_int,
                ) -> c_int;
            }
            // posix_acl_xattr 形式（version 2 と {tag, perm, id} の列。リトルエンディアン）:
            // USER_OBJ rw-・USER(65534) r--・GROUP_OBJ r--・MASK r--・OTHER ---。
            let mut blob = 2u32.to_le_bytes().to_vec();
            for (tag, perm, id) in [
                (0x01u16, 6u16, u32::MAX),
                (0x02, 4, 65534),
                (0x04, 4, u32::MAX),
                (0x10, 4, u32::MAX),
                (0x20, 0, u32::MAX),
            ] {
                blob.extend_from_slice(&tag.to_le_bytes());
                blob.extend_from_slice(&perm.to_le_bytes());
                blob.extend_from_slice(&id.to_le_bytes());
            }
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::other("path contains NUL"))?;
            // SAFETY: `cpath` と `name` は NUL 終端の文字列で、`blob` は `blob.len()` バイトの読み取り可能な
            // 領域。いずれも呼び出しの間は生存する。
            let rc = unsafe {
                setxattr(
                    cpath.as_ptr(),
                    name.as_ptr(),
                    blob.as_ptr().cast::<c_void>(),
                    blob.len(),
                    0,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    #[cfg(target_os = "macos")]
    mod imp {
        use std::ffi::{c_int, c_void};
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        /// `ENOENT`（macOS で 2）。`acl_get_fd` はファイルに ACL がなければこの errno で NULL を返す。
        const ENOENT: i32 = 2;

        unsafe extern "C" {
            // SAFETY（宣言）: `acl_t acl_get_fd(int fd)`（sys/acl.h。libSystem）。`ACL_TYPE_EXTENDED` の
            // ACL を新たに確保して返す（呼び出し側が `acl_free` する）。失敗・ACL なしは NULL で errno を設定する。
            fn acl_get_fd(fd: c_int) -> *mut c_void;
            // SAFETY（宣言）: `int acl_free(void *obj_p)`（sys/acl.h）。`acl_get_fd` が返したものを解放する。
            fn acl_free(obj: *mut c_void) -> c_int;
        }

        pub(super) fn has_extended_acl(file: &File) -> std::io::Result<bool> {
            // SAFETY: `file` は生存中の `File` が所有する有効な fd。戻り値は下で NULL 判定し、非 NULL なら
            // 1 回だけ `acl_free` する（以降は参照しない）。
            let acl = unsafe { acl_get_fd(file.as_raw_fd()) };
            if acl.is_null() {
                let e = std::io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(ENOENT) => Ok(false),
                    _ => Err(e),
                };
            }
            // SAFETY: `acl` は `acl_get_fd` が確保した非 NULL の ACL で、ここで 1 回だけ解放する。
            unsafe {
                acl_free(acl);
            }
            Ok(true)
        }
    }

    #[cfg(not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    )))]
    mod imp {
        use std::fs::File;

        /// 判定方法を持たない OS・アーキテクチャ。ACL の有無を確かめられないため常に `Err`（fail-closed）。
        pub(super) fn has_extended_acl(_file: &File) -> std::io::Result<bool> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "extended ACL detection is not supported on this platform",
            ))
        }
    }

    #[cfg(all(
        test,
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        )
    ))]
    mod tests {
        use super::*;

        /// WIN-2・TASK-67.2: ACL のない通常のファイルは `false`。
        #[test]
        fn plain_file_has_no_extended_acl() {
            let p = std::env::temp_dir().join(format!("fc-sys-noacl-{}", std::process::id()));
            std::fs::write(&p, b"x").expect("write");
            let r = has_extended_acl(&File::open(&p).expect("open"));
            let _ = std::fs::remove_file(&p);
            assert!(!r.expect("detect"));
        }

        /// WIN-2・TASK-67.2: 拡張 ACL（`nobody` の読み取り）を付けたファイルは `true`。
        #[test]
        fn file_with_acl_entry_is_detected() {
            let p = std::env::temp_dir().join(format!("fc-sys-acl-{}", std::process::id()));
            std::fs::write(&p, b"x").expect("write");
            add_test_acl(&p);
            let r = has_extended_acl(&File::open(&p).expect("open"));
            let _ = std::fs::remove_file(&p);
            assert!(r.expect("detect"));
        }
    }

    /// テスト用: `path` に拡張 ACL（`nobody` の読み取り）を付ける。Linux は `setxattr`、macOS は `chmod +a`。
    #[cfg(all(
        test,
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        )
    ))]
    pub(crate) fn add_test_acl(path: &std::path::Path) {
        #[cfg(target_os = "linux")]
        imp::set_test_acl(path, c"system.posix_acl_access").expect("setxattr posix_acl_access");
        #[cfg(target_os = "macos")]
        {
            let st = std::process::Command::new("chmod")
                .arg("+a")
                .arg("nobody allow read")
                .arg(path)
                .status()
                .expect("chmod");
            assert!(st.success(), "chmod +a failed: {st:?}");
        }
    }

    /// テスト用: ディレクトリ `dir` に、新しく作るファイルへ継承される ACL（`nobody` の読み取り）を付ける。
    /// Linux は default ACL（`system.posix_acl_default`）、macOS は `file_inherit` つきの ACE。
    #[cfg(all(
        test,
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        )
    ))]
    pub(crate) fn add_test_default_acl(dir: &std::path::Path) {
        #[cfg(target_os = "linux")]
        imp::set_test_acl(dir, c"system.posix_acl_default").expect("setxattr posix_acl_default");
        #[cfg(target_os = "macos")]
        {
            let st = std::process::Command::new("chmod")
                .arg("+a")
                .arg("nobody allow read,file_inherit")
                .arg(dir)
                .status()
                .expect("chmod");
            assert!(st.success(), "chmod +a failed: {st:?}");
        }
    }
}
