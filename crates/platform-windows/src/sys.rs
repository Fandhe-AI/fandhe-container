//! OS の FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! `wslconfig` の既存 `.wslconfig` 置換（TASK-67.2・#373・WIN-2）が、一時ファイルへ内容を書く前に元ファイルの
//! アクセス制御を再現できるかを確かめ、rename 後もアクセス制御が後退しないようにするために使う（置き換わりで
//! `kernelCommandLine` 等が他ユーザーに読まれるのを防ぐ）。
//! - Windows（[`windows`]）: [`copy_security`] で DACL・整合性ラベルを写し、[`file_id`] で置換直前に宛先が
//!   読み込み元と同じファイルかを確かめる。
//! - unix（[`unix`]）: [`has_extended_acl`] で拡張 ACL（Linux の POSIX ACL・macOS の ACL）の有無を調べる。
//!   パーミッションだけでは再現できないため、ある場合は置換を拒否する。`.wslconfig` は Windows のファイルで
//!   unix には実運用の用途がない（`default_path` は `UNIMPLEMENTED`）。書き込み処理を 3 OS の CI で検証するため
//!   unix でもビルドし、再現できない属性を持つファイルの置換は fail-closed で拒否する。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ（`unsafe fn` を外へ出さない）。
//! - 依存（`windows-sys`・`libc` 等）を増やさず、必要最小限の `extern` 宣言だけを持つ
//!   （dependency-policy「ユーザー承認制」。`crates/io` の `sys` と同方針）。宣言のシグネチャと定数は
//!   `windows-sys` 0.61.2・`libc` 0.2.189 と照合済み（`libc` にない macOS の ACL 関数は `sys/acl.h`）。

#[cfg(windows)]
pub(crate) use windows::{GENERIC_WRITE, WRITE_DAC, WRITE_OWNER, copy_security, file_id};

#[cfg(unix)]
pub(crate) use unix::has_extended_acl;

/// Windows のセキュリティ記述子・ファイル ID の操作（advapi32・kernel32）。
#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

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
    /// `ERROR_SUCCESS`。
    const ERROR_SUCCESS: u32 = 0;

    /// `WRITE_DAC`（winnt.h）。[`copy_security`] の宛先ハンドルはこの権限つきで開く必要がある。
    pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
    /// `WRITE_OWNER`（winnt.h）。整合性ラベルの設定に必要で、[`copy_security`] の宛先ハンドルに要る。
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

    /// 取得する ACL の種類。
    #[derive(Clone, Copy)]
    enum AclKind {
        /// DACL（`DACL_SECURITY_INFORMATION`）。
        Dacl,
        /// 整合性ラベルだけを含む SACL（`LABEL_SECURITY_INFORMATION`。READ_CONTROL で読める）。
        Label,
    }

    /// `handle` の SD から `kind` の ACL を取得する。戻り値の ACL ポインタは SD の内部（または NULL）を指し、
    /// 返した [`LocalSecurityDescriptor`] の生存中だけ有効。
    fn get_acl(
        src: &File,
        kind: AclKind,
    ) -> std::io::Result<(LocalSecurityDescriptor, *mut c_void)> {
        let mut acl: *mut c_void = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let (info, dacl_out, sacl_out): (u32, *mut *mut c_void, *mut *mut c_void) = match kind {
            AclKind::Dacl => (DACL_SECURITY_INFORMATION, &mut acl, std::ptr::null_mut()),
            AclKind::Label => (LABEL_SECURITY_INFORMATION, std::ptr::null_mut(), &mut acl),
        };
        // SAFETY: `src` は生存中の `File` が所有する有効なハンドル。出力引数 `dacl_out` / `sacl_out` の一方と `sd`
        // は有効なローカル変数を指し、要求しない owner / group と他方の ACL には NULL を渡す（API 仕様で許容）。
        // 成功時に返る `sd` は直後に `LocalSecurityDescriptor` が所有し、全経路で 1 回だけ解放される。
        let rc = unsafe {
            GetSecurityInfo(
                src.as_raw_handle(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl_out,
                sacl_out,
                &mut sd,
            )
        };
        let sd = LocalSecurityDescriptor(sd);
        if rc != ERROR_SUCCESS {
            return Err(win32_error(rc));
        }
        if sd.0.is_null() {
            return Err(std::io::Error::other(
                "GetSecurityInfo returned no descriptor",
            ));
        }
        Ok((sd, acl))
    }

    /// `src` のアクセス制御（DACL と継承保護の有無・整合性ラベル）を `dst` へ写す。
    ///
    /// `src` は READ_CONTROL を含む権限（`read(true)` の GENERIC_READ）で、`dst` は [`WRITE_DAC`] と
    /// [`WRITE_OWNER`]（整合性ラベルの設定に必要）を含む権限で開いたハンドルであること（満たさなければ `Err`）。
    /// - DACL: NULL DACL（全員にフルアクセス）は NULL DACL のまま写す（元より広げない）。継承保護の有無も揃える。
    ///   `dst` が `src` と同じディレクトリにあれば、親から継承される ACE も同一になり、実効的な DACL は一致する。
    /// - 整合性ラベル: 元のラベル ACL をそのまま設定する（ラベルがなければ空の ACL で「ラベルなし」を写す）。
    ///   呼び出し元の整合性レベルより高いラベルなど設定できない場合は `Err`（呼び出し側は置換を拒否する）。
    /// - 写さないもの: 所有者（変更には SeRestorePrivilege が要る。新しい所有者は書き込みを行う本人で、他者への
    ///   アクセスは広がらない）、監査用 SACL（SeSecurityPrivilege が要り、アクセス可否に影響しない）。
    pub(crate) fn copy_security(src: &File, dst: &File) -> std::io::Result<()> {
        let (dacl_sd, dacl) = get_acl(src, AclKind::Dacl)?;
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `dacl_sd.0` は `get_acl` が取得した有効な SD（`dacl_sd` の生存中は解放されない）。
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

        let (label_sd, label) = get_acl(src, AclKind::Label)?;
        if label.is_null() {
            return Ok(());
        }
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
        drop(label_sd);
        if rc != ERROR_SUCCESS {
            return Err(win32_error(rc));
        }
        Ok(())
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
    /// Linux は `system.posix_acl_access` 拡張属性の有無で判定する（基本エントリだけの ACL は拡張属性として
    /// 保存されないため、あれば拡張 ACL）。ファイルシステムが拡張属性に対応しない（`EOPNOTSUPP`）場合は ACL を
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

        pub(super) fn has_extended_acl(file: &File) -> std::io::Result<bool> {
            // SAFETY: `file` は生存中の `File` が所有する有効な fd。`name` は NUL 終端の静的文字列。
            // `size` に 0 を渡すため `value`（NULL）には書き込まれない。
            let rc = unsafe {
                fgetxattr(
                    file.as_raw_fd(),
                    c"system.posix_acl_access".as_ptr(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc >= 0 {
                return Ok(true);
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(ENODATA) | Some(EOPNOTSUPP) => Ok(false),
                _ => Err(e),
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
}
