//! Windows 向け FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能は [`copy_dacl`] のみ。`wslconfig` の既存 `.wslconfig` 置換（TASK-67.2・#373・WIN-2）が、
//! 一時ファイルへ内容を書く前に元ファイルの DACL を写し、rename 後もアクセス制御が後退しないようにする
//! （親ディレクトリからの継承 ACL への置き換わりで `kernelCommandLine` 等が他ユーザーに読まれるのを防ぐ）。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ（`unsafe fn` を外へ出さない）。
//! - 依存（`windows-sys` 等）を増やさず、必要最小限の `extern "system"` 宣言だけを持つ
//!   （dependency-policy「ユーザー承認制」。`crates/io` の `sys` と同方針）。宣言のシグネチャと定数は
//!   `windows-sys` 0.61.2 の `Win32::Security`・`Win32::Security::Authorization`・`Win32::Foundation` と
//!   照合済み。

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
/// `ERROR_SUCCESS`。
const ERROR_SUCCESS: u32 = 0;

/// `WRITE_DAC`（winnt.h）。[`copy_dacl`] の宛先ハンドルはこの権限つきで開く必要がある。
pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
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
}

/// `GetSecurityInfo` が返した SD を、スコープを抜けるときに必ず `LocalFree` する所有者。
struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` は `GetSecurityInfo` が成功時に LocalAlloc で返した SD で、本型だけが所有し、
            // 解放はこの 1 回だけ行う。解放後に参照する DACL ポインタは本型の生存期間内でしか使わない
            // （[`copy_dacl`] が `SetSecurityInfo` の完了後に本値を落とす）。
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// `src` の DACL（と継承保護の有無）を `dst` へ写す。
///
/// `src` は READ_CONTROL を含む権限（`read(true)` の GENERIC_READ）で、`dst` は [`WRITE_DAC`] を含む権限で
/// 開いたハンドルであること（満たさなければ `Err`）。所有者・SACL・整合性ラベルは写さない（所有者の
/// 変更には SeRestorePrivilege が要り、SACL は監査用で SeSecurityPrivilege が要るため。呼び出し側の
/// 文書を参照）。NULL DACL（全員にフルアクセス）の元ファイルは NULL DACL のまま写す（元より広げない）。
/// 継承保護の有無も元と揃える。`dst` が `src` と同じディレクトリにあれば、親から継承される ACE も同一に
/// なり、実効的なアクセス制御は元ファイルと一致する。
pub(crate) fn copy_dacl(src: &File, dst: &File) -> std::io::Result<()> {
    let mut dacl: *mut c_void = std::ptr::null_mut();
    let mut sd: *mut c_void = std::ptr::null_mut();
    // SAFETY: `src` は生存中の `File` が所有する有効なハンドル。出力引数 `dacl`・`sd` は有効なローカル変数を
    // 指し、不要な owner / group / sacl には NULL を渡す（API 仕様で許容）。成功時に返る `sd` は直後に
    // `LocalSecurityDescriptor` が所有し、全経路で 1 回だけ解放される。
    let rc = unsafe {
        GetSecurityInfo(
            src.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
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
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: `sd.0` は上で取得した有効な SD（`sd` の生存中は解放されない）。出力引数は有効なローカル変数。
    let ok = unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let protection = if control & SE_DACL_PROTECTED != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: `dst` は生存中の `File` が所有する有効なハンドル。`dacl` は `sd` の内部（または NULL DACL を
    // 表す NULL）を指し、`sd` はこの呼び出しの完了後まで解放されない（`sd` の drop は関数末尾）。
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
    drop(sd);
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

    /// WIN-2・TASK-67.2: 元ファイルの明示 ACE と継承保護が宛先へそのまま写る（icacls の出力が一致する）。
    #[test]
    fn copy_dacl_reproduces_explicit_and_protected_dacl() {
        let d = TmpDir(std::env::temp_dir().join(format!("fc-sys-dacl-{}", std::process::id())));
        std::fs::create_dir_all(&d.0).expect("mkdir");
        std::fs::write(d.0.join("src"), b"x").expect("write src");
        std::fs::write(d.0.join("dst"), b"y").expect("write dst");
        // 継承を明示 ACE に変換して保護し、LOCAL SERVICE（S-1-5-19）の読み取りを明示 ACE として加える。
        icacls(&d.0, &["src", "/inheritance:d"]);
        icacls(&d.0, &["src", "/grant", "*S-1-5-19:R"]);
        let src_acl = icacls(&d.0, &["src"]).replacen("src", "", 1);
        let dst_before = icacls(&d.0, &["dst"]).replacen("dst", "", 1);
        assert_ne!(src_acl, dst_before, "test setup must differ");

        let src = File::open(d.0.join("src")).expect("open src");
        let dst = std::fs::OpenOptions::new()
            .write(true)
            .access_mode(GENERIC_WRITE | WRITE_DAC)
            .open(d.0.join("dst"))
            .expect("open dst");
        copy_dacl(&src, &dst).expect("copy_dacl");
        drop(dst);
        let dst_after = icacls(&d.0, &["dst"]).replacen("dst", "", 1);
        assert_eq!(dst_after, src_acl);
    }

    /// WIN-2: WRITE_DAC なしで開いた宛先には写せず `Err`（失敗を握りつぶさない）。
    #[test]
    fn copy_dacl_without_write_dac_fails() {
        let d = TmpDir(std::env::temp_dir().join(format!("fc-sys-nodac-{}", std::process::id())));
        std::fs::create_dir_all(&d.0).expect("mkdir");
        std::fs::write(d.0.join("src"), b"x").expect("write src");
        std::fs::write(d.0.join("dst"), b"y").expect("write dst");
        let src = File::open(d.0.join("src")).expect("open src");
        let dst = std::fs::OpenOptions::new()
            .write(true)
            .open(d.0.join("dst"))
            .expect("open dst");
        let e = copy_dacl(&src, &dst).expect_err("must fail");
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
