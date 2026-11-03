//! 外部イメージを使わない最小 rootfs と `config.json` の構築（TASK-190・OCI-4・REPAIR-3）。
//!
//! ベンチ自身の実行ファイルを rootfs の `/probe` へコピーし、動的ローダと読み込み済みの共有ライブラリを同じ
//! 絶対パスへ写す。ワークロードは同じ実行ファイルを `--startup-latency-probe <nonce>` で再実行したもの
//! （固定時間眠って終了。`startup_latency::run_workload`）。方式は
//! `crates/supervisor/tests/supervisor_bin_real.rs`（#1819）の rootfs 構築と同じで、解析部品（ELF・maps・
//! `LD_LIBRARY_PATH`）は core の `tests/support/loader_deps.rs`、コピーは `file_copy.rs`（`create_new`）と共有する
//! （#2963・#3041）。エラーにパスを載せない契約は、ここの包み（`io_err`）が `ErrorKind` だけを出して保つ。
//! bundle は計測の前に 1 回だけ作り、全試行で再利用する（区間の外）。

use super::StartupLatencyError;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

/// ELF の解析・maps の解釈・`LD_LIBRARY_PATH` の組み立て。core・supervisor・cli の試験と共有する
/// （`#[path]`。置き場所の判断は同ファイルの `//!`。#2963・REPAIR-1）。
#[path = "../../../crates/core/tests/support/loader_deps.rs"]
mod loader_deps;

/// `create_new` のコピー。core・supervisor・cli の試験と共有する（#3041・REPAIR-1）。エラー整形は呼び出し側。
#[path = "../../../crates/core/tests/support/file_copy.rs"]
mod file_copy;

fn io_err(what: &'static str, e: &std::io::Error) -> StartupLatencyError {
    StartupLatencyError::new("io-error", format!("{what} failed ({:?})", e.kind()))
}

fn mkdir_all(path: &Path, mode: u32) -> Result<(), StartupLatencyError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|e| io_err("create directory", &e))
}

/// 共有部品 `file_copy::copy_new`（`create_new`・symlink を辿らない・mode 0755）の包み。エラーは `ErrorKind` だけを出す。
fn copy_new(src: &Path, dest: &Path, what: &'static str) -> Result<(), StartupLatencyError> {
    file_copy::copy_new(src, dest).map_err(|e| io_err(what, &e))
}

/// `host` のファイルを rootfs 内の同じ絶対パスへコピーする。
fn copy_into(rootfs: &Path, host: &Path) -> Result<(), StartupLatencyError> {
    let rel = host
        .strip_prefix("/")
        .map_err(|_| StartupLatencyError::new("io-error", "library path is not absolute"))?;
    let dest = rootfs.join(rel);
    if let Some(parent) = dest.parent() {
        mkdir_all(parent, 0o755)?;
    }
    file_copy::replace_with_copy(host, &dest).map_err(|e| io_err("copy library", &e))
}

/// 最小 rootfs を作り、`LD_LIBRARY_PATH` に使う値を返す。
fn make_rootfs(rootfs: &Path) -> Result<String, StartupLatencyError> {
    mkdir_all(rootfs, 0o755)?;
    for d in ["proc", "dev", "tmp", "etc"] {
        mkdir_all(&rootfs.join(d), 0o755)?;
    }
    let exe = std::env::current_exe().map_err(|e| io_err("resolve current exe", &e))?;
    let exe = std::fs::canonicalize(exe).map_err(|e| io_err("canonicalize current exe", &e))?;
    let probe = rootfs.join("probe");
    copy_new(&exe, &probe, "copy probe binary")?;
    let bytes = std::fs::read(&exe).map_err(|e| io_err("read current exe", &e))?;
    if let Some(interp) = loader_deps::elf_interp(&bytes) {
        copy_into(rootfs, Path::new(&interp))?;
    }
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| io_err("read maps", &e))?;
    let libs = loader_deps::libraries_from_maps(&maps, &exe);
    for lib in &libs {
        copy_into(rootfs, lib)?;
    }
    Ok(loader_deps::ld_library_path(&libs))
}

/// `<dir>/bundle`（rootfs と `config.json`）を作り、bundle のパスを返す。`nonce` は英数字（後始末の目印）。
pub fn build_bundle(dir: &Path, nonce: &str) -> Result<PathBuf, StartupLatencyError> {
    if nonce.is_empty() || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(StartupLatencyError::new("invalid-args", "nonce is invalid"));
    }
    let bundle = dir.join("bundle");
    mkdir_all(&bundle, 0o755)?;
    let ld = make_rootfs(&bundle.join("rootfs"))?;
    if ld.contains('"') || ld.contains('\\') {
        return Err(StartupLatencyError::new(
            "io-error",
            "library path contains unsupported characters",
        ));
    }
    let config = format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-startup",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--startup-latency-probe","{nonce}"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
    );
    std::fs::write(bundle.join("config.json"), config)
        .map_err(|e| io_err("write config.json", &e))?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn le_elf_with_interp(interp: &[u8]) -> Vec<u8> {
        // 最小の ELF64 ヘッダ + 1 個のプログラムヘッダ（PT_INTERP）+ 文字列。
        let mut b = vec![0u8; 0x40 + 56];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let off = b.len() as u64;
        b[0x40..0x44].copy_from_slice(&3u32.to_le_bytes());
        b[0x40 + 8..0x40 + 16].copy_from_slice(&off.to_le_bytes());
        b[0x40 + 32..0x40 + 40].copy_from_slice(&(interp.len() as u64 + 1).to_le_bytes());
        b.extend_from_slice(interp);
        b.push(0);
        b
    }

    #[test]
    fn interp_is_extracted() {
        let elf = le_elf_with_interp(b"/lib64/ld-linux-x86-64.so.2");
        assert_eq!(
            loader_deps::elf_interp(&elf).as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn truncated_or_non_elf_input_is_none() {
        assert_eq!(loader_deps::elf_interp(b"not elf"), None);
        let mut elf = le_elf_with_interp(b"/lib/ld.so");
        elf.truncate(0x50);
        assert_eq!(loader_deps::elf_interp(&elf), None);
        assert_eq!(loader_deps::elf_interp(&[]), None);
    }

    #[test]
    fn maps_parsing_skips_pseudo_and_duplicate_entries() {
        let maps = "\
7f00-7f01 r-xp 0 00:00 0 /proc/self/exe\n\
7f01-7f02 r-xp 0 00:00 0 [vdso]\n\
7f02-7f03 r-xp 0 00:00 0\n\
7f03-7f04 r-xp 0 00:00 0 /nonexistent/libx.so\n";
        assert!(loader_deps::libraries_from_maps(maps, Path::new("/x/exe")).is_empty());
    }

    /// 試験ごとの使い捨てディレクトリ（`src` に内容 `new` を置く）。
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fc-filecopy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("src"), b"new").expect("write src");
        dir
    }

    fn is_symlink(p: &Path) -> bool {
        std::fs::symlink_metadata(p)
            .expect("lstat")
            .file_type()
            .is_symlink()
    }

    /// REPAIR-12・#3041: 新規作成は内容が写り mode 0755。
    #[test]
    fn copy_new_creates_with_0755() {
        let dir = scratch("create");
        let dest = dir.join("dest");
        file_copy::copy_new(&dir.join("src"), &dest).expect("copy");
        assert_eq!(std::fs::read(&dest).expect("read"), b"new");
        let mode = std::fs::metadata(&dest).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-12・#3041: 既存の通常ファイルは `AlreadyExists` で内容も変わらない。
    #[test]
    fn copy_new_refuses_existing_file() {
        let dir = scratch("exist");
        let dest = dir.join("dest");
        std::fs::write(&dest, b"old").expect("write");
        let e = file_copy::copy_new(&dir.join("src"), &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&dest).expect("read"), b"old");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-12・SEC-2・#3041: 宛先が symlink なら辿らず失敗し、指す先は変わらない。
    #[test]
    fn copy_new_refuses_symlink_without_following_it() {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("write");
        let dest = dir.join("dest");
        std::os::unix::fs::symlink(&victim, &dest).expect("symlink");
        let e = file_copy::copy_new(&dir.join("src"), &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&victim).expect("read"), b"keep");
        assert!(is_symlink(&dest));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-12・SEC-2・#3041: dangling symlink でも失敗し、指す先は作られない。
    #[test]
    fn copy_new_refuses_dangling_symlink_without_creating_target() {
        let dir = scratch("dangling");
        let target = dir.join("target");
        let dest = dir.join("dest");
        std::os::unix::fs::symlink(&target, &dest).expect("symlink");
        let e = file_copy::copy_new(&dir.join("src"), &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::symlink_metadata(&target).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-12・#3041: `replace_with_copy` は symlink 自体を消して通常ファイルを作り、指す先は変えない
    /// （`fs::copy` が symlink 越しに書いていた挙動との差を固定する）。
    #[test]
    fn replace_with_copy_replaces_symlink_not_its_target() {
        let dir = scratch("replace-link");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("write");
        let dest = dir.join("dest");
        std::os::unix::fs::symlink(&victim, &dest).expect("symlink");
        file_copy::replace_with_copy(&dir.join("src"), &dest).expect("replace");
        assert!(!is_symlink(&dest));
        assert_eq!(std::fs::read(&dest).expect("read"), b"new");
        let mode = std::fs::metadata(&dest).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_eq!(std::fs::read(&victim).expect("read"), b"keep");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-12・#3041: `replace_with_copy` は既存の通常ファイルを置き換える。
    #[test]
    fn replace_with_copy_replaces_existing_file() {
        let dir = scratch("replace-file");
        let dest = dir.join("dest");
        std::fs::write(&dest, b"old").expect("write");
        file_copy::replace_with_copy(&dir.join("src"), &dest).expect("replace");
        assert_eq!(std::fs::read(&dest).expect("read"), b"new");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-8・#3041: 包みはパスを載せず `io-error` と `ErrorKind` だけを出す。
    #[test]
    fn copy_new_wrapper_reports_kind_without_path() {
        let dir = scratch("wrapper");
        let dest = dir.join("dest");
        std::fs::write(&dest, b"old").expect("write");
        let e = copy_new(&dir.join("src"), &dest, "copy test").unwrap_err();
        assert_eq!(e.code, "io-error");
        assert!(!e.message.contains("fc-filecopy"), "{}", e.message);
        assert!(e.message.contains("AlreadyExists"), "{}", e.message);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn ld_library_path_dedups_parents_in_order() {
        let libs = [
            PathBuf::from("/a/lib/x.so"),
            PathBuf::from("/b/y.so"),
            PathBuf::from("/a/lib/z.so"),
        ];
        assert_eq!(loader_deps::ld_library_path(&libs), "/a/lib:/b");
        assert_eq!(loader_deps::ld_library_path(&[]), "");
    }
}
