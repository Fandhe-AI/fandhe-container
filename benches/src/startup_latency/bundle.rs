//! 外部イメージを使わない最小 rootfs と `config.json` の構築（TASK-190・OCI-4・REPAIR-3）。
//!
//! ベンチ自身の実行ファイルを rootfs の `/probe` へコピーし、動的ローダと読み込み済みの共有ライブラリを同じ
//! 絶対パスへ写す。ワークロードは同じ実行ファイルを `--startup-latency-probe <nonce>` で再実行したもの
//! （固定時間眠って終了。`startup_latency::run_workload`）。方式は
//! `crates/supervisor/tests/supervisor_bin_real.rs`（#1819）の rootfs 構築と同じで、解析部品（ELF・maps・
//! `LD_LIBRARY_PATH`）は core の `tests/support/loader_deps.rs` と共有する（#2963）。ファイル操作は、パスをエラーに載せない・
//! `create_new` で書く契約が強いため共有せず、ここに残す。
//! bundle は計測の前に 1 回だけ作り、全試行で再利用する（区間の外）。

use super::StartupLatencyError;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// ELF の解析・maps の解釈・`LD_LIBRARY_PATH` の組み立て。core・supervisor・cli の試験と共有する
/// （`#[path]`。置き場所の判断は同ファイルの `//!`。#2963・REPAIR-1）。
#[path = "../../../crates/core/tests/support/loader_deps.rs"]
mod loader_deps;

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

fn chmod(path: &Path, mode: u32) -> Result<(), StartupLatencyError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io_err("set permissions", &e))
}

/// `src` を `dest` へ新規作成でコピーする。宛先は `create_new`（O_CREAT|O_EXCL）で開くため、既存のファイルや
/// symlink があれば（指す先を辿らずに）失敗し、呼び出しユーザーの任意のファイルを上書きしない。mode は 0755。
fn copy_new(src: &Path, dest: &Path, what: &'static str) -> Result<(), StartupLatencyError> {
    let mut input = std::fs::File::open(src).map_err(|e| io_err(what, &e))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(dest)
        .map_err(|e| io_err(what, &e))?;
    std::io::copy(&mut input, &mut output).map_err(|e| io_err(what, &e))?;
    chmod(dest, 0o755)
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
    let _ = std::fs::remove_file(&dest);
    copy_new(host, &dest, "copy library")
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

    #[test]
    fn copy_new_refuses_existing_symlink_without_following_it() {
        let dir = std::env::temp_dir().join(format!("fc-bundle-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("write");
        let src = dir.join("src");
        std::fs::write(&src, b"new").expect("write");
        let dest = dir.join("dest");
        std::os::unix::fs::symlink(&victim, &dest).expect("symlink");
        let e = copy_new(&src, &dest, "copy test").unwrap_err();
        assert_eq!(e.code, "io-error");
        assert_eq!(std::fs::read(&victim).expect("read"), b"keep");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn copy_new_refuses_existing_file_and_creates_new_with_0755() {
        let dir = std::env::temp_dir().join(format!("fc-bundle-copy2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        let src = dir.join("src");
        std::fs::write(&src, b"new").expect("write");
        let dest = dir.join("dest");
        copy_new(&src, &dest, "copy test").expect("first copy");
        assert_eq!(std::fs::read(&dest).expect("read"), b"new");
        let mode = std::fs::metadata(&dest).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert!(copy_new(&src, &dest, "copy test").is_err());
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
