//! 外部イメージを使わない最小 rootfs と `config.json` の構築（TASK-190・OCI-4・REPAIR-3）。
//!
//! ベンチ自身の実行ファイルを rootfs の `/probe` へコピーし、動的ローダと読み込み済みの共有ライブラリを同じ
//! 絶対パスへ写す。ワークロードは同じ実行ファイルを `--startup-latency-probe <nonce>` で再実行したもの
//! （固定時間眠って終了。`startup_latency::run_workload`）。方式は
//! `crates/supervisor/tests/supervisor_bin_real.rs`（#1819）の rootfs 構築を写した（crate が違うため共有できない）。
//! ELF 解析・`/proc/self/maps` の解釈は `get()` と checked 演算だけで行う（外部入力の経路の規約）。
//! bundle は計測の前に 1 回だけ作り、全試行で再利用する（区間の外）。

use super::StartupLatencyError;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

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
    std::fs::copy(host, &dest).map_err(|e| io_err("copy library", &e))?;
    chmod(&dest, 0o755)
}

/// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` と checked 演算で検査する。
fn elf_interp(exe: &[u8]) -> Option<String> {
    let u16_at = |o: usize| {
        Some(u16::from_le_bytes(
            exe.get(o..o.checked_add(2)?)?.try_into().ok()?,
        ))
    };
    let u32_at = |o: usize| {
        Some(u32::from_le_bytes(
            exe.get(o..o.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let u64_at = |o: usize| {
        Some(u64::from_le_bytes(
            exe.get(o..o.checked_add(8)?)?.try_into().ok()?,
        ))
    };
    if exe.get(0..4)? != b"\x7fELF" {
        return None;
    }
    let phoff = usize::try_from(u64_at(0x20)?).ok()?;
    let phentsize = usize::from(u16_at(0x36)?);
    let phnum = usize::from(u16_at(0x38)?);
    for i in 0..phnum {
        let base = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(base)? == 3 {
            let off = usize::try_from(u64_at(base.checked_add(8)?)?).ok()?;
            let len = usize::try_from(u64_at(base.checked_add(32)?)?).ok()?;
            let raw = exe.get(off..off.checked_add(len)?)?;
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            return String::from_utf8(raw.get(..end)?.to_vec()).ok();
        }
    }
    None
}

/// `/proc/self/maps` の本文から、読み込み済み共有ライブラリの実パスを重複なしで集める。
fn libraries_from_maps(maps: &str, exe: &Path) -> Vec<PathBuf> {
    let mut libs: Vec<PathBuf> = Vec::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        let p = PathBuf::from(path);
        if !path.starts_with('/')
            || p == exe
            || ["/dev/", "/proc/", "/sys/", "/tmp/", "/memfd:"]
                .iter()
                .any(|pre| path.starts_with(pre))
            || libs.contains(&p)
        {
            continue;
        }
        if std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            libs.push(p);
        }
    }
    libs
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
    std::fs::copy(&exe, &probe).map_err(|e| io_err("copy probe binary", &e))?;
    chmod(&probe, 0o755)?;
    let bytes = std::fs::read(&exe).map_err(|e| io_err("read current exe", &e))?;
    if let Some(interp) = elf_interp(&bytes) {
        copy_into(rootfs, Path::new(&interp))?;
    }
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| io_err("read maps", &e))?;
    let mut lib_dirs: Vec<String> = Vec::new();
    for lib in libraries_from_maps(&maps, &exe) {
        copy_into(rootfs, &lib)?;
        if let Some(dir) = lib.parent().and_then(Path::to_str)
            && !lib_dirs.iter().any(|d| d == dir)
        {
            lib_dirs.push(dir.to_string());
        }
    }
    Ok(lib_dirs.join(":"))
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
            elf_interp(&elf).as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn truncated_or_non_elf_input_is_none() {
        assert_eq!(elf_interp(b"not elf"), None);
        let mut elf = le_elf_with_interp(b"/lib/ld.so");
        elf.truncate(0x50);
        assert_eq!(elf_interp(&elf), None);
        assert_eq!(elf_interp(&[]), None);
    }

    #[test]
    fn maps_parsing_skips_pseudo_and_duplicate_entries() {
        let maps = "\
7f00-7f01 r-xp 0 00:00 0 /proc/self/exe\n\
7f01-7f02 r-xp 0 00:00 0 [vdso]\n\
7f02-7f03 r-xp 0 00:00 0\n\
7f03-7f04 r-xp 0 00:00 0 /nonexistent/libx.so\n";
        assert!(libraries_from_maps(maps, Path::new("/x/exe")).is_empty());
    }
}
