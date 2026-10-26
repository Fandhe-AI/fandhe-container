//! 実機前提の結合試験が使う最小 rootfs の組み立て部品（`exec_subordinate_e2e` 専用。SEC-5・CORE-6・REPAIR-12。#2835）。
//!
//! 試験バイナリ自身を rootfs の `/probe`（別 inode のコピー。ランタイム自身のバイナリを exec させない）へ置き、
//! 動的ローダ（ELF の `PT_INTERP`）と読み込み済みの共有ライブラリを同じ絶対パスへコピーする。ロジックは
//! `supervisor_bin_real.rs` の `make_rootfs`・`elf_interp`・`loaded_libraries`・`copy_into` と同じで、本ファイルは
//! `#[path = "support/rootfs.rs"] mod rootfs;` で取り込む（`tests/support/` には `main.rs` が無く cargo の自動検出の
//! 対象にならない）。`supervisor_bin_real.rs` との共通化は追跡事項（スコープ外）。
//!
//! 契約: 失敗はすべて panic。ELF の読み取り（外部入力）は `get()` で範囲を検査し、添字アクセスをしない。

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// `path` を（親も含めて）作り 0755 にする。失敗は panic。
pub fn mkdir(path: &Path) {
    std::fs::create_dir_all(path).unwrap_or_else(|e| panic!("mkdir {}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

/// `host` のファイルを rootfs 内の同じ絶対パスへ（実体の内容を通常ファイルとして）コピーする。
fn copy_into(rootfs: &Path, host: &Path, mode: u32) {
    let dest = rootfs.join(host.strip_prefix("/").expect("absolute path"));
    mkdir(dest.parent().expect("parent"));
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(host, &dest)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", host.display(), dest.display()));
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", dest.display()));
}

/// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` で検査する。
fn elf_interp(exe: &[u8]) -> Option<String> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(exe.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(exe.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(exe.get(o..o + 8)?.try_into().ok()?));
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

/// 自プロセスに読み込み済みの共有ライブラリの実パス（`/proc/self/maps` から。重複なし）。
fn loaded_libraries(exe: &Path) -> Vec<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
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

/// 最小 rootfs を作る（`proc`・`dev`・`tmp`・`etc` と `/probe`・ローダ・共有ライブラリ）。戻り値はプローブが使う
/// `LD_LIBRARY_PATH` の値。
pub fn make_rootfs(rootfs: &Path) -> String {
    mkdir(rootfs);
    for d in ["proc", "dev", "tmp", "etc"] {
        mkdir(&rootfs.join(d));
    }
    let exe = std::env::current_exe().expect("current_exe");
    let exe = std::fs::canonicalize(exe).expect("canonicalize exe");
    let probe = rootfs.join("probe");
    std::fs::copy(&exe, &probe).expect("copy probe binary");
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).expect("chmod probe");
    let bytes = std::fs::read(&exe).expect("read exe");
    let mut lib_dirs: Vec<String> = Vec::new();
    if let Some(interp) = elf_interp(&bytes) {
        copy_into(rootfs, Path::new(&interp), 0o755);
    }
    for lib in loaded_libraries(&exe) {
        copy_into(rootfs, &lib, 0o755);
        if let Some(dir) = lib.parent().and_then(Path::to_str)
            && !lib_dirs.iter().any(|d| d == dir)
        {
            lib_dirs.push(dir.to_string());
        }
    }
    lib_dirs.join(":")
}
