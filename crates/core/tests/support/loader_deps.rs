//! 試験バイナリを最小 rootfs へ写すときの「動的ローダと共有ライブラリの特定」の純粋な解析部品
//! （REPAIR-1・REPAIR-12・SEC-5。#2963・#2889）。
//!
//! # 利用元
//! `minimal_rootfs.rs`（core・supervisor・cli の実機前提試験の rootfs 組み立て）と
//! `benches/src/startup_latency/bundle.rs`（起動 p95 ベンチの bundle 構築）が `#[path]` で取り込む。
//! ELF の `PT_INTERP` の解析・`/proc/self/maps` の解釈・`LD_LIBRARY_PATH` の組み立てを 1 か所に集め、
//! 修正が 4 か所へ波及するのを避ける。
//!
//! # 契約
//! - std のみに依存し、`fandhe_container_*` を use しない。panic もしない（エラーの形は呼び出し側が決める）
//! - 外部入力（ELF・maps の本文）は `get()` と checked 演算だけで読み、添字アクセスや溢れる加算をしない
//! - 取り込み元ごとに使う項目が違うため `dead_code` を許す
//!
//! # 置き場所の判断
//! crate をまたぐ共有は `#[path]` で行う（前例は `scratch_root.rs`）。試験用の補助 crate は、workspace メンバーの追加と
//! 各 crate の dev-dependencies の追加が要り、依存を増やさない方針に反するため採らない。
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` と checked 演算で検査する。
pub fn elf_interp(exe: &[u8]) -> Option<String> {
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

/// `/proc/self/maps` の本文から、読み込み済み共有ライブラリの実パスを重複なしで集める（`exe` 自身と擬似パスは除く）。
pub fn libraries_from_maps(maps: &str, exe: &Path) -> Vec<PathBuf> {
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

/// 自プロセスに読み込み済みの共有ライブラリの実パス（`/proc/self/maps` から。重複なし）。
pub fn loaded_libraries(exe: &Path) -> std::io::Result<Vec<PathBuf>> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    Ok(libraries_from_maps(&maps, exe))
}

/// ライブラリの親ディレクトリを出現順・重複なしで `:` 区切りにした `LD_LIBRARY_PATH` の値。
pub fn ld_library_path(libs: &[PathBuf]) -> String {
    let mut dirs: Vec<&str> = Vec::new();
    for lib in libs {
        if let Some(dir) = lib.parent().and_then(Path::to_str)
            && !dirs.contains(&dir)
        {
            dirs.push(dir);
        }
    }
    dirs.join(":")
}
