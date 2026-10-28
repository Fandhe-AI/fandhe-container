//! 実機前提試験が使う最小 rootfs の組み立て部品（core・supervisor・cli 共通。REPAIR-1・REPAIR-12・SEC-5・SEC-2。
//! #2963・#2889）。
//!
//! 試験バイナリ自身を `rootfs/<dest_name>` へ置き、動的ローダ（ELF の `PT_INTERP`）と読み込み済みの共有ライブラリを
//! 同じ絶対パスへコピーして、`LD_LIBRARY_PATH` の値を返す。解析は `loader_deps.rs`（`loader_deps` として公開）。
//!
//! # 利用元
//! core の `real_entry.rs`（`production_launcher`・rootless 系・`seccomp`）、supervisor の `support/rootfs.rs`
//! （`exec_subordinate_e2e`・`supervisor_bin_real`）、cli の `start_stop_delete_real`。各利用元が `#[path]` で取り込む
//! （`tests/support/` には `main.rs` が無く cargo の自動検出の対象にならない）。
//!
//! # 契約
//! - エラーは `Result<_, String>`。panic 契約の利用元（core・supervisor）は薄い包みで panic にし、cli は `?` で `FAILED:` 行へ流す
//! - `mkdir` は祖先を 1 階層ずつ `lstat` し、symlink や非ディレクトリを拒否する（`create_dir_all` は symlink を辿るため使わない。#2324）
//! - 作成順は「ディレクトリ → バイナリ → ローダ・共有ライブラリ」。mode は 0755
//! - コピーは `file_copy.rs`（`create_new`・symlink を辿らない。#3041）を使う。benches の `bundle.rs` も同じ部品を共有する
//!
//! # 置き場所の判断
//! crate をまたぐ共有は `#[path]`（前例は `scratch_root.rs`）。補助 crate は workspace メンバーと dev-dependencies の
//! 追加が要るため採らない。std のみに依存し、`fandhe_container_core` は use しない。

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

#[path = "file_copy.rs"]
pub mod file_copy;
#[path = "loader_deps.rs"]
pub mod loader_deps;

/// `path` までの祖先を 1 階層ずつ `lstat` して非 symlink のディレクトリだけを許容し、無ければ `create_dir` で作って
/// 0755 にする。基点の親は呼び出し元が保護済み（scratch_root 配下）であること。
pub fn mkdir(path: &Path) -> Result<(), String> {
    let mut chain: Vec<&Path> = path.ancestors().filter(|a| a.parent().is_some()).collect();
    chain.reverse();
    for dir in chain {
        match std::fs::symlink_metadata(dir) {
            Ok(md) => {
                if !md.is_dir() || md.file_type().is_symlink() {
                    return Err(format!(
                        "{} exists and is not a plain directory",
                        dir.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            }
            Err(e) => return Err(format!("lstat {}: {e}", dir.display())),
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// `host` のファイルを rootfs 内の同じ絶対パスへ（実体の内容を通常ファイルとして）コピーする。
fn copy_into(rootfs: &Path, host: &Path) -> Result<(), String> {
    let rel = host
        .strip_prefix("/")
        .map_err(|_| format!("not absolute: {}", host.display()))?;
    let dest = rootfs.join(rel);
    mkdir(dest.parent().ok_or("no parent")?)?;
    file_copy::replace_with_copy(host, &dest)
        .map_err(|e| format!("copy {} -> {}: {e}", host.display(), dest.display()))
}

/// 試験バイナリ自身を `rootfs/<dest_name>`（0755）へ置き、動的ローダと読み込み済みの共有ライブラリを同じ絶対パスへ
/// コピーする。`rootfs` と `dirs`（rootfs 直下のディレクトリ名）を先に作る。戻り値は `LD_LIBRARY_PATH` の値。
pub fn install_binary_at(rootfs: &Path, dest_name: &str, dirs: &[&str]) -> Result<String, String> {
    mkdir(rootfs)?;
    for d in dirs {
        mkdir(&rootfs.join(d))?;
    }
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe = std::fs::canonicalize(exe).map_err(|e| format!("canonicalize exe: {e}"))?;
    let dest = rootfs.join(dest_name);
    file_copy::replace_with_copy(&exe, &dest).map_err(|e| format!("copy the test binary: {e}"))?;
    let bytes = std::fs::read(&exe).map_err(|e| format!("read exe: {e}"))?;
    if let Some(interp) = loader_deps::elf_interp(&bytes) {
        // ローダは PT_INTERP のパスのまま（symlink を辿らず）rootfs 内で開かれるため、実体の内容をそのパスへ置く。
        copy_into(rootfs, Path::new(&interp))?;
    }
    let libs = loader_deps::loaded_libraries(&exe).map_err(|e| format!("read maps: {e}"))?;
    for lib in &libs {
        copy_into(rootfs, lib)?;
    }
    Ok(loader_deps::ld_library_path(&libs))
}
