//! rootfs へ実行ファイル・共有ライブラリを写すファイルコピーの共有部品（#3041・REPAIR-1・REPAIR-12・SEC-2）。
//!
//! 利用元は core の `minimal_rootfs.rs`（core・supervisor・cli の実機前提試験）と
//! `benches/src/startup_latency/bundle.rs`。どちらも `#[path]` で取り込む。以前は benches だけが `create_new` で書き、
//! 試験側は `std::fs::copy`（宛先の symlink を辿って指す先へ書く）で、方式が 2 系統に割れていた。強い方へ統一する。
//!
//! # 契約
//! - 宛先は `create_new`（O_CREAT|O_EXCL）・mode 0755 で開く。既存の通常ファイル・symlink（dangling を含む）があれば
//!   `ErrorKind::AlreadyExists` で失敗し、symlink は辿らない（指す先を作らず変更しない）
//! - エラーは `std::io::Error` のまま返し、パスも文脈も載せない。整形は取り込み元が行う
//!   （benches は `ErrorKind` だけを出す契約、試験側はパスつきの文言）
//!
//! # 置き場所の判断
//! 解析専用の `loader_deps.rs` にはファイル操作を入れず別ファイルにした。std のみに依存し、
//! `fandhe_container_*` は use しない。補助 crate は依存追加が要るため採らない（前例は `scratch_root.rs`）。
//! 単体試験は取り込み先ごとの重複実行を避け、benches の lib（`bundle.rs`）に置く。

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// `src` を `dest` へ新規作成でコピーし、mode を 0755 にする。宛先に何かあれば `AlreadyExists` で失敗する。
pub fn copy_new(src: &Path, dest: &Path) -> std::io::Result<()> {
    let mut input = std::fs::File::open(src)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(dest)?;
    std::io::copy(&mut input, &mut output)?;
    // umask で落ちたビットを戻す。
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))
}

/// 宛先の既存エントリ（symlink は指す先ではなくリンク自体）を消してから [`copy_new`] する。削除の失敗は無視するが、
/// 何かが残っていたり削除後に別のものが置かれたりしても `create_new` が失敗するため fail-closed。
pub fn replace_with_copy(src: &Path, dest: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(dest);
    copy_new(src, dest)
}
