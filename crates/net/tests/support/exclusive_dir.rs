//! root で動く `*_privileged` 試験の launcher が使う、残骸に強い一時ディレクトリの作成（REPAIR-12・#3375）。
//!
//! 名前が `<prefix>-<pid>` だけだと、PID の再利用や前回の異常終了の残骸と衝突して `create_dir` が
//! `AlreadyExists` になる。誰でも書ける `temp_dir()` で root が予測できる名前を再帰削除すると、
//! 削除と作成の間に先取りされる余地がある（`/tmp` の symlink 差し替え）ため、
//! ここでは既存のパスを**消さず**、排他作成（0700）がぶつかったら連番を進める。
//! 後始末は呼び出し側の `remove_dir`（またはガード）が行う。

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// 連番を進める上限。超えたら残骸が多すぎるとして `AlreadyExists` を返す（fail-closed）。
const MAX_ATTEMPTS: u32 = 1000;

/// `temp_dir()/<prefix>-<pid>-<n>` を排他的に（0700 で）作って返す。既存のパスは消さない。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn create(prefix: &str) -> io::Result<PathBuf> {
    create_in(&std::env::temp_dir(), prefix)
}

/// `create` の親ディレクトリ指定版（残骸の試験が専用の親で呼ぶ）。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn create_in(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    for n in 0..MAX_ATTEMPTS {
        let p = parent.join(format!("{prefix}-{}-{n}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many stale test directories",
    ))
}
