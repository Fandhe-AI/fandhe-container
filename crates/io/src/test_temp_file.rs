//! 試験用の一時ファイルを、予測できる名前の先行削除・上書きをせずに排他作成する補助
//! （REPAIR-12・#3479。core の `ScratchDir`・net の `exclusive_dir` と同じ方針）。
//!
//! 名前が `<prefix>-<pid>` だけだと、前回の異常終了や別ユーザーの残骸と衝突し、`File::create` は
//! 既存の symlink を辿って切り詰める。ここでは `create_new`（`O_CREAT | O_EXCL` / `CREATE_NEW`、
//! symlink を辿らない）で作り、`AlreadyExists` なら連番を進める。後始末は [`TempFile`] の drop が
//! 自分で作ったファイルだけ行う。barrier / writeback / sys の単体試験から使い、製品コードは不変。

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// 連番を進める上限。超えたら残骸が多すぎるとして `AlreadyExists` を返す（fail-closed）。
const MAX_ATTEMPTS: u32 = 1000;

/// 排他作成したファイルの所有ガード。drop で自分の分だけ消す（既に無くても無視）。
pub(crate) struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// 作成したファイルのパス。
    #[allow(dead_code)] // OS ごとに使う試験が異なるため
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `dir/<prefix>-<pid>-<n>` を排他的に作る（unix は 0600）。既存のパスは消さない。
pub(crate) fn create_in(dir: &Path, prefix: &str) -> io::Result<(TempFile, File)> {
    for n in 0..MAX_ATTEMPTS {
        let path = dir.join(format!("{prefix}-{}-{n}", std::process::id()));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(file) => return Ok((TempFile { path }, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many stale test files",
    ))
}

/// `temp_dir()` 直下に作る版。
#[allow(dead_code)] // OS ごとに使う試験が異なるため
pub(crate) fn create(prefix: &str) -> io::Result<(TempFile, File)> {
    create_in(&std::env::temp_dir(), prefix)
}

/// 試験用の専用の親ディレクトリ。`temp_dir()` 直下に排他作成し、drop で自分の分だけ消す。
#[cfg(test)]
pub(crate) struct TempDir(PathBuf);

#[cfg(test)]
impl TempDir {
    /// `temp_dir()/<prefix>-<pid>-<n>` を排他作成する（既存は消さず連番を進める）。
    pub(crate) fn new(prefix: &str) -> Self {
        for n in 0..MAX_ATTEMPTS {
            let p = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("mkdir failed: {e}"),
            }
        }
        panic!("too many stale test directories");
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 残骸（同名の通常ファイル・symlink）を先に置いても消さず・辿らず連番を進めること
    /// （IO-2・REPAIR-12・#3479）。
    #[test]
    fn io2_repair12_exclusive_temp_file_skips_stale_residue() {
        let parent = TempDir::new("fcio-tf-residue");
        let parent = parent.path();
        let pid = std::process::id();
        let stale0 = parent.join(format!("t-{pid}-0"));
        std::fs::write(&stale0, b"stale").unwrap();
        let canary = parent.join("canary");
        std::fs::write(&canary, b"canary").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&canary, parent.join(format!("t-{pid}-1"))).unwrap();
        // unix は `-1` の symlink も飛ばして `-2`、それ以外は `-1`。
        let expect = if cfg!(unix) { 2 } else { 1 };
        let new_path = {
            let (guard, file) = create_in(parent, "t").unwrap();
            assert_eq!(guard.path(), parent.join(format!("t-{pid}-{expect}")));
            assert_eq!(file.metadata().unwrap().len(), 0);
            guard.path().to_path_buf()
        };
        assert!(!new_path.exists(), "own file must be removed on drop");
        assert_eq!(std::fs::read(&stale0).unwrap(), b"stale");
        assert_eq!(std::fs::read(&canary).unwrap(), b"canary");
    }
}
