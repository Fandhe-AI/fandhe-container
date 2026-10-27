//! 起動対象の差し替え試験の共通部品（unix。Linux は fd の実体を実行する試験、macOS は直前の同一性確認の試験。#1856・#1866・PLUG-11）。`lifecycle_one_shot.rs` と
//! `lifecycle_resident.rs` が `#[path]` で取り込む。構築口を呼んでよいのは試験コードだけ。

use fandhe_container_plugin::{PluginError, PluginLaunchTarget};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Fixture {
    dir: PathBuf,
    orig: PathBuf,
    target: PluginLaunchTarget,
}

fn unique_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "swap-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Fixture {
    /// テストバイナリ自身を hard link（別ファイルシステムなら copy）した実行ファイルを起動対象にする。
    pub fn new() -> Self {
        let dir = unique_dir();
        let orig = dir.join("plugin");
        let exe = std::env::current_exe().unwrap();
        if std::fs::hard_link(&exe, &orig).is_err() {
            std::fs::copy(&exe, &orig).unwrap();
        }
        Self::with_target(dir, orig)
    }

    // `lifecycle_resident.rs` は同じ inode の書き換え試験を行わないため未使用になる。
    #[allow(dead_code)]
    /// 小さな非スクリプトファイル（モード 0700）を起動対象にする（同じ inode の書き換え試験用）。
    pub fn new_rewritable() -> Self {
        let dir = unique_dir();
        let orig = dir.join("plugin");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&orig)
            .unwrap();
        f.write_all(b"not a script\n").unwrap();
        drop(f);
        Self::with_target(dir, orig)
    }

    fn with_target(dir: PathBuf, orig: PathBuf) -> Self {
        let target = PluginLaunchTarget::from_verified_file(
            File::open(&orig).unwrap(),
            orig.clone(),
            orig.clone(),
        )
        .unwrap();
        Self { dir, orig, target }
    }

    pub fn target(&self) -> PluginLaunchTarget {
        self.target.clone()
    }

    // macOS では Linux 専用の試験からしか呼ばれない。
    #[allow(dead_code)]
    /// 元のパスへ別の inode（`exit 0` するだけのスクリプト）を rename で置く。
    pub fn replace_with_script(&self) {
        let tmp = self.dir.join("replacement");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&tmp)
            .unwrap();
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        drop(f);
        std::fs::rename(&tmp, &self.orig).unwrap();
    }

    /// 元のパスへ別の inode（実行すると `marker` を作るスクリプト）を rename で置く（#1866。macOS で
    /// 子が spawn されないことの照合用）。
    #[allow(dead_code)]
    pub fn replace_with_marker_script(&self, marker: &std::path::Path) {
        let tmp = self.dir.join("replacement-marker");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&tmp)
            .unwrap();
        f.write_all(format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes())
            .unwrap();
        drop(f);
        std::fs::rename(&tmp, &self.orig).unwrap();
    }

    /// マーカーを置く場所（作業ディレクトリ内）。
    #[allow(dead_code)]
    pub fn marker_path(&self) -> PathBuf {
        self.dir.join("spawned-marker")
    }

    // `lifecycle_resident.rs` は同じ inode の書き換え試験を行わないため未使用になる。
    #[allow(dead_code)]
    /// 同じ inode の中身を `#!` スクリプトへ書き換える。
    pub fn rewrite_in_place_to_script(&self) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.orig)
            .unwrap();
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
    }

    // `lifecycle_resident.rs` の macOS 側の試験は使わない。
    #[allow(dead_code)]
    /// 現在のパスから起動対象を作り直す（差し替えを検出できることの対照）。
    pub fn try_target_from_path(&self) -> Result<PluginLaunchTarget, PluginError> {
        PluginLaunchTarget::from_verified_file(
            File::open(&self.orig).unwrap(),
            self.orig.clone(),
            self.orig.clone(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
