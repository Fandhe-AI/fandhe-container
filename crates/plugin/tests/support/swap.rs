//! 起動対象の差し替え試験の共通部品（Linux。#1856・PLUG-11）。`lifecycle_one_shot.rs` と
//! `lifecycle_resident.rs` が `#[path]` で取り込む。構築口を呼んでよいのは試験コードだけ。

// 取り込み側のテストファイルごとに使う部品が異なる。
#![allow(dead_code)]

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

    /// 同じ inode の中身を `#!` スクリプトへ書き換える。
    pub fn rewrite_in_place_to_script(&self) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.orig)
            .unwrap();
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
    }

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
