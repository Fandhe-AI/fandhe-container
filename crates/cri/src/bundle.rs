//! CRI の設定から OCI bundle を作る層（CRI-1・CRI-2・ERR-3・OCI-4・SEC-1・SEC-5・REPAIR-2・REPAIR-3。#2395・TASK-60 追補）。
//!
//! - [`spec`]: `PodSandboxConfig` と `ContainerConfig` から `config.json` への純粋な変換と入力検証
//!   （[`build_runtime_config`]）。ファイルシステムに触れない。
//! - [`provider`]: bundle ディレクトリの作成・`config.json` の書き込み・解放を担う [`SpecBundleProvider`]
//!   （[`crate::adapter::BundleProvider`] の汎用実装）と、`rootfs/` の用意の注入点 [`RootfsSource`]。
//!
//! **未実装・簡易実装（REPAIR-3）**: 本番の [`RootfsSource`]（イメージのレイヤー展開とイメージ config の
//! Entrypoint・Cmd・Env・WorkingDir・User の読み取り）と、plugin-cri の `main.rs` への結線は #2433 の範囲で、
//! 本モジュールは変換と上限検証、bundle の寿命までを提供する。start・kill・stop の本番結線は #2434。
//! crictl の `runp`→`create`→`start` の実機確認（#442）が最後まで通るには #2433・#2434 も要る。
//! #2433 の config 変換と上限検証は [`build_runtime_config`] を使う。

pub mod provider;
pub mod spec;

pub use provider::{RootfsSource, SpecBundleProvider};
pub use spec::{ImageDefaults, RuntimeConfigJson, build_runtime_config, validate_config};
