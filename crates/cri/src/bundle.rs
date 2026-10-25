//! CRI の設定から OCI bundle を作る層（CRI-1・CRI-2・ERR-3・OCI-4・SEC-1・SEC-5・REPAIR-2・REPAIR-3。#2395・TASK-60 追補）。
//!
//! - [`spec`]: `PodSandboxConfig` と `ContainerConfig` から `config.json` への純粋な変換と入力検証
//!   （[`build_runtime_config`]）。ファイルシステムに触れない。
//! - [`provider`]: bundle ディレクトリの作成・`config.json` の書き込み・解放を担う [`SpecBundleProvider`]
//!   （[`crate::adapter::BundleProvider`] の汎用実装）と、`rootfs/` の用意の注入点 [`RootfsSource`]。
//!
//! - [`image_rootfs`]: 本番の [`RootfsSource`] [`ImageRootfsSource`]（pull 済みイメージを bundle の `rootfs/` へ再展開し、
//!   イメージ config の Entrypoint・Cmd・Env・WorkingDir・User を [`ImageDefaults`] で返す。#2433）。
//!
//! **未実装・簡易実装（REPAIR-3）**: タグ・digest 参照の解決（plugin-cri は `ImageService` をサーブしていない）、
//! イメージの User の名前解決、overlay による rootfs の用意は未実装で、詳細は [`image_rootfs`] の doc。
//! start・kill・stop の本番結線は #2434。crictl の `runp`→`create`→`start` の実機確認（#442）が最後まで通るには
//! タグ解決（`container.json` がタグのため）と #2434 も要る。

pub mod image_rootfs;
pub mod provider;
pub mod spec;

pub use image_rootfs::{ImageExtractConfig, ImageRootfsSource};
pub use provider::{RootfsSource, SpecBundleProvider, UserResolveRequest};
pub use spec::{ImageDefaults, RuntimeConfigJson, build_runtime_config, validate_config};
