//! コンテナ起動時オプション群（SUP-12・TASK-169。namespace・cgroup 作成時の設定または `execve`
//! 引数へ反映する Docker 互換オプション）の入口。
//!
//! # 役割
//!
//! オプションごとにサブモジュールを置き、Docker 互換の文字列文法を解析して `fandhe-container-core` の
//! 検証済み型へ変換する薄い層とする（実際の適用は core。supervisor → core の一方向依存）。
//!
//! | サブモジュール | TASK | 内容 |
//! | -------------- | ---- | ---- |
//! | [`mounts`] | TASK-169.2（#527） | `--shm-size` / `--tmpfs`（tmpfs の仕様型への変換。適用は core の `exec::mount_tmpfs`） |
//!
//! `--ulimit`（TASK-169.1）・`--ipc`（TASK-169.3）・env/secrets/configs（TASK-169.4）・label は別 Issue で、
//! 未実装（REPAIR-3）。

pub mod mounts;

pub use mounts::{DEFAULT_SHM_SIZE_BYTES, MountOptions, ShmSize, TmpfsOption};
