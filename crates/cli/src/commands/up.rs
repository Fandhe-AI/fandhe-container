//! `up`: プロジェクト定義（TOML）のサービスを依存順に create → start する（STACK-8・STACK-2・STACK-10・SEC-1・TASK-155・#4638）。
//!
//! # 役割と呼び出し元
//! `commands::run` が `up --file <toml> --image-root <abs> [--project-name <n>] [--profile <p>]... [<service>...]` を
//! 解析して [`run_up`] を呼ぶ。純ロジック（依存順の計画・待ち・`create` / `start` の argv の組み立て・プロジェクト名と
//! コンテナ ID の規則・依存閉包）は stack crate（`fandhe_container_stack::cli::up`）にあり、本 module は stack が注入点
//! として定義した 4 つのポートの本番アダプタを cli 側に置く（`stack -> core` の辺を張らない。#4630）。
//!
//! | ポート | 本番アダプタ |
//! | ------ | ------------ |
//! | `ServiceLauncher` | [`launcher`]: bundle を用意して CLI 自身の `create --unpack` → `start` を子プロセスで期限つきに呼ぶ |
//! | `DependencyObserver` / `HealthSource` | [`observe`]: 今回の `up` が作ったものに限り、状態ストアの記録を読む |
//! | `NetworkProvisioner` | [`provision`]: `network ls` / `network create` と同じ経路で定義の存在確認と作成 |
//!
//! launcher・observer・health は [`observe::Ledger`]（サービス名 → 今回 create したコンテナ ID）を共有し、
//! 「前回の実行の残骸を満たし扱いしない」契約（`ServiceLauncher` の (b)）を満たす。
//!
//! # 副作用の順序（fail-closed）
//! 引数・TOML・プロファイル・依存閉包・全サービスの事前検査（argv の組み立て・`env_files` の fd 起点の読み取り・イメージの
//! 解決とプロセス設定の合成）をすべて済ませてから、初めてネットワークの作成と bundle の作成・子プロセスの起動を行う
//! ([`prepare`])。どれかが拒否されたら起動ゼロで失敗する。途中で失敗したときのロールバックはしない（`down` の責務）。
//!
//! # 実装済みを装わない（REPAIR-3）
//! - `down`・`ps`・プロジェクト単位の `logs` の CLI 結線は未実装（後続 issue）。ID の導出（`ServiceContainerId::derive`）と
//!   プロジェクト名の解決（`resolve_project_name`）は stack の同じ関数を使うため、結線時に食い違わない。
//! - `healthcheck`・`volumes`・`deploy`・`restart` 等、`create` に写す先が無いフィールドは `UNIMPLEMENTED` で拒否する
//!   （詳細は `docs/design/stack-up-wiring.md`）。このため `depends_on: healthy` は健康状態が書かれず期限切れになる。
//! - 既存コンテナの再利用（compose の冪等な `up`）は無い。同じ ID の記録があれば `ALREADY_EXISTS` で失敗する。
//! - イメージは pull しない（pull 済みが前提。`--image-root` 必須）。イメージの `User` が名前のときは `UNIMPLEMENTED`。
//! - Linux の rootless のみ。非 Linux は `UNIMPLEMENTED`、rootful は子の `create` が `UNIMPLEMENTED`。

use std::io::Write;

use fandhe_container_core::oci_runtime::exit_code_for;
use fandhe_container_core::traits::ErrorCode;

use super::CliExit;
use super::args::{GlobalArgs, UpArgs};
#[cfg(not(target_os = "linux"))]
use crate::error::CliError;

#[cfg(target_os = "linux")]
mod bundle;
#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
mod observe;
#[cfg(target_os = "linux")]
mod prepare;
#[cfg(target_os = "linux")]
mod provision;
#[cfg(target_os = "linux")]
mod run;

/// 非 Linux の拒否文言（plugin 経路は未結線。fail-closed）。
#[cfg(not(target_os = "linux"))]
const MSG_UNSUPPORTED_OS: &str = "up is not supported on this platform yet";

/// 終了コード（ERR-2 の表）から対応する [`ErrorCode`] を引く。表にない値は `Internal`。
///
/// 子の `create` / `start` の終了コードを、cli 自身の構造化エラーの `code` に戻すために使う
/// （終了コードの表の SSOT は core の `exit_code_for`）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn error_code_for_exit(exit: u8) -> ErrorCode {
    const CODES: [ErrorCode; 9] = [
        ErrorCode::InvalidArgument,
        ErrorCode::NotFound,
        ErrorCode::AlreadyExists,
        ErrorCode::FailedPrecondition,
        ErrorCode::PermissionDenied,
        ErrorCode::Timeout,
        ErrorCode::Unimplemented,
        ErrorCode::Unavailable,
        ErrorCode::ResourceExhausted,
    ];
    CODES
        .into_iter()
        .find(|c| exit_code_for(*c).get() == exit)
        .unwrap_or(ErrorCode::Internal)
}

/// `up` の入口。
#[cfg(target_os = "linux")]
pub(super) fn run_up(global: &GlobalArgs, args: &UpArgs, stdout: &mut dyn Write) -> CliExit {
    run::run_up(global, args, stdout)
}

/// `up` の入口（非 Linux は引数の解析後に `UNIMPLEMENTED`）。
#[cfg(not(target_os = "linux"))]
pub(super) fn run_up(_global: &GlobalArgs, _args: &UpArgs, _stdout: &mut dyn Write) -> CliExit {
    CliExit::Error(CliError::new(ErrorCode::Unimplemented, MSG_UNSUPPORTED_OS))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ERR-2: 終了コードの表の往復（2〜9 は対応する code、0・1・未知は Internal）。
    #[test]
    fn err2_4638_exit_code_round_trips_through_error_code() {
        for (exit, code) in [
            (2, ErrorCode::InvalidArgument),
            (3, ErrorCode::NotFound),
            (4, ErrorCode::AlreadyExists),
            (5, ErrorCode::FailedPrecondition),
            (6, ErrorCode::PermissionDenied),
            (7, ErrorCode::Timeout),
            (8, ErrorCode::Unimplemented),
            (9, ErrorCode::Unavailable),
        ] {
            assert_eq!(error_code_for_exit(exit), code, "{exit}");
            assert_eq!(exit_code_for(code).get(), exit);
        }
        assert_eq!(error_code_for_exit(1), ErrorCode::Internal);
        assert_eq!(error_code_for_exit(0), ErrorCode::Internal);
        assert_eq!(error_code_for_exit(200), ErrorCode::Internal);
    }
}
