//! `fandhe-container-plugin-cri` バイナリの入口（TASK-114.1・#457、TASK-114.3.1・#849。PLUG-1・CRI-2）。
//!
//! 呼び出し元: 将来は core 側 plugin proxy（#1869 の設計。承認待ち）が検証済みの起動対象として spawn する。
//! 役割は起動引数の解析（`startup::parse_args`）を終了コードと stderr の 1 行へ写すことと、`--socket <PATH>` で
//! 受けた UDS 上で `CriRuntimeService` をサーブすること（`server::serve`。unix のみ）。
//! 実装の組み立ては `adapter::CriPluginBackends::production`（失敗したら fail-closed で起動しない）。
//! 既定の socket パスは未定義のため、引数なしの起動は `UNIMPLEMENTED` で失敗させる（REPAIR-3）。
//! SIGTERM の正常停止は未実装（SIGKILL で止まる。`server` の未実装の注記を参照）。
//!
//! 終了コード: 0 = `--help`、2 = `InvalidArgument`（plugin-macos / plugin-mcp と同じ値）、1 = それ以外の失敗
//! （未実装・起動失敗・serve の失敗）。
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（固定文言のみ。引数の値は含めない。REPAIR-4）。
//! stdout に書くのは `--help` の usage だけ。起動完了の通知行は出さない（呼び出し側は socket の出現と接続の成否で判定する）。

use std::process::ExitCode;

use fandhe_container_plugin::{PluginError, PluginErrorCode};
use fandhe_container_plugin_cri::startup::{self, Invocation};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// 未実装・その他の起動失敗の終了コード。
const EXIT_FAILURE: u8 = 1;

fn fail(code: PluginErrorCode, message: &str) -> ExitCode {
    eprintln!("error: {}: {}", code.as_str(), message);
    if code == PluginErrorCode::InvalidArgument {
        ExitCode::from(EXIT_INVALID_ARGUMENT)
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn fail_err(e: &PluginError) -> ExitCode {
    fail(e.code(), e.message())
}

/// `Serve` の本体。UDS を持たない OS では未実装を返す（WIN-1）。
#[cfg(unix)]
fn serve(socket: &std::path::Path) -> ExitCode {
    use fandhe_container_plugin::grpc::GrpcServerConfig;
    use fandhe_container_plugin_cri::adapter::{CriPluginBackends, UnimplementedBundleProvider};
    use fandhe_container_plugin_cri::server;

    let backends = match CriPluginBackends::production() {
        Ok(b) => b,
        Err(e) => {
            // 状態ルートが解決できない等は fail-closed。メッセージは固定文言のコードだけ写す。
            eprintln!(
                "error: {}: failed to open the state store",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let svc = backends.runtime_service(std::sync::Arc::new(UnimplementedBundleProvider));
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return fail(PluginErrorCode::Internal, "failed to start the runtime"),
    };
    let result = rt.block_on(server::serve(
        socket,
        svc,
        &GrpcServerConfig::new(),
        std::future::pending(),
    ));
    match result {
        // pending() は完了しないため通常ここへは来ない。成功を装わず失敗扱いにする。
        Ok(()) => fail(PluginErrorCode::Internal, "server stopped unexpectedly"),
        Err(e) => fail_err(&e),
    }
}

#[cfg(not(unix))]
fn serve(_socket: &std::path::Path) -> ExitCode {
    fail(
        PluginErrorCode::Unimplemented,
        "cri plugin server requires unix domain sockets on this platform",
    )
}

fn main() -> ExitCode {
    match startup::parse_args(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{}", startup::usage());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Serve { socket }) => serve(&socket),
        Ok(_) => {
            // `Run` と、将来足される値は成功扱いにしない。
            fail(
                PluginErrorCode::Unimplemented,
                startup::MSG_SOCKET_DEFAULT_UNDEFINED,
            )
        }
        Err(e) => fail_err(&e),
    }
}
