//! 親が受けた SIGINT・SIGTERM・SIGHUP を起動中の plugin へ転送してから、親自身をシグナルで終了させる
//! （#1513・PLUG-7・REPAIR-5・#1403 方式 A）。
//!
//! # 役割と呼び出し文脈
//! バイナリ `fandhe-container` の `main` が起動時に 1 回だけ [`install_signal_forwarding`] を呼ぶ。
//! シグナルハンドラの登録はバイナリの責務で（#1403 判断 2）、転送の実体（登録表と `kill`）は
//! `fandhe-container-plugin` の `signal_forward` が持つ。コマンドの実行中に起動した plugin
//! （都度起動・常駐）の pid は、同 crate の登録表に載っている。
//!
//! # 契約
//! - ハンドラは async-signal-safe な操作だけを行う（登録表の走査と `kill`、`raise`）。
//!   割り当て・print・panic・ロックをしない。
//! - 転送後、ハンドラ進入時に `SA_RESETHAND` で既定動作へ戻っている当該シグナルを自分へ再送する。ハンドラ中は
//!   当該シグナルがブロックされるため保留となり、ハンドラから戻った時点で配送されて親は
//!   シグナル終了（`ExitStatus::signal()` がそのシグナル）になる。errno は再送で終了するため退避しない。
//! - 起動時に `SIG_IGN` を継承したシグナルは上書きしない（nohup・バックグラウンドジョブの慣行を壊さない）。
//! - シグナルハンドラの構造体レイアウトを確認済みでない unix（Linux の glibc〔x86_64・aarch64〕と macOS
//!   以外。例: musl の Linux、riscv64 の Linux、FreeBSD）では登録が失敗し、`main` は構造化エラー（`INTERNAL`）で
//!   起動を拒否する（fail-closed。転送なしで継続する方針は採らない）。対象は 3 OS 一級対応の範囲外。
//! - プロセス全体の設定のため、バイナリから 1 回だけ呼ぶこと。
//! - SIGKILL・`panic = abort` では転送されない。Linux は #1514（`PR_SET_PDEATHSIG`）で補う予定、
//!   macOS は plugin が残留し得る、Windows は対象外（モジュールごと `cfg(unix)`）。

use crate::error::CliError;
use crate::sys;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_plugin::{ForwardSignal, forward_to_running_plugins};

/// 転送対象のシグナル番号（SIGHUP・SIGINT・SIGTERM。Linux・macOS 共通）。
const FORWARDED: [i32; 3] = [1, 2, 15];

/// 受けたシグナルを plugin へ転送し、既定動作へ戻った同じシグナルを自分へ再送する。
extern "C" fn forward_and_reraise(sig: i32) {
    if let Some(forward) = ForwardSignal::from_raw(sig) {
        let _ = forward_to_running_plugins(forward);
    }
    sys::raise_signal(sig);
}

/// SIGINT・SIGTERM・SIGHUP のハンドラを登録する。失敗は構造化エラー（`INTERNAL`）で返す。
///
/// 起動時に無視されていたシグナルは登録しない。1 回だけ、`main` から呼ぶこと。
pub fn install_signal_forwarding() -> Result<(), CliError> {
    for sig in FORWARDED {
        sys::install_handler(sig, forward_and_reraise).map_err(|_| {
            CliError::new(
                ErrorCode::Internal,
                "failed to install the signal handler for plugin forwarding",
            )
        })?;
    }
    Ok(())
}

/// 結合試験の plugin 役が受信シグナルを記録するためのハンドラ登録（#1513・PLUG-7。テスト専用）。
///
/// `handler` は async-signal-safe であること（原子変数への書き込みのみ等）。登録は
/// [`install_signal_forwarding`] と同じ `sys::install_handler` を使う（起動時 `SIG_IGN` は尊重）。
#[doc(hidden)]
pub fn install_recording_handler_for_test(
    sig: i32,
    handler: extern "C" fn(i32),
) -> std::io::Result<()> {
    sys::install_handler(sig, handler).map(|_| ())
}
