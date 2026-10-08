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
//! - ハンドラは `sys` の固定ハンドラ（`forward_and_reraise`）で、async-signal-safe な操作だけを行う
//!   （登録表の走査と `kill`、`raise`）。割り当て・print・panic・ロックをしない。任意の関数をハンドラとして
//!   登録する公開 API は持たない（PR #1572 事後監査の P2）。
//! - 転送後、ハンドラ進入時に `SA_RESETHAND` で既定動作へ戻っている当該シグナルを自分へ再送する。ハンドラ中は
//!   当該シグナルがブロックされるため保留となり、ハンドラから戻った時点で配送されて親は
//!   シグナル終了（`ExitStatus::signal()` がそのシグナル）になる。errno は再送で終了するため退避しない。
//! - 起動時に `SIG_IGN` を継承したシグナルは上書きしない（nohup・バックグラウンドジョブの慣行を壊さない）。
//! - 例外として、継承した `SIGCHLD` の `SIG_IGN` は `SIG_DFL` へ戻す（PR #1572 事後監査の P2）。`SIG_IGN` の
//!   ままだとカーネルが plugin の子を自動回収し、登録表に残った pid が再利用されて転送が無関係なプロセス
//!   （グループ）へ届く窓ができる（`fandhe_container_plugin` の `signal_forward` の「制限」）。SIGHUP の
//!   `SIG_IGN` は利用者の意図（nohup）だが、`SIGCHLD` の `SIG_IGN` を exec 越しに引き継ぐかは POSIX で未規定で
//!   起動元が依存できる慣行ではなく、本バイナリは自分の子を wait する前提で動くため、戻しても起動元の意図を
//!   壊さない（本バイナリの中の挙動だけが変わり、起動元の設定は変えない）。
//! - シグナルハンドラの構造体レイアウトを確認済みでない unix（Linux の glibc〔x86_64・aarch64〕と macOS
//!   以外。例: musl の Linux、riscv64 の Linux、FreeBSD）では登録が失敗し、`main` は構造化エラー（`INTERNAL`）で
//!   起動を拒否する（fail-closed。転送なしで継続する方針は採らない）。対象は 3 OS 一級対応の範囲外。
//! - プロセス全体の設定のため、バイナリから 1 回だけ呼ぶこと。
//! - SIGKILL・`panic = abort` では転送されない。Linux は #1514（`PR_SET_PDEATHSIG`）で補う予定、
//!   macOS は plugin が残留し得る、Windows は対象外（モジュールごと `cfg(unix)`）。

use crate::error::CliError;
use crate::sys;
use fandhe_container_core::traits::ErrorCode;

/// 転送対象のシグナル番号（SIGHUP・SIGINT・SIGTERM。Linux・macOS 共通）。
const FORWARDED: [i32; 3] = [1, 2, 15];

/// SIGINT・SIGTERM・SIGHUP のハンドラを登録する。失敗は構造化エラー（`INTERNAL`）で返す。
///
/// 起動時に無視されていたシグナルは登録しない（`SIGCHLD` の `SIG_IGN` だけは `SIG_DFL` へ戻す）。
/// 1 回だけ、`main` から呼ぶこと。ハンドラ本体は
/// `sys` の固定ハンドラ（転送して再送する）で、呼び出し側は差し替えられない。
pub fn install_signal_forwarding() -> Result<(), CliError> {
    // 転送の前提（登録表の pid が回収前の子を指すこと）を保つため、先に SIGCHLD を既定へ戻す。
    sys::reset_child_signal_if_ignored().map_err(|_| {
        CliError::new(
            ErrorCode::Internal,
            "failed to reset the SIGCHLD disposition for plugin forwarding",
        )
    })?;
    for sig in FORWARDED {
        sys::install_forwarding_handler(sig).map_err(|_| {
            CliError::new(
                ErrorCode::Internal,
                "failed to install the signal handler for plugin forwarding",
            )
        })?;
    }
    Ok(())
}

/// 結合試験の plugin 役が受信シグナルを記録するための固定ハンドラを登録する（#1513・PLUG-7。テスト専用。
/// feature `signal-test-support` のときだけ存在する）。
///
/// ハンドラは `sys` の固定の記録ハンドラ（受信番号を原子変数へ store するだけ）で、任意の関数は渡せない。
/// `sig` は転送対象の 3 シグナル（1・2・15）に限り、それ以外は `InvalidInput`。起動時 `SIG_IGN` は
/// [`install_signal_forwarding`] と同じく尊重する。受信番号は [`recorded_signal_for_test`] で読む。
#[cfg(feature = "signal-test-support")]
#[doc(hidden)]
pub fn install_recording_handler_for_test(sig: i32) -> std::io::Result<()> {
    if !FORWARDED.contains(&sig) {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    sys::install_recording_handler(sig).map(|_| ())
}

/// 記録用の固定ハンドラが最後に受けたシグナル番号（未受信は 0。feature `signal-test-support`）。
#[cfg(feature = "signal-test-support")]
#[doc(hidden)]
pub fn recorded_signal_for_test() -> i32 {
    sys::recorded_signal()
}

/// 結合試験専用: 自プロセスの SIGCHLD を `SIG_IGN` にする（起動元から `SIG_IGN` を継承した状態の再現。
/// feature `signal-test-support` のときだけ存在する）。隔離した子プロセスの役からだけ呼ぶこと（同じ
/// プロセスの子は自動回収されるようになる）。[`install_signal_forwarding`] が `SIG_DFL` へ戻す。
#[cfg(feature = "signal-test-support")]
#[doc(hidden)]
pub fn ignore_child_signal_for_test() -> std::io::Result<()> {
    sys::ignore_child_signal_for_test()
}
