//! macOS の VM 保持役（共用 VM を CLI の終了後も生かす常駐プロセス）の骨格（MAC-4・CORE-1・PLUG-12・REPAIR-3・TASK-191・#2278）。
//!
//! 設計の正は `docs/design/macos-shared-vm.md` の「項目 1」と「期限の表」（#1906 で承認済み）。本モジュールが持つのは
//! 保持役プロセスの骨格だけである。
//!
//! | 部品 | 役割 |
//! | ---- | ---- |
//! | [`lock`] | `flock` による二重起動の拒否・期限つき取得。死亡（SIGKILL を含む）でカーネルが解放する（制約 C4） |
//! | [`protocol`] | 登録・解除・照会の要求と応答（固定長ヘッダの型つきレコード。`Frame` の payload に載せる） |
//! | [`registry`] | コンテナの参照数（上限 64）と、参照数 0 の猶予（30 秒）の状態機械 |
//! | `server` | `UdsListener`（peer UID 照合つき）の受付ループ。猶予後に終了する（[`run`]） |
//! | [`client`] | 起動役側。接続して照会し、保持役がいなければ起動して待つ（`ensure_running`） |
//!
//! # 呼び出し元と未配線の範囲（REPAIR-3）
//! - bin `fandhe-container-vm-keeper`（macOS のみ。[`run_main`]）が入口。CLI・plugin-macos アダプタからの起動の配線は
//!   #2281（と W8 #4705）で行う。
//! - 保持役が core の起動口（W4 #4684）で plugin-macos を `ResidentPlugin` として起動し VM を起動・停止する部分は
//!   **未配線**である。猶予後の VM の停止は [`VmLifecycle`] の背後に置き、本番の実装 [`UnwiredVm`] は停止する VM が無いことを
//!   返す。登録簿は参照数を数えるだけで VM を起動しない。
//! - 上限（64）超過の正式な応答・VM の世代 ID つき所属記録・VM 喪失時の `UNAVAILABLE` は #2279、オプション方式（容量 1）は #2283。
//!
//! # 契約
//! - 排他の正はロックの保持者だけ。ロックは保持役自身が取る（承認済みの文言「CLI が取り保持役が継承」からの差分。std の
//!   `Command` は fd を継承させず、継承には `pre_exec` の unsafe が要るため。起動役は「接続 → 無ければ起動 → 期限まで接続を
//!   ポーリング」で、ロックを取れなかった保持役は `FAILED_PRECONDITION` で即終了する）。
//! - ロックと socket は明示の基底ディレクトリ（`--base`）配下の `fandhe-container` に置く。環境変数・`getpwuid` による
//!   既定の解決は本モジュールでは行わない。
//! - 終了の順序は VM の停止 → socket の削除（listener の drop）→ ロックの解放。
//! - すべての待ちに期限がある。受付は単一スレッドで直列に処理するため、同一 UID の遅いクライアントは 1 要求の期限
//!   （[`REQUEST_IO_TIMEOUT`]）まで他を待たせうる（残余）。

pub mod client;
pub mod lock;
pub mod protocol;
pub mod registry;
mod server;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

pub use server::run;

/// 参照数 0 の猶予（#1906 で承認済みの 30 秒）。
pub const KEEPER_IDLE_GRACE: Duration = Duration::from_secs(30);

/// 猶予後の VM の協調停止の期限（#1906 で承認済みの 30 秒）。
pub const VM_STOP_DEADLINE: Duration = Duration::from_secs(30);

/// 1 要求あたりの読み書きの期限（`RpcTimeout` の上限 10 秒以内。REPAIR-5）。
pub const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// 保持役の設定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeeperConfig {
    idle_grace: Duration,
}

impl KeeperConfig {
    /// 猶予を検証して作る。1ms 未満（猶予なし）と [`KEEPER_IDLE_GRACE`] 超（承認値を超える常駐）は `InvalidArgument`。
    pub fn new(idle_grace: Duration) -> Result<Self, TraitError> {
        if idle_grace < Duration::from_millis(1) || idle_grace > KEEPER_IDLE_GRACE {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "vm keeper idle grace must be within 1ms and the approved maximum",
            ));
        }
        Ok(Self { idle_grace })
    }

    /// 猶予。
    pub fn idle_grace(&self) -> Duration {
        self.idle_grace
    }
}

impl Default for KeeperConfig {
    /// 承認済みの猶予 [`KEEPER_IDLE_GRACE`]。
    fn default() -> Self {
        Self {
            idle_grace: KEEPER_IDLE_GRACE,
        }
    }
}

/// [`VmLifecycle::stop`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmStopOutcome {
    /// VM を停止した。
    Stopped,
    /// 停止する VM が無かった（VM の起動が未配線の間はこちら）。
    NoVm,
    /// 停止を試みて失敗した（保持役は続けて終了する）。
    Failed,
}

/// 猶予後に保持役が VM を止める操作の背後（REPAIR-3）。
///
/// 本番の実装は W4（#4684）と #2281 で配線する。試験は呼ばれた回数を記録する偽の実装を使う。
pub trait VmLifecycle {
    /// VM を `deadline` 以内に協調停止する。
    fn stop(&mut self, deadline: Duration) -> Result<VmStopOutcome, TraitError>;
}

/// 未配線の本番実装。停止する VM が無いことを返す（VM の起動・停止の配線までの間。MAC-4・REPAIR-3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnwiredVm;

impl VmLifecycle for UnwiredVm {
    fn stop(&mut self, _deadline: Duration) -> Result<VmStopOutcome, TraitError> {
        Ok(VmStopOutcome::NoVm)
    }
}

/// 保持役が終了した理由と結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeeperExit {
    /// 猶予後の VM の停止の結果。
    pub vm_stop: VmStopOutcome,
}

/// plugin 境界のエラーを監視プロセス側の構造化エラーへ写す（文言は plugin の固定文言。パス・UID を含まない）。
pub(crate) fn from_plugin(e: PluginError) -> TraitError {
    let code = match e.code() {
        PluginErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        PluginErrorCode::NotFound => ErrorCode::NotFound,
        PluginErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        PluginErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        PluginErrorCode::Unimplemented => ErrorCode::Unimplemented,
        PluginErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        PluginErrorCode::Timeout => ErrorCode::Timeout,
        PluginErrorCode::Unavailable => ErrorCode::Unavailable,
        PluginErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    };
    TraitError::new(code, format!("vm keeper transport: {}", e.message()))
}

/// bin の入口の本体。引数は `--base <絶対パス>` だけ（環境変数・既定パスは使わない）。成功は終了コード 0、
/// 失敗は構造化エラーを stderr へ出して非 0（ロックを取れなかった場合は `FAILED_PRECONDITION`）。
pub fn run_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    let result = parse_base(args).and_then(|base| {
        let mut vm = UnwiredVm;
        run(&KeeperConfig::default(), &base, &mut vm)
    });
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            let err = OciRuntimeError::from_trait_error(LifecycleOp::Start, e);
            let mut line = Vec::new();
            if err.write_json_line(&mut line).is_ok() {
                // stderr の読み手が止まっていても期限で終わる（REPAIR-5）。
                let _ = crate::stderr_sink::stderr().emit_and_wait(line, Duration::from_secs(1));
            }
            ExitCode::from(err.exit_code().get())
        }
    }
}

fn parse_base(mut args: impl Iterator<Item = OsString>) -> Result<PathBuf, TraitError> {
    let bad = || {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "usage: fandhe-container-vm-keeper --base <absolute path>",
        )
    };
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--base" => Ok(PathBuf::from(path)),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac4_config_bounds_idle_grace() {
        assert!(KeeperConfig::new(Duration::ZERO).is_err());
        assert!(KeeperConfig::new(Duration::from_millis(1)).is_ok());
        assert!(KeeperConfig::new(KEEPER_IDLE_GRACE).is_ok());
        assert!(KeeperConfig::new(KEEPER_IDLE_GRACE + Duration::from_millis(1)).is_err());
        assert_eq!(
            KeeperConfig::default().idle_grace(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn mac4_parse_base_accepts_only_exact_usage() {
        let ok = parse_base(["--base", "/x"].iter().map(OsString::from));
        assert_eq!(ok.expect("ok"), PathBuf::from("/x"));
        for args in [
            vec![],
            vec!["--base"],
            vec!["/x"],
            vec!["--base", "/x", "extra"],
            vec!["--other", "/x"],
        ] {
            let e = parse_base(args.iter().map(OsString::from)).expect_err("usage");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn mac4_unwired_vm_reports_no_vm() {
        let mut vm = UnwiredVm;
        assert_eq!(
            vm.stop(VM_STOP_DEADLINE).expect("stop"),
            VmStopOutcome::NoVm
        );
    }
}
