//! pod 保持役モード（supervisor の bin の `pod-holder`。CRI-2・CORE-1・CORE-3・SEC-5・REPAIR-5・#2874。
//! 設計は `docs/design/pod-namespace-holder.md` の H2）。
//!
//! pod の ipc・net 共有の供給元となるプロセスで、core の `establish_pod_namespaces`（H1・#2870）で user（写像つき）・ipc・
//! net を作って持ち続ける。bin の main が [`is_pod_holder_invocation`] で `run_main` より前に振り分け、
//! [`run_pod_holder_main`] が本体を動かす。結果チャネル・fd 検証を通さない（結果は固定長の READY / ERROR フレームを
//! stdout へ書く）。特権ランチャーは `StartArgs::parse` を通った argv だけを転送するので、この分岐の入口にはならない。
//!
//! # 構成
//! - `frame`（OS 非依存）: 64 バイト固定の READY / ERROR フレーム
//! - `holder`（Linux）: 保持役の手順（段 1・段 2）。詳細はそちらの doc
//! - `client`（Linux）: 受信側の期限つき `read_ready`
//!
//! # 未実装・残余（REPAIR-3）
//! 保持役の起動・回収・ハンドル化（plugin-cri）は H6（#2877）、CI の `--ignored` は `platform-ci` の ubuntu で実行済み（#2875）、
//! core の net join は H7（#2872）。本モジュールは READY を返して待つ保持役プロセスまで。

use std::ffi::OsStr;
use std::process::ExitCode;
use std::time::Duration;

mod frame;
pub use frame::{FRAME_LEN, NsId, PodHolderFrame, PodHolderMessage, PodHolderReady};

#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
pub use client::read_ready;
#[cfg(target_os = "linux")]
mod holder;

/// bin の第 1 引数（固定。`PATH`・環境変数・引数による上書きは受けない）。
pub const POD_HOLDER_SUBCOMMAND: &str = "pod-holder";

/// 受信側が READY を待つ契約上の上限。保持役の内部の最長の待ち（`getent` の期限と範囲写像の helper の期限の和）
/// 以上にする。下の単体試験が内部の期限との関係を照合する。
pub const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// bin の main が保持役へ振り分ける呼び出しか（第 1 引数が `pod-holder`）。
pub fn is_pod_holder_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(POD_HOLDER_SUBCOMMAND))
}

/// 保持役の本体。`args` は `pod-holder` の後ろの引数。
#[cfg(target_os = "linux")]
pub fn run_pod_holder_main(args: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    holder::run(args)
}

/// 保持役の本体（非 Linux）。Linux の namespace が前提のため `UNIMPLEMENTED` を stderr に出して 1 で終わる。
#[cfg(not(target_os = "linux"))]
pub fn run_pod_holder_main(_args: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr(),
        "error code=UNIMPLEMENTED message=the pod holder requires Linux"
    );
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-2・#2874: 振り分けは第 1 引数が完全一致のときだけ。
    #[test]
    fn cri2_dispatch_matches_only_the_exact_subcommand() {
        assert!(is_pod_holder_invocation(Some(OsStr::new("pod-holder"))));
        assert!(!is_pod_holder_invocation(Some(OsStr::new("pod-holder "))));
        assert!(!is_pod_holder_invocation(Some(OsStr::new("netns-holder"))));
        assert!(!is_pod_holder_invocation(None));
    }

    /// REPAIR-5: 受信側の上限は、保持役の内部の最長の待ち（`getent` 3 回と helper 3 回〔uid・gid・停止〕を各
    /// `DEFAULT_HELPER_TIMEOUT` と見積もった和）に余裕 10 秒を足した値を下回らない。内部の期限を変えたら落ちる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_ready_timeout_covers_internal_waits() {
        let internal = fandhe_container_core::rootless::DEFAULT_HELPER_TIMEOUT * 6;
        assert!(READY_TIMEOUT >= internal + Duration::from_secs(10));
    }
}
