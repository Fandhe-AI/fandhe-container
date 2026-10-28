//! rootless のユーザー定義ネットワーク（pasta 構成。NET-9）の **netns holder**（NET-9・CORE-6・SEC-5・REPAIR-5・
//! #3197。`docs/design/rootless-network.md` 12.2・12.8・12.9・12.10）。
//!
//! pasta は PID の形（`pasta ... <PID>`）で対象の `/proc/<PID>/ns/{net,user}` を開く。コンテナの子は D8 により
//! non-dumpable で、fd を渡す形も pasta の `isolate_fds` が閉じるため使えない。そこで supervisor が
//! `/proc/self/exe netns-holder` として exec し直した専用プロセス（holder）がコンテナの user / net namespace に
//! `setns(2)` で入り、capability をすべて落として dumpable のまま待機する。pasta はその holder の PID を対象にする。
//!
//! # 構成
//! - `holder`（Linux のみ）: holder プロセスの本体 [`run_netns_holder_main`]。supervisor の bin の main が第 1 引数
//!   [`NETNS_HOLDER_SUBCOMMAND`] で振り分けて呼ぶ（DNS ヘルパーの `run_dns_helper_main` と同じ形）
//! - `channel`（Linux のみ）: supervisor 側の端 `NetnsHolderChannel`（socketpair・fd 2 本の送信・READY の待ちと
//!   検証・STOP の送信）。launch が holder を起動するときに使う
//! - `frame`（OS 非依存）: 両方向の固定長フレームの型付きコーデック（REPAIR-2）
//!
//! # holder の手順（12.2。順序は変えない）
//! 1. `PR_SET_PDEATHSIG=SIGKILL` を設定し、stdin が `SOCK_SEQPACKET` で、その作成者（`SO_PEERCRED` の pid）が親
//!    であることを確かめる（親が既に死んでいれば終了する）
//! 2. stdin から [`HolderMessage::Namespaces`] と `SCM_RIGHTS` の fd ちょうど 2 本（user、net の順）を **期限つき**
//!    （[`FDS_RECV_TIMEOUT`]）で受ける。スレッドは使わない（`setns(CLONE_NEWUSER)` は多スレッドで `EINVAL`）
//! 3. 各 fd の (dev, ino) を記録し、`setns(user)` → `setns(net)` の順に参加し、`/proc/self/ns/{net,user}` の
//!    (dev, ino) が受けた fd と一致することを確かめ、fd を閉じる
//! 4. capability をすべて落とし（`capset` で空）`PR_SET_NO_NEW_PRIVS` を設定し、PDEATHSIG と dumpable
//!    （pasta が `/proc/<holder>/ns/*` を開ける前提）を確かめる
//! 5. 固定長の READY フレーム（参加した ns の識別）を返す。以後は socket の EOF または STOP を待つだけ
//!
//! 参加前後の失敗は ERR-1 の `code` を持つ [`HolderMessage::Error`] を返してから非 0 で終了する。
//!
//! # supervisor への契約
//! - holder は supervisor と同じ寿命のスレッド（入口の main スレッド）から spawn すること。PDEATHSIG は spawn した
//!   スレッドの終了でも届く（12.10）
//! - stdin に `NetnsHolderChannel::pair` の子の端を渡し、`env_clear`、stdout は null、stderr は supervisor のログにする
//! - READY は [`READY_TIMEOUT`] 以内に待つ。停止は `NetnsHolderChannel::send_stop` または端を閉じて
//!   [`STOP_GRACE`] 待ち、超えたら SIGKILL し [`REAP_TIMEOUT`] 以内に回収する（12.9）
//! - 起動・回収・構造化ログ（`netns_holder_ready` / `netns_holder_exit`）は supervisor の責務で
//!   （実装は `fandhe_container_supervisor::netns_holder`。#3198）、pidfd での監視は #1940。
//!   本モジュールは所要時間（`HolderReady::elapsed`）などの材料を返すだけ
//!
//! # 範囲外
//! fd 2 本の送出（core の同期点）と supervisor の基準 netns との照合（D8 の `Other`）は #1939、pasta の起動は
//! #1938・#1940、実機での pasta を含む確認は #1941。nsfs であることの確認（`fstatfs`）は行わず、型の最終照合は
//! `setns(2)` の `EINVAL`（12.2）と参加後の (dev, ino) 照合が担う。

pub mod frame;

#[cfg(target_os = "linux")]
mod channel;
#[cfg(target_os = "linux")]
mod holder;

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

pub use frame::{FRAME_LEN, HolderFrame, HolderMessage, NsIdentity};

#[cfg(target_os = "linux")]
pub use channel::{HolderReady, NetnsHolderChannel, NetnsHolderFds, SentNamespaces};

/// supervisor の bin の main が holder へ振り分ける第 1 引数（argv は固定。12.2）。
pub const NETNS_HOLDER_SUBCOMMAND: &str = "netns-holder";

/// holder の READY を待つ期限（12.9。REPAIR-5）。
pub const READY_TIMEOUT: Duration = Duration::from_secs(2);

/// holder が supervisor からの fd を待つ期限（親が送る前に壊れても残らないための上限。READY の期限と揃える。REPAIR-5）。
pub const FDS_RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// STOP / EOF を送ってから SIGKILL するまでの猶予（12.9。REPAIR-5）。
pub const STOP_GRACE: Duration = Duration::from_secs(1);

/// SIGKILL の後に回収を待つ期限（12.9。REPAIR-5）。
pub const REAP_TIMEOUT: Duration = Duration::from_secs(1);

/// holder プロセスの入口。`netns-holder` の後ろの引数（空でなければならない）を受ける。
///
/// 成功（STOP または EOF で終了）は 0、手順の失敗は 1、引数の誤りは 2。失敗は stderr に英語 1 行
/// `error code=<CODE> message=<固定の文言>` だけを出し、パス・入力値は含めない（12.9・ERR-1）。
/// Linux 以外では `UNIMPLEMENTED` を出して 1 で終了する。
pub fn run_netns_holder_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        holder::run(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("error code=UNIMPLEMENTED message=netns holder is only available on Linux");
        ExitCode::from(1)
    }
}
