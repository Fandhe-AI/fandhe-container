//! POD ネットワークの PortForward 用 `netns-dial` helper の公開面（CRI-6・NET-3・SEC-1・REPAIR-2・#4477。
//! 設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」）。
//!
//! plugin-cri は dial ごとに単一スレッドの helper を立て、helper は保持役の user / net namespace へ `setns` して
//! `127.0.0.1:<port>` へ connect し、接続済みの fd を `SCM_RIGHTS` で返す。本モジュールの現状は両者の間を行き来する
//! 固定長 frame（[`frame`]。OS 非依存の純関数）、受け取った fd の検証 `verify`
//! （`verify_dialed_socket`。#4478。SEC-1 の多層防御。`NsId` が Linux 限定のため Linux のみ）、helper 本体
//! `run_netns_dial_main`（#4479。Linux のみ。それ以外は終了コード 1）。親側の channel `channel`
//! （`NetnsDialChannel`。#4480。Linux のみ）が socketpair・要求の送信・応答の期限つき受信・fd の検証を担う。
//!
//! # helper の手順（順序は変えない。失敗の固定語彙への対応表は `helper` モジュールの `//!`）
//! 1. argv が空であることを確かめる（非空は応答なしで終了コード 2）
//! 2. `PR_SET_DUMPABLE=0` にして 0 を確かめる（失敗は応答なしで終了コード 1。#4558）、`PR_SET_PDEATHSIG=SIGKILL`、stdin が `SOCK_SEQPACKET` で `SO_PEERCRED` の pid が親であることを確かめる
//!    （違えば応答せず終了コード 1）、`close_range(3..)`
//! 3. 要求 frame と `SCM_RIGHTS` の fd ちょうど 2 本（user、net の順）を期限（`REQUEST_RECV_TIMEOUT`）つきで受ける
//! 4. 各 fd の (dev, ino) を記録し、`setns(user)` → `setns(net)` の順に参加して `/proc/self/ns` の識別を照合する
//!    （カーネル v6.12 の `userns_install` は多スレッド・fs 共有で `EINVAL`、`CAP_SYS_ADMIN` 不足で `EPERM`。
//!    `netns_install` は対象 netns の所有 userns と現 cred の userns の両方に `CAP_SYS_ADMIN` を要求する）。
//!    参加後に dumpable が 0 のままであることを確かめる（0 でなければ `JoinFailed`。#4558）
//! 5. capability を空にし、NNP・PDEATHSIG の再武装・non-dumpable の再設定と確認を行う
//! 6. `127.0.0.1:<port>` へ要求の期限つきで connect し、接続済み fd 1 本を添えた `Connected` か `Error{code}` を返す
//!
//! 終了コードは `Connected` を送れたら 0、それ以外の失敗は 1、argv の誤りは 2。

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

/// supervisor の main が第 1 引数で helper へ振り分けるための名前（振り分けは #4482）。
pub const NETNS_DIAL_SUBCOMMAND: &str = "netns-dial";

/// 要求 frame と fd の受信期限（`netns_holder::FDS_RECV_TIMEOUT` と同値。REPAIR-5）。
pub const REQUEST_RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// `netns-dial` helper プロセスの本体。引数は空でなければならない。Linux 以外では何もせず終了コード 1。
pub fn run_netns_dial_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        helper::run(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        ExitCode::from(1)
    }
}

#[cfg(target_os = "linux")]
pub mod channel;
pub mod frame;
#[cfg(target_os = "linux")]
mod helper;
#[cfg(all(target_os = "linux", feature = "netns-dial-test-support"))]
#[doc(hidden)]
pub mod test_support;
#[cfg(target_os = "linux")]
pub mod verify;

pub use frame::{
    ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame,
    FRAME_LEN, MAX_CONNECT_TIMEOUT_MS, MIN_CONNECT_TIMEOUT_MS,
};

#[cfg(target_os = "linux")]
pub use channel::{
    MAX_RESPONSE_TIMEOUT, NetnsDialChannel, NetnsDialError, NetnsDialFailure, NetnsDialFds,
    SentDial,
};
#[cfg(target_os = "linux")]
pub use verify::{
    DialExpectation, DialedSocketError, DialedSocketRejection, NsId, verify_dialed_socket,
};
