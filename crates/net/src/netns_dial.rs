//! POD ネットワークの PortForward 用 `netns-dial` helper の公開面（CRI-6・NET-3・SEC-1・REPAIR-2・#4477。
//! 設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」）。
//!
//! plugin-cri は dial ごとに単一スレッドの helper を立て、helper は保持役の user / net namespace へ `setns` して
//! `127.0.0.1:<port>` へ connect し、接続済みの fd を `SCM_RIGHTS` で返す。本モジュールの現状は両者の間を行き来する
//! 固定長 frame（[`frame`]。OS 非依存の純関数）と、受け取った fd の検証 `verify`
//! （`verify_dialed_socket`。#4478。SEC-1 の多層防御。`NsId` が Linux 限定のため Linux のみ）。helper 本体（#4479）と親側の channel（#4480）は
//! 未実装（REPAIR-3。未実装のものを実装済みとして扱わない）。

pub mod frame;
#[cfg(target_os = "linux")]
pub mod verify;

pub use frame::{
    ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame,
    FRAME_LEN, MAX_CONNECT_TIMEOUT_MS, MIN_CONNECT_TIMEOUT_MS,
};

#[cfg(target_os = "linux")]
pub use verify::{
    DialExpectation, DialedSocketError, DialedSocketRejection, NsId, verify_dialed_socket,
};
