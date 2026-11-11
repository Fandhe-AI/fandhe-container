//! POD ネットワークの PortForward 用 `netns-dial` helper の公開面（CRI-6・NET-3・SEC-1・REPAIR-2・#4477。
//! 設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」）。
//!
//! plugin-cri は dial ごとに単一スレッドの helper を立て、helper は保持役の user / net namespace へ `setns` して
//! `127.0.0.1:<port>` へ connect し、接続済みの fd を `SCM_RIGHTS` で返す。本モジュールの現状は両者の間を行き来する
//! 固定長 frame（[`frame`]。OS 非依存の純関数）だけで、helper 本体・親側の channel・sys は後続の issue
//! （#4478〜#4480）が足す（REPAIR-3。未実装のものを実装済みとして扱わない）。

pub mod frame;

pub use frame::{
    ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame,
    FRAME_LEN, MAX_CONNECT_TIMEOUT_MS, MIN_CONNECT_TIMEOUT_MS,
};
