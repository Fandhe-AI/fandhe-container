//! rootless のユーザー定義ネットワークで使う pasta（passt）の外部ヘルパーまわり（NET-9・PLUG-11）。
//!
//! fandhe-container は pasta を同梱もリンクもせず、利用者が導入したものを別プロセスとして exec する
//! （`docs/design/rootless-network.md` 12 章）。そのため「どのバイナリを実行するか」を確かめる入口が
//! 安全の要になる。本モジュールは検証済みのバイナリを表す型（[`binary::PastaBinary`]）と、その検証・
//! opt-in の `PATH` 探索・`--version` の解釈（[`version`]）、ポート公開指定の検証と pasta の引数配列への
//! 変換（`port_forward`。OS 非依存の純粋関数。#1937）を持つ。起動・準備完了待ち（#1938）は兄弟の
//! 子モジュールとして後続が足す。
//!
//! 呼び出し元は cli（作成時の検証と FCOPT1 への記録。12.14）と supervisor（起動時の再検証・#1940）。

pub mod binary;
pub mod port_forward;
pub mod version;

pub use port_forward::{
    DEFAULT_LISTEN_ADDR, MAX_PORT_FORWARD_SPEC_LEN, PastaPortForward, PastaPortForwards,
};
