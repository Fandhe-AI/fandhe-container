//! rootless のユーザー定義ネットワークで使う pasta（passt）の外部ヘルパーまわり（NET-9・PLUG-11）。
//!
//! fandhe-container は pasta を同梱もリンクもせず、利用者が導入したものを別プロセスとして exec する
//! （`docs/design/rootless-network.md` 12 章）。そのため「どのバイナリを実行するか」を確かめる入口が
//! 安全の要になる。本モジュールは検証済みのバイナリを表す型（[`binary::PastaBinary`]）と、その検証・
//! opt-in の `PATH` 探索・`--version` の解釈（[`version`]）を持つ。起動・準備完了待ち（#1938）、ポート公開の
//! 引数（#1937）は兄弟の子モジュールとして後続が足す。
//!
//! 呼び出し元は cli（作成時の検証と FCOPT1 への記録。12.14）と supervisor（起動時の再検証・#1940）。

pub mod binary;
pub mod version;
