//! バッチ write-back（[`fandhe_container_io::writeback::serve_connection`]）の
//! 整合性テストスイート入口（TASK-14・親 #79・IO-4・REPAIR-6）。
//!
//! IO-4（Must・確定）は、並行 write・rename・truncate を含む整合性テスト
//! スイートでデータ破損 0 件・close-to-open 整合性違反 0 件を確認することを
//! 求める。REPAIR-6（Must・確定）は、その相当のテストが実際の I/O 実装
//! （[`fandhe_container_io::writeback`]）へ適用され、破損を検出できることを
//! 求める。本ファイルは兄弟 sub-issue（#81 の rename/truncate・#82 の
//! グレースフルシャットダウン close-to-open）と成果物パスを共有する入口の
//! `mod` 宣言のみを持つ（並行する PR 同士の衝突を最小にするため。REPAIR-1）。
//!
//! # 「並行 write」の定義（本ファイル・TASK-14.1・#80 の範囲）
//!
//! ワイヤー形式（[`fandhe_container_io::payload`]）はパスもオフセットも
//! 持たず、サーバーは呼び出し側が開いた 1 つの [`std::fs::File`] へ body を
//! 到着順に追記するだけである（`writeback.rs` の D1）。したがって本スイートが
//! 検証する「並行 write」は、**複数の接続（クライアント）が同時に write
//! ストリームを流し、接続ごとに `serve_connection` がスレッド並行で書き込む
//! こと**と定義する。同じオフセット領域への上書き競合はワイヤーで表現
//! できないため対象外（out-of-scope-tracking で追跡）。
//!
//! # 実行する OS の方針
//!
//! [`harness::DuplexEnd`]（`std::sync::mpsc` によるメモリ内の二方向
//! トランスポート）を使う 8 件の主ケース（[`concurrent_write`]）は 3 OS
//! すべてで動く（ci.md「OS 依存のファイルシステム挙動のテストは 3 OS すべてで
//! 実行する」）。[`fandhe_container_io::UdsServer`] は Linux / macOS 限定の
//! ため、実ソケット越しの並行性を追加で補強するケースは範囲外とし、
//! out-of-scope-tracking で追跡する（`fandhe_container_io::server` モジュール
//! doc の「範囲外」節が同じ理由で UDS 受付ループ自体を後続 sub-issue としている
//! ことと整合させる）。

#[path = "consistency/harness.rs"]
mod harness;

#[path = "consistency/concurrent_write.rs"]
mod concurrent_write;
