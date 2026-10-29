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
//! # 「グレースフルシャットダウン / close-to-open」の定義（TASK-14.3・#82 の範囲）
//!
//! ワイヤー形式・`serve_connection` の終了原因は上記と共通（D1・D4・D5）。
//! [`graceful_shutdown`] は次の 2 経路をグレースフルシャットダウンと定義する:
//! (a) write の後に `Flush` を送り、残りが書き込まれ ACK された後
//! `Unimplemented` で終わる経路（FlushAck・syncfs の返却は TASK-15.2.2・#824
//! の担当。着手時点で未マージ）、(b) 送った write の ACK をすべて受け取って
//! から切断する経路（`Unavailable`・`discarded_pending_frames == 0`）。
//! close は `serve_connection` の join（[`harness::join_within`]）で sink が
//! 確実に閉じた状態、open はその後に新しいハンドルで読むこと
//! （[`graceful_shutdown::read_fresh`]）と定義する。PoC
//! （`03-poc/io-layer-redesign`）は EOF で残りを flush する前提だったが、
//! 現行の `serve_connection` は EOF 時点で未 ACK の保留分を破棄する（D5）ため、
//! 本スイートはこの現行実装を基準に定義し直している（詳細は
//! [`graceful_shutdown`] モジュール doc 参照。spec 側の変更は不要と判断）。
//! クラッシュ耐性（fsync・電源断時の永続化。IO-2・IO-3・TASK-15）は対象外。
//!
//! # 「並行 write」の定義（本ファイル・TASK-14.1・#80 の範囲）
//!
//! ワイヤー形式（[`fandhe_container_io::payload`]）はパスもオフセットも
//! 持たず、サーバーは呼び出し側が開いた 1 つの [`std::fs::File`] へ body を
//! 到着順に追記するだけである（`writeback.rs` の D1）。したがって本スイートが
//! 検証する「並行 write」は、**複数の接続（クライアント）が同時に write
//! ストリームを流し、接続ごとに `serve_connection` がスレッド並行で書き込む
//! こと**と定義する。同じオフセット領域への上書き競合はワイヤーで表現
//! できないため対象外とする（ワイヤー形式の拡張〔IO-1 の I/O 契約の変更〕が
//! 前提。設計の入口は #1886）。
//!
//! # 「rename / truncate」の定義（TASK-14.2・#81 の範囲）
//!
//! ワイヤー形式はパスもオフセットも持たない（上記 D1 参照）。そこで本
//! sub-issue（[`rename_truncate`]）のケースは、**[`fandhe_container_io::AppendFileSink`]
//! が書き込む先のファイルに対して、呼び出し側（ホスト側）が
//! `std::fs::rename` / `File::set_len` を実行する操作**と定義する。
//!
//! 操作は決定的な静止点でのみ行う（静止点を作らない交錯は後述の
//! [`interleave`]〔TASK-14 追補・#1830〕が担う）。セッション境界の操作
//! （[`rename_truncate::run_session`](rename_truncate)）は `serve_connection`
//! の join 後（内部の [`fandhe_container_io::AppendFileSink`] が確実に閉じた
//! 後）、ライブセッション中の操作（[`rename_truncate::LiveSession`]）は
//! 「`batch_size` の倍数件を送り、対応する ACK をすべて受け取った直後」で
//! 行う。ACK はバッチ書き込みの後にしか返らないため、この時点でファイル
//! 内容は確定している（`writeback.rs` D3）。`Flush`（受信すると
//! `serve_connection` が `Unimplemented` で終了する。D4）とクライアントの
//! drop はセッション終了にのみ使い、`sleep` によるタイミング同期は行わない。
//!
//! # 「書き込み・truncate と同時に読む読み手」の定義（#1828・[`concurrent_read`] の範囲）
//!
//! 上記の読み手は書き込み停止後に開き直す（close-to-open）のみだったため、
//! 書き込み・truncate と同時に読む試験を足す。R を送信したレコード列の連結、
//! スナップショットを「読み手がファイルを新しく開いて全体を読んだ結果」とする。
//!
//! - (a) 接頭辞: スナップショットは R の接頭辞である（順序入れ替え・他接続の
//!   body の混入・穴が無い）。共有ファイルでは完全なレコードに分解でき、
//!   クライアントごとの seq が 0 から連続する
//! - (b) ACK 床: 読み手が ACK 済み件数 A を先に読んでから開いた場合、先頭の
//!   A 件分は R と完全一致する（ACK はバッチ書き込み完了後に返る。永続化は
//!   主張しない。IO-2 の領分）
//! - (c) 書きかけ許容: 末尾にヘッダ未満・本体未満の書きかけが見えてよい。
//!   ACK 床より後ろは「期待値または 0x00」まで許容する（3 OS の一次資料で
//!   確認できる範囲に留める。根拠は [`concurrent_read`] モジュール doc）
//! - (d) 単調性: 書き込みのみの局面では、同じ読み手の長さと ACK 床は減らない
//! - (e) truncate: 書き込み側の静止点（`drain_acks` 後）で `set_len` する間、
//!   各スナップショットは旧内容の接頭辞で、truncate 完了後に開けば期待長になる。
//!   truncate 後に再開した書き込みは新 EOF に穴なしで着地する。静止点なしの
//!   rename / truncate・同じオフセットへの上書き競合は対象外
//!
//! [`concurrent_read`] の 6 件（`io4_concurrent_read_*`）とヘルパー検証 3 件
//! （`io4_helper_*`）は [`harness::DuplexEnd`] 基盤で 3 OS すべてで動く。
//! 開始同期は Barrier・ACK 進行・チャネルのみで行い（`sleep` 不使用）、待ちには
//! すべて期限を付ける（REPAIR-5）。

//! # 実行する OS の方針
//!
//! [`harness::DuplexEnd`]（`std::sync::mpsc` によるメモリ内の二方向
//! トランスポート）を使う 8 件の主ケース（[`concurrent_write`]）は 3 OS
//! すべてで動く（ci.md「OS 依存のファイルシステム挙動のテストは 3 OS すべてで
//! 実行する」）。[`fandhe_container_io::UdsServer`] は Linux / macOS 限定の
//! ため、実ソケット越しの並行性は [`uds_concurrent`]（TASK-14 追補・#1831）の
//! 5 件（U1〜U5。`WritebackSettings::bind` → `accept` → `serve` の実経路で複数の
//! UDS 接続を同時に流し、内容をバイト単位で照合する）が Linux・macOS で補強する。
//! Windows は UDS 未対応のため
//! `io4_uds_concurrent_bind_is_unimplemented_on_unsupported_os` の 1 件で未対応を
//! 明示する。[`rename_truncate`] の 11 件（R1〜R5・T1〜T6）も
//! 同じ [`harness::DuplexEnd`] 基盤で 3 OS すべてで動くが、1 点だけ OS 差の
//! 前提を置く: Rust std の既定 `share_mode` には `FILE_SHARE_DELETE` が
//! 含まれるため、開いているファイルを**移動元**として rename するのは
//! Windows でも成功する見込みだが、開いているファイルへ**上書きで rename
//! する**（既存ファイルの置換）操作は Windows では失敗しうる。そのため
//! 置換のケース（R3）は移動先を閉じた状態でだけ実行する。なお置換の原子性
//! （並行する読み手が旧内容・新内容のどちらかだけを観測すること）は OS の
//! rename が担う性質で本スイートの検証対象外とし、R3 は置換後の最終内容の
//! 完全一致だけを確認する。[`graceful_shutdown`] の 5 件（G1〜G5）も同じ
//! [`harness::DuplexEnd`] 基盤（実ソケットを使わない）で 3 OS すべてで動き、
//! OS 差の前提は置かない。[`write_failure`]（TASK-14 追補・#1829）の 5 件
//! （W1〜W5）は実ファイルへの書き込み失敗で部分レコードが ACK されないことを
//! 確認し、3 OS で動く（W3 の `/dev/full` ケースだけ Linux 限定で `cfg` により
//! コンパイル対象を分ける。skip ではない）。[`interleave`]（TASK-14 追補・#1830）の
//! 8 件（I1〜I7。I7 は通常・追記の 2 テスト）は `BatchSink` ラッパーで `write_batch` の前・サブバッチの間・
//! 後（ACK 送出前）に rename・`set_len` を差し込み、書き込みの途中で信号を出して並行に rename する反復（I6）と、1 回の
//! `write_batch` 中の並行 truncate（I7）も行う（静止点を作らない交錯）。差し込めない位置（1 回の
//! `AppendFileSink::write_batch` 内のフレーム間）と成り立つ条件の表は
//! [`interleave`] のモジュール doc に記す。3 OS で動く。
//! 合計は Linux 56 件・macOS 55 件・Windows 51 件。

// 残骸・PID 再利用との衝突を避ける一時ディレクトリの補助（REPAIR-12・#3435）。harness は作成前削除（A）、
// uds_concurrent は排他作成（B。UDS の短いパス）を使う。
#[cfg(unix)]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

#[path = "consistency/harness.rs"]
mod harness;

#[path = "consistency/concurrent_write.rs"]
mod concurrent_write;

#[path = "consistency/rename_truncate.rs"]
mod rename_truncate;

#[path = "consistency/graceful_shutdown.rs"]
mod graceful_shutdown;

#[path = "consistency/concurrent_read.rs"]
mod concurrent_read;

#[path = "consistency/write_failure.rs"]
mod write_failure;

#[path = "consistency/interleave.rs"]
mod interleave;

#[path = "consistency/uds_concurrent.rs"]
mod uds_concurrent;
