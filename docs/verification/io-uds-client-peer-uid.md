# UDS クライアントの接続先 uid 照合の実機確認 手順書と結果記録（#3167）

`UdsClientConnection::connect`（`crates/io/src/uds_client.rs`）が、接続前のパス検査を通った後でも、別 uid が動かすサーバーへの接続を接続後の peer uid 照合で拒否することを、実機で確かめる手順と結果記録の雛形。対応する ID は PLUG-12・SEC-4・IO-1・REPAIR-5・REPAIR-12。設計は `docs/design/io-protocol.md` の「ワイヤー上のファイル操作要求と UDS クライアント」F14。関連 issue は #3167（自動試験の追加）・#3165（実装）。

実行・結果の記録・成否の判定は人間が行う。Agent は root のコマンドを実行しない。本書のコマンドは作成時に未実行である。ホスト名・アドレス・ユーザー名・実 uid の値・`$HOME` の実パスは記録しない。対象は Linux と macOS。

## 背景と自動試験との分担

- uid が違う policy での拒否は CI で確かめ済み: `crates/io/tests/uds_client.rs` の `plug12_uds_client_rejects_policy_with_different_uid`（接続前のパス検査で `InvalidArgument`）と、`src/uds_client.rs` の `UnixStream::pair()` の単体試験（接続後の peer uid 照合）
- 本書が扱うのは、別 uid が実際に動かすサーバーへの接続。root が要るため CI では回さない
- 素朴に「2 ユーザー」で試すと、0700 の親ディレクトリで接続前のパス検査の段階で止まり、接続後の照合まで届かない。接続後の照合を識別するには、パス検査を通る配置（ソケットと親ディレクトリの所有者がクライアントの uid）で、サーバープロセスだけが別 uid になる構成にする

## 構成

1. 実行ユーザー（以下 A）所有の 0700 のディレクトリを作り、その中でサーバーのソケットを bind する。ソケットと親ディレクトリを A 所有にするため、サーバーを root で起動した後に `chown` で A へ渡す（`bind` 後・クライアント接続前）
2. サーバー: `UdsServer::bind` 相当を root で動かすスクリプトまたは試験用バイナリ（作成者が用意し、内容を確認した信頼できるファイルだけを絶対パスで渡す）
3. クライアント: A で `UdsClientConnection::connect` を `UdsServerPolicy::same_effective_uid()`（または `exact_uid(A)`）で呼び、観測フックに接続時の拒否記録を共有できる記録先を渡す（`Err` のとき接続ごと drop されるため）

## 期待値

| 場面 | 期待 |
| ---- | ---- |
| サーバーが root、ソケットと親が A 所有、policy が A | `InvalidArgument`（peer uid が 0 で A と不一致）。観測フックに `RejectedPeerCredential`（op = `Connect`）が 1 件。サーバーはデータを受け取らない |
| 対照: サーバーも A で動かす | 接続が成功し、`create` の ACK が返る |
| サーバーが無い | `Unavailable`（`ENOENT`・`ECONNREFUSED`） |

## 事前確認

- `cargo test -p fandhe-container-io --test uds_client` が通ること
- 実行したコミットの SHA（`git rev-parse HEAD`）・`uname -r` を控える

## 結果記録（人間が記入）

| 項目 | 記入欄 |
| ---- | ------ |
| 実行日 | |
| コミット SHA | |
| OS・カーネル版 | |
| root サーバー + A クライアント: エラー種別 | |
| `RejectedPeerCredential`（op = `Connect`）の件数 | |
| 対照（A サーバー）: ACK の受信 | |
| 判定 | |
| 備考 | |
