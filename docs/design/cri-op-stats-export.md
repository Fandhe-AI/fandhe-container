# plugin-cri の操作統計を stderr 以外へ出す方式（判断記録）

plugin-cri の常駐サーバーが集計する操作統計を、stderr 以外のメトリクス公開口へ出す方式を比較し、採用案を記録する（CRI-6・REPAIR-4）。採用は案 C（原子的に置き換える opt-in のスナップショットファイル）で、6 章の作業単位 W1〜W4 により実装済みである。

> **位置づけ**: オーナー承認済み（2026-11-09・#4295）。Q1（公開口）は案 C、Q2（形式）は読み手が決まるまで stderr と同じ JSON Lines のままとする。REPAIR-4 は stderr の JSON Lines で既に充足しており、この公開口は spec の要求外の改善で優先度は低い。

- 関連ビヘイビア: CRI-6・REPAIR-4・REPAIR-3・REPAIR-5・CORE-1・SEC-1・SEC-4（SSOT は `docs/spec` の `04-behavior/`）
- 関連 issue: #4228（本判断）・#4295（オーナー判断）・#4335・#4336・#4337・#4340・#4341（作業単位 W1〜W5）・#1869（closed。backend 配線の設計。メトリクス公開口は定義していない）
- 修正の発端: `crates/plugin-cri/src/telemetry.rs` の「未実装」に「公開口への接続は #1869 の core 側 proxy の責務」とあったが、#1869 の成果物（`plugin-backend-wiring.md`）にメトリクス公開口の定義は無く、plugin-cri は gRPC サーバーで core の長さ接頭辞フレームの proxy を通らない（同 4.9）ため、前提が成り立たなかった

## 1. 目的と範囲

- 対象: plugin-cri の常駐サーバーの操作統計。共有記録器と oci 専用記録器の 2 ブロック（`cri.streaming.*` の接続件数と、`cri.port_forward.*` の回収できない helper の保持・上限超過・満杯の件数〔#4546。名前は暫定〕を含む）
- 対象外: shim（`containerd-shim-fandhe-container-v2`）。短命のため stderr のままとする（定期出力・ファイル公開口の対象外。stderr へ出すのは 2 時点だけ。(1) 起動時の `@container-logs` 走査の後に、回収が 1 件以上あれば操作統計のブロックを 1 回（#4319・CRI-5）、(2) serve の終了時に、集計対象が 1 件以上あれば serve 開始からの累計を 1 回（待ちは 1 秒で打ち切り。#4408・REPAIR-4・REPAIR-5）。定期出力・ファイル公開口は引き続き無い）

## 2. 現状

- `telemetry::op_stats_export_loop_many` が 60 秒ごとに stderr の `LineSink` へ JSON Lines（core の `OpRecorder::export_json_lines`。`op_stats` 行と `op_stats_meta` 行）を出す
- 1 周期に記録器ごとのブロックが出て、`op_stats_meta` は 3 行になる（CRI・ライフサイクル・oci の順。#2900・#4380）。種類数の上限は 64。I/O は集計のロックを外してから行う（REPAIR-5）
- CLI には `FANDHE_CONTAINER_OP_LOG` が指すファイルへ追記する前例がある（`crates/cli/src/commands/create_start.rs`。cli の private で plugin-cri からは使えない）

## 3. 前提・制約

- CORE-1: plugin プロセス以外の常駐を作らない
- 既定では何も開かない（fail-closed）。外部インターフェースへ bind しない
- REPAIR-5: 出力先の詰まりで記録経路と RPC を止めない
- 種類数は有界。行の値は固定語彙の操作名と整数だけで、パス・コンテナ ID・資格情報は入れない
- 新しい外部依存は足さない（足す場合はユーザー承認。[dependency-policy](../../.claude/rules/dependency-policy.md)）

## 4. 候補の比較

| 案 | 利点 | 欠点 | 採否・再評価条件 |
| -- | ---- | ---- | ---------------- |
| A. stderr のみ（現状維持） | 変更なし | 収集は親（journal・containerd 等）任せでスクレイプできない。監査行と同じ sink で、洪水時の間引きの影響を受ける | 既定の出力先としては残すが、これだけでは不十分 |
| B. CLI と同じ追記ファイル | リポ内に前例 | 長寿命で 60 秒ごとに追記すると際限なく大きくなる | 却下。回転・上限つき追記が必要になったら再評価 |
| C. 原子的に置き換えるスナップショットファイル（opt-in の絶対パス。同じディレクトリの一時ファイルへ書き fsync して rename） | 常駐もポートも増えない。読み手は最新の 1 スナップショットだけを読む | 置き先ディレクトリの信頼検査が要る。node_exporter の textfile collector は Prometheus のテキスト形式しか読まず、0600 の JSON Lines は別 uid の収集器から読めないため、収集器とは直結できない（読み手側の変換、または形式・権限の再評価が要る。7 章） | **採用**（2026-11-09・#4295） |
| D. loopback の HTTP で Prometheus / OpenMetrics を返す | 標準的なスクレイプ | D1（既存ストリーミングサーバーへ `/metrics` を足す）はトークンで守られた面に未認証 route を足し、`--streaming-allow-external` の意味が変わる。D2（別 listener）はポートと bind 方針が増える。クレートを使うなら承認が要る | 却下。HTTP スクレイプが必須になったとき、または認証付き公開方式が決まったときに再評価 |
| E. CRI の UDS に独自 gRPC サービスを足す | 既存 socket を使える | その socket は kubelet のもので、cri-api は無改変（CRI-3）。契約がにごり proto も増える | 却下 |
| F. CRI の `ListMetricDescriptors`・`ListPodSandboxMetrics` | 標準の RPC | pod・コンテナのメトリクス用で、ランタイムの操作統計を運ぶ型ではない | 却下 |
| G. #1869 の core 側 proxy が回収 | 旧い記述の想定 | plugin-cri は proxy を通らない（`plugin-backend-wiring.md` 4.9） | 却下。旧い追跡先を外す根拠 |
| H. OTLP などの push 型 | 一般的 | 外部の収集先と依存が要り、既定で外へ出さない前提と相いれない | 却下 |

## 5. 採用案 C の契約

- **既定**: 無効。stderr への出力は変えず残す
- **有効化**: 起動引数 `--op-stats-file <PATH>`（`=` 形も可。確定）。非 Linux では `UNIMPLEMENTED` で拒否する。`--streaming-*` と同じ解析の流儀（重複・欠落・相対パス・`..` は `InvalidArgument` の固定文言）。環境変数にしない理由は、plugin の環境が将来の proxy で空になりうるため
- **形式**: 1 周期分の `export_json_lines` の出力（記録器ごとのブロック）を既存のスキーマのまま 1 ファイルにする。版のヘッダ行は付けない（#4337 で決定）。読み手（監視基盤の要件）が決まるまで、既存の stderr と同じ JSON Lines とする（Q2・#4295）。OpenMetrics 形式は再評価条件に回す。ヘッダ行を付けない理由は、(1) 各行が `event` で自己記述し、各ブロックが `op_stats_meta` 行で閉じるので、読み手はブロック数と完全性を `op_stats_meta` の行数で確かめられる、(2) stderr のストリームとバイト単位で同じ形に保てるので読み手の実装を共有できる、(3) ヘッダを足すと読み手が決まる前に新しいスキーマが増える。再評価条件は、既存の行スキーマを非互換に変えるとき、OpenMetrics / Prometheus 形式を採るとき（7 章）
- **書き方**: `O_NOFOLLOW`・`O_NONBLOCK`・`O_CLOEXEC`・権限 0600。置き先ディレクトリは実効 UID 所有・group/other 書き込み不可・symlink でないことを検査する。周期ごとに一時ファイルへ書き、fsync し、rename する
- **上限**: サイズは 64 KiB × ブロック数。超えたら書かずに失敗を数える
- **非同期**: 書き込みは専用 thread だけが行う（`LineSink` と同じ形）。仕事中なら次の周期は飛ばして数える。停止時の最後の書き出しは期限つきで、`shutdown::OP_STATS_FINAL_WRITE_WAIT`（1 秒）を超えたら `final_timeout` の行を残して停止を続ける。失敗・飛ばしは固定語彙の行（`op_stats_file_failed`・`op_stats_file_skipped`）で stderr に残し、黙って捨てない（SEC-4・REPAIR-4）。RPC の受付は止めない（REPAIR-5）
- **出さない情報**: パス・errno・コンテナ ID

## 6. 作業単位（起票・実装済み）

| 単位 | issue | 内容 | 状態 |
| ---- | ----- | ---- | ---- |
| W1 | #4335 | 安全な open と原子的な置き換えの部品 | 済み |
| W2 | #4336 | `startup.rs` で `--op-stats-file` を解析する | 済み |
| W3 | #4337 | telemetry のスナップショットファイル sink | 済み |
| W4 | #4340 | `main.rs` への結線・停止時の最後の書き出し・usage | 済み |
| W5 | #4341 | 文書の更新（本書・`telemetry.rs`・CLAUDE.md） | 本更新 |

- W1 は `crates/plugin-cri/src/snapshot_file.rs` として plugin-cri 側に置いた（REPAIR-1）。改修が plugin-cri の 1 crate で閉じ、core の公開面を広げず他 crate へ波及させないため。cli の `open_op_log` は cli の private のまま残す
- REPAIR-4 は stderr で充足済みで、この公開口は spec の要求外の改善のため優先度は低い
- 実機前提の確認は不要。本番バイナリの結合試験 `crates/plugin-cri/tests/op_stats_file.rs`（Linux・既定の試験集合）で照合している。`docs/verification/` の記録欄は作らない

## 7. 未確認事項・再評価条件

- Prometheus / OpenMetrics 形式の要否・監視基盤からの要件、および読み手（収集器）の uid とファイル権限 0600 の扱い（監視基盤の要件が出たときに再評価する）
- 外部公開の方式（TLS・認証）が決まったとき
- shim の操作統計が要るようになったとき（#4379 で exec 起動役の計数 2 種が増え、この条件に当たったため #4408 で再評価した。結論: serve の終了時に 1 回書き出す。shim は短命でコンテナごとに起動するため、ファイル公開口・定期出力は採らない。SIGKILL と停止の期限切れでは出ない。次の再評価条件: shim の稼働中の値を収集器が読む必要が出たとき、SIGKILL や停止の期限切れで欠ける値が運用で問題になったとき）
