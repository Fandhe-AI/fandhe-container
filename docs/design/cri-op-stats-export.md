# plugin-cri の操作統計を stderr 以外へ出す方式（判断記録）

plugin-cri の常駐サーバーが集計する操作統計を、stderr 以外のメトリクス公開口へ出す方式を比較し、暫定の採用案を記録する（CRI-6・REPAIR-4）。公開口そのものは未実装で、実装は本書 6 章の作業単位（未起票）に分ける。

> **位置づけ**: 自動運転で安全側に選んだ判断であり、採用案のオーナー承認は未取得である（実装に入る前に承認を得る）。

- 関連ビヘイビア: CRI-6・REPAIR-4・REPAIR-3・REPAIR-5・CORE-1・SEC-1・SEC-4（SSOT は `docs/spec` の `04-behavior/`）
- 関連 issue: #4228（本判断）・#1869（closed。backend 配線の設計。メトリクス公開口は定義していない）
- 修正の発端: `crates/plugin-cri/src/telemetry.rs` の「未実装」に「公開口への接続は #1869 の core 側 proxy の責務」とあったが、#1869 の成果物（`plugin-backend-wiring.md`）にメトリクス公開口の定義は無く、plugin-cri は gRPC サーバーで core の長さ接頭辞フレームの proxy を通らない（同 4.9）ため、前提が成り立たなかった

## 1. 目的と範囲

- 対象: plugin-cri の常駐サーバーの操作統計。共有記録器と oci 専用記録器の 2 ブロック（`cri.streaming.*` の接続件数を含む）
- 対象外: shim（`containerd-shim-fandhe-container-v2`）。短命のため stderr のままとする（定期出力・ファイル公開口の対象外。起動時の `@container-logs` 走査の後に限り、回収が 1 件以上あれば操作統計のブロックを 1 回だけ stderr へ出す。#4319・CRI-5）

## 2. 現状

- `telemetry::op_stats_export_loop_many` が 60 秒ごとに stderr の `LineSink` へ JSON Lines（core の `OpRecorder::export_json_lines`。`op_stats` 行と `op_stats_meta` 行）を出す
- 1 周期に記録器ごとのブロックが出て、`op_stats_meta` は 2 行になる（#2900）。種類数の上限は 64。I/O は集計のロックを外してから行う（REPAIR-5）
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
| C. 原子的に置き換えるスナップショットファイル（opt-in の絶対パス。同じディレクトリの一時ファイルへ書き fsync して rename） | 常駐もポートも増えない。読み手は最新の 1 スナップショットだけを読む。textfile collector 型の収集器と組める | 置き先ディレクトリの信頼検査が要る | **暫定の採用案** |
| D. loopback の HTTP で Prometheus / OpenMetrics を返す | 標準的なスクレイプ | D1（既存ストリーミングサーバーへ `/metrics` を足す）はトークンで守られた面に未認証 route を足し、`--streaming-allow-external` の意味が変わる。D2（別 listener）はポートと bind 方針が増える。クレートを使うなら承認が要る | 却下。HTTP スクレイプが必須になったとき、または認証付き公開方式が決まったときに再評価 |
| E. CRI の UDS に独自 gRPC サービスを足す | 既存 socket を使える | その socket は kubelet のもので、cri-api は無改変（CRI-3）。契約がにごり proto も増える | 却下 |
| F. CRI の `ListMetricDescriptors`・`ListPodSandboxMetrics` | 標準の RPC | pod・コンテナのメトリクス用で、ランタイムの操作統計を運ぶ型ではない | 却下 |
| G. #1869 の core 側 proxy が回収 | 旧い記述の想定 | plugin-cri は proxy を通らない（`plugin-backend-wiring.md` 4.9） | 却下。旧い追跡先を外す根拠 |
| H. OTLP などの push 型 | 一般的 | 外部の収集先と依存が要り、既定で外へ出さない前提と相いれない | 却下 |

## 5. 採用案 C の契約（後続の実装の前提）

- **既定**: 無効。stderr への出力は変えず残す
- **有効化**: 起動引数 `--op-stats-file <PATH>`（仮名）。`--streaming-*` と同じ解析の流儀（重複・欠落・相対パス・`..` は `InvalidArgument` の固定文言）。環境変数にしない理由は、plugin の環境が将来の proxy で空になりうるため
- **形式**: 1 周期分の `export_json_lines` の出力（記録器ごとのブロック）を既存のスキーマのまま 1 ファイルにする。版のヘッダ行は付けない（#4337 で決定）。OpenMetrics 形式は再評価条件に回す。ヘッダ行を付けない理由は、(1) 各行が `event` で自己記述し、各ブロックが `op_stats_meta` 行で閉じるので、読み手はブロック数と完全性を `op_stats_meta` の行数で確かめられる、(2) stderr のストリームとバイト単位で同じ形に保てるので読み手の実装を共有できる、(3) ヘッダを足すと読み手が決まる前に新しいスキーマが増える。再評価条件は、既存の行スキーマを非互換に変えるとき、OpenMetrics / Prometheus 形式を採るとき（7 章）
- **書き方**: `O_NOFOLLOW`・`O_NONBLOCK`・`O_CLOEXEC`・権限 0600。置き先ディレクトリは実効 UID 所有・group/other 書き込み不可・symlink でないことを検査する。周期ごとに一時ファイルへ書き、fsync し、rename する
- **上限**: サイズは 64 KiB × ブロック数。超えたら書かずに失敗を数える
- **非同期**: 書き込みは専用 thread だけが行う（`LineSink` と同じ形）。仕事中なら次の周期は飛ばして数える。停止時の最後の書き出しは期限つき。失敗は固定語彙の 1 行（例 `op_stats_file_failed`）で stderr に残し、黙って捨てない（SEC-4・REPAIR-4）。RPC の受付は止めない（REPAIR-5）
- **出さない情報**: パス・errno・コンテナ ID

## 6. 後続の実装の作業単位（未起票）

起票したら issue 番号を本書と `telemetry.rs` に追記する。

- W1: cli の `open_op_log` 相当の安全な open の部品を、core へ移すか plugin-cri 側で同等に作るかを決めて実装する（core へ移すなら `cargo check --workspace --all-targets` も通す）
- W2: `startup.rs` で `--op-stats-file` を解析する（具体値の単体試験）
- W3: telemetry にスナップショットファイルの sink（専用 thread・一時ファイル → rename・上限・失敗の計数）を足し、stderr と並べて出す。試験: symlink・ディレクトリ権限の拒否、上限超過、置き換えの原子性、2 ブロックの内容
- W4: `main.rs` への結線、停止時の最後の書き出し、usage の更新
- W5: 文書の更新（本書の状態、`telemetry.rs` の未実装の節、CLAUDE.md）。実機前提の確認が要るなら `docs/verification/` に記録欄を作る

## 7. 未確認事項・再評価条件

- Prometheus 形式の要否・監視基盤からの要件
- 外部公開の方式（TLS・認証）が決まったとき
- shim の操作統計が要るようになったとき
