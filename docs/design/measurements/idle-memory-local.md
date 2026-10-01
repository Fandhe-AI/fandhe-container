# アイドル時常駐メモリのローカル実測レポート

コンテナ 0 個のとき、fandhe-container 関連の常駐プロセスが 0 個で PSS / RSS も 0 kB であることを、非特権のローカル環境で確認した記録。PoC-17（supervisor-model）の Linux 実機実測の確定値と整合する。ただし対象の実行ファイルが現状存在しないため、この 0 は実装の性質ではなく構造上の自明な値である。

- 対象ビヘイビア: CORE-7（アイドル時常駐メモリ）。関連: SUP-1（コンテナ 0 個なら常駐プロセス 0 個）・CORE-1・REPAIR-3・REPAIR-5
- 関連タスク: TASK-45・TASK-45.1（#210・PR #1184。`scripts/bench/idle_memory.sh`）・TASK-45.2（#211。本書）・TASK-47（#214。人間担当・root 権限での最終確認）・TASK-157・TASK-158（#484。supervisor の PSS 按分計測）・TASK-29
- 対象マイルストーン: MS-2 Phase 3
- ステータス: **非特権でのローカル実測と補助計測を記録。root 権限での確定計測は未実施で TASK-47 へ引き継ぎ**（実装済みを装わない。REPAIR-3）

## 計測方法

- 本スクリプト: [`scripts/bench/idle_memory.sh`](../../../scripts/bench/idle_memory.sh)（`make idle-memory`）。実行ファイルの basename で対象プロセスを識別し、確認できないプロセスがあると fail-closed で終了コード 3 になる。識別規則・終了コードの詳細はスクリプトのヘッダコメントと `AGENTS.md` を参照
- 補助計測（非特権・読み取りのみ・3 試行）: 全ユーザーが読める情報から、対象名のプロセスが存在しないことを確認する。cmdline 全文と環境変数は出力せず、件数だけを記録する
  - `pgrep -c '^fandhe-contain'`（comm は 15 文字で切れるため前方一致）
  - `/proc/<pid>/comm` が `fandhe-container`・`fandhe-container-*`・`fandhe-containe` のいずれかに一致する件数
  - `/proc/<pid>/exe` の basename が `fandhe-container`・`fandhe-container-*` に一致する件数（読めるプロセスに限る）

## 計測環境

| 項目 | 値 |
| ---- | ---- |
| 計測対象コミット | `707dad97cf7876cb80aecbc1026b722488b9f7b1`（`origin/main`） |
| 実施日（UTC） | 2026-10-01 |
| 環境 | Linux x86_64（ローカル開発機）・カーネル 7.0.0-34-generic・bash 5.3 |
| 実行ユーザー | 非 root（uid 0 ではない）。sudo は実行していない |

## 実測結果

### 構造的確認

| 確認 | 結果 |
| ---- | ---- |
| `cargo metadata` の bin ターゲット | 1 件のみ。`crates/io/tests/bin/crash_test_server.rs` の `crash_test_server`（io crate のテスト用ヘルパで fandhe-container の製品実行ファイルではない） |
| `command -v fandhe-container` | 見つからない |
| `target/` 配下の実行ファイル | ビルド成果物なし（`target/` が存在しない） |

cli・supervisor は `src/lib.rs` のみで、fandhe-container の実行ファイルは構造上まだ存在しない。

### 本スクリプトの実行（非特権）

| 実行 | 終了コード | stderr |
| ---- | ---- | ---- |
| `make idle-memory` | 3（make 自身は 2。`Error 3` 行で確認） | `error: measurement-failed: cannot verify executable of pid 1 (insufficient permission?)` |
| `bash scripts/bench/idle_memory.sh --format json` を 3 試行 | 3（3 試行とも同一） | 同上 |

他ユーザーのプロセス（pid 1 等）の exe を非特権では読めないため、スクリプトは設計どおり fail-closed で停止した。成功出力（JSON）は得られていない。

### 補助計測

| 試行 | `pgrep -c` | comm 一致 | 自ユーザーの exe 一致 |
| ---- | ---- | ---- | ---- |
| 1 | 0 | 0 | 0 |
| 2 | 0 | 0 | 0 |
| 3 | 0 | 0 | 0 |

`pgrep` は 0 件のとき終了コード 1 を返すが、これは「該当なし」として扱った。exe の照合は自ユーザーのプロセスに限られる。

### 結論値

| 項目 | 値 | 導出元 |
| ---- | ---- | ---- |
| process_count | 0 | 補助計測 3 試行（comm・exe・pgrep） |
| pss_kb | 0 | 対象プロセス 0 個に対する合計であり、定義上の値 |
| rss_kb | 0 | 同上 |

これらはスクリプトの成功出力から得た値ではない。

## 事実と推論の区別

- 事実: 非特権では `idle_memory.sh` は終了コード 3 で停止する。補助計測で対象名のプロセスは 0 件
- 推論: 製品の実行ファイルがない現状では 0 は構造上自明で、実装がアイドル時にゼロへ戻ることの証拠にはならない
- 未検証: CLI / supervisor（TASK-29 系・TASK-157）の実装後に、コンテナの create → delete を経ても常駐が残らないこと

## PoC-17（supervisor-model）の確定値との比較

| 項目 | PoC-17（Linux 実機・own n=0） | 本実測（補助計測） |
| ---- | ---- | ---- |
| プロセス数 | 0（3 試行） | 0（3 試行） |
| PSS / RSS | 0 KB（3 試行） | 0 kB（対象 0 個のため定義上） |
| pgrep | 該当 0 件 | 0 件 |
| 判定 | 整合 | 整合 |

差異:

- 計測対象: PoC は PoC 用のプロトタイプ、本実測は fandhe-container の命名規則
- 権限: PoC は root 権限での計測、本実測は非特権で exe を読める範囲に限る
- 参考: Docker（dockerd + containerd）の n=0 PSS は 133,046 / 188,410 / 183,793 KB（PoC-17）。ローカルでの Docker 比較は TASK-47 の範囲

## 再実行手順

非特権の補助計測は、上記「計測方法」の 3 コマンドをそれぞれ実行する。

root 権限での確定計測（操作者が権限付きシェルで明示的に実行する。Agent は実行しない）:

```bash
timeout --kill-after=10 120 bash scripts/bench/idle_memory.sh --format json --expect-zero
```

## TASK-47（#214・人間担当）への引き継ぎ

判断はせず、確認事項として並べる。

- root 権限で終了コード 0 の成功出力（JSON）を観測できるか
- `--expected-dir` の指定方針をどうするか
- CLI / supervisor 実装後に create → delete を経てゼロへ戻るか
- ローカルの Docker の n=0 との比較（CORE-7）

計測ハーネス（Agent 担当分・#214）: [`scripts/bench/idle_memory_supervised.sh`](../../../scripts/bench/idle_memory_supervised.sh)（`make idle-memory-supervised DRIVER=<絶対パス>`）が「0 個 → 監視プロセス込み 1 個 → 0 個」の 3 フェーズを計測し、0 へ戻ることを機械判定する。操作者が渡す driver（`up` / `down`）が必要だが、製品バイナリ（supervisor の入口・CLI。TASK-79）が未提供のため実 driver は現時点で存在せず、実機での確定値取得は本タスクの担当。実機では `EXPECTED_DIR` に配置ディレクトリを渡す。
