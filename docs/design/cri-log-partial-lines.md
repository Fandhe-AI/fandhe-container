# CRI ログの部分行 `P` の方式（CRI-2・SUP-7・REPAIR-3）

issue #4116 の項目 8（2026-11-12 にオーナーが「追跡する: 方式の設計から」と判断）を受けた設計記録（#4574）。コードは変更しない。実装は #4580・#4582、`fandhe logs` の扱いの判断は #4581（下の「実装 issue」）。

## 目的

kubelet・crictl が読む CRI ログ（`--cri-log-path`）に、次の差がある。

1. **64 KiB を超える行の欠落**: 捕捉側が 1 行を `MAX_LINE_BYTES`（64 KiB）で切り詰めて超過分を捨てる。containerd は長い行を部分行 `P` に分けて残す。大きな JSON のログなどが、この実装でだけ途中から失われる
2. **LF の無い出力の滞留**: tty のプロンプトなど、LF・EOF・上限のどれも来ない出力は CRI ログに出ない

どちらを、どの方式で埋めるか（または埋めないか）を決める。

## 現状の経路と 2 つのレコード形式（R1）

```text
コンテナの stdout / stderr
  → 捕捉リーダー（logs/reader.rs → LineSplitter。LF・EOF・MAX_LINE_BYTES で行にする）
  → TeeLogSink（logs/cri.rs。出力先ごとに失敗状態を持つ）
      ├─ ① RotatingFileSink（@container-logs。fandhe logs が読む）
      └─ ② CriFileSink（--cri-log-path。kubelet・crictl が読む）
```

| 項目 | ① `@container-logs` | ② CRI ログ |
| ---- | ------------------- | ---------- |
| 形式 | `stdout` / `stderr` のタグ（後ろに空白）+ 行 + LF | `<RFC3339Nano> <stdout\|stderr> <F\|P> <内容>\n` |
| 1 行の上限 | `MAX_LINE_BYTES`（64 KiB）。`Scanner` が超過を `Malformed` にする | 書き手が 16 KiB（`CRI_LOG_CHUNK_BYTES`）ごとに `P…P F` へ分ける。**P への分割は既にある** |
| 読み手 | CLI の `logs`（`--tail`・`--stream`・`--escape`・`--follow`） | kubelet・crictl |

64 KiB を超えた分が CRI ログで失われる原因は、手前の `LineSplitter` の切り詰め（`StreamSummary::truncated_lines` に数える）で、`CriFileSink` ではない。Attach の出力は捕捉の tap（#4072）が生のチャンクを複製するため、この経路の影響を受けない。

## 一次情報（出典を固定して原文で確認）

- containerd v2.1.0（commit `fcfeb3fe8f3b1aad04c54f569b8de8d3d12cca8e`）`internal/cri/io/logger.go` の `redirectLogs` / `readLine`
  - 1 行が `maxLen`（`max_container_log_line_size`）を超えると、`maxLen` ちょうどで切って `P` で書き、残りを次へ持ち越す。LF で終わった行の最後が `F`
  - **EOF（または読み取りエラー）で LF の無い末尾が残ると、`P` で書いて止まる**（コメント「it should be treated as a partial line」）。`F` ではない
  - **期限・タイマーでの書き出しは無い**。`bufio.Reader`（大きさは `min(4096, maxLen)`）が満ちると `isPrefix` で内容を溜め続け、LF か EOF か `maxLen` 超過まで書かない
  - 読み取りエラーでも、溜めた内容は `P` で書く（EOF と同じ）
  - タイムスタンプはレコードを書く時点の `time.Now()`（レコードごと）
  - `\r\n` の `\r` は落とす（`readLine`）
- containerd v2.1.0 `internal/cri/config/config.go`: `max_container_log_line_size` は「これを超える行は複数行に分ける。非正の値は無制限」。既定値は 16384
- Kubernetes v1.34.0（commit `275918a59a3df182fc5e9f7f9f6e960384399a35`）`staging/src/k8s.io/cri-client/pkg/logs/logs.go` の `parseCRILog`: タグが `P` のレコードは末尾の LF を落として内容だけを表示し、`F` は LF を付けて表示する。`LogTagPartial`・`LogTagFull` は cri-api の定数

## 論点と決定

### 論点 A: 64 KiB を超える行（採る: A3）

| 案 | 内容 | 判断 |
| -- | ---- | ---- |
| A1 | 現状維持（切り詰め） | 却下。大きな行がこの実装でだけ失われる |
| A2 | `MAX_LINE_BYTES` を上げる | 却下。切り詰めは残り、リーダーごとのメモリが増え、`@container-logs` の検証値と `MIN_LOG_FILE_BYTES` にも波及する |
| **A3** | **捕捉側が「行の断片」を sink へ渡し、断片の扱いは sink ごとに決める** | **採る** |
| A4 | `@container-logs` にも部分行の印（新しいタグ）を入れる | 却下（この issue の範囲では）。`Scanner`・raw 出力・`--follow`（完全な行だけ出す）・`--tail` の数え方が変わり、旧 CLI は新しいファイルを `Malformed` で読めなくなる。採るかは #4581 の判断に回す |

A3 の設計:

- `LogSink` に `append_part(stream, bytes, part: LinePart)` を足す。`LinePart` は `#[non_exhaustive]` で、`index`（何番目の断片か）と `end`（`Continued` / `Lf` / `Eof`）を持つ
- `LineSplitter` は、バッファが `MAX_LINE_BYTES` に達しても LF が無ければ、そこまでを `Continued` で渡してバッファを空にし、読み続ける。メモリは従来どおり 1 ストリーム 64 KiB 以下
- **トレイトの既定実装で現行の挙動を残す**: `index == 0` なら `append(stream, bytes)` を呼び（`Continued` の 64 KiB は現行の切り詰めと同じバイト列）、`index > 0` なら何もしない。`RotatingFileSink`・`MemoryLogSink`・`DiscardLogSink` と試験用の sink は変更不要で、`@container-logs` のレコード形式・`Scanner` の検証・CLI の `logs` の全オプション・既存ログファイルの読み取りは変わらない（R2 の互換）
- `CriFileSink` は上書きする: `Continued` は全チャンク `P`、`Lf` は最後のチャンクだけ `F`、`Eof` は全チャンク `P`（containerd と同じ）
- `MAX_LINE_BYTES`（64 KiB）は `CRI_LOG_CHUNK_BYTES`（16 KiB）の倍数なので、断片の境界と CRI のチャンクの境界が揃う。`const` の表明で固定する
- `TeeLogSink` は断片を両方へ渡す。出力先ごとの失敗状態は変えない
- `truncated_lines` の意味は「`@container-logs` で切り詰めた行数」とする。CRI ログ側では欠落しない
- 総量は従来どおり `CRI_LOG_MAX_BYTES`（50 MiB）で頭打ち。LF の無い巨大な出力でも、ディスクへの書き込みは有界

### 論点 B: LF の無い出力を期限で `P` として書き出すか（採らない）

- 不採用。containerd も期限では書き出さない（上の一次情報）
- 書き出すにはリーダーにタイマーか read の期限が要り、read の期限は `sys` の宣言と `unsafe` を、タイマーは追加のスレッドを増やす。行が任意の位置で細切れになる
- 対話の用途は Attach の tap（#4072）が生バイト列で担う
- 残る差: tty のプロンプトは LF・EOF・64 KiB のどれかまで CRI ログに出ない。これは containerd と同じ

### 論点 C: 読み取りエラーで終わった未完了の末尾

- 現行の契約（途中で欠けた内容を正常な行として残さない。`discard_partial`）を保つ。CRI 側にもその末尾は書かない
- containerd はこの末尾も `P` で書くため差になる（下の表）。それより前の `Continued` 断片は書き済みで、CRI ログは `F` の無い `P` で終わることがある。kubelet は LF なしで表示する

### 論点 D: 再起動をまたぐ sink と `Eof` の `P`

- `Eof` を `P` にすると、同じ CRI ログを次の実行が使い回した場合に、kubelet の表示で前回の末尾と次の行がつながる
- CRI のコンテナは supervisor に `--restart` を渡さず（既定の `no`。`docs/design/cri-record-readoption.md`）、kubelet が `<containerName>/<restartCount>.log` を新しく作る。使い回しは起きないため `Eof` は `P` にする（containerd と同じ）
- 前提が崩れる経路（同じ書き先への再 launch）が見つかったら、`Eof` を `F` にするか再 launch の前に区切るかを、そのとき決める

## containerd との差・残る差

| 項目 | 本実装（採用後） | containerd |
| ---- | ---------------- | ---------- |
| チャンクの大きさ | 16 KiB に固定（設定できない） | `max_container_log_line_size` で変えられる（非正で無制限） |
| 期限での書き出し | しない | しない（同じ） |
| EOF の末尾のタグ | `P` | `P`（同じ） |
| 読み取りエラーの末尾 | 捨てる（`discard_partial`） | `P` で書く（差） |
| 総量の上限 | 50 MiB で書き出しを止める（`ReopenContainerLog` が未実装のため） | 上限なし（kubelet の回転に任せる） |
| タイムスタンプ | 1 断片に 1 時刻（断片内の複数チャンクは同じ時刻） | レコードごと |
| `\r\n` | `\r` を残す（現行） | `\r` を落とす（`readLine`） |
| `fandhe logs`（`@container-logs`） | 64 KiB で切り詰めたまま（#4581 で判断） | 対象外 |

## セキュリティ・資源の観点（OWASP / SEC）

- 不安全な設計: 断片は `MAX_LINE_BYTES` 以下で、メモリはストリームごとに有界。期限での書き出しを採らないのでタイマーのスレッドも read の期限の `unsafe` も増えない。LF の無い巨大な出力は、捨てる代わりに `CRI_LOG_MAX_BYTES` で有界に書く
- インジェクション: 断片は LF を含まない（`LineSplitter` が LF で分ける）ので、CRI のレコード（タイムスタンプ・タグ・LF）を偽装する行は作れない。`CriFileSink` は LF を含む入力を引き続き拒否する
- 情報の露出: 行の内容は不透明なバイト列のまま扱い、エラー・op ログ・telemetry に内容・パス・errno を出さない（ERR-1）
- アクセス制御: 開き方（`O_NOFOLLOW`・親の検査・ambient capability での拒否・`flock`）は変えない
- 新しい依存・`unsafe`・特権操作は無い

## 実装 issue と依存の順

| issue | 内容 | 依存 |
| ----- | ---- | ---- |
| #4580 | `LogSink::append_part` と `LinePart` を足し、`LineSplitter` が断片を渡す（既定は現行の切り詰め） | なし |
| #4582 | `CriFileSink`・`TeeLogSink` が断片を `P` / `F` で書く。kubelet と同じ規則で連結する解析の試験。関連文書の状況欄を直す | #4580 |
| #4581 | `fandhe logs` でも 64 KiB 超の行を残すかの判断（オーナー判断・人間担当。(a) 現状維持を推奨） | なし（#4580・#4582 は待たない） |

親は #4474（#4581 は #816）。

## 再評価条件

- #4581 で (b)（`@container-logs` にも部分行の印）を採ったとき
- containerd の `redirectLogs` が期限での書き出しや EOF の扱いを変えたとき
- `ReopenContainerLog` を実装して総量の上限を外すとき
- CRI のコンテナで同じ書き先への再 launch が起きるようになったとき（論点 D）
