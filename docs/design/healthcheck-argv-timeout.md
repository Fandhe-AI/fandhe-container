# healthcheck の argv[0] の解決方式と timeout の上限（判断記録）

healthcheck コマンドの `argv[0]` をどう解決するかと、timeout の上限の食い違いをどう解くかの判断材料を整理する（SUP-4・SUP-6・STACK-2・REPAIR-5・TASK-161 追補。#2439）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまで現行の挙動（60 秒超の timeout は構築時に拒否・本番の exec アダプタは未実装）を保つ（fail-closed）。判断の窓口は #2439。関連: #2441（本番 HealthProbe アダプタ）・#2407・#495・#2314（PR #2331）・#863・#492。spec の SUP-4 は解決方式も上限値も定めておらず、いずれも本実装の判断である。

## 現状

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/supervisor/src/healthcheck.rs` | `MAX_TIMEOUT`（1 時間）・`DEFAULT_TIMEOUT`（30 秒）。`validate_command` は空・予約語・件数・合計バイト・NUL を拒否するが、絶対パスかは検査しない |
| `crates/supervisor/src/healthcheck/periodic.rs` | `HealthcheckSchedule::from_definition` が `timeout > MAX_POLL_INTERVAL` を `InvalidArgument` で拒否する。試験 `sup4_periodic_timeout_limit` が 60 秒受理・61 秒拒否を照合する |
| `crates/supervisor/src/health.rs` | `probe_and_record`・`probe_aggregate_and_record` が同じ上限（`MAX_POLL_INTERVAL`）で拒否する。判定は `ProbeRunner` の排他区間で同時に最大 1 本 |
| `crates/supervisor/src/run.rs` | `MAX_POLL_INTERVAL`（60 秒）は本来 monitor の `poll_interval` の上限で、probe の timeout 上限へ流用されている |
| `crates/supervisor/src/healthcheck/exec_probe.rs` | 本番アダプタ `ExecHealthProbe::new` は argv[0] が絶対パスでなければ `InvalidArgument`（固定文言）で拒否する（PATH 探索なしの現行を保つ）。60 秒超の timeout は上の拒否のまま。helper の `--timeout-ms` も 60 秒が上限（#2441。`healthcheck-exec-helper.md`） |
| `crates/supervisor/src/exec.rs` | `ExecRequest::new` の `path` はコンテナ内の絶対パスで、PATH 探索はしない。SUP-4 は healthcheck を exec（SUP-6）と同じ関数で実行することを求める |
| `crates/core`（PR #2331・#2314） | `process.args[0]` が `/` を含まない名前なら `process.env` の `PATH` で pivot 後の rootfs 内だけを探索する。稼働中コンテナへの exec は絶対パスのみのままで、追跡 issue は見当たらない |

PoC-17（`docs/spec/03-poc/supervisor-model/`）の healthcheck は `execvp`（PATH 解決）で実行され、使われたコマンドは数 ms〜数十 ms だった。実行期限の既定は run 5 秒・up 15 秒・後方互換ラッパー 60 秒。

## 論点 1: argv[0] の解決方式

### 1-A. 絶対パス限定

- 共有の `ExecRequest` は無変更で済む。`/bin/sh -c ...` 包み（CMD-SHELL 相当）は通る
- 名前指定（compose の `["CMD","curl",...]` 等）は拒否される。compose-convert はコンテナの `PATH` を知らず、名前を絶対パスへ機械変換できないため、互換の負担が利用者に移る

### 1-B. コンテナの PATH で解決（core の規則と揃える）

- SUP-4 の「exec と同じ関数」により、共有 exec 経路へ rootfs 内に閉じた探索を足すことになり、`ExecCommand`（SUP-6）も PATH 解決に変わる
- 決めること: 使う `PATH`（launch 時の `process.env` か healthcheck 定義の env か）、`/` を含む相対パスの扱い（拒否か cwd 起点か）、見つからないときの構造化エラー
- PoC-17 の実績と Docker 互換に近い。PoC-17 の `execvp` は supervisor 側の環境の `PATH` を使い得た点に注意する（探索は setns 後のコンテナ内に限る）

### 1-C. healthcheck だけ PATH 解決・exec は絶対パス

- SUP-4 の共通関数要件と衝突しやすいため非推奨

**Agent の推奨（決定ではない）**: 1-B。core（#2314）と規則が揃い、PoC-17 とも一致する。採用する場合は exec 側の PATH 探索の追跡 issue の起票と、#2441 の受け入れ条件の更新が要る。

## 論点 2: timeout の上限

### 2-A. 定義の `MAX_TIMEOUT` を 60 秒へ下げる

- 上限が 1 つに揃い、`HealthcheckDefinition::parse` の段階（stack / compose の検証）で早期に失敗する
- 60 秒超を書いた compose は検証で失敗する

### 2-B. probe 専用の上限定数を `MAX_POLL_INTERVAL` から切り離す

- 意味が違う 2 つの上限を分離し、値は別途決める（例: 定義と同じ 1 時間、または中間値）
- `ProbeRunner` の排他区間が長く塞がる。有限待ちなので REPAIR-5 は満たすが、停止（`StopToken`）・回収の期限との整合を確認する必要がある

### 2-C. 現状維持（スケジュール構築時の拒否）

- 食い違いは残るが fail-closed。コード変更なし

**Agent の推奨（決定ではない）**: 2-A。実用上の healthcheck は数 ms〜数十秒で、PoC-17 の期限も 5〜60 秒だった。Docker 互換（長い timeout を許す）を重視するなら 2-B。

いずれの選択でも関係するコード: `healthcheck.rs` のモジュール doc（既知の食い違い）・`MAX_TIMEOUT`、`periodic.rs` の `from_definition` と試験 `sup4_periodic_timeout_limit`、2-B なら `health.rs` の 2 関数の上限検査。

## Docker / compose の挙動

一次情報（Docker ドキュメント・moby・compose-spec）での照合は未実施で、本書では断定しない。決定前に次を確認する: exec 形式の `PATH` 解決の有無、`CMD-SHELL` が `/bin/sh -c` か、`timeout` の既定値と上限の有無、compose-spec の `healthcheck.test` / `timeout` の定義。

## セキュリティ考慮

- インジェクション: argv をシェル連結しない。`CMD-SHELL` は拒否し、変換は compose-convert の責務（現行どおり）
- 分離（SEC-1・SEC-5）: PATH 探索を採るなら setns 後の rootfs 内に閉じ、ホストの `PATH`・ファイルを見ない。symlink で rootfs の外へ出ない（#2314 と同じ条件）。コンテナ内で書き込める `PATH` 上の差し替えはコンテナ内の権限で起こることで、ホストへの昇格経路ではない
- 資源枯渇（REPAIR-5）: timeout の上限は必ず有限にする。上限を上げる案は `ProbeRunner` の占有時間が延びる
- 監査（SEC-4）: 実行は `run_command_with_pidfd` の監査必須（#2441）
- command の中身をエラー・ログへ出さない既存方針を維持する

## 決定後の作業

1. #2439 に判断を記録する
2. #2441 の受け入れ条件を更新する（または別 issue を起票する）。1-B なら exec の PATH 探索の追跡 issue も要る
3. 判断に沿って `healthcheck.rs`・`periodic.rs`・`health.rs` の定数・doc・試験を直す
4. #863（stack の型定義）・compose-convert への影響を確認する

## オーナー決定

| 論点 | 選択 | 決定日 | 理由 |
| ---- | ---- | ------ | ---- |
| 1: argv[0] の解決方式 | （未決） | | |
| 2: timeout の上限 | （未決） | | |
