# macOS VM cold start 計測ハーネス

実 VM の cold start（MAC-2「VM の cold start が 2 秒以内」）を実機で測るための計測ハーネスの定義である（MAC-2・MAC-1・REPAIR-4・REPAIR-5・REPAIR-12。TASK-70〔#381〕の準備・TASK-64 追補・#1879）。実機での実測と合否の判定は #381（人間担当）が行う。ハーネスは合否を出さない。

入口は `crates/platform-macos/tests/vm_cold_start.rs` の `#[ignore]` テスト `mac2_vm_cold_start_trials_on_real_macos` である。実行手順は `AGENTS.md`「実機前提テスト」の `vm_cold_start` の項を参照する。

## 他の計測との違い

| 計測 | 対象 | 実 VM |
| ---- | ---- | ----- |
| 本ハーネス（`vm_cold_start`） | `Vm::launch` から ready マーカー観測まで | 起動する |
| `make bench-macos-cold-start`（`benches/tests/macos_cold_start.rs`・TASK-113.4・PLUG-6） | plugin 境界を挟むことによる上乗せ（模擬制御コア） | 起動しない |
| `vm_boot` の `elapsed_ms` | launch 後の待ち時間（100 ms 刻み） | 起動する（cold start ではない） |

plugin 経由（`fandhe-container-plugin-macos`）の cold start は本ハーネスの範囲外である。

## 計測区間（暫定）

MAC-2 は計測区間を定めていないため、次の区間を暫定とする。オーナー確認事項である（下の「確認事項」）。

| 項目 | 内容 |
| ---- | ---- |
| 始点 | `Vm::launch(&spec, timeouts)` を呼ぶ直前 |
| 終点 | ブートマーカーの後に ready マーカーが現れたことを、watcher がコンソールログから読み取った直後 |
| 区間に入る | `Vm::launch` の中身すべて（VZ 構成の構築・コンソールログの open・VM 生成・start 完了待ち）、ゲストのブートから ready の出力まで |
| 区間に入らない | spec の組み立てとパス検証、scratch の作成、watcher の起動、stop と停止確認 |
| 追加の時刻 | 試行ごとに `launch_returned`（launch が戻った時点）と `boot_marker`（ブートマーカー観測）も出す。別の区間定義を選んでも出力から導ける |

virtiofs 共有を渡さないため、mount 報告は終点にならない。

## 終点の分解能

`SerialConsoleSink` には `LogFile` しか無く、ゲスト出力を外から観測する公開の口が無い。そこで watcher スレッドが試行ごとの新しいログファイルを名目 1 ms 間隔で読み、ready を含むバイトを読んだ直後に時刻を取る。

- `end_window`: ready を観測した読み取りと直前の読み取りの時刻差。ready はこの幅の中でファイルへ書かれた、という上限の幅になる。実際の幅は sleep の粒度に依存する
- 含まれない遅れ: 書き出しスレッドが pipe からファイルへ書くまでの遅れ（ホスト側。計測していない）
- 100 ms 刻みの照会（`vm_boot`）より細かいが、イベント駆動ではない

## 試行・期限

試行ごとに新しい VM を起動し、`Stopped` を確かめてから次へ進む。環境変数（libtest は独自の引数を受けられないため）:

| 環境変数 | 意味 | 既定 | 範囲 |
| -------- | ---- | ---- | ---- |
| `FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIALS` | 試行回数 | 5 | 5〜50 |
| `FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIAL_TIMEOUT_SECS` | 1 試行の期限 | 60 | 1〜600 |
| `FANDHE_CONTAINER_MACOS_VM_COLD_START_TOTAL_TIMEOUT_SECS` | 全体の期限 | 900 | 1〜3600 |

ゲスト資産は `vm_boot` と同じ環境変数（`FANDHE_CONTAINER_MACOS_VM_KERNEL`・`_INITRD`・`_DISK_IMAGE`・`_CMDLINE`・`_BOOT_MARKER`・`_READY_MARKER`）で受ける。範囲外・非数・空は VM 起動前に panic で拒否する。

- 失敗した試行を除外しない。1 件でも失敗があれば最後に assert で非ゼロ終了する
- 全体の残りが 100 ms 未満になったら VM を起動せず、以降を `not_run` とする
- VM を得た試行は、結果にかかわらず stop と `Stopped` の確認を行う。停止を確認できなければ以降の試行は `not_run` とする（REPAIR-5）
- kernel / initrd はホストのページキャッシュに載るため、2 回目以降は読み込みが温まっている。試行を捨てず、全試行を出力する

## 出力

stdout に 1 行の JSON を出す（libtest 自身の行も混ざるため `grep '"schema":"fandhe-container.macos-vm-cold-start.v1"' | jq .` で取り出す）。単位は ms（小数点以下 3 桁）、計算は整数で行う。

- `summary`: 成功試行の `median`・`min`・`max`。偶数個の中央値は真ん中 2 つの平均。成功 0 件なら `null`
- `failures`: コード別の件数。語彙は `launch_failed`・`ready_timeout`・`guest_not_running`・`stop_failed`・`not_stopped`・`watcher_io`・`not_run`。`launch_failed` は `detail` に `PlatformError::code()`（`[a-z0-9._]` 以外は `unknown`）を持つ
- `label`: 本ハーネスが実際にやっていること（`Vm::launch` を直接呼ぶ・試行ごとに新しい VM）の固定値
- 載せないもの: マーカー・パス・cmdline・ホスト名・合否・目標値（2000 ms）

## 範囲外と後続候補

- 合否の判定と実測の記録: #381
- 共用 VM 方式（`docs/design/macos-shared-vm.md`・#1905、承認待ち #1906）の語彙（既定 / オプション、初回 / 暖まった状態）への `label` の対応づけと schema の版の扱い: 共用 VM の実装後に決める
- 終点の分解能を上げるための `console_log` のイベント駆動の観測フック: 製品コードの変更になるため別途判断する

## 確認事項（オーナー）

- 計測区間（特に「`Vm::launch` 全体を含める」「ready マーカーを終点にする」）は暫定である。確定は #381 の実測前に行う
