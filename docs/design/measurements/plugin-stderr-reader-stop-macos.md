# one-shot の stderr 読み手停止の macOS 繰り返し照合（#3003 の修正後）

Issue #3138（#3003・PR #3133 の追補）。ビヘイビア: REPAIR-5・PLUG-7・PLUG-12・REPAIR-12。

## 目的と対象

- 対象の試験: `crates/plugin/tests/lifecycle_one_shot.rs` の
  `unix::repair5_one_shot_stops_stderr_reader_when_grandchild_holds_stderr`
- #3133 は停止経路を `poll(2)` と停止用 pipe（書き込み端を閉じて `POLLHUP` で起こす）へ変え、
  止まらないときだけ最後の手段として `shutdown`（`last_resort`）を呼ぶ。修正の詳細はコードのコメントを参照する
- 未達だった受け入れ条件: 修正後に macOS で 100 回以上繰り返した記録と、原因の確定

## 手順（`workflow_dispatch`・1 回だけ）

PR ブランチを `--ref` にして dispatch する（main に向けない。concurrency group の衝突を避ける）。

```bash
gh workflow run ci.yml -R Fandhe-AI/fandhe-container --ref <ブランチ> \
  -f repeat-package=fandhe-container-plugin \
  -f repeat-test-bin=lifecycle_one_shot \
  -f repeat-libtest-name=unix::repair5_one_shot_stops_stderr_reader_when_grandchild_holds_stderr \
  -f repeat-features=test-support \
  -f repeat-os=macos-latest \
  -f repeat-count=<N>
```

- 回数 N は 100 以上、かつ「指定した試験の繰り返し」ステップの 30 分に収まる値にする
- macOS の leg の最終行 `passed=N failed=M count=C test_bin=lifecycle_one_shot` だけを証跡にする
  （ubuntu・windows の leg ではこのステップは飛ばされる）
- `last_resort` に落ちた回は `reader_stopped=false` で試験が失敗するため、`failed=0` なら全回が `POLLHUP` の経路で
  500ms 以上 4s 未満に止まったことになる。停止時間の分布は既存の assert では区別できない

## 結果

未実施（記入待ち）。作成時のエージェントは push が禁止されており、dispatch に必要な ref を用意できなかった。
push 後に次を記入する。

| 項目 | 値 |
| ---- | -- |
| run の URL | 未取得 |
| ref・headSha | 未取得 |
| #3231（`--exact` 絞り込み）を含むか | 未取得 |
| 最終行 | 未取得 |
| ステップの所要時間・1 回の平均 | 未取得 |

## 残余

- 失敗が出た場合は、診断ログ入りの使い捨てブランチ（マージしない）で停止経路と経過時間を実測してから修正する。
  試験は弱体化せず、`PLUGIN_STDERR_STOP_TIMEOUT`（1 秒）は変えない
- 停止が 1 秒付近に張り付く系統だった場合は、値の見直しを owner:human の issue に切り出す
- `shutdown` 競合説そのものは、再現が 0 件であれば実測では確定しない
