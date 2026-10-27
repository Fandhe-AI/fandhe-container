# MAC-3 小ファイル多数ワークロードの計測定義

TASK-70 準備（#1880・MAC-3・MS-5）。macOS で小ファイルを多数扱うワークロードを、Docker Desktop（VirtioFS）を基準に
比べるための計測定義と手順をまとめる。実測と合否判定は人間（TASK-70・#381・#354）。本書のスクリプトは合否を出さない。

## 目的と判定基準（spec）

- MAC-3（Should・確定。根拠 PoC-5）: Docker Desktop（VirtioFS）を基準に、次のどちらかを満たすこと
  - 壁時計時間を 15% 以上短縮する
  - メタデータ操作の p95 レイテンシを 20% 以上低減する
- 閾値の判定は #381 で人間が行う。`mac_small_files.sh` の report は短縮率・低減率（`1 - own/baseline`）を出すだけで合否は出さない

## ワークロード定義

出典: spec の PoC-1・PoC-11（`03-poc/docker-bottleneck-baseline/scripts/microbench.py`、`03-poc/container-landscape-2026/scripts/runtime_bench.py`）。

| 項目 | 既定値 | 備考 |
| ---- | ------ | ---- |
| イメージ | `alpine:3.20` | 事前に手動 pull。計測中は `--pull never` |
| ファイル数 N | 2000（`--count` で 2000〜50000） | |
| 内容 | `x\n`（2 バイト） | 下記「spec の食い違い」を参照 |
| 操作の列 | `mkdir` → N 個の作成（busybox ash の組み込み `echo x > f_$i`。fork を排除） → `ls \| wc -l` で件数確認 → `rm -rf` | 件数が N と違えば試行は失敗 |
| 試行数 | 5（`--trials` は 5〜20） | 有効な試行が 5 回未満なら失敗 |
| 壁時計時間 | `docker run --rm` 全体（method `docker-run-rm-total`） | 中央値。各試行の生の値を `samples` に残す |
| メタデータ p95 | **暫定**（method `batch-boundary-provisional`） | 下記「オーナー確認待ち」 |
| マウント | bind mount（`-v <host-dir>:/data`）のみ | VM 越境を測るため。最初に書き戻りを確認する（PoC-11 の `verify_bind` 相当） |

ワークロードの生成は `workload_script`（両側共通）に隔離し、ランタイム固有の呼び出し（イメージ確認・起動・一覧・削除）は
スクリプト内の「バックエンド差し替え点」の関数群に隔離している。自前側は CLI の差分が出たらこの関数群だけを差し替える。

## オーナー確認待ち

- メタデータ操作の p95 の取り方は spec（MAC-3・PoC-5 手順 4）に「p95 を測る」とあるだけで、方法が決まっていない。
  暫定として、作成ループを K（既定 20）個ずつの区間に区切り、区間境界でだけ時刻を 1 回読む（既定イメージ alpine の BusyBox `date` は `%N` 非対応のため、`/proc/uptime` の 10ms 刻みの値を ns へ換算する。分解能が粗いので区間が短いと 0 や 10ms 単位の値になる。区間 K を大きくするかは実機の結果で決める）。
  区間ごとの「1 操作あたりの平均 ns」を全試行で集めた p95 を `metadata_p95_us` とする（per-op の p95 ではなく区間平均の p95）。
  fork は区間の数だけで、fork 排除の趣旨（PoC-1）と両立させている。確定したら method 名から `provisional` を外す
- alpine の busybox `date` は `%N` 非対応のため使わない。時刻が数値でない・非単調な場合は試行を失敗扱いにする（fail-closed）。
  `/proc/uptime` の分解能（10ms）で p95 が意味を持つかは実機でしか確かめられない。足りなければ人間がオーナーへ報告し、取り方を決め直す

## spec の食い違い（spec 側への報告事項）

PoC-11 の本文は「4KB ファイル 2000 個」と書くが、実測したスクリプトの実体は `echo x`（2 バイト）である。本書は実測済みの
スクリプト側（2 バイト）に合わせ、spec を勝手に 4KB へ直さない。

## 自前側の計測（未実装）

`--mode own` は未実装で、終了コード 5 と `code=unimplemented` で拒否する（REPAIR-3: 実装済みを装わない）。測れるようになる条件は次の後続実装:

- #2232: plugin 実バックエンド配線（`plugin-backend-wiring.md`・TASK-115）の承認と W1〜W13 の起票・実装
- #1906: TASK-191.h1。macOS 既定方式（常駐 VM 共用）の設計の承認。MAC-3 は既定方式の共有ルート配下の bind mount の上で測る想定
  （`macos-shared-vm.md` の項目 5）。共有ルートの構成は #1906 の承認後に本書の手順へ足す（承認前は確定扱いにしない）

## 計測衛生

- 他のランタイムの VM（Docker Desktop 以外・Colima 等）は計測中に停止する（PoC-11）
- Docker Desktop の版を `docker version` で記録し、ファイル共有の実装が VirtioFS であることを Settings → General の
  「file sharing implementation」で人間が確かめる（スクリプトでは判定しない）
- `--host-dir` は symlink を含まない実体のパスにする（macOS の `/tmp` は `/private/tmp` の symlink のため、実体で渡す）

## 実行

実行コマンド・出力の読み方は `AGENTS.md`「実機前提テスト」の MAC-3 の行を参照。自己テストは `make mac-small-files-selftest`
（スタブの docker のみ。CI の `bench-regression` の並列グループ）。
