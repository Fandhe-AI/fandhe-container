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
| 壁時計時間 | `docker run --rm` 全体（method `docker-run-rm-total`。時刻源は下記「時刻源」） | 中央値。各試行の生の値を `samples` に残す |
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

## 時刻源（壁時計。#3104・MAC-3・REPAIR-5）

決定: 各試行の壁時計は、perl の `Time::HiRes` を使う 1 プロセスのラッパーで測る。bash の版に関係なく時刻源は 1 経路で、
bash 5 の `EPOCHREALTIME` は使わない。前提ツールは bash 3.2 以上（macOS 標準の `/bin/bash` で動く）・perl（`Time::HiRes`）・jq。

- ラッパーは 1 回の perl 起動の中で、時刻ファイルを開く → t0（`gettimeofday` のマイクロ秒）→ `fork` → `exec`（シェルを介さない）
  → `waitpid` → t1 → `<t0_us> <t1_us>` を書く、の順に動く。perl の起動は t0 の前、終了処理は t1 の後に起きるため、
  起動・終了の遅れは区間に入らない。区間は docker CLI の fork から終了までで、従来の `EPOCHREALTIME` の区間と同等かそれより狭い
- 時刻の意味は従来と同じ壁時計（`gettimeofday`）のため、`metrics.wall_clock_median_ms.method` は `docker-run-rm-total` のまま、
  schema `fandhe-container.mac-small-files/v1` も変えない
- 時刻ファイルは非信頼の入力として読む。正規ファイル（symlink 不可）・64 バイトまで・数字 2 つちょうど・各 18 桁以内・t1 が t0 以上。
  不正なら試行を失敗に数え、有効な試行が 5 回未満なら全体を失敗にする（fail-closed）
- 期限（REPAIR-5）: ラッパーと docker CLI は `run_limited` の同じプロセスグループに入り、期限切れでは両方に TERM から KILL が届く。
  時刻源の確認（`perl -MTime::HiRes -e 1`）も `run_limited` で包み、docker を呼ぶ前に終了コード 3（`code=missing-tool`）で止まる
  （Debian 系では `Time::HiRes` が perl-base に無いことがあるため、perl の存在でなく実際の読み込みで確かめる）

不採用の案:

- python3: macOS 12.3 以降の `/usr/bin/python3` は Command Line Tools の導入を促す shim で、標準で使えるとは限らない
- BSD `date`: `%N`（ナノ秒）に対応していない
- bash 5 を必須のまま導入手順を書く案: 実測者の環境（Homebrew 等）を変える必要があり、本件の目的に反する

一次情報と観測:

- Apple の macOS Catalina 10.15 Release Notes は、Python・Ruby・Perl などのスクリプト言語ランタイムを互換のために同梱し、
  将来は既定で含めないとしている。macOS Monterey 12.3 Release Notes は Python 2.7 の削除を記載している。
  perl の同梱が将来も続くかは Apple の保証の範囲外で、外れた場合は本節の決定を見直す（その場合は終了コード 3 で止まり、誤った値は出さない）
- `Time::HiRes` は perl の core module（perldoc Time::HiRes）
- 観測値: Linux のローカルでは perl v5.40.1・Time::HiRes 1.9777。macOS の Homebrew 版は perl v5.44.0・Time::HiRes 1.978
  （platform-ci macos-latest・run 40758633132）。macOS の `/usr/bin/perl` の版は未観測
  （自己テストは macOS で `/usr/bin/perl` の回を必ず回す〔#3354〕。platform-ci の macOS のログの `perl-variant=system perl=... hires=...` 行を
  確認してここへ反映する。実機の版は #381・#354〔人間担当〕で記入する）

## 計測衛生

- 他のランタイムの VM（Docker Desktop 以外・Colima 等）は計測中に停止する（PoC-11）
- Docker Desktop の版を `docker version` で記録し、ファイル共有の実装が VirtioFS であることを Settings → General の
  「file sharing implementation」で人間が確かめる（スクリプトでは判定しない）
- `--host-dir` は symlink を含まない実体のパスにする（macOS の `/tmp` は `/private/tmp` の symlink のため、実体で渡す）

## 実行

実行コマンド・出力の読み方は `AGENTS.md`「実機前提テスト」の MAC-3 の行を参照。自己テストは `make mac-small-files-selftest`
（スタブの docker のみ。CI の `bench-regression` の並列グループ。platform-ci の macOS〔main への push と workflow_dispatch〕では
`/bin/bash` 3.2 と `/usr/bin/perl` でも回す。#3354）。
