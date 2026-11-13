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

- report の壁時計の暫定対応表（#3106）: own の `cli-create-start-wait-delete-total` と docker の `docker-run-rm-total` の 1 組だけを
  同等扱いにして率を出し、`wall_clock_method_match` に `provisional-pair` を記す（区間の定義は異なる: own は CLI 4 段の和、docker は run 全体）。
  表以外の組は従来どおり `null` と `methods_differ`。この対応を確定扱いにするかはオーナー確認待ち

## spec の食い違い（spec 側への報告事項）

PoC-11 の本文は「4KB ファイル 2000 個」と書くが、実測したスクリプトの実体は `echo x`（2 バイト）である。本書は実測済みの
スクリプト側（2 バイト）に合わせ、spec を勝手に 4KB へ直さない。

## 自前側の計測（#3106・MAC-3）

`--mode own`（`make mac-small-files-own`）は、自前 CLI の契約（CLI-1 の 3 OS 同一構文）で docker 側と同じワークロードを測る。
`workload_script`・ファイル数・内容 2 バイト・試行数・バッチを共用し、出力は同じ schema（`target=own`・`mode=own`）。

**実機の現状（REPAIR-3）**: macOS の実経路（#4705 cli の置き換え・#2280 共有ルートの構成と bind ソース検証・#2281 plugin-macos の
保持役の中継・#2275・#2278）は未実装。それが入るまで、実機の最初の probe（create / start）は構造化エラー
（`UNIMPLEMENTED` / `FAILED_PRECONDITION`）を返し、`error: code=measurement-failed ... (cli code=<CODE>)` と終了コード 1 で止まる。
値が出るのは後続実装の後で、実測と合否は #381（人間）。

起動契約（1 試行）: `create --bundle <bundle> --label fandhe.mac-small-files.run=<tag> <id>` → `start <id>` →
`state <id>`（`stopped` まで 0.1 秒間隔で繰り返す）→ `logs --stream stdout <id>` → `inspect <id>`（`status=stopped` かつ `exitCode=0`）→
`delete <id>`。ID は `fms-<16 桁 16 進の tag>-<n>`。`--root` は付けない（macOS の状態はゲスト側にあり、#1906 項目 3 と
Issue #2431 が未了のため専用ルートが効く前提を置かない）。他のコンテナには触れず、記録した自分の ID だけを後始末で `state`（NOT_FOUND を確認）→
必要なら `kill KILL` → `delete` → `state` の順に片づける。確認できない ID があれば終了コード 4。回収対象に記録するのは create が成功した ID だけで、create が失敗（`ALREADY_EXISTS` を含む）した ID には kill・delete・state を送らない（所有を証明できないため）。create の期限切れ（成否不明）は警告で手動確認を促す。

区間（method `cli-create-start-wait-delete-total`）: `(create の開始から stopped を返した state の終了まで) + (delete の開始から終了まで)`。
logs・inspect の時間は含めない。偏りの向きは own に不利: CLI のプロセス起動を呼び出し回数ぶん払い、state のポーリング間隔（0.1 秒）が
待ちに入る。`samples` に `create_us`・`start_us`・`wait_us`・`state_polls`・`delete_us` を残す。

共有ルート構成（#1906 項目 2 の A 案）: VM 生成時に構成した共有ルート（既定はホームディレクトリ配下の作業用ルート 1 件）を virtiofs で共有し、
ゲスト内でサブツリーを bind する。本スクリプトは VM の構成を変えず、操作者が申告した `--shared-root` の配下に `--host-dir`（試行ごとの bind 元）と
`--bundle` があること、両者が互いに祖先・子孫でないこと、symlink を含まないことだけを副作用の前に確かめる（違反は終了コード 2）。共有ルートの
実際の構成手段は #2280 の実装後に追記する。bind は `/data`（`rbind,rw`）、bundle の rootfs は `root.readonly=true`。

bundle の作り方: `--bundle` は `rootfs/` を含み `config.json` を含まない実体ディレクトリ（`config.json` は試行ごとに jq で書き、終了時に消す。
既にあれば拒否する）。rootfs は docker 側と同じイメージから作る: `docker image inspect --format '{{.Id}}' <image>` で ID を取り、その ID で
`docker create` → `docker export` → `<bundle>/rootfs` へ展開する。その ID を `--image-id`（`IMAGE_ID`）で申告する。

残余: `image_id` は申告値で、rootfs が本当にそのイメージかは検証しない（結果に `image_id_source: "declared"`）。macOS ホストでローカルの
ImageStore を開く経路は作らない（#1906 項目 3）。ログの回転（既定 1 MiB × 3 世代）で `TS` 行が欠けた試行は件数の照合で失敗になる
（count 50000・batch 1 の最悪でも約 1.5 MB で 3 世代に収まる見込み）。自前 CLI に版の表示は無く `backend_version` は `unknown`。

logs の取得: `state` が stopped でも supervisor の最終 flush は終わっていない（`Stopped` の記録が先。crates/cli の list_logs の契約）ため、計測区間の外で `logs --follow --stream stdout` を使い、書き手の終了まで待って出し切る（期限は試行の残り時間）。非追従の取得は末尾の `TS`・`FILES_CREATED`・`DONE` を落とし得る。

不採用の案: 区間内で `logs --follow` の終了を待つ案（追従のポーリング 200 ms が区間に入るため。logs は区間外なので取得には使う）、専用の `--root` を使う案（上記）。

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
（スタブの docker と自前 CLI のみ。CI の `bench-regression` の並列グループ。platform-ci の macOS〔main への push と workflow_dispatch〕では
`/bin/bash` 3.2 と `/usr/bin/perl` でも回す。#3354）。
