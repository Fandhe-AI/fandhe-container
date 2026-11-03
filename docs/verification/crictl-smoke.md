# crictl 疎通確認の手順書と結果記録（TASK-60・CRI-1・MS-4）

実物の `crictl` で `runp` -> `create` -> `start` が通ること（CRI-1。`RunPodSandbox` -> `CreateContainer` -> `StartContainer`）を実機で確かめる手順と、結果レポートの雛形。実機での実行と判定は人間担当の TASK-60.h1（[#442](https://github.com/Fandhe-AI/fandhe-container/issues/442)）で、Agent は実行しない。自動化の本体は `scripts/cri/crictl-smoke.sh`（Agent 担当の [#441](https://github.com/Fandhe-AI/fandhe-container/issues/441)）。

## 前提

- Linux 実機。`sudo` はスクリプトが呼ばない。root で実行するかどうかは操作者が決める
- `crictl` は版を固定し、取得元と sha256 を下の結果レポートに記録する。導入は人間が行う
- CRI サーバーが UDS（`unix:///<絶対パス>`）で待ち受けていること。plugin-cri のバイナリ（`fandhe-container-plugin-cri --socket <PATH>`。TASK-114）は同じ UDS で `RuntimeService` と `ImageService` をサーブする（#2592）。`crictl pull` が登録したタグを `crictl create` が同じプロセス内の在庫から image ID へ解決する。在庫はプロセス内だけで、バイナリを再起動するとタグの対応は失われる（もう一度 `crictl pull` する。キャッシュ済みの blob は再取得されない）。start は supervisor 経由の本番経路のため、`systemd --user` の委譲 cgroup scope の中で動かす（前提は `docs/setup/linux.md`）
- レジストリの資格情報を含む設定で実行しない（crictl の stderr をそのままログへ転記するため）。実機のホスト名・アドレスは記録しない

## pod.json のネットワーク名前空間

`scripts/testdata/cri/pod.json` は `linux.security_context.namespace_options.network` を NODE（enum の数値 `2`）にしている。既定の POD だと RunPodSandbox が pod 用の network namespace を要求するが、core の start はまだ network namespace の join を受けず拒否するため、start（手順 `start`）で止まる（`crates/cri/src/bundle/spec.rs`。#2675・#2592）。NODE は **ホストの network namespace** でコンテナを動かす指定で、分離を弱める。この smoke 専用の fixture であり、本番の既定ではない。利用者が明示したときだけ使う。pid / ipc を NODE にすると今も拒否される。crictl が enum を数値で読むかは実機で確かめる（自己テストはスタブの crictl のため検出できない）。

## イメージの扱い

`crictl create` が既定でイメージを pull するか（`--no-pull`・`--with-pull`・`pull-image-on-create`）は crictl の版で異なりうる。実機で確かめて下の欄に記録する（記憶で断定しない）。既定の運用は、事前に `crictl pull <image>` を実行してから本スクリプトを実行する。既定の fixture（`scripts/testdata/cri/container.json`）のイメージは `docker.io/library/alpine:3.20`。

## 実行

```bash
# 事前: イメージを pull する
crictl --runtime-endpoint unix:///run/example/cri.sock --image-endpoint unix:///run/example/cri.sock pull docker.io/library/alpine:3.20

# 本体（値はダミー。CRI_ENDPOINT は実機の UDS の絶対パスに置き換える）
make crictl-smoke CRI_ENDPOINT=unix:///run/example/cri.sock LOG_DIR=/var/tmp/crictl-smoke-001
```

任意の変数: `CRICTL`・`POD_CONFIG`・`CONTAINER_CONFIG`・`STEP_TIMEOUT`（各手順の期限。既定 60 秒）・`CRICTL_TIMEOUT`（crictl の `--timeout`。既定 10s）・`KEEP=1`（後始末をしない）・`CRICTL_SMOKE_TIMEOUT`（全体の期限）。

## 結果の読み方

- `<LOG_DIR>/summary.txt`: 手順ごとに `step=<name> status=<ok|failed|timeout|invalid-id|skipped> exit=<n> duration_ms=<n>`。手順は version（到達確認）-> runp -> create -> start -> 後始末（`cleanup-*`）の順
- `<LOG_DIR>/<NN>-<step>.{argv,stdout,stderr}`: 各 crictl 呼び出しの引数（1 行 1 引数）・標準出力・標準エラー
- 最終行 `result=ok` または `result=failed failed_step=<name>`。失敗時は stderr に `error: code=step-failed ...` と失敗手順の stderr の末尾が出る
- 終了コード: 0 = 3 手順とも成功、1 = いずれかの手順が失敗（期限切れ・ID 不正を含む）、2 = 引数・出力先の誤り、3 = 前提欠如（crictl・timeout・ソケット・Version RPC が応答しない）、4 = 後始末の失敗（残存の可能性。手で確認する）
- サンドボックスの metadata（name・namespace・uid・attempt）は重複作成が拒否される（#2293）。後始末に失敗すると再実行が runp で失敗するため、先に残存を片付ける

## 結果レポートの雛形

| 項目 | 記入 |
| ---- | ---- |
| 実施日 | (記入) |
| 実施者 | (記入) |
| crictl の版・取得元・sha256 | (記入) |
| カーネルの版 | (記入) |
| fandhe-container の commit | (記入) |
| `crictl create` の pull の既定 | (記入) |
| version | status / exit |
| runp | status / exit |
| create | status / exit |
| start | status / exit |
| 後始末 | status / exit |
| 判定（CRI-1 を満たす / 満たさない） | (記入) |
| 失敗時の stderr の抜粋 | (記入) |
