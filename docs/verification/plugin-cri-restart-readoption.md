# running のコンテナを残した plugin-cri の再起動と再採用の実機確認 手順書と結果記録（#2942）

supervisor 経由の本番の start で running にしたコンテナを残したまま plugin-cri だけを再起動し、新しい plugin プロセスが記録を再採用して、自分で spawn していない supervisor を通して Stop・Remove できることを実機で確かめる手順と、結果記録の雛形。対応する ID は CRI-1・CRI-2・CORE-1・SUP-5・REPAIR-4・REPAIR-5。関連 issue は [#2942](https://github.com/Fandhe-AI/fandhe-container/issues/2942)（本確認。人間担当）・#2902（設計。[cri-record-readoption.md](../design/cri-record-readoption.md)）・#2938（本番配線）・#2939（手動回収手順）・#2941（`pod_netns` の永続）・#2945（在庫の永続）。

実行・結果の記録・成否の判定は人間が行う。Agent は実行しない。本書のコマンドは作成時に未実行である。ホスト名・アドレス・ユーザー名・UID の値・`$HOME` の実パスは記録しない。sandbox・コンテナの ID は先頭 12 桁までを記録する。対象は Linux のみ（非 Linux の plugin-cri 本番は未実装）。

## 背景

- running のコンテナを残した再起動と再採用の gRPC 直叩きでの照合は、実機前提の自動試験 `production_binary_restart_readopts_running_container_real`（#3225。`platform-ci` の ubuntu）が担う。本確認（#2942）は crictl の経路と、実機での観測（`state.json`・プロセスの生死）に絞る
- 既定の集合の結合試験 `cri1_cri2_core1_records_survive_plugin_restart`（`crates/plugin-cri/tests/container_grpc.rs`、段 D）は root 不要・ネットワーク不要だが、コンテナは Created の状態でしか確かめていない
- 本確認は、running のコンテナを残した再起動のあとに、新しい plugin が自分で spawn していない supervisor を通して core の stop / delete を行えること（本確認の中心のリスク）を確かめる
- sandbox は保持役が再起動をまたがない設計のため、再起動後は `SANDBOX_NOTREADY` で見える（sandbox に core の記録は無い）

## 前提（非 root・sudo 不要）

- Linux 実機・非 root。`sudo` は使わない（root での実行は本書の対象外）
- `XDG_RUNTIME_DIR` が絶対パスで設定されていること。状態ルートは `$XDG_RUNTIME_DIR/fandhe-container`（以下 `<状態ルート>`）
- start は supervisor 経由の本番経路のため、`systemd --user` の委譲 cgroup scope（`systemd-run --user --scope -p Delegate=yes`）の中で plugin-cri を動かす。Landlock ABI・user manager の private ソケットなどの前提は [linux.md](../setup/linux.md) と `production_binary_full_lifecycle_real`（`crates/plugin-cri/tests/`）の doc に従う
- バイナリ: `cargo build -p fandhe-container-plugin-cri -p fandhe-container-supervisor --bins` の後、`fandhe-container-plugin-cri` と `fandhe-container-supervisor` だけを実行ユーザー所有の 0700 ディレクトリ（`<bin_dir>`）へ複製する。隣に `fandhe-container-launcher` を置かない（置くと rootful の特権ランチャー経路に入る。SUP-14）
- `crictl` は版・取得元・sha256 を記録する（[crictl-smoke.md](crictl-smoke.md) と同じ扱い）。レジストリの資格情報を含む設定で実行しない
- pull の前に `make docker-hub-ratelimit-probe` で匿名 pull の残量を確認する
- 作業用ディレクトリ（`<work>`。socket・stderr・fixture）は実行ユーザー所有の 0700 ディレクトリを `$HOME` 配下に作る。`/tmp` 直下など共有の場所は使わない

## fixture

pod は network を NODE（enum の数値 `2`）にする。core の start は pod の network namespace への join をまだ受けず（[crictl-smoke.md](crictl-smoke.md) と同じ）、pod network を使わないので再起動後の `tear_down`（#2941 で未完）の経路にも入らない。NODE はホストの network namespace を使い分離を弱める。この確認専用の設定で、本番の既定ではない。

`<work>/pod.json`:

```json
{
  "metadata": {
    "name": "readopt-pod",
    "namespace": "readopt",
    "uid": "readopt-uid-0001",
    "attempt": 0
  },
  "linux": {
    "security_context": {
      "namespace_options": { "network": 2 }
    }
  }
}
```

`<work>/container.json`（`sleep 3600` は再起動・確認の間に終了しない長さ。`scripts/testdata/cri/container.json` は `sleep 30` のため流用しない）:

```json
{
  "metadata": { "name": "readopt-ctr", "attempt": 0 },
  "image": { "image": "docker.io/library/busybox:1.36" },
  "command": ["/bin/sh", "-c", "sleep 3600"]
}
```

以降 `crictl` は `-r unix://<work>/<sock> -i unix://<work>/<sock>` を付けて実行する（`<sock>` は段ごとの socket）。各段の plugin の stderr は別ファイルへ保存する。

## 手順

### 1. 1 回目の起動

```bash
systemd-run --user --scope -p Delegate=yes \
  "<bin_dir>/fandhe-container-plugin-cri" --socket "<work>/s1.sock" 2> "<work>/plugin-1.stderr" &
```

- plugin 本体の pid を控える。`$!` が `systemd-run` の pid でなく plugin 本体の pid であることを `ps` で確認する（違えば `pgrep -f fandhe-container-plugin-cri` で本体を特定する）
- `crictl pull docker.io/library/busybox:1.36` -> `crictl runp pod.json` -> `crictl create <sb> container.json pod.json` -> `crictl start <cid>`
- `crictl ps -a`・`crictl inspect <cid>`・`crictl inspectp <sb>` を保存する（再起動後の `image_ref`・`image_id`・metadata との比較用）
- `plugin-1.stderr` に要約行（`cri record readoption`）が出ないこと

### 2. 再起動前の観測（core の状態）

- `<状態ルート>/<cid>/state.json` の status が running であること（直接読む。status と pid の有無だけを記録し、annotations 等は転記しない）
- supervisor とコンテナのプロセスが生きていること（`ps`・`pgrep`）
- `<状態ルート>/.cri/records/sandboxes/<sb>.rec`・`<状態ルート>/.cri/records/containers/<cid>.rec`・`<状態ルート>/.cri/bundles/<cid>` が在ること

### 3. plugin-cri だけを SIGKILL

```bash
kill -KILL "<plugin の pid>"
```

- SIGTERM の正常停止は #3226 で実装済み。クラッシュ経路の確認には SIGKILL を使う（SIGTERM では実行中の RPC を待って終わる）。scope 単位の停止（`systemctl --user stop` 等）は使わない（操作を plugin プロセスに限定するため）
- kill 後も supervisor とコンテナのプロセスが生きていること、`state.json` が running のままであることを記録する（SUP-5・CORE-1）

### 4. 2 回目の起動（壊れた記録なし）

別の socket パス `<work>/s2.sock` で起動し、stderr を `plugin-2.stderr` へ保存する（旧 socket と `.lock` は SIGKILL で残るため。同じパスで起動したい場合の `ALREADY_EXISTS` と手動回収は [plugin-socket-recovery.md](../setup/plugin-socket-recovery.md)）。

`plugin-2.stderr` の要約行は次の 4 段を ` | ` でつないだ 1 行。各段の先頭は次のとおりで、以降の項目（`not_regular_file` 以降、`scanned` 以降など）は実測値を記入する。

- `cri record readoption: kind=sandbox adopted=1 pending_unresolved=0 broken=0 malformed=0`
- `cri record readoption: kind=container adopted=1 present=1 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=0 malformed=0`
- `cri stale create release: released=0 kept=0 release_failed=0 record_remove_failed=0 not_attempted=0 skipped=0`
- `cri orphan bundle reclamation: scan=completed` に続く `scanned`・`reclaimed=0`・`kept_has_record=1` など

要約行に sandbox・コンテナの ID やパスが含まれないこと（`grep -F "<sb の全桁>"`・`grep -F "<cid の全桁>"` が 0 件。REPAIR-4）。

RPC の期待:

- `crictl pods`・`crictl inspectp <sb>` は `SANDBOX_NOTREADY`
- `crictl ps -a`（ListContainers）・`crictl inspect <cid>`（ContainerStatus）は `CONTAINER_RUNNING`。`image_ref`・`image_id`・metadata が 1 回目の `inspect` と一致する
- 任意: `crictl start <cid>` は親 sandbox が NotReady のため `FAILED_PRECONDITION` で拒否される
- 期待どおりの差分: `crictl images` は空になる（在庫がプロセス内の `InMemoryImageStore` のため。#2945）。不具合として扱わない

### 5. 壊れた記録の注入と 3 回目の起動

plugin を SIGKILL したあと、操作者自身が壊れた記録を 1 件作る（既存を上書きしない）。

```bash
( set -o noclobber
  f="<状態ルート>/.cri/records/containers/$(printf '%064x' 0xdead).rec"
  umask 077
  printf 'garbage' > "$f" )
```

`<work>/s3.sock` で起動し `plugin-3.stderr` へ保存する。

- 起動は止まらず、container 段が `adopted=1 present=1 ... broken=1 malformed=1` になる
- running のコンテナは引き続き `CONTAINER_RUNNING` で見える
- 壊れた記録のファイルは消されずに残る（`ls -l` で確認）
- 参考（任意）: 件数上限を超えると `error: FAILED_PRECONDITION: failed to readopt cri records` で起動しない（既定集合の `cri2_record_limit_exceeded_stops_startup` で確認済み。実施しなくてよい）

### 6. 再採用後の後始末の RPC

kubelet の順で実行し、それぞれ core の状態と対応づけて記録する。

1. `crictl stop <cid>` -> `CONTAINER_EXITED`、`state.json` が stopped、supervisor が終了
2. `crictl rm <cid>` -> `.cri/records/containers/<cid>.rec`・`.cri/bundles/<cid>`・`<状態ルート>/<cid>/` が消える
3. `crictl stopp <sb>` -> 成功
4. `crictl rmp <sb>` -> `.cri/records/sandboxes/<sb>.rec` が消える

壊れた記録は残る。

### 7. 4 回目の起動（任意）

壊れた記録だけが残る状態で `<work>/s4.sock` を起動し、container 段が `adopted=0 present=0 ... broken=1 malformed=1` で起動が止まらないことを確認する。最後に plugin を SIGKILL し、手順 5 で自分が作った壊れた記録ファイルだけを `rm` する（他の記録・bundle・socket は消さない）。照合できない記録の一般的な手動回収は #2939。

## 失敗時の切り分け

| 事象 | 扱い |
| ---- | ---- |
| `systemd-run` の失敗・委譲 cgroup が無い・Landlock / user manager の前提エラー・pull の 429 | 環境要因。前提を直して再実行 |
| launcher が隣にある構成の rootful 経路のエラー | 環境要因（配置を直す） |
| 同じ socket パスでの `ALREADY_EXISTS` | 想定内。別パスで続行 |
| 2 回目の起動が `error: <CODE>: failed to readopt cri records` で止まる | 製品側。修正 issue の対象 |
| 再起動後に sandbox が READY、コンテナが見えない、`CONTAINER_UNKNOWN` になる | 製品側（core の状態の照会の失敗を含む）。修正 issue の対象 |
| 再起動後の StopContainer / RemoveContainer が失敗・ハングする | 製品側。CRI-1・CRI-2・SUP-5 を付けて修正 issue の対象 |
| 壊れた記録で起動が止まる、壊れた記録が消される、要約行に ID / パスが出る | 製品側（CRI-2・REPAIR-4） |
| 再起動前に supervisor・コンテナが plugin と一緒に終了した | 起動構成（scope ごと停止していないか）を先に確認。正しければ製品側（SUP-5・CORE-1） |

## 判定

| 結果 | 扱い |
| ---- | ---- |
| すべて期待どおり | 結果を #2942 に記録し、人間が close する |
| 環境要因の失敗 | 準備を直して再実行する |
| 製品側の失敗 | 原因を #2942 に記録し、修正 issue を起票する。本文に再現手順・実行コミット SHA・失敗メッセージ（伏せ字済み）・CRI-1・CRI-2 を書く |

## 結果記録の雛形

| 項目 | 記録 |
| ---- | ---- |
| 実施日 | (記入) |
| 実行コミット SHA | (記入) |
| OS / ディストリの版・`uname -r` | (記入) |
| crictl の版・取得元・sha256 | (記入) |
| systemd の版・Landlock ABI | (記入) |
| 非 root で実行したこと | (記入) |

要約行（`plugin-N.stderr`）:

| 段 | 要約行の抜粋 |
| -- | ------------ |
| 1 回目（出ないこと） | (記入) |
| 2 回目 | (記入) |
| 3 回目（broken=1 malformed=1） | (記入) |
| 4 回目（任意） | (記入) |

RPC と core の状態の対応:

| 操作 | CRI の結果（state / code） | `state.json` の status | supervisor の生死 | 記録ファイル | bundle・`<状態ルート>/<id>/` |
| ---- | -------------------------- | ---------------------- | ----------------- | ------------ | ---------------------------- |
| 再起動前 inspect | (記入) | (記入) | (記入) | (記入) | (記入) |
| kill 直後 | - | (記入) | (記入) | (記入) | (記入) |
| ListPodSandbox / PodSandboxStatus | (記入) | - | - | - | - |
| ListContainers | (記入) | - | - | - | - |
| ContainerStatus（image_ref・image_id の一致） | (記入) | (記入) | (記入) | - | - |
| StartContainer（任意） | (記入) | - | - | - | - |
| StopContainer | (記入) | (記入) | (記入) | (記入) | (記入) |
| RemoveContainer | (記入) | (記入) | (記入) | (記入) | (記入) |
| StopPodSandbox | (記入) | - | - | - | - |
| RemovePodSandbox | (記入) | - | - | (記入) | - |

壊れた記録:

| 項目 | 記録 |
| ---- | ---- |
| 起動の成否 | (記入) |
| container 段の `broken`・`malformed` | (記入) |
| 壊れた記録のファイルが残ったか | (記入) |
| 要約行に ID / パスが無いこと | (記入) |

| 項目 | 記録 |
| ---- | ---- |
| 判定 | (記入) |
| 起票した修正 issue | (記入) |
