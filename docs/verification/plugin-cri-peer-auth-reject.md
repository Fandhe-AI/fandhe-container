# plugin-cri の別 UID 接続拒否の実機確認 手順書と結果記録（#2485）

plugin-cri のバイナリが、別 UID（root）の connector からの接続を peer credential 検証で切断することを、実機で `#[ignore]` 試験を実行して確かめる手順と、結果記録の雛形。対応する ID は PLUG-12・PLUG-1・TASK-114.5・REPAIR-12。関連 issue は [#2485](https://github.com/Fandhe-AI/fandhe-container/issues/2485)（本確認。人間担当）・#461・#2471（試験の追加）・#2484（監査行の `@audit.log` への配線）。

実行・結果の記録・成否の判定は人間が行う。Agent は root のコマンドを実行しない。本書のコマンドは作成時に未実行である。ホスト名・アドレス・ユーザー名・実 UID の値・`$HOME` の実パスは記録しない。対象は Linux のみ（試験は `cfg(target_os = "linux")`）。

## 背景

- 試験 `task114_5_plug12_rejects_other_uid_connection_to_cri_plugin`（`crates/plugin-cri/tests/integration.rs`）は、別 UID の connector が必要なため `#[ignore]` で既定集合から外してある（CI 通過のための弱体化ではない）
- 試験が照合する内容
  - connector は 10 秒以内に終了し、受信が 0 バイトである（認証前にデータを送らない）
  - stderr に `"event":"plugin_peer_auth"` の行があり、`"op":"accept"`・`"reason":"peer_uid_mismatch"`・`"code":"PERMISSION_DENIED"`・`"expected_uid":<実行 UID>`・`"socket_path":"<sock>"` を含み、`peer_uid` は実行 UID と異なる
  - 拒否の後も、同一 UID の接続で PodSandbox の一連の操作が成功する
- root の connector が要る理由: 非 root の別 UID は、0700 の配置ディレクトリで connect 前に遮断され、peer 検証まで届かない

## 実行するコミットの扱い

- 実行したコミットの SHA（`git rev-parse HEAD`）を必ず記録する
- #2484 の PR（#2585）のマージ前は、stderr の `plugin_peer_auth` 行の照合までになる。マージ後のコミットでは、`@audit.log` へ `"layer":"plugin_peer"` の行がちょうど 1 行永続化される照合（`plugin_peer_uid_mismatch`）も試験に含まれる
- マージ後のコミットでの実行を推奨する。マージ前に実行した場合は、その旨を記録して再実行の要否を判断する

## 事前確認（非 root・sudo 不要）

- Linux であること。`uname -r`・`python3 --version` を控える。`/usr/bin/python3` があること
- 既定集合の試験 A が通ること: `cargo test -p fandhe-container-plugin-cri --test integration`

## connector の準備

- 実行ユーザー所有の 0700 のディレクトリを `$HOME` 配下に作り、python3 版 connector を 0700 で置く。内容は [AGENTS.md](../../AGENTS.md)「実機前提テスト」の「UDS 境界の別 UID 接続拒否」項の python3 版（`sudo -n /usr/bin/python3 -I` で起動し `settimeout(15)`）を使う。`AGENTS.md` が正で、本書は転記しない
- connector は root で実行される。自分で作った信頼できるファイルだけを絶対パスで渡す。`/tmp` 直下など共有の場所には置かない
- `nc`（`nc.openbsd`）は使わない。AppArmor に制限されて 0700 のディレクトリを辿れず、PLUG-12 の検証結果ではなく Timeout で失敗する。AppArmor プロファイルを complain / disable にして回避しない

## 実行（同じ対話端末で行う）

```bash
sudo -v
FANDHE_CONTAINER_TEST_OTHER_UID_CONNECT_CMD=<connector の絶対パス> \
  cargo test -p fandhe-container-plugin-cri --test integration -- \
  --ignored task114_5_plug12_rejects_other_uid_connection_to_cri_plugin
sudo -k
```

- cargo は非 root で実行する。`sudo cargo test` は使わない（PATH・`CARGO_HOME`・`target/` の所有者がずれ、試験自身も `uid != 0` の検査で失敗する）
- connector は内部で `sudo -n` を使うため、実行直前に同じ端末で `sudo -v` を行う。終わったら `sudo -k` でチケットを破棄する

## 期待される結果

- 成功行 `test task114_5_plug12_rejects_other_uid_connection_to_cri_plugin ... ok` と `test result: ok. 1 passed`
- 試験は 60 秒の watchdog・connector の期限 10 秒・回収の猶予 5 秒で動き、ハングしない（REPAIR-5）

## 失敗時の切り分け

| 失敗の表示 | 原因と扱い |
| ---------- | ---------- |
| `FANDHE_CONTAINER_TEST_OTHER_UID_CONNECT_CMD must be set` | 環境変数が未設定。環境要因 |
| `connector path must be absolute` / `connector command must exist` / `must be a regular file` | パスの誤り。環境要因 |
| `this test must run as a non-root user` | sudo 経由で cargo を実行している。環境要因 |
| `connector did not exit after the connection was rejected` | sudo チケットが無い（`sudo -n` の失敗）か、`nc` を使って AppArmor に当たっている。環境要因を先に疑う |
| `server must not send anything before peer auth` | 受信が 0 バイトでない。PLUG-12 違反の疑い。修正 issue の対象 |
| `no peer auth line` / `missing ... in ...` | 監査行の欠落・形式の差。修正 issue の対象 |
| `peer_uid must differ from the expected uid` | connector が別 UID で動いていない。環境要因 |
| `persisted audit lines`（#2585 のマージ後） | `@audit.log` への配線の不具合。#2484 系の修正 issue の対象 |

失敗時に root の python3 が最大 15 秒残ることがある（試験が kill できるのは sh ラッパーまでで、python3 は自身の `settimeout` で終わる）。想定内でリークとして追わない。

## 判定

| 結果 | 扱い |
| ---- | ---- |
| 成功行あり | 結果を #2485 に記録し、人間が close する |
| 環境要因の失敗 | 準備を直して再実行する |
| 製品側の失敗（上の表で修正 issue の対象としたもの） | 原因を #2485 に記録し、修正 issue を起票する。本文に再現手順・実行コミット SHA・失敗メッセージ（伏せ字済み）・PLUG-12・TASK-114.5 を書く |

## 結果記録の雛形

| 項目 | 記録 |
| ---- | ---- |
| 実施日 | |
| 実行コミット SHA | |
| #2585 のマージ前か後か | |
| OS / ディストリ版 | |
| kernel 版（`uname -r`） | |
| python3 の版 | |
| 実行ユーザーが非 root であること | はい / いいえ（UID の値は書かない） |
| 成功行 | |
| `test result` 行 | |
| 失敗時のメッセージ | （`expected_uid`・`socket_path` 内のユーザー名とパスは伏せる。`peer_uid` が 0 であることと reason / code は残す） |
| 判定 | |
| 起票した修正 issue | |
