# CLI 基本 6 コマンド（と inspect・stop --signal・create --cap-drop）の 3 OS 同一構文・挙動 確認記録（雛形）

TASK-125（共同タスク）の確認記録の雛形。実機での実行・結果の記入・CLI-1 の合否判定は #661（TASK-125.h1・人間担当）が行う。本ファイルと `scripts/cli-parity-check.sh` は Agent 担当分（TASK-125.1・#660）の準備物で、結果欄に Agent が実測値を埋めてはならない。

- 対応: TASK-125・CLI-1・MS-6（Phase 12）
- 関連: ERR-2（終了コード表）・PLUG-4・PLUG-11・REPAIR-3（未実装を実装済みと装わない）
- 親: #659 / Agent 担当: #660 / 実機確認（人間）: #661

## 現状の制約（必読）

| 項目 | 内容 |
| ---- | ---- |
| 非 Linux の plugin 起動・RPC | 発見 → 登録 → 信頼性検証までは配線済みだが、plugin の起動と RPC は未実装（TASK-114）。macOS / Windows ではバックエンド解決が必ず失敗する。よって B 層（挙動）の非 Linux 欄は **前提未達** であり、合格として記入しない |
| Linux 経路の未実装 | `start` の本番 launcher、cgroup 配置つき `delete` は未実装（REPAIR-3）。pid ありの `stop` は Linux では supervisor の制御チャネル経由で結線済み（#2059。supervisor に届かなければ `UNAVAILABLE`（9））。Linux 側の現行値（`start` = 8 など）は「現行実装での参考値」で、launcher 提供後に変わる。固定の合格基準にしない |
| イメージ管理の現状（C 層） | コンテナ参照（#2341・#2352）と manifest の在庫・タグ・リース（#2380）は永続化済みで、在庫は plugin-cri の `PullImage`（cri の `OciImagePuller::pull`）が登録する。plugin-cri のキャッシュは「plugin-cri が解決する既定の状態ルート（`StateRoot::resolve(None)`）の `.cri/images`」（#2539・#2800・#2592）。CLI に `pull` サブコマンドは無い（`docs/design/pull-inventory-wiring.md`）。同じ root を `--image-root` に渡せば、pull 済みの在庫に対して `image ls`・`image rm`・`image tag`・`create --image-root <dir> --image <digest または name[:tag]>`（タグ参照は永続化済みの在庫から解決。#2496）が成功する。未 pull の root（空のストア）では従来どおり `image ls` は 0 件（ヘッダのみ）・`image rm` と `image tag` と `create --image` は `NOT_FOUND`（3）で、`system df` の images 側は 0 件。`--image-root` は必須で既定位置は未決（#2221）。非 Linux はイメージキャッシュの置き場が未決のため他コマンドと同じ plugin 解決の失敗（5 など）で fail-closed。`scripts/cli-parity-check.sh` は C 層を自動収集しないため、手動で実行して記録する。pull 済み root の手順は C 層の節の「pull 済みの root の用意」 |
| Windows の自動化 | `scripts/cli-parity-check.sh` は Git Bash で実行する。スタブ CLI による自己テストは CI の 3 OS（ubuntu・macos・windows）で実行しているが、製品バイナリ（ネイティブ exe）に対する capture は CI で確かめていない（実機確認の範囲）。タイムアウト時の子孫回収だけはヘルパー exe で CI 実測する（#1548） |

期待値の正は「Linux ネイティブ実行と同一」。Linux の capture を基準にして他 OS を突き合わせる。

## 確認手順

1. 各 OS でリポジトリをチェックアウトし、`cargo build -p fandhe-container-cli` でビルドする（実行ファイルは `target/debug/fandhe-container`）
2. 各 OS で capture を取る（出力は新規ファイルのみ。CLI は絶対パスで指定する）

   ```bash
   make cli-parity CLI=<絶対パス>/target/debug/fandhe-container OUTPUT=<新規ファイル>
   ```

3. Linux の capture を基準に、他 OS の capture を突き合わせる

   ```bash
   make cli-parity BASELINE=<linux の capture> CANDIDATE=<他 OS の capture>
   ```

   終了コード 0 = 全ケース一致 / 1 = 不一致・欠落・タイムアウト / 2 = 引数・入力エラー / 3 = 前提欠如。1 は機械照合の事実報告で、合否は人間が判定する。`BASELINE` は Linux で取った capture、`CANDIDATE` は別 OS で取った capture でなければならず、それ以外（非 Linux 基準・同じ OS 同士）は比較せず終了コード 3 で止まる
4. 下のチェックリストの結果欄を記入する（A 層は capture の値を転記。B 層の非 Linux は前提が整うまで「前提未達」のまま）
5. Windows でスクリプトが動かない場合の手動手順: 下のケース表の引数を PowerShell 等で 1 件ずつ実行し、終了コードと stderr 1 行 JSON の `code` を転記する。状態ルートは `--root` に専用の一時ディレクトリを指定し、既定の状態ルートに触れない。B 層は表の順（上から）に実行する

スクリプトは全ケースで `--root` を一時ディレクトリに向け、sudo を呼ばず、各 CLI 呼び出しにタイムアウトを持つ。タイムアウト・中断時の回収は CLI を起動したプロセスグループ単位で行うため、CLI の子孫が `setsid` 等で別セッションへ出た場合は回収できない。Windows（Git Bash）のネイティブ exe の子は POSIX の pgid を持たないため、未回収の CLI に限り `taskkill /T` でもツリーごと回収する（#1548・REPAIR-5）。CLI の正常終了後に残った子孫と、期限前に親が死んで孤児になった子孫は辿れない。CI の `platform-ci`（Windows を含む 3 OS は main への push と `workflow_dispatch`。PR は ubuntu のみ）が `make cli-parity-native-reclaim-check` で回収を実測し、ログの `cli-parity native reclaim:` 行（`descendant_alive`・`winpid_available`・`baseline_group_kill_descendant_alive`）に結果を出す。このスクリプトは全体の期限（既定 150 秒）を持ち、超えると子孫を回収して `deadline_exceeded` の行つきで失敗する（#1688）。Windows の実測値は PR の CI ログで確認する。
スクリプトは判定・CLI の実行ともに `LC_ALL=C` に固定する（#1548・CLI-1）。製品 CLI は setlocale を呼ばず出力は英語固定のため比較の情報は減らず、無効な `LC_ALL` による bash 製スタブの警告で `code` の判定が壊れるのを防ぐ。

### stderr の `code` の読み取り（ERR-1・ERR-2）

スクリプトが `code` として受理する stderr は次の 2 形式だけで、どちらも 1 行・LF 終端・キー順固定とする。

- 固定文言の失敗（使い方エラー・未実装・状態ルート不在など）: `{"code":"<CODE>","message":"<文字列>"}`
- core 由来の失敗（`create` / `start` / `stop` / `delete`）: `{"op":"<操作>","code":"<CODE>","message":"<文字列>"}`（`stop` の `op` は `kill`）

`message` は JSON 文字列として検証する（未エスケープの `"`・`\`・制御文字、不正なエスケープ、不正な UTF-8 は拒否）。記録と比較の対象は `code` だけで、`op` の有無と値・`message` の内容は記録しない。上記以外の出力（キーの追加・欠落・順序違い、複数行、LF 終端なし、NUL、16384 バイト超）は `<unparsed>` と記録し、compare は同じ `<unparsed>` 同士でも一致扱いにしない（UNVERIFIED）。

エラー形式は TASK-95（ERR 系）で確定する。キーの追加など形式が変わった場合は `scripts/cli-parity-check.sh` の受理形式を追従させる必要がある（追従前は該当ケースが `<unparsed>` になり、合格には見えない）。手動手順で転記する場合も、stderr が上の形式の 1 行であることを確かめてから `code` を書く。

## 記録ルール

- ホスト名・ユーザー名・絶対パス・アドレス・環境変数を書かない（capture にも出力されない）
- 書いてよいもの: OS 名と版数・アーキ・コミット SHA・実施日
- capture ファイルを貼る場合は正規化済みの出力そのままのみ
- 結果欄は実測した値だけを書く。未実施は空欄、前提未達は「前提未達」と書く。推測で埋めない

## 実施情報（記入欄）

| 項目 | Linux | macOS | Windows |
| ---- | ----- | ----- | ------- |
| OS 版数 | Ubuntu 26.04.1 LTS（カーネル 7.0.0-34-generic） | macOS 27.0.1（26A434） | |
| アーキ | x86_64 | arm64（Apple M4） | |
| コミット SHA | `d2566bc166500dccf137b1d918adecfdfd9a0e72` | `d2566bc166500dccf137b1d918adecfdfd9a0e72` | |
| 実施日 | 2026-10-12 | 2026-10-12 | |

## A 層: 構文・使い方エラー（3 OS で比較可能）

引数解析は OS 非依存の純粋関数。全 OS で終了コード 2・`code` = `INVALID_ARGUMENT`・stdout 空を期待する。結果欄には終了コード / `code` を書く。`--root` の値は常に一時ディレクトリ、`<bundle>` は最小 OCI バンドルを指す。

| ID | 構文 | 期待 | Linux | macOS | Windows | 一致 | 備考 |
| -- | ---- | ---- | ----- | ----- | ------- | ---- | ---- |
| A01 | コマンドなし | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A02 | 未知コマンド | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A03 | `create`（引数なし） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A04 | `create <id>`（`--bundle` 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A05 | `create --bundle <bundle>`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A06 | `create` の ID 余剰 | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A07 | `start`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A08 | `start` の ID 余剰 | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A09 | `stop`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A10 | `delete`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A11 | `delete --force --force <id>`（重複） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A12 | `list extra`（余剰引数） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A13 | `logs`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A14 | `start a/b`（不正な ID） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A15 | `--root` の重複 | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A16 | `--plugin-path-search` の重複 | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A17 | `--root` の値欠落 | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A18 | `start --bogus <id>`（未知オプション） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | Linux・macOS 一致 | |
| A19 | `stop --signal`（値欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A20 | `stop --signal BOGUS <id>`（未知のシグナル名） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A21 | `stop --signal 65 <id>`（範囲外の番号） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A22 | `create <id> --cap-drop`（値欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A23 | `create --cap-drop CAP_BOGUS ...`（未知の capability 名） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A24 | `inspect`（ID 欠落） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |
| A25 | `inspect <id> <id>`（余剰引数） | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | 2 / `INVALID_ARGUMENT` | | 未確認（#2775 で追加） | |

## B 層: 挙動（macOS / Windows は plugin 発見機構経由）

B 層は上から順に実行し、状態遷移を直後の `list` で観測する。Linux 欄の期待は現行実装の参考値（REPAIR-3）。macOS / Windows 欄は plugin 起動・RPC 配線（TASK-114）が整うまで「前提未達」を既定値とする。

### 6 コマンド別の比較項目

| コマンド | 受理される構文 | 比較項目 |
| -------- | -------------- | -------- |
| `create` | `create --bundle <dir> <id>` | 終了コード・`code`・stdout 空・直後の `list` に ID が現れる（状態 `created`） |
| `start` | `start <id>` | 終了コード・`code`・stdout 空・不在 ID は `NOT_FOUND`（3） |
| `stop` | `stop <id>` | 終了コード・`code`・stdout 空・不在 ID は `NOT_FOUND`（3） |
| `delete` | `delete [--force] <id>` | 終了コード・`code`・stdout 空・直後の `list` から ID が消える |
| `list` | `list` | 終了コード・stdout の形式（ヘッダ `ID<TAB>STATUS<TAB>PID`、ID 昇順、0 件はヘッダのみで 0）・状態ルート不在は `NOT_FOUND`（3） |
| `inspect` | `inspect <id>` | 終了コード・`code`・正規化した 1 行 JSON（B17。種別 `i`）・不在 ID は `NOT_FOUND`（3）。構文は A24・A25 |
| `logs` | `logs [--follow] [--tail <N>] [--stream <stdout\|stderr>] [--escape] <id>` | 終了コード・`code`・不在 ID は `NOT_FOUND`（3）。オプションの構文は D 層（#2447・SUP-7） |

### ケース別チェックリスト

結果欄は 終了コード / `code` / stdout 要約（`-` = 空、`list:H;<id>,<status>,<pid|->` = list 形式、`inspect:...` = inspect の 1 行 JSON の正規化形式）。

`inspect:<id>,<status>,pid=<pid|->,exit=<整数|->,rev=<整数>,cg=<set|->,sup=<pid|->,health=<語彙|->,rst=<整数>,audit=<policy/seccompKill/landlock/record|->,idmap=<model:uid件数:gid件数|->,stop=<語彙>,caps=<件数|->` の固定語彙の 1 欄に畳んで記録する（`scripts/cli-parity-check.sh` の `norm_inspect`。CLI-1・#2826）。値を記録する項目は id・status・health・exitCode・revision・restartCount・explicitStop で、PID（pid・supervisorPid）は `<pid>`、cgroup（cgroupScope・cgroupInstance）は `<set>` に置換する。記録しない項目は bundle（絶対パス）・auditCoverage の reason（カーネル版数に依る詳細）・idMapping の hostId（ホストの subuid 設定）・capabilities の名前（件数だけ記録）。キー順や形が製品の出力契約（`crates/supervisor/src/inspect.rs`）と違う出力は `<unexpected>:<行数>` になり、一致扱いにならない。

| ID | コマンドと前提 | Linux の参考期待値 | Linux | macOS | Windows | 一致 | 備考 |
| -- | -------------- | ------------------ | ----- | ----- | ------- | ---- | ---- |
| B01 | `list`（空の状態ルート） | 0 / `-` / `list:H` | 0 / `-` / `list:H` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B02 | `create --bundle <bundle> c1` | 0 / `-` / `-` | 0 / `-` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B03 | `list`（create 後） | 0 / `-` / `list:H;c1,created,-` | 0 / `-` / `list:H;c1,created,-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B17 | `inspect c1`（B03 の直後。created のコンテナ） | 0 / `-` / `inspect:c1,created,pid=-,exit=-,rev=<実装の値>,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=not_recorded,caps=-` | | 前提未達 | 前提未達 | | `rev` は参考値で固定の合格基準にしない。macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない）。#2826 で追加 |
| B04 | `create`（c1 重複） | 4 / `ALREADY_EXISTS` / `-` | 4 / `ALREADY_EXISTS` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B05 | `start c1` | 8 / `UNIMPLEMENTED` / `-`（本番 launcher 未提供） | 8 / `UNIMPLEMENTED` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B06 | `list`（start 後） | 0 / `-` / `list:H;c1,created,-` | 0 / `-` / `list:H;c1,created,-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B07 | `logs c1` | 0 / `-` / `-`（ログ無しは成功。#1543） | 0 / `-` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B08 | `stop c1` | 5 / `FAILED_PRECONDITION` / `-`（未起動） | 5 / `FAILED_PRECONDITION` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない）。値は Linux と同じだが、未起動の判定ではなくバックエンド解決の失敗 |
| B09 | `delete c1` | 0 / `-` / `-` | 0 / `-` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B10 | `list`（delete 後） | 0 / `-` / `list:H` | 0 / `-` / `list:H` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B11 | `start nonexist` | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B12 | `stop nonexist` | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B13 | `delete nonexist` | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B14 | `logs nonexist` | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B15 | `list`（状態ルートの親ディレクトリも不在） | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |
| B16 | `inspect nonexist` | 3 / `NOT_FOUND` / `-` | 3 / `NOT_FOUND` / `-` | 前提未達 | 前提未達 | | macOS の capture の値: 5 / `FAILED_PRECONDITION` / `-`（合格として扱わない） |

**手動確認（自動収集しない）**: created の `inspect <id>` は B17 で自動収集する。Linux で start 済みコンテナの `inspect <id>` は 1 行の JSON を出し、末尾が `"explicitStop":"...","capabilities":{"bounding":[...]}` になる（`create --cap-drop chown` なら `CAP_CHOWN` が bounding から消える）。start 前・旧記録は `"capabilities":null`。capture の環境では B05 の `start` が成功しない（本番 launcher が無い）ため、start 済みの capability 集合の中身は自動収集できず手動のままにする（B17 の `caps=` は件数だけ。中身の照合は crates/cli・crates/supervisor の試験が担う。#2775・#2826・CLI-1）。

## C 層: イメージ管理（`image ls`・`system df`・`image rm`・`image tag`。#2221・#2316・CLI-1・OCI-7）

`scripts/cli-parity-check.sh` は本層を自動収集しない。手動で実行し、結果欄だけを記入する（#661）。パス・ホスト名は記録しない（記録ルールは上記）。`<dir>` は事前に作った空のイメージストア root（絶対パス。`blobs/sha256` を持つ）。C29〜C31 だけは pull 済みの root（下記）を使う。

### pull 済みの root の用意（Linux 限定・人間担当。#661）

CLI に `pull` は無いため、plugin-cri の `PullImage` で在庫を埋める。手順は `docs/verification/crictl-smoke.md` の前提（plugin-cri を UDS で起動。`fandhe-container-plugin-cri --socket <PATH>`）に従い、`crictl pull docker.io/library/busybox:latest` を実行する。plugin-cri のキャッシュは、plugin-cri が解決する既定の状態ルート（`StateRoot::resolve(None)`）の `.cri/images` である（状態ルートを指定するフラグは無い。#2592）。その `.cri/images` の絶対パスを `<pulled-dir>` として C29〜C31 の `--image-root` に渡す。C29〜C31 は変更を伴うため、実行順（C29 → C30 → C31）を守り、実行前に在庫を取り直せるようにしておく（`crictl pull` は再実行できる）。実環境の状態ルートのパスは記録しない。

### 4 コマンドの比較項目

| コマンド | 受理される構文 | 比較項目 |
| -------- | -------------- | -------- |
| `image ls` | `image ls --image-root <dir>` | 終了コード・stdout の形式（ヘッダ `REPOSITORY<TAB>TAG<TAB>DIGEST<TAB>SIZE<TAB>MISSING`、0 件はヘッダのみで 0） |
| `system df` | `system df --image-root <dir>` | 終了コード・stdout の形式（ヘッダ `KEY<TAB>VALUE` と固定順 9 行） |
| `image rm` | `image rm [--force] --image-root <dir> <ref>` | 終了コード・`code`・未知の参照は `NOT_FOUND`（3）・使用中は `FAILED_PRECONDITION`（5） |
| `image tag` | `image tag --image-root <dir> <source> <target>` | 終了コード・`code`・未知の source は `NOT_FOUND`（3）・digest の target は `INVALID_ARGUMENT`（2） |

### C 層の構文ケース（3 OS で 2 / `INVALID_ARGUMENT` を期待）

| ID | 構文 | 期待 | Linux | macOS | Windows | 一致 | 備考 |
| -- | ---- | ---- | ----- | ----- | ------- | ---- | ---- |
| C01 | `image`（サブコマンドなし） | 2 / `INVALID_ARGUMENT` | | | | | |
| C02 | `image bogus` | 2 / `INVALID_ARGUMENT` | | | | | |
| C03 | `system` / `system bogus` | 2 / `INVALID_ARGUMENT` | | | | | |
| C04 | `image ls`（`--image-root` 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| C05 | `image ls --image-root`（値欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| C06 | `image ls --image-root <相対パス>` | 2 / `INVALID_ARGUMENT` | | | | | |
| C07 | `image ls --image-root <dir> extra` / `system df --image-root <dir> extra` | 2 / `INVALID_ARGUMENT` | | | | | |
| C08 | `image rm --image-root <dir>`（参照欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| C09 | `image rm --image-root <dir> a b`（余剰） | 2 / `INVALID_ARGUMENT` | | | | | |
| C10 | `image rm --force --force --image-root <dir> x`（重複） | 2 / `INVALID_ARGUMENT` | | | | | |
| C11 | `image rm --image-root <dir> 'bad ref!'`（不正な参照） | 2 / `INVALID_ARGUMENT` | | | | | Linux のみ到達（非 Linux は解決の失敗が先） |
| C12 | `image tag --image-root <dir> a`（target 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| C13 | `image tag --image-root <dir> a b c`（余剰） | 2 / `INVALID_ARGUMENT` | | | | | |
| C14 | `image tag --force --image-root <dir> a b`（未対応オプション） | 2 / `INVALID_ARGUMENT` | | | | | |
| C15 | `image tag --image-root <dir> busybox sha256:<64 hex>`（digest の target） | 2 / `INVALID_ARGUMENT` | | | | | Linux のみ到達（非 Linux は解決の失敗が先） |
| C16 | `image rm --image-root <dir> sha256:<大文字 hex 64>`（digest に見える不正な参照） | 2 / `INVALID_ARGUMENT` | | | | | Linux のみ到達（非 Linux は解決の失敗が先） |
| C17 | `image rm --image-root <dir> sha512:<hex 128>` | 2 / `INVALID_ARGUMENT` | | | | | Linux のみ到達（非 Linux は解決の失敗が先） |
| C18 | `image tag --image-root <dir> busybox sha256:<大文字 hex 64>` | 2 / `INVALID_ARGUMENT` | | | | | Linux のみ到達（非 Linux は解決の失敗が先） |

### C 層の挙動ケース（Linux の参考期待値のみ。macOS / Windows は「前提未達」が既定）

| ID | コマンドと前提 | Linux の参考期待値 | Linux | macOS | Windows | 一致 | 備考 |
| -- | -------------- | ------------------ | ----- | ----- | ------- | ---- | ---- |
| C20 | `image ls --image-root <dir>`（空） | 0 / ヘッダのみ | | 前提未達 | 前提未達 | | |
| C21 | `system df --image-root <dir>`（空） | 0 / 固定 9 行（値は 0） | | 前提未達 | 前提未達 | | |
| C22 | `image rm --image-root <dir> busybox:latest` | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | 空のストア（未 pull の root）での値。pull 済みの root は C31 |
| C23 | `image ls --image-root <存在しない dir>` | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | |
| C24 | `image ls --image-root <通常ファイル>` | 5 / `FAILED_PRECONDITION` | | 前提未達 | 前提未達 | | |
| C25 | `image tag --image-root <dir> busybox:latest busybox:v2` | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | 空のストア（未 pull の root）での値。pull 済みの root は C29 |
| C26 | `create --image-root <dir> --image sha256:<64 hex> または name[:tag] --bundle <bundle> <id>`（OCI-7・#2315） | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | 空のストア（未 pull の root）での値で、状態は作られない。pull 済みの root は C30。`--image` だけ・`--image-root` だけは 2 / `INVALID_ARGUMENT` |
| C27 | `image rm --image-root <dir> nginx@sha256:<64 hex>`（空のストア。#2659） | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | `name@digest` は digest 優先で受ける（`INVALID_ARGUMENT` にならない） |
| C28 | `image tag --image-root <dir> nginx@sha256:<64 hex> busybox:v2`（空のストア。#2659） | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | 同上 |
| C29 | `image tag --image-root <pulled-dir> busybox:latest busybox:v2`（pull 済みの root。#2826） | 0 / `tagged` の 1 行 | | 前提未達 | 前提未達 | | 出力は `tagged\t<tag>\t<manifest>`（`crates/cli/src/commands/image.rs`）。値は記録しない。同じ操作の再実行は `unchanged` |
| C30 | `create --image-root <pulled-dir> --image busybox:latest --bundle <bundle> <id>`（pull 済みの root。OCI-7・#2826） | 0 / `-` | | 前提未達 | 前提未達 | | 状態が作られ、直後の `list` に ID が現れる。この参照が残る間、C31 は使用中になる |
| C31 | `image rm --image-root <pulled-dir> busybox:latest`（pull 済みの root。#2826） | 0 / `untagged` 行のみ | | 前提未達 | 前提未達 | | C30 の `delete` 後（参照が残らない状態）の値。C29 で付けた `busybox:v2` が残るため `deleted` 行は出ない（最後のタグを消すと `deleted` 行も出る。`image rm busybox:v2` を続けて確認してよい）。コンテナが使用中なら 5 / `FAILED_PRECONDITION`（`--force` なしの拒否）。値は記録しない |

## D 層: logs のオプション（`--follow`・`--tail`・`--stream`・`--escape`。#2447・CLI-1・SUP-7）

`scripts/cli-parity-check.sh` は本層のうち、速く決定的に終わる D01〜D05・D06（`-f` のみ）・D24 の 7 件を自動収集する（#2605。層の文字 `D`。`compare` の集計に `layer D (logs options)` が出る）。手動で実行し結果欄を記入するのは D06 の `-n 1` と D20〜D23・D25・D26 である。手動に残す理由は、書き手が作ったログのレコードが前提になること、`--follow` が期限（24 時間）やシグナルまで終わらないこと、試験専用 feature の期限の上書きが本番バイナリでは使えないことによる。これらの挙動は `crates/cli/tests/binary_entry.rs` の結合試験で機械照合している。3 OS で同じなのは構文（D 層の構文ケース）で、読み出しの挙動は Linux だけが実装済み・確認済みである（非 Linux は plugin 経由で、TASK-114・TASK-125 待ち。`logs` の入口は plugin 解決の失敗で fail-closed）。出力の意味は `list_logs` module の doc を正とする（オプションなしはバイトのまま。`--escape` は `cat -v` と同じ表で本体だけ変換）。

### D 層の構文ケース（3 OS で 2 / `INVALID_ARGUMENT` を期待）

| ID | 構文 | 期待 | Linux | macOS | Windows | 一致 | 備考 |
| -- | ---- | ---- | ----- | ----- | ------- | ---- | ---- |
| D01 | `logs --tail`（値欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| D02 | `logs --tail x c1` | 2 / `INVALID_ARGUMENT` | | | | | 10 進数字以外（`-1`・`+5`・`all` を含む） |
| D03 | `logs --tail 1000001 c1` | 2 / `INVALID_ARGUMENT` | | | | | 上限は 1,000,000（値はオーナー確認待ち。#2605） |
| D04 | `logs --stream bogus c1` | 2 / `INVALID_ARGUMENT` | | | | | 値は `stdout` / `stderr` のみ |
| D05 | `logs --follow --follow c1`（重複） | 2 / `INVALID_ARGUMENT` | | | | | `--tail`・`--stream`・`--escape` の重複も同じ |
| D06 | `logs -f c1` / `logs -n 1 c1`（短縮形） | 2 / `INVALID_ARGUMENT` | | | | | 長い形だけを受ける |

### D 層の挙動ケース（Linux の参考期待値のみ。macOS / Windows は「前提未達」が既定）

前提: c1 を create 済みで、コンテナログ（`<state_root>/@container-logs/c1.log`）が `stdout a` / `stderr b<ESC>[1m` / `stdout c` の 3 レコード（タグと LF つき）。

| ID | コマンドと前提 | Linux の参考期待値 | Linux | macOS | Windows | 一致 | 備考 |
| -- | -------------- | ------------------ | ----- | ----- | ------- | ---- | ---- |
| D20 | `logs --tail 2 c1` | 0 / 末尾 2 レコード（`stderr b<ESC>[1m` と `stdout c`） | | 前提未達 | 前提未達 | | |
| D21 | `logs --tail 0 c1` | 0 / 空 | | 前提未達 | 前提未達 | | |
| D22 | `logs --stream stderr c1` | 0 / `stderr b<ESC>[1m` のみ（タグを残す） | | 前提未達 | 前提未達 | | コンテナの stderr は CLI の stderr へ流さない |
| D23 | `logs --escape --stream stderr c1` | 0 / `stderr b^[[1m` | | 前提未達 | 前提未達 | | |
| D24 | `logs --follow nonexist` | 3 / `NOT_FOUND` | | 前提未達 | 前提未達 | | 待たずに終わる |
| D25 | `logs --follow c1` の実行中に追記し、Ctrl-C（SIGINT） | シグナル終了・stderr 空・それまでの行は stdout に届く | | 前提未達 | 前提未達 | | 期限は組み込みの 24 時間（値はオーナー確認待ち。#2605）。ローテーションをまたいでも欠落・重複なし（結合試験で確認） |
| D26 | `start` 済みの c1 に対し `logs --follow c1` を実行中に `stop c1` | 残りを出し切って 0 で終わる（stderr 空） | | 前提未達 | 前提未達 | | 書き手の終了（ログのロックの解放）と状態が `Running` でないことの両方で終える。restart ポリシーの再起動の間は終わらない。結合試験 `sup7_logs_follow_ends_when_container_stopped` が書き手の終了を模擬して機械照合。実機の確認は人間（#2605） |

追従の遅延は、LF で終わる行について最大で 1 ポーリング間隔（200 ms）と読み出しの時間で、短縮はしない（`list_logs` module の doc）。世代数 1 の設定の追従は 9 / `UNAVAILABLE` で拒否する（本番は固定の 3 世代で到達しない）。

## 差異のフィードバック先

起票・追記は人間の承認後に行う（Agent は自動で起票しない）。

| 差異の種類 | 戻し先 |
| ---------- | ------ |
| 構文（A 層）・Linux 経路の挙動 | TASK-79 系（CLI 本体） |
| 非 Linux の plugin 経由の挙動 | TASK-114（plugin 起動・RPC）・TASK-115 / TASK-116（macOS / Windows バックエンド）の該当 Issue |
| 本スクリプトの不具合 | TASK-125.1（#660）系 |
