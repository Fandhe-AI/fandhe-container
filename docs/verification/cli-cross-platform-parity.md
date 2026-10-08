# CLI 基本 6 コマンドの 3 OS 同一構文・挙動 確認記録（雛形）

TASK-125（共同タスク）の確認記録の雛形。実機での実行・結果の記入・CLI-1 の合否判定は #661（TASK-125.h1・人間担当）が行う。本ファイルと `scripts/cli-parity-check.sh` は Agent 担当分（TASK-125.1・#660）の準備物で、結果欄に Agent が実測値を埋めてはならない。

- 対応: TASK-125・CLI-1・MS-6（Phase 12）
- 関連: ERR-2（終了コード表）・PLUG-4・PLUG-11・REPAIR-3（未実装を実装済みと装わない）
- 親: #659 / Agent 担当: #660 / 実機確認（人間）: #661

## 現状の制約（必読）

| 項目 | 内容 |
| ---- | ---- |
| 非 Linux の plugin 起動・RPC | 発見 → 登録 → 信頼性検証までは配線済みだが、plugin の起動と RPC は未実装（TASK-114）。macOS / Windows ではバックエンド解決が必ず失敗する。よって B 層（挙動）の非 Linux 欄は **前提未達** であり、合格として記入しない |
| Linux 経路の未実装 | `start` の本番 launcher、`logs`、pid ありの `stop`、cgroup 配置つき `delete` は未実装（REPAIR-3）。Linux 側の現行値（`start` = 8 など）は「現行実装での参考値」で、launcher 提供後に変わる。固定の合格基準にしない |
| Windows の自動化 | `scripts/cli-parity-check.sh` は Git Bash での実行を想定するが、CI では未検証（自己テストは ubuntu・macos のみ） |

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

   終了コード 0 = 全ケース一致 / 1 = 不一致・欠落・タイムアウト / 2 = 引数・入力エラー / 3 = 前提欠如。1 は機械照合の事実報告で、合否は人間が判定する
4. 下のチェックリストの結果欄を記入する（A 層は capture の値を転記。B 層の非 Linux は前提が整うまで「前提未達」のまま）
5. Windows でスクリプトが動かない場合の手動手順: 下のケース表の引数を PowerShell 等で 1 件ずつ実行し、終了コードと stderr 1 行 JSON の `code` を転記する。状態ルートは `--root` に専用の一時ディレクトリを指定し、既定の状態ルートに触れない。B 層は表の順（上から）に実行する

スクリプトは全ケースで `--root` を一時ディレクトリに向け、sudo を呼ばず、各 CLI 呼び出しにタイムアウトを持つ。

### stderr の `code` の読み取り（ERR-1・ERR-2）

スクリプトが `code` として受理する stderr は次の 2 形式だけで、どちらも 1 行・LF 終端・キー順固定とする。

- 固定文言の失敗（使い方エラー・未実装・状態ルート不在など）: `{"code":"<CODE>","message":"<文字列>"}`
- core 由来の失敗（`create` / `start` / `stop` / `delete`）: `{"op":"<操作>","code":"<CODE>","message":"<文字列>"}`（`stop` の `op` は `kill`）

`message` は JSON 文字列として検証する（未エスケープの `"`・`\`・制御文字、不正なエスケープ、不正な UTF-8 は拒否）。記録と比較の対象は `code` だけで、`op` の有無と値・`message` の内容は記録しない。上記以外の出力（キーの追加・欠落・順序違い、複数行、LF 終端なし、16384 バイト超）は `<unparsed>` と記録し、compare は同じ `<unparsed>` 同士でも一致扱いにしない（UNVERIFIED）。

エラー形式は TASK-95（ERR 系）で確定する。キーの追加など形式が変わった場合は `scripts/cli-parity-check.sh` の受理形式を追従させる必要がある（追従前は該当ケースが `<unparsed>` になり、合格には見えない）。手動手順で転記する場合も、stderr が上の形式の 1 行であることを確かめてから `code` を書く。

## 記録ルール

- ホスト名・ユーザー名・絶対パス・アドレス・環境変数を書かない（capture にも出力されない）
- 書いてよいもの: OS 名と版数・アーキ・コミット SHA・実施日
- capture ファイルを貼る場合は正規化済みの出力そのままのみ
- 結果欄は実測した値だけを書く。未実施は空欄、前提未達は「前提未達」と書く。推測で埋めない

## 実施情報（記入欄）

| 項目 | Linux | macOS | Windows |
| ---- | ----- | ----- | ------- |
| OS 版数 | | | |
| アーキ | | | |
| コミット SHA | | | |
| 実施日 | | | |

## A 層: 構文・使い方エラー（3 OS で比較可能）

引数解析は OS 非依存の純粋関数。全 OS で終了コード 2・`code` = `INVALID_ARGUMENT`・stdout 空を期待する。結果欄には終了コード / `code` を書く。`--root` の値は常に一時ディレクトリ、`<bundle>` は最小 OCI バンドルを指す。

| ID | 構文 | 期待 | Linux | macOS | Windows | 一致 | 備考 |
| -- | ---- | ---- | ----- | ----- | ------- | ---- | ---- |
| A01 | コマンドなし | 2 / `INVALID_ARGUMENT` | | | | | |
| A02 | 未知コマンド | 2 / `INVALID_ARGUMENT` | | | | | |
| A03 | `create`（引数なし） | 2 / `INVALID_ARGUMENT` | | | | | |
| A04 | `create <id>`（`--bundle` 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A05 | `create --bundle <bundle>`（ID 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A06 | `create` の ID 余剰 | 2 / `INVALID_ARGUMENT` | | | | | |
| A07 | `start`（ID 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A08 | `start` の ID 余剰 | 2 / `INVALID_ARGUMENT` | | | | | |
| A09 | `stop`（ID 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A10 | `delete`（ID 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A11 | `delete --force --force <id>`（重複） | 2 / `INVALID_ARGUMENT` | | | | | |
| A12 | `list extra`（余剰引数） | 2 / `INVALID_ARGUMENT` | | | | | |
| A13 | `logs`（ID 欠落） | 2 / `INVALID_ARGUMENT` | | | | | |
| A14 | `start a/b`（不正な ID） | 2 / `INVALID_ARGUMENT` | | | | | |
| A15 | `--root` の重複 | 2 / `INVALID_ARGUMENT` | | | | | |
| A16 | `--plugin-path-search` の重複 | 2 / `INVALID_ARGUMENT` | | | | | |
| A17 | `--root` の値欠落 | 2 / `INVALID_ARGUMENT` | | | | | |
| A18 | `start --bogus <id>`（未知オプション） | 2 / `INVALID_ARGUMENT` | | | | | |

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
| `logs` | `logs <id>` | 終了コード・`code`・不在 ID は `NOT_FOUND`（3） |

### ケース別チェックリスト

結果欄は 終了コード / `code` / stdout 要約（`-` = 空、`list:H;<id>,<status>,<pid|->` = list 形式）。

| ID | コマンドと前提 | Linux の参考期待値 | Linux | macOS | Windows | 一致 | 備考 |
| -- | -------------- | ------------------ | ----- | ----- | ------- | ---- | ---- |
| B01 | `list`（空の状態ルート） | 0 / `-` / `list:H` | | 前提未達 | 前提未達 | | |
| B02 | `create --bundle <bundle> c1` | 0 / `-` / `-` | | 前提未達 | 前提未達 | | |
| B03 | `list`（create 後） | 0 / `-` / `list:H;c1,created,-` | | 前提未達 | 前提未達 | | |
| B04 | `create`（c1 重複） | 4 / `ALREADY_EXISTS` / `-` | | 前提未達 | 前提未達 | | |
| B05 | `start c1` | 8 / `UNIMPLEMENTED` / `-`（本番 launcher 未提供） | | 前提未達 | 前提未達 | | |
| B06 | `list`（start 後） | 0 / `-` / `list:H;c1,created,-` | | 前提未達 | 前提未達 | | |
| B07 | `logs c1` | 8 / `UNIMPLEMENTED` / `-` | | 前提未達 | 前提未達 | | |
| B08 | `stop c1` | 5 / `FAILED_PRECONDITION` / `-`（未起動） | | 前提未達 | 前提未達 | | |
| B09 | `delete c1` | 0 / `-` / `-` | | 前提未達 | 前提未達 | | |
| B10 | `list`（delete 後） | 0 / `-` / `list:H` | | 前提未達 | 前提未達 | | |
| B11 | `start nonexist` | 3 / `NOT_FOUND` / `-` | | 前提未達 | 前提未達 | | |
| B12 | `stop nonexist` | 3 / `NOT_FOUND` / `-` | | 前提未達 | 前提未達 | | |
| B13 | `delete nonexist` | 3 / `NOT_FOUND` / `-` | | 前提未達 | 前提未達 | | |
| B14 | `logs nonexist` | 3 / `NOT_FOUND` / `-` | | 前提未達 | 前提未達 | | |
| B15 | `list`（状態ルートの親ディレクトリも不在） | 3 / `NOT_FOUND` / `-` | | 前提未達 | 前提未達 | | |

## 差異のフィードバック先

起票・追記は人間の承認後に行う（Agent は自動で起票しない）。

| 差異の種類 | 戻し先 |
| ---------- | ------ |
| 構文（A 層）・Linux 経路の挙動 | TASK-79 系（CLI 本体） |
| 非 Linux の plugin 経由の挙動 | TASK-114（plugin 起動・RPC）・TASK-115 / TASK-116（macOS / Windows バックエンド）の該当 Issue |
| 本スクリプトの不具合 | TASK-125.1（#660）系 |
