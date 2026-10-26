# 起動オプション（ulimit・env・label ほか）の CLI から supervisor への受け渡し

SUP-12・CLI-1・CLI-4・SEC-1・REPAIR-2・REPAIR-3・REPAIR-5（#2713。#2625・#2707 の続き）の判断記録。

## 背景

`ContainerOptions::launch_options` は本番 launcher へ結線済み（#2625）だが、CLI・stack から supervisor へ
`ContainerOptions` を渡す経路が無く、`run_main` は常に既定値で動いていた。ulimit・env も launcher まで届いておらず
（`LaunchOptions` が持つのは tmpfs・注入ファイル・IPC だけ）、label を `CreateStateRequest::with_annotations` へ渡す
経路も無かった。

## 決定: 状態ルート配下の 0600 の文書ファイル

置き場所は `<state_root>/@container-options/<id>`（ディレクトリ 0700・ファイル 0600）。`--root` と `<id>` だけから
導くため、supervisor の起動契約（argv）・特権ランチャー・`start_client`（plugin-cri と共有）は変えない。

| 役割 | 担当 |
| ---- | ---- |
| 書く | CLI の `create`（core の create より前。失敗したら inode を照合して巻き戻す） |
| 読む | supervisor の `start`（`start_entry` の手順 2c。期限つきの作業スレッド） |
| 消す | CLI の `delete`（成功の後。同じ ID が再作成されていなければ。失敗は警告 1 行のみ）。plugin-cri の `create`（core の create の前。状態の記録が無い ID の残骸）と `delete`（core の delete の成功の後。記録が無くなった ID の文書。#2760） |

文書が無ければ既定値で動く（plugin-cri・従来のコンテナは書かない）。文書があって壊れている・権限が不正なら
手順 4 で cgroup にも launch にも触れずに止める（fail-closed）。手順 3 の中断起動の回復（CORE-2）は従来どおり先に走る。

### 却下した案

| 案 | 却下理由 |
| ---- | ---- |
| 制御チャネルで渡す | 作られるのが launch の後（手順 10）で、オプションを使う手順 4・7 に間に合わない |
| 継承 fd で渡す | 入口と特権ランチャーが fd 3 以降を閉じる（`start_contract`） |
| argv / env で渡す | env の値が `/proc/<pid>/cmdline`・`environ` に出る。`MAX_ARGS`（8）も超える |
| core の `StateRecord` へ同梱する | StateStore の型とスキーマ（plugin 境界の型）の変更が大きい。`state`・`inspect` に env が出る危険もある |
| supervisor に serde / toml を足す | 依存の追加（ユーザー承認制）。独自の長さ接頭辞形式で足りる |

## 文書の形式（`FCOPT1`）

符号化と復号を同じ型（`ContainerOptionsDocument`）に置く（REPAIR-2）。

```text
FCOPT1\n
<kind> <len>\n<len バイトの UTF-8>\n     （繰り返し）
```

- `kind` は閉じた語彙 `ulimit`・`env`・`ipc`・`shm-size`・`tmpfs`。`len` は 10 進（先頭 0 と `+` は不可、7 桁まで）
- 値の改行を許すため行区切りではなく長さ接頭辞にする
- 中身は Docker 構文の生の文字列で、復号のたびに既存のパーサ（`Ulimit::parse` 等）へ通し直す（未信頼の入力として検証）
- 上限は確保の前に検証する: 全体 `ENV_MAX_TOTAL_BYTES + 256 KiB`、件数（ulimit 16・env `ENV_MAX_ENTRIES`・tmpfs
  `TMPFS_MAX_MOUNTS`）、kind ごとの 1 レコード長
- エラーは固定の英語文言で、値・パスを含めない。`Debug` は env の値を伏せる

## 各オプションの経路

| オプション | 経路 |
| ---------- | ---- |
| `--ulimit` | 文書 → `LaunchOptions::with_rlimits` → launcher が 16 種へ補完して `Rlimits` 段へ渡し、同じ集合を Running の状態記録（`state.json` の `rlimits`）にも書く。exec の再適用が launch と同じ制限を載せる |
| `--env` / `--env-file` | CLI が `--env-file` を利用者の権限で読み、`-e` が後勝ちで統合した `KEY=VALUE` を文書へ → `LaunchOptions::with_env` → `process.env` へ位置を保って重ねる（新しいキーは末尾）。PATH 解決もマージ後の env で行う |
| `--ipc` / `--shm-size` / `--tmpfs` | 文書 → 既存の `ContainerOptions::launch_options`（#2625） |
| `--label` | 文書を通さず、create 時に `CreateRequest::with_annotations` → `CreateStateRequest::with_annotations` で `state.json` の `annotations` へ |

core は supervisor の検証を信用せず `LaunchOptions::with_env` で件数・長さ・形式を再検証する。

## セキュリティ上の判断

- 特権の supervisor（`CAP_DAC_OVERRIDE` を持ちうる）に利用者指定のホストのパスを読ませない（confused deputy）。
  `--env-file` は CLI が非特権のまま読む。secrets / configs（ホストのパスを指す）は今回扱わない（下記）
- 読み取りは `O_NOFOLLOW`・`O_NOCTTY`・`O_NONBLOCK`、fstat で通常ファイル・所有者が実効 uid・group / other のビットなし・
  サイズ上限を確認し、`take` で上限つきに読む
- `--ipc=host` は明示指定のときだけ。ulimit の hard を継承値より上げる指定は `prlimit` の EPERM で起動失敗になる
  （黙ってクランプしない）
- env はディスク上の 0600 の文書に残る（Docker の config と同等）。ログ・エラーには出さない

## 残余・後続（REPAIR-3）

- **secrets / configs の CLI フラグ**: 文書の kind も未定義。ホストのパスを特権の supervisor が読む方式は confused deputy に
  なりうるため、fd の所有者照合か、CLI が非特権のまま開いて渡す方式を別に設計する（core の `launch_options.rs` の
  「未設計」と同じ課題）
- **同じ ID の並行 create / delete**: ID 単位のロック（`@container-options/@lock-<id>`、期限つき）を create の間と delete の削除の間に保持して直列化する。文書の I/O（ロック取得・掃除・書き込み・fsync・巻き戻し・`--env-file` の読み取り）は作業スレッドで期限つきに待つ（REPAIR-5）。期限切れで残った文書は状態が無いので次の create / delete が掃除する。文書の書き込みは親ディレクトリも fsync してから成功を返す（OCI-5）
- **plugin-cri の create・delete は残骸を掃除する（#2760）**: plugin-cri は文書を書かないので、状態の記録が無い ID の文書はすべて前のコンテナの残骸である。`create` は core を呼ぶ前、`delete` は core の delete の成功の後に、ID 単位のロックの下で「状態ストアが `NotFound`」を確かめてから消す（`container_options::store::remove_stale_bounded`。CLI の delete 後の掃除と同じ関数）。記録がある ID（重複 create の `ALREADY_EXISTS`、作り直された新しいインスタンス）の文書は、世代が一致するものも含めて消さない（読み取りに失敗したら fail-closed で消さない）。文書が無ければロックも作らない。失敗・期限切れ（ロック 8 秒・全体 10 秒）は best effort で、create / delete の結果は変えず、記録器の op `container_options_remove` の Failure と、delete 側は構造化ログ 1 行（`event: container_delete_cleanup`・`target: container_options`）で知らせる。`DeleteResponse` / `CleanupTarget` には語彙を足さない（plugin 境界の型を変えない）。掃除に失敗しても、文書は作成世代（`gen` レコード）を持ち、CLI の create が同じ値を状態記録の annotations（`io.fandhe.container.options-generation`）へ書く。supervisor の `start` は両者が一致する文書だけを採用し（`select_document`）、一致しない残骸は適用しない（前の世代の env・ulimit・`--ipc=host` を次のコンテナへ適用しない。SEC-1）。記録が世代を持つのに文書が無ければ `FAILED_PRECONDITION` で拒否する
- **exec・healthcheck の env**: launch の env 上書きは `exec::run_command_with_pidfd_env` の `launch_env`（`store::launch_env_for` が世代を照合して返す）で `process.env` の上、exec 固有の指定の下に重ねる。呼び出し元の配線は healthcheck #2441・CLI の exec #2626（未実装）
- **stack**: `Service::create_option_args` が env・env_files・labels を create の引数列へ写すところまで。`up`
  からの結線は TASK-155、ulimit・tmpfs のスキーマは #586・#862
- **`--audit-policy` の CLI からの受け渡し**: 対象外（`start_contract` の doc に未実装とある）
- **実機での観測**: `--ulimit`・`--env` を付けたコンテナ内の `/proc/self/limits`・environ の観測は未実施（実機前提テストは未追加）
