# fio 4K ランダム write ベンチスクリプト

`scripts/fio-randwrite-4k.sh`（DB 書き込み相当の 4K ランダム write ワークロードを fio 経由で計測し、IOPS・レイテンシを機械可読形式で出力するスクリプト）の前提条件・使い方・パラメータ・出力スキーマ・終了コードを記録する。

- 対象ビヘイビア: IO-8（fio 4K ランダム write ベンチ実施・目標値設定。DB 書き込み相当のワークロードを I/O 共有プロトコル経由で実行し、Docker ベースライン比で IOPS を計測する）
- 関連タスク: TASK-25.1（#112。本スクリプトの実装）・TASK-25.2（#113。Docker ベースライン比の実測と目標値案。人間共同）・TASK-25.h1（#114。目標値の妥当性判断。人間担当）
- 対象マイルストーン: MS-1 Phase 2
- ステータス: 本ドキュメントは TASK-25.1 で確定したスクリプトの契約（前提条件・パラメータ・出力スキーマ・終了コード）を記録する。Docker ベースラインの実測レポートと目標値案は TASK-25.2 が追記する

## 現状の制約（実装済みを装わない。REPAIR-3）

fandhe-container の I/O 共有プロトコル経由の共有マウントはまだ公開されていない（クライアント側 UDS・ディスクへの書き込み・共有ファイルシステムとしてのマウントは TASK-13.2.2 以降）。そのため本スクリプトは書き込み先を `--target-dir` で受け取る汎用の形にし、`--label` で計測対象（Docker の bind mount / named volume のパスか、将来公開される fandhe 経路か）を出力に記録する契約とする。**fandhe 経路の実測は、共有マウントを公開する後続 TASK を待つ（IO-8）。** 本 PR（TASK-25.1）ではスクリプト本体と自己テストのみを実装し、Docker ベースライン比の実測・目標値の判断は行わない（TASK-25.2・TASK-25.h1）。

## 前提条件

- **run モード**（実際に fio を実行する）: fio 3.x 以上（`lat_ns`/`clat_ns` 等の `*_ns` キーを出力する版）・GNU coreutils の `timeout`・`realpath`・`jq`。**Linux ホストのみ対象**（GNU `timeout` が無い macOS 標準環境・Windows は対象外。VM ゲスト経由の経路は後続 TASK で扱う）
- **`--from-json` モード**（既存の fio JSON 出力を変換するだけ）: `jq`（fio・`timeout` は不要）。bash と jq だけで動くため、fio 未導入の CI・ローカル環境でも自己テストが完結する
- **全モード共通**: `grep`・`dirname`・`wc`・`tr`・`mktemp`・`find`・`ln`・`head`・`sleep`・`id`（欠如時は終了コード 3。欠如したまま進むと別の終了コードへ誤分類されるため事前に検出する）
- **root 権限・`/dev/kvm` は不要**（親 #111 の受入基準）

## 使い方

### run モード（Docker ベースラインの計測例）

```bash
# Docker の bind mount パスを直接 --target-dir に渡す（例: docker run -v /path/to/bind:/data ...）
bash scripts/fio-randwrite-4k.sh --target-dir /path/to/docker/bind-mount --label docker_bind_mount

# Docker の named volume の実体パス（docker volume inspect の Mountpoint）も同様に渡せる
bash scripts/fio-randwrite-4k.sh --target-dir "$(docker volume inspect my-volume --format '{{.Mountpoint}}')" --label docker_named_volume

# Makefile 経由（TARGET_DIR・LABEL は必須。RUNTIME 省略時は 30 秒）
make fio-bench TARGET_DIR=/path/to/docker/bind-mount LABEL=docker_bind_mount RUNTIME=30
```

fandhe 経路（共有マウント）の計測は、共有マウントが公開されてから同じスクリプトで `--target-dir` にそのマウントポイントを渡す（上記「現状の制約」を参照）。

### `--from-json` モード（既存の fio 出力を変換するだけ）

```bash
fio --name=fandhe-fio-randwrite-4k --directory=/path/to/target \
    --filename=fandhe-fio-randwrite-4k.dat --rw=randwrite --bs=4k --ioengine=psync \
    --direct=1 --size=256m --runtime=30 --time_based --iodepth=1 --numjobs=1 \
    --end_fsync=1 --group_reporting --output-format=json --output=/tmp/fio-out.json
bash scripts/fio-randwrite-4k.sh --from-json /tmp/fio-out.json --label docker_bind_mount
```

`--from-json` は run モードと同じ条件で実行された fio JSON だけを受け付ける（IO-8: `fio_randwrite_4k_*` の名前で出す結果は 4K ランダム write の条件で計測されたものに限る）。照合内容は次のとおりで、1 つでも満たさなければ終了コード 2 で拒否する。

- `jobs` はちょうど 1 件（`--group_reporting` を付け、ジョブセクションは 1 つ）、`jobname` は `fandhe-fio-randwrite-4k`、`error` は 0
- `global options` と `jobs[0]["job options"]` を合わせた（job 側を優先した）fio オプションは、run モードが渡すもの（`name`・`directory`・`filename`・`rw`・`bs`・`ioengine`・`direct`・`size`・`runtime`・`time_based`・`iodepth`・`numjobs`・`end_fsync`・`group_reporting`）に限る。これ以外のオプション（`rate_iops`・`fsync`・`percentile_list` 等）が 1 つでもあれば拒否する。`job options` が無い JSON も拒否する
- 上記 14 項目はすべて必須で、1 つでも欠ければ拒否する（値があるときだけ照合する項目は置かない）。`global options` は fio が空のとき出力しないため省略可だが、存在する場合はオブジェクトでなければ拒否する
- 固定値: `name=fandhe-fio-randwrite-4k`・`rw=randwrite`・`bs=4k`（`4k`/`4K`/`4096`）・`ioengine=psync`・`filename=fandhe-fio-randwrite-4k.dat`・`end_fsync=1`・`time_based` と `group_reporting` が有効（値なし、または `1`）
- `directory`: 空でない絶対パス（`/` で始まる）で、コロン（`:`。fio がディレクトリ・ファイル名リストの区切り文字として解釈する）を含まないこと（run モードの `--target-dir` と同じ制約。Windows 版 fio のドライブレター形式は受け付けない）。run モードではさらに、本スクリプトが作った専用サブディレクトリ（下記「書き込み先の安全性」）と完全一致することを要求する。`--from-json` では元の実行先を知り得ないため形式のみを照合し、値は出力の `params` に含めない
- 本スクリプトの同名オプション（既定値を含む）との一致: `direct`・`iodepth`・`numjobs`（文字列として一致）、`size`（`k`/`m`/`g` の大文字小文字・単位なしのバイト数を正規化して一致）、`runtime`（秒。末尾 `s` は可）。元の fio 実行が既定値と異なる条件なら、変換時に同じ値を `--size`・`--runtime`・`--iodepth`・`--numjobs`・`--direct` へ渡す

fio の JSON 上のオプション表現（`job options`/`global options` は正規オプション名→入力文字列の組で、値なしフラグは空文字列）は fio 本体（axboe/fio）の `parse.c`（`add_to_dump_list`）・`stat.c`（`json_add_job_opts`）・`json.h` を直接参照して確認した。実 fio の出力での照合は未実施（実機での確認は下記「実機での確認」節）。

### オプション

`--target-dir` は run モード専用で、`--from-json` と併用すると終了コード 2 で拒否する（黙って無視すると、呼び出し元が実測したと誤認するため）。`--direct`・`--size`・`--runtime`・`--iodepth`・`--numjobs` は、run モードでは fio へ渡す条件、`--from-json` モードでは fio JSON に記録された条件と照合する期待値になる。

| オプション | 既定値 | 説明 |
| ---- | ---- | ---- |
| `--target-dir <dir>` | （run モード必須） | fio の書き込み先ディレクトリ。symlink 拒否・書き込み可能なディレクトリであることを検証してから `realpath` で正規化する。正規化後のパスに `:` を含む場合も拒否する（fio が `--directory`/`--filename` の `:` をディレクトリ・ファイル名リストの区切り文字として解釈するため）。下記「ディレクトリの権限確認」を満たさないディレクトリも拒否する。データファイルは下記「書き込み先の安全性」のとおり、このディレクトリ内に実行ごとに作る専用サブディレクトリへ書く |
| `--from-json <path>` | （from-json モード必須） | 既存の fio `--output-format=json` 出力へのパス。symlink・通常ファイル以外を拒否し、サイズ上限（4 MiB）あり。下記「変換対象 JSON の読み取り」のとおり 1 回だけ読んだコピーを判定・変換に使う |
| `--label <label>` | 必須 | `^[a-z0-9_-]{1,64}$`。出力 JSON にそのまま記録し、計測対象（Docker ベースラインか fandhe 経路か等）を表す |
| `--output <path>` | （出力しない） | 指定時、結果 JSON をこのパスにも書く。symlink 拒否・既存ファイルへの上書きは拒否する。親ディレクトリの存在・書き込み可否も事前検証する（未検証のまま書き込みに失敗すると、呼び出し元が終了コード 1「fio 実行失敗」と誤認するため）。親ディレクトリが下記「ディレクトリの権限確認」を満たさなければ拒否する。書き込みは下記「`--output` の排他作成」の手順で行い、検証後に何かを置かれた場合も既存のエントリやリンク先を開かない |
| `--direct 0\|1` | `1` | fio `--direct`。tmpfs・FUSE 系の共有 FS では O_DIRECT が失敗しうるため変更できる |
| `--size <NkNmNg>` | `256m` | fio `--size`（ジョブごとの値）。`^[1-9][0-9]{0,5}[kmg]$`（先頭ゼロ不可）。DoS 防止の上限は総量で課し、`--size` × `--numjobs` が 10 GiB 以下（例: `10g`×1・`5g`×2 は可、`5g`×3 は不可）。全ジョブが同じ `--filename` を共有するためディスク上のファイルは 1 つだが、書き込み量に対して保守的に総量で制限する |
| `--runtime <1-600>` | `30` | fio `--runtime`（秒。`--time_based` と併用）。`^[1-9][0-9]{0,3}$`（先頭ゼロ不可） |
| `--iodepth <1-64>` | `1` | fio `--iodepth`（`ioengine=psync` では実質 1。記録用）。`^[1-9][0-9]{0,2}$`（先頭ゼロ不可） |
| `--numjobs <1-16>` | `1` | fio `--numjobs`。`^[1-9][0-9]{0,2}$`（先頭ゼロ不可） |

先頭ゼロを拒否する理由: 先頭ゼロを許すとシェル側の算術評価が 8 進数として解釈してしまい（例: `08` は無効な 8 進数リテラルとしてエラーになる）、入力エラーであるべきケースが「fio 実行失敗」等の別の終了コードに化ける、または無効な JSON 数値として渡ってしまうため。

`--rw`（`randwrite` 固定）・`--bs`（`4k` 固定）・`--ioengine`（`psync` 固定。libaio は Linux 専用のため移植性を優先）・`--end_fsync`（`1` 固定。write-back とフラッシュの意味論〔IO-2〕を含めて測るため）・`--group_reporting`（有効固定）は変更できない。有効値はすべて出力 JSON の `params` に記録する。run モードの fio 出力にも `--from-json` と同じ実行条件の照合をかけるため、`params` はどちらのモードでも fio JSON に記録された実行条件と一致する。

### 書き込み先の安全性（symlink 経由のボリューム外書き込み対策）

fio はデータファイルを `O_CREAT`（`O_EXCL` なし）で開き symlink をたどるため、`--target-dir` 直下の固定パスへ書かせると、事前に同名の symlink を置かれた場合にリンク先（ボリューム外の任意ファイル）を `--size` 分上書きしてしまう（security.md のパストラバーサル・symlink 対策）。そこで run モードは実行ごとに `mktemp -d` で `--target-dir` 内へ一意な名前の専用サブディレクトリ（`fandhe-fio-randwrite-4k.XXXXXXXXXX`・0700）を新規作成し、fio にはその中の固定ファイル名 `fandhe-fio-randwrite-4k.dat` だけを渡す。後始末はそのサブディレクトリを `rm -rf` で消すだけで、symlink をたどらない。

「symlink・既存ファイルなら拒否する」事前検査を採らないのは、検査から fio の open までの競合（TOCTOU）を原理的に塞げないため。`--target-dir` 直下に置かれた同名 symlink はそのまま残り、リンク先も変更されない（自己テストで照合する）。

### `--output` の排他作成

保証範囲: `--output` のパスが（検証後に置かれたものも含め）何らかの形で存在すれば、通常ファイル・ディレクトリ・FIFO・デバイス・それらを指す symlink・dangling symlink のいずれでも、書き込まずに終了コード 2 で止め、既存のエントリやリンク先を開かない・変更しない。事前検査（symlink・既存パスの拒否）は早期に分かりやすいエラーを返すためのもので、安全性は次の書き込み手順が担う。

1. 出力先と同じディレクトリに `mktemp` で新しい通常ファイル（`.fandhe-fio-output.XXXXXXXXXX`・0600。`O_CREAT|O_EXCL` で作られ既存の symlink をたどらない）を作り、結果を書く
2. `ln -n` で `--output` のパスへハードリンクを張る。link(2) は宛先が既に存在すれば（symlink を含む）失敗し、宛先の symlink をたどらない。`-n` は宛先がディレクトリを指す symlink のときにその中へ作らないためのもので、GNU・BSD（macOS）共通のオプションを使う（GNU 専用の `mv -T`/`ln -T` には依存しない。`--from-json` モードは macOS でも動く前提のため）
3. 検証後に実ディレクトリを置かれると `ln` はその中へリンクを作るため、`--output` のパスが一時ファイルと同一 inode の通常ファイル（symlink でない）であることを確かめ、違えば終了コード 2（この場合、置かれたディレクトリの中に一時ファイル名のハードリンクが残るが、既存のエントリは変更しない）
4. 一時ファイル名を消す（成否に関わらず EXIT 時の後始末でも消す）

一時ファイルをパス名で開き直して書くため、親ディレクトリが下記「ディレクトリの権限確認」を満たさない場合は拒否する（他ユーザーが一時ファイルを symlink へ差し替えられないようにするため）。`-` で始まる相対パスは `./` を前置して外部コマンドへ渡し、オプションとして解釈させない。制約として、ハードリンク非対応のファイルシステム（FAT 系等）では手順 2 が失敗して終了コード 2 になる。出力ファイルの権限は 0600 になる。

### ディレクトリの権限確認

本スクリプトがエントリを作るディレクトリ（`--target-dir` の正規化後のパス・`--output` の親ディレクトリ）は、次の両方を満たさなければ終了コード 2 で拒否する。作成直後のエントリを第三者が symlink へ差し替え、書き込みをディレクトリ外へ向けさせる競合を防ぐため。

- 所有者が実行ユーザーまたは root（ディレクトリの所有者は sticky bit があっても任意のエントリを rename・削除できるため）
- 他ユーザー書き込み不可、または sticky bit あり（`/tmp` 等の 1777 は可）

グループ書き込み可（775 等）は、ユーザープライベートグループ既定の環境で一般的なため許容する（同じグループのメンバーは信頼する前提）。判定は fail-closed で、`find` が「安全」と判定して終了コード 0 かつ出力がその判定結果と完全一致したときだけ通す。`find` の失敗・エラー出力・空出力はすべて拒否になる（空出力を合格とみなす判定は `find` の失敗時に素通りするため採らない）。

### 変換対象 JSON の読み取り

`--from-json` の入力と run モードの fio 出力は、検証と使用の間にパスを差し替えられても判定済みの内容と変換する内容がずれないよう、次の手順で 1 回だけ読む（TOCTOU 対策・DoS 防止）。

1. 本スクリプト専用の一時ディレクトリ（`mktemp -d`・0700）に `mktemp` でコピー先（0600）を作る
2. 元のパスを 1 回だけ open し、その fd が通常ファイルであることを確かめてから `head -c`（上限 +1 バイト）でコピーする。FIFO・デバイス等へ差し替えられた場合は終了コード 2。open が FIFO で止まる場合に備え、10 秒で打ち切る（`timeout` は macOS 標準環境に無いため `sleep` と `kill` の見張りで実装）
3. コピーのサイズを数値であることを確かめてから上限（4 MiB）と比較し、超えたら終了コード 2（`wc` の出力が非数値のときに比較が偽になって素通りするのを防ぐ）
4. 以後のサイズ判定・`jq` による変換はこのコピーだけを入力にする

検証後に元のパスを通常ファイルへの symlink に差し替えられた場合はリンク先を読む（読み取りのみで書き込みはしない。内容は untrusted として変換時にすべて検証する）。事前検査（symlink・存在・通常ファイルの確認）は分かりやすいエラーを早く返すためのもの。

### 後始末と終了コード

一時ディレクトリ・専用サブディレクトリ・`--output` 用の一時ファイルは EXIT 時に必ず消す。後始末の失敗は `warning: cleanup-failed` を stderr に出すだけで、終了コードの契約（0〜3）を上書きしない（`set -e` 下の EXIT trap で失敗したコマンドがあると、終了コードがその失敗の値に変わるため、元の終了コードを保存して終わる）。

## 出力スキーマ

`schema_version: 1`・`metrics.<name>.{value, unit}` は `scripts/check-bench-regression.sh` の results.json スキーマと互換で、そのまま回帰比較にかけられる（TASK-88・TASK-113 で再利用するかどうかはそれぞれの TASK の判断事項であり、本 PR では組み込まない）。

```json
{
  "schema_version": 1,
  "benchmark": "fio_randwrite_4k",
  "label": "docker_bind_mount",
  "fio_version": "fio-3.35",
  "target_kind": "run",
  "params": {
    "rw": "randwrite", "bs": "4k", "ioengine": "psync", "direct": 1,
    "size": "256m", "runtime": 30, "iodepth": 1, "numjobs": 1,
    "end_fsync": 1, "group_reporting": true, "filename": "fandhe-fio-randwrite-4k.dat"
  },
  "metrics": {
    "fio_randwrite_4k_iops": { "value": 1000.0, "unit": "ops/s" },
    "fio_randwrite_4k_lat_mean_us": { "value": 500, "unit": "us" },
    "fio_randwrite_4k_clat_p50_us": { "value": 400, "unit": "us" },
    "fio_randwrite_4k_clat_p95_us": { "value": 900, "unit": "us" },
    "fio_randwrite_4k_clat_p99_us": { "value": 1300, "unit": "us" }
  }
}
```

- `target_kind` は実行経路を表す（`run`: fio を実際に実行した、`from_json`: 既存出力の変換のみで実測を伴わない）。Docker ベースラインか fandhe 経路かの区別は `--label` で表現する契約
- `params` は run・`--from-json` のどちらのモードでも、fio JSON に記録された実行条件と照合済みの値である（照合内容は上記「`--from-json` モード」節。不一致なら出力せず終了コード 2）
- IOPS・レイテンシが 0 以下・欠落・非有限のときは出力せず、終了コード 2 で止める（fail-closed）
- fio 2.x 系の `lat`/`clat`（usec 単位・キー名も異なる）は非対応。`"fio version"` の major が 3 未満、または `lat_ns`/`clat_ns` キーが無い場合は終了コード 2 で拒否する
- 人が読む進捗・サマリーは stderr に出し、stdout は JSON のみ。`--output` を指定した場合はファイルを先に書き、その書き込みに失敗したときは stdout に何も出さず終了コード 2 で止める（呼び出し元は終了コード 0 のときだけ stdout を結果として読む）

## 終了コード

| コード | 意味 |
| ---- | ---- |
| 0 | 成功 |
| 1 | fio の実行失敗（exit 0 でも出力 JSON を書かなかった場合を含む）またはタイムアウト（`timeout` が保護する。SIGTERM で止まらない場合は 10 秒後に SIGKILL する。REPAIR-5） |
| 2 | 入力エラー（引数の検証失敗、fio JSON のスキーマ不正・実行条件の不一致、値が 0 以下、ファイルサイズ・総書き込み量の上限超過、symlink 等） |
| 3 | 前提ツールが無い（run モードでの fio・timeout・realpath。全モード共通で jq・grep・dirname・wc・tr・mktemp・find・ln・head・sleep・id） |

## 自己テスト（`scripts/fio-randwrite-4k-selftest.sh`）

`--from-json` モードと `scripts/testdata/fio-bench/` の固定 fixture、および最小の fio スタブ（受け取ったオプションを fio と同じ形で `job options` に記録した固定 JSON を書き出す）を使い、実 fio なしで終了コード・出力値・`check-bench-regression.sh` との round-trip 互換性、実行条件の照合（負例 fixture は照合を通る `job options` を持たせたうえで 1 点だけ壊し、拒否理由をメッセージで照合する。必須 14 項目は 1 つずつ欠落させた JSON を selftest 内で生成して照合する）、総書き込み量の上限の境界、および symlink・競合に対する書き込み先の安全性（上記「書き込み先の安全性」・「`--output` の排他作成」。検証後に通常ファイル・FIFO・ディレクトリを指す symlink や実ディレクトリを置く競合をスタブで再現する）を機械照合する（REPAIR-12）。`make fio-bench-selftest` から実行し、CI の `bench-regression` ジョブにも組み込む。run モードの実 fio を使った実行確認は「実機での確認」節を参照。

## 実機での確認（人間担当・TASK-25.2 との切り分け）

fio が導入された Linux 環境で `make fio-bench TARGET_DIR=<一時ディレクトリ> LABEL=local_tmp RUNTIME=5` を実行し、JSON が出力されること・実行後に target ディレクトリへ専用サブディレクトリ（`fandhe-fio-randwrite-4k.*`）とデータファイルが残らないことを確認する。実行条件の照合（`job options` の形）は fio 本体のソースから導いたもので実 fio では未確認のため、この実行が最初の実機照合になる。`unexpected fio options` や `jobs[0]["job options"] is missing` で終了コード 2 になった場合は、使用した fio の版が想定と異なる形でオプションを記録していることを意味するので、回避せず fio の版と出力 JSON を添えて報告する。Docker ベースライン比の実測・レポート・目標値案は TASK-25.2（#113）、目標値の妥当性判断は TASK-25.h1（#114。人間担当）で行う。
