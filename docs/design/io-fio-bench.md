# fio 4K ランダム write ベンチスクリプト

`scripts/fio-randwrite-4k.sh`（DB 書き込み相当の 4K ランダム write ワークロードを fio 経由で計測し、IOPS・レイテンシを機械可読形式で出力するスクリプト）の前提条件・使い方・パラメータ・出力スキーマ・終了コードを記録する。

- 対象ビヘイビア: IO-8（fio 4K ランダム write ベンチ実施・目標値設定。DB 書き込み相当のワークロードを I/O 共有プロトコル経由で実行し、Docker ベースライン比で IOPS を計測する）
- 関連タスク: TASK-25.1（#112。本スクリプトの実装）・TASK-25.2（#113。Docker ベースライン比の実測と目標値案。人間共同）・TASK-25.h1（#114。目標値の妥当性判断。人間担当）
- 対象マイルストーン: MS-1 Phase 2
- ステータス: 本ドキュメントは TASK-25.1 で確定したスクリプトの契約（前提条件・パラメータ・出力スキーマ・終了コード）を記録する。Docker ベースラインの実測レポートと目標値案は TASK-25.2 が追記する

## 現状の制約（実装済みを装わない。REPAIR-3）

fandhe-container の I/O 共有プロトコル経由の共有マウントはまだ公開されていない（クライアント側 UDS・ディスクへの書き込み・共有ファイルシステムとしてのマウントは TASK-13.2.2 以降）。そのため本スクリプトは書き込み先を `--target-dir` で受け取る汎用の形にし、`--label` で計測対象（Docker の bind mount / named volume のパスか、将来公開される fandhe 経路か）を出力に記録する契約とする。**fandhe 経路の実測は、共有マウントを公開する後続 TASK を待つ（IO-8）。** 本 PR（TASK-25.1）ではスクリプト本体と自己テストのみを実装し、Docker ベースライン比の実測・目標値の判断は行わない（TASK-25.2・TASK-25.h1）。

## 前提条件

- **run モード**（実際に fio を実行する）: fio 3.x 以上（`lat_ns`/`clat_ns` 等の `*_ns` キーを出力する版）・GNU coreutils の `timeout`・`realpath`・`find`・`jq`。**Linux ホストのみ対象**（GNU `timeout` が無い macOS 標準環境・Windows は対象外。VM ゲスト経由の経路は後続 TASK で扱う）
- **`--from-json` モード**（既存の fio JSON 出力を変換するだけ）: `jq`（fio・`timeout` は不要）。bash と jq だけで動くため、fio 未導入の CI・ローカル環境でも自己テストが完結する
- **全モード共通**: `grep`・`dirname`・`wc`・`tr`・`mktemp`（欠如時は終了コード 3。欠如したまま進むと別の終了コードへ誤分類されるため事前に検出する）
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
fio --name=x --rw=randwrite --bs=4k --size=256m --runtime=30 --time_based \
    --ioengine=psync --direct=1 --end_fsync=1 --group_reporting \
    --output-format=json --output=/tmp/fio-out.json --directory=/path/to/target
bash scripts/fio-randwrite-4k.sh --from-json /tmp/fio-out.json --label docker_bind_mount
```

### 共通オプション

| オプション | 既定値 | 説明 |
| ---- | ---- | ---- |
| `--target-dir <dir>` | （run モード必須） | fio の書き込み先ディレクトリ。symlink 拒否・書き込み可能なディレクトリであることを検証してから `realpath` で正規化する。正規化後のパスに `:` を含む場合も拒否する（fio が `--directory`/`--filename` の `:` をディレクトリ・ファイル名リストの区切り文字として解釈するため）。他ユーザー書き込み可能で sticky bit が無いディレクトリも拒否する（`/tmp` 等の 1777 は可）。データファイルは下記「書き込み先の安全性」のとおり、このディレクトリ内に実行ごとに作る専用サブディレクトリへ書く |
| `--from-json <path>` | （from-json モード必須） | 既存の fio `--output-format=json` 出力へのパス。symlink 拒否・サイズ上限（4 MiB）あり |
| `--label <label>` | 必須 | `^[a-z0-9_-]{1,64}$`。出力 JSON にそのまま記録し、計測対象（Docker ベースラインか fandhe 経路か等）を表す |
| `--output <path>` | （出力しない） | 指定時、結果 JSON をこのパスにも書く。symlink 拒否・既存ファイルへの上書きは拒否する。親ディレクトリの存在・書き込み可否も事前検証する（未検証のまま書き込みに失敗すると、呼び出し元が終了コード 1「fio 実行失敗」と誤認するため）。書き込み自体も noclobber（対象が無ければ `O_CREAT\|O_EXCL`）で行い、検証後に symlink・ファイルを置かれた場合は書かずに終了コード 2 で止める（bash の noclobber の仕様上、FIFO・デバイス等の通常ファイル以外を指す symlink を検証後に置かれた場合は対象外） |
| `--direct 0\|1` | `1` | fio `--direct`。tmpfs・FUSE 系の共有 FS では O_DIRECT が失敗しうるため変更できる |
| `--size <NkNmNg>` | `256m` | fio `--size`。`^[1-9][0-9]{0,5}[kmg]$`（先頭ゼロ不可）かつ 10 GiB 以下（DoS 防止の上限） |
| `--runtime <1-600>` | `30` | fio `--runtime`（秒。`--time_based` と併用）。`^[1-9][0-9]{0,3}$`（先頭ゼロ不可） |
| `--iodepth <1-64>` | `1` | fio `--iodepth`（`ioengine=psync` では実質 1。記録用）。`^[1-9][0-9]{0,2}$`（先頭ゼロ不可） |
| `--numjobs <1-16>` | `1` | fio `--numjobs`。`^[1-9][0-9]{0,2}$`（先頭ゼロ不可） |

先頭ゼロを拒否する理由: 先頭ゼロを許すとシェル側の算術評価が 8 進数として解釈してしまい（例: `08` は無効な 8 進数リテラルとしてエラーになる）、入力エラーであるべきケースが「fio 実行失敗」等の別の終了コードに化ける、または無効な JSON 数値として渡ってしまうため。

### 書き込み先の安全性（symlink 経由のボリューム外書き込み対策）

fio はデータファイルを `O_CREAT`（`O_EXCL` なし）で開き symlink をたどるため、`--target-dir` 直下の固定パスへ書かせると、事前に同名の symlink を置かれた場合にリンク先（ボリューム外の任意ファイル）を `--size` 分上書きしてしまう（security.md のパストラバーサル・symlink 対策）。そこで run モードは実行ごとに `mktemp -d` で `--target-dir` 内へ一意な名前の専用サブディレクトリ（`fandhe-fio-randwrite-4k.XXXXXXXXXX`・0700）を新規作成し、fio にはその中の固定ファイル名 `fandhe-fio-randwrite-4k.dat` だけを渡す。後始末はそのサブディレクトリを `rm -rf` で消すだけで、symlink をたどらない。

「symlink・既存ファイルなら拒否する」事前検査を採らないのは、検査から fio の open までの競合（TOCTOU）を原理的に塞げないため。`--target-dir` 直下に置かれた同名 symlink はそのまま残り、リンク先も変更されない（自己テストで照合する）。

`--rw`（`randwrite` 固定）・`--bs`（`4k` 固定）・`--ioengine`（`psync` 固定。libaio は Linux 専用のため移植性を優先）・`--end_fsync`（`1` 固定。write-back とフラッシュの意味論〔IO-2〕を含めて測るため）・`--group_reporting`（有効固定）は変更できない。有効値はすべて出力 JSON の `params` に記録する。

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
- `--from-json` モード（`target_kind: "from_json"`）の `params` は、**変換時に渡した本スクリプトの CLI 引数（既定値含む）であり、元の fio 実行が実際にどの条件で行われたかを保証しない**。呼び出し元が測定条件を記録として残したい場合は、変換時に元の fio 実行と同じ値を `--size`・`--runtime`・`--iodepth`・`--numjobs`・`--direct` へ明示的に渡す
- IOPS・レイテンシが 0 以下・欠落・非有限のときは出力せず、終了コード 2 で止める（fail-closed）
- fio 2.x 系の `lat`/`clat`（usec 単位・キー名も異なる）は非対応。`"fio version"` の major が 3 未満、または `lat_ns`/`clat_ns` キーが無い場合は終了コード 2 で拒否する
- 人が読む進捗・サマリーは stderr に出し、stdout は JSON のみ

## 終了コード

| コード | 意味 |
| ---- | ---- |
| 0 | 成功 |
| 1 | fio の実行失敗またはタイムアウト（`timeout` が保護する。SIGTERM で止まらない場合は 10 秒後に SIGKILL する。REPAIR-5） |
| 2 | 入力エラー（引数の検証失敗、fio JSON のスキーマ不正、値が 0 以下、ファイルサイズ超過、symlink 等） |
| 3 | 前提ツールが無い（run モードでの fio・timeout・realpath・find。全モード共通で jq・grep・dirname・wc・tr・mktemp） |

## 自己テスト（`scripts/fio-randwrite-4k-selftest.sh`）

`--from-json` モードと `scripts/testdata/fio-bench/` の固定 fixture、および最小の fio スタブ（固定 JSON を書き出すだけ）を使い、実 fio なしで終了コード・出力値・`check-bench-regression.sh` との round-trip 互換性、および symlink・競合に対する書き込み先の安全性（上記「書き込み先の安全性」・`--output` の排他作成）を機械照合する（REPAIR-12）。`make fio-bench-selftest` から実行し、CI の `bench-regression` ジョブにも組み込む。run モードの実 fio を使った実行確認は「実機での確認」節を参照。

## 実機での確認（人間担当・TASK-25.2 との切り分け）

fio が導入された Linux 環境で `make fio-bench TARGET_DIR=<一時ディレクトリ> LABEL=local_tmp RUNTIME=5` を実行し、JSON が出力されること・実行後に target ディレクトリへ専用サブディレクトリ（`fandhe-fio-randwrite-4k.*`）とデータファイルが残らないことを確認する。Docker ベースライン比の実測・レポート・目標値案は TASK-25.2（#113）、目標値の妥当性判断は TASK-25.h1（#114。人間担当）で行う。
