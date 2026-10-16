# 小ファイル多数ワークロードの files/s 計測ハーネス

TASK-189・IO-6・IO-7・REPAIR-8（関連: IO-1・IO-2・REPAIR-3・REPAIR-5）。計測定義の承認は #1897、実装は #1898。実装は `benches/src/small_files.rs`、入口は `benches/benches/small_files.rs`。

## 位置づけ

- IO-6（3〜5 万件の実機実測。#107）・IO-7（bind / named volume の比。#110）・REPAIR-8（主要ベンチ）が使う計測手段
- 回帰ゲート（`benches/metrics.json`・`scripts/lib.sh` の `BENCH_NAMES`・`baseline.json`・`make bench-check`）への登録は #1899。本ハーネスはゲート未接続
- 実測値はこの文書に書かない（実機実測は人間担当の #107・#230）

## 承認された計測定義（#1897）

| 項目 | 内容 |
| ---- | ---- |
| 1 file の区間 | `create_file` → 固定長の write を 1 回（既定 2 バイト）→ その write が永続化されるまで。files/s = 件数 ÷（最初の `create_file` の直前から最後の永続化の完了まで）。作業ディレクトリの用意・`GuestFileCreator` の構築・書き込む `Batch` の組み立て・削除は区間に入れない |
| FLUSH の位置 | 1 ファイルごと（既定。IO-2 の契約どおり）と K ファイルごと（参考値。IO-2 の保証外）を引数で選ぶ |
| 配置 | 2,000 件は平置き、3〜5 万件は決定的な合成ツリー（1 ディレクトリ 256 件まで）。祖先ディレクトリの作成は区間に入る |
| 2 構成 | 書き込み先の置き場所の違いで表す。ハーネスはパスと構成名を受け、結果に構成名を記録する |
| Docker との比較 | いまは「FS 操作のみ」同士（Docker 側はフルサイクルの時間から `docker run` の起動時間を引く）。IO-6 の合否をこの値だけで出すかは未決 |
| 集計 | 試行の中央値（IO-7 が中央値で判定）。各試行の値も出す |

## 実装で決めた細部

- **ワイヤー経路ではない**: いまのワイヤー形式（IO-1）の `Write` はパスを持たず、1 接続で多数のファイルを作る要求を表せない。`BatchSink::write_batch` と `BatchSink::persist` を直接呼ぶ。`serve_connection` を通さないのは、`create_file` が 1 ファイルにつき 1 つの sink を返すのに対し `serve_connection` は 1 接続で 1 つの sink しか扱えず、フレームの符号化・復号のコストが区間に混ざるため。ワイヤー経路への切り替えは #1886 の後に別 issue で行う
- **Write フレーム**: `SendQueue`・`encode_request`・`BatchBuffer` の公開 API だけで組み立てる（REPAIR-2）。区間の外で 1 回だけ作り、全ファイルで使い回す。書き込み報告は `frames_written == 1`・`bytes_written == file_size` を照合する
- **`method`**: `server-api-direct/flush-per-file`（`io2_guaranteed: true`）と `server-api-direct/flush-every-k`（`io2_guaranteed: false`）。後者は K 件ごと（と最後）にだけ永続化する。Linux の `syncfs` が file system 全体を書き戻すことに依存するため、`PersistSupport::Supported` の環境だけが受け付け、それ以外は副作用の前に `unsupported-flush-mode` で拒否する。macOS / Windows の永続化は sink のファイルと親ディレクトリしか同期しないため
- **配置**: 平置きは `f{i:05}`、ツリーは `d{i/256:03}/f{i%256:03}`（例: 257 件目 = `d001/f001`、5 万件目 = `d195/f079`）。「2 階層」は「ディレクトリ 1 段＋ファイル」（パスの深さ 2）と解釈した。`--layout auto` は件数 2,000 以下なら平置き、それより多ければツリー
- **2 構成はラベル**: `--config bind|named-volume` は結果に記録するだけで挙動を変えない。いまの main に `VolumeProvider` の実装は無く、置き場所の違いは呼び出し側が `--root` で与える（REPAIR-3）
- **期限（REPAIR-5）**: 試行ごと（`--trial-timeout-secs`）と全体（`--timeout-secs`）。各ファイルの処理の前に照合する協調的な期限で、`create_file` の内部で止まった syscall には割り込めない。永続化は `IoTimeout`（`MAX_IO_TIMEOUT` 以下）で切る。切れたら値を出さず `timeout` で非ゼロ終了する
- **後始末**: `--root` の下に新しく作る専用サブディレクトリ（`fandhe-small-files-<pid>-<nanos>`。unix では 0700）だけを、終了時（失敗時を含む）に消す。symlink は辿らず、差し替えられていたら消さずに残す。`--root` の既存の内容には触れない

## 実行方法

```bash
# bind mount 相当（利用者が指定したホストのディレクトリ）
cargo bench -p fandhe-container-benches --bench small_files -- \
  --count 50000 --config bind --root <ホストのディレクトリ> --output <結果 JSON>

# named volume 相当（ランタイムが管理するディレクトリ）
cargo bench -p fandhe-container-benches --bench small_files -- \
  --count 50000 --config named-volume --root <ランタイム管理のディレクトリ> --output <結果 JSON>
```

| 引数 | 範囲 | 既定 |
| ---- | ---- | ---- |
| `--count` | 2,000..=50,000 | 2,000 |
| `--batch-size`（K） | 1..=4,096 かつ count 以下 | 1 |
| `--file-size`（バイト） | 1..=65,536 | 2 |
| `--layout` | auto / flat / tree | auto |
| `--config` | bind / named-volume | bind |
| `--trials` | 1..=20 | 5 |
| `--root` | 既存のディレクトリ | 一時ディレクトリ |
| `--trial-timeout-secs` | 1..=7,200 | 1,800 |
| `--timeout-secs` | 1..=86,400 | 10,800 |
| `--output` | オプションを 1 つでも渡したら必須 | — |

引数なし（`--bench` は無視）は件数 32 の 1 試行だけのスモークで、結果を標準出力へ出して終了コード 0 で終わる（永続化に対応しない環境では値を出さずに skip を表示して 0 で終わる）。範囲外・未知・値の欠落・重複は副作用の前に拒否し、標準エラーへ `{"error":{"code":"…","message":"…"}}` を出して非ゼロで終わる。

## 出力の読み方

`scripts/check-bench-regression.sh` の results スキーマ互換（`schema_version`・`metrics.small_files_files_per_sec.{value,unit}`）に加え、`method`・`wire_path`・`io2_guaranteed`・`note`・`aggregate`（`median`）・`persist_support`・`params`・`trials[]`（`elapsed_ns`・`files_per_sec`）を持つ。`value` は試行の中央値。絶対パス・ホスト名・ユーザー名は出さない。

## #107・#110 での使い方

- IO-6（#107）: `--count 50000` で実機の値を採る。Docker 側は同じ件数のフルサイクルの時間から `docker run` の起動時間を引いた「FS 操作のみ」の値と比べる。合否をこの値だけで出すかは未決
- IO-7（#110）: bind / named volume の 2 構成で同じ引数を使い、中央値の比を出す

## 既知の限界

- 平置きでは `create_file` が作成のたびに祖先ディレクトリの実在エントリを読み直すため、N 件で約 N²/2 の走査になり、計測値に含まれる。ツリー配置では 1 回あたり高々約 452 件
- K ファイルごとの FLUSH は IO-2 の保証外で、Linux のみ
- 2 構成は置き場所の違いを呼び出し側が与えるラベルで、`VolumeProvider` の実装は対象外
- 期限は協調的で、`create_file` の内部で止まった syscall には割り込めない
