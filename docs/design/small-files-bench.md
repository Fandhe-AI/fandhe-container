# 小ファイル多数ワークロードの files/s 計測ハーネス

TASK-189・IO-6・IO-7・REPAIR-8（関連: IO-1・IO-2・REPAIR-3・REPAIR-5）。計測定義の承認は #1897、実装は #1898。実装は `benches/src/small_files.rs`、入口は `benches/benches/small_files.rs`。

- 対象マイルストーン: MS-1 Phase 2（IO 系ベンチ。io-fio-bench と同じ）。REPAIR-8 の基準値登録は MS-2 Phase 3（bench-calibration.md と同じ）。spec が未取得の環境で既存設計文書から対応づけたため、spec と食い違う場合は spec を正とする

## 位置づけ

- IO-6（3〜5 万件の実機実測。#107）・IO-7（bind / named volume の比。#110）・REPAIR-8（主要ベンチ）が使う計測手段
- 回帰ゲート（`benches/metrics.json`・`scripts/lib.sh` の `BENCH_NAMES`・`baseline.json`・`make bench-check`）への登録は #1899 で `metrics.json`・`BENCH_NAMES`（段階登録）まで済み。baseline は未登録で、実測基準値の確定は #230（TASK-88.h1）。`make bench-check` / `make bench-baseline` は `scripts/lib.sh` の `bench_args_for` が決める固定引数（`--count 2000 --batch-size 1 --file-size 2 --layout tree --config bind --trials 3 --trial-timeout-secs 120 --timeout-secs 300`）で実行し、Windows では実行しない
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

- **経路（`--route`。#2074）**: 2 経路を持ち、`method`・`wire_path`・`params.route` で区別する。値の違う経路同士は比べない（`method` を必ず照合する）。

  | `--route` | 内容 | `method` | `wire_path` |
  | --------- | ---- | -------- | ----------- |
  | `server-api`（既定） | `BatchSink::write_batch` と `BatchSink::persist` を直接呼ぶ。`serve_connection` を通さず、フレームの符号化・復号・UDS を含まない | `server-api-direct/...` | `false` |
  | `wire` | UDS 越しに v2 のファイル操作（Create → WriteFile → Close → Flush。#1886 F6〜F9）を送る。client の符号化、UDS の往復、server の復号・実行・応答・FlushAck の待ちをすべて区間に含む。Linux と macOS のみ。それ以外は副作用の前に `unsupported-route` | `wire-uds/...` | `true` |

  - 既定を `server-api` にしたのは、`scripts/bench/small_files_compare.sh`（server-api の `method` と `wire_path == false` を固定で照合する）と、UDS の無い Windows の引数なしスモークを壊さないため。回帰ゲートの引数（`scripts/lib.sh` の `bench_args_for`）は `--route wire`
  - server-api 経路は残す。2 経路の差でワイヤーの上乗せ（フレーム化・UDS・ACK の往復）を分けて見られるため
  - wire 経路の 1 試行: server を `UdsServer` + `serve_file_connection_with_limit` のスレッドで動かし、client は `UdsClientConnection`（`same_effective_uid` で接続先 uid を照合）+ `PipelineClient`。ソケットは `--root` ではなく `std::env::temp_dir()` 下の専用ディレクトリ（0700。`fcsf-<pid>-<nanos>`）に置く（`sun_path` の上限のため）。接続・server の起動・body の用意・後始末・server の report の照合は区間に入れない
  - server の設定: バッチは `DEFAULT_BATCH_SIZE`（64。`params.server_batch_size`）、IO-10 の上限と保持表の上限は io crate の最大。K ごとの FLUSH が自動フラッシュで細かくならないよう、wire の `--batch-size` は 1..=4,095 に絞る（保持表の上限 4,096 に達すると明示 Flush の前に自動フラッシュが入るため）。超えたら `invalid-args`
  - デッドロックしない不変条件: client は 64 フレーム送るたびと Flush のたびにその分の応答を受けるため、未読の応答は高々 64 件。崩れても `recv_ack` の期限で `timeout` になる
  - 値を出す前に server の report を照合する（作成・書き込み・Close の件数、バイト数、Nack 0、自動フラッシュ 0、FlushAck の数、破棄 0、永続化失敗 0）。合わなければ `server-report-mismatch`（fail-closed）
  - `io2_guaranteed`: wire の per-file は `true`。wire の every-k は **`false`**。F9 の複数ファイル FLUSH（同じ接続で Ack を返した要求すべてが対象）を IO-2 の範囲と読んでよいかは #1886 の spec 確認事項 (b) の回答待ちで、回答が出たら見直す。every-k は Linux（syncfs）と macOS（ファイルごとの `F_FULLFSYNC` とディレクトリの同期）で受け付ける
  - 記録値との比較: #107・#110・#230 に small_files の記録値はまだ無く、失う比較は無い。#230 の基準値は、ゲートが測る wire 経路（`method == wire-uds/flush-per-file`）の値で作る。metric 名 `small_files_files_per_sec` は変えない（baseline に small_files の項目は無く、移行するものが無いため）
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
| `--route` | wire / server-api（wire は K が 1..=4,095 かつ Linux / macOS のみ） | server-api |
| `--trials` | 1..=20 | 5 |
| `--root` | 既存のディレクトリ | 一時ディレクトリ |
| `--trial-timeout-secs` | 1..=7,200 | 1,800 |
| `--timeout-secs` | 1..=86,400 | 10,800 |
| `--output` | オプションを 1 つでも渡したら必須 | — |

引数なし（`--bench` は無視）は件数 32 の 1 試行だけのスモークで、結果を標準出力へ出して終了コード 0 で終わる（永続化に対応しない環境では値を出さずに skip を表示して 0 で終わる）。範囲外・未知・値の欠落・重複は副作用の前に拒否し、標準エラーへ `{"error":{"code":"…","message":"…"}}` を出して非ゼロで終わる。

## 出力の読み方

`scripts/check-bench-regression.sh` の results スキーマ互換（`schema_version`・`metrics.small_files_files_per_sec.{value,unit}`）に加え、`method`・`wire_path`・`io2_guaranteed`・`note`・`aggregate`（`median`）・`persist_support`・`params`・`trials[]`（`elapsed_ns`・`files_per_sec`）を持つ。`value` は試行の中央値。絶対パス・ホスト名・ユーザー名は出さない。

## #107・#110 での使い方

- IO-6（#107）: `--route wire --count 50000` で実機の値を採る（ゲートと同じ経路。フレーム化と UDS の往復を含むため、Docker 側の「FS 操作のみ」と比べるときはこの上乗せを注記する）。Docker 側は同じ件数のフルサイクルの時間から `docker run` の起動時間を引いた「FS 操作のみ」の値と比べる。合否をこの値だけで出すかは未決
- IO-7（#110）: bind / named volume の 2 構成で同じ引数を使い、中央値の比を出す。比較スクリプトは server-api 経路のまま（wire へ切り替えるかは #110 で決める。#2074 のスコープ外）
  - 2 構成の実行は `make small-files-compare BIND_ROOT=<絶対パス> VOLUME_ROOT=<絶対パス> [TRIALS=<5〜20>] [OUTPUT=<新規ファイル>]`（TASK-24.1。`scripts/bench/small_files_compare.sh`）。同一引数で `--config bind` → `--config named-volume` の順に各 5 試行以上回し、ハーネスの結果 JSON（`method`・`note`・`wire_path`・`io2_guaranteed` を含む）を `results.bind` / `results["named-volume"]` に丸ごと残した 1 つの JSON（schema `fandhe-container.small-files-compare/v1`）にまとめる。形式は CSV ではなく JSON にした（ハーネスの出力が JSON で、`method`・`note` の文字列を欠けなく運べるため）
  - このスクリプトは合否も中央値の比も出さない。比と 1.5 倍の判定は #110（TASK-24.2）で行う。実機での実測は #107（人間）
  - 既知の限界: 実行順は bind → named-volume で固定（順序の偏りは交互化していない。必要なら #110 で判断する）。2 つのルートは別ディレクトリであることだけを確かめ、別の file system かどうかは確かめない

## 既知の限界

- 平置きでは `create_file` が作成のたびに祖先ディレクトリの実在エントリを読み直すため、N 件で約 N²/2 の走査になり、計測値に含まれる。ツリー配置では 1 回あたり高々約 452 件
- K ファイルごとの FLUSH は IO-2 の保証外。server-api 経路は Linux のみ、wire 経路は Linux と macOS（`io2_guaranteed` の扱いは #1886 の spec 確認事項 (b) の回答待ち）
- wire 経路: 1 回の FLUSH が `MAX_IO_TIMEOUT`（10 秒）を超えると値を出さずに失敗する。Linux では保持する `Close` 済みファイルが K 個の fd を持つため、`RLIMIT_NOFILE` が K に足りないと失敗する。server スレッドは強制停止できず、終わらなければプロセスの終了に任せる。Windows は非対応
- 2 構成は置き場所の違いを呼び出し側が与えるラベルで、`VolumeProvider` の実装は対象外（担当と時期は [volume-provider-implementation.md](volume-provider-implementation.md) で判断待ち・#2451）
- 期限は協調的で、`create_file` の内部で止まった syscall には割り込めない
