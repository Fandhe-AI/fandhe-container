# CRI ログの部分行 `P` の方式（CRI-2・SUP-7・REPAIR-3）

issue #4116 の項目 8（2026-11-12 にオーナーが「追跡する: 方式の設計から」と判断）を受けた設計記録（#4574）。実装は #4580・#4582（どちらも実装済み）。`fandhe logs` の扱いは #4581 でオーナーが (a) 現状維持と判断（2026-11-13。下の「実装 issue」）。

## 目的

kubelet・crictl が読む CRI ログ（`--cri-log-path`）に、次の差がある。

1. **64 KiB を超える行の欠落**: 捕捉側が 1 行を `MAX_LINE_BYTES`（64 KiB）で切り詰めて超過分を捨てる。containerd は長い行を部分行 `P` に分けて残す。大きな JSON のログなどが、この実装でだけ途中から失われる
2. **LF の無い出力の滞留**: tty のプロンプトなど、LF・EOF・上限のどれも来ない出力は CRI ログに出ない

どちらを、どの方式で埋めるか（または埋めないか）を決める。

## 現状の経路と 2 つのレコード形式（R1）

```text
コンテナの stdout / stderr
  → 捕捉リーダー（logs/reader.rs → LineSplitter。LF・EOF・MAX_LINE_BYTES で行にする）
  → TeeLogSink（logs/cri.rs。出力先ごとに失敗状態を持つ）
      ├─ ① RotatingFileSink（@container-logs。fandhe logs が読む）
      └─ ② CriFileSink（--cri-log-path。kubelet・crictl が読む）
```

| 項目 | ① `@container-logs` | ② CRI ログ |
| ---- | ------------------- | ---------- |
| 形式 | `stdout` / `stderr` のタグ（後ろに空白）+ 行 + LF | `<RFC3339Nano> <stdout\|stderr> <F\|P> <内容>\n` |
| 1 行の上限 | `MAX_LINE_BYTES`（64 KiB）。`Scanner` が超過を `Malformed` にする | 書き手が 16 KiB（`CRI_LOG_CHUNK_BYTES`）ごとに `P…P F` へ分ける。**P への分割は既にある** |
| 読み手 | CLI の `logs`（`--tail`・`--stream`・`--escape`・`--follow`） | kubelet・crictl |

64 KiB を超えた分が CRI ログで失われる原因は、手前の `LineSplitter` の切り詰め（`StreamSummary::truncated_lines` に数える）で、`CriFileSink` ではない。Attach の出力は捕捉の tap（#4072）が生のチャンクを複製するため、この経路の影響を受けない。

## 一次情報（出典を固定して原文で確認）

- containerd v2.1.0（commit `fcfeb3fe8f3b1aad04c54f569b8de8d3d12cca8e`）`internal/cri/io/logger.go` の `redirectLogs` / `readLine`
  - 1 行が `maxLen`（`max_container_log_line_size`）を超えると、`maxLen` ちょうどで切って `P` で書き、残りを次へ持ち越す。LF で終わった行の最後が `F`
  - **EOF（または読み取りエラー）で LF の無い末尾が残ると、`P` で書いて止まる**（コメント「it should be treated as a partial line」）。`F` ではない
  - **期限・タイマーでの書き出しは無い**。`bufio.Reader`（大きさは `min(4096, maxLen)`）が満ちると `isPrefix` で内容を溜め続け、LF か EOF か `maxLen` 超過まで書かない
  - 読み取りエラーでも、溜めた内容は `P` で書く（EOF と同じ）
  - タイムスタンプはレコードを書く時点の `time.Now()`（レコードごと）
  - `\r\n` の `\r` は落とす（`readLine`）
- containerd v2.1.0 `internal/cri/config/config.go`: `max_container_log_line_size` は「これを超える行は複数行に分ける。非正の値は無制限」。既定値は 16384
- Kubernetes v1.34.0（commit `275918a59a3df182fc5e9f7f9f6e960384399a35`）`staging/src/k8s.io/cri-client/pkg/logs/logs.go` の `parseCRILog`: タグが `P` のレコードは末尾の LF を落として内容だけを表示し、`F` は LF を付けて表示する。`LogTagPartial`・`LogTagFull` は cri-api の定数

## 論点と決定

### 論点 A: 64 KiB を超える行（採る: A3）

| 案 | 内容 | 判断 |
| -- | ---- | ---- |
| A1 | 現状維持（切り詰め） | 却下。大きな行がこの実装でだけ失われる |
| A2 | `MAX_LINE_BYTES` を上げる | 却下。切り詰めは残り、リーダーごとのメモリが増え、`@container-logs` の検証値と `MIN_LOG_FILE_BYTES` にも波及する |
| **A3** | **捕捉側が「行の断片」を sink へ渡し、断片の扱いは sink ごとに決める** | **採る** |
| A4 | `@container-logs` にも部分行の印（新しいタグ）を入れる | 却下。`Scanner`・raw 出力・`--follow`（完全な行だけ出す）・`--tail` の数え方が変わり、旧 CLI は新しいファイルを `Malformed` で読めなくなる。#4581 の判断（(a) 現状維持。2026-11-13）で採らない |

A3 の設計:

- `LogSink` に `append_part(stream, bytes, part: LinePart)` を足す。`LinePart` は `#[non_exhaustive]` で、`index`（何番目の断片か）・`end`（`Continued` / `Lf` / `Eof`）・`head`（その行の先頭断片のバイト列。`index == 0` では空）を持つ
- `LineSplitter` は、バッファが `MAX_LINE_BYTES` に達しても LF が無ければ、そこまでを `Continued` で渡して読み続ける。ただし先頭断片（64 KiB）は `head` として splitter 側に保持し続け、行が終わる（`Lf` / `Eof`）か破棄（`discard_partial`）されるまで手放さない。メモリは従来の 1 ストリーム 64 KiB 以下から、先頭断片 + 作業バッファの 128 KiB 以下に増える（有界。CORE-7 の常駐メモリへの影響は実装 issue で計測する）
  - 実装での補足（#4580）: `Continued` は満杯の状態で LF 以外の次のバイトが来た時点で渡す（ちょうど 64 KiB で終わる行は 1 断片）。長い行の処理中だけストリームあたり約 +64 KiB で、行の終端で解放するためアイドル時は不変（実測は未実施）
- **トレイトの既定実装で現行の挙動を残す**（既存 sink への追記を行の終端まで遅延させる）: `Continued` では何もしない。`end` が `Lf` / `Eof` なら、`index == 0` はその `bytes`、`index > 0` は `head` を `append(stream, ...)` する（現行の切り詰めと同じバイト列）。読み取りエラーで終わった行は `Continued` しか渡っておらず、`discard_partial` が `head` ごと破棄するので、既定実装の sink には何も追記されない。LF の無い 64 KiB の出力が `@container-logs` に完全なレコードとして残ったり、`--follow` に終端前に表示されたりする退行は起きない。`RotatingFileSink`・`MemoryLogSink`・`DiscardLogSink` と試験用の sink は変更不要で、`@container-logs` のレコード形式・`Scanner` の検証・CLI の `logs` の全オプション・既存ログファイルの読み取りは変わらない（R2 の互換）
- `CriFileSink` は上書きする: `Continued` は全チャンク `P`、`Lf` は最後のチャンクだけ `F`、`Eof` は全チャンク `P`（containerd と同じ）
- `MAX_LINE_BYTES`（64 KiB）は `CRI_LOG_CHUNK_BYTES`（16 KiB）の倍数なので、断片の境界と CRI のチャンクの境界が揃う。`const` の表明で固定する
- `TeeLogSink` は断片を両方へ渡す。出力先ごとの失敗状態は変えない
- `truncated_lines` の意味は「`@container-logs` で切り詰めた行数」とする。CRI ログ側では欠落しない
- 総量は従来どおり `CRI_LOG_MAX_BYTES`（50 MiB）で頭打ち。LF の無い巨大な出力でも、ディスクへの書き込みは有界

### 論点 B: LF の無い出力を期限で `P` として書き出すか（採らない）

- 不採用。containerd も期限では書き出さない（上の一次情報）
- 書き出すにはリーダーにタイマーか read の期限が要り、read の期限は `sys` の宣言と `unsafe` を、タイマーは追加のスレッドを増やす。行が任意の位置で細切れになる
- 対話の用途は Attach の tap（#4072）が生バイト列で担う
- 残る差: tty のプロンプトは LF・EOF・64 KiB のどれかまで CRI ログに出ない。期限で書き出さない点は containerd と同じだが、可視化される閾値は異なる（containerd は 16 KiB 超で `P` を書き、本設計は捕捉側が 64 KiB に達するまで `Continued` を渡さない）。LF のない 32 KiB を出して待機するプロセスでは、containerd は先頭部分を可視化し、本設計は全量が滞留する

### 論点 C: 読み取りエラーで終わった未完了の末尾

- 現行の契約（途中で欠けた内容を正常な行として残さない。`discard_partial`）を保つ。`@container-logs`（既定実装）には、先頭断片の `head` も含め何も追記しない。CRI 側にもその末尾（書き出されていない作業バッファ）は書かない
- containerd はこの末尾も `P` で書くため差になる（下の表）。それより前の `Continued` 断片は書き済みで、CRI ログは `F` の無い `P` で終わることがある。kubelet は LF なしで表示する

### 論点 D: 再起動をまたぐ sink と `Eof` の `P`

- `Eof` を `P` にすると、同じ CRI ログを次の実行が使い回した場合に、kubelet の表示で前回の末尾と次の行がつながる
- CRI のコンテナは supervisor に `--restart` を渡さず（既定の `no`。`docs/design/cri-record-readoption.md`）、kubelet が `<containerName>/<restartCount>.log` を新しく作る。使い回しは起きないため `Eof` は `P` にする（containerd と同じ）
- 前提が崩れる経路（同じ書き先への再 launch）が見つかったら、`Eof` を `F` にするか再 launch の前に区切るかを、そのとき決める

## containerd との差・残る差

| 項目 | 本実装（採用後） | containerd |
| ---- | ---------------- | ---------- |
| チャンクの大きさ | 16 KiB に固定（設定できない） | `max_container_log_line_size` で変えられる（非正で無制限） |
| 期限での書き出し | しない | しない（同じ） |
| LF のない出力が CRI ログに出る閾値 | 64 KiB（`MAX_LINE_BYTES`）に達するまで滞留 | `max_container_log_line_size`（既定 16 KiB）超で `P` を書く（差） |
| EOF の末尾のタグ | `P` | `P`（同じ） |
| 読み取りエラーの末尾 | 捨てる（`discard_partial`） | `P` で書く（差） |
| 総量の上限 | 50 MiB で書き出しを止める。開き直し（`ReopenContainerLog`・#4652）で新しいファイルのサイズから数え直して再開する。長い行の途中で達すると `F` の無い `P` で終わる（kubelet は LF なしで表示） | 上限なし（kubelet の回転に任せる） |
| 開き直しの途中の部分行 | `P` の途中で開き直すと、新しいファイルは続きの断片から始まる（区切りを保証しない） | 保証しない（同じ） |
| `ReopenContainerLog` の対象外 | running でないコンテナは `FAILED_PRECONDITION`。新しいファイルを作らない（cri-api の MUST NOT） | 同じ（containerd は not running をエラーにする） |
| タイムスタンプ | 1 断片に 1 時刻（断片内の複数チャンクは同じ時刻） | レコードごと |
| `\r\n` | `\r` を残す（現行） | `\r` を落とす（`readLine`） |
| `fandhe logs`（`@container-logs`） | 64 KiB で切り詰めたまま（#4581 の判断: (a) 現状維持。2026-11-13）。CRI 経由で行全体を見るには kubelet のログ（`crictl logs` を含む）を使う | 対象外 |

## セキュリティ・資源の観点（OWASP / SEC）

- 不安全な設計: 断片は `MAX_LINE_BYTES` 以下で、メモリはストリームごとに有界。期限での書き出しを採らないのでタイマーのスレッドも read の期限の `unsafe` も増えない。LF の無い巨大な出力は、捨てる代わりに `CRI_LOG_MAX_BYTES` で有界に書く
- インジェクション: 断片は LF を含まない（`LineSplitter` が LF で分ける）ので、CRI のレコード（タイムスタンプ・タグ・LF）を偽装する行は作れない。`CriFileSink` は LF を含む入力を引き続き拒否する
- 情報の露出: 行の内容は不透明なバイト列のまま扱い、エラー・op ログ・telemetry に内容・パス・errno を出さない（ERR-1）
- アクセス制御: 開き方（`O_NOFOLLOW`・親の検査・ambient capability での拒否・`flock`）は変えない
- 新しい依存・`unsafe`・特権操作は無い

## 実装 issue と依存の順

| issue | 内容 | 依存 |
| ----- | ---- | ---- |
| #4580（実装済み） | `LogSink::append_part` と `LinePart` を足し、`LineSplitter` が断片を渡す（既定は現行の切り詰め） | なし |
| #4582（実装済み） | `CriFileSink`・`TeeLogSink` が断片を `P` / `F` で書く。kubelet と同じ規則で連結する解析の試験。関連文書の状況欄を直す | #4580 |
| #4581 | `fandhe logs` でも 64 KiB 超の行を残すかの判断。**決定済み: (a) 現状維持（2026-11-13・オーナー判断）**。(b) は採らない | 完了 |

親は #4474（#4581 は #816）。

## ReopenContainerLog との関係（CRI-2・SUP-7・REPAIR-3・REPAIR-5・TASK-59・TASK-164・MS-4・MS-9。#4652）

- kubelet がログを回転するとき、rename の後に `ReopenContainerLog` を呼ぶ。supervisor は同じパスを開き直す（制御チャネルの kind 10。`CriFileSink::reopen`）
- 別 inode（rename 済み）のときだけ切り替える。新しいファイルは先に開いて検査し、失敗なら既存の書き込み先を変えずエラーにする。親ディレクトリは作らない
- 親ディレクトリは検査した後に `O_DIRECTORY|O_NOFOLLOW` で開いた fd に固定し、ファイルはその fd からの `openat` で開く（既存なら追記で開き、無ければ `O_CREAT|O_EXCL`・0640 で作る）。検証・ロックした fd がそのまま元のパスのファイルになり、名前を引き直さない。失敗・拒否の後始末は、名前が今回作った inode（dev・ino の一致）を指すときだけ `unlinkat` で消す（他者のファイルは消さない）。残余: 照合と `unlinkat` の間（マイクロ秒）に kubelet が回転済みのファイルを元の名前へ rename で戻すと、それを消しうる。Linux に「同じ inode のときだけ消す」原語が無いため閉じられない。親は `check_dir` で得た実体パスを `/` から 1 要素ずつ `openat(O_DIRECTORY|O_NOFOLLOW)` で辿って開き、開いた各祖先の fd を `fstat` で確かめる（所有者が root か自分で、other が書き込めるなら sticky、group 書き込み可は root 所有か sticky のときだけ。Ubuntu の `/var/log` は `root:syslog 0775` のため、root 所有の group 書き込み可は管理用のグループに委ねた配置として通す）。最後のディレクトリは所有者が root か自分で、group / other が書き込めないこと（sticky の祖先の直下に他人が作ったディレクトリを受けない）。祖先を名前で引き直さないため、検査と open の間の祖先の差し替えは通らない。既存の `open`（`ensure_parent_dir`）は祖先の権限を見ず、祖先に書き込める主体への露出が残る（#4913）。確定の直前には、元の名前が書き手にする inode を今も指すことを照合する。照合から確定までと確定の後に名前を移されると書き込み先と元のパスは分かれうるが、Linux にはディレクトリのエントリを固定する手段が無く閉じられない。既存のファイルへ切り替えるときは、別 inode ならリンクが 1 本のものだけ受ける（ログディレクトリの外の inode へのハードリンクへ移さない）。既知の制約: 新しいファイルは検証した fd をそのまま公開するため（一時名・`O_TMPFILE` と `linkat` は確定点の関門の中で I/O をすることになるため採らない）、ファイルシステムが応答しない間は空の新ファイルが見え続けうる。`openat`・`unlinkat` に期限や取り消しの手段が無く、ユーザー空間では有界にできない
- 待ちうる処理（open・作成・ロック・メタデータ・旧 writer の flush）はすべて確定点より前に行う。旧 writer の flush が失敗したら切り替えず、旧 writer と未書き込み分を保ってエラーにする（同じ inode では残りの予算も変えない）
- 確定点では sink のロックとコンテナのスロットのロックの下で期限と稼働の世代を確かめ直し、通ったときだけメモリ上で書き込み先を差し替える。RPC が取り消された（future の破棄・`grpc-timeout` の期限切れ）ときは、cri が取り消しの旗を立て、plugin-cri の制御チャネルのクライアントが応答を待たずに接続を閉じる。supervisor は確定点の関門の直前に要求元の切断を待ちの無い `poll`（`POLLRDHUP`）で確かめ、切れていれば確定しない。期限は `grpc-timeout` が 5 秒より短ければそれに合わせる。既知の制約: 確定点を通った後に要求元が取り消すと、supervisor は切り替え済みのまま kubelet が失敗として扱いうる（プロセスをまたいで確定と応答の受領を一体にする手段が無い）。確定点の後に I/O は残らない（BufWriter は確定前に flush 済みで、旧 fd は退役した writer として返し、応答を書いた後に閉じる。開き直しの枠は閉じ終えるまで持つので、close(2) が止まっても止まるスレッドは 1 本に限られる）。応答は確定の結果に一致する。期限の直前の確定は応答がクライアントの期限に間に合わないおそれがあるため、確定点では期限まで 200 ms の余裕（`COMMIT_MARGIN`）を残して拒否する。拒否されたら作ったファイルを消して `TIMEOUT` か `FAILED_PRECONDITION` を返す。ロックの順は sink → スロット
- 終了の遷移は開始の時点で新しい開き直しの受付を閉じ、進行中のものを最大 500 ms 待つ。待ちを越えた開き直しも確定点で拒否される
- 開き直しは supervisor の専用の実行枠（コンテナごとに同時 1 件。使用中は `Busy`）で行い、制御チャネルの受付を止めない。plugin-cri 側も処理スレッドを同時 4 件（`MAX_CONTAINER_LOG_REOPENS`）までに絞り、処理が終わるまで枠を保持する（超えた要求は `UNAVAILABLE`）
- 書き込みの失敗の状態は `CriFileSink` 自身が持ち、開き直しの差し替えと同じロックの下で解除する（1 行だけ通知する）。開き直しできる副が設定されている間は、両方の出力先が失敗しても捕捉を止めず、開き直しの後に追記が再開する。開き直しに対応しない通常の副 sink は従来どおり Tee が失敗を記録して以後呼ばない
- 切り替えの境界でも行の欠落・重複は無い（同じ捕捉スレッドが順に書く。SUP-7・TASK-164。実機前提の段 L が新しいファイルの先頭が旧ファイルの末尾のちょうど次の番号であることを照合する）
- 総量の上限は開き直しのたびに新しいファイルのサイズから数え直す。上限で止まった CRI ログも再開する
- 部分行 `P` の途中で開き直すと、新しいファイルは続きの断片から始まる（上の「containerd との差・残る差」の表）
- 古い supervisor は kind 10 を拒否し、plugin-cri は `UNAVAILABLE` を返す（既存コンテナは作り直すまで開き直せない）
- cri 側の順序と `FAILED_PRECONDITION` の扱いは [cri-config-acceptance.md](cri-config-acceptance.md)「log_path / log_directory の受け入れ方式」

## 再評価条件

- `fandhe logs` の 64 KiB 切り詰めを見直すとき（#4581 の判断の再評価。(b) の検討を含む）
- containerd の `redirectLogs` が期限での書き出しや EOF の扱いを変えたとき
- 総量の上限（`CRI_LOG_MAX_BYTES`）を外すか、上限の値を変えるとき
- CRI のコンテナで同じ書き先への再 launch が起きるようになったとき（論点 D）
