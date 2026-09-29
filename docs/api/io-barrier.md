# I/O 共有層の ACK と永続化保証の契約

`fandhe-container-io`（`crates/io`）の 2 種類の ACK（通常 ACK・FLUSH ACK）が何を保証し、何を保証しないかを利用者向けに定める。

- 関連タスク: TASK-17（#92。本書）・TASK-15（#84・#85・#87・#88。FLUSH バリアの型分離と永続化）・MS-1
- 関連ビヘイビア: IO-1（バッファリング時点の ACK）・IO-2（通常 ACK と FLUSH ACK の区別）・IO-3（SIGKILL 耐性の実測と未検証範囲）・IO-10（自動フラッシュ。未実装）・ERR-3（`DATA_LOSS`）・REPAIR-3（未実装を装わない）・REPAIR-5（タイムアウト）
- 仕様の SSOT は spec リポ（`docs/spec` submodule の `04-behavior/`）である。本書と食い違う場合は spec を正とする。ワイヤー形式の詳細は [io-protocol.md](../design/io-protocol.md) を参照

## 要点

- 通常 ACK は永続化を保証しない。受け取ってもクライアント側のデータを破棄してはならない
- 永続化が必要なときは FLUSH バリアを発行し、対応する FLUSH ACK を待つ
- FLUSH ACK が返らなかった書き込みは、永続化を確認できない状態として扱う。未永続化とは断定せず、照合または冪等化してから復旧する（fail-closed）

## 2 種類の ACK の比較

| 項目 | 通常 ACK | FLUSH ACK |
| ---- | -------- | --------- |
| ワイヤー値（`FrameKind`） | `Ack`（2） | `FlushAck`（4） |
| Rust の型 | `barrier::WriteAck` | `barrier::FlushAck` |
| 契約上の保証（IO-1・IO-2） | プロセスが正常に動いている間の受理のみ。永続化は保証しない | 「バリア以前」（後述）の書き込みが永続化済み |
| 現行実装の送出タイミング | バッチの `BatchSink::write_batch` が `Ok` を返した後（OS への `write()` 完了後。`fsync` は待たない） | `BatchSink::persist` が成功した後 |
| サーバープロセスの異常終了（SIGKILL）時 | 失われうる | PoC で損失 0 件を確認済み（IO-3。本実装での自動試験は TASK-18） |
| 電源断・OS クラッシュ時 | 失われうる | 未検証（IO-3）。保証すると主張しない |

2 つの型は相互変換を持たない。通常 ACK を永続化済みとして扱う誤用（データ損失。ERR-3）はコンパイル時に防がれる。

## 通常 ACK の契約（IO-1）

- 契約は IO-1 が許す弱い保証である。プロセスクラッシュで、ACK 済みのデータが失われうる
- 現行実装は OS への `write()` 完了後に送るが、利用者はこの挙動に依存してはならない。現行実装の SIGKILL 耐性は TASK-18 で未検証であり、耐えるとは主張しない
- 通常 ACK を受け取っても、クライアント側の送信元データは保持し続ける（永続化が必要なら FLUSH ACK を待つ）

## FLUSH ACK の契約（IO-2）

サーバーは `Flush` を受信すると、次の順で処理する。

1. フレームの形式を検証する
2. 滞留中の書き込みを取り出して書き込み、通常 ACK を返す
3. `BatchSink::persist` で永続化する
4. 成功したときだけ FLUSH ACK を送る

永続化の手段は OS ごとに異なる。

| 環境 | 手段 |
| ---- | ---- |
| Linux 5.8 以上 | sink の fd に対する `syncfs(2)` |
| macOS | ファイルへの `fcntl(F_FULLFSYNC)` と、sink が持つディレクトリハンドルの同期 |
| Windows | `FlushFileBuffers` と、ディレクトリハンドルの同期 |
| 上記以外（親ディレクトリのハンドルを持たない sink の macOS / Windows、Linux 5.8 未満、版数判定不能、その他の OS） | `Unimplemented` で拒否し、FLUSH ACK を返さない（fail-closed） |

- FLUSH ACK が返りうる環境かは `barrier::persist_support()` と `PersistSupport::is_supported()` で判定できる
- 直前の成功から書き込みがない `Flush` は `syncfs` を省略して成功を返す（増幅対策）。保証は前回の成功で満たされている
- 永続化の同時実行数はプロセス全体で `MaxConcurrentPersist`（既定 2・上限 64）に制限し、待ち時間には期限（既定・上限 10 秒。`with_flush_timeout`）を設ける。期限を過ぎると `Timeout` を返し、FLUSH ACK は返さない（REPAIR-5）
- `syncfs` を発行した後の失敗・タイムアウトでは sink が使用不能になり、以後の永続化は `Internal` を返す

## 「バリア以前」の範囲

範囲は、**同じ接続（1 本の `serve_connection` ループ = 1 つの sink）で、その `Flush` フレームより前に受信した `Write` のうち、`write_batch` が `Ok` を返したもの**である。件数未達で滞留していた分も含む。

保証の対象外は次のとおり。

- 別の接続・別の sink への書き込み。Linux の `syncfs` はファイルシステム全体を同期するため結果として永続化されることはあるが、契約上の保証ではない
- 呼び出し側が持つ別の `File` ハンドルや別プロセスからの書き込み（`BatchSink::persist` と `AppendFileSink` は単一書き込み元を前提とする）
- `Flush` より後に受信した書き込み（パイプライン送信でも、受信順で後ろに来たものは対象外）

クライアント側では、`recv_ack` が送信順（FIFO）で照合するため、FLUSH ACK はそれ以前の書き込みの通常 ACK をすべて受け取った後に届く。`PipelineClient::flush` が返す `FlushBarrier` と `FlushAck::barrier()` を突き合わせ、待っていたバリアの ACK かを確認する。

## 検証済みの範囲と未検証の範囲

- 検証済み: SIGKILL 耐性（PoC での実測。下記）
- 未検証: 電源断・OS クラッシュへの耐性（IO-3）
- 本実装での SIGKILL 耐性の自動試験は TASK-18（`crates/io/tests/crash_safety.rs`）で行う

## 根拠となった実測

詳細は spec の IO-2・IO-3 を参照。要点のみ示す。

- PoC-2: SIGKILL で、未フラッシュのデータ 2000 件中 15 件が失われた
- Linux 実機（aarch64）での再実測（2026-09-23）: FLUSH バリアなし・ACK 済み未書き込みの状態で SIGKILL すると、有効試行 10/10 で損失（17〜30 件）。FLUSH ACK 受信直後の SIGKILL は、有効試行 10/10 で損失 0 件
- これは PoC プロトタイプでの実測であり、本 crate の実装への組み込みと CI での自動化は TASK-18 の対象である

## 失敗時の振る舞いと利用者の責務

永続化が失敗・タイムアウト・未対応になると、サーバーは FLUSH ACK を送らずに接続を終える。プロトコルにエラーフレームはない。クライアントはこれを次のように観測する。

| 観測 | `IoError` の code | 意味 |
| ---- | ----------------- | ---- |
| 接続が閉じた（EOF） | `Unavailable` | サーバーが永続化失敗・未対応・異常終了等で接続を終えた |
| `recv_ack` の待ちが期限切れ | `Timeout` | ACK が期限内に届かなかった |

- エラー後の接続再利用は禁止（[io-protocol.md](../design/io-protocol.md) の「エラー後の接続再利用禁止」節。REPAIR-5）
- FLUSH ACK が届かないことは「未永続化」を意味しない。`AppendFileSink` は `write_batch` の時点でデータを追記済みであり、永続化（`persist`）は成功したが ACK の送信だけが失敗した可能性がある。IO-2 の保証は「FLUSH ACK を受け取ったなら永続化済み」までで、ACK がないときの永続化状態は不明である
- ACK 不在の書き込みを新しい接続で無条件に再送してはならない。同じデータが二重に追記されうる
- 再送前に次のいずれかで復旧する
  - 照合: sink 側の実際の内容（末尾のオフセット・件数・チェックサム等）を確認し、未反映の書き込みだけを再送する
  - 冪等化: 書き込みに一意な識別子（連番等）を付け、受け側で重複を排除できるようにしてから再送する
  - 重複許容: 呼び出し側が重複を許容できる（重複を検知して読み飛ばせる）場合に限り、再送して後段で重複を除去する
- 上記の照合・冪等化の仕組みは本 crate では未実装である（REPAIR-3）。利用者が用意する

## 利用例

トランスポート（`FrameSender` 実装）は呼び出し側が用意する。クライアント側の UDS `connect` は未実装である（REPAIR-3）。

```rust,ignore
use fandhe_container_io::barrier::{AckReceipt, FlushAck};
use fandhe_container_io::client::PipelineClient;
use fandhe_container_io::protocol::FrameKind;

// PipelineClient::new(sender, limit, observer) で構築済みとする
client.send(FrameKind::Write, &body, timeout)?;
let barrier = client.flush(timeout)?;
loop {
    let receipt: AckReceipt = client.recv_ack(timeout)?;
    if let Ok(ack) = FlushAck::try_from(receipt) {
        if ack.barrier() == barrier {
            break; // barrier 以前の書き込みは永続化済み
        }
    }
    // 通常 ACK（WriteAck）は永続化を意味しない
}
```

## 未実装範囲（REPAIR-3）

- 自動フラッシュと未フラッシュ滞留量の上限（IO-10。TASK-16）
- クラッシュ安全性テスト（TASK-18）
- クライアント側の UDS `connect` と `PipelineClient` の本番結合
- vsock・named pipe のトランスポート
- 電源断への耐性の検証

## 関連ドキュメント・ソース

- [io-protocol.md](../design/io-protocol.md)
- [barrier.rs](../../crates/io/src/barrier.rs)・[client.rs](../../crates/io/src/client.rs)・[writeback.rs](../../crates/io/src/writeback.rs)・[protocol.rs](../../crates/io/src/protocol.rs)
