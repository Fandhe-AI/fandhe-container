# plugin の frame_loop の置き場所の判断記録

plugin-macos・plugin-windows・plugin-microvm の 3 crate に、UDS 上の長さ接頭辞フレームの受信ループ `src/frame_loop.rs` が別々にある。
受信の期限・ヘッダ検証・エラー方針を 1 回直すと 3 crate に波及するため、共通化の置き場所を決める
（REPAIR-1・PLUG-1・PLUG-4・OSS-3・REPAIR-5。TASK-115.2・TASK-116.2・TASK-117.1。親 #3729・本件 #3772）。

## 結論

- **案 (a)（既存の `crates/plugin` に共通の受信ループを置く）を採用する**。オーナー決定（2026-11-03）。
  根拠は [#3773 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/3773#issuecomment-6595749900)と
  [#4 のコメント 3 番目の項](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6595741383)
- 決定の内容（書かれたとおりに記録する）:
  - 新しい crate を作らないので、ライセンスの判断と crate-naming.md の確定一覧の変更は不要
  - 差分表で共通化できないと分かった部分は案 (c)（同期の検査のみ）に切り替える
  - #3774〜#3776 は `crates/plugin` に共通の受信ループを置く
- 下の差分表を分析した限り、frame_loop の中に共通化できない部分は無い。分岐はどれも引数か trait の既定メソッドで表せる。
  crate ごとに残るのは `sys.rs`（SIGTERM の登録・自前の FFI 宣言）と各 adapter（ハンドラ）だけ。
  #3774〜#3776 の実装で共通化できない部分が見つかったら、決定どおりその部分を (c) に切り替え、本記録に追記する
- 本記録は決定済みの判断記録であり、3 案の比較は採用理由として残す

## 3 実装の比較

plugin-macos と plugin-microvm は、コメントと `Recv` の variant の並び順を除いてコードが同一（microvm は macos の写し）。
plugin-windows は停止まわりが独自に拡張されており、本体の受信には macos の後から入った堅牢化が入っていない。

| 項目 | plugin-macos | plugin-microvm | plugin-windows |
| ---- | ---- | ---- | ---- |
| 定数 `IDLE_POLL`（1 秒）・`FRAME_DEADLINE`（`UDS_RPC_TIMEOUT_DEFAULT`）・`REQUEST_BODY_MAX_ITEMS`（64）・`BODY_CHUNK`（64 KiB）・`MSG_ENCODE_FAILED` | 同一 | 同一 | 同一 |
| `RequestHandler` | `handle` のみ（`FnMut` の blanket impl あり） | 同左 | `handle` に加え、既定で `handle` へ委譲する `handle_with_stop(body, &AtomicBool)` を持つ（`adapter.rs` が上書き） |
| `UnimplementedHandler`・`LoopExit`（`PeerClosed`・`ShutdownRequested`。`non_exhaustive`） | 同一 | 同一 | 同一 |
| `handle_frame` のエラー方針 | 復号失敗・`Response`/`Error`・未知 variant は応答せず切断。本体件数 0 または 65 以上は `InvalidArgument`。応答の符号化失敗は固定文言の `Internal` | 同一 | 同一。内部の `handle_frame_with(…, Option<&AtomicBool>)` 経由で `handle_with_stop` を呼ぶ |
| 停止フラグの確認位置（受信） | ヘッダの 1 バイト目より前（`got == 0`）だけ。受信を始めたフレームは受け切って応答する | 同左 | ヘッダ・本体の途中を含む毎回の read の前。途中のフレームは破棄して `Shutdown`（WIN-2: 共有マウント解除の 5 秒の猶予を守るため） |
| 本体の読み方 | 固定長の作業バッファ `chunk` に読み `extend_from_slice` で足す（1 バイトずつ送る相手に 0 埋めを繰り返さない） | 同左 | 読むたびに `resize` / `truncate`（0 埋めが毎回走る旧い形） |
| 受信後の期限の再確認 | 最後の read の後と `decode_body` の後の 2 回 | 同左 | なし |
| 応答の送信 | `stream.write_frame(…, RpcTimeout::default())` | 同左 | `send_frame_until`。`IDLE_POLL` ごとに停止フラグを見て `Send::Shutdown` で抜ける。合計期限の超過は `Timeout` |
| `RawUnusable` 後の代わりの受信 | `read_frame(RpcTimeout::default())`。`Unavailable` を `PeerClosed` にする | 同左 | 先に停止フラグを見る。期限 `IDLE_POLL` で `read_frame` し、`fallback_outcome` が「`Timeout` かつ停止」を `ShutdownRequested` にする |
| `cfg` | なし（`cfg(test)` のみ） | なし | なし |
| 単体試験（`src/frame_loop.rs` の `#[test]` 数） | 15 | 15 | 22（`send_tests` を含む） |
| 結合試験（`tests/frame_loop.rs` の `#[test]` 数。`#![cfg(unix)]`） | 15 | 18 | 14 |

- macos の `task115_2_plug1_recv_deadline_exceeded_by_last_read_is_timeout` に当たる試験が windows に無い（受信後の期限の再確認が無いことに対応する）
- 件数は 2026-11-03 の origin/main で `grep -c '#\[test\]'` を使って数えた値。#3774〜#3776 で「件数を減らさない」の照合基準に使う

## 共通化するときの分岐の扱い（#3774〜#3776 への申し送り）

- **本当に挙動が分かれる点は停止フラグの粒度だけ**（受信を始めたフレームを受け切るか、途中で破棄するか）。
  黙って片方に揃えると macos・microvm か windows のどちらかの挙動が変わるので、引数（例: 停止の方針を表す enum）として残す
- windows の送信の停止（`send_frame_until`）、代わりの受信の期限と分類（`fallback_outcome`）、`handle_with_stop` は
  他の 2 crate の挙動を包含する拡張。既定値を今の macos・microvm と同じにすれば、その 2 crate の挙動は変わらない
- macos・microvm の本体の読み方（作業バッファ）と受信後の期限の再確認は、共通側の挙動として 3 crate すべてに入れる。
  windows に REPAIR-5 の堅牢化が入り、挙動が変わるのはこの点だけなので、#3776 で試験を足して確かめる
- fail-closed のエラー方針（復号失敗は応答せず切断・応答の符号化失敗は固定文言）を共通化で弱めない
- 公開面の最小化: 共通側の `RequestHandler`・定数・`LoopExit` は、外部の plugin の作者もリンクする境界 crate の公開面になる。
  公開する型・関数は必要最小にする。peer 認証（PLUG-12）は `UdsStream::connect` 側にあり受信ループの外に残る

## 置き場所の候補

| 観点 | (a) `crates/plugin`（採用） | (b) Apache-2.0 の新 crate | (c) 写しのまま同期検査のみ |
| ---- | ---- | ---- | ---- |
| ライセンス | Apache-2.0 単独のコードを `MIT OR Apache-2.0` の crate へ移す（オーナー承認済み） | 新 crate のライセンスの決定が要る（中核は Apache-2.0 単独が既定） | 変化なし。試験を `#[path]` で共有すると #3476（OPEN・人間担当）と同種の論点になる |
| PLUG-4 | `scripts/check-plug4-core-invariance.sh` は `crates/plugin*/Cargo.toml` の新規追加時だけ merge-base と比べる。既存 crate の src の変更ではスクリプトの判定に影響しない。core の rlib は依存先の内容で main と比べて変わりうるがスクリプトは測っていない。PLUG-4 は plugin を足しても core が変わらない規則で、境界 crate 自体の整理は対象外。共通側を非既定 feature の後ろに置けば core の既定ビルドに入れずに済むが、rlib が変わらないかは未実測で #3774 で選んで実測する | crate と辺が増え、crate-naming.md の確定一覧が変わる | 影響なし |
| 依存方向 | 3 crate は既に `fandhe-container-plugin` に依存しており辺は増えない | crate 1 つと辺 3 本が増える（REPAIR-1） | 辺なし |
| 3 OS の cfg | `cfg` なしで成り立つ。`UdsStream` の型は全 OS で見える（確認は #3774 の cross-target-check） | 同左 | 同左 |
| 修正の波及 | 1 か所 | 1 か所 | 3 か所（同期検査で乖離を検出するのみ） |

## 許容する差

crate ごとに残してよいもの: `sys.rs`（SIGTERM の登録・自前の FFI 宣言）、各 adapter（ハンドラ）、`main.rs` の終了処理、crate 固有の試験。

## 残余（本件の対象外）

- 共通側を置いたときの core の rlib の実測（#3774）
- #3476 の判断（Apache-2.0 単独のファイルを `MIT OR Apache-2.0` の試験が `#[path]` で取り込む扱い。OPEN）
- Windows の SIGTERM の経路（[windows-execution-layout.md](windows-execution-layout.md)・#1862）
- plugin-microvm の `frame_loop.rs` の doc にある「共通化は別 issue で追跡」の記述の差し替え（#3774 で行う）

## 見直す条件

- 実装の途中で共通化できない差が見つかったとき（その部分を (c) に回して本記録に追記する）
- PLUG-4 の判定対象（[crate-naming.md](crate-naming.md) 決定 3）が変わったとき
- `crates/plugin` のライセンスの方針が変わったとき

## #3776 の結果（plugin-windows の切り替え）

- 案 c に回した部分は無かった。windows 固有の差はすべて「引数 1 つ」と「既定実装つきメソッド 1 つ」で表せた
- 共通側に足したもの（いずれも既存の `serve`・`serve_until`・`handle_frame` の署名と挙動は変えない非破壊の追加）:
  - `ShutdownPolicy`（`CompleteFrame` が既定、`DiscardInProgress` が windows）。受信途中の停止確認・停止フラグで中断できる送信（`send_frame_until`）・`IDLE_POLL` 期限の代替受信（`fallback_outcome`）の 3 つは `DiscardInProgress` のときだけ有効
  - `serve_until_with(stream, handler, stop, policy)`。`serve_until` は `CompleteFrame` 固定でこれへ委譲する
  - `RequestHandler::handle_with_stop`（既定は `handle` へ委譲）。macos・microvm の adapter は無変更
- plugin-windows の `frame_loop.rs` は再 export と、`DiscardInProgress` を固定した薄い `serve` / `serve_until` だけになった（共有側の `serve_until` をそのまま再 export すると `CompleteFrame` になり WIN-2 の猶予を守れないため）
- windows の挙動が変わるのは、macos 系の堅牢化（作業バッファ `chunk` による本体読み、最後の read の後と `decode_body` の後の合計期限の再確認。REPAIR-5）が入る点だけ。確認試験: `task116_5_repair5_discard_policy_deadline_exceeded_by_last_read_is_timeout`（共有側）。方針の対比は `task3776_policy_contrast_flag_mid_frame`
- 単体試験の移設: windows の単体 22 件のうち、停止まわりの 11 件（`task116_5_win1_*` 7 件・`task116_5_win2_*` 4 件）は名前を保って共有側へ移した。残り 11 件（`task116_2_*`）は共有側の `plug1_frame_loop_*`（アサーションが同一）と重複するため移さない。windows の結合試験 14・peer_auth 2・e2e 7 は不変
- PLUG-4: 共有 crate の変更であり plugin の追加ではないため `make plug4-core-invariance` の判定対象外
