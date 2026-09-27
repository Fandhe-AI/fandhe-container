# I/O 共有層のワイヤーフレーム（チェックサム）

`fandhe-container-io`（`crates/io`）が提供するフレーム全体型（[`Frame`](../../crates/io/src/protocol.rs)）のバイトレイアウトと、採用したチェックサムアルゴリズムの根拠を記録する。

- 対象ビヘイビア: IO-1（ホスト⇔ゲスト間のファイル共有プロトコル）・REPAIR-2（壊れた値を表現できない型）
- 関連タスク: TASK-11.3（#70）。ヘッダ newtype は TASK-11.2（#69）
- 対象マイルストーン: MS-1
- ステータス: 本ドキュメントはチェックサム節・レイアウト表のみの最小構成。フレーム図の全体・newtype 選定理由・IO-1 / REPAIR-2 対応表の網羅は TASK-11.4（#71）が追記する

## バイトレイアウト

```text
+----------------+----------------------+---------------------+
| header (5 B)   | payload (N B)        | checksum (4 B)      |
| kind: u8       | N = payload_len      | CRC-32C, u32 LE     |
| payload_len: u32 LE (N ≤ MAX_PAYLOAD_LEN = 64 MiB)           |
+----------------+----------------------+---------------------+
```

- `header` は `FrameHeader`（TASK-11.2・#69）が持つ固定長 5 バイト（`kind: u8` + `payload_len: u32 LE`）
- `payload` は不透明なバイト列。request id・ACK status 等のレイアウトはこの型の関知するところではなく、TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める
- `checksum` はトレーラ（末尾）に置く CRC-32C（4 バイト・リトルエンディアン）で、**ヘッダ 5 バイト + ペイロード**を対象に計算する（`header` のみ・`payload` のみではない）

ヘッダも対象に含める理由: ペイロードのみを対象にすると、送信側が申告する `payload_len` を実際より少なく偽る破壊（後述の BREAK-2）に対して、その偽った長さと整合するチェックサムが偶然一致してしまう余地がある。ヘッダを対象に含めることで、種別・長さフィールドの破壊も検出できる。

## チェックサムアルゴリズム: CRC-32C（Castagnoli）

- 反射多項式 `0x82F6_3B78`、初期値 `0xFFFF_FFFF`、最終 XOR `0xFFFF_FFFF`
- 依存追加なし。std のみで `const fn` により 256 エントリのテーブルを生成し、`update(&[u8])` / `finalize()` のストリーミング API で計算する（`crates/io/src/checksum.rs`。dependency-policy のフルスクラッチ方針）

### 採用理由

- 目的は**偶発的破損・フレーム境界ずれの検出**であり、改ざん防止（真正性の保証）ではない。CRC は短〜中長のバースト誤り検出能力が保証されており、FNV・Adler-32 より誤り検出特性が良い
- CRC-32C は iSCSI（RFC 3720）・ext4・Btrfs 等ストレージ系で広く使われており、同じ 32 ビットで CRC-32（IEEE 802.3）よりハミング距離特性が良い
- x86_64 SSE4.2・AArch64 CRC 拡張によるハードウェア加速の道がある。ただし intrinsics の利用は `unsafe`（coding-rust の unsafe 事前承認範囲外）であり、本件では導入しない。必要性は TASK-113（ベンチ）の結果を見てから判断し、導入する場合はユーザー承認を得る
- 4 バイトでワイヤー上のオーバーヘッドが小さい

### 範囲外（真正性は保証しない）

CRC-32C は MAC（HMAC 等の暗号学的完全性検証）ではない。ホスト・ゲスト間の相手は untrusted であり、悪意ある改ざんへの耐性は本チェックサムの範囲外で、信頼境界の検証は別レイヤーの責務とする。

## デコード時の検証順序と検出する破壊

`Frame::decode` / `Frame::decode_body` は次の順序で検証し、上限検証前にアロケーションしない（DoS 対策。security.md）。

1. 先頭 `FRAME_HEADER_LEN`（5 バイト）を `FrameHeader::from_bytes` で検証（種別が既知の値か・`payload_len` が `MAX_PAYLOAD_LEN` 以下か）。ここで `IoErrorCode::InvalidArgument`
2. 期待される本体長（`payload_len + CHECKSUM_LEN`）と実際の本体長を比較。不一致なら `IoErrorCode::InvalidArgument`（チェックサム不一致とは別コード）
3. ヘッダ＋ペイロードから再計算した CRC-32C とトレーラの値を比較。不一致なら `IoErrorCode::DataLoss`

PoC-8（`03-poc/ai-self-repair`）の BREAK-2 は、送信側がペイロード長を実際より 1 バイト少なく申告する破壊が `cargo build` を素通りし、整合性テストでしか検出できなかった事例である。本チェックサムは、正しくエンコードされたフレームに対して転送中の偶発的破損（ビット反転・末尾切り詰め等）でヘッダの `payload_len` が書き換わった場合に、元のペイロード＋トレイラの残りバイトを申告長どおりに読み直した結果としてチェックサム不一致を検出し、上記手順 3 で `IoErrorCode::DataLoss` として拒否する（`crates/io/src/protocol.rs` の `repair2_decode_detects_break2_short_declared_len` テストで確認）。ただし、これは CRC-32C が偶発的破損を検出する性質によるものであり、送信側が短く申告した `payload_len` とそれに整合するペイロードからチェックサムを再計算して送出した場合（意図的な長さの偽装）は、ヘッダ・ペイロード・チェックサムが自己整合しているため検出できない（38 行目のとおり CRC-32C は改ざん耐性を持たない）。意図的な偽装への耐性が必要な経路では、別レイヤーでの真正性検証（信頼境界の検証）が必要になる。
