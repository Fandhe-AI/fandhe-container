# I/O 共有層のワイヤーフレーム（チェックサム）

`fandhe-container-io`（`crates/io`）が提供するフレーム全体型（[`Frame`](../../crates/io/src/protocol.rs)）のバイトレイアウト・採用したチェックサムアルゴリズムの根拠・newtype 設計方針・IO-1 / REPAIR-2 対応表を記録する。

- 対象ビヘイビア: IO-1（ホスト⇔ゲスト間のファイル共有プロトコル）・REPAIR-2（壊れた値を表現できない型）
- 関連タスク: TASK-11.1（#68）・TASK-11.2（#69。ヘッダ newtype）・TASK-11.3（#70。チェックサム付きフレーム型）・TASK-11.4（#71。本節以降）・TASK-13.1（#76。バッチ集約バッファ）
- 関連ビヘイビア: IO-2（Flush / FlushAck 種別）・REPAIR-5（`IoTimeout`。無期限待ちを型で表現しない）
- 対象マイルストーン: MS-1
- ステータス: 本ドキュメントは TASK-11.1〜11.4 で確定したフレーム形式（バイトレイアウト・newtype 設計・IO-1 / REPAIR-2 対応）に加え、TASK-13.1 で追加したバッチ集約バッファ（[`BatchBuffer`](../../crates/io/src/batch.rs)・`BatchConfig`）を記録する。ペイロード内部レイアウト（request id・ACK status 等）・UDS 受信ループ・ディスク書き込み・ACK 返却は TASK-12（パイプライン送信クライアント）・TASK-13 の後続 sub-issue（TASK-13.2 系）が本書へ追記する

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

### オフセット表

| オフセット | サイズ | フィールド | 型・エンコード | 検証内容 | 違反時のエラーコード |
| ---------- | ------ | ---------- | --------------- | -------- | -------------------- |
| `0` | 1 B | `kind` | `u8`（[`FrameKind`](../../crates/io/src/protocol.rs)） | 既知値（1〜4）か | `INVALID_ARGUMENT` |
| `1` | 4 B | `payload_len` | `u32` LE（[`PayloadLen`](../../crates/io/src/protocol.rs)） | `≤ MAX_PAYLOAD_LEN` | `INVALID_ARGUMENT` |
| `5` | N B | `payload` | 不透明なバイト列 | 実本体長 = `payload_len + CHECKSUM_LEN` | `INVALID_ARGUMENT` |
| `5+N` | 4 B | `checksum` | CRC-32C `u32` LE（[`FrameChecksum`](../../crates/io/src/protocol.rs)） | header 5 B ‖ payload の再計算値と一致 | `DATA_LOSS` |

### 定数

| 定数 | 値 | 備考 |
| ---- | -- | ---- |
| `FRAME_HEADER_LEN` | 5 | 種別 1 バイト + ペイロード長 4 バイト |
| `CHECKSUM_LEN` | 4 | CRC-32C（`u32` LE） |
| `MAX_PAYLOAD_LEN` | 64 MiB（`67_108_864`） | 暫定値。PoC-2（`03-poc/io-layer-redesign`）の `MAX_DATA_LEN` に由来し、`fandhe-container-plugin` の境界機構（plugin-framed）が使う 16 MiB 上限とは別の境界。TASK-12・TASK-13 で見直してよい |
| `MAX_FRAME_LEN` | `FRAME_HEADER_LEN + MAX_PAYLOAD_LEN + CHECKSUM_LEN` | フレーム全体の最大バイト数 |

### `FrameKind` 値表

| 値 | バリアント | 意味 |
| -- | ---------- | ---- |
| `0` | （予約） | ゼロ埋めバッファの誤解釈を検出するための予約値。いずれのバリアントにも割り当てない |
| `1` | `Write` | パイプライン送信の書き込みフレーム |
| `2` | `Ack` | 書き込みフレームに対する ACK。バッファリング時点（受理）までを保証し、永続化は保証しない（IO-1） |
| `3` | `Flush` | FLUSH バリア。これ以前に受理した書き込みの永続化を要求する（IO-2） |
| `4` | `FlushAck` | FLUSH バリアに対する ACK。バリア以前に受理した書き込みが永続化済みであることを保証する（IO-2） |
| `5..=255` | （未知値） | `INVALID_ARGUMENT` として拒否する |

### エンコード例

いずれも `crates/io/src/checksum.rs` が実装する CRC-32C と同一パラメータ（反射多項式 `0x82F6_3B78`・初期値 `0xFFFF_FFFF`・最終 XOR `0xFFFF_FFFF`）の独立実装で、標準 check 値 `"123456789"` → `0xE3069283`（`io1_crc32c_matches_standard_check_value` と同じ期待値）を確認した上で算出した値。

- `Write`・payload `"abc"`: `01 03 00 00 00 61 62 63 38 26 3e 2b`（checksum = `0x2b3e2638`）
- `Flush`・空 payload: `03 00 00 00 00 c1 c6 41 0d`（checksum = `0x0d41c6c1`）

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

## newtype 設計方針

### 動機

PoC-2（`03-poc/io-layer-redesign`）のフレームは生の `Vec<u8>` 手組み（`id + name_len + name + data_len + data`、FLUSH を `id == u32::MAX` の番兵 `FLUSH_MARKER` で表現）だった。PoC-8（`03-poc/ai-self-repair`）の BREAK-2（`data_len` を実際より 1 バイト少なく申告する破壊）はこの構造に対して `cargo build` を素通りし、整合性テストでしか検出できなかった。REPAIR-2 に従い、`crates/io/src/protocol.rs`・`transport.rs` のフレーム関連型は「構築できた値は正しい」型に寄せている。

### 型ごとの選定理由

- **`PayloadLen`**: 非公開フィールドを持ち、`new` / `TryFrom<u32|usize>` を経由して `MAX_PAYLOAD_LEN` 以下であることを検証した値のみを表現できる
- **`FrameKind`**: `#[repr(u8)]` でワイヤー値と一致させ、`#[non_exhaustive]` で将来のバリアント追加に備える。`0` を予約値としていずれのバリアントにも割り当てず、`TryFrom<u8>` で未知値を拒否する。PoC-2 の番兵値（`FLUSH_MARKER`）ではなく種別フィールドで `Flush` を表現するため、「有効な id を FLUSH と誤解釈する」余地がない
- **`FrameHeader`**: 非公開フィールドを持ち、`new` / `from_bytes` のみで構築でき、`to_bytes` は固定長 `[u8; FRAME_HEADER_LEN]` を返す。request id・ACK status を含めないのは、それらがペイロード側の責務（TASK-12・TASK-13）であり、ヘッダの役割を種別・長さの検証に限定するため
- **`FrameChecksum`**: 公開コンストラクタを持たない。呼び出し側が任意のチェックサム値を注入する経路が型として存在しない
- **`Frame`**: 不変条件は 2 点（`header.payload_len().get() as usize == payload.len()`、`checksum` が `header.to_bytes() ‖ payload` の CRC-32C と一致）。`Frame::new` はヘッダの `payload_len` を引数のペイロード実長（`payload.len()`）から導出するため、送信側が「実際より短い長さ」を申告する経路が型として存在しない（BREAK-2 の送信側原因を型で封じ込める）。`Debug` は手書きし、ペイロード内容を出力しない
- **`WireFrame`（sealed trait）**: `sealed::Sealed` で封印し、crate 外から生のバイト列型を送受信境界（`FrameSender` / `FrameReceiver`）に差し込めないようにする。`FrameHeader` 単体には実装させていない。ヘッダはフレーム全体（ヘッダ + ペイロード + チェックサム）の構成要素の 1 つに過ぎず、送受信境界が扱うのは検証済みのフレーム全体（`Frame`）であるため
- **`IoTimeout`（関連）**: `Duration::ZERO`・`MAX_IO_TIMEOUT` 超過を構築時に拒否し、無期限待ちを型として表現できないようにする（REPAIR-5）

### 依存を使わない理由

serde 等の外部クレートを使わず、std のみでヘッダ・チェックサムのエンコード / デコードを表現できる規模であり、フルスクラッチ・依存最小方針（`docs/design/from-scratch-policy.md`・[dependency-policy](../../.claude/rules/dependency-policy.md)）に沿う。

## IO-1 / REPAIR-2 対応表

| ビヘイビア ID | 要求の観点 | 保証する仕組み（型・関数） | 確認テスト |
| -------------- | ---------- | -------------------------- | ---------- |
| IO-1 | パイプライン送信の土台（送受信の抽象） | `FrameSender::send_frame` は ACK を待たずに戻る契約・`FrameKind::Write` / `Ack` | `transport.rs` の `io1_frame_sender_and_receiver_are_dyn_compatible`・`io1_frame_transport_blanket_impl_applies` |
| IO-1 | ACK はバッファリング時点まで保証（永続化は非保証） | `FrameKind::Ack` の契約（ドキュメンテーションコメント） | `io1_frame_kind_round_trips_all_variants` |
| IO-1 | ワイヤー形式の往復 | `Frame::encode` / `Frame::decode` | `io1_frame_encode_layout`・`io1_frame_round_trips_all_kinds`・`io1_frame_header_to_bytes_layout`・`io1_frame_header_from_bytes_round_trip`・`tests/protocol.rs` の `io1_public_api_frame_round_trips` |
| IO-1 | 長さ上限の検証（DoS 対策） | `PayloadLen::new` / `FrameHeader::from_bytes` がアロケーション前に検証 | `io1_payload_len_rejects_max_plus_one`・`io1_frame_header_from_bytes_rejects_len_over_max`・`tests/protocol.rs` の `io1_public_api_frame_new_rejects_oversized_payload` |
| REPAIR-2 | 長さ偽装（BREAK-2） | 送信側: `Frame::new` の長さ導出で表現不能。受信側: 本体長不一致（`INVALID_ARGUMENT`）またはチェックサム不一致（`DATA_LOSS`）で拒否 | `repair2_decode_detects_break2_short_declared_len`・`io1_decode_rejects_length_mismatch`・`tests/protocol.rs` の `io1_public_api_decode_rejects_length_mismatch`・`tests/frame_integrity.rs`（TASK-83.1・#116。ワイヤー上の `payload_len` フィールド自体を書き換えた入力で、一括 `decode` とストリーム読みの両経路を確認: `repair2_break2_declared_len_shorter_rejected_by_decode`・`repair2_break2_declared_len_shorter_rejected_by_stream_read`・`repair2_break2_declared_len_longer_rejected_by_decode`・`repair2_break2_declared_len_longer_rejected_by_stream_read`・`repair2_break2_declared_len_zero_rejected_by_both_paths`・`repair2_break2_declared_len_over_max_rejected_by_decode`） |
| REPAIR-2 | ビット反転・種別すり替え・チェックサム破損の検出 | CRC-32C（ヘッダ + ペイロードを対象） | `repair2_decode_rejects_flipped_payload_bit`・`repair2_decode_rejects_kind_swapped_to_valid_kind`・`repair2_decode_rejects_corrupted_checksum`・`tests/protocol.rs` の `io1_public_api_decode_rejects_corrupted_payload`・`io1_public_api_decode_rejects_corrupted_checksum` |
| REPAIR-2 | 未知種別・切り詰めの拒否 | `FrameKind::try_from`・`Frame::decode` の `split_first_chunk` | `io1_frame_kind_rejects_unknown_bytes`・`io1_frame_header_from_bytes_rejects_unknown_kind`・`io1_decode_rejects_truncated_header`・`tests/protocol.rs` の `io1_public_api_decode_rejects_too_short_input` |
| IO-1 | CRC 実装の正しさ | `crates/io/src/checksum.rs` の `Crc32c` | `io1_crc32c_matches_standard_check_value`・`io1_crc32c_matches_rfc3720_vectors`・`io1_crc32c_split_update_matches_single_call` |
| IO-1 | 既定 64 件（設定可能）単位でのバッチ集約 | `crates/io/src/batch.rs` の `BatchBuffer::push`・`BatchConfig`（既定値 `DEFAULT_BATCH_SIZE = 64`・上限 `MAX_BATCH_SIZE = 4096`〔暫定〕） | `io1_batch_buffer_fires_at_default_64`・`io1_batch_buffer_fires_at_custom_size_8`・`io1_batch_config_default_is_64`・`io1_batch_config_rejects_zero`・`io1_batch_config_rejects_above_max`・`tests/batch.rs` の `io1_public_api_batch_buffer_fires_at_default_size`・`io1_public_api_batch_config_custom_size_fires`・`io1_public_api_batch_config_rejects_zero` |
| P0 | バッチ 1 つあたりの累積ペイロードバイト数の上限（無制限確保による DoS の防止） | `BatchConfig::max_bytes` / `BatchConfig::with_max_bytes`（既定 `MAX_BATCH_BYTES = 256 MiB`〔暫定〕）。累積が上限を超える手前で `BatchBuffer::push` が既存滞留分を `BatchTrigger::BytesLimitReached` として強制発火させる（件数上限 `MAX_BATCH_SIZE` × 1 フレーム最大長 `MAX_PAYLOAD_LEN` の理論値〔約 256 GiB〕とは独立した安全弁。PR #1105 codex レビュー指摘）。フレーム単体のペイロード長が `max_bytes` を超える場合は `pending` の状態によらず追加前に `INVALID_ARGUMENT` で拒否し、`pending_bytes` が `max_bytes` を上回った状態を作らない（`with_max_bytes` は `MAX_PAYLOAD_LEN` より小さい値も個別設定できるため。PR #1105 codex レビュー指摘・2 巡目） | `batch_config_rejects_zero_max_bytes`・`batch_config_default_max_bytes_is_max_batch_bytes`・`batch_buffer_fires_on_bytes_limit_before_size_limit`・`batch_buffer_does_not_fire_when_bytes_exactly_at_limit`・`batch_buffer_rejects_single_frame_larger_than_max_bytes`・`batch_buffer_accepts_single_frame_exactly_at_max_bytes`・`max_batch_bytes_bounds_worst_case_far_below_size_only_limit` |

補足: TASK-13.1（#76）でバッチ集約バッファ（`BatchBuffer`）と設定 API（`BatchConfig`）を追加した。ディスク書き込み・ACK 返却・UDS 受信ループ・CLI からのバッチサイズ配線（`--batch-size` 相当）は本書時点では未実装であり、TASK-13.2 系・TASK-13.3 の範囲で扱う（REPAIR-3: 実装済みを装わない）。累積バイト数上限（`MAX_BATCH_BYTES`）は `BatchBuffer` 単体の確保量を抑える安全弁であり、受信経路自体の長さ・件数検証（TASK-13.4）・未フラッシュ滞留量上限（IO-10・TASK-16）とは別物。

## デコード時の検証順序と検出する破壊

`Frame::decode` / `Frame::decode_body` は次の順序で検証し、上限検証前にアロケーションしない（DoS 対策。security.md）。

1. 先頭 `FRAME_HEADER_LEN`（5 バイト）を `FrameHeader::from_bytes` で検証（種別が既知の値か・`payload_len` が `MAX_PAYLOAD_LEN` 以下か）。ここで `IoErrorCode::InvalidArgument`
2. 期待される本体長（`payload_len + CHECKSUM_LEN`）と実際の本体長を比較。不一致なら `IoErrorCode::InvalidArgument`（チェックサム不一致とは別コード）
3. ヘッダ＋ペイロードから再計算した CRC-32C とトレーラの値を比較。不一致なら `IoErrorCode::DataLoss`

PoC-8（`03-poc/ai-self-repair`）の BREAK-2 は、送信側がペイロード長を実際より 1 バイト少なく申告する破壊が `cargo build` を素通りし、整合性テストでしか検出できなかった事例である。本チェックサムは、正しくエンコードされたフレームに対して転送中の偶発的破損（ビット反転・末尾切り詰め等）でヘッダの `payload_len` が書き換わった場合に、元のペイロード＋トレイラの残りバイトを申告長どおりに読み直した結果としてチェックサム不一致を検出し、上記手順 3 で `IoErrorCode::DataLoss` として拒否する（`crates/io/src/protocol.rs` の `repair2_decode_detects_break2_short_declared_len` テストで確認）。ただし、これは CRC-32C が偶発的破損を検出する性質によるものであり、送信側が短く申告した `payload_len` とそれに整合するペイロードからチェックサムを再計算して送出した場合（意図的な長さの偽装）は、ヘッダ・ペイロード・チェックサムが自己整合しているため検出できない（前述「範囲外（真正性は保証しない）」節のとおり CRC-32C は改ざん耐性を持たない）。意図的な偽装への耐性が必要な経路では、別レイヤーでの真正性検証（信頼境界の検証）が必要になる。

BREAK-2 検出経路の整理:

- 送信側の申告誤り（`Frame::new` を経由する限りの誤り）: 型として表現不能（`payload_len` は `payload.len()` から導出される）
- 転送中に長さフィールドが偶発的に破損した場合（一括 `decode`。全長が既知）: `body.len()` と `payload_len + CHECKSUM_LEN` が食い違うため必ず `InvalidArgument`（`DataLoss` には至らない）
- 転送中に長さフィールドが偶発的に破損した場合（ストリーム読み。申告された `payload_len` ぶんだけ読んでから `decode_body` へ渡す想定。TASK-12・TASK-13）: 長さ検証は申告どおりの本体長と一致するため通過し、ペイロード＋チェックサムの再計算で不一致となり `DataLoss`（`repair2_decode_detects_break2_short_declared_len` はこの経路を模している。`tests/frame_integrity.rs` の `stream_read_frame` ヘルパーは同じ経路を公開 API のみで再現し、申告長を短く／長く偽った両方向で確認する。TASK-83.1・#116）
- 意図的な自己整合偽装（申告長・ペイロード・チェックサムを揃えて送出）: 本チェックサムの範囲外（真正性は別レイヤーの責務。上記「範囲外」節のとおり）

## 見直し

- `crates/io/src/protocol.rs` のフレーム形式・定数・`FrameKind` のバリアントが変わった場合は本書を追従させる
- TASK-12（パイプライン送信クライアント）・TASK-13（バッチ write-back サーバー）がペイロード内部のレイアウト（request id・ACK status 等）を確定させた際は、本書へ追記する
