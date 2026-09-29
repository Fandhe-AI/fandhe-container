# I/O 共有層のワイヤーフレーム（チェックサム）

`fandhe-container-io`（`crates/io`）が提供するフレーム全体型（[`Frame`](../../crates/io/src/protocol.rs)）のバイトレイアウト・採用したチェックサムアルゴリズムの根拠・newtype 設計方針・IO-1 / REPAIR-2 対応表を記録する。

- 対象ビヘイビア: IO-1（ホスト⇔ゲスト間のファイル共有プロトコル）・REPAIR-2（壊れた値を表現できない型）・REPAIR-5（タイムアウト保護・エラー後の接続再利用禁止）・REPAIR-6（整合性テスト）
- 関連タスク: TASK-11.1（#68）・TASK-11.2（#69。ヘッダ newtype）・TASK-11.3（#70。チェックサム付きフレーム型）・TASK-11.4（#71。本節以降）・TASK-12.1（#73。送信キュー）・TASK-12.2（#74。ペイロード形式・ACK 受信）・TASK-13.1（#76。バッチ集約バッファ）・TASK-13.2.1（#820。UDS サーバー側トランスポート）・TASK-13.2.2（#822。バッチ write-back の実行・ACK 返却）・TASK-13.3（#78。バッチサイズ設定 API）・TASK-13.4（#796。受信フレームの受理判定ゲート）・TASK-15.1（#85。FLUSH バリア API 型定義・通常 ACK との区別）・TASK-83.1（#116。BREAK-2 相当のワイヤーレベル検出テスト）・TASK-83.2（#117。デコード時の範囲外長さ検証の強化とアロケーション前拒否のテスト）。ヘッダ拡張（version・header_crc）・接続再利用契約は TASK-12・TASK-13 着手前の設計レビュー（2026-09-28 オーナー決定・#67・#115）による
- 関連ビヘイビア: IO-2（Flush / FlushAck 種別）・REPAIR-5（`IoTimeout`。無期限待ちを型で表現しない）
- 対象マイルストーン: MS-1
- ステータス: 本ドキュメントは TASK-11.1〜11.4 で確定したフレーム形式（バイトレイアウト・newtype 設計・IO-1 / REPAIR-2 対応）、TASK-13.1 で追加したバッチ集約バッファ（[`BatchBuffer`](../../crates/io/src/batch.rs)・`BatchConfig`）、TASK-12.1 で追加した送信キュー（`SendQueue`・`PipelineClient`）、TASK-12.2 で追加したペイロード内部レイアウト（[`crates/io/src/payload.rs`](../../crates/io/src/payload.rs)）と ACK 受信・対応付け（`PipelineClient::recv_ack`）、TASK-13.2.1（#820）で追加した UDS サーバー側トランスポート（[`UdsServer`・`UdsConnection`](../../crates/io/src/server.rs)。Linux / macOS）、TASK-13.2.2（#822）で追加したバッチ write-back の実行と通常 ACK 返却（[`serve_connection`・`AppendFileSink`](../../crates/io/src/writeback.rs)）、TASK-13.3（#78）で追加したバッチサイズ設定 API（[`parse_batch_size`・`WritebackSettings`](../../crates/io/src/settings.rs)）、TASK-15.1（#85）で追加した FLUSH バリア API の ACK 型分離（[`barrier`](../../crates/io/src/barrier.rs) モジュールの `WriteAck`・`FlushAck`・`FlushBarrier`・`AckReceipt`、`PipelineClient::flush`）に加え、2026-09-28 の設計レビュー（TASK-12・TASK-13 着手前に P1 として指摘・オーナー決定で先行対応）で追加したヘッダの `version`・`header_crc` フィールドと、エラー後の接続再利用禁止契約を記録する。TASK-15.2.2（#824）で追加した FLUSH バリアの永続化（`syncfs`）と FLUSH ACK 返却（Linux）に加え、クライアント側の UDS 接続との本番結合・Windows のトランスポートは後続 sub-issue が本書へ追記する

## バイトレイアウト

```text
+---------------------------------------+----------------------+---------------------+
| header (10 B)                         | payload (N B)        | checksum (4 B)      |
| version: u8 | kind: u8                | N = payload_len      | CRC-32C, u32 LE     |
| payload_len: u32 LE (N ≤ MAX_PAYLOAD_LEN = 64 MiB)                                  |
| header_crc: u32 LE (CRC-32C over [version, kind, payload_len])                      |
+---------------------------------------+----------------------+---------------------+
```

- `header` は `FrameHeader`（TASK-11.2・#69。ヘッダ拡張は 2026-09-28 の設計レビュー・#67・#115）が持つ固定長 10 バイト（`version: u8` + `kind: u8` + `payload_len: u32 LE` + `header_crc: u32 LE`）
- `payload` は不透明なバイト列。request id・ACK status 等のレイアウトはこの型の関知するところではなく、TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める
- `checksum` はトレーラ（末尾）に置く CRC-32C（4 バイト・リトルエンディアン）で、**ヘッダの意味あるフィールド（`version` ‖ `kind` ‖ `payload_len`。6 バイト。`header_crc` は含めない）+ ペイロード**を対象に計算する

ヘッダの意味あるフィールドも対象に含める理由: ペイロードのみを対象にすると、送信側が申告する `payload_len` を実際より少なく偽る破壊（後述の BREAK-2）に対して、その偽った長さと整合するチェックサムが偶然一致してしまう余地がある。ヘッダを対象に含めることで、種別・長さフィールドの破壊も検出できる。

**なぜトレーラの対象からヘッダ全体（`header_crc` を含む 10 バイト）ではなく `header_crc` を除いた 6 バイトだけを使うか**: CRC-32C は線形写像であり、`M ‖ CRC(M)` を処理した後の CRC レジスタ状態は `M` の中身によらず常に同じ定数（residue。Rocksoft の CRC カタログ・Ethernet FCS の自己検証定数と同種の性質）になる。もしトレーラが `header_crc` を含む 10 バイト全体を対象にすると、送信側が `header_crc` さえ正しく再計算していれば `version`・`kind`・`payload_len` にどんな値を入れてもヘッダ部分の CRC への寄与が常に同一の定数になり、ペイロードが同じである限り「どの自己整合ヘッダに差し替えても同じトレーラ値」になってしまう（実測: `version=1`・`payload_len=5` 固定で `kind` だけを 4 種変えた場合、10 バイト全体を対象にすると全通り `0x64e6a5da` に一致する一方、6 バイトの prefix を対象にすると 4 通りとも異なる値になることを確認済み）。これは「トレーラが種別・長さフィールドの破壊も検出する」という設計意図を静かに壊すため、`header_crc` を除いた 6 バイトを対象にしている（実装時の逸脱の詳細は `crates/io/src/protocol.rs` の `Frame::compute_checksum` ドキュメンテーションコメントを参照）。

### オフセット表

| オフセット | サイズ | フィールド | 型・エンコード | 検証内容 | 違反時のエラーコード |
| ---------- | ------ | ---------- | --------------- | -------- | -------------------- |
| `0` | 1 B | `version` | `u8`（[`PROTOCOL_VERSION`](../../crates/io/src/protocol.rs)） | このビルドの `PROTOCOL_VERSION` と一致するか | `UNIMPLEMENTED` |
| `1` | 1 B | `kind` | `u8`（[`FrameKind`](../../crates/io/src/protocol.rs)） | 既知値（1〜4）か | `INVALID_ARGUMENT` |
| `2` | 4 B | `payload_len` | `u32` LE（[`PayloadLen`](../../crates/io/src/protocol.rs)） | `≤ MAX_PAYLOAD_LEN` | `INVALID_ARGUMENT` |
| `6` | 4 B | `header_crc` | CRC-32C `u32` LE | `[version, kind, payload_len]`（オフセット `0..6`）の再計算値と一致 | `DATA_LOSS` |
| `10` | N B | `payload` | 不透明なバイト列 | 実本体長 = `payload_len + CHECKSUM_LEN` | `INVALID_ARGUMENT` |
| `10+N` | 4 B | `checksum` | CRC-32C `u32` LE（[`FrameChecksum`](../../crates/io/src/protocol.rs)） | `[version, kind, payload_len]`（6 B）‖ payload の再計算値と一致 | `DATA_LOSS` |

### 定数

| 定数 | 値 | 備考 |
| ---- | -- | ---- |
| `PROTOCOL_VERSION` | 1 | このビルドが送受信するワイヤー形式のバージョン。「バージョン方針」節を参照 |
| `FRAME_HEADER_LEN` | 10 | version 1 バイト + 種別 1 バイト + ペイロード長 4 バイト + ヘッダ CRC 4 バイト |
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

- `Write`・payload `"abc"`: `01 01 03 00 00 00 06 f1 29 e2 61 62 63 59 2a cd e8`（`header_crc` = `0xe229f106`・trailer `checksum` = `0xe8cd2a59`）
- `Flush`・空 payload: `01 03 00 00 00 00 67 a7 29 f0 67 a7 29 f0`（`header_crc` = `0xf029a767`・trailer `checksum` = `0xf029a767`。ペイロードが空のためトレーラは `header_crc` と同じ入力〔`[version, kind, payload_len]`〕から計算され、`header_crc` と同じ値になる）

## バージョン方針（P1-1・設計レビュー・2026-09-28 オーナー決定）

ホスト側 CLI と microVM ゲストは別ビルドになり得るため、`version` フィールドでワイヤー形式の版ずれをフレームごとに検出する。ワイヤー形式（ヘッダ・フレーム全体のバイトレイアウト）を変える変更は必ず `PROTOCOL_VERSION` を上げる。MVP ではネゴシエーション（Hello 交換）は行わず、`FrameHeader::from_bytes` が受信した `version` と自分自身の `PROTOCOL_VERSION` を比較し、不一致を `UNIMPLEMENTED` として返す（message に受信 `version` と対応 `PROTOCOL_VERSION` の両方を含める）。ネゴシエーションが必要になった場合（複数バージョンの相互運用が要件化した場合）は別途設計する。

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
- **`FrameHeader`**: 非公開フィールドを持ち、`new` / `from_bytes` のみで構築でき、`to_bytes` は固定長 `[u8; FRAME_HEADER_LEN]` を返す。`version` は常に構築時のビルドの `PROTOCOL_VERSION` であり、フィールドとして保持しない（`from_bytes` の不一致は構築失敗として扱う）。request id・ACK status を含めないのは、それらがペイロード側の責務（TASK-12・TASK-13）であり、ヘッダの役割を version・種別・長さの検証に限定するため。`body_len()`（TASK-83.2・#117）は検証済みの `payload_len` から本体長（`payload_len + CHECKSUM_LEN`）を返す失敗しない関数で、受信側（ストリーム読み。TASK-12・TASK-13）が読み取り上限に使う値を一元化し、生のヘッダバイトから長さを自前で再計算する経路を排除する。`header_crc`（2026-09-28 設計レビュー追加）はヘッダ単体の CRC-32C で、ストリーム読みが `body_len()` ぶんの巨大確保をする前にヘッダの偶発的破損を検出する
- **`FrameChecksum`**: 公開コンストラクタを持たない。呼び出し側が任意のチェックサム値を注入する経路が型として存在しない
- **`Frame`**: 不変条件は 2 点（`header.payload_len().get() as usize == payload.len()`、`checksum` がヘッダの意味あるフィールド（`prefix_bytes()`。6 バイト。`header_crc` を含まない）‖ payload の CRC-32C と一致）。`Frame::new` はヘッダの `payload_len` を引数のペイロード実長（`payload.len()`）から導出するため、送信側が「実際より短い長さ」を申告する経路が型として存在しない（BREAK-2 の送信側原因を型で封じ込める）。`Debug` は手書きし、ペイロード内容を出力しない
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
| IO-1 | 長さ上限の検証（DoS 対策） | `PayloadLen::new` / `FrameHeader::from_bytes` がアロケーション前に検証。申告長に比例するペイロード用バッファの確保は `copy_validated_payload`（非公開）の 1 か所に集約し、長さ検証・チェックサム検証を通過した後にのみ呼ぶ（TASK-83.2・#117） | `io1_payload_len_rejects_max_plus_one`・`io1_frame_header_from_bytes_rejects_len_over_max`・`tests/protocol.rs` の `io1_public_api_frame_new_rejects_oversized_payload`・`repair2_decode_rejects_over_max_len_before_allocation`・`repair2_decode_body_rejects_len_mismatch_before_allocation`・`repair2_decode_rejects_checksum_mismatch_before_allocation`・`repair2_decode_allocates_exactly_once_for_valid_frame`（陽性対照） |
| REPAIR-2 | 長さ偽装（BREAK-2） | 送信側: `Frame::new` の長さ導出で表現不能。受信側: 本体長不一致（`INVALID_ARGUMENT`）またはチェックサム不一致（`DATA_LOSS`）で拒否 | `repair2_decode_detects_break2_short_declared_len`・`io1_decode_rejects_length_mismatch`・`tests/protocol.rs` の `io1_public_api_decode_rejects_length_mismatch`・`tests/frame_integrity.rs`（TASK-83.1・#116。ワイヤー上の `payload_len` フィールド自体を書き換えた入力で、一括 `decode` とストリーム読みの両経路を確認: `repair2_break2_declared_len_shorter_rejected_by_decode`・`repair2_break2_declared_len_shorter_rejected_by_stream_read`・`repair2_break2_declared_len_longer_rejected_by_decode`・`repair2_break2_declared_len_longer_rejected_by_stream_read`・`repair2_break2_declared_len_zero_rejected_by_both_paths`・`repair2_break2_declared_len_over_max_rejected_by_decode`） |
| REPAIR-2 | ビット反転・種別すり替え・チェックサム破損の検出 | CRC-32C（ヘッダ + ペイロードを対象） | `repair2_decode_rejects_flipped_payload_bit`・`repair2_decode_rejects_kind_swapped_to_valid_kind`・`repair2_decode_rejects_corrupted_checksum`・`tests/protocol.rs` の `io1_public_api_decode_rejects_corrupted_payload`・`io1_public_api_decode_rejects_corrupted_checksum` |
| REPAIR-2 | 未知種別・切り詰めの拒否 | `FrameKind::try_from`・`Frame::decode` の `split_first_chunk` | `io1_frame_kind_rejects_unknown_bytes`・`io1_frame_header_from_bytes_rejects_unknown_kind`・`io1_decode_rejects_truncated_header`・`tests/protocol.rs` の `io1_public_api_decode_rejects_too_short_input` |
| IO-1 | CRC 実装の正しさ | `crates/io/src/checksum.rs` の `Crc32c` | `io1_crc32c_matches_standard_check_value`・`io1_crc32c_matches_rfc3720_vectors`・`io1_crc32c_split_update_matches_single_call` |
| REPAIR-5・REPAIR-6 | ヘッダ単体の破損をペイロード確保前に検出（P1-2。ストリーム読みでの巨大確保・待ち続けの防止） | `FrameHeader::from_bytes` が `header_crc` を最初に検証（version・kind・payload_len のどの破損も `DATA_LOSS` として即座に拒否） | `repair5_frame_header_from_bytes_rejects_header_crc_mismatch`・`repair5_frame_header_from_bytes_detects_any_single_bit_flip`（10 バイト全オフセットの 1 ビット反転） |
| REPAIR-5 | ホスト⇔ゲスト間のワイヤー形式の版ずれ検出（P1-1） | `PROTOCOL_VERSION`・`FrameHeader::from_bytes` の version 照合（`header_crc` 検証の後、種別・長さ検証の前） | `repair5_frame_header_from_bytes_rejects_version_mismatch`（message に受信 version と対応 version の両方を含むことも確認） |
| REPAIR-2 | 自己整合的なヘッダ差し替え（kind swap）の検出がトレーラの CRC 残差性質で壊れないこと | `Frame::compute_checksum` がトレーラの対象を `prefix_bytes()`（`header_crc` を含まない 6 バイト）に限定 | `repair2_decode_rejects_kind_swapped_to_valid_kind`（`header_crc` を正しく再計算した自己整合ヘッダへの差し替えでも `DATA_LOSS` になることを確認する回帰テスト） |
| REPAIR-5・REPAIR-6 | エラー後の接続再利用禁止（P1-3。フレーム境界の同期マーカー欠如） | `FrameSender::send_frame` / `FrameReceiver::recv_frame` のドキュメンテーションコメントの契約（実装はエラー後 `UNAVAILABLE` を返し続けなければならない） | `transport.rs` の `p1_3_connection_becomes_unavailable_after_error`（mock 実装での契約確認。具象トランスポート実装〔TASK-12・TASK-13〕はこの契約に従う義務を負う） |
| IO-1 | 既定 64 件（設定可能）単位でのバッチ集約 | `crates/io/src/batch.rs` の `BatchBuffer::push`・`BatchConfig`（既定値 `DEFAULT_BATCH_SIZE = 64`・上限 `MAX_BATCH_SIZE = 4096`〔暫定〕） | `io1_batch_buffer_fires_at_default_64`・`io1_batch_buffer_fires_at_custom_size_8`・`io1_batch_config_default_is_64`・`io1_batch_config_rejects_zero`・`io1_batch_config_rejects_above_max`・`tests/batch.rs` の `io1_public_api_batch_buffer_fires_at_default_size`・`io1_public_api_batch_config_custom_size_fires`・`io1_public_api_batch_config_rejects_zero` |
| P0 | バッチ 1 つあたりの累積ペイロードバイト数の上限（無制限確保による DoS の防止） | `BatchConfig::max_bytes` / `BatchConfig::with_max_bytes`（既定 `MAX_BATCH_BYTES = 256 MiB`〔暫定〕）。累積が上限を超える手前で `BatchBuffer::push` が既存滞留分を `BatchTrigger::BytesLimitReached` として強制発火させる（件数上限 `MAX_BATCH_SIZE` × 1 フレーム最大長 `MAX_PAYLOAD_LEN` の理論値〔約 256 GiB〕とは独立した安全弁。PR #1105 codex レビュー指摘）。フレーム単体のペイロード長が `max_bytes` を超える場合は `pending` の状態によらず追加前に `INVALID_ARGUMENT` で拒否し、`pending_bytes` が `max_bytes` を上回った状態を作らない（`with_max_bytes` は `MAX_PAYLOAD_LEN` より小さい値も個別設定できるため。PR #1105 codex レビュー指摘・2 巡目） | `batch_config_rejects_zero_max_bytes`・`batch_config_default_max_bytes_is_max_batch_bytes`・`batch_buffer_fires_on_bytes_limit_before_size_limit`・`batch_buffer_does_not_fire_when_bytes_exactly_at_limit`・`batch_buffer_rejects_single_frame_larger_than_max_bytes`・`batch_buffer_accepts_single_frame_exactly_at_max_bytes`・`max_batch_bytes_bounds_worst_case_far_below_size_only_limit` |
| TASK-13.4 | 受信フレームの長さ・滞留件数を、本体バッファ確保前に設定上限で検証する受理判定ゲート（無制限確保による DoS の防止） | `crates/io/src/recv_limits.rs` の `ReceiveLimits::admit`（`BatchConfig` から `for_batch` で導出。`RESOURCE_EXHAUSTED` で拒否）・`AdmittedHeader::allocate_body`（受理後に一括で本体バッファを確保する経路） | `io1_admit_rejects_payload_over_limit_before_allocation`・`io1_admit_rejects_pending_at_limit_before_allocation`・`io1_admit_pending_check_ignores_control_frames`・`io1_admit_accepts_boundaries`・`io1_admitted_allocates_exactly_once`（陽性対照）・`io1_admitted_decode_body_round_trips`・`tests/recv_limits.rs` の `io1_public_api_under_limit_frames_are_buffered`・`io1_public_api_over_config_max_bytes_rejected_before_batch_push` |
| TASK-13.3 | `--batch-size` 相当の設定 API（CLI / 設定の文字列から検証済み `BatchConfig`・`ReceiveLimits` を単一の入口から導く） | `crates/io/src/settings.rs` の `parse_batch_size`・`WritebackSettings`（`FromStr for BatchConfig` も同じ検証へ委譲） | `settings.rs` の `io1_parse_batch_size_accepts_one`・`io1_parse_batch_size_accepts_max`・`io1_parse_batch_size_rejects_zero_and_out_of_range`・`io1_parse_batch_size_rejects_non_ascii_digit`・`io1_parse_batch_size_rejects_overflow`・`io1_writeback_settings_receive_limits_match_batch_config`・`tests/settings.rs` の `io1_settings_rejects_zero_and_negative`・`io1_settings_rejects_non_numeric_and_out_of_range`・`unix::io1_settings_batch_size_{1,5,64}_via_uds_fires_at_configured_count` |

補足: TASK-13.1（#76）でバッチ集約バッファ（`BatchBuffer`）と設定 API（`BatchConfig`）を追加した。TASK-13.2.1（#820）で UDS サーバー側トランスポート（`UdsServer`・`UdsConnection`。Linux / macOS。1 接続の期限付き送受信までを提供し、受付ループ自体は呼び出し側が組む）を追加した。TASK-13.2.2（#822）でディスク書き込み・ACK 返却・`BatchBuffer` とのつなぎ込み（`serve_connection`・`AppendFileSink`）を追加した。TASK-13.3（#78）で `--batch-size` 相当の設定 API（CLI / 設定の文字列から検証済み `BatchConfig` と `ReceiveLimits` を単一の入口から導く `WritebackSettings`・`parse_batch_size`）を追加した（「バッチサイズ設定 API」節参照）。実際の CLI バイナリ（`fandhe-container`）からその値を受け取る配線・クライアント側の UDS 接続は本書時点では未実装であり、TASK-79・後続タスクの範囲で扱う（REPAIR-3: 実装済みを装わない）。累積バイト数上限（`MAX_BATCH_BYTES`）は `BatchBuffer` 単体の確保量を抑える安全弁であり、受信経路の長さ・件数検証は `recv_limits`（TASK-13.4・#796）が担う。複数接続を跨いだ累積・未フラッシュ滞留量上限（IO-10・TASK-16）とは別物。

「確保量の上限は `admit` を通過した `AdmittedHeader` からしか得られない」という契約には 2 つの経路がある（#820 レビュー指摘。security P2）: 一括確保する経路は `AdmittedHeader::allocate_body`（`Frame::decode_body` 等が本体をまるごと読める場合向け）を使い、相手が遅い・悪意ある場合でも接続 1 本あたりの瞬間的なメモリ使用量を抑えたい分割読みの経路（`crates/io/src/server.rs` の `read_body_until`。UDS 受信ループが使う）は本メソッドを経由せず `AdmittedHeader::body_len` を読み取りの上限として使う。どちらの経路も `AdmittedHeader` を経由しない長さを確保量へ用いてはならない。分割読みの経路は、確保容量そのものも `body_len` 以下に保つ（`imp::BodyBuffer`。初期容量 `min(body_len, 64 KiB)`、空きを使い切ったときだけ `reserve_exact` で最大 64 KiB ずつ伸ばし、償却つきの成長〔2 倍化〕で `body_len` を超えて確保しない。読み込み先は `Vec` の領域そのもので中間バッファを持たない。#820 codex P0 指摘対応）。復号は所有権を受け取る crate 内部の変種（`AdmittedHeader::decode_body_owned` → `Frame::decode_body_owned`。検証は `Frame::decode_body` と共通の `Frame::verify_body`）で行い、チェックサム検証後に末尾のチェックサムを落とした同じ領域をペイロードとして使う（複製しない）。したがって 1 フレームの受信で申告長に比例して確保するのは `body_len` ぶんの 1 回だけである（#820 codex P0 指摘対応）。

### UDS サーバーの観測（REPAIR-4・REPAIR-5・TASK-13.2.1・#820）

`UdsServer::bind`・`UdsServer::accept`（`crates/io/src/server.rs`）は `crate::observe::ServerObserver` を必須引数として要求する（観測しない場合は呼び出し元が `NoopServerObserver` を明示的に渡す。暗黙の既定にはしない。TASK-12.1・#73 の `SendObserver` と同じ方針）。accept（`ServerOp::Accept`）は `bind` で渡した観測フックへ、1 接続内の送受信（`ServerOp::Recv`・`ServerOp::Send`）は `accept` が受け取る接続ごとの観測フックへ、成功・各拒否（プロトコル違反・`ReceiveLimits::admit` の拒否・poison 済みでの拒否）・タイムアウトを含む全分岐で最終結果のイベントを 1 回通知する。送受信は 1 回の呼び出しにつき 1 回だが、`accept` の中で peer credential 拒否が起きた場合は、拒否 1 件ごとのイベント（`reason` が `rejected_peer_credential`）に加えて最終的な成功・失敗イベントも通知するため、1 回の `accept` 呼び出しで `1 + 拒否件数` 回通知される（H1・#820 security-auditor 指摘対応。「UDS の peer credential 検証」節参照）。`on_event` はブロックする I/O を行わない（`crate::observe::JsonLinesServerObserver` はメモリ内バッファへ積むだけにとどめ、実際の書き出しは呼び出し元が `drain_lines` を呼んで行う）。

既定実装 `JsonLinesServerObserver` の出力キーは `JsonLinesSendObserver`（TASK-12.1・#73）と共通の語彙に揃え、次の順で固定する: `event`（常に `"io_server"`）・`op`（`"accept"`/`"recv"`/`"send"`）・`kind`（`WRITE`/`ACK`/`FLUSH`/`FLUSH_ACK`。`Accept` やヘッダ検証前の拒否ではキー自体を省く）・`outcome`（`"ok"`/`"error"`）・`reason`（失敗系のみ。`success`/`rejected_poisoned`/`rejected_peer_credential`/`failure` のいずれかで、P1-3 の poison 拒否〔`rejected_poisoned`〕・peer credential 拒否〔`rejected_peer_credential`。H1・#820 security-auditor 指摘対応〕とそれ以外の失敗〔`failure`〕を区別できる。ただし監査枠があふれたときの集約行〔後述〕だけは `peer_credential_rejections_coalesced` を使う）・`code`（失敗系のみ・ERR-1 文字列）・`message`（失敗系のみ・512 バイトで切り詰め・エスケープ済み）・`message_truncated`（切り詰め発生時のみ `true`）・`accept_aborted_retries`（`u32`。`Accept` が `ConnectionAborted`〔相手が accept 完了前に切断した〕により受付ループ内で再試行した回数。`Recv`/`Send` では常に `0`）・`peer_credential_rejections`（`u32`。`Accept` が peer credential の検証失敗により再試行した回数。`accept_aborted_retries` とは別に数える。H1・#820 security-auditor 指摘対応。「UDS の peer credential 検証」節参照。`Recv`/`Send` では常に `0`）・`peer_uid`（`u32`。peer credential 拒否で接続元の uid が取得できた場合のみキーを出す。H1・#820）・`coalesced`・`count`・`latency_sum_us`（分割後の保留キューがあふれた分の集約イベントのみ。下記「分割後の観測と集約イベント」節。#1118）・`latency_us`（集約イベントでは最大値）。`JsonLinesServerObserver` は有界の一時バッファであり、永続的な SEC-4 監査ログではない（`drain_lines` で取り出した行を永続的な監査ログへ書き出す配線は TASK-13.2.2・#822 で行う）。バッファは 2 つの枠に分かれ、互いに追い出し合わない（#820 codex P0 指摘対応）:

- 通常枠（peer credential 拒否以外）: 行数上限（`DEFAULT_SEND_LOG_CAPACITY`・`MAX_SEND_LOG_CAPACITY`）・合計バイト数上限（`MAX_SEND_LOG_BUFFER_BYTES` = 1 MiB）・満杯時に新規イベント側を破棄して `dropped_count` を増やす方針を `JsonLinesSendObserver` と共有する
- 監査枠（`reason` が `rejected_peer_credential` のイベント専用）: 行数上限 `SERVER_AUDIT_LOG_CAPACITY`（256 行）・合計バイト数上限 `MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`（128 KiB）。満杯になっても拒否を捨てず、以降の拒否を 1 件の集約レコードに合算する（集約が始まったら drain まで以降の拒否はすべて集約する）。集約行は `{"event":"io_server","op":"accept","outcome":"error","reason":"peer_credential_rejections_coalesced","count":N,"last_peer_uid":U}`（`last_peer_uid` は最後に集約した拒否の接続元 uid で、取得できなかった場合はキー自体を省く）

ためる量の上限は通常枠 1 MiB + 監査枠 128 KiB + 集約行 1 行（数値のみ・256 バイト以下）で、`message` の切り詰め長（`MAX_SEND_LOG_MESSAGE_BYTES`）は両枠で共通。`drain_lines` は両枠と集約行を `on_event` に届いた順にマージして 1 本で返し、集約行は最初に集約した拒否が届いた位置に置く（欠けた区間の始点を前後のイベントとの関係で示す。監査枠専用の drain API を別に設けると、`drain_lines` だけを呼ぶ呼び出し元が監査枠を取り出さず集約し続けるため採らない）。契約は「peer credential 拒否は黙って失われない（個別の行、または欠けた区間を明示する集約行として `drain_lines` に現れる）」。集約した件数の累計は `coalesced_peer_credential_rejections()`、集約が 1 度でも起きたかは `audit_degraded()`（drain 後も `false` に戻らない）で得られ、通常枠の破棄件数 `dropped_count` には拒否は含まれない。`bind` 自体（`ServerOp` に `Bind` は含まれない）は観測イベントを発生させない。

#### 分割後の観測と集約イベント（REPAIR-4・REPAIR-5・#1118）

`UdsConnection` を `SplitTransport::split` で `UdsSendHalf` / `UdsRecvHalf` に分けると、両半分は 1 つの観測フックを共有する。送受信の結果はいったん有界の保留キュー（`MAX_PENDING_EVENTS` = 1024 件）へ積み、フックのロックが取れたときに順序どおり適用する。I/O 経路はロックを待たず、排出も件数（`MAX_DRAIN_PER_CALL`）と送受信の `IoTimeout` 期限で打ち切る（REPAIR-5）。期限で残ったイベントは次の送受信・`with_observer`（クロージャの実行前に排出する）・最後の参照の drop のいずれかで必ず適用する。

保留キューが満杯のときは、あふれた操作を捨てずに `(op, kind, outcome, code)` ごとの集約値へ合算する。集約値は、件数・所要時間の最大値と合計・最後のメッセージ（切り詰め済み）を持つ。分割後の両半分から届くキーは最大 100 種類で、表の上限は `MAX_COALESCED_KEYS` = 128 件（op 2 × kind 5 × 〔`(Success, なし)`・`(RejectedPoisoned, UNAVAILABLE)`・`(Failure, エラーコード 8 種類)`〕= 100。`Accept` と `RejectedPeerCredential` はこの経路を通らない）。表も満杯の場合は fail-closed で件数だけを数え、`ResourceExhausted` の欠落サマリ（`observer event queue overflowed; N events were dropped`）で通知する。排出の順序は 欠落サマリ → 集約イベント → キュー本体とする。時系列では集約分のほうが後だが、フック側の行数上限（既定 1024 行 = キュー上限）で捨てられないよう先に出す。

集約値はフックへ `ServerEvent::coalesced = Some(CoalescedServerEvents { count, latency_sum })` の 1 イベントとして届く。このとき `latency` は集約した操作の **最大値** で、合計は `latency_sum` に入る（平均は `latency_sum / count`）。`JsonLinesServerObserver` はこれを、通常の行と同じキーに `"coalesced":true`・`count`（`u64`）・`latency_sum_us` を `latency_us` の直前へ加えた 1 行で出す。この行の `latency_us` は最大値である。例: `{"event":"io_server","op":"recv","kind":"WRITE","outcome":"error","reason":"failure","code":"TIMEOUT","message":"last","accept_aborted_retries":0,"peer_credential_rejections":0,"coalesced":true,"count":2,"latency_sum_us":11000,"latency_us":8000}`。`count` のない行は 1 行 1 操作なので、操作別・結果別の件数は「`count` があればその値、なければ 1」の合計で求められる。

### UDS の受信上限（[`ReceiveLimits`]。F・#820 codex P1 指摘対応）

`UdsServer::bind` は検証済みの `ReceiveLimits`（TASK-13.4・#796。上記「IO-1 / REPAIR-2 対応表」参照）を構築時の必須引数として受け取り、`UdsServer::accept` が返す各 `UdsConnection` へそのまま引き継ぐ。`recv_frame`（`crates/io/src/server.rs` の `imp::ConnectionInner::recv_frame`）はこの受け取った上限を使い、`ReceiveLimits::default()` を暗黙に使うことはない。呼び出し側が `BatchConfig::with_max_bytes` 等で既定値より小さい上限を設定した場合、その設定が実際の UDS 受信経路（本体バッファの確保前検証）へ確実に反映される（`crates/io/tests/server.rs` の `f_820_uds_recv_honors_receive_limits_passed_to_bind` で確認する）。

### UDS の peer credential 検証（PLUG-12・security.md「UDS は所有者・権限・symlink を検証してから bind し、別 UID からの接続は peer credential 検証で切断する」。E・#820 codex P0 指摘対応。H1〜H4・H6・#820 security-auditor 指摘対応）

`UdsServer::accept` は、accept した接続の相手側の接続時点の実効 uid（euid）が、`UdsServer::bind` の時点で 1 回だけ取得して保存した自プロセスの実効 uid と一致することを確かめる（accept のたびに取り直さない。I2・#820 security-auditor 再監査指摘対応。`SO_PEERCRED` の `struct ucred.uid`・`getpeereid(2)` の値はいずれも相手プロセスの実 uid ではなく接続時点の euid。接続元が別の user namespace にあり uid がマッピングされていない場合は `overflowuid`〔Linux の既定値 `65534`〕として見え、実効 uid と一致せず拒否される。H2・#820 security-auditor 指摘対応）。接続元の euid の取得には std だけでは取得できない値が必要で、`libc`/`nix` の依存を追加せず（dependency-policy）、`crates/io/src/sys.rs`（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27）が FFI で直接呼ぶ: Linux は `getsockopt(SOL_SOCKET, SO_PEERCRED)`（`SOL_SOCKET`/`SO_PEERCRED` の値は `x86_64`/`aarch64` それぞれで個別定義し、他アーキテクチャでは `Unimplemented` を返す）、macOS は `getpeereid(2)`。自プロセスの実効 uid は両 OS 共通の `geteuid(2)` で取得する（第 1 ラウンド〔#820〕時点で bind 時の所有者照合〔`imp::check_socket_owner`〕が使っていた「ソケットファイルの所有者を実効 uid の代理として使う」手法は、`geteuid(2)` を直接呼べるようになったことでこの代理を経由しない直接比較に置き換えた）。この実効 uid と親ディレクトリの所有者の照合は bind より前（`imp::validate_parent_dir` の中）で行い、不一致ならソケットファイルを作らずに `InvalidArgument` で拒否する（I1・#820 security-auditor 再監査指摘対応。bind 後に照合して作成済みのファイルを片付ける方式は、片付けの stat → unlink の間に親ディレクトリを symlink へ差し替えられる TOCTOU を生むため採らない）。

比較するのは uid のみで、gid・pid・所属する user namespace は見ない。user namespace の中にいても本プロセス側から見て同じ uid に写されるプロセス（rootless コンテナ内の root が、本プロセスを実行しているホストの非特権 uid に写されている場合等。SEC-5）は、本プロセスと同じ主体として受理する（I6・#820 security-auditor 再監査指摘対応）。これはソケットのパス（とその親ディレクトリ）をコンテナへマウントしないことを前提にした設計であり、コンテナ内のプロセスがソケットへ到達できる構成ではこの照合だけでは分離にならない（到達経路を塞ぐのは呼び出し側・マウント構成の責務）。

不一致・取得失敗（対応していないアーキテクチャを含む）のいずれも拒否する（fail-closed）。拒否した接続はすぐに閉じ、1 件の不正な接続で受付ループ全体は止めない（期限・再試行回数上限の両方で有界に、`ACCEPT_POLL_INTERVAL` の待ちを挟んで再試行する。H6）。SEC-4「分離違反の試行は監査ログに記録する」に従い、拒否 1 件ごとに `ServerOutcome::RejectedPeerCredential` のイベントを `bind` で渡した観測フックへ即座に通知し、正常な接続が最終的に成立してもそれまでの拒否の通知が取り消されないようにする（H1・#820 security-auditor 指摘対応。通知は他の観測イベントと同じくブロックする I/O を行わない）。既定実装の `JsonLinesServerObserver` はこれを専用の監査枠に積み、あふれた分は集約行として残す（上記「UDS サーバーの観測」節。#820 codex P0 指摘対応）。件数は `ConnectionAborted`〔相手が accept 完了前に切断した〕の `accept_aborted_retries` とは分けて `peer_credential_rejections` で数え、最終的な Accept の成功・失敗イベントにも両方の件数を載せる（上記「UDS サーバーの観測」節参照）。件数の加算と拒否の通知は期限切れの判定より先に行う（H3）。再試行の上限を超えた場合は、実装バグを示す `Internal` ではなく相手に起因する異常を示す `Unavailable` を返す（H4）。この `Unavailable` は不正・無効な接続が続いたことを示すだけでリスナー自体は健全であり、呼び出し元は同じ `UdsServer` で `accept` を再度呼んでよい（受付ループを継続できる。受付ループの扱いは TASK-13.2.2・#822）。これに対し `UdsConnection` の送受信が返す `Unavailable` は、その接続が poison 済みで以後使えず再接続が必要であることを示す（下記「エラー後の接続再利用禁止」節。I7・#820 security-auditor 再監査指摘対応）。拒否時のエラーコードは新設せず、bind 時の所有者照合と同じ `InvalidArgument` を使う。

別 uid からの接続は root 権限がないと再現できないため結合試験の対象にはせず、uid の一致判定を純粋関数（`imp::peer_credential_matches`）へ切り出して具体値で検証する（`crates/io/src/server.rs` のユニットテスト）。拒否 1 件ごとの通知から最終イベントまでの配線は、同じファイルのユニットテストで照合関数をテスト時だけ差し替え（非公開の `imp::ServerInner::accept_with`。本番の `accept` は常に固定の照合を渡す）、実際のソケット（同一 uid の接続）で確かめる（I4・#820 security-auditor 再監査指摘対応）。同一プロセスからの自己接続（`UnixStream::pair`）で `crate::sys::peer_uid` が自プロセスの実効 uid と一致することは `crates/io/src/sys.rs` のユニットテストで確認する。

### UDS の期限判定（REPAIR-5・K1・K2・#820 codex P1 指摘対応）

`UdsServer::accept` は listen キューから接続を取り出す前（再試行のたびを含む）と、peer credential の照合を通過して接続を返す直前の両方で期限を判定し、期限を過ぎてから取り出しを始めず、取り出し・照合の間に期限を過ぎた接続は閉じて `Timeout` を返す（成功を返した後の接続は呼び出し元の責任になるため）。`UdsConnection` の `send_frame` / `recv_frame` は 1 回ごとの read / write を始める前に期限を判定し（待ちも残り時間を上限にする）、期限内に始めた最後の read / write が期限をわずかに超えて完了した場合は成功として返す。完了したバイト列はすでにカーネルへ渡した / ストリームから取り出した後であり、`Timeout` にすると送信では相手が完全なフレームを受け取っているのに失敗扱い（poison・再送による重複）になり、受信ではそのフレームを失うためである。

相手が完全なフレームを送り切ってから close した場合も、`recv_frame` はそのフレームを受信でき、受信バッファが尽きた次の `recv_frame` が `Unavailable` を返す（IO-1・REPAIR-5・#820。`crates/io/tests/server.rs` の `io1_repair5_820_recv_reads_frames_sent_before_peer_close` で確認）。macOS では、相手が close した後のソケットに対する `set_read_timeout`（`setsockopt(SO_RCVTIMEO)`）が `EINVAL` を返す（CI での実測。XNU のソースを読む限り、送受信とも shutdown 済みのソケットへの setsockopt が一律に `EINVAL` になるように見える）。この `EINVAL` を読み取り経路で失敗にすると受信バッファに残った正当なフレームを失うため、読み取り経路ではソケットを nonblocking に切り替えてタイムアウトなしで残りを読み（drain）、データが尽きた時点（read が 0 または `WouldBlock`）で `Unavailable` を返す。nonblocking の read はブロックしないため、タイムアウトを設定できなくても待ち続けない。各 read の前の期限判定は drain 中も行い、読み取り関数を抜ける際に blocking へ戻す。書き込み経路の `set_write_timeout` の `EINVAL` は、相手が閉じていれば書けないため従来どおり `Unavailable` にする。Linux では相手の切断後も setsockopt は成功し切断は read / write の結果で分かるため、`EINVAL` は相手の切断とみなさず `Internal` として扱う（H7・#820 security-auditor 指摘対応。実装は `crates/io/src/server.rs` の `classify_read_timeout_error`・`map_write_timeout_error`・`ReadWait`）。

### UDS ソケットファイルのモード（PLUG-12・security.md。J2・#820 codex P0 指摘対応）

`UdsServer::bind` は bind の後にソケットのパスを再解決する操作（パス経由の chmod 等）を行わない。以前は bind 後にパス経由でソケットファイルを `0600` へ chmod していたが、bind 後にパスや祖先ディレクトリを差し替えられると、symlink の参照先など別のファイルのモードをサーバープロセスの権限で変えうるため廃止した。socket fd 経由の `fchmod(2)` も代替にならない: Linux では sockfs 側の inode にしか作用せず、ファイルシステム上のソケットファイル（パスの inode）のモードは変わらない（#820 で実測。fd 側の `fstat` は `0600` に変わるが、パスの `lstat` は umask 由来のモード〔umask 022 で `0755`〕のまま）。macOS では socket fd への `fchmod(2)` 自体がエラーになる。

したがってソケットファイル自体のモードは bind 時の umask に従う（umask `000` なら `0777`）。別 uid の到達を遮断するのはソケットファイルのモードではなく、(1) bind 前に検証する親ディレクトリ（symlink でない・ディレクトリである・`mode & 0o077 == 0`・所有者 == 自プロセスの実効 uid。パス名での `connect(2)` には親ディレクトリの search 権限が要るため、owner 以外はソケットファイルのモードに関係なく到達できない）と、(2) accept 時の peer credential 検証（上記「UDS の peer credential 検証」節）の 2 段である。親ディレクトリの検証は bind 時点の 1 回だけで、以後も owner 専用に保つのは所有者（呼び出し側）の責務とする。結合試験 `io1_plug12_uds_parent_dir_guards_socket_access_and_cleanup`（`crates/io/tests/server.rs`）が bind 後の親ディレクトリの不変条件を確かめる。

### UDS ソケットファイルの片付け（PLUG-12・security.md。J3・#820 codex P1 指摘対応）

`UdsServer::bind` は bind 直後に `symlink_metadata` でパス上のファイルを調べ、ソケットであり・所有者 uid が bind 時点の実効 uid と一致することを確かめて、その `(dev, ino)`・所有者 uid を保存する（`imp::SocketFileIdentity`。socket fd の `fstat` は sockfs 側の inode を返しパスの inode と一致しないため、記録にはパスの `lstat` を使う）。確かめられなかった場合（別物に差し替わっていた等）は、自分が作ったと確認できないためパス上のファイルを削除せず、listener を閉じてエラーを返す（`symlink_metadata` 自体の失敗は `Internal`、ソケットでない・所有者 uid が異なる場合は bind 前の所有者照合と同じ `InvalidArgument`）。

`UdsServer` の `Drop`（と bind 失敗時の後始末）は、削除直前に `symlink_metadata` で取り直した実体が、保存した実体（ソケットであること・`(dev, ino)`・所有者 uid）とすべて一致する場合だけソケットファイルを削除し、一致しなければ何もしない。bind 後に元のパスが unlink され、別の listener が同じパスへ bind した場合でも、古い `UdsServer` の drop が新しいソケットを削除して接続不能にすることはない（結合試験 `j3_plug12_uds_drop_keeps_socket_rebound_by_another_listener`）。検査と削除の間に残る競合の窓でパス上のファイルを差し替えられるのは、親ディレクトリ（owner 専用・自プロセスの実効 uid が所有）に書き込める主体、すなわち同じ uid か root に限られ、それらは窓がなくても同じファイルを直接操作できるため、新たな権限昇格の経路にはならない。

## デコード時の検証順序と検出する破壊

`FrameHeader::from_bytes` は次の順序で検証する（設計レビュー・2026-09-28 オーナー決定・P1-2: 先に検証したフィールドが壊れていれば後続フィールドの値を一切信用しない）。

1. `header_crc`（オフセット `6..10`）が `[version, kind, payload_len]`（オフセット `0..6`）の再計算値と一致するか。不一致なら `IoErrorCode::DataLoss`（化けたヘッダの偶発的破損の検出。改ざん耐性ではない）
2. `version` が `PROTOCOL_VERSION` と一致するか。不一致なら `IoErrorCode::Unimplemented`（message に受信 `version` と対応 `PROTOCOL_VERSION` の両方を含める）
3. 種別が既知の値か。不一致なら `IoErrorCode::InvalidArgument`
4. `payload_len` が `MAX_PAYLOAD_LEN` 以下か。超過なら `IoErrorCode::InvalidArgument`

続けて `Frame::decode` / `Frame::decode_body` は次の順序で検証し、上限検証前にアロケーションしない（DoS 対策。security.md）。

5. （`Frame::decode` のみ）先頭 `FRAME_HEADER_LEN`（10 バイト）を `FrameHeader::from_bytes` で検証（上記 1〜4）
6. `header.body_len()`（検証済みの `payload_len + CHECKSUM_LEN`。失敗しない）を期待される本体長とし、実際の本体長と比較。不一致なら `IoErrorCode::InvalidArgument`（チェックサム不一致とは別コード）
7. `prefix_bytes()`（ヘッダの意味あるフィールド。6 バイト。`header_crc` を含まない）＋ペイロードから再計算した CRC-32C とトレーラの値を比較。不一致なら `IoErrorCode::DataLoss`

申告長に比例するペイロード用バッファの確保（`copy_validated_payload`。非公開関数）は上記 1〜7 をすべて通過した後の 1 か所だけで行い（所有権を受け取る変種 `Frame::decode_body_owned` は呼び出し元が確保済みの本体を再利用し、新たに確保しない）、これをユニットテスト（`repair2_decode_rejects_over_max_len_before_allocation` 等。TASK-83.2・#117）で確かめる。「アロケーション」はここでは申告長に比例するペイロード用バッファの確保を指し、`IoError` の message（`String`）の確保はサイズが一定の上限に収まるため対象外とする。

### ストリーム読みの手順（TASK-12・TASK-13 が実装する想定。REPAIR-5・REPAIR-6）

1. 先頭 `FRAME_HEADER_LEN`（10 バイト）を読む
2. `FrameHeader::from_bytes` で検証する（上記 1〜4）。ここで拒否されれば、化けた `payload_len` を信用した巨大確保は一切発生しない
3. `ReceiveLimits::admit`（TASK-13.4・#796）で設定上限（`MAX_PAYLOAD_LEN` 以下へ個別設定できる）・現在の滞留件数を照合する。ここで拒否されれば、設定上限を下回るがプロトコル上限以下の申告長でも、まだ本体バッファは確保されない
4. 検証が通ってから `FrameHeader::body_len()`（`≤ MAX_PAYLOAD_LEN + CHECKSUM_LEN`。失敗しない）ぶんの本体を読む。一括で確保できる場合は `AdmittedHeader::allocate_body` で確保して読み、相手が遅い場合の DoS 耐性を優先する UDS 受信ループ（`crates/io/src/server.rs` の `read_body_until`）は `AdmittedHeader::body_len` を上限に少しずつ確保しながら読む（B1・#820 レビュー指摘。どちらの経路も確保量の上限は `AdmittedHeader` からしか得ない）
5. `AdmittedHeader::decode_body`（`Frame::decode_body` への薄い委譲）へ渡す。UDS 受信ループは所有権を受け取る crate 内部の変種 `AdmittedHeader::decode_body_owned`（`Frame::decode_body_owned`。検証は同じ `Frame::verify_body`）へ渡し、読み込んだ本体の領域をペイロードとして再利用する（複製しない。#820）

これにより「申告長に比例するアロケーションは検証後だけ」という DoS 対策が、一括 `Frame::decode` だけでなくストリーム読み経路でも成り立つ（`header_crc` がなければ、ストリーム読みは手順 2 の検証をヘッダ単体では完結できず、`payload_len` を信用してから手順 3 の確保をした後で初めて手順 7 のトレーラ検証に到達することになり、化けた `payload_len` による巨大確保・待ち続けを防げなかった。これが `header_crc` を追加した動機。P1-2）。

PoC-8（`03-poc/ai-self-repair`）の BREAK-2 は、送信側がペイロード長を実際より 1 バイト少なく申告する破壊が `cargo build` を素通りし、整合性テストでしか検出できなかった事例である。本チェックサムは、正しくエンコードされたフレームに対して転送中の偶発的破損（ビット反転・末尾切り詰め等）でヘッダの `payload_len` が書き換わった場合に、元のペイロード＋トレイラの残りバイトを申告長どおりに読み直した結果としてチェックサム不一致を検出し、上記手順 7 で `IoErrorCode::DataLoss` として拒否する（`crates/io/src/protocol.rs` の `repair2_decode_detects_break2_short_declared_len` テストで確認）。ただし、これは CRC-32C が偶発的破損を検出する性質によるものであり、送信側が短く申告した `payload_len` とそれに整合するペイロード・`header_crc`・トレーラ `checksum` をすべて再計算して送出した場合（意図的な長さの偽装）は、ヘッダ・ペイロード・チェックサムが自己整合しているため検出できない（前述「範囲外（真正性は保証しない）」節のとおり CRC-32C は改ざん耐性を持たない）。意図的な偽装への耐性が必要な経路では、別レイヤーでの真正性検証（信頼境界の検証）が必要になる。

BREAK-2 検出経路の整理:

- 送信側の申告誤り（`Frame::new` を経由する限りの誤り）: 型として表現不能（`payload_len` は `payload.len()` から導出される）
- 転送中に長さフィールドが偶発的に破損した場合（`header_crc` を再計算せずに `payload_len` だけが書き換わる。実際の伝送路でのビット化けを想定）: `header_crc` が検証順序の手順 1 で不一致となり、種別・長さの検証にすら到達せず `DataLoss`（`tests/frame_integrity.rs` の `repair2_break2_declared_len_over_max_rejected_by_decode` はこの経路を模している）
- `header_crc` を新しい `payload_len` に対して正しく再計算した（＝ヘッダ単体は自己整合的な）状態で、一括 `decode`（全長が既知）に渡した場合: `body.len()` と `payload_len + CHECKSUM_LEN` が食い違うため必ず `InvalidArgument`（`DataLoss` には至らない）
- 同じ自己整合的なヘッダを、ストリーム読み（申告された `payload_len` ぶんだけ読んでから `decode_body` へ渡す想定。TASK-12・TASK-13）に渡した場合: 長さ検証は申告どおりの本体長と一致するため通過し、トレーラのペイロード＋チェックサムの再計算で不一致となり `DataLoss`（`repair2_decode_detects_break2_short_declared_len` はこの経路を模している。`tests/frame_integrity.rs` の `stream_read_frame` ヘルパーは同じ経路を公開 API のみで再現し、`tamper_declared_len` で `header_crc` を新しい `payload_len` に対して正しく再計算した自己整合的なヘッダへ入れ替えた上で、申告長を短く／長く偽った両方向で確認する。TASK-83.1・#116）
- 意図的な自己整合偽装（`header_crc`・申告長・ペイロード・トレーラ `checksum` をすべて揃えて送出）: 本チェックサムの範囲外（真正性は別レイヤーの責務。上記「範囲外」節のとおり）

## エラー後の接続再利用禁止（P1-3・設計レビュー・2026-09-28 オーナー決定・REPAIR-5・REPAIR-6）

`FrameHeader` には同期マーカー（フレーム境界を再同期するための番兵バイト列）がないため、`FrameSender::send_frame` / `FrameReceiver::recv_frame` の送受信途中でエラーが起きると、以後のバイト列がフレーム境界からずれて解釈される可能性がある。両トレイトの契約として、`Timeout`・`DataLoss`・`InvalidArgument`・`Unimplemented` 等いずれのエラーを返した後も、その接続は以後使用不可（fail-closed）とする。実装はエラーを返した後の呼び出しに対して実際の読み書きを一切行わず `IoErrorCode::Unavailable` を返さなければならず、呼び出し元は同じ接続を再利用せず再接続しなければならない。`crates/io/src/transport.rs` の `MockTransport`（テスト専用）がこの契約を実装し、`p1_3_connection_becomes_unavailable_after_error` で確認する。TASK-13.2.1（#820）で追加した `crates/io/src/server.rs` の `UdsConnection`（UDS サーバー側。Linux / macOS）もこの契約を実装し、`crates/io/tests/server.rs` の `p1_3_uds_connection_unavailable_after_error`・`io1_uds_recv_rejects_corrupted_header` で確認する。TASK-13.2.2（#822）が実装するクライアント側の UDS 接続・vsock・named pipe 等の残りの具象トランスポートもこの契約に従う義務を負う。

## 送信キュー（TASK-12.1・IO-1・#73）

`crates/io/src/client.rs` の `SendQueue`・`PipelineClient` は、パイプライン送信（IO-1: ACK を待たずに連続送信する）で未 ACK 件数が際限なく増えないよう、上限件数付きで送信済みリクエストを追跡する。

- 未 ACK 件数の上限は `InFlightLimit`（検証済み newtype）で表現し、既定値は `DEFAULT_IN_FLIGHT_LIMIT = 64`。根拠は PoC-2（`03-poc/io-layer-redesign`）のクライアントが使っていた in-flight window の既定値（サーバー側バッチサイズに揃えた値）
- 上限の最大値は `MAX_IN_FLIGHT_LIMIT = 4096`（暫定値。`InFlightRequest` は id・種別のみを保持しペイロードを持たないため上限まで埋まってもメモリ量は小さい。TASK-113 のベンチ・TASK-85 の結合試験で見直してよい）
- 上限に達した状態で `PipelineClient::send` を呼ぶと、**トランスポートへ書き込む前に** `IoErrorCode::ResourceExhausted` を返す（ブロックしない）
- request id（`RequestId`）はクライアントがローカルに振る単調増加の連番であり、ワイヤー上のレイアウトは下記「ペイロード形式と ACK 対応付け」節（TASK-12.2・#74）が定める
- ACK フレームの受信・デコード・id との対応付け・タイムアウト付き ACK 待ちは `PipelineClient::recv_ack`（TASK-12.2・#74）が提供する

`IoErrorCode::ResourceExhausted` は `DataLoss` と同じく ERR-1/3/5 の既定表にない拡張コード（gRPC 正準コードの `RESOURCE_EXHAUSTED` を借用）。spec `error-format.md` への反映要否は spec 側への報告事項（spec-reference）。

## ペイロード形式と ACK 対応付け（TASK-12.2・IO-1・IO-2・#74）

`crates/io/src/payload.rs` が `crates/io/src/protocol.rs` の `Frame` ペイロードの内部レイアウト（request id・ACK の対応付け）を定める。`FrameHeader` は `[version][kind][payload_len][header_crc]` の固定 10 バイトで確定済み（2026-09-28 オーナー決定・#67・#115・#1108）であり、ヘッダに request id フィールドを追加するのはワイヤー互換を壊す変更（`PROTOCOL_VERSION` の繰り上げが必要）かつ I/O 契約（IO-1）の設計変更にあたるため、TASK-12 系の受入基準が言う「フレームヘッダの ID フィールド」は、本書では代わりに「ペイロード先頭 8 バイトの固定オフセットに置く request id」として実装する（このずれは実装計画・PR で明記し、spec 側の記述と合わせるかはユーザー判断事項として報告する。out-of-scope-tracking）。

### ペイロードレイアウト

| 種別 | ペイロード | 制約 |
| ---- | ---------- | ---- |
| `FrameKind::Write` | `[request_id: u64 LE][body...]` | `body.len() ≤ MAX_WRITE_BODY_LEN`（`= MAX_PAYLOAD_LEN - 8`） |
| `FrameKind::Flush` | `[request_id: u64 LE]` | ちょうど 8 バイト（body は空） |
| `FrameKind::Ack` / `FrameKind::FlushAck` | `[request_id: u64 LE]` | ちょうど 8 バイト（短くても長くても拒否） |

- `WireRequestId`（非公開フィールド。`RequestId` からのみ構築できる）がワイヤー表現を担う。`RequestId` が内部に持つ発行元キュー識別子（`QueueId`）はメモリ内の区別にのみ使い、ワイヤー上には一切現れない（TASK-12.1 の契約を維持する）
- `encode_request` / `decode_request`（`Write`・`Flush` 用）、`encode_ack` / `decode_ack`（`Ack`・`FlushAck` 用）が公開 API。種別違反・長さ違反は構築前に検証し、`Frame::decode` 系のアロケーション前検証（TASK-83.2）を壊さない
- ACK に status バイト（成功/失敗）は持たせない。サーバー側の失敗は接続再利用禁止契約（P1-3。上記「エラー後の接続再利用禁止」節）により接続断で伝わるため、ACK 自体に真偽値を足す必要がない。あとから追加する場合はワイヤー形式の変更（`PROTOCOL_VERSION` の繰り上げ）が要る（PoC-2 の `status(0=OK)` をあえて再現しない理由）
- `PROTOCOL_VERSION` は `1` のまま据え置く。ペイロードはこれまで意味づけされていない不透明なバイト列だったため、本節が初めてその形式を定めるのであり、ヘッダ・フレーム全体のバイトレイアウトは変わっていない

### 送信（`PipelineClient::send`）

`send(kind, body, timeout)` は `SendQueue::peek_next_id` で次の id を覗き見てから `encode_request` でフレームを組み立て、`SendQueue::register` で確定した id と一致することを確認してから送信する（id が一致しない場合は内部不整合として `IoErrorCode::Internal` を返す。単一スレッド前提のこの型では構造上起こらないはずの分岐）。ペイロード形式の検証に失敗した場合は `SendOutcome::RejectedInvalidPayload` として送信前に拒否する（`SendOutcome::RejectedInvalidFrameKind` とは別の分類。REPAIR-4）。

### 受信・対応付け（`PipelineClient::recv_ack`）

`recv_ack(timeout)` は引数で任意の受信側を取らず、`PipelineClient::new` へ渡した送信用トランスポート（`self.sender`）自身から `FrameReceiver::recv_frame` で ACK を受信する（このため `recv_ack` を呼ぶには `S: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>` が必要）。以前の実装は `recv_ack(receiver: &mut R, timeout)` として送信側とは無関係な任意のトランスポートを引数に取っていたが、ワイヤー上の request id は各クライアントで `0` から独立に採番されるため、呼び出し元が誤って別接続（別 `PipelineClient`）の受信側を渡すと、id と種別だけの照合を通過して未 ACK 枠を誤って解放できてしまっていた（`FlushAck` の場合は実際には永続化されていない書き込みを完了扱いにしてしまい IO-2 に反する。TASK-12.2・#74 codex 再指摘対応。P0）。送受信を同じ接続オブジェクトへ束ねることで、この誤対応付けを型レベルで起こせなくした。

次の順で検証し、いずれかに失敗すると `PipelineClient` を失効させる（`is_poisoned() == true`。以後の `send`・`recv_ack` はすべて `IoErrorCode::Unavailable`）:

1. 失効済みなら `self.sender.recv_frame` を呼ばずに `Unavailable`
2. 未 ACK が 0 件なら `self.sender.recv_frame` を呼ばずに `InvalidArgument`（待つ対象がない呼び出しの誤りであり、プロトコル違反ではないため失効させない）
3. `self.sender.recv_frame(timeout)` が `Err` を返したら、そのエラー（`Timeout` を含む）をそのまま返して失効させる。`FrameReceiver::recv_frame` の P1-3 契約（エラー後は接続を再利用しない）により、同じ接続でポーリングする使い方は想定しない
4. `decode_ack` の検証に失敗したら `InvalidArgument`
5. **送信順の照合**: 受信した request id が `SendQueue::oldest()` の id と一致しなければ `InvalidArgument`。キュー内に存在するが最古でない場合は "out-of-order ack"、キューのどこにも存在しない場合は "unknown ack id" とメッセージを区別する。`SendQueue` は FIFO であり、サーバー側は送信順に ACK を返す設計（TASK-13.2）を前提とする。順序が入れ替わる必要が生じた場合は TASK-13 側で本方針を見直す
6. 種別対応の確認: `Ack` は元が `Write` に、`FlushAck` は元が `Flush` に対応しなければならない。ずれていれば `InvalidArgument`
7. `crates/io/src/barrier.rs` の `AckReceipt::from_matched` で種別ごとの `AckReceipt`（`AckReceipt::Write` / `AckReceipt::Flush`）を組み立ててから `SendQueue::remove` で解放し、その `AckReceipt` を返す

`FrameKind::Ack` は対応する書き込みがバッファリングされたことのみを保証し（IO-1）、`FrameKind::FlushAck` はそのバリア以前に受理したすべての書き込みが永続化済みであることを保証する（IO-2）。送信順照合はどちらの種別でも同じ規則（キュー先頭との一致）を使い、この保証範囲の違いと矛盾しない。

### ACK 種別の型による区別（TASK-15.1・IO-2・#85）

`recv_ack` が返す `AckReceipt` は、以前は `{ request: InFlightRequest, ack_kind: FrameKind }` という単一構造体で、呼び出し元が `ack_kind()` を確認して種別を判別する形だった。これだと確認を怠った呼び出し元が、永続化を保証しない通常 ACK（IO-1）を永続化済み（IO-2）として扱えてしまう（データ損失。ERR-3 `DATA_LOSS`）。`crates/io/src/barrier.rs` はこれを型で分離する:

- `WriteAck` / `FlushAck`: それぞれ通常 ACK・FLUSH ACK の受領記録。`request()` アクセサのみ持ち、相互変換は一切実装しない
- `FlushAck::barrier() -> FlushBarrier`: 受信した FLUSH ACK が対応するバリアのハンドルを返す。`PipelineClient::flush(timeout) -> Result<FlushBarrier, IoError>`（`send(Flush)` の薄いラッパー）が送信直後に返す `FlushBarrier` と `PartialEq` で突き合わせられる
- `AckReceipt`: `#[non_exhaustive] enum { Write(WriteAck), Flush(FlushAck) }`。共通アクセサ `request()` は残すが、判別用の `ack_kind()` は公開面から削除した
- `TryFrom<AckReceipt> for FlushAck` / `for WriteAck`: 「FLUSH ACK だけを待つ」呼び出し元が型で絞り込める変換（逆種別なら `InvalidArgument`）
- 構築経路: `WriteAck`・`FlushAck`・`AckReceipt` はいずれもフィールドが非公開で、`pub(crate)` の `AckReceipt::from_matched(request, ack_kind)` だけが生成できる。crate 外のコードは `recv_ack` に実際に受信した ACK を通す以外の方法でこれらの値を得られない（`pub(crate)` のため crate 内の他コードからは `from_matched` を直接呼べるが、`client.rs`（`recv_ack`）以外の呼び出し箇所は用意しない）

本節が定めるのはクライアント側の型契約のみ。サーバー側の永続化と FLUSH ACK 送出は下記「FLUSH フレームの扱い」（TASK-15.2.2・#824）が定める。

### 範囲外（後続タスク）

- `PipelineClient` 自体の送受信分割（共有 `SendQueue` を持つ送信側・ACK 受信側）。トランスポート層の分割は `transport::SplitTransport`（#1118・IO-1・P1-3）で定義済みで、`UdsConnection`（サーバー側）が `UdsSendHalf` / `UdsRecvHalf` へ分けられる（poison を両半分で共有し、片側のエラーで `shutdown(Both)`。期限・受信上限の契約は分割前と同じ）
- ACK status バイトの導入（導入する場合は `PROTOCOL_VERSION` の繰り上げが必要）

サーバー側が本形式で ACK を返す実装と送信順を守る義務は、下記「バッチ write-back と ACK 返却」節（TASK-13.2.2・#822）で実装済み。

## バッチ write-back と ACK 返却（TASK-13.2.2・IO-1・#822）

`crates/io/src/writeback.rs` の `serve_connection` が、`crates/io/src/batch.rs` の `BatchBuffer`（TASK-13.1）が集約したバッチを実際にディスクへ書き込み、書き込み完了後に上記「ペイロード形式と ACK 対応付け」節と同じ形式で通常 ACK（`FrameKind::Ack`）を送信順に返す。トランスポートは `FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>` の generic 境界のみを要求し、`crates/io/src/server.rs`（TASK-13.2.1・#820）の `UdsConnection` に限らない。

### 書き込み先（ワイヤーにパスがない）

`Write` ペイロードは `[request_id][body]` のみでパス・オフセットを持たない。`serve_connection` はファイル命名規則を独自に作らず、書き込み先を `BatchSink` トレイトへ抽象化する。既定実装 `AppendFileSink` は、呼び出し側が開いた `File` へ各 `Write` の body を到着順に `write_all` で追記するだけで、パス解決・ファイル作成・rename・truncate は行わない。パストラバーサル・symlink 経由の書き込み経路は構造上生まれない（security.md）。`body` を不透明なバイト列として追記するのはスタブの意味論であり（REPAIR-3）、ファイル操作をペイロードで表す形式（TASK-14 が前提とする）は、今後の I/O 契約拡張として別途検討する。

### ACK を返す時点（IO-1 の「バッファリング時点」との対応）

通常 ACK（`FrameKind::Ack`）は、1 バッチ内の全 `Write` について `BatchSink::write_batch` が `Ok` を返した時点（＝ OS のページキャッシュへの `write()` 発行が完了した時点）で送る。`fsync(2)` / `syncfs(2)` は呼ばない。プロセスが正常に動いている限りこの時点のデータは他の reader から見えるが、プロセスクラッシュ・電源断では失われうる。これが IO-1 の「バッファリング時点で ACK」の本実装における対応物である。永続化完了を保証するのは IO-2 の FLUSH ACK（`FrameKind::FlushAck`）のみであり、`serve_connection` は `Flush` の永続化成功後にだけ送る（下記「FLUSH フレームの扱い」参照）。ACK の API としての利用者向け文書化は TASK-17 で行う。

### バッチが件数未達のまま残る場合の運用制約

ACK をバッチ書き込みの後に返すため、クライアントが `batch_size` 未満だけ送って ACK を待つと、サーバー側に発火のきっかけがない。使える発火条件は「設定件数到達（`BatchTrigger::SizeReached`）」「累積バイト数上限到達（`BatchTrigger::BytesLimitReached`）」「`FrameKind::Flush`」の 3 つのみで、時間ベースの追い出しは範囲外（IO-10・TASK-16）。クライアントは「in-flight 上限 ≥ `batch_size`、または件数未達分の後に `Flush` を送ること」を前提とする（既定値 64 / 64 で整合）。

### FLUSH フレームの扱い（IO-2・TASK-15.2.2・#824。FlushAck は偽装しない）

`FrameKind::Flush` を受信すると、`BatchBuffer::take_pending` で件数未達分を取り出して書き込み・通常 ACK した後、`BatchSink::persist`（`AppendFileSink` は Linux で `syncfs(2)`）で永続化し、**成功したときだけ** `FrameKind::FlushAck` を送ってループを継続する（IO-2）。

- `persist` が失敗・タイムアウト・未対応のときは FlushAck を送らず、そのエラーで終了する（fail-closed）。プロトコルにエラーフレームはなく、クライアントは EOF を `Unavailable` として観測する。既定の `BatchSink::persist` は `Unimplemented`
- `syncfs` は中断できないため、dup した fd を小さなスタックの helper スレッドで 1 回だけ実行し、`AppendFileSink::with_flush_timeout`（既定 10 秒。REPAIR-5）で待つ。この期限は下記の同時実行数の枠待ちと `syncfs` 本体を合わせたもの。タイムアウトした helper は detach され、中断できない `syncfs` が戻るまで同時実行数の枠を占有し続ける（ハングした分だけ新しい `syncfs` を起動しない。helper スレッドの数は常に同時実行数と一致し、絶対上限 64 本を超えない）
- `syncfs` を発行した後に失敗・タイムアウトした `AppendFileSink` はポイズンされ、以後の `persist` は syscall なしで `Internal` を返す（errseq は 1 回しか報告されないため、再試行が 0 を返して永続化を偽装しうる）。カーネル版数による拒否・fd 複製・枠確保・スレッド生成など発行前の失敗は errseq を消費しないためポイズンしない
- Linux 5.8 未満、またはカーネル版数を判定できない場合、`persist` は `Unimplemented` で拒否する（`syncfs` が書き戻しエラーを報告するのは 5.8 以降のため、FlushAck の偽装を避ける。IO-2）。判定は公開関数 `persist_support()`（`PersistSupport`。`crates/io/src/barrier.rs`）に集約し、利用者・結合試験も同じ関数で「FlushAck が返る環境か」を知る
- macOS / Windows は `File::sync_all`（macOS は `F_FULLFSYNC`、Windows は `FlushFileBuffers`）による代替フラッシュ（`PersistSupport::SupportedFileSync`。TASK-15.3・#88）。永続化するのは sink のファイル自体（データ＋ファイルメタデータ）のみで、新規作成ファイルの親ディレクトリエントリは保証しない（Linux の `syncfs` との差）。`F_FULLFSYNC` 非対応の FS では失敗し FlushAck を返さない。Linux・macOS・Windows 以外の OS は `Unimplemented`
- 増幅対策（#824 の A4）:
  - `AppendFileSink` は直近の成功以降に書き込みがなければ `syncfs` を再発行せず合流する（書き込みを伴わない連続 FLUSH）
  - プロセス全体で同時に実行中の `syncfs` の数を `MaxConcurrentPersist`（既定 2。`set_max_concurrent_persist` で 1〜64 に設定。0 と 64 超は `InvalidArgument`）までに抑える。上限に達している FLUSH は、その FLUSH の期限内で枠が空くのを `Condvar` で待ち（ビジーウェイトしない）、期限を過ぎたら FlushAck を返さず `Timeout` で確定する（`syncfs` 未発行のため sink はポイズンしない。接続は他の persist 失敗と同じく終了する）
  - `Timeout` を選ぶ理由: 失敗の本質は「その FLUSH の期限（REPAIR-5）が枠待ちの間に尽きた」ことで、`syncfs` が期限内に終わらない場合と利用者から見て同じ扱い（再接続して再送）になる。また `Timeout` は spec の ERR-3 対応表の `DEADLINE_EXCEEDED` に当たる定義済みのコードだが、`ResourceExhausted` は ERR-3 にまだない拡張コードである
  - 保証の範囲: 接続を増やしても `syncfs` の同時負荷は上限までに留まる。`syncfs` の回数そのものは減らない（書き戻しエラーは `struct file` ごとに報告されるため、各 sink は必ず自分の fd で発行し、他の sink の結果を流用しない）。頻度（間隔）の制限は行わない
- 保証範囲: FlushAck が保証するのは `write_batch` 経由で受理した書き込み（IO-2 の「バリア以前に受理した書き込み」）の永続化に限る。呼び出し側が保持する別の `File` ハンドル（`new` に渡す前の `try_clone()` 等）・別プロセスからの書き込みは対象外で、dirty 追跡にも反映されない。`AppendFileSink` の利用者は対象ファイルへの書き込みを sink に一本化する（単一書き込み元の前提）
- 未対応の範囲（REPAIR-3）: FLUSH の頻度（間隔）の制限、fd を開く前の書き戻しエラー、電源断耐性の検証（TASK-18）

### ACK していない保留分・sink 失敗時の扱い

受信エラー（EOF を含む）・プロトコル違反で処理を終えるとき、`BatchBuffer` に残った保留分は書き込まずに破棄する（`WritebackStats::discarded_pending_frames`）。ACK していない以上クライアントはそれらを前提にできず、書いてしまうと再送時に重複を生むため（P1-3 の fail-closed と一貫する）。`BatchSink::write_batch` が失敗した場合、そのバッチのフレームには ACK を 1 件も返さない。バッチの途中まで書き込まれた可能性がある（部分書き込み）ため、ACK 前の書き込みは「書かれたかどうか不定」という意味論になる。

### 受信上限（`pending_frames` に `0` を渡す根拠）

`serve_connection` の write-back は同期的（発火したバッチをその場で書き込み・ACK まで終えてから次のフレームを受信する）であり、受信時点で「排出済みだが未書き込み」のキューは常に空になる。したがって `crates/io/src/server.rs` が `ReceiveLimits::admit` へ渡す `pending_frames = 0` は、現行の呼び出し方の下で構造上正確（`crates/io/src/recv_limits.rs`・`crates/io/src/writeback.rs` の各モジュール doc 参照）。write-back を非同期化する場合はこの前提を見直す必要がある。

## バッチサイズ設定 API（TASK-13.3・IO-1・#78）

`crates/io/src/settings.rs` の `parse_batch_size` が、CLI / 設定の文字列値から検証済み `BatchConfig` を作る入口。`WritebackSettings` はその `BatchConfig` と、`UdsServer::bind` が使う `ReceiveLimits` を同じ内部値から導く単一の入口（`WritebackSettings::receive_limits()` は常に `WritebackSettings::batch_config()` と整合する。REPAIR-2: `bind` と `serve_connection` に別々の設定を渡してしまう経路を型で塞ぐ）。

パース規則（fail-closed の順で検査する）:

1. 空文字列 → `INVALID_ARGUMENT`
2. `MAX_BATCH_SIZE_ARG_LEN`（20 バイト。`u64::MAX` の桁数）を超える長さ → パースを試みる前に `INVALID_ARGUMENT`（P0: 無制限確保による DoS の防止）
3. ASCII 数字（`0`-`9`）以外を 1 文字でも含む（符号・空白・桁区切り `_`・全角数字・`0x` 表記を含む） → `INVALID_ARGUMENT`
4. `usize::from_str` が桁あふれで失敗 → `INVALID_ARGUMENT`
5. 範囲（`1..=MAX_BATCH_SIZE`）の検証は二重に持たず `BatchConfig::new` へ委譲する（`0` または `MAX_BATCH_SIZE` 超は `INVALID_ARGUMENT`）

先頭ゼロ（`"064"`）は `usize::from_str` と同じく 64 として受理する。エラーメッセージには入力値そのものを含めない（security.md「情報漏えい」観点。任意長・制御文字を含みうる外部入力をログ・構造化エラーへそのまま流し込まないため）。

CLI オプション名（`BATCH_SIZE_OPTION = "--batch-size"`）・宣言的設定のキー名（`BATCH_SIZE_SETTING_KEY = "batch_size"`）は定数として予約するのみで、実際の CLI バイナリ（`fandhe-container`）からの配線は TASK-79（`crates/cli`）、TOML 等の宣言的設定ファイルからの読み込みは CLI-4（TASK-82）の範囲。`max_bytes`（累積バイト数上限）用の CLI / 設定値（`--batch-bytes` 相当）は本タスクの対象外（IO-10・TASK-16）であり、`WritebackSettings` を `#[non_exhaustive]` にすることで後から非公開フィールドとして追加できる形にしている。

### 範囲外（後続タスク。要起票）

- UDS 接続受付ループ（accept → `serve_connection` → 次の accept）・同時接続数の上限
- クライアント側の UDS `connect` と `PipelineClient` との本番結合
- 永続的な監査ログへの配線（`JsonLinesServerObserver` の peer credential 拒否行）
- macOS / Windows での親ディレクトリエントリの永続化・FLUSH の頻度（間隔）の制限
- 件数未達分を時間ベースで追い出す仕組み・未フラッシュ滞留量の上限（IO-10・TASK-16）
- 実際の CLI バイナリ（`fandhe-container`）での `--batch-size` 引数の解釈・`crates/cli → crates/io` の依存追加（TASK-79）
- ファイル操作を表すペイロード形式（パス・rename・truncate。TASK-14 の前提。I/O 契約の拡張にあたる）
- Windows のトランスポート（`windows-sys` の依存承認が必要）

## 見直し

- `crates/io/src/protocol.rs` のフレーム形式・定数・`FrameKind` のバリアントが変わった場合は本書を追従させる
- `crates/io/src/payload.rs` のペイロードレイアウトが変わった場合は「ペイロード形式と ACK 対応付け」節を追従させる
