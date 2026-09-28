# I/O 共有層のワイヤーフレーム（チェックサム）

`fandhe-container-io`（`crates/io`）が提供するフレーム全体型（[`Frame`](../../crates/io/src/protocol.rs)）のバイトレイアウト・採用したチェックサムアルゴリズムの根拠・newtype 設計方針・IO-1 / REPAIR-2 対応表を記録する。

- 対象ビヘイビア: IO-1（ホスト⇔ゲスト間のファイル共有プロトコル）・REPAIR-2（壊れた値を表現できない型）・REPAIR-5（タイムアウト保護・エラー後の接続再利用禁止）・REPAIR-6（整合性テスト）
- 関連タスク: TASK-11.1（#68）・TASK-11.2（#69。ヘッダ newtype）・TASK-11.3（#70。チェックサム付きフレーム型）・TASK-11.4（#71。本節以降）・TASK-13.1（#76。バッチ集約バッファ）・TASK-83.1（#116。BREAK-2 相当のワイヤーレベル検出テスト）・TASK-83.2（#117。デコード時の範囲外長さ検証の強化とアロケーション前拒否のテスト）。ヘッダ拡張（version・header_crc）・接続再利用契約は TASK-12・TASK-13 着手前の設計レビュー（2026-09-28 オーナー決定・#67・#115）による
- 関連ビヘイビア: IO-2（Flush / FlushAck 種別）・REPAIR-5（`IoTimeout`。無期限待ちを型で表現しない）
- 対象マイルストーン: MS-1
- ステータス: 本ドキュメントは TASK-11.1〜11.4 で確定したフレーム形式（バイトレイアウト・newtype 設計・IO-1 / REPAIR-2 対応）、TASK-13.1 で追加したバッチ集約バッファ（[`BatchBuffer`](../../crates/io/src/batch.rs)・`BatchConfig`）に加え、2026-09-28 の設計レビュー（TASK-12・TASK-13 着手前に P1 として指摘・オーナー決定で先行対応）で追加したヘッダの `version`・`header_crc` フィールドと、エラー後の接続再利用禁止契約を記録する。ペイロード内部レイアウト（request id・ACK status 等）・UDS 受信ループ・ディスク書き込み・ACK 返却は TASK-12（パイプライン送信クライアント）・TASK-13 の後続 sub-issue（TASK-13.2 系）が本書へ追記する

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

補足: TASK-13.1（#76）でバッチ集約バッファ（`BatchBuffer`）と設定 API（`BatchConfig`）を追加した。ディスク書き込み・ACK 返却・UDS 受信ループ・CLI からのバッチサイズ配線（`--batch-size` 相当）は本書時点では未実装であり、TASK-13.2 系・TASK-13.3 の範囲で扱う（REPAIR-3: 実装済みを装わない）。累積バイト数上限（`MAX_BATCH_BYTES`）は `BatchBuffer` 単体の確保量を抑える安全弁であり、受信経路自体の長さ・件数検証（TASK-13.4）・未フラッシュ滞留量上限（IO-10・TASK-16）とは別物。

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

申告長に比例するペイロード用バッファの確保（`copy_validated_payload`。非公開関数）は上記 1〜7 をすべて通過した後の 1 か所だけで行い、これをユニットテスト（`repair2_decode_rejects_over_max_len_before_allocation` 等。TASK-83.2・#117）で確かめる。「アロケーション」はここでは申告長に比例するペイロード用バッファの確保を指し、`IoError` の message（`String`）の確保はサイズが一定の上限に収まるため対象外とする。

### ストリーム読みの手順（TASK-12・TASK-13 が実装する想定。REPAIR-5・REPAIR-6）

1. 先頭 `FRAME_HEADER_LEN`（10 バイト）を読む
2. `FrameHeader::from_bytes` で検証する（上記 1〜4）。ここで拒否されれば、化けた `payload_len` を信用した巨大確保は一切発生しない
3. 検証が通ってから `FrameHeader::body_len()`（`≤ MAX_PAYLOAD_LEN + CHECKSUM_LEN`。失敗しない）ぶんのバッファを確保して読む
4. `Frame::decode_body` へ渡す

これにより「申告長に比例するアロケーションは検証後だけ」という DoS 対策が、一括 `Frame::decode` だけでなくストリーム読み経路でも成り立つ（`header_crc` がなければ、ストリーム読みは手順 2 の検証をヘッダ単体では完結できず、`payload_len` を信用してから手順 3 の確保をした後で初めて手順 7 のトレーラ検証に到達することになり、化けた `payload_len` による巨大確保・待ち続けを防げなかった。これが `header_crc` を追加した動機。P1-2）。

PoC-8（`03-poc/ai-self-repair`）の BREAK-2 は、送信側がペイロード長を実際より 1 バイト少なく申告する破壊が `cargo build` を素通りし、整合性テストでしか検出できなかった事例である。本チェックサムは、正しくエンコードされたフレームに対して転送中の偶発的破損（ビット反転・末尾切り詰め等）でヘッダの `payload_len` が書き換わった場合に、元のペイロード＋トレイラの残りバイトを申告長どおりに読み直した結果としてチェックサム不一致を検出し、上記手順 7 で `IoErrorCode::DataLoss` として拒否する（`crates/io/src/protocol.rs` の `repair2_decode_detects_break2_short_declared_len` テストで確認）。ただし、これは CRC-32C が偶発的破損を検出する性質によるものであり、送信側が短く申告した `payload_len` とそれに整合するペイロード・`header_crc`・トレーラ `checksum` をすべて再計算して送出した場合（意図的な長さの偽装）は、ヘッダ・ペイロード・チェックサムが自己整合しているため検出できない（前述「範囲外（真正性は保証しない）」節のとおり CRC-32C は改ざん耐性を持たない）。意図的な偽装への耐性が必要な経路では、別レイヤーでの真正性検証（信頼境界の検証）が必要になる。

BREAK-2 検出経路の整理:

- 送信側の申告誤り（`Frame::new` を経由する限りの誤り）: 型として表現不能（`payload_len` は `payload.len()` から導出される）
- 転送中に長さフィールドが偶発的に破損した場合（`header_crc` を再計算せずに `payload_len` だけが書き換わる。実際の伝送路でのビット化けを想定）: `header_crc` が検証順序の手順 1 で不一致となり、種別・長さの検証にすら到達せず `DataLoss`（`tests/frame_integrity.rs` の `repair2_break2_declared_len_over_max_rejected_by_decode` はこの経路を模している）
- `header_crc` を新しい `payload_len` に対して正しく再計算した（＝ヘッダ単体は自己整合的な）状態で、一括 `decode`（全長が既知）に渡した場合: `body.len()` と `payload_len + CHECKSUM_LEN` が食い違うため必ず `InvalidArgument`（`DataLoss` には至らない）
- 同じ自己整合的なヘッダを、ストリーム読み（申告された `payload_len` ぶんだけ読んでから `decode_body` へ渡す想定。TASK-12・TASK-13）に渡した場合: 長さ検証は申告どおりの本体長と一致するため通過し、トレーラのペイロード＋チェックサムの再計算で不一致となり `DataLoss`（`repair2_decode_detects_break2_short_declared_len` はこの経路を模している。`tests/frame_integrity.rs` の `stream_read_frame` ヘルパーは同じ経路を公開 API のみで再現し、`tamper_declared_len` で `header_crc` を新しい `payload_len` に対して正しく再計算した自己整合的なヘッダへ入れ替えた上で、申告長を短く／長く偽った両方向で確認する。TASK-83.1・#116）
- 意図的な自己整合偽装（`header_crc`・申告長・ペイロード・トレーラ `checksum` をすべて揃えて送出）: 本チェックサムの範囲外（真正性は別レイヤーの責務。上記「範囲外」節のとおり）

## エラー後の接続再利用禁止（P1-3・設計レビュー・2026-09-28 オーナー決定・REPAIR-5・REPAIR-6）

`FrameHeader` には同期マーカー（フレーム境界を再同期するための番兵バイト列）がないため、`FrameSender::send_frame` / `FrameReceiver::recv_frame` の送受信途中でエラーが起きると、以後のバイト列がフレーム境界からずれて解釈される可能性がある。両トレイトの契約として、`Timeout`・`DataLoss`・`InvalidArgument`・`Unimplemented` 等いずれのエラーを返した後も、その接続は以後使用不可（fail-closed）とする。実装はエラーを返した後の呼び出しに対して実際の読み書きを一切行わず `IoErrorCode::Unavailable` を返さなければならず、呼び出し元は同じ接続を再利用せず再接続しなければならない。`crates/io/src/transport.rs` の `MockTransport`（テスト専用）がこの契約を実装し、`p1_3_connection_becomes_unavailable_after_error` で確認する。TASK-12・TASK-13 が実装する具象トランスポート（UDS・vsock・named pipe 等）もこの契約に従う義務を負う。

## 送信キュー（TASK-12.1・IO-1・#73）

`crates/io/src/client.rs` の `SendQueue`・`PipelineClient` は、パイプライン送信（IO-1: ACK を待たずに連続送信する）で未 ACK 件数が際限なく増えないよう、上限件数付きで送信済みリクエストを追跡する。

- 未 ACK 件数の上限は `InFlightLimit`（検証済み newtype）で表現し、既定値は `DEFAULT_IN_FLIGHT_LIMIT = 64`。根拠は PoC-2（`03-poc/io-layer-redesign`）のクライアントが使っていた in-flight window の既定値（サーバー側バッチサイズに揃えた値）
- 上限の最大値は `MAX_IN_FLIGHT_LIMIT = 4096`（暫定値。`InFlightRequest` は id・種別のみを保持しペイロードを持たないため上限まで埋まってもメモリ量は小さい。TASK-113 のベンチ・TASK-85 の結合試験で見直してよい）
- 上限に達した状態で `PipelineClient::send` を呼ぶと、**トランスポートへ書き込む前に** `IoErrorCode::ResourceExhausted` を返す（ブロックしない。ACK 待ちによる枠の解放は TASK-12.2〔#74〕の範囲）
- request id（`RequestId`）はクライアントがローカルに振る単調増加の連番であり、ペイロードには含めない。ワイヤー上のレイアウトは TASK-12.2（#74）が定める
- ACK フレームの受信・デコード・id との対応付け・タイムアウト付き ACK 待ちは本件の範囲外で、TASK-12.2（#74）が `client` モジュールへ追加する

`IoErrorCode::ResourceExhausted` は `DataLoss` と同じく ERR-1/3/5 の既定表にない拡張コード（gRPC 正準コードの `RESOURCE_EXHAUSTED` を借用）。spec `error-format.md` への反映要否は spec 側への報告事項（spec-reference）。

## 見直し

- `crates/io/src/protocol.rs` のフレーム形式・定数・`FrameKind` のバリアントが変わった場合は本書を追従させる
- TASK-12.2（#74）・TASK-13（バッチ write-back サーバー）がペイロード内部のレイアウト（request id・ACK status 等）を確定させた際は、本書へ追記する
