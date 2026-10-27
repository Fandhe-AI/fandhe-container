# FS 正規化（Unicode 正規化の別表記の衝突検出）

ゲストが作る名前のうち、NFC と NFD の別表記だけが異なるものを、名前を書き換えずに検出して拒否する方針と実装を記録する（IO-5）。

- 対象ビヘイビア: IO-5（関連: REPAIR-3・WIN-4・WIN-5・CLI-1）
- タスク: TASK-21（TASK-21.h1・TASK-21.hdep1・TASK-21.1・TASK-21.2）。前提は TASK-19（MS-1 Phase 2）。Win32 固有の名前の節は TASK-19 追補・TASK-68 追補
- 関連 issue: #103（方針）・#798・#1720（依存）・#104（親）・#105（実装）・#106（本書）・PR #1733・#2535（oci の試験の追補）・#1317（Win32 固有の名前の決定）・#1855（その追記）・#379（実機観測の記録先）
- 出典: `docs/spec/04-behavior/api-io-share.md` の `IO-5` と `05-tasks.md` の `TASK-21`（submodule リビジョン `18386e7`）

## 背景（解決する課題）

- ゲスト（ext4）は名前をバイト列で区別する
- APFS は名前を書かれたとおりに保存し、比較のときに正規化の違いを区別しない（normalization-insensitive）
- このため、ゲストが合成済みの `é`（U+00E9）と `e` + U+0301 を別ファイルとして作ると、ホストでは同じファイルになり、後から作った方が先の内容を黙って上書きする（データ損失）
- 事実の訂正: 当初の issue 記述「APFS は NFD が既定」は誤りで、保存時に NFD へ正規化するのは HFS+ である（#103 の補足コメントで判明。spec は `18386e7` で訂正済み。#104 の概要には古い表記が残っており、直すのはオーナー側）

## 方針決定の経緯（TASK-21.h1・#103。オーナー判断 2026-10-10）

採用した方針は「検出のみ」。

- 名前は正規化せず、バイト列も書き換えない
- 同じ親ディレクトリの下で、NFC / NFD にすると同じになる別表記の名前を作ろうとしたら、構造化エラー（`ALREADY_EXISTS`）で拒否する
- 見逃しより過検出を選ぶ

理由:

1. 大文字小文字の衝突（TASK-19・#98）と同じ型の問題なので、同じ考え方で扱え、大文字小文字の畳み込みと組み合わせて判定できる
2. ゲストから見える名前が変わらないので、git などバイト列の一致に頼るツールを壊さない
3. 後から統一方式へ変える余地が残る

| 案 | 採否 | 理由 |
| -- | ---- | ---- |
| 検出のみ（拒否） | 採用 | 上記 |
| 統一（例: NFC へ書き換える） | 不採用 | 名前の不一致で git などが壊れる。ext4 の意味論と食い違う。ホストに書いた名前は戻せない |
| 何もしない | 不採用 | 黙った上書きが残る |

IO-5 と TASK-21 の見出しは spec PR #12（`18386e7`）で改訂済み。詳細は spec を参照する。

## 正規化表の入手（TASK-21.hdep1）

- 外部 crate の `unicode-normalization` `=0.1.25`（MIT OR Apache-2.0）を使う。承認は #798（2026-09-26）で、#1720（2026-10-10）でその承認をそのまま使うと決まった
- 配置は `crates/io` に限り、`[workspace.dependencies]` で `default-features = false` として取り込む。Unicode のデータは自前で同梱しない
- 使うのは正準分解（`nfd()`）だけ
- 表の版は Unicode 17.0.0 で、`io5_unicode_normalization_table_version_is_pinned` で固定している。割り当て済み文字の正準分解は、Unicode の正規化の安定性方針により版が上がっても変わらない。版を上げるときは #798 の運用どおり PR で確かめる
- 完全固定（`=x.y.z`）であり、`cargo deny` の対象。許容依存リストは [from-scratch-policy.md](./from-scratch-policy.md) を参照

## 実装の詳細（TASK-21.1・PR #1733）

- 実装箇所: `crates/io/src/fs_normalize.rs`（`fold_component`・`CaseCollisionSet`）と `crates/io/src/guest_files.rs`（`GuestFileCreator::create_file`）
- 衝突キー: `fold_component` が `NFD → 大文字小文字の畳み込み（case_fold_chars。lower→upper→lower）→ NFD` の順に適用する。Unicode の canonical caseless matching と同じ形である
  - 末尾の NFD は、Unicode 17.0.0 の全スカラー値で外しても結果が変わらないことを実測で確かめている（`io5_trailing_nfd_difference_is_pinned`）。表の更新に備えた過検出側の安全策として残している
- 互換分解（NFKC / NFKD）は扱わない。`①` と `1` は衝突しない。ただし、大文字小文字の畳み込みで展開される合字（`ﬁ` → `FI`）は `fi` と衝突する
- 判定の単位: TASK-19 と同じく、パスの全祖先プレフィックスごとに判定する。キーは同じ親ノードと畳み込み後のコンポーネントの組で、別の親の下では衝突しない
- エラー: コードは `IoErrorCode::AlreadyExists`。文言は 2 種類ある
  - 大文字小文字だけで一致する組: 従来どおり `differ only by case`
  - 正規化を経て初めて一致する組: `differ only by case or Unicode normalization (NFC/NFD)`
  - パスは `quote_for_message` で衛生化（制御文字のエスケープ）と切り詰め（`MAX_COLLISION_MESSAGE_PATH_CHARS`・`MAX_COLLISION_MESSAGE_PATH_BYTES`）をしてから埋め込む。ログ注入と巨大メッセージを防ぐため
- 書き込み経路: `GuestFileCreator::create_file` は、作成のたびに祖先の実在項目を読み直し、その場限りの `CaseCollisionSet` で検査する。`fold_component` を共有するため、ここも同じ判定になる。APFS で NFD の既存名に対して NFC の名前を `O_EXCL` で作ると EEXIST になり、衝突として扱う
- 資源上限: 衝突キーの長さは入力の定数倍に収まる（NFD の展開は文字あたり有界）。索引の件数上限は `GuestFileCreator::with_max_tracked_paths` で、超えると `ResourceExhausted`
- ホスト OS ごとの有効化（#103 で #104・#105 に委ねられた点）: 実装は OS で切り替えず、3 OS で同じ検出をする。これは本リポ側の実装判断であり、オーナーの個別判断ではない。理由は、過検出の方針に沿うことと、ゲストから見える挙動を 3 OS で揃えること
- 本機能はパストラバーサル防止の本体ではない。rootfs への閉じ込めは `guest_files` の `openat` 系と `create_new` が担う

### 根拠となるテスト（REPAIR-12）

| 場所 | テスト |
| ---- | ------ |
| `crates/io/src/fs_normalize.rs` | `io5_nfc_and_nfd_spellings_collide`・`io5_distinct_names_do_not_collide_under_normalization`・`io5_case_only_collision_keeps_legacy_message`・`io5_collision_message_keeps_original_spellings`・`io5_trailing_nfd_difference_is_pinned`・`io5_unicode_normalization_table_version_is_pinned` |
| `crates/io/tests/fs_normalize.rs` | `io5_public_api_detects_nfc_nfd_collision` |
| `crates/io/tests/guest_files.rs` | `io5_nfc_then_nfd_create_is_rejected_without_creating_second_file` |

### oci のレイヤー展開での同じ方針（TASK-52 追補・TASK-53 追補・#2310・#2535）

`crates/oci` のレイヤー展開（`layer::extract`）も、別表記（大文字小文字・NFC / NFD）の衝突を検出して拒否し、名前を書き換えない（`ALREADY_EXISTS`）。実装は io の `fold_component` や正規化表を使わず、展開先 FS の `lstat` と `NameIndex`（この展開が作った実在項目の索引）で「展開先 FS が別表記を既存の実体へ解決するか」の実挙動で判定する。上位レイヤーの whiteout（`.wh.<名前>`）・不透明ディレクトリ（`.wh..wh..opq`）が対象または親を別表記で指す場合も、変更操作（削除）の前に拒否し、下位の木とルート外を変えない（OCI-2）。上の表は io の実装の根拠で、oci は独立した実装のため別表にする。

| 場所 | テスト |
| ---- | ------ |
| `crates/oci/src/layer/extract.rs`（`folding_lstat` で区別しない FS を模擬） | `oci2_whiteout_alias_spelling_is_rejected_without_removal`・`oci2_opaque_alias_parent_is_rejected_without_removal`・`io5_marker_alias_is_rejected_before_any_removal`・`io5_stack_alias_entry_replacing_lower_dir_is_rejected`・`io5_oci2_stack_alias_markers_are_rejected_without_removal`・`io5_oci2_stack_same_spelling_markers_still_apply`・`io5_case_variants_follow_destination_fs`・`io5_normalization_variants_follow_destination_fs` |
| `crates/oci/tests/layer_overlay.rs`（実 FS） | `io5_oci1_upper_alias_file_over_lower_dir_follows_destination_fs`・`io5_default_host_fs_folds_spelling_variants`（macOS / Windows のみ） |
| `crates/oci/tests/layer_whiteout.rs`（実 FS） | `io5_oci2_alias_markers_follow_destination_fs` |

## Win32 固有の名前の同一視（TASK-19 追補・#1317・#1855）

末尾の `.` / 空白の除去、8.3 短縮名、`CON` 等の予約デバイス名は、大文字小文字や NFC / NFD とは別種の、Win32 API 経由で起きる名前の同一視である。

### 決定と理由

いまは IO-5 の衝突検出の対象にしない（#1317・オーナー判断 2026-10-12）。

1. spec（IO-5・WIN-4）が求めていない
2. WSL2 の共有（virtiofs / 9P）でこの同一視が起きるかを、実機で確かめていない
3. 名前だけで 3 OS 一律に拒否すると、Linux で普通に使う名前（`aux.c` 等）まで拒否してしまう

実装済みの挙動ではなく「検出しない」ことの記録である（REPAIR-3）。同じ実体になる場合は黙った上書きが起きうる。

### 実機で観測する項目

WSL2 の共有上で、ゲストから次の名前を作り、結果を「別ファイルになる」「同じ実体になる」「作成に失敗する」のどれかで記録する。記録先は #379（TASK-68.h1。人間担当・Windows 実機の調達待ち）。観測項目を #379 に追記するのはオーナーである。

| 組 | 観測すること |
| -- | ------------ |
| `a.` と `a` | 末尾の `.` が除去されて同じ実体になるか |
| 末尾に空白を付けた `a` と `a` | 末尾の空白が除去されて同じ実体になるか |
| `con.txt` | 予約デバイス名として作成・参照に失敗するか |
| 既存の長い名前の短縮名と同じ名前（例: `longfilename.txt` があるときの `LONGFI~1.TXT`） | 短縮名が同じ実体を指すか |

### 再検討の条件

- 「同じ実体になる」と確かめられた種類だけを、Windows ホストの経路に限り、IO-5 の衝突と同じ構造化エラー（`ALREADY_EXISTS`）で検出する。その時点で、WIN-4 への追記を spec リポ側の課題として起こす
- 作成・参照に失敗するだけの種類は検出せず、`docs/setup/windows.md` に書く

### 8.3 短縮名を検出しない理由

短縮名が作られるかはボリュームの設定と既存ファイルで決まり、ゲストが作る名前だけからは判定できない。共有するボリュームで生成を無効にする手順は [windows.md](../setup/windows.md) の「8.3 短縮名（8dot3）」節を参照する（実機では未確認）。

## 既知の限界・未実装（REPAIR-3）

- ワイヤー上の作成要求からの呼び出しは未実装（`RequestEnvelope` にパスが無い。IO-1・TASK-14 の拡張が後続）
- 260 文字検証（TASK-20.1）の書き込み経路への組み込みは未実装
- 非 UTF-8 のファイル名は取り込めない
- APFS / NTFS の実際の case folding 表とは厳密に一致しない
- Win32 固有の名前の同一視（末尾の `.`・8.3 短縮名・予約デバイス名）は検出しない（#1317）。理由と再検討の条件は上の「Win32 固有の名前の同一視」節
- `CaseCollisionSet` 単体は削除と改名を追跡しない（過検出側）
- HFS+ のホストは本方針の前提外。保存時に NFD へ書き換えるため「名前を書き換えない」は保証できず、検証済みの挙動としては扱わない

## 未計測・後続

- `unicode-normalization` を加えたことによる release ビルドのサイズの増分は、#1720 で「#105 の PR で測って記録する」と決まったが、PR #1733 に記録が無い。本書時点では未計測で、後続の課題とする
- `crates/io/tests/acceptance_spec.rs` の選定表に TASK-21 の行を足すかは、#1733 で別判断とされている

## 見直し条件

次のいずれかがあれば本書を更新する。

- IO-5 または TASK-21 の改訂
- `unicode-normalization` の版の更新
- `fold_component` の方式の変更
- #379 で Win32 固有の名前の同一視の観測結果が出たとき
