# fdinfo の `mnt_id` 解析の置き場所の判断記録

core・net・gpu の 3 crate が `/proc/<pid>/fdinfo/<fd>` の `mnt_id:` 行を同じ規則で別々に解析している。
共通化するか・置き場所をどうするかを決める（GPU-2・SEC-1・REPAIR-1・#3140。#3025・#3130 の追補）。

## 結論

- 案 C（現状維持＋共有 fixture による機械照合）を採る。新しい crate も依存辺も足さない
- 共有 fixture は `crates/core/testdata/fdinfo_mnt_id_cases.txt`。3 crate の試験が `include_str!` で読み、
  同じ入力に同じ結果を返すことを照合する（Cargo の辺ではなく試験コードだけの参照）
- 案 B（std だけの共有下位 crate の新設）は **オーナー承認待ちの将来案**。本 PR では承認を得ていない

## 3 か所の実装の比較

| 項目 | core（`oci_runtime/mountinfo_identity.rs`） | net（`netns.rs`） | gpu（`cdi_apply/hooks/run.rs`） |
| ---- | ---- | ---- | ---- |
| 解析関数の入力 | `&str` | `&[u8]` | `&str` |
| 読む procfs | `/proc/thread-self/fdinfo/N` | `/proc/self/fdinfo/N` | `/proc/thread-self/fdinfo/N` |
| 上限 | 64 KiB（上限 + 1 まで読み超過は `TooLarge`） | 同じ | 同じ |
| 行の選択 | 行頭が `mnt_id:` | 同じ | 同じ |
| 重複 | 値が同じ・壊れていても `Duplicate` | 同じ | 同じ |
| 値 | `trim()` 後に `u64`、失敗は `Invalid` | 同じ | 同じ |
| UTF-8 でない本文 | 読み取りの段で `Read` | 値は `Invalid`、他の行は無視 | core と同じ |
| エラー型 | 5 種（`Read`・`TooLarge`・`Missing`・`Duplicate`・`Invalid`）を各 crate で独立定義 | 同じ | 同じ |

## 置き場所の候補

| 案 | 依存辺・crate | 評価 |
| ---- | ---- | ---- |
| A1 core に集約 | `net → core`・`gpu → core` が新たに要る | 不可。net は依存を持たない core 側ライブラリで、将来 `core → gpu` が張られると循環する |
| A2 io に置く | `net → io`・`gpu → io` | 不可。procfs 解析は io の責務（write-back・バリア・FS 正規化）外 |
| A3 plugin に置く | 新しい辺 | 不可。責務・ライセンス（`MIT OR Apache-2.0`）が合わない |
| B 新しい下位 crate | crate 追加・3 crate からの辺 | 設計は素直だが crate 境界の変更でオーナー承認が要る。十数行の純関数に対し CI・deny・about の対象増と釣り合わない |
| C 現状維持＋照合試験 | なし | 採用。規則の直し忘れを試験で検出でき（REPAIR-1）、承認を要する変更を含まない |

`architecture.md` の一方向依存の規則 3（共有する型は下位 crate に置く）とは、Cargo の辺を作らず試験の fixture だけを
core 側に置くことで両立させる。PLUG-4（core の rlib の不変性）には影響しない（core の製品コードは不変）。

## 機械照合の仕様

- 試験: `repair1_fdinfo_mnt_id_shared_cases`（core）・`repair1_net_fdinfo_mnt_id_shared_cases`（net）・
  `repair1_gpu2_fdinfo_mnt_id_shared_cases`（gpu）
- fixture の形式は fixture 先頭のコメントを正とする。入力は 16 進、期待は `ok:<u64>`・`missing`・`duplicate`・`invalid`・`read`
- 各試験は fixture の `max_bytes` と自 crate の上限の定数の一致、上限ちょうど（通る）と上限 + 1（`too_large`）、
  5 種の分類がすべて 1 件以上あることを確かめる
- 規則を変えるときは fixture と 3 か所を同じ PR で直す

## 許容する差

UTF-8 でない本文の扱いだけ（上表）。net の試験だけが `net=` で期待を上書きでき、上書きは入力に 0x80 以上のバイトを含む事例に
限る（別の差を逃がす経路を塞ぐ）。実機の fdinfo は ASCII のみで実害は無い。差の解消は hosts_file の message が変わる挙動変更のため本件では行わない。

## 残余（本件の対象外）

- net が `/proc/self/fdinfo`、core・gpu が `/proc/thread-self/fdinfo` を読む差。`unshare(CLONE_FILES)` したスレッドから呼ばれる場合に別の fd を読みうるため、
  net の呼び出し元（cli の `doctor`・hosts_file）の点検と統一の判断が別途要る
- UTF-8 の差の解消、core・gpu で上限境界の多バイト文字が `TooLarge` でなく `Read` になる差（どちらも拒否で fail-closed）

## 案 B を見直す条件

- fdinfo の `mnt_id` の利用箇所が別 crate に増えたとき
- 規則そのもの（行の選択・重複・上限）を変えるとき
- Linux procfs の解析を共有する下位 crate が別の理由で設けられたとき
