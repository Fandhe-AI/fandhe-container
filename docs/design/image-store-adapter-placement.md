# ImageStore 系アダプタ（ContainerImageRefs ほか）の置き場所の判断材料

core が定義する `ContainerImageRefs`・`ImageRootfsUnpacker` を満たす本番アダプタを、どの crate に置くかをオーナーが決めるための判断材料を整理する。

> 位置づけ: **オーナー承認待ち（#2315 の受け入れ条件 1）**。本書は判断材料であり決定ではない。決まるまでアダプタは cli に暫定で置く。判断の記録は GitHub 上に見当たらなかったため、未取得として扱う。

- 対象ビヘイビア: OCI-7・OCI-5（関連: PLUG-1・PLUG-4・REPAIR-1・REPAIR-3・CORE-7）
- タスク: TASK-183.8 追補・TASK-29・TASK-30
- 関連 issue: #2315（本書）・#2377（本番の `ImageRootfsUnpacker`）・#2791（plugin-cri の参照の登録・解除）・#2792・#482・#1322・#2490・#2495
- 作成日: 2026-11-12

## 1. 現状

受け入れ条件のうち、世代・確定状態・永続化（#2335・#2352・#2346）、契機 A / B の回収と create ゲート（#2495）、CLI の `create --image-root --image` / `delete`（#2490・#2496・#2499・#2500）は実装済み。残るのは置き場所の判断だけである。

判断を待っている部品:

| 部品 | 場所 | 役割 |
| ---- | ---- | ---- |
| `StoreImageRefs` | `crates/cli/src/commands/image_refs.rs` | `ContainerImageRefs` の本番アダプタ（oci の `ImageStore` ↔ core のトレイト） |
| 所有者解決の変換 | `crates/cli/src/image_ownership.rs` | #2389・#2528 の変換部品 |
| probe の橋渡し | `crates/cli/src/commands/ref_reconcile.rs` | `StateStore::get` を照合の probe へ写す |

判断を待つ後続:

- #2377: 本番の `ImageRootfsUnpacker`。依存欄に #2315 がある
- #2791: plugin-cri の create / delete での参照の登録・解除。依存欄に #2315 がある

問題は、plugin-cri が cli に依存しないため、cli にある `StoreImageRefs` を使えないことである。置き場所が決まらないと、CRI 側で複製するか移設するかを決められない。

CLI の経路では `with_unpacker` を付けていない（`create_start.rs` の `create_container_with_image`）。core の rootfs の作成と孤児の回収は展開器ありの経路（`oci_runtime/create.rs` の `unpack_rootfs`）の中だけなので、CLI の経路では core が所有する rootfs は作られない。

## 2. 依存辺（各 `Cargo.toml` の `[dependencies]` より）

| crate | oci | core | cri | cli | 備考 |
| ----- | --- | ---- | --- | --- | ---- |
| cli | あり | あり（default-features = false） | なし | — | supervisor・net・plugin(optional) にも依存 |
| cri | あり | あり | — | なし | tonic / prost / hyper 系を持つ |
| plugin-cri | あり | あり | あり | なし | supervisor・net・plugin(grpc) にも依存 |
| oci | — | 通常の依存なし（dev のみ） | なし | なし | `tests/container_image_refs.rs` が試験用アダプタを持つ |
| core | なし | — | なし | なし | oci への dev 依存も無い |

cli → cri の辺も plugin-cri → cli の辺も無い。core は oci に依存しない（[architecture.md](../architecture.md)）。

前例: #1322 のオーナー判断（2026-10-12）は、計装アダプタを「その操作を本番で呼び、相手の型を持っている crate」に置き、アダプタのためだけに依存辺を足さないとしている。

## 3. 論点 1: アダプタの置き場所

| 案 | 内容 | 増える辺 | 利点 | 懸念 |
| -- | ---- | -------- | ---- | ---- |
| A | 呼び出し側の crate ごとに置く（#1322 と同形）。cli は現状維持、CRI は cri か plugin-cri に別のアダプタ | なし | 辺が増えない。PLUG-4 に影響しない | 変換層が 2 か所に重複し、キー導出の食い違いが他コンテナの参照の解除につながる（#2500 と同種の危険） |
| A' | 案 A に加え、純粋な文字列関数（`ref_key`・`state_scope` のキー導出、`legacy_scope`）だけを oci の `image_management` へ寄せる。core の型は使わない | なし | キー形式（#2500 の SHA-256 化）の真実源が 1 か所 | oci の公開 API が増える。変換層自体は 2 か所のまま |
| B | oci → core を通常依存へ昇格し oci に置く | oci → core | 実装 1 か所。cli と plugin-cri の両方から使える。循環なし（core は oci に依存しない） | イメージ層が実行層に依存する向きになり、oci の依存ツリーに core が入る |
| C | oci と core に依存する上位 crate を新設 | 2 本 | cli と plugin-cri から使える | crate-naming.md の確定一覧の変更が要る。crate が増える |
| D | cri に置き cli → cri の辺を足す | cli → cri | 辺は 1 本 | cli の依存ツリーに tonic / prost / hyper 系が入り、サイズと常駐が増える（CORE-7） |

どの案でも保つ契約:

- create ゲートの共有で包む規約（#2495）
- 参照キーの SHA-256 の形式（#2500）
- イメージストア root の所有者と 0700 の検査（#2381）

## 4. 論点 2: 同じ判断に従う部品

`image_ownership.rs`、`ref_reconcile.rs` の probe の橋渡し、#2377 の本番の `ImageRootfsUnpacker` のアダプタを、論点 1 と同じ答えで決めるか、個別に決めるか。

## 5. Agent の推奨（オーナー判断ではない）

案 A' を推奨する。理由は、#1322 の前例と整合すること、新しい crate・辺が要らないこと、キー形式の真実源を 1 か所に保てること。実装を 1 本にしたい場合の代替は案 B。再評価条件は、3 つ目の呼び出し元が現れたとき、または変換層の重複が 2 か所を超えたとき。

## 6. 残りの配線の分担と、今やらない理由

| 項目 | 扱い・行き先 |
| ---- | ------------ |
| 起動時の照合から `reap_stale_unpacks` を呼ぶ配線（PR #2519） | [container-ref-reconcile.md](container-ref-reconcile.md) の決定 5 で解消済み。起動時の照合は無く、同じ bundle への次の create と、bundle を知る呼び出し元が回収する |
| CLI からの `ImageRootfsPrivilege` / `DeleteOptions` / `ReapOptions`（PR #2611） | CLI は展開器を付けず、core 所有の rootfs が生じないため今は効き目が無い。CLI の create に本番の展開器を付けるとき（#2377）に同時に配線する |
| CRI / tokio 経路の子プロセス方式、`ChownInUserNamespace`（PR #2522・#2611） | CRI が `create_with_image` を使う配線（#2791）と本番の `ExtractOptions`（#2792）の範囲 |
| `image_ownership.rs` の最終的な置き場所（PR #2528） | 論点 2 に含める |
| plugin 経由のイメージつき create / delete | #2791（create ゲートの共有で包む規約も同じ） |

## 7. 判断が出た後の作業

1. 結果を #2315 にコメントで記録してから close する
2. cli 以外に決まった場合は該当 module を移す実装 issue を起こす（外部へ公開している型は無く、そのまま移せる）
3. 本書の位置づけ欄を「決定」へ更新する
4. #2377 と #2791 の依存を解く

## 8. 不採用・保留の記録

Agent は依存辺も crate も足していない。依存の追加はユーザー承認が要る（[dependency-policy](../../.claude/rules/dependency-policy.md)）。本書の作成時点で承認は得ていない。
