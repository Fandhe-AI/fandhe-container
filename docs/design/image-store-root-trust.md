# イメージストア root の検査の基準と残りの判断記録

`ImageStore::open` / `with_table`（`crates/oci/src/image_management/store.rs`）が行う root と祖先の信頼検査について、オーナー判断が要る基準と、残りの論点の採否・根拠を整理する。

> 位置づけ: **論点 1（権限ビットと root の所有者の基準）はオーナー承認待ち（#2547）**。本書は判断材料であり決定ではない。決まるまで現行の挙動（`0o022` 拒否・root は実効 uid の所有）を保つ（REPAIR-3）。論点 2〜5 は実装者が採否を決めた記録。

- 対象ビヘイビア: OCI-7・SEC-1（関連: REPAIR-3・REPAIR-7）
- 関連 issue: #2547（本書）・#2381 / PR #2521（検査の導入）・#2428（Windows の対の判断）・#1318 / #1837（libc 照合）・#1906（macos-shared-vm.md・MAC-4）
- 作成日: 2026-10-23

## 1. 論点 1: 権限ビットと root の所有者の基準（オーナー判断待ち）

### 1-a. 権限ビット

| 案 | 内容 | 影響 |
| -- | ---- | ---- |
| A（現行） | `0o022` が立っていれば拒否（0700・0755 を受理、0770・0757・1777 を拒否） | 既定 umask 022 の 0755 の root を壊さない。他ユーザーが root 配下を列挙でき、どの digest を持つかが漏れうる（実物の mode は実装時に確認） |
| B | 厳密に `0o077` 拒否（core の `verify_root` と同じ） | 0755 の root は `PERMISSION_DENIED` になり、既存の利用者は `chmod 700` が要る。CRI 配線（未実装）が root 所有の 0755 を使うなら、作成側が 0700 で作る必要がある |

### 1-b. root の所有者

| 案 | 内容 | 影響 |
| -- | ---- | ---- |
| A'（現行） | 実効 uid のみ（core の `verify_root` と同じ） | 非 root が作ったストアは rootful の CLI で拒否される |
| B' | 実効 uid か root | 非 root の CLI が root 所有のストアを開けるが、書き込みは後段で失敗し `PERMISSION_DENIED` ではなく `INTERNAL` 等で表れる |

祖先の基準（root か実効 uid の所有）はどの案でも変えない。

Agent の推奨（決定ではない）: 案 A + 案 A'（現行維持）。既定 umask の root を壊さず、所有者の基準が core と揃っているため。

## 2. 論点 2: macOS の拡張 ACL（今は拒否しない）

- 本番経路では macOS で `ImageStore::open` に届かない（cli の `image` / `system` は `non_linux_failure`、create / delete の `--image-root` は `require_local_backend` で先に fail-closed。cri・plugin からの呼び出しは無い）
- macOS でイメージキャッシュをホストに置くか（ゲスト VM 内か）は MAC-4・#1906 で未決
- 拒否にすると oci の `sys` に新しい FFI と `unsafe` を足すことになり、core と同じくホスト配下の既定の deny ACL による制約（実機で未確認）も抱える
- 再検討の契機: macOS ホストでローカルの `ImageStore` を開く本番経路を足すとき。core の `sys/macos.rs` の `has_extended_acl` と同じ形で root と祖先に入れる

## 3. 論点 3: `lock` ごとの再検査（入れる）と `openat` 起点の検査（入れない）

- 入れた: `lock`（`recover_pending_deletion` を含む）と create ゲート（`enter_container_create` / `quiesce_container_creates`）の取得ごとに、`@lock` / ゲートファイルの作成より前に `reverify_root` で root の dev / ino・権限・所有者と祖先を再検査する。open 後の chmod・差し替えは fail-closed（`PermissionDenied` / `Internal`）。`unsafe` は増えない
- 入れない: 永続化・GC・pull の各モジュール（`container_ref_persist`・`inventory_persist`・`gc_journal`・`pull`・`pull_recovery`・`usage`）が `self.root` からパスで組み立てて操作しており、fd 起点へ移すと全体に手が入る。`sys/at.rs`（`openat2`）は Linux の x86_64 / aarch64 限定で `layer::anchored` 専用、macOS に `RESOLVE_*` 相当が無い
- 残る隙間: 再検査から使用までの差し替えは「root と祖先は所有者専用」の前提で防ぐ。所有者自身による差し替えは信頼境界の内側。fd 起点への移行は必要になったときのフォローアップ

## 4. 論点 4: libc 照合（しない）

issue #1318 の決定は対象を 9 crate と列挙し oci を含まず、#1837 の子 issue にも oci は無い。oci へ libc の dev 依存を足すには新しいユーザー承認が要る（dependency-policy）ため、承認を得るまで照合しない。理由は `crates/oci/src/sys.rs` のモジュール doc にも書いた。承認後は `ffi-libc-check.md` の方式で `geteuid` の型と `sys/at.rs` の番号・フラグ・`OpenHow` を照合する。

## 5. 未決事項（論点 1 の決定後に変える箇所）

- `verify_root_meta` の権限の定数と所有者の判定（`store.rs`）
- `store.rs` の試験の期待値、cli の `cli1_oci7_sec1_store_root_mode_checks` と `binary_entry.rs` の 0755 受理の期待
