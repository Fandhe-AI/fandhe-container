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

## 3. 論点 3: `lock` ごとの再検査と root の fd 起点の操作（#2638）

2 層で防ぐ。(a) 入口の検出: `lock`（`recover_pending_deletion` を含む）と create ゲート（`enter_container_create` / `quiesce_container_creates`）の取得ごとに、`@lock` / ゲートファイルの作成より前に `reverify_root` で root の dev / ino・権限・所有者と祖先を再検査し、open 後の chmod・差し替えを fail-closed（`PermissionDenied` / `Internal`）にする。(b) 区間内の閉じ込め: 検査済み root を `RootHandle`（`crates/oci/src/image_management/root_handle.rs`）が開いたまま持ち、排他区間の中の永続化操作を、その fd 起点の `openat2`（`RESOLVE_IN_ROOT | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV`・最後の要素も `O_NOFOLLOW`）と `*at` に閉じ込める。再検査の後に root が差し替えられても、書き込み・削除は検査済みの実体にだけ届き、差し替え後のディレクトリには何も書かず何も消さない。名前は定数か検証済みの hex の 1 コンポーネントに限る。

### 3-a. 棚卸し（#2638 時点）

| 区分 | 操作 | 対象 | 扱い |
| ---- | ---- | ---- | ---- |
| ロック | `store::open_named_lock_file`（`lock`・create ゲート） | `@lock`・`@create-gate` | fd 起点へ移した |
| 参照 | `container_ref_persist` の読み込み・保存・一時ファイル・rename・root の fsync | `@container-refs.json` | 移した |
| 在庫 | `inventory_persist` の読み込み・保存 | `@image-inventory.json` | 移した |
| ジャーナル | `gc_journal` の存在確認・読み・公開・削除・root の fsync | `@gc-pending.json`（墓標・一時ファイルを含む） | 移した |
| 残骸回収 | `gc_journal::reap_stale_tmp` | root 直下の `*.tmp-*` | 移した（走査は新しい open file description で行う） |
| blob の削除 | `gc_journal::remove_blob_durable`・`sweep_blobs`・`settle` の `blobs/sha256` の fsync、`remove` / `prune` の事前検査 | `blobs/sha256/<hex>` | 移した（`blobs/sha256` は root の fd から開き直す） |
| 読み取りのみ | `usage*`（`blob_size`・`scan_cache`・`expanded`・`staging`） | `blobs/`・`staging/` | 移していない（#2695） |
| pull | `pull::PullSession`・`pull_recovery` の staging の作成・`@pull.lock`・blob の検証・公開（`link` / `rename` / `unlink`）・fsync・中止・回収の削除 | `staging/<pull-id>/`・`blobs/sha256` | 移した（#2694。`root_handle/staging.rs` の `StagingDir` / `PullDir` と `BlobDir`）。fetcher の書き込み先だけ移していない |

移していない根拠:

- `usage*`: 読み取り専用で書き込みも削除もしない。差し替えの影響は表示する値の誤りにとどまり、root の外へは書き込まない。入口の再検査で差し替えは検出される。追跡は #2695
- fetcher の書き込み先（`PullSession::staged_blob_path` -> `RegistryClient::fetch_blob(dest: &Path)`）: fetch の API と cri の fetch トレイトがパスを受け取る形のため、handle 起点にするには crate をまたぐ API 変更が要り、#2694 の範囲を超える。本番の配線（cri の `image_pull` -> `PullSession`）も未実装（REPAIR-3）。残る隙間: `begin_pull` から fetch までの間に root が差し替えられると、fetcher の書き込みがおとりの `staging/<id>/` へ届きうる。公開は fail-closed のまま: `verify_staged_blob` は保持している pull ディレクトリ fd 起点で開き直すため `NotFound`（`staged blob not found`）になり、おとりへ書かれた内容は検証済みの集合に入らず `blobs/sha256` へ公開されない。隙間を狭める処置として、`staged_blob_path` はパスで辿った `<root>/staging/<id>` が保持している fd と同じ実体であることを (dev, ino) で確かめ、違えば `Internal`（`image store root changed after open`）で拒否する（確認から書き込みまでの間の差し替えは残る）。後続: fetch の API を handle 起点（fd またはディレクトリ handle を受け取る形）へ変える変更（追跡 issue は PR 本文の「対象外」に記載）
- Windows の一時名による固定（`pin_staged_blobs`）: Windows の `RootHandle` はパス起点（3-b）のため、設計は変えず `pull.rs` の `cfg(windows)` に残した。`hard_link` / `rename` / `remove_file` のうち公開側は `BlobDir` / `PullDir` のパス起点の実装を通る
- 退けた案: `staged_blob_path` が `/proc/self/fd/<fd>/<hex>` を返す案。procfs に依存し（コンテナ内・seccomp の構成で使えないことがある）、パスがプロセス内でしか有効でなく、`staging_dir()` の表示・照合の意味が崩れるため

### 3-b. `cfg` の局所化と OS ごとの扱い

`cfg` は `root_handle.rs` と `root_handle/staging.rs` の中だけに置き、永続化モジュールには `cfg(target_os)` / `cfg(target_arch)` を書かない。

- Linux の x86_64 / aarch64: fd 起点（`sys::at` の `openat2`・`renameat`・`unlinkat`・`getdents64`）。`openat2`（Linux 5.6 以降）が使えない環境（`ENOSYS`・seccomp による `EPERM`）では `ImageStore::open` が `Unimplemented` で拒否し、パス起点へは縮退しない（fail-closed）。Linux 5.6 未満ではストアを開けなくなる
- macOS: 本番経路が `ImageStore::open` に届かない（cli の `non_linux_failure`）。fd 起点の `openat` 系には macOS 用の定数・FFI・libc 照合が要り、足す根拠が無いため、パス起点＋入口の再検査の現行を保つ。再検討の契機は論点 2 と同じ
- Windows: パス起点のまま。ACL の検査は #2428 の方式判断待ち
- Linux の他アーキテクチャ: パス起点。`sys::at` の定数・番号を確かめていない

### 3-c. 残る隙間

- 読み取り専用の集計がパス起点のまま（#2695）、fetcher の書き込み先がパスのまま（3-a のとおり公開は fail-closed）
- fd を開いた後に、所有者自身が root を信頼できない場所へ移す操作は信頼境界の内側。入口の再検査で検出される
- 試験: `root_swap_tests.rs`（Linux の x86_64 / aarch64。再検査の直後・区間内で root を差し替えても、参照・在庫・ジャーナル・blob の削除・残骸の回収が検査済みの root にだけ作用し、おとりが無傷であることを具体値で照合する）。pull は `begin_pull`・`publish`・`abort`・`recover_stale_pulls` の各排他区間の直後に差し替えた場合と、fetcher がおとりへ書いた場合（公開されない）を `oci7_sec1_root_swapped_during_*`・`oci7_sec1_fetch_into_swapped_root_is_not_published` で照合する（#2694）

## 4. 論点 4: libc 照合（#2590 で導入済み）

issue #1318 の決定は当初 oci を含まなかったが、#2590 のオーナーコメント（2026-10-23）で oci の dev 依存 `libc` が承認され、`geteuid` の型と `sys/at.rs` の番号・フラグ・`OpenHow`・関数の型を `ffi-libc-check.md` の方式で照合している。#2638 で足した `renameat` の宣言も同じ PR で `sys/at.rs` の `libc_abi` に照合を足した。

## 5. 未決事項（論点 1 の決定後に変える箇所）

- `verify_root_meta` の権限の定数と所有者の判定（`store.rs`）
- `store.rs` の試験の期待値、cli の `cli1_oci7_sec1_store_root_mode_checks` と `binary_entry.rs` の 0755 受理の期待
