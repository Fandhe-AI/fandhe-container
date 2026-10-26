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
| 読み取りのみ | `usage*`（`blob_size`・`scan_cache`・`expanded`・`staging`） | `blobs/`・`staging/` | 移した（#2695。`blobs/sha256` と `staging/<pull-id>` は root の fd から開いたディレクトリの fd 起点で stat・列挙し、`disk_usage` は開いた `blobs/sha256` を images 側と cache 側で共有する。排他区間の中で区間の root と別のパスは `InvalidArgument`。`ExpandedSizePlan` は区間のハンドルを持ち、ガードの外の `measure` も同じ照合を通す） |
| pull | `pull::PullSession`・`pull_recovery` の staging の作成・`@pull.lock`・blob の検証・公開（`link` / `rename` / `unlink`）・fsync・中止・回収の削除 | `staging/<pull-id>/`・`blobs/sha256` | 移した（#2694。`root_handle/staging.rs` の `StagingDir` / `PullDir` と `BlobDir`）。fetcher の書き込み先だけ移していない |

移していない根拠（`usage*` は #2695 で移したため残るのは pull だけ）:

- fetcher の書き込み先（`PullSession::staged_blob_path` -> `RegistryClient::fetch_blob(dest: &Path)`）: fetch の API と cri の fetch トレイトがパスを受け取る形のため、handle 起点にするには crate をまたぐ API 変更が要り、#2694 の範囲を超える。本番の配線（cri の `image_pull` -> `PullSession`）も未実装（REPAIR-3）。残る隙間: `begin_pull` から fetch までの間に root が差し替えられると、fetcher の書き込みがおとりの `staging/<id>/` へ届きうる。公開は fail-closed のまま: `verify_staged_blob` は保持している pull ディレクトリ fd 起点で開き直すため `NotFound`（`staged blob not found`）になり、おとりへ書かれた内容は検証済みの集合に入らず `blobs/sha256` へ公開されない。隙間を狭める処置として、`staged_blob_path` はパスで辿った `<root>/staging/<id>` が保持している fd と同じ実体であることを (dev, ino) で確かめ、違えば `Internal`（`image store root changed after open`）で拒否する（確認から書き込みまでの間の差し替えは残る）。後続: fetch の API を handle 起点（fd またはディレクトリ handle を受け取る形）へ変える変更（追跡 issue は PR 本文の「対象外」に記載）
- Windows の一時名による固定（`pin_staged_blobs`）: Windows の `RootHandle` はパス起点（3-b）のため、設計は変えず `pull.rs` の `cfg(windows)` に残した。`hard_link` / `rename` / `remove_file` のうち公開側は `BlobDir` / `PullDir` のパス起点の実装を通る
- 退けた案: `staged_blob_path` が `/proc/self/fd/<fd>/<hex>` を返す案。procfs に依存し（コンテナ内・seccomp の構成で使えないことがある）、パスがプロセス内でしか有効でなく、`staging_dir()` の表示・照合の意味が崩れるため

### 3-b. `cfg` の局所化と OS ごとの扱い

`cfg` は `root_handle.rs` と `root_handle/staging.rs` の中だけに置き、永続化モジュールには `cfg(target_os)` / `cfg(target_arch)` を書かない。

- Linux の x86_64 / aarch64: fd 起点（`sys::at` の `openat2`・`renameat`・`unlinkat`・`getdents64`）。`openat2`（Linux 5.6 以降）が使えない環境（`ENOSYS`・seccomp による `EPERM`）では `ImageStore::open` が `Unimplemented` で拒否し、パス起点へは縮退しない（fail-closed）。Linux 5.6 未満ではストアを開けなくなる
- macOS: 本番経路が `ImageStore::open` に届かない（cli の `non_linux_failure`）。fd 起点の `openat` 系には macOS 用の定数・FFI・libc 照合が要り、足す根拠が無いため、パス起点＋入口の再検査の現行を保つ。再検討の契機は論点 2 と同じ
- Windows: パス起点のまま。ACL の検査は #2428 の方式判断待ち
- Linux の他アーキテクチャ: `sys::at` の定数・番号を確かめていないため、パス起点へ縮退せず `ImageStore::open` が `Unimplemented` で拒否する（`layer::anchored` と同じ fail-closed。同じアーキテクチャではレイヤー展開も既に `Unimplemented` でイメージを使えない。#2701）

### 3-c. 残る隙間

- fetcher の書き込み先がパスのまま（3-a のとおり公開は fail-closed）
- fd を開いた後に、所有者自身が root を信頼できない場所へ移す操作は信頼境界の内側。入口の再検査で検出される
- 試験: `xdev_tests.rs`（3-d の拒否を `EXDEV` の注入で決定的に再現。既定のテスト集合）・`tests/image_store_xdev.rs`（実マウントでの確認。実機前提・`--ignored`）
- 試験: `root_swap_tests.rs`（Linux の x86_64 / aarch64。再検査の直後・区間内で root を差し替えても、参照・在庫・ジャーナル・blob の削除・残骸の回収が検査済みの root にだけ作用し、おとりが無傷であることを具体値で照合する。#2695 で `disk_usage` / `list_images` / `ExpandedSizePlan::measure` の読み取りが検査済みの実体の値だけを返すことも加えた）。pull は `begin_pull`・`publish`・`abort`・`recover_stale_pulls` の各排他区間の直後に差し替えた場合と、fetcher がおとりへ書いた場合（公開されない）を `oci7_sec1_root_swapped_during_*`・`oci7_sec1_fetch_into_swapped_root_is_not_published` で照合する（#2694）

### 3-d. マウント越え（EXDEV）と openat2 の拒否（#2701・OCI-7・SEC-1・ERR-1）

fd 起点の名前解決は `RESOLVE_NO_XDEV` を常に付けるため、root 配下に別マウント（`blobs`・`blobs/sha256` を別ボリュームにしたもの、`@lock` などの固定名ファイルの bind mount）があると `EXDEV` で失敗する。この構成は**対応外**で、受け入れる方向には変えない（fail-closed）。変えたのは分類と文言だけである。

- **写像**: `EXDEV` は `FailedPrecondition` とメッセージ `image store path crosses a mount point; unsupported (RESOLVE_NO_XDEV)` に写す（`root_handle::map_root_io`・`mount_crossing`）。永続化モジュールは errno を書かず、この写像を通す。
- **対象**: `@lock`・create ゲート・`@gc-pending.json`・`@container-refs.json`・`@image-inventory.json`（とその一時ファイル）の stat・open・作成・rename と、blob 置き場の検査（`blobs/sha256`）。rm・prune はテーブルもディスクも変える前の `check_blob_dirs` で止まり、何も変えない。
- **個々の blob ファイルが bind mount の場合**: 検査は通り、削除だけが失敗するため、従来どおり「消せずに残す」（`undeleted`）扱いのまま変えない。
- **復旧**: ジャーナルがあり `blobs/sha256` が別マウントのとき、`lock` と `recover_pending_deletion` はジャーナルに触れず（`attempts` も増やさず）に同じエラーで止まる。構成の誤りは一時的な障害ではなく、再試行回数を消費すると `MAX_GC_RETRY_ATTEMPTS` でジャーナルが断念され blob が黙って孤児になるため。墓標も同じ（root の fsync に blob 置き場が絡む）。構成を直せば次の `lock` が復旧する。
- **`@gc-pending.json` が別マウント**: stat の失敗は従来どおり存在とみなす（fail-closed）が、`EXDEV` だけは "pending deletion" という誤った原因ではなくマウント越えとして返す。
- **採らなかった案**: `lock` のたびに blob 置き場を検査して一律に拒否する案。既存構成の pull・ls・run まで止めてしまい本 issue の範囲を超えるため、ジャーナルがあるときの復旧だけで検査する。`blobs` だけが別マウントでジャーナルが無ければ `lock` は成功し、rm・prune だけが恒久的に失敗する非対称が残る（原因は上のエラーで分かる）。pull は現状パス起点のため成功する（#2694 で fd 起点にする際は同じ写像を通すこと）。usage 系（`disk_usage`・`list_images`・`ExpandedSizePlan::measure`）は #2695 で fd 起点になっており、`RootHandle::open_blob_dir` が `EXDEV` を `FailedPrecondition` に写すため、`blobs/sha256` が別マウントなら集計も同じエラーで拒否される。
- **`openat2` の拒否の区別**: root を開けないとき、`ENOSYS`（Linux 5.6 未満、または seccomp が `ENOSYS` を返す）と `EPERM`（古い Docker の既定 seccomp プロファイルなど、外側のコンテナランタイムによる拒否）はどちらも `Unimplemented` のまま、メッセージで見分ける（`openat2 is not available (ENOSYS): …` / `openat2 was denied (EPERM), likely by a seccomp profile …`）。`PermissionDenied` は root の権限・所有者の信頼検査の違反に使っており、`FailedPrecondition` は cli の `failure_message` が別の文言に写すため、どちらも使わない。cli は oci のメッセージを出さない（`(Stage, code)` から固定文言を引く）ので、これらの原因は CRI・構造化ログ・ライブラリの利用者に届き、CLI の出力には出ない。
- **単体テーブルの拒否（P2-2）**: `ImageStore::lock` のガードを経由しない単体の `ReferenceTable` の rm・prune・`resume_pending_deletion` は、本番ビルドでは `FailedPrecondition`（`image store operation requires the exclusive section of an opened ImageStore`）で拒否する。読み取り専用の `list_images`・`disk_usage`・`ExpandedSizePlan::measure` は対象外で、従来どおり単体テーブルでも動く（永続化を行わないため）。信頼検査なしの root とジャーナルの検査抜きで永続化操作が動く経路を公開 API から閉じるため（本番の cli は必ずガード経由）。`cfg(test)` の単体テストだけが従来の検査なしの経路（`RootHandle::open_unchecked`）を使う。

## 4. 論点 4: libc 照合（#2590 で導入済み）

issue #1318 の決定は当初 oci を含まなかったが、#2590 のオーナーコメント（2026-10-23）で oci の dev 依存 `libc` が承認され、`geteuid` の型と `sys/at.rs` の番号・フラグ・`OpenHow`・関数の型を `ffi-libc-check.md` の方式で照合している。#2638 で足した `renameat` の宣言も同じ PR で `sys/at.rs` の `libc_abi` に照合を足した。

## 5. 未決事項（論点 1 の決定後に変える箇所）

- `verify_root_meta` の権限の定数と所有者の判定（`store.rs`）
- `store.rs` の試験の期待値、cli の `cli1_oci7_sec1_store_root_mode_checks` と `binary_entry.rs` の 0755 受理の期待
