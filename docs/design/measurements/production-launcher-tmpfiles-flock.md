# production_launcher の create の間欠失敗（tmpfiles の aging 走査との flock 競合）

Issue #2840。ビヘイビア: CORE-1・CORE-2・CORE-5・CORE-6・SEC-1・REPAIR-4・REPAIR-5・REPAIR-12。

## 現象

main の CI（run 40298579586・commit 3ebc80ce）の `platform-ci (ubuntu-latest)`「production_launcher の実行」で、
シナリオ F の成功行の直後、シナリオ G の 1 周目（`bind`）の `do_create` が
`FailedPrecondition`・`container start is in progress in another process` で失敗した。次の run は通っており間欠失敗である。

## 否定した仮説

- ID の重なり: エラーは状態ストアではなく bundle の flock（`BundleLock::acquire`）から出る。全シナリオの ID は重ならない
- start のロックの解放漏れ・別 start の残り: G の bundle は直前に `create_dir` で排他作成した新しい inode で、
  前のシナリオのロックは別 inode に掛かる。F の start は fork 前の検査で拒否され `lock_owner` に届かない。
  本番 launcher は `LaunchMode::SelfBounded` で、残るスレッドも無い

したがって、新しい bundle の作成から create までの間に、試験プロセス以外が flock を掛けたことになる。

## 原因（有力。runner 上の直接観測は未取得）

- Ubuntu noble の `tmpfiles.d/tmp.conf` は `D /tmp 1777 root root 30d` で /tmp は aging 対象
- systemd の `dir_cleanup` は、サブディレクトリごとに `flock(LOCK_EX|LOCK_NB)` を取ってから再帰する（age に関係なく走査中は保持）
- `systemd-tmpfiles-clean.timer` は `OnBootSec=15min`
- 失敗した run だけが、ジョブ開始から production_launcher の実行までが約 14 分 37 秒で、起動後 15 分前後の走査に重なる
  （成功した 3 run は約 16 分 04 秒〜16 分 38 秒）。直近 40 件の失敗 run で同じ文言は 1 件のみ

## 修正

`crates/core/tests/production_launcher.rs` の一時領域を、`create_dir` で排他作成し 0700 にした親ディレクトリ
（`fandhe-prodlaunch-<pid>-<nanos>`）の下へまとめ、親に共有 flock を期限つきで取って試験の終わりまで保持する。
tmpfiles は LOCK_EX を取れないディレクトリを丸ごと飛ばす（tmpfiles.d(5)）。製品のロックは子の inode で親と干渉しない。
あわせて create の失敗時に `/proc/locks` から保持者を stderr に出す診断を足した（判定は変えない。REPAIR-4）。

採らなかった案: create の再試行（本物のロック漏れを隠す）、`target/tmp` への移動（祖先の権限への影響）、
ci.yml の `TMPDIR` 指定（CI でしか効かない）。

## 繰り返し実行の結果

未実施の項目を含む。この記録の作成環境（Unshare 段が `PermissionDenied` になる AppArmor 制限下）では本番試験を最後まで
回せなかったため、修正前後の繰り返し（注入あり・なし）の件数は未取得である。PR の CI（ubuntu）での通過を確認し、
再現頻度と修正後の失敗 0 の確認は人手で追記する。なお `make repeat-test` は最終成功行が 200 文字を超え `;` を含むこと、
委譲 scope（`systemd-run --user --scope -p Delegate=yes`）と `FANDHE_CONTAINER_TEST_ID_HELPER=1` を付けないことから、
この試験にはそのまま使えない。

## 残余（製品側）

`BundleLock` は待たない設計（#1316・#1854・#2378 で確定）のため、aging 対象の場所に bundle を置く利用者でも
create・start・delete が稀に同じ文言で失敗しうる。`launch.rs` の doc に既知の制約として記した。
待たない取得を期限つきの再試行にする案・文言の改善などはオーナー判断として追跡する。

## 他の実機前提試験への展開（#2887・CORE-5・REPAIR-12）

`production_launcher` の保護（排他作成した 0700 の親ディレクトリ＋その親への共有 flock の保持）を共通補助
`crates/core/tests/support/scratch_root.rs` にまとめ、同じ競合を受ける他の `--ignored` 実機試験へ広げた。
`production_launcher` 自身の挙動（名前 `fandhe-prodlaunch-<pid>-<nanos>`・0700・期限・削除位置）は変えていない。

### 判定基準

失敗は「製品がディレクトリに待たない flock を取る経路」でだけ起きる（tmpfiles はディレクトリだけを flock する。
状態ストアの `@lock` はファイルで無関係）。該当は `oci_runtime::{create,start,delete,create_with_image}` の
`BundleLock` と image rootfs の `try_lock` で、これらを通る試験だけを対象にした。通らない試験は、作成直後の木を
aging（30d）が消さないため対象外。

### 適用した試験

| 試験 | crate | CI |
| ---- | ----- | -- |
| `production_launcher`（共通補助へ移行） | core | platform-ci |
| `rootless`・`rootless_uid_mapping`・`rootless_file_owner`・`rootless_image_rootfs_remove` | core | platform-ci |
| `exec_subordinate_e2e`・`supervisor_bin_real` | supervisor | platform-ci |
| `start_stop_delete_real` | cli | platform-ci |
| `start_scope_real`・`delete_cgroup_real`・`start_recover_real` | cli | CI 外（人手の実機） |

### 対象外

- `rootless_launch`・`seccomp`・`exec_setns_join`・`sysfs_mount`・`config_paths_implicit_dev`・`inject_files`・`tmpfs_mount`・
  `readonly_paths`・`landlock_implicit_dev`・`unshare_isolation`・`container_options_ipc`・`rootless_holder_*`:
  `ProcessLauncher::launch` 等を直接呼び、製品のディレクトリ flock を通らない
- `userns_extract`・`image_store_xdev`（oci）: image store の `@lock` はファイルで、ディレクトリ flock を通らない
- plugin-cri の `production_binary_full_lifecycle_real`・cri の `runtime_service_namespaces`: bundle を temp_dir 直下に実体で置かない

### 置き場所の決定

正本は core の試験補助（`crates/core/tests/support/scratch_root.rs`）で、supervisor・cli の試験は
`#[path = "../../core/tests/support/scratch_root.rs"]` で同じファイルを取り込む（複製しない。保護条件の修正を
1 箇所に保つため。試験専用で製品コード・rlib に影響しない）。代替は、各 crate の `tests/support/` へ複製し
正本を指すヘッダを付ける方式（`crates/supervisor/tests/support/rootfs.rs` の前例）。

### 残余

- 既定のテスト集合（`--ignored` 不要）で temp_dir 直下に bundle を作り fake launcher で create/start/delete を通す試験も
  同じ競合を受けうる（本 issue の対象外）
- `linux-env-probe.yml` への tmpfiles 設定・timer の観測ステップ（任意項目）は未実施
- CI 外の 3 件（cli）はビルドと clippy までの確認で、実機実行は人手
