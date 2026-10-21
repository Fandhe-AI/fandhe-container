# レイヤー展開の setuid / setgid / sticky の扱い

OCI-1・OCI-2・SEC-5・SEC-1・REPAIR-3・REPAIR-4（#1810・#2251。前段は TASK-52.3・#409）。実装は `crates/oci/src/layer/extract.rs`。

## 背景

レイヤー展開物は実行ユーザーの所有になる。ホスト root が、ほかのユーザーも辿れる場所へ展開すると、tar 由来の
setuid 実行ファイルが root 所有で残り、ホスト上の権限昇格に使える。そのため既定では通常ファイルの
setuid / setgid / sticky を常に落とし、件数を `ExtractedLayer::files_with_stripped_special_bits` に返す
（`SpecialBitsPolicy::Strip`）。一方、展開した rootfs ではイメージ内の setuid 実行ファイル（`su`・`mount` 等）が効かない。

## 方針

`SpecialBitsPolicy::PreserveIfOwnerMapped { uid, gid }`（opt-in）を渡した呼び出しだけが、下表の条件を満たすビットを
tar の値のまま適用する。満たさないものは落とす（fail-closed）。既存の入口は `Strip` のままで挙動を変えない。
新しい入口は `extract_layers_with_policy` / `extract_layer_blobs_with_policy`。

`uid` / `gid` は user namespace の写像（core の `IdMapping` と同じ意味の `container_id host_id count` の 1 行）を
`IdRange` で渡す。`host_id` は展開するプロセス自身の user namespace から見える ID（そのプロセスの `fstat` が返す
uid / gid）で渡す。入れ子の user namespace の中で展開するときは、初期 user namespace のホスト ID ではなく展開プロセスの
名前空間での ID を渡す（取り違えると所有者の照合が別の ID と一致したり、常に食い違ったりする。#2251 P2-4）。

## 条件

ポリシー全体（展開の開始時に 1 回評価。結果は `SpecialBitsDecision`）

| 条件 | 満たさないとき | 根拠 |
| ---- | -------------- | ---- |
| ポリシーが `PreserveIfOwnerMapped` | `StripPolicy` | 既定は fail-closed |
| ホストが Linux | `UnsupportedHost` | macOS は非 root の通常ファイルへの sticky が `EFTYPE`、setgid の継承規則も異なる。Windows には mode が無い |
| `root` がディレクトリで `mode & 0o077 == 0` | `RootAccessibleByOthers` | 0700 ならほかのユーザーは `root` より下へ入れず、祖先の権限は判定に要らない |

ファイル単位（`write_file` で書いた後、`fchmod` の前に評価。所有者は書いたファイル自身の metadata から得る）

| ビット | 残す条件 |
| ------ | -------- |
| 共通 | `root` の所有 uid が、書いたファイルの所有 uid と一致する |
| setuid | ファイルの所有 uid が 0 でなく、`uid.map_to_host(tar の uid) == ファイルの所有 uid` |
| setgid | ファイルの所有 uid と gid がともに 0 でなく、`gid.map_to_host(tar の gid) == ファイルの gid` |
| sticky | 共通の条件のみ（Linux の通常ファイルの sticky は権限を与えない） |

- rootful（ファイルの所有 uid が 0）は setuid / setgid を常に落とす。gid が 0 でなくても落とし、sticky は共通の条件だけで決まる（#2251 P2-1）
- `ExtractLimits::max_entries` にはグローバル PAX ヘッダも数える（`ExtractedLayer::entries` には含めない。パス 1 で書き込み前に
  拒否する。#2251 P2-3）

- tar の uid / gid は PAX の `uid` / `gid` を優先する。解析できない・u32 に収まらない値は `None` とし、setuid / setgid を落とす
- 適用後に mode を読み戻し、求めたビットが残っていなければ（所属しない gid への setgid をカーネルが落とす等）、
  適用したことにせず落とした件数に入れる。保持した件数は `SpecialBitsOutcome::preserved_files`
- ビットごとの件数は `SpecialBitsOutcome::preserved_bits`（読み戻しで残ったビット）と `stripped_bits`（求めたが残らなかったビット）。
  setuid と setgid を求めて setgid だけが落ちたときは、setuid を `preserved_bits`、setgid だけを `stripped_bits` に数える。
  ファイル単位の件数（`preserved_files`・`files_with_stripped_special_bits`）は従来どおり、一部でも落ちれば後者に数える（#2251 P2-6）
- hardlink は inode を共有するため、mode は参照先のものになる
- ディレクトリの mode（setgid・sticky を含む）はポリシーに関係なくそのまま適用する

## 呼び出し側の契約

- `root` を排他的に所有し、展開から rootfs として使い終わるまで 0700 を保つ。権限の後からの変更（TOCTOU）は防げない。
  0700 の確認は展開の開始時の 1 回だけで、展開中・展開後には確かめ直さない。呼び出し側は展開中も展開の後も group / other に開かない（#2251 P2-2）
- 展開の後に呼び出し側が所有者を変えるときは、fchown → fchmod の順にし、所有者と mode を読み戻して確かめる。Linux は `chown` で
  setuid / setgid を落とすため、mode を先に適用するとビットが失われるか意図しない所有者の setuid が残る。展開内の `chown`
  （`ChownMapped`）は #2225 でこの順序を実装済み（#2251 P2-5）
- コンテナ内で setuid が実際に効くかは `process.noNewPrivileges` に依る。本変更はビットの保持までを扱う

## 所有者の適用（chown。#2225・SEC-5）

`ExtractOptions { ownership, special_bits }` を受ける入口 `extract_layers_with_options` /
`extract_layer_blobs_with_options` を足した（既存の `*_with_policy` はこれへ委譲し、挙動は変えない）。
`OwnershipPolicy::ChownMapped { uid, gid }`（複数行の写像 `IdMap`。core の `IdMapSet::new` と同じ検証規則で、
`tests/idmap_core_parity.rs` が同じ入力の表で照合する）を渡すと、tar の uid / gid を写像してホストの ID へ `chown` する。
既定は `Keep`（`chown` しない）。

| 項目 | 決定 |
| ---- | ---- |
| 呼び出し側 | 初期 user namespace で `CAP_CHOWN` を持つプロセス（典型はホスト root）。ホストの非特権ユーザーは subuid 範囲へ `chown` できず、`EPERM` は `PermissionDenied`（fail-closed）。写像はコンテナ起動時の user namespace の写像と同じものを渡す。入手経路は 1 本だけで、cli の `image_ownership`（start の launcher と同じ supervisor `id_model::resolve_rootless_id_source` → core `SubordinateIdSource::resolve_id_maps` を呼ぶ。#2389。本番の呼び出し元は未配線） |
| 非 Linux | 開始前に `Unimplemented`（黙って飛ばさない）。特殊ビットは従来どおり `UnsupportedHost`（Strip 相当） |
| 範囲外・不正な ID | 写像に無い ID は `PermissionDenied`、解析できない ID（PAX の不正値を含む）は `InvalidArgument`。パス 1 で書き込み前に拒否 |
| ホスト ID 0 | `IdMap::new` が `PermissionDenied` で拒否する（コンテナ root をホスト root に写さない。SEC-5） |
| 通常ファイル | 書き込み後に `fchown` → 所有者を読み戻して照合（不一致は `FailedPrecondition`）→ 特殊ビット判定 → `fchmod`。`chown` を先にするのは Linux が `chown` で setuid / setgid を落とすため |
| ディレクトリ | 全レイヤーの後に深い順で `lchown` し、直後に mode を適用する。子の作成を妨げないため |
| 暗黙のディレクトリ | tar に所有者が無いため、コンテナ内 0:0 を写した ID にする |
| symlink | `lchown`（追従しない）。mode は扱わない |
| hardlink | `chown` しない。inode を共有する参照先の所有者と特殊ビットを書き換えないため。所有者は参照先のエントリのもの |
| `root` | 最後にコンテナ内 0:0 を写した ID へ `chown`。mode は 0700 のまま（ホスト root 所有のままだとコンテナ root が `/` を辿れない） |
| PAX `uname` / `gname` | 使わない（読まない）。数値の uid / gid だけを正とする。名前はイメージの `/etc/passwd` に属し、ホストの NSS で引くと別のユーザーに写りうるため。NSS 解決の FFI も要る |
| xattr | 扱わない |

結果は `ExtractedLayer::ownership`（`OwnershipOutcome { decision, chowned_entries }`）。ディレクトリと `root` の件数は
最後のレイヤーに数える。

## rootful で特殊ビットを残す条件（`SpecialBitsPolicy::PreserveIfChowned`）

`ChownMapped` と組み合わせたときだけ有効（`Keep` との組み合わせは開始前に `InvalidArgument`）。`chown` と読み戻しの後の
所有者で判定する。ポリシー全体の条件は `PreserveIfOwnerMapped` と同じ（Linux・`root` が 0700）。

| ビット | 残す条件 |
| ------ | -------- |
| setuid | 読み戻した所有 uid が 0 でなく、`uid.map_to_host(tar の uid) == 所有 uid` |
| setgid | 読み戻した所有 gid が 0 でなく、`gid.map_to_host(tar の gid) == 所有 gid` |
| sticky | ポリシー全体の条件のみ |

- 「`root` の所有 uid と一致」の共通条件は使わない（`chown` 後の所有者は写像先のため）
- 根拠: `IdMap` はホスト ID 0 を含む写像を拒否するため、残る setuid / setgid はホスト上で非特権の subuid / subgid にしか
  効かない。`root` が 0700 なのでほかのホストユーザーは辿れない。コンテナ内で setuid が効くかは `process.noNewPrivileges` 次第
- 適用後に mode を読み戻し、残っていなければ落とした件数に入れる（既存の規則と同じ）
- TOCTOU（ディレクトリ fd 起点の解決が未実装）は既存の制限のまま。呼び出し側が `root` を排他的に所有する契約に依る

## rootless の user namespace の中での展開（`OwnershipPolicy::ChownInUserNamespace`。#2382・OCI-2・SEC-5）

`ChownMapped` は展開プロセスが初期 user namespace で `CAP_CHOWN` を持つ前提（rootful）で、ホストの非特権ユーザーは
subuid 範囲へ `chown` できない。rootless では展開プロセス自身がコンテナと同じ写像の user namespace の中に入り、
tar のコンテナ内 ID をそのまま `chown` する（namespace の中では恒等写像）。渡す写像は `ChownMapped` と同じく cli の `image_ownership` で作り、start と食い違わせない（#2389）。

- 責務の分け: namespace へ入る処理（fork・`unshare`・`newuidmap`。core の `isolate` / `isolate_rootless_subordinate`）は
  core の責務で、oci は入らない。oci は「呼び出しプロセスがすでに入っている」契約を開始前に検証する。
- 契約: 単一スレッド・初期 user namespace の直下に作った namespace・ns 内で euid / fsuid / egid / fsgid が 0。
- `IdMap` の意味は `ChownMapped` と同じ（コンテナの写像。`container_id parent_id count`。ホスト ID 0 は `IdMap::new` が拒否）。
  tar の ID が写像に含まれるかの判定にだけ使い、宛先は tar の ID そのまま。暗黙のディレクトリと `root` は ns 内の 0:0。
  写像に無い ID は `PermissionDenied`、解析不能は `InvalidArgument`（そのレイヤーの書き込み前）。順序は `ChownMapped` と同じ。
- 開始前の検証（`root` に触れる前。失敗は `FailedPrecondition`）: `/proc/self/{uid,gid}_map` を上限つき（16 KiB・340 行）で
  厳格に解析し、(1) 初期 user namespace の恒等写像（`0 0 4294967295`）でない、(2) 渡された `IdMap` と行の集合として完全一致、
  (3) `/proc/self/status` の effective / fs の uid・gid が 0。`user_namespaces(7)` のとおり、読む側と対象が同じ namespace に
  いるとき写像の 2 列目は親の namespace の ID なので、ホストから見た `IdMap` と直接比べられる。写像はカーネルが 1 回しか
  書かせないため、検証から使用までの間に書き換えられない（TOCTOU なし）。新しい `unsafe` は無い。
- `chown` の `EINVAL`（ns の中で写像に無い ID）は `PermissionDenied` に写す（fail-closed）。
- 特殊ビット（`PreserveIfChowned` と組み合わせたとき）: 「所有 uid ≠ 0」の条件はこのモードには合わない（コンテナ root の所有は
  ns 内 uid 0）。代わりに、setuid は読み戻した所有 uid が tar の uid と一致し、その ID が写像に含まれること、setgid は gid で
  同様、sticky はポリシー全体の条件（Linux・`root` が 0700）だけで決める。根拠は上の rootful と同じで、残る setuid / setgid は
  ホストでは起動ユーザー自身か subuid にしか効かず、`root` が 0700 なので他のホストユーザーは辿れない。
- 残余・制約: 入れ子の user namespace では「親の ID ≠ 0」が「ホスト ID ≠ 0」を意味しない（契約で初期 namespace の直下に限る）。
  展開した木はホストから見ると subuid の所有になり、ホスト側の後始末（`CreatedRootfs::remove`・delete）は `EPERM` で失敗しうる。
  削除も namespace の中で行う必要がある（`remove_extracted_tree`）。この経路は core 側で未配線（下記）で、端から端の後始末が
  動くとは言わない。

## 未実装（REPAIR-3）

- rootless の user namespace へ入って `ImageRootfsUnpacker::unpack` を呼ぶ core 側の配線（子プロセス方式。tokio の
  マルチスレッドの pull 経路ではプロセス内で入れない）と、subuid 所有の rootfs の削除経路（#2315・#482）。
  `PreserveIfOwnerMapped` の rootless 経路（`chown` しない 1 行の写像）は従来どおり
- 0700 の祖先ディレクトリで閉じ込めを判定する方式。`root` が 0700 のため、複数範囲の写像でもコンテナ内の非 root ユーザーは
  `/` を辿れない
- 本番の呼び出し元（pull → 展開 → 起動の経路）から `ExtractOptions` を渡す配線
- `IdMap` と core の `IdMapSet` を下位 crate へ共通化するかどうか（crate 境界の判断）

## 試験との対応

`extract.rs` の単体試験。`sec5_special_bits_preserved_when_owner_mapped`（条件を満たす経路で tar の値どおり）、
`sec5_special_bits_stripped_when_root_is_accessible_by_others`・`sec5_special_bits_dropped_when_tar_owner_is_not_mapped`・
`sec5_special_bits_dropped_when_file_owner_is_host_root`・`sec5_special_bits_dropped_when_pax_uid_is_malformed`
（満たさない経路で落ち、件数が出る）、`oci1_directory_setgid_is_applied`（ディレクトリの setgid）、
`sec5_special_bits_to_keep_matrix`・`sec5_id_range_maps_with_checked_arithmetic`（純関数の条件の組み合わせ）、
Issue #2251 で追加: `sec5_setgid_dropped_when_file_owner_uid_is_host_root`・`oci2_global_pax_headers_count_toward_entry_limit`・
`oci2_global_pax_headers_accumulate_across_layers`・`sec5_readback_setgid_only_drop_does_not_count_setuid_as_stripped`・
`sec5_special_bit_counts_add_bits`。

chown（#2225）: `extract.rs` の `chown_tests`（`chown` を記録する差し替え口で呼び出しの値・順序を照合。
`sec5_chown_maps_tar_owner_through_multi_line_map`・`sec5_chown_order_file_before_mode`・
`sec5_chown_dirs_deepest_first_before_mode`・`sec5_hardlink_is_not_chowned`・
`sec5_owner_outside_map_is_rejected_before_layer_writes`・`sec5_malformed_pax_owner_is_rejected_when_chowning`・
`sec5_chown_readback_mismatch_is_failed_precondition`・`sec5_chown_eperm_is_permission_denied`・
`sec5_preserve_if_chowned_*`・`sec5_special_bits_to_keep_chowned_matrix`・`sec5_keep_policy_does_not_chown`）、
非 Linux の `sec5_chown_is_unimplemented_off_linux`・`sec5_non_linux_preserve_policy_strips_everything`（main の 3 OS 実行で確認）、
`idmap.rs` の単体試験、`tests/idmap_core_parity.rs`（core との照合）、`tests/layer_extract.rs` の
`sec5_chown_via_public_api_with_real_syscalls`・`sec5_chown_outside_map_and_without_privilege_fail_closed`
（実 syscall。権限なしで通る）。実機前提（root）の `sec5_chown_subuid_range_as_root` は `#[ignore]`（AGENTS.md「実機前提テスト」）。

rootless の user namespace の中での展開（#2382）: `extract.rs` の `chown_tests` の `oci2_userns_*`・
`oci2_check_user_namespace_cases`・`oci2_parse_status_ids`・`sec5_userns_preserve_if_chowned_end_to_end`・
`sec5_special_bits_to_keep_in_userns_matrix`（`/proc/self` の見え方の差し替え口で開始前の検証と宛先の値を照合）、
`idmap.rs` の `sec5_parse_proc_id_map`・`sec5_same_lines_as`、`tests/idmap_core_parity.rs` の
`oci2_parse_proc_id_map_matches_core`。実機前提の `tests/userns_extract.rs`（`harness = false`。`unshare --user --map-root-user`
で子を namespace へ入れ、ホストから見た所有者・setuid を照合。`-- --ignored`。AGENTS.md「実機前提テスト」）。
