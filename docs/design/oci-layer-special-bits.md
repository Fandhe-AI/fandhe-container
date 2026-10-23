# レイヤー展開の setuid / setgid / sticky の扱い

OCI-1・OCI-2・SEC-5・SEC-1・REPAIR-3・REPAIR-4（#1810・#2251・#2437。前段は TASK-52.3・#409）。実装は `crates/oci/src/layer/extract.rs`。

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
| （展開中）`root` の所有者と 0700 が開始時のまま | `RootChangedDuringExtraction` | 展開の途中で変えられても、以後のビットを保持しない（#2437。下記「展開中の再確認」） |

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

- `root` を排他的に所有し、展開から rootfs として使い終わるまで 0700 を保つ。展開中の権限の変更は、特殊ビットを保持する
  経路について展開中に検出して fail-closed にする（下記「展開中の再確認」・#2437）。展開の後は確かめ直さない。呼び出し側は
  展開中も展開の後も group / other に開かない（#2251 P2-2）
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
- TOCTOU は Linux の x86_64 / aarch64 ではディレクトリ fd 起点の解決と展開中の再確認で縮める（下記）。呼び出し側が `root` を
  排他的に所有する契約は引き続き前提

## ディレクトリ fd 起点の解決と展開中の再確認（#2437・OCI-1・OCI-2・SEC-5）

実装は `crates/oci/src/layer/anchored.rs`（`AnchoredRoot`）と `crates/oci/src/sys/at.rs`（`openat2` 等の自前宣言。新しい `unsafe` は
`sys` の中だけ）。

- 解決は 2 段にする。各コンポーネントの `lstat` による確認（別表記の検出 IO-5・型の衝突・symlink の chroot 意味論）は残し、
  変更操作（作成・削除・symlink・hardlink・`chown`・mode の適用・whiteout の削除）だけを `root` の fd 起点にする。`root` は
  展開の開始時に 1 回だけ `O_NOFOLLOW | O_DIRECTORY` で開き、以後パスで開き直さない
- 親ディレクトリは、解決済みの物理コンポーネント列（symlink も `..` も含まない）を `root` の fd からの相対パスとして
  `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` で開き直す。列に symlink が
  無いはずなので `RESOLVE_NO_SYMLINKS` は差し替えの検出器になる。確認の後に祖先が symlink にされると `ELOOP`、マウントを
  またぐと `EXDEV`、非ディレクトリにされると `ENOTDIR` で失敗し、`FailedPrecondition`（`an extraction path changed during
  extraction`）にする。`RESOLVE_IN_ROOT` は二重の保険。`EAGAIN`（解決中の rename・mount の競合）は 8 回まで再試行し、超えたら
  同じエラー
- 最終コンポーネントは親 fd に対する `*at(2)` で追従しない形にする: 作成は `O_CREAT | O_EXCL | O_NOFOLLOW`、`mkdirat`、
  `symlinkat`、`linkat`（flags 0 で参照元の symlink を追従しない。`AT_EMPTY_PATH` は非特権で使えない）、`unlinkat`、
  `fchownat(AT_SYMLINK_NOFOLLOW)`。hardlink は作成後に通常ファイルであることを確かめ、違えばリンクを消して拒否する
- 古いカーネル: `openat2` は Linux 5.6 以降。`ENOSYS`・`E2BIG`・`EINVAL`（`open_how` や `RESOLVE_*` を知らない）は展開の開始前に
  `Unimplemented`（`openat2 is not available on this kernel`）で拒否し、パス起点へ縮退しない。`Strip` ポリシーでも同じ（Landlock
  前提の 5.13 より古いカーネルは CORE の前提外）。seccomp による `EPERM` は `PermissionDenied`
- 他の OS・アーキテクチャ: macOS・Windows はパス起点のまま（特殊ビットの保持は Linux 限定で `UnsupportedHost` になるため、
  SEC-5 の TOCTOU は Linux 固有）。Linux の他アーキテクチャは定数を確かめていないので展開は `Unimplemented`
  （`remove_extracted_tree` はパス起点のまま。理由と残余は下記「未実装」。#2598）
- whiteout の削除（`remove_tree` / `remove_contents`）も fd 起点で、`getdents64` で列挙する。子は 1 コンポーネントずつ
  `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` で開く。所有者の rwx が欠けるディレクトリは権限を戻して消す。
  所有者に `r` が無い（0000）ディレクトリは、同じ `dirfd` と名前から `O_PATH` で開き、`/proc/self/fd/<n>` 経由で権限を戻し
  （`fchmodat` は最終コンポーネントの symlink を追従するため使わない）、その fd の `.` を開き直す（名前を解決し直さない）。
  `/proc` が必要で、無ければ失敗する。所有者でなければ `PermissionDenied`（#2598）
- 公開の `remove_extracted_tree` も同じ削除（`remove_path_tree`）で fd 起点にした（#2598）。`path` の親だけは信頼済みの
  接頭辞としてパスで 1 回開き、`path` から下の差し替えは `FailedPrecondition`、`file_name` を持たない `/`・`..` 終わりは
  `InvalidArgument`。木の中に残ったマウントは `RESOLVE_NO_XDEV` で `FailedPrecondition` になり、中身を消さない
  （非特権では作れないため試験では確かめていない）

### 展開中の再確認（SEC-5）

- 特殊ビットを判定する直前と、ビットを付けた直後に、開いた `root` の fd の `fstat` で「ディレクトリで、`mode & 0o077 == 0`、
  所有 uid が開始時と同じ」を確かめる。費用は特殊ビット付きのファイル数に比例する
- 変わっていたら判定を一方向にラッチする（`SpecialBitsDecision::RootChangedDuringExtraction`）。そのファイルを含め以後は
  すべて落とし（付けた直後の検出では `fchmod` で外す）、落とした件数は `stripped_bits` に数える
- 保持済みのビットが 1 件でもある状態で前提が崩れた場合は、遡って外さず、全レイヤーの展開後（`chown_root` の前）に
  `FailedPrecondition`（`the extraction root changed while special mode bits were preserved`）で展開全体を拒否する。`Err` を
  受けた呼び出し側は `root` ごと破棄する（契約）。`chown_root` は `root` の所有者を正当に変えるため、その後は確認しない
- 残る窓: `fstat` と `fchmod` の間は、事後の確認で縮めるがゼロではない。0700 は `root` の inode の性質なので、`root` のパスを
  rename で動かされても fd 起点の書き込みと配下の保護は保たれる

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
- macOS・Windows・Linux の他アーキテクチャでの、展開と公開の `remove_extracted_tree` のディレクトリ fd 起点の解決（#2598 で
  広げないと決めた）。パス起点のままで、確認から使用までの TOCTOU と、木の中に残ったマウントの中身の削除を防げない。理由:
  特殊ビットの保持は Linux 限定で SEC-5 の TOCTOU は Linux 固有／macOS・Windows の本番経路は cli の `non_linux_failure` が先に
  fail-closed にしホストでの展開に届かない／Linux の他アーキテクチャは展開が `Unimplemented` で展開物が無く、削除も空の木を
  消すだけ／macOS の `openat` 系・Windows のハンドル起点操作は新しい FFI 宣言・libc 照合（Windows はオーナー判断）が要る。
  ゲストが共有ディレクトリへ書き込みうる設計（`macos-shared-vm.md`）になれば優先度が上がる
- oci の `sys` への `libc` との機械照合の導入（`docs/design/ffi-libc-check.md`。`sys/at.rs` の定数は一次情報との突き合わせのみ）
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

fd 起点の解決と再確認（#2437）: `extract.rs` の `anchored_tests`（`oci1_parent_swapped_to_symlink_after_probe_is_rejected`・
`oci2_whiteout_parent_swapped_to_symlink_does_not_remove_outside`・`oci2_opaque_parent_swapped_to_symlink_does_not_remove_outside`・
`oci1_hardlink_target_parent_swapped_is_rejected`・`sec5_root_mode_change_before_special_file_strips_remaining`・
`sec5_root_owner_change_is_detected`・`sec5_root_mode_change_after_preserved_file_fails_closed`・
`oci1_extract_refuses_when_openat2_unavailable`・`oci1_eagain_is_retried_with_a_cap`）、`anchored.rs` の単体試験と `sys/at.rs` の
単体試験（dirent の解析・名前の検証・`RESOLVE_NO_SYMLINKS` の `ELOOP`）。既存の拒否試験（`oci1_path_traversal_is_rejected`・
`oci1_symlink_*`・`oci1_hardlink_*`・`oci2_*_does_not_follow_symlinks`・`io5_*`）は期待値を変えずに通る。

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
