# レイヤー展開の setuid / setgid / sticky の扱い

OCI-1・SEC-5・SEC-1・REPAIR-3・REPAIR-4（#1810。前段は TASK-52.3・#409）。実装は `crates/oci/src/layer/extract.rs`。

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
`IdRange` で渡す。

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
| setgid | ファイルの gid が 0 でなく、`gid.map_to_host(tar の gid) == ファイルの gid` |
| sticky | 共通の条件のみ（Linux の通常ファイルの sticky は権限を与えない） |

- tar の uid / gid は PAX の `uid` / `gid` を優先する。解析できない・u32 に収まらない値は `None` とし、setuid / setgid を落とす
- 適用後に mode を読み戻し、求めたビットが残っていなければ（所属しない gid への setgid をカーネルが落とす等）、
  適用したことにせず落とした件数に入れる。保持した件数は `SpecialBitsOutcome::preserved_files`
- hardlink は inode を共有するため、mode は参照先のものになる
- ディレクトリの mode（setgid・sticky を含む）はポリシーに関係なくそのまま適用する

## 呼び出し側の契約

- `root` を排他的に所有し、展開から rootfs として使い終わるまで 0700 を保つ。権限の後からの変更（TOCTOU）は防げない
- コンテナ内で setuid が実際に効くかは `process.noNewPrivileges` に依る。本変更はビットの保持までを扱う

## 未実装（REPAIR-3）

- tar の uid / gid の適用（`chown`・subuid の複数範囲への写像）。展開物は常に実行ユーザー所有のため、rootless
  （コンテナ内 0 → 実行ユーザーの 1 行の写像）のように、所有者が写像先と一致する経路だけを保持の対象にしている
- rootful（ホスト uid 0）で特殊ビットを残す経路。ファイルの所有 uid が 0 のため常に落とす。`chown` と idmap の導入後に再検討する
- 写像が複数行の場合の `IdRange` の拡張
- PAX の `uname` / `gname` は使わない

## 試験との対応

`extract.rs` の単体試験。`sec5_special_bits_preserved_when_owner_mapped`（条件を満たす経路で tar の値どおり）、
`sec5_special_bits_stripped_when_root_is_accessible_by_others`・`sec5_special_bits_dropped_when_tar_owner_is_not_mapped`・
`sec5_special_bits_dropped_when_file_owner_is_host_root`・`sec5_special_bits_dropped_when_pax_uid_is_malformed`
（満たさない経路で落ち、件数が出る）、`oci1_directory_setgid_is_applied`（ディレクトリの setgid）、
`sec5_special_bits_to_keep_matrix`・`sec5_id_range_maps_with_checked_arithmetic`（純関数の条件の組み合わせ）。
