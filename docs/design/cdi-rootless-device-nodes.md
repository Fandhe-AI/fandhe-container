# rootless での CDI deviceNodes のホストのノードの bind による供給方式（設計・判断シート）

rootless（非特権 user namespace）で、検証済みの CDI `deviceNodes` をコンテナの `/dev` へ供給する方式を整理する。core の rootless の基本デバイス 6 種の供給（`open_tree(2)` + `move_mount(2)`、#1659・#1660）を CDI のノードへ広げられるか、広げるなら何を条件にするかを判断材料にまとめる。

> **位置づけ**: 状態は **オーナー承認待ち**（[#2986](https://github.com/Fandhe-AI/fandhe-container/issues/2986)）。本書は決定ではなく判断材料である。承認が出るまで、`crates/gpu` の `create_device_nodes` は rootless の `mknod` の `EPERM` を `PermissionDenied` で返す現状を保つ（fail-closed）。本書の時点で製品コードは 1 行も変えておらず、承認を得たものも無い。

- 対象ビヘイビア: GPU-2・GPU-4・CORE-6・SEC-5・SEC-1・SEC-4。関連: GPU-3・OCI-4・PLUG-1・PLUG-11・REPAIR-3・REPAIR-4
- タスク: TASK-127 追補・TASK-129。関連 issue: #1659・#1660・#1676・#2979（TASK-127.1 の `deviceNodes` の mknod）・#563（TASK-129.4）・#553（TASK-128）・#2774・#2241
- 関連文書: [cri-devices-cdi.md](cri-devices-cdi.md)・[dev-default-mounts.md](dev-default-mounts.md)（3.6・4 章）・[cgroups.md](cgroups.md)（デバイス cgroup）
- 確認日: 2026-10-27（`origin/main` のソースで確認）

## 一次情報

### コード（本リポ）

| 項目 | 場所と識別子 |
| ---- | ------------ |
| gpu の mknod | `crates/gpu/src/cdi_apply/device_nodes.rs` の `create_device_nodes`。モジュール doc に rootless の bind は未実装、`EPERM` は `PermissionDenied` のまま返すと明記 |
| core の固定 6 種 | `crates/core/src/sys.rs` の `HostDeviceNode`（列挙子 6 つの固定表）・`verify_device_node_fd`（`rdev == makedev(固定表の値)` のみ照合）・`VerifiedDeviceNodeFd`・`open_tree_clone` |
| core の供給方式の選択 | `crates/core/src/exec/devices.rs` の `DeviceSupply::BindFromHost`（`DevptsGidSource::Rootless` の申告で決まる）・`bind_host_devices`・`bind_one`・`roll_back_dev` |
| `mounts[]` の bind の種別拒否 | `crates/core/src/exec/bind_mounts.rs` の `pin_source` → `sys::verify_bind_source_fd` → `BindSourceError::NotDirOrRegular` → `ViolationReason::BindSourceUnsupportedType`（試験 `sec1_source_unsupported_type_is_rejected`） |
| `mounts[]` の bind の `nodev` | `crates/core/src/oci_runtime/bind_mounts.rs` の `parse_options`（`nosuid`・`nodev` は常に付与され外せない。#1910） |
| 違反記録 | `crates/core/src/exec/violation.rs` の `ViolationReason::HostDeviceNodeUnexpected`（`host_device_node_unexpected`） |
| gpu の依存 | `crates/gpu/Cargo.toml` は serde と serde-saphyr のみ。core は gpu に依存しない。`open_tree` / `move_mount` のラッパーは core の `sys` にだけある |

### カーネル（Linux v6.12 を想定。本書では原文を未確認）

以下は既知の挙動に基づく前提で、**原文での確認は未了**（実装 issue の最初の作業として確認する）。

- `fs/namei.c` の `may_open_dev`: マウントの `MNT_NODEV` または superblock の `SB_I_NODEV` があるとデバイスノードを open できない
- `fs/super.c` の `alloc_super`: user namespace が所有する superblock には `SB_I_NODEV` が付く（ユーザー namespace 内で作ったマウントのデバイスは開けない）
- `vfs_mknod`: 文字・ブロックデバイスの作成は init user namespace の `CAP_MKNOD` を要する（user namespace 内の root では `EPERM`）
- `fs/namespace.c` の `__do_loopback`: 複製元のマウントが呼び出し元の mount namespace に属すること（`check_mnt`）を要する
- 読み取り専用マウントはデバイスファイルの書き込み open を止めない（書き込み拒否の対象は通常ファイル・ディレクトリ・symlink）

### spec

- GPU-2 の前提は rootful（sudo で namespace を作れる環境）。GPU-4 は rootless では device cgroup が使えずデバイス制限が実質機能しないことの明記を求める。PoC-14 は非特権環境の代替に `--standalone` 相当を挙げる
- rootless での CDI 供給を GPU-2 の範囲に入れるかは spec の確定範囲の外。spec リポ側で扱う確認事項として報告する（本書は先取りしない）

## 現状

- gpu は `mknodat` でノードを作り、rootless では `EPERM` を `PermissionDenied` で返して起動できない
- core の rootless は基本 6 種だけをホストのノードの bind で供給する。供給方式は `DevptsGidSource` の申告で決まり、`EPERM` を見て切り替えない
- rootless では device cgroup を適用しない（`DevicePolicyOutcome::NotApplied(Rootless)`）。残る層はホストのノードの bind・rootfs の `nodev`（#1676）・Landlock（[cgroups.md](cgroups.md)）

## #1660 の経路と `mounts[]` の bind の関係

### #1660 は広げるのではなく、第 2 の検証型を作る

`HostDeviceNode` は 6 列挙子の固定表で、`open_tree_clone` は `VerifiedDeviceNodeFd` しか受けない。doc も「CDI の deviceNodes は別責務で、ここへ列挙子を足して受け付けない」とする。したがって「#1660 を広げる」とは列挙子を足すことではなく、期待する `(種別, rdev)` を受ける別の検証型（仮称 `VerifiedCdiDeviceNodeFd`）を core の `sys` に作ることを意味する。

このとき fail-closed の根拠は「固定表に無い値は表現できない」から「gpu の `resolve_device_nodes` とホストの照合を通った値に由来する」へ移る。信頼境界が core の型から CDI spec の出所の検査へ動くことが、この設計の要点である。

### `mounts[]` の bind（`bind_mounts.rs`）は入口にならない

独立した 2 つの理由がある。

1. **種別の拒否**: 受ける種別はディレクトリと通常ファイルだけで、デバイスは `BindSourceUnsupportedType` で拒否される
2. **外せない `nodev`**: `mounts[]` の bind には常に `nosuid|nodev` が付く。`nodev` が付くとノードは開けない

種別の検査を外してもノードは使えない。入口は `devices.rs` 型（マウント属性を足さず、順序を固定した経路）にする必要がある。gpu の `cdi_apply/mounts.rs` は CDI の mount を `mounts[]` の経路へ渡す設計なので、同じ理由でデバイスノードには使えない。結論として、`mounts[]` も `HostDeviceNode` も広げず、`devices.rs` 型の新しい入口を作る。

## 方式の比較

| 案 | 内容 | 利点 | 欠点 | 分離への影響 | 評価 |
| -- | ---- | ---- | ---- | ------------ | ---- |
| A | 検証済み CDI の文字デバイスに限り、ホストのノードを fd 起点で bind する（#1660 と同じ手順を第 2 の検証型で） | rootless で GPU が使える。基本 6 種と同じ検証の型 | 信頼境界が CDI spec の出所に移る。device cgroup が無い | 利用者のホスト上の DAC 以上は与えない。要求外のノードは置かない | **推奨** |
| B | rootless では CDI の `deviceNodes` を恒久的に拒否する | 実装なし。GPU-2 の rootful 前提と整合 | rootless で GPU を使えない | 緩めない | A が承認されないときの既定 |
| C | ホストの `/dev/<vendor>` のディレクトリごと bind する | 実装が単純 | 配下がすべて入り、ノードごとの照合ができない。`mounts[]` 経路は `nodev` も付く | 広がりすぎる | 不採用 |
| D | PoC-14 の `--standalone` 相当（namespace 分離なし） | 実装が単純 | コンテナにならず、分離（CORE 系）を満たさない | 分離なし | 不採用 |
| E | `mknod` の `EPERM` を見て bind へ縮退する | 呼び出し側が単純 | [cri-devices-cdi.md](cri-devices-cdi.md) と #1660 の「申告で決める」原則に反する | 失敗が黙って別経路に変わる | 不採用 |

## 許すノードの条件（方式 A）

- **供給方式は申告で決める**: `DevptsGidSource::Rootless` → `BindFromHost`。`EPERM` の後で切り替えない
- **対象**: `resolve_device_nodes` を通った `ResolvedDeviceNode` に由来する値だけ。CDI spec のディレクトリは root 所有で他者が書けないこと（PLUG-11 と同型。[cri-devices-cdi.md](cri-devices-cdi.md)）を前提とする。spec の読み込み経路は TASK-127 の別の子の担当
- **種別**: 文字デバイス（`c` / `u`）に限る。ブロック（`b`）は生のディスクへ届きうる。FIFO（`p`）は検証の前提（バインド元が文字デバイス 1 個）が成り立たない。どちらも rootless では拒否のまま。nvidia の CDI spec はすべて文字デバイスで実用上困らない
- **`fileMode`・`uid`・`gid`**: rootless では適用しない（ホストの inode の chmod・chown はしない。`devices.rs` のモード補正をしない方針と同じ）。ホストの値と食い違った指定の扱いは判断シート Q3
- **`permissions`（`rwm`）**: device cgroup が無いと効かない。読み取り専用の bind でも書き込みの open は止まらない（前提、未確認）。`rw` を含まない指定の扱いは判断シート Q4

## 宛先と元の検証

### 宛先

- コンテナ内の path は `/dev/` 配下だけ（gpu の `parse_dev_path` が既にそうしている）
- core が載せた `/dev` の tmpfs のルート fd 起点で、途中のディレクトリを `O_NOFOLLOW` で辿るか作る
- 末端はモード 0 の空ファイルを `O_CREAT|O_EXCL|O_NOFOLLOW` で作る。`EEXIST` は拒否し、基本 6 種との衝突も拒否する。作成時の fd と同じ inode であることを照合する

### 元

- hostPath は `/dev/` 配下に限る
- `pivot_root` の前に開いたホストの `/dev` の fd 起点で、1 要素ずつ `O_PATH|O_NOFOLLOW` で辿る（`pin_source` と同じ型）。途中の symlink も拒否する。gpu の `RealHost::lstat` は `symlink_metadata(path)` で最終要素は辿らないが途中は辿る点が異なる
- 同じ fd の `fstat` で `S_IFCHR` を確かめ、`rdev == makedev(resolved.major, resolved.minor)` を照合してから `open_tree_clone` する。照合の後にパスを開き直さない（TOCTOU なし）
- `AT_RECURSIVE`・`nosuid`・`noexec`・`nodev`・`mount_setattr` は付けない（#1659 と同じ。ルートが文字デバイス 1 個のため）

### 呼び出し順

- `unshare(CLONE_NEWNS)` の後・`pivot_root` の前（`__do_loopback` の `check_mnt`）
- 同じスレッドで seccomp の適用前（`DeniedSyscall::OpenTree`・`MoveMount`）
- 載せた後に開き直し、種別・`rdev`・自分のマウントであることを再確認する
- 失敗時は `roll_back_dev` と同じ順に後始末する（逆順に `MNT_DETACH` → 同じ inode のときだけ空ファイルを消す → この呼び出しが作った空ディレクトリを消す）

## 置き場所（gpu か core か）

- 候補 (i): core の `sys` と `exec::devices` に、gpu が作れる「検証済みのノードの要求」（core 所有の型）を受ける安全な入口を置く
- 候補 (ii): gpu の `sys` に `open_tree`・`move_mount` を重複して実装する
- 推奨は「`unsafe` を重複させない」ことまで。最終判断は「CDI の適用を core の起動経路へ配線する設計」（#2774 の前提。未起票・オーナー判断待ち）に従う
- gpu は core に依存しない現在の向きを保つ。PLUG-1・REPAIR-1 の観点で、境界をまたぐ型は下位 crate か core 所有にする

## 分離の論拠（GPU-4・SEC-5・SEC-1）

- rootless ではノードへの到達が、ホストの devtmpfs の inode の DAC（利用者の uid と補助グループ）だけで決まる。利用者がコンテナの外で開けるもの以上は与えない
- 危険は、コンテナ内の（信頼できないイメージの）プロセスが要求外のデバイスに届くこと。次で閉じる
  - spec で要求されたノードだけを置く
  - イメージ同梱のノードは `/dev` の tmpfs で隠れ、rootfs の `nodev`（#1676）で開けない
  - 新しい `mknod` は Landlock（`MAKE_CHAR`・`MAKE_BLOCK` を許さない）と init user namespace の `CAP_MKNOD` の要件で止まる
- ioctl の制限は GPU-3（TASK-128・#553）の担当。rootless で device cgroup が効かない制約の文書化は #563（TASK-129.4）を参照し、本書で重複して書かない

## 監査と観測（SEC-4・REPAIR-4）

- 照合に失敗したら bind せずに拒否し、違反記録を残す。理由は既存の `host_device_node_unexpected` の再利用か CDI 専用の理由の新設かを Q6 で決める
- 記録するパスは、spec 由来の値をそのまま載せず、長さ上限と字句検証を通した値に限る案を推奨する（gpu のエラー文言が固定でパスを含めない方針、OWASP A09 と揃える）
- 成功の結果は core の `DeviceNodeStatus::BoundFromHost` に相当する状態と観測値で報告する

## 残余（REPAIR-3）

- 0660 の `root:render` 系のノード（AMD・Intel）は利用者の補助グループに依存する。コンテナ内で補助グループを設定し直すと開けなくなる見込み（実機で未確認）
- CDI hooks の rootless での所有者検査（`cdi_apply/hooks.rs`）は本書の範囲外
- 実機確認（非特権 user namespace・Linux 5.2 以降・実 GPU）は人間担当
- 新しいマウント API が無いカーネルは `Unimplemented`（#1660 と同じ）
- rootful の差は #2241 を参照
- spec 側の確認事項: rootless の CDI 供給を GPU-2 の範囲に入れるか

## 判断シート（オーナー承認事項）

番号で答えられる形にする。推奨を併記する。

| Q | 問い | 推奨 |
| - | ---- | ---- |
| Q1 | 方式 A か B か | A（承認されなければ B のまま） |
| Q2 | 文字デバイスに限るか | 限る |
| Q3 | `fileMode`・`uid`・`gid` がホストの値と食い違うとき拒否か報告のみか | 拒否 |
| Q4 | `rw` を含まない `permissions` を rootless で拒否するか | 拒否 |
| Q5 | ホストのノードのマウントがホストの `/dev` と同じマウント（devtmpfs）であることを mount ID で照合するか | 照合する |
| Q6 | 違反の理由を再利用するか新設するか。記録するパスの扱い | 新設し、検証済みの値だけ記録 |
| Q7 | 置き場所は #2774 の配線の設計に委ねるか | 委ねる（`unsafe` の重複だけ避ける） |

### 承認後に起票する実装 issue の分割案（起票は承認後）

| # | 内容 | 粒度 | 依存・ID |
| - | ---- | ---- | -------- |
| 1 | core の `sys` に検証型と照合（元の fd 起点の辿り・`S_IFCHR`・`rdev`）を足す | 2h | CORE-6・SEC-5 |
| 2 | `exec::devices` に CDI ノードの bind の入口を足す（dry-run の単体試験つき） | 2h | 1・#2774 の配線の設計 |
| 3 | gpu 側の rootless での振り分け（申告で `mknod` と bind を分ける） | 2h | 2・GPU-2 |
| 4 | 実機前提の結合試験（`--ignored`・人間担当） | 人間担当 | 3・GPU-4 |
