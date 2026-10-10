# OCI 既定の /dev の残りと rootless の /dev 供給方式（設計ドラフト）

OCI 既定の `/dev` のうち、基本デバイスノード 6 種と default symlink 4 本の後に残る `/dev/pts`・`/dev/ptmx`・`/dev/shm`・`/dev/console` と、rootless（user namespace）での `/dev/*` の供給方式を整理し、確定した方式と、起票した実装 issue の一覧を示す。

> **位置づけ**: TASK-29 追補・#1609 の設計ドラフト。方式はオーナー判断（2026-10-10。#1609 のコメントに記録）で確定し、実装・調査 issue 9 件を Phase 3 の親 #54 の配下に起票した（5 章）。

- 対象ビヘイビア: CORE-1・CORE-2・OCI-4・SEC-1（関連: CORE-5・CORE-6・SEC-5・SUP-12）
- タスク: TASK-29 追補、TASK-27.6（#834）、MS-2
- 確認日: 2026-10-10
- 確定日: 2026-10-10（オーナー判断。#1609 のコメント）

## 1. 一次情報

| 文書 | 版 | 節 | 要点 |
| ---- | -- | -- | ---- |
| OCI runtime-spec `config-linux.md` | v1.3.0 | Default Filesystems | `/proc`・`/sys`・`/dev/pts`（devpts）・`/dev/shm`（tmpfs）を SHOULD で提供。`/dev/mqueue` は表に無い |
| 同上 | v1.3.0 | Default Devices | 6 種に加え、`terminal` 有効時は pty を `/dev/console` へ bind mount。`/dev/ptmx` は `/dev/pts/ptmx` の bind mount または symlink |
| runc `libcontainer/specconv/example.go` | v1.5.2 | 既定マウント | devpts: `nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5`。shm: `nosuid,noexec,nodev,mode=1777,size=65536k`。`/dev` は tmpfs（`nosuid,strictatime,mode=755,size=65536k`）。`/dev/mqueue` は runc の生成 config にある |
| 同上（rootless 変換） | v1.5.2 | `ToRootless` | マウントオプションから `gid=` と `uid=` を取り除く |
| runc `libcontainer/rootfs_linux.go` | v1.5.2 | `createDevices`・`bindMountDeviceNode`・`setupPtmx` | user namespace では mknod 不可のためホストのノードを bind。bind 先は fd 起点で `O_CREAT\|O_NOFOLLOW` により作る。`/dev/ptmx` は `pts/ptmx` への相対 symlink（既存を unlink してから作る） |
| Linux `Documentation/filesystems/devpts.rst` | v6.12 | 全体 | devpts は mount ごとに独立し、`/dev/pts/ptmx`（0000）を作る。`/dev/ptmx` を symlink または bind にする場合は `ptmxmode=0666` が要る。`max=<count>` で instance ごとの上限を設けられる |

未確認（実装 issue の着手時に確かめる）: `user_namespaces(7)` / `mount_namespaces(7)` における userns 内での devpts・mqueue マウント条件、`dev.tty.legacy_tiocsti`（6.2 以降）、Docker の `/dev/shm` 既定 64 MiB と `--ipc=host` の扱い。本書では確認できていないため、確定扱いしない。

## 2. 現状（本リポ）

- `create_default_devices` は rootfs の `dev` に専用の nodev なし tmpfs（`sys::mount_dev_tmpfs_on`・#1652）を載せてから、基本 6 デバイスと default symlink 4 本をそのマウントのルート fd 起点で作る（#1653）。ノードはホストの rootfs に残らず、イメージ同梱の `dev` 配下は覆い隠される。起動順序は `prepare_rootfs` → `create_default_devices`（`dev` に tmpfs → ノード → symlink）→ `mount_tmpfs` → `pivot_root`。`/dev/shm`・`/dev/pts` は本 tmpfs の上に載せる後続 issue（5 章）の担当
- `/dev/shm` は `--shm-size` 指定時のみマウントする。未指定時に既定 64 MiB を常にマウントする処理は無い
- `sys` の新マウント API ラッパーは tmpfs 固定（`mount_tmpfs_on`）。devpts のラッパーは無い
- `process.terminal: true` と `mounts[]` は拒否する。`/proc` と基本 6 デバイスは `mounts[]` を使わず暗黙の固定集合
- Landlock のルールは `config.json` の `root` と `mounts[]` のみから作る。暗黙の `/dev/pts`・`/dev/shm` に対するルールは無い。`PSEUDO_FS` に devpts は入っていない
- rootless は tmpfs までは載るが `mknod` が `EPERM` になり `PermissionDenied` で fail-closed（載せた tmpfs は外す）。ホスト `/dev` の bind は未実装（#1660）

## 3. 方式の比較

### 3.1 `/dev` 自体を tmpfs にするか

| 案 | 利点 | 欠点 |
| -- | ---- | ---- |
| tmpfs にする（runc 方式） | ノードがホスト側 rootfs ディレクトリに残らない。イメージ同梱の偽ノードを覆い隠せる | 順序変更（`prepare_rootfs` → `/dev` に tmpfs → ノード → devpts・shm → `pivot_root`）。既存の `EEXIST` 検証の意味が変わる |
| 現状維持 | 変更が小さい | ホスト側にノードが残る |

tmpfs にする（runc 方式）に確定（4 章の判断 1）。実装は #1652・#1653。

### 3.2 暗黙の固定集合か `mounts[]` の汎用処理か

暗黙の固定集合は `/proc`・基本 6 デバイスと揃い、小さく入れられる。`mounts[]` 経由は汎用だが `mounts[]` の受け入れ処理（TASK-127 系）に依存する。Landlock のルール生成が `mounts[]` 前提のため、暗黙集合を採るなら暗黙分のルールを別途足す必要がある。

暗黙の固定集合に確定した（判断 2）。`mounts[]` の受け入れ処理は待たない。暗黙分の Landlock ルールは #1657 で扱う。

### 3.3 devpts と `/dev/ptmx`

- devpts は `fsopen("devpts")` と `fsconfig` を `sys` に新設し、オプションは型付きフィールドからキー単位で渡す。利用者の文字列や `data` 文字列は渡さない。常に独立 instance にする
- rootless で `gid=5` が写像されていない場合、runc は `gid=` を除く。本リポも `gid=` を除いて載せる（runc `ToRootless` と同じ。判断 3）
- `/dev/ptmx` は `pts/ptmx` への symlink にする（runc と同じ。#1656）。symlink はマウント後に置く必要があり、`devices.rs` の default symlink 集合に足すと順序が逆になる。既存の `ptmx` が完全一致でなければ拒否する

### 3.4 `/dev/shm`

`--shm-size` 未指定でも 64 MiB（`nosuid,noexec,nodev,mode=1777`）を常にマウントする。利用者指定との重複は指定を優先する。`--ipc=host` はホストの `/dev/shm` の bind が要り、別の関心事として切り出す。

### 3.5 `/dev/console`

`terminal: true` の pty 受け渡し（console socket）に依存し、2h では収まらない。`terminal: false` の間は不要。端末機能の親 issue を別に設計する。

### 3.6 rootless の供給

| 案 | 内容 | 評価 |
| -- | ---- | ---- |
| (a) ホストのノードを `open_tree` + `move_mount` で bind | rootfs の `dev` に fd 起点で空ファイルを作り、ホスト側を `O_PATH\|O_NOFOLLOW` で開いて文字デバイスと `rdev` を検証してから載せる | 検証と TOCTOU 耐性が高い。新規 sys ラッパーが要る |
| (b) 既存の `mount(2)` + `MS_BIND` に合わせる | `bind_mount_recursive` の流儀 | 実装は軽いが、パス経由で競合の余地が増える |
| (c) 供給せず fail-closed のまま | 現状 | rootless で実用にならない |

(a) に確定した（判断 4）。実装は #1659・#1660。`nodev` の rootfs を検出していない既知の問題（`devices.rs` に記載済み）と、bind したマウントへの `nosuid`・`noexec` の付与も併せて扱う。

### 3.7 失敗時の後始末

`mount_tmpfs` と同じく、この呼び出しで作ったマウントを逆順に `MNT_DETACH` で外し、この呼び出しで作った空ディレクトリ・ファイルだけを消す。プロセスは破棄する契約に揃える。新マウント API が `ENOSYS` のときは `mount(2)` へ縮退せず fail-closed にする。

## 4. 確定した事項（オーナー判断 2026-10-10）

1. `/dev` 自体を tmpfs にする（3.1）
2. `/dev/pts`・`/dev/shm` は暗黙の固定集合として常に載せる（3.2）
3. rootless で gid 5 が写像されていなければ、devpts の `gid=` を除いて載せる（3.3）
4. rootless の基本デバイスは (a) `open_tree` + `move_mount` の bind で供給する（3.6）

分割案は #54 の配下に 2h 粒度で起票した（5 章）。

## 5. 実装 issue（2h 粒度。#54 配下）

launcher への配線（`spawn_container` がこれらを呼ぶこと）は #1314 の範囲で、含めない。

| 順 | issue | 旧分割案 | 内容 | 依存 | ID |
| -- | ----- | -------- | ---- | ---- | -- |
| 1 | #1652 | #8 | `/dev` に載せる nodev なしの tmpfs を新マウント API で作る `sys` の入口 | #1651（本書の確定） | CORE-1・SEC-1 |
| 2 | #1653 | #8 | rootfs の `/dev` に tmpfs を載せてから基本デバイスノードと default symlink を作る（順序の変更） | #1652 | CORE-1・SEC-1 |
| 3 | #1654 | #1 | `--shm-size` 未指定時も `/dev/shm` に既定 64 MiB | #1653 | CORE-1・SUP-12 |
| 4 | #1655 | #2 | devpts の `sys` ラッパー（`fsopen`・`fsconfig`） | #1651（本書の確定） | CORE-1・SEC-1 |
| 5 | #1656 | #3 | `/dev/pts`（独立 instance）と `/dev/ptmx` の symlink、rootless の `gid=` | #1655・#1653・#1654 | CORE-1・OCI-4・SEC-1 |
| 6 | #1657 | #4 | 暗黙の `/dev`・`/dev/pts`・`/dev/shm` の Landlock ルール | #1654・#1656 | CORE-5 |
| 7 | #1658 | #5 | pty の ioctl（`TIOCSTI` 等）の扱いの調査と判断（コード変更なし） | #1656 | CORE-5・SEC-1 |
| 8 | #1659 | #6 | `open_tree`・`move_mount` の `sys` ラッパー | #1651（本書の確定） | CORE-6・SEC-5・CORE-1 |
| 9 | #1660 | #7 | rootless 経路の基本デバイスの bind 供給 | #1659・#1653 | CORE-6・SEC-5・CORE-1 |
| - | 起票しない | #9 | `/dev/mqueue`（spec 判断待ち） | spec 判断 | CORE-1 |
| - | 起票しない（対象外） | - | `/dev/console`（端末機能の親 issue として別に設計する。3.5） | 端末機能 | CORE-2・OCI-4 |

旧分割案 #8 は確定し、#1・#3・#7 の前提として前に置いた（#1652・#1653）。

新規 `unsafe` は各 crate の `sys` モジュール内に限り、`// SAFETY:`・security-auditor 観点のレビュー・PR への記録を要する（[coding-rust](../../.claude/rules/coding-rust.md)）。

## 6. spec 側の確認事項（ユーザーへ報告済み）

- CORE-1 が列挙する 6 デバイスに `/dev/pts`・`/dev/shm` 等を加えるか
- `/dev/mqueue` を既定とするか（OCI runtime-spec v1.3.0 の既定表には無く、runc の生成 config にある）
- rootless のデバイス供給をどのビヘイビアに対応づけるか

spec リポ側の課題としてユーザーへ報告済み。本リポでは spec 側の判断を先取りしない。
