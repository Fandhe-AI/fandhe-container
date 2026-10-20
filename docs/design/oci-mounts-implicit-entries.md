# mounts[] の bind・sysfs 以外の項目を受けるか（判断記録）

OCI `config.json` の `mounts[]` のうち、bind と `/sys` の sysfs 以外の項目（暗黙に供給済みの `/proc`・`/dev` 系、任意宛先の tmpfs など）を受けるか拒むかの判断材料を整理する（OCI-4・SEC-1・SEC-2・CORE-5）。

> **位置づけ**: 状態は **オーナー承認待ち**（[#2347](https://github.com/Fandhe-AI/fandhe-container/issues/2347)）。本書は決定ではなく判断材料である。決まるまで `start` は bind と sysfs 以外を `Unimplemented` で拒否したままにする（分離を緩めない。fail-closed）。

- 対象ビヘイビア: OCI-4（`config.json` の互換性）・SEC-1・SEC-2・CORE-5
- タスク: TASK-29 追補。関連: #1910（bind のみ受けるオーナー決定 2026-10-12）・#2020（sysfs を受ける。PR #2288）・#1609・#1651・#1657（暗黙の `/dev`）・PR #2344

## 現状

- 種類の分類は `crates/core/src/oci_runtime/sysfs_mount.rs` の `OciMountKind::of`（Bind / Sysfs / Other）。bind 側・sysfs 側・Landlock 側が共有する
- `BindMountSet::from_mounts`（`bind_mounts.rs`）は sysfs を読み飛ばし、それ以外の非 bind を `Unimplemented`（message: `mount type is not supported (only bind mounts)`）で拒否する。bind の宛先 `/proc`・`/sys`・`/dev` とその配下は `RESERVED_DESTINATIONS` で拒否する
- `start.rs` は `validate_bind_mounts` → `SysfsMountSpec::from_mounts` の順に fork 前で検証する。拒否は launcher の監査 sink に記録される（SEC-4）
- 暗黙に供給しているもの（`crates/core/src/dev_mounts.rs`・`tmpfs.rs`・`exec.rs` の `mount_proc`）:

| 宛先 | 供給方法 | 属性 |
| ---- | -------- | ---- |
| `/proc` | `mount_proc` が常に載せる | 別実装（`mounts[]` 非依存） |
| `/dev` | 暗黙の固定集合 | tmpfs・`nosuid`（`strictatime`） |
| `/dev/pts` | 暗黙の固定集合 | devpts・`nosuid,noexec` |
| `/dev/shm` | 暗黙の固定集合（`--ipc=host` では載せない） | tmpfs・`nosuid,nodev,noexec`・既定 64 MiB・`mode=1777` |
| `/sys` | `mounts[]` の sysfs を受けて供給（#2020） | sysfs |

- **`/dev/mqueue` と `/sys/fs/cgroup` は供給していない**。暗黙の固定集合に `/dev/mqueue` は入っていない
- Landlock は `mounts[]` が暗黙の固定集合と同じ宛先を指すと拒否する（`landlock/rules.rs`）
- 任意宛先の tmpfs は CLI の `--tmpfs` 用に `TmpfsMountSet`（`tmpfs.rs`）がある。`push` が宛先と件数（`TMPFS_MAX_MOUNTS`）を検証し、`nosuid`・`nodev` を常に付ける。`/proc`・`/sys` 配下と `/dev` 自身は拒否する

## 標準の既定 config との突き合わせ

出典: opencontainers/runc `libcontainer/specconv/example.go` の `Example()`（commit a75076b4a413f628c4b6aa4c5568b159aa128a56 で確認）。`ToRootless()` は `/sys` を rbind の bind へ置き換える（同ファイル 194 行付近。options の詳細は未確認）。runc は Apache-2.0 で NOTICE を持つ。下表は mounts の type と options を要約したもので、写した量は少ないが NOTICE への追記の要否はユーザー判断に回す（[licensing](../../.claude/rules/licensing.md)）。

| 宛先 | 既定 config（type / options） | 本ランタイムが載せるもの | 今の扱い | A での扱い |
| ---- | ----------------------------- | ------------------------ | -------- | ---------- |
| `/proc` | proc / なし | `mount_proc` | 拒否 | 受けて読み飛ばす |
| `/dev` | tmpfs / `nosuid,strictatime,mode=755,size=65536k` | tmpfs・`nosuid` | 拒否 | A-1 は `size` の差で外れうる。A-2 で判断 |
| `/dev/pts` | devpts / `nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5` | devpts・`nosuid,noexec` | 拒否 | 同上 |
| `/dev/shm` | tmpfs / `nosuid,noexec,nodev,mode=1777,size=65536k` | 一致（既定 64 MiB） | 拒否 | 受ける。`--ipc=host` では拒否を推奨 |
| `/dev/mqueue` | mqueue / `nosuid,noexec,nodev` | 供給なし | 拒否 | 拒否のまま（新規供給は別 issue） |
| `/sys` | sysfs / `nosuid,noexec,nodev,ro` | sysfs（#2020） | 受ける | 変わらない |
| `/sys/fs/cgroup` | cgroup / `nosuid,noexec,nodev,relatime,ro` | 供給なし | 拒否 | 拒否のまま（cgroup namespace と `ro` の設計が要る） |
| `/sys`（rootless 版） | bind（rbind） | — | `RESERVED_DESTINATIONS` で拒否 | A の範囲外 |

要点: A を字義どおり採っても、標準の既定 config は `/dev/mqueue` と `/sys/fs/cgroup` の 2 項目で拒否され続ける。互換性を目的にするなら、この 2 項目の扱いも同時に決める必要がある。

## 選択肢

### A. 一致する項目を供給済みとして受ける（Agent の推奨。決定ではない）

暗黙に供給済みの項目と一致する `mounts[]` の項目を、重複なく読み飛ばして受ける。「一致」の定義がオーナーの判断点である。

- **A-1 厳格一致**: type・宛先・options が完全一致。`mode=`・`size=` の差で標準の既定 config でも外れやすい
- **A-2 緩い一致**: type と宛先が一致し、options が供給済みの属性を緩めない集合に収まる。`nosuid`・`nodev`・`noexec`・`ro` は供給側より緩めない方向だけ受ける。`mode=`・`size=`・`gid=`・`ptmxmode=`・`newinstance`・`strictatime` は値を照合するか無視するかを決める。供給済みの属性より強い制限（例: `/dev` に `noexec`）を求める指定は、黙って満たさない起動をせず拒否する（SEC-1）
- `/dev/mqueue`・`/sys/fs/cgroup` は供給していないため A でも拒否のまま。供給するなら別 issue
- `--ipc=host`（`/dev/shm` を載せない構成）で `mounts[]` に `/dev/shm` があれば、載らないものを受けたことになるため拒否を推奨する
- 触る箇所: `OciMountKind::of` に「暗黙に供給済み」の分類を足す／`BindMountSet::from_mounts` が sysfs と同様に読み飛ばすか、`SysfsMountSpec` と同じ形の専用検証型で照合・監査する／`landlock/rules.rs` の重複拒否を分類で除外する／`MountDestination` の正規化を共有する／`/proc` は `mount_proc` の属性と照合する

### B. A に加えて任意宛先の tmpfs を受ける

必要な設計:

- 受ける options の許可集合、`size` の上限、`mode` の範囲、`uid=` / `gid=` の扱い
- 必ず `TmpfsMountSet::push` を通す（`tmpfs.rs` の契約）。`mount(2)` の data は型付きフィールドからのみ組み立て、利用者の options 文字列を連結しない
- `--tmpfs` との重複検査と件数上限（`TMPFS_MAX_MOUNTS`）の共有
- Landlock のルール（利用者指定の tmpfs は今は反映しない）
- memory cgroup の課金で上限が効くこと。bind・保護パスとの重なり検査の順序

### C. 拒否のまま確定する

標準ツールが作る `config.json` は利用者側で書き換える必要があり、OCI-4 の互換性は下がる。決定時は `Unimplemented` を `InvalidArgument`（静的な文言。config の値を含めない）へ替える案を併記する。利用者向け doc（[bind-mounts](../api/bind-mounts.md)）の更新が要る。

## 本書の時点で済んだこと・決定後に残る作業

- 済み: コード・doc の「見送り」の参照先を本書と #2347 に統一した（挙動は変えていない）
- 残り: オーナーが A〜C を決めて #2347 にコメントで記録する。A・B なら #54 配下に実装 issue を起票する。C ならコードの変更と利用者 doc の更新
- 受けない指定の拒否は今と同じく launcher の監査 sink に記録される（SEC-4）
