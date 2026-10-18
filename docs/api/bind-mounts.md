# bind mount（`config.json` の `mounts[]`）

Linux の fandhe-container は、OCI `config.json` の `mounts[]` に書いた bind mount を、コンテナの起動時（`start`）に適用する（TASK-29 追補・#1915・OCI-4・CORE-2・CORE-5・SEC-1。#1907・#1910 のオーナー決定）。本書は利用者向けの書き方と、Docker / runc と異なる既定をまとめる。受け入れ規則の SSOT はコード（`crates/core/src/oci_runtime/bind_mounts.rs` の module doc）で、本書はそこへの案内である。

## 書き方

```json
{
  "mounts": [
    {
      "destination": "/data",
      "type": "bind",
      "source": "/srv/data",
      "options": ["rbind", "rw"]
    }
  ]
}
```

- `source` はホストの絶対パス。`destination` はコンテナ内の絶対パス
- 種類は `type: "bind"`、または `options` に `bind` / `rbind` を含める
- 検証に失敗した `start` は、子プロセスを作らず、状態を Created のまま構造化エラー（`code`・`message`。ERR-2）で終了する

## 受けるオプション

`bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・`rprivate`。後に書いた指定が勝つ（`ro` と `rw`、`noexec` と `exec`）。`rbind` のときだけ再帰的に bind する。

## 拒否するもの

| 指定 | 理由 |
| ---- | ---- |
| `suid`・`dev` | 必須の制限を外すため（SEC-1） |
| `shared`・`rshared`・`slave`・`rslave`・`unbindable`・`runbindable` | 伝播は常に private（ホストへのマウントの漏れを防ぐ） |
| 上記以外のオプション（`defaults`・`rro`・`idmap` を含む） | 未知の指定は fail-closed |
| `bind` と `rbind` の併記 | 意味が曖昧なため |
| 相対パス・`..`・`.`・空要素・`\`・NUL を含む `source`、`source: "/"` | 絶対パスの正規形のみ受ける |
| bundle の rootfs・bundle ディレクトリと同一、またはその祖先の `source` | コンテナが自身の rootfs を書き換える経路を作らない |
| 状態ルート（状態の保存先）と同一・祖先・子孫の `source` | `state.json` 等の改変を防ぐ。rootfs・bundle の配下の `source` は受ける（#2063・SEC-1・OCI-4） |
| procfs・sysfs・cgroup などの疑似 FS 上の `source`（`rbind` の配下に疑似 FS のマウントがある場合を含む） | ホストのプロセス・カーネルの情報の露出と、`linux.maskedPaths` / `readonlyPaths` の迂回を防ぐ。適用の段が固定した元の `fstatfs` の `f_type` と、付け替えた木の mountinfo の fstype で判定する（SEC-1・#2098・#2065） |
| `/proc`・`/sys`・`/dev` とその配下の `destination` | 暗黙のマウントと固定の保護パスがあるため |
| bind 同士で同一・入れ子の `destination` | 子の宛先がホストのディレクトリになるのを防ぐ |
| `linux.readonlyPaths` / `maskedPaths` と重なる `destination` | 保護パスを覆えないようにする |
| bind 以外の種類（`proc`・`tmpfs` など） | 未対応（`UNIMPLEMENTED`） |

拒否する疑似 FS（mountinfo の fstype 名）は、`proc`・`sysfs`・`debugfs`・`tracefs`・`securityfs`・`cgroup`（v1）・`cgroup2`・`bpf`・`configfs`・`pstore`・`efivarfs`・`selinuxfs`・`smackfs`・`binfmt_misc`・`fusectl`・`resctrl`・`xenfs`・`nsfs`・`mqueue`・`devpts`・`binder`・`devtmpfs` の 22 種である。`devtmpfs`（ホストの `/dev`）は `f_type` が tmpfs と同じため、付け替えた木の mountinfo の fstype 名だけで判定する（SEC-1・#2129）。根拠と Linux v7.0 での出典（ファイル:行）と magic 値は `crates/core/src/exec/bind_mounts.rs` の `PSEUDO_FS_DENYLIST`。ext4・xfs・btrfs・tmpfs・overlayfs・NFS などデータを持つ通常の FS は受ける。

## Docker / runc と異なる既定

- `nosuid` と `nodev` を常に付ける。外せない
- 伝播は常に private
- `source` は絶対パスのみ（bundle 相対は不可）
- 疑似 FS（procfs・sysfs・cgroup など）上の `source` は拒否する（runc は受ける）
- ホストの `/dev`（devtmpfs）配下の `source` は拒否する（runc は受ける。SEC-1・#2129）
- `source` に symlink が含まれるときは拒否する（辿らない）。存在しない `source` は作らずに拒否する
- `destination` の経路に symlink があるときは拒否する。`destination` のディレクトリは rootfs の中に作る
- rootless（user namespace を使う）の起動経路だけが対象。rootful では受けない

## 制約と未対応

- `ro` の bind は、root が書き込み可能な構成では Landlock が書き込み制限を保証できないため、起動前に拒否される。解消は #1917
- bind 以外の `mounts[]` の種類は未対応
- 状態ルート（`StateStore::host_state_root`）と同一・祖先・子孫の `source` は start が拒否する（字句比較と `canonicalize` した実体の比較。SEC-1）。状態ルートを示せないストアでは bind つきの start を拒否する。適用の段も、固定した元に対して状態ルートとの重なりを毎回再検証する（元の属するマウントは fd の `mnt_id` で特定し、`rbind` のときだけ配下のマウントも照合する。保護対象と同じファイルシステム上でリンク数 2 以上の通常ファイルは状態ファイルへのハードリンクかもしれないため拒否する。start は状態ルート配下の通常ファイルのリンク数を上限つきで走査し、リンク数 2 以上のものがある〔または走査できない〕場合は、同じファイルシステム上のディレクトリ元も適用の段で拒否する）。元のマウント ID は `O_PATH` で固定した fd から取り、FIFO への差し替えでもブロックしない（REPAIR-5）。mountinfo は読み取りバイト数と行数に上限を設け、超過は構造化エラーで拒否する
- 疑似 FS の拒否は拒否リストの方式のため、リストにない未知の疑似 FS は受ける。許可リスト方式にすると zfs・ceph・9p・virtiofs などを壊すため採らず、リストの見直しはカーネルの版を上げるときに行う（SEC-1・#2129）。実機での確認は #1916
- FUSE（`fuse`・`fuseblk`・`fuse.lxcfs` などの派生名）はデータを持つ FS として受ける。FUSE デーモンが見せる中身は検出しない。中身はデーモンの資格情報の範囲を超えないためである
- overlayfs 上の元は、付け替えた木の mountinfo の super_options（`lowerdir`・`lowerdir+`・`datadir+`・`upperdir`・`workdir`）の層を `/` から辿り、rootfs・状態ルートと同一・祖先・子孫でないことを inode で照合する（`rbind` では配下の overlay も対象。SEC-1・#2166）。次の場合は `FAILED_PRECONDITION` で拒否する。(1) 層を現在の mount namespace で解決できない（相対パス・消えた層・symlink・ディレクトリでない層）。たとえば Docker のコンテナ内のように `/` が overlay で下層が見えない環境では、その overlay 上の元を拒否する。(2) super_options を解析できない、または上限（層 500・1 層 4096 バイト・1 件の bind で合計 4096 層）を超える。(3) 層が別の overlay の上にある（入れ子。再帰的には照合しない）。層は inode の鎖に加え、層の属するマウントの ID から求めた mountinfo の `(dev, path)` でも保護対象・子マウントと照合する（bind mount を挟んだ祖先関係の検出）。(4) 上の照合に通っても、overlay の元は拒否する。開き直した層のパスは overlay が保持する実際の backing directory と同一とは限らず（作成後に lowerdir のパスを別の bind mount で覆う等）、同一性を保証できる識別情報が無いため fail-closed とする。違反の記録には層のパスを載せない
- start の後に状態ルートが移動・改名・差し替えられた場合、適用の段（restart を含む）は記録したホスト側パスを辿り直し、固定した実体と一致しなければ `FAILED_PRECONDITION` で拒否する（SEC-1・#2129）。mountinfo の `(dev, path)`（状態ルートと、その配下の子マウント）も適用の時点で作り直し、start の記録と作り直した値の両方で照合する。作り直せない、または dev が記録と食い違う場合は `FAILED_PRECONDITION` で拒否する（#2166）
- restart でも、起動時と同じ bind の集合を適用する

## 疑似 FS の拒否リストの見直し（カーネルの版を上げるとき）

拒否リストの SSOT は `crates/core/src/exec/bind_mounts.rs` の `PSEUDO_FS_DENYLIST` の doc で、本節は更新の手順書である（SEC-1・#2166）。カーネルの版を上げる（サポートする最低版や確認済みの版を変える）たびに次を行う。

1. 新旧の版の `include/uapi/linux/magic.h` の差分から、新しい `*_MAGIC` を拾う
2. `struct file_system_type` の `.name` を grep し、既存の 22 種の出典（ファイル:行）が動いていないか確かめる。uapi に無い `configfs`・`mqueue`・`fusectl` はソースで確かめる
3. 新しく見つかった FS を「拒否する」「受ける」に分け、理由をつけて `PSEUDO_FS_DENYLIST` の doc に記録する。ホストのプロセス・カーネル・LSM・cgroup・名前空間などの情報や制御口を見せる FS は拒否し、データを持つ FS は受ける
4. overlayfs の super_options の書式（`fs/overlayfs/params.c` の `ovl_show_options`、`include/linux/seq_file.h` の `seq_show_option` のエスケープ、`fs/overlayfs/params.h` の `OVL_MAX_STACK`）が変わっていないか確かめ、`crates/core/src/exec/overlay_layers.rs` の module doc の出典と上限を更新する
5. 表の照合テスト（`sec1_2098_denylist_table_is_exact` など）と、必要なら `sys` の magic 定数を同じ変更で更新する

受ける（拒否しない）と判断済みの fstype は、データを持つ通常の FS である。`ext4`・`xfs`・`btrfs`・`tmpfs`・`overlay`・NFS・`zfs`・`ceph`・`9p`・`virtiofs`・FUSE（`fuse`・`fuseblk`・`fuse.<subtype>`）。Linux v7.0 での全件の grep 結果は未作成のため、版を上げる際に手順 2 で作る。

## 拒否の記録

分離違反にあたる拒否（設定の検証・launcher 側の重なり検査・適用の段）は、監査ログに記録する（SEC-4）。記録に載せるのはコンテナ内の `destination` だけで、ホスト側の `source` は載せない。
