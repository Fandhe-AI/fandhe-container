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
| bind 以外の種類（`proc`・`tmpfs` など。`/sys` の sysfs を除く） | 未対応（`UNIMPLEMENTED`） |

拒否する疑似 FS（mountinfo の fstype 名）は、`proc`・`sysfs`・`debugfs`・`tracefs`・`securityfs`・`cgroup`（v1）・`cgroup2`・`bpf`・`configfs`・`pstore`・`efivarfs`・`selinuxfs`・`smackfs`・`binfmt_misc`・`fusectl`・`resctrl`・`xenfs`・`nsfs`・`mqueue`・`devpts`・`binder`・`devtmpfs` の 22 種である。`devtmpfs`（ホストの `/dev`）は `f_type` が tmpfs と同じため、付け替えた木の mountinfo の fstype 名だけで判定する（SEC-1・#2129）。根拠と Linux v7.0 での出典（ファイル:行）と magic 値は `crates/core/src/exec/bind_mounts.rs` の `PSEUDO_FS_DENYLIST`。ext4・xfs・btrfs・tmpfs・overlayfs・NFS などデータを持つ通常の FS は受ける。

## `/sys` の sysfs（bind 以外に受ける種類）

OCI の既定 config にある `{"destination":"/sys","type":"sysfs"}` を受け、コンテナの `/sys` に**読み取り専用**の sysfs を供給する（SEC-2・OCI-4・TASK-29 追補・#2020）。

| 項目 | 内容 |
| ---- | ---- |
| 宛先 | `/sys` のみ。それ以外の宛先の sysfs は `INVALID_ARGUMENT` で拒否する |
| `source` | 無指定または `sysfs` のみ（ホストのパスとしては使わない） |
| 受けるオプション | `ro`・`nosuid`・`nodev`・`noexec`（いずれも常に付くので指定しても同じ） |
| 拒否するオプション | `rw`・`suid`・`dev`・`exec`（黙って読み取り専用に丸めず拒否する）、伝播系（`shared`・`private` など）、`defaults`・`rro` など許可集合外すべて |
| 件数 | sysfs は 1 件まで（2 件目は拒否） |
| 供給方式 | 初期 user namespace（ホスト root の試験経路）は新しい sysfs。user namespace の中（本番の `start` 経路）はホストの `/sys` を再帰 bind し、切り離したまま再帰で `ro`・`nosuid`・`nodev`・`noexec` を付けてから載せる |
| 事後検証 | 載せた後に mountinfo で、`/sys` が sysfs であり、`/sys` とその配下のすべてのマウントが `ro,nosuid,nodev,noexec` であることを確かめる。満たさなければ起動しない |

方式は結果ではなく user namespace で事前に決め、失敗しても別の方式へ縮退しない（想定外の拒否を隠さないため）。コンテナは自前の network namespace を持たないため、user namespace の中では新しい sysfs を載せられず、本番では常にホストの `/sys` の読み取り専用の再帰 bind になる。この場合、ホストの `/sys` とその配下のマウント（cgroup2・securityfs・bpf・debugfs・tracefs など）が読み取り専用で見える。`/sys` 配下の個別項目（`/sys/firmware` など）の覆いは #2014、`/sys` 配下への tmpfs・注入ファイルは #2233 で扱う。Landlock には `/sys` のルールを足さない（実効の権利は root と同じで、書き込みの禁止は VFS の `ro` が担う）。

Docker / runc との差: 本実装は方式を事前に決め、縮退しない。runc・moby が rootless で sysfs をどの条件で bind に差し替えるかは一次資料の確認が済んでおらず（未確認）、確定したら本節を更新する。

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
- bind と `/sys` の sysfs（下記）以外の `mounts[]` の種類は未対応
- 状態ルート（`StateStore::host_state_root`）と同一・祖先・子孫の `source` は start が拒否する（字句比較と `canonicalize` した実体の比較。SEC-1）。状態ルートを示せないストアでは bind つきの start を拒否する。適用の段も、固定した元に対して状態ルートとの重なりを毎回再検証する（元の属するマウントは fd の `mnt_id` で特定し、`rbind` のときだけ配下のマウントも照合する。保護対象と同じファイルシステム上でリンク数 2 以上の通常ファイルは状態ファイルへのハードリンクかもしれないため拒否する。start は状態ルート配下の通常ファイルのリンク数を上限つきで走査し、リンク数 2 以上のものがある〔または走査できない〕場合は、同じファイルシステム上のディレクトリ元も適用の段で拒否する）。元のマウント ID は `O_PATH` で固定した fd から取り、FIFO への差し替えでもブロックしない（REPAIR-5）。mountinfo は読み取りバイト数と行数に上限を設け、超過は構造化エラーで拒否する
- 疑似 FS の拒否は拒否リストの方式のため、リストにない未知の疑似 FS は受ける。許可リスト方式にすると zfs・ceph・9p・virtiofs などを壊すため採らず、リストの見直しはカーネルの版を上げるときに行う（SEC-1・#2129）。実機での確認は #1916
- FUSE（`fuse`・`fuseblk`・`fuse.lxcfs` などの派生名）と overlayfs は、データを持つ FS として受ける。overlayfs の下層（`lowerdir`）や FUSE デーモンが見せる中身、別の superblock 経由で状態ルートなどと同じ実体を見せる別名は検出しない。FUSE の中身はデーモンの資格情報の範囲を超えず、ホストの mount namespace に overlayfs を作るには root が要るためである。今後の方向は mountinfo の `lowerdir=`・`upperdir=` の照合（SEC-1・#2129）
- start の後に状態ルートが移動・改名・差し替えられた場合、適用の段（restart を含む）は記録したホスト側パスを辿り直し、固定した実体と一致しなければ `FAILED_PRECONDITION` で拒否する（SEC-1・#2129）。残余は、祖先の bind mount を別の経路から改名するなど、パスが同じ inode に解決したままファイルシステム内パスだけが変わる場合で、mountinfo の `(dev, path)` は適用時に作り直さない
- restart でも、起動時と同じ bind の集合を適用する

## 拒否の記録

分離違反にあたる拒否（設定の検証・launcher 側の重なり検査・適用の段）は、監査ログに記録する（SEC-4）。記録に載せるのはコンテナ内の `destination` だけで、ホスト側の `source` は載せない。
