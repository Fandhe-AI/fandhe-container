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

`bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・`rprivate`・`rslave`。後に書いた指定が勝つ（`ro` と `rw`、`noexec` と `exec`）。`rbind` のときだけ再帰的に bind する。

`rslave` は、ホストの peer group から受けるだけの slave で付ける（ホストで後からその元の下にマウントされた内容がコンテナ内に見える。コンテナからホストへは伝播しない）。元が属するホスト側のマウントが shared か slave である必要があり、private なら `start` は rootfs に触れる前に `FAILED_PRECONDITION` で失敗する（黙って private で載せない）。`private`・`rprivate` との併記は `INVALID_ARGUMENT`。CRI の HostToContainer はこの指定へ変換される（#2669・CRI-2・OCI-4）。

## 拒否するもの

| 指定 | 理由 |
| ---- | ---- |
| `suid`・`dev` | 必須の制限を外すため（SEC-1） |
| `shared`・`rshared`・`slave`・`unbindable`・`runbindable` | コンテナからホストへ伝播させない（ホストへのマウントの漏れを防ぐ）。user namespace の中ではホストの shared マウントが slave に格下げされるため、`rshared` は原理的に成り立たない（`docs/design/mount-propagation.md`）。`slave`（非再帰）は `rbind` で配下も slave になり意味が食い違うため受けない |
| `rslave` と `private`・`rprivate` の併記 | 意味が曖昧なため（#2669。`bind` と `rbind` の併記と同じ扱い） |
| 上記以外のオプション（`defaults`・`rro`・`idmap` を含む） | 未知の指定は fail-closed |
| `bind` と `rbind` の併記 | 意味が曖昧なため |
| 相対パス・`..`・`.`・空要素・`\`・NUL を含む `source`、`source: "/"` | 絶対パスの正規形のみ受ける |
| bundle の rootfs・bundle ディレクトリと同一、またはその祖先の `source` | コンテナが自身の rootfs を書き換える経路を作らない |
| 状態ルート（状態の保存先）と同一・祖先・子孫の `source` | `state.json` 等の改変を防ぐ。rootfs・bundle の配下の `source` は受ける（#2063・SEC-1・OCI-4） |
| procfs・sysfs・cgroup などの疑似 FS 上の `source`（`rbind` の配下に疑似 FS のマウントがある場合を含む） | ホストのプロセス・カーネルの情報の露出と、`linux.maskedPaths` / `readonlyPaths` の迂回を防ぐ。適用の段が固定した元の `fstatfs` の `f_type` と、付け替えた木の mountinfo の fstype で判定する（SEC-1・#2098・#2065） |
| `/proc`・`/sys`・`/dev` とその配下の `destination` | 暗黙のマウントと固定の保護パスがあるため |
| bind 同士で同一・入れ子の `destination` | 子の宛先がホストのディレクトリになるのを防ぐ |
| `linux.readonlyPaths` / `maskedPaths` と重なる `destination` | 保護パスを覆えないようにする |
| bind 以外の種類（`proc`・`tmpfs` など。`/sys` の sysfs を除く） | 未対応（`UNIMPLEMENTED`。受けるかは [#2347](https://github.com/Fandhe-AI/fandhe-container/issues/2347) で判断待ち。[判断記録](../design/oci-mounts-implicit-entries.md)） |

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

方式は結果ではなく user namespace で事前に決め、失敗しても別の方式へ縮退しない（想定外の拒否を隠さないため）。コンテナは自前の network namespace を持たないため、user namespace の中では新しい sysfs を載せられず、本番では常にホストの `/sys` の読み取り専用の再帰 bind になる。この場合、ホストの `/sys` とその配下のマウント（cgroup2・securityfs・bpf・debugfs・tracefs など）が読み取り専用で見える。sysfs を供給する構成では、`/sys/devices/virtual/powercap`・`/sys/firmware`・`/sys/devices/system/cpu/cpuN/thermal_throttle`（`possible` が示す CPU のうち存在するもの。上限 8192 件。存在しないものは飛ばす）を読み取り専用の空 tmpfs で覆う（moby の既定の覆いと同じ集合。#2014）。sysfs を供給しない構成では覆わない。debugfs・tracefs・securityfs・bpf 等の擬似 FS は覆わない（moby も覆わず、rootless ではコンテナ内 root がホストの非特権 UID に写り、すべて読み取り専用のため。範囲を広げるかはオーナー判断待ち）。`/sys` 配下への tmpfs・注入ファイルは #2233 で扱う。Landlock には `/sys` のルールを足さない（実効の権利は root と同じで、書き込みの禁止は VFS の `ro` が担う）。

Docker / runc との差: 本実装は方式を事前に決め、縮退しない。runc・moby が rootless で sysfs をどの条件で bind に差し替えるかは一次資料の確認が済んでおらず（未確認）、確定したら本節を更新する。

## Docker / runc と異なる既定

- `nosuid` と `nodev` を常に付ける。外せない
- 伝播は private が既定。`rslave` だけ受け、ホスト側の元が private なら runc と違って起動を拒否する（runc は private のまま載せる）
- `source` は絶対パスのみ（bundle 相対は不可）
- 疑似 FS（procfs・sysfs・cgroup など）上の `source` は拒否する（runc は受ける）
- ホストの `/dev`（devtmpfs）配下の `source` は拒否する（runc は受ける。SEC-1・#2129）
- `source` に symlink が含まれるときは拒否する（辿らない）。存在しない `source` は作らずに拒否する
- `destination` の経路に symlink があるときは拒否する。`destination` のディレクトリは rootfs の中に作る
- rootless（user namespace を使う）の起動経路だけが対象。rootful では受けない

## 制約と未対応

- `rslave` でホストから伝播してきたマウントには、ホスト側のマウントの属性とカーネルのロックが付き、こちらの `nosuid`・`nodev`・`ro`・`noexec` は付かない。疑似 FS と状態ルートの検査も付け替えた時点の 1 回だけである（HostToContainer の意味に内在する。引き起こせるのはホスト側の特権主体だけ。#2669）。実機での伝播の確認は [verification](../verification/bind-rslave-propagation.md)
- `ro` の bind は、root が書き込み可能な構成では Landlock が書き込み制限を保証できないため、起動前に拒否される。`root.readonly=true`（start が受け、pivot 直後に rootfs を読み取り専用にする。#2767。`create --read-only` でも同じ実効値になる。#2828）の構成では root に書き込み権が無いため `ro` で適用される。書き込み可能な root での解消は #1917
- bind と `/sys` の sysfs（下記）以外の `mounts[]` の種類は未対応
- 状態ルート（`StateStore::host_state_root`）と同一・祖先・子孫の `source` は start が拒否する（字句比較と `canonicalize` した実体の比較。SEC-1）。状態ルートを示せないストアでは bind つきの start を拒否する。適用の段も、固定した元に対して状態ルートとの重なりを毎回再検証する（元の属するマウントは fd の `mnt_id` で特定し、`rbind` のときだけ配下のマウントも照合する。保護対象と同じファイルシステム上でリンク数 2 以上の通常ファイルは状態ファイルへのハードリンクかもしれないため拒否する。start は状態ルート配下の通常ファイルのリンク数を上限つきで走査し、リンク数 2 以上のものがある〔または走査できない〕場合は、同じファイルシステム上のディレクトリ元も適用の段で拒否する）。元のマウント ID は `O_PATH` で固定した fd から取り、FIFO への差し替えでもブロックしない（REPAIR-5）。mountinfo は読み取りバイト数と行数に上限を設け、超過は構造化エラーで拒否する
- 疑似 FS の拒否は拒否リストの方式のため、リストにない未知の疑似 FS は受ける。許可リスト方式にすると zfs・ceph・9p・virtiofs などを壊すため採らず、リストの見直しはカーネルの版を上げるときに行う（SEC-1・#2129）。実機での確認は #1916
- FUSE（`fuse`・`fuseblk`・`fuse.lxcfs` などの派生名）はデータを持つ FS として受ける。FUSE デーモンが見せる中身は検出しない。中身はデーモンの資格情報の範囲を超えないためである
- overlayfs 上の元は、付け替えた木の mountinfo の super_options（`lowerdir`・`lowerdir+`・`datadir+`・`upperdir`・`workdir`）の層を `/` から辿り、rootfs・状態ルートと同一・祖先・子孫でないことを inode で照合する（`rbind` では配下の overlay も対象。SEC-1・#2166）。次の場合は `FAILED_PRECONDITION` で拒否する。(1) 層を現在の mount namespace で解決できない（相対パス・消えた層・symlink・ディレクトリでない層）。たとえば Docker のコンテナ内のように `/` が overlay で下層が見えない環境では、その overlay 上の元を拒否する。(2) super_options を解析できない、または上限（層 500・1 層 4096 バイト・1 件の bind で合計 4096 層）を超える。(3) 層が別の overlay の上にある（入れ子。再帰的には照合しない）。層は inode の鎖に加え、層の属するマウントの ID から求めた mountinfo の `(dev, path)` でも保護対象・子マウントと照合する（bind mount を挟んだ祖先関係の検出）。(4) 上の照合に通っても、overlay の元は拒否する。開き直した層のパスは overlay が保持する実際の backing directory と同一とは限らず（作成後に lowerdir のパスを別の bind mount で覆う等）、同一性を保証できる識別情報が無いため fail-closed とする。違反の記録には層のパスを載せない
- 保護対象（状態ルート・rootfs・bundle）の側が overlayfs の上にある場合は、逆方向の別名も照合する（SEC-1・#2317）。overlay と下層の FS は `st_dev` が異なるため、元が層の実パス（下層の FS 上）を指しても、保護対象の dev との比較では一致しない。適用の時点の mountinfo で保護対象の dev の行が `overlay` なら、その super_options の層を `/` から辿って保護対象に加え、元が層と同一・祖先・子孫であれば宛先を作る前に拒否する。状態ルート由来の層は `bind_source_reaches_state_root`、rootfs・bundle 由来の層は同一・祖先・子孫のすべてを `bind_source_contains_rootfs` とする（overlay の内側の対応〔redirect_dir・metacopy〕は信頼できず、配下のどこが rootfs の祖先に当たるかを決められないため。層は実行基盤の内部の backing storage で、配下を元にできなくても実害は小さい）。層は inode の鎖に加え、層の属するマウントの `(dev, path)` でも照合し（bind mount を挟んだ別名と、`rbind` で一緒に公開される子マウントを検出）、状態ルートのハードリンクの検査にも層の dev を加える。層を解決できない・解析できない・上限超過・入れ子・同じ dev の行の食い違いは `FAILED_PRECONDITION`。**挙動の変化**: Docker のコンテナ内のように保護対象が `/` の overlay の上にあり下層が見えない環境では、層を解決できないため、volume を元にした bind を含めすべての bind mount が `FAILED_PRECONDITION` で拒否される（緩和は後続の課題）。残余: 開き直した層は overlay の実際の backing directory と同一とは限らない（上の (4) と同じ）が、逆方向では一律拒否にしない（一律拒否にすると保護対象が overlay 上にある限りどの bind も拒否になり、層を解決できる環境の無関係な元まで止まるため）。照合は検出できる範囲に限る。違反の記録には層のパスを載せない 保護対象の dev の行が適用の時点の mountinfo に無い場合は、保護対象の FS の種別を確認できず照合が素通りするため、状態ルート・rootfs・bundle のいずれでも `FAILED_PRECONDITION` で拒否する（#2536。mountinfo の行数上限は解析より先に効かせる）。**既知の残余**: fstype が `overlay` の完全一致でない積層 FS（`fuse.fuse-overlayfs` など）が保護対象の下にあると、super_options に層のパスが載らず層を解決できないため、逆方向の照合は効かない（FUSE は上の項目のとおりデータを持つ FS として受ける）。実機の overlayfs での確認は `crates/core/src/exec/bind_mounts.rs` の `sec1_2536_protected_root_on_real_overlay`（実機前提・`AGENTS.md`「実機前提テスト」）で行う
- 判断待ち（#2536。オーナー判断。判断が出るまで #2536 は close しない）: 逆方向で開き直した層が overlay の実際の backing directory と同一とは限らない残余を受け入れるか。選択肢は (1) 受け入れる（現状。検出できる範囲だけを照合し、無関係な元は通す）、(2) 一律拒否（保護対象が overlay 上にある限りすべての bind が `FAILED_PRECONDITION`。残余は無くなるが、層を解決できる環境の無関係な元まで止まる）。現状の挙動は (1) だが、判断済みではない
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
