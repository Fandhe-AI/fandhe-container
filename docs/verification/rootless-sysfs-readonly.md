# rootless の /sys 読み取り専用 rbind の実機確認 手順書と結果記録（#2305）

rootless の `/sys`（ホストの `/sys` の読み取り専用 rbind）を実機で通し、user namespace の root から最上位の ro を `mount_setattr` で外せるかを測る手順と、結果記録の雛形。対応する ID は SEC-2・SEC-1・OCI-4・CORE-5・TASK-29 追補、REPAIR-3・REPAIR-12。関連 issue は [#2305](https://github.com/Fandhe-AI/fandhe-container/issues/2305)（本確認。人間担当）・#2020（`/sys` の sysfs 供給）・#2288（その事後監査）・#1621（分離系結合試験の実機実行）。

実行・結果の記録・成否の判定は人間が行う。Agent は実行しない（本ホストの AppArmor が非特権 user namespace を制限しており、緩和は root 権限の sysctl 変更になるため）。本書のコマンドは作成時に未実行である。

## 背景

- `crates/core/src/exec/sysfs.rs` の rootless 経路（`SysfsSource::HostReadOnlyRbind`。本番の `start` は常にここを通る）は、`open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` でホストの `/sys` を複製し、`mount_setattr` で再帰の `ro,noexec` を付けてから載せる
- 疑い（P2-1）: unshare した時点でホストの `/sys` が rw なら、複製に後から付けた ro には `MNT_LOCK_READONLY` が立たない見込みである。そうなら、user namespace の root（`CAP_SYS_ADMIN` あり・seccomp なし）は `mount_setattr` で ro を外せる。いまコンテナ内から外されないのは、SEC-1 の capability 削減と seccomp による `mount_setattr` の拒否（`ERRNO(EPERM)`）だけに頼っているためである
- これはカーネルソース（`fs/namespace.c` の `lock_mnt_tree`・`clone_mnt`・`mount_setattr_prepare`・`can_change_locked_flags`）との照合を済ませていない推論である。本書の測定で確かめる。ホステッド runner での初回の観測が出たため、`sysfs.rs` の docs は #2789 で観測結果に更新した（下記「`platform-ci` での継続観測」）。人間の実機（rootful 経路・別カーネル）の確認は引き続き必要で、本書の結果記録を置き換えない
- 測定は結合試験 `tests/sysfs_mount.rs` のシナリオ `ro-clear`（`escape-probe` feature 限定の試験用入口 `probe_clear_sysfs_readonly_for_test`）が行う。従来の `default` シナリオ（P2-3: rootless 実機での `sysfs_mount` の初回実行）と同じ 1 コマンドで両方の観測値が得られる

## 事前確認

ホスト名・アドレス・ユーザー名は記録しない。

- Linux 5.12 以上（`open_tree`・`move_mount`・`mount_setattr`）: `uname -r`
- 非 root で実行する（root では `ro-clear` は「該当なし」になる。問いは rbind 経路にしか無い）
- 非特権 user namespace を許可している。`sysctl kernel.apparmor_restrict_unprivileged_userns` が 1 だと `setgroups` で拒否される。設定の変更は人間が判断する。本書は sudo を呼ばない
- ホストの `/sys` が rw か: `findmnt -no OPTIONS /sys`（試験も `sysfs_mount: host /sys read-only=<bool>` を出力する）。ro だと、ro が外せなくても仮説（ロックされない）とは別の理由なので、結果の解釈が変わる

## 実行

```bash
cargo test -p fandhe-container-core --test sysfs_mount -- --ignored
```

子プロセスの待ちは `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1〜600 秒、既定 10）で変えられる。

### 期待する成功行

```text
sysfs_mount: mountinfo judgement self-check passed
sysfs_mount: host /sys read-only=<bool>
sysfs_mount: /sys is a read-only sysfs (nosuid,nodev,noexec), writes refused, reads allowed (root=false)
sysfs_mount: <N> /sys entries masked (firmware=<bool>, powercap=<bool>, thermal_throttle=<K>) (root=false)
sysfs_mount: ro-clear observation: sys_stack=<N>
sysfs_mount: ro-clear observation: top_opts="<options>"
sysfs_mount: ro-clear observation: ro_clear_errno=<0|errno>
sysfs_mount: ro-clear observation: ro_clear_defended_errno=1
sysfs_mount: ro-clear on /sys top mount (stack=<N>): undefended=<0|errno>, defended errno=1 (root=false)
```

`ro_clear_errno=0` のときは、続けて `top_ro_after_clear`・`children_after_clear`・`children_ro_after_clear`・`open_w_errno_after_clear:<path>` の観測行が出る（書き込みは一切しない。書き込み用の `open(2)` の errno だけ）。

### 何を測っているか

| 項目 | 意味 |
| -- | -- |
| `sys_stack` / `top_opts` | コンテナ内の `/sys` の行数（`readonly_paths` の rbind が最上位を入れ替えるため 2 以上のことがある）と、最上位のマウントの属性。測ったマウントの特定に使う |
| `ro_clear_errno`（防御なし） | `StageKind::CgroupJoin` のフック（pivot 後・capability 削減前。user namespace 内の全 capability あり・seccomp なし）で、最上位の ro を `mount_setattr(attr_clr=MOUNT_ATTR_RDONLY)` で外す試行の結果。**値は測定対象のため試験は assert しない** |
| `ro_clear_defended_errno`（防御あり） | 組み込みの制限段（capability 削減・seccomp）の通過後の同じ試行。`1`（`EPERM`）を要求する。本番の防御の性質であり、assert する |

防御なしの値が `precondition`・`unsupported`・`failed` のときは測定が行われていないため、試験は失敗する（false-green を避ける）。

## 予測値と出典（未確認）

カーネルソースの照合は本書の作成時に済んでいない。次は読みであり、実測で置き換える。

| 条件 | 防御なしの予測 |
| -- | -- |
| ホストの `/sys` が rw（unshare 時点で ro でない） | `0`（外せる） |
| ホストの `/sys` が最初から ro | `1`（`EPERM`。user namespace への複製でロックされるため） |
| 外せた後の `open_w_errno_after_clear` | root 所有の sysfs ファイルは `13`（`EACCES`。DAC）、`cgroup.procs` は `30`（`EROFS`。子マウントの ro は再帰して外していないため） |

最上位が sysfs 段の rbind か `readonly_paths` の rbind かにかかわらず、どちらも unshare の後にコンテナの mount namespace 内で作った複製で、ro はどちらも作った後に `mount_setattr` で付けるため、ロックの状態は同じになるはずである。この点も実測（`sys_stack`・`top_opts`）で確かめる。

## 結果記録（#2305 へ貼る）

| 項目 | 値 |
| -- | -- |
| 実施日 | |
| カーネル版（`uname -r`） | |
| `kernel.apparmor_restrict_unprivileged_userns` | |
| ホストの `/sys` が ro か（`host /sys read-only=`） | |
| `default` シナリオの結果（成功行 2 行、`open_w_errno:*`、子マウント数、覆いの件数） | |
| `sys_stack` / `top_opts` | |
| `ro_clear_errno`（防御なし） | |
| `ro_clear_defended_errno`（防御あり） | |
| 外せた場合: `top_ro_after_clear` / `children_ro_after_clear` / `open_w_errno_after_clear:*` | |
| 判定 | 外せた / 外せなかった（理由） |

コメントの雛形:

```text
#2305 の実機結果（rootless sysfs_mount）
- 環境: カーネル <版>、apparmor_restrict_unprivileged_userns=<値>、ホストの /sys ro=<bool>
- default シナリオ: <成功行、errno、子マウント数、覆いの件数>
- ro-clear: sys_stack=<N>、top_opts=<属性>、防御なし ro_clear_errno=<値>、防御あり ro_clear_defended_errno=<値>
- 判定: <外せた／外せなかった>
```

## `platform-ci` での継続観測（ホステッド runner）

`platform-ci (ubuntu-latest)` の `sysfs_mount の実行` ステップが PR・main ごとに `--ignored` で `sysfs_mount` を回し、成功行 3 本を照合して step summary に `kernel:` と観測行を出す（#2533・PR #2781）。`ro-clear` の `defended errno=1` の照合は、/sys の ro を保つ前提（`CAP_SYS_ADMIN` の削減・seccomp の mount 系の拒否）が崩れたことの検出に使われる（#2789）。

初回の観測値（PR #2781・run 40271388345。GitHub ホステッド runner。イメージ ubuntu-24.04 / 20261012.334.1。カーネル 6.17.0-1022-azure はイメージのリリースノートからの転記で、step summary の `kernel:` 行の確認は人間が行う）:

| 項目 | 値 |
| ---- | -- |
| host /sys read-only | false |
| sys_stack | 2 |
| top_opts | `ro,nosuid,nodev,noexec,relatime` |
| ro_clear_errno（防御なし） | 0 |
| top_ro_after_clear | false |
| children_after_clear | 19 |
| children_ro_after_clear | true |
| open_w_errno_after_clear | 4 パスとも 13（`EACCES`） |
| ro_clear_defended_errno（防御あり） | 1（`EPERM`） |

予測表との対応: rw ホストで「0（外せる）」の予測は一致した。`cgroup.procs` は予測の 30（`EROFS`）ではなく 13（`EACCES`）で、DAC の検査が先に効いたと見られる。これはホステッド runner の 1 回分の観測であり、本書の結果記録（人間の実機）を置き換えない。

## 外せた場合（`ro_clear_errno=0`）の起票文の下書き

> #2789 として起票済み（2026-10-26。ホステッド runner の観測に基づく）。以下は人間の実機で外せた場合の下書きとして残す。

条件 3 のとき、次の issue を起票する（起票は人間の承認を経る）。

- タイトル案: `docs(core): rootless の /sys の rbind の ro が user namespace の root から外せることを前提として明記し、防御ありの照合を恒久化する (SEC-2・SEC-1)`
- 背景: #2305 の実測で、rbind の最上位の ro が user namespace の root から外せた（カーネル `<版>`）。コンテナ内から外されないのは CapabilityDrop と seccomp による `mount_setattr` の拒否だけに依存している
- やること:
  1. `crates/core/src/exec/sysfs.rs` の docs に前提（`CAP_SYS_ADMIN` が無いこと・seccomp が mount 系を拒否すること）を明記する
  2. 防御ありの照合（`ro_clear_defended_errno=1`）を恒久的な試験として残し、試験用入口 `probe_clear_sysfs_readonly_for_test` の将来仕様（REPAIR-3）を確定する
  3. ro をロックさせる緩和策（属性を付けた後に下位の user namespace へ複製する等）を検討する（別判断）
- ID: SEC-2・SEC-1・OCI-4・CORE-5・TASK-29 追補
