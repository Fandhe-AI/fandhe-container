# launch への封印複製（B'）を適用しない判断（判断記録）

稼働中コンテナへの exec の子で使っている「エントリポイント本体を封印した memfd に複製して実行する方式（B'）」を、launch 経路（`EntrypointSource::Pinned`）へ適用するかを再検討した結果を残す（CORE-5・CORE-7〜9・SUP-6・SEC-1・REPAIR-3・TASK-163 追補。#2687）。

> **位置づけ**: 本実装の判断（既存の設計判断の維持）。launch は従来どおり `EntrypointSource::Pinned`（照合した fd をそのまま `execveat` する方式 A）のままとし、挙動は変えない。新たなオーナー承認は得ていない。関連: #1529・#1530・#1531（B' の設計と exec への組み込み）・#2686（方式 B。ランタイム自身の封印複製）・#2631。

## 現状

| 経路 | 方式 | 実装 |
| ---- | ---- | ---- |
| 稼働中コンテナへの exec | 条件付き切り替え（オーナー判断 2026-10-09）。Linux 6.14 以上かつ有効な LSM が許可リストに収まるなら B'、それ以外は A | `crates/core/src/exec/sealed_copy.rs`・`entrypoint_mode.rs`・`EntrypointSource::Switchable` |
| launch（pivot 直後のエントリポイント） | A のみ（`EntrypointSource::Pinned`） | `crates/core/src/exec/process.rs` |

B' が使えるのは Linux 6.14 以上で、有効な LSM が許可リストに収まるホストだけである。Ubuntu 既定（`lockdown,capability,landlock,yama,apparmor,ima,evm`）は `lsm_apparmor`、Fedora 等は `lsm_selinux` で現行方式（A）に落ちる。

## 論点

### (a) 脅威モデル

- launch は pivot 直後で、コンテナ内に他のプロセスがいない。照合から `execveat` までの間にコンテナ内から書き換える主体はない
- 残る主体は、ホスト側のプロセスと、書き込み可能な bind mount / named volume を共有する別のコンテナである。後者はエントリポイントを launch 中に書き換えうる。「書き換える主体がない」はコンテナ内に限った話で、無条件の前提として扱わない
- B' はエントリポイント本体を封印した同一のバイト列で解析・照合・実行するため、共有ボリューム経由の本体の書き換え（シェバン・`PT_INTERP` の文字列の差し替えを含む）には効く。B' で閉じないのは、インタープリタのパスの差し替えと、インタープリタ自身の内容の書き換えだけである（`interpreter.rs` の方式比較表と同じ区別）。この残余に対する筋は、共有ボリューム上のインタープリタ・エントリポイントを書き換え可能にしないマウント・Landlock の方針と、方式 B（#2686）である

### (b) メモリ

ローカルのマイクロベンチ（下記「実測」）では、同じ実行ファイルを 50 本常駐させたとき、B 相当（memfd に複製して実行）は A 相当（直接 `execve`）に対して次のとおり増えた。

| 対象 | 系統 | PSS 合計 | Rss 合計 | Pss_Shmem 合計 | `/proc/meminfo` の Shmem 増分 |
| ---- | ---- | -------- | -------- | -------------- | ----------------------------- |
| python3.14（7.1 MiB） | A | 156 MiB | 478 MiB | 0 MiB | 約 0 MiB（-1〜51 の揺れ。他プロセスの影響） |
| python3.14（7.1 MiB） | B' 相当 | 343 MiB | 479 MiB | 190 MiB | 356〜370 MiB |
| 上記 + 末尾 100 MiB の詰め物（107 MiB） | A | 157 MiB | 479 MiB | 3 MiB | 0 MiB |
| 上記 + 末尾 100 MiB の詰め物（107 MiB） | B' 相当 | 343 MiB | 479 MiB | 190 MiB | 5384 MiB |

- A は page cache を共有し、触れたページだけが常駐する。B は 1 本ごとに private な shmem を `st_size` ぶん確保し、swap 以外では回収されない
- python3.14 の 50 本では PSS が約 2.2 倍（+187 MiB）、Shmem が約 360 MiB 増える
- 大きいバイナリでは、マップされないページは PSS に出ないため PSS 合計は変わらないが、Shmem は 50 本で 5.3 GiB（107 MiB × 50）増える。CORE-9 の主指標（PSS 合計）だけでは過小評価になるため、評価には Shmem と cgroup の `memory.current` を併用する
- memfd は子 cgroup の `memory.max` に計上される。利用者が見る使用可能量も減る

### (c) 機能面の代償

- 長寿命の PID 1 の `/proc/self/exe`（`/proc/1/exe`）が `/memfd:fandhe-exec-entrypoint (deleted)` になる。これに依存する処理（JVM の `JAVA_HOME` 推定、Go の `os.Executable`、自己 re-exec、監視・調査ツール）が壊れうる。exec の子は短命なものが多いが、launch の対象は PID 1 そのものである
- 256 MiB（`MAX_SEALED_COPY_BYTES`）を超えるエントリポイントは launch できなくなる。上限を上げるほどメモリが増える

### (d) 実効範囲

B' が効くのは 6.14 以上かつ許可リストの LSM のホストだけで、主要ディストリの既定（AppArmor・SELinux・IMA）では現行方式に落ちる。適用しても多くのホストでは効かず、効くホストではメモリと互換性の代償を払う。

## 判断

launch には B' を適用しない。`EntrypointSource::Pinned` を維持する。実装と結合試験は不要。

理由:

1. 封じたい競合の主体が launch の時点ではコンテナ内におらず、共有ボリューム経由の本体の書き換えは B' で閉じるものの、B' で閉じない残余（共有ボリューム上のインタープリタのパス・内容の書き換え）が主要なリスクとして残る
2. PID 1 の常駐メモリ（CORE-7〜9）と `/proc/self/exe` の互換性を、効かないホストが多い方式のために払う釣り合いがない
3. 閉じ方の本筋は方式 B（#2686）とマウント・Landlock の方針である

## 再検討の条件

- #2686（方式 B）の結論が出たとき
- 共有ボリューム上のエントリポイント本体への書き換えを脅威として扱うと決めたとき（その場合も先にマウント・Landlock の方針で対処する）
- IMA の memfd に対する挙動を一次情報で確認できたとき
- 利用者から opt-in の要望が出たとき（有効化するフラグの案は示さない。採否は別途決める）

## 実測

ローカルのマイクロベンチであり、CORE-9 の正式な計測（TASK-49・TASK-50 の `scripts/bench/concurrent_50_memory.sh`）ではない。非 root・自分が起動した子プロセスのみを対象にした。本番の rootfs（overlay の lower を共有する場合の page cache の共有）での確認は正式な計測に委ねる。

- 環境: kernel 7.0.0-34、LSM は `lockdown,capability,landlock,yama,apparmor,ima,evm`、`vm.memfd_noexec=0`、10 コア、総メモリ約 28 GiB
- 対象: `/usr/bin/python3.14` を `-c 'import time; time.sleep(40)'` で 50 本常駐させ、起動 8 秒後に各子の `/proc/<pid>/smaps_rollup` の `Pss`・`Rss`・`Pss_Shmem` を合計し、`/proc/meminfo` の `Shmem` の起動前後の差を採った。大きいバイナリは同ファイルの末尾に 100 MiB のゼロを足したコピー（ELF ローダは末尾を無視する）
- A（現行 launch 相当）: 子で対象を直接 `os.execv`
- B（B' 相当）: 子で `os.memfd_create` → 対象の全バイトを書き込み → `/proc/self/fd/N` を `O_RDONLY` で開き直し、書き込み用 fd を閉じて、開き直した fd の `/proc/self/fd/M` を `os.execv`（`ETXTBSY` を避ける。封印（seal）自体は計測に影響しないため付けていない）
- 各系統を繰り返して再現性を確認した（python3.14 は各 2〜3 回で PSS・Rss は同値、大きいバイナリは各 1 回）。計測後の子は SIGKILL して回収し、残りがないことを `pgrep` で確認した
- 限界: 揺れの大きい Shmem の A 側の値は、他プロセスの shmem の増減を含む。B 側との差は桁が違うため結論には影響しない
