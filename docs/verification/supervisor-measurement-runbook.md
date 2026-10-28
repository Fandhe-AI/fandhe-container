# 監視プロセス系の実機計測 実行手順書

人間担当の実機計測 #499（SUP-5）・#485（SUP-2）・#491（SUP-3）・#219（CORE-9・SUP-1）で、そのまま使える実行手順。計測スクリプトの起動行は supervisor の bin の契約に合わせ済み（#1820）。実行と合否判定は人間が行う。スクリプトは合否を出さない箇所があり、結果欄に Agent が実測値を埋めてはならない。

- 対応: TASK-158・TASK-160・TASK-162・TASK-50（追補）・MS-9（Phase 8）
- ビヘイビア: SUP-1・SUP-2・SUP-3・SUP-5・CORE-9・REPAIR-3（未実装を実装済みと装わない）・REPAIR-5（期限）・REPAIR-12
- 起動契約の根拠: `crates/supervisor/src/start_contract.rs`・`start_entry.rs`・`crates/cli/src/commands/supervisor_start.rs`（#1717・#1819）

## 現状の制約（必読）

| 項目 | 内容 |
| ---- | ---- |
| restart の再 launch（#491） | supervisor の再 launch は本番 launcher の単一スレッド要求で拒否される（#2043）。#2043 が入るまで `make restart-latency` は再起動未観測（終了コード 1）になり数値は出ない。`make supervisor-independence` の `--check-restart` も同じ |
| 計測の権限（#485・#219） | supervisor は入口で `PR_SET_DUMPABLE=0` にする（SUP-14）。同じ利用者の非 root からも `/proc/<pid>/exe`・`smaps_rollup` を読めない。一方 supervisor は rootful 起動を拒否する（SEC-5）。両立のため #2090 のオーナー決定（案 A）に従い、**計測（`/proc` の読み取りとシグナル送信）だけを root で行い、create・`systemd-run`・supervisor の起動は対象の利用者（`RUN_AS`）へ降格する**。#485 は「root が計測し、supervisor は対象の利用者が起動する」2 つのシェルで行う（これが案 A そのもの）。#219 の own は 1 つのスクリプトが root で動き、起動だけを `setpriv` で降格する（実装は #2099。自己テストはスタブのみで、**実機〔root〕での実行・検証は #485・#219 の人間担当が行う。結果は未取得**）。製品の `dumpable=0`・rootful 拒否は変えない |
| supervisor の停止 | CLI の `stop` は Linux で制御チャネル経由に結線済み（#2059・#2142）だが、SIGTERM を渡すだけで猶予後の SIGKILL は無く（#1545）、restart ポリシーの下では終了が再起動の対象になる（SUP-9 は #2162・#2440 で実装済みだが、本手順の stop 経由への切り替えは未実施）。コンテナの PID 1 の init はハンドラが無いと SIGTERM を捨てる。このため restart ポリシー `no` の後始末（#499 の既定・#485 の手順 1）だけ `stop` を第 1 段にし、記録した pid・起動時刻の同一性を照合して子孫へ SIGKILL を送る既存の回収を fallback として残す。#491 と #499 の `--check-restart` は `stop` を使わない。`stop` は supervisor と同じ利用者のシェルから呼ぶ（制御チャネルは別 uid の接続元を拒否する）。CLI の `delete` は委譲スコープの外では cgroup の検出に失敗するため呼ばず（#2133）、状態ルートごと削除する |
| バックオフ（#491） | supervisor の bin にバックオフを指定する引数は無く、既定 100ms 固定（`crates/supervisor/src/restart.rs` の `DEFAULT_BACKOFF`）。計測値はバックオフを含むため、スクリプトは差し引いた値も出す |

## 共通の必要環境

- Linux 6.12 以上（Landlock ABI 6 以上）。bash 5・`jq`・`timeout`・`mkfifo`・`cp`・`setsid`・`systemd-run`
- #499・#491 は非 root の利用者で実行する。#485 の PSS 読み取りと #219 は root で実行する（#219 は起動を `RUN_AS` の利用者へ降格する。root で動くのは計測だけ）
- #485・#219 の対象の利用者（`RUN_AS`）は非 root（uid 0 は終了コード 2）で、その user マネージャが動いていること（`/run/user/<uid>/bus` がある。ログアウト後も使うなら `loginctl enable-linger <利用者>`）。#219 では `setpriv`（util-linux。既定 `/usr/bin/setpriv`。違う場合は `SETPRIV=<絶対パス>`）が必要。`systemctl --user` の確認は root のシェルではなく対象の利用者のシェルで行う
- 非特権 user namespace を許可する（例: `kernel.apparmor_restrict_unprivileged_userns=0`）
- `systemd-run --user` が使える（利用者の systemd と DBus セッション）。supervisor は親 cgroup に自分だけがいることを要求するため、スクリプトは supervisor ごとに `systemd-run --user --scope --quiet --collect --unit=fc-bench-... -p Delegate=yes --` で新しいスコープへ入れる（#219 は対象の利用者へ降格した側がこれを呼ぶ）
- cgroup v2 の委譲がある
- 参考: `crates/supervisor/tests/supervisor_bin_real.rs` の module doc に同じ前提がある

## ビルド

```bash
cargo build --release -p fandhe-container-cli -p fandhe-container-supervisor
# fandhe-container-launcher を CLI の隣に置かない（置くと #2442 以降 start がランチャー経由の rootful 経路を選ぶ。
# start_client.rs の classify_launcher_beside）。CLI と supervisor の 2 つだけを利用者所有の使い捨てディレクトリへ置く
BIN_DIR="$(mktemp -d)" && chmod 0755 "$BIN_DIR"
install -m 0755 target/release/fandhe-container "$BIN_DIR/fandhe-container"
install -m 0755 target/release/fandhe-container-supervisor "$BIN_DIR/fandhe-container-supervisor"
test ! -e "$BIN_DIR/fandhe-container-launcher"
export BIN_DIR
```

- `BIN_DIR` は `fandhe-container` と `fandhe-container-supervisor` を置いたディレクトリの絶対パス。スクリプトは固定名で解決し PATH 探索をしない
- スクリプトはバイナリが symlink でなく、所有者が実行ユーザーか root で、group / other に書き込み権が無く、祖先ディレクトリも安全であることを検査する。`install -m 0755` で group 書き込み権は付かないため umask 002 のビルドでも通る。`BIN_DIR` は `mktemp -d`（既定 `/tmp` は sticky）で、`RUN_AS` の利用者が辿れるよう 0755 にする。`target/release` を直接 `BIN_DIR` にしない（`cargo build` が `fandhe-container-launcher` も作るため）
- `systemd-run` は既定 `/usr/bin/systemd-run`。違う場合は `SYSTEMD_RUN=<絶対パス>` を渡す

## bundle の用意

- 計測専用の使い捨てのテンプレートを作る。コンテナごとの複製は `cp -a --reflink=auto` で作る（inode を共有しない。複製に失敗すると終了コード 2）
- `cp -al` は使わない。複製が rootfs 外にもリンクを持つ inode になり、製品の `check_no_external_hardlinks` が起動前に拒否するため。reflink 非対応の FS では複製ごとに page cache が別になり、PSS が Docker の lower 共有より大きく出うる（比較条件として結果に記す）
- `config.json` を置く。user namespace（UID マッピング）を入れる（`linux.namespaces` に user namespace を指定する意味。`linux.uidMappings` / `linux.gidMappings` は省略か空配列にする。非空だと core が `UNIMPLEMENTED` で拒否する。写像は launcher が権限モデルから導出する）。`process.args` は長時間動き続けるものにする（restart 計測では即時終了しないもの）。静的リンクのバイナリか、共有ライブラリを rootfs へコピーしたものにする
- `stop` で止められるコンテナにするには、`process.args` の init が SIGTERM のハンドラを持つこと。持たない場合は `stop` が効かず fallback の SIGKILL で回収されるだけで、計測結果には影響しない

- 並列起動するスクリプトは、コンテナごとに bundle 全体を `cp -a --reflink=auto` で複製して使う（supervisor は start 中に bundle へ flock を取るため、同じ bundle を共有できない）

## #499 監視プロセス独立性（SUP-5・TASK-162）

```bash
make supervisor-independence BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> COUNT=50 OUTPUT=<新規ファイル>
```

- 非 root で実行する。N 個の supervisor を同時に起動し、1 個へ SIGKILL を送って次を判定する: (a) 対象の消滅・(b) 残り N-1 個の監視プロセスの生存・(c) 残りのコンテナ側プロセスの継続・(d) 対象のコンテナ側プロセスの稼働継続
- 出力の読み方: JSON の `result` が `pass` なら全判定成立。`supervisors_alive_after_kill`・`monitored_containers_alive` は期待値 N-1。`target_container_reparented_to` は孤児化後の親 pid（参考値）
- 終了コード: 0 = 全判定成立、1 = 判定不成立・起動数不足・期限切れ、2 = 引数・入力エラー、3 = 前提欠如（root 実行を含む）、4 = 後始末失敗
- `--check-restart` は #2043 の後に有効（既定 off）
- 後始末: 既定では残り N-1 個を CLI の `stop`（期限つき）で止めてから、記録した pid・起動時刻での回収を fallback として行う。対象の個体は SIGKILL 済みで `stop` が届かないため、記録した pid で回収する。`--check-restart` では `stop` を使わない（SUP-9 は実装済みだが、stop 経由への切り替えは未実施）。stderr の `info: cli-stop: <成功>/<対象> supervisors exited after stop` は stop 後に監視プロセスが終了した数で、計測値ではない（0 でも fallback で回収され、判定は変わらない）
- 実機でだけ確認できること: `systemd-run --scope` が pid・親子関係を変えずに supervisor を exec すること。実行後に `systemctl --user list-units --type=scope` へ残骸が無いこと

## #485 監視プロセスの常駐メモリ（SUP-2・TASK-158）

2 つのシェルで行う。

1. 非 root のシェルで、supervisor を N 個起動したまま保つ。コンテナごとに create し、結果チャネルは FIFO にする

   ```bash
   # /proc/<pid>/stat は comm が空白を含みうるため、最後の ")" より後ろだけを読む（ppid が $2・起動時刻が $20）
   pstat() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null; }
   root=$(mktemp -d)
   declare -A FD
   for i in $(seq 1 50); do
     cp -a --reflink=auto <テンプレート> "$root/b$i"
     "$BIN_DIR/fandhe-container" --root "$root/state" create --bundle "$root/b$i" "sup-$i"
     mkfifo "$root/f$i"
     exec {FD[$i]}<>"$root/f$i"   # コンテナごとの fd を保存する（報告の読み取りと後始末で使う）
     systemd-run --user --scope --quiet -p Delegate=yes -- \
       "$BIN_DIR/fandhe-container-supervisor" start --root "$root/state" "sup-$i" >"$root/f$i" &
     sp=$!
     echo "$sp $(pstat "$sp" | awk '{print $20, $2}')" >"$root/sup$i.pid"   # pid・起動時刻・親 pid
   done
   ```

   起動報告を期限付きで読み、全員の `FCSUP1 OK <pid>` を確認する（60 秒で打ち切る）。報告の pid はコンテナ側 init で、報告を受けた時点で supervisor の子孫であることを確かめ、pid と起動時刻の組を `ctr<i>.pid` に保存する（後始末で pid 再利用の取り違えを防ぎ、init 自身を追跡するため）。子孫と確かめられない pid は保存しない。

   ```bash
   is_desc() { # <pid> <祖先の pid>: PPid 連鎖を 64 段まで辿り、祖先に到達すれば 0
     local p="$1" d=0
     while [ "$d" -lt 64 ] && [ -n "$p" ] && [ "$p" -gt 1 ]; do
       p=$(pstat "$p" | awk '{print $2}') || return 1
       [ "$p" = "$2" ] && return 0
       d=$((d + 1))
     done
     return 1
   }
   ok=0
   for i in $(seq 1 50); do
     line=""
     IFS= read -r -t 60 -u "${FD[$i]}" line || true
     case "$line" in
       "FCSUP1 OK "*)
         ip="${line#FCSUP1 OK }"
         read -r sp _ <"$root/sup$i.pid"
         is="$(pstat "$ip" | awk '{print $20}' || true)"
         if [[ "$ip" =~ ^[1-9][0-9]{0,9}$ ]] && [ -n "$is" ] && is_desc "$ip" "$sp"; then
           echo "$ip $is" >"$root/ctr$i.pid"; ok=$((ok + 1))
         else
           echo "sup-$i: reported pid is not a verified descendant of the supervisor" >&2
         fi ;;
       *) echo "sup-$i: not ready: ${line:-<no report within 60s>}" >&2 ;;   # ERR 行や無報告はここに出る
     esac
   done
   echo "ready: $ok/50"
   ```

   `ready: 50/50` で起動完了。ERR や無報告があれば計測せず、下の後始末をして原因を調べる。

   後始末は、supervisor の SIGTERM ではコンテナを停止しない（コンテナ側プロセスが孤児として残る）ため、次の順で行う。追跡の対象はコンテナ側 init（報告 pid）自身で、`ctr<i>.pid` に pid と起動時刻の組を保存できていない個体は「追跡不能」とする（supervisor が生きていても、一時的な子孫を数えられても同じ。ERR 報告・無報告・報告前の中断では、最後の記録の後に init が生まれる順序が成立し、未回収のコンテナ側プロセスが残りうるため）。追跡不能の個体が 1 つでもあれば状態を削除せず保持する（スクリプトの終了コード 4 に相当）。

   ```bash
   # 1. supervisor を止める前に、全 supervisor の生存中の子孫（孫以下を含む）の pid と起動時刻を保存する（pid 再利用の取り違え防止）。
   #    init（ctr<i>.pid の pid・起動時刻の組）を記録できていない個体は「追跡不能」とし、状態を削除しない
   : >"$root/tracked"
   untracked=0
   desc_of() { # <pid>: 子孫を再帰的に列挙する
     local c
     for c in $(pgrep -P "$1" 2>/dev/null); do echo "$c"; desc_of "$c"; done
   }
   for i in $(seq 1 50); do
     read -r sp st pp <"$root/sup$i.pid" 2>/dev/null || { untracked=1; continue; }
     if [ "$(pstat "$sp" | awk '{print $20, $2}')" = "$st $pp" ]; then
       for c in $(desc_of "$sp"); do
         s2=$(pstat "$c" | awk '{print $20}') || continue
         [ -n "$s2" ] && echo "$c $s2" >>"$root/tracked"
       done
     fi
     # init 自身を、報告時に保存した起動時刻つきで追跡対象へ加える（supervisor が消えていても記録は残る）
     if read -r ip is <"$root/ctr$i.pid" 2>/dev/null && [ -n "$is" ]; then
       echo "$ip $is" >>"$root/tracked"
     else
       echo "sup-$i: container init not recorded (cannot prove no container process remains)" >&2; untracked=1
     fi
   done
   # 1b. CLI の stop を第 1 段にする（restart ポリシー no の個体のみ。このシェルは supervisor と同じ利用者。SUP-5・CLI-1）。
   #     失敗しても次の fallback（2 以降）で回収するので、止まらなくても中断しない。期限は呼び出しごと 10 秒。
   for i in $(seq 1 50); do
     timeout --kill-after=2 10 "$BIN_DIR/fandhe-container" --root "$root/state" stop "sup-$i" </dev/null >/dev/null 2>&1 || echo "sup-$i: stop failed; falling back" >&2
   done
   for _ in $(seq 1 100); do
     alive=0
     for f in "$root"/sup*.pid; do
       read -r sp st pp <"$f" 2>/dev/null || continue
       [ -n "$st" ] && [ "$(pstat "$sp" | awk '{print $20, $2}')" = "$st $pp" ] && alive=1
     done
     [ "$alive" -eq 0 ] && break
     sleep 0.1
   done
   # 2. supervisor を終了させる。送信直前に pid・起動時刻・親 pid（このシェルの $$）の一致を確認する（pid 再利用の取り違え防止）。
   #    保存した pid が同じ起動時刻のまま生きていれば SIGKILL
   for f in "$root"/sup*.pid; do
     read -r sp st pp <"$f"
     [ -n "$st" ] && [ "$(pstat "$sp" | awk '{print $20, $2}')" = "$st $pp" ] && [ "$pp" = "$$" ] && kill "$sp"
   done
   sleep 1
   while read -r c st; do
     [ "$(pstat "$c" | awk '{print $20}')" = "$st" ] && kill -KILL "$c"
   done <"$root/tracked"
   sleep 1
   # 3. 残存確認（1 つでも残っている、または追跡不能の個体があれば削除せず手で回収する）
   left=0
   while read -r c st; do
     [ "$(pstat "$c" | awk '{print $20}')" = "$st" ] && { echo "still alive: $c" >&2; left=1; }
   done <"$root/tracked"
   [ "$untracked" -eq 0 ] || left=1
   # 4. 残存も追跡不能も無いときだけ fd を閉じて状態を削除する
   if [ "$left" -eq 0 ]; then
     for i in $(seq 1 50); do eval "exec ${FD[$i]}>&-"; done
     rm -rf "$root"
   else
     echo "cleanup incomplete: state kept at $root. Recover by hand (ps -ef --forest; compare each suspected process start time) before deleting." >&2
   fi
   ```

   追跡不能・残存で状態を保持したときは、`ps -ef --forest` で `fandhe-container` 系の孤児プロセスを探し、起動時刻が本計測の開始以降のものだけを手で止めてから `$root` を削除する。

2. root のシェル（権限付きシェル）で計測する。`RUN_AS` は 1. のシェルの利用者（案 A: 起動は対象の利用者、計測だけ root）

   ```bash
   sudo make supervisor-pss COUNT=50 RUN_AS=<1. のシェルの利用者> EXPECTED_DIR="$BIN_DIR" SAMPLES=5 OUTPUT=<root 所有のディレクトリ配下の新規ファイル>
   ```

   - スクリプトは起動しない。測定対象の各 pid が `RUN_AS` の利用者で動き（`/proc/<pid>/status` の Uid 4 値）、`user@<uid>.service` 配下の `.scope` に入っていること（`systemd-run --user --scope` の委譲スコープ）を確かめ、違えば終了コード 3 になる（root のまま起動した supervisor は SEC-5 で拒否されるため通常は起きない）
   - 非 root で実行すると終了コード 2、`RUN_AS` が uid 0 でも 2

- 出力の読み方: `apportioned_pss_kb_median`（N 按分後の主指標）と `per_process_pss_kb_median`（単体の参考）。目標 2048KB は `target_pss_kb` に参考値として載るだけで、スクリプトは合否を出さない
- 読めないときは終了コード 3 で、メッセージに dumpable の旨が出る。root のシェルから実行する
- 結果欄は空のまま。実測値は人間が #485 に記録する（この手順書・スクリプトは実測値を持たない）

## #491 restart レイテンシ（SUP-3・TASK-160）

前提: #2043 が入っていること。入っていなければ再起動未観測で終了コード 1 になる。

後始末で CLI の `stop` は使わない（`--restart` の下では SIGTERM の終了が restart の対象になる〔SUP-9 は #2162・#2440 で実装済みだが、stop 経由への切り替えは未実施〕ため）。計測の起点はコンテナ側プロセスへの SIGKILL のままで、`stop` 経由にはしない。後始末の正常系は下記のとおり CLI の `delete`。

```bash
make restart-latency BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> TRIALS=20 WARMUP=1 OUTPUT=<新規ファイル>
```

- 非 root で実行する。supervisor を `--restart on-failure:<試行数>` で起動し、コンテナ側プロセスへ SIGKILL を送って、state.json が新 pid・`restartCount` + 1 を示すまでを計測する
- 出力の読み方（単位 ms）
  - `observed`: SIGKILL 送信から state.json の更新観測まで（主系列）。シグナル配送・終了検知・ポーリング粒度・**バックオフ**を含む
  - `supervisor_reported`: ログの `elapsed_us`（終了検知から Running 記録完了まで。バックオフを含む）。件数が合わなければ `null`
  - `observed_minus_backoff`・`supervisor_reported_minus_backoff`: 上の値から `backoff_ms_assumed`（100ms）を差し引いた値。supervisor はバックオフ以上眠るので「バックオフを除いた遅延の上側の推定」（寝過ごし分を含む保守側）。負になったら計測異常で終了コード 1
  - SUP-3 の目標（バックオフ 0 で中央値 100ms 以下）との比較と合否は #491 の担当。PoC-17 は区間が異なるため直接比較しない
- 後始末（OCI-6・#2157）: 計測値の確定後に、最後のコンテナ側プロセスへ SIGKILL を 1 回送って supervisor を `Stopped` で終わらせ、プロセスの回収を確認してから CLI の `delete`（`systemd-run --user --scope -p Delegate=yes -- fandhe-container --root <dir> delete <id>`）で状態を消す。結果の `cleanup.delete` が `ok` なら delete で消えている。`skipped`（`reason: state-not-stopped`）は自然停止しなかった場合（`--policy always` は SIGKILL で終わらせるため再起動されてこうなる）で、delete は呼ばず従来どおり回収する
- delete が拒否・期限超過になったら終了コード 4 で結果は出ず、stderr に `cleanup-failed: delete was rejected (<CODE>)` と残した状態の場所が出る。手動で回収するときは同じ包み込みで `systemd-run --user --scope -p Delegate=yes -- <bin-dir>/fandhe-container --root <残った状態の state ディレクトリ> delete <id>` を実行する（直接呼ぶと委譲スコープの検出が失敗する）
- 終了コード: 0 = 成功、1 = 計測失敗、2 = 引数エラー、3 = 前提欠如、4 = 後始末失敗（delete の拒否・期限超過を含む）

## #219 50 コンテナ同時起動の集約メモリ（CORE-9・SUP-1・TASK-50）

```bash
sudo make concurrent-memory BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> TARGET=own RUN_AS=<対象の利用者> COUNT=50 TRIALS=3 OUTPUT=<root 所有のディレクトリ配下の新規ファイル>
make concurrent-memory-docker DOCKER=<docker の絶対パス> ...   # Docker 側の同一手法計測（#218）
make concurrent-memory-report OWN_RESULT=<own の出力> DOCKER_RESULT=<docker の出力>
```

- **権限（案 A。#2090 で決定・#2099 で実装）**: スクリプトは root で動く。root で行うのは計測だけで、bundle の複製・create・`systemd-run --user --scope`・supervisor の起動と、対象の利用者の領域（状態ルート・bundle の複製）への書き込み・削除は、`RUN_AS` の利用者へ降格して実行する（`setpriv --reuid --regid --init-groups`。環境変数は `HOME`・`USER`・`LOGNAME`・`PATH`・`XDG_RUNTIME_DIR`・`DBUS_SESSION_BUS_ADDRESS` の許可リストだけ。fd 3 以上は閉じる）。起動前に降格した `id` を確かめ、起動後は各 supervisor の Uid・Gid・補助グループと、cgroup が `user@<uid>.service` 配下の本スクリプトのスコープであることを確かめる（不一致は終了コード 1〔`demotion-mismatch` / `scope-mismatch`〕。結果は公開しない）
- 前提: `RUN_AS` の利用者が `BUNDLE` のテンプレートを読めること。`OUTPUT` は root 所有のディレクトリ配下の新規ファイル（祖先を含む所有者・書き込み権を検査する）。バイナリ（`BIN_DIR`）は symlink でない通常ファイルで、`RUN_AS` の利用者が実行できること（root は直接実行しない）。`--no-new-privs` は付けない（rootless の user namespace の設定が setuid の `newuidmap` / `newgidmap` を使うため）
- 後始末: 中断（HUP / INT / TERM）・失敗でも、supervisor・スコープ・状態ルート・利用者所有の一時ディレクトリを回収する。利用者の領域に root 所有のファイルがあれば削除せず、スコープや一時ディレクトリが残れば識別子（スコープ名・パス）つきで報告して終了コード 4
- 実機（root）での実行と検証は未実施。自己テスト（スタブの `setpriv`・疑似 `/proc`）は root 不要で、実機の結果はこの手順書に書かない
- 後始末は SIGTERM → SIGKILL のまま（CLI の `stop` へは未切り替え。root の本スクリプトからは `RUN_AS` の利用者へ降格して呼ぶ配線が要るため。別 issue）
- 集計の対象は supervisor を根とする子孫全体（コンテナ側プロセスを含む）。コンテナ側プロセスは環境変数を継承しないため、所有の証明は生存中に記録した pid・起動時刻の同一性で行う
- 出力の読み方・SUP-1（Docker の 80% 以下）の判定は #219 の担当。スクリプトは合否を出さない
- 終了コード: 0 = 全試行 N/N 起動、1 = 計測失敗、2 = 引数エラー（bundle の複製失敗を含む）、3 = 前提欠如（非 root 実行・降格の不一致〔`demotion-mismatch`〕・対象の利用者の user マネージャの bus が無い）、4 = 後始末失敗（残存プロセス・スコープ・利用者の一時ディレクトリ、利用者の領域の root 所有ファイル）

## 実行後の確認

- `systemctl --user list-units --type=scope` に `run-*.scope` の残骸が無いこと
- 一時ディレクトリ（`TMPDIR` 配下の `tmp.*`）が残っていないこと
- 残存プロセスが無いこと（終了コード 4 の場合はスクリプトの警告に従い手で回収する）
