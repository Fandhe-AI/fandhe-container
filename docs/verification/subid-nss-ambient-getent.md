# LDAP / sssd の subid と ambient capability つき構成の getent の実機確認 手順書と結果記録（#2637）

rootless の subuid / subgid の所有者名の解決（`/etc/passwd` に無いときだけ固定パスの `getent passwd <uid>` を 5 秒の期限つきで実行。`subid:` が `files` 以外なら拒否。`getent` の子は exec 直前に ambient capability を全消去）を、LDAP / sssd の実環境と ambient capability つきの本番構成で確かめる手順と、結果記録の雛形。対応する ID は SEC-5・CORE-6・SUP-14（関連 REPAIR-3・REPAIR-5）。設計は [subid-owner-resolution.md](../design/subid-owner-resolution.md)。元 PR は #2614（#2545）。本確認は [#2637](https://github.com/Fandhe-AI/fandhe-container/issues/2637)（人間担当）。関連: #2692（`subid:` の判定規則を最初の語だけで見る変更。マージ済み）・#538・#539（特権ランチャーの実機確認）・#1621・#2062・#2241。

実行・結果の記録・成否の判定は人間が行う。Agent は実行しない。本書のコマンドは作成時に未実行である。

- ホスト名・アドレス・ユーザー名・LDAP の DN・bind 資格情報・Kerberos keytab・`XDG_RUNTIME_DIR` の実パスは記録しない（例はダミー値）
- root 権限の操作（`/etc/nsswitch.conf`・`/etc/subuid` の編集、sssd の停止、ランチャーのインストール、`getent` の差し替え）は、使い捨ての試験ホストで人間が判断して行う。本書は sudo を呼ばない
- 検査を緩める設定変更（`getent` を利用者が書ける場所に置く等）は行わない

## 期待値の出典と判定規則の版

期待する `code`・`message`・終了コードは、`crates/supervisor/src/id_model.rs`・`crates/supervisor/src/user_db.rs`・`crates/cli/src/doctor/id_mapping_check.rs` の 2026-10-25 時点の main（34f75cd5。#2692 を含む）から写した。実施時に実装を読み直して照合し、結果記録に実行した commit の SHA を書く。

`subid:` の判定は #2692（マージ済み）以降、最初の語だけを見る（shadow 4.13 の `nss.c` に合わせた判定で、大文字小文字を区別しない）。最初の語が `files` 以外なら拒否し、`subid: files sss` は受理する。#2692 より前の commit で確かめる場合は `files` 以外の語を 1 つでも含めば拒否するため、ケース A4 の期待が A3 と同じになる。

## 事前確認

Linux・cgroup v2・非 root・非特権 user namespace・user マネージャへの到達・`systemd-run` の固定候補は [rootless-start-cgroup.md](rootless-start-cgroup.md#事前確認) と同じ。加えて次を確認する。

- `uidmap`（`newuidmap` / `newgidmap`）がある
- `getent` の固定候補（`/usr/bin/getent`・`/bin/getent`・`/usr/sbin/getent`・`/sbin/getent`・`/run/current-system/sw/bin/getent`）のうち最初に解決できるものについて、`readlink -f` の実体と祖先ディレクトリが root 所有で group / other から書き込めない（`stat -c '%U %a' <path>`）。満たさないと「利用不可」となり、シナリオ A は `SUBID_OWNER_LOOKUP_UNAVAILABLE` / `SUBID_OWNER_UNDETERMINED` 側に落ちる
- 試験ユーザーは LDAP / sssd 側にだけあり `/etc/passwd` に行が無い: `grep -c "^[^:]*:[^:]*:$(id -u):" /etc/passwd` が 0、`getent passwd "$(id -u)"` が 1 行を返す
- `/etc/nsswitch.conf` の `passwd:` と `subid:` の行、sssd / FreeIPA / LDAP クライアントの版を記録する
- 変更前の `/etc/nsswitch.conf`・`/etc/subuid`・`/etc/subgid` の `sha256sum` を控える

## ビルドと配置

- シナリオ A（rootless）: [rootless-start-cgroup.md](rootless-start-cgroup.md#ビルドと配置) と同じ
- シナリオ B（ambient 構成）: `cargo build --release` で `fandhe-container-launcher` も作り、root が `scripts/install-privileged-launcher.sh`（[linux.md](../setup/linux.md)「rootful」）で launcher・supervisor・CLI をインストールする。配置後に非 root で `fandhe-container doctor` を実行し `"check":"launcher"` の行を記録する。このインストール自体の実機確認は #538・#539 で未実施のため、失敗したらそちらの問題として切り分ける

## シナリオ A: LDAP / sssd での所有者名の解決と `subid:` の拒否

各ケースで `fandhe-container doctor` の JSON Lines のうち `nsswitch` と ID 写像の行の `code`・`severity`・`state` と終了コード、続けて rootless の `create` → `start` の終了コードと stderr の JSON の `code`・`message` を記録する。bundle は [rootless-start-cgroup.md](rootless-start-cgroup.md#bundle-の用意) と同じ（`uidMappings` は書かない）。成功したら `state.json` の `launchIsolation.id_mapping`（`model` が `subordinate` か）を記録し、`stop` → `delete` で片付ける。

| ケース | 設定 | 期待する doctor | 期待する start |
| ------ | ---- | --------------- | -------------- |
| A1 | `/etc/subuid`・`/etc/subgid` に LDAP の名前の行（例 `ldapuser:100000:65536`）、`subid:` 無し、sssd 稼働 | ID 写像の警告なし（終了コード 0） | 0。`model` は `subordinate`（`getent` が起動されて名前を得た経路） |
| A2 | A1 の行を数値 uid の行に替える | 同上 | 0・`subordinate` |
| A3 | A1 と `subid: sss` | `SUBID_NAME_SERVICE_UNSUPPORTED`（warning・check `nsswitch`・state `subid_name_service`。終了コード 3） | 5・`FAILED_PRECONDITION`・`subordinate ids from a name service are not supported` |
| A4 | A1 と `subid: files sss`、続けて `subid: sss files` | `files sss` は A1 と同じ、`sss files` は A3 と同じ（#2692 より前の commit ではどちらも A3 と同じ） | 同左 |
| A5 | A1 で sssd を停止しキャッシュも無効化（LDAP に届かない状態） | `SUBID_OWNER_LOOKUP_FAILED`（warning・state `lookup_failed`。終了コード 3） | 5・`the user database lookup failed`・`the user database lookup could not start`・`the user database could not confirm that the entry is absent` のいずれか、または期限切れで 7・`TIMEOUT`・`the user database lookup timed out`。経過秒も記録 |
| A6 | 参考: LDAP にも無い uid | `getent passwd <存在しない uid>; echo $?` が 2 になることだけ記録（遠隔源があると終了コード 2 を「名前なし」と断定しない） | — |
| A7（任意） | `subid:` に不正な値（空、壊れた角括弧） | `NSSWITCH_UNUSABLE`（warning・state `unusable`） | 5・`the name service switch configuration is unusable` |

- doctor の終了コードは network・user scope・ID 写像・launcher の各 check の合成（`crates/cli/src/doctor.rs` の `run`。warning が 1 件でもあれば 3、無くて判定不能があれば 4）。表の終了コードは ID 写像・`nsswitch` 以外の check が warning を出さない前提の値で、他の check が warning を出す環境では ID 写像・`nsswitch` の行の `code`・`severity` で判定し、終了コードは記録だけにする
- 各ケースの後に設定ファイルを元へ戻し、`sha256sum` が控えと一致することを記録する
- A3・A4 で shadow の `newuidmap` 自身の挙動を手で試すのは任意の参考記録とする（我々の拒否の判定とは独立）

## シナリオ B: ambient capability つきの本番構成で getent の子の capability

ランチャーが必要最小集合を ambient に載せて supervisor を exec する。supervisor は passwd に行が無いときだけ `getent` を spawn するため、LDAP ユーザーで passwd に行が無い構成（A1）を流用する。`doctor` は CLI（capability 無し）で動くので対象外。

1. 前提の確認: 起動中の supervisor の `/proc/<pid>/status` の `CapInh`・`CapPrm`・`CapEff`・`CapAmb`・`CapBnd`・`NoNewPrivs` を記録し、`CapAmb` が 0 でないことを確かめる。0 なら本構成になっていないので判定不能とし、#538・#539 側の問題として記録する
2. `getent` の子（5 秒以内に終わる）を次のどちらかで観測する。

   - 方法 1（推奨。システムのファイルを変えない）: root で bpftrace を使い、`tracepoint:sched:sched_process_exec` で実行ファイル名が `getent` のものについて、`curtask->cred` の `cap_effective`・`cap_permitted`・`cap_inheritable`・`cap_ambient` と uid を出力する。kernel 6.3 以降は `kernel_cap_t` が `.val`（u64）。BTF が要る。版により書き方が変わるため例として扱い、実施時に調整する
   - 方法 2（使い捨てホストに限る）: root が `getent` を `getent.real` へ移し、同じ場所に root 所有・0755 のラッパーを置く。ラッパーは `/proc/self/status` の `Cap*`・`NoNewPrivs` の行だけを、試験ユーザー所有・0600 のログ（root が事前に作る）へ追記してから `exec <getent.real> "$@"` する。注意点: (a) 子は `env_clear` で `PATH` が無いので外部コマンドは絶対パスで呼ぶかシェル組み込みだけで書く、(b) argv[0] は候補のパスで渡される（busybox 環境では `exec -a "$0"`）、(c) ラッパーと親ディレクトリは root 所有・g/o 書き込み不可（信頼の検査を通すため）。終了後に元の `getent` へ戻し `sha256sum` の一致を記録する

3. 期待値: `getent` の子の `CapAmb`・`CapPrm`・`CapEff` がすべて 0、uid は非 root。`CapInh` は supervisor から引き継がれて 0 でないことがありうる（記録のみで判定に含めない）。`CapBnd` も記録のみ
4. 補助確認（任意。本番経路ではない）: 単体試験 `sec5_child_has_no_ambient_caps`（`crates/supervisor/src/user_db.rs`）を ambient つきで走らせる。`cargo test -p fandhe-container-supervisor --lib sec5_child_has_no_ambient_caps --no-run` で試験バイナリを作り、root が `capsh` で試験ユーザーへ落としつつ任意の capability を inheritable と ambient に載せて実行する（形の例: `capsh --keep=1 --user=<試験ユーザー> --inh=cap_net_raw --addamb=cap_net_raw -- -c '<bin> sec5_child_has_no_ambient_caps --exact'`。版により引数が異なるので調整する）。事前に親の `grep CapAmb /proc/self/status` が 0 でないことを確かめる。この試験はホストの `nsswitch.conf` に左右されない。合格は `test ... ok`

## 結果記録の雛形

本書の表と #2637 のコメントの両方に記録する。

| 項目 | 結果 |
| ---- | ---- |
| 実施日・OS とカーネル・systemd・sssd / FreeIPA / LDAP クライアントの版 | |
| fandhe-container の commit SHA（#2692 を含むか） | |
| `passwd:` と `subid:` の行 | |
| `getent` の候補の実体と信頼の検査の結果 | |
| A1〜A7（doctor の code / severity / state / 終了コード、start の終了コード / code / message、`model`、判定） | |
| B: supervisor の Cap 集合 | |
| B: `getent` の子の Cap 集合（方法 1 / 2）、補助確認、判定 | |
| 後始末（設定ファイルと `getent` の sha256 の一致、cgroup・`state.json`・scope の残骸なし） | |
| 総合判定 | |

## 食い違ったときの扱い

- 集める材料: stderr の JSON、doctor の JSON Lines、`/etc/nsswitch.conf` の該当行、Cap 集合、`getent passwd <uid>` の終了コード（資格情報・実名は除く）
- Agent 向けの修正 issue は人間が起票する。タイトル例「fix(supervisor): <現象>（SEC-5・CORE-6・SUP-14）」、本文は「元 PR #2614・#2545、確認元 #2637」、再現条件、期待と実際、関連する決定の番号
- `getent` の子に capability が残っていた場合は SEC-5・SUP-14 の P0 として扱い、ambient 構成での運用を止める

## 後続

- #539（ambient の子での解除の取りこぼしの全体確認）・#1621（root 分岐）・#2241（root の呼び出し元の扱いの再検討）
