# supervisor 不在時（孤児化・再起動後）の exec の方式（判断記録）

supervisor が不在のとき（孤児化・再起動後）に、稼働中コンテナへの exec をどう成立させるか、または成立させないかの判断材料を整理する（SUP-4・SUP-5・SUP-6・SUP-8・SEC-1・CORE-1・REPAIR-3。TASK-163 追補・TASK-165。#2688）。

> **位置づけ**: **判断記録（オーナー承認待ち）**。本書は決定ではなく判断材料である。決まるまで現行の拒否（fail-closed）を保つ。関連: #1461・#1617（起動時 pidfd の恒久策）・#2626 / PR #2708（CLI の exec の配線）・#2441（healthcheck の配線）・#2631 / PR #2684（本 issue が追跡先になった経緯）・#513・#514・#515（re-adopt。TASK-165）。spec は孤児時の exec の方式を定めておらず、本書の判断は実装側の判断である。実装は本書の対象外（docs のみ）で、新しい試験も足さない。

## 現状（fail-closed の根拠）

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/supervisor/src/exec.rs` | 本番の通しの入口は `run_command_with_pidfd` だけ。起動時（fork 直後・回収前）から supervisor が保持する pidfd（`LaunchedProcess::launch_pidfd`）を引数の型で必須にする |
| 縮退経路 | 記録 pid から開く入口 `run_command` は `exec-test-support` feature の試験専用で、既定ビルドには無い（#1617） |
| `crates/supervisor/src/control/target.rs` | 起動時 pidfd を持つのは稼働中 supervisor の `ControlledProcess` だけ |
| `crates/supervisor/src/control/client.rs` | ソケットが無い・接続拒否のとき `Unavailable` を返す。CLI の exec は `state.json` の記録 pid からの `pidfd_open` へ縮退しない（#2626 の設計） |
| `crates/core/src/exec/setns.rs` | `Pid1Target::open`（記録 pid から開き cgroup パスの完全一致で照合）は「コンテナから cgroupfs に書けない」前提の間だけの縮退経路。`open_with_launch_pidfd` は渡された pidfd の `Pid:` と記録 pid の一致を同一性の根拠にする |
| spec | SUP-5: 孤児化したコンテナは稼働を続けるが restart・healthcheck・ログ捕捉は失われる。SUP-8: re-adopt か終了かを決める。SUP-4: healthcheck は exec と同じ関数で動く |

結果として、孤児の間は CLI の exec も healthcheck も拒否される。これは SUP-5 で失われる監視機能と同じ範囲である。

## 論点の核心

pidfd をあとから開いても、それ自体では何も証明されない。起動時の pidfd の持ち主が消えた後、`pidfd_open(記録 pid)` が元のコンテナの PID 1 を指していると何で確かめるか、が論点の中心である（「どうやって pidfd を取り直すか」ではない）。記録 pid は終了後に再利用されうる（SEC-1）。

## 案の比較

| 案 | 内容 | 評価 |
| -- | ---- | ---- |
| (i) 拒否を保つ | re-adopt まで exec を拒否し、exec 側に縮退経路を持たない | 現状。安全。孤児の間は exec と healthcheck が使えない |
| (ii) cgroup パスでの同一性（`Pid1Target::open`）を本番で使う | 記録 pid から開き `<scope>/fc-<id>@<instance>` との一致で照合する | cgroupfs に書けない前提に頼る。前提を崩す変更（cgroupfs のマウント・cgroup namespace・`/sys/fs/cgroup` の rw bind）で壊れる。#1461 が恒久策を入れた理由そのもの。不採用を推奨 |
| (iii) 起動時の同一性の証跡を `state.json` に記録して照合する | 起動時にコンテナが偽れない証跡を記録する。候補は (a) pidfd の inode 番号（pidfd の `fstat` の `st_ino`）、(b) `/proc/<pid>/stat` の starttime と `boot_id` の組。取り直しのとき `pidfd_open(記録 pid)` → 証跡の照合 → pidfd の未終了の確認、の順に固定する | cgroupfs の前提に頼らない。`state.json` のスキーマ追加が要る（現状の exec は instance を使ってスキーマを変えない方針）。カーネル版数の要件（(a) は 6.9 以上の 64 bit、起動をまたぐ照合には `boot_id` が要る。下記「カーネルの事実」）と、満たさない環境の扱いを決める必要がある |
| (iv) supervisor の外で pidfd を持ち続ける | systemd の fd store・常駐の holder など | supervisor は `systemd-run --user --scope` で包んで起動される（`crates/cli` の start）。fd store は service 単位の機能で、scope では使えない（systemd v262.1 のソースと man で照合済み。下記「systemd の事実」）。常駐の holder は CORE-1（中央の常駐デーモンを持たない）と衝突する。不採用を推奨 |

誰が取り直すかも分けて考える。

- (α) CLI の exec が自分で取り直す
- (β) re-adopt（#513 で検知、#514 で再監視）した supervisor が取り直して保持する。以後は既存の制御チャネルの受け渡しで、CLI の exec も healthcheck も今のまま動く

## Agent の推奨（決定ではない）

- 同一性を確立し直すのは re-adopt（#514）の責務とし、exec は持たない（(β)）。re-adopt の前は (i) で拒否を保つ
- 証跡には (iii) を使う。pidfs の inode が使える環境ではそれを優先し、使えない環境で starttime と `boot_id` に切り替えるか拒否するかはオーナー判断として残す
- (β) を推す理由: pidfd を持つ主体が supervisor 1 つに保たれる（CORE-1）／exec と healthcheck（SUP-4 の共通関数）の経路を変えずに済む／孤児の状態を exec が覆い隠さない（SUP-5・SUP-8 の「再監視下に戻る、または明示的に終了する」と合う）／本番の入口に縮退経路を新しく作らない

re-adopt (#514) が満たすべき契約（案）:

1. 証跡の照合を通った pidfd だけを `ControlledProcess` へ登録する
2. 照合できない（証跡が無い・一致しない・既に終了している）ときは re-adopt せず、終了ポリシーか拒否に倒す（fail-closed）
3. 照合の順序は、pidfd を先に開いて固定し、読み取りの後で未終了を確認する（`setns.rs` の TOCTOU の契約と同じ）
4. 受け取った pidfd は core の `Pid1Target::open_with_launch_pidfd` がそのまま受け入れる（`Pid:` と記録 pid の一致、cgroup の照合は多層防御）
5. 証跡はカーネルが付ける値に限り、コンテナ内から書ける値（cgroup の所属・環境・ファイル）を同一性の根拠にしない

## カーネルの事実（版・commit 固定の一次情報で照合済み。#2772）

確認日は 2026-10-26。ソースは torvalds/linux の次の tag を commit に解決して固定した。man-pages は kernel.org の man-pages.git の tag `man-pages-6.20`（commit `1bffe43b9ff4a4d8f73d33f6bd24743f4c1254d6`）。リポの他の判断で Linux 6.9 を閾値として扱っている箇所と、本件の根拠は別に確かめた。

| tag | commit |
| --- | ------ |
| v6.8 | `e8f897f4afef0031fe618a8e94127a0934896aba` |
| v6.9 | `a38297e3fb012ddfa7ce0321a7e5a8daeb1872b6` |
| v6.12 | `adc218676eef25575469234709c2d87185ca223a` |
| v6.13 | `ffd294d346d185b70e28b1a28abe367bbfe53c04` |

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| pidfs の導入版 | [v6.8 の `fs/` に `pidfs.c` が無い](https://github.com/torvalds/linux/tree/e8f897f4afef0031fe618a8e94127a0934896aba/fs)。[v6.9 の `fs/pidfs.c`](https://github.com/torvalds/linux/blob/a38297e3fb012ddfa7ce0321a7e5a8daeb1872b6/fs/pidfs.c)（`pidfs_init_inode`・`init_pseudo(fc, PID_FS_MAGIC)`）があり、`kernel/pid.c` の `pidfd_create`（L603）が `linux/pidfs.h` を使う | 一致。pidfs は 6.9 で導入。6.8 以前は pidfd が共有の anon inode で、pidfd ごとの inode 番号は使えない |
| pidfs の inode 番号の一意性 | 64 bit: [v6.12 `kernel/pid.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/kernel/pid.c) の `pidfs_ino`（L71。`RESERVED_PIDS` で初期化）と `pid->ino = ++pidfs_ino`（L280。`pidmap_lock` の下）、[`fs/pidfs.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/pidfs.c) の `pidfs_inum`（L266-L273。`*ino = pid->ino`）。v6.9 も同じ形（`kernel/pid.c` L71・L280、`fs/pidfs.c` L152-L159）。32 bit: `pidfs_inum` は IDA（`ida_alloc_range`、L241-L265）で、`pidfs_evict_inode` が番号を返す（L320-L328） | 一致（条件つき）。64 bit（x86_64・aarch64）では `struct pid` ごとに単調増加の u64 を割り当て、減らさないので、同じ起動の中では再利用されない。32 bit は解放した番号を再利用するため、32 bit は対象外とする。カウンタは起動のたびに `RESERVED_PIDS` から数え直すので、**再起動をまたぐ比較には使えない**（`boot_id` と組にする） |
| starttime の欄番号と単位 | [man-pages `proc_pid_stat(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man/man5/proc_pid_stat.5?h=man-pages-6.20) の `(22) starttime %llu`（clock tick。`sysconf(_SC_CLK_TCK)` で割る）。ソースは [v6.12 `fs/proc/array.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/proc/array.c) の `do_task_stat`（L585-L587 で `nsec_to_clock_t(timens_add_boottime_ns(task->start_boottime))`、L612 で出力） | 一致。22 番目、単位は clock tick。**追加の注意**: 値に time namespace の boottime オフセットが足される。足されるのは `current`（読む側）の time namespace のオフセット（[v6.12 `include/linux/time_namespace.h`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/include/linux/time_namespace.h) L82-L87）なので、記録時と照合時で読み手の time namespace が違うと値が変わる。2 番目の欄 comm は括弧つきで空白や `)` を含みうる（man の `(2) comm`）ため、欄の数え方は最後の `)` の後から始める |
| `boot_id` のパス | [v6.12 `drivers/char/random.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/drivers/char/random.c) の sysctl 表の `boot_id`（L1697-L1702。mode 0444）と、`register_sysctl_init("kernel/random", random_table)`（L1716） | 一致。パスは `/proc/sys/kernel/random/boot_id` |
| `PIDFD_GET_INFO` の導入版 | [v6.12 の `include/uapi/linux/pidfd.h`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/include/uapi/linux/pidfd.h) と `fs/pidfs.c` の `pidfd_ioctl` に定義が無い。[v6.13 の `pidfd.h`](https://github.com/torvalds/linux/blob/ffd294d346d185b70e28b1a28abe367bbfe53c04/include/uapi/linux/pidfd.h) L80 に `PIDFD_GET_INFO` | 一致（導入は 6.13）。リポの参照版 6.12 には無いので、証跡の取得に使わない |

案 (iii) への含意（判断はオーナー）:

- 候補 (a) の pidfd の `st_ino` は 6.9 以上かつ 64 bit で成立する。ただし起動をまたぐと番号が戻るので、**`boot_id` を併せて記録して照合する**（`boot_id` の一致 → `st_ino` の一致）。単独の (a) は、再起動後に同じ pid・同じ番号が偶然そろう場合を排除できない
- 候補 (b) は 6.9 未満でも使えるが、starttime は clock tick の粒度で、time namespace の影響を受ける。照合側は初期 time namespace（記録時と同じ読み手）で読む前提を契約に入れる
- 6.9 未満・32 bit の環境の扱い（(b) に切り替えるか、拒否するか）は、引き続きオーナー判断として残す

## systemd の事実（版・commit 固定の一次情報で照合済み。#2837）

確認日は 2026-10-26。取得時点の最新の安定版 tag `v262.1`（annotated tag `f85dfc5dd463f37b67ce589e511be36f527b19f6` が指す commit `73612ea502d53baf9b0df4336cfc296a7ee0d524`）の systemd で、案 (iv) の「fd store は scope では使えない」を確かめた。

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| `FDSTORE=1` を受けて fd を保存するのは service unit の処理 | [`src/core/service.c` L662](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/src/core/service.c#L662)（`service_add_fd_store`）、[L5604](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/src/core/service.c#L5604)（`service_notify_message`）、[L6741](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/src/core/service.c#L6741)（service の vtable の `.notify_message`） | 確認 |
| notify メッセージは unit の vtable の `notify_message` に振り分けられる | [`src/core/manager.c` L3028-L3029](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/src/core/manager.c#L3028-L3029)（`if (UNIT_VTABLE(u)->notify_message)` のときだけ呼ぶ） | 確認 |
| scope の vtable に `notify_message` が無く、fd store の処理も無い | [`src/core/scope.c` L730-L781](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/src/core/scope.c#L730-L781)（`scope_vtable`。通知系は `.notify_cgroup_empty`・`.notify_cgroup_oom` のみ）。`scope.c` に `FDSTORE`・`FileDescriptorStore` の文字列は無い | 確認。scope のプロセスが `FDSTORE=1` を送っても受ける側の処理が無い |
| fd store の設定は service の設定で、scope の man に無い | [`man/systemd.service.xml` L1246](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/man/systemd.service.xml#L1246)（`FileDescriptorStoreMax=`）、[`man/sd_notify.xml` L396-L412](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/man/sd_notify.xml#L396-L412)（`FDSTORE=1` は service の `FileDescriptorStoreMax=` が 0 でない場合のみ受け、保存した fd は service の次の start / restart で返す）。[`man/systemd.scope.xml`](https://github.com/systemd/systemd/blob/73612ea502d53baf9b0df4336cfc296a7ee0d524/man/systemd.scope.xml) に該当する設定は無い | 確認。scope には fd store の設定も、fd を返す「次の start」もない |
| 本番の supervisor は scope で包まれる | リポ内: `crates/cli/src/doctor/user_scope_check.rs` の冒頭の doc（「`start` は supervisor を `systemd-run --user --scope` で包む」） | リポの記述どおり |

結論: 案 (iv) のうち systemd の fd store は、`systemd-run --user --scope` で包む現状の本番の構成では使えない（食い違いなし。見込みが確定した）。`systemd-run --user`（service unit 側）へ変える場合は fd store の対象になりうるが、それは supervisor の起動方式の変更で、本件の範囲外（確かめていない）。推奨（(iv) は不採用）は変わらない。常駐の holder が CORE-1 と衝突する点は、設計上の論点でソースでの照合の対象ではない。

## 確認が必要な点（オーナー判断）

- 推奨の採否（(β) と (i)、または (α)）
- `state.json` への証跡の追加（スキーマ変更。証跡の無い旧レコードは re-adopt を拒否する方向）
- カーネル版数未満（6.9 未満）・32 bit の環境の扱い（上の照合の結果を踏まえる）
- CLI の exec が supervisor 不在を `Unavailable` で返すことの利用者への案内（構造化エラーの `message` の語彙。英語の固定文言で、ホスト側のパスを載せない）

## 範囲外・後続

| 項目 | 担当 |
| ---- | ---- |
| 証跡の記録と照合の実装（core・supervisor） | 未起票（承認後に起票） |
| re-adopt 本体 | #514 |
| 孤児の検知 | #513 |
| 結合試験 | #515 |
| healthcheck の配線 | #2441 |
| CLI の exec の stdio 等 | #2712 |
