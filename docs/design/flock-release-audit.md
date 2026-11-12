# close だけで flock を外す RAII の点検表

対象 issue: #4492（OCI-5・CORE-2・REPAIR-5。試験は REPAIR-12）。前例: #3471（core `StoreGuard`）・#1537（`BundleLock`）・#3292（監査ログ）・#3420。点検表の形は `channel-send-resource-audit.md`（#3507・#3549）に倣う。

## 問題の形

`flock` は open file description（OFD）に付く。ロックを持つ `File` を drop（close）するだけでは、同じ OFD を指す複製 fd が残っている間はロックが外れない。複製は、fork した子が exec か終了するまで持つ fd や、他スレッドの `Command::spawn` が fork から exec までの間に作る fd である。その間、別プロセスの取得は期限切れになり、待たない `try_lock` は「使用中」「Alive」と誤判定する。

## 判定基準

各箇所を次の 3 点で判定する。

1. 解放の方式: (a) 明示 unlock（`File::unlock` / `LOCK_UN`）、(b) close のみ、(c) close のみだが取得側が猶予つきで再試行する（`try_lock_with_grace`）。
2. 保持中の fork・spawn: ファイル単位ではなく**ホストプロセス単位**で判定する。保持中に同じプロセスのどのスレッドでも fork・spawn しうるなら「あり」。対象は `Command::spawn`（fork から exec の窓。`pre_exec` があると広がる）と core の `sys::fork_single_threaded*`（exec しない子）。ホストは cli・supervisor・plugin-cri・shim daemon・plugin のいずれか。「このファイルに fork が無い」ことは無害の理由にしない。
3. 遅れの影響: 競合側（別プロセス）が `WouldBlock` のときの振る舞い。期限つきで待つ（遅れが `Timeout` になる）、待たずに拒否する、`Alive` として残す、観測する側が無い。

「無害」とする条件は次のいずれか: 解放が (a)／fork・spawn が無い／複製を持つのが保持者の子だけで親が手放す前に必ず回収する／ロック保持と資源の生存の対応が fork をまたいでも崩れないことが source に意図として書いてある／遅れが無期限にならず競合側の誤判定が無い。(b) で fork があり、競合側に期限切れ・誤った拒否・誤った `Alive` が起きうるものは「該当」。判定できないものは安全側で「該当」とする。

## 点検結果

範囲: `crates/*/src` の本番コード（`rg 'try_lock|lock_shared|\.unlock\('` の一致を全て確認）、および試験コードのうち外せないもの（下の「試験コード」節）。

| 箇所 | 型 | 解放 | 保持中の fork / spawn | 競合側の振る舞い | 判定 |
| ---- | -- | ---- | --------------------- | ---------------- | ---- |
| core `state_store.rs` | `StoreGuard`（`@lock`） | (a) | あり | 期限つき | 修正済み（#3471。`oci5_repair5_3471_store_guard_drop_releases_lock_despite_inherited_fd`） |
| core `oci_runtime/launch.rs` | `BundleLock` | (a) | あり | 待たず拒否 | 修正済み（#1537。`core2_bundle_lock_release_survives_inherited_fd`） |
| core `audit_log/file_writer.rs` | 監査の書き手 | (a) | あり | 期限つき | 修正済み（#3292） |
| core `oci_runtime/image_rootfs.rs` | `Backing._lock` / `_wrapper_lock`（`CreatedRootfs` が保持） | (a)（本 PR で `ExplicitUnlockFile`） | あり（plugin-cri 等の複数スレッドの呼び出し元） | 回収が `Alive` と誤判定し、同じ bundle の create が `AlreadyExists` になりうる | 修正済み（#4492。`oci7_repair5_4492_created_rootfs_drop_releases_flock_despite_inherited_fd`） |
| core `image_rootfs.rs` | `reap_one` / `inspect_published` の局所ロック・`Orphan._lock` | (a)（本 PR） | あり（保持中に userns の子を fork） | 回収同士の `Alive` | 修正済み（#4492。同じ型） |
| core `image_rootfs.rs` | `ChildLocked._lock`（userns の子の中） | (b) | 無し（子の中。`_exit` で OS が外す。親は子を回収してから進む） | - | 無害（親が回収してから進む） |
| core `state_store.rs` `lock_file_until` | 取得の補助 | - | - | - | 対象外（保持は `StoreGuard`） |
| oci `image_management/create_gate.rs` | `ContainerCreatePass` / `CreateQuiescence` | (a)（`ExplicitUnlockFile`） | あり（create 中に supervisor を spawn） | 期限つき（`Timeout` / `Ok(None)`） | 修正済み（#4513。`oci5_repair5_4513_create_pass_drop_releases_gate_despite_duplicate_fd`・`oci5_repair5_4513_quiescence_drop_releases_gate_despite_duplicate_fd`。guard は参照で渡され fork 子へムーブしない） |
| oci `image_management/store.rs` | `ImageStoreGuard._file` | (a)（`ExplicitUnlockFile`） | あり | 期限つき | 修正済み（#4513。`oci5_repair5_4513_image_store_guard_drop_releases_lock_despite_duplicate_fd`） |
| oci `image_management/pull.rs` | `@pull.lock` | (b) | あり | GC が `Live` と見て残す（次回回収） | 無害（余分に残す側に倒れ、無期限にならない） |
| oci `image_management/pull_recovery.rs` | 回収側の `Absent(Some(file))` | (b) | あり | ファイルを消した後は待つ側が無い | 無害 |
| net `network_store/imp.rs` | `GlobalLockGuard` / `NetworkLockGuard`（`Drop` は `note_release()` のみ） | (a)（`ExplicitUnlockFile`） | あり（pasta 等を spawn） | 期限つき | 修正済み（#4514。`oci5_repair5_4514_global_lock_guard_drop_releases_lock_despite_duplicate_fd` ほか） |
| net `network/publish.rs` | 共有ポート登録のロック | (a)（`ExplicitUnlockFile`） | あり | 期限つき（`Timeout`） | 修正済み（#4514。`oci5_repair5_4514_shared_port_registry_lock_releases_despite_duplicate_fd`） |
| net `add_host_dns/hosts_file.rs` | hosts のロック | (a)（`ExplicitUnlockFile`） | あり | 期限つき（`Timeout`） | 修正済み（#4514。`oci5_repair5_4514_hosts_lock_releases_despite_duplicate_fd`） |
| cri `shim_v2/bootstrap.rs` | `IdLock`・ops.log・daemon log のロック | (a)（#4515 で `ExplicitUnlockFile`） | あり（daemon の spawn・監査 relay の fork） | 期限つき | 修正済み（#4515。`oci5_repair5_4515_id_lock_*`・`_ops_log_lock_*`・`_daemon_log_lock_*`） |
| cri `runtime_service/record_store/file.rs` | 記録ストアの `.lock` | (a)（#4515 で `ExplicitUnlockFile`） | あり | 期限つき（`LockTimeout`） | 修正済み（#4515。`oci5_repair5_4515_record_store_lock_*`） |
| plugin-cri `netsetup/reclaim_store.rs` | 回収待ち記録の `.lock` | (a)（`ExplicitUnlockFile`） | あり | 期限つき | 修正済み（#4516。`net1_repair5_4516_reclaim_store_lock_drop_releases_despite_duplicate_fd`） |
| plugin-cri `instance_lock.rs` | `InstanceLock._file` | (a)（`ExplicitUnlockFile`） | あり（モジュール doc に exec しない fork の残余） | 期限つき | 修正済み（#4516。`cri2_repair5_4516_instance_lock_drop_releases_despite_duplicate_fd`）。残余: Drop を経ない終了（SIGKILL 等）では複製 fd を持つ子が生きている間だけ再取得が遅れる（期限つき） |
| supervisor `container_options/store.rs` | `OptionsLock._file` | (a)（`ExplicitUnlockFile`） | あり | 期限つき | 修正済み（#4517。`oci5_repair5_4517_options_lock_drop_releases_despite_duplicate_fd`） |
| supervisor `logs/rotating.rs` | sink のログロック | (a)（`ExplicitUnlockFile`） | あり | 待たず拒否（40ms 程度の再試行） | 修正済み（#4517。`oci5_repair5_4517_sink_drop_releases_log_lock_despite_duplicate_fd`・`oci5_repair5_4517_remove_lock_file_unlocks_despite_duplicate_fd`） |
| supervisor `logs/rotating.rs` の読み手 | 共有ロックの一時保持 | (a) | - | - | 無害（明示 unlock） |
| supervisor `logs/cri.rs` | `try_lock_with_grace` | (c) | あり | 猶予（`LOCK_GRACE`）つき再試行 | 無害（fork の窓を猶予で覆う設計） |
| platform-macos `console_log.rs` | コンソールログのロック | (c) | あり | 猶予つき再試行 | 無害（同上） |
| plugin `uds_security.rs` | `BindLock` | (a) | - | - | 無害（明示 unlock） |
| plugin `sys.rs` | listener のロック | (b) | あり | - | 無害（fork した子も listener を持つので、ロック保持と listener 生存の対応が崩れない設計。`sys.rs` 1592 行付近の doc） |
| core `oci_runtime/image_rootfs.rs` の `#[cfg(test)]`（`oci7_lock_held_by_other_is_reported_as_alive_not_deleted`） | 素の `File`（試験の保持者） | (a)（#4541 で `File::unlock`） | あり（core の lib 試験バイナリの他の試験が `sys::fork_single_threaded*`・`Command::spawn` を行う） | 待たない再取得（`kept_alive` に倒れる） | 修正済み（#4541。試験の保持者を明示 unlock。製品の誤判定ではなかった） |

## 複製の一致の照合（#4532 の判断・#4566）

`ExplicitUnlockFile` は core・oci・cri・plugin-cri・supervisor・net の 6 か所に別々に置かれている（OCI-5・CORE-2・REPAIR-1・REPAIR-5）。片方だけ直す漏れを防ぐ方式は、#4532 の 2026-11-12 のオーナーコメントで案 C に決まった。

### 結論

- 複製は残す。新しい crate も Cargo の依存の辺も足さない。
- 本体の振る舞いの一致は、共有の試験ケースで照合する。ケースは `crates/core/tests/support/flock_release_cases.rs`（群 A）と `flock_release_with_cases.rs`（群 B）に置き、各 crate の `lib.rs` が `#[path]` で `#[cfg(test)]` のモジュールとして取り込む。試験専用で製品バイナリ・rlib には入らない。
- 新しく書く試験コードのロックも、その crate の `ExplicitUnlockFile` を使う。

### 採らない案

| 案 | 理由 |
| -- | ---- |
| A1: core に `pub` で集約 | oci・net が参加できない。`oci → core`・`net → core` の製品の辺が新設になり、net の「core に依存しない」と食い違う。core の変更が PLUG-4 の判定に響くおそれもある |
| A2: cri から plugin-cri へ | 減るのは 1 か所だけで、cri の責務の外の部品を公開することになる |
| A3: io に置く | 6 本の新しい辺が要り、io の責務の外（fdinfo の前例でも不可とした） |
| B: 新しい下位 crate | 約 50 行の部品に対し、crate 境界の変更と CI・`deny`・`about` の対象の追加が重い |

### 照合の方式

| 群 | 内容 | 参加する crate | 件数 |
| -- | ---- | -------------- | ---- |
| A | `new` と `Drop`（陽性対照・`new` が生きている間は保持・複製 fd が残っても `Drop` で外れる） | 6 crate すべて | 3 件 × 6 |
| B | `release_lock_file_with`（unlock は close の前に 1 回・失敗しても close）と `release_lock_file`（実際に unlock） | net 以外の 5 crate | 3 件 × 5 |

- 試験名は `repair1_oci5_4566_*`。件数は `cargo test -p <パッケージ名> --lib flock_release_cases -- --list`（群 A）と `flock_release_with_cases -- --list`（群 B）で確かめる。
- 一時ディレクトリの作り方は crate ごとに違うため、各 `flock_release.rs` が試験専用の `shared_case_dir(tag)` を持つ（共有ファイルの外）。
- 規則を変えるときは、共有ケースと 6 か所を同じ PR で直す。

### 許容する差（共有ケースの外）

- core の `ExplicitUnlockFile` は `cfg(target_os = "linux")`。
- supervisor の `as_file()`。
- oci・supervisor の `LockRelease` の `allow(dead_code)`。
- 試験用補助 `clone_file_for_test` の cfg と戻り値（net は `Result`）。
- net は形が違う。`Deref`/`DerefMut`、名前つきフィールド、その場で unlock する `Drop` を持ち、製品に `release_lock_file_with`・`LockRelease` が無い（`cfg(all(test, unix))` の `release_with` は試験専用）。そのため群 A だけに参加する。

### 残余

- net を他の 5 crate の形（`Option<File>`・`release_lock_file*`）へ寄せるかは未判断。オーナー判断の候補とする。
- net の試験専用 `release_with` と、その試験 `oci5_repair5_4514_release_continues_close_when_unlock_fails` の整理の要否。

### 再評価の条件

- 7 つ目の複製が現れたとき。
- 複数の crate で同じ修正が要る不具合が出たとき。
- 下位 crate の新設が別の理由で承認されたとき。

## 試験コード

対象は `tests/`・`src/**/tests.rs`・`#[cfg(test)]` の素の `File` のロック。判定の単位は**試験バイナリ**（判定基準 2 のホストプロセス単位）で、lib 試験なら crate 全体の `#[cfg(test)]` と、そこから届く製品経路の fork・spawn を数える。「そのファイルに spawn が無い」は理由にしない。並列の試験の fork で解放が遅れうるため、新しく書く試験コードのロックも、その crate の `ExplicitUnlockFile` を使う（#4532 の判断 3。#3292・#3420 の流儀）。

次のいずれかに当たるものは表に載せない（確認日: #4535 実装時）。共通の理由は、影響が試験プロセスの中に閉じ、製品の `Alive` / 拒否の誤判定につながらない（起こりうるのは試験の間欠失敗だけ）こと。

- (i) 陽性対照: `*_despite_duplicate_fd` / `*_despite_inherited_fd` の `plain`。複製 fd の対照として意図的に素の `File` を close だけで閉じる（core `state_store.rs`・`launch.rs`、oci `store.rs`、supervisor `logs/rotating/tests.rs`）。
- (ii) `File::unlock` で外す: core `start.rs` の `other.unlock()`・`probe.unlock()`、core `state_store.rs`、core `audit_log/file_writer.rs`、`tests/oci_create_with_image.rs` の `holder.unlock()`、`tests/audit_file_writer_timeout.rs`。
- (iii) 再取得が待ち、期限が fork の窓より十分長い: `tests/oci_start.rs` の `eventually(...)`、platform-macos `config.rs` の `rotation_and_removal_refuse_locked_generation`（取得側が `try_lock_with_grace`。同じ試験バイナリは `Command::new("mkfifo")` を使う）、oci `store.rs` の `oci7_other_file_handle_holding_lock_times_out`（`drop(other)` の後の再取得の期限は `SHORT` = 200ms。同じ lib 試験バイナリの `layer.rs` が `mkfifo` を spawn するが、窓は exec までの短時間）。
- (iv) その試験バイナリに fork・spawn の経路が無い: `tests/oci_start.rs`（`FakeLauncher` のみ）・`tests/oci_create_with_image.rs` の `drop(tree_lock)`・`drop(bundle_lock)` の直後の再取得（展開器は偽物で userns の fork に入らない）。
- (v) 競合側が製品でなく、遅れても誤判定が無い: core `tests/support/scratch_root.rs` の `ScratchDir`（競合側は systemd-tmpfiles の aging 走査だけで、遅れると走査が飛ばされる時間が延びるのみ）。

外せないもの（close だけで外した直後に、待たずに、または短い期限で再取得の成功を断定し、同じ試験バイナリに fork・spawn の経路があるもの）は上の表に行を足す。修正（試験側の明示 unlock）は本 issue の範囲外で、表の追跡 issue で行う。

## fork 子による誤解放の確認

`LOCK_UN` は OFD 単位で効くため、fork した子で guard の `Drop` が走ると親のロックまで外れる。core の fork 子（`sys::fork_single_threaded*`）は `_exit` で終わり親のスタックを巻き戻さない。`remove_tree_in_userns`・孤児回収の子の body は、親の `Backing`・局所ロックをムーブしていない（子が自分で `lock_and_recheck` を呼ぶ）。確認日: #4492 実装時。plugin-cri（#4516）は fork の原始を持たず、`ExplicitUnlockFile`・`ReclaimStore` の guard・`Arc<InstanceLock>` を core の `fork_single_threaded*` のクロージャへ渡す箇所が無いことを `git grep` で確認した。

supervisor（#4517）: supervisor 自身の `sys` に fork は無く、core の `sys::fork_single_threaded` を呼ぶ `exec.rs` の `spawn_exec_worker` の子 body は `RotatingFileSink`・`OptionsLock`・`ExplicitUnlockFile` を所有・ムーブしていない（子は exec か `_exit` で終わる）。確認日: #4517 実装時。

net の子プロセスは `Command::spawn`（exec 経路）だけで、exec しない fork を持たない。`pre_exec` の closure は `prctl`・`getppid` のみで guard を捕捉しない。guard の外部利用者（cli・supervisor）も子の body へムーブしていない。確認日: #4514 実装時。

## 範囲外

- platform-windows `wsl2/mount.rs` のゲスト内シェルの `flock -n 9`: Rust の RAII ではなく、ゲスト内のシェルの終了で外れる。
- 試験コードの素の `File` のロック: 「試験コード」節の条件に当たるものは点検の対象から外す（影響が試験プロセスに閉じ、陽性対照は意図的に素の `File` を使うため）。外せないものは表にある。理由の詳細は同節に置く。
- `Mutex` / `RwLock` の `try_lock`（oci `store.rs` の `table`、net `hosts_file.rs` の `HOSTS_APPEND_GUARD`、cri `shim_v2/exec.rs`、plugin-cri `supervisor_attach.rs` の `arbiter`、io・microvm・platform-macos `virtiofs`・supervisor `exec_probe.rs`）。

## 再点検

```bash
grep -rnE 'try_lock|lock_shared|\.unlock\(|LOCK_UN|LOCK_EX' crates --include='*.rs' | grep -v '/tests/'
```

新しい一致が、上の表のどの行にも当てはまらなければ、表に行を足して同じ基準で判定する。

`grep -v '/tests/'` が外すのは `tests/` ディレクトリ（`crates/*/tests/` と `src/**/tests/`）だけである。`#[cfg(test)]` のモジュールと `src/**/tests.rs`（例: supervisor `logs/rotating/tests.rs`、plugin-cri `pod_holder/tests.rs`）は一致に残る。その一致は「試験コード」節の条件で判定する。`tests/` ディレクトリ側を点検するときは `grep -rnE 'try_lock|lock_shared|\.unlock\(|LOCK_UN|LOCK_EX' crates --include='*.rs' | grep '/tests/'` で取り直す。
