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

範囲: `crates/*/src` の本番コード（`rg 'try_lock|lock_shared|\.unlock\('` の一致を全て確認）。

| 箇所 | 型 | 解放 | 保持中の fork / spawn | 競合側の振る舞い | 判定 |
| ---- | -- | ---- | --------------------- | ---------------- | ---- |
| core `state_store.rs` | `StoreGuard`（`@lock`） | (a) | あり | 期限つき | 修正済み（#3471。`oci5_repair5_3471_store_guard_drop_releases_lock_despite_inherited_fd`） |
| core `oci_runtime/launch.rs` | `BundleLock` | (a) | あり | 待たず拒否 | 修正済み（#1537。`core2_bundle_lock_release_survives_inherited_fd`） |
| core `audit_log/file_writer.rs` | 監査の書き手 | (a) | あり | 期限つき | 修正済み（#3292） |
| core `oci_runtime/image_rootfs.rs` | `Backing._lock` / `_wrapper_lock`（`CreatedRootfs` が保持） | (a)（本 PR で `ExplicitUnlockFile`） | あり（plugin-cri 等の複数スレッドの呼び出し元） | 回収が `Alive` と誤判定し、同じ bundle の create が `AlreadyExists` になりうる | 修正済み（#4492。`oci7_repair5_4492_created_rootfs_drop_releases_flock_despite_inherited_fd`） |
| core `image_rootfs.rs` | `reap_one` / `inspect_published` の局所ロック・`Orphan._lock` | (a)（本 PR） | あり（保持中に userns の子を fork） | 回収同士の `Alive` | 修正済み（#4492。同じ型） |
| core `image_rootfs.rs` | `ChildLocked._lock`（userns の子の中） | (b) | 無し（子の中。`_exit` で OS が外す。親は子を回収してから進む） | - | 無害（親が回収してから進む） |
| core `state_store.rs` `lock_file_until` | 取得の補助 | - | - | - | 対象外（保持は `StoreGuard`） |
| oci `image_management/create_gate.rs` | `ContainerCreatePass` / `CreateQuiescence` | (b) | あり（create 中に supervisor を spawn） | 期限つき（`Timeout` / `Ok(None)`） | 該当（#4513） |
| oci `image_management/store.rs` | `ImageStoreGuard._file` | (b) | あり | 期限つき | 該当（#4513） |
| oci `image_management/pull.rs` | `@pull.lock` | (b) | あり | GC が `Live` と見て残す（次回回収） | 無害（余分に残す側に倒れ、無期限にならない） |
| oci `image_management/pull_recovery.rs` | 回収側の `Absent(Some(file))` | (b) | あり | ファイルを消した後は待つ側が無い | 無害 |
| net `network_store/imp.rs` | `GlobalLockGuard` / `NetworkLockGuard`（`Drop` は `note_release()` のみ） | (b) | あり（pasta 等を spawn） | 期限つき | 該当（#4514） |
| net `network/publish.rs` | 共有ポート登録のロック | (b) | あり | 期限つき（`Timeout`） | 該当（#4514） |
| net `add_host_dns/hosts_file.rs` | hosts のロック | (b) | あり | 期限つき（`Timeout`） | 該当（#4514） |
| cri `shim_v2/bootstrap.rs` | `IdLock`・ops.log・daemon log のロック | (b) | あり（daemon の spawn・監査 relay の fork） | 期限つき | 該当（#4515） |
| cri `runtime_service/record_store/file.rs` | 記録ストアの `.lock` | (b) | あり | 期限つき（`LockTimeout`） | 該当（#4515） |
| plugin-cri `netsetup/reclaim_store.rs` | 回収待ち記録の `.lock` | (b) | あり | 期限つき | 該当（#4516） |
| plugin-cri `instance_lock.rs` | `InstanceLock._file` | (b) | あり（モジュール doc に exec しない fork の残余） | 期限つき | 該当（#4516。判断できないため安全側） |
| supervisor `container_options/store.rs` | `OptionsLock._file` | (b) | あり | 期限つき | 該当（#4517） |
| supervisor `logs/rotating.rs` | sink のログロック | (b) | あり | 待たず拒否（40ms 程度の再試行） | 該当（#4517） |
| supervisor `logs/rotating.rs` の読み手 | 共有ロックの一時保持 | (a) | - | - | 無害（明示 unlock） |
| supervisor `logs/cri.rs` | `try_lock_with_grace` | (c) | あり | 猶予（`LOCK_GRACE`）つき再試行 | 無害（fork の窓を猶予で覆う設計） |
| platform-macos `console_log.rs` | コンソールログのロック | (c) | あり | 猶予つき再試行 | 無害（同上） |
| plugin `uds_security.rs` | `BindLock` | (a) | - | - | 無害（明示 unlock） |
| plugin `sys.rs` | listener のロック | (b) | あり | - | 無害（fork した子も listener を持つので、ロック保持と listener 生存の対応が崩れない設計。`sys.rs` 1592 行付近の doc） |

## 試験コード

`mod tests`・`tests/` が保持するロックは並列の試験の fork で解放が遅れうる。#3292・#3420 の流儀（明示 unlock）に倣い、新しく書く試験は `ExplicitUnlockFile` か `File::unlock` を使う。本 issue では既存の試験は直していない。

## fork 子による誤解放の確認

`LOCK_UN` は OFD 単位で効くため、fork した子で guard の `Drop` が走ると親のロックまで外れる。core の fork 子（`sys::fork_single_threaded*`）は `_exit` で終わり親のスタックを巻き戻さない。`remove_tree_in_userns`・孤児回収の子の body は、親の `Backing`・局所ロックをムーブしていない（子が自分で `lock_and_recheck` を呼ぶ）。確認日: #4492 実装時。

## 範囲外

- platform-windows `wsl2/mount.rs` のゲスト内シェルの `flock -n 9`: Rust の RAII ではなく、ゲスト内のシェルの終了で外れる。
- `Mutex` / `RwLock` の `try_lock`（oci `store.rs` の `table`、net `hosts_file.rs` の `HOSTS_APPEND_GUARD`、cri `shim_v2/exec.rs`、plugin-cri `supervisor_attach.rs` の `arbiter`、io・microvm・platform-macos `virtiofs`・supervisor `exec_probe.rs`）。

## 再点検

```bash
grep -rnE 'try_lock|lock_shared|\.unlock\(|LOCK_UN|LOCK_EX' crates --include='*.rs' | grep -v '/tests/'
```

新しい一致が、上の表のどの行にも当てはまらなければ、表に行を足して同じ基準で判定する。
