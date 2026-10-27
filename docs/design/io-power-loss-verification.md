# 電源断・カーネルクラッシュ後の媒体永続化（IO-2）の検証方式

ステータス: オーナー承認待ち（#1965・TASK-18 追補。IO-2・IO-3・REPAIR-3・REPAIR-5・REPAIR-12）。採否は本書では決めない。`docs/spec` は編集しない。

## 目的と背景

- SIGKILL 試験（`crates/io/tests/crash_safety.rs`・IO-3）の再読込はページキャッシュ経由で、FLUSH ACK を返した書き込みが媒体まで出ているか（IO-2 の契約）は示せない（[io-crash-safety.md](io-crash-safety.md)「この対照で示せる範囲」）
- 永続化の実装は Linux が sink の fd への `syncfs(2)`（5.8 以上）、macOS が `fcntl(F_FULLFSYNC)`、Windows が `FlushFileBuffers`（[io-barrier.md](../api/io-barrier.md)）。電源断・OS クラッシュ時の保証は未検証のまま
- 本書は検証方式を比較し推奨を示す。推奨方式の試験は用意したが、実機（root）での実行と結果の判定は人間が行う

## 方式の比較

| 案 | 中身 | 権限・環境 | 検証できる範囲 | CI |
| -- | ---- | ---------- | -------------- | -- |
| A（推奨） | loop デバイス上の ext4 に dm-flakey を挟む。FLUSH ACK を観測した直後に table を `drop_writes` へ切り替え、サーバーを SIGKILL、umount、table を戻して再 mount し、seq の連続性を照合する（xfstests の `_flakey_drop_and_remount` と同じ型） | root・Linux・`dm_flakey`・`losetup`・`dmsetup`・`mkfs.ext4` | `syncfs` が返った時点でデータとメタデータがブロック層より下へ出ていること。カーネルクラッシュに相当 | 回さない（実機前提） |
| A'（追補候補） | dm-log-writes で書き込み・FLUSH・FUA の順序を記録し、FLUSH ACK 時点の mark まで replay して照合する | root・replay ツール。xfstests の `replay-log` は GPL とされる（要確認）ため、外部ツールとして使えるかはライセンス判断。自前のパーサーも可 | A に加え、キャッシュフラッシュ命令の順序。電源断により近い | 回さない |
| B | QEMU/KVM のゲストで試験し、`echo c > /proc/sysrq-trigger` かゲストの強制リセットを起こす | KVM・x86_64 のゲストカーネルと initrd（既存の `guest/kernel` は macOS 向け arm64） | カーネルクラッシュ。電源断の近似はホスト側のキャッシュ設定しだい | 回さない（人間） |
| C | 物理的に電源を抜く | 実機・人間 | 実電源断（再現性が低い） | 回さない（人間） |
| D（不採用） | FUSE で未同期データを捨てる FS（LazyFS 等）を使う | FUSE | FUSE の `syncfs` の意味論しだいで ext4 等の実 FS と別物になる。ライセンスも未確認 | - |
| E（不採用） | `syncfs` 成功の後に FLUSH ACK が返る順序だけを確かめる | 不要 | 媒体への永続化は示せない。順序は既存の試験で担保済み | - |

## 推奨と理由

- 推奨は A。Linux の主経路（`syncfs`）と「カーネルクラッシュ後」の観点を、root だけで再現性よく確かめられる。対照も組める
- A' は電源断の厳密化の追補候補、B と C は人間の任意確認として残す
- macOS（`F_FULLFSYNC`）と Windows（`FlushFileBuffers`）には dm に当たるものが無く、本書では未検証。後続の追跡が要る

## 用意した試験（案 A）

- `crates/io/tests/power_loss.rs`（`required-features = ["crash-test-server"]`）。root を要する本体 `linux::io2_flushed_data_survives_dm_flakey_drop_writes` は `#[ignore]` で既定のテスト集合から外してある。table 組み立て・名前検証・mountinfo 解析などの純粋ロジックは既定の集合で走る
- 手順: 一時ディレクトリの疎イメージ（64 MiB）を loop に接続、dm-flakey（up）を載せて ext4 を作り mount。各試行で `crash_test_server` を起動して 30 件の Write と Flush を送り、FLUSH ACK の観測後に `dmsetup suspend --nolockfs` → `load`（`drop_writes`）→ `resume`、SIGKILL、umount、table を up に戻して再 mount、`check_disk_records` で seq 0..30 と照合する
- 対照: 製品 sink で通常 ACK だけを受け Flush せずに同じ手順を行う試行は、損失件数を `power_loss_summary` に出すだけで合否にしない（期待値はオーナー判断待ち）
- 実行（人間が root で）: `sudo -E cargo test -p fandhe-container-io --features crash-test-server --test power_loss -- --ignored --exact linux::io2_flushed_data_survives_dm_flakey_drop_writes --nocapture`。成功行は `io2_flushed_data_survives_dm_flakey_drop_writes: ok`
- fail-closed: root でない・外部コマンドが無い・mount 先が ext4 でない等は skip せず失敗にする。外部コマンドはシェルを経由せず期限つき（60 秒）で実行する
- 安全: 操作対象は試験が作った一時ディレクトリのイメージと、その loop・dm・mount だけ。loop は `/sys/block/loopN/loop/backing_file` で自分のイメージと照合する。後始末は Drop で逆順（umount、`dmsetup remove`、`losetup -d`）に行い、失敗は stderr に出す
- UDS クライアント端点は `crash_safety` と共有する（`crates/io/tests/crash_safety/client_end.rs`）

## 保証範囲

- 示せること: `syncfs` が返った時点のデータ・メタデータが、以降の書き込みを捨てた媒体の再 mount 後にも残ること（Linux）
- 示せないこと: 実際の電源断でのディスク内蔵キャッシュの挙動、macOS・Windows の永続化。`io-barrier.md` の「電源断・OS クラッシュ時: 未検証」は、人間が実機で結果を記録するまで変えない
- 未確認の事実（実機または一次情報での確認が要る）: dm-flakey の table 書式と `drop_writes` の意味（本試験は xfstests の書式に合わせた記憶に基づく）、`suspend --nolockfs` の要否、ext4 の `sync_fs` がキャッシュフラッシュを発行する条件。未フラッシュ対照が損失を出すには試行時間が `vm.dirty_expire_centisecs` より短い必要がある

## オーナー承認待ちの事項

1. 案 A を採るか
2. A' の replay ツールのライセンス判断と導入
3. 未フラッシュ対照の期待値（現状は報告のみ）
4. CI で sudo を使って回すか（`.claude/rules/ci.md` の方針変更になる。現状は回さない）

## 範囲外（追跡候補）

- 実機での実行と結果の妥当性の判定（人間。TASK-18.h1 と同じ型）、結果後の `io-barrier.md` 比較表の更新
- macOS・Windows の永続化検証、案 B・C
- spec の IO-2・IO-3 の記述更新（spec リポ側の課題）
- `make io-power-loss` の薄い入口（任意。未作成）
