# RotatingFileSink とコンソールログの回転を共通化しない判断（判断記録）

supervisor の `RotatingFileSink`（`crates/supervisor/src/logs/rotating.rs`）と platform-macos のコンソールログ回転（`crates/platform-macos/src/console_log.rs`）を、下位 crate へ共通化するかを検討した結果を残す（REPAIR-1・REPAIR-4・MAC-1・SUP-7・TASK-164.2・TASK-64 追補。#2172）。

> **位置づけ**: 本実装の判断（現状維持）。コード・試験・依存は変えない。新たなオーナー承認は得ていない。crate 境界を変える選択（新 crate・新しい依存辺）はオーナー判断事項のため、本記録では選ばない。

## 現状

Issue #2138 で macOS ゲストのコンソールログに回転（1 MiB × 3 世代。supervisor の `SUPERVISOR_LOG_FILE_BYTES`・`SUPERVISOR_LOG_GENERATIONS` と同じ値と番号規則）が入り、似た処理が 2 か所に並んだ。値の一致は macOS 側の試験（`console_log_limits_match_supervisor`）が固定している。

## 置き場所の候補と依存方向

| 候補 | 評価 |
| ---- | ---- |
| `core` | `platform-macos` から `core` への新しい辺が要る。core は Linux の実行層で重く、3 OS の backend lib に回転のためだけに引かせるのは釣り合わない |
| `supervisor` | 向き（backend から core 側）は規則に反しないが、監視プロセスで bin・試験用 feature・Linux 前提の部品が多く、ゲスト VM 側の backend lib の依存先として責務が合わない |
| `io` | `platform-macos` から `io` は既にある。ただし `supervisor` から `io` の辺が新たに要り、io の責務（バッチ write-back・フラッシュバリア・FS 正規化）の外になる。`RotatingFileSink` は core の `ContainerId`・`TraitError` に依存しており、型の切り離しの再設計も要る |
| 新しい crate | crate-naming.md の確定一覧（REPAIR-1・TASK-1.h1）を変える。オーナー判断事項 |
| 定数だけを共有 | 共有するのは 2 つの値だけで、依存辺の理由として弱い。両側に値を固定する試験が既にある |

## 挙動・検査の差

| 観点 | supervisor `RotatingFileSink` | platform-macos コンソールログ |
| ---- | ---- | ---- |
| 名前 | `<id>.log`・`<id>.log.N`・`<id>.log.lock` | 利用者指定のパス `<name>`・`<name>.N`・排他用 `<name>.0` |
| 回転の時点 | 稼働中にレコード単位で、上限を超える前に回転 | 起動直前に 1 回だけ。起動中は上限で切り区切り文を書く（ブートログの先頭を残す） |
| パスの検査 | ディレクトリの絶対パス・祖先の symlink と `..` の拒否・権限・名前空間の別名検査 | 保護入力（kernel・initrd・disk）との `(dev, ino)` 同一性・euid 所有・nlink・mode・親ディレクトリ・`O_NOFOLLOW` と FIFO 対策 |
| 排他 | `<id>.log.lock` の flock | `<name>.0` の lifecycle lock と、現在のログ・各世代の lock |
| エラー・可観測性 | `TraitError`（ERR-1） | `ConfigError` と stderr の lifecycle JSON（`rotate` / `remove`。REPAIR-4） |
| OS | 3 OS | unix 限定 |

共通にできるのは、世代番号の規則と「古い順に rename して送る」十数行のループだけである。これを両方の差に合わせて引数化すると、重複より大きな公開面が生まれ、改修の波及範囲を最小に保つ REPAIR-1 の趣旨に反する。共通化の過程で片側の検査（保護入力の照合、別名検査、Windows の ID 照合）を弱める退行の危険もある。

## 決定

共通化せず、2 か所のまま残す。両側の doc コメントに、値と番号規則が同じ別実装であることと本記録へのリンクを記す。

## 再評価条件

- 回転つきログの 3 つ目の実装が現れたとき
- core に OS 非依存の「ディレクトリハンドル相対の安全な open」の公開 API が設計されたとき（`rotating.rs` の未実装・制限と #1470 が挙げる部品。両者の自然な共有基盤になり得る）
- オーナーが、ログ回転を共通化する下位 crate の新設を判断したとき

その場合は別 issue で crate 境界を設計してから実装する。
