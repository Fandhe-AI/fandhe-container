# 非 Linux の監査の記録経路（設計ドラフト）

`FileAuditSink` の主経路の隔離（Windows）と代替経路（非 Linux 全般）をどうするかを、同じ比較軸で並べた判断資料。

> **位置づけ**: **設計ドラフト・オーナー承認待ち**。実装は未着手で、本書は実装済みを意味しない（REPAIR-3）。本書は判断を代行せず、推奨は「推奨（承認待ち）」である。判断の記録と、判断に沿った実装 issue の起票は #2430 の受け入れ条件であり、未実施。

- 対象ビヘイビア: SEC-4（関連: REPAIR-3・REPAIR-5・CLI-1・OCI-5・WIN-1・MAC-4・PLUG-11）
- タスク: TASK-41 追補、#2430（親 #2247）
- 作成日: 2026-10-20
- 関連: #2018（配送経路の方式採用。[audit-delivery.md](audit-delivery.md)）・#2429（macOS の主経路）・#2428（Windows の `FileStateStore` の実装方式）・#2459（#2428 の判断資料）・#1415 / #1539（Windows 構成 C）・#2027（縮退の扱い）
- 出典: SSOT は `docs/spec` の `04-behavior/`（SEC-4 ほか）。本書は ID で参照し、長い引用はしない

## 1. 背景と現状

`FileAuditSink`（`crates/core/src/audit_log/file_sink.rs`）は、主経路（監査ファイルへの追記）を fork した使い捨て子プロセスで隔離して期限を付け（`run_isolated`。REPAIR-5）、失敗時は代替経路（`KernelAuditFallback`。NETLINK_AUDIT）へ回す。非 Linux では次の 3 か所が塞がっている。

| 箇所 | 非 Linux の現状 | 担当 |
| ---- | --------------- | ---- |
| `run_isolated`（主経路の隔離） | 常に失敗（`IsolationUnavailable`） | macOS は #2429、Windows は本書の論点 1 |
| `file_writer.rs` の `open_checked` | `Unsupported` | macOS は #2429（fd 相対 open は #1864） |
| `kernel_audit.rs`（代替経路） | `UnsupportedTransport` | 本書の論点 2 |

| 環境 | 拒否が起きる場所 | 現 main の記録先の状態 |
| ---- | ---------------- | ---------------------- |
| Linux | 同一ホストの seccomp・Landlock | 実装済み・一部未着手（audit-delivery.md） |
| macOS ホスト | ホスト側の層（plugin の信頼性検証・CLI）のみ | `FileStateStore` は通る（#2247）が記録は `SinkFailed` |
| macOS ゲスト VM | ゲストの Linux 内（seccomp・Landlock） | 本書の論点外（9 章） |
| Windows ホスト | ホスト側の層のみ（構成 C ではゲスト内の core が分離を担う。#1415・#1539） | `FileStateStore::open` が `Unimplemented`（#2428）で構築入口も fail-closed |
| WSL2 ゲスト | ゲスト内の Linux | Linux の実装がそのまま動く |

どの案でも、記録できないときに拒否が許可へ倒れない（`SinkFailed` で拒否を保つ。fail-closed）ことを前提とする。

## 2. 一次情報の確認状況

外部仕様は本書の作成時点で公式文書による再確認を行っていない。確認済みでない項目は確定扱いにせず、判断の前に確かめる。

| 項目 | 内容 | 状態 |
| ---- | ---- | ---- |
| Windows の Job Object | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` でハンドルを閉じると配下のプロセスが終了する | 見込み（Microsoft Learn で未確認） |
| Windows の I/O 取り消し | overlapped I/O は `CancelIoEx`、同期 I/O は `CancelSynchronousIo` で取り消せる。`FlushFileBuffers` が取り消せるかは不明 | 見込み・一部未確認 |
| Windows の Event Log / ETW | 書き込みの権限要件（セキュリティログは `SeAuditPrivilege`） | 見込み |
| macOS の unified logging | `os_log` は C マクロで、FFI から呼べる公開関数の入口があるか未確認。動的な値は `%{public}` を付けないと伏せられる | 見込み・未確認 |
| macOS の `syslog(3)` | unified logging へ流れる | 見込み |
| OpenBSM の `audit_submit(3)` | 監査の権限（root）が要る。Apple による非推奨化の有無と時期 | 未確認 |

## 3. 棚卸し（非 Linux から監査の記録先へ到達する呼び出し元）

origin/main の `git grep` による。

| 呼び出し元 | 内容 | 非 Linux での到達 |
| ---------- | ---- | ----------------- |
| `crates/cli/src/commands/plugin_backend.rs` | `FileAuditSink::open_in_state_root` を作り `verify_candidate_audited` に渡す | macOS は到達する（記録は `SinkFailed`）。Windows は `FileStateStore::open` が `Unimplemented` のため構築で fail-closed |
| `crates/supervisor/src/exec.rs` | `open_in_state_root`（supervisor はゲスト内の Linux で動く想定） | Windows ホスト・macOS ホストでは動かさない想定 |
| `crates/core/src/plugin_trust/report.rs` | `verify_candidate_audited` / `record_plugin_trust_rejection` | 上の CLI 経由 |

## 4. 論点 1: Windows の主経路の隔離

軸は、期限（REPAIR-5）・残留資源・依存と承認の要否・`unsafe` の置き場・試験のしやすさ・#2428 との整合。

| 案 | 内容 | 期限 | 依存・承認 | 課題 |
| -- | ---- | ---- | ---------- | ---- |
| **W-C（推奨・承認待ち）** | Windows ホストには監査の記録先を持たず、現状の fail-closed を保つ。記録はゲスト内の Linux 経路が担う | 該当なし | 追加なし | 前提は、ホスト CLI の `plugin_backend` 経路が `SinkFailed` で拒否を保つこと（3 章）。#2428 の案 C と整合 |
| W-P | 自分の exe（`current_exe()` と固定の隠しサブコマンド。`PATH` は探さない）を別プロセスで起動し、Job Object で期限後に終了させる。レコードは stdin で渡す | プロセス終了で強制 | core に `windows-sys` の依存辺（承認が要る。#2428 の案 A と同じ）か `sys/windows.rs` の自前宣言 | 起動コスト、exe の置き場所の信頼（PLUG-11 と同系統） |
| W-T | スレッド＋overlapped I/O＋`CancelIoEx`（同期 I/O は `CancelSynchronousIo`） | 取り消し | 同上 | Windows には「単一スレッドでないと fork できない」制約が無く、Linux でスレッドを避けた理由は当てはまらない。取り消せない I/O ではスレッドが残る（上限の設計が要る） |
| 不採用 | 隔離しない同期書き込み | なし | - | REPAIR-5 に反する |

**#2428 と同時に判断するよう勧める**（W-C を採るなら #2428 も案 C が自然）。

## 5. 論点 2: 非 Linux の代替経路

軸は、権限・改ざん耐性・主経路と別の故障経路になるか・依存と FFI・期限・記録の機密。

| 案 | 内容 | 評価 |
| -- | ---- | ---- |
| **N-0（推奨・承認待ち）** | 代替経路を持たず、監査ファイル（主経路）だけにする。両方失敗したときと同じく固定スキーマの stderr 通知と `INTERNAL`（`SinkFailed`）で扱い、拒否は覆らない | macOS ホストで記録が要るのはホスト側の層（plugin 信頼検証）だけで件数が少なく、独立した経路を足す利点が小さい。依存・FFI の追加なし |
| N-L | macOS の unified logging（`os_log` / `syslog(3)`） | 非特権で書け、ストレージ停止と別の故障経路になる見込み。改ざん耐性・保持期間はファイルと同程度か短い見込み。`sys/macos.rs` の FFI で足りれば新規 crate は不要（事前承認の `sys` の範囲。入口がマクロかの確認が先）。外部由来の値のエスケープと、固定書式（`%{public}s`）が要る。件数の上限（レート制限）の要否も書く |
| N-B | BSM（OpenBSM の `audit_submit`） | root が要り rootless の CLI では使えない。非推奨化が一次資料で確かめられれば不採用とし出典を書く |
| N-E | Windows の Event Log / ETW | W-C を採るなら不要 |

## 6. 承認事項

1. 論点 1 の選択（W-C / W-P / W-T）
2. 論点 2 の選択（N-0 / N-L / N-B）
3. W-P または W-T を採る場合の core の Win32 FFI の方式（`windows-sys =0.61.2` の依存辺〔feature を絞る〕か `sys` の自前宣言か。依存の追加は別の承認事項に分ける）
4. N-0 を採る場合に、縮退を表示へ出すか（#2027 の語彙に載せるか）
5. #2428 との同時判断

## 7. 判断後の実装 issue 案（起票はしない）

いずれの案も #2247 の受け入れ条件 2（非 Linux で拒否の記録が残る、または残せない旨が明示される）との対応を本文に書く。

- W-C: 「test(core): Windows ホストの CLI から監査の記録先に到達しないこと（`SinkFailed` で拒否を保つこと）を機械照合する」と doc の更新。依存: #2428
- W-P / W-T: 「feat(core): Windows の主経路の隔離を実装する」。受け入れ条件は期限内の打ち切りと残留資源の上限の試験。依存: #2428・FFI 方式の承認
- N-0: 「docs/test(core): 非 Linux の代替経路なしを doc と試験で固定し、縮退の表示を足す」。依存: #2429・#2027
- N-L: 「feat(core): macOS の代替経路（unified logging）を `KernelAuditFallback` と同じ trait の差し替えで実装する」。対象は `kernel_audit.rs` の非 Linux 分岐。依存: #2429

## 8. 残余とセキュリティ上の論点

- 代替経路（os_log・syslog・Event Log）へ書く値（パス・plugin 名）は untrusted で、エスケープし、書式文字列に外部の値を渡さない
- W-P は exe の解決に `PATH` を使わず、`current_exe()` の隣の固定名に限り、置き場所の書き込み権限を検証する（PLUG-11 と同系統）
- 無制限の出力による DoS を避けるため、件数の上限を持つ
- rootless では改ざん耐性が無いという既存の限界（`file_sink.rs` の SEC-5 の記述）は変わらない
- 権限を広げる案（`SeAuditPrivilege`・root の付与）は承認事項として分ける
- 依存の追加は本書では行わない（`=x.y.z` 固定・ユーザー承認制）

## 9. 論点外

- macOS の主経路（`open_checked`・`run_isolated` の macOS 版）は #2429、Windows の `FileStateStore` は #2428 が担う
- macOS ゲスト VM 内（Linux）の監査記録をホストへ持ち出して保存するか（MAC-4）は本 issue の論点外。追跡する issue は未起票で、起票の要否はオーナーの判断を要する
