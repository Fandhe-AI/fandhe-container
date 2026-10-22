# start の事前検査への connect と SO_PEERCRED 照合（判断記録）

`start` の事前検査に systemd user マネージャの直結ソケットへの実 connect を足すか（D1）、connect 先の peer credential（`SO_PEERCRED`）を照合するか（D2）の判断材料を整理する（CORE-3・OCI-6・SUP-14。参照: CORE-4・CORE-10・REPAIR-3・REPAIR-5・CRI-2。#2448・#2158・#2421・#2434）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまで `start` は lstat による判定（`user_manager_env`）だけの現状を維持し、fail-closed（`FAILED_PRECONDITION`）を緩めない。判断の窓口は #2448（末尾「承認事項（判断シート）」）。

## 現状

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/supervisor/src/user_scope.rs` | `user_manager_env`（lstat・symlink を辿らない・euid 所有のソケット）と `probe_user_manager_socket`（`SOCK_NONBLOCK` の connect を期限まで繰り返す。結果は `Refused`／`TimedOut`／`Unsupported`／`Failed`）がある。判定は `start`・`doctor`・ベンチの 3 か所で共有する前提 |
| `crates/supervisor/src/start_client.rs` | `SupervisorLaunch::resolve` が spawn より前に `user_manager_env` だけを呼び、失敗は `FAILED_PRECONDITION`。plugin-cri の `start` も同じクライアントを使う（#2434）。1 行も報告が無いまま EOF の場合は `INTERNAL`＋`EOF_MESSAGE` で、supervisor の異常終了と systemd-run の失敗を区別できない |
| `crates/cli/src/doctor/user_scope_check.rs` | `doctor` だけが実 connect を行う（期限 1 秒）。`Refused` は Warning、期限切れ・試せなかった場合は判定不能の通知 |
| `benches/src/startup_latency/` | 起動 p95 ベンチ（TASK-190・CORE-10）も `user_manager_env` だけを使う |
| `crates/supervisor/src/sys/linux.rs` | `peer_credentials`（`getsockopt(SO_PEERCRED)`。制御チャネル #2058 向け）と `connect_unix_nonblocking` が既にある |

## D1: start に実 connect を足すか

利点: 死んだソケット（ファイルは残るが listener がいない）は現状 lstat を通過し、systemd-run の失敗が `INTERNAL`＋原因不明の文言になる。事前 connect なら spawn より前に固定文言の `FAILED_PRECONDITION` で原因を特定できる。

### 選択肢

- **A. 足さない（現状維持）**: 挙動・p95 の計測範囲とも変わらない。EOF の原因は区別できないまま
- **B. 足して、失敗しても通し op ログ（`FANDHE_CONTAINER_OP_LOG`。REPAIR-4）にだけ残す**: `start` の契約は「失敗時は stderr に 1 行の JSON、成功時は stdout に pid」で、警告の出し先は op ログしか無い。利用者には見えず、利点がほぼ残らない
- **C. 足して fail-closed にする（推奨案）**: 結果の写し方は次の表。

| 結果 | C の案 | 代案 |
| ---- | ------ | ---- |
| `Refused` | `FAILED_PRECONDITION` | なし |
| `TimedOut`（backlog 満杯） | `FAILED_PRECONDITION`（systemd-run も詰まり受信期限 58.9 秒を食うため） | 通す |
| `Unsupported`（`sun_path` 超過等） | 通して systemd-run に任せる | 止める |
| `Failed`（lstat と connect の間に消えた等） | 通して systemd-run に任せる | 止める |

### 付随する論点

- **期限（REPAIR-5）**: probe は spawn より前に動き、受信期限（`cli_receive_deadline`）の外にある。独自の上限が要る。`doctor` と同じ 1 秒なら、最悪で `start` が 1 秒延びる
- **共通化**: 足すと「3 か所で同じ判定」からずれる。ベンチにも足すなら起動 p95（CORE-10・`startup-latency-bench.md`）の計測範囲が変わる。足さないならずれを文書に残す
- **コスト**: `start` 1 回ごとに connect と close が 1 回増え p95 の経路に乗る。相手側では accept と EOF が観測されるだけでデータは送らない
- **波及**: `start_client` は共有クライアントなので plugin-cri の `start`（CRI-2）にも及ぶ

## D2: connect 先の SO_PEERCRED を照合するか

- **A. 照合しない（現状維持・推奨案）**
- **B. uid／gid が自ユーザーと一致するかを照合する**: `peer_credentials` が同じ crate の `sys` にあり、probe の `drop(stream)` の前に 1 回呼ぶだけで済む。新しい `unsafe` も unsafe の承認手続きも要らない。ただし lstat で確かめている「ソケットファイルが euid 所有」とほぼ重なり、同じ uid の書き手に対して権限の境界にならない
- **C. B に加えて pid から相手が systemd であることを確かめる**: `/proc/<pid>/comm` は同じ uid なら書き換えられる。`exe` の照合などの方式は**未検証**

**限界（TOCTOU）**: 実際にデータを送るのは systemd-run 自身の接続で、probe の接続で照合してもその経路は守れない。照合を足しても安全が保証されるとは書かない。

## 決定後の変更の棚卸し

- D1 = C: `start_client.rs`（`resolve` と試験）、`user_scope.rs`（doc）、`user_scope_check.rs`（`doctor` との重複の整理）、ベンチの `scope_wrap` と `startup-latency-bench.md`、plugin-cri の `start` への波及、`crates/cli/tests/binary_entry.rs` の結合試験。実装 issue の単位は CLI の `start`・`doctor`・結合試験
- D2 = B/C: `user_scope.rs` の probe と、その試験
- 新しい文言は既存の `message()` と同じ「値（パス・`XDG_RUNTIME_DIR`）を載せない固定の英語文言」の契約に従う

## 本書の時点で済ませたこと・残る作業

- 済み: 判断材料の整理と、コード中の「別判断」の参照先を本書と #2448 にそろえる doc コメントの更新（挙動の変更なし）
- 残る: D1・D2 の決定、#2448 への記録、決定に応じた実装 issue の起票（すべてオーナー判断待ち）

## 範囲外

`delete` が委譲スコープの検出に失敗したときに記録の経路へ回すかは、#2156 のオーナー判断（2026-10-17、案 A 現状維持）で決定済み。

## 承認事項（判断シート）

すべて**未決**。番号で答えられる。

- D1-1: start に実 connect を足すか（A 足さない／B 警告のみ／C fail-closed）
- D1-2: C の場合の `TimedOut` の扱い（止める／通す）
- D1-3: C の場合の `Unsupported`・`Failed` の扱い（通す／止める）
- D1-4: probe の期限（1 秒／その他）
- D1-5: ベンチ（`scope_wrap`）にも足すか、ずれを文書に残すか
- D2-1: SO_PEERCRED を照合するか（A しない／B uid・gid／C pid まで）
