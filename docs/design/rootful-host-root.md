# RootfulHostRoot の扱い（判断記録）

`IsolationPrivilege::RootfulHostRoot`（user namespace を作らず、ホスト root 権限のまま分離する権限モデル）を本番経路で許すかの判断材料を整理する（SEC-5・CORE-6。参照: CORE-7・CORE-9・SUP-14。#2241）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまで本番の launcher・supervisor・CLI は `Unimplemented` で拒否を続け、分離を緩めない（fail-closed）。判断の窓口は #2241（open のまま。末尾近くの「承認事項（判断シート）」）。関連: #2009・#2240・#2090。

## 現状

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/core/src/oci_runtime/start.rs` | user namespace の無い config を `PermissionDenied`・`"a user namespace is required (SEC-5)"` で拒否する。start を通る構成は `RootfulHostRoot` に到達しない |
| `crates/core/src/oci_runtime/launcher.rs` | `RootfulHostRoot` を fork より前に `Unimplemented`・`"the rootful privilege model is not supported by the launcher"` で拒否する |
| `crates/supervisor/src/start_entry.rs` | real / effective / saved / fs のいずれかの uid が 0 なら `Unimplemented`・`"rootful start is not supported by the production launcher"` で拒否する |
| `crates/cli/src/commands/supervisor_start.rs` | `privilege_gate` が、real / effective / saved / fs のいずれかの uid が 0 なら supervisor と同じ文言で `Unimplemented` にする。読めない・壊れた入力は `FailedPrecondition` |
| `crates/cli/src/doctor/user_scope_check.rs` | 拒否ではない。root で実行すると user scope の検査を飛ばし、notice `USER_SCOPE_CHECK_SKIPPED_AS_ROOT`（「rootful start is not supported」）で案内する |
| `crates/core/src/exec.rs` | `plan_rootful_host_root` / `isolate_rootful_host_root` が下位 API として存在する。利用者は結合試験と CORE-7・CORE-9 の rootful 計測の構成 |
| `crates/core/src/cgroups/device_policy.rs` | `RootfulHostRoot` を `DevicePolicyMode::Rootful` へ写す |

どの段も fork より前に拒否し、プロセスも状態も残さない。SUP-14 の特権ランチャー（ambient capability）は uid が非 root のままなので `RootlessSingleId` に入り、`RootfulHostRoot` にはならない。

## 選択肢

### A. 本番経路では恒久的に拒否する（推奨）

- 理由: コンテナ内 root がホスト root そのものになり、SEC-5 の保護（非特権 UID への写像）が無い。権限昇格は SUP-14 の特権ランチャーで足り、uid 0 で動く本番経路は要らない。TASK-158 追補（#2090）も「supervisor は rootful の起動を拒否する」を前提にしている。`macos-shared-vm.md` も CLI の `privilege_gate` の拒否を「解除しない」と書いている
- 決定後の変更（一覧は「決定後の変更の棚卸し」）: launcher・supervisor・CLI の code を `Unimplemented` から `PermissionDenied`（または `FailedPrecondition`）へ替え、固定文言を理由を述べる英語にする（値は含めない）。doc の「未実装」は「意図した拒否」に替える
- exec の下位 API の扱いは別の論点: (A-1) 結合試験・計測用に残し本番経路から呼ばない、(A-2) feature または `cfg(test)` の陰へ移す、(A-3) 削除する（`device_policy` と試験への波及がある）

### B. 条件つきで許す

- 必要な設計: 明示の opt-in、euid 0 の検証、`process.user` の扱い（user namespace が無く写像の照合ができない）、start の「user namespace 必須」との整合、capability・seccomp・Landlock は rootless と同等以上、デバイス cgroup は `DevicePolicyMode::Rootful`、SEC-4 の監査、CI の rootful 結合試験（現在は未検証）
- spec 側: SEC-5 の適用範囲の追記が要る。spec リポ側の課題としてオーナーへ報告する（本リポからは編集しない）

### C. 未決定のまま `Unimplemented` を続ける

本書時点の状態。

## 決定後の変更の棚卸し

A を選んだ場合に触れる箇所（本書の時点では何も変えていない）。

| 区分 | 箇所 |
| ---- | ---- |
| code・文言 | `launcher.rs`・`start_entry.rs`（`privilege_for_status`）・CLI の `privilege_gate` |
| 試験 | `launcher.rs`（2434・2442 行付近）・`start_entry.rs`（3054 行付近）・`crates/supervisor/tests/supervisor_bin.rs`（169 行付近）・`supervisor_start.rs`（682 行付近） |
| doc | `docs/design/cgroups.md` の rootful の行の code、`crates/core/src/lib.rs`・`launcher.rs` のモジュール doc・`exec.rs` の「未実装」の言い回し、doctor の notice 文言を変えるか |
| ベンチ関連 | `docs/design/startup-latency-bench.md`・`docs/design/bench-calibration.md`・`scripts/bench/concurrent_50_memory.sh` の rootful への言及の見直し |
| 下位 API の影響 | `cgroups/device_policy.rs`（`DevicePolicyMode::Rootful`）・`crates/core/tests/namespace_isolation.rs`・`unshare_isolation.rs`・CORE-7・CORE-9 の rootful 計測。A-3（削除）だと影響が最も大きい |

B を選んだ場合は、選択肢 B の「必要な設計」を設計 issue と実装 issue に分け、親 #2308 の配下に起票する。

## 本書の時点で済ませたこと・残る作業

- 済み: コード中の参照先を本書と #2241 に統一、拒否が `process.user` の照合より前に来ることのテスト固定、判断シートの整備（本書。CLI の拒否と doctor の案内の追記、変更の棚卸しを含む）
- 残り: A なら code・文言・doc の変更（launcher・supervisor とテスト）と下位 API の扱い。B なら上記の設計と実装（後続 issue）

## 承認事項（判断シート）

承認の窓口は #2241。すべて**未決**（承認済みのものは無い）。返信は「D1: 推奨どおり / D2: …」のように番号で答えられる。

| 番号 | 判断事項 | 選択肢 | 推奨 | 影響 | 判断 |
| ---- | -------- | ------ | ---- | ---- | ---- |
| D1 | 本番の経路で `RootfulHostRoot` を許すか | A 恒久的に拒否 / B 条件つきで許す / C 未決のまま | A | A: 拒否は変わらず意図したものになる。B: 上記「必要な設計」を実装 issue に分ける（親 #2308）。C: `Unimplemented`（スタブ扱い）が続く | 未決 |
| D2 | D1 が A のときの拒否の code | `PermissionDenied` / `FailedPrecondition` | `PermissionDenied`（構成の誤りではなく権限モデルの方針による拒否のため）。固定文言は理由を述べる英語にし、値は含めない | launcher・supervisor・CLI と試験の差し替え（棚卸しの表） | 未決 |
| D3 | D1 が A のときの exec の下位 API の扱い | A-1 結合試験・計測用に残す / A-2 feature か `cfg(test)` の陰へ移す / A-3 削除 | A-1 | A-2・A-3 は `device_policy`・`namespace_isolation`・`unshare_isolation`・CORE-7・CORE-9 の計測へ波及する | 未決 |
| D4 | D1 が B のときだけ: spec の SEC-5 に適用範囲を追記するか | 追記する（spec リポ側の課題。本リポからは編集しない）/ 追記しない（= A） | なし（D1 に従属） | B の前提 | 未決 |

決まった後の作業は上記の棚卸しのとおり。この文書の更新時点では、コードの変更も issue の起票も行っていない。

## 監査（SEC-4）

拒否は構成の選択であって脱出の試行ではないため、監査には記録しない。

## 関連文書

- [privilege-separation.md](privilege-separation.md)（SUP-14 の権限昇格方式）
