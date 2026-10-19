# RootfulHostRoot の扱い（判断記録）

`IsolationPrivilege::RootfulHostRoot`（user namespace を作らず、ホスト root 権限のまま分離する権限モデル）を本番経路で許すかの判断材料を整理する（SEC-5・CORE-6。参照: CORE-7・CORE-9・SUP-14。#2241）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまで本番の launcher と supervisor は `Unimplemented` で拒否を続け、分離を緩めない（fail-closed）。関連: #2009・#2240・#2090。

## 現状

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/core/src/oci_runtime/start.rs` | user namespace の無い config を `PermissionDenied`・`"a user namespace is required (SEC-5)"` で拒否する。start を通る構成は `RootfulHostRoot` に到達しない |
| `crates/core/src/oci_runtime/launcher.rs` | `RootfulHostRoot` を fork より前に `Unimplemented`・`"the rootful privilege model is not supported by the launcher"` で拒否する |
| `crates/supervisor/src/start_entry.rs` | real / effective / saved / fs のいずれかの uid が 0 なら `Unimplemented`・`"rootful start is not supported by the production launcher"` で拒否する |
| `crates/core/src/exec.rs` | `plan_rootful_host_root` / `isolate_rootful_host_root` が下位 API として存在する。利用者は結合試験と CORE-7・CORE-9 の rootful 計測の構成 |
| `crates/core/src/cgroups/device_policy.rs` | `RootfulHostRoot` を `DevicePolicyMode::Rootful` へ写す |

どの段も fork より前に拒否し、プロセスも状態も残さない。SUP-14 の特権ランチャー（ambient capability）は uid が非 root のままなので `RootlessSingleId` に入り、`RootfulHostRoot` にはならない。

## 選択肢

### A. 本番経路では恒久的に拒否する（推奨）

- 理由: コンテナ内 root がホスト root そのものになり、SEC-5 の保護（非特権 UID への写像）が無い。権限昇格は SUP-14 の特権ランチャーで足り、uid 0 で動く本番経路は要らない。TASK-158 追補（#2090）も「supervisor は rootful の起動を拒否する」を前提にしている
- 決定後の変更: launcher と supervisor の code を `Unimplemented` から `PermissionDenied`（または `FailedPrecondition`）へ替え、固定文言を理由を述べる英語にする（値は含めない）。doc の「未実装」は「意図した拒否」に替える
- exec の下位 API の扱いは別の論点: (A-1) 結合試験・計測用に残し本番経路から呼ばない、(A-2) feature または `cfg(test)` の陰へ移す、(A-3) 削除する（`device_policy` と試験への波及がある）

### B. 条件つきで許す

- 必要な設計: 明示の opt-in、euid 0 の検証、`process.user` の扱い（user namespace が無く写像の照合ができない）、start の「user namespace 必須」との整合、capability・seccomp・Landlock は rootless と同等以上、デバイス cgroup は `DevicePolicyMode::Rootful`、SEC-4 の監査、CI の rootful 結合試験（現在は未検証）
- spec 側: SEC-5 の適用範囲の追記が要る。spec リポ側の課題としてオーナーへ報告する（本リポからは編集しない）

### C. 未決定のまま `Unimplemented` を続ける

本書時点の状態。

## 本書の時点で済ませたこと・残る作業

- 済み: コード中の参照先を本書と #2241 に統一、拒否が `process.user` の照合より前に来ることのテスト固定
- 残り: A なら code・文言・doc の変更（launcher・supervisor とテスト）と下位 API の扱い。B なら上記の設計と実装（後続 issue）

## 監査（SEC-4）

拒否は構成の選択であって脱出の試行ではないため、監査には記録しない。

## 関連文書

- [privilege-separation.md](privilege-separation.md)（SUP-14 の権限昇格方式）
