# RootfulHostRoot の扱い（判断記録）

`IsolationPrivilege::RootfulHostRoot`（user namespace を作らず、ホスト root 権限のまま分離する権限モデル）を本番経路で許すかの判断記録（SEC-5・CORE-6。参照: CORE-7・CORE-9・SUP-14。#2241）。

> **位置づけ**: **決定済み（2026-11-13。D1 A・D2 A・D3 A-1）**。本番経路は `RootfulHostRoot` を意図した恒久拒否（`PermissionDenied`。fail-closed）で扱う。#4709 でその拒否を `Unimplemented` から `PermissionDenied` へ替え、本書の「現状」を決定後の挙動に合わせた。判断の窓口は #2241（末尾の「判断事項（決定の記録）」）。関連: #2009・#2240・#2090・#4709。

## 現状

決定後の挙動（#4709）。どの段も fork より前に拒否し、コンテナのプロセスを新たに作らない（plugin-cri の supervised の start は、共有クライアントの権限検査を呼ぶ前に起動数の枠を一時的に予約し、拒否の後に解放する。その間は並行する start の上限の計算に数えられる）。ただし supervisor の bin を直接起動した場合は（CLI・plugin-cri の共有クライアントは起動前の `privilege_gate` で拒否するため当たらない）、対象のレコードがあると手順 2b（`crates/supervisor/src/start_entry.rs`）が手順 4 の権限の拒否より前に、状態ルート配下の supervisor のログの保存先を作りうる。

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/core/src/oci_runtime/start.rs` | user namespace の無い config を `PermissionDenied`・`"a user namespace is required (SEC-5)"` で拒否する。start を通る構成は `RootfulHostRoot` に到達しない |
| `crates/core/src/oci_runtime/launcher.rs` | `RootfulHostRoot` を fork より前に `PermissionDenied` で拒否する（方針による恒久拒否。固定文言は値を含まない）。この検査は `process.user` の照合より前に来る |
| `crates/core/src/oci_runtime/pod_holder.rs` | 保持役の入口の検査（副作用の前）で `RootfulHostRoot` を `PermissionDenied` で拒否する |
| `crates/supervisor/src/start_entry.rs` | real / effective / saved / fs のいずれかの uid が 0 なら `PermissionDenied` で拒否する（手順 4） |
| `crates/supervisor/src/start_client.rs` | 共有クライアントの `privilege_gate`。supervisor と同じ規則で uid 0 を `PermissionDenied` にする。読めない・壊れた入力は `FailedPrecondition`。CLI の `start` と plugin-cri の supervised の start が使う |
| `crates/cli/src/commands/supervisor_start.rs` | 権限の規則は共有クライアント側にある（上の行）。CLI の `start` は uid 0 で、権限モデルの検査に到達すれば終了コード 6（`PERMISSION_DENIED`。8 の `UNIMPLEMENTED` ではない）。それより先に返る前提エラー（対象 ID が無ければ `NOT_FOUND`、supervisor が未配置なら終了コード 5）は従来どおり |
| `crates/plugin-cri/src/pod_holder.rs` | `rootful_guard`: 実 uid か実効 uid が 0 の provider は `PermissionDenied` で拒否する。注入は実 uid か実効 uid が 0 なら行わない（`should_inject_pod_holder`） |
| `crates/cli/src/doctor/user_scope_check.rs` | 拒否ではない。root で実行すると user scope の検査を飛ばし、notice（「rootful start is not supported」を含む）で案内する |
| `crates/core/src/exec.rs` | `plan_rootful_host_root` / `isolate_rootful_host_root` が下位 API として存在する（D3 A-1）。本番経路は呼ばない。利用者は結合試験と CORE-7・CORE-9 の rootful 計測の構成 |
| `crates/core/src/cgroups/device_policy.rs` | `RootfulHostRoot` を `DevicePolicyMode::Rootful` へ写す（下位 API の計測用） |

SUP-14 の特権ランチャー（ambient capability）は uid が非 root のままなので `RootlessSingleId` に入り、`RootfulHostRoot` にはならない。

## 選択肢

決定前の比較と推奨の理由の記録。決定は A（2026-11-13）。

### A. 本番経路では恒久的に拒否する（決定）

- 理由: コンテナ内 root がホスト root そのものになり、SEC-5 の保護（非特権 UID への写像）が無い。権限昇格は SUP-14 の特権ランチャーで足り、uid 0 で動く本番経路は要らない。TASK-158 追補（#2090）も「supervisor は rootful の起動を拒否する」を前提にしている。`macos-shared-vm.md` も CLI の `privilege_gate` の拒否を「解除しない」と書いている
- 決定後の変更（一覧は「決定後の変更の棚卸し」。#4709 で code・試験・文書を済ませた）: launcher・supervisor・CLI の code を `Unimplemented` から `PermissionDenied` へ替え、固定文言を理由を述べる英語にする（値は含めない）。doc の「未実装」は「意図した拒否」に替える
- exec の下位 API の扱いは別の論点: (A-1) 結合試験・計測用に残し本番経路から呼ばない（決定）、(A-2) feature または `cfg(test)` の陰へ移す、(A-3) 削除（`device_policy` と試験への波及がある）

### B. 条件つきで許す（不採用）

- 必要な設計: 明示の opt-in、euid 0 の検証、`process.user` の扱い（user namespace が無く写像の照合ができない）、start の「user namespace 必須」との整合、capability・seccomp・Landlock は rootless と同等以上、デバイス cgroup は `DevicePolicyMode::Rootful`、SEC-4 の監査、CI の rootful 結合試験（現在は未検証）
- spec 側: SEC-5 の適用範囲の追記が要る。spec リポ側の課題としてオーナーへ報告する（本リポからは編集しない）

### C. 未決定のまま `Unimplemented` を続ける（不採用）

決定前（初版）の状態。2026-11-13 の決定により採らない。

## 決定後の変更の棚卸し

D1 A・D2 A・D3 A-1 に伴う変更。「済」は #4709 で完了したもの、「残」は未了のもの。

| 区分 | 箇所 | 状態 |
| ---- | ---- | ---- |
| code・文言 | `launcher.rs`・`start_entry.rs`・`start_client.rs`・core の `pod_holder.rs`・plugin-cri の `pod_holder.rs` の `rootful_guard` | 済（#4709）。固定文言は値を含まない英語。文言の最終調整は別途行うため、本書には逐語で載せない |
| 試験 | `launcher.rs`・`start_entry.rs`・`start_client.rs`・`supervisor_bin.rs` の rootful の期待値 | 済（#4709） |
| doc | `docs/design/cgroups.md` の rootful の行・`crates/core/src/lib.rs`・`launcher.rs` のモジュール doc・`exec.rs` の下位 API の記述 | 済（#4709） |
| doc | doctor の notice 文言（「rootful start is not supported」を含む）を変えるか | 残（変更の要否は未決） |
| doc | `docs/design/startup-latency-bench.md`・`docs/design/bench-calibration.md`・`scripts/bench/concurrent_50_memory.sh` の rootful への言及 | 残（#4709 の docs 更新では未確認） |
| 下位 API | `cgroups/device_policy.rs`（`DevicePolicyMode::Rootful`）・`crates/core/tests/namespace_isolation.rs`・`unshare_isolation.rs`・CORE-7・CORE-9 の rootful 計測 | 変更なし（D3 A-1 で残すため） |

本変更（#4709）の対象外で `Unimplemented` のまま（変えない）:

- uid 0 の `create` でユーザー定義ネットワーク・`-p` を指定した場合（終了コード 8。D13）
- rootful の network（user-defined network・`-p`・`up` の rootful）は D13（#3207）の判断待ちで `UNIMPLEMENTED`
- rootful の POD の PortForward は #4708 の持ち越しで、恒久的な拒否ではない（[cri-streaming-server.md](cri-streaming-server.md)）

## 経緯と残る作業

- 決定前（初版）に済んだこと: コード中の参照先を本書と #2241 に統一、拒否が `process.user` の照合より前に来ることのテスト固定、判断シートの整備（CLI の拒否と doctor の案内の追記、変更の棚卸しを含む）
- 2026-11-13 の決定と #4709: code・試験・文書を `PermissionDenied` の恒久拒否へ差し替え（上の棚卸しの「済」）
- 残り: 上の棚卸しの「残」の行。D13 待ちの rootful の network・`-p`・`up` は別判断で、本書の対象外

## 判断事項（決定の記録）

承認の窓口は #2241。2026-11-13 に以下を決定した。新しい判断事項はこの表に足さず、#2241 で扱う。

| 番号 | 判断事項 | 選択肢 | 推奨 | 影響 | 判断 |
| ---- | -------- | ------ | ---- | ---- | ---- |
| D1 | 本番の経路で `RootfulHostRoot` を許すか | A 恒久的に拒否 / B 条件つきで許す / C 未決のまま | A | A: 拒否は意図したものになる。B: 上記「必要な設計」を実装 issue に分ける（親 #2308）。C: `Unimplemented`（スタブ扱い）が続く | 決定: A（2026-11-13） |
| D2 | D1 が A のときの拒否の code | `PermissionDenied` / `FailedPrecondition` | `PermissionDenied`（構成の誤りではなく権限モデルの方針による拒否のため）。固定文言は理由を述べる英語にし、値は含めない | launcher・supervisor・CLI と試験の差し替え（棚卸しの表） | 決定: `PermissionDenied`（2026-11-13）。#4709 で反映 |
| D3 | D1 が A のときの exec の下位 API の扱い | A-1 結合試験・計測用に残す / A-2 feature か `cfg(test)` の陰へ移す / A-3 削除 | A-1 | A-2・A-3 は `device_policy`・`namespace_isolation`・`unshare_isolation`・CORE-7・CORE-9 の計測へ波及する | 決定: A-1（2026-11-13） |
| D4 | D1 が B のときだけ: spec の SEC-5 に適用範囲を追記するか | 追記する（spec リポ側の課題。本リポからは編集しない）/ 追記しない（= A） | なし（D1 に従属） | B の前提 | 決定: 追記しない（D1 = A のため。2026-11-13） |

## 監査（SEC-4）

拒否は構成の選択であって脱出の試行ではないため、監査には記録しない。

## 関連文書

- [privilege-separation.md](privilege-separation.md)（SUP-14 の権限昇格方式）
