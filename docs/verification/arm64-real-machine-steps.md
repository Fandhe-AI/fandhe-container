# arm64 の Linux での実機前提ステップの確認記録

`platform-ci` の実機前提のステップ（AppArmor の緩和以降の `--ignored` のステップ）を、`ubuntu-24.04-arm` の leg でも回せるかを `workflow_dispatch` で 1 回確かめた記録（#4810・REPAIR-7・REPAIR-5）。arm64 の leg そのものは #4807 で足した（実機前提でないステップだけ。`.claude/rules/ci.md`「arm64 の Linux の leg」）。

広げること自体（`ci.yml` の変更）は本記録の範囲に入れない。広げる案は #4810 のコメントでオーナーの判断を求めた。

## 実行の条件

| 項目 | 値 |
| ---- | -- |
| run | [44467915141](https://github.com/Fandhe-AI/fandhe-container/actions/runs/44467915141)（job 135370065675・2026-11-19） |
| ref | 検証用ブランチ `probe/4810-arm64-real-machine`（commit `e854bf4f`。親は main の `93d9f6e7`）。マージしない。記録の参照先として残す |
| 検証用の変更 | `ci.yml` だけ。(1) `platform-ci` の matrix を `ubuntu-24.04-arm` の 1 要素にする、(2) AppArmor の緩和以降の `matrix.os == 'ubuntu-latest' && env.HANG_PROBE != 'true'` の 117 か所（うち 1 か所は繰り返しステップの複合条件の中）を `!cancelled() && env.HANG_PROBE != 'true'` にする（途中で落ちても後続を回して全ステップの結果を得るため）、(3) ジョブ上限を 180 分にする |
| runner イメージ | `ubuntu-24.04-arm`（Version 20261111.182.1） |
| カーネル | `7.0.0-1017-azure` |
| Landlock ABI | 8（試験出力 `landlock_enforcement child: abi=8`） |

## 前提の確認結果

| 前提 | 結果 | 根拠 |
| ---- | ---- | ---- |
| パスワード無しの sudo | 満たす | AppArmor の緩和ステップの `sudo sysctl` が成功 |
| AppArmor の緩和（`kernel.apparmor_restrict_unprivileged_userns`） | 満たす | 緩和後の値 0 |
| uidmap・subuid / subgid の行・`systemd --user` の委譲 cgroup・Landlock ABI 6 以上 | 満たす | 「範囲写像と委譲 cgroup の前提確認（sudo なし）」ステップ（fail-closed）が成功 |
| containerd の既定導入物（`/usr/bin/containerd`・`/usr/bin/ctr`。major 2 以上・root 所有） | 満たす | `shim_v2_containerd_real` のビルドステップの検査が成功（版は Step Summary にだけ出るため本記録には写していない） |
| Docker Hub の匿名 pull の残量 | 満たす | 事前プローブ `ok remaining=100 limit=100 min=4`。arm64 の busybox を pull して試験が通った |
| pasta | 対象外 | x86_64 の ubuntu でも `pasta_rootless`・`pasta_launch_rootless` は CI で回していない（#341）。arm64 でも同じく ignored |

## ステップごとの結果

AppArmor の緩和から `production_binary_attach_real` の実行までの区間は 117 ステップで、実機前提のステップ 116 件がすべて成功した。残り 1 件（110 の「委譲スコープでの試験の繰り返し」）は `repeat-user-scope` を指定した dispatch 専用で、本 run では skipped（x86_64 の run でも同じ）。arm64 だけで落ちた試験は無く、起票した issue は無い。

秒はステップの開始から終了まで（GitHub の記録の秒単位）。ビルドの多くは前段の結合試験のビルドで済んでいるため短い。

| # | ステップ | 結果 | 秒 |
| - | -------- | ---- | -- |
| 61 | AppArmor の非特権 user namespace 制限を緩和（unshare_isolation 用・Linux のみ。CORE-1・SEC-5） | success | 0 |
| 62 | unshare_isolation のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 9 |
| 63 | unshare_isolation の実行（実機前提テスト・--ignored。CORE-1・SEC-5・TASK-27.2） | success | 1 |
| 64 | exec_setns_join のビルド（Linux のみ。SUP-6・TASK-163.1） | success | 12 |
| 65 | exec_setns_join の実行（実機前提テスト・--ignored。SUP-6・TASK-163.1） | success | 1 |
| 66 | exec のビルド（Linux のみ。実行は実機前提。SUP-6・TASK-163.4） | success | 1 |
| 67 | container_options_ipc のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 68 | container_options_ipc の実行（実機前提テスト・--ignored。SUP-12・TASK-169.3） | success | 1 |
| 69 | tmpfs_mount のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 70 | tmpfs_mount の実行（実機前提テスト・--ignored。SUP-12・TASK-169.2） | success | 1 |
| 71 | exec_child_setup のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 72 | exec_child_setup の実行（実機前提テスト・--ignored。SUP-6・SEC-1・#2885） | success | 1 |
| 73 | readonly_paths のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 74 | readonly_paths の実行（実機前提テスト・--ignored。SEC-2・#1850） | success | 1 |
| 75 | config_paths_implicit_dev のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 76 | config_paths_implicit_dev の実行（実機前提テスト・--ignored。SEC-2・#2015） | success | 1 |
| 77 | sysfs_mount のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 78 | sysfs_mount の実行（実機前提テスト・--ignored。SEC-2・SEC-1・#2305・#2533） | success | 1 |
| 79 | inject_files のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 80 | inject_files の実行（実機前提テスト・--ignored。SUP-12・TASK-169.4.2） | success | 1 |
| 81 | etc_files_mount のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 82 | etc_files_mount の実行（実機前提テスト・--ignored。NET-12・#1872） | success | 1 |
| 83 | bind_mounts_real のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 84 | bind_mounts_real の実行（実機前提テスト・--ignored。SEC-1・SEC-5・#1916） | success | 2 |
| 85 | lo_self_delivery のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 86 | lo_self_delivery の実行（実機前提テスト・--ignored。NET-2・NET-11・#2077） | success | 3 |
| 87 | netns_holder_userns のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 88 | netns_holder_userns の実行（実機前提テスト・--ignored。NET-9・CORE-6・#3197） | success | 1 |
| 89 | netns_dial_userns のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 90 | netns_dial_userns の実行（実機前提テスト・--ignored。CRI-6・NET-3・SEC-1・#4479・#4480） | success | 1 |
| 91 | netns_holder_launch_userns のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 92 | netns_holder_launch_userns の実行（実機前提テスト・--ignored。NET-9・CORE-1・#3198） | success | 1 |
| 93 | pod_holder のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 94 | pod_holder の実行（実機前提テスト・--ignored。CRI-2・CORE-3・SEC-5・#2875） | success | 1 |
| 95 | pod_holder_bin_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 96 | pod_holder_bin_real の実行（実機前提テスト・--ignored。CRI-2・CORE-1・SEC-5・#2875） | success | 3 |
| 97 | pod_holder_provider_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 33 |
| 98 | pod_holder_provider_real の実行（実機前提テスト・--ignored。CRI-2・CORE-1・SEC-5・#2877） | success | 2 |
| 99 | runtime_service_namespaces のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 100 | runtime_service_namespaces の実行（実機前提テスト・--ignored。CRI-2・TASK-59.2・TASK-59.3） | success | 1 |
| 101 | sec1_2536_protected_root_on_real_overlay のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 26 |
| 102 | sec1_2536_protected_root_on_real_overlay の実行（実機前提テスト・--ignored。SEC-1・OCI-4・SEC-5・#2536） | success | 1 |
| 103 | sec1_2823_overmount_hides_child_in_real_namespace の実行（実機前提テスト・--ignored。SEC-1・CORE-2・#2823） | success | 1 |
| 104 | net3_2872_real_holder_net_join_identity_and_ownership の実行（実機前提テスト・--ignored。NET-3・SEC-5・#2872・#2875） | success | 1 |
| 105 | gpu cdi hooks の namespace 試験のビルド（バイナリの特定。GPU-2・SEC-1・#2987） | success | 5 |
| 106 | gpu cdi hooks の namespace 試験の実行（実機前提テスト・--ignored。GPU-2・SEC-1・#2987） | success | 1 |
| 107 | net の socket 世代の namespace 試験のビルド（バイナリの特定。NET-3・SEC-1・#3356） | success | 12 |
| 108 | net の socket 世代の namespace 試験の実行（実機前提テスト・--ignored。NET-3・SEC-1・#3068・#3356） | success | 1 |
| 109 | 範囲写像と委譲 cgroup の前提確認（sudo なし。CORE-6・SEC-5・#2376） | success | 0 |
| 110 | 委譲スコープでの試験の繰り返し（workflow_dispatch のみ。#2886） | skipped | 0 |
| 111 | userns_extract のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 10 |
| 112 | userns_extract の実行（実機前提テスト・--ignored。OCI-2・SEC-5・#2542・#2642） | success | 1 |
| 113 | image_store_xdev のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 114 | image_store_xdev の実行（実機前提テスト・--ignored。OCI-7・SEC-1・ERR-1・#2701） | success | 1 |
| 115 | staged_blob_owner のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 116 | staged_blob_owner の実行（実機前提テスト・--ignored。OCI-7・SEC-1・SEC-5・#2907） | success | 1 |
| 117 | userns_helper_real のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 118 | userns_helper_real の実行（実機前提テスト・--ignored。SEC-5・OCI-2・OCI-7・#4802） | success | 1 |
| 119 | landlock_implicit_dev のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 120 | landlock_implicit_dev の実行（実機前提テスト・--ignored。CORE-5・SEC-4・#1657・#2768） | success | 1 |
| 121 | fork_exec_isolation のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 122 | fork_exec_isolation の実行（実機前提テスト・--ignored。CORE-1・CORE-5・#3295） | success | 1 |
| 123 | capabilities のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 124 | capabilities の実行（実機前提テスト・--ignored。SEC-1・CORE-5・#3422） | success | 1 |
| 125 | escape_suite のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 126 | escape_suite の実行（実機前提テスト・--ignored。SEC-2・SEC-4・SEC-5・CORE-5・#2016） | success | 1 |
| 127 | production_launcher のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 128 | production_launcher の実行（実機前提テスト・--ignored・委譲スコープ。CORE-6・SEC-5・#2376） | success | 5 |
| 129 | exec_subordinate_e2e のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 130 | exec_subordinate_e2e の実行（実機前提・--ignored・委譲スコープ。SEC-5・SEC-1・SEC-4・#2835・#3291） | success | 1 |
| 131 | exec_launch_netns_rootless のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 132 | exec_launch_netns_rootless の実行（実機前提・--ignored・委譲スコープ。SUP-6・NET-9・CORE-6・#3349） | success | 1 |
| 133 | rootless_file_owner のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 134 | rootless_file_owner の実行（実機前提テスト・--ignored。CORE-6・SEC-5・TASK-40.3・#2376） | success | 4 |
| 135 | rootless_holder_expiry のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 136 | rootless_holder_expiry の実行（実機前提テスト・--ignored。CORE-6・SEC-5・#2551） | success | 5 |
| 137 | rootless_holder_memory のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 138 | rootless_holder_memory の実行（実機前提テスト・--ignored。CORE-6・SEC-5・#2628） | success | 1 |
| 139 | rootless_image_rootfs_remove のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 140 | rootless_image_rootfs_remove の実行（実機前提テスト・--ignored。OCI-7・SEC-5・#2540） | success | 2 |
| 141 | seccomp のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 0 |
| 142 | seccomp の実行（実機前提テスト・--ignored。CORE-5・TASK-38.4・#179・#2376） | success | 1 |
| 143 | rootless_launch・rootless・rootless_uid_mapping のビルド（実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 144 | rootless_launch の実行（実機前提テスト・--ignored。CORE-6・SEC-1・SEC-5・#2596） | success | 1 |
| 145 | rootless の実行（実機前提テスト・--ignored。CORE-6・SEC-1・SEC-5・#2596） | success | 4 |
| 146 | rootless_uid_mapping の実行（実機前提テスト・--ignored。CORE-6・SEC-5・ESC-09・#2596） | success | 4 |
| 147 | healthcheck_exec_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 148 | healthcheck_exec_real の実行（実機前提テスト・--ignored。SUP-4・SUP-6・REPAIR-5・#2441） | success | 3 |
| 149 | stream_exec_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 150 | stream_exec_real の実行（実機前提テスト・--ignored。SUP-6・SEC-1・REPAIR-5・#3760） | success | 4 |
| 151 | supervisor_bin_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 1 |
| 152 | supervisor_bin_real の実行（実機前提テスト・--ignored。SUP-1・SUP-4・CORE-6・ESC-03・#2596） | success | 23 |
| 153 | start_stop_delete_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 15 |
| 154 | start_stop_delete_real の実行（実機前提テスト・--ignored・委譲スコープ。CLI-1・SUP-4・SEC-1・#2596・#2833・#3097） | success | 2 |
| 155 | network_modes_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 156 | network_modes_real の実行（実機前提テスト・--ignored・委譲スコープ。NET-6・NET-12・CLI-1・#3345） | success | 2 |
| 157 | local_image_gc のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 158 | local_image_gc の実行（実機前提テスト・--ignored・委譲スコープ。OCI-7・CLI-1・#663） | success | 3 |
| 159 | local_image_gc の 50 並行の実行（実機前提テスト・--ignored --scenario concurrent・委譲スコープ。OCI-7・#868） | success | 16 |
| 160 | local_image_gc のクラッシュ復旧の実行（実機前提テスト・--ignored --scenario crash・委譲スコープ。OCI-7・#667） | success | 7 |
| 161 | 委譲 cgroup の CLI 実機前提テスト 3 本のビルド（バイナリの特定。実行の時間枠を消費しないよう分離） | success | 1 |
| 162 | start_scope_real の実行（実機前提テスト・--ignored・包まない。CORE-3・CORE-4・SUP-1・CLI-1・#2081・#3105） | success | 1 |
| 163 | delete_cgroup_real の実行（実機前提テスト・--ignored・委譲スコープ。OCI-6・CORE-3・SEC-1・#2061・#3105） | success | 1 |
| 164 | start_recover_real の実行（実機前提テスト・--ignored・委譲スコープ。CORE-2・SEC-1・OCI-6・#2011・#3105） | success | 1 |
| 165 | shim_v2_kill_all_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 166 | shim_v2_kill_all_real の実行（実機前提テスト・--ignored・委譲スコープ。CRI-5・CORE-4・REPAIR-12・#4055） | success | 2 |
| 167 | shim_v2_exec_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 168 | shim_v2_exec_real の実行（実機前提テスト・--ignored・委譲スコープ。CRI-5・SEC-1・REPAIR-12・#4150） | success | 2 |
| 169 | shim_v2_containerd_real のビルド（前提確認とバイナリの特定。CRI-5・TASK-62.6・#4104） | success | 11 |
| 170 | shim_v2_containerd_real の実行（実機前提テスト・--ignored・委譲スコープ。CRI-5・CRI-7・PLUG-1・TASK-62.6・#4104） | success | 2 |
| 171 | Docker Hub の匿名 pull 残量の確認（production_binary_full_lifecycle_real の前提。CRI-3・#2818・#3312） | success | 0 |
| 172 | production_binary_full_lifecycle_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 6 |
| 173 | container_grpc の実機前提試験 2 件の実行（--ignored・委譲スコープ。CRI-2・CRI-3・PLUG-1・#2818・#3225） | success | 12 |
| 174 | production_binary_exec_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 3 |
| 175 | production_binary_exec_real の実行（--ignored・委譲スコープ。CRI-6・SEC-1・REPAIR-12・#3762） | success | 29 |
| 176 | production_binary_attach_real のビルド（バイナリの特定。実行タイムアウトの時間枠を消費しないよう分離） | success | 2 |
| 177 | production_binary_attach_real の実行（--ignored・委譲スコープ。CRI-6・SUP-4・SEC-1・REPAIR-12・#4079） | success | 6 |

## 成功行の照合

`scripts/check-success-lines.sh` の `<name> verified (<n> lines)` は 71 件で、x86_64 の ubuntu の次の 2 つの run と、試験名・行数・順序まで一致した。

- PR #4887 の run [44465830440](https://github.com/Fandhe-AI/fandhe-container/actions/runs/44465830440)（job 135363266020。`93d9f6e7` の上の PR。下の所要時間の比較もこの run）
- 検証用ブランチの親と同じ commit の main の run [44453328174](https://github.com/Fandhe-AI/fandhe-container/actions/runs/44453328174)（job 135322473667）

| # | 試験 | 照合行数 |
| - | ---- | -------- |
| 1 | `unshare_isolation` | 2 |
| 2 | `exec_setns_join` | 6 |
| 3 | `container_options_ipc` | 1 |
| 4 | `tmpfs_mount` | 1 |
| 5 | `exec_child_setup` | 2 |
| 6 | `readonly_paths` | 1 |
| 7 | `config_paths_implicit_dev` | 1 |
| 8 | `sysfs_mount` | 1 |
| 9 | `sysfs_mount` | 1 |
| 10 | `sysfs_mount` | 1 |
| 11 | `inject_files` | 1 |
| 12 | `etc_files_mount` | 1 |
| 13 | `bind_mounts_real` | 1 |
| 14 | `lo_self_delivery` | 1 |
| 15 | `netns_holder_userns` | 1 |
| 16 | `netns_dial_userns` | 6 |
| 17 | `netns_holder_launch_userns` | 1 |
| 18 | `pod_holder` | 2 |
| 19 | `pod_holder_bin_real` | 8 |
| 20 | `pod_holder_provider_real` | 7 |
| 21 | `runtime_service_namespaces` | 2 |
| 22 | `sec1_2536_protected_root_on_real_overlay` | 1 |
| 23 | `sec1_2823_overmount_hides_child_in_real_namespace` | 2 |
| 24 | `net3_2872_real_holder_net_join_identity_and_ownership` | 3 |
| 25 | `gpu_cdi_hooks_ns` | 2 |
| 26 | `net_socket_generation_ns` | 1 |
| 27 | `userns_extract` | 8 |
| 28 | `image_store_xdev` | 5 |
| 29 | `staged_blob_owner` | 6 |
| 30 | `userns_helper_real` | 5 |
| 31 | `landlock_implicit_dev` | 1 |
| 32 | `fork_exec_isolation` | 1 |
| 33 | `capabilities` | 2 |
| 34 | `escape_suite` | 1 |
| 35 | `production_launcher` | 26 |
| 36 | `production_launcher` | 9 |
| 37 | `production_launcher` | 2 |
| 38 | `production_launcher` | 2 |
| 39 | `production_launcher` | 1 |
| 40 | `exec_subordinate_e2e` | 5 |
| 41 | `exec_launch_netns_rootless` | 5 |
| 42 | `rootless_file_owner` | 2 |
| 43 | `rootless_holder_expiry` | 1 |
| 44 | `rootless_holder_memory` | 1 |
| 45 | `rootless_image_rootfs_remove` | 12 |
| 46 | `seccomp` | 2 |
| 47 | `rootless_launch` | 2 |
| 48 | `rootless` | 3 |
| 49 | `rootless_uid_mapping` | 4 |
| 50 | `rootless_uid_mapping` | 1 |
| 51 | `healthcheck_exec_real` | 2 |
| 52 | `stream_exec_real` | 12 |
| 53 | `supervisor_bin_real` | 12 |
| 54 | `supervisor_bin_real` | 1 |
| 55 | `start_stop_delete_real` | 8 |
| 56 | `network_modes_real` | 5 |
| 57 | `local_image_gc` | 13 |
| 58 | `local_image_gc_concurrent` | 8 |
| 59 | `local_image_gc_crash` | 4 |
| 60 | `start_scope_real` | 1 |
| 61 | `delete_cgroup_real` | 1 |
| 62 | `start_recover_real` | 1 |
| 63 | `shim_v2_kill_all_real` | 3 |
| 64 | `shim_v2_exec_real` | 4 |
| 65 | `shim_v2_containerd_real` | 2 |
| 66 | `production_binary_full_lifecycle_real` | 2 |
| 67 | `production_binary_exec_real` | 1 |
| 68 | `production_binary_exec_real_pod_net` | 2 |
| 69 | `production_binary_exec_real_pod_forward` | 5 |
| 70 | `production_binary_exec_real_pod_pid` | 5 |
| 71 | `production_binary_attach_real` | 1 |

## 所要時間

| 区間 | arm64（本記録の run） | x86_64 の ubuntu（PR #4887 の run） |
| ---- | --------------------- | ----------------------------------- |
| 実機前提のステップ（AppArmor の緩和の開始から `production_binary_attach_real` の実行の終了まで） | 372 秒 | 293 秒 |
| ジョブ全体 | 2439 秒（40.6 分） | 1580 秒（26.3 分。ジョブ上限 35 分） |

- main の push の `platform-ci (ubuntu-24.04-arm)`（実機前提を回さない現行）は 2047〜2114 秒（直近の成功 6 件・2026-11-19 時点）。実機前提を足すと約 6 分増える見込みで、ジョブ上限 60 分に収まる
- ジョブ全体の差 859 秒の内訳: arm64 の leg は `--all-features` の `cargo test`（441 秒。x86_64 は `rust-ci` が担う）と、x86_64 では `bench-regression` が担う自己テスト 3 件（repeat-test 126 秒・cli-parity の回収 88 秒・lib 61 秒。計 275 秒）も回す。実機前提の区間の差は 79 秒、既定 feature の `cargo test` の差は 78 秒（arm64 624 秒・x86_64 546 秒）

## 残余

- 1 回の実行の結果で、間欠失敗の有無は分からない。広げる場合は main の push の数回分で確かめる
- root の分岐・人間担当の実機確認（#1621 ほか）は対象外（x86_64 と同じ）
