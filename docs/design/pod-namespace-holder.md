# pod の namespace 保持役・netns の共有・本番の PodNetworkProvider 注入の設計（CRI-2・CORE-3・SEC-5・NET-3・CORE-1）

設計記録（#2838）。コードは本変更で変えない。実装は「実装単位」の各 issue で行う。オーナー確認が要る点は「要確認事項」に分けて列挙する。

## 背景

- cri は pod の ipc 共有を bundle へ変換できる（#2674）。パスは `PodNamespacePaths::for_holder_pid`（`/proc/<pid>/ns/{user,ipc}` だけ。#2776）でしか作れないが、供給元の保持役が無い。このため `CriRuntimeService::create_container_runtime` は `with_pod_namespaces` を渡さず、本番の pod のコンテナは常に新しい namespace で起動する
- pod の netns は `PodNetworkProvider`（cri）と plugin-cri の `NetsetupPodNetwork`（bridge・veth。rootful 前提）まで実装済み（#2675・#2676）。ただし本番へは未注入で、core の `NamespaceJoin` は network の path を `Unimplemented` で拒否し、`PodSandboxStatus.network` は空のスタブ
- plugin-cri の本番は rootless（uid 0 は `UNIMPLEMENTED`。#2442・#2241）。bridge・veth は作れず、rootless の netns は pasta 構成（NET-9。#1935・#341）の領域
- 受け入れ方式の現状は [cri-config-acceptance.md](cri-config-acceptance.md) の順 12〜14

## 前提と制約

- core の `isolate_join` は、`setns(user)` → `setns(ipc)` の後に `/proc/self/{uid,gid}_map` が launch の計画の写像と完全一致すること（`verify_joined_id_maps`・SEC-5）、user namespace の親が呼び出し側で作成者 uid が euid であること、ipc を所有する userns が join 先の userns と同じであることを求める
- したがって保持役の userns の写像は、コンテナの launch と同じ権限モデルの解決（`SingleId` / `Subordinate`）で core が作る。範囲写像の背景は [rootless-id-map-holder.md](rootless-id-map-holder.md)
- plugin-cri はマルチスレッド（tokio と worker）のため、単一スレッドを前提とする fork 系の機構を RPC の worker から直接は使えない。保持役は exec された単一スレッドのプロセスにする
- #2776 の契約: rootless では同じユーザーの別 pod の userns も core の認可を満たしてしまう。パスは自 sandbox の記録の pid からだけ作る（SEC-5 の P0）

## プロセスの形

採用: 既存の `fandhe-container-supervisor` の bin に `pod-holder` モードを足す。

- 起動: plugin-cri が `supervised.rs` と同じ規則（実体と同じディレクトリの固定名。`PATH`・環境変数・引数による上書きなし。PLUG-11 の方針）で解決して exec する
- namespace の確立: 新設の core の公開 API（`oci_runtime::pod_holder`・仮称）が担う。権限モデルの写像で user を作成 → ipc → net の `unshare`。範囲写像の経路は既存の holder / mapper を再利用する
- 起動後: fd 3 以上を閉じてから固定長の READY（pid と各 ns の dev・inode）を返し、以後は待機だけをする

| 却下案 | 理由 |
| ------ | ---- |
| 新しい bin（`fandhe-container-pod-holder`） | `install-privileged-launcher.sh`・`docs/setup/linux.md`・CLAUDE.md・配置手順まで波及する |
| pause コンテナ（`ContainerRuntime` で sandbox 用のコンテナを作る） | rootfs・pause イメージが要り、seccomp・Landlock・cgroup の一式を負う。CORE-7〜9 の資源目標に反する |
| plugin-cri からの fork | マルチスレッドのため単一スレッド fork の前提を満たさない |

## 寿命と Stop・Remove の後始末

- 生成: `RunPodSandbox` が worker で保持役を起動し、READY を期限つき（REPAIR-5）で受ける。失敗・期限超過では子を SIGKILL して回収し、sandbox を登録しない。順序は保持役 → 結線（netns は保持役のものを使う）
- 回収しないことで pid を固定する: 保持役は plugin-cri の直接の子として、sandbox の記録が残る間は `wait` しない。想定外に終了しても zombie として pid が残るので、`/proc/<pid>` が別プロセスを指す窓ができない。zombie の `/proc/<pid>/ns/*` は開けず、core の起動前検査が `FailedPrecondition` で止める（fail-closed）。生存の判定は回収を伴わない方法（`waitid(WNOHANG|WNOWAIT)` か pidfd の poll）で行い、plugin-cri の `sys` の事前承認範囲のラッパーに置く
- 子の一覧は `MAX_TRACKED_SUPERVISORS` に倣った上限つき。超過は `RESOURCE_EXHAUSTED`
- StopPodSandbox: 配下のコンテナの停止 → `PodNetworkProvider::tear_down` → 保持役の解放。解放は stdin パイプを閉じる → 期限つきで待つ → 超過なら SIGKILL → 回収。冪等で、失敗時は記録を残して再試行できる（`network_owned` と同じ形の `holder_owned` 等のフラグ）
- RemovePodSandbox: 残っていれば同じ解放を行う
- 保持役が死んだときは、Status・List で `SANDBOX_NOTREADY`、`CreateContainer` は `FAILED_PRECONDITION`

## クラッシュ後の回収と CORE-1

- 保持役は stdin の EOF（plugin-cri の終了・SIGKILL でも閉じる）と SIGTERM で終了する。PDEATHSIG は使わない（#2376 と同じ理由）。孤児の保持役は原則として残らない
- sandbox の記録はプロセス内メモリのスタブ（TASK-59 の `StateStore` 置換が前提。REPAIR-3）で、plugin-cri の再起動で失われる。保持役の寿命をこれに揃えるのは整合した fail-closed である。永続化と再起動後の再採用は `StateStore` 置換時に再設計する。ネットワークの残りは既存の reclaim の仕組み（#2604）に委ねる
- CORE-1 との整合: 保持役は pod ごとの軽量プロセス（supervisor がコンテナごとなのと同じ粒度）で、中央の常駐デーモンではない。常駐するのは CRI サーバーとしての plugin-cri だけ（既存の前提）
- 再起動後にコンテナのプロセスが残る場合、namespace はそのプロセスが保持し続ける。その掃除は TASK-59 の範囲

## netns の共有と core の join の受け口

- 保持役は user → ipc → net の順に作り、netns は pod の userns が所有する
- core の `NamespaceJoin` を拡張し、user＋ipc に加えて任意で net を受ける。net の所有 userns（`NS_GET_USERNS`）が join する user と同じであることを照合し、`setns` は user → ipc → net → 残りの `unshare` の順にする。net 単独の path・user が無い path は従来どおり `Unimplemented`
- 現行の注記（netns を userns より先に `setns` する順序）は、userns が所有する netns では問題にならない。user の後に net へ入れる
- rootful の init userns 所有の netns（bridge・veth の `NetsetupPodNetwork`）は、#2241 の判断まで `Unimplemented` のまま
- cri: `PodNamespacePaths` に net（同じ pid の `/proc/<pid>/ns/net`）を足す。構築口は `for_holder_pid` のまま。`namespace_options.network` が `POD` で保持役があれば bundle の network に保持役の path を出す
- `PodNetworkRequest`（`#[non_exhaustive]`）に保持役の netns を渡す欄を足す。provider は自前で netns を作らず、その netns を結線する（rootless では pasta が保持役の user / net へ attach）。`lo` の up は provider の責務（NET-2・NET-11）

## 本番の PodNetworkProvider 注入

- `CriPluginBackends::runtime_service` に、権限モデルが許すときだけ provider を差す受け口を設ける。rootless は pasta の provider（#1935・#341 の後）、rootful は #2241 の判断の後
- 保持役の注入は Linux・非 root で常に行う。ipc の共有は provider が無くても成立する
- provider が無い `POD` の扱いは要確認事項 2
- 本番の pod ネットワークが動くとは書かない

## PodSandboxStatus.network の IP 報告

- `PodNetns`（`#[non_exhaustive]`）に `ip`・`additional_ips` を足し、provider が報告した値だけを記録して返す。推測しない（REPAIR-3）。provider が無い・報告が無い場合は空

## 範囲外

- pid の共有（`shareProcessNamespace`。`Pid1Target` の見直しが要る）
- `/dev/shm` の共有、uts の共有、`NamespaceMode::TARGET`
- rootful の pod netns（#2241）
- 再起動をまたぐ sandbox の再採用（TASK-59）

## セキュリティ上の要点

- 別 pod の userns の受理: core の認可だけでは防げない（#2776）。パスは自 sandbox の記録の pid からだけ作り、CRI リクエストの値（annotations・config の文字列）からは作らない。pod A / B の取り違えが無い結合試験を必須にする
- TOCTOU: 保持役を記録が残る間は回収しない。core は start で 1 回だけ開いて fd に固定し素性を照合する。userns の写像の完全一致の照合（SEC-5）は維持する
- 攻撃面: 保持役は fd 3 以上を閉じ、秘密を持たない。READY は固定長で上限つきで解釈する
- DoS: 子の一覧は上限つき。READY の受信・解放の待ちはすべて期限つきで、超過したら SIGKILL して回収する（REPAIR-5）
- 後始末: Run の途中で失敗したら保持役・ネットワークの資源を逆順に戻し、戻せなければ記録を残して Stop・Remove で再試行する
- エラー文言は固定文言にし、パス・pid・config の値を含めない（REPAIR-4）
- rootful（uid 0）は #2241 の判断まで `UNIMPLEMENTED`。init userns 所有の netns への join は受けない
- 依存は追加しない。追加が必要と分かったら承認事項として報告する

## 要確認事項

1. 保持役の dumpable の扱い（未照合。H2 の受け入れ条件で、カーネルの一次情報〔tag・commit を固定した `fs/proc/namespaces.c`・`kernel/ptrace.c`〕と実機で確認する）。`/proc/<pid>/ns/*` の open は `PTRACE_MODE_READ_FSCREDS` を要し、non-dumpable の保持役が exec 後に `unshare` すると、同じ uid の core から開けない恐れがある。候補 (a) `unshare(USER)` の後に自身を再 exec して non-dumpable を保つ（推奨）、候補 (b) dumpable にして fd・秘密を一切持たない
2. provider が無い `POD` で保持役の netns（`lo` だけ）へ join して pod 内で localhost を共有するか（推奨。core の net の join が入った後。`NetworkReady` は false のまま）
3. 本番の pasta provider の起動点・版（#1935 に依存。依存の追加はユーザー承認制）

## 実装単位

起票元は #2838。すべて #2778 の sub-issue（`phase:7`）。

| 記号 | issue | 内容 | 担当 | 依存 |
| ---- | ----- | ---- | ---- | ---- |
| H1 | #2870 | core: 保持役の namespace 確立 API | runtime-builder | なし |
| H2 | #2874 | supervisor: `pod-holder` モード | runtime-builder | H1 |
| H3 | #2875 | ci: 実機前提試験の組み込み | infra-builder | H2・H7 |
| H4 | #2871 | cri: 保持役の注入点と sandbox 記録への pid の保持 | oci-cri-builder | なし |
| H5 | #2876 | cri: `with_pod_namespaces` の配線と pod A/B の結合試験 | oci-cri-builder | H4 |
| H6 | #2877 | plugin-cri: 本番の保持役 provider と注入 | oci-cri-builder | H2・H4 |
| H7 | #2872 | core: pod の network namespace の join | runtime-builder | なし |
| H8 | #2878 | cri: 保持役の netns を bundle と `PodNetworkRequest` へ渡す | oci-cri-builder | H5・H7 |
| H9 | #2873 | cri: `PodSandboxStatus.network` の IP の報告 | oci-cri-builder | なし |
| H10 | #2879 | cri: rootless の本番 `PodNetworkProvider`（pasta）の注入 | oci-cri-builder・net-builder | #1935・#341・H8 |
| H11 | #2880 | 実機確認（人間担当） | 人間 | H6・H8 |

rootful の netns は #2241 のオーナー判断に紐づけ、新規起票しない。
