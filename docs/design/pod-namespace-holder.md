# pod の namespace 保持役・netns の共有・本番の PodNetworkProvider 注入の設計（CRI-2・CORE-3・SEC-5・NET-3・CORE-1）

設計記録（#2838）。コードは本変更で変えない。実装は「実装単位」の各 issue で行う。オーナーが 2026-11-09 に承認した（記録は #2838 のコメント）。採用は supervisor の bin の `pod-holder` モード・依存の追加なし・`unsafe` は各 crate の `sys` の事前承認範囲。旧要確認事項 3 点の決定は「オーナー判断（2026-11-09）」に記す。

## 背景

- cri は pod の ipc 共有を bundle へ変換できる（#2674）。パスは `PodNamespacePaths::for_holder_pid`（`/proc/<pid>/ns/{user,ipc,net}` だけ。#2776・#2878）でしか作れない。`CriRuntimeService` の配線は #2876（H5）で実装済みで、保持役の provider を注入したときだけ `with_pod_namespaces` を渡す。本番（plugin-cri）は Linux・非 root で `ProductionPodHolder` を注入済み（H6・#2877）で、ipc が `POD` のコンテナは保持役の user＋ipc（network も `POD` なら net）へ join する。rootful（uid 0）は注入せず、注入された provider も uid 0 を `PERMISSION_DENIED` で恒久拒否する（#2241 の決定 D1 A・#4709）
- pod の netns は `PodNetworkProvider`（cri）と plugin-cri の `NetsetupPodNetwork`（bridge・veth。rootful 前提）まで実装済み（#2675・#2676）。ただし本番へは未注入で、core の `NamespaceJoin` は user＋ipc の組に net を足す形を受理済み（H7・#2872）だが、本番の rootless では `NetsetupPodNetwork`（rootful 前提）を使えず rootless の provider は H10（#2879）で未実装のため、`PodSandboxStatus.network` は provider の報告だけを返す経路が実装済み（#2873）だが、provider 未注入（本番は rootless・H10 待ち）のため実際には空
- plugin-cri の本番は rootless（uid 0 は `PERMISSION_DENIED` で恒久拒否。#2442・#2241 の決定 D1 A・#4709）。bridge・veth は作れず、rootless の netns は pasta 構成（NET-9。#1935・#341）の領域
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
- 起動後: fd 3 以上を閉じてから固定長の READY（pid と各 ns の dev・inode）を返し、以後は待機だけをする。#4808 で mount ns（pod の userns が所有・`/` は再帰 private）を足し、段 2 が capability を落とす前に pod-init の空の root（どこにも接続しない tmpfs。`nosuid,nodev,noexec`）を作って fd で持つ（READY は版 2・80 バイトで mnt の素性を載せる）

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
- 記録の永続化と再採用の設計は [cri-record-readoption.md](cri-record-readoption.md)（#2902）

## netns の共有と core の join の受け口

- 保持役は user → ipc → net の順に作り、netns は pod の userns が所有する
- core の `NamespaceJoin` を拡張し、user＋ipc に加えて任意で net を受ける。net の所有 userns（`NS_GET_USERNS`）が join する user と同じであることを照合し、`setns` は user → ipc → net → 残りの `unshare` の順にする。net 単独の path・user が無い path は従来どおり `Unimplemented`
- 実装済み（H7・#2872）: `paths_of` は user＋ipc の組に net を足す形だけを受け、`pin` は net の所有 userns を照合する（呼び出し側自身または外側の所有は `Unimplemented`〔`pod_join_net_not_pod_owned`〕、別の userns 所有は `PermissionDenied`〔`pod_join_net_owner_mismatch`〕）。`EffectiveNetwork::PodJoined` を足し、exec 直前の netns 素性の同期点（D8）にも通す（pin 時に固定した netns の素性との一致を期待する。`FromConfig` の CRI の経路のうち join する起動だけ）。受理と拒否は層 `pod_namespace_join` の監査に残す（SEC-4）
- 現行の注記（netns を userns より先に `setns` する順序）は、userns が所有する netns では問題にならない。user の後に net へ入れる
- rootful の init userns 所有の netns（bridge・veth の `NetsetupPodNetwork`）は、#2241 の決定 D1 A（恒久拒否。#4709）により本番の経路では扱わない
- cri: `PodNamespacePaths` に net（同じ pid の `/proc/<pid>/ns/net`）を足す。構築口は `for_holder_pid` のまま。`namespace_options.network` が `POD` で保持役があれば bundle の network に保持役の path を出す
- `PodNetworkRequest`（`#[non_exhaustive]`）に保持役の netns を渡す欄を足す。provider は自前で netns を作らず、その netns を結線する（rootless では pasta が保持役の user / net へ attach）。`lo` の up は provider の責務にせず、保持役が netns 作成直後に行う（次節の「`lo` の up」）

## 本番の PodNetworkProvider 注入

- `CriPluginBackends::runtime_service` に、権限モデルが許すときだけ provider を差す受け口を設ける。rootless は pasta の provider（起動方式は #340 の決定で決着済み。実装は #341 の後）、rootful は #2241 の判断の後
- 保持役の注入は Linux・非 root で常に行う。ipc の共有は provider が無くても成立する
- provider が無い `POD` は、保持役の netns（`lo` のみ）へ join して pod 内で localhost を共有する（オーナー判断 2）。`NetworkReady=false` は維持する
- 本番の pod ネットワークが動くとは書かない

### `lo` の up

- 新しい netns の `lo` は down で、join だけでは localhost 通信が成立しない（`crates/net/tests/lo_self_delivery.rs` が前提を固定。NET-2・NET-11）。provider の有無に依らず localhost を共有するため、`lo` を up にする責務は provider ではなく保持役に置く
- 保持役は pod の userns が所有する netns の中で（userns 内の `CAP_NET_ADMIN` で）、READY を返す前に `lo` を up にする。失敗したら READY を返さず固定文言のエラーで終了し、Run は保持役を回収して失敗する（fail-closed）。provider が結線する場合も `lo` は既に up で、provider は触らない
- 実装単位は H2（#2874）に含める（`lo` の up の実装と、provider が無い `POD` で pod 内の 2 コンテナが `127.0.0.1` で通信できる実機試験。H3 #2875 が CI へ組み込む）。H7（#2872）は join の受け口のみ。新規 issue の起票が要る場合は承認事項として報告する
- 実装の現況（H2・#2874）: `lo` の up は H1 の `establish_pod_namespaces`（#2870）が netns の作成直後に行う（失敗したらエラー）ため、`pod-holder` モードは重ねて up にせず、保持役の netns の中で `127.0.0.1` が使えることを実機試験で確かめる（`pod_holder_bin_real` のシナリオ B。保持役の netns へ `nsenter` で入った 2 つのプロセスが TCP で往復する）。コンテナを使った「pod 内の 2 コンテナ」の試験は core の net join（H7・#2872）が要るため、H7 の後に H3（#2875）か H5 で扱う（#4405 で `production_binary_exec_real` の段 P として実装済み。CI は platform-ci の ubuntu）。

## PodSandboxStatus.network の IP 報告

- `PodNetns`（`#[non_exhaustive]`）に `ip`・`additional_ips` を足し、provider が報告した値だけを記録して返す。推測しない（REPAIR-3）。provider が無い・報告が無い場合は空

## 範囲外

- pid の共有（`shareProcessNamespace`）・`/dev/shm` の共有・uts の共有・`NamespaceMode::TARGET`: 下の「pid・uts・/dev/shm の共有と TARGET（#2903）」で設計した。uts は実装単位 U1〜U5 を起票済み。pid の共有は #4816・#4817 で実装済み（下の節）。`TARGET` は core・supervisor の受け口を #4819（T1）で、cri の受け入れと argv の書き出しを #4820（T2）で実装し、同じ pod・対象の pid が `CONTAINER`・対象の ipc が `POD` のときだけ受ける（CRI-2・CORE-3・SEC-1・SEC-5）。`/dev/shm` は #4823（S3）で共有する（下の S3 の節。`mounts[]` のホストの `/dev/shm` の bind〔#4888〕は pod の共有とは別の経路で、本節の対象ではない）
- rootful の pod netns（#2241）
- 再起動をまたぐ sandbox の再採用（TASK-59。設計は [cri-record-readoption.md](cri-record-readoption.md)・#2902）

## pid・uts・/dev/shm の共有と TARGET（#2903）

保持役（user → ipc → net）の上で、残り 4 項目をどう受けるかの設計。コードは変えない。ビヘイビア: CRI-2・CORE-3・SEC-5・SEC-1。Agent が決められない点は末尾の O1〜O6（人間担当 #4607）。

### uts の共有（受ける）

- 保持役が net の後に `unshare(CLONE_NEWUTS)` し、検証済みの sandbox の hostname で `sethostname` してから READY を返す。hostname は argv で渡し、cri の `check_hostname` と同じ規則で保持役の側でも上限つきに再検査する
- core の `NamespaceJoin` は uts を「user＋ipc の組に足す形」でだけ受ける。所有する userns が join する user と同じであることを照合する。`setns` の順は user → ipc → net → uts → 残りの `unshare`
- uts の path と config の `hostname` の併用は `InvalidArgument`（pod 共有の uts をコンテナの起動が書き換えないため。fail-closed）。cri は join するとき hostname を出さない
- cri は保持役がいて ipc を join するとき常に uts の path を出す（containerd は pod 内を常に共有）。network が `NODE` の pod でも保持役の uts を共有する。containerd との差: ホストの uts ではない（rootless では init userns 所有の uts へ入れないため）
- `kernel.hostname`・`kernel.domainname` の sysctl は `UNIMPLEMENTED` のまま（pod 共有の uts をコンテナから書き換える経路になるため）
- 攻撃面: コンテナは既定で `CAP_SYS_ADMIN` を持たず、seccomp が `setns`・`unshare` を禁じる。共有で増える面は無い
- 実装単位: U1〜U5（下の表）

### pid の共有（方式を設計。受けるかは O1・オーナー判断待ち）

現状は pid が `POD`／`CONTAINER` のどちらでもコンテナごとの新しい pid namespace で、`NODE` は `UNIMPLEMENTED`。core は pid の path を `Unimplemented` にしている。理由は、init が PID 1 である証跡（`check_establish_preconditions`・`Pid1Target`・`reapply` の pid ns 照合）と、「init の終了で pid ns ごと回収される」という前提が共有と両立しないため。

- pod の PID 1: 保持役が段 2 で `unshare(CLONE_NEWPID)` の後に 1 回だけ fork した子 pod-init。単一スレッド・capability なし・non-dumpable で孤児の回収だけを行い、root は空の tmpfs へ `pivot_root` する（mount ns は保持役が pod の userns で作る。`/dev/shm` の案 A と共用）。pod-init が死ぬとその pid ns では fork できなくなる想定のため、保持役は pod-init を監視して死んだら終了し、plugin-cri は `SANDBOX_NOTREADY` にする（fail-closed）。カーネルの挙動は Linux v6.12（tag の commit `06090c9b622a7e1f797e775db4c035e0d779b76e`）の原文で確かめた（#4815）。
  - `unshare` 後の最初の fork が init になる: `kernel/pid.c` の `alloc_pid`（228〜241 行。新しい ns の最初の割り当ては `pid_min = 1`）と、`kernel/fork.c` の `copy_process`（2558〜2560 行。PID 1 が `child_reaper` になり `SIGNAL_UNKILLABLE`）
  - init の死後はその ns で fork が失敗する: `kernel/exit.c` の `find_child_reaper`（587 行〜。612 行で `zap_pid_ns_processes`）と、`kernel/pid_namespace.c` の `zap_pid_ns_processes`（170 行〜。179 行で `disable_pid_allocation`。ns の残りのプロセスも SIGKILL で止まる）、`kernel/pid.c` の `alloc_pid`（277 行。`PIDNS_ADDING` が無ければ `-ENOMEM`）
  - 実装: 保持役は `pod-holder --share-pid` のときだけ、段 2 で capability を落とす前に core の `spawn_pod_init` で pod-init を作る
  - pod-init の手順
    - 自分の mount ns を作り、空の root を `/` の上に付けて `pivot_root(".", ".")` で移る
    - 自分の ns を作るのは、`fs/namespace.c` の `pivot_root` の `chroot_fs_refs` が同じ root を持つプロセスすべての root を差し替え、保持役の root まで変えてしまうため
    - fd を閉じ、`SIGCHLD` を無視にして孤児を自動回収させる（`kernel/signal.c` の `do_notify_parent` 2117〜2134 行）
    - capability をすべて落とし、non-dumpable を自分で確かめる
  - READY に保持役の `pid_for_children` の素性を載せる（版 3 で足した）
  - 保持役は pod-init の終了で終了コード 1 で終わり、stdin の EOF では pod-init を止めて 0 で終わる
- パス: 保持役の pid からだけ `/proc/<holder>/ns/pid_for_children` を作る（#2776 の契約）。READY に pid ns の素性を載せ、plugin-cri が照合する（#4816 で実装。plugin-cri の provider は sandbox の pid が `POD`〔未指定を含む〕のときだけ `--share-pid` を渡し、READY の pid ns の有無が求めた共有と一致し、素性が `/proc/<holder>/ns/pid_for_children` と一致することを確かめ、素性を記録の `holder=` 行の 6 つ目の要素に残す。pod-init の死で保持役が終わり、既存の `reconcile_holders`〔#2871〕が `SANDBOX_NOTREADY` にする）
- core の join の検査: pid は user＋ipc の組に足す形でだけ受ける。`NS_GET_NSTYPE` が `CLONE_NEWPID`、所有 userns が join する user と同じ、`NS_GET_PARENT` が呼び出し側の pid ns。`setns(pid)` は中間プロセスで行い、効くのは以後に fork した init だけ
- PID 1 の証跡: 「joined pid ns の init」の種別を足す。`getpid() != 1` を許すのは、`/proc/thread-self/ns/pid` が launch で固定した pod の pid ns の素性と一致するときだけ。初期 pid ns でないこと・単一スレッドの検査は保つ。`check_evidence` も同じ素性で照合する（#4812 で実装）
- `Pid1Target`（exec・healthcheck）: pid を共有するコンテナでは `NSpid` の末尾が 1 でない対象を受ける。ただし launch pidfd の経路（#1461）で、記録した pod の pid ns の素性と一致するときだけ。記録 pid から開く縮退経路は拒否し、監査の語彙を足す（SEC-4）。#4813 で実装した（素性は `LaunchIsolationRecord::pod_pid_ns` に残し、語彙は `exec_target_joined_pid_namespace_mismatch`・`exec_target_joined_pid_namespace_requires_launch_pidfd`）
- 停止と終了: init が終了しても子孫は pod-init へ付け替わって残るため、init の終了時と停止時にコンテナの cgroup へ `cgroup.kill` を書く（O4）。#4811 で実装した（supervisor の `pid_share`。監視ループは init の終了を観測した後・終了を記録する前、停止は起動ハンドルの回収の後に、core の `cgroups::kill_all_in_recorded` で止めて空になるのを 5 秒まで待ち、結果を `pid_shared_kill_all` の行に出す）。containerd の shim と同じ挙動であることを v2.1.0 の原文で確かめた: `cmd/containerd-shim-runc-v2/runc/util.go` の `ShouldKillAllOnExit`（31〜47 行。pid の namespace が path なしで宣言されていなければ真）と、`cmd/containerd-shim-runc-v2/task/service.go` の `handleInitExit`（696〜713 行。真なら `p.KillAll` の後に init の終了を公開する）
- containerd との差: PID 1 はコンテナではない（rootfs・seccomp・cgroup の一式を持たない。CORE-7〜9）。兄弟コンテナの `/proc/<pid>/root`・`environ`・`fd` は Landlock の ptrace の境界で開けない（k8s では見える）。同じ uid の signal は届く。pod-init の `/proc/1/root` は空の root
- 既定値: CRI の enum の 0 は `POD`。sandbox の pid が `POD`（未指定を含む）のときだけ保持役が pid ns を作る。食い違いは O3
  - 2026-11-19 にオーナーが確定した。CRI の proto（`crates/cri/proto/api.proto`）が既定を `POD` と明記し、containerd v2.1.0 もコンテナの pid が `CONTAINER` でなければ（未指定を含む）sandbox の pid ns へ入れる（`internal/cri/opts/spec_opts.go` 330 行）。kubelet は `shareProcessNamespace` が既定（false）のとき pid に `CONTAINER` を明示する（kubernetes v1.34.0 `pkg/kubelet/kuberuntime/util/util.go` の `PidNamespaceForPod`）ので、Kubernetes 経由で共有になるのは `shareProcessNamespace: true` の pod だけ。crictl などで設定を手書きして pid を省くと共有になる
- plugin-cri の停止: 保持役は plugin-cri の停止（SIGKILL・SIGTERM・更新）で stdin の EOF を受けて pod-init を止めるため、pid を共有する pod は、pod-init の終了でカーネルが ns の残りを SIGKILL するため（`zap_pid_ns_processes`）、中のプロセスがすべて即座に止まる（preStop・猶予期間は効かない）。共有しない pod は plugin-cri が止まっている間も動き続け、plugin-cri の再起動後に sandbox が `SANDBOX_NOTREADY` になると、kubelet が猶予つきで止める（restartPolicy が Never でなければ作り直す。kubernetes v1.34.0 `pkg/kubelet/kuberuntime/kuberuntime_manager.go` の `computePodActions`〔1001〜1025 行〕は ready な sandbox が無いと `KillPod` と `CreateSandbox` を立て、Never では作り直さない）。containerd は pause コンテナが containerd と別に生きるため、containerd の再起動では pod が止まらない。この差は [cri-record-readoption.md](cri-record-readoption.md) の要確認事項 1 を (b) で確定したときに受け入れた（2026-11-19 のオーナー判断）
- cri の bundle（#4817 で実装）: 記録の保持役の素性に pid ns があり、コンテナの pid が `POD`（未指定を含む）なら、config の pid に保持役の pid から作った `/proc/<holder>/ns/pid_for_children` を path として出す（user＋ipc の組に足す形）。この path が supervisor の kill-all（#4811）の対象の判定になる
  - sandbox が `CONTAINER`（保持役が pid ns を持たない）でコンテナが `POD` の食い違いは、コンテナごとの新しい pid ns にする（O3。containerd は sandbox の pid ns に入るので差になる）
  - 保持役が pid ns を持ち、コンテナの pid が `POD`（未指定を含む）なのに ipc が `POD` でない構成は、共有の要求を黙って落とさず `UNIMPLEMENTED`（core は pid の join を user＋ipc の組に足す形でしか受けない）。pid の `NODE`・`TARGET` は `UNIMPLEMENTED` のまま
    - 2026-11-19 にオーナーが確定した。kubelet はコンテナの ipc を `POD` か `NODE`（もともと `UNIMPLEMENTED`）でしか送らないため、Kubernetes からこの構成は来ない。containerd v2.1.0 はコンテナの ipc の指定に関係なく sandbox の ipc へ入る（`spec_opts.go` 325〜327 行）ので、断る本リポのほうが fail-closed
  - 素性の無い保持役（検証が無効な構成・試験用の偽 provider）は pid を共有しない

### `NamespaceMode::TARGET`

- pid の `TARGET`（方式を設計。受けるかは O5。core・supervisor は T1〔#4819〕で実装済みで、下の「実装（T1・#4819）」）: 対象コンテナの init の pid ns へ入る。保持役の「回収しないことで pid を固定する」保証は対象に及ばないため、core が状態ストアから `target_id` を解決し、supervisor の launch pidfd（#2626 の制御チャネル kind 6・`SCM_RIGHTS`）で対象を固定して未終了を確かめ、ns の fd を固定する。CRI の文字列からパスを作らない。証跡は「joined pid ns の init」を流用する。cri は同じ pod であること・対象の pid が `CONTAINER` であること・対象が存在することを検証する（T2・#4820 で実装済み。上の「`NamespaceMode::TARGET`」の判定は [cri-config-acceptance.md](cri-config-acceptance.md)）。対象の init が終了すると pid ns ごと止まる（k8s と同じ）
- ipc・network・userns の `TARGET` は `UNIMPLEMENTED` のまま: kubelet が送らない（proto の注記は pid だけ `TARGET` を送る）、userns は proto 上 `POD` と `NODE` だけ、network と ipc は core が単独の join を受けない

#### 実装（T1・#4819）: core・supervisor の受け口

- 入力: 対象は supervisor の起動オプション `--pid-target <コンテナ ID>` で受ける。config.json の pid は path なしの entry 1 件（保持役の user・ipc は path つき）で、config は純 OCI のまま。`--pid-target` は plugin-cri が T2（#4820）で書き出す。
- 固定: supervisor の `resolve_pid_target(store, source, target)` が、`build_launcher` で fork の前に呼ぶ（特権ランチャー経由の拒否は `check_launcher_available` と `build_launcher` の両方）。手順は次のとおり（CRI-2・CORE-3・SEC-1）。
  1. 状態ストアの対象の記録を読む。稼働中で pid・cgroup・起動素性があり、pod 共有の pid ns の init でないことを確かめる
  2. 対象の supervisor の制御チャネル（kind 6。[exec-pidfd-handover.md](exec-pidfd-handover.md)）から launch pidfd を受け取る。待ちの予算は 2 秒（`PID_TARGET_OBTAIN_BUDGET`）。受け取ったら接続はすぐ閉じる
  3. launch pidfd の経路（`Pid1Target`）で、未終了・NSpid の直接の入れ子の PID 1・cgroup の所属を確かめる
  4. pidfd で未終了を確かめてから `/proc/<pid>/ns/pid` を開いて素性を固定し、開いた後にもう一度確かめる
  - 記録の pid からの `pidfd_open` や `/proc` 経由の参加は行わない（SEC-1）。
- 合流: 固定した pid ns の fd は既存の `NamespaceJoin` の pid 欄へ入る。以降の検査（nsfs・所有 userns・親の pid ns・素性）と監査は pid の path の場合と同じ（既存の `PodNamespaceJoinOutcome` を使い、新しい語彙は足さない）。固定の段（`resolve`）で出る分離違反（pidfd の不一致・cgroup 所属の不一致・直接入れ子の PID 1 でない）は、固定文言へ写す前に exec の対象の拒否と同じ層 `exec_target` の記録（コンテナ ID は対象）として 1 件届ける。`build_launcher` は start の作業スレッド（複数スレッド）で走り `FileAuditSink` の直接書きは `isolation_unavailable` で落ちるため、pod の join・pasta の再検証と同じく単一スレッドの時点で構築した中継（`rejection_audit`・`ControlAuditRelay`）経由で配送する（中継の枠に `ExecTarget` を足し、理由は閉じた表 `ViolationReason::EXEC_TARGET_REASONS`。表に無い理由は `InvalidArgument`。SEC-4。#4899 のレビュー指摘）。対象の不在・終了・supervisor 不在など違反を伴わない失敗は記録しない。記録の失敗は拒否を覆さない（fail-closed）。
- 非 Linux: `PinnedPidTarget` は作れない（型だけ）。supervisor 自体が Linux 限定で、`the supervisor requires Linux` で拒否する。
- 受ける構成と拒否:

| 構成 | 判定 |
| ---- | ---- |
| 新コンテナが保持役の user・ipc に join し、対象の pid ns の所有 userns が同じ pod の userns | 受ける |
| 新コンテナに user・ipc の join が無い | `Unimplemented` |
| 対象が pod の userns に入っていない | `PermissionDenied`（既存の `PidOwnerMismatch`） |
| 対象が自分の pid ns の PID 1 でない | `FailedPrecondition` |
| 親が呼び出し側の pid ns でない | `PermissionDenied`（既存の `PidNotChild`） |

- restart（再 launch）: 再解決しない。launch のたびに fork の前で、spec の pid の素性と `options.pid_target().identity()` の一致と、対象の生存（`ensure_alive`）を確かめ、違えば拒否する。対象が再起動しても追従しない（#4819）。
- 固定エラー: Pid1Target 由来のエラーは pid を含むものがあるため、そのまま返さず写像する。表に無いものと、状態ストアの NotFound 以外の失敗は `could not be verified` に落とす。

| 場合 | code | message |
| ---- | ---- | ------- |
| 対象の記録なし | NotFound | `the pid namespace target does not exist` |
| 稼働中でない（Created・Stopped・pid なし・自分自身） | FailedPrecondition | `the pid namespace target is not running` |
| 終了済み（pidfd が readable・検証中に消えた・再 launch 時） | FailedPrecondition | `the pid namespace target has exited` |
| supervisor 不在・launch pidfd を得られない | Unavailable | `the launch pidfd of the pid namespace target is unavailable` |
| pidfd の不一致・pidfd でない fd | FailedPrecondition | `the launch pidfd does not match the pid namespace target` |
| 対象が自分の pid ns の init でない（pod 共有を含む） | FailedPrecondition | `the pid namespace target does not own its pid namespace` |
| 記録不足・その他 | FailedPrecondition | `the pid namespace target could not be verified` |
| 特権ランチャー経由 | Unimplemented | `a pid namespace target is not supported with elevated capabilities` |
| user・ipc の join なし | Unimplemented | `a pid namespace target requires a pod user and ipc namespace join` |
| pid の path と併用 | InvalidArgument | `a pid namespace target cannot be combined with a pid namespace path` |
| spec と launcher の食い違い（restart の再 launch を含む） | FailedPrecondition | `the launch spec was reconciled with a different pid namespace target` |

#### 実装（T2・#4820）: cri・plugin-cri

- 検証（cri。Create と Start の両方）: 対象の記録の存在・同じ pod sandbox・対象の実効の pid が `CONTAINER`・対象の実効の ipc が `POD`（pod の userns の中）。`crates/cri/src/runtime_service.rs` の `check_pid_target`。Running は見ない（Start で core が拒否する）。固定エラーの表は [cri-config-acceptance.md](cri-config-acceptance.md) の「pid の TARGET の受け入れ」。
- bundle: 保持役の user・ipc への join があるときだけ pid の `TARGET` を受け、config.json の pid は path なし（`crates/cri/src/bundle/spec.rs` の `namespaces`）。join が無ければ `UNIMPLEMENTED`。
- 配線: `start_inputs` が対象の ID を返し、`CriAdapter::start_with_pid_target` → `StartRequest::with_pid_target`（core）→ plugin-cri の `Supervised::start_with_pid_target` を通り、supervisor の argv に `--pid-target <ID>` が `--pod-shm` の後・ID の前に載る（`crates/supervisor/src/start_client.rs` の `with_pid_target`）。`None` のときは載らない。
- 要求と launcher の食い違い（core の `start.rs`）: 要求に対象があるのに launcher に無いときは `FailedPrecondition` で拒否する。逆（launcher にだけある）は `pod_shm` と同じく通す。
- 段 G（pid-target。#4820）: `crates/plugin-cri/tests/cri_exec_real.rs` の本番の実機前提試験で通す（[real-machine-tests.md](../verification/real-machine-tests.md)）。
- 残り: 対象の Running を Create で要求しない（containerd v2.1.0 と差。Start で拒否する）。対象の再起動には追従しない。ipc・network・userns の `TARGET` は `UNIMPLEMENTED` のまま。

### `/dev/shm` の共有（方式の比較。採否は O6）

- 案 A（推奨候補）: 保持役が pod の userns で mount ns を作り tmpfs（64 MiB・`nosuid,nodev,noexec,mode=1777`）を載せる。コンテナの init は `pivot_root` の前に保持役の mnt ns の fd へ `setns` して `open_tree(OPEN_TREE_CLONE)` で複製を取り、自分の mnt ns に戻って `move_mount` で rootfs の `/dev/shm` に載せる。カーネルの条件は Linux v6.12 の原文で確かめ、非特権の user + mount namespace の PoC も通った（#4806。下の脚注「案 A の一次情報と PoC」）
- 案 B: plugin-cri の状態ルート下の pod ごとのディレクトリを bind する。簡単だがサイズ上限が無く、利用者のセッションの tmpfs を埋める DoS になる
- 案 C: 共有しない（現状）。SysV IPC と mqueue は共有される
- 実装: 案 A を S1〜S3（#4821・#4822・#4823）で実装した。S3 の受け渡しは下の「実装: S3（#4823）」の節。`#4607` の O6（方式と既定サイズ）の正式な判断の記録は、本書では扱わない（#4607 で扱う）。共有の条件と差は cri-config-acceptance.md の「pod の ipc 共有の受け入れ方式」

#### 脚注: 案 A の一次情報と PoC（S0・#4806）

原文は Linux `v6.12`（tag の commit `06090c9b622a7e1f797e775db4c035e0d779b76e`）。行番号はこの tag のもの。

| 段 | 条件 | 原文（ファイル・関数・行） |
| -- | ---- | -------------------------- |
| 1. 保持役が pod の userns で mount ns を作り tmpfs を載せる | `unshare(CLONE_NEWNS)` の新しい ns の所有者は呼び出し側の userns（`alloc_mnt_ns(user_ns, …)`）。userns をまたぐ複製は shared を slave にする | `kernel/nsproxy.c` `create_new_namespaces` 78 行（`copy_mnt_ns`）・`fs/namespace.c` `copy_mnt_ns` 3916・3935・3942〜3943 行 |
| | tmpfs は userns の中でマウントできる | `mm/shmem.c` の `shmem_fs_type` の `.fs_flags = FS_USERNS_MOUNT \| FS_ALLOW_IDMAP`（4946 行） |
| 2. init が保持役の mnt ns へ `setns` | 参加先の ns の所有 userns と、自分の userns の両方で権限が要る（`CAP_SYS_ADMIN`・`CAP_SYS_CHROOT`）。anon ns は不可。`fs_struct` を共有していないこと（`fs->users == 1`。単一スレッドの fork 子で満たす） | `fs/namespace.c` `mntns_install` 5747〜5789 行（権限 5756〜5759・anon 5761・`fs->users` 5764） |
| 2. `open_tree(OPEN_TREE_CLONE)` で複製 | 呼び出し側の今の ns の所有 userns の `CAP_SYS_ADMIN`（`may_mount`） | `fs/namespace.c` `open_tree` 2839〜2888 行（2865 行）・`may_mount` 1974〜1977 行 |
| | 複製元が呼び出し側の今の mount ns にあること（`check_mnt`）。参加してから開く理由。複製は `MNT_LOCKED` が外れ、呼び出し側の ns の userns が所有する anon ns に入る | `fs/namespace.c` `__do_loopback` 2728〜2750 行（`check_mnt` 2735・`MNT_LOCKED` 2747）・`check_mnt` 964〜967 行・`open_detached_copy` 2801〜2837 行 |
| 3. 自分の mnt ns へ戻り `move_mount` で載せる | 入口で `may_mount`。載せ先は自分の ns にあること、移すものは接続されていない anon ns の root であること、`MNT_LOCKED` でないこと、ディレクトリ同士であること | `fs/namespace.c` `move_mount` 4230〜4286 行（`may_mount` 4239）・`do_move_mount` 3270〜3364 行（3296〜3316 行）・`fs/mount.h` `is_anon_ns` 143〜146 行 |

補足: issue に書いた `may_copy_tree` は v6.12 には無い。v6.12 の `open_tree` は「今の ns にあるマウントだけを複製できる」（`check_mnt`）ので、保持役の mnt ns へ参加してから複製する手順が要る（案 A の手順のまま）。

PoC: `crates/core/src/oci_runtime/namespace_join.rs` の実機前提試験 `cri2_core3_4806_shm_clone_via_holder_mnt_ns`（`--ignored`）。

- 構成: 保持役の代わり（`unshare --user --map-root-user --mount` の中で tmpfs を載せる）と、init の代わり（その userns に参加して自分の mount ns を作った fork 子）で 3 段を通す
- 照合: 載せ先の `nosuid,nodev,noexec`（`fstatfs`）、大きさ `size=65536k`（mountinfo）、両方向の内容の一致、試験プロセスの ns に付かないこと
- 結果: 非特権の uid 1000・カーネル 7.2（OrbStack の Linux）で成功した。CI の platform-ci（ubuntu の AppArmor 緩和後）でも、namespace_join の実機前提のステップで回す
- 実装単位: S1（保持役の shm の tmpfs。#4821）・S2（`setns` の往復による複製と載せる処理。#4822）・S3（受け渡し。#4823）
- S1（#4821 で実装）: 保持役は段 2 で、pod-init の空の root を作った後・capability を落とす前に、core の `mount_pod_shm` で自分の mount ns の `/dev/shm` に tmpfs を載せる
  - 中身はコンテナの既定の `/dev/shm`（`TmpfsMountSpec::default_dev_shm`。#1654）と同じ定義で、64 MiB・`nosuid,nodev,noexec`・mode 1777
  - 載せ先は `O_NOFOLLOW` で開いた fd のまま `move_mount` へ渡す。載せた後に開き直して、自分のマウントと同じ素性・属性 3 つ・mode を確かめる（fail-closed）。ホストに `/dev/shm` のディレクトリが無い構成では保持役が `FAILED_PRECONDITION` で起動しない
  - マウントの fd は持たない。READY は版 4（112 バイト）で、tmpfs のルートの `st_dev`・`st_ino` を常に載せる（S2 が保持役の mnt ns へ入って開いた `/dev/shm` を照合する材料）
  - 載せる場所を保持役の mount ns の `/dev/shm` にしたのは Agent の判断（issue は場所を決めていない）。v6.12 の `open_tree` は呼び出し側の今の mount ns に付いたマウントしか複製できない（`check_mnt`）ため、どこにも接続しない tmpfs を fd で持つ方式（pod-init の空の root と同じ形）は S2 で複製できない。付ける先は保持役の ns に既にあるディレクトリが要り、ホストの `/dev/shm` のディレクトリは Linux の標準の構成にあり、保持役自身は使わない。ns は private な複製のため、上に載せてもホストの `/dev/shm` は変わらない
  - S2 の注意: pod の tmpfs が載っていない（保持役が別物・途中で外れた）と、同じパスはホストの `/dev/shm` の tmpfs に解決する。S2 は開いた `/dev/shm` の `(dev, ino)` を READY の値と照合することを必須にする（無いとホストの `/dev/shm` を複製しうる）

- S2（#4822 で実装。core と supervisor の受け口まで。本番の指定元の配線は S3・#4823。S3 で実装済み）: コンテナの init が pivot 前に保持役の mnt ns の `/dev/shm` を複製して rootfs の `dev/shm` へ載せる
  - **受け渡しは supervisor の argv → `LaunchOptions`（オーナー決定 2026-11-19）**: `--pod-shm <dev>:<ino>:<絶対パス>`（例 `48:2:/proc/1234/ns/mnt`。`dev`・`ino` は保持役の `/dev/shm`〔tmpfs のルート〕の素性で READY の値、パスは `/proc/<正の整数>/ns/mnt`）を supervisor の入口が `LaunchOptions::with_pod_shm` へ渡す。config.json は純 OCI のまま（`mounts[]` に独自の type を足さず、annotations も使わない）。argv の要素数の上限は 12 から 14 へ（T1 の `--pid-target` で後に 16）。特権ランチャー経由（ambient capability あり）では `Unimplemented` で拒否する。`StartRequest` への欄の追加と cri・plugin-cri の配線は S3 で、S2 の時点では本番の呼び出し元が無い（REPAIR-3。`supervisor::StartOptions::with_pod_shm` が S3 の入口）
  - **pin（fork の前）**: core の `start` が user・ipc の join の固定の直後に、`/proc/<pid>/ns/mnt` を 1 回だけ開いて fd に固定する（`namespace_join/pod_shm.rs`）。検査は、同じ config に user と ipc の join があること（無ければ `Unimplemented`）、パスの pid が user の join の path の pid と同じ（字句。違えば `InvalidArgument`）、nsfs で `NS_GET_NSTYPE` が mount（違えば `InvalidArgument`）、所有する user namespace が固定済みの user の join と同じ（違う・取れない〔呼び出し側自身・外側の mnt ns もここで落ちる〕は `PermissionDenied`）。拒否は閉じた語彙 `PodNamespaceJoinOutcome` で監査し、所有者の不一致用に末尾へ `PodShmOwnerMismatch`（`pod_join_shm_owner_mismatch`。中継の表の添字は途中に挿入しない）だけを足した。受理の記録は join の 1 件で足りるため出さない
  - **複製して載せる手順（`exec/pod_shm.rs`。`create_default_devices` の後・`mount_tmpfs` の前。新しい `PrePivotStep`・`IsolationStage` は足さず、失敗は段 `mount_tmpfs` で返る）**: 自分の mnt ns の fd・`/`・`.` を控える → `setns(保持役の mnt ns)` → `/dev/shm` を開く → **同じ fd で** `(st_dev, st_ino)` が launch の固定時の期待値と一致・tmpfs・`nosuid,nodev,noexec` を確かめる → `open_tree(OPEN_TREE_CLONE)` で複製 → `setns(自分の mnt ns)`（失敗したらパス操作を一切せず固定文言で終える）→ `/` の素性（`st_dev`・`st_ino`・mount ID）が往復前と同じことを確かめて cwd を戻す → rootfs の `dev/shm` を fd 起点で開き、shared でないことと移動していないことを確かめて `move_mount` → 載せた後に開き直して素性・属性・shared でないことを再照合。新しい `unsafe` は無い（既存の sys のラッパーだけ）
  - **後始末は無い**: 載せるのは init 専用の mnt ns の rootfs（`/dev` の tmpfs の中）で、init の破棄でマウントごと消える。pod の tmpfs へは書かず外さない。`run_child_then` の失敗経路に段をまたぐ後始末が無いことを確かめた
  - **launch の記録と既定の 64 MiB**: 載せた `/dev/shm` は既定の tmpfs の `/dev/shm` と同じ識別子（`MountedBy::Tmpfs`・宛先 `/dev/shm`）で記録する（`MountedTargets`・exec の再適用〔#3201〕・`state.json` の形は変えない。Landlock の暗黙規則も `All` のまま）。launcher は pod の共有 `/dev/shm` があるとき、子へ渡す tmpfs 集合から既定の `/dev/shm` の件だけを除く。`/dev/shm` が無い（`--ipc=host`）・既定と違う（`--shm-size`・`--tmpfs /dev/shm`）・`/dev/shm` 配下の tmpfs は `LaunchOptions::with_pod_shm` と launch の fork 前に `InvalidArgument`
  - **転送漏れで黙って縮退しない**: `ProcessLauncher::pod_shm_source`（既定 `None`）を supervisor の `SpecCapturingLauncher`・`PastaAttachingLauncher` が内側へ転送する。本番 launcher は spec の固定と自身の起動オプションの有無の食い違い（どちら向きも）を fork の前に `FailedPrecondition` で拒否する
  - 試験: `crates/core/src/oci_runtime/namespace_join.rs` の実機前提試験 `cri2_core3_4806_shm_clone_via_holder_mnt_ns` は本番の複製の関数（`exec::pod_shm::clone_from_holder`）を呼ぶ形に直した（往復の後の mnt ns・cwd、属性、`size=65536k`、両方向の内容、素性違いの拒否、tmpfs を載せていない保持役〔ホストの `/dev/shm` に解決する〕の拒否、pin の受理と所有者違いの拒否）。端から端は `crates/core/tests/production_launcher.rs` のシナリオ `W-shm`（A のコンテナを保持役の代わりにし、A の `/dev/shm` の素性を期待値にして B を起動。Landlock の暗黙規則込みで内容が両方向に見える）
  - 範囲外・残余: 保持役が READY で報告した素性を launch の記録の `/dev/shm` の規則と親側でも照合する案は入れていない（init が複製の前後に同じ素性を照合済みのため。必要なら S3 の統合後に再評価）
  - **拒否の監査**: 素性・tmpfs 種別・属性 3 つの不一致（複製の前後と載せた後の再照合）は理由語 `pod_shm_identity_mismatch`（種別 `pod_shm_identity`・ビヘイビア CRI-2・`ErrorCode` は `PermissionDenied`）で返り、段 `mount_tmpfs` の許可リスト経由で親へ届いて層 `mount` の監査に 1 件残る（パスなし）。往復の失敗（`setns`・`/` の素性の変化）と権限不足は違反ではなく `NotApplicable`。launcher は fork の前に、spec が固定した期待の素性と自身の起動オプションの指定の素性の一致も確かめる（多重防御）。init は pod shm の指定があるのに tmpfs の集合に `/dev/shm`（配下を含む）が残っていれば、載せる前に `FailedPrecondition` で拒否する
  - **S3 への申し送り**: `(dev, ino)` は時間をまたいで一意ではない（tmpfs の匿名 dev は解放後に再利用される）。pin より前の窓の安全は保持役が生きていることに依存するため、S3 は READY の値をそのまま渡し、plugin-cri 側で `/dev/shm` を再 stat して値を作り直さない。chroot した環境では往復の後の `/` の照合が必ず食い違い `Internal` になるため使えない（fail-closed。縮退しない）
  - **S3 と #4888 の関係**: CRI の `mounts[]` に `/dev/shm` の bind（許可リストの宛先。[cri-config-acceptance](cri-config-acceptance.md)）があれば、S3 は pod の共有 `/dev/shm` を渡さない（S3 の受け入れ条件。cri は S3 で実装済み）。core は bind と pod の共有 `/dev/shm` の併用を `OverlapsTmpfs`（監査つき）で拒否するため、両方が載ることはない（#4888）

#### 実装: S3（#4823）の受け渡し

- 対象: pod の共有 `/dev/shm` を、CRI の `CreateContainer`・`StartContainer` の経路で保持役の素性つきで渡し、S2 の入口（supervisor の `--pod-shm`）へ届ける。S1・S2 の init 側の複製と supervisor の入口（`--pod-shm`）は変えない。core は `StartRequest` の欄と食い違いの検査だけを足す
- 流れ（cri → plugin-cri → supervisor → core）: 保持役の READY v4 の shm の `(dev, ino)` を `HolderIdentity` の素性として記録し（メモリ上の `SandboxRecord.pod_holder` だけ）、`start_inputs` が Start のロック区間で条件を判定して `StartRequest` の欄へ載せる。plugin-cri は `StartOptions::with_pod_shm` で `--pod-shm <dev>:<ino>:/proc/<保持役の pid>/ns/mnt` に写す。以降は S2 の経路（supervisor の入口 → `LaunchOptions::with_pod_shm` → core の pin と複製）
- 受け渡しの運び役は `StartRequest` の欄: cri の `StartOptions` だけでは足りない（cri から plugin-cri への唯一の経路が `ContainerRuntime::start(&StartRequest)` のため）。型は S2 の `PodShmSource` を `core::traits` から再 export する（cri の adapter は `core::traits` だけを参照する契約〔CRI-7〕のため）
- 検査の二重化: core の `start` は `StartRequest` の欄が `Some` で launcher の指定と食い違えば、予約・fork の前に `FailedPrecondition` で拒否する。core を直接使う経路で欄を黙って無視して共有を落とさないため。欄が `None` なら従来どおり通す（supervisor は argv から launcher にだけ載せ、`StartRequest` には載せないため）

##### 共有の条件と一次情報

オーナー決定（2026-11-19。Q1 A）: 共有は「実効の ipc が `POD` で、保持役（user＋ipc を join する）があり、CRI mounts に `/dev/shm` が無いとき」。

| 記録の保持役 | 条件（mounts に `/dev/shm` 無し・ipc `POD`） | 結果 |
| ------------ | -------------------------------------------- | ---- |
| あり・素性あり | 真 | `PodShmSource::new("/proc/<pid>/ns/mnt", dev, ino)`（pid と素性は同じ `PodHolder` から 1 式で取る） |
| あり・素性なし（`PodHolder::new`。照合が無効な試験用の構成） | 真 | `None`（共有しない。オーナー決定） |
| 無し・provider 注入済み | 真 | `FAILED_PRECONDITION`（`sandbox holder is unavailable`。Stop との競合を縮退させない） |
| sandbox の記録が無い（`begin_start` が先に拒否するため通常は到達しない） | 問わない | `FAILED_PRECONDITION`（`sandbox record is unavailable`。条件に当たらない場合の `None` と区別する） |
| 無し・provider なし（rootful 等。join しない） | 真 | `None` |
| 問わない | 偽 | `None` |

- containerd `v2.4.2`（commit `b7a25261`）: `internal/cri/server/container_create.go` の 1151 行 `if !isInCRIMounts(devShm, config.GetMounts()) {` で、CRI mounts に無いときだけ sandbox の shm を足す。ipc のモードでは分けず、1153〜1154 行でコンテナの ipc が `NODE` のときだけ元をホストの `/dev/shm` に変える。`isInCRIMounts` は `internal/cri/server/helpers.go` 221〜228 行で `filepath.Clean` してから比べる。sandbox の ipc は常に共有される（`internal/cri/opts/spec_opts.go` 348〜371 行の `WithPodNamespaces`）。sandbox の shm は `podsandbox/sandbox_run_linux.go` 306〜318 行で `mode=1777,size=64MiB`・`nosuid,nodev,noexec`
- containerd `v2.1.0`（commit `061792f0`）も同じ分岐を 1145〜1149 行に持つ
- kubernetes `v1.37.1`（commit `f78e7223`）: `pkg/kubelet/kuberuntime/util/util.go` 74〜79 行で ipc は `HostIPC` なら `NODE`、それ以外は `POD`。`CONTAINER` は送らない
- 読み: `POD` の範囲で本リポの条件と containerd は一致する。`CONTAINER`・`NODE`・保持役が無い構成・素性なしの保持役は、既存の差に従属するか、本 issue で埋めない（cri-config-acceptance.md の表）

##### 記録に書かない判断（Agent の判断。オーナー了承 2026-11-19）

- 記録ファイル（sandbox 記録 v2）に shm を書かない。`holder=` 行も変えない。再採用した sandbox は常に `NotReady` で、`pod_holder` が `None` のため、記録の shm を読む場面が無い（`begin_start` が `sandbox is not ready` で拒否する）。旧記録（v1・shm を知らない v2）も同じ拒否で fail-closed し、共有なしへの縮退経路は無い
- 受け渡しは `StartRequest` → argv。bundle（config.json）は純 OCI のまま。issue 本文の「bundle へ渡し」は S2 のオーナー決定（argv）に従う
- 再起動をまたいで保持役を生かす方式（(a)）を採るときは、記録の版を上げて shm も書く（再評価条件）
- 稼働中のコンテナは起動時に載せた複製のマウントを持つ。保持役が消えても tmpfs の superblock は生きるため、稼働中の兄弟どうしの共有は続く（新しいコンテナは足せない）

##### `verify_ready` の判断（Agent の判断）

- 照合が有効な構成の `verify_ready` に、READY の shm の `dev` が plugin-cri 自身の `/dev/shm` の `dev` と同じなら拒否する（固定文言の `FAILED_PRECONDITION`。stat できないときも拒否する）
- 理由: S2 の init の照合は「保持役の mnt ns で開いた `/dev/shm` が READY と同じ」までしか確かめない。READY の値自体がホストの tmpfs を指す（保持役に pod の tmpfs が無い）場合は弾けない。保持役の ns は plugin-cri の ns の複製なので、plugin-cri 自身の `/dev/shm` が比較対象になる
- `/proc/<pid>/root/dev/shm` と READY の照合は足さない。同じ照合を init が使用時点で行うため、plugin-cri で先に行っても検査と使用の時点がずれるだけで強度は上がらない。実機試験 `pod_holder_bin_real`（`assert_pod_shm`）が同じ照合を持つ
- 値は READY のまま渡し、plugin-cri で `/dev/shm` を再 stat して作り直さない（S2 の申し送り。`(dev, ino)` は時間をまたいで一意ではないため、保持役が生きている間の READY の値を使う）

##### core の食い違い検査（Agent の判断）

- `oci_runtime::start` は、`StartRequest` の欄と launcher の `pod_shm_source()` の食い違いを、予約と fork の前に `FailedPrecondition` で拒否する（supervisor は argv → launcher の経路のまま。`req` へは載せない）

##### 残余

- 64 MiB は pod の合計。兄弟が埋められる（containerd と同じ。pod 単位の cgroup は未対応）
- 特権ランチャー経由の構成（supervisor が ambient capability つき）は、supervisor が `--pod-shm` を `Unimplemented` で拒否するため、ipc `POD` の CRI コンテナの Start が通らない（オーナー決定 2026-11-19。受け入れて明記。縮退させない）。log_path を省く利用は S3 で新たに落ちる（読みだけ。実機未確認）
- ipc `NODE` のホスト `/dev/shm` は埋めない（オーナー決定 2026-11-19。cri が ipc `NODE` を `UNIMPLEMENTED` にしている）
- 素性なしの保持役（`PodHolder::new`。照合が無効な試験用の構成・外部の provider）は共有しない
- `CONTAINER`（kubelet は送らない）は共有しない（ipc を共有しない既存の差に従属。オーナー決定 2026-11-19）
- kubelet の実機（emptyDir のホスト側 0750 への到達性）は未確認のまま。SELinux 有効ノードは非対応（#4895）
- 実機の確認は PR の `production_binary_exec_real`（段 M・termination-log。成功行は試験ソースから導出して照合）で取る。手元に Linux が無いため、本書の時点では未実行（Windows のスロットの実測も PR 本文で行う）

### オーナー確認事項（#4607）

| 記号 | 確認事項 | 推奨 |
| ---- | -------- | ---- |
| O1 | pid の共有を受けるか（可視性・同じ uid の signal） | 受ける。Landlock による遮断は差として明記 |
| O2 | pod の PID 1 の実体 | 保持役の子 pod-init（pause コンテナは #2838 で却下済み） |
| O3 | pid の既定値と食い違い（sandbox が `CONTAINER`・コンテナが `POD`） | コンテナごとの新しい ns にし差として明記。代案は `UNIMPLEMENTED` |
| O4 | init 終了時の kill-all を既定にするか | 既定にする |
| O5 | pid の `TARGET` を受けるか。対象の固定手段 | launch pidfd の経路だけ。縮退経路は拒否 |
| O6 | `/dev/shm` の方式（A / B / C）と既定サイズ | A（PoC が通れば）、64 MiB |

### セキュリティ上の要点

- パスは自 sandbox の保持役の pid からだけ作る。`TARGET` は状態ストアと launch pidfd で固定する
- ns は 1 回だけ開いて fd に固定し、素性を READY と launch の記録で照合する（TOCTOU）
- pod-init は空の root・capability なし・non-dumpable。兄弟と pod-init の `/proc/<pid>/root` を開けないことを実機試験で必須にする
- pid 共有は「init の終了で pid ns ごと回収される」前提を崩すため、縮退経路の拒否と kill-all を必須にする。判断が出るまでは `UNIMPLEMENTED` で fail-closed（REPAIR-3）
- hostname は cri と保持役の両方で上限つきに検査し、エラー文言は固定文言にする（REPAIR-4）

## PortForward との関係（#3766）

保持役は変えない（待機だけのまま）。POD の PortForward は、plugin-cri が自分の表の保持役の pid から user・net の fd を開き、単一スレッドの helper（`netns-dial`）へ渡して `127.0.0.1:<port>` へ接続させる。設計は [cri-streaming-server.md](cri-streaming-server.md) の「POD ネットワークの PortForward の設計（#3766）」。

## セキュリティ上の要点

- 別 pod の userns の受理: core の認可だけでは防げない（#2776）。パスは自 sandbox の記録の pid からだけ作り、CRI リクエストの値（annotations・config の文字列）からは作らない。pod A / B の取り違えが無い結合試験を必須にする
- TOCTOU: 保持役を記録が残る間は回収しない。core は start で 1 回だけ開いて fd に固定し素性を照合する。userns の写像の完全一致の照合（SEC-5）は維持する
- 攻撃面: 保持役は fd 3 以上を閉じ、秘密を持たない。READY は固定長で上限つきで解釈する
- DoS: 子の一覧は上限つき。READY の受信・解放の待ちはすべて期限つきで、超過したら SIGKILL して回収する（REPAIR-5）
- 後始末: Run の途中で失敗したら保持役・ネットワークの資源を逆順に戻し、戻せなければ記録を残して Stop・Remove で再試行する
- エラー文言は固定文言にし、パス・pid・config の値を含めない（REPAIR-4）
- rootful（uid 0）は #2241 の決定 D1 A により `PERMISSION_DENIED` で恒久拒否（#4709）。init userns 所有の netns への join は受けない（保持役を使うかの決定は下の「rootful の扱い」・#4708）
- 依存は追加しない。追加が必要と分かったら承認事項として報告する

## オーナー判断（2026-11-09）

1. 保持役の dumpable の扱い: 案 (a)（`unshare(USER)` の後に自身を再 exec して non-dumpable を保つ）を作業仮説とする。確定は H2（#2874）の受け入れ条件で、カーネルの一次情報（tag・commit を固定した `fs/proc/namespaces.c`・`kernel/ptrace.c`）と実機（ubuntu CI の `--ignored`）で行い、それまでは未確定として扱う。背景は、`/proc/<pid>/ns/*` の open が `PTRACE_MODE_READ_FSCREDS` を要し、non-dumpable の保持役が exec 後に `unshare` すると同じ uid の core から開けない恐れがあること。確定前の代替は案 (b)（dumpable にして fd・秘密を一切持たない）

2. provider が無い `POD`: 保持役の netns（`lo` のみ。保持役が up にする。H2・#2874）へ join し、pod 内で localhost を共有する（Kubernetes の意味論。core の net の join〔H7・#2872〕が入った後）。`NetworkReady=false` は維持する
3. 本番の pasta provider: #340 の決定（利用者が導入した pasta を exec）で決着した。H10（#2879）は #341 待ちのまま。依存（crate）の追加は伴わない

### 脚注: 案 (a) の根拠と確認結果（H2・#2874）

一次情報（Linux v6.12 の tag。`gh api repos/torvalds/linux/contents/<path>?ref=v6.12` で確認）:

- `fs/proc/namespaces.c` の `proc_ns_get_link`（58 行）・`proc_ns_readlink`（83 行）は `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)` を求める
- `kernel/ptrace.c` の `__ptrace_may_access`（276 行）は、uid が同じなら資格情報の検査を通した後（324 行は `ptrace_has_cap(tcred->user_ns, mode)`）、`get_dumpable(mm) != SUID_DUMP_USER` かつ `!ptrace_has_cap(mm->user_ns, mode)` なら拒否する（342〜343 行）
- `mm->user_ns` は `mm_alloc` → `mm_init(mm, current, current_user_ns())`（`kernel/fork.c` 1336 行）で exec 時の user namespace に決まる（`fs/exec.c` 383 行の `bprm_mm_init`）。exec は dumpable を `SUID_DUMP_USER` に戻す（`fs/exec.c` 1342〜1347 行）。実行ファイルが読めないと `would_dump` が `BINPRM_FLAGS_ENFORCE_NONDUMP` を立てる（1411 行）ため、bin は利用者に読める必要がある（インストールスクリプトは 0755）

したがって、`unshare(USER)` の後に再 exec しないと `mm->user_ns` は初期 namespace のままで、同じ uid の core・plugin-cri は `CAP_SYS_PTRACE` が無く開けない。再 exec すると `mm->user_ns` が pod の user namespace になり、その作成者（親 namespace で euid が owner）は全 capability を持つので開ける。案 (a) の手順は `crates/supervisor/src/pod_holder/holder.rs` の module doc を参照。

実機での確認（`crates/supervisor/tests/pod_holder_bin_real.rs` のシナリオ E）:

- 陰性対照（再 exec しない non-dumpable の保持役相当）では、親が `/proc/<pid>/ns/net` を開けず `PermissionDenied` になる
- 案 (a) の保持役では、親が `ns/net`・`ns/ipc`・`ns/user`・`environ` を開ける。pod の user namespace の中で capability を持たないプロセスは `environ` を開けない（non-dumpable の効果）。同じプロセスが `ns/net` は開けた（Linux 7.0.0-34-generic の実測。ns リンクの扱いはカーネルの版で異なり得るため、non-dumpable の判別には `environ` を使い、ns リンクの拒否は assert しない）
- 保持役自身が READY の前に `PR_GET_DUMPABLE == 0` を確かめる（fail-closed）
- 守れないもの: 親 namespace の同じ uid からの ptrace は non-dumpable でも防げない（設計上の前提）。exec から `PR_SET_DUMPABLE 0` までの短い窓があるが、その間の保持役は秘密を持たない（env は空、argv は namespace の番号だけ）
- 実行記録: ローカル（Linux 7.0.0-34-generic、`kernel.apparmor_restrict_unprivileged_userns=1`、subuid の範囲写像）で 6 シナリオが通った。ubuntu CI の `--ignored` での確認は H3（#2875）で CI に組み込んだ後に行う（それまで CI での確定は未了）

## rootful の扱い（オーナー判断 2026-11-13・#4708・CRI-6・NET-3・SEC-5・CORE-3）

2026-11-13 に #4708 の判断事項 1〜3 がオーナー承認で決着した。以下の (a)〜(d) はコードと文書からの読みで、実機では未確認。

### 決定

1. uid 0 の plugin-cri では保持役 `ProductionPodHolder` を使わない。特権ランチャー経由の非 root の plugin-cri での注入は変えない
2. POD の PortForward は `UNIMPLEMENTED` のまま持ち越す。恒久的な拒否ではない。host の loopback へは縮退しない
3. netns-dial helper は変えない（[cri-streaming-server.md](cri-streaming-server.md) の「オーナー判断（2026-11-13・#4708）」）
4. 実装 issue は起票しない

根拠: rootful の CRI コンテナはまだ起動できず、保持役を使う構成を今設計しても確かめる手段が無い。

判断し直す条件: rootful（uid 0 の plugin-cri、または特権ランチャー経由）の CRI コンテナを起動する経路を設計するとき。

### 読みで確かめた前提（実機では未確認）

- (a) 注入は real / effective のどちらかの uid が 0 と確定しないときだけ（plugin-cri の `adapter.rs` の `pod_holder_injection_enabled`、`pod_holder.rs` の `should_inject_pod_holder`・`current_euid`）。特権ランチャー経由の非 root の plugin-cri では今も注入される。決定文の「実効 uid」より判定は広く、real uid が 0 でも注入しない（決定の趣旨とは矛盾しない。Agent が読みで補った記述でオーナー承認の文言ではない）
- (b) その構成では pod の user namespace の owner と netns-dial helper の euid が同じになり、参加後に dumpable が戻る条件に当たらない見込み（推論。コードでは直接確認できない）
- (c) ambient capability を持つ supervisor は CRI ログの書き込みを `UNIMPLEMENTED` で拒否する（`crates/supervisor/src/logs/cri.rs` の `deny_elevated_capabilities`、[cri-config-acceptance.md](cri-config-acceptance.md)）。`log_path` を渡す通常の kubelet ではコンテナが起動しない
- (d) uid のどれかが 0 の start は `privilege_gate`（`crates/supervisor/src/start_client.rs`）が `PERMISSION_DENIED` で拒否し、provider（`pod_holder.rs` の `rootful_guard`）も uid 0 を `PermissionDenied` で拒否する（#4709）

### 持ち越し: F3 と root 専用 `#[ignore]` 試験

- F3: rootful で `ChownMapped` を使う場合の bundle の所有者の条件（PR #4759 の対象外）
- 試験: `crates/oci/tests/layer_extract.rs` に足す予定だった root 専用の `#[ignore]` 試験（0700 の bundle 配下から写像先 uid で `ChownMapped` の rootfs に到達できるか。`real-machine-tests.md`・`AGENTS.md` への追記を含む）。現時点で未実装（既存の `sec5_chown_subuid_range_as_root` とは別物）
- 持ち越し理由: `ChownMapped` の本番の消費者が無く（#2241 D1:A）、試験は root 実行が要る
- 判断し直す条件: `ChownMapped` の本番の消費者（rootful の CRI コンテナ起動経路）ができたとき。F3 の条件の整理と試験の追加を同時に行う
- 関連: [oci-layer-special-bits.md](oci-layer-special-bits.md) の「未実装」の「配線するときの確認事項」

## 実装の現況（H6・#2877）

plugin-cri の `ProductionPodHolder`（`crates/plugin-cri/src/pod_holder.rs`）が `PodNamespaceHolderProvider` の本番実装で、`CriPluginBackends::production*()` が Linux・非 root の構成だけで `runtime_service()` に注入する。判断（自動運転のため安全側で決めたもの。異論はオーナー判断で差し替える）:

1. **bin の事前検査は行う（fail-closed）**: spawn の前に、実体の隣の固定名（`holder_executable_beside`。`PATH`・環境変数・引数の上書きなし）について、通常ファイル・所有者が root か実効 uid・group / other 書き込み不可・読み取り専用の `open` 成功を確かめる。保持役は段 1 で `/proc/self/exe` を開き直し、non-dumpable 下では `would_dump` の読み取り許可が要るため、読めない bin では成り立たない。読み取り専用の `open` がその代理になる。失敗は固定文言の `FAILED_PRECONDITION`。
2. **READY の後の検証（fail-closed）**: READY の pid が spawn した子の pid と一致し、`/proc/<pid>/ns/{user,ipc,net}` の `(dev, ino)` が READY と一致することを確かめる。この stat は ptrace のアクセス検査を通るため、案 (a)（再 exec で non-dumpable を保つ）が実際に成り立つことの直接の確認にもなる。不一致は SIGKILL して回収し `FAILED_PRECONDITION`。
3. **注入の条件**: `production()`／`production_with_audit_sink()` の構成で、実 uid か実効 uid が 0 と確定しないときだけ注入する（`current_euid`）（読めない場合は注入し、spawn の検査が落とす）。provider 自身も uid 0 では `PermissionDenied` で恒久拒否する（rootful は #2241 の決定 D1 A・#4709）。`new`／`with_recorder` の構成には注入せず、`with_pod_holder_provider` で差す。
4. **上限**: 追跡する子は `MAX_TRACKED_POD_HOLDERS`（1024。`MAX_TRACKED_SUPERVISORS` に倣う）まで。起動途中と回収できなかった子（orphan）も数え、超えたら `RESOURCE_EXHAUSTED`。1 件あたり stdin のパイプ 1 本の fd を保つ。
5. **生存は回収しない**: sandbox の記録が残る間は子を `wait` しない（pid を zombie のままでも保って再利用を防ぐ。SEC-5・#2776）。生存は `waitid(P_PID, WEXITED | WNOHANG | WNOWAIT)` で判定する（pidfd だと 1 件ごとに fd がもう 1 本要るため採らない）。ラッパー `sys::child_exit_observed` は plugin-cri の `sys` の事前承認範囲。回収は `release` が終了を確かめた後だけ。解放は stdin を閉じる → 期限の手前まで待つ → SIGKILL → 回収。
6. **試験の opt-out**: 既定の集合の試験は本番バイナリで `RunPodSandbox` を呼ぶが、rust-ci は AppArmor を緩和せず supervisor の bin も隣に無い。試験用 feature `pod-holder-test-support`（release で有効にすると `compile_error!`）のビルドに限り、環境変数 `FANDHE_CONTAINER_TEST_POD_HOLDER=off` で注入を止める。実機前提の試験は注入する。注入の配線は `pod_sandbox_grpc` の `cri2_h6_injected_pod_holder_fails_closed_without_supervisor_bin` が固定する。

あわせて readopt の不具合を直した（H4 の残り）: 保持役の注入下では起動の前に `pending=1`（`network_pending=0`）を書くため、クラッシュ後の再採用が `network_owned=true` に倒すと、pod network provider を差さない本番で Stop・Remove が回収待ちから抜けられなくなる。`network_owned` は `network_pending` だけから導く（`pending_unresolved` には従来どおり数える）。R11（#2940）は #2877 に依存しており循環するため、ここで直した。

未実装（REPAIR-3）: 保持役の pid から `PodNamespacePaths` を作って bundle へ渡す配線（H5・#2876）は配線済みで、POD のコンテナは user・ipc に join する。保持役の netns の bundle への受け渡しも H8（#2878）で実装済み。素性（pid・starttime・ns の dev:ino）の記録と再採用時の終了済みの確認は R11（#2940）で実装済み（再採用した pid からパスやシグナルは作らない。再起動後の保持役の再採用は未採用）。`/dev/shm` の共有は S3（#4823）で実装済み（下の「実装: S3（#4823）の受け渡し」）。未実装は、pod ネットワークの本番 provider（H10・#2879）と uts の共有（U1〜U5。#4608〜#4612）。

## 実装単位

起票元は #2838。H1〜H10 は中間親 #4334（`phase:7`・#4054 の配下）の sub-issue（#2643 への一時退避から付け替え済み）。H11（#2880）は人間担当として #816 の配下。

| 記号 | issue | 内容 | 担当 | 依存 |
| ---- | ----- | ---- | ---- | ---- |
| H1 | #2870 | core: 保持役の namespace 確立 API | runtime-builder | なし |
| H2 | #2874 | supervisor: `pod-holder` モード（`lo` の up は H1 の API が実施済み。確認のみ） | runtime-builder | H1 |
| H3 | #2875 | ci: 実機前提試験の組み込み | infra-builder | H2・H7 |
| H4 | #2871 | cri: 保持役の注入点と sandbox 記録への pid の保持 | oci-cri-builder | なし |
| H5 | #2876 | cri: `with_pod_namespaces` の配線と pod A/B の結合試験 | oci-cri-builder | H4 |
| H6 | #2877 | plugin-cri: 本番の保持役 provider と注入 | oci-cri-builder | H2・H4 |
| H7 | #2872 | core: pod の network namespace の join | runtime-builder | なし |
| H8 | #2878 | cri: 保持役の netns を bundle と `PodNetworkRequest` へ渡す（実装済み） | oci-cri-builder | H5・H7 |
| H9 | #2873 | cri: `PodSandboxStatus.network` の IP の報告 | oci-cri-builder | なし |
| H10 | #2879 | cri: rootless の本番 `PodNetworkProvider`（pasta）の注入 | oci-cri-builder・net-builder | #1935・#341・H8 |
| H11 | #2880 | 実機確認（人間担当） | 人間 | H6・H8 |

rootful の netns は #2241 のオーナー判断に紐づけ、新規起票しない。

### 共有拡張の単位（#2903）

uts は #4334 の配下に起票済み。pid の `TARGET` は T1（#4819）と T2（#4820）として起票済みで、両方実装済み。pid の共有（P 系）・`/dev/shm` はオーナー判断（#4607）で形が変わりうるため未起票のままで、判断後に #4334 の配下へ起票する。

| 記号 | issue | 内容 | 担当 | 依存 |
| ---- | ----- | ---- | ---- | ---- |
| U1 | #4608 | core: 保持役の namespace 確立に uts を足す | runtime-builder | なし |
| U2 | #4610 | supervisor: `pod-holder` の hostname と READY の uts の素性 | runtime-builder | U1 |
| U3 | #4611 | plugin-cri: hostname の受け渡しと uts の素性の照合 | oci-cri-builder | U2 |
| U4 | #4609 | core: `NamespaceJoin` の uts | runtime-builder | なし |
| U5 | #4612 | cri: uts の path と hostname の抑止・実機試験の段 | oci-cri-builder | U3・U4 |
| T1 | #4819 | core・supervisor: pid の `TARGET` の解決と固定（実装済み。上の「実装（T1・#4819）」） | runtime-builder | なし |
| T2 | #4820 | cri・plugin-cri: `target_id` の検証と `--pid-target` の書き出し（実装済み。上の「実装（T2・#4820）」） | oci-cri-builder | T1 |
| 判断 | #4607 | pid・`TARGET`・`/dev/shm` の受け入れ判断（O1〜O6。人間担当、#816 の配下） | 人間 | なし |

判断後に起票する単位（未起票）: P1 core: join の pid の検査／P2 core: joined pid ns の init の証跡／P3 core: `Pid1Target`・reapply／P4 supervisor: init 終了時の `cgroup.kill`／M1 core＋supervisor: 保持役の mount ns と空の root／P5 core＋supervisor: pod-init と pid ns／P6 plugin-cri: pid の素性の照合と NOTREADY／P7 cri: bundle の pid の path と既定値／P8 ci: 実機試験／S0: 案 A の一次情報と PoC／S1: 保持役の shm の tmpfs／S2 core: `setns` の往復による clone と載せる処理／S3 cri: 受け渡し（#4823 で実装済み）。
