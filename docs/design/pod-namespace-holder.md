# pod の namespace 保持役・netns の共有・本番の PodNetworkProvider 注入の設計（CRI-2・CORE-3・SEC-5・NET-3・CORE-1）

設計記録（#2838）。コードは本変更で変えない。実装は「実装単位」の各 issue で行う。オーナーが 2026-11-09 に承認した（記録は #2838 のコメント）。採用は supervisor の bin の `pod-holder` モード・依存の追加なし・`unsafe` は各 crate の `sys` の事前承認範囲。旧要確認事項 3 点の決定は「オーナー判断（2026-11-09）」に記す。

## 背景

- cri は pod の ipc 共有を bundle へ変換できる（#2674）。パスは `PodNamespacePaths::for_holder_pid`（`/proc/<pid>/ns/{user,ipc}` だけ。#2776）でしか作れない。`CriRuntimeService` の配線は #2876（H5）で実装済みで、保持役の provider を注入したときだけ `with_pod_namespaces` を渡す。本番（plugin-cri）は provider が未注入（H6・#2877）のため、pod のコンテナは常に新しい namespace で起動する
- pod の netns は `PodNetworkProvider`（cri）と plugin-cri の `NetsetupPodNetwork`（bridge・veth。rootful 前提）まで実装済み（#2675・#2676）。ただし本番へは未注入で、core の `NamespaceJoin` は network の path を `Unimplemented` で拒否し、`PodSandboxStatus.network` は provider の報告だけを返す経路が実装済み（#2873）だが、provider 未注入のため実際には空
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
- 記録の永続化と再採用の設計は [cri-record-readoption.md](cri-record-readoption.md)（#2902）

## netns の共有と core の join の受け口

- 保持役は user → ipc → net の順に作り、netns は pod の userns が所有する
- core の `NamespaceJoin` を拡張し、user＋ipc に加えて任意で net を受ける。net の所有 userns（`NS_GET_USERNS`）が join する user と同じであることを照合し、`setns` は user → ipc → net → 残りの `unshare` の順にする。net 単独の path・user が無い path は従来どおり `Unimplemented`
- 実装済み（H7・#2872）: `paths_of` は user＋ipc の組に net を足す形だけを受け、`pin` は net の所有 userns を照合する（呼び出し側自身または外側の所有は `Unimplemented`〔`pod_join_net_not_pod_owned`〕、別の userns 所有は `PermissionDenied`〔`pod_join_net_owner_mismatch`〕）。`EffectiveNetwork::PodJoined` を足し、exec 直前の netns 素性の同期点（D8）にも通す（pin 時に固定した netns の素性との一致を期待する。`FromConfig` の CRI の経路のうち join する起動だけ）。受理と拒否は層 `pod_namespace_join` の監査に残す（SEC-4）
- 現行の注記（netns を userns より先に `setns` する順序）は、userns が所有する netns では問題にならない。user の後に net へ入れる
- rootful の init userns 所有の netns（bridge・veth の `NetsetupPodNetwork`）は、#2241 の判断まで `Unimplemented` のまま
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
- 実装の現況（H2・#2874）: `lo` の up は H1 の `establish_pod_namespaces`（#2870）が netns の作成直後に行う（失敗したらエラー）ため、`pod-holder` モードは重ねて up にせず、保持役の netns の中で `127.0.0.1` が使えることを実機試験で確かめる（`pod_holder_bin_real` のシナリオ B。保持役の netns へ `nsenter` で入った 2 つのプロセスが TCP で往復する）。コンテナを使った「pod 内の 2 コンテナ」の試験は core の net join（H7・#2872）が要るため、H7 の後に H3（#2875）か H5 で扱う

## PodSandboxStatus.network の IP 報告

- `PodNetns`（`#[non_exhaustive]`）に `ip`・`additional_ips` を足し、provider が報告した値だけを記録して返す。推測しない（REPAIR-3）。provider が無い・報告が無い場合は空

## 範囲外

- pid の共有（`shareProcessNamespace`。`Pid1Target` の見直しが要る）
- `/dev/shm` の共有、uts の共有、`NamespaceMode::TARGET`
- rootful の pod netns（#2241）
- 再起動をまたぐ sandbox の再採用（TASK-59。設計は [cri-record-readoption.md](cri-record-readoption.md)・#2902）

## セキュリティ上の要点

- 別 pod の userns の受理: core の認可だけでは防げない（#2776）。パスは自 sandbox の記録の pid からだけ作り、CRI リクエストの値（annotations・config の文字列）からは作らない。pod A / B の取り違えが無い結合試験を必須にする
- TOCTOU: 保持役を記録が残る間は回収しない。core は start で 1 回だけ開いて fd に固定し素性を照合する。userns の写像の完全一致の照合（SEC-5）は維持する
- 攻撃面: 保持役は fd 3 以上を閉じ、秘密を持たない。READY は固定長で上限つきで解釈する
- DoS: 子の一覧は上限つき。READY の受信・解放の待ちはすべて期限つきで、超過したら SIGKILL して回収する（REPAIR-5）
- 後始末: Run の途中で失敗したら保持役・ネットワークの資源を逆順に戻し、戻せなければ記録を残して Stop・Remove で再試行する
- エラー文言は固定文言にし、パス・pid・config の値を含めない（REPAIR-4）
- rootful（uid 0）は #2241 の判断まで `UNIMPLEMENTED`。init userns 所有の netns への join は受けない
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

## 実装の現況（H6・#2877）

plugin-cri の `ProductionPodHolder`（`crates/plugin-cri/src/pod_holder.rs`）が `PodNamespaceHolderProvider` の本番実装で、`CriPluginBackends::production*()` が Linux・非 root の構成だけで `runtime_service()` に注入する。判断（自動運転のため安全側で決めたもの。異論はオーナー判断で差し替える）:

1. **bin の事前検査は行う（fail-closed）**: spawn の前に、実体の隣の固定名（`holder_executable_beside`。`PATH`・環境変数・引数の上書きなし）について、通常ファイル・所有者が root か実効 uid・group / other 書き込み不可・読み取り専用の `open` 成功を確かめる。保持役は段 1 で `/proc/self/exe` を開き直し、non-dumpable 下では `would_dump` の読み取り許可が要るため、読めない bin では成り立たない。読み取り専用の `open` がその代理になる。失敗は固定文言の `FAILED_PRECONDITION`。
2. **READY の後の検証（fail-closed）**: READY の pid が spawn した子の pid と一致し、`/proc/<pid>/ns/{user,ipc,net}` の `(dev, ino)` が READY と一致することを確かめる。この stat は ptrace のアクセス検査を通るため、案 (a)（再 exec で non-dumpable を保つ）が実際に成り立つことの直接の確認にもなる。不一致は SIGKILL して回収し `FAILED_PRECONDITION`。
3. **注入の条件**: `production()`／`production_with_audit_sink()` の構成で、実効 uid が 0 と確定しないときだけ注入する（読めない場合は注入し、spawn の検査が落とす）。provider 自身も uid 0 では `UNIMPLEMENTED`（rootful は #2241・#2442 の判断まで従来どおり）。`new`／`with_recorder` の構成には注入せず、`with_pod_holder_provider` で差す。
4. **上限**: 追跡する子は `MAX_TRACKED_POD_HOLDERS`（1024。`MAX_TRACKED_SUPERVISORS` に倣う）まで。起動途中と回収できなかった子（orphan）も数え、超えたら `RESOURCE_EXHAUSTED`。1 件あたり stdin のパイプ 1 本の fd を保つ。
5. **生存は回収しない**: sandbox の記録が残る間は子を `wait` しない（pid を zombie のままでも保って再利用を防ぐ。SEC-5・#2776）。生存は `waitid(P_PID, WEXITED | WNOHANG | WNOWAIT)` で判定する（pidfd だと 1 件ごとに fd がもう 1 本要るため採らない）。ラッパー `sys::child_exit_observed` は plugin-cri の `sys` の事前承認範囲。回収は `release` が終了を確かめた後だけ。解放は stdin を閉じる → 期限の手前まで待つ → SIGKILL → 回収。
6. **試験の opt-out**: 既定の集合の試験は本番バイナリで `RunPodSandbox` を呼ぶが、rust-ci は AppArmor を緩和せず supervisor の bin も隣に無い。試験用 feature `pod-holder-test-support`（release で有効にすると `compile_error!`）のビルドに限り、環境変数 `FANDHE_CONTAINER_TEST_POD_HOLDER=off` で注入を止める。実機前提の試験は注入する。注入の配線は `pod_sandbox_grpc` の `cri2_h6_injected_pod_holder_fails_closed_without_supervisor_bin` が固定する。

あわせて readopt の不具合を直した（H4 の残り）: 保持役の注入下では起動の前に `pending=1`（`network_pending=0`）を書くため、クラッシュ後の再採用が `network_owned=true` に倒すと、pod network provider を差さない本番で Stop・Remove が回収待ちから抜けられなくなる。`network_owned` は `network_pending` だけから導く（`pending_unresolved` には従来どおり数える）。R11（#2940）は #2877 に依存しており循環するため、ここで直した。

未実装（REPAIR-3）: 保持役の pid から `PodNamespacePaths` を作って bundle へ渡す配線は H5（#2876）、保持役の netns を pod ネットワークへ渡すのは H8（#2878）で、それまでコンテナは保持役の namespace に join しない（保持役は起動して生きているだけ）。素性の永続化と再起動後の再採用は R11（#2940）。

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
| H8 | #2878 | cri: 保持役の netns を bundle と `PodNetworkRequest` へ渡す | oci-cri-builder | H5・H7 |
| H9 | #2873 | cri: `PodSandboxStatus.network` の IP の報告 | oci-cri-builder | なし |
| H10 | #2879 | cri: rootless の本番 `PodNetworkProvider`（pasta）の注入 | oci-cri-builder・net-builder | #1935・#341・H8 |
| H11 | #2880 | 実機確認（人間担当） | 人間 | H6・H8 |

rootful の netns は #2241 のオーナー判断に紐づけ、新規起票しない。
