# CRI の cgroup_parent の受け入れ方針（判断記録）

CRI の `PodSandboxConfig.linux.cgroup_parent` を受け入れるかの判断材料を整理する（CRI-2・CORE-4）。

> **位置づけ**: 状態は **オーナー承認待ち**（[#2672](https://github.com/Fandhe-AI/fandhe-container/issues/2672)）。本書は決定ではなく判断材料である。決まるまで cri は `UNIMPLEMENTED` のまま拒否する（分離を緩めない）。

- 対象ビヘイビア: CRI-2・CORE-4。関連: CORE-3・SEC-1
- タスク: TASK-114 追補・TASK-56。関連: #2010・#2060・#2606（受け入れ順序は [cri-config-acceptance.md](cri-config-acceptance.md) の順 10）

## 現状

- cri: `crates/cri/src/bundle/spec.rs` が `linux.cgroup_parent` の非空を `UNIMPLEMENTED`（固定文言 `linux.cgroup_parent is not supported`。値を含めない）で拒否する。検査は `validate_config` 経由で `CreateContainer` の時点で効く。`RunPodSandbox` の時点では検査しない（観察事項。本書の時点では変えない）
- core: `linux.cgroupsPath` は #2010 の方針で値に関わらず `check_cgroups_path` が拒否する。コンテナの cgroup は常に委譲スコープ配下の `fc-<id>@<n>` に置かれる（[cgroups.md](cgroups.md)）
- CORE-4: cgroups v2 のみ。systemd cgroup driver は持たない
- 試験: `crates/cri/tests/bundle_spec.rs` の `cri2_core4_cgroup_parent_is_rejected_with_fixed_message` が code・固定文言・値の非混入を具体値で照合する

## 実務への影響

kubelet は既定（cgroupsPerQOS）で cgroup_parent を送るため、kubelet 経由の `CreateContainer` は現状すべて `UNIMPLEMENTED` になる。crictl の疎通確認（#442）は cgroup_parent を指定しなければ影響を受けない。

## 受け取る値の 2 形式

- cgroupfs 形式（例: `/kubepods/burstable/pod<uid>`）
- systemd 形式（例: `kubepods-burstable-pod<uid>.slice`）。CORE-4（systemd cgroup driver を持たない）により、どの選択肢でも受け入れない

containerd の変換は一次情報で照合済み（確認日 2026-10-26。#2772。containerd `v2.4.2`・commit `b7a25261e029d68978bbf290df0a62fc819b3c51`。出典の一覧は `cri-config-acceptance.md`「外部の事実の照合」）。

- `getCgroupsPath`（[`internal/cri/server/helpers.go` L447-L455](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/helpers.go#L447-L455)）: 親の末尾の要素が `.slice` なら `<末尾の要素>:cri-containerd:<コンテナ id>`（runc の systemd 形式）、そうでなければ `<親>/<コンテナ id>`（cgroupfs 形式）。親の形で形式が決まり、containerd 側の設定で選ぶものではない
- kubelet（`v1.37.1`・commit `f78e722310e50bcaca9276be22276d9e91d91308`）は `kuberuntime_sandbox.go` L167-L170 で `CgroupParent` を常に設定する。値は `pkg/kubelet/cm/pod_container_manager_linux.go` の QoS 別の pod の cgroup 名で、cgroupsPerQOS を無効にした構成だけ空になる（同 L343-L349）。下の「実務への影響」はこれと一致する

本実装が受け入れないという判断（CORE-4）は変わらない。

## 選択肢

### A. 判断が出るまで `UNIMPLEMENTED` を維持する（推奨）

本項は、#2010 の方針を再判断するまで受理しない。文言は未決を表す `is not supported` のまま。

### B. 委譲スコープの中に閉じる相対パスに限って受け入れる

core が `linux.cgroupsPath` の受理を先に開く必要がある（core → cri の順。別 issue）。必要な設計:

- 相対パスだけを受け、`..`・絶対パス・NUL・空要素・別表記・symlink を拒否する
- 長さは core と同じ 4096 バイト以下とし、要素数にも上限を設ける
- 置き場所は委譲スコープ配下とし、`fc-<id>@<n>` との関係を状態記録・検証つき削除（#2060）と整合させる
- kubelet の QoS / pod の cgroup（ホストの `/sys/fs/cgroup/kubepods/...`）とは別の木になる。kubelet が書いた制限は効かないため、B でも kubelet との完全な互換にはならない
- エラー code（形式不正は `INVALID_ARGUMENT`、委譲スコープの外は `UNIMPLEMENTED` か `PERMISSION_DENIED` か）は判断事項として残す

### C. 受けて値を無視する（採らない）

kubelet の pod 単位・QoS 単位の資源制限と eviction の計上が黙って効かなくなり、要求より弱い資源制限で起動する（fail-open。SEC-1・CORE-3）。

## 済ませたこと / 残る作業

- 済み: 拒否の照合の強化（code・固定文言・値の非混入）と参照の整備
- A に決まれば、文言と doc の確定だけが残る
- B に決まれば、core の `linux.cgroupsPath` の受理（委譲スコープ内の検証・状態記録との整合）、cri の変換と単体試験（具体値）の順で、別 issue を起票する
- 監査（SEC-4）には記録しない。設定の未対応であり、脱出の試行ではないため
