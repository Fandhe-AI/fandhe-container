# CRI の devices・CDI の受け入れ方針（判断記録）

CRI の `ContainerConfig.devices`（`Device{container_path, host_path, permissions}`）と `ContainerConfig.cdi_devices`（`CDIDevice{name}`）を受け入れるかの判断材料を整理する（CRI-2・GPU-1）。

> **位置づけ**: 状態は **オーナー判断待ち**（[#2673](https://github.com/Fandhe-AI/fandhe-container/issues/2673)）。本書は決定ではなく判断材料である。判断が出るまで cri は `UNIMPLEMENTED` のまま拒否する（分離を緩めない）。本書の時点で受け入れた項目は 1 つも無い。

- 対象ビヘイビア: CRI-2・GPU-1。関連: GPU-2・GPU-3・GPU-4・GPU-8・GPU-9・OCI-4・SEC-1・PLUG-11
- タスク: TASK-114 追補・TASK-56。関連: #541・#60・#2606（受け入れ順序は [cri-config-acceptance.md](cri-config-acceptance.md) の順 11）

## 現状

- cri: `crates/cri/src/bundle/spec.rs` が `devices` の非空を `devices is not supported`、`cdi_devices` の非空を `cdi_devices is not supported`（どちらも固定文言。値を含めない）の `UNIMPLEMENTED` で拒否する。両方あるときは先に評価する `devices` の文言になる
- core: `linux.devices` は `UnappliedField::LinuxDevices`、`linux.resources.devices` は `UnappliedField::LinuxResourcesDevices` として create / start が拒否する。`exec/devices.rs` が作るのは OCI 既定の 6 デバイスだけ。`DeviceAllowList`（`cgroups/device.rs`）は封印され、公開の構築は固定表の `oci_default()` だけ（外部入力から major / minor を受ける経路は設計上作らない）
- gpu: 実装済みは CDI spec の解析・集計・usr-merge 正規化（TASK-126）まで。適用（TASK-127・#546）、Landlock の `IOCTL_DEV`・seccomp（TASK-128・#553）、`BPF_CGROUP_DEVICE`（TASK-129・#559）、読み取り専用 rootfs と hook の両立（TASK-131・#566）は未実装。名前（`vendor/class=name`）から spec を引く解決と `/var/run/cdi` の走査も未実装
- 試験: `crates/cri/tests/bundle_spec.rs` の `cri2_gpu1_devices_and_cdi_devices_are_rejected_with_fixed_message` が code・固定文言・値の非混入・評価順を具体値で照合する

## 依存の連鎖

受け入れは次の順に進む。どれも本 PR の範囲外で、既存の open issue が担う。

1. GPU-1（解析・集計。済み）
2. GPU-2（TASK-127・#546。mknod・bind・hook のホスト側実行）
3. GPU-4（TASK-129・#559。device cgroup の許可リスト）
4. GPU-3（TASK-128・#553。Landlock・seccomp）
5. GPU-8（TASK-131・#566）
6. cri の配線（CRI-2。上記の完了後に起票する）

一般デバイスの `devices[]` は GPU-9 にかかり、spec 側で **検討中**のため確定扱いしない。確定は spec リポ側の課題である。core の `linux.devices` の解釈には OCI-4、権限の拡張の扱いには SEC-1 を併記する。

## 選択肢

### A. 判断が出るまで `UNIMPLEMENTED` を維持する（推奨・当面）

受けて値を捨てると、要求したデバイスが黙って無いコンテナが起動する。device cgroup 無しに付与すれば Docker・runc より弱い fail-open になる。どちらも作らない。

### B. TASK-127・129・128 の完了後に CDI だけ受け入れる

`cdi_devices` を gpu の適用へ配線する。名前から spec を引く解決の置き場所（cri か gpu か）は未決。

### C. 一般デバイスの `devices[]` も受け入れる

GPU-9 の確定とオーナー判断が要る。

## 受け入れの前に後続が満たす要件

- device cgroup（TASK-129）無しに `devices[]` を受けない
- rootless では device cgroup が効かない（GPU-4）。mknod の `EPERM` を黙ってホストの bind に縮退させない。[dev-default-mounts.md](dev-default-mounts.md)・`DeviceSupply::BindFromHost` と整合をとる
- CDI spec ディレクトリは root 所有で他ユーザーが書けないことを検査する（PLUG-11 と同型）
- CDI hook は spec が指定するホスト側のバイナリを実行する。完全性（OWASP A08）のため、hook のパスの信頼を前提にする
- `host_path` は文字・ブロックデバイスであることを、symlink を辿らない fd 起点の stat で検証し、major / minor は stat の値を正とする
- `permissions` は `rwm` の部分集合であることを検証する

## 観察事項

`ContainerConfig.annotations` は cri が見ていないため、device plugin が従来の注釈（`cdi.k8s.io/*`）で CDI デバイスを要求しても黙って無視され、デバイス無しで起動する。分離を弱める方向ではないが、fail-closed の既定として拒否を推奨する。拒否するかはオーナー判断の事項で、本書の時点では挙動を変えない。
