# 非 GPU デバイスの CDI spec 一般化の検証準備

CDI の適用機構（GPU-1〜GPU-4）を GPU 以外の一般デバイス（USB・シリアル等）にも使えるかについて、机上で確かめられた範囲と GPU 固有の前提が残る箇所を整理する。

> **位置づけ**: TASK-132 のうち Claude Code が担当する部分（[#570](https://github.com/Fandhe-AI/fandhe-container/issues/570)）。実機 PoC と GPU-9 の確定の要否は [#571](https://github.com/Fandhe-AI/fandhe-container/issues/571)（TASK-132.h1・人間）が判断する。本書は判断材料であり、GPU-9 は spec で **検討中**のまま確定扱いしない。

- 対象ビヘイビア: GPU-9。関連: GPU-1〜GPU-4・GPU-7・GPU-8・CRI-2・SEC-1・PLUG-11
- タスク: TASK-132。前提: TASK-126（#541。解析・集計・usr-merge。済み）
- CRI の一般デバイス `devices[]` の受け入れ側の要件は [cri-devices-cdi.md](cri-devices-cdi.md) が持つ。本書では書き直さない

## 机上検証の対象とした範囲

| 層 | 状態 | 本書での扱い |
| -- | ---- | ------------ |
| 解析・版の検査（`cdi_spec`）、集計（`cdi_edits`）、usr-merge（`cdi_paths`） | 実装済み（TASK-126） | 自作 spec で試験した |
| 適用（mknod・bind mount・hook。TASK-127・#546） | 未実装 | spec の記述からの洗い出しのみ |
| Landlock・seccomp（TASK-128・#553） | 未実装 | 同上 |
| `BPF_CGROUP_DEVICE`（TASK-129・#559） | 未実装 | 同上 |
| 読み取り専用 rootfs と hook（TASK-131・#566） | 未実装 | 同上 |
| `/var/run/cdi` の走査と名前の解決、CRI の配線 | 未実装 | 対象外 |

## サンプル spec と結果

`example.com` の例示用ドメインで自作した（実在のベンダー名・シリアル番号は使わない）。major は Linux の `devices.txt` の固定割り当てで、#571 の実機で `ls -l` と照合できる。

| fixture | 想定 | 要点 |
| ------- | ---- | ---- |
| `crates/gpu/tests/fixtures/cdi-non-gpu-serial.yaml` | USB シリアル変換器 | `cdiVersion` 0.7.0・`/dev/ttyUSB0`（c 188:0・rw・fileMode 432・gid 20）・`additionalGids` [20]・env 1 件 |
| `crates/gpu/tests/fixtures/cdi-non-gpu-usb.yaml` | 生の USB デバイスノード | `cdiVersion` 0.5.0・`/dev/bus/usb/001/002`（c 189:1・rwm・`hostPath` あり）・`/run/udev` の `ro,nosuid,nodev,bind` mount 1 件 |

試験は `crates/gpu/tests/cdi_non_gpu.rs`（公開 API のみ。5 件）。

- `gpu1_non_gpu_serial_spec_parses_and_aggregates` / `gpu1_non_gpu_usb_spec_parses_and_aggregates`: 解析と集計の結果（deviceNodes・mounts・env・hooks・additionalGids）を具体値で照合
- `gpu1_non_gpu_specs_read_from_file`: ファイル経路と文字列経路で結果が等しい
- `gpu1_non_gpu_usr_merge_leaves_dev_paths_unchanged`: usr-merge 正規化は `/dev`・`/run` の path を変えない。なお正規化は `hostPath` 省略時に `path` と同じ値を補う（観測した挙動）
- `gpu1_non_gpu_min_version_rules_apply`: `additionalGids`（0.7.0 以上）・`hostPath`（0.5.0 以上）の最小版の規則が非 GPU の spec にも効き、`InvalidArgument` で拒否される

結論: 解析・集計・版の検査・usr-merge の層に GPU 固有の前提は無く、非 GPU の spec をそのまま受ける。CDI 1.1.0 の `netDevices` だけは適用が未実装のため spec 全体を `Unimplemented` で拒否する（#2445。既知の挙動で、サンプルには含めていない）。

## GPU 固有の前提の洗い出し

区分は「文言」（コメント・doc の書き方だけ）、「根拠」（値は足りるが根拠の説明が GPU 寄り）、「挙動」（適用時に決める必要がある）。

### 実装済みの層

| 箇所 | GPU 固有の前提 | 非 GPU への影響 | 区分 |
| ---- | -------------- | --------------- | ---- |
| `crates/gpu/src/cdi_edits.rs` の `CDI_EDITS_MAX_REQUESTED_DEVICES`・`CDI_EDITS_MAX_DEVICE_NAME_BYTES` | 上限の根拠が nvidia.yaml の構成（GPU 16 基・MIG 7 分割・`GPU-` UUID 長） | 値は USB・シリアルでも足りる。#2983 で根拠を GPU に限らない書き方へ直した（値・挙動は不変） | 根拠 |
| `crates/gpu/src/cdi_spec.rs` の入力上限 1 MiB | 根拠が「nvidia.yaml は数十 KiB」 | 非 GPU の spec は小さく問題なし。#2983 で根拠を GPU に限らない書き方へ直した（値・挙動は不変） | 根拠 |
| `crates/gpu/src/cdi_spec.rs` の `reopen_via_proc` の doc | 「GPU 編集を飛ばすのを防ぐ」と書かれている | 挙動は汎用。#2983 で doc を GPU に限らない書き方へ直した（挙動は不変） | 文言 |
| `crates/gpu/src/cdi_paths.rs` | usr-merge の動機が firmware・`/usr/bin` | `/dev` は対象外で変わらない（試験で確認）。hooks の `path` は正規化しない | 影響なし |

### 未実装の層（spec の記述から。確定した設計ではない）

| 層 | GPU 固有の前提 | 非 GPU デバイスへの影響 | 区分 |
| -- | -------------- | ----------------------- | ---- |
| TASK-127（適用） | hook の実行順（rootfs 自己 bind → /proc → hook → pivot_root）は nvidia-ctk の hook のための制約 | hook の無い非 GPU spec では効かない。一般の制約として固定しない | 挙動 |
| TASK-127 | `type: b` / `p` の mknod、`hostPath` が symlink の場合（`/dev/serial/by-id/...` 等）の扱いは GPU の spec では出番が少ない | 適用時に決める必要がある | 挙動 |
| TASK-128（Landlock・seccomp） | `/proc/self/task/<tid>/comm` への書き込み許可は GPU ドライバ用 | 非 GPU では付けない（条件付きにする）。`IOCTL_DEV` は termios・usbfs の ioctl にも同様に効く | 挙動 |
| TASK-129（device cgroup） | 許可リストは major / minor 単位（GPU-7 のリスク (b)：major が動的に割り当てられる） | USB の minor は抜き差しで変わり、spec の生成時と実行時でずれる。許可リストの対象に `b` も要る。rootless では device cgroup が効かない（GPU-4） | 挙動 |
| TASK-131・GPU-8 | 書き込み対象パスが `/etc/nvidia/` 等の GPU 固有のもの | hook の無い非 GPU spec では不要 | 挙動 |
| `additionalGids` | GPU では video / render 系 | シリアルの dialout 等は 0.7.0 の `additionalGids` で表せる | 影響なし |

### 観察事項・要追跡

- `kind` / `name` の形式と `deviceNodes[].permissions` の値は #2984 で解析層（`cdi_spec.rs`）が検証する。`deviceNodes[].type` の値は #2979、パスの絶対性・正規形は #2978・#2979 で適用層が検証済み。`permissions` の device cgroup への反映は TASK-129.1（#560）
- spec ディレクトリの所有者の検査と hook の完全性（PLUG-11 と同型）は、非 GPU でも同じ前提になる。device cgroup（TASK-129）を入れずに一般デバイスを受けてはならない（受け入れ前の要件は [cri-devices-cdi.md](cri-devices-cdi.md)）
- 上限値の根拠・`reopen_via_proc` の doc の GPU 寄りの文言は、#2983 でコメントのみ直した（上限値・挙動は不変）
- 抜き差しで変わる minor が、許可リストで別のデバイスを許す・拒否するおそれ。major / minor は stat の値を正とする方針と整合させる

## #571 向けの実機 PoC 手順（案）

実施と判断は人間が行う。本書は案に留める。

1. 用意: USB シリアル変換器 1 台、Linux ホスト（podman と CDI が使えるもの）
2. fixture の major / minor を `ls -l /dev/ttyUSB0`・`/dev/bus/usb/...` の実値に合わせて写し、`/etc/cdi/` に置く
3. `podman run --device example.com/serial=ttyusb0 ...` で、コンテナ内の deviceNodes・mounts・env・groups を観測する（GPU-1 と同様に件数を照合する）
4. TASK-127 / 129 の実装後に、fandhe-container 側で同じ照合をする

成功基準の案: deviceNodes・mounts・env の件数の差が 0、シリアルの読み書きの疎通、device cgroup 下で許可リストに無いデバイスへの open が `EPERM`。

判断事項: GPU-9 を確定とするかは spec 側の課題として報告する（本リポからは spec を編集しない）。

## 残課題・追跡

- GPU 前提の文言の直し（コメントのみ）は #2983 で済み
- 抜き差しで変わる minor への対応、`type: b` の扱いは未追跡。新規の起票は行わず、PR 本文に要追跡として挙げる
