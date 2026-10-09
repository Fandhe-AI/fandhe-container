# VZCustomVirtioDevice による最小 virtio-gpu 登録の可否確認（TASK-172.6）

macOS 27 の `VZCustomVirtioDevice` で、VENUS capset だけを広告する最小 virtio-gpu を TASK-64 の最小 VM に登録できるかを確かめる PoC。結果は #1057（TASK-172.h5。人間担当）の VMM 方式判定（Virtualization.framework 統合か Hypervisor.framework 上の自前 VMM か）に使う。対象ビヘイビア: GPU-6・MAC-5（MS-13）。issue: #1056。

製品 crate ではない。workspace 外に置き、ビルド対象にしない。

## 現状（実装済みを装わない。REPAIR-3）

| 項目 | 状態 |
| ---- | ---- |
| ゲスト側確認スクリプト（`guest/check-virtio-gpu.sh`）と自己テスト | 実装済み。合成 fixture だけで検証 |
| ホスト側のデバイス登録コード | **未実装**。承認事項 A〜D は決定済み（`docs/design/venus-decoder-poc.md` 9 章）。本体は #1522 |
| 実機での判定（probe・capset・host visible・Mesa venus 初期化） | 未実施。#1057 で人間が行う |

ホスト側を止めた理由は、採用中の `objc2-virtualization =0.3.2` が `VZCustomVirtioDevice` 系を含まず、新規依存・`unsafe` の承認が要るため。

## ホスト側デバイス契約（後続のホスト実装が満たす値。要確認を含む）

- virtio device ID 16（GPU）。virtqueue 数 2（controlq・cursorq）。PCI class は display（0x03）、subclass は other（0x80）の見込み（要確認）
- feature: `VIRTIO_GPU_F_VIRGL`（bit 0）・`VIRTIO_GPU_F_RESOURCE_BLOB`（bit 3）・`VIRTIO_GPU_F_CONTEXT_INIT`（bit 4）。EDID は広告しない。`VIRTIO_F_VERSION_1` の要否と mandatory / optional の振り分けは要確認
- device config（16 B・u32 LE ×4）: `events_read`=0・`events_clear`=0・`num_scanouts`=0・`num_capsets`=1
- capset は VENUS（id 4）のみ。GET_CAPSET_INFO の応答は `crates/plugin-macos/src/gpu/venus/capset.rs` の `capset_info`（max_version 0・max_size 160）
- 共有メモリ: shmid 1（`VIRTIO_GPU_SHM_ID_HOST_VISIBLE`）を `VZVirtioSharedMemoryRegionConfiguration` で提示する。サイズは未決
- `num_scanouts=0` は古いゲストカーネルで probe が失敗しうる（`num_scanouts is zero`）。ゲストカーネル版を必ず記録する
- 共有メモリはゲストが書き込める host メモリで信頼境界になる。ホスト実装時は security-auditor のレビューを必須とする

## ゲスト側確認の手順（#1057 で人間が実施）

1. TASK-64 の最小 VM でゲスト Linux を起動する（ホスト側ハーネス実装後）
2. ゲスト内で `sudo dmesg > dmesg.txt`。任意で `VN_DEBUG=init vulkaninfo --summary > vulkaninfo.txt`
3. `bash guest/check-virtio-gpu.sh --dmesg-file dmesg.txt [--vulkaninfo-file vulkaninfo.txt]`
4. 出力（`key=value`）と終了コード（0 = 期待どおり、1 = 期待外れ、2 = 入力エラー）、ゲストカーネル版、Mesa 版を #1057 に貼る

実機ログを貼る前に、ホスト名・アドレス等のホスト固有情報を伏せること。fixture には合成データのみを置き、実機ログはコミットしない。

自己テスト: `make vz-virtio-gpu-guest-check-selftest`（macOS 27・VM 不要）。CI は `integration-test` ジョブが ubuntu・macos・windows（Git Bash）の 3 OS で実行し、下記の前提ツールで動くことを確かめる。

前提ツール: bash と、`head -c`・`dd`・`mktemp`・`sed -E`・`grep -E`・`wc`・`tr`・`cut`・`sort`・`uniq`。いずれも macOS 標準（BSD 系）と Linux（GNU coreutils・busybox）の双方にあり、GNU coreutils の追加導入は不要（`truncate` 等の GNU 専用コマンドは使わない）。
