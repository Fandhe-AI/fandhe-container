# virtio の VIRTIO_F_RING_RESET（キュー個別の reset と再有効化）を非対応とする判断記録

MVM-1・MVM-5・#4169（親 #4115、停止側の実装は #4031 / PR #4093）。本書の判断は Agent の記録した判断であり、オーナー承認ではない。

## 現状の挙動

- `QueueReady=0` は `FEATURES_OK` 済みなら `DRIVER_OK` の後でも受け、ready だったキューは `VirtioDevice::queue_stopped` でデバイス側の処理を止める（#4031。サポート済み）。
- `DRIVER_OK` の後の `QueueReady=1` は `WrongDeviceState` で無視する。止めたキューを使える状態に戻す方法は、Status=0 によるデバイス全体の reset と、その後の再初期化だけ。
- `VIRTIO_F_RING_RESET`（ビット 40）は device features に提示しない。ドライバが要求すると `FEATURES_OK` を立てない（fail-closed）。
- `QueueReset`（オフセット 0x0c0）は未知のレジスタとして無視する。
- つまり「停止は対応、停止後の再有効化だけ非対応」である。`virtio_mmio.rs` の `queue_stopped`・`QueueStopped` の doc と同じ内容。

## 判断

`VIRTIO_F_RING_RESET` は非対応とする。

## 理由

- キュー単位の reset の状態遷移（`QueueReset` が 1 の間は reset 中で、完了したら `QueueReset` と `QueueReady` を両方 0 にする）を持たない。
- 1 本のキューだけを activate し直す口が `VirtioDevice` に無い。`activate` は `DRIVER_OK` で 1 回呼ばれるだけで、`queue_stopped` は状態を手放すだけ。
- 提示しなければ、仕様上ドライバはキュー個別の reset を使えない（2.6.1）。半端な実装でゲストが再有効化し、古いリングをホストが読み続ける窓ができるより、提示しないほうが安全。

## 影響

`RING_RESET` を前提にするゲストの機能（例: 実行中にキュー数や長さを変える操作）は使えないか、デバイス全体の reset に縮退する。実ゲストでの観測は本書の範囲外。

## 再評価条件

- 対象のゲストカーネルや機能が `RING_RESET` を必須にするとき。
- 実行中のキューのサイズ変更や個別回復が必要になったとき。
- `VirtioDevice` にキュー単位の re-activate の口を足す設計をするとき。

## 試験による固定

`crates/microvm/tests/virtio_ring_reset.rs`（KVM 不要・既定のテスト集合）。

- `mvm1_4169_block_does_not_offer_ring_reset`・`mvm1_4169_net_does_not_offer_ring_reset`: 上位ページが 1（VERSION_1 だけ）でビット 40 が 0
- `mvm1_4169_driver_requesting_ring_reset_is_rejected`: 要求すると `FeaturesRejected`、Status は 3 のまま
- `mvm1_4169_queue_reset_register_is_not_implemented`: 0x0c0 は `UnknownRegister`
- `mvm1_4169_block_reenable_after_driver_ok_is_ignored`・`mvm1_4169_net_reenable_after_driver_ok_is_ignored`: 停止後の `QueueReady=1` は `WrongDeviceState`、復帰は Status=0 から

## 出典

確認日 2026-11-08（計画時の確認値。値だけを転記する）。rust-vmm 等の実装は参照しない（MVM-4）。

- VIRTIO 1.2 の TeX 原稿（`oasis-tcs/virtio-spec` のタグ `v1.2-csd01`、commit `9ac62542d7190d517e5682a4a3b108a1b9a1549b` の `content.tex`）: 6 章に `VIRTIO_F_RING_RESET(40)`、2.6.1 Virtqueue Reset、4.2.2 の MMIO レジスタ表に `QueueReset`（0x0c0・RW）、4.2.2.1・4.2.2.2 に要件
- OASIS の公開 HTML（`docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html`）でも 2.6.1 と 4.2.2 が同じ
- Linux の `include/uapi/linux/virtio_config.h`（最終更新 commit `838bebb4c926a573839ff1bfe1b654a6ed0f9779`）に `#define VIRTIO_F_RING_RESET 40`
