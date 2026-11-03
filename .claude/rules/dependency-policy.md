# 依存管理規約（リポ固有）

## 原則

- **フルスクラッチ方針**: youki・Cloud Hypervisor・Firecracker・rust-vmm は設計の参考にとどめ、コードの流用・低レベル基盤クレートとしての利用は行わない（README「実装方針（要点）」）
- **依存最小方針**: コアを最小に保ち、外部クレートへの依存は必要なものに限る（plugin 境界で拡張を分離する）
- **完全固定**: 採用する依存は `Cargo.toml` で `=x.y.z` の完全固定（exact pin）で管理する（`^`・`~`・範囲指定は禁止）。workspace 共通依存は `[workspace.dependencies]` に集約する
- **ユーザー承認制**: 依存の追加・更新・削除は必ずユーザーの明示承認を経てから行う

## 禁止クレート

- rust-vmm organization のクレート群（`vm-memory`・`kvm-ioctls`・`kvm-bindings`・`vhost`・`vhost-user-backend`・`virtio-queue`・`vmm-sys-util`・`linux-loader`・`event-manager`・`vm-superio` 等）は依存ツリーに含めない（MVM-4）。機械判定は `scripts/check-microvm-deps.sh`（`make check-microvm-deps`。導入済み・TASK-73.1）と、`deny.toml` の `[bans]`（導入済み・TASK-73.2。名前の完全一致で見る cargo-deny と、`_` 表記・repository を補うスクリプトの補完関係。一致と検出力は `make deny-bans-fail-closed-selftest`）
- youki（`libcontainer` 等）・Cloud Hypervisor・Firecracker 由来のクレートも同様に採用しない

## 承認を求める際に提示する情報

1. クレート名・バージョン（`=x.y.z`）・目的（なぜ自作でなく依存か。フルスクラッチ方針との整合）・配置する crate
2. ライセンス（[licensing](./licensing.md) の許可範囲に収まること）
3. メンテナンス状況（最終リリース日・リポジトリの活動状況）
4. 推移的依存の概要（大量の間接依存・ネイティブビルド（C/C++）を引き込まないか、3 OS でビルドできるか）
5. 常駐メモリ・バイナリサイズへの影響（リソース効率が設計目標のため。CORE-7〜9）

## 想定済みの土台（導入時にバージョンをユーザー承認）

- `libc`（=0.2.189。用途は自前の FFI 宣言の機械照合に限り、dev-dependencies のみ。製品コードの syscall・ioctl は各 crate の `sys` の自前宣言で行う。#1318・2026-10-12 のオーナー判断）
- `nix` は土台に含めない（どの crate も使っていない。2026-10-15 のオーナー判断で不採用。必要になったら改めて承認を得る。[from-scratch-policy](../../docs/design/from-scratch-policy.md)「不採用の記録」）
- `objc2-virtualization`（macOS Virtualization.framework の橋渡し層の土台。MAC 系）
- `windows-sys`（Windows API）

## subagent への適用

- builder Agent は依存の追加・更新を行わない。必要と判断した場合は「承認事項」として main へ報告し、main がユーザーに確認する
