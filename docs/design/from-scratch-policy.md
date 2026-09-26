# フルスクラッチ方針

自作・外部依存の判断基準を定め、設計参考の利用と実装採用を区別する。

- 決定日: 2026-09-26（ユーザー決定）
- 関連 issue: #25（MS-0・TASK-73〜75 の前提）

## 方針

youki・Cloud Hypervisor・Firecracker・rust-vmm（およびその organization のクレート群）は設計の参考にとどめ、以下を行わない：

- コードの採用・流用・拡張
- 低レベル基盤クレートとしての利用

（出典: spec `04-behavior/README.md` 前提条件・`01-brainstorm.md` 決定 2。2026-09-23 ユーザー確認）

禁止クレート一覧（rust-vmm organization）: `vm-memory`・`kvm-ioctls`・`kvm-bindings`・`vhost`・`vhost-user-backend`・`virtio-queue`・`vmm-sys-util`・`linux-loader`・`event-manager`・`vm-superio`

機械判定（TASK-73・MVM-4）: `scripts/check-microvm-deps.sh` と `deny.toml` の `[bans]` で自動検出

## 依存の判断基準

1〜2 のいずれかに当たり、かつ 3〜6 をすべて満たす場合に限り、外部クレートの採用を検討する：

1. **自作の価値が低い**: OS / 言語境界の橋渡し（syscall・FFI 宣言）、仕様準拠の汎用データ形式
2. **自作がリスク**: 暗号プリミティブなど、自作すると監査コストと欠陥リスクが大きいもの
3. **ライセンス**: permissive ライセンスのみ（.claude/rules/licensing.md・OSS-3 参照）
4. **ビルド互換**: C/C++ ネイティブビルドを引き込まない・macOS / Windows / Linux 3 OS でビルド可能
5. **メンテ継続**: メンテナンスが継続しており、RustSec advisory（unmaintained を含む）が出ていない
6. **固定・承認**: `=x.y.z` 完全固定・ユーザー承認（.claude/rules/dependency-policy.md）

逆に以下は中核価値のため自作：

- VMM・virtio デバイス・コンテナ実行層（core・runtime）
- netlink / nftables（NET-11）
- seccomp / Landlock プロファイル生成（SEC・CORE）
- I/O 共有層・フラッシュバリア（IO・MVP 中核）
- plugin 境界機構（PLUG・信頼性検証）

## 許容依存リスト（2026-09-26 承認済み）

| クレート | バージョン | 用途 | issue |
| -------- | ---------- | ---- | ----- |
| `libc` | =0.2.189 | syscall 宣言（全 OS） | #86 |
| `nix` | =0.31.3 | syscall wrapper（Unix のみ cfg(unix)・feature 最小） | #86 |
| `unicode-normalization` | =0.1.25 | パス正規化（io crate のみ） | #798 |
| `serde` | =1.0.229 | データシリアライズ | #138 |
| `serde_json` | =1.0.151 | JSON（ペイロード・設定） | #138 |
| `sha2` | =0.11.0 | SHA-256（digest 検証） | #278 |
| `objc2-virtualization` | =0.3.2 | macOS Virtualization.framework（macOS のみ） | #356 |
| `objc2` | =0.6.4 | Objective-C ランタイム連携（macOS のみ） | #356 |
| `objc2-foundation` | =0.3.2 | Foundation フレームワーク（macOS のみ） | #356 |
| `block2` | =0.6.2 | Objective-C block（macOS のみ） | #356 |
| `dispatch2` | =0.3.1 | libdispatch（macOS のみ） | #356 |
| `windows-sys` | =0.61.2 | Windows API（Windows のみ） | #371 |

版は承認時点の値。`Cargo.toml` への追加時に新版がある場合は PR で再確認する。objc2 系は `default-features = false` で必要な feature だけを列挙し、AppKit（`objc2-app-kit`）を引き込まない。

## 不採用の記録

| クレート | 理由 | issue |
| -------- | ---- | ----- |
| `bincode` | RUSTSEC-2025-0141 により不採用。ペイロードは serde_json で代替 | #246 |
| `ring`・`aws-lc-rs` | C/C++ ネイティブビルドを引き込む | — |
| 署名検証クレート（`ed25519-dalek` 等） | PLUG-11 の既定実装はハッシュ一覧比較のため当面不要 | #281 |

## 承認待ち（後続 Phase）

以下は対応 Phase の着手時にユーザー承認を取る：

- HTTP クライアント（#399）
- gzip 圧縮（#406）
- tar ファイル処理（#408）
- prost / tonic（protobuf・gRPC・#425）
- YAML パーサ（#540）
- toml パーサ（#582）
- shlex シェルパーサ（#597）
- ttrpc（CRI・#670）
- ストリーミング HTTP サーバ（#678）
- libloading（動的ライブラリロード・#1048）

**非同期ランタイム**（tokio など）: 現時点で未承認。必要になった時点で検討・承認

## 未決事項

**rootless の外部ヘルパー採否**（pasta 等）

- spec 01-brainstorm.md D-18・未解決疑問点 14
- netlink / nftables は自前実装で決定済み（NET-11）

## 非 Cargo 資産（ライセンス手動確認）

- **macOS ゲストカーネル**: kernel.org LTS を自前ビルド。GPL-2.0 ソース提供は tarball URL・版数・defconfig・ビルドスクリプト公開で充足。release に別資産配布
- **initrd**: 自前 Rust 製 init のみ（#362。外部 init システム不採用）
