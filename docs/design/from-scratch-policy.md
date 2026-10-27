# フルスクラッチ方針

自作・外部依存の判断基準を定め、設計参考の利用と実装採用を区別する。

- 決定日: 2026-09-26（ユーザー決定）
- 関連 issue: #25（MS-0・TASK-73〜75 の前提）
- 更新: 2026-10-10（オーナー判断。#399・#406・#408・#425・#540・#582・#597・#670・#678 の承認・不採用を反映。2026-10-12 の判断（#340）で rootless の外部ヘルパー pasta の例外を記録。2026-10-12 の判断（#1048・#1525・#1318）で MoltenVK 動的ロードの自前ラッパー・`libloading`／`ash`／`vulkanalia` の不採用・`libc` の用途限定を反映。2026-10-15 の判断で `nix` を許容依存リストから外して不採用へ移した。2026-10-23 の判断で tokio を =1.53.3 へ更新）

## 方針

youki・Cloud Hypervisor・Firecracker・rust-vmm（およびその organization のクレート群）は設計の参考にとどめ、以下を行わない（TASK-7・MVM-4・MS-0）：

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

## 許容依存リスト（2026-09-26・2026-10-10 承認済み）

| クレート | バージョン | 用途 | issue |
| -------- | ---------- | ---- | ----- |
| `libc` | =0.2.189 | 自前 FFI 宣言の機械照合（2026-10-12 の判断で用途を限定。dev-dependencies のみで、製品コードの依存には入れない。syscall の宣言自体は各 crate の `sys` の自前宣言を続ける。`Cargo.toml` への追加は #1838 で完了し、`[workspace.dependencies]` と、crates/cli・crates/core・crates/io・crates/oci・crates/platform-macos・crates/plugin・crates/plugin-macos・crates/plugin-windows の `cfg(unix)` と、crates/net・crates/supervisor の `cfg(target_os = "linux")` の dev-dependencies に導入済み。適用状況の正は `ffi-libc-check.md`「適用状況」。oci は #2590、io は #1842、plugin は #1843、supervisor は #1840、net は #1841、platform-macos は #1844、plugin-macos は #1845、plugin-windows は #1846、core は #1847〜#1849） | #86・#1318・#2590・#1840・#1841・#1842・#1843・#1844・#1845・#1846・#1847・#1848・#1849 |
| `unicode-normalization` | =0.1.25 | NFC / NFD の別表記の衝突検出（IO-5。io crate のみ。名前は正規化せず、`nfd()` で比べて衝突を構造化エラーで拒否する。#103 の決定） | #798（#1720 でそのまま使うと決定） |
| `serde` | =1.0.229 | データシリアライズ | #138 |
| `serde_json` | =1.0.151 | JSON（ペイロード・設定。crates/oci のトークン応答パースにも使用。TASK-51.2・#401） | #138 |
| `sha2` | =0.11.0 | SHA-256（digest 検証） | #278 |
| `objc2-virtualization` | =0.3.2 | macOS Virtualization.framework（macOS のみ） | #356 |
| `objc2` | =0.6.5 | Objective-C ランタイム連携（macOS のみ。0.6.5 は aarch64 macOS の release ビルドの use-after-free 修正版〔upstream #861〕） | #356・#1889 |
| `objc2-foundation` | =0.3.2 | Foundation フレームワーク（macOS のみ） | #356 |
| `block2` | =0.6.2 | Objective-C block（macOS のみ） | #356 |
| `dispatch2` | =0.3.1 | libdispatch（macOS のみ） | #356 |
| `windows-sys` | =0.61.2 | Windows API（Windows のみ） | #371 |
| `ureq` | =3.4.2 | OCI Distribution API の HTTPS クライアント（OCI-1。crates/oci のみ。default-features 無効・`rustls-no-provider`） | #399 |
| `rustls` | =0.23.46 | TLS（crates/oci のみ。default-features 無効・`std`/`tls12`/`logging`。RUSTSEC-2026-0346〜0349 の修正版のため 0.23.46 未満へ固定しない） | #399 |
| `rustls-graviola` | =0.4.0 | rustls の暗号実装（純 Rust・C ビルドなし。crates/oci のみ。CPU 機能不足は panic させず構造化エラーで返す） | #399 |
| `rustls-native-certs` | =0.8.4 | OS のルート証明書の読み込み（crates/oci のみ。webpki-roots の代わり） | #399 |
| `flate2` | =1.1.10 | gzip 展開（OCI-1。crates/oci。展開後サイズの上限は呼び出し側で検証）と、CRI ストリーミングの SPDY/3.1 ヘッダの zlib 辞書（CRI-6。crates/cri。`set_dictionary`）。default-features 無効・`zlib-rs` backend で純 Rust。参照は crates/oci と crates/cri のみ | #406・#678 |
| `tar` | =0.4.46 | tar ヘッダ・PAX の解析のみ（OCI-1。crates/oci のみ。default-features 無効。`Entry::unpack`/`unpack_in` は使わず、展開は crates/oci で fd 起点に自作） | #408 |
| `tonic` | =0.14.6 | gRPC サーバー / クライアント（CRI-3・PLUG-2。cri / plugin の gRPC 面のみ。default-features 無効・`codegen`/`transport`/`router`） | #425 |
| `tonic-prost` | =0.14.6 | tonic の prost 連携（cri / plugin の gRPC 面のみ） | #425 |
| `prost` | =0.14.4 | protobuf メッセージ（cri / plugin の gRPC 面と、crates/cri で自作する ttrpc の Task API メッセージ〔CRI-5〕のみ） | #425・#670 |
| `tokio` | =1.53.3 | 非同期ランタイム（LTS。cri / plugin の gRPC 面と、#678 の crates/cri のストリーミングサーバーのみで core には入れない。features は資料の案で `rt`/`net`/`time`/`macros`） | #425・#678（2026-10-23 に =1.53.2 から更新。RUSTSEC-2026-0386 への対応でオーナー承認） |
| `tokio-stream` | =0.1.19 | UDS 上の tonic の接続（#454。cri / plugin の gRPC 面のみ。`net`） | #425 |
| `tower-service` | =0.3.3 | UDS 上の tonic の接続（#454。cri / plugin の gRPC 面のみ） | #425 |
| `hyper` | =1.12.0 | CRI ストリーミングサーバーの HTTP/1.1 Upgrade（CRI-6。crates/cri の直接依存。`server`/`http1`。SPDY/3.1 は自作） | #678 |
| `hyper-util` | =0.1.21 | UDS 上の tonic の接続（#425）・ストリーミングサーバー（#678。crates/cri の直接依存。`server`/`http1`/`tokio`） | #425・#678 |
| `http` | =1.5.0 | UDS 上の tonic の接続（#454。cri / plugin の gRPC 面のみ） | #425 |
| `tonic-prost-build` | =0.14.6 | build 時のみ: cri-api の `.proto` からのコード生成（CRI-3。default-features 無効・`transport`） | #425 |
| `protox` | =0.9.1 | build 時のみ: 純 Rust の `.proto` 解析（`protoc` 不要。#670 の Task API メッセージの生成にも使う） | #425・#670 |
| `serde-saphyr` | =1.3.0 | YAML（CDI spec・compose.yaml。GPU-1・STACK-3。crates/gpu と crates/compose-convert のみで core には入れない。default-features 無効・`deserialize`。`from_str_with_options` で `Budget` を用途ごとに明示・`duplicate_keys: Error`・compose は `strict_booleans: true`） | #540 |
| `toml` | =1.1.8 | 独自 TOML スタック定義の parse / serialize（STACK-1・CLI-4。default-features 無効・`std`/`serde`/`parse`/`display`、`unbounded` は無効。crates.io 上の版は `1.1.8+spec-1.1.0`。配置は crates/stack〔#583 で追加〕、必要なら crates/compose-convert） | #582 |

版は承認時点の値。`Cargo.toml` への追加時に新版がある場合は PR で再確認する。objc2 系は `default-features = false` で必要な feature だけを列挙し、AppKit（`objc2-app-kit`）を引き込まない。

2026-10-10 承認分（#399・#406・#408・#425・#540・#582・#678）のうち、#540 の `serde-saphyr` は #542（TASK-126.1）で `Cargo.toml` に追加済み（crates/gpu）、#399 は #400（TASK-51.1）で `Cargo.toml` に追加済み（crates/oci。ureq・rustls・rustls-graviola・rustls-native-certs）、`toml` は #583（TASK-149.1）で `[workspace.dependencies]` に追加し crates/stack から参照する。#425 の build 時の依存 `tonic-prost-build`・`protox` は #426（TASK-56.3）で `Cargo.toml` に入った。`tonic`・`tonic-prost`・`prost` は #427（TASK-56.4）で crates/cri の実行時依存として入った。`tokio` は #453（TASK-108.1）で `[workspace.dependencies]` に追加し crates/plugin の非既定 feature `grpc` から参照する（core には入らない）。`hyper-util` は #454（TASK-108.2）で `[workspace.dependencies]` に追加し、同じ feature `grpc` の UDS connector（`TokioIo`）だけが使う（Cargo.lock には tonic の推移依存として既存）。残り（tokio-stream・tower-service・http 等）は直接依存としては入れていない（`tonic::codegen` の再 export を使う）。追加は各実装 issue（#407・#409・#426・#453・#454・#541・TASK-151・#583・#679）で行う。「cri / plugin の gRPC 面」は crates/cri・`fandhe-container-plugin-cri`・crates/plugin の gRPC 面（TASK-108）を指す。`prost-build`・`tonic-build` は `tonic-prost-build` から推移的に入るため直接の依存には書かない（版は `Cargo.lock` で固定される）。

**非同期ランタイム**: tokio を承認（#425・2026-10-10）。使ってよいのは cri / plugin の gRPC 面だけで、core には入れない（PLUG-1・CORE-1）。例外は #678 で crates/cri の直接依存として承認した CRI ストリーミングサーバー（hyper・hyper-util の `tokio` feature。CRI-6）で、crates/cri の中で同じ tokio を使う。hyper・hyper-util の参照も cri / plugin に限る。

## 不採用の記録

| クレート | 理由 | issue |
| -------- | ---- | ----- |
| `bincode` | RUSTSEC-2025-0141 により不採用。ペイロードは serde_json で代替 | #246 |
| `ring`・`aws-lc-rs` | C/C++ ネイティブビルドを引き込む（TLS の暗号実装は `rustls-graviola`）。`Cargo.lock` には rustls-webpki の optional 依存として `ring`・`cc` の項目が残るが、有効な feature に含まれずビルドされない（`cargo tree -e normal,build -i ring --target all` が空であることで確認する）。`ring`・`cc`・`aws-lc-rs` は `deny.toml` の `[bans]` で機械的に禁止しており、ビルド対象の依存グラフに入ると `make deny`（CI の rust-ci）が fail する | #399・#1779 |
| `webpki-roots` | CDLA-Permissive-2.0 で `deny.toml` の許可外。ルート証明書は `rustls-native-certs` で OS から読む | #399 |
| `native-tls` | Linux で OpenSSL のヘッダと `cc`・`pkg-config` のビルドが要る | #399 |
| `ttrpc` | protobuf の実行時ライブラリの二重化・prost / nix の版の重複を招く。ワイヤー形式は crates/cri で自作 | #670 |
| `containerd-shim-protos` | ttrpc 0.9.0 に固定され、build 時に prost 0.8・syn 1 系の古い依存が入る | #670 |
| `spdy-mux` | GPL-3.0-only（コピーレフト） | #678 |
| `spdystream-rs` | 2026-05 公開で実績・保守体制が乏しい。SPDY/3.1 は自作 | #678 |
| `shlex` | compose-go が使う go-shellwords v1.0.12 と分割規則が違う。分割は crates/compose-convert で自作 | #597 |
| `nix` | どの crate も使っておらず、syscall・ioctl は各 crate の `sys` の自前宣言で行う（#1318）。2026-10-15 のオーナー判断で許容依存リストから外した（PR #1966 の保留の解消）。必要になったら改めて承認を得る | #86・#1318 |
| `serde_norway` | libyaml を機械翻訳した unsafe コードを未信頼入力に晒し、上限を設定できない | #540 |
| `serde_yaml` | 作者が非推奨とし archived。依存の unsafe-libyaml に RUSTSEC-2023-0075（unsound） | #540 |
| `serde_yml` | RUSTSEC-2025-0068（unsound・unmaintained）。repo は archived | #540 |
| `basic-toml` | 保守終了（README に "no longer maintained"） | #582 |
| `astral-tokio-tar` | tokio が前提で、2025〜2026 年に advisory が 5 件 | #408 |
| `libloading` | MoltenVK の動的ロードの対象は POSIX の `dlopen` だけで、宣言は 4 個。入れても `Library::new`・`get` は `unsafe fn` のままで、各 crate の `sys` に FFI 宣言を置く現行の流儀と変わらないため、自前ラッパーにする。#1525 で `ash` の `loaded` feature を使う場合だけ `=0.8.9` で再検討する | #1048 |
| `ash` | `ash =0.38.0` は最終リリースが 2024-04-01 で、呼び出しは `unsafe fn` のままのため `unsafe` も減らない。Vulkan 呼び出しは自前 FFI | #1525 |
| `vulkanalia` | Vulkan 呼び出しは自前 FFI で行う | #1525 |
| 署名検証クレート（`ed25519-dalek` 等） | PLUG-11 の既定実装はハッシュ一覧比較のため当面不要 | #281 |

## 例外の記録

- **rootless の外部ヘルパー（pasta）**（2026-10-12 のオーナー判断。TASK-147.h1・NET-9。#340）
  - フルスクラッチ方針の例外として認める。例外は rootless のユーザー空間転送に限る（D-14 の例外も同じ経路に限る）
  - Cargo の依存ではなく、利用者が導入した外部バイナリを別プロセスとして exec するだけ。同梱・リンクはしない
  - ライセンスは GPL-2.0-or-later。この使い方に限って認める。依存を permissive に限る規約は変えない
  - netlink・nftables の自前実装（NET-11）は変えない
  - 詳細は [rootless-network.md](rootless-network.md) の「決定」

## 承認待ち（後続 Phase）

- #1521（macOS 27 対応の `objc2-virtualization` への更新）: 保留中（リリース待ち）。採用・更新範囲は未決定で、承認の依頼は出していない

## MoltenVK の動的ロード（自前 dlopen ラッパー）

2026-10-12 の判断（#1048・#1525。TASK-180・GPU-6・MAC-5）。macOS の GPU 経路で、外部ライブラリの MoltenVK をホスト側の GPU バックエンドが実行時に読み込む用途に限る。実装は #1049・#1526 で行い、現時点では未実装。

- 配置: `crates/plugin-macos` の `sys` モジュール（`cfg(unix)`）に `dlopen`・`dlsym`・`dlclose`・`dlerror` の自前ラッパーを置く。Cargo の依存は増えない（`Cargo.toml` は変えない）
- Vulkan の呼び出しは自前 FFI で行い、ロードと関数解決は同じラッパーを使う（#1525）
- 絶対パスだけを受け取る
- 所有者とモードを検証してから開く（PLUG-11 と同じ水準）
- ライブラリ名だけを渡す探索をしない
- plugin の読み込みには使わない（plugin は別プロセス＋UDS に限る。PLUG-2）
- `dlerror` のスレッド安全性は #1049 で照合する

## 未決事項

現時点で無い。

## 非 Cargo 資産（ライセンス手動確認）

- **macOS ゲストカーネル**: kernel.org LTS を自前ビルド。GPL-2.0 ソース提供は tarball URL・版数・defconfig・ビルドスクリプト公開で充足。release に別資産配布
- **initrd**: 自前 Rust 製 init のみ（#362。外部 init システム不採用）
- **rootless の外部ヘルパー（pasta）**: 同梱しない。利用者が導入する。GPL-2.0-or-later。exec のみ（リンク・同梱なし。2026-10-12 の判断。#340）
