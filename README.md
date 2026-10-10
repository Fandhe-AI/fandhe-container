# fandhe-container

## 概要

Rust でフルスクラッチ開発する軽量なコンテナ実行基盤の実装リポジトリです。Docker の課題（リソース消費の大きさ・ボリューム I/O のボトルネック・macOS / Windows での VM 越境オーバーヘッド）を是正することを目指します。

## 位置づけ

- **本リポジトリは public** です（fandhe-db・fandhe-browser と同一方針）
- **仕様・ビヘイビア定義**: [fandhe-container-spec](https://github.com/Fandhe-AI/fandhe-container-spec)（`docs/spec` に submodule 参照。**private リポジトリとして意図的に非公開を維持**する方針であり、アクセス権のない環境からは submodule を解決できません）
- **製品名**: `fandhe-container` を製品名として採用しています（TASK-2・`OSS-1`・`OSS-2`・MS-0）

## ステータス

開発進行中で、実装済みの範囲は crate ごとに異なります。進捗は GitHub の Issue で管理します。タスク定義は spec リポの [`05-tasks.md`](https://github.com/Fandhe-AI/fandhe-container-spec/blob/main/05-tasks.md)、マイルストーンは [`06-roadmap.md`](https://github.com/Fandhe-AI/fandhe-container-spec/blob/main/06-roadmap.md)（MS-1〜14）を参照してください。

## 実装方針（要点）

- **フルスクラッチ**: youki / Cloud Hypervisor / Firecracker / rust-vmm は設計の参考にとどめ、コードの採用や低レベル基盤クレートとしての利用は行いません
- **OCI / CRI 互換**: OCI 準拠のコンテナランタイムとして動作し、VM は macOS / Windows 対応と分離オプションの手段として使います
- **I/O レイヤー再設計**: 大量ボリューム書き込み時のボトルネック解消を MVP の中核とします
- **対象 OS**: macOS（Apple Silicon）・Windows 10/11（WSL2）・Linux（x86_64 / arm64）の 3 OS で、ローカルとサーバーの双方に対応します
  - Linux のカーネルは 6.12 以降を前提とします（Landlock ABI 6 以上。CORE-5）。起動時の rootfs の `nodev` 付与（rootful・rootless とも）は `mount_setattr(2)`（Linux 5.12 以降。#1676）を、rootless の基本デバイスの bind は新マウント API（Linux 5.2 以降。#1660）を使い、いずれも 6.12 の範囲に含まれます。これらが使えないカーネルでは `mount(2)` へ縮退せず起動を拒否します
- **plugin 分割**: 拡張機能は別プロセス＋UDS 境界の plugin として分離します
- **周辺機能**: GPU パススルー・network・複数コンテナ定義・コンテナごとの軽量監視を含みます
- **AI 自己補修**: AI 自身が保守・改善・機能追加できるモジュール設計（crate 境界・型契約）を MVP の設計制約とします
- **crate 名前空間**: `fandhe-container-*`（workspace 内部パスは `crates/<短縮名>`）

詳細なビヘイビアは spec リポの [`04-behavior/`](https://github.com/Fandhe-AI/fandhe-container-spec/tree/main/04-behavior) を唯一の正（SSOT）とします。

## クイックスタート

現時点では利用者向けの統一 CLI（TASK-79・`CLI-1`）が未提供のため、ここではソースからのビルドとテストの手順を示します。利用者向けの手順は CLI の実装後に追記します。

前提: `git`・`make`・`rustup`（toolchain は `rust-toolchain.toml` で固定）。`make setup` は最後に git hooks を導入するため、`lefthook`・`brew`・`npx` のいずれかも必要です（いずれも無いと `make hooks` が終了コード 1 で停止します。ビルドとテストだけなら `make setup` を使わず、`git submodule update --init`〔任意〕の後に下記の `cargo build` / `make test` を実行できます）。

```bash
git clone https://github.com/Fandhe-AI/fandhe-container.git
cd fandhe-container
make setup               # submodule → rustup 確認 → git hooks 導入
cargo build --workspace  # ビルド
make test                # テスト（lint・deny まで含めた一括検証は make ci）
```

`make help` でターゲット一覧を表示します。コントリビュートの流れは [CONTRIBUTING.md](./CONTRIBUTING.md)、crate 境界は [docs/architecture.md](./docs/architecture.md)、ビルド・回帰確認コマンドは [AGENTS.md](./AGENTS.md) を参照してください。

## 開発環境構築

```bash
git clone git@github.com:Fandhe-AI/fandhe-container.git   # SSH の場合
cd fandhe-container
git submodule update --init   # docs/spec（private・要アクセス権）
make hooks                    # git hooks のみ導入する場合
make docker-ci                # 開発コンテナ内で make ci を実行（環境非依存の検証）
```

`docs/spec`（`fandhe-container-spec`）は private リポジトリのため、アクセス権のない環境では submodule 取得が失敗します（`make setup` は警告のみで続行します）。実装コードのビルド・テストは `docs/spec` 抜きでも成立するよう維持します。

## ライセンス

Apache License 2.0 です（[LICENSE-APACHE](./LICENSE-APACHE)）。spec の OSS-3 に従い中核 crate は Apache-2.0 単独とし、汎用再利用可能な補助 crate は `MIT OR Apache-2.0` を選択肢として残します。
