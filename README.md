# fandhe-container

Rust でフルスクラッチ開発する軽量なコンテナ実行基盤の実装リポジトリです。Docker の課題（リソース消費の大きさ・ボリューム I/O のボトルネック・macOS / Windows での VM 越境オーバーヘッド）を是正することを目指します。

## 位置づけ

- **本リポジトリは public** です（vector-db・fandhe-browser と同一方針）
- **仕様・ビヘイビア定義**: [fandhe-container-spec](https://github.com/Fandhe-AI/fandhe-container-spec)（`docs/spec` に submodule 参照。**private リポジトリとして意図的に非公開を維持**する方針であり、アクセス権のない環境からは submodule を解決できません）

## ステータス

実装は未着手です（ロードマップの着手判定は条件付き Go 済み。実装開始は別途の指示を経て行います）。タスク定義は spec リポの [`05-tasks.md`](https://github.com/Fandhe-AI/fandhe-container-spec/blob/main/05-tasks.md)、マイルストーンは [`06-roadmap.md`](https://github.com/Fandhe-AI/fandhe-container-spec/blob/main/06-roadmap.md)（MS-1〜14）を参照してください。

## 実装方針（要点）

- **フルスクラッチ**: youki / Cloud Hypervisor / Firecracker / rust-vmm は設計の参考にとどめ、コードの採用や低レベル基盤クレートとしての利用は行いません
- **OCI / CRI 互換**: OCI 準拠のコンテナランタイムとして動作し、VM は macOS / Windows 対応と分離オプションの手段として使います
- **I/O レイヤー再設計**: 大量ボリューム書き込み時のボトルネック解消を MVP の中核とします
- **対象 OS**: macOS（Apple Silicon）・Windows 10/11（WSL2）・Linux（x86_64 / arm64）の 3 OS で、ローカルとサーバーの双方に対応します
- **plugin 分割**: 拡張機能は別プロセス＋UDS 境界の plugin として分離します
- **周辺機能**: GPU パススルー・network・複数コンテナ定義・コンテナごとの軽量監視を含みます
- **AI 自己補修**: AI 自身が保守・改善・機能追加できるモジュール設計（crate 境界・型契約）を MVP の設計制約とします
- **crate 名前空間**: `fandhe-container-*`（workspace 内部パスは `crates/<短縮名>`）

詳細なビヘイビア（151 件）は spec リポの [`04-behavior/`](https://github.com/Fandhe-AI/fandhe-container-spec/tree/main/04-behavior) を唯一の正（SSOT）とします。

## 開発環境構築

```bash
git clone git@github.com:Fandhe-AI/fandhe-container.git
cd fandhe-container
git submodule update --init   # docs/spec（private・要アクセス権）
```

`docs/spec`（`fandhe-container-spec`）は private リポジトリのため、アクセス権のない環境では submodule 取得が失敗します。実装コードのビルド・テストは `docs/spec` 抜きでも成立するよう維持します。

## ライセンス

Apache License 2.0 です（[LICENSE](./LICENSE)）。spec の OSS-3 に従い中核 crate は Apache-2.0 単独とし、汎用再利用可能な補助 crate は `MIT OR Apache-2.0` を選択肢として残します。
