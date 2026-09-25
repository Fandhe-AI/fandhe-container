# セキュリティ規約

## 秘密情報の混入防止（P0）

- 実トークン・レジストリ資格情報・API キー・接続資格情報をコード・テスト・fixture・ドキュメントに書かない（例示はダミー値に限る）
- `.env` 等の資格情報ファイルをコミットしない。レジストリ資格情報をログ・エラーメッセージへ出力しない
- hooks・settings.json にシークレットをハードコードしない

## コンテナ分離（P0。CORE・SEC 系ビヘイビア）

- 分離は既定で閉じる（fail-closed）。capability は OCI 既定の最小セットのみを付与し、`CAP_SYS_ADMIN`・`CAP_SYS_MODULE`・`CAP_SYS_PTRACE` 等は既定拒否する（SEC-1）
- seccomp・Landlock の許可は最小セットから明示的に開ける（CORE-5）。cgroups v2 のみを対象とする（CORE-4・SEC-6）
- rootfs・マウント・ボリュームの外へ書き込める経路（パストラバーサル・symlink・ハードリンク・マウント伝播）を作らない。パス要素は検証・正規化してからルート配下であることを確認する
- user namespace の UID マッピングでコンテナ内 root をホストの非特権 UID に写す（SEC-5）
- 分離違反の試行は監査ログに記録する（SEC-4）

## plugin 境界（P0。PLUG 系ビヘイビア）

- 動的ライブラリの実行時ロードを行わない。拡張は別プロセス＋UDS に限る
- 他ユーザー書き込み可能な場所の plugin・許可済みハッシュ / 署名に一致しない plugin は登録を拒否する。`PATH` 探索は opt-in のみ（PLUG-11）
- UDS は所有者・権限・symlink を検証してから bind し、別 UID からの接続は peer credential 検証で切断する（PLUG-12）
- plugin からの入力は untrusted として検証する

## OWASP Top 10 観点（PR 作成前チェック）

| 観点 | 本リポでの具体例 |
| ---- | ---------------- |
| インジェクション | CLI 引数・TOML / compose・CDI hooks・MCP / CRI リクエストをシェル・パス・コマンドへ未検証で連結 |
| アクセス制御の不備 | CRI / MCP / Docker 互換 API を既定で外部インターフェースへ公開・UDS の権限不備 |
| 不安全な設計 | 無制限リソース確保（巨大レイヤ・無限フレーム長・タイムアウト欠如）・特権操作失敗時の後始末欠如 |
| ソフトウェアとデータの完全性 | イメージ digest 未検証・plugin のハッシュ / 署名未検証 |
| 脆弱な依存 | 未固定バージョン・メンテ停止クレート（[dependency-policy](./dependency-policy.md)） |

## 運用

- `git commit --no-verify` を使用しない（pre-commit フックを必ず通す）
- root 権限を要するコマンド・エスケープ検証コードは、ユーザーの明示指示なしに実環境で実行しない
- セキュリティ上の疑義を発見した場合は作業を中断してユーザーに警告する
