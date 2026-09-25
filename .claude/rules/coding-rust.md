# Rust コーディング規約

## ツールチェーン

- `rust-toolchain.toml`（stable・rustfmt・clippy）を単一真実源とする
- `make fmt`・`make lint`（clippy `-D warnings`）・`make test` を通してからコミットする（clippy 警告 0 件を維持。[ci](./ci.md)）
- ビルド・テストは `docs/spec` 抜きで成立させる。コード・`build.rs`・テストから `docs/spec` 配下を参照しない

## crate 構成と境界

- workspace は `crates/<短縮名>`・crate 名前空間 `fandhe-container-*` で構成する（短縮名は TASK-1・REPAIR-1 で確定）
- 1 回の改修が波及する crate・モジュールを最小に保つ（単一責務・疎結合。AI 自己補修の前提。REPAIR-1）
- 循環依存を作らない。複数 crate が共有する型は下位 crate へ置き、上位から下位への一方向依存を保つ
- 拡張機能は別プロセス＋UDS 境界の plugin として分離する。`ContainerRuntime`・`StateStore`・`NetworkPlugin` の実装は plugin 側、`VolumeProvider`（データパス）は core 側に置く（PLUG-1）。plugin の追加で core を変更しない（PLUG-4）
- 中央の常駐デーモンを前提にした設計をしない（CORE-1・D-19。監視はコンテナごとの supervisor）

## 公開 API・型設計

- 戻り値は将来拡張できる構造を持つ型にする（真偽値・フラットな文字列で済ませない）
- ワイヤーフォーマット・フレームは「壊れた値を表現できない」型（固定長ヘッダの newtype・チェックサム等）で組み立て、生の `Vec<u8>` を手で組まない（REPAIR-2）
- 未実装・簡易実装の箇所は「実装済みを装わない」。ドキュメントコメントに将来仕様と対応するビヘイビア ID を明記する（REPAIR-3・[code-comment-style](./code-comment-style.md)）

## エラーハンドリング・可観測性

- ライブラリコードでは `Result` を返し、panic させない
- 外部入力（イメージ・CDI spec・TOML / compose・CRI / MCP リクエスト・plugin 入出力・カーネル応答）の経路では `unwrap` / `expect` / 添字アクセス（`[]`）を使わず、`get()`・`try_into()`・checked 演算で明示的に処理する
- 長さ・件数を上限検証してからアロケーションに使う（無制限確保による DoS を防ぐ）
- 相手の応答を待つ処理（ACK・plugin RPC・子プロセス）には必ずタイムアウトを設ける（REPAIR-5）
- エラーは非ゼロ終了コード・機械可読な `code` / `message` の構造化形式に揃える（ERR 系）。レイテンシ等は構造化ログ / メトリクスで出す（REPAIR-4）

## unsafe・FFI・syscall

- `unsafe` は原則禁止。syscall・ioctl・FFI 境界（objc2・Win32）で必要な場合のみ、`// SAFETY:` コメントで理由と維持すべき不変条件を明記する
- `unsafe` の新規追加はユーザー承認を得る（レビューで P0 として扱う）
- syscall 番号・構造体レイアウトのアーキテクチャ差（x86_64 / aarch64）は `cfg(target_arch = ...)` で扱い、定数を流用しない

## クロスプラットフォーム（macOS・Windows・Linux の 3 OS 一級対応）

- パスは `PathBuf` / `Path::join` で組み立て、文字列連結・区切り文字のハードコードをしない
- 大文字小文字非区別・長パス（260 文字超）・Unicode 正規化の差を考慮する（IO-5）
- 内部データファイルの改行は LF 固定。OS 固有処理は `cfg(target_os = ...)` で担当 crate 内に局所化し、上位 crate へ OS 固有型を漏らさない（CLI-1）

## テスト

- 挙動は `docs/spec` のビヘイビア ID（例: `IO-2`）に対応づけてテストし、テスト名またはドキュメントコメントに ID を記す
- ユニットテストと結合テストを併置し、期待値は具体値で書く（真偽値のみの assert に頼らない）。受け入れ基準を機械照合するテストを置く（REPAIR-12）
- テストの skip・ignore・アサーション弱体化で CI を通さない。root・KVM・GPU 等の実機前提テストの扱いは [ci](./ci.md) に従う

## コメント

- [code-comment-style](./code-comment-style.md) に従う（`//!` / `///` のドキュメンテーションコメント）
