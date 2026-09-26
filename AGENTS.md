# AGENTS.md

## 本書の用途

本書は `.github/workflows/ai-review.yml`（`Fandhe-AI/actions` の `ai-review` reusable workflow を呼ぶ wrapper。check 名 `codex / preflight`・`codex / review`・`codex / post_feedback`）が Codex による PR 自動レビューの基準として読む、リポジトリ固有のレビュー観点集である。

- Codex の既定 prompt は **PR の base コミットの本書** を読む。そのため本書への変更は、当該 PR のレビューには反映されず、**マージ後の次の PR から実効** になる
- 本書は日本語で記述する。プログラムの出力文字列（エラーメッセージ・ログ・CLI 出力）や識別子・コマンドは原語（英語）のままでよい
- `docs/spec`（`fandhe-container-spec` submodule）は private であり、レビュー実行環境からは読めない前提とする。レビューでは spec 本文との一致を判定材料にせず、**ビヘイビア ID（`<PREFIX>-<N>`）・TASK-n・MS-n の併記があるか** という、diff だけで確認できる観点に限定する。ID が欠けた spec 由来の変更は「spec 参照規約」観点（P1）として指摘する
- 本書が挙げる spec ビヘイビア ID には現時点でステータス「検討中」のものを含む。検討中の ID は「対応する設計判断・実装方針が spec 側で確定していない」ことを意味し、本書の各観点自体は `.claude/rules/` に定めるリポジトリの現行方針として扱う（ID は SSOT への参照であり、確定扱いの根拠ではない）

## 優先度定義

| 優先度 | 意味 | 判断基準 | 扱い |
| ---- | ---- | ---- | ---- |
| P0 | マージブロック | セキュリティ・ライセンス・アーキテクチャ根幹の違反、または回帰検出の後退（テストの skip・ignore 等）・実装済みを装う偽装など品質ゲートの破壊 | 修正するまでマージしない |
| P1 | 強く推奨 | 規約違反・保守性の重大な低下 | 未対応のままマージ不可（ai-review の codex ジョブが fail する）。対応不要の場合はスレッドで理由を明示して resolve する |
| P2 | 提案 | 改善提案 | CI を fail させない。次回以降の改善提案として記録すればよい |

## ビルド・テスト・回帰確認コマンド（REPAIR-7・REPAIR-10）

`make` ターゲットを正とする（括弧内に実行される cargo コマンドを併記する）。

```bash
make fmt-check   # cargo fmt --all --check
make lint        # cargo clippy --workspace --all-targets -- -D warnings（既定 feature）
make test        # cargo test --workspace（既定 feature）
make deny        # cargo deny --locked check advisories bans licenses sources
make ci          # lint-docs + check-workspace-manifest + 上記 4 つを一括実行
```

- `Cargo.toml`（workspace）が未作成の間、`fmt`/`lint`/`test` は対象がなく実行できない。`Cargo.toml` と `crates/*/Cargo.toml`（メンバー crate）の両方が揃うまで Makefile 側でこれらは skip される。`deny` は加えて `deny.toml` の存在を要する。`check-workspace-manifest`（`cargo verify-project`）は `Cargo.toml` の存在のみで判定し、メンバー crate 未追加の中間状態でも実行される
- workspace 作成後の PR からは、PR 本文にこれらのコマンドの実行結果が記載されているか（同じ PR で CI 設定を変更する場合はその diff にこれらのコマンドが含まれているか）を確認する。本節の未達は、個別に優先度を明記した項目を除き既定で P1 とする
- CI の `rust-ci`（3 OS matrix）は clippy/test を `--all-features` で実行し（fmt/deny は feature 非依存）、`rust-ci-default-features`（3 OS matrix）が `make lint`/`make test` と同一コマンド（既定 feature）を再現する。両者は別ジョブであり、既定 feature 側の回帰は `rust-ci-default-features` でのみ検出される
- clippy 警告は 0 件を維持する。理由コメントなしで `#[allow(...)]` により警告を握りつぶす差分は P1。crate・モジュール全体に及ぶ広範な `#[allow(...)]`（`#![allow(...)]` 等）や、`unsafe` 関連 lint（`unsafe_code`・`clippy::undocumented_unsafe_blocks` 等）・外部入力の検証を隠す lint（`clippy::unwrap_used`・`clippy::expect_used`・`clippy::indexing_slicing` 等。下記「外部入力の検証」観点）の外部入力経路での抑止は、理由コメントの有無を問わず P0
- テストの skip・ignore・アサーション弱体化で CI を通す差分は P0（回帰検出の後退を招くため）

### タイムアウト保護された結合試験・ベンチ回帰（REPAIR-5・REPAIR-8）

REPAIR-7 の 5 段階ゲートのうち、(3) タイムアウト保護された結合試験（ACK 未送信等のハング検出。推奨 5〜10 秒）・(4) ベンチ回帰チェック（15% 超の悪化で fail）は現時点で CI 未導入である。導入時は本節・`.claude/rules/ci.md` に実行コマンドと判定基準を追記する。ACK・plugin RPC・子プロセスなど相手の応答を待つ処理に、タイムアウトなしで無期限に待ち得る経路を追加する差分は P0（REPAIR-5）

### 実機前提テスト

- root 権限・KVM・GPU・特定カーネル版数（Landlock ABI 等）・WSL2 を要するテストは、GitHub ホステッド runner で実行できないため既定のテスト集合から明示的に分離されているか確認する。分離の仕組み・実行コマンドは該当タスクで決め、本書に追記する
- 分離したテストに理由（必要な権限・環境）とビヘイビア ID が記され、実機での実行結果が PR に記録されているか確認する
- 既定のテスト集合で動くはずのテストを、CI 通過のために実機前提テストへ移す差分は P0
- 実機での実測・判定が「人間」担当のタスク（`.claude/rules/delegation-impl.md`「着手条件」）を、計測スクリプト準備を超えて Agent が単独で完了扱いにしていないか確認する

### ライセンス検査

```bash
make deny   # cargo deny --locked check advisories bans licenses sources
```

### 3 OS 一級対応

- CI は Linux・macOS・Windows の 3 OS ネイティブランナーでビルド・テストする（クロスコンパイル前提にしない）
- OS 固有のパス・大文字小文字非区別ファイルシステム・長パス・改行コードに関わる変更（IO-5・CLI-1）は、PR 本文に 3 OS での実行結果が記載されているか（同じ PR で CI 設定を変更する場合はその diff に 3 OS matrix でのテスト実行が含まれているか）を確認する

## レビュー観点

### セキュリティ（P0 中心。`.claude/rules/security.md`・`.claude/rules/dependency-policy.md`・`.claude/rules/licensing.md`）

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| 秘密情報 | 実トークン・レジストリ資格情報・API キー・接続資格情報がコード・テスト・fixture・ドキュメント・hooks・`settings.json` に含まれていないか | P0 |
| コンテナ分離（fail-closed） | capability は OCI 既定の最小セットのみを付与し、`CAP_SYS_ADMIN`・`CAP_SYS_MODULE`・`CAP_SYS_PTRACE` 等を既定拒否しているか（SEC-1）。seccomp・Landlock の許可を最小セットから明示的に開けているか（CORE-5）。cgroups v2 のみを対象としているか（CORE-4・SEC-6） | P0 |
| user namespace | コンテナ内 root をホストの非特権 UID へ写しているか（SEC-5） | P0 |
| 監査ログ | 分離違反の試行を監査ログに記録しているか（SEC-4） | P0 |
| rootfs・マウント・ボリューム境界 | rootfs・マウント・ボリュームの外へ書き込める経路（パストラバーサル・symlink・ハードリンク・マウント伝播）がないか。パス要素を検証・正規化してからルート配下であることを確認しているか | P0 |
| plugin 境界 | 動的ライブラリの実行時ロードを行っていないか（拡張は別プロセス＋UDS に限る。PLUG-2）。`ContainerRuntime`・`NetworkPlugin` の実装が plugin 側、`VolumeProvider` が core 側になっているか（PLUG-1）。`StateStore` はトレイト定義とファイルベースの既定実装が core 側にあり、別実装を plugin として差し替えられる構造になっているか（TASK-31・OCI-5・PLUG-1）。他ユーザー書き込み可能な場所の plugin・許可済みハッシュ / 署名に一致しない plugin の登録を拒否しているか。`PATH` 探索が opt-in のみになっているか（PLUG-11） | P0 |
| UDS 境界 | UDS を所有者・権限・symlink を検証してから bind しているか。別 UID からの接続を peer credential 検証で切断しているか（PLUG-12） | P0 |
| plugin 入力の検証 | plugin からの入力を untrusted として検証しているか | P0 |
| 外部入力の検証 | イメージ・CDI spec・TOML / compose・CRI / MCP リクエスト・plugin 入出力・カーネル応答の経路で `unwrap`・`expect`・添字アクセス（`[]`）を使わず、`get()`・`try_into()`・checked 演算で処理しているか | P0 |
| リソース上限 | 長さ・件数を上限検証してからアロケーションに使っているか（無制限確保による DoS を防ぐ） | P0 |
| タイムアウト | ACK・plugin RPC・子プロセスなど相手の応答を待つ処理に、有限時間で打ち切るタイムアウトが設けられているか（REPAIR-5） | P0 |
| `unsafe`/FFI | `unsafe` の新規追加はユーザー承認済みか（PR 本文に承認の記録（承認した Issue・コメントへのリンクと承認内容の転記等）があるかで確認）。`unsafe` ブロックに `// SAFETY:` コメント（理由・維持すべき不変条件）があるか | P0 |
| イメージ完全性 | イメージ digest の検証を省略・弱体化していないか | P0 |
| API の公開範囲 | CRI / MCP / Docker 互換 API を既定で外部インターフェースへ認証なし公開する変更になっていないか | P0 |
| インジェクション | CLI 引数・TOML / compose・CDI hooks・MCP / CRI リクエストをシェル・パス・コマンドへ未検証で連結していないか | P0 |
| 特権操作の後始末 | root 権限を要する操作の失敗時に、マウント・namespace・一時ファイル等の後始末を欠いていないか | P0 |
| 依存の追加・更新 | `Cargo.toml` の依存が `=x.y.z` の完全固定（exact pin）か。`[workspace.dependencies]` に集約されているか。ユーザー承認（クレート名・バージョン・目的・配置する crate、ライセンス、メンテナンス状況、推移的依存の概要・ネイティブビルドの有無・3 OS ビルド可否、常駐メモリ / バイナリサイズへの影響〔CORE-7〜9〕の提示）を経ているか（PR 本文に承認の記録があるかで確認）。git 依存・crates.io 以外のレジストリ、バージョン無指定（wildcard）の依存を追加していないか（`deny.toml` `[sources]`・`[bans]`） | P0 |
| 禁止クレート | rust-vmm organization のクレート群・youki（`libcontainer` 等）・Cloud Hypervisor・Firecracker 由来のクレート・コードを依存ツリーやコードへ混入させていないか（MVM-4。`.claude/rules/dependency-policy.md`。機械判定は TASK-73〔`scripts/check-microvm-deps.sh`・`deny.toml` `[bans]`〕で導入予定） | P0 |
| ライセンス | 中核 crate は Apache-2.0 単独になっているか（OSS-3）。補助 crate の `MIT OR Apache-2.0` 採用はクレートごとにユーザー承認を経ているか。GPL / LGPL / AGPL・MPL-2.0 等のコピーレフト系ライセンスの依存を導入していないか | P0 |
| 非 Cargo 資産のライセンス | ビルド時に埋め込むデータ（seccomp プロファイル・CDI サンプル等）・VM イメージ / カーネル等、`cargo deny` の対象外資産のライセンス・帰属表示要否をユーザーへ確認しているか | P0 |

### アーキテクチャ・設計整合（`.claude/rules/coding-rust.md`・`CLAUDE.md`）

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| crate 構成 | 変更が `crates/<短縮名>`（名前空間 `fandhe-container-*`）の想定責務（`io`: I/O 共有層／`core`・`supervisor`: 実行層・監視プロセス／`oci`・`cri`: イメージ・ライフサイクル・CRI／`platform-macos`・`platform-windows`・`microvm`: プラットフォーム層／`gpu`・`net`: GPU パススルー・network／`plugin`: plugin 境界機構（`fandhe-container-plugin`）／`cli`・`stack`: 統一 CLI・複数コンテナ定義スキーマ／`compose-convert`: compose.yaml 変換ツール／`plugin-*`: plugin crate 群。詳細は `docs/design/crate-naming.md`・`CLAUDE.md` の Repository Structure）に収まっているか。短縮名は `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み | P1 |
| 依存方向 | crate 間の一方向依存が保たれ循環がないか。複数 crate が共有する型が下位 crate に置かれているか。crate 構成は確定済み（`docs/design/crate-naming.md`。TASK-1・REPAIR-1）で、決まっている一方向依存は `compose-convert` → `stack`・`supervisor` → `core`・`plugin-*` → `plugin`。全体の許可依存表は未整備で、後続のタスク（`docs/architecture.md`。TASK-6）で追記する | P0 |
| core / plugin 境界 | `ContainerRuntime`・`NetworkPlugin` の実装が plugin 側、`VolumeProvider`（データパス）がトレイト定義・実装とも core 側に置かれているか（PLUG-1）。`StateStore` はトレイト定義とファイルベースの既定実装が core 側にあり、別実装を plugin として差し替えられるか（TASK-31・OCI-5。常駐デーモンを持たない CORE-1 と整合）。plugin の追加で core（ソース・バイナリ）を変更していないか（PLUG-4） | P0 |
| 常駐デーモン前提の排除 | 中央の常駐デーモンを前提にした設計になっていないか（監視はコンテナごとの supervisor に限る。CORE-1・D-19） | P0 |
| 3 OS 対応 | パスを `PathBuf` / `Path::join` で組み立てているか（文字列連結・区切り文字のハードコードがないか）。大文字小文字非区別・長パス（260 文字超）・Unicode 正規化の差を考慮しているか（IO-5）。内部データファイルの改行が LF 固定か。OS 固有処理が `cfg(target_os = ...)` で局所化されているか（CLI-1） | P1 |
| `docs/spec` 非依存ビルド | コード・`build.rs`・テストが `docs/spec` 配下を読み込んでいないか（`docs/spec` 抜きでビルド・テストが成立するか） | P0 |
| spec 参照規約 | spec の内容を引用・要約する箇所にビヘイビア ID・TASK-n・MS-n が併記されているか（spec ファイルの丸ごとコピーになっていないか）。`docs/spec` 配下自体を本リポ側で編集していないか | P1 |
| エラーハンドリング | ライブラリコードが `Result` を返し panic させていないか | P0 |
| 構造化エラー | エラーが非ゼロ終了コード・機械可読な `code` / `message` の構造化形式に揃っているか（ERR 系） | P1 |

### I/O 契約（`crates/io` に触れる変更。`.claude/rules/coding-rust.md`・`.claude/rules/security.md`）

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| フラッシュバリアの保証範囲 | 明示フラッシュバリア（FLUSH ACK）が「バリア以前に受理した書き込みの永続化完了」を保証する契約を弱める変更になっていないか（データ損失につながるため。IO-2・IO-3） | P0 |
| ACK 種別の区別 | 通常の書き込み ACK（バッファリング ACK。プロセス正常稼働の保証まで）と FLUSH ACK（永続化完了の保証）を混同・取り違えていないか、ドキュメント上も区別されているか（IO-1・IO-2） | P0 |

### 再利用・AI 自己補修性（REPAIR 系ビヘイビア）

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| 単一責務・疎結合 | 1 回の改修が波及する crate・モジュールが最小に保たれているか（REPAIR-1） | P1 |
| ワイヤー型 | I/O 共有プロトコル（`crates/io`）・plugin 境界の長さ接頭辞フレーム（`crates/plugin`。PLUG-2）等のプロトコルフレーム（ID・長さ・データ）を生の `Vec<u8>` の手組みで扱わず、「壊れた値を表現できない」型（固定長ヘッダの newtype・チェックサム等）で組み立てているか（REPAIR-2） | P1 |
| 構造化された戻り値 | 公開 API の戻り値が将来拡張できる構造を持つ型か（真偽値・フラットな文字列で済ませていないか） | P1 |
| スタブの明示 | 未実装・簡易実装箇所が「実装済みを装って」いないか。ドキュメントコメントに将来仕様と対応するビヘイビア ID が明記されているか（REPAIR-3） | P0 |
| 可観測性 | read/write/create/start 等の操作の成功 / 失敗カウント・レイテンシ分布が構造化ログ / メトリクスとして出力されているか（REPAIR-4） | P1 |
| コメント規約 | crate・モジュールの入口に `//!`、公開 API に `///` で役割要約があるか。呼び出し元・呼び出し先の文脈、他 crate との契約（公開トレイト・エラー型・前提条件・スレッド安全性）が書かれているか。逐語説明や spec 本文の長い引用になっていないか（`.claude/rules/code-comment-style.md`） | P2 |
| テストとビヘイビア ID の対応 | 挙動がビヘイビア ID（例: `IO-2`）に対応づけてテストされ、テスト名またはドキュメントコメントに ID が記されているか。ユニットテストと結合テストが併置され、期待値が具体値で書かれているか。受け入れ基準を機械照合するテストがあるか（REPAIR-12） | P1 |
| スコープ外事項の追跡 | 実装・レビュー中に見つかったスコープ外の事項が、当該 PR に混入せず Issue 追跡へ切り出されているか（`.claude/rules/out-of-scope-tracking.md`。スコープ外混入は `.claude/rules/conventional-commits.md` の禁止事項） | P1 |

### 規約（表記・コミット）

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| 日本語規約 | コード内コメント・ドキュメントが日本語で書かれているか。エラーメッセージ・ログ・CLI 出力・API レスポンス等プログラムの出力文字列が英語になっているか（`.claude/rules/japanese-style.md`） | P2 |
| Conventional Commits | PR タイトル（および PR 本文に見えるコミットメッセージ）が Conventional Commits 形式か。type/scope が英語、説明文が日本語になっているか（`.claude/rules/conventional-commits.md`） | P2 |

### CI・ワークフロー

| 観点 | 確認内容 | 優先度 |
| ---- | ---- | ---- |
| 第三者 action の固定 | サードパーティ action はコミット SHA で固定されているか | P0 |
| `Fandhe-AI/actions` の例外 | `Fandhe-AI/actions` は組織内（first-party）の上流リポジトリであり、上記「第三者 action の固定」の対象ではない。reusable workflow への参照は組織方針（2026-08-18 オーナー判断）により可変タグ `@latest` の使用が認められている。`@latest` への統一・SHA pin の除去を指摘しない | 指摘しない（例外） |
| runner 方針 | public リポジトリのため既定は GitHub ホステッドランナー。self-hosted の使用が許可されるのは `ai-review.yml` の `codex / review` ジョブ（組織承認済み例外）のみで、`codex / preflight`・`codex / post_feedback` を含む他ジョブ・他 workflow は GitHub ホステッドランナーになっているか | P0 |
| permissions | ワークフロー・ジョブの `permissions` が最小権限で明示されているか | P0 |
| secrets の扱い | secrets が `pull_request` イベントのログへ出力されていないか | P0 |
| `ci.yml` の現状 | `ci.yml` は準備が整うまで発火条件を無効化中（`workflow_dispatch` のみ）であり、workspace（`Cargo.toml`）とメンバー crate の作成後に `pull_request` / `push` を有効化する設計であることを踏まえ、この無効化自体を指摘しない | 指摘しない（既知の暫定状態） |
| `ci.yml` への変更 | `ci.yml` を変更する差分では、3 OS matrix（Linux・macOS・Windows）を維持しているか、本リポに存在しない `make` ターゲット・`scripts/` を前提にしたジョブが混入していないかを確認する | P1 |
| `release.yml` | `workflow_dispatch` 限定のプレースホルダであり、有効化には公開対象クレート・crates.io 公開方針の確定を要する。現状のプレースホルダ状態自体は指摘しない | 指摘しない（既知の暫定状態） |
| ゲート未導入段階の追記 | REPAIR-7 の 5 段階ゲートのうち (3) タイムアウト保護された結合試験・(4) ベンチ回帰チェック（REPAIR-8）の導入時は、本書「ビルド・テスト・回帰確認コマンド」節・`.claude/rules/ci.md` の更新を伴っているか | P2 |
