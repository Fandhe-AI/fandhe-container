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

`make` ターゲットを正とする（括弧内に実行される cargo コマンドを併記する）。本節は REPAIR-10 が求める 4 項目 (a) ビルドコマンドと成功基準・(b) 回帰確認コマンド一覧・(c) 推奨タイムアウト値・(d) 新機能追加時に更新すべきテスト一覧をすべて扱う。(d) は下記「新機能追加時に更新すべきテスト一覧」節で扱う。

- `Cargo.toml`（workspace）と `crates/*/Cargo.toml`（メンバー crate）は現在すべて揃っており、`deny.toml` も存在するため、下記の `fmt`/`lint`/`test`/`deny` は Makefile 側で skip されず常に実行される（`HAS_CARGO`/`HAS_MEMBERS`/`HAS_DENY` はいずれも真）。`skip: ...` という出力が現れた場合は本来実行されるはずのターゲットが実行されていない異常事態であり、**合格の根拠にしない**（false-green 防止）。`check-workspace-manifest`（`cargo verify-project`）は `Cargo.toml` の存在のみで判定し、メンバー crate 未追加の中間状態でも実行される仕組みだった名残で、現状は常に実行される
- PR 本文にこれらのコマンドの実行結果（終了コードと要点）が記載されているか（同じ PR で CI 設定を変更する場合はその diff にこれらのコマンドが含まれているか）を確認する。本節の未達は、個別に優先度を明記した項目を除き既定で P1 とする
- clippy 警告は 0 件を維持する。理由コメントなしで `#[allow(...)]` により警告を握りつぶす差分は P1。crate・モジュール全体に及ぶ広範な `#[allow(...)]`（`#![allow(...)]` 等）や、`unsafe` 関連 lint（`unsafe_code`・`clippy::undocumented_unsafe_blocks` 等）・外部入力の検証を隠す lint（`clippy::unwrap_used`・`clippy::expect_used`・`clippy::indexing_slicing` 等。下記「外部入力の検証」観点）の外部入力経路での抑止は、理由コメントの有無を問わず P0
- テストの skip・ignore・アサーション弱体化で CI を通す差分は P0（回帰検出の後退を招くため）

### ビルドコマンドと成功基準（REPAIR-10 (a)）

合格は共通して「終了コード 0」とする。`skip: ...` が出力された場合は実行されていないため合格扱いにしない（上記の注意を参照）。

| ターゲット | 実行内容 | 成功基準 |
| ---- | ---- | ---- |
| `make fmt-check` | `cargo fmt --all --check` | 終了コード 0。整形差分（`Diff in ...`）を出力しない。差分がある場合は `make fmt` で整形してから再実行する |
| `make lint` | `cargo clippy --workspace --all-targets -- -D warnings`（既定 feature） | 終了コード 0 かつ clippy 警告 0 件（`-D warnings` により警告はエラー扱いになる）。理由なしの `#[allow]` での抑止は上記のとおり P1・外部入力系 lint の抑止は P0 |
| `make test` | `cargo test --workspace`（既定 feature） | 終了コード 0。すべての `test result:` 行が `0 failed`。`ignored` の増加で通していないこと（skip/ignore は P0） |
| `make deny` | `cargo deny --locked check advisories bans licenses sources` | 終了コード 0 かつ advisories・bans・licenses・sources の 4 チェックすべて ok（`--locked` により `Cargo.lock` の更新が必要な状態も失敗として検出する） |
| `make ci` | `lint-docs` → `check-workspace-manifest` → `fmt-check` → `lint` → `test` → `deny` の順に実行 | 6 サブターゲットすべてが終了コード 0（make は最初の失敗で停止する）。`lint-docs` は markdownlint・yamllint・editorconfig-checker・commitlint（`origin/main` からの分岐点以降のコミット）を含む |

**`make ci` の合格はローカルゲート（[ci](.claude/rules/ci.md)）であり、PR のマージゲートである CI 全体と同一ではない。** `make ci` は `--all-features` での検証・`test-integration`・`bench-check`・3 OS matrix を含まない。PR のマージゲートは `ci.yml` の集約ジョブ `ci-complete` が `lint-docs`・`rust-ci`・`rust-ci-default-features`・`integration-test`・`bench-regression`・`aarch64-linux-check` の全ジョブの成功を fail-closed で検証した上で成功することである。

### 回帰確認コマンド一覧（REPAIR-7・REPAIR-10 (b)）

```bash
make fmt-check              # cargo fmt --all --check
make lint                   # cargo clippy --workspace --all-targets -- -D warnings（既定 feature）
make test                   # cargo test --workspace（既定 feature）
make test-integration       # cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server ＋ --bins（結合試験。integration test target が 0 件なら notice を出して成功終了する）
make deny                   # cargo deny --locked check advisories bans licenses sources
make ci                     # lint-docs + check-workspace-manifest + fmt-check + lint + test + deny を一括実行
make bench-check-selftest   # ベンチ回帰比較スクリプトの自己テスト（REPAIR-8）
make plugin-feature-size    # core の既定 / plugin 除外 release ビルドの rlib サイズ記録（PLUG-3・TASK-111.2。最終バイナリ未実装のため rlib 計測）
make bench-check            # ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）
cargo bench -p fandhe-container-benches --bench plugin_boundary -- --output <path>  # 代表操作 A の plugin 境界ベンチ（TASK-113.1・PLUG-5。同一プロセスと境界越しの p50 と Δp50（TASK-113.3）を ns で出力し、Δp50 と CORE-10 比は stderr へログ。Unix のみ。baseline 未登録のため bench-check には未接続）
cargo bench -p fandhe-container-benches --bench plugin_boundary_list_images [-- --output <path>]  # 代表操作 B（イメージ一覧）の plugin 境界ベンチ（TASK-113.2・PLUG-5。引数なしはスモーク。Δp50 も出力。bench-check には未接続）
make bench-plugin-boundary  # plugin 境界ベンチ A・B を実行し Δp50 と CORE-10 の Linux 実機値（0.290〜0.298 秒）に対する割合をログ出力（TASK-113.3・PLUG-5。基準値比較なし）
make bench-macos-cold-start  # macOS cold start 上乗せ（都度起動・常駐）を計測し、MAC-2 目標 2 秒の 1% 未満（20 ms 未満）を判定（TASK-113.4・PLUG-6。macOS のみ。他 OS は skip。CI の macos では結合試験 `benches/tests/macos_cold_start.rs` として実行。bench-check には未接続）
make bench-baseline-selftest  # baseline.json 生成スクリプトの自己テスト（TASK-88.1・REPAIR-12）
make bench-baseline         # ベンチを実行し baseline.json を再生成する（TASK-88.1。BENCH_ENVIRONMENT・BENCH_BASELINE_OUT で指定。実測の記録は TASK-88.2）
make fio-bench-selftest     # fio 4K ランダム write ベンチスクリプトの自己テスト（TASK-25.1・IO-8・REPAIR-12。実 fio 不要）
make fio-bench TARGET_DIR=<dir> LABEL=<label> [RUNTIME=<seconds>]  # fio 4K ランダム write ベンチを実行する（実機前提。下記「実機前提テスト」節を参照）
make fio-baseline-ratio-selftest  # fio ベースライン比算出スクリプトの自己テスト（TASK-25.2・IO-8・REPAIR-12。実 fio 不要）
make fio-baseline-ratio BASELINE=<results.json> CANDIDATE=<results.json>  # Docker ベースライン比（IOPS・レイテンシの倍率）を算出する（実 fio 不要。results.json は fio-randwrite-4k.sh の出力）
make startup-latency-selftest  # 起動時間計測スクリプトの自己テスト（TASK-46.1・TASK-46.2・CORE-10・REPAIR-12。スタブランタイム・スタブ docker で完結。Linux 限定）
make startup-latency RUNTIME=<abs-path> BUNDLE=<dir> TARGET=<name> [ITERATIONS=<n>] [LABEL=<label>]  # create からプロセス実行開始（state が running / stopped を返した時点）までの起動時間の中央値を計測する（実機前提）
make startup-latency-docker DOCKER=<abs-path> [TARGET=<name>] [IMAGE=<ref>] [ITERATIONS=<n>] [LABEL=<label>] [OUTPUT=<file>]  # `docker run --rm --pull never ... --entrypoint true <image>` 全体の起動時間の中央値を計測する（TASK-46.2・CORE-10。実機前提。イメージは事前に手動 pull）
make startup-latency-report OWN_RESULT=<file> DOCKER_RESULT=<file> [OUTPUT=<file>]  # own（oci モード）と Docker の結果を 1 つのレポートに統合する（TASK-46.2。合否判定は出さない）
make idle-memory-selftest   # アイドル時常駐メモリ計測スクリプトの自己テスト（TASK-45.1・CORE-7・SUP-1。疑似 /proc のみで実計測はしない。終了コード 0 かつ FAIL 行なし。Linux・非 root 限定で、root 実行は chmod 000 系のケースが成立しないため失敗する）
make idle-memory-supervised-selftest   # 監視プロセス込みアイドル常駐メモリ回帰テストの自己テスト（TASK-47・CORE-7・SUP-1。スタブ計測・スタブ driver のみで実計測はしない。終了コード 0 かつ FAIL 行なし。Linux・非 root 限定）
make idle-memory-supervised DRIVER=<abs-path> [EXPECTED_DIR=<dir>] [OUTPUT=<file>] [IDLE_MEMORY_SUPERVISED_TIMEOUT=<秒>]  # 0 個 → 監視プロセス込み 1 個 → 0 個の常駐メモリを計測し 0 へ戻ることを判定（実機前提・make ci 対象外。Linux・root の操作者が明示実行し、スクリプト内で sudo は呼ばない。DRIVER は `up` / `down` を受ける実行可能ファイルの絶対パスで、製品バイナリ〔TASK-79〕未提供のため現状は実 driver なし。実機では EXPECTED_DIR に配置ディレクトリを渡す）。終了コードは idle-memory と同じ契約（0 = 成功、1 = 期待違反、2 = 引数・入力エラー、3 = 計測失敗・driver 失敗）。make は失敗時に自身は 2 で終わるため、レシピの値は `Error <n>` 行で確認する
make idle-memory [IDLE_MEMORY_TIMEOUT=<秒>]  # プロセス数・PSS・RSS を JSON 出力（ローカル実測は [idle-memory-local](docs/design/measurements/idle-memory-local.md)。Linux 限定・実機計測。timeout 付き〔既定 120 秒〕）。スクリプトの終了コード: 0 = 成功、1 = --expect-zero 違反（結果は公開しない）、2 = 引数・入力エラー・非 Linux・出力先エラー・timeout 配下で起動できない、3 = 計測失敗（読めない値・識別不能・timeout 超過・想定外の終了）。make は失敗時に自身は 2 で終わるため、レシピの値は `Error <n>` 行で確認する
make concurrent-memory-selftest  # 50 コンテナ同時起動メモリ計測スクリプトの自己テスト（TASK-50.1・TASK-50.2・CORE-9・SUP-1・REPAIR-12。スタブ launcher・スタブ docker CLI・疑似 /proc で完結し、実コンテナ・実 Docker・root は使わない。own・docker・report の全モードを照合する。Linux・非 root 限定）
make concurrent-memory LAUNCHER=<abs-path> BUNDLE=<dir> TARGET=<name> [COUNT=<n>] [TRIALS=<n>] [OUTPUT=<新規ファイル。既存のパスは拒否し上書きしない>] [CONCURRENT_MEMORY_TIMEOUT=<秒>]  # N（既定 50）個を同時起動し、集約 PSS の中央値を計測する（実機前提。TASK-50.1。launcher 契約はスクリプト冒頭を参照。全体を timeout で包む〔既定 1800 秒。超過・想定外の終了は 1〕）
make concurrent-memory-docker DOCKER=<docker CLI の絶対パス> [TARGET=<name>] [IMAGE=<ref>] [COUNT=<n>] [TRIALS=<n>] [OUTPUT=<新規ファイル。既存のパスは拒否し上書きしない>] [CONCURRENT_MEMORY_TIMEOUT=<秒>]  # Docker 側の N（既定 50）個を同じ手法で同時起動し、集約 PSS の中央値を計測する（実機前提。TASK-50.2。集計対象はデーモン〔dockerd・containerd〕＋各コンテナの containerd-shim 配下のツリー。全体を timeout で包む〔既定 1800 秒〕）
make concurrent-memory-report OWN_RESULT=<own の結果 JSON> DOCKER_RESULT=<docker の結果 JSON> [OUTPUT=<新規ファイル>]  # own・Docker の結果を 1 つのレポートへ統合する（TASK-50.2。入力は非信頼 JSON として検証し、count 不一致・mode 取り違え・中央値の改ざん等は終了コード 2。合否は出さない。jq が必要）
```

- `make test-integration`: 終了コード 0 が成功基準。`notice:` 出力での成功終了は、全 crate から `tests/*.rs` が無くなった場合のフォールバック。通常は `cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server` と `cargo test -p fandhe-container-io --bins --features crash-test-server` の 2 段が実行される。`crash_safety` 等 `required-features` 付きの target は `make test`（既定 feature）では実行されず、本ターゲットと CI の `integration-test`・`rust-ci`（`--all-features`）で実行される。実行された件数は Makefile・CI が出力する `integration test targets: N` 行で確認する。`notice:` での成功終了は結合試験が 1 件も実行されていないことを意味し、`tests/*.rs` を追加・変更した PR の合格根拠にしない（冒頭の `skip:` と同じ扱い）。jq 未導入時は fail-closed で終了コード非 0 になる
- `make bench-check-selftest` / `make bench-check`: 終了コード 0 が成功基準。`bench-check` を呼ぶ比較スクリプト（`scripts/check-bench-regression.sh`）自体の終了コードは 0（合格）/ 1（回帰検出）/ 2（入力エラー）の 3 値で、詳細は下記「タイムアウト保護された結合試験・ベンチ回帰」節 (4) を参照する。**現時点では計測対象がプレースホルダのため、`bench-check` の成功を性能回帰がない根拠として扱わない**
- `make fio-bench-selftest`: 終了コード 0 が成功基準。`--from-json` モードと固定 fixture（`scripts/testdata/fio-bench/`）・fio スタブで完結し、実 fio は使わない。CI の `bench-regression` ジョブにも組み込まれている
- `make concurrent-memory-selftest`: 終了コード 0 かつ FAIL 行なしが成功基準。スタブ launcher・スタブ docker CLI・疑似 /proc で完結し実ランタイム・実 Docker・root は使わない。Linux 限定。CI の `bench-regression` ジョブにも組み込まれている（TASK-50.1・CORE-9・SUP-1）。
- `make concurrent-memory`: 実機前提（`run --id <id> --bundle <dir>` を受けてフォアグラウンドに留まる launcher と bundle が必要。own の CLI・本番 launcher は未提供のため、現時点では own を実測できない。REPAIR-3）。`LAUNCHER`（絶対パス）・`BUNDLE`・`TARGET` 未指定時は案内を出して終了コード 2 で止まる。終了コード 0 = 全試行 N/N 起動で成功、1 = 起動数不足・PSS 0 混入・読めない値・期限切れ・集計中のコンテナ終了・子プロセス一覧を読めない（結果は公開しない。launcher のログは収集側で 1 つあたり先頭 256 KiB だけを記録して以降は読み捨て、launcher 側には ulimit を掛けない。READY 行はその範囲内に出す）、2 = 引数・出力先エラー、3 = 前提欠如、4 = 後始末失敗（残存プロセス）。スクリプトを直接実行した場合、HUP / INT / TERM による中断は後始末の完了後に 129 / 130 / 143 を返す（make 経由では 1）。user namespace 内のプロセスの smaps_rollup を読むため権限付きシェルから実行する（スクリプトは sudo を呼ばない）。実測と CORE-9・SUP-1 の判定は #219（TASK-50.h1）で人間が行い、Docker 側の同一手法計測は #218（TASK-50.2）。`make ci` には含めない
- `make concurrent-memory-docker`: 実機前提（実 Docker・ローカルの rootful デーモン・`IMAGE`〔既定 `alpine:3.20`〕の事前 pull・他のコンテナが稼働していないこと・権限付きシェル〔root 所有のデーモン・shim の smaps_rollup を読むため。スクリプトは sudo を呼ばない〕）。`DOCKER`（絶対パス）未指定時は案内を出して終了コード 2 で止まる。終了コードは `make concurrent-memory` と同じ（1 には計測前の拒否〔image-not-present・foreign-containers-running・docker-daemon-not-local〕を含み、4 は `docker rm -f` 後の残存）。`docker rm -f` は cidfile で所有を証明した ID だけに行う。実測値は未取得で、実測・SUP-1（80% 以下）の判定・PoC-17 の値との整合確認は #219（TASK-50.h1）で人間が行う。`make ci` には含めない
- `make concurrent-memory-report`: own・Docker の結果 JSON を統合する（jq が必要。実機・root 不要）。`OWN_RESULT`・`DOCKER_RESULT` 未指定時は終了コード 2。出力にはデーモン固定分の内訳（`daemon_pss_kb`）と `methods_differ` を含み、合否判定は出さない（#219）
- `make startup-latency-selftest`: 終了コード 0 が成功基準。スタブランタイムで完結し実ランタイム・root は使わない。Linux 限定（計測スクリプトが単調時計として `/proc/uptime` を必須とするため、macOS 等では前提欠如で失敗する）。CI の `bench-regression` ジョブにも組み込まれている（TASK-46.1・CORE-10）。TASK-46.2 で追加した docker モード・report モードのケース（スタブ docker・固定 fixture）も同じターゲットで実行される
- `make startup-latency`: 実機前提（OCI Runtime CLI 契約のランタイム実行ファイルと bundle が必要）。`RUNTIME`（絶対パス）・`BUNDLE`・`TARGET`（計測対象のランタイム名。出力の `target` に記録。例: `own`）未指定時は案内を出して終了コード 2 で止まる。Linux 限定。スクリプトの終了コードは次のとおり。

  - 0: 成功
  - 1: create / start / state の失敗・タイムアウト、実行開始（state が running / stopped）を期限内に観測できない、ID が既に使用中、計測中の時計の変更を検出した
  - 2: 入力エラー（`--output` の親から `/` までに symlink や他ユーザーが書き込めるディレクトリ〔sticky を除く〕がある場合を含む）
  - 3: 前提欠如（`/proc/uptime`・GNU timeout / dd / ln 等）
  - 4: 後始末失敗（作成済みコンテナを削除できない、または create が成功せず未作成を確定できない。後者では ID に操作を送らず、手動確認を促す。ERR-1 の構造化エラー〔code: NOT_FOUND〕を出さない runc 等では、create 失敗時は常に 4）

  `make ci` には含めない
- `make startup-latency-docker`: 実機前提（Docker CLI とローカルに取得済みのイメージが必要。既定 `alpine:3.20`。自動 pull はしない）。`DOCKER`（docker CLI の絶対パス）未指定時は案内を出して終了コード 2 で止まる。`docker run --rm --pull never ... --entrypoint true <image>` 全体の壁時計時間を計測し（CORE-10 の Docker ベースライン 0.290〜0.298 秒と同じ手法）、終了コードは `startup-latency` と同じ意味。後始末は cidfile に書かれた ID だけに `rm -f` を送り、cidfile がなければラベル一覧が空のときだけ未作成とみなす（所有を証明できないコンテナには何も送らず、終了コード 4 で手動確認を促す）。Docker ソケットは root 同等の権限のため、実測は #213（TASK-46.h1）で人間が明示実行する。`make ci` には含めない
- `make startup-latency-report`: `OWN_RESULT`（oci モードの出力）・`DOCKER_RESULT`（docker モードの出力）未指定時は案内を出して終了コード 2 で止まる。入力 JSON は非信頼として検証し（symlink 拒否・1 MiB 上限・`schema_version`・`benchmark`・`mode`・正の p50）、違反は終了コード 2。**own と Docker は計測区間が異なる**（own は create 直前から実行開始の観測まで、Docker は `docker run --rm` 全体）ため、出力の `comparison.methods_differ` が `true` になり、比率は参考値。合否判定（Conditional Go 条件 1）は出さず、#213 で人間が行う。実 Docker を必要としないが、入力は実機計測の結果
- `make fio-bench`: 実機前提（fio・GNU coreutils の `timeout`・Linux ホスト）。`TARGET_DIR`・`LABEL` 未指定時は案内を出して終了コード 2 で止まる。詳細は下記「実機前提テスト」節・[docs/design/io-fio-bench.md](docs/design/io-fio-bench.md) を参照
- `make fio-baseline-ratio-selftest`: 終了コード 0 が成功基準。固定 fixture（`scripts/testdata/fio-baseline/`）で完結し、実 fio・Docker は使わない。CI の `bench-regression` ジョブにも組み込まれている
- `make fio-baseline-ratio`: `BASELINE`・`CANDIDATE`（いずれも `fio-randwrite-4k.sh` の出力 JSON）未指定時は案内を出して終了コード 2 で止まる。fio・Docker を必要としないため実機前提テストではない
- CI の `rust-ci`（3 OS matrix）は clippy/test を `--all-features` で実行し（fmt/deny は feature 非依存）、`rust-ci-default-features`（3 OS matrix）が `make lint`/`make test` と同一コマンド（既定 feature）を再現する。両者は別ジョブであり、既定 feature 側の回帰は `rust-ci-default-features` でのみ検出される
- 各コマンドと CI ジョブの対応（TASK-94 の整合確認で参照する）:

| コマンド | 対応する CI ジョブ |
| ---- | ---- |
| `fmt-check`・`deny` | `rust-ci` |
| `lint`・`test`（既定 feature） | `rust-ci-default-features`（`--all-features` 側は `rust-ci`） |
| `test-integration` | `integration-test` |
| `bench-check-selftest`・`bench-baseline-selftest`・`bench-check`・`bench-plugin-boundary`・`plugin-feature-size` | `bench-regression` |
| （対応 target なし。`rustup target add aarch64-unknown-linux-gnu` の後に `cargo check --workspace --all-targets --all-features --target aarch64-unknown-linux-gnu` と `cargo clippy --workspace --all-targets --all-features --target aarch64-unknown-linux-gnu -- -D warnings`） | `aarch64-linux-check` |
| `lint-docs` | `lint-docs` |
| `check-workspace-manifest`（`make ci` の一部） | 専用の CI ジョブはない（ローカルゲート専用）。workspace manifest が不正なら各 cargo ジョブのビルドが失敗するため、CI では間接的に検出される |

### 推奨タイムアウト値（REPAIR-5・REPAIR-10 (c)）

| 層 | 値 | 設定箇所 | 根拠 |
| ---- | ---- | ---- | ---- |
| テスト 1 件の応答待ち（ACK・plugin RPC・子プロセス） | 推奨 5〜10 秒（CI 設定値 10 秒） | `ci.yml` `integration-test` ジョブの env `FANDHE_CONTAINER_TEST_TIMEOUT_SECS: "10"`（TASK-87.1・#40） | PoC-8 実測・REPAIR-10 (c)・REPAIR-5 |
| plugin の ACK / RPC 応答待ち（フレーム 1 つ） | 既定 10 秒・上限 10 秒（0 と上限超過は構築不可） | `crates/plugin/src/transport.rs` の `RpcTimeout`（`UDS_RPC_TIMEOUT_DEFAULT`・`UDS_RPC_TIMEOUT_MAX`。TASK-107.6・#250） | REPAIR-5・PLUG-2・PLUG-5 |
| plugin 都度起動の合計期限（spawn から応答受信まで）・応答後の終了猶予・強制終了後の回収待ち・stderr の収集待ち | 合計期限 既定 10 秒・上限 10 秒（0 と上限超過は構築不可）／終了猶予 5 秒（超過で強制終了）／回収待ち 2 秒（超過は回収失敗としてエラー）／stderr の収集待ち 500 ミリ秒（超過は途中結果で打ち切り、読み取りスレッドを停止させる。停止の確認は 1 秒まで。保持は 64 KiB まで） | `crates/plugin/src/lifecycle.rs` の `OneShotTimeout`・`ONE_SHOT_EXIT_TIMEOUT`・`ONE_SHOT_REAP_TIMEOUT`・`ONE_SHOT_STDERR_DRAIN_TIMEOUT`・`ONE_SHOT_STDERR_STOP_TIMEOUT`・`ONE_SHOT_STDERR_MAX_BYTES`（TASK-110.1・#258） | REPAIR-5・PLUG-7 |
| plugin 常駐モードの起動期限（spawn から接続確立まで）・往復ごとの期限・失敗後の終了確認の猶予 | 起動期限 既定 10 秒・上限 10 秒（0 と上限超過は構築不可）／往復は呼び出しごとの `RpcTimeout`（送信と受信の合計）／往復失敗後の終了確認 200 ミリ秒／終了待ち・回収待ち・stderr 収集待ちは都度起動と共用 | `crates/plugin/src/lifecycle/resident.rs` の `ResidentStartTimeout`・`RESIDENT_EXIT_DETECT_TIMEOUT`（TASK-110.2・#259） | REPAIR-5・PLUG-7 |
| 結合試験の実行ステップ | 10 分 | `integration-test` ジョブの実行ステップ `timeout-minutes: 10` | TASK-86.2（#36）・TASK-87 |
| ジョブ全体 | `integration-test` 30 分・`bench-regression` 15 分・`ci-complete` 5 分 | 各ジョブの `timeout-minutes` | 多層防御 |

- この env を読んで `IoTimeout` を組み立てる消費側コードは `crates/io/tests/responsiveness.rs`（TASK-85.1・#119、TASK-85.2・#120。REPAIR-5）。範囲外・非数値の値は fail-closed で panic し、未設定時の既定は 10 秒。`crates/core/tests/unshare_isolation.rs`（TASK-27.2・#134。Linux のみ、`-- --ignored` 時の子プロセス待ち）と `crates/core/tests/escape_suite.rs`（TASK-42.6・#204。同条件）も同 env を読むが、`IoTimeout` ではなく `Duration` を組み立て、範囲外（1〜600 秒以外）・非数値の値は panic せず既定の 10 秒へフォールバックする。UDS 対応 OS（Linux / macOS）でのみコンパイルされ、Windows では当該経路は対象外。他の結合試験（スタブのトランスポートを使うもの）は env を読まず、固定の短いタイムアウトを使う
- 新しく書く応答待ち処理は 5〜10 秒の範囲を既定とする。ACK・plugin RPC・子プロセスなど相手の応答を待つ処理に、タイムアウトなしで無期限に待ち得る経路を追加する差分は P0（REPAIR-5。詳細は下記「タイムアウト保護された結合試験・ベンチ回帰」節および「レビュー観点」のタイムアウト項目）
- タイムアウト値を検出が弱まる方向（上限の撤廃・大幅な延長）へ変える差分は、根拠の記録がなければ「回帰検出の後退」として扱う（bench 閾値の既存記述と同じ扱い）
- ハングプローブ（TASK-87.2・#41）の実施記録は下記「タイムアウト保護された結合試験・ベンチ回帰」節に記載済み

### 新機能追加時に更新すべきテスト一覧（REPAIR-10 (d)）

新機能を追加したり既存の挙動を変えたりする差分では、触れたビヘイビア ID に対応するユニットテストと結合試験を追加・更新する。テスト名またはドキュメントコメントにビヘイビア ID を書き、期待値は具体値で書く（REPAIR-12・[coding-rust](.claude/rules/coding-rust.md)「テスト」）。本節は「追加時に用意すべきテストのカテゴリ」を示すものであり、既存テストの一覧ではない（REPAIR-3）。現時点で未実装の仕組みは各行に「現状」を注記する。本節の未達は、個別に優先度を明記した項目を除き既定で P1 とする（上記「ビルド・テスト・回帰確認コマンド」節と同じ扱い）。

共通カテゴリ:

| カテゴリ | 置き場所 | 実行コマンド | 現状 |
| ---- | ---- | ---- | ---- |
| ユニットテスト | 各 crate の `src/` 内 `#[cfg(test)]` | `make test` | — |
| 結合試験 | 各 crate の `tests/*.rs`（integration test target） | `make test-integration` | `crates/io/tests/` に導入済み。他 crate の結合試験は各機能タスクで追加する。件数は `make test-integration` が出力する `integration test targets: N` 行で確認する |
| SIGKILL 耐性（IO-3・TASK-18.3.1。実測は [io-crash-safety](docs/design/io-crash-safety.md)） | `crates/io/tests/crash_safety.rs` | `make test-integration`、単体は `cargo test -p fandhe-container-io --features crash-test-server --test crash_safety` | 既定 CI 集合（`integration-test` 3 OS・`rust-ci`）で実行し、実機前提ではない。`integration-test` は「crash_safety の存在確認」ステップで glob による無言除外を検出する。電源断後の媒体永続化（IO-2）と実測レポート・妥当性判断（TASK-18 の人間担当）は保証しない |
| デーモンレス確認（CORE-1・D-19・SUP-1・TASK-28.2） | `crates/core/tests/daemonless.rs`・`crates/supervisor/tests/daemonless.rs` | `make test-integration`、単体は `cargo test -p fandhe-container-core --test daemonless`・`cargo test -p fandhe-container-supervisor --test daemonless` | root・namespace を要さず自身が起動した子プロセスのみを対象とするため、分離せず既定 CI 集合に含める。検証本体は Linux のみ（`/proc` 走査）。役割プロセスは代役で、本番バイナリでの n=0 確認と SUP-1 の実機計測は TASK-45・47・49 の担当 |
| ベンチ回帰 | `benches/benches/*.rs`・`benches/baseline.json`・`benches/metrics.json`・`scripts/bench/` | `make bench-check`・`make bench-baseline-selftest` | `bench-check` の対象はプレースホルダ段階。plugin 境界ベンチの Δp50 は metric 出力と fixture 判定（`make bench-check-selftest`。16% 悪化は exit 1・ちょうど 15% は exit 0）まで実装済みで、baseline 未登録のため常時比較は未有効（TASK-113.3）。基準値の校正は TASK-88（校正記録: [bench-calibration](docs/design/bench-calibration.md)） |
| fio 4K ランダム write ベンチ | `scripts/fio-randwrite-4k.sh`・`scripts/testdata/fio-bench/` | `make fio-bench-selftest`（自己テスト）・`make fio-bench`（実機） | TASK-25.1 で実装済み |
| 起動時間計測（CORE-10） | `scripts/bench/startup_latency.sh`・`scripts/bench/startup_latency_selftest.sh` | `make startup-latency-selftest`（自己テスト）・`make startup-latency`（実機）・`make startup-latency-docker`（実機）・`make startup-latency-report` | TASK-46.1: 計測ハーネスのみ実装済み。own 実測は CLI（TASK-79）・本番 launcher 提供後に人間が #213（TASK-46.h1）で実施。Docker 側の計測と own・Docker の統合レポートは TASK-46.2（#842）で追加済み（docker / report モード。計測区間が異なる点は `methods_differ` に明示。実測と判定は #213） |
| 50 コンテナ同時起動の集約メモリ計測（CORE-9・SUP-1） | `scripts/bench/concurrent_50_memory.sh`・`scripts/bench/concurrent_50_memory_selftest.sh` | `make concurrent-memory-selftest`（自己テスト）・`make concurrent-memory`・`make concurrent-memory-docker`（実機）・`make concurrent-memory-report`（統合） | TASK-50.1: own 側の計測ハーネス（起動数 N 未満・PSS 0 混入を失敗として検出）。TASK-50.2: Docker 側の同一手法計測（`--mode docker`）と own・Docker の統合レポート（`--mode report`）。実測と SUP-1 の判定は CLI（TASK-79）・本番 launcher 提供後に人間が #219（TASK-50.h1）で実施（実測値は未取得） |
| fio ベースライン比算出 | `scripts/fio-baseline-ratio.sh`・`scripts/testdata/fio-baseline/` | `make fio-baseline-ratio-selftest`（自己テスト）・`make fio-baseline-ratio`（比率算出） | TASK-25.2: 手順・比率算出・目標値案は整備済み。Docker ベースライン比の実測値は人間実施待ち（#114） |
| 実機前提テスト | 既定のテスト集合から分離する | 分離の仕組みは該当タスクで決める | 下記「実機前提テスト」節・[ci](.claude/rules/ci.md)「実機前提テスト」を参照 |
| feature 無効構成（PLUG-3・TASK-111.1・TASK-111.2） | `crates/core` の `plugin` feature（`--no-default-features`） | `make test-core-no-plugin`（CI の `rust-ci-default-features` ジョブが実行）・`make plugin-feature-size`（release ビルドの rlib サイズ記録。CI の `bench-regression` ジョブが実行。記録: [plugin-feature-size-record](docs/design/plugin-feature-size-record.md)） | 無効構成で core がテストでき、依存ツリーに `fandhe-container-plugin` が入らないことを検証する |
| 依存・ライセンス検査 | `Cargo.toml`・`deny.toml` | `make deny` | 依存を追加・更新するときのみ（ユーザー承認制。[dependency-policy](.claude/rules/dependency-policy.md)） |

コマンドと CI ジョブの対応は上記「回帰確認コマンド一覧」節の表を参照する（重複管理しない。TASK-94）。

#### crate 追加時（`crates/<短縮名>` を新設するとき）

- root `Cargo.toml` の `members` に追加し、`make check-workspace-manifest`・`make ci` が `skip:` を出さずに実行されることを確認する
- 公開 API ごとのユニットテスト（ビヘイビア ID と具体値の期待値）
- 外部入力（イメージ・TOML・CDI・リクエスト等）を受ける crate は、不正値・上限超過を拒否することのユニットテスト（[coding-rust](.claude/rules/coding-rust.md)「エラーハンドリング」）
- 他 crate との結合や応答待ち（ACK・RPC・子プロセス）を持つ crate は、`tests/*.rs` に結合試験を置く。応答待ちにはタイムアウトを付ける（REPAIR-5）
- OS 依存の FS 挙動（パス・大文字小文字・改行・長パス。IO-5・CLI-1）に触れる crate は、3 OS すべてで実行されるテストにする。特定 OS だけ skip して CI を通さない
- 性能目標を持つ crate は、ベンチの metric を追加し baseline を用意する（校正は TASK-88 の手順に従う。現状は placeholder）
- root 権限・KVM・GPU・WSL2・特定カーネル版数（Landlock ABI 等）が必要なテストは実機前提テストとして分離し、理由とビヘイビア ID を記して、実機での実行結果を PR に残す（[ci](.claude/rules/ci.md)「実機前提テスト」・下記「実機前提テスト」節）

#### plugin 追加時（`crates/plugin-<名前>` を追加するとき）

上記「crate 追加時」の全項目に加えて、次を追加で用意する。

- plugin 境界フレーム（長さ接頭辞フレーム。PLUG-2）の符号化・復号、壊れたフレームや長さ上限超過を拒否することのユニットテスト。フレームは型で組み立てる（REPAIR-2）。plugin からの入力は untrusted として検証する
- plugin RPC の応答待ちがタイムアウトで打ち切られることの結合試験（REPAIR-5。フレーム単位の待機は `crates/plugin/tests/transport_frame_io.rs`〔#250〕。要求・応答の往復の試験は TASK-107.7・#251）。都度起動モードの合計期限・子プロセス回収の結合試験は `crates/plugin/tests/lifecycle_one_shot.rs`（TASK-110.1・#258・PLUG-7）、常駐モードの順次処理・異常終了検知の結合試験は `crates/plugin/tests/lifecycle_resident.rs`（TASK-110.2・#259・PLUG-7）
- PLUG-4「core 無変更」の 3 点比較（core 側ソースの sha256 一覧・`cargo tree -p <core> --locked -e normal` で見た core の依存木・core バイナリの sha256。[crate-naming.md](docs/design/crate-naming.md) 決定 3）が変化しないこと。**現状**: `scripts/check-plug4-core-invariance.sh`（`make plug4-core-invariance`。core バイナリは未存在のため rlib で代理。TASK-79 後に実行ファイルへ切替）が plugin 追加前後の別ビルドで 3 点を比較する。ソース一覧と、plugin crate を新規追加する PR の差分検査は `crates/core` 配下全体（`src/` に加え `tests/` 等）を対象とする。スクリプトの自己テストは `make plug4-core-invariance-selftest`（CI の `integration-test` ジョブの ubuntu・macos）。plugin を通すために core 側のソースやテストを書き換えないこと（PLUG-4 違反は既存の P0 観点）
- plugin 境界のベンチ（TASK-113 の `plugin_boundary` 系）。**現状**: 代表操作 A・B と Δp50・CORE-10 比のログ出力は実装済み（TASK-113.1〜113.3）。macOS cold start 上乗せ確認（TASK-113.4・PLUG-6・MAC-2）は macOS のみ結合試験として 3 OS matrix の macos で実行し（`bench-regression` は不変）、2 秒の 1% 未満を判定する。実測基準値の `benches/baseline.json` 登録と `make bench-check` への組み込み（常時の 15% 回帰判定）は TASK-88.h1・TASK-113.h1 待ちで未有効。それまで `bench-regression` の成功は plugin 境界の性能回帰がない根拠にならない。`bench-check` は `bench-baseline` と同じ `BENCH_NAMES` を実行し baseline.json 登録済み metric に絞って比較するため、基準値の再生成後は plugin 系 metric も自動で 15% 判定の対象になる
- plugin の信頼性検証（PLUG-11: 他ユーザー書き込み可能な場所・ハッシュ不一致の plugin の登録拒否）と UDS 境界（PLUG-12: 権限・peer credential 検証）について、新しい plugin を対象にしたケース。**現状**: 管理ディレクトリからの候補探索（TASK-109.1）と PATH 探索の opt-in・警告ログ（TASK-109.2。候補は未検証・CLI フラグ配線は TASK-79）は実装済み。同名候補を解決するレジストリも TASK-109.3 で実装済み（登録は信頼済みを意味しない）。所有者・モード・symlink 実体解決（TASK-122.1・122.2）と sha256 許可済みハッシュ照合（TASK-122.3。許可一覧は sha256sum 互換テキストの設定ファイル方式）は `crates/core` の `plugin_trust` に実装済み（Linux のみ）。検証方式の切替点は TASK-122.4 で実装済み（既定はハッシュ一覧、署名検証本体は未実装で指定時は拒否）。拒否の構造化エラー（code / reason / message の 1 行 JSON）と `PluginTrust` 監査レコード化（TASK-122.5）も実装済み（本番 sink・CLI 出力への配線は未実装）。公開 API 経由の拒否ケース結合試験（他ユーザー書き込み可能ディレクトリ・未許可ハッシュ・symlink 経由の実体。TASK-122.6）も追加済み。レジストリ配線・UDS 検証（TASK-123・124）は未実装
- `plugin-microvm` 等 microVM 系の依存に触れる場合は `make deny` の禁止クレート検査（MVM-4）。**現状**: 機械判定（`scripts/check-microvm-deps.sh`・`deny.toml` `[bans]`）は TASK-73 で導入予定
- macOS Virtualization.framework・WSL2・KVM を使うバックエンド plugin（`plugin-macos`・`plugin-windows`・`plugin-microvm`）の実機依存テストは、実機前提テストとして分離する（[ci](.claude/rules/ci.md)「実機前提テスト」）

### タイムアウト保護された結合試験・ベンチ回帰（REPAIR-5・REPAIR-8）

数値・設定箇所は上記「推奨タイムアウト値」節に集約している。本節はその判定基準・実施記録の詳細を扱う。

REPAIR-7 の 5 段階ゲートのうち、(3) タイムアウト保護された結合試験は TASK-86.2（#36）で CI 導入済み。(4) ベンチ回帰チェック（15% 超の悪化で fail）の比較の仕組みは TASK-86.3（#37）で導入したが、計測対象がプレースホルダ（固定値）のため現時点では実装の性能悪化を検出しない（実測ベンチ・基準値への置き換えは TASK-113〔#269〕・TASK-88〔#227〕）。`bench-regression` の成功を「性能回帰がない」根拠として扱わない。ACK・plugin RPC・子プロセスなど相手の応答を待つ処理に、タイムアウトなしで無期限に待ち得る経路を追加する差分は P0（REPAIR-5）

(3) の内容:

- 対象: Cargo の integration test target（各 crate の `tests/*.rs`。lib 内 unit test は rust-ci / rust-ci-default-features が担うため対象外）
- 実行コマンド: `make test-integration`（`cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server`。integration test target が 0 件の場合は notice を出して成功終了する）
- Linux のみの追加実行: `integration-test` ジョブは既定の結合試験の後に `unshare_isolation` を `-- --ignored` 付きで実行する（Linux 限定の 3 ステップ。詳細は下記「実機前提テスト」節。#1159）
- 判定基準: CI（ci.yml の `integration-test` ジョブ。3 OS matrix）は実行ステップ 10 分・ジョブ全体 30 分の timeout-minutes でハングを検出して fail させる。テスト 1 件ごとの推奨タイムアウト値（PoC-8 実測に基づく 5〜10 秒のレンジ）は `integration-test` ジョブの env `FANDHE_CONTAINER_TEST_TIMEOUT_SECS: "10"` として TASK-87.1（#40）で設定済み。この値を読む消費側コードの実装状況は上記「推奨タイムアウト値」節を参照する（`crates/io/tests/responsiveness.rs`。Linux / macOS のみ。実装済みを装わない。REPAIR-3）
- TASK-87.2（#41）: ハングプローブ実施済み（REPAIR-5・REPAIR-7）。2026-09-27、main（4469898）に対し `gh workflow run ci.yml --ref main -f hang-probe=true` を実行した（[run 36335480476](https://github.com/Fandhe-AI/fandhe-container/actions/runs/36335480476)）。integration-test の 3 OS すべてで実行ステップが「has timed out after 10 minutes」で fail し、ジョブ全体は約 10〜11 分で終了した（ジョブの timeout-minutes 30 分に達する前に詰まらず fail）。`main` への `workflow_dispatch` は `push`（main）の通常 CI と同一 concurrency グループ（`cancel-in-progress: true`）になり互いを cancel し合うため、再実行は並列自動マージ中を避け、衝突しない時間帯または ref で行う
- ハングプローブ: `gh workflow run ci.yml --ref <branch> -f hang-probe=true` で起動する。リポ外の使い捨て crate に仕込んだハングするテストを実行し、実行ステップの timeout で 3 OS とも fail することを実証するための手動トリガー（PR・push イベントでは動かない）
- integration test target の追加・変更は各機能タスクが担当する。追加・変更する差分は、実行ステップの `timeout-minutes` 内で完走することを PR 本文で確認しているか

(4) の内容: `.github/workflows/ci.yml` の `bench-regression` ジョブ（ubuntu-latest 単独。3 OS matrix にはしない。理由は ci.yml のジョブコメントおよび `.claude/rules/ci.md` を参照）で比較の仕組みを導入済み（TASK-86.3）。現時点では計測対象がプレースホルダのため性能回帰を検出しない。判定基準:

- ベンチ実行結果（`benches/baseline.json` と同スキーマの JSON）と基準値を `scripts/check-bench-regression.sh` で比較し、metric ごとに `direction`（`higher_is_better` / `lower_is_better`）に応じた向きで悪化率を判定する
- 15% **超**の悪化を回帰として fail させる（ちょうど 15.0% の悪化は合格）。終了コードは `0`（合格）/ `1`（回帰検出）/ `2`（入力エラー。引数・ファイル・スキーマ不正等）の 3 値
- 基準値にある metric が結果に無い、または結果にしかない metric がある場合も入力エラー（`2`）として fail する（基準値の無いベンチを素通りさせない）
- 現時点では `benches/benches/regression_placeholder.rs`（決定的な固定値を返す stub）と `benches/baseline.json`（`placeholder: true` の暫定値）で動作確認する段階にある。実測を伴う本物のベンチと基準値への置き換えはそれぞれ TASK-113・TASK-88 で行う
- `benches/baseline.json` の値を回帰が隠れる方向へ書き換える差分、`scripts/check-bench-regression.sh` の閾値（`THRESHOLD_PERCENT`）を変える差分、比較対象から metric を外す差分、`benches/metrics.json` の `direction` を変える・metric を削除する差分は、TASK-88 の校正記録が無い限り「回帰検出の後退」（P0）として扱う

### 実機前提テスト

- root 権限・KVM・GPU・特定カーネル版数（Landlock ABI 等）・WSL2 を要するテストは、GitHub ホステッド runner で実行できないため既定のテスト集合から明示的に分離されているか確認する。分離の仕組み・実行コマンドは該当タスクで決め、本書に追記する
- 分離したテストに理由（必要な権限・環境）とビヘイビア ID が記され、実機での実行結果が PR に記録されているか確認する
- 既定のテスト集合で動くはずのテストを、CI 通過のために実機前提テストへ移す差分は P0
- `crash_safety`（IO-3・TASK-18.3.1）は root・KVM・GPU を要さず SIGKILL の対象も自身が起動した子プロセスのみのため、分離せず既定 CI 集合（`integration-test`）に含める。カーネル依存の永続化対応可否は skip ではなくテスト内の分岐で検証する
- `unshare_isolation`（CORE-1・SEC-5・TASK-27.2。`crates/core/tests/unshare_isolation.rs`、`harness = false`）: namespace 分離（PID / mount / UTS / IPC / user）と、分離後の子が PID 1 で `/proc` にホストのプロセスが見えないことを検証する実機前提テスト。root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）が必要なため `#[ignore]` 相当（`harness = false` のため `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない。CI の `--all-features` でも実行されない）で既定のテスト集合（`make test`・`make test-integration`）から分離している。実行は `cargo test -p fandhe-container-core --test unshare_isolation -- --ignored`。CI（#1159）では `integration-test` ジョブ（ubuntu-latest のみ）が `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` の後、非 root のまま同コマンドを実行し、成功行 `unshare_isolation: full isolation verified (root=false)` をログで照合して fail-closed にしている（rootless 経路を検証。`RootfulHostRoot` 経路は CI で未検証）。必要環境は Linux で非特権 user namespace が使えること（または root）。実行時は namespace 作成の拒否も失敗として扱い、検証せずに成功する分岐は持たない。実機での実行結果を PR に記録する
- `pivot_root_isolation`（CORE-1・TASK-27.3。`crates/core/tests/pivot_root_isolation.rs`、`harness = false`）: `prepare_rootfs`（自己 bind と rootfs 配下への `/proc` マウント）と `pivot_root`（rootfs 切替と旧 root の切り離し）の後、分離された子（新しい PID namespace の PID 1）から見える `/` が rootfs の内容のみで、ホスト側パスが不可視・mountinfo が `/` と `/proc` のみ・`/proc` にホストのプロセスが見えず・cwd が `/` であることを具体値で検証する実機前提テスト。root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）が必要で、GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない（`make test`・`make test-integration` の既定集合では実行されない）。実行は `cargo test -p fandhe-container-core --test pivot_root_isolation -- --ignored`。実行時は namespace 作成の拒否も失敗として扱い、検証せずに成功する分岐は持たない。root（sudo）での実行は root 権限コマンドのため明示指示のもとで行い、実機での実行結果を PR に記録する
- `namespace_isolation`（CORE-1・TASK-28.1。`crates/core/tests/namespace_isolation.rs`、`harness = false`）: 分離後のコンテナ（新しい PID namespace の PID 1・pivot 済み rootfs）から、ホストのプロセスが見えないこと・hostname が独自であること・rootfs が独自であること・namespace 識別子（pid / mnt / uts / ipc）がホストと異なることを具体値で検証し、終了後にホスト側の hostname・namespace・ファイルシステムが無傷であることも照合する実機前提テスト。必要環境は Linux で root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）。GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない（`make test`・`make test-integration` の既定集合では実行されない）。実行は `cargo test -p fandhe-container-core --test namespace_isolation -- --ignored`。成功行は `namespace_isolation: unshare isolation verified (root=<bool>)`。CI の `integration-test` ジョブには現状未組み込み。実行時は namespace 作成の拒否も失敗として扱い、検証せずに成功する分岐は持たない。「コンテナ 0 個時点のデーモンレス確認」は #146（TASK-28.2）で同ファイルへ追加予定で未実装。root（sudo）での実行は root 権限コマンドのため明示指示のもとで行い、実機での実行結果を PR に記録する
- `fork_exec_isolation`（CORE-1・TASK-27.4.1。`crates/core/tests/fork_exec_isolation.rs`、`harness = false`）: `spawn_container`（fork）と `exec_entrypoint`（`close_range`・`SIGPIPE` 復元・`execve`）を、分離済みの親から実行し、制限ステージ（capability 削減・seccomp・Landlock。#832。no_new_privs は #833 で固定ステージ実装済みだが単独では証跡にしない）の適用証跡が無い間は exec を拒否するため、シナリオ `ok`・`missing`・`not-executable` が `Exited(126)` かつ stderr に `PERMISSION_DENIED` になることを具体値で検証する実機前提テスト（分離・fork・exec 前段の到達と fail-closed の確認）。加えて `spawn_container_with_stages`（#832・TASK-27.4.2）を実際の子プロセスで検証する: `stages-order`（逆順登録の 2 段フック〔cgroup 参加・Landlock〕が子の pivot 後に固定順で実行され、組み込みの capability 削減〔#173・TASK-37.2〕と NO_NEW_PRIVS ステージ〔#833・TASK-27.4.3〕が cgroup 参加の後・Landlock の前に実際に適用されたことを各フック時点の `NoNewPrivs` 値で照合し、フック成功後も exec は `Exited(126)`・`PERMISSION_DENIED`）と `stage-fail`（途中の段の失敗で後続段・exec に進まず `Exited(125)`・stderr に失敗した段 `at Landlock`）。プローブの終了コード 42（成功経路）と不在時 127（stderr に `NOT_FOUND`）の検証は、制限ステージ実装後の課題で、その時点でシナリオの期待値を戻す。プローブの ELF は分離前にホスト上で 42 を返すことのみ自己検証する。`unshare(CLONE_NEWPID)` 後の最初の子だけが PID 1 になるため、各シナリオは自身を `--scenario` で再起動した別プロセスで実行する。必要環境・分離の理由は `pivot_root_isolation` と同じ（root もしくは非特権 user namespace を許可するホスト。`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test fork_exec_isolation -- --ignored`。CI の `integration-test` ジョブには未組み込み（組み込みは別 PR）。実行時は namespace 作成の拒否も失敗として扱い、検証せずに成功する分岐は持たない。root（sudo）での実行は root 権限コマンドのため明示指示のもとで行い、実機での実行結果を PR に記録する
- `default_devices`（CORE-1・TASK-27.6。`crates/core/tests/default_devices.rs`、`harness = false`）: `create_default_devices`（rootfs の `dev` 直下への基本デバイスノード 6 種〔null・zero・full・random・urandom・tty〕の `mknodat`）を検証する実機前提テスト。root では 6 種が OCI default devices と同じ major/minor・文字デバイス・モード 0666 で作成され、再実行で既存ノードを上書きせず `AlreadyPresent` になることを具体値で照合する。非 root（非特権 user namespace）では `mknod(2)` が `EPERM` になるため `PermissionDenied`・段 `CreateDevices` で fail-closed することを照合する。root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない（`make test`・`make test-integration` の既定集合では実行されない。CI での実行はしていない）。実行は `cargo test -p fandhe-container-core --test default_devices -- --ignored`。root（sudo）での実行は root 権限コマンドのため明示指示のもとで行い、実機での実行結果を PR に記録する
- `cgroup_delegation`（CORE-3・TASK-32.1。`crates/core/tests/cgroup_delegation.rs`、通常の libtest harness）: `DelegatedCgroup::detect`（委譲 cgroup v2 の検出）・`prepare`（コンテナ用子 cgroup の作成と自プロセスの退避リーフへの移動・退避検証）・`enable_controllers`（退避済み証明つきの `memory`・`cpu` 有効化）を実 cgroup の状態で具体値照合する実機前提テスト。非特権ユーザーに委譲された cgroup v2 サブツリー（systemd user セッションで `memory`・`cpu` が委譲されていること）が必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合（`make test`・`make test-integration`）から分離している（CI 通過のための弱体化ではない。CI での実行はしていない）。親 cgroup に他プロセスがいると `prepare` は他者を動かさず失敗するため、`cargo` を経由せずビルド済みバイナリを直接実行する: `cargo test -p fandhe-container-core --test cgroup_delegation --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する（root 不要）。実機での実行結果を PR に記録する
- `cgroup_memory`（CORE-3・TASK-32.2。`crates/core/tests/cgroup_memory.rs`、通常の libtest harness）: `ContainerCgroup::set_memory_limits` が子 cgroup の `memory.max`（64 MiB）と `memory.swap.max`（0）へ正規形を書き、実 cgroup のファイル内容 `67108864` / `0` と戻り値の実効値が具体値で一致すること、範囲外の値（`i64::MAX` 超の `Bytes`。文字列形式の `-1`・`64MB` は単体テストで拒否を検証）が書き込み前に `InvalidArgument` で拒否されることを検証する実機前提テスト。必要環境は `cgroup_delegation` と同じ（非特権ユーザーに委譲された cgroup v2 サブツリーで `memory` が委譲され、`memory.swap.max` が存在すること。swap accounting 無効のホストでは `FailedPrecondition` で失敗する。root 不要）で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離している（CI 通過のための弱体化ではない。CI での実行はしていない）。実行は `cargo test -p fandhe-container-core --test cgroup_memory --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。実機での実行結果を PR に記録する
- `cgroup_cpu_max`（CORE-3・TASK-32.3・#160。`crates/core/tests/cgroup_cpu_max.rs`、通常の libtest harness）: 委譲 cgroup 上でコンテナ用子 cgroup を作り `cpu` を有効化したうえで、`ContainerCgroup::set_cpu_max` が書いた `cpu.max` を実ファイルの内容（`50000 100000`・`max 100000`）で具体値照合し、不正値が `InvalidArgument` で拒否されファイルが変化しないことを確認する実機前提テスト。必要環境は `cgroup_delegation` と同じ（`cpu` が委譲された cgroup v2 サブツリー。root 不要）で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離している（CI 通過のための弱体化ではない。CI での実行はしていない）。実行は `cargo test -p fandhe-container-core --test cgroup_cpu_max --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。実機での実行結果を PR に記録する
- `cgroup_join`（CORE-3・TASK-32.4・#161。`crates/core/tests/cgroup_join.rs`、`harness = false`）: 委譲 cgroup 上でコンテナ用子 cgroup を作り、`ContainerCgroup::join_hook` を `spawn_container_with_stages` の `CgroupJoin` 段へ登録して fork した実プロセスについて、親から見た PID が子 cgroup の `cgroup.procs` に含まれること、観測点（Landlock 段）の時点で子の `/proc/self/cgroup` が既に子 cgroup（`0::<委譲パス>/fc-<id>`）を指すこと（参加が後続段より前）、exec が `Exited(126)` で拒否されることを具体値で照合する実機前提テスト。必要環境は非特権ユーザーに委譲された cgroup v2 サブツリーと、root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）で、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない。CI 未組み込み）。実行は `cargo test -p fandhe-container-core --test cgroup_join --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。実機での実行結果を PR に記録する
- `cgroup_delete`（CORE-3・OCI-6・TASK-30.3。`crates/core/tests/cgroup_delete.rs`、通常の libtest harness）: 実 `DelegatedCgroup`（`ContainerCgroupRemover` の本番実装）と実 `FileStateStore` を `oci_runtime::delete` へ渡し、状態記録に委譲スコープを記録して `state.json` の `cgroupScope`・`cgroupInstance` を照合したうえで、delete の後にコンテナ用子 cgroup（`<委譲パス>/fc-<id>@<instance>`）と `state.json`・`<id>/` が実ファイルシステム上から消えていること、2 回目の delete が `NotFound` になることを具体値で照合する実機前提テスト。必要環境は `cgroup_delegation` と同じ（非特権ユーザーに委譲された cgroup v2 サブツリー。root 不要）で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離している（CI 通過のための弱体化ではない。CI での実行はしていない。cgroup 削除の呼び出し結線は既定のテスト集合の `oci_delete.rs` が記録用 fake で照合する）。実行は `cargo test -p fandhe-container-core --test cgroup_delete --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。実機での実行結果を PR に記録する
- `cgroups`（CORE-3・TASK-32.5・#162。`crates/core/tests/cgroups.rs`、`harness = false`）: 同一の子 cgroup に `memory.max`（64 MiB）・`memory.swap.max`（0）・`cpu.max`（`50000 100000`）を設定し、`ContainerCgroup::join_hook` を `spawn_container_with_stages` の `CgroupJoin` 段へ登録して fork した実プロセスについて、親から見た子 cgroup の各ファイル内容（`67108864` / `0` / `50000 100000`）・`cgroup.procs` への PID 参加・子の `/proc/self/cgroup`（`0::<委譲パス>/fc-<id>`）・exec が `Exited(126)` で拒否されること・後始末で子 cgroup が消えることを具体値で照合する実機前提テスト（観測点は `CgroupJoin` 段へ登録するクロージャで、Landlock 段には依存しない）。必要環境は非特権ユーザーに委譲された cgroup v2 サブツリー（`memory`・`cpu` 委譲、swap accounting 有効）と、root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境。root 必須ではない）で、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない。CI 未組み込み）。実行は `cargo test -p fandhe-container-core --test cgroups --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。`set_memory_limits` / `set_cpu_max` の書き込み値の照合は通常ファイル上のユニットテスト（`core3_task32_5_*`）として既定のテスト集合（`make test`）で動く。実機での実行結果を PR に記録する
- `cgroups_regression`（CORE-3・TASK-36.1・#169。`crates/core/tests/cgroups_regression.rs`、`harness = false`）: 委譲 cgroup v2 上で「子 cgroup 作成 → 自プロセス退避 → controller 有効化」の順序（各段階の `cgroup.procs`・`/proc/self/cgroup`・`cgroup.subtree_control` と、退避前の `+memory` が EBUSY で失敗する負の対照）と、`memory.max=64M`・`memory.swap.max=0` の下で `CgroupJoin` 段直後に 300 MiB を確保した子が `Signaled(9)`（シェル慣例の 137）で終了し `memory.events` の `oom_kill` が 1 以上になることを具体値で照合する実機前提テスト。必要環境は `cgroups` と同じ（委譲 cgroup v2・swap accounting 有効・非特権 user namespace 可または root）に加え、実行プロセスの `oom_score_adj` が -1000 でないことで、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 未組み込み）。実行は `cargo test -p fandhe-container-core --test cgroups_regression --no-run` の後、`systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored`。実測レポートの雛形は `docs/design/measurements/cgroups-v2-regression.md`（記入と妥当性判断は人間担当・TASK-36）
- `cgroups_release_agent`（SEC-6・CORE-4・TASK-35・#167。`crates/core/tests/cgroups_release_agent.rs`、通常の libtest harness）: cgroups v2 専用実装で `release_agent` 悪用（脱出クラス 2・CVE-2022-0492）が成立しないことの確認。既定のテスト集合（`make test`）では、`crates/core/src` のコード行が `release_agent` / `notify_on_release` を参照しないことの静的監査（3 OS）と、Linux 実ホストの確認（`/sys/fs/cgroup` が cgroup2 ならルート・自 cgroup に当該ファイルが無いこと、そうでなければ `DelegatedCgroup::detect` が構造化エラーで拒否すること。ホスト状態に応じたテスト内分岐で、どちらも必ず assert する）が走る。実機前提部分は `#[ignore]` の 1 件で、委譲 cgroup 上の親・退避リーフ・コンテナ用子 cgroup に当該ファイルが無く、作成も拒否されることを照合する。非特権ユーザーに委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できないため分離している（CI 通過のための弱体化ではない。CI での実行はしていない）。`prepare` が自プロセスを移動するため `--include-ignored` は非対応。実行は `cargo test -p fandhe-container-core --test cgroups_release_agent --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する（root 不要）。実機での実行結果を PR に記録する
- `cgroups_oom`（CORE-3・TASK-33.1・#164。`crates/core/tests/cgroups_oom.rs`、`harness = false`）: `memory.max`（64 MiB）・`memory.swap.max`（0）を設定した子 cgroup に `join_hook` で参加したプロセスが 64 MiB 超を確保して OOM Kill されることについて、終了状態 `Signaled(9)`（シェル慣習 137）と、子 cgroup の `memory.events` の `oom` / `oom_kill` が起動前 0・終了後 1 であること、設定値 `67108864` / `0` を具体値で照合する実機前提テスト。必要環境は非特権ユーザーに委譲された cgroup v2 サブツリー（`memory` 委譲、swap accounting 有効）と、root もしくは非特権 user namespace を許可するホストで、`oom_score_adj` が -1000 でないこと。`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない。CI 未組み込み）。実行は `cargo test -p fandhe-container-core --test cgroups_oom --no-run` の後、出力された実行ファイルを `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` で実行する。実行ファイルのパスは `cargo test -p fandhe-container-core --test cgroups_oom --no-run 2>&1 | grep -o 'target/[^)]*cgroups_oom-[0-9a-f]*'` で求める。非特権ローカルでの試行結果は [docs/design/measurements/cgroups-oom-local.md](docs/design/measurements/cgroups-oom-local.md)（TASK-33.2・#165。AppArmor の userns 制限で isolate 失敗、root または sysctl 緩和での合格確認は未実施）
- `rootless_id_map`（CORE-6・SEC-5・TASK-40.1。`crates/core/tests/rootless_id_map.rs`、`harness = false`）: 新しい user namespace の子 pid に `rootless::apply_id_maps`（`Direct`）で UID/GID 写像を設定し、`/proc/<pid>/uid_map` の読み戻しと、コンテナ内 root が親から見て非特権 UID（≠0）に写ることを検証する実機前提テスト。非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）が必要なため、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test rootless_id_map -- --ignored`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` を併せて指定すると `newuidmap` / `newgidmap` 経由の範囲写像も検証する（`uidmap` パッケージと `/etc/subuid`・`/etc/subgid` の自ユーザー行が必要。opt-in 時に前提が無ければ失敗とする）。root で実行した場合はホスト root への写像が SEC-5 で拒否されることを照合する。CI の `integration-test` ジョブへの組み込みは未実施（別 PR）。実機での実行結果を PR に記録する
- `landlock` の ABI 6+ 前提テスト `core5_detect_requires_abi6_on_real_host`（CORE-5・TASK-39.1。`crates/core/src/landlock.rs` の `#[ignore]` テスト）: 実機の Landlock ABI が 6 以上であることを検証する実機前提テスト。GitHub ホステッド runner は ABI 6 未満の可能性が高く保証できないため `#[ignore]` で既定のテスト集合から分離している（CI 通過のための弱体化ではない。既定集合では実カーネルの結果と `detect_landlock_abi` の整合を照合する `core5_detect_matches_raw_probe` が走る）。必要環境は Linux 6.12+ で Landlock が LSM として有効なホスト（root 不要）。実行は `cargo test -p fandhe-container-core --lib landlock -- --ignored`（公開 API の結合試験 `crates/core/tests/landlock_detect.rs` の `core5_detect_succeeds_on_abi6_host` も `--test landlock_detect -- --ignored` で同条件）。実機での実行結果（検出 ABI 値）を PR に記録する
- `landlock_path_rules` の ABI 6+ 前提テスト `core5_path_rules_on_abi6_host`（CORE-5・TASK-39.2・#182。`crates/core/tests/landlock_path_rules.rs` の `#[ignore]` テスト）: 検出（`detect_landlock_abi`）の成功を必須としたうえで、公開 API のルール生成（`path_rules_from_config` が root・mount ごとに生成するパス・由来・権利ビットの具体値、`build_path_rules` による同一 destination と後の親マウントに隠れた子マウントの除外と実行権の shadowed 記録、書き込み制限が祖先ルールで無効になる構成の `InvalidArgument` での拒否）を必ず照合する実機前提テスト。GitHub ホステッド runner は Landlock ABI 6 以上を保証できないため `#[ignore]` で既定のテスト集合から分離している（CI 通過のための弱体化ではない。既定集合では同ファイルの 3 テストが、検出が `Ok` のカーネルでは同じルールを、`Err` のカーネルでは構造化された拒否〔コード・理由・文字列表現〕を照合する形で走り、検証せずに成功する分岐は持たない）。必要環境は Linux 6.12+ で Landlock が LSM として有効なホスト（root 不要）。実行は `cargo test -p fandhe-container-core --test landlock_path_rules -- --ignored`。実機での実行結果を PR に記録する
- `landlock` の許可外パス遮断テスト（CORE-5・TASK-39.5・#185。`crates/core/tests/landlock.rs`、`harness = false`）: 1 つの ruleset（root は READ のみ・`allowed/` のみ `rw` mount）を本番のステージ関数経由で使い捨ての子へ適用し、許可パスの操作成功と許可外パスの書き込み系操作の `EACCES`、存在しないルールパスでの適用失敗（プローブ未実行）を具体値で照合する（拒否 5 件に対する監査レコード 5 件・パス一致も照合。SEC-4・TASK-41.3・#194）。既定の `cargo test` では、検出が `Ok` のカーネルならフル照合、`Err` のカーネル（ABI 6 未満等）では fail-closed（ruleset 未生成・適用せず・プローブ未実行）を照合し、検証せずに成功する分岐は持たない。`-- --ignored` 指定時は検出失敗を失敗として扱いフル照合を必須にする実機前提部分で、GitHub ホステッド runner は Landlock ABI 6 以上を保証できないため既定の CI 経路では必須化していない（CI 通過のための弱体化ではない）。必要環境は Linux 6.12+ で Landlock ABI 6+ が LSM として有効なホスト（root 不要）。実行は `cargo test -p fandhe-container-core --test landlock -- --ignored`。実機での実行結果（検出 ABI 値）を PR に記録する
- `rootless_launch`（CORE-6・SEC-5・TASK-40.2。`crates/core/tests/rootless_launch.rs`、`harness = false`）: 非 root で `exec::plan_rootless_subordinate` → `isolate_rootless_subordinate`（fork した mapper が親 pid の UID/GID 写像を書く）→ `spawn_container` を通し、自プロセスの `uid_map` の読み戻しと、子が `Exited(126)`・stderr に `PERMISSION_DENIED`（制限ステージ未実装のため exec だけが拒否される。setup 失敗の 125 ではなく、user namespace・写像・`pivot_root` がホスト root なしで成功し exec 段まで到達したことの証跡）になることを検証する実機前提テスト。非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）が必要なため、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test rootless_launch -- --ignored`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` を併せて指定すると `newuidmap` / `newgidmap` 経由の範囲写像（extent 2 件以上）も検証する（`uidmap` パッケージと `/etc/subuid`・`/etc/subgid` の自ユーザー行が必要。opt-in 時に前提が無ければ失敗とする）。root で実行した場合はホスト root 起動が SEC-5 で拒否されることを照合する。CI の `integration-test` ジョブへの組み込みは未実施（別 PR）。実機での実行結果を PR に記録する
- `rootless_file_owner`（CORE-6・SEC-5・TASK-40.3。`crates/core/tests/rootless_file_owner.rs`、`harness = false`）: 非 root で `plan_rootless_subordinate` → `isolate_rootless_subordinate` 後のコンテナ内 uid 0 のプロセスがファイルを作成し、分離されていない外側のディスパッチャがホスト視点の `stat` で所有者が写像先の非特権 UID（呼び出しユーザーの euid・egid。≠ 0）であることを具体値で検証する実機前提テスト（制限ステージ未実装の間は exec でファイルを作れないため分離後プロセスで作成する。TASK-38・TASK-39 以降にエントリポイント内作成へ移せる）。非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等がない環境）が必要なため、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test rootless_file_owner -- --ignored`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` を併せて指定すると範囲写像（ns 内 1 → subuid 範囲先頭）も検証する（`uidmap` パッケージと `/etc/subuid`・`/etc/subgid` の自ユーザー行が必要。opt-in 時に前提が無ければ失敗とする）。root で実行した場合はホスト root への写像が SEC-5 で拒否されることを照合する。CI の `integration-test` ジョブへの組み込みは未実施（別 PR）。実機での実行結果を PR に記録する
- `rootless`（CORE-6・SEC-5・MS-2・TASK-40.4。`crates/core/tests/rootless.rs`、`harness = false`）: 非 root で公開 API の `oci_runtime::create` → `start` → `kill` を通し、起動した代役 init（`isolate_rootless_subordinate` を通った中間プロセス。制限ステージ未適用の間は実エントリポイントの exec が拒否されるため）を、ホスト視点の `/proc/<pid>/uid_map`・`gid_map`（`0 <euid> 1`）・`status`（実 ID が euid・egid で 0 でない）と、状態・revision・kill 後に回収済みハンドルへ再送しないこと（`FailedPrecondition`）・kill 直後の delete（CORE-2・TASK-30.2・#152）が Running・pid ありとして `FailedPrecondition`（`container is still running`）で拒否され状態・revision が残ること・観測記録（create・start が成功 1 件、kill が成功 1 件・失敗 1 件、delete が失敗 1 件）で具体値検証する実機前提テスト。停止後の delete の成功（本テストでは状態を書き換えず、状態を直接作る `oci_lifecycle.rs`・`oci_delete.rs` が照合する）・Running → Stopped 遷移と SIGTERM 配送（supervisor・TASK-157）・実エントリポイントの exec（TASK-38・TASK-39 以降）は未検証。非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`〔Ubuntu 24.04 の既定〕・`user.max_user_namespaces=0`・Docker 既定 seccomp の開発コンテナ内では `PermissionDenied` 等で失敗する。緩和は root 権限コマンドで明示指示が要る）が必要なため、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test rootless -- --ignored`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` を併せて指定すると範囲写像（`newuidmap` / `newgidmap`）も検証する（`uidmap` パッケージと `/etc/subuid`・`/etc/subgid` の自ユーザー行が必要。opt-in 時に前提が無ければ失敗とする）。root で実行した場合はホスト root への写像が SEC-5 で拒否されることを照合する。既知課題の詳細はテストファイル冒頭の `//!` を参照。CI の `integration-test` ジョブへの組み込みは未実施（別 PR）。実機での実行結果を PR に記録する
- `rootless_uid_mapping`（CORE-6・SEC-5・ESC-09・MS-2・TASK-44。`crates/core/tests/rootless_uid_mapping.rs`、`harness = false`）: 非 root で分離した新 PID namespace の PID 1（コンテナ。制限ステージ未適用の間は exec が拒否されるためテストバイナリ自身が代役）が `MountIsolation::establish` → `prepare_rootfs` → `pivot_root` 後の rootfs 直下へコンテナ内 root としてファイルを作り、分離されていないディスパッチャがホスト視点の `stat` で所有者が写像先の非特権 UID・GID（≠ 0）であることを具体値で検証する ESC-09 相当の実機前提テスト。`rootless_file_owner` が pivot 前のホスト上ディレクトリで作成するのに対し、本テストは pivot 済みコンテナ rootfs 内での作成を見る。非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`・`user.max_user_namespaces=0`・Docker 既定 seccomp の開発コンテナ内では `PermissionDenied` 等で失敗する。緩和は root 権限コマンドで明示指示が要る）が必要なため、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。実行は `cargo test -p fandhe-container-core --test rootless_uid_mapping -- --ignored`。`FANDHE_CONTAINER_TEST_ID_HELPER=1` を併せて指定すると範囲写像（ns 内 1 → subuid 範囲先頭も確認）も検証する（`uidmap` パッケージと `/etc/subuid`・`/etc/subgid` の自ユーザー行が必要。opt-in 時に前提が無ければ失敗とする）。root で実行した場合はホスト root への写像が SEC-5 で拒否されることを照合する。成功時は `RESULT scenario=... verdict=pass` 行を出力する。CI の `integration-test` ジョブへの組み込みは未実施（別 PR）。実機での実行結果の記録は #208（TASK-44.h1）
- `capabilities`（SEC-1・TASK-37.3。`crates/core/tests/capabilities.rs`、`harness = false`）: capability 最小化の結合試験。常に走る部分（3 OS 共通・既定のテスト集合）は、公開 API から組み立てた OCI 既定マスク `0x0000_0000_a804_25fb`（14 個）と、`CAP_SYS_ADMIN` 等の危険な capability の不在、`/proc/<pid>/status` パーサの自己テスト。実機前提部分（`-- --ignored` 指定時のみ）は、`spawn_container_with_stages` が fork した実際のコンテナプロセスを、組み込みの capability 削減・NO_NEW_PRIVS の後・exec の直前（組み込みでない Seccomp 段のフックで親と同期して停止）で、親から `/proc/<pid>/status` を読み、`CapEff`・`CapPrm`・`CapBnd` がマスクと完全一致、`CapInh`・`CapAmb` が 0、危険な capability と未知の番号（41 以上）が 0 であることを具体値で照合する（子自身の値とも一致を確認）。exec は seccomp・Landlock 未実装の間は拒否される（`Exited(126)`・`PERMISSION_DENIED`）ため exec 後の capability は未検証で、TASK-38・TASK-39 以降の課題。必要環境は `fork_exec_isolation` と同じ（root もしくは非特権 user namespace を許可するホスト）で、未指定時は「ignored」を出力して成功終了する実機前提テストの分離であり、CI 通過のための弱体化ではない。実行は `cargo test -p fandhe-container-core --test capabilities -- --ignored`。CI の `integration-test` ジョブには未組み込み（別 PR）。root（sudo）での実行は明示指示のもとで行い、実機での実行結果を PR に記録する
- `seccomp_enforcement`（CORE-5・TASK-38.3・#178。`crates/core/tests/seccomp_enforcement.rs`、`harness = false`）: 本番の seccomp 適用経路（既定 deny フィルタの構築と `prctl(PR_SET_SECCOMP)`）を使い捨ての子プロセス（テストバイナリ自身を `--child` で再実行。単一スレッドが適用の前提）で適用し、適用前の対照（`unshare(0)` 成功）と適用後の遮断（`unshare`・`mount`・`pivot_root`・`umount2` が `EPERM`=1、`Seccomp:` が 2）を具体値で照合する。root・KVM 不要で既定のテスト集合（`make test`・`make test-integration`）で動く実機前提ではないテスト。非 Linux・x86_64 / aarch64 以外は not applicable を出力して成功終了する（OS・アーキ非該当）
- `seccomp`（CORE-5・TASK-38.4・#179。`crates/core/tests/seccomp.rs`、`harness = false`）: 起動したコンテナプロセス（`spawn_container_seccomp_probe` が fork した PID 1・pivot 済み・capability 削減・NO_NEW_PRIVS 済み）の中で、組み込み `Seccomp` 段が載せたフィルタによる禁止 syscall の遮断を、子が書く記録の具体値で照合する実機前提テスト。識別的な検査は `unshare`・`ptrace` が `EPERM`=1（フィルタが無ければ成功・`ESRCH`）と `Seccomp:` が 2、対照として `/proc` の読み出しが成功すること。`mount`・`pivot_root`・`umount2`・`kexec_load` が `EPERM` であることは網羅確認（capability 不足でも `EPERM` になり得る）。`seccomp_enforcement`（使い捨ての子で適用経路を呼ぶ検証）と違い、本物の起動フローと組み込み段を通す。exec は制限証跡が無い間は拒否されるため、プローブ用 API が exec の代わりに終端でプローブを実行する（exec 許可後の検証は TASK-39.4・#184 以降）。必要環境は `capabilities` と同じ（root もしくは非特権 user namespace を許可するホスト）で、`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（CI 通過のための弱体化ではない）。常に走る部分（プローブ対象が禁止 syscall 一覧に含まれること・記録の解析の自己テスト）は既定のテスト集合で動く。実行は `cargo test -p fandhe-container-core --test seccomp -- --ignored`。CI の `integration-test` ジョブには未組み込み（別 PR）。実機での実行結果を PR に記録する
- `escape_suite`（SEC-2・SEC-4・SEC-5・CORE-5・TASK-42.1〜42.6・#199〜#204・MS-2。`crates/core/tests/escape_suite.rs`、`harness = false`）: PoC-9 の最小攻撃セット ESC-01〜ESC-10（ホスト FS 書き込み・ホスト PID ns・mount・release_agent・`/proc/sys`・禁止 syscall・ランタイムバイナリ書き込み・許可外 mount・userns 所有者・Landlock 許可外）を、制限ステージ通過後のコンテナプロセス内で実行し、拒否されることを判定する攻撃テストスイート。必要環境は Linux x86_64 / aarch64 で、root もしくは非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` や Docker 既定 seccomp 下の開発コンテナでは失敗する。緩和は root 権限コマンドのため明示指示が要る）。ESC-01・ESC-07・ESC-10（Landlock を使うケース）は Landlock ABI 6+（Linux 6.12+）も要る。`-- --ignored` 指定時のみ実機ケースを実行し、未指定時（`make test`・`make test-integration`・`--all-features`）は常に走る自己テスト（判定ロジック `judge`・記録パーサ）だけを実行して「ignored」を出力し成功終了する（CI 通過のための弱体化ではない）。非 Linux・非対応アーキテクチャでは「not applicable」を出力する。実行は `cargo test -p fandhe-container-core --test escape_suite -- --ignored`（子プロセス待ちは `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` で変更可）。実行時は分離の拒否・事前条件の不成立を含め失敗として扱い、検証せずに成功する分岐は持たない。ESC-09 は非 root 起動でのみ検証でき、root 起動時は `verdict=not-applicable behavior=SEC-5` を出力する（合格扱いしない）。成功時の最終行は `escape_suite: SEC-2 harness verified N of M case(s), ...`。ESC-04・05（`maskedPaths` / `readonlyPaths` 未適用）と ESC-06（`ERRNO` 返却で SIGSYS にならない）は現行実装の実機実行で失敗し得る（期待は弱めない）。監査（SEC-4）は配送経路が未配線のため一部ケースで `Deferred`。CI の `integration-test` ジョブには未組み込み（上記の既知失敗の解消と Landlock ABI 6+ の runner 確保が前提。別 PR）。実機での実行結果は人間担当ツリーで記録し PR に載せる
- `make fio-bench`（TASK-25.1・IO-8）: fio・GNU coreutils の `timeout` が入った Linux 環境が必要（root 権限・`/dev/kvm` は不要）。`make fio-bench-selftest`（`--from-json` モード＋固定 fixture＋fio スタブで完結し、実 fio は使わない）は CI の `bench-regression` ジョブに組み込み済みで既定のテスト集合の一部。`make fio-bench` 自体の実機実行・Docker コンテナ内での fio 実行（runbook は [docs/design/io-fio-bench.md](docs/design/io-fio-bench.md)「Docker ベースラインの計測手順」）・その結果の `make fio-baseline-ratio` への入力は TASK-25.2（#113。人間共同）が担う。`make fio-baseline-ratio`（比率算出そのもの）は fio・Docker を必要としないため既定のテスト集合の一部（`make fio-baseline-ratio-selftest` として CI に組み込み済み）
- 実機での実測・判定が「人間」担当のタスク（`.claude/rules/delegation-impl.md`「着手条件」）を、計測スクリプト準備を超えて Agent が単独で完了扱いにしていないか確認する
- カーネル監査フォールバックの肯定側送信（SEC-4・TASK-41.5.2。`crates/core/tests/audit_kernel_fallback.rs` の `sec4_task41_5_2_real_kernel_accepts_with_cap_audit_write`）は、`CAP_AUDIT_WRITE` を持つ初期 user namespace が必要でホストの監査ログへ 1 件書き込むため `#[ignore]` で分離している。実行コマンドは `cargo test -p fandhe-container-core --test audit_kernel_fallback -- --ignored`（root 等の権限付きで人間が実施し、結果を PR に記録する）。権限が無い環境の否定側テスト（`sec4_task41_5_2_real_kernel_rejects_without_privilege`）は既定のテスト集合で動く
- plugin 信頼性検証の別 UID 所有ファイル拒否（PLUG-11・TASK-122.6。`crates/core/tests/plugin_trust_rejection.rs` の `plug11_task122_6_rejects_symlink_to_other_uid_owned`）: 別の非 root UID 所有の通常ファイルは root の chown なしに作れないため `#[ignore]` で既定集合から分離している実機前提テスト（同一 UID・同一マシンで完結する拒否ケース 3 種は既定集合で実行する）。必要環境は Linux・非 root の実行ユーザー・事前に人間が用意した「別の非 root UID 所有・group/other 書き込み不可」の通常ファイル（実行ユーザーの `$HOME` 配下の 0755 ディレクトリ内に置き `sudo chown nobody <file>` する。`/tmp` 配下は祖先ディレクトリで別理由の拒否になるため不可）。実行は `FANDHE_CONTAINER_TEST_OTHER_UID_PLUGIN=<絶対パス> cargo test -p fandhe-container-core --test plugin_trust_rejection -- --ignored plug11_task122_6_rejects_symlink_to_other_uid_owned`（sudo 経由ではなく非 root で実行する。前提不備は skip せず失敗する）。実機での実行結果を PR に記録する
- UDS 境界の別 UID 所有ディレクトリ拒否（PLUG-12・TASK-123.5。`crates/plugin/tests/uds_security.rs` の `plug12_rejects_other_uid_owned_directory`）: 別の非 root UID 所有のディレクトリは root の chown なしに作れないため `#[ignore]` で既定集合から分離している実機前提テスト（CI 通過のための弱体化ではない。同一 UID で完結する symlink 拒否・stale socket 再 bind・所有者不一致の分岐照合は既定集合で実行する）。必要環境は Linux / macOS・非 root の実行ユーザー・事前に人間が用意した「別の非 root UID 所有・モード 0755・空」のディレクトリ（実行ユーザーの `$HOME` 配下の 0755 ディレクトリ内に作成し `sudo chown nobody <dir>` する）。実行は `FANDHE_CONTAINER_TEST_OTHER_UID_DIR=<絶対パス> cargo test -p fandhe-container-plugin --test uds_security -- --ignored plug12_rejects_other_uid_owned_directory`（sudo 経由ではなく非 root で実行する。前提不備は skip せず失敗する）。実機での実行結果を PR に記録する
- UDS 境界の別 UID 接続拒否（PLUG-12・TASK-124.4。`crates/plugin/tests/peer_auth.rs` の `plug12_rejects_other_uid_connection`・`plug12_connect_rejects_other_uid_listener`）: 別 UID のプロセスは root 権限なしに用意できないため `#[ignore]` で既定集合から分離している実機前提テスト（CI 通過のための弱体化ではない。同一 UID の受理・peer 取得失敗の fail-closed は既定集合で実行する）。必要環境は Linux / macOS・非 root の実行ユーザー・sudo 可能な人間による準備。listener 側は 0700 の配置ディレクトリを越えられる root の connector が必要（非 root の別 UID は connect 前に遮断され peer 検証へ届かない）。人間が「socket パスを第 1 引数に取り、別 UID で接続して受信内容を stdout へ出す」実行ファイルを用意する（例: 中身が `exec sudo -n nc -U "$1" </dev/null` のスクリプト。事前に `sudo -v`。nc のオプションは OS 付属実装で差があり、macOS は未確認の例）。実行は `FANDHE_CONTAINER_TEST_OTHER_UID_CONNECT_CMD=<絶対パス> cargo test -p fandhe-container-plugin --test peer_auth -- --ignored plug12_rejects_other_uid_connection`。client 側は別 UID が listen 中で実行ユーザーから接続できる socket を人間が用意する（例: `sudo sh -c 'umask 000; exec nc -lU <絶対パス>'`）。実行は `FANDHE_CONTAINER_TEST_OTHER_UID_SOCKET=<絶対パス> cargo test -p fandhe-container-plugin --test peer_auth -- --ignored plug12_connect_rejects_other_uid_listener`。いずれも sudo 経由ではなく非 root で cargo を実行し、前提不備は skip せず失敗する。connector は env で渡した実行ファイルをテストが起動するため信頼できるファイルのみ指定する。実機での実行結果を PR に記録する

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
| `unsafe`/FFI | 新規 `unsafe` ごとに次を確認する。(a) 各 crate の `sys` モジュール（`src/sys.rs`・`src/sys/` 配下）にある syscall・ioctl・FFI ラッパーの `unsafe` は事前承認の範囲（[coding-rust.md](https://github.com/Fandhe-AI/fandhe-container/blob/main/.claude/rules/coding-rust.md)・オーナー決定 2026-09-27）で、PR 本文に当該箇所の一覧（ファイル・行）・security-auditor 観点のレビューの実施記録（確認した不変条件と指摘への対応）・事前承認コメント（[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)）へのリンクがそろい、`unsafe fn` を `sys` の外へ公開していないか。いずれかが欠ければ P0。(b) `sys` モジュールの外の `unsafe` は事前承認の範囲外で、PR 本文に当該箇所への個別のユーザー承認の記録（承認した Issue・コメントへのリンクと承認内容の転記等）があるか。無ければ P0。いずれの場合も全ての `unsafe` ブロックに `// SAFETY:` コメント（理由・維持すべき不変条件）があるか | P0 |
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
| テストとビヘイビア ID の対応 | 挙動がビヘイビア ID（例: `IO-2`）に対応づけてテストされ、テスト名またはドキュメントコメントに ID が記されているか。ユニットテストと結合テストが併置され、期待値が具体値で書かれているか。受け入れ基準を機械照合するテストがあるか（REPAIR-12）。新機能追加時に揃えるテストのカテゴリは上記「新機能追加時に更新すべきテスト一覧」節を参照 | P1 |
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
| `ai-review.yml` の同期 PR skip | `ai-review.yml` の codex ジョブの `skip-branch-prefixes: chore/skills-update-,chore/submodule-update-` は、`update-external.yml` が生成する日次同期 PR（上流の取り込みで、指摘があってもその PR では直せない）の AI レビューを skip するためのオーナー判断による受容済みの設定である（2026-09-27 オーナー判断。Fandhe-AI/actions の `ai-review/README.md`「`skip-branch-prefixes` の受容済み残留リスク」〔2026-09-24〕と同じ運用）。ブランチ名接頭辞のみで判定するため push 権限者が gate を回避できる点は受容済みで、この 2 接頭辞の設定そのもの・その追加を指摘しない。前提は write 権限者がオーナー相当のみであること（第三者の write コラボレーターを迎える場合は入力を空に戻す）。skip 対象 PR にも Cursor Bugbot と CI の必須チェックは適用される。一方、この 2 接頭辞以外の追加・`skip-*` 系の条件拡大（actor・ラベル等による skip の新設）・fork PR への拡大は従来どおり「品質ゲートの破壊」として P0 で指摘する | 指摘しない（受容済みの例外。範囲拡大は P0） |
| runner 方針 | public リポジトリのため既定は GitHub ホステッドランナー。self-hosted の使用が許可されるのは `ai-review.yml` の `codex / review` ジョブ（組織承認済み例外）のみで、`codex / preflight`・`codex / post_feedback` を含む他ジョブ・他 workflow は GitHub ホステッドランナーになっているか | P0 |
| permissions | ワークフロー・ジョブの `permissions` が最小権限で明示されているか | P0 |
| secrets の扱い | secrets が `pull_request` イベントのログへ出力されていないか | P0 |
| `ci.yml` の発火条件 | `ci.yml` は `workflow_dispatch`・`pull_request`・`push`（main）で稼働中（TASK-86.1・REPAIR-7）。`on:` から `pull_request` / `push` を外す変更・`pull_request_target` への変更は P1 で指摘する | P1 |
| `ci.yml` への変更 | `ci.yml` を変更する差分では、3 OS matrix（Linux・macOS・Windows）を維持しているか（単独ジョブの `bench-regression`・`aarch64-linux-check` は ubuntu-latest 単独が意図的な例外）、本リポに存在しない `make` ターゲット・`scripts/` を前提にしたジョブが混入していないかを確認する | P1 |
| `release.yml` | `workflow_dispatch` 限定のプレースホルダであり、有効化には公開対象クレート・crates.io 公開方針の確定を要する。現状のプレースホルダ状態自体は指摘しない | 指摘しない（既知の暫定状態） |
| ゲート未導入段階の追記 | REPAIR-7 の 5 段階ゲートのうち (3) タイムアウト保護された結合試験（TASK-86.2）は導入済み。(4) ベンチ回帰チェックの比較の仕組み（TASK-86.3）は導入済みだが、計測がプレースホルダのため現時点では実装の性能悪化を検出しない。残る段階・実測ベンチへの置き換え時は、本書「ビルド・テスト・回帰確認コマンド」節・`.claude/rules/ci.md` の更新を伴っているか | P2 |
