# crate 短縮名と plugin crate 配置

crate の命名規約、18 候補 crate の責務区分、plugin crate を workspace 内外どちらに置くかの論点を記録する。

- ステータス: ドラフト（#9・TASK-1.h1 で最終確定）
- 関連 issue: #7（TASK-1）・#8（TASK-1.1）・#9（TASK-1.h1）
- 対象ビヘイビア: REPAIR-1（検討中）
- 対象マイルストーン: MS-0

## 命名規約

spec で確定済みの前提と、本ドラフトの提案を区別する。

**spec で確定済みの前提**（`05-tasks.md` TASK-1・冒頭、REPAIR-1）:

- **workspace 内 crate のパス形式**: `crates/<短縮名>`
- **crate 名（Cargo.toml）の名前空間**: `fandhe-container-*`。plugin crate も同様に `fandhe-container-plugin-*` で統一する（PLUG-4）
- **CLI バイナリ名**: `fandhe-container` に統一する。plugin バイナリ名は `fandhe-container-plugin-*`（発見対象）とする
- **旧提案の不採用**: `vm-core`・`vm-io` 等の `vm-*` 形式は採用しない（TASK-1）

**本ドラフトの提案**（採否は #9 で判断する）:

- 下表の短縮名（「短縮名（crate 内パス）」列）・crate 名・責務区分は本ドラフトの候補であり、spec で確定した個々の名称ではない

## 候補 crate 一覧

spec の仮称（`05-tasks.md` 冒頭）は core 系 8 個（`io`・`core`・`oci`・`cri`・`platform-macos`・`platform-windows`・`microvm`・`cli`）・plugin 系 5 個（`plugin-cri`・`plugin-macos`・`plugin-windows`・`plugin-microvm`・`plugin-mcp`）であり、実装の境界線（G0〜G12・TASK-n）に基づいて残る 5 crate（`supervisor`・`gpu`・`net`・`plugin-api`・`stack`）を本ドラフトが追加候補として列挙し、以下の 18 候補とした。PLUG-1（plugin 境界表）・PLUG-4（発見対象）・各グループの成果物パスから、core 系 13・plugin 系 5 の 18 crate を抽出している。

なお「core 系 13・plugin 系 5」は本ドラフトが workspace 上の配置区分として便宜的に付けた分類であり、PLUG-1 の「core／plugin」区分（下表「PLUG-1 区分」列）とは別軸である。`cri`・`platform-macos`・`platform-windows`・`microvm` の 4 crate は、PLUG-1 上は「plugin 境界の外側」（plugin バイナリから呼ばれるバックエンド実装ライブラリ）であり、PLUG-1 上の「core」には区分されない。

| # | 短縮名（crate 内パス） | crate 名（`fandhe-container-*`） | 責務 | グループ・主な TASK | PLUG-1 区分 |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 1 | io | io | I/O 共有層（バッチ write-back・フラッシュバリア・FS 正規化） | G2（TASK-11〜26） | core |
| 2 | core | core | 実行層（namespace・cgroups v2・seccomp/Landlock・rootless・ログ・状態管理） | G3（TASK-27〜50） | core |
| 3 | supervisor | supervisor | コンテナごとの軽量監視プロセス（restart・healthcheck・exec・logs・stats） | G12（TASK-157〜171。TASK-157 が crate 雛形・監視プロセス基本ループ、SUP-1） | core（D-19。PLUG-1 境界表では supervisor は plugin 境界〔PLUG-2〕を経由せず実行層コアの一部と整理されている） |
| 4 | oci | oci | OCI イメージ管理（pull・キャッシュ・`image ls`/`rm`/`tag`） | G4（TASK-51〜55・TASK-183〜184） | core |
| 5 | cri | cri | CRI 実装ライブラリ（Runtime/ImageService・shim v2・streaming） | G4（TASK-56〜63） | plugin 境界の外側（`cri` は CRI 実装ライブラリ。実行時は `plugin-cri` バイナリが別プロセスとして動かす。TASK-114） |
| 6 | platform-macos | platform-macos | macOS Virtualization.framework 経由の VM 起動・VirtioFS | G5（TASK-64〜66） | plugin 境界の外側（`platform-macos` はバックエンド実装ライブラリ。実行時は `plugin-macos` バイナリが別プロセスとして動かす。TASK-115） |
| 7 | platform-windows | platform-windows | Windows WSL2 経由（virtiofs opt-in）の実装 | G5（TASK-67〜72） | plugin 境界の外側（`platform-windows` はバックエンド実装ライブラリ。実行時は `plugin-windows` バイナリが別プロセスとして動かす。TASK-116） |
| 8 | microvm | microvm | KVM 直接制御・最小 virtio デバイスモデル（Linux オプション） | G5（TASK-74〜78） | plugin 境界の外側（`microvm` はバックエンド実装ライブラリ。実行時は `plugin-microvm` バイナリが別プロセスとして動かす。TASK-117） |
| 9 | cli | cli | 統一 CLI・基本コマンド（create/start/stop/delete/list/logs/ps）、観測性 | G6（TASK-79〜98 の一部。crate の中核成果物は TASK-79〔基本コマンド〕・TASK-95〔エラー形式〕。REPAIR・ERR 系タスクを含む） | core |
| 10 | plugin-api | plugin-api | plugin 境界機構（UDS・長さ接頭辞フレーム・gRPC・常駐/都度起動・信頼性検証） | G8（TASK-107 が crate 本体、TASK-108 が gRPC〔tonic〕境界、TASK-110・TASK-113・TASK-122〜124。plugin 発見・登録〔TASK-109〕の成果物は `crates/core/src/plugin_discovery.rs` であり `plugin-api` ではない） | core・plugin 双方が依存する境界基盤ライブラリ |
| 11 | gpu | gpu | GPU CDI spec 解析・edits 適用・Landlock/seccomp・cgroup device・読み取り専用 rootfs | G9（TASK-126〜135） | core（推奨）〔注 1〕。macOS Venus〔GPU-6〕は対象・実装機構が異なる別枠で、成果物は `plugin-macos` 側に置かれる |
| 12 | net | net | netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開 | G10（TASK-136〜148・TASK-185〜186） | 検討中（ネットワーク設定操作は制御面として PLUG-1 で `NetworkPlugin` が plugin 側に区分される一方、NET-5・NET-9 の DNS ヘルパー・rootless 転送はデータパス判定未確定、`plugin-system.md`） |
| 13 | stack | stack | TOML スキーマ・`depends_on` 起動順・compose.yaml 変換器・`profiles` 絞り込み | G11（TASK-149〜156・TASK-182・TASK-187〜188。TASK-149 が crate 雛形） | core（CLI＋ライブラリ API） |
| 14 | plugin-cri | plugin-cri | CRI サーバー plugin バイナリ（`cri` の実装を別プロセス化） | G8（TASK-114） | plugin |
| 15 | plugin-macos | plugin-macos | macOS バックエンド plugin バイナリ（TASK-115）。macOS Venus（GPU-6、TASK-172〜181）の virtio-gpu デバイスモデル・コンテキスト分配層・venus デコーダも `crates/plugin-macos/src/gpu/` に置く定義になっている | G8（TASK-115）・G-別枠（TASK-172〜181） | plugin |
| 16 | plugin-windows | plugin-windows | Windows バックエンド plugin バイナリ（`platform-windows` の実装を別プロセス化） | G8（TASK-116） | plugin |
| 17 | plugin-microvm | plugin-microvm | microVM 制御 plugin バイナリ（`microvm` の実装を別プロセス化） | G8（TASK-117） | plugin |
| 18 | plugin-mcp | plugin-mcp | MCP サーバー plugin バイナリ（参照実装） | G8（TASK-118、PoC-13） | plugin |

〔注 1〕`gpu` 行の PLUG-1 区分の内訳: `plugin-system.md` の境界表で「core（推奨）」と明記されているのは GPU-1〜4（CDI 適用・OCI hook 実行）のみ。GPU-5・GPU-7・GPU-8（Landlock/seccomp・cgroup device・読み取り専用 rootfs との両立）は境界表での明示判定がなく、`gpu` crate に実装される付随機能として扱っている。GPU-9 は `api-gpu.md` でステータス「検討中」のため確定扱いしない。

## plugin crate の配置論点

plugin crate（#14〜18）は、実行時のバイナリ配置（PLUG-11 の管理ディレクトリ配下）には関わらず、**開発時のソース配置**が未決である。以下 3 案の長所・短所を並べ、#9 で判断すべき問いを列挙する。

なお、spec（`05-tasks.md`）の各タスクの成果物パスは、既に plugin crate を `crates/plugin-cri`・`crates/plugin-macos` 等の `crates/` 配下として書いており、同一リポ内配置を暗黙に前提にしている。これは論点の材料として記録するにとどめ、結論は出さない。

### 案 A: workspace 内の独立 crate として配置

`crates/plugin-cri/`・`crates/plugin-macos/` 等を workspace メンバーとする。

#### 長所

- `[workspace.dependencies]` で共通依存を統一管理し、`=x.y.z` 固定（dependency-policy）を確実に適用できる
- `make ci`（lint・fmt・clippy・test）が全 crate に一括適用され、3 OS CI でも plugin バイナリ全体を統一して検証できる
- PLUG-3（Cargo feature による軽量化）を実装する場合、feature フラグを workspace ルート `Cargo.toml` で一元管理しやすい

#### 短所

- plugin を追加する際、root `Cargo.toml`・`Cargo.lock` が変化する（依存追加・メンバー追加）
- PLUG-4（TASK-109）の判定対象は「core crate のソース sha256 一覧・core バイナリの sha256」である。workspace メンバー追加で root `Cargo.lock` が変わっても core crate 自身のソースは不変だが、依存解決の統一（feature unification 等）により core バイナリの sha256 が変わり得る。判定対象から root `Cargo.toml`/`Cargo.lock` を除外するか、ビルド条件をどう固定するかが論点になる
- plugin バイナリのビルド成功・失敗が core CI に波及しやすい（一つの plugin が compile error を起こすと全体が fail する）

### 案 B1: 同一リポの workspace 外に配置

`[workspace] exclude` または別 Cargo workspace として、同一リポ内・root workspace の外に置く。

#### 長所

- root `Cargo.toml`・`Cargo.lock` が plugin 追加で変化しないため、PLUG-4 の「core 無変更」判定への影響を避けやすい
- plugin のビルド失敗が core CI に波及しない（プロトタイプ段階での active development に有利）
- 同一リポのため、core と plugin にまたがる変更を 1 PR で扱える

#### 短所

- `[workspace.dependencies]` による共通依存の統一管理が及ばず、plugin ごとに依存を `=x.y.z` で個別に固定する手間が増える
- 別 workspace の CI・`make ci`・`cargo deny` を別途用意する必要がある
- PLUG-3（Cargo feature）を実装する場合、feature フラグを plugin ごとに個別管理する

### 案 B2: 別リポジトリに配置

plugin crate を root リポジトリの外（別 GitHub リポジトリ）に置く。

#### 長所

- 案 B1 の長所に加え、plugin ごとの版数・リリースサイクルを core と独立に設定できる
- plugin の開発・レビュー体制を core と分離できる

#### 短所

- 案 B1 の短所（別リポの CI・`make ci`・`cargo deny` の個別整備を含む）に加え、plugin crate が依存する `plugin-api` をバージョン付きで公開・参照する仕組み（レジストリ公開または git 依存）が別途必要になる
- リリースを core・plugin で分ける必要があり、バージョン履歴が分散する

### A・B1 共通の課題: 全 crate の版数管理

案 A（workspace 内）・案 B1（同一リポの workspace 外）はいずれも単一リポジトリ内で全 crate を管理するため、リリース版作成時に全 18 crate の版数・changelog を管理する手間が増える点は共通の課題である（`[workspace.package]` で版数を一元管理すれば個々の `Cargo.toml` への転記は避けられるが、crate ごとの独立リリースサイクルは持てない）。案 B2（別リポジトリ）のみ、plugin ごとに独立した版数・リリースサイクルを持てるためこの課題が緩和される（上記「長所」参照）。

### PoC-13 での計測上の措置の位置づけ

PoC-13（plugin-boundary-mechanism）は、MCP 参照 plugin（Python 製、`fandhe-container-plugin-mcp`）を意図的に Cargo workspace 外（独立スクリプト）に置いた。理由は、workspace メンバーにすると root `Cargo.toml`/`Cargo.lock` が変化し `core-harness` バイナリの再ビルド条件も変わるため、`core-harness` の sha256 判定が「実装上の副作用」で汚染されるのを避けるためである（`plugin-boundary-mechanism/README.md`）。ただし PoC-13 は Rust 製 plugin crate を workspace 内外どちらに置くかの実測根拠を含んでおらず、MCP 参照 plugin が Python 製である点（Cargo ワークスペースの対象にそもそもならない）の影響も評価していない。本リポジトリで Rust plugin crate を案 A・案 B1・案 B2 のいずれに置く場合でも、PLUG-4 の判定対象（core 無変更とは何を指すか）を先に定める必要がある。

また、TASK-102（workspace 構成の最終レビュー、担当: 人間、OSS-6）は Must/Should 中核の実装完了後に予定されており、この時点で本論点を実装の進捗を踏まえて再整理する機会がある。

## その他の論点

### 1. `fandhe-container-plugin-api` の命名衝突

TASK-109（PLUG-4・PLUG-11）の plugin 発見機構は、PLUG-11 が定める管理ディレクトリ（既定。`PATH` 探索は opt-in）に置かれた `fandhe-container-plugin-*` という名前のバイナリを対象にする。`plugin-api` はバイナリを生成しないライブラリ crate であり、管理ディレクトリにも配置されないため、実行時に plugin として誤検出される経路は通常存在しない。ただし次の点が論点として残る。

- crate 名・パッケージ名から plugin 本体と誤認されやすい
- 将来 `plugin-api` に補助バイナリ（開発用ツール等）を足すと、命名規約に一致してしまう
- 発見側で `plugin-api` を除外する規則を持つと、発見ロジックが複雑化する

**改名案**（いずれも問題を確実に解消するものではなく、#9 で採否・案の選定を判断する）: `fandhe-container-plugin-sdk`・`fandhe-container-plugin-proto`・`fandhe-container-pluginapi` など。

### 2. compose 変換器の配置

D-14（`01-brainstorm.md`「設計上の論点」6）は compose.yaml 変換器を「別バイナリ（`fandhe-container-plugin-*` の命名規約に従う plugin、または独立ツール）」とする案を推奨している。一方 TASK-151 は変換器の成果物を `crates/stack/src/compose_convert.rs`（`serde_norway` 依存を想定）と定義しており、D-14 の推奨と食い違っている。この食い違いは spec 側の記述の不整合であるため、#9 で本リポの方針を判断し、spec 側（TASK-151 の成果物パス）の修正が必要と判断した場合はユーザーが spec リポ側で対応する。

### 3. `StateStore` 実装の分散

PLUG-1（`plugin-system.md`）は `StateStore` のトレイト定義・ファイルベース既定実装をいずれも core に置き、別実装は plugin として差し替え可能とする。一方 TASK-31（`crates/core/src/state_store.rs`、OCI-5）と TASK-157（`crates/supervisor/src/state.rs`。同じく OCI-5 の `StateStore` トレイトの実装として記載）で実装が 2 箇所に分かれている。`StateStore` を単一実装に集約するか、コンテナライフサイクル（create/delete）側と監視プロセス側で役割を分けるべきかは spec 側の整合の問題でもあるため、#9 で判断し、必要ならユーザーが spec リポ側で対応する。

### 4. `benches/` の置き場所と workspace メンバー扱い

`benches/` を実際の成果物パスとするタスクは TASK-88（`benches/baseline.json`、ベンチ基準値の初回校正）・TASK-113（`benches/plugin_boundary.rs`、制御面往復レイテンシ回帰ベンチ）である。TASK-112（core／plugin 常駐 RSS 比較の自動計測）の成果物は `crates/plugin-api/tests/rss_comparison.rs` であり `benches/` ではない。`benches/` を workspace メンバー（`[[bench]]` を持つ独立 crate）とするか、各 crate の `benches/` サブディレクトリとするか、root の `benches/` を非メンバーの集約所とするかは TASK-1（REPAIR-1 の一部）で決める設計事項である。

## #9 で確定すべき事項

- [ ] 短縮名 18 件そのものの採否（表の短縮名・crate 名・責務区分）
- [ ] plugin crate を案 A（workspace 内）・案 B1（同一リポの workspace 外）・案 B2（別リポジトリ）のいずれで置くか、またはハイブリッドで置くか
- [ ] PLUG-4 の「core 無変更」判定対象の定義（core ソース sha256・core バイナリ sha256・root `Cargo.lock` のいずれを対象とするか）
- [ ] `fandhe-container-plugin-api` の改名の要否・案の選定（問題が限定的なら改名不要）
- [ ] compose 変換器を D-14 の推奨どおり別バイナリとするか、TASK-151 どおり `crates/stack` 内に置くか（別バイナリとする場合、spec 側の TASK-151 修正が必要かも判断する）
- [ ] `StateStore` 実装の分散を許容するか、単一実装に集約するか（spec 側の整合の要否も含む）
- [ ] `benches/` を workspace メンバー・各 crate サブディレクトリ・root 非メンバーのいずれで集約するか

## 見直し

REPAIR-1（ステータス「検討中」）のビヘイビア定義や、TASK-1 の定義・前提タスクが spec 側で変わったら、本ドキュメントも追従する。spec と食い違った場合は spec を正とする。
