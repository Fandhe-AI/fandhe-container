# crate 短縮名と plugin crate 配置

crate の命名規約、19 crate（＋root の benches 用メンバー crate）の責務区分、plugin crate の配置を記録する。

- 決定日: 2026-09-26（ユーザー決定、#9・TASK-1.h1）
- 関連 issue: #7（TASK-1）・#8（TASK-1.1）・#9（TASK-1.h1）
- ステータス: 確定。本リポジトリの設計文書としての確定であり、spec 側（`05-tasks.md` 冒頭の仮称一覧・REPAIR-1 のステータス等）への反映は spec リポジトリ側の課題として追跡する（「後続タスクへの引き継ぎ」参照）
- 対象ビヘイビア: REPAIR-1（spec 上のステータスは「検討中」のまま。本決定はビヘイビア自体を確定させるものではない）
- 対象マイルストーン: MS-0

## 命名規約

spec で確定済みの前提と、本ドキュメントで確定した内容を区別する。

**spec で確定済みの前提**（`05-tasks.md` TASK-1・冒頭、REPAIR-1）:

- **workspace 内 crate のパス形式**: `crates/<短縮名>`
- **CLI バイナリ名**: `fandhe-container` に統一する。plugin バイナリ名は `fandhe-container-plugin-*`（発見対象）とする
- **旧提案の不採用**: `vm-core`・`vm-io` 等の `vm-*` 形式は採用しない（TASK-1）

**本決定（#9）で確定した内容**:

- **crate 名（Cargo.toml）の名前空間**: `fandhe-container-*`。ただし plugin 境界機構ライブラリは `fandhe-container-plugin`（`crates/plugin/`）とし、plugin バイナリ専用の `fandhe-container-plugin-*` と区別する。発見はバイナリ名で行う（PLUG-4・PLUG-11）ため、この区別により発見ロジックが `plugin`（境界機構ライブラリ）を誤検出する経路をなくす（決定 4）
- 下表の短縮名（「短縮名（crate 内パス）」列）・crate 名・責務区分を確定一覧とする

## crate 一覧（確定）

spec の仮称（`05-tasks.md` 冒頭）は core 系 8 個（`io`・`core`・`oci`・`cri`・`platform-macos`・`platform-windows`・`microvm`・`cli`）・plugin 系 5 個（`plugin-cri`・`plugin-macos`・`plugin-windows`・`plugin-microvm`・`plugin-mcp`）である。本決定はこれに `supervisor`・`gpu`・`net`・`plugin`（旧称 `plugin-api`）・`stack`・`compose-convert` の 6 crate を加え、core 系 13・独立ツール 1（`compose-convert`）・plugin 系 5 の 19 crate を確定一覧とした（決定 1・決定 4・決定 5）。加えて、crate をまたぐベンチ（TASK-113）・基準値（TASK-88）を置く root の `benches/` を、19 crate とは別枠で `publish = false` の workspace メンバー crate（`fandhe-container-benches`）とする（決定 7）。

なお「core 系 13・独立ツール 1・plugin 系 5」は本ドキュメントが workspace 上の配置区分として便宜的に付けた分類であり、PLUG-1 の「core／plugin」区分（下表「PLUG-1 区分」列）とは別軸である。`cri`・`platform-macos`・`platform-windows`・`microvm` の 4 crate は、PLUG-1 上は「plugin 境界の外側」（plugin バイナリから呼ばれるバックエンド実装ライブラリ）であり、PLUG-1 上の「core」には区分されない。`compose-convert` は plugin ではない独立ツールであり、PLUG-1 区分の対象外である（決定 5）。

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
| 10 | plugin | plugin（旧称 `plugin-api`） | plugin 境界機構（UDS・長さ接頭辞フレーム・gRPC・常駐/都度起動・信頼性検証） | G8（TASK-107 が crate 本体〔`crates/plugin/` に改名〕、TASK-108 が gRPC〔tonic〕境界、TASK-110・TASK-113・TASK-122〜124。plugin 発見・登録〔TASK-109〕の成果物は `crates/core/src/plugin_discovery.rs` であり `plugin` ではない） | core・plugin 双方が依存する境界基盤ライブラリ |
| 11 | gpu | gpu | GPU CDI spec 解析・edits 適用・Landlock/seccomp・cgroup device・読み取り専用 rootfs | G9（TASK-126〜135） | core（推奨）〔注 1〕。macOS Venus〔GPU-6〕は対象・実装機構が異なる別枠で、成果物は `plugin-macos` 側に置かれる |
| 12 | net | net | netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開 | G10（TASK-136〜148・TASK-185〜186） | 検討中（ネットワーク設定操作は制御面として PLUG-1 で `NetworkPlugin` が plugin 側に区分される一方、NET-5・NET-9 の DNS ヘルパー・rootless 転送はデータパス判定未確定、`plugin-system.md`） |
| 13 | stack | stack | TOML スキーマ・`depends_on` 起動順・`profiles` 絞り込み | G11（TASK-149・150・187〜188。TASK-149 が crate 雛形） | core（CLI＋ライブラリ API） |
| 14 | compose-convert | compose-convert | `compose.yaml` → TOML の片方向変換ツール（変換レポート・キー分類・`--downgrade` 格下げ・GPU 予約変換・`build:` エラー処理・往復検証テスト〔TASK-152〕） | G11（TASK-151 が crate 雛形・変換器本体、TASK-152・153・154・156・182） | 該当外（plugin ではない独立ツール。決定 5） |
| 15 | plugin-cri | plugin-cri | CRI サーバー plugin バイナリ（`cri` の実装を別プロセス化） | G8（TASK-114） | plugin |
| 16 | plugin-macos | plugin-macos | macOS バックエンド plugin バイナリ（TASK-115）。macOS Venus（GPU-6、TASK-172〜181）の virtio-gpu デバイスモデル・コンテキスト分配層・venus デコーダも `crates/plugin-macos/src/gpu/` に置く定義になっている | G8（TASK-115）・G-別枠（TASK-172〜181） | plugin |
| 17 | plugin-windows | plugin-windows | Windows バックエンド plugin バイナリ（`platform-windows` の実装を別プロセス化） | G8（TASK-116） | plugin |
| 18 | plugin-microvm | plugin-microvm | microVM 制御 plugin バイナリ（`microvm` の実装を別プロセス化） | G8（TASK-117） | plugin |
| 19 | plugin-mcp | plugin-mcp | MCP サーバー plugin バイナリ（参照実装） | G8（TASK-118、PoC-13） | plugin |

〔注 1〕`gpu` 行の PLUG-1 区分の内訳: `plugin-system.md` の境界表で「core（推奨）」と明記されているのは GPU-1〜4（CDI 適用・OCI hook 実行）のみ。GPU-5・GPU-7・GPU-8（Landlock/seccomp・cgroup device・読み取り専用 rootfs との両立）は境界表での明示判定がなく、`gpu` crate に実装される付随機能として扱っている。GPU-9 は `api-gpu.md` でステータス「検討中」のため確定扱いしない。

## plugin crate の配置（決定）

plugin crate（#15〜19）の開発時のソース配置は、**案 A（workspace 内の独立 crate として配置）を採用する**（決定 2）。`crates/plugin-cri/`・`crates/plugin-macos/` 等を workspace メンバーとする。

採用理由:

- spec（`05-tasks.md`）の各タスクの成果物パスが、既に plugin crate を `crates/plugin-cri`・`crates/plugin-macos` 等の `crates/` 配下として書いており、workspace 内配置と一致する
- 依存の固定（`[workspace.dependencies]`）・`cargo deny`・3 OS CI を 1 か所で扱える
- core と plugin にまたがる改修を 1 PR で直せる（REPAIR-1）
- 発見はバイナリ名で行う（PLUG-4・PLUG-11）ため、案 A を採用してもサードパーティ製 plugin を別リポジトリで開発することは妨げない

### 検討経緯

案 A のほか、案 B1（同一リポの workspace 外。`[workspace] exclude` または別 Cargo workspace）・案 B2（別リポジトリ）を比較した。

- **案 B1**: root `Cargo.toml`/`Cargo.lock` が plugin 追加で変化しない・plugin のビルド失敗が core CI に波及しない長所がある一方、`[workspace.dependencies]` による共通依存の統一管理が及ばず、別 workspace の CI・`cargo deny` を個別に用意する必要がある短所がある
- **案 B2**: 案 B1 の長所に加え版数・リリースサイクル・レビュー体制を core と独立にできる一方、`plugin` crate をバージョン付きで公開・参照する仕組み（レジストリ公開または git 依存）が別途必要になり、案 B1 の短所も引き継ぐ

案 A の短所として挙げていた「plugin を追加すると root `Cargo.toml`・`Cargo.lock` が変化し、PLUG-4（TASK-109）の『core 無変更』判定に影響し得る」点は、決定 3（判定対象の定義）で解消した。

TASK-102（workspace 構成の最終レビュー、担当: 人間、OSS-6）は Must/Should 中核の実装完了後に予定されており、この時点で実装の進捗を踏まえて本論点を再確認する機会がある。

### PoC-13 での計測上の措置の位置づけ

PoC-13（plugin-boundary-mechanism）は、MCP 参照 plugin（Python 製、`fandhe-container-plugin-mcp`）を意図的に Cargo workspace 外（独立スクリプト）に置いた。理由は、workspace メンバーにすると root `Cargo.toml`/`Cargo.lock` が変化し `core-harness` バイナリの再ビルド条件も変わるため、`core-harness` の sha256 判定が「実装上の副作用」で汚染されるのを避けるためである（`plugin-boundary-mechanism/README.md`）。ただし PoC-13 は Rust 製 plugin crate を workspace 内外どちらに置くかの実測根拠を含んでおらず、MCP 参照 plugin が Python 製である点（Cargo workspace の対象にそもそもならない）の影響も評価していない。本リポジトリでは案 A を採用し、PLUG-4 の判定対象は決定 3 のとおり定義した。

## 決定事項

### 決定 3: PLUG-4「core 無変更」の判定対象

次の 3 点を判定対象とする。root の `Cargo.toml`・`Cargo.lock` はファイル全体の比較から外す。

1. core 側 crate のソースの sha256 一覧
2. `cargo tree -p <core> --locked -e normal` で見た core の依存木が変わっていないこと
3. `cargo build -p <core のバイナリ> --locked` で作った core バイナリの sha256

判定対象を `-p <core>` で選んだ core 自身の依存木・core バイナリに絞っているため、plugin を足して root の `Cargo.lock` が変化しても、core に解決される依存だけを見比べられる。加えて、依存は `[workspace.dependencies]` で `=x.y.z` に完全固定しているため、plugin 側で feature を足しても core の依存の版は動かない。この 2 点により、案 A（workspace 内配置）を採用しても root `Cargo.toml`/`Cargo.lock` の変化を判定対象から外すことで PLUG-4 の趣旨を満たせる。

### 決定 4: `fandhe-container-plugin-api` の改名

`fandhe-container-plugin-api`（`crates/plugin-api/`）を `fandhe-container-plugin`（`crates/plugin/`）に改名する。

- `fandhe-container-plugin-*` は plugin バイナリ専用とし、PLUG-4・PLUG-11 の発見対象の命名規約と重ならないようにする
- Conventional Commits の scope `plugin` はそのまま使う（対象を `crates/plugin` に更新する）

### 決定 5: compose 変換器の配置

D-14（`01-brainstorm.md`「設計上の論点」6）の推奨に合わせ、compose 変換器を独立した crate とバイナリにする（`crates/compose-convert/`、`fandhe-container-compose-convert`）。

- TOML の型は `stack` のものを使う（`compose-convert` → `stack` の一方向依存）
- YAML パーサーの依存を CLI 本体（`cli`）に入れない（依存最小方針・CORE-7〜9）
- plugin ではないため `plugin-*` という名前は付けない
- TASK-152（往復検証テスト、成果物 `crates/stack/tests/roundtrip.rs`）は変換器（`compose-convert`）の出力を検証するテストであり、`stack` 側に置くと依存の向き（`compose-convert` → `stack`）が逆転する。テストは `crates/compose-convert/tests/` に移す
- spec の TASK-151・152・153・154・156・182 の成果物パス（現状 `crates/stack/src/compose_convert.rs`・`crates/stack/tests/roundtrip.rs` 等）の修正は、spec リポジトリ側で行う（「後続タスクへの引き継ぎ」参照）

### 決定 6: `StateStore` 実装の一本化

`StateStore` の実装は core（TASK-31、PLUG-1）の 1 つだけにする。

- supervisor は core の `StateStore` を使う（supervisor → core の一方向依存）
- `state.json` の形式と、supervisor が使う項目（`supervisor_pid`・`health`・`restart_count`）は core の型に含める
- CLI と supervisor の書き込みの排他は TASK-157 で詰める
- spec の TASK-157 の記述（現状 `crates/supervisor/src/state.rs` を `StateStore` トレイトの実装として記載）の修正は、spec リポジトリ側で行う

### 決定 7: `benches/` の置き場所

`benches/` は 2 つに分ける。

- crate の中で完結するベンチは、各 crate の `benches/` に置く
- crate をまたぐベンチ（TASK-113 の `benches/plugin_boundary.rs`）と基準値（TASK-88 の `benches/baseline.json`）は、root の `benches/` に置く。root は virtual workspace のため root 直下の `benches/*.rs` は単体では動かせず、`publish = false` の workspace メンバー crate（`fandhe-container-benches`）として置く
- ベンチの枠組みのクレート（criterion 等）は使わず、まずは `harness = false` の自前計測で始める（依存を足すならユーザー承認が要る。[dependency-policy](../../.claude/rules/dependency-policy.md)）

## 後続タスクへの引き継ぎ

- #10・#11 の `Cargo.toml` 雛形作成では本ドキュメントの確定一覧（crate 一覧・命名規約）を使う
- spec 側の修正が必要な項目（ユーザーが spec リポジトリ側で対応する）:
  - REPAIR-1 のステータス（「検討中」からの更新要否）
  - TASK-1・`05-tasks.md` 冒頭の仮称一覧（`plugin-api`・`stack` 内 compose 変換器等）
  - TASK-107・108・110・112・123・124 の crate 名・成果物パス（`crates/plugin-api/` → `crates/plugin/`、crate 名 `fandhe-container-plugin-api` → `fandhe-container-plugin`）
  - TASK-151・152・153・154・156・182 の成果物パス（`crates/stack/` → `crates/compose-convert/`）
  - TASK-157 の `StateStore` 実装箇所の記述
- TASK-157 で CLI と supervisor の `state.json` 書き込みの排他を詰める
- TASK-109（plugin 発見・登録の実装）は、決定 3 の判定対象 3 点（core ソース sha256・core 依存木・core バイナリ sha256）を踏まえて実装する
- root の `benches/` を `fandhe-container-benches` crate として置く際、Cargo の bench 自動発見は crate 内の `benches/` を探すため、実際の配置は `benches/benches/*.rs` になるか `[[bench]] path` の明示指定が要る。#10・#11 の雛形作成時にこの点と、TASK-113（`benches/plugin_boundary.rs`）・TASK-88（`benches/baseline.json`）の成果物パスの解釈を確認する

## 見直し

REPAIR-1（ステータス「検討中」）のビヘイビア定義や、TASK-1 の定義・前提タスクが spec 側で変わったら、本ドキュメントも追従する。spec と食い違った場合は spec を正とする。
