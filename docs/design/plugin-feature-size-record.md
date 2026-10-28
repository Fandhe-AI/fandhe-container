# plugin feature 除外ビルドとサイズのビルド確認記録

core の `plugin` Cargo feature を除外（`--no-default-features`）したビルドの成立と、既定構成との成果物サイズ差を記録する。

- 対象ビヘイビア: PLUG-3（未使用 plugin 相当機能を Cargo feature で除外して軽量バイナリを作る）
- 関連タスク: TASK-111（feature 定義とビルド確認記録）・TASK-111.1（#262。feature 定義）・TASK-111.2（#263。本書と CI 組み込み）
- 対象マイルストーン: MS-3 Phase 4
- ステータス: ビルド成立の確認は完了。軽量化効果の実測は未完（下記「解釈と限界」）

## 計測方法

`make plugin-feature-size` が次を行う（#3204 で core の rlib から CLI の実行ファイルへ切り替えた）。CI では `bench-regression` ジョブのステップとして実行し、出力の表を `$GITHUB_STEP_SUMMARY` へ追記する。

1. `cargo tree -p fandhe-container-cli --no-default-features -e normal --target all` に `fandhe-container-plugin` が現れないことを確認（現れたら失敗）
2. `mktemp -d` 配下の別 target dir で `cargo build --release -p fandhe-container-cli`（既定構成）
3. 別の target dir で `cargo build --release -p fandhe-container-cli --no-default-features`（除外構成）
4. 両構成の実行ファイル `fandhe-container` のバイト数と 2 回のビルドの経過秒を記録
5. ビルド失敗・実行ファイル不在・不正なサイズ・既定構成で plugin rlib が無い・除外構成での plugin rlib の出現は非ゼロ終了（fail-closed）。サイズ差の大小には閾値を設けない

`make check-cli-no-plugin`（CI の `platform-ci` が実行。main では 3 OS）は、除外構成の CLI の lib / bin の clippy（`-D warnings`）と依存木の不在検査を行う。

## 実測値（#3204・ローカル）

| 項目 | 値 |
| ---- | -- |
| 環境 | Linux x86_64・rustc 1.99.0 (b940084d7 2026-09-28)・release |
| 既定: CLI 実行ファイル | 4,413,696 bytes |
| 除外: CLI 実行ファイル | 4,384,544 bytes |
| 差 | 29,152 bytes（0.66 %） |
| ビルド時間（cold） | 既定 32 s・除外 22 s（`make check-cli-no-plugin` は warm で数秒） |

CI 上の値は PR の `bench-regression` ジョブのサマリを参照する。

## cli・supervisor の feature 伝播の設計（#3204）

断った経路は 3 本だった: cli → plugin（直接依存）、cli → core(default)、cli → supervisor → core(default)。

採用案:

- supervisor: core の `plugin` ゲート配下（`fandhe_container_core::plugin`）を使っていないため、feature を持たず core を `default-features = false` で引く（oci・cri・plugin-cri と同じ）。plugin-cri の #2434 の統合も解消する
- cli: `plugin` feature（既定で有効）を新設し、`fandhe-container-plugin` を optional にして `fandhe-container-core/plugin` を連動させる。無効時はシグナル転送（再送だけ行う。ハンドラ登録と継承した `SIGCHLD` の `SIG_IGN` の解除は残す）と延期した後始末の記録を持たず、スレッドを起動できないときの縮退出力は書かない（REPAIR-5 を優先）
- 安全性: 無効なら plugin crate がリンクされず `PluginLaunchTarget` も存在しないので、検証だけが抜けて読み込める経路（fail-open）にならない。構築口は引き続き `make check-launch-target` が限定する。新しい `unsafe` は無い

却下案:

| 案 | 理由 |
| -- | ---- |
| rlib の計測を恒久にする | PLUG-3 は軽量バイナリを求める。変更が小さく伝播を設計できる |
| workspace 全体の `--no-default-features` | 依存元（plugin-mcp・benches）が既定 feature で core を引くと統合で再有効化される |
| supervisor にも `plugin` feature を作って中継 | 使わない機能の feature が増えるだけ。`default-features = false` で足りる |
| supervisor の実行ファイルも 2 構成で計る | 採用後は既定ビルドが plugin なしで差は常に 0 |
| `write_stderr_nonblocking` 等を plugin crate から移す | 補助 crate（MIT OR Apache-2.0）の公開 API と境界を変えるためスコープ外 |
| `check-standalone-clippy` の行列に無効構成を足す | 対象は cli 1 件。専用の `check-cli-no-plugin` で足りる |

申し送り: macOS・Windows でバックエンド plugin を起動する配線（#1869）を入れるときは、cli の `plugin` feature が無効なら構造化エラー（`UNIMPLEMENTED` 等）を返す fail-closed にする。

## 解釈と限界

- 実行ファイルの差（0.66 %）は僅少で、軽量化効果の実測ではない。ゲート配下が再エクスポートと小さな配線だけのため。切り替えは TASK-109・TASK-110 でゲート配下に実装が入ったときに効果を測るための土台
- PLUG-3 の軽量化効果の実測は未完。TASK-109・TASK-110 の後に再計測する
- `cross-target-check` は `--all-features` と既定 feature しか見ないため、cli の無効構成の macOS・Windows 向け型検査は PR では行われない（main の `platform-ci` の 3 OS で検出する）

## 再現手順

```bash
make plugin-feature-size
```
