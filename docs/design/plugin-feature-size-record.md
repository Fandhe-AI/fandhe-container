# plugin feature 除外ビルドとサイズのビルド確認記録

core の `plugin` Cargo feature を除外（`--no-default-features`）したビルドの成立と、既定構成との成果物サイズ差を記録する。

- 対象ビヘイビア: PLUG-3（未使用 plugin 相当機能を Cargo feature で除外して軽量バイナリを作る）
- 関連タスク: TASK-111（feature 定義とビルド確認記録）・TASK-111.1（#262。feature 定義）・TASK-111.2（#263。本書と CI 組み込み）
- 対象マイルストーン: MS-3 Phase 4
- ステータス: ビルド成立の確認は完了。軽量化効果の実測は未完（下記「解釈と限界」）

## 計測方法

`make plugin-feature-size` が次を行う。CI では `bench-regression` ジョブのステップとして実行し、出力の表を `$GITHUB_STEP_SUMMARY` へ追記する。

1. `mktemp -d` 配下の別 target dir で `cargo build --release -p fandhe-container-core`（既定構成）
2. 別の target dir で `cargo build --release -p fandhe-container-core --no-default-features`（除外構成）
3. 両構成の `libfandhe_container_core.rlib` と、既定構成のみでビルドされる `libfandhe_container_plugin-*.rlib` のバイト数を記録
4. ビルド失敗・rlib 不在・不正なサイズ・除外構成での plugin rlib の出現は非ゼロ終了（fail-closed）。サイズ差の大小には閾値を設けない

`-p fandhe-container-core` で計測する理由: workspace 全体の `--no-default-features` は、supervisor が core を既定 feature つきで依存するため feature 統合で `plugin` が再有効化され、除外ビルドにならない。

## 実測値

| 項目 | 値 |
| ---- | -- |
| 環境 | Linux x86_64・rustc 1.98.1 (48a229cea 2026-09-01)・release |
| 既定: core rlib | 7,126,540 bytes |
| 既定: plugin rlib | 532,496 bytes |
| 既定: 合計 | 7,659,036 bytes |
| 除外: core rlib | 7,122,218 bytes |
| 除外: plugin rlib | ビルドされない |
| core rlib の差 | 4,322 bytes |
| 合計の差 | 536,818 bytes（7.01 %） |

CI 上の値は PR の `bench-regression` ジョブのサマリを参照する。

## 解釈と限界

- 計測対象は rlib（中間成果物）で、リンク後のサイズではない。最終バイナリ（CLI）は TASK-79 で追加予定のため、追加後に実行ファイルのサイズへ切り替える
- 合計の差の大半は plugin rlib 自体であり、実行ファイルでの削減量を意味しない。core rlib の差が 4,322 bytes と僅少なのは、ゲート配下が現状再エクスポートのみのため
- PLUG-3 の軽量化効果の実測は未完。ゲート配下に実装が入る TASK-109・TASK-110 の後に再計測する
- supervisor 経由のビルドでは `plugin` を除外できない。最終バイナリで PLUG-3 を成立させるには feature 伝播の設計が別途必要

## 再現手順

```bash
make plugin-feature-size
```
