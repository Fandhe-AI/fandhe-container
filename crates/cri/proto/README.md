# crates/cri/proto

CRI（Container Runtime Interface）の `.proto` 定義を置くディレクトリ。CRI-3（公式 `kubernetes/cri-api` の `.proto` から wire 互換な Rust コードを生成する）の入力であり、TASK-56.2（#424）で配置した。

現時点ではどこからも読まれていない。コード生成（`build.rs`）は TASK-56.3（#426）で実装する。

## 出典

| 項目 | 値 |
| ---- | ---- |
| リポジトリ | <https://github.com/kubernetes/cri-api> |
| パス | `pkg/apis/runtime/v1/api.proto` |
| バージョン | `v0.37.1`（`v0.37.0` と同一コミット。取得時点の最新安定版） |
| コミット | `d279f3cbb9d18b653d5fab12e187589914329c77` |
| git blob SHA | `f0a2cbd661113f6691855c165ad2ba1e168b1318` |
| sha256 | `381aab5cf67425b3c90ab016489de661ccb83ed9f21204066dc5df83b9b83360` |
| サイズ | 102158 バイト・2395 行（LF） |
| 取得日 | 2026-10-06 |

## ライセンス

Apache-2.0（本リポジトリの `LICENSE` と同一）。著作権表記（`Copyright 2020 The Kubernetes Authors`）は `api.proto` 冒頭のヘッダをそのまま保持している。upstream のルートに NOTICE ファイルは無い。

## 改変の有無

無改変（upstream とバイト一致）。当該版は `import` も `gogoproto` オプションも含まないため、gogoproto 拡張の除去作業は不要だった。将来の版で拡張が再導入された場合は、除去内容をここに記録する。

## 検証と更新

検証は次のコマンドで行う。

```sh
sha256sum crates/cri/proto/api.proto
```

更新は、タグではなくコミット SHA を固定して取得し、ハッシュ・本 README・`crates/cri/tests/proto_placement.rs` の期待値を同時に更新する。手編集はしない。

`api.proto` はタブと行末空白を含む原文のため、`.editorconfig` で整形対象外にしている。
