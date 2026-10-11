# 非許可ライセンス検出の fail-closed 確認記録

`deny.toml` の `[licenses]` は permissive の SPDX 識別子だけを `allow` に並べ、コピーレフトは並べない。許可リストに無いライセンスを拒否して非ゼロで終了すること（fail-closed）を、実際に拒否させて確認した記録である。

- 対象ビヘイビア: OSS-4・OSS-5・REPAIR-9（関連: REPAIR-12。受け入れ基準の機械照合）
- 関連タスク: TASK-90.2（#127。本書）。先行の TASK-90.1（#126）は `make deny` が skip されず動くことまでを確認した
- 対象マイルストーン: MS-1

## 検証方式

- 使い捨ての workspace（一時ディレクトリ）に、Apache-2.0 の root crate と、path で依存する probe crate を作る。probe の `license` を case ごとに差し替える
- 本物の `deny.toml` を `--config` で渡して `cargo deny --locked check licenses` を実行する。本番の `Cargo.toml`・`Cargo.lock`・`deny.toml` は変えない。crates.io へは接続しない（`--offline`）。新規依存は無い
- 判定は終了コードと診断の両方で行う。拒否されるべき case は「非ゼロ」かつ出力に `rejected` と `licenses FAILED` を含むこと。許可されるべき case は終了コード 0 かつ `rejected` を含まないこと。lock 不整合など別理由の非ゼロを合格にしないため、対照 case で常時失敗するテストも防ぐ
- スクリプト: `scripts/deny-license-fail-closed-selftest.sh`。再現は `make deny-license-fail-closed-selftest`。CI では `platform-ci`（ubuntu のみ）が実行する

## 結果（cargo-deny 0.20.2）

| probe の license | 期待 | 終了コード | 結果 |
| ---- | ---- | ---- | ---- |
| GPL-3.0-only | 拒否 | 4 | `rejected` あり |
| LGPL-2.1-only | 拒否 | 4 | `rejected` あり |
| AGPL-3.0-only | 拒否 | 4 | `rejected` あり |
| MPL-2.0 | 拒否 | 4 | `rejected` あり |
| MIT AND GPL-3.0-only | 拒否 | 4 | `rejected` あり |
| MIT（対照） | 許可 | 0 | `rejected` なし |
| MIT OR GPL-3.0-only | 許可 | 0 | `rejected` なし |

自己テスト自体の検出力も確認した。コミットしない一時改変として `deny.toml` の `allow` に `GPL-3.0-only` を足すと、GPL と `MIT AND GPL-3.0-only` の case が FAIL し、スクリプトは非ゼロで終了した（改変は元に戻して未コミット）。

## 既知の境界

- `MIT OR GPL-3.0-only` のような OR 式は、permissive 側を選べるため cargo-deny は許可する。これは cargo-deny の仕様であり欠陥ではない
- OR 式の扱いを厳しくするかどうかは許可方針の変更にあたり、ユーザー判断事項である（`.claude/rules/licensing.md`）。本タスクでは `deny.toml` の設定値を変えていない
- `license-not-encountered` 警告は事前許可による想定内の警告で、判定には使っていない
