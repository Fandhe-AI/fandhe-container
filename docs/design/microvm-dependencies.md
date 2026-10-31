# rust-vmm 禁止クレートの判定結果の記録

MVM-4（rust-vmm の低レベル基盤クレートを依存ツリーに含めない）の機械判定を、`crates/microvm` 本体の実装前（雛形のみ）のワークスペースで実行した結果と、TASK-74・TASK-75 の後に同じ判定を再実行する手順を記録する（TASK-73.3・#687・MS-7。関連: REPAIR-9・REPAIR-12・OSS-3・OSS-5）。判定の仕組みは TASK-73.1（#685）と TASK-73.2（#686）で導入済み。

この記録は判定の代わりではない。PR ごとの継続的な検出は CI（`platform-ci` の `make check-microvm-deps`、rust-ci の `cargo deny`、`make deny-bans-fail-closed-selftest`）が担う。

## 判定の仕組み

| 判定 | 実体 | 見るもの |
| ---- | ---- | ---- |
| 照合 A / B | `scripts/check-microvm-deps.sh`（`make check-microvm-deps`） | `cargo tree -e normal,build,dev --target all --all-features --locked` の名前（`_` を `-` に正規化した完全一致）と repository URL（`github.com/rust-vmm/`） |
| bans | `deny.toml` の `[bans]`（`cargo deny check bans`） | 禁止クレート名 |

禁止リストの正は `scripts/check-microvm-deps.sh --list`。説明の詳細はスクリプト冒頭のコメントと [from-scratch-policy.md](from-scratch-policy.md) を参照する。

## 対象クレート一覧

- 禁止クレート（10 種）: `vm-memory`・`kvm-ioctls`・`kvm-bindings`・`vhost`・`vhost-user-backend`・`virtio-queue`・`vmm-sys-util`・`linux-loader`・`event-manager`・`vm-superio`
- 検査したマニフェスト: ルート workspace の `Cargo.toml`（500 packages）・`poc/venus-decoder/jig/Cargo.toml`（41 packages）
- workspace メンバー（21 件）: `fandhe-container-` に続く `benches`・`cli`・`compose-convert`・`core`・`cri`・`gpu`・`guest-init`・`io`・`microvm`・`net`・`oci`・`platform-macos`・`platform-windows`・`plugin`・`plugin-cri`・`plugin-macos`・`plugin-mcp`・`plugin-microvm`・`plugin-windows`・`stack`・`supervisor`
- `crates/microvm`・`crates/plugin-microvm` は TASK-1.3 の雛形で `[dependencies]` を持たない。`cargo tree -p <名前> -e normal,build,dev --target all --all-features --locked` は自分自身の 1 行だけを返した

## 実行結果

| 日時 | commit | 契機 | 環境 | コマンド | 結果 |
| ---- | ------ | ---- | ---- | -------- | ---- |
| 2026-10-31 17:28 UTC（2026-11-01 02:28 JST） | `1c918a76` | 初回（microvm 雛形のみ） | Linux x86_64・cargo 1.99.0・cargo-deny 0.20.2 | `make check-microvm-deps` | 終了コード 0。ルート 500 packages・治具 41 packages ともに `OK: no rust-vmm crate` |
| 同上 | `1c918a76` | 同上 | 同上 | `cargo deny --locked check bans licenses`（ルート）と、治具に対する `--manifest-path poc/venus-decoder/jig/Cargo.toml --config deny.toml` 付きの同検査 | 両方 `bans ok, licenses ok`（`unmatched license allowance` は警告で、判定に影響しない） |
| 同上 | `1c918a76` | 同上 | 同上 | `make deny-bans-fail-closed-selftest` | 全ケース合格（禁止クレートは終了コード 2 で拒否、対照は 0） |
| 同上 | `1c918a76` | 同上 | 同上 | `make check-microvm-deps-selftest` | 17 passed, 0 failed |

advisories は外部 DB に依存して時点で変わるため、この記録の対象外とし、CI の `make deny` が担う。

## 既知の境界

- vendoring や repository を書き換えた改名 fork は検出できない
- youki・Firecracker・Cloud Hypervisor 由来のクレートは機械判定の範囲外で、AGENTS.md の観点で見る
- 10 種以外の rust-vmm クレートは照合 B（repository URL）が補うのみ

## TASK-74・TASK-75 の後の再実行手順

1. `crates/microvm` に依存を追加する PR（依存の追加はユーザー承認制。[dependency-policy](../../.claude/rules/dependency-policy.md)）と、TASK-74・TASK-75 の完了時に次を実行する: `make check-microvm-deps`・`cargo deny --locked check bans licenses`・治具の `cargo deny --manifest-path poc/venus-decoder/jig/Cargo.toml --config deny.toml --locked check bans licenses`・`cargo tree -p fandhe-container-microvm -e normal,build,dev --target all --all-features --locked`
2. 結果は既存の行を上書きせず、「実行結果」の表へ日時・commit・契機（TASK-74 / TASK-75 / 依存追加 PR）の行を追記する
3. NG なら依存を入れずに止める。`deny.toml` の例外追加や禁止リストの変更は、ユーザー承認とセットでのみ行う
