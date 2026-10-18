# pull_e2e 実機前提ハーネスの公開イメージ実行記録

`crates/oci/tests/pull_e2e.rs` を実際の公開イメージで実行した結果を記録する。

- 対象ビヘイビア: OCI-1（イメージの pull・展開・実行）
- 関連タスク: TASK-55.1（#420・PR #2190。ハーネス本体）・TASK-55.2（#421。本書）。親は TASK-55（#419）・MS-4
- ステータス: **pull・digest 検証・展開は 4 イメージで成功（4/5）。run 段（コンテナ実行・終了コード 0 の確認）は AppArmor による非特権 user namespace の制限で 4 件とも `PERMISSION_DENIED` のため未達。`redis:alpine` は config 段で `INVALID_ARGUMENT`（所見参照）。終了コード 0 の確認は人間へ引き継ぐ**（成功を装わない。REPAIR-3）

## 必要環境・必要権限

- Linux 6.12 以降・非 root・非特権 user namespace が許可されたホスト（`kernel.apparmor_restrict_unprivileged_userns` が 1 でないこと）
- 委譲された cgroup v2 サブツリー・registry-1.docker.io への外向き HTTPS（匿名 pull。レート制限で失敗しうる）
- exec 可能な作業ディレクトリ（`--work-dir`。tmpfs の quota を避けるため `/tmp` 以外を使った）

## 実行手順

```text
cargo test -p fandhe-container-oci --test pull_e2e --no-run
systemd-run --user --scope -p Delegate=yes <上で得た実行ファイル> --ignored \
  --work-dir <作業ディレクトリ> \
  --image alpine \
  --image debian:bookworm-slim --cmd /bin/true \
  --image nginx:alpine --cmd /usr/sbin/nginx -v \
  --image busybox --cmd /bin/true \
  --image redis:alpine --cmd /usr/local/bin/redis-server --version
```

- cargo 経由で実行すると cargo が同じ cgroup に入り `prepare` が失敗するため、実行ファイルを直接起動する
- `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` で待ち時間の上限を変更できる

## 試行環境

| 項目 | 値 |
| ---- | -- |
| 実行日時 | 2026-10-18 18:13 UTC（1 回のみ。再実行なし） |
| uid | 1000（非 root） |
| カーネル | 7.0.0-34-generic（x86_64） |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 |
| `user.max_user_namespaces` | 102024 |
| cgroup 委譲 | `user@1000.service` が `cpu memory pids` を委譲 |
| 作業ディレクトリ | `/home` 配下（ext 系ファイルシステム。空き 200 GB 超） |

## 結果

| イメージ | レイヤー数 | config / レイヤー合計 (B) | auth / manifest / blobs / verify / extract / run (ms) | stripped_special_bits | stage_failed | error_code | 成否 |
| -------- | ---------- | ------------------------- | ----------------------------------------------------- | --------------------- | ------------ | ---------- | ---- |
| alpine | 1 | 611 / 3,849,738 | 711 / 803 / 446 / 39 / 931 / 42 | 0 | run | PERMISSION_DENIED | 失敗（run 段） |
| debian:bookworm-slim | 1 | 453 / 28,249,323 | 736 / 804 / 634 / 292 / 8223 / 41 | 11 | run | PERMISSION_DENIED | 失敗（run 段） |
| nginx:alpine | 8 | 12,323 / 28,801,526 | 697 / 821 / 1995 / 289 / 8919 / 43 | 0 | run | PERMISSION_DENIED | 失敗（run 段） |
| busybox | 1 | 459 / 2,226,163 | 709 / 800 / 417 / 23 / 542 / 31 | 0 | run | PERMISSION_DENIED | 失敗（run 段） |
| redis:alpine | 7 | 6,839 / 39,102,983 | 703 / 785 / 3417 / 399 / 0 / 0 | 0 | config | INVALID_ARGUMENT | 失敗（config 段） |

- 全行で `from_index: true`（manifest list から linux/amd64 を解決）、`exit` は `not_started`
- `manifest_digest`（タグが動いても再現できるように記録）
  - alpine: `sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395`
  - debian:bookworm-slim: `sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91`
  - nginx:alpine: `sha256:138af827713b7671ef4ee2deea73bc6f08ae265130ce350307e3e7b52cd4b51b`
  - busybox: `sha256:f97baa533a26513c453a362be331a43eb60214302f449c16571b23cea141dce4`
  - redis:alpine: `sha256:2d3814be5e9b06a30a0be54770b7e12052e7e79ec85271aefd34875c1f393b23`
- 単一レイヤー（alpine・debian・busybox）と複数レイヤー（nginx:alpine は 8 層）の両方で、匿名 pull・digest 検証・展開・bundle 生成まで通った
- ハーネスの最終行: `pull_e2e: FAILED 5/5 images failed`、プロセスの終了コード 1
- 作業ディレクトリの残置なし（`FAILED cleanup` の行なし、実行後の作業ディレクトリは空）

## 原因の切り分け（run 段の `PERMISSION_DENIED`）

| 確認 | 結果 |
| ---- | ---- |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 |
| `unshare -Ur true` | `unshare: write failed /proc/self/uid_map: Operation not permitted` |
| `journalctl -k` の AppArmor 行 | 未取得（ユーザー権限では読めず、該当行なし） |

- 判断: 非特権 user namespace の作成後に `uid_map` の書き込みが拒否されるのは、AppArmor の制限（sysctl が 1）の典型的な症状で、ハーネスと無関係な `unshare` 単体でも再現する。`docs/design/measurements/cgroups-oom-local.md` の記録と同じ状況である。よって run 段の失敗はハーネス・oci・core の不具合ではなくホスト環境の制限と判断する
- 緩和（`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`）は root 権限コマンドのため実装担当は実行していない

## 所見

- 展開時のデバイス・FIFO・hardlink 制限による失敗は出なかった（ハーネスでの回避なし）。debian の `stripped_special_bits: 11` は setuid / setgid / sticky を既定で落とした数（`docs/design/oci-layer-special-bits.md`）
- `redis:alpine` は config 段で `INVALID_ARGUMENT`。この記録では `stderr_tail` に詳細が無く、原因は未調査（`--cmd` の指定か image config の Entrypoint / Cmd の算出に起因する可能性。要調査）。pull と verify は成功しているため、受け入れ条件の 3 種以上には既定の 3 種（alpine・debian・nginx:alpine）を用いる
- 既知の制約（ハーネスの `//!` と同じ）: `User`・`WorkingDir` は無視、`diff_id` は未検証、レイヤーは gzip のみ

## 引き継ぎ（人間担当）

受け入れ条件の「終了コード 0 の確認」は未達。次を人間が実機で行い、結果を本書へ追記する。#1621 でも同じ sysctl の緩和が要るため、同じ作業の中で実施するとよい。

1. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
2. 上記「実行手順」のコマンドを実行する
3. 結果の表の run 列と exit を本書へ追記する（`redis:alpine` の config 段の原因も調べる）
4. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1` で元に戻す
