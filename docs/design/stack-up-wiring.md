# `up` の本番配線（cli 側アダプタ）

STACK-8・STACK-2・STACK-10・SEC-1・TASK-155・#4638（判断の出典は #4630）。実装は `crates/cli/src/commands/up*`、純ロジックは `crates/stack`。

## 構成

- 依存の辺は `cli -> stack` のみ（`stack -> core` は張らない）。`make check-stack-deps` が `cargo metadata` で機械判定する。
- stack の 4 ポートの本番アダプタは cli に置く。

| ポート | 実装 |
| ------ | ---- |
| `ServiceLauncher` | `up/launcher.rs`。bundle を用意し、CLI 自身（`current_exe()`）の `create --unpack` → `start` を子プロセスで期限つきに呼ぶ |
| `DependencyObserver` / `HealthSource` | `up/observe.rs`。台帳（今回 create したサービス名 → ID）にあるものだけ状態ストアを読む |
| `NetworkProvisioner` | `up/provision.rs`。`network ls` / `network create` と同じ関数を同一プロセスで呼ぶ |

## bundle

`<状態ルート>/.stack/bundles/<コンテナ ID>/`（0700、fd 起点の oci `ExtractRoot` で操作）に `config.json` と `env/<n>.env`（0600）を置く。
`config.json` は手組みして core の `parse_config_bytes` で検証してから書く。rootfs は `create --unpack` が展開する。

- 同じ ID の状態記録がある: `ALREADY_EXISTS`（事前検査で全サービス分を先に見る。再利用は未実装）。
- 記録は無いが `rootfs/` が残っている: `FAILED_PRECONDITION`。回収は、記録が無いことを確かめたうえで該当 bundle ディレクトリを手動で削除する。
- 期限で kill した `create` は展開途中の rootfs を残しうる。同じ手順で回収する。

## 検査の順序（副作用の前に拒否）

引数 → TOML（4 MiB 上限）→ プロジェクト名（`--project-name` > `[project].name` > ディレクトリ名。正規化しない）→ プロファイル → 依存閉包 → pasta 整合 → ストアを開く → 各サービスの事前検査（`create_argv` 空実行・`env_files`・イメージ解決・config 合成・User）→ `up()`。

`env_files` は project_dir 起点で `RESOLVE_IN_ROOT | NO_SYMLINKS`（oci `read_rootfs_file`）で読み、bundle の `env/` に複製して子へ渡す（TOCTOU を閉じる）。`openat2` が使えないカーネルは `FAILED_PRECONDITION`。新しい `unsafe` は無い。

## フィールドの判断

| フィールド | 判断 |
| ---------- | ---- |
| `image` / `command` / `entrypoint` / `working_dir` | 写す（`command` 等は `config.json`。compose の意味論） |
| `env` / `env_files` / `labels` / `cap_drop` / `ulimits` / `shm_size` / `tmpfs` / `ports` / `networks` | 既存の `create` フラグで写す |
| `security_opt` | `no-new-privileges` のみ |
| `container_name` | 拒否（ID 規則 `<project>.<service>` を down / ps / logs と共有するため） |
| `volumes` / `healthcheck` / `deploy` / `restart` / `stdin_open` / `tty` / `secrets` / `configs` / `devices` | 拒否（`UNIMPLEMENTED`）。`healthcheck` が写らない間、`depends_on: healthy` は期限切れになる |

## 残余と後続

`down`・`ps`・プロジェクト単位 `logs` の結線、拒否中フィールドの写像、既存コンテナの再利用、イメージ User の名前解決、`--env` の値が cmdline に見える点、`up_real`（実機前提の通し試験）と CI 組み込み、既定の TOML ファイル名（spec に定め無し。現状 `--file` 必須）。
