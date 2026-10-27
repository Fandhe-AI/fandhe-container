# 本番の rootless start と委譲 cgroup の prepare の実機確認 手順書と結果記録（#2062）

本番の rootless `fandhe-container start` が、supervisor の `DelegatedCgroup::prepare`（`crates/core/src/cgroups.rs`）で拒否されずに通るかを実機で確かめる手順と、結果記録の雛形。対応する ID は TASK-79 追補・TASK-32 追補・TASK-157 追補・MS-6、CORE-3・CORE-4・CORE-6・SEC-1・SEC-5・CLI-1・REPAIR-3・REPAIR-5・REPAIR-12。関連 issue は [#2062](https://github.com/Fandhe-AI/fandhe-container/issues/2062)（本確認。人間担当）・#2081（CLI が supervisor を新しい user scope で起動）・#2061（`delete` の実 cgroup 通し試験）・#1314・#2133・#1621。

実行・結果の記録・成否の判定は人間が行う。Agent は実行しない（ホストに transient scope と cgroup を作るため）。本書のコマンドは作成時に未実行である。

## #2081 による前提の変化

- `prepare` は、委譲された親 cgroup の `cgroup.procs` に自分以外の PID がいると `FAILED_PRECONDITION`（`delegated cgroup contains other processes; refusing to move them`）で拒否する（他者の PID を動かさない。SEC-1）
- 以前の CLI は supervisor を自分と同じ cgroup に起動して最大 36 秒そこに残っていたため、本番の `start` は拒否される見込みが高かった
- #2081 で CLI は `systemd-run --user --scope --quiet -p Delegate=yes --` で supervisor を包み、新しい scope で一人にして起動する（[cgroups.md](../design/cgroups.md)「前提環境」）。このため主シナリオは「普通の端末のシェルの cgroup から `start` を実行する」形である
- #2062 の受け入れ条件 1 にある「利用者が用意した委譲スコープの中で start する」は #2081 より前の前提である。副次の変種として任意で確認する

## 事前確認

欠けたときの失敗のしかたで切り分けられるよう、1 行ずつ確認する。ホスト名・アドレス・ユーザー名・`XDG_RUNTIME_DIR` の実パスは記録しない。

- Linux 6.12 以上（Landlock ABI 6）: `uname -r`
- cgroup v2: `stat -fc %T /sys/fs/cgroup` が `cgroup2fs`
- 非 root で実行する（rootful は `UNIMPLEMENTED`・終了コード 8）
- 非特権 user namespace を許可している（例: `kernel.apparmor_restrict_unprivileged_userns=0`）。設定の変更は人間が判断する。本書は sudo を呼ばない
- user マネージャに届く: `test -S "$XDG_RUNTIME_DIR/systemd/private"` と `systemctl --user is-system-running`
- `systemd-run` が固定候補（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`・`/run/current-system/sw/bin`）にあり、root 所有で group / other に書き込み権が無い。PATH 探索や `DBUS_SESSION_BUS_ADDRESS` による回避は行わない。NixOS の既知の限界は #2133
- subuid / subgid の自分の行と `uidmap` の有無（ID 写像のモデル〔subordinate / single〕が変わる。#2243・#1621）。結果欄に記録する

## ビルドと配置

```bash
cargo build --release -p fandhe-container-cli -p fandhe-container-supervisor
chmod g-w target/release/fandhe-container target/release/fandhe-container-supervisor
export BIN_DIR="$PWD/target/release"
```

CLI と supervisor は同じディレクトリに置く（[linux.md](../setup/linux.md)「rootless」）。umask 002 のビルドでは上の `chmod g-w` が要る。詳細は [supervisor-measurement-runbook.md](supervisor-measurement-runbook.md#ビルド)。

## bundle の用意

[supervisor-measurement-runbook.md](supervisor-measurement-runbook.md#bundle-の用意) に従う。要点は次のとおり。

- `config.json` の `linux.namespaces` に user namespace を指定する。`linux.uidMappings` / `linux.gidMappings` は省略するか空配列にする。非空にすると core の `reject_config_id_mappings` が `UNIMPLEMENTED` で拒否し、`prepare` に到達できない（config-id-mappings.md、SEC-5・CORE-6）。写像は launcher が権限モデルから導出する。runbook の「UID マッピングを入れる」は user namespace の指定の意味で読み、写像の配列は書かない
- `process.args` は長時間動く静的リンクのプロセスにする
- `linux.cgroupsPath` は書かない（`UNIMPLEMENTED` で拒否される。cgroups.md）
- 資格情報を含めない

## シナリオ 1（主）: 端末からの本番の start、観察、delete

`start_stop_delete_real`（#2450）は委譲スコープの中から本番の `start` から `delete` までを自動で通し、CI でも回っている（下の「CI での先行観測」）。ただし端末の session scope から `start` する本シナリオと、利用者の実機の版での確認は自動試験に無いため、手作業で補う（受け入れ条件 1・3）。`<root>`・`<bundle>`・`<id>` は置き換える。

1. 実行前に自分のシェルの cgroup を記録する: `cat /proc/self/cgroup`
2. 作成と起動:

   ```bash
   "$BIN_DIR/fandhe-container" --root <root> create --bundle <bundle> <id>
   "$BIN_DIR/fandhe-container" --root <root> start <id>; echo "exit=$?"
   ```

3. 終了コードと stderr の JSON の `code`・`message` を記録する。

   | 終了コード | `code` | 読み方 |
   | ---------- | ------ | ------ |
   | 0 | なし | 成功 |
   | 5 | `FAILED_PRECONDITION` | 前提不備。`prepare` の拒否でも、本番 supervisor の `prepare_cgroup`（`crates/supervisor/src/start_entry.rs`）が detect・scope 記録・cgroup 作成のエラーを固定文言に変換するため、message は `failed to prepare the container cgroup` になる（同居による拒否の内部メッセージ `delegated cgroup contains other processes; refusing to move them` は stderr に出ない）。同居が原因かどうかは、stderr だけでは判別できず、親 scope の `cgroup.procs` に自分以外の PID がいるかを追加で観察して特定する（結果記録の「親 scope の `cgroup.procs`」と同じ） |
   | 7 | `TIMEOUT` | 結果不明（受信期限 58.9 秒）。`state`・`list` で確かめる |
   | 8 | `UNIMPLEMENTED` | rootful で実行した等 |
   | 1 | `INTERNAL` | その他 |

4. 成功時の観察:
   - `state` / `list` が Running と pid を示す
   - その pid の `/proc/<pid>/cgroup` が `fc-<id>@<n>` を指す
   - supervisor の scope の `cgroup.procs` に CLI がいない。CLI は既に終了している
   - `systemctl --user list-units --type=scope` に新しい scope がある
   - `state.json` の `cgroupScope`・`cgroupInstance`
5. 後始末: `stop`（`run_stop`）は `ControlSignaler` と supervisor の制御チャネルで SIGTERM を送る。実装済みなのはこの SIGTERM の送達までで、猶予後の SIGKILL や停止完了の確認などは未実装（#1545 で追う）のため、停止しないときがある。止まらないプロセスを止めるときは [runbook の後始末](supervisor-measurement-runbook.md#実行後の確認)と同じく、pid と起動時刻の一致を確かめてから送る（pid 再利用による誤 kill を避ける）。その後 `delete <id>` を実行する。通常の端末（SSH・TTY の root 所有 session scope）のシェルからの `delete` は `DelegatedCgroup::detect` が失敗し、記録済み scope を使う削除へ進めず、cgroup と状態記録が残る。これは本確認の前提不備であり、`prepare` の回帰とは区別して記録する。後始末は `systemd-run --user --scope -p Delegate=yes -- "$BIN_DIR/fandhe-container" --root <root> delete <id>` で包んで実行する。その終了コードを記録し、cgroup・`state.json`・scope の残骸が無いことを確かめる。`cgroup.procs` が空でない状態の `delete` が `FAILED_PRECONDITION` で拒否されるのは仕様どおり（`delete_cgroup_real` のシナリオ B）
6. 副次の変種（任意）: `systemd-run --user --scope -p Delegate=yes -- <シェル>` で作った scope の中のシェルから 1〜5 を行う

## CI での先行観測

`start_stop_delete_real` は #2596 以降、`platform-ci` の ubuntu-latest が `systemd-run --user --scope --quiet -p Delegate=yes --` の中で毎回実行し、成功行を `scripts/check-success-lines.sh` で完全一致照合している（job の緑だけを根拠にしない）。これは参考であり、受け入れ条件 1 の記録の代わりにならない。理由は次のとおり。

- 委譲スコープの中から `start` する変種で、端末の session scope から `start` する主シナリオとは別物である
- 人間の実機の OS・カーネル・systemd の版での結果ではない

## シナリオ 2: 実機前提試験の実行

どれも `harness = false` で、`cargo test -p <パッケージ> --test <名前> --no-run` でビルドし、出力された試験バイナリを `cargo` 経由でなく直接実行する。前提が欠けると skip でなく失敗する。起動の仕方の取り違えに注意する。成功時の最終行は [AGENTS.md](../../AGENTS.md)「実機前提テスト」と同じ。

| 試験 | パッケージ | 起動の仕方 | 成功時の最終行 | CI での実行 |
| ---- | ---------- | ---------- | -------------- | ----------- |
| `start_scope_real`（#2081） | `fandhe-container-cli` | **包まず**直接 `<bin> --ignored`（同居する cgroup から実行しないと感度の確認が逆になる） | `start_scope_real: supervisor ran alone in a delegated user scope; cli did not linger; prepare accepted` | なし（人間が実行） |
| `delete_cgroup_real`（#2061。受け入れ条件 3） | `fandhe-container-cli` | `systemd-run --user --scope -p Delegate=yes <bin> --ignored` | `delete_cgroup_real: cli delete removed the container cgroup and state for matching, recorded and vanished scopes; refused a non-empty cgroup without killing` | なし（人間が実行） |
| `start_recover_real`（任意） | `fandhe-container-cli` | `cargo build -p fandhe-container-supervisor` で CLI の隣に supervisor を置き、`systemd-run --user --scope -p Delegate=yes <bin> --ignored` | `start_recover_real: a second cli start recovered the interrupted reservation from the recorded cgroup; delete then removed it` | なし（人間が実行） |
| `start_stop_delete_real`（任意） | `fandhe-container-cli` | `cargo build -p fandhe-container-supervisor` で CLI の隣に supervisor を置き、`systemd-run --user --scope -p Delegate=yes <bin> --ignored`（CLI の実バイナリだけで create → start → list → logs → stop → delete を通す。#2450） | `start_stop_delete_real: cli start ran the container under the production launcher; stop recorded Stopped(43); delete left no cgroup, state dir, control socket or logs` | あり（platform-ci の ubuntu。#2596） |
| `supervisor_bin_real`（任意・参考） | `fandhe-container-supervisor` | 直接 `<bin> --ignored`（試験の側で包む） | AGENTS.md の該当行を参照 | あり（platform-ci の ubuntu。#2596） |

## 結果記録の雛形

この表と #2062 のコメントの両方に記録する。ホスト名・アドレス・ユーザー名は書かない。

| 項目 | 記入 |
| ---- | ---- |
| 実施日 | (記入) |
| OS・カーネルの版 | (記入) |
| systemd の版 | (記入) |
| fandhe-container の commit（main の SHA） | (記入) |
| ID 写像のモデル（subordinate / single） | (記入) |
| シナリオ 1: create・start の終了コードと `code` | (記入) |
| シナリオ 1: 観察結果 | (記入) |
| シナリオ 1: delete の終了コードと残骸の有無 | (記入) |
| `start_scope_real` 最終行の一致 | 一致 / 不一致（出力の末尾） |
| `delete_cgroup_real` 最終行の一致 | 一致 / 不一致（出力の末尾） |
| `start_recover_real`（任意） | (記入) |
| `start_stop_delete_real`（任意） | 一致 / 不一致（出力の末尾。`scope_present_before_delete` の値も記入） |
| 後始末で残骸が無いこと | (記入) |
| CI の先行観測（参考。判定には使わない） | 直近の main の CI の `start_stop_delete_real` 最終行の一致 / 不一致 |
| 判定 | 成功 / prepare で拒否 / その他の失敗 |

## 拒否・失敗したときの扱い

方式の選択（受け入れ条件 2）はオーナーの判断で、本書では候補を選ばない。次の材料を集めて #2062 に記録する。

- `code`・`message`（stderr の JSON）
- CLI と supervisor それぞれの `/proc/<pid>/cgroup`
- 親 scope の `cgroup.procs`
- `systemctl --user status <scope>`

候補は #2062 の 3 案。#2081 で案 A（CLI が新しい scope で包む）は実装済みのため、拒否は #2081 の退行か想定外の環境差の可能性が高い。案 3（`prepare` の検証を緩める）は他者の PID を動かさない規則の変更で、選ぶ場合は security-auditor 観点の確認が必須。実装 issue の起票はオーナーが方式を選んでから行う。

## 後続

本番の `start` から `stop`・`delete` までの自動の通し試験 `start_stop_delete_real` を追加した（#2450）。CI では #2596 以降実行している。手元の実機での実行と結果の記録は人間担当（#2062・#1621）。
