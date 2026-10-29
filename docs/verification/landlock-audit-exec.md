# Landlock `LOG_NEW_EXEC_ON` 付き restrict_self の実機確認 手順書と結果記録（#2306）

ABI 7 以上の実カーネルで `landlock_restrict_self` に `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`（値 2）を渡す適用が受理され、拒否が監査ログに残ることと、`CONFIG_AUDIT=n` または監査が無効なカーネルで flags 2 が受理されるかを実機で確かめる手順と、結果記録の雛形。対応する ID は SEC-4・CORE-5・TASK-41 追補・REPAIR-12。関連 issue は [#2306](https://github.com/Fandhe-AI/fandhe-container/issues/2306)（本確認。人間担当）・#2026・#2291・#2027・#2062。

実行・結果の記録・成否の判定は人間が行う。Agent は root のコマンドを実行しない。本書のコマンドは作成時に未実行である。ホスト名・アドレス・ユーザー名・`auid` / `ses` の値・`XDG_RUNTIME_DIR` の実パスは記録しない。

## 背景

- 本番の適用（`crates/core/src/landlock/apply.rs`）は ABI 7 以上で flags 2 を渡す。失敗しても flags 0 でやり直さず起動を拒否する（fail-closed）。監査が無効なホストで flags 2 が拒否されると、そのホストで起動できなくなるおそれがある
- Agent の事前確認（非 root）: `cargo test -p fandhe-container-core --test landlock_enforcement -- --no-capture` は ABI 7 以上のホストで flags 2 を通す。出力に `abi=<n> restrict_self_flags=<0|2> audit_mode=<語彙>` の行が出る

## カーネルソースでの確認（Agent。実機未確認）

Linux v6.15 `security/landlock/syscalls.c` と `limits.h` の原文で次を確認した（v7.0 は未確認）。

| 点 | 内容 |
| -- | ---- |
| ABI | `landlock_abi_version = 7`。`LANDLOCK_CREATE_RULESET_VERSION` はこの値を返し、`CONFIG_AUDIT` に依らない |
| flags の検査 | `landlock_restrict_self` の先頭で `(flags \| LANDLOCK_MASK_RESTRICT_SELF) != LANDLOCK_MASK_RESTRICT_SELF` なら `-EINVAL`。マスクは `LOG_SUBDOMAINS_OFF` までの全ビットで、`CONFIG_AUDIT` の条件分岐の外 |
| `CONFIG_AUDIT` | ログ関連の状態更新だけが `#ifdef CONFIG_AUDIT` の中にあり、`CONFIG_AUDIT=n` では flags は受理されて無視される |

見立ては判定表の (ii)（受理される）。実カーネルでの確認は下の手順で行う。

## 事前確認

- `uname -r`（6.15 以上）
- `grep -E '^CONFIG_(AUDIT|AUDITSYSCALL|SECURITY_LANDLOCK)' /boot/config-$(uname -r)`
- `cat /sys/kernel/security/lsm` に `landlock` がある
- `systemctl is-active auditd`、`/var/log/audit/audit.log` があり読めること、`sudo auditctl -s` の `enabled`
- auditd の導入・起動の要否は人間が判断する

## シナリオ A（監査有効・受け入れ条件 1）

```bash
cargo test -p fandhe-container-core --test landlock_audit_exec --no-run   # 出力された実行ファイルのパスを控える
sudo <控えたパス> --ignored
```

`sudo cargo test` は使わない（PATH・`CARGO_HOME`・`target/` の所有者がずれるため）。成功行 `landlock_audit_exec: ok` と、audit ログの `type=LANDLOCK_ACCESS`・`blockers=fs.make_reg` の行（PID とパスだけ残し、`auid`・`ses` は伏せる）を記録する。行が出ないときは `audit_enabled` と backlog を確認する。

## シナリオ B（本番の起動・任意）

ABI 7 以上のホストで [rootless-start-cgroup.md](rootless-start-cgroup.md) のシナリオ 1 の `start` を実行し、`state.json` の `launchIsolation.landlock.audit.mode` が `kernel_audit_requested` であることを記録する。

## シナリオ C（監査無効・受け入れ条件 2）

`CONFIG_AUDIT=n` のカーネル、または監査が無効なホスト（auditd 停止・`audit=0`）で、非 root のまま次を実行する。

```bash
cargo test -p fandhe-container-core --test landlock_enforcement -- --no-capture
```

`abi=` と `restrict_self_flags=` の行と成否を記録する。拒否された場合は `landlock_restrict_self_failed` と errno を記録する。

## 判定表

| 結果 | 判定 |
| ---- | ---- |
| (i) ABI が 7 未満と報告され `restrict_self_flags=0` | 問題なし（flags 2 を渡さない） |
| (ii) ABI 7 以上で `restrict_self_flags=2` が受理される | 問題なし |
| (iii) ABI 7 以上で flags 2 が `EINVAL` 等で拒否される | 縮退方針を決める issue を起票する（flags 0 でのやり直しは監査の記録を黙って失うため、オーナーが決める） |

## 結果記録の雛形

| 項目 | 記録 |
| ---- | ---- |
| 日付 | |
| kernel 版 | |
| 検出した ABI | |
| `CONFIG_AUDIT` / `CONFIG_AUDITSYSCALL` | |
| auditd・`audit_enabled` | |
| シナリオ A（成否・audit 行〔伏せ字つき〕） | |
| シナリオ B（`audit.mode`） | |
| シナリオ C（`abi=`・`restrict_self_flags=`・成否） | |
| 判定 | |

## GitHub ホステッド runner（ubuntu-latest）での計測（#2483）

`.github/workflows/linux-env-probe.yml` の `escape-suite-probe` ジョブが、auditd の導入・`landlock_audit_exec --ignored`（シナリオ A 相当）・`escape_suite` の opt-in のカーネル監査の段を実行して Step Summary に記録する。ABI 7 は #2022 で計測済み。本計測は #2306 の実機確認（人間担当）の代わりではない。結果は人間が下表へ転記し、`platform-ci` へ組み込むかを判断する（`auid` / `ses` は伏せる）。

| 項目 | 記録 |
| ---- | ---- |
| 日付・run | |
| kernel 版・ABI | |
| `CONFIG_AUDIT` / `CONFIG_AUDITSYSCALL` | |
| auditd の導入・起動・`auditctl -s` の `enabled` | |
| `landlock_audit_exec`（root） | |
| `escape_suite` opt-in の段（root） | |
| `escape_suite` opt-in の段（非 root・ACL） | |
| `LANDLOCK_ACCESS` の件数 | |
