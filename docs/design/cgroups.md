# cgroups 対応範囲

MVP のリソース制限が cgroups v2 単独対応であることと、非対応とする範囲を定める（CORE-4）。

- 対象ビヘイビア: CORE-4（関連: SEC-6・CORE-3）
- タスク: TASK-34（MS-2）。前提は TASK-32（#153。cgroup v2 の実装）
- 関連 issue: #166
- 出典: `docs/spec/04-behavior/api-runtime-core.md` の `CORE-4`、`security-isolation.md` の `SEC-6`、`04-behavior/README.md` の制約事項・除外事項（submodule リビジョン `984f8a2`）

## 対応範囲

- cgroups v2（unified hierarchy）単独に対応する
- 非特権ユーザーに委譲された cgroup v2 サブツリー上で子 cgroup を作成し、controller（`memory`・`cpu`・`pids`・`io`）でリソースを制限する（CORE-3・SUP-13・TASK-170）

## 非対応

- cgroups v1
- hybrid 構成（`/proc/self/cgroup` に v1 の行が 1 行でも混在する構成）
- systemd cgroup driver

### 「systemd cgroup driver 非対応」の意味

- 本ランタイムは cgroupfs（`/sys/fs/cgroup` 配下）へ直接書き込んで cgroup を管理する。systemd の D-Bus API（transient unit の作成等）経由で cgroup を操作する driver は持たない
- 一方、systemd が委譲した cgroup v2 サブツリー（例: `systemd-run --user --scope -p Delegate=yes`）の上で動作することは前提環境として許容する。これは委譲を受ける側であり、driver ではない（実機前提テストの実行手順は `AGENTS.md` を参照）

## 非対応とする理由

### spec に明記された理由（SEC-6）

- cgroups v2 には `release_agent` 機構が存在しないため、cgroup release_agent を悪用するコンテナエスケープ手法（クラス 2）が構造的に無効化される
- 本書の主張はこの範囲に限る。cgroups v2 化だけでコンテナエスケープ全般を防げるとは述べない

### 実装上の理由（spec の主張ではなく、本リポの設計判断）

- 階層が単一であり、実装・検証対象を 1 系統に絞れる（改修の波及を最小に保つ。REPAIR-1）
- cgroup v2 の委譲モデルにより rootless でのリソース制限が成立し、no-internal-process 制約に沿った「子 cgroup 作成、自プロセスの退避、controller 有効化」の順序（CORE-3）を一貫して扱える
- v1 の controller ごとの階層や systemd driver を併存させないことで、攻撃面とコード量を抑える（フルスクラッチ・依存最小方針と整合）

## 実装での担保（fail-closed）

`crates/core/src/cgroups.rs` で v1 / hybrid を拒否する。

- `parse_self_cgroup_v2`: `/proc/self/cgroup` に v1 の行が混在する場合、または `0::` 行が無い場合は `FailedPrecondition`（段 `CgroupStep::ReadSelfCgroup`）で拒否する
- `verify_cgroup2`: `/sys/fs/cgroup` と対象 cgroup が cgroup2 ファイルシステム（`CGROUP2_SUPER_MAGIC`）であることを `fstatfs` で確認する（段 `CgroupStep::VerifyCgroup2`）
- 対応するユニットテスト: `core4_sec6_task32_1_parse_self_cgroup_v2_rejects_hybrid`

## exec 用の子 cgroup と `cgroup.kill`（SUP-6・SUP-4・TASK-163 追補・#1466）

exec のコマンドは、コンテナ cgroup（`<scope>/fc-<id>@<instance>`）の直下に exec ごとに作る子 cgroup `exec-<nonce>` へ入れて実行し、期限切れ・中断・worker 異常終了のいずれでも `cgroup.kill` で子孫ごと停止して削除する。

- `cgroup.kill` は Linux 5.14 以降。開けなければ exec を拒否する（fail-closed。親死亡シグナルだけへ縮退しない）
- 内部プロセス禁止規則: `fc-<id>@<instance>` は pid1 を直接持つため、その `cgroup.subtree_control` は空のままにし、`exec-*` にも controller を有効化しない。`memory.max`・`pids.max` 等は親から階層的に子孫へ掛かる
- 名前は `exec-` 接頭辞で、コンテナ用の `fc-` と衝突しない（`Pid1Target` の cgroup 完全一致照合に影響しない）
- 実装は `crates/core/src/cgroups/exec_kill.rs`・`crates/core/src/exec/cgroup_join.rs`。実機前提テストは `crates/core/tests/exec_cgroup_kill.rs`（AGENTS.md）

## デバイス cgroup（`BPF_CGROUP_DEVICE`。SEC-1・CORE-4・TASK-32 追補・#1677〜#1681）

GPU 以外のコンテナでも、許可リスト外のデバイスノードの open と `mknod` を止める。`CAP_MKNOD` は rootful の既定に残すため（オーナー判断 2026-10-10）、`mknod` と既存ノードの open を止める多層防御を層ごとに実機で照合する。

### 既定の許可リスト

OCI の default devices と同じ固定表（`DeviceAllowList::oci_default()`。#1678）。アクセスはすべて `rwm`。表にないもの（ブロックデバイス・c 5:1 console・c 10:200 tun・c 10:229 fuse 等）はすべて拒否する。mknod（`m`）も表にあるものだけに許し、runc の `c *:* m`・`b *:* m` は採らない。

| 種別 | major:minor | 名前 |
| ---- | ----------- | ---- |
| c | 1:3 | null |
| c | 1:5 | zero |
| c | 1:7 | full |
| c | 1:8 | random |
| c | 1:9 | urandom |
| c | 5:0 | tty |
| c | 5:2 | ptmx |
| c | 136:* | pts（devpts の slave） |

### 付け方

- `BPF_PROG_ATTACH`・attach flags 0 で付ける。子孫の `exec-*` は上書きも追加もできず、祖先の実効集合で継承される（`exec-*` 自身には付かない）。`BPF_LINK_CREATE` は使わない（CORE-1）
- 付ける前に問い合わせ、既存のプログラムがあれば拒否する。祖先の `BPF_F_ALLOW_MULTI`・`BPF_F_ALLOW_OVERRIDE` の扱いは `crates/core/src/cgroups/device_policy.rs` のモジュール doc を参照する
- rootless では適用しない（`DevicePolicyOutcome::NotApplied(Rootless)`。失敗にはしない）。ロードに init user namespace の `CAP_BPF`+`CAP_NET_ADMIN`（または `CAP_SYS_ADMIN`）が要り、BPF token を使わないため。rootless ではホストのノードの bind（#1660）・rootfs の `nodev`（#1676）・Landlock が残る（SEC-5）
- ローダーは core（`sys::bpf`・`cgroups::device_policy`）に置き、gpu が再利用する。GPU 付きのコンテナは既定の表に CDI の `deviceNodes` を足す（#562・TASK-129）

### 層の一覧

| 層 | 止めるもの | errno | 照合する試験 |
| -- | ---------- | ----- | ------------ |
| rootfs の自己 bind の `nodev`（#1676） | rootfs の `/dev` 以外にあるノードの open | `EACCES`（13） | `tests/default_devices.rs`・`tests/device_cgroup_layers.rs` |
| `/dev` の専用 tmpfs（#1653。`nodev` なし） | 基本の 6 種と devpts だけを置く供給の層（制限は下の 2 層が担う） | — | `tests/default_devices.rs` |
| Landlock（#1657・PR #1675） | `/dev`・`/dev/shm` での `mknod`（`MAKE_CHAR`） | `EACCES`（13） | `tests/landlock_implicit_dev.rs` |
| デバイス cgroup（#1680） | 許可リスト外の open と `mknod` | `EPERM`（1） | `tests/device_cgroup_layers.rs`（実機・root）・`tests/cgroup_device_policy_rootful.rs`／`_rootless.rs`（入口）・`tests/cgroup_device_program.rs`（評価器。ブロックデバイスの拒否は実機の試験になく、ここで照合する） |

- 順序: open は `fs/namei.c` の `may_open()` が `may_open_dev()`（`MNT_NODEV`）を `inode_permission()` 内の `devcgroup_inode_permission()` より先に評価するため、nodev の `EACCES` がデバイス cgroup の `EPERM` より先に働く。許可リストにない c 120:0 を rootfs の `opt/` で開いても `EPERM` ではなく `EACCES` になる
- `mknod`: `vfs_mknod()` が `CAP_MKNOD`（`EPERM`）の後に `devcgroup_inode_mknod()`（`EPERM`）を評価する。試験は root（`CAP_MKNOD` あり）で行うため `EPERM` はデバイス cgroup 由来で、許可リストにある c 1:3 の `mknod` が成功することを対照にする
- errno で層を区別できるのは Landlock を適用しない構成に限る（Landlock も `EACCES` を返すため）。`tests/device_cgroup_layers.rs` は Landlock・seccomp を適用しない
- 試験用の major に 120 を使う理由: 当初想定の 240 はカーネルの動的 major 割り当て（`find_dynamic_major()` は 254 から 234 へ向けて割り当てる）と重なり、開発ホストの `/proc/devices` にも `240 ttyDBC` が実在した。devices.txt で char 120-127 は LOCAL/EXPERIMENTAL USE で動的割り当ての範囲の外にある
- 実機での実行は人間担当で、結果は #1621 に記録する（AGENTS.md「実機前提テスト」）

## OCI `linux.resources` の写像（TASK-29 追補・#2019・CORE-3・CORE-4・SEC-1・SUP-13）

`config.json` の `linux.resources` のうち、cgroup v2 で表せて setter がある項目を create / start で受理し、start の cgroup 連鎖（`record_scope` → `create_cgroup` → `apply_limits` → `into_join`）の `apply_limits` が委譲 cgroup の制限ファイルへ書く。`enable_controllers` を呼べるのは退避済みの証明を持つ `apply_limits` の中だけなので、controller の有効化と setter の呼び出しはそこに置く。controller が委譲に無ければ `FAILED_PRECONDITION` で止まり、制限なしでは起動しない。

### 受理する項目

| OCI のキー | 書き先 | 値の規則（逸脱は `INVALID_ARGUMENT`。メッセージはキー名だけ） |
| --- | --- | --- |
| `memory.limit` | `memory.max` | `-1` は `max`、`> 0` はバイト数。`0` と `< -1` は拒否 |
| `memory.swap`（メモリ + swap の合計） | `memory.swap.max` | `-1` は `max`。`> 0` は `limit` がバイト数で `swap >= limit` のとき `swap - limit` を書く（runc の v2 変換と同じ）。それ以外は拒否。swap accounting が無いホストでは `FAILED_PRECONDITION` |
| `cpu.quota` / `cpu.period` | `cpu.max` | quota は `-1` か `> 0`。period の範囲は `CpuMax` の検証に従う。period だけの指定は quota 無制限 |
| `pids.limit` | `pids.max` | `-1` か `1..=PIDS_MAX_LIMIT` |
| `blockIO.weight` | `io.bfq.weight` / `io.weight` | `10..=1000` |
| `blockIO.throttle{Read,Write}{Bps,IOPS}Device[]` | デバイスごとに 4 項目を 1 つにまとめた `io.max` | rate の `0` と `u64::MAX` は拒否。同じリスト内の重複デバイスは拒否。1 リスト 64 件まで |

cgroup v2 の範囲に収まるかは Linux では create の時点でも検査する（`cgroups::ResourceLimitPlan`）。start は手順 5 で同じ変換を行って書き、書いた値を launcher に渡す。launcher は fork の前に `config.json` の値との一致を確かめ、手順 5 と手順 8 の間に config が書き換えられた場合は `FAILED_PRECONDITION` で拒否する。

### 拒否する項目

setter が無い既知の項目は未適用として記録し、create / start が `UNIMPLEMENTED`（`unsupported config fields: <キー>`）で拒否する: `memory.{reservation,kernel,kernelTCP,swappiness,disableOOMKiller,useHierarchy,checkBeforeUpdate}`、`cpu.{shares,cpus,mems,realtimeRuntime,realtimePeriod,burst,idle}`、`blockIO.{leafWeight,weightDevice,leafWeightDevice}`、`hugepageLimits`、`network`、`rdma`、`unified`、`devices`。`rdma` と `network` は cgroup v2 で扱いにくいため拒否を続ける。

`linux.resources` とその下の object の未知のキーは、OCI の「未知のプロパティは無視する」規則から外れて `INVALID_ARGUMENT` で拒否する。新しい版の spec にある制限を黙って落とし、指定より弱い資源制限で起動する経路を作らないため（SEC-1）。`resources: {}` も cgroup が必要な指定として扱い、値による「不要」判定への精緻化はしない（#2010の判断）。未対応の既知キー（`memory.reservation` 等）は制限が空の `LinuxResourceLimits` に正規化されて空に見えるため、値だけで判定すると fail-open になる。本番の start は常に supervisor の cgroup 連鎖で join の手段を渡すので、精緻化の実益も無い（SEC-1・CORE-3）。

### `linux.cgroupsPath`

型つき（4096 バイト以下・空と NUL は拒否）で保持するが、コンテナの cgroup は常に委譲スコープ配下の `fc-<id>@<n>` に置かれ、値を配置に使わない方針とする（#2010 の判断）。状態記録・記録済みスコープの検証つき削除（#2060）がこの配置を前提にしており、systemd cgroup driver は対象外（TASK-32）で `slice:prefix:name` 形式を解釈する必要も無いため。指定があれば値に関わらず（`..`・絶対パス・別表記を含め）`cgroup_requirement::check_cgroups_path` が create / start で fork 前に `UNIMPLEMENTED` として拒否する。受理に開く場合は、委譲スコープ配下に閉じる検証（`..`・絶対パス・symlink・別表記の拒否）と状態記録との整合を前提とし、オーナー判断を経て別 issue で扱う。CRI の `cgroup_parent` の受け入れ方針は判断記録 [cri-cgroup-parent.md](cri-cgroup-parent.md)（#2672・CRI-2・CORE-4）にまとめている。

## 前提環境（委譲スコープの作り手。#2081・CORE-3・CORE-4・SUP-1・CLI-1）

supervisor の `DelegatedCgroup::prepare` は、委譲された親 cgroup に自分以外のプロセスが 1 つでもあると拒否する。このため CLI の `start` は、supervisor を CLI と同じ cgroup ではなく、`systemd-run --user --scope --quiet -p Delegate=yes --`（`start_contract::USER_SCOPE_WRAPPER_ARGS`）で包んで起動し、新しい scope の中で一人で動かす。

- systemd-run は scope の登録後に同じプロセスで supervisor を exec する。spawn した pid・プロセスグループ・stdio はそのまま supervisor のものになり、CLI は scope に居残らない（根拠は `man systemd-run` と systemd の `src/run/run.c` の `start_transient_scope`。実機での照合は `crates/cli/tests/start_scope_real.rs`）
- systemd-run は固定候補（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`）から解決し、`PATH` 探索はしない（PLUG-11）。実体が root 所有の通常ファイルで、実体と祖先ディレクトリの group / other に書き込み権が無いことを確かめてから使う。検証から exec までの TOCTOU は、root 所有で非 root が書けない場所に限ることで抑える
- 渡す環境は `PATH`（固定値）と `XDG_RUNTIME_DIR`（絶対パスを検証）だけ。`DBUS_SESSION_BUS_ADDRESS` は渡さない（任意プログラムの起動や接続先の付け替えを防ぐ。user マネージャの直結ソケット `$XDG_RUNTIME_DIR/systemd/private` だけで足りる）
- fail-closed: 次の場合は spawn の前に機械可読な `code` / `message` で失敗する。CLI の cgroup の下に子 cgroup を作る方式（案 B）へは落とさない

| 条件 | code |
| ---- | ---- |
| rootful（uid のどれかが 0。SEC-5） | `UNIMPLEMENTED` |
| `/proc/self/status` が読めない | `FAILED_PRECONDITION` |
| systemd-run が無い、または信頼できる実行ファイルでない | `FAILED_PRECONDITION` |
| `XDG_RUNTIME_DIR` が絶対パスでない、または user マネージャの直結ソケットが euid 所有のソケットでない | `FAILED_PRECONDITION` |
| 委譲が効いていない（`Delegate=yes` が反映されない等） | supervisor の `detect` / `prepare` が報告したコード |

- 簡易実装（REPAIR-3）: 結果の 1 行が無いまま EOF のとき、supervisor の異常終了と systemd-run の失敗（D-Bus 接続の失敗等）を区別できない（`INTERNAL`）。制御チャネル（#2058）の後の課題とする
- 上記の「systemd cgroup driver 非対応」との関係: CLI は systemd-run を起動して scope を 1 つ作らせるだけで、D-Bus を自分では話さない。scope の中の cgroup 操作はすべて cgroupfs へ直接行う。CORE-4 の言い回しとの整合は spec 側の判断事項として報告する
- CI では platform-ci の ubuntu が `start_scope_real` も回す（#3105）。実機の OS・カーネル版での実行は人間担当で、結果は #2062 に記録する（手順は [rootless-start-cgroup.md](../verification/rootless-start-cgroup.md)。`AGENTS.md`「実機前提テスト」の `start_scope_real`・`supervisor_bin_real`）

## 関連・後続

- TASK-35（SEC-6・CORE-4）で release_agent 悪用手法の無効化確認を記録する。本書は当該確認が済んでいるとは主張しない

## 見直し

CORE-4 / SEC-6 が spec 側で変更された場合、または v1・systemd cgroup driver 対応をスコープに加える場合は、spec（SSOT）でビヘイビア・タスクを定義したうえで本書を更新する。
