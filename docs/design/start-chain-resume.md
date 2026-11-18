# 回復後に start の連鎖を再開する API と回復結果の構造化ログ

CORE-2・OCI-6・REPAIR-4・SEC-1。TASK-29 追補・#2245（前提: #2011・PR #2210）。

## 目的

`recover_interrupted_start` は、中断された start の予約（Running・pid なし）を、記録済みの cgroup 配置から残存プロセスの
不在を確かめたうえで Created へ戻す。戻した後のレコードは配置が記録済みのまま残るため、次の 2 点が未解決だった。

1. `DelegatedCgroup::record_scope` は記録済みを拒否し、StateStore の契約 8 も配置の上書きを禁じていた（#4814 で不在を確かめた後の記録し直しを足した）。delete と再作成なしに
   同じコンテナを start し直す入口が無かった
2. 回復結果の内訳（`RecordedCgroupOutcome`: `AlreadyAbsent`・`WasEmpty`・`Killed`）を `ProductionLauncher` が捨てており、観測に残らなかった

## 決定（本 PR）

### 回復結果の内訳

- `ProcessLauncher::confirm_no_process_recorded_detailed` を、既定実装つきで追加した（`confirm_no_process_recorded` の
  シグネチャは変えない）。成功値 `NoProcessEvidence` は `LaunchLedger`・`RecordedCgroup(RecordedCgroupOutcome)`・`Unreported`
  （`#[non_exhaustive]`）。既定実装は従来のメソッドへ転送して `Unreported` を返す（確認は省かない）
- `ProductionLauncher` は判定の経路を detailed の 1 本にし、従来のメソッドは結果を捨てる薄い形にした
- ラッパー（supervisor の `restart.rs`・`pasta_attach.rs`）は detailed も内側へ転送する。転送漏れは `Unreported` への縮退
  （観測の欠落）に留まり、安全性は従来のメソッドが担保する
- `recover_interrupted_start_reported` が `RecoveredStart`（レコードと根拠）を返す。`recover_interrupted_start` はその薄い
  ラッパーで、既存の呼び出し元は変えない。期限・所有ロック・読み直しの順序は不変
- `RecoveredStart::encode_log_line` が共通ログ型 `LogLine`（#653）の 1 行（level `info`・event `interrupted_start_recovered`・
  本体 `outcome`）を組む。語彙は `launch_ledger`・`already_absent`・`was_empty`・`killed`・`unreported`。パス・errno・pid・ID は載せない
- supervisor の本番の `recover_interrupted` が、その行を遅延バッファ（`flush_deferred_logs` が報告の後に出す）へ積む。
  符号化できなくても回復の成否は変えない

### 再開 API `DelegatedCgroup::resume_recorded_scope`

回復後の Created（配置が記録済み）から `CgroupScopeRecorded` を返し、以後は既存の
`create_cgroup` → `apply_limits` → `into_join` に進める。順序（破壊的な操作の前に照合と CAS）:

1. `observed` が Created・pid なし・配置が記録済み（満たさなければ `FailedPrecondition`）
2. 検出した委譲スコープが記録済みのスコープと文字列で **一致する**か、一致しなければ **記録し直す**（#4814。下の「配置の記録し直し」）
3. 一致したとき: `observed.revision()` での CAS で状態を書く（配置は契約 8 で引き継がれ、revision だけが進む）。配置が保たれたことを照合し、
   食い違えば `Internal`（この時点で mkdir していない）
4. 一致したとき: 残った `fc-<id>@<instance>` を既存の fd 起点の削除経路で消す。プロセスが居れば kill せず元の code を保って失敗する
   （止めるのは回復の責務で、再開に破壊的な停止の経路を増やさない）

段は新設の `CgroupStep::ResumeScope`（`resume_scope`）。

### 配置の記録し直し（#4814・#4779 の決定・案 B）

StateStore の契約 8 を「配置は記録したものだけが正。記録し直すのは、旧い配置の不在を確かめたときだけで、`observed.revision()`
での CAS で行う」に改めた（`crates/core/src/traits/state_store.rs`）。拡張点トレイトの契約の変更（PLUG-1）で、別の実装（plugin）も
同じ規則に従う。

- 要求: `UpdateStateRequest::with_cgroup_scope_replacement(scope, absent)`。`absent` は不在の証跡 `CgroupPlacementAbsence` で、
  コンストラクタは core の crate 内に閉じる（証跡なしでは要求を作れない）。追記（`with_cgroup_scope`）とは排他
- ストア: 「不在なら `NotFound`」→「revision が合わなければ `FailedPrecondition`」→「既存の配置が証跡の配置と一致しなければ
  （配置が無い場合を含む）`FailedPrecondition`」の順に照合し、合えば新しいスコープと書き込み直前の revision（instance）の組を書く。
  失敗したときはレコードを変えない。新しい instance は使われたことのない revision で、旧い instance と重ならない
- 再開の手順 2（不一致のとき）: 記録のスコープを検証つきで開き、旧い `fc-<id>@<instance>` を `cgroup.kill` を書かずに消す
  （`recorded_scope::remove_recorded_without_kill`。無ければそのまま）→ 証跡を添えた CAS で新しい配置を書く → 書いた配置を照合する
  （食い違えば `Internal`）。**旧い配置を消してから新しい配置を書く**。旧い配置にプロセスが居る（回復していない）ときは何も止めず、
  ストアにも触れずに `FailedPrecondition`（`could not confirm that the recorded cgroup placement is absent; recover the container first`）
- 消した後の CAS が負けた場合（並行する再開・古い `observed`）は、旧い配置が記録に残る。その cgroup は消えているため、delete は
  `NotPresent` として扱う（何も止めていない）
- delete: 記録し直した後の配置（新しいスコープと instance）でだけ照合する。旧い配置は照合にも削除にも使わない
- spec: OCI-5（`api-oci-image.md`）は状態ファイルのパスだけを定め、契約 8 に当たる記述（配置を 1 回だけ記録する）は無い。OCI-6 の
  「start のときに記録した委譲スコープ」は記録し直した後のスコープとも矛盾しない（spec の commit `ee3f631` を読んで確かめた）

### 残余の競合

CAS で直列化した後も、先行する再開の `prepare` の後・launch の前に、後続の再開の手順 4 が先行の空の cgroup を消しうる。
その場合、先行の参加フックは削除済みの cgroup へ参加できず（`cgroup.procs` への書き込みが失敗）、launch は fail-closed で
失敗する（cgroup の外では起動しない）。

## 未解決（オーナー判断待ち）

CLI の `start` は、`systemd-run --user --scope --quiet -p Delegate=yes --` で supervisor を毎回新しい一時 scope に置く
（unit 名の指定なし）。このため 2 回目の start の supervisor が検出する委譲スコープは、1 回目に記録されたスコープと
原則として一致せず、本 API は不一致で `FailedPrecondition` になる（1 回目の scope はプロセスが居なくなれば消え、回復は
通常 `AlreadyAbsent` で終わる）。CLI 経路で実際に再開できるようにする選択肢（#4779 で案 B に決まり、契約と再開 API は #4814 で
改めた。本節の残りは #4780 で直す）:

| 案 | 内容 | 影響 |
| -- | ---- | ---- |
| A（本 PR） | 一致時のみ再開。不一致は fail-closed | 契約・CLI を変えない。CLI 経路では再開できない |
| B | StateStore の契約 8 の改訂（旧配置の不在を確かめたうえでの再記録を許す） | 拡張点トレイトの契約変更（PLUG-1）。delete が配置で照合する前提に触れる |
| C | supervisor の scope の unit 名をコンテナごとに決定的にする | 同名 unit の同時起動・残存の扱いを `start_contract` で決める必要がある |

supervisor の入口（手順 3 で回復した後に start を続け、配置が記録済みなら `resume_recorded_scope` を使う）の結線は、
`start_recover_real` の期待値（終了コード 5・固定文言）、CI の成功行の照合、`docs/verification/real-machine-tests.md`、
`ci.md` を同時に変えるため、判断後の別 issue とする。

## 検証

- 既定の集合: `start_chain.rs`（再開の成功・前提の拒否・配置を落とすストア）、`start.rs`（`Unreported`・ログ行のバイト列）、
  `launcher.rs`（3 種の内訳）、`logging/err4_cross_check.rs`（共有検査器）
- 実機前提: `crates/core/tests/confirm_recorded_cgroup.rs`（回復結果の内訳と、シナリオ C の記録し直しによる再開〔#4814〕、シナリオ E の再開から `create_cgroup`）。
  実行と結果の記録は #1477（人間担当）
