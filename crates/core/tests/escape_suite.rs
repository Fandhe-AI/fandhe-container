//! 攻撃テストハーネス基盤（SEC-2・TASK-42.1・#199。親は TASK-42・#198）。
//!
//! PoC-9（`03-poc/security-isolation`）で定めた最小攻撃セット ESC-01〜ESC-10 を CI 自動テストスイート
//! として実装する TASK-42 の土台。各 ESC ケースは `linux::CASES` へ `EscapeCase` を 1 行追加するだけで
//! 実装できる（ESC-01〜03 は #200、04〜06 は #201、07〜08 は #202、09〜10 は #203 で実装済み）。
//!
//! # ESC-01〜03（SEC-2・TASK-42.2・#200）の検証範囲と監査（SEC-4）の扱い（REPAIR-3）
//! - ESC-01（ホスト FS 書き込み）: ホスト側に用意した canary ファイルへ、ホスト絶対パス・`/proc/1/root`・
//!   `/proc/self/root` 経由で書き込みを試み、いずれも成功しないこと、およびホスト側で canary が無変更
//!   （内容一致・余計なファイルなし）であることをディスパッチ側で観測する。加えて readonly root への書き込みが
//!   EACCES（Landlock 適用下）で拒否されることを確認する。EACCES は DAC でも返り得るため層の厳密な証跡ではない
//! - ESC-02（ホスト PID namespace）: 監査記録は要求しない（拒否ではなく不可視であることの観測）
//! - ESC-03（`mount(2)`）: 拒否主体は組み込み seccomp の `ERRNO(EPERM)`（と capability 削減）
//! - 監査（SEC-4）: 攻撃コード自身が記録ヘルパを呼んで作った記録は監査成功の証拠にならない。監査の証拠は
//!   コンテナの外で回収した本番の配送経路の出力だけで、子の記録（pipe）の `audit=` 行は拒否する。
//!   ESC-03 は `USER_NOTIF` 版の filter の通知を応答者が本番の記録先へ記録した `@audit.log` の行、ESC-01 は
//!   カーネル監査の `LANDLOCK_ACCESS`（opt-in の段）で照合する（#2028。下の「監査の照合」節）
//!
//! # シナリオプロセスのスレッド制約（#2319）
//! シナリオプロセスは `isolate()` の後にスレッドを作れない（`unshare(CLONE_NEWPID)` をした本人の `CLONE_THREAD` は
//! `clone(2)` が EINVAL にする）。isolate の前も `CLONE_NEWUSER` と `fork_single_threaded` の単一スレッド要件で
//! 作れない。そのため記録の回収と ESC-03 の応答は単一スレッドで行う。ケースや補助処理を足すときは、シナリオ側で
//! `thread::spawn` / `Builder` / `scope` を使わない（dispatcher 側は isolate しないので使ってよい）。
//!
//! # 共通関数の流れ（コンテナ起動 → 攻撃 → 判定 → 後始末）
//! `linux::run_case`（ディスパッチャ）が排他作成した一時 rootfs を用意し、自身を
//! `--scenario <case-id> <rootfs>` で再起動する（`unshare(CLONE_NEWPID)` の後に PID 1 になれるのは最初の
//! 子だけのため、ケースごとに別プロセスにする）。シナリオは分離（`isolate`）→
//! `spawn_container_probe`（制限ステージ通過後の子で攻撃クロージャを実行）→ 子の終了待ち（期限付き）→
//! 子が pipe へ書いた記録（攻撃の結果のみ）の回収 → stdout の 1 行（`escape_suite-meta`。終了状態・結果・
//! 子の pid・開始時刻）でディスパッチャへ報告する。ディスパッチャが本番の監査記録を回収して `judge` で判定し、
//! 終了後に rootfs と状態ルートを削除する。結果は構造化型（`CaseVerdict`）で返す。
//!
//! # 判定の対象
//! - 攻撃の結果: 許可された結果の集合（`Expectation::allowed`）に入るか。ESC-06 のようにシグナル終了を
//!   期待するケースは `Expectation::signal` で指定する
//! - 監査ログ: `AuditExpectation::Required` のケースは、本番の配送経路の出力（`AuditSource`）が期待どおりで
//!   なければ失敗する。`AuditExpectation::Deferred` は spec 上は要求するが、この試験からは本番の経路を駆動
//!   できないため合否に使わない（現状は ESC-06 だけ）。判定はコンテナの外（ディスパッチャ）で `judge` が行う
//!
//! # 監査の照合（SEC-4・TASK-41 追補・TASK-43・#2028。監査配送 7/7）
//! - `AuditSource::StateRootLog`（既定の `--ignored` の段。root 不要）: ケースごとに排他作成する 0700 の一時状態ルート
//!   の `@audit.log` を、シナリオ終了後にディスパッチャが上限つきで回収し、件数（ちょうど）・層・コンテナ ID・
//!   seccomp 層の syscall 番号と arch と攻撃した子の pid を具体値で照合する。
//!   - ESC-03: `spawn_container_probe_with_seccomp_listener`（`ErrnoDelivery::UserNotif` ＋ `NEW_LISTENER` ＋ `SCM_RIGHTS`
//!     による listener の受け渡し〔本番と同じ検証〕）で子を起動し、シナリオ側の応答ループ（単一スレッド）が通知ごとに
//!     `record_seccomp_denial_for` → `ControlAuditRelay` → `FileAuditSink` で記録して `-EPERM` で応答する。
//!     応答ループ自体は試験側が core の公開 API だけで組む（supervisor の `SeccompNotifyHub` の試験ではない。
//!     それは `crates/supervisor/tests/seccomp_notify_audit.rs` が担い、ESC-03 と同じ攻撃を本番の supervisor bin が
//!     起動した実コンテナで通す照合は `crates/supervisor/tests/supervisor_bin_real.rs` のシナリオ E〔実機前提・#2482〕が担う）
//!   - ESC-08（bind の元）: `create` → `start` に、マウント元が rootfs・bundle・状態ルートの bind を渡し、
//!     本番の `start` の拒否経路（`validate_bind_mounts` → `audit_bind_mount_error` →
//!     `ProcessLauncher::rejection_audit_sink` → `FileAuditSink`）が出した mount 層の記録を要求ごとに 1 行（計 3 行）
//!     照合する。launcher は `rejection_audit_sink` を返すだけの最小実装（本番の `ProductionLauncher` は構築に
//!     ホストの前提を要する）。この試験は単一スレッドで `start` を呼ぶため `FileAuditSink` を使う。本番の
//!     supervisor の `start`（複数スレッド）が relay 経由で届くことは supervisor の結合試験
//!     `start_bind_audit_relay` が照合する（#2481。`docs/design/audit-delivery.md`）
//! - `AuditSource::KernelAudit`（opt-in の段。環境変数 `FANDHE_CONTAINER_TEST_KERNEL_AUDIT=1`）: Landlock の拒否の
//!   本番の記録はカーネル監査の `AUDIT_LANDLOCK_ACCESS` だけ（core は `LOG_SAME_EXEC_OFF` を渡さない）。ESC-01・ESC-07
//!   （Landlock 帰属）・ESC-10 は、ホストの `/var/log/audit/audit.log` のケース開始後の追記から、`blockers=` の
//!   要素・同じイベント連番の `SYSCALL` の `pid`（攻撃した子のホスト pid）・時刻の下限をフィールド完全一致で
//!   照合する。root か audit ログの読み取り権限・auditd・Landlock ABI 7（Linux 6.15 以降）が要る。
//!   opt-in なしでは攻撃結果だけを照合し、監査は `verdict=audit-not-verified` として出力する（合格に数えない）。
//!   opt-in で前提が欠けたら skip せず失敗にする
//! - 残余（実装済みを装わない。REPAIR-3）: ESC-06（`KILL_PROCESS` の 3 件）の監査は `Deferred`（追跡: #2236・#2237）。
//!   `USER_NOTIF` では届かず、補助の `exit_signal` は本番 launcher の回収点が出し、正の記録はカーネルの
//!   `AUDIT_SECCOMP` で fandhe は自前の読み手を持たない。`create` のパース時の destination 拒否
//!   （`esc-08-config-destination`）は本番の `create_audited` が `@audit.log` へ記録する（#2480）。start の TOCTOU
//!   再検証（create 後に `config.json` の destination を書き換えて `start`。`esc-08-start-destination-rewrite`）も
//!   本番の `start` → `rejection_audit_sink` → `FileAuditSink` が mount 層 3 行を記録する（#2594・#2641）。
//!   plugin-cri の `create` と supervisor の `start` の relay 経由は結合試験
//!   `crates/plugin-cri/tests/create_destination_audit_relay.rs`・`crates/supervisor/tests/start_destination_audit_relay.rs`
//!   が照合する（`docs/design/audit-delivery.md`）
//!
//! # 構成
//! - 常に走る部分（3 OS 共通・既定のテスト集合）: 判定ロジック `judge` と記録パーサの自己テスト
//! - 実機前提部分（Linux x86_64 / aarch64。`-- --ignored` 指定時のみ）: 上記の共通関数を実機で実行する
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可する Linux ホスト（namespace 分離: PID / mount / UTS / IPC、
//! 非 root 時は user を追加）が必要。AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` や
//! Docker 既定 seccomp 下の開発コンテナでは分離に失敗する。GitHub ホステッド runner で保証できないため
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。実行コマンド:
//! `cargo test -p fandhe-container-core --test escape_suite -- --ignored`。実行された場合は分離の拒否・
//! 事前条件の不成立を含めあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。ただし起動ユーザー
//! （root / 非 root）で前提が成立しないケース（`LauncherRequirement`）は、そのケースだけを合格ではなく
//! 「対象外」（`verdict=not-applicable`）として理由とビヘイビア ID を出力し、他のケースは実行する。分離方式（TASK-42.6・#204）は
//! `harness = false` ＋ `--ignored` 引数ゲートで確定（CLONE_NEWUSER は単一スレッド前提で libtest と相容れないため
//! `#[ignore]` や feature flag は使わない）。既定の集合では自己テストのみ走る。既定の `--ignored` の段
//! （非 root）は `platform-ci`（ubuntu）で実行する（#2016）。root の分岐とカーネル監査の opt-in の段は
//! CI 外（#206・#2483）。実行条件は AGENTS.md「実機前提テスト」節を参照。
//!
//! # ESC-04〜ESC-06（TASK-42.3・#201・MS-2）
//! - ESC-04（cgroup の `release_agent` 書き込み）・ESC-05（`/proc/sys`・`/proc/sysrq-trigger` 書き込み）は、
//!   書き込み用に「開くだけ」で判定し 1 バイトも書かない（制限が欠けてもホストへ作用させないため）。
//!   ESC-04 は対象（`sys/fs/cgroup/release_agent`）を rootfs に実在させ `Absent` を受理しない。ESC-04・05 の
//!   拒否は、実行層が `setup` の有無によらず pivot 前に常に適用する読み取り専用の固定集合（`crate::path_masks` の
//!   `READONLY_PROC_PATHS` と `READONLY_SYS_PATH`。適用は `exec::path_masks`。SEC-2・TASK-29 追補・#1850）が担う。
//!   覆う固定集合（`MASKED_PROC_PATHS`。#1851）は `setup` 指定時のみ適用され `spawn_container_probe`（`setup` なし）
//!   では適用されないが、ESC-04・05 の対象はいずれも読み取り専用側に含まれるため最小構成でも拒否される。
//!   ESC-04 は `/sys` 全体の読み取り専用化で `EROFS` になり、`has_mask_evidence` の証拠には頼らない。ESC-05 は
//!   `/proc/sys`・`/proc/sysrq-trigger` の読み取り専用化による（rootful は `EROFS`。rootless は権限検査が先に
//!   `EACCES` を返し得るため、読み取り専用マウントの証拠で受理する）。実機で失敗した場合は判定を緩めず
//!   #1850・#1851 の実装不具合として扱う（期待は変えない）。
//!   適用範囲の限定: ESC-04 は rootfs 内の「通常の空ファイル」への書き込み拒否（`maskedPaths` / `readonlyPaths`
//!   相当のパスマスク）だけを検証し、実際の cgroup v1 `release_agent`（v1 階層の mount 経路）は検証しない
//!   （v1 の mount 拒否は `tests/seccomp.rs`、ホスト側根拠は `tests/cgroups_release_agent.rs`）。
//!   ESC-04・05 とも `EROFS` はそれ自体を読み取り専用の証拠として受理し、ホスト側の権限拒否でも返る
//!   `EPERM` / `EACCES` は、対象パスに実際に適用されるマウント（mountinfo の親子関係から特定する実効マウント）が
//!   読み取り専用であるという証拠（`has_mask_evidence`）がある場合だけ受理する。拒否理由別のより厳密な判定と
//!   実 cgroup v1 の安全な観測は REPAIR-12 の後続課題
//! - ESC-06（禁止 syscall の SIGSYS 強制終了＋監査記録）: SIGSYS での強制終了は spec の期待どおり必須とする。
//!   現行の CORE-5 フィルタは `unshare`・`ptrace`・`kexec_load` を `SECCOMP_RET_KILL_PROCESS` で拒否する
//!   （`DeniedSyscall::deny_action`。#1834）ため、子は SIGSYS で終了する。戻って終了コード 0 になれば失敗（fail-closed）。
//! - ESC-06 の監査（SEC-4）は `AuditExpectation::Deferred`（追跡: #2236・#2237）とし、合否に使わない。
//!   理由: `KILL_PROCESS` の 3 件は `USER_NOTIF` に載らず（ERRNO 側の 40 件だけが載る）、子が SIGSYS で終了すると
//!   子からは記録を書けない。本番の記録は、本番 launcher の回収点が出す補助の `exit_signal`（この試験の入口
//!   `spawn_container_probe` では作られない）と、カーネルの `AUDIT_SECCOMP`（fandhe は自前の読み手を持たず、
//!   読み手の設計と複数スレッド・rootless・子孫でも確実に残す条件が #2236・#2237 の結論待ち）である。
//!   親側で記録を推測生成すると監査の偽造になるため行わない。
//! - 将来仕様（REPAIR-3）: #2236・#2237 の結論が出たら、その本番経路の出力を回収して照合する `Required` へ切り替える
//!
//! # ESC-09・ESC-10（TASK-42.5・#203）
//! - `esc-09-userns-owner`（SEC-5）: コンテナ内 root が作成したファイルの所有者を、ディスパッチャ（分離なし・
//!   ホスト視点）が `EscapeCase::host_check` で検査し、起動ユーザーの非特権 UID/GID（≠ 0）であることを具体値で
//!   照合する。**非 root 起動でのみ検証できる**（root 起動は user namespace なしでコンテナ内 root = ホスト root に
//!   なるため）。root 起動時はディスパッチャが ESC-09 のシナリオを起動せず、ESC-09 だけを対象外として理由と
//!   SEC-5 を出力し（`ESC09_LAUNCHER`）、他のケースは実行する。非 root 起動では必ず実行する。
//!   subuid 範囲の写像は `rootless_uid_mapping.rs`（TASK-44）の担当で、
//!   本ケースは既定経路（単一 ID 写像）を対象にする
//! - `esc-10-landlock-outside`（CORE-5・SEC-4）: readonly root（READ のみ許可）の下で許可外の作成が `EACCES` で
//!   拒否されること。Landlock ABI 6+（Linux 6.12+）が必須。spec が求める landlock レイヤーの監査記録は、
//!   カーネル監査の `LANDLOCK_ACCESS`（`blockers=fs.make_reg`）を opt-in の段で回収して照合する（SEC-4・#2028）
//! - `control-esc-10-no-landlock`: 同じ操作が Landlock なしでは成功する否定対照（拒否が DAC 等ではなく Landlock
//!   に帰属することの裏付け）
//!
//! ESC-01・ESC-07・ESC-10（Landlock を使うケース）は Landlock ABI 6+（Linux 6.12+）を要する。
//!
//! ケースの攻撃操作は、制限が欠けていてもホストへ副作用が出ない引数・対象に限る（`seccomp.rs` と同方針）。
//! 攻撃クロージャ・ハーネスは `unsafe` を書かない。raw syscall が要る攻撃は core 側の `#[doc(hidden)]`
//! プローブ（syscall 本体は `sys` モジュール）を経由する。
//!
//! # fork 子で観測する理由（ESC-03・ESC-06。#2630・CORE-5・REPAIR-3）
//! `spawn_container_probe` と `_with_seccomp_listener` を使い続け、ESC-03・ESC-06 を含めてエントリポイント内へは移さない。
//! - seccomp フィルタ・`NO_NEW_PRIVS`・Landlock のドメイン・マウントの状態は execve をまたいで変わらないため、
//!   組み込み `Seccomp` 段の後の fork 子の観測は exec 後と同じフィルタによる
//! - ESC-03: USER_NOTIF の listener の受け渡しと応答ループ・`@audit.log` の照合を ESC-01〜10 の 1 つのハーネスで扱っており、
//!   exec 後の対応物は `supervisor_bin_real` のシナリオ E（本番の `SeccompNotifyHub` 経由）と `production_launcher` のシナリオ J
//! - ESC-06: exec 後の対応物は `seccomp.rs` の `kill-<名前>` と `production_launcher` のシナリオ K
//! - 移す条件（後続）: 本 suite の `platform-ci` への組み込みは済んだ（#2016）が、移行は ESC-06 の監査の解消
//!   （#2236・#2237）の結論待ちで、移行時に観測の同等性を CI で確かめる

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(target_os = "linux")]
#[path = "support/proc_status.rs"]
mod proc_status;

use std::fmt;

/// errno / シグナル番号（asm-generic の値で x86_64・aarch64 とも共通）。
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const EROFS: i32 = 30;
const SIGSYS: i32 = 31;

/// ESC-04 が受理する結果（SEC-2・TASK-42.3・MS-2）（権限・読み取り専用による拒否のみ）。対象を rootfs に実在させて観測するため、
/// 対象の不在（`Absent`）は「防御を検証できていない」ことを意味し、受理しない（SEC-2）。
const ESC04_ALLOWED: &[AttackOutcome] = &[
    AttackOutcome::Errno(EPERM),
    AttackOutcome::Errno(EACCES),
    AttackOutcome::Errno(EROFS),
];

/// ESC-05 が受理する結果（SEC-2・TASK-42.3・MS-2）（対象の不在・権限・読み取り専用による拒否）。
const ESC05_ALLOWED: &[AttackOutcome] = &[
    AttackOutcome::Absent,
    AttackOutcome::Errno(EPERM),
    AttackOutcome::Errno(EACCES),
    AttackOutcome::Errno(EROFS),
];

/// ESC-04 の期待（SEC-2・TASK-42.3・MS-2。spec は監査記録を要求しない）。
const ESC04_EXPECT: Expectation = Expectation {
    allowed: ESC04_ALLOWED,
    signal: None,
    audit: AuditExpectation::None,
};

/// ESC-05 の期待（SEC-2・TASK-42.3・MS-2。spec は監査記録を要求しない）。
const ESC05_EXPECT: Expectation = Expectation {
    allowed: ESC05_ALLOWED,
    signal: None,
    audit: AuditExpectation::None,
};

/// ESC-06 の期待（SEC-2・SEC-4・TASK-42.3・MS-2）。SIGSYS での強制終了を要求する。
///
/// spec は seccomp 監査記録も要求するが、`KILL_PROCESS` の 3 件は子が SIGSYS で終了するため `USER_NOTIF` では
/// 届かず、正の記録はカーネルの `AUDIT_SECCOMP`（fandhe は自前の読み手を持たない）と、補助の `exit_signal` レコード
/// （本番 launcher の回収点が出す）になる。どちらもこの試験の入口（`spawn_container_probe`）からは駆動できず、
/// 読み手の設計と複数スレッド・rootless・子孫での確実な記録の結論が出ていないため、監査は
/// `Deferred`（#2236・#2237）とし合否に使わない（SEC-4・REPAIR-3）。結論が出たら `Required` へ切り替える
/// （詳細はモジュール doc の ESC-04〜ESC-06 節）。
const ESC06_EXPECT: Expectation = Expectation {
    allowed: &[],
    signal: Some(SIGSYS),
    audit: AuditExpectation::Deferred {
        layer: "seccomp",
        tracking: "#2236, #2237",
    },
};

/// ESC-06 が発行する禁止 syscall 名（`DeniedSyscall::ALL` の名前と一致していること）。
const ESC06_PROBED: [&str; 3] = ["unshare", "ptrace", "kexec_load"];

/// 攻撃操作の結果（子が観測した事実）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackOutcome {
    /// 操作が成功した（許可された）。
    Succeeded,
    /// errno 付きで失敗した。
    Errno(i32),
    /// 操作の対象が存在しない・見えない（ESC-02・04・05 向け）。
    Absent,
    /// errno なしの失敗。
    Failed,
}

impl AttackOutcome {
    /// 記録行の値表現。
    fn render(self) -> String {
        match self {
            AttackOutcome::Succeeded => "ok".to_string(),
            AttackOutcome::Errno(n) => format!("errno={n}"),
            AttackOutcome::Absent => "absent".to_string(),
            AttackOutcome::Failed => "failed".to_string(),
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ok" => Ok(AttackOutcome::Succeeded),
            "absent" => Ok(AttackOutcome::Absent),
            "failed" => Ok(AttackOutcome::Failed),
            other => other
                .strip_prefix("errno=")
                .and_then(|n| n.parse::<i32>().ok())
                .filter(|n| *n > 0)
                .map(AttackOutcome::Errno)
                .ok_or_else(|| format!("invalid outcome {other:?}")),
        }
    }
}

/// 監査ログの期待（SEC-4。本番の配送経路が出した記録で照合する。#2028）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditExpectation {
    /// 監査レコードを要求しない。
    None,
    /// 指定レイヤー（`AuditLayer::as_str()` の値: `seccomp` / `landlock` / `mount`）の記録を要求する。
    /// 記録は本番の配送経路がコンテナの外へ出したものに限る（テスト側が生成した記録を証拠にしてはならない）。
    Required {
        layer: &'static str,
        source: AuditSource,
    },
    /// 指定レイヤーの監査を spec 上は要求するが、本番の配送経路をこの試験からは駆動できないため合否に使わない
    /// （REPAIR-3・SEC-4）。`tracking` は追跡先の issue。追跡先の結論が出たら `Required` へ置き換える。
    Deferred {
        layer: &'static str,
        tracking: &'static str,
    },
}

/// `Required` の記録の出所（どの本番経路の出力を回収して照合するか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditSource {
    /// 状態ルート直下の `@audit.log`（`ControlAuditRelay` → `FileAuditSink` が書く行）。ちょうど `count` 行を要求する。
    /// `seccomp` は seccomp 層のときの syscall 番号と arch（`None` なら照合しない）。
    StateRootLog {
        count: usize,
        seccomp: Option<SeccompSpec>,
    },
    /// ホストのカーネル監査ログの `LANDLOCK_ACCESS`（`AUDIT_LANDLOCK_ACCESS`）。`blockers` はその行の `blockers=`
    /// に現れるべき拒否種別（例: `fs.make_reg`）。opt-in の段（`KERNEL_AUDIT_ENV`）でだけ回収できる。
    KernelAudit { blockers: &'static str },
}

/// seccomp 層の記録で照合する syscall 番号と arch（`AUDIT_ARCH_*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeccompSpec {
    syscall: u64,
    arch: u64,
}

/// `mount(2)` の syscall 番号（x86_64 は 165、aarch64 は 40。アーキテクチャ間で流用しない）。
#[cfg(target_arch = "aarch64")]
const MOUNT_SYSCALL_NR: u64 = 40;
#[cfg(not(target_arch = "aarch64"))]
const MOUNT_SYSCALL_NR: u64 = 165;
/// 上の syscall 番号の `AUDIT_ARCH_*`（x86_64 は `0xC000_003E`、aarch64 は `0xC000_00B7`）。
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u64 = 0xC000_00B7;
#[cfg(not(target_arch = "aarch64"))]
const AUDIT_ARCH_NATIVE: u64 = 0xC000_003E;

/// 状態ルートの `@audit.log` を使うケースが、記録に載せるコンテナ ID（ハーネス固定。照合に使う）。
const AUDIT_CONTAINER_ID: &str = "escape-suite";

/// カーネル監査の回収を有効にする環境変数（opt-in の段。root か audit ログの読み取り権限・auditd・Landlock ABI 7 が要る）。
/// `1` のときだけ有効。前提が欠けたら skip せず失敗にする。
const KERNEL_AUDIT_ENV: &str = "FANDHE_CONTAINER_TEST_KERNEL_AUDIT";

/// カーネル監査を回収しなかった理由（opt-in なし。出力と `AuditNotVerified` に載せる固定語彙）。
const KERNEL_AUDIT_NOT_ENABLED: &str = "kernel audit collection is not enabled";

/// ケースの期待。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expectation {
    /// 受理する攻撃結果の集合（`signal` 指定時は照合しない）。
    allowed: &'static [AttackOutcome],
    /// 子が指定シグナルで終了することを期待する場合のシグナル番号（ESC-06 の SIGSYS 等）。
    signal: Option<i32>,
    /// 監査ログの期待。
    audit: AuditExpectation,
}

/// 子の終了状態（OS 非依存の自前表現。Linux 側で `ChildExit` から変換する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedExit {
    Exited(i32),
    Signaled(i32),
}

impl fmt::Display for ObservedExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservedExit::Exited(c) => write!(f, "exited({c})"),
            ObservedExit::Signaled(s) => write!(f, "signaled({s})"),
        }
    }
}

/// `@audit.log` の 1 行（`encode_json_line` の出力）から照合に要る項目だけを取り出したもの。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditLine {
    layer: String,
    pid: u64,
    syscall: Option<u64>,
    arch: Option<u64>,
    container_id: Option<String>,
}

/// コンテナの外で回収した監査の証拠（本番の配送経路の出力だけ。子の記録からは作らない）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditEvidence {
    /// このケースは監査を回収しない（`None` / `Deferred`）。
    NotApplicable,
    /// 状態ルートの `@audit.log` の全行。`subject_pid` は seccomp 層の記録の pid と突き合わせる、
    /// 攻撃した子の（記録者から見た）pid。
    StateRootLog {
        lines: Vec<AuditLine>,
        subject_pid: Option<u64>,
    },
    /// カーネル監査ログで、期待する `blockers`・子の pid・時刻の下限に合った `LANDLOCK_ACCESS` の件数。
    KernelAudit { matched: usize },
    /// 回収の前提が無く読まなかった（opt-in なし）。合格ではなく「監査は未検証」を表す。
    NotCollected { reason: &'static str },
}

/// 観測結果。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    exit: ObservedExit,
    outcome: Option<AttackOutcome>,
    audit: AuditEvidence,
}

/// 期待との不一致。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mismatch {
    UnexpectedExit {
        got: ObservedExit,
    },
    MissingOutcome,
    UnexpectedOutcome {
        got: AttackOutcome,
    },
    /// 要求した層の記録が 1 件も回収できなかった。
    MissingAudit {
        layer: &'static str,
    },
    /// 記録はあるが件数・層・コンテナ ID・syscall 番号・arch・pid のいずれかが期待と違う。
    AuditDetail {
        layer: &'static str,
        detail: String,
    },
    /// シナリオ側の失敗（ディスパッチャが子プロセスの失敗を報告する）。実プロセス部（Linux）でのみ構築される。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    ScenarioFailed {
        detail: String,
    },
    /// ホスト視点の検査（`EscapeCase::host_check`）の失敗。実プロセス部（Linux）でのみ構築される。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    HostCheckFailed {
        detail: String,
    },
    /// ホスト側の canary が攻撃後に変化した（ホスト FS へ到達・書き込めた = エスケープ。ESC-01）。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    HostTargetModified {
        detail: String,
    },
}

/// ケースの判定結果（真偽値ではなく不一致の一覧を持つ）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaseVerdict {
    Pass,
    Fail(Vec<Mismatch>),
    /// 攻撃の結果は期待どおりだが、要求された監査を回収できず照合していない（合格ではない。ESC-09 の
    /// `NotApplicable` と同じく「検証していない」ことを表す。SEC-4）。
    AuditNotVerified {
        layer: &'static str,
        reason: &'static str,
    },
}

/// 状態ルートの `@audit.log` の証拠を期待（件数・層・コンテナ ID・seccomp の値）で照合し、不一致の一覧を返す。
fn check_state_root_log(
    layer: &'static str,
    count: usize,
    seccomp: Option<SeccompSpec>,
    lines: &[AuditLine],
    subject_pid: Option<u64>,
) -> Vec<Mismatch> {
    if lines.is_empty() {
        return vec![Mismatch::MissingAudit { layer }];
    }
    let mut problems = Vec::new();
    if lines.len() != count {
        problems.push(format!(
            "expected exactly {count} record(s), got {}",
            lines.len()
        ));
    }
    for (i, line) in lines.iter().enumerate() {
        if line.layer != layer {
            problems.push(format!(
                "record {i}: layer {:?}, expected {layer:?}",
                line.layer
            ));
        }
        if line.container_id.as_deref() != Some(AUDIT_CONTAINER_ID) {
            problems.push(format!(
                "record {i}: container_id {:?}, expected {AUDIT_CONTAINER_ID:?}",
                line.container_id
            ));
        }
        if let Some(spec) = seccomp {
            if line.syscall != Some(spec.syscall) {
                problems.push(format!(
                    "record {i}: syscall {:?}, expected {}",
                    line.syscall, spec.syscall
                ));
            }
            if line.arch != Some(spec.arch) {
                problems.push(format!(
                    "record {i}: arch {:?}, expected {}",
                    line.arch, spec.arch
                ));
            }
            if subject_pid != Some(line.pid) {
                problems.push(format!(
                    "record {i}: pid {}, expected the probe child's pid {subject_pid:?}",
                    line.pid
                ));
            }
        }
    }
    problems
        .into_iter()
        .map(|detail| Mismatch::AuditDetail { layer, detail })
        .collect()
}

/// 観測が期待に合うかを判定する。監査必須のケースで記録が無ければ必ず `Fail`、記録を回収できていなければ
/// `AuditNotVerified`（合格にしない。SEC-2・SEC-4）。
fn judge(expect: &Expectation, obs: &Observation) -> CaseVerdict {
    let mut mismatches = Vec::new();
    match expect.signal {
        Some(sig) => {
            if obs.exit != ObservedExit::Signaled(sig) {
                mismatches.push(Mismatch::UnexpectedExit { got: obs.exit });
            }
            // 攻撃が成功（結果を記録）した後に別経路でシグナル終了した場合と区別する。
            if let Some(got) = obs.outcome {
                mismatches.push(Mismatch::UnexpectedOutcome { got });
            }
        }
        None => {
            if obs.exit != ObservedExit::Exited(0) {
                mismatches.push(Mismatch::UnexpectedExit { got: obs.exit });
            } else {
                match obs.outcome {
                    None => mismatches.push(Mismatch::MissingOutcome),
                    Some(got) if !expect.allowed.contains(&got) => {
                        mismatches.push(Mismatch::UnexpectedOutcome { got });
                    }
                    Some(_) => {}
                }
            }
        }
    }
    let mut not_verified = None;
    if let AuditExpectation::Required { layer, source } = expect.audit {
        match (source, &obs.audit) {
            (
                AuditSource::StateRootLog { count, seccomp },
                AuditEvidence::StateRootLog { lines, subject_pid },
            ) => mismatches.extend(check_state_root_log(
                layer,
                count,
                seccomp,
                lines,
                *subject_pid,
            )),
            (AuditSource::KernelAudit { .. }, AuditEvidence::KernelAudit { matched }) => {
                if *matched == 0 {
                    mismatches.push(Mismatch::MissingAudit { layer });
                }
            }
            (AuditSource::KernelAudit { .. }, AuditEvidence::NotCollected { reason }) => {
                not_verified = Some((layer, *reason));
            }
            // 証拠の種類が期待の出所と合わない（ハーネスの不備）。合格にしない。
            (_, other) => mismatches.push(Mismatch::AuditDetail {
                layer,
                detail: format!("evidence kind does not match the expected source: {other:?}"),
            }),
        }
    }
    if !mismatches.is_empty() {
        CaseVerdict::Fail(mismatches)
    } else if let Some((layer, reason)) = not_verified {
        CaseVerdict::AuditNotVerified { layer, reason }
    } else {
        CaseVerdict::Pass
    }
}

/// 子が書く記録の累計バイト上限（pipe 容量 64 KiB より十分小さくし、親が読む前に子が書き切ってもブロックしない）。
const RECORD_MAX_BYTES: usize = 16 * 1024;

/// 子から回収した記録の解析結果。
///
/// 監査の記録は子からは受け取らない（`audit=` 行は拒否する）。攻撃側が書いた記録は SEC-4 の証拠にならないため、
/// 監査の証拠はコンテナの外で回収した本番の記録（`@audit.log`・カーネル監査）に限る（#2028）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRecord {
    /// outcome 行が無ければ `None`。シグナル終了では outcome 行の前に停止し得るため、欠落の可否は
    /// 終了状態を見る `judge` が決める（`Exited` なら `MissingOutcome`。`Signaled` なら許容）。
    outcome: Option<AttackOutcome>,
}

/// 記録（行指向テキスト）を厳格に解析する。子の出力は untrusted として扱い、欠落・重複・未知キー・
/// 不正値・上限超過を拒否する。形式: `outcome=<ok|errno=N|absent|failed>` を高々 1 行（省略可）。
/// `audit=` を含むそれ以外のキーは未知キーとして拒否する。
fn parse_record(text: &str) -> Result<ParsedRecord, String> {
    if text.len() > RECORD_MAX_BYTES {
        return Err("record exceeds the size limit".to_string());
    }
    let mut outcome = None;
    // 許す行は outcome の 1 行だけなので、行数は重複・未知キーの拒否で、量はバイト上限で抑える。
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed line {line:?}"))?;
        match key {
            "outcome" => {
                if outcome.is_some() {
                    return Err("duplicate key \"outcome\"".to_string());
                }
                outcome = Some(AttackOutcome::parse(value)?);
            }
            other => return Err(format!("unknown key {other:?}")),
        }
    }
    Ok(ParsedRecord { outcome })
}

/// `@audit.log` の読み出し上限（バイト）。
const STATE_LOG_MAX_BYTES: usize = 1024 * 1024;
/// `@audit.log` の行数上限。
const STATE_LOG_MAX_LINES: usize = 256;

/// `@audit.log` の全文を厳格に解析する（untrusted 入力として、上限超過・JSON 不正・必須項目欠落・型違いを拒否）。
fn parse_state_root_log(text: &str) -> Result<Vec<AuditLine>, String> {
    if text.len() > STATE_LOG_MAX_BYTES {
        return Err("audit log exceeds the size limit".to_string());
    }
    let mut lines = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        if i >= STATE_LOG_MAX_LINES {
            return Err("audit log exceeds the line limit".to_string());
        }
        let json: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("line {i}: invalid json: {e}"))?;
        let layer = json
            .get("layer")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("line {i}: no string \"layer\""))?;
        let pid = json
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("line {i}: no unsigned \"pid\""))?;
        let optional_u64 = |key: &str| -> Result<Option<u64>, String> {
            match json.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(v) => v
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| format!("line {i}: \"{key}\" is not an unsigned integer")),
            }
        };
        let container_id = match json.get("container_id") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(
                v.as_str()
                    .ok_or_else(|| format!("line {i}: \"container_id\" is not a string"))?
                    .to_string(),
            ),
        };
        lines.push(AuditLine {
            layer: layer.to_string(),
            pid,
            syscall: optional_u64("syscall")?,
            arch: optional_u64("arch")?,
            container_id,
        });
    }
    Ok(lines)
}

/// カーネル監査の行 `msg=audit(<秒>.<ミリ秒>:<連番>)` から（秒, 連番）を取り出す。
fn kernel_audit_stamp(line: &str) -> Option<(u64, u64)> {
    let rest = line.split("msg=audit(").nth(1)?;
    let stamp = rest.split(')').next()?;
    let (time, seq) = stamp.split_once(':')?;
    let secs = time.split('.').next()?.parse().ok()?;
    Some((secs, seq.parse().ok()?))
}

/// カーネル監査ログの本文から、`blocker` を含む `LANDLOCK_ACCESS` で、同じイベント連番の `SYSCALL` 記録の
/// `pid` が `child_pid` に一致し、時刻が `min_epoch_secs` 以上のものの件数を数える（連番の重複は 1 件）。
///
/// 照合は空白区切りのフィールドの完全一致に限る（`blockers=` の値はカンマ区切りの要素の完全一致。
/// 部分一致はしない。`comm`・`exe`・`path` などコンテナが左右できる値は解釈しない）。`min_epoch_secs` は
/// ケースの開始前に取った時刻で、PID の再利用による過去の記録を除く（SEC-4・REPAIR-12）。
fn count_landlock_access_records(
    log: &str,
    child_pid: u32,
    blocker: &str,
    min_epoch_secs: u64,
) -> usize {
    let mut seqs = std::collections::BTreeSet::new();
    for line in log.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !fields.contains(&"type=LANDLOCK_ACCESS") {
            continue;
        }
        let blocked = fields.iter().any(|f| {
            f.strip_prefix("blockers=")
                .is_some_and(|v| v.split(',').any(|b| b == blocker))
        });
        if let Some((secs, seq)) = kernel_audit_stamp(line)
            && blocked
            && secs >= min_epoch_secs
        {
            seqs.insert(seq);
        }
    }
    let want_pid = format!("pid={child_pid}");
    let mut matched = std::collections::BTreeSet::new();
    for line in log.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.contains(&"type=SYSCALL")
            && fields.contains(&want_pid.as_str())
            && let Some((_, seq)) = kernel_audit_stamp(line)
            && seqs.contains(&seq)
        {
            matched.insert(seq);
        }
    }
    matched.len()
}

/// シナリオがディスパッチャへ返す 1 行（stdout）。判定の材料のうち、コンテナ内で確定する事実だけを運ぶ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScenarioMeta {
    exit: ObservedExit,
    outcome: Option<AttackOutcome>,
    /// 攻撃した子の（シナリオから見た）pid。子を作らないケース（start の拒否）は `None`。
    child_pid: Option<u32>,
    /// 攻撃した子自身の PID namespace での pid（`/proc/<child_pid>/status` の `NSpid` の末尾）。seccomp 層の
    /// 記録の `pid` はこの値になる（本番の supervisor の変換と同じ。SEC-4）。カーネル監査はホストの `child_pid` で照合する。
    pid_in_ns: Option<u32>,
    /// ケース開始の UNIX 秒（カーネル監査の時刻の下限）。
    started_at: u64,
}

/// `ScenarioMeta` の行の先頭語。
const META_PREFIX: &str = "escape_suite-meta";

impl ScenarioMeta {
    fn render(&self) -> String {
        let exit = match self.exit {
            ObservedExit::Exited(c) => format!("exited:{c}"),
            ObservedExit::Signaled(s) => format!("signaled:{s}"),
        };
        let outcome = self
            .outcome
            .map_or_else(|| "none".to_string(), AttackOutcome::render);
        let pid = self
            .child_pid
            .map_or_else(|| "none".to_string(), |p| p.to_string());
        let inner = self
            .pid_in_ns
            .map_or_else(|| "none".to_string(), |p| p.to_string());
        format!(
            "{META_PREFIX} exit={exit} outcome={outcome} child_pid={pid} pid_in_ns={inner} started_at={}",
            self.started_at
        )
    }

    /// シナリオの stdout から meta 行をちょうど 1 行取り出して解析する。コンテナの子は stdout を継承するため、
    /// 偽の行を書かれても 2 行目以降が現れて拒否される（0 行・2 行以上・未知キー・欠落・不正値は `Err`。fail-closed）。
    fn parse_from_stdout(stdout: &str) -> Result<Self, String> {
        let mut found = stdout
            .lines()
            .filter(|l| l.split(' ').next() == Some(META_PREFIX));
        let line = found.next().ok_or("no meta line")?;
        if found.next().is_some() {
            return Err("more than one meta line".to_string());
        }
        let (mut exit, mut outcome, mut pid, mut inner, mut started) =
            (None, None, None, None, None);
        for field in line.split(' ').skip(1) {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| format!("malformed field {field:?}"))?;
            let dup = |name: &str| format!("duplicate key {name:?}");
            match key {
                "exit" => {
                    let (kind, n) = value.split_once(':').ok_or("malformed exit")?;
                    let n: i32 = n.parse().map_err(|_| "invalid exit number".to_string())?;
                    let parsed = match kind {
                        "exited" => ObservedExit::Exited(n),
                        "signaled" => ObservedExit::Signaled(n),
                        _ => return Err("invalid exit kind".to_string()),
                    };
                    if exit.replace(parsed).is_some() {
                        return Err(dup("exit"));
                    }
                }
                "outcome" => {
                    let parsed = if value == "none" {
                        None
                    } else {
                        Some(AttackOutcome::parse(value)?)
                    };
                    if outcome.replace(parsed).is_some() {
                        return Err(dup("outcome"));
                    }
                }
                "child_pid" => {
                    let parsed = if value == "none" {
                        None
                    } else {
                        Some(
                            value
                                .parse::<u32>()
                                .map_err(|_| "invalid child_pid".to_string())?,
                        )
                    };
                    if pid.replace(parsed).is_some() {
                        return Err(dup("child_pid"));
                    }
                }
                "pid_in_ns" => {
                    let parsed = if value == "none" {
                        None
                    } else {
                        Some(
                            value
                                .parse::<u32>()
                                .map_err(|_| "invalid pid_in_ns".to_string())?,
                        )
                    };
                    if inner.replace(parsed).is_some() {
                        return Err(dup("pid_in_ns"));
                    }
                }
                "started_at" => {
                    let parsed = value
                        .parse::<u64>()
                        .map_err(|_| "invalid started_at".to_string())?;
                    if started.replace(parsed).is_some() {
                        return Err(dup("started_at"));
                    }
                }
                other => return Err(format!("unknown key {other:?}")),
            }
        }
        Ok(ScenarioMeta {
            exit: exit.ok_or("missing exit")?,
            outcome: outcome.ok_or("missing outcome")?,
            child_pid: pid.ok_or("missing child_pid")?,
            pid_in_ns: inner.ok_or("missing pid_in_ns")?,
            started_at: started.ok_or("missing started_at")?,
        })
    }
}
/// 監査を回収しないケース（`None` / `Deferred`）の観測。
fn obs_plain(exit: ObservedExit, outcome: Option<AttackOutcome>) -> Observation {
    Observation {
        exit,
        outcome,
        audit: AuditEvidence::NotApplicable,
    }
}

/// 状態ルートの `@audit.log` の証拠（コンテナ ID はハーネス固定値）の 1 行。
fn state_line(layer: &str, pid: u64, syscall: Option<u64>, arch: Option<u64>) -> AuditLine {
    AuditLine {
        layer: layer.to_string(),
        pid,
        syscall,
        arch,
        container_id: Some(AUDIT_CONTAINER_ID.to_string()),
    }
}

/// ESC-03 の seccomp の期待値（`mount` の番号と arch）。
const ESC03_SECCOMP: SeccompSpec = SeccompSpec {
    syscall: MOUNT_SYSCALL_NR,
    arch: AUDIT_ARCH_NATIVE,
};

/// SEC-2・TASK-42.1: 判定ロジックの自己テスト（具体値で照合。REPAIR-12）。
fn sec2_task42_1_judge_selftest() {
    let allow_ok = Expectation {
        allowed: &[AttackOutcome::Succeeded],
        signal: None,
        audit: AuditExpectation::None,
    };
    let kernel = Expectation {
        allowed: &[AttackOutcome::Errno(1), AttackOutcome::Errno(13)],
        signal: None,
        audit: AuditExpectation::Required {
            layer: "landlock",
            source: AuditSource::KernelAudit {
                blockers: "fs.make_reg",
            },
        },
    };
    let sig = Expectation {
        allowed: &[],
        signal: Some(31),
        audit: AuditExpectation::None,
    };
    let ok_exit = ObservedExit::Exited(0);
    let with = |outcome, audit| Observation {
        exit: ok_exit,
        outcome: Some(outcome),
        audit,
    };

    assert_eq!(
        judge(
            &allow_ok,
            &obs_plain(ok_exit, Some(AttackOutcome::Succeeded))
        ),
        CaseVerdict::Pass
    );
    // カーネル監査: 照合できた記録 1 件で合格。0 件は不合格、攻撃結果の不一致は不合格のまま。
    assert_eq!(
        judge(
            &kernel,
            &with(
                AttackOutcome::Errno(13),
                AuditEvidence::KernelAudit { matched: 1 }
            )
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &kernel,
            &with(
                AttackOutcome::Errno(13),
                AuditEvidence::KernelAudit { matched: 0 }
            )
        ),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &kernel,
            &with(
                AttackOutcome::Succeeded,
                AuditEvidence::KernelAudit { matched: 1 }
            )
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    // 回収していない（opt-in なし）: 合格にせず「監査は未検証」。攻撃結果が不一致なら不合格が優先される。
    let not_collected = AuditEvidence::NotCollected {
        reason: "kernel audit not enabled",
    };
    assert_eq!(
        judge(
            &kernel,
            &with(AttackOutcome::Errno(13), not_collected.clone())
        ),
        CaseVerdict::AuditNotVerified {
            layer: "landlock",
            reason: "kernel audit not enabled"
        }
    );
    assert_eq!(
        judge(&kernel, &with(AttackOutcome::Succeeded, not_collected)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    // 証拠の種類が期待の出所と違う（ハーネスの不備）は不合格。
    assert!(matches!(
        judge(
            &kernel,
            &with(
                AttackOutcome::Errno(13),
                AuditEvidence::StateRootLog {
                    lines: vec![state_line("landlock", 1, None, None)],
                    subject_pid: None,
                }
            )
        ),
        CaseVerdict::Fail(ref m) if matches!(m.as_slice(), [Mismatch::AuditDetail { layer: "landlock", .. }])
    ));
    assert_eq!(
        judge(&allow_ok, &obs_plain(ok_exit, None)),
        CaseVerdict::Fail(vec![Mismatch::MissingOutcome])
    );
    assert_eq!(
        judge(&sig, &obs_plain(ObservedExit::Exited(0), None)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedExit {
            got: ObservedExit::Exited(0)
        }])
    );
    assert_eq!(
        judge(&sig, &obs_plain(ObservedExit::Signaled(31), None)),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &sig,
            &obs_plain(ObservedExit::Signaled(31), Some(AttackOutcome::Succeeded))
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
}

/// SEC-4・#2028: 状態ルートの `@audit.log` の照合（ESC-03 の seccomp 1 行・ESC-08 の mount 3 行）の自己テスト。
/// 件数はちょうど、層・コンテナ ID・syscall 番号・arch・pid は具体値で照合する（REPAIR-12）。
fn sec4_2028_state_root_log_selftest() {
    let esc03 = &ESC03_EXPECTATION;
    let ok_exit = ObservedExit::Exited(0);
    let obs = |lines: Vec<AuditLine>, pid: Option<u64>| Observation {
        exit: ok_exit,
        outcome: Some(AttackOutcome::Errno(EPERM)),
        audit: AuditEvidence::StateRootLog {
            lines,
            subject_pid: pid,
        },
    };
    let good = state_line(
        "seccomp",
        4242,
        Some(MOUNT_SYSCALL_NR),
        Some(AUDIT_ARCH_NATIVE),
    );
    assert_eq!(
        judge(esc03, &obs(vec![good.clone()], Some(4242))),
        CaseVerdict::Pass
    );
    // 0 行は MissingAudit。2 行（余分な記録）・層違い・コンテナ ID 違い・syscall/arch/pid 違いは不合格。
    assert_eq!(
        judge(esc03, &obs(vec![], Some(4242))),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "seccomp" }])
    );
    let detail = |verdict: CaseVerdict| -> Vec<String> {
        match verdict {
            CaseVerdict::Fail(m) => m
                .into_iter()
                .map(|m| match m {
                    Mismatch::AuditDetail { detail, .. } => detail,
                    other => panic!("unexpected mismatch {other:?}"),
                })
                .collect(),
            other => panic!("expected a failure, got {other:?}"),
        }
    };
    assert_eq!(
        detail(judge(
            esc03,
            &obs(vec![good.clone(), good.clone()], Some(4242))
        )),
        vec!["expected exactly 1 record(s), got 2".to_string()]
    );
    let mut wrong_layer = good.clone();
    wrong_layer.layer = "mount".to_string();
    assert_eq!(
        detail(judge(esc03, &obs(vec![wrong_layer], Some(4242)))),
        vec!["record 0: layer \"mount\", expected \"seccomp\"".to_string()]
    );
    let mut wrong_id = good.clone();
    wrong_id.container_id = Some("other".to_string());
    assert_eq!(
        detail(judge(esc03, &obs(vec![wrong_id], Some(4242)))),
        vec![format!(
            "record 0: container_id Some(\"other\"), expected {AUDIT_CONTAINER_ID:?}"
        )]
    );
    let mut wrong_nr = good.clone();
    wrong_nr.syscall = Some(MOUNT_SYSCALL_NR + 1);
    assert_eq!(
        detail(judge(esc03, &obs(vec![wrong_nr], Some(4242)))),
        vec![format!(
            "record 0: syscall Some({}), expected {MOUNT_SYSCALL_NR}",
            MOUNT_SYSCALL_NR + 1
        )]
    );
    let mut wrong_arch = good.clone();
    wrong_arch.arch = Some(0);
    assert_eq!(
        detail(judge(esc03, &obs(vec![wrong_arch], Some(4242)))),
        vec![format!(
            "record 0: arch Some(0), expected {AUDIT_ARCH_NATIVE}"
        )]
    );
    assert_eq!(
        detail(judge(esc03, &obs(vec![good.clone()], Some(1)))),
        vec!["record 0: pid 4242, expected the probe child's pid Some(1)".to_string()]
    );
    assert_eq!(
        detail(judge(esc03, &obs(vec![good], None))),
        vec!["record 0: pid 4242, expected the probe child's pid None".to_string()]
    );

    // ESC-08: mount 層の 3 行（要求ごとに 1 行）。syscall・arch・pid は照合しない。
    let mount = |n: usize| Observation {
        exit: ok_exit,
        outcome: Some(AttackOutcome::Failed),
        audit: AuditEvidence::StateRootLog {
            lines: (0..n).map(|_| state_line("mount", 7, None, None)).collect(),
            subject_pid: None,
        },
    };
    assert_eq!(judge(&ESC08_EXPECT, &mount(3)), CaseVerdict::Pass);
    assert_eq!(
        judge(&ESC08_EXPECT, &mount(0)),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "mount" }])
    );
    assert_eq!(
        detail(judge(&ESC08_EXPECT, &mount(2))),
        vec!["expected exactly 3 record(s), got 2".to_string()]
    );
    // StateRootLog を要求するケースで「未回収」の証拠は不合格（合格にも未検証にもしない）。
    let not_collected = Observation {
        exit: ok_exit,
        outcome: Some(AttackOutcome::Failed),
        audit: AuditEvidence::NotCollected { reason: "x" },
    };
    assert!(matches!(
        judge(&ESC08_EXPECT, &not_collected),
        CaseVerdict::Fail(_)
    ));

    // `@audit.log` の解析: 本番の出力形式（`encode_json_line`）の具体値と、拒否する入力。
    let text = format!(
        "{{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":1,\"ts_nsec\":2,\"pid\":4242,\"syscall\":{MOUNT_SYSCALL_NR},\"arch\":{AUDIT_ARCH_NATIVE},\"container_id\":\"{AUDIT_CONTAINER_ID}\"}}\n\
         {{\"event\":\"audit\",\"layer\":\"mount\",\"pid\":7,\"path\":\"/data\",\"container_id\":null}}\n"
    );
    assert_eq!(
        parse_state_root_log(&text),
        Ok(vec![
            state_line(
                "seccomp",
                4242,
                Some(MOUNT_SYSCALL_NR),
                Some(AUDIT_ARCH_NATIVE)
            ),
            AuditLine {
                layer: "mount".to_string(),
                pid: 7,
                syscall: None,
                arch: None,
                container_id: None
            },
        ])
    );
    assert_eq!(parse_state_root_log(""), Ok(vec![]));
    assert!(parse_state_root_log("{broken\n").is_err());
    assert_eq!(
        parse_state_root_log("{\"pid\":1}\n"),
        Err("line 0: no string \"layer\"".to_string())
    );
    assert_eq!(
        parse_state_root_log("{\"layer\":\"mount\",\"pid\":-1}\n"),
        Err("line 0: no unsigned \"pid\"".to_string())
    );
    assert_eq!(
        parse_state_root_log("{\"layer\":\"mount\",\"pid\":1,\"syscall\":\"x\"}\n"),
        Err("line 0: \"syscall\" is not an unsigned integer".to_string())
    );
    assert_eq!(
        parse_state_root_log("{\"layer\":\"mount\",\"pid\":1,\"container_id\":5}\n"),
        Err("line 0: \"container_id\" is not a string".to_string())
    );
    let many = "{\"layer\":\"mount\",\"pid\":1}\n".repeat(STATE_LOG_MAX_LINES + 1);
    assert_eq!(
        parse_state_root_log(&many),
        Err("audit log exceeds the line limit".to_string())
    );
    let big = "x".repeat(STATE_LOG_MAX_BYTES + 1);
    assert_eq!(
        parse_state_root_log(&big),
        Err("audit log exceeds the size limit".to_string())
    );
}

/// SEC-4・#2028: カーネル監査ログの `LANDLOCK_ACCESS` の照合（フィールドの完全一致・連番による SYSCALL との結合・
/// 時刻の下限・部分一致の拒否）の fixture での自己テスト（REPAIR-12）。
fn sec4_2028_kernel_audit_selftest() {
    let log = "\
type=LANDLOCK_ACCESS msg=audit(100.5:10): domain=1 blockers=fs.make_reg path=\"/x\" dev=\"sda1\" ino=5\n\
type=SYSCALL msg=audit(100.5:10): arch=c000003e syscall=257 success=no exit=-13 pid=4242 ppid=1 comm=\"pid=9999\"\n\
type=LANDLOCK_ACCESS msg=audit(100.9:11): domain=1 blockers=fs.read_file,fs.write_file path=\"/y\"\n\
type=SYSCALL msg=audit(100.9:11): arch=c000003e syscall=257 success=no exit=-13 pid=4242 ppid=1\n\
type=LANDLOCK_ACCESS msg=audit(100.9:12): domain=1 blockers=fs.make_reg_extra path=\"/z\"\n\
type=SYSCALL msg=audit(100.9:12): pid=4242\n\
type=LANDLOCK_ACCESS msg=audit(100.9:13): domain=1 blockers=fs.make_reg path=\"/w\"\n\
type=SYSCALL msg=audit(100.9:13): pid=5555\n\
type=LANDLOCK_ACCESS msg=audit(50.0:14): domain=1 blockers=fs.make_reg path=\"/old\"\n\
type=SYSCALL msg=audit(50.0:14): pid=4242\n";
    // 連番 10 だけが「blockers に完全一致・pid 一致・時刻 OK」。
    assert_eq!(
        count_landlock_access_records(log, 4242, "fs.make_reg", 100),
        1
    );
    // カンマ区切りの要素は完全一致で数える（連番 11 の write_file）。
    assert_eq!(
        count_landlock_access_records(log, 4242, "fs.write_file", 100),
        1
    );
    assert_eq!(
        count_landlock_access_records(log, 4242, "fs.read_file", 100),
        1
    );
    // 部分一致（`fs.make_reg_extra`・`fs.make`）と comm の中の `pid=9999` は数えない。
    assert_eq!(count_landlock_access_records(log, 4242, "fs.make", 100), 0);
    assert_eq!(
        count_landlock_access_records(log, 9999, "fs.make_reg", 100),
        0
    );
    // 別 pid の記録は数えず、時刻の下限より前の記録（PID 再利用で残る過去分）も数えない。
    assert_eq!(
        count_landlock_access_records(log, 5555, "fs.make_reg", 100),
        1
    );
    assert_eq!(
        count_landlock_access_records(log, 4242, "fs.make_reg", 40),
        2
    );
    assert_eq!(
        count_landlock_access_records(log, 4242, "fs.make_reg", 101),
        0
    );
    assert_eq!(count_landlock_access_records("", 1, "fs.make_reg", 0), 0);
    assert_eq!(
        kernel_audit_stamp("type=X msg=audit(1700000000.123:456): a=b"),
        Some((1_700_000_000, 456))
    );
    assert_eq!(kernel_audit_stamp("type=X nothing"), None);
}

/// SEC-4・#2028: シナリオの meta 行の往復と拒否の自己テスト（子が stdout を継承するため偽造行を拒否する）。
fn sec4_2028_meta_selftest() {
    // opt-in の環境変数名は AGENTS.md の手順と一致させる（名前を変えたら文書も直す）。
    assert_eq!(KERNEL_AUDIT_ENV, "FANDHE_CONTAINER_TEST_KERNEL_AUDIT");
    let meta = ScenarioMeta {
        exit: ObservedExit::Signaled(31),
        outcome: None,
        child_pid: Some(4242),
        pid_in_ns: Some(1),
        started_at: 1_700_000_000,
    };
    assert_eq!(
        meta.render(),
        "escape_suite-meta exit=signaled:31 outcome=none child_pid=4242 pid_in_ns=1 started_at=1700000000"
    );
    let stdout = format!("noise\n{}\nmore\n", meta.render());
    assert_eq!(ScenarioMeta::parse_from_stdout(&stdout), Ok(meta));
    let exited = ScenarioMeta {
        exit: ObservedExit::Exited(0),
        outcome: Some(AttackOutcome::Errno(1)),
        child_pid: None,
        pid_in_ns: None,
        started_at: 5,
    };
    assert_eq!(
        ScenarioMeta::parse_from_stdout(&exited.render()),
        Ok(exited)
    );
    assert_eq!(
        ScenarioMeta::parse_from_stdout("nothing\n"),
        Err("no meta line".to_string())
    );
    // 2 行ある（コンテナの子が偽の行を書いた）場合は、どちらも採用せず拒否する。
    let forged = format!("{}\n{}\n", exited.render(), meta.render());
    assert_eq!(
        ScenarioMeta::parse_from_stdout(&forged),
        Err("more than one meta line".to_string())
    );
    for bad in [
        "escape_suite-meta exit=exited:0 outcome=ok child_pid=none pid_in_ns=none",
        "escape_suite-meta exit=exited:0 outcome=ok child_pid=none started_at=1",
        "escape_suite-meta exit=exited:0 outcome=ok child_pid=none pid_in_ns=none started_at=1 extra=1",
        "escape_suite-meta exit=exited:0 exit=exited:0 outcome=ok child_pid=none pid_in_ns=none started_at=1",
        "escape_suite-meta exit=gone:0 outcome=ok child_pid=none pid_in_ns=none started_at=1",
        "escape_suite-meta exit=exited:0 outcome=bogus child_pid=none pid_in_ns=none started_at=1",
        "escape_suite-meta exit=exited:0 outcome=ok child_pid=-1 started_at=1",
    ] {
        assert!(
            ScenarioMeta::parse_from_stdout(bad).is_err(),
            "must reject: {bad}"
        );
    }
}

/// SEC-2・TASK-42.1: 記録パーサの自己テスト（正常系・欠落・重複・未知キー・不正値・上限超過）。
fn sec2_task42_1_record_parser_selftest() {
    assert_eq!(
        parse_record("outcome=errno=13\n"),
        Ok(ParsedRecord {
            outcome: Some(AttackOutcome::Errno(13)),
        })
    );
    assert_eq!(
        parse_record("outcome=ok\n"),
        Ok(ParsedRecord {
            outcome: Some(AttackOutcome::Succeeded),
        })
    );
    assert_eq!(AttackOutcome::Errno(13).render(), "errno=13");
    assert_eq!(parse_record(""), Ok(ParsedRecord { outcome: None }));
    // 子からの `audit=` 行は証拠にならないため、形式が正しくても未知キーとして拒否する（SEC-4・#2028）。
    let audit = r#"audit={"event":"audit","layer":"landlock","pid":1}"#;
    assert_eq!(
        parse_record(&format!("outcome=errno=13\n{audit}\n")),
        Err("unknown key \"audit\"".to_string())
    );
    assert_eq!(
        parse_record("outcome=ok\noutcome=absent\n"),
        Err("duplicate key \"outcome\"".to_string())
    );
    assert_eq!(
        parse_record("outcome=ok\nextra=1\n"),
        Err("unknown key \"extra\"".to_string())
    );
    assert_eq!(
        parse_record("outcome=errno=x\n"),
        Err("invalid outcome \"errno=x\"".to_string())
    );
    assert_eq!(
        parse_record("outcome=errno=0\n"),
        Err("invalid outcome \"errno=0\"".to_string())
    );
    assert_eq!(
        parse_record("garbage\n"),
        Err("malformed line \"garbage\"".to_string())
    );
    let too_long = format!("outcome=ok\n{}", "x".repeat(RECORD_MAX_BYTES));
    assert_eq!(
        parse_record(&too_long),
        Err("record exceeds the size limit".to_string())
    );
}
/// ESC-06 が発行する syscall 名が CORE-5 の禁止表に含まれることを照合する。
fn sec2_task42_3_esc06_probed_names_in_deny_table() {
    let names: Vec<&str> = fandhe_container_core::seccomp::DeniedSyscall::ALL
        .iter()
        .map(|d| d.name())
        .collect();
    for probed in ESC06_PROBED.iter() {
        assert!(
            names.contains(probed),
            "SEC-2: ESC-06 syscall {probed} must be in DeniedSyscall::ALL"
        );
    }
}

/// ESC-04〜06 の期待が意図どおりに判定されること（現行実装の観測が失敗になることを含む）を具体値で照合する。
fn sec2_task42_3_case_expectation_selftest() {
    // 第 3 引数は子が運ぶ監査の記録の名残で無視する（監査の証拠はコンテナの外で回収した記録だけ。#2028）。
    let obs = |exit, outcome, _layers: &[&str]| obs_plain(exit, outcome);
    let ok_exit = ObservedExit::Exited(0);
    for pass in [AttackOutcome::Absent, AttackOutcome::Errno(EACCES)] {
        assert_eq!(
            judge(&ESC05_EXPECT, &obs(ok_exit, Some(pass), &[])),
            CaseVerdict::Pass
        );
    }
    assert_eq!(
        judge(
            &ESC04_EXPECT,
            &obs(ok_exit, Some(AttackOutcome::Errno(EROFS)), &[])
        ),
        CaseVerdict::Pass
    );
    // ESC-04 は対象が実在する前提のため、不在（防御を検証できていない）と書き込み成功は失敗になる。
    for bad in [AttackOutcome::Absent, AttackOutcome::Succeeded] {
        assert_eq!(
            judge(&ESC04_EXPECT, &obs(ok_exit, Some(bad), &[])),
            CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome { got: bad }])
        );
    }
    assert_eq!(
        judge(
            &ESC05_EXPECT,
            &obs(ok_exit, Some(AttackOutcome::Succeeded), &[])
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    assert_eq!(
        judge(
            &ESC06_EXPECT,
            &obs(ObservedExit::Signaled(31), None, &["seccomp"])
        ),
        CaseVerdict::Pass
    );
    // 監査は Deferred のため、SIGSYS 終了なら監査記録の有無にかかわらず合格（記録を合否に使わない。SEC-4）。
    assert_eq!(
        judge(
            &ESC06_EXPECT,
            &obs(ObservedExit::Signaled(SIGSYS), None, &[])
        ),
        CaseVerdict::Pass
    );
    // SIGSYS 以外のシグナル終了は失敗。
    assert_eq!(
        judge(&ESC06_EXPECT, &obs(ObservedExit::Signaled(9), None, &[])),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedExit {
            got: ObservedExit::Signaled(9)
        }])
    );
    // 強制終了にならず EPERM で戻る実装（フィルタの退行）は失敗として検出される。
    assert_eq!(
        judge(
            &ESC06_EXPECT,
            &obs(ok_exit, Some(AttackOutcome::Errno(EPERM)), &[])
        ),
        CaseVerdict::Fail(vec![
            Mismatch::UnexpectedExit {
                got: ObservedExit::Exited(0)
            },
            Mismatch::UnexpectedOutcome {
                got: AttackOutcome::Errno(1)
            },
        ])
    );
}

/// ESC-01: ホスト FS への書き込みは成功せず（ホスト側 canary 無変更）、readonly root への書き込みは EACCES（Landlock）。
///
/// 監査（SEC-4）は Landlock の本番の記録であるカーネル監査 `LANDLOCK_ACCESS`（`blockers=fs.write_file`）を、
/// opt-in の段（`KERNEL_AUDIT_ENV`）で回収して照合する。opt-in なしでは攻撃結果だけを照合し、
/// 監査は `audit-not-verified` として出力する（合格にしない。#2028）。
const ESC01_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(13)],
    signal: None,
    audit: AuditExpectation::Required {
        layer: "landlock",
        source: AuditSource::KernelAudit {
            blockers: "fs.write_file",
        },
    },
};

/// ESC-02: ホストの PID namespace が参照できない（`/proc/1` はコンテナ内の自分自身）。監査記録は要求しない。
const ESC02_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Absent],
    signal: None,
    audit: AuditExpectation::None,
};

/// ESC-03: 既定 capability セット下の `mount(2)` は EPERM（1）で拒否される。拒否主体は組み込み seccomp の
/// `ERRNO(EPERM)`（と capability 削減）で `AuditLayer::Mount` ではない。監査（SEC-4）は、`USER_NOTIF` 版の filter が
/// 出す通知を応答者が `record_seccomp_denial_for` → `ControlAuditRelay` → `FileAuditSink` で記録した状態ルートの
/// `@audit.log` の seccomp 層の行を、ちょうど 1 行（`mount` の syscall 番号・arch・攻撃した子の pid・コンテナ ID）
/// 照合する（#2028）。応答者の本体は試験側（core の公開 API だけで組む。supervisor の応答ハブそのものではない）。
const ESC03_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(1)],
    signal: None,
    audit: AuditExpectation::Required {
        layer: "seccomp",
        source: AuditSource::StateRootLog {
            count: 1,
            seccomp: Some(ESC03_SECCOMP),
        },
    },
};

/// ESC-02 の判定: コンテナ内から見える PID 空間を分類する（OS 非依存の純粋関数）。
///
/// `self_pid` は `process::id()`、`proc_self_link` は `readlink("/proc/self")`、`visible` は `/proc` の数値エントリ。
/// 自分が PID 1 で、`/proc/self` が `1` を指し、可視 PID が `[1]` のみなら「ホストのプロセスは不可視」
/// （`Absent`）。それ以外はホストのプロセスを参照できた（PID namespace 未分離・別 namespace の `/proc`）ため
/// `Succeeded`（= エスケープ）。
fn classify_pid_view(self_pid: u32, proc_self_link: &str, visible: &[u32]) -> AttackOutcome {
    if self_pid == 1 && proc_self_link == "1" && visible == [1] {
        AttackOutcome::Absent
    } else {
        AttackOutcome::Succeeded
    }
}

/// SEC-2・TASK-42.2: ESC-02 の PID 可視性分類と ESC-01〜03 の期待の自己テスト（具体値で照合。REPAIR-12）。
fn sec2_task42_2_selftest() {
    assert_eq!(classify_pid_view(1, "1", &[1]), AttackOutcome::Absent);
    assert_eq!(
        classify_pid_view(1, "1", &[1, 734]),
        AttackOutcome::Succeeded
    );
    assert_eq!(
        classify_pid_view(4321, "4321", &[1, 4321]),
        AttackOutcome::Succeeded
    );
    assert_eq!(classify_pid_view(1, "57", &[1]), AttackOutcome::Succeeded);
    assert_eq!(classify_pid_view(1, "1", &[]), AttackOutcome::Succeeded);

    let plain = |outcome| obs_plain(ObservedExit::Exited(0), Some(outcome));
    let kernel = |outcome, matched| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit: AuditEvidence::KernelAudit { matched },
    };
    let seccomp_log = |outcome| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit: AuditEvidence::StateRootLog {
            lines: vec![state_line(
                "seccomp",
                4242,
                Some(MOUNT_SYSCALL_NR),
                Some(AUDIT_ARCH_NATIVE),
            )],
            subject_pid: Some(4242),
        },
    };
    // ESC-03: 攻撃結果が EPERM でも、本番の記録が無ければ合格にしない。成功してしまえば記録があっても不合格。
    assert_eq!(
        judge(&ESC03_EXPECTATION, &seccomp_log(AttackOutcome::Errno(1))),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC03_EXPECTATION, &plain(AttackOutcome::Errno(1))),
        CaseVerdict::Fail(vec![Mismatch::AuditDetail {
            layer: "seccomp",
            detail: "evidence kind does not match the expected source: NotApplicable".to_string()
        }])
    );
    assert_eq!(
        judge(&ESC03_EXPECTATION, &seccomp_log(AttackOutcome::Succeeded)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    // ESC-01: カーネル監査の記録（write_file）が照合できて合格。opt-in なしは未検証で、合格にはならない。
    assert_eq!(
        judge(&ESC01_EXPECTATION, &kernel(AttackOutcome::Errno(13), 1)),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC01_EXPECTATION, &kernel(AttackOutcome::Errno(13), 0)),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &ESC01_EXPECTATION,
            &Observation {
                exit: ObservedExit::Exited(0),
                outcome: Some(AttackOutcome::Errno(13)),
                audit: AuditEvidence::NotCollected {
                    reason: KERNEL_AUDIT_NOT_ENABLED
                },
            }
        ),
        CaseVerdict::AuditNotVerified {
            layer: "landlock",
            reason: KERNEL_AUDIT_NOT_ENABLED
        }
    );
    assert_eq!(
        judge(&ESC01_EXPECTATION, &kernel(AttackOutcome::Errno(1), 1)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Errno(1)
        }])
    );
    assert_eq!(
        judge(&ESC02_EXPECTATION, &plain(AttackOutcome::Absent)),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC02_EXPECTATION, &plain(AttackOutcome::Succeeded)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
}

/// Linux asm-generic の errno 値（x86_64・aarch64 共通。syscall 番号ではないため arch 分岐は不要）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const ENOENT: i32 = 2;
const ETXTBSY: i32 = 26;

/// ESC-07（SEC-2・TASK-42.4・#202）: ランタイムバイナリへの書き込み open の期待値。
/// 書き込みの拒否は Landlock（EACCES）のほか、実行中バイナリへの書き込み拒否（ETXTBSY）や DAC（EACCES・EPERM）
/// でも起こり得るため、いずれも許可する。成功（`Succeeded`）だけが失敗。spec は監査を要求しない。
#[cfg_attr(
    not(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )),
    allow(dead_code)
)]
const ESC07_WRITE_EXPECT: Expectation = Expectation {
    allowed: &[
        AttackOutcome::Errno(EACCES),
        AttackOutcome::Errno(ETXTBSY),
        AttackOutcome::Errno(EPERM),
        AttackOutcome::Absent,
    ],
    signal: None,
    audit: AuditExpectation::None,
};

/// ESC-07 の Landlock 帰属確認（読み取り open。ETXTBSY に覆われない）。EACCES と、カーネル監査の
/// `LANDLOCK_ACCESS`（`blockers=fs.read_file`。opt-in の段で回収。#2028）が必須。
#[cfg_attr(
    not(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )),
    allow(dead_code)
)]
const ESC07_LANDLOCK_EXPECT: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(EACCES)],
    signal: None,
    audit: AuditExpectation::Required {
        layer: "landlock",
        source: AuditSource::KernelAudit {
            blockers: "fs.read_file",
        },
    },
};

/// ESC-08: マウント元が状態ルート・rootfs・bundle の bind の `start` は `InvalidArgument` で拒否され（`Failed`）、
/// 要求ごとに mount 層の監査記録がちょうど 1 行（計 3 行）、状態ルートの `@audit.log` に届く（#2028）。
/// 記録を作るのは本番の `start` の拒否経路（`validate_bind_mounts` → `audit_bind_mount_error` →
/// `ProcessLauncher::rejection_audit_sink` → `FileAuditSink`）で、試験は記録を作らない。
#[cfg_attr(
    not(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )),
    allow(dead_code)
)]
const ESC08_EXPECT: Expectation = Expectation {
    allowed: &[AttackOutcome::Failed],
    signal: None,
    audit: AuditExpectation::Required {
        layer: "mount",
        source: AuditSource::StateRootLog {
            count: 3,
            seccomp: None,
        },
    },
};

/// ESC-07・ESC-08 の期待値の機械照合（REPAIR-12・SEC-2・TASK-42.4）。非 Linux でも定数を使う。
fn sec2_task42_4_expectation_selftest() {
    let plain = |outcome| obs_plain(ObservedExit::Exited(0), Some(outcome));
    let kernel = |outcome, matched| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit: AuditEvidence::KernelAudit { matched },
    };
    assert_eq!(
        judge(&ESC07_WRITE_EXPECT, &plain(AttackOutcome::Succeeded)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    for o in [
        AttackOutcome::Errno(EACCES),
        AttackOutcome::Errno(ETXTBSY),
        AttackOutcome::Errno(EPERM),
        AttackOutcome::Absent,
    ] {
        assert_eq!(judge(&ESC07_WRITE_EXPECT, &plain(o)), CaseVerdict::Pass);
    }
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &kernel(AttackOutcome::Errno(EACCES), 1)
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &kernel(AttackOutcome::Errno(EACCES), 0)
        ),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &kernel(AttackOutcome::Errno(ETXTBSY), 1)
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Errno(ETXTBSY)
        }])
    );
    // ESC-08: 攻撃結果が成功（拒否されなかった）なら、記録が 3 行あっても不合格。
    let mount_log = |outcome| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit: AuditEvidence::StateRootLog {
            lines: (0..3).map(|_| state_line("mount", 7, None, None)).collect(),
            subject_pid: None,
        },
    };
    assert_eq!(
        judge(&ESC08_EXPECT, &mount_log(AttackOutcome::Failed)),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC08_EXPECT, &mount_log(AttackOutcome::Succeeded)),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
}

/// `/proc/self/mountinfo` の 1 行のうち、実効マウントの特定に要る項目（REPAIR-12・SEC-2・TASK-42.3・MS-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountEntry<'a> {
    /// マウント ID（第 1 欄）。
    id: &'a str,
    /// 親マウントの ID（第 2 欄）。
    parent: &'a str,
    /// マウントポイント（第 5 欄。空白等は 8 進エスケープのまま比較する）。
    mount_point: &'a str,
    /// マウント単位のオプション（第 6 欄）に `ro` があるか。
    read_only: bool,
}

/// mountinfo の 1 行を解析する。欄が足りない行は `None`。
fn parse_mount_entry(line: &str) -> Option<MountEntry<'_>> {
    let mut f = line.split(' ');
    let id = f.next()?;
    let parent = f.next()?;
    let mount_point = f.nth(2)?;
    let opts = f.next()?;
    Some(MountEntry {
        id,
        parent,
        mount_point,
        read_only: opts.split(',').any(|o| o == "ro"),
    })
}

/// `mount_point` が `path` 自身またはその祖先か（パス要素単位で比較する）。
fn mount_covers(mount_point: &str, path: &str) -> bool {
    mount_point == "/"
        || mount_point == path
        || path
            .strip_prefix(mount_point)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path` に実際に適用されるマウント（パス解決で最後に到達するマウント）を mountinfo から特定する
/// （REPAIR-12・SEC-2・TASK-42.3・MS-2）。
///
/// 親子関係（第 1・2 欄）を `/` から辿る。開始点は `/` のマウントのうち、別の `/` マウントの親になって
/// いない最上段のもの。各段では、現在のマウントの子のうち `path` を覆うものの中で最も浅いマウントポイントの
/// ものへ降りる（同じ親の下でより深い子は、浅い子が後から重なって隠れているため）。同じ深さは後の行
/// （上に積まれた側）を採る。行の欠落・最上段が 1 件に定まらない・親子の循環など、特定できない場合は
/// `None`（呼び出し側は証拠なしとして扱う。fail-closed）。
fn effective_mount<'a>(mountinfo: &'a str, path: &str) -> Option<MountEntry<'a>> {
    let mut entries = Vec::new();
    for line in mountinfo.lines().filter(|l| !l.is_empty()) {
        entries.push(parse_mount_entry(line)?);
    }
    let mut tops = entries.iter().filter(|e| {
        e.mount_point == "/"
            && !entries
                .iter()
                .any(|c| c.mount_point == "/" && c.parent == e.id && c.id != e.id)
    });
    let mut current = *tops.next()?;
    if tops.next().is_some() {
        return None;
    }
    // 1 段ごとに別のマウントへ降りるため、正常な入力なら件数以内で終わる（循環は打ち切って `None`）。
    for _ in 0..entries.len() {
        let next = entries
            .iter()
            .filter(|c| {
                c.parent == current.id && c.id != current.id && mount_covers(c.mount_point, path)
            })
            .fold(None, |best: Option<&MountEntry<'a>>, c| match best {
                Some(b) if b.mount_point.len() < c.mount_point.len() => Some(b),
                _ => Some(c),
            });
        match next {
            Some(n) => current = *n,
            None => return Some(current),
        }
    }
    None
}

/// `/proc/self/mountinfo` の内容から、`path` に `maskedPaths` / `readonlyPaths` が適用された証拠があるかを返す
/// （REPAIR-12・SEC-2・TASK-42.3・MS-2）。
///
/// 証拠は「`path` に実際に適用されるマウント（[`effective_mount`]）が読み取り専用（`ro`）で、そのマウント
/// ポイントが `path` 自身か `/`・`/proc`・`/sys` 以外の祖先であること」。rw マウントは対象自身へのものでも
/// 証拠にせず、読み取り専用の祖先マウントがあっても、より深い書き込み可能なマウントが重なっていれば証拠に
/// しない。ホスト側の権限拒否（EPERM / EACCES）だけで防御ありと誤判定しないために、攻撃結果とは独立に
/// この証拠を確認する。
fn has_mask_evidence(mountinfo: &str, path: &str) -> bool {
    effective_mount(mountinfo, path)
        .is_some_and(|m| m.read_only && !["/", "/proc", "/sys"].contains(&m.mount_point))
}

/// `has_mask_evidence` の期待値を具体値で照合する（REPAIR-12・SEC-2・TASK-42.3・MS-2）。
fn sec2_task42_3_mask_evidence_selftest() {
    // 共通の土台: rootfs（ID 30）の上に proc（ID 40）。
    let base = "30 20 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
                40 30 0:30 / /proc rw,nosuid - proc proc rw\n";
    let with = |extra: &str| format!("{base}{extra}");
    let core = "/proc/sys/kernel/core_pattern";
    let sysrq = "/proc/sysrq-trigger";

    // 実効マウントの特定。
    assert_eq!(
        effective_mount(base, core).map(|m| (m.id, m.mount_point)),
        Some(("40", "/proc"))
    );
    let ro_sys = with("41 40 0:30 /sys /proc/sys ro,nosuid - proc proc rw\n");
    assert_eq!(
        effective_mount(&ro_sys, core).map(|m| (m.id, m.read_only)),
        Some(("41", true))
    );

    // readonlyPaths 相当（`/proc/sys` の ro）は配下の証拠になる。対象外のパスには及ばない。
    assert!(has_mask_evidence(&ro_sys, core));
    assert!(!has_mask_evidence(&ro_sys, sysrq));
    // maskedPaths 相当（対象自身への ro マウント）は証拠。rw なら証拠にしない。
    let mask = with("42 40 0:6 /null /proc/sysrq-trigger ro - devtmpfs dev rw\n");
    let mask_rw = with("42 40 0:6 /null /proc/sysrq-trigger rw - devtmpfs dev rw\n");
    assert!(has_mask_evidence(&mask, sysrq));
    assert!(!has_mask_evidence(&mask_rw, sysrq));
    // rw の `/proc` だけ・空入力は証拠なし。
    assert!(!has_mask_evidence(base, core));
    assert!(!has_mask_evidence("", sysrq));

    // ro の祖先にさらに深い rw マウントが重なると、実効マウントは rw なので証拠にしない。
    let ro_then_rw_deeper = with(
        "41 40 0:30 /sys /proc/sys ro - proc proc rw\n43 41 0:31 / /proc/sys/kernel rw - tmpfs t rw\n",
    );
    assert_eq!(
        effective_mount(&ro_then_rw_deeper, core).map(|m| m.id),
        Some("43")
    );
    assert!(!has_mask_evidence(&ro_then_rw_deeper, core));
    // より深い側も ro なら証拠になる。
    let ro_then_ro_deeper = with(
        "41 40 0:30 /sys /proc/sys ro - proc proc rw\n43 41 0:31 / /proc/sys/kernel ro - tmpfs t rw\n",
    );
    assert!(has_mask_evidence(&ro_then_ro_deeper, core));
    // 同じマウントポイントへ積み重ねた場合は上（後の行・前の行を親に持つ側）が実効。
    let ro_under_rw = with(
        "41 40 0:30 /sys /proc/sys ro - proc proc rw\n44 41 0:30 /sys /proc/sys rw - proc proc rw\n",
    );
    let rw_under_ro = with(
        "41 40 0:30 /sys /proc/sys rw - proc proc rw\n44 41 0:30 /sys /proc/sys ro - proc proc rw\n",
    );
    assert!(!has_mask_evidence(&ro_under_rw, core));
    assert!(has_mask_evidence(&rw_under_ro, core));
    // rootfs 上の `/proc/sys`（ro）が後から重なった `/proc` に隠れた場合は、隠れた ro を証拠にしない。
    let hidden = "30 20 8:1 / / rw - ext4 /dev/sda1 rw\n\
                  41 30 0:30 /sys /proc/sys ro - proc proc rw\n\
                  40 30 0:30 / /proc rw - proc proc rw\n";
    assert_eq!(effective_mount(hidden, core).map(|m| m.id), Some("40"));
    assert!(!has_mask_evidence(hidden, core));
    // `/` 自体の ro（readonly root）は対象を絞ったマスクではないため証拠にしない。
    let ro_root = "30 20 8:1 / / ro - ext4 /dev/sda1 rw\n";
    assert!(!has_mask_evidence(ro_root, "/sys/fs/cgroup/release_agent"));
    // 特定できない入力（欄の欠落・最上段の `/` が 2 件）は証拠なし（fail-closed）。
    assert_eq!(effective_mount("30 20 8:1", core), None);
    let two_roots = "30 20 8:1 / / ro - ext4 a ro\n31 21 8:2 / / ro - ext4 b ro\n";
    assert_eq!(effective_mount(two_roots, core), None);
}

/// ケースが前提とする起動ユーザー（ディスパッチャ＝分離前のホスト側プロセスの実効 UID）。
///
/// 起動ユーザーで前提が成立しないケースは、スイート全体を失敗させずにそのケースだけを「対象外」として
/// 理由とビヘイビア ID を出力する（他のケースは実行する。ci.md「実機前提テスト」）。対象外は合格ではなく、
/// 検証していないことを明示する別の結果として扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LauncherRequirement {
    /// root・非 root のどちらで起動しても検証できる。
    Any,
    /// 非 root 起動でのみ検証できる（root 起動では前提が成立しない）。
    NonRoot {
        /// 対象外とする理由（出力文字列。英語）。
        reason: &'static str,
        /// 前提が対応するビヘイビア ID。
        behavior: &'static str,
    },
}

/// 起動ユーザーの前提が成立しないことの記録（対象外の理由）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotApplicable {
    reason: &'static str,
    behavior: &'static str,
}

/// 起動ユーザーの前提を判定する（OS 非依存の純粋関数）。`is_root` はディスパッチャ自身の実効 UID が 0 か。
/// user namespace 内の写像後 UID（コンテナ内では 0 に見える）を渡してはならない。
fn launcher_applicability(req: LauncherRequirement, is_root: bool) -> Result<(), NotApplicable> {
    match req {
        LauncherRequirement::NonRoot { reason, behavior } if is_root => {
            Err(NotApplicable { reason, behavior })
        }
        LauncherRequirement::Any | LauncherRequirement::NonRoot { .. } => Ok(()),
    }
}

/// ESC-09（SEC-5）の起動ユーザー前提: root 起動の rootful 経路はコンテナ内 root をホスト root に写す
/// （user namespace なし）ため、非特権 UID への写像を検証できない。
const ESC09_LAUNCHER: LauncherRequirement = LauncherRequirement::NonRoot {
    reason: "requires a non-root launcher: the rootful path has no user namespace and maps container root to host root",
    behavior: "SEC-5",
};

/// SEC-2・SEC-5・TASK-42.5: 起動ユーザー前提の判定の自己テスト（具体値で照合。REPAIR-12）。
fn sec2_task42_5_launcher_selftest() {
    assert_eq!(
        launcher_applicability(ESC09_LAUNCHER, true),
        Err(NotApplicable {
            reason: "requires a non-root launcher: the rootful path has no user namespace and maps container root to host root",
            behavior: "SEC-5",
        })
    );
    // 非 root 起動では ESC-09 を必ず実行する（対象外にする経路を持たない）。
    assert_eq!(launcher_applicability(ESC09_LAUNCHER, false), Ok(()));
    assert_eq!(
        launcher_applicability(LauncherRequirement::Any, true),
        Ok(())
    );
    assert_eq!(
        launcher_applicability(LauncherRequirement::Any, false),
        Ok(())
    );
}

fn always() {
    sec2_task42_1_judge_selftest();
    sec2_task42_1_record_parser_selftest();
    sec4_2028_state_root_log_selftest();
    sec4_2028_kernel_audit_selftest();
    sec4_2028_meta_selftest();
    sec2_task42_2_selftest();
    sec2_task42_3_esc06_probed_names_in_deny_table();
    sec2_task42_3_case_expectation_selftest();
    sec2_task42_3_mask_evidence_selftest();
    sec2_task42_4_expectation_selftest();
    sec2_task42_5_launcher_selftest();
    println!("escape_suite: SEC-2 judge and record parser verified");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    always();
    println!("escape_suite: real-process part is Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    always();
    println!(
        "escape_suite: real-process part is x86_64/aarch64 only, not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // シナリオ再入時は常に走る部分を繰り返さない。
    if std::env::args().any(|a| a == "--scenario") {
        linux::run();
        return;
    }
    always();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "escape_suite: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use crate::temp_rootfs;
    use std::io::{PipeWriter, Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AUDIT_LOG_FILE_NAME, AuditSink, AuditTimestamp, ControlAuditRelay, FileAuditSink,
        SeccompDenialReport, record_seccomp_denial_for,
    };
    use fandhe_container_core::dev_mounts::ImplicitDevMounts;
    use fandhe_container_core::exec::{
        ChildExit, ContainerChild, EscapeSyscallProbe, IsolationConfig, ListenerReadiness,
        Namespace, NamespaceSet, ProbeOutcome, SeccompListener, StagePipeline, escape_probe_mount,
        isolate, isolate_rootful_host_root, plan, plan_rootful_host_root, probe_escape_syscall,
        spawn_container_probe, spawn_container_probe_with_seccomp_listener,
    };
    use fandhe_container_core::landlock::{
        MIN_LANDLOCK_AUDIT_ABI, build_path_rules_with_dev, detect_landlock_abi,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchSpec, LaunchedProcess, ProcessLauncher, StartTimeouts, create, create_audited,
        parse_config_bytes, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateStore, TraitError,
    };

    use super::{
        AUDIT_CONTAINER_ID, AttackOutcome, AuditEvidence, AuditExpectation, AuditSource,
        CaseVerdict, ENOENT, ESC01_EXPECTATION, ESC02_EXPECTATION, ESC03_EXPECTATION, ESC04_EXPECT,
        ESC05_EXPECT, ESC06_EXPECT, ESC07_LANDLOCK_EXPECT, ESC07_WRITE_EXPECT, ESC08_EXPECT,
        ESC09_LAUNCHER, Expectation, KERNEL_AUDIT_NOT_ENABLED, LauncherRequirement, Mismatch,
        NotApplicable, Observation, ObservedExit, RECORD_MAX_BYTES, ScenarioMeta,
        classify_pid_view, count_landlock_access_records, judge, launcher_applicability,
        parse_record,
    };

    /// ESC-04 の攻撃対象（rootfs 内の相対パス）。rootfs 作成時に実在させる（`make_rootfs`）。
    const ESC04_TARGET_REL: [&str; 4] = ["sys", "fs", "cgroup", "release_agent"];

    /// 子（コンテナ内）で攻撃を実行するクロージャの型。結果は `Recorder` へ書く。
    ///
    /// 第 2 引数はホスト側に用意した canary ファイルの絶対パス（ホスト FS 到達の観測対象。ESC-01）。
    type Attack = fn(&Recorder, &Path);

    /// 1 件の攻撃ケース。ESC-01〜10 は `CASES` へ追加する（#200〜#203）。
    struct EscapeCase {
        /// `--scenario` に渡す識別子（例: `esc-01-mount`）。
        id: &'static str,
        /// ケースの実行の仕方（コンテナ内の probe か、`start` の拒否か）。
        body: CaseBody,
        expectation: Expectation,
        /// 子の制限ステージ列（Landlock を伴うケースは `with_landlock` を載せて返す）。
        stages: fn() -> StagePipeline,
        attack: Attack,
        /// Landlock 適用前（親側）に走らせる対照。制限が拒否の原因であることを示すために使う（既定は何もしない）。
        precondition: fn(),
        /// ディスパッチャ（分離なし・ホスト視点）がシナリオ成功後・rootfs 削除前に行う検査。
        /// 別テーブルにせずフィールドにすることで、追記漏れを rebase 後のコンパイルエラーで表面化させる。
        host_check: Option<HostCheck>,
        /// 起動ユーザーの前提。成立しなければディスパッチャがシナリオを起動せず、このケースだけを理由と
        /// ビヘイビア ID 付きの対象外として出力する（他のケースは実行する）。`host_check` と同じ理由でフィールドにする。
        launcher: LauncherRequirement,
    }

    /// ケースの実行の仕方（シナリオが分岐する）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CaseBody {
        /// 分離 → `spawn_container_probe`（制限ステージ通過後の子で攻撃クロージャを実行）。
        Probe,
        /// `Probe` に、ERRNO 側の拒否を `USER_NOTIF` で受けて記録・応答する応答者を足す（ESC-03。SEC-4・#2028）。
        ProbeWithSeccompListener,
        /// 分離もコンテナ probe もせず、`create` → `start` の拒否を実行する（ESC-08。SEC-4・#2028）。
        StartRejection,
        /// 分離もコンテナ probe もせず、本番の `create_audited` の destination 拒否を実行する（ESC-08。SEC-4・OCI-4・#2480）。
        CreateRejection,
        /// 分離もコンテナ probe もせず、create 後に `config.json` の destination を書き換えて `start` の再検証（TOCTOU）の
        /// 拒否を実行する（ESC-08。SEC-4・OCI-4・#2594・#2641）。
        StartDestinationRewrite,
    }

    /// ホスト視点の検査関数の型。
    type HostCheck = fn(&HostView) -> Result<(), String>;

    /// ホスト視点の検査入力（ESC-09。SEC-5）。
    struct HostView<'a> {
        rootfs: &'a Path,
        euid: u32,
        egid: u32,
        is_root: bool,
    }

    /// ESC-08 のパース時の拒否の期待。本番の `create_audited` が mount 層 3 件（遡り・`/`・相対 `..`）を
    /// `@audit.log` へ記録する（SEC-4・OCI-4・#2480）。start の bind の拒否（`ESC08_EXPECT`）と同じ形。
    const ESC08_CONFIG_EXPECT: Expectation = ESC08_EXPECT;

    /// ESC-08 の start の TOCTOU（destination の書き換え）の期待。本番の `start` → `build_spec` →
    /// `validate_bundle_audited` → `rejection_audit_sink` → `FileAuditSink` が要求ごとに 1 行、計 3 行を
    /// `@audit.log` の mount 層へ記録する（SEC-4・OCI-4・#2594・#2641）。
    const ESC08_START_REWRITE_EXPECT: Expectation = ESC08_EXPECT;

    /// ESC-08 の destination の攻撃入力（rootfs 外への遡り・rootfs 全体・相対 `..`）。
    /// `create_rejection`（パース時）と `start_destination_rewrite`（TOCTOU）が共有する。
    const ESC08_DESTINATIONS: [&str; 3] = ["/../../run/fandhe-container", "/", "run/../../../etc"];

    /// 登録済みケース。対照ケースと ESC-01〜03（#200）・ESC-04〜06（#201）・ESC-07〜08（#202）・ESC-09〜10（#203）。
    const CASES: &[EscapeCase] = &[
        EscapeCase {
            id: "control-read-proc",
            body: CaseBody::Probe,
            expectation: Expectation {
                allowed: &[AttackOutcome::Succeeded],
                signal: None,
                audit: AuditExpectation::None,
            },
            stages: StagePipeline::new,
            attack: attack_control_read_proc,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        // 否定対照: Landlock なしなら ESC-10 と同じ作成が成功する（拒否の Landlock への帰属の裏付け）。
        EscapeCase {
            id: "control-esc-10-no-landlock",
            body: CaseBody::Probe,
            expectation: Expectation {
                allowed: &[AttackOutcome::Succeeded],
                signal: None,
                audit: AuditExpectation::None,
            },
            stages: StagePipeline::new,
            attack: attack_control_create_outside,
            host_check: None,
            launcher: LauncherRequirement::Any,
            precondition: no_precondition,
        },
        // ESC-10（CORE-5・SEC-4・SEC-2）。
        EscapeCase {
            id: "esc-10-landlock-outside",
            body: CaseBody::Probe,
            expectation: Expectation {
                allowed: &[AttackOutcome::Errno(13)],
                signal: None,
                // 監査は本番のカーネル監査 `LANDLOCK_ACCESS`（`blockers=fs.make_reg`）を opt-in の段で回収して照合する
                // （テスト側が作った記録を証拠にしない。SEC-4・#2028）。
                audit: AuditExpectation::Required {
                    layer: "landlock",
                    source: AuditSource::KernelAudit {
                        blockers: "fs.make_reg",
                    },
                },
            },
            stages: esc10_stages,
            attack: attack_esc10_create_outside,
            host_check: None,
            launcher: LauncherRequirement::Any,
            precondition: no_precondition,
        },
        // ESC-09（SEC-5・SEC-2）。
        EscapeCase {
            id: "esc-09-userns-owner",
            body: CaseBody::Probe,
            expectation: Expectation {
                allowed: &[AttackOutcome::Succeeded],
                signal: None,
                audit: AuditExpectation::None,
            },
            stages: StagePipeline::new,
            attack: attack_esc09_create_file,
            host_check: Some(host_check_esc09_owner),
            launcher: ESC09_LAUNCHER,
            precondition: no_precondition,
        },
        EscapeCase {
            id: "esc-01-host-fs-write",
            body: CaseBody::Probe,
            expectation: ESC01_EXPECTATION,
            stages: esc01_stages,
            attack: attack_esc01_host_fs_write,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-02-host-pid-ns",
            body: CaseBody::Probe,
            expectation: ESC02_EXPECTATION,
            stages: StagePipeline::new,
            attack: attack_esc02_host_pid_ns,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-03-cap-sys-admin-mount",
            body: CaseBody::ProbeWithSeccompListener,
            expectation: ESC03_EXPECTATION,
            stages: StagePipeline::new,
            attack: attack_esc03_cap_sys_admin_mount,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-04-release-agent",
            body: CaseBody::Probe,
            expectation: ESC04_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc04_release_agent,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-05-proc-sys-core-pattern",
            body: CaseBody::Probe,
            expectation: ESC05_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc05_proc_sys_core_pattern,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-05-sysrq-trigger",
            body: CaseBody::Probe,
            expectation: ESC05_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc05_sysrq_trigger,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-unshare",
            body: CaseBody::Probe,
            expectation: ESC06_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc06_unshare,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-ptrace",
            body: CaseBody::Probe,
            expectation: ESC06_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc06_ptrace,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-kexec-load",
            body: CaseBody::Probe,
            expectation: ESC06_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc06_kexec_load,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        // ESC-07〜08（TASK-42.4・#202）
        EscapeCase {
            id: "esc-07-runtime-binary-write",
            body: CaseBody::Probe,
            expectation: ESC07_WRITE_EXPECT,
            stages: landlock_rootfs_only_stages,
            attack: attack_esc07_runtime_binary_write,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-07-runtime-binary-landlock",
            body: CaseBody::Probe,
            expectation: ESC07_LANDLOCK_EXPECT,
            stages: landlock_rootfs_only_stages,
            attack: attack_esc07_runtime_binary_landlock,
            precondition: precondition_esc07_exe_readable,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-08-mount-outside-whitelist",
            body: CaseBody::StartRejection,
            expectation: ESC08_EXPECT,
            stages: StagePipeline::new,
            attack: attack_unused,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        // ESC-08 の `create` のパース時の destination 拒否。本番の `create_audited` が `@audit.log` の mount 層へ
        // 記録するため、拒否と監査 3 行の両方を照合する（#2480）。
        EscapeCase {
            id: "esc-08-config-destination",
            body: CaseBody::CreateRejection,
            expectation: ESC08_CONFIG_EXPECT,
            stages: StagePipeline::new,
            attack: attack_unused,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        // ESC-08 の start の TOCTOU: create 後に destination を書き換えても `start` の再検証が拒否し、本番の
        // 拒否経路が `@audit.log` の mount 層へ記録する（#2594・#2641）。
        EscapeCase {
            id: "esc-08-start-destination-rewrite",
            body: CaseBody::StartDestinationRewrite,
            expectation: ESC08_START_REWRITE_EXPECT,
            stages: StagePipeline::new,
            attack: attack_unused,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
    ];

    /// ESC-01 の制限ステージ列: readonly root・mounts なしの Landlock ruleset を載せる（親・fork 前に構築）。
    ///
    /// ABI 6 未満など Landlock が使えない環境は実機前提の不成立として panic（失敗）にする。skip しない。
    fn esc01_stages() -> StagePipeline {
        let json =
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},"mounts":[]}"#;
        let config = parse_config_bytes(json).expect("valid config");
        let support = detect_landlock_abi()
            .unwrap_or_else(|e| panic!("Landlock ABI 6+ is required for ESC-01: {e}"));
        // rootfs に dev が無い最小入口（`spawn_container` は `create_default_devices` を呼ばない。本番の launch 経路は /dev を作り `All` を使う）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない（#1657）。
        let ruleset = build_path_rules_with_dev(
            &support,
            config.root(),
            config.mounts(),
            ImplicitDevMounts::None,
        )
        .unwrap_or_else(|e| panic!("rules: {e}"));
        StagePipeline::new()
            .with_landlock(ruleset)
            .unwrap_or_else(|e| panic!("with_landlock: {e}"))
    }

    /// ESC-01 の対照ファイル（rootfs 直下。シナリオが fork 前に作成し、rootfs と共に削除される）。
    const CONTROL_NAME: &str = "esc-01-control";
    /// pivot 後の名前空間から見た対照ファイルのパス。
    const CONTROL_PATH: &str = "/esc-01-control";

    /// `prefix` 配下にホスト絶対パス `host` を連結した経路（`/proc/1/root` 等経由）を作る。
    fn via(prefix: &str, host: &Path) -> PathBuf {
        let mut p = PathBuf::from(prefix);
        p.extend(host.components().skip(1));
        p
    }

    /// 既存ファイルへの書き込みオープンを試みる（作成・切り詰めはしない。成功しても内容は変わらない）。
    fn try_open_for_write(target: &Path) -> AttackOutcome {
        match std::fs::OpenOptions::new().write(true).open(target) {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        }
    }

    /// ESC-01: pivot_root 後にホスト FS へ書き込めないこと（SEC-2・TASK-42.2）。
    ///
    /// 0. 対照: rootfs 内の既存ファイルへの書き込みが EACCES（Landlock）で拒否されること。経路自体が機能して
    ///    いることを先に確かめ、以降のホスト経路の ENOENT を「到達不能」（正常な隔離）と読めるようにする。
    /// 1. ホスト側に用意した canary（`host_canary`。rootfs の外）へ、ホスト絶対パス・`/proc/1/root`・
    ///    `/proc/self/root` 経由で書き込みオープンを試みる。いずれかが成功したら `Succeeded`（エスケープ）。
    ///    ENOENT / EACCES / EPERM 以外の errno はその errno を結果にして期待と不一致にする。
    ///    canary の無変更はシナリオ側（コンテナ外）が別途観測する。
    /// 2. readonly root への書き込み（`/proc/1/root` は PID 1 = 自分の rootfs）が Landlock（EACCES）で
    ///    拒否されることを確認する。ここは Landlock の拒否の観測であり、ホスト FS への到達検査は 1 が担う。
    ///
    /// 制限が欠けて 2 が成功してもマーカーは一時 rootfs 内に作られ `Rootfs::drop` で削除される。
    /// 監査記録は作らない（攻撃側生成の記録は SEC-4 の証拠にならない。期待はコンテナの外で回収する
    /// カーネル監査の `LANDLOCK_ACCESS`。#2028）。
    fn attack_esc01_host_fs_write(rec: &Recorder, host_canary: &Path) {
        // 対照経路: pivot 後の rootfs 内の既存ファイル（シナリオが fork 前に作成）への書き込みオープン。
        // パス解決・オープンの経路自体は機能しており Landlock（readonly root）が EACCES で拒否する、
        // という前提を先に確認する。ENOENT（経路の不備）や成功（Landlock 欠落）なら以降の
        // ホスト経路の ENOENT を「到達不能」と読めないため、その結果を記録して失敗にする。
        match try_open_for_write(Path::new(CONTROL_PATH)) {
            AttackOutcome::Errno(13) => {}
            other => {
                rec.outcome(other);
                return;
            }
        }
        // ホスト経路: ENOENT = ホスト FS は pivot 後の名前空間から到達不能（正常な隔離）。
        // EACCES / EPERM = 到達はしたが書き込みは拒否された（ここでも成功ではない）。
        // 成功・その他の errno は期待（EACCES）と不一致にする。
        let routes = [
            host_canary.to_path_buf(),
            via("/proc/1/root", host_canary),
            via("/proc/self/root", host_canary),
        ];
        for route in &routes {
            match try_open_for_write(route) {
                AttackOutcome::Errno(1 | 2 | 13) => {}
                other => {
                    rec.outcome(other);
                    return;
                }
            }
        }
        let outcome = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("/proc/1/root/esc-01-marker")
        {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        };
        rec.outcome(outcome);
    }

    /// `/proc` の列挙件数の上限（超過は PID 空間が想定外に広い = `Succeeded` 扱い。無制限な蓄積の防止）。
    const PROC_ENTRY_LIMIT: usize = 4096;

    /// ESC-02: ホストの PID namespace が参照できず `/proc/1` が自分自身であること（SEC-2・TASK-42.2）。
    ///
    /// `/proc` の数値エントリ・`/proc/self` のリンク先・`process::id()` から可視 PID 空間を観測し、
    /// `classify_pid_view` で分類する。読み出しの失敗は errno / `Failed` として記録する（成功扱いにしない）。
    fn attack_esc02_host_pid_ns(rec: &Recorder, _host_canary: &Path) {
        let observe = || -> Result<AttackOutcome, std::io::Error> {
            let link = std::fs::read_link("/proc/self")?;
            let link = link.to_string_lossy().into_owned();
            let mut visible: Vec<u32> = Vec::new();
            for entry in std::fs::read_dir("/proc")? {
                let name = entry?.file_name();
                if let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) {
                    if visible.len() >= PROC_ENTRY_LIMIT {
                        return Ok(AttackOutcome::Succeeded);
                    }
                    visible.push(pid);
                }
            }
            visible.sort_unstable();
            Ok(classify_pid_view(std::process::id(), &link, &visible))
        };
        let outcome = match observe() {
            Ok(o) => o,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        };
        rec.outcome(outcome);
    }

    /// ESC-03: 既定 capability セット下の `mount(2)` が EPERM で拒否されること（SEC-2・TASK-42.2）。
    ///
    /// core の `escape_probe_mount`（PID 1 限定・propagation 変更のみで新規マウントを作らない）を呼ぶ。
    ///
    /// 監査（SEC-4・#2028）: 実際の拒否主体は組み込み seccomp の `ERRNO(EPERM)`（と capability 削減）。このケースは
    /// `USER_NOTIF` 版の filter で起動され（`CaseBody::ProbeWithSeccompListener`）、通知を受けた応答者（シナリオ側）が
    /// 本番の記録先へ記録する。攻撃側では記録を作らない（攻撃側生成の記録は SEC-4 の証拠にならない）。
    fn attack_esc03_cap_sys_admin_mount(rec: &Recorder, _host_canary: &Path) {
        let probe = escape_probe_mount().unwrap_or_else(|e| panic!("escape_probe_mount: {e}"));
        let outcome = match probe {
            ProbeOutcome::Ok => AttackOutcome::Succeeded,
            ProbeOutcome::Errno(errno) => AttackOutcome::Errno(errno),
            ProbeOutcome::Unsupported | ProbeOutcome::Failed => AttackOutcome::Failed,
        };
        rec.outcome(outcome);
    }

    // ---- ESC-07〜08（SEC-2・TASK-42.4・#202） ----

    /// 対照なし（既定）。
    fn no_precondition() {}

    /// ESC-07 の対照: Landlock 適用前（ディスパッチ後・fork 前の親側）に `/proc/self/exe` を読み取りで開けることを
    /// 確認する。開けない場合は DAC 等が拒否原因になり得るため、子の EACCES を Landlock の効果と言えない。失敗は panic。
    /// 子は fork で同一 UID・同一実行ファイルを引き継ぐため、同じ対象への対照になる。
    fn precondition_esc07_exe_readable() {
        std::fs::File::open("/proc/self/exe").unwrap_or_else(|e| {
            panic!("control: /proc/self/exe must be readable before Landlock: {e}")
        });
    }

    /// rootfs のみを許可する Landlock ステージ列（`EscapeCase::stages`。シナリオの親で fork 前に評価される）。
    /// ホスト側ファイル（`/proc/self/exe` の実体等）は許可ツリーの外になる。Landlock ABI 6+ が無い環境では
    /// 成功扱いにせず panic し、シナリオ失敗にする（検証せずに成功する分岐を持たない）。ESC-10 等でも再利用できる。
    fn landlock_rootfs_only_stages() -> StagePipeline {
        let json =
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":false},"mounts":[]}"#;
        let config = parse_config_bytes(json).unwrap_or_else(|e| panic!("valid config: {e}"));
        let support = detect_landlock_abi()
            .unwrap_or_else(|e| panic!("Landlock ABI 6+ is required for this case: {e}"));
        // rootfs に dev が無い最小入口（`spawn_container` は `create_default_devices` を呼ばない。本番の launch 経路は /dev を作り `All` を使う）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない（#1657）。
        let ruleset = build_path_rules_with_dev(
            &support,
            config.root(),
            config.mounts(),
            ImplicitDevMounts::None,
        )
        .unwrap_or_else(|e| panic!("landlock rules: {e}"));
        StagePipeline::new()
            .with_landlock(ruleset)
            .unwrap_or_else(|e| panic!("with_landlock: {e}"))
    }

    /// ESC-10 の OCI config（readonly root・mount なし。固定リテラルでホスト側パスを含まない）。
    const ESC10_CONFIG: &[u8] =
        br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},"mounts":[]}"#;
    /// ESC-10 が作成を試みるコンテナ内パス。
    const ESC10_PROBE: &str = "/esc-10-landlock-probe";
    /// ESC-09 が作成するコンテナ内ファイル名（ホスト側は rootfs 直下の同名ファイルとして観測する）。
    const ESC09_PROBE: &str = "esc-09-owner-probe";

    /// ESC-10 用の制限ステージ列。readonly root（READ のみ許可）の Landlock ruleset を載せる。
    ///
    /// config は固定リテラルでホスト側パスを含まない。ABI 6 未満など検出・構築に失敗したら panic し、
    /// シナリオ失敗（`ScenarioFailed`）として fail-closed にする（シナリオプロセス・fork 前で呼ばれる）。
    fn esc10_stages() -> StagePipeline {
        let config = parse_config_bytes(ESC10_CONFIG).expect("valid config");
        let support = detect_landlock_abi()
            .unwrap_or_else(|e| panic!("Landlock ABI 6+ is required for ESC-10: {e}"));
        // rootfs に dev が無い最小入口（`spawn_container` は `create_default_devices` を呼ばない。本番の launch 経路は /dev を作り `All` を使う）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない（#1657）。
        let ruleset = build_path_rules_with_dev(
            &support,
            config.root(),
            config.mounts(),
            ImplicitDevMounts::None,
        )
        .unwrap_or_else(|e| panic!("rules: {e}"));
        StagePipeline::new()
            .with_landlock(ruleset)
            .unwrap_or_else(|e| panic!("with_landlock: {e}"))
    }

    /// 排他作成を試みて結果を `AttackOutcome` へ写す。
    fn try_create(path: &str) -> AttackOutcome {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        }
    }

    /// 否定対照の攻撃: Landlock なしで ESC-10 と同じ作成を試みる（結果の報告のみ）。
    fn attack_control_create_outside(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(try_create(ESC10_PROBE));
    }

    /// ESC-10 の攻撃: 起動ステージ（`esc10_stages` の readonly root Landlock）が適用済みの子で、
    /// 追加の Landlock 適用をせずに許可外の作成（MAKE_REG）をそのまま試みる。
    /// 起動ステージの Landlock が欠落・回帰すれば作成が成功し、`Errno(13)` 期待に反してケースが失敗する
    /// （ステージ自体の回帰検出。CORE-5）。監査レコードは作らない（テスト側生成の記録は SEC-4 の証拠にならない）。
    /// 期待はコンテナの外で回収するカーネル監査の `LANDLOCK_ACCESS`（`blockers=fs.make_reg`。#2028）。
    fn attack_esc10_create_outside(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(try_create(ESC10_PROBE));
    }

    /// ESC-09 の攻撃: コンテナ内（pivot 後）の root としてファイルを作る。所有者の検査はホスト側で行う。
    fn attack_esc09_create_file(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(try_create(&format!("/{ESC09_PROBE}")));
    }

    /// ESC-09 のホスト視点検査（SEC-5）: コンテナ内 root 作成のファイルが起動ユーザーの非特権 UID/GID 所有であること。
    /// root 起動はディスパッチャが `ESC09_LAUNCHER` で対象外にしてシナリオ自体を起動しないため、ここへは到達しない。
    /// 到達した場合はハーネスの不変条件違反として失敗させる（所有者を照合せずに成功させる分岐は持たない）。
    fn host_check_esc09_owner(view: &HostView) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        if view.is_root {
            return Err("harness invariant violated: ESC-09 ran under a root launcher; it must be reported as not applicable (SEC-5)".to_string());
        }
        let path = view.rootfs.join(ESC09_PROBE);
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("stat {} failed: {e}", path.display()))?;
        if !meta.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let (uid, gid) = (meta.uid(), meta.gid());
        if uid != view.euid || uid == 0 {
            return Err(format!(
                "owner uid is {uid}, expected the launcher's unprivileged uid {} (and != 0)",
                view.euid
            ));
        }
        if gid != view.egid || gid == 0 {
            return Err(format!(
                "owner gid is {gid}, expected the launcher's unprivileged gid {} (and != 0)",
                view.egid
            ));
        }
        Ok(())
    }

    /// `std::io::Error` を攻撃結果へ写す（ENOENT は `Absent`）。
    fn outcome_of_error(e: &std::io::Error) -> AttackOutcome {
        match e.raw_os_error() {
            Some(n) if n == ENOENT => AttackOutcome::Absent,
            Some(n) => AttackOutcome::Errno(n),
            None => AttackOutcome::Failed,
        }
    }

    /// ESC-07（SEC-2・TASK-42.4・#202。CVE-2019-5736 系）: `/proc/self/exe`（fork しただけの子ではホスト側
    /// テスト実行ファイル＝ランタイムバイナリの代役。magic link のため pivot 後もホストの実体へ解決される）を
    /// 書き込みモードで開こうとする。truncate・create・append は付けず、開けても即 drop して 1 バイトも
    /// 書かないため、制限が全て欠けてもホストは変わらない（`Succeeded` を記録して失敗するだけ）。
    /// ETXTBSY は LSM の file_open より先に判定されるため許可する（Landlock 帰属は別ケースで確認）。
    fn attack_esc07_runtime_binary_write(rec: &Recorder, _host_canary: &Path) {
        let outcome = match std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/exe")
        {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => outcome_of_error(&e),
        };
        rec.outcome(outcome);
    }

    /// ESC-07 の補助（SEC-2・TASK-42.4・#202）: ETXTBSY に覆われない読み取り open で、Landlock が
    /// ホスト側バイナリ（rootfs の許可ツリー外）の経路を塞いでいることを独立に示す。読み込みはしない。
    fn attack_esc07_runtime_binary_landlock(rec: &Recorder, _host_canary: &Path) {
        let outcome = match std::fs::File::open("/proc/self/exe") {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => outcome_of_error(&e),
        };
        rec.outcome(outcome);
    }

    /// 何もしない攻撃（`CaseBody::StartRejection` / `CreateRejection` / `StartDestinationRewrite` は子で攻撃を実行しないため、フィールドを埋めるためだけに使う）。
    fn attack_unused(_rec: &Recorder, _host_canary: &Path) {}

    /// 対照: 禁止対象外の操作（`/proc/self/status` の読み出し）が制限下でも動くこと。
    fn attack_control_read_proc(rec: &Recorder, _host_canary: &Path) {
        let outcome = match std::fs::read_to_string("/proc/self/status") {
            Ok(s) if s.contains("Seccomp:") => AttackOutcome::Succeeded,
            Ok(_) => AttackOutcome::Failed,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        };
        rec.outcome(outcome);
    }

    /// 書き込み用に開くだけ（`create` / `truncate` / `append` なし・1 バイトも書かない）で拒否を観測する。
    /// EPERM / EACCES はマスク・読み取り専用の適用証拠（`has_mask_evidence`）が無ければ `Failed` とする（REPAIR-12）。
    /// 開けた場合は即 drop して `Succeeded`（＝制限の欠落）を返す。ホストのカーネルへ作用させないための設計。
    fn open_write_only(path: &str) -> AttackOutcome {
        let outcome = open_write_raw(path);
        // EPERM / EACCES はホスト側の権限拒否でも起こるため、マスク・読み取り専用の適用証拠が無ければ
        // 防御の効果とみなさず `Failed`（受理されない）にする（REPAIR-12。EROFS は読み取り専用そのものの証拠）。
        if matches!(
            outcome,
            AttackOutcome::Errno(super::EPERM) | AttackOutcome::Errno(super::EACCES)
        ) {
            let applied =
                read_mountinfo_bounded().is_some_and(|m| super::has_mask_evidence(&m, path));
            if !applied {
                return AttackOutcome::Failed;
            }
        }
        outcome
    }

    /// `/proc/self/mountinfo` の読み出し上限（コンテナ内のマウント表には十分な大きさ）。
    const MOUNTINFO_MAX_BYTES: u64 = 1024 * 1024;

    /// `/proc/self/mountinfo` を上限付きで読む。読めない・上限を超える場合は `None`
    /// （呼び出し側は証拠なしとして扱う。fail-closed）。
    fn read_mountinfo_bounded() -> Option<String> {
        let file = std::fs::File::open("/proc/self/mountinfo").ok()?;
        let mut text = String::new();
        file.take(MOUNTINFO_MAX_BYTES + 1)
            .read_to_string(&mut text)
            .ok()?;
        (text.len() as u64 <= MOUNTINFO_MAX_BYTES).then_some(text)
    }

    /// 書き込み用に開くだけの生の結果（`open_write_only` の下請け）。
    fn open_write_raw(path: &str) -> AttackOutcome {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(file) => {
                drop(file);
                AttackOutcome::Succeeded
            }
            Err(e) => match e.raw_os_error() {
                Some(ENOENT) => AttackOutcome::Absent,
                Some(n) => AttackOutcome::Errno(n),
                None => AttackOutcome::Failed,
            },
        }
    }

    /// ESC-04（SEC-2・TASK-42.3・#201・MS-2）: cgroup v1 の `release_agent` への書き込み。
    /// 対象は rootfs 作成時に実在させる（`make_rootfs` が `sys/fs/cgroup/release_agent` を空ファイルで置く。
    /// ホストの cgroup は触らない）。そのため `ENOENT`（`Absent`）は受理せず、`EPERM` / `EACCES` / `EROFS` の
    /// 拒否だけを期待する。拒否は `/sys` 全体の読み取り専用化（#1850）による `EROFS` で、`has_mask_evidence` の
    /// 証拠には頼らない（実機で失敗すれば本物の欠陥として検出する。期待は変えない）。
    /// v1 階層の新規 mount の拒否は seccomp の `mount` 拒否（`tests/seccomp.rs`）、ホスト側の根拠は
    /// `tests/cgroups_release_agent.rs`（TASK-35）にある。
    fn attack_esc04_release_agent(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(open_write_only("/sys/fs/cgroup/release_agent"));
    }

    /// ESC-05（SEC-2・TASK-42.3・#201・MS-2）: マスク対象 `/proc/sys` 配下（`core_pattern`）への書き込み。
    /// `/proc/sys` の読み取り専用化（#1850）で拒否される。覆う側（#1851）には依存しない（期待は変えない）。
    fn attack_esc05_proc_sys_core_pattern(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(open_write_only("/proc/sys/kernel/core_pattern"));
    }

    /// ESC-05（SEC-2・TASK-42.3・#201・MS-2）: `/proc/sysrq-trigger` への書き込み。開くだけで書かない。
    /// 拒否の担い手は `/proc/sysrq-trigger` の読み取り専用化（#1850）。
    fn attack_esc05_sysrq_trigger(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(open_write_only("/proc/sysrq-trigger"));
    }

    /// `ProbeOutcome` を攻撃結果へ写す。
    fn probe_to_attack(p: ProbeOutcome) -> AttackOutcome {
        match p {
            ProbeOutcome::Ok => AttackOutcome::Succeeded,
            ProbeOutcome::Errno(n) => AttackOutcome::Errno(n),
            _ => AttackOutcome::Failed,
        }
    }

    /// ESC-06（SEC-2・TASK-42.3・#201・MS-2）: `unshare(0)`（副作用なし）。期待は spec どおり SIGSYS 終了。
    /// 戻ってきた場合（フィルタの退行）は結果を記録し、判定側が失敗にする。seccomp 監査は親側の本番経路が
    /// 未配線のため `Deferred`（#2236・#2237。SEC-4・REPAIR-3）で、攻撃側で監査レコードを作らない（偽造しない）。
    fn attack_esc06_unshare(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(probe_to_attack(probe_escape_syscall(
            EscapeSyscallProbe::Unshare,
        )));
    }

    /// ESC-06: `ptrace(PTRACE_CONT, 自 pid)`（attach を伴わず副作用なし）。期待は `attack_esc06_unshare` と同じ。
    fn attack_esc06_ptrace(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(probe_to_attack(probe_escape_syscall(
            EscapeSyscallProbe::Ptrace,
        )));
    }

    /// ESC-06: segment 数上限超過の `kexec_load`（ロードに至らない）。期待は `attack_esc06_unshare` と同じ。
    fn attack_esc06_kexec_load(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(probe_to_attack(probe_escape_syscall(
            EscapeSyscallProbe::KexecLoad,
        )));
    }

    /// 子側の記録器。攻撃結果を 1 回だけ pipe へ書く。累計量は `RECORD_MAX_BYTES` で打ち切る。
    /// 監査レコードは書かない（攻撃側が書いた記録は SEC-4 の証拠にならない。#2028）。
    pub struct Recorder {
        inner: Mutex<RecorderState>,
    }

    struct RecorderState {
        writer: PipeWriter,
        written: usize,
        outcome_written: bool,
    }

    impl Recorder {
        fn new(writer: PipeWriter) -> Self {
            Recorder {
                inner: Mutex::new(RecorderState {
                    writer,
                    written: 0,
                    outcome_written: false,
                }),
            }
        }

        fn write_line(&self, line: &str) -> Result<(), TraitError> {
            let fail = |msg: &str| TraitError::new(ErrorCode::Internal, msg.to_string());
            let mut st = self.inner.lock().map_err(|_| fail("recorder poisoned"))?;
            if st.written.saturating_add(line.len() + 1) > RECORD_MAX_BYTES {
                return Err(fail("record size limit exceeded"));
            }
            st.writer
                .write_all(line.as_bytes())
                .and_then(|()| st.writer.write_all(b"\n"))
                .map_err(|_| fail("failed to write the record"))?;
            st.written += line.len() + 1;
            Ok(())
        }

        /// 攻撃の結果を記録する（1 回だけ。2 回目は panic し、子の異常終了として失敗にする）。
        pub fn outcome(&self, outcome: AttackOutcome) {
            {
                let mut st = self.inner.lock().expect("recorder lock");
                assert!(!st.outcome_written, "outcome must be recorded once");
                st.outcome_written = true;
            }
            self.write_line(&format!("outcome={}", outcome.render()))
                .expect("write outcome");
        }
    }

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let id = args.get(i + 1).expect("case id after --scenario");
                let rootfs = args.get(i + 2).expect("rootfs path after the case id");
                let state_root = args.get(i + 3).expect("state root path after the rootfs");
                scenario(id, Path::new(rootfs), Path::new(state_root));
            }
            None => dispatcher(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/` と ESC-04 の攻撃対象（`sys/fs/cgroup/release_agent`）を持つ rootfs を排他的に作る（推測されにくい名前・`mkdir` は既存なら失敗）。
    fn make_rootfs() -> Rootfs {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-escape-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        // ESC-04 の攻撃対象を rootfs 内に実在させる（ENOENT で防御を検証できないことを避ける）。
        let target = ESC04_TARGET_REL
            .iter()
            .fold(rootfs.0.clone(), |p, c| p.join(c));
        let parent_rel = &ESC04_TARGET_REL[..ESC04_TARGET_REL.len() - 1];
        temp_rootfs::create_dir_chain(&rootfs.0, parent_rel);
        std::fs::write(&target, b"").expect("create rootfs release_agent stand-in");
        rootfs
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(child: &mut std::process::Child, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    while child.try_wait().expect("try_wait").is_none() {
                        assert!(
                            Instant::now() < reap_deadline,
                            "the child was not reaped after SIGKILL"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// `/proc/self/status` の `Uid:`・`Gid:` 行の effective（2 列目）を返す。
    fn effective_ids() -> (u32, u32) {
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        let field = |key: &str| -> u32 {
            status
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{key} line in /proc/self/status"))
        };
        (field("Uid:"), field("Gid:"))
    }

    fn is_root() -> bool {
        effective_ids().0 == 0
    }

    /// 自プロセスの `Seccomp:` 行の値（`/proc/self/status`）。
    fn seccomp_mode_of_self() -> String {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp:").map(|v| v.trim().to_string()))
            .expect("Seccomp line in /proc/self/status")
    }

    /// パイプを別スレッドで上限付きに読み切り、結果を channel で返す（呼び出し側が期限付きで待つ）。
    fn drain<R: std::io::Read + Send + 'static>(r: R) -> std::sync::mpsc::Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = r.take(RECORD_MAX_BYTES as u64).read_to_string(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    }

    /// 状態ルート（ケースごとに排他作成する 0700 のディレクトリ。`@audit.log` と状態ストアの置き場。drop で削除）を
    /// `rootfs` の隣に作る。名前は rootfs と同じ接頭辞に `-state` を付ける（canary の `-canary` と同じ規則）。
    fn make_state_root(rootfs: &Path) -> Rootfs {
        use std::os::unix::fs::DirBuilderExt as _;
        let path = state_root_for(rootfs);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("exclusively create the state root");
        Rootfs(path)
    }

    fn state_root_for(rootfs: &Path) -> PathBuf {
        let mut name = rootfs.as_os_str().to_os_string();
        name.push("-state");
        PathBuf::from(name)
    }

    /// カーネル監査ログの置き場（auditd の既定）。
    const KERNEL_AUDIT_LOG: &str = "/var/log/audit/audit.log";
    /// カーネル監査ログの読み出し上限（ケース 1 件の開始後に増えた分）。
    const KERNEL_AUDIT_READ_MAX: u64 = 16 * 1024 * 1024;
    /// 記録が audit ログに現れるのを待つ上限（REPAIR-5）。
    const KERNEL_AUDIT_WAIT: Duration = Duration::from_secs(10);

    /// opt-in の段（`KERNEL_AUDIT_ENV=1`）が有効か。
    fn kernel_audit_enabled() -> bool {
        std::env::var(super::KERNEL_AUDIT_ENV).is_ok_and(|v| v == "1")
    }

    /// opt-in の段の前提（Landlock ABI 7 以上・audit ログの可読）を確かめる。欠けたら skip せず panic（失敗）にする。
    fn require_kernel_audit_prerequisites() {
        let support = detect_landlock_abi()
            .unwrap_or_else(|e| panic!("{}=1 needs Landlock: {e}", super::KERNEL_AUDIT_ENV));
        assert!(
            support.abi.get() >= MIN_LANDLOCK_AUDIT_ABI,
            "{}=1 needs Landlock ABI {MIN_LANDLOCK_AUDIT_ABI}+, detected {}",
            super::KERNEL_AUDIT_ENV,
            support.abi.get()
        );
        std::fs::File::open(KERNEL_AUDIT_LOG).unwrap_or_else(|e| {
            panic!(
                "{}=1 needs a readable {KERNEL_AUDIT_LOG} (auditd + permission): {e}",
                super::KERNEL_AUDIT_ENV
            )
        });
    }

    /// カーネル監査ログの現在の長さ（ケースの開始前に取り、増えた分だけを読む）。
    fn kernel_audit_len() -> u64 {
        std::fs::metadata(KERNEL_AUDIT_LOG)
            .unwrap_or_else(|e| panic!("stat {KERNEL_AUDIT_LOG}: {e}"))
            .len()
    }

    /// `start` 以降に追記されたカーネル監査ログを上限つきで読む。
    fn read_kernel_audit_since(start: u64) -> String {
        use std::io::{Seek as _, SeekFrom};
        let mut file = std::fs::File::open(KERNEL_AUDIT_LOG)
            .unwrap_or_else(|e| panic!("open {KERNEL_AUDIT_LOG}: {e}"));
        file.seek(SeekFrom::Start(start))
            .unwrap_or_else(|e| panic!("seek {KERNEL_AUDIT_LOG}: {e}"));
        let mut bytes = Vec::new();
        file.take(KERNEL_AUDIT_READ_MAX)
            .read_to_end(&mut bytes)
            .unwrap_or_else(|e| panic!("read {KERNEL_AUDIT_LOG}: {e}"));
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// 状態ルートの `@audit.log` を上限つきで読んで解析する（無ければ空）。読めない・不正なら `Err`。
    fn collect_state_root_log(state_root: &Path) -> Result<Vec<super::AuditLine>, String> {
        let path = state_root.join(AUDIT_LOG_FILE_NAME);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("open {}: {e}", path.display())),
        };
        let mut text = String::new();
        file.take(super::STATE_LOG_MAX_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        super::parse_state_root_log(&text)
    }

    /// 共通関数（ディスパッチャ側）: 1 ケースを「起動 → 攻撃 → 回収 → 判定 → 後始末」で実行する。
    ///
    /// rootfs・状態ルートの作成、自身のシナリオ再起動、期限付き待機、出力と監査の証拠の回収を行い、
    /// 判定（`judge`）はここ（コンテナの外・ホスト視点）で行う。rootfs と状態ルートは drop で削除する。
    /// 起動ユーザーの前提（`EscapeCase::launcher`）が成立しなければ、シナリオを起動せず `NotApplicable` を返す。
    fn run_case(case: &EscapeCase) -> CaseRun {
        // 前提の判定はディスパッチャ自身（分離前・ホスト側）の実効 UID で行う。user namespace 内では
        // 写像後の UID が 0 に見えるため、シナリオ・子の側では判定しない。
        if let Err(na) = launcher_applicability(case.launcher, is_root()) {
            return CaseRun::NotApplicable(na);
        }
        CaseRun::Ran(run_scenario(case))
    }

    /// 1 ケースの実行結果。対象外（`NotApplicable`）は合格ではなく、検証していないことを表す。
    enum CaseRun {
        Ran(CaseVerdict),
        NotApplicable(NotApplicable),
    }

    /// 監査の証拠をコンテナの外で回収する。`NotApplicable` 以外は本番の配送経路の出力だけから作る。
    fn collect_evidence(
        case: &EscapeCase,
        state_root: &Path,
        meta: &ScenarioMeta,
        kernel_start: Option<u64>,
    ) -> Result<AuditEvidence, String> {
        let AuditExpectation::Required { source, .. } = case.expectation.audit else {
            return Ok(AuditEvidence::NotApplicable);
        };
        match source {
            AuditSource::StateRootLog { .. } => Ok(AuditEvidence::StateRootLog {
                lines: collect_state_root_log(state_root)?,
                subject_pid: meta.pid_in_ns.map(u64::from),
            }),
            AuditSource::KernelAudit { blockers } => {
                let Some(start) = kernel_start else {
                    return Ok(AuditEvidence::NotCollected {
                        reason: KERNEL_AUDIT_NOT_ENABLED,
                    });
                };
                let pid = meta.child_pid.ok_or_else(|| {
                    "harness invariant violated: a kernel-audit case has no child pid".to_string()
                })?;
                // 記録は非同期に audit ログへ届くため、見つかるか期限まで待つ（REPAIR-5）。
                let deadline = Instant::now() + KERNEL_AUDIT_WAIT;
                loop {
                    let log = read_kernel_audit_since(start);
                    let matched =
                        count_landlock_access_records(&log, pid, blockers, meta.started_at);
                    if matched > 0 || Instant::now() >= deadline {
                        return Ok(AuditEvidence::KernelAudit { matched });
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    /// `run_case` の本体: 起動前提の成立済みのケースを起動・判定・後始末する。
    fn run_scenario(case: &EscapeCase) -> CaseVerdict {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
        let state_root = make_state_root(&rootfs.0);
        // シナリオの異常終了・panic でも canary ディレクトリが残らないよう、ディスパッチャ側でも
        // 全終了経路（drop）で削除する（未作成なら no-op）。
        let _canary_cleanup = Rootfs(canary_dir_for(&rootfs.0));
        // 開始前のカーネル監査ログの長さ（opt-in の段のみ）。
        let kernel_start = (kernel_audit_enabled()
            && matches!(
                case.expectation.audit,
                AuditExpectation::Required {
                    source: AuditSource::KernelAudit { .. },
                    ..
                }
            ))
        .then(kernel_audit_len);
        let mut child = Command::new(&exe)
            .args(["--scenario", case.id])
            .arg(&rootfs.0)
            .arg(&state_root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn scenario");
        // シナリオ内の子待ち（`timeout()`）より長い期限にして、シナリオ側の失敗報告を優先させる。
        let limit = timeout() + Duration::from_secs(10);
        let status = wait_deadline(&mut child, limit);
        let mut stdout = String::new();
        let mut stderr = String::new();
        // 孫プロセスが fd を保持したまま残ると EOF が来ないため、読み出しは別スレッドで行い期限付きで待つ。
        let readers = [
            child.stdout.take().map(drain),
            child.stderr.take().map(drain),
        ];
        let [out_rx, err_rx] = readers;
        if let Some(rx) = out_rx {
            stdout = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
        }
        if let Some(rx) = err_rx {
            stderr = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
        }
        print!("{stdout}");
        let failed = |detail: String| CaseVerdict::Fail(vec![Mismatch::ScenarioFailed { detail }]);
        match status {
            Some(st) if st.code() == Some(0) => {}
            Some(st) => return failed(format!("scenario exited with {st}; stderr:\n{stderr}")),
            None => {
                return failed(format!(
                    "scenario did not exit within {limit:?}; stderr:\n{stderr}"
                ));
            }
        }
        let meta = match ScenarioMeta::parse_from_stdout(&stdout) {
            Ok(m) => m,
            Err(e) => return failed(format!("invalid scenario result: {e}; stderr:\n{stderr}")),
        };
        let audit = match collect_evidence(case, &state_root.0, &meta, kernel_start) {
            Ok(a) => a,
            Err(e) => return failed(format!("audit evidence could not be collected: {e}")),
        };
        let mut verdict = judge(
            &case.expectation,
            &Observation {
                exit: meta.exit,
                outcome: meta.outcome,
                audit,
            },
        );
        if let Some(check) = case.host_check {
            let (euid, egid) = effective_ids();
            let view = HostView {
                rootfs: &rootfs.0,
                euid,
                egid,
                is_root: euid == 0,
            };
            if let Err(detail) = check(&view) {
                let mismatch = Mismatch::HostCheckFailed { detail };
                verdict = match verdict {
                    CaseVerdict::Fail(mut m) => {
                        m.push(mismatch);
                        CaseVerdict::Fail(m)
                    }
                    _ => CaseVerdict::Fail(vec![mismatch]),
                };
            }
        }
        verdict
    }

    fn dispatcher() {
        let kernel_audit = kernel_audit_enabled();
        if kernel_audit {
            require_kernel_audit_prerequisites();
        }
        let mut failed = 0usize;
        let mut verified = 0usize;
        let mut not_applicable = Vec::new();
        let mut audit_not_verified = Vec::new();
        for case in CASES {
            match run_case(case) {
                CaseRun::Ran(CaseVerdict::Pass) => verified += 1,
                CaseRun::Ran(CaseVerdict::AuditNotVerified { layer, reason }) => {
                    // 攻撃の結果は期待どおりだが、要求された監査は照合していない。合格として数えない（SEC-4）。
                    println!(
                        "escape_suite: {} verdict=audit-not-verified behavior=SEC-4 layer={layer} reason={reason:?}",
                        case.id
                    );
                    audit_not_verified.push(case.id);
                }
                CaseRun::Ran(verdict) => {
                    failed += 1;
                    eprintln!("escape_suite: {} verdict=fail {verdict:?}", case.id);
                }
                CaseRun::NotApplicable(na) => {
                    // 検証していないことを理由とビヘイビア ID 付きで出力する（合格として数えない）。
                    println!(
                        "escape_suite: {} verdict=not-applicable behavior={} reason={:?}",
                        case.id, na.behavior, na.reason
                    );
                    not_applicable.push(case.id);
                }
            }
        }
        assert_eq!(failed, 0, "{failed} escape case(s) failed");
        // 非 root 起動で対象外になるケースは存在しない（`launcher_applicability` の契約）。
        assert!(
            is_root() || not_applicable.is_empty(),
            "non-root launcher must run every case: {not_applicable:?}"
        );
        // opt-in の段では、監査を照合できなかったケースがあってはならない（ハーネスの不変条件）。
        assert!(
            !kernel_audit || audit_not_verified.is_empty(),
            "kernel audit was enabled but these cases were not verified: {audit_not_verified:?}"
        );
        println!(
            "escape_suite: SEC-2 harness verified {verified} of {} case(s), not applicable {:?}, audit not verified {:?} (root={}, kernel_audit={})",
            CASES.len(),
            not_applicable,
            audit_not_verified,
            is_root(),
            kernel_audit
        );
    }

    /// ホスト側 canary の初期内容。
    const CANARY_CONTENT: &[u8] = b"fandhe-escape-host-canary\n";

    /// rootfs と同じ親ディレクトリに作る canary ディレクトリのパス（rootfs の外）。
    fn canary_dir_for(rootfs: &Path) -> PathBuf {
        let mut name = rootfs.as_os_str().to_os_string();
        name.push("-canary");
        PathBuf::from(name)
    }

    /// canary が攻撃後も無変更か（内容一致・ディレクトリに余計なエントリなし）。違反なら詳細を返す。
    fn canary_violation(dir: &Path, canary: &Path) -> Option<String> {
        match std::fs::read(canary) {
            Ok(c) if c == CANARY_CONTENT => {}
            Ok(c) => return Some(format!("canary content changed ({} bytes)", c.len())),
            Err(e) => return Some(format!("canary unreadable: {e}")),
        }
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                let count = entries.count();
                (count != 1).then(|| format!("canary dir has {count} entries (expected 1)"))
            }
            Err(e) => Some(format!("canary dir unreadable: {e}")),
        }
    }

    /// 現在の UNIX 秒。
    fn unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 本番の監査配送の入口（`FileAuditSink` ← `ControlAuditRelay`）を作る。`ControlAuditRelay::spawn` は単一スレッドの
    /// 呼び出し元を要求し helper プロセスを fork するため、`isolate()` とスレッドの作成より前に呼ぶ（複数スレッドに
    /// なった後の `FileAuditSink` は NETLINK_AUDIT の代替経路へ回り、非 root では記録を失う）。
    fn spawn_relay(state_root: &Path) -> Arc<ControlAuditRelay> {
        let sink = FileAuditSink::open_in_state_root(Some(state_root.to_path_buf()))
            .unwrap_or_else(|e| panic!("open the audit sink in the state root: {e}"));
        Arc::new(
            ControlAuditRelay::spawn(sink).unwrap_or_else(|e| panic!("spawn the audit relay: {e}")),
        )
    }

    /// シナリオ: 分離 → 子で攻撃 → 記録回収 → meta 行の出力。判定はディスパッチャが行う
    /// （監査の証拠はシナリオの外で回収するため）。canary の変化はここで検出して失敗（終了コード 1）にする。
    fn scenario(case_id: &str, rootfs: &Path, state_root: &Path) {
        let case = CASES
            .iter()
            .find(|c| c.id == case_id)
            .unwrap_or_else(|| panic!("unknown escape case {case_id:?}"));
        // 継承した seccomp フィルタがあると拒否を組み込み段へ帰属できないため、事前条件として失敗扱いにする。
        assert_eq!(
            seccomp_mode_of_self(),
            "0",
            "precondition: the test process must not inherit a seccomp filter (cannot attribute the denial to the built-in stage)"
        );
        let started_at = unix_secs();
        // seccomp の記録を運ぶ本番の監査配送の入口（relay）は、最初に（`isolate()`・スレッドより前に）作る。
        let relay =
            (case.body == CaseBody::ProbeWithSeccompListener).then(|| spawn_relay(state_root));
        let meta = match case.body {
            CaseBody::StartRejection => start_rejection(rootfs, state_root, started_at),
            CaseBody::CreateRejection => create_rejection(rootfs, state_root, started_at),
            CaseBody::StartDestinationRewrite => {
                start_destination_rewrite(rootfs, state_root, started_at)
            }
            CaseBody::Probe | CaseBody::ProbeWithSeccompListener => {
                probe_scenario(case, rootfs, relay, started_at)
            }
        };
        println!("{}", meta.render());
    }

    /// `/proc/<pid>/status` の `NSpid` の末尾（対象自身の PID namespace での pid）を返す。本番の supervisor の変換
    /// （`seccomp_notify::parse_nspid_innermost`）と同じ規則で、行が無い・0・壊れた値は `None`（記録しない）。
    /// `seccomp_notif.pid` は listener の PID namespace の値で、無変換では記録に渡せない（`SeccompDenialReport::from_user_notif`）。
    fn pid_in_own_ns(pid_in_listener_ns: u32) -> Option<u32> {
        let status = std::fs::read(format!("/proc/{pid_in_listener_ns}/status")).ok()?;
        let line = status
            .split(|b| *b == b'\n')
            .find_map(|l| l.strip_prefix(b"NSpid:".as_slice()))?;
        let last = line
            .split(|b| b.is_ascii_whitespace())
            .rfind(|t| !t.is_empty())?;
        std::str::from_utf8(last)
            .ok()?
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
    }

    /// 応答者（ESC-03）: seccomp の listener の通知を受けて、`record_seccomp_denial_for` → 本番の sink で記録し、
    /// `-EPERM` で応答する。試験側の応答ループで、supervisor の `SeccompNotifyHub` そのものではない（core の公開 API
    /// だけで組む。hub をコンテナ経由で通す照合は `supervisor_bin_real` のシナリオ E が担う。#2482）。記録の成否にかかわらず応答は必ず返し、許可（`CONTINUE`）には覆さない。
    ///
    /// シナリオプロセスは `isolate()` の `unshare(CLONE_NEWPID)` の後にスレッドを作れない（`clone(2)` の EINVAL）ため、
    /// 呼び出し元のスレッドで回す。子の終了（回収）を各周回で確かめ、回収済み・listener の閉鎖・期限超過で抜ける。
    /// 期限を過ぎたら子を kill して回収してから panic する（REPAIR-5）。抜けた後の終了状態は `child` から得る。
    fn respond_loop(
        child: &ContainerChild,
        listener: &SeccompListener,
        sink: &dyn AuditSink,
        container: &ContainerId,
    ) -> ChildExit {
        const POLL: Duration = Duration::from_millis(100);
        let deadline = Instant::now() + timeout();
        loop {
            match child.wait_for_exit(Duration::ZERO) {
                Ok(Some(exit)) => return exit,
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill_and_reap(Duration::from_secs(5));
                    panic!("wait: {e}")
                }
            }
            let now = Instant::now();
            if now >= deadline {
                let diag = crate::proc_status::excerpt(child.pid());
                let _ = child.kill_and_reap(Duration::from_secs(5));
                panic!(
                    "the container process did not exit within {:?}; {diag}",
                    timeout()
                );
            }
            match listener.wait(POLL.min(deadline - now)) {
                Ok(ListenerReadiness::Readable) => {}
                Ok(ListenerReadiness::Idle) => continue,
                // 利用者の消滅（子の終了）か読めない状態。以後の通知は来ない。終了状態の回収へ進む。
                _ => break,
            }
            let notification = match listener.receive() {
                Ok(Some(n)) => n,
                Ok(None) => continue,
                Err(_) => break,
            };
            let id = notification.id();
            // 対象がまだ応答待ちであることを確かめてから記録する（pid の再利用で別プロセスを記録しない）。
            if listener.is_pending(id).unwrap_or(false)
                && let Some(pid_in_process_ns) = pid_in_own_ns(notification.pid_in_listener_ns())
                && let Ok(report) = SeccompDenialReport::from_user_notif(
                    pid_in_process_ns,
                    notification.nr(),
                    notification.arch(),
                )
                && let Ok(at) = AuditTimestamp::now()
            {
                let _ = record_seccomp_denial_for(&report, at, Some(container), sink);
            }
            let _ = listener.deny_eperm(id);
        }
        child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        })
    }

    /// 子（コンテナ）で攻撃を実行するシナリオ（`CaseBody::Probe` / `ProbeWithSeccompListener`）。
    fn probe_scenario(
        case: &EscapeCase,
        rootfs: &Path,
        relay: Option<Arc<ControlAuditRelay>>,
        started_at: u64,
    ) -> ScenarioMeta {
        let is_root = is_root();
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        // ホスト側 canary（rootfs の外。ESC-01 の到達観測対象）。分離後もホスト FS は親から見える。
        let canary_dir = Rootfs(canary_dir_for(rootfs));
        std::fs::create_dir(&canary_dir.0).expect("exclusively create canary dir");
        let canary = canary_dir.0.join("canary");
        std::fs::write(&canary, CANARY_CONTENT).expect("write canary");
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o666))
            .expect("chmod canary");

        // ESC-01 の対照ファイル（rootfs 内。rootfs と共にディスパッチャが削除する）。
        std::fs::write(rootfs.join(CONTROL_NAME), b"control\n").expect("write control file");

        let (reader, writer) = std::io::pipe().expect("create record pipe");
        (case.precondition)();
        let attack = case.attack;
        let attack_canary = canary.clone();
        // 親側の writer 端は fork 時に閉じられる（クロージャは子にだけ残る）ため、子の終了で EOF になる。
        let probe = move || {
            let recorder = Recorder::new(writer);
            attack(&recorder, &attack_canary);
        };
        let stages = (case.stages)();
        let (child, listener) = match case.body {
            CaseBody::ProbeWithSeccompListener => {
                let (child, listener) =
                    spawn_container_probe_with_seccomp_listener(rootfs, stages, probe)
                        .unwrap_or_else(|e| panic!("spawn with the seccomp listener: {e}"));
                (child, Some(listener))
            }
            CaseBody::Probe => (
                spawn_container_probe(rootfs, stages, probe)
                    .unwrap_or_else(|e| panic!("spawn: {e}")),
                None,
            ),
            CaseBody::StartRejection => unreachable!("handled by start_rejection"),
            CaseBody::CreateRejection => unreachable!("handled by create_rejection"),
            CaseBody::StartDestinationRewrite => {
                unreachable!("handled by start_destination_rewrite")
            }
        };
        let child_pid = child.pid();
        // seccomp の記録の期待値: 子自身の PID namespace での pid。子の最初の拒否は応答ループが読むまで
        // 保留されるため、ループの開始前（ここ）に外側から独立に読む。listener を使わないケースは不要。
        let pid_in_ns = (case.body == CaseBody::ProbeWithSeccompListener)
            .then(|| pid_in_own_ns(child_pid))
            .flatten();
        // このプロセスは `isolate()` で PID namespace を unshare 済みのため、スレッドを作れない（`clone(2)` の
        // `CLONE_THREAD` は EINVAL）。応答と回収は単一スレッドで行う。
        let exit = match listener {
            Some(listener) => {
                // 子は listener の ACK を受けた後に拒否対象の syscall を発行し、通知は読まれるまでカーネル内で保留される。
                let relay = relay.expect("a listener case records to the state root");
                let container = ContainerId::new(AUDIT_CONTAINER_ID).expect("harness container id");
                respond_loop(&child, &listener, relay.as_ref(), &container)
            }
            None => child.wait_timeout(timeout()).unwrap_or_else(|e| {
                let diag = crate::proc_status::excerpt(child.pid());
                let _ = child.kill_and_reap(Duration::from_secs(5));
                panic!("wait: {e}; {diag}")
            }),
        };
        let exit = match exit {
            ChildExit::Exited(c) => ObservedExit::Exited(c),
            ChildExit::Signaled(s) => ObservedExit::Signaled(s),
            other => panic!("unexpected child exit {other:?}"),
        };

        // 子（新しい PID namespace の PID 1）が終了すると、カーネルは namespace 内の全プロセスを終わらせて回収してから
        // 終了を親へ報告する（`zap_pid_ns_processes`）。親側の writer は fork 時に閉じ済みなので、回収後は EOF に
        // 直ちに届き、期限なしで読んでもブロックしない（REPAIR-5。全体の上限は dispatcher の `wait_deadline`）。
        // 子は 16 KiB 以下しか書かず（`RECORD_MAX_BYTES`）既定の pipe 容量より小さいため、読み手がいなくても詰まらない。
        // 上限 + 1 バイトで打ち切り、超過は記録として不正にする。
        let mut text = String::new();
        reader
            .take(RECORD_MAX_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .expect("read record");
        // outcome 欠落は `judge` が終了状態と突き合わせて判定する（シグナル終了では行が残らないことがある）。
        let record = parse_record(&text)
            .unwrap_or_else(|e| panic!("invalid record from the container: {e}"));
        // ホスト側 canary の無変更を、コンテナ外から観測する（到達・書き込みの副作用の有無）。
        if let Some(detail) = canary_violation(&canary_dir.0, &canary) {
            eprintln!(
                "escape_suite: {} verdict=fail {:?}",
                case.id,
                Mismatch::HostTargetModified { detail }
            );
            drop(canary_dir);
            std::process::exit(1);
        }
        ScenarioMeta {
            exit,
            outcome: record.outcome,
            child_pid: Some(child_pid),
            pid_in_ns,
            started_at,
        }
    }

    /// `start` の拒否で何も起動しないことの確認用 launcher。拒否の監査 sink として本番の `FileAuditSink`
    /// （状態ルートの `@audit.log` が主経路）を返す。`launch` に到達したら（＝拒否されなかったら）回数を数えて
    /// 失敗を返す。
    ///
    /// 本番の `ProductionLauncher` は構築にホストの前提（cgroup 等）を要するため使わない。`rejection_audit_sink` が
    /// 構築時の sink をそのまま返すことは `launcher.rs` の単体試験（`sec4_rejection_audit_sink_is_the_launcher_sink`）
    /// が担い、ここでは `start` の拒否経路から本番の sink 経由で `@audit.log` に届くまでを照合する（#2028）。
    ///
    /// `ControlAuditRelay` は使わない: この試験は単一スレッドで `start` を呼ぶため `FileAuditSink` が主経路で書ける。
    /// 本番の supervisor の `start` は検証が複数スレッドの作業スレッドで走るので、`rejection_audit_sink` に relay
    /// （理由なしの `Mount` と、rootfs の固定の違反の閉じた表の理由つき `Mount` を運べる。#2481・#2623）を渡す。その経路の照合は supervisor の結合試験
    /// `start_bind_audit_relay` が担う（docs/design/audit-delivery.md）。
    struct RejectionOnlyLauncher {
        sink: FileAuditSink,
        launches: AtomicUsize,
    }

    impl ProcessLauncher for RejectionOnlyLauncher {
        fn rejection_audit_sink(&self) -> Option<&dyn AuditSink> {
            Some(&self.sink)
        }

        fn launch(
            &self,
            _spec: &LaunchSpec,
            _timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Err(TraitError::new(
                ErrorCode::Internal,
                "the escape suite launcher never launches",
            ))
        }
    }

    /// ESC-08 の本体: マウント元が rootfs・bundle・状態ルートの bind を持つ config の `start` が、いずれも
    /// `InvalidArgument` で拒否されること（launcher に到達しない・状態は Created のまま）を確かめる。
    /// 記録は本番の拒否経路が出す（ここでは作らない）。ディスパッチャが `@audit.log` の mount 層 3 行を照合する。
    fn start_rejection(bundle: &Path, state_root: &Path, started_at: u64) -> ScenarioMeta {
        let id = ContainerId::new(AUDIT_CONTAINER_ID).expect("harness container id");
        // `FileAuditSink` は単一スレッドの呼び出し元から記録するとき、書き込みを fork した子で行う（複数スレッドでは
        // NETLINK_AUDIT の代替経路へ回る）。このシナリオは `start` の拒否までスレッドを作らない。
        let sink = FileAuditSink::open_in_state_root(Some(state_root.to_path_buf()))
            .unwrap_or_else(|e| panic!("open the audit sink in the state root: {e}"));
        std::fs::create_dir(bundle.join("rootfs")).expect("create bundle/rootfs");
        let store = FileStateStore::open(
            StateRoot::from_override(state_root.to_path_buf()).expect("state root"),
        )
        .unwrap_or_else(|e| panic!("open the state store: {e}"));
        let recorder = OpRecorder::new();
        let config = |mounts: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/echo", "it"], "cwd": "/"},
                "mounts": mounts,
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
                ]}
            }))
            .expect("serialize config")
        };
        let config_path = bundle.join("config.json");
        std::fs::write(&config_path, config(serde_json::json!([]))).expect("write config");
        create(
            &store,
            &recorder,
            &CreateRequest::new(id.clone(), bundle.to_path_buf()).expect("absolute bundle"),
        )
        .unwrap_or_else(|e| panic!("create: {e}"));

        let launcher = Arc::new(RejectionOnlyLauncher {
            sink,
            launches: AtomicUsize::new(0),
        });
        let dyn_launcher: Arc<dyn ProcessLauncher> = launcher.clone();
        let host_state_root = store
            .host_state_root()
            .expect("the file store knows its root")
            .to_path_buf();
        let sources = [bundle.join("rootfs"), bundle.to_path_buf(), host_state_root];
        let mut outcome = AttackOutcome::Failed;
        for source in &sources {
            let mounts = serde_json::json!([{
                "destination": "/data",
                "type": "bind",
                "source": source.to_str().expect("utf-8 path"),
                "options": ["rbind", "rw"]
            }]);
            std::fs::write(&config_path, config(mounts)).expect("rewrite config");
            match start(
                &store,
                &recorder,
                &dyn_launcher,
                &StartRequest::new(id.clone()),
                &StartTimeouts::default(),
            ) {
                // 拒否されなかった（bind の元の制限の欠落）。残りは試さず、成功として失敗にする。
                Ok(_) => {
                    outcome = AttackOutcome::Succeeded;
                    break;
                }
                Err(err) => assert_eq!(
                    err.code(),
                    ErrorCode::InvalidArgument,
                    "bind source {} must be rejected as InvalidArgument: {err}",
                    source.display()
                ),
            }
        }
        assert_eq!(
            launcher.launches.load(Ordering::SeqCst),
            0,
            "a rejected start must never reach the launcher"
        );
        let state = store
            .get(&GetStateRequest::new(id))
            .expect("state after the rejected starts");
        assert_eq!(
            state.status().state(),
            ContainerState::Created,
            "a rejected start leaves the container Created"
        );
        ScenarioMeta {
            exit: ObservedExit::Exited(0),
            outcome: Some(outcome),
            child_pid: None,
            pid_in_ns: None,
            started_at,
        }
    }

    /// ESC-08 のパース時の拒否の本体（SEC-2・SEC-4・OCI-4・TASK-42.4・#202・#2480）: 宛先が rootfs 外への遡り・
    /// rootfs 全体・相対 `..` の config を、CLI と同じ構成（`FileStateStore` ＋ 状態ルートの `FileAuditSink`）の
    /// `create_audited` へ渡し、いずれも `InvalidArgument` で拒否されて状態が作られないことを確かめる。
    /// 記録は本番の拒否経路が出す（ここでは作らない）。ディスパッチャが `@audit.log` の mount 層 3 行を照合する。
    fn create_rejection(bundle: &Path, state_root: &Path, started_at: u64) -> ScenarioMeta {
        let id = ContainerId::new(AUDIT_CONTAINER_ID).expect("harness container id");
        // 単一スレッドの呼び出し元なので、書き込みは fork した子で行われる（`start_rejection` と同じ前提）。
        let sink = FileAuditSink::open_in_state_root(Some(state_root.to_path_buf()))
            .unwrap_or_else(|e| panic!("open the audit sink in the state root: {e}"));
        std::fs::create_dir(bundle.join("rootfs")).expect("create bundle/rootfs");
        let store = FileStateStore::open(
            StateRoot::from_override(state_root.to_path_buf()).expect("state root"),
        )
        .unwrap_or_else(|e| panic!("open the state store: {e}"));
        let recorder = OpRecorder::new();
        let config_path = bundle.join("config.json");
        let mut outcome = AttackOutcome::Failed;
        for dest in ESC08_DESTINATIONS {
            let config = serde_json::to_vec(&serde_json::json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/echo", "it"], "cwd": "/"},
                "mounts": [{
                    "destination": dest,
                    "type": "bind",
                    "source": "/run/fandhe-container",
                    "options": ["bind"]
                }]
            }))
            .expect("serialize config");
            std::fs::write(&config_path, config).expect("write config");
            match create_audited(
                &store,
                &recorder,
                &CreateRequest::new(id.clone(), bundle.to_path_buf()).expect("absolute bundle"),
                &sink,
            ) {
                // 拒否されなかった（destination の検証の欠落）。残りは試さず、成功として失敗にする。
                Ok(_) => {
                    outcome = AttackOutcome::Succeeded;
                    break;
                }
                Err(err) => assert_eq!(
                    err.code(),
                    ErrorCode::InvalidArgument,
                    "destination {dest:?} must be rejected as InvalidArgument: {err}"
                ),
            }
        }
        assert!(
            store.get(&GetStateRequest::new(id)).is_err(),
            "a rejected create must not leave a state"
        );
        ScenarioMeta {
            exit: ObservedExit::Exited(0),
            outcome: Some(outcome),
            child_pid: None,
            pid_in_ns: None,
            started_at,
        }
    }

    /// ESC-08 の start の TOCTOU の本体（SEC-4・OCI-4・#2594・#2641）: 正しい config で `create` した後に
    /// `config.json` の destination を遡り・`/`・相対 `..` へ書き換え、`start` の再検証がいずれも
    /// `InvalidArgument` で拒否すること（launcher に到達しない・状態は Created のまま）を確かめる。
    /// 記録は本番の拒否経路が出す（ここでは作らない）。ディスパッチャが `@audit.log` の mount 層 3 行
    /// （要求ごとに 1 行。cgroup の準備は supervisor 側で core の `start` には無い）を照合する。
    /// 単一スレッドで `FileAuditSink` を使う前提は `start_rejection` と同じ。supervisor の relay 経由は結合試験
    /// `start_destination_audit_relay` が担う。
    fn start_destination_rewrite(
        bundle: &Path,
        state_root: &Path,
        started_at: u64,
    ) -> ScenarioMeta {
        let id = ContainerId::new(AUDIT_CONTAINER_ID).expect("harness container id");
        let sink = FileAuditSink::open_in_state_root(Some(state_root.to_path_buf()))
            .unwrap_or_else(|e| panic!("open the audit sink in the state root: {e}"));
        std::fs::create_dir(bundle.join("rootfs")).expect("create bundle/rootfs");
        let store = FileStateStore::open(
            StateRoot::from_override(state_root.to_path_buf()).expect("state root"),
        )
        .unwrap_or_else(|e| panic!("open the state store: {e}"));
        let recorder = OpRecorder::new();
        let config = |mounts: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/echo", "it"], "cwd": "/"},
                "mounts": mounts,
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
                ]}
            }))
            .expect("serialize config")
        };
        let config_path = bundle.join("config.json");
        std::fs::write(&config_path, config(serde_json::json!([]))).expect("write config");
        create(
            &store,
            &recorder,
            &CreateRequest::new(id.clone(), bundle.to_path_buf()).expect("absolute bundle"),
        )
        .unwrap_or_else(|e| panic!("create: {e}"));

        let launcher = Arc::new(RejectionOnlyLauncher {
            sink,
            launches: AtomicUsize::new(0),
        });
        let dyn_launcher: Arc<dyn ProcessLauncher> = launcher.clone();
        let mut outcome = AttackOutcome::Failed;
        for dest in ESC08_DESTINATIONS {
            // create 後の書き換え（TOCTOU）。
            let mounts = serde_json::json!([{
                "destination": dest,
                "type": "bind",
                "source": "/run/fandhe-container",
                "options": ["bind"]
            }]);
            std::fs::write(&config_path, config(mounts)).expect("rewrite config");
            match start(
                &store,
                &recorder,
                &dyn_launcher,
                &StartRequest::new(id.clone()),
                &StartTimeouts::default(),
            ) {
                // 拒否されなかった（start の再検証の欠落）。残りは試さず、成功として失敗にする。
                Ok(_) => {
                    outcome = AttackOutcome::Succeeded;
                    break;
                }
                Err(err) => assert_eq!(
                    err.code(),
                    ErrorCode::InvalidArgument,
                    "rewritten destination {dest:?} must be rejected as InvalidArgument: {err}"
                ),
            }
        }
        assert_eq!(
            launcher.launches.load(Ordering::SeqCst),
            0,
            "a rejected start must never reach the launcher"
        );
        let state = store
            .get(&GetStateRequest::new(id))
            .expect("state after the rejected starts");
        assert_eq!(
            state.status().state(),
            ContainerState::Created,
            "a rejected start leaves the container Created"
        );
        ScenarioMeta {
            exit: ObservedExit::Exited(0),
            outcome: Some(outcome),
            child_pid: None,
            pid_in_ns: None,
            started_at,
        }
    }
}
