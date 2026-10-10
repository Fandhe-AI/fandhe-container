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
//! - 監査（SEC-4）: 本番の監査配送経路（`AuditSink` を fork 後の子へ渡す経路・seccomp ERRNO の報告経路）は
//!   未配線のため、攻撃コード自身が記録ヘルパを呼んで記録を作る方式は監査成功の証拠にならない。
//!   ESC-01・03 は `AuditExpectation::Deferred` とし、監査レコードの有無を合否に使わない（攻撃の拒否検証と
//!   監査配送経路の検証を分離）。ヘルパ自体の契約は core 側ユニットテストが担う。配送経路の配線後に
//!   本番経路の実出力を回収して照合する `Required` へ切り替える
//!
//! # 共通関数の流れ（コンテナ起動 → 攻撃 → 判定 → 後始末）
//! `linux::run_case`（ディスパッチャ）が排他作成した一時 rootfs を用意し、自身を
//! `--scenario <case-id> <rootfs>` で再起動する（`unshare(CLONE_NEWPID)` の後に PID 1 になれるのは最初の
//! 子だけのため、ケースごとに別プロセスにする）。シナリオは分離（`isolate`）→
//! `spawn_container_probe`（制限ステージ通過後の子で攻撃クロージャを実行）→ 子の終了待ち（期限付き）→
//! 子が pipe へ書いた記録（攻撃の結果・監査レコード）の回収 → `judge` による判定を行い、終了後に
//! rootfs を削除する。結果は構造化型（`CaseVerdict`）で返す。
//!
//! # 判定の対象
//! - 攻撃の結果: 許可された結果の集合（`Expectation::allowed`）に入るか。ESC-06 のようにシグナル終了を
//!   期待するケースは `Expectation::signal` で指定する
//! - 監査ログ: `AuditExpectation::Required(layer)` のケースは、そのレイヤーの記録が 0 件なら必ず失敗する。
//!   `AuditExpectation::Deferred(layer)` は spec 上は要求するが本番の配送経路が未配線のため合否に使わない。
//!   監査ログの本番配線（`AuditSink` を fork 後の子へ渡す経路）は未実装（REPAIR-3）のため、現状は攻撃
//!   クロージャが記録ヘルパで作った記録は ESC-07 など一部ケースの暫定方式であり、ESC-10 は
//!   `Deferred`（起動ステージ適用済みの子で追加の Landlock 適用をせず、ステージ自体の回帰を攻撃結果で検出）。
//!   配線完了後は本番経路の出力を照合する形へ置き換える
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
//! `#[ignore]` や feature flag は使わない）。既定の集合では自己テストのみ走る。CI の `integration-test` への
//! 組み込みは ESC-04〜06 の既知失敗の解消と Landlock ABI 6+ runner の確保後に別 PR で行う。実行条件は AGENTS.md
//! 「実機前提テスト」節を参照。
//!
//! # ESC-04〜ESC-06（TASK-42.3・#201・MS-2）
//! - ESC-04（cgroup の `release_agent` 書き込み）・ESC-05（`/proc/sys`・`/proc/sysrq-trigger` 書き込み）は、
//!   書き込み用に「開くだけ」で判定し 1 バイトも書かない（制限が欠けてもホストへ作用させないため）。
//!   ESC-04 は対象（`sys/fs/cgroup/release_agent`）を rootfs に実在させ `Absent` を受理しない。ESC-04・05 とも
//!   `linux.maskedPaths` / `readonlyPaths` が未適用のため、実機実行では本物の欠陥として失敗し得る（期待は変えない）。
//!   適用範囲の限定: ESC-04 は rootfs 内の「通常の空ファイル」への書き込み拒否（`maskedPaths` / `readonlyPaths`
//!   相当のパスマスク）だけを検証し、実際の cgroup v1 `release_agent`（v1 階層の mount 経路）は検証しない
//!   （v1 の mount 拒否は `tests/seccomp.rs`、ホスト側根拠は `tests/cgroups_release_agent.rs`）。
//!   ESC-04・05 とも `EROFS` はそれ自体を読み取り専用の証拠として受理し、ホスト側の権限拒否でも返る
//!   `EPERM` / `EACCES` は、対象パスに実際に適用されるマウント（mountinfo の親子関係から特定する実効マウント）が
//!   読み取り専用であるという証拠（`has_mask_evidence`）がある場合だけ受理する。拒否理由別のより厳密な判定と
//!   実 cgroup v1 の安全な観測は REPAIR-12 の後続課題
//! - ESC-06（禁止 syscall の SIGSYS 強制終了＋監査記録）: SIGSYS での強制終了は spec の期待どおり必須とする。
//!   現行の CORE-5 フィルタは `ERRNO(EPERM)` を返して戻るため、実機実行では失敗する（fail-closed。期待は弱めない）。
//! - ESC-06 の監査（SEC-4）は `AuditExpectation::Deferred("seccomp")` とし、合否に使わない（ESC-03 と同じ扱い）。
//!   理由: 子が SIGSYS で終了すると子からは記録を書けず、親側で取得できる本番の監査経路がまだない。
//!   既存の記録経路はどれも使えない。`ExecError::violation`（`IsolationViolation`）は親側の分離確立時の拒否だけを
//!   表し、seccomp の種別を持たない。`record_seccomp_denial` は SIGSYS の siginfo（`si_syscall`・`si_arch`）か
//!   USER_NOTIF の通知から作る報告を要するが、その配送元（TRAP の SIGSYS ハンドラ / supervisor の USER_NOTIF
//!   listener）は未実装で、親が `waitpid` で得られるのは終了シグナルだけである。親側で記録を推測生成すると
//!   監査の偽造になるため行わない。
//! - 将来仕様（REPAIR-3）: フィルタのアクションを TRAP / USER_NOTIF へ変える設計判断と配送経路の配線
//!   （`audit_log/seccomp_hook.rs`）の後に、その本番経路が出力した記録を親側で回収して照合する
//!   `Required("seccomp")` へ切り替える。`SECCOMP_RET_KILL` 系では子が記録を書く前に終了するため、親側の
//!   listener か TRAP ハンドラ内の記録が前提になる
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
//!   拒否されること。Landlock ABI 6+（Linux 6.12+）が必須。spec が求める landlock レイヤーの監査記録は、本番の
//!   配送経路が未配線のため `AuditExpectation::Deferred` とし合否に使わない（SEC-4・REPAIR-3）
//! - `control-esc-10-no-landlock`: 同じ操作が Landlock なしでは成功する否定対照（拒否が DAC 等ではなく Landlock
//!   に帰属することの裏付け）
//!
//! ESC-01・ESC-07・ESC-10（Landlock を使うケース）は Landlock ABI 6+（Linux 6.12+）を要する。
//!
//! ケースの攻撃操作は、制限が欠けていてもホストへ副作用が出ない引数・対象に限る（`seccomp.rs` と同方針）。
//! 攻撃クロージャ・ハーネスは `unsafe` を書かない。raw syscall が要る攻撃は core 側の `#[doc(hidden)]`
//! プローブ（syscall 本体は `sys` モジュール）を経由する。

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
/// spec は seccomp 監査記録も要求するが、子が SIGSYS で終了した後に親側で取得できる本番の監査経路がまだ
/// ないため、監査は `Deferred("seccomp")` とし合否に使わない（ESC-03 と同じ扱い。SEC-4・REPAIR-3）。
/// 経路の配線後に `Required("seccomp")` へ切り替える（詳細はモジュール doc の ESC-04〜ESC-06 節）。
const ESC06_EXPECT: Expectation = Expectation {
    allowed: &[],
    signal: Some(SIGSYS),
    audit: AuditExpectation::Deferred("seccomp"),
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

/// 監査ログの期待。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditExpectation {
    /// 監査レコードを要求しない。
    None,
    /// 指定レイヤー（`AuditLayer::as_str()` の値: `seccomp` / `landlock` / `mount`）の記録を 1 件以上要求する。
    /// 記録は本番の配送経路が出力したものに限る（テスト側が生成した記録を証拠にしてはならない）。
    Required(&'static str),
    /// 指定レイヤーの監査を spec 上は要求するが、本番の配送経路が未配線のため合否に使わない（REPAIR-3・SEC-4）。
    /// 配線完了後に `Required` へ置き換える。判定は攻撃結果のみで行う。
    Deferred(&'static str),
}

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

/// 観測結果。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    exit: ObservedExit,
    outcome: Option<AttackOutcome>,
    audit_layers: Vec<String>,
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
    MissingAudit {
        layer: &'static str,
    },
    /// シナリオ側の失敗（ディスパッチャが子プロセスの失敗を報告する）。実プロセス部（Linux）でのみ構築される。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    ScenarioFailed {
        detail: String,
    },
    /// ホスト視点の検査（`EscapeCase::host_check`）の失敗。実プロセス部（Linux）でのみ構築される。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    HostCheckFailed {
        detail: String,
    },
    /// ホスト側の canary が攻撃後に変化した（ホスト FS へ到達・書き込めた = エスケープ。ESC-01）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
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
}

/// 観測が期待に合うかを判定する。監査必須のケースでレコード 0 件なら必ず `Fail`（SEC-2・SEC-4）。
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
    if let AuditExpectation::Required(layer) = expect.audit
        && !obs.audit_layers.iter().any(|l| l == layer)
    {
        mismatches.push(Mismatch::MissingAudit { layer });
    }
    if mismatches.is_empty() {
        CaseVerdict::Pass
    } else {
        CaseVerdict::Fail(mismatches)
    }
}

/// 子が書く記録の累計バイト上限（pipe 容量 64 KiB より十分小さくし、子の書き込みブロックを避ける）。
const RECORD_MAX_BYTES: usize = 16 * 1024;
/// 記録の行数上限（audit 行の無制限な蓄積を防ぐ）。
const RECORD_MAX_LINES: usize = 64;

/// 子から回収した記録の解析結果。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRecord {
    /// outcome 行が無ければ `None`。シグナル終了では outcome 行の前に停止し得るため、欠落の可否は
    /// 終了状態を見る `judge` が決める（`Exited` なら `MissingOutcome`。`Signaled` なら許容）。
    outcome: Option<AttackOutcome>,
    audit_layers: Vec<String>,
}

/// 記録（行指向テキスト）を厳格に解析する。子の出力は untrusted として扱い、欠落・重複・未知キー・
/// 不正値・上限超過を拒否する。形式: `outcome=<ok|errno=N|absent|failed>` を高々 1 行（省略可）、
/// `audit=<encode_json_line の 1 行>` を 0 行以上。
fn parse_record(text: &str) -> Result<ParsedRecord, String> {
    if text.len() > RECORD_MAX_BYTES {
        return Err("record exceeds the size limit".to_string());
    }
    let mut outcome = None;
    let mut audit_layers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i >= RECORD_MAX_LINES {
            return Err("record exceeds the line limit".to_string());
        }
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
            "audit" => {
                let json: serde_json::Value =
                    serde_json::from_str(value).map_err(|e| format!("invalid audit json: {e}"))?;
                let layer = json
                    .get("layer")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "audit line without a string \"layer\"".to_string())?;
                audit_layers.push(layer.to_string());
            }
            other => return Err(format!("unknown key {other:?}")),
        }
    }
    Ok(ParsedRecord {
        outcome,
        audit_layers,
    })
}

/// SEC-2・TASK-42.1: 判定ロジックの自己テスト（具体値で照合。REPAIR-12）。
fn sec2_task42_1_judge_selftest() {
    let allow_ok = Expectation {
        allowed: &[AttackOutcome::Succeeded],
        signal: None,
        audit: AuditExpectation::None,
    };
    let deny = Expectation {
        allowed: &[AttackOutcome::Errno(1), AttackOutcome::Errno(13)],
        signal: None,
        audit: AuditExpectation::Required("landlock"),
    };
    let sig = Expectation {
        allowed: &[],
        signal: Some(31),
        audit: AuditExpectation::None,
    };
    let obs = |exit, outcome, layers: &[&str]| Observation {
        exit,
        outcome,
        audit_layers: layers.iter().map(|s| s.to_string()).collect(),
    };
    let ok_exit = ObservedExit::Exited(0);

    // シグナル終了 + 監査必須: outcome 行なし・audit 行のみの記録でも判定できる。
    let sig_audit = Expectation {
        allowed: &[],
        signal: Some(31),
        audit: AuditExpectation::Required("seccomp"),
    };
    assert_eq!(
        judge(
            &sig_audit,
            &obs(ObservedExit::Signaled(31), None, &["seccomp"])
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&sig_audit, &obs(ObservedExit::Signaled(31), None, &[])),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "seccomp" }])
    );

    assert_eq!(
        judge(
            &allow_ok,
            &obs(ok_exit, Some(AttackOutcome::Succeeded), &[])
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &deny,
            &obs(ok_exit, Some(AttackOutcome::Succeeded), &["landlock"])
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    assert_eq!(
        judge(&deny, &obs(ok_exit, Some(AttackOutcome::Errno(13)), &[])),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &deny,
            &obs(ok_exit, Some(AttackOutcome::Errno(13)), &["seccomp"])
        ),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &deny,
            &obs(ok_exit, Some(AttackOutcome::Errno(13)), &["landlock"])
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&allow_ok, &obs(ok_exit, None, &[])),
        CaseVerdict::Fail(vec![Mismatch::MissingOutcome])
    );
    assert_eq!(
        judge(&sig, &obs(ObservedExit::Exited(0), None, &[])),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedExit {
            got: ObservedExit::Exited(0)
        }])
    );
    assert_eq!(
        judge(&sig, &obs(ObservedExit::Signaled(31), None, &[])),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &sig,
            &obs(
                ObservedExit::Signaled(31),
                Some(AttackOutcome::Succeeded),
                &[]
            )
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
}

/// SEC-2・TASK-42.1: 記録パーサの自己テスト（正常系・欠落・重複・未知キー・不正値・上限超過）。
fn sec2_task42_1_record_parser_selftest() {
    let audit = r#"audit={"event":"audit","layer":"landlock","pid":1}"#;
    let ok = format!("outcome=errno=13\n{audit}\n");
    assert_eq!(
        parse_record(&ok),
        Ok(ParsedRecord {
            outcome: Some(AttackOutcome::Errno(13)),
            audit_layers: vec!["landlock".to_string()],
        })
    );
    assert_eq!(
        parse_record("outcome=ok\n"),
        Ok(ParsedRecord {
            outcome: Some(AttackOutcome::Succeeded),
            audit_layers: vec![],
        })
    );
    assert_eq!(AttackOutcome::Errno(13).render(), "errno=13");
    assert_eq!(
        parse_record(&format!("{audit}\n")),
        Ok(ParsedRecord {
            outcome: None,
            audit_layers: vec!["landlock".to_string()],
        })
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
    assert!(parse_record("outcome=ok\naudit={broken\n").is_err());
    assert_eq!(
        parse_record("outcome=ok\naudit={\"layer\":1}\n"),
        Err("audit line without a string \"layer\"".to_string())
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
    let many = format!(
        "outcome=ok\n{}",
        format!("{audit}\n").repeat(RECORD_MAX_LINES)
    );
    assert_eq!(
        parse_record(&many),
        Err("record exceeds the line limit".to_string())
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
    let obs = |exit, outcome, layers: &[&str]| Observation {
        exit,
        outcome,
        audit_layers: layers.iter().map(|s| s.to_string()).collect(),
    };
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
    // 現行実装（EPERM で戻り、SIGSYS で終了しない）は失敗として検出される。
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
/// `landlock` 層の監査は配送経路未配線のため `Deferred`（SEC-4・REPAIR-3）。
const ESC01_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(13)],
    signal: None,
    audit: AuditExpectation::Deferred("landlock"),
};

/// ESC-02: ホストの PID namespace が参照できない（`/proc/1` はコンテナ内の自分自身）。監査記録は要求しない。
const ESC02_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Absent],
    signal: None,
    audit: AuditExpectation::None,
};

/// ESC-03: 既定 capability セット下の `mount(2)` は EPERM（1）で拒否される。拒否主体は組み込み seccomp の
/// `ERRNO(EPERM)`（と capability 削減）で `AuditLayer::Mount` ではないため、`seccomp` 層の監査を
/// 配送経路未配線のため `Deferred` とする（SEC-4・REPAIR-3）。
const ESC03_EXPECTATION: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(1)],
    signal: None,
    audit: AuditExpectation::Deferred("seccomp"),
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

    let obs = |outcome, layers: &[&str]| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit_layers: layers.iter().map(|s| s.to_string()).collect(),
    };
    // Deferred: 監査記録の有無は合否に影響しない（テスト側生成の記録を証拠にしない。SEC-4）。
    assert_eq!(
        judge(&ESC03_EXPECTATION, &obs(AttackOutcome::Errno(1), &[])),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &ESC03_EXPECTATION,
            &obs(AttackOutcome::Errno(1), &["mount"])
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &ESC03_EXPECTATION,
            &obs(AttackOutcome::Succeeded, &["mount"])
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
    assert_eq!(
        judge(&ESC01_EXPECTATION, &obs(AttackOutcome::Errno(13), &[])),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &ESC01_EXPECTATION,
            &obs(AttackOutcome::Errno(1), &["landlock"])
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Errno(1)
        }])
    );
    assert_eq!(
        judge(&ESC02_EXPECTATION, &obs(AttackOutcome::Absent, &[])),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC02_EXPECTATION, &obs(AttackOutcome::Succeeded, &[])),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Succeeded
        }])
    );
}

/// Linux asm-generic の errno 値（x86_64・aarch64 共通。syscall 番号ではないため arch 分岐は不要）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const ENOENT: i32 = 2;
const ETXTBSY: i32 = 26;

/// ESC-07（SEC-2・TASK-42.4・#202）: ランタイムバイナリへの書き込み open の期待値。
/// 書き込みの拒否は Landlock（EACCES）のほか、実行中バイナリへの書き込み拒否（ETXTBSY）や DAC（EACCES・EPERM）
/// でも起こり得るため、いずれも許可する。成功（`Succeeded`）だけが失敗。spec は監査を要求しない。
#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
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

/// ESC-07 の Landlock 帰属確認（読み取り open。ETXTBSY に覆われない）。EACCES と landlock 層の記録が必須。
#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
const ESC07_LANDLOCK_EXPECT: Expectation = Expectation {
    allowed: &[AttackOutcome::Errno(EACCES)],
    signal: None,
    audit: AuditExpectation::Required("landlock"),
};

/// ESC-08: マウント先ホワイトリスト外の要求は拒否（`Failed`）され、mount 層の監査記録が必須。
#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
const ESC08_EXPECT: Expectation = Expectation {
    allowed: &[AttackOutcome::Failed],
    signal: None,
    audit: AuditExpectation::Required("mount"),
};

/// ESC-07・ESC-08 の期待値の機械照合（REPAIR-12・SEC-2・TASK-42.4）。非 Linux でも定数を使う。
fn sec2_task42_4_expectation_selftest() {
    let obs = |outcome: AttackOutcome, layers: &[&str]| Observation {
        exit: ObservedExit::Exited(0),
        outcome: Some(outcome),
        audit_layers: layers.iter().map(|l| (*l).to_string()).collect(),
    };
    assert_eq!(
        judge(&ESC07_WRITE_EXPECT, &obs(AttackOutcome::Succeeded, &[])),
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
        assert_eq!(judge(&ESC07_WRITE_EXPECT, &obs(o, &[])), CaseVerdict::Pass);
    }
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &obs(AttackOutcome::Errno(EACCES), &["landlock"])
        ),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &obs(AttackOutcome::Errno(EACCES), &[])
        ),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "landlock" }])
    );
    assert_eq!(
        judge(
            &ESC07_LANDLOCK_EXPECT,
            &obs(AttackOutcome::Errno(ETXTBSY), &["landlock"])
        ),
        CaseVerdict::Fail(vec![Mismatch::UnexpectedOutcome {
            got: AttackOutcome::Errno(ETXTBSY)
        }])
    );
    assert_eq!(
        judge(&ESC08_EXPECT, &obs(AttackOutcome::Failed, &["mount"])),
        CaseVerdict::Pass
    );
    assert_eq!(
        judge(&ESC08_EXPECT, &obs(AttackOutcome::Failed, &[])),
        CaseVerdict::Fail(vec![Mismatch::MissingAudit { layer: "mount" }])
    );
    assert_eq!(
        judge(&ESC08_EXPECT, &obs(AttackOutcome::Succeeded, &["mount"])),
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
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    always();
    println!(
        "escape_suite: real-process part is x86_64/aarch64 only, not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
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
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::io::{PipeWriter, Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AuditDelivery, AuditRecord, AuditSink, encode_json_line, landlock_denial_record_now,
    };
    use fandhe_container_core::dev_mounts::ImplicitDevMounts;
    use fandhe_container_core::exec::{
        ChildExit, EscapeSyscallProbe, IsolationConfig, Namespace, NamespaceSet, ProbeOutcome,
        StagePipeline, escape_probe_mount, isolate, isolate_rootful_host_root, plan,
        plan_rootful_host_root, probe_escape_syscall, spawn_container_probe,
    };
    use fandhe_container_core::landlock::{build_path_rules_with_dev, detect_landlock_abi};
    use fandhe_container_core::oci_runtime::{audit_mount_config_error, parse_config_bytes};
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    use super::{
        AttackOutcome, AuditExpectation, CaseVerdict, ENOENT, ESC01_EXPECTATION, ESC02_EXPECTATION,
        ESC03_EXPECTATION, ESC04_EXPECT, ESC05_EXPECT, ESC06_EXPECT, ESC07_LANDLOCK_EXPECT,
        ESC07_WRITE_EXPECT, ESC08_EXPECT, ESC09_LAUNCHER, Expectation, LauncherRequirement,
        Mismatch, NotApplicable, Observation, ObservedExit, RECORD_MAX_BYTES, classify_pid_view,
        judge, launcher_applicability, parse_record,
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

    /// ホスト視点の検査関数の型。
    type HostCheck = fn(&HostView) -> Result<(), String>;

    /// ホスト視点の検査入力（ESC-09。SEC-5）。
    struct HostView<'a> {
        rootfs: &'a Path,
        euid: u32,
        egid: u32,
        is_root: bool,
    }

    /// 登録済みケース。対照ケースと ESC-01〜03（#200）・ESC-04〜06（#201）・ESC-07〜08（#202）・ESC-09〜10（#203）。
    const CASES: &[EscapeCase] = &[
        EscapeCase {
            id: "control-read-proc",
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
            expectation: Expectation {
                allowed: &[AttackOutcome::Errno(13)],
                signal: None,
                // 配送経路未配線のため Deferred（テスト側生成の記録を合格証拠にしない。SEC-4・REPAIR-3）。
                audit: AuditExpectation::Deferred("landlock"),
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
            expectation: ESC01_EXPECTATION,
            stages: esc01_stages,
            attack: attack_esc01_host_fs_write,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-02-host-pid-ns",
            expectation: ESC02_EXPECTATION,
            stages: StagePipeline::new,
            attack: attack_esc02_host_pid_ns,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-03-cap-sys-admin-mount",
            expectation: ESC03_EXPECTATION,
            stages: StagePipeline::new,
            attack: attack_esc03_cap_sys_admin_mount,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-04-release-agent",
            expectation: ESC04_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc04_release_agent,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-05-proc-sys-core-pattern",
            expectation: ESC05_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc05_proc_sys_core_pattern,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-05-sysrq-trigger",
            expectation: ESC05_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc05_sysrq_trigger,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-unshare",
            expectation: ESC06_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc06_unshare,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-ptrace",
            expectation: ESC06_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc06_ptrace,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-06-kexec-load",
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
            expectation: ESC07_WRITE_EXPECT,
            stages: landlock_rootfs_only_stages,
            attack: attack_esc07_runtime_binary_write,
            precondition: no_precondition,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-07-runtime-binary-landlock",
            expectation: ESC07_LANDLOCK_EXPECT,
            stages: landlock_rootfs_only_stages,
            attack: attack_esc07_runtime_binary_landlock,
            precondition: precondition_esc07_exe_readable,
            host_check: None,
            launcher: LauncherRequirement::Any,
        },
        EscapeCase {
            id: "esc-08-mount-outside-whitelist",
            expectation: ESC08_EXPECT,
            stages: StagePipeline::new,
            attack: attack_esc08_mount_outside_whitelist,
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
        // rootfs に dev が無い最小フロー（`spawn_container` は `create_default_devices` を呼ばない。#1314 未配線）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない。#1314 で配線したら `ImplicitDevMounts::All` に戻す（#1657）。
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
    /// 監査記録は作らない（攻撃側生成の記録は SEC-4 の証拠にならない。期待は `Deferred`）。
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
    /// 監査（SEC-4・REPAIR-3）: 実際の拒否主体は組み込み seccomp の `ERRNO(EPERM)`（と capability 削減）で、
    /// seccomp ERRNO にはユーザー空間への報告経路がまだない。攻撃側で記録を作ると監査の証拠にならないため
    /// 記録せず、期待は `Deferred`。配送経路の配線後に本番経路の出力照合（`Required`）へ置き換える。
    /// `SeccompDenialReport` は偽造しない。
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
        // rootfs に dev が無い最小フロー（`spawn_container` は `create_default_devices` を呼ばない。#1314 未配線）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない。#1314 で配線したら `ImplicitDevMounts::All` に戻す（#1657）。
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
        // rootfs に dev が無い最小フロー（`spawn_container` は `create_default_devices` を呼ばない。#1314 未配線）
        // では暗黙の `/dev` 系のルールを足せない（存在しないパスは適用時に拒否される）ため含めない。ルールは
        // 従来と同じで弱体化ではない。#1314 で配線したら `ImplicitDevMounts::All` に戻す（#1657）。
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
    /// 期待は `Deferred`。本番の監査配送経路の配線後（REPAIR-3）に実出力を回収して `Required` へ切り替える。
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

    /// EACCES なら Landlock 拒否の監査レコードを記録する（SEC-4 の記録経路との整合）。
    fn record_landlock_denial(rec: &Recorder, outcome: AttackOutcome, path: &str) {
        if let AttackOutcome::Errno(n) = outcome {
            match landlock_denial_record_now(Path::new(path), Some(n)) {
                Ok(Some(r)) => rec.record(&r).expect("record landlock denial"),
                Ok(None) => {}
                Err(e) => panic!("build landlock audit record: {e:?}"),
            }
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
        record_landlock_denial(rec, outcome, "/proc/self/exe");
        rec.outcome(outcome);
    }

    /// ESC-07 の補助（SEC-2・TASK-42.4・#202）: ETXTBSY に覆われない読み取り open で、Landlock が
    /// ホスト側バイナリ（rootfs の許可ツリー外）の経路を塞いでいることを独立に示す。読み込みはしない。
    fn attack_esc07_runtime_binary_landlock(rec: &Recorder, _host_canary: &Path) {
        let outcome = match std::fs::File::open("/proc/self/exe") {
            Ok(_) => AttackOutcome::Succeeded,
            Err(e) => outcome_of_error(&e),
        };
        record_landlock_denial(rec, outcome, "/proc/self/exe");
        rec.outcome(outcome);
    }

    /// ESC-08（SEC-2・SEC-4・TASK-42.4・#202）: マウント先ホワイトリスト外の要求（rootfs 外への遡り・rootfs
    /// 全体・相対 `..`。source はホストの機密パスを例示）を API 層（config パース）で検証し、拒否と Mount
    /// 監査記録を確認する。実マウントは行わない（純粋関数のみ）。
    /// 注意（実装済みを装わない）: マウント元（source）側のホワイトリストは未実装で、start は空でない mounts
    /// を一律 `Unimplemented` で拒否するが監査されない。コンテナ内から生の `mount(2)` を試すケースは
    /// raw syscall プローブが必要なため範囲外。本ケースは監査経路が実装済みの destination 側を検証する。
    fn attack_esc08_mount_outside_whitelist(rec: &Recorder, _host_canary: &Path) {
        for dest in ["/../../run/fandhe-container", "/", "run/../../../etc"] {
            let before = rec.audit_count();
            let json = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},"mounts":[{{"destination":"{dest}","type":"bind","source":"/run/fandhe-container","options":["bind"]}}]}}"#
            );
            match parse_config_bytes(json.as_bytes()) {
                Ok(_) => {
                    rec.outcome(AttackOutcome::Succeeded);
                    return;
                }
                Err(err) => {
                    assert_eq!(
                        err.code(),
                        ErrorCode::InvalidArgument,
                        "mount rejection must be InvalidArgument"
                    );
                    let audited = audit_mount_config_error(err, rec);
                    assert_eq!(
                        audited.delivery,
                        AuditDelivery::Recorded,
                        "mount rejection must be audited"
                    );
                    assert_eq!(
                        rec.audit_count(),
                        before + 1,
                        "each rejected mount request ({dest}) must add exactly one audit record"
                    );
                }
            }
        }
        rec.outcome(AttackOutcome::Failed);
    }

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
    /// 拒否だけを期待する。拒否の本番実装（`linux.readonlyPaths` / `maskedPaths` 適用）は未実装（REPAIR-3）のため、
    /// 現行の実機実行では書き込み用に開けて失敗する（ESC-05 と同様に本物の欠陥として検出。期待は変えない）。
    /// v1 階層の新規 mount の拒否は seccomp の `mount` 拒否（`tests/seccomp.rs`）、ホスト側の根拠は
    /// `tests/cgroups_release_agent.rs`（TASK-35）にある。
    fn attack_esc04_release_agent(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(open_write_only("/sys/fs/cgroup/release_agent"));
    }

    /// ESC-05（SEC-2・TASK-42.3・#201・MS-2）: マスク対象 `/proc/sys` 配下（`core_pattern`）への書き込み。
    /// `maskedPaths` 未適用のため rootful では開けてしまい得る（本物の欠陥の検出。期待は変えない）。
    fn attack_esc05_proc_sys_core_pattern(rec: &Recorder, _host_canary: &Path) {
        rec.outcome(open_write_only("/proc/sys/kernel/core_pattern"));
    }

    /// ESC-05（SEC-2・TASK-42.3・#201・MS-2）: `/proc/sysrq-trigger` への書き込み。開くだけで書かない。
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
    /// 戻ってきた場合（現行は EPERM）は結果を記録し、判定側が失敗にする。seccomp 監査は親側の本番経路が
    /// 未配線のため `Deferred`（SEC-4・REPAIR-3）で、攻撃側で監査レコードを作らない（偽造しない）。
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

    /// 子側の記録器。攻撃結果を 1 回だけ、監査レコードを 0 件以上、pipe へ書く。`AuditSink` として
    /// 既存の記録ヘルパへ渡せる。累計量は `RECORD_MAX_BYTES` で打ち切る。
    pub struct Recorder {
        inner: Mutex<RecorderState>,
    }

    struct RecorderState {
        writer: PipeWriter,
        written: usize,
        outcome_written: bool,
        audits: usize,
    }

    impl Recorder {
        fn new(writer: PipeWriter) -> Self {
            Recorder {
                inner: Mutex::new(RecorderState {
                    writer,
                    written: 0,
                    outcome_written: false,
                    audits: 0,
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

        /// これまでに記録した監査レコードの件数（要求ごとの記録確認用）。
        fn audit_count(&self) -> usize {
            self.inner.lock().expect("recorder lock").audits
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

    impl AuditSink for Recorder {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            let bytes = encode_json_line(record)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to encode record"))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "record is not UTF-8"))?;
            self.write_line(&format!("audit={}", text.trim_end_matches('\n')))?;
            self.inner.lock().expect("recorder lock").audits += 1;
            Ok(())
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
                scenario(id, Path::new(rootfs));
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
        let dir = target.parent().expect("release_agent has a parent dir");
        std::fs::create_dir_all(dir).expect("create rootfs/sys/fs/cgroup");
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

    /// 共通関数（ディスパッチャ側）: 1 ケースを「起動 → 攻撃 → 判定 → 後始末」で実行する。
    ///
    /// rootfs の作成・自身のシナリオ再起動・期限付き待機・出力回収を行い、rootfs は drop で削除する。
    /// 判定そのものはシナリオ内（`scenario`）で `judge` により行い、終了コード 0 を `Pass` とする。
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

    /// `run_case` の本体: 起動前提の成立済みのケースを起動・判定・後始末する。
    fn run_scenario(case: &EscapeCase) -> CaseVerdict {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
        // シナリオの異常終了・panic でも canary ディレクトリが残らないよう、ディスパッチャ側でも
        // 全終了経路（drop）で削除する（未作成なら no-op）。
        let _canary_cleanup = Rootfs(canary_dir_for(&rootfs.0));
        let mut child = Command::new(&exe)
            .args(["--scenario", case.id])
            .arg(&rootfs.0)
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
        match status {
            Some(st) if st.code() == Some(0) => match case.host_check {
                None => CaseVerdict::Pass,
                Some(check) => {
                    let (euid, egid) = effective_ids();
                    let view = HostView {
                        rootfs: &rootfs.0,
                        euid,
                        egid,
                        is_root: euid == 0,
                    };
                    match check(&view) {
                        Ok(()) => CaseVerdict::Pass,
                        Err(detail) => {
                            CaseVerdict::Fail(vec![Mismatch::HostCheckFailed { detail }])
                        }
                    }
                }
            },
            Some(st) => CaseVerdict::Fail(vec![Mismatch::ScenarioFailed {
                detail: format!("scenario exited with {st}; stderr:\n{stderr}"),
            }]),
            None => CaseVerdict::Fail(vec![Mismatch::ScenarioFailed {
                detail: format!("scenario did not exit within {limit:?}; stderr:\n{stderr}"),
            }]),
        }
    }

    fn dispatcher() {
        let mut failed = 0usize;
        let mut verified = 0usize;
        let mut not_applicable = Vec::new();
        for case in CASES {
            match run_case(case) {
                CaseRun::Ran(CaseVerdict::Pass) => verified += 1,
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
        println!(
            "escape_suite: SEC-2 harness verified {verified} of {} case(s), not applicable {:?} (root={})",
            CASES.len(),
            not_applicable,
            is_root()
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

    /// シナリオ: 分離 → 子で攻撃 → 記録回収 → 判定。結果は 1 行出力し、不合格は終了コード 1 にする。
    fn scenario(case_id: &str, rootfs: &Path) {
        let case = CASES
            .iter()
            .find(|c| c.id == case_id)
            .unwrap_or_else(|| panic!("unknown escape case {case_id:?}"));
        let is_root = is_root();
        // 継承した seccomp フィルタがあると拒否を組み込み段へ帰属できないため、事前条件として失敗扱いにする。
        assert_eq!(
            seccomp_mode_of_self(),
            "0",
            "precondition: the test process must not inherit a seccomp filter (cannot attribute the denial to the built-in stage)"
        );
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
        let child = spawn_container_probe(rootfs, (case.stages)(), move || {
            let recorder = Recorder::new(writer);
            attack(&recorder, &attack_canary);
        })
        .unwrap_or_else(|e| panic!("spawn: {e}"));
        // パイプ容量を超える記録でも子が write で詰まらないよう、子の待機と並行して別スレッドで読む（REPAIR-5）。
        // fork は単一スレッド必須（`fork_single_threaded` が Threads: 1 を要求）のため、読み取りスレッドは fork の後に起動する。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let res = reader
                .take(RECORD_MAX_BYTES as u64 + 1)
                .read_to_string(&mut text)
                .map(|_| text);
            let _ = tx.send(res);
        });
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        let exit = match exit {
            ChildExit::Exited(c) => ObservedExit::Exited(c),
            ChildExit::Signaled(s) => ObservedExit::Signaled(s),
            other => panic!("unexpected child exit {other:?}"),
        };

        // 上限 + 1 バイトで打ち切り（超過は記録として不正）。子孫が writer を保持し続けても EOF 待ちで
        // 無期限にブロックしないよう、回収には期限を設けて超過なら失敗にする。
        let text = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("record read did not finish in time: {e}"))
            .expect("read record");
        let observation = match parse_record(&text) {
            // outcome 欠落は `judge` が終了状態と突き合わせて判定する（シグナル終了では audit 行のみが残り得る）。
            Ok(rec) => Observation {
                exit,
                outcome: rec.outcome,
                audit_layers: rec.audit_layers,
            },
            Err(e) => panic!("invalid record from the container: {e}"),
        };
        let mut verdict = judge(&case.expectation, &observation);
        // ホスト側 canary の無変更を、コンテナ外から観測する（到達・書き込みの副作用の有無）。
        if let Some(detail) = canary_violation(&canary_dir.0, &canary) {
            let mismatch = Mismatch::HostTargetModified { detail };
            verdict = match verdict {
                CaseVerdict::Pass => CaseVerdict::Fail(vec![mismatch]),
                CaseVerdict::Fail(mut m) => {
                    m.push(mismatch);
                    CaseVerdict::Fail(m)
                }
            };
        }
        match verdict {
            CaseVerdict::Pass => {
                println!("escape_suite: {} verdict=pass exit={}", case.id, exit);
            }
            CaseVerdict::Fail(ref m) => {
                println!("escape_suite: {} verdict=fail {m:?}", case.id);
                drop(canary_dir);
                std::process::exit(1);
            }
        }
    }
}
