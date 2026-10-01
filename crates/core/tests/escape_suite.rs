//! 攻撃テストハーネス基盤（SEC-2・TASK-42.1・#199。親は TASK-42・#198）。
//!
//! PoC-9（`03-poc/security-isolation`）で定めた最小攻撃セット ESC-01〜ESC-10 を CI 自動テストスイート
//! として実装する TASK-42 の土台。各 ESC ケースは `linux::CASES` へ `EscapeCase` を 1 行追加するだけで
//! 実装できる（ESC-01〜03 は #200、04〜06 は #201、07〜08 は #202、09〜10 は #203 で追加する）。
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
//!   監査ログの本番配線（`AuditSink` を fork 後の子へ渡す経路）は未実装（REPAIR-3）のため、現状は攻撃
//!   クロージャが既存の記録ヘルパ（`landlock_denial_record_now`・`record_seccomp_denial` 等）経由で
//!   `Recorder`（`AuditSink`）へ記録したレコードを pipe で回収して判定する。配線完了後は本番経路の
//!   出力を照合する形へ置き換える
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
//! 事前条件の不成立を含めあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。AGENTS.md への
//! 記載と CI での分離方式の確定は #204（TASK-42.6）で行う。
//!
//! ケースの攻撃操作は、制限が欠けていてもホストへ副作用が出ない引数・対象に限る（`seccomp.rs` と同方針）。
//! 攻撃クロージャ・ハーネスは `unsafe` を書かない。raw syscall が要る攻撃は core 側の `#[doc(hidden)]`
//! プローブ（syscall 本体は `sys` モジュール）を経由する。

use std::fmt;

/// 攻撃操作の結果（子が観測した事実）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackOutcome {
    /// 操作が成功した（許可された）。
    Succeeded,
    /// errno 付きで失敗した。
    Errno(i32),
    /// 操作の対象が存在しない（ESC-04・05 向け）。
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
    Required(&'static str),
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
    outcome: AttackOutcome,
    audit_layers: Vec<String>,
}

/// 記録（行指向テキスト）を厳格に解析する。子の出力は untrusted として扱い、欠落・重複・未知キー・
/// 不正値・上限超過を拒否する。形式: `outcome=<ok|errno=N|absent|failed>` を 1 行、
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
    let outcome = outcome.ok_or_else(|| "missing key \"outcome\"".to_string())?;
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
            outcome: AttackOutcome::Errno(13),
            audit_layers: vec!["landlock".to_string()],
        })
    );
    assert_eq!(
        parse_record("outcome=ok\n"),
        Ok(ParsedRecord {
            outcome: AttackOutcome::Succeeded,
            audit_layers: vec![],
        })
    );
    assert_eq!(AttackOutcome::Errno(13).render(), "errno=13");
    assert_eq!(
        parse_record(&format!("{audit}\n")),
        Err("missing key \"outcome\"".to_string())
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

fn always() {
    sec2_task42_1_judge_selftest();
    sec2_task42_1_record_parser_selftest();
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

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink, encode_json_line};
    use fandhe_container_core::exec::{
        ChildExit, IsolationConfig, Namespace, NamespaceSet, StagePipeline, isolate,
        isolate_rootful_host_root, plan, plan_rootful_host_root, spawn_container_probe,
    };
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    use super::{
        AttackOutcome, AuditExpectation, CaseVerdict, Expectation, Mismatch, Observation,
        ObservedExit, RECORD_MAX_BYTES, judge, parse_record,
    };

    /// 子（コンテナ内）で攻撃を実行するクロージャの型。結果は `Recorder` へ書く。
    type Attack = fn(&Recorder);

    /// 1 件の攻撃ケース。ESC-01〜10 は `CASES` へ追加する（#200〜#203）。
    struct EscapeCase {
        /// `--scenario` に渡す識別子（例: `esc-01-mount`）。
        id: &'static str,
        expectation: Expectation,
        /// 子の制限ステージ列（Landlock を伴うケースは `with_landlock` を載せて返す）。
        stages: fn() -> StagePipeline,
        attack: Attack,
    }

    /// 登録済みケース。本 PR は、ハーネスが end-to-end で動くことを示す対照ケースのみ。
    const CASES: &[EscapeCase] = &[EscapeCase {
        id: "control-read-proc",
        expectation: Expectation {
            allowed: &[AttackOutcome::Succeeded],
            signal: None,
            audit: AuditExpectation::None,
        },
        stages: StagePipeline::new,
        attack: attack_control_read_proc,
    }];

    /// 対照: 禁止対象外の操作（`/proc/self/status` の読み出し）が制限下でも動くこと。
    fn attack_control_read_proc(rec: &Recorder) {
        let outcome = match std::fs::read_to_string("/proc/self/status") {
            Ok(s) if s.contains("Seccomp:") => AttackOutcome::Succeeded,
            Ok(_) => AttackOutcome::Failed,
            Err(e) => e
                .raw_os_error()
                .map_or(AttackOutcome::Failed, AttackOutcome::Errno),
        };
        rec.outcome(outcome);
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

    impl AuditSink for Recorder {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            let bytes = encode_json_line(record)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to encode record"))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "record is not UTF-8"))?;
            self.write_line(&format!("audit={}", text.trim_end_matches('\n')))
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

    /// `proc/` だけを持つ rootfs を排他的に作る（推測されにくい名前・`mkdir` は既存なら失敗）。
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

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
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
    fn run_case(case: &EscapeCase) -> CaseVerdict {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
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
            Some(st) if st.code() == Some(0) => CaseVerdict::Pass,
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
        for case in CASES {
            let verdict = run_case(case);
            if verdict != CaseVerdict::Pass {
                failed += 1;
                eprintln!("escape_suite: {} verdict=fail {verdict:?}", case.id);
            }
        }
        assert_eq!(failed, 0, "{failed} escape case(s) failed");
        println!(
            "escape_suite: SEC-2 harness verified {} case(s) (root={})",
            CASES.len(),
            is_root()
        );
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

        let (reader, writer) = std::io::pipe().expect("create record pipe");
        let attack = case.attack;
        // 親側の writer 端は fork 時に閉じられる（クロージャは子にだけ残る）ため、子の終了で EOF になる。
        let child = spawn_container_probe(rootfs, (case.stages)(), move || {
            let recorder = Recorder::new(writer);
            attack(&recorder);
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
            Ok(rec) => Observation {
                exit,
                outcome: Some(rec.outcome),
                audit_layers: rec.audit_layers,
            },
            // 記録なし（シグナル終了等）は outcome 無しの観測にする。不正な記録は失敗。
            Err(_) if text.is_empty() => Observation {
                exit,
                outcome: None,
                audit_layers: Vec::new(),
            },
            Err(e) => panic!("invalid record from the container: {e}"),
        };
        let verdict = judge(&case.expectation, &observation);
        match verdict {
            CaseVerdict::Pass => {
                println!("escape_suite: {} verdict=pass exit={}", case.id, exit);
            }
            CaseVerdict::Fail(ref m) => {
                println!("escape_suite: {} verdict=fail {m:?}", case.id);
                std::process::exit(1);
            }
        }
    }
}
