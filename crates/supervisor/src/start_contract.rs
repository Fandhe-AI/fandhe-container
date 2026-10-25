//! CLI と supervisor の起動の契約（argv の解析・結果の 1 行報告・期限）
//! （TASK-157 追補・#1717・SUP-1・MS-9。関連: CORE-1・D-19・REPAIR-2・REPAIR-3・REPAIR-5・CLI-1）。
//!
//! 呼び出し元は 2 者ある。supervisor の bin 入口（[`crate::start_entry`]）は [`StartArgs::parse`] で argv を検証し、
//! 結果を [`StartReport::encode`] で結果チャネル（stdout の pipe）へ 1 行書く。CLI 側（#1718）は
//! 同じ pipe から読んだバイト列を [`StartReport::decode`] で復号する。文字列を手で組み立てない・手で割らないために
//! 符号化と復号を同じ型に置く（REPAIR-2）。OS 非依存の純ロジックで、`unsafe` を含まない。
//!
//! # 起動のしかた（呼び出し側の責務。#1718・#1719）
//! - 実行ファイルは固定のインストール先から解決する（`PATH` 探索をしない）。
//! - argv: `fandhe-container-supervisor start --root <状態ルートの絶対パス> [--restart <policy>] [--audit-policy <best-effort|strict>] <container-id>`。
//!   `--root` は必須（CLI が `StateRoot::resolve` で解決した値を渡す。supervisor は状態ルートを環境変数から決めない）。
//!   `--restart` は任意で既定は `no`。`--audit-policy` は任意で既定は `best-effort`（カーネル監査頼みの層が縮退した
//!   環境の扱い。`strict` は縮退を起動前に拒否する。SEC-4・#2027。CLI からの受け渡しは未実装）。`--cri-log-path` は任意で、CRI の `log_directory/log_path` を結合・検証した絶対パス
//!   （POSIX 形式。`ContainerLogPath` が再検証する）。指定があれば `@container-logs` に加えて CRI ログ形式で追記する
//!   （CRI-2・SUP-4・#2671。plugin-cri の StartContainer が渡す。CLI は渡さない）。各オプションは 1 回まで・順不同で、`<container-id>` は末尾の位置引数 1 個。
//! - 契約の fd は 0〜2 のみ。supervisor は入口（`start_entry`）で fd [`FIRST_INHERITED_FD`] 以降を閉じる
//!   （特権ランチャーと同じ処理。#2070・SEC-1）。呼び出し側が追加の fd を渡しても使われない。exec から入口までの
//!   短い窓は残る（CLI は CLOEXEC の無い fd を自分では閉じない）。
//! - 環境変数は契約に含めない（supervisor は契約の値を環境から読まない）。CLI が渡す環境は `PATH`（固定値）と
//!   `XDG_RUNTIME_DIR`（systemd-run が user マネージャへ接続するため。supervisor は読まない）だけである。
//! - 委譲スコープ（#2081・CORE-3・CORE-4）: `DelegatedCgroup::prepare` は親 cgroup に自分以外のプロセスがいると拒否するため、
//!   CLI は supervisor を [`USER_SCOPE_WRAPPER_ARGS`] で包んで起動する（`systemd-run <引数> <supervisor の絶対パス> start ...`）。
//!   systemd-run は scope の登録後に同じプロセスでコマンドを exec する（`man systemd-run` の scope の説明と systemd の
//!   `src/run/run.c` の `start_transient_scope`）ため、spawn した pid・プロセスグループ・stdio はそのまま supervisor のものになる。
//! - stdin は `/dev/null`、**stdout は結果を通知する pipe の書き込み端**（supervisor は報告を 1 行書いたら以後 stdout に
//!   何も書かない）、stderr は呼び出し側が選ぶ。supervisor の構造化ログは supervisor 自身が
//!   `<root>/@supervisor-logs/` へ保存する（[`crate::supervisor_log`]。#2067）ので、呼び出し側の stderr へ行くのは fd 2 へ
//!   直接書かれるもの（core の診断・panic 等。同モジュールの「未実装・残余」）だけで、null でもログは失われない。
//! - supervisor は CLI より長く生きる（CORE-1・D-19）。端末の SIGINT / SIGHUP を受けないよう、CLI は
//!   `CommandExt::process_group(0)` で別のプロセスグループにして spawn する。ただし特権ランチャー経由の起動（#2442）では
//!   付けない: ランチャーの入口の `setsid` はプロセスグループのリーダーだと `EPERM` になり拒否される（#537）。stdio に pty も渡さない。
//!
//! # 結果の報告（1 行・固定書式）
//! ASCII、`\n` で終わる 1 行、最大 [`MAX_REPORT_LEN`] バイト。
//! - 成功: `FCSUP1 OK <pid>\n`（pid は 10 進・先頭 0 なし・1 以上）
//! - 失敗: `FCSUP1 ERR <CODE> <exit_code> <message>\n`（`CODE` は `ErrorCode::as_str`、`message` は印字可能 ASCII で最大
//!   [`MAX_REPORT_MESSAGE_LEN`] バイト）
//!
//! # 期限（REPAIR-5）
//! supervisor が結果を書くまでの内部上限は [`result_deadline`]、CLI の受信期限は [`cli_receive_deadline`]。
//! CLI が期限内に 1 行を受け取れなければ `TIMEOUT`（結果不明。supervisor は遅れて成功しても監視を続けるので、
//! 利用者は `state` で確かめる）。行が無いまま EOF なら `INTERNAL`（supervisor が報告の前に落ちた）。
//!
//! # 報告の後の後始末
//! supervisor は報告を期限内に 1 回書いてから、失敗の後始末（予約を Created へ戻す・cgroup の削除・terminate・
//! `Stopped` の記録）を行う。起動の準備（手順 3〜7）が期限に間に合わなかったときは `INTERNAL`（期限超過の
//! message）を報告し、準備が後から終わっても launch せず作った cgroup を消す（launch は準備の完了後に入口スレッドが
//! 行うため、期限超過の後に新しいプロセスは作られない。#1819）。
//! **ERR（`INTERNAL` を含む）の報告の後、後始末が終わるまで同じ ID は予約中**で、その間の同じ ID の start は
//! 記録済みの cgroup スコープ・起動権の予約（revision 照合）・bundle の所有ロックの照合で `FAILED_PRECONDITION`
//! として拒否される。後始末を確かめられなければ supervisor は `INTERNAL` の終了コードで終わる。

use std::ffi::OsString;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::PathBuf;
use std::time::Duration;

use fandhe_container_core::audit_log::RECORD_WAIT_LIMIT;
use fandhe_container_core::oci_runtime::{
    LAUNCHER_REPLY_GRACE, OciRuntimeError, StartTimeouts, exit_code_for,
};
use fandhe_container_core::traits::{ContainerId, ContainerLogPath, ErrorCode, TraitError};

use crate::restart::RestartPolicy;
use fandhe_container_core::audit_log::AuditCoveragePolicy;

/// supervisor の入口とランチャーが閉じ始める fd 番号（0〜2 は契約の stdin / stdout / stderr。SEC-1・#2070）。
pub const FIRST_INHERITED_FD: u32 = 3;
/// supervisor を委譲された新しい cgroup scope で起動するための `systemd-run` の引数（#2081・CORE-3・CORE-4）。
///
/// CLI の `start` と実機試験（`supervisor_bin_real`）の唯一の出所。後ろに supervisor の絶対パスと契約の argv が続く。
/// `--unit` は付けない（名前を決め打ちすると残った scope と衝突して start が落ちうるため）。
pub const USER_SCOPE_WRAPPER_ARGS: [&str; 6] =
    ["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"];
/// 報告の先頭トークン（契約の版。互換性のない変更では数字を上げる）。
///
/// `ErrorCode` への語彙の追加（`RESOURCE_EXHAUSTED`・#2609）では上げない。未知の文字列は `parse_error_code` が
/// `None` にして fail-closed で失敗し、CLI と supervisor は同じ版を一組で配置する前提のため。
pub const REPORT_MAGIC: &str = "FCSUP1";
/// 報告 1 行（終端の `\n` を含む）の最大バイト数。
pub const MAX_REPORT_LEN: usize = 640;
/// 報告に載せる `message` の最大バイト数。
pub const MAX_REPORT_MESSAGE_LEN: usize = 512;
/// argv の最大要素数（プログラム名を除く）。
pub const MAX_ARGS: usize = 10;
/// argv の 1 要素の最大バイト数。
pub const MAX_ARG_LEN: usize = 4096;
/// cgroup の準備（mkdir・退避・制限の設定）に見込む時間。
pub const CGROUP_PREPARE_ALLOWANCE: Duration = Duration::from_secs(6);
/// CLI が [`result_deadline`] に足す受信の猶予。
pub const CLI_RECEIVE_GRACE: Duration = Duration::from_secs(2);

/// 報告の `message`。印字可能な ASCII（0x20..=0x7E）だけを持ち、最大 [`MAX_REPORT_MESSAGE_LEN`] バイト。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportMessage(String);

impl ReportMessage {
    /// 非 ASCII・制御文字を `?` に置き換え、[`MAX_REPORT_MESSAGE_LEN`] バイトで切って作る。空は `unspecified` にする
    /// （復号側が空の `message` を不正として拒否するため）。
    pub fn new(raw: &str) -> Self {
        let mut out = String::with_capacity(raw.len().min(MAX_REPORT_MESSAGE_LEN));
        for c in raw.chars().take(MAX_REPORT_MESSAGE_LEN) {
            out.push(if matches!(c, ' '..='~') { c } else { '?' });
        }
        if out.is_empty() {
            out.push_str("unspecified");
        }
        Self(out)
    }

    /// 文字列として返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// supervisor の起動結果の報告（結果チャネルに 1 行で書く。`#[non_exhaustive]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartReport {
    /// 起動して Running を記録した。`pid` はコンテナの PID 1。
    Started {
        /// 記録した pid。
        pid: NonZeroU32,
    },
    /// 起動に失敗した（状態は Created のまま、または固定文言で示した不確かな状態）。
    Failed {
        /// 機械可読なエラー分類。
        code: ErrorCode,
        /// CLI が使う終了コード（`OciRuntimeError::exit_code` と同じ写像）。
        exit_code: NonZeroU8,
        /// 固定文言（入力値・OS のエラー文字列を含めない）。
        message: ReportMessage,
    },
}

fn invalid(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

/// `ErrorCode::as_str` の逆写像（完全一致のみ）。未知の文字列は `None`（`Internal` に写さない）。
pub fn parse_error_code(s: &str) -> Option<ErrorCode> {
    Some(match s {
        "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
        "NOT_FOUND" => ErrorCode::NotFound,
        "ALREADY_EXISTS" => ErrorCode::AlreadyExists,
        "FAILED_PRECONDITION" => ErrorCode::FailedPrecondition,
        "UNIMPLEMENTED" => ErrorCode::Unimplemented,
        "INTERNAL" => ErrorCode::Internal,
        "PERMISSION_DENIED" => ErrorCode::PermissionDenied,
        "TIMEOUT" => ErrorCode::Timeout,
        "UNAVAILABLE" => ErrorCode::Unavailable,
        "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
        _ => return None,
    })
}

/// 10 進数字だけ・先頭 0 なしの文字列を `u32` へ `checked` で変換する（`+`・空・空白を拒否）。
fn parse_decimal_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse::<u32>().ok()
}

impl StartReport {
    /// 失敗の報告を `OciRuntimeError`（`LifecycleOp::Start`）から作る。`code` / `exit_code` は ERR-2 の写像に揃う。
    pub fn failed(err: &OciRuntimeError) -> Self {
        Self::Failed {
            code: err.code(),
            exit_code: err.exit_code(),
            message: ReportMessage::new(err.message()),
        }
    }

    /// 1 行の書式（末尾 `\n` 付き）へ符号化する。
    pub fn encode(&self) -> String {
        match self {
            Self::Started { pid } => format!("{REPORT_MAGIC} OK {pid}\n"),
            Self::Failed {
                code,
                exit_code,
                message,
            } => format!(
                "{REPORT_MAGIC} ERR {} {} {}\n",
                code.as_str(),
                exit_code,
                message.as_str()
            ),
        }
    }

    /// 結果チャネルから読んだバイト列を復号する。壊れた入力は `InvalidArgument`（panic しない）。
    ///
    /// 検査順: 長さの上限 → `\n` の終端がちょうど 1 個 → ASCII → 接頭辞 → トークン数 → 数値（数字のみ・`checked`）→
    /// `CODE` の完全一致（未知の値は拒否）→ `exit_code` が `exit_code_for(CODE)` と一致（分類と終了コードの矛盾を拒否）。
    pub fn decode(bytes: &[u8]) -> Result<Self, TraitError> {
        if bytes.len() > MAX_REPORT_LEN {
            return Err(invalid("report is too long"));
        }
        if bytes.iter().filter(|&&b| b == b'\n').count() != 1 || bytes.last() != Some(&b'\n') {
            return Err(invalid(
                "report must be exactly one newline-terminated line",
            ));
        }
        if !bytes.is_ascii() {
            return Err(invalid("report must be ASCII"));
        }
        let line = std::str::from_utf8(bytes).map_err(|_| invalid("report must be ASCII"))?;
        let body = line.strip_suffix('\n').unwrap_or(line);
        let mut head = body.splitn(3, ' ');
        if head.next() != Some(REPORT_MAGIC) {
            return Err(invalid("report has an unknown prefix"));
        }
        match (head.next(), head.next()) {
            (Some("OK"), Some(pid)) => {
                let pid = parse_decimal_u32(pid)
                    .and_then(NonZeroU32::new)
                    .ok_or_else(|| invalid("report pid is invalid"))?;
                Ok(Self::Started { pid })
            }
            (Some("ERR"), Some(rest)) => {
                let mut it = rest.splitn(3, ' ');
                let (Some(code), Some(exit), Some(message)) = (it.next(), it.next(), it.next())
                else {
                    return Err(invalid("report has the wrong number of fields"));
                };
                let code = parse_error_code(code)
                    .ok_or_else(|| invalid("report error code is unknown"))?;
                let exit_code = parse_decimal_u32(exit)
                    .and_then(|v| u8::try_from(v).ok())
                    .and_then(NonZeroU8::new)
                    .ok_or_else(|| invalid("report exit code is invalid"))?;
                if exit_code != exit_code_for(code) {
                    return Err(invalid("report exit code does not match the error code"));
                }
                if message.is_empty()
                    || message.len() > MAX_REPORT_MESSAGE_LEN
                    || !message.bytes().all(|b| matches!(b, 0x20..=0x7E))
                {
                    return Err(invalid("report message is invalid"));
                }
                Ok(Self::Failed {
                    code,
                    exit_code,
                    message: ReportMessage(message.to_owned()),
                })
            }
            _ => Err(invalid("report has the wrong number of fields")),
        }
    }
}

/// 検証済みの supervisor `start` 引数。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartArgs {
    /// 状態ルートの絶対パス（検査は `StateRoot::resolve` が行う）。
    pub root: PathBuf,
    /// restart ポリシー（既定 `no`）。
    pub restart: RestartPolicy,
    /// 監査の網羅を満たせない環境への方針（既定 `best-effort`。SEC-4・#2027）。
    pub audit_policy: AuditCoveragePolicy,
    /// CRI ログの書き先（`--cri-log-path`。CRI の `log_directory/log_path` を結合・検証済みの絶対パス。
    /// CRI-2・SUP-4・#2671）。指定があれば `@container-logs` への書き出しに加えて、コンテナ出力を CRI ログ形式で
    /// このパスへ追記する。未指定は従来どおり。
    pub cri_log_path: Option<ContainerLogPath>,
    /// 起動するコンテナの ID。
    pub id: ContainerId,
}

impl StartArgs {
    /// プログラム名を除いた argv を検証して解析する。要素数 [`MAX_ARGS`] 以下・各要素 [`MAX_ARG_LEN`] バイト以下。
    /// 非 UTF-8・未知のオプション・重複・値の欠落・位置引数の過不足・相対の `--root` は `InvalidArgument`
    /// （文言に入力値を埋め込まない）。
    pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, TraitError> {
        let mut tokens: Vec<String> = Vec::new();
        for arg in args.into_iter().take(MAX_ARGS + 1) {
            let s = arg
                .into_string()
                .map_err(|_| invalid("argument is not valid UTF-8"))?;
            if s.len() > MAX_ARG_LEN {
                return Err(invalid("argument is too long"));
            }
            tokens.push(s);
        }
        if tokens.len() > MAX_ARGS {
            return Err(invalid("too many arguments"));
        }
        let mut it = tokens.into_iter();
        if it.next().as_deref() != Some("start") {
            return Err(invalid("the first argument must be \"start\""));
        }
        let mut root: Option<String> = None;
        let mut restart: Option<String> = None;
        let mut audit_policy: Option<String> = None;
        let mut cri_log_path: Option<String> = None;
        let mut id: Option<String> = None;
        while let Some(tok) = it.next() {
            match tok.as_str() {
                "--root" | "--restart" | "--audit-policy" | "--cri-log-path" => {
                    let value = it
                        .next()
                        .ok_or_else(|| invalid("option value is missing"))?;
                    let slot = match tok.as_str() {
                        "--root" => &mut root,
                        "--restart" => &mut restart,
                        "--cri-log-path" => &mut cri_log_path,
                        _ => &mut audit_policy,
                    };
                    if slot.replace(value).is_some() {
                        return Err(invalid("option given more than once"));
                    }
                }
                t if t.starts_with('-') => return Err(invalid("unknown option")),
                _ => {
                    if id.replace(tok).is_some() {
                        return Err(invalid("exactly one container id is required"));
                    }
                }
            }
        }
        let root = PathBuf::from(root.ok_or_else(|| invalid("--root is required"))?);
        if !root.is_absolute() {
            return Err(invalid("--root must be an absolute path"));
        }
        let restart = match restart {
            Some(p) => p.parse::<RestartPolicy>()?,
            None => RestartPolicy::No,
        };
        let audit_policy = match audit_policy {
            Some(p) => p.parse::<AuditCoveragePolicy>()?,
            None => AuditCoveragePolicy::default(),
        };
        // 外部入力（argv）なので cri 側で検証済みでもここで再検証する（SEC-1）。
        let cri_log_path = cri_log_path.map(ContainerLogPath::new).transpose()?;
        let id =
            ContainerId::new(id.ok_or_else(|| invalid("exactly one container id is required"))?)?;
        Ok(Self {
            root,
            restart,
            audit_policy,
            cri_log_path,
            id,
        })
    }
}

/// 監査の記録経路の確認（起動前の `probe`。supervisor の入口が `launch` の前に 1 回行う）に見込む時間。
///
/// `probe` は helper の応答を [`RECORD_WAIT_LIMIT`] まで待ち得るため、同じ値を見込む（SEC-4・REPAIR-5・#2027）。
/// [`result_deadline`] に含め、期限の起点を `probe` の前に置いても launch の見込みを食わないようにする。
pub const AUDIT_PROBE_ALLOWANCE: Duration = RECORD_WAIT_LIMIT;

/// launch の直前に行う監査の網羅の記録（縮退の同期配送）に見込む時間（[`RECORD_WAIT_LIMIT`] と同じ）。
///
/// launcher（`SelfBounded`）は入口の単一期限（引数 `timeout`）から配送を含む待ちを導き、配送は残り時間で打ち切られる
/// ため、この分は launch の上限を広げない（遅い配送は `TIMEOUT` で拒否される）。入口が見込む手順 8 の時間への
/// 余裕としてのみ残す（SEC-4・REPAIR-5・#2027）。
pub const AUDIT_DELIVERY_ALLOWANCE: Duration = RECORD_WAIT_LIMIT;

/// 起動手順 8（`oci_runtime::start`。launch・失敗時の terminate・確認）に見込む時間:
/// `launch + terminate + confirm + 3 × LAUNCHER_REPLY_GRACE + AUDIT_DELIVERY_ALLOWANCE`（あふれたら `Duration::MAX` に張り付く）。
///
/// 手順 8 は入口スレッドが直接行う（本番 launcher は単一スレッドの呼び出しを要求するため。#1819・CORE-1）。
/// launcher 自身が上限を守る（`SelfBounded`）ので、入口は launch の前にこの時間が期限内に残っているかを確かめ、
/// 足りなければ launch せず `INTERNAL`（期限超過）を報告する（期限内に終わらない launch を始めない。REPAIR-5）。
/// 既定値で 39.45s（28s + 11.45s）。
pub fn launch_step_budget(timeouts: &StartTimeouts) -> Duration {
    timeouts
        .launch()
        .saturating_add(AUDIT_DELIVERY_ALLOWANCE)
        .saturating_add(timeouts.terminate())
        .saturating_add(timeouts.confirm())
        .saturating_add(LAUNCHER_REPLY_GRACE.saturating_mul(3))
}

/// supervisor が結果を書くまでの内部上限: [`launch_step_budget`] + [`CGROUP_PREPARE_ALLOWANCE`] + [`AUDIT_PROBE_ALLOWANCE`]
/// （既定値で 56.9s。あふれたら `Duration::MAX` に張り付く）。起点は記録経路の確認（`probe`）の前に置く。
///
/// supervisor（`start_entry::run_start`）は手順 3〜7（状態の確認・cgroup の連鎖・監査 sink・launcher の構築）を
/// 作業スレッドで行い、開始時刻にこの値を足した期限から報告の書き込み分（`start_entry::REPORT_RESERVE`）を引いた
/// 時点まで結果を待つ。作業スレッドが終わったら入口スレッドが手順 8 を直接行う（上の [`launch_step_budget`]）。
/// 準備に使える実質の時間は [`CGROUP_PREPARE_ALLOWANCE`] から報告の書き込み分（1s）と launch 前の作業スレッド消滅の待ち（最大 1s）を引いた 4s で、
/// 手順 3〜7 が長引いて手順 8 の見込みが残らなければ launch せず `INTERNAL`（期限超過）を報告するため、報告は
/// この上限内に届く。失敗後の後始末は報告の後に行う（REPAIR-5）。
pub fn result_deadline(timeouts: &StartTimeouts) -> Duration {
    launch_step_budget(timeouts)
        .saturating_add(CGROUP_PREPARE_ALLOWANCE)
        .saturating_add(AUDIT_PROBE_ALLOWANCE)
}

/// CLI の受信期限: [`result_deadline`] + [`CLI_RECEIVE_GRACE`]。
pub fn cli_receive_deadline(timeouts: &StartTimeouts) -> Duration {
    result_deadline(timeouts).saturating_add(CLI_RECEIVE_GRACE)
}

#[cfg(test)]
mod tests {
    /// CORE-3・SUP-1: 委譲 scope の包み込みの引数は固定（CLI と実機試験が同じ値を使う。#2081）。
    #[test]
    fn sup1_core3_user_scope_wrapper_args_are_fixed() {
        assert_eq!(
            super::USER_SCOPE_WRAPPER_ARGS,
            ["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"]
        );
    }

    use super::*;

    /// 絶対パスの fixture（Windows の `Path::is_absolute` はドライブ接頭辞を要する。CLI-1）。
    #[cfg(windows)]
    const ROOT: &str = r"C:\r";
    #[cfg(windows)]
    const ROOT2: &str = r"C:\s";
    #[cfg(not(windows))]
    const ROOT: &str = "/r";
    #[cfg(not(windows))]
    const ROOT2: &str = "/s";

    const ALL_CODES: [ErrorCode; 10] = [
        ErrorCode::InvalidArgument,
        ErrorCode::NotFound,
        ErrorCode::AlreadyExists,
        ErrorCode::FailedPrecondition,
        ErrorCode::Unimplemented,
        ErrorCode::Internal,
        ErrorCode::PermissionDenied,
        ErrorCode::Timeout,
        ErrorCode::Unavailable,
        ErrorCode::ResourceExhausted,
    ];

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// REPAIR-2: 成功報告の符号化は固定バイト列で、往復で同じ値に戻る。
    #[test]
    fn repair2_report_started_encodes_exact_bytes() {
        let r = StartReport::Started {
            pid: NonZeroU32::new(4242).unwrap(),
        };
        assert_eq!(r.encode().as_bytes(), b"FCSUP1 OK 4242\n");
        assert_eq!(StartReport::decode(b"FCSUP1 OK 4242\n").unwrap(), r);
    }

    /// REPAIR-2・ERR-2: 失敗報告の符号化は固定バイト列で、往復で同じ値に戻る。
    #[test]
    fn repair2_report_failed_roundtrip() {
        let err = OciRuntimeError::new(
            fandhe_container_core::oci_runtime::LifecycleOp::Start,
            ErrorCode::Unimplemented,
            "production process launcher is not available yet",
        );
        let r = StartReport::failed(&err);
        let exit = exit_code_for(ErrorCode::Unimplemented);
        assert_eq!(
            r.encode(),
            format!(
                "FCSUP1 ERR UNIMPLEMENTED {exit} production process launcher is not available yet\n"
            )
        );
        assert_eq!(StartReport::decode(r.encode().as_bytes()).unwrap(), r);
    }

    /// REPAIR-2・ERR-2: `exit_code` が `exit_code_for(CODE)` と食い違う報告は拒否し、一致すれば受理する。
    #[test]
    fn repair2_report_decode_rejects_exit_code_mismatch() {
        for code in ALL_CODES {
            let expected = exit_code_for(code).get();
            let ok = format!("FCSUP1 ERR {} {expected} m\n", code.as_str());
            let decoded = StartReport::decode(ok.as_bytes()).expect("matching exit code");
            assert_eq!(
                decoded,
                StartReport::Failed {
                    code,
                    exit_code: exit_code_for(code),
                    message: ReportMessage("m".to_owned()),
                }
            );
            let wrong = if expected == 255 { 254 } else { expected + 1 };
            let bad = format!("FCSUP1 ERR {} {wrong} m\n", code.as_str());
            let e = StartReport::decode(bad.as_bytes()).expect_err("mismatched exit code");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                e.message(),
                "report exit code does not match the error code"
            );
        }
    }

    /// REPAIR-2: 壊れた報告はすべて InvalidArgument で拒否される。
    #[test]
    fn repair2_report_decode_rejects_malformed() {
        let long_msg = "x".repeat(MAX_REPORT_MESSAGE_LEN + 1);
        let too_long = format!("FCSUP1 ERR INTERNAL 1 {}\n", "x".repeat(MAX_REPORT_LEN));
        let over_msg = format!("FCSUP1 ERR INTERNAL 1 {long_msg}\n");
        let cases: Vec<&[u8]> = vec![
            too_long.as_bytes(),
            over_msg.as_bytes(),
            b"FCSUP1 OK 4242",
            b"FCSUP1 OK 4242\n\n",
            b"FCSUP1 OK 4\n2\n",
            b"FCSUP2 OK 4242\n",
            b"FCSUP1 OK 0\n",
            b"FCSUP1 OK 04242\n",
            b"FCSUP1 OK 4294967296\n",
            b"FCSUP1 OK +5\n",
            b"FCSUP1 OK\n",
            b"FCSUP1 OK 1 2\n",
            b"FCSUP1 ERR BOGUS 1 m\n",
            b"FCSUP1 ERR INTERNAL 0 m\n",
            b"FCSUP1 ERR INTERNAL 256 m\n",
            b"FCSUP1 ERR INTERNAL 1\n",
            b"FCSUP1 ERR INTERNAL 1 \n",
            b"FCSUP1 ERR INTERNAL 1 m\tx\n",
            "FCSUP1 ERR INTERNAL 1 caf\u{e9}\n".as_bytes(),
            b"",
            b"\n",
        ];
        for c in cases {
            let e = StartReport::decode(c).expect_err("must be rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "input: {c:?}");
        }
    }

    /// REPAIR-2: message は ASCII 化され 512 バイトで切られる。
    #[test]
    fn repair2_report_message_sanitizes_and_truncates() {
        assert_eq!(ReportMessage::new("a\nb\u{1b}c\u{e9}").as_str(), "a?b?c?");
        let m = ReportMessage::new(&"y".repeat(600));
        assert_eq!(m.as_str().len(), MAX_REPORT_MESSAGE_LEN);
        assert_eq!(ReportMessage::new("").as_str(), "unspecified");
    }

    /// ERR-1: 既知の全 ErrorCode で as_str と parse_error_code が往復する。
    #[test]
    fn err2_error_code_strings_roundtrip() {
        for c in ALL_CODES {
            assert_eq!(parse_error_code(c.as_str()), Some(c));
        }
        assert_eq!(parse_error_code("internal"), None);
        assert_eq!(parse_error_code(""), None);
    }

    /// SUP-1: 正しい argv の解析。
    #[test]
    fn sup1_args_parse_accepts_valid() {
        let a = StartArgs::parse(os(&["start", "--root", ROOT, "c1"])).unwrap();
        assert_eq!(a.root, PathBuf::from(ROOT));
        assert_eq!(a.restart, RestartPolicy::No);
        assert_eq!(a.id.as_str(), "c1");
        let b =
            StartArgs::parse(os(&["start", "--restart", "always", "--root", ROOT, "c-2"])).unwrap();
        assert_eq!(b.restart, RestartPolicy::Always);
        assert_eq!(b.id.as_str(), "c-2");
        let c = StartArgs::parse(os(&[
            "start",
            "c1",
            "--root",
            ROOT,
            "--restart",
            "on-failure:3",
        ]))
        .unwrap();
        assert_eq!(c.restart, "on-failure:3".parse::<RestartPolicy>().unwrap());
    }

    /// SEC-4・#2027: `--audit-policy` の既定は best-effort、`strict` を受理し、順不同で渡せる。
    #[test]
    fn sec4_2027_args_audit_policy() {
        let a = StartArgs::parse(os(&["start", "--root", ROOT, "c1"])).unwrap();
        assert_eq!(a.audit_policy, AuditCoveragePolicy::BestEffort);
        let b = StartArgs::parse(os(&[
            "start",
            "--audit-policy",
            "strict",
            "--root",
            ROOT,
            "c1",
        ]))
        .unwrap();
        assert_eq!(b.audit_policy, AuditCoveragePolicy::Strict);
        let c = StartArgs::parse(os(&[
            "start",
            "c1",
            "--audit-policy",
            "best-effort",
            "--root",
            ROOT,
        ]))
        .unwrap();
        assert_eq!(c.audit_policy, AuditCoveragePolicy::BestEffort);
        for bad in [
            vec!["start", "--root", ROOT, "--audit-policy", "Strict", "c1"],
            vec!["start", "--root", ROOT, "--audit-policy", "c1"],
            vec!["start", "--root", ROOT, "c1", "--audit-policy"],
            vec![
                "start",
                "--root",
                ROOT,
                "--audit-policy",
                "strict",
                "--audit-policy",
                "strict",
                "c1",
            ],
        ] {
            let e = StartArgs::parse(os(&bad)).expect_err("must be rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "input: {bad:?}");
        }
    }

    /// CRI-2・SUP-4・#2671: `--cri-log-path` の受理（全オプション同時の 10 要素を含む）と拒否。
    #[test]
    fn cri2_cri_log_path_parse() {
        let none = StartArgs::parse(os(&["start", "--root", ROOT, "c1"])).unwrap();
        assert_eq!(none.cri_log_path, None);
        let all = StartArgs::parse(os(&[
            "start",
            "--root",
            ROOT,
            "--restart",
            "always",
            "--audit-policy",
            "strict",
            "--cri-log-path",
            "/l/c/0.log",
            "c1",
        ]))
        .unwrap();
        assert_eq!(all.cri_log_path.as_ref().unwrap().as_str(), "/l/c/0.log");
        for bad in [
            vec!["start", "--root", ROOT, "--cri-log-path", "c1"],
            vec!["start", "--root", ROOT, "c1", "--cri-log-path"],
            vec!["start", "--root", ROOT, "--cri-log-path", "rel/x.log", "c1"],
            vec!["start", "--root", ROOT, "--cri-log-path", "/a/../x", "c1"],
            vec![
                "start",
                "--root",
                ROOT,
                "--cri-log-path",
                "/a/x.log",
                "--cri-log-path",
                "/a/y.log",
                "c1",
            ],
        ] {
            let e = StartArgs::parse(os(&bad)).expect_err("must be rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "input: {bad:?}");
        }
    }

    /// SUP-1: 不正な argv はすべて InvalidArgument。
    #[test]
    fn sup1_args_parse_rejects_invalid() {
        let long = "a".repeat(MAX_ARG_LEN + 1);
        let eleven: Vec<&str> = vec!["start"; 11];
        let cases: Vec<Vec<&str>> = vec![
            vec![],
            vec!["run", "--root", ROOT, "c1"],
            vec!["start", "--root", "r", "c1"],
            vec!["start", "--root", ROOT],
            vec!["start", "--root", ROOT, "a", "b"],
            vec!["start", "--root", ROOT, "--root", ROOT2, "c1"],
            vec![
                "start",
                "--root",
                ROOT,
                "--restart",
                "no",
                "--restart",
                "no",
                "c1",
            ],
            vec!["start", "--root", ROOT, "--bogus", "c1"],
            vec!["start", "--root"],
            vec!["start", "--root", ROOT, "--restart", "sometimes", "c1"],
            vec!["start", "c1"],
            vec!["start", "--root", ROOT, "bad/id"],
            eleven,
            vec!["start", "--root", ROOT, long.as_str()],
        ];
        for c in cases {
            let e = StartArgs::parse(os(&c)).expect_err("must be rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "input: {c:?}");
        }
    }

    /// REPAIR-5・SEC-4・#1819・#2027: 手順 8 の見込みは既定で 28s + 監査配送 11.45s。内部上限はそれに cgroup の準備（6s）と
    /// 記録経路の確認（11.45s）を足した値。
    #[test]
    fn repair5_launch_step_budget_default_includes_audit_delivery() {
        let t = StartTimeouts::default();
        assert_eq!(RECORD_WAIT_LIMIT, Duration::from_millis(11_450));
        assert_eq!(launch_step_budget(&t), Duration::from_millis(39_450));
        assert_eq!(
            result_deadline(&t),
            launch_step_budget(&t) + CGROUP_PREPARE_ALLOWANCE + AUDIT_PROBE_ALLOWANCE
        );
    }

    /// REPAIR-5: 既定の内部上限は 56.9s で、CLI の受信期限はそれより厳密に長い。
    #[test]
    fn repair5_result_deadline_default_is_56_9s() {
        let t = StartTimeouts::default();
        assert_eq!(result_deadline(&t), Duration::from_millis(56_900));
        assert_eq!(cli_receive_deadline(&t), Duration::from_millis(58_900));
        assert!(cli_receive_deadline(&t) > result_deadline(&t));
    }
}
