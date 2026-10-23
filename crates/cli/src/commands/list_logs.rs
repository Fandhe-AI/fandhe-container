//! `list` / `logs` コマンド本体（Linux は plugin を介さず core の状態ストアを直接読む。TASK-79.3・CLI-1・MS-6）。
//!
//! `commands::run_to` が argv を解析した後に [`run_list`] / [`run_logs`] を呼ぶ。状態の読み出しは core の
//! `StateStore::list` / `get`（OCI-5）へ委ね、ID の文字種検証も core の型（`ContainerId`）を唯一の判定とする。
//! 状態ルートの解決・状態ストアの組み立ては `create_start::production_runtime` を共用する。
//!
//! # list の出力形式
//!
//! stdout へタブ区切りテキスト（LF 固定）を出す。1 行目は固定ヘッダ `ID\tSTATUS\tPID`、以降 1 レコード 1 行で
//! `<id>\t<status>\t<pid または ->`。並びは状態ストアが返す順（ID 昇順）、0 件はヘッダのみで終了コード 0。
//! 値は core が検証済みの ID（`[A-Za-z0-9._-]`）・固定語の状態（`creating/created/running/stopped`）・
//! 10 進の PID だけで、エスケープ不要。`bundle` や annotations は任意の UTF-8（タブ・改行・端末制御文字を含み得る）
//! ため出力しない（インジェクション回避。SEC-1）。
//!
//! # 状態ルートの開き方と失敗時の文言（#1607 E1〜E3・ERR-1・OCI-5）
//!
//! - 状態ルート自体が無ければ core の `FileStateStore::open` が親の下に 0700 で作る（stop / delete も同じ）。
//!   開く段階の `NotFound` は「状態ルートの親が無い」ときだけで、固定文言 `parent of the state root not found`（3）にする。
//! - 読み取り専用の open は足さない（E2）。理由: (1) list / get も含め全メソッドが `@lock` を作るため本当の読み取り専用に
//!   ならない。(2) 新規ルートで `@revision` の初期化を省くと、外部で作ったルートに `@lock` だけが残り以後の create が
//!   恒久的に fail-closed になる。(3) 作るのは存在する親の下の 0700 検証済みルートだけで副作用が小さく、初回 list が
//!   ヘッダのみで 0 を返す挙動を保てる。(4) 6 コマンドで open の経路と検証を共有できる。ロック手順を含む本当の
//!   読み取り専用 open は core の設計変更として別途扱う。
//! - 破損レコードがあると `StateStore::list` は全体を fail-closed で失敗させる（E3）。失敗時だけ具体型のストアを開き直し
//!   core の `find_corrupted` で破損の存在を確かめ、あれば回復手段（`purge_corrupted` の管理操作）を示す固定文言にする。
//!   code と終了コードは list のものを保つ。ID・パスは出さない。list はページごとにストア全体を走査する
//!   （効率化は規模が課題になった時点で扱う）。
//!
//! # logs の出力と判定表（fail-closed。CLI-1・SUP-7・#1543）
//!
//! 読み出しは supervisor の `logs::read_container_log` が担い、本 module は状態ルートからログのディレクトリ
//! （`<state_root>/@container-logs`）を決めて呼び、stdout へ渡すだけにする。stdout には古い世代から現在ログの順に、
//! ファイルのバイト列をそのまま出す（`stdout ` / `stderr ` のタグと LF を残す）。コンテナの出力は CLI の stderr へ
//! 出さない（stderr は失敗時の 1 行 JSON の契約。ERR-1・ERR-2）。
//!
//! 書き手は supervisor のバイナリ入口である。起動の手順 6 で `StartDeps::open_log_sink` の本番実装が同じ
//! ディレクトリ（`<state_root>/@container-logs`）に `RotatingFileSink` を開き、`log_pipeline::CaptureHub` が core の
//! 本番 launcher の出力パイプ（`take_output`）から行を流す（#1471・#1819・SUP-7）。本 module は書き手と同じ定義
//! （`container_log_dir`・`container_log_rotation_config`）で読む。
//!
//! # logs のオプション（CLI-1・SUP-7・#2447）
//!
//! 構文は `logs [--follow] [--tail <N>] [--stream <stdout|stderr>] [--escape] [--] <id>`（順不同・各 1 回まで。長い形だけ。
//! 3 OS で同じ構文を受理する）。オプションなしは従来どおりバイトのまま出す。どれかを指定するとレコード単位になり、
//! レコードの検証（タグが `stdout ` / `stderr ` であること・1 行が上限以下であること）をする。
//!
//! - `--tail <N>`: 絞り込みの後の末尾 N レコード（`0..=1,000,000`。範囲外は使い方エラー）。メモリは N に依らず固定。
//! - `--stream <stdout|stderr>`: そのタグのレコードだけを、タグを残して stdout へ出す。コンテナの stderr を CLI の stderr へ
//!   流さないのは、CLI の stderr が失敗時の 1 行 JSON の契約（ERR-1・ERR-2）だからである。
//! - `--escape`: レコード本体の制御文字を `cat -v` と同じ表（ESC → `^[`、CR → `^M`、`0x7F` → `^?`、`0x80` 以上は `M-` を前置、
//!   TAB はそのまま）で表示用に変換する。タグと区切りの LF は変えない。信頼できないコンテナのログを端末へ出すときに使う。
//!   指定しない出力は、docker / kubectl と同じくデータを加工しない。端末へ直接出すと ESC 系のシーケンスが解釈され得る。
//! - `--follow`: 出し終えた後も現在ログの追記を追う（完全な行だけ。ローテーションをまたいでも欠落・重複なし）。
//!   終わりは (1) 組み込みの期限（24 時間。値はオーナー確認待ち。超えたら残りを出し切って 0）、(2) SIGINT・SIGTERM・SIGHUP
//!   （`signals` が転送した後に既定動作で終了する。stderr に JSON は出ず、それまでに出した行は stdout に届いている。
//!   起動時に `SIG_IGN` を継承したシグナルは上書きしない）、(3) stdout の失敗（`| head` 等。1 / `INTERNAL`）、(4) 追いつけない
//!   ローテーション（9 / `UNAVAILABLE`）、(5) ログの削除（出し切って 0）、(6) コンテナの停止（書き手の sink がいなくなり、
//!   かつ状態の記録が `Running` でないとき、残りを出し切って 0。Docker 互換）。`Stopped` の記録は supervisor の最終 flush より
//!   先に書かれるため、状態だけでは末尾を取りこぼす。書き手の終了（`<id>.log.lock` の解放）も条件にするので取りこぼさない。
//!   restart ポリシーの再 launch の間は sink が保持されるので終わらない。状態の読み取りに失敗したら続ける（期限が上限）。
//!   supervisor がクラッシュして記録が `Running` のまま残る場合は期限まで続く。`create` 済みで未 `start`（sink が無い）の
//!   コンテナへの `--follow` は、書き手がいないため直ちに終わる。
//!   追従の遅延は、LF で終わる行について最大で 1 ポーリング間隔（200 ms）と読み出しの時間である（捕捉リーダーが read のたびに
//!   flush するため、書き手側の滞留は無い）。LF の来ていない行は、LF・EOF・64 KiB の上限のどれかまで出ない。
//!   世代数 1 の設定の追従は拒否する（9 / `UNAVAILABLE`）。理由は supervisor の `logs::reader` のモジュール doc を参照。
//!   本番の設定は固定の 3 世代で、利用者が世代数を設定する手段は無いため、本番の CLI からは到達しない。
//!   試験専用 feature `logs-test-support` のときだけ、環境変数 `FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS`（10 進ミリ秒。
//!   上限で丸め、不正なら無視）で期限を短くできる。
//!
//! | 条件 | 結果 |
//! | ---- | ---- |
//! | ID の文字種違反 | 2（`INVALID_ARGUMENT`） |
//! | 状態ルートの親が無い | 3（`NOT_FOUND`。文言は `parent of the state root not found`） |
//! | 状態ルートを開けない（非 Linux は plugin 解決の失敗） | core のコードどおり（非 Linux は候補なしで 5、他は 8 / 6） |
//! | 対象の状態レコードが無い | 3（`NOT_FOUND`。`container not found`） |
//! | ログが無い（ディレクトリが無い・ファイルが 0 件・0 バイト） | 0（stdout は空） |
//! | ログがある | 0（stdout はレコード列） |
//! | ログを読めない（名前空間に受理できない名前・symlink・権限・I/O エラー・レコードの破損） | 1（`INTERNAL`。`container log could not be read`） |
//! | 世代の入れ替わりが収まらない | 9（`UNAVAILABLE`。`container log is rotating; retry`） |
//! | 追従がローテーションに追いつけない | 9（`UNAVAILABLE`。`container log rotated faster than it could be followed`） |
//! | 追従の期限 | 0 |
//! | 読む量の上限を超えた | 5（`FAILED_PRECONDITION`。`container log exceeds the read limit`） |
//! | stdout への書き込みに失敗した | 1（`INTERNAL`） |
//!
//! delete でのコンテナログ（`@container-logs/<id>.log*`）の削除は、core の delete の成功後に `stop_delete` が行う（#2446）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - logs: 利用者向けの期限フラグ（`--until` 等）の要否と構文、`--follow` の期限（24 時間）・`--tail` の件数（1,000,000）の
//!   上限の値はオーナー確認待ち（#2605）。追従の遅延の短縮（inotify / kqueue）は行わない。非 Linux の読み出しは plugin 経由
//!   （TASK-114・TASK-125）。
//! - 再起動をまたぐ出力の捕捉: 再 launch が実機で成り立つのを待つ（#2043）。
//! - list の JSON 出力・bundle 列: JSON を手組みしない（REPAIR-2）ため serde 系の配線か core の公開ライタが前提
//!   （TASK-95・TASK-98）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。非 Linux では状態ストアを開けず core 側が
//!   `Unimplemented` を返す（fail-closed）。

use std::io::Write;
use std::num::NonZeroU32;
use std::time::Instant;

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, ListStateRequest, MAX_PAGE_SIZE,
    StateRecord, StateStore, TraitError,
};

use fandhe_container_supervisor::logs::{
    ContainerActivity, FollowOptions, LogReadFailure, LogReadOptions, MAX_FOLLOW_DURATION,
    StreamKind, TailCount, container_log_dir, container_log_rotation_config,
    read_container_log_with,
};

use super::CliExit;
use super::args::{GlobalArgs, ListArgs, LogStreamArg, LogsArgs};
use super::create_start::{OP_LOG_ENV, export_ops, open_store, production_runtime};

/// list の固定ヘッダ行（LF 終端）。
const LIST_HEADER: &str = "ID\tSTATUS\tPID\n";

/// 走査するページ数の上限（REPAIR-5）。不正なストア実装が `next_cursor` を返し続けても無期限に回らない。
pub(super) const MAX_LIST_PAGES: u32 = 100_000;

/// 1 レコードを 1 行（LF 終端）で `out` へ追記する。PID が無ければ `-`。
fn format_record_line(record: &StateRecord, out: &mut String) {
    out.push_str(record.id().as_str());
    out.push('\t');
    out.push_str(record.status().state().as_str());
    out.push('\t');
    match record.status().pid() {
        Some(pid) => out.push_str(&pid.get().to_string()),
        None => out.push('-'),
    }
    out.push('\n');
}

/// list の失敗の出どころ。stdout の書き込み失敗を破損の診断対象にしない（誤って破損と伝えない）ための区別。
enum ListFailure {
    /// 状態ストア側の失敗（破損レコードによる fail-closed を含む）。
    Store(TraitError),
    /// stdout への書き込み失敗。
    Stdout,
}

impl From<TraitError> for ListFailure {
    fn from(e: TraitError) -> Self {
        ListFailure::Store(e)
    }
}

/// 状態ストアの全レコードをヘッダ付きで `out` へ書く。ページごとに 1 回の `write_all` で書き、全件を溜めない。
fn list_containers(
    store: &dyn StateStore,
    out: &mut dyn Write,
    page_size: NonZeroU32,
) -> Result<(), ListFailure> {
    out.write_all(LIST_HEADER.as_bytes())
        .map_err(|_| ListFailure::Stdout)?;
    let mut req = ListStateRequest::new(page_size)?;
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        let mut buf = String::new();
        for record in page.records() {
            format_record_line(record, &mut buf);
        }
        if !buf.is_empty() {
            out.write_all(buf.as_bytes())
                .map_err(|_| ListFailure::Stdout)?;
        }
        match page.next_cursor() {
            Some(cursor) => req = req.with_cursor(cursor.clone()),
            None => return Ok(()),
        }
    }
    Err(ListFailure::Store(TraitError::new(
        ErrorCode::Internal,
        "state listing did not terminate",
    )))
}

/// list の失敗を終了値へ写す。ストア側の失敗では、同じ `--root` を開き直して core の `find_corrupted` で
/// 破損の存在を確かめ、あれば回復手段を示す固定文言にする（code・終了コードは list のものを保つ。#1607 E3）。
/// 開き直せない・破損が見つからない場合は従来の写像（診断は 1 回だけでループしない。REPAIR-5）。
fn list_failure(global: &GlobalArgs, f: &ListFailure) -> CliExit {
    match f {
        ListFailure::Stdout => CliExit::failed(ErrorCode::Internal),
        ListFailure::Store(e) => {
            let corrupted = open_store(global)
                .and_then(|s| s.find_corrupted())
                .is_ok_and(|found| !found.is_empty());
            if corrupted {
                CliExit::state_store_corrupted(e.code())
            } else {
                store_open_failure(e)
            }
        }
    }
}

/// 対象の状態レコードが存在することを確かめる（無ければ `NotFound`）。
fn container_exists(store: &dyn StateStore, id: &ContainerId) -> Result<(), TraitError> {
    store.get(&GetStateRequest::new(id.clone())).map(|_| ())
}

/// 計測へ成功・失敗を 1 回だけ記録する（core の list / get は記録しないため CLI 側で記録する。REPAIR-4）。
pub(super) fn record_op(recorder: &OpRecorder, op_name: &str, ok: bool, started: Instant) {
    if let Ok(name) = OpName::new(op_name) {
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
}

/// 状態ストアを開く段階の失敗を終了値へ写す。コンテナ ID を参照していない段階の `NotFound` は
/// 状態ルートの親の不在であり（ルート自体は open が作る）、コンテナ不在（`container not found`）と誤報しない。
///
/// 非 Linux では plugin 解決の失敗（`plugin_backend::BackendFailure`）を先に拾い、「未導入」と「信頼性検証の
/// 拒否」などを区別できる固定文言の識別子で出す（C1・TASK-79.4 追補）。照合は `plugin_backend` の固定文言表との
/// 完全一致のみで、一致時に出すのはその `&'static str` 定数だけ。core の `TraitError::message`
/// （`--root` 不正・発見の I/O エラー等を含む）は出力へ流さず、表に無い失敗は従来の汎用文言に落とす。
pub(super) fn store_open_failure(e: &TraitError) -> CliExit {
    #[cfg(not(target_os = "linux"))]
    if let Some(kind) = super::plugin_backend::BackendFailure::classify(e) {
        return CliExit::Error(crate::error::CliError::new(kind.code(), kind.message()));
    }
    match e.code() {
        ErrorCode::NotFound => CliExit::state_root_parent_not_found(),
        c => CliExit::failed(c),
    }
}

/// 本番入口の `list`。成功時は stdout に一覧を出す。
pub(super) fn run_list(global: &GlobalArgs, _args: &ListArgs, stdout: &mut dyn Write) -> CliExit {
    let started = Instant::now();
    let rt = match production_runtime(global, OpRecorder::new(), "list", started, || Ok(())) {
        Ok((rt, ())) => rt,
        // core 到達前の失敗は production_runtime が記録・出力済み。
        Err(e) => return store_open_failure(&e),
    };
    let page_size = NonZeroU32::new(MAX_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let result = list_containers(rt.store.as_ref(), stdout, page_size);
    record_op(&rt.recorder, "list", result.is_ok(), started);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(()) => CliExit::Success,
        // list はコンテナを参照しないため、NotFound はコンテナ不在ではない。
        Err(f) => list_failure(global, &f),
    }
}

/// `logs` のコンテナログ読み出しの失敗を終了値へ写す。ログ側の `NotFound` は「コンテナ不在」ではないため
/// `Internal` へ寄せる（`container not found` と誤報しない。出力に core のメッセージ・パスは流さない。ERR-1）。
fn log_read_failure(f: &LogReadFailure) -> CliExit {
    match f {
        LogReadFailure::Output => CliExit::failed(ErrorCode::Internal),
        LogReadFailure::Source(e) => CliExit::container_log_failed(e),
    }
}

/// 試験専用: `--follow` の期限を上書きする環境変数（feature `logs-test-support` のときだけ読む。10 進ミリ秒）。
#[cfg(feature = "logs-test-support")]
const TEST_FOLLOW_DEADLINE_ENV: &str = "FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS";

/// `--follow` の期限。既定は上限（24 時間）。試験用 feature のときだけ環境変数で短くできる（不正な値は無視する）。
fn follow_deadline() -> std::time::Duration {
    #[cfg(feature = "logs-test-support")]
    if let Some(ms) = std::env::var(TEST_FOLLOW_DEADLINE_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return std::time::Duration::from_millis(ms).min(MAX_FOLLOW_DURATION);
    }
    MAX_FOLLOW_DURATION
}

/// 引数から supervisor の読み出しオプションを組む。範囲外は構築の段階で `InvalidArgument`（args が先に弾くため防御）。
fn read_options(args: &LogsArgs) -> Result<LogReadOptions, TraitError> {
    let mut opts = LogReadOptions::default().with_escape(args.escape);
    if let Some(n) = args.tail {
        opts = opts.with_tail(TailCount::new(n)?);
    }
    if let Some(s) = args.stream {
        opts = opts.with_stream(match s {
            LogStreamArg::Stdout => StreamKind::Stdout,
            LogStreamArg::Stderr => StreamKind::Stderr,
        });
    }
    if args.follow {
        opts = opts.with_follow(FollowOptions::new(follow_deadline())?);
    }
    Ok(opts)
}

/// `--follow` の継続判定用に、状態ストアの記録から稼働状態を読む（書き手の sink がいないときだけ supervisor が呼ぶ）。
///
/// 記録が `Running` なら `Running`、それ以外（`Created`・`Stopped`・記録の不在）は `NotRunning`、読み取りの失敗は
/// `Unknown`（追従を続ける。早く終えると取りこぼし、失敗にすると長い追従が一時的な競合で中断するため。#2605・REPAIR-5）。
fn container_activity(store: &dyn StateStore, id: &ContainerId) -> ContainerActivity {
    match store.get(&GetStateRequest::new(id.clone())) {
        Ok(rec) if rec.status().state() == ContainerState::Running => ContainerActivity::Running,
        Ok(_) => ContainerActivity::NotRunning,
        Err(e) if e.code() == ErrorCode::NotFound => ContainerActivity::NotRunning,
        Err(_) => ContainerActivity::Unknown,
    }
}

/// 本番入口の `logs`。対象の存在を確かめ、supervisor の読み出し入口でコンテナログを古い順に stdout へ出す
/// （CLI-1・SUP-7・#1543）。ログが無ければ何も出さず成功する。
pub(super) fn run_logs(global: &GlobalArgs, args: &LogsArgs, stdout: &mut dyn Write) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "logs", started, || {
        ContainerId::new(args.id.as_str())
    });
    let (rt, id) = match prepared {
        Ok(v) => v,
        Err(e) => return store_open_failure(&e),
    };
    let exit = match container_exists(rt.store.as_ref(), &id) {
        Err(e) => CliExit::failed(e.code()),
        Ok(()) => match rt.store.host_state_root() {
            // `FileStateStore` では起きない防御。ログの置き場が決められなければ読めない（fail-closed）。
            None => CliExit::unimplemented(),
            Some(root) => match read_options(args) {
                Err(e) => CliExit::failed(e.code()),
                Ok(opts) => {
                    let dir = container_log_dir(root);
                    let store = rt.store.as_ref();
                    let mut activity = || container_activity(store, &id);
                    match read_container_log_with(
                        &dir,
                        &id,
                        container_log_rotation_config(),
                        &opts,
                        stdout,
                        &mut activity,
                    ) {
                        Ok(_) => CliExit::Success,
                        Err(f) => log_read_failure(&f),
                    }
                }
            },
        },
    };
    record_op(
        &rt.recorder,
        "logs",
        matches!(exit, CliExit::Success),
        started,
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{ContainerStatus, StateRevision};

    fn record(status: ContainerStatus) -> StateRecord {
        StateRecord::new(status, std::env::temp_dir(), StateRevision::from_raw(1)).expect("rec")
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    /// CLI-1: 1 行の形式（pid なし `-`・pid あり 10 進）。
    #[test]
    fn cli1_format_record_line() {
        let mut s = String::new();
        let pid = NonZeroU32::new(4242);
        format_record_line(&record(ContainerStatus::created(cid("a1"), None)), &mut s);
        format_record_line(&record(ContainerStatus::running(cid("b2"), pid)), &mut s);
        format_record_line(
            &record(ContainerStatus::stopped(cid("c3"), Some(0))),
            &mut s,
        );
        assert_eq!(s, "a1\tcreated\t-\nb2\trunning\t4242\nc3\tstopped\t-\n");
    }

    fn stderr_line(e: &CliExit) -> String {
        let mut buf = Vec::new();
        e.write_stderr(&mut buf).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// CLI-1: ストアを開く段階の NotFound は状態ルートの親の不在で、コンテナ不在と区別される。
    #[test]
    fn cli1_store_open_not_found_is_state_root_parent() {
        let nf = TraitError::new(ErrorCode::NotFound, "x");
        let e = store_open_failure(&nf);
        assert_eq!(e.exit_code(), 3);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"NOT_FOUND\",\"message\":\"parent of the state root not found\"}\n"
        );
        let inv = TraitError::new(ErrorCode::InvalidArgument, "x");
        let e = store_open_failure(&inv);
        assert_eq!(e.exit_code(), 2);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid argument\"}\n"
        );
    }

    /// C1: 非 Linux の plugin 解決失敗は「未導入」と「検証未実装」で別の固定文言になる。
    /// 表に無い失敗（任意文言）は汎用文言のまま。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn c1_plugin_failures_have_distinct_identifiers_off_linux() {
        use super::super::plugin_backend::BackendFailure;
        let e = store_open_failure(&BackendFailure::NotInstalled.into_error());
        assert_eq!(e.exit_code(), 5);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"platform backend plugin is not installed\"}\n"
        );
        let e = store_open_failure(&BackendFailure::TrustUnsupported.into_error());
        assert_eq!(e.exit_code(), 8);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin trust verification is not implemented on this platform\"}\n"
        );
        let e = store_open_failure(&TraitError::new(ErrorCode::FailedPrecondition, "detail"));
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"failed precondition\"}\n"
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use fandhe_container_core::oci_runtime::create;
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_core::traits::CreateRequest;

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-cli-ll-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// 書き込みに失敗する Write。
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn store(base: &TmpDir) -> FileStateStore {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            FileStateStore::open(root).expect("open")
        }

        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn create_all(base: &TmpDir, st: &FileStateStore, names: &[&str]) {
            let rec = OpRecorder::new();
            for n in names {
                let req = CreateRequest::new(ContainerId::new(*n).expect("id"), make_bundle(base))
                    .expect("req");
                create(st, &rec, &req).expect("create");
            }
        }

        fn listed(st: &FileStateStore, page: u32) -> String {
            let mut out = Vec::new();
            list_containers(st, &mut out, NonZeroU32::new(page).expect("nz"))
                .unwrap_or_else(|_| panic!("list"));
            String::from_utf8(out).expect("utf8")
        }

        /// CLI-1: 0 件はヘッダのみ。
        #[test]
        fn cli1_list_empty_is_header_only() {
            let base = TmpDir::new("empty");
            let st = store(&base);
            assert_eq!(listed(&st, 2), "ID\tSTATUS\tPID\n");
        }

        /// CLI-1: 複数件は ID 昇順で、ページ境界（3 件 / ページサイズ 2、1 件ずつ）をまたいでも全件出る。
        #[test]
        fn cli1_list_spans_pages() {
            let base = TmpDir::new("pages");
            let st = store(&base);
            create_all(&base, &st, &["c3", "a1", "b2"]);
            let expect = "ID\tSTATUS\tPID\na1\tcreated\t-\nb2\tcreated\t-\nc3\tcreated\t-\n";
            assert_eq!(listed(&st, 2), expect);
            assert_eq!(listed(&st, 1), expect);
            assert_eq!(listed(&st, 1000), expect);
        }

        /// CLI-1: logs の存在確認。無ければ NotFound、あれば Ok。
        #[test]
        fn cli1_container_exists() {
            let base = TmpDir::new("exists");
            let st = store(&base);
            create_all(&base, &st, &["a1"]);
            let a1 = ContainerId::new("a1").expect("id");
            let nope = ContainerId::new("nope").expect("id");
            assert!(container_exists(&st, &a1).is_ok());
            let e = container_exists(&st, &nope).expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
        }

        /// 書き込み失敗は panic せず Internal になる。
        #[test]
        fn err2_list_write_failure_is_internal() {
            let base = TmpDir::new("wfail");
            let st = store(&base);
            let f = list_containers(&st, &mut FailingWriter, NonZeroU32::MIN).expect_err("io");
            assert!(matches!(f, ListFailure::Stdout));
            let e = list_failure(&GlobalArgs::default(), &f);
            assert_eq!(e.exit_code(), 1);
            assert_eq!(
                stderr_line(&e),
                "{\"code\":\"INTERNAL\",\"message\":\"operation failed\"}\n"
            );
        }
    }
}
