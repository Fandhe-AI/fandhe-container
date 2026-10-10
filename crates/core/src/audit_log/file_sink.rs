//! 本番用の監査記録先 [`FileAuditSink`]（SEC-4・SUP-6・TASK-41・TASK-163 追補・#1594）。
//!
//! # 役割
//!
//! 主経路（ローカルファイルへの JSON Lines 追記。`AuditFileWriter`）と代替経路（カーネル監査。
//! `KernelAuditFallback`）を `write_with_fallback` で束ね、[`AuditSink`] を実装する。supervisor の
//! `exec::run_command`（exec 対象の拒否の永続化）のほか、mount 検証/API・plugin 信頼検証・seccomp フックが
//! 同じ [`AuditSink`] 経由で使う想定の、全レイヤー共有の本番実体。
//!
//! # 置き場所の判断
//!
//! core に置く。利用者が supervisor に限られない（CLI 側の plugin 信頼検証などからも使う）ことと、
//! `StateStore` がトレイトもファイルベース既定実装も core に置く前例（TASK-31・OCI-5）に揃えるため。
//! 別の記録先は [`AuditSink`] の別実装として差し替えられる。
//!
//! # 既定パスと所有者・権限の前提
//!
//! - 既定パスは `<状態ルート>/@audit.log`（[`AUDIT_LOG_FILE_NAME`]。OCI-5 の状態ルート。root 実行は
//!   `/run/fandhe-container`、rootless は `$XDG_RUNTIME_DIR/fandhe-container`）。`@` 始まりは `ContainerId` の
//!   許容文字に含まれないため、コンテナ ID と衝突せず `list` 等からも読み飛ばされる
//! - 構築（本番）は [`FileAuditSink::in_state_store`] のみ。open 済みの `FileStateStore` を要求して順序を型で固定する
//!   （`FileStateStore::open` は状態ルートに `@revision.init-*` 以外のエントリがあると既存ストアとみなして
//!   `@revision` を初期化しないため、open より前に `@audit.log` を作ると永久に fail-closed になる）
//! - ファイルは 0600・実効 uid 所有・ハードリンク数 1、親は 0700 の状態ルート。symlink・FIFO・他者所有・
//!   g/o 権限付きは `AuditFileWriter::open` が拒否し、その場合は代替経路へ回る
//! - **限界（rootless。SEC-5）**: ログの所有者は実効 uid（コンテナ内 root の写し先と同じホスト UID）で、
//!   `CAP_AUDIT_WRITE` が無いため代替経路（カーネル監査）も使えない。同じホストユーザーの権限を得た主体は
//!   ログを書き換え・削除できる（改ざん耐性は無い。本質的な限界）
//!
//! # 排他とタイムアウト（REPAIR-5）
//!
//! - プロセス内 `Mutex` は持たない。排他は `AuditFileWriter::write_record` の `flock`（open file description
//!   単位）が担い、同一プロセスの別スレッド・別プロセスのいずれも直列化される
//! - **主経路のファイル I/O は fork した使い捨ての子プロセスで行い、親は [`PRIMARY_WRITE_TIMEOUT`] だけ待つ**。
//!   `write_all`・`sync_data` には期限を付けられず（ストレージ停止で戻らない）、スレッドでの隔離は時間切れ後に
//!   スレッドが残って以後の fork（exec の worker は `Threads: 1` 必須）を妨げるため、プロセスで隔離する。
//!   時間切れの子は SIGKILL で止め、親は `isolation_timeout` を主経路の失敗として代替経路（カーネル監査）へ進む
//!   （代替経路はストレージに触れず、ACK は [`KERNEL_AUDIT_ACK_TIMEOUT`] が上限）。D 状態で SIGKILL が
//!   効かない子は PID を追跡して後続の呼び出しで回収し、未回収が上限に達したら fork せず代替経路へ進む
//!   （スレッドではないので親の `Threads` は増えない）。未回収の子の追跡の `Mutex` が poison すると、以後
//!   プロセスが終わるまで上限到達扱いになり、主経路・通知の子を fork しない（fail-closed）。非 Linux は隔離を
//!   提供せず常に代替経路へ進む（CLI-1）
//! - 子は `close_range(2)`（Linux 5.11 以降。exec の子と同じ前提）で fd 3 以上を閉じてから処理する（D 状態で
//!   残った子が呼び出し側の `flock`・pipe の書き込み端を持ち続けない）。閉じられないカーネルでは処理せずに
//!   終わり、主経路は `isolation_fds_not_closed` で代替経路へ、通知はスレッドでの出し直しへ進む。**限界
//!   （REPAIR-3）**: Linux 5.11 未満では主経路は常に使われない（代替経路が成功すると通知も出ないため、ファイルは
//!   黙って使われないままになる。両経路が失敗したときの通知の `primary` が `isolation_fds_not_closed` になり、
//!   fork 不能の `isolation_unavailable` と見分けられる）
//! - 子の結果は終了 status ではなく子が書く結果 pipe の印で受ける（`SIGCHLD` が `SIG_IGN`・`SA_NOCLDWAIT` の
//!   プロセスでは子が自動回収され status が失われるため）。印は「開始」（通知の子が出力先へ書き込む直前に書く）と
//!   「結果」（終了コード）の 2 種類。シグナルは fork 直後に開いた pidfd 経由で送り、`waitpid` が `ECHILD` を
//!   返した子（回収済み）へは送らない（pid 再利用対策。CORE-1）
//! - 子は `fork_single_threaded` で作る。呼び出しプロセスが複数スレッドだと fork できないため、その場合は
//!   主経路を試行せず `isolation_unavailable` で代替経路へ進む（期限を保証できない I/O を呼び出しスレッドで
//!   実行しない。fail-closed）。supervisor の exec は単一スレッドのプロセスから呼ぶ契約
//! - 1 回の `record` の待ち時間の上限は [`RECORD_WAIT_LIMIT`]（主経路・代替経路・失敗通知の上限の合算。
//!   定期 exec〔healthcheck。TASK-161〕へ配線するときは、この値を呼び出し側の期限の積み上げに含める）
//! - 呼び出し側（supervisor）の記録点は worker を回収した後の親プロセスで、sink が詰まっても worker・
//!   コマンドは残らない
//!
//! # 書くたびに開き直す理由
//!
//! 1. `KernelAuditFallback` は `Send` 境界のない transport を持つため、保持すると `AuditSink: Send + Sync` を
//!    満たせない。生成関数を持ち毎回作る（送信ごとに socket を開閉する設計なのでコストは変わらない）
//! 2. fd を持たないので、sink 生成後に fork する exec の worker（コンテナの mnt ns・cgroup に入る）へ
//!    ホストの監査ファイルの fd が継承されない
//! 3. 毎回、親ディレクトリ・ファイルの信頼検査をやり直すため、差し替え・ローテーションに追従しつつ検査を保てる
//!
//! # 両経路失敗時
//!
//! 固定スキーマの 1 行（`AuditWriteFailure::write_json_line`）を **本 sink が 1 回だけ** stderr へ出し、
//! `INTERNAL` を返す。stderr への出力も fork した子プロセスで行い、[`NOTIFY_WAIT`] で打ち切る（出力先が満杯の
//! パイプで詰まっても、スレッドを残さず以後の exec を妨げない）。子で出せたと確認できないとき（複数スレッドで
//! fork できない・fork 失敗・未回収の子が上限・子のシグナル死・継承 fd を閉じられない・書き込み失敗・書き込みに
//! 達する前の時間切れ）は、上限付きの短命スレッドで出し直す（未完了 [`NOTIFY_QUEUE_CAP`] 件で頭打ち）。子が
//! 書き込みを始めた（「開始」の印がある）後に [`NOTIFY_WAIT`] を超えて詰まった場合だけは出し直さない（同じ
//! 出力先で詰まるだけのため）。書き込みを始めた子が失敗した後の出し直しは、途中まで出た断片と完全な行が 1 行に
//! 連結されないよう、先頭に改行を 1 つ付ける（REPAIR-4）。**fail-closed**: 出し直しのスレッドが詰まった出力先で
//! 残ると、単一スレッドだったプロセスはそれ以後 fork できず、以後の exec の worker 生成は拒否される。完了した
//! スレッドは join し、スレッド数が元へ戻るのを [`NOTIFY_THREAD_EXIT_WAIT`] まで待つ（join の直後は解放前の
//! スレッドが数に残り、続く fork が `MultiThreaded` で拒否され得るため。上限を超えたら待たずに戻る）。
//! `AuditDelivery::SinkFailed` はこの行を再構成できないため、呼び出し側は二重に出さない。
//! 拒否の判定は覆らない（fail-closed）。主経路だけ失敗して代替経路に記録できた場合の運用通知は未実装。
//!
//! # 未実装（REPAIR-3）
//!
//! `/run` は tmpfs のため再起動を越える保持は保証しない。永続的な置き場所（`/var/log` 等）・ローテーション・
//! 常時の二重記録（tee）は未実装。非 Linux では `FileStateStore::open` が `Unimplemented` を返すため
//! 構築入口も fail-closed になる。
//!
//! `@audit.log` にはサイズ上限もローテーションも無い。entrypoint 層の理由（`stdio_null_not_null_device` 等）は
//! コンテナの中身で引き起こせるため、定期 exec（healthcheck。TASK-161）を配線すると、コンテナ起点で tmpfs の
//! `/run` が単調に増え得る。配線の前に、サイズ上限（超えたら代替経路へ回して件数を数える）か同じ理由の連続の
//! 抑制を入れる（SEC-4・CORE-7・REPAIR-5）。

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::state_store::FileStateStore;
#[cfg(target_os = "linux")]
use crate::sys;
use crate::traits::TraitError;

use super::{
    AuditFallback, AuditFileWriter, AuditRecord, AuditSink, AuditWriteError, AuditWriteErrorKind,
    AuditWriteFailure, KERNEL_AUDIT_ACK_TIMEOUT, KernelAuditFallback,
};

/// 状態ルート直下の監査ログのファイル名。
pub const AUDIT_LOG_FILE_NAME: &str = "@audit.log";

/// 主経路（ファイル書き込み）を隔離した子プロセスの待ち時間の上限（REPAIR-5）。
///
/// `flock` の待ち上限（5 秒）に open・write・`sync_data` の余裕を足した値。超過した子は SIGKILL する。
pub const PRIMARY_WRITE_TIMEOUT: Duration = Duration::from_secs(8);

/// 失敗通知（stderr 出力）を隔離した子プロセスの待ち時間の上限。超過した子は SIGKILL する。
pub const NOTIFY_WAIT: Duration = Duration::from_millis(200);

/// kill 後に子の回収を待つ上限。SIGKILL が効かない子（D 状態）は PID を [`pending`] に保持して諦める。
const KILL_REAP_WAIT: Duration = Duration::from_secs(1);
/// 子の終了を確認するポーリング間隔。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 同時に未完了でいられる通知の出し直しスレッド数の上限（子で出せたと確認できなかったときの出し直し。
/// 条件は `notify_retry`。単一スレッドのプロセスでも使われる）。
const NOTIFY_QUEUE_CAP: usize = 8;

/// 出し直しのスレッドを join した後、スレッド数が元へ戻るのを待つ上限（REPAIR-5・SUP-6）。
///
/// join は終了の通知（`CLONE_CHILD_CLEARTID`）で戻り、スレッドの解放はその直後に行われるため、戻った直後の
/// `/proc/self/status` には短い間だけ残る。その間に次の exec が `fork_single_threaded` すると拒否されるので待つ。
const NOTIFY_THREAD_EXIT_WAIT: Duration = Duration::from_millis(50);

/// 1 回の `record` の待ち時間の上限（スケジューリングの遅れ・ポーリング間隔の端数を除く。REPAIR-5）。
///
/// 内訳は、主経路（`PRIMARY_WRITE_TIMEOUT` の 8 秒＋kill 後の回収待ち 1 秒）＋代替経路の ACK
/// （[`KERNEL_AUDIT_ACK_TIMEOUT`]）＋失敗通知（子の `NOTIFY_WAIT` の 200 ms＋kill 後の回収待ち 1 秒＋出し直し
/// スレッドの `NOTIFY_WAIT`＋スレッド数が戻るのを待つ 50 ms）で、合計 11.45 秒。定期 exec（healthcheck。TASK-161・#492／#495）へ配線する
/// ときは、`run_command` の `timeout` とは別にこの値が積み上がる。
pub const RECORD_WAIT_LIMIT: Duration = PRIMARY_WRITE_TIMEOUT
    .saturating_add(KILL_REAP_WAIT)
    .saturating_add(KERNEL_AUDIT_ACK_TIMEOUT)
    .saturating_add(NOTIFY_WAIT)
    .saturating_add(KILL_REAP_WAIT)
    .saturating_add(NOTIFY_WAIT)
    .saturating_add(NOTIFY_THREAD_EXIT_WAIT);

type FallbackFactory = Arc<dyn Fn() -> Box<dyn AuditFallback> + Send + Sync>;
type FailureNotifier = Arc<dyn Fn(&AuditWriteFailure) + Send + Sync>;
/// 主経路の 1 回分の書き込み（パスを開いて 1 件追記）。隔離した子の中で実行される。
type PrimaryStep = Arc<dyn Fn(&Path, &AuditRecord) -> Result<(), AuditWriteError> + Send + Sync>;
/// 通知の出力先の生成関数（隔離した子の中で呼ぶ）。
type NotifyOut = Arc<dyn Fn() -> Box<dyn Write> + Send + Sync>;

/// 未回収の子（SIGKILL 後も回収できなかった D 状態等）を保持する上限。到達したら新規 fork を避ける。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_UNREAPED: usize = 4;

/// 隔離した子プロセスの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum IsolatedOutcome {
    /// 子が終了コード付きで終了した。
    Exited(i32),
    /// 期限内に終わらず SIGKILL した。
    TimedOut,
    /// 呼び出しプロセスが複数スレッドで fork できない。
    MultiThreaded,
    /// fork・待機に失敗した、子がシグナルで死んだ・結果を残さず自動回収された（非対応 OS を含む）。
    Failed,
    /// 子が継承した fd（3 以上）を閉じられず、`child` を実行せずに終わった（`close_range(2)` が無い Linux 5.11
    /// 未満等。[`CLOSE_FDS_FAILED_EXIT`]）。
    FdsNotClosed,
    /// 未回収の子が [`MAX_UNREAPED`] に達しているため fork しなかった（代替経路へ進む）。
    TooManyUnreaped,
}

/// 隔離した子の 1 回分の実行結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Isolated {
    outcome: IsolatedOutcome,
    /// 子が結果 pipe へ「開始」の印（[`START_TAG`]）を書いた。通知の子は出力先へ書き込む直前に書くため、
    /// `false` なら子は出力先へ 1 バイトも書いていない（時間切れの子は SIGKILL 済みで以後も書かない）。
    started: bool,
}

impl Isolated {
    /// 子を作らなかった（fork しなかった・できなかった）結果。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn not_run(outcome: IsolatedOutcome) -> Self {
        Self {
            outcome,
            started: false,
        }
    }
}

/// 結果 pipe の印: 子が「開始」を知らせた（通知の子では出力先へ書き込む直前。続く印は [`RESULT_TAG`]）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const START_TAG: u8 = b'S';
/// 結果 pipe の印: 続く 1 バイトが子の終了コード（`_exit` の直前に 2 バイトを 1 回の write で書く）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RESULT_TAG: u8 = b'R';
/// 結果 pipe から読む上限（開始 1 バイト＋結果 2 バイト）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RESULT_PIPE_MAX: usize = 3;

/// 結果 pipe から読んだバイト列を解釈する。戻り値は `(開始の印があった, 終了コード)`。
///
/// 子の書く順は「[`START_TAG`]（任意）→ [`RESULT_TAG`]＋コード」。未知の値が現れたらそこで読むのをやめ、それ以降の
/// 結果は無いものとする（壊れた値から結果を作らない。終了 status へ退避する）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn decode_result_bytes(bytes: &[u8]) -> (bool, Option<i32>) {
    let mut started = false;
    let mut iter = bytes.iter();
    while let Some(&tag) = iter.next() {
        match tag {
            START_TAG => started = true,
            RESULT_TAG => return (started, iter.next().map(|&code| i32::from(code))),
            _ => break,
        }
    }
    (started, None)
}

/// 隔離した子が `child` の前に fd 3 以上（結果 pipe の書き込み側を除く）を閉じられなかったときの終了コード。
///
/// `close_range(2)`（Linux 5.11 以降。exec の子と同じ前提）が使えないカーネルでは、呼び出し側から継承した fd
/// （`BundleLock`・状態ストアの `@lock` の `flock`、pipe の書き込み端等）を持ったまま I/O しない（fail-closed）。
/// 0（成功）・2（panic）・10 以上（主経路の失敗種別）と重ならない。[`run_isolated`] が
/// [`IsolatedOutcome::FdsNotClosed`] へ写す。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CLOSE_FDS_FAILED_EXIT: i32 = 3;

/// 回収できなかった子の追跡（Linux のみ）。後続の呼び出しで回収を再試行する。
#[cfg(target_os = "linux")]
mod pending {
    use super::{MAX_UNREAPED, sys};
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::Mutex;

    /// 未回収の子 1 件。`pidfd` は fork 直後に開いたもの（開けなければ `None`）。
    struct Unreaped {
        pid: u32,
        pidfd: Option<OwnedFd>,
    }

    static UNREAPED: Mutex<Vec<Unreaped>> = Mutex::new(Vec::new());

    /// 追跡中の子を回収し、まだ残っている件数を返す。
    ///
    /// poison 時は以後ずっと上限到達扱い（[`MAX_UNREAPED`]）になり、プロセスが終わるまで主経路・通知の子を
    /// fork しない（fail-closed。ロック中の処理は panic しないため実際には起きない想定）。
    pub(super) fn reap_and_count() -> usize {
        let Ok(mut list) = UNREAPED.lock() else {
            return MAX_UNREAPED;
        };
        list.retain(still_unreaped);
        list.len()
    }

    /// 子がまだ回収されていなければ `true`。
    ///
    /// pidfd があれば、それが読み取り可能（＝指すプロセスが終了済み）になるまで `waitpid` を呼ばない。終了前の
    /// 子は pid が再利用されないため、終了を確認してからの `waitpid` は自分の子だけを対象にする。`SIGCHLD` が
    /// `SIG_IGN` で自動回収されていれば `ECHILD` になり、回収済みとして外す。pidfd が無い（開けなかった）子は
    /// `waitpid(WNOHANG)` だけで判定する（`ECHILD` 等の失敗は回収済みとみなす）。
    fn still_unreaped(u: &Unreaped) -> bool {
        if let Some(fd) = &u.pidfd
            && matches!(sys::poll_readable(fd.as_fd(), 0), Ok(false))
        {
            return true;
        }
        matches!(sys::wait_pid_nohang(u.pid), Ok(None))
    }

    /// 回収できなかった子を追跡に加える（poison 時は加えない。上の `reap_and_count` が上限到達扱いにする）。
    pub(super) fn track(pid: u32, pidfd: Option<OwnedFd>) {
        if let Ok(mut list) = UNREAPED.lock() {
            list.push(Unreaped { pid, pidfd });
        }
    }
}

/// 子が結果（終了コード 1 バイト）を返す pipe を作る。戻り値は `(読み取り側, 書き込み側)`（両端とも
/// close-on-exec・3 以上の番号）。
///
/// 3 以上へ置く理由: 呼び出しプロセスの fd 0〜2 が閉じていると pipe がその番号を取り、子の
/// `close_range(3, ..)` で残る上に、通知の子が書く stderr（fd 2）と衝突する（`exec::exec_status_pipe` と同じ扱い）。
#[cfg(target_os = "linux")]
fn result_pipe() -> Option<(std::fs::File, std::fs::File)> {
    use std::os::fd::{AsFd, OwnedFd};
    let (reader, writer) = std::io::pipe().ok()?;
    let reader = sys::dup_fd_at_least(OwnedFd::from(reader).as_fd(), 3).ok()?;
    let writer = sys::dup_fd_at_least(OwnedFd::from(writer).as_fd(), 3).ok()?;
    Some((std::fs::File::from(reader), std::fs::File::from(writer)))
}

/// 結果 pipe が今すぐ読めるか（待たない）。シグナルによる中断（`EINTR`）は 1 回だけ再試行する（中断を
/// 「結果なし」と取り違えると、`SIGCHLD` を無視するプロセスで主経路の成功を失敗とみなし代替経路へ二重に
/// 記録するため。SEC-4）。
#[cfg(target_os = "linux")]
fn readable_now(rx: &std::fs::File) -> bool {
    use std::os::fd::AsFd;
    match sys::poll_readable(rx.as_fd(), 0) {
        Ok(ready) => ready,
        Err(sys::SysError::Os(e)) if e == sys::EINTR => {
            matches!(sys::poll_readable(rx.as_fd(), 0), Ok(true))
        }
        Err(_) => false,
    }
}

/// 結果 pipe に残っている印を読んで解釈する（[`decode_result_bytes`]）。待たない。
///
/// 読む前に毎回 [`readable_now`] を確かめるため、D 状態の子が書き込み側を持ったまま残っていても止まらない。
/// `read` の `EINTR` も 1 回だけ再試行する。
#[cfg(target_os = "linux")]
fn read_result(rx: &std::fs::File) -> (bool, Option<i32>) {
    use std::io::Read as _;
    let mut buf = [0u8; RESULT_PIPE_MAX];
    let mut len = 0;
    while len < buf.len() && readable_now(rx) {
        let Some(rest) = buf.get_mut(len..) else {
            break;
        };
        let mut reader = rx;
        let n = match reader.read(rest) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => reader.read(rest),
            other => other,
        };
        match n {
            Ok(n) if n > 0 => len += n,
            _ => break,
        }
    }
    decode_result_bytes(buf.get(..len).unwrap_or_default())
}

/// 子の結果を確定する。結果 pipe に子が残したコードがあれば最優先する（`child` の処理を終えた後にだけ書くため、
/// 例えば主経路の `sync_data` まで完了している）。無ければ `otherwise`（`waitpid` の status 等）を使う。
/// [`CLOSE_FDS_FAILED_EXIT`] は [`IsolatedOutcome::FdsNotClosed`] へ写す。
#[cfg(target_os = "linux")]
fn settle(rx: &std::fs::File, otherwise: IsolatedOutcome) -> Isolated {
    let (started, code) = read_result(rx);
    let outcome = match code.map_or(otherwise, IsolatedOutcome::Exited) {
        IsolatedOutcome::Exited(CLOSE_FDS_FAILED_EXIT) => IsolatedOutcome::FdsNotClosed,
        other => other,
    };
    Isolated { outcome, started }
}

/// `child` を fork した子プロセスで実行し、`timeout` まで終了を待つ（REPAIR-5）。`child` に渡す関数を呼ぶと
/// 結果 pipe へ「開始」の印を書く（通知の子が出力先へ書き込む直前に呼ぶ。主経路は呼ばない）。
///
/// 親にはスレッドも fd も残さない。子は `_exit` するため、終了コードは 0〜255。panic は 2。
/// fork 前に親で stdio を flush しない（出力先が詰まると期限前に停止するため。
/// `sys::fork_single_threaded_no_flush`）。期限超過は SIGKILL して回収を [`KILL_REAP_WAIT`] まで待ち、
/// それでも回収できなければ追跡して後続の呼び出しで回収する。未回収が [`MAX_UNREAPED`] 件に
/// 達していれば fork せず [`IsolatedOutcome::TooManyUnreaped`]（ゾンビの無制限な蓄積を防ぐ）。
///
/// - **継承 fd**: 子は `child` の前に fd 3 以上を結果 pipe の書き込み側だけ残して閉じる（`close_range`。
///   SIGKILL が効かない D 状態の子が、呼び出し側の `flock`・pipe の書き込み端を持ち続けないため）。閉じられなければ
///   `child` を実行せず [`CLOSE_FDS_FAILED_EXIT`] で終わる
/// - **結果の受け渡し**: 子は `child` の戻り値（fd を閉じられなければ [`CLOSE_FDS_FAILED_EXIT`]）を結果 pipe へ
///   印付きで書いてから `_exit` する。`SIGCHLD` が
///   `SIG_IGN`・`SA_NOCLDWAIT` のプロセスでは子が自動回収されて `waitpid` が `ECHILD` を返し status が失われるが、
///   pipe の値で結果を確定する（主経路の成功を失敗と取り違えて代替経路へ二重に記録しない）
/// - **シグナル**: fork 直後（回収前）に開いた pidfd があれば `pidfd_send_signal` で送る（回収後に pid が
///   再利用されても別プロセスへ届かない。`exec::ContainerChild` と同じ作法）。pidfd が無ければ、直前の
///   `waitpid(WNOHANG)` が未回収（`Ok(None)`）を返したときだけ `kill(2)` する。`waitpid` が `ECHILD`（自動回収・
///   他の回収者）・その他の失敗を返したときは、pidfd の有無によらず送らない（追跡して後続の呼び出しで回収する）。
///   pidfd 経由で送るのも、`pidfd_open` の後に `waitpid(WNOHANG)` が未回収（`Ok(None)`）を返した後だけ
/// - **残余のリスク（CORE-1）**: `SIGCHLD` を無視するプロセスでは、(1) pidfd が無いとき、確認から `kill` までの
///   間に子が終了・自動回収され pid が再利用される窓が残る。(2) fork から `pidfd_open` までの間に子が終了・
///   自動回収され pid が再利用されると、pidfd は別プロセスを指し得る。シグナルは `Ok(None)` を確かめた後だけ
///   送るためこの pidfd へは送らないが、想定外の `waitpid` の失敗で追跡に載ると、そのプロセスが終わるまで
///   未回収の 1 件として数える（fail-closed の向き）。いずれも pid の一巡が要る。根本対策は
///   `clone3(CLONE_PIDFD)` で fork と同時に pidfd を得ること（未実装）
#[cfg(target_os = "linux")]
fn run_isolated(timeout: Duration, child: impl FnOnce(&dyn Fn()) -> i32) -> Isolated {
    use std::io::Write as _;
    use std::os::fd::AsFd;
    if pending::reap_and_count() >= MAX_UNREAPED {
        return Isolated::not_run(IsolatedOutcome::TooManyUnreaped);
    }
    let Some((rx, tx)) = result_pipe() else {
        return Isolated::not_run(IsolatedOutcome::Failed);
    };
    let forked = sys::fork_single_threaded_no_flush(
        || {
            // 継承した fd を、結果 pipe の書き込み側を除いて閉じる（fd 0〜2 は残す。通知の子は fd 2 だけ使う）。
            let code = if sys::close_fds_from_except(3, tx.as_fd()).is_err() {
                CLOSE_FDS_FAILED_EXIT
            } else {
                // 印は合計 3 バイトで pipe は空から始まるため、どの write も待たされない（ヒープも使わない）。
                child(&|| {
                    let _ = (&tx).write_all(&[START_TAG]);
                })
            };
            // 失敗しても `_exit` の status が残る。
            let byte = u8::try_from(code).unwrap_or(u8::MAX);
            let _ = (&tx).write_all(&[RESULT_TAG, byte]);
            code
        },
        2,
    );
    // 書き込み側は子だけが持つ（子の終了で EOF になる）。
    drop(tx);
    let pid = match forked {
        Ok(pid) => pid,
        Err(sys::SysError::MultiThreaded) => {
            return Isolated::not_run(IsolatedOutcome::MultiThreaded);
        }
        Err(_) => return Isolated::not_run(IsolatedOutcome::Failed),
    };
    // 回収前に開くので、以後 pid が回収・再利用されても元の子を指す。開けなければ `None`（kill(2) へ退避）。
    let pidfd = sys::pidfd_open(pid).ok();
    let deadline = Instant::now() + timeout;
    loop {
        match sys::wait_pid_nohang(pid) {
            Ok(Some(status)) => return settle(&rx, decode_status(status)),
            Ok(None) => {}
            Err(sys::SysError::Os(e)) if e == sys::ECHILD => {
                // 自動回収（`SIGCHLD` の `SIG_IGN`・`SA_NOCLDWAIT`）か他の回収者。終了済みなので kill しない。
                return settle(&rx, IsolatedOutcome::Failed);
            }
            Err(_) => {
                // 想定外の失敗（`WNOHANG` では `EINTR` にならず、実際には到達しない）。`Ok(None)` を確かめる前は
                // pidfd が自分の子を指すとは限らない（fork から `pidfd_open` までに自動回収・pid 再利用が起き得る）
                // ため、pidfd へも生の pid へも送らず、追跡して後続の呼び出しで回収する。
                pending::track(pid, pidfd);
                return settle(&rx, IsolatedOutcome::Failed);
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    // 期限超過。pidfd 経由で送る。無ければ未回収の自分の子であることを確かめてから kill(2) する。
    match &pidfd {
        Some(fd) => {
            let _ = sys::pidfd_send_signal(fd.as_fd(), sys::Signal::Kill);
        }
        None => match sys::wait_pid_nohang(pid) {
            Ok(None) => {
                let _ = sys::kill_pid(pid, sys::Signal::Kill);
            }
            Ok(Some(status)) => return settle(&rx, decode_status(status)),
            Err(_) => return settle(&rx, IsolatedOutcome::TimedOut),
        },
    }
    let reap_deadline = Instant::now() + KILL_REAP_WAIT;
    while Instant::now() < reap_deadline {
        if !matches!(sys::wait_pid_nohang(pid), Ok(None)) {
            return settle(&rx, IsolatedOutcome::TimedOut);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    // SIGKILL でも回収できない子（D 状態等）。追跡して後続の呼び出しで回収する。
    pending::track(pid, pidfd);
    settle(&rx, IsolatedOutcome::TimedOut)
}

/// 非 Linux では子プロセス隔離を提供しない（`crate::sys` が Linux 専用。CLI-1）。常に `Failed` を返し、
/// 呼び出し側は主経路を `IsolationUnavailable` として代替経路へ進む。
#[cfg(not(target_os = "linux"))]
fn run_isolated(_timeout: Duration, _child: impl FnOnce(&dyn Fn()) -> i32) -> Isolated {
    Isolated::not_run(IsolatedOutcome::Failed)
}

/// `waitpid` の status を解釈する。正常終了以外（シグナル死）は `Failed`。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn decode_status(status: i32) -> IsolatedOutcome {
    if status & 0x7f == 0 {
        IsolatedOutcome::Exited((status >> 8) & 0xff)
    } else {
        IsolatedOutcome::Failed
    }
}

/// 子が終了コードで返せる主経路の失敗種別（コード = 添字 + [`KIND_EXIT_BASE`]）。範囲外は `Write` として扱う。
const PRIMARY_KINDS: [AuditWriteErrorKind; 11] = [
    AuditWriteErrorKind::RelativePath,
    AuditWriteErrorKind::Unsupported,
    AuditWriteErrorKind::NotRegularFile,
    AuditWriteErrorKind::InsecureFile,
    AuditWriteErrorKind::Open,
    AuditWriteErrorKind::Encode,
    AuditWriteErrorKind::LineTooLong,
    AuditWriteErrorKind::Write,
    AuditWriteErrorKind::Lock,
    AuditWriteErrorKind::LockFailed,
    AuditWriteErrorKind::Sync,
];
/// 失敗種別の終了コードの起点（0 は成功、2 は子の panic に使うため 10 から）。
const KIND_EXIT_BASE: i32 = 10;
/// `PRIMARY_KINDS` 内の `Write` の添字（未知の種別の既定）。
const WRITE_INDEX: usize = 7;

fn kind_to_exit(kind: AuditWriteErrorKind) -> i32 {
    let idx = PRIMARY_KINDS
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(WRITE_INDEX);
    KIND_EXIT_BASE + i32::try_from(idx).unwrap_or(0)
}

fn exit_to_kind(code: i32) -> AuditWriteErrorKind {
    usize::try_from(code - KIND_EXIT_BASE)
        .ok()
        .and_then(|i| PRIMARY_KINDS.get(i).copied())
        .unwrap_or(AuditWriteErrorKind::Write)
}

/// 主経路を隔離した子の結果を、主経路の成否と失敗種別へ写す。
fn primary_result(outcome: IsolatedOutcome) -> Result<(), AuditWriteError> {
    let kind = match outcome {
        IsolatedOutcome::Exited(0) => return Ok(()),
        IsolatedOutcome::Exited(code) => exit_to_kind(code),
        IsolatedOutcome::TimedOut => AuditWriteErrorKind::IsolationTimeout,
        IsolatedOutcome::FdsNotClosed => AuditWriteErrorKind::IsolationFdsNotClosed,
        IsolatedOutcome::MultiThreaded
        | IsolatedOutcome::Failed
        | IsolatedOutcome::TooManyUnreaped => AuditWriteErrorKind::IsolationUnavailable,
    };
    Err(AuditWriteError::new(kind))
}

/// 主経路の既定の 1 回分: パスを検査付きで開いて 1 件追記する。
fn default_primary_step(path: &Path, record: &AuditRecord) -> Result<(), AuditWriteError> {
    AuditFileWriter::open(path)?.write_record(record)
}

/// 主経路をどこで実行するか。
#[derive(Clone, Copy)]
enum Isolation {
    /// fork した子プロセス。`timeout` で SIGKILL する（本番）。
    Process { timeout: Duration },
    /// 呼び出しスレッドで直接実行する（libtest のように複数スレッドで fork できないユニットテスト専用）。
    #[cfg(test)]
    InProcess,
}

/// 通知の子が出力先への書き込み・flush に失敗したときの終了コード（親は短命スレッドで出し直す）。
const NOTIFY_WRITE_FAILED_EXIT: i32 = 1;

/// 子での通知の結果を受けて、短命スレッドで出し直すかどうか（[`notify_retry`] の戻り値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyRetry {
    /// 出し直さない。
    Skip,
    /// 1 行をそのまま出す（子は出力先へ何も書いていない）。
    Line,
    /// 改行を 1 つ付けてから 1 行を出す（子が途中まで書いた断片と連結しないため。REPAIR-4）。
    AfterNewline,
}

/// 子プロセスでの通知が 1 行を出せたと確認できなかったとき、短命スレッドで出し直すかどうか
/// （SEC-4・REPAIR-4・REPAIR-5）。
///
/// - 出し直す: fork できない（複数スレッド・fork 失敗・未回収の子が上限）、子がシグナルで死んだ・継承 fd を
///   閉じられなかった・書き込みに失敗した・panic した（`Exited(0)` 以外の終了）、書き込みに達する前に時間切れに
///   なった（「開始」の印が無い `TimedOut`。負荷で子の実行が遅れた等）。いずれも 1 行が出ていない（または出たか
///   分からない）ため、`AuditDelivery::SinkFailed` を受けた呼び出し側が出さない契約の下で通知が欠けないよう、
///   上限付きのスレッド経路で出す。子が書き込みを始めていた（「開始」の印がある）ときは先頭に改行を付ける
/// - 出し直さない: `Exited(0)`（出せた）と、書き込みを始めた後の `TimedOut`（出力先が [`NOTIFY_WAIT`] を超えて
///   詰まっている。スレッドで出し直しても同じ出力先で詰まってスレッドが残り、以後の exec の fork を妨げるだけ
///   なので出さない。部分的に書かれた行の二重出力も避ける）
fn notify_retry(run: Isolated) -> NotifyRetry {
    match run.outcome {
        IsolatedOutcome::Exited(0) => NotifyRetry::Skip,
        IsolatedOutcome::TimedOut if run.started => NotifyRetry::Skip,
        IsolatedOutcome::TimedOut => NotifyRetry::Line,
        IsolatedOutcome::Exited(_)
        | IsolatedOutcome::MultiThreaded
        | IsolatedOutcome::Failed
        | IsolatedOutcome::FdsNotClosed
        | IsolatedOutcome::TooManyUnreaped => {
            if run.started {
                NotifyRetry::AfterNewline
            } else {
                NotifyRetry::Line
            }
        }
    }
}

/// 通知を子プロセスで出す通知器を作る。子で出せたと確認できなければ短命スレッドで出し直す（[`notify_retry`]）。
///
/// 子での出力は、出力先の生成・書き込みをすべて子の中で行うため、出力先が詰まっても親にスレッドは残らない。
/// 子は出力先を作った後、書き込みの直前に「開始」の印を書く。
/// **限界（fail-closed）**: スレッドでの出し直しは、出力先が詰まっているとそのスレッドが残る（未完了
/// [`NOTIFY_QUEUE_CAP`] 件で頭打ち。超えた通知は捨てる）。単一スレッドだったプロセスはそれ以後 fork できず、
/// 以後の exec の worker 生成は拒否される（拒否の向きに倒れる）。
fn isolated_notifier(out: NotifyOut, wait: Duration) -> FailureNotifier {
    let threaded = {
        let out = Arc::clone(&out);
        thread_line_emitter(move || out(), NOTIFY_QUEUE_CAP, wait)
    };
    Arc::new(move |failure| {
        let mut line = Vec::new();
        if failure.write_json_line(&mut line).is_err() {
            return;
        }
        let run = run_isolated(wait, |mark_started| {
            let mut sink = out();
            mark_started();
            match sink.write_all(&line).and_then(|()| sink.flush()) {
                Ok(()) => 0,
                Err(_) => NOTIFY_WRITE_FAILED_EXIT,
            }
        });
        match notify_retry(run) {
            NotifyRetry::Skip => {}
            NotifyRetry::Line => threaded(line),
            NotifyRetry::AfterNewline => {
                let mut separated = Vec::with_capacity(line.len().saturating_add(1));
                separated.push(b'\n');
                separated.extend_from_slice(&line);
                threaded(separated);
            }
        }
    })
}

/// 書き込み時に毎回 stderr をロックする `Write`（ロック取得も通知側で行う）。
struct StderrLine;

impl Write for StderrLine {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().lock().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().lock().flush()
    }
}

/// 符号化済みの通知（1 行分のバイト列）を出す関数。
type LineEmitter = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// 呼び出しプロセスの現在のスレッド数（Linux 以外は数えない）。
fn current_threads() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        sys::current_thread_count()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// join したスレッドが数から消えるのを、スレッド数が `baseline`（起動前の数）以下に戻るか
/// [`NOTIFY_THREAD_EXIT_WAIT`] が過ぎるまで待つ（REPAIR-5・SUP-6）。
///
/// 起動前の数を基準にするのは、複数スレッドのプロセス（libtest 等）では 1 に戻らないため。数えられなければ
/// 待たない。上限を超えても失敗にはしない（続く fork が `MultiThreaded` で拒否される fail-closed の向き）。
fn wait_thread_released(baseline: Option<u64>) {
    let Some(baseline) = baseline else {
        return;
    };
    let deadline = Instant::now() + NOTIFY_THREAD_EXIT_WAIT;
    while current_threads().is_some_and(|n| n > baseline) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// 出力先を生成する関数から、非同期・有限待ちの短命スレッドで 1 行を出す関数を作る（子で出せたと確認できな
/// かった通知の出し直し。[`isolated_notifier`] が [`notify_retry`] の条件で呼ぶ。単一スレッドのプロセスでも使う）。
///
/// 生成時にはスレッドを起動しない（遅延起動）。未完了スレッドが `cap` 件に達していれば通知を捨てる。完了を
/// `wait` 以内に確認できたら join し、スレッド数が戻るのを待つ（[`wait_thread_released`]）。
/// **限界**: 出力先が詰まり続けるとそのスレッドは残る（以後の fork は拒否される。fail-closed）。
fn thread_line_emitter(
    make: impl Fn() -> Box<dyn Write> + Send + Sync + 'static,
    cap: usize,
    wait: Duration,
) -> LineEmitter {
    let make = Arc::new(make);
    let in_flight = Arc::new(AtomicUsize::new(0));
    Arc::new(move |line: Vec<u8>| {
        // 満杯なら待たずに捨てる。
        if in_flight.fetch_add(1, Ordering::AcqRel) >= cap {
            in_flight.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(1);
        let make = Arc::clone(&make);
        let counter = Arc::clone(&in_flight);
        let baseline = current_threads();
        let spawned = std::thread::Builder::new()
            .name("audit-notify".into())
            .spawn(move || {
                let mut out = make();
                // 書き込み失敗は握りつぶす（拒否経路を止めない）。
                let _ = out.write_all(&line);
                let _ = out.flush();
                counter.fetch_sub(1, Ordering::AcqRel);
                let _ = ack_tx.try_send(());
            });
        match spawned {
            Ok(handle) => {
                // 完了を確認できたら join してスレッドを確実に消す。時間切れなら切り離す。
                if ack_rx.recv_timeout(wait).is_ok() {
                    let _ = handle.join();
                    wait_thread_released(baseline);
                }
            }
            Err(_) => {
                in_flight.fetch_sub(1, Ordering::AcqRel);
            }
        }
    })
}

/// [`thread_line_emitter`] に符号化を足した通知器（ユニットテスト用。本番は [`isolated_notifier`] が使う）。
#[cfg(test)]
fn notifier_to(
    make: impl Fn() -> Box<dyn Write> + Send + Sync + 'static,
    cap: usize,
    wait: Duration,
) -> FailureNotifier {
    let emit = thread_line_emitter(make, cap, wait);
    Arc::new(move |failure| {
        let mut line = Vec::new();
        if failure.write_json_line(&mut line).is_ok() {
            emit(line);
        }
    })
}

/// ファイル（主経路）＋カーネル監査（代替経路）の本番 [`AuditSink`]。
pub struct FileAuditSink {
    path: PathBuf,
    primary: PrimaryStep,
    isolation: Isolation,
    fallback: FallbackFactory,
    notify: FailureNotifier,
}

impl FileAuditSink {
    /// open 済みの状態ストアの正規化済みルート直下 `@audit.log` を主経路とする本番 sink を作る。
    ///
    /// 呼び出し元: supervisor の `exec::default_audit_sink`。ファイルはここでは開かない（`record` ごとに、
    /// fork した子プロセスで開く）。
    pub fn in_state_store(store: &FileStateStore) -> Self {
        Self {
            path: store.root().join(AUDIT_LOG_FILE_NAME),
            primary: Arc::new(default_primary_step),
            isolation: Isolation::Process {
                timeout: PRIMARY_WRITE_TIMEOUT,
            },
            fallback: Arc::new(|| Box::new(KernelAuditFallback::new())),
            notify: isolated_notifier(Arc::new(|| Box::new(StderrLine)), NOTIFY_WAIT),
        }
    }

    /// 結合試験専用: 主経路の 1 回分・待ち上限・代替経路・通知の出力先を差し込む。隔離は本番と同じ
    /// 子プロセス方式（`tests/audit_sink_isolation.rs`。REPAIR-5・SEC-4・TASK-163）。
    #[cfg(feature = "exec-test-support")]
    #[doc(hidden)]
    pub fn isolated_for_test(
        path: PathBuf,
        primary: PrimaryStep,
        primary_timeout: Duration,
        fallback: FallbackFactory,
        notify_out: NotifyOut,
        notify_wait: Duration,
    ) -> Self {
        Self {
            path,
            primary,
            isolation: Isolation::Process {
                timeout: primary_timeout,
            },
            fallback,
            notify: isolated_notifier(notify_out, notify_wait),
        }
    }

    /// 結合試験専用: 入力を閉じるまで読み続けて待つ子を [`MAX_UNREAPED`] 件 fork し、未回収の子として追跡に
    /// 加える（未回収が上限に達した状態の再現。`tests/audit_sink_isolation.rs`。SEC-4・REPAIR-5・#1594）。
    ///
    /// 戻り値（子の入力 pipe の書き込み側）を drop すると子は EOF で終了し、後続の呼び出しで回収される。
    /// 作れなかった場合は `None`（作った分は追跡に残り、戻り値が無いため終了しない子は無い: 子は pipe を
    /// 閉じられなければ直ちに終了する）。
    #[cfg(all(target_os = "linux", feature = "exec-test-support"))]
    #[doc(hidden)]
    pub fn hold_unreaped_children_for_test() -> Option<std::fs::File> {
        use std::io::Read as _;
        use std::os::fd::AsFd;
        let (rx, tx) = result_pipe()?;
        for _ in 0..MAX_UNREAPED {
            let pid = sys::fork_single_threaded_no_flush(
                || {
                    if sys::close_fds_from_except(3, rx.as_fd()).is_err() {
                        return 1;
                    }
                    let mut byte = [0u8; 1];
                    let mut reader = &rx;
                    while matches!(reader.read(&mut byte), Ok(n) if n > 0) {}
                    0
                },
                2,
            )
            .ok()?;
            pending::track(pid, sys::pidfd_open(pid).ok());
        }
        Some(tx)
    }

    /// 結合試験専用: 追跡中の未回収の子を回収し、残っている件数を返す。
    #[cfg(all(target_os = "linux", feature = "exec-test-support"))]
    #[doc(hidden)]
    pub fn unreaped_children_for_test() -> usize {
        pending::reap_and_count()
    }

    /// 結合試験専用: 自プロセスの `SIGCHLD` を `ignored` なら `SIG_IGN`、そうでなければ `SIG_DFL` にする
    /// （子が自動回収されるプロセスでの照合用）。成功なら `true`。
    #[cfg(all(target_os = "linux", feature = "exec-test-support"))]
    #[doc(hidden)]
    pub fn set_child_signal_ignored_for_test(ignored: bool) -> bool {
        sys::set_child_signal_ignored_for_test(ignored).is_ok()
    }

    /// テスト用: 主経路パス・代替経路・通知先を差し込む（呼び出しスレッドで直接実行）。
    #[cfg(test)]
    pub(crate) fn with_parts(
        path: PathBuf,
        fallback: FallbackFactory,
        notify: FailureNotifier,
    ) -> Self {
        Self {
            path,
            primary: Arc::new(default_primary_step),
            isolation: Isolation::InProcess,
            fallback,
            notify,
        }
    }

    /// 主経路を 1 回試す。隔離した子の結果（終了コード・時間切れ・fork 不能）を主経路の失敗へ写す。
    fn write_primary(&self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        match self.isolation {
            #[cfg(test)]
            Isolation::InProcess => (self.primary)(&self.path, record),
            Isolation::Process { timeout } => {
                let run = run_isolated(timeout, |_| match (self.primary)(&self.path, record) {
                    Ok(()) => 0,
                    Err(e) => kind_to_exit(e.kind()),
                });
                primary_result(run.outcome)
            }
        }
    }
}

impl fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAuditSink").finish_non_exhaustive()
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let primary = match self.write_primary(record) {
            Ok(()) => return Ok(()),
            Err(primary) => primary,
        };
        // 主経路の失敗（open・時間切れ・隔離不能を含む）は代替経路へ回す。代替経路はストレージに触れない。
        let mut fallback = (self.fallback)();
        let failure = match fallback.record_fallback(record, &primary) {
            Ok(()) => return Ok(()),
            Err(fb) => AuditWriteFailure::new(primary, fb),
        };
        (self.notify)(&failure);
        Err(TraitError::new(failure.error_code(), failure.message()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{
        AuditDelivery, AuditEvent, AuditPid, AuditReason, AuditTimestamp, AuditWriteError,
        AuditWriteErrorKind, NoAuditFallback, record_mount_rejection,
    };
    use crate::traits::ErrorCode;
    use std::sync::Mutex;

    fn sample() -> AuditRecord {
        AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_not_nested_pid1"),
            },
        )
    }

    struct Rec {
        calls: Arc<Mutex<Vec<AuditWriteErrorKind>>>,
        ok: bool,
    }

    impl AuditFallback for Rec {
        fn record_fallback(
            &mut self,
            _r: &AuditRecord,
            primary: &AuditWriteError,
        ) -> Result<(), AuditWriteError> {
            self.calls.lock().unwrap().push(primary.kind());
            if self.ok {
                Ok(())
            } else {
                Err(AuditWriteError::fallback_unavailable())
            }
        }
    }

    fn missing_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("fandhe-auditsink-missing-{}", std::process::id()))
            .join("nodir")
            .join(AUDIT_LOG_FILE_NAME)
    }

    type Notes = Arc<Mutex<Vec<u8>>>;
    type Calls = Arc<Mutex<Vec<AuditWriteErrorKind>>>;

    fn sink_with(path: PathBuf, ok: bool) -> (FileAuditSink, Calls, Notes) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let notes: Notes = Arc::new(Mutex::new(Vec::new()));
        let c = calls.clone();
        let n = notes.clone();
        let sink = FileAuditSink::with_parts(
            path,
            Arc::new(move || {
                Box::new(Rec {
                    calls: c.clone(),
                    ok,
                })
            }),
            Arc::new(move |f| {
                let mut g = n.lock().unwrap();
                f.write_json_line(&mut *g).unwrap();
            }),
        );
        (sink, calls, notes)
    }

    fn primary_kind() -> AuditWriteErrorKind {
        if cfg!(target_os = "linux") {
            AuditWriteErrorKind::Open
        } else {
            AuditWriteErrorKind::Unsupported
        }
    }

    /// SEC-4・SUP-6・TASK-163: 主経路が失敗すると代替経路へ 1 回だけ回り、成功を返す。
    #[test]
    fn sec4_task163_primary_failure_goes_to_fallback() {
        let (sink, calls, notes) = sink_with(missing_path(), true);
        sink.record(&sample()).unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![primary_kind()]);
        assert!(notes.lock().unwrap().is_empty());
    }

    /// SEC-4・SUP-6・TASK-163: 両経路失敗は固定スキーマ 1 行を通知し INTERNAL を返す。
    #[test]
    fn sec4_task163_both_fail_notifies_fixed_line_and_errors() {
        let (sink, _calls, notes) = sink_with(missing_path(), false);
        let e = sink.record(&sample()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(
            e.message(),
            "audit record could not be persisted by primary or fallback path"
        );
        let (p, pc) = if cfg!(target_os = "linux") {
            ("open", "INTERNAL")
        } else {
            ("unsupported", "UNIMPLEMENTED")
        };
        let expect = format!(
            "{{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"{p}\",\"primary_code\":\"{pc}\",\"fallback\":\"fallback_unavailable\",\"fallback_code\":\"UNIMPLEMENTED\"}}\n"
        );
        assert_eq!(
            String::from_utf8(notes.lock().unwrap().clone()).unwrap(),
            expect
        );
    }

    /// SEC-4・SUP-6・TASK-163: 両経路失敗でも mount 拒否の判定は覆らない。
    #[test]
    fn sec4_task163_both_fail_keeps_rejection() {
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, Arc::new(|_| {}));
        let r = record_mount_rejection("denied", None, &sink);
        assert_eq!(r.error, "denied");
        assert!(matches!(
            r.delivery,
            AuditDelivery::SinkFailed(ref e) if e.code() == ErrorCode::Internal
        ));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::audit_log::encode_json_line;
        use crate::state_store::StateRoot;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn fresh_dir(tag: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("fandhe-auditsink-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        fn open_store(dir: &std::path::Path) -> FileStateStore {
            FileStateStore::open(StateRoot::from_override(dir.join("root")).unwrap()).unwrap()
        }

        /// SEC-4・SUP-6・TASK-163: 拒否 1 件がファイルへ 1 行記録される。
        #[test]
        fn sec4_task163_production_sink_writes_one_line() {
            let dir = fresh_dir("one");
            let store = open_store(&dir);
            let (sink, _calls, _notes) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), false);
            sink.record(&sample()).unwrap();
            let text = std::fs::read_to_string(store.root().join(AUDIT_LOG_FILE_NAME)).unwrap();
            let expect = String::from_utf8(encode_json_line(&sample()).unwrap()).unwrap();
            assert_eq!(text, expect);
            assert_eq!(text.lines().count(), 1);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// SEC-4・TASK-163: symlink の @audit.log は主経路で拒否され代替経路へ回る。
        #[test]
        fn sec4_task163_symlinked_log_goes_to_fallback() {
            let dir = fresh_dir("sym");
            let store = open_store(&dir);
            let target = dir.join("target");
            std::fs::write(&target, b"").unwrap();
            symlink(&target, store.root().join(AUDIT_LOG_FILE_NAME)).unwrap();
            let (sink, calls, _n) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), true);
            sink.record(&sample()).unwrap();
            assert_eq!(*calls.lock().unwrap(), vec![AuditWriteErrorKind::Open]);
            assert_eq!(std::fs::read(&target).unwrap(), b"");
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// OCI-5: sink が @audit.log を作った後でも、ストアの再 open で @revision が保たれる。
        #[test]
        fn oci5_task163_audit_log_does_not_break_store_reopen() {
            let dir = fresh_dir("reopen");
            let store = open_store(&dir);
            let (sink, _calls, _notes) = sink_with(store.root().join(AUDIT_LOG_FILE_NAME), false);
            sink.record(&sample()).unwrap();
            let rev = std::fs::read(store.root().join("@revision")).unwrap();
            let again = open_store(&dir);
            assert_eq!(std::fs::read(again.root().join("@revision")).unwrap(), rev);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 書き込みが戻らない出力先（満杯パイプ相当）。
    struct Stuck(Arc<Mutex<mpsc::Receiver<()>>>);

    impl Write for Stuck {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.lock().map(|r| r.recv());
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// REPAIR-5・SEC-4・TASK-163: 通知先が無期限に詰まっても `record` は上限時間内に拒否結果を返す。
    #[test]
    fn repair5_task163_stuck_notifier_does_not_block_record() {
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        let hold_rx = Arc::new(Mutex::new(hold_rx));
        let notify = notifier_to(
            move || Box::new(Stuck(Arc::clone(&hold_rx))),
            2,
            Duration::from_millis(50),
        );
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, notify);
        let start = Instant::now();
        // キュー上限を超える回数を呼んでも、各呼び出しが有限時間で戻る。
        for _ in 0..6 {
            let e = sink.record(&sample()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Internal);
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        drop(hold_tx);
    }

    /// REPAIR-5・SEC-4・TASK-163: 隔離した子の終了コードと主経路の失敗種別が往復し、未知のコードは `Write`。
    #[test]
    fn repair5_task163_primary_kind_exit_code_roundtrip() {
        for kind in PRIMARY_KINDS {
            assert_eq!(exit_to_kind(kind_to_exit(kind)), kind);
        }
        assert_eq!(kind_to_exit(AuditWriteErrorKind::Open), 14);
        assert_eq!(exit_to_kind(255), AuditWriteErrorKind::Write);
        assert_eq!(exit_to_kind(2), AuditWriteErrorKind::Write);
        assert_eq!(
            kind_to_exit(AuditWriteErrorKind::IsolationTimeout),
            KIND_EXIT_BASE + 7
        );
    }

    /// SEC-4・REPAIR-4・REPAIR-5・#1594・#1616: 子で通知を出せたと確認できない結果はすべてスレッドで出し直し、
    /// 出せた（`Exited(0)`）・書き込みを始めた後に詰まった（開始の印がある `TimedOut`）ときだけ出し直さない。
    /// 子が書き込みを始めていれば改行を付けてから出す。
    #[test]
    fn sec4_1616_notify_retry_covers_every_undelivered_outcome() {
        use IsolatedOutcome as O;
        use NotifyRetry as R;
        let cases = [
            (O::Exited(0), true, R::Skip),
            (O::Exited(NOTIFY_WRITE_FAILED_EXIT), true, R::AfterNewline),
            (O::Exited(NOTIFY_WRITE_FAILED_EXIT), false, R::Line),
            (O::Exited(2), true, R::AfterNewline),
            (O::Exited(2), false, R::Line),
            (O::Exited(255), false, R::Line),
            (O::TimedOut, true, R::Skip),
            (O::TimedOut, false, R::Line),
            (O::MultiThreaded, false, R::Line),
            (O::Failed, false, R::Line),
            (O::Failed, true, R::AfterNewline),
            (O::FdsNotClosed, false, R::Line),
            (O::TooManyUnreaped, false, R::Line),
        ];
        for (outcome, started, retry) in cases {
            let run = Isolated { outcome, started };
            assert_eq!(notify_retry(run), retry, "{run:?}");
        }
    }

    /// SEC-4・REPAIR-4・#1616: 結果 pipe の印（開始・結果）を解釈し、壊れた値から結果を作らない。
    #[test]
    fn sec4_1616_result_pipe_bytes_are_decoded_by_tag() {
        type Decoded = (bool, Option<i32>);
        let cases: [(&[u8], Decoded); 8] = [
            (b"", (false, None)),
            (b"S", (true, None)),
            (b"R\x00", (false, Some(0))),
            (b"SR\x01", (true, Some(1))),
            (&[RESULT_TAG, 3], (false, Some(3))),
            (b"R", (false, None)),
            (b"X R\x00", (false, None)),
            (b"SX", (true, None)),
        ];
        for (bytes, expect) in cases {
            assert_eq!(decode_result_bytes(bytes), expect, "{bytes:?}");
        }
    }

    /// SEC-4・REPAIR-3・REPAIR-5・#1616: 隔離した子の結果を主経路の失敗種別へ写す。fd を閉じられない子は
    /// fork 不能（`isolation_unavailable`）と別の `isolation_fds_not_closed`（`UNAVAILABLE`）になる。
    #[test]
    fn sec4_1616_primary_result_maps_each_outcome() {
        use IsolatedOutcome as O;
        assert_eq!(primary_result(O::Exited(0)), Ok(()));
        let kind = |o| primary_result(o).unwrap_err().kind();
        assert_eq!(kind(O::Exited(14)), AuditWriteErrorKind::Open);
        assert_eq!(kind(O::Exited(2)), AuditWriteErrorKind::Write);
        assert_eq!(kind(O::TimedOut), AuditWriteErrorKind::IsolationTimeout);
        assert_eq!(
            kind(O::MultiThreaded),
            AuditWriteErrorKind::IsolationUnavailable
        );
        assert_eq!(kind(O::Failed), AuditWriteErrorKind::IsolationUnavailable);
        assert_eq!(
            kind(O::TooManyUnreaped),
            AuditWriteErrorKind::IsolationUnavailable
        );
        let fds = primary_result(O::FdsNotClosed).unwrap_err();
        assert_eq!(fds.kind(), AuditWriteErrorKind::IsolationFdsNotClosed);
        assert_eq!(fds.kind().as_str(), "isolation_fds_not_closed");
        assert_eq!(fds.error_code(), ErrorCode::Unavailable);
        assert_eq!(
            fds.message(),
            "isolated audit log writer could not close inherited file descriptors"
        );
    }

    /// REPAIR-5・#1616: 1 回の `record` の待ち時間の上限は、各経路の上限の合算（11.45 秒）。
    #[test]
    fn repair5_1616_record_wait_limit_is_the_sum_of_each_limit() {
        assert_eq!(RECORD_WAIT_LIMIT, Duration::from_millis(11_450));
    }

    /// REPAIR-5・TASK-163: `waitpid` の status は正常終了だけ終了コードに、シグナル死は `Failed`。
    #[test]
    fn repair5_task163_decode_status() {
        assert_eq!(decode_status(0), IsolatedOutcome::Exited(0));
        assert_eq!(decode_status(14 << 8), IsolatedOutcome::Exited(14));
        assert_eq!(decode_status(9), IsolatedOutcome::Failed);
    }

    /// REPAIR-5・SUP-6・TASK-163: 通知器は生成時にスレッドを起動せず（出力先も作らず）、通知のたびに短命スレッドを
    /// 起動して完了後に残さない（exec の fork 前単一スレッド要件の維持）。
    #[test]
    fn repair5_task163_notifier_spawns_lazily_and_leaves_no_thread() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let made = Arc::new(AtomicUsize::new(0));
        let m = made.clone();
        let notify = notifier_to(
            move || {
                m.fetch_add(1, Ordering::SeqCst);
                Box::new(std::io::sink())
            },
            2,
            Duration::from_secs(5),
        );
        assert_eq!(made.load(Ordering::SeqCst), 0);
        let f: FallbackFactory = Arc::new(|| Box::new(NoAuditFallback));
        let sink = FileAuditSink::with_parts(missing_path(), f, notify);
        for n in 1..=3 {
            sink.record(&sample()).unwrap_err();
            assert_eq!(made.load(Ordering::SeqCst), n);
        }
    }
}
