//! コンテナログの読み出しの正規入口（`logs` コマンドの本体。CLI-1・SUP-7・TASK-79 追補・#1543。関連: REPAIR-1・REPAIR-5）。
//!
//! CLI の `logs <id>` が `<state_root>/@container-logs`（[`super::container_log_dir`]）と [`super::container_log_rotation_config`]
//! を渡して [`read_container_log`] を呼ぶ。書き手は [`super::RotatingFileSink`]（supervisor の bin が開く）で、
//! レコード形式・ファイル名の写像・symlink を辿らない open の契約はどれも supervisor の持ち物のため、読み出しも
//! ここに置く（形式が変わっても直すのが 1 crate で済む。REPAIR-1）。
//!
//! # 契約
//! - 出力は、古い世代（`<enc>.log.<n>`、`n` が大きいほど古い）から現在ログ（`<enc>.log`）の順に、ファイルのバイト列を
//!   そのまま連結する。レコードのタグ（`stdout ` / `stderr `）・LF・書き込み失敗で途中切れの末尾も加工しない。
//!   ロックファイル・他 ID は含めない（[`super::log_file_paths`] が選ぶ）。
//! - ログが無い（ディレクトリが無い・ファイルが 0 件・0 バイト）は成功で、何も出力しない。
//! - オプションなしでは端末制御文字（ESC 系を含む）をエスケープしない。ログはコンテナ利用者のデータであり、端末へ
//!   直接出すと解釈され得る。表示用のエスケープは `--escape`（下記）。
//! - 出力先への書き込みが詰まれば `cat` と同じく書き先次第で待つ（本関数は出力先にタイムアウトを持たない）。
//!
//! # ローテーションとの競合（REPAIR-5）
//! 1 回の試行は「一覧 → 古い順に全部 open（`fstat` で dev / ino / len を記録）→ 各パスと一覧を再確認」で、
//! 再確認が一致したときだけ成立とする。ずれたら全 fd を閉じて最大 [`MAX_SNAPSHOT_ATTEMPTS`] 回やり直し、
//! 尽きれば `Unavailable` を返す。成立後は握った fd から記録した `len` だけを固定バッファで流す（rename / unlink
//! されても fd の中身は変わらないため、抜けも重複も出さない。`len` 以降の追記は今回は出さない）。
//!
//! # 上限
//! 読む合計は `max_file_bytes × (generations + 1)`、ファイル数は `generations + 1` まで（ローテーション中に 1 世代
//! 増える余裕）。超えたら 1 バイトも出さず `FailedPrecondition` で失敗する（黙って切り詰めない）。
//! メモリは固定 8 KiB のバッファ 1 本。FIFO への差し替えは `open_for_read`（`O_NONBLOCK | O_NOFOLLOW` と種別照合）で止まらない。
//!
//! # オプション指定の読み出し（`--tail` / `--stream` / `--escape` / `--follow`。CLI-1・SUP-7）
//! [`read_container_log_with`] が [`LogReadOptions`] を受ける。どれかを指定すると、出力はバイト単位のコピーではなく
//! レコード単位（`record` モジュール）になり、レコードの検証（タグが `stdout ` / `stderr ` であること・1 行が
//! `MAX_LINE_BYTES` 以下であること）を行う。破損は `Internal`（固定文言）で、検証をしないのはオプションなしの経路だけ。
//! - `--stream`: 対象のタグのレコードだけを、タグを残して出す。CLI の stderr は 1 行 JSON のエラー契約（ERR-1・ERR-2）の
//!   ため、コンテナの stderr を CLI の stderr へ流す方式は採らない。
//! - `--tail N`: 絞り込みの後の末尾 N レコード。スナップショットで開いた fd を 2 回読む（1 回目はタグだけ見て対象の総数 M を
//!   数え、2 回目は先頭 `M - N` 件を読み飛ばして出す）ので、メモリは N に依らず固定。読む量は上限の 2 倍以内。
//! - `--escape`: `cat -v` と同じ表でレコード本体だけを変換する（信頼できないコンテナの出力による端末制御の対策。
//!   既定は加工しない。docker / kubectl と同じ）。
//! - `--follow`: スナップショットを出した後、[`FOLLOW_POLL_INTERVAL`] ごとのポーリングで現在ログの追記を出す。
//!   完全な行（LF まで）だけを出す。現在ログの dev / ino が変わったら（ローテーション）、保持中の fd を EOF まで出し切り、
//!   一覧からそれより新しい世代を古い順に全部出し、新しい現在ログを先頭から追う（欠落・重複なし）。fd を保持している間は
//!   inode が解放されないので、ino の再利用で誤って一致することはない。保持中のファイルが一覧から消えるほど速く
//!   ローテーションされたら、黙って飛ばさず `Unavailable`（[`FOLLOW_OUTRAN_MESSAGE`]）で失敗する。`delete` でログが消えたら
//!   出し切って成功で終わる。終わりは次のいずれか。
//!   - コンテナの停止: 書き手（sink）がいない（`<id>.log.lock` を誰も保持していない）**かつ** 呼び出し側の probe
//!     （[`ContainerActivity`]）が `Running` でないとき、残りを出し切って成功で終わる（Docker 互換）。状態の `Stopped` の記録は
//!     supervisor の最終 flush より先に書かれるため、状態だけでは末尾を取りこぼす。sink の drop（最終 flush）の後でロックが
//!     解放されるので、ロック解放を終了条件に含める。restart ポリシーの再 launch の間も sink は保持されるので追従は続く。
//!     probe が `Unknown`（状態ストアの一時的な読み取り失敗）なら続ける（早く終えると取りこぼし、失敗にすると長い追従が
//!     一時的な競合で中断するため。期限が上限を担う。REPAIR-5）。supervisor がクラッシュして記録が stale な `Running` のまま
//!     残る場合は期限まで続く（復旧はクラッシュ復旧の GC の担当）。ロックの検査はポーリングのたびに行い、状態の probe は
//!     ロックが解放されたときだけ呼ぶ（状態ストアの `@lock` との競合を減らす。#2229）。
//!   - [`FollowOptions`] の期限（上限 [`MAX_FOLLOW_DURATION`]。超えたら残りを出し切って成功。REPAIR-5）。
//!   - 呼び出し側プロセスへのシグナル（CLI の `signals` が転送後に既定動作で終了する）。
//!
//! # 追従の遅延の上限と世代数 1（CLI-1・SUP-7・#2605）
//! LF で終わる行が `--follow` に現れるまでの遅延は、捕捉リーダーが読んで flush した時点から最大で 1 ポーリング間隔
//! （[`FOLLOW_POLL_INTERVAL`] = 200 ms）と読み出しの時間である。捕捉リーダーは read のたびに sink を flush するため、
//! 書き手側にタイマーによる滞留は無い。LF の来ていない行は、LF・EOF・`MAX_LINE_BYTES`（64 KiB）の上限のどれかまで出ない。
//! inotify / kqueue による短縮は、`unsafe`・`sys` の宣言を増やさず 3 OS で同じ挙動にするため行わない。
//! 世代数 1 の設定では、追従を `Unavailable` で拒否する。照合する一つ前の世代が無く、ポーリングの間の複数回のローテーションで
//! 読めない現在ログが生じても検出できず（黙って欠落させるのは不可）、ローテーションの隙間とログの削除も区別できないため。
//! 本番の設定は固定の 3 世代（`container_log_rotation_config`）で利用者が世代数を設定する手段は無く、世代数 1 には到達しない。
//! 設定化するときは `--follow` に 2 世代以上を要求し、使い方エラーとして先に拒否すること。
//!
//! # 未実装（REPAIR-3）
//! 非 unix では dev / ino 相当で再確認できないため `Unimplemented` で fail-closed にする（非 Linux の CLI は
//! plugin 経由で、この入口まで来ない。TASK-114・TASK-125）。`--follow` の期限の上限・`--tail` の件数の上限の値と、利用者向けの
//! `--until` の要否はオーナー確認待ち（#2605）。

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use super::StreamKind;
use super::rotating::RotationConfig;

#[cfg(unix)]
mod follow;
// 呼び出し元（imp・follow）が unix 限定のため、非 unix では dead_code になる。
#[cfg(unix)]
mod record;

/// 世代の入れ替わりで再試行する回数の上限（無限に回らない。REPAIR-5）。
pub const MAX_SNAPSHOT_ATTEMPTS: u32 = 3;

/// `--tail` に指定できる件数の上限（範囲外は `InvalidArgument`。値はオーナー確認待ち）。
pub const MAX_TAIL_RECORDS: u32 = 1_000_000;

/// `--follow` の期限の上限（これを超える指定は `InvalidArgument`。値はオーナー確認待ち。REPAIR-5）。
pub const MAX_FOLLOW_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// `--follow` の継続判定で呼び出し側が答えるコンテナの稼働状態（状態ストアの記録の読み取り結果。CLI-1・SUP-7）。
///
/// 真偽値にしないのは、読み取り失敗（`Unknown`）を「止まった」と取り違えて末尾を取りこぼさないため。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerActivity {
    /// 記録が `Running`。追従を続ける。
    Running,
    /// 記録が `Running` でない（`Stopped`・`Created`・記録の不在を含む）。書き手もいなければ追従を終える。
    NotRunning,
    /// 記録を読めなかった。追従を続ける（期限が上限）。
    Unknown,
}

/// `--follow` のポーリング間隔の既定。
pub const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// `--follow` のポーリング間隔に指定できる範囲（上端。下端は 1 ms）。
const MAX_FOLLOW_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// 追従が保持中のファイルを失う速さでローテーションされたときの `Unavailable` の固定文言（CLI が照合して別の文言へ写す）。
pub const FOLLOW_OUTRAN_MESSAGE: &str = "log was rotated faster than it could be followed";

/// 読み出しの結果（将来の拡張に備えた構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogReadReport {
    files: u32,
    bytes: u64,
}

impl LogReadReport {
    /// 読んだファイル数（現在ログ・世代の合計）。
    pub fn files(&self) -> u32 {
        self.files
    }

    /// 出力先へ書いたバイト数。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// 読み出しの失敗。出力先の失敗と読み取り側の失敗を分ける（CLI が別の文言へ写すため）。
#[derive(Debug)]
pub enum LogReadFailure {
    /// ログ側の失敗。`Unavailable`（入れ替わりが収まらない・追従が追いつかない）と `FailedPrecondition`（上限超過）以外は
    /// `Internal` にまとめる（パス・errno を含めない。ERR-1）。
    Source(TraitError),
    /// 出力先（stdout）への書き込みの失敗。
    Output,
}

fn source(code: ErrorCode, msg: &'static str) -> LogReadFailure {
    LogReadFailure::Source(TraitError::new(code, msg))
}

/// `--tail` の件数（`0..=`[`MAX_TAIL_RECORDS`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailCount(u32);

impl TailCount {
    /// 範囲外は `InvalidArgument`。
    pub fn new(n: u32) -> Result<Self, TraitError> {
        if n > MAX_TAIL_RECORDS {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "tail count is out of range",
            ));
        }
        Ok(Self(n))
    }

    /// 件数。
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// `--follow` の終わり方（期限）とポーリング間隔。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowOptions {
    deadline: Duration,
    poll_interval: Duration,
}

impl FollowOptions {
    /// 期限が [`MAX_FOLLOW_DURATION`] を超えたら `InvalidArgument`。間隔は [`FOLLOW_POLL_INTERVAL`]。
    pub fn new(deadline: Duration) -> Result<Self, TraitError> {
        if deadline > MAX_FOLLOW_DURATION {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "follow deadline is out of range",
            ));
        }
        Ok(Self {
            deadline,
            poll_interval: FOLLOW_POLL_INTERVAL,
        })
    }

    /// ポーリング間隔を変える（1 ms 以上 60 秒以下。範囲外は `InvalidArgument`）。
    pub fn with_poll_interval(self, interval: Duration) -> Result<Self, TraitError> {
        if interval < Duration::from_millis(1) || interval > MAX_FOLLOW_POLL_INTERVAL {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "follow poll interval is out of range",
            ));
        }
        Ok(Self {
            poll_interval: interval,
            ..self
        })
    }

    /// 期限。
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// ポーリング間隔。
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

/// [`read_container_log_with`] のオプション（将来の拡張に備えた構造体。何も指定しなければバイト単位のコピー）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogReadOptions {
    tail: Option<TailCount>,
    stream: Option<StreamKind>,
    escape: bool,
    follow: Option<FollowOptions>,
}

impl LogReadOptions {
    /// 絞り込みの後の末尾 N レコードだけを出す。
    pub fn with_tail(mut self, tail: TailCount) -> Self {
        self.tail = Some(tail);
        self
    }

    /// 指定のストリームのレコードだけを出す。
    pub fn with_stream(mut self, stream: StreamKind) -> Self {
        self.stream = Some(stream);
        self
    }

    /// レコード本体の制御文字を `cat -v` と同じ表で表示用に変換する。
    pub fn with_escape(mut self, escape: bool) -> Self {
        self.escape = escape;
        self
    }

    /// 出し終えた後も現在ログの追記を期限まで追う。
    pub fn with_follow(mut self, follow: FollowOptions) -> Self {
        self.follow = Some(follow);
        self
    }

    /// 末尾 N 件の指定。
    pub fn tail(&self) -> Option<TailCount> {
        self.tail
    }

    /// ストリームの絞り込み。
    pub fn stream(&self) -> Option<StreamKind> {
        self.stream
    }

    /// エスケープ表示か。
    pub fn escape(&self) -> bool {
        self.escape
    }

    /// 追従の指定。
    pub fn follow(&self) -> Option<FollowOptions> {
        self.follow
    }

    /// 何も指定していない（オプションなしのバイト単位のコピー）か。
    #[cfg(unix)]
    fn is_plain(&self) -> bool {
        self.tail.is_none() && self.stream.is_none() && !self.escape && self.follow.is_none()
    }
}

/// `id` のコンテナログを古い順に `out` へ書く。ログが無ければ何も書かず成功。
#[cfg(unix)]
pub fn read_container_log(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    out: &mut dyn Write,
) -> Result<LogReadReport, LogReadFailure> {
    imp::read(dir, id, config, out, &mut |_| {})
}

/// 非 unix は再確認の手段が無いため fail-closed（モジュール doc「未実装」）。
#[cfg(not(unix))]
pub fn read_container_log(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    out: &mut dyn Write,
) -> Result<LogReadReport, LogReadFailure> {
    let _ = (dir, id, config, out);
    Err(source(
        ErrorCode::Unimplemented,
        "reading container logs is not supported on this platform",
    ))
}

/// [`read_container_log`] のオプション指定版（`logs --follow` / `--tail` / `--stream` / `--escape`。CLI-1・SUP-7）。
/// `options` が既定なら [`read_container_log`] と同じ。`--follow` は期限・コンテナの停止（書き手の終了を確かめた後。
/// `activity` が `Running` を返す間は続く）・呼び出し側プロセスの終了のいずれかまで戻らない。`activity` は追従中だけ呼ばれる。
#[cfg(unix)]
pub fn read_container_log_with(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    options: &LogReadOptions,
    out: &mut dyn Write,
    activity: &mut dyn FnMut() -> ContainerActivity,
) -> Result<LogReadReport, LogReadFailure> {
    let start = std::time::Instant::now();
    let mut elapsed = move || start.elapsed();
    let mut sleep = std::thread::sleep;
    let mut driver = follow::Driver {
        elapsed: &mut elapsed,
        sleep: &mut sleep,
        activity,
    };
    imp::read_with(dir, id, config, options, out, &mut |_| {}, &mut driver)
}

/// 非 unix は [`read_container_log`] と同じく fail-closed。
#[cfg(not(unix))]
pub fn read_container_log_with(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    options: &LogReadOptions,
    out: &mut dyn Write,
    activity: &mut dyn FnMut() -> ContainerActivity,
) -> Result<LogReadReport, LogReadFailure> {
    let _ = (dir, id, config, options, out, activity);
    Err(source(
        ErrorCode::Unimplemented,
        "reading container logs is not supported on this platform",
    ))
}

#[cfg(unix)]
mod imp {
    use std::fs::{self, File};
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};

    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

    use super::super::rotating::{
        MIN_LOG_FILE_BYTES, RotationConfig, is_replaced_during_open, log_file_paths, open_for_read,
    };
    use super::follow::{self, Driver};
    use super::record::{ScanError, Scanner};
    use super::{LogReadFailure, LogReadOptions, LogReadReport, MAX_SNAPSHOT_ATTEMPTS, source};

    /// 流すときの固定バッファ。
    pub(super) const COPY_BUFFER_BYTES: usize = 8 * 1024;

    pub(super) const MSG_READ: &str = "container log could not be read";

    /// 開いた 1 ファイルの記録（fd と、開いた時点の dev / ino / len）。
    pub(super) struct Opened {
        pub(super) path: PathBuf,
        pub(super) file: File,
        pub(super) dev: u64,
        pub(super) ino: u64,
        pub(super) len: u64,
    }

    enum Attempt {
        Done(Vec<Opened>),
        /// 世代が入れ替わった。やり直す。
        Retry,
    }

    pub(super) fn read_error(e: TraitError) -> LogReadFailure {
        match e.code() {
            ErrorCode::Unavailable | ErrorCode::FailedPrecondition => LogReadFailure::Source(e),
            _ => source(ErrorCode::Internal, MSG_READ),
        }
    }

    pub(super) fn internal() -> LogReadFailure {
        source(ErrorCode::Internal, MSG_READ)
    }

    pub(super) fn scan_error(e: ScanError) -> LogReadFailure {
        match e {
            ScanError::Malformed => internal(),
            ScanError::Output => LogReadFailure::Output,
        }
    }

    /// 1 回のスナップショットを作る。`hook` は全 open の後・再確認の前に呼ばれる（試験用の差し込み口）。
    fn snapshot(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        attempt: u32,
        hook: &mut dyn FnMut(u32),
    ) -> Result<Attempt, LogReadFailure> {
        let paths = log_file_paths(dir, id).map_err(read_error)?;
        let max_files = u64::from(config.generations()).saturating_add(1);
        if u64::try_from(paths.len()).unwrap_or(u64::MAX) > max_files {
            return Err(source(
                ErrorCode::FailedPrecondition,
                "container log exceeds the read limit",
            ));
        }
        let mut opened: Vec<Opened> = Vec::with_capacity(paths.len());
        for path in &paths {
            let file = match open_for_read(path) {
                Ok(f) => f,
                // 一覧の後にローテーションで消えた。やり直す。
                Err(e) if e.code() == ErrorCode::NotFound => return Ok(Attempt::Retry),
                // lstat と open の間に同じ世代パスが別の通常ファイルへ入れ替わった（ローテーション）。やり直す。
                Err(e) if is_replaced_during_open(&e) => return Ok(Attempt::Retry),
                Err(e) => return Err(read_error(e)),
            };
            let meta = file.metadata().map_err(|_| internal())?;
            opened.push(Opened {
                path: path.clone(),
                file,
                dev: meta.dev(),
                ino: meta.ino(),
                len: meta.len(),
            });
        }
        hook(attempt);
        for o in &opened {
            match fs::symlink_metadata(&o.path) {
                Ok(m) if m.dev() == o.dev && m.ino() == o.ino => {}
                Ok(_) => return Ok(Attempt::Retry),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Attempt::Retry),
                Err(_) => return Err(internal()),
            }
        }
        let again = log_file_paths(dir, id).map_err(read_error)?;
        if again != paths {
            return Ok(Attempt::Retry);
        }
        Ok(Attempt::Done(opened))
    }

    /// 一貫したスナップショット（古い順）を作る。ディレクトリが無ければ空。入れ替わりは最大
    /// [`MAX_SNAPSHOT_ATTEMPTS`] 回やり直し、尽きれば `Unavailable`（REPAIR-5）。
    pub(super) fn open_consistent(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        hook: &mut dyn FnMut(u32),
    ) -> Result<Vec<Opened>, LogReadFailure> {
        // ディレクトリが無い = まだ何も書かれていない。`log_file_paths` の検査エラーと区別するため先に見る。
        if let Err(e) = fs::symlink_metadata(dir) {
            if e.kind() == ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(internal());
        }
        for attempt in 0..MAX_SNAPSHOT_ATTEMPTS {
            if let Attempt::Done(o) = snapshot(dir, id, config, attempt, hook)? {
                return Ok(o);
            }
        }
        Err(source(
            ErrorCode::Unavailable,
            "container log is rotating; retry",
        ))
    }

    /// 読む合計の上限（`max_file_bytes × (generations + 1)`）を確かめる。
    pub(super) fn check_limit(
        opened: &[Opened],
        config: RotationConfig,
    ) -> Result<(), LogReadFailure> {
        let total = opened.iter().fold(0u64, |acc, o| acc.saturating_add(o.len));
        check_bytes(total, config)
    }

    /// 1 回の読取対象の合計バイト数が上限以下か確かめる。追従中の各回（新しいスナップショット・保持ファイルの増加量）にも
    /// 同じ上限を適用する（読み出す前に検証する。REPAIR-5）。
    pub(super) fn check_bytes(total: u64, config: RotationConfig) -> Result<(), LogReadFailure> {
        let limit = config
            .max_file_bytes()
            .saturating_mul(u64::from(config.generations()).saturating_add(1));
        if total > limit {
            return Err(source(
                ErrorCode::FailedPrecondition,
                "container log exceeds the read limit",
            ));
        }
        Ok(())
    }

    pub(super) fn read(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        out: &mut dyn Write,
        hook: &mut dyn FnMut(u32),
    ) -> Result<LogReadReport, LogReadFailure> {
        let opened = open_consistent(dir, id, config, hook)?;
        check_limit(&opened, config)?;
        let mut written = 0u64;
        let mut files = 0u32;
        let mut buf = [0u8; COPY_BUFFER_BYTES];
        for o in opened {
            let mut reader = o.file.take(o.len);
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => return Err(internal()),
                };
                let Some(chunk) = buf.get(..n) else {
                    return Err(internal());
                };
                out.write_all(chunk).map_err(|_| LogReadFailure::Output)?;
                written = written.saturating_add(n as u64);
            }
            files = files.saturating_add(1);
        }
        out.flush().map_err(|_| LogReadFailure::Output)?;
        Ok(LogReadReport {
            files,
            bytes: written,
        })
    }

    /// 出力先へ書いたバイト数を数える `Write`。
    pub(super) struct Counting<'a> {
        pub(super) inner: &'a mut dyn Write,
        pub(super) bytes: u64,
    }

    impl Write for Counting<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.bytes = self.bytes.saturating_add(n as u64);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// `[from, to)` を `file` から読んで `scanner` へ流す（`out` が `None` なら数えるだけ）。
    /// 途中でファイルが縮んだ（`to` より前の EOF）ときは `Internal`。
    pub(super) fn feed_range(
        file: &File,
        from: u64,
        to: u64,
        scanner: &mut Scanner,
        mut out: Option<&mut dyn Write>,
    ) -> Result<(), LogReadFailure> {
        let mut pos = from;
        let mut buf = [0u8; COPY_BUFFER_BYTES];
        while pos < to {
            let want = usize::try_from(to - pos)
                .unwrap_or(COPY_BUFFER_BYTES)
                .min(COPY_BUFFER_BYTES);
            let Some(window) = buf.get_mut(..want) else {
                return Err(internal());
            };
            let n = match file.read_at(window, pos) {
                Ok(0) => return Err(internal()),
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(internal()),
            };
            let Some(chunk) = buf.get(..n) else {
                return Err(internal());
            };
            scanner
                .feed(chunk, out.as_mut().map(|w| &mut **w as &mut dyn Write))
                .map_err(scan_error)?;
            pos = pos.saturating_add(n as u64);
        }
        Ok(())
    }

    /// `[lower, len)` の中の最後の LF の直後の位置（LF が無ければ `lower`）。書き込み中の途中の行を除くために使う。
    /// 最大 1 レコード（[`MIN_LOG_FILE_BYTES`]）だけ後ろへ遡り、それでも LF が無ければ 1 行が上限を超えた破損として
    /// `Internal`（無制限に読まない。REPAIR-5）。
    pub(super) fn last_lf_end(file: &File, len: u64, lower: u64) -> Result<u64, LogReadFailure> {
        let floor = lower.max(len.saturating_sub(MIN_LOG_FILE_BYTES));
        let mut pos = len;
        let mut buf = [0u8; COPY_BUFFER_BYTES];
        while pos > floor {
            let start = floor.max(pos.saturating_sub(COPY_BUFFER_BYTES as u64));
            let want = usize::try_from(pos - start).map_err(|_| internal())?;
            let Some(window) = buf.get_mut(..want) else {
                return Err(internal());
            };
            file.read_exact_at(window, start).map_err(|_| internal())?;
            if let Some(i) = window.iter().rposition(|b| *b == b'\n') {
                return Ok(start + i as u64 + 1);
            }
            pos = start;
        }
        if len.saturating_sub(lower) > MIN_LOG_FILE_BYTES {
            return Err(internal());
        }
        Ok(lower)
    }

    /// 現在ログ（`<enc>.log`）か（世代は `.log.<n>` で終わる）。
    pub(super) fn is_current_log(path: &Path) -> bool {
        path.extension().is_some_and(|e| e == "log")
    }

    /// スナップショットの各ファイルで出す範囲 `[0, limit)` と、現在ログか。現在ログは最後の LF まで（書き込み中の
    /// 途中の行を出さない）、確定済みの世代は全長（切れた末尾を含む）。
    pub(super) fn plan_limits(opened: &[Opened]) -> Result<Vec<(u64, bool)>, LogReadFailure> {
        let mut plan = Vec::with_capacity(opened.len());
        for (i, o) in opened.iter().enumerate() {
            let current = i + 1 == opened.len() && is_current_log(&o.path);
            let limit = if current {
                last_lf_end(&o.file, o.len, 0)?
            } else {
                o.len
            };
            plan.push((limit, current));
        }
        Ok(plan)
    }

    /// オプション指定の読み出し（`--tail` の 2 パス・絞り込み・エスケープ・追従の入口）。
    pub(super) fn read_with(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        options: &LogReadOptions,
        out: &mut dyn Write,
        hook: &mut dyn FnMut(u32),
        driver: &mut Driver<'_>,
    ) -> Result<LogReadReport, LogReadFailure> {
        if options.is_plain() {
            return read(dir, id, config, out, hook);
        }
        let opened = open_consistent(dir, id, config, hook)?;
        check_limit(&opened, config)?;
        let plan = plan_limits(&opened)?;
        let mut counting = Counting {
            inner: out,
            bytes: 0,
        };
        let mut skip = 0u64;
        if let Some(tail) = options.tail() {
            // 1 パス目: 出力せずタグだけ見て、対象のレコードの総数を数える。
            let mut counter = Scanner::new(options.stream(), false);
            for (o, (limit, current)) in opened.iter().zip(&plan) {
                feed_range(&o.file, 0, *limit, &mut counter, None)?;
                if !*current {
                    counter.end_file(None).map_err(scan_error)?;
                }
            }
            skip = counter.matched().saturating_sub(u64::from(tail.get()));
        }
        let mut scanner = Scanner::new(options.stream(), options.escape());
        scanner.set_skip(skip);
        let mut files = u32::try_from(opened.len()).unwrap_or(u32::MAX);
        for (o, (limit, current)) in opened.iter().zip(&plan) {
            feed_range(&o.file, 0, *limit, &mut scanner, Some(&mut counting))?;
            if !*current {
                scanner.end_file(Some(&mut counting)).map_err(scan_error)?;
            }
        }
        counting.flush().map_err(|_| LogReadFailure::Output)?;
        if let Some(f) = options.follow() {
            let start = follow::Start {
                opened,
                plan,
                scanner,
            };
            let extra = follow::run(dir, id, config, f, start, &mut counting, driver)?;
            files = files.saturating_add(extra);
        }
        Ok(LogReadReport {
            files,
            bytes: counting.bytes,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 第 2 要素は残骸を消して作った実体（Drop で後始末する。REPAIR-12・#3435）。
    struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);

    impl Tmp {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fc-sup-rd-{tag}-{}-{n}", std::process::id()));
            // 残骸・PID 再利用との衝突を避けるため作成前に削除する（0700。REPAIR-12・#3435）。
            let root = crate::test_root::test_root_at(p.clone());
            Self(p, root)
        }
        fn put(&self, name: &str, body: &[u8]) {
            fs::write(self.0.join(name), body).expect("write");
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn small() -> RotationConfig {
        RotationConfig::default()
    }

    fn read_with(
        dir: &Path,
        id: &str,
        config: RotationConfig,
        hook: &mut dyn FnMut(u32),
    ) -> (Result<LogReadReport, LogReadFailure>, Vec<u8>) {
        let mut out = Vec::new();
        let r = imp::read(dir, &cid(id), config, &mut out, hook);
        (r, out)
    }

    fn code(r: Result<LogReadReport, LogReadFailure>) -> ErrorCode {
        match r {
            Err(LogReadFailure::Source(e)) => e.code(),
            other => panic!("expected Source error, got {other:?}"),
        }
    }

    /// SUP-7・CLI-1: 世代をまたいで古い順にバイト単位で連結する。ロックと他 ID は含めない。
    #[test]
    fn sup7_reads_generations_oldest_first_byte_exact() {
        let t = Tmp::new("gen");
        t.put("c1.log.2", b"stdout a\n");
        t.put("c1.log.1", b"stderr b\n");
        t.put("c1.log", b"stdout c\x1b[0m\n");
        t.put("c1.log.lock", b"");
        t.put("c2.log", b"stdout other\n");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        let rep = r.expect("ok");
        assert_eq!(out, b"stdout a\nstderr b\nstdout c\x1b[0m\n");
        assert_eq!(rep.files(), 3);
        assert_eq!(rep.bytes(), 9 + 9 + 13);
    }

    /// SUP-7・IO-5: 大文字の ID は小文字化した名前へ写る。
    #[test]
    fn sup7_uppercase_id_maps_to_encoded_name() {
        let t = Tmp::new("upper");
        t.put("_web.log", b"stdout w\n");
        let (r, out) = read_with(&t.0, "Web", small(), &mut |_| {});
        r.expect("ok");
        assert_eq!(out, b"stdout w\n");
    }

    /// CLI-1: ディレクトリが無い・空・0 バイトはどれも空の成功。
    #[test]
    fn cli1_no_logs_is_empty_success() {
        let t = Tmp::new("none");
        let missing = t.0.join("absent");
        let (r, out) = read_with(&missing, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok"), LogReadReport::default());
        assert!(out.is_empty());
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok").files(), 0);
        assert!(out.is_empty());
        t.put("c1.log", b"");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok").bytes(), 0);
        assert!(out.is_empty());
    }

    /// SUP-7: 世代の位置の symlink・名前空間の別名は Internal（辿らない）。
    #[test]
    fn sup7_symlink_and_alias_are_internal() {
        let t = Tmp::new("sym");
        t.put("target", b"secret\n");
        std::os::unix::fs::symlink(t.0.join("target"), t.0.join("c1.log.1")).expect("symlink");
        t.put("c1.log", b"stdout x\n");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(code(r), ErrorCode::Internal);
        assert!(out.is_empty());
        let t = Tmp::new("alias");
        t.put("C1.log", b"stdout x\n");
        let (r, _) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(code(r), ErrorCode::Internal);
    }

    /// REPAIR-5: 合計バイトの上限超過は何も出さず FailedPrecondition。
    #[test]
    fn repair5_total_bytes_over_limit_fails_without_output() {
        let cfg = RotationConfig::new(super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let t = Tmp::new("big");
        let part = vec![b'x'; usize::try_from(cfg.max_file_bytes()).expect("usize")];
        t.put("c1.log.1", &part);
        t.put("c1.log", &part);
        // 上限は max × (1 + 1) 以内なので成功する。
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        r.expect("at limit");
        assert_eq!(out.len(), part.len() * 2);
        // 両方が 1 バイト超過して合計が上限を超える。
        let mut over = part.clone();
        over.push(b'y');
        t.put("c1.log", &over);
        t.put("c1.log.1", &over);
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        assert_eq!(code(r), ErrorCode::FailedPrecondition);
        assert!(out.is_empty());
    }

    /// REPAIR-5: ファイル数が generations + 1 を超えたら FailedPrecondition。
    #[test]
    fn repair5_file_count_over_limit_fails() {
        let cfg = RotationConfig::new(super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let t = Tmp::new("count");
        t.put("c1.log.2", b"stdout a\n");
        t.put("c1.log.1", b"stdout b\n");
        t.put("c1.log", b"stdout c\n");
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        assert_eq!(code(r), ErrorCode::FailedPrecondition);
        assert!(out.is_empty());
    }

    struct Failing;

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// ERR-1: 出力先の失敗は Output で、Source と区別される。
    #[test]
    fn err1_output_failure_is_distinct() {
        let t = Tmp::new("out");
        t.put("c1.log", b"stdout a\n");
        let r = imp::read(&t.0, &cid("c1"), small(), &mut Failing, &mut |_| {});
        assert!(matches!(r, Err(LogReadFailure::Output)));
    }

    /// REPAIR-5: open 後にパスが別の実体へ替わったら 1 回やり直して成功する（旧内容の取りこぼしを出さない）。
    #[test]
    fn repair5_swap_once_retries_and_succeeds() {
        let t = Tmp::new("swap1");
        t.put("c1.log.1", b"stdout old\n");
        t.put("c1.log", b"stdout cur\n");
        let dir = t.0.clone();
        let mut hook = |attempt: u32| {
            if attempt == 0 {
                // ローテーション: 現在ログを .1 へ、新しい現在ログを作る。
                fs::rename(dir.join("c1.log.1"), dir.join("c1.log.2")).expect("r1");
                fs::rename(dir.join("c1.log"), dir.join("c1.log.1")).expect("r2");
                fs::write(dir.join("c1.log"), b"stdout new\n").expect("w");
            }
        };
        let (r, out) = read_with(&t.0, "c1", small(), &mut hook);
        r.expect("ok");
        assert_eq!(out, b"stdout old\nstdout cur\nstdout new\n");
    }

    /// REPAIR-5: 毎回替わるなら 3 回で Unavailable（無限に回らない）。
    #[test]
    fn repair5_always_swapping_is_unavailable() {
        let t = Tmp::new("swapn");
        t.put("c1.log", b"stdout cur\n");
        let dir = t.0.clone();
        let mut calls = 0u32;
        let mut hook = |_: u32| {
            calls += 1;
            let tmp = dir.join("tmp");
            fs::write(&tmp, b"stdout other\n").expect("w");
            fs::rename(&tmp, dir.join("c1.log")).expect("r");
        };
        let (r, out) = read_with(&t.0, "c1", small(), &mut hook);
        assert_eq!(code(r), ErrorCode::Unavailable);
        assert!(out.is_empty());
        assert_eq!(calls, MAX_SNAPSHOT_ATTEMPTS);
    }

    fn read_opts(
        t: &Tmp,
        config: RotationConfig,
        opts: LogReadOptions,
    ) -> (Result<LogReadReport, LogReadFailure>, Vec<u8>) {
        let mut elapsed = || Duration::ZERO;
        let mut sleep = |_: Duration| {};
        let mut activity = || ContainerActivity::Running;
        let mut driver = follow::Driver {
            elapsed: &mut elapsed,
            sleep: &mut sleep,
            activity: &mut activity,
        };
        let mut out = Vec::new();
        let r = imp::read_with(
            &t.0,
            &cid("c1"),
            config,
            &opts,
            &mut out,
            &mut |_| {},
            &mut driver,
        );
        (r, out)
    }

    fn tail(n: u32) -> LogReadOptions {
        LogReadOptions::default().with_tail(TailCount::new(n).expect("tail"))
    }

    fn three_generations(t: &Tmp) {
        t.put("c1.log.2", b"stdout a\nstderr b\n");
        t.put("c1.log.1", b"stdout c\n");
        t.put("c1.log", b"stderr d\x1b[0m\nstdout e\n");
    }

    /// CLI-1: 末尾 N 件は世代をまたいで数える（具体バイト列）。
    #[test]
    fn cli1_tail_last_n_across_generations() {
        let t = Tmp::new("tail");
        three_generations(&t);
        let (r, out) = read_opts(&t, small(), tail(3));
        r.expect("ok");
        assert_eq!(out, b"stdout c\nstderr d\x1b[0m\nstdout e\n");
        let (_, out) = read_opts(&t, small(), tail(1));
        assert_eq!(out, b"stdout e\n");
    }

    /// CLI-1: `--tail 0` は何も出さず、総数より大きければ全部出す。
    #[test]
    fn cli1_tail_zero_and_more_than_total() {
        let t = Tmp::new("tail0");
        three_generations(&t);
        let (r, out) = read_opts(&t, small(), tail(0));
        r.expect("ok");
        assert!(out.is_empty());
        let (_, out) = read_opts(&t, small(), tail(1000));
        assert_eq!(
            out,
            b"stdout a\nstderr b\nstdout c\nstderr d\x1b[0m\nstdout e\n"
        );
    }

    /// CLI-1: 末尾 N 件はストリームの絞り込みの後に数え、エスケープも効く。
    #[test]
    fn cli1_tail_after_stream_filter_and_escape() {
        let t = Tmp::new("tailstream");
        three_generations(&t);
        let opts = tail(1).with_stream(StreamKind::Stderr).with_escape(true);
        let (r, out) = read_opts(&t, small(), opts);
        r.expect("ok");
        assert_eq!(out, b"stderr d^[[0m\n");
        let only_stdout = LogReadOptions::default().with_stream(StreamKind::Stdout);
        let (_, out) = read_opts(&t, small(), only_stdout);
        assert_eq!(out, b"stdout a\nstdout c\nstdout e\n");
    }

    /// SUP-7: 破損（未知のタグ）はオプション指定時に Internal。オプションなしはバイトのまま通す。
    #[test]
    fn sup7_options_reject_malformed_records() {
        let t = Tmp::new("bad");
        t.put("c1.log", b"junk line\n");
        let (r, out) = read_opts(&t, small(), tail(5));
        assert_eq!(code(r), ErrorCode::Internal);
        assert!(out.is_empty());
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        r.expect("plain");
        assert_eq!(out, b"junk line\n");
    }

    /// SUP-7: 世代の切れた末尾はそのまま出し、現在ログの書き込み途中の行は出さない。
    #[test]
    fn sup7_torn_generation_tail_passes_and_current_partial_is_withheld() {
        let t = Tmp::new("torn");
        t.put("c1.log.1", b"stdout a\nstderr tor");
        t.put("c1.log", b"stdout b\nstdout par");
        let (r, out) = read_opts(&t, small(), LogReadOptions::default().with_escape(true));
        r.expect("ok");
        assert_eq!(out, b"stdout a\nstderr torstdout b\n");
    }

    /// REPAIR-5: 上限を超えるログは `--tail` でも何も出さず FailedPrecondition。
    #[test]
    fn repair5_tail_respects_read_limit() {
        let cfg = RotationConfig::new(super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let t = Tmp::new("tailbig");
        let mut part = vec![b'x'; usize::try_from(cfg.max_file_bytes()).expect("usize")];
        part.push(b'y');
        t.put("c1.log.1", &part);
        t.put("c1.log", &part);
        let (r, out) = read_opts(&t, cfg, tail(1));
        assert_eq!(code(r), ErrorCode::FailedPrecondition);
        assert!(out.is_empty());
    }

    /// REPAIR-5: LF の無いまま 1 行の上限を超える現在ログは破損（無制限に読まない）。
    #[test]
    fn repair5_current_log_without_lf_over_limit_is_internal() {
        let t = Tmp::new("nolf");
        let mut body = b"stdout ".to_vec();
        body.extend(std::iter::repeat_n(b'x', 70_000));
        t.put("c1.log", &body);
        let (r, out) = read_opts(&t, small(), tail(1));
        assert_eq!(code(r), ErrorCode::Internal);
        assert!(out.is_empty());
    }

    /// 出力先の失敗はオプション指定でも Output。
    #[test]
    fn err1_output_failure_with_options_is_distinct() {
        let t = Tmp::new("outopt");
        t.put("c1.log", b"stdout a\n");
        let mut elapsed = || Duration::ZERO;
        let mut sleep = |_: Duration| {};
        let mut activity = || ContainerActivity::Running;
        let mut driver = follow::Driver {
            elapsed: &mut elapsed,
            sleep: &mut sleep,
            activity: &mut activity,
        };
        let r = imp::read_with(
            &t.0,
            &cid("c1"),
            small(),
            &tail(1),
            &mut Failing,
            &mut |_| {},
            &mut driver,
        );
        assert!(matches!(r, Err(LogReadFailure::Output)));
    }

    /// 範囲外の件数・期限・間隔は InvalidArgument。
    #[test]
    fn cli1_option_ranges_are_validated() {
        assert!(TailCount::new(MAX_TAIL_RECORDS).is_ok());
        assert!(TailCount::new(MAX_TAIL_RECORDS + 1).is_err());
        assert!(FollowOptions::new(MAX_FOLLOW_DURATION).is_ok());
        assert!(FollowOptions::new(MAX_FOLLOW_DURATION + Duration::from_secs(1)).is_err());
        let f = FollowOptions::new(Duration::from_secs(1)).expect("f");
        assert_eq!(f.poll_interval(), FOLLOW_POLL_INTERVAL);
        assert!(f.with_poll_interval(Duration::ZERO).is_err());
        assert!(f.with_poll_interval(Duration::from_secs(61)).is_err());
    }
}
