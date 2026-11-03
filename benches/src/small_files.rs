//! 小ファイル多数ワークロードの files/s 計測ロジック（TASK-189・IO-6・IO-7・REPAIR-8）。
//!
//! `benches/benches/small_files.rs`（`harness = false` の薄い入口）から呼ばれる。計測定義の記録は
//! `docs/design/small-files-bench.md`（承認は #1897）。回帰ゲート（`benches/metrics.json`・
//! `scripts/check-bench-regression.sh` の対象）へは登録済み（#1899）。baseline 未登録の間は比較対象外（基準値は #230）。
//!
//! # 計測する区間（1 ファイル）
//!
//! `GuestFileCreator::create_file` → 固定長の write を 1 回（`BatchSink::write_batch`）→ 永続化
//! （`BatchSink::persist`。FLUSH 相当）まで。files/s = 件数 ÷（最初の `create_file` の直前から
//! 最後の永続化の完了まで）。作業ディレクトリの用意・`GuestFileCreator` の構築・書き込む `Batch`
//! の組み立て・後始末は区間に入れない。祖先ディレクトリの作成は区間に入る。
//!
//! # 経路（`--route`）
//!
//! 2 つの経路を持ち、結果の `method`・`wire_path`・`params.route` で区別する（#2074）。
//!
//! | `--route` | 内容 | `method` の接頭辞 | `wire_path` |
//! | --------- | ---- | ----------------- | ----------- |
//! | `server-api`（既定） | サーバー側の API を直接呼ぶ（`serve_*_connection` を通さない）。符号化・復号・UDS を含まない | `server-api-direct/` | `false` |
//! | `wire` | UDS 越しに I/O 共有層のフレーム（Create → WriteFile → Close → Flush。#1886 の v2）を送る。符号化・復号・UDS の往復・ACK の待ちを区間に含む（`small_files/wire.rs`）。Linux と macOS のみ | `wire-uds/` | `true` |
//!
//! 回帰ゲートの引数は `--route wire`（`scripts/lib.sh` の `bench_args_for`）。既定を `server-api`
//! のままにしているのは、Windows（UDS なし）の引数なしスモークと、`scripts/bench/small_files_compare.sh`
//! （server-api 経路で照合する）を壊さないため。経路の違う値同士は比べない（`method` を必ず照合する）。
//!
//! # FLUSH の位置（`method`）
//!
//! - `--batch-size 1`（既定）: 1 ファイルごとに永続化する（IO-2 の契約どおり。`flush-per-file`）
//! - `--batch-size K`（K > 1）: K ファイルごと（と最後）にだけ永続化する（`flush-every-k`）。PoC と
//!   比べるための参考値で IO-2 の保証外。Linux の `syncfs` が file system 全体を書き戻すことに
//!   依存するため、`PersistSupport::Supported` の環境でのみ受け付ける
//!
//! # 2 構成（IO-7）
//!
//! `--config bind|named-volume` は結果に記録するラベルで、挙動は変えない。いまの main には
//! `VolumeProvider` の実装が無く、置き場所の違い（利用者指定のホストディレクトリか、ランタイム
//! 管理のディレクトリか）は呼び出し側が `--root` で与える（REPAIR-3: 実装済みを装わない）。
//!
//! # 既知の限界
//!
//! - `create_file` は作成のたびに祖先ディレクトリの実在エントリを読み直す。平置きで N 件作ると
//!   読むエントリの合計は約 N²/2 になり、この走査も計測値に含まれる。ツリー配置では 1 回あたり
//!   高々約 452 件
//! - 期限（REPAIR-5）は協調的で、各ファイルの処理の前に照合する。`create_file` の内部で止まった
//!   syscall には割り込めない。応答を待つ永続化だけは `IoTimeout` で切る
//!
//! # 後始末
//!
//! 書き込み先は `--root` の下に新しく作る専用サブディレクトリだけで、終了時（失敗時を含む）に
//! 自分が作ったものだけを消す。`--root` の既存の内容には触れず、symlink は辿らない。

pub mod wire;

use fandhe_container_io::{
    BatchBuffer, BatchConfig, BatchSink, FrameKind, GuestFileCreator, InFlightLimit, IoError,
    IoErrorCode, IoTimeout, MAX_IO_TIMEOUT, PersistSupport, PushOutcome, SendQueue, WireRequestId,
    encode_request, persist_support,
};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 件数の下限・上限（IO-6 の 2,000 件〜IO-6 の 3〜5 万件に対応）。
pub const MIN_COUNT: u64 = 2_000;
pub const MAX_COUNT: u64 = 50_000;
/// バッチサイズ（K）の上限。`fandhe_container_io::MAX_BATCH_SIZE` と同じ。
pub const MAX_BATCH_SIZE_ARG: u64 = 4_096;
/// 1 ファイルの書き込みバイト数の範囲。
pub const MAX_FILE_SIZE: u64 = 65_536;
/// 試行回数の上限。
pub const MAX_TRIALS: u64 = 20;
/// 期限（秒）の上限。
pub const MAX_TRIAL_TIMEOUT_SECS: u64 = 7_200;
pub const MAX_TIMEOUT_SECS: u64 = 86_400;
/// 平置きにする件数の上限（`--layout auto`）。
pub const AUTO_FLAT_MAX: u64 = 2_000;
/// ツリー配置で 1 ディレクトリに置く件数。
pub const DIR_CAPACITY: u64 = 256;

/// 既定値。
pub const DEFAULT_FILE_SIZE: u64 = 2;
pub const DEFAULT_TRIALS: u64 = 5;
pub const DEFAULT_TRIAL_TIMEOUT_SECS: u64 = 1_800;
pub const DEFAULT_TIMEOUT_SECS: u64 = 10_800;

/// スモーク（引数なし）の件数と期限。
pub const SMOKE_COUNT: u64 = 32;
pub const SMOKE_TIMEOUT_SECS: u64 = 60;

/// 結果 JSON の metric 名と単位（`scripts/check-bench-regression.sh` の名前規則に合う）。
pub const METRIC_NAME: &str = "small_files_files_per_sec";
pub const METRIC_UNIT: &str = "files/s";

const METHOD_PER_FILE: &str = "server-api-direct/flush-per-file";
const METHOD_EVERY_K: &str = "server-api-direct/flush-every-k";
const NOTE_PER_FILE: &str =
    "server API called directly, not the wire path; each file is flushed individually";
const NOTE_EVERY_K: &str = "outside IO-2 guarantee; relies on syncfs flushing the whole file system (Linux only); server API called directly, not the wire path";
const METHOD_WIRE_PER_FILE: &str = "wire-uds/flush-per-file";
const METHOD_WIRE_EVERY_K: &str = "wire-uds/flush-every-k";
const NOTE_WIRE_PER_FILE: &str = "wire path over UDS (frame encode/decode and round trips included); each file is flushed individually";
const NOTE_WIRE_EVERY_K: &str = "wire path over UDS; multi-file FLUSH per #1886 F9; treated as outside IO-2 until spec confirmation (b) of #1886 is answered";

/// 構造化エラー（標準エラーへ 1 行の JSON で出す。`code` は機械可読、`message` は英語）。
///
/// message にはパス・ホスト名・OS 由来の文字列を載せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallFilesError {
    pub code: &'static str,
    pub message: String,
}

impl SmallFilesError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn args(message: impl Into<String>) -> Self {
        Self::new("invalid-args", message)
    }
}

impl std::fmt::Display for SmallFilesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // code・message は固定文字列に由来し、引用符・バックスラッシュを含まない。
        write!(
            f,
            "{{\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}",
            self.code, self.message
        )
    }
}

impl std::error::Error for SmallFilesError {}

/// `fandhe_container_io` のエラーを、パスを含まない構造化エラーへ写す。
fn from_io(err: &IoError) -> SmallFilesError {
    let code = if err.code() == IoErrorCode::Timeout {
        "timeout"
    } else {
        "io-error"
    };
    SmallFilesError::new(
        code,
        format!("io operation failed ({})", err.code().as_str()),
    )
}

fn from_fs(err: &std::io::Error) -> SmallFilesError {
    SmallFilesError::new(
        "io-error",
        format!("file system operation failed ({:?})", err.kind()),
    )
}

/// ファイルの配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 共有ルート直下に平置き。
    Flat,
    /// `d{NNN}/f{NNN}`（1 ディレクトリ 256 件まで・パスの深さ 2）。
    Tree,
}

impl Layout {
    fn as_str(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Tree => "tree",
        }
    }
}

/// 計測する経路（モジュール doc「経路」参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// UDS 越しのフレーム（Linux / macOS のみ）。
    Wire,
    /// サーバー側の API の直接呼び出し。
    ServerApi,
}

impl Route {
    fn as_str(self) -> &'static str {
        match self {
            Self::Wire => "wire",
            Self::ServerApi => "server-api",
        }
    }
}

/// 2 構成のラベル（挙動は変えない。モジュール doc 参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    Bind,
    NamedVolume,
}

impl Config {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::NamedVolume => "named-volume",
        }
    }
}

/// 検証済みの計測計画。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub count: u64,
    pub batch_size: u64,
    pub file_size: u64,
    pub layout: Layout,
    pub config: Config,
    pub route: Route,
    pub trials: u64,
    pub trial_timeout: Duration,
    pub timeout: Duration,
}

impl Plan {
    /// 引数なし（スモーク）の計画。範囲検証を通さない内部の固定値。
    pub fn smoke() -> Self {
        Self {
            count: SMOKE_COUNT,
            batch_size: 1,
            file_size: DEFAULT_FILE_SIZE,
            layout: Layout::Flat,
            config: Config::Bind,
            route: Route::ServerApi,
            trials: 1,
            trial_timeout: Duration::from_secs(SMOKE_TIMEOUT_SECS),
            timeout: Duration::from_secs(SMOKE_TIMEOUT_SECS),
        }
    }

    /// 副作用・確保の前に、全フィールドが安全な内部範囲にあることを検証する。
    ///
    /// 件数の下限は 1（smoke・テスト用の小さい件数を許す）。計測用の下限 `MIN_COUNT` は
    /// CLI 引数の解釈（`parse_args`）でのみ課す。上限・その他の範囲は `parse_args` と同じ。
    ///
    /// フィールドが公開で `run*` を直接呼べるため、公開の実行入口はすべてこれを通す
    /// （`batch_size == 0` の剰余 panic・過大確保の防止。REPAIR-5・coding-rust）。
    pub fn validate(&self) -> Result<(), SmallFilesError> {
        let check = |ok: bool, msg: &'static str| {
            if ok {
                Ok(())
            } else {
                Err(SmallFilesError::args(msg))
            }
        };
        check(
            (1..=MAX_COUNT).contains(&self.count),
            "count is out of range",
        )?;
        check(
            (1..=MAX_BATCH_SIZE_ARG).contains(&self.batch_size) && self.batch_size <= self.count,
            "batch_size is out of range",
        )?;
        check(
            self.route != Route::Wire || self.batch_size <= wire::WIRE_MAX_BATCH_SIZE,
            "batch_size is out of range for the wire route",
        )?;
        check(
            (1..=MAX_FILE_SIZE).contains(&self.file_size),
            "file_size is out of range",
        )?;
        check(
            (1..=MAX_TRIALS).contains(&self.trials),
            "trials is out of range",
        )?;
        check(
            (1..=MAX_TRIAL_TIMEOUT_SECS).contains(&self.trial_timeout.as_secs()),
            "trial_timeout is out of range",
        )?;
        check(
            (1..=MAX_TIMEOUT_SECS).contains(&self.timeout.as_secs()),
            "timeout is out of range",
        )
    }

    fn is_every_k(&self) -> bool {
        self.batch_size > 1
    }
}

/// 解釈済みのコマンド。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 引数なし。小さい固定件数で 1 回だけ走り、結果を標準出力へ出す。
    Smoke,
    Run {
        plan: Plan,
        root: PathBuf,
        output: PathBuf,
    },
}

fn parse_range(name: &str, value: &str, lo: u64, hi: u64) -> Result<u64, SmallFilesError> {
    let n: u64 = value
        .parse()
        .map_err(|_| SmallFilesError::args(format!("invalid value for {name}")))?;
    if n < lo || n > hi {
        return Err(SmallFilesError::args(format!(
            "value for {name} is out of range {lo}..={hi}"
        )));
    }
    Ok(n)
}

/// 引数（プログラム名を除く）を解釈し、副作用の前に範囲を検証する（REPAIR-5・coding-rust）。
///
/// `--bench` は cargo が付与するため無視する。未知・重複・値の欠落・範囲外は `invalid-args`。
pub fn parse_args(args: &[String]) -> Result<Command, SmallFilesError> {
    let mut seen: Vec<&str> = Vec::new();
    let mut count = MIN_COUNT;
    let mut batch_size = 1;
    let mut file_size = DEFAULT_FILE_SIZE;
    let mut layout_arg: Option<Layout> = None;
    let mut config = Config::Bind;
    let mut route = Route::ServerApi;
    let mut trials = DEFAULT_TRIALS;
    let mut root: Option<PathBuf> = None;
    let mut trial_timeout = DEFAULT_TRIAL_TIMEOUT_SECS;
    let mut timeout = DEFAULT_TIMEOUT_SECS;
    let mut output: Option<PathBuf> = None;

    let mut iter = args.iter().filter(|a| a.as_str() != "--bench");
    while let Some(arg) = iter.next() {
        let name = arg.as_str();
        const KNOWN: [&str; 11] = [
            "--count",
            "--batch-size",
            "--file-size",
            "--layout",
            "--config",
            "--route",
            "--trials",
            "--root",
            "--trial-timeout-secs",
            "--timeout-secs",
            "--output",
        ];
        let Some(known) = KNOWN.iter().find(|k| **k == name) else {
            return Err(SmallFilesError::args("unknown argument"));
        };
        if seen.contains(known) {
            return Err(SmallFilesError::args(format!("duplicate option {known}")));
        }
        seen.push(known);
        let Some(value) = iter.next() else {
            return Err(SmallFilesError::args(format!("missing value for {known}")));
        };
        match *known {
            "--count" => count = parse_range(known, value, MIN_COUNT, MAX_COUNT)?,
            "--batch-size" => batch_size = parse_range(known, value, 1, MAX_BATCH_SIZE_ARG)?,
            "--file-size" => file_size = parse_range(known, value, 1, MAX_FILE_SIZE)?,
            "--layout" => {
                layout_arg = match value.as_str() {
                    "auto" => None,
                    "flat" => Some(Layout::Flat),
                    "tree" => Some(Layout::Tree),
                    _ => return Err(SmallFilesError::args("invalid value for --layout")),
                }
            }
            "--config" => {
                config = match value.as_str() {
                    "bind" => Config::Bind,
                    "named-volume" => Config::NamedVolume,
                    _ => return Err(SmallFilesError::args("invalid value for --config")),
                }
            }
            "--route" => {
                route = match value.as_str() {
                    "wire" => Route::Wire,
                    "server-api" => Route::ServerApi,
                    _ => return Err(SmallFilesError::args("invalid value for --route")),
                }
            }
            "--trials" => trials = parse_range(known, value, 1, MAX_TRIALS)?,
            "--root" => root = Some(PathBuf::from(value)),
            "--trial-timeout-secs" => {
                trial_timeout = parse_range(known, value, 1, MAX_TRIAL_TIMEOUT_SECS)?;
            }
            "--timeout-secs" => timeout = parse_range(known, value, 1, MAX_TIMEOUT_SECS)?,
            _ => output = Some(PathBuf::from(value)),
        }
    }

    if seen.is_empty() {
        return Ok(Command::Smoke);
    }
    let Some(output) = output else {
        return Err(SmallFilesError::args("--output is required"));
    };
    if batch_size > count {
        return Err(SmallFilesError::args(
            "--batch-size must not exceed --count",
        ));
    }
    if route == Route::Wire && batch_size > wire::WIRE_MAX_BATCH_SIZE {
        return Err(SmallFilesError::args(
            "--batch-size is out of range for --route wire",
        ));
    }
    let layout = layout_arg.unwrap_or(if count <= AUTO_FLAT_MAX {
        Layout::Flat
    } else {
        Layout::Tree
    });
    Ok(Command::Run {
        plan: Plan {
            count,
            batch_size,
            file_size,
            layout,
            config,
            route,
            trials,
            trial_timeout: Duration::from_secs(trial_timeout),
            timeout: Duration::from_secs(timeout),
        },
        root: root.unwrap_or_else(std::env::temp_dir),
        output,
    })
}

/// `i` 番目（0 起点）のファイルのゲスト相対パス（`/` 区切り。小文字と数字だけ）。
pub fn guest_path(layout: Layout, i: u64) -> String {
    match layout {
        Layout::Flat => format!("f{i:05}"),
        Layout::Tree => format!("d{:03}/f{:03}", i / DIR_CAPACITY, i % DIR_CAPACITY),
    }
}

/// 全ファイルで使い回す Write のバッチを公開 API だけで組み立てる（REPAIR-2）。
fn build_write_batch(file_size: u64) -> Result<fandhe_container_io::Batch, SmallFilesError> {
    let len = usize::try_from(file_size)
        .map_err(|_| SmallFilesError::args("file size is out of range"))?;
    let body = vec![b'f'; len];
    let limit = InFlightLimit::new(1).map_err(|e| from_io(&e))?;
    let mut queue = SendQueue::new(limit);
    let req = queue.register(FrameKind::Write).map_err(|e| from_io(&e))?;
    let frame = encode_request(FrameKind::Write, WireRequestId::from(req.id()), &body)
        .map_err(|e| from_io(&e))?;
    let mut buffer = BatchBuffer::new(BatchConfig::new(1).map_err(|e| from_io(&e))?);
    match buffer.push(frame).map_err(|e| from_io(&e))? {
        PushOutcome::Ready(batch) => Ok(batch),
        _ => Err(SmallFilesError::new(
            "write-failed",
            "write batch did not fire",
        )),
    }
}

/// `deadline` までの残り時間から永続化の期限を作る。残りが無ければ `timeout`。
fn flush_timeout(deadline: Instant) -> Result<IoTimeout, SmallFilesError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SmallFilesError::new("timeout", "deadline exceeded"));
    }
    IoTimeout::new(remaining.min(MAX_IO_TIMEOUT)).map_err(|e| from_io(&e))
}

/// 1 試行（計測区間）を `plan.route` の経路で実行して所要時間を返す。`trial_root` は存在する
/// ディレクトリ。
pub fn run_trial(
    trial_root: &Path,
    plan: &Plan,
    trial_deadline: Instant,
    overall_deadline: Instant,
) -> Result<Duration, SmallFilesError> {
    match plan.route {
        Route::ServerApi => {
            run_trial_server_api(trial_root, plan, trial_deadline, overall_deadline)
        }
        Route::Wire => wire::run_trial(trial_root, plan, trial_deadline, overall_deadline),
    }
}

/// `server-api` 経路の 1 試行（計測区間）。
///
/// 試行の期限 `trial_deadline` と全体の期限 `overall_deadline` を各ファイルの処理の前に照合する
/// （協調的。モジュール doc 参照）。永続化は `plan.batch_size` 件ごと（と最後）に行う。
fn run_trial_server_api(
    trial_root: &Path,
    plan: &Plan,
    trial_deadline: Instant,
    overall_deadline: Instant,
) -> Result<Duration, SmallFilesError> {
    plan.validate()?;
    check_environment(plan)?;
    // 区間の外: Batch の組み立てと creator の構築。
    let batch = build_write_batch(plan.file_size)?;
    let creator = GuestFileCreator::new(trial_root.to_path_buf()).map_err(|e| from_io(&e))?;
    let deadline = trial_deadline.min(overall_deadline);

    let start = Instant::now();
    for i in 0..plan.count {
        if Instant::now() >= deadline {
            return Err(SmallFilesError::new("timeout", "deadline exceeded"));
        }
        let mut sink = creator
            .create_file(&guest_path(plan.layout, i))
            .map_err(|e| from_io(&e))?;
        let report = sink.write_batch(&batch).map_err(|e| from_io(&e))?;
        if report.frames_written != 1 || report.bytes_written != plan.file_size {
            return Err(SmallFilesError::new(
                "write-failed",
                "unexpected write report",
            ));
        }
        // i + 1 は count <= 50,000 のため溢れない。
        let flush_here = (i + 1) % plan.batch_size == 0 || i + 1 == plan.count;
        if flush_here {
            let mut sink = sink.with_flush_timeout(flush_timeout(deadline)?);
            sink.persist().map_err(|e| from_io(&e))?;
        }
    }
    Ok(start.elapsed())
}

/// 作業用の専用サブディレクトリ。`Drop` で自分が作ったものだけを消す（symlink は辿らない）。
struct WorkDir {
    path: PathBuf,
    /// `cleanup` が成功済みなら `true`（`Drop` の再試行を省く）。
    cleaned: bool,
    #[cfg(unix)]
    id: (u64, u64),
    /// Windows では `FILE_SHARE_DELETE` なしでディレクトリのハンドルを保持し、測定中の改名・差し替えを
    /// OS に拒否させる（安定版 std には volume serial / file index が無く、`unsafe` / 新規依存も使わないため）。
    #[cfg(windows)]
    guard: Option<std::fs::File>,
}

impl WorkDir {
    fn create(root: &Path) -> Result<Self, SmallFilesError> {
        Self::create_with_prefix(root, "fandhe-small-files")
    }

    /// 接頭辞を指定して作る（wire 経路のソケット用は `sun_path` に収めるため短い接頭辞を使う）。
    fn create_with_prefix(root: &Path, prefix: &str) -> Result<Self, SmallFilesError> {
        let meta = std::fs::metadata(root);
        match meta {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(SmallFilesError::args("--root must be a directory")),
            Err(_) => return Err(SmallFilesError::args("--root is not accessible")),
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = root.join(format!("{prefix}-{}-{nanos:x}", std::process::id()));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|e| from_fs(&e))?;
        #[cfg(unix)]
        let id = {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(&path).map_err(|e| from_fs(&e))?;
            (m.dev(), m.ino())
        };
        #[cfg(windows)]
        let guard = {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_BACKUP_SEMANTICS（ディレクトリを開く）・FILE_READ_ATTRIBUTES・
            // 共有は READ|WRITE のみ（DELETE を含めない = 改名・削除が共有違反になる）。
            let f = std::fs::OpenOptions::new()
                .access_mode(0x0080)
                .share_mode(0x1 | 0x2)
                .custom_flags(0x0200_0000)
                .open(&path)
                .map_err(|e| from_fs(&e))?;
            Some(f)
        };
        Ok(Self {
            path,
            cleaned: false,
            #[cfg(unix)]
            id,
            #[cfg(windows)]
            guard,
        })
    }
}

impl WorkDir {
    /// 作業ディレクトリを削除し、失敗を `cleanup-failed` で返す（REPAIR-4）。
    ///
    /// 成功経路ではこれを明示的に呼び、100 万ファイル規模の残骸を黙って残さない。成功するまで
    /// 何度でも呼べる（失敗時は `Drop` が補助的に再試行する）。
    fn cleanup(&mut self) -> Result<(), SmallFilesError> {
        if self.cleaned {
            return Ok(());
        }
        // Windows: ハンドルを保持していた間は改名・差し替えが不可能だったため同一性は保証済み。
        // 削除のため、ここでハンドルを閉じる。
        #[cfg(windows)]
        drop(self.guard.take());
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.cleaned = true;
                return Ok(());
            }
            Err(_) => return Err(cleanup_failed()),
        };
        // symlink 等に差し替わっていたら消さずに残し、残置を報告する。
        if !meta.is_dir() {
            return Err(cleanup_failed());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (meta.dev(), meta.ino()) != self.id {
                return Err(cleanup_failed());
            }
        }
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(_) => Err(cleanup_failed()),
        }
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        // 明示 cleanup が済んでいない経路（早期 return・panic）の補助的な再試行。
        // Drop では失敗を報告できないため結果は捨てる。
        let _ = self.cleanup();
    }
}

/// 後始末の失敗（パス・OS 文字列は載せない。REPAIR-4）。
fn cleanup_failed() -> SmallFilesError {
    SmallFilesError::new(
        "cleanup-failed",
        "failed to remove the work directory; leftover files may remain under --root",
    )
}

/// 本来の結果 `result` と後始末の結果 `cleanup` を合成する。
///
/// 後始末が失敗していれば、成功結果は値を出さず `cleanup-failed` にする。既存のエラーがある場合は
/// そのエラーを主とし、message に後始末の失敗を併記する。
fn merge_cleanup<T>(
    result: Result<T, SmallFilesError>,
    cleanup: Result<(), SmallFilesError>,
) -> Result<T, SmallFilesError> {
    match (result, cleanup) {
        (Ok(v), Ok(())) => Ok(v),
        (Ok(_), Err(c)) => Err(c),
        (Err(e), Ok(())) => Err(e),
        (Err(mut e), Err(c)) => {
            e.message = format!("{}; also {}", e.message, c.message);
            Err(e)
        }
    }
}

/// 1 試行の結果。
#[derive(Debug, Clone, PartialEq)]
pub struct TrialResult {
    pub elapsed_ns: u64,
    pub files_per_sec: f64,
}

/// 全試行の結果。
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    pub trials: Vec<TrialResult>,
    pub median_files_per_sec: f64,
}

/// files/s を求める。elapsed が 0、または結果が有限の正の数でなければ `invalid-measurement`。
pub fn files_per_sec(count: u64, elapsed: Duration) -> Result<f64, SmallFilesError> {
    let secs = elapsed.as_secs_f64();
    let value = count as f64 / secs;
    if secs <= 0.0 || !value.is_finite() || value <= 0.0 {
        return Err(SmallFilesError::new(
            "invalid-measurement",
            "elapsed time is not usable",
        ));
    }
    Ok(value)
}

/// 中央値（偶数個なら中央 2 つの平均）。空なら `None`。
pub fn median(values: &[f64]) -> Option<f64> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    let mid = n / 2;
    if n % 2 == 1 {
        sorted.get(mid).copied()
    } else {
        let lo = sorted.get(mid - 1)?;
        let hi = sorted.get(mid)?;
        Some((lo + hi) / 2.0)
    }
}

/// 永続化の対応状況と FLUSH 方式を、ファイルを作る前に検査する（`run_trial` と
/// `run_with_deadline` が共有する）。
fn check_environment(plan: &Plan) -> Result<(), SmallFilesError> {
    if plan.route == Route::Wire {
        return wire::check_environment();
    }
    if !persist_support().is_supported() {
        return Err(SmallFilesError::new(
            "persist-unsupported",
            "persist is not supported on this host",
        ));
    }
    if plan.is_every_k() && persist_support() != PersistSupport::Supported {
        return Err(SmallFilesError::new(
            "unsupported-flush-mode",
            "flush-every-k requires syncfs support (Linux 5.8 or later)",
        ));
    }
    Ok(())
}

/// 計画を `root` の下で実行する。全体の期限は呼び出し時点から `plan.timeout`。
pub fn run(plan: &Plan, root: &Path) -> Result<Measurement, SmallFilesError> {
    plan.validate()?;
    let deadline = Instant::now()
        .checked_add(plan.timeout)
        .ok_or_else(|| SmallFilesError::args("timeout is out of range"))?;
    run_with_deadline(plan, root, deadline)
}

/// [`run`] の全体期限を明示する版。
pub fn run_with_deadline(
    plan: &Plan,
    root: &Path,
    overall_deadline: Instant,
) -> Result<Measurement, SmallFilesError> {
    plan.validate()?;
    check_environment(plan)?;
    let mut work = WorkDir::create(root)?;
    let result = run_trials(plan, &work.path, overall_deadline);
    let cleanup = work.cleanup();
    merge_cleanup(result, cleanup)
}

/// `work_path` の下で全試行を実行する（後始末は呼び出し側の `WorkDir` が担う）。
fn run_trials(
    plan: &Plan,
    work_path: &Path,
    overall_deadline: Instant,
) -> Result<Measurement, SmallFilesError> {
    let mut trials = Vec::with_capacity(usize::try_from(plan.trials).unwrap_or(0));
    for n in 0..plan.trials {
        let trial_root = work_path.join(format!("trial-{n}"));
        std::fs::create_dir(&trial_root).map_err(|e| from_fs(&e))?;
        let trial_deadline = Instant::now()
            .checked_add(plan.trial_timeout)
            .ok_or_else(|| SmallFilesError::args("trial timeout is out of range"))?;
        let elapsed = run_trial(&trial_root, plan, trial_deadline, overall_deadline)?;
        std::fs::remove_dir_all(&trial_root).map_err(|_| cleanup_failed())?;
        // 後始末（最大 5 万ファイルの削除）で全体期限を超えうるため、値を採用する前に再確認する（REPAIR-5）。
        ensure_before(overall_deadline)?;
        trials.push(TrialResult {
            elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            files_per_sec: files_per_sec(plan.count, elapsed)?,
        });
    }
    let values: Vec<f64> = trials.iter().map(|t| t.files_per_sec).collect();
    let median_files_per_sec =
        median(&values).ok_or_else(|| SmallFilesError::new("invalid-measurement", "no trials"))?;
    // 成功を返す直前にも再確認する。超過していれば値を出さず timeout にする（REPAIR-5）。
    ensure_before(overall_deadline)?;
    Ok(Measurement {
        trials,
        median_files_per_sec,
    })
}

/// 全体期限 `deadline` を過ぎていれば `timeout` を返す（REPAIR-5）。
pub fn ensure_before(deadline: Instant) -> Result<(), SmallFilesError> {
    if Instant::now() >= deadline {
        return Err(SmallFilesError::new("timeout", "deadline exceeded"));
    }
    Ok(())
}

/// 結果 JSON（`scripts/check-bench-regression.sh` の results スキーマと互換）。
///
/// 文字列は enum と定数に由来するものだけで、パス・ホスト名・ユーザー名は含まない。
pub fn results_json(plan: &Plan, support: PersistSupport, m: &Measurement) -> String {
    let (method, note, guaranteed) = match (plan.route, plan.is_every_k()) {
        (Route::ServerApi, true) => (METHOD_EVERY_K, NOTE_EVERY_K, false),
        (Route::ServerApi, false) => (METHOD_PER_FILE, NOTE_PER_FILE, true),
        (Route::Wire, true) => (METHOD_WIRE_EVERY_K, NOTE_WIRE_EVERY_K, false),
        (Route::Wire, false) => (METHOD_WIRE_PER_FILE, NOTE_WIRE_PER_FILE, true),
    };
    let wire_path = plan.route == Route::Wire;
    let server_batch = if wire_path {
        format!(", \"server_batch_size\": {}", wire::WIRE_SERVER_BATCH)
    } else {
        String::new()
    };
    let support = match support {
        PersistSupport::Supported => "supported",
        PersistSupport::SupportedFileSync => "supported-file-sync",
        _ => "unsupported",
    };
    let mut s = String::new();
    // String への write! は失敗しない。
    let _ = write!(
        s,
        "{{\n  \"schema_version\": 1,\n  \"metrics\": {{ \"{METRIC_NAME}\": {{ \"value\": {:.3}, \"unit\": \"{METRIC_UNIT}\" }} }},\n  \"method\": \"{method}\",\n  \"wire_path\": {wire_path},\n  \"io2_guaranteed\": {guaranteed},\n  \"note\": \"{note}\",\n  \"aggregate\": \"median\",\n  \"persist_support\": \"{support}\",\n  \"params\": {{ \"count\": {}, \"batch_size\": {}, \"file_size_bytes\": {}, \"layout\": \"{}\", \"config\": \"{}\", \"route\": \"{}\"{server_batch}, \"trials\": {}, \"trial_timeout_secs\": {}, \"timeout_secs\": {} }},\n  \"trials\": [",
        m.median_files_per_sec,
        plan.count,
        plan.batch_size,
        plan.file_size,
        plan.layout.as_str(),
        plan.config.as_str(),
        plan.route.as_str(),
        plan.trials,
        plan.trial_timeout.as_secs(),
        plan.timeout.as_secs(),
    );
    for (i, t) in m.trials.iter().enumerate() {
        let sep = if i == 0 { "" } else { "," };
        let _ = write!(
            s,
            "{sep}\n    {{ \"elapsed_ns\": {}, \"files_per_sec\": {:.3} }}",
            t.elapsed_ns, t.files_per_sec
        );
    }
    s.push_str("\n  ]\n}\n");
    s
}

/// 実行結果（入口が出力先へ書く）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Execution {
    /// 永続化に対応しない環境のスモーク。値は出さず、メッセージだけ出して成功終了する。
    Skipped,
    /// 結果 JSON と、`--output` があればその書き出し先。
    Done {
        json: String,
        output: Option<PathBuf>,
    },
}

/// 解釈済みのコマンドを実行する。
pub fn execute(command: Command) -> Result<Execution, SmallFilesError> {
    let support = persist_support();
    let (plan, root, output) = match command {
        Command::Smoke => {
            if !support.is_supported() {
                return Ok(Execution::Skipped);
            }
            (Plan::smoke(), std::env::temp_dir(), None)
        }
        Command::Run { plan, root, output } => (plan, root, Some(output)),
    };
    let m = run(&plan, &root)?;
    Ok(Execution::Done {
        json: results_json(&plan, support, &m),
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// IO-6: 公開の実行入口は不正な計画を副作用の前に構造化エラーで拒否する。
    #[test]
    fn invalid_plan_is_rejected_before_side_effects() {
        let bad = [
            Plan {
                batch_size: 0,
                ..Plan::smoke()
            },
            Plan {
                file_size: 0,
                ..Plan::smoke()
            },
            Plan {
                file_size: MAX_FILE_SIZE + 1,
                ..Plan::smoke()
            },
            Plan {
                trials: MAX_TRIALS + 1,
                ..Plan::smoke()
            },
            Plan {
                count: MAX_COUNT + 1,
                ..Plan::smoke()
            },
        ];
        let root = std::env::temp_dir();
        let now = Instant::now();
        for plan in &bad {
            assert_eq!(
                run_trial(&root, plan, now, now).unwrap_err().code,
                "invalid-args"
            );
            assert_eq!(run(plan, &root).unwrap_err().code, "invalid-args");
        }
    }

    fn run_plan(v: &[&str]) -> (Plan, PathBuf, PathBuf) {
        match parse_args(&args(v)) {
            Ok(Command::Run { plan, root, output }) => (plan, root, output),
            other => panic!("unexpected: {other:?}"),
        }
    }

    fn code(v: &[&str]) -> &'static str {
        parse_args(&args(v)).expect_err("must be rejected").code
    }

    /// REPAIR-5: 後始末後の再確認。期限超過なら `timeout`、期限内なら通る。
    #[test]
    fn repair5_ensure_before_rejects_expired_deadline() {
        let past = Instant::now();
        assert_eq!(ensure_before(past).unwrap_err().code, "timeout");
        let future = Instant::now() + Duration::from_secs(60);
        assert!(ensure_before(future).is_ok());
    }

    /// IO-6: 配置は決定的で、全ディレクトリが 256 件以内に収まる。
    #[test]
    fn io6_guest_path_flat_and_tree_are_deterministic() {
        assert_eq!(guest_path(Layout::Flat, 0), "f00000");
        assert_eq!(guest_path(Layout::Flat, 49_999), "f49999");
        assert_eq!(guest_path(Layout::Tree, 0), "d000/f000");
        assert_eq!(guest_path(Layout::Tree, 257), "d001/f001");
        assert_eq!(guest_path(Layout::Tree, 49_999), "d195/f079");
        let mut dirs: std::collections::BTreeMap<String, u64> = Default::default();
        for i in 0..50_000 {
            let p = guest_path(Layout::Tree, i);
            let (d, _) = p.split_once('/').expect("tree path has a directory");
            *dirs.entry(d.to_string()).or_default() += 1;
        }
        assert_eq!(dirs.len(), 196);
        assert!(dirs.values().all(|n| *n <= 256));
    }

    /// IO-6: `--layout auto` は 2,000 件以下で平置き、超えるとツリー。
    #[test]
    fn io6_layout_auto_defaults() {
        let layout = |count: &str| run_plan(&["--count", count, "--output", "o"]).0.layout;
        assert_eq!(layout("2000"), Layout::Flat);
        assert_eq!(layout("2001"), Layout::Tree);
        assert_eq!(layout("50000"), Layout::Tree);
    }

    /// REPAIR-8: files/s は具体値で求まり、0 秒は拒否する。
    #[test]
    fn repair8_files_per_sec_concrete() {
        assert_eq!(
            files_per_sec(2_000, Duration::from_millis(1_250)).unwrap(),
            1600.0
        );
        assert_eq!(
            files_per_sec(50_000, Duration::from_secs(40)).unwrap(),
            1250.0
        );
        assert_eq!(
            files_per_sec(10, Duration::ZERO).unwrap_err().code,
            "invalid-measurement"
        );
    }

    /// REPAIR-8: 中央値（奇数・偶数・1 個）。
    #[test]
    fn repair8_median_concrete() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert_eq!(median(&[7.0]), Some(7.0));
        assert_eq!(median(&[]), None);
    }

    /// REPAIR-8: 引数なし・`--bench` だけはスモーク、既定値と各オプションの反映。
    #[test]
    fn repair8_parse_args_defaults_and_smoke() {
        assert_eq!(parse_args(&args(&[])).unwrap(), Command::Smoke);
        assert_eq!(parse_args(&args(&["--bench"])).unwrap(), Command::Smoke);
        let (plan, root, output) = run_plan(&["--bench", "--output", "out.json"]);
        assert_eq!(plan.count, 2_000);
        assert_eq!(plan.batch_size, 1);
        assert_eq!(plan.file_size, 2);
        assert_eq!(plan.layout, Layout::Flat);
        assert_eq!(plan.config, Config::Bind);
        assert_eq!(plan.trials, 5);
        assert_eq!(plan.trial_timeout, Duration::from_secs(1_800));
        assert_eq!(plan.timeout, Duration::from_secs(10_800));
        assert_eq!(root, std::env::temp_dir());
        assert_eq!(output, PathBuf::from("out.json"));

        let (plan, root, _) = run_plan(&[
            "--count",
            "30000",
            "--batch-size",
            "8",
            "--file-size",
            "100",
            "--layout",
            "flat",
            "--config",
            "named-volume",
            "--trials",
            "3",
            "--root",
            "r",
            "--trial-timeout-secs",
            "9",
            "--timeout-secs",
            "99",
            "--output",
            "o",
        ]);
        assert_eq!(plan.count, 30_000);
        assert_eq!(plan.batch_size, 8);
        assert_eq!(plan.file_size, 100);
        assert_eq!(plan.layout, Layout::Flat);
        assert_eq!(plan.config, Config::NamedVolume);
        assert_eq!(plan.trials, 3);
        assert_eq!(plan.trial_timeout, Duration::from_secs(9));
        assert_eq!(plan.timeout, Duration::from_secs(99));
        assert_eq!(root, PathBuf::from("r"));
    }

    /// REPAIR-8: 範囲外・未知・欠落・重複は副作用の前に `invalid-args`。
    #[test]
    fn repair8_parse_args_rejects_invalid() {
        let cases: &[&[&str]] = &[
            &["--count", "1999", "--output", "o"],
            &["--count", "50001", "--output", "o"],
            &["--count", "x", "--output", "o"],
            &["--trials", "0", "--output", "o"],
            &["--trials", "21", "--output", "o"],
            &["--batch-size", "0", "--output", "o"],
            &["--batch-size", "4097", "--output", "o"],
            &["--batch-size", "2001", "--output", "o"],
            &["--file-size", "0", "--output", "o"],
            &["--file-size", "65537", "--output", "o"],
            &["--timeout-secs", "0", "--output", "o"],
            &["--trial-timeout-secs", "7201", "--output", "o"],
            &["--layout", "x", "--output", "o"],
            &["--config", "x", "--output", "o"],
            &["--wat"],
            &["--count"],
            &["--count", "2000", "--count", "2000", "--output", "o"],
            &["--count", "3000"],
        ];
        for case in cases {
            assert_eq!(code(case), "invalid-args", "case: {case:?}");
        }
    }

    /// REPAIR-8: 結果 JSON のスキーマと method の具体値（per-file）。
    #[test]
    fn repair8_results_json_schema_and_method() {
        let plan = Plan {
            count: 2_000,
            ..Plan::smoke()
        };
        let m = Measurement {
            trials: vec![
                TrialResult {
                    elapsed_ns: 1_000_000_000,
                    files_per_sec: 2000.0,
                },
                TrialResult {
                    elapsed_ns: 2_000_000_000,
                    files_per_sec: 1000.0,
                },
            ],
            median_files_per_sec: 1500.0,
        };
        let json = results_json(&plan, PersistSupport::Supported, &m);
        for needle in [
            "\"schema_version\": 1",
            "\"small_files_files_per_sec\": { \"value\": 1500.000, \"unit\": \"files/s\" }",
            "\"method\": \"server-api-direct/flush-per-file\"",
            "\"wire_path\": false",
            "\"io2_guaranteed\": true",
            "\"aggregate\": \"median\"",
            "\"persist_support\": \"supported\"",
            "\"count\": 2000",
            "\"batch_size\": 1",
            "\"file_size_bytes\": 2",
            "\"layout\": \"flat\"",
            "\"config\": \"bind\"",
            "\"trials\": 1",
            "{ \"elapsed_ns\": 1000000000, \"files_per_sec\": 2000.000 }",
            "{ \"elapsed_ns\": 2000000000, \"files_per_sec\": 1000.000 }",
        ] {
            assert!(json.contains(needle), "missing {needle} in {json}");
        }
        assert_eq!(json.matches("\"elapsed_ns\"").count(), 2);
        assert!(!json.contains('\\') && !json.contains("\"/"));

        let k = Plan {
            batch_size: 4,
            ..plan
        };
        let json = results_json(&k, PersistSupport::Supported, &m);
        assert!(json.contains("\"method\": \"server-api-direct/flush-every-k\""));
        assert!(json.contains("\"io2_guaranteed\": false"));
        assert!(json.contains("outside IO-2 guarantee"));
        assert!(json.contains("\"route\": \"server-api\""));
    }

    /// REPAIR-8・#2074: wire 経路の method・wire_path・route・保証の扱い。
    #[test]
    fn repair8_results_json_wire_method() {
        let m = Measurement {
            trials: vec![TrialResult {
                elapsed_ns: 1_000_000_000,
                files_per_sec: 2000.0,
            }],
            median_files_per_sec: 2000.0,
        };
        let per_file = Plan {
            count: 2_000,
            route: Route::Wire,
            ..Plan::smoke()
        };
        let json = results_json(&per_file, PersistSupport::Supported, &m);
        for needle in [
            "\"method\": \"wire-uds/flush-per-file\"",
            "\"wire_path\": true",
            "\"io2_guaranteed\": true",
            "\"route\": \"wire\", \"server_batch_size\": 64",
        ] {
            assert!(json.contains(needle), "missing {needle} in {json}");
        }
        let every_k = Plan {
            batch_size: 4,
            ..per_file
        };
        let json = results_json(&every_k, PersistSupport::Supported, &m);
        assert!(json.contains("\"method\": \"wire-uds/flush-every-k\""));
        assert!(json.contains("\"io2_guaranteed\": false"));
        assert!(json.contains("\"wire_path\": true"));
    }

    /// REPAIR-8・#2074: `--route` の解釈と、wire の K の上限。
    #[test]
    fn repair8_parse_args_route() {
        let run = |extra: &[&str]| {
            let mut v = vec!["--output", "/x/out.json"];
            v.extend_from_slice(extra);
            parse_args(&args(&v))
        };
        let route_of = |extra: &[&str]| match run(extra).unwrap() {
            Command::Run { plan, .. } => plan.route,
            Command::Smoke => unreachable!(),
        };
        assert_eq!(route_of(&[]), Route::ServerApi);
        assert_eq!(route_of(&["--route", "wire"]), Route::Wire);
        assert_eq!(route_of(&["--route", "server-api"]), Route::ServerApi);
        for bad in [
            &["--route", "udp"][..],
            &["--route"][..],
            &["--route", "wire", "--route", "wire"][..],
        ] {
            assert_eq!(run(bad).unwrap_err().code, "invalid-args");
        }
        let k =
            |route: &str, k: &str| run(&["--count", "5000", "--route", route, "--batch-size", k]);
        assert!(k("wire", "4095").is_ok());
        assert_eq!(k("wire", "4096").unwrap_err().code, "invalid-args");
        assert!(k("server-api", "4096").is_ok());
        let bad_plan = Plan {
            route: Route::Wire,
            count: 5_000,
            batch_size: 4_096,
            ..Plan::smoke()
        };
        assert_eq!(bad_plan.validate().unwrap_err().code, "invalid-args");
    }

    /// REPAIR-3: エラーの JSON は固定の形で、パスを含まない。
    #[test]
    fn repair3_error_display_is_structured() {
        let e = SmallFilesError::new("timeout", "deadline exceeded");
        assert_eq!(
            e.to_string(),
            "{\"error\":{\"code\":\"timeout\",\"message\":\"deadline exceeded\"}}"
        );
    }

    /// REPAIR-4: 後始末の失敗は成功結果を握りつぶさず、既存エラーには併記される。
    #[test]
    fn merge_cleanup_reports_cleanup_failure() {
        let e = merge_cleanup(Ok(1_u8), Err(cleanup_failed())).unwrap_err();
        assert_eq!(e.code, "cleanup-failed");
        let e = merge_cleanup::<u8>(
            Err(SmallFilesError::new("timeout", "deadline exceeded")),
            Err(cleanup_failed()),
        )
        .unwrap_err();
        assert_eq!(e.code, "timeout");
        assert!(
            e.message
                .contains("also failed to remove the work directory")
        );
        assert_eq!(merge_cleanup(Ok(7_u8), Ok(())).unwrap(), 7);
    }

    /// REPAIR-4: 明示 cleanup は作業ディレクトリを消し、2 回目も成功する。
    #[test]
    fn work_dir_cleanup_removes_directory() {
        let base = std::env::temp_dir();
        let mut work = WorkDir::create(&base).unwrap();
        let path = work.path.clone();
        std::fs::write(path.join("f"), b"x").unwrap();
        work.cleanup().unwrap();
        assert!(!path.exists());
        work.cleanup().unwrap();
    }
}
