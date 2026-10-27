//! macOS VM の cold start 計測ハーネス（MAC-2・MAC-1・REPAIR-4・REPAIR-5・REPAIR-12。TASK-70 〔#381〕の準備・TASK-64 追補・#1879）。
//!
//! 役割: 実機 macOS で `Vm::launch`（platform-macos の公開 API）を試行ごとに新しい VM で呼び、
//! 起動完了マーカー（ready）がコンソールログに現れるまでの時間を複数回測って JSON で出す。
//! 実測と合否（2 秒以内か）の判定は #381（人間担当）が行う。本ハーネスは合否を出さない。
//!
//! 計測区間（暫定。オーナー確認待ち。MAC-2 は区間を定めていない。詳細は `docs/design/macos-vm-cold-start-bench.md`）:
//! - 始点: `Vm::launch` を呼ぶ直前。終点: watcher がコンソールログから ready マーカー（ブートマーカーより後）を
//!   読み取った直後。
//! - 区間に入る: `Vm::launch` の中身すべて（VZ 構成の構築・VM 生成・start 完了待ち）とゲストのブートから ready の出力まで。
//! - 区間に入らない: spec の組み立て・scratch の作成・watcher の起動・stop と停止確認。
//! - 終点の分解能: watcher は名目 1 ms 間隔でログを読む。ready を観測した読み取りと直前の読み取りの時刻差を
//!   `end_window` として試行ごとに出す（ホスト側の pipe → ファイルの遅れは含まれず、計測していない）。
//!
//! `make bench-macos-cold-start`（`benches/tests/macos_cold_start.rs`・TASK-113.4・PLUG-6）とは別の計測である。
//! あちらは模擬制御コアで plugin 境界の上乗せだけを測り、実 VM を起動しない。本ハーネスは plugin
//! （`fandhe-container-plugin-macos`）を経由する cold start も測らない（範囲外）。
//!
//! 二層構成: 純粋ロジック（引数の検証・集計・JSON 整形・マーカー走査・watcher）は全 OS の既定集合で具体値を照合する。
//! 実 VM を起動する 1 件は macOS 限定の `#[ignore]` で分離する（実機 macOS 13 以上・
//! `com.apple.security.virtualization` 付き署名・ゲスト資産が要る。CI 通過のための弱体化ではない）。手順は AGENTS.md。

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// 利用箇所は macOS 限定の実 VM 試験だけなので、宣言自体を macOS に限る（dead_code の抑止を使わない）。
#[cfg(target_os = "macos")]
#[path = "support/guest_markers.rs"]
mod guest_markers;

/// 出力 JSON の schema 名。
const SCHEMA: &str = "fandhe-container.macos-vm-cold-start.v1";
const TRIALS_DEFAULT: u32 = 5;
const TRIALS_MIN: u32 = 5;
const TRIALS_MAX: u32 = 50;
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "実 VM 試験（macOS 限定）だけが使う")
)]
const TRIAL_TIMEOUT_DEFAULT_SECS: u64 = 60;
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "実 VM 試験（macOS 限定）だけが使う")
)]
const TRIAL_TIMEOUT_RANGE_SECS: (u64, u64) = (1, 600);
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "実 VM 試験（macOS 限定）だけが使う")
)]
const TOTAL_TIMEOUT_DEFAULT_SECS: u64 = 900;
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "実 VM 試験（macOS 限定）だけが使う")
)]
const TOTAL_TIMEOUT_RANGE_SECS: (u64, u64) = (1, 3600);
/// `fandhe_container_platform_macos::vm::MIN_OP_TIMEOUT` と同値（100 ms。これ未満の予算では VM を起動しない）。
const MIN_BUDGET: Duration = Duration::from_millis(100);
/// `Vm::launch` の start 待ちの上限（`DEFAULT_START_TIMEOUT` と同値）。
const START_TIMEOUT_CAP: Duration = Duration::from_secs(30);
/// コンソールログの名目読み取り間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(1);
/// watcher の読み込み累計の上限（書き出しスレッドの上限 1 MiB に余裕を持たせた値。無制限読み込みの防止）。
const WATCH_READ_LIMIT: usize = 2 * 1024 * 1024;

static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---- 環境変数の解決 -------------------------------------------------------------------------------

/// 試行回数を決める。未指定は 5、5〜50 の整数以外（空・非数・範囲外）は拒否する（MAC-2 は 5 回以上）。
fn resolve_trials(raw: Option<String>) -> Result<u32, String> {
    match raw {
        None => Ok(TRIALS_DEFAULT),
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|n| (TRIALS_MIN..=TRIALS_MAX).contains(n))
            .ok_or_else(|| {
                format!("trials must be an integer in {TRIALS_MIN}..={TRIALS_MAX}, got {v:?}")
            }),
    }
}

/// 秒数の環境変数を決める。未指定は既定値、範囲外・非数は拒否する（VM 起動前に拒否するため）。
fn resolve_secs(raw: Option<String>, default: u64, range: (u64, u64)) -> Result<u64, String> {
    match raw {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (range.0..=range.1).contains(n))
            .ok_or_else(|| {
                format!(
                    "seconds must be an integer in {}..={}, got {v:?}",
                    range.0, range.1
                )
            }),
    }
}

/// 1 試行の予算（試行の期限と全体の残りの小さい方）。100 ms 未満なら `None`（VM を起動しない）。
fn trial_budget(trial_timeout: Duration, total_remaining: Duration) -> Option<Duration> {
    let budget = trial_timeout.min(total_remaining);
    (budget >= MIN_BUDGET).then_some(budget)
}

/// `OpTimeouts` の start に渡す値（30 秒と予算の小さい方。予算は 100 ms 以上のため下限に収まる）。
fn start_timeout_for(budget: Duration) -> Duration {
    budget.min(START_TIMEOUT_CAP)
}

// ---- マーカーの増分走査 ---------------------------------------------------------------------------

/// 1 回の `feed` で見つかったマーカー。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ScanEvent {
    boot: bool,
    ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitBoot,
    AwaitReady,
    Done,
}

/// コンソール出力のチャンクを順に受け、ブートマーカー → ready マーカーの順の出現を検出する。
///
/// ready の探索はブートマーカー末尾より後だけに限る（`guest_markers::markers_observed_in_order` と同じ順序規則）。
/// チャンク境界をまたぐマーカーのため `carry` に末尾 `マーカー長 - 1` バイトだけを残し、メモリを一定に保つ。
struct MarkerScanner {
    boot: Vec<u8>,
    ready: Vec<u8>,
    phase: Phase,
    carry: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn tail(bytes: &[u8], keep: usize) -> Vec<u8> {
    bytes
        .get(bytes.len().saturating_sub(keep)..)
        .unwrap_or_default()
        .to_vec()
}

impl MarkerScanner {
    fn new(boot: &str, ready: &str) -> Self {
        Self {
            boot: boot.as_bytes().to_vec(),
            ready: ready.as_bytes().to_vec(),
            phase: Phase::AwaitBoot,
            carry: Vec::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) -> ScanEvent {
        let mut ev = ScanEvent::default();
        if self.phase == Phase::Done {
            return ev;
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let mut rest: &[u8] = &buf;
        if self.phase == Phase::AwaitBoot {
            match find(rest, &self.boot).and_then(|p| rest.get(p + self.boot.len()..)) {
                Some(after) => {
                    ev.boot = true;
                    self.phase = Phase::AwaitReady;
                    rest = after;
                }
                None => {
                    self.carry = tail(rest, self.boot.len().saturating_sub(1));
                    return ev;
                }
            }
        }
        if find(rest, &self.ready).is_some() {
            ev.ready = true;
            self.phase = Phase::Done;
        } else {
            self.carry = tail(rest, self.ready.len().saturating_sub(1));
        }
        ev
    }
}

// ---- コンソールログの watcher ----------------------------------------------------------------------

/// watcher から計測側への通知。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchMsg {
    /// ブートマーカーを観測した時刻。
    Boot(Instant),
    /// ready を観測した時刻と、直前の読み取りとの時刻差（終点の分解能の上限幅）。
    Ready { at: Instant, window: Duration },
    /// 読み取りの失敗（`watcher_io`）。
    Failed,
}

/// コンソールログを `poll` 間隔で追跡し、マーカーを読み取った直後の時刻を送るスレッドを起動する。
///
/// `Vm::launch` の呼び出し前に起動し、launch が戻る前に書かれた出力も取りこぼさない。`stop` か `deadline`
/// で終了し、ready を見つけた・読み取りに失敗した・累計読み込みが `WATCH_READ_LIMIT` を超えたときも終了する。
fn spawn_watcher(
    path: PathBuf,
    boot: &str,
    ready: &str,
    poll: Duration,
    deadline: Instant,
    stop: Arc<AtomicBool>,
) -> (JoinHandle<()>, Receiver<WatchMsg>) {
    let (tx, rx) = mpsc::channel();
    let mut scanner = MarkerScanner::new(boot, ready);
    let handle = std::thread::spawn(move || {
        let mut file: Option<std::fs::File> = None;
        let mut total = 0usize;
        let mut last_poll = Instant::now();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return;
            }
            // この周回の開始時刻。ready が無いと確認した読み取り（EOF）の開始より後にはならないので、
            // 次の周回で ready を見つけたときの `end_window` の始点に使える（REPAIR-4）。
            let mut iter_start = Instant::now();
            if file.is_none() {
                match std::fs::File::open(&path) {
                    Ok(f) => file = Some(f),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        let _ = tx.send(WatchMsg::Failed);
                        return;
                    }
                }
            }
            if let Some(f) = file.as_mut() {
                loop {
                    // EOF を確認する読み取りの開始時刻。ここまでに書かれた出力は読み切っていると保証できる。
                    let read_started = Instant::now();
                    match f.read(&mut buf) {
                        Ok(0) => {
                            iter_start = read_started;
                            break;
                        }
                        Ok(n) => {
                            total += n;
                            let chunk = buf.get(..n).unwrap_or_default();
                            let ev = scanner.feed(chunk);
                            let at = Instant::now();
                            if ev.boot {
                                let _ = tx.send(WatchMsg::Boot(at));
                            }
                            if ev.ready {
                                let _ = tx.send(WatchMsg::Ready {
                                    at,
                                    window: at.saturating_duration_since(last_poll),
                                });
                                return;
                            }
                            if total > WATCH_READ_LIMIT {
                                let _ = tx.send(WatchMsg::Failed);
                                return;
                            }
                        }
                        Err(_) => {
                            let _ = tx.send(WatchMsg::Failed);
                            return;
                        }
                    }
                }
            }
            last_poll = iter_start;
            std::thread::sleep(poll);
        }
    });
    (handle, rx)
}

// ---- 結果の集計と JSON ---------------------------------------------------------------------------

/// 1 試行の結果。失敗も除外せず保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
enum TrialResult {
    Ok {
        ready: Duration,
        launch_returned: Duration,
        boot_marker: Option<Duration>,
        end_window: Duration,
    },
    Err {
        code: &'static str,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    median: Duration,
    min: Duration,
    max: Duration,
}

/// 中央値・最小・最大。偶数個の中央値は真ん中 2 つの平均（ns 未満切り捨て）。空なら `None`。
fn summarize(values: &[Duration]) -> Option<Summary> {
    let mut v = values.to_vec();
    v.sort();
    let n = v.len();
    let (min, max) = (*v.first()?, *v.last()?);
    let median = if n % 2 == 1 {
        *v.get(n / 2)?
    } else {
        (*v.get(n / 2 - 1)? + *v.get(n / 2)?) / 2
    };
    Some(Summary { median, min, max })
}

/// ms 単位で小数点以下 3 桁（µs）まで。整数演算のみで浮動小数を使わない。
fn fmt_ms(d: Duration) -> String {
    let us = d.as_micros();
    format!("{}.{:03}", us / 1000, us % 1000)
}

/// 出力 JSON に埋め込むコード片を `[a-z0-9._]` だけに制限する。それ以外は `unknown`。
fn sanitize_code(s: &str) -> String {
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_');
    if ok {
        s.to_string()
    } else {
        "unknown".to_string()
    }
}

/// 出力は固定語彙と数値だけ。環境変数由来の文字列・パス・ホスト名・合否は載せない。
fn render_json(requested: u32, trials: &[TrialResult]) -> String {
    let oks: Vec<Duration> = trials
        .iter()
        .filter_map(|t| match t {
            TrialResult::Ok { ready, .. } => Some(*ready),
            TrialResult::Err { .. } => None,
        })
        .collect();
    let mut failures: BTreeMap<&str, u32> = BTreeMap::new();
    for t in trials {
        if let TrialResult::Err { code, .. } = t {
            *failures.entry(code).or_insert(0) += 1;
        }
    }
    let failed: u32 = failures.values().sum();
    let failures_json = failures
        .iter()
        .map(|(k, v)| format!("\"{k}\":{v}"))
        .collect::<Vec<_>>()
        .join(",");
    let summary = match summarize(&oks) {
        Some(s) => format!(
            "{{\"median\":{},\"min\":{},\"max\":{}}}",
            fmt_ms(s.median),
            fmt_ms(s.min),
            fmt_ms(s.max)
        ),
        None => "null".to_string(),
    };
    let trials_json = trials
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let n = i + 1;
            match t {
                TrialResult::Ok {
                    ready,
                    launch_returned,
                    boot_marker,
                    end_window,
                } => format!(
                    "{{\"trial\":{n},\"result\":\"ok\",\"ready\":{},\"launch_returned\":{},\"boot_marker\":{},\"end_window\":{}}}",
                    fmt_ms(*ready),
                    fmt_ms(*launch_returned),
                    boot_marker.map_or("null".to_string(), fmt_ms),
                    fmt_ms(*end_window)
                ),
                TrialResult::Err { code, detail } => {
                    let d = detail
                        .as_deref()
                        .map(|d| format!(",\"detail\":\"{}\"", sanitize_code(d)))
                        .unwrap_or_default();
                    format!("{{\"trial\":{n},\"result\":\"error\",\"code\":\"{code}\"{d}}}")
                }
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":\"{SCHEMA}\",\"unit\":\"ms\",\"interval\":{{\"start\":\"before-vm-launch\",\"end\":\"ready-marker-observed\"}},\"label\":{{\"path\":\"platform-macos-vm-launch\",\"vm\":\"fresh-per-trial\"}},\"poll_interval_ms\":{},\"trials_requested\":{requested},\"trials_succeeded\":{},\"trials_failed\":{failed},\"failures\":{{{failures_json}}},\"summary\":{summary},\"trials\":[{trials_json}]}}",
        POLL_INTERVAL.as_millis(),
        oks.len()
    )
}

/// `CARGO_TARGET_TMPDIR` 配下に新規ディレクトリを作る（既存を再利用・削除しない。Unix は 0700）。
fn fresh_dir(tag: &str) -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base).expect("create tmp base");
    let base = base.canonicalize().expect("canonicalize tmp base");
    for _ in 0..100 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
        if std::fs::create_dir(&dir).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod scratch dir");
            }
            return dir;
        }
    }
    panic!("could not create a fresh scratch directory");
}

// ---- 実機（macOS 限定・#[ignore]） ----------------------------------------------------------------

#[cfg(target_os = "macos")]
mod real_vm {
    use super::*;
    use fandhe_container_platform_macos::config::{
        BlockDeviceSpec, ConsoleLogPath, DeviceConfigSpec, DiskImagePath, SerialConsoleSink,
        VmConfigSpec,
    };
    use fandhe_container_platform_macos::vm::{
        DEFAULT_STATE_QUERY_TIMEOUT, DEFAULT_STOP_TIMEOUT, OpTimeouts, Vm, VmState,
    };
    use std::sync::mpsc::RecvTimeoutError;

    struct Guest {
        kernel: PathBuf,
        initrd: Option<PathBuf>,
        disk: Option<PathBuf>,
        cmdline: String,
        boot: String,
        ready: String,
    }

    fn env_path(name: &str) -> Option<PathBuf> {
        std::env::var_os(name).map(PathBuf::from)
    }

    fn env_opt(name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    /// 試行 1 回。VM を得た経路では必ず stop → `Stopped` の確認まで行う。戻り値の bool は「以降の試行を止める」。
    fn run_trial(n: u32, g: &Guest, root: &Path, budget: Duration) -> (TrialResult, bool) {
        let dir = root.join(format!("trial-{n}"));
        std::fs::create_dir(&dir).expect("create trial dir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod trial dir");
        }
        let log = dir.join("console.log");
        eprintln!("vm_cold_start: trial {n} console log at {}", log.display());
        // spec の組み立てとパス検証は計測区間の外。VM を持つ前なので設定誤りは panic でよい。
        let blocks = g
            .disk
            .iter()
            .map(|p| BlockDeviceSpec::root(DiskImagePath::try_new(p).expect("disk image path")))
            .collect();
        let devices = DeviceConfigSpec::try_new(
            blocks,
            Some(SerialConsoleSink::LogFile(
                ConsoleLogPath::try_new(&log).expect("console log path"),
            )),
        )
        .expect("device spec");
        let spec = VmConfigSpec::from_parts(&g.kernel, g.initrd.as_deref(), &g.cmdline)
            .expect("spec")
            .with_devices(devices)
            .expect("with_devices");
        let timeouts = OpTimeouts::try_new(
            start_timeout_for(budget),
            DEFAULT_STOP_TIMEOUT,
            DEFAULT_STATE_QUERY_TIMEOUT,
        )
        .expect("timeouts");

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (watcher, rx) = spawn_watcher(
            log,
            &g.boot,
            &g.ready,
            POLL_INTERVAL,
            Instant::now() + budget + Duration::from_secs(1),
            Arc::clone(&stop_flag),
        );
        let finish_watcher = |flag: &AtomicBool, h: JoinHandle<()>| {
            flag.store(true, Ordering::Relaxed);
            let _ = h.join();
        };

        let t0 = Instant::now();
        let deadline = t0 + budget;
        let vm = match Vm::launch(&spec, timeouts) {
            Ok(vm) => vm,
            Err(e) => {
                finish_watcher(&stop_flag, watcher);
                return (
                    TrialResult::Err {
                        code: "launch_failed",
                        detail: Some(sanitize_code(e.code())),
                    },
                    // launch 失敗（start のタイムアウト等）では `Vm` の drop が停止要求を非同期に投入するだけで、
                    // 停止完了を確認できない。以降の試行は起動せず not_run にする（REPAIR-5）。
                    true,
                );
            }
        };
        let launch_returned = t0.elapsed();

        // ここから `vm` が生きている間は panic しない（失敗は値として記録する）。
        let mut boot_marker = None;
        let mut outcome: Result<(Duration, Duration), &'static str> = Err("ready_timeout");
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(remaining) {
                Ok(WatchMsg::Boot(at)) => boot_marker = Some(at.saturating_duration_since(t0)),
                Ok(WatchMsg::Ready { at, window }) => {
                    // 期限後にキューへ入った Ready は成功にしない（REPAIR-5）。
                    outcome = if at <= deadline {
                        Ok((at.saturating_duration_since(t0), window))
                    } else {
                        Err("ready_timeout")
                    };
                    break;
                }
                Ok(WatchMsg::Failed) | Err(RecvTimeoutError::Disconnected) => {
                    outcome = Err("watcher_io");
                    break;
                }
                Err(RecvTimeoutError::Timeout) => break,
            }
        }
        if outcome.is_ok() && vm.state() != VmState::Running {
            outcome = Err("guest_not_running");
        }

        let mut halt = false;
        if vm.stop().is_err() {
            halt = true;
            if outcome.is_ok() {
                outcome = Err("stop_failed");
            }
        }
        if vm.state() != VmState::Stopped {
            halt = true;
            if outcome.is_ok() {
                outcome = Err("not_stopped");
            }
        }
        drop(vm);
        finish_watcher(&stop_flag, watcher);

        let result = match outcome {
            Ok((ready, end_window)) => TrialResult::Ok {
                ready,
                launch_returned,
                boot_marker,
                end_window,
            },
            Err(code) => TrialResult::Err { code, detail: None },
        };
        (result, halt)
    }

    /// MAC-2・MAC-1・TASK-70 準備: 実機で試行ごとに新しい VM を起動し、ready マーカーまでの時間を JSON で出す。
    ///
    /// 実機前提のため既定集合から分離している（CI 通過のための弱体化ではない）。必要なもの: 実機 macOS 13 以上、
    /// `com.apple.security.virtualization` 付きで署名したテストバイナリ、ゲスト資産。合否は出さない（#381）。
    #[test]
    #[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and guest assets (MAC-2, TASK-70); see AGENTS.md"]
    fn mac2_vm_cold_start_trials_on_real_macos() {
        // 入力の検証は VM 起動前にすべて終える。
        let trials = resolve_trials(env_opt("FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIALS"))
            .expect("invalid FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIALS");
        let trial_secs = resolve_secs(
            env_opt("FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIAL_TIMEOUT_SECS"),
            TRIAL_TIMEOUT_DEFAULT_SECS,
            TRIAL_TIMEOUT_RANGE_SECS,
        )
        .expect("invalid FANDHE_CONTAINER_MACOS_VM_COLD_START_TRIAL_TIMEOUT_SECS");
        let total_secs = resolve_secs(
            env_opt("FANDHE_CONTAINER_MACOS_VM_COLD_START_TOTAL_TIMEOUT_SECS"),
            TOTAL_TIMEOUT_DEFAULT_SECS,
            TOTAL_TIMEOUT_RANGE_SECS,
        )
        .expect("invalid FANDHE_CONTAINER_MACOS_VM_COLD_START_TOTAL_TIMEOUT_SECS");
        let kernel = env_path("FANDHE_CONTAINER_MACOS_VM_KERNEL").unwrap_or_else(|| {
            panic!(
                "FANDHE_CONTAINER_MACOS_VM_KERNEL (absolute path to a guest kernel) and \
                 FANDHE_CONTAINER_MACOS_VM_READY_MARKER are required. See AGENTS.md."
            )
        });
        let boot =
            guest_markers::resolve_boot_marker(env_opt("FANDHE_CONTAINER_MACOS_VM_BOOT_MARKER"))
                .expect("invalid FANDHE_CONTAINER_MACOS_VM_BOOT_MARKER");
        let ready =
            guest_markers::resolve_ready_marker(env_opt("FANDHE_CONTAINER_MACOS_VM_READY_MARKER"))
                .expect("invalid FANDHE_CONTAINER_MACOS_VM_READY_MARKER");
        guest_markers::validate_marker_pair(&boot, &ready).expect("invalid marker pair");
        let g = Guest {
            kernel,
            initrd: env_path("FANDHE_CONTAINER_MACOS_VM_INITRD"),
            disk: env_path("FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE"),
            cmdline: env_opt("FANDHE_CONTAINER_MACOS_VM_CMDLINE")
                .unwrap_or_else(|| "console=hvc0".to_string()),
            boot,
            ready,
        };

        // 診断のため scratch は残す。パスは stderr にだけ出す（JSON に載せない）。
        let root = fresh_dir("vm-cold-start");
        eprintln!("vm_cold_start: scratch at {}", root.display());
        let total_end = Instant::now() + Duration::from_secs(total_secs);
        let mut results = Vec::new();
        let mut halted = false;
        for n in 1..=trials {
            let remaining = total_end.saturating_duration_since(Instant::now());
            let budget = trial_budget(Duration::from_secs(trial_secs), remaining);
            match (halted, budget) {
                (false, Some(b)) => {
                    let (r, halt) = run_trial(n, &g, &root, b);
                    halted = halt;
                    results.push(r);
                }
                _ => results.push(TrialResult::Err {
                    code: "not_run",
                    detail: None,
                }),
            }
        }
        // libtest の「test ... ... 」と同じ行に出ないよう、JSON の前に改行を置く。
        println!("\n{}", render_json(trials, &results));
        let failed = results
            .iter()
            .filter(|r| matches!(r, TrialResult::Err { .. }))
            .count();
        assert_eq!(
            failed, 0,
            "{failed} of {trials} trials failed (see JSON above)"
        );
    }
}

// ---- 既定集合の単体テスト（全 OS） -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn s(x: &str) -> Option<String> {
        Some(x.to_string())
    }

    #[test]
    fn mac2_trials_resolve_default_and_range() {
        assert_eq!(resolve_trials(None), Ok(5));
        assert_eq!(resolve_trials(s("5")), Ok(5));
        assert_eq!(resolve_trials(s("50")), Ok(50));
        for bad in ["4", "51", "", "abc", "-1", "5.0"] {
            assert!(resolve_trials(s(bad)).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn mac2_secs_resolve_default_and_range() {
        assert_eq!(resolve_secs(None, 60, (1, 600)), Ok(60));
        assert_eq!(resolve_secs(s("1"), 60, (1, 600)), Ok(1));
        assert_eq!(resolve_secs(s("600"), 60, (1, 600)), Ok(600));
        for bad in ["0", "601", "", "x"] {
            assert!(resolve_secs(s(bad), 60, (1, 600)).is_err());
        }
    }

    #[test]
    fn mac2_budget_is_min_of_trial_and_remaining() {
        assert_eq!(trial_budget(ms(60_000), ms(50)), None);
        assert_eq!(trial_budget(ms(60_000), ms(99)), None);
        assert_eq!(trial_budget(ms(60_000), ms(100)), Some(ms(100)));
        assert_eq!(trial_budget(ms(60_000), ms(10_000)), Some(ms(10_000)));
        assert_eq!(trial_budget(ms(5_000), ms(900_000)), Some(ms(5_000)));
        assert_eq!(start_timeout_for(ms(10_000)), ms(10_000));
        assert_eq!(start_timeout_for(ms(60_000)), ms(30_000));
        assert_eq!(start_timeout_for(ms(100)), ms(100));
    }

    #[test]
    fn mac2_scanner_detects_boot_split_across_chunks() {
        let mut sc = MarkerScanner::new("Linux version", "login:");
        assert_eq!(sc.feed(b"Linu"), ScanEvent::default());
        assert_eq!(sc.feed(b"x vers"), ScanEvent::default());
        assert_eq!(
            sc.feed(b"ion 6.1\n"),
            ScanEvent {
                boot: true,
                ready: false
            }
        );
        assert_eq!(sc.feed(b"log"), ScanEvent::default());
        assert_eq!(
            sc.feed(b"in: "),
            ScanEvent {
                boot: false,
                ready: true
            }
        );
    }

    #[test]
    fn mac2_scanner_ignores_ready_before_boot() {
        let mut sc = MarkerScanner::new("Linux version", "login:");
        assert_eq!(sc.feed(b"login: \n"), ScanEvent::default());
        assert_eq!(
            sc.feed(b"Linux version 6\n"),
            ScanEvent {
                boot: true,
                ready: false
            }
        );
    }

    #[test]
    fn mac2_scanner_same_chunk_boot_then_ready() {
        let mut sc = MarkerScanner::new("Linux version", "login:");
        assert_eq!(
            sc.feed(b"Linux version 6.1\nlogin: "),
            ScanEvent {
                boot: true,
                ready: true
            }
        );
        assert_eq!(sc.feed(b"login:"), ScanEvent::default());
    }

    #[test]
    fn mac2_scanner_ready_overlapping_boot_is_not_detected() {
        // ready は boot の末尾より後でなければならない（boot の内側と重なる出現は数えない）。
        let mut sc = MarkerScanner::new("abcdef", "defxyz");
        assert_eq!(
            sc.feed(b"abcdefxyz"),
            ScanEvent {
                boot: true,
                ready: false
            }
        );
    }

    #[test]
    fn mac2_scanner_byte_by_byte_matches_whole_chunk() {
        let text = b"noise\nLinux version 6.1\nmore\nfandhe-guest: init ready v1\n";
        let mut sc = MarkerScanner::new("Linux version", "fandhe-guest: init ready v1");
        let (mut boot_at, mut ready_at) = (None, None);
        for (i, b) in text.iter().enumerate() {
            let ev = sc.feed(std::slice::from_ref(b));
            if ev.boot {
                boot_at = Some(i);
            }
            if ev.ready {
                ready_at = Some(i);
            }
        }
        // boot は "noise\n"(6) + "Linux version"(13) の末尾バイト（添字 18）、ready は最後の改行の 1 つ前。
        assert_eq!(boot_at, Some(18));
        assert_eq!(ready_at, Some(text.len() - 2));
    }

    #[test]
    fn mac2_summarize_median_min_max() {
        assert_eq!(
            summarize(&[ms(3), ms(1), ms(2)]),
            Some(Summary {
                median: ms(2),
                min: ms(1),
                max: ms(3)
            })
        );
        assert_eq!(
            summarize(&[ms(1), ms(2), ms(3), ms(4)]).map(|x| x.median),
            Some(Duration::from_micros(2500))
        );
        assert_eq!(
            summarize(&[Duration::from_nanos(1), Duration::from_nanos(2)]).map(|x| x.median),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(summarize(&[]), None);
    }

    #[test]
    fn mac2_fmt_ms_three_decimals() {
        assert_eq!(fmt_ms(Duration::from_micros(1_234_567)), "1234.567");
        assert_eq!(fmt_ms(Duration::from_micros(999)), "0.999");
        assert_eq!(fmt_ms(Duration::ZERO), "0.000");
    }

    #[test]
    fn mac2_sanitize_code_allows_only_safe_chars() {
        assert_eq!(sanitize_code("vm.start_failed"), "vm.start_failed");
        assert_eq!(sanitize_code("a\"b"), "unknown");
        assert_eq!(sanitize_code(""), "unknown");
        assert_eq!(sanitize_code("Upper"), "unknown");
    }

    #[test]
    fn mac2_render_json_exact() {
        let trials = vec![
            TrialResult::Ok {
                ready: Duration::from_micros(1_800_000),
                launch_returned: Duration::from_micros(300_500),
                boot_marker: Some(Duration::from_micros(400_000)),
                end_window: Duration::from_micros(1_104),
            },
            TrialResult::Err {
                code: "ready_timeout",
                detail: None,
            },
            TrialResult::Ok {
                ready: Duration::from_micros(2_000_000),
                launch_returned: Duration::from_micros(310_000),
                boot_marker: None,
                end_window: Duration::from_micros(900),
            },
            TrialResult::Err {
                code: "launch_failed",
                detail: Some("vm.start_failed".to_string()),
            },
        ];
        let expected = concat!(
            "{\"schema\":\"fandhe-container.macos-vm-cold-start.v1\",\"unit\":\"ms\",",
            "\"interval\":{\"start\":\"before-vm-launch\",\"end\":\"ready-marker-observed\"},",
            "\"label\":{\"path\":\"platform-macos-vm-launch\",\"vm\":\"fresh-per-trial\"},",
            "\"poll_interval_ms\":1,\"trials_requested\":5,\"trials_succeeded\":2,\"trials_failed\":2,",
            "\"failures\":{\"launch_failed\":1,\"ready_timeout\":1},",
            "\"summary\":{\"median\":1900.000,\"min\":1800.000,\"max\":2000.000},",
            "\"trials\":[",
            "{\"trial\":1,\"result\":\"ok\",\"ready\":1800.000,\"launch_returned\":300.500,\"boot_marker\":400.000,\"end_window\":1.104},",
            "{\"trial\":2,\"result\":\"error\",\"code\":\"ready_timeout\"},",
            "{\"trial\":3,\"result\":\"ok\",\"ready\":2000.000,\"launch_returned\":310.000,\"boot_marker\":null,\"end_window\":0.900},",
            "{\"trial\":4,\"result\":\"error\",\"code\":\"launch_failed\",\"detail\":\"vm.start_failed\"}",
            "]}"
        );
        assert_eq!(render_json(5, &trials), expected);
    }

    #[test]
    fn mac2_render_json_without_successes_has_null_summary() {
        let trials = vec![TrialResult::Err {
            code: "not_run",
            detail: None,
        }];
        let out = render_json(5, &trials);
        assert!(out.contains("\"trials_succeeded\":0,\"trials_failed\":1,"));
        assert!(out.contains("\"failures\":{\"not_run\":1},\"summary\":null,"));
    }

    #[test]
    fn mac2_watcher_reports_boot_then_ready_from_real_file() {
        let dir = fresh_dir("watcher-ok");
        let path = dir.join("console.log");
        let stop = Arc::new(AtomicBool::new(false));
        let (h, rx) = spawn_watcher(
            path.clone(),
            "Linux version",
            "fandhe-guest: init ready v1",
            Duration::from_millis(1),
            Instant::now() + Duration::from_secs(30),
            Arc::clone(&stop),
        );
        std::thread::sleep(ms(20));
        std::fs::write(&path, b"Linux version 6.1\n").expect("write boot");
        std::thread::sleep(ms(30));
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open");
            f.write_all(b"fandhe-guest: init ready v1\n")
                .expect("write ready");
        }
        let first = rx.recv_timeout(Duration::from_secs(10)).expect("boot msg");
        let second = rx.recv_timeout(Duration::from_secs(10)).expect("ready msg");
        let boot_at = match first {
            WatchMsg::Boot(at) => at,
            other => panic!("expected Boot, got {other:?}"),
        };
        match second {
            WatchMsg::Ready { at, .. } => assert!(boot_at <= at),
            other => panic!("expected Ready, got {other:?}"),
        }
        stop.store(true, Ordering::Relaxed);
        h.join().expect("join watcher");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mac2_watcher_stops_at_deadline_without_ready() {
        let dir = fresh_dir("watcher-deadline");
        let path = dir.join("console.log");
        std::fs::write(&path, b"Linux version 6.1\n").expect("write boot");
        let stop = Arc::new(AtomicBool::new(false));
        let (h, rx) = spawn_watcher(
            path,
            "Linux version",
            "fandhe-guest: init ready v1",
            Duration::from_millis(1),
            Instant::now() + ms(200),
            stop,
        );
        h.join().expect("watcher ends at its deadline");
        let mut ready = false;
        let mut boots = 0;
        while let Ok(m) = rx.try_recv() {
            match m {
                WatchMsg::Boot(_) => boots += 1,
                WatchMsg::Ready { .. } => ready = true,
                WatchMsg::Failed => panic!("unexpected failure"),
            }
        }
        assert_eq!(boots, 1);
        assert!(!ready);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
