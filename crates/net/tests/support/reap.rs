//! 試験が起こした子プロセスを期限つきで回収する共有補助（net の結合試験〔`netns_holder_*`・実機前提の
//! `*_privileged`・`tcp_rtt_probe`〕から `#[path]` で取り込む。REPAIR-5・NET-9）。kill の後も無期限の
//! `Child::wait()` を呼ばず、`try_wait()` を有限の期限でポーリングする。`wait_within` は kill しない
//! 正常終了待ちの期限つき版で、期限切れの扱い（reap して失敗させる）は呼び出し側が決める。
//! `run_within` は外部コマンド（`kill` 等）を期限つきで実行する（`Command::status()` は spawn と無期限の wait を
//! 兼ねるため使わない。#3306）。
//!
//! 回収期限（`reap_within`）の決め方: 各試験の `timeout()` と同じ規則（環境変数
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` を 1..=600 で解釈し、範囲外・非数値は 10 秒）の 3 倍とする。
//! 既定では 30 秒。SIGKILL 後の回収は通常即時で、期限は D 状態などの異常時の上限であり、作業の期限より
//! 短い回収期限で偽の失敗を出さないよう作業期限より長く取る。期限のつまみを 1 つの環境変数に揃えるため、
//! 解釈の規則は各試験の `timeout()` と重複して持つ（`timeout()` の置き場が取り込み元ごとに違い共有できない）。
//! 規則を変えるときは各試験の `timeout()` と合わせること。
//! 取り込み元によって使う項目が異なるため、dead_code の許可は項目ごとに理由つきで付ける。

use std::fs::File;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 子を kill し、`within` 以内に `try_wait()` で回収する。回収できない（期限切れ・`try_wait` の失敗）なら
/// 具体的なメッセージの `Err` を返す。すでに終了していた子の kill の失敗は無視する。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn reap(child: &mut Child, within: Duration) -> Result<(), String> {
    let _ = child.kill();
    let pid = child.id();
    let until = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait on child {pid} failed: {e}")),
        }
        if Instant::now() >= until {
            return Err(format!(
                "child {pid} was not reaped within {within:?} after kill"
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 回収期限。各試験の `timeout()` と同じ規則で求めた期限の 3 倍（既定 30 秒。理由は冒頭の説明）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn reap_within() -> Duration {
    let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=600).contains(s))
        .unwrap_or(10);
    Duration::from_secs(secs * 3)
}

/// kill しない正常終了待ちの期限つき版。期限切れ・`try_wait` の失敗は具体的なメッセージの `Err`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn wait_within(child: &mut Child, within: Duration) -> Result<ExitStatus, String> {
    let pid = child.id();
    let until = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Ok(st),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait on child {pid} failed: {e}")),
        }
        if Instant::now() >= until {
            return Err(format!("child {pid} did not exit within {within:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 期限切れ後の後始末用。回収失敗を握り潰さず stderr に出す（呼び出し側は既に失敗を返す経路）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn reap_or_report(child: &mut Child, within: Duration) {
    if let Err(e) = reap(child, within) {
        eprintln!("reap failure: {e}");
    }
}

/// `Drop` 用。回収失敗は通常時は panic で表に出し、巻き戻し中は abort を避けて stderr に出す。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn reap_on_drop(child: &mut Child) {
    if let Err(e) = reap(child, reap_within()) {
        if std::thread::panicking() {
            eprintln!("reap failure: {e}");
        } else {
            panic!("reap failure: {e}");
        }
    }
}

/// `cmd` を spawn し、`within` 以内の終了を待つ（外部 `kill` 等の期限つき実行。REPAIR-5）。
/// spawn の失敗は `spawn <program> failed: <io error>`、期限切れは `<program> did not finish within <within>`
/// （`<within>` は `Debug` 表記）の `Err`。期限切れでは起動した子を kill して回収してから返す
/// （回収失敗は stderr に出す）。stdio は呼び出し側が設定する。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn run_within(cmd: &mut Command, within: Duration) -> Result<ExitStatus, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {program} failed: {e}"))?;
    match wait_within(&mut child, within) {
        Ok(st) => Ok(st),
        Err(e) => {
            reap_or_report(&mut child, reap_within());
            if e.contains("did not exit within") {
                Err(format!("{program} did not finish within {within:?}"))
            } else {
                Err(format!("{program}: {e}"))
            }
        }
    }
}
/// `output_within` が各出力ファイルから取り込む最大バイト数（上限を超えた分は読み捨てる）。
const OUTPUT_CAP: u64 = 1 << 20;

/// 一時ファイルの連番（同一プロセス内の `output_within` の呼び出し間で名前が衝突しないようにする）。
static OUTPUT_SEQ: AtomicU64 = AtomicU64::new(0);

/// 出力の受け皿にする一時ファイルを排他的に作る（`create_new`。既存名は連番を進めて作り直す）。
fn create_output_file(tag: &str) -> Result<(File, std::path::PathBuf), String> {
    let dir = std::env::temp_dir();
    for _ in 0..1000 {
        let n = OUTPUT_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("fc-reap-{}-{n}-{tag}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create output file {}: {e}", path.display())),
        }
    }
    Err("create output file: too many name collisions".to_string())
}

/// 一時ファイルを `OUTPUT_CAP` まで読んで消す。
fn drain_output_file(path: &std::path::Path) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(f) = File::open(path) {
        let _ = f.take(OUTPUT_CAP).read_to_end(&mut buf);
    }
    let _ = std::fs::remove_file(path);
    buf
}

/// `spawn_captured` が作った出力の受け皿（一時ファイルの組）。`finish` で読んで消すか、`discard` で消す。
pub struct Captured {
    out_path: std::path::PathBuf,
    err_path: std::path::PathBuf,
}

impl Captured {
    /// 終了した子の出力を読み（各 `OUTPUT_CAP` まで）、一時ファイルを消して `Output` にする。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn finish(self, status: ExitStatus) -> Output {
        Output {
            status,
            stdout: drain_output_file(&self.out_path),
            stderr: drain_output_file(&self.err_path),
        }
    }

    /// 出力を読まずに一時ファイルを消す（期限切れ・失敗の経路）。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn discard(self) {
        let _ = std::fs::remove_file(&self.out_path);
        let _ = std::fs::remove_file(&self.err_path);
    }
}

/// `cmd` の stdin を null、stdout・stderr を一時ファイルへ向けて spawn する。子の終了待ちは呼び出し側が
/// `wait_within` 等で行い、終了後に `Captured::finish` で出力を取り出す（子の実行中に診断を採りたい試験向け。
/// 単純な場合は `output_within`）。spawn の失敗は `spawn <program> failed: <io error>`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn spawn_captured(cmd: &mut Command) -> Result<(Child, Captured), String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let (out_file, out_path) = create_output_file("out")?;
    let (err_file, err_path) = match create_output_file("err") {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&out_path);
            return Err(e);
        }
    };
    let captured = Captured { out_path, err_path };
    match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
    {
        Ok(child) => Ok((child, captured)),
        Err(e) => {
            captured.discard();
            Err(format!("spawn {program} failed: {e}"))
        }
    }
}

/// `cmd` を spawn して `within` 以内の終了を待ち、stdout・stderr を返す（`Command::output()` /
/// `wait_with_output()` の期限つき版。REPAIR-5・#3409）。stdin は null に固定する。
/// stdout・stderr は pipe ではなく一時ファイルへ向けて、終了後にファイルから読む。pipe の EOF を待たないため、
/// 子の終了後に孫が出力先を持ち続けても戻る（その孫が後で書いた分は取り込まない）。読み手スレッドも立てない
/// ので、fork・`unshare`・`setns` を後に控えた単一スレッド前提の段でも使える。
/// 期限切れは `<program> did not finish within <within>` で、子を kill して回収してから返す。取り込みは各
/// `OUTPUT_CAP`（1 MiB）まで。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn output_within(cmd: &mut Command, within: Duration) -> Result<Output, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let (mut child, captured) = spawn_captured(cmd)?;
    match wait_within(&mut child, within) {
        Ok(status) => Ok(captured.finish(status)),
        Err(e) => {
            reap_or_report(&mut child, reap_within());
            captured.discard();
            Err(if e.contains("did not exit within") {
                format!("{program} did not finish within {within:?}")
            } else {
                format!("{program}: {e}")
            })
        }
    }
}
