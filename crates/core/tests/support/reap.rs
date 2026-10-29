//! 試験が起こした子プロセスを期限つきで回収する共有補助の正本（REPAIR-1・REPAIR-5・REPAIR-12・#3302・#3410）。
//! kill の後も無期限の `Child::wait()` を呼ばず、`try_wait()` を有限の期限でポーリングする。`wait_within` は
//! kill しない正常終了待ちの期限つき版で、期限切れの扱い（reap して失敗させる）は呼び出し側が決める。
//! `run_within` は外部コマンド（`kill` 等）を期限つきで実行する（`Command::status()` は spawn と無期限の
//! wait を兼ねるため使わない。#3306）。
//!
//! 取り込み方: core の結合試験は `#[path = "support/reap.rs"]`、他 crate の結合試験・単体試験は
//! `#[path = "../../core/tests/support/reap.rs"]` で取り込む。複製しない（片方だけ直してずれるのを防ぐ。
//! `scratch_root.rs` と同じ方式。試験専用で製品コード・rlib には影響しない）。取り込み元は
//! `tests/support/reap.rs` を grep して探す。
//!
//! 回収期限（`reap_within`）の決め方: 各試験の `timeout()` と同じ規則（環境変数
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` を 1..=600 で解釈し、範囲外・非数値は 10 秒）の 3 倍とする。
//! 既定では 30 秒。SIGKILL 後の回収は通常即時で、期限は D 状態などの異常時の上限であり、作業の期限より
//! 短い回収期限で偽の失敗を出さないよう作業期限より長く取る。期限のつまみを 1 つの環境変数に揃えるため、
//! 解釈の規則は各試験の `timeout()` と重複して持つ（`timeout()` の置き場が取り込み元ごとに違い共有できない）。
//! 規則を変えるときは各試験の `timeout()` と合わせること。
//! 取り込み元によって使う項目が異なるため、dead_code の許可は項目ごとに理由つきで付ける。
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// 回収期限の固定値。環境変数に連動しない（`reap_within()` の既定値と同じ 30 秒）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const REAP_WITHIN: Duration = Duration::from_secs(30);

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
