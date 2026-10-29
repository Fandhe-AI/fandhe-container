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
use std::fs::File;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// `cmd` を spawn し、`within` 以内の終了を待つ（外部 `kill` 等の期限つき実行。REPAIR-5・#3409）。
/// spawn の失敗は `spawn <program> failed: <io error>`、期限切れは `<program> did not finish within <within>`
/// （`<within>` は `Debug` 表記）の `Err`。期限切れでは起動した子を kill して回収してから返す
/// （回収失敗は stderr に出す）。stdio は呼び出し側が設定する。スレッドを立てないので、fork・`unshare`・
/// `setns` を後に控えた単一スレッド前提の段でも使える（`Command::status()` は spawn と無期限の wait を兼ねる）。
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

/// プロセスグループ `pgid` の全員へ SIGKILL を送る。この補助は `unsafe` を持たないため、`kill(2)` の直接
/// 呼び出しの代わりに OS 同梱の `kill` を環境空・絶対パス・期限つき（10 秒）で起動する。引数形式は GNU
/// （Linux）の `-s KILL -- -<pgid>` を先に、BSD（macOS）の kill が `--` を pid として拒否するため
/// `-s KILL -<pgid>` を次に試す（`crates/plugin/tests/rss_comparison.rs` の `kill_process_group` と同じ）。
/// どれかが成功すれば `Ok`。全部失敗しても、いずれかの stderr が `No such process`（ESRCH。グループがすでに
/// 空）なら `Ok`。それ以外（起動失敗・期限切れ・権限不足等）は具体的な `Err`。`pgid` が 0 や 1 のときは
/// 自分のグループや全体を撃たないよう何もしない。Unix 以外では何もしない。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
fn kill_group(pgid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        if pgid <= 1 {
            return Ok(());
        }
        let target = format!("-{pgid}");
        let forms: [&[&str]; 2] = [&["-s", "KILL", "--", &target], &["-s", "KILL", &target]];
        let mut last = String::from("no kill binary found");
        let mut gone = false;
        for bin in ["/bin/kill", "/usr/bin/kill"] {
            for args in forms {
                let mut cmd = Command::new(bin);
                cmd.args(args)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        last = format!("spawn {bin} failed: {e}");
                        continue;
                    }
                };
                match wait_within(&mut child, Duration::from_secs(10)) {
                    Ok(st) if st.success() => return Ok(()),
                    Ok(st) => {
                        // kill の stderr は 1 行程度。終了後に上限つきで読む。
                        let mut msg = String::new();
                        if let Some(mut e) = child.stderr.take() {
                            let _ = e.by_ref().take(4096).read_to_string(&mut msg);
                        }
                        if msg.contains("No such process") {
                            gone = true;
                        }
                        last = format!("{bin} {args:?} exited with {st}: {}", msg.trim());
                    }
                    Err(e) => {
                        reap_or_report(&mut child, REAP_WITHIN);
                        last = format!("{bin}: {e}");
                    }
                }
            }
        }
        if gone {
            return Ok(());
        }
        Err(format!("kill process group {pgid} failed: {last}"))
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
        Ok(())
    }
}

/// `output_within` が各出力ファイルに許す最大バイト数。超えたら「出力が完全でない」として `Err` にする
/// （先頭だけ返して後続の存在を隠さない。禁止文字列の不在を検証する試験が上限後の漏れを見逃すため。REPAIR-12）。
const OUTPUT_CAP: u64 = 1 << 20;

/// 出力ファイルの大きさを待ちループの中で監視する間隔。
const OUTPUT_POLL: Duration = Duration::from_millis(5);

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

/// 一時ファイルを読んで消す。`cap` バイトを超える出力・開く / 読むときの失敗は、空や途中までの出力を正常値
/// として返さず `Err`（ファイルは常に消す）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn drain_output_file(path: &std::path::Path, cap: u64) -> Result<Vec<u8>, String> {
    let result = (|| {
        let f =
            File::open(path).map_err(|e| format!("open output file {}: {e}", path.display()))?;
        let mut buf = Vec::new();
        // cap + 1 まで読み、超過を検出する（確認から読みまでの間に伸びた分も拾う）。
        f.take(cap.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| format!("read output file {}: {e}", path.display()))?;
        if buf.len() as u64 > cap {
            return Err(format!("output exceeded the {cap} byte capture cap"));
        }
        Ok(buf)
    })();
    let _ = std::fs::remove_file(path);
    result
}

/// 出力ファイルが `cap` バイトを超えて大きいか。メタデータが読めないときは `Err`。
fn exceeds_cap(path: &std::path::Path, cap: u64) -> Result<bool, String> {
    std::fs::metadata(path)
        .map(|m| m.len() > cap)
        .map_err(|e| format!("stat output file {}: {e}", path.display()))
}

/// `spawn_captured` が作った出力の受け皿（一時ファイルの組）。`finish` で読んで消すか、`discard` で消す。
pub struct Captured {
    pub(crate) out_path: std::path::PathBuf,
    err_path: std::path::PathBuf,
    cap: u64,
    /// 子を先頭にしたプロセスグループ ID（0 は「グループなし」で kill しない。Unix 以外は常に 0）。
    pgid: u32,
}

impl Captured {
    /// 終了した子の出力を読み、一時ファイルを消して `Output` にする。各出力が上限（`OUTPUT_CAP`）を超えた・
    /// 読み取りに失敗した場合は `Err`（途中までの出力は返さない）。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn finish(self, status: ExitStatus) -> Result<Output, String> {
        // 出力先を継承した子孫が居残って書き続けないよう、読む前にグループの残りを止める。
        // 失敗しても一時ファイルの回収は進め、止められなかったことを `Err` で表に出す。
        let killed = kill_group(self.pgid);
        let stdout = drain_output_file(&self.out_path, self.cap);
        let stderr = drain_output_file(&self.err_path, self.cap);
        killed?;
        Ok(Output {
            status,
            stdout: stdout.map_err(|e| format!("stdout: {e}"))?,
            stderr: stderr.map_err(|e| format!("stderr: {e}"))?,
        })
    }

    /// いずれかの出力が上限を超えて書き込まれていれば `Err`（子の実行中に呼べる）。
    fn check_cap(&self) -> Result<(), String> {
        if exceeds_cap(&self.out_path, self.cap)? {
            return Err(format!("stdout exceeded the {} byte capture cap", self.cap));
        }
        if exceeds_cap(&self.err_path, self.cap)? {
            return Err(format!("stderr exceeded the {} byte capture cap", self.cap));
        }
        Ok(())
    }

    /// 子の終了を `within` まで待つ。待ちの最中に 5 ms ごとに出力の大きさを見て、上限超過・期限切れ・
    /// `try_wait` の失敗では、子のグループを kill・回収し、出力を切り詰めてから `Err`（ファイルを消すのは
    /// 呼び出し側の `discard`）。期限切れの文言は `wait_within` と同じ `child <pid> did not exit within <within>`。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn wait_within(&self, child: &mut Child, within: Duration) -> Result<ExitStatus, String> {
        let pid = child.id();
        let until = Instant::now() + within;
        let stop = |child: &mut Child, msg: String| {
            let killed = kill_group(self.pgid);
            reap_or_report(child, REAP_WITHIN);
            self.truncate();
            match killed {
                Ok(()) => Err(msg),
                Err(k) => Err(format!("{msg}; {k}")),
            }
        };
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return Ok(st),
                Ok(None) => {}
                Err(e) => return stop(child, format!("try_wait on child {pid} failed: {e}")),
            }
            if let Err(e) = self.check_cap() {
                return stop(child, e);
            }
            if Instant::now() >= until {
                return stop(child, format!("child {pid} did not exit within {within:?}"));
            }
            std::thread::sleep(OUTPUT_POLL);
        }
    }

    /// 出力ファイルを 0 へ切り詰める（残った書き手が居ても溜まった領域を解放する）。
    fn truncate(&self) {
        for p in [&self.out_path, &self.err_path] {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(p);
        }
    }

    /// 出力を読まずに一時ファイルを消す（期限切れ・失敗の経路）。消す前に 0 へ切り詰めて、出力先を持ち続ける
    /// 子孫が後で書いても、すでに溜まった分の領域を残さない。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn discard(self) -> Result<(), String> {
        let killed = kill_group(self.pgid);
        self.truncate();
        for p in [&self.out_path, &self.err_path] {
            let _ = std::fs::remove_file(p);
        }
        killed
    }
}

/// `cmd` の stdin を null、stdout・stderr を一時ファイルへ向けて spawn する。子の終了待ちは呼び出し側が
/// `wait_within` 等で行い、終了後に `Captured::finish` で出力を取り出す（子の実行中に診断を採りたい試験向け。
/// 単純な場合は `output_within`）。spawn の失敗は `spawn <program> failed: <io error>`。
/// 待ちは `Captured::wait_within`（保存量を 5 ms ごとに監視し、上限超過で kill・切り詰め・`Err`）で行う。
/// `wait_within`（自由関数）で待つと保存量は監視されず、上限超過は `finish` が `Err` にするだけになる。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn spawn_captured(cmd: &mut Command) -> Result<(Child, Captured), String> {
    spawn_captured_capped(cmd, OUTPUT_CAP)
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn spawn_captured_capped(
    cmd: &mut Command,
    cap: u64,
) -> Result<(Child, Captured), String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let (out_file, out_path) = create_output_file("out")?;
    let (err_file, err_path) = match create_output_file("err") {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&out_path);
            return Err(e);
        }
    };
    let captured = Captured {
        out_path,
        err_path,
        cap,
        pgid: 0,
    };
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cmd = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file));
    // 子を新しいプロセスグループの先頭にして、後始末でグループごと止められるようにする（P1: 出力先を
    // 継承した孫の書き込みを止める）。setsid / setpgid で自分から抜けた子孫は止められない（限界）。
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd = cmd.process_group(0);
    }
    match cmd.spawn() {
        Ok(child) => {
            let captured = Captured {
                pgid: if cfg!(unix) { child.id() } else { 0 },
                ..captured
            };
            Ok((child, captured))
        }
        Err(e) => {
            let _ = captured.discard();
            Err(format!("spawn {program} failed: {e}"))
        }
    }
}

/// `cmd` を spawn して `within` 以内の終了を待ち、stdout・stderr を返す（`Command::output()` /
/// `wait_with_output()` の期限つき版。REPAIR-5・#3409）。stdin は null に固定する。
/// stdout・stderr は pipe ではなく一時ファイルへ向けて、終了後にファイルから読む。pipe の EOF を待たないため、
/// 子の終了後に孫が出力先を持ち続けても戻る（その孫が後で書いた分は取り込まない）。読み手スレッドも立てない
/// ので、fork・`unshare`・`setns` を後に控えた単一スレッド前提の段でも使える。
/// 期限切れは `<program> did not finish within <within>` で、子を kill して回収してから返す。
///
/// 保存量の上限（各 `OUTPUT_CAP` = 1 MiB。REPAIR-5・REPAIR-12）: 待ちループ（5 ms 間隔）で出力ファイルの
/// 大きさを監視し、超えたら子を kill・回収してファイルを切り詰めて消し、`<program> output exceeded ...` の
/// `Err` を返す。終了後に上限を超えていた場合や読み取りの失敗も `Err`（先頭だけを正常値として返さない）。
/// 子は新しいプロセスグループの先頭として起動し、kill・終了後の読み取り前にはグループ全体へ SIGKILL を送る
/// （出力先を継承した孫が書き続けて保存量を増やさない。REPAIR-5）。
/// 残る限界: 監視は間隔ごとのため間隔内に書かれた分だけ上限を超えて溜まりうる。`setsid` / `setpgid` で
/// グループを抜けた子孫は止められない（切り詰めてから unlink するので溜まった領域は解放され、孫の後続の
/// 書き込みは取り込まれないが、削除済み inode への書き込みは続きうる）。グループ ID は子の回収後に送るため、
/// グループが空で pid が再利用されていると誤送信しうるが、pid の再利用が一巡する間隔では実質起きない。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn output_within(cmd: &mut Command, within: Duration) -> Result<Output, String> {
    output_within_capped(cmd, within, OUTPUT_CAP)
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn output_within_capped(
    cmd: &mut Command,
    within: Duration,
    cap: u64,
) -> Result<Output, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let (mut child, captured) = spawn_captured_capped(cmd, cap)?;
    match captured.wait_within(&mut child, within) {
        Ok(status) => captured
            .finish(status)
            .map_err(|e| format!("{program}: {e}")),
        Err(e) => {
            let e = match captured.discard() {
                Ok(()) => e,
                Err(k) => format!("{e}; {k}"),
            };
            if e.contains("did not exit within") {
                Err(format!("{program} did not finish within {within:?}"))
            } else if e.starts_with("try_wait ") {
                Err(format!("{program}: {e}"))
            } else {
                Err(format!("{program} {e}"))
            }
        }
    }
}
