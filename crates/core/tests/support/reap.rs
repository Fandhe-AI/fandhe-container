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

/// `drain_output_file` のエラーを、上限超過なら `check_cap`・pipe 方式と同じ `<name> exceeded the <cap> byte
/// capture cap` に揃える（どの経路で検出しても同じ文言にする）。それ以外は `<name>: <e>`。
fn file_err(name: &str, e: String, cap: u64) -> String {
    if e.starts_with("output exceeded the ") {
        format!("{name} exceeded the {cap} byte capture cap")
    } else {
        format!("{name}: {e}")
    }
}

/// 出力ファイルが `cap` バイトを超えて大きいか。メタデータが読めないときは `Err`。
fn exceeds_cap(path: &std::path::Path, cap: u64) -> Result<bool, String> {
    std::fs::metadata(path)
        .map(|m| m.len() > cap)
        .map_err(|e| format!("stat output file {}: {e}", path.display()))
}

/// 出力の受け方。Unix は一時ファイル（子の終了後に孫が出力先を持っていても戻れ、読み手スレッドも要らない）、
/// それ以外（Windows）は pipe と読み手スレッド（グループ kill が無く、子孫の書き込みでファイルが増えるのを
/// 防ぐため。pipe は読み手が上限で読むのをやめて閉じるので保存量が増えない。REPAIR-5・REPAIR-12）。
/// 単体試験が両方の経路を Unix でも試せるよう、型としては全 OS で持つ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code, reason = "既定でない方式は単体試験からだけ選ばれる")]
pub(crate) enum CaptureMode {
    Files,
    Pipes,
}

/// 既定の受け方（Unix はファイル、それ以外は pipe）。
const DEFAULT_MODE: CaptureMode = if cfg!(unix) {
    CaptureMode::Files
} else {
    CaptureMode::Pipes
};

/// pipe 方式で、子の終了後に読み手スレッドの EOF を待つ最長時間。孫が pipe を握ったままだと EOF は来ないので、
/// 過ぎたらスレッドを切り離し、その時点までに読めた分を返す（切り離したスレッドの確保量は `cap + 読み取り
/// 単位` 以下で、上限に達すれば自分で終わる）。
const PIPE_EOF_GRACE: Duration = Duration::from_secs(2);

/// 読み手スレッドが貯める 1 本分の出力。
#[derive(Default)]
struct StreamState {
    buf: Vec<u8>,
    /// 上限を超える出力を受けた（以降は読まずに pipe を閉じる）。
    overflow: bool,
    /// EOF または読み取りエラーで読み手が終わった。
    done: Option<String>,
    eof: bool,
}

type Stream = std::sync::Arc<std::sync::Mutex<StreamState>>;

/// 1 本の pipe を上限つきで読むスレッドを起こす。上限を超える手前まで貯め、超えたら印を立てて読み手側の
/// 端を閉じる（書き手は以後 broken pipe になり、保存量は増えない）。
fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut r: R,
    cap: u64,
    name: &str,
) -> Result<Stream, String> {
    let st: Stream = Stream::default();
    let st2 = st.clone();
    std::thread::Builder::new()
        .name(format!("reap-{name}"))
        .spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                let res = r.read(&mut chunk);
                let Ok(mut g) = st2.lock() else { return };
                match res {
                    Ok(0) => {
                        g.eof = true;
                        return;
                    }
                    Ok(n) => {
                        let room = (cap as usize).saturating_sub(g.buf.len());
                        if n > room {
                            g.buf.extend_from_slice(&chunk[..room]);
                            g.overflow = true;
                            return;
                        }
                        g.buf.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        g.done = Some(format!("read pipe: {e}"));
                        return;
                    }
                }
            }
        })
        .map_err(|e| format!("spawn pipe reader {name}: {e}"))?;
    Ok(st)
}

/// pipe 方式の受け皿（stdout・stderr の読み手）。
struct Pipes {
    out: Stream,
    err: Stream,
}

impl Pipes {
    fn overflow(&self) -> Option<&'static str> {
        let o = |s: &Stream| s.lock().map(|g| g.overflow).unwrap_or(false);
        if o(&self.out) {
            Some("stdout")
        } else if o(&self.err) {
            Some("stderr")
        } else {
            None
        }
    }

    /// 両方の読み手が終わる（EOF・上限・エラー）のを `PIPE_EOF_GRACE` まで待つ。子が上限超過の pipe 閉鎖で
    /// 書き込みエラーになり終了した場合に、終了の検出より先に超過の印を確実に見るために使う。
    fn wait_finished(&self) {
        let until = Instant::now() + PIPE_EOF_GRACE;
        let finished = |s: &Stream| {
            s.lock()
                .map(|g| g.eof || g.overflow || g.done.is_some())
                .unwrap_or(true)
        };
        while !(finished(&self.out) && finished(&self.err)) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 読み手が終わるのを待ち（`wait_finished`）、貯まった分を取り出す。
    fn take(&self, cap: u64) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.wait_finished();
        let mut res = Vec::new();
        for (name, s) in [("stdout", &self.out), ("stderr", &self.err)] {
            let g = s.lock().map_err(|_| format!("{name}: reader panicked"))?;
            if g.overflow {
                return Err(format!(
                    "{name}: output exceeded the {cap} byte capture cap"
                ));
            }
            if let Some(e) = &g.done {
                return Err(format!("{name}: {e}"));
            }
            res.push(g.buf.clone());
        }
        let err = res.pop().unwrap_or_default();
        let out = res.pop().unwrap_or_default();
        Ok((out, err))
    }
}

/// `spawn_captured` が作った出力の受け皿（一時ファイルの組）。`finish` で読んで消すか、`discard` で消す。
pub struct Captured {
    pub(crate) out_path: std::path::PathBuf,
    err_path: std::path::PathBuf,
    cap: u64,
    /// 子を先頭にしたプロセスグループ ID（0 は「グループなし」で kill しない。Unix 以外は常に 0）。
    pgid: u32,
    /// pipe 方式のときの読み手（このとき上の 2 つのパスは空で使わない）。
    pipes: Option<Pipes>,
}

impl Captured {
    /// 終了した子の出力を読み、一時ファイルを消して `Output` にする。各出力が上限（`OUTPUT_CAP`）を超えた・
    /// 読み取りに失敗した場合は `Err`（途中までの出力は返さない）。
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn finish(self, status: ExitStatus) -> Result<Output, String> {
        // 出力先を継承した子孫が居残って書き続けないよう、読む前にグループの残りを止める。
        // 失敗しても一時ファイルの回収は進め、止められなかったことを `Err` で表に出す。
        let killed = kill_group(self.pgid);
        if let Some(p) = &self.pipes {
            let got = p.take(self.cap);
            killed?;
            let (stdout, stderr) = got?;
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        let stdout = drain_output_file(&self.out_path, self.cap);
        let stderr = drain_output_file(&self.err_path, self.cap);
        killed?;
        Ok(Output {
            status,
            stdout: stdout.map_err(|e| file_err("stdout", e, self.cap))?,
            stderr: stderr.map_err(|e| file_err("stderr", e, self.cap))?,
        })
    }

    /// いずれかの出力が上限を超えて書き込まれていれば `Err`（子の実行中に呼べる）。
    fn check_cap(&self) -> Result<(), String> {
        if let Some(p) = &self.pipes {
            return match p.overflow() {
                Some(n) => Err(format!("{n} exceeded the {} byte capture cap", self.cap)),
                None => Ok(()),
            };
        }
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
                Ok(Some(st)) => {
                    // 終了を検出したときも上限超過を確かめ、検出経路によらず同じ `Err` にする。
                    if let Some(p) = &self.pipes {
                        p.wait_finished();
                    }
                    return match self.check_cap() {
                        Ok(()) => Ok(st),
                        Err(e) => stop(child, e),
                    };
                }
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
        if self.pipes.is_some() {
            return;
        }
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
        if self.pipes.is_none() {
            for p in [&self.out_path, &self.err_path] {
                let _ = std::fs::remove_file(p);
            }
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
    spawn_captured_mode(cmd, cap, DEFAULT_MODE)
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn spawn_captured_mode(
    cmd: &mut Command,
    cap: u64,
    mode: CaptureMode,
) -> Result<(Child, Captured), String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut captured = Captured {
        out_path: std::path::PathBuf::new(),
        err_path: std::path::PathBuf::new(),
        cap,
        pgid: 0,
        pipes: None,
    };
    cmd.stdin(Stdio::null());
    match mode {
        CaptureMode::Files => {
            let (out_file, out_path) = create_output_file("out")?;
            let (err_file, err_path) = match create_output_file("err") {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_file(&out_path);
                    return Err(e);
                }
            };
            captured.out_path = out_path;
            captured.err_path = err_path;
            cmd.stdout(Stdio::from(out_file))
                .stderr(Stdio::from(err_file));
        }
        CaptureMode::Pipes => {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
    }
    // 子を新しいプロセスグループの先頭にして、後始末でグループごと止められるようにする（出力先を継承した
    // 孫の書き込みを止める）。setsid / setpgid で自分から抜けた子孫は止められない（限界）。
    // Windows にはこの手段が無い（Job Object は `unsafe` か依存が要る）ため pipe 方式で資源の増加だけを防ぐ。
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = captured.discard();
            return Err(format!("spawn {program} failed: {e}"));
        }
    };
    captured.pgid = if cfg!(unix) { child.id() } else { 0 };
    if mode == CaptureMode::Pipes {
        let readers = match (child.stdout.take(), child.stderr.take()) {
            (Some(o), Some(e)) => spawn_pipe_reader(o, cap, "stdout")
                .and_then(|o| spawn_pipe_reader(e, cap, "stderr").map(|e| (o, e))),
            _ => Err("child pipes missing".to_string()),
        };
        match readers {
            Ok((out, err)) => captured.pipes = Some(Pipes { out, err }),
            Err(e) => {
                kill_group_or_report(captured.pgid);
                reap_or_report(&mut child, REAP_WITHIN);
                return Err(format!("{program}: {e}"));
            }
        }
    }
    Ok((child, captured))
}

/// `kill_group` の失敗を stderr に出す（後始末の経路用）。
fn kill_group_or_report(pgid: u32) {
    if let Err(e) = kill_group(pgid) {
        eprintln!("{e}");
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
/// Windows（`CaptureMode::Pipes`）: 一時ファイルではなく pipe と読み手スレッド 2 本で受け、上限に達したら読み手が
/// 印を立てて読み端を閉じる（書き手は broken pipe になり保存量は増えない）。孫が pipe を握ったままでも、
/// 子の終了後の EOF 待ちは `PIPE_EOF_GRACE`（2 秒）で切り上げ、読み手を切り離して戻る（切り離した読み手の
/// 確保量は `cap` 以下）。限界: Windows では孫を止められない（孫は居残るが、資源は増えない）。
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
    output_within_mode(cmd, within, cap, DEFAULT_MODE)
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn output_within_mode(
    cmd: &mut Command,
    within: Duration,
    cap: u64,
    mode: CaptureMode,
) -> Result<Output, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let (mut child, captured) = spawn_captured_mode(cmd, cap, mode)?;
    match captured.wait_within(&mut child, within) {
        Ok(status) => captured.finish(status).map_err(|e| {
            if e.starts_with("stdout exceeded") || e.starts_with("stderr exceeded") {
                format!("{program} {e}")
            } else {
                format!("{program}: {e}")
            }
        }),
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
