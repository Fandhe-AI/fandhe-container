//! 1 バイト TCP 往復の p50・p99 計測プログラム（NET-3・NET-2・TASK-140 準備・#1881）。
//!
//! TASK-140（#319。人間担当）の条件 3「1 バイト TCP 往復の p50・p99」を測るための、std のみの小さな計測器。
//! `network_paths_privileged --hold`（トポロジーの保持入口）が用意した netns の中で、`nsenter --net=<pin>`
//! 越しに本実行ファイルを起動して使う（呼び出し元は #1882 の計測スクリプトまたは人間の手動実行）。
//! root も特権も要らず、loopback だけで 3 OS の既定のテスト集合で自己試験が走る（REPAIR-12）。
//!
//! # モード
//!
//! - `--serve <ip:port>`: bind して `{"tcp_rtt_probe":"listening","addr":"..."}` を 1 行出し、接続を 1 本だけ
//!   期限つきで受け、受けた 1 バイトをそのまま返し続ける。EOF で `served` 行を出して終了する
//! - `--client <ip:port> [--rounds N] [--warmup W]`: 接続して W 回のウォームアップの後 N 回を計り、
//!   結果を 1 行 JSON（`schema` = `fandhe-container.tcp-rtt/v1`、単位 us）で出す
//! - 先頭が上記以外（引数なし・`--nocapture`・試験名フィルタ等）: loopback の自己試験（成功行 `tcp_rtt_probe: self-test passed (NET-3)`）
//!
//! # 契約
//!
//! - 両端とも `TCP_NODELAY`。1 往復 = 1 バイト送信から同じ 1 バイトの受信まで。返ったバイトの不一致は失敗
//! - 百分位は nearest-rank（`rank = ceil(p * n / 100)`、整数演算）
//! - `--rounds` は 1..=100000（既定 10000）、`--warmup` は 0..=10000（既定 100）。上限検証してから確保する
//! - 接続・accept・各往復に期限（`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`、既定 10 秒）を置き、
//!   クライアントは全体も `期限 x 30` で打ち切る（REPAIR-5）
//! - 失敗は stderr に `{"tcp_rtt_probe":"error","code":"...","message":"..."}`。終了コードは引数誤り 2、他 1
//! - 値は暫定値（`provisional: true`）。計測の場所（隔離 netns・コンテナ役が製品の起動経路を通らない等）の
//!   制約は `docs/design/net-tcp-rtt-bench.md` と保持入口の `method` を参照

#[path = "support/reap.rs"]
mod reap;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ROUNDS_MAX: u32 = 100_000;
const ROUNDS_DEFAULT: u32 = 10_000;
const WARMUP_MAX: u32 = 10_000;
const WARMUP_DEFAULT: u32 = 100;
const OK_LINE: &str = "tcp_rtt_probe: self-test passed (NET-3)";
const METHOD: &str = "1-byte echo over one TCP connection, TCP_NODELAY on both ends, nearest-rank percentiles; measurement location caveats are in docs/design/net-tcp-rtt-bench.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
    Args,
    Timeout,
    Connect,
    Desync,
    Io,
}

impl Code {
    fn as_str(self) -> &'static str {
        match self {
            Code::Args => "ARGS",
            Code::Timeout => "TIMEOUT",
            Code::Connect => "CONNECT",
            Code::Desync => "DESYNC",
            Code::Io => "IO",
        }
    }
}

#[derive(Debug)]
struct ProbeError {
    code: Code,
    message: String,
}

fn err(code: Code, message: impl Into<String>) -> ProbeError {
    ProbeError {
        code,
        message: message.into(),
    }
}

fn io_err(what: &str, e: &std::io::Error) -> ProbeError {
    let code = match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Code::Timeout,
        _ => Code::Io,
    };
    err(code, format!("{what}: {e}"))
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Serve(SocketAddr),
    Client {
        addr: SocketAddr,
        rounds: u32,
        warmup: u32,
    },
}

fn take_u32(args: &[String], i: usize, flag: &str, min: u32, max: u32) -> Result<u32, ProbeError> {
    args.get(i + 1)
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| (min..=max).contains(v))
        .ok_or_else(|| {
            err(
                Code::Args,
                format!("{flag} must be an integer in {min}..={max}"),
            )
        })
}

fn take_addr(args: &[String], i: usize, flag: &str) -> Result<SocketAddr, ProbeError> {
    args.get(i + 1)
        .and_then(|v| v.parse::<SocketAddr>().ok())
        .ok_or_else(|| err(Code::Args, format!("{flag} requires a valid <ip:port>")))
}

/// `args`（プログラム名を除く）を検証して `Mode` にする。未知のフラグ・重複・範囲外は `ARGS`。
fn parse_args(args: &[String]) -> Result<Mode, ProbeError> {
    let mut serve: Option<SocketAddr> = None;
    let mut client: Option<SocketAddr> = None;
    let mut rounds: Option<u32> = None;
    let mut warmup: Option<u32> = None;
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "--serve" => {
                if serve.is_some() {
                    return Err(err(Code::Args, "duplicate --serve"));
                }
                serve = Some(take_addr(args, i, "--serve")?);
            }
            "--client" => {
                if client.is_some() {
                    return Err(err(Code::Args, "duplicate --client"));
                }
                client = Some(take_addr(args, i, "--client")?);
            }
            "--rounds" => {
                if rounds.is_some() {
                    return Err(err(Code::Args, "duplicate --rounds"));
                }
                rounds = Some(take_u32(args, i, "--rounds", 1, ROUNDS_MAX)?);
            }
            "--warmup" => {
                if warmup.is_some() {
                    return Err(err(Code::Args, "duplicate --warmup"));
                }
                warmup = Some(take_u32(args, i, "--warmup", 0, WARMUP_MAX)?);
            }
            other => return Err(err(Code::Args, format!("unknown argument: {other}"))),
        }
        i += 2;
    }
    match (serve, client) {
        (Some(_), Some(_)) => Err(err(Code::Args, "--serve and --client are exclusive")),
        (Some(addr), None) if rounds.is_none() && warmup.is_none() => Ok(Mode::Serve(addr)),
        (Some(_), None) => Err(err(Code::Args, "--rounds/--warmup apply to --client only")),
        (None, Some(addr)) => Ok(Mode::Client {
            addr,
            rounds: rounds.unwrap_or(ROUNDS_DEFAULT),
            warmup: warmup.unwrap_or(WARMUP_DEFAULT),
        }),
        (None, None) => Err(err(Code::Args, "--serve or --client is required")),
    }
}

/// 昇順済みサンプルの nearest-rank 百分位。空なら `None`。
fn percentile(sorted: &[u64], p: u64) -> Option<u64> {
    let n = sorted.len() as u64;
    if n == 0 {
        return None;
    }
    let rank = ((p * n).div_ceil(100)).clamp(1, n);
    sorted.get((rank - 1) as usize).copied()
}

#[derive(Debug, PartialEq)]
struct Stats {
    p50_ns: u64,
    p99_ns: u64,
    min_ns: u64,
    max_ns: u64,
    mean_ns: u64,
}

fn summarize(samples: &mut [u64]) -> Option<Stats> {
    samples.sort_unstable();
    let sum: u128 = samples.iter().map(|&s| u128::from(s)).sum();
    Some(Stats {
        p50_ns: percentile(samples, 50)?,
        p99_ns: percentile(samples, 99)?,
        min_ns: *samples.first()?,
        max_ns: *samples.last()?,
        mean_ns: u64::try_from(sum / samples.len() as u128).ok()?,
    })
}

fn us(ns: u64) -> String {
    format!("{:.3}", ns as f64 / 1000.0)
}

/// 結果の 1 行 JSON。載せるのは数値・固定文字列・型つきの `SocketAddr` だけ。
fn result_json(target: SocketAddr, rounds: u32, warmup: u32, s: &Stats) -> String {
    format!(
        "{{\"schema\":\"fandhe-container.tcp-rtt/v1\",\"unit\":\"us\",\"target\":\"{target}\",\"rounds\":{rounds},\"warmup\":{warmup},\"p50\":{},\"p99\":{},\"min\":{},\"max\":{},\"mean\":{},\"nodelay\":true,\"provisional\":true,\"method\":\"{METHOD}\"}}",
        us(s.p50_ns),
        us(s.p99_ns),
        us(s.min_ns),
        us(s.max_ns),
        us(s.mean_ns),
    )
}

fn say(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// 期限つきの accept。
fn accept_with_deadline(l: &TcpListener, limit: Duration) -> Result<TcpStream, ProbeError> {
    l.set_nonblocking(true)
        .map_err(|e| io_err("set_nonblocking", &e))?;
    let deadline = Instant::now() + limit;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)
                    .map_err(|e| io_err("set_nonblocking", &e))?;
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(err(
                        Code::Timeout,
                        "no client connected before the deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(io_err("accept", &e)),
        }
    }
}

/// 待ち受け側。`on_listening` へ実際の bind 先を渡し、1 接続を処理して往復数を返す。
fn run_serve(
    addr: SocketAddr,
    limit: Duration,
    on_listening: impl FnOnce(SocketAddr),
) -> Result<u32, ProbeError> {
    let l = TcpListener::bind(addr).map_err(|e| io_err("bind", &e))?;
    on_listening(l.local_addr().map_err(|e| io_err("local_addr", &e))?);
    let mut s = accept_with_deadline(&l, limit)?;
    s.set_nodelay(true).map_err(|e| io_err("set_nodelay", &e))?;
    s.set_read_timeout(Some(limit))
        .and_then(|()| s.set_write_timeout(Some(limit)))
        .map_err(|e| io_err("set timeouts", &e))?;
    let mut served = 0u32;
    let mut buf = [0u8; 1];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(served),
            Ok(_) => {}
            Err(e) => return Err(io_err("read", &e)),
        }
        if served >= ROUNDS_MAX + WARMUP_MAX {
            return Err(err(Code::Io, "round limit exceeded"));
        }
        s.write_all(&buf).map_err(|e| io_err("write", &e))?;
        served += 1;
    }
}

/// 全体期限までの残り時間。尽きていれば `TIMEOUT`。
fn remaining(overall: Instant) -> Result<Duration, ProbeError> {
    let left = overall.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(err(Code::Timeout, "overall deadline exceeded"))
    } else {
        Ok(left)
    }
}

/// 個別の期限 `limit` と全体の残りの小さい方を、読み書きの期限として設定する。
fn arm(s: &TcpStream, limit: Duration, overall: Instant) -> Result<(), ProbeError> {
    let t = limit.min(remaining(overall)?);
    s.set_read_timeout(Some(t))
        .and_then(|()| s.set_write_timeout(Some(t)))
        .map_err(|e| io_err("set timeouts", &e))
}

/// 送信側。`rounds` は呼び出し側が上限検証済みであること。
/// `overall_limit` は接続前から数える全体期限で、connect・各往復・close 待ちはその残り以下に制限する。
fn run_client(
    addr: SocketAddr,
    rounds: u32,
    warmup: u32,
    limit: Duration,
    overall_limit: Duration,
) -> Result<Stats, ProbeError> {
    let overall = Instant::now() + overall_limit;
    let mut s = TcpStream::connect_timeout(&addr, limit.min(remaining(overall)?)).map_err(|e| {
        let mut p = io_err("connect", &e);
        if p.code != Code::Timeout {
            p.code = Code::Connect;
        }
        p
    })?;
    s.set_nodelay(true).map_err(|e| io_err("set_nodelay", &e))?;
    let mut samples: Vec<u64> = Vec::with_capacity(rounds as usize);
    let mut back = [0u8; 1];
    for i in 0..(u64::from(rounds) + u64::from(warmup)) {
        arm(&s, limit, overall)?;
        let byte = [(i % 251) as u8];
        let start = Instant::now();
        s.write_all(&byte).map_err(|e| io_err("write", &e))?;
        s.read_exact(&mut back).map_err(|e| io_err("read", &e))?;
        let elapsed = start.elapsed();
        if back != byte {
            return Err(err(
                Code::Desync,
                format!("round {i}: sent {byte:?}, received {back:?}"),
            ));
        }
        if i >= u64::from(warmup) {
            samples.push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        }
    }
    // サーバーの close を全体期限の残りの範囲で待つ。期限が尽きていれば成功にしない。
    arm(&s, limit, overall)?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.read(&mut back);
    remaining(overall)?;
    summarize(&mut samples).ok_or_else(|| err(Code::Io, "no samples"))
}

fn timeout() -> Duration {
    let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=600).contains(s))
        .unwrap_or(10);
    Duration::from_secs(secs)
}

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c if (c as u32) < 0x20 => vec![' '],
            c => vec![c],
        })
        .collect()
}

fn run(mode: Mode) -> Result<(), ProbeError> {
    match mode {
        Mode::Serve(addr) => {
            let served = run_serve(addr, timeout(), |a| {
                say(&format!(
                    "{{\"tcp_rtt_probe\":\"listening\",\"addr\":\"{a}\"}}"
                ));
            })?;
            say(&format!(
                "{{\"tcp_rtt_probe\":\"served\",\"rounds\":{served}}}"
            ));
        }
        Mode::Client {
            addr,
            rounds,
            warmup,
        } => {
            let stats = run_client(addr, rounds, warmup, timeout(), timeout() * 30)?;
            say(&result_json(addr, rounds, warmup, &stats));
        }
    }
    Ok(())
}

/// probe モードに入るか。先頭が `--serve` / `--client` のときだけ。
fn is_probe_mode(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("--serve" | "--client")
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // probe モードは先頭が `--serve` / `--client` のときだけ。それ以外（Cargo が足す `--nocapture`・
    // `--ignored`・試験名フィルタ等）は無視して自己試験を実行する（兄弟の dns_helper_process と同じ）。
    // `--list`（libtest 互換の列挙）は列挙する試験名が無いので何も出さず成功する。
    if args.iter().any(|a| a == "--list") {
        return;
    }
    if is_probe_mode(&args) {
        let outcome = parse_args(&args).and_then(run);
        if let Err(e) = outcome {
            eprintln!(
                "{{\"tcp_rtt_probe\":\"error\",\"code\":\"{}\",\"message\":\"{}\"}}",
                e.code.as_str(),
                json_escape(&e.message)
            );
            std::process::exit(if e.code == Code::Args { 2 } else { 1 });
        }
        return;
    }
    self_test();
    println!("{OK_LINE}");
}

// ---- 自己試験（引数なし。loopback のみ・root 不要・3 OS）----

fn sv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

/// 子プロセスを drop で kill + wait するガード。
struct Guard(std::process::Child);
impl Drop for Guard {
    fn drop(&mut self) {
        reap::reap_on_drop(&mut self.0);
    }
}

fn self_test() {
    net3_percentiles();
    net3_json_line();
    net3_args();
    net3_timeouts();
    net3_desync();
    net3_overall_deadline();
    net3_loopback_via_processes();
    net3_wait_within_reports_expiry();
}

fn net3_percentiles() {
    let v: Vec<u64> = (1..=100).collect();
    assert_eq!(percentile(&v, 50), Some(50));
    assert_eq!(percentile(&v, 99), Some(99));
    assert_eq!(percentile(&[7], 50), Some(7));
    assert_eq!(percentile(&[7], 99), Some(7));
    let big: Vec<u64> = (1..=10_000).collect();
    assert_eq!(percentile(&big, 99), Some(9_900));
    assert_eq!(percentile(&[], 50), None);
    let mut s = vec![4000, 1000, 3000, 2000];
    assert_eq!(
        summarize(&mut s),
        Some(Stats {
            p50_ns: 2000,
            p99_ns: 4000,
            min_ns: 1000,
            max_ns: 4000,
            mean_ns: 2500
        })
    );
}

fn net3_json_line() {
    let st = Stats {
        p50_ns: 12_345,
        p99_ns: 99_000,
        min_ns: 10_000,
        max_ns: 120_000,
        mean_ns: 15_000,
    };
    let addr: SocketAddr = "10.214.0.3:9101".parse().expect("addr");
    let want = format!(
        "{{\"schema\":\"fandhe-container.tcp-rtt/v1\",\"unit\":\"us\",\"target\":\"10.214.0.3:9101\",\"rounds\":10,\"warmup\":2,\"p50\":12.345,\"p99\":99.000,\"min\":10.000,\"max\":120.000,\"mean\":15.000,\"nodelay\":true,\"provisional\":true,\"method\":\"{METHOD}\"}}"
    );
    assert_eq!(result_json(addr, 10, 2, &st), want);
}

fn net3_args() {
    // Cargo が足しうる引数は probe モードにしない（自己試験を実行する）。
    for a in [
        &["--nocapture"][..],
        &["--ignored"],
        &["some_filter"],
        &["--bogus", "x"],
        &[],
    ] {
        assert!(!is_probe_mode(&sv(a)), "{a:?}");
    }
    assert!(is_probe_mode(&sv(&["--serve", "127.0.0.1:0"])));
    assert!(is_probe_mode(&sv(&["--client", "127.0.0.1:1"])));
    let a: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
    assert_eq!(
        parse_args(&sv(&["--serve", "127.0.0.1:9000"])).expect("serve"),
        Mode::Serve(a)
    );
    assert_eq!(
        parse_args(&sv(&["--client", "127.0.0.1:9000"])).expect("client defaults"),
        Mode::Client {
            addr: a,
            rounds: 10_000,
            warmup: 100
        }
    );
    assert_eq!(
        parse_args(&sv(&[
            "--client",
            "127.0.0.1:9000",
            "--rounds",
            "100000",
            "--warmup",
            "0"
        ]))
        .expect("client max"),
        Mode::Client {
            addr: a,
            rounds: 100_000,
            warmup: 0
        }
    );
    let bad: [&[&str]; 11] = [
        &["--client", "127.0.0.1:9000", "--rounds", "0"],
        &["--client", "127.0.0.1:9000", "--rounds", "100001"],
        &["--client", "127.0.0.1:9000", "--rounds", "abc"],
        &["--client", "127.0.0.1:9000", "--warmup", "10001"],
        &["--client"],
        &["--client", "not-an-addr"],
        &["--client", "127.0.0.1:9000", "--client", "127.0.0.1:9001"],
        &[
            "--client",
            "127.0.0.1:9000",
            "--rounds",
            "5",
            "--rounds",
            "6",
        ],
        &["--client", "127.0.0.1:9000", "--bogus", "1"],
        &["--serve", "127.0.0.1:9000", "--rounds", "5"],
        &["--serve", "127.0.0.1:9000", "--client", "127.0.0.1:9001"],
    ];
    for b in bad {
        let e = parse_args(&sv(b)).expect_err("must reject");
        assert_eq!(e.code, Code::Args, "{b:?}");
    }
}

fn net3_timeouts() {
    // accept されない待ち受けは期限で TIMEOUT。
    let e = run_serve(
        "127.0.0.1:0".parse().expect("addr"),
        Duration::from_millis(300),
        |_| {},
    )
    .expect_err("serve must time out");
    assert_eq!(e.code, Code::Timeout);
    // 応答しないサーバーに対するクライアントは TIMEOUT。
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let h = std::thread::spawn(move || {
        let s = accept_with_deadline(&l, Duration::from_secs(10)).expect("accept");
        std::thread::sleep(Duration::from_millis(1500));
        drop(s);
    });
    let e = run_client(
        addr,
        5,
        0,
        Duration::from_millis(300),
        Duration::from_secs(30),
    )
    .expect_err("must time out");
    assert_eq!(e.code, Code::Timeout);
    let _ = h.join();
}

fn net3_overall_deadline() {
    // 個別の期限は十分長くても、全体期限が尽きたら成功を返さず TIMEOUT にする。
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let h = std::thread::spawn(move || {
        let mut s = accept_with_deadline(&l, Duration::from_secs(10)).expect("accept");
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut b = [0u8; 1];
        while s.read_exact(&mut b).is_ok() {
            std::thread::sleep(Duration::from_millis(60));
            if s.write_all(&b).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    let e = run_client(
        addr,
        1000,
        0,
        Duration::from_secs(5),
        Duration::from_millis(250),
    )
    .expect_err("must hit the overall deadline");
    assert_eq!(e.code, Code::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
    let _ = h.join();
}

fn net3_desync() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let h = std::thread::spawn(move || {
        let mut s = accept_with_deadline(&l, Duration::from_secs(10)).expect("accept");
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut b = [0u8; 1];
        if s.read_exact(&mut b).is_ok() {
            let _ = s.write_all(&[b[0].wrapping_add(1)]);
        }
    });
    let e = run_client(addr, 3, 0, Duration::from_secs(5), Duration::from_secs(150))
        .expect_err("must desync");
    assert_eq!(e.code, Code::Desync);
    let _ = h.join();
}

fn wait_exit(child: &mut std::process::Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return st;
        }
        assert!(Instant::now() < deadline, "child did not exit in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn net3_loopback_via_processes() {
    use std::io::{BufRead as _, BufReader};

    use std::sync::mpsc;

    let exe = std::env::current_exe().expect("current_exe");
    let mut server = Guard(
        Command::new(&exe)
            .args(["--serve", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn server"),
    );
    let out = server.0.stdout.take().expect("server stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let listening = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("listening line");
    let addr = listening
        .split("\"addr\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .map(str::to_owned)
        .expect("addr in listening line");
    assert!(addr.starts_with("127.0.0.1:"), "{listening}");

    let mut client = Guard(
        Command::new(&exe)
            .args(["--client", &addr, "--rounds", "100", "--warmup", "5"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn client"),
    );
    // 出力収集も期限つき。子がハングしたら panic し、Guard の drop が子を kill して回収する。
    let mut cstdout = client.0.stdout.take().expect("client stdout");
    let (otx, orx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let r = cstdout.read_to_string(&mut buf).map(|_| buf);
        let _ = otx.send(r);
    });
    let cout = orx
        .recv_timeout(Duration::from_secs(20))
        .expect("client output not collected in time")
        .expect("read client stdout");
    let st = wait_exit(&mut client.0, Duration::from_secs(10));
    assert_eq!(st.code(), Some(0), "client output: {cout}");
    let line = cout.trim();
    assert!(
        line.contains("\"schema\":\"fandhe-container.tcp-rtt/v1\""),
        "{line}"
    );
    assert!(line.contains("\"unit\":\"us\""), "{line}");
    assert!(line.contains("\"rounds\":100,\"warmup\":5,"), "{line}");
    assert!(line.contains("\"provisional\":true"), "{line}");
    let field = |name: &str| -> f64 {
        line.split(&format!("\"{name}\":"))
            .nth(1)
            .and_then(|r| r.split(',').next())
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or_else(|| panic!("field {name} in {line}"))
    };
    let (min, p50, p99, max) = (field("min"), field("p50"), field("p99"), field("max"));
    assert!(min <= p50 && p50 <= p99 && p99 <= max, "{line}");

    let served = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("served line");
    assert_eq!(served, "{\"tcp_rtt_probe\":\"served\",\"rounds\":105}");
    let st = wait_exit(&mut server.0, Duration::from_secs(10));
    assert_eq!(st.code(), Some(0));
}

/// 期限切れが失敗として表に出ることの照合（REPAIR-5・REPAIR-12）。終わらない子（`--serve`）に対し
/// `wait_within` が具体的なメッセージの `Err` を返し、続く `reap` で回収できることを確かめる。
fn net3_wait_within_reports_expiry() {
    let exe = std::env::current_exe().expect("current_exe");
    let child = Command::new(exe)
        .args(["--serve", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    let mut g = Guard(child);
    let pid = g.0.id();
    let r = reap::wait_within(&mut g.0, Duration::from_millis(200));
    assert_eq!(
        r.unwrap_err(),
        format!("child {pid} did not exit within 200ms")
    );
    assert_eq!(reap::reap(&mut g.0, Duration::from_secs(10)), Ok(()));
}
