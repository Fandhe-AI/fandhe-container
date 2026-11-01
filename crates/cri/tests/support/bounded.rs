//! 子プロセスを期限つきで実行して出力を得る補助（REPAIR-5・CRI-5・#872）。
//!
//! `Command::output` は子が止まると無期限に待つ。本補助は標準出力・標準エラーを別スレッドで読み、
//! 期限を超えたら子を kill して回収してから panic する（待ちが戻らない試験を残さない）。
//! `#[path]` で shim v2 の結合試験が取り込む。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// 既定の期限。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub const LIMIT: Duration = Duration::from_secs(30);

fn drain<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = r {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    })
}

/// `cmd` を実行し、`limit` 以内に終わらなければ kill・回収して panic する。
#[allow(dead_code)] // 取り込む試験ごとに使う項目が異なるため
pub fn output_within(mut cmd: Command, limit: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn child");
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not exit within {limit:?} (killed and reaped)");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    }
}
