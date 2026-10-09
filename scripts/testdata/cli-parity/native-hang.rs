//! cli-parity-check のタイムアウト回収確認用ヘルパー exe（#1548・TASK-125.1・CLI-1・REPAIR-5）。
//!
//! `scripts/cli-parity-native-reclaim-check.sh` が rustc で直接ビルドし、ネイティブ exe（Windows では
//! CreateProcess で子を起動する）の子孫が capture のタイムアウトで回収されるかを確かめる。
//! workspace 外・std のみ。`bogus` を含む引数（A02）でだけ自分自身を子として起動して居座り、
//! それ以外は使い方エラーを 1 行 JSON で出して即終了する。寿命は最大 20 秒で、失敗時も自然に消える。
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// 1 秒ごとに `ticks.<role>.<pid>` へ 1 行追記する（最大 20 回）。回収後に増えないことを外から数える。
fn tick_loop(dir: &str, role: &str) {
    let path = format!("{}/ticks.{}.{}", dir, role, std::process::id());
    for _ in 0..20 {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "t");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn main() {
    let dir = match std::env::var("STUB_NATIVE_DIR") {
        Ok(d) => d,
        Err(_) => {
            println!("{{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage\"}}");
            std::process::exit(2);
        }
    };
    if std::env::var("STUB_NATIVE_ROLE").as_deref() == Ok("child") {
        tick_loop(&dir, "child");
        return;
    }
    if std::env::args().any(|a| a == "bogus") {
        if let Ok(exe) = std::env::current_exe() {
            // 子の標準入出力は null にし、親の出力ファイルのハンドルを握り続けない。
            let _ = Command::new(exe)
                .env("STUB_NATIVE_ROLE", "child")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        tick_loop(&dir, "parent");
        return;
    }
    eprintln!("{{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage\"}}");
    std::process::exit(2);
}
