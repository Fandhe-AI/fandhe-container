//! 試験治具の起動 bin（GPU-6・REPAIR-5・TASK-172 F4・#1598）。
//!
//! 役割: 引数を集めて `launch` を呼び、エラーを stderr に 1 行の JSON（`code` / `message`）で出して終了コードを返すだけ。
//! 処理の本体は lib の `launch`（UDS の bind・期限つき accept・ログのファイル出力）。治具 VMM（crosvm 等の
//! vhost-user frontend）が `--socket` のパスへ接続する。Linux 限定で、他 OS では `UNSUPPORTED` を出して非ゼロで終わる。
//! 実機での疎通は #725（人間担当）。

// lib.rs の属性は bin には効かないため、ここにも付ける（unsafe は `sys` にだけ置く）。
#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use fandhe_container_poc_venus_jig::launch;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let result = launch::parse_args(&args).and_then(|c| launch::run(&c));
    if let Err(e) = result {
        eprintln!("{}", e.to_json_line());
        std::process::exit(e.exit_code());
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("{{\"code\":\"UNSUPPORTED\",\"message\":\"venus-jig requires Linux\"}}");
    std::process::exit(1);
}
