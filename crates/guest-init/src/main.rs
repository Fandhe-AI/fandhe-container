//! ゲスト init の bin 入口（薄い入口。実体は lib の `run`）。
//!
//! Linux ゲストの PID 1 として起動される。`[[bin]]` は cfg で消せないため、Linux 以外では
//! 何もせず異常終了する（3 OS でワークスペース全体がビルドできるようにするため。MAC-1）。

#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    fandhe_container_guest_init::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fandhe-container-guest-init: unsupported target (Linux guest only)");
    std::process::exit(2);
}
