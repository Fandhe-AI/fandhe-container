//! CDI env の合成の公開 API 結合試験（TASK-127.4・GPU-2・MS-10）。root・GPU 不要。
//!
//! PoC-14 の fixture を `parse_cdi_spec` → `aggregate_container_edits` → `apply_cdi_env` で通し、具体値で照合する。
//! Linux では合成結果だけで子プロセスを exec し、環境変数がそのまま届きホストの環境が混ざらないことも確かめる。
//! 本物のコンテナ起動経路での確認は #2774・実機 GPU での確認は #552。

use fandhe_container_gpu::cdi_apply::env::apply_cdi_env;
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

const NODE4: &str = include_str!("fixtures/poc14-node4.json");
const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");

fn base() -> Vec<String> {
    vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "NVIDIA_VISIBLE_DEVICES=all".to_string(),
    ]
}

fn compose(spec: &str) -> Vec<String> {
    let spec = parse_cdi_spec(spec).unwrap();
    let edits = aggregate_container_edits(&spec, &["all"]).unwrap();
    apply_cdi_env(&base(), &edits).unwrap().into_env()
}

/// GPU-2: devbox02 の env が base に重なる。
#[test]
fn gpu2_task127_4_devbox02_env() {
    assert_eq!(
        compose(DEVBOX02),
        [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NVIDIA_VISIBLE_DEVICES=void",
            "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu",
        ]
    );
}

/// GPU-2: node4（aarch64）の env が base に重なる。
#[test]
fn gpu2_task127_4_node4_env() {
    assert_eq!(
        compose(NODE4),
        [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NVIDIA_VISIBLE_DEVICES=void",
            "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/aarch64-linux-gnu",
        ]
    );
}

/// GPU-2: 合成結果だけで exec した子が、その環境変数をそのまま持つ（ホストの環境は混ざらない）。
#[cfg(target_os = "linux")]
#[test]
fn gpu2_task127_4_cdi_env_reaches_exec_child() {
    use std::collections::BTreeSet;
    use std::process::Command;

    let composed = compose(DEVBOX02);
    let pairs: Vec<(&str, &str)> = composed
        .iter()
        .map(|e| e.split_once('=').unwrap())
        .collect();
    // REPAIR-5: 子の終了も出力の EOF も有限の期限で待つ。超過時は kill して回収し、失敗にする。
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let mut child = Command::new("/usr/bin/env")
        .env_clear()
        .envs(pairs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let limit = Duration::from_secs(10);
    let start = Instant::now();
    let status = loop {
        match child.try_wait().unwrap() {
            Some(st) => break st,
            None if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            None => {
                reap::reap_or_report(&mut child, reap::reap_within());
                panic!("/usr/bin/env did not exit within {limit:?}");
            }
        }
    };
    assert_eq!(status.code(), Some(0));
    let stdout = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stdout EOF was not reached in time");
    let got: BTreeSet<String> = String::from_utf8(stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let want: BTreeSet<String> = composed.into_iter().collect();
    assert_eq!(got, want);
}
