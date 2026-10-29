//! ID 写像の holder が継承するメモリから注入ファイルの secret が外れていることの結合試験
//! (CORE-6・SEC-5・SUP-12・#2628)。
//!
//! 本番の holder(`unshare(CLONE_NEWUSER)` 済み・dumpable)を、注入集合を保持した中間プロセスから fork し、
//! holder が生きている間に試験の最上位プロセス(祖先。Yama `ptrace_scope=1` でも読める)が
//! `/proc/<holder>/mem` の読める領域を走査して、既知の secret(`/dev/urandom` の 64 バイト)の一致件数を数える。
//!
//! - 本試験: secret を `InjectedContent::from_file`(封印 memfd。本番の経路)で保持 → 一致 0 件・holder は memfd を持たない
//! - 陽性対照: 同じ種類の secret を `Vec`(`InjectedContent::from_bytes`)で保持 → 一致 1 件以上(走査器の故障で
//!   合格させないための照合。見つからなければ失敗)
//!
//! secret は試験バイナリのリテラルにしない(`.rodata` が holder にも写像されるため)。試験プロセスは中間プロセスを fork
//! した後で初めてファイルを読む。単一スレッドの fork が要るため `harness = false`。非 Linux では対象外。
//! `-- --ignored` 指定時のみ実行する実機前提テスト(非特権 user namespace を許可するホスト。Yama `ptrace_scope>=2` は
//! 前提欠如として失敗にする。AGENTS.md)。成功行は
//! `rootless_holder_memory: holder memory has no injected secret (...)`。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_holder_memory: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "rootless_holder_memory: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use fandhe_container_core::rootless::{HolderMemorySource, observe_holder_memory};

    /// `/dev/urandom` の 64 バイトをファイルへ書く(内容は試験プロセスのメモリを通さない)。
    fn make_secret(dir: &std::path::Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let out = std::fs::File::create(&path).expect("create secret file");
        let mut child = Command::new("head")
            .args(["-c", "64", "/dev/urandom"])
            .stdout(Stdio::from(out))
            .spawn()
            .expect("spawn head");
        // 待機には期限を設ける(REPAIR-5)。超過したら kill して有限時間で回収する。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            match child.try_wait().expect("try_wait head") {
                Some(s) => break s,
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    // kill 後の回収にも有限の期限を設ける(REPAIR-5)。回収できなくても失敗報告へ到達する。
                    let reap_deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(5);
                    while std::time::Instant::now() < reap_deadline {
                        if !matches!(child.try_wait(), Ok(None)) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    panic!("head did not finish within 10s");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        assert!(status.success(), "head failed: {status:?}");
        assert_eq!(std::fs::metadata(&path).expect("meta").len(), 64);
        path
    }

    pub fn run() {
        // pid だけの名前を先に消さず、排他作成の `ScratchDir` の子を使う（#3434・REPAIR-12）。
        let scratch = super::scratch_root::ScratchDir::new(
            "fandhe-holder-memory",
            std::time::Duration::from_secs(10),
        );
        let dir = scratch.path().join("d");
        std::fs::create_dir(&dir).expect("temp dir");

        // 陽性対照: 呼び出し元のメモリ(Vec)に secret を持つ中間プロセスから fork した holder には載る。
        let control = observe_holder_memory(
            make_secret(&dir, "control"),
            HolderMemorySource::CallerMemory,
        )
        .expect("observe control");
        assert!(
            control.regions_scanned > 0 && control.hits >= 1,
            "the scanner must find the secret in a holder forked from a Vec-holding parent: {control:?}"
        );

        // 本試験: 封印 memfd(本番の経路)に置いた secret は holder のメモリに無く、holder は memfd を持たない。
        let sealed =
            observe_holder_memory(make_secret(&dir, "sealed"), HolderMemorySource::SealedFile)
                .expect("observe sealed");
        assert!(
            sealed.regions_scanned > 0 && sealed.bytes_scanned > 0,
            "nothing was scanned (empty scan must not pass): {sealed:?}"
        );
        assert_eq!(
            sealed.hits, 0,
            "the injected secret must not be in the holder's memory: {sealed:?}"
        );
        assert!(
            !sealed.fd_targets.iter().any(|t| t.contains("memfd:")),
            "the holder must not hold the sealed memfd: {sealed:?}"
        );
        println!(
            "rootless_holder_memory: holder memory has no injected secret (regions={}, hits={}, control_hits={})",
            sealed.regions_scanned, sealed.hits, control.hits
        );
    }
}
