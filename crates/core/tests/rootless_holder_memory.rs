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
mod linux {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use fandhe_container_core::rootless::{HolderMemorySource, observe_holder_memory};

    /// `/dev/urandom` の 64 バイトをファイルへ書く(内容は試験プロセスのメモリを通さない)。
    fn make_secret(dir: &std::path::Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let out = std::fs::File::create(&path).expect("create secret file");
        let status = Command::new("head")
            .args(["-c", "64", "/dev/urandom"])
            .stdout(Stdio::from(out))
            .status()
            .expect("run head");
        assert!(status.success(), "head failed: {status:?}");
        assert_eq!(std::fs::metadata(&path).expect("meta").len(), 64);
        path
    }

    pub fn run() {
        let dir = std::env::temp_dir().join(format!("fandhe-holder-memory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

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
        let _ = std::fs::remove_dir_all(&dir);
        println!(
            "rootless_holder_memory: holder memory has no injected secret (regions={}, hits={}, control_hits={})",
            sealed.regions_scanned, sealed.hits, control.hits
        );
    }
}
