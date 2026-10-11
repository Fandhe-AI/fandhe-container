//! 起動経路（`spawn_container_with_stages`）から `dev.tty.legacy_tiocsti` の警告 1 行が出ることを照合する結合試験
//! （CORE-5・SEC-1・REPAIR-4・REPAIR-5・REPAIR-12・#1739）。
//!
//! 単体試験では警告の出力が試験プロセスの標準エラーを汚さないよう省かれ、呼び出しの削除を検出できない。
//! そこで観測値と出力先を注入できる入口 `spawn_container_with_stages_reporting_for_test`
//! （`exec-test-support` feature。本番の `spawn_container_with_stages` と同じ本体）を、fork した実プロセスで通し、
//! 次の 3 点を具体値で確かめる。
//!
//! - 有効（`1`）のとき、出力先へ固定の JSON 1 行がちょうど 1 回、改行付きで届く
//! - 対象外（`0`・ファイル無し・想定外・読み取り失敗）では何も出力されない
//! - 出力先が満杯でも、起動処理は有限時間内に戻り、警告は `Dropped(WouldBlock)` で捨てられる
//!
//! fork は呼び出しプロセスが単一スレッドであることを要求するため `harness = false` の単一スレッド `main` で動かす。
//! root・実コンテナは不要（子は存在しない rootfs で setup 失敗として終わる）。非 Linux では対象外。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("legacy_tiocsti_launch: Linux only, not applicable on this OS");
}

/// feature なしのビルドでは注入用の入口が無い。検証せずに成功しない（fail-closed）。
#[cfg(all(target_os = "linux", not(feature = "exec-test-support")))]
fn main() {
    eprintln!("legacy_tiocsti_launch: not verified; the exec-test-support feature is not enabled");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
fn main() {
    linux::run();
    println!("legacy_tiocsti_launch: ok");
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        DiagnosticDelivery, DiagnosticDropReason, Entrypoint, LegacyTiocstiReport, StagePipeline,
        spawn_container_with_stages_reporting_for_test,
    };
    use fandhe_container_core::legacy_tiocsti::LegacyTiocsti;

    /// `Enabled` のときの固定 1 行（契約。`legacy_tiocsti::warning_line`）。
    const LINE: &str = r#"{"level":"warn","event":"legacy_tiocsti_enabled","sysctl":"dev.tty.legacy_tiocsti","value":1}"#;

    pub fn run() {
        enabled_emits_exact_line_once();
        non_applicable_states_emit_nothing();
        full_output_does_not_block_launch();
    }

    /// 存在しない rootfs で fork する（子は setup 失敗で終わる）。親の戻りと報告だけを照合する。
    fn launch(
        state: LegacyTiocsti,
        out: std::os::fd::BorrowedFd<'_>,
    ) -> (LegacyTiocstiReport, Duration) {
        let entry =
            Entrypoint::new("/nonexistent", ["/nonexistent"], [] as [&str; 0]).expect("entrypoint");
        let start = Instant::now();
        let (child, report) = spawn_container_with_stages_reporting_for_test(
            Path::new("/nonexistent-rootfs-1739"),
            &entry,
            StagePipeline::new(),
            state,
            out,
        )
        .expect("spawn");
        let elapsed = start.elapsed();
        child
            .kill_and_reap(Duration::from_secs(10))
            .expect("reap child");
        (report, elapsed)
    }

    fn read_available(rx: &mut UnixStream) -> Vec<u8> {
        rx.set_nonblocking(true).expect("nonblocking");
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match rx.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        out
    }

    /// 有効のとき、固定 1 行がちょうど 1 回、改行付きで届く。
    fn enabled_emits_exact_line_once() {
        let (tx, mut rx) = UnixStream::pair().expect("pair");
        let (report, _) = launch(LegacyTiocsti::Enabled, tx.as_fd());
        assert_eq!(
            report,
            LegacyTiocstiReport::Emitted(DiagnosticDelivery::Sent)
        );
        assert_eq!(read_available(&mut rx), format!("{LINE}\n").into_bytes());
        assert_eq!(read_available(&mut rx), Vec::<u8>::new());
    }

    /// 対象外の 4 状態では何も出力されない。
    fn non_applicable_states_emit_nothing() {
        for state in [
            LegacyTiocsti::Absent,
            LegacyTiocsti::Disabled,
            LegacyTiocsti::Unexpected,
            LegacyTiocsti::ReadFailed {
                kind: std::io::ErrorKind::PermissionDenied,
            },
        ] {
            let (tx, mut rx) = UnixStream::pair().expect("pair");
            let (report, _) = launch(state, tx.as_fd());
            assert_eq!(report, LegacyTiocstiReport::NotApplicable, "{state:?}");
            assert_eq!(read_available(&mut rx), Vec::<u8>::new(), "{state:?}");
        }
    }

    /// 出力先が満杯（読み手が止まっている）でも起動処理は戻り、警告は待たずに捨てられる（REPAIR-5）。
    fn full_output_does_not_block_launch() {
        let (mut tx, rx) = UnixStream::pair().expect("pair");
        tx.set_nonblocking(true).expect("nonblocking");
        let chunk = [b'x'; 4096];
        loop {
            match tx.write(&chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill: {e}"),
            }
        }
        // 共有している open file description をブロッキングに戻し、`O_NONBLOCK` に頼らないことも照合する。
        tx.set_nonblocking(false).expect("blocking");
        let (report, elapsed) = launch(LegacyTiocsti::Enabled, tx.as_fd());
        assert_eq!(
            report,
            LegacyTiocstiReport::Emitted(DiagnosticDelivery::Dropped(
                DiagnosticDropReason::WouldBlock
            ))
        );
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        drop(rx);
    }
}
