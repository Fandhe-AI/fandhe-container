//! macOS cold start 上乗せ回帰確認の結合試験（TASK-113.4・PLUG-6・MAC-2）。
//! macOS では実プロセスを spawn して両モードを測り、他 OS では skip を明示する。待ちはすべて期限付き。

#[cfg(target_os = "macos")]
mod macos {
    use fandhe_container_benches::macos_cold_start::{
        MAX_OVERHEAD_RATIO_PERCENT, Mode, measure_all,
    };
    use std::path::Path;

    /// PLUG-6・MAC-2: 都度起動・常駐とも上乗せが 2 秒の 1% 未満（20 ms 未満）。
    /// ノイズで plugin 経路が速く見えると上乗せは 0 に丸められるため、下限は 0 以上（0 も正常値）。
    #[test]
    fn plug6_mac2_cold_start_overhead_below_one_percent() {
        let exe = Path::new(env!("CARGO_BIN_EXE_plugin-boundary-stub"));
        let (spawn, resident) = measure_all(exe, 3).unwrap();
        assert_eq!(spawn.mode, Mode::Spawn);
        assert_eq!(resident.mode, Mode::Resident);
        assert!(
            spawn.overhead_ms >= 0.0 && spawn.overhead_ms < 20.0,
            "{spawn:?}"
        );
        assert!(
            resident.overhead_ms >= 0.0 && resident.overhead_ms < 20.0,
            "{resident:?}"
        );
        assert!(spawn.ratio_percent < MAX_OVERHEAD_RATIO_PERCENT);
        assert!(resident.ratio_percent < MAX_OVERHEAD_RATIO_PERCENT);
    }
}

/// 他 OS では計測しない（TASK-113.4 は macOS のみ）。skip の根拠となる上限定数を固定する。
#[cfg(not(target_os = "macos"))]
#[test]
fn macos_cold_start_is_skipped_on_non_macos() {
    use fandhe_container_benches::macos_cold_start::{MAC2_TARGET_MS, limit_ms};
    assert_eq!(MAC2_TARGET_MS, 2000.0);
    assert_eq!(limit_ms(), 20.0);
}
