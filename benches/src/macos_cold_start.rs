//! macOS バックエンドを plugin 化した場合の VM cold start への上乗せ回帰確認（TASK-113.4・PLUG-6・MAC-2・MS-3）。
//!
//! 役割: plugin 境界（別プロセス＋UDS＋長さ接頭辞フレーム）を挟むことで増える起動コストを
//! 「都度起動（spawn → 接続受理）」と「常駐（プロセス起動＋UDS 接続＋4 RPC）」の 2 モードで測り、
//! MAC-2 の cold start 目標（2 秒）に対する比が PLUG-6 の期待（1% 未満＝20 ms 未満）に収まるか判定する。
//! 参照値は PoC-13（長さ接頭辞フレーム: 都度 2.043 ms／常駐 4.500 ms、gRPC: 2.537 ms／5.032 ms）。
//!
//! 呼び出し元: `benches/plugin_boundary_macos_cold_start.rs`（薄い `main`）と
//! `tests/macos_cold_start.rs`（macOS 結合試験）、子プロセス側 `bin/plugin_boundary_stub.rs`。
//! 純粋ロジック（定数・比率・判定・ログ整形）は全 OS で単体テストし、計測部（`cfg(unix)`）の
//! 実行は macOS のみで有効化する（他 OS では呼び出し側が skip を明示する）。
//!
//! 計測対象は 113.1・113.2 と同じ **模擬制御コア**であり、実 macOS バックエンド plugin
//! （`crates/plugin-macos`。TASK-115）や macOS 独自 VM の cold start 実測（TASK-70・人間担当）ではない
//! （REPAIR-3）。PoC-13 との差分: 常駐モードでは子プロセスの回収（期限付き wait）を計測区間の外に置く。
//! gRPC 経路（TASK-108）は未実装のため同条件比較はフレーム行のみで、gRPC 値は参照ログに出すだけ。
//! 実測基準値の登録と回帰ゲート（`baseline.json`）への接続は TASK-88.h1・TASK-113.h1。

use crate::plugin_boundary_list_images::{BenchError, p50};

/// MAC-2 の VM cold start 目標（ms）。
pub const MAC2_TARGET_MS: f64 = 2000.0;
/// PLUG-6 の期待: 上乗せは cold start 目標の 1% 未満。
pub const MAX_OVERHEAD_RATIO_PERCENT: f64 = 1.0;
/// PoC-13 参照値（フレーム）: 都度起動（ms）。
pub const REF_FRAMED_SPAWN_MS: f64 = 2.043;
/// PoC-13 参照値（フレーム）: 常駐（ms）。
pub const REF_FRAMED_RESIDENT_MS: f64 = 4.500;
/// PoC-13 参照値（gRPC）: 都度起動（ms）。
pub const REF_GRPC_SPAWN_MS: f64 = 2.537;
/// PoC-13 参照値（gRPC）: 常駐（ms）。
pub const REF_GRPC_RESIDENT_MS: f64 = 5.032;
/// 本計測の試行数（PoC-13 と同じ 5。上限付き定数）。
pub const TRIALS: usize = 5;
/// 試行数の上限。
pub const MAX_TRIALS: usize = 100;

/// 子プロセスの引数（plugin 役）。
pub const ARG_PLUGIN_SERVE: &str = "--plugin-serve";
/// 子プロセスの引数（core 役ハーネス）。
pub const ARG_CORE_HARNESS: &str = "--core-harness";

/// 判定の上限値（ms）= MAC-2 目標 × PLUG-6 の 1%（= 20 ms）。
pub fn limit_ms() -> f64 {
    MAC2_TARGET_MS * MAX_OVERHEAD_RATIO_PERCENT / 100.0
}

/// 上乗せ（ms）が MAC-2 目標に占める割合（%）。非有限・負値は構造化エラー（0 へ丸めない）。
pub fn ratio_percent(overhead_ms: f64) -> Result<f64, BenchError> {
    if !overhead_ms.is_finite() || overhead_ms < 0.0 {
        return Err(BenchError::new(
            "invalid-measurement",
            "overhead must be a finite non-negative number",
        ));
    }
    Ok(overhead_ms / MAC2_TARGET_MS * 100.0)
}

/// 計測モード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 都度起動（spawn → 接続受理）。
    Spawn,
    /// 常駐（プロセス起動＋UDS 接続＋代表操作 A×3＋B×1 の 4 RPC）。
    Resident,
}

impl Mode {
    /// ログ用の名前。
    pub fn name(self) -> &'static str {
        match self {
            Mode::Spawn => "spawn",
            Mode::Resident => "resident",
        }
    }

    /// PoC-13 参照値（フレーム, gRPC）。
    fn reference(self) -> (f64, f64) {
        match self {
            Mode::Spawn => (REF_FRAMED_SPAWN_MS, REF_GRPC_SPAWN_MS),
            Mode::Resident => (REF_FRAMED_RESIDENT_MS, REF_GRPC_RESIDENT_MS),
        }
    }
}

/// 1 モードの判定結果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// 計測モード。
    pub mode: Mode,
    /// 上乗せ中央値（ms）。
    pub overhead_ms: f64,
    /// MAC-2 目標に対する比（%）。
    pub ratio_percent: f64,
}

/// 上乗せが 20 ms 未満（2 秒の 1% 未満）なら `Ok`。ちょうど上限は不合格（PLUG-6「未満」）。
pub fn judge(mode: Mode, overhead_ms: f64) -> Result<Verdict, BenchError> {
    let ratio = ratio_percent(overhead_ms)?;
    if overhead_ms >= limit_ms() {
        return Err(BenchError::new(
            "overhead-exceeded",
            format!(
                "{} overhead {overhead_ms:.3} ms is not below the limit {:.3} ms (PLUG-6)",
                mode.name(),
                limit_ms()
            ),
        ));
    }
    Ok(Verdict {
        mode,
        overhead_ms,
        ratio_percent: ratio,
    })
}

/// 構造化ログ 1 行（英語。stderr 用）。参照値は PoC-13。
pub fn log_line(mode: Mode, overhead_ms: f64) -> Result<String, BenchError> {
    let ratio = ratio_percent(overhead_ms)?;
    let (framed, grpc) = mode.reference();
    Ok(format!(
        "macos_cold_start mode={} overhead_ms={overhead_ms:.3} ratio_percent={ratio:.4} limit_percent={MAX_OVERHEAD_RATIO_PERCENT:.1} ref_framed_ms={framed:.3} ref_grpc_ms={grpc:.3}",
        mode.name(),
    ))
}

/// 結果 JSON（`--output` 用。ms 単位。回帰ゲートの metrics.json には未接続）。
pub fn results_json(spawn: &Verdict, resident: &Verdict) -> String {
    format!(
        "{{\n  \"schema_version\": 1,\n  \"metrics\": {{\n    \"macos_cold_start_spawn_overhead\": {{\n      \"value\": {:.3},\n      \"unit\": \"ms\"\n    }},\n    \"macos_cold_start_resident_overhead\": {{\n      \"value\": {:.3},\n      \"unit\": \"ms\"\n    }}\n  }}\n}}\n",
        spawn.overhead_ms, resident.overhead_ms
    )
}

/// 試行値の中央値（ms）。空・非有限は構造化エラー。
pub fn median_ms(samples: &[f64]) -> Result<f64, BenchError> {
    p50(samples)
}

#[cfg(unix)]
pub use proc::{measure_all, run_core_harness, serve_plugin_socket};

#[cfg(unix)]
mod proc {
    use super::*;
    use crate::plugin_boundary::{Model, round_trip, run_op_a_framed};
    use crate::plugin_boundary_list_images::{ImageLister, MockImageStore};
    use fandhe_container_plugin::{
        ControlMessage, PluginError, PluginErrorCode, RpcTimeout, UdsListener, UdsStream,
        decode_message, encode_message,
    };
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
    const RPC_TIMEOUT: Duration = Duration::from_secs(10);
    const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
    const MAX_NAME_ATTEMPTS: usize = 64;
    const OP_LIST_IMAGES: &str = "list_images";

    /// plugin エラーを構造化エラーへ写す（相手由来の文字列は載せない）。
    fn pe(e: PluginError) -> BenchError {
        BenchError::new(
            &e.code().as_str().to_ascii_lowercase(),
            "plugin boundary error",
        )
    }

    fn timeout() -> Result<RpcTimeout, BenchError> {
        RpcTimeout::new(RPC_TIMEOUT).map_err(pe)
    }

    /// 0700 の専用一時ディレクトリ（既存名は失敗扱い。Drop で削除）。名前は `sun_path` 制限に収まる短さ。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Result<Self, BenchError> {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            for _ in 0..MAX_NAME_ATTEMPTS {
                let p = std::env::temp_dir().join(format!(
                    "fcm-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::DirBuilder::new().mode(0o700).create(&p) {
                    Ok(()) => return Ok(Self(p)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        return Err(BenchError::new(
                            "io",
                            format!("create temp dir failed: {e}"),
                        ));
                    }
                }
            }
            Err(BenchError::new(
                "io",
                "create temp dir failed: names exhausted",
            ))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 子プロセス。Drop で kill・wait（失敗時もゾンビを残さない）。
    struct Guard(Option<Child>);

    impl Guard {
        fn spawn(exe: &Path, flag: &str, socket: &Path) -> Result<Self, BenchError> {
            // シェルを介さず絶対パスの exe を引数配列で起動する（PATH 探索なし。PLUG-11 の趣旨）。
            let child = Command::new(exe)
                .arg(flag)
                .arg(socket)
                .stdin(Stdio::null())
                .spawn()
                .map_err(|e| BenchError::new("io", format!("spawn failed: {e}")))?;
            Ok(Self(Some(child)))
        }

        /// 期限付きで正常終了を待つ。計測区間の外で呼ぶ。
        fn finish(mut self) -> Result<(), BenchError> {
            let Some(mut child) = self.0.take() else {
                return Ok(());
            };
            let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(st)) if st.success() => return Ok(()),
                    Ok(Some(_)) => {
                        return Err(BenchError::new(
                            "child-failed",
                            "child exited unsuccessfully",
                        ));
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(BenchError::new("timeout", "child did not exit in time"));
                    }
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(BenchError::new("io", format!("wait failed: {e}")));
                    }
                }
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// plugin 役のサーバーループ（A の 3 操作＋`list_images`）。切断で正常終了。要求は untrusted として検証。
    fn serve(stream: &mut UdsStream) -> Result<(), BenchError> {
        let t = timeout()?;
        let mut model = Model::new();
        let store = MockImageStore;
        loop {
            let frame = match stream.read_frame(t) {
                Ok(f) => f,
                Err(e) if e.code() == PluginErrorCode::Unavailable => return Ok(()),
                Err(e) => return Err(pe(e)),
            };
            let reply = match decode_message::<Vec<String>>(&frame).map_err(pe)? {
                ControlMessage::Request { id, body } if body.as_slice() == [OP_LIST_IMAGES] => {
                    ControlMessage::Response {
                        id,
                        body: store.list_images(),
                    }
                }
                ControlMessage::Request { id, body } => match model.handle(&body) {
                    Ok(body) => ControlMessage::Response { id, body },
                    Err(error) => ControlMessage::Error { id, error },
                },
                _ => return Err(BenchError::new("protocol", "expected a request")),
            };
            stream
                .write_frame(&encode_message(&reply).map_err(pe)?, t)
                .map_err(pe)?;
        }
    }

    /// 子プロセス（plugin 役。`--plugin-serve`）の本体。`socket` へ接続して [`serve`] を回す。
    pub fn serve_plugin_socket(socket: &Path) -> Result<(), BenchError> {
        let mut stream = UdsStream::connect(socket, SETUP_TIMEOUT).map_err(pe)?;
        serve(&mut stream)
    }

    /// 子プロセス（core 役ハーネス。`--core-harness`）の本体。接続して A×3＋B×1 の 4 RPC を行い、
    /// 応答内容を具体値で検証して終了する（切断で常駐側ループが終わる）。
    pub fn run_core_harness(socket: &Path) -> Result<(), BenchError> {
        let mut stream = UdsStream::connect(socket, SETUP_TIMEOUT).map_err(pe)?;
        let mut next_id = 0u64;
        let a = run_op_a_framed(&mut stream, &mut next_id)
            .map_err(|e| BenchError::new(e.code, e.message))?;
        if a.state != "running" {
            return Err(BenchError::new("bad-response", "unexpected state"));
        }
        next_id += 1;
        let images = round_trip(&mut stream, next_id, vec![OP_LIST_IMAGES.to_string()])
            .map_err(|e| BenchError::new(e.code, e.message))?;
        if images != MockImageStore.list_images() {
            return Err(BenchError::new("bad-response", "unexpected image list"));
        }
        Ok(())
    }

    /// 都度起動: bind 済み listener に対し、spawn から accept 完了（READY の代理）までを測る。
    fn once_spawn(exe: &Path) -> Result<f64, BenchError> {
        let dir = TempDir::new()?;
        let listener = UdsListener::bind(&dir.0.join("s")).map_err(pe)?;
        let start = Instant::now();
        let child = Guard::spawn(exe, ARG_PLUGIN_SERVE, listener.path())?;
        let stream = listener.accept(SETUP_TIMEOUT).map_err(pe)?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        drop(stream);
        child.finish()?;
        Ok(ms)
    }

    /// 常駐: 計測側が plugin 役。spawn から 4 RPC 完了（切断観測）までを測る。
    fn once_resident(exe: &Path) -> Result<f64, BenchError> {
        let dir = TempDir::new()?;
        let listener = UdsListener::bind(&dir.0.join("s")).map_err(pe)?;
        let start = Instant::now();
        let child = Guard::spawn(exe, ARG_CORE_HARNESS, listener.path())?;
        let mut stream = listener.accept(SETUP_TIMEOUT).map_err(pe)?;
        serve(&mut stream)?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        drop(stream);
        child.finish()?;
        Ok(ms)
    }

    fn measure_mode(exe: &Path, mode: Mode, trials: usize) -> Result<f64, BenchError> {
        if trials == 0 || trials > MAX_TRIALS {
            return Err(BenchError::new("invalid-args", "trials must be in 1..=100"));
        }
        let once = |exe: &Path| match mode {
            Mode::Spawn => once_spawn(exe),
            Mode::Resident => once_resident(exe),
        };
        // 初回 exec 検査等の影響を除くため 1 回捨てる。
        once(exe)?;
        let mut v = Vec::with_capacity(trials);
        for _ in 0..trials {
            v.push(once(exe)?);
        }
        median_ms(&v)
    }

    /// 両モードを計測してログ出力し、判定する。`exe` は stub バイナリの絶対パス。
    pub fn measure_all(exe: &Path, trials: usize) -> Result<(Verdict, Verdict), BenchError> {
        let s = measure_mode(exe, Mode::Spawn, trials)?;
        let r = measure_mode(exe, Mode::Resident, trials)?;
        // 片方が超過でももう片方の値を残すため、判定前に両方のログを出す。
        eprintln!("{}", log_line(Mode::Spawn, s)?);
        eprintln!("{}", log_line(Mode::Resident, r)?);
        let sv = judge(Mode::Spawn, s);
        let rv = judge(Mode::Resident, r);
        Ok((sv?, rv?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-6・MAC-2: 上限は 2000 ms × 1% = 20 ms。
    #[test]
    fn plug6_limit_is_twenty_ms() {
        assert_eq!(limit_ms(), 20.0);
    }

    /// PoC-13 の参照値の比率（gRPC 常駐 5.032 ms → 0.2516%）。
    #[test]
    fn mac2_ratio_matches_poc13() {
        assert!((ratio_percent(5.032).unwrap() - 0.2516).abs() < 1e-9);
        assert!((ratio_percent(2.537).unwrap() - 0.12685).abs() < 1e-9);
    }

    /// 「1% 未満」なので 19.999 ms は合格・ちょうど 20 ms は不合格。
    #[test]
    fn plug6_boundary_is_exclusive() {
        assert!(judge(Mode::Spawn, 19.999).is_ok());
        assert_eq!(
            judge(Mode::Spawn, 20.0).unwrap_err().code,
            "overhead-exceeded"
        );
    }

    /// 非有限・負値は 0 へ丸めず構造化エラー。
    #[test]
    fn invalid_measurements_are_rejected() {
        for bad in [f64::NAN, f64::INFINITY, -0.1] {
            assert_eq!(ratio_percent(bad).unwrap_err().code, "invalid-measurement");
        }
        assert_eq!(median_ms(&[]).unwrap_err().code, "invalid-input");
    }

    /// ログ行は完全一致で照合する。
    #[test]
    fn log_line_exact() {
        assert_eq!(
            log_line(Mode::Resident, 4.5).unwrap(),
            "macos_cold_start mode=resident overhead_ms=4.500 ratio_percent=0.2250 limit_percent=1.0 ref_framed_ms=4.500 ref_grpc_ms=5.032"
        );
    }

    /// 結果 JSON の値。
    #[test]
    fn results_json_exact_values() {
        let s = judge(Mode::Spawn, 2.0).unwrap();
        let r = judge(Mode::Resident, 4.0).unwrap();
        let j = results_json(&s, &r);
        assert!(j.contains("\"macos_cold_start_spawn_overhead\": {\n      \"value\": 2.000"));
        assert!(j.contains("\"macos_cold_start_resident_overhead\": {\n      \"value\": 4.000"));
    }
}
