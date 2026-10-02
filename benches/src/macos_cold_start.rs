//! macOS バックエンドを plugin 化した場合の VM cold start への上乗せ回帰確認（TASK-113.4・PLUG-6・MAC-2・MS-3）。
//!
//! 役割: plugin 境界（別プロセス＋UDS＋長さ接頭辞フレーム）を挟むことで増える起動コストを
//! 「都度起動（spawn → 接続受理）」と「常駐（計測前に起動・接続済みの plugin へ 4 RPC）」の 2 モードで測る。
//! 各モードは plugin を挟まない同一プロセス経路（同じ操作の直接呼び出し）を同条件で計測し、
//! その**差（上乗せ）**が MAC-2 の cold start 目標（2 秒）の PLUG-6 の期待（1% 未満＝20 ms 未満）に収まるか判定する。
//! 常駐の子は `Model::new()` 後に準備完了通知（1 フレーム）を送り、親は計測開始前にそれを受け取る（accept は接続成立のみを示すため）。
//! 計測区間は都度起動が「spawn → accept 完了」、常駐が「接続済み plugin への代表操作 A×3＋B×1 の 4 RPC」のみで、
//! 常駐 plugin の起動・接続・子プロセス回収は計測区間の外に置く。
//! 参照値は PoC-13（長さ接頭辞フレーム: 都度 2.043 ms／常駐 4.500 ms、gRPC: 2.537 ms／5.032 ms）。
//!
//! 呼び出し元: `benches/plugin_boundary_macos_cold_start.rs`（薄い `main`）と
//! `tests/macos_cold_start.rs`（macOS 結合試験）、子プロセス側 `bin/plugin_boundary_stub.rs`（plugin 役のみ）。
//! 純粋ロジック（定数・比率・判定・ログ整形）は全 OS で単体テストし、計測部（`cfg(unix)`）の
//! 実行は macOS のみで有効化する（他 OS では呼び出し側が skip を明示する）。
//!
//! 計測対象は 113.1・113.2 と同じ **模擬制御コア**であり、実 macOS バックエンド plugin
//! （`crates/plugin-macos`。TASK-115）や macOS 独自 VM の cold start 実測（TASK-70・人間担当）ではない
//! （REPAIR-3）。PoC-13 との差分: 常駐モードは plugin の起動を計測区間の外に置き（PoC-13 は起動込みの 4.500 ms）、
//! 都度起動・常駐とも非 plugin 経路との差を上乗せとして判定する。
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
    /// 常駐（計測前に起動・接続済みの plugin へ代表操作 A×3＋B×1 の 4 RPC。起動は計測区間の外）。
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

/// plugin 経路の所要（ms）から非 plugin 経路の所要（ms）を引いた上乗せ（ms）。
///
/// 非有限・負値の入力は構造化エラー。差が負（計測ノイズで plugin 経路の方が速く見えた）の場合は
/// 上乗せなしとして 0 へ丸める（入力そのものの不正とは区別する）。
pub fn overhead_ms(plugin_ms: f64, baseline_ms: f64) -> Result<f64, BenchError> {
    if !plugin_ms.is_finite() || !baseline_ms.is_finite() || plugin_ms < 0.0 || baseline_ms < 0.0 {
        return Err(BenchError::new(
            "invalid-measurement",
            "timings must be finite non-negative numbers",
        ));
    }
    Ok((plugin_ms - baseline_ms).max(0.0))
}

/// 構造化ログ 1 行（英語。stderr 用）。参照値は PoC-13。
/// `plugin_ms`（plugin 経路）と `baseline_ms`（非 plugin 経路）の差を上乗せとして出す。
pub fn log_line(mode: Mode, plugin_ms: f64, baseline_ms: f64) -> Result<String, BenchError> {
    let overhead_ms = overhead_ms(plugin_ms, baseline_ms)?;
    let ratio = ratio_percent(overhead_ms)?;
    let (framed, grpc) = mode.reference();
    Ok(format!(
        "macos_cold_start mode={} plugin_ms={plugin_ms:.3} baseline_ms={baseline_ms:.3} overhead_ms={overhead_ms:.3} ratio_percent={ratio:.4} limit_percent={MAX_OVERHEAD_RATIO_PERCENT:.1} ref_framed_ms={framed:.3} ref_grpc_ms={grpc:.3}",
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
pub use proc::{measure_all, serve_plugin_socket};

#[cfg(unix)]
mod proc {
    use super::*;
    use crate::plugin_boundary::{Model, round_trip, run_op_a_framed, run_op_a_inproc};
    use crate::plugin_boundary_list_images::{ImageLister, MockImageStore};
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginError, PluginErrorCode, RpcTimeout, UdsListener,
        UdsStream, decode_message, encode_message,
    };
    use std::fs;
    use std::hint::black_box;
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
    /// 準備完了通知の ID と本体（子が `Model::new()` を終えサーバーループに入る直前に 1 回送る）。
    const READY_ID: u64 = u64::MAX;
    const READY_BODY: &str = "ready";

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
        // 準備完了ハンドシェイク: 親は計測開始前（常駐）または計測終了後（都度起動）にこれを受け取る。
        let ready: ControlMessage<Vec<String>> = ControlMessage::Response {
            id: MessageId::new(READY_ID),
            body: vec![READY_BODY.to_string()],
        };
        stream
            .write_frame(&encode_message(&ready).map_err(pe)?, t)
            .map_err(pe)?;
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

    /// 子の準備完了通知を受け取り検証する（accept は接続成立しか示さず、子の `Model::new()` 完了を保証しない）。
    fn wait_ready(stream: &mut UdsStream) -> Result<(), BenchError> {
        let t = timeout()?;
        let frame = stream.read_frame(t).map_err(pe)?;
        match decode_message::<Vec<String>>(&frame).map_err(pe)? {
            ControlMessage::Response { id, body }
                if id == MessageId::new(READY_ID) && body.as_slice() == [READY_BODY] =>
            {
                Ok(())
            }
            _ => Err(BenchError::new("protocol", "expected a ready notification")),
        }
    }

    /// 接続済みの plugin へ代表操作 A×3＋B×1 の 4 RPC を行い、応答内容を具体値で検証する。
    fn run_four_rpcs(stream: &mut UdsStream) -> Result<(), BenchError> {
        let mut next_id = 0u64;
        let a = run_op_a_framed(stream, &mut next_id)
            .map_err(|e| BenchError::new(e.code, e.message))?;
        if a.state != "running" {
            return Err(BenchError::new("bad-response", "unexpected state"));
        }
        next_id += 1;
        let images = round_trip(stream, next_id, vec![OP_LIST_IMAGES.to_string()])
            .map_err(|e| BenchError::new(e.code, e.message))?;
        if images != MockImageStore.list_images() {
            return Err(BenchError::new("bad-response", "unexpected image list"));
        }
        Ok(())
    }

    /// 都度起動（plugin 経路）: bind 済み listener に対し、spawn から accept 完了（READY の代理）までを測る。
    fn once_spawn(exe: &Path) -> Result<f64, BenchError> {
        let dir = TempDir::new()?;
        let listener = UdsListener::bind(&dir.0.join("s")).map_err(pe)?;
        let start = Instant::now();
        let child = Guard::spawn(exe, ARG_PLUGIN_SERVE, listener.path())?;
        let mut stream = listener.accept(SETUP_TIMEOUT).map_err(pe)?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        // 子が通知を書く前に切断して EPIPE にならないよう、計測後に準備完了通知を読み捨てる。
        wait_ready(&mut stream)?;
        drop(stream);
        child.finish()?;
        Ok(ms)
    }

    /// 都度起動（非 plugin 経路）: 同じ制御コアを同一プロセス内で用意するまでを測る。
    fn once_spawn_baseline() -> Result<f64, BenchError> {
        let start = Instant::now();
        let model = black_box(Model::new());
        let store = black_box(MockImageStore);
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        drop((model, store));
        Ok(ms)
    }

    /// 常駐（plugin 経路）: plugin を計測前に起動・接続済みにし、4 RPC だけを測る。
    /// plugin の起動・accept・切断後の回収は計測区間の外。
    fn once_resident(exe: &Path) -> Result<f64, BenchError> {
        let dir = TempDir::new()?;
        let listener = UdsListener::bind(&dir.0.join("s")).map_err(pe)?;
        let child = Guard::spawn(exe, ARG_PLUGIN_SERVE, listener.path())?;
        let mut stream = listener.accept(SETUP_TIMEOUT).map_err(pe)?;
        // 子の準備完了（Model::new() 済み・サーバーループ直前）を待ってから計測を始める。
        wait_ready(&mut stream)?;
        let start = Instant::now();
        run_four_rpcs(&mut stream)?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        // 切断で plugin 側ループが終わる。回収は計測区間の外。
        drop(stream);
        child.finish()?;
        Ok(ms)
    }

    /// 常駐（非 plugin 経路）: 同じ 4 操作を同一プロセス内の直接呼び出しで測る（制御コアは計測前に用意）。
    fn once_resident_baseline() -> Result<f64, BenchError> {
        let mut model = Model::new();
        let store = MockImageStore;
        let start = Instant::now();
        let a = run_op_a_inproc(&mut model).map_err(|e| BenchError::new(e.code, e.message))?;
        let images = black_box(store.list_images());
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if a.state != "running" || images != MockImageStore.list_images() {
            return Err(BenchError::new(
                "bad-response",
                "unexpected baseline result",
            ));
        }
        Ok(ms)
    }

    /// `(plugin 経路の中央値, 非 plugin 経路の中央値)`（ms）。
    fn measure_mode(exe: &Path, mode: Mode, trials: usize) -> Result<(f64, f64), BenchError> {
        if trials == 0 || trials > MAX_TRIALS {
            return Err(BenchError::new("invalid-args", "trials must be in 1..=100"));
        }
        let plugin = |exe: &Path| match mode {
            Mode::Spawn => once_spawn(exe),
            Mode::Resident => once_resident(exe),
        };
        let baseline = || match mode {
            Mode::Spawn => once_spawn_baseline(),
            Mode::Resident => once_resident_baseline(),
        };
        // 初回 exec 検査等の影響を除くため 1 回捨てる。
        plugin(exe)?;
        baseline()?;
        let mut p = Vec::with_capacity(trials);
        let mut b = Vec::with_capacity(trials);
        for _ in 0..trials {
            p.push(plugin(exe)?);
            b.push(baseline()?);
        }
        Ok((median_ms(&p)?, median_ms(&b)?))
    }

    /// 両モードを計測してログ出力し、上乗せ（plugin 経路 − 非 plugin 経路）を判定する。`exe` は stub バイナリの絶対パス。
    pub fn measure_all(exe: &Path, trials: usize) -> Result<(Verdict, Verdict), BenchError> {
        let (sp, sb) = measure_mode(exe, Mode::Spawn, trials)?;
        let (rp, rb) = measure_mode(exe, Mode::Resident, trials)?;
        // 片方が超過でももう片方の値を残すため、判定前に両方のログを出す。
        eprintln!("{}", log_line(Mode::Spawn, sp, sb)?);
        eprintln!("{}", log_line(Mode::Resident, rp, rb)?);
        let sv = judge(Mode::Spawn, overhead_ms(sp, sb)?);
        let rv = judge(Mode::Resident, overhead_ms(rp, rb)?);
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
            log_line(Mode::Resident, 4.6, 0.1).unwrap(),
            "macos_cold_start mode=resident plugin_ms=4.600 baseline_ms=0.100 overhead_ms=4.500 ratio_percent=0.2250 limit_percent=1.0 ref_framed_ms=4.500 ref_grpc_ms=5.032"
        );
    }

    /// 上乗せは plugin 経路と非 plugin 経路の差（PLUG-6）。ノイズによる負の差は 0、不正入力はエラー。
    #[test]
    fn overhead_is_difference_of_paths() {
        assert!((overhead_ms(4.6, 0.1).unwrap() - 4.5).abs() < 1e-9);
        assert_eq!(overhead_ms(0.1, 0.2).unwrap(), 0.0);
        assert_eq!(
            overhead_ms(f64::NAN, 0.1).unwrap_err().code,
            "invalid-measurement"
        );
        assert_eq!(
            overhead_ms(1.0, -0.1).unwrap_err().code,
            "invalid-measurement"
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
