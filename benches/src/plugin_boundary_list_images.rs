//! plugin 境界ベンチの計測ハーネス（TASK-113.2・#271。代表操作 B「イメージ一覧」）。
//!
//! PLUG-5 は「別プロセス＋UDS＋長さ接頭辞フレーム」の制御面往復コストを、代表操作
//! (A) 作成〜起動相当（N=3）と (B) イメージ一覧（N=1）について 1 試行 1,000 回 × 5 試行で
//! 計測すると定める。PoC-13 は bincode ペイロードでの計測だったため、serde_json 化（PLUG-2）
//! 後の再計測が TASK-113 に要る。本モジュールはそのうち代表操作 B の計測部品を持つ。
//!
//! 呼び出し元: `benches/benches/plugin_boundary_list_images.rs`（薄い `main`。引数解釈・子プロセス起動・
//! 結果出力のみ）と、本モジュール内のユニットテスト（`harness = false` のベンチには
//! `#[test]` を置けないため、ロジックはライブラリ側に置く。REPAIR-12）。
//! 結果 JSON は `scripts/check-bench-regression.sh` の results スキーマ（`schema_version: 1`）に
//! 適合する。Δp50 算出・CORE-10 比・回帰ゲートへの接続は #272（TASK-113.4）で行う。
//!
//! 計測対象は **模擬制御コア**（固定の少数件のイメージ参照文字列を返すだけ）であり、実 OCI
//! イメージストアではない（REPAIR-3）。実処理を混ぜると境界コストが埋もれるため（PoC-13 と
//! 同じ整理）。
//!
//! - 同一プロセス経路: [`ImageLister`] 越しに直接呼ぶ。1 呼び出しが時計分解能を下回りうるため、
//!   1 サンプル = [`INPROC_BATCH`] 回の経過時間 ÷ 回数
//! - 境界越し経路（`cfg(unix)`）: 自分自身を子プロセス（plugin 役）として起動し、UDS 上で
//!   `encode_message → write_frame → read_frame → decode_message` の往復を 1 サンプルとして計測
//! - 集計: 試行ごとの p50 を出し、試行間の中央値を最終値とする（PoC-13 と同じ。[`p50`]）
//! - 非 unix（Windows）では UDS 転送が `Unimplemented`（WIN-1 により WSL2 内 Linux 側機構に
//!   乗る）のため境界経路は計測できず、片方だけの結果を成功として出さない（fail-closed）

use std::fmt;
use std::hint::black_box;
use std::time::Instant;

/// 1 試行あたりのサンプル数（PLUG-5）。
pub const SAMPLES_PER_TRIAL: usize = 1_000;
/// 試行数（PLUG-5）。
pub const TRIALS: usize = 5;
/// 境界経路の計測前ウォームアップ往復数（結果に含めない）。
pub const WARMUP_ROUND_TRIPS: usize = 100;
/// スモークモードのサンプル数。
pub const SMOKE_SAMPLES: usize = 20;
/// スモークモードの試行数。
pub const SMOKE_TRIALS: usize = 1;
/// 同一プロセス経路で 1 サンプルに含める呼び出し回数。
pub const INPROC_BATCH: usize = 1_000;

/// 同一プロセス経路の metric 名。
pub const METRIC_INPROC: &str = "plugin_boundary_list_images_inproc_p50";
/// 境界越し経路の metric 名。
pub const METRIC_FRAMED: &str = "plugin_boundary_list_images_framed_p50";

/// ハーネスのエラー。`error: <code>: <message>`（英語）で標準エラーへ出す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchError {
    /// 機械可読な種別。
    pub code: String,
    /// 説明。
    pub message: String,
}

impl BenchError {
    /// エラーを作る。
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {}: {}", self.code, self.message)
    }
}

impl std::error::Error for BenchError {}

/// p50 を返す。昇順に並べ、奇数件は中央要素、偶数件は中央 2 要素の平均（PLUG-5）。
/// 試行間の中央値も同じ関数で求める。空入力・非有限値は `Err`。
pub fn p50(samples: &[f64]) -> Result<f64, BenchError> {
    if samples.is_empty() {
        return Err(BenchError::new("invalid-input", "no samples"));
    }
    if samples.iter().any(|v| !v.is_finite()) {
        return Err(BenchError::new("invalid-input", "non-finite sample"));
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    let mid = n / 2;
    if n % 2 == 1 {
        Ok(sorted[mid])
    } else {
        Ok((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// 代表操作 B（イメージ一覧）を提供する制御コアの抽象。同一プロセス経路ではこのトレイト越し、
/// 境界越し経路では plugin 役プロセスが応答の生成に使う。
pub trait ImageLister {
    /// イメージ参照の一覧を返す。
    fn list_images(&self) -> Vec<String>;
}

/// 模擬制御コア。固定の少数件を返すだけで、実 OCI イメージストアには触れない（REPAIR-3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct MockImageStore;

/// 模擬イメージ参照（ダミー値）。
const MOCK_IMAGES: [&str; 4] = [
    "example.invalid/app/alpha:1.0",
    "example.invalid/app/beta:2.1",
    "example.invalid/lib/gamma:0.9",
    "example.invalid/lib/delta:3.4",
];

impl ImageLister for MockImageStore {
    fn list_images(&self) -> Vec<String> {
        MOCK_IMAGES.iter().map(|s| (*s).to_string()).collect()
    }
}

/// 同一プロセス経路の p50（ns）を計測する。`trials` 試行 × `samples` サンプルで、
/// 1 サンプルは [`INPROC_BATCH`] 回呼び出しの平均。
pub fn measure_inproc(
    lister: &dyn ImageLister,
    trials: usize,
    samples: usize,
) -> Result<f64, BenchError> {
    let mut trial_p50s = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut values = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = Instant::now();
            for _ in 0..INPROC_BATCH {
                black_box(black_box(lister).list_images());
            }
            let ns = start.elapsed().as_nanos() as f64 / INPROC_BATCH as f64;
            // 経過 0 は未計測であり正の値へ置き換えない（計測エラーとして失敗させる）。
            if ns <= 0.0 {
                return Err(BenchError::new(
                    "measurement",
                    "elapsed time was zero (clock resolution too coarse)",
                ));
            }
            values.push(ns);
        }
        trial_p50s.push(p50(&values)?);
    }
    p50(&trial_p50s)
}

/// 計測結果。`framed` は境界経路を計測できなかった場合（非 unix のスモーク）に `None`。
#[derive(Debug, Clone, PartialEq)]
pub struct Results {
    /// 同一プロセス経路の p50（ns）。
    pub inproc: f64,
    /// 境界越し経路の p50（ns）。
    pub framed: Option<f64>,
}

impl Results {
    /// results スキーマの JSON（LF 改行）を返す。全値が有限かつ 0 超でなければ `Err`。
    pub fn to_json(&self) -> Result<String, BenchError> {
        // 未計測（`None`）は metric ごと省略せず `null` で明示する（スモーク出力の契約）。
        let entries = [
            (METRIC_INPROC, Some(self.inproc)),
            (METRIC_FRAMED, self.framed),
        ];
        let mut body = Vec::new();
        for (name, value) in entries {
            match value {
                Some(value) => {
                    if !value.is_finite() || value <= 0.0 {
                        return Err(BenchError::new(
                            "invalid-result",
                            format!("metric {name} must be finite and positive"),
                        ));
                    }
                    body.push(format!(
                        "    \"{name}\": {{ \"value\": {value}, \"unit\": \"ns\" }}"
                    ));
                }
                None => body.push(format!("    \"{name}\": null")),
            }
        }
        Ok(format!(
            "{{\n  \"schema_version\": 1,\n  \"metrics\": {{\n{}\n  }}\n}}\n",
            body.join(",\n")
        ))
    }
}

/// 実行モード。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// 本計測（1,000×5）。結果 JSON を `output` へ書く。
    Measure {
        /// 出力先パス。
        output: String,
    },
    /// スモーク（少回数で両経路を通す）。
    Smoke,
    /// 子プロセス（plugin 役）。内部用。
    PluginServe {
        /// 接続先 socket パス。
        socket: String,
    },
}

/// 引数（プログラム名を除く）を解釈する。`--bench`（cargo が自動付与）は無視する。
pub fn parse_args(args: &[String]) -> Result<Mode, BenchError> {
    let rest: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--bench")
        .collect();
    match rest.as_slice() {
        [] => Ok(Mode::Smoke),
        ["--output", path] => Ok(Mode::Measure {
            output: (*path).to_string(),
        }),
        ["--plugin-serve", path] => Ok(Mode::PluginServe {
            socket: (*path).to_string(),
        }),
        ["--output"] | ["--plugin-serve"] => {
            Err(BenchError::new("invalid-args", "missing value for option"))
        }
        _ => Err(BenchError::new("invalid-args", "unrecognized arguments")),
    }
}

#[cfg(unix)]
pub use boundary::{
    PluginProcess, TempDir, measure_framed, run_framed_with_child, serve_connection, serve_socket,
};

/// 境界越し経路。非 unix では UDS 転送が `Unimplemented` のため計測不能。
#[cfg(not(unix))]
pub fn run_framed_with_child(_trials: usize, _samples: usize) -> Result<f64, BenchError> {
    Err(BenchError::new(
        "unimplemented",
        "UDS transport is unavailable on this platform (WIN-1: Linux side of WSL2)",
    ))
}

#[cfg(unix)]
mod boundary {
    use super::{BenchError, ImageLister, MockImageStore, WARMUP_ROUND_TRIPS, p50};
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginError, PluginErrorCode, RpcTimeout, UdsListener,
        UdsStream, decode_message, encode_message,
    };
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    /// 要求本文が表す操作名（代表操作 B）。クライアントとサーバで共有し照合に使う。
    const LIST_IMAGES_OP: &str = "list_images";

    /// accept・connect の期限（REPAIR-5）。
    const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 往復 1 回の期限（REPAIR-5）。
    const RPC_TIMEOUT: Duration = Duration::from_secs(10);
    /// 子プロセス終了待ちの期限。
    const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);

    fn rpc_timeout() -> Result<RpcTimeout, BenchError> {
        RpcTimeout::new(RPC_TIMEOUT).map_err(plugin_err)
    }

    fn plugin_err(e: PluginError) -> BenchError {
        BenchError::new(&e.code().as_str().to_ascii_lowercase(), e.message())
    }

    /// 0700 の専用一時ディレクトリ。既存名は失敗（予測可能名の先取り対策）。Drop で削除する。
    /// `sun_path` 長制限（macOS 104 バイト）に収まるよう名前は短くする。
    #[derive(Debug)]
    pub struct TempDir(PathBuf);

    /// 名前衝突時の再試行上限。
    const MAX_ATTEMPTS: usize = 64;

    impl TempDir {
        /// 一時ディレクトリを作る。
        pub fn new() -> Result<Self, BenchError> {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            // 強制終了後の PID 再利用で名前が衝突しても、連番を進めて別名で再試行する。
            // 既存名は先取り対策のため引き続き失敗扱い（`create` は既存を流用しない）。
            for _ in 0..MAX_ATTEMPTS {
                let name = format!(
                    "fcb-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, Ordering::Relaxed)
                );
                let path = std::env::temp_dir().join(name);
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(path)),
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
                "create temp dir failed: all candidate names already exist",
            ))
        }

        /// ディレクトリのパス。
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// plugin 役の子プロセス。Drop で確実に kill・wait する（ゾンビを残さない）。
    #[derive(Debug)]
    pub struct PluginProcess(Option<Child>);

    impl PluginProcess {
        /// 自分自身（`current_exe()` のみ。`PATH` 探索なし）を `--plugin-serve` で起動する。
        pub fn spawn(socket: &Path) -> Result<Self, BenchError> {
            let exe = std::env::current_exe()
                .map_err(|e| BenchError::new("io", format!("current_exe failed: {e}")))?;
            let child = Command::new(exe)
                .arg("--plugin-serve")
                .arg(socket)
                .spawn()
                .map_err(|e| BenchError::new("io", format!("spawn failed: {e}")))?;
            Ok(Self(Some(child)))
        }

        /// 子の正常終了を期限付きで待つ。呼び出し前に接続を閉じておくこと。
        pub fn finish(mut self) -> Result<(), BenchError> {
            let Some(mut child) = self.0.take() else {
                return Ok(());
            };
            let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => return Ok(()),
                    Ok(Some(status)) => {
                        return Err(BenchError::new(
                            "plugin-failed",
                            format!("plugin process exited with {status}"),
                        ));
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(BenchError::new("timeout", "plugin process did not exit"));
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

    impl Drop for PluginProcess {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// plugin 役のループ。要求を受けて模擬コアの結果を同じ ID の応答で返す。
    /// 相手切断（`Unavailable`）で正常終了、それ以外のエラーは `Err`。
    pub fn serve_connection(
        stream: &mut UdsStream,
        lister: &dyn ImageLister,
    ) -> Result<(), BenchError> {
        let timeout = rpc_timeout()?;
        loop {
            let frame = match stream.read_frame(timeout) {
                Ok(f) => f,
                Err(e) if e.code() == PluginErrorCode::Unavailable => return Ok(()),
                Err(e) => return Err(plugin_err(e)),
            };
            let msg = decode_message::<Vec<String>>(&frame).map_err(plugin_err)?;
            // 要求本文が `list_images` 単独であることを照合し、想定外の操作は拒否する。
            // 誤った要求を送る変更があってもベンチが成功してしまうのを防ぐ（代表操作 B の往復を担保）。
            let id = match msg {
                ControlMessage::Request { id, body } if body.as_slice() == [LIST_IMAGES_OP] => id,
                ControlMessage::Request { .. } => {
                    return Err(BenchError::new(
                        "protocol",
                        "unexpected operation in request body",
                    ));
                }
                _ => return Err(BenchError::new("protocol", "expected a request")),
            };
            let resp = ControlMessage::Response {
                id,
                body: lister.list_images(),
            };
            let out = encode_message(&resp).map_err(plugin_err)?;
            stream.write_frame(&out, timeout).map_err(plugin_err)?;
        }
    }

    /// 子プロセスの本体。`socket` へ接続して [`serve_connection`] を回す。
    pub fn serve_socket(socket: &Path) -> Result<(), BenchError> {
        let mut stream = UdsStream::connect(socket, SETUP_TIMEOUT).map_err(plugin_err)?;
        serve_connection(&mut stream, &MockImageStore)
    }

    /// 往復 1 回。応答の ID・種別・本文（模擬コアの期待一覧と完全一致）を照合し、経過 ns を返す。
    fn round_trip(stream: &mut UdsStream, id: u64, expected: &[String]) -> Result<f64, BenchError> {
        let timeout = rpc_timeout()?;
        let req = ControlMessage::Request {
            id: MessageId::new(id),
            body: vec![LIST_IMAGES_OP.to_string()],
        };
        let start = Instant::now();
        let frame = encode_message(&req).map_err(plugin_err)?;
        stream.write_frame(&frame, timeout).map_err(plugin_err)?;
        let reply = stream.read_frame(timeout).map_err(plugin_err)?;
        let msg = decode_message::<Vec<String>>(&reply).map_err(plugin_err)?;
        let ns = start.elapsed().as_nanos() as f64;
        match msg {
            ControlMessage::Response { id: rid, body }
                if rid.get() == id && body.as_slice() == expected =>
            {
                if ns <= 0.0 {
                    // 経過 0 は未計測であり正の値へ置き換えない。
                    return Err(BenchError::new(
                        "measurement",
                        "elapsed time was zero (clock resolution too coarse)",
                    ));
                }
                Ok(ns)
            }
            _ => Err(BenchError::new("protocol", "unexpected response")),
        }
    }

    /// 接続済みの境界越し経路の p50（ns）を計測する（ウォームアップ → `trials` × `samples`）。
    pub fn measure_framed(
        stream: &mut UdsStream,
        trials: usize,
        samples: usize,
    ) -> Result<f64, BenchError> {
        let expected = MockImageStore.list_images();
        let mut id = 0u64;
        for _ in 0..WARMUP_ROUND_TRIPS {
            id += 1;
            round_trip(stream, id, &expected)?;
        }
        let mut trial_p50s = Vec::with_capacity(trials);
        for _ in 0..trials {
            let mut values = Vec::with_capacity(samples);
            for _ in 0..samples {
                id += 1;
                values.push(round_trip(stream, id, &expected)?);
            }
            trial_p50s.push(p50(&values)?);
        }
        p50(&trial_p50s)
    }

    /// 子プロセス（plugin 役）を起動して境界越し経路を計測する。
    pub fn run_framed_with_child(trials: usize, samples: usize) -> Result<f64, BenchError> {
        let dir = TempDir::new()?;
        let listener = UdsListener::bind(&dir.path().join("s")).map_err(plugin_err)?;
        let child = PluginProcess::spawn(listener.path())?;
        let mut stream = listener.accept(SETUP_TIMEOUT).map_err(plugin_err)?;
        let result = measure_framed(&mut stream, trials, samples);
        drop(stream);
        // 計測失敗時は `child` の Drop で kill・wait される。
        let value = result?;
        child.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// PLUG-5: p50 は奇数件で中央要素、偶数件で中央 2 要素の平均（未ソート入力でも）。
    #[test]
    fn plug5_p50_odd_even_unsorted_single() {
        assert_eq!(p50(&[5.0, 1.0, 3.0]).unwrap(), 3.0);
        assert_eq!(p50(&[4.0, 1.0, 3.0, 2.0]).unwrap(), 2.5);
        assert_eq!(p50(&[7.0]).unwrap(), 7.0);
    }

    /// PLUG-5: 空入力・非有限値は拒否する。
    #[test]
    fn plug5_p50_rejects_empty_and_nan() {
        assert_eq!(p50(&[]).unwrap_err().code, "invalid-input");
        assert_eq!(p50(&[1.0, f64::NAN]).unwrap_err().code, "invalid-input");
        assert_eq!(p50(&[f64::INFINITY]).unwrap_err().code, "invalid-input");
    }

    /// PLUG-5: 5 試行の p50 の中央値。
    #[test]
    fn plug5_median_of_five_trials() {
        assert_eq!(p50(&[10.0, 50.0, 30.0, 20.0, 40.0]).unwrap(), 30.0);
    }

    /// PLUG-5: 結果 JSON は既存スキーマ（schema_version 1・unit ns）に完全一致する。
    #[test]
    fn plug5_results_json_exact() {
        let r = Results {
            inproc: 120.5,
            framed: Some(9000.0),
        };
        assert_eq!(
            r.to_json().unwrap(),
            "{\n  \"schema_version\": 1,\n  \"metrics\": {\n    \
             \"plugin_boundary_list_images_inproc_p50\": { \"value\": 120.5, \"unit\": \"ns\" },\n    \
             \"plugin_boundary_list_images_framed_p50\": { \"value\": 9000, \"unit\": \"ns\" }\n  }\n}\n"
        );
    }

    /// PLUG-5: 未計測の framed は metric を省略せず null で出力する。
    #[test]
    fn plug5_results_json_null_when_framed_unmeasured() {
        let r = Results {
            inproc: 120.5,
            framed: None,
        };
        assert_eq!(
            r.to_json().unwrap(),
            "{\n  \"schema_version\": 1,\n  \"metrics\": {\n    \
             \"plugin_boundary_list_images_inproc_p50\": { \"value\": 120.5, \"unit\": \"ns\" },\n    \
             \"plugin_boundary_list_images_framed_p50\": null\n  }\n}\n"
        );
    }

    /// PLUG-5: 0 以下・非有限値の結果は出力しない。
    #[test]
    fn plug5_results_json_rejects_bad_values() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let r = Results {
                inproc: bad,
                framed: Some(1.0),
            };
            assert_eq!(r.to_json().unwrap_err().code, "invalid-result");
        }
        let r = Results {
            inproc: 1.0,
            framed: Some(0.0),
        };
        assert!(r.to_json().is_err());
    }

    /// PLUG-5: 引数解釈（`--bench` は無視・値欠落・未知引数）。
    #[test]
    fn plug5_parse_args() {
        assert_eq!(parse_args(&s(&["--bench"])).unwrap(), Mode::Smoke);
        assert_eq!(
            parse_args(&s(&["--bench", "--output", "/x/r.json"])).unwrap(),
            Mode::Measure {
                output: "/x/r.json".into()
            }
        );
        assert_eq!(
            parse_args(&s(&["--plugin-serve", "/x/s"])).unwrap(),
            Mode::PluginServe {
                socket: "/x/s".into()
            }
        );
        assert_eq!(
            parse_args(&s(&["--output"])).unwrap_err().code,
            "invalid-args"
        );
        assert_eq!(
            parse_args(&s(&["--nope"])).unwrap_err().code,
            "invalid-args"
        );
    }

    /// PLUG-5: 模擬コアは固定 4 件を返し、同一プロセス計測は 0 超の有限な p50 を返す。
    #[test]
    fn plug5_inproc_measures_positive() {
        assert_eq!(MockImageStore.list_images().len(), 4);
        let v = measure_inproc(&MockImageStore, 2, 3).unwrap();
        assert!(v > 0.0 && v.is_finite());
    }

    /// PLUG-5: 非 unix では境界経路は Unimplemented 相当のエラー。
    #[cfg(not(unix))]
    #[test]
    fn plug5_framed_unimplemented_on_non_unix() {
        assert_eq!(
            run_framed_with_child(1, 1).unwrap_err().code,
            "unimplemented"
        );
    }

    /// PLUG-5: 境界往復（plugin 役をスレッドで動かす）。ハング時はウォッチドッグで失敗させる。
    #[cfg(unix)]
    #[test]
    fn plug5_framed_round_trip_with_thread_plugin() {
        use fandhe_container_plugin::{UdsListener, UdsStream};
        use std::sync::mpsc;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let run = || -> Result<f64, BenchError> {
                let dir = TempDir::new()?;
                let listener = UdsListener::bind(&dir.path().join("s"))
                    .map_err(|e| BenchError::new("bind", e.message()))?;
                let sock = listener.path().to_path_buf();
                let plugin = std::thread::spawn(move || {
                    let mut st = UdsStream::connect(&sock, Duration::from_secs(5))
                        .map_err(|e| BenchError::new("connect", e.message()))?;
                    serve_connection(&mut st, &MockImageStore)
                });
                let mut st = listener
                    .accept(Duration::from_secs(5))
                    .map_err(|e| BenchError::new("accept", e.message()))?;
                let v = measure_framed(&mut st, 2, 5)?;
                drop(st);
                plugin
                    .join()
                    .map_err(|_| BenchError::new("thread", "plugin thread panicked"))??;
                Ok(v)
            };
            let _ = tx.send(run());
        });
        let v = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("round trip hung")
            .unwrap();
        assert!(v > 0.0 && v.is_finite());
    }

    /// PLUG-5: 想定外の要求本文は protocol エラーで拒否する（本文照合の回帰防止）。
    #[cfg(unix)]
    #[test]
    fn plug5_serve_rejects_unexpected_request_body() {
        use fandhe_container_plugin::{
            ControlMessage, MessageId, RpcTimeout, UdsListener, UdsStream, encode_message,
        };
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let listener = UdsListener::bind(&dir.path().join("s")).unwrap();
        let sock = listener.path().to_path_buf();
        let client = std::thread::spawn(move || {
            let mut st = UdsStream::connect(&sock, Duration::from_secs(5)).unwrap();
            let req = ControlMessage::Request {
                id: MessageId::new(1),
                body: vec!["delete_images".to_string()],
            };
            let out = encode_message(&req).unwrap();
            let t = RpcTimeout::new(Duration::from_secs(5)).unwrap();
            st.write_frame(&out, t).unwrap();
            // サーバが拒否して閉じるまで保持する。
            std::thread::sleep(Duration::from_millis(200));
        });
        let mut st = listener.accept(Duration::from_secs(5)).unwrap();
        let err = serve_connection(&mut st, &MockImageStore).unwrap_err();
        assert_eq!(err.code, "protocol");
        client.join().unwrap();
    }
}
