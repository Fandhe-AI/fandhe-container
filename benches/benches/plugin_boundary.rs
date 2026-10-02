//! `fandhe-container-benches` の `plugin_boundary` ベンチ（`harness = false`。TASK-113.1・PLUG-5・PLUG-6）。
//!
//! 役割: 代表操作 A（作成〜起動相当の 3 往復）を同一プロセスと plugin 境界越し（別プロセス＋UDS＋
//! 長さ接頭辞フレーム）で測り、p50 を結果 JSON として出力する。計測ロジックは
//! `fandhe_container_benches::plugin_boundary` にあり、ここは引数の振り分け・子プロセスの起動と
//! 後始末・ファイル書き出しだけを担う。
//!
//! 配置方式の決定（TASK-113）: root の `benches/benches/*.rs` を自動発見に任せ、`path` 明示はしない。
//!
//! 呼び出し: `cargo bench -p fandhe-container-benches --bench plugin_boundary -- --output <path>`。
//! 引数なしはスモーク実行（結果 JSON を標準出力へ）。`--plugin-serve <socket>` は子プロセス専用の内部引数。
//! ゲート（`scripts/check-bench-regression.sh`）へは未接続（baseline 未登録。TASK-113.3・TASK-88）。
//!
//! 境界機構は Unix ドメインソケットに依存するため、Windows では未対応（WIN-1 により境界機構は
//! WSL2 内の Linux 側で動く）。

#[cfg(unix)]
mod imp {
    use std::env;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::process::{Child, Command as Proc, ExitCode, Stdio};

    use fandhe_container_benches::plugin_boundary::{
        BenchError, CONNECT_TIMEOUT, Command, Plan, SMOKE_ITERATIONS, SMOKE_TRIALS,
        WARMUP_ITERATIONS, measure_framed, measure_inproc, parse_args, results_json, serve,
    };
    use fandhe_container_plugin::{UdsListener, UdsStream};

    /// 子プロセスと一時ディレクトリを失敗時も含めて必ず後始末する。
    struct Guard {
        child: Option<Child>,
        dir: PathBuf,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                // 接続切断で自発終了するが、残っていれば kill して回収する。
                let _ = c.kill();
                let _ = c.wait();
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn run_parent(plan: Plan) -> Result<String, BenchError> {
        let inproc = measure_inproc(plan)?;

        // sun_path の長さ制限（macOS 104 バイト）を避けるため名前を短くする。
        // 作成は mkdir 相当（既存なら失敗）で、0700 にして他ユーザーの先回りを拒否する。
        // PID 再利用による衝突を避けるため、ナノ秒時刻を接尾辞に加える（短さを保つため 16 進）。
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
            .unwrap_or(0);
        let dir = env::temp_dir().join(format!("fcpb-{}-{:x}", std::process::id(), nanos));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| BenchError::new("io-error", "failed to create temporary directory"))?;
        let mut guard = Guard {
            child: None,
            dir: dir.clone(),
        };

        let listener = UdsListener::bind(&dir.join("s.sock"))?;
        let exe = env::current_exe()
            .map_err(|_| BenchError::new("io-error", "failed to resolve current executable"))?;
        // シェルを経由せず引数配列で起動する。
        let child = Proc::new(exe)
            .arg("--plugin-serve")
            .arg(listener.path())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|_| BenchError::new("spawn-failed", "failed to spawn plugin process"))?;
        guard.child = Some(child);

        let mut stream = listener.accept(CONNECT_TIMEOUT)?;
        let framed = measure_framed(plan, &mut stream)?;
        drop(stream);
        Ok(results_json(inproc, framed))
    }

    fn run_child(socket: &str) -> Result<(), BenchError> {
        let mut stream = UdsStream::connect(std::path::Path::new(socket), CONNECT_TIMEOUT)?;
        serve(&mut stream)
    }

    pub fn main() -> ExitCode {
        let args: Vec<String> = env::args().skip(1).collect();
        let result = parse_args(&args).and_then(|cmd| match cmd {
            Command::PluginServe { socket } => run_child(&socket),
            Command::Smoke => run_parent(Plan {
                iterations: SMOKE_ITERATIONS,
                trials: SMOKE_TRIALS,
                warmup: WARMUP_ITERATIONS,
            })
            .map(|j| print!("{j}")),
            Command::Run { plan, output } => run_parent(plan).and_then(|j| {
                fs::write(&output, j)
                    .map_err(|_| BenchError::new("write-failed", "failed to write the output file"))
            }),
        });
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    use fandhe_container_benches::plugin_boundary::{Command, parse_args};
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Command::Smoke) => {
            println!("plugin_boundary: skipped; the plugin boundary requires Unix domain sockets");
            std::process::ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!(
                "error: unsupported-platform: the plugin boundary requires Unix domain sockets"
            );
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
