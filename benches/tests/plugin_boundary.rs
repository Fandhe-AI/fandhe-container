//! `plugin_boundary` ベンチ計測ロジックの結合試験（TASK-113.1・PLUG-5・REPAIR-5）。
//! サーバーループはスレッドで動かし、実 UDS 越しに少数回だけ計測する。待ちはすべて有限の期限付き。

#[cfg(not(unix))]
#[test]
fn plug5_framed_path_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, UdsStream};
    let err = UdsStream::connect(
        std::path::Path::new("s.sock"),
        std::time::Duration::from_secs(1),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use fandhe_container_benches::plugin_boundary::{
        METRIC_FRAMED, METRIC_INPROC, Model, Plan, measure_framed, measure_inproc, results_json,
        run_op_a_framed, run_op_a_inproc, serve,
    };
    use fandhe_container_plugin::{UdsListener, UdsStream};

    const WAIT: Duration = Duration::from_secs(5);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpbt-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// listener と、`serve` を回すスレッド（plugin 役）への接続済み stream を返す。
    fn connected() -> (TempDir, UdsStream, thread::JoinHandle<()>) {
        let dir = TempDir::new();
        let listener = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
        let path = listener.path().to_path_buf();
        let h = thread::spawn(move || {
            let mut s = UdsStream::connect(
                &path,
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            serve(&mut s).unwrap();
        });
        let core_side = listener
            .accept(
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
        (dir, core_side, h)
    }

    /// PLUG-5: 境界越しと同一プロセスの双方を計測でき、応答内容が一致する。
    #[test]
    fn plug5_both_paths_measured_and_outcomes_match() {
        let (_dir, mut stream, h) = connected();
        let mut id = 0;
        let framed = run_op_a_framed(&mut stream, &mut id).unwrap();
        let inproc = run_op_a_inproc(&mut Model::new()).unwrap();
        assert_eq!(framed, inproc);
        assert_eq!(id, 3);

        let plan = Plan {
            iterations: 20,
            trials: 2,
            warmup: 5,
        };
        let f = measure_framed(plan, &mut stream).unwrap();
        let i = measure_inproc(plan).unwrap();
        assert!(f > 0 && i > 0);
        let json = results_json(i, f).unwrap();
        assert!(json.contains(METRIC_INPROC) && json.contains(METRIC_FRAMED));
        assert!(json.contains("plugin_boundary_op_a_delta_p50"));
        drop(stream);
        h.join().unwrap();
    }

    /// REPAIR-5: 相手が消えた場合に有限時間で失敗する（ウォッチドッグ付き）。
    #[test]
    fn repair5_peer_gone_fails_in_bounded_time() {
        let dir = TempDir::new();
        let listener = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
        let path = listener.path().to_path_buf();
        // macOS では相手が切断済みの socket に set_{read,write}_timeout すると EINVAL になるため、
        // accept が完了するまで client を生かし、その後に切断して「相手が消えた」状態を作る。
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let client = thread::spawn(move || {
            let s = UdsStream::connect(
                &path,
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            let _ = go_rx.recv_timeout(Duration::from_secs(15));
            drop(s);
        });
        let mut stream = listener
            .accept(
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
        go_tx.send(()).unwrap();
        client.join().unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut id = 0;
            let _ = tx.send(run_op_a_framed(&mut stream, &mut id).map(|_| ()));
        });
        let r = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("watchdog expired");
        assert_eq!(r.unwrap_err().code, "unavailable");
    }
}
