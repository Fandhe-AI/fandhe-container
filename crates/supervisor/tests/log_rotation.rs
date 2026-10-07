//! TASK-164.2（#506）・SUP-7: 実パイプ経由の捕捉をローテーション sink へ流し、世代切り替え後も
//! 全ファイルが上限以内であることを公開 API だけで照合する結合試験（root 不要・3 OS で実行）。

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::ContainerId;
use fandhe_container_supervisor::logs::rotating::MIN_LOG_FILE_BYTES;
use fandhe_container_supervisor::logs::{
    LogCapture, OutputStreams, ReaderBudget, RotatingFileSink, RotationConfig,
};

struct TmpDir(PathBuf);

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// SUP-7: 複数回ローテーションしても全ファイルが上限以内で、捕捉側にエラーが出ない。
#[test]
fn sup7_task164_2_pipe_capture_rotates_within_limit() {
    let dir = std::env::temp_dir().join(format!("fc-sup7-it-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let _guard = TmpDir(dir.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 3).unwrap();
    let sink =
        Arc::new(RotatingFileSink::open(&dir, &ContainerId::new("it1").unwrap(), cfg).unwrap());

    let (out_r, mut out_w) = std::io::pipe().unwrap();
    let cap = LogCapture::start(
        OutputStreams::new(&ReaderBudget::with_max_limit(), Some(Box::new(out_r)), None),
        sink.clone(),
    )
    .unwrap();
    let line = format!("{}\n", "a".repeat(999));
    for _ in 0..500 {
        out_w.write_all(line.as_bytes()).unwrap();
    }
    drop(out_w);
    let summary = cap.drain(Duration::from_secs(10)).unwrap();
    assert_eq!(summary.stdout().and_then(|s| s.error_code()), None);

    assert_eq!(sink.rotations().unwrap(), 7);
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    // ログ 3 世代と、同一 ID の排他に使う空のロックファイルだけがある。
    assert_eq!(names, ["it1.log", "it1.log.1", "it1.log.2", "it1.log.lock"]);
    assert_eq!(fs::metadata(dir.join("it1.log.lock")).unwrap().len(), 0);
    // 500 行 × 1007 バイト（"stdout " 7 + 999 + LF 1）。1 ファイルは 65 行（65,455 バイト）で、
    // 7 回のローテーション後は現在ログに 45 行が残る。保持中の合計は上限 × 世代数以内。
    let lens: Vec<u64> = ["it1.log", "it1.log.1", "it1.log.2"]
        .iter()
        .map(|n| fs::metadata(dir.join(n)).unwrap().len())
        .collect();
    assert_eq!(lens, [45 * 1007, 65 * 1007, 65 * 1007]);
    assert!(lens.iter().all(|l| *l <= cfg.max_file_bytes()));
    assert!(lens.iter().sum::<u64>() <= cfg.max_file_bytes() * u64::from(cfg.generations()));
}
