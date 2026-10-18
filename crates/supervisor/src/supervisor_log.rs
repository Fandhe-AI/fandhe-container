//! supervisor 自身の構造化ログ（stderr に出す固定スキーマの JSON 1 行）の保存先（TASK-79 追補・#2067・REPAIR-4・REPAIR-5）。
//!
//! CLI の `start` は supervisor の stderr を `Stdio::null()` にする（CLI の stderr は失敗時の 1 行 JSON の契約で、
//! supervisor のログを混ぜない。ERR-2）。そのままでは `start_entry::log_event`・`run::StderrLogObserver`・起動の
//! 計測行がどこにも残らないため、supervisor が自分で状態ルート配下のローテーションログを開き、
//! [`crate::stderr_sink::install_stderr_writer`] で共有の出口（[`crate::stderr_sink`]）の書き先をそこへ差し替える。
//! 特権ランチャー経由の起動（#1719）も最後は同じ `run_main` で開くので、保存先は同じになる。
//!
//! # 保存先と名前
//! - ディレクトリ: `<state_root>/@supervisor-logs/`（unix では 0700）。`@` で始まる名前は `ContainerId` にならないため、
//!   core の `FileStateStore` はコンテナ ID として扱わず、コンテナのログ（`<root>/logs`）とも衝突しない
//! - ファイル: [`RotatingFileSink`] の名前空間どおり `<id>.log`（現在）・`.log.1`・`.log.2`（世代）・`.log.lock`（排他）。
//!   記録は 1 行ごとに `stderr <JSON 1 行>`（コンテナログと同じ形式と読み出し入口）
//! - 権限・作成: ファイルは 0600 で `create_new` のみ、既存の現在ログは開かず世代へ退避する。symlink・ディレクトリ・
//!   名前空間の別名があれば何も動かさず拒否する（SEC-1。[`RotatingFileSink::open`] の契約）
//!
//! # 上限とローテーション
//! 1 ファイル [`SUPERVISOR_LOG_FILE_BYTES`]（1 MiB）・[`SUPERVISOR_LOG_GENERATIONS`]（3 世代）で、1 ID あたり最大 3 MiB。
//! 起動のたびに既存の現在ログを 1 世代送る（空なら世代を消費しない）。同じ ID の supervisor が生存中なら flock で
//! 2 本目の open が `FailedPrecondition` になり、稼働中のファイルは動かない。
//!
//! # 書き込みが詰まる・失敗するとき（REPAIR-5）
//! 呼び出し側は `stderr_sink` の有界キューへ `try_send` するだけで、満杯なら捨てる。ファイルへの書き込みが失敗
//! （ENOSPC・EIO 等）すると sink は失敗状態に固定され、以後の書き込みはすぐ `Err` になる。`stderr_sink` の専用スレッドが
//! 失敗行を数えて続けるだけで、監視・回収・restart の経路は止まらない。FS が止まって書き込みが戻らない場合に止まる
//! のも専用スレッドだけで、呼び出し側の待ちは期限つき。
//!
//! # 後始末
//! [`remove`] が delete 時に best effort で全ファイルを消す（stderr へ何も書かない。ERR-2）。消せなかった分は
//! 1 ID あたり 3 MiB に収まり、同じ ID の次の start で世代として回される。
//!
//! # 未実装・残余（REPAIR-3）
//! 保存されるのは `stderr_sink` を通る構造化ログだけ。次は fd 2 へ直接書かれ、CLI 起動では null、ランチャー経由では
//! 呼び出し元の fd 2 を継承する: core の `writeln!(stderr)`（`rootless`・`exec/process`）・監査 sink の stderr
//! フォールバック・panic のメッセージ。core の `exec::diagnostic::emit_diagnostic_line`（`legacy_tiocsti` の警告）は
//! fd 2 が AF_UNIX のソケットのときだけ書くため、保存先には届かない。
//! `legacy_tiocsti` の警告は #2008 の決定で、start の成功後に supervisor が自分で観測し（`start_entry`）、
//! `stderr_sink` 経由で本ログへ 1 行残す（core の fd 2 経路は AF_UNIX の socket のときだけ届き、その構成では重複する）。
//!
//! 呼び出し元: `start_entry::run_main_inner`（open と差し込み）・CLI の `delete`（[`remove`]）。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use crate::logs::rotating::{DEFAULT_LOG_FILE_BYTES, RemovedLogs};
use crate::logs::{LogSink, RotatingFileSink, RotationConfig, StreamKind};

/// 状態ルート直下の保存先ディレクトリ名（`ContainerId` にならない `@` 始まり）。
pub const SUPERVISOR_LOG_DIR_NAME: &str = "@supervisor-logs";
/// 1 ファイルの上限バイト数（コンテナログの既定と同じ 1 MiB）。
pub const SUPERVISOR_LOG_FILE_BYTES: u64 = DEFAULT_LOG_FILE_BYTES;
/// 保持する世代数（現在ログを含む）。
pub const SUPERVISOR_LOG_GENERATIONS: u32 = 3;

/// 保存先ディレクトリのパス（作成はしない）。
pub fn log_dir(root: &Path) -> PathBuf {
    root.join(SUPERVISOR_LOG_DIR_NAME)
}

/// `stderr_sink` の書き手として使う、[`LogSink`] へ行を流すアダプタ。
///
/// 書き込まれたバイト列を LF で割り、空でない区切りごとに 1 行として `append` する（末尾に LF が無い区切りも 1 行）。
/// 失敗は固定文言の `io::Error` にし、パス・errno を含めない（ERR-1）。
pub struct SupervisorLogWriter {
    sink: Arc<dyn LogSink>,
}

impl SupervisorLogWriter {
    /// 任意の sink を包む（試験で失敗・停止する sink を渡す入口）。
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self { sink }
    }
}

impl Write for SupervisorLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for seg in buf.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
            self.sink
                .append(StreamKind::Stderr, seg)
                .map_err(|_| std::io::Error::other("supervisor log write failed"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink
            .flush()
            .map_err(|_| std::io::Error::other("supervisor log flush failed"))
    }
}

/// 保存先ディレクトリを（無ければ 0700 で）作り、`id` のローテーションログを開いて書き手を返す。
///
/// 既存のディレクトリの検証（symlink・種別・権限）は [`RotatingFileSink::open`] が行う。同じ ID の supervisor が
/// 生存中なら `FailedPrecondition`。スレッドは作らない（`start_entry` の手順 2 の単一スレッド前提）。
pub fn open(root: &Path, id: &ContainerId) -> Result<SupervisorLogWriter, TraitError> {
    let config = RotationConfig::new(SUPERVISOR_LOG_FILE_BYTES, SUPERVISOR_LOG_GENERATIONS)?;
    open_with_config(root, id, config)
}

fn open_with_config(
    root: &Path,
    id: &ContainerId,
    config: RotationConfig,
) -> Result<SupervisorLogWriter, TraitError> {
    let dir = log_dir(root);
    create_dir(&dir)?;
    let sink = RotatingFileSink::open(&dir, id, config)?;
    Ok(SupervisorLogWriter::new(Arc::new(sink)))
}

fn create_dir(dir: &Path) -> Result<(), TraitError> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        b
    };
    // unix 以外ではモード指定が無く、変更しないので mut を付けない（unused_mut 回避）。
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    match builder.create(dir) {
        Ok(()) => Ok(()),
        // 既存の検証（symlink・種別・権限）は RotatingFileSink::open の check_dir に任せる。
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(TraitError::new(
            ErrorCode::Internal,
            "failed to create the supervisor log directory",
        )),
    }
}

/// `id` の supervisor ログ（現在ログ・世代・ロック）を消す（stderr へは何も書かない）。
///
/// ディレクトリが無ければ 0 件で成功する（冪等）。同じ ID の supervisor が生存中なら `FailedPrecondition` で何も消さない。
pub fn remove(root: &Path, id: &ContainerId) -> Result<RemovedLogs, TraitError> {
    let dir = log_dir(root);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => RotatingFileSink::remove_all_quiet(&dir, id),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemovedLogs::default()),
        Err(_) => Err(TraitError::new(
            ErrorCode::Internal,
            "supervisor log directory inspection failed",
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::logs::rotating::MIN_LOG_FILE_BYTES;
    use crate::stderr_sink::{EmitOutcome, StderrSink};

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-2067-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn id() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// REPAIR-4: ディレクトリは 0700、ログは 0600、ロックが作られる。
    #[test]
    fn repair4_open_creates_dir_0700_and_log_0600() {
        let t = TmpDir::new("perm");
        let _w = open(&t.0, &id()).unwrap();
        let dir = t.0.join("@supervisor-logs");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("c1.log")), 0o600);
        assert!(dir.join("c1.log.lock").exists());
    }

    /// REPAIR-4: LF 区切りの各行が `stderr <行>` で記録され、空の write は何も書かない。
    #[test]
    fn repair4_writer_records_stderr_prefixed_lines() {
        let t = TmpDir::new("lines");
        let mut w = open(&t.0, &id()).unwrap();
        w.write_all(b"").unwrap();
        w.write_all(b"{\"a\":1}\n{\"b\":2}\n").unwrap();
        w.write_all(b"{\"c\":3}").unwrap();
        w.flush().unwrap();
        let body = fs::read_to_string(t.0.join("@supervisor-logs/c1.log")).unwrap();
        assert_eq!(
            body,
            "stderr {\"a\":1}\nstderr {\"b\":2}\nstderr {\"c\":3}\n"
        );
    }

    /// SEC-1: 保存先ディレクトリが symlink なら拒否し、リンク先に何も作らない。
    #[test]
    fn sec1_open_rejects_symlinked_dir() {
        let t = TmpDir::new("symdir");
        let target = t.0.join("elsewhere");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, t.0.join("@supervisor-logs")).unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    /// SEC-1: 現在ログが symlink なら拒否し、リンク先の内容は変わらない。
    #[test]
    fn sec1_open_rejects_symlink_log() {
        let t = TmpDir::new("symlog");
        let dir = t.0.join("@supervisor-logs");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = t.0.join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("c1.log")).unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
    }

    /// SUP-7: 内容のある既存の現在ログは世代 1 へ移り、新しい現在ログは空になる。
    #[test]
    fn sup7_open_rotates_existing_log() {
        let t = TmpDir::new("rot");
        let dir = t.0.join("@supervisor-logs");
        {
            let mut w = open(&t.0, &id()).unwrap();
            w.write_all(b"old\n").unwrap();
            w.flush().unwrap();
        }
        let _w = open(&t.0, &id()).unwrap();
        assert_eq!(fs::read(dir.join("c1.log.1")).unwrap(), b"stderr old\n");
        assert_eq!(fs::metadata(dir.join("c1.log")).unwrap().len(), 0);
    }

    /// REPAIR-5: 上限を超える書き込みでも全ファイルが上限以内で、ファイル数は世代数以内。
    #[test]
    fn repair5_size_cap() {
        let t = TmpDir::new("cap");
        let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 2).unwrap();
        let mut w = open_with_config(&t.0, &id(), cfg).unwrap();
        let line = vec![b'x'; 1000];
        for _ in 0..200 {
            w.write_all(&line).unwrap();
        }
        w.flush().unwrap();
        let dir = t.0.join("@supervisor-logs");
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".lock"))
            .collect();
        names.sort();
        assert_eq!(names, ["c1.log", "c1.log.1"]);
        for n in names {
            assert!(fs::metadata(dir.join(n)).unwrap().len() <= MIN_LOG_FILE_BYTES);
        }
    }

    /// SUP-7: 1 本目が生きている間の 2 本目は FailedPrecondition で、既存ファイルを動かさない。
    #[test]
    fn sup7_second_open_while_alive_is_failed_precondition() {
        let t = TmpDir::new("second");
        let mut w = open(&t.0, &id()).unwrap();
        w.write_all(b"live\n").unwrap();
        w.flush().unwrap();
        let e = open(&t.0, &id()).err().expect("must be rejected");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        let dir = t.0.join("@supervisor-logs");
        assert_eq!(fs::read(dir.join("c1.log")).unwrap(), b"stderr live\n");
        assert!(!dir.join("c1.log.1").exists());
    }

    /// REPAIR-4: remove は全ファイルを消し冪等。生存中は FailedPrecondition で何も消さない。
    #[test]
    fn repair4_remove_deletes_all_and_is_idempotent() {
        let t = TmpDir::new("rm");
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 0);
        let dir = t.0.join("@supervisor-logs");
        {
            let mut w = open(&t.0, &id()).unwrap();
            w.write_all(b"a\n").unwrap();
            w.flush().unwrap();
            let e = remove(&t.0, &id()).expect_err("alive");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert!(dir.join("c1.log").exists());
        }
        // 現在ログ（空）と世代 1（"a"）を持つ状態を作ってから消す。
        drop(open(&t.0, &id()).unwrap());
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 2);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(remove(&t.0, &id()).unwrap().log_files(), 0);
    }

    struct FailingSink;

    impl LogSink for FailingSink {
        fn append(&self, _s: StreamKind, _l: &[u8]) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "log write failed"))
        }
    }

    /// 解放されるまで `append` が戻らない sink。
    struct StuckSink(std::sync::Mutex<std::sync::mpsc::Receiver<()>>);

    impl LogSink for StuckSink {
        fn append(&self, _s: StreamKind, _l: &[u8]) -> Result<(), TraitError> {
            let _ = self.0.lock().unwrap().recv();
            Ok(())
        }
    }

    /// REPAIR-5: 書き込みが失敗しても呼び出し側は待たず、失敗は行数つきで返る。
    #[test]
    fn repair5_failing_log_sink_does_not_block() {
        let w = SupervisorLogWriter::new(Arc::new(FailingSink));
        let sink = StderrSink::spawn(w, 8);
        let started = Instant::now();
        assert_eq!(sink.emit(b"{}\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(
            sink.flush(Duration::from_secs(5)),
            EmitOutcome::WriteFailed { failed_lines: 1 }
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// REPAIR-5: 書き込みが戻らなくても `emit` は待たず、`emit_and_wait` は期限で打ち切られる。
    #[test]
    fn repair5_stuck_log_sink_does_not_block_callers() {
        let (release, rx) = std::sync::mpsc::channel();
        let w = SupervisorLogWriter::new(Arc::new(StuckSink(std::sync::Mutex::new(rx))));
        let sink = StderrSink::spawn(w, 8);
        let started = Instant::now();
        assert_eq!(sink.emit(b"{}\n".to_vec()), EmitOutcome::Queued);
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            sink.emit_and_wait(b"{}\n".to_vec(), Duration::from_millis(200)),
            EmitOutcome::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(release);
    }
}
