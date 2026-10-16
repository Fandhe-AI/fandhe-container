//! `start` の実処理: supervisor の bin を起動し、結果の 1 行を期限付きで受け取る adapter
//! （TASK-79 追補・#1718・CLI-1・CORE-1・SUP-1・REPAIR-2・REPAIR-3・REPAIR-4・REPAIR-5・ERR-1・ERR-2・MS-6）。
//!
//! `create_start::run_start` から呼ばれる。CLI は特権を持たず、コンテナの子プロセスを fork しない。
//! `oci_runtime::start`（起動権の予約・launch・Running の記録）を呼ぶ層は supervisor 側にあり（#1314 の配置 1-A）、
//! CLI は `fandhe_container_supervisor::start_contract`（#1717）の契約どおりに supervisor を spawn して
//! 結果の 1 行（`FCSUP1 OK <pid>` / `FCSUP1 ERR <CODE> <exit> <msg>`）を受け取り、終了コードへ写すだけである。
//! CLI は `start` で状態を書かない。したがって、起動や受信に失敗してもプロセスのいない Running を CLI が
//! 残す経路は無い（#1541）。報告の復号は契約の型（`StartReport::decode`）に任せ、ここで書式を組まない・割らない（REPAIR-2）。
//!
//! # 契約の要点（呼び出し側の責務。詳細は `start_contract` の module doc）
//! - argv: `start --root <状態ルートの絶対パス> <id>`（`--restart` は渡さず既定の `no`）。環境変数は契約に含まれないため、
//!   `env_clear` の後に固定の `PATH` だけを渡す（ランチャー経由の起動と同じ環境）。cwd は `/`。
//! - stdin は null、stdout は結果の pipe、stderr は null。supervisor の構造化ログは stderr へ出るが、CLI の stderr は
//!   「失敗時に 1 行の JSON」という契約のため混ぜず、受け手を置かない（保存先は未整備。下記）。
//! - `process_group(0)` で別のプロセスグループにし、端末の SIGINT / SIGHUP が supervisor に届かないようにする。
//!
//! # 期限と子の扱い（REPAIR-5）
//! - 受信期限は `cli_receive_deadline`（既定 36 秒）。期限内に 1 行が来なければ `TIMEOUT`（結果不明）、1 行も無いまま EOF なら
//!   `INTERNAL`。読み込みは `MAX_REPORT_LEN` バイトで頭打ちにし、改行の無い出力で無制限に確保しない。
//! - supervisor は報告の後も生き続け stdout を閉じないため、EOF を待たず 1 行の受信で完了とみなす。
//! - どの枝でも子を `wait` しない。supervisor は CLI より長く生きる前提で、期限切れでも kill しない
//!   （kill すると起動権の予約や子プロセスを宙に浮かせる。後始末は supervisor の責務。利用者は `state` で確かめる）。
//!
//! # 待機中のシグナル（#2069・CLI-1・ERR-2・REPAIR-5・PLUG-7）
//! 結果待ちの間に SIGINT・SIGTERM・SIGHUP を受けたときの扱いは、現状の挙動を契約とする（Linux のみ。
//! `tests/start_signal_interrupt.rs` が具体値で固定する）。
//! - CLI: `signals` の固定ハンドラが plugin へ転送してから同じシグナルを自分へ再送し、シグナル終了する
//!   （`ExitStatus::signal()` が 2 / 15 / 1、`code()` は `None`。シェル上は 128+N）。`main` へ戻らないため stderr に
//!   構造化エラーの JSON は出ず、stdout も空で、この起動の op ログの行も書かれない（REPAIR-4 の観測の穴）。
//! - supervisor: plugin の登録表に載らず転送されない。`process_group(0)` で別グループのため、端末から前面グループへ
//!   配送される SIGINT・SIGHUP も届かない。start を続け、結果の 1 行を書くときは読み手が居らず EPIPE になる
//!   （std は SIGPIPE を無視する）が、報告の失敗を構造化ログへ出して監視・後始末を続ける。
//! - 状態: CLI は `start` で状態を書かない（#1541）。supervisor が成功すれば Running を記録し、失敗すれば自分の
//!   後始末の規則で Created へ戻す。利用者は `state`・`list` で確かめる（期限切れの `TIMEOUT` と同じ案内）。
//! - 起動時に `SIG_IGN` を継承したシグナルはハンドラが入らず無視され、待機は期限まで続く。
//! - 待機の取り消しを supervisor へ伝える経路は無い。#2058 の制御チャネルが入った後の将来課題とする。
//!
//! # 未実装・簡易実装（REPAIR-3）
//! - 実行ファイルは CLI 自身の実体パスと同じディレクトリの固定名 `fandhe-container-supervisor` から解決する
//!   （`PATH` 探索・環境変数・引数による上書きは作らない）。`PATH` 上の symlink から起動されても、Linux の `current_exe()` は
//!   `/proc/self/exe` の解決結果（実体のパス）を返すため、argv[0] や symlink の置き場所ではなく実体のディレクトリを見る
//!   （配布手順は CLI を launcher・supervisor と同じディレクトリに置く。#2068・SUP-14）。同一ユーザーで起動するため CLI と supervisor の間に権限の境界は無く、
//!   実行ファイルの所有者・権限の fd 経由の検証は特権経路のランチャー（#1719）の責務とする。
//! - rootful の特権起動でランチャー（`fandhe-container-launcher`）を選ぶ規則は未実装（#1719・#1722）。
//! - supervisor の stderr（構造化ログ）の保存先は未整備。
//! - 親から継承した CLOEXEC の無い fd は CLI では閉じない。supervisor の bin の入口が fd 3 以降を閉じる
//!   （ランチャー経由と同じ処理。#2070・SEC-1）。exec から入口までの短い窓は残る。
//! - core の本番 launcher（#1715 の Phase B）が入るまで、supervisor は `UNIMPLEMENTED` を報告する。

use std::io::Read;
use std::num::NonZeroU32;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError, StartTimeouts};
use fandhe_container_core::traits::{ContainerId, ErrorCode};
use fandhe_container_supervisor::launcher::SUPERVISOR_FILE_NAME;
use fandhe_container_supervisor::start_contract::{
    MAX_REPORT_LEN, StartReport, cli_receive_deadline,
};

/// supervisor へ渡す `PATH` の値（固定）。ランチャーの `FIXED_PATH_ENV` と同値で、呼び出し元の `PATH` は渡さない。
const SUPERVISOR_PATH_ENV: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// EINTR で 1 バイトも読めなかった read をやり直す回数の上限（REPAIR-5）。
const READ_INTERRUPT_RETRIES: u32 = 16;

/// 結果チャネルの読み取り結果。
#[derive(Debug, PartialEq, Eq)]
enum Received {
    /// 改行まで、または `MAX_REPORT_LEN` バイトまでの読み取り（復号は呼び出し側）。
    Line(Vec<u8>),
    /// 1 バイトも来ないまま EOF。
    Eof,
    /// 読み取りの失敗（EINTR の再試行上限超過を含む）。
    ReadError,
    /// 期限内に 1 行が来なかった。
    TimedOut,
}

fn start_error(code: ErrorCode, message: &str) -> OciRuntimeError {
    OciRuntimeError::new(LifecycleOp::Start, code, message)
}

/// 最初の `\n` まで、最大 `MAX_REPORT_LEN` バイトを 1 バイトずつ読む（上限の無い `read_line` は使わない。REPAIR-5）。
fn read_report_line(mut out: impl Read) -> Received {
    let mut buf = Vec::with_capacity(MAX_REPORT_LEN);
    let mut byte = [0u8; 1];
    let mut interrupts = 0u32;
    loop {
        match out.read(&mut byte) {
            Ok(0) => {
                return if buf.is_empty() {
                    Received::Eof
                } else {
                    // 改行の無い途中までの行。復号側が未終端として拒否する。
                    Received::Line(buf)
                };
            }
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' || buf.len() >= MAX_REPORT_LEN {
                    return Received::Line(buf);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                interrupts += 1;
                if interrupts > READ_INTERRUPT_RETRIES {
                    return Received::ReadError;
                }
            }
            Err(_) => return Received::ReadError,
        }
    }
}

/// 補助スレッドで [`read_report_line`] を行い、`within` を過ぎたら [`Received::TimedOut`] を返す。
///
/// 期限切れのとき補助スレッドは read で止まったまま残る（CLI は直後に終了する。子は kill しないため pipe は閉じない）。
fn receive_report(out: impl Read + Send + 'static, within: Duration) -> Received {
    let (tx, rx) = mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("supervisor-report".to_string())
        .spawn(move || {
            let _ = tx.send(read_report_line(out));
        });
    if spawned.is_err() {
        return Received::ReadError;
    }
    match rx.recv_timeout(within) {
        Ok(r) => r,
        Err(mpsc::RecvTimeoutError::Timeout) => Received::TimedOut,
        Err(mpsc::RecvTimeoutError::Disconnected) => Received::ReadError,
    }
}

/// 受信結果を `start` の結果へ写す（ERR-1・ERR-2）。報告は untrusted として復号で検証済みの値だけを使い、
/// 壊れた報告は `INTERNAL` で fail-closed にする（利用者の引数の誤りではないため `INVALID_ARGUMENT` には写さない）。
fn map_received(received: Received) -> Result<NonZeroU32, OciRuntimeError> {
    const MALFORMED: &str = "supervisor start report is malformed";
    match received {
        Received::Line(bytes) => match StartReport::decode(&bytes) {
            Ok(StartReport::Started { pid }) => Ok(pid),
            Ok(StartReport::Failed { code, message, .. }) => {
                Err(start_error(code, message.as_str()))
            }
            Ok(_) | Err(_) => Err(start_error(ErrorCode::Internal, MALFORMED)),
        },
        Received::Eof => Err(start_error(
            ErrorCode::Internal,
            "supervisor exited without reporting a start result",
        )),
        Received::ReadError => Err(start_error(
            ErrorCode::Internal,
            "failed to read the supervisor start result",
        )),
        Received::TimedOut => Err(start_error(
            ErrorCode::Timeout,
            "supervisor did not report a start result within the deadline; check the container state",
        )),
    }
}

/// 契約どおりの argv・stdio・環境・cwd・プロセスグループを `cmd` に設定する（シェルも文字列連結も使わない）。
fn configure(cmd: &mut Command, root: &Path, id: &ContainerId) {
    cmd.arg("start")
        .arg("--root")
        .arg(root)
        .arg(id.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", SUPERVISOR_PATH_ENV)
        .current_dir("/")
        .process_group(0);
}

/// CLI の実体パスと同じディレクトリの固定名から supervisor の実行ファイルを決める（`PATH` 探索をしない。純関数）。
fn supervisor_path_beside(cli_exe: &Path) -> Result<PathBuf, OciRuntimeError> {
    match cli_exe.parent() {
        Some(dir) if dir.is_absolute() => Ok(dir.join(SUPERVISOR_FILE_NAME)),
        _ => Err(start_error(
            ErrorCode::FailedPrecondition,
            "cannot resolve the cli executable path",
        )),
    }
}

/// 設定済みの `cmd` を spawn し、結果の 1 行を `receive_within` まで待って `start` の結果へ写す。
///
/// 戻りの `Child` はテストが回収するためのもの。本番の呼び出し側は `wait` せずに drop する（supervisor は
/// CLI より長く生きる。drop は kill しない）。1 行も来ないまま EOF の枝だけ、既に終了した子を 1 回 `try_wait` で回収する
/// （ECHILD 等の失敗は無視する）。
fn launch_and_receive(
    mut cmd: Command,
    receive_within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = if e.kind() == std::io::ErrorKind::NotFound {
                start_error(
                    ErrorCode::FailedPrecondition,
                    "supervisor executable is not installed",
                )
            } else {
                start_error(
                    ErrorCode::Internal,
                    &format!("failed to spawn the supervisor: {}", e.kind()),
                )
            };
            return (Err(err), None);
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return (
            Err(start_error(
                ErrorCode::Internal,
                "failed to read the supervisor start result",
            )),
            Some(child),
        );
    };
    let received = receive_report(stdout, receive_within);
    if received == Received::Eof {
        let _ = child.try_wait();
    }
    (map_received(received), Some(child))
}

/// CLI の受信期限（既定 36 秒。supervisor の内部上限 34 秒（手順 8 の見込み 28 秒 + cgroup 準備 6 秒。`result_deadline` 参照） + 受信の猶予 2 秒。REPAIR-5）。
fn production_deadline() -> Duration {
    cli_receive_deadline(&StartTimeouts::default())
}

/// 本番入口: supervisor を起動して pid か構造化エラーを期限付きで受け取る。
///
/// `root` は `StateRoot::resolve` で解決した絶対パス。`id` は `ContainerId::new` で検証済みの値。
pub(super) fn start_via_supervisor(
    root: &Path,
    id: &ContainerId,
) -> Result<NonZeroU32, OciRuntimeError> {
    let cli_exe = std::env::current_exe().map_err(|_| {
        start_error(
            ErrorCode::FailedPrecondition,
            "cannot resolve the cli executable path",
        )
    })?;
    let program = supervisor_path_beside(&cli_exe)?;
    let mut cmd = Command::new(program);
    configure(&mut cmd, root, id);
    let (result, child) = launch_and_receive(cmd, production_deadline());
    // supervisor は CLI より長く生きる。wait も kill もせずに手放す。
    drop(child);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{OCI_EXIT_TIMEOUT, create};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerState, CreateRequest, GetStateRequest, StateRecord, StateStore,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    /// テスト用の一意な一時ディレクトリ（Drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("fc-sup-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("mkdir");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 状態ストアに Created のレコードを 1 件用意した環境。
    struct Fixture {
        _dir: TmpDir,
        root: PathBuf,
        store: FileStateStore,
        id: ContainerId,
        before: StateRecord,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = TmpDir::new(tag);
            let bundle = dir.0.join("bundle");
            std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
            std::fs::write(
                bundle.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            let root = dir.0.join("state");
            let store = FileStateStore::open(StateRoot::from_override(root.clone()).expect("root"))
                .expect("open");
            let id = ContainerId::new("c1").expect("id");
            let req = CreateRequest::new(id.clone(), bundle).expect("req");
            create(&store, &OpRecorder::new(), &req).expect("create");
            let before = store.get(&GetStateRequest::new(id.clone())).expect("get");
            Self {
                _dir: dir,
                root,
                store,
                id,
                before,
            }
        }

        /// 状態が Created・pid なし・revision 不変のままであること（CLI は start で状態を書かない。#1541）。
        fn assert_state_untouched(&self) {
            let after = self
                .store
                .get(&GetStateRequest::new(self.id.clone()))
                .expect("get");
            assert_eq!(after.status().state(), ContainerState::Created);
            assert_eq!(after.status().pid(), None);
            assert_eq!(after.revision(), self.before.revision());
        }

        /// `/bin/sh -c <script>` を契約の引数つきで組む（ファイルを書いて exec しないため ETXTBSY を避けられる）。
        fn fake(&self, script: &str) -> Command {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg(script).arg("fake-supervisor");
            configure(&mut cmd, &self.root, &self.id);
            cmd
        }
    }

    /// 回収を伴う後始末（子を kill して wait する）。
    fn reap(child: Option<Child>) {
        if let Some(mut c) = child {
            let _ = c.kill();
            // REPAIR-5: 回収も有限の猶予（5 秒）で打ち切る（超過時は回収を諦める）。
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match c.try_wait() {
                    Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                    _ => break,
                }
            }
        }
    }

    const ARGV_CHECK: &str = r#"[ "$1" = start ] && [ "$2" = --root ] && [ "$4" = c1 ] || { printf 'FCSUP1 ERR INTERNAL 1 badargs\n'; exit 0; }; "#;

    /// SUP-1・CLI-1: OK の報告を受けて pid を返し、wait せずに戻る。argv は契約どおりで、状態は CLI が書かない。
    #[test]
    fn sup1_cli1_receives_started_report() {
        let fx = Fixture::new("ok");
        let script = format!("{ARGV_CHECK}printf 'FCSUP1 OK 4242\\n'; exec sleep 5");
        let t = Instant::now();
        let (result, child) = launch_and_receive(fx.fake(&script), Duration::from_secs(10));
        let elapsed = t.elapsed();
        reap(child);
        assert_eq!(result.expect("started").get(), 4242);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        fx.assert_state_untouched();
    }

    /// ERR-2・CLI-1: ERR の報告は code・exit_code・message をそのまま写し、op は start。状態は不変。
    #[test]
    fn err2_cli_maps_failed_report() {
        let fx = Fixture::new("err");
        let script = "printf 'FCSUP1 ERR UNIMPLEMENTED 8 production process launcher is not available yet\\n'";
        let (result, child) = launch_and_receive(fx.fake(script), Duration::from_secs(10));
        reap(child);
        let e = result.expect_err("failed");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.exit_code().get(), 8);
        assert_eq!(e.op(), LifecycleOp::Start);
        assert_eq!(
            e.message(),
            "production process launcher is not available yet"
        );
        fx.assert_state_untouched();
    }

    /// REPAIR-5: 期限内に報告が無ければ TIMEOUT（結果不明）。supervisor は kill されず、状態は不変。
    #[test]
    fn repair5_cli_times_out_without_report() {
        let fx = Fixture::new("timeout");
        let t = Instant::now();
        let (result, child) =
            launch_and_receive(fx.fake("exec sleep 5"), Duration::from_millis(300));
        let elapsed = t.elapsed();
        let mut child = child.expect("child");
        let alive = child.try_wait().expect("try_wait").is_none();
        reap(Some(child));
        let e = result.expect_err("timeout");
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert_eq!(e.exit_code(), OCI_EXIT_TIMEOUT);
        assert_eq!(e.exit_code().get(), 7);
        assert!(alive, "supervisor must not be killed on timeout");
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        fx.assert_state_untouched();
    }

    /// SUP-1: 1 行も無いまま EOF なら INTERNAL（supervisor が報告の前に落ちた）。
    #[test]
    fn sup1_cli_internal_on_eof() {
        let fx = Fixture::new("eof");
        let (result, child) = launch_and_receive(fx.fake("exit 0"), Duration::from_secs(10));
        reap(child);
        let e = result.expect_err("eof");
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(
            e.message(),
            "supervisor exited without reporting a start result"
        );
        fx.assert_state_untouched();
    }

    /// REPAIR-2: 壊れた報告（接頭辞違い・pid 0）は INVALID_ARGUMENT ではなく INTERNAL に写す。
    #[test]
    fn repair2_cli_internal_on_malformed_report() {
        for body in ["garbage", "FCSUP1 OK 0"] {
            let fx = Fixture::new("malformed");
            let script = format!("printf '{body}\\n'; exec sleep 5");
            let (result, child) = launch_and_receive(fx.fake(&script), Duration::from_secs(10));
            reap(child);
            let e = result.expect_err("malformed");
            assert_eq!(e.code(), ErrorCode::Internal, "{body}");
            assert_eq!(e.exit_code().get(), 1, "{body}");
            assert_eq!(e.message(), "supervisor start report is malformed");
            fx.assert_state_untouched();
        }
    }

    /// REPAIR-5: 改行の無い出力は上限（640 バイト）で打ち切って INTERNAL にし、期限まで待たない。
    #[test]
    fn repair5_cli_report_read_is_bounded() {
        let fx = Fixture::new("bounded");
        let script = "head -c 1024 /dev/zero | tr '\\0' x; exec sleep 5";
        let t = Instant::now();
        let (result, child) = launch_and_receive(fx.fake(script), Duration::from_secs(10));
        let elapsed = t.elapsed();
        reap(child);
        let e = result.expect_err("bounded");
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(e.message(), "supervisor start report is malformed");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        fx.assert_state_untouched();
    }

    /// ERR-2: 実行ファイルが無ければ FAILED_PRECONDITION（5）で、状態は不変。
    #[test]
    fn err2_cli_spawn_not_installed() {
        let fx = Fixture::new("noexe");
        let mut cmd = Command::new(fx.root.join("no-such-supervisor"));
        configure(&mut cmd, &fx.root, &fx.id);
        let (result, child) = launch_and_receive(cmd, Duration::from_secs(10));
        assert!(child.is_none());
        let e = result.expect_err("not installed");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.exit_code().get(), 5);
        assert_eq!(e.message(), "supervisor executable is not installed");
        fx.assert_state_untouched();
    }

    /// SUP-1: 実行ファイルは CLI の実体の隣の固定名で、相対パス・親の無いパスは拒否する。
    #[test]
    fn sup1_supervisor_path_beside() {
        assert_eq!(
            supervisor_path_beside(Path::new("/opt/x/fandhe-container")).expect("path"),
            PathBuf::from("/opt/x/fandhe-container-supervisor")
        );
        for bad in ["fandhe-container", "rel/fandhe-container", "/", ""] {
            let e = supervisor_path_beside(Path::new(bad)).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{bad}");
            assert_eq!(e.message(), "cannot resolve the cli executable path");
        }
    }

    /// REPAIR-5: 本番の受信期限は 36 秒。
    #[test]
    fn repair5_production_deadline_is_36s() {
        assert_eq!(production_deadline(), Duration::from_secs(36));
    }

    /// 契約: stdout 以外は null、環境は PATH だけ、cwd は `/`、argv は契約の順。
    #[test]
    fn sup1_configure_follows_contract() {
        let id = ContainerId::new("c1").expect("id");
        let mut cmd = Command::new("/bin/true");
        configure(&mut cmd, Path::new("/r"), &id);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["start", "--root", "/r", "c1"]);
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs,
            [("PATH".to_string(), Some(SUPERVISOR_PATH_ENV.to_string()))]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
    }
}
