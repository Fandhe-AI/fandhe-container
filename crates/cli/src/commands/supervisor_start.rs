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
//! - argv: `start --root <状態ルートの絶対パス> <id>`（`--restart` は渡さず既定の `no`）。`env_clear` の後に渡す環境は
//!   許可リストの 2 つだけ: 固定の `PATH` と、`XDG_RUNTIME_DIR`（systemd-run が user マネージャへ接続するため。絶対パスを検証する）。
//!   `DBUS_SESSION_BUS_ADDRESS` は渡さない（sd-bus のアドレスは `unixexec:` 等で任意プログラムの起動や接続先の付け替えができ、
//!   user マネージャの直結ソケット `$XDG_RUNTIME_DIR/systemd/private` だけで足りる。`man sd_bus_default` と systemd の
//!   `src/shared/bus-util.c` の `bus_connect_user_systemd`）。supervisor は契約の値を環境から読まず、状態ルートは常に
//!   `--root` で受けるため、契約に反しない。cwd は `/`。
//! - stdin は null、stdout は結果の pipe、stderr は null。CLI の stderr は「失敗時に 1 行の JSON」という契約のため、
//!   supervisor のログを混ぜず受け手も置かない。supervisor の構造化ログは supervisor 自身が `<root>/@supervisor-logs/<id>.log*`
//!   へ保存する（サイズ上限・世代ローテーションつき。`fandhe_container_supervisor::supervisor_log`。#2067・REPAIR-4）。
//!   `delete` が後始末する（`stop_delete`）。
//! - `process_group(0)` で別のプロセスグループにし、端末の SIGINT / SIGHUP が supervisor に届かないようにする。
//!
//! # 委譲スコープでの起動（#2081・CORE-3・CORE-4・SEC-5）
//! supervisor 側の `DelegatedCgroup::prepare` は、委譲された親 cgroup に自分以外のプロセスがいると拒否する。CLI と同じ
//! cgroup（端末のシェルと同居）で起動するとほぼ必ず拒否されるため、`systemd-run --user --scope --quiet -p Delegate=yes --`
//! （`start_contract::USER_SCOPE_WRAPPER_ARGS`）で包み、supervisor を新しい scope で一人で動かす。
//! systemd-run は scope の登録後に同じプロセスで `execvpe` する（`man systemd-run` の「scope として実行するコマンドは
//! systemd-run 自身が親プロセスとして実行し〜同期的」の段落と systemd の `src/run/run.c` の `start_transient_scope`）。
//! したがって spawn した `Child` の pid・`process_group(0)`・stdio・渡した環境はそのまま supervisor のものになり、
//! CLI は scope に居残らない。scope の取得時間も受信期限（36 秒）に含まれる。
//! fail-closed（案 B の「CLI の cgroup の下に子 cgroup を作る」へは落とさない）の判定はすべて spawn の前に行う。
//! - rootful（`/proc/self/status` の uid のどれかが 0）: `UNIMPLEMENTED`（supervisor の判定と同じ文）。
//! - `systemd-run` が固定候補（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`。`PATH` 探索はしない。PLUG-11）に無い、または
//!   実体が root 所有の通常ファイルで group / other 書き込み不可（祖先ディレクトリも同様）でない: `FAILED_PRECONDITION`。
//!   検証から exec までの TOCTOU は、root 所有で非 root が書けない場所に限ることで抑える（CLI と supervisor は同じ uid で
//!   権限の境界が無いため、fd 経由の検証は特権ランチャー〔#1719〕の責務とする）。
//! - `XDG_RUNTIME_DIR` が絶対パスでない、または `systemd/private` が euid 所有のソケットでない（symlink は辿らない）:
//!   `FAILED_PRECONDITION`（user マネージャに届かない）。
//! - 委譲が効いていない場合の判定は supervisor の `detect` / `prepare` が行い、その報告を `map_received` が写す。
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
//!   構造化エラーの JSON は出ず、stdout も空で、この起動の op ログ（`FANDHE_CONTAINER_OP_LOG`）の行も書かれない（REPAIR-4 の観測の穴）。
//!   残せない理由: ハンドラは async-signal-safe な操作（atomic・`kill`・`raise`）しか使えず、op ログの出力は JSON の
//!   組み立て（割り当て）と symlink・ハードリンク・親の検証つきの open を伴うため呼べない。ハンドラは全コマンド共通で
//!   `SA_RESETHAND` のうえ再送する契約でもある。後続の候補は、事前に開いた fd と固定バッファへハンドラから
//!   `write(2)` だけを行う案と、結果待ちの間だけ再送を遅らせ待機側が書いてから再送する案（#2132）。
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
//! - supervisor の fd 2 へ直接書かれるもの（core の診断・panic のメッセージ等）は保存されない（stderr が null のため捨てられる。
//!   範囲は `supervisor_log` の「未実装・残余」。`legacy_tiocsti` の警告の届け方は #2008）。
//! - 親から継承した CLOEXEC の無い fd は CLI では閉じない。supervisor の bin の入口が fd 3 以降を閉じる
//!   （ランチャー経由と同じ処理。#2070・SEC-1）。exec から入口までの短い窓は残る。
//! - supervisor は core の本番 launcher（#1715・#1819 で結線済み）で起動する。権限モデルは rootless のみで、
//!   rootful は spawn の前に `UNIMPLEMENTED`（上記）。restart の再 launch は fail-closed（#2043）。実機での通し確認
//!   （委譲 cgroup の準備で拒否されないか）は未実施（#2062。`tests/supervisor_bin_real.rs` は実機前提）。
//! - 1 行も無いまま EOF のとき、supervisor の異常終了と systemd-run の失敗（D-Bus 接続の失敗等）を区別できない
//!   （stderr を pipe にすると supervisor の構造化ログが混ざり、CLI の終了後に EPIPE になるため採らない。制御チャネル #2058 の後の課題）。
//! - 固定候補の外にある `systemd-run`（NixOS 等）には未対応。
//! - 試験専用 feature `start-test-support` のときだけ、環境変数 `FANDHE_CONTAINER_TEST_SYSTEMD_RUN`（絶対パス）で
//!   systemd-run の解決を差し替えられる（所有者の検証だけを飛ばす。他の検査は飛ばさない）。本番のビルドにはこの環境変数を
//!   読むコードが存在せず、最適化ビルドで feature を有効にするとコンパイルが止まる（`lib.rs`）。

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::num::NonZeroU32;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError, StartTimeouts};
use fandhe_container_core::traits::{ContainerId, ErrorCode};
use fandhe_container_supervisor::launcher::SUPERVISOR_FILE_NAME;
use fandhe_container_supervisor::privilege::parse_proc_status;
use fandhe_container_supervisor::start_contract::{
    MAX_REPORT_LEN, StartReport, USER_SCOPE_WRAPPER_ARGS, cli_receive_deadline,
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

/// 1 行も無いまま EOF のときの message（supervisor の異常終了と systemd-run の失敗を区別できない。REPAIR-3）。
const EOF_MESSAGE: &str = "supervisor exited without reporting a start result (systemd-run may have failed to create the user scope)";

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
        Received::Eof => Err(start_error(ErrorCode::Internal, EOF_MESSAGE)),
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
                    "systemd-run is not installed; starting a container requires a systemd user manager",
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

/// systemd-run の固定の探索先（`SUPERVISOR_PATH_ENV` と同じ順序。`PATH` 探索はしない。PLUG-11）。
const SYSTEMD_RUN_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// 固定候補に置く systemd-run の実行ファイル名。
const SYSTEMD_RUN_NAME: &str = "systemd-run";

/// 試験専用: systemd-run の解決を差し替える環境変数（feature `start-test-support` のときだけ読む）。
#[cfg(feature = "start-test-support")]
const TEST_SYSTEMD_RUN_ENV: &str = "FANDHE_CONTAINER_TEST_SYSTEMD_RUN";

/// `/proc/self/status` の読み取り上限（`privilege::MAX_STATUS_BYTES` と同じ）。
const MAX_STATUS_READ: u64 = fandhe_container_supervisor::privilege::MAX_STATUS_BYTES as u64;

/// rootful 判定と euid の取得（純関数。SEC-5）。real / effective / saved / fs の uid のどれかが 0 なら
/// supervisor の `privilege_for_status` と同じ文で `UNIMPLEMENTED`、読めない・壊れた入力は `FAILED_PRECONDITION`。
fn privilege_gate(status_text: &str) -> Result<u32, OciRuntimeError> {
    let snapshot = parse_proc_status(status_text).map_err(|_| {
        start_error(
            ErrorCode::FailedPrecondition,
            "process status is unreadable",
        )
    })?;
    let uid = snapshot.uid;
    if [uid.real, uid.effective, uid.saved, uid.fs].contains(&0) {
        return Err(start_error(
            ErrorCode::Unimplemented,
            "rootful start is not supported by the production launcher",
        ));
    }
    Ok(uid.effective)
}

/// `/proc/self/status` を上限つきで読む。
fn read_self_status() -> Result<String, OciRuntimeError> {
    let unreadable = || {
        start_error(
            ErrorCode::FailedPrecondition,
            "process status is unreadable",
        )
    };
    let file = std::fs::File::open("/proc/self/status").map_err(|_| unreadable())?;
    let mut text = String::new();
    file.take(MAX_STATUS_READ + 1)
        .read_to_string(&mut text)
        .map_err(|_| unreadable())?;
    Ok(text)
}

/// group / other に書き込み権が無く、所有者が `owner` であること。
fn is_owned_and_closed(meta: &std::fs::Metadata, owner: u32) -> bool {
    meta.uid() == owner && meta.mode() & 0o022 == 0
}

/// 固定候補から systemd-run の実体を決める（PLUG-11 の方針に揃え `PATH` 探索をしない）。
///
/// 最初に存在した候補を `canonicalize`（usrmerge の `/bin -> usr/bin` を解く）し、実体が実行ビットのある通常ファイルで
/// `required_owner` 所有・group / other 書き込み不可、かつ `ancestor_floor` 以下の祖先ディレクトリがすべて同じ条件であることを
/// 確かめる。本番は `required_owner = 0`・`ancestor_floor = "/"`。試験は一時ディレクトリを floor にして成功経路を確かめる。
fn resolve_systemd_run(
    candidates: &[&Path],
    required_owner: u32,
    ancestor_floor: &Path,
) -> Result<PathBuf, OciRuntimeError> {
    let Some(real) = candidates
        .iter()
        .find_map(|c| std::fs::canonicalize(c).ok())
    else {
        return Err(start_error(
            ErrorCode::FailedPrecondition,
            "systemd-run is not installed; starting a container requires a systemd user manager",
        ));
    };
    let untrusted = || {
        start_error(
            ErrorCode::FailedPrecondition,
            "systemd-run is not a trusted executable (must be a root-owned regular file not writable by group or others)",
        )
    };
    let meta = std::fs::metadata(&real).map_err(|_| untrusted())?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 || !is_owned_and_closed(&meta, required_owner) {
        return Err(untrusted());
    }
    for dir in real.ancestors().skip(1) {
        if !dir.starts_with(ancestor_floor) {
            break;
        }
        let m = std::fs::metadata(dir).map_err(|_| untrusted())?;
        if !m.is_dir() || !is_owned_and_closed(&m, required_owner) {
            return Err(untrusted());
        }
    }
    Ok(real)
}

/// 本番の systemd-run の解決（試験専用 feature のときだけ環境変数で差し替えられる）。
fn locate_systemd_run() -> Result<PathBuf, OciRuntimeError> {
    #[cfg(feature = "start-test-support")]
    if let Some(p) = std::env::var_os(TEST_SYSTEMD_RUN_ENV) {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            return Ok(p);
        }
    }
    let candidates: Vec<PathBuf> = SYSTEMD_RUN_DIRS
        .iter()
        .map(|d| Path::new(d).join(SYSTEMD_RUN_NAME))
        .collect();
    let refs: Vec<&Path> = candidates.iter().map(PathBuf::as_path).collect();
    resolve_systemd_run(&refs, 0, Path::new("/"))
}

/// systemd の user マネージャに届くかを検査し、環境へ渡す `XDG_RUNTIME_DIR` の値を返す（純関数に近い検査）。
///
/// 値は絶対パスであること、`<値>/systemd/private` が symlink でなく euid 所有のソケットであること（直結ソケット。
/// systemd-run `--user` の接続先）を確かめる。値そのものはエラー文に載せない。
fn user_manager_env(xdg: Option<&OsStr>, euid: u32) -> Result<OsString, OciRuntimeError> {
    let unset = || {
        start_error(
            ErrorCode::FailedPrecondition,
            "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable",
        )
    };
    let xdg = xdg.filter(|v| !v.is_empty()).ok_or_else(unset)?;
    let dir = Path::new(xdg);
    if !dir.is_absolute() {
        return Err(unset());
    }
    let sock = dir.join("systemd").join("private");
    let unreachable = || {
        start_error(
            ErrorCode::FailedPrecondition,
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)",
        )
    };
    let meta = std::fs::symlink_metadata(&sock).map_err(|_| unreachable())?;
    if !meta.file_type().is_socket() || meta.uid() != euid {
        return Err(unreachable());
    }
    Ok(xdg.to_os_string())
}

/// systemd-run で包んだ起動コマンドを組む（シェルも文字列連結も使わない）。内側の設定は [`configure`]。
fn scoped_command(
    systemd_run: &Path,
    supervisor: &Path,
    root: &Path,
    id: &ContainerId,
    xdg: &OsStr,
) -> Command {
    let mut cmd = Command::new(systemd_run);
    cmd.args(USER_SCOPE_WRAPPER_ARGS).arg(supervisor);
    configure(&mut cmd, root, id);
    cmd.env("XDG_RUNTIME_DIR", xdg);
    cmd
}

/// 本番入口: supervisor を委譲 scope で起動して pid か構造化エラーを期限付きで受け取る。
///
/// `root` は `StateRoot::resolve` で解決した絶対パス。`id` は `ContainerId::new` で検証済みの値。
/// 事前検査（supervisor の実在・rootful・systemd-run・user マネージャ）はすべて spawn の前に行い、失敗は案 B へ落とさず返す。
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
    if !std::fs::metadata(&program).is_ok_and(|m| m.is_file()) {
        return Err(start_error(
            ErrorCode::FailedPrecondition,
            "supervisor executable is not installed",
        ));
    }
    let euid = privilege_gate(&read_self_status()?)?;
    let systemd_run = locate_systemd_run()?;
    let xdg = user_manager_env(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), euid)?;
    let cmd = scoped_command(&systemd_run, &program, root, id, &xdg);
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
        assert_eq!(e.message(), EOF_MESSAGE);
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
        assert_eq!(
            e.message(),
            "systemd-run is not installed; starting a container requires a systemd user manager"
        );
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

    /// 擬似の `/proc/self/status`（uid の 4 つ組だけ可変）。
    fn status_with_uid(uid: &str) -> String {
        format!(
            "Name:\tx\nUid:\t{uid}\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nNoNewPrivs:\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"
        )
    }

    /// SEC-5・CLI-1: rootful（どの位置の uid が 0 でも）は UNIMPLEMENTED で拒否し、壊れた入力は FAILED_PRECONDITION。
    #[test]
    fn sec5_cli_rootful_is_unimplemented() {
        assert_eq!(
            privilege_gate(&status_with_uid("1000\t1000\t1000\t1000")).expect("rootless"),
            1000
        );
        for uid in [
            "0\t1000\t1000\t1000",
            "1000\t0\t1000\t1000",
            "1000\t1000\t0\t1000",
            "1000\t1000\t1000\t0",
        ] {
            let e = privilege_gate(&status_with_uid(uid)).expect_err(uid);
            assert_eq!(e.code(), ErrorCode::Unimplemented, "{uid}");
            assert_eq!(e.exit_code().get(), 8, "{uid}");
            assert_eq!(
                e.message(),
                "rootful start is not supported by the production launcher"
            );
        }
        for bad in ["", "garbage"] {
            let e = privilege_gate(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "process status is unreadable");
        }
    }

    /// CORE-3・SUP-1: systemd-run で包んだ argv・環境・cwd は固定（環境は PATH と XDG_RUNTIME_DIR だけ）。
    #[test]
    fn core3_sup1_scoped_command_argv_env_cwd() {
        let id = ContainerId::new("c1").expect("id");
        let cmd = scoped_command(
            Path::new("/usr/bin/systemd-run"),
            Path::new("/opt/x/fandhe-container-supervisor"),
            Path::new("/r"),
            &id,
            OsStr::new("/run/user/1000"),
        );
        assert_eq!(cmd.get_program(), "/usr/bin/systemd-run");
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "Delegate=yes",
                "--",
                "/opt/x/fandhe-container-supervisor",
                "start",
                "--root",
                "/r",
                "c1"
            ]
        );
        let mut envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        envs.sort();
        assert_eq!(
            envs,
            [
                ("PATH".to_string(), Some(SUPERVISOR_PATH_ENV.to_string())),
                (
                    "XDG_RUNTIME_DIR".to_string(),
                    Some("/run/user/1000".to_string())
                )
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn self_uid() -> u32 {
        std::fs::metadata("/proc/self").expect("meta").uid()
    }

    /// CLI-1・PLUG-11: systemd-run の解決。候補が無い・所有者違い・書き込み可・非通常ファイル・実行ビット無しは拒否し、
    /// 条件を満たす実体（symlink 経由なら解決後のパス）だけを返す。
    #[test]
    fn cli1_systemd_run_resolution() {
        const NOT_INSTALLED: &str =
            "systemd-run is not installed; starting a container requires a systemd user manager";
        const UNTRUSTED: &str = "systemd-run is not a trusted executable (must be a root-owned regular file not writable by group or others)";
        let tmp = TmpDir::new("sdrun");
        let me = self_uid();
        let floor = std::fs::canonicalize(&tmp.0).expect("canon");
        let bin = floor.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        set_mode(&bin, 0o755);
        let exe = bin.join("systemd-run");

        let missing = bin.join("nope");
        let e = resolve_systemd_run(&[missing.as_path()], me, &floor).expect_err("missing");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), NOT_INSTALLED);

        std::fs::write(&exe, b"#!/bin/sh\n").expect("write");
        for (mode, why) in [(0o775, "group-w"), (0o757, "other-w"), (0o644, "no-exec")] {
            set_mode(&exe, mode);
            let e = resolve_systemd_run(&[exe.as_path()], me, &floor).expect_err(why);
            assert_eq!(e.message(), UNTRUSTED, "{why}");
        }
        set_mode(&exe, 0o755);
        let e =
            resolve_systemd_run(&[exe.as_path()], me.wrapping_add(1), &floor).expect_err("owner");
        assert_eq!(e.message(), UNTRUSTED);
        let e = resolve_systemd_run(&[bin.as_path()], me, &floor).expect_err("dir");
        assert_eq!(e.message(), UNTRUSTED);

        assert_eq!(
            resolve_systemd_run(&[missing.as_path(), exe.as_path()], me, &floor).expect("ok"),
            exe
        );
        // 祖先ディレクトリが group / other 書き込み可なら拒否する。
        set_mode(&bin, 0o775);
        let e = resolve_systemd_run(&[exe.as_path()], me, &floor).expect_err("ancestor");
        assert_eq!(e.message(), UNTRUSTED);
        set_mode(&bin, 0o755);
        // symlink 経由の候補は実体のパスを返す。
        let link_dir = floor.join("link");
        std::os::unix::fs::symlink(&bin, &link_dir).expect("symlink");
        let via = link_dir.join("systemd-run");
        assert_eq!(
            resolve_systemd_run(&[via.as_path()], me, &floor).expect("via link"),
            exe
        );
    }

    /// CLI-1: user マネージャの到達性。未設定・空・相対パス・ソケット無し・通常ファイル・symlink は拒否し、
    /// euid 所有のソケットなら値を返す。
    #[test]
    fn cli1_user_manager_env() {
        const UNSET: &str = "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable";
        const UNREACHABLE: &str =
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)";
        let me = self_uid();
        for bad in [None, Some(OsStr::new("")), Some(OsStr::new("rel/dir"))] {
            let e = user_manager_env(bad, me).expect_err("unset");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), UNSET);
        }
        let tmp = TmpDir::new("xdg");
        let xdg = tmp.0.join("xdg");
        std::fs::create_dir_all(xdg.join("systemd")).expect("mkdir");
        let e = user_manager_env(Some(xdg.as_os_str()), me).expect_err("no socket");
        assert_eq!(e.message(), UNREACHABLE);
        let sock = xdg.join("systemd").join("private");
        std::fs::write(&sock, b"").expect("file");
        let e = user_manager_env(Some(xdg.as_os_str()), me).expect_err("regular file");
        assert_eq!(e.message(), UNREACHABLE);
        std::fs::remove_file(&sock).expect("rm");
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        assert_eq!(
            user_manager_env(Some(xdg.as_os_str()), me).expect("socket"),
            xdg.as_os_str()
        );
        let e = user_manager_env(Some(xdg.as_os_str()), me.wrapping_add(1)).expect_err("owner");
        assert_eq!(e.message(), UNREACHABLE);
        // symlink は辿らない（ソケットへの symlink でも拒否）。
        let xdg2 = tmp.0.join("xdg2");
        std::fs::create_dir_all(xdg2.join("systemd")).expect("mkdir");
        std::os::unix::fs::symlink(&sock, xdg2.join("systemd").join("private")).expect("symlink");
        let e = user_manager_env(Some(xdg2.as_os_str()), me).expect_err("symlink");
        assert_eq!(e.message(), UNREACHABLE);
        drop(listener);
    }
}
