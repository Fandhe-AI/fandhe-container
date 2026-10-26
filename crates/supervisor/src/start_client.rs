//! supervisor の bin を委譲 scope で起動し、結果の 1 行を期限付きで受け取るクライアント
//! （TASK-79 追補・#1718・#2434・CLI-1・CRI-2・CORE-1・SUP-1・REPAIR-2・REPAIR-3・REPAIR-4・REPAIR-5・ERR-1・ERR-2・MS-6）。
//!
//! 呼び出し側の `start`（`commands::supervisor_start`）と plugin-cri の `CoreLifecycleRuntime::start`（#2434）が共有する。
//! 元は 呼び出し側の private 実装で、plugin-cri が複製しない（REPAIR-1）ためにここへ移した。挙動と契約は移設前と同じである。
//! 呼び出し側は特権を持たず、コンテナの子プロセスを fork しない。
//! `oci_runtime::start`（起動権の予約・launch・Running の記録）を呼ぶ層は supervisor 側にあり（#1314 の配置 1-A）、
//! 呼び出し側は [`crate::start_contract`]（#1717）の契約どおりに supervisor を spawn して
//! 結果の 1 行（`FCSUP1 OK <pid>` / `FCSUP1 ERR <CODE> <exit> <msg>`）を受け取り、終了コードへ写すだけである。
//! 呼び出し側は `start` で状態を書かない。したがって、起動や受信に失敗してもプロセスのいない Running を残す経路は無い（#1541）。
//! 報告の復号は契約の型（`StartReport::decode`）に任せ、ここで書式を組まない・割らない（REPAIR-2）。
//!
//! # 契約の要点（呼び出し側の責務。詳細は `start_contract` の module doc）
//! - argv: `start --root <状態ルートの絶対パス> [--audit-policy <best-effort|strict>] [--cri-log-path <絶対パス>] <id>`（`--restart` は渡さず既定の `no`。
//!   `--audit-policy` は CLI の `start --audit-policy` が指定したときだけ載せ、未指定なら supervisor の既定 best-effort が効く。
//!   `--cri-log-path` は plugin-cri だけが使う。SEC-4・#2761）。`env_clear` の後に渡す環境は
//!   許可リストの 2 つだけ: 固定の `PATH` と、`XDG_RUNTIME_DIR`（systemd-run が user マネージャへ接続するため。絶対パスを検証する）。
//!   `DBUS_SESSION_BUS_ADDRESS` は渡さない（sd-bus のアドレスは `unixexec:` 等で任意プログラムの起動や接続先の付け替えができ、
//!   user マネージャの直結ソケット `$XDG_RUNTIME_DIR/systemd/private` だけで足りる。`man sd_bus_default` と systemd の
//!   `src/shared/bus-util.c` の `bus_connect_user_systemd`）。supervisor は契約の値を環境から読まず、状態ルートは常に
//!   `--root` で受けるため、契約に反しない。cwd は `/`。
//! - stdin は null、stdout は結果の pipe、stderr は null。呼び出し側の stderr は「失敗時に 1 行の JSON」という契約のため、
//!   supervisor のログを混ぜず受け手も置かない。supervisor の構造化ログは supervisor 自身が `<root>/@supervisor-logs/<id>.log*`
//!   へ保存する（サイズ上限・世代ローテーションつき。`fandhe_container_supervisor::supervisor_log`。#2067・REPAIR-4）。
//!   `delete` が後始末する（`stop_delete`）。
//! - 直接経路は `process_group(0)` で別のプロセスグループにし、端末の SIGINT / SIGHUP が supervisor に届かないようにする
//!   （ランチャー経路は付けない。後述の #2442）。
//!
//! # 委譲スコープでの起動（#2081・CORE-3・CORE-4・SEC-5）
//! supervisor 側の `DelegatedCgroup::prepare` は、委譲された親 cgroup に自分以外のプロセスがいると拒否する。CLI と同じ
//! cgroup（端末のシェルと同居）で起動するとほぼ必ず拒否されるため、`systemd-run --user --scope --quiet -p Delegate=yes --`
//! （`start_contract::USER_SCOPE_WRAPPER_ARGS`）で包み、supervisor を新しい scope で一人で動かす。
//! systemd-run は scope の登録後に同じプロセスで `execvpe` する（`man systemd-run` の「scope として実行するコマンドは
//! systemd-run 自身が親プロセスとして実行し〜同期的」の段落と systemd の `src/run/run.c` の `start_transient_scope`）。
//! したがって spawn した `Child` の pid・`process_group(0)`・stdio・渡した環境はそのまま supervisor のものになり、
//! 呼び出し側は scope に居残らない。scope の取得時間も受信期限（58.9 秒）に含まれる。
//! fail-closed（案 B の「呼び出し側の cgroup の下に子 cgroup を作る」へは落とさない）の判定はすべて spawn の前に行う。
//! - rootful（`/proc/self/status` の uid のどれかが 0）: `UNIMPLEMENTED`（supervisor の判定と同じ文）。
//! - `systemd-run` が固定候補（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`・NixOS の `/run/current-system/sw/bin`。`PATH` 探索は
//!   しない）に無い、または実体が root か実効 UID 所有の通常ファイルで group / other 書き込み不可（祖先ディレクトリも同様。
//!   PLUG-11 と同じ判定関数）でない: `FAILED_PRECONDITION`。探索と信頼の基準の詳細・NixOS の既知の限界は `crate::systemd_run`
//!   （#2133）。検証から exec までの TOCTOU は、信頼できる所有者だけが書ける場所に限ることで抑える（CLI と supervisor は同じ
//!   uid で権限の境界が無いため、fd 経由の検証は特権ランチャー〔#1719〕の責務とする）。
//! - `XDG_RUNTIME_DIR` が絶対パスでない、または `systemd/private` が euid 所有のソケットでない（symlink は辿らない）:
//!   `FAILED_PRECONDITION`（user マネージャに届かない）。
//! - 委譲が効いていない場合の判定は supervisor の `detect` / `prepare` が行い、その報告を `map_received` が写す。
//!
//! # 期限と子の扱い（REPAIR-5）
//! - 受信期限は `cli_receive_deadline`（既定 58.9 秒）。期限内に 1 行が来なければ `TIMEOUT`（結果不明）、1 行も無いまま EOF なら
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
//! - 状態: 呼び出し側は `start` で状態を書かない（#1541）。supervisor が成功すれば Running を記録し、失敗すれば自分の
//!   後始末の規則で Created へ戻す。利用者は `state`・`list` で確かめる（期限切れの `TIMEOUT` と同じ案内）。
//! - 起動時に `SIG_IGN` を継承したシグナルはハンドラが入らず無視され、待機は期限まで続く。
//! - 待機の取り消しを supervisor へ伝える経路は無い。#2058 の制御チャネルが入った後の将来課題とする。
//!
//! # 未実装・簡易実装（REPAIR-3）
//! - 実行ファイルは CLI 自身の実体パスと同じディレクトリの固定名 `fandhe-container-supervisor` から解決する
//!   （`PATH` 探索・環境変数・引数による上書きは作らない）。`PATH` 上の symlink から起動されても、Linux の `current_exe()` は
//!   `/proc/self/exe` の解決結果（実体のパス）を返すため、`argv[0]` や symlink の置き場所ではなく実体のディレクトリを見る
//!   （配布手順は CLI を launcher・supervisor と同じディレクトリに置く。#2068・SUP-14）。同一ユーザーで起動するため CLI と supervisor の間に権限の境界は無く、
//!   実行ファイルの所有者・権限の fd 経由の検証は特権経路のランチャー（#1719）の責務とする。
//! - 特権ランチャーの選択（#2442・SUP-14）: 非 root で、CLI の実体と同じディレクトリに固定名 `fandhe-container-launcher`
//!   があれば rootful のインストールとみなし、`systemd-run ... -- <launcher> start --root <root> <id>` で起動する
//!   （`process_group(0)` は付けない。ランチャーの `setsid` が `EPERM` になるため。stdio に pty は渡さない）。無ければ従来の
//!   直接経路。在るが通常ファイル・実行可能・所有者 root か euid・g/o 書き込み不可でなければ `FAILED_PRECONDITION` で止め、
//!   直接経路へ黙って落とさない。uid 0 の起動はランチャーの前提（呼び出し元は非 root）に反し、`RootfulHostRoot` の判断
//!   （#2241）待ちのため今のまま `UNIMPLEMENTED`。実機での通し確認は未実施（#538・#539）。
//! - supervisor の fd 2 へ直接書かれるもの（core の診断・panic のメッセージ等）は保存されない（stderr が null のため捨てられる。
//!   範囲は `supervisor_log` の「未実装・残余」。`legacy_tiocsti` の警告は supervisor のログへ残る。#2008）。
//! - 親から継承した CLOEXEC の無い fd は CLI では閉じない。supervisor の bin の入口が fd 3 以降を閉じる
//!   （ランチャー経由と同じ処理。#2070・SEC-1）。exec から入口までの短い窓は残る。
//! - supervisor は core の本番 launcher（#1715・#1819 で結線済み）で起動する。uid 0 は spawn の前に `UNIMPLEMENTED`（上記）。restart の再 launch は fail-closed（#2043）。実機での通し確認
//!   （委譲 cgroup の準備で拒否されないか）は未実施（#2062。`tests/supervisor_bin_real.rs` は実機前提）。
//! - 1 行も無いまま EOF のとき、supervisor の異常終了と systemd-run の失敗（D-Bus 接続の失敗等）を区別できない
//!   （stderr を pipe にすると supervisor の構造化ログが混ざり、CLI の終了後に EPIPE になるため採らない。制御チャネル #2058 の後の課題）。
//!   事前の実 connect で死んだソケットだけ区別する案は未実装で、判断待ち（#2448・`docs/design/user-manager-connect-precheck.md`。`resolve` は今も `user_manager_env` の lstat のみ）。
//! - 固定候補の外にある `systemd-run` には未対応（`PATH` は探さない。理由は `crate::systemd_run`）。NixOS の store が
//!   group 書き込み可・sticky の祖先として拒否される可能性があり、実機での確認と扱いはオーナー判断待ち（#2133）。
//! - CLI の試験専用 feature `start-test-support` のときだけ、環境変数 `FANDHE_CONTAINER_TEST_SYSTEMD_RUN`（絶対パス）で
//!   systemd-run の解決を差し替えられる。この差し替えは CLI 側（`SupervisorLaunch::resolve_beside_with` に渡す関数）にあり、
//!   このモジュールと plugin-cri には環境変数を読むコードが存在しない（plugin-cri の試験は `SupervisorLaunch::new` で注入する。#2434）。
//! - plugin-cri から使うときの前提: `XDG_RUNTIME_DIR` が plugin の環境に必要（将来の plugin proxy が `env_clear` すると
//!   `FAILED_PRECONDITION` になる。#1869）。実行ファイルは plugin の実体と同じディレクトリに置く（#2434）。

use std::ffi::OsStr;
use std::io::Read;
use std::num::NonZeroU32;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_core::audit_log::AuditCoveragePolicy;
use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError, StartTimeouts};
use fandhe_container_core::plugin_trust::{PluginTrustErrorKind, check_owner_and_mode};
use fandhe_container_core::traits::{ContainerId, ContainerLogPath, ErrorCode};

use crate::launcher::{LAUNCHER_FILE_NAME, SUPERVISOR_FILE_NAME};
use crate::start_contract::{
    MAX_REPORT_LEN, StartReport, USER_SCOPE_WRAPPER_ARGS, cli_receive_deadline,
};
use crate::systemd_run::{
    Identity, SystemdRunRejection, identity_from_status, read_self_status, resolve_systemd_run,
    systemd_run_candidates,
};
use crate::user_scope::{UserManagerError, user_manager_env};

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
/// 期限切れのとき補助スレッドは read で止まったまま残る。受信期限切れだけを理由に子を kill しない（supervisor は
/// 起動権の予約・子プロセス・cgroup を回収中かもしれず、kill すると後始末が失われる。CORE-2）。supervisor は内部上限で
/// 自ら終了して pipe が閉じ、スレッドも終わる。常駐する呼び出し側（plugin-cri）は `Child` を追跡数の上限つきで保持するため、
/// 残るスレッドの数もその上限で抑えられる。
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
            Err(_) => Err(start_error(ErrorCode::Internal, MALFORMED)),
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

/// `start` の argv に載せる任意の項目（`--audit-policy`・`--cri-log-path`）。
///
/// 呼び出し側（CLI の `start`・plugin-cri）が supervisor の契約（`crate::start_contract::StartArgs`）の任意引数を
/// 渡すための入口。未指定（`None`）の項目は argv に載らず、supervisor の既定が効く。監査の方針は core のライフサイクル要求ではなく
/// CLI と supervisor の間の契約の値のため、`StartRequest` ではなくここに置く（SEC-4・#2761）。
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct StartOptions<'a> {
    /// CRI ログの書き先（plugin-cri だけが指定する。CRI-2・SUP-4・#2671）。
    pub cri_log_path: Option<&'a ContainerLogPath>,
    /// 監査の縮退の扱い（`start --audit-policy`。SEC-4・#2027・#2761）。
    pub audit_policy: Option<AuditCoveragePolicy>,
}

impl<'a> StartOptions<'a> {
    /// すべて未指定の options。
    pub fn new() -> Self {
        Self::default()
    }

    /// CRI ログの書き先を設定する。
    pub fn with_cri_log_path(mut self, path: Option<&'a ContainerLogPath>) -> Self {
        self.cri_log_path = path;
        self
    }

    /// 監査の縮退の扱いを設定する（`None` は argv に載せない）。
    pub fn with_audit_policy(mut self, policy: Option<AuditCoveragePolicy>) -> Self {
        self.audit_policy = policy;
        self
    }
}

/// 契約どおりの argv・stdio・環境・cwd を `cmd` に設定する（シェルも文字列連結も使わない）。
/// プロセスグループは設定しない（直接経路は [`configure`]、ランチャー経路は付けない。#2442）。
fn configure_common(cmd: &mut Command, root: &Path, opts: &StartOptions<'_>, id: &ContainerId) {
    cmd.arg("start").arg("--root").arg(root);
    // 監査の縮退の扱いは CLI が指定したときだけ載せる（SEC-4・#2761）。固定語彙の `as_str()` を argv の 1 要素として渡す。
    if let Some(policy) = opts.audit_policy {
        cmd.arg("--audit-policy").arg(policy.as_str());
    }
    // CRI ログの書き先は位置引数（ID）の前に置く（CRI-2・SUP-4・#2671）。値は検証済みの型で、argv の 1 要素として渡す。
    if let Some(path) = opts.cri_log_path {
        cmd.arg("--cri-log-path").arg(path.as_str());
    }
    cmd.arg(id.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", SUPERVISOR_PATH_ENV)
        .current_dir("/");
}

/// 直接経路（rootless）の設定: [`configure_common`] に `process_group(0)` を足す。
fn configure(cmd: &mut Command, root: &Path, opts: &StartOptions<'_>, id: &ContainerId) {
    configure_common(cmd, root, opts, id);
    cmd.process_group(0);
}

/// CLI の実体パスと同じディレクトリの固定名から特権ランチャーの実行ファイルを決める（`PATH` 探索をしない。純関数）。
fn launcher_path_beside(cli_exe: &Path) -> Result<PathBuf, OciRuntimeError> {
    match cli_exe.parent() {
        Some(dir) if dir.is_absolute() => Ok(dir.join(LAUNCHER_FILE_NAME)),
        _ => Err(start_error(
            ErrorCode::FailedPrecondition,
            "cannot resolve the cli executable path",
        )),
    }
}

/// 隣のランチャーの有無と信頼の判定結果（#2442）。
///
/// `start`（[`SupervisorLaunch::resolve_beside_with`]）と `doctor` の特権ランチャー診断（#2599・SUP-14）が
/// 同じ判定を共有するため公開する（規則を 2 か所に書かない）。
#[derive(Debug, PartialEq, Eq)]
pub enum LauncherPresence {
    /// 無い（rootless のインストール）。
    Absent,
    /// 実体が通常ファイル・実行可能・所有者が root か `euid`・group/other 書き込み不可。
    Trusted(TrustedLauncher),
    /// 在るが信頼条件を満たさない、または読めない（fail-closed。直接経路へ落とさない）。
    Untrusted(LauncherUntrustedReason),
}

/// 信頼できると判定したランチャー（symlink 解決後の実体）の情報。
///
/// `start` は `path` だけを使う。`owner_uid`・`mode` は doctor が setuid root の代替を判定するために使う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLauncher {
    /// symlink を解決した実体のパス。
    pub path: PathBuf,
    /// 実体の所有者 uid。
    pub owner_uid: u32,
    /// 実体の `st_mode`（種別ビットを含む）。
    pub mode: u32,
}

/// ランチャーが信頼できない理由（機械可読。doctor の `state` に写す。パス・uid は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LauncherUntrustedReason {
    /// 通常ファイルではない（ディレクトリ等）。
    NotRegularFile,
    /// 実行ビットが無い。
    NoExecuteBit,
    /// 所有者が root でも `euid` でもない。
    FileOwner,
    /// group または other が書き込める。
    FileMode,
    /// 解決できない（リンク切れ・ループ・権限エラー等。エントリ自体は在る）。
    Unresolvable,
    /// 解決後の属性を読めない。
    Unreadable,
}

/// CLI の実体パス `cli_exe` の隣のランチャーを分類する（`start` と `doctor` の共通入口。`PATH` 探索なし）。
///
/// `cli_exe` が絶対パスの親を持たない場合は `FAILED_PRECONDITION`。
pub fn classify_launcher_beside(
    cli_exe: &Path,
    euid: u32,
) -> Result<LauncherPresence, OciRuntimeError> {
    Ok(classify_launcher(&launcher_path_beside(cli_exe)?, euid))
}

/// `path` のランチャーを分類する。祖先は辿らない（特権側の信頼チェーンはランチャーが自分で検証する。#1719）。
fn classify_launcher(path: &Path, euid: u32) -> LauncherPresence {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let real = match std::fs::canonicalize(path) {
        Ok(p) => p,
        // 解決失敗でもディレクトリエントリ自体が在る（リンク切れ・ループ・権限エラー等）なら不存在とみなさない
        // （SUP-14: 在るが信頼できないランチャーは fail-closed。直接経路へ黙って落とさない）。
        Err(_) => {
            return match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => LauncherPresence::Absent,
                _ => LauncherPresence::Untrusted(LauncherUntrustedReason::Unresolvable),
            };
        }
    };
    let Ok(meta) = std::fs::metadata(&real) else {
        return LauncherPresence::Untrusted(LauncherUntrustedReason::Unreadable);
    };
    let mode = meta.permissions().mode();
    if !meta.is_file() {
        return LauncherPresence::Untrusted(LauncherUntrustedReason::NotRegularFile);
    }
    if mode & 0o111 == 0 {
        return LauncherPresence::Untrusted(LauncherUntrustedReason::NoExecuteBit);
    }
    if let Err(e) = check_owner_and_mode(meta.uid(), mode, euid) {
        return LauncherPresence::Untrusted(match e {
            PluginTrustErrorKind::UntrustedOwner => LauncherUntrustedReason::FileOwner,
            _ => LauncherUntrustedReason::FileMode,
        });
    }
    LauncherPresence::Trusted(TrustedLauncher {
        path: real,
        owner_uid: meta.uid(),
        mode,
    })
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
#[cfg(test)]
fn launch_and_receive(
    cmd: Command,
    receive_within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
    let (result, child, _) = launch_and_receive_ex(cmd, receive_within);
    (result, child)
}

/// [`launch_and_receive`] に「受信期限が切れたか」を加えたもの。
///
/// 3 つ目の値が `true` のときだけ、supervisor が報告を出さないまま期限を過ぎた（読み取りスレッドが pipe で止まったまま残る）。
/// supervisor が `TIMEOUT` を報告した場合（報告を受信できた）は `false` で、supervisor は後始末の途中にいる（SUP-1・REPAIR-5）。
fn launch_and_receive_ex(
    mut cmd: Command,
    receive_within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>, bool) {
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
            return (Err(err), None, false);
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return (
            Err(start_error(
                ErrorCode::Internal,
                "failed to read the supervisor start result",
            )),
            Some(child),
            false,
        );
    };
    let received = receive_report(stdout, receive_within);
    if received == Received::Eof {
        let _ = child.try_wait();
    }
    let expired = received == Received::TimedOut;
    (map_received(received), Some(child), expired)
}

/// CLI の受信期限（既定 58.9 秒。supervisor の内部上限 56.9 秒（手順 8 の見込み 39.45 秒〔監査配送 11.45 秒を含む〕+ cgroup 準備 6 秒 + 記録経路の確認 11.45 秒。`result_deadline` 参照） + 受信の猶予 2 秒。REPAIR-5）。
pub fn production_deadline() -> Duration {
    cli_receive_deadline(&StartTimeouts::default())
}

/// rootful 判定と euid の取得（SEC-5）。real / effective / saved / fs の uid のどれかが 0 なら
/// supervisor の `privilege_for_status` と同じ文で `UNIMPLEMENTED`、読めない・壊れた入力は `FAILED_PRECONDITION`。
fn privilege_gate(status_text: Option<&str>) -> Result<u32, OciRuntimeError> {
    match status_text.map(identity_from_status) {
        Some(Identity::Rootless { euid }) => Ok(euid),
        Some(Identity::Rootful) => Err(start_error(
            ErrorCode::Unimplemented,
            "rootful start is not supported by the production launcher",
        )),
        Some(Identity::Unreadable) | None => Err(start_error(
            ErrorCode::FailedPrecondition,
            "process status is unreadable",
        )),
    }
}

/// systemd-run の解決失敗を `start` の固定文言へ写す（値〔パス〕は載せない）。
fn systemd_run_error(rejection: SystemdRunRejection) -> OciRuntimeError {
    match rejection {
        SystemdRunRejection::NotFound => start_error(
            ErrorCode::FailedPrecondition,
            "systemd-run is not installed; starting a container requires a systemd user manager",
        ),
        _ => start_error(
            ErrorCode::FailedPrecondition,
            "systemd-run is not a trusted executable (must be a regular file owned by root or the current user, not writable by group or others)",
        ),
    }
}

/// user マネージャへ届かない理由を `start` の結果へ写す。
fn user_manager_error(e: UserManagerError) -> OciRuntimeError {
    start_error(ErrorCode::FailedPrecondition, e.message())
}

/// 本番の systemd-run の解決（固定候補だけ。試験専用の差し替えは呼び出し側の責務で、ここには無い）。
pub fn locate_systemd_run(euid: u32) -> Result<PathBuf, OciRuntimeError> {
    let candidates = systemd_run_candidates();
    let refs: Vec<&Path> = candidates.iter().map(PathBuf::as_path).collect();
    resolve_systemd_run(&refs, euid, Path::new("/")).map_err(systemd_run_error)
}

/// systemd-run で包んだ起動コマンドを組む（シェルも文字列連結も使わない）。内側の設定は [`configure_common`]。
///
/// `launcher` が `Some` のときは supervisor の代わりに特権ランチャーを包む（argv は同じ。ランチャーが検証して転送する）。
/// この経路では `process_group(0)` を付けない: 付けると子がプロセスグループのリーダーになり、ランチャーの入口の
/// `setsid` が `EPERM` で拒否される（#537・#2442）。systemd-run は同じプロセスで exec するため、ランチャーは CLI の
/// グループの非リーダーのまま `setsid` に成功する。stdio は pty を渡さない（null / pipe / null）。
fn scoped_command(
    systemd_run: &Path,
    launcher: Option<&Path>,
    supervisor: &Path,
    root: &Path,
    opts: &StartOptions<'_>,
    id: &ContainerId,
    xdg: &OsStr,
) -> Command {
    let mut cmd = Command::new(systemd_run);
    cmd.args(USER_SCOPE_WRAPPER_ARGS);
    match launcher {
        Some(launcher) => {
            cmd.arg(launcher);
            configure_common(&mut cmd, root, opts, id);
        }
        None => {
            cmd.arg(supervisor);
            configure(&mut cmd, root, opts, id);
        }
    }
    cmd.env("XDG_RUNTIME_DIR", xdg);
    cmd
}

/// 解決済みの起動依存（systemd-run・supervisor の実行ファイル・`XDG_RUNTIME_DIR`）。
///
/// 本番は [`SupervisorLaunch::resolve_beside`]（または試験専用の差し替えつきの [`SupervisorLaunch::resolve_beside_with`]）で
/// 組む。環境変数・引数・RPC から読む経路は作らない（PLUG-11 と同じ方針。#2434 の D11）。[`SupervisorLaunch::new`] は
/// 結合試験が偽の systemd-run・supervisor を注入するための入口で、製品コードは呼ばない。
#[derive(Debug, Clone)]
pub struct SupervisorLaunch {
    systemd_run: PathBuf,
    supervisor: PathBuf,
    /// `Some` なら特権ランチャー経由（rootful のインストール。#2442）。`None` は直接経路（rootless）。
    launcher: Option<PathBuf>,
    xdg_runtime_dir: std::ffi::OsString,
}

impl SupervisorLaunch {
    /// 解決済みの値から組む（試験の注入用。検査はしない）。
    pub fn new(
        systemd_run: PathBuf,
        supervisor: PathBuf,
        xdg_runtime_dir: std::ffi::OsString,
    ) -> Self {
        Self {
            systemd_run,
            supervisor,
            launcher: None,
            xdg_runtime_dir,
        }
    }

    /// [`Self::new`] のランチャー経由版（試験の注入用。検査はしない。製品コードは呼ばない）。
    pub fn new_via_launcher(
        systemd_run: PathBuf,
        launcher: PathBuf,
        supervisor: PathBuf,
        xdg_runtime_dir: std::ffi::OsString,
    ) -> Self {
        Self {
            systemd_run,
            supervisor,
            launcher: Some(launcher),
            xdg_runtime_dir,
        }
    }

    /// 特権ランチャー経由の起動か（試験・診断用）。
    pub fn uses_launcher(&self) -> bool {
        self.launcher.is_some()
    }

    /// 実行ファイルの実体パス `exe` と同じディレクトリの固定名から supervisor を決め、本番の検査で解決する。
    ///
    /// 検査（supervisor の実在・rootful・systemd-run・user マネージャ）はすべて spawn の前に行い、失敗は案 B へ落とさず返す。
    pub fn resolve_beside(exe: &Path) -> Result<Self, OciRuntimeError> {
        Self::resolve_beside_with(exe, locate_systemd_run)
    }

    /// [`Self::resolve_beside`] の systemd-run の解決だけを差し替えられる版（CLI の試験専用 feature 用）。
    pub fn resolve_beside_with(
        exe: &Path,
        locate: impl FnOnce(u32) -> Result<PathBuf, OciRuntimeError>,
    ) -> Result<Self, OciRuntimeError> {
        let program = supervisor_path_beside(exe)?;
        if !std::fs::metadata(&program).is_ok_and(|m| m.is_file()) {
            return Err(start_error(
                ErrorCode::FailedPrecondition,
                "supervisor executable is not installed",
            ));
        }
        let euid = privilege_gate(read_self_status().as_deref())?;
        // rootful のインストールは CLI の隣にランチャーがあること（#2442）。在るのに信頼できなければ直接経路へ落とさず止める。
        let launcher = match classify_launcher_beside(exe, euid)? {
            LauncherPresence::Absent => None,
            LauncherPresence::Trusted(t) => Some(t.path),
            LauncherPresence::Untrusted(_) => {
                return Err(start_error(
                    ErrorCode::FailedPrecondition,
                    "privileged launcher is not a trusted executable (must be a regular file owned by root or the current user, not writable by group or others)",
                ));
            }
        };
        let systemd_run = locate(euid)?;
        let xdg = user_manager_env(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), euid)
            .map_err(user_manager_error)?;
        Ok(Self {
            systemd_run,
            supervisor: program,
            launcher,
            xdg_runtime_dir: xdg,
        })
    }
}

/// 解決済みの `launch` で supervisor を委譲 scope で起動し、pid か構造化エラーを `within` まで待って受け取る。
///
/// `root` は `StateRoot::resolve` で解決した絶対パス。`id` は `ContainerId::new` で検証済みの値。戻りの `Child` は
/// 呼び出し側が回収・手放しを決めるためのもの（`wait` も kill もここでは行わない。supervisor は呼び出し元より長く生きる）。
/// CLI は即座に drop する。常駐する plugin-cri は終了済みの子を `try_wait` で回収する（ゾンビを溜めない。#2434 の D7）。
pub fn start_with(
    launch: &SupervisorLaunch,
    root: &Path,
    id: &ContainerId,
    within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
    start_with_cri_log(launch, root, None, id, within)
}

/// [`start_with`] に CRI ログの書き先（`--cri-log-path`。CRI-2・SUP-4・#2671）を足したもの。`None` は同じ挙動。
///
/// 常駐する plugin-cri の StartContainer が、cri が結合・検証した `log_directory/log_path` を渡す。supervisor 側で
/// 再検証され、特権ランチャー経由（ambient capability あり）では fail-closed で拒否される（`crate::start_entry` の doc）。
pub fn start_with_cri_log(
    launch: &SupervisorLaunch,
    root: &Path,
    cri_log_path: Option<&ContainerLogPath>,
    id: &ContainerId,
    within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
    start_with_options(
        launch,
        root,
        &StartOptions::new().with_cri_log_path(cri_log_path),
        id,
        within,
    )
}

/// [`start_with`] に任意の argv 項目（[`StartOptions`]）を足したもの。CLI の `start --audit-policy`（SEC-4・#2761）が使う。
pub fn start_with_options(
    launch: &SupervisorLaunch,
    root: &Path,
    opts: &StartOptions<'_>,
    id: &ContainerId,
    within: Duration,
) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
    let cmd = scoped_command(
        &launch.systemd_run,
        launch.launcher.as_deref(),
        &launch.supervisor,
        root,
        opts,
        id,
        &launch.xdg_runtime_dir,
    );
    let (result, child, _) = launch_and_receive_ex(cmd, within);
    (result, child)
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
            configure(&mut cmd, &self.root, &StartOptions::new(), &self.id);
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

    /// CORE-2・REPAIR-5: 報告された TIMEOUT は受信期限切れではない（呼び出し側が kill しない判断に使う）。
    #[test]
    fn core2_reported_timeout_is_not_receive_expiry() {
        let fx = Fixture::new("reported-timeout");
        let script = "printf 'FCSUP1 ERR TIMEOUT 7 launch timed out\\n'; exec sleep 5";
        let (result, child, expired) =
            launch_and_receive_ex(fx.fake(script), Duration::from_secs(10));
        reap(child);
        assert_eq!(result.expect_err("timeout").code(), ErrorCode::Timeout);
        assert!(!expired);
    }

    /// CORE-2・REPAIR-5: 報告が来ないまま期限を過ぎたときだけ expired が true。
    #[test]
    fn core2_receive_expiry_is_flagged() {
        let fx = Fixture::new("expiry-flag");
        let (result, child, expired) =
            launch_and_receive_ex(fx.fake("exec sleep 5"), Duration::from_millis(300));
        reap(child);
        assert_eq!(result.expect_err("timeout").code(), ErrorCode::Timeout);
        assert!(expired);
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
        configure(&mut cmd, &fx.root, &StartOptions::new(), &fx.id);
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

    /// REPAIR-5: 本番の受信期限は 58.9 秒。
    #[test]
    fn repair5_production_deadline_is_58_9s() {
        assert_eq!(production_deadline(), Duration::from_millis(58_900));
    }

    /// 契約: stdout 以外は null、環境は PATH だけ、cwd は `/`、argv は契約の順。
    #[test]
    fn sup1_configure_follows_contract() {
        let id = ContainerId::new("c1").expect("id");
        let mut cmd = Command::new("/bin/true");
        configure(&mut cmd, Path::new("/r"), &StartOptions::new(), &id);
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
            privilege_gate(Some(&status_with_uid("1000\t1000\t1000\t1000"))).expect("rootless"),
            1000
        );
        for uid in [
            "0\t1000\t1000\t1000",
            "1000\t0\t1000\t1000",
            "1000\t1000\t0\t1000",
            "1000\t1000\t1000\t0",
        ] {
            let e = privilege_gate(Some(&status_with_uid(uid))).expect_err(uid);
            assert_eq!(e.code(), ErrorCode::Unimplemented, "{uid}");
            assert_eq!(e.exit_code().get(), 8, "{uid}");
            assert_eq!(
                e.message(),
                "rootful start is not supported by the production launcher"
            );
        }
        for bad in [Some(""), Some("garbage"), None] {
            let e = privilege_gate(bad).expect_err("bad");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "process status is unreadable");
        }
    }

    /// SUP-14: ランチャー経路の argv・環境・cwd（プログラムは systemd-run、supervisor の代わりにランチャーを包む）。
    #[test]
    fn sup14_scoped_command_via_launcher_argv_env_cwd() {
        let id = ContainerId::new("c1").expect("id");
        let cmd = scoped_command(
            Path::new("/usr/bin/systemd-run"),
            Some(Path::new("/opt/x/fandhe-container-launcher")),
            Path::new("/opt/x/fandhe-container-supervisor"),
            Path::new("/r"),
            &StartOptions::new(),
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
                "/opt/x/fandhe-container-launcher",
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
                ),
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
    }

    /// SUP-14: ランチャーのパスは CLI の実体と同じディレクトリの固定名。相対パス・親なしは拒否する。
    #[test]
    fn sup14_launcher_path_beside() {
        assert_eq!(LAUNCHER_FILE_NAME, "fandhe-container-launcher");
        assert_eq!(
            launcher_path_beside(Path::new("/opt/x/fandhe-container")).expect("ok"),
            PathBuf::from("/opt/x/fandhe-container-launcher")
        );
        for bad in ["fandhe-container", "/", ""] {
            assert!(launcher_path_beside(Path::new(bad)).is_err(), "{bad}");
        }
    }

    /// SUP-14: ランチャーの分類。無い / 信頼できる / 信頼できない（g+w・o+w・実行ビット無し・ディレクトリ・他人所有）。
    #[test]
    fn sup14_classify_launcher() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = TmpDir::new("classify");
        let euid = std::fs::metadata(&dir.0).expect("meta").uid();
        let path = dir.0.join("fandhe-container-launcher");
        assert_eq!(classify_launcher(&path, euid), LauncherPresence::Absent);

        std::fs::write(&path, b"#!/bin/sh\n").expect("write");
        let real = std::fs::canonicalize(&path).expect("canon");
        for (mode, want) in [
            (0o755, None),
            (0o4755, None),
            (0o775, Some(LauncherUntrustedReason::FileMode)),
            (0o757, Some(LauncherUntrustedReason::FileMode)),
            (0o644, Some(LauncherUntrustedReason::NoExecuteBit)),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let want = match want {
                None => LauncherPresence::Trusted(TrustedLauncher {
                    path: real.clone(),
                    owner_uid: euid,
                    mode: 0o100000 | mode,
                }),
                Some(r) => LauncherPresence::Untrusted(r),
            };
            assert_eq!(classify_launcher(&path, euid), want, "mode {mode:o}");
        }
        // 所有者が root でも euid でもない場合（euid を別の値にして擬似的に表す）。
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        if euid != 0 {
            assert_eq!(
                classify_launcher(&path, euid.wrapping_add(1)),
                LauncherPresence::Untrusted(LauncherUntrustedReason::FileOwner)
            );
        }
        // リンク切れの symlink はエントリが在るので Untrusted（Absent にしない）。
        let dangling = dir.0.join("dangling-launcher");
        std::os::unix::fs::symlink(dir.0.join("no-such-target"), &dangling).expect("symlink");
        assert_eq!(
            classify_launcher(&dangling, euid),
            LauncherPresence::Untrusted(LauncherUntrustedReason::Unresolvable)
        );
        // ディレクトリは通常ファイルではない。
        let sub = dir.0.join("d");
        std::fs::create_dir(&sub).expect("mkdir");
        assert_eq!(
            classify_launcher(&sub, euid),
            LauncherPresence::Untrusted(LauncherUntrustedReason::NotRegularFile)
        );
    }

    /// CRI-2・SUP-4・#2671: CRI ログの書き先は `--cri-log-path <絶対パス>` として ID の前に載り、直接経路でもランチャー経路でも同じ。
    #[test]
    fn cri2_scoped_command_carries_cri_log_path() {
        let id = ContainerId::new("c1").expect("id");
        let lp = ContainerLogPath::new("/l/c/0.log").expect("log path");
        for launcher in [None, Some(Path::new("/opt/x/fandhe-container-launcher"))] {
            let cmd = scoped_command(
                Path::new("/usr/bin/systemd-run"),
                launcher,
                Path::new("/opt/x/fandhe-container-supervisor"),
                Path::new("/r"),
                &StartOptions::new().with_cri_log_path(Some(&lp)),
                &id,
                OsStr::new("/run/user/1000"),
            );
            let args: Vec<_> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                args[7..],
                [
                    "start",
                    "--root",
                    "/r",
                    "--cri-log-path",
                    "/l/c/0.log",
                    "c1"
                ]
            );
        }
    }

    /// CORE-3・SUP-1: systemd-run で包んだ argv・環境・cwd は固定（環境は PATH と XDG_RUNTIME_DIR だけ）。
    #[test]
    fn core3_sup1_scoped_command_argv_env_cwd() {
        let id = ContainerId::new("c1").expect("id");
        let cmd = scoped_command(
            Path::new("/usr/bin/systemd-run"),
            None,
            Path::new("/opt/x/fandhe-container-supervisor"),
            Path::new("/r"),
            &StartOptions::new(),
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

    /// SEC-4・#2761: `--audit-policy` は `--root` の直後・ID の前に載り、直接経路でもランチャー経路でも同じ。
    /// 組み立てた argv は契約の復号（`StartArgs::parse`）で元の方針に戻る（REPAIR-12）。
    #[test]
    fn sec4_scoped_command_carries_audit_policy() {
        use crate::start_contract::StartArgs;
        let id = ContainerId::new("c1").expect("id");
        let lp = ContainerLogPath::new("/l/c/0.log").expect("log path");
        for launcher in [None, Some(Path::new("/opt/x/fandhe-container-launcher"))] {
            let args_of = |opts: &StartOptions<'_>| -> Vec<String> {
                let cmd = scoped_command(
                    Path::new("/usr/bin/systemd-run"),
                    launcher,
                    Path::new("/opt/x/fandhe-container-supervisor"),
                    Path::new("/r"),
                    opts,
                    &id,
                    OsStr::new("/run/user/1000"),
                );
                cmd.get_args()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect()
            };
            let strict = StartOptions::new().with_audit_policy(Some(AuditCoveragePolicy::Strict));
            let a = args_of(&strict);
            assert_eq!(
                a[7..],
                ["start", "--root", "/r", "--audit-policy", "strict", "c1"]
            );
            let parsed =
                StartArgs::parse(a[7..].iter().map(std::ffi::OsString::from)).expect("contract");
            assert_eq!(parsed.audit_policy, AuditCoveragePolicy::Strict);
            let best = StartOptions::new().with_audit_policy(Some(AuditCoveragePolicy::BestEffort));
            assert_eq!(
                args_of(&best)[7..],
                [
                    "start",
                    "--root",
                    "/r",
                    "--audit-policy",
                    "best-effort",
                    "c1"
                ]
            );
            assert_eq!(
                args_of(&StartOptions::new())[7..],
                ["start", "--root", "/r", "c1"]
            );
            let both = strict.with_cri_log_path(Some(&lp));
            let a = args_of(&both);
            assert_eq!(
                a[7..],
                [
                    "start",
                    "--root",
                    "/r",
                    "--audit-policy",
                    "strict",
                    "--cri-log-path",
                    "/l/c/0.log",
                    "c1"
                ]
            );
            let parsed =
                StartArgs::parse(a[7..].iter().map(std::ffi::OsString::from)).expect("contract");
            assert_eq!(parsed.audit_policy, AuditCoveragePolicy::Strict);
        }
    }

    /// CLI-1・CORE-3: systemd-run の解決失敗は 2 つの固定文言へ写り、パスを載せない。
    #[test]
    fn cli1_systemd_run_error_messages() {
        const NOT_INSTALLED: &str =
            "systemd-run is not installed; starting a container requires a systemd user manager";
        const UNTRUSTED: &str = "systemd-run is not a trusted executable (must be a regular file owned by root or the current user, not writable by group or others)";
        let e = systemd_run_error(SystemdRunRejection::NotFound);
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), NOT_INSTALLED);
        for r in [
            SystemdRunRejection::Unreadable,
            SystemdRunRejection::NotRegularFile,
            SystemdRunRejection::NoExecuteBit,
            SystemdRunRejection::UntrustedOwner { ancestor: true },
            SystemdRunRejection::GroupOrOtherWritable { ancestor: false },
        ] {
            let e = systemd_run_error(r);
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), UNTRUSTED, "{r:?}");
        }
    }

    /// CLI-1・CORE-3: user マネージャに届かない理由は FAILED_PRECONDITION と共通の固定文言へ写る。
    #[test]
    fn cli1_user_manager_error_messages() {
        let e = user_manager_error(UserManagerError::RuntimeDirUnset);
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable"
        );
        let e = user_manager_error(UserManagerError::Unreachable);
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)"
        );
    }
}
