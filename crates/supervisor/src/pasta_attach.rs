//! rootless の pasta 構成を supervisor の起動経路へ結線し、コンテナの寿命に連動させる層
//! （NET-9・NET-6・CORE-1・ERR-1・REPAIR-4・REPAIR-5・SEC-4・#1940。方式は `docs/design/rootless-network.md` 12.2・12.10）。
//!
//! # 役割と呼び出し文脈
//!
//! - start の手順 7（`ProductionStartDeps::build_launcher`）が、起動オプションの network が `Attachable`
//!   （ユーザー定義名。rootless）のときだけ、本モジュールの [`PastaAttachHook`] を core の
//!   `ProductionLauncherBuilder::netns_attach_hook` へ渡し、できた launcher を [`PastaAttachingLauncher`] で包む。
//! - core の launcher は PID 1 の exec の直前の同期点で netns と user namespace の fd 2 本を渡し、
//!   [`PastaAttachHook::attach`] を呼ぶ。フックは **holder の起動 → pasta の起動と準備完了の待ち** の順で行い、
//!   成功したときだけ core が PID 1 へ合図する（12.2 の (2)〜(6)）。pasta の準備が整う前に entrypoint は動かない。
//! - launch が成功すれば [`PastaAttachingLauncher::launch`] が起動済みの holder と pasta を
//!   [`PastaGuardedProcess`] に載せて返す。以後は supervisor の監視（`wait`）が、途中死の検出・PID 1 の回収後の
//!   pasta → holder の停止・`@pasta/<id>` の削除を行う（12.10）。
//!
//! # 後始末の保証（逆順の巻き戻し）
//!
//! - フックの途中の失敗: 起動済みのものを逆順（pasta → run dir → holder）に止めてから `Err` を返す
//! - launch が `Ok` の後で失敗: [`PastaAttachingLauncher::launch`] が受け渡し口に残った分を同じ順序で止める
//! - PID 1 の回収後・`terminate`・ハンドルの drop: pasta を止め、holder を止め、`@pasta/<id>` を消す（1 回だけ）
//! - 途中死: pasta か holder が先に死んだら **分離を緩めず** コンテナへ SIGTERM を送り、[`TERM_GRACE`] を超えたら
//!   SIGKILL する（ネットワーク無しで続けない。公開ポートが黙って消えない）。終了は通常の経路で restart policy に流れる
//!
//! # 単一スレッドの区間
//!
//! フックは core の launch の単一スレッドの区間から呼ばれる。スレッドを作らず、`stderr_sink` も呼ばない。この区間で
//! 出すログは [`PastaLogBuffer`] に積み、start の報告の後に `StartDeps::flush_deferred_logs` が出す
//! (準備期限超過・放棄の経路を含む全終端。deps が戻らない経路は入口の後ろ盾が同じバッファを出す。
//! 取り出しで空にするので 1 度だけ。#3359)。
//!
//! # 将来仕様・残余（REPAIR-3）
//!
//! - **pidfd での監視は採らない**: `pidfd_open` は `sys` の新しい `unsafe` になるため、生存確認は未回収の `Child` の
//!   `try_wait`（`wait` の周期ごと。pasta の stderr を読む責務も兼ねる）で行う。検出の遅れは `POLL_INTERVAL` 程度
//! - **restart の再 launch**: 同じ launcher とフックを通る形（起動の経路を 1 つ）だが、本番 launcher の再 launch は
//!   #2043 まで `FailedPrecondition` で拒否される。restart で動くことは本モジュールの時点では保証しない
//! - SEC-4 の監査への記録（識別の不一致）は #3330、CLI の `--network` の受け口と start での D10 の再照合は #3329、
//!   実機の通し確認は #3331
//!
//! Linux 専用（`lib.rs` で cfg）。エラーと構造化ログは固定語彙で、パス・argv・入力値を含めない（ERR-1）。

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{
    AttachableNamespaces, ContainerOutput, LaunchSpec, LaunchedProcess, NetnsAttachHook,
    ProcessExit, ProcessLauncher,
};
use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};
use fandhe_container_net::netns_holder::NetnsHolderFds;
use fandhe_container_net::pasta::binary::PastaBinary;
use fandhe_container_net::pasta::process::{
    PASTA_READY_TIMEOUT_DEFAULT, PastaExit, PastaStopPath, check_ready_timeout,
};
use fandhe_container_net::pasta::run_dir::{
    RunDirIdentity, RunDirRemoval, observe_run_dir, remove_pasta_run_dir,
    remove_pasta_run_dir_expecting, validate_container_id,
};
use fandhe_container_net::pasta::{
    PastaPortForwards, PastaProcess, PastaRunDir, PastaTarget, spawn_pasta,
};

use crate::netns_holder::{
    HolderExit, NetnsHolderProcess, StopPath, spawn_netns_holder, trait_code,
};

/// pasta の準備完了の待ちの既定(net の `PASTA_READY_TIMEOUT_DEFAULT`)。
pub const READY_TIMEOUT_DEFAULT: Duration = PASTA_READY_TIMEOUT_DEFAULT;

/// 途中死を検出してコンテナへ SIGTERM を送ってから、SIGKILL へ上げるまでの猶予。
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// 途中死の検出で `signal` に渡す期限（送信直前の確認用）。
/// drop が継続中の teardown のスレッドを待つ上限。teardown の各停止(pasta 最大 3 秒＋holder 最大 2 秒＋
/// 状態ルートの I/O の上限 [`RUN_DIR_IO_TIMEOUT`])を覆う。
const TEARDOWN_REAP_CAP: Duration = Duration::from_secs(10);
const SIGNAL_DEADLINE: Duration = Duration::from_secs(1);

/// `terminate` の後始末に使う、PID 1 を回収できなかったときの待ち。
/// 超過・失敗したときは回収を確かめられないため、`last_launch_may_have_left_process` を true にする
/// (fail-closed。CORE-2・REPAIR-5・#3360)。
const MISSING_ATTACHMENT_TERMINATE: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------------------------
// 構造化ログ
// ---------------------------------------------------------------------------------------------

/// 構造化ログの値。`Text` は helper の stderr など任意の文字列で、JSON の文字列として必ずエンコードして出す。
///
/// helper の stderr は net の `StderrExcerpt` が診断用に整形したもの(二重引用符・バックスラッシュをそのまま保持し、
/// 非 ASCII バイトは `\xNN` の文字列にする)で、JSON のエスケープ済みではない。直接挿入すると行が壊れるため
/// [`push_json_string`] で値ごとにエンコードする(REPAIR-4)。
enum Val {
    U(u64),
    S(&'static str),
    Text(String),
}

/// `s` を JSON の文字列リテラル(両端の二重引用符を除く本体)として `out` へ足す。
/// `"`・`\`・制御文字(U+0000〜U+001F)をエスケープする。
fn push_json_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
}

/// 1 行の構造化ログを組む（`component` / `event` / `container` と固定語彙の項目。REPAIR-4）。
fn json_line(event: &str, container: &str, fields: &[(&str, Val)]) -> String {
    let mut line = format!(
        "{{\"component\":\"supervisor\",\"event\":\"{event}\",\"container\":\"{container}\""
    );
    for (key, val) in fields {
        match val {
            Val::U(n) => line.push_str(&format!(",\"{key}\":{n}")),
            Val::S(s) => line.push_str(&format!(",\"{key}\":\"{s}\"")),
            Val::Text(s) => {
                line.push_str(&format!(",\"{key}\":\""));
                push_json_string(&mut line, s);
                line.push('"');
            }
        }
    }
    line.push_str("}\n");
    line
}

/// 単一スレッドの区間で出すログの遅延バッファ（start の報告の後に [`Self::flush`] が出す）。
#[derive(Debug, Default)]
pub struct PastaLogBuffer {
    lines: Mutex<Vec<String>>,
    /// 手順 2c の再検証が見つけた改ざんの疑い(作業スレッドが置き、単一スレッドの入口が取り出して監査へ配送する。
    /// SEC-4・#3330。作業スレッドは監査の `FileAuditSink`〔fork 隔離〕を使えないため、記録は入口に任せる)。
    tamper: Mutex<Option<fandhe_container_core::audit_log::PastaVerifyRejection>>,
    /// 2c の待ちが期限切れで、作業スレッドを join できないまま進んだ印。報告後に有界で回収する要否の判断と、
    /// 試験の照合に使う(回収の本体は `start_entry` の `UnjoinedOptionsWorker::drain`。SEC-4・REPAIR-5・#3431)。
    worker_unjoined: std::sync::atomic::AtomicBool,
    /// 2c の作業スレッドが pasta の再検証に入った印(記録があるときだけ立つ)。期限超過の行の `stage` を決める(#3431)。
    verify_started: std::sync::atomic::AtomicBool,
}

impl PastaLogBuffer {
    /// 空のバッファ。
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 行を積む（上限 64 行。超えた分は捨てる。無制限確保を避ける）。
    pub fn push(&self, line: String) {
        let mut g = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        if g.len() < 64 {
            g.push(line);
        }
    }

    /// 再検証が見つけた改ざんの疑いを置く(最初の 1 件を残す)。
    pub fn set_tamper(&self, rejection: fandhe_container_core::audit_log::PastaVerifyRejection) {
        let mut g = self.tamper.lock().unwrap_or_else(PoisonError::into_inner);
        g.get_or_insert(rejection);
    }

    /// 作業スレッドを join できないまま進んだことを記す。
    pub fn mark_worker_unjoined(&self) {
        self.worker_unjoined
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// 再検証(pasta の記録がある場合)に入ったことを記す。
    pub fn mark_verify_started(&self) {
        self.verify_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// 再検証に入ったか。
    pub fn verify_started(&self) -> bool {
        self.verify_started
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 作業スレッドを join できていないか。
    pub fn worker_unjoined(&self) -> bool {
        self.worker_unjoined
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 置かれた改ざんの疑いを取り出す。
    pub fn take_tamper(&self) -> Option<fandhe_container_core::audit_log::PastaVerifyRejection> {
        self.tamper
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// 積んだ行を取り出す（試験と flush が使う）。
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.lines.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// 積んだ行を supervisor の出力口へ待たずに流す（キュー満杯なら捨てる。REPAIR-5）。
    ///
    /// 取り出しで空にするので複数回（期限超過の経路と入口の後ろ盾など）呼んでも各行は 1 度だけ出る（#3359）。
    pub fn flush(&self) {
        for line in self.take() {
            emit_now(line);
        }
    }
}

/// 出力口へ待たずに 1 行を入れる。
fn emit_now(line: String) {
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

/// 出力の宛先（単一スレッドの区間では遅延、監視の段階では直接）。
#[derive(Clone)]
struct Logger {
    container: Arc<str>,
    buffer: Arc<PastaLogBuffer>,
}

impl Logger {
    fn log(&self, deferred: bool, event: &str, fields: &[(&str, Val)]) {
        let line = json_line(event, &self.container, fields);
        if deferred {
            self.buffer.push(line);
        } else {
            emit_now(line);
        }
    }
}

/// start の手順 2c の再検証の結果を `pasta_verify` として遅延バッファへ積む(NET-9・REPAIR-4)。
///
/// `Ok(日付)` は検証に通った版の日付(`YYYYMMDD`)、`Err((code, tamper))` は拒否の分類と改ざんの疑いの有無。
/// パス・出力は載せない(ERR-1)。SEC-4 の監査への記録は入口が `PastaLogBuffer::take_tamper` を配送する(#3330)。
pub(crate) fn log_pasta_verify(
    buffer: &PastaLogBuffer,
    container: &str,
    outcome: Result<u32, (ErrorCode, bool)>,
    elapsed: Duration,
) {
    let mut f = vec![("elapsed_ms", Val::U(millis(elapsed)))];
    match outcome {
        Ok(date) => {
            f.push(("result", Val::S("ok")));
            f.push(("version_date", Val::U(u64::from(date))));
        }
        Err((code, tamper)) => {
            f.push(("result", Val::S("rejected")));
            f.push(("code", Val::S(code.as_str())));
            f.push((
                "tamper_suspected",
                Val::S(if tamper { "true" } else { "false" }),
            ));
        }
    }
    buffer.push(json_line("pasta_verify", container, &f));
}

/// 手順 2c の作業スレッドが期限内に戻らなかったことを `pasta_verify`(`result:"timeout"`)として遅延バッファへ積む
/// (REPAIR-4・REPAIR-5・NET-9・#3431)。
///
/// `log_pasta_verify` の拒否(再検証の `--version` の期限超過)とは別の事実なので専用にした。`stage` は固定語彙で、
/// `verify` は再検証に入っていた(pasta の記録あり)、`document` は文書の読み取り・照合の段階で止まったことを表す。
/// 改ざんの疑いではないため SEC-4 の監査記録は出さない。パス・入力値は載せない(ERR-1)。
pub(crate) fn log_pasta_verify_timeout(
    buffer: &PastaLogBuffer,
    container: &str,
    waited: Duration,
    verify_started: bool,
) {
    buffer.push(json_line(
        "pasta_verify",
        container,
        &[
            ("elapsed_ms", Val::U(millis(waited))),
            ("result", Val::S("timeout")),
            (
                "stage",
                Val::S(if verify_started { "verify" } else { "document" }),
            ),
        ],
    ));
}

/// 改ざんの疑いを監査の記録先へ書けなかったことを `pasta_audit_unavailable` として遅延バッファへ積む(SEC-4・#3330)。
/// 起動の拒否は覆らない(fail-closed)。パス・出力は載せない(ERR-1)。
pub(crate) fn log_pasta_audit_unavailable(
    buffer: &PastaLogBuffer,
    container: &str,
    code: ErrorCode,
) {
    buffer.push(json_line(
        "pasta_audit_unavailable",
        container,
        &[("code", Val::S(code.as_str()))],
    ));
}

// ---------------------------------------------------------------------------------------------
// helper の抽象（試験のための差し替え点）
// ---------------------------------------------------------------------------------------------

/// helper（holder・pasta）の終了の材料。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitInfo {
    /// 終了コード。
    pub code: Option<i32>,
    /// 終了シグナル。
    pub signal: Option<i32>,
    /// stderr（診断用に整形済み・4 KiB 以下。JSON のエスケープはログの出力時に `Val::Text` が行う）。
    pub stderr: String,
}

/// 停止の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// 要求で終わった。
    Stopped,
    /// 猶予を超えて SIGKILL した。
    Killed,
    /// 要求の前に終わっていた。
    AlreadyExited,
    /// 回収できなかった（zombie が残り得る）。
    Unreaped,
}

impl StopKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Killed => "killed",
            Self::AlreadyExited => "already_exited",
            Self::Unreaped => "unreaped",
        }
    }
}

/// 停止の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    /// 停止の経路。
    pub kind: StopKind,
    /// 終了の材料。
    pub exit: ExitInfo,
    /// 停止に要した時間。
    pub elapsed: Duration,
}

/// 起動済みの helper のハンドル。
pub trait HelperHandle: Send {
    /// helper の pid（回収前だけ有効）。
    fn pid(&self) -> u32;
    /// 生きているか。状態を得られないときは `Err`（死んでいると誤認しない）。
    fn is_alive(&mut self) -> Result<bool, TraitError>;
    /// 止めて回収する。`detach_ok` が偽なら回収用のスレッドを作らない（単一スレッドの区間）。
    fn stop(&mut self, detach_ok: bool) -> StopReport;
}

/// 起動した helper と、起動から準備完了までの時間。
pub struct Spawned {
    /// ハンドル。
    pub handle: Box<dyn HelperHandle>,
    /// 準備完了までの時間（ミリ秒）。
    pub ready_ms: u64,
    /// pasta の `@pasta/<id>/` の世代(pasta の起動だけが `Some`。後始末の削除が、再作成後の新しい置き場所を
    /// 消さないための照合に使う。CORE-2)。
    pub generation: Option<u64>,
}

/// holder と pasta を実際に起動する層（本番は [`ProductionBackend`]、試験はフェイク）。
pub trait PastaAttachBackend: Send + Sync {
    /// fd 2 本を渡して holder を起動し、READY を `deadline` までに受ける。
    fn spawn_holder(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<Spawned, TraitError>;

    /// holder の pid を対象に pasta を起動し、準備完了を `deadline` までに待つ。
    fn spawn_pasta(&self, holder_pid: u32, deadline: Instant) -> Result<Spawned, TraitError>;

    /// `@pasta/<id>/` を launch の前の準備段階で作っておく(期限つき。launch 内の `spawn_pasta` は準備済みのものを使い、
    /// 状態ルートの I/O を同期で行わない。REPAIR-5)。既定は何もしない(フェイクの backend 用)。
    fn prepare_run_dir(&self, _deadline: Instant) -> Result<(), TraitError> {
        Ok(())
    }

    /// `@pasta/<id>/` を消す（無ければ成功）。`generation` が `Some` のときは、その世代が最新のときだけ消す
    /// (再作成された新しい置き場所を旧い後始末が消さない。`None` は起動の巻き戻しで、無条件に消す)。
    fn remove_run_dir(&self, generation: Option<u64>) -> Result<(), TraitError>;
}

// ---------------------------------------------------------------------------------------------
// 本番の backend
// ---------------------------------------------------------------------------------------------

/// 本番の構成値（検証済みのバイナリ・ポート公開・状態ルートの fd・コンテナ ID・準備完了の待ち）。
pub struct PastaAttachConfig {
    /// 起動時の再検証を通ったバイナリ（exec に使えるのはこれだけ）。
    pub binary: PastaBinary,
    /// 検証済みのポート公開。
    pub forwards: PastaPortForwards,
    /// 状態ルートのディレクトリ fd（`O_DIRECTORY | O_NOFOLLOW` で開いたもの）。
    pub state_root: OwnedFd,
    /// 状態ルートのパス(`state_root` の fd と同じ場所)。コンテナ単位のプロセス間ロック
    /// (`@container-options/@locks/<id>`。CLI の create / delete と共通)の取得に使う。
    pub state_root_path: PathBuf,
    /// コンテナ ID。
    pub container: ContainerId,
    /// 準備完了の待ち（既定は [`PASTA_READY_TIMEOUT_DEFAULT`]）。
    pub ready_timeout: Duration,
}

/// 状態ルートを `O_DIRECTORY | O_NOFOLLOW` で開く（symlink を辿らない。fd 起点の操作の土台。SEC-1）。
pub fn open_state_root(root: &Path) -> Result<OwnedFd, TraitError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let flags = crate::sys::open_dir_nofollow_flags()
        .map_err(|_| TraitError::new(ErrorCode::Unimplemented, "unsupported architecture"))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(root)
        .map_err(|_| {
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "the state root cannot be opened",
            )
        })?;
    Ok(OwnedFd::from(file))
}

/// CLI の delete が呼ぶ入口。`@pasta/<id>/` の残骸を消す（無ければ成功。記録の pid でのプロセス操作はしない。12.10）。
pub fn remove_pasta_leftovers(state_root: &Path, id: &ContainerId) -> Result<(), TraitError> {
    let fd = open_state_root(state_root)?;
    remove_pasta_run_dir(fd.as_fd(), id.as_str())
        .map_err(|e| TraitError::new(trait_code(e.code()), e.message().to_owned()))
}

/// 本番の backend。holder は [`spawn_netns_holder`]、pasta は net の `spawn_pasta` を呼ぶ。
///
/// `@pasta/<id>/` の作成・削除(状態ルートの I/O)は作業スレッドで期限つきに行う(止まった I/O で呼び出し元を
/// 無期限に止めない。REPAIR-5)。作成は launch の前の [`PastaAttachBackend::prepare_run_dir`] で済ませ、
/// `spawn_pasta` は準備済みのものを取り出して使う。
pub struct ProductionBackend {
    binary: PastaBinary,
    forwards: PastaPortForwards,
    container: ContainerId,
    ready_timeout: Duration,
    state_root: Arc<OwnedFd>,
    state_root_path: PathBuf,
    logger: Logger,
    run_dirs: Arc<RunDirGenerations>,
    /// 準備段階で作った置き場所(世代つき)。期限切れの後に作業スレッドが作り終えた分もここへ残る。
    prepared: Arc<Mutex<PreparedSlot>>,
}

impl ProductionBackend {
    fn new(config: PastaAttachConfig, logger: Logger) -> Self {
        Self {
            binary: config.binary,
            forwards: config.forwards,
            container: config.container,
            ready_timeout: config.ready_timeout,
            state_root: Arc::new(config.state_root),
            state_root_path: config.state_root_path,
            logger,
            run_dirs: Arc::new(RunDirGenerations::default()),
            prepared: Arc::new(Mutex::new(PreparedSlot::default())),
        }
    }
}

/// 準備段階の成果物。`ready` は `spawn_pasta` が取り出す。`ours` は自分が作った置き場所の同一性
/// (`st_dev`, `st_ino`)で、後始末の照合に使う。期限切れの旧い操作が、別の起動が作った新しい置き場所に
/// 触れないよう、削除は net の `remove_pasta_run_dir_expecting` がこの同一性に束縛して行う(CORE-2 の世代保護。
/// プロセス間でも効く。#3411)。
#[derive(Default)]
struct PreparedSlot {
    ready: Option<(u64, PastaRunDir)>,
    ours: Option<RunDirIdentity>,
}

/// 自分が作った置き場所(`ours`)と同一のときだけ削除する。別物(削除・再作成された新しい置き場所・symlink)・
/// 自分のものが無い(`ours` が `None`)ときは何も触れず `Ok(false)`。消す対象が無ければ `Ok(true)`。
///
/// 名前の引き直しや別の照合はせず、net の束縛した削除を 1 回だけ呼ぶ(中身は照合済み fd 起点・`rmdir` の直前に
/// 親 fd 起点で取り直す。再照合から `rmdir` までの窓は net の doc の残余で、コンテナ単位のロックが担う)。
fn remove_run_dir_if_ours(
    root: std::os::fd::BorrowedFd<'_>,
    id: &str,
    ours: Option<RunDirIdentity>,
) -> Result<bool, TraitError> {
    let Some(ours) = ours else { return Ok(false) };
    match remove_pasta_run_dir_expecting(root, id, ours).map_err(|e| net_to_trait(&e))? {
        RunDirRemoval::Removed | RunDirRemoval::Absent => Ok(true),
        RunDirRemoval::NotOurs => Ok(false),
    }
}

/// 準備の成果物を渡す。呼び出し側が期限切れで見限った(`abandoned`)後に作り終えた分は、捨てて渡さない
/// (新しい起動が旧い準備の置き場所を誤って使わない)。判定と格納は同じロックの下で行う。
fn deliver_prepared(
    slot: &Mutex<PreparedSlot>,
    abandoned: &AtomicBool,
    generation: u64,
    dir: PastaRunDir,
    ours: Option<RunDirIdentity>,
) -> bool {
    let mut g = lock(slot);
    if abandoned.load(Ordering::SeqCst) {
        return false;
    }
    g.ready = Some((generation, dir));
    g.ours = ours;
    true
}

/// 期限切れの準備を見限る。以後その準備の成果物は渡されず、自分のものとしても扱わない。
fn abandon_prepared(slot: &Mutex<PreparedSlot>, abandoned: &AtomicBool) {
    let mut g = lock(slot);
    abandoned.store(true, Ordering::SeqCst);
    g.ready = None;
    g.ours = None;
}

/// 作業スレッドへ渡す状態ルート操作の道具立て(所有物のみ。`'static`)。
struct IoJob {
    state_root: Arc<OwnedFd>,
    root_path: PathBuf,
    container: ContainerId,
    id: String,
}

impl IoJob {
    /// コンテナ単位のプロセス間ロックを `wait` まで待って取る(CLI の create / delete と共通。REPAIR-5)。
    /// 取れなければ(期限切れ含む)エラー。呼び出し側は何にも触れずに返す。
    fn lock(
        &self,
        wait: Duration,
    ) -> Result<crate::container_options::store::OptionsLock, TraitError> {
        crate::container_options::store::acquire_lock(&self.root_path, &self.container, wait)
    }

    fn abandoned_error(&self) -> TraitError {
        TraitError::new(
            ErrorCode::Timeout,
            "the pasta run directory operation was abandoned",
        )
    }
}

/// 置き場所の準備の本体(作業スレッドで動く)。コンテナ単位のロック(プロセス間)を `wait` まで待って取り、
/// 取れなければ何にも触れず失敗する(fail-closed)。ロックを取れても、呼び出し側が見限った(`abandoned`)なら何もしない
/// (期限切れの worker がロックを持たない間・持った後に新しい世代へ触れない構造。CORE-2・REPAIR-5)。
fn prepare_run_dir_job(
    job: &IoJob,
    wait: Duration,
    run_dirs: &RunDirGenerations,
    prepared: &Mutex<PreparedSlot>,
    abandoned: &AtomicBool,
) -> Result<(), TraitError> {
    let _guard = job.lock(wait)?;
    if abandoned.load(Ordering::SeqCst) {
        return Err(job.abandoned_error());
    }
    let fd = &job.state_root;
    // 観測と prepare を同じ排他の下で続けて行い、別世代の dir の pid を消さない(#3355・CORE-2)。
    let (generation, made) = run_dirs.advance_with(|| {
        let expected = observe_run_dir(fd.as_fd(), &job.id)?;
        PastaRunDir::prepare_expecting(fd.as_fd(), &job.id, expected)
    });
    let dir = made.map_err(|e| net_to_trait(&e))?;
    // 名前を引き直さず、保持している fd の同一性を記録する。
    let identity = dir.identity();
    deliver_prepared(prepared, abandoned, generation, dir, Some(identity));
    Ok(())
}

/// 置き場所の削除の本体(作業スレッドで動く)。ロックの取得から、同一性の確認、削除の完了までを 1 つのロックの下で行う。
fn remove_run_dir_job(
    job: &IoJob,
    wait: Duration,
    run_dirs: &RunDirGenerations,
    generation: Option<u64>,
    ours: Option<RunDirIdentity>,
    abandoned: &AtomicBool,
) -> Result<bool, TraitError> {
    let _guard = job.lock(wait)?;
    if abandoned.load(Ordering::SeqCst) {
        return Err(job.abandoned_error());
    }
    run_dirs.remove_if_current(generation, || {
        remove_run_dir_if_ours(job.state_root.as_fd(), &job.id, ours)
    })
}

impl ProductionBackend {
    fn io_job(&self) -> IoJob {
        IoJob {
            state_root: Arc::clone(&self.state_root),
            root_path: self.state_root_path.clone(),
            container: self.container.clone(),
            id: self.container.as_str().to_owned(),
        }
    }
}

/// 状態ルートの I/O(作成・削除)の待ちの上限。超えたら待ちを打ち切る(作業スレッドは残り、枠は実終了まで保持する)。
const RUN_DIR_IO_TIMEOUT: Duration = Duration::from_secs(3);

/// `job`(状態ルートの同期 I/O)を作業スレッドで実行し、`timeout` までだけ待つ(REPAIR-5)。
/// 期限切れは `Timeout`、同時実行枠の満杯は `ResourceExhausted`(何も実行していない)。
fn run_dir_io_bounded<T: Send + 'static>(
    timeout: Duration,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TraitError> {
    use crate::supervisor_log::{BoundedFailure, run_bounded_classified};
    run_bounded_classified(job, timeout).map_err(|f| match f {
        BoundedFailure::Busy => TraitError::new(
            ErrorCode::ResourceExhausted,
            "too many pending state root operations",
        ),
        BoundedFailure::Unfinished => TraitError::new(
            ErrorCode::Timeout,
            "the pasta run directory operation timed out",
        ),
    })
}

/// `@pasta/<id>/` の世代と、作成・削除を直列化するロック(CORE-2)。
///
/// 期限内に終わらなかった旧い teardown が、同じコンテナ ID で再作成された新しい置き場所を開き直して消さないよう、
/// 作成(世代の更新)と削除(世代の照合)を同じロックの下で行う。
#[derive(Debug, Default)]
struct RunDirGenerations {
    current: Mutex<u64>,
}

impl RunDirGenerations {
    /// ロックの下で世代を進め、`create` を実行する。新しい世代を返す。
    fn advance_with<T>(&self, create: impl FnOnce() -> T) -> (u64, T) {
        let mut g = lock(&self.current);
        *g += 1;
        let generation = *g;
        (generation, create())
    }

    /// ロックの下で `remove` を実行する。`generation` が最新でなければ何もしない(`Ok(false)`)。`remove` の戻りは
    /// 「触れた(消した・消す対象が無かった)か」で、同一性が違って触れなかったときは `Ok(false)`。
    fn remove_if_current<E>(
        &self,
        generation: Option<u64>,
        remove: impl FnOnce() -> Result<bool, E>,
    ) -> Result<bool, E> {
        let g = lock(&self.current);
        if generation.is_some_and(|want| want != *g) {
            return Ok(false);
        }
        remove()
    }
}

fn net_to_trait(e: &fandhe_container_net::error::NetError) -> TraitError {
    TraitError::new(trait_code(e.code()), e.message().to_owned())
}

/// main スレッドから呼ばれていること（pasta の `PR_SET_PDEATHSIG` は spawn したスレッドの終了でも届く。12.10）。
fn require_main_thread() -> Result<(), TraitError> {
    if crate::netns_holder::is_main_thread()? {
        Ok(())
    } else {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "pasta must be spawned from the main thread",
        ))
    }
}

impl PastaAttachBackend for ProductionBackend {
    fn spawn_holder(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<Spawned, TraitError> {
        let fds = NetnsHolderFds::new(user, net).map_err(|e| net_to_trait(&e))?;
        let started = Instant::now();
        match spawn_netns_holder(fds, deadline) {
            Ok(p) => {
                let pid = p.pid();
                Ok(Spawned {
                    handle: Box::new(HolderAdapter {
                        proc: Some(p),
                        pid,
                        exited: None,
                    }),
                    ready_ms: millis(started.elapsed()),
                    generation: None,
                })
            }
            Err(e) => {
                if !e.holder_stderr.is_empty() {
                    self.logger.log(
                        true,
                        "netns_holder_failed",
                        &[
                            ("code", Val::S(e.code().as_str())),
                            ("stderr", Val::Text(e.holder_stderr.clone())),
                        ],
                    );
                }
                Err(e.trait_error())
            }
        }
    }

    fn spawn_pasta(&self, holder_pid: u32, deadline: Instant) -> Result<Spawned, TraitError> {
        require_main_thread()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = self.ready_timeout.min(remaining);
        if timeout.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the attach deadline was exceeded before pasta started",
            ));
        }
        check_ready_timeout(timeout).map_err(|e| net_to_trait(&e))?;
        // 置き場所は準備段階(`prepare_run_dir`)で作ってある。launch 内では状態ルートの I/O を同期で行わない。
        let Some((generation, run_dir)) = lock(&self.prepared).ready.take() else {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the pasta run directory was not prepared",
            ));
        };
        let target = PastaTarget::from_pid(holder_pid).map_err(|e| net_to_trait(&e))?;
        match spawn_pasta(&self.binary, &run_dir, &self.forwards, target, timeout) {
            Ok((proc, ready)) => {
                let pid = proc.pid();
                Ok(Spawned {
                    handle: Box::new(PastaAdapter {
                        proc: Some(proc),
                        pid,
                    }),
                    ready_ms: millis(ready.elapsed()),
                    generation: Some(generation),
                })
            }
            Err(mut e) => {
                let d = e.diagnostics().clone();
                self.logger.log(
                    true,
                    "pasta_failed",
                    &[
                        ("code", Val::S(trait_code(e.code()).as_str())),
                        ("elapsed_ms", Val::U(millis(d.elapsed))),
                        ("stderr", Val::Text(d.stderr_excerpt)),
                    ],
                );
                // 未回収の子は drop が kill と回収を試みる（単一スレッドの区間なので回収スレッドは作らない）。
                drop(e.take_unreaped());
                Err(net_to_trait(&e.into_net_error()))
            }
        }
    }

    fn prepare_run_dir(&self, deadline: Instant) -> Result<(), TraitError> {
        let timeout = RUN_DIR_IO_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if timeout.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the deadline was exceeded before the pasta run directory was prepared",
            ));
        }
        let job = self.io_job();
        let (run_dirs, prepared) = (Arc::clone(&self.run_dirs), Arc::clone(&self.prepared));
        let abandoned = Arc::new(AtomicBool::new(false));
        let worker_abandoned = Arc::clone(&abandoned);
        let result = run_dir_io_bounded(timeout, move || {
            prepare_run_dir_job(&job, timeout, &run_dirs, &prepared, &worker_abandoned)
        });
        match result {
            Ok(r) => r,
            Err(e) => {
                abandon_prepared(&self.prepared, &abandoned);
                Err(e)
            }
        }
    }

    fn remove_run_dir(&self, generation: Option<u64>) -> Result<(), TraitError> {
        // 未使用の準備済み置き場所の fd は手放し、自分が作った置き場所の同一性を控える。
        let ours = {
            let mut g = lock(&self.prepared);
            g.ready = None;
            g.ours
        };
        let job = self.io_job();
        let run_dirs = Arc::clone(&self.run_dirs);
        let abandoned = Arc::new(AtomicBool::new(false));
        let worker_abandoned = Arc::clone(&abandoned);
        // ロックの取得から、同一性の確認、削除の完了までを 1 つの作業で行う(ロックを持たない間は何にも触れない)。
        let removed = run_dir_io_bounded(RUN_DIR_IO_TIMEOUT, move || {
            remove_run_dir_job(
                &job,
                RUN_DIR_IO_TIMEOUT,
                &run_dirs,
                generation,
                ours,
                &worker_abandoned,
            )
        });
        let removed = match removed {
            Ok(r) => r,
            Err(e) => {
                // 期限切れ。以後ロックを取れても何もしない。
                abandoned.store(true, Ordering::SeqCst);
                return Err(e);
            }
        };
        match removed {
            Ok(true) => {}
            // 世代が新しい、または同一性が違う(別の起動の置き場所)ので触れなかった。
            Ok(false) => self.logger.log(
                false,
                "pasta_run_dir_remove_skipped",
                &[("reason", Val::S("newer_generation"))],
            ),
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// holder のハンドルの本番アダプタ。
struct HolderAdapter {
    proc: Option<NetnsHolderProcess>,
    pid: u32,
    exited: Option<HolderExit>,
}

fn exit_of_holder(e: &HolderExit) -> ExitInfo {
    ExitInfo {
        code: e.code,
        signal: e.signal,
        stderr: e.stderr.clone(),
    }
}

impl HelperHandle for HolderAdapter {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_alive(&mut self) -> Result<bool, TraitError> {
        let Some(p) = self.proc.as_mut() else {
            return Ok(false);
        };
        match p.try_exit()? {
            None => Ok(true),
            Some(e) => {
                self.exited = Some(e);
                self.proc = None;
                Ok(false)
            }
        }
    }

    fn stop(&mut self, _detach_ok: bool) -> StopReport {
        let Some(p) = self.proc.take() else {
            return StopReport {
                kind: StopKind::AlreadyExited,
                exit: self.exited.as_ref().map(exit_of_holder).unwrap_or_default(),
                elapsed: Duration::ZERO,
            };
        };
        let out = p.stop();
        let kind = match out.path {
            StopPath::Stopped => StopKind::Stopped,
            StopPath::Killed => StopKind::Killed,
            StopPath::ReapTimedOut => StopKind::Unreaped,
        };
        // 回収できなかった子は手放す（zombie は監視プロセスの終了で init が回収する。回収スレッドは作らない）。
        drop(out.unreaped);
        StopReport {
            kind,
            exit: out.exit.as_ref().map(exit_of_holder).unwrap_or_default(),
            elapsed: out.elapsed,
        }
    }
}

/// pasta のハンドルの本番アダプタ。
struct PastaAdapter {
    proc: Option<PastaProcess>,
    pid: u32,
}

fn exit_of_pasta(e: PastaExit, stderr: String) -> ExitInfo {
    ExitInfo {
        code: e.code,
        signal: e.signal,
        stderr,
    }
}

impl HelperHandle for PastaAdapter {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_alive(&mut self) -> Result<bool, TraitError> {
        let Some(p) = self.proc.as_mut() else {
            return Ok(false);
        };
        p.is_alive().map_err(|e| net_to_trait(&e))
    }

    fn stop(&mut self, detach_ok: bool) -> StopReport {
        let started = Instant::now();
        let Some(p) = self.proc.as_mut() else {
            return StopReport {
                kind: StopKind::AlreadyExited,
                exit: ExitInfo::default(),
                elapsed: Duration::ZERO,
            };
        };
        match p.stop_checked() {
            Ok(o) => {
                self.proc = None;
                let kind = match o.path {
                    PastaStopPath::Term => StopKind::Stopped,
                    PastaStopPath::Kill => StopKind::Killed,
                    _ => StopKind::AlreadyExited,
                };
                StopReport {
                    kind,
                    exit: exit_of_pasta(o.exit, o.stderr_excerpt),
                    elapsed: started.elapsed(),
                }
            }
            Err(_) => {
                // 期限内に回収できなかった。監視の段階では回収を専用スレッドへ移す。単一スレッドの区間では
                // 子を持ったまま呼び出し元が drop し、drop が kill と回収を試みる。
                if detach_ok && let Some(p) = self.proc.take() {
                    let _ = p.detach_reaper();
                }
                StopReport {
                    kind: StopKind::Unreaped,
                    exit: ExitInfo::default(),
                    elapsed: started.elapsed(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 起動中の組（Attachment）
// ---------------------------------------------------------------------------------------------

/// 起動済みの holder と pasta の組と、それらを止めるのに要るもの。
struct Attachment {
    holder: Box<dyn HelperHandle>,
    pasta: Box<dyn HelperHandle>,
    /// pasta の置き場所の世代(削除の照合用)。
    generation: Option<u64>,
    backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
}

impl Attachment {
    /// どちらかが死んでいれば、その名前（`pasta` / `netns_holder`）を返す。状態不明は死んでいるとみなさない。
    fn dead_helper(&mut self) -> Option<&'static str> {
        if matches!(self.pasta.is_alive(), Ok(false)) {
            return Some("pasta");
        }
        if matches!(self.holder.is_alive(), Ok(false)) {
            return Some("netns_holder");
        }
        None
    }

    /// 逆順に止める: pasta → holder → `@pasta/<id>` の削除。1 回で消費する。
    fn teardown(mut self, reason: &'static str, detach_ok: bool, deferred: bool) {
        let rep = self.pasta.stop(detach_ok);
        self.log_exit("pasta_exit", reason, &rep, deferred);
        let rep = self.holder.stop(detach_ok);
        self.log_exit("netns_holder_exit", reason, &rep, deferred);
        if let Err(e) = self.backend.remove_run_dir(self.generation) {
            self.logger.log(
                deferred,
                "pasta_run_dir_remove_failed",
                &[("code", Val::S(e.code().as_str()))],
            );
        }
    }

    fn log_exit(&self, event: &str, reason: &'static str, rep: &StopReport, deferred: bool) {
        let mut f = vec![
            ("reason", Val::S(reason)),
            ("stop", Val::S(rep.kind.as_str())),
            ("elapsed_ms", Val::U(millis(rep.elapsed))),
        ];
        if let Some(c) = rep.exit.code.and_then(|c| u64::try_from(c).ok()) {
            f.push(("status", Val::U(c)));
        }
        if let Some(s) = rep.exit.signal.and_then(|s| u64::try_from(s).ok()) {
            f.push(("signal", Val::U(s)));
        }
        if !rep.exit.stderr.is_empty() {
            f.push(("stderr", Val::Text(rep.exit.stderr.clone())));
        }
        self.logger.log(deferred, event, &f);
    }
}

/// フックから launcher へ attachment を渡す口。
type Slot = Arc<Mutex<Option<Attachment>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// フックと launcher の包み
// ---------------------------------------------------------------------------------------------

/// pasta 構成の組み立て一式。フックと launcher の包みは同じ受け渡し口とログを共有する。
#[derive(Clone)]
pub struct PastaWiring {
    hook: Arc<PastaAttachHook>,
    slot: Slot,
    backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
}

impl PastaWiring {
    /// 本番の構成から作る。`container` は `validate_container_id` を通す。
    pub fn production(
        config: PastaAttachConfig,
        buffer: Arc<PastaLogBuffer>,
    ) -> Result<Self, TraitError> {
        validate_container_id(config.container.as_str()).map_err(|e| net_to_trait(&e))?;
        check_ready_timeout(config.ready_timeout).map_err(|e| net_to_trait(&e))?;
        let logger = Logger {
            container: Arc::from(config.container.as_str()),
            buffer,
        };
        let backend: Arc<dyn PastaAttachBackend> =
            Arc::new(ProductionBackend::new(config, logger.clone()));
        Ok(Self::with_backend(backend, logger))
    }

    /// 任意の backend から作る（試験用）。
    fn with_backend(backend: Arc<dyn PastaAttachBackend>, logger: Logger) -> Self {
        let slot: Slot = Arc::new(Mutex::new(None));
        let hook = Arc::new(PastaAttachHook {
            backend: Arc::clone(&backend),
            slot: Arc::clone(&slot),
            logger: logger.clone(),
        });
        Self {
            hook,
            slot,
            backend,
            logger,
        }
    }

    /// 準備済みの(または準備を試みた)`@pasta/<id>/` を回収する。起動権の予約を握ったまま、launch しなかった・
    /// 失敗した経路から呼ぶ。コンテナ単位のロックの下で、自分が作った置き場所にだけ触れる(冪等)。
    pub fn discard(&self) -> Result<(), TraitError> {
        self.backend.remove_run_dir(None)
    }

    /// 起動権の予約を握った後の準備段階で `@pasta/<id>/` を期限つきに作っておく(launch 内では準備済みのものを使う。
    /// コンテナ単位のロックの下で作る。ロックを取れなければ触れずに失敗する。REPAIR-5・CORE-2)。
    pub fn prepare(&self, deadline: Instant) -> Result<(), TraitError> {
        self.backend.prepare_run_dir(deadline)
    }

    /// core の launcher 構築器へ渡すフック。
    pub fn hook(&self) -> Arc<dyn NetnsAttachHook> {
        Arc::clone(&self.hook) as Arc<dyn NetnsAttachHook>
    }

    /// `inner`（フックを渡した core の launcher）を包んだ launcher。
    pub fn wrap(&self, inner: Arc<dyn ProcessLauncher>) -> Arc<dyn ProcessLauncher> {
        Arc::new(PastaAttachingLauncher {
            inner,
            slot: Arc::clone(&self.slot),
            _backend: Arc::clone(&self.backend),
            logger: self.logger.clone(),
            left_process: AtomicBool::new(false),
        })
    }
}

/// `NetnsAttachHook` の実装。順序は holder → pasta（12.2 の (2)〜(4)）。
pub struct PastaAttachHook {
    backend: Arc<dyn PastaAttachBackend>,
    slot: Slot,
    logger: Logger,
}

impl PastaAttachHook {
    /// fd を取り出した後の本体（試験が直接呼べるよう分ける。core の `AttachableNamespaces` は crate 外で作れない）。
    pub fn attach_fds(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        if lock(&self.slot).is_some() {
            // 前回の attachment が回収されていない。二重の attach を許さない（fail-closed）。
            return Err(TraitError::new(
                ErrorCode::Internal,
                "a previous pasta attachment was not collected",
            ));
        }
        if Instant::now() >= deadline {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the attach deadline was exceeded",
            ));
        }
        let mut holder = match self.backend.spawn_holder(user, net, deadline) {
            Ok(h) => h,
            Err(e) => {
                self.logger.log(
                    true,
                    "netns_holder_failed",
                    &[("code", Val::S(e.code().as_str()))],
                );
                return Err(e);
            }
        };
        let pasta = match self.backend.spawn_pasta(holder.handle.pid(), deadline) {
            Ok(p) => p,
            Err(e) => {
                // 逆順の巻き戻し: pasta は自分で片付けて戻る。ここ(core の単一スレッド区間)では helper の回収だけを行う。
                // 置き場所(`@pasta/<id>/`)の削除は作業スレッドとロックを要するため、区間の外の後始末
                // (`PastaAttachingLauncher::adopt` の launch 失敗経路と `release_network`)へ渡す。準備済みの
                // 置き場所の同一性は backend が保持している(REPAIR-1・REPAIR-5)。
                let rep = holder.handle.stop(false);
                self.logger.log(
                    true,
                    "netns_holder_exit",
                    &[
                        ("reason", Val::S("attach_failed")),
                        ("stop", Val::S(rep.kind.as_str())),
                        ("elapsed_ms", Val::U(millis(rep.elapsed))),
                    ],
                );
                return Err(e);
            }
        };
        self.logger.log(
            true,
            "netns_holder_ready",
            &[("elapsed_ms", Val::U(holder.ready_ms))],
        );
        self.logger.log(
            true,
            "pasta_ready",
            &[("elapsed_ms", Val::U(pasta.ready_ms))],
        );
        *lock(&self.slot) = Some(Attachment {
            holder: holder.handle,
            pasta: pasta.handle,
            generation: pasta.generation,
            backend: Arc::clone(&self.backend),
            logger: self.logger.clone(),
        });
        Ok(())
    }
}

impl NetnsAttachHook for PastaAttachHook {
    fn attach(
        &self,
        namespaces: AttachableNamespaces,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        let (user, net) = namespaces.into_parts();
        self.attach_fds(user, net, deadline)
    }
}

/// `ProcessLauncher` の包み。内側の launch が成功したら受け渡し口の attachment を [`PastaGuardedProcess`] に載せ、
/// 失敗したら残った分を逆順に止める。他のメソッドは内側へ転送する（転送の漏れは降格・監査の欠落になる）。
/// 例外は `last_launch_may_have_left_process` で、内側の判定に自前の状態を OR する
/// (内側の `Ok` を本ラッパーが `Err` に変えるため、trait の「Ok のときは呼ばれない」前提が崩れる。CORE-2・REPAIR-5・SUP-3)。
pub struct PastaAttachingLauncher {
    inner: Arc<dyn ProcessLauncher>,
    slot: Slot,
    _backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
    /// 直近の launch で、attachment なしの拒否時に PID 1 の terminate を確かめられず、プロセスが残り得るか
    /// (core の start / restart が起動予約を保持して確認つき回復へ回す判断材料。CORE-2・REPAIR-5・#3360)。
    left_process: AtomicBool,
}

impl PastaAttachingLauncher {
    /// 内側の launch の結果に、フックが残した attachment を結びつける(`LaunchSpec` を作れない試験のため分けた本体)。
    ///
    /// - `Ok`: attachment を [`PastaGuardedProcess`] に載せる。無ければ(フックが走っていない)プロセスを止めて `Err`。
    ///   止められなかった・期限を超えたときは `last_launch_may_have_left_process` が true(予約を保持させる)
    /// - `Err`: フックが `Ok` を返した後の launch の失敗(合図の失敗など)。残った分を逆順に止める(core の契約)
    fn adopt(
        &self,
        result: Result<Box<dyn LaunchedProcess>, TraitError>,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        // launch ごとに 1 回だけ呼ばれ、間に読み手が無いため launch 冒頭でのリセットと等価(core の launcher と同じ意味論)。
        self.left_process.store(false, Ordering::SeqCst);
        match result {
            Ok(process) => {
                let taken = lock(&self.slot).take();
                match taken {
                    Some(attachment) => Ok(Box::new(PastaGuardedProcess::new(
                        process,
                        attachment,
                        self.logger.clone(),
                    ))),
                    None => {
                        // フックが走らなかった(network のモードとフックの組が崩れた)。ネットワーク無しで走らせない。
                        if let Err(te) = process.terminate(MISSING_ATTACHMENT_TERMINATE) {
                            // 回収を確かめられない。予約を戻させず確認つき回復に回す(fail-closed)。
                            self.left_process.store(true, Ordering::SeqCst);
                            self.logger.log(
                                true,
                                "pasta_missing_attachment_terminate_failed",
                                &[("code", Val::S(te.code().as_str()))],
                            );
                        }
                        // 準備済みの置き場所も回収する(失敗経路で所有物を残さない。NET-9)。
                        let _ = self._backend.remove_run_dir(None);
                        Err(TraitError::new(
                            ErrorCode::Internal,
                            "the pasta attachment is missing after launch",
                        ))
                    }
                }
            }
            Err(e) => {
                // 単一スレッドの区間なのでスレッドは作らない。
                let taken = lock(&self.slot).take();
                match taken {
                    Some(a) => a.teardown("launch_failed", false, true),
                    // フックが attach する前(または attach に失敗)に launch が失敗した。準備済みの置き場所を回収する
                    // (全失敗経路で所有物を残さない。NET-9)。
                    None => {
                        if let Err(re) = self._backend.remove_run_dir(None) {
                            self.logger.log(
                                true,
                                "pasta_run_dir_remove_failed",
                                &[("code", Val::S(re.code().as_str()))],
                            );
                        }
                    }
                }
                Err(e)
            }
        }
    }
}

impl ProcessLauncher for PastaAttachingLauncher {
    fn launch_mode(&self) -> fandhe_container_core::oci_runtime::LaunchMode {
        self.inner.launch_mode()
    }

    fn rejection_audit_sink(&self) -> Option<&dyn fandhe_container_core::audit_log::AuditSink> {
        self.inner.rejection_audit_sink()
    }

    fn network_mode(&self) -> fandhe_container_core::oci_runtime::LaunchNetworkMode {
        self.inner.network_mode()
    }

    fn last_launch_may_have_left_process(&self) -> bool {
        self.left_process.load(Ordering::SeqCst) || self.inner.last_launch_may_have_left_process()
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.adopt(self.inner.launch(spec, timeout))
    }

    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        self.inner.confirm_no_process(id, timeout)
    }

    fn confirm_no_process_recorded(
        &self,
        id: &ContainerId,
        recorded: Option<&fandhe_container_core::traits::CgroupPlacement>,
        timeout: Duration,
    ) -> Result<(), TraitError> {
        self.inner
            .confirm_no_process_recorded(id, recorded, timeout)
    }
}

/// 起動済みの PID 1 と helper をまとめて持つハンドル。PID 1 の回収後に helper を止め、途中死でコンテナを止める。
pub struct PastaGuardedProcess {
    inner: Box<dyn LaunchedProcess>,
    attachment: Mutex<Option<Attachment>>,
    /// 途中死の検出後のシグナル送信の状態（成功した送信だけを送信済みとして記録する。REPAIR-5）。
    signals: Mutex<SignalState>,
    /// 期限内に終わらなかった teardown のスレッド。回収まで追跡し、`wait` / `terminate` / drop で join する（REPAIR-1）。
    teardown_worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// PID 1 の終了を観測したが helper の後始末が未完了のため、まだ呼び出し元へ返していない終了状態。
    /// 後始末の完了後にだけ `Some(exit)` を返す(旧 supervisor の遅れた teardown が、同じ ID で再作成された
    /// 新しい `@pasta/<id>` を消す窓を作らない。CORE-2・NET-9)。
    pending_exit: Mutex<Option<ProcessExit>>,
    unexpected: AtomicBool,
    /// SIGTERM から SIGKILL へ上げるまでの猶予(既定 [`TERM_GRACE`]。試験が縮める)。
    term_grace: Duration,
    /// drop が継続中の teardown を待つ上限(既定 [`TEARDOWN_REAP_CAP`]。試験が縮める)。
    reap_cap: Duration,
    logger: Logger,
}

/// 途中死の検出後のシグナル送信の進行。失敗は送信済みに数えず、有限回の再試行の後に段階を上げる。
#[derive(Default)]
struct SignalState {
    /// SIGTERM の送信に成功した時刻（猶予の起点。SIGTERM が送れず上限に達したときは猶予が経過済みの時刻）。
    term_sent_at: Option<Instant>,
    term_failures: u32,
    kill_failures: u32,
    /// SIGKILL の送信に成功した、または最終手段の terminate まで進めた。
    killed: bool,
}

/// シグナル送信の失敗を許す回数（`wait` の周期ごとに 1 回試す）。超えたら次の段階（SIGKILL / terminate）へ進む。
const MAX_SIGNAL_FAILURES: u32 = 3;

impl PastaGuardedProcess {
    /// 期限を超えて継続中だった teardown のスレッドを回収する。`block` が偽なら終了済みのときだけ join する。
    fn reap_teardown_worker(&self, block: bool) {
        let handle = {
            let mut g = lock(&self.teardown_worker);
            match g.take() {
                Some(h) if block || h.is_finished() => h,
                other => {
                    *g = other;
                    return;
                }
            }
        };
        let _ = handle.join();
    }

    /// 継続中の teardown のスレッドを `cap` までだけ待って回収する。終わらなければ join せず手放す(スレッドは
    /// 各停止の有限の期限で自力で終わる。Drop が無期限に塞がらないようにする。REPAIR-5)。
    fn reap_teardown_worker_bounded(&self, cap: Duration) {
        let until = Instant::now() + cap;
        loop {
            self.reap_teardown_worker(false);
            if lock(&self.teardown_worker).is_none() || Instant::now() >= until {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // 上限に達したら追跡を手放す(JoinHandle の drop は detach)。
        drop(lock(&self.teardown_worker).take());
    }

    /// helper の後始末が残っているか(attachment が未消費、または teardown のスレッドが継続中)。
    fn teardown_pending(&self) -> bool {
        lock(&self.attachment).is_some() || lock(&self.teardown_worker).is_some()
    }

    fn new(inner: Box<dyn LaunchedProcess>, attachment: Attachment, logger: Logger) -> Self {
        Self {
            inner,
            attachment: Mutex::new(Some(attachment)),
            signals: Mutex::new(SignalState::default()),
            teardown_worker: Mutex::new(None),
            pending_exit: Mutex::new(None),
            unexpected: AtomicBool::new(false),
            term_grace: TERM_GRACE,
            reap_cap: TEARDOWN_REAP_CAP,
            logger,
        }
    }

    /// helper を 1 回だけ止める。
    fn teardown(&self, reason: &'static str, detach_ok: bool) {
        let taken = lock(&self.attachment).take();
        if let Some(a) = taken {
            let reason = if self.unexpected.load(Ordering::SeqCst) {
                "unexpected"
            } else {
                reason
            };
            a.teardown(reason, detach_ok, false);
        }
    }

    /// `deadline` までに終わらせる teardown。helper の停止は pasta 最大 3 秒＋holder 最大 2 秒かかりうるため、
    /// 専用スレッドで実行して期限まで待つ。期限内に終わらなければ所有権はスレッドが保持したまま継続する
    /// （呼び出し元の期限契約を守る。REPAIR-5）。スレッドを作れないときは呼び出し元で実行する。
    fn teardown_bounded(&self, reason: &'static str, deadline: Instant) {
        let taken = lock(&self.attachment).take();
        let Some(a) = taken else { return };
        let reason = if self.unexpected.load(Ordering::SeqCst) {
            "unexpected"
        } else {
            reason
        };
        let cell = Arc::new(Mutex::new(Some(a)));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let worker_cell = Arc::clone(&cell);
        let spawned = std::thread::Builder::new()
            .name("pasta-teardown".into())
            .spawn(move || {
                let taken = lock(&worker_cell).take();
                if let Some(a) = taken {
                    a.teardown(reason, true, false);
                }
                let _ = tx.send(());
            });
        match spawned {
            Ok(handle) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if rx.recv_timeout(remaining).is_ok() {
                    let _ = handle.join();
                } else {
                    // 期限切れでも止めず、ハンドルを保持して後続の呼び出しと drop で回収する（未追跡で手放さない）。
                    *lock(&self.teardown_worker) = Some(handle);
                }
            }
            Err(_) => {
                // スレッドを作れない。ここで止めると pasta と holder の停止の猶予で期限を超えうるため実行しない。
                // 所有権を戻し、後続の `wait` / `terminate` の再試行と drop(最終手段の同期停止)に任せる。
                let taken = lock(&cell).take();
                if let Some(a) = taken {
                    self.logger.log(
                        false,
                        "pasta_teardown_deferred",
                        &[("reason", Val::S(reason))],
                    );
                    *lock(&self.attachment) = Some(a);
                }
            }
        }
    }

    /// PID 1 がまだ動いている間の helper の生死確認。死んでいたらコンテナを止める（分離は緩めない）。
    ///
    /// `budget_end` は呼び出し元の `wait` の絶対期限。予算が残っていなければシグナルの送信も回収も行わず、
    /// 次の周期へ繰り越す（`LaunchedProcess::wait` の「timeout まで」の契約と監視ループの停止応答を守る。REPAIR-5）。
    fn check_helpers(&self, budget_end: Instant) {
        let dead = {
            let mut g = lock(&self.attachment);
            match g.as_mut() {
                Some(a) => a.dead_helper(),
                None => return,
            }
        };
        let Some(which) = dead else { return };
        if !self.unexpected.swap(true, Ordering::SeqCst) {
            self.logger
                .log(false, "pasta_helper_died", &[("helper", Val::S(which))]);
        }
        let mut st = lock(&self.signals);
        let remaining = budget_end.saturating_duration_since(Instant::now());
        if st.killed || remaining.is_zero() {
            return;
        }
        let signal_budget = SIGNAL_DEADLINE.min(remaining);
        let deadline = Instant::now() + signal_budget;
        let kill_due = match st.term_sent_at {
            Some(at) => at.elapsed() >= self.term_grace,
            None => false,
        };
        if st.term_sent_at.is_none() {
            match self.inner.signal(Signal::SIGTERM, deadline) {
                Ok(()) => st.term_sent_at = Some(Instant::now()),
                Err(e) => {
                    st.term_failures += 1;
                    self.logger.log(
                        false,
                        "pasta_signal_failed",
                        &[
                            ("signal", Val::S("SIGTERM")),
                            ("code", Val::S(e.code().as_str())),
                        ],
                    );
                    if st.term_failures >= MAX_SIGNAL_FAILURES {
                        // SIGTERM が届かないまま待ち続けない。次の周期で SIGKILL へ上げる。
                        st.term_sent_at = Some(
                            Instant::now()
                                .checked_sub(self.term_grace)
                                .unwrap_or_else(Instant::now),
                        );
                    }
                }
            }
        } else if kill_due {
            match self.inner.signal(Signal::SIGKILL, deadline) {
                Ok(()) => st.killed = true,
                Err(e) => {
                    st.kill_failures += 1;
                    self.logger.log(
                        false,
                        "pasta_signal_failed",
                        &[
                            ("signal", Val::S("SIGKILL")),
                            ("code", Val::S(e.code().as_str())),
                        ],
                    );
                    if st.kill_failures >= MAX_SIGNAL_FAILURES {
                        // 最終手段: 内側の terminate（自身の期限つき）で回収に進める。成功を確認できたときだけ
                        // 完了扱いにし、失敗なら次の周期から SIGKILL の再試行に戻る(生存したまま監視だけ続けない。NET-9)。
                        match self.inner.terminate(signal_budget) {
                            Ok(()) => st.killed = true,
                            Err(e) => {
                                st.kill_failures = 0;
                                self.logger.log(
                                    false,
                                    "pasta_terminate_failed",
                                    &[("code", Val::S(e.code().as_str()))],
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for PastaGuardedProcess {
    fn drop(&mut self) {
        // 回収前に手放された場合も helper を残さない（単一スレッドの区間かもしれないので回収スレッドは作らない）。
        self.teardown("drop", false);
        // 期限を超えて継続中の teardown は、プロセスの終了で打ち切られないようここで回収する（各停止は有限時間）。
        self.reap_teardown_worker_bounded(self.reap_cap);
    }
}

impl LaunchedProcess for PastaGuardedProcess {
    fn pid(&self) -> std::num::NonZeroU32 {
        self.inner.pid()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        let deadline = Instant::now() + timeout;
        self.reap_teardown_worker(false);
        let cached = lock(&self.pending_exit).take();
        let result = match cached {
            Some(exit) => {
                // 後始末の完了待ち。期限まで短い周期で回収を試みる(REPAIR-5)。
                while self.teardown_pending() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5).min(timeout));
                    self.reap_teardown_worker(false);
                }
                Some(exit)
            }
            None => {
                // 子の終了待ちは生存中だと渡された timeout を使い切るため、helper の死亡処理(シグナル送信)は
                // 待ちの前に行い、予算を先に確保する(後ろへ回すと残り時間が常に 0 で永遠に繰り越される。NET-9・REPAIR-5)。
                // 死亡の検知が遅れるのは最大で 1 周期(待ちの timeout)。
                self.check_helpers(deadline);
                let remaining = deadline.saturating_duration_since(Instant::now());
                self.inner.wait(remaining)?
            }
        };
        match result {
            Some(exit) => {
                self.teardown_bounded("container_exit", deadline);
                self.reap_teardown_worker(false);
                if self.teardown_pending() {
                    // 後始末が終わるまで終了を返さない。呼び出し元(monitor)は Stopped を記録せず次の周期で再度呼ぶ。
                    *lock(&self.pending_exit) = Some(exit);
                    Ok(None)
                } else {
                    Ok(Some(exit))
                }
            }
            None => Ok(None),
        }
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let deadline = Instant::now() + timeout;
        let result = self.inner.terminate(timeout);
        self.teardown_bounded("terminate", deadline);
        self.reap_teardown_worker(false);
        // helper の後始末が期限内に終わっていないのに成功を返さない。呼び出し元はハンドルを保持して再試行できる
        // (別 supervisor による同一 ID の再作成と、遅れた teardown の競合を作らない。CORE-2・NET-9)。
        if result.is_ok() && self.teardown_pending() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "pasta helper teardown is still in progress",
            ));
        }
        result
    }

    fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
        self.inner.signal(signal, deadline)
    }

    fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.launch_pidfd()
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.inner.take_output()
    }

    fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
        self.inner.take_seccomp_listener()
    }

    fn launch_isolation(
        &self,
    ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
        self.inner.launch_isolation()
    }

    fn launch_rlimits(&self) -> Option<&fandhe_container_core::rlimits::Rlimits> {
        self.inner.launch_rlimits()
    }
}

#[cfg(test)]
mod tests;
