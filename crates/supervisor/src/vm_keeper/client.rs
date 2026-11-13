//! VM 保持役の起動役側（CLI・plugin-macos アダプタが使う予定の窓口。MAC-4・PLUG-12・REPAIR-5）。
//!
//! 呼び出し元は #2281（plugin-macos アダプタ）と W8 #4705 の CLI で、現時点では結合試験だけが使う（未配線。REPAIR-3）。
//! 1 要求ごとに接続する（保持役は 1 接続 1 要求）。接続時に保持役の peer UID が自 UID であることを `UdsStream::connect` が
//! 照合する。peer 拒否の監査イベントは起動役では出力せず、`PermissionDenied` のエラーとして返す。
//!
//! [`KeeperClient::ensure_running`] は「照会 → 失敗なら保持役を起動 → 期限まで照会をポーリング」で、ロックの競合は
//! 保持役同士が flock で決める（負けた保持役は `FAILED_PRECONDITION` で終わり、起動役は勝った側へつながる）。

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};
use fandhe_container_plugin::{
    Frame, JsonLinesPeerAuthObserver, RESIDENT_START_TIMEOUT_DEFAULT, RpcTimeout, RuntimeDir,
    UdsStream,
};

use super::protocol::{Request, Response};
use super::server::SOCKET_NAME;
use super::{REQUEST_IO_TIMEOUT, from_plugin};

/// 保持役が起動していない場合の待ちの既定（plugin 側の常駐 plugin の起動予算と同じ 10 秒）。
pub const ENSURE_RUNNING_TIMEOUT_DEFAULT: Duration = RESIDENT_START_TIMEOUT_DEFAULT;

/// 接続 1 回の待ち。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// 起動直後の存在確認の接続の待ち（居なければすぐ起動に進む）。
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
/// `ensure_running` の `deadline` の上限（これを超える値は `InvalidArgument`）。
pub const ENSURE_RUNNING_TIMEOUT_MAX: Duration = Duration::from_secs(60);
/// 単発の要求（status / register / unregister）の総予算。
const CALL_BUDGET: Duration = Duration::from_secs(5);
/// 残り時間が尽きかけでも 0 の待ちを作らないための下限。
const MIN_STEP: Duration = Duration::from_millis(1);
/// 書き込み後に総期限を過ぎた場合でも応答の読み取りに与える下限（応答を捨てない。有界）。
const READ_GRACE: Duration = Duration::from_millis(50);
/// 起動後のポーリング間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 保持役への窓口。
#[derive(Debug, Clone)]
pub struct KeeperClient {
    socket: PathBuf,
}

impl KeeperClient {
    /// 基底ディレクトリ（保持役の `--base` と同じ）から窓口を作る。配置ディレクトリを検証して作成する（PLUG-12）。
    pub fn new(base: &Path) -> Result<Self, TraitError> {
        let dir = RuntimeDir::ensure_under(base).map_err(from_plugin)?;
        let socket = dir.socket_path(SOCKET_NAME).map_err(from_plugin)?;
        Ok(Self { socket })
    }

    /// 1 要求を送る。接続・送受信・やり直しのすべてを `deadline` までに収める（REPAIR-5）。サーバーが期限直前の接続を
    /// 閉じる窓（`server::ACCEPT_SLICE` の doc）に当たると `Unavailable` になるため、残り時間があれば 1 回だけ新しい
    /// 接続でやり直す。やり直しは冪等な `Status` と、要求の送信が完了する前の失敗（接続・書き込み）に限る。
    /// `Register` / `Unregister` は要求を書き終えた後の失敗（応答の読み取りで切れた等）では適用済みの可能性があり、
    /// 別クライアントの更新を挟んだ再送が新しい登録を消すため、再送せず `Unavailable` を返す（MAC-4 の参照管理）。
    fn call(
        &self,
        request: &Request,
        connect_timeout: Duration,
        deadline: Instant,
    ) -> Result<Response, TraitError> {
        let mut sent = false;
        match self.call_once(request, connect_timeout, deadline, &mut sent) {
            Err(e)
                if e.code() == ErrorCode::Unavailable
                    && (!sent || matches!(request, Request::Status)) =>
            {
                self.call_once(request, connect_timeout, deadline, &mut sent)
            }
            other => other,
        }
    }

    fn call_once(
        &self,
        request: &Request,
        connect_timeout: Duration,
        deadline: Instant,
        sent: &mut bool,
    ) -> Result<Response, TraitError> {
        let remaining = remaining_until(deadline)?;
        // 起動役側の peer 拒否はエラーとして返すため、観測用の受け手は捨てる。
        let mut observer = JsonLinesPeerAuthObserver::new();
        let mut stream = UdsStream::connect(
            &self.socket,
            connect_timeout.min(remaining).max(MIN_STEP),
            &mut observer,
        )
        .map_err(from_plugin)?;
        let io_timeout = REQUEST_IO_TIMEOUT
            .min(remaining_until(deadline)?)
            .max(MIN_STEP);
        let timeout = RpcTimeout::new(io_timeout).map_err(from_plugin)?;
        let frame = Frame::new(request.encode()).map_err(from_plugin)?;
        stream.write_frame(&frame, timeout).map_err(from_plugin)?;
        // 以後の失敗は、サーバーが要求を適用した後かもしれない。
        *sent = true;
        // 書き込み後に総期限を過ぎていても、届いている応答を捨てないよう読み取りを短い下限つきで試みる
        // （読み取りは有界。期限切れ後の上乗せは `READ_GRACE` まで）。
        let read_budget = remaining_until(deadline).unwrap_or(Duration::ZERO);
        let timeout = RpcTimeout::new(
            REQUEST_IO_TIMEOUT
                .min(read_budget.max(READ_GRACE))
                .max(MIN_STEP),
        )
        .map_err(from_plugin)?;
        let reply = stream.read_frame(timeout).map_err(from_plugin)?;
        // 期限直後に届いた成功応答も捨てない（読み取り自体は上の期限つきで有界。捨てると準備済みの保持役を
        // 起動役が SIGKILL しうる）。
        Response::decode(reply.payload())
    }

    /// 単発の要求の総予算つきで送る。
    fn call_budgeted(&self, request: &Request) -> Result<Response, TraitError> {
        let deadline = Instant::now()
            .checked_add(CALL_BUDGET)
            .ok_or_else(deadline_error)?;
        self.call(request, CONNECT_TIMEOUT, deadline)
    }

    /// 参照数と保持役の pid を照会する。
    pub fn status(&self) -> Result<Response, TraitError> {
        self.call_budgeted(&Request::Status)
    }

    /// コンテナ 1 件を登録する。
    pub fn register(&self, id: &ContainerId) -> Result<Response, TraitError> {
        self.call_budgeted(&Request::Register(id.clone()))
    }

    /// コンテナ 1 件の登録を外す。
    pub fn unregister(&self, id: &ContainerId) -> Result<Response, TraitError> {
        self.call_budgeted(&Request::Unregister(id.clone()))
    }

    /// 保持役が応答する状態にして、その時点の照会結果を返す。
    ///
    /// すでに居れば `spawn` を呼ばない（戻り値の `Child` は `None`）。居なければ `spawn` で 1 回起動し、`deadline` まで
    /// 照会をポーリングする。起動した子が先に終わっても（二重起動で負けた等）待ちは続ける。期限切れは `Timeout` で、
    /// 起動した子は SIGKILL しない（子は応答を始めた時点で他クライアントの登録を受け付ける共有の保持役になりうるため。MAC-4）。
    /// すでに終了していれば回収するだけで、生きていれば保持役自身のロック競合による終了または猶予後の終了に任せる。
    /// peer 拒否（`PermissionDenied`）も同様に待たずに返し、子は kill しない。
    /// 戻り値の `Child` は呼び出し側が回収する。
    pub fn ensure_running(
        &self,
        spawn: impl FnOnce() -> io::Result<Child>,
        deadline: Duration,
    ) -> Result<(Response, Option<Child>), TraitError> {
        if deadline.is_zero() || deadline > ENSURE_RUNNING_TIMEOUT_MAX {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "the vm keeper start deadline is out of range",
            ));
        }
        // 入口で総期限を確定し、以後の接続・送受信・再試行・sleep をすべてこの残り時間で制限する。
        let limit = Instant::now()
            .checked_add(deadline)
            .ok_or_else(deadline_error)?;
        match self.call(&Request::Status, PROBE_CONNECT_TIMEOUT, limit) {
            Ok(resp) => return Ok((resp, None)),
            Err(e) if e.code() == ErrorCode::PermissionDenied => return Err(e),
            Err(_) => {}
        }
        if Instant::now() >= limit {
            return Err(deadline_error());
        }
        // 子を作る前に枠と回収担当を確保する。失敗・所有権移譲・回収完了で枠は解放される。
        let slot = REAP_LEDGER.reserve()?;
        let child = spawn().map_err(|_| {
            TraitError::new(ErrorCode::Internal, "the vm keeper could not be spawned")
        })?;
        loop {
            match self.call(&Request::Status, PROBE_CONNECT_TIMEOUT, limit) {
                // 期限直後でも応答済みの保持役は採用する（kill しない）。
                Ok(resp) => return Ok((resp, Some(child))), // slot は drop で解放（呼び出し側が回収）
                Err(e) if e.code() == ErrorCode::PermissionDenied => {
                    return Err(release_child(slot, child, e));
                }
                Err(_) => {}
            }
            let now = Instant::now();
            if now >= limit {
                return Err(release_child(slot, child, deadline_error()));
            }
            std::thread::sleep(POLL_INTERVAL.min(limit - now));
        }
    }
}

/// 期限までの残り。0 なら `Timeout`。
fn remaining_until(deadline: Instant) -> Result<Duration, TraitError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(deadline_error());
    }
    Ok(deadline - now)
}

fn deadline_error() -> TraitError {
    TraitError::new(
        ErrorCode::Timeout,
        "the vm keeper did not become ready in time",
    )
}

/// 起動した子を kill せずに回収担当へ渡し、`primary` を返す（REPAIR-5）。
///
/// 子は応答の開始後は他クライアントの登録を受け付けるため、起動元の待機失敗だけで SIGKILL すると共有の保持役と登録簿を失う
/// （MAC-4）。公開前の子はロック競合で自ら終了し、公開後の子は無登録の猶予後に自ら終了する。生きている子の `Child` を
/// そのまま drop すると親が回収しない限りゾンビとして残るため、共有の回収簿へ渡して終了まで回収する。
fn release_child(slot: SpawnSlot, child: Child, primary: TraitError) -> TraitError {
    slot.hand_over(child);
    primary
}

/// 回収簿に載せる子の上限（起動中の枠と回収待ちの子の合計）。超えると新規の起動を受け付けない
/// （子は drop せず、終了まで必ず回収する）。
const REAP_MAX_CHILDREN: usize = 16;
/// 回収スレッドの走査間隔。
const REAP_INTERVAL: Duration = Duration::from_millis(200);

/// 回収簿の状態。`in_flight` は予約済みでまだ回収簿へ渡っていない枠（起動中の子）。
struct LedgerState {
    in_flight: usize,
    children: Vec<Child>,
    reaper_started: bool,
}

/// 起動中の枠と回収待ちの子を合わせて上限を守り、常駐の回収担当が `try_wait` で終了まで回収する台帳（REPAIR-5）。
///
/// 回収担当は最初の予約の時点で確保し（`Child` を作る前）、確保できなければ起動を拒否する。以後は追加の API 呼び出しに
/// 頼らず担当が走査を続ける。
struct ReapLedger {
    state: std::sync::Mutex<LedgerState>,
    wake: std::sync::Condvar,
}

/// 起動前に予約した 1 枠。drop で解放し、`hand_over` で子の回収責任を台帳へ移す。
struct SpawnSlot {
    ledger: &'static ReapLedger,
    live: bool,
}

static REAP_LEDGER: ReapLedger = ReapLedger::new();

impl ReapLedger {
    const fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(LedgerState {
                in_flight: 0,
                children: Vec::new(),
                reaper_started: false,
            }),
            wake: std::sync::Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 終了済みの子を回収し、起動中と回収待ちの合計枠数を返す（待たない）。
    fn sweep(g: &mut LedgerState) -> usize {
        g.children.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        g.children.len() + g.in_flight
    }

    /// 枠を 1 つ予約する。満杯、または回収担当を確保できなければ `Unavailable`（子はまだ作られない）。
    fn reserve(&'static self) -> Result<SpawnSlot, TraitError> {
        let mut g = self.lock();
        if Self::sweep(&mut g) >= REAP_MAX_CHILDREN {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "too many vm keeper children are awaiting reaping",
            ));
        }
        if !g.reaper_started {
            std::thread::Builder::new()
                .name("vm-keeper-reaper".to_owned())
                .spawn(move || self.reaper_loop())
                .map_err(|_| {
                    TraitError::new(
                        ErrorCode::Unavailable,
                        "the vm keeper reaper could not be started",
                    )
                })?;
            g.reaper_started = true;
        }
        g.in_flight += 1;
        Ok(SpawnSlot {
            ledger: self,
            live: true,
        })
    }

    /// 常駐の回収担当。回収待ちがあれば一定間隔で走査し、無ければ通知まで眠る（プロセスの存続中動き続ける）。
    fn reaper_loop(&'static self) {
        let mut g = self.lock();
        loop {
            Self::sweep(&mut g);
            g = if g.children.is_empty() {
                self.wake
                    .wait(g)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            } else {
                self.wake
                    .wait_timeout(g, REAP_INTERVAL)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0
            };
        }
    }
}

impl SpawnSlot {
    /// 子の回収責任を台帳へ移す（枠は回収完了まで保たれる）。
    fn hand_over(mut self, child: Child) {
        let mut g = self.ledger.lock();
        g.children.push(child);
        g.in_flight = g.in_flight.saturating_sub(1);
        self.live = false;
        drop(g);
        self.ledger.wake.notify_all();
    }
}

impl Drop for SpawnSlot {
    fn drop(&mut self) {
        if self.live {
            let mut g = self.ledger.lock();
            g.in_flight = g.in_flight.saturating_sub(1);
        }
    }
}

/// 回収簿の終了済みの子を回収し、残りの件数（回収待ち）を返す（待たない）。
#[cfg(test)]
fn sweep_ledger() -> usize {
    let mut g = REAP_LEDGER.lock();
    ReapLedger::sweep(&mut g);
    g.children.len()
}

/// 保持役のログファイル名（配置ディレクトリ直下。保持役の stderr の出力先。REPAIR-4）。
pub const KEEPER_LOG_NAME: &str = "vm-keeper.log";
/// ログファイルの大きさの上限。超えていれば起動時に切り詰める（無制限の増加を避ける）。
const KEEPER_LOG_MAX_BYTES: u64 = 1 << 20;

/// 保持役の stderr の出力先を開く。検証済みの配置ディレクトリ直下の通常ファイルに限り、symlink は追従せず、
/// 所有者がディレクトリと同じで group / other の権限が無いことを確かめる（満たさなければ起動しない）。
fn open_keeper_log(base: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let denied = |m: &'static str| io::Error::new(io::ErrorKind::PermissionDenied, m);
    let dir = RuntimeDir::ensure_under(base)
        .map_err(|_| denied("the vm keeper runtime directory is not usable"))?;
    let dir_uid = std::fs::metadata(dir.path())?.uid();
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(crate::logs::rotating::LOG_READ_FLAGS)
        .open(dir.path().join(KEEPER_LOG_NAME))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != dir_uid || meta.mode() & 0o077 != 0 {
        return Err(denied(
            "the vm keeper log file has an unexpected type, owner or mode",
        ));
    }
    if meta.len() > KEEPER_LOG_MAX_BYTES {
        file.set_len(0)?;
    }
    Ok(file)
}

/// 保持役の実行ファイル `exe` を `--base <base>` で、CLI の終了に巻き込まれないよう別プロセスグループで起動する
/// （stdin / stdout は null。stderr は配置ディレクトリ直下の検証済みログ [`KEEPER_LOG_NAME`] へ追記し、操作別カウント・
/// レイテンシ・起動失敗理由を CLI の終了後も残す。REPAIR-4。`PATH` 探索・シェルは使わない）。
///
/// `exe` は絶対パスに限る。相対パス・単なる実行ファイル名は `PATH` 探索で意図しないバイナリを起動しうるため、
/// 起動前に `InvalidInput` で拒否する。
pub fn spawn_keeper(exe: &Path, base: &Path) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    if !exe.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the vm keeper executable path must be absolute",
        ));
    }
    let log = open_keeper_log(base)?;
    Command::new(exe)
        .arg("--base")
        .arg(base)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 相対パス・単なる名前は spawn 前に `InvalidInput` で拒否される（PATH 探索をしない契約）。
    #[test]
    fn spawn_keeper_rejects_non_absolute_exe() {
        for exe in ["fandhe-container-vm-keeper", "./keeper", "bin/keeper"] {
            let e = spawn_keeper(Path::new(exe), Path::new("/tmp"))
                .expect_err("non-absolute exe must be rejected");
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{exe}");
        }
    }

    /// 期限切れでも、起動した子（公開済みの保持役でありうる）を kill しない（MAC-4）。
    #[test]
    fn ensure_running_timeout_does_not_kill_spawned_child() {
        let dir = crate::test_root::test_root("vmk-client", "nokill");
        let client = KeeperClient::new(&dir).expect("client");
        let mut pid = 0u32;
        let r = client.ensure_running(
            || {
                let c = Command::new("sleep").arg("30").spawn()?;
                pid = c.id();
                Ok(c)
            },
            Duration::from_millis(200),
        );
        let e = r.expect_err("must time out");
        assert_eq!(e.code(), ErrorCode::Timeout);
        let alive = Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .expect("kill -0")
            .success();
        let _ = Command::new("kill").arg(pid.to_string()).status();
        assert!(
            alive,
            "spawned child {pid} must stay alive after the timeout"
        );
    }

    /// 終了済みの子は回収簿から `try_wait` で回収され、無期限の `wait` を使わない（REPAIR-5）。
    #[test]
    fn released_child_is_reaped_without_blocking_wait() {
        let slot = REAP_LEDGER.reserve().expect("reserve");
        let child = Command::new("true").spawn().expect("spawn true");
        let e = release_child(slot, child, deadline_error());
        assert_eq!(e.code(), ErrorCode::Timeout);
        let end = Instant::now() + Duration::from_secs(10);
        while sweep_ledger() > 0 {
            assert!(Instant::now() < end, "ledger must drain after child exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 要求を読んだ後に応答なしで切れた場合、`Register` / `Unregister` は再送せず（適用済みの可能性）、`Status` は
    /// 新しい接続で 1 回やり直す（MAC-4）。
    #[test]
    fn mutating_requests_are_not_resent_after_request_was_written() {
        use std::io::Read as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = crate::test_root::test_root("vmk-client", "noresend");
        let client = KeeperClient::new(&dir).expect("client");
        let _ = std::fs::remove_file(&client.socket);
        let listener = std::os::unix::net::UnixListener::bind(&client.socket).expect("bind");
        let conns = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&conns);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                seen.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                // 応答せずに閉じる。
            }
        });
        let id = ContainerId::new("c1").expect("id");
        for (name, r) in [
            ("register", client.register(&id)),
            ("unregister", client.unregister(&id)),
        ] {
            let e = r.expect_err(name);
            assert_eq!(e.code(), ErrorCode::Unavailable, "{name}");
        }
        assert_eq!(conns.load(Ordering::SeqCst), 2, "one connection each");
        let e = client.status().expect_err("status");
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert_eq!(conns.load(Ordering::SeqCst), 4, "status retried once");
    }

    /// 並行する予約が上限を超えず、解放・回収完了で枠が戻る（MAC-4・REPAIR-5）。
    #[test]
    fn reservations_never_exceed_cap_under_concurrency() {
        let ledger: &'static ReapLedger = Box::leak(Box::new(ReapLedger::new()));
        let granted = std::sync::atomic::AtomicUsize::new(0);
        let slots = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|sc| {
            for _ in 0..(REAP_MAX_CHILDREN * 3) {
                sc.spawn(|| {
                    if let Ok(slot) = ledger.reserve() {
                        granted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        slots.lock().expect("slots").push(slot);
                    }
                });
            }
        });
        assert_eq!(
            granted.load(std::sync::atomic::Ordering::SeqCst),
            REAP_MAX_CHILDREN
        );
        let e = ledger.reserve().err().expect("full");
        assert_eq!(e.code(), ErrorCode::Unavailable);
        // 解放すると枠が戻る。
        slots.lock().expect("slots").pop();
        let again = ledger.reserve().expect("freed slot");
        // 回収待ちへ移った子も、終了して回収されるまで枠を占める。
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        again.hand_over(child);
        assert!(ledger.reserve().is_err());
        {
            let mut g = ledger.lock();
            for c in g.children.iter_mut() {
                let _ = c.kill();
            }
        }
        let end = Instant::now() + Duration::from_secs(10);
        while ledger.reserve().is_err() {
            assert!(Instant::now() < end, "reaper must free the slot");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 保持役の stderr の出力先は配置ディレクトリ直下の 0600 の通常ファイルで、symlink は追従しない（REPAIR-4）。
    #[test]
    fn open_keeper_log_creates_private_file_and_rejects_symlink() {
        use std::os::unix::fs::MetadataExt as _;
        let base = crate::test_root::test_root("vmk-client", "log");
        let f = open_keeper_log(&base).expect("open log");
        assert_eq!(f.metadata().expect("meta").mode() & 0o777, 0o600);
        let dir = RuntimeDir::ensure_under(&base).expect("dir");
        let log = dir.path().join(KEEPER_LOG_NAME);
        std::fs::remove_file(&log).expect("rm");
        std::os::unix::fs::symlink(base.join("elsewhere"), &log).expect("symlink");
        assert!(open_keeper_log(&base).is_err());
    }
}
