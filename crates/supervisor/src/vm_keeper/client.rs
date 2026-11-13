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
/// 期限切れ後に子を SIGKILL してから回収を待つ上限。
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
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
    /// 接続でやり直す。その接続は要求を処理していないので重複適用にはならないが、応答の読み取りで切れた場合は処理済みの
    /// 可能性があり、やり直しの応答が `AlreadyRegistered` / `NotRegistered` になりうる（呼び出し側はこれを
    /// 「すでにその状態」と読む）。
    fn call(
        &self,
        request: &Request,
        connect_timeout: Duration,
        deadline: Instant,
    ) -> Result<Response, TraitError> {
        match self.call_once(request, connect_timeout, deadline) {
            Err(e) if e.code() == ErrorCode::Unavailable => {
                self.call_once(request, connect_timeout, deadline)
            }
            other => other,
        }
    }

    fn call_once(
        &self,
        request: &Request,
        connect_timeout: Duration,
        deadline: Instant,
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
        let timeout = RpcTimeout::new(
            REQUEST_IO_TIMEOUT
                .min(remaining_until(deadline)?)
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
    /// 起動した子が残っていれば SIGKILL して期限つきで回収し、回収できなければ `Internal` を返す。peer 拒否（`PermissionDenied`）は待たずに返す。
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
        let mut child = spawn().map_err(|_| {
            TraitError::new(ErrorCode::Internal, "the vm keeper could not be spawned")
        })?;
        loop {
            match self.call(&Request::Status, PROBE_CONNECT_TIMEOUT, limit) {
                // 期限直後でも応答済みの保持役は採用する（kill しない）。
                Ok(resp) => return Ok((resp, Some(child))),
                Err(e) if e.code() == ErrorCode::PermissionDenied => {
                    return Err(stop_child(&mut child, e));
                }
                Err(_) => {}
            }
            let now = Instant::now();
            if now >= limit {
                return Err(stop_child(&mut child, deadline_error()));
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

/// 子を SIGKILL して期限つきで回収し、`primary` を返す。回収できなければ構造化エラー（`Internal`）に替える
/// （`wait` を無期限に呼ばない。REPAIR-5）。
fn stop_child(child: &mut Child, primary: TraitError) -> TraitError {
    // すでに終了していれば kill は失敗するが、その場合は下の try_wait が回収する。
    let _ = child.kill();
    let reap_deadline = Instant::now().checked_add(REAP_TIMEOUT);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return primary,
            Ok(None) => {}
            Err(_) => break,
        }
        match reap_deadline {
            Some(d) if Instant::now() < d => std::thread::sleep(POLL_INTERVAL),
            _ => break,
        }
    }
    TraitError::new(
        ErrorCode::Internal,
        "the vm keeper child could not be reaped after the failure",
    )
}

/// 保持役の実行ファイル `exe` を `--base <base>` で、CLI の終了に巻き込まれないよう別プロセスグループで起動する
/// （stdin / stdout / stderr は null。`PATH` 探索・シェルは使わない）。
pub fn spawn_keeper(exe: &Path, base: &Path) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    Command::new(exe)
        .arg("--base")
        .arg(base)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}
