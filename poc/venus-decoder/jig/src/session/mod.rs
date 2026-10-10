//! vhost-user セッションと ctrl キューの応答ループ（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。Linux 限定。
//!
//! 治具 VMM（frontend。crosvm 等）と接続済みの `UnixStream` 1 本分を最後まで処理する上位層。
//! `vhost_user`（codec・fd 受け渡し・ゲストメモリ）、`virtqueue`（split ring）、`adapter`（ctrl 要求の応答）をつなぎ、
//! 次の流れを作る。ネゴシエーション（`negotiation`）→ kick を受ける → ctrl キューから要求を取り出す →
//! `CtrlAdapter::handle_ctrl` → 応答を used ring へ書く → call で通知する。受入基準 2（ゲストの Mesa venus の capset
//! クエリが自前デコーダへ届いたことをログで確認）の前提で、実機での実行は F3（#725。人間担当）。
//!
//! 呼び出し元: `launch`（UDS を bind して `accept` した接続を渡す。F4・#1598）と結合試験。bind・所有者 / 権限 / symlink の検証は
//! `launch` が行う。peer credential の検証（PLUG-12。`SO_PEERCRED`）は `launch` が accept 直後に行い、この関数に渡る接続は照合済み
//! （`launch` の doc と設計書 10.9）。
//!
//! 待機はすべて期限つき（REPAIR-5）。単一 fd 用の `sys::wait_fd` を socket と ctrl の kick で交互に短く待つ方式のため、
//! kick への反応には最大 [`SessionLimits::poll_slice`] の遅延が乗る（複数 fd の ppoll 化は unsafe の承認範囲外）。
//! 共有メモリ（F5.2b.2・#1641）: `GET_SHMEM_CONFIG` への応答と `SET_BACKEND_REQ_FD` の fd の保持は `negotiation` が担い、終了時に
//! host-visible の成立状況（`host_visible` 行）を出す。backend 要求（`SHMEM_MAP` / `SHMEM_UNMAP`）の期限つき送信は `Session::shmem_map` / `shmem_unmap`（#1642）で、
//! ctrl の `RESOURCE_MAP_BLOB` / `UNMAP_BLOB` から呼ぶ（F5.2b.4a・#1643）。MAP は resource の大きさの memfd を作って frontend へ渡し、
//! UNMAP 後も memfd は resource の寿命（UNREF・セッション終了）まで保持して再 MAP で再利用する。frontend の失敗・期限切れ・切断ではゲストへ ERR を返し adapter を巻き戻す（無応答にしない）。
//! map 中の資源の解放（#1645 で確定）: map 中の `RESOURCE_UNREF` は拒否（`ERR_INVALID_PARAMETER`）、`CTX_DESTROY` は detach だけで map は残す、
//! map が残ったままのセッション終了（正常・エラー）では `release_blobs_at_end` が期限つきで `SHMEM_UNMAP` を送ってから memfd を閉じる。
//! 未実装（REPAIR-3）: cursorq（ring 1）の要求処理・`SET_CONFIG`・`VRING_NOFD`・inflight・
//! `observe::snapshot_lines` の定期出力（終了時の集計出力は実装済み。定期出力と virtqueue 個別の観測カウンタは未実装）。
//!
//! kick / call の fd は frontend が複製を持ち得るため、`O_NONBLOCK` を含む open file description のフラグと counter は
//! 相手と共有され、poll の後に相手が eventfd を読み書きして状態を変えたり、フラグを落としたりできる。そこでセッションの
//! スレッドは eventfd を直接 read / write せず、使い捨ての補助スレッドへ I/O を任せ、`recv_timeout` で期限を評価する
//! （共有フラグに依存しない。REPAIR-5）。補助スレッド自身も I/O の前に期限つきの poll で readiness を待つので、満杯の socket
//! や空の eventfd が渡されても期限で自力終了して fd ごと回収される。poll の後に相手が状態を変えた競合で I/O が止まった
//! 場合だけ、起こす逆向きの操作（kick は 1 を書く）を別の切り離したスレッドで試む。それでも残るスレッドの数は
//! プロセス全体で [`MAX_LIVE_WORKERS`] に抑え、超えたら `WORKER_LIMIT` で新規の I/O を拒否する。
//! 補助スレッドを使うぶん kick 1 回あたり数十 us の上乗せがあり、`ctrl_kick` のヒストグラムに現れる。
//! 未対応（REPAIR-3・将来仕様）: kick / call の fd の種類（eventfd）検査。eventfd の生成は `sys` の承認範囲（U1〜U10）外の
//! `unsafe` を要し、結合試験の偽 frontend が `UnixStream` で代用しているため、現状は種類によらず期限つき poll で守る。

mod backend_req;
mod error;
mod metrics;
mod negotiation;

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use error::{Cause, SessionError, SessionErrorCode};

use crate::adapter::{CtrlAdapter, ShmemOp, ShmemOpKind, Submit3d};
use crate::ctrl::{CtrlResponse, RESP_ERR_INVALID_PARAMETER};
use crate::device;
use crate::log::{self, QueryResult};
use crate::resource::MAX_RESOURCES;
use crate::sys;
use crate::vhost_user::backend_req::{
    BackendRequest, BackendRequestCode, ShmemMapRequest, ShmemMapping,
};
use crate::vhost_user::fd_passing::{
    MAX_FDS, MAX_TIMEOUT, create_memfd, recv_with_fds, send_with_fds,
};
use crate::vhost_user::observe;
use crate::vhost_user::{
    Ack, Decoded, EncodedMessage, HEADER_LEN, Header, MAX_PAYLOAD_LEN, Reply, RequestCode,
    TransportError, TransportErrorCode, decode_request_payload,
};
use crate::virtqueue::VirtqueueErrorCode;
use backend_req::{BackendAck, BackendReqError};
use metrics::{SessionMetrics, SessionOp};
use negotiation::{State, expected_fds, host_visible_config};

/// ctrl 要求として受け付ける readable の最大長（固定長のスタックバッファの大きさ）。`CTX_CREATE`（96 バイト）より十分大きい。
pub const MAX_CTRL_REQ_LEN: usize = 4096;
// 3 OS でビルドされる `ctrl` の上限（`SUBMIT_3D` の検査）と同じ値に保つ。
const _: () = assert!(MAX_CTRL_REQ_LEN == crate::ctrl::MAX_REQ_LEN);

const DEFAULT_POLL_SLICE: Duration = Duration::from_millis(10);

/// セッションの時間制限。すべて 0 より大きく [`MAX_TIMEOUT`]（1 時間）以下。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    message_timeout: Duration,
    idle_timeout: Duration,
    poll_slice: Duration,
}

impl SessionLimits {
    /// `message_timeout` は 1 メッセージの受信・応答送信・call 書き込みの期限、`idle_timeout` は無通信の上限。
    /// `poll_slice` は既定 10ms（`idle_timeout` が短ければそれ以下）。範囲外は `INVALID_ARGUMENT`。
    pub fn new(message_timeout: Duration, idle_timeout: Duration) -> Result<Self, SessionError> {
        let ok = |d: Duration| !d.is_zero() && d <= MAX_TIMEOUT;
        if !ok(message_timeout) || !ok(idle_timeout) {
            return Err(SessionError::new(SessionErrorCode::InvalidArgument, None));
        }
        Ok(Self {
            message_timeout,
            idle_timeout,
            poll_slice: DEFAULT_POLL_SLICE.min(idle_timeout),
        })
    }

    /// `poll_slice` を差し替える（0 より大きく `idle_timeout` 以下）。
    pub fn with_poll_slice(mut self, poll_slice: Duration) -> Result<Self, SessionError> {
        if poll_slice.is_zero() || poll_slice > self.idle_timeout {
            return Err(SessionError::new(SessionErrorCode::InvalidArgument, None));
        }
        self.poll_slice = poll_slice;
        Ok(self)
    }

    /// 1 メッセージの期限。
    pub fn message_timeout(&self) -> Duration {
        self.message_timeout
    }
    /// 無通信の上限。
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
    /// socket と kick を交互に待つ 1 回の長さ。
    pub fn poll_slice(&self) -> Duration {
        self.poll_slice
    }
}

/// セッションの正常終了の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// frontend がメッセージの境界で切断した。
    PeerClosed,
}

/// 接続 1 本分のセッションを最後まで処理する。ログ（1 行 1 要求）は `sink` へ流す。
///
/// エラーで終わる場合は `session_error` の行を 1 行出してから `Err` を返す。どの経路でも保持する fd と mmap は `Drop` で解放される。
/// map が残ったままの終了（正常・エラー）では、frontend へ期限つきで `SHMEM_UNMAP` を送ってから blob の memfd を閉じ、`blob_release` の
/// 集計行を出す（片づけの成否は結果を変えない。#1645）。
/// 内部状態が `!Send` なので、この関数を呼ぶスレッドの中で完結する。
pub fn run(
    sock: &UnixStream,
    limits: &SessionLimits,
    sink: &mut dyn FnMut(&str),
) -> Result<SessionEnd, SessionError> {
    run_with_submit_hook(sock, limits, sink, &mut |_| None)
}

/// 受理した `SUBMIT_3D` の受け渡し点を受けるフック。返した行は `sink` へそのまま流す（停止の通知など）。
pub type SubmitHook<'a> = &'a mut dyn FnMut(&Submit3d) -> Option<String>;

/// [`run`] に、受理した `SUBMIT_3D` ごとに呼ぶフックを足したもの（`--record` の記録。GPU-6・TASK-172 F6・#1602）。
///
/// 呼び出し元は `launch`（`recording::SubmitRecorder::on_submit` を渡す）と結合試験。フックを呼ぶのは、応答を used ring へ
/// 書き戻せた提出だけで、応答を捨てて adapter を巻き戻した提出（ゲストが ACK を見ていない）は呼ばない。ファイルや記録器の
/// 後始末は呼び出し側が行い、session はファイルに触れない。
pub fn run_with_submit_hook(
    sock: &UnixStream,
    limits: &SessionLimits,
    sink: &mut dyn FnMut(&str),
    on_submit: SubmitHook<'_>,
) -> Result<SessionEnd, SessionError> {
    let mut session = Session {
        state: State::new(),
        adapter: CtrlAdapter::default(),
        limits: *limits,
        metrics: SessionMetrics::default(),
        blobs: BlobMemTable::default(),
    };
    let result = session.serve(sock, sink, on_submit);
    // #1641: host-visible 共有メモリが成立したか（しない場合は理由）。#725 の実機確認でログから直接読めるようにする。
    // 成立の意味（セッション中に成立したか）を保つため、片づけで channel が壊れる前に出す。
    sink(&log::host_visible_line(
        session.state.host_visible().as_str(),
    ));
    // #1645: map が残ったままの終了では、frontend の map の表を治具の状態と食い違わせないよう SHMEM_UNMAP を送ってから
    // memfd を閉じる。片づけの成否は上のセッションの結果を変えない。
    session.release_blobs_at_end(sink);
    // REPAIR-4: 操作ごとの成功 / 失敗件数と所要時間、fd 受け渡し・ゲストメモリ I/O の集計を終了時に出す。
    for line in session
        .metrics
        .lines()
        .into_iter()
        .chain(observe::snapshot_lines())
    {
        sink(&line);
    }
    match &result {
        Ok(_) => sink(&log::session_end_line()),
        Err(e) => sink(&log::session_error_line(e.code.as_str(), e.request)),
    }
    result
}

struct Session {
    state: State,
    adapter: CtrlAdapter,
    limits: SessionLimits,
    metrics: SessionMetrics,
    /// blob の実メモリ（memfd）。`UNMAP_BLOB` の後も `UNREF` まで保持する。map が残ったままの終了では、
    /// `release_blobs_at_end` が `SHMEM_UNMAP` を（期限つきで）送ってから表を空にして `Drop` で閉じる（#1645）。
    blobs: BlobMemTable,
}

/// blob の memfd の名前（`/proc/self/maps` に出るため固定文字列。ゲスト由来の値を入れない）。
const BLOB_MEMFD_NAME: &std::ffi::CStr = c"venus-jig-blob";

/// blob の実メモリ 1 件分（資源表は `File` を持てないので `session` が持つ。F5.2b.4a・#1643）。
#[derive(Debug)]
struct BlobMem {
    res_id: u32,
    /// frontend へ `SHMEM_MAP` で渡した memfd。治具自身は map しない。保持と `Drop` での close が目的。
    memfd: File,
    /// 直近の（または現在の）host-visible 領域内の区間。`mapped == false` の間は参照しない。
    mapping: ShmemMapping,
    /// frontend へ map 中か。`UNMAP_BLOB` の成功で偽になるが、memfd は resource の寿命（`UNREF`・セッション終了）まで保持し、
    /// 再 MAP では同じ memfd を渡す（UNMAP をまたいで blob の内容を失わない）。
    mapped: bool,
}

/// 固定長（資源表と同じ上限 [`MAX_RESOURCES`]）の副表。ゲスト入力でアロケーションは増えない。
#[derive(Debug)]
struct BlobMemTable {
    slots: [Option<BlobMem>; MAX_RESOURCES],
}

impl Default for BlobMemTable {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
        }
    }
}

impl BlobMemTable {
    fn has_free_slot(&self) -> bool {
        self.slots.iter().any(Option::is_none)
    }

    /// 空きスロットにだけ入れる。満杯なら渡された値を返す。
    fn insert(&mut self, blob: BlobMem) -> Result<(), BlobMem> {
        match self.slots.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(blob);
                Ok(())
            }
            None => Err(blob),
        }
    }

    /// map 中の区間（UNMAP の対象）。
    fn mapped_of(&self, res_id: u32) -> Option<ShmemMapping> {
        self.slots
            .iter()
            .flatten()
            .find(|b| b.res_id == res_id && b.mapped)
            .map(|b| b.mapping)
    }

    /// 該当 resource の実メモリを取り出す（再 MAP で memfd を再利用するため。空きができるので `insert` は必ず成功する）。
    fn take(&mut self, res_id: u32) -> Option<BlobMem> {
        self.slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|b| b.res_id == res_id))
            .and_then(Option::take)
    }

    /// UNMAP の成功を記録する。memfd は残す。
    fn mark_unmapped(&mut self, res_id: u32) {
        for b in self.slots.iter_mut().flatten() {
            if b.res_id == res_id {
                b.mapped = false;
            }
        }
    }

    /// 資源表に無い（`UNREF` 済み）・大きさが違う（作り直された）resource の実メモリを閉じる。map 中のものは
    /// `UNREF` が拒否されるので残る。
    fn prune(&mut self, adapter: &CtrlAdapter) {
        for slot in self.slots.iter_mut() {
            let stale = slot.as_ref().is_some_and(|b| {
                !b.mapped && adapter.resource_size(b.res_id) != Some(b.mapping.len())
            });
            if stale {
                *slot = None;
            }
        }
    }

    /// map 中の区間を slot 順に返す（終了時の片づけ用。固定長の表の走査だけでアロケーションしない）。
    fn mapped_mappings(&self) -> impl Iterator<Item = ShmemMapping> + '_ {
        self.slots
            .iter()
            .flatten()
            .filter(|b| b.mapped)
            .map(|b| b.mapping)
    }

    /// map 中の件数。
    fn mapped_count(&self) -> usize {
        self.slots.iter().flatten().filter(|b| b.mapped).count()
    }

    /// 保持している memfd の件数（map 中・UNMAP 済みを問わない）。
    fn memfd_count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.memfd_count()
    }
}

/// `service_ctrl` の 1 要求分の処理結果（応答の書き戻し前）。
struct Processed {
    response: CtrlResponse,
    log_line: String,
    submit: Option<Submit3d>,
    /// frontend へ渡した map / unmap があったか（あれば応答の書き戻し失敗は巻き戻せない）。
    had_shmem: bool,
    /// 応答を書き戻せない要求として捨てる（adapter は巻き戻し済み）。
    dropped: bool,
    /// 応答を書き戻せなかったときに戻す adapter。
    adapter_before: CtrlAdapter,
}

/// 受信した要求と添付 fd。
struct Incoming {
    decoded: Decoded,
    fds: Vec<OwnedFd>,
}

fn wait(fd: BorrowedFd<'_>, interest: sys::Interest, d: Duration) -> Result<bool, SessionError> {
    match sys::wait_fd(fd, interest, d) {
        Ok(ready) => Ok(ready),
        Err(sys::SysError::Interrupted(_)) => Ok(false),
        Err(e) => Err(SessionError::transport(TransportError::from_sys(e), None)),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SessionError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(SessionError::new(SessionErrorCode::Timeout, None));
    }
    Ok(left)
}

/// `buf` を期限内に読み切る。fd は最初の受信でだけ受け付ける（`first_with_fds`）。`eof_ok` で先頭の 0 バイト（切断）は `Ok(false)`。
fn fill(
    sock: &UnixStream,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    first_with_fds: bool,
    deadline: Instant,
    eof_ok: bool,
) -> Result<bool, SessionError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let max_fds = if first_with_fds && filled == 0 {
            MAX_FDS
        } else {
            0
        };
        let dst = buf
            .get_mut(filled..)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
        match recv_with_fds(sock, dst, max_fds, remaining(deadline)?) {
            Ok(r) => {
                filled += r.len;
                fds.extend(r.fds);
            }
            Err(e) if e.code == TransportErrorCode::PeerClosed && filled == 0 && eof_ok => {
                return Ok(false);
            }
            Err(e) => return Err(SessionError::transport(e, None)),
        }
    }
    Ok(true)
}

impl Session {
    /// セッション終了時の blob の片づけ（D3。GPU-6・REPAIR-5・#1645）。`run_with_submit_hook` が `serve` の後に呼ぶ。
    ///
    /// map 中の blob（frontend が 0 を返したもの）へ slot 順に 1 件ずつ `SHMEM_UNMAP` を送る。crosvm は backend の切断でも
    /// reset でも SHMEM_MAP の map を自分から消さない（設計書 10.4.4）ため、治具が自分で外す。最初の失敗（期限切れ・切断・
    /// 非 0 の応答）で打ち切り、全体を `message_timeout` 1 つ分の期限で抑える。channel が未成立・`Broken` なら 1 バイトも送らない
    /// （`backend_exchange_within` のゲート）。最後に表を空にして memfd を `Drop` で閉じる。frontend が受け取った複製 fd と
    /// その mmap は治具が閉じても有効なまま。ログは数値と固定語彙だけ。
    fn release_blobs_at_end(&mut self, sink: &mut dyn FnMut(&str)) {
        let mapped = self.blobs.mapped_count();
        let memfds = self.blobs.memfd_count();
        let mut unmapped = 0usize;
        if mapped > 0 {
            let deadline = Instant::now().checked_add(self.limits.message_timeout);
            let targets: Vec<ShmemMapping> = self.blobs.mapped_mappings().collect();
            for mapping in targets {
                let left = match deadline {
                    Some(d) => d.saturating_duration_since(Instant::now()),
                    None => self.limits.message_timeout,
                };
                if left.is_zero() {
                    break;
                }
                let req = BackendRequest::ShmemUnmap(mapping);
                if self
                    .backend_exchange_within(&req, None, left, sink)
                    .is_err()
                {
                    break;
                }
                unmapped = unmapped.saturating_add(1);
            }
        }
        // 表を差し替えて memfd をすべて閉じる（どの経路でも閉じ忘れない）。
        self.blobs = BlobMemTable::default();
        sink(&log::blob_release_line(mapped, unmapped, memfds));
    }

    /// `SHMEM_MAP` を frontend へ送り、応答を確かめる（#1642。呼び出し元は `execute_shmem`＝ctrl `MAP_BLOB`。#1643）。
    ///
    /// ゲート（REPLY_ACK 確定・host-visible 成立）を通らなければ送らずに `Err`（ログも出さない。呼び出し側が ctrl の
    /// エラーとして記録する）。送った場合は結果を 1 行ログに出し、治具側の失敗なら channel を閉じる。`fd` は借りるだけ。
    fn shmem_map(
        &mut self,
        req: &ShmemMapRequest,
        fd: BorrowedFd<'_>,
        sink: &mut dyn FnMut(&str),
    ) -> Result<BackendAck, BackendReqError> {
        self.backend_exchange(&BackendRequest::ShmemMap(*req), Some(fd), sink)
    }

    /// `SHMEM_UNMAP` を送る（#1642。MAP と同じ区間。fd なし）。
    fn shmem_unmap(
        &mut self,
        mapping: &ShmemMapping,
        sink: &mut dyn FnMut(&str),
    ) -> Result<BackendAck, BackendReqError> {
        self.backend_exchange(&BackendRequest::ShmemUnmap(*mapping), None, sink)
    }

    fn backend_exchange(
        &mut self,
        req: &BackendRequest,
        fd: Option<BorrowedFd<'_>>,
        sink: &mut dyn FnMut(&str),
    ) -> Result<BackendAck, BackendReqError> {
        let timeout = self.limits.message_timeout;
        self.backend_exchange_within(req, fd, timeout, sink)
    }

    /// `backend_exchange` の期限を呼び出し側が決める版（終了時の片づけが全体の期限の残りを渡す。#1645）。
    fn backend_exchange_within(
        &mut self,
        req: &BackendRequest,
        fd: Option<BorrowedFd<'_>>,
        timeout: Duration,
        sink: &mut dyn FnMut(&str),
    ) -> Result<BackendAck, BackendReqError> {
        let result = {
            let sock = self.state.backend_channel(req.code())?;
            backend_req::exchange(sock, req, fd, timeout)
        };
        let m = req.mapping();
        let (shmid, off, len) = (m.shmid(), m.shm_offset(), m.len());
        let outcome = match &result {
            Ok(_) => log::BackendReqOutcome::Ok,
            Err(e) => match e.status {
                Some(v) => log::BackendReqOutcome::Status(v),
                None => log::BackendReqOutcome::Code(e.code.as_str()),
            },
        };
        sink(&log::backend_req_result_line(
            req.code().as_str(),
            shmid,
            off,
            len,
            outcome,
        ));
        if let Err(e) = &result
            && e.desyncs_channel()
        {
            self.state.mark_backend_broken();
        }
        result
    }

    fn serve(
        &mut self,
        sock: &UnixStream,
        sink: &mut dyn FnMut(&str),
        on_submit: SubmitHook<'_>,
    ) -> Result<SessionEnd, SessionError> {
        let mut last_activity = Instant::now();
        loop {
            if last_activity.elapsed() >= self.limits.idle_timeout {
                return Err(SessionError::new(SessionErrorCode::IdleTimeout, None));
            }
            if wait(
                sock.as_fd(),
                sys::Interest::Readable,
                self.limits.poll_slice,
            )? {
                let started = Instant::now();
                let handled = match self.read_message(sock) {
                    Ok(None) => return Ok(SessionEnd::PeerClosed),
                    Ok(Some(incoming)) => self.dispatch(sock, incoming, sink),
                    Err(e) => Err(e),
                };
                self.metrics
                    .record(SessionOp::Message, handled.is_ok(), started.elapsed());
                handled?;
                last_activity = Instant::now();
            }
            let started = Instant::now();
            let serviced = self.service_ctrl(sink, on_submit);
            if !matches!(serviced, Ok(false)) {
                self.metrics
                    .record(SessionOp::CtrlKick, serviced.is_ok(), started.elapsed());
            }
            if serviced? {
                last_activity = Instant::now();
            }
        }
    }

    /// 1 メッセージを受信して復号し、添付 fd の個数を照合する。メッセージの境界での切断は `None`。
    fn read_message(&self, sock: &UnixStream) -> Result<Option<Incoming>, SessionError> {
        let deadline = Instant::now()
            .checked_add(self.limits.message_timeout)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
        let mut fds = Vec::new();
        let mut hdr = [0u8; HEADER_LEN];
        if !fill(sock, &mut hdr, &mut fds, true, deadline, true)? {
            return Ok(None);
        }
        let header = Header::decode_request(&hdr)?;
        let mut payload = [0u8; MAX_PAYLOAD_LEN];
        let n = header.payload_len();
        let body = payload
            .get_mut(..n)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?;
        fill(sock, body, &mut fds, false, deadline, false)?;
        let decoded = decode_request_payload(&header, body)?;
        let want = expected_fds(&decoded.request);
        if fds.len() != want {
            let code = if want == 0 {
                SessionErrorCode::UnexpectedFds
            } else {
                SessionErrorCode::FdCountMismatch
            };
            return Err(SessionError::new(code, Some(header.request().as_u32())));
        }
        Ok(Some(Incoming { decoded, fds }))
    }

    fn dispatch(
        &mut self,
        sock: &UnixStream,
        incoming: Incoming,
        sink: &mut dyn FnMut(&str),
    ) -> Result<(), SessionError> {
        let Incoming { decoded, fds } = incoming;
        let code = decoded.request.code();
        let need_reply = decoded.need_reply;
        // NEED_REPLY つき SET_PROTOCOL_FEATURES 自体にも応答するため、処理前後どちらかで REPLY_ACK が
        // 確定していれば応答義務ありとする（初回有効化の ACK と、解除要求への従前義務の ACK。#1639）。
        let ack_before = self.state.reply_ack();
        match self.state.handle(decoded.request, fds) {
            Ok(Some(reply)) => {
                self.send_reply(sock, &reply.encode()?, code)?;
                if let Reply::ShmemConfig(cfg) = &reply {
                    let id = device::SHM_ID_HOST_VISIBLE;
                    sink(&log::shmem_config_line(cfg.nregions(), id, cfg.size(id)));
                }
                Ok(())
            }
            // 応答本体を持たない要求の成功。REPLY_ACK 確定済みで NEED_REPLY が立っていれば u64 の 0 を返す。
            Ok(None) if code == RequestCode::SetBackendReqFd => {
                // 受理の記録は ack より先に出す（ack の送信に失敗しても受理した事実は残る）。
                sink(&log::backend_req_line());
                self.ack_success(sock, code, need_reply, ack_before, sink)
            }
            Ok(None) if need_reply && (ack_before || self.state.reply_ack()) => {
                self.send_reply(sock, &Reply::Ack(Ack::success(code)?).encode()?, code)?;
                sink(&log::need_reply_ack_line(code.as_u32(), true));
                Ok(())
            }
            // REPLY_ACK が確定していないセッションでは NEED_REPLY に応答しない。
            Ok(None) if need_reply => {
                sink(&log::need_reply_ignored_line(code.as_u32()));
                Ok(())
            }
            Ok(None) => Ok(()),
            // 失敗した SET_* に NEED_REPLY があれば非 0 を返してからセッションを終える（fail-closed。#1639 D2）。
            // GET_* の失敗には応答しない（ack の値が応答値と誤解されうる）。送信失敗でも元のエラーを優先する。
            Err(e) => {
                if need_reply
                    && (ack_before || self.state.reply_ack())
                    && !code.has_reply_body()
                    && let Ok(ack) = Ack::failure(code)
                    && let Ok(msg) = Reply::Ack(ack).encode()
                    && self.send_reply(sock, &msg, code).is_ok()
                {
                    sink(&log::need_reply_ack_line(code.as_u32(), false));
                }
                Err(e)
            }
        }
    }

    /// 応答本体を持たない要求の成功への ack（REPLY_ACK 確定済みで NEED_REPLY のときだけ送る）。
    fn ack_success(
        &self,
        sock: &UnixStream,
        code: RequestCode,
        need_reply: bool,
        ack_before: bool,
        sink: &mut dyn FnMut(&str),
    ) -> Result<(), SessionError> {
        if !need_reply {
            return Ok(());
        }
        if ack_before || self.state.reply_ack() {
            self.send_reply(sock, &Reply::Ack(Ack::success(code)?).encode()?, code)?;
            sink(&log::need_reply_ack_line(code.as_u32(), true));
        } else {
            sink(&log::need_reply_ignored_line(code.as_u32()));
        }
        Ok(())
    }

    /// 符号化済みの応答を fd なしで期限内に送り切る（REPAIR-5）。`GET_*` の応答と ack で共有する。
    fn send_reply(
        &self,
        sock: &UnixStream,
        msg: &EncodedMessage,
        code: RequestCode,
    ) -> Result<(), SessionError> {
        let deadline = Instant::now()
            .checked_add(self.limits.message_timeout)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
        let bytes = msg.as_bytes();
        let mut off = 0usize;
        while off < bytes.len() {
            let rest = bytes
                .get(off..)
                .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?;
            let sent = send_with_fds(sock, rest, &[], remaining(deadline)?)
                .map_err(|e| SessionError::transport(e, Some(code.as_u32())))?;
            off += sent.len;
        }
        Ok(())
    }

    /// ctrl キュー（ring 0）の kick を待ち、積まれた要求を空にして call で通知する。処理したら真。
    ///
    /// 1 要求ごとに 3 段に分ける。(a) ring を借りて取り出し・読み取り、(b) `state` の借用を手放して `process_ctrl`
    /// （`MAP_BLOB` / `UNMAP_BLOB` が backend channel を使うため）、(c) もう一度 ring を借りて応答を書き戻す。
    fn service_ctrl(
        &mut self,
        sink: &mut dyn FnMut(&str),
        on_submit: SubmitHook<'_>,
    ) -> Result<bool, SessionError> {
        let poll_slice = self.limits.poll_slice;
        let message_timeout = self.limits.message_timeout;
        let Some((ring, _)) = self.state.ctrl_parts() else {
            return Ok(false);
        };
        if !wait(ring.kick.as_fd(), sys::Interest::Readable, poll_slice)? {
            return Ok(false);
        }
        // 相手が poll の後に counter を読み切っていれば処理するものが無い（次の kick を待つ）。
        let kick = read_kick(&ring.kick, poll_slice)?;
        if kick == KickRead::Drained {
            return Ok(false);
        }
        let depth = ring.depth();
        let vq = |e| SessionError::virtqueue(e, None);
        let mut done = 0usize;
        for _ in 0..depth {
            // (a) 取り出しと読み取り。
            let mut buf = [0u8; MAX_CTRL_REQ_LEN];
            let (chain, req_len, writable_len) = {
                let Some((ring, mem)) = self.state.ctrl_parts() else {
                    break;
                };
                let chain = match ring.queue.pop(mem) {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => return Err(vq(e)),
                };
                let req_len = if chain.readable_len() > MAX_CTRL_REQ_LEN as u64 {
                    None
                } else {
                    Some(chain.read_readable(mem, &mut buf).map_err(vq)?)
                };
                let writable_len = chain.writable_len();
                (chain, req_len, writable_len)
            };
            // (b) 処理。
            let req = match req_len {
                Some(n) => Some(
                    buf.get(..n)
                        .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?,
                ),
                None => None,
            };
            let p = self.process_ctrl(req, writable_len, sink);
            // (c) 書き戻し。
            let Some((ring, mem)) = self.state.ctrl_parts() else {
                return Err(SessionError::new(SessionErrorCode::InvalidValue, None));
            };
            let mut dropped = p.dropped;
            let len = if dropped {
                0
            } else {
                match chain.write_writable(mem, p.response.as_bytes()) {
                    Ok(n) => n,
                    // 書き戻し先が足りない要求は応答を捨て（len=0）、セッションは続ける。
                    // frontend が結果を確認できないため、この要求による adapter の状態変更も取り消す
                    // （取り消さないと同じ ID の再送が重複エラーになる）。
                    // frontend へ渡した map / unmap があるときは事前検査で起きないはずで、起きたら不整合を残さず終える。
                    Err(e)
                        if e.code == VirtqueueErrorCode::UsedLenExceedsWritable && !p.had_shmem =>
                    {
                        dropped = true;
                        self.adapter = p.adapter_before.clone();
                        0
                    }
                    Err(e) => return Err(vq(e)),
                }
            };
            ring.queue.add_used(mem, chain, len).map_err(vq)?;
            // 応答が確定した（巻き戻しが無い）ので、`UNREF` 済み resource の実メモリをここで閉じる。
            if !dropped {
                self.blobs.prune(&self.adapter);
            }
            sink(&p.log_line);
            if dropped {
                sink(&log::response_dropped_line());
            } else if let Some(s) = p.submit
                && let Some(line) = on_submit(&s)
            {
                sink(&line);
            }
            done += 1;
        }
        if done > 0 {
            let started = Instant::now();
            let Some((ring, _)) = self.state.ctrl_parts() else {
                return Err(SessionError::new(SessionErrorCode::InvalidValue, None));
            };
            let notified = notify(&ring.call, message_timeout);
            self.metrics
                .record(SessionOp::Notify, notified.is_ok(), started.elapsed());
            notified?;
        }
        // `Lost` では kick を読めたか不明なので ring は走査済み。処理が無ければ偽。
        Ok(done > 0 || kick == KickRead::Read)
    }

    /// ctrl 要求 1 件（`None` は長すぎて読まなかった要求）を処理する。ring・ゲストメモリには触れない。
    ///
    /// `MAP_BLOB` / `UNMAP_BLOB` は adapter の実行指示（[`ShmemOp`]）に従い frontend とやりとりする。応答を書き戻せない
    /// （`writable_len` が応答の最大長に満たない）要求は、frontend へ**送る前に**捨てる（送ってから捨てると frontend にだけ
    /// map が残る）。成功以外の結果は adapter を巻き戻す（資源表の map 状態も戻る）。
    fn process_ctrl(
        &mut self,
        req: Option<&[u8]>,
        writable_len: u64,
        sink: &mut dyn FnMut(&str),
    ) -> Processed {
        // 応答を書き戻せず捨てる場合に adapter の状態変更（CTX の作成・破棄、map 状態）を取り消すための控え。
        let adapter_before = self.adapter.clone();
        let Some(req) = req else {
            return Processed {
                response: CtrlResponse::new(None, RESP_ERR_INVALID_PARAMETER, &[]),
                log_line: log::rejected_line(None, QueryResult::InvalidParameter),
                submit: None,
                had_shmem: false,
                dropped: false,
                adapter_before,
            };
        };
        let h = self.adapter.handle_ctrl(req);
        let Some(op) = h.shmem else {
            // `h.submit`（受理した SUBMIT_3D の受け渡し点）は、応答を書き戻せた場合だけフックへ渡す
            // （`dropped` で adapter を巻き戻した要求の提出は、ゲストが ACK を見ていないので捨てる。#1602）。
            return Processed {
                response: h.response,
                log_line: h.log_line,
                submit: h.submit,
                had_shmem: false,
                dropped: false,
                adapter_before,
            };
        };
        let writable_ok = u64::try_from(op.max_response_len()).is_ok_and(|m| writable_len >= m);
        if !writable_ok {
            self.adapter = adapter_before.clone();
            return Processed {
                response: h.response,
                log_line: h.log_line,
                submit: None,
                had_shmem: false,
                dropped: true,
                adapter_before,
            };
        }
        let result = self.execute_shmem(&op, sink);
        if result != QueryResult::Ok {
            self.adapter = adapter_before.clone();
        }
        Processed {
            response: op.response(result),
            log_line: op.log_line(result),
            submit: None,
            had_shmem: true,
            dropped: false,
            adapter_before,
        }
    }

    /// 取り出した実メモリを（あれば）表へ戻して `result` を返す。
    fn restore_blob(&mut self, blob: Option<BlobMem>, result: QueryResult) -> QueryResult {
        if let Some(b) = blob {
            let _ = self.blobs.insert(b);
        }
        result
    }

    /// `MAP_BLOB` / `UNMAP_BLOB` の実体。frontend とのやりとりの結果を ctrl の結果語彙で返す。
    ///
    /// 共有メモリが未成立・frontend の失敗・期限切れ・切断は `Unspec`、memfd を作れないときは `OutOfMemory`。
    /// 失敗した MAP の新規 memfd は捨てる（UNMAP 後に残した memfd は保つ）。失敗した UNMAP は map 中のまま残す（frontend 側に map が残っているかもしれず、
    /// 区間を再利用させない。残った map は終了時の片づけ `release_blobs_at_end` が扱う。#1645）。channel の破損は `backend_exchange` が扱う。
    fn execute_shmem(&mut self, op: &ShmemOp, sink: &mut dyn FnMut(&str)) -> QueryResult {
        match op.kind {
            ShmemOpKind::Map => {
                if self
                    .state
                    .backend_channel(BackendRequestCode::ShmemMap)
                    .is_err()
                {
                    return QueryResult::Unspec;
                }
                // 再 MAP なら UNMAP 後も残した memfd を使う。無ければ新しく作る（空きが無ければ拒否）。
                self.blobs.prune(&self.adapter);
                let kept = self
                    .blobs
                    .take(op.res_id)
                    .filter(|b| !b.mapped && b.memfd.metadata().is_ok_and(|m| m.len() == op.len));
                if kept.is_none() && !self.blobs.has_free_slot() {
                    return QueryResult::Unspec;
                }
                let Ok(cfg) = host_visible_config() else {
                    return self.restore_blob(kept, QueryResult::Unspec);
                };
                let Ok(mapping) =
                    ShmemMapping::new(&cfg, device::SHM_ID_HOST_VISIBLE, op.shm_offset, op.len)
                else {
                    return self.restore_blob(kept, QueryResult::Unspec);
                };
                let Ok(req) = ShmemMapRequest::new(mapping, 0) else {
                    return self.restore_blob(kept, QueryResult::Unspec);
                };
                let reused = kept.is_some();
                let memfd = match kept {
                    Some(b) => b.memfd,
                    None => match create_memfd(BLOB_MEMFD_NAME, op.len) {
                        Ok(f) => f,
                        Err(_) => return QueryResult::OutOfMemory,
                    },
                };
                let blob = BlobMem {
                    res_id: op.res_id,
                    memfd,
                    mapping,
                    mapped: false,
                };
                if self.shmem_map(&req, blob.memfd.as_fd(), sink).is_err() {
                    // 失敗した MAP でも再利用できる memfd（内容を持つ）は unmapped で残す。新規の memfd は捨てる。
                    if reused {
                        let _ = self.blobs.insert(blob);
                    }
                    return QueryResult::Unspec;
                }
                let blob = BlobMem {
                    mapped: true,
                    ..blob
                };
                if let Err(blob) = self.blobs.insert(blob) {
                    // 事前に空きを確かめているので到達しない。到達したら frontend に map が残るため UNMAP で戻す。
                    let _ = self.shmem_unmap(&blob.mapping, sink);
                    return QueryResult::Unspec;
                }
                QueryResult::Ok
            }
            ShmemOpKind::Unmap => {
                let Some(mapping) = self.blobs.mapped_of(op.res_id) else {
                    return QueryResult::Unspec;
                };
                if self.shmem_unmap(&mapping, sink).is_err() {
                    return QueryResult::Unspec;
                }
                // memfd は閉じない（再 MAP で同じ内容を渡す）。`UNREF` / セッション終了で閉じる。
                self.blobs.mark_unmapped(op.res_id);
                QueryResult::Ok
            }
        }
    }
}

/// [`read_kick`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KickRead {
    /// counter を読めた。
    Read,
    /// 相手が先に読み切っていて counter が無かった（現在は run_bounded が期限切れを `Lost` に畳むため返らない）。
    Drained,
    /// 補助スレッドが期限内に終わらなかった（相手が読み切ってフラグも落としている等）。読めたか不明なので、
    /// 呼び出し側は ring を走査する（空なら何も起きない）。
    Lost,
}

/// 補助スレッド（fd I/O 用・unblock 用の合計）のプロセス全体での同時存在数の上限（REPAIR-5）。セッション 1 本は高々
/// 数本しか持たないので、これを超えるのは接続の繰り返しで残存スレッドが蓄積している異常時で、新規の I/O を拒否する。
const MAX_LIVE_WORKERS: usize = 64;

/// 生存中の補助スレッド数。[`WorkerSlot`] の取得で増え、`Drop`（スレッド終了時）で減る。
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// 補助スレッド 1 本分の枠。スレッドのクロージャへ move し、スレッドの終了（またはクロージャの破棄）で解放する。
struct WorkerSlot<'a>(&'a AtomicUsize);

impl<'a> WorkerSlot<'a> {
    /// `live` が `max` 未満なら枠を取る。上限なら `None`（fail-closed）。
    fn acquire(live: &'a AtomicUsize, max: usize) -> Option<Self> {
        // fetch_update は toolchain により deprecated（try_update へ改名）になるため CAS ループで書く。
        let mut n = live.load(Ordering::Acquire);
        loop {
            if n >= max {
                return None;
            }
            match live.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self(live)),
                Err(cur) => n = cur,
            }
        }
    }
}

impl Drop for WorkerSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn global_slot() -> Option<WorkerSlot<'static>> {
    WorkerSlot::acquire(&LIVE_WORKERS, MAX_LIVE_WORKERS)
}

/// 補助スレッドで `interest` の readiness を最大 `wait_for` 待ってから `op` を実行し、`wait_for` 以内の結果を返す。
/// 補助スレッドは複製 fd を `O_NONBLOCK`（`FIONBIO`）にして、期限つきの poll → 非ブロッキング `op` を期限までループする。
/// `op` が `WouldBlock`（poll 後に相手が counter を読み切った・満たした競合）なら残り時間で poll からやり直し、期限で
/// `io::ErrorKind::TimedOut` を返して自力終了する。blocking I/O に入らないので、共有フラグを変えない相手でも
/// スレッドと [`WorkerSlot`] は期限＋poll 1 回分の遅延以内に必ず回収される（REPAIR-5）。
/// `O_NONBLOCK` は open file description 共有なので、フラグを同時に落とし続ける敵対的な相手に対しては
/// poll 後の隙間が理論上残る（その場合も [`MAX_LIVE_WORKERS`] で数を抑え、受け側は `recv_timeout` で期限切れにする）。
/// 期限切れ（結果が来ない）は `Ok(None)`。
fn run_bounded<T: Send + 'static>(
    file: &File,
    interest: sys::Interest,
    wait_for: Duration,
    op: impl Fn(&File) -> io::Result<T> + Send + 'static,
) -> Result<Option<io::Result<T>>, SessionError> {
    let failed = || SessionError::new(SessionErrorCode::FdSetupFailed, None);
    let Some(slot) = global_slot() else {
        return Err(SessionError::new(SessionErrorCode::WorkerLimit, None));
    };
    let dup = file.try_clone().map_err(|_| failed())?;
    // `FIONBIO` を safe に発行するため、別の複製を `UnixStream` として包む（`set_nonblocking` は fd の種別に依らない ioctl）。
    let nb = UnixStream::from(OwnedFd::from(file.try_clone().map_err(|_| failed())?));
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("venus-jig-fd-io".into())
        .spawn(move || {
            let _slot = slot;
            let deadline = Instant::now().checked_add(wait_for);
            let result = loop {
                let left = match deadline {
                    Some(d) => d.saturating_duration_since(Instant::now()),
                    None => wait_for,
                };
                // EINTR は残り時間で再試行する（シグナルで生きたセッションを TimedOut にしない）。
                let ready = match sys::wait_fd(dup.as_fd(), interest, left) {
                    Ok(ready) => ready,
                    Err(sys::SysError::Interrupted(_)) if !left.is_zero() => continue,
                    Err(sys::SysError::Interrupted(_)) => false,
                    Err(_) => break Err(io::Error::from(ErrorKind::Other)),
                };
                if !ready {
                    break Err(io::Error::from(ErrorKind::TimedOut));
                }
                // poll の直後に毎回立て直してから非ブロッキングで実行する。
                if nb.set_nonblocking(true).is_err() {
                    break Err(io::Error::from(ErrorKind::Other));
                }
                match op(&dup) {
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        if deadline.is_some_and(|d| Instant::now() >= d) {
                            break Err(io::Error::from(ErrorKind::TimedOut));
                        }
                        // busy loop を避けて短く待ってから poll へ戻る。
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    other => break other,
                }
            };
            // 受け側が期限切れで捨てていれば送信は失敗するが、結果が要らないので無視する。
            let _ = tx.send(result);
        })
        .map_err(|_| failed())?;
    // 補助スレッドの期限（`wait_for`）より少し長く待ち、通常は補助スレッド自身の TimedOut を受け取る。
    match rx.recv_timeout(wait_for.saturating_add(WORKER_GRACE)) {
        Ok(r) => Ok(Some(r)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(failed()),
    }
}

/// 補助スレッドの結果を待つときに `wait_for` へ足す余裕。
const WORKER_GRACE: Duration = Duration::from_millis(50);

/// kick の eventfd から counter（8 バイト）を読む。読み取りは補助スレッドに任せ（readiness を期限つきで待ち、非ブロッキングで
/// 読む）、`wait_for` 以内に読めなければ `Lost`（読めたか不明なので呼び出し側は ring を走査する。空なら何も起きない）。
fn read_kick(kick: &File, wait_for: Duration) -> Result<KickRead, SessionError> {
    let result = run_bounded(kick, sys::Interest::Readable, wait_for, |f| {
        let mut counter = [0u8; 8];
        let mut r = f;
        r.read(&mut counter).map(|n| (n, counter))
    })?;
    match result {
        None => Ok(KickRead::Lost),
        Some(Err(e)) if e.kind() == ErrorKind::TimedOut => Ok(KickRead::Lost),
        Some(Ok((0, _))) => Err(SessionError::new(SessionErrorCode::KickClosed, None)),
        Some(Ok((8, _))) => Ok(KickRead::Read),
        Some(Ok(_)) => Err(SessionError::new(SessionErrorCode::InvalidKick, None)),
        Some(Err(_)) => Err(SessionError::new(SessionErrorCode::InvalidKick, None)),
    }
}

/// call の eventfd へ 1 を書いてゲストへ通知する。書き込みは補助スレッドに任せ、書き込み可能になるのを期限つきの poll で
/// 待ってから非ブロッキングで書く。満杯の socket など書けない fd でも補助スレッドは期限で自力終了し、`timeout` で `TIMEOUT` になる。
fn notify(call: &File, timeout: Duration) -> Result<(), SessionError> {
    let result = run_bounded(call, sys::Interest::Writable, timeout, |f| {
        let mut w = f;
        w.write(&1u64.to_le_bytes())
    })?;
    match result {
        None => Err(SessionError::new(SessionErrorCode::Timeout, None)),
        Some(Err(e)) if e.kind() == ErrorKind::TimedOut => {
            Err(SessionError::new(SessionErrorCode::Timeout, None))
        }
        Some(Ok(8)) => Ok(()),
        Some(Ok(_)) | Some(Err(_)) => Err(SessionError::new(SessionErrorCode::CallFailed, None)),
    }
}

#[cfg(test)]
mod backend_req_tests;
#[cfg(test)]
mod map_blob_tests;
#[cfg(test)]
mod tests;
