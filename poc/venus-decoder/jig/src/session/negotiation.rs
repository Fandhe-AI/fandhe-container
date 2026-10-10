//! vhost-user ネゴシエーションと ring 設定の状態遷移（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! I/O を持たない状態機械。[`super::run`] が受信・復号した要求を [`State::handle`] へ渡し、返った応答（`GET_*` のみ）を
//! 送る。順序のゲートは「本当の依存関係」だけで判定し、一本道の順序は強制しない（QEMU と crosvm で `SET_OWNER` /
//! `GET_PROTOCOL_FEATURES` の位置が違うため。根拠は `docs/design/venus-decoder-poc.md` 10.8）。違反は `OUT_OF_ORDER`。
//! ring は [`Ring::Setup`]（設定中）と [`Ring::Running`]（ADDR・KICK・CALL・ENABLE がそろった）の enum で表し、
//! 「実行中なのに設定が欠けている」状態を型として作れないようにする。
//! 共有メモリ（host-visible。GPU-6・TASK-172 F5.2b.2・#1641）: protocol feature の SHMEM を確定した接続だけ `GET_SHMEM_CONFIG` に
//! 応じ（shmid 1 を 1 個、`device::HOST_VISIBLE_SHM_SIZE`）、BACKEND_REQ を確定した接続だけ `SET_BACKEND_REQ_FD` の UDS を 1 回保持する。
//! 保持した fd は [`State`] の drop（セッションの終了。正常もエラーも）で閉じる。確定の食い違いは [`State::host_visible`] が理由つきで表し、
//! 拒否はしない（寛容。`MAP_BLOB` の ERR 化は #1643）。
//! backend 要求の送信（F5.2b.3・#1642）: 送ってよいかの判定は [`State::backend_channel`]、失敗後の閉鎖は
//! [`State::mark_backend_broken`]（`BackendChannel::Broken`。同期が崩れたストリームを使い続けない）。送受信は `super::backend_req`。
//! 未実装（REPAIR-3）: `SET_CONFIG`・`VRING_NOFD`（polling）・inflight・cursorq（ring 1）の要求処理、
//! `SET_BACKEND_REQ_FD` の fd が SOCK_STREAM かの検査（`getsockopt(SO_TYPE)` は `sys` の承認範囲外の unsafe になる。種類違いは #1642 の
//! 期限つき送受信で `TRANSPORT` か `TIMEOUT` になる）。

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;

use super::backend_req::{BackendReqCause, BackendReqError, BackendReqErrorCode};
use super::error::{SessionError, SessionErrorCode};
use crate::device;
use crate::vhost_user::backend_req::BackendRequestCode;
use crate::vhost_user::guest_memory::GuestMemory;
use crate::vhost_user::{
    ConfigPayload, F_PROTOCOL_FEATURES, PROTOCOL_F_BACKEND_REQ, PROTOCOL_F_CONFIG, PROTOCOL_F_MQ,
    PROTOCOL_F_REPLY_ACK, PROTOCOL_F_SHMEM, Reply, Request, RequestCode, ShmemConfig, ShmemRegion,
    VringAddr, VringState,
};
use crate::virtqueue::{MAX_QUEUE_SIZE, QueueConfig, SplitQueue};

/// `GET_FEATURES` で広告する値（治具の virtio feature と `PROTOCOL_FEATURES`）。
pub(crate) const OFFERED_FEATURES: u64 = device::FEATURES | F_PROTOCOL_FEATURES;
/// `SET_FEATURES` で必須とするビット。Mesa venus は VIRGL・RESOURCE_BLOB・CONTEXT_INIT が無いと capset 取得前に中止し、
/// bit 30 が無いと `SET_VRING_ENABLE` の意味が変わるため、広告した全ビットを必須にして fail-closed にする。
pub(crate) const REQUIRED_FEATURES: u64 = OFFERED_FEATURES;
/// `GET_PROTOCOL_FEATURES` で広告する値。
pub(crate) const OFFERED_PROTOCOL: u64 = PROTOCOL_F_MQ
    | PROTOCOL_F_REPLY_ACK
    | PROTOCOL_F_BACKEND_REQ
    | PROTOCOL_F_CONFIG
    | PROTOCOL_F_SHMEM;
/// ring の本数（0 = controlq、1 = cursorq）。
pub(crate) const NUM_RINGS: usize = 2;

/// 要求に添付されるべき fd の個数（`SET_MEM_TABLE` は領域数、NOFD でない kick / call と `SET_BACKEND_REQ_FD` は 1、他は 0）。
pub(crate) fn expected_fds(req: &Request) -> usize {
    match req {
        Request::SetMemTable(t) => t.regions().len(),
        Request::SetVringKick(f) | Request::SetVringCall(f) => usize::from(!f.no_fd),
        Request::SetBackendReqFd => 1,
        _ => 0,
    }
}

/// feature の照合。広告していないビットは `FEATURE_NOT_OFFERED`、必須ビットの欠落は `REQUIRED_FEATURE_MISSING`。
pub(crate) fn check_features(acked: u64) -> Result<(), SessionErrorCode> {
    if acked & !OFFERED_FEATURES != 0 {
        return Err(SessionErrorCode::FeatureNotOffered);
    }
    if acked & REQUIRED_FEATURES != REQUIRED_FEATURES {
        return Err(SessionErrorCode::RequiredFeatureMissing);
    }
    Ok(())
}

/// 設定中の ring。
#[derive(Debug, Default)]
pub(crate) struct RingSetup {
    num: Option<u32>,
    base: u16,
    cfg: Option<QueueConfig>,
    kick: Option<File>,
    call: Option<File>,
    enabled: bool,
}

/// 実行中の ring（kick / call の fd と split virtqueue を必ず持つ）。
#[derive(Debug)]
pub(crate) struct RunningRing {
    pub(crate) queue: SplitQueue,
    pub(crate) kick: File,
    pub(crate) call: File,
    num: u32,
    cfg: QueueConfig,
}

impl RunningRing {
    /// キューサイズ（1 回の kick で処理する要求数の上限）。
    pub(crate) fn depth(&self) -> u32 {
        self.num
    }
}

#[derive(Debug)]
pub(crate) enum Ring {
    Setup(RingSetup),
    Running(RunningRing),
}

impl Default for Ring {
    fn default() -> Self {
        Self::Setup(RingSetup::default())
    }
}

/// backend 要求用 UDS の状態（GPU-6・TASK-172 F5.2b.3・#1642）。
///
/// 期限切れ・切断・応答の形式不正の後はストリームの同期が崩れ、遅れて届く応答が次の要求の応答に見える。そこで
/// `Broken` にして stream を閉じ、以後送らない（fail-closed）。`Broken` からは戻らない。
#[derive(Debug, Default)]
enum BackendChannel {
    /// `SET_BACKEND_REQ_FD` がまだ来ていない。
    #[default]
    Missing,
    /// 使える。
    Open(UnixStream),
    /// 同期が崩れたため閉じた。
    Broken,
}

/// セッション 1 本分のネゴシエーション状態。`GuestMemory` を持つので `!Send`。
#[derive(Debug, Default)]
pub(crate) struct State {
    owner: bool,
    features: Option<u64>,
    protocol_queried: bool,
    protocol: Option<u64>,
    mem: Option<GuestMemory>,
    rings: [Ring; NUM_RINGS],
    /// `SET_BACKEND_REQ_FD` で受けた backend 要求用の UDS（接続の間は保持し、`State` の drop で閉じる）。
    backend_req: BackendChannel,
    /// `GET_SHMEM_CONFIG` に答えたか（frontend が領域を知っているか）。
    shmem_config_sent: bool,
}

/// host-visible 共有メモリが使える状態か（確定の食い違いの理由つき。GPU-6・TASK-172 F5.2b.2・#1641）。
///
/// 真偽値にしないのは、使えない理由をログで #725 の実機確認に渡し、#1643 が `MAP_BLOB` の拒否を理由別に扱えるようにするため。
/// 判定はこの順で、毎回その時点の確定値から求める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostVisible {
    /// SHMEM・BACKEND_REQ を確定し、領域の大きさを答え、backend 要求用ソケットを保持している。
    Ready,
    /// 使えない。
    Unavailable(HostVisibleUnavailable),
}

/// [`HostVisible::Unavailable`] の理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostVisibleUnavailable {
    /// SHMEM を確定していない。
    ShmemNotNegotiated,
    /// `GET_SHMEM_CONFIG` にまだ答えていない（frontend は領域を知らない）。
    ConfigNotQueried,
    /// SHMEM は確定したが BACKEND_REQ を確定していない。
    BackendReqNotNegotiated,
    /// BACKEND_REQ は確定したが `SET_BACKEND_REQ_FD` が来ていない。
    BackendChannelMissing,
    /// backend 要求の送受信に失敗して channel を閉じた（#1642。同期が崩れたため以後送らない）。
    BackendChannelBroken,
}

impl HostVisible {
    /// ログに出す固定語彙。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unavailable(HostVisibleUnavailable::ShmemNotNegotiated) => "shmem_not_negotiated",
            Self::Unavailable(HostVisibleUnavailable::ConfigNotQueried) => "config_not_queried",
            Self::Unavailable(HostVisibleUnavailable::BackendReqNotNegotiated) => {
                "backend_req_not_negotiated"
            }
            Self::Unavailable(HostVisibleUnavailable::BackendChannelMissing) => {
                "backend_channel_missing"
            }
            Self::Unavailable(HostVisibleUnavailable::BackendChannelBroken) => {
                "backend_channel_broken"
            }
        }
    }
}

/// `GET_SHMEM_CONFIG` の応答（shmid 1 を 1 個、大きさは `device::HOST_VISIBLE_SHM_SIZE`）。
fn host_visible_config() -> Result<ShmemConfig, SessionError> {
    ShmemConfig::new(&[ShmemRegion {
        id: device::SHM_ID_HOST_VISIBLE,
        size: device::HOST_VISIBLE_SHM_SIZE,
    }])
    .map_err(SessionError::from)
}

/// `SET_BACKEND_REQ_FD` の fd を、ソケットかつ AF_UNIX と確かめて `UnixStream` にする。種類違い（memfd・pipe・TCP / UDP）は
/// `INVALID_BACKEND_REQ_FD`。std の safe API だけで確かめる（`fstat` と `getsockname`。std の `SocketAddr` は AF_UNIX 以外を拒否する）。
fn backend_req_stream(fd: OwnedFd, code: RequestCode) -> Result<UnixStream, SessionError> {
    let bad = || fail(SessionErrorCode::InvalidBackendReqFd, code);
    let file = File::from(fd);
    if !file.metadata().map_err(|_| bad())?.file_type().is_socket() {
        return Err(bad());
    }
    let stream = UnixStream::from(OwnedFd::from(file));
    stream.local_addr().map_err(|_| bad())?;
    Ok(stream)
}

fn ooo(code: RequestCode) -> SessionError {
    SessionError::new(SessionErrorCode::OutOfOrder, Some(code.as_u32()))
}

fn fail(c: SessionErrorCode, code: RequestCode) -> SessionError {
    SessionError::new(c, Some(code.as_u32()))
}

fn ring_index(index: u32, code: RequestCode) -> Result<usize, SessionError> {
    usize::try_from(index)
        .ok()
        .filter(|i| *i < NUM_RINGS)
        .ok_or_else(|| fail(SessionErrorCode::InvalidVringIndex, code))
}

impl State {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// REPLY_ACK が確定済みなら真（NEED_REPLY への応答義務がある。#1639）。
    ///
    /// 呼び出し側は [`State::handle`] の**後**に判定する。NEED_REPLY つきの `SET_PROTOCOL_FEATURES` 自体にも応答するため
    /// で、失敗した `SET_PROTOCOL_FEATURES` は状態を変えないので直前の確定値で判定される。
    pub(crate) fn reply_ack(&self) -> bool {
        self.protocol.is_some_and(|p| p & PROTOCOL_F_REPLY_ACK != 0)
    }

    /// host-visible 共有メモリが使える状態か。ログ（セッション終了時）と #1643 の `MAP_BLOB` 判定の入口。
    pub(crate) fn host_visible(&self) -> HostVisible {
        let negotiated = |bit: u64| self.protocol.is_some_and(|p| p & bit != 0);
        let reason = if !negotiated(PROTOCOL_F_SHMEM) {
            HostVisibleUnavailable::ShmemNotNegotiated
        } else if !self.shmem_config_sent {
            HostVisibleUnavailable::ConfigNotQueried
        } else if !negotiated(PROTOCOL_F_BACKEND_REQ) {
            HostVisibleUnavailable::BackendReqNotNegotiated
        } else {
            match self.backend_req {
                BackendChannel::Missing => HostVisibleUnavailable::BackendChannelMissing,
                BackendChannel::Broken => HostVisibleUnavailable::BackendChannelBroken,
                BackendChannel::Open(_) => return HostVisible::Ready,
            }
        };
        HostVisible::Unavailable(reason)
    }

    /// backend 要求を送ってよいときだけ UDS を返す（#1642）。順序は固定: REPLY_ACK 未確定（`REPLY_ACK_NOT_NEGOTIATED`）→
    /// host-visible 未成立（`HOST_VISIBLE_UNAVAILABLE`。理由は `cause`）。`Ready` は SHMEM の確定・`GET_SHMEM_CONFIG` への
    /// 回答・ソケットの保持をまとめて満たす。
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "#1643 の ctrl（MAP_BLOB / UNMAP_BLOB）から呼ぶ")
    )]
    pub(crate) fn backend_channel(
        &self,
        request: BackendRequestCode,
    ) -> Result<&UnixStream, BackendReqError> {
        if !self.reply_ack() {
            return Err(BackendReqError::new(
                BackendReqErrorCode::ReplyAckNotNegotiated,
                request,
            ));
        }
        if let HostVisible::Unavailable(why) = self.host_visible() {
            return Err(
                BackendReqError::new(BackendReqErrorCode::HostVisibleUnavailable, request)
                    .with_cause(BackendReqCause::Unavailable(why)),
            );
        }
        match &self.backend_req {
            BackendChannel::Open(s) => Ok(s),
            _ => Err(BackendReqError::new(
                BackendReqErrorCode::HostVisibleUnavailable,
                request,
            )),
        }
    }

    /// 送受信の失敗後に channel を閉じる（stream を drop する）。
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "#1643 の ctrl（MAP_BLOB / UNMAP_BLOB）から呼ぶ")
    )]
    pub(crate) fn mark_backend_broken(&mut self) {
        self.backend_req = BackendChannel::Broken;
    }

    fn any_running(&self) -> bool {
        self.rings.iter().any(|r| matches!(r, Ring::Running(_)))
    }

    fn setup_mut(&mut self, idx: usize, code: RequestCode) -> Result<&mut RingSetup, SessionError> {
        match self.rings.get_mut(idx) {
            Some(Ring::Setup(s)) => Ok(s),
            _ => Err(ooo(code)),
        }
    }

    /// ctrl キュー（ring 0）が実行中なら、その ring とゲストメモリを返す。
    pub(crate) fn ctrl_parts(&mut self) -> Option<(&mut RunningRing, &GuestMemory)> {
        let mem = self.mem.as_ref()?;
        match self.rings.get_mut(0)? {
            Ring::Running(r) => Some((r, mem)),
            Ring::Setup(_) => None,
        }
    }

    /// ADDR・KICK・CALL・ENABLE(1) がそろった ring を実行状態へ移す。初期の used_idx は base とする
    /// （新規開始では 0。inflight は扱わない割り切り）。
    fn try_start(&mut self, idx: usize) {
        let Some(ring) = self.rings.get_mut(idx) else {
            return;
        };
        *ring = match std::mem::take(ring) {
            Ring::Setup(RingSetup {
                num: Some(num),
                base,
                cfg: Some(cfg),
                kick: Some(kick),
                call: Some(call),
                enabled: true,
            }) => Ring::Running(RunningRing {
                queue: SplitQueue::new(cfg, base, base),
                kick,
                call,
                num,
                cfg,
            }),
            other => other,
        };
    }

    /// ring を設定中へ戻し、`last_avail`（停止中なら base）を返す。`keep_fds` が偽なら kick / call を閉じる。
    fn stop(&mut self, idx: usize, keep_fds: bool) -> u16 {
        let Some(ring) = self.rings.get_mut(idx) else {
            return 0;
        };
        let (next, base) = match std::mem::take(ring) {
            Ring::Running(r) => {
                let base = r.queue.last_avail();
                let setup = RingSetup {
                    num: Some(r.num),
                    base,
                    cfg: Some(r.cfg),
                    kick: keep_fds.then_some(r.kick),
                    call: keep_fds.then_some(r.call),
                    enabled: false,
                };
                (Ring::Setup(setup), base)
            }
            Ring::Setup(mut s) => {
                if !keep_fds {
                    s.kick = None;
                    s.call = None;
                }
                s.enabled = false;
                let base = s.base;
                (Ring::Setup(s), base)
            }
        };
        *ring = next;
        base
    }

    /// 要求 1 件を処理する。`fds` は添付 fd（個数は呼び出し側が `expected_fds` で照合済み）。
    /// `GET_*` には応答を返し、`SET_*` は `None`。
    pub(crate) fn handle(
        &mut self,
        req: Request,
        fds: Vec<OwnedFd>,
    ) -> Result<Option<Reply>, SessionError> {
        let code = req.code();
        match req {
            Request::GetFeatures => Ok(Some(Reply::Features(OFFERED_FEATURES))),
            Request::GetProtocolFeatures => {
                self.protocol_queried = true;
                Ok(Some(Reply::ProtocolFeatures(OFFERED_PROTOCOL)))
            }
            Request::SetOwner => {
                if self.owner {
                    return Err(ooo(code));
                }
                self.owner = true;
                Ok(None)
            }
            Request::SetProtocolFeatures(v) => {
                if !self.protocol_queried {
                    return Err(ooo(code));
                }
                if v & !OFFERED_PROTOCOL != 0 {
                    return Err(fail(SessionErrorCode::FeatureNotOffered, code));
                }
                self.protocol = Some(v);
                Ok(None)
            }
            Request::GetQueueNum => {
                if self.protocol.is_none_or(|p| p & PROTOCOL_F_MQ == 0) {
                    return Err(ooo(code));
                }
                Ok(Some(Reply::QueueNum(NUM_RINGS as u64)))
            }
            Request::GetConfig(c) => {
                if self.protocol.is_none_or(|p| p & PROTOCOL_F_CONFIG == 0) {
                    return Err(ooo(code));
                }
                Ok(Some(config_reply(&c)?))
            }
            Request::SetConfig(_) => Err(fail(SessionErrorCode::UnsupportedRequest, code)),
            Request::GetShmemConfig => {
                if self.protocol.is_none_or(|p| p & PROTOCOL_F_SHMEM == 0) {
                    return Err(ooo(code));
                }
                self.shmem_config_sent = true;
                Ok(Some(Reply::ShmemConfig(host_visible_config()?)))
            }
            Request::SetBackendReqFd => {
                // features の bit 30 や owner は要求しない（crosvm は SET_FEATURES より前に送る。ゲートは本当の依存だけ）。
                if self
                    .protocol
                    .is_none_or(|p| p & PROTOCOL_F_BACKEND_REQ == 0)
                {
                    return Err(ooo(code));
                }
                // 2 回目は拒否（fail-closed）。置き換えを許すと #1642 で送信中の要求と応答がずれうる。
                if !matches!(self.backend_req, BackendChannel::Missing) {
                    return Err(ooo(code));
                }
                let mut it = fds.into_iter();
                let (Some(fd), None) = (it.next(), it.next()) else {
                    return Err(fail(SessionErrorCode::FdCountMismatch, code));
                };
                self.backend_req = BackendChannel::Open(backend_req_stream(fd, code)?);
                Ok(None)
            }
            Request::SetFeatures(v) => {
                if !self.owner || self.any_running() {
                    return Err(ooo(code));
                }
                check_features(v).map_err(|c| fail(c, code))?;
                self.features = Some(v);
                Ok(None)
            }
            Request::SetMemTable(table) => {
                if !self.owner || self.features.is_none() || self.any_running() {
                    return Err(ooo(code));
                }
                // 古い表を先に drop する（backing の二重占有を避ける）。送り直しでは ring のアドレス検証結果も無効になる。
                self.mem = None;
                for r in &mut self.rings {
                    if let Ring::Setup(s) = r {
                        s.cfg = None;
                        s.enabled = false;
                    }
                }
                let mem = GuestMemory::from_table(&table, fds)
                    .map_err(|e| SessionError::transport(e, Some(code.as_u32())))?;
                self.mem = Some(mem);
                Ok(None)
            }
            Request::SetVringNum(VringState { index, num }) => {
                let idx = ring_index(index, code)?;
                if !self.owner {
                    return Err(ooo(code));
                }
                // virtqueue と同じ条件（0 以外・2 の冪・上限以下）。ここで弾き、後段の `QueueConfig::new` に頼らない。
                if num == 0 || num > MAX_QUEUE_SIZE || !num.is_power_of_two() {
                    return Err(fail(SessionErrorCode::InvalidValue, code));
                }
                let setup = self.setup_mut(idx, code)?;
                setup.num = Some(num);
                // サイズを変えたら旧アドレスの検証結果は無効。SET_VRING_ADDR の再送と ENABLE をやり直させる。
                setup.cfg = None;
                setup.enabled = false;
                Ok(None)
            }
            Request::SetVringBase(VringState { index, num }) => {
                let idx = ring_index(index, code)?;
                if !self.owner {
                    return Err(ooo(code));
                }
                let base =
                    u16::try_from(num).map_err(|_| fail(SessionErrorCode::InvalidValue, code))?;
                self.setup_mut(idx, code)?.base = base;
                Ok(None)
            }
            Request::SetVringAddr(addr) => {
                let idx = ring_index(addr.index, code)?;
                self.set_addr(idx, &addr, code)?;
                self.try_start(idx);
                Ok(None)
            }
            Request::SetVringKick(f) | Request::SetVringCall(f) => {
                let idx = ring_index(u32::from(f.index), code)?;
                if self.mem.is_none() {
                    return Err(ooo(code));
                }
                if f.no_fd {
                    return Err(fail(SessionErrorCode::NofdUnsupported, code));
                }
                let mut it = fds.into_iter();
                let (Some(fd), None) = (it.next(), it.next()) else {
                    return Err(fail(SessionErrorCode::FdCountMismatch, code));
                };
                let file = File::from(fd);
                let setup = self.setup_mut(idx, code)?;
                if code == RequestCode::SetVringKick {
                    setup.kick = Some(file);
                } else {
                    setup.call = Some(file);
                }
                self.try_start(idx);
                Ok(None)
            }
            Request::SetVringEnable(VringState { index, num }) => {
                let idx = ring_index(index, code)?;
                let proto_ok = self.features.is_some_and(|f| f & F_PROTOCOL_FEATURES != 0);
                let has_cfg = match self.rings.get(idx) {
                    Some(Ring::Setup(s)) => s.cfg.is_some(),
                    Some(Ring::Running(_)) => true,
                    None => false,
                };
                if !proto_ok || !has_cfg {
                    return Err(ooo(code));
                }
                match num {
                    1 => {
                        if let Some(Ring::Setup(s)) = self.rings.get_mut(idx) {
                            s.enabled = true;
                        }
                        self.try_start(idx);
                    }
                    0 => {
                        self.stop(idx, true);
                    }
                    _ => return Err(fail(SessionErrorCode::InvalidValue, code)),
                }
                Ok(None)
            }
            Request::GetVringBase(VringState { index, .. }) => {
                let idx = ring_index(index, code)?;
                let base = self.stop(idx, false);
                Ok(Some(Reply::VringBase(VringState {
                    index,
                    num: u32::from(base),
                })))
            }
        }
    }

    fn set_addr(
        &mut self,
        idx: usize,
        addr: &VringAddr,
        code: RequestCode,
    ) -> Result<(), SessionError> {
        let Some(mem) = self.mem.as_ref() else {
            return Err(ooo(code));
        };
        let setup = match self.rings.get_mut(idx) {
            Some(Ring::Setup(s)) => s,
            _ => return Err(ooo(code)),
        };
        let Some(num) = setup.num else {
            return Err(ooo(code));
        };
        let cfg = QueueConfig::new(num, addr, mem)
            .map_err(|e| SessionError::virtqueue(e, Some(code.as_u32())))?;
        setup.cfg = Some(cfg);
        Ok(())
    }
}

/// `GET_CONFIG` の応答。範囲外（`offset + size > 16`）は仕様どおりの空ペイロード（`ConfigError`）で、セッションは続ける。
fn config_reply(c: &ConfigPayload) -> Result<Reply, SessionError> {
    let code = RequestCode::GetConfig;
    let full = device::config_bytes();
    let range = usize::try_from(c.offset())
        .ok()
        .and_then(|off| Some(off..off.checked_add(c.data().len())?))
        .and_then(|r| full.get(r));
    match range {
        Some(slice) => Ok(Reply::Config(
            ConfigPayload::new(code, c.offset(), c.flags(), slice).map_err(SessionError::from)?,
        )),
        None => Ok(Reply::ConfigError),
    }
}
