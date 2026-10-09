//! vhost-user ネゴシエーションと ring 設定の状態遷移（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! I/O を持たない状態機械。[`super::run`] が受信・復号した要求を [`State::handle`] へ渡し、返った応答（`GET_*` のみ）を
//! 送る。順序のゲートは「本当の依存関係」だけで判定し、一本道の順序は強制しない（QEMU と crosvm で `SET_OWNER` /
//! `GET_PROTOCOL_FEATURES` の位置が違うため。根拠は `docs/design/venus-decoder-poc.md` 10.8）。違反は `OUT_OF_ORDER`。
//! ring は [`Ring::Setup`]（設定中）と [`Ring::Running`]（ADDR・KICK・CALL・ENABLE がそろった）の enum で表し、
//! 「実行中なのに設定が欠けている」状態を型として作れないようにする。
//! 未実装（REPAIR-3）: `SET_CONFIG`・`VRING_NOFD`（polling）・REPLY_ACK・inflight・cursorq（ring 1）の要求処理。

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use super::error::{SessionError, SessionErrorCode};
use crate::device;
use crate::vhost_user::guest_memory::GuestMemory;
use crate::vhost_user::{
    ConfigPayload, F_PROTOCOL_FEATURES, PROTOCOL_F_CONFIG, PROTOCOL_F_MQ, Reply, Request,
    RequestCode, VringAddr, VringState,
};
use crate::virtqueue::{MAX_QUEUE_SIZE, QueueConfig, SplitQueue};

/// `GET_FEATURES` で広告する値（治具の virtio feature と `PROTOCOL_FEATURES`）。
pub(crate) const OFFERED_FEATURES: u64 = device::FEATURES | F_PROTOCOL_FEATURES;
/// `SET_FEATURES` で必須とするビット。Mesa venus は VIRGL・RESOURCE_BLOB・CONTEXT_INIT が無いと capset 取得前に中止し、
/// bit 30 が無いと `SET_VRING_ENABLE` の意味が変わるため、広告した全ビットを必須にして fail-closed にする。
pub(crate) const REQUIRED_FEATURES: u64 = OFFERED_FEATURES;
/// `GET_PROTOCOL_FEATURES` で広告する値。
pub(crate) const OFFERED_PROTOCOL: u64 = PROTOCOL_F_MQ | PROTOCOL_F_CONFIG;
/// ring の本数（0 = controlq、1 = cursorq）。
pub(crate) const NUM_RINGS: usize = 2;

/// 要求に添付されるべき fd の個数（`SET_MEM_TABLE` は領域数、NOFD でない kick / call は 1、他は 0）。
pub(crate) fn expected_fds(req: &Request) -> usize {
    match req {
        Request::SetMemTable(t) => t.regions().len(),
        Request::SetVringKick(f) | Request::SetVringCall(f) => usize::from(!f.no_fd),
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

/// セッション 1 本分のネゴシエーション状態。`GuestMemory` を持つので `!Send`。
#[derive(Debug, Default)]
pub(crate) struct State {
    owner: bool,
    features: Option<u64>,
    protocol_queried: bool,
    protocol: Option<u64>,
    mem: Option<GuestMemory>,
    rings: [Ring; NUM_RINGS],
}

fn ooo(code: RequestCode) -> SessionError {
    SessionError::new(SessionErrorCode::OutOfOrder, Some(code.as_u32()))
}

fn fail(c: SessionErrorCode, code: RequestCode) -> SessionError {
    SessionError::new(c, Some(code.as_u32()))
}

/// fd の `O_NONBLOCK` を立てる。フラグは open file description に属し、frontend が複製を持てば相手側からも落とせるため、
/// 受け取り時と I/O の直前に呼ぶ。`UnixStream::set_nonblocking` は `ioctl(FIONBIO)` で fd の種別に依らず効く
/// （eventfd でも使える）ので、複製を一時的に `UnixStream` として包んで呼ぶ（unsafe を増やさない）。
pub(super) fn force_nonblocking(f: &File) -> Result<(), SessionError> {
    let failed = || SessionError::new(SessionErrorCode::FdSetupFailed, None);
    let dup = f.try_clone().map_err(|_| failed())?;
    UnixStream::from(OwnedFd::from(dup))
        .set_nonblocking(true)
        .map_err(|_| failed())
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
                force_nonblocking(&file).map_err(|mut e| {
                    e.request = Some(code.as_u32());
                    e
                })?;
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
