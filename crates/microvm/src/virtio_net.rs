//! virtio-net デバイス（TASK-74.3.1・MVM-1・MVM-4・MS-7。OS 非依存・unsafe なし）。
//!
//! `virtio_mmio` の [`VirtioMmioTransport`](crate::virtio_mmio::VirtioMmioTransport) に包んで使う
//! [`VirtioDevice`] 実装。receiveq（キュー 0）と transmitq（キュー 1）の split virtqueue（`virtqueue`）を扱い、
//! ゲストが送るフレームを [`NetBackend::send`] へ、[`NetBackend::recv`] が返すフレームをゲストの受信バッファへ流す。
//! virtio-block（`virtio_block`）と同じ流儀で、トランスポート・ゲストメモリ・virtqueue は作り直さず再利用する。
//!
//! # 呼び出し契約
//! `KVM_RUN` の MMIO exit を振り分ける側（TASK-74.4.2 の `dispatch`）は、`QueueNotify(0)` で
//! [`VirtioNet::process_rx`]、`QueueNotify(1)` で [`VirtioNet::process_tx`]、`QueueStopped(i)` で
//! [`VirtioNet::stop_queue`] を呼ぶ。処理結果の `completed` が 1 以上なら
//! `raise_interrupt(InterruptReason::UsedBuffer)` を呼ぶ（割り込みの実配送は `crate::interrupt::complete_net_notify`。TASK-74.3.2・#881）。
//! リング破損は `Err` で返り、`Err` でも途中までの要求は used へ書かれ `used.idx` が進んでいることがある。
//! その内訳は [`VirtioNet::rx_stats_before_error`] / [`VirtioNet::tx_stats_before_error`] で取り、
//! `completed` が 1 以上なら `Err` でも `UsedBuffer` を上げる。壊れたチェーンは `last_avail` を進めないため、
//! 以後の呼び出しも同じ `Err` になる（停止・リセットの判断は呼び出し元が行う）。
//!
//! backend にフレームが届いたことを知らせるホスト側のイベントループ（ポーリング・eventfd）はまだ無い。
//! 呼び出し元は、ゲストの kick が無くても backend にフレームがあるときに `process_rx` を呼ぶ必要がある
//! （REPAIR-3。TASK-75 / TASK-117 で決める）。
//!
//! # 受信の保持と取りこぼし
//! 受信用のゲストバッファが無いとき、取り出したフレームは device が固定長の staging buffer に 1 フレームだけ保持し
//! （[`NetRxStats::waiting_for_buffer`]）、次の `process_rx` で配送する。無制限には溜めない。
//! 小さすぎるバッファに当たったフレームは捨てて、バッファは used len 0 で返す（ゲストのリングを止めない）。
//!
//! # 範囲外（REPAIR-3。将来仕様）
//! ctrl vq・マルチキュー・チェックサム / TSO / UFO オフロード・`MRG_RXBUF`・`STATUS`・`MTU`・`EVENT_IDX`・
//! `INDIRECT`・packed。TAP などの実 backend は起動フローの TASK-75 / TASK-117 で決める
//! （TAP の `TUNSETIFF` は `sys` の unsafe が要るため本モジュールでは扱わない）。
//! 割り込みの実配送（`KVM_IRQFD` / `ioeventfd`）は `crate::interrupt::complete_net_notify`（TASK-74.3.2・#881。実装済み）。
//!
//! # 準拠先
//! OASIS "Virtual I/O Device (VIRTIO) Version 1.2" の 5.1（Network Device。5.1.3 feature bits・
//! 5.1.4 device configuration layout・5.1.6 device operation）。待ちを持たない同期処理なので REPAIR-5 の
//! タイムアウトは不要。広告するのは `VIRTIO_NET_F_MAC` だけで、`VERSION_1` はトランスポートが加える。
//! 送信ヘッダの `flags` のうち `NEEDS_CSUM` と `gso_type != NONE` だけを拒否し（どちらも未合意のオフロード）、
//! その他のビットは無視する（受信側の意味しか持たないビットを含むため）。この寛容側の扱いは仕様書本文での
//! 再確認が済んでいない判断であり、厳格化が必要なら 5.1.6.2 を確かめて直す。
//!
//! # 外部入力の扱い
//! 記述子の内容・ヘッダ・フレーム長はゲストが決める非信頼入力。bounce / staging は
//! `NET_HDR_LEN + MAX_FRAME_LEN` の固定長を `new` で 1 回だけ確保し、ゲストが指定した長さでは確保しない。
//! 1 回の処理はキュー長で頭打ち。算術は checked 演算で行い、panic・添字アクセスを使わない。
//! ゲストへ書くのはヘッダ + フレームの長さだけで、bounce の残り（前のフレームの残骸）は書かない。

use std::collections::VecDeque;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestMemory, GuestMemoryBacking};
use crate::virtio_mmio::{FeatureBits, QueueConfig, VirtioDevice, VirtioDeviceType};
use crate::virtqueue::{Descriptor, DescriptorChain, SplitQueue};

/// feature: 設定空間の `mac` が有効（bit 5）。
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// 送信ヘッダの `flags`: チェックサム計算の依頼（CSUM を合意していないので拒否する）。
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
/// 送信ヘッダの `gso_type`: 分割なし。
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;

/// `virtio_net_hdr` の長さ（VERSION_1・HASH_REPORT 無し。`num_buffers` を含む 12 バイト）。
pub const NET_HDR_LEN: u32 = 12;
/// フレーム長の上限（Ethernet ヘッダ 14 + VLAN タグ 4 + MTU 1500。FCS は含まない）。
pub const MAX_FRAME_LEN: u32 = 1518;
/// フレーム長の下限（Ethernet ヘッダ）。
pub const MIN_FRAME_LEN: u32 = 14;
/// 各キューの最大長。
pub const QUEUE_MAX_SIZE: u16 = 256;
/// [`MemoryNetBackend`] の受信待ち・送信済みそれぞれの件数上限。
pub const MAX_MEMORY_FRAMES: usize = 256;

/// キュー 0: receiveq1。
const RX_QUEUE: u16 = 0;
/// キュー 1: transmitq1。
const TX_QUEUE: u16 = 1;
/// 受信でゲストへ書くヘッダ（全フィールド 0、`num_buffers = 1`。MRG_RXBUF 未合意）。
const RX_HEADER: [u8; NET_HDR_LEN as usize] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
const BUF_LEN: usize = (NET_HDR_LEN + MAX_FRAME_LEN) as usize;

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

/// ネットワークデバイスの実体。範囲検査は [`VirtioNet`] が済ませてから呼ぶ。
pub trait NetBackend {
    /// ゲストが送ったフレームを 1 つ渡す（長さは `MIN_FRAME_LEN..=MAX_FRAME_LEN`）。
    fn send(&mut self, frame: &[u8]) -> Result<(), MicrovmError>;
    /// 届いているフレームを 1 つ `buf` へ書いて長さを返す。待たない（届いていなければ `Ok(None)`）。
    ///
    /// 返す長さは `MIN_FRAME_LEN..=MAX_FRAME_LEN` かつ `buf.len()` 以下でなければならない
    /// （外れた値は [`VirtioNet`] が `rx_backend_error` として捨てる）。
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, MicrovmError>;
}

/// メモリ上の backend（試験と KVM を使わない用途）。
#[derive(Debug, Clone, Default)]
pub struct MemoryNetBackend {
    inbound: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl MemoryNetBackend {
    /// 空で作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// ゲストへ届けるフレームを積む。長さが範囲外なら `InvalidArgument`、満杯なら `ResourceExhausted`。
    pub fn push_inbound(&mut self, frame: &[u8]) -> Result<(), MicrovmError> {
        let len = u32::try_from(frame.len()).map_err(|_| invalid("invalid frame length"))?;
        if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&len) {
            return Err(invalid("invalid frame length"));
        }
        if self.inbound.len() >= MAX_MEMORY_FRAMES {
            return Err(MicrovmError::new(
                MicrovmErrorCode::ResourceExhausted,
                "inbound frame queue is full",
            ));
        }
        self.inbound.push_back(frame.to_vec());
        Ok(())
    }

    /// まだ配送されていない受信待ちの件数。
    pub fn inbound_len(&self) -> usize {
        self.inbound.len()
    }

    /// ゲストが送ったフレーム（古い順）。
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// 送信済みフレームを取り出して空にする。
    pub fn take_sent(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.sent)
    }
}

impl NetBackend for MemoryNetBackend {
    fn send(&mut self, frame: &[u8]) -> Result<(), MicrovmError> {
        if self.sent.len() >= MAX_MEMORY_FRAMES {
            return Err(MicrovmError::new(
                MicrovmErrorCode::ResourceExhausted,
                "sent frame buffer is full",
            ));
        }
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, MicrovmError> {
        let Some(frame) = self.inbound.front() else {
            return Ok(None);
        };
        let dst = buf
            .get_mut(..frame.len())
            .ok_or_else(|| invalid("receive buffer too small"))?;
        dst.copy_from_slice(frame);
        let n = frame.len();
        self.inbound.pop_front();
        Ok(Some(n))
    }
}

/// `process_tx` 1 回分の処理内訳（REPAIR-4: 真偽値にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetTxStats {
    /// used へ返したチェーンの数（捨てたものを含む）。
    pub completed: u32,
    /// backend へ渡せたフレームの数。
    pub sent: u32,
    /// 構造が不正（writable を含む・ヘッダ未満）で捨てた数。
    pub tx_malformed: u32,
    /// 合計バイト数が上限を超えて捨てた数。
    pub tx_dropped_oversize: u32,
    /// ヘッダが未合意のオフロード（NEEDS_CSUM・GSO）を要求して捨てた数。
    pub tx_invalid_header: u32,
    /// フレームが `MIN_FRAME_LEN` 未満で捨てた数。
    pub tx_invalid_frame: u32,
    /// backend の `send` が失敗して捨てた数。
    pub tx_backend_error: u32,
}

/// `process_rx` 1 回分の処理内訳。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetRxStats {
    /// used へ返したチェーンの数（malformed・小さすぎるバッファを含む）。
    pub completed: u32,
    /// フレームを書いて返した数。
    pub delivered: u32,
    /// 構造が不正（readable を含む）で len 0 のまま返した数。
    pub rx_malformed: u32,
    /// バッファが小さすぎてフレームを捨てた数。
    pub rx_dropped_buffer_too_small: u32,
    /// backend の `recv` の失敗・契約違反で捨てた（または抜けた）数。
    pub rx_backend_error: u32,
    /// 保持中のフレームがあるのに受信バッファが無く、次の kick を待っている。
    pub waiting_for_buffer: bool,
}

/// virtio-net デバイス。
#[derive(Debug)]
pub struct VirtioNet<B: NetBackend> {
    backend: B,
    mac: [u8; 6],
    rx_cfg: Option<QueueConfig>,
    tx_cfg: Option<QueueConfig>,
    rx_queue: Option<SplitQueue>,
    tx_queue: Option<SplitQueue>,
    /// 送信の bounce（ヘッダ + フレーム）。
    tx_buf: Vec<u8>,
    /// 受信の staging。先頭 `NET_HDR_LEN` バイトは常に `RX_HEADER`、その先がフレーム。
    rx_buf: Vec<u8>,
    /// staging が保持しているフレームの長さ。
    staged_len: Option<usize>,
    negotiated: FeatureBits,
    rx_aborted: NetRxStats,
    tx_aborted: NetTxStats,
}

impl<B: NetBackend> VirtioNet<B> {
    /// backend と MAC から作る。
    pub fn new(backend: B, mac: [u8; 6]) -> Self {
        let mut rx_buf = vec![0u8; BUF_LEN];
        if let Some(head) = rx_buf.get_mut(..RX_HEADER.len()) {
            head.copy_from_slice(&RX_HEADER);
        }
        Self {
            backend,
            mac,
            rx_cfg: None,
            tx_cfg: None,
            rx_queue: None,
            tx_queue: None,
            tx_buf: vec![0u8; BUF_LEN],
            rx_buf,
            staged_len: None,
            negotiated: FeatureBits::EMPTY,
            rx_aborted: NetRxStats::default(),
            tx_aborted: NetTxStats::default(),
        }
    }

    /// backend への参照。
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// backend への可変参照。
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// 設定空間で広告する MAC。
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// 直近の `process_rx` が `Err` を返した時点までの内訳。成功時は空。
    pub fn rx_stats_before_error(&self) -> NetRxStats {
        self.rx_aborted
    }

    /// 直近の `process_tx` が `Err` を返した時点までの内訳。成功時は空。
    pub fn tx_stats_before_error(&self) -> NetTxStats {
        self.tx_aborted
    }

    /// 指定キューの処理を止める（トランスポートの `QueueStopped(index)` で呼ぶ）。
    ///
    /// 0 は receiveq（保持中のフレームも捨てる）、1 は transmitq。範囲外の index は無視する。
    pub fn stop_queue(&mut self, index: u16) {
        match index {
            RX_QUEUE => {
                self.rx_cfg = None;
                self.rx_queue = None;
                self.staged_len = None;
            }
            TX_QUEUE => {
                self.tx_cfg = None;
                self.tx_queue = None;
            }
            _ => {}
        }
    }

    /// backend のフレームを受信バッファへ配送する（1 回に最大キュー長の回数）。
    ///
    /// activate 前・停止後は `FailedPrecondition`。リング破損は `Err`（`InvalidArgument`）。
    /// backend の失敗はゲストのリングを止めないため `Err` にせず `rx_backend_error` に数える。
    pub fn process_rx<M: GuestMemoryBacking>(
        &mut self,
        mem: &mut GuestMemory<M>,
    ) -> Result<NetRxStats, MicrovmError> {
        self.rx_aborted = NetRxStats::default();
        let mut queue = take_queue(
            &mut self.rx_queue,
            self.rx_cfg,
            mem,
            "net receive queue is not active",
        )?;
        let mut stats = NetRxStats::default();
        let result = self.drain_rx(&mut queue, mem, &mut stats);
        self.rx_queue = Some(queue);
        match result {
            Ok(()) => Ok(stats),
            Err(e) => {
                self.rx_aborted = stats;
                Err(e)
            }
        }
    }

    fn drain_rx<M: GuestMemoryBacking>(
        &mut self,
        queue: &mut SplitQueue,
        mem: &mut GuestMemory<M>,
        stats: &mut NetRxStats,
    ) -> Result<(), MicrovmError> {
        for _ in 0..queue.size() {
            if self.staged_len.is_none() && !self.fetch_frame(stats) {
                break;
            }
            let Some(frame_len) = self.staged_len else {
                // backend の契約違反で捨てた。次の反復で取り直す（反復回数はキュー長で頭打ち）。
                continue;
            };
            let Some(chain) = queue.pop(mem)? else {
                // フレームは保持したまま次の kick を待つ。
                stats.waiting_for_buffer = true;
                break;
            };
            let used_len = self.deliver(&chain, frame_len, mem, stats);
            queue.add_used(mem, &chain, used_len)?;
            stats.completed += 1;
        }
        Ok(())
    }

    /// backend から 1 フレームを staging へ取り出す。続行してよければ true。
    fn fetch_frame(&mut self, stats: &mut NetRxStats) -> bool {
        let Some(frame_area) = self.rx_buf.get_mut(NET_HDR_LEN as usize..) else {
            return false;
        };
        match self.backend.recv(frame_area) {
            Ok(None) => false,
            Ok(Some(n)) => {
                let valid = u32::try_from(n)
                    .is_ok_and(|n| (MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&n))
                    && n <= frame_area.len();
                if valid {
                    self.staged_len = Some(n);
                } else {
                    stats.rx_backend_error += 1;
                }
                true
            }
            Err(_) => {
                stats.rx_backend_error += 1;
                false
            }
        }
    }

    /// 受信バッファ 1 本を処理して used len を返す。フレームを消費したら `staged_len` を空にする。
    fn deliver<M: GuestMemoryBacking>(
        &mut self,
        chain: &DescriptorChain,
        frame_len: usize,
        mem: &mut GuestMemory<M>,
        stats: &mut NetRxStats,
    ) -> u32 {
        if chain.readable_len() > 0 {
            stats.rx_malformed += 1;
            return 0;
        }
        let total = (NET_HDR_LEN as usize).saturating_add(frame_len);
        let fits = u64::try_from(total).is_ok_and(|t| chain.writable_len() >= t);
        if !fits {
            self.staged_len = None;
            stats.rx_dropped_buffer_too_small += 1;
            return 0;
        }
        let writable: Vec<Descriptor> = chain
            .descriptors()
            .iter()
            .filter(|d| d.writable)
            .copied()
            .collect();
        let delivered = self
            .rx_buf
            .get(..total)
            .is_some_and(|data| scatter(mem, &writable, data));
        self.staged_len = None;
        if !delivered {
            stats.rx_backend_error += 1;
            return 0;
        }
        stats.delivered += 1;
        u32::try_from(total).unwrap_or(0)
    }

    /// 送信キューのフレームを backend へ渡す（1 回に最大キュー長の本数）。
    ///
    /// activate 前・停止後は `FailedPrecondition`。リング破損は `Err`（`InvalidArgument`）。
    pub fn process_tx<M: GuestMemoryBacking>(
        &mut self,
        mem: &mut GuestMemory<M>,
    ) -> Result<NetTxStats, MicrovmError> {
        self.tx_aborted = NetTxStats::default();
        let mut queue = take_queue(
            &mut self.tx_queue,
            self.tx_cfg,
            mem,
            "net transmit queue is not active",
        )?;
        let mut stats = NetTxStats::default();
        let result = self.drain_tx(&mut queue, mem, &mut stats);
        self.tx_queue = Some(queue);
        match result {
            Ok(()) => Ok(stats),
            Err(e) => {
                self.tx_aborted = stats;
                Err(e)
            }
        }
    }

    fn drain_tx<M: GuestMemoryBacking>(
        &mut self,
        queue: &mut SplitQueue,
        mem: &mut GuestMemory<M>,
        stats: &mut NetTxStats,
    ) -> Result<(), MicrovmError> {
        for _ in 0..queue.size() {
            let Some(chain) = queue.pop(mem)? else {
                break;
            };
            self.transmit(&chain, mem, stats);
            // 送信バッファにデバイスは書かないので used len は常に 0。
            queue.add_used(mem, &chain, 0)?;
            stats.completed += 1;
        }
        Ok(())
    }

    /// 送信チェーン 1 本を検査して backend へ渡す。捨てた理由は `stats` に数える。
    fn transmit<M: GuestMemoryBacking>(
        &mut self,
        chain: &DescriptorChain,
        mem: &GuestMemory<M>,
        stats: &mut NetTxStats,
    ) {
        if chain.writable_len() > 0 {
            stats.tx_malformed += 1;
            return;
        }
        let readable = chain.readable_len();
        if chain.oversized() || readable > u64::from(NET_HDR_LEN + MAX_FRAME_LEN) {
            stats.tx_dropped_oversize += 1;
            return;
        }
        let Some(total) = usize::try_from(readable)
            .ok()
            .filter(|t| *t >= NET_HDR_LEN as usize)
        else {
            stats.tx_malformed += 1;
            return;
        };
        let Some(buf) = self.tx_buf.get_mut(..total) else {
            stats.tx_malformed += 1;
            return;
        };
        if !gather(mem, chain.descriptors(), buf) {
            stats.tx_malformed += 1;
            return;
        }
        let (Some(&flags), Some(&gso_type)) = (buf.first(), buf.get(1)) else {
            stats.tx_malformed += 1;
            return;
        };
        if flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 || gso_type != VIRTIO_NET_HDR_GSO_NONE {
            stats.tx_invalid_header += 1;
            return;
        }
        let Some(frame) = buf.get(NET_HDR_LEN as usize..) else {
            stats.tx_malformed += 1;
            return;
        };
        if frame.len() < MIN_FRAME_LEN as usize {
            stats.tx_invalid_frame += 1;
            return;
        }
        match self.backend.send(frame) {
            Ok(()) => stats.sent += 1,
            // ゲストへエラーを返す手段が無いので捨てる。
            Err(_) => stats.tx_backend_error += 1,
        }
    }
}

/// 遅延作成済みのキューを取り出す。無ければ設定から作る（設定も無ければ `FailedPrecondition`）。
fn take_queue<M: GuestMemoryBacking>(
    slot: &mut Option<SplitQueue>,
    cfg: Option<QueueConfig>,
    mem: &GuestMemory<M>,
    inactive: &'static str,
) -> Result<SplitQueue, MicrovmError> {
    if let Some(q) = slot.take() {
        return Ok(q);
    }
    let cfg =
        cfg.ok_or_else(|| MicrovmError::new(MicrovmErrorCode::FailedPrecondition, inactive))?;
    Ok(SplitQueue::new(&cfg, mem)?)
}

/// readable な記述子列のバイト列の先頭から `buf.len()` バイトを、記述子の境界をまたいで読む。
/// バイト列が足りない・読み取りに失敗したら false。
fn gather<M: GuestMemoryBacking>(
    mem: &GuestMemory<M>,
    descs: &[Descriptor],
    buf: &mut [u8],
) -> bool {
    let mut filled = 0usize;
    for d in descs.iter().filter(|d| !d.writable) {
        if filled == buf.len() {
            break;
        }
        let Ok(dlen) = usize::try_from(d.len) else {
            return false;
        };
        let n = (buf.len() - filled).min(dlen);
        let Some(end) = filled.checked_add(n) else {
            return false;
        };
        let Some(dst) = buf.get_mut(filled..end) else {
            return false;
        };
        if mem.read_at(d.addr, dst).is_err() {
            return false;
        }
        filled = end;
    }
    filled == buf.len()
}

/// `data` を writable な記述子列のバイト列の先頭から、記述子の境界をまたいで書く。入りきらなければ false。
fn scatter<M: GuestMemoryBacking>(
    mem: &mut GuestMemory<M>,
    descs: &[Descriptor],
    data: &[u8],
) -> bool {
    let mut done = 0usize;
    for d in descs.iter().filter(|d| d.writable) {
        if done == data.len() {
            break;
        }
        let Ok(dlen) = usize::try_from(d.len) else {
            return false;
        };
        let n = (data.len() - done).min(dlen);
        let Some(end) = done.checked_add(n) else {
            return false;
        };
        let Some(src) = data.get(done..end) else {
            return false;
        };
        if mem.write_at(d.addr, src).is_err() {
            return false;
        }
        done = end;
    }
    done == data.len()
}

impl<B: NetBackend> VirtioDevice for VirtioNet<B> {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Net
    }

    fn device_features(&self) -> FeatureBits {
        FeatureBits::from_bits(VIRTIO_NET_F_MAC)
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE, QUEUE_MAX_SIZE]
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // mac[6] を offset 0 に置く。その先は 0。
        data.fill(0);
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        for (i, b) in data.iter_mut().enumerate() {
            if let Some(v) = start.checked_add(i).and_then(|p| self.mac.get(p)) {
                *b = *v;
            }
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(
        &mut self,
        features: FeatureBits,
        queues: &[QueueConfig],
    ) -> Result<(), MicrovmError> {
        match (queues.get(RX_QUEUE as usize), queues.get(TX_QUEUE as usize)) {
            (Some(rx), Some(tx)) if rx.ready() && tx.ready() => {
                self.rx_cfg = Some(*rx);
                self.tx_cfg = Some(*tx);
                self.rx_queue = None;
                self.tx_queue = None;
                self.staged_len = None;
                self.negotiated = features;
                Ok(())
            }
            _ => Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "net rx/tx queues are not ready",
            )),
        }
    }

    fn reset(&mut self) {
        self.stop_queue(RX_QUEUE);
        self.stop_queue(TX_QUEUE);
        self.negotiated = FeatureBits::EMPTY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_memory::{GuestAddress, HeapBacking};
    use crate::virtio_mmio::VirtioMmioTransport;
    use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

    type Mem = GuestMemory<HeapBacking>;
    const N: u16 = VRING_DESC_F_NEXT;
    const W: u16 = VRING_DESC_F_WRITE;
    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    // rx / tx の 2 組のリング。
    const RX_DESC: u64 = 0x1000;
    const RX_AVAIL: u64 = 0x2000;
    const RX_USED: u64 = 0x3000;
    const TX_DESC: u64 = 0x4000;
    const TX_AVAIL: u64 = 0x5000;
    const TX_USED: u64 = 0x6000;
    const BUF: u64 = 0x10000;

    fn new_mem() -> Mem {
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(4 << 20).unwrap()).unwrap()
    }

    fn ga(a: u64) -> GuestAddress {
        GuestAddress::new(a)
    }

    /// 2 キューを MMIO レジスタで設定し、DRIVER_OK まで進めて activate 済みのデバイスを返す。
    fn net() -> VirtioNet<MemoryNetBackend> {
        use crate::virtio_mmio::reg;
        let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
        let w = |t: &mut VirtioMmioTransport<VirtioNet<MemoryNetBackend>>, off: u64, v: u32| {
            t.write(off, &v.to_le_bytes());
        };
        w(&mut t, reg::STATUS, 1);
        w(&mut t, reg::STATUS, 3);
        w(&mut t, reg::DRIVER_FEATURES_SEL, 0);
        w(&mut t, reg::DRIVER_FEATURES, VIRTIO_NET_F_MAC as u32);
        w(&mut t, reg::DRIVER_FEATURES_SEL, 1);
        w(&mut t, reg::DRIVER_FEATURES, 1);
        w(&mut t, reg::STATUS, 11);
        for (q, d, a, u) in [
            (0, RX_DESC, RX_AVAIL, RX_USED),
            (1, TX_DESC, TX_AVAIL, TX_USED),
        ] {
            w(&mut t, reg::QUEUE_SEL, q);
            w(&mut t, reg::QUEUE_NUM, 16);
            w(&mut t, reg::QUEUE_DESC_LOW, d as u32);
            w(&mut t, reg::QUEUE_DRIVER_LOW, a as u32);
            w(&mut t, reg::QUEUE_DEVICE_LOW, u as u32);
            w(&mut t, reg::QUEUE_READY, 1);
        }
        w(&mut t, reg::STATUS, 15);
        assert_eq!(t.negotiated_features().map(|f| f.bits() & 0xff), Some(0x20));
        let cfgs = [*t.queue(0).unwrap(), *t.queue(1).unwrap()];
        let mut dev = VirtioNet::new(MemoryNetBackend::new(), MAC);
        dev.activate(FeatureBits::from_bits(VIRTIO_NET_F_MAC), &cfgs)
            .unwrap();
        dev
    }

    fn put_desc(m: &mut Mem, base: u64, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let at = base + u64::from(i) * 16;
        m.write_at(ga(at), &addr.to_le_bytes()).unwrap();
        m.write_u32_le(ga(at + 8), len).unwrap();
        m.write_u16_le(ga(at + 12), flags).unwrap();
        m.write_u16_le(ga(at + 14), next).unwrap();
    }

    fn publish(m: &mut Mem, avail: u64, slot: u16, head: u16, idx: u16) {
        m.write_u16_le(ga(avail + 4 + 2 * u64::from(slot)), head)
            .unwrap();
        m.write_u16_le(ga(avail + 2), idx).unwrap();
    }

    /// tx: head=slot の単一 readable 記述子（ヘッダ + フレーム）。バッファは BUF + 0x1000 * slot。
    fn tx_single(m: &mut Mem, slot: u16, hdr: [u8; 12], frame: &[u8]) {
        let at = BUF + 0x1000 * u64::from(slot);
        let mut data = hdr.to_vec();
        data.extend_from_slice(frame);
        m.write_at(ga(at), &data).unwrap();
        put_desc(m, TX_DESC, slot, at, data.len() as u32, 0, 0);
        publish(m, TX_AVAIL, slot, slot, slot + 1);
    }

    /// rx: head=slot の単一 writable 記述子。バッファは BUF + 0x1000 * slot（0xee 埋め）。
    fn rx_single(m: &mut Mem, slot: u16, len: u32) {
        let at = BUF + 0x1000 * u64::from(slot);
        m.write_at(ga(at), &vec![0xee; len as usize]).unwrap();
        put_desc(m, RX_DESC, slot, at, len, W, 0);
        publish(m, RX_AVAIL, slot, slot, slot + 1);
    }

    fn frame(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    fn used(m: &Mem, base: u64, slot: u64) -> (u32, u32) {
        (
            m.read_u32_le(ga(base + 4 + 8 * slot)).unwrap(),
            m.read_u32_le(ga(base + 8 + 8 * slot)).unwrap(),
        )
    }

    /// MVM-1: 設定空間・feature・キュー最大長の具体値。
    #[test]
    fn mvm1_config_space_and_features() {
        let n = net();
        assert_eq!(n.device_type(), VirtioDeviceType::Net);
        assert_eq!(n.device_features().bits(), 1 << 5);
        assert_eq!(n.queue_max_sizes(), &[256, 256]);
        let mut d = [0xffu8; 8];
        n.read_config(0, &mut d);
        assert_eq!(d, [0x02, 0, 0, 0, 0, 0x01, 0, 0]);
        let mut d = [0xffu8; 4];
        n.read_config(4, &mut d);
        assert_eq!(d, [0, 0x01, 0, 0]);
        n.read_config(0x20, &mut d);
        assert_eq!(d, [0; 4]);
        n.read_config(u64::MAX, &mut d);
        assert_eq!(d, [0; 4]);
    }

    /// MVM-1: ヘッダの途中で区切った 2 記述子の送信が backend に完全一致で届く。
    #[test]
    fn mvm1_tx_frame_split_across_descriptors_reaches_backend() {
        let mut m = new_mem();
        let mut n = net();
        let f = frame(60, 0x10);
        m.write_at(ga(BUF), &[0u8; 5]).unwrap();
        m.write_at(ga(BUF + 0x1000), &[0u8; 7]).unwrap();
        m.write_at(ga(BUF + 0x1000 + 7), &f).unwrap();
        put_desc(&mut m, TX_DESC, 0, BUF, 5, N, 1);
        put_desc(&mut m, TX_DESC, 1, BUF + 0x1000, 7 + 60, 0, 0);
        publish(&mut m, TX_AVAIL, 0, 0, 1);
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!(
            s,
            NetTxStats {
                completed: 1,
                sent: 1,
                ..Default::default()
            }
        );
        assert_eq!(n.backend().sent(), &[f]);
        assert_eq!(m.read_u16_le(ga(TX_USED + 2)).unwrap(), 1);
        assert_eq!(used(&m, TX_USED, 0), (0, 0));
    }

    /// MVM-1: 受信フレームはヘッダ 12 バイトの後に書かれ、used len がヘッダ + フレーム長になる。
    #[test]
    fn mvm1_rx_frame_written_after_header() {
        for split in [false, true] {
            let mut m = new_mem();
            let mut n = net();
            let f = frame(60, 0x40);
            n.backend_mut().push_inbound(&f).unwrap();
            if split {
                // ヘッダの途中で 2 つの writable に分ける。
                m.write_at(ga(BUF), &[0xee; 0x1000]).unwrap();
                put_desc(&mut m, RX_DESC, 0, BUF, 8, W | N, 1);
                put_desc(&mut m, RX_DESC, 1, BUF + 0x1000, 100, W, 0);
                publish(&mut m, RX_AVAIL, 0, 0, 1);
            } else {
                rx_single(&mut m, 0, 2048);
            }
            let s = n.process_rx(&mut m).unwrap();
            assert_eq!(
                s,
                NetRxStats {
                    completed: 1,
                    delivered: 1,
                    ..Default::default()
                }
            );
            let mut got = vec![0u8; 72];
            if split {
                m.read_at(ga(BUF), &mut got[..8]).unwrap();
                m.read_at(ga(BUF + 0x1000), &mut got[8..]).unwrap();
            } else {
                m.read_at(ga(BUF), &mut got).unwrap();
            }
            assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
            assert_eq!(&got[12..], &f[..]);
            assert_eq!(used(&m, RX_USED, 0), (0, 72));
        }
    }

    /// MVM-1: バッファが無い間はフレームを device が 1 つ保持し、バッファが来たら配送する。
    #[test]
    fn mvm1_rx_frame_staged_until_buffer_posted() {
        let mut m = new_mem();
        let mut n = net();
        n.backend_mut().push_inbound(&frame(60, 1)).unwrap();
        n.backend_mut().push_inbound(&frame(61, 2)).unwrap();
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!(s.delivered, 0);
        assert!(s.waiting_for_buffer);
        assert_eq!(n.backend().inbound_len(), 1);
        rx_single(&mut m, 0, 2048);
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!((s.completed, s.delivered), (1, 1));
        assert!(s.waiting_for_buffer);
        assert_eq!(used(&m, RX_USED, 0), (0, 72));
        let mut got = vec![0u8; 60];
        m.read_at(ga(BUF + 12), &mut got).unwrap();
        assert_eq!(got, frame(60, 1));
    }

    /// MVM-1: 小さすぎるバッファのフレームは捨て、バッファは len 0 で返り、次は次のバッファへ届く。
    #[test]
    fn mvm1_rx_buffer_too_small_drops_frame() {
        let mut m = new_mem();
        let mut n = net();
        n.backend_mut()
            .push_inbound(&frame(MAX_FRAME_LEN as usize, 3))
            .unwrap();
        n.backend_mut().push_inbound(&frame(60, 4)).unwrap();
        rx_single(&mut m, 0, 1526);
        put_desc(&mut m, RX_DESC, 1, BUF + 0x1000, 2048, W, 0);
        publish(&mut m, RX_AVAIL, 1, 1, 2);
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!(
            s,
            NetRxStats {
                completed: 2,
                delivered: 1,
                rx_dropped_buffer_too_small: 1,
                ..Default::default()
            }
        );
        assert_eq!(used(&m, RX_USED, 0), (0, 0));
        assert_eq!(used(&m, RX_USED, 1), (1, 72));
        let mut got = vec![0u8; 60];
        m.read_at(ga(BUF + 0x1000 + 12), &mut got).unwrap();
        assert_eq!(got, frame(60, 4));
        // 捨てたバッファの先頭にフレームの残骸が書かれていない。
        let mut head = [0u8; 4];
        m.read_at(ga(BUF), &mut head).unwrap();
        assert_eq!(head, [0xee; 4]);
    }

    /// MVM-1: 壊れた構造のチェーンは Err にならず used へ返り、キューが進む。
    #[test]
    fn mvm1_malformed_chains_are_consumed() {
        let mut m = new_mem();
        let mut n = net();
        let good = [0u8; 12];
        let mut csum = good;
        csum[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        let mut gso = good;
        gso[1] = 1;
        // 0: writable を含む / 1: ヘッダ未満 / 2: NEEDS_CSUM / 3: GSO / 4: 14 バイト未満 /
        // 5: 上限超過 / 6: 正常。
        put_desc(&mut m, TX_DESC, 0, BUF, 100, W, 0);
        publish(&mut m, TX_AVAIL, 0, 0, 1);
        put_desc(&mut m, TX_DESC, 1, BUF + 0x1000, 11, 0, 0);
        publish(&mut m, TX_AVAIL, 1, 1, 2);
        let cases: [(u16, [u8; 12], usize); 4] =
            [(2, csum, 60), (3, gso, 60), (4, good, 13), (5, good, 1519)];
        for (head, hdr, flen) in cases.iter() {
            let at = BUF + 0x1000 * u64::from(*head);
            let mut data = hdr.to_vec();
            data.extend_from_slice(&vec![7u8; *flen]);
            m.write_at(ga(at), &data).unwrap();
            put_desc(&mut m, TX_DESC, *head, at, data.len() as u32, 0, 0);
            publish(&mut m, TX_AVAIL, *head, *head, *head + 1);
        }
        tx_single(&mut m, 6, good, &frame(60, 0));
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!(
            s,
            NetTxStats {
                completed: 7,
                sent: 1,
                tx_malformed: 2,
                tx_dropped_oversize: 1,
                tx_invalid_header: 2,
                tx_invalid_frame: 1,
                tx_backend_error: 0,
            }
        );
        assert_eq!(m.read_u16_le(ga(TX_USED + 2)).unwrap(), 7);
        assert_eq!(n.backend().sent().len(), 1);

        // rx: readable を含むチェーンは len 0 で消費され、保持中のフレームは次のバッファへ届く。
        n.backend_mut().push_inbound(&frame(60, 9)).unwrap();
        put_desc(&mut m, RX_DESC, 0, BUF, 64, 0, 0);
        publish(&mut m, RX_AVAIL, 0, 0, 1);
        rx_single(&mut m, 1, 2048);
        m.write_u16_le(ga(RX_AVAIL + 2), 2).unwrap();
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!(
            s,
            NetRxStats {
                completed: 2,
                delivered: 1,
                rx_malformed: 1,
                ..Default::default()
            }
        );
        assert_eq!(used(&m, RX_USED, 0), (0, 0));
        assert_eq!(used(&m, RX_USED, 1), (1, 72));
    }

    /// MVM-1: フレーム上限を超える tx チェーンは捨てられ、used len 0 で返る。
    #[test]
    fn mvm1_tx_oversized_chain_is_dropped() {
        let mut m = new_mem();
        let mut n = net();
        // ヘッダ + 最大フレーム + 1 バイト。
        put_desc(
            &mut m,
            TX_DESC,
            0,
            BUF,
            NET_HDR_LEN + MAX_FRAME_LEN + 1,
            0,
            0,
        );
        publish(&mut m, TX_AVAIL, 0, 0, 1);
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!(
            s,
            NetTxStats {
                completed: 1,
                tx_dropped_oversize: 1,
                ..Default::default()
            }
        );
        assert_eq!(used(&m, TX_USED, 0), (0, 0));
        assert!(n.backend().sent().is_empty());
    }

    /// MVM-1: backend の失敗は件数に数えられ、リングは進む。
    #[test]
    fn mvm1_backend_errors_are_counted() {
        struct Spy;
        impl NetBackend for Spy {
            fn send(&mut self, _: &[u8]) -> Result<(), MicrovmError> {
                Err(invalid("send failed"))
            }
            fn recv(&mut self, _: &mut [u8]) -> Result<Option<usize>, MicrovmError> {
                Err(invalid("recv failed"))
            }
        }
        let mut m = new_mem();
        let cfg = {
            let mut d = net();
            let c = [d.rx_cfg.unwrap(), d.tx_cfg.unwrap()];
            d.reset();
            c
        };
        let mut n = VirtioNet::new(Spy, MAC);
        n.activate(FeatureBits::EMPTY, &cfg).unwrap();
        tx_single(&mut m, 0, [0; 12], &frame(60, 0));
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!((s.completed, s.sent, s.tx_backend_error), (1, 0, 1));
        assert_eq!(m.read_u16_le(ga(TX_USED + 2)).unwrap(), 1);
        rx_single(&mut m, 0, 2048);
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!((s.completed, s.rx_backend_error), (0, 1));
    }

    /// MVM-1: backend が契約外の長さを返したら捨てて数える。
    #[test]
    fn mvm1_backend_contract_violation_is_dropped() {
        struct Liar(usize);
        impl NetBackend for Liar {
            fn send(&mut self, _: &[u8]) -> Result<(), MicrovmError> {
                Ok(())
            }
            fn recv(&mut self, _: &mut [u8]) -> Result<Option<usize>, MicrovmError> {
                Ok(Some(self.0))
            }
        }
        for bad in [0usize, 13, 1519, usize::MAX] {
            let mut m = new_mem();
            let cfg = {
                let d = net();
                [d.rx_cfg.unwrap(), d.tx_cfg.unwrap()]
            };
            let mut n = VirtioNet::new(Liar(bad), MAC);
            n.activate(FeatureBits::EMPTY, &cfg).unwrap();
            rx_single(&mut m, 0, 2048);
            let s = n.process_rx(&mut m).unwrap();
            assert_eq!(s.delivered, 0, "len={bad}");
            // 1 回の呼び出しはキュー長（16）で頭打ち。
            assert_eq!(s.rx_backend_error, 16, "len={bad}");
            assert_eq!(s.completed, 0);
        }
    }

    /// MVM-1: activate 前・キュー停止後・リセット後は FailedPrecondition。
    #[test]
    fn mvm1_inactive_stop_and_reset() {
        let mut m = new_mem();
        let mut idle = VirtioNet::new(MemoryNetBackend::new(), MAC);
        for code in [
            idle.process_rx(&mut m).unwrap_err().code(),
            idle.process_tx(&mut m).unwrap_err().code(),
        ] {
            assert_eq!(code, MicrovmErrorCode::FailedPrecondition);
        }

        let mut n = net();
        n.stop_queue(1);
        assert_eq!(
            n.process_tx(&mut m).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
        assert!(n.process_rx(&mut m).is_ok());
        n.stop_queue(7);
        assert!(n.process_rx(&mut m).is_ok());

        let mut n = net();
        n.backend_mut().push_inbound(&frame(60, 0)).unwrap();
        assert!(n.process_rx(&mut m).unwrap().waiting_for_buffer);
        n.reset();
        assert_eq!(n.staged_len, None);
        for code in [
            n.process_rx(&mut m).unwrap_err().code(),
            n.process_tx(&mut m).unwrap_err().code(),
        ] {
            assert_eq!(code, MicrovmErrorCode::FailedPrecondition);
        }
    }

    /// MVM-1: 片方のキューしか ready でない activate は失敗する。
    #[test]
    fn mvm1_activate_requires_both_queues() {
        let d = net();
        let both = [d.rx_cfg.unwrap(), d.tx_cfg.unwrap()];
        let mut n = VirtioNet::new(MemoryNetBackend::new(), MAC);
        for queues in [&both[..1], &both[1..], &[][..]] {
            // 1 本だけ（または 0 本）では rx / tx が揃わない。
            let err = n.activate(FeatureBits::EMPTY, queues).unwrap_err();
            assert_eq!(err.code(), MicrovmErrorCode::FailedPrecondition);
        }
        assert!(n.activate(FeatureBits::EMPTY, &both).is_ok());
    }

    /// MVM-1: 途中でリング破損に当たっても、それまでの内訳が取れる。
    #[test]
    fn mvm1_partial_stats_survive_ring_error() {
        let mut m = new_mem();
        let mut n = net();
        tx_single(&mut m, 0, [0; 12], &frame(60, 0));
        // 2 本目は自分自身へ戻るループ。
        put_desc(&mut m, TX_DESC, 1, BUF + 0x1000, 8, N, 1);
        publish(&mut m, TX_AVAIL, 1, 1, 2);
        assert!(n.process_tx(&mut m).is_err());
        let s = n.tx_stats_before_error();
        assert_eq!((s.completed, s.sent), (1, 1));
        assert_eq!(m.read_u16_le(ga(TX_USED + 2)).unwrap(), 1);
    }

    /// MVM-1: 1 回の呼び出しで処理するのはキュー長（16）まで。
    #[test]
    fn mvm1_queue_loop_is_bounded() {
        let mut m = new_mem();
        let mut n = net();
        for i in 0..16u16 {
            let at = BUF + 0x100 * u64::from(i);
            m.write_at(ga(at), &[0u8; 12 + 60]).unwrap();
            put_desc(&mut m, TX_DESC, i, at, 72, 0, 0);
            m.write_u16_le(ga(TX_AVAIL + 4 + 2 * u64::from(i)), i)
                .unwrap();
        }
        m.write_u16_le(ga(TX_AVAIL + 2), 16).unwrap();
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!((s.completed, s.sent), (16, 16));
        // 続きの 1 本は次の呼び出しで処理される。
        m.write_u16_le(ga(TX_AVAIL + 4), 0).unwrap();
        m.write_u16_le(ga(TX_AVAIL + 2), 17).unwrap();
        let s = n.process_tx(&mut m).unwrap();
        assert_eq!(s.completed, 1);

        // backend に 20 件あっても rx は 16 回まで。
        for _ in 0..20 {
            n.backend_mut().push_inbound(&frame(60, 0)).unwrap();
        }
        for i in 0..16u16 {
            let at = BUF + 0x10000 + 0x800 * u64::from(i);
            put_desc(&mut m, RX_DESC, i, at, 2048, W, 0);
            m.write_u16_le(ga(RX_AVAIL + 4 + 2 * u64::from(i)), i)
                .unwrap();
        }
        m.write_u16_le(ga(RX_AVAIL + 2), 16).unwrap();
        let s = n.process_rx(&mut m).unwrap();
        assert_eq!((s.completed, s.delivered), (16, 16));
        assert_eq!(n.backend().inbound_len(), 4);
    }

    /// MVM-1: メモリ backend の入力検証と件数上限。
    #[test]
    fn mvm1_memory_backend_validation() {
        let mut b = MemoryNetBackend::new();
        for len in [0usize, 13, 1519] {
            assert_eq!(
                b.push_inbound(&vec![0u8; len]).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument,
                "len={len}"
            );
        }
        for _ in 0..MAX_MEMORY_FRAMES {
            b.push_inbound(&[0u8; 14]).unwrap();
        }
        assert_eq!(
            b.push_inbound(&[0u8; 14]).unwrap_err().code(),
            MicrovmErrorCode::ResourceExhausted
        );
        let mut s = MemoryNetBackend::new();
        for _ in 0..MAX_MEMORY_FRAMES {
            s.send(&[0u8; 14]).unwrap();
        }
        assert_eq!(
            s.send(&[0u8; 14]).unwrap_err().code(),
            MicrovmErrorCode::ResourceExhausted
        );
        assert_eq!(s.take_sent().len(), MAX_MEMORY_FRAMES);
        assert!(s.sent().is_empty());
    }
}
