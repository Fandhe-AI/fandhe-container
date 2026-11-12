//! venus のリング（ゲストと共有する blob）に書かれたコマンド列の記録（GPU-6・REPAIR-2・REPAIR-3・TASK-172 後続・#1884）。
//!
//! 役割: ゲストの venus ドライバは通常のコマンドを `vkCreateRingMESA` で作ったリング（HOST3D の blob＝治具が `MAP_BLOB` で作る
//! memfd）へ書き、virtqueue の `SUBMIT_3D` には制御（リングの作成・通知）しか載せない（設計書 10.4.5）。このため
//! `SUBMIT_3D` の本体だけの記録（`recording`）ではゲストが提出したコマンドストリームを残せない。本モジュールは受理した
//! `CreateRingMESA` の本体からリングの配置を検証つきで取り出し、契機ごとに `[cursor, tail)` の差分を読んで同じ記録器へ
//! FCVNSREC の kind 1 の 1 レコードとして足す。
//!
//! 呼び出し元: `session` が `SessionHooks` 経由で [`RecordingHooks`] を呼ぶ（`on_submit`・応答後の `after_notify`・終了時の
//! `before_release`。Linux 限定）。本モジュールはファイルにも memfd にも触れず、読み取り口 [`BlobRead`] だけに依存するため
//! 3 OS でビルドし、偽の `BlobRead` で単体試験する。
//!
//! 守る制約（#1822 の決定）: `unsafe` を足さない（memfd は map せず `FileExt::read_exact_at` で読む）。リングを消費しない
//! （head・status・reply を書かない。dispatch は TASK-177.x）。`MmapRegion::map_shared` の契約は変えない。
//!
//! 信頼境界: `CreateRingMESA` の引数と共有メモリ上の head・tail はゲスト由来（untrusted）。長さは確保の前に検査し、
//! 算術は checked / wrapping で行い、添字アクセスと `unwrap` を使わない。異常が出たリングはその記録だけを止め、
//! ログ行を 1 回だけ出す（洪水の防止）。セッションは続ける。
//!
//! 記録しないもの（REPAIR-3）: reply ストリーム・期待出力・extra 領域・間接の cs の shmem・status・head の更新。
//! `vkNotifyRingMESA` を契機にしない理由: 治具は status を書かず IDLE bit が立たないため、実機では来ない見込み（設計書 10.4.5。未実測・#725）。
//! Destroy なしに blob が `UNREF` された場合、直前のスナップショット以降の分は失う（`blob_not_held`）。
//!
//! 出典（値と配置だけを転記。コードは写さない。MVM-4）: Mesa `mesa-25.0.0` の `src/virtio/vulkan/vn_ring.c` と
//! `src/virtio/venus-protocol/vn_protocol_driver_{transport,types,defines}.h`（設計書 10.4.1）。

use std::io::Write;

use fandhe_container_plugin_macos::gpu::venus::replay::MAX_RECORD_PAYLOAD_LEN;
use fandhe_container_plugin_macos::gpu::venus::{
    CommandType, VenusWireError, WireReader, parse_command_header,
};

use crate::adapter::Submit3d;
use crate::log;
use crate::recording::{RecordOutcome, SubmitRecorder};

/// リング表の件数の上限（固定長。ゲスト入力で増えない）。
pub const MAX_RINGS: usize = 16;
/// `pNext` の chain の深さの上限（Monitor と Priority の 2 種を 1 回ずつ）。
const MAX_PNEXT_DEPTH: usize = 2;

const STYPE_RING_CREATE_INFO: i32 = 1_000_384_000;
const STYPE_RING_MONITOR_INFO: i32 = 1_000_384_006;
const STYPE_RING_PRIORITY_INFO: i32 = 1_000_384_007;

/// リングの異常・拒否の固定語彙（ログに出す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingErrorCode {
    /// `CreateRingMESA` / `DestroyRingMESA` の本体が wire 規則に合わない（切り詰め・未知の sType・余りなど）。
    MalformedCommand,
    /// 配置が不正（bufferSize が 0 / 2 の冪でない / 上限超え、offset の溢れ・整列違反・範囲外）。
    InvalidLayout,
    /// リング表が満杯。
    TableFull,
    /// 同じ ring id が作成済み。
    DuplicateRing,
    /// resource の memfd を保持していない。
    BlobNotHeld,
    /// リングが blob の長さを超える。
    OutOfRange,
    /// `read_exact_at` が失敗または短い。
    ReadFailed,
    /// head・tail・cursor の関係が bufferSize に収まらない。
    TailOutOfRange,
    /// 記録器の上限で止まった。
    RecordStopped,
}

impl RingErrorCode {
    /// ログに出す固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedCommand => "malformed_command",
            Self::InvalidLayout => "invalid_layout",
            Self::TableFull => "table_full",
            Self::DuplicateRing => "duplicate_ring",
            Self::BlobNotHeld => "blob_not_held",
            Self::OutOfRange => "out_of_range",
            Self::ReadFailed => "read_failed",
            Self::TailOutOfRange => "tail_out_of_range",
            Self::RecordStopped => "record_stopped",
        }
    }
}

/// [`BlobRead::read_exact_at`] の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobReadError {
    /// その resource の memfd を保持していない。
    NotHeld,
    /// 範囲が blob の長さの外。
    OutOfRange,
    /// 読み取りの失敗（短い読み取りを含む）。
    ReadFailed,
}

/// blob の中身を読む口。`session` の `BlobMemTable` が memfd の `read_exact_at` で実装し、試験は偽の実装を使う。
pub trait BlobRead {
    /// 読める長さ（保持していなければ `None`）。
    fn blob_len(&self, res_id: u32) -> Option<u64>;
    /// `buf` を `offset` から読み切る。範囲は実装が blob の長さで検査する。
    fn read_exact_at(&self, res_id: u32, offset: u64, buf: &mut [u8]) -> Result<(), BlobReadError>;
}

/// 検証済みのリング配置。[`RingLayout::parse_create`] か [`RingLayout::new`] を通ったときだけ作れる（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingLayout {
    res_id: u32,
    offset: u64,
    size: u64,
    head_offset: u64,
    tail_offset: u64,
    status_offset: u64,
    buffer_offset: u64,
    buffer_size: u32,
}

/// `CreateRingMESA` の self の値（未検証）。
#[derive(Debug, Clone, Copy)]
struct RawLayout {
    res_id: u32,
    offset: u64,
    size: u64,
    head_offset: u64,
    tail_offset: u64,
    status_offset: u64,
    buffer_offset: u64,
    buffer_size: u64,
}

impl RingLayout {
    fn new(raw: RawLayout) -> Result<Self, RingErrorCode> {
        let bad = RingErrorCode::InvalidLayout;
        let buffer_size = u32::try_from(raw.buffer_size).map_err(|_| bad)?;
        if buffer_size == 0
            || !buffer_size.is_power_of_two()
            || buffer_size > MAX_RECORD_PAYLOAD_LEN
            || raw.res_id == 0
        {
            return Err(bad);
        }
        raw.offset.checked_add(raw.size).ok_or(bad)?;
        for off in [raw.head_offset, raw.tail_offset, raw.status_offset] {
            let end = off.checked_add(4).ok_or(bad)?;
            if end > raw.size || off % 4 != 0 {
                return Err(bad);
            }
        }
        let buf_end = raw
            .buffer_offset
            .checked_add(u64::from(buffer_size))
            .ok_or(bad)?;
        if buf_end > raw.size {
            return Err(bad);
        }
        Ok(Self {
            res_id: raw.res_id,
            offset: raw.offset,
            size: raw.size,
            head_offset: raw.head_offset,
            tail_offset: raw.tail_offset,
            status_offset: raw.status_offset,
            buffer_offset: raw.buffer_offset,
            buffer_size,
        })
    }

    /// `CreateRingMESA` のコマンド本体（ヘッダを含む）から ring id と配置を取り出す。fail-closed。
    pub fn parse_create(payload: &[u8]) -> Result<(u64, Self), RingErrorCode> {
        let bad = RingErrorCode::MalformedCommand;
        let mut r = WireReader::new(payload);
        let header = parse_command_header(&mut r).map_err(|_| bad)?;
        if header.command != CommandType::CreateRingMESA {
            return Err(bad);
        }
        let ring = r.read_u64().map_err(|_| bad)?;
        // pCreateInfo（simple pointer。1 のみ）。
        if r.read_u64().map_err(|_| bad)? != 1 {
            return Err(bad);
        }
        if r.read_i32().map_err(|_| bad)? != STYPE_RING_CREATE_INFO {
            return Err(bad);
        }
        read_pnext_chain(&mut r, 0, &mut [false; 2]).map_err(|_| bad)?;
        let rd = |r: &mut WireReader<'_>| -> Result<u64, RingErrorCode> {
            r.read_u64().map_err(|_| bad)
        };
        let _flags = r.read_u32().map_err(|_| bad)?;
        let res_id = r.read_u32().map_err(|_| bad)?;
        let offset = rd(&mut r)?;
        let size = rd(&mut r)?;
        let _idle_timeout = rd(&mut r)?;
        let head_offset = rd(&mut r)?;
        let tail_offset = rd(&mut r)?;
        let status_offset = rd(&mut r)?;
        let buffer_offset = rd(&mut r)?;
        let buffer_size = rd(&mut r)?;
        let _extra_offset = rd(&mut r)?;
        let _extra_size = rd(&mut r)?;
        if r.remaining() != 0 {
            return Err(bad);
        }
        let layout = Self::new(RawLayout {
            res_id,
            offset,
            size,
            head_offset,
            tail_offset,
            status_offset,
            buffer_offset,
            buffer_size,
        })?;
        Ok((ring, layout))
    }

    /// `DestroyRingMESA` のコマンド本体から ring id を取り出す。
    pub fn parse_destroy(payload: &[u8]) -> Result<u64, RingErrorCode> {
        let bad = RingErrorCode::MalformedCommand;
        let mut r = WireReader::new(payload);
        let header = parse_command_header(&mut r).map_err(|_| bad)?;
        if header.command != CommandType::DestroyRingMESA {
            return Err(bad);
        }
        let ring = r.read_u64().map_err(|_| bad)?;
        if r.remaining() != 0 {
            return Err(bad);
        }
        Ok(ring)
    }

    /// resource の id。
    pub fn res_id(&self) -> u32 {
        self.res_id
    }
    /// bufferSize（0 でない 2 の冪で 16 MiB 以下）。
    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }
    /// リングの blob 内の先頭 offset。
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// リング全体の大きさ。
    pub fn size(&self) -> u64 {
        self.size
    }
    /// status の offset（記録しない。配置の検証にだけ使う）。
    pub fn status_offset(&self) -> u64 {
        self.status_offset
    }
}

/// `pNext` の chain を読む。要素は「pointer(1) → sType → 入れ子の chain → self」で、末端は pointer(0)。
/// Monitor・Priority を 1 回ずつだけ受け、未知の sType・重複・pointer が 0 / 1 以外・深さ超過は拒否する。
fn read_pnext_chain(
    r: &mut WireReader<'_>,
    depth: usize,
    seen: &mut [bool; 2],
) -> Result<(), VenusWireError> {
    let invalid = VenusWireError::Truncated {
        needed: 0,
        remaining: r.remaining(),
    };
    match r.read_u64()? {
        0 => Ok(()),
        1 => {
            if depth >= MAX_PNEXT_DEPTH {
                return Err(invalid);
            }
            let stype = r.read_i32()?;
            let idx = match stype {
                STYPE_RING_MONITOR_INFO => 0,
                STYPE_RING_PRIORITY_INFO => 1,
                _ => return Err(invalid),
            };
            let slot = seen.get_mut(idx).ok_or(invalid)?;
            if *slot {
                return Err(invalid);
            }
            *slot = true;
            read_pnext_chain(r, depth + 1, seen)?;
            // self: Monitor は maxReportingPeriodMicroseconds(u32)、Priority は priority(i32)。いずれも 4 バイト。
            r.read_u32()?;
            Ok(())
        }
        _ => Err(invalid),
    }
}

/// リング 1 本分の状態。
#[derive(Debug)]
struct RingEntry {
    /// 作成した ctx。ring_id は ctx ごとに採番されるため、識別は (ctx_id, ring_id) の組で行う。
    ctx_id: u32,
    ring_id: u64,
    layout: RingLayout,
    /// 次に読む位置（最初のスナップショットの head で初期化）。
    cursor: Option<u32>,
    /// 異常で記録を止めた。以後は読まない。
    dead: bool,
}

/// 受理した提出を記録し、契機ごとにリングの差分も足す記録フック。
#[derive(Debug)]
pub struct RecordingHooks<W: Write> {
    recorder: SubmitRecorder<W>,
    rings: [Option<RingEntry>; MAX_RINGS],
}

impl<W: Write> RecordingHooks<W> {
    /// 記録器を包む。
    pub fn new(recorder: SubmitRecorder<W>) -> Self {
        Self {
            recorder,
            rings: std::array::from_fn(|_| None),
        }
    }

    /// 記録器を取り出す（`finish` 用）。
    pub fn into_recorder(self) -> SubmitRecorder<W> {
        self.recorder
    }

    /// 受理した `SUBMIT_3D` の本体を記録し、`CreateRingMESA` / `DestroyRingMESA` ならリング表を更新する。ログ行は `sink` へ流す。
    pub fn on_submit(&mut self, s: &Submit3d, sink: &mut dyn FnMut(&str)) {
        if let Some(line) = self.recorder.on_submit(s) {
            sink(&line);
        }
        let Some(Ok(header)) = &s.header else {
            return;
        };
        match header.command {
            CommandType::CreateRingMESA => match RingLayout::parse_create(&s.payload) {
                Ok((ring_id, layout)) => match self.insert_ring(s.ctx_id, ring_id, layout) {
                    Ok(()) => sink(&log::ring_create_line(
                        ring_id,
                        layout.res_id(),
                        layout.buffer_size(),
                        None,
                    )),
                    Err(code) => sink(&log::ring_create_line(
                        ring_id,
                        layout.res_id(),
                        layout.buffer_size(),
                        Some(code),
                    )),
                },
                Err(code) => sink(&log::ring_create_failed_line(code)),
            },
            // 破棄は応答の公開前に `before_response` が最終読み取りを済ませて表から外す（ここでは何もしない）。
            CommandType::DestroyRingMESA => {}
            _ => {}
        }
    }

    fn insert_ring(
        &mut self,
        ctx_id: u32,
        ring_id: u64,
        layout: RingLayout,
    ) -> Result<(), RingErrorCode> {
        if self
            .rings
            .iter()
            .flatten()
            .any(|e| e.ctx_id == ctx_id && e.ring_id == ring_id)
        {
            return Err(RingErrorCode::DuplicateRing);
        }
        let slot = self
            .rings
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(RingErrorCode::TableFull)?;
        *slot = Some(RingEntry {
            ctx_id,
            ring_id,
            layout,
            cursor: None,
            dead: false,
        });
        Ok(())
    }

    /// `DestroyRingMESA` の応答を used ring へ公開する**前**に呼ぶ。該当 (ctx_id, ring_id) のリングを最後に 1 回読み、表から外す。
    ///
    /// 公開後は後続の `UNMAP_BLOB` / `RESOURCE_UNREF` で memfd が閉じられ、ゲストが領域を再利用できるため、ここで読み切る（設計書 10.4.5）。
    pub fn before_response(
        &mut self,
        s: &Submit3d,
        blobs: &dyn BlobRead,
        sink: &mut dyn FnMut(&str),
    ) {
        let Some(Ok(header)) = &s.header else {
            return;
        };
        if header.command != CommandType::DestroyRingMESA {
            return;
        }
        let Ok(ring_id) = RingLayout::parse_destroy(&s.payload) else {
            return;
        };
        for slot in self.rings.iter_mut() {
            let matched = slot
                .as_ref()
                .is_some_and(|e| e.ctx_id == s.ctx_id && e.ring_id == ring_id);
            if matched {
                if let Some(entry) = slot.as_mut() {
                    Self::snapshot_entry(&mut self.recorder, entry, blobs, sink);
                }
                *slot = None;
            }
        }
    }

    fn snapshot_entry(
        recorder: &mut SubmitRecorder<W>,
        entry: &mut RingEntry,
        blobs: &dyn BlobRead,
        sink: &mut dyn FnMut(&str),
    ) {
        if entry.dead {
            return;
        }
        match snapshot_one(entry, blobs, recorder) {
            Ok(Some(line)) => sink(&line),
            Ok(None) => {}
            Err((code, stop_line)) => {
                entry.dead = true;
                if let Some(l) = stop_line {
                    sink(&l);
                }
                sink(&log::ring_error_line(entry.ring_id, code));
            }
        }
    }

    /// 全リングを 1 回ずつスナップショットする。
    pub fn snapshot_all(&mut self, blobs: &dyn BlobRead, sink: &mut dyn FnMut(&str)) {
        for entry in self.rings.iter_mut().flatten() {
            Self::snapshot_entry(&mut self.recorder, entry, blobs, sink);
        }
    }
}

/// 1 リングの差分を読んで記録する。差分が 0 なら `Ok(None)`。失敗は語彙と、記録器の停止行（あれば）。
fn snapshot_one<W: Write>(
    e: &mut RingEntry,
    blobs: &dyn BlobRead,
    recorder: &mut SubmitRecorder<W>,
) -> Result<Option<String>, (RingErrorCode, Option<String>)> {
    let l = e.layout;
    let fail = |c: RingErrorCode| (c, None);
    let blob_len = blobs
        .blob_len(l.res_id)
        .ok_or(fail(RingErrorCode::BlobNotHeld))?;
    let end = l
        .offset
        .checked_add(l.size)
        .ok_or(fail(RingErrorCode::OutOfRange))?;
    if end > blob_len {
        return Err(fail(RingErrorCode::OutOfRange));
    }
    let read_u32 = |off: u64| -> Result<u32, (RingErrorCode, Option<String>)> {
        let abs = l
            .offset
            .checked_add(off)
            .ok_or(fail(RingErrorCode::OutOfRange))?;
        let mut b = [0u8; 4];
        blobs.read_exact_at(l.res_id, abs, &mut b).map_err(|er| {
            fail(match er {
                BlobReadError::NotHeld => RingErrorCode::BlobNotHeld,
                BlobReadError::OutOfRange => RingErrorCode::OutOfRange,
                BlobReadError::ReadFailed => RingErrorCode::ReadFailed,
            })
        })?;
        Ok(u32::from_le_bytes(b))
    };
    let head = read_u32(l.head_offset)?;
    let tail = read_u32(l.tail_offset)?;
    let size = l.buffer_size;
    let cursor = e.cursor.unwrap_or(head);
    let diff = tail.wrapping_sub(cursor);
    if tail.wrapping_sub(head) > size || diff > size {
        return Err(fail(RingErrorCode::TailOutOfRange));
    }
    if diff == 0 {
        e.cursor = Some(cursor);
        return Ok(None);
    }
    // 確保の前に記録器の上限を検査する。
    if let Some(outcome) = recorder.precheck(u64::from(diff)) {
        let stop_line = match outcome {
            RecordOutcome::Stopped(reason) => {
                Some(log::record_stopped_line(reason, recorder.record_count()))
            }
            _ => None,
        };
        return Err((RingErrorCode::RecordStopped, stop_line));
    }
    let diff_len = usize::try_from(diff).map_err(|_| fail(RingErrorCode::TailOutOfRange))?;
    let mut buf = vec![0u8; diff_len];
    let pos = u64::from(cursor & (size - 1));
    let first = u64::from(diff).min(u64::from(size) - pos);
    let first_len = usize::try_from(first).map_err(|_| fail(RingErrorCode::TailOutOfRange))?;
    let buf_abs = l
        .offset
        .checked_add(l.buffer_offset)
        .ok_or(fail(RingErrorCode::OutOfRange))?;
    let map_read = |er: BlobReadError| {
        fail(match er {
            BlobReadError::NotHeld => RingErrorCode::BlobNotHeld,
            BlobReadError::OutOfRange => RingErrorCode::OutOfRange,
            BlobReadError::ReadFailed => RingErrorCode::ReadFailed,
        })
    };
    let (a, b) = buf.split_at_mut(first_len);
    blobs
        .read_exact_at(
            l.res_id,
            buf_abs
                .checked_add(pos)
                .ok_or(fail(RingErrorCode::OutOfRange))?,
            a,
        )
        .map_err(map_read)?;
    if !b.is_empty() {
        blobs
            .read_exact_at(l.res_id, buf_abs, b)
            .map_err(map_read)?;
    }
    let seqno = recorder.record_count();
    match recorder.record(&buf) {
        RecordOutcome::Recorded => {
            e.cursor = Some(tail);
            Ok(Some(log::ring_record_line(
                e.ring_id, l.res_id, cursor, tail, diff, seqno,
            )))
        }
        RecordOutcome::Stopped(reason) => Err((
            RingErrorCode::RecordStopped,
            Some(log::record_stopped_line(reason, recorder.record_count())),
        )),
        RecordOutcome::Skipped => Err(fail(RingErrorCode::RecordStopped)),
    }
}

#[cfg(test)]
mod tests;
