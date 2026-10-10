//! vhost-user の要求・応答ペイロードの型と復号・符号化（GPU-6・MVM-4・REPAIR-2・TASK-172 F1.1・#1516）。
//!
//! 役割: [`super::Header`] の検証を通ったメッセージを、要求種別ごとの型付き値へ変換する（逆方向も）。
//! 呼び出し元は後続の F1.2（ソケットから読んだバイト列の復号）と F1.4（応答の符号化）。
//! ここでは値の意味（vring addr のアラインメント・index の範囲・ネゴシエーション済み feature との照合）を検査しない。
//! それらは F1.3（#1518）/ F1.4（#1519）の責務で、本ファイルが検査するのはワイヤー上の予約ビットと個数・長さの上限だけ。
//!
//! 長さと個数は上限を検証してから使い、固定長配列に格納する。生の `Vec<u8>` を手で組まない。

use super::{
    CONFIG_FIXED_LEN, CONFIG_FLAGS_DEFINED, CodecError, CodecErrorCode, Direction, EncodedMessage,
    HEADER_LEN, Header, MAX_CONFIG_SIZE, MAX_MEM_REGIONS, MAX_SHMEM_REGIONS, MEM_REGION_LEN,
    Reader, RequestCode, SHMEM_CONFIG_LEN, SHMEM_PAGE_ALIGN, VRING_INDEX_MASK, VRING_NOFD, Writer,
};

fn err(code: CodecErrorCode, req: RequestCode) -> CodecError {
    CodecError::new(code, Some(req.as_u32()))
}

/// vring の状態（index と num / base / enable）。`SET_VRING_NUM`・`SET_VRING_BASE`・`GET_VRING_BASE`・
/// `SET_VRING_ENABLE` の要求と `GET_VRING_BASE` の応答で共通の 8 バイト。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VringState {
    /// vring index。
    pub index: u32,
    /// num / base / enable のいずれか（要求種別による）。
    pub num: u32,
}

/// `SET_VRING_ADDR` のペイロード（40 バイト）。値の意味（アラインメント・log ビット）はここでは検査せず、`crate::virtqueue::QueueConfig::new`（F1.3・#1518）が検査する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VringAddr {
    /// vring index。
    pub index: u32,
    /// フラグ（log ビット等。意味は `crate::virtqueue::QueueConfig::new` が検査する）。
    pub flags: u32,
    /// descriptor table の user アドレス。
    pub descriptor: u64,
    /// used ring の user アドレス。
    pub used: u64,
    /// available ring の user アドレス。
    pub available: u64,
    /// ログ用アドレス。
    pub log: u64,
}

/// `SET_VRING_KICK` / `SET_VRING_CALL` の u64（bit 0-7 が vring index、bit 8 が「fd なし」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VringFd {
    /// vring index。
    pub index: u8,
    /// fd が添付されない（NOFD）。
    pub no_fd: bool,
}

impl VringFd {
    fn from_u64(v: u64, req: RequestCode) -> Result<Self, CodecError> {
        if v & !(VRING_INDEX_MASK | VRING_NOFD) != 0 {
            return Err(err(CodecErrorCode::InvalidValue, req));
        }
        Ok(Self {
            index: u8::try_from(v & VRING_INDEX_MASK).unwrap_or(0),
            no_fd: v & VRING_NOFD != 0,
        })
    }

    fn to_u64(self) -> u64 {
        u64::from(self.index) | if self.no_fd { VRING_NOFD } else { 0 }
    }
}

/// メモリ領域 1 個（32 バイト）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemRegion {
    /// ゲスト物理アドレス。
    pub guest_phys_addr: u64,
    /// 領域サイズ。
    pub memory_size: u64,
    /// frontend プロセス側の user アドレス。
    pub userspace_addr: u64,
    /// fd 内のオフセット（mmap 用。F1.2）。
    pub mmap_offset: u64,
}

/// `SET_MEM_TABLE` のペイロード。1〜`MAX_MEM_REGIONS` 領域で、範囲外の個数は型として作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemTable {
    regions: [MemRegion; MAX_MEM_REGIONS],
    count: usize,
}

impl MemTable {
    /// 領域列から作る。0 件または上限超過は `INVALID_VALUE`。
    pub fn new(regions: &[MemRegion]) -> Result<Self, CodecError> {
        let bad = || err(CodecErrorCode::InvalidValue, RequestCode::SetMemTable);
        if regions.is_empty() || regions.len() > MAX_MEM_REGIONS {
            return Err(bad());
        }
        let mut table = [MemRegion::default(); MAX_MEM_REGIONS];
        table
            .get_mut(..regions.len())
            .ok_or_else(bad)?
            .copy_from_slice(regions);
        Ok(Self {
            regions: table,
            count: regions.len(),
        })
    }

    /// 有効な領域。
    pub fn regions(&self) -> &[MemRegion] {
        self.regions.get(..self.count).unwrap_or(&[])
    }
}

/// `GET_CONFIG` / `SET_CONFIG` のペイロード（offset・size・flags + データ）。データは `MAX_CONFIG_SIZE` 以下。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigPayload {
    offset: u32,
    flags: u32,
    size: usize,
    data: [u8; MAX_CONFIG_SIZE],
}

impl ConfigPayload {
    /// 作る。データが上限超過、または flags に未定義ビットがあれば `INVALID_VALUE`。
    /// `req` はエラーに載せる要求種別（`GetConfig` / `SetConfig`）。
    pub fn new(req: RequestCode, offset: u32, flags: u32, data: &[u8]) -> Result<Self, CodecError> {
        let bad = || err(CodecErrorCode::InvalidValue, req);
        if flags & !CONFIG_FLAGS_DEFINED != 0 {
            return Err(bad());
        }
        let mut buf = [0u8; MAX_CONFIG_SIZE];
        buf.get_mut(..data.len())
            .ok_or_else(bad)?
            .copy_from_slice(data);
        Ok(Self {
            offset,
            flags,
            size: data.len(),
            data: buf,
        })
    }

    /// config 空間内のオフセット。
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// flags（crosvm の `WRITABLE`=0x1・`LIVE_MIGRATION`=0x2 のビット集合）。
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// データ部。
    pub fn data(&self) -> &[u8] {
        self.data.get(..self.size).unwrap_or(&[])
    }

    fn payload_len(&self) -> usize {
        CONFIG_FIXED_LEN + self.size
    }

    fn read(r: &mut Reader, req: RequestCode) -> Result<Self, CodecError> {
        let offset = r.u32()?;
        let size = r.u32()?;
        let flags = r.u32()?;
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        // 検査順は固定（LENGTH_MISMATCH → INVALID_VALUE）。期待長を先に照合してから上限を検証する。
        if r.remaining() != size {
            return Err(err(CodecErrorCode::LengthMismatch, req));
        }
        if size > MAX_CONFIG_SIZE {
            return Err(err(CodecErrorCode::InvalidValue, req));
        }
        let data = r.bytes(size)?;
        Self::new(req, offset, flags, data)
    }

    fn write(&self, w: &mut Writer) -> Result<(), CodecError> {
        let size = u32::try_from(self.size)
            .map_err(|_| err(CodecErrorCode::InvalidValue, RequestCode::GetConfig))?;
        w.u32(self.offset)?;
        w.u32(size)?;
        w.u32(self.flags)?;
        w.put(self.data())
    }
}

/// 共有メモリ領域 1 個（id と大きさ）。[`ShmemConfig::new`] の入力。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmemRegion {
    /// 領域 id（virtio の shmid。host-visible は 1）。
    pub id: u8,
    /// 領域の大きさ（バイト）。0 ではなく、[`SHMEM_PAGE_ALIGN`] の倍数。
    pub size: u64,
}

/// `GET_SHMEM_CONFIG` の応答（`nregions` u32・padding u32・`sizes` [u64; 256] の 2056 バイト。GPU-6・TASK-172 F5.2b.2・#1641）。
///
/// 配置は「非 0 の領域の数 = `nregions`、`sizes[id]` = その大きさ、未使用は 0」（QEMU rst v11.1.0）。`nregions` はフィールドに持たず
/// `sizes` の非 0 の数から毎回求めるので、両者の食い違いは型として作れない（REPAIR-2）。crosvm は `sizes` を添字つきで走査し非 0 だけを
/// 領域 id として使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmemConfig {
    sizes: [u64; MAX_SHMEM_REGIONS],
}

impl ShmemConfig {
    /// 領域列から作る。大きさが 0・ページの倍数でない、id の重複、件数が 256 超のいずれかは `INVALID_VALUE`
    /// （要求種別は `GetShmemConfig`）。空の列は受理する（`nregions` = 0）。
    pub fn new(regions: &[ShmemRegion]) -> Result<Self, CodecError> {
        let bad = || err(CodecErrorCode::InvalidValue, RequestCode::GetShmemConfig);
        if regions.len() > MAX_SHMEM_REGIONS {
            return Err(bad());
        }
        let mut sizes = [0u64; MAX_SHMEM_REGIONS];
        for r in regions {
            if r.size == 0 || !r.size.is_multiple_of(SHMEM_PAGE_ALIGN) {
                return Err(bad());
            }
            let slot = sizes.get_mut(usize::from(r.id)).ok_or_else(bad)?;
            if *slot != 0 {
                return Err(bad());
            }
            *slot = r.size;
        }
        Ok(Self { sizes })
    }

    /// 非 0 の領域の数。
    pub fn nregions(&self) -> u32 {
        // 256 以下なので変換は失敗しない。
        u32::try_from(self.sizes.iter().filter(|s| **s != 0).count()).unwrap_or(0)
    }

    /// 領域 `id` の大きさ（未使用は 0）。
    pub fn size(&self, id: u8) -> u64 {
        self.sizes.get(usize::from(id)).copied().unwrap_or(0)
    }

    /// 256 個の大きさ（添字が領域 id）。
    pub fn sizes(&self) -> &[u64; MAX_SHMEM_REGIONS] {
        &self.sizes
    }

    fn write(&self, w: &mut Writer) -> Result<(), CodecError> {
        w.u32(self.nregions())?;
        w.u32(0)?;
        for s in &self.sizes {
            w.u64(*s)?;
        }
        Ok(())
    }

    /// frontend 役（試験）の復号。長さを先に照合し（`LENGTH_MISMATCH`）、padding・ページ境界・`nregions` の整合を検査する（`INVALID_VALUE`）。
    fn read(r: &mut Reader) -> Result<Self, CodecError> {
        let code = RequestCode::GetShmemConfig;
        if r.remaining() != SHMEM_CONFIG_LEN {
            return Err(err(CodecErrorCode::LengthMismatch, code));
        }
        let nregions = r.u32()?;
        let padding = r.u32()?;
        let mut sizes = [0u64; MAX_SHMEM_REGIONS];
        for s in &mut sizes {
            *s = r.u64()?;
        }
        let cfg = Self { sizes };
        let aligned = cfg.sizes.iter().all(|s| s.is_multiple_of(SHMEM_PAGE_ALIGN));
        if padding != 0 || !aligned || nregions != cfg.nregions() {
            return Err(err(CodecErrorCode::InvalidValue, code));
        }
        Ok(cfg)
    }
}

/// frontend から backend への要求（最小集合 18 種）。
// 固定長配列で持ちヒープ確保をしない設計（REPAIR-2）のため、バリアント間のサイズ差は許容する。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// `GET_FEATURES`（ペイロードなし）。
    GetFeatures,
    /// `SET_FEATURES`（virtio feature の u64）。
    SetFeatures(u64),
    /// `SET_OWNER`（ペイロードなし）。
    SetOwner,
    /// `SET_MEM_TABLE`。
    SetMemTable(MemTable),
    /// `SET_VRING_NUM`。
    SetVringNum(VringState),
    /// `SET_VRING_ADDR`。
    SetVringAddr(VringAddr),
    /// `SET_VRING_BASE`。
    SetVringBase(VringState),
    /// `GET_VRING_BASE`。
    GetVringBase(VringState),
    /// `SET_VRING_KICK`。
    SetVringKick(VringFd),
    /// `SET_VRING_CALL`。
    SetVringCall(VringFd),
    /// `GET_PROTOCOL_FEATURES`（ペイロードなし）。
    GetProtocolFeatures,
    /// `SET_PROTOCOL_FEATURES`（protocol feature の u64）。
    SetProtocolFeatures(u64),
    /// `GET_QUEUE_NUM`（ペイロードなし）。
    GetQueueNum,
    /// `SET_VRING_ENABLE`。
    SetVringEnable(VringState),
    /// `GET_CONFIG`（要求側もデータ領域を含む）。
    GetConfig(ConfigPayload),
    /// `SET_CONFIG`。
    SetConfig(ConfigPayload),
    /// `SET_BACKEND_REQ_FD`（ペイロードなし。fd 1 本は補助データで届く）。
    SetBackendReqFd,
    /// `GET_SHMEM_CONFIG`（ペイロードなし）。
    GetShmemConfig,
}

/// 復号済みの要求と、ヘッダの `NEED_REPLY`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// 要求本体。
    pub request: Request,
    /// `NEED_REPLY` が立っていたか。
    pub need_reply: bool,
}

/// ヘッダ 12 バイト + ペイロードが連なったバッファを要求として復号する。バッファ長は `12 + size` と完全一致が必要。
pub fn decode_request(buf: &[u8]) -> Result<Decoded, CodecError> {
    let header = Header::decode(buf, Direction::Request)?;
    let total = HEADER_LEN
        .checked_add(header.payload_len())
        .ok_or_else(|| err(CodecErrorCode::LengthMismatch, header.request()))?;
    if buf.len() != total {
        return Err(err(CodecErrorCode::LengthMismatch, header.request()));
    }
    let payload = buf
        .get(HEADER_LEN..)
        .ok_or_else(|| err(CodecErrorCode::LengthMismatch, header.request()))?;
    decode_request_payload(&header, payload)
}

/// 検証済みヘッダとペイロードから要求を復号する（F1.2 が 2 段読みで使う）。`payload` の長さは `header` の size と一致が必要。
pub fn decode_request_payload(header: &Header, payload: &[u8]) -> Result<Decoded, CodecError> {
    let code = header.request();
    if header.is_reply() {
        return Err(err(CodecErrorCode::InvalidFlags, code));
    }
    if payload.len() != header.payload_len() {
        return Err(err(CodecErrorCode::LengthMismatch, code));
    }
    let mut r = Reader::new(payload, code);
    let request = match code {
        RequestCode::GetFeatures => Request::GetFeatures,
        RequestCode::SetOwner => Request::SetOwner,
        RequestCode::GetProtocolFeatures => Request::GetProtocolFeatures,
        RequestCode::GetQueueNum => Request::GetQueueNum,
        RequestCode::SetBackendReqFd => Request::SetBackendReqFd,
        RequestCode::GetShmemConfig => Request::GetShmemConfig,
        RequestCode::SetFeatures => Request::SetFeatures(r.u64()?),
        RequestCode::SetProtocolFeatures => Request::SetProtocolFeatures(r.u64()?),
        RequestCode::SetVringKick => Request::SetVringKick(read_vring_fd(&mut r, code)?),
        RequestCode::SetVringCall => Request::SetVringCall(read_vring_fd(&mut r, code)?),
        RequestCode::SetVringNum => Request::SetVringNum(read_state(&mut r)?),
        RequestCode::SetVringBase => Request::SetVringBase(read_state(&mut r)?),
        RequestCode::GetVringBase => Request::GetVringBase(read_state(&mut r)?),
        RequestCode::SetVringEnable => Request::SetVringEnable(read_state(&mut r)?),
        RequestCode::SetVringAddr => Request::SetVringAddr(VringAddr {
            index: r.u32()?,
            flags: r.u32()?,
            descriptor: r.u64()?,
            used: r.u64()?,
            available: r.u64()?,
            log: r.u64()?,
        }),
        RequestCode::SetMemTable => Request::SetMemTable(read_mem_table(&mut r)?),
        RequestCode::GetConfig => Request::GetConfig(ConfigPayload::read(&mut r, code)?),
        RequestCode::SetConfig => Request::SetConfig(ConfigPayload::read(&mut r, code)?),
    };
    r.finish()?;
    Ok(Decoded {
        request,
        need_reply: header.need_reply(),
    })
}

/// VRING fd 要求のペイロード（u64）を読む。値検証より先に長さ（8 バイトちょうど）を照合する（LENGTH_MISMATCH → INVALID_VALUE）。
fn read_vring_fd(r: &mut Reader, code: RequestCode) -> Result<VringFd, CodecError> {
    if r.remaining() != 8 {
        return Err(err(CodecErrorCode::LengthMismatch, code));
    }
    VringFd::from_u64(r.u64()?, code)
}

fn read_state(r: &mut Reader) -> Result<VringState, CodecError> {
    Ok(VringState {
        index: r.u32()?,
        num: r.u32()?,
    })
}

fn read_mem_table(r: &mut Reader) -> Result<MemTable, CodecError> {
    let n = r.u32()?;
    let _padding = r.u32()?;
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    // 検査順は固定（LENGTH_MISMATCH → INVALID_VALUE）。期待長（飽和乗算なので溢れない）を先に照合する。
    if r.remaining() != n.saturating_mul(MEM_REGION_LEN) {
        return Err(err(
            CodecErrorCode::LengthMismatch,
            RequestCode::SetMemTable,
        ));
    }
    if n == 0 || n > MAX_MEM_REGIONS {
        return Err(err(CodecErrorCode::InvalidValue, RequestCode::SetMemTable));
    }
    let mut regions = [MemRegion::default(); MAX_MEM_REGIONS];
    for slot in regions.iter_mut().take(n) {
        *slot = MemRegion {
            guest_phys_addr: r.u64()?,
            memory_size: r.u64()?,
            userspace_addr: r.u64()?,
            mmap_offset: r.u64()?,
        };
    }
    MemTable::new(regions.get(..n).unwrap_or(&[]))
}

fn write_state(w: &mut Writer, s: &VringState) -> Result<(), CodecError> {
    w.u32(s.index)?;
    w.u32(s.num)
}

impl Request {
    /// 要求種別。
    pub fn code(&self) -> RequestCode {
        match self {
            Self::GetFeatures => RequestCode::GetFeatures,
            Self::SetFeatures(_) => RequestCode::SetFeatures,
            Self::SetOwner => RequestCode::SetOwner,
            Self::SetMemTable(_) => RequestCode::SetMemTable,
            Self::SetVringNum(_) => RequestCode::SetVringNum,
            Self::SetVringAddr(_) => RequestCode::SetVringAddr,
            Self::SetVringBase(_) => RequestCode::SetVringBase,
            Self::GetVringBase(_) => RequestCode::GetVringBase,
            Self::SetVringKick(_) => RequestCode::SetVringKick,
            Self::SetVringCall(_) => RequestCode::SetVringCall,
            Self::GetProtocolFeatures => RequestCode::GetProtocolFeatures,
            Self::SetProtocolFeatures(_) => RequestCode::SetProtocolFeatures,
            Self::GetQueueNum => RequestCode::GetQueueNum,
            Self::SetVringEnable(_) => RequestCode::SetVringEnable,
            Self::GetConfig(_) => RequestCode::GetConfig,
            Self::SetConfig(_) => RequestCode::SetConfig,
            Self::SetBackendReqFd => RequestCode::SetBackendReqFd,
            Self::GetShmemConfig => RequestCode::GetShmemConfig,
        }
    }

    fn payload_len(&self) -> usize {
        match self {
            Self::GetFeatures
            | Self::SetOwner
            | Self::GetProtocolFeatures
            | Self::GetQueueNum
            | Self::SetBackendReqFd
            | Self::GetShmemConfig => 0,
            Self::SetFeatures(_)
            | Self::SetProtocolFeatures(_)
            | Self::SetVringKick(_)
            | Self::SetVringCall(_)
            | Self::SetVringNum(_)
            | Self::SetVringBase(_)
            | Self::GetVringBase(_)
            | Self::SetVringEnable(_) => 8,
            Self::SetVringAddr(_) => 40,
            Self::SetMemTable(t) => 8 + t.count * MEM_REGION_LEN,
            Self::GetConfig(c) | Self::SetConfig(c) => c.payload_len(),
        }
    }

    /// frontend 役（偽の frontend を使う結合テストや F1.4 の自己試験）が送るバイト列へ符号化する。
    pub fn encode(&self, need_reply: bool) -> Result<EncodedMessage, CodecError> {
        let header = Header::new(self.code(), false, need_reply, self.payload_len())?;
        EncodedMessage::build(&header, |w| match self {
            Self::GetFeatures
            | Self::SetOwner
            | Self::GetProtocolFeatures
            | Self::GetQueueNum
            | Self::SetBackendReqFd
            | Self::GetShmemConfig => Ok(()),
            Self::SetFeatures(v) | Self::SetProtocolFeatures(v) => w.u64(*v),
            Self::SetVringKick(f) | Self::SetVringCall(f) => w.u64(f.to_u64()),
            Self::SetVringNum(s)
            | Self::SetVringBase(s)
            | Self::GetVringBase(s)
            | Self::SetVringEnable(s) => write_state(w, s),
            Self::SetVringAddr(a) => {
                w.u32(a.index)?;
                w.u32(a.flags)?;
                w.u64(a.descriptor)?;
                w.u64(a.used)?;
                w.u64(a.available)?;
                w.u64(a.log)
            }
            Self::SetMemTable(t) => {
                let n = u32::try_from(t.count)
                    .map_err(|_| err(CodecErrorCode::InvalidValue, RequestCode::SetMemTable))?;
                w.u32(n)?;
                w.u32(0)?;
                for m in t.regions() {
                    w.u64(m.guest_phys_addr)?;
                    w.u64(m.memory_size)?;
                    w.u64(m.userspace_addr)?;
                    w.u64(m.mmap_offset)?;
                }
                Ok(())
            }
            Self::GetConfig(c) | Self::SetConfig(c) => c.write(w),
        })
    }
}

/// ack の失敗値（非 0 の固定値）。仕様は成功 0・失敗は非 0 とだけ定め、値の意味は無い。
const ACK_FAILURE: u64 = 1;

/// REPLY_ACK 確定後に、応答本体を持たない要求へ NEED_REPLY が立っていたとき返す u64 の ack。
///
/// `GET_*`（`RequestCode::has_reply_body` が真）の要求 ID では作れない。そうしないと frontend が ack の値を
/// features 等の応答値として解釈しうる（REPAIR-2・GPU-6・TASK-172 F5.2b.1・#1639）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    request: RequestCode,
    value: u64,
}

impl Ack {
    fn new(request: RequestCode, value: u64) -> Result<Self, CodecError> {
        if request.has_reply_body() {
            return Err(err(CodecErrorCode::InvalidValue, request));
        }
        Ok(Self { request, value })
    }

    /// 成功（値 0）の ack。
    pub fn success(request: RequestCode) -> Result<Self, CodecError> {
        Self::new(request, 0)
    }

    /// 失敗（非 0 の固定値）の ack。
    pub fn failure(request: RequestCode) -> Result<Self, CodecError> {
        Self::new(request, ACK_FAILURE)
    }

    /// 対応する要求種別。
    pub fn request(&self) -> RequestCode {
        self.request
    }

    /// 応答の u64（0 が成功）。
    pub fn value(&self) -> u64 {
        self.value
    }
}

/// backend から frontend への応答（値を返す 6 種と、REPLY_ACK の ack）。
// 固定長配列で持ちヒープ確保をしない設計（REPAIR-2）のため、バリアント間のサイズ差は許容する。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// `GET_FEATURES` の応答（virtio feature）。
    Features(u64),
    /// `GET_PROTOCOL_FEATURES` の応答。
    ProtocolFeatures(u64),
    /// `GET_QUEUE_NUM` の応答。
    QueueNum(u64),
    /// `GET_VRING_BASE` の応答。
    VringBase(VringState),
    /// `GET_CONFIG` の応答。
    Config(ConfigPayload),
    /// `GET_CONFIG` のエラー応答（仕様どおりヘッダ size = 0 の空ペイロード）。
    ConfigError,
    /// `GET_SHMEM_CONFIG` の応答（2056 バイト）。
    ShmemConfig(ShmemConfig),
    /// NEED_REPLY への ack（REPLY_ACK 確定後。応答本体を持たない要求のみ）。
    Ack(Ack),
}

impl Reply {
    /// 対応する要求種別。
    pub fn code(&self) -> RequestCode {
        match self {
            Self::Features(_) => RequestCode::GetFeatures,
            Self::ProtocolFeatures(_) => RequestCode::GetProtocolFeatures,
            Self::QueueNum(_) => RequestCode::GetQueueNum,
            Self::VringBase(_) => RequestCode::GetVringBase,
            Self::Config(_) | Self::ConfigError => RequestCode::GetConfig,
            Self::ShmemConfig(_) => RequestCode::GetShmemConfig,
            Self::Ack(a) => a.request(),
        }
    }

    /// 応答へ符号化する（flags は version 1 + REPLY）。
    pub fn encode(&self) -> Result<EncodedMessage, CodecError> {
        let len = match self {
            Self::Features(_) | Self::ProtocolFeatures(_) | Self::QueueNum(_) => 8,
            Self::VringBase(_) | Self::Ack(_) => 8,
            Self::Config(c) => c.payload_len(),
            Self::ConfigError => 0,
            Self::ShmemConfig(_) => SHMEM_CONFIG_LEN,
        };
        let header = Header::new(self.code(), true, false, len)?;
        EncodedMessage::build(&header, |w| match self {
            Self::Features(v) | Self::ProtocolFeatures(v) | Self::QueueNum(v) => w.u64(*v),
            Self::Ack(a) => w.u64(a.value()),
            Self::VringBase(s) => write_state(w, s),
            Self::Config(c) => c.write(w),
            Self::ConfigError => Ok(()),
            Self::ShmemConfig(c) => c.write(w),
        })
    }
}

/// backend の応答を復号する（frontend 役の試験用）。`expected` は直前に送った要求で、応答の要求 ID が違えば
/// `INVALID_VALUE`。flags は REPLY 必須・NEED_REPLY 不可。
pub fn decode_reply(buf: &[u8], expected: RequestCode) -> Result<Reply, CodecError> {
    let header = Header::decode(buf, Direction::Reply)?;
    let code = header.request();
    if code != expected {
        return Err(err(CodecErrorCode::InvalidValue, code));
    }
    let total = HEADER_LEN
        .checked_add(header.payload_len())
        .ok_or_else(|| err(CodecErrorCode::LengthMismatch, code))?;
    if buf.len() != total {
        return Err(err(CodecErrorCode::LengthMismatch, code));
    }
    let payload = buf
        .get(HEADER_LEN..)
        .ok_or_else(|| err(CodecErrorCode::LengthMismatch, code))?;
    let mut r = Reader::new(payload, code);
    let reply = match code {
        RequestCode::GetFeatures => Reply::Features(r.u64()?),
        RequestCode::GetProtocolFeatures => Reply::ProtocolFeatures(r.u64()?),
        RequestCode::GetQueueNum => Reply::QueueNum(r.u64()?),
        RequestCode::GetVringBase => Reply::VringBase(read_state(&mut r)?),
        // ペイロード長 0 は GET_CONFIG のエラー応答（仕様）。
        RequestCode::GetConfig if payload.is_empty() => Reply::ConfigError,
        RequestCode::GetConfig => Reply::Config(ConfigPayload::read(&mut r, code)?),
        RequestCode::GetShmemConfig => Reply::ShmemConfig(ShmemConfig::read(&mut r)?),
        // 応答本体を持たない要求（SET_* 等）への応答は ack（u64）。frontend 視点の復号なので値は任意の u64 を受ける。
        // 長さは上の total 照合で確定済みで、u64 が 8 バイトでなければ `r.u64()` / `finish` が LENGTH_MISMATCH にする。
        _ => Reply::Ack(Ack {
            request: code,
            value: r.u64()?,
        }),
    };
    r.finish()?;
    Ok(reply)
}
