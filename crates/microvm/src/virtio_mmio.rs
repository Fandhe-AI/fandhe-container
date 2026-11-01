//! virtio-mmio（modern・Version = 2）の共通トランスポート（TASK-74.2.1・MVM-1・MVM-4。OS 非依存）。
//!
//! virtio-block（TASK-74.2.2）と virtio-net（TASK-74.3.1）が共有するレジスタ状態・デバイス状態の遷移・
//! feature negotiation・キュー設定レジスタを 1 か所に置く。各デバイスは [`VirtioDevice`] を実装し、
//! [`VirtioMmioTransport`] に包んで使う。`KVM_RUN` の MMIO exit からは TASK-74.4.2 が
//! [`VirtioMmioTransport::read`] / [`VirtioMmioTransport::write`] を呼び、結果の
//! [`MmioWriteOutcome::QueueNotify`] 等で virtqueue 処理へ振り分ける。割り込みの実配送は TASK-74.2.3・74.3.2。
//!
//! # 範囲外（REPAIR-3）
//! - ゲストメモリへのアクセスと `GuestAddress` 型: キューのアドレスはドライバが書いた値を組み立てた素の `u64` で
//!   持つだけで、アドレスとしての検証は担当の sub-issue に残す（docs/design/microvm-memory-ownership.md）
//! - legacy（Version = 1）・packed virtqueue・共有メモリ領域レジスタは非対応（未知のレジスタとして無視する）
//!
//! # 準拠先
//! OASIS "Virtual I/O Device (VIRTIO) Version 1.2" の 4.2.2（MMIO レジスタ配置）・2.1（Device Status）・
//! 2.2（Feature Bits）・3.1.1（初期化手順）。定数は仕様書本文から取り、rust-vmm 等の実装は参照しない（MVM-4）。
//!
//! # 外部入力の扱い
//! レジスタへの値・オフセット・幅はすべてゲストが決める非信頼入力。panic・添字アクセスを使わず、
//! 不正なアクセスは [`IgnoredAccess`] つきで無視して呼び出し元へ返す（ホストのエラーにはしない）。
//! `unsafe` は使わない。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// 設定空間の先頭オフセット（仕様 4.2.2。0x100 以降がデバイス固有）。
const CONFIG_BASE: u64 = 0x100;
/// 設定空間の最大バイト数（上限を固定してゲスト値でのアロケーションを避ける）。
pub const CONFIG_SPACE_SIZE: u64 = 0x100;
/// デバイスが持てるキュー数の上限。
pub const MAX_QUEUES: usize = 8;
/// split virtqueue のキュー長の上限（仕様 2.7）。
pub const MAX_QUEUE_SIZE: u16 = 32768;
/// MagicValue（仕様 4.2.2。ASCII "virt" のリトルエンディアン）。
pub const MAGIC_VALUE: u32 = 0x7472_6976;
/// Version レジスタの値（modern = 2。仕様 4.2.2）。
pub const MMIO_VERSION: u32 = 2;
/// VendorID。本プロジェクトとして 0 を返す（ゲストのドライバは VendorID で振る舞いを変えない前提）。
pub const VENDOR_ID: u32 = 0;

/// レジスタオフセット（仕様 4.2.2 の表）。
mod reg {
    pub const MAGIC: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const CONFIG_GENERATION: u64 = 0x0fc;
}

/// デバイス種別（Device ID。仕様 5.1・5.2 および 4.2.2 の DeviceID）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VirtioDeviceType {
    /// ネットワークカード（Device ID 1）。
    Net,
    /// ブロックデバイス（Device ID 2）。
    Block,
}

impl VirtioDeviceType {
    /// DeviceID レジスタの値。
    pub const fn id(self) -> u32 {
        match self {
            VirtioDeviceType::Net => 1,
            VirtioDeviceType::Block => 2,
        }
    }
}

/// feature ビット集合（64 ビット。仕様 2.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FeatureBits(u64);

impl FeatureBits {
    /// 空集合。
    pub const EMPTY: FeatureBits = FeatureBits(0);
    /// `VIRTIO_F_VERSION_1`（bit 32。仕様 6）。modern では必須。
    pub const VERSION_1: FeatureBits = FeatureBits(1 << 32);

    /// 生のビット列から作る。
    pub const fn from_bits(bits: u64) -> Self {
        FeatureBits(bits)
    }

    /// 生のビット列。
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// 和集合。
    pub const fn union(self, other: FeatureBits) -> Self {
        FeatureBits(self.0 | other.0)
    }

    /// `other` のビットをすべて含むか。
    pub const fn contains(self, other: FeatureBits) -> bool {
        self.0 & other.0 == other.0
    }

    /// `other` の部分集合か。
    pub const fn is_subset_of(self, other: FeatureBits) -> bool {
        other.contains(self)
    }

    /// 32 ビット窓（`sel` = 0 で下位、1 で上位）。それ以外の `sel` は `None`。
    pub const fn window(self, sel: u32) -> Option<u32> {
        match sel {
            0 => Some(self.0 as u32),
            1 => Some((self.0 >> 32) as u32),
            _ => None,
        }
    }
}

/// Device Status（仕様 2.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DeviceStatus(u32);

impl DeviceStatus {
    /// ゲストが当該デバイスを認識した。
    pub const ACKNOWLEDGE: DeviceStatus = DeviceStatus(1);
    /// ゲストがドライバを持っている。
    pub const DRIVER: DeviceStatus = DeviceStatus(2);
    /// ドライバが動作可能。
    pub const DRIVER_OK: DeviceStatus = DeviceStatus(4);
    /// feature negotiation 完了。
    pub const FEATURES_OK: DeviceStatus = DeviceStatus(8);
    /// デバイスがリセットを要求している。
    pub const DEVICE_NEEDS_RESET: DeviceStatus = DeviceStatus(64);
    /// ドライバが失敗を宣言した。
    pub const FAILED: DeviceStatus = DeviceStatus(128);
    /// 定義済みビットの全体。
    const KNOWN: u32 = 1 | 2 | 4 | 8 | 64 | 128;

    /// 生の値。
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// `other` のビットをすべて含むか。
    pub const fn contains(self, other: DeviceStatus) -> bool {
        self.0 & other.0 == other.0
    }
}

/// InterruptStatus に立てる理由（仕様 4.2.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptReason {
    /// 使用済みバッファの通知（bit 0）。
    UsedBuffer,
    /// 設定変更の通知（bit 1）。
    ConfigChange,
}

impl InterruptReason {
    const fn bit(self) -> u32 {
        match self {
            InterruptReason::UsedBuffer => 1,
            InterruptReason::ConfigChange => 2,
        }
    }
}

/// 1 キュー分の設定（ドライバが書いた値。アドレスは検証前の素の値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueConfig {
    max_size: u16,
    size: u16,
    ready: bool,
    desc_table: u64,
    driver_area: u64,
    device_area: u64,
}

impl QueueConfig {
    /// デバイスが許すキュー長の上限。
    pub const fn max_size(&self) -> u16 {
        self.max_size
    }
    /// ドライバが設定したキュー長（未設定は 0）。
    pub const fn size(&self) -> u16 {
        self.size
    }
    /// QueueReady が立っているか。
    pub const fn ready(&self) -> bool {
        self.ready
    }
    /// descriptor table のゲスト物理アドレス（素の値）。
    pub const fn desc_table(&self) -> u64 {
        self.desc_table
    }
    /// driver area（avail ring）のゲスト物理アドレス（素の値）。
    pub const fn driver_area(&self) -> u64 {
        self.driver_area
    }
    /// device area（used ring）のゲスト物理アドレス（素の値）。
    pub const fn device_area(&self) -> u64 {
        self.device_area
    }

    fn reset(&mut self) {
        *self = QueueConfig {
            max_size: self.max_size,
            ..QueueConfig::default()
        };
    }
}

/// トランスポートが無視したアクセスの理由（REPAIR-4: 呼び出し元がログ・監査へ回せる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IgnoredAccess {
    /// 幅が 4 バイトでない・整列していない（設定空間は 1/2/4/8 バイトの自然整列以外）。
    UnalignedOrBadWidth,
    /// 未定義のレジスタ。
    UnknownRegister,
    /// 読み取り専用レジスタへの書き込み。
    ReadOnlyRegister,
    /// 書き込み専用レジスタの読み取り（0 を返した）。
    WriteOnlyRegister,
    /// Sel や QueueNotify の値が範囲外。
    InvalidSelector,
    /// QueueNum が 0・最大超・2 のべきでない。
    InvalidQueueSize,
    /// QueueReady を立てる条件（size 設定済み・アドレス整列）を満たさない・値が不正。
    InvalidQueueState,
    /// ready のキューへの再設定。
    QueueAlreadyReady,
    /// 現在のデバイス状態では受け付けない書き込み。
    WrongDeviceState,
    /// 設定空間の範囲外。
    ConfigOutOfRange,
    /// オフセット + 幅の桁あふれ。
    OffsetOverflow,
}

/// 読み取りの結果。読み取りの値は呼び出し元の `data` に書かれる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmioReadOutcome {
    /// 処理した。
    Handled,
    /// 無視した（`data` は 0 で埋める）。
    Ignored(IgnoredAccess),
}

/// 書き込みの結果。呼び出し元が副作用（kick・割り込み等）を振り分けるために使う。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmioWriteOutcome {
    /// 状態を更新しただけ。
    Handled,
    /// 無視した。
    Ignored(IgnoredAccess),
    /// 指定キューが kick された。
    QueueNotify(u16),
    /// FEATURES_OK が立った（negotiation 成功）。
    FeaturesAccepted,
    /// negotiation 失敗。FEATURES_OK は立てていない。
    FeaturesRejected,
    /// DRIVER_OK が立ち、デバイスが activate された。
    DeviceActivated,
    /// activate に失敗した。DEVICE_NEEDS_RESET を立てた。
    ActivationFailed(MicrovmError),
    /// Status への 0 の書き込みでリセットした。
    DeviceReset,
    /// ドライバが FAILED を宣言した。
    DriverFailed,
}

/// virtio デバイス本体（block・net）が実装する口。
///
/// トランスポートが Version・DeviceID・feature negotiation・キュー設定を処理し、デバイスは自分固有の
/// feature・設定空間・activate だけを担う。
pub trait VirtioDevice {
    /// デバイス種別。
    fn device_type(&self) -> VirtioDeviceType;
    /// デバイス固有の feature（`VERSION_1` はトランスポートが常に加えるので含めなくてよい）。
    fn device_features(&self) -> FeatureBits;
    /// キューごとの最大長（要素数がキュー数。`new` で検証される）。
    fn queue_max_sizes(&self) -> &[u16];
    /// 設定空間の読み取り（`offset` は設定空間先頭からの相対。範囲はトランスポートが検査済み）。
    fn read_config(&self, offset: u64, data: &mut [u8]);
    /// 設定空間の書き込み（同上）。
    fn write_config(&mut self, offset: u64, data: &[u8]);
    /// DRIVER_OK に達したとき 1 回呼ばれる。失敗は DEVICE_NEEDS_RESET になる。
    fn activate(
        &mut self,
        features: FeatureBits,
        queues: &[QueueConfig],
    ) -> Result<(), MicrovmError>;
    /// Status へ 0 が書かれたとき呼ばれる。
    fn reset(&mut self);
}

/// virtio-mmio modern トランスポート。
#[derive(Debug)]
pub struct VirtioMmioTransport<D: VirtioDevice> {
    device: D,
    status: DeviceStatus,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: [u32; 2],
    negotiated: Option<FeatureBits>,
    queue_sel: u32,
    queues: Vec<QueueConfig>,
    interrupt_status: u32,
    config_generation: u32,
}

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

impl<D: VirtioDevice> VirtioMmioTransport<D> {
    /// デバイスの記述（キュー数・最大長）を検証して作る。不正なら `InvalidArgument`（fail-closed）。
    pub fn new(device: D) -> Result<Self, MicrovmError> {
        let sizes = device.queue_max_sizes();
        if sizes.is_empty() || sizes.len() > MAX_QUEUES {
            return Err(invalid("queue count out of range"));
        }
        let mut queues = Vec::with_capacity(sizes.len());
        for &max in sizes {
            if max == 0 || max > MAX_QUEUE_SIZE || !max.is_power_of_two() {
                return Err(invalid(
                    "queue max size must be a power of two in 1..=32768",
                ));
            }
            queues.push(QueueConfig {
                max_size: max,
                ..QueueConfig::default()
            });
        }
        Ok(Self {
            device,
            status: DeviceStatus::default(),
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            negotiated: None,
            queue_sel: 0,
            queues,
            interrupt_status: 0,
            config_generation: 0,
        })
    }

    /// 現在の Device Status。
    pub fn status(&self) -> DeviceStatus {
        self.status
    }
    /// negotiation 済みの feature（FEATURES_OK 後だけ `Some`）。
    pub fn negotiated_features(&self) -> Option<FeatureBits> {
        self.negotiated
    }
    /// キュー設定（範囲外は `None`）。
    pub fn queue(&self, index: usize) -> Option<&QueueConfig> {
        self.queues.get(index)
    }
    /// InterruptStatus の現在値。
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }
    /// デバイス本体への参照。
    pub fn device(&self) -> &D {
        &self.device
    }
    /// デバイス本体への可変参照。
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// 使用済みバッファ等の割り込み要因を立てる（実配送は TASK-74.2.3・74.3.2）。
    pub fn raise_interrupt(&mut self, reason: InterruptReason) {
        self.interrupt_status |= reason.bit();
        // VIRTIO 1.2 4.2.2: ConfigGeneration はデバイス側が設定を変えたときだけ進める
        // （ドライバの書き込みでは進めない）。
        if matches!(reason, InterruptReason::ConfigChange) {
            self.config_generation = self.config_generation.wrapping_add(1);
        }
    }

    fn offered_features(&self) -> FeatureBits {
        self.device.device_features().union(FeatureBits::VERSION_1)
    }

    fn selected_queue(&self) -> Option<usize> {
        let idx = usize::try_from(self.queue_sel).ok()?;
        (idx < self.queues.len()).then_some(idx)
    }

    /// MMIO 読み取り。値はリトルエンディアンで `data` に書く。
    pub fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        data.fill(0);
        if offset >= CONFIG_BASE {
            return match self.config_range(offset, data.len()) {
                Ok(rel) => {
                    self.device.read_config(rel, data);
                    MmioReadOutcome::Handled
                }
                Err(why) => MmioReadOutcome::Ignored(why),
            };
        }
        if data.len() != 4 || !offset.is_multiple_of(4) {
            return MmioReadOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth);
        }
        let value = match offset {
            reg::MAGIC => MAGIC_VALUE,
            reg::VERSION => MMIO_VERSION,
            reg::DEVICE_ID => self.device.device_type().id(),
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => self
                .offered_features()
                .window(self.device_features_sel)
                .unwrap_or(0),
            reg::QUEUE_NUM_MAX => self
                .selected_queue()
                .and_then(|i| self.queues.get(i))
                .map_or(0, |q| u32::from(q.max_size)),
            reg::QUEUE_READY => self
                .selected_queue()
                .and_then(|i| self.queues.get(i))
                .map_or(0, |q| u32::from(q.ready)),
            reg::INTERRUPT_STATUS => self.interrupt_status,
            reg::STATUS => self.status.0,
            reg::CONFIG_GENERATION => self.config_generation,
            reg::DEVICE_FEATURES_SEL
            | reg::DRIVER_FEATURES
            | reg::DRIVER_FEATURES_SEL
            | reg::QUEUE_SEL
            | reg::QUEUE_NUM
            | reg::QUEUE_NOTIFY
            | reg::INTERRUPT_ACK
            | reg::QUEUE_DESC_LOW
            | reg::QUEUE_DESC_HIGH
            | reg::QUEUE_DRIVER_LOW
            | reg::QUEUE_DRIVER_HIGH
            | reg::QUEUE_DEVICE_LOW
            | reg::QUEUE_DEVICE_HIGH => {
                return MmioReadOutcome::Ignored(IgnoredAccess::WriteOnlyRegister);
            }
            _ => return MmioReadOutcome::Ignored(IgnoredAccess::UnknownRegister),
        };
        data.copy_from_slice(&value.to_le_bytes());
        MmioReadOutcome::Handled
    }

    /// MMIO 書き込み。`data` はリトルエンディアン。
    pub fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        if offset >= CONFIG_BASE {
            return match self.config_range(offset, data.len()) {
                Ok(rel) => {
                    self.device.write_config(rel, data);
                    MmioWriteOutcome::Handled
                }
                Err(why) => MmioWriteOutcome::Ignored(why),
            };
        }
        let Ok(bytes) = <[u8; 4]>::try_from(data) else {
            return MmioWriteOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth);
        };
        if !offset.is_multiple_of(4) {
            return MmioWriteOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth);
        }
        let value = u32::from_le_bytes(bytes);
        match self.write_reg(offset, value) {
            Ok(outcome) => outcome,
            Err(why) => MmioWriteOutcome::Ignored(why),
        }
    }

    /// 設定空間のアクセスを検査し、設定空間先頭からの相対オフセットを返す。
    fn config_range(&self, offset: u64, len: usize) -> Result<u64, IgnoredAccess> {
        if !matches!(len, 1 | 2 | 4 | 8) {
            return Err(IgnoredAccess::UnalignedOrBadWidth);
        }
        let rel = offset
            .checked_sub(CONFIG_BASE)
            .ok_or(IgnoredAccess::UnknownRegister)?;
        let len = len as u64;
        let end = rel.checked_add(len).ok_or(IgnoredAccess::OffsetOverflow)?;
        if end > CONFIG_SPACE_SIZE {
            return Err(IgnoredAccess::ConfigOutOfRange);
        }
        if !rel.is_multiple_of(len) {
            return Err(IgnoredAccess::UnalignedOrBadWidth);
        }
        Ok(rel)
    }

    /// キュー設定を書ける状態か（FEATURES_OK 済み・DRIVER_OK 前・異常状態でない）。
    fn queue_config_writable(&self) -> bool {
        self.status.contains(DeviceStatus::FEATURES_OK)
            && !self.status.contains(DeviceStatus::DRIVER_OK)
            && !self.status.contains(DeviceStatus::FAILED)
            && !self.status.contains(DeviceStatus::DEVICE_NEEDS_RESET)
    }

    /// 書き込み可能な（未 ready の）選択中キューを返す。
    fn writable_queue(&mut self) -> Result<&mut QueueConfig, IgnoredAccess> {
        if !self.queue_config_writable() {
            return Err(IgnoredAccess::WrongDeviceState);
        }
        let idx = self
            .selected_queue()
            .ok_or(IgnoredAccess::InvalidSelector)?;
        let q = self
            .queues
            .get_mut(idx)
            .ok_or(IgnoredAccess::InvalidSelector)?;
        if q.ready {
            return Err(IgnoredAccess::QueueAlreadyReady);
        }
        Ok(q)
    }

    fn write_reg(&mut self, offset: u64, value: u32) -> Result<MmioWriteOutcome, IgnoredAccess> {
        match offset {
            reg::DEVICE_FEATURES_SEL => {
                self.device_features_sel = value;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::DRIVER_FEATURES_SEL => {
                self.driver_features_sel = value;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::DRIVER_FEATURES => {
                if !self.status.contains(DeviceStatus::DRIVER)
                    || self.status.contains(DeviceStatus::FEATURES_OK)
                {
                    return Err(IgnoredAccess::WrongDeviceState);
                }
                let slot = usize::try_from(self.driver_features_sel)
                    .ok()
                    .and_then(|i| self.driver_features.get_mut(i))
                    .ok_or(IgnoredAccess::InvalidSelector)?;
                *slot = value;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::QUEUE_SEL => {
                self.queue_sel = value;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::QUEUE_NUM => {
                let q = self.writable_queue()?;
                let size = u16::try_from(value).map_err(|_| IgnoredAccess::InvalidQueueSize)?;
                if size == 0 || size > q.max_size || !size.is_power_of_two() {
                    return Err(IgnoredAccess::InvalidQueueSize);
                }
                q.size = size;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::QUEUE_READY => self.write_queue_ready(value),
            reg::QUEUE_DESC_LOW => self.write_addr(value, |q| &mut q.desc_table, false),
            reg::QUEUE_DESC_HIGH => self.write_addr(value, |q| &mut q.desc_table, true),
            reg::QUEUE_DRIVER_LOW => self.write_addr(value, |q| &mut q.driver_area, false),
            reg::QUEUE_DRIVER_HIGH => self.write_addr(value, |q| &mut q.driver_area, true),
            reg::QUEUE_DEVICE_LOW => self.write_addr(value, |q| &mut q.device_area, false),
            reg::QUEUE_DEVICE_HIGH => self.write_addr(value, |q| &mut q.device_area, true),
            reg::QUEUE_NOTIFY => {
                if !self.status.contains(DeviceStatus::DRIVER_OK) {
                    return Err(IgnoredAccess::WrongDeviceState);
                }
                let idx = usize::try_from(value).map_err(|_| IgnoredAccess::InvalidSelector)?;
                let q = self.queues.get(idx).ok_or(IgnoredAccess::InvalidSelector)?;
                if !q.ready {
                    return Err(IgnoredAccess::WrongDeviceState);
                }
                let index = u16::try_from(value).map_err(|_| IgnoredAccess::InvalidSelector)?;
                Ok(MmioWriteOutcome::QueueNotify(index))
            }
            reg::INTERRUPT_ACK => {
                self.interrupt_status &= !value;
                Ok(MmioWriteOutcome::Handled)
            }
            reg::STATUS => Ok(self.write_status(value)),
            reg::MAGIC
            | reg::VERSION
            | reg::DEVICE_ID
            | reg::VENDOR_ID
            | reg::DEVICE_FEATURES
            | reg::QUEUE_NUM_MAX
            | reg::INTERRUPT_STATUS
            | reg::CONFIG_GENERATION => Err(IgnoredAccess::ReadOnlyRegister),
            _ => Err(IgnoredAccess::UnknownRegister),
        }
    }

    fn write_addr(
        &mut self,
        value: u32,
        field: impl FnOnce(&mut QueueConfig) -> &mut u64,
        high: bool,
    ) -> Result<MmioWriteOutcome, IgnoredAccess> {
        let q = self.writable_queue()?;
        let slot = field(q);
        *slot = if high {
            (*slot & 0xffff_ffff) | (u64::from(value) << 32)
        } else {
            (*slot & !0xffff_ffff) | u64::from(value)
        };
        Ok(MmioWriteOutcome::Handled)
    }

    fn write_queue_ready(&mut self, value: u32) -> Result<MmioWriteOutcome, IgnoredAccess> {
        if !self.queue_config_writable() {
            return Err(IgnoredAccess::WrongDeviceState);
        }
        let idx = self
            .selected_queue()
            .ok_or(IgnoredAccess::InvalidSelector)?;
        let q = self
            .queues
            .get_mut(idx)
            .ok_or(IgnoredAccess::InvalidSelector)?;
        match value {
            0 => q.ready = false,
            1 => {
                // split virtqueue の整列要件（仕様 2.7: descriptor table 16・avail 2・used 4）。
                if q.size == 0
                    || !q.desc_table.is_multiple_of(16)
                    || !q.driver_area.is_multiple_of(2)
                    || !q.device_area.is_multiple_of(4)
                {
                    return Err(IgnoredAccess::InvalidQueueState);
                }
                q.ready = true;
            }
            _ => return Err(IgnoredAccess::InvalidQueueState),
        }
        Ok(MmioWriteOutcome::Handled)
    }

    fn write_status(&mut self, value: u32) -> MmioWriteOutcome {
        if value == 0 {
            self.reset();
            return MmioWriteOutcome::DeviceReset;
        }
        let ignored = MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState);
        let current = self.status;
        let new = DeviceStatus(value);
        // 未定義ビット・ドライバからの NEEDS_RESET・ビットを落とす書き込み・異常状態からの書き込みは無視する。
        let driver_sets_needs_reset = new.contains(DeviceStatus::DEVICE_NEEDS_RESET)
            && !current.contains(DeviceStatus::DEVICE_NEEDS_RESET);
        if value & !DeviceStatus::KNOWN != 0
            || driver_sets_needs_reset
            || !new.contains(current)
            || current.contains(DeviceStatus::FAILED)
            || current.contains(DeviceStatus::DEVICE_NEEDS_RESET)
        {
            return ignored;
        }
        let added = DeviceStatus(value & !current.0);
        if added.contains(DeviceStatus::FAILED) {
            self.status = new;
            return MmioWriteOutcome::DriverFailed;
        }
        // 3.1.1 の順序: ACKNOWLEDGE → DRIVER → FEATURES_OK → DRIVER_OK。
        let has = |s: DeviceStatus| new.contains(s);
        let ordered = (!has(DeviceStatus::DRIVER) || has(DeviceStatus::ACKNOWLEDGE))
            && (!has(DeviceStatus::FEATURES_OK)
                || (has(DeviceStatus::ACKNOWLEDGE) && has(DeviceStatus::DRIVER)))
            && (!has(DeviceStatus::DRIVER_OK) || has(DeviceStatus::FEATURES_OK));
        let both =
            added.contains(DeviceStatus::FEATURES_OK) && added.contains(DeviceStatus::DRIVER_OK);
        if !ordered || both {
            return ignored;
        }
        if added.contains(DeviceStatus::FEATURES_OK) {
            return self.negotiate(new);
        }
        if added.contains(DeviceStatus::DRIVER_OK) {
            let features = self.negotiated.unwrap_or(FeatureBits::EMPTY);
            self.status = new;
            return match self.device.activate(features, &self.queues) {
                Ok(()) => MmioWriteOutcome::DeviceActivated,
                Err(err) => {
                    self.status = DeviceStatus(new.0 | DeviceStatus::DEVICE_NEEDS_RESET.0);
                    MmioWriteOutcome::ActivationFailed(err)
                }
            };
        }
        self.status = new;
        MmioWriteOutcome::Handled
    }

    /// FEATURES_OK を立てる書き込みの処理（仕様 3.1.1 の手順 6〜7）。fail-closed。
    fn negotiate(&mut self, new: DeviceStatus) -> MmioWriteOutcome {
        let driver = FeatureBits::from_bits(
            u64::from(self.driver_features[0]) | (u64::from(self.driver_features[1]) << 32),
        );
        if driver.is_subset_of(self.offered_features()) && driver.contains(FeatureBits::VERSION_1) {
            self.negotiated = Some(driver);
            self.status = new;
            MmioWriteOutcome::FeaturesAccepted
        } else {
            self.negotiated = None;
            self.status = DeviceStatus(new.0 & !DeviceStatus::FEATURES_OK.0);
            MmioWriteOutcome::FeaturesRejected
        }
    }

    fn reset(&mut self) {
        self.status = DeviceStatus::default();
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = [0; 2];
        self.negotiated = None;
        self.queue_sel = 0;
        self.interrupt_status = 0;
        for q in &mut self.queues {
            q.reset();
        }
        self.device.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy {
        ty: VirtioDeviceType,
        feats: u64,
        sizes: Vec<u16>,
        config: [u8; 16],
        fail_activate: bool,
        activated: Option<(FeatureBits, Vec<QueueConfig>)>,
        resets: u32,
    }

    impl Dummy {
        fn new(ty: VirtioDeviceType, feats: u64, sizes: Vec<u16>) -> Self {
            Dummy {
                ty,
                feats,
                sizes,
                config: [0; 16],
                fail_activate: false,
                activated: None,
                resets: 0,
            }
        }
    }

    impl VirtioDevice for Dummy {
        fn device_type(&self) -> VirtioDeviceType {
            self.ty
        }
        fn device_features(&self) -> FeatureBits {
            FeatureBits::from_bits(self.feats)
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &self.sizes
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            for (i, b) in data.iter_mut().enumerate() {
                *b = self.config.get(offset as usize + i).copied().unwrap_or(0);
            }
        }
        fn write_config(&mut self, offset: u64, data: &[u8]) {
            for (i, b) in data.iter().enumerate() {
                if let Some(s) = self.config.get_mut(offset as usize + i) {
                    *s = *b;
                }
            }
        }
        fn activate(&mut self, f: FeatureBits, q: &[QueueConfig]) -> Result<(), MicrovmError> {
            if self.fail_activate {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "activate failed",
                ));
            }
            self.activated = Some((f, q.to_vec()));
            Ok(())
        }
        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    type T = VirtioMmioTransport<Dummy>;

    fn rd(t: &T, off: u64) -> u32 {
        let mut b = [0u8; 4];
        assert_eq!(t.read(off, &mut b), MmioReadOutcome::Handled);
        u32::from_le_bytes(b)
    }
    fn wr(t: &mut T, off: u64, v: u32) -> MmioWriteOutcome {
        t.write(off, &v.to_le_bytes())
    }
    fn ign(why: IgnoredAccess) -> MmioWriteOutcome {
        MmioWriteOutcome::Ignored(why)
    }

    fn block() -> T {
        VirtioMmioTransport::new(Dummy::new(VirtioDeviceType::Block, 0x1234, vec![256])).unwrap()
    }
    fn net() -> T {
        VirtioMmioTransport::new(Dummy::new(VirtioDeviceType::Net, 0x20, vec![256, 128, 64]))
            .unwrap()
    }

    fn to_driver(t: &mut T) {
        assert_eq!(wr(t, reg::STATUS, 1), MmioWriteOutcome::Handled);
        assert_eq!(wr(t, reg::STATUS, 3), MmioWriteOutcome::Handled);
    }
    /// 提示された feature をそのまま要求して FEATURES_OK まで進める。
    fn negotiate_ok(t: &mut T) {
        to_driver(t);
        wr(t, reg::DEVICE_FEATURES_SEL, 0);
        let lo = rd(t, reg::DEVICE_FEATURES);
        wr(t, reg::DEVICE_FEATURES_SEL, 1);
        let hi = rd(t, reg::DEVICE_FEATURES);
        wr(t, reg::DRIVER_FEATURES_SEL, 0);
        wr(t, reg::DRIVER_FEATURES, lo);
        wr(t, reg::DRIVER_FEATURES_SEL, 1);
        wr(t, reg::DRIVER_FEATURES, hi);
        assert_eq!(wr(t, reg::STATUS, 11), MmioWriteOutcome::FeaturesAccepted);
    }
    fn setup_queue(t: &mut T, i: u32, size: u32) {
        wr(t, reg::QUEUE_SEL, i);
        assert_eq!(wr(t, reg::QUEUE_NUM, size), MmioWriteOutcome::Handled);
        wr(t, reg::QUEUE_DESC_LOW, 0x1000);
        wr(t, reg::QUEUE_DESC_HIGH, 0x1);
        wr(t, reg::QUEUE_DRIVER_LOW, 0x2002);
        wr(t, reg::QUEUE_DEVICE_LOW, 0x3004);
        assert_eq!(wr(t, reg::QUEUE_READY, 1), MmioWriteOutcome::Handled);
    }

    #[test]
    fn mvm1_identification_registers() {
        let b = block();
        assert_eq!(rd(&b, reg::MAGIC), 0x7472_6976);
        assert_eq!(rd(&b, reg::VERSION), 2);
        assert_eq!(rd(&b, reg::DEVICE_ID), 2);
        assert_eq!(rd(&b, reg::VENDOR_ID), 0);
        assert_eq!(rd(&net(), reg::DEVICE_ID), 1);
    }

    fn full_init(mut t: T) {
        wr(&mut t, reg::STATUS, 0);
        negotiate_ok(&mut t);
        assert_eq!(rd(&t, reg::STATUS) & 8, 8);
        let n = t.device().queue_max_sizes().len() as u32;
        for i in 0..n {
            setup_queue(&mut t, i, 64);
        }
        assert_eq!(
            wr(&mut t, reg::STATUS, 15),
            MmioWriteOutcome::DeviceActivated
        );
        let (f, qs) = t.device().activated.clone().unwrap();
        assert_eq!(f, t.negotiated_features().unwrap());
        assert!(f.contains(FeatureBits::VERSION_1));
        assert_eq!(qs.len() as u32, n);
        for q in &qs {
            assert_eq!((q.size(), q.ready()), (64, true));
            assert_eq!(q.desc_table(), 0x1_0000_1000);
            assert_eq!(q.driver_area(), 0x2002);
            assert_eq!(q.device_area(), 0x3004);
        }
        assert_eq!(
            wr(&mut t, reg::QUEUE_NOTIFY, 0),
            MmioWriteOutcome::QueueNotify(0)
        );
    }

    #[test]
    fn mvm1_full_init_block_and_net() {
        full_init(block());
        full_init(net());
    }

    #[test]
    fn mvm1_feature_windows() {
        let mut t = block();
        wr(&mut t, reg::DEVICE_FEATURES_SEL, 0);
        assert_eq!(rd(&t, reg::DEVICE_FEATURES), 0x1234);
        wr(&mut t, reg::DEVICE_FEATURES_SEL, 1);
        assert_eq!(rd(&t, reg::DEVICE_FEATURES), 1);
        wr(&mut t, reg::DEVICE_FEATURES_SEL, 2);
        assert_eq!(rd(&t, reg::DEVICE_FEATURES), 0);
    }

    #[test]
    fn mvm1_negotiation_rejects_unoffered_and_missing_version1() {
        let mut t = block();
        to_driver(&mut t);
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
        wr(&mut t, reg::DRIVER_FEATURES, 0x8000_0000);
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 1);
        wr(&mut t, reg::DRIVER_FEATURES, 1);
        assert_eq!(
            wr(&mut t, reg::STATUS, 11),
            MmioWriteOutcome::FeaturesRejected
        );
        assert_eq!(rd(&t, reg::STATUS), 3);
        assert_eq!(t.negotiated_features(), None);
        // VERSION_1 を落とした要求も拒否。
        wr(&mut t, reg::DRIVER_FEATURES, 0);
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
        wr(&mut t, reg::DRIVER_FEATURES, 0x1234);
        assert_eq!(
            wr(&mut t, reg::STATUS, 11),
            MmioWriteOutcome::FeaturesRejected
        );
        // FEATURES_OK 前の DRIVER_OK は無視。
        assert_eq!(
            wr(&mut t, reg::STATUS, 7),
            ign(IgnoredAccess::WrongDeviceState)
        );
        assert_eq!(rd(&t, reg::STATUS), 3);
    }

    #[test]
    fn mvm1_status_transitions() {
        let mut t = block();
        // ACKNOWLEDGE なしの DRIVER は無視。
        assert_eq!(
            wr(&mut t, reg::STATUS, 2),
            ign(IgnoredAccess::WrongDeviceState)
        );
        // ビットを落とす書き込みは無視。
        to_driver(&mut t);
        assert_eq!(
            wr(&mut t, reg::STATUS, 1),
            ign(IgnoredAccess::WrongDeviceState)
        );
        let mut t = block();
        negotiate_ok(&mut t);
        // FEATURES_OK 後の DriverFeatures は無視。
        assert_eq!(
            wr(&mut t, reg::DRIVER_FEATURES, 5),
            ign(IgnoredAccess::WrongDeviceState)
        );
        // ドライバが DEVICE_NEEDS_RESET を立てる書き込みは無視。
        assert_eq!(
            wr(&mut t, reg::STATUS, 11 | 64),
            ign(IgnoredAccess::WrongDeviceState)
        );
        assert_eq!(
            wr(&mut t, reg::STATUS, 11 | 128),
            MmioWriteOutcome::DriverFailed
        );
        assert_eq!(rd(&t, reg::STATUS), 139);
    }

    #[test]
    fn mvm1_reset_clears_state_keeps_queue_max() {
        let mut t = net();
        negotiate_ok(&mut t);
        setup_queue(&mut t, 1, 32);
        t.raise_interrupt(InterruptReason::UsedBuffer);
        assert_eq!(wr(&mut t, reg::STATUS, 0), MmioWriteOutcome::DeviceReset);
        assert_eq!(t.device().resets, 1);
        assert_eq!(t.status().bits(), 0);
        assert_eq!(t.negotiated_features(), None);
        assert_eq!(t.interrupt_status(), 0);
        let q = t.queue(1).unwrap();
        assert_eq!(
            (q.size(), q.ready(), q.desc_table(), q.max_size()),
            (0, false, 0, 128)
        );
    }

    #[test]
    fn mvm1_activate_failure_sets_needs_reset() {
        let mut t = block();
        t.device_mut().fail_activate = true;
        negotiate_ok(&mut t);
        setup_queue(&mut t, 0, 8);
        assert!(matches!(
            wr(&mut t, reg::STATUS, 15),
            MmioWriteOutcome::ActivationFailed(_)
        ));
        assert_eq!(rd(&t, reg::STATUS), 15 | 64);
    }

    #[test]
    fn mvm1_queue_register_validation() {
        let mut t = net();
        // FEATURES_OK 前はキュー設定を書けない。
        assert_eq!(
            wr(&mut t, reg::QUEUE_NUM, 8),
            ign(IgnoredAccess::WrongDeviceState)
        );
        negotiate_ok(&mut t);
        wr(&mut t, reg::QUEUE_SEL, 3);
        assert_eq!(rd(&t, reg::QUEUE_NUM_MAX), 0);
        assert_eq!(
            wr(&mut t, reg::QUEUE_NUM, 8),
            ign(IgnoredAccess::InvalidSelector)
        );
        wr(&mut t, reg::QUEUE_SEL, 0);
        assert_eq!(rd(&t, reg::QUEUE_NUM_MAX), 256);
        for bad in [0, 3, 512, 0x1_0000] {
            assert_eq!(
                wr(&mut t, reg::QUEUE_NUM, bad),
                ign(IgnoredAccess::InvalidQueueSize)
            );
        }
        // size 未設定・非整列では ready にならない。
        assert_eq!(
            wr(&mut t, reg::QUEUE_READY, 1),
            ign(IgnoredAccess::InvalidQueueState)
        );
        wr(&mut t, reg::QUEUE_NUM, 16);
        wr(&mut t, reg::QUEUE_DESC_LOW, 0x1008);
        assert_eq!(
            wr(&mut t, reg::QUEUE_READY, 1),
            ign(IgnoredAccess::InvalidQueueState)
        );
        wr(&mut t, reg::QUEUE_DESC_LOW, 0x1000);
        assert_eq!(wr(&mut t, reg::QUEUE_READY, 1), MmioWriteOutcome::Handled);
        assert_eq!(rd(&t, reg::QUEUE_READY), 1);
        // ready のキューの再設定は無視。
        assert_eq!(
            wr(&mut t, reg::QUEUE_NUM, 8),
            ign(IgnoredAccess::QueueAlreadyReady)
        );
        assert_eq!(t.queue(0).unwrap().size(), 16);
    }

    #[test]
    fn mvm1_notify_and_interrupts() {
        let mut t = net();
        assert_eq!(
            wr(&mut t, reg::QUEUE_NOTIFY, 0),
            ign(IgnoredAccess::WrongDeviceState)
        );
        negotiate_ok(&mut t);
        setup_queue(&mut t, 0, 16);
        wr(&mut t, reg::STATUS, 15);
        assert_eq!(
            wr(&mut t, reg::QUEUE_NOTIFY, 1),
            ign(IgnoredAccess::WrongDeviceState)
        );
        assert_eq!(
            wr(&mut t, reg::QUEUE_NOTIFY, 9),
            ign(IgnoredAccess::InvalidSelector)
        );
        assert_eq!(
            wr(&mut t, reg::QUEUE_NOTIFY, 0),
            MmioWriteOutcome::QueueNotify(0)
        );
        t.raise_interrupt(InterruptReason::UsedBuffer);
        assert_eq!(rd(&t, reg::INTERRUPT_STATUS), 1);
        t.raise_interrupt(InterruptReason::ConfigChange);
        assert_eq!(rd(&t, reg::INTERRUPT_STATUS), 3);
        wr(&mut t, reg::INTERRUPT_ACK, 1);
        assert_eq!(rd(&t, reg::INTERRUPT_STATUS), 2);
    }

    #[test]
    fn mvm1_access_width_and_range() {
        let mut t = block();
        let mut b8 = [0xffu8; 8];
        assert_eq!(
            t.read(reg::MAGIC, &mut b8),
            MmioReadOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(b8, [0; 8]);
        let mut b4 = [0xffu8; 4];
        assert_eq!(
            t.read(2, &mut b4),
            MmioReadOutcome::Ignored(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(b4, [0; 4]);
        assert_eq!(
            t.read(0x0a8, &mut b4),
            MmioReadOutcome::Ignored(IgnoredAccess::UnknownRegister)
        );
        assert_eq!(
            t.write(reg::STATUS, &[1, 0]),
            ign(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(
            wr(&mut t, reg::MAGIC, 1),
            ign(IgnoredAccess::ReadOnlyRegister)
        );
        assert_eq!(
            t.read(reg::QUEUE_NUM, &mut b4),
            MmioReadOutcome::Ignored(IgnoredAccess::WriteOnlyRegister)
        );
        assert_eq!(t.write(0x0a8, &[0; 4]), ign(IgnoredAccess::UnknownRegister));
        // 設定空間。
        assert_eq!(t.write(0x100, &[1, 2, 3, 4]), MmioWriteOutcome::Handled);
        // ドライバの書き込みでは ConfigGeneration は進まない。
        assert_eq!(rd(&t, reg::CONFIG_GENERATION), 0);
        assert_eq!(rd(&t, 0x100), 0x0403_0201);
        t.raise_interrupt(InterruptReason::ConfigChange);
        assert_eq!(rd(&t, reg::CONFIG_GENERATION), 1);
        assert_eq!(
            t.write(0x1fc, &[0; 8]),
            ign(IgnoredAccess::ConfigOutOfRange)
        );
        assert_eq!(
            t.write(u64::MAX - 1, &[0; 4]),
            ign(IgnoredAccess::ConfigOutOfRange)
        );
        assert_eq!(
            t.write(0x101, &[0; 4]),
            ign(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(
            t.write(0x100, &[0; 3]),
            ign(IgnoredAccess::UnalignedOrBadWidth)
        );
        assert_eq!(rd(&t, reg::CONFIG_GENERATION), 1);
    }

    #[test]
    fn mvm1_new_validates_device_description() {
        let mk = |s: Vec<u16>| VirtioMmioTransport::new(Dummy::new(VirtioDeviceType::Block, 0, s));
        for bad in [
            vec![],
            vec![8; 9],
            vec![0],
            vec![3],
            vec![0x8001],
            vec![0xffff],
        ] {
            let err = mk(bad).err().unwrap();
            assert_eq!(err.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert!(mk(vec![32768]).is_ok());
        assert!(mk(vec![1; 8]).is_ok());
    }
}
