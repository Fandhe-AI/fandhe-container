//! WFI の待ちを SPI の注入と停止要求で起こす仕組み（#3887・#3933・MVM-5・MVM-1・REPAIR-5）。OS 非依存・`unsafe` なし。
//!
//! 役割: macOS の `hvf::timer::handle_wfx` は WFI でホスト側に待つ。その待ちを `std::thread::sleep` ではなく
//! [`WfiWaker::wait`] にし、(a) `hv_gic_set_spi` の assert 成功後（`hvf::gic` の SPI sink。virtio の完了通知・シリアル入力）と
//! (b) 停止要求の kick（[`WakingKick`]。`LoopHandle::stop` / drop が `hv_vcpus_exit` の代わりに呼ぶ）から [`WfiWaker::notify`] で
//! 即座に起こす（(a) は宛先の vCPU だけ。#3948）。`hv_*` を呼ばないので Linux の CI で単体試験できる。
//!
//! GIC つきの構成では WFI は exit せず `hv_vcpu_run` の中で待つため、この待ちは macOS 27.2・Apple M4 Max では通らない
//! （#3803・#3994）。別の版・チップで exit した場合のために残す（要否の判断は #3995）。
//!
//! # 契約
//! - 通知は VM 全体で共有する世代番号の加算で、待ち手（[`WfiWaker`] の clone 1 個 = vCPU 1 台）は clone ごとに既読位置を持つ。
//!   1 回の [`WfiWaker::notify`] は、待っている全待ち手を起こす（SMP で最初に起きた 1 台が通知を消費して残りが
//!   `WFI_WAIT_MAX` まで寝る取り合いをなくす。#3933）。各 vCPU は自分専用の clone を持つこと。
//! - 待つ前に届いた通知は各待ち手に 1 回ずつ残り、次の [`WfiWaker::wait`] を 1 回だけ即時に戻す（取りこぼし防止）。
//!   複数回の通知は 1 回の早期再開に畳まれる（セマフォではない）。ゲストの走行中に届いた通知も残るため、次の WFI が
//!   1 回だけ早期に再開する。ゲストは `wfi` を再実行して正しく待つので、WFI の早期再開（spurious wakeup）は
//!   アーキテクチャ上許される範囲に収まる。clone は元の既読位置を写すので、clone 前の通知でも 1 回の早期再開が起こりうる。
//! - 待ちは常に期限つき（呼び出し側が `WFI_WAIT_MAX` を渡す。REPAIR-5）。通知されない起床要因（framework 側で pending に
//!   なる PPI 等）の安全網は、この期限である。世代番号は `wrapping_add` で、ちょうど 2^64 回の通知で 1 回取りこぼしても期限で有界。
//! - 内部の lock が poison されても回復する（世代番号の状態は常に有効）。panic しない。
//!
//! # 宛先指定の起床（#3948・MVM-5・REPAIR-5）
//! #3933 の後は 1 回の SPI で待つ全 vCPU が `hv_vcpu_run` へ再入し、宛先でない vCPU はすぐ WFI へ戻っていた。そこで vCPU ごとに
//! 独立した [`WfiWaker`]（別々の mutex と condvar）を [`WfiWakeSet`] に束ね、SPI の注入は [`WfiWakeSet::notify_spi`] で
//! 宛先の 1 台だけを起こす。宛先は、framework 側の GIC のルーティング（`GICD_IROUTER<n>`。`hv_gic_get_distributor_reg` で読む。
//! macOS 15.0 以降。#3960）を主とし、読めない・1 台に決まらないときの縮退先を [`SpiRouteHint`] とする（決定規則は
//! [`spi_wake_target`]、起床は [`WfiWakeSet::notify_spi_routed`]）。ヒントはホストから見える `InterruptACK` の MMIO 書き込みを
//! 処理した vCPU を [`AckRouteLearner`] が記録した値である（virtio-mmio ドライバは割り込みハンドラの中で ACK を書くため、
//! ACK した vCPU が宛先である）。
//! - ルーティングが読めて IRM = 0・affinity が割り当て済みの vCPU に当たれば、その 1 台（ヒントが食い違ってもルーティングが勝つ）。
//!   ゲストが affinity を移した直後も、次の assert から新しい宛先を起こせる。
//! - 読めない・IRM = 1（1-of-N）・書式違反・該当 vCPU なしのときはヒント。ヒントも無い（未学習）・範囲外の index は全台を起こす
//!   （取りこぼさない側に倒す）。
//! - 停止要求の kick（[`WakingKick`]）と VM の終了通知は常に全台を起こす（[`WfiWakeSet::notify_all`]）。
//! - vCPU 1 台の構成では従来の単一 waker と同じ効果になる。
//! - スロットの mutex は 1 個ずつ取り入れ子にしない。ヒントは atomic で lock ではない。
//!
//! # 残余（REPAIR-3）
//! - ルーティングが読めないとき（macOS 15 未満の想定外・シンボル欠落・framework の失敗）は従来のヒントに縮退する。ヒントは学習値の
//!   ため、ゲストが irq affinity を移した直後・CPU_OFF の直後は古いままになりうる。その 1 回は新しい宛先が最大 `WFI_WAIT_MAX`
//!   （10 ms）遅れて起きる（待ちは常に期限つきで有界）。新しい宛先が次の ACK を書くとヒントは自己修復する。
//! - シリアル（UART の level 線）は ACK の経路が違うため学習しない。ルーティングが読めれば宛先の 1 台だけを起こし、読めなければ全台。
//! - 縮退は理由別に数え、理由ごとの初回だけ構造化ログを 1 行出す（#3974・REPAIR-4。[`SpiRouting`]）。`GICD_CTLR.ARE` は
//!   ARE = 1 を観測するまで assert のたびに読み、ARE = 0・読めないときは IROUTER を使わずヒントへ縮退する。ARE = 1 を観測したら
//!   ラッチして以後は読まない（ARE = 0 を恒久キャッシュすると、最初の assert がゲストの GIC 初期化より前に来た VM は
//!   寿命の間ずっと IROUTER を使えない。ARE を 1 から 0 へ戻すのは distributor 無効化後でないと UNPREDICTABLE のためラッチは安全）。
//!   実機の `GICD_CTLR` は DS = 1 の単一セキュリティ状態の値で、非 vCPU スレッドから `GICD_IROUTER48` も読めた（#3803）。件数は 2^64 回で巻き戻り、初回ログが再度出うる（実害なし）。
//! - 毎回の assert で IROUTER を 1 回読む。コストが問題になればキャッシュ（affinity の変更検知）を別 issue で検討する（未計測。読み出し自体の要否は #3995）。
//! - 通知されない起床要因（PPI 等）は従来どおり `WFI_WAIT_MAX` の期限が安全網である。

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::arm64_layout::arm64_vcpu_index_from_affinity;
use crate::error::MicrovmError;
use crate::error::MicrovmErrorCode;
use crate::hvf_abi::{
    GicDistributorReg, GicdCtlrAre, HVF_MAX_VCPUS, IrouterRoute, decode_gicd_ctlr_are,
    decode_irouter,
};
use crate::hvf_loop::VcpuKick;

/// [`WfiWaker::wait`] の戻り。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// 通知で戻った（待つ前の通知を含む）。
    Notified,
    /// 通知が無く、期限で戻った。
    TimedOut,
}

/// WFI の待ちを起こす通知口。clone は同じ世代番号（通知）を共有するが、既読位置は clone ごとに持つ
/// （VM・SPI の sink で共有し、vCPU スレッドごとに 1 個の clone を割り当てる。#3933）。
#[derive(Default)]
pub struct WfiWaker {
    inner: Arc<(Mutex<u64>, Condvar)>,
    /// この clone が観測済みの世代。`inner` の mutex を持つ間だけ読み書きする。
    seen: AtomicU64,
}

impl Clone for WfiWaker {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            seen: AtomicU64::new(self.seen.load(Ordering::Relaxed)),
        }
    }
}

impl fmt::Debug for WfiWaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WfiWaker").finish_non_exhaustive()
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WfiWaker>();
};

impl WfiWaker {
    /// 世代を進めて、待っている全スレッドを起こす。アロケーションも待ちも持たない。
    pub fn notify(&self) {
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        cv.notify_all();
    }

    /// 通知か `limit` の期限まで待つ。この clone の既読位置まで進めて戻る。`limit` が 0 なら待たずに世代だけ見る。
    pub fn wait(&self, limit: Duration) -> WakeOutcome {
        let (lock, cv) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let seen = self.seen.load(Ordering::Relaxed);
        let (guard, _) = cv
            .wait_timeout_while(guard, limit, |g| *g == seen)
            .unwrap_or_else(|e| e.into_inner());
        if *guard != seen {
            self.seen.store(*guard, Ordering::Relaxed);
            WakeOutcome::Notified
        } else {
            WakeOutcome::TimedOut
        }
    }
}

/// 待っている全 vCPU を起こす口。停止要求の kick（[`WakingKick`]）が使う（#3948）。
pub trait WakeAll: Send + Sync + 'static {
    /// 待っている全スレッドを起こす。
    fn wake_all(&self);
}

impl WakeAll for WfiWaker {
    fn wake_all(&self) {
        self.notify();
    }
}

/// vCPU ごとに独立した [`WfiWaker`] の束（#3948・MVM-5・REPAIR-5）。
///
/// `hvf::gic::VmWithGic` が VM につき 1 個持ち、vCPU スレッドは [`Self::handle`] で自分のスロットの clone を受け取って待つ。
/// SPI の sink は [`Self::notify_spi`]、停止要求・VM の終了は [`Self::notify_all`] で起こす。スロットごとに mutex と condvar が
/// 別なので、宛先以外のスレッドは OS のレベルでも起きない。
#[derive(Clone)]
pub struct WfiWakeSet {
    slots: Arc<[WfiWaker]>,
}

impl fmt::Debug for WfiWakeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WfiWakeSet")
            .field("vcpus", &self.slots.len())
            .finish()
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WfiWakeSet>();
};

impl WfiWakeSet {
    /// `vcpus` 台分のスロットを作る。0 と [`HVF_MAX_VCPUS`] 超は `InvalidArgument`（台数は host の構成値で、確保はここで 1 回だけ）。
    pub fn new(vcpus: u32) -> Result<Self, MicrovmError> {
        if vcpus == 0 || vcpus > HVF_MAX_VCPUS {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "wake set vcpu count out of range",
            ));
        }
        let slots: Vec<WfiWaker> = (0..vcpus).map(|_| WfiWaker::default()).collect();
        Ok(Self {
            slots: slots.into(),
        })
    }

    /// vCPU `index` 専用の待ち手（スロットの clone）。範囲外は `InvalidArgument`。各 vCPU は自分のスロットだけで待つこと。
    pub fn handle(&self, index: u32) -> Result<WfiWaker, MicrovmError> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.slots.get(i))
            .cloned()
            .ok_or_else(|| {
                MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "wake set vcpu index out of range",
                )
            })
    }

    /// 全スロットを起こす（停止要求・VM の終了・宛先不明）。スロットの mutex は 1 個ずつ取る。
    pub fn notify_all(&self) {
        for w in self.slots.iter() {
            w.notify();
        }
    }

    /// vCPU `index` のスロットだけを起こす。範囲外なら取りこぼさないよう全台を起こす。
    pub fn notify_vcpu(&self, index: u32) {
        match usize::try_from(index).ok().and_then(|i| self.slots.get(i)) {
            Some(w) => w.notify(),
            None => self.notify_all(),
        }
    }

    /// SPI の注入後の起床。ヒントがあればその vCPU だけ、無ければ（未学習）全台を起こす。
    pub fn notify_spi(&self, route: &SpiRouteHint) {
        match route.get() {
            Some(i) => self.notify_vcpu(i),
            None => self.notify_all(),
        }
    }

    /// SPI の注入後の起床（#3960・MVM-5）。`irouter`（`GICD_IROUTER<n>` の生値。読めなければ `None`）が主、`route`（学習した
    /// ヒント）が縮退先。宛先の決定は [`spi_wake_target`]。
    pub fn notify_spi_routed(&self, irouter: Option<u64>, route: &SpiRouteHint) {
        self.notify_target(spi_wake_target(irouter, route.get(), self.vcpus()));
    }

    /// 決定済みの宛先を起こす（#3974）。
    pub fn notify_target(&self, target: SpiWakeTarget) {
        match target {
            SpiWakeTarget::Vcpu(i) => self.notify_vcpu(i),
            SpiWakeTarget::All => self.notify_all(),
        }
    }

    /// スロットの数（vCPU 数）。
    pub fn vcpus(&self) -> u32 {
        u32::try_from(self.slots.len()).unwrap_or(0)
    }
}

/// SPI の起床の宛先（#3960）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiWakeTarget {
    /// この vCPU だけを起こす。
    Vcpu(u32),
    /// 全台を起こす（宛先を決められない。取りこぼさない側）。
    All,
}

/// SPI の宛先 vCPU を決める純関数（#3960・MVM-5・REPAIR-5）。
///
/// 1. `irouter` が読めて、IRM = 0・書式が正しく・affinity が `vcpus` 台の割り当てに当たるなら、その vCPU（ヒントが食い違っても
///    ルーティングが勝つ）。
/// 2. 決まらない場合（読めない・IRM = 1・書式違反・該当 vCPU なし）は、ヒントが `vcpus` 未満ならその vCPU。
/// 3. それ以外は全台。
///
/// `irouter` はゲストが書く非信頼値。結果は「どの vCPU を起こすか」だけに効き、誤っても `WFI_WAIT_MAX` で有界。
pub fn spi_wake_target(irouter: Option<u64>, hint: Option<u32>, vcpus: u32) -> SpiWakeTarget {
    if let Some(raw) = irouter
        && let Ok(i) = classify_irouter(raw, vcpus)
    {
        return SpiWakeTarget::Vcpu(i);
    }
    fallback_target(hint, vcpus)
}

/// IROUTER の生値から宛先 vCPU を決める。決まらなければ縮退の理由（#3974）。
fn classify_irouter(raw: u64, vcpus: u32) -> Result<u32, SpiRouteFallback> {
    match decode_irouter(raw) {
        IrouterRoute::Affinity(aff) => {
            arm64_vcpu_index_from_affinity(aff, vcpus).ok_or(SpiRouteFallback::OutOfRange)
        }
        IrouterRoute::AnyParticipating => Err(SpiRouteFallback::AnyParticipating),
        IrouterRoute::Malformed => Err(SpiRouteFallback::Malformed),
    }
}

/// 縮退先: ヒントが `vcpus` 未満ならその vCPU、そうでなければ全台。
fn fallback_target(hint: Option<u32>, vcpus: u32) -> SpiWakeTarget {
    match hint {
        Some(i) if i < vcpus => SpiWakeTarget::Vcpu(i),
        _ => SpiWakeTarget::All,
    }
}

/// SPI の宛先をルーティングから決められず縮退した理由（#3974・MVM-5・REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiRouteFallback {
    /// 読み出しが `Unimplemented`（シンボル無し・macOS 15 未満）。
    Unavailable,
    /// 読み出しのその他の失敗（framework の失敗・拒否）。
    Failed,
    /// IROUTER の RES0 違反、または `GICD_CTLR` の上位 32 ビットが 0 でない。
    Malformed,
    /// IRM = 0 の affinity が割り当て済みの vCPU に当たらない。
    OutOfRange,
    /// `GICD_CTLR.ARE` = 0。IROUTER は意味を持たないので読まない。
    AreDisabled,
    /// IRM = 1（1-of-N）。読み出しの失敗ではなくゲストの正当な選択だが、宛先を 1 台に決められず縮退する。
    AnyParticipating,
}

impl SpiRouteFallback {
    /// 全理由（件数の添字の順）。
    pub const ALL: [Self; 6] = [
        Self::Unavailable,
        Self::Failed,
        Self::Malformed,
        Self::OutOfRange,
        Self::AreDisabled,
        Self::AnyParticipating,
    ];

    /// ログ・メトリクス用の固定文字列。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
            Self::Malformed => "malformed",
            Self::OutOfRange => "out-of-range",
            Self::AreDisabled => "are-disabled",
            Self::AnyParticipating => "any-participating",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Unavailable => 0,
            Self::Failed => 1,
            Self::Malformed => 2,
            Self::OutOfRange => 3,
            Self::AreDisabled => 4,
            Self::AnyParticipating => 5,
        }
    }

    /// 読み出しの失敗を理由と code に分類する。
    fn from_read_error(e: &MicrovmError) -> (Self, Option<MicrovmErrorCode>) {
        let reason = if e.code() == MicrovmErrorCode::Unimplemented {
            Self::Unavailable
        } else {
            Self::Failed
        };
        (reason, Some(e.code()))
    }
}

/// `GICD_*` レジスタの読み手。本番は `hvf::gic` の sink（`hv_gic_get_distributor_reg`）、試験は偽物。
pub trait GicdRegisterRead {
    /// レジスタの生値を読む。
    fn read(&self, reg: GicDistributorReg) -> Result<u64, MicrovmError>;
}

/// 理由別の縮退件数の写し（#3974）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpiRouteStatsSnapshot {
    counts: [u64; 6],
}

impl SpiRouteStatsSnapshot {
    /// `reason` の件数。
    pub fn count(&self, reason: SpiRouteFallback) -> u64 {
        self.counts.get(reason.index()).copied().unwrap_or(0)
    }

    /// 全理由の合計（飽和加算）。
    pub fn total(&self) -> u64 {
        self.counts.iter().fold(0u64, |a, c| a.saturating_add(*c))
    }
}

/// [`SpiRouting::resolve`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiRouteDecision {
    /// 起こす宛先。
    pub target: SpiWakeTarget,
    /// 縮退したときの理由。ルーティングで決まれば `None`。
    pub fallback: Option<SpiRouteFallback>,
    /// 読み出しの失敗に由来する縮退のときの失敗コード（ログ用）。
    pub code: Option<MicrovmErrorCode>,
    /// 縮退の理由として初回（ログを出す）か。
    pub first: bool,
}

#[derive(Debug, Default)]
struct SpiRoutingInner {
    counts: [AtomicU64; 6],
    are_enabled: AtomicBool,
}

type RouteError = (SpiRouteFallback, Option<MicrovmErrorCode>);

/// VM ごとの SPI ルーティングの共有状態（#3974・MVM-5・REPAIR-4）。縮退の理由別件数と、ARE のラッチを持つ。
///
/// `hvf::gic` の sink が clone を共有し、assert 成功のたびに [`Self::resolve`] で宛先を決める。件数はアロケーションしない
/// 固定長の atomic で、ゲストが不正な値を書き続けてもログは理由ごとの初回しか出ない。`Relaxed` なのは、値で他のデータを
/// 公開しない統計であり、ARE のラッチも誤っても次の assert で直る（起床先が変わるだけで `WFI_WAIT_MAX` で有界）ため。
#[derive(Debug, Clone, Default)]
pub struct SpiRouting(Arc<SpiRoutingInner>);

impl SpiRouting {
    /// 理由別件数の写し。
    pub fn snapshot(&self) -> SpiRouteStatsSnapshot {
        let mut counts = [0u64; 6];
        for (dst, src) in counts.iter_mut().zip(self.0.counts.iter()) {
            *dst = src.load(Ordering::Relaxed);
        }
        SpiRouteStatsSnapshot { counts }
    }

    /// 縮退を 1 件数える。その理由で初回なら `true`。
    fn record(&self, reason: SpiRouteFallback) -> bool {
        self.0
            .counts
            .get(reason.index())
            .is_some_and(|c| c.fetch_add(1, Ordering::Relaxed) == 0)
    }

    /// 宛先を決める。ARE が未確認なら `GICD_CTLR` を読み、ARE = 1 のときだけ `GICD_IROUTER<intid>` を読む。
    /// `hint` は縮退先（学習した宛先）。`hv_*` は `reader` の中だけ。
    pub fn resolve<R: GicdRegisterRead>(
        &self,
        reader: &R,
        intid: u32,
        hint: Option<u32>,
        vcpus: u32,
    ) -> SpiRouteDecision {
        match self.route(reader, intid, vcpus) {
            Ok(i) => SpiRouteDecision {
                target: SpiWakeTarget::Vcpu(i),
                fallback: None,
                code: None,
                first: false,
            },
            Err((reason, code)) => SpiRouteDecision {
                target: fallback_target(hint, vcpus),
                fallback: Some(reason),
                code,
                first: self.record(reason),
            },
        }
    }

    fn route<R: GicdRegisterRead>(
        &self,
        reader: &R,
        intid: u32,
        vcpus: u32,
    ) -> Result<u32, RouteError> {
        if !self.0.are_enabled.load(Ordering::Relaxed) {
            let raw = reader
                .read(GicDistributorReg::ctlr())
                .map_err(|e| SpiRouteFallback::from_read_error(&e))?;
            match decode_gicd_ctlr_are(raw) {
                GicdCtlrAre::Enabled => self.0.are_enabled.store(true, Ordering::Relaxed),
                GicdCtlrAre::Disabled => return Err((SpiRouteFallback::AreDisabled, None)),
                GicdCtlrAre::Malformed => return Err((SpiRouteFallback::Malformed, None)),
            }
        }
        let reg = GicDistributorReg::irouter(intid)
            .map_err(|e| (SpiRouteFallback::Failed, Some(e.code())))?;
        let raw = reader
            .read(reg)
            .map_err(|e| SpiRouteFallback::from_read_error(&e))?;
        classify_irouter(raw, vcpus).map_err(|r| (r, None))
    }
}

/// 縮退の初回ログの 1 行（#3974・REPAIR-4）。ゲスト由来の値は埋め込まない固定文言。`code` は読み出しの失敗の分類。
pub fn spi_route_fallback_log_line(
    reason: SpiRouteFallback,
    code: Option<MicrovmErrorCode>,
) -> String {
    let code = code
        .map(|c| format!(" code={}", c.as_str()))
        .unwrap_or_default();
    format!(
        "level=warn op=hvf.gic.spi_route outcome=fallback reason={}{code} message=\"gic routing is not used; waking the learned hint or all vcpus (logged once per reason)\"",
        reason.as_str()
    )
}

impl WakeAll for WfiWakeSet {
    fn wake_all(&self) {
        self.notify_all();
    }
}

/// ある SPI 線の宛先 vCPU のヒント（#3948）。`u32::MAX` が「不明」。
///
/// ヒントにすぎず、誤っても `WFI_WAIT_MAX` の期限で有界なので `Relaxed` で足りる（値の順序で他のデータを公開しない）。
/// 値は host 側の vCPU index だけで、ゲスト由来の値は入らない。
#[derive(Debug, Clone)]
pub struct SpiRouteHint(Arc<AtomicU32>);

const ROUTE_UNKNOWN: u32 = u32::MAX;

impl SpiRouteHint {
    /// 宛先不明の状態で作る。
    pub fn unknown() -> Self {
        Self(Arc::new(AtomicU32::new(ROUTE_UNKNOWN)))
    }

    /// 宛先の vCPU を記録する（`u32::MAX` は不明の番兵のため記録しても不明のまま）。
    pub fn record(&self, vcpu: u32) {
        self.0.store(vcpu, Ordering::Relaxed);
    }

    /// 記録された宛先。無ければ `None`。
    pub fn get(&self) -> Option<u32> {
        match self.0.load(Ordering::Relaxed) {
            ROUTE_UNKNOWN => None,
            v => Some(v),
        }
    }
}

/// `InterruptACK` を処理した vCPU を、その線の宛先として [`SpiRouteHint`] に記録する部品（#3948）。
///
/// vCPU スレッドごとに 1 個持つ（`hvf::mmio::handle_data_abort` の ACK の分岐から呼ばれる）。キー数は組み立て時に host が作った
/// 線の数で決まり、ゲストはキーを足せない。キーは `hvf::mmio` では `DeviceId`。
#[derive(Debug, Clone)]
pub struct AckRouteLearner<K> {
    vcpu: u32,
    hints: Vec<(K, SpiRouteHint)>,
}

impl<K: PartialEq> AckRouteLearner<K> {
    /// vCPU `vcpu` が処理する ACK を `hints` の線へ記録する learner を作る。
    pub fn new(vcpu: u32, hints: Vec<(K, SpiRouteHint)>) -> Self {
        Self { vcpu, hints }
    }

    /// `device` の ACK をこの vCPU が処理した。未登録のキーは何もしない。
    pub fn on_interrupt_ack(&self, device: &K) {
        if let Some((_, hint)) = self.hints.iter().find(|(k, _)| k == device) {
            hint.record(self.vcpu);
        }
    }
}

/// `inner.kick()` の後に全 vCPU の待ちを起こす [`VcpuKick`]。停止要求で WFI の待ちも起こす。
///
/// `hvf::vcpu` が `VcpuCanceller` を包んで `spawn_loop` へ渡す。`inner` の成否によらず起こし、`inner` の結果を返す
/// （vCPU 破棄後の kick が失敗しても、待っているスレッドは起こす）。`W` は [`WfiWaker`]（単一）か [`WfiWakeSet`]（全台。#3948）。
#[derive(Debug)]
pub struct WakingKick<K, W = WfiWaker> {
    inner: K,
    waker: W,
}

impl<K: VcpuKick, W: WakeAll> WakingKick<K, W> {
    /// `inner` と `waker` を束ねる。
    pub fn new(inner: K, waker: W) -> Self {
        Self { inner, waker }
    }
}

impl<K: VcpuKick, W: WakeAll> VcpuKick for WakingKick<K, W> {
    fn kick(&self) -> Result<(), MicrovmError> {
        let r = self.inner.kick();
        self.waker.wake_all();
        r
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MicrovmErrorCode;
    use crate::hvf_abi::HvRunStats;
    use crate::hvf_loop::spawn_loop;
    use crate::stop::StopReason;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    #[derive(Debug)]
    struct FakeKick(Result<(), MicrovmErrorCode>);

    impl VcpuKick for FakeKick {
        fn kick(&self) -> Result<(), MicrovmError> {
            self.0
                .map_err(|c| MicrovmError::new(c, "fake kick failure"))
        }
    }

    #[test]
    fn repair5_mvm5_3887_notify_from_thread_wakes_within_100ms() {
        let w = WfiWaker::default();
        let w2 = w.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1));
            w2.notify();
        });
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(100));
        t.join().unwrap();
    }

    #[test]
    fn repair5_mvm5_3887_pending_notify_returns_without_waiting() {
        let w = WfiWaker::default();
        w.notify();
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(50));
        // 通知は消費されている。
        assert_eq!(w.wait(Duration::from_millis(20)), WakeOutcome::TimedOut);
    }

    #[test]
    fn repair5_mvm5_3887_no_notify_times_out_at_limit() {
        let w = WfiWaker::default();
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_millis(50)), WakeOutcome::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn repair5_mvm5_3887_zero_limit_does_not_block() {
        let w = WfiWaker::default();
        assert_eq!(w.wait(Duration::ZERO), WakeOutcome::TimedOut);
        w.notify();
        assert_eq!(w.wait(Duration::ZERO), WakeOutcome::Notified);
    }

    #[test]
    fn repair5_mvm5_3887_waking_kick_notifies_even_if_inner_fails() {
        let w = WfiWaker::default();
        let k = WakingKick::new(
            FakeKick(Err(MicrovmErrorCode::FailedPrecondition)),
            w.clone(),
        );
        let e = k.kick().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    /// 停止要求の kick が、WFI の待ちを模した長い `wait` を起こして `Requested` で止まる（結線の照合）。
    #[test]
    fn repair5_mvm5_3887_stop_wakes_blocked_wfi_wait() {
        let waker = WfiWaker::default();
        let body_waker = waker.clone();
        let h = spawn_loop("hvf-wake-test", Duration::from_secs(5), move |start| {
            let kick = WakingKick::new(FakeKick(Ok(())), body_waker.clone());
            let stop = start.ready(kick);
            while !stop.load(Ordering::Acquire) {
                // 通知が無ければ 1 秒待つ（WFI の待ちの模擬）。
                let _ = body_waker.wait(Duration::from_secs(1));
            }
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        // 本体が待ちに入る時間を与える。
        std::thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        let report = h.stop(Duration::from_secs(2)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    /// N 台が同時に待つとき、1 回の通知で全台が上限を待たず `Notified` で戻る（#3933・MVM-5・REPAIR-5）。
    #[test]
    fn repair5_mvm5_3933_one_notify_wakes_all_concurrent_waiters() {
        const N: usize = 4;
        let w = WfiWaker::default();
        let barrier = Arc::new(std::sync::Barrier::new(N + 1));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let wc = w.clone();
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let r = wc.wait(Duration::from_secs(1));
                    (r, Instant::now(), wc)
                })
            })
            .collect();
        barrier.wait();
        std::thread::sleep(Duration::from_millis(20));
        let notified_at = Instant::now();
        w.notify();
        let mut notified = 0;
        for h in handles {
            let (r, at, wc) = h.join().unwrap();
            if r == WakeOutcome::Notified {
                notified += 1;
            }
            assert!(at.duration_since(notified_at) < Duration::from_millis(100));
            // 通知は各待ち手で 1 回ずつ消費されている。
            assert_eq!(wc.wait(Duration::from_millis(20)), WakeOutcome::TimedOut);
        }
        assert_eq!(notified, N);
    }

    /// 待つ前の複数回の通知は、各待ち手に 1 回の早期再開として残る（#3933）。
    #[test]
    fn repair5_mvm5_3933_pending_notifies_collapse_per_waiter() {
        let w = WfiWaker::default();
        let (a, b) = (w.clone(), w.clone());
        w.notify();
        w.notify();
        for x in [&a, &b] {
            assert_eq!(x.wait(Duration::ZERO), WakeOutcome::Notified);
            assert_eq!(x.wait(Duration::ZERO), WakeOutcome::TimedOut);
        }
    }

    /// 停止要求の kick 1 回が、待っている 2 台とも起こす（#3933）。
    #[test]
    fn repair5_mvm5_3933_waking_kick_wakes_all_waiters() {
        let w = WfiWaker::default();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let wc = w.clone();
                std::thread::spawn(move || {
                    let s = Instant::now();
                    (wc.wait(Duration::from_secs(1)), s.elapsed())
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        WakingKick::new(FakeKick(Ok(())), w.clone()).kick().unwrap();
        for h in handles {
            let (r, e) = h.join().unwrap();
            assert_eq!(r, WakeOutcome::Notified);
            assert!(e < Duration::from_millis(200));
        }
    }

    const SLOTS: usize = 4;

    fn set4() -> WfiWakeSet {
        WfiWakeSet::new(4).unwrap()
    }

    /// 各スロットを別スレッドで `limit` まで待たせ、全員が待ちに入った後 20 ms で `fire` を呼び、(結果, 経過) を返す。
    fn run_waiters(
        set: &WfiWakeSet,
        limit: Duration,
        fire: impl FnOnce(&WfiWakeSet),
    ) -> Vec<(WakeOutcome, Duration)> {
        let barrier = Arc::new(std::sync::Barrier::new(SLOTS + 1));
        let handles: Vec<_> = (0..SLOTS as u32)
            .map(|i| {
                let w = set.handle(i).unwrap();
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let s = Instant::now();
                    (w.wait(limit), s.elapsed())
                })
            })
            .collect();
        barrier.wait();
        std::thread::sleep(Duration::from_millis(20));
        fire(set);
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    }

    /// 宛先の 1 台だけが上限を待たず戻り、他の 3 台は起きずに期限まで待つ（#3948）。
    #[test]
    fn repair5_mvm5_3948_targeted_notify_wakes_only_target() {
        let set = set4();
        let r = run_waiters(&set, Duration::from_millis(300), |s| s.notify_vcpu(2));
        for (i, (out, el)) in r.iter().enumerate() {
            if i == 2 {
                assert_eq!(*out, WakeOutcome::Notified);
                assert!(*el < Duration::from_millis(250), "target waited {el:?}");
            } else {
                assert_eq!(*out, WakeOutcome::TimedOut, "slot {i}");
                assert!(*el >= Duration::from_millis(300), "slot {i} woke at {el:?}");
            }
        }
    }

    /// 決定的な版: 通知の後に各スロットの既読を即時に見る（#3948）。
    #[test]
    fn repair5_mvm5_3948_targeted_notify_leaves_others_pending_free() {
        let set = set4();
        set.notify_vcpu(1);
        for i in 0..SLOTS as u32 {
            let want = if i == 1 {
                WakeOutcome::Notified
            } else {
                WakeOutcome::TimedOut
            };
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                want,
                "slot {i}"
            );
        }
    }

    #[test]
    fn repair5_mvm5_3948_notify_all_wakes_every_slot() {
        let set = set4();
        let r = run_waiters(&set, Duration::from_secs(1), |s| s.notify_all());
        assert_eq!(r.len(), SLOTS);
        for (out, el) in r {
            assert_eq!(out, WakeOutcome::Notified);
            assert!(el < Duration::from_millis(500));
        }
    }

    // ---- #3974: 縮退の理由別件数・初回ログ・ARE ----

    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct FakeGicd {
        ctlr: RefCell<Result<u64, MicrovmErrorCode>>,
        irouter: RefCell<Result<u64, MicrovmErrorCode>>,
        ctlr_reads: Cell<u32>,
        irouter_reads: Cell<u32>,
    }

    impl FakeGicd {
        fn new(
            ctlr: Result<u64, MicrovmErrorCode>,
            irouter: Result<u64, MicrovmErrorCode>,
        ) -> Self {
            Self {
                ctlr: RefCell::new(ctlr),
                irouter: RefCell::new(irouter),
                ctlr_reads: Cell::new(0),
                irouter_reads: Cell::new(0),
            }
        }
    }

    impl GicdRegisterRead for FakeGicd {
        fn read(&self, reg: GicDistributorReg) -> Result<u64, MicrovmError> {
            let (cell, n) = if reg == GicDistributorReg::ctlr() {
                (&self.ctlr, &self.ctlr_reads)
            } else {
                (&self.irouter, &self.irouter_reads)
            };
            n.set(n.get() + 1);
            cell.borrow()
                .map_err(|c| MicrovmError::new(c, "fake read failed"))
        }
    }

    fn counts_of(r: &SpiRouting) -> HashMap<&'static str, u64> {
        let s = r.snapshot();
        SpiRouteFallback::ALL
            .iter()
            .map(|f| (f.as_str(), s.count(*f)))
            .collect()
    }

    #[test]
    fn mvm5_repair4_3974_unavailable_counts_and_first() {
        let routing = SpiRouting::default();
        let g = FakeGicd::new(Err(MicrovmErrorCode::Unimplemented), Ok(0x1));
        let d1 = routing.resolve(&g, 40, Some(1), 4);
        let d2 = routing.resolve(&g, 40, Some(1), 4);
        let d3 = routing.resolve(&g, 40, None, 4);
        assert_eq!(d1.target, SpiWakeTarget::Vcpu(1));
        assert_eq!(d3.target, SpiWakeTarget::All);
        assert_eq!(d1.fallback, Some(SpiRouteFallback::Unavailable));
        assert_eq!(d1.code, Some(MicrovmErrorCode::Unimplemented));
        assert_eq!([d1.first, d2.first, d3.first], [true, false, false]);
        let s = routing.snapshot();
        assert_eq!(s.count(SpiRouteFallback::Unavailable), 3);
        assert_eq!(s.total(), 3);
        // CTLR が読めないとき IROUTER は読まない（二重計上しない）。
        assert_eq!(g.irouter_reads.get(), 0);
        assert_eq!(g.ctlr_reads.get(), 3);
    }

    #[test]
    fn mvm5_repair4_3974_each_reason_counted() {
        let r = SpiRouting::default();
        // Failed: IROUTER の読み出しが Internal。
        let g = FakeGicd::new(Ok(0x10), Err(MicrovmErrorCode::Internal));
        let d = r.resolve(&g, 40, None, 4);
        assert_eq!(d.fallback, Some(SpiRouteFallback::Failed));
        assert_eq!(d.code, Some(MicrovmErrorCode::Internal));
        assert!(d.first);
        // Malformed: IROUTER の RES0。
        *g.irouter.borrow_mut() = Ok(1 << 40);
        let d = r.resolve(&g, 40, None, 4);
        assert_eq!(d.fallback, Some(SpiRouteFallback::Malformed));
        assert_eq!(d.code, None);
        // OutOfRange: affinity 5 は 2 台に当たらない。
        *g.irouter.borrow_mut() = Ok(0x5);
        let d = r.resolve(&g, 40, Some(1), 2);
        assert_eq!(d.fallback, Some(SpiRouteFallback::OutOfRange));
        assert_eq!(d.target, SpiWakeTarget::Vcpu(1));
        // AnyParticipating。
        *g.irouter.borrow_mut() = Ok(0x8000_0000);
        let d = r.resolve(&g, 40, None, 4);
        assert_eq!(d.fallback, Some(SpiRouteFallback::AnyParticipating));
        assert_eq!(d.target, SpiWakeTarget::All);
        // 成功は件数を増やさない。
        *g.irouter.borrow_mut() = Ok(0x2);
        let d = r.resolve(&g, 40, None, 4);
        assert_eq!(d.target, SpiWakeTarget::Vcpu(2));
        assert_eq!((d.fallback, d.first), (None, false));
        let c = counts_of(&r);
        assert_eq!(c["failed"], 1);
        assert_eq!(c["malformed"], 1);
        assert_eq!(c["out-of-range"], 1);
        assert_eq!(c["any-participating"], 1);
        assert_eq!(c["unavailable"], 0);
        assert_eq!(c["are-disabled"], 0);
        // Malformed の CTLR（別の VM）。
        let r2 = SpiRouting::default();
        let g2 = FakeGicd::new(Ok(1 << 32), Ok(0x1));
        let d = r2.resolve(&g2, 40, None, 4);
        assert_eq!(d.fallback, Some(SpiRouteFallback::Malformed));
        assert_eq!(g2.irouter_reads.get(), 0);
    }

    #[test]
    fn mvm5_repair4_3974_are_disabled_skips_irouter_and_latch() {
        let r = SpiRouting::default();
        let g = FakeGicd::new(Ok(0x0), Ok(0x1));
        let d1 = r.resolve(&g, 40, Some(3), 4);
        let d2 = r.resolve(&g, 40, Some(3), 4);
        assert_eq!(d1.fallback, Some(SpiRouteFallback::AreDisabled));
        assert_eq!(d1.target, SpiWakeTarget::Vcpu(3));
        assert_eq!((d1.first, d2.first), (true, false));
        assert_eq!(r.snapshot().count(SpiRouteFallback::AreDisabled), 2);
        assert_eq!(g.irouter_reads.get(), 0);
        // ゲストが ARE を立てた。次の assert から IROUTER を使う。
        *g.ctlr.borrow_mut() = Ok(0x10);
        let d3 = r.resolve(&g, 40, Some(3), 4);
        assert_eq!(d3.target, SpiWakeTarget::Vcpu(1));
        assert_eq!(d3.fallback, None);
        // ラッチ後は CTLR を読まない。
        let d4 = r.resolve(&g, 40, Some(3), 4);
        assert_eq!(d4.target, SpiWakeTarget::Vcpu(1));
        assert_eq!(g.ctlr_reads.get(), 3);
        assert_eq!(g.irouter_reads.get(), 2);
        assert_eq!(r.snapshot().total(), 2);
    }

    #[test]
    fn repair4_mvm5_3974_log_line_and_as_str_values() {
        assert_eq!(
            spi_route_fallback_log_line(SpiRouteFallback::AreDisabled, None),
            "level=warn op=hvf.gic.spi_route outcome=fallback reason=are-disabled message=\"gic routing is not used; waking the learned hint or all vcpus (logged once per reason)\""
        );
        assert_eq!(
            spi_route_fallback_log_line(SpiRouteFallback::Failed, Some(MicrovmErrorCode::Internal)),
            "level=warn op=hvf.gic.spi_route outcome=fallback reason=failed code=INTERNAL message=\"gic routing is not used; waking the learned hint or all vcpus (logged once per reason)\""
        );
        let names: Vec<_> = SpiRouteFallback::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            names,
            [
                "unavailable",
                "failed",
                "malformed",
                "out-of-range",
                "are-disabled",
                "any-participating"
            ]
        );
    }

    #[test]
    fn repair5_mvm5_3974_record_is_first_exactly_once_under_contention() {
        let r = SpiRouting::default();
        let firsts = Arc::new(AtomicU64::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let r = r.clone();
                let f = Arc::clone(&firsts);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if r.record(SpiRouteFallback::Failed) {
                            f.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(r.snapshot().count(SpiRouteFallback::Failed), 8000);
        assert_eq!(firsts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn repair5_mvm5_3974_notify_target_wakes_only_target_slot() {
        let set = set4();
        set.notify_target(SpiWakeTarget::Vcpu(2));
        for i in 0..SLOTS as u32 {
            let want = if i == 2 {
                WakeOutcome::Notified
            } else {
                WakeOutcome::TimedOut
            };
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                want,
                "slot {i}"
            );
        }
    }

    #[test]
    fn mvm5_3960_spi_wake_target_values() {
        use SpiWakeTarget::{All, Vcpu};
        let t = spi_wake_target;
        assert_eq!(t(Some(0x1), Some(0), 4), Vcpu(1));
        assert_eq!(t(Some(0x0), None, 4), Vcpu(0));
        assert_eq!(t(Some(0x8000_0000), Some(2), 4), Vcpu(2));
        assert_eq!(t(Some(0x8000_0000), None, 4), All);
        assert_eq!(t(None, Some(1), 4), Vcpu(1));
        assert_eq!(t(None, None, 4), All);
        assert_eq!(t(Some(0x5), Some(3), 4), Vcpu(3));
        assert_eq!(t(Some(0x5), None, 4), All);
        assert_eq!(t(None, Some(7), 4), All);
        // 書式違反はヒントへ縮退する。
        assert_eq!(t(Some(0x0100_0001), Some(2), 4), Vcpu(2));
    }

    #[test]
    fn repair5_mvm5_3960_notify_spi_routed_wakes_only_routed_slot() {
        let set = set4();
        // ヒントは別の vCPU（3）を指すが、ルーティング（affinity 1）が勝つ。
        let hint = SpiRouteHint::unknown();
        hint.record(3);
        set.notify_spi_routed(Some(0x1), &hint);
        for i in 0..SLOTS as u32 {
            let want = if i == 1 {
                WakeOutcome::Notified
            } else {
                WakeOutcome::TimedOut
            };
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                want,
                "slot {i}"
            );
        }
    }

    #[test]
    fn repair5_mvm5_3948_unknown_route_spi_wakes_all() {
        let set = set4();
        set.notify_spi(&SpiRouteHint::unknown());
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
    }

    #[test]
    fn repair5_mvm5_3948_learned_route_spi_wakes_only_target() {
        let set = set4();
        let hint = SpiRouteHint::unknown();
        hint.record(3);
        set.notify_spi(&hint);
        for i in 0..SLOTS as u32 {
            let want = if i == 3 {
                WakeOutcome::Notified
            } else {
                WakeOutcome::TimedOut
            };
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                want,
                "slot {i}"
            );
        }
    }

    #[test]
    fn repair5_mvm5_3948_out_of_range_target_falls_back_to_all() {
        let set = set4();
        set.notify_vcpu(4);
        let hint = SpiRouteHint::unknown();
        hint.record(99);
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
        set.notify_spi(&hint);
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
    }

    /// 停止の kick は全スロットを起こし、inner の失敗も透過する（#3948）。
    #[test]
    fn repair5_mvm5_3948_waking_kick_with_set_wakes_all() {
        let set = set4();
        let k = WakingKick::new(
            FakeKick(Err(MicrovmErrorCode::FailedPrecondition)),
            set.clone(),
        );
        let e = k.kick().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
        WakingKick::new(FakeKick(Ok(())), set.clone())
            .kick()
            .unwrap();
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
    }

    /// vCPU 1 台なら、どの経路の通知も従来の単一 waker と同じ（1 回だけ起こす）（#3948）。
    #[test]
    fn repair5_mvm5_3948_single_vcpu_unchanged() {
        let set = WfiWakeSet::new(1).unwrap();
        let w = set.handle(0).unwrap();
        let routed = SpiRouteHint::unknown();
        routed.record(0);
        let paths: [&dyn Fn(); 4] = [
            &|| set.notify_vcpu(0),
            &|| set.notify_all(),
            &|| set.notify_spi(&SpiRouteHint::unknown()),
            &|| set.notify_spi(&routed),
        ];
        for fire in paths {
            fire();
            assert_eq!(w.wait(Duration::ZERO), WakeOutcome::Notified);
            assert_eq!(w.wait(Duration::ZERO), WakeOutcome::TimedOut);
        }
    }

    #[test]
    fn mvm5_3948_wake_set_rejects_invalid_vcpu_count() {
        assert_eq!(
            WfiWakeSet::new(0).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            WfiWakeSet::new(HVF_MAX_VCPUS + 1).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let set = WfiWakeSet::new(HVF_MAX_VCPUS).unwrap();
        assert!(set.handle(HVF_MAX_VCPUS - 1).is_ok());
        assert_eq!(
            set.handle(HVF_MAX_VCPUS).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let two = WfiWakeSet::new(2).unwrap();
        assert_eq!(
            two.handle(2).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    #[test]
    fn mvm5_3948_ack_learner_records_and_overrides() {
        let (a, b) = (SpiRouteHint::unknown(), SpiRouteHint::unknown());
        let hints = vec![(10u32, a.clone()), (11u32, b.clone())];
        let on_vcpu1 = AckRouteLearner::new(1, hints.clone());
        let on_vcpu3 = AckRouteLearner::new(3, hints);
        assert_eq!((a.get(), b.get()), (None, None));
        on_vcpu1.on_interrupt_ack(&10);
        assert_eq!((a.get(), b.get()), (Some(1), None));
        on_vcpu3.on_interrupt_ack(&10);
        assert_eq!(a.get(), Some(3));
        // 未登録のキーは何も変えない。
        on_vcpu1.on_interrupt_ack(&99);
        assert_eq!((a.get(), b.get()), (Some(3), None));
    }
}
