//! macOS の最小 microVM の起動から停止までの通し試験（MVM-5・MVM-1・MVM-4・REPAIR-12・TASK-192.17・#3799・#3782）。
//! Linux の `tests/microvm.rs`（#700・TASK-75.5）の macOS 対応物で、`HvfMicroVm::assemble` → `start` → ゲスト起因の停止 → `stop` を
//! FDT・起動レジスタ・virtio-mmio・シリアル・PSCI まで一貫して観測する。部品ごとの試験は `hvf_device.rs` が担う。
//!
//! 観測手段: 合成の arm64 Image（`support/arm64_image.rs`）自身が起動状態を検証し、結果を「exit の並び」「シリアル出力」
//! 「停止理由」へ写す。正の試験は全一致のときだけシリアルへ `OK\n` を書き、負の対照（virtio-block 無し）は書き込み 0 回で終わる。
//! 正負とも停止理由は `GuestShutdown` で、「シャットダウンできた＝成功」とはみなさず、区別は exit の並びと出力で行う。
//! 書き先を空き virtio 窓の観測器ではなくシリアルにしたのは、`assemble` が virtio の窓数と block + net の個数の一致を要求し、
//! 製品の構成外の登録（`dispatcher()` への後付け）を避けるため。
//! `hvf_device.rs` の `synthetic_image*` との重複は意図的に解消しない（1 PR・1 関心事。REPAIR-1 の後続候補）。
//!
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_microvm` の項。1 プロセス 1 VM のため `--test-threads=1` で実行する。
//! 期限 watchdog つき（REPAIR-5。超過は `hvf_microvm: WATCHDOG EXPIRED` と終了コード 124）。実機の記録は人間担当の #3803。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "support/arm64_image.rs"]
mod arm64_image;
/// 記述子のワイヤー配置の正本（`tests/support/virtqueue_driver.rs`。複製しない・#4113）。
#[path = "support/virtqueue_driver.rs"]
mod virtqueue_driver;

use arm64_image::{BOOT_CHECK_CODE, image_with_code};
use fandhe_container_microvm::arm64_layout::{
    ARM64_SERIAL_BASE, ARM64_VIRTIO_MMIO_BASE, Arm64Layout,
};
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::hvf::{
    HvVm, HvfMicroVm, HvfMicroVmConfig, HvfStopReport, VcpuThreadConfig, VmWithGic,
};
use fandhe_container_microvm::hvf_loop::{ExitKind, VcpuExitObserver};
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::virtio_block::{BlockBackend, MemoryBlockBackend};
use fandhe_container_microvm::virtio_net::MemoryNetBackend;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 試験全体の期限。ハングを失敗として残す（REPAIR-5）。
const DEADLINE: Duration = Duration::from_secs(30);
/// ゲストが SYSTEM_OFF に達するまでの待ちの上限。
const FINISH_WAIT: Duration = Duration::from_secs(10);

/// 環境の前提（権限）を、組み立てとは別に先に確かめる。権限不足だけを環境の問題とし、macOS 14 の `Unimplemented` と
/// GIC の呼び出しの失敗（定数の誤りなど）はそのままの失敗として出す（#3989）。
fn require_vm_with_gic(layout: &Arm64Layout) {
    match VmWithGic::create(layout) {
        Ok(vm) => drop(vm),
        Err(e) if e.code() == MicrovmErrorCode::PermissionDenied => {
            panic!("hvf_microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
        Err(e) => panic!("hvf_microvm: gic: {e}"),
    }
}

/// VM を作る。解放の観測（解放漏れなら 2 個目の作成が `FailedPrecondition`）にも使うため、権限不足と hypervisor 不可
/// だけを環境の問題とする（#3989）。
fn create_vm_or_precondition() -> HvVm {
    match HvVm::create() {
        Ok(vm) => vm,
        Err(e)
            if matches!(
                e.code(),
                MicrovmErrorCode::PermissionDenied | MicrovmErrorCode::Unimplemented
            ) =>
        {
            panic!("hvf_microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
        Err(e) => panic!("hvf_microvm: vm: {e}"),
    }
}

/// 期限 watchdog。panic しても止めて join する RAII ガード。
struct Watchdog(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);

impl Watchdog {
    fn start(deadline: Duration) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < deadline {
                if f.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_microvm: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        Watchdog(flag, Some(h))
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        if let Some(h) = self.1.take() {
            let _ = h.join();
        }
    }
}

/// exit の並びを記録する観測器（上限 64 件。ブロックしない）。
#[derive(Debug, Default)]
struct ExitSeq(Mutex<Vec<ExitKind>>);

impl ExitSeq {
    fn snapshot(&self) -> Vec<ExitKind> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl VcpuExitObserver for ExitSeq {
    fn on_exit(&self, kind: ExitKind) {
        if let Ok(mut v) = self.0.lock()
            && v.len() < 64
        {
            v.push(kind);
        }
    }
}

type Config = HvfMicroVmConfig<MemoryBlockBackend, MemoryNetBackend>;

/// 起動確認ゲストを載せた構成（vCPU 1・シリアルあり・net なし）。`block` は virtio-block の台数。
fn config(layout: Arm64Layout, block: usize, observer: Arc<ExitSeq>) -> Config {
    config_with_code(layout, block, observer, &BOOT_CHECK_CODE)
}

/// [`config`] のゲストの機械語を差し替えたもの。
fn config_with_code(
    layout: Arm64Layout,
    block: usize,
    observer: Arc<ExitSeq>,
    code: &[u32],
) -> Config {
    HvfMicroVmConfig {
        vcpus: layout.vcpus,
        layout,
        kernel: image_with_code(code),
        initrd: None,
        cmdline: "console=ttyS0".to_string(),
        block: (0..block)
            .map(|_| MemoryBlockBackend::new(512 * 1024, false).unwrap())
            .collect(),
        net: Vec::new(),
        vcpu: VcpuThreadConfig {
            observer: Some(observer),
            ..Default::default()
        },
        serial: true,
    }
}

/// start してゲストが SYSTEM_OFF に達するのを待ち、stop する。(exit の並び, シリアル出力, 停止報告) を返す。
fn run_boot_check(
    vm: HvfMicroVm<MemoryBlockBackend, MemoryNetBackend>,
    seq: &ExitSeq,
) -> (Vec<ExitKind>, Vec<u8>, HvfStopReport) {
    let console = vm.serial_console().expect("serial console is enabled");
    let running = vm.start().unwrap();

    let mut out = Vec::new();
    let start = Instant::now();
    while !running.is_finished() {
        assert!(
            start.elapsed() < FINISH_WAIT,
            "hvf_microvm: guest did not reach SYSTEM_OFF"
        );
        out.extend(console.take_output().unwrap());
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = running.stop(Duration::from_secs(1)).unwrap();
    // 追加の出力が無いことも確かめるため、少し待ってからもう一度取り出す。
    std::thread::sleep(Duration::from_millis(100));
    out.extend(console.take_output().unwrap());
    let exits = seq.snapshot();
    eprintln!(
        "hvf_microvm: boot_check: exits={exits:?} output={out:?} reason={:?} stats={:?}",
        report.reason, report.stats
    );
    (exits, out, report)
}

/// 正の試験: FDT・virtio-block の MagicValue と DeviceID をゲストが確かめ、全一致のときだけシリアルへ `OK\n` を書いて SYSTEM_OFF。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_microvm_boots_minimal_device_model_and_stops() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 1)
        .unwrap()
        .with_default_serial()
        .unwrap();
    // ゲストの機械語に固定した配置との一致。
    assert_eq!(
        layout.virtio_mmio_window(0).unwrap().base.raw(),
        0x0a00_0000
    );
    assert_eq!(ARM64_VIRTIO_MMIO_BASE, 0x0a00_0000);
    assert_eq!(layout.serial.unwrap().base.raw(), 0x0900_0000);
    assert_eq!(ARM64_SERIAL_BASE, 0x0900_0000);
    require_vm_with_gic(&layout);

    let seq = Arc::new(ExitSeq::default());
    let vm = HvfMicroVm::assemble(config(layout, 1, Arc::clone(&seq))).unwrap();

    // ゲストの検証の前提がホスト側でも成り立つ: x0 = FDT の GPA、その位置に BE の 0xd00dfeed、block が 1 台。
    assert_eq!(vm.boot_registers().x0, vm.loaded().fdt.base.raw());
    let mut magic = [0u8; 4];
    vm.read_guest(vm.loaded().fdt.base.raw(), &mut magic)
        .unwrap();
    assert_eq!(magic, 0xd00d_feedu32.to_be_bytes());
    assert_eq!(vm.devices().len(), 1);

    let (exits, out, report) = run_boot_check(vm, &seq);
    // MagicValue 読み・DeviceID 読み・THR への strb 3 回（すべて data abort）・SYSTEM_OFF の HVC。
    assert_eq!(
        exits,
        vec![
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::Hvc,
        ]
    );
    assert_eq!(out, b"OK\n");
    assert_eq!(report.reason, StopReason::GuestShutdown);

    // stop の後に VM を作り直せる（解放漏れなら FailedPrecondition）。
    drop(create_vm_or_precondition());
}

/// 負の対照: virtio-block が無い同じゲストは MagicValue が一致せず、書き込み 0 回で SYSTEM_OFF に至る（検査が効いている証拠）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_microvm_boot_check_fails_without_block_device() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 0)
        .unwrap()
        .with_default_serial()
        .unwrap();
    require_vm_with_gic(&layout);

    let seq = Arc::new(ExitSeq::default());
    let vm = HvfMicroVm::assemble(config(layout, 0, Arc::clone(&seq))).unwrap();
    assert_eq!(vm.devices().len(), 0);

    let (exits, out, report) = run_boot_check(vm, &seq);
    // 窓 0 は未登録で、読み出しは 0xFFFF_FFFF（MagicValue 不一致）。MagicValue 読み 1 回の後に fail へ分岐する。
    assert_eq!(exits, vec![ExitKind::DataAbort, ExitKind::Hvc]);
    assert_eq!(out, b"");
    assert_eq!(report.reason, StopReason::GuestShutdown);

    drop(create_vm_or_precondition());
}

/// OS Lock の SysReg trap 用ゲストの機械語（#4037・MVM-5）。msr の語は Arm ARM の MSR（register）の符号化
/// `0xD510_0000 | crn<<12 | crm<<8 | op2<<5 | rt`（op0=2・op1=0）から組み、`d5101388`・`d5101088` は実機で確認済み。
const MOVZ_X8_0: u32 = 0xD280_0008;
const MOVZ_X8_1: u32 = 0xD280_0028;
const MSR_OSDLR_EL1_X8: u32 = 0xD510_1388;
const MSR_OSLAR_EL1_X8: u32 = 0xD510_1088;
const MSR_OSLAR_EL1_XZR: u32 = 0xD510_109F;
/// PSCI SYSTEM_OFF（`movz x0, #0x8400, lsl #16` / `movk x0, #8` / `hvc #0`）。
const SYSTEM_OFF: [u32; 3] = [0xD2B0_8000, 0xF280_0100, 0xD400_0002];

fn os_lock_guest(prefix: &[u32]) -> Vec<u32> {
    let mut code = prefix.to_vec();
    code.extend_from_slice(&SYSTEM_OFF);
    code
}

fn run_os_lock_guest(code: &[u32]) -> (Vec<ExitKind>, HvfStopReport) {
    let layout = Arm64Layout::new(64 << 20, 1, 0)
        .unwrap()
        .with_default_serial()
        .unwrap();
    require_vm_with_gic(&layout);
    let seq = Arc::new(ExitSeq::default());
    let vm = HvfMicroVm::assemble(config_with_code(layout, 0, Arc::clone(&seq), code)).unwrap();
    let (exits, _out, report) = run_boot_check(vm, &seq);
    drop(create_vm_or_precondition());
    (exits, report)
}

/// 陽性: `msr OSDLR_EL1, x8`（x8 = 0）と `msr OSLAR_EL1, xzr` は trap しても処理されて続行し、後続の SYSTEM_OFF で `GuestShutdown`。
/// `rt` の読み出し・XZR・PC の書き戻しの実配線を通す（#4037・MVM-5・MVM-1）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn mvm5_4037_os_lock_writes_of_zero_are_handled() {
    let _wd = Watchdog::start(DEADLINE);
    let (exits, report) = run_os_lock_guest(&os_lock_guest(&[
        MOVZ_X8_0,
        MSR_OSDLR_EL1_X8,
        MSR_OSLAR_EL1_XZR,
    ]));
    assert_eq!(
        exits,
        vec![ExitKind::Sysreg, ExitKind::Sysreg, ExitKind::Hvc]
    );
    assert_eq!(report.reason, StopReason::GuestShutdown);
}

/// 陰性: `msr OSLAR_EL1, x8`（x8 = 1）は `Failed(Unimplemented)` で止まり、SYSTEM_OFF に達しない。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn mvm5_4037_os_lock_write_of_nonzero_fails_unimplemented() {
    let _wd = Watchdog::start(DEADLINE);
    let (exits, report) = run_os_lock_guest(&os_lock_guest(&[MOVZ_X8_1, MSR_OSLAR_EL1_X8]));
    assert_eq!(exits, vec![ExitKind::Sysreg]);
    assert_eq!(
        report.reason,
        StopReason::Failed(MicrovmErrorCode::Unimplemented)
    );
}
// ---- virtio-block の QueueNotify（#4028・MVM-5・MVM-1・REPAIR-12） ----
//
// 合成ゲストが virtio-mmio の窓 0 を初期化し、Image 自身に埋め込んだ記述子で read 要求を 1 件出して `QueueNotify` を書く。
// 記述子・avail・ヘッダはホストが Image の中へ事前に置く（ゲストは MMU off の Device 属性で書かずに済み、機械語が短くなる）。
// used・データ・status は device が同じ Image の領域へ書くため、ホストが終了後に `read_guest` で照合する。
// ゲストの機械語に絶対アドレスは埋めず、`adr` で得た Image 先頭からの相対で参照する。
// 割り込みの配送は照合しない（CPSR の DAIF がマスクされ、ベクタも無い）。`InterruptStatus` の UsedBuffer だけをゲストが読む。
// 実カーネルでの block-read と配送（edge と LevelHigh）は `hvf_kernel_boot`（#4014）で照合する。

/// Image 内のオフセット（ゲスト RAM 上では Image 先頭の GPA からの相対）。
const Q_DESC: usize = 0x400;
const Q_AVAIL: usize = 0x500;
const Q_USED: usize = 0x600;
const Q_HDR: usize = 0x700;
const Q_DATA: usize = 0x800;
const Q_STATUS: usize = 0xa00;
/// キュー深さ（`QUEUE_NUM`）。
const Q_NUM: u32 = 4;

// 命令の符号化（Arm ARM）。`BOOT_CHECK_CODE` の既存の語（例 movz x3 = 0xD2A1_4003、ldr w1,[x3,#8] = 0xB940_0861）と同じ式。
/// `movz wd, #imm`。
const fn movz_w(rd: u32, imm: u32) -> u32 {
    0x5280_0000 | (imm << 5) | rd
}
/// `movz xd, #imm, lsl #16`。
const fn movz_x_lsl16(rd: u32, imm: u32) -> u32 {
    0xD2A0_0000 | (imm << 5) | rd
}
/// `str wt, [xn, #off]`（off は 4 の倍数）。
const fn str_w(rt: u32, rn: u32, off: u32) -> u32 {
    0xB900_0000 | ((off / 4) << 10) | (rn << 5) | rt
}
/// `ldr wt, [xn, #off]`（off は 4 の倍数）。
const fn ldr_w(rt: u32, rn: u32, off: u32) -> u32 {
    0xB940_0000 | ((off / 4) << 10) | (rn << 5) | rt
}
/// `strb wt, [xn]`。
const fn strb_w(rt: u32, rn: u32) -> u32 {
    0x3900_0000 | (rn << 5) | rt
}
/// `add xd, xn, #imm`（imm は 12 bit）。
const fn add_x(rd: u32, rn: u32, imm: u32) -> u32 {
    0x9100_0000 | (imm << 10) | (rn << 5) | rd
}
/// `cmp wn, #imm`（`subs wzr, wn, #imm`）。
const fn cmp_w(rn: u32, imm: u32) -> u32 {
    0x7100_001F | (imm << 10) | (rn << 5)
}
/// `adr xd, #byte_off`（自分の位置からの符号つき 21 bit）。
const fn adr(rd: u32, byte_off: i32) -> u32 {
    let imm = (byte_off as u32) & 0x1F_FFFF;
    0x1000_0000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd
}
/// `b.ne` を `words` 命令先（符号つき 19 bit）へ。
const fn b_ne(words: i32) -> u32 {
    0x5400_0001 | (((words as u32) & 0x7_FFFF) << 5)
}
const DSB_SY: u32 = 0xD503_3F9F;

/// virtio-block を初期化して `QueueNotify` を書き、`InterruptStatus == UsedBuffer(1)` のときだけシリアルへ `OK\n` を書いて
/// SYSTEM_OFF するゲスト。食い違えば書かずに SYSTEM_OFF へ飛ぶ。x1 = Image 先頭の GPA、x3 = 窓 0 の基底。
fn block_read_guest_code() -> Vec<u32> {
    // 窓 0 のレジスタ（`virtio_mmio::reg`）。
    const STATUS: u32 = 0x070;
    const DRV_FEAT: u32 = 0x020;
    const DRV_FEAT_SEL: u32 = 0x024;
    const Q_SEL: u32 = 0x030;
    const Q_NUM_R: u32 = 0x038;
    const Q_READY: u32 = 0x044;
    const Q_NOTIFY: u32 = 0x050;
    const INT_STATUS: u32 = 0x060;
    const Q_DESC_LO: u32 = 0x080;
    const Q_DRIVER_LO: u32 = 0x090;
    const Q_DEVICE_LO: u32 = 0x0a0;
    let wr = |c: &mut Vec<u32>, reg: u32, v: u32| {
        c.push(movz_w(5, v));
        c.push(str_w(5, 3, reg));
    };
    let mut c: Vec<u32> = Vec::new();
    // 命令列の先頭は Image の offset 0x40 なので、Image 先頭は 0x40 戻った位置。
    c.push(adr(1, -0x40)); // adr x1, <Image 先頭>
    c.push(movz_x_lsl16(3, 0x0a00)); // x3 = 0x0a00_0000（窓 0）
    wr(&mut c, STATUS, 1); // ACKNOWLEDGE
    wr(&mut c, STATUS, 3); // + DRIVER
    wr(&mut c, DRV_FEAT_SEL, 0);
    wr(&mut c, DRV_FEAT, 0x6); // SIZE_MAX | SEG_MAX（device が要求する）
    wr(&mut c, DRV_FEAT_SEL, 1);
    wr(&mut c, DRV_FEAT, 1); // VERSION_1（word 1 の bit 0）
    wr(&mut c, STATUS, 11); // + FEATURES_OK
    wr(&mut c, Q_SEL, 0);
    wr(&mut c, Q_NUM_R, Q_NUM);
    for (reg, off) in [
        (Q_DESC_LO, Q_DESC),
        (Q_DRIVER_LO, Q_AVAIL),
        (Q_DEVICE_LO, Q_USED),
    ] {
        c.push(add_x(6, 1, off as u32)); // x6 = Image 先頭 + off（RAM は 4 GiB 未満なので下位 32 bit で足りる）
        c.push(str_w(6, 3, reg));
    }
    wr(&mut c, Q_READY, 1);
    wr(&mut c, STATUS, 15); // + DRIVER_OK
    c.push(DSB_SY);
    wr(&mut c, Q_NOTIFY, 0); // QueueNotify(0): route が同期で処理する
    c.push(ldr_w(7, 3, INT_STATUS)); // InterruptStatus
    c.push(cmp_w(7, 1)); // UsedBuffer のみ
    let bne = c.len();
    c.push(0); // b.ne fail（後で埋める）
    c.push(movz_x_lsl16(4, 0x0900)); // シリアル THR
    for ch in *b"OK\n" {
        c.push(movz_w(5, u32::from(ch)));
        c.push(strb_w(5, 4));
    }
    let fail = c.len();
    c.extend_from_slice(&[0xD2B0_8000, 0xF280_0100, 0xD400_0002]); // PSCI SYSTEM_OFF（hvc #0）
    c.push(0x1400_0000); // b .
    c[bne] = b_ne(i32::try_from(fail - bne).unwrap());
    c
}

/// ゲスト用の Image。記述子（header R → data W → status W）・avail（`head` を 1 件）・read ヘッダを埋め込む。
/// `head` がキュー深さ以上ならリング破損になる。
fn block_read_image(kernel_gpa: u64, head: u16) -> Vec<u8> {
    let mut img = image_with_code(&block_read_guest_code());
    let put = |img: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        img[at..at + bytes.len()].copy_from_slice(bytes);
    };
    let desc = |img: &mut Vec<u8>, i: usize, addr: usize, len: u32, flags: u16, next: u16| {
        let at = Q_DESC + i * 16;
        put(
            img,
            at,
            &virtqueue_driver::desc_bytes(kernel_gpa + addr as u64, len, flags, next),
        );
    };
    desc(&mut img, 0, Q_HDR, 16, 1, 1); // NEXT
    desc(&mut img, 1, Q_DATA, 512, 1 | 2, 2); // NEXT | WRITE
    desc(&mut img, 2, Q_STATUS, 1, 2, 0); // WRITE
    put(&mut img, Q_AVAIL + 2, &1u16.to_le_bytes()); // avail.idx = 1
    put(&mut img, Q_AVAIL + 4, &head.to_le_bytes()); // avail.ring[0]
    // header は type = VIRTIO_BLK_T_IN(0)・reserved = 0・sector = 0（Image の既定の 0 のまま）。
    // 未処理と区別する印（device が書けば消える）。
    img[Q_DATA..Q_DATA + 512].fill(0xff);
    img[Q_STATUS] = 0xff;
    img
}

/// sector 0 に入れる既知のパターン（全 0 や印の 0xff と区別できる値）。
fn sector0_pattern() -> Vec<u8> {
    (0..512usize).map(|i| (i as u8) ^ 0x5a).collect()
}

/// block-read ゲストの構成（vCPU 1・block 1・シリアルあり）。sector 0 へ `sector0_pattern` を書いた backend を渡す。
fn block_read_config(layout: Arm64Layout, observer: Arc<ExitSeq>, head: u16) -> (Config, u64) {
    let kernel_gpa = layout.ram.base.raw() + 0x8_0000; // text_offset（合成 Image のヘッダ）
    let mut cfg = config_with_code(layout, 1, observer, &BOOT_CHECK_CODE);
    cfg.kernel = block_read_image(kernel_gpa, head);
    let backend = cfg.block.get_mut(0).unwrap();
    backend.write_at(0, &sector0_pattern()).unwrap();
    (cfg, kernel_gpa)
}

fn block_read_layout() -> Arm64Layout {
    let layout = Arm64Layout::new(64 << 20, 1, 1)
        .unwrap()
        .with_default_serial()
        .unwrap();
    assert_eq!(
        layout.virtio_mmio_window(0).unwrap().base.raw(),
        0x0a00_0000
    );
    assert_eq!(layout.serial.unwrap().base.raw(), 0x0900_0000);
    layout
}

/// 正の試験: read 要求が QueueNotify で同期処理され、used・データ・status・InterruptStatus がゲストとホストの両側から見える。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn mvm5_4028_block_queue_notify_completes_read() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = block_read_layout();
    require_vm_with_gic(&layout);
    let seq = Arc::new(ExitSeq::default());
    let (cfg, kernel_gpa) = block_read_config(layout, Arc::clone(&seq), 0);
    let vm = HvfMicroVm::assemble(cfg).unwrap();
    // 埋め込んだ記述子の絶対アドレスの前提: Image が想定の GPA に載り、全体が Image の長さに収まる。
    assert_eq!(vm.loaded().kernel.base.raw(), kernel_gpa);
    assert_eq!(vm.loaded().kernel.size, 4096);

    let console = vm.serial_console().expect("serial console is enabled");
    let running = vm.start().unwrap();
    let start = Instant::now();
    while !running.is_finished() {
        assert!(
            start.elapsed() < FINISH_WAIT,
            "hvf_microvm: guest did not finish block read"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // 解放（stop）の後はメモリが取り出されて読めないため、先に used・データ・status を読む。
    let mut view = vec![0u8; Q_STATUS + 1 - Q_USED];
    running
        .read_guest(kernel_gpa + Q_USED as u64, &mut view)
        .unwrap();
    let report = running.stop(Duration::from_secs(1)).unwrap();
    let out = console.take_output().unwrap();
    let exits = seq.snapshot();
    let at = |off: usize| off - Q_USED;
    let u16_at = |off: usize| u16::from_le_bytes([view[at(off)], view[at(off) + 1]]);
    let u32_at = |off: usize| {
        u32::from_le_bytes([
            view[at(off)],
            view[at(off) + 1],
            view[at(off) + 2],
            view[at(off) + 3],
        ])
    };
    eprintln!(
        "hvf_microvm: block_notify: exits={} used_idx={} used_id={} used_len={} status={} output={out:?} reason={:?}",
        exits.len(),
        u16_at(Q_USED + 2),
        u32_at(Q_USED + 4),
        u32_at(Q_USED + 8),
        view[at(Q_STATUS)],
        report.reason
    );
    assert_eq!(u16_at(Q_USED + 2), 1, "used.idx");
    assert_eq!(u32_at(Q_USED + 4), 0, "used.ring[0].id");
    assert_eq!(
        u32_at(Q_USED + 8),
        513,
        "used.ring[0].len = data 512 + status 1"
    );
    assert_eq!(view[at(Q_STATUS)], 0, "status = VIRTIO_BLK_S_OK");
    assert_eq!(&view[at(Q_DATA)..at(Q_DATA) + 512], &sector0_pattern()[..]);
    assert_eq!(out, b"OK\n", "InterruptStatus was UsedBuffer");
    // data abort の内訳: STATUS 書き 4・DRIVER_FEATURES(_SEL) 書き 4・QUEUE_SEL/NUM/DESC/DRIVER/DEVICE/READY 書き 6・
    // QUEUE_NOTIFY 書き 1・InterruptStatus 読み 1・THR 書き 3 = 19。最後は SYSTEM_OFF の HVC。
    let aborts = exits.iter().filter(|k| **k == ExitKind::DataAbort).count();
    assert_eq!(aborts, 19);
    assert_eq!(exits.last(), Some(&ExitKind::Hvc));
    assert_eq!(report.reason, StopReason::GuestShutdown);

    drop(create_vm_or_precondition());
}

/// 負の試験: avail が範囲外の記述子（リング破損）を指すと、通知の処理が `queue_error` を返し VM が fail-closed で止まる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn mvm5_4028_block_queue_notify_ring_error_stops_vm() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = block_read_layout();
    require_vm_with_gic(&layout);
    let seq = Arc::new(ExitSeq::default());
    // head = 7 は `Q_NUM`（4）以上: DescIndexOutOfRange（InvalidArgument）。
    let (cfg, _kernel_gpa) = block_read_config(layout, Arc::clone(&seq), 7);
    let vm = HvfMicroVm::assemble(cfg).unwrap();
    let console = vm.serial_console().expect("serial console is enabled");
    let running = vm.start().unwrap();
    let start = Instant::now();
    while !running.is_finished() {
        assert!(
            start.elapsed() < FINISH_WAIT,
            "hvf_microvm: vm did not stop on ring error"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = running.stop(Duration::from_secs(1)).unwrap();
    let out = console.take_output().unwrap();
    let exits = seq.snapshot();
    eprintln!(
        "hvf_microvm: block_notify_error: exits={} output={out:?} reason={:?}",
        exits.len(),
        report.reason
    );
    // QueueNotify の書き込みが最後の exit で、PC は進まず、ゲストは InterruptStatus を読まず SYSTEM_OFF にも達しない。
    assert_eq!(
        report.reason,
        StopReason::Failed(MicrovmErrorCode::InvalidArgument)
    );
    assert!(!exits.contains(&ExitKind::Hvc));
    assert_eq!(exits.last(), Some(&ExitKind::DataAbort));
    assert_eq!(
        exits.iter().filter(|k| **k == ExitKind::DataAbort).count(),
        15
    );
    assert_eq!(out, b"");

    drop(create_vm_or_precondition());
}
/// 読み出しの途中で止まる block backend（vCPU スレッドを `read_at` の中に留め、`stop` を期限切れにするため）。
/// 入ったことを `entered` で知らせ、`gate` に値が来る（または送り手が落ちる）まで戻らない。
struct StallingBlock {
    inner: MemoryBlockBackend,
    entered: std::sync::mpsc::Sender<()>,
    gate: std::sync::mpsc::Receiver<()>,
}

type BlockResult<T> = Result<T, fandhe_container_microvm::error::MicrovmError>;

impl BlockBackend for StallingBlock {
    fn capacity_bytes(&self) -> u64 {
        self.inner.capacity_bytes()
    }
    fn read_only(&self) -> bool {
        self.inner.read_only()
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> BlockResult<()> {
        let _ = self.entered.send(());
        let _ = self.gate.recv();
        self.inner.read_at(offset, buf)
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> BlockResult<()> {
        self.inner.write_at(offset, data)
    }
    fn flush(&mut self) -> BlockResult<()> {
        self.inner.flush()
    }
}

/// MVM-5・MVM-1・REPAIR-5・REPAIR-12・#4032: 本番の vCPU スレッドが `read_at` で止まり `stop` が期限切れになっても、
/// スレッドが終わるまで RAM と VM は保持され（同じプロセスで VM を作り直せない）、終わった後は unmap と VM の占有解除まで進んで
/// 作り直せる。デバイスの解放を確かめたうえでの回収（devices → RAM → VM）の配線を、偽の資源ではなく実機の vCPU 経路で見る。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn mvm5_4032_timeout_detached_vcpu_thread_reclaims_ram_and_vm() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = block_read_layout();
    require_vm_with_gic(&layout);
    let seq = Arc::new(ExitSeq::default());
    let kernel_gpa = layout.ram.base.raw() + 0x8_0000;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let mut inner = MemoryBlockBackend::new(512 * 1024, false).unwrap();
    inner.write_at(0, &sector0_pattern()).unwrap();
    let cfg: HvfMicroVmConfig<StallingBlock, MemoryNetBackend> = HvfMicroVmConfig {
        vcpus: layout.vcpus,
        layout,
        kernel: block_read_image(kernel_gpa, 0),
        initrd: None,
        cmdline: "console=ttyS0".to_string(),
        block: vec![StallingBlock {
            inner,
            entered: entered_tx,
            gate: gate_rx,
        }],
        net: Vec::new(),
        vcpu: VcpuThreadConfig {
            observer: Some(seq),
            ..Default::default()
        },
        serial: true,
    };
    let vm = HvfMicroVm::assemble(cfg).unwrap();
    let running = vm.start().unwrap();
    entered_rx
        .recv_timeout(FINISH_WAIT)
        .expect("hvf_microvm: guest did not reach the stalling read");
    let e = running.stop(Duration::from_millis(200)).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
    // スレッドは read_at の中。RAM と VM は保持されたままで、作り直せない。
    let e = HvVm::create().expect_err("vm must still be held");
    assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
    // スレッドを解放して終わらせる。終了後に unmap と VM の破棄まで進み、同じプロセスで作り直せる。
    drop(gate_tx);
    let start = Instant::now();
    loop {
        match HvVm::create() {
            Ok(vm) => {
                drop(vm);
                break;
            }
            Err(e) if e.code() == MicrovmErrorCode::FailedPrecondition => {
                assert!(
                    start.elapsed() < FINISH_WAIT,
                    "hvf_microvm: detached vcpu thread did not reclaim the vm"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("hvf_microvm: vm: {e}"),
        }
    }
}
