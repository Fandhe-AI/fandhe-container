//! 試験用の合成 arm64 Image（arm64 Linux boot protocol のヘッダを手で組んだもの）の正本。
//!
//! 役割: macOS の Hypervisor.framework の実機前提試験が、本物のカーネルを使わずに「Image ヘッダの検証を通り、
//! エントリから実行される」ことを確かめるための入力を組み立てる。以前は `hvf_device.rs` の private 関数だった
//! ものを、plugin-microvm の E2E からも使えるよう正本として切り出した。`bzimage.rs`（#3750）と同じ
//! `#[path]` 共有の方式で取り込み、複製しない（REPAIR-1・REPAIR-12）。
//!
//! 取り込み方:
//! - `crates/microvm/tests/hvf_device.rs`: `#[path = "support/arm64_image.rs"] mod arm64_image;`
//! - `crates/plugin-microvm/tests/e2e.rs`: `#[path = "../../microvm/tests/support/arm64_image.rs"] mod arm64_image;`
//!
//! `hvf_microvm.rs`（TASK-192.17・#3799）は `BOOT_CHECK_CODE` と `image_with_code` を使う（同じ正本から取り込む）。
//!
//! 対応: MVM-5・MVM-1・TASK-192.18・#3800。ローダ側の解釈は `fandhe_container_microvm::boot_arm64::Arm64ImageHeader`。
//! 取り込み元ごとに使う関数が違うため、`dead_code` の許可は項目ごとに理由つきで付ける。

/// `ARM\x64`（リトルエンディアンで offset 56 に置く magic。`boot_arm64::ARM64_IMAGE_MAGIC` と同値）。
/// std のみに依存し、取り込み元が microvm crate を import するかに関わらず単独でコンパイルできるようにする。
const ARM64_IMAGE_MAGIC: u32 = 0x644d_5241;

/// 合成の arm64 Image。先頭の命令は `b .`（自分自身への分岐）で、ゲストはその場で走り続ける。
/// ヘッダ（64 バイト）: offset 0 = code0、8 = text_offset、16 = image_size、24 = flags、56 = magic（`ARM\x64`）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn synthetic_image(magic_ok: bool) -> Vec<u8> {
    synthetic_image_with_code(magic_ok, &[])
}

/// [`synthetic_image`] の先頭を `b +0x40` にし、ヘッダの直後（offset 0x40）へ `code` を置いたもの（`code` が空なら `b .`）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn synthetic_image_with_code(magic_ok: bool, code: &[u32]) -> Vec<u8> {
    let mut img = vec![0u8; 4096];
    let first: u32 = if code.is_empty() {
        0x1400_0000
    } else {
        0x1400_0010
    };
    img[0..4].copy_from_slice(&first.to_le_bytes());
    for (i, w) in code.iter().enumerate() {
        img[0x40 + i * 4..0x44 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    img[8..16].copy_from_slice(&0x8_0000u64.to_le_bytes());
    img[16..24].copy_from_slice(&4096u64.to_le_bytes());
    // flags = 0（リトルエンディアン・ページサイズ未指定）のまま。
    let magic = if magic_ok { ARM64_IMAGE_MAGIC } else { 0 };
    img[56..60].copy_from_slice(&magic.to_le_bytes());
    img
}

/// 起動確認ゲストのコード（ヘッダ直後の offset 0x40 から置く。各行の `0x..` はコード先頭からのバイト位置）。
///
/// 流れ: FDT の magic（x0 が指す GPA）を確かめ、virtio-block の MagicValue と DeviceID を読み、全一致のときだけ
/// シリアルの THR（0x0900_0000）へ `O` `K` `\n` を書く。どれかが食い違えば書かずに `fail` へ分岐する。
/// 成功も失敗も同じ PSCI SYSTEM_OFF に合流するため、停止理由は正負で同じ `GuestShutdown` になり、
/// 区別は exit の並びとシリアル出力だけが担う。
///
/// 3 つの `b.ne` は `fail`（0x58）への相対オフセットを命令語に含む。命令を挿入・並べ替えるときは必ず再計算すること。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) const BOOT_CHECK_CODE: [u32; 26] = [
    0xB940_0001, // 0x00 ldr  w1, [x0]                ; FDT 先頭の 4 バイト（ゲスト RAM 上なので exit にならない）
    0x5AC0_0821, // 0x04 rev  w1, w1                  ; FDT は BE 格納で ldr は LE のため、反転して比較する
    0x529F_DDA2, // 0x08 movz w2, #0xfeed
    0x72BA_01A2, // 0x0c movk w2, #0xd00d, lsl #16    ; w2 = 0xd00dfeed
    0x6B02_003F, // 0x10 cmp  w1, w2
    0x5400_0221, // 0x14 b.ne fail                    ; +0x44
    0xD2A1_4003, // 0x18 movz x3, #0x0a00, lsl #16    ; virtio-mmio 窓 0
    0xB940_0061, // 0x1c ldr  w1, [x3]                ; MagicValue（data abort 1）
    0x528D_2EC2, // 0x20 movz w2, #0x6976
    0x72AE_8E42, // 0x24 movk w2, #0x7472, lsl #16    ; w2 = 0x7472_6976（"virt"）
    0x6B02_003F, // 0x28 cmp  w1, w2
    0x5400_0161, // 0x2c b.ne fail                    ; +0x2c
    0xB940_0861, // 0x30 ldr  w1, [x3, #8]            ; DeviceID（data abort 2）
    0x7100_083F, // 0x34 cmp  w1, #2                  ; 2 = virtio-block
    0x5400_0101, // 0x38 b.ne fail                    ; +0x20
    0xD2A1_2004, // 0x3c movz x4, #0x0900, lsl #16    ; シリアル（ns16550a）の THR
    0x5280_09E5, // 0x40 movz w5, #0x4f               ; 'O'
    0x3900_0085, // 0x44 strb w5, [x4]                ; data abort 3
    0x5280_0965, // 0x48 movz w5, #0x4b               ; 'K'
    0x3900_0085, // 0x4c strb w5, [x4]                ; data abort 4
    0x5280_0145, // 0x50 movz w5, #0x0a               ; '\n'
    0x3900_0085, // 0x54 strb w5, [x4]                ; data abort 5
    0xD2B0_8000, // 0x58 fail: movz x0, #0x8400, lsl #16
    0xF280_0100, // 0x5c movk x0, #0x8                ; PSCI SYSTEM_OFF = 0x8400_0008
    0xD400_0002, // 0x60 hvc  #0                      ; HVC の exit -> GuestShutdown
    0x1400_0000, // 0x64 b .                          ; 到達しない（安全側の自己ループ）
];

/// `code` をヘッダの直後（offset 0x40）に置いた 4096 バイトの合成 arm64 Image を作る。
/// ヘッダ（64 バイト）: offset 0 = `b +0x40`（code0）、8 = text_offset、16 = image_size、24 = flags、56 = magic（`ARM\x64`）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub(crate) fn image_with_code(code: &[u32]) -> Vec<u8> {
    synthetic_image_with_code(true, code)
}
