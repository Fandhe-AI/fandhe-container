//! `hvf_microvm` 専用の合成 arm64 Image とゲスト機械語（MVM-5・MVM-1・REPAIR-12・TASK-192.17・#3799）。
//!
//! `tests/hvf_microvm.rs` が `#[path]` で取り込む。実カーネルの起動完走は求めず、`HvfMicroVm::assemble` が作った
//! FDT・起動レジスタ・virtio-mmio・シリアルをゲスト自身に検証させ、結果を exit の並びとシリアル出力へ写すための最小のコード。
//! 機械語は `llvm-mc -triple=aarch64 -show-encoding` で符号化し、`llvm-objdump -d` で逆アセンブルして確認した。

use fandhe_container_microvm::boot_arm64::ARM64_IMAGE_MAGIC;

/// 起動確認ゲストのコード（ヘッダ直後の offset 0x40 から置く。各行の `0x..` はコード先頭からのバイト位置）。
///
/// 流れ: FDT の magic（x0 が指す GPA）を確かめ、virtio-block の MagicValue と DeviceID を読み、全一致のときだけ
/// シリアルの THR（0x0900_0000）へ `O` `K` `\n` を書く。どれかが食い違えば書かずに `fail` へ分岐する。
/// 成功も失敗も同じ PSCI SYSTEM_OFF に合流するため、停止理由は正負で同じ `GuestShutdown` になり、
/// 区別は exit の並びとシリアル出力だけが担う。
///
/// 3 つの `b.ne` は `fail`（0x58）への相対オフセットを命令語に含む。命令を挿入・並べ替えるときは必ず再計算すること。
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
pub(crate) fn image_with_code(code: &[u32]) -> Vec<u8> {
    assert!(
        0x40 + code.len() * 4 <= 4096,
        "guest code exceeds the image"
    );
    let mut img = vec![0u8; 4096];
    // b +0x40: ヘッダを飛び越えて offset 0x40 のコードへ入る。
    img[0..4].copy_from_slice(&0x1400_0010u32.to_le_bytes());
    for (i, w) in code.iter().enumerate() {
        img[0x40 + i * 4..0x44 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    img[8..16].copy_from_slice(&0x8_0000u64.to_le_bytes());
    img[16..24].copy_from_slice(&4096u64.to_le_bytes());
    // flags = 0（リトルエンディアン・ページサイズ未指定）のまま。
    img[56..60].copy_from_slice(&ARM64_IMAGE_MAGIC.to_le_bytes());
    img
}
