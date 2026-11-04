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
