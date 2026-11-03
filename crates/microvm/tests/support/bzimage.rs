//! 試験用の合成 bzImage（x86 boot protocol の setup header を手で組んだもの）の正本。
//!
//! 役割: `KvmDevice` / `MicroVm::load_kernel` / `KvmBackend` の実機前提試験が、本物のカーネルを
//! 使わずに「ロードされ、64-bit エントリから実行される」ことを確かめるための入力を組み立てる。
//! 以前は 3 ファイル・計 10 か所に同じヘッダの組み立てが写されており、片方だけ直すとずれた
//! （REPAIR-1・REPAIR-12）。ここを唯一の正本とし、`crates/core/tests/support/` と同じ
//! `#[path]` 共有の方式（#3410）で取り込む。複製しない。
//!
//! 取り込み方:
//! - `crates/microvm/tests/{microvm,kvm_device,bzimage_support}.rs`: `#[path = "support/bzimage.rs"] mod bzimage;`
//! - `crates/plugin-microvm/tests/e2e.rs`: `#[path = "../../microvm/tests/support/bzimage.rs"] mod bzimage;`
//!
//! 対応: MVM-1・TASK-75.3.1・TASK-117.4。ローダ側の解釈は `fandhe_container_microvm::boot_x86::SetupHeader`。
//! 取り込み元ごとに使う項目が違うため、`dead_code` の許可は項目ごとに理由つきで付ける。
//! std のみに依存し、`fandhe_container_microvm` を import しない（plugin-microvm からも取り込むため）。

/// `setup_sects`（0x1F1）。setup のセクタ数（boot sector を除く）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const SETUP_SECTS: u8 = 4;
/// protected-mode カーネル本体（payload）の先頭オフセット（(setup_sects + 1) * 512）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const PAYLOAD_OFFSET: usize = (SETUP_SECTS as usize + 1) * 512;
/// payload の長さ。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const PAYLOAD_LEN: usize = 0x1000;
/// イメージ全体の長さ。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const IMAGE_LEN: usize = PAYLOAD_OFFSET + PAYLOAD_LEN;
/// 64-bit エントリは payload 先頭 + 0x200（boot protocol の XLF_KERNEL_64 の規約）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const ENTRY_64_OFFSET: usize = 0x200;
/// `HdrS` magic（0x202）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const HEADER_MAGIC: [u8; 4] = *b"HdrS";
/// プロトコル版 2.15。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const PROTOCOL_VERSION: u16 = 0x020F;
/// `pref_address`（0x258）。payload のロード先。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const PREF_ADDRESS: u64 = 0x100_0000;
/// ロード後のエントリの期待値（pref_address + 0x200）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const EXPECTED_ENTRY: u64 = PREF_ADDRESS + ENTRY_64_OFFSET as u64;
/// `initrd_addr_max`（0x22C）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const INITRD_ADDR_MAX: u32 = 0x3FF_FFFF;
/// `kernel_alignment`（0x230）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const KERNEL_ALIGNMENT: u32 = 0x20_0000;
/// `cmdline_size`（0x238）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const CMDLINE_SIZE: u32 = 2047;
/// `init_size`（0x260）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const INIT_SIZE: u32 = 0x40_0000;
/// `ud2`（#UD を起こす命令）。不一致時に即座に失敗させる payload の埋め草。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub const UD2: [u8; 2] = [0x0F, 0x0B];

/// ヘッダのフィールドを書く。範囲外は試験のバグなので panic でよい（内部入力のみ）。
fn put(img: &mut [u8], off: usize, bytes: &[u8]) {
    let end = off + bytes.len();
    img.get_mut(off..end)
        .expect("header field must fit in the synthetic image")
        .copy_from_slice(bytes);
}

/// ヘッダ 13 フィールドだけを書いた、長さ [`IMAGE_LEN`] のゼロ埋めイメージ（payload はゼロのまま）。
///
/// setup_sects=4・version 2.15・LOADED_HIGH・XLF_KERNEL_64・relocatable・pref 0x100_0000。
/// 実行しない試験（ローダ・LAPIC の確認）と、payload を自前で埋める試験の土台。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn header_only() -> Vec<u8> {
    let mut img = vec![0u8; IMAGE_LEN];
    put(&mut img, 0x1F1, &[SETUP_SECTS]);
    put(&mut img, 0x1FE, &0xAA55u16.to_le_bytes());
    put(&mut img, 0x201, &[0x62]);
    put(&mut img, 0x202, &HEADER_MAGIC);
    put(&mut img, 0x206, &PROTOCOL_VERSION.to_le_bytes());
    put(&mut img, 0x211, &[1]);
    put(&mut img, 0x22C, &INITRD_ADDR_MAX.to_le_bytes());
    put(&mut img, 0x230, &KERNEL_ALIGNMENT.to_le_bytes());
    put(&mut img, 0x234, &[1]);
    put(&mut img, 0x236, &1u16.to_le_bytes());
    put(&mut img, 0x238, &CMDLINE_SIZE.to_le_bytes());
    put(&mut img, 0x258, &PREF_ADDRESS.to_le_bytes());
    put(&mut img, 0x260, &INIT_SIZE.to_le_bytes());
    img
}

/// payload の i 番目（payload 先頭が 0）を `fill(i)` で埋める。ヘッダ部は触らない。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn fill_payload(img: &mut [u8], mut fill: impl FnMut(usize) -> u8) {
    let payload = img
        .get_mut(PAYLOAD_OFFSET..)
        .expect("image must be at least as long as the payload offset");
    for (i, b) in payload.iter_mut().enumerate() {
        *b = fill(i);
    }
}

/// payload を `ud2`（0F 0B）の交互で埋める。エントリ以外へ迷い込んだら即座に #UD で失敗させる。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn fill_payload_ud2(img: &mut [u8]) {
    fill_payload(img, |i| UD2[i % 2]);
}

/// 64-bit エントリ（payload + 0x200）へ `code` を置く。payload に収まらなければ panic する。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn put_entry_code(img: &mut [u8], code: &[u8]) {
    let start = PAYLOAD_OFFSET + ENTRY_64_OFFSET;
    img.get_mut(start..start + code.len())
        .expect("entry code must fit in the synthetic payload")
        .copy_from_slice(code);
}

/// 合成 bzImage 本体。ヘッダ + `ud2` 埋めの payload + エントリの `entry_code`。
///
/// `entry_code` が空なら payload 全体が `ud2`。実機前提試験が `KvmDevice` で実行する標準の入力。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn synthetic_bzimage(entry_code: &[u8]) -> Vec<u8> {
    let mut img = header_only();
    fill_payload_ud2(&mut img);
    put_entry_code(&mut img, entry_code);
    img
}
