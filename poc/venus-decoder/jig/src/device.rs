//! 治具バックエンドが広告する virtio-gpu の feature と config（GPU-6・TASK-172.4）。
//!
//! Mesa venus（`mesa-25.0.0` の `vn_renderer_virtgpu.c` の `required_params`）は capset 取得より前に
//! 3D 機能・blob リソース・コンテキスト初期化を必須として検査し、欠けると初期化を中止する。治具 VMM が
//! ゲストへこれらの feature を見せることが、capset クエリが発行される前提になる。後続 F1 のトランスポートが使う。

/// `VIRTIO_GPU_F_VIRGL`（bit 0）。
pub const F_VIRGL: u32 = 0;
/// `VIRTIO_GPU_F_RESOURCE_BLOB`（bit 3）。
pub const F_RESOURCE_BLOB: u32 = 3;
/// `VIRTIO_GPU_F_CONTEXT_INIT`（bit 4）。
pub const F_CONTEXT_INIT: u32 = 4;
/// `VIRTIO_F_VERSION_1`（bit 32）。
pub const F_VERSION_1: u32 = 32;

/// 広告する feature ビット集合（64bit）。
pub const FEATURES: u64 =
    (1 << F_VIRGL) | (1 << F_RESOURCE_BLOB) | (1 << F_CONTEXT_INIT) | (1 << F_VERSION_1);

/// 広告する capset の個数（`virtio_gpu_config.num_capsets`。VENUS のみ）。
pub const NUM_CAPSETS: u32 = 1;

/// `struct virtio_gpu_config`（events_read・events_clear・num_scanouts・num_capsets の 16 バイト）を作る。
/// `num_scanouts` は 0（ヘッドレス）。カーネルが 0 を受け付けるかは未確認で、F1 の実機で確かめる。
pub fn config_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(dst) = out.get_mut(12..16) {
        dst.copy_from_slice(&NUM_CAPSETS.to_le_bytes());
    }
    out
}
