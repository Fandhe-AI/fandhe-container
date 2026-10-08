//! macOS の GPU 経路（virtio-gpu＋Mesa venus → MoltenVK → Metal。GPU-6・MAC-5・TASK-172〜181）の置き場。
//!
//! 現状は venus の wire パース骨格（[`venus`]。TASK-172.2）のみ。virtio-gpu デバイスモデル・
//! コンテキスト分配層・Vulkan ディスパッチは未実装（REPAIR-3。TASK-173〜181）。

pub mod venus;
