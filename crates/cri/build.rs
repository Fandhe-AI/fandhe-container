//! fandhe-container-cri のビルドスクリプト: cri-api の `.proto` から gRPC コードを生成する。
//!
//! 役割（CRI-3・TASK-56.3・#426）: TASK-56.2 で配置した `proto/api.proto`（cri-api v0.37.1・無改変）を
//! protox（純 Rust の `.proto` パーサ）で解析し、tonic-prost-build で `OUT_DIR/runtime.v1.rs` へ
//! `RuntimeService` / `ImageService` のサーバー・クライアントとメッセージ型を出力する。
//! `protoc` は不要（承認: Issue #425）。外部コマンドは起動せず、入力は vendor 済みの固定ファイルのみ。
//! 生成物は `src/lib.rs` の `runtime::v1` で取り込む（TASK-56.4・#427）。

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or("CARGO_MANIFEST_DIR is not set")?;
    let proto_dir = manifest_dir.join("proto");
    let proto_file = proto_dir.join("api.proto");

    // compile_fds は rerun-if-changed を出さないため、入力と build.rs 自身を明示する。
    println!("cargo:rerun-if-changed=proto/api.proto");
    println!("cargo:rerun-if-changed=build.rs");

    let fds = protox::compile([&proto_file], [&proto_dir])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // 記録に載る config の map フィールドを BTreeMap にして符号化を決定的にする（記録の復号が再符号化とのバイト完全一致で正準性を判定するため。#2930・REPAIR-2）。
        .btree_map(".runtime.v1.PodSandboxConfig")
        .btree_map(".runtime.v1.LinuxPodSandboxConfig")
        .btree_map(".runtime.v1.ContainerConfig")
        .btree_map(".runtime.v1.ImageSpec")
        .btree_map(".runtime.v1.LinuxContainerResources")
        .compile_fds(fds)?;
    Ok(())
}
