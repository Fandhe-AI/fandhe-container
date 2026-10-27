//! rootless の pasta 構成（NET-9）の `crates/net` 側の部品の入口（TASK-147 追補）。
//!
//! 現在は `port_forward`（ポート公開指定の検証と pasta の引数配列への変換。#1937）だけを持つ。
//! pasta の探索・検証・起動は別 issue（#1936・#1938）が同じ親モジュールに足す。OS 非依存の純粋関数のみで、
//! `cfg` を付けない。

pub mod port_forward;

pub use port_forward::{
    DEFAULT_LISTEN_ADDR, MAX_PORT_FORWARD_SPEC_LEN, PastaPortForward, PastaPortForwards,
};
