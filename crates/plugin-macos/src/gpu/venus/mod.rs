//! 最小 venus デコーダの wire フォーマットパース骨格（GPU-6・TASK-172.2・#723）。
//!
//! ゲスト（Mesa venus ドライバ）が virtio-gpu 経由で送る Vulkan コマンドストリームの「構造」だけを
//! 解釈する: 境界検査つき読み取りカーソル（[`WireReader`]）、候補コマンド種別（[`CommandType`]。
//! TASK-172.1 の 116 件に限定）、コマンドヘッダ（[`parse_command_header`]）、構造化エラー
//! （[`VenusWireError`]）。入力は untrusted で、全読み取りを境界検査し、未知の種別は読み飛ばさず
//! 拒否する（fail-closed）。借用のみで確保しない。
//!
//! 出典: virgl/venus-protocol タグ `v1.1.3`（コミット `ca19b6358d7c`）。
//! `xmls/VK_MESA_venus_protocol.xml` SHA-256 `d92839bc728fa9ad9a7decdc6b91df6fa1a0fb26cffae4009865f18a789e0535`、
//! `xmls/VK_EXT_command_serialization.xml` SHA-256 `2451e5dcc5306f604c52da48a8cc883a24de708dd86f38bbb035d29a753a0474`。
//! 値（事実情報）のみを転記し、コードや生成物は流用していない。
//!
//! コマンドストリームの記録と再生ハーネスは [`replay`]（TASK-172.5・#889）。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: コマンドごとの引数パース（構造体・pNext・ハンドル表）と
//! Vulkan へのディスパッチ（TASK-177.x: #765・#769・#771・#773・#774）、reply ストリームの符号化、
//! ring・共有メモリ、virtio-gpu の ctrl 枠（`GET_CAPSET_INFO` / `GET_CAPSET`。TASK-175）、対象サブセットの確定（#726）。
//! capset の中身の応答は [`capset_info`]・[`respond_capset_query`] に最小実装がある（TASK-172.3・#724。暫定値・実ゲスト未検証）。現時点でどこからも
//! 呼ばれない独立モジュールで、frame_loop・adapter へは配線していない。

mod capset;
mod command;
mod error;
mod reader;
pub mod replay;

pub use capset::{
    CapsetInfo, CapsetResponse, VENUS_CAPSET_ID, VENUS_CAPSET_LEN, VENUS_CAPSET_MAX_VERSION,
    VenusCapset, capset_info, respond_capset_query,
};
pub use command::{
    COMMAND_HEADER_LEN, CommandFlags, CommandHeader, CommandPriority, CommandType,
    parse_command_header,
};
pub use error::{VenusCapsetError, VenusWireError};
pub use reader::{MAX_ARRAY_LEN, WireReader};

#[cfg(test)]
mod tests;
