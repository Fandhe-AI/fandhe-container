//! core から見た plugin 境界基盤の入口（`plugin` feature 配下）。
//!
//! # 役割
//!
//! `fandhe-container-plugin`（UDS・長さ接頭辞フレーム等の境界基盤）の型を core の利用側へ
//! 再エクスポートする。本モジュールと `fandhe-container-plugin` への依存は `plugin` feature が
//! 無効（`--no-default-features`）のときコンパイル対象から外れる（PLUG-3・TASK-111.1・#262）。
//!
//! # 現状（REPAIR-3）
//!
//! 再エクスポートのみで、新しいロジック・`unsafe`・I/O は持たない。plugin の発見・登録
//! （TASK-109）はこのゲート配下に置く予定だが未実装で、現時点では軽量化の効果はほぼない。
//! 効果の実測と CI への組み込みは TASK-111.2（#263）で行う。
//!
//! # 注意
//!
//! 将来 PLUG-11・PLUG-12 の検証コードをこのゲート配下に置く場合は、feature を無効にしたとき
//! 検証だけが抜けて plugin を読み込める構成（fail-open）にしないこと。

pub use fandhe_container_plugin::{
    ControlMessage, Frame, FrameHeader, MAX_FRAME_LEN, MessageId, PROTOCOL_VERSION, PluginError,
    PluginErrorCode,
};

#[cfg(test)]
mod tests {
    /// 再エクスポートが plugin crate の定数と一致すること（PLUG-3・TASK-111.1）。
    #[test]
    fn plug3_task111_1_reexports_match_plugin_crate() {
        assert_eq!(
            super::PROTOCOL_VERSION,
            fandhe_container_plugin::PROTOCOL_VERSION
        );
        assert_eq!(super::PROTOCOL_VERSION, 1);
        assert_eq!(super::MAX_FRAME_LEN, fandhe_container_plugin::MAX_FRAME_LEN);
    }
}
