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
//! 再エクスポートと、照合済み fd から起動対象を作る変換 [`HashVerifiedPluginFile::into_launch_target`]
//! （PLUG-11・#1857）を持つ。変換は `unsafe`・パスの再 open・新しい I/O を持たない。本番で起動 API を
//! 呼ぶ配線は未実装（設計は #1869、承認と実装 issue の起票は #2232）。macOS 等は起動直前に dev / ino を照合する（#1866。実装済み）。
//! plugin の発見・登録（TASK-109）はこのゲート配下に置く予定だが未実装で、現時点では軽量化の効果はほぼない。
//! CI への組み込みとサイズ記録は TASK-111.2（#263）で導入済み（`make plugin-feature-size`・docs/design/plugin-feature-size-record.md）。
//! `make plugin-feature-size` は CLI の実行ファイルの既定 / 除外を比べる（cli の `plugin` feature・supervisor の
//! `default-features = false` で feature 伝播を設計済み。#3204）。ゲート配下に実装が入る TASK-109・TASK-110 の後に再計測する。
//!
//! # 注意
//!
//! 将来 PLUG-11・PLUG-12 の検証コードをこのゲート配下に置く場合は、feature を無効にしたとき
//! 検証だけが抜けて plugin を読み込める構成（fail-open）にしないこと。

use crate::plugin_trust::HashVerifiedPluginFile;

pub use fandhe_container_plugin::{
    ControlMessage, Frame, FrameHeader, MAX_FRAME_LEN, MessageId, PROTOCOL_VERSION, PluginError,
    PluginErrorCode, PluginLaunchTarget,
};

impl HashVerifiedPluginFile {
    /// ハッシュ照合を通した fd を、plugin の起動 API が受け取る [`PluginLaunchTarget`] へ変換する。
    ///
    /// 本番で `PluginLaunchTarget::from_verified_file` を呼んでよい唯一の場所（#1320 のオーナー判断・
    /// #1857・PLUG-11）。`make check-launch-target` が CI で「構築口の呼び出しが本変換と許可した
    /// 試験コードだけ」であることを機械判定する。受けるのは `HashVerifiedPluginFile` の値だけで、
    /// パス・生の fd・未照合の `VerifiedPluginFile` からは作れない。
    ///
    /// 照合に使った fd をそのまま渡し（plugin 側で close-on-exec に複製される）、パスは開き直さない。
    /// `display` は検証時のパス、`exec` は実体の正規パス。`#!` スクリプト等は plugin 側が
    /// `InvalidArgument` で拒否し、パス起動へは縮退しない（fail-closed）。
    /// 本番で起動を呼ぶ配線は #1869 の設計（承認と実装 issue の起票は #2232）、エラーコードへの写像も呼び出し側が決める。
    pub fn into_launch_target(self) -> Result<PluginLaunchTarget, PluginError> {
        let display = self.path().to_path_buf();
        let exec = self.resolved_path().to_path_buf();
        let file = self.into_file().into_file();
        PluginLaunchTarget::from_verified_file(file, display, exec)
    }
}

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
