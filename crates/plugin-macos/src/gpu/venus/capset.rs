//! venus capset 応答の最小実装（GPU-6・TASK-172.3・#724）。
//!
//! PoC-14 では既存 OSS 構成が venus capset（id 4）を `max-size=0` で返し、ゲストの Mesa venus が
//! 物理デバイス 0 件と判定して機能しなかった。本モジュールは「capset クエリに max-size が 0 でない
//! 応答を返す」最小実装で、トランスポート非依存（virtio-gpu の ctrl ヘッダ・virtqueue は持たない）。
//! 将来の呼び出し元は #888 の治具アダプタと、TASK-175 のデバイスモデル（本応答を
//! `GET_CAPSET_INFO` / `GET_CAPSET` の応答へ包む）。現時点でどこからも呼ばれない独立モジュール。
//!
//! レイアウト（`struct virgl_renderer_capset_venus`。全て `u32` リトルエンディアン、計 160 バイト）:
//! `wire_format_version`(0) / `vk_xml_version`(4) / `vk_ext_command_serialization_spec_version`(8) /
//! `vk_mesa_venus_protocol_spec_version`(12) / `supports_blob_id_0`(16) / `vk_extension_mask1[32]`(20..148) /
//! `allow_vk_wait_syncs`(148) / `supports_multiple_timelines`(152) / `use_guest_vram`(156)。
//!
//! 出典（確認日 2026-10-09。値のみ転記しコードは流用していない。SHA-256 は全件を計画フェーズで上流から再取得して照合）:
//! - virglrenderer `virglrenderer-1.1.0` の `src/venus_hw.h`（`7bc1a8195294d681f4081719e7c4dfea396765e82b5583a2471fad9705aab64e`）: 構造体レイアウトとフィールド名
//! - mesa `mesa-25.0.0` の `src/virtio/virtio-gpu/venus_hw.h`（`fa736817518a9c94bf50788a404cae8282987e2e82bcee6436370b2cc6a5988b`）: レイアウトと、`vk_extension_mask1` の bit 0 の意味
//! - mesa `mesa-25.0.0` の `src/virtio/vulkan/vn_renderer_virtgpu.c`（`a7a0f1a395d006bfb1ef4aea4d3b2c6a44c30c50ede855416e1183442e1e03aa`）: flag 3 件と `supports_blob_id_0` への `assert`（1394・1402・1404・1456 行。release ビルドでは検査されない）
//! - mesa `mesa-25.0.0` の `src/virtio/vulkan/vn_instance.c`（`b8d3461d9a8b8d740d7c383100ac972e256263d9bd55e663be31f709c4e838a9`）: ゲストの受理条件（`wire_format_version` の完全一致・`vk_xml_version` の上限クランプと最小版の拒否。165〜184 行）
//! - venus-protocol `v1.1.3` の `xmls/VK_EXT_command_serialization.xml`（`2451e5dcc5306f604c52da48a8cc883a24de708dd86f38bbb035d29a753a0474`）: 拡張番号 384・spec version 1
//! - venus-protocol `v1.1.3` の `xmls/VK_MESA_venus_protocol.xml`（`d92839bc728fa9ad9a7decdc6b91df6fa1a0fb26cffae4009865f18a789e0535`）: 拡張番号 385・spec version 4
//! - venus-protocol `v1.1.3` の `xmls/vk.xml`（`264d0d7350e37d70c82407fb430d085040fc01a9a961d43dec8c2d6ed1dfd183`）: `VK_HEADER_VERSION`（357）だけを取った。venus の 2 拡張は含まれない
//!
//! ライセンス・著作権表記（転記はフィールド名・並び・数値定数のみのため NOTICE は作らない。オーナー判断）:
//! - `venus_hw.h`（virglrenderer・mesa）: MIT、`Copyright 2020 Chromium`
//! - `vn_renderer_virtgpu.c`: MIT、`Copyright 2020 Google LLC`
//! - `vn_instance.c`: MIT、`Copyright 2019 Google LLC`（ほかに anv / radv 由来の帰属表記〔Intel Corporation・Red Hat・Bas Nieuwenhuizen〕を含む）
//! - `VK_EXT_command_serialization.xml`・`VK_MESA_venus_protocol.xml`: `Apache-2.0 OR MIT`、`Copyright 2020 Google LLC`
//! - `vk.xml`: `Apache-2.0 OR MIT`、`Copyright 2015-2026 The Khronos Group Inc.`
//!
//! 広告値は PoC の暫定値で確定扱いにしない（#725・#726・#1057 で見直す）。未実装（REPAIR-3）:
//! `supports_blob_id_0`・`allow_vk_wait_syncs`・`supports_multiple_timelines` を 1 にするのは対応機能
//! （TASK-176・177 で実装）を前提とした宣言で、現時点では未実装。実ゲストが受理するかは未検証（#725）。

use super::error::VenusCapsetError;

/// venus の capset id（virtio-gpu の `VIRTIO_GPU_CAPSET_VENUS`）。
pub const VENUS_CAPSET_ID: u32 = 4;
/// 対応する capset の最大 version（Mesa は version 0 で要求する）。
pub const VENUS_CAPSET_MAX_VERSION: u32 = 0;
/// capset データの長さ（バイト）。`u32` 5 個 + 拡張マスク 32 個 + `u32` 3 個。
pub const VENUS_CAPSET_LEN: usize = 4 * (5 + 32 + 3);

const _: () = assert!(VENUS_CAPSET_LEN <= u32::MAX as usize);

/// 広告する capset の個数（VENUS のみ）。
const CAPSET_COUNT: u32 = 1;
/// 拡張マスクの語数。
const EXT_MASK_WORDS: usize = 32;

/// `VK_MAKE_API_VERSION(variant, major, minor, patch)` 相当。
const fn make_api_version(variant: u32, major: u32, minor: u32, patch: u32) -> u32 {
    (variant << 29) | (major << 22) | (minor << 12) | patch
}

/// 拡張番号 `ext` を立てる（`mask1[ext / 32]` の bit `ext % 32`）。範囲外の番号は無視する。
const fn with_extension(mut mask: [u32; EXT_MASK_WORDS], ext: u32) -> [u32; EXT_MASK_WORDS] {
    let word = (ext / 32) as usize;
    if word < EXT_MASK_WORDS {
        mask[word] |= 1 << (ext % 32);
    }
    mask
}

/// `VK_EXT_command_serialization` の拡張番号（venus-protocol v1.1.3 の `xmls/VK_EXT_command_serialization.xml`）。
const EXT_COMMAND_SERIALIZATION: u32 = 384;
/// `VK_MESA_venus_protocol` の拡張番号（venus-protocol v1.1.3 の `xmls/VK_MESA_venus_protocol.xml`）。
const EXT_MESA_VENUS_PROTOCOL: u32 = 385;

/// 最小拡張マスク: bit 0（マスク有効。未設定だと「全拡張対応」と解釈される）と venus 自身の 2 拡張のみ。
const fn minimal_extension_mask() -> [u32; EXT_MASK_WORDS] {
    let mut mask = [0u32; EXT_MASK_WORDS];
    mask = with_extension(mask, 0);
    mask = with_extension(mask, EXT_COMMAND_SERIALIZATION);
    with_extension(mask, EXT_MESA_VENUS_PROTOCOL)
}

/// venus capset の中身（`struct virgl_renderer_capset_venus` 相当）。
///
/// フィールド非公開で、[`VenusCapset::minimal`] 以外の構築経路を持たない（壊れた値を表現させない。REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VenusCapset {
    wire_format_version: u32,
    vk_xml_version: u32,
    vk_ext_command_serialization_spec_version: u32,
    vk_mesa_venus_protocol_spec_version: u32,
    supports_blob_id_0: u32,
    vk_extension_mask1: [u32; EXT_MASK_WORDS],
    allow_vk_wait_syncs: u32,
    supports_multiple_timelines: u32,
    use_guest_vram: u32,
}

impl VenusCapset {
    /// 最小実装が広告する暫定値で組み立てる唯一の構築経路（値の根拠はモジュール doc と設計文書）。
    pub const fn minimal() -> Self {
        Self {
            wire_format_version: 1,
            // venus-protocol v1.1.3 の VK_HEADER_VERSION 357。ゲスト側で上限クランプされる。
            vk_xml_version: make_api_version(0, 1, 4, 357),
            vk_ext_command_serialization_spec_version: 1,
            vk_mesa_venus_protocol_spec_version: 4,
            supports_blob_id_0: 1,
            vk_extension_mask1: minimal_extension_mask(),
            allow_vk_wait_syncs: 1,
            supports_multiple_timelines: 1,
            use_guest_vram: 0,
        }
    }

    /// `wire_format_version`（Mesa が完全一致を要求する）。
    pub const fn wire_format_version(&self) -> u32 {
        self.wire_format_version
    }

    /// 広告する拡張マスク（32 語）。
    pub const fn extension_mask(&self) -> &[u32; EXT_MASK_WORDS] {
        &self.vk_extension_mask1
    }

    /// ワイヤー表現（全フィールド `u32` リトルエンディアン、160 バイト）へ符号化する。
    pub fn encode(&self) -> [u8; VENUS_CAPSET_LEN] {
        let head = [
            self.wire_format_version,
            self.vk_xml_version,
            self.vk_ext_command_serialization_spec_version,
            self.vk_mesa_venus_protocol_spec_version,
            self.supports_blob_id_0,
        ];
        let tail = [
            self.allow_vk_wait_syncs,
            self.supports_multiple_timelines,
            self.use_guest_vram,
        ];
        let words = head
            .iter()
            .chain(self.vk_extension_mask1.iter())
            .chain(tail.iter());
        let mut out = [0u8; VENUS_CAPSET_LEN];
        let (chunks, _) = out.as_chunks_mut::<4>();
        for (chunk, word) in chunks.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        out
    }
}

/// capset info クエリへの回答（`GET_CAPSET_INFO` 相当の中身）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapsetInfo {
    /// capset id。
    pub id: u32,
    /// 対応する最大 version。
    pub max_version: u32,
    /// capset データの長さ（バイト）。0 でない。
    pub max_size: u32,
}

/// capset クエリへの回答（`GET_CAPSET` 相当の中身）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapsetResponse {
    /// 対応する info。
    pub info: CapsetInfo,
    /// capset データ（`info.max_size` バイト）。
    pub data: [u8; VENUS_CAPSET_LEN],
}

fn venus_info() -> CapsetInfo {
    CapsetInfo {
        id: VENUS_CAPSET_ID,
        max_version: VENUS_CAPSET_MAX_VERSION,
        // 上の const assert で収まることを静的に検査済み。
        max_size: u32::try_from(VENUS_CAPSET_LEN).unwrap_or(u32::MAX),
    }
}

/// index 番目の capset の info を返す。index 0 のみ VENUS で、他は拒否する（fail-closed）。
pub fn capset_info(index: u32) -> Result<CapsetInfo, VenusCapsetError> {
    if index == 0 {
        Ok(venus_info())
    } else {
        Err(VenusCapsetError::IndexOutOfRange {
            index,
            count: CAPSET_COUNT,
        })
    }
}

/// `(id, version)` の capset クエリに応答する。VENUS・version 0 以外は拒否する（fail-closed）。
pub fn respond_capset_query(id: u32, version: u32) -> Result<CapsetResponse, VenusCapsetError> {
    if id != VENUS_CAPSET_ID {
        return Err(VenusCapsetError::UnsupportedCapset { id });
    }
    if version > VENUS_CAPSET_MAX_VERSION {
        return Err(VenusCapsetError::UnsupportedVersion {
            requested: version,
            max: VENUS_CAPSET_MAX_VERSION,
        });
    }
    Ok(CapsetResponse {
        info: venus_info(),
        data: VenusCapset::minimal().encode(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(data: &[u8], off: usize) -> u32 {
        let b: [u8; 4] = data[off..off + 4].try_into().unwrap();
        u32::from_le_bytes(b)
    }

    #[test]
    fn task172_3_gpu6_len_is_160() {
        assert_eq!(VENUS_CAPSET_LEN, 160);
        assert_eq!(VenusCapset::minimal().encode().len(), 160);
    }

    #[test]
    fn task172_3_gpu6_info_has_nonzero_max_size() {
        let info = capset_info(0).unwrap();
        assert_eq!(info.id, 4);
        assert_eq!(info.max_version, 0);
        assert_eq!(info.max_size, 160);
    }

    #[test]
    fn task172_3_gpu6_fields_at_fixed_offsets() {
        let r = respond_capset_query(4, 0).unwrap();
        let d = &r.data;
        assert_eq!(le(d, 0), 1);
        assert_eq!(le(d, 4), 0x0040_4165);
        assert_eq!(le(d, 8), 1);
        assert_eq!(le(d, 12), 4);
        assert_eq!(le(d, 16), 1);
        assert_eq!(le(d, 148), 1);
        assert_eq!(le(d, 152), 1);
        assert_eq!(le(d, 156), 0);
    }

    #[test]
    fn task172_3_gpu6_extension_mask() {
        let d = respond_capset_query(4, 0).unwrap().data;
        for i in 0..32 {
            let expected = match i {
                0 => 0x1,
                12 => 0x3,
                _ => 0,
            };
            assert_eq!(le(&d, 20 + 4 * i), expected, "mask word {i}");
        }
    }

    #[test]
    fn task172_3_gpu6_full_bytes_match_independent_build() {
        let mut expected = vec![0u8; 160];
        let mut put = |off: usize, v: u32| expected[off..off + 4].copy_from_slice(&v.to_le_bytes());
        put(0, 1);
        put(4, 0x0040_4165);
        put(8, 1);
        put(12, 4);
        put(16, 1);
        put(20, 1);
        put(20 + 48, 3);
        put(148, 1);
        put(152, 1);
        put(156, 0);
        assert_eq!(respond_capset_query(4, 0).unwrap().data.to_vec(), expected);
    }

    #[test]
    fn task172_3_gpu6_rejects_other_capsets_and_versions() {
        for id in [0, 1, 2, 3, 5, 6, u32::MAX] {
            let e = respond_capset_query(id, 0).unwrap_err();
            assert_eq!(e, VenusCapsetError::UnsupportedCapset { id });
            assert_eq!(e.code(), "venus_capset.unsupported_capset");
        }
        for v in [1, u32::MAX] {
            let e = respond_capset_query(4, v).unwrap_err();
            assert_eq!(
                e,
                VenusCapsetError::UnsupportedVersion {
                    requested: v,
                    max: 0
                }
            );
            assert_eq!(e.code(), "venus_capset.unsupported_version");
        }
        for i in [1, u32::MAX] {
            let e = capset_info(i).unwrap_err();
            assert_eq!(e, VenusCapsetError::IndexOutOfRange { index: i, count: 1 });
            assert_eq!(e.code(), "venus_capset.index_out_of_range");
        }
    }

    #[test]
    fn task172_3_gpu6_error_messages_are_english_numeric() {
        assert_eq!(
            VenusCapsetError::UnsupportedCapset { id: 7 }.message(),
            "unsupported capset id 7"
        );
        assert_eq!(
            VenusCapsetError::UnsupportedVersion {
                requested: 2,
                max: 0
            }
            .message(),
            "unsupported capset version 2, max 0"
        );
        assert_eq!(
            VenusCapsetError::IndexOutOfRange { index: 3, count: 1 }.message(),
            "capset index 3 out of range, count 1"
        );
    }
}
