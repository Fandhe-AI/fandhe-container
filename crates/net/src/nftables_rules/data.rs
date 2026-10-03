//! nf_tables の `NFTA_DATA_VALUE`（cmp・immediate が運ぶ定数データ）の型付きエンコード
//! （TASK-138.3・NET-11・REPAIR-2・MS-8・#311）。
//!
//! [`super::NftCmp`]・[`super::NftImmediate`] が共有する OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。
//!
//! ```text
//! <属性種別> | NLA_F_NESTED {
//!   NFTA_DATA_VALUE = 1..=16 バイトの生データ（呼び出し側が必要なバイトオーダーで渡す）
//! }
//! ```
//!
//! # 信頼境界
//!
//! 値長は 1..=[`NFT_REG_SIZE`]（`struct nft_data` の大きさ）に構築時に制限する。
//! [`NftDataValue::from_attr`] は kernel 応答など外部由来の属性も untrusted として扱い、
//! 非ネスト・子の過不足・`NFTA_DATA_VERDICT`・ネストした子・長さ違反を `DataLoss` で拒否する。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - verdict データ（`NFTA_DATA_VERDICT`）。型として表現できず、受け取ると `DataLoss` にする

use super::{NftExprAttr, NftExprValue, data_loss, invalid};
use crate::error::NetError;

/// データ値の属性（`NFTA_DATA_VALUE`）。
pub const NFTA_DATA_VALUE: u16 = 1;
/// データ値の最大長（`NFT_REG_SIZE`）。
pub const NFT_REG_SIZE: usize = 16;

/// 1..=[`NFT_REG_SIZE`] バイトの定数データ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftDataValue(Vec<u8>);

impl NftDataValue {
    /// 長さ 0 と [`NFT_REG_SIZE`] 超は `InvalidArgument`。
    pub fn new(bytes: &[u8]) -> Result<Self, NetError> {
        if bytes.is_empty() || bytes.len() > NFT_REG_SIZE {
            return Err(invalid("nft data value length must be 1..=16 bytes"));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// 生バイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// バイト長。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 構築時に 1 バイト以上を強制しているため常に false。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `attr_type` のネスト属性（子は `NFTA_DATA_VALUE` のみ）へ変換する。
    pub(super) fn to_attr(&self, attr_type: u16) -> Result<NftExprAttr, NetError> {
        NftExprAttr::nested(
            attr_type,
            vec![NftExprAttr::bytes(NFTA_DATA_VALUE, self.0.clone())?],
        )
    }

    /// `to_attr` の逆変換。違反はすべて `DataLoss`。
    pub(super) fn from_attr(attr: &NftExprAttr) -> Result<Self, NetError> {
        let NftExprValue::Nested(children) = attr.value() else {
            return Err(data_loss("nft data attribute is not nested"));
        };
        let [child] = children.as_slice() else {
            return Err(data_loss("nft data must have exactly one child"));
        };
        if child.attr_type() != NFTA_DATA_VALUE {
            return Err(data_loss("unsupported nft data kind"));
        }
        let NftExprValue::Bytes(b) = child.value() else {
            return Err(data_loss("nft data value is nested"));
        };
        Self::new(b).map_err(|_| data_loss("nft data value length out of range"))
    }
}
