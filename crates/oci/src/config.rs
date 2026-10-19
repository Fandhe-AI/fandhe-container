//! image config の `rootfs.diff_ids` の読み取り（#2017・OCI-1・TASK-52 追補）。
//!
//! image config は pull したイメージの「展開後 tar の sha256（diff_id）」をレイヤーごとに宣言する。
//! 本モジュールは config 本文から `rootfs.diff_ids` だけを検証済みの型で取り出し、
//! `layer::extract::extract_image_layers` が展開と同じ読み取りで計算した diff_id と突合できるようにする。
//! config は信頼できない入力のため、長さ・件数を先に検証し、不正な形は fail-closed で拒否する。
//!
//! 呼び出し契約: config blob 自体の digest 検証（`layer::verify_blob_digest`）は呼び出し側の責務で、
//! 本モジュールは本文の JSON だけを見る。`rootfs` 以外のフィールド（`config`・`history` 等）は読まない。

use serde::Deserialize;

use crate::error::{OciError, OciErrorCode};
use crate::manifest::MAX_LAYERS;
use crate::reference::Digest;

/// config 本文の最大バイト数（cri の `DEFAULT_MAX_CONFIG_BYTES` と同値。依存の向きを守るため oci 側で定義する）。
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// image config の `rootfs`（`type` と `diff_ids`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageRootFs {
    diff_ids: Vec<Digest>,
}

impl ImageRootFs {
    /// 下位から上位の順の diff_id。
    pub fn diff_ids(&self) -> &[Digest] {
        &self.diff_ids
    }
}

#[derive(Deserialize)]
struct RawConfig {
    rootfs: Option<RawRootFs>,
}

#[derive(Deserialize)]
struct RawRootFs {
    #[serde(rename = "type")]
    kind: Option<String>,
    diff_ids: Option<Vec<String>>,
}

fn data_loss(msg: &'static str) -> OciError {
    OciError::new(OciErrorCode::DataLoss, msg)
}

/// config 本文から `rootfs.diff_ids` を検証して取り出す。
///
/// エラー: 本文が [`MAX_CONFIG_BYTES`] 超・件数が `manifest::MAX_LAYERS` 超は `ResourceExhausted`、
/// JSON として不正・`rootfs` 欠落・`type` が `layers` でない・`diff_ids` 欠落・要素の形式不正は `DataLoss`、
/// sha256 以外のアルゴリズムは `Unimplemented`。
pub fn parse_image_config_rootfs(body: &[u8]) -> Result<ImageRootFs, OciError> {
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config body is too large",
        ));
    }
    let raw: RawConfig =
        serde_json::from_slice(body).map_err(|_| data_loss("image config is not valid JSON"))?;
    let rootfs = raw
        .rootfs
        .ok_or_else(|| data_loss("image config is missing rootfs"))?;
    if rootfs.kind.as_deref() != Some("layers") {
        return Err(data_loss("image config rootfs type is not layers"));
    }
    let ids = rootfs
        .diff_ids
        .ok_or_else(|| data_loss("image config is missing rootfs.diff_ids"))?;
    if ids.len() > MAX_LAYERS {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config has too many diff_ids",
        ));
    }
    let mut diff_ids = Vec::with_capacity(ids.len());
    for id in &ids {
        match Digest::parse(id) {
            Ok(d) => diff_ids.push(d),
            Err(_) => {
                // `<alg>:<hex>` 形で sha256 以外は未対応、それ以外は形式不正。
                let other_alg = id.split_once(':').is_some_and(|(alg, hex)| {
                    !alg.is_empty() && !hex.is_empty() && alg != "sha256"
                });
                return Err(if other_alg {
                    OciError::new(OciErrorCode::Unimplemented, "unsupported diff_id algorithm")
                } else {
                    data_loss("image config diff_id is malformed")
                });
            }
        }
    }
    Ok(ImageRootFs { diff_ids })
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn code(body: &str) -> OciErrorCode {
        parse_image_config_rootfs(body.as_bytes())
            .unwrap_err()
            .code()
    }

    /// OCI-1: 正常な config から diff_ids が順序どおり取れる。
    #[test]
    fn oci1_config_diff_ids_are_parsed_in_order() {
        let body = format!(
            r#"{{"architecture":"arm64","rootfs":{{"type":"layers","diff_ids":["sha256:{H1}","sha256:{H2}"]}}}}"#
        );
        let r = parse_image_config_rootfs(body.as_bytes()).unwrap();
        let got: Vec<&str> = r.diff_ids().iter().map(Digest::as_str).collect();
        assert_eq!(got, vec![format!("sha256:{H1}"), format!("sha256:{H2}")]);
    }

    /// OCI-1: 欠落・型不正・形式不正は DataLoss、他アルゴリズムは Unimplemented。
    #[test]
    fn oci1_config_malformed_inputs_are_rejected() {
        assert_eq!(code("not json"), OciErrorCode::DataLoss);
        assert_eq!(code("{}"), OciErrorCode::DataLoss);
        assert_eq!(
            code(r#"{"rootfs":{"type":"other","diff_ids":[]}}"#),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(r#"{"rootfs":{"type":"layers"}}"#),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(r#"{"rootfs":{"type":"layers","diff_ids":"x"}}"#),
            OciErrorCode::DataLoss
        );
        assert_eq!(
            code(r#"{"rootfs":{"type":"layers","diff_ids":["sha256:zz"]}}"#),
            OciErrorCode::DataLoss
        );
        let sha512 = format!(r#"{{"rootfs":{{"type":"layers","diff_ids":["sha512:{H1}"]}}}}"#);
        assert_eq!(code(&sha512), OciErrorCode::Unimplemented);
    }

    /// OCI-1: 件数・本文長の上限は ResourceExhausted。
    #[test]
    fn oci1_config_limits_are_enforced() {
        let one = format!(r#""sha256:{H1}""#);
        let many = vec![one; MAX_LAYERS + 1].join(",");
        let body = format!(r#"{{"rootfs":{{"type":"layers","diff_ids":[{many}]}}}}"#);
        assert_eq!(code(&body), OciErrorCode::ResourceExhausted);
        let big = vec![b' '; MAX_CONFIG_BYTES as usize + 1];
        assert_eq!(
            parse_image_config_rootfs(&big).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
    }
}
