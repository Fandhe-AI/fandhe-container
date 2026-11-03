//! image config の `rootfs.diff_ids` の読み取り（#2017・OCI-1・TASK-52 追補）。
//!
//! image config は pull したイメージの「展開後 tar の sha256（diff_id）」をレイヤーごとに宣言する。
//! 本モジュールは config 本文から `rootfs.diff_ids` だけを検証済みの型で取り出し、
//! `layer::extract::extract_image_layers` が、検証済みハンドル（`layer::VerifiedLayerBlob`）から展開と同じ読み取りで
//! 計算した diff_id と突合できるようにする。
//! config は信頼できない入力のため、長さ・件数を先に検証し、不正な形は fail-closed で拒否する。
//!
//! 呼び出し契約: config blob 自体の digest 検証（`layer::verify_blob_digest`）は呼び出し側の責務で、
//! `parse_image_config_rootfs` / `parse_image_config_process` は本文の JSON だけを見る。
//! 読むのは `rootfs`（`diff_ids`）と `config` 節の Entrypoint・Cmd・Env・WorkingDir・User・StopSignal だけで、
//! `history` 等は読まない。`config` 節は create 経路が bundle の `config.json` の既定値に使う（#2433・CRI-2）。
//! 読んだバイト列そのものを照合してから両方を解析する入口が [`parse_verified_image_config`]
//! （検証と解析の内容がずれない）。

use serde::Deserialize;

use crate::error::{OciError, OciErrorCode};
use crate::layer::verify_bytes_digest;
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

/// `config` 節の引数・環境変数の件数上限（cri の bundle 変換の `MAX_ARGS` / `MAX_ENV` と同値。依存の向きを守るため
/// oci 側で定義し、一致は cri の試験で照合する）。
pub const MAX_PROCESS_ITEMS: usize = 4096;
/// `config` 節の文字列 1 要素の長さ上限（cri の `MAX_STRING_BYTES` と同値）。
pub const MAX_PROCESS_STRING_BYTES: usize = 131_071;
/// `config` 節の WorkingDir の長さ上限（cri の `MAX_PATH_BYTES` と同値）。
pub const MAX_PROCESS_PATH_BYTES: usize = 4096;
/// `config` 節の User の長さ上限。
pub const MAX_PROCESS_USER_BYTES: usize = 256;
/// `config` 節の StopSignal の長さ上限（シグナル名・番号として十分な長さ。解釈は呼び出し側）。
pub const MAX_PROCESS_STOP_SIGNAL_BYTES: usize = 64;

/// image config の `config` 節（実行の既定値。#2433・CRI-2）。
///
/// 欠落・`null` は空として扱う。値の意味（Entrypoint と Cmd の合成・User の名前解決）は解釈せず、
/// 件数・長さ・NUL の検証だけを済ませた文字列を返す。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageProcessConfig {
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<String>,
    working_dir: String,
    user: String,
    stop_signal: String,
}

impl ImageProcessConfig {
    /// Entrypoint。
    pub fn entrypoint(&self) -> &[String] {
        &self.entrypoint
    }
    /// Cmd。
    pub fn cmd(&self) -> &[String] {
        &self.cmd
    }
    /// Env（`KEY=VALUE`。形式の検証は呼び出し側）。
    pub fn env(&self) -> &[String] {
        &self.env
    }
    /// WorkingDir（空は未指定）。
    pub fn working_dir(&self) -> &str {
        &self.working_dir
    }
    /// User（空は未指定。`uid`・`uid:gid`・名前のいずれか。解釈は呼び出し側）。
    pub fn user(&self) -> &str {
        &self.user
    }
    /// StopSignal（空は未指定。シグナル名または番号の文字列。解釈は呼び出し側。#2771・CRI-2）。
    pub fn stop_signal(&self) -> &str {
        &self.stop_signal
    }
}

#[derive(Deserialize)]
struct RawProcessDoc {
    config: Option<RawProcess>,
}

#[derive(Deserialize)]
struct RawProcess {
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(rename = "User")]
    user: Option<String>,
    #[serde(rename = "StopSignal")]
    stop_signal: Option<String>,
}

fn check_items(items: &[String], max_items: usize) -> Result<(), OciError> {
    if items.len() > max_items {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config has too many entries",
        ));
    }
    for s in items {
        check_string(s, MAX_PROCESS_STRING_BYTES)?;
    }
    Ok(())
}

fn check_string(s: &str, max_bytes: usize) -> Result<(), OciError> {
    if s.len() > max_bytes {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config value is too long",
        ));
    }
    if s.contains('\0') {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "image config value contains NUL",
        ));
    }
    Ok(())
}

/// config 本文から `config` 節（Entrypoint・Cmd・Env・WorkingDir・User・StopSignal）を検証して取り出す（#2433・CRI-2）。
///
/// エラー: 本文が [`MAX_CONFIG_BYTES`] 超・件数や長さの超過は `ResourceExhausted`、JSON として不正・型が違う・
/// NUL を含むは `InvalidArgument`（黙って捨てない。fail-closed）。
pub fn parse_image_config_process(body: &[u8]) -> Result<ImageProcessConfig, OciError> {
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config body is too large",
        ));
    }
    let doc: RawProcessDoc = serde_json::from_slice(body).map_err(|_| {
        OciError::new(
            OciErrorCode::InvalidArgument,
            "image config has an invalid config section",
        )
    })?;
    let Some(raw) = doc.config else {
        return Ok(ImageProcessConfig::default());
    };
    let entrypoint = raw.entrypoint.unwrap_or_default();
    let cmd = raw.cmd.unwrap_or_default();
    let env = raw.env.unwrap_or_default();
    let working_dir = raw.working_dir.unwrap_or_default();
    let user = raw.user.unwrap_or_default();
    let stop_signal = raw.stop_signal.unwrap_or_default();
    check_items(&entrypoint, MAX_PROCESS_ITEMS)?;
    check_items(&cmd, MAX_PROCESS_ITEMS)?;
    check_items(&env, MAX_PROCESS_ITEMS)?;
    check_string(&working_dir, MAX_PROCESS_PATH_BYTES)?;
    check_string(&user, MAX_PROCESS_USER_BYTES)?;
    check_string(&stop_signal, MAX_PROCESS_STOP_SIGNAL_BYTES)?;
    Ok(ImageProcessConfig {
        entrypoint,
        cmd,
        env,
        working_dir,
        user,
        stop_signal,
    })
}

/// 読んだバイト列そのものの sha256 を `expected`（image ID = config digest）と照合してから、`rootfs` と `config` 節を
/// 同じ本文から解析する（#2433・OCI-1。検証と解析の対象がずれない）。
///
/// 本文長の上限を先に確かめ、不一致は `DataLoss`。他のエラーは各 parse 関数と同じ。
pub fn parse_verified_image_config(
    body: &[u8],
    expected: &Digest,
) -> Result<(ImageRootFs, ImageProcessConfig), OciError> {
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "image config body is too large",
        ));
    }
    verify_bytes_digest(body, expected)?;
    Ok((
        parse_image_config_rootfs(body)?,
        parse_image_config_process(body)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(body: &str) -> Result<ImageProcessConfig, OciError> {
        parse_image_config_process(body.as_bytes())
    }

    /// CRI-2: config 節の 5 項目が具体値で取れる。欠落・null は空。
    #[test]
    fn cri2_process_section_is_parsed() {
        let p = process(
            r#"{"config":{"Entrypoint":["/bin/app"],"Cmd":["-v","x"],"Env":["A=1","B=2"],"WorkingDir":"/srv","User":"1000:2000"}}"#,
        )
        .unwrap();
        assert_eq!(p.entrypoint(), ["/bin/app"]);
        assert_eq!(p.cmd(), ["-v", "x"]);
        assert_eq!(p.env(), ["A=1", "B=2"]);
        assert_eq!(p.working_dir(), "/srv");
        assert_eq!(p.user(), "1000:2000");
        assert_eq!(process("{}").unwrap(), ImageProcessConfig::default());
        let n =
            process(r#"{"config":{"Entrypoint":null,"Cmd":null,"Env":null,"User":null}}"#).unwrap();
        assert_eq!(n, ImageProcessConfig::default());
    }

    /// CRI-2・OCI-1: StopSignal が具体値で取れ、欠落・null は空、型違い・NUL・長すぎる値は拒否される（#2771）。
    #[test]
    fn cri2_process_section_reads_stop_signal() {
        let p = process(r#"{"config":{"StopSignal":"SIGINT"}}"#).unwrap();
        assert_eq!(p.stop_signal(), "SIGINT");
        let n = process(r#"{"config":{"StopSignal":"9"}}"#).unwrap();
        assert_eq!(n.stop_signal(), "9");
        let null = process(r#"{"config":{"StopSignal":null}}"#).unwrap();
        assert_eq!(null.stop_signal(), "");
        assert_eq!(process(r#"{"config":{}}"#).unwrap().stop_signal(), "");
        let code = |b: &str| process(b).unwrap_err().code();
        assert_eq!(
            code(r#"{"config":{"StopSignal":15}}"#),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            code(r#"{"config":{"StopSignal":"SIG\u0000"}}"#),
            OciErrorCode::InvalidArgument
        );
        let long = "S".repeat(MAX_PROCESS_STOP_SIGNAL_BYTES + 1);
        assert_eq!(
            code(&format!(r#"{{"config":{{"StopSignal":"{long}"}}}}"#)),
            OciErrorCode::ResourceExhausted
        );
    }

    /// CRI-2: 型違い・NUL は InvalidArgument、件数と長さの超過は ResourceExhausted。
    #[test]
    fn cri2_process_section_rejects_bad_shapes() {
        let code = |b: &str| process(b).unwrap_err().code();
        assert_eq!(code("not json"), OciErrorCode::InvalidArgument);
        assert_eq!(
            code(r#"{"config":{"Entrypoint":"sh"}}"#),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            code(r#"{"config":{"Cmd":[1]}}"#),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            code(r#"{"config":{"WorkingDir":"/a\u0000b"}}"#),
            OciErrorCode::InvalidArgument
        );
        let many = vec![r#""x""#; MAX_PROCESS_ITEMS + 1].join(",");
        assert_eq!(
            code(&format!(r#"{{"config":{{"Cmd":[{many}]}}}}"#)),
            OciErrorCode::ResourceExhausted
        );
        let ok = vec![r#""x""#; MAX_PROCESS_ITEMS].join(",");
        assert!(process(&format!(r#"{{"config":{{"Cmd":[{ok}]}}}}"#)).is_ok());
        let long = "a".repeat(MAX_PROCESS_PATH_BYTES + 1);
        assert_eq!(
            code(&format!(r#"{{"config":{{"WorkingDir":"{long}"}}}}"#)),
            OciErrorCode::ResourceExhausted
        );
        let big = vec![b' '; MAX_CONFIG_BYTES as usize + 1];
        assert_eq!(
            parse_image_config_process(&big).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
    }

    /// OCI-1: 読んだ本文そのものの digest が一致するときだけ、rootfs と config 節が同じ本文から取れる。
    #[test]
    fn oci1_verified_config_requires_matching_digest() {
        use sha2::{Digest as _, Sha256};
        let body = format!(
            r#"{{"config":{{"Cmd":["sh"]}},"rootfs":{{"type":"layers","diff_ids":["sha256:{H1}"]}}}}"#
        );
        let hex: String = Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let good = Digest::parse(&format!("sha256:{hex}")).unwrap();
        let (rootfs, process) = parse_verified_image_config(body.as_bytes(), &good).unwrap();
        assert_eq!(rootfs.diff_ids().len(), 1);
        assert_eq!(process.cmd(), ["sh"]);
        let bad = Digest::parse(&format!("sha256:{H2}")).unwrap();
        assert_eq!(
            parse_verified_image_config(body.as_bytes(), &bad)
                .unwrap_err()
                .code(),
            OciErrorCode::DataLoss
        );
        let tampered = body.replace("sh", "ls");
        assert_eq!(
            parse_verified_image_config(tampered.as_bytes(), &good)
                .unwrap_err()
                .code(),
            OciErrorCode::DataLoss
        );
    }

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
