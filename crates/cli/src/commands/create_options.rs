//! `create` の起動オプション(`--ulimit`・`--env`・`--env-file`・`--label`・`--ipc`・`--shm-size`・`--tmpfs`・`--cap-drop`)の
//! 意味検証と、supervisor へ渡す文書・状態記録へ書く label の組み立て(SUP-12・CLI-1・SEC-1・#2713)。
//!
//! # 役割と呼び出し文脈
//!
//! `args::parse_create` が集めた生の文字列([`CreateOptionArgs`])を、`create_start::run_create` の要求構築で検証する。
//! 形式の判定は supervisor の既存パーサ(`Ulimit`・`EnvVar`・`IpcMode`・`ShmSize`・`TmpfsOption`・`Label`)を
//! 唯一の判定とし、CLI は二重実装しない。
//!
//! - [`document_of`]: ulimit・env・ipc・shm-size・tmpfs・cap-drop(名前は core の `parse_drop_list` で検証。CRI と共有。
//!   CLI-1・SEC-1・#2775)を [`ContainerOptionsDocument`] にする。`--env-file` は
//!   **CLI が利用者の権限で**読み(非ブロッキング・上限つき。FIFO で止まらない)、`-e` との優先順位(`-e` が後勝ち)で
//!   統合した `KEY=VALUE` 列を文書の `env` にする。特権の supervisor に利用者指定のホストのパスを読ませない
//!   (confused deputy の回避。SEC-1)。
//! - [`labels_of`]: `--label` を core の `Annotations` にし、`CreateRequest::with_annotations` で状態記録へ直接書く
//!   (supervisor を通らない)。
//!
//! エラーは固定の英語文言の `InvalidArgument` で、値・パスを含めない。secrets / configs のフラグは未提供(後続。REPAIR-3)。

use std::path::PathBuf;
use std::time::Duration;

use fandhe_container_core::traits::Annotations;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::env::{EnvFile, EnvSet, EnvVar};
use fandhe_container_supervisor::container_options::{Label, Labels};

use super::args::CreateOptionArgs;

/// 起動オプション文書を作る(空なら `is_empty()`。その場合 CLI は文書を書かない)。
pub(super) fn document_of(
    options: &CreateOptionArgs,
) -> Result<ContainerOptionsDocument, TraitError> {
    let vars = options
        .env
        .iter()
        .map(|s| EnvVar::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let files = read_env_files(&options.env_files)?;
    let env = EnvSet::resolve(&[], &files, &vars)?.to_env_strings();
    ContainerOptionsDocument::new(
        options.ulimits.clone(),
        env,
        options.ipc.clone(),
        options.shm_size.clone(),
        options.tmpfs.clone(),
    )?
    .with_cap_drop(options.cap_drop.clone())
}

/// `--env-file` を読む待ちの上限(REPAIR-5)。
const ENV_FILE_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// `--env-file` を作業スレッドで期限つきに読む(応答しない FUSE・ネットワーク FS で create が止まらない。REPAIR-5)。
///
/// 期限切れは `TIMEOUT`(作業スレッドは CLI の終了で消える。読み取りだけなので他の世代へ影響しない)。
fn read_env_files(paths: &[PathBuf]) -> Result<Vec<EnvFile>, TraitError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let paths = paths.to_vec();
    use fandhe_container_supervisor::supervisor_log::{BoundedFailure, run_bounded_waiting};
    match run_bounded_waiting(
        move || {
            paths
                .iter()
                .map(|p| EnvFile::read(p))
                .collect::<Result<Vec<_>, _>>()
        },
        ENV_FILE_READ_TIMEOUT,
    ) {
        Ok(result) => result,
        // 同時実行枠が期限まで空かなかった（何も読んでいない）。期限切れの TIMEOUT と区別する（#2834・ERR-2）。
        Err(BoundedFailure::Busy) => Err(TraitError::new(
            ErrorCode::ResourceExhausted,
            "env file workers are busy",
        )),
        Err(BoundedFailure::Unfinished) => Err(TraitError::new(
            ErrorCode::Timeout,
            "reading the env file did not finish within the deadline",
        )),
    }
}

/// `--label` を状態記録へ書く `Annotations` にする(件数・長さ・キー形式の上限は core の型が唯一の真実源)。
pub(super) fn labels_of(options: &CreateOptionArgs) -> Result<Annotations, TraitError> {
    let labels = options
        .labels
        .iter()
        .map(|s| Label::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let annotations = Labels::resolve(labels)?.annotations().clone();
    // 予約キー(作成世代)は CLI が足す。利用者の指定を受けると、文書が無いのに世代だけが記録され start が拒否される(#2713)。
    // イメージストア root の記録(`IMAGE_ROOT_ANNOTATION`)も同じ予約キー。偽装すると delete が別のストアを開く(#2499)。
    if annotations
        .get(fandhe_container_supervisor::container_options::store::GENERATION_ANNOTATION)
        .is_some()
        || annotations
            .get(super::image_refs::IMAGE_ROOT_ANNOTATION)
            .is_some()
    {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the label key is reserved",
        ));
    }
    Ok(annotations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::ErrorCode;

    fn args() -> CreateOptionArgs {
        CreateOptionArgs::default()
    }

    /// SUP-12・CLI-1: 指定なしは空の文書・空の label。
    #[test]
    fn sup12_create_options_empty() {
        assert!(document_of(&args()).expect("doc").is_empty());
        assert_eq!(labels_of(&args()).expect("labels"), Annotations::default());
    }

    /// SUP-12・CLI-1: `--env-file` は `-e` より優先順位が低く、統合後の `KEY=VALUE` が文書に入る。
    #[test]
    fn sup12_create_options_env_file_then_flags() {
        let dir = std::env::temp_dir().join(format!("fcopt-envf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("a.env");
        std::fs::write(&file, "# c\nA=file\nB=file\n").expect("write");
        let mut a = args();
        a.env_files.push(file);
        a.env.push("B=flag".into());
        a.env.push("C=3".into());
        a.ulimits.push("nofile=1024:2048".into());
        let doc = document_of(&a).expect("doc");
        assert_eq!(doc.env(), ["A=file", "B=flag", "C=3"]);
        assert_eq!(doc.ulimits(), ["nofile=1024:2048"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CLI-1・SEC-1(#2775): `--cap-drop` は文書の cap-drop になり、未知名は固定文言の `InvalidArgument` で拒否する。
    #[test]
    fn cli1_create_options_cap_drop() {
        let mut a = args();
        a.cap_drop = vec!["ALL".into(), "chown".into()];
        let doc = document_of(&a).expect("doc");
        assert_eq!(doc.cap_drop(), ["ALL", "chown"]);
        assert!(!doc.is_empty());
        a.cap_drop = vec!["CAP_BOGUS".into()];
        let e = document_of(&a).expect_err("unknown");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "a cap-drop record is invalid");
    }

    /// SUP-12・SEC-1: 不正な値・矛盾は固定文言の `InvalidArgument` で拒否する(値を出さない)。
    #[test]
    fn sup12_create_options_rejections() {
        let cases: Vec<(CreateOptionArgs, &str)> = vec![
            (
                CreateOptionArgs {
                    ulimits: vec!["bogus=1".into()],
                    ..args()
                },
                "unknown ulimit name",
            ),
            (
                CreateOptionArgs {
                    env: vec!["NOEQUALS".into()],
                    ..args()
                },
                "env entry must be KEY=VALUE",
            ),
            (
                CreateOptionArgs {
                    ipc: Some("host".into()),
                    shm_size: Some("64m".into()),
                    ..args()
                },
                "--shm-size cannot be combined with --ipc=host",
            ),
            (
                CreateOptionArgs {
                    env_files: vec!["/nonexistent/fcopt.env".into()],
                    ..args()
                },
                "cannot open env file",
            ),
        ];
        for (a, message) in cases {
            let e = document_of(&a).expect_err("rejected");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert_eq!(e.message(), message);
        }
        let bad_label = CreateOptionArgs {
            labels: vec!["=v".into()],
            ..args()
        };
        assert_eq!(
            labels_of(&bad_label).expect_err("label").code(),
            ErrorCode::InvalidArgument
        );
    }

    /// SUP-12・CLI-1: label は値なしを空文字で受け、同一キーは後勝ち。
    #[test]
    fn sup12_create_options_labels() {
        let a = CreateOptionArgs {
            labels: vec!["tier=web".into(), "flag".into(), "tier=db".into()],
            ..args()
        };
        let l = labels_of(&a).expect("labels");
        assert_eq!(l.get("tier"), Some("db"));
        assert_eq!(l.get("flag"), Some(""));
    }

    /// SUP-12・SEC-1(#2713): 作成世代の予約キーは利用者の label として受けない。
    #[test]
    fn sup12_create_options_rejects_reserved_generation_label() {
        let a = CreateOptionArgs {
            labels: vec!["io.fandhe.container.options-generation=x".into()],
            ..args()
        };
        let e = labels_of(&a).expect_err("reserved");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// OCI-7・SEC-1(#2499): イメージストア root の記録の予約キーも利用者の label として受けない。
    #[test]
    fn oci7_create_options_rejects_reserved_image_root_label() {
        let a = CreateOptionArgs {
            labels: vec!["io.fandhe.container.image-root=/x".into()],
            ..args()
        };
        let e = labels_of(&a).expect_err("reserved");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "the label key is reserved");
    }
}
