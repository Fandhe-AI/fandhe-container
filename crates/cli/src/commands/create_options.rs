//! `create` の起動オプション(`--ulimit`・`--env`・`--env-file`・`--label`・`--ipc`・`--shm-size`・`--tmpfs`・`--cap-drop`・`--read-only`)の
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
//!   `--read-only`(#2828・CLI-1・SUP-12)は文書の `read-only` になる。実効値は起動時に core が config の `root.readonly` と
//!   OR で決める(狭める方向のみ)。指定が無ければ外部 bundle の値に従い、`readonly:true` の bundle を書き込み可能に
//!   戻す指定は無い(`--read-only=false` は使い方エラー)。CLI は外部 bundle の `config.json` を書き換えない。
//! - [`labels_of`]: `--label` を core の `Annotations` にし、`CreateRequest::with_annotations` で状態記録へ直接書く
//!   (supervisor を通らない)。
//!
//! エラーは固定の英語文言の `InvalidArgument` で、値・パスを含めない。secrets / configs のフラグは未提供(後続。REPAIR-3)。

use std::path::PathBuf;
use std::time::Duration;

use fandhe_container_core::traits::Annotations;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::pasta::record::PastaRecord;
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::env::{EnvFile, EnvSet, EnvVar};
use fandhe_container_supervisor::container_options::{Label, Labels};

use super::args::CreateOptionArgs;

/// 起動オプション文書を作る(空なら `is_empty()`。その場合 CLI は文書を書かない)。
///
/// `pasta` は作成時に検証した pasta の記録(NET-9・#3199)。あるときだけ `--network`・`--add-host`・`--dns` も文書へ
/// 載せる(`pasta` は `network` がユーザー定義名のときだけ置けるため)。`pasta` が無いときの挙動は従来どおり。
pub(super) fn document_of(
    options: &CreateOptionArgs,
    pasta: Option<&PastaRecord>,
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
    .and_then(|doc| doc.with_read_only(options.read_only))
    .and_then(|doc| match pasta {
        // Linux は常に `network` を書く。`--network` の省略は `none`(SEC-1 の「既定で閉じる」。D4・#1873)。
        // これが既定を `none` に変える唯一の箇所。非 Linux は `create_network` が指定を `UNIMPLEMENTED` で止める。
        None if cfg!(target_os = "linux") => doc.with_network(
            Some(
                options
                    .network
                    .network
                    .clone()
                    .unwrap_or_else(|| "none".to_owned()),
            ),
            options.network.add_hosts.clone(),
            options.network.dns.clone(),
        ),
        None => Ok(doc),
        Some(record) => doc
            .with_network(
                options.network.network.clone(),
                options.network.add_hosts.clone(),
                options.network.dns.clone(),
            )?
            .with_pasta(Some(record.to_body())),
    })
    // `network` を書く pasta の段の後ろに `publish` を並べる(`with_publish` はユーザー定義名の `network` を要する)。
    // 継ぎ目(REPAIR-3・NET-9・#3200): `publish` はユーザー定義名の `network` と組で書く。ユーザー定義名は
    // `create_network::reject_unwired_network` が `UNIMPLEMENTED` で止めるため、空でない `publish` はここへ届かない
    // (届いても `none` / `host` では文書にできず `InvalidArgument`)。
    .and_then(|doc| doc.with_publish(options.network.publish.clone()))
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

    /// SUP-12・CLI-1: 指定なしの label は空。文書は非 Linux では空、Linux では既定の `network none` だけを持つ。
    #[test]
    fn sup12_create_options_empty() {
        let doc = document_of(&args(), None).expect("doc");
        if cfg!(target_os = "linux") {
            assert_eq!(doc.network(), Some("none"));
            assert!(doc.add_hosts().is_empty());
            assert!(doc.dns().is_empty());
        } else {
            assert!(doc.is_empty());
        }
        assert_eq!(labels_of(&args()).expect("labels"), Annotations::default());
    }

    /// NET-6・NET-12・SEC-1(#1873): Linux は `--network` 省略で `none`、指定した値と add-host / dns は入力順で載る。
    #[cfg(target_os = "linux")]
    #[test]
    fn net6_document_of_writes_network_modes() {
        let mut a = args();
        a.network.network = Some("host".into());
        a.network.add_hosts = vec!["b:192.0.2.2".into(), "a:192.0.2.1".into()];
        a.network.dns = vec!["192.0.2.53".into()];
        let doc = document_of(&a, None).expect("doc");
        assert_eq!(doc.network(), Some("host"));
        assert_eq!(doc.add_hosts(), ["b:192.0.2.2", "a:192.0.2.1"]);
        assert_eq!(doc.dns(), ["192.0.2.53"]);
        let mut a = args();
        a.network.add_hosts = vec!["a:192.0.2.1".into()];
        assert_eq!(document_of(&a, None).expect("doc").network(), Some("none"));
    }

    /// NET-9(#3200): `network` の無い `publish` は文書にできない(継ぎ目の固定)。
    #[test]
    fn net9_document_of_rejects_publish_without_network() {
        let mut a = args();
        a.network.publish.push("8080:80".into());
        let e = document_of(&a, None).expect_err("publish alone");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "publish records require a user-defined network"
        );
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
        let doc = document_of(&a, None).expect("doc");
        assert_eq!(doc.env(), ["A=file", "B=flag", "C=3"]);
        assert_eq!(doc.ulimits(), ["nofile=1024:2048"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CLI-1・SUP-12(#2828): `--read-only` だけでも文書は空にならず(黙って効かなくなるのを防ぐ)、`read_only()` が true になる。
    /// 指定が無ければ空のまま。
    #[test]
    fn cli1_sup12_create_options_read_only() {
        let mut a = CreateOptionArgs::default();
        assert!(!document_of(&a, None).expect("doc").read_only());
        a.read_only = true;
        let doc = document_of(&a, None).expect("doc");
        assert!(!doc.is_empty());
        assert!(doc.read_only());
    }

    /// CLI-1・SEC-1(#2775): `--cap-drop` は文書の cap-drop になり、未知名は固定文言の `InvalidArgument` で拒否する。
    #[test]
    fn cli1_create_options_cap_drop() {
        let mut a = args();
        a.cap_drop = vec!["ALL".into(), "chown".into()];
        let doc = document_of(&a, None).expect("doc");
        assert_eq!(doc.cap_drop(), ["ALL", "chown"]);
        assert!(!doc.is_empty());
        a.cap_drop = vec!["CAP_BOGUS".into()];
        let e = document_of(&a, None).expect_err("unknown");
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
            let e = document_of(&a, None).expect_err("rejected");
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

    /// NET-9・SUP-12(#3199): pasta の記録があるときだけ network 系も文書へ載り、本文は記録のとおりになる。
    #[test]
    fn net9_sup12_document_of_carries_pasta_record() {
        const BODY: &str =
            "20260120 2049 131074 1234567 1760000000 123456789 -5 0 0 755\n/usr/bin/pasta";
        let record = PastaRecord::parse_body(BODY).expect("record");
        let a = CreateOptionArgs {
            network: crate::commands::args::CreateNetworkArgs {
                network: Some("web".into()),
                add_hosts: vec![],
                dns: vec![],
                publish: vec![],
            },
            ..args()
        };
        let doc = document_of(&a, Some(&record)).expect("doc");
        assert_eq!(doc.pasta(), Some(BODY));
        assert_eq!(doc.network(), Some("web"));
        // pasta の記録が無ければ pasta は載らない。network は Linux では常に書く(非 Linux は載せない。#1873)。
        let doc = document_of(&a, None).expect("doc");
        assert!(doc.pasta().is_none());
        assert_eq!(
            doc.network(),
            if cfg!(target_os = "linux") {
                Some("web")
            } else {
                None
            }
        );
        // ユーザー定義名でなければ pasta は置けない(fail-closed)。
        let none = CreateOptionArgs {
            network: crate::commands::args::CreateNetworkArgs {
                network: Some("none".into()),
                ..Default::default()
            },
            ..args()
        };
        let e = document_of(&none, Some(&record)).expect_err("none");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }
}
