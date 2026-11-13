//! `up` の事前検査: 1 サービスぶんの入力を、副作用の前にすべて検証して束ねる（STACK-8・SEC-1・OCI-1・TASK-155・#4638）。
//!
//! # 役割と呼び出し元
//! `run::run_up` が依存閉包の全サービスについて [`Preparer::prepare`] を呼ぶ。1 件でも拒否されたら起動ゼロで失敗する
//! （ネットワークの作成も bundle の作成も、この段を全部通ってから始まる）。結果の [`Prepared`] は launcher が bundle の
//! `config.json` と子プロセスの argv を作るのに使う。
//!
//! # 検査の中身
//! 1. コンテナ ID の導出（`ServiceContainerId::derive`）と、`create_argv` の空実行（拒否規則だけを走らせる）。
//!    続けて `env_files` の fd 起点の読み取り（イメージ・状態ストアに触れる前に拒否できるよう先に行う）。
//! 2. イメージ参照の解決（digest かタグ。タグは在庫の対応表から引く）。以後は解決済みの manifest digest を子の
//!    `create --image` に渡す（タグが検査後に付け替えられても、検査した内容と違うイメージにならない）。
//! 3. イメージ config の `config` 節（Entrypoint・Cmd・Env・WorkingDir・User）を信頼条件つきで読み、サービスの
//!    `command` / `entrypoint` / `working_dir` と合成する（`process_args` / `process_cwd`）。`User` は数値だけ受ける
//!    （名前の解決は未実装で `UNIMPLEMENTED`。後続 issue）。
//! 4. `env_files` を **project_dir を起点に fd 起点で** 読む（`RESOLVE_IN_ROOT | NO_SYMLINKS`）。途中の要素でも最後の要素でも
//!    symlink があれば拒否し、通常ファイル以外・上限超えも拒否する。読んだ内容は bundle の `env/<n>.env` へ複製して子に渡す
//!    ため、検査の後に元のファイルを差し替えられても子へは届かない（TOCTOU を閉じる）。`openat2` が使えないカーネルは
//!    字句の検査へ縮退せず `FAILED_PRECONDITION`（fail-closed）。
//!
//! エラーの `message` は固定文言とフィールド名だけで、値・パス・env の内容を含めない。

use std::path::Path;

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::ImageStore;
use fandhe_container_oci::layer::read_rootfs_file;
use fandhe_container_oci::reference::Digest;
use fandhe_container_stack::cli::up::{
    CreateArgsError, CreateArgvContext, ProjectName, ServiceContainerId, create_argv, process_args,
    process_cwd,
};
use fandhe_container_stack::schema::Service;
use fandhe_container_supervisor::container_options::env::ENV_FILE_MAX_BYTES;

use super::super::image::{Stage, trait_failure};
use super::super::image_refs::{classify_create_image, resolve_create_image};
use crate::error::CliError;

/// 検査済みの 1 サービス。launcher が bundle と子プロセスの argv を作る入力。
#[derive(Debug, Clone)]
pub(super) struct Prepared {
    /// コンテナ ID（`<project>.<service>`）。
    pub(super) id: ServiceContainerId,
    /// 子の `create` に渡す定義。`image` は解決済みの manifest digest、`env_files` は bundle の `env/` 配下の相対名に
    /// 置き換えてある。
    pub(super) spec: Service,
    /// `process.args`。
    pub(super) args: Vec<String>,
    /// `process.cwd`。
    pub(super) cwd: String,
    /// イメージの Env（`KEY=VALUE`）。サービスの `env` は `create` のフラグで重ねる。
    pub(super) image_env: Vec<String>,
    /// `process.user.uid`。
    pub(super) uid: u32,
    /// `process.user.gid`。
    pub(super) gid: u32,
    /// `env_files` の内容（`spec.env_files` と同じ並び。`env/<n>.env` に書く）。
    pub(super) env_files: Vec<Vec<u8>>,
}

/// 事前検査の入力（プロジェクト単位で共通）。
pub(super) struct Preparer<'a> {
    pub(super) project: &'a ProjectName,
    /// TOML のあるディレクトリ（`env_files` の起点）。
    pub(super) project_dir: &'a Path,
    pub(super) image_root: &'a Path,
    pub(super) store: &'a ImageStore,
}

fn invalid(msg: String) -> CliError {
    CliError::new(ErrorCode::InvalidArgument, msg)
}

fn from_args(e: CreateArgsError) -> CliError {
    let code = match e {
        CreateArgsError::Unsupported { .. } => ErrorCode::Unimplemented,
        _ => ErrorCode::InvalidArgument,
    };
    CliError::new(code, format!("{} ({})", e.message(), e.field()))
}

fn from_trait(e: &TraitError) -> CliError {
    CliError::new(e.code(), e.message())
}

impl Preparer<'_> {
    /// `name` / `spec` を検査して束ねる。副作用は無い（読み取りだけ）。
    pub(super) fn prepare(&self, name: &str, spec: &Service) -> Result<Prepared, CliError> {
        let id = ServiceContainerId::derive(self.project, name)
            .map_err(|e| invalid(e.message().to_owned()))?;

        // 1. 拒否規則だけを走らせる空実行（bundle は仮の絶対パス。argv は捨てる）。
        let dummy_bundle = self.image_root.join(".stack-dryrun");
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: self.project_dir,
            bundle: &dummy_bundle,
            image_root: self.image_root,
            unpack: true,
        };
        create_argv(spec, None, &ctx).map_err(from_args)?;

        // 1b. env_files を fd 起点で読む。
        let mut env_files = Vec::with_capacity(spec.env_files.len());
        for rel in &spec.env_files {
            env_files.push(read_env_file(self.project_dir, rel)?);
        }

        // 2. イメージ参照の解決（digest に固定）。
        let image_ref = spec
            .image
            .as_deref()
            .ok_or_else(|| from_args(CreateArgsError::Unsupported { field: "image" }))?;
        let classified = classify_create_image(image_ref).map_err(|e| from_trait(&e))?;
        let manifest = resolve_create_image(self.store, classified).map_err(|e| from_trait(&e))?;
        let digest = Digest::parse(manifest.as_str())
            .map_err(|_| CliError::new(ErrorCode::Internal, "resolved image digest is invalid"))?;

        // 3. イメージ config の config 節との合成。
        let cfg = self.store.image_process_config(&digest).map_err(|e| {
            if e.code() == OciErrorCode::NotFound {
                CliError::new(
                    ErrorCode::NotFound,
                    "image is not in the image store; pull it first (image)",
                )
            } else {
                from_trait(&trait_failure(&e, Stage::Read))
            }
        })?;
        let args = process_args(spec, cfg.entrypoint(), cfg.cmd()).map_err(from_args)?;
        let cwd = process_cwd(spec, cfg.working_dir()).map_err(from_args)?;
        let (uid, gid) = parse_numeric_user(cfg.user())?;

        let mut rewritten = spec.clone();
        rewritten.image = Some(manifest.as_str().to_owned());
        rewritten.env_files = (0..env_files.len()).map(env_file_name).collect();
        Ok(Prepared {
            id,
            spec: rewritten,
            args,
            cwd,
            image_env: cfg.env().to_vec(),
            uid,
            gid,
            env_files,
        })
    }
}

/// `rel`（`project_dir` からの相対。字句の検査は `create_argv` が済ませている）を fd 起点で読む。
fn read_env_file(project_dir: &Path, rel: &str) -> Result<Vec<u8>, CliError> {
    let parts: Vec<&str> = rel
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let bad = || {
        invalid(
            "env_files entry must be a plain file under the project directory (env_files)"
                .to_owned(),
        )
    };
    if parts.is_empty() {
        return Err(bad());
    }
    match read_rootfs_file(project_dir, &parts, ENV_FILE_MAX_BYTES as u64) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(CliError::new(
            ErrorCode::NotFound,
            "env_files entry was not found (env_files)",
        )),
        Err(e) => Err(match e.code() {
            OciErrorCode::Unimplemented => CliError::new(
                ErrorCode::FailedPrecondition,
                "openat2 is required to read env_files safely (env_files)",
            ),
            OciErrorCode::ResourceExhausted => CliError::new(
                ErrorCode::ResourceExhausted,
                "env_files entry exceeds the size limit (env_files)",
            ),
            _ => bad(),
        }),
    }
}

/// bundle の `env/` 配下の `n` 番目の複製の名前。
pub(super) fn env_file_name(n: usize) -> String {
    format!("{n}.env")
}

/// イメージ config の `User` を数値の `uid[:gid]` として解く。空は 0:0、`uid` のみは gid 0。
///
/// 名前（`/etc/passwd` の解決）は未実装のため `UNIMPLEMENTED`（CRI の fd 起点の passwd 読み取りと同等の実装は後続 issue）。
fn parse_numeric_user(user: &str) -> Result<(u32, u32), CliError> {
    let unsupported = || {
        CliError::new(
            ErrorCode::Unimplemented,
            "a non-numeric image user is not supported yet (image)",
        )
    };
    if user.is_empty() {
        return Ok((0, 0));
    }
    let num = |s: &str| -> Option<u32> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    match user.split_once(':') {
        None => num(user).map(|u| (u, 0)).ok_or_else(unsupported),
        Some((u, g)) => match (num(u), num(g)) {
            (Some(u), Some(g)) => Ok((u, g)),
            _ => Err(unsupported()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OCI-1・SEC-5・#4638: 数値の User だけを受け、名前・空要素・符号・溢れは `UNIMPLEMENTED`。
    #[test]
    fn oci1_4638_numeric_image_user_table() {
        assert_eq!(parse_numeric_user("").expect("empty"), (0, 0));
        assert_eq!(parse_numeric_user("1000").expect("uid"), (1000, 0));
        assert_eq!(parse_numeric_user("1000:2000").expect("pair"), (1000, 2000));
        for bad in [
            "nobody",
            "nobody:nogroup",
            "1000:",
            ":1",
            "+1",
            "-1",
            "1:x",
            "99999999999",
        ] {
            let e = parse_numeric_user(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::Unimplemented, "{bad}");
        }
    }

    #[test]
    fn stack8_4638_env_file_copy_names_are_stable() {
        assert_eq!(env_file_name(0), "0.env");
        assert_eq!(env_file_name(12), "12.env");
    }
}
