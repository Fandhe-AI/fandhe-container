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

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::env::{
    ENV_FILE_MAX_BYTES, ENV_MAX_TOTAL_BYTES, EnvFile, EnvSet, EnvVar,
};
use fandhe_container_supervisor::container_options::{Label, Labels};
use fandhe_container_supervisor::supervisor_log::{BoundedFailure, run_bounded_waiting};

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

/// 1 サービスが持てる `env_files` の件数の上限（無制限確保の防止。SEC-1・#4734）。
const ENV_FILES_PER_SERVICE_MAX: usize = 16;
/// プロジェクト全体で `env_files` の本文として保持してよい合計バイト数（副作用より前の確保の上限。#4734）。
const ENV_FILES_PROJECT_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// プロジェクト全体の `env_files` の読み取りに許す時間（応答しない FUSE・ネットワーク FS で止まらない。REPAIR-5・#4734）。
const ENV_FILES_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// `env_files` の読み取りの残り容量と期限（プロジェクト全体で 1 つ）。
pub(super) struct EnvReadBudget {
    remaining: Cell<u64>,
    deadline: Instant,
}

impl EnvReadBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining: Cell::new(ENV_FILES_PROJECT_MAX_BYTES),
            deadline: Instant::now() + ENV_FILES_READ_TIMEOUT,
        }
    }
}

/// 事前検査の入力（プロジェクト単位で共通）。
pub(super) struct Preparer<'a> {
    pub(super) project: &'a ProjectName,
    /// TOML のあるディレクトリ（`env_files` の起点）。
    pub(super) project_dir: &'a Path,
    pub(super) image_root: &'a Path,
    pub(super) store: &'a ImageStore,
    /// `env_files` の合計容量と読み取り期限（プロジェクト全体で共有）。
    pub(super) env_budget: EnvReadBudget,
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

        // 1b. env_files を fd 起点・件数と合計バイト数の上限つき・期限つきの作業スレッドで読む。
        let env_files = read_env_files(self.project_dir, &self.env_budget, &spec.env_files)?;

        // 1c. 起動オプションの意味検証（create が後で拒否する内容を、副作用の前に同じ検証関数で拒否する）。
        validate_options(spec, &env_files)?;

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

/// `rels` を順に読む。件数・サービス単位の合計（`ENV_MAX_TOTAL_BYTES`）・プロジェクト全体の合計の上限を、
/// 追加の確保より前に `read_rootfs_file` の `max_bytes` へ反映する。読み取りは期限つきの作業スレッドで行う。
fn read_env_files(
    project_dir: &Path,
    budget: &EnvReadBudget,
    rels: &[String],
) -> Result<Vec<Vec<u8>>, CliError> {
    if rels.is_empty() {
        return Ok(Vec::new());
    }
    if rels.len() > ENV_FILES_PER_SERVICE_MAX {
        return Err(CliError::new(
            ErrorCode::ResourceExhausted,
            "too many env_files entries (env_files)",
        ));
    }
    let cap = (ENV_MAX_TOTAL_BYTES as u64).min(budget.remaining.get());
    let timeout = budget.deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(env_timeout());
    }
    let dir: PathBuf = project_dir.to_path_buf();
    let rels: Vec<String> = rels.to_vec();
    let worker = move || -> Result<Vec<Vec<u8>>, CliError> {
        let mut left = cap;
        let mut out = Vec::with_capacity(rels.len());
        for rel in &rels {
            let bytes = read_env_file(&dir, rel, left)?;
            left = left.saturating_sub(bytes.len() as u64);
            out.push(bytes);
        }
        Ok(out)
    };
    let files = match run_bounded_waiting(worker, timeout) {
        Ok(r) => r?,
        Err(BoundedFailure::Busy) => {
            return Err(CliError::new(
                ErrorCode::ResourceExhausted,
                "env_files workers are busy (env_files)",
            ));
        }
        Err(BoundedFailure::Unfinished) => return Err(env_timeout()),
    };
    let used: u64 = files.iter().map(|f| f.len() as u64).sum();
    budget
        .remaining
        .set(budget.remaining.get().saturating_sub(used));
    Ok(files)
}

fn env_timeout() -> CliError {
    CliError::new(
        ErrorCode::Timeout,
        "reading env_files did not finish within the deadline (env_files)",
    )
}

/// `create` が検証する起動オプション（env・env_files の本文・ulimits・shm_size・tmpfs・cap_drop・labels）を、
/// 副作用の前に同じ検証関数（supervisor の `EnvSet` / `ContainerOptionsDocument`・`Labels`）で検証する。
fn validate_options(spec: &Service, env_files: &[Vec<u8>]) -> Result<(), CliError> {
    let opt = |e: TraitError| CliError::new(e.code(), e.message());
    let vars = spec
        .env
        .iter()
        .map(|(k, v)| EnvVar::parse(&format!("{k}={v}")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(opt)?;
    let files = env_files
        .iter()
        .map(|b| {
            let text = std::str::from_utf8(b).map_err(|_| {
                TraitError::new(ErrorCode::InvalidArgument, "env file must be UTF-8")
            })?;
            EnvFile::parse(text)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(opt)?;
    let env = EnvSet::resolve(&[], &files, &vars)
        .map_err(opt)?
        .to_env_strings();
    let ulimits = spec
        .ulimits
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect();
    ContainerOptionsDocument::new(
        ulimits,
        env,
        None,
        spec.shm_size.clone(),
        spec.tmpfs.clone(),
    )
    .and_then(|d| d.with_cap_drop(spec.cap_drop.clone()))
    .map_err(opt)?;
    let labels = spec
        .labels
        .iter()
        .map(|(k, v)| Label::parse(&format!("{k}={v}")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(opt)?;
    Labels::resolve(labels).map_err(opt)?;
    Ok(())
}

/// `rel`（`project_dir` からの相対。字句の検査は `create_argv` が済ませている）を fd 起点で最大 `max_bytes` まで読む。
fn read_env_file(project_dir: &Path, rel: &str, max_bytes: u64) -> Result<Vec<u8>, CliError> {
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
    match read_rootfs_file(
        project_dir,
        &parts,
        max_bytes.min(ENV_FILE_MAX_BYTES as u64),
    ) {
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

    fn service() -> Service {
        Service {
            image: Some("x".to_owned()),
            ..Service::default()
        }
    }

    /// STACK-8・SEC-1・#4734: env_files の本文・env のキー・ulimits・shm_size を副作用の前に意味検証する。
    #[test]
    fn stack8_4734_validate_options_rejects_semantic_errors() {
        let ok = service();
        validate_options(&ok, &[]).expect("empty");
        // env ファイルの本文の不正行（値なしの KEY）。
        let e = validate_options(&ok, &[b"NOEQUALS\n".to_vec()]).expect_err("bad line");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 非 UTF-8。
        let e = validate_options(&ok, &[vec![0xff, 0xfe]]).expect_err("utf8");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 不正な shm_size・ulimits。
        let bad_shm = Service {
            shm_size: Some("abc".to_owned()),
            ..service()
        };
        assert_eq!(
            validate_options(&bad_shm, &[]).expect_err("shm").code(),
            ErrorCode::InvalidArgument
        );
        let mut bad_ulimit = service();
        bad_ulimit
            .ulimits
            .insert("nofile".to_owned(), "zz".to_owned());
        assert_eq!(
            validate_options(&bad_ulimit, &[])
                .expect_err("ulimit")
                .code(),
            ErrorCode::InvalidArgument
        );
        // 正常な本文は通る。
        validate_options(&ok, &[b"# c\nA=b\n".to_vec()]).expect("valid file");
    }

    /// SEC-1・REPAIR-5・#4734: 件数の上限超過と、合計容量の枯渇・期限切れは読む前に拒否する。
    #[test]
    fn sec1_4734_env_read_limits_reject_before_reading() {
        let dir = std::env::temp_dir().join(format!("fc-prep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("a.env"), "A=1\n").expect("write");
        let store_dir = dir.join("store");
        std::fs::create_dir_all(&store_dir).expect("store dir");
        let rels: Vec<String> = (0..=ENV_FILES_PER_SERVICE_MAX)
            .map(|_| "a.env".to_owned())
            .collect();
        let check = |budget: EnvReadBudget, rels: &[String]| {
            // `Preparer` は ImageStore を要するが、`read_env_files` は触れない。予算だけを直接照合する。
            read_env_files(&dir, &budget, rels)
        };
        let e = check(EnvReadBudget::new(), &rels).expect_err("count");
        assert_eq!(e.code(), ErrorCode::ResourceExhausted);
        let one = vec!["a.env".to_owned()];
        assert_eq!(
            check(EnvReadBudget::new(), &one).expect("one"),
            vec![b"A=1\n".to_vec()]
        );
        let drained = EnvReadBudget::new();
        drained.remaining.set(2);
        let e = check(drained, &one).expect_err("capacity");
        assert_eq!(e.code(), ErrorCode::ResourceExhausted);
        let expired = EnvReadBudget::new();
        let expired = EnvReadBudget {
            deadline: Instant::now() - Duration::from_secs(1),
            ..expired
        };
        let e = check(expired, &one).expect_err("deadline");
        assert_eq!(e.code(), ErrorCode::Timeout);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stack8_4638_env_file_copy_names_are_stable() {
        assert_eq!(env_file_name(0), "0.env");
        assert_eq!(env_file_name(12), "12.env");
    }
}
