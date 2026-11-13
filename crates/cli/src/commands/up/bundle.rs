//! `up` が 1 サービスごとに用意する bundle（`config.json` と `env/`）の作成（STACK-8・OCI-4・SEC-1・TASK-155・#4638）。
//!
//! # 役割と呼び出し元
//! CLI の `create` は `--bundle` が必須で、`<bundle>/config.json` を core が検証する。TOML には `image` しか無いため、
//! launcher（`launcher::ProductionServiceLauncher`）が `<状態ルート>/.stack/bundles/<コンテナ ID>/` に
//! `config.json` を組んで置き、`create --unpack` にイメージの rootfs を `rootfs/` へ展開させる（前例は CRI の
//! `<状態ルート>/.cri/bundles`）。`env_files` の内容の複製（`env/<n>.env`）もここに置く。
//!
//! # 安全性
//! - ディレクトリ操作は oci の `ExtractRoot`（fd 起点・`RESOLVE_NO_SYMLINKS`）だけで行う。パスで開き直さず、symlink を辿らない。
//!   作るディレクトリは 0700、ファイルは 0600（排他作成）。
//! - `config.json` は `json_escape` で手組みし、**書く前に** core の `parse_config_bytes` で検証する（不合格は書かず
//!   `INTERNAL`。手組みの誤りを core の検証に頼って fail-closed にする）。namespaces は pid・mount・uts・ipc・user の既定集合
//!   だけで、network は書かない（ネットワークは `--network` で決まる）。
//! - 既存の扱い: `rootfs/` が残っていれば前回の残骸として `FAILED_PRECONDITION`（`create --unpack` は既存 rootfs を
//!   `ALREADY_EXISTS` で拒否する。回収手順は `docs/design/stack-up-wiring.md`）。`config.json` と `env/` は作り直す
//!   （`delete` は bundle ディレクトリを消さないため、前回の `down` の後は残っている）。

use std::io::Write as _;
use std::path::{Path, PathBuf};

use fandhe_container_core::oci_runtime::parse_config_bytes;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::ExtractRoot;

use super::prepare::{Prepared, env_file_name};
use crate::error::CliError;
use crate::json::json_escape;

/// bundle 置き場（状態ルート直下）の隠しディレクトリ名。
const STACK_DIR: &str = ".stack";
/// その下の bundle 群のディレクトリ名。
const BUNDLES_DIR: &str = "bundles";
/// `env_files` の複製を置くディレクトリ名。
pub(super) const ENV_DIR: &str = "env";
/// `config.json` の ociVersion（core が受ける版。他の cli 試験の bundle と同じ）。
const OCI_VERSION: &str = "1.2.0";

/// 用意した bundle のパス。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BundlePaths {
    /// `--bundle` に渡すディレクトリ。
    pub(super) bundle: PathBuf,
    /// `env/` の絶対パス（子の `--env-file` の基準）。
    pub(super) env_dir: PathBuf,
}

fn oci_failure(e: &fandhe_container_oci::error::OciError) -> CliError {
    let code = match e.code() {
        OciErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        OciErrorCode::NotFound => ErrorCode::NotFound,
        OciErrorCode::Unimplemented => ErrorCode::Unimplemented,
        OciErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        OciErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Internal,
    };
    CliError::new(code, "failed to prepare the service bundle")
}

/// `config.json` の本文を手組みする（キーの並びは固定）。
pub(super) fn config_json(p: &Prepared) -> String {
    let list = |items: &[String]| {
        items
            .iter()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        concat!(
            "{{\"ociVersion\":\"{ver}\",\"root\":{{\"path\":\"rootfs\",\"readonly\":false}},",
            "\"process\":{{\"terminal\":false,\"user\":{{\"uid\":{uid},\"gid\":{gid}}},",
            "\"args\":[{args}],\"env\":[{env}],\"cwd\":\"{cwd}\"}},",
            "\"linux\":{{\"namespaces\":[{{\"type\":\"pid\"}},{{\"type\":\"mount\"}},",
            "{{\"type\":\"uts\"}},{{\"type\":\"ipc\"}},{{\"type\":\"user\"}}]}}}}"
        ),
        ver = OCI_VERSION,
        uid = p.uid,
        gid = p.gid,
        args = list(&p.args),
        env = list(&p.image_env),
        cwd = json_escape(&p.cwd),
    )
}

pub(super) fn write_private(dir: &ExtractRoot, name: &str, body: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut f = dir
        .create_new_file(name, 0o600)
        .map_err(|e| oci_failure(&e))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| CliError::new(ErrorCode::Internal, "failed to prepare the service bundle"))?;
    f.write_all(body)
        .and_then(|()| f.sync_all())
        .map_err(|_| CliError::new(ErrorCode::Internal, "failed to write the service bundle"))
}

/// プロジェクト単位の `up` の排他ロック（事前検査から create / start の完了まで保持する。STACK-8・SEC-1・REPAIR-5・#4734）。
///
/// 同じプロジェクトを並行して `up` すると、両者が状態記録なしの事前検査を通り、同じ bundle の `config.json` と
/// `env/` を削除・再作成し合える。`<状態ルート>/.stack/up-<project>.lock` への非ブロッキングの `flock` で、
/// 後行を待たせずに `ABORTED` 相当の `FAILED_PRECONDITION` で拒否する（待ちが無いため期限は不要）。
/// drop（プロセス終了を含む）で解放される。
#[derive(Debug)]
pub(super) struct ProjectLock {
    file: Option<std::fs::File>,
}

/// 期限切れで置き去りにした作業スレッドがある（[`bounded_io`]）。真の間は [`ProjectLock`] を解放せず、プロセス終了まで
/// 排他を保つ（残った作業が次回の `up` の bundle と競合しない。STACK-8・REPAIR-5）。
static ABANDONED_WORK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Drop for ProjectLock {
    fn drop(&mut self) {
        if let Some(f) = self.file.take()
            && ABANDONED_WORK.load(std::sync::atomic::Ordering::SeqCst)
        {
            // fd を閉じない（flock を保つ）。CLI の終了で OS が解放する。
            std::mem::forget(f);
        }
    }
}

/// 状態ルート配下のブロックしうる I/O を期限つきの作業スレッドで行う（REPAIR-5）。
///
/// 期限切れは `TIMEOUT`、同時実行枠の満杯は `RESOURCE_EXHAUSTED`。期限切れの作業は止められないため、
/// [`ABANDONED_WORK`] を立ててプロジェクトのロックを手放さない。
pub(super) fn bounded_io<T: Send + 'static>(
    timeout: std::time::Duration,
    f: impl FnOnce() -> Result<T, CliError> + Send + 'static,
) -> Result<T, CliError> {
    use fandhe_container_supervisor::supervisor_log::{BoundedFailure, run_bounded_waiting};
    match run_bounded_waiting(f, timeout) {
        Ok(r) => r,
        Err(BoundedFailure::Busy) => Err(CliError::new(
            ErrorCode::ResourceExhausted,
            "bundle workers are busy",
        )),
        Err(BoundedFailure::Unfinished) => {
            ABANDONED_WORK.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(CliError::new(
                ErrorCode::Timeout,
                "a state root operation did not finish within the deadline",
            ))
        }
    }
}

impl ProjectLock {
    /// `state_root` 配下で `project` のロックを取る。他の `up` が保持していれば `FAILED_PRECONDITION`。
    pub(super) fn acquire(state_root: &Path, project: &str) -> Result<Self, CliError> {
        let fail = || CliError::new(ErrorCode::Internal, "failed to lock the project");
        let root = ExtractRoot::open_existing_dir(state_root).map_err(|e| oci_failure(&e))?;
        root.ensure_child_dir(STACK_DIR, 0o700)
            .map_err(|e| oci_failure(&e))?;
        // ロックファイルは `.stack` の fd 起点（openat2・NOFOLLOW）で開く。パスを組み直して開かないので、`.stack` が
        // symlink に差し替えられても状態ルートの外のファイルには flock しない（SEC-1・#4734）。
        let stack = root
            .open_child_dir(STACK_DIR)
            .map_err(|e| oci_failure(&e))?
            .ok_or_else(fail)?;
        let file = stack
            .open_or_create_file(&format!("up-{project}.lock"), 0o600)
            .map_err(|e| oci_failure(&e))?;
        if !file.metadata().map_err(|_| fail())?.is_file() {
            return Err(fail());
        }
        match file.try_lock() {
            Ok(()) => Ok(Self { file: Some(file) }),
            Err(std::fs::TryLockError::WouldBlock) => Err(CliError::new(
                ErrorCode::FailedPrecondition,
                "another up for the project is in progress",
            )),
            Err(_) => Err(fail()),
        }
    }
}

/// 合成した `config.json` を core の検証に通す（副作用なし）。`up` の事前検査が全サービスに対して呼び、
/// 後続サービスの入力不正を先行サービスの起動後に初めて見つける事態を防ぐ（STACK-8・SEC-1・#4734）。
/// 不合格は入力起因として `INVALID_ARGUMENT`（メッセージは固定文言で値を含めない）。
pub(super) fn validate_config(p: &Prepared) -> Result<(), CliError> {
    parse_config_bytes(config_json(p).as_bytes())
        .map(|_| ())
        .map_err(|_| {
            CliError::new(
                ErrorCode::InvalidArgument,
                "the service command, environment or working directory was rejected by config validation",
            )
        })
}

/// `<state_root>/.stack/bundles/<id>/rootfs` が残っているか（何も作らず、symlink を辿らず読むだけ）。
pub(super) fn rootfs_residue(state_root: &Path, id: &str) -> Result<bool, CliError> {
    let root = ExtractRoot::open_existing_dir(state_root).map_err(|e| oci_failure(&e))?;
    let mut dir = root;
    for name in [STACK_DIR, BUNDLES_DIR, id] {
        match dir.open_child_dir(name).map_err(|e| oci_failure(&e))? {
            Some(d) => dir = d,
            None => return Ok(false),
        }
    }
    dir.child_dir_exists("rootfs").map_err(|e| oci_failure(&e))
}

/// `state_root` 配下に `p` の bundle を用意する。`state_root` は開いた状態ストアの正規パス。
pub(super) fn write_bundle(state_root: &Path, p: &Prepared) -> Result<BundlePaths, CliError> {
    // 書く前に core の検証へ通す（手組みの誤りを fail-closed にする）。
    let config = config_json(p);
    parse_config_bytes(config.as_bytes()).map_err(|_| {
        CliError::new(
            ErrorCode::Internal,
            "generated service config was rejected by validation",
        )
    })?;

    let missing = || CliError::new(ErrorCode::Internal, "failed to prepare the service bundle");
    let root = ExtractRoot::open_existing_dir(state_root).map_err(|e| oci_failure(&e))?;
    root.ensure_child_dir(STACK_DIR, 0o700)
        .map_err(|e| oci_failure(&e))?;
    let stack = root
        .open_child_dir(STACK_DIR)
        .map_err(|e| oci_failure(&e))?
        .ok_or_else(missing)?;
    stack
        .ensure_child_dir(BUNDLES_DIR, 0o700)
        .map_err(|e| oci_failure(&e))?;
    let bundles = stack
        .open_child_dir(BUNDLES_DIR)
        .map_err(|e| oci_failure(&e))?
        .ok_or_else(missing)?;
    let id = p.id.as_str();
    bundles
        .ensure_child_dir(id, 0o700)
        .map_err(|e| oci_failure(&e))?;
    let dir = bundles
        .open_child_dir(id)
        .map_err(|e| oci_failure(&e))?
        .ok_or_else(missing)?;

    // 前回の rootfs が残っていれば残骸として拒否する（create --unpack は既存を ALREADY_EXISTS にする）。
    if dir
        .child_dir_exists("rootfs")
        .map_err(|e| oci_failure(&e))?
    {
        return Err(CliError::new(
            ErrorCode::FailedPrecondition,
            "a previous bundle rootfs remains; see docs/design/stack-up-wiring.md",
        ));
    }
    dir.unlink_child_file("config.json")
        .map_err(|e| oci_failure(&e))?;
    dir.remove_child_tree(ENV_DIR)
        .map_err(|e| oci_failure(&e))?;
    dir.ensure_child_dir(ENV_DIR, 0o700)
        .map_err(|e| oci_failure(&e))?;
    let env = dir
        .open_child_dir(ENV_DIR)
        .map_err(|e| oci_failure(&e))?
        .ok_or_else(missing)?;
    for (n, body) in p.env_files.iter().enumerate() {
        write_private(&env, &env_file_name(n), body)?;
    }
    write_private(&dir, "config.json", config.as_bytes())?;

    let bundle = state_root.join(STACK_DIR).join(BUNDLES_DIR).join(id);
    let env_dir = bundle.join(ENV_DIR);
    Ok(BundlePaths { bundle, env_dir })
}

#[cfg(test)]
mod tests {
    /// STACK-8・REPAIR-5: 応答しない I/O は期限で TIMEOUT になり、完了する I/O の結果はそのまま返る。
    #[test]
    fn stack8_repair5_bounded_io_times_out_and_passes_results() {
        let d = std::time::Duration::from_millis(200);
        assert_eq!(bounded_io(d, || Ok(7_u8)).expect("ok"), 7);
        let e = bounded_io(d, || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(())
        })
        .expect_err("timeout");
        assert_eq!(e.code(), ErrorCode::Timeout);
        let e = bounded_io(d, || -> Result<(), CliError> {
            Err(CliError::new(ErrorCode::NotFound, "x"))
        })
        .expect_err("inner");
        assert_eq!(e.code(), ErrorCode::NotFound);
    }

    /// STACK-8・SEC-1: 残った rootfs は何も作らずに検出し、bundle が無ければ false。
    #[test]
    fn stack8_sec1_rootfs_residue_is_detected_without_creating() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = std::env::temp_dir().join(format!("fc-residue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(!rootfs_residue(&base, "p.s").expect("none"));
        assert!(!base.join(".stack").exists());
        std::fs::create_dir_all(base.join(".stack/bundles/p.s/rootfs")).expect("rootfs");
        assert!(rootfs_residue(&base, "p.s").expect("some"));
        assert!(!rootfs_residue(&base, "p.t").expect("other"));
        let _ = std::fs::remove_dir_all(&base);
    }

    use super::*;
    use fandhe_container_stack::cli::up::{ProjectName, ServiceContainerId};
    use fandhe_container_stack::schema::Service;

    fn prepared(args: &[&str], env: &[&str], cwd: &str, env_files: Vec<Vec<u8>>) -> Prepared {
        let id =
            ServiceContainerId::derive(&ProjectName::new("shop").expect("p"), "web").expect("id");
        Prepared {
            id,
            spec: Service::default(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: cwd.to_owned(),
            image_env: env.iter().map(|s| (*s).to_owned()).collect(),
            uid: 1000,
            gid: 2000,
            env_files,
        }
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-up-bundle-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// OCI-4・SEC-1・#4638: 手組みの config.json は core の検証を通り、引数・env・cwd・user が具体値で入る。
    /// JSON の特殊文字（引用符・バックスラッシュ・改行）は壊さずにエスケープされる。
    #[test]
    fn oci4_4638_config_json_is_valid_for_core_and_escapes() {
        let p = prepared(
            &["/bin/sh", "-c", "echo \"a\\b\"\n"],
            &["PATH=/usr/bin", "K=v w"],
            "/srv",
            vec![],
        );
        let json = config_json(&p);
        let cfg = parse_config_bytes(json.as_bytes()).expect("core accepts");
        let _ = cfg;
        assert!(
            json.contains(r#""args":["/bin/sh","-c","echo \"a\\b\"\n"]"#),
            "{json}"
        );
        assert!(
            json.contains(r#""env":["PATH=/usr/bin","K=v w"]"#),
            "{json}"
        );
        assert!(json.contains(r#""user":{"uid":1000,"gid":2000}"#), "{json}");
        assert!(json.contains(r#""cwd":"/srv""#), "{json}");
        assert!(!json.contains("\"network\""), "{json}");
    }

    /// SEC-1・#4638: core が受けない内容（空の args）は書く前に拒否される。
    #[test]
    fn sec1_4638_write_bundle_rejects_a_config_core_would_reject() {
        let s = Scratch::new("reject");
        let p = prepared(&[], &[], "/", vec![]);
        let e = write_bundle(&s.0, &p).expect_err("rejected");
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(!s.0.join(".stack").exists());
    }

    /// STACK-8・SEC-1・#4734: 事前検査用の検証は core が拒否する内容を `INVALID_ARGUMENT` で返し、正常な内容は通す。
    #[test]
    fn stack8_4734_validate_config_is_invalid_argument_not_internal() {
        let e = validate_config(&prepared(&[], &[], "/", vec![])).expect_err("empty args");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 上限（CONFIG_MAX_STRING_BYTES）を超える command 要素。
        let huge = "a".repeat(1 << 20);
        let e = validate_config(&prepared(&[huge.as_str()], &[], "/", vec![])).expect_err("huge");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        validate_config(&prepared(&["/bin/true"], &[], "/", vec![])).expect("valid");
    }

    /// STACK-8・SEC-1・#4638: bundle は 0700 のディレクトリ、config.json と env は 0600 で作られ、
    /// 2 回目は config.json と env を作り直し、rootfs が残っていれば `FAILED_PRECONDITION`。
    #[test]
    fn stack8_4638_write_bundle_layout_modes_and_rewrite() {
        use std::os::unix::fs::PermissionsExt as _;
        let s = Scratch::new("layout");
        let p = prepared(
            &["/bin/true"],
            &[],
            "/",
            vec![b"A=1\n".to_vec(), b"B=2\n".to_vec()],
        );
        let paths = write_bundle(&s.0, &p).expect("bundle");
        assert_eq!(paths.bundle, s.0.join(".stack/bundles/shop.web"));
        assert_eq!(paths.env_dir, paths.bundle.join("env"));
        let mode = |q: &Path| std::fs::metadata(q).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&paths.bundle), 0o700);
        assert_eq!(mode(&paths.env_dir), 0o700);
        assert_eq!(mode(&paths.bundle.join("config.json")), 0o600);
        assert_eq!(
            std::fs::read(paths.env_dir.join("1.env")).expect("env1"),
            b"B=2\n"
        );
        assert_eq!(mode(&paths.env_dir.join("0.env")), 0o600);

        // 作り直し: env_files が減っても古い複製は残らない。
        let p2 = prepared(&["/bin/true"], &[], "/", vec![b"C=3\n".to_vec()]);
        write_bundle(&s.0, &p2).expect("rewrite");
        assert_eq!(
            std::fs::read(paths.env_dir.join("0.env")).expect("env0"),
            b"C=3\n"
        );
        assert!(!paths.env_dir.join("1.env").exists());

        // 前回の rootfs が残っていれば拒否。
        std::fs::create_dir(paths.bundle.join("rootfs")).expect("rootfs");
        let e = write_bundle(&s.0, &p2).expect_err("residue");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    }

    /// SEC-1・#4638: `.stack` が symlink に差し替えられていたら辿らずに拒否する。
    #[test]
    fn sec1_4638_write_bundle_does_not_follow_a_symlinked_stack_dir() {
        let s = Scratch::new("symlink");
        let outside = Scratch::new("outside");
        std::os::unix::fs::symlink(&outside.0, s.0.join(".stack")).expect("symlink");
        let p = prepared(&["/bin/true"], &[], "/", vec![]);
        assert!(write_bundle(&s.0, &p).is_err());
        assert!(!outside.0.join("bundles").exists());
    }

    /// SEC-1・STACK-8・#4734: `.stack` が symlink なら、ロックは辿らず拒否し、外側にロックファイルを作らない。
    /// 通常は 2 回目の取得が `FAILED_PRECONDITION`。
    #[test]
    fn sec1_4734_project_lock_is_fd_anchored_and_exclusive() {
        let s = Scratch::new("lock");
        let first = ProjectLock::acquire(&s.0, "shop").expect("lock");
        let e = ProjectLock::acquire(&s.0, "shop").expect_err("second");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        drop(first);
        ProjectLock::acquire(&s.0, "shop").expect("released");

        let s2 = Scratch::new("lock-link");
        let outside = Scratch::new("lock-outside");
        std::os::unix::fs::symlink(&outside.0, s2.0.join(".stack")).expect("symlink");
        assert!(ProjectLock::acquire(&s2.0, "shop").is_err());
        assert!(!outside.0.join("up-shop.lock").exists());
    }
}
