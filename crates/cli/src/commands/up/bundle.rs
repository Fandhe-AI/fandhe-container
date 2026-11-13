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

fn write_private(dir: &ExtractRoot, name: &str, body: &[u8]) -> Result<(), CliError> {
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
}
