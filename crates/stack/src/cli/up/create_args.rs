//! `Service` から CLI の `create` / `start` の argv を組み立てる（STACK-8・SUP-12・SEC-1・TASK-155・#3639）。
//!
//! 呼び出し元は cli crate の本番 `ServiceLauncher`（子プロセスで CLI の `create` → `start` を呼ぶ。#4638）。
//! 返すのはサブコマンド以降だけで、グローバルオプション（`--root`・`--pasta-path` 等）は結線側が前置する。
//! 各値は別要素の `OsString` にし、連結もシェル文字列化もしない。ID の前に `--` を置き、
//! 値をオプションと取り違えない。
//!
//! `Service` は網羅的に分解する（`..` を使わない）。フィールドを足すとここがコンパイルエラーになり、
//! 写すか拒否するかの判断を強制する。CLI の `create` に写す先が無いフィールドは黙って捨てず
//! fail-closed で拒否する（`Unsupported`）。`security_opt` は分離を弱める指定を拒否する（SEC-1）。
//!
//! `command` / `entrypoint` / `working_dir` は `create` のフラグではなく bundle の `config.json` の `process` に
//! 入る（[`process_args`]・[`process_cwd`] で image の既定値と合成する）ため、本関数は拒否も出力もしない。
//!
//! 残余: (1) `env_files` は字句でだけ検査する。symlink 越しの範囲外参照は呼び出し側（cli の launcher）が
//! fd 起点で読んで防ぐ。(2) `--env KEY=VALUE` で渡した値は子プロセスの間 `/proc/<pid>/cmdline` から同じ uid に
//! 見える（後続判断）。エラーと `Debug` には値を入れない（フィールド名だけ）。

use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroU8;
use std::path::{Component, Path};

use super::LaunchError;
use super::identity::ServiceContainerId;
use super::network::NetworkAttachment;
use crate::schema::Service;

/// argv 組み立ての失敗。フィールド名（静的文字列）だけを持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateArgsError {
    /// CLI の `create` に写す先が無い指定（`UNIMPLEMENTED`）。
    Unsupported {
        /// 該当フィールド名。
        field: &'static str,
    },
    /// 指定が不正または分離を弱める（`INVALID_ARGUMENT`）。
    Invalid {
        /// 該当フィールド名。
        field: &'static str,
    },
}

impl CreateArgsError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "UNIMPLEMENTED",
            Self::Invalid { .. } => "INVALID_ARGUMENT",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "service field is not supported by create",
            Self::Invalid { .. } => "service field is invalid",
        }
    }

    /// 該当フィールド名。
    pub fn field(&self) -> &'static str {
        match self {
            Self::Unsupported { field } | Self::Invalid { field } => field,
        }
    }

    /// 終了コード（ERR-2 の表: UNIMPLEMENTED は 8、INVALID_ARGUMENT は 2）。
    pub fn exit_code(&self) -> NonZeroU8 {
        match self {
            Self::Unsupported { .. } => NonZeroU8::MIN.saturating_add(7),
            Self::Invalid { .. } => NonZeroU8::MIN.saturating_add(1),
        }
    }

    /// [`ServiceLauncher`](super::ServiceLauncher) の失敗へ写す（値は含まない）。
    pub fn to_launch_error(&self) -> LaunchError {
        LaunchError::new(self.code(), self.message())
    }
}

impl fmt::Display for CreateArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.code(), self.message(), self.field())
    }
}

impl std::error::Error for CreateArgsError {}

/// argv の組み立てに要る呼び出し側の文脈。
#[derive(Debug, Clone, Copy)]
pub struct CreateArgvContext<'a> {
    /// 対象のコンテナ ID。
    pub id: &'a ServiceContainerId,
    /// スタック定義のあるディレクトリ（`env_files` の基準）。
    pub project_dir: &'a Path,
    /// `--bundle` に渡すディレクトリ（CLI の `create` は必須）。絶対パス。
    pub bundle: &'a Path,
    /// `--image-root` に渡すイメージストアの root。絶対パス。
    pub image_root: &'a Path,
    /// `true` なら `--unpack` を付け、イメージを bundle の `rootfs/` へ展開させる（`up` の本番は常に `true`）。
    pub unpack: bool,
}

/// `create` の argv（サブコマンド名から ID まで）を作る。
///
/// 並び: `create`、サービス由来のオプション、`--bundle`、`--image-root`、`--image`、
/// ネットワーク、`--`、ID。
pub fn create_argv(
    spec: &Service,
    network: Option<NetworkAttachment<'_>>,
    ctx: &CreateArgvContext<'_>,
) -> Result<Vec<OsString>, CreateArgsError> {
    let Service {
        image,
        container_name,
        // bundle の config.json の process へ入る（process_args・process_cwd）。
        command: _,
        entrypoint: _,
        working_dir: _,
        cap_drop: _,
        security_opt,
        stdin_open,
        tty,
        env: _,
        env_files,
        ports,
        // 接続先は `plan_networks` が検証した `network` だけを使う。
        networks: _,
        volumes,
        // 計画と profiles の絞り込みで消費済み。
        depends_on: _,
        labels: _,
        restart,
        secrets,
        configs,
        ulimits,
        shm_size,
        tmpfs,
        devices,
        // 計画と profiles の絞り込みで消費済み。
        profiles: _,
        healthcheck,
        deploy,
    } = spec;

    let image = image
        .as_deref()
        .ok_or(CreateArgsError::Unsupported { field: "image" })?;
    for (field, present) in [
        ("container_name", container_name.is_some()),
        ("volumes", !volumes.is_empty()),
        ("restart", restart.is_some()),
        ("secrets", !secrets.is_empty()),
        ("configs", !configs.is_empty()),
        ("devices", !devices.is_empty()),
        ("healthcheck", healthcheck.is_some()),
        ("deploy", deploy.is_some()),
        ("stdin_open", *stdin_open == Some(true)),
        ("tty", *tty == Some(true)),
    ] {
        if present {
            return Err(CreateArgsError::Unsupported { field });
        }
    }
    // 常に有効な固定段と同じ意味の指定だけを許す。それ以外は分離を弱めうる。
    if security_opt
        .iter()
        .any(|o| !matches!(o.as_str(), "no-new-privileges" | "no-new-privileges:true"))
    {
        return Err(CreateArgsError::Invalid {
            field: "security_opt",
        });
    }
    if env_files.iter().any(|f| !is_relative_lexical(f)) {
        return Err(CreateArgsError::Invalid { field: "env_files" });
    }
    if !ctx.image_root.is_absolute() {
        return Err(CreateArgsError::Invalid {
            field: "image_root",
        });
    }
    if !ctx.bundle.is_absolute() {
        return Err(CreateArgsError::Invalid { field: "bundle" });
    }

    let mut args = vec![OsString::from("create")];
    args.extend(spec.create_option_args(ctx.project_dir));
    for (name, value) in ulimits {
        args.push("--ulimit".into());
        args.push(format!("{name}={value}").into());
    }
    if let Some(size) = shm_size {
        args.push("--shm-size".into());
        args.push(size.into());
    }
    for entry in tmpfs {
        args.push("--tmpfs".into());
        args.push(entry.into());
    }
    for port in ports {
        args.push("--publish".into());
        args.push(port.into());
    }
    args.push("--bundle".into());
    args.push(ctx.bundle.as_os_str().to_owned());
    args.push("--image-root".into());
    args.push(ctx.image_root.as_os_str().to_owned());
    args.push("--image".into());
    args.push(image.into());
    if ctx.unpack {
        args.push("--unpack".into());
    }
    if let Some(network) = network {
        args.extend(network.create_option_args());
    }
    args.push("--".into());
    args.push(ctx.id.as_str().into());
    Ok(args)
}

/// image の Entrypoint・Cmd とサービスの `entrypoint`・`command` から `process.args` を合成する（compose の意味論）。
///
/// `entrypoint` を指定すると image の Entrypoint を置き換え、image の Cmd も捨てる。`command` は image の Cmd を置き換える。
/// 結果が空なら起動できないため `Invalid { field: "command" }`。要素に NUL を含むものも拒否する。
pub fn process_args(
    spec: &Service,
    image_entrypoint: &[String],
    image_cmd: &[String],
) -> Result<Vec<String>, CreateArgsError> {
    let entrypoint: &[String] = spec.entrypoint.as_deref().unwrap_or(image_entrypoint);
    let cmd: &[String] = match (&spec.command, &spec.entrypoint) {
        (Some(c), _) => c,
        (None, Some(_)) => &[],
        (None, None) => image_cmd,
    };
    let args: Vec<String> = entrypoint.iter().chain(cmd).cloned().collect();
    if args.is_empty() || args.iter().any(|a| a.contains('\0')) {
        return Err(CreateArgsError::Invalid { field: "command" });
    }
    Ok(args)
}

/// `process.cwd` を決める。サービスの `working_dir`（絶対パスのみ）、無ければ image の WorkingDir、無ければ `/`。
pub fn process_cwd(spec: &Service, image_working_dir: &str) -> Result<String, CreateArgsError> {
    let pick = |s: &str| s.starts_with('/') && !s.contains('\0');
    match spec.working_dir.as_deref() {
        Some(w) if pick(w) => Ok(w.to_owned()),
        Some(_) => Err(CreateArgsError::Invalid {
            field: "working_dir",
        }),
        None if pick(image_working_dir) => Ok(image_working_dir.to_owned()),
        None => Ok("/".to_owned()),
    }
}

/// `start` の argv（サブコマンド名から ID まで）を作る。
pub fn start_argv(id: &ServiceContainerId) -> Vec<OsString> {
    vec!["start".into(), "--".into(), id.as_str().into()]
}

/// 相対で、`..`・ルート・prefix 成分を含まない（字句の検査。symlink は見ない）。
fn is_relative_lexical(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !p.is_absolute()
        && p.components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        // Windows 形式の区切りや prefix は他 OS では Normal に見えるため字句でも拒否する。
        && !path.contains('\\')
        && !path.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::super::identity::ProjectName;
    use super::*;
    use crate::schema::{Deploy, Healthcheck};
    use std::path::PathBuf;

    fn id() -> ServiceContainerId {
        ServiceContainerId::derive(&ProjectName::new("app").unwrap(), "web").unwrap()
    }

    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:\\store")
        } else {
            PathBuf::from("/store")
        }
    }

    fn argv(spec: &Service) -> Result<Vec<OsString>, CreateArgsError> {
        let id = id();
        let bundle = root().join("b");
        let image_root = root();
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: Path::new("proj"),
            bundle: &bundle,
            image_root: &image_root,
            unpack: false,
        };
        create_argv(spec, None, &ctx)
    }

    fn base() -> Service {
        Service {
            image: Some("busybox:1.36".into()),
            ..Service::default()
        }
    }

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn stack8_full_argv_is_exact() {
        let mut s = base();
        s.env.insert("K".into(), "-x".into());
        s.env_files.push("sub/.env".into());
        s.labels.insert("l".into(), "v".into());
        s.cap_drop.push("NET_RAW".into());
        s.ulimits.insert("nofile".into(), "1024:2048".into());
        s.shm_size = Some("64m".into());
        s.tmpfs.push("/run".into());
        s.ports.push("8080:80".into());
        s.security_opt.push("no-new-privileges:true".into());
        s.stdin_open = Some(false);
        let id = id();
        let bundle = root().join("b");
        let image_root = root();
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: Path::new("proj"),
            bundle: &bundle,
            image_root: &image_root,
            unpack: false,
        };
        let net = NetworkAttachment::new("backend");
        let got = strs(&create_argv(&s, Some(net), &ctx).unwrap());
        let want: Vec<String> = [
            "create",
            "--env-file",
            &Path::new("proj").join("sub/.env").to_string_lossy(),
            "--env",
            "K=-x",
            "--label",
            "l=v",
            "--cap-drop",
            "NET_RAW",
            "--ulimit",
            "nofile=1024:2048",
            "--shm-size",
            "64m",
            "--tmpfs",
            "/run",
            "--publish",
            "8080:80",
            "--bundle",
            &bundle.to_string_lossy(),
            "--image-root",
            &image_root.to_string_lossy(),
            "--image",
            "busybox:1.36",
            "--network",
            "backend",
            "--",
            "app.web",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(got, want);
        assert_eq!(strs(&start_argv(&id)), ["start", "--", "app.web"]);
    }

    #[test]
    fn stack8_unsupported_fields_are_rejected_one_by_one() {
        type Setter = Box<dyn Fn(&mut Service)>;
        let cases: Vec<(&str, Setter)> = vec![
            (
                "container_name",
                Box::new(|s| s.container_name = Some("c".into())),
            ),
            ("volumes", Box::new(|s| s.volumes.push("a:b".into()))),
            ("restart", Box::new(|s| s.restart = Some("always".into()))),
            ("secrets", Box::new(|s| s.secrets.push("x".into()))),
            ("configs", Box::new(|s| s.configs.push("x".into()))),
            ("devices", Box::new(|s| s.devices.push("/dev/x".into()))),
            (
                "healthcheck",
                Box::new(|s| s.healthcheck = Some(Healthcheck::default())),
            ),
            ("deploy", Box::new(|s| s.deploy = Some(Deploy::default()))),
            ("stdin_open", Box::new(|s| s.stdin_open = Some(true))),
            ("tty", Box::new(|s| s.tty = Some(true))),
        ];
        for (field, set) in cases {
            let mut s = base();
            set(&mut s);
            let err = argv(&s).expect_err(field);
            assert_eq!(err, CreateArgsError::Unsupported { field }, "{field}");
            assert_eq!(err.code(), "UNIMPLEMENTED");
            assert_eq!(err.exit_code().get(), 8);
        }
        let mut s = base();
        s.tty = Some(false);
        s.stdin_open = None;
        assert!(argv(&s).is_ok());
        assert_eq!(
            argv(&Service::default()),
            Err(CreateArgsError::Unsupported { field: "image" })
        );
    }

    #[test]
    fn sec1_security_opt_only_allows_no_new_privileges() {
        for ok in ["no-new-privileges", "no-new-privileges:true"] {
            let mut s = base();
            s.security_opt.push(ok.into());
            assert!(argv(&s).is_ok(), "{ok}");
        }
        for bad in [
            "seccomp=unconfined",
            "apparmor=unconfined",
            "label=disable",
            "x",
        ] {
            let mut s = base();
            s.security_opt.push(bad.into());
            let err = argv(&s).expect_err(bad);
            assert_eq!(
                err,
                CreateArgsError::Invalid {
                    field: "security_opt"
                }
            );
            assert_eq!(err.code(), "INVALID_ARGUMENT");
            assert_eq!(err.exit_code().get(), 2);
        }
    }

    #[test]
    fn sec1_env_files_are_lexically_confined() {
        for bad in ["../x", "/etc/x", "a/../../x", "", "a\\b", "C:\\x"] {
            let mut s = base();
            s.env_files.push(bad.into());
            assert_eq!(
                argv(&s),
                Err(CreateArgsError::Invalid { field: "env_files" }),
                "{bad:?}"
            );
        }
        let mut s = base();
        s.env_files.push("sub/.env".into());
        assert!(argv(&s).is_ok());
    }

    #[test]
    fn sec1_relative_roots_are_rejected() {
        let id = id();
        let abs = root();
        let rel = Path::new("rel");
        let s = base();
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: rel,
            bundle: &abs,
            image_root: rel,
            unpack: false,
        };
        assert_eq!(
            create_argv(&s, None, &ctx),
            Err(CreateArgsError::Invalid {
                field: "image_root"
            })
        );
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: rel,
            bundle: rel,
            image_root: &abs,
            unpack: false,
        };
        assert_eq!(
            create_argv(&s, None, &ctx),
            Err(CreateArgsError::Invalid { field: "bundle" })
        );
    }

    #[test]
    fn sec1_errors_do_not_carry_values() {
        let mut s = base();
        s.env.insert("K".into(), "s3cr3t".into());
        s.restart = Some("s3cr3t".into());
        let err = argv(&s).unwrap_err();
        let le = err.to_launch_error();
        let text = format!("{err} {err:?} {le} {le:?}");
        assert!(!text.contains("s3cr3t"), "{text}");
        assert_eq!(le.code(), "UNIMPLEMENTED");
    }

    /// STACK-8・#4638: `unpack` で `--image` の直後に `--unpack` が出る。
    #[test]
    fn stack8_4638_unpack_flag_follows_image() {
        let id = id();
        let bundle = root().join("b");
        let image_root = root();
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: Path::new("proj"),
            bundle: &bundle,
            image_root: &image_root,
            unpack: true,
        };
        let got = strs(&create_argv(&base(), None, &ctx).unwrap());
        let at = got.iter().position(|a| a == "--image").unwrap();
        assert_eq!(got[at + 1], "busybox:1.36");
        assert_eq!(got[at + 2], "--unpack");
        assert_eq!(got[at + 3], "--");
    }

    /// STACK-8・#4638: command / entrypoint / working_dir は create の argv に出ず、拒否もされない。
    #[test]
    fn stack8_4638_process_fields_are_not_create_flags() {
        let mut s = base();
        s.command = Some(vec!["x".into()]);
        s.entrypoint = Some(vec!["y".into()]);
        s.working_dir = Some("/w".into());
        let got = strs(&argv(&s).unwrap());
        assert!(!got.iter().any(|a| a == "x" || a == "y" || a == "/w"));
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    /// STACK-8・#4638: process.args の合成表（compose の意味論）を具体値で照合する。
    #[test]
    fn stack8_4638_process_args_compose_table() {
        let ie = v(&["/ep"]);
        let ic = v(&["c1", "c2"]);
        // 指定なし: image の Entrypoint ++ Cmd。
        assert_eq!(
            process_args(&base(), &ie, &ic).unwrap(),
            v(&["/ep", "c1", "c2"])
        );
        // command: image の Cmd を置き換える。
        let mut s = base();
        s.command = Some(v(&["z"]));
        assert_eq!(process_args(&s, &ie, &ic).unwrap(), v(&["/ep", "z"]));
        // entrypoint: Entrypoint を置き換え、image の Cmd も捨てる。
        let mut s = base();
        s.entrypoint = Some(v(&["/new"]));
        assert_eq!(process_args(&s, &ie, &ic).unwrap(), v(&["/new"]));
        // 両方。
        s.command = Some(v(&["a"]));
        assert_eq!(process_args(&s, &ie, &ic).unwrap(), v(&["/new", "a"]));
        // 空は起動できない。
        assert_eq!(
            process_args(&base(), &[], &[]),
            Err(CreateArgsError::Invalid { field: "command" })
        );
        let mut s = base();
        s.command = Some(v(&["a\0b"]));
        assert!(process_args(&s, &ie, &ic).is_err());
    }

    /// STACK-8・#4638: process.cwd は working_dir ＞ image の WorkingDir ＞ `/`。相対パスは拒否する。
    #[test]
    fn stack8_4638_process_cwd_priority() {
        let mut s = base();
        assert_eq!(process_cwd(&s, "").unwrap(), "/");
        assert_eq!(process_cwd(&s, "/app").unwrap(), "/app");
        s.working_dir = Some("/w".into());
        assert_eq!(process_cwd(&s, "/app").unwrap(), "/w");
        s.working_dir = Some("rel".into());
        assert_eq!(
            process_cwd(&s, "/app"),
            Err(CreateArgsError::Invalid {
                field: "working_dir"
            })
        );
        s.working_dir = None;
        assert_eq!(process_cwd(&s, "rel").unwrap(), "/");
    }
}
