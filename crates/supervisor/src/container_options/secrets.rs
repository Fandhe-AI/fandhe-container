//! secrets / configs の指定モデル（SUP-12・TASK-169.4.2・#1473・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! CLI（TASK-79）や stack（TOML）が渡す Docker 互換の指定（名前・内容の出所・マウント先・モード）を検証して
//! 保持し、[`ContainerOptions::injected_files`](super::ContainerOptions::injected_files) が core の
//! [`InjectedFileSet`]（検証済みの仕様型）へ変換する。実注入は core の `exec::inject_files` が
//! 「`mount_tmpfs` の後・`pivot_root` の前」で行う（親ディレクトリごとの専用 tmpfs へ書き込み、read-only へ
//! 再マウントする。supervisor → core の一方向依存）。OS 非依存の純粋な解析・読み取りのみで、`cfg` 分岐も
//! `unsafe` も持たない。
//!
//! # 文法
//!
//! - 参照部 `source=<name>[,target=<path>][,mode=<octal>]`（[`InjectedFileOption::parse`]）。`source=` は
//!   secret / config の名前（`[A-Za-z0-9._-]`・64 文字以下・`.` / `..` は不可）。`target=` 未指定の
//!   ファイルは secrets が `/run/secrets/<name>`、configs が `/run/configs/<name>`（相対指定は既定
//!   ディレクトリ配下として扱う）。`mode=` は 8 進数字のみ（`0777` 以下）で、未指定は `0444`
//! - 内容の出所は [`InjectedSource`]: ホスト上のファイル（`File`）か、呼び出し側が組み立てた内容（`Inline`）。
//!   ホストファイルは通常ファイルのみ・上限 [`INJECTED_FILE_MAX_BYTES`]・FIFO でブロックしない
//!   （`EnvFile::read` と同じ手順。REPAIR-5）。読み取りは [`ContainerOptions::injected_files`] の消費時点で行い、
//!   指定モデルは出所のパスだけを保持する
//!
//! # 契約
//!
//! - 内容は `Debug`・エラー message に出さない（[`InjectedContent`] は長さのみ。message は固定の英語文言で
//!   入力値・パス・内容を含めない）
//! - 件数・サイズ・マウント先の検証は core の [`InjectedFileSet`] が行う（rootfs 外・`..`・深さ・重複・入れ子）
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! launcher・CLI・stack（TOML）からの配線、`uid=` / `gid=`、環境変数由来の内容（ホスト環境の漏洩経路になり得る
//! ため。env と同じ方針）、単一ファイルの bind 注入（Docker の configs 既定 `/<name>` は、rootfs 直下を覆う
//! tmpfs になるため `/run/configs/<name>` を既定にしている）。

use std::io::Read as _;
use std::path::{Path, PathBuf};

use fandhe_container_core::injected_files::{
    INJECTED_FILE_MAX_BYTES, INJECTED_MAX_FILES, InjectedContent, InjectedFileMode,
    InjectedFileSet, InjectedFileSpec,
};
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::env::open_nonblocking;

/// secrets の既定ディレクトリ。
pub const SECRETS_DEFAULT_DIR: &str = "/run/secrets";

/// configs の既定ディレクトリ。
pub const CONFIGS_DEFAULT_DIR: &str = "/run/configs";

/// 参照部（`source=...,target=...,mode=...`）の入力長上限（core の `CONFIG_MAX_PATH_BYTES` に name と mode を足せる値）。
const MAX_SPEC_BYTES: usize = 4096 + 256;

/// name の長さ上限。
const MAX_NAME_BYTES: usize = 64;

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

/// secret か config か（既定ディレクトリの決定に使う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedKind {
    /// secret（既定 `/run/secrets/<name>`）。
    Secret,
    /// config（既定 `/run/configs/<name>`）。
    Config,
}

impl InjectedKind {
    fn default_dir(self) -> &'static str {
        match self {
            Self::Secret => SECRETS_DEFAULT_DIR,
            Self::Config => CONFIGS_DEFAULT_DIR,
        }
    }
}

/// 内容の出所。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectedSource {
    /// ホスト上のファイル（消費時点に読む。通常ファイルのみ）。
    File(PathBuf),
    /// 呼び出し側が用意した内容（`Debug` は長さのみ）。
    Inline(InjectedContent),
}

/// secret / config 1 件の指定（検証済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedFileOption {
    kind: InjectedKind,
    name: String,
    source: InjectedSource,
    target: Option<String>,
    mode: Option<InjectedFileMode>,
}

impl InjectedFileOption {
    /// 名前と出所から作る（マウント先・モードは既定）。
    pub fn new(kind: InjectedKind, name: &str, source: InjectedSource) -> Result<Self, TraitError> {
        validate_name(name)?;
        Ok(Self {
            kind,
            name: name.to_owned(),
            source,
            target: None,
            mode: None,
        })
    }

    /// `source=<name>[,target=<path>][,mode=<octal>]` を解析して作る。未知キー・重複キー・
    /// `uid` / `gid`（未対応）は拒否する。
    pub fn parse(
        kind: InjectedKind,
        spec: &str,
        source: InjectedSource,
    ) -> Result<Self, TraitError> {
        if spec.len() > MAX_SPEC_BYTES {
            return Err(invalid("secret or config reference is too long"));
        }
        let (mut name, mut target, mut mode): (Option<&str>, Option<&str>, Option<&str>) =
            (None, None, None);
        for item in spec.split(',') {
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| invalid("secret or config reference must be key=value pairs"))?;
            let slot = match key {
                "source" => &mut name,
                "target" => &mut target,
                "mode" => &mut mode,
                _ => return Err(invalid("unknown key in secret or config reference")),
            };
            if slot.replace(value).is_some() {
                return Err(invalid("duplicate key in secret or config reference"));
            }
        }
        let name = name.ok_or_else(|| invalid("secret or config reference needs source="))?;
        let mut opt = Self::new(kind, name, source)?;
        if let Some(t) = target {
            opt = opt.with_target(t)?;
        }
        if let Some(m) = mode {
            opt = opt.with_mode(parse_mode(m)?);
        }
        Ok(opt)
    }

    /// コンテナ内のマウント先を設定する。相対指定は既定ディレクトリ配下として扱う。形式の検証は
    /// 変換時（core の [`InjectedFileSpec::new`]）に行うが、空文字と NUL はここで拒否する。
    pub fn with_target(mut self, target: &str) -> Result<Self, TraitError> {
        if target.is_empty() || target.contains('\0') {
            return Err(invalid("invalid secret or config target"));
        }
        self.target = Some(target.to_owned());
        Ok(self)
    }

    /// ファイルのモードを設定する（未指定は `0444`）。
    pub fn with_mode(mut self, mode: InjectedFileMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// secret か config か。
    pub fn kind(&self) -> InjectedKind {
        self.kind
    }

    /// 名前。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 既定ディレクトリを反映した、コンテナ内のマウント先（正規化前の文字列）。
    fn destination(&self) -> String {
        let dir = self.kind.default_dir();
        match &self.target {
            None => format!("{dir}/{}", self.name),
            Some(t) if t.starts_with('/') => t.clone(),
            Some(t) => format!("{dir}/{t}"),
        }
    }

    /// 内容を解決して core の仕様型へ変換する（`File` はここで読む）。
    fn to_core_spec(&self) -> Result<InjectedFileSpec, TraitError> {
        let content = match &self.source {
            InjectedSource::Inline(c) => c.clone(),
            InjectedSource::File(p) => read_host_file(p)?,
        };
        InjectedFileSpec::new(
            &self.destination(),
            content,
            self.mode.unwrap_or(InjectedFileMode::DEFAULT),
        )
    }
}

/// `source=` の名前を検証する（1 要素・`[A-Za-z0-9._-]`・64 文字以下・`.` / `..` 不可）。
fn validate_name(name: &str) -> Result<(), TraitError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(invalid("invalid secret or config name"))
    }
}

/// 8 進数字のみの mode（`0777` 以下。先頭の `+`・空文字・`0o` 接頭辞は拒否）。
fn parse_mode(text: &str) -> Result<InjectedFileMode, TraitError> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(invalid("secret or config mode must be octal digits"));
    }
    let bits =
        u32::from_str_radix(text, 8).map_err(|_| invalid("invalid secret or config mode"))?;
    InjectedFileMode::new(bits)
}

/// ホストファイルを読む。通常ファイルのみ・上限付き・FIFO でブロックしない（`EnvFile::read` と同じ手順）。
/// message にパス・内容は含めない。
fn read_host_file(path: &Path) -> Result<InjectedContent, TraitError> {
    let pre =
        std::fs::metadata(path).map_err(|_| invalid("cannot open secret or config source"))?;
    if !pre.is_file() {
        return Err(invalid("secret or config source must be a regular file"));
    }
    let file =
        open_nonblocking(path).map_err(|_| invalid("cannot open secret or config source"))?;
    let meta = file
        .metadata()
        .map_err(|_| invalid("cannot stat secret or config source"))?;
    if !meta.is_file() {
        return Err(invalid("secret or config source must be a regular file"));
    }
    let mut buf = Vec::new();
    file.take(INJECTED_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| invalid("cannot read secret or config source"))?;
    InjectedContent::from_bytes(buf)
}

/// secrets / configs の指定一覧（`ContainerOptions` が保持する）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InjectedFileOptions {
    secrets: Vec<InjectedFileOption>,
    configs: Vec<InjectedFileOption>,
}

impl InjectedFileOptions {
    /// secrets を設定する。`kind` が `Secret` でないものと、件数上限超過は拒否する。
    pub fn with_secrets(mut self, secrets: Vec<InjectedFileOption>) -> Result<Self, TraitError> {
        check_list(&secrets, InjectedKind::Secret)?;
        self.secrets = secrets;
        Ok(self)
    }

    /// configs を設定する。`kind` が `Config` でないものと、件数上限超過は拒否する。
    pub fn with_configs(mut self, configs: Vec<InjectedFileOption>) -> Result<Self, TraitError> {
        check_list(&configs, InjectedKind::Config)?;
        self.configs = configs;
        Ok(self)
    }

    /// secrets。
    pub fn secrets(&self) -> &[InjectedFileOption] {
        &self.secrets
    }

    /// configs。
    pub fn configs(&self) -> &[InjectedFileOption] {
        &self.configs
    }

    /// 内容を解決して core の [`InjectedFileSet`] へ変換する（secrets → configs の順）。
    /// 合計件数・サイズ・重複・入れ子の検証は `InjectedFileSet::push` が行う。
    pub fn to_file_set(&self) -> Result<InjectedFileSet, TraitError> {
        let mut set = InjectedFileSet::new();
        for o in self.secrets.iter().chain(&self.configs) {
            set.push(o.to_core_spec()?)?;
        }
        Ok(set)
    }
}

fn check_list(list: &[InjectedFileOption], kind: InjectedKind) -> Result<(), TraitError> {
    if list.len() > INJECTED_MAX_FILES {
        return Err(invalid("too many secrets or configs"));
    }
    if list.iter().any(|o| o.kind != kind) {
        return Err(invalid("secret or config kind does not match"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &[u8] = b"SENTINEL-DUMMY-VALUE";

    fn inline(b: &[u8]) -> InjectedSource {
        InjectedSource::Inline(InjectedContent::from_bytes(b.to_vec()).expect("content"))
    }

    fn err(r: Result<impl std::fmt::Debug, TraitError>) -> (ErrorCode, String) {
        let e = r.expect_err("must be rejected");
        (e.code(), e.message().to_owned())
    }

    fn dest_mode(o: &InjectedFileOption) -> (String, u32, usize) {
        let s = o.to_core_spec().expect("spec");
        (
            s.destination().as_str().to_owned(),
            s.mode().bits(),
            s.content().len(),
        )
    }

    /// SUP-12・TASK-169.4.2: 既定ターゲット・相対 / 絶対 target・mode を具体値で照合する。
    #[test]
    fn sup12_task169_4_2_parse_targets_and_modes() {
        let p = |k, s: &str| InjectedFileOption::parse(k, s, inline(SENTINEL)).expect(s);
        assert_eq!(
            dest_mode(&p(InjectedKind::Secret, "source=db_password")),
            ("/run/secrets/db_password".to_owned(), 0o444, 20)
        );
        assert_eq!(
            dest_mode(&p(InjectedKind::Config, "source=app.conf,mode=0400")),
            ("/run/configs/app.conf".to_owned(), 0o400, 20)
        );
        assert_eq!(
            dest_mode(&p(InjectedKind::Secret, "source=a,target=sub/b,mode=640")),
            ("/run/secrets/sub/b".to_owned(), 0o640, 20)
        );
        assert_eq!(
            dest_mode(&p(InjectedKind::Config, "source=a,target=/etc/app/a.conf")),
            ("/etc/app/a.conf".to_owned(), 0o444, 20)
        );
    }

    /// SUP-12・TASK-169.4.2: 不正な参照部・name・mode・target を拒否する。
    #[test]
    fn sup12_task169_4_2_parse_rejects_invalid() {
        let parse = |s: &str| InjectedFileOption::parse(InjectedKind::Secret, s, inline(b""));
        let bad_name = (ErrorCode::InvalidArgument, "invalid secret or config name");
        for s in [
            "source=",
            "source=..",
            "source=a/b",
            "source=a b",
            "source=a\nb",
        ] {
            assert_eq!(err(parse(s)), (bad_name.0, bad_name.1.to_owned()), "{s:?}");
        }
        assert_eq!(
            err(parse(&format!("source={}", "n".repeat(65)))),
            (bad_name.0, bad_name.1.to_owned())
        );
        let cases = [
            ("target=/x", "secret or config reference needs source="),
            (
                "source=a,uid=0",
                "unknown key in secret or config reference",
            ),
            (
                "source=a,gid=0",
                "unknown key in secret or config reference",
            ),
            (
                "source=a,source=b",
                "duplicate key in secret or config reference",
            ),
            (
                "source=a,mode=8",
                "secret or config mode must be octal digits",
            ),
            (
                "source=a,mode=0o4",
                "secret or config mode must be octal digits",
            ),
            (
                "source=a,mode=",
                "secret or config mode must be octal digits",
            ),
            (
                "source=a,mode=1777",
                "injected file mode must not exceed 0777",
            ),
            ("source=a,target=", "invalid secret or config target"),
            ("source=a,target=x\0y", "invalid secret or config target"),
            (
                "source",
                "secret or config reference must be key=value pairs",
            ),
        ];
        for (s, msg) in cases {
            assert_eq!(
                err(parse(s)),
                (ErrorCode::InvalidArgument, msg.to_owned()),
                "{s:?}"
            );
        }
        let long = format!("source=a,target=/{}", "x".repeat(MAX_SPEC_BYTES));
        assert_eq!(
            err(parse(&long)),
            (
                ErrorCode::InvalidArgument,
                "secret or config reference is too long".to_owned()
            )
        );
        // マウント先の検証は変換時（core）が行う（`..`・rootfs 直下）。
        let traversal = InjectedFileOption::parse(
            InjectedKind::Secret,
            "source=a,target=/x/../../etc/passwd",
            inline(b""),
        )
        .expect("parse");
        assert_eq!(
            err(traversal.to_core_spec()),
            (
                ErrorCode::InvalidArgument,
                "invalid injected file destination".to_owned()
            )
        );
        let root = InjectedFileOption::new(InjectedKind::Secret, "a", inline(b""))
            .and_then(|o| o.with_target("/top"))
            .expect("opt");
        assert_eq!(
            err(root.to_core_spec()),
            (
                ErrorCode::InvalidArgument,
                "injected file must be placed in a directory below the root".to_owned()
            )
        );
    }

    /// SUP-12・TASK-169.4.2: ホストファイルの読み取り（上限境界・ディレクトリ・欠落）と、
    /// Debug・エラー message に内容・パスが出ないこと。
    #[test]
    fn sup12_task169_4_2_host_file_source() {
        let dir = std::env::temp_dir().join(format!("fandhe-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = |name: &str, body: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, body).expect("write");
            InjectedFileOption::new(InjectedKind::Secret, "s", InjectedSource::File(p))
                .expect("opt")
        };
        let ok = file("ok", SENTINEL);
        assert_eq!(
            dest_mode(&ok),
            ("/run/secrets/s".to_owned(), 0o444, SENTINEL.len())
        );
        let at_limit = file("limit", &vec![b'x'; INJECTED_FILE_MAX_BYTES]);
        assert_eq!(dest_mode(&at_limit).2, INJECTED_FILE_MAX_BYTES);
        let over = file("over", &vec![b'x'; INJECTED_FILE_MAX_BYTES + 1]);
        assert_eq!(
            err(over.to_core_spec()),
            (
                ErrorCode::InvalidArgument,
                "injected file content is too large".to_owned()
            )
        );
        let as_dir =
            InjectedFileOption::new(InjectedKind::Secret, "s", InjectedSource::File(dir.clone()))
                .expect("opt");
        let missing = InjectedFileOption::new(
            InjectedKind::Secret,
            "s",
            InjectedSource::File(dir.join("SENTINEL-MISSING")),
        )
        .expect("opt");
        let e_dir = err(as_dir.to_core_spec());
        let e_missing = err(missing.to_core_spec());
        assert_eq!(e_dir.1, "secret or config source must be a regular file");
        assert_eq!(e_missing.1, "cannot open secret or config source");
        assert!(!e_missing.1.contains("SENTINEL"));
        assert!(!format!("{:?}", inline(SENTINEL)).contains("SENTINEL"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-12・TASK-169.4.2: FIFO を指定してもブロックせず拒否する（REPAIR-5）。
    #[cfg(unix)]
    #[test]
    fn sup12_task169_4_2_fifo_source_is_rejected_without_blocking() {
        let dir = std::env::temp_dir().join(format!("fandhe-secrets-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if made {
            let o = InjectedFileOption::new(InjectedKind::Secret, "s", InjectedSource::File(fifo))
                .expect("opt");
            assert_eq!(
                err(o.to_core_spec()),
                (
                    ErrorCode::InvalidArgument,
                    "secret or config source must be a regular file".to_owned()
                )
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-12・TASK-169.4.2: 一覧の kind 不一致・件数超過の拒否と、secrets → configs の順の変換。
    #[test]
    fn sup12_task169_4_2_options_lists_and_file_set() {
        let sec = |n: &str| InjectedFileOption::new(InjectedKind::Secret, n, inline(b"s"));
        let cfg = |n: &str| InjectedFileOption::new(InjectedKind::Config, n, inline(b"c"));
        let opts = InjectedFileOptions::default()
            .with_secrets(vec![sec("a").expect("a"), sec("b").expect("b")])
            .and_then(|o| o.with_configs(vec![cfg("c").expect("c")]))
            .expect("opts");
        let set = opts.to_file_set().expect("set");
        let dests: Vec<_> = set
            .files()
            .iter()
            .map(|f| f.destination().as_str().to_owned())
            .collect();
        assert_eq!(
            dests,
            ["/run/secrets/a", "/run/secrets/b", "/run/configs/c"]
        );
        assert_eq!(
            err(InjectedFileOptions::default().with_secrets(vec![cfg("c").expect("c")])),
            (
                ErrorCode::InvalidArgument,
                "secret or config kind does not match".to_owned()
            )
        );
        let many: Vec<_> = (0..=INJECTED_MAX_FILES)
            .map(|i| sec(&format!("s{i}")).expect("s"))
            .collect();
        assert_eq!(
            err(InjectedFileOptions::default().with_secrets(many)),
            (
                ErrorCode::InvalidArgument,
                "too many secrets or configs".to_owned()
            )
        );
        // secrets と configs が同じマウント先になる指定は重複として拒否される。
        let dup = InjectedFileOptions::default()
            .with_secrets(vec![
                sec("a").expect("a").with_target("/etc/x/f").expect("t"),
            ])
            .and_then(|o| {
                o.with_configs(vec![
                    cfg("a").expect("a").with_target("/etc/x/f").expect("t"),
                ])
            })
            .expect("opts");
        assert_eq!(
            err(dup.to_file_set()),
            (
                ErrorCode::InvalidArgument,
                "duplicate injected file destination".to_owned()
            )
        );
    }
}
