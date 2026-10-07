//! 稼働中コンテナへの exec に渡すコマンドと環境変数の型（SUP-6・SEC-1・TASK-163 追補・#1457・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `exec/exec_command.rs` の `spawn_exec_command` が受け取るコマンド [`ExecCommand`] と、その環境変数
//! [`ContainerEnv`] を定める。`fandhe-container-supervisor` の `exec::run_command` が、worker の中で対象の bundle の
//! `config.json` から [`ContainerEnv`] を組み立てて渡す（CLI の exec・TASK-161 / SUP-4 の healthcheck が同じ経路を使う）。
//!
//! # 契約（環境変数。#1457）
//!
//! - **exec されたコマンドの環境は [`ContainerEnv`] の中身だけ**: `execveat` には envp を明示的に渡すため、exec を
//!   起動したプロセス（CLI・supervisor）の環境は 1 つも引き継がれない。既定値（`PATH` 等）の補完もしない
//! - **ホスト環境から暗黙に組み立てられない**: [`ContainerEnv`] を作れるのは、空（[`ContainerEnv::empty`]）・
//!   コンテナ定義（[`ContainerEnv::from_config`]。bundle の `config.json` の `process.env`。launch 経路が
//!   エントリポイントへ渡すのと同じ出所）・それへの 1 件ずつの明示的な上書き（[`ContainerEnv::with_var`]）だけで
//!   ある。`FromIterator`・`From<Vec<_>>`・`Extend`・`Default` を実装せず、文字列の列をまとめて受け取る入口を
//!   持たないため、`std::env::vars()` を渡す式はコンパイルできない（下の `compile_fail`）。呼び出し側が
//!   ホスト環境を 1 件ずつ `with_var` へ写すことは型では防げないため、**`with_var` へ渡してよいのは利用者が
//!   その exec に対して明示した値（CLI の `-e KEY=VALUE` 等）だけ** とする（supervisor の入口は検証済みの
//!   `EnvVar` だけを受け取り、値なしの `-e KEY` によるホスト環境の継承は元から拒否している）
//! - **launch と同じ検証**: 各要素は `KEY=VALUE`（KEY は空でなく `=`・NUL を含まない。VALUE は NUL を含まない）。
//!   件数・1 要素・合計のバイト数の上限は [`Entrypoint`] が検証する。同じ KEY は後勝ちで、位置は最初に現れた
//!   位置を保つ（supervisor の `EnvSet` と同じ規則）
//! - 値は秘密情報を含み得るため、エラーメッセージと `Debug` 出力に値を載せない
//!
//! ```compile_fail,E0308
//! // ホスト環境の列を、そのまま exec のコマンドへ渡すことはできない。
//! let _ = fandhe_container_core::exec::ExecCommand::new("/bin/true", ["true"], std::env::vars());
//! ```
//!
//! ```compile_fail,E0277
//! // 文字列の列から環境をまとめて作る入口は無い。
//! let _: fandhe_container_core::exec::ContainerEnv = std::env::vars().collect();
//! ```
//!
//! # 未実装（REPAIR-3）
//!
//! - 作業ディレクトリ・ユーザーの指定（OCI `process.cwd`・`process.user`）。cwd は rootfs の根で固定し、uid / gid は
//!   exec を起動したプロセスのものを引き継ぐ（launch 経路も同じ。補助グループだけは launch・exec とも空にする。
//!   `exec/capabilities.rs` の `SupplementaryGroups`）

use std::ffi::OsStr;
use std::path::Path;

use crate::oci_runtime::OciConfig;
use crate::traits::types::ErrorCode;

use super::{Entrypoint, ExecError, IsolationStage};

/// コンテナ定義に由来する環境変数の集合（順序つき・KEY で重複排除。契約はモジュール doc）。
#[derive(Clone, PartialEq, Eq)]
pub struct ContainerEnv {
    /// `(KEY, VALUE)`。KEY は一意で、最初に現れた位置を保つ。
    vars: Vec<(String, String)>,
}

impl std::fmt::Debug for ContainerEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 値は出さない（秘密情報を含み得る）。
        f.debug_list()
            .entries(self.vars.iter().map(|(key, _)| key))
            .finish()
    }
}

impl ContainerEnv {
    /// 環境変数を 1 つも持たない集合。
    pub fn empty() -> Self {
        Self { vars: Vec::new() }
    }

    /// コンテナ定義（bundle の `config.json`）の `process.env` から作る。`process` が無ければ空。
    ///
    /// launch 経路がエントリポイントへ渡すのと同じ出所で、exec を起動したプロセスの環境は参照しない。
    /// 書式に合わない要素（`=` が無い・KEY が空・NUL を含む）は `InvalidArgument`（段 `Validate`）。
    pub fn from_config(config: &OciConfig) -> Result<Self, ExecError> {
        let entries = config.process().map(|p| p.env()).unwrap_or_default();
        entries.iter().try_fold(Self::empty(), |env, entry| {
            let (key, value) = entry.split_once('=').ok_or_else(|| {
                invalid("each env element of the container definition must be KEY=VALUE")
            })?;
            env.with_var(key, value)
        })
    }

    /// `key` = `value` を 1 件、明示的に上書き・追加する（同じ KEY は置き換え、無ければ末尾へ足す）。
    ///
    /// 渡してよいのは、利用者がその exec に対して明示した値だけ（モジュール doc）。KEY が空・`=` か NUL を
    /// 含む・VALUE が NUL を含む場合は `InvalidArgument`（段 `Validate`。メッセージに値を載せない）。
    pub fn with_var(mut self, key: &str, value: &str) -> Result<Self, ExecError> {
        if key.is_empty() || key.contains(['=', '\0']) {
            return Err(invalid(
                "an env key must be non-empty and must not contain '=' or NUL",
            ));
        }
        if value.contains('\0') {
            return Err(invalid("an env value must not contain NUL"));
        }
        match self.vars.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => value.clone_into(slot),
            None => self.vars.push((key.to_owned(), value.to_owned())),
        }
        Ok(self)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// `key` の値。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `(KEY, VALUE)` を順に返す。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

fn invalid(message: &str) -> ExecError {
    ExecError::new(
        ErrorCode::InvalidArgument,
        IsolationStage::Validate,
        message,
    )
}

/// 稼働中コンテナの中で実行するコマンド（コンテナ内の絶対パス・argv・[`ContainerEnv`]）。
///
/// `spawn_exec_command` が受け取る唯一のコマンドの型で、環境変数は [`ContainerEnv`] でしか渡せない（契約は
/// モジュール doc）。パス・argv・件数・バイト数の検証は launch 経路と同じ [`Entrypoint`] が行う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    entry: Entrypoint,
}

impl ExecCommand {
    /// 検証して作る。`path` は空でない絶対パス、`args`（argv）は 1 件以上で NUL を含まない
    /// （違反は `InvalidArgument`・段 `Validate`。[`Entrypoint::new`] と同じ）。
    pub fn new<P, A>(path: P, args: A, env: &ContainerEnv) -> Result<Self, ExecError>
    where
        P: AsRef<Path>,
        A: IntoIterator,
        A::Item: AsRef<OsStr>,
    {
        let env = env.iter().map(|(key, value)| format!("{key}={value}"));
        Entrypoint::new(path, args, env).map(|entry| Self { entry })
    }

    /// コンテナ内の絶対パス。
    pub fn path(&self) -> &Path {
        self.entry.path()
    }

    /// 検証済みのエントリポイント（exec の入口と観測用の入口が使う）。
    pub(super) fn entrypoint(&self) -> &Entrypoint {
        &self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::parse_config_bytes;

    fn config(process: &str) -> OciConfig {
        parse_config_bytes(
            format!(r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}}{process}}}"#).as_bytes(),
        )
        .expect("valid config.json")
    }

    fn pairs(env: &ContainerEnv) -> Vec<(String, String)> {
        env.iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: 環境はコンテナ定義の `process.env` だけから作られ、テストプロセスの
    /// 環境（`PATH`・`HOME` 等）は 1 つも入らない。`process` が無ければ空。
    #[test]
    fn sup6_sec1_task163_container_env_comes_only_from_the_container_definition() {
        // テストプロセス自身は環境変数を持つ（対照。ホスト環境が空だから入らないのではない）。
        assert!(std::env::vars_os().next().is_some());
        let env = ContainerEnv::from_config(&config(
            r#","process":{"user":{"uid":0,"gid":0},"cwd":"/","args":["/bin/app"],"env":["A=1","EMPTY=","EQ=a=b"]}"#,
        ))
        .unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("A".to_owned(), "1".to_owned()),
                ("EMPTY".to_owned(), String::new()),
                ("EQ".to_owned(), "a=b".to_owned()),
            ]
        );
        assert_eq!((env.len(), env.is_empty()), (3, false));
        assert_eq!(env.get("EQ"), Some("a=b"));
        assert_eq!(env.get("PATH"), None);
        assert_eq!(env.get("HOME"), None);

        let none = ContainerEnv::from_config(&config("")).unwrap();
        assert_eq!(none, ContainerEnv::empty());
        assert_eq!((none.len(), none.is_empty()), (0, true));
        let no_env = ContainerEnv::from_config(&config(
            r#","process":{"user":{"uid":0,"gid":0},"cwd":"/","args":["/bin/app"]}"#,
        ))
        .unwrap();
        assert_eq!(no_env, ContainerEnv::empty());
    }

    /// SUP-6・TASK-163 追補（#1457）: 明示の上書きは同じ KEY を置き換えて位置を保ち、新しい KEY は末尾へ足す。
    /// 定義の中の重複も後勝ち。
    #[test]
    fn sup6_task163_container_env_overrides_keep_first_position() {
        let env = ContainerEnv::from_config(&config(
            r#","process":{"user":{"uid":0,"gid":0},"cwd":"/","args":["/bin/app"],"env":["A=1","B=2","A=3"]}"#,
        ))
        .unwrap()
        .with_var("B", "override")
        .unwrap()
        .with_var("C", "new")
        .unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("A".to_owned(), "3".to_owned()),
                ("B".to_owned(), "override".to_owned()),
                ("C".to_owned(), "new".to_owned()),
            ]
        );
    }

    /// SUP-6・TASK-163 追補（#1457）: 壊れた KEY / VALUE は `InvalidArgument`（段 `Validate`）で、メッセージと
    /// `Debug` 出力に値を載せない。
    #[test]
    fn sup6_task163_container_env_rejects_malformed_vars_without_leaking_values() {
        for (key, value) in [("", "v"), ("A=B", "v"), ("A\0", "v"), ("A", "se\0cret")] {
            let err = ContainerEnv::empty().with_var(key, value).unwrap_err();
            assert_eq!(
                (err.code, err.stage),
                (ErrorCode::InvalidArgument, IsolationStage::Validate)
            );
            assert!(!err.message.contains("cret"), "{}", err.message);
        }
        let env = ContainerEnv::empty()
            .with_var("TOKEN", "s3cr3t-value")
            .unwrap();
        assert_eq!(format!("{env:?}"), r#"["TOKEN"]"#);
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: コマンドの検証は launch と同じ（絶対パス・argv 1 件以上）。
    #[test]
    fn sup6_task163_exec_command_validates_like_the_launch_entrypoint() {
        let env = ContainerEnv::empty().with_var("K", "V").unwrap();
        let command = ExecCommand::new("/bin/true", ["true", "-x"], &env).unwrap();
        assert_eq!(command.path(), Path::new("/bin/true"));
        assert_eq!(
            command.entrypoint(),
            &Entrypoint::new("/bin/true", ["true", "-x"], ["K=V"]).unwrap()
        );
        for err in [
            ExecCommand::new("relative", ["x"], &env).unwrap_err(),
            ExecCommand::new("/bin/true", [] as [&str; 0], &env).unwrap_err(),
            ExecCommand::new("/bin/true", ["a\0b"], &env).unwrap_err(),
        ] {
            assert_eq!(
                (err.code, err.stage),
                (ErrorCode::InvalidArgument, IsolationStage::Validate)
            );
        }
    }
}
