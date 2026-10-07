//! env / env ファイルの公開 API 受け入れ照合（SUP-12・TASK-169.4・#529・REPAIR-12）。
//!
//! `-e` と env ファイルを統合した結果が `execve` の envp 形式（`KEY=VALUE` 列）になることを、
//! `ContainerOptions` 経由で具体値で確認する。3 OS で実行する。

use fandhe_container_supervisor::container_options::ContainerOptions;
use fandhe_container_supervisor::container_options::env::{EnvFile, EnvSet, EnvVar};

/// SUP-12・TASK-169.4: ContainerOptions 経由で優先順位どおりの envp が得られる。
#[test]
fn sup12_options_env_acceptance() {
    let base = [EnvVar::parse("PATH=/usr/bin").unwrap()];
    let file = EnvFile::parse("# comment\nMODE=file\nNAME=dummy\n").unwrap();
    let cli = [EnvVar::parse("MODE=cli").unwrap()];
    let set = EnvSet::resolve(&base, &[file], &cli).unwrap();
    let opts = ContainerOptions::new().with_env(set);
    assert_eq!(
        opts.env().to_env_strings(),
        ["PATH=/usr/bin", "MODE=cli", "NAME=dummy"]
    );
    assert!(ContainerOptions::new().env().is_empty());
}
