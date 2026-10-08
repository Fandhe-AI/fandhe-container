//! `--ipc` の指定モデル（SUP-12・TASK-169.3・#528・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `docker run --ipc=<mode>` 相当の指定を検証済みの [`IpcMode`] へ写し、`ContainerOptions` が保持する。
//! Linux では `IpcMode::apply_to` が core の `exec::NamespaceSet` を組み替え、
//! `exec::plan` / `exec::isolate` が IPC namespace を作る（`Shareable`・`Private`）か作らない（`Host`）かを決める。
//!
//! # 分離の緩和（セキュリティ）
//!
//! - 既定は [`IpcMode::Private`]（fail-closed）。解釈失敗や未指定から `Host` へ落ちる経路は無い。
//! - `Host` は IPC namespace を作らず、ホストの SysV IPC・POSIX メッセージキューがコンテナから見える。
//!   明示指定のときだけ有効にする。
//!
//! # 未実装の箇所（REPAIR-3）
//!
//! - `Shareable` は現時点では `Private` と同じ分離（専用 IPC namespace）で、「他コンテナが join できる」側
//!   （`container:<id>` の `setns`・ns パス公開・`/dev/shm` の配置）は未実装。`is_shareable` で印を保持するのみ。
//!   core が `linux.namespaces[].path` を未実装としていることに依存する。
//! - `--ipc=container:<id>`・`--ipc=none` は受理しない。
//! - `Host` と `--shm-size` の併用は拒否する（TASK-169.5.2・#856。`ContainerOptions::tmpfs_set` が消費時点で検証）。
//! - 本番 `ProcessLauncher` が未提供のため消費者は無い。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use fandhe_container_core::exec::{Namespace, NamespaceSet};

/// `--ipc` 値の最大バイト数（最長の `shareable` に十分な余裕を持たせた上限）。
const IPC_MODE_MAX_LEN: usize = 32;

/// `--ipc` の指定（SUP-12・TASK-169.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IpcMode {
    /// 指定なしの既定。コンテナ専用の IPC namespace を作る（fail-closed）。
    #[default]
    Private,
    /// ホストの IPC namespace を共有する（IPC namespace を作らない）。
    Host,
    /// コンテナ専用の IPC namespace を作り、他コンテナからの共有対象として印を付ける（join 側は未実装）。
    Shareable,
}

impl IpcMode {
    /// `--ipc` の値を解釈する。受理するのは `host`・`shareable`・`private` の完全一致のみ。
    ///
    /// 空文字・大文字混じり・`none`・`container:<id>`・未知値・長さ超過は `InvalidArgument`。
    pub fn parse(input: &str) -> Result<Self, TraitError> {
        if input.len() > IPC_MODE_MAX_LEN {
            return Err(invalid("ipc mode is too long"));
        }
        match input {
            "host" => Ok(Self::Host),
            "shareable" => Ok(Self::Shareable),
            "private" => Ok(Self::Private),
            _ => Err(invalid("ipc mode must be host, shareable or private")),
        }
    }

    /// ホストの IPC namespace を共有するか（`Host` のみ true）。
    pub fn shares_host_namespace(self) -> bool {
        matches!(self, Self::Host)
    }

    /// 他コンテナからの共有対象として印を付けるか（`Shareable` のみ true）。
    pub fn is_shareable(self) -> bool {
        matches!(self, Self::Shareable)
    }

    /// 分離する namespace 集合へ反映する。`Host` は IPC を外し、それ以外は IPC を含める。
    #[cfg(target_os = "linux")]
    pub fn apply_to(self, base: NamespaceSet) -> NamespaceSet {
        if self.shares_host_namespace() {
            base.without(Namespace::Ipc)
        } else {
            base.with(Namespace::Ipc)
        }
    }
}

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-12・TASK-169.3: 3 値の解釈を具体値で照合する。
    #[test]
    fn sup12_ipc_parse_valid() {
        assert_eq!(IpcMode::parse("host").unwrap(), IpcMode::Host);
        assert_eq!(IpcMode::parse("shareable").unwrap(), IpcMode::Shareable);
        assert_eq!(IpcMode::parse("private").unwrap(), IpcMode::Private);
    }

    /// SUP-12・TASK-169.3: 不正値は固定メッセージの InvalidArgument で拒否し、入力値を含めない。
    #[test]
    fn sup12_ipc_parse_rejects_invalid() {
        let long = "h".repeat(IPC_MODE_MAX_LEN + 1);
        for bad in [
            "",
            "none",
            "container:abc",
            "HOST",
            " host",
            "host ",
            "Shareable",
            long.as_str(),
        ] {
            let e = IpcMode::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad:?}");
            // メッセージは固定文言のみで、入力値をそのまま含めない。
            let msg = e.to_string();
            assert!(
                msg.contains("ipc mode is too long")
                    || msg.contains("ipc mode must be host, shareable or private"),
                "{msg}"
            );
        }
    }

    /// SUP-12・TASK-169.3: 既定は Private で、真理値表が仕様どおり。
    #[test]
    fn sup12_ipc_default_and_predicates() {
        assert_eq!(IpcMode::default(), IpcMode::Private);
        let all = [IpcMode::Private, IpcMode::Host, IpcMode::Shareable];
        assert_eq!(
            all.map(IpcMode::shares_host_namespace),
            [false, true, false]
        );
        assert_eq!(all.map(IpcMode::is_shareable), [false, false, true]);
    }

    /// SUP-12・TASK-169.3: Host は IPC のみを外し、Shareable・Private は IPC を含める。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup12_ipc_apply_to_namespace_set() {
        let others = [
            Namespace::Pid,
            Namespace::Mount,
            Namespace::Uts,
            Namespace::User,
        ];
        let host = IpcMode::Host.apply_to(NamespaceSet::all());
        assert!(!host.contains(Namespace::Ipc));
        for ns in others {
            assert!(host.contains(ns), "{ns:?}");
        }
        for mode in [IpcMode::Shareable, IpcMode::Private] {
            assert!(mode.apply_to(NamespaceSet::all()).contains(Namespace::Ipc));
            let added = mode.apply_to(NamespaceSet::empty().with(Namespace::User));
            assert!(added.contains(Namespace::Ipc));
            assert!(added.contains(Namespace::User));
            assert!(!added.contains(Namespace::Pid));
        }
    }
}
