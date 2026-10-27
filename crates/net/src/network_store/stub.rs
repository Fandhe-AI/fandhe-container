//! Linux 以外のネットワーク定義ストア（全操作が `Unimplemented`。fail-closed。NET-6・#3059）。
//!
//! 置き場の検査（fd 起点の openat・flock・fstat）が Linux 前提のため、他 OS では何も作らず拒否する。
//! FCNET1 コーデック（`definition`）は OS 非依存で使える。

use std::marker::PhantomData;
use std::path::Path;
use std::time::Duration;

use super::{NetworkDefinition, NetworkListing};
use crate::error::{NetError, NetErrorCode};
use crate::network::NetworkName;

fn unsupported() -> NetError {
    NetError::new(
        NetErrorCode::Unimplemented,
        "network store is supported only on Linux",
    )
}

/// ネットワーク定義ストア（Linux 以外では開けない）。
#[derive(Debug)]
pub struct NetworkStore {
    _private: (),
}

/// 全体のロックのガード（Linux 以外では作れない）。
#[derive(Debug)]
pub struct GlobalLockGuard<'a> {
    _store: PhantomData<&'a NetworkStore>,
}

/// ネットワークのロックのガード（Linux 以外では作れない）。
#[derive(Debug)]
pub struct NetworkLockGuard<'g> {
    _global: PhantomData<&'g ()>,
}

impl NetworkStore {
    /// 常に `Unimplemented`。
    pub fn open(_state_root: &Path) -> Result<Self, NetError> {
        Err(unsupported())
    }

    /// ロック待ちの期限を差し替える（試験用）。
    pub fn with_lock_timeout(self, _timeout: Duration) -> Self {
        self
    }

    /// 常に `Unimplemented`。
    pub fn lock_global_shared(&self) -> Result<GlobalLockGuard<'_>, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn lock_global_exclusive(&self) -> Result<GlobalLockGuard<'_>, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn create(&self, _def: &NetworkDefinition) -> Result<(), NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn get(&self, _name: &NetworkName) -> Result<NetworkDefinition, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn list(&self) -> Result<NetworkListing, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn remove(&self, _name: &NetworkName) -> Result<(), NetError> {
        Err(unsupported())
    }
}

impl GlobalLockGuard<'_> {
    /// 常に `Unimplemented`。
    pub fn lock_network(&self, _name: &NetworkName) -> Result<NetworkLockGuard<'_>, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn lock_network_shared(
        &self,
        _name: &NetworkName,
    ) -> Result<NetworkLockGuard<'_>, NetError> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net6_3059_open_is_unimplemented_off_linux() {
        let e = NetworkStore::open(Path::new("/nonexistent")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Unimplemented);
    }
}
