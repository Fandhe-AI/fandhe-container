//! Linux 以外のネットワーク定義ストア（全操作が `Unimplemented`。fail-closed。NET-6・#3059）。
//!
//! 置き場の検査（fd 起点の openat・flock・fstat）が Linux 前提のため、他 OS では何も作らず拒否する。
//! FCNET1 コーデック（`definition`）は OS 非依存で使える。

use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::{NetworkDefinition, NetworkListing};
use crate::dns_helper::record::{DnsHelperIntent, DnsHelperRecord};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::NetOpRecorder;
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

impl NetworkLockGuard<'_> {
    /// 記録先（Linux 以外ではガードを作れないため、記録しない先を返す）。
    pub(crate) fn net_op_recorder(&self) -> &dyn NetOpRecorder {
        &crate::instrument::NoopNetOpRecorder
    }

    /// Linux 以外ではガードを作れないため常に偽（Linux 実装と同じシグネチャ）。
    pub fn is_held(&self) -> bool {
        false
    }

    /// 常に `Unimplemented`（DNS ヘルパーの記録。Linux 実装と同じシグネチャ。NET-7・#3070）。
    pub fn read_dns_helper(&self) -> Result<Option<DnsHelperRecord>, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn write_dns_helper(&self, _rec: &DnsHelperRecord) -> Result<(), NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn remove_dns_helper(&self) -> Result<(), NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`（起動窓の意図記録）。
    pub fn read_dns_helper_intent(&self) -> Result<Option<DnsHelperIntent>, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn write_dns_helper_intent(&self, _rec: &DnsHelperIntent) -> Result<(), NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`（意図記録への同一性の追記。#3344）。
    pub fn replace_dns_helper_intent(&self, _rec: &DnsHelperIntent) -> Result<(), NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`。
    pub fn remove_dns_helper_intent(&self) -> Result<(), NetError> {
        Err(unsupported())
    }
}

impl NetworkStore {
    /// 常に `Unimplemented`。
    pub fn open(_state_root: &Path) -> Result<Self, NetError> {
        Err(unsupported())
    }

    /// 常に `Unimplemented`（記録先は使わない）。
    pub fn open_with_recorder(
        _state_root: &Path,
        _recorder: Arc<dyn NetOpRecorder>,
    ) -> Result<Self, NetError> {
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
