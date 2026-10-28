//! ネットワークのディレクトリに置く DNS ヘルパーの記録（`dns-helper`）と起動窓の意図記録（`dns-helper.intent`）の
//! 読み書き（NET-5・NET-7・REPAIR-2・REPAIR-5・SEC-1・#3070）。
//!
//! # 役割と契約
//! `dns_helper::detach` が、ネットワークの排他ロック（[`NetworkLockGuard`]）を持ったまま呼ぶ。形式は
//! `dns_helper::record` が持ち、ここは置き場の検査（fd 起点・`O_NOFOLLOW`・0600・所有者・nlink 1・通常ファイル）と
//! 永続化（ファイルの fsync の後にディレクトリの fsync）を担う。
//! - 書き込みは新規作成だけ（`create_new`）で、既存の記録を上書きしない。古い記録は停止の経路で消してから書く
//! - 書き込みの途中で失敗したら、中途半端なファイルを消してから失敗を返す（正準形以外を読ませない）
//! - 共有ロックの guard からの書き込み・削除は `FailedPrecondition`（排他の下でしか変えない）
//! - 読み取りは 4096 バイトを上限にし、サイズを検証してから確保する。壊れた記録は `DataLoss` で、自動修復しない
//! - エラー文言に pid・ネットワーク名・アドレスを含めない

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use super::{FILE_MODE, FLAGS_FILE, NetworkLockGuard, err, map_io};
use crate::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, RECORD_MAX_BYTES};
use crate::error::{NetError, NetErrorCode};

/// 起動済みヘルパーの記録のファイル名。
pub const DNS_HELPER_FILE: &str = "dns-helper";
/// 起動窓の意図記録のファイル名。
pub const DNS_HELPER_INTENT_FILE: &str = "dns-helper.intent";

impl NetworkLockGuard<'_> {
    fn require_exclusive(&self) -> Result<(), NetError> {
        if self.shared {
            return Err(err(
                NetErrorCode::FailedPrecondition,
                "network record can be changed only under the exclusive lock",
            ));
        }
        Ok(())
    }

    fn read_record_bytes(&self, name: &str) -> Result<Option<Vec<u8>>, NetError> {
        let f = match self.dir.open_regular_ro(name, RECORD_MAX_BYTES as u64) {
            Ok(f) => f,
            Err(e) if e.code() == NetErrorCode::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut buf = Vec::new();
        f.take(RECORD_MAX_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| map_io(&e, "failed to read network record"))?;
        if buf.len() > RECORD_MAX_BYTES {
            return Err(err(
                NetErrorCode::DataLoss,
                "network record exceeds the size limit",
            ));
        }
        Ok(Some(buf))
    }

    fn write_record_bytes(&self, name: &str, bytes: &[u8]) -> Result<(), NetError> {
        self.require_exclusive()?;
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(err(
                NetErrorCode::InvalidArgument,
                "network record exceeds the size limit",
            ));
        }
        let path = self.dir.path(name);
        let msg = "failed to write network record";
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(FLAGS_FILE)
            .open(&path)
            .map_err(|e| map_io(&e, msg))?;
        let written = f
            .set_permissions(fs::Permissions::from_mode(FILE_MODE))
            .and_then(|()| f.write_all(bytes))
            .and_then(|()| f.sync_all());
        if let Err(e) = written {
            let _ = fs::remove_file(&path);
            return Err(map_io(&e, msg));
        }
        // 名前の永続化。失敗したら記録としては扱えないため消して失敗を返す。
        if let Err(e) = self.dir.sync() {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(())
    }

    fn remove_record(&self, name: &str) -> Result<(), NetError> {
        self.require_exclusive()?;
        match fs::remove_file(self.dir.path(name)) {
            Ok(()) => {}
            // 無いものは消えている（冪等）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(map_io(&e, "failed to remove network record")),
        }
        self.dir.sync()
    }

    /// 起動済みヘルパーの記録を読む。無ければ `None`。壊れていれば `DataLoss`（自動修復しない）。
    pub fn read_dns_helper(&self) -> Result<Option<DnsHelperRecord>, NetError> {
        self.read_record_bytes(DNS_HELPER_FILE)?
            .map(|b| DnsHelperRecord::decode(&b))
            .transpose()
    }

    /// 起動済みヘルパーの記録を新規に書く（fsync まで）。既にあれば `AlreadyExists`。排他ロックの下に限る。
    pub fn write_dns_helper(&self, rec: &DnsHelperRecord) -> Result<(), NetError> {
        self.write_record_bytes(DNS_HELPER_FILE, &rec.encode())
    }

    /// 起動済みヘルパーの記録を消す（無ければ成功）。排他ロックの下に限る。
    pub fn remove_dns_helper(&self) -> Result<(), NetError> {
        self.remove_record(DNS_HELPER_FILE)
    }

    /// 起動窓の意図記録を読む。無ければ `None`。壊れていれば `DataLoss`。
    pub fn read_dns_helper_intent(&self) -> Result<Option<DnsHelperIntent>, NetError> {
        self.read_record_bytes(DNS_HELPER_INTENT_FILE)?
            .map(|b| DnsHelperIntent::decode(&b))
            .transpose()
    }

    /// 起動窓の意図記録を新規に書く（fsync まで）。既にあれば `AlreadyExists`。排他ロックの下に限る。
    pub fn write_dns_helper_intent(&self, rec: &DnsHelperIntent) -> Result<(), NetError> {
        self.write_record_bytes(DNS_HELPER_INTENT_FILE, &rec.encode())
    }

    /// 起動窓の意図記録を消す（無ければ成功）。排他ロックの下に限る。
    pub fn remove_dns_helper_intent(&self) -> Result<(), NetError> {
        self.remove_record(DNS_HELPER_INTENT_FILE)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::fs::MetadataExt as _;

    use super::*;
    use crate::dns_helper::DnsListenAddr;
    use crate::dns_helper::identity::{BootId, ProcessIdentity};
    use crate::dns_helper::record::HelperNonce;
    use crate::network::NetworkName;
    use crate::network_store::{NetworkDefinition, NetworkStore};

    fn rec() -> DnsHelperRecord {
        DnsHelperRecord::new(
            ProcessIdentity {
                pid: 77,
                start_time_ticks: 12345,
                boot_id: BootId::new("0a1b2c3d-4e5f-6789-abcd-ef0123456789").expect("boot"),
            },
            HelperNonce::new("00112233445566778899aabbccddeeff").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        )
        .expect("rec")
    }

    fn intent() -> DnsHelperIntent {
        DnsHelperIntent::new(
            NetworkName::new("web").expect("name"),
            HelperNonce::new("00112233445566778899aabbccddeeff").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        )
    }

    fn store() -> (std::path::PathBuf, NetworkStore) {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-dnsh-store-{}-{}",
            std::process::id(),
            super::super::stage_name("t")
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let st = NetworkStore::open(&dir).expect("open");
        st.create(&NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        (dir, st)
    }

    /// NET-7・REPAIR-2・SEC-1・#3070: 記録は 0600・nlink 1 で作られ、読み戻せ、二重に書けず、消せる。
    #[test]
    fn net7_3070_record_write_read_remove() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        assert_eq!(n.read_dns_helper().expect("read"), None);
        n.write_dns_helper(&rec()).expect("write");
        assert_eq!(n.read_dns_helper().expect("read"), Some(rec()));
        let m = fs::metadata(dir.join("@networks/web/dns-helper")).expect("meta");
        assert_eq!(m.mode() & 0o7777, 0o600);
        assert_eq!(m.nlink(), 1);
        assert_eq!(
            n.write_dns_helper(&rec()).expect_err("twice").code(),
            NetErrorCode::AlreadyExists
        );
        n.write_dns_helper_intent(&intent()).expect("intent");
        assert_eq!(n.read_dns_helper_intent().expect("read"), Some(intent()));
        n.remove_dns_helper().expect("rm");
        n.remove_dns_helper().expect("rm again");
        n.remove_dns_helper_intent().expect("rm intent");
        assert_eq!(n.read_dns_helper().expect("read"), None);
        assert_eq!(n.read_dns_helper_intent().expect("read"), None);
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-7・SEC-1・#3070: 共有ロックからは書き込み・削除ができない。
    #[test]
    fn net7_3070_shared_lock_cannot_change_records() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let g = st.lock_global_shared().expect("global");
        let n = g.lock_network_shared(&name).expect("net");
        assert_eq!(
            n.write_dns_helper(&rec()).expect_err("write").code(),
            NetErrorCode::FailedPrecondition
        );
        assert_eq!(
            n.remove_dns_helper().expect_err("rm").code(),
            NetErrorCode::FailedPrecondition
        );
        assert_eq!(n.read_dns_helper().expect("read"), None);
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-7・SEC-1・#3070: 権限違反・symlink・ハードリンク・壊れた中身は fail-closed で、自動修復しない。
    #[test]
    fn net7_3070_record_fail_closed() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let path = dir.join("@networks/web/dns-helper");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        // 0644
        fs::write(&path, rec().encode()).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            n.read_dns_helper().expect_err("mode").code(),
            NetErrorCode::PermissionDenied
        );
        // 壊れた中身
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::write(&path, b"garbage").expect("write");
        assert_eq!(
            n.read_dns_helper().expect_err("garbage").code(),
            NetErrorCode::DataLoss
        );
        // ハードリンク
        fs::write(&path, rec().encode()).expect("write");
        fs::hard_link(&path, dir.join("link")).expect("link");
        assert_eq!(
            n.read_dns_helper().expect_err("nlink").code(),
            NetErrorCode::FailedPrecondition
        );
        fs::remove_file(dir.join("link")).expect("rm link");
        // symlink
        fs::remove_file(&path).expect("rm");
        fs::write(dir.join("target"), rec().encode()).expect("target");
        std::os::unix::fs::symlink(dir.join("target"), &path).expect("symlink");
        assert!(n.read_dns_helper().is_err());
        fs::remove_file(&path).expect("rm symlink");
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-6・#3070: 記録が残っているネットワークは `remove` が拒否する（誤って消さない）。
    #[test]
    fn net7_3070_remove_refuses_while_record_exists() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        {
            let g = st.lock_global_exclusive().expect("global");
            let n = g.lock_network(&name).expect("net");
            n.write_dns_helper(&rec()).expect("write");
        }
        assert_eq!(
            st.remove(&name).expect_err("remove").code(),
            NetErrorCode::FailedPrecondition
        );
        {
            let g = st.lock_global_exclusive().expect("global");
            let n = g.lock_network(&name).expect("net");
            n.remove_dns_helper().expect("rm");
        }
        st.remove(&name).expect("remove after record is gone");
        let _ = fs::remove_dir_all(dir);
    }
}
