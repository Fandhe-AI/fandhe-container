//! ネットワークのディレクトリに置く DNS ヘルパーの記録（`dns-helper`）と起動窓の意図記録（`dns-helper.intent`）の
//! 読み書き（NET-5・NET-7・REPAIR-2・REPAIR-5・SEC-1・#3070）。
//!
//! # 役割と契約
//! `dns_helper::detach` が、ネットワークの排他ロック（[`NetworkLockGuard`]）を持ったまま呼ぶ。形式は
//! `dns_helper::record` が持ち、ここは置き場の検査（fd 起点・`O_NOFOLLOW`・0600・所有者・nlink 1・通常ファイル）と
//! 永続化（ファイルの fsync の後にディレクトリの fsync）を担う。
//! - 書き込みは一時名（`<名前>.tmp`）へ完全に書いて fsync した後、上書き禁止の `link(2)` で最終名へ公開する。
//!   既存の記録は上書きしない（`AlreadyExists`）。起動元が SIGKILL されても最終名には空・不完全な内容が現れず、
//!   残った一時名は排他ロックを持つ次の操作（読み取り・書き込み・ネットワーク削除）が回収する。
//!   唯一の例外が意図記録の置き換え（`replace_dns_helper_intent`。#3344）で、識別行の照合後に同一性を足すため、
//!   同じ一時名へ書いて fsync し `rename(2)` で原子的に置き換える（消してから書くと nonce を失う窓ができる）
//! - 共有ロックの guard からの書き込み・削除は `FailedPrecondition`（排他の下でしか変えない）
//! - 読み取りは 4096 バイトを上限にし、サイズを検証してから確保する。壊れた記録は `DataLoss` で、自動修復しない
//! - エラー文言に pid・ネットワーク名・アドレスを含めない

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use super::{FILE_MODE, FLAGS_FILE, NetworkLockGuard, err, map_io};
use crate::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, RECORD_MAX_BYTES};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, record_net_op};

/// 起動済みヘルパーの記録のファイル名。
pub const DNS_HELPER_FILE: &str = "dns-helper";
/// 起動窓の意図記録のファイル名。
pub const DNS_HELPER_INTENT_FILE: &str = "dns-helper.intent";

/// 記録の書き込みに使う一時名（記録ごとに固定。排他ロックの下でだけ作る）。
fn temp_name(name: &str) -> String {
    format!("{name}.tmp")
}

impl NetworkLockGuard<'_> {
    /// 書き込み途中で起動元が中断されて残った一時ファイルを消す（排他ロックの下だけ。共有では何もしない）。
    ///
    /// 一時名は記録ごとに固定で、排他ロックの下では同時に書く者がいないため、残っていれば必ず中断の残骸。
    /// 最終名へ公開する前に fsync 済みなので、最終名は常に完全な内容で、一時名の側だけを捨てればよい
    /// （公開後・一時名の削除前の中断では最終名の nlink が 2 になるため、ここで 1 に戻す）。
    pub(crate) fn discard_stale_temps(&self) -> Result<(), NetError> {
        if !self.exclusive {
            return Ok(());
        }
        let mut removed = false;
        for name in [DNS_HELPER_FILE, DNS_HELPER_INTENT_FILE] {
            match fs::remove_file(self.dir.path(&temp_name(name))) {
                Ok(()) => removed = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_io(&e, "failed to remove stale network record")),
            }
        }
        if removed {
            self.dir.sync()?;
        }
        Ok(())
    }

    /// 記録を読む。読み取り経路は副作用を持たない（一時ファイルの掃除は排他ロックの書き込み経路だけが行う）。
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

    /// 一時名へ完全に書いて fsync し、上書き禁止の `link(2)` で最終名として公開する。公開の途中で中断されても
    /// 最終名には空・不完全な内容が現れない（残るのは一時名だけで、[`discard_stale_temps`] が回収する）。
    fn write_record_bytes(&self, name: &str, bytes: &[u8]) -> Result<(), NetError> {
        self.require_exclusive()?;
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(err(
                NetErrorCode::InvalidArgument,
                "network record exceeds the size limit",
            ));
        }
        self.discard_stale_temps()?;
        let final_path = self.dir.path(name);
        let tmp_path = self.dir.path(&temp_name(name));
        let msg = "failed to write network record";
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(FLAGS_FILE)
            .open(&tmp_path)
            .map_err(|e| map_io(&e, msg))?;
        let written = f
            .set_permissions(fs::Permissions::from_mode(FILE_MODE))
            .and_then(|()| f.write_all(bytes))
            .and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp_path);
            return Err(map_io(&e, msg));
        }
        // 上書き禁止の公開。最終名が既にあれば AlreadyExists。
        let linked = fs::hard_link(&tmp_path, &final_path);
        let _ = fs::remove_file(&tmp_path);
        if let Err(e) = linked {
            return Err(map_io(&e, msg));
        }
        // 名前の永続化。失敗したら記録としては扱えないため消して失敗を返す。
        if let Err(e) = self.dir.sync() {
            let _ = fs::remove_file(&final_path);
            return Err(e);
        }
        Ok(())
    }

    /// 既存の記録を、一時名へ完全に書いて fsync した後の `rename(2)` で原子的に置き換える（#3344）。
    /// 途中で中断されても、最終名には古い内容か新しい内容のどちらかが完全に残る。一時名は固定名のままなので
    /// [`discard_stale_temps`] が残骸を回収する。
    fn replace_record_bytes(&self, name: &str, bytes: &[u8]) -> Result<(), NetError> {
        self.require_exclusive()?;
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(err(
                NetErrorCode::InvalidArgument,
                "network record exceeds the size limit",
            ));
        }
        self.discard_stale_temps()?;
        let final_path = self.dir.path(name);
        let tmp_path = self.dir.path(&temp_name(name));
        let msg = "failed to replace network record";
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(FLAGS_FILE)
            .open(&tmp_path)
            .map_err(|e| map_io(&e, msg))?;
        let written = f
            .set_permissions(fs::Permissions::from_mode(FILE_MODE))
            .and_then(|()| f.write_all(bytes))
            .and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp_path);
            return Err(map_io(&e, msg));
        }
        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(map_io(&e, msg));
        }
        // 置き換え後の名前の永続化。失敗しても古い内容か新しい内容のどちらかが完全に残るので消さずに返す。
        self.dir.sync()
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
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreDnsHelperWrite,
            || self.write_record_bytes(DNS_HELPER_FILE, &rec.encode()),
        )
    }

    /// 起動済みヘルパーの記録を消す（無ければ成功）。排他ロックの下に限る。
    pub fn remove_dns_helper(&self) -> Result<(), NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreDnsHelperRemove,
            || self.remove_record(DNS_HELPER_FILE),
        )
    }

    /// 起動窓の意図記録を読む。無ければ `None`。壊れていれば `DataLoss`。
    /// 記録のネットワーク名がこのロックの対象と違えば `DataLoss`（別ネットワークの nonce を採用させない。fail-closed）。
    pub fn read_dns_helper_intent(&self) -> Result<Option<DnsHelperIntent>, NetError> {
        let Some(rec) = self
            .read_record_bytes(DNS_HELPER_INTENT_FILE)?
            .map(|b| DnsHelperIntent::decode(&b))
            .transpose()?
        else {
            return Ok(None);
        };
        if rec.network() != &self.name {
            return Err(err(
                NetErrorCode::DataLoss,
                "dns helper intent record belongs to a different network",
            ));
        }
        Ok(Some(rec))
    }

    /// 起動窓の意図記録を新規に書く（fsync まで）。既にあれば `AlreadyExists`。排他ロックの下に限る。
    /// 記録のネットワーク名がロック対象と違えば、何も書かず `InvalidArgument`。
    pub fn write_dns_helper_intent(&self, rec: &DnsHelperIntent) -> Result<(), NetError> {
        if rec.network() != &self.name {
            return Err(err(
                NetErrorCode::InvalidArgument,
                "dns helper intent record names a different network",
            ));
        }
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreDnsHelperWrite,
            || self.write_record_bytes(DNS_HELPER_INTENT_FILE, &rec.encode()),
        )
    }

    /// 既存の意図記録を、同一性つきの記録へ原子的に置き換える（#3344。識別行の照合後、`dns-helper` を書く前）。
    /// 排他ロックの下に限る。意図記録が無ければ `NotFound`、ネットワーク名が違えば `InvalidArgument`、
    /// nonce・待受アドレスが既存と違えば（別の起動の記録）何も書かず `FailedPrecondition`。
    pub fn replace_dns_helper_intent(&self, rec: &DnsHelperIntent) -> Result<(), NetError> {
        self.require_exclusive()?;
        if rec.network() != &self.name {
            return Err(err(
                NetErrorCode::InvalidArgument,
                "dns helper intent record names a different network",
            ));
        }
        let Some(cur) = self.read_dns_helper_intent()? else {
            return Err(err(
                NetErrorCode::NotFound,
                "dns helper intent record does not exist",
            ));
        };
        if cur.nonce() != rec.nonce() || cur.listen() != rec.listen() {
            return Err(err(
                NetErrorCode::FailedPrecondition,
                "dns helper intent record belongs to a different launch",
            ));
        }
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreDnsHelperWrite,
            || self.replace_record_bytes(DNS_HELPER_INTENT_FILE, &rec.encode()),
        )
    }

    /// 起動窓の意図記録を消す（無ければ成功）。排他ロックの下に限る。
    pub fn remove_dns_helper_intent(&self) -> Result<(), NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreDnsHelperRemove,
            || self.remove_record(DNS_HELPER_INTENT_FILE),
        )
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

    /// NET-7・REPAIR-5・#3070: 書き込み途中で中断され一時名だけが残っても、最終名は現れず、
    /// 公開後・一時名の削除前の中断（nlink 2）の記録が残っていても、`discard_stale_temps` の後なら読める。
    /// 回収前の読み取りは `FailedPrecondition`（open_regular_ro の検査）。
    #[test]
    fn net7_3070_nlink2_record_recovers_after_discard() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let net = dir.join("@networks/web");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        n.write_dns_helper_intent(&intent()).expect("write");
        fs::hard_link(
            net.join("dns-helper.intent"),
            net.join("dns-helper.intent.tmp"),
        )
        .expect("link");
        assert!(n.read_dns_helper_intent().is_err());
        n.discard_stale_temps().expect("discard");
        assert_eq!(n.read_dns_helper_intent().expect("read"), Some(intent()));
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// 排他ロックの書き込み経路が一時名を回収して書き直せる。公開後の一時名の取り残し（nlink 2）も戻る。
    #[test]
    fn net7_3070_stale_temp_is_recovered() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let net = dir.join("@networks/web");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        // 空の一時ファイル（作成直後の中断）。
        fs::write(net.join("dns-helper.tmp"), b"").expect("tmp");
        // 読み取り経路は副作用を持たない（一時名を消さない）。回収は排他ロックの書き込み経路が行う。
        assert_eq!(n.read_dns_helper().expect("read"), None);
        assert!(net.join("dns-helper.tmp").exists());
        n.discard_stale_temps().expect("discard");
        assert!(!net.join("dns-helper.tmp").exists());
        fs::write(net.join("dns-helper.intent.tmp"), b"part").expect("tmp");
        n.write_dns_helper_intent(&intent()).expect("write");
        assert_eq!(n.read_dns_helper_intent().expect("read"), Some(intent()));
        // 公開後・一時名の削除前の中断（最終名の nlink が 2）。
        fs::hard_link(
            net.join("dns-helper.intent"),
            net.join("dns-helper.intent.tmp"),
        )
        .expect("link");
        n.discard_stale_temps().expect("discard");
        assert_eq!(n.read_dns_helper_intent().expect("read"), Some(intent()));
        assert_eq!(
            fs::metadata(net.join("dns-helper.intent"))
                .expect("meta")
                .nlink(),
            1
        );
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-5・NET-7・SEC-1: 意図記録のネットワーク名がロック対象と違えば、読み取りは `DataLoss`、書き込みは
    /// `InvalidArgument`（別ネットワークの nonce を採用させない。fail-closed）。
    #[test]
    fn net7_3070_intent_network_mismatch_is_rejected() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let other = DnsHelperIntent::new(
            NetworkName::new("other").expect("name"),
            HelperNonce::new("00112233445566778899aabbccddeeff").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        );
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        assert_eq!(
            n.write_dns_helper_intent(&other).expect_err("write").code(),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(n.read_dns_helper_intent().expect("read"), None);
        // 別ネットワーク名の記録がディスクに置かれていた場合。
        n.write_record_bytes(DNS_HELPER_INTENT_FILE, &other.encode())
            .expect("plant");
        assert_eq!(
            n.read_dns_helper_intent().expect_err("read").code(),
            NetErrorCode::DataLoss
        );
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-5・NET-7・REPAIR-4: 記録の書き込み・削除と回収は `record_net_op` を通り、種別と結果が具体値で記録される。
    #[test]
    fn net7_3070_record_ops_and_recovery_are_instrumented() {
        use crate::dns_helper::detach::{IntentRecovery, recover_dns_helper_intent};
        use crate::instrument::NetOpOutcome;
        use crate::instrument::testing::Collect;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!(
            "fandhe-dnsh-store-{}-{}",
            std::process::id(),
            super::super::stage_name("i")
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let col = Arc::new(Collect::default());
        let st = NetworkStore::open_with_recorder(&dir, col.clone()).expect("open");
        st.create(&NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        let name = NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        let before = col.kinds().len();
        n.write_dns_helper_intent(&intent()).expect("write");
        let r = recover_dns_helper_intent(&n, &mut std::iter::empty(), &*col).expect("recover");
        assert_eq!(r, IntentRecovery::Recovered { stopped: 0 });
        let got: Vec<_> = col.kinds().into_iter().skip(before).collect();
        assert_eq!(
            got,
            vec![
                (NetOpKind::NetworkStoreDnsHelperWrite, NetOpOutcome::Success),
                (
                    NetOpKind::NetworkStoreDnsHelperRemove,
                    NetOpOutcome::Success
                ),
                (NetOpKind::DnsHelperRecover, NetOpOutcome::Success),
            ]
        );
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-5・NET-7: 確定記録の nonce が意図記録と違えば「記録が正」とはせず、意図記録の nonce で候補を調べる
    /// （候補なしなら意図記録だけ消え、確定記録のヘルパーの記録は残る）。
    #[test]
    fn net7_3070_recovery_ignores_record_with_different_nonce() {
        use crate::dns_helper::detach::{IntentRecovery, recover_dns_helper_intent};
        use crate::instrument::NoopNetOpRecorder;

        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        let other_nonce = DnsHelperIntent::new(
            name.clone(),
            HelperNonce::new("ffeeddccbbaa99887766554433221100").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        );
        n.write_dns_helper(&rec()).expect("record");
        n.write_dns_helper_intent(&other_nonce).expect("intent");
        let r = recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
            .expect("recover");
        assert_eq!(r, IntentRecovery::Recovered { stopped: 0 });
        assert_eq!(n.read_dns_helper().expect("read"), Some(rec()));
        assert_eq!(n.read_dns_helper_intent().expect("read"), None);
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// REPAIR-5・NET-5: 回収前に終了してゾンビになった自分の子の候補は、回収されたうえで意図記録が消える。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net7_3070_recovery_reaps_zombie_candidate() {
        use crate::dns_helper::detach::{IntentRecovery, recover_dns_helper_intent};
        use crate::instrument::NoopNetOpRecorder;
        use std::process::{Command, Stdio};

        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        n.write_dns_helper_intent(&intent()).expect("intent");
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let pid = child.id();
        child.kill().expect("kill");
        let stat = format!("/proc/{pid}/stat");
        let t = std::time::Instant::now();
        while std::fs::read_to_string(&stat).is_ok_and(|s| {
            !s.rsplit_once(')')
                .is_some_and(|(_, r)| r.trim_start().starts_with('Z'))
        }) {
            assert!(t.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(std::path::Path::new(&stat).exists(), "zombie before");
        let r = recover_dns_helper_intent(&n, &mut std::iter::once(pid), &NoopNetOpRecorder)
            .expect("recover");
        assert_eq!(r, IntentRecovery::Recovered { stopped: 0 });
        assert!(!std::path::Path::new(&stat).exists(), "zombie reaped");
        assert_eq!(n.read_dns_helper_intent().expect("read"), None);
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-7・REPAIR-2・SEC-1・#3344: 意図記録は同一性つきに原子的に置き換わり、0600・nlink 1 のまま。
    /// 無ければ `NotFound`、別の起動（nonce・listen 違い）と共有ロックは拒否して元の記録を残す。
    #[test]
    fn net7_3344_replace_intent_adds_identity() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        let id = ProcessIdentity {
            pid: 77,
            start_time_ticks: 12345,
            boot_id: BootId::new("0a1b2c3d-4e5f-6789-abcd-ef0123456789").expect("boot"),
        };
        let upgraded = intent().with_identity(id.clone()).expect("id");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        assert_eq!(
            n.replace_dns_helper_intent(&upgraded)
                .expect_err("none")
                .code(),
            NetErrorCode::NotFound
        );
        n.write_dns_helper_intent(&intent()).expect("intent");
        let other_nonce = DnsHelperIntent::new(
            name.clone(),
            HelperNonce::new("ffeeddccbbaa99887766554433221100").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        );
        let other_listen = DnsHelperIntent::new(
            name.clone(),
            HelperNonce::new("00112233445566778899aabbccddeeff").expect("nonce"),
            DnsListenAddr::new(Ipv4Addr::LOCALHOST, 5354).expect("listen"),
        );
        for bad in [other_nonce, other_listen] {
            assert_eq!(
                n.replace_dns_helper_intent(&bad)
                    .expect_err("mismatch")
                    .code(),
                NetErrorCode::FailedPrecondition
            );
            assert_eq!(n.read_dns_helper_intent().expect("read"), Some(intent()));
        }
        n.replace_dns_helper_intent(&upgraded).expect("replace");
        assert_eq!(n.read_dns_helper_intent().expect("read"), Some(upgraded));
        let p = dir.join("@networks/web/dns-helper.intent");
        let m = fs::metadata(&p).expect("meta");
        assert_eq!(m.mode() & 0o7777, 0o600);
        assert_eq!(m.nlink(), 1);
        assert!(!dir.join("@networks/web/dns-helper.intent.tmp").exists());
        // 一時名の残骸は次の排他操作が回収する。
        fs::write(dir.join("@networks/web/dns-helper.intent.tmp"), b"junk").expect("junk");
        n.replace_dns_helper_intent(&intent().with_identity(id).expect("id"))
            .expect("replace again");
        assert!(!dir.join("@networks/web/dns-helper.intent.tmp").exists());
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }

    /// NET-7・SEC-1・#3344: 共有ロックからは意図記録を置き換えられない。
    #[test]
    fn net7_3344_replace_intent_requires_exclusive() {
        let (dir, st) = store();
        let name = NetworkName::new("web").expect("name");
        {
            let g = st.lock_global_exclusive().expect("global");
            let n = g.lock_network(&name).expect("net");
            n.write_dns_helper_intent(&intent()).expect("intent");
        }
        let g = st.lock_global_shared().expect("global");
        let n = g.lock_network_shared(&name).expect("net");
        assert_eq!(
            n.replace_dns_helper_intent(&intent())
                .expect_err("shared")
                .code(),
            NetErrorCode::FailedPrecondition
        );
        drop(n);
        drop(g);
        let _ = fs::remove_dir_all(dir);
    }
}
