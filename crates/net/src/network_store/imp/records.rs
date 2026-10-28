//! ネットワークごとの記録（メンバー・意図・`realized`・回収待ちの請求書）の読み書き（NET-1・NET-6・REPAIR-5・#3067）。
//!
//! 役割: `NetworkLockGuard` に、記録ファイルの検査つき読み取りと、一時ファイル → fsync → rename → 親ディレクトリの
//! fsync による原子的な書き込みを足す。符号化は `member`・`realized` と請求書の `to_record`、組み直しは
//! `ipam_rebuild`。呼び出し元は `network::recorded`（記録つきの attach / detach / create / delete）。
//! 検査（0700 / 0600・所有者・nlink 1・`O_NOFOLLOW`・親 fd 起点）は親モジュールの `Dir` が担い、違反は自動修復せず拒否する。
//! 書き込み系はネットワークの排他ロックのガードでだけ許す（共有ロックでは `FailedPrecondition`）。
//! 一時ファイルは `@tmp-` 接頭辞で、読み取りでは無視し、書き込みと `remove` の前に掃除する。
//! 新しい `unsafe` は無い（std の `/proc/self/fd/<fd>/<名前>` 方式のみ）。

use std::io::Write;

use super::*;
use crate::network::{FailedAttachClaim, FailedCreateClaim, StaticIpam};
use crate::network_store::ipam_rebuild::rebuild_ipam;
use crate::network_store::member::{MemberId, MemberIntent, MemberRecord};
use crate::network_store::realized::{RealizedIntent, RealizedRecord};
use crate::network_store::{MAX_MEMBERS_PER_NETWORK, RECORD_MAX_BYTES, ReclaimRecords};

const REALIZED_FILE: &str = "realized";
const REALIZED_INTENT_FILE: &str = "realized.intent";
const MEMBERS_DIR: &str = "members";
const MEMBER_INTENTS_DIR: &str = "members-intent";
const RECLAIM_DIR: &str = "pending-reclaim";
const RECLAIM_CREATE_FILE: &str = "create";
const RECLAIM_ATTACH_DIR: &str = "attach";
const TMP_PREFIX: &str = "@tmp-";
const REC_MAX: u64 = RECORD_MAX_BYTES as u64;
/// 一覧の走査で許す項目数（件数の上限 + 一時ファイルの余裕）。
const LIST_LIMIT: usize = MAX_MEMBERS_PER_NETWORK + 64;

type SyncFn<'a> = &'a dyn Fn(&Dir) -> Result<(), NetError>;

impl Dir {
    fn open_subdir_opt(&self, name: &str) -> Result<Option<Dir>, NetError> {
        match self.open_subdir(name) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.code() == NetErrorCode::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 子ディレクトリを（無ければ 0700 で作って）開く。作ったときは親を fsync する。
    fn ensure_subdir(&self, name: &str) -> Result<Dir, NetError> {
        let msg = "failed to create network record directory";
        match DirBuilder::new().mode(DIR_MODE).create(self.path(name)) {
            Ok(()) => {
                // umask が読み取りビットを落としていても開けるよう、open より先にパスで権限を整える。
                fs::set_permissions(self.path(name), fs::Permissions::from_mode(DIR_MODE))
                    .map_err(|e| map_io(&e, msg))?;
                self.sync()?;
            }
            // 既存の再利用でも、前回の作成後の親 fsync が失敗していた可能性があるため親を同期し直す（D11）。
            Err(e) if e.raw_os_error() == Some(sys::EEXIST) => self.sync()?,
            Err(e) => return Err(map_io(&e, msg)),
        }
        self.open_subdir(name)
    }

    /// 記録ファイルを検査して読む。無ければ `None`。サイズは確保の前に検査する。
    fn read_record(&self, name: &str) -> Result<Option<Vec<u8>>, NetError> {
        let mut f = match self.open_regular_ro(name, REC_MAX) {
            Ok(f) => f,
            Err(e) if e.code() == NetErrorCode::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = usize::try_from(
            f.metadata()
                .map_err(|e| map_io(&e, "failed to stat network record"))?
                .len(),
        )
        .map_err(|_| err(NetErrorCode::DataLoss, "network record is too large"))?;
        let mut buf = Vec::with_capacity(len.min(RECORD_MAX_BYTES));
        (&mut f)
            .take(REC_MAX + 1)
            .read_to_end(&mut buf)
            .map_err(|e| map_io(&e, "failed to read network record"))?;
        if buf.len() != len {
            return Err(err(
                NetErrorCode::DataLoss,
                "network record changed while reading",
            ));
        }
        Ok(Some(buf))
    }

    /// 無いときだけ書く（一時ファイル → fsync → rename → 親の fsync）。あれば `AlreadyExists`。
    ///
    /// 親の fsync が失敗しても記録は残す（呼び出し側が意図記録の扱いを決める）。
    fn write_new(&self, name: &str, bytes: &[u8], sync: SyncFn<'_>) -> Result<(), NetError> {
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(err(
                NetErrorCode::Internal,
                "network record exceeds the size limit",
            ));
        }
        match fs::symlink_metadata(self.path(name)) {
            Ok(_) => {
                return Err(err(
                    NetErrorCode::AlreadyExists,
                    "network record already exists",
                ));
            }
            Err(e) if e.raw_os_error() == Some(sys::ENOENT) => {}
            Err(e) => return Err(map_io(&e, "failed to stat network record")),
        }
        let msg = "failed to write network record";
        let tmp = stage_name(TMP_PREFIX);
        let written = (|| {
            let mut f = self.open_regular(&tmp, true, u64::MAX)?;
            f.write_all(bytes).map_err(|e| map_io(&e, msg))?;
            f.sync_all().map_err(|e| map_io(&e, msg))?;
            fs::rename(self.path(&tmp), self.path(name)).map_err(|e| map_io(&e, msg))
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(self.path(&tmp));
            return Err(e);
        }
        sync(self)
    }

    /// [`write_new`](Self::write_new) の再試行可能版。既に同じ内容の記録があれば（前回は rename 後の親 fsync で
    /// 失敗した可能性があるため）同期だけをやり直して成功とし、内容が違えば `AlreadyExists` を返す（D11）。
    fn write_new_idempotent(
        &self,
        name: &str,
        bytes: &[u8],
        sync: SyncFn<'_>,
    ) -> Result<(), NetError> {
        match self.write_new(name, bytes, sync) {
            Err(e) if e.code() == NetErrorCode::AlreadyExists => match self.read_record(name)? {
                Some(old) if old == bytes => sync(self),
                _ => Err(e),
            },
            other => other,
        }
    }

    /// 消す。無ければ `Ok(false)`。消したら親を fsync する。
    fn remove_record(&self, name: &str, sync: SyncFn<'_>) -> Result<bool, NetError> {
        match fs::remove_file(self.path(name)) {
            Ok(()) => {
                sync(self)?;
                Ok(true)
            }
            Err(e) if e.raw_os_error() == Some(sys::ENOENT) => Ok(false),
            Err(e) => Err(map_io(&e, "failed to remove network record")),
        }
    }

    /// 一時ファイルを除いた項目名（昇順）。件数が上限を超えたら `ResourceExhausted`。
    fn record_names(&self) -> Result<Vec<String>, NetError> {
        let mut names: Vec<String> = self
            .entries(LIST_LIMIT)?
            .into_iter()
            .filter(|n| !n.starts_with(TMP_PREFIX))
            .collect();
        if names.len() > MAX_MEMBERS_PER_NETWORK {
            return Err(err(
                NetErrorCode::ResourceExhausted,
                "too many network records",
            ));
        }
        names.sort();
        Ok(names)
    }

    /// クラッシュの残りの一時ファイルを消す（ベストエフォート。排他ロックの下でだけ呼ぶ）。
    pub(super) fn sweep_tmp(&self) {
        if let Ok(names) = self.entries(LIST_LIMIT) {
            for n in names.into_iter().filter(|n| n.starts_with(TMP_PREFIX)) {
                let _ = fs::remove_file(self.path(&n));
            }
        }
    }
}

/// `remove` が許す「空の既知ディレクトリ」か。一時ファイルは掃除してから数える。
pub(super) fn is_empty_known_dir(net: &Dir, name: &str) -> Result<bool, NetError> {
    let sub = match name {
        MEMBERS_DIR | MEMBER_INTENTS_DIR | RECLAIM_DIR => net.open_subdir(name)?,
        _ => return Ok(false),
    };
    sub.sweep_tmp();
    let items = sub.entries(LIST_LIMIT)?;
    if name != RECLAIM_DIR {
        return Ok(items.is_empty());
    }
    match items.as_slice() {
        [] => Ok(true),
        [only] if only == RECLAIM_ATTACH_DIR => {
            let attach = sub.open_subdir(RECLAIM_ATTACH_DIR)?;
            attach.sweep_tmp();
            Ok(attach.entries(LIST_LIMIT)?.is_empty())
        }
        _ => Ok(false),
    }
}

/// 空になった既知ディレクトリを消す（`remove_tree` から。ベストエフォート）。
pub(super) fn remove_known_dirs(net: &Dir) {
    let _ = fs::remove_dir(net.path(MEMBERS_DIR));
    let _ = fs::remove_dir(net.path(MEMBER_INTENTS_DIR));
    let _ = fs::remove_dir(net.path(&format!("{RECLAIM_DIR}/{RECLAIM_ATTACH_DIR}")));
    let _ = fs::remove_dir(net.path(RECLAIM_DIR));
}

fn data_loss(msg: &'static str) -> NetError {
    err(NetErrorCode::DataLoss, msg)
}

impl NetworkLockGuard<'_> {
    fn require_exclusive(&self) -> Result<(), NetError> {
        if self.exclusive {
            Ok(())
        } else {
            Err(err(
                NetErrorCode::FailedPrecondition,
                "network records need the exclusive network lock",
            ))
        }
    }

    /// 排他ロックのガードか（共有ロックなら偽）。記録つきの操作がカーネル操作の前に確かめる。
    pub(crate) fn is_exclusive(&self) -> bool {
        self.exclusive
    }

    /// ロックしているネットワークの名前。
    pub fn network(&self) -> &NetworkName {
        &self.name
    }

    fn read_realized_file(&self, file: &str) -> Result<Option<Vec<u8>>, NetError> {
        self.dir.read_record(file)
    }

    /// ロック保持中のネットワークの定義を、保持しているディレクトリから読み直す（NET-1・D10・#3067）。
    ///
    /// 定義の取得後、ロックを取る前に同名のネットワークが削除・再作成された窓を塞ぐため、記録つきの create は
    /// 渡された定義をこの値と照合してからカーネル操作へ進む。破損は `DataLoss`。
    pub fn definition(&self) -> Result<NetworkDefinition, NetError> {
        read_definition_in(&self.dir, self.name.as_str())
    }

    /// `realized` を読む。無ければ `None`。名前がこのネットワークと違えば `DataLoss`。
    pub fn realized(&self) -> Result<Option<RealizedRecord>, NetError> {
        let Some(bytes) = self.read_realized_file(REALIZED_FILE)? else {
            return Ok(None);
        };
        let rec = RealizedRecord::decode(&bytes)?;
        if rec.name() != &self.name {
            return Err(data_loss("realized record belongs to another network"));
        }
        Ok(Some(rec))
    }

    /// `realized.intent` を読む。無ければ `None`。残っていれば操作が未完了。
    pub fn realized_intent(&self) -> Result<Option<RealizedIntent>, NetError> {
        let Some(bytes) = self.read_realized_file(REALIZED_INTENT_FILE)? else {
            return Ok(None);
        };
        let rec = RealizedIntent::decode(&bytes)?;
        if rec.name() != &self.name {
            return Err(data_loss("realized intent belongs to another network"));
        }
        Ok(Some(rec))
    }

    /// 確定したメンバー記録を ID 順に読む。1 件でも壊れていれば `DataLoss`（IPAM を組めないため全体を失敗にする）。
    pub fn members(&self) -> Result<Vec<MemberRecord>, NetError> {
        let Some(dir) = self.dir.open_subdir_opt(MEMBERS_DIR)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for n in dir.record_names()? {
            let id = MemberId::new(&n).map_err(|_| data_loss("member record name is invalid"))?;
            let bytes = dir
                .read_record(&n)?
                .ok_or_else(|| data_loss("member record vanished"))?;
            let rec = MemberRecord::decode(&bytes)?;
            if rec.id() != &id {
                return Err(data_loss("member record id does not match its file name"));
            }
            out.push(rec);
        }
        Ok(out)
    }

    /// 意図記録を ID 順に読む。壊れていれば `DataLoss`。
    pub fn member_intents(&self) -> Result<Vec<MemberIntent>, NetError> {
        let Some(dir) = self.dir.open_subdir_opt(MEMBER_INTENTS_DIR)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for n in dir.record_names()? {
            let id = MemberId::new(&n).map_err(|_| data_loss("member intent name is invalid"))?;
            let bytes = dir
                .read_record(&n)?
                .ok_or_else(|| data_loss("member intent vanished"))?;
            let rec = MemberIntent::decode(&bytes)?;
            if rec.id() != &id {
                return Err(data_loss("member intent id does not match its file name"));
            }
            out.push(rec);
        }
        Ok(out)
    }

    /// 記録から静的 IPAM を組み直す（独立したカウンタを持たない。D11）。`realized` が無ければ
    /// `FailedPrecondition`、記録が食い違っていれば `DataLoss`。
    pub fn rebuild_ipam(&self) -> Result<StaticIpam, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreIpamRebuild, || {
            let realized = self.realized()?.ok_or_else(|| {
                err(
                    NetErrorCode::FailedPrecondition,
                    "network has no realized record",
                )
            })?;
            rebuild_ipam(&realized, &self.members()?, &self.member_intents()?)
        })
    }

    /// 意図記録を書く（カーネル操作の前）。同じ ID があれば `AlreadyExists`、件数超過は `ResourceExhausted`。
    /// 親の fsync に失敗したら書いた記録を取り消して失敗を返す（カーネル操作を始めないため）。
    pub fn write_member_intent(&self, intent: &MemberIntent) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreMemberWrite, || {
            self.require_exclusive()?;
            let dir = self.dir.ensure_subdir(MEMBER_INTENTS_DIR)?;
            dir.sweep_tmp();
            if dir.record_names()?.len() >= MAX_MEMBERS_PER_NETWORK {
                return Err(err(
                    NetErrorCode::ResourceExhausted,
                    "too many member intents",
                ));
            }
            let name = intent.id().as_str();
            dir.write_new(name, &intent.encode(), &Dir::sync)
                .inspect_err(|e| {
                    if e.code() != NetErrorCode::AlreadyExists {
                        let _ = fs::remove_file(dir.path(name));
                    }
                })
        })
    }

    /// 確定記録を書き、続けて同じ ID の意図記録を消す（attach の成功後）。
    pub fn commit_member(&self, rec: &MemberRecord) -> Result<(), NetError> {
        self.commit_member_with_sync(rec, &Dir::sync)
    }

    /// [`commit_member`](Self::commit_member) の本体。親の fsync を差し替えられる（同期失敗の試験用）。
    /// 確定記録の永続化を確認できなければ意図記録を消さず失敗を返す（アドレスは使用中のまま残る）。
    fn commit_member_with_sync(
        &self,
        rec: &MemberRecord,
        sync: SyncFn<'_>,
    ) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreMemberWrite, || {
            self.require_exclusive()?;
            let members = self.dir.ensure_subdir(MEMBERS_DIR)?;
            members.sweep_tmp();
            let names = members.record_names()?;
            // 再試行（同じ ID の確定記録が既にある）は件数の上限に数えない。
            if names.len() >= MAX_MEMBERS_PER_NETWORK
                && !names.iter().any(|n| n == rec.id().as_str())
            {
                return Err(err(NetErrorCode::ResourceExhausted, "too many members"));
            }
            members.write_new_idempotent(rec.id().as_str(), &rec.encode(), sync)?;
            if let Some(intents) = self.dir.open_subdir_opt(MEMBER_INTENTS_DIR)? {
                intents.remove_record(rec.id().as_str(), &Dir::sync)?;
            }
            Ok(())
        })
    }

    /// 確定記録を消す（detach の成功後）。無ければ `Ok(false)`。
    pub fn remove_member(&self, id: &MemberId) -> Result<bool, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreMemberRemove, || {
            self.require_exclusive()?;
            match self.dir.open_subdir_opt(MEMBERS_DIR)? {
                Some(d) => d.remove_record(id.as_str(), &Dir::sync),
                None => Ok(false),
            }
        })
    }

    /// 意図記録を消す（attach が失敗して取り残しが無いとき）。無ければ `Ok(false)`。
    pub fn remove_member_intent(&self, id: &MemberId) -> Result<bool, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreMemberRemove, || {
            self.require_exclusive()?;
            match self.dir.open_subdir_opt(MEMBER_INTENTS_DIR)? {
                Some(d) => d.remove_record(id.as_str(), &Dir::sync),
                None => Ok(false),
            }
        })
    }

    /// `realized.intent` を書く（作成・削除のカーネル操作の前）。あれば `AlreadyExists`。
    pub fn write_realized_intent(&self, intent: &RealizedIntent) -> Result<(), NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreRealizedWrite,
            || {
                self.require_exclusive()?;
                self.dir.sweep_tmp();
                self.dir
                    .write_new(REALIZED_INTENT_FILE, &intent.encode(), &Dir::sync)
                    .inspect_err(|e| {
                        if e.code() != NetErrorCode::AlreadyExists {
                            let _ = fs::remove_file(self.dir.path(REALIZED_INTENT_FILE));
                        }
                    })
            },
        )
    }

    /// `realized` を書き、続けて `realized.intent` を消す（作成の成功後）。
    pub fn commit_realized(&self, rec: &RealizedRecord) -> Result<(), NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreRealizedWrite,
            || {
                self.require_exclusive()?;
                self.dir
                    .write_new_idempotent(REALIZED_FILE, &rec.encode(), &Dir::sync)?;
                self.dir.remove_record(REALIZED_INTENT_FILE, &Dir::sync)?;
                Ok(())
            },
        )
    }

    /// `realized` を消し、続けて `realized.intent` を消す（削除の成功後）。
    pub fn remove_realized(&self) -> Result<(), NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreRealizedRemove,
            || {
                self.require_exclusive()?;
                self.dir.remove_record(REALIZED_FILE, &Dir::sync)?;
                self.dir.remove_record(REALIZED_INTENT_FILE, &Dir::sync)?;
                Ok(())
            },
        )
    }

    /// `realized.intent` だけを消す（作成が失敗して `realized` を作っていないとき）。
    pub fn remove_realized_intent(&self) -> Result<bool, NetError> {
        record_net_op(
            &*self.recorder,
            NetOpKind::NetworkStoreRealizedRemove,
            || {
                self.require_exclusive()?;
                self.dir.remove_record(REALIZED_INTENT_FILE, &Dir::sync)
            },
        )
    }

    /// 同じ内容なら成功、違えば `AlreadyExists` で請求書を書く。
    fn save_claim(&self, dir: &Dir, name: &str, record: &str) -> Result<(), NetError> {
        match dir.write_new(name, record.as_bytes(), &Dir::sync) {
            Err(e) if e.code() == NetErrorCode::AlreadyExists => match dir.read_record(name)? {
                // 前回は rename 後の親 fsync で失敗した可能性があるため、同じ内容でも同期をやり直す（D11）。
                Some(old) if old == record.as_bytes() => Dir::sync(dir),
                _ => Err(e),
            },
            other => other,
        }
    }

    /// 作成失敗の請求書を `pending-reclaim/create` に残す。対象のネットワーク名が違えば `InvalidArgument`。
    pub fn save_reclaim_create(&self, claim: &FailedCreateClaim) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreReclaimWrite, || {
            self.require_exclusive()?;
            if claim.network() != &self.name {
                return Err(err(
                    NetErrorCode::InvalidArgument,
                    "claim belongs to another network",
                ));
            }
            let dir = self.dir.ensure_subdir(RECLAIM_DIR)?;
            dir.sweep_tmp();
            self.save_claim(&dir, RECLAIM_CREATE_FILE, &claim.to_record())
        })
    }

    /// attach・切り離し失敗の請求書を `pending-reclaim/attach/<endpoint>` に残す。
    pub fn save_reclaim_attach(&self, claim: &FailedAttachClaim) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreReclaimWrite, || {
            self.require_exclusive()?;
            if claim.network() != &self.name {
                return Err(err(
                    NetErrorCode::InvalidArgument,
                    "claim belongs to another network",
                ));
            }
            let reclaim = self.dir.ensure_subdir(RECLAIM_DIR)?;
            let attach = reclaim.ensure_subdir(RECLAIM_ATTACH_DIR)?;
            attach.sweep_tmp();
            let names = attach.record_names()?;
            // 再試行（同じ endpoint の請求書が既にある）は件数の上限に数えず、内容照合と再同期へ進める（D11）。
            if names.len() >= MAX_MEMBERS_PER_NETWORK
                && !names.iter().any(|n| n == claim.endpoint().as_str())
            {
                return Err(err(
                    NetErrorCode::ResourceExhausted,
                    "too many pending reclaim records",
                ));
            }
            self.save_claim(&attach, claim.endpoint().as_str(), &claim.to_record())
        })
    }

    /// 回収待ちの請求書を読む。壊れた記録は `DataLoss`（回収の根拠にできないため全体を失敗にする）。
    pub fn reclaim_records(&self) -> Result<ReclaimRecords, NetError> {
        let mut out = ReclaimRecords::default();
        let Some(reclaim) = self.dir.open_subdir_opt(RECLAIM_DIR)? else {
            return Ok(out);
        };
        if let Some(bytes) = reclaim.read_record(RECLAIM_CREATE_FILE)? {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| data_loss("reclaim record is not UTF-8"))?;
            let claim = FailedCreateClaim::from_record(text)
                .map_err(|_| data_loss("reclaim record is invalid"))?;
            if claim.network() != &self.name {
                return Err(data_loss("reclaim record belongs to another network"));
            }
            out.create = Some(claim);
        }
        if let Some(attach) = reclaim.open_subdir_opt(RECLAIM_ATTACH_DIR)? {
            for n in attach.record_names()? {
                let bytes = attach
                    .read_record(&n)?
                    .ok_or_else(|| data_loss("reclaim record vanished"))?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| data_loss("reclaim record is not UTF-8"))?;
                let claim = FailedAttachClaim::from_record(text)
                    .map_err(|_| data_loss("reclaim record is invalid"))?;
                if claim.endpoint().as_str() != n || claim.network() != &self.name {
                    return Err(data_loss("reclaim record does not match its file name"));
                }
                out.attach.push(claim);
            }
        }
        Ok(out)
    }

    fn remove_claim_if(
        &self,
        dir: Option<Dir>,
        name: &str,
        record: &str,
    ) -> Result<bool, NetError> {
        let Some(dir) = dir else { return Ok(false) };
        match dir.read_record(name)? {
            Some(cur) if cur == record.as_bytes() => dir.remove_record(name, &Dir::sync),
            _ => Ok(false),
        }
    }

    /// 保存済みの作成失敗の請求書を、内容が一致するときだけ消す（回収の成功後）。
    pub fn remove_reclaim_create_if(&self, claim: &FailedCreateClaim) -> Result<bool, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreReclaimWrite, || {
            self.require_exclusive()?;
            let dir = self.dir.open_subdir_opt(RECLAIM_DIR)?;
            self.remove_claim_if(dir, RECLAIM_CREATE_FILE, &claim.to_record())
        })
    }

    /// 保存済みの attach の請求書を、内容が一致するときだけ消す（回収の成功後）。
    pub fn remove_reclaim_attach_if(&self, claim: &FailedAttachClaim) -> Result<bool, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreReclaimWrite, || {
            self.require_exclusive()?;
            let attach = match self.dir.open_subdir_opt(RECLAIM_DIR)? {
                Some(r) => r.open_subdir_opt(RECLAIM_ATTACH_DIR)?,
                None => None,
            };
            self.remove_claim_if(attach, claim.endpoint().as_str(), &claim.to_record())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etc_hosts::NameResolution;
    use crate::netlink_route::{IfIndex, IpPrefix};
    use crate::network::{CreatedNetwork, EndpointId, NetworkResourceNames};
    use crate::network_store::NetworkDefinition;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    const BRIDGE_TOKEN: &str = "fandhe-net:web:1:0:0";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-netrec-{}-{tag}", stage_name("t")));
            DirBuilder::new().mode(0o700).create(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pfx(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }
    fn nn() -> NetworkName {
        NetworkName::new("web").unwrap()
    }
    fn setup(t: &Tmp) -> NetworkStore {
        let store = NetworkStore::open(&t.0).unwrap();
        store
            .create(&NetworkDefinition::bridge("web", pfx([10, 0, 0, 0], 24)).unwrap())
            .unwrap();
        store
    }
    fn realized_rec() -> RealizedRecord {
        let name = nn();
        let names = NetworkResourceNames::derive(&name).unwrap();
        let c = CreatedNetwork {
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: BRIDGE_TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: pfx([10, 0, 0, 1], 24),
            name_resolution: NameResolution::default(),
            name,
        };
        RealizedRecord::from_created(&c, pfx([10, 0, 0, 0], 24)).unwrap()
    }
    fn token(ep: &str) -> String {
        format!("{BRIDGE_TOKEN}/ep/{ep}/g/00000000000000000000000000000001")
    }
    fn member(id: &str, last: u8) -> MemberRecord {
        MemberRecord::new(
            MemberId::new(id).unwrap(),
            EndpointId::new(id).unwrap(),
            pfx([10, 0, 0, last], 24),
            &token(id),
            Path::new("/run/ns"),
            (8, 9),
            &[],
        )
        .unwrap()
    }
    fn intent(id: &str, last: u8) -> MemberIntent {
        MemberIntent::new(
            MemberId::new(id).unwrap(),
            EndpointId::new(id).unwrap(),
            pfx([10, 0, 0, last], 24),
            &token(id),
        )
        .unwrap()
    }
    fn code<T>(r: Result<T, NetError>) -> NetErrorCode {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.code(),
        }
    }
    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    /// NET-1・#3067: 確定記録は意図記録を置き換え、読み戻せて、0700 / 0600 で作られる。
    #[test]
    fn net1_3067_store_member_intent_commit_remove() {
        let t = Tmp::new("member");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        n.write_member_intent(&intent("c1", 2)).unwrap();
        assert_eq!(n.member_intents().unwrap(), vec![intent("c1", 2)]);
        assert_eq!(
            code(n.write_member_intent(&intent("c1", 2))),
            NetErrorCode::AlreadyExists
        );
        n.commit_member(&member("c1", 2)).unwrap();
        assert_eq!(n.members().unwrap(), vec![member("c1", 2)]);
        assert!(n.member_intents().unwrap().is_empty());
        let base = t.0.join("@networks/web");
        assert_eq!(mode(&base.join("members")), 0o700);
        assert_eq!(mode(&base.join("members/c1")), 0o600);
        assert!(n.remove_member(&MemberId::new("c1").unwrap()).unwrap());
        assert!(!n.remove_member(&MemberId::new("c1").unwrap()).unwrap());
        assert!(n.members().unwrap().is_empty());
    }

    /// 共有ロックでは書けない。
    #[test]
    fn net1_3067_store_shared_lock_cannot_write() {
        let t = Tmp::new("shared");
        let store = setup(&t);
        let g = store.lock_global_shared().unwrap();
        let n = g.lock_network_shared(&nn()).unwrap();
        assert_eq!(
            code(n.write_member_intent(&intent("c1", 2))),
            NetErrorCode::FailedPrecondition
        );
        assert!(n.members().unwrap().is_empty());
    }

    /// 確定記録の親の fsync が失敗したら Internal を返し、意図記録は残る（アドレスは使用中のまま）。
    #[test]
    fn net1_3067_store_commit_sync_failure_keeps_intent() {
        let t = Tmp::new("syncfail");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        n.write_member_intent(&intent("c1", 2)).unwrap();
        let fail = |_: &Dir| Err(err(NetErrorCode::Internal, "injected sync failure"));
        assert_eq!(
            code(n.commit_member_with_sync(&member("c1", 2), &fail)),
            NetErrorCode::Internal
        );
        assert_eq!(n.member_intents().unwrap(), vec![intent("c1", 2)]);
        // 同期の失敗後に同じ内容で再試行すると、同期をやり直して意図記録まで消せる。
        n.commit_member(&member("c1", 2)).unwrap();
        assert!(n.member_intents().unwrap().is_empty());
        assert_eq!(n.members().unwrap(), vec![member("c1", 2)]);
        // 内容が違う確定記録は拒否する。
        assert_eq!(
            code(n.commit_member(&member("c1", 3))),
            NetErrorCode::AlreadyExists
        );
    }

    /// 確定記録 `realized` が残ったまま意図記録も残る状態（同期失敗後）で、同じ内容の再試行が意図記録を消す。
    #[test]
    fn net1_3067_store_commit_realized_is_retryable() {
        let t = Tmp::new("realizedretry");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        let ri = RealizedIntent::new(
            crate::network_store::RealizedOp::Create,
            nn(),
            BRIDGE_TOKEN,
            pfx([10, 0, 0, 0], 24),
        )
        .unwrap();
        n.write_realized_intent(&ri).unwrap();
        n.dir
            .write_new(REALIZED_FILE, &realized_rec().encode(), &Dir::sync)
            .unwrap();
        n.commit_realized(&realized_rec()).unwrap();
        assert_eq!(n.realized_intent().unwrap(), None);
        assert_eq!(n.realized().unwrap(), Some(realized_rec()));
    }

    /// realized と realized.intent の書き込みと、組み直し。
    #[test]
    fn net1_3067_store_realized_and_rebuild() {
        let t = Tmp::new("realized");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        assert_eq!(
            code(n.rebuild_ipam()),
            NetErrorCode::FailedPrecondition,
            "realized が無ければ組み直せない"
        );
        let ri = RealizedIntent::new(
            crate::network_store::RealizedOp::Create,
            nn(),
            BRIDGE_TOKEN,
            pfx([10, 0, 0, 0], 24),
        )
        .unwrap();
        n.write_realized_intent(&ri).unwrap();
        assert_eq!(n.realized_intent().unwrap(), Some(ri));
        n.commit_realized(&realized_rec()).unwrap();
        assert_eq!(n.realized().unwrap(), Some(realized_rec()));
        assert_eq!(n.realized_intent().unwrap(), None);
        n.write_member_intent(&intent("d", 4)).unwrap();
        n.commit_member(&member("a", 2)).unwrap();
        let ipam = n.rebuild_ipam().unwrap();
        assert_eq!(ipam.allocated_count(), 2);
        n.remove_realized().unwrap();
        assert_eq!(n.realized().unwrap(), None);
    }

    /// 権限違反は自動修復せず拒否する。
    #[test]
    fn net1_3067_store_permission_violations_are_rejected() {
        let t = Tmp::new("perm");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        n.commit_member(&member("c1", 2)).unwrap();
        let base = t.0.join("@networks/web");
        // ファイルのハードリンク（nlink 2）。
        fs::hard_link(base.join("members/c1"), base.join("members/c2")).unwrap();
        assert_eq!(code(n.members()), NetErrorCode::FailedPrecondition);
        fs::remove_file(base.join("members/c2")).unwrap();
        // ファイルの権限。
        fs::set_permissions(base.join("members/c1"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(code(n.members()), NetErrorCode::PermissionDenied);
        fs::set_permissions(base.join("members/c1"), fs::Permissions::from_mode(0o600)).unwrap();
        // ディレクトリの権限。
        fs::set_permissions(base.join("members"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(code(n.members()), NetErrorCode::PermissionDenied);
        fs::set_permissions(base.join("members"), fs::Permissions::from_mode(0o700)).unwrap();
        // ディレクトリが symlink。
        fs::rename(base.join("members"), base.join("members.real")).unwrap();
        symlink(base.join("members.real"), base.join("members")).unwrap();
        assert_eq!(code(n.members()), NetErrorCode::FailedPrecondition);
        // ファイル名が ID と一致しない記録は DataLoss。
        fs::remove_file(base.join("members")).unwrap();
        fs::rename(base.join("members.real"), base.join("members")).unwrap();
        fs::rename(base.join("members/c1"), base.join("members/c9")).unwrap();
        assert_eq!(code(n.members()), NetErrorCode::DataLoss);
    }

    /// `remove`: 空の既知ディレクトリだけなら消せる。記録・realized があれば拒否する。
    #[test]
    fn net1_3067_store_remove_requires_no_records() {
        let t = Tmp::new("remove");
        let store = setup(&t);
        {
            let g = store.lock_global_exclusive().unwrap();
            let n = g.lock_network(&nn()).unwrap();
            n.write_member_intent(&intent("c1", 2)).unwrap();
            n.remove_member_intent(&MemberId::new("c1").unwrap())
                .unwrap();
            // 一時ファイルの残りは掃除される。
            fs::write(t.0.join("@networks/web/members-intent/@tmp-leftover"), b"x").unwrap();
        }
        store.remove(&nn()).unwrap();
        assert!(!t.0.join("@networks/web").exists());

        let store2 = setup(&t);
        {
            let g = store2.lock_global_exclusive().unwrap();
            let n = g.lock_network(&nn()).unwrap();
            n.commit_member(&member("c1", 2)).unwrap();
        }
        assert_eq!(code(store2.remove(&nn())), NetErrorCode::FailedPrecondition);
        {
            let g = store2.lock_global_exclusive().unwrap();
            let n = g.lock_network(&nn()).unwrap();
            n.remove_member(&MemberId::new("c1").unwrap()).unwrap();
            n.commit_realized(&realized_rec()).unwrap();
        }
        assert_eq!(code(store2.remove(&nn())), NetErrorCode::FailedPrecondition);
    }

    /// 請求書は保存・読み出し・一致時削除ができ、他のネットワークの請求書は拒否する。
    /// 請求書が上限件数あっても、既存 endpoint の同一内容の再保存は成功する（D11 の冪等な再試行）。
    #[test]
    fn net1_3067_store_reclaim_attach_retry_at_limit() {
        let t = Tmp::new("claim-limit");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        let claim = |i: usize| {
            FailedAttachClaim::for_test(
                nn(),
                EndpointId::new(&format!("c{i}")).unwrap(),
                BRIDGE_TOKEN,
                "00000000000000000000000000000001",
                true,
                false,
                false,
            )
        };
        for i in 0..MAX_MEMBERS_PER_NETWORK {
            n.save_reclaim_attach(&claim(i)).unwrap();
        }
        n.save_reclaim_attach(&claim(0)).unwrap();
        assert_eq!(
            code(n.save_reclaim_attach(&claim(MAX_MEMBERS_PER_NETWORK))),
            NetErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn net1_3067_store_reclaim_claims() {
        let t = Tmp::new("reclaim");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&nn()).unwrap();
        let create = FailedCreateClaim::for_test(nn(), BRIDGE_TOKEN, true, false);
        n.save_reclaim_create(&create).unwrap();
        n.save_reclaim_create(&create).unwrap();
        let other = FailedCreateClaim::for_test(nn(), BRIDGE_TOKEN, true, true);
        assert_eq!(
            code(n.save_reclaim_create(&other)),
            NetErrorCode::AlreadyExists
        );
        let foreign = FailedCreateClaim::for_test(
            NetworkName::new("db").unwrap(),
            "fandhe-net:db:1:0:0",
            true,
            true,
        );
        assert_eq!(
            code(n.save_reclaim_create(&foreign)),
            NetErrorCode::InvalidArgument
        );
        let attach = FailedAttachClaim::for_test(
            nn(),
            EndpointId::new("c1").unwrap(),
            BRIDGE_TOKEN,
            "00000000000000000000000000000001",
            true,
            false,
            false,
        );
        n.save_reclaim_attach(&attach).unwrap();
        let rec = n.reclaim_records().unwrap();
        assert_eq!(rec.create, Some(create.clone()));
        assert_eq!(rec.attach, vec![attach.clone()]);
        assert!(!n.remove_reclaim_create_if(&other).unwrap());
        assert!(n.remove_reclaim_create_if(&create).unwrap());
        assert!(n.remove_reclaim_attach_if(&attach).unwrap());
        assert_eq!(n.reclaim_records().unwrap(), ReclaimRecords::default());
        // 空になった請求書の置き場は remove を妨げない。
        drop(n);
        drop(g);
        store.remove(&nn()).unwrap();
    }
}
