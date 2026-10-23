//! rootless の ID 写像モデル（1 対 1 か `/etc/subuid`・`/etc/subgid` の範囲写像か）を選ぶ純ロジック
//! （CORE-6・SEC-5・#2243。TASK-157）。
//!
//! # 役割
//! `start_entry` の本番 `StartDeps`（Linux 限定）が `/etc/subuid`・`/etc/subgid`・`/etc/passwd` を読んだ結果を受け、
//! core の本番 launcher へ `RootlessSingleId` と `RootlessSubordinateIds` のどちらを渡すかを決める。
//! ファイル I/O と core の型への写しは Linux 側が行い、本モジュールは OS に依らず 3 OS の CI で具体値照合できる。
//!
//! # 選択規則（subuid / subgid 各ファイルを個別に分類して 2 つ組で判定する）
//!
//! | subuid | subgid | 判定 |
//! | ---- | ---- | ---- |
//! | 所有者の行あり | 所有者の行あり | 範囲写像（`SubordinateIds`） |
//! | 無い（ファイル無し / 行無し） | 無い（同） | 1 対 1 写像（`SingleId`。設定の無いホストの従来挙動） |
//! | 片方だけ行あり | — | `FailedPrecondition`（単一 ID へ黙って縮退しない） |
//! | どちらかが読めない・解析不正 | — | `FailedPrecondition`（fail-closed） |
//!
//! - 範囲があるのに helper（`newuidmap` / `newgidmap`）が無い・検証に通らない場合は、core の launcher 構築が失敗する。
//!   helper が無いことを理由に `SingleId` へ縮退しない（設定が範囲写像の意図を示しているため）。
//! - real uid と effective uid が食い違う場合の範囲写像は拒否する（`newuidmap` は real uid で所有者を確かめる）。
//!
//! # 所有者名（passwd 優先・無ければ NSS）
//! `/etc/subuid` の第 1 欄は多くがユーザー名のため、`/etc/passwd` を上限つきで直接読み、uid 欄が実効 uid と一致する
//! 最初の行の第 1 欄を名前にする（[`owner_name_from_passwd`]）。環境変数 `USER` は信頼しない（CLI が起動時に消す。
//! 利用者が書き換えられる入力でもある）。argv で渡す案・数値 uid だけで照合する案は採らない。
//! `/etc/passwd` に行が無い（LDAP / sssd 等）ときだけ、`user_db::resolve_owner_name` が固定パスの `getent` を
//! 期限つきで実行して NSS の名前を得る（`newuidmap` が NSS で呼び出し元を解決するのに合わせる。#2390）。
//! NSS の参照失敗・期限切れ・不正な出力は fail-closed（黙って 1 対 1 へ落とさない）。信頼できる `getent` が無いときは
//! 名前なしで数値 uid の行だけで照合する（`doctor` が通知する）。ただし、そのとき選ばれるモデルが 1 対 1 で、
//! subuid / subgid に**名前の行**（第 1 欄が `u32` でない行）があれば、自分の行か判定できないため拒否する
//! （`RefusalReason::OwnerUndetermined`。数値行だけ・ファイル無しなら従来どおり。#2545）。
//! `/etc/nsswitch.conf` の `subid:` が `files` 以外（範囲を NSS から配る構成）は、ファイルを読む方式では範囲を得られない
//! ため拒否する（`SubidFromNameService`。読めない・書式不正は `NsswitchUnusable`。#2545）。
//!
//! # doctor との共用
//! 設定ファイルの既定位置（`SYSTEM_*`）・passwd の読み取り（`read_owner_name`）・subuid / subgid の分類
//! （`probe_sub_id_file`）は Linux 限定で公開し、`start`（`start_entry` の `resolve_launch_privilege`）と
//! pull 時の展開の所有者（cli の `image_ownership`。`resolve_rootless_id_source`。#2389）と
//! CLI の `doctor`（`doctor::id_mapping_check`。#2387）が同じ関数を呼ぶ。診断と `start` の判定を食い違わせない。
//! 判定の本体は型つきの拒否理由を返す `diagnose_rootless_id_source_with` で、`resolve_rootless_id_source*` は
//! その結果を `TraitError` と範囲写像の入力元へ写す薄い包みである（`doctor` は文字列比較をせず `RefusalReason` で分岐する。#2545）。
//!
//! エラー文言は固定の英語で、ユーザー名・パス・errno・ファイルの内容を含めない。

use fandhe_container_core::traits::{ErrorCode, TraitError};

use crate::user_db::OwnerLookupFailure;

/// `/etc/passwd` の読み取り上限（バイト）。外部入力のため先に検証する。
pub const MAX_PASSWD_BYTES: u64 = 1024 * 1024;
/// `/etc/passwd` の行数の上限。
pub const MAX_PASSWD_LINES: usize = 10_000;

/// subuid / subgid 1 ファイルの読み取り結果の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubIdFileProbe {
    /// ファイルが無い（ENOENT）。
    Absent,
    /// 読めたが所有者の行が無い。
    NoOwnerRows,
    /// 所有者の行が 1 件以上ある。
    Assigned,
    /// 読めない・解析できない・上限超過（内容は問わず fail-closed）。
    Unusable,
}

/// 選んだ rootless の ID 写像モデル（拡張できるよう列挙にする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootlessIdModel {
    /// コンテナ 0 → 実効 uid / gid の 1 対 1。
    SingleId,
    /// コンテナ 0 → 実効 uid / gid、1.. → subordinate 範囲（`newuidmap` / `newgidmap`）。
    SubordinateIds,
}

/// 所有者名の出所の種別（`diagnose_rootless_id_source_with` の結果。名前そのものは持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerNameKind {
    /// passwd または NSS で名前を得た。
    Resolved,
    /// passwd にも NSS にも行が無い（NSS が不在を確定した）。
    NotFound,
    /// passwd に行が無く、信頼できる `getent` も無い。
    LookupUnavailable,
}

/// 拒否の理由（`doctor` が `start` と同じ分類をするための型。固定文言は [`RootlessIdRefusal::to_trait_error`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalReason {
    /// 所有者名の解決の失敗。
    Owner(OwnerLookupFailure),
    /// 名前が `SubIdOwner` の規則に違反する。
    OwnerNameInvalid,
    /// 名前を引けず（`LookupUnavailable`）、名前の行が自分のものか判定できない（#2545）。
    OwnerUndetermined,
    /// `nsswitch.conf` の `subid:` が `files` 以外（#2545）。
    SubidFromNameService,
    /// `nsswitch.conf` が読めない・書式不正（#2545）。
    NsswitchUnusable,
    /// subuid / subgid が読めない・解析できない。
    SubIdUnreadable,
    /// subuid だけに自分の行がある。
    IncompleteSubuidOnly,
    /// subgid だけに自分の行がある。
    IncompleteSubgidOnly,
    /// real uid と effective uid が違う範囲写像。
    UidMismatch,
    /// 範囲写像の入力元の構築の失敗。
    Source,
}

/// 型つきの拒否（理由・そこまでに分かった事実・従来どおりの固定文言のエラー）。
#[derive(Debug)]
pub struct RootlessIdRefusal {
    /// 理由。
    pub reason: RefusalReason,
    /// 所有者名の出所（解決できた後の拒否のとき）。
    pub owner: Option<OwnerNameKind>,
    /// subuid / subgid の分類（分類まで進んだ拒否のとき）。
    pub probes: Option<(SubIdFileProbe, SubIdFileProbe)>,
    error: TraitError,
}

impl RootlessIdRefusal {
    /// 従来と同じ固定文言・コードの `TraitError`。
    #[must_use]
    pub fn to_trait_error(self) -> TraitError {
        self.error
    }
}

/// 拒否されなかった判定の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessIdDiagnosis {
    /// 所有者名の出所。
    pub owner: OwnerNameKind,
    /// 所有者名（得られたとき）。
    pub name: Option<String>,
    /// subuid の分類。
    pub subuid: SubIdFileProbe,
    /// subgid の分類。
    pub subgid: SubIdFileProbe,
    /// 選ばれたモデル。
    pub model: RootlessIdModel,
}

/// 名前を引けない（`LookupUnavailable`）まま 1 対 1 へ落としてよいか（純関数・#2545）。
///
/// `LookupUnavailable` で、選ばれたモデルが `SingleId` で、subuid / subgid のどちらかに名前の行があるときだけ拒否する。
/// `NotFound`（NSS が不在を確定）は名前の行が自分のものでないと分かっているため許可する。
pub fn check_owner_determinable(
    owner: OwnerNameKind,
    model: RootlessIdModel,
    subuid_named: bool,
    subgid_named: bool,
) -> Result<(), RefusalReason> {
    if owner == OwnerNameKind::LookupUnavailable
        && model == RootlessIdModel::SingleId
        && (subuid_named || subgid_named)
    {
        Err(RefusalReason::OwnerUndetermined)
    } else {
        Ok(())
    }
}

/// `/etc/passwd` の既定位置（NSS は使わない）。
#[cfg(target_os = "linux")]
pub const SYSTEM_PASSWD: &str = "/etc/passwd";
/// `/etc/subuid` の既定位置。
#[cfg(target_os = "linux")]
pub const SYSTEM_SUBUID: &str = "/etc/subuid";
/// `/etc/subgid` の既定位置。
#[cfg(target_os = "linux")]
pub const SYSTEM_SUBGID: &str = "/etc/subgid";

fn precondition(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, message)
}

/// 2 ファイルの分類からモデルを選ぶ（表は module doc）。
pub fn select_rootless_id_model(
    subuid: SubIdFileProbe,
    subgid: SubIdFileProbe,
    real_uid: u32,
    effective_uid: u32,
) -> Result<RootlessIdModel, TraitError> {
    use SubIdFileProbe::{Absent, Assigned, NoOwnerRows, Unusable};
    match (subuid, subgid) {
        (Unusable, _) | (_, Unusable) => {
            Err(precondition("subordinate id configuration is unreadable"))
        }
        (Assigned, Assigned) => {
            if real_uid == effective_uid {
                Ok(RootlessIdModel::SubordinateIds)
            } else {
                Err(precondition(
                    "real and effective uid differ for a subordinate id mapping",
                ))
            }
        }
        (Assigned, Absent | NoOwnerRows) | (Absent | NoOwnerRows, Assigned) => {
            Err(precondition("subordinate id configuration is incomplete"))
        }
        (Absent | NoOwnerRows, Absent | NoOwnerRows) => Ok(RootlessIdModel::SingleId),
    }
}

/// `/etc/passwd` の内容から、uid 欄が `uid` と一致する最初の行の名前（第 1 欄）を返す。該当行が無ければ `None`。
///
/// 他人の行は検証せず読み飛ばす。該当行の欄が足りない・名前が空・UTF-8 でない・上限超過は `FailedPrecondition`。
/// 名前の文字種・長さの検証は呼び出し側が `SubIdOwner::new` で行う（規則を二重に持たない）。
pub fn owner_name_from_passwd(bytes: &[u8], uid: u32) -> Result<Option<String>, TraitError> {
    let bad = || precondition("the passwd database is unusable");
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_PASSWD_BYTES) {
        return Err(bad());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    for (i, line) in text.lines().enumerate() {
        if i >= MAX_PASSWD_LINES {
            return Err(bad());
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let name = fields.next();
        let _password = fields.next();
        let uid_field = fields.next();
        // uid 欄が数値として一致しない行（他人の行・壊れた行）は読み飛ばす。
        if uid_field.and_then(|f| f.parse::<u32>().ok()) != Some(uid) {
            continue;
        }
        return match name {
            Some(n) if !n.is_empty() => Ok(Some(n.to_owned())),
            _ => Err(bad()),
        };
    }
    Ok(None)
}

/// 上限つきでファイルを読む（超過は `None`）。
#[cfg(target_os = "linux")]
fn read_bounded(path: &std::path::Path, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)?;
    Ok((u64::try_from(buf.len()).unwrap_or(u64::MAX) <= limit).then_some(buf))
}

/// `passwd` を上限つきで読み、`effective` の名前を返す（`start` と `doctor` が共用。#2387）。
///
/// ファイルが無ければ `None`（名前なしで数値 uid の行だけ照合する）。上限超過・その他の I/O 失敗・書式不正は
/// 固定文言の `FailedPrecondition`。
#[cfg(target_os = "linux")]
pub fn read_owner_name(
    passwd: &std::path::Path,
    effective: u32,
) -> Result<Option<String>, TraitError> {
    match read_bounded(passwd, MAX_PASSWD_BYTES) {
        Ok(Some(bytes)) => owner_name_from_passwd(&bytes, effective),
        Ok(None) => Err(precondition("the passwd database is unusable")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(precondition("the passwd database is unusable")),
    }
}

/// subuid / subgid の 1 ファイルを分類する（`ErrorCode::NotFound` はファイル無し。それ以外の失敗は `Unusable`）。
#[cfg(target_os = "linux")]
pub fn probe_sub_id_file(
    path: &std::path::Path,
    owner: &fandhe_container_core::rootless::SubIdOwner,
) -> SubIdFileProbe {
    match fandhe_container_core::rootless::load_subordinate_ids(path, owner) {
        Ok(ranges) if ranges.is_empty() => SubIdFileProbe::NoOwnerRows,
        Ok(_) => SubIdFileProbe::Assigned,
        Err(e) if e.code == ErrorCode::NotFound => SubIdFileProbe::Absent,
        Err(_) => SubIdFileProbe::Unusable,
    }
}

/// 所有者の解決の結果(`resolve_rootless_id_source`)。start の権限モデルと pull 時の展開の写像の両方の入力になる。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub enum RootlessIdResolution {
    /// コンテナ 0 → 自 ID の 1 対 1(subuid / subgid の設定が無いホスト)。
    SingleId,
    /// 範囲写像。入力元は probe したのと同じ subuid / subgid を読む。
    SubordinateIds(fandhe_container_core::oci_runtime::SubordinateIdSource),
}

/// 所有者名を passwd、無ければ NSS(`getent`)から得て、subuid / subgid を分類し、モデルと範囲写像の入力元を決める。
///
/// rootless の start(`start_entry` の `resolve_launch_privilege`)と、pull 時の展開の所有者(cli の
/// `image_ownership`。#2389・SEC-5・CORE-6・OCI-1)が同じこの関数を呼び、所有者の解決を食い違わせない。
/// rootful(uid 0)の判定は呼び出し側が先に行う。`real` / `effective` は start する利用者の uid。
/// 名前が規則に違反する行は `SingleId` へ黙って落とさず拒否する。
#[cfg(target_os = "linux")]
pub fn resolve_rootless_id_source(
    real: u32,
    effective: u32,
    passwd: &std::path::Path,
    subuid: &std::path::Path,
    subgid: &std::path::Path,
) -> Result<RootlessIdResolution, TraitError> {
    resolve_rootless_id_source_with(
        real,
        effective,
        passwd,
        subuid,
        subgid,
        &crate::user_db::UserDbLookup::system(),
    )
}

/// [`resolve_rootless_id_source`] の NSS 参照の設定を差し替えられる版(試験・別配置向け。本番は上の関数)。
#[cfg(target_os = "linux")]
pub fn resolve_rootless_id_source_with(
    real: u32,
    effective: u32,
    passwd: &std::path::Path,
    subuid: &std::path::Path,
    subgid: &std::path::Path,
    lookup: &crate::user_db::UserDbLookup,
) -> Result<RootlessIdResolution, TraitError> {
    use fandhe_container_core::oci_runtime::SubordinateIdSource;
    let d = diagnose_rootless_id_source_with(real, effective, passwd, subuid, subgid, lookup)
        .map_err(RootlessIdRefusal::to_trait_error)?;
    match d.model {
        RootlessIdModel::SingleId => Ok(RootlessIdResolution::SingleId),
        RootlessIdModel::SubordinateIds => Ok(RootlessIdResolution::SubordinateIds(
            SubordinateIdSource::with_id_files(d.name, subuid, subgid)?,
        )),
    }
}

/// 所有者名の解決から ID 写像モデルの選択までを型つきで判定する(`start`・pull の展開・`doctor` が共用。#2545)。
///
/// 順序: 所有者名 → `SubIdOwner` の規則 → `nsswitch.conf` の `subid:` → subuid / subgid の分類 → モデルの選択 →
/// 名前を引けないときの判定(`check_owner_determinable`)。範囲の写像・helper の検証は含まない(`start` では core の
/// launcher が担う段で、`doctor` が同じ core の関数で別途行う)。
#[cfg(target_os = "linux")]
pub fn diagnose_rootless_id_source_with(
    real: u32,
    effective: u32,
    passwd: &std::path::Path,
    subuid: &std::path::Path,
    subgid: &std::path::Path,
    lookup: &crate::user_db::UserDbLookup,
) -> Result<RootlessIdDiagnosis, RootlessIdRefusal> {
    use crate::user_db::{OwnerNameResolution, SubidSourceProbe, resolve_owner_name_typed};
    use fandhe_container_core::rootless::{SubIdOwner, load_has_named_rows};
    let refuse = |reason, owner, probes, error: TraitError| RootlessIdRefusal {
        reason,
        owner,
        probes,
        error,
    };
    let resolution = resolve_owner_name_typed(passwd, effective, lookup).map_err(|e| {
        refuse(
            RefusalReason::Owner(e.kind()),
            None,
            None,
            TraitError::from(e),
        )
    })?;
    let (kind, name) = match resolution {
        OwnerNameResolution::Resolved { name, .. } => (OwnerNameKind::Resolved, Some(name)),
        OwnerNameResolution::NotFound => (OwnerNameKind::NotFound, None),
        OwnerNameResolution::LookupUnavailable => (OwnerNameKind::LookupUnavailable, None),
    };
    let owner = SubIdOwner::new(effective, name.clone()).map_err(|_| {
        refuse(
            RefusalReason::OwnerNameInvalid,
            Some(kind),
            None,
            precondition("the owner name is not usable for subordinate ids"),
        )
    })?;
    match lookup.subid_source() {
        SubidSourceProbe::Files => {}
        SubidSourceProbe::NameService => {
            return Err(refuse(
                RefusalReason::SubidFromNameService,
                Some(kind),
                None,
                precondition("subordinate ids from a name service are not supported"),
            ));
        }
        SubidSourceProbe::Unusable => {
            return Err(refuse(
                RefusalReason::NsswitchUnusable,
                Some(kind),
                None,
                precondition("the name service switch configuration is unusable"),
            ));
        }
    }
    let (pu, pg) = (
        probe_sub_id_file(subuid, &owner),
        probe_sub_id_file(subgid, &owner),
    );
    let model = match select_rootless_id_model(pu, pg, real, effective) {
        Ok(m) => m,
        Err(error) => {
            use SubIdFileProbe::{Assigned, Unusable};
            let reason = match (pu, pg) {
                (Unusable, _) | (_, Unusable) => RefusalReason::SubIdUnreadable,
                (Assigned, Assigned) => RefusalReason::UidMismatch,
                (Assigned, _) => RefusalReason::IncompleteSubuidOnly,
                _ => RefusalReason::IncompleteSubgidOnly,
            };
            return Err(refuse(reason, Some(kind), Some((pu, pg)), error));
        }
    };
    // 名前の行の有無は、判定が要るとき(名前を引けず 1 対 1 になるとき)だけ読む。読めなければ「ある」とみなす。
    let named = |probe: SubIdFileProbe, path: &std::path::Path| {
        probe == SubIdFileProbe::NoOwnerRows && load_has_named_rows(path).unwrap_or(true)
    };
    let needs_check =
        kind == OwnerNameKind::LookupUnavailable && model == RootlessIdModel::SingleId;
    let (un, gn) = if needs_check {
        (named(pu, subuid), named(pg, subgid))
    } else {
        (false, false)
    };
    check_owner_determinable(kind, model, un, gn).map_err(|reason| {
        refuse(
            reason,
            Some(kind),
            Some((pu, pg)),
            precondition("the owner of named subordinate id lines cannot be determined"),
        )
    })?;
    Ok(RootlessIdDiagnosis {
        owner: kind,
        name,
        subuid: pu,
        subgid: pg,
        model,
    })
}

#[cfg(test)]
mod tests {
    use super::SubIdFileProbe::{Absent, Assigned, NoOwnerRows, Unusable};
    use super::*;

    fn msg(r: Result<RootlessIdModel, TraitError>) -> (ErrorCode, String) {
        let e = r.expect_err("must be rejected");
        (e.code(), e.message().to_owned())
    }

    /// CORE-6・SEC-5: 両方に所有者の行があれば範囲写像。
    #[test]
    fn core6_both_assigned_selects_subordinate() {
        assert_eq!(
            select_rootless_id_model(Assigned, Assigned, 1000, 1000).unwrap(),
            RootlessIdModel::SubordinateIds
        );
    }

    /// CORE-6: 設定の無いホストは従来どおり 1 対 1。
    #[test]
    fn core6_absent_or_no_rows_selects_single() {
        for a in [Absent, NoOwnerRows] {
            for b in [Absent, NoOwnerRows] {
                assert_eq!(
                    select_rootless_id_model(a, b, 1000, 1000).unwrap(),
                    RootlessIdModel::SingleId
                );
            }
        }
    }

    /// SEC-5: 片側だけ・読めない・uid 食い違いは固定文言で fail-closed。
    #[test]
    fn sec5_partial_unusable_and_uid_mismatch_are_rejected() {
        let incomplete = (
            ErrorCode::FailedPrecondition,
            "subordinate id configuration is incomplete".to_owned(),
        );
        for (a, b) in [
            (Assigned, Absent),
            (Assigned, NoOwnerRows),
            (Absent, Assigned),
            (NoOwnerRows, Assigned),
        ] {
            assert_eq!(msg(select_rootless_id_model(a, b, 1000, 1000)), incomplete);
        }
        let unreadable = (
            ErrorCode::FailedPrecondition,
            "subordinate id configuration is unreadable".to_owned(),
        );
        for (a, b) in [
            (Unusable, Assigned),
            (Assigned, Unusable),
            (Unusable, Absent),
            (Absent, Unusable),
            (Unusable, Unusable),
        ] {
            assert_eq!(msg(select_rootless_id_model(a, b, 1000, 1000)), unreadable);
        }
        assert_eq!(
            msg(select_rootless_id_model(Assigned, Assigned, 1000, 1001)),
            (
                ErrorCode::FailedPrecondition,
                "real and effective uid differ for a subordinate id mapping".to_owned()
            )
        );
        // 範囲が無ければ uid の食い違いは選択に影響しない。
        assert_eq!(
            select_rootless_id_model(Absent, Absent, 1000, 1001).unwrap(),
            RootlessIdModel::SingleId
        );
    }

    /// SEC-5・#2545: 名前を引けず 1 対 1 になるとき、名前の行があれば拒否する(全組み合わせ)。
    #[test]
    fn sec5_owner_undetermined_rule() {
        use OwnerNameKind::{LookupUnavailable, NotFound, Resolved};
        use RootlessIdModel::{SingleId, SubordinateIds};
        for (owner, model, un, gn, want) in [
            (LookupUnavailable, SingleId, true, false, false),
            (LookupUnavailable, SingleId, false, true, false),
            (LookupUnavailable, SingleId, true, true, false),
            (LookupUnavailable, SingleId, false, false, true),
            (LookupUnavailable, SubordinateIds, true, true, true),
            (NotFound, SingleId, true, true, true),
            (Resolved, SingleId, true, true, true),
        ] {
            let r = check_owner_determinable(owner, model, un, gn);
            assert_eq!(r.is_ok(), want, "{owner:?} {model:?} {un} {gn}");
            if !want {
                assert_eq!(r, Err(RefusalReason::OwnerUndetermined));
            }
        }
    }

    /// 通常の行・最初の一致・コメントと空行・他人の壊れた行の読み飛ばし。
    #[test]
    fn core6_passwd_owner_name_lookup() {
        let text = b"# c\n\nroot:x:0:0::/root:/bin/sh\nbroken\nalice:x:1000:1000::/h:/bin/sh\nalice2:x:1000:1000::/h:/bin/sh\n";
        assert_eq!(
            owner_name_from_passwd(text, 1000).unwrap(),
            Some("alice".to_owned())
        );
        assert_eq!(owner_name_from_passwd(text, 4242).unwrap(), None);
        assert_eq!(owner_name_from_passwd(b"", 1000).unwrap(), None);
    }

    /// 該当行の欄不足・空の名前・UTF-8 不正・上限超過は fail-closed。
    #[test]
    fn sec5_passwd_unusable_inputs_are_rejected() {
        let expect = (
            ErrorCode::FailedPrecondition,
            "the passwd database is unusable".to_owned(),
        );
        let run = |b: &[u8]| {
            let e = owner_name_from_passwd(b, 1000).expect_err("must be rejected");
            (e.code(), e.message().to_owned())
        };
        assert_eq!(run(b":x:1000:1000::/h:/bin/sh\n"), expect);
        assert_eq!(run(&[0xff, 0xfe]), expect);
        let big = vec![b'a'; usize::try_from(MAX_PASSWD_BYTES).unwrap() + 1];
        assert_eq!(run(&big), expect);
        let many = "x:x:1:1\n".repeat(MAX_PASSWD_LINES + 1);
        assert_eq!(run(many.as_bytes()), expect);
    }

    /// Linux 限定: `read_owner_name`・`probe_sub_id_file` の分類（`doctor` と共用する経路。#2387・CORE-6）。
    #[cfg(target_os = "linux")]
    mod linux_shared {
        use super::super::*;
        use fandhe_container_core::rootless::SubIdOwner;
        use std::path::PathBuf;

        /// 解決の入力一式を一時ディレクトリへ置く。
        fn resolve(
            tag: &str,
            subuid: Option<&str>,
            subgid: Option<&str>,
        ) -> (Result<RootlessIdResolution, TraitError>, PathBuf) {
            let d = tmp(tag);
            std::fs::write(d.join("passwd"), "alice:x:1000:1000::/h:/bin/sh\n").unwrap();
            for (n, b) in [("subuid", subuid), ("subgid", subgid)] {
                if let Some(b) = b {
                    std::fs::write(d.join(n), b).unwrap();
                }
            }
            let r = resolve_rootless_id_source(
                1000,
                1000,
                &d.join("passwd"),
                &d.join("subuid"),
                &d.join("subgid"),
            );
            (r, d)
        }

        /// CORE-6・SEC-5(#2389): 設定なし → 1 対 1、両方あり → 範囲写像、片側のみ → 拒否。
        #[test]
        fn core6_resolve_rootless_id_source_cases() {
            let (r, d) = resolve("r-single", None, None);
            assert!(matches!(r.unwrap(), RootlessIdResolution::SingleId));
            let _ = std::fs::remove_dir_all(&d);
            let (r, d) = resolve(
                "r-sub",
                Some("alice:100000:65536\n"),
                Some("alice:200000:65536\n"),
            );
            match r.unwrap() {
                RootlessIdResolution::SubordinateIds(src) => {
                    let maps = src.resolve_id_maps(1000, 1000).unwrap();
                    assert_eq!(maps.uid().host_id_of(1), Some(100000));
                    assert_eq!(maps.gid().host_id_of(1), Some(200000));
                }
                RootlessIdResolution::SingleId => panic!("expected a ranged mapping"),
            }
            let _ = std::fs::remove_dir_all(&d);
            let (r, d) = resolve("r-part", Some("alice:100000:65536\n"), None);
            let _ = std::fs::remove_dir_all(&d);
            let e = r.unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "subordinate id configuration is incomplete");
        }

        /// CORE-6・SEC-5(#2390): passwd に行が無く NSS(stub の getent)が名前を返すと、名前で書かれた subuid / subgid の
        /// 行で範囲写像になる。NSS の失敗は縮退せず拒否する。
        #[test]
        fn core6_resolve_uses_nss_name_when_passwd_misses() {
            use crate::user_db::UserDbLookup;
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            use std::time::Duration;
            let d = tmp("r-nss");
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::write(d.join("passwd"), "other:x:2000:2000::/h:/bin/sh\n").unwrap();
            std::fs::write(d.join("subuid"), "ldapuser:100000:65536\n").unwrap();
            std::fs::write(d.join("subgid"), "ldapuser:200000:65536\n").unwrap();
            let euid = std::fs::metadata("/proc/self").unwrap().uid();
            let lookup_for = |body: &str| {
                let p = d.join("getent");
                let _ = std::fs::remove_file(&p);
                std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
                UserDbLookup::custom(vec![p], Duration::from_secs(5), Some(euid), d.clone())
            };
            let run = |l: &UserDbLookup| {
                resolve_rootless_id_source_with(
                    1000,
                    1000,
                    &d.join("passwd"),
                    &d.join("subuid"),
                    &d.join("subgid"),
                    l,
                )
            };
            match run(&lookup_for("echo 'ldapuser:*:1000:1000::/h:/bin/sh'")).unwrap() {
                RootlessIdResolution::SubordinateIds(src) => {
                    let maps = src.resolve_id_maps(1000, 1000).unwrap();
                    assert_eq!(maps.uid().host_id_of(1), Some(100000));
                    assert_eq!(maps.gid().host_id_of(1), Some(200000));
                }
                RootlessIdResolution::SingleId => panic!("expected a ranged mapping"),
            }
            // 名前なし(終了 2)は従来どおり数値 uid の行だけで照合され、名前の行は一致せず 1 対 1。
            assert!(matches!(
                run(&lookup_for("exit 2")).unwrap(),
                RootlessIdResolution::SingleId
            ));
            // NSS の失敗は縮退せず拒否。
            let e = run(&lookup_for("exit 1")).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            let _ = std::fs::remove_dir_all(&d);
        }

        /// SEC-5・CORE-6・#2545: 信頼できる getent が無く(LookupUnavailable)、名前の行しか無ければ拒否。
        /// 数値行が両方にあれば範囲写像、ファイル無し・数値行だけ(片側のみは別の拒否)なら 1 対 1。
        #[test]
        fn sec5_lookup_unavailable_with_named_rows_is_refused() {
            use crate::user_db::UserDbLookup;
            use std::time::Duration;
            let d = tmp("r-unavail");
            std::fs::write(d.join("passwd"), "other:x:2000:2000::/h:/bin/sh\n").unwrap();
            let lookup = UserDbLookup::custom(
                vec![d.join("absent-getent")],
                Duration::from_secs(5),
                None,
                d.clone(),
            );
            let run = || {
                resolve_rootless_id_source_with(
                    1000,
                    1000,
                    &d.join("passwd"),
                    &d.join("subuid"),
                    &d.join("subgid"),
                    &lookup,
                )
            };
            // ファイル無し → 1 対 1。
            assert!(matches!(run().unwrap(), RootlessIdResolution::SingleId));
            // 名前の行だけ → 拒否(固定文言)。
            std::fs::write(d.join("subuid"), "ldapuser:100000:65536\n").unwrap();
            std::fs::write(d.join("subgid"), "ldapuser:200000:65536\n").unwrap();
            let e = run().unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "the owner of named subordinate id lines cannot be determined"
            );
            // 型つきの理由も具体値で照合する。
            let r = diagnose_rootless_id_source_with(
                1000,
                1000,
                &d.join("passwd"),
                &d.join("subuid"),
                &d.join("subgid"),
                &lookup,
            )
            .unwrap_err();
            assert_eq!(r.reason, RefusalReason::OwnerUndetermined);
            assert_eq!(r.owner, Some(OwnerNameKind::LookupUnavailable));
            assert_eq!(
                r.probes,
                Some((SubIdFileProbe::NoOwnerRows, SubIdFileProbe::NoOwnerRows))
            );
            // 数値行が両方にあれば範囲写像。
            std::fs::write(d.join("subuid"), "1000:100000:65536\n").unwrap();
            std::fs::write(d.join("subgid"), "1000:200000:65536\n").unwrap();
            assert!(matches!(
                run().unwrap(),
                RootlessIdResolution::SubordinateIds(_)
            ));
            // 他人の数値行だけ・コメントだけなら 1 対 1。
            std::fs::write(d.join("subuid"), "2000:100000:65536\n# c\n").unwrap();
            std::fs::write(d.join("subgid"), "").unwrap();
            assert!(matches!(run().unwrap(), RootlessIdResolution::SingleId));
            let _ = std::fs::remove_dir_all(&d);
        }

        /// CORE-6・#2545: `subid:` が files 以外なら拒否、files・無しなら従来どおり、読めなければ拒否。
        #[test]
        fn core6_subid_name_service_is_refused() {
            use crate::user_db::UserDbLookup;
            use std::time::Duration;
            let d = tmp("r-subid");
            std::fs::write(d.join("passwd"), "alice:x:1000:1000::/h:/bin/sh\n").unwrap();
            let conf = d.join("nsswitch.conf");
            let base = UserDbLookup::custom(vec![], Duration::from_secs(5), None, d.clone());
            let run = |text: Option<&str>| {
                let l = match text {
                    Some(t) => {
                        std::fs::write(&conf, t).unwrap();
                        base.clone().with_nsswitch_conf(conf.clone())
                    }
                    None => base.clone().with_nsswitch_conf(d.clone()),
                };
                diagnose_rootless_id_source_with(
                    1000,
                    1000,
                    &d.join("passwd"),
                    &d.join("subuid"),
                    &d.join("subgid"),
                    &l,
                )
            };
            assert_eq!(
                run(Some("subid: files\n")).unwrap().model,
                RootlessIdModel::SingleId
            );
            assert_eq!(
                run(Some("passwd: files\n")).unwrap().model,
                RootlessIdModel::SingleId
            );
            let r = run(Some("subid: sss\n")).unwrap_err();
            assert_eq!(r.reason, RefusalReason::SubidFromNameService);
            assert_eq!(
                r.to_trait_error().message(),
                "subordinate ids from a name service are not supported"
            );
            let r = run(None).unwrap_err();
            assert_eq!(r.reason, RefusalReason::NsswitchUnusable);
            assert_eq!(
                r.to_trait_error().message(),
                "the name service switch configuration is unusable"
            );
            let _ = std::fs::remove_dir_all(&d);
        }

        fn tmp(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!(
                "fc-idmodel-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        fn core6_read_owner_name_cases() {
            let d = tmp("pw");
            assert_eq!(read_owner_name(&d.join("none"), 1000).unwrap(), None);
            let pw = d.join("passwd");
            std::fs::write(&pw, "alice:x:1000:1000::/h:/bin/sh\n").unwrap();
            assert_eq!(
                read_owner_name(&pw, 1000).unwrap(),
                Some("alice".to_owned())
            );
            let big = d.join("big");
            std::fs::write(
                &big,
                vec![b'a'; usize::try_from(MAX_PASSWD_BYTES).unwrap() + 1],
            )
            .unwrap();
            let e = read_owner_name(&big, 1000).unwrap_err();
            assert_eq!(e.message(), "the passwd database is unusable");
            // ディレクトリは読めない（NotFound 以外の I/O 失敗）。
            let e = read_owner_name(&d, 1000).unwrap_err();
            assert_eq!(e.message(), "the passwd database is unusable");
            let _ = std::fs::remove_dir_all(&d);
        }

        #[test]
        fn core6_probe_sub_id_file_cases() {
            let d = tmp("sub");
            let owner = SubIdOwner::new(1000, Some("alice".to_owned())).unwrap();
            assert_eq!(
                probe_sub_id_file(&d.join("none"), &owner),
                SubIdFileProbe::Absent
            );
            let f = d.join("subuid");
            std::fs::write(&f, "bob:100000:65536\n").unwrap();
            assert_eq!(probe_sub_id_file(&f, &owner), SubIdFileProbe::NoOwnerRows);
            std::fs::write(&f, "alice:100000:65536\n").unwrap();
            assert_eq!(probe_sub_id_file(&f, &owner), SubIdFileProbe::Assigned);
            std::fs::write(&f, "alice:bad\n").unwrap();
            assert_eq!(probe_sub_id_file(&f, &owner), SubIdFileProbe::Unusable);
            assert_eq!(probe_sub_id_file(&d, &owner), SubIdFileProbe::Unusable);
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}
