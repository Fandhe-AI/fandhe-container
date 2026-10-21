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
//! # 所有者名（NSS を使わない）
//! `/etc/subuid` の第 1 欄は多くがユーザー名のため、`/etc/passwd` を上限つきで直接読み、uid 欄が実効 uid と一致する
//! 最初の行の第 1 欄を名前にする（[`owner_name_from_passwd`]）。環境変数 `USER` は信頼しない（CLI が起動時に消す。
//! 利用者が書き換えられる入力でもある）。argv で渡す案・数値 uid だけで照合する案は採らない。
//! 既知の制約: `/etc/passwd` に載らないユーザー（LDAP / sssd 等）は名前なしとなり、数値 uid の行だけで照合される。
//! `newuidmap` は NSS で呼び出し元を解決するため、NSS と `/etc/passwd` が食い違うと helper が拒否する（fail-closed）。
//!
//! # doctor との共用
//! 設定ファイルの既定位置（`SYSTEM_*`）・passwd の読み取り（`read_owner_name`）・subuid / subgid の分類
//! （`probe_sub_id_file`）は Linux 限定で公開し、`start`（`start_entry` の `resolve_launch_privilege`）と
//! pull 時の展開の所有者（cli の `image_ownership`。`resolve_rootless_id_source`。#2389）と
//! CLI の `doctor`（`doctor::id_mapping_check`。#2387）が同じ関数を呼ぶ。診断と `start` の判定を食い違わせない。
//!
//! エラー文言は固定の英語で、ユーザー名・パス・errno・ファイルの内容を含めない。

use fandhe_container_core::traits::{ErrorCode, TraitError};

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

/// passwd から所有者名を得て、subuid / subgid を分類し、モデルと範囲写像の入力元を決める(NSS を使わない)。
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
    use fandhe_container_core::oci_runtime::SubordinateIdSource;
    use fandhe_container_core::rootless::SubIdOwner;
    let name = read_owner_name(passwd, effective)?;
    let owner = SubIdOwner::new(effective, name.clone())
        .map_err(|_| precondition("the owner name is not usable for subordinate ids"))?;
    let model = select_rootless_id_model(
        probe_sub_id_file(subuid, &owner),
        probe_sub_id_file(subgid, &owner),
        real,
        effective,
    )?;
    match model {
        RootlessIdModel::SingleId => Ok(RootlessIdResolution::SingleId),
        RootlessIdModel::SubordinateIds => Ok(RootlessIdResolution::SubordinateIds(
            SubordinateIdSource::with_id_files(name, subuid, subgid)?,
        )),
    }
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
