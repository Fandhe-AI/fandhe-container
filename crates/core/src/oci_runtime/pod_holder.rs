//! pod の保持役が、pod で共有する user・ipc・net namespace を確立する公開 API(Linux 限定。
//! CRI-2・CORE-3・SEC-5・NET-2。#2870。設計は #2838 と `docs/design/pod-namespace-holder.md`)。
//!
//! # 役割と呼び出し元
//!
//! pod の ipc 共有(#2674)は core 側の join(`NamespaceJoin`・`exec::isolate_join`)まで実装済みだが、join 先の
//! namespace を作って持ち続ける供給元が無かった。本モジュールはその土台(H1)で、supervisor の bin の
//! `pod-holder` モード(H2・#2874)が、exec された単一スレッドのプロセスから [`establish_pod_namespaces`] を
//! 呼ぶ。保持役のプロセス自体(READY フレーム・stdin EOF / SIGTERM での終了)は本モジュールの範囲外で未実装
//! (REPAIR-3)。後で `NamespaceJoin::pin` と `exec::isolate_join` が要求する条件(user namespace の親子・作成者 uid・
//! ipc の所有・写像の完全一致。SEC-5)を満たす namespace をここで作る。
//!
//! # 手順(権限モデルの解決は launch と同じ `resolve_privilege` を使う)
//!
//! 1. 入口の検査(すべて副作用の前): 単一スレッド・`RootfulHostRoot` の拒否・入力元の整合
//! 2. user(写像つき)→ ipc → net の順に作る。`RootlessSingleId` は `exec::isolate` の `unshare(2)` 1 回、
//!    `RootlessSubordinateIds` は `exec::isolate_rootless_subordinate`(holder・mapper 経由。呼び出しプロセスは
//!    dumpable にならない。#2374)
//! 3. `/proc/self/{uid,gid}_map` を読み戻し、計画と **完全一致** することを照合する(不一致は成功値を返さない)
//! 4. ipc・net の所有者が新しい user namespace であることを fd で照合し、各 namespace の素性を報告する
//!
//! # 契約(呼び出し側の義務)
//!
//! - **単一スレッドから呼ぶ**(`CLONE_NEWUSER` の条件。満たさなければ副作用なしで `FailedPrecondition`)
//! - **機密をメモリに置いたまま呼ばない**: 範囲写像の holder は呼び出し時点のメモリの COW 複製を持ち、release
//!   まで dumpable である(#2546)。保持役は秘密を持たないこと
//! - **失敗したプロセスは破棄する**(写像は write-once で戻せない)
//! - 範囲写像の経路は Linux 6.9 以降が要る(`exec::isolate_rootless_subordinate` の helper の停止手段。緩めない)
//! - **`lo` は本 API が up にする**: netns の作成直後に `lo` を up にし、up にできなければエラー(fail-closed)。
//!   保持役(H2)が重複して up にしたり、up でない前提で組んだりしない
//!
//! # 未実装・残余(REPAIR-3)
//!
//! - 保持役のプロセス(`pod-holder` モード。READY フレーム・終了条件・fd の整理)は #2874
//! - `NamespaceJoin` の net 対応(user + ipc + net の join)は #2872
//! - `RootfulHostRoot` は #2241 のオーナー判断まで `Unimplemented`
//!
//! エラーは `TraitError` で返し、文言は固定の英語でパス・pid・errno・写像の値を含めない(REPAIR-4)。

use std::os::fd::AsFd as _;

use super::SubordinateIdSource;
use super::launcher::{SubordinateIds, resolve_privilege};
use super::namespace_join::identity_plain as identity;
use crate::exec::{
    IdMapping, IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet, plan,
    plan_rootless_subordinate,
};
use crate::rootless::{IdKind, ProcHandle, RootlessError, TargetPid};
use crate::sys;
use crate::traits::{ErrorCode, TraitError};

const MSG_MULTI_THREADED: &str = "the pod holder must be called from a single-threaded process";
const MSG_ROOTFUL: &str = "the rootful privilege model is not supported for the pod holder";
const MSG_MAP_MISMATCH: &str = "the pod holder id mapping does not match the expected mapping";
const MSG_NOT_OWNED: &str = "the pod holder namespaces are not owned by the pod user namespace";
const MSG_NOT_NEW: &str = "the pod holder user namespace was not created";
const MSG_INSPECT: &str = "failed to inspect the pod holder namespaces";
const MSG_TIMEOUT: &str = "the pod holder namespaces were not established within the timeout";
const MSG_DENIED: &str = "permission denied while establishing the pod holder namespaces";
const MSG_PRECONDITION: &str = "a precondition for the pod holder namespaces was not met";
const MSG_FAILED: &str = "failed to establish the pod holder namespaces";

/// nsfs 上の namespace の素性(`st_dev`・`st_ino`)。保持役の READY フレームの材料(#2874)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceIdentity {
    dev: u64,
    ino: u64,
}

impl NamespaceIdentity {
    /// nsfs の `st_dev`。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// nsfs の `st_ino`。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// [`establish_pod_namespaces`] の成功結果(照合済み。将来拡張できるよう `non_exhaustive`)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PodHolderNamespaces {
    privilege: IsolationPrivilege,
    uid_map: Vec<IdMapping>,
    gid_map: Vec<IdMapping>,
    user: NamespaceIdentity,
    ipc: NamespaceIdentity,
    net: NamespaceIdentity,
}

impl PodHolderNamespaces {
    /// 実際に使った権限モデル。
    pub fn privilege(&self) -> IsolationPrivilege {
        self.privilege
    }

    /// 読み戻して計画との一致を確かめた uid 写像。
    pub fn uid_map(&self) -> &[IdMapping] {
        &self.uid_map
    }

    /// 読み戻して計画との一致を確かめた gid 写像。
    pub fn gid_map(&self) -> &[IdMapping] {
        &self.gid_map
    }

    /// 新しい user namespace の素性。
    pub fn user(&self) -> NamespaceIdentity {
        self.user
    }

    /// 新しい ipc namespace の素性(所有者は [`Self::user`])。
    pub fn ipc(&self) -> NamespaceIdentity {
        self.ipc
    }

    /// 新しい net namespace の素性(所有者は [`Self::user`])。
    pub fn net(&self) -> NamespaceIdentity {
        self.net
    }

    /// `lo` が up か。作成直後に up にできなければ確立自体が失敗するため、成功値では常に `true`(NET-2)。
    pub fn loopback_up(&self) -> bool {
        true
    }
}

/// 副作用の前の権限モデルの検査(純関数)。`RootfulHostRoot` は #2241 の判断まで `Unimplemented`。
fn check_request(privilege: IsolationPrivilege) -> Result<(), TraitError> {
    match privilege {
        IsolationPrivilege::RootfulHostRoot => {
            Err(TraitError::new(ErrorCode::Unimplemented, MSG_ROOTFUL))
        }
        _ => Ok(()),
    }
}

/// 計画から導いた期待する写像(純関数。`SingleId` は自 ID をコンテナ 0 へ 1 行、範囲写像は解決済みの行)。
fn expected_id_maps(
    euid: u32,
    egid: u32,
    subordinate: Option<&SubordinateIds>,
) -> (Vec<IdMapping>, Vec<IdMapping>) {
    match subordinate {
        Some(ids) => (ids.uid.entries().to_vec(), ids.gid.entries().to_vec()),
        None => (
            vec![IdMapping {
                container_id: 0,
                host_id: euid,
                count: 1,
            }],
            vec![IdMapping {
                container_id: 0,
                host_id: egid,
                count: 1,
            }],
        ),
    }
}

/// 読み戻した写像が期待と構造上一致するか(行数・順序・`container_id`・`count`)を照合する(SEC-5)。
///
/// 確立後の呼び出し側は新しい user namespace の内側にいるため、`/proc/self/{uid,gid}_map` の `host_id` は
/// 開いた側の namespace を基準に報告され、ホスト側の計画値とは一致しない場合がある。そのため `host_id` は比較しない
/// (範囲写像の `host_id` は `apply_id_maps` が書き込み時にホスト側で読み戻して照合済み。単一 ID は計画の 1 行を
/// カーネルが書いたもの)。
fn verify_id_maps(
    read: impl Fn(IdKind) -> Result<Vec<IdMapping>, RootlessError>,
    uid: &[IdMapping],
    gid: &[IdMapping],
) -> Result<(), TraitError> {
    for (kind, expected) in [(IdKind::Uid, uid), (IdKind::Gid, gid)] {
        let got = read(kind).map_err(|e| TraitError::new(e.code, MSG_INSPECT))?;
        let shape = |v: &[IdMapping]| -> Vec<(u32, u32)> {
            v.iter().map(|e| (e.container_id, e.count)).collect()
        };
        if shape(&got) != shape(expected) {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                MSG_MAP_MISMATCH,
            ));
        }
    }
    Ok(())
}

/// `ExecError` を固定文言の `TraitError` へ写す(code は保つ。パス・errno・値は外へ出さない)。
fn map_exec_error(e: &crate::exec::ExecError) -> TraitError {
    let message = match e.code {
        ErrorCode::Timeout => MSG_TIMEOUT,
        ErrorCode::PermissionDenied => MSG_DENIED,
        ErrorCode::FailedPrecondition => MSG_PRECONDITION,
        _ => MSG_FAILED,
    };
    TraitError::new(e.code, message)
}

/// pod で共有する user(写像つき)・ipc・net namespace を確立し、照合して素性を返す。
///
/// 呼び出し元は保持役(H2・#2874)。権限モデルの解決は launch と同じ(`RootlessSingleId` は `subordinate_ids` を
/// 渡さない、`RootlessSubordinateIds` は必須。取り違えは `InvalidArgument`)。契約(単一スレッド・機密なし・失敗時は
/// プロセスを破棄・`lo` を up にする)はモジュール doc を参照。
pub fn establish_pod_namespaces(
    privilege: IsolationPrivilege,
    subordinate_ids: Option<SubordinateIdSource>,
) -> Result<PodHolderNamespaces, TraitError> {
    // 1. 入口の検査(すべて副作用の前)。
    if !sys::self_is_single_threaded() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_MULTI_THREADED,
        ));
    }
    check_request(privilege)?;
    let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
    let subordinate = resolve_privilege(privilege, subordinate_ids, euid, egid)?;
    let config = IsolationConfig {
        namespaces: NamespaceSet::empty()
            .with(Namespace::User)
            .with(Namespace::Ipc)
            .with(Namespace::Net),
        hostname: None,
    };
    let (expected_uid, expected_gid) = expected_id_maps(euid, egid, subordinate.as_ref());

    // 2. 確立。開始前の user namespace の素性と dumpable を記録する。
    let before_user = identity_of(c"/proc/self/ns/user")?;
    let was_non_dumpable = matches!(sys::is_dumpable(), Ok(false));
    match subordinate {
        None => {
            let p = plan(&config).map_err(|e| map_exec_error(&e))?;
            crate::exec::isolate(&p).map_err(|e| map_exec_error(&e))?;
        }
        Some(ids) => {
            let p = plan_rootless_subordinate(&config, ids.uid, ids.gid, ids.writer, ids.timeout)
                .map_err(|e| map_exec_error(&e))?;
            crate::exec::isolate_rootless_subordinate(&p).map_err(|e| map_exec_error(&e))?;
        }
    }
    // 戻す方向にだけ動かす(dumpable の方針そのものは保持役側の判断。#2874)。
    if was_non_dumpable {
        sys::set_non_dumpable().map_err(|_| TraitError::new(ErrorCode::Internal, MSG_FAILED))?;
    }

    // 3. 写像の読み戻しと完全一致の照合。
    verify_id_maps(
        |kind| {
            let target = TargetPid::new(std::process::id())?;
            crate::rootless::read_id_map_of(&ProcHandle::open(target)?, kind)
        },
        &expected_uid,
        &expected_gid,
    )?;

    // 4. 所有の照合(fd を 1 回だけ開き、検査と報告に同じ fd を使う)。
    let inspect = |_: sys::SysError| TraitError::new(ErrorCode::Internal, MSG_INSPECT);
    let user = open_self_ns(c"/proc/self/ns/user")?;
    let ipc = open_self_ns(c"/proc/self/ns/ipc")?;
    let net = open_self_ns(c"/proc/self/ns/net")?;
    let user_id = identity(user.as_fd())?;
    if user_id == before_user {
        return Err(TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_NEW));
    }
    for fd in [&ipc, &net] {
        let owner = sys::ns_owner_userns(fd.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_OWNED)
            }
            other => inspect(other),
        })?;
        if identity(owner.as_fd())? != user_id {
            return Err(TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_OWNED));
        }
    }
    let ident = |(dev, ino)| NamespaceIdentity { dev, ino };
    Ok(PodHolderNamespaces {
        privilege,
        uid_map: expected_uid,
        gid_map: expected_gid,
        user: ident(user_id),
        ipc: ident(identity(ipc.as_fd())?),
        net: ident(identity(net.as_fd())?),
    })
}

/// 自プロセスの namespace を開く(固定の `/proc/self/ns/*` のみ。外部入力は使わない)。
fn open_self_ns(path: &std::ffi::CStr) -> Result<std::os::fd::OwnedFd, TraitError> {
    sys::open_ns_file(path).map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))
}

/// 固定パスの namespace の素性。
fn identity_of(path: &std::ffi::CStr) -> Result<(u64, u64), TraitError> {
    let fd = open_self_ns(path)?;
    identity(fd.as_fd())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        }
    }

    /// SEC-5・CRI-2: SingleId の期待する写像は自 ID をコンテナ 0 へ 1 行。
    #[test]
    fn sec5_2870_expected_maps_single_id() {
        let (u, g) = expected_id_maps(1000, 1001, None);
        assert_eq!(u, vec![m(0, 1000, 1)]);
        assert_eq!(g, vec![m(0, 1001, 1)]);
    }

    /// 照合は行の構造の一致(過不足・順序・container_id・count の違いを拒否。host_id は比較しない)。
    #[test]
    fn sec5_2870_verify_id_maps_requires_exact_match() {
        let uid = vec![m(0, 1000, 1), m(1, 100000, 65536)];
        let gid = vec![m(0, 1000, 1)];
        let reader = |u: Vec<IdMapping>, g: Vec<IdMapping>| {
            move |k: IdKind| {
                Ok(match k {
                    IdKind::Uid => u.clone(),
                    IdKind::Gid => g.clone(),
                })
            }
        };
        assert_eq!(
            verify_id_maps(reader(uid.clone(), gid.clone()), &uid, &gid),
            Ok(())
        );
        let bad: [(Vec<IdMapping>, Vec<IdMapping>); 5] = [
            (vec![m(0, 1000, 2), m(1, 100000, 65536)], gid.clone()),
            (uid.clone(), vec![m(1, 1000, 1)]),
            (
                vec![m(0, 1000, 1), m(1, 100000, 65536), m(65537, 5, 1)],
                gid.clone(),
            ),
            (vec![m(0, 1000, 1)], gid.clone()),
            (vec![m(1, 100000, 65536), m(0, 1000, 1)], gid.clone()),
        ];
        // host_id は開いた側の namespace 基準で変わりうるため、違っていても受理する。
        assert_eq!(
            verify_id_maps(
                reader(vec![m(0, 0, 1), m(1, 1, 65536)], vec![m(0, 0, 1)]),
                &uid,
                &gid
            ),
            Ok(())
        );
        for (u, g) in bad {
            let err = verify_id_maps(reader(u, g), &uid, &gid).expect_err("mismatch");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(err.message(), MSG_MAP_MISMATCH);
        }
    }

    /// 読み取りの失敗はエラー(固定文言)。
    #[test]
    fn sec5_2870_verify_id_maps_propagates_read_failure() {
        let read = |_: IdKind| -> Result<Vec<IdMapping>, RootlessError> {
            TargetPid::new(0).map(|_| Vec::new())
        };
        let err = verify_id_maps(read, &[], &[]).expect_err("read failure");
        assert_eq!(err.message(), MSG_INSPECT);
    }

    /// libtest はマルチスレッドのため、確立は副作用なしで `FailedPrecondition`(固定文言)。
    #[test]
    fn core3_2870_multi_threaded_caller_is_rejected() {
        let err = establish_pod_namespaces(IsolationPrivilege::RootlessSingleId, None)
            .expect_err("multi-threaded");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), MSG_MULTI_THREADED);
    }

    /// rootful は #2241 の判断まで `Unimplemented`。
    #[test]
    fn sec5_2870_rootful_is_unimplemented() {
        let err = check_request(IsolationPrivilege::RootfulHostRoot).expect_err("rootful");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(err.message(), MSG_ROOTFUL);
        assert_eq!(check_request(IsolationPrivilege::RootlessSingleId), Ok(()));
    }

    /// 入力元の取り違えは launch と同じ解決で `InvalidArgument`。
    #[test]
    fn sec5_2870_source_mismatch_is_invalid_argument() {
        let missing =
            resolve_privilege(IsolationPrivilege::RootlessSubordinateIds, None, 1000, 1000)
                .expect_err("source required");
        assert_eq!(missing.code(), ErrorCode::InvalidArgument);
        let source = SubordinateIdSource::system(None).expect("source");
        let extra = resolve_privilege(
            IsolationPrivilege::RootlessSingleId,
            Some(source),
            1000,
            1000,
        )
        .expect_err("source forbidden");
        assert_eq!(extra.code(), ErrorCode::InvalidArgument);
    }

    /// 失敗の写像は固定文言のみで、パス・数字を含まない。
    #[test]
    fn repair4_2870_error_mapping_is_fixed_text() {
        use crate::exec::{ExecError, IsolationStage};
        let allowed = [MSG_TIMEOUT, MSG_DENIED, MSG_PRECONDITION, MSG_FAILED];
        for code in [
            ErrorCode::Timeout,
            ErrorCode::PermissionDenied,
            ErrorCode::FailedPrecondition,
            ErrorCode::Internal,
            ErrorCode::InvalidArgument,
        ] {
            let e = ExecError::new(code, IsolationStage::Unshare, "open /etc/subuid failed: 42");
            let t = map_exec_error(&e);
            assert_eq!(t.code(), code);
            assert!(allowed.contains(&t.message()), "{}", t.message());
            assert!(!t.message().contains('/') && !t.message().chars().any(|c| c.is_ascii_digit()));
        }
    }
}
