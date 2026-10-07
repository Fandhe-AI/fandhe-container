//! exec の入口: 稼働中コンテナの pid1 を特定し、その namespace と cgroup へ参加して制限を再適用する（SUP-6・TASK-163.1〜163.3・#500〜#502・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `state.json` のレコードから対象を決め、`fandhe_container_core::exec` の安全 API（`Pid1Target` /
//! `join_namespaces` / `prepare_cgroup_join` / `join_cgroup` / `prepare_exec_restrictions` /
//! `reapply_restrictions`）へ配線するだけの薄い層で、`unsafe` も OS 分岐も持たない（OS 局所化は core。CLI-1）。
//! 将来 #503 の exec 専用プロセスと TASK-161（SUP-4）の healthcheck が同じ関数を使う
//! （`health.rs` の `HealthProbe` が期待する共通コードパス）。
//!
//! # 契約
//!
//! - 記録上の pid は **候補** にすぎず、シグナル送信・回収・`/proc` の宛先にそのまま使わない
//!   （pid 再利用対策。SEC-1）。core の `Pid1Target::open` が pidfd 固定のうえで pid1 であることを検証し、
//!   通ったものだけを [`ExecTarget`] にする。さらに pid が別コンテナに再利用されていないことを、
//!   記録した cgroup 配置（委譲スコープと instance）から core が導くコンテナ固有の cgroup パス
//!   `<scope>/fc-<id>@<instance>` と対象の所属 cgroup の完全一致で確認する（SEC-1）。instance は
//!   ストア全体で再利用されないため、`state.json` へプロセス識別情報（開始時刻等）を追加せずに
//!   「記録したコンテナのプロセスであること」を照合できる（スキーマ変更なし）。この照合が依存する前提
//!   （コンテナから cgroupfs に書けないこと）と見直しの条件は core の `exec/setns.rs` のモジュール doc を参照
//! - 既定のビルドの公開 API に、期待 cgroup パスを文字列で受ける入口は無い（core・supervisor とも
//!   `exec-test-support` feature を付けたビルドに限る）
//! - [`enter_namespaces`] は呼び出しスレッドの namespace を不可逆に変える。単一スレッドのプロセスから
//!   のみ呼べる。logs 捕捉スレッドを持つ supervisor 本体からは呼ばず、exec 専用プロセスから呼ぶ（#503）
//! - 順序: [`prepare_cgroup_join`]（cgroup.procs の fd 確保。#501）は [`enter_namespaces`] の **前**、
//!   [`join_cgroup`] は準備の後（#503 は `enter_namespaces` の後・seccomp の前に呼ぶ想定）。
//!   `/proc/self/cgroup` の fd も準備で確保する（`setns` 後は自プロセスを procfs から解決できないため）
//! - seccomp / Landlock の再適用（#502）: [`prepare_restrictions`]（ホスト側の `config.json` を読み、
//!   コンテナの rootfs を固定し、自プロセスの `/proc/self/status` の fd を確保）は [`enter_namespaces`] の **前**、
//!   [`reapply_restrictions`] は [`enter_namespaces`] と [`join_cgroup`] の **後**（seccomp が `setns` を
//!   拒否するため）。**準備したプロセス自身** が単一スレッドで呼ぶ（fork した子から呼ぶと別プロセスの
//!   スレッド数を読むため、core が準備時の pid との不一致を拒否する）。適用は不可逆で、失敗時は制限が
//!   部分的に載った不定状態のため、呼び出し側は続行せず終了する。#503 は「適用 → fork → execve」の順にする
//!   （制限は fork / execve を越えて継承される）。順序の全体:
//!   `identify_pid1` → `prepare_cgroup_join` → `prepare_restrictions` → `enter_namespaces` → `join_cgroup` →
//!   `reapply_restrictions`
//! - 再適用は、参加後の自プロセスの `/` が **記録したコンテナの rootfs**（[`identify_pid1`] に渡した記録の
//!   bundle から、start と同じ検査・固定で得たディレクトリ）であることを照合してから適用する。不一致
//!   （pivot していない対象・`/` へ別のマウントが重ねられた対象）は違反 `exec_root_not_container_rootfs` で
//!   拒否し、何も適用しない（SEC-1。根拠は core の `exec/reapply.rs` のモジュール doc）。bundle は
//!   [`ExecTarget`] が特定時の記録から保持するため、別の記録の `config.json`・rootfs を取り違えない
//! - **再適用の成功は exec してよい状態を意味しない（完了は型で表す）**: 載るのは `NO_NEW_PRIVS`・Landlock・
//!   seccomp だけで、capability 削減と rlimit 適用は行わない。`setns` は資格情報を変えないため、rootful の exec
//!   プロセスは再適用の後も全 capability を持つ。`ExecRestrictionReport` のフィールドは非公開で、crate の外から
//!   未適用の一覧を書き換えたり値を構築したりできない。exec へ進んでよいことの証跡は core の `ExecReady` で、
//!   [`require_exec_ready`]（core の `ExecRestrictionReport::into_complete`）だけが作る。未適用が残る間は必ず
//!   `FailedPrecondition` になり、現在の実装では常に失敗する。**fork / execve の入口（#503 が追加する）は
//!   `ExecReady` を値で受け取ること**（`ExecRestrictionReport`・真偽値を受け取る入口を作らない。SEC-1）
//! - 再適用の Landlock ルールは、launcher が実際にマウントした結果ではなく bundle の `config.json` から
//!   再導出する（launch 時の ruleset は保存されていない）。launch 後に `config.json` が書き換えられると
//!   追従してしまうが、bundle は supervisor と同じ信頼境界（コンテナから書けない場所）にある前提とする。
//!   config の mount destination が稼働中の rootfs に無ければ Landlock の適用が失敗し、exec は拒否される
//!   （fail-closed）
//! - [`join_cgroup`] は呼び出しプロセスをコンテナの cgroup へ移す（`cgroup.procs` はスレッドグループ全体を
//!   移す）。supervisor 本体から呼ばず、委譲スコープの内側で動く exec 専用プロセスからのみ呼ぶ（#503）。
//!   失敗時は所属が不定のため、呼び出し側は続行せず終了する（fail-closed）。保持 fd は `execve` の前に
//!   `close_range` で閉じる必要がある（#503）
//!
//! # #503（TASK-163.4）が `execve` を結線する前の条件
//!
//! 次の 5 点をすべて満たすまで、exec 専用プロセスはコマンドを実行してはならない（SUP-6・SEC-1。詳細は core の
//! `exec/reapply.rs` のモジュール doc の同名の節）。
//!
//! 1. **完了を型で強制する**: fork / execve の入口は `ExecReady` だけを受け取る。本モジュールにも core にも、
//!    `ExecReady` を作る別経路（テスト用の公開コンストラクタ・feature による抜け道を含む）を足さない
//! 2. **capability 削減と rlimit 適用を実装し、未適用を空にする**: 実装したものを core の
//!    `ExecRestrictionReport::UNAPPLIED` から外す。空になって初めて [`require_exec_ready`] が成功する
//! 3. **制限を exec の対象へ束縛する**: 現在の `ExecRestrictions` は準備時の [`ExecTarget`] を覚えておらず、
//!    [`reapply_restrictions`] は「[`enter_namespaces`] で参加した対象」と「[`prepare_restrictions`] に渡した
//!    対象」が同じであることを確かめない。参加後の `/` の照合は rootfs のディレクトリの同一性だけを見るため、
//!    同じ rootfs を共有する 2 つのコンテナでは取り違えても照合を通過する。対象の mount namespace の識別子を
//!    準備時に記録して参加後に照合する等で束縛し、`ExecReady` も同じ対象に束縛する
//! 4. **`setns` を伴う通し試験**: 実コンテナへ参加した後の `/` と rootfs の一致、保持した status fd からの
//!    スレッド数の読み取り、ルールパスの解決の起点が照合済みの fd であること（プロセスの `/` を引き直して
//!    いないことを区別できる検査）、pivot していない対象の拒否を具体値で照合する
//! 5. **exec 専用プロセス全体のタイムアウトと fd の後始末**: 準備から `execve` までの全体に上限時間を設け
//!    （REPAIR-5）、`execve` の前に `close_range` でホスト側の fd を閉じる
//!
//! # 未実装（REPAIR-3）
//!
//! namespace 参加・cgroup join・seccomp / Landlock 再適用までで、コマンド実行は未実装。fork・execve・
//! `close_range` と統合テスト（#503・TASK-163.4）は未実装（SUP-6）。`setns` の後に保持 fd からスレッド数が
//! 読めることの実機確認（再適用の通し試験）も #503 の統合テストで扱う（#502 のテストは `setns` をしない）。
//! exec プロセスの capability 削減・rlimit 適用も未実装（TASK-163 の内容は seccomp / Landlock のみ。要確認）。
//! 未実装である間、[`reapply_restrictions`] の成功結果は未適用の制限を列挙し、[`require_exec_ready`] は
//! 必ず失敗する（完了を装わない）。
//! 実 cgroup への参加の実機結合試験も #503 の統合テストで扱う（本 Issue では core の既定集合のユニットテストで
//! `cgroup.procs` への書き込みと読み戻しを照合）。
//! user namespace への参加も未実装で、既定の rootless（コンテナが user namespace を持つ）では
//! [`enter_namespaces`] が `EPERM` で失敗する（fail-closed。rootless の exec には必須）。
//! 違反記録（SEC-4）の監査ログへの保存の配線も未実装（#839・#503）。

use fandhe_container_core::exec::{
    ExecCgroupJoin, ExecCgroupJoinReport, ExecError, ExecReady, ExecRestrictionReport,
    ExecRestrictions, NamespaceJoinReport, Pid1Target, join_cgroup as core_join_cgroup,
    join_namespaces, prepare_cgroup_join as core_prepare_cgroup_join,
    prepare_exec_restrictions as core_prepare_exec_restrictions,
    reapply_restrictions as core_reapply_restrictions,
};
use fandhe_container_core::oci_runtime::{OciConfig, RootfsDir, load_config, pin_bundle_rootfs};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, StateRecord, TraitError,
};

/// 検証済みの exec 対象（コンテナ ID と、pidfd で固定した pid1、特定に使った記録の bundle）。
#[derive(Debug)]
pub struct ExecTarget {
    id: ContainerId,
    pid1: Pid1Target,
    /// pid1 の特定に使った記録の bundle。[`prepare_restrictions`] が `config.json` と rootfs をここから
    /// 取るため、pid1 を照合した記録と別の記録の設定で制限を組み立てることがない。
    bundle: std::path::PathBuf,
}

impl ExecTarget {
    /// 対象のコンテナ ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 検証済みの pid1。
    pub fn pid1(&self) -> &Pid1Target {
        &self.pid1
    }
}

/// `record` が稼働中で pid の記録を持つことを確かめ、記録 pid（候補）を返す。
fn running_pid(record: &StateRecord) -> Result<std::num::NonZeroU32, TraitError> {
    let status = record.status();
    match status.pid() {
        Some(pid) if status.state() == ContainerState::Running => Ok(pid),
        _ => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not running or has no recorded pid; cannot identify pid1",
        )),
    }
}

/// `record` の稼働中コンテナから pid1 を特定する。
///
/// `Running` かつ pid 記録ありでなければ `FailedPrecondition`。記録 pid は検証（pidfd 固定・直接入れ子の
/// PID 1・記録の cgroup 配置から導いた cgroup への所属・自分と別の pid / mnt namespace）を通ったときだけ
/// 採用する。期待 cgroup パスは core が記録の型（コンテナ ID・cgroup 配置）から組み立て、ここでは文字列を
/// 扱わない。
pub fn identify_pid1(record: &StateRecord) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    // 記録 pid が別コンテナの PID 1 に再利用されていないことを、コンテナ固有の cgroup で確かめる
    // （pidfd だけでは記録上の元プロセスとの同一性を証明できない。SEC-1）。cgroup 配置の記録がなければ
    // 同一性を確認できないため拒否する（fail-closed）。
    let Some(placement) = record.cgroup() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded cgroup placement; cannot verify pid1 identity",
        ));
    };
    let id = record.status().id();
    let pid1 = Pid1Target::open(pid, id, placement).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: id.clone(),
        pid1,
        bundle: record.bundle().to_path_buf(),
    })
}

/// 実機結合試験専用の入口: 期待 cgroup 絶対パスを呼び出し側から受け取って pid1 を特定する。
///
/// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開 API には
/// 含まれない（core の `Pid1Target::open_with_cgroup_path` も同じ feature に限る）。コンテナ用 cgroup を
/// 作れない試験環境で `Pid1Target` 以降の成功経路を通すためのもので、期待値を記録から導かないため
/// 「記録したコンテナのプロセスであること」（SEC-1）の照合にはならない。本番経路は必ず [`identify_pid1`] を使う。
#[cfg(feature = "exec-test-support")]
pub fn identify_pid1_in(
    record: &StateRecord,
    expected_cgroup_path: &str,
) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    let pid1 =
        Pid1Target::open_with_cgroup_path(pid, expected_cgroup_path).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: record.status().id().clone(),
        pid1,
        bundle: record.bundle().to_path_buf(),
    })
}

/// SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ参加する。単一スレッドからのみ呼ぶこと。
pub fn enter_namespaces(target: &ExecTarget) -> Result<NamespaceJoinReport, TraitError> {
    join_namespaces(&target.pid1).map_err(from_exec_error)
}

/// 対象のコンテナ cgroup を開き、参加に必要な fd を確保する。[`enter_namespaces`] の **前** に呼ぶ（SUP-6・#501）。
pub fn prepare_cgroup_join(target: &ExecTarget) -> Result<ExecCgroupJoin, TraitError> {
    core_prepare_cgroup_join(&target.pid1).map_err(from_exec_error)
}

/// 自プロセスをコンテナの cgroup へ参加させ、所属を確認する。exec 専用プロセスからのみ呼ぶこと
/// （契約はモジュール doc）。失敗時は続行せず終了すること。
pub fn join_cgroup(join: ExecCgroupJoin) -> Result<ExecCgroupJoinReport, TraitError> {
    core_join_cgroup(join).map_err(from_exec_error)
}

/// コンテナの `config.json` から Landlock ruleset を作り、コンテナの rootfs を固定し、自プロセスの status fd を
/// 確保する。[`enter_namespaces`] の **前** に、再適用を行うプロセス自身が呼ぶ（SUP-6・#502。契約はモジュール doc）。
///
/// `config.json` と rootfs は、`target` を特定した記録の bundle から取る（呼び出し側は記録を渡し直さない）。
/// rootfs は start と同じ検査（bundle 配下・symlink なし）で固定し、参加後の `/` と照合する基準にする。
/// Landlock 未対応カーネル・ルール生成失敗・rootfs を固定できない場合は拒否する（fail-closed。CORE-5・SEC-1）。
pub fn prepare_restrictions(target: &ExecTarget) -> Result<ExecRestrictions, TraitError> {
    let (config, rootfs) = load_exec_bundle(&target.bundle)?;
    core_prepare_exec_restrictions(&config, &rootfs).map_err(from_exec_error)
}

/// `NO_NEW_PRIVS` → Landlock → seccomp を自プロセスへ不可逆に適用する。[`enter_namespaces`] と
/// [`join_cgroup`] の **後**、準備したプロセス自身から単一スレッドで呼ぶ（SUP-6・#502）。
/// 適用の前に、参加後の `/` が記録したコンテナの rootfs であることを照合し、不一致なら何も適用せず拒否する。
/// 失敗時は制限が部分的に載った不定状態のため、続行せず終了すること。
///
/// 成功しても capability 削減と rlimit 適用は行われていない。`execve` へ進んでよいことの証跡は
/// [`require_exec_ready`] が返す `ExecReady` だけで、戻り値そのものは exec の許可に使えない（SEC-1）。
pub fn reapply_restrictions(
    restrictions: ExecRestrictions,
) -> Result<ExecRestrictionReport, TraitError> {
    core_reapply_restrictions(restrictions).map_err(from_exec_error)
}

/// 再適用の結果を、exec へ進んでよいことの証跡 `ExecReady` に変える（SUP-6・SEC-1・#502）。
///
/// launch 経路と同じ制限のうち未適用のものが 1 つでも残っていれば `FailedPrecondition`。現在の実装は
/// capability 削減と rlimit を適用しないため **必ず失敗する**（#503 が実装するまで exec へ進めない）。
/// #503 の fork / execve の入口は、この関数が返す `ExecReady` を値で受け取ること（契約はモジュール doc）。
pub fn require_exec_ready(report: ExecRestrictionReport) -> Result<ExecReady, TraitError> {
    report.into_complete().map_err(from_exec_error)
}

/// `bundle` の `config.json` を読み、その `root.path` が指す rootfs を固定する。
///
/// エラーメッセージに bundle のパスを含めない（core の `OciConfigError`・rootfs の検査は固定文言）。
fn load_exec_bundle(bundle: &std::path::Path) -> Result<(OciConfig, RootfsDir), TraitError> {
    let config = load_config(&bundle.join("config.json"))
        .map_err(|e| TraitError::new(e.code(), format!("exec stage Landlock: {e}")))?;
    let rootfs = pin_bundle_rootfs(bundle, &config)
        .map_err(|e| TraitError::new(e.code(), format!("exec stage Validate: {}", e.message())))?;
    Ok((config, rootfs))
}

/// `ExecError` を `code` を保ったまま `TraitError` へ写す（段名はメッセージへ含める）。
///
/// 分離違反による拒否（`ExecError::violation`。SEC-4）は、種別・理由コード・ビヘイビア ID をメッセージの
/// 末尾に機械可読な形で残す（`TraitError` は違反記録を運べないため）。違反の対象（期待 cgroup パス）は
/// メッセージへ含めない。監査ログへの保存の配線は未実装（#839・#503。REPAIR-3）。
fn from_exec_error(err: ExecError) -> TraitError {
    let violation = err.violation.as_ref().map_or_else(String::new, |v| {
        format!(
            " (violation: {}/{}, {})",
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id
        )
    });
    TraitError::new(
        err.code,
        format!("exec stage {:?}: {}{violation}", err.stage, err.message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerStatus, StateRevision,
    };
    use std::num::NonZeroU32;

    fn record(status: ContainerStatus) -> StateRecord {
        StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap()
    }

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    /// SUP-6: Running 以外・pid なしは FailedPrecondition。
    #[test]
    fn sup6_identify_rejects_non_running_or_pidless() {
        let pid = NonZeroU32::new(std::process::id());
        for st in [
            ContainerStatus::created(cid(), pid),
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), None),
        ] {
            let err = identify_pid1(&record(st)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "container is not running or has no recorded pid; cannot identify pid1"
            );
        }
    }

    /// SUP-6・SEC-1: cgroup 配置の記録がなければ pid の同一性を確認できないため拒否する。
    #[test]
    fn sup6_identify_rejects_missing_cgroup_placement() {
        let pid = NonZeroU32::new(std::process::id());
        let err = identify_pid1(&record(ContainerStatus::running(cid(), pid))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container has no recorded cgroup placement; cannot verify pid1 identity"
        );
    }

    /// SUP-6・SEC-1・SEC-4: cgroup 配置の記録があれば、記録の型のまま core の検証まで進む。自プロセスは
    /// 入れ子の PID 1 でないため SetNs 段で拒否され、違反の種別・理由コード・ビヘイビア ID がメッセージに残る。
    #[test]
    fn sup6_identify_with_placement_reaches_core_verification() {
        let pid = NonZeroU32::new(std::process::id());
        let rec = record(ContainerStatus::running(cid(), pid)).with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/user.slice/x.scope").unwrap(),
            StateRevision::from_raw(7),
        ));
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target is not PID 1 of a directly nested PID namespace \
             (violation: exec_target/exec_target_not_nested_pid1, SUP-6)"
        );
    }

    /// SUP-6: 違反記録のないエラー（システムエラー）は、段とメッセージだけを写す。
    #[test]
    fn sup6_identify_missing_pid_has_no_violation_suffix() {
        let rec = record(ContainerStatus::running(cid(), NonZeroU32::new(4_194_305))).with_cgroup(
            CgroupPlacement::new(CgroupScope::new("/").unwrap(), StateRevision::from_raw(7)),
        );
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(
            err.message().starts_with("exec stage SetNs: pidfd_open"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("violation"), "{}", err.message());
    }

    /// SUP-6・TASK-163.2: cgroup join の公開入口の型（検証済みの `ExecTarget` だけから準備でき、参加は準備の結果を
    /// 消費する）。実 pid1 を要する成功経路は core のユニットテスト（`sup6_task163_2_*`）と #503 の統合
    /// テストが担い、ここでは配線の型が保たれていることだけを機械照合する。
    #[test]
    fn sup6_task163_2_cgroup_join_entry_points_have_expected_shape() {
        let _prepare: fn(&ExecTarget) -> Result<ExecCgroupJoin, TraitError> = prepare_cgroup_join;
        let _join: fn(ExecCgroupJoin) -> Result<ExecCgroupJoinReport, TraitError> = join_cgroup;
    }

    /// SUP-6・TASK-163.3: seccomp / Landlock 再適用の公開入口の型（検証済みの `ExecTarget` と記録から準備でき、
    /// 適用は準備の結果を消費する）。実 pid1 を要する成功経路は core のユニットテスト・結合試験
    /// （`exec_restrictions_reapply`）と #503 の統合テストが担い、ここでは配線の型だけを機械照合する。
    #[test]
    fn sup6_task163_3_restrictions_entry_points_have_expected_shape() {
        let _prepare: fn(&ExecTarget) -> Result<ExecRestrictions, TraitError> =
            prepare_restrictions;
        let _reapply: fn(ExecRestrictions) -> Result<ExecRestrictionReport, TraitError> =
            reapply_restrictions;
        // exec の許可は証跡 `ExecReady` だけ（結果そのもの・真偽値では表さない。SEC-1）。
        let _ready: fn(ExecRestrictionReport) -> Result<ExecReady, TraitError> = require_exec_ready;
    }

    /// 祖先に symlink を含まない使い捨ての bundle ディレクトリ（rootfs の固定は symlink を辿らない）。
    fn bundle_dir(name: &str) -> std::path::PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = base.join(format!(
            "fandhe-sup-exec-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const MINIMAL_CONFIG: &[u8] = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#;

    /// SUP-6・TASK-163.3: `config.json` が無い bundle は `NotFound` で拒否し、メッセージに bundle のパスを出さない。
    #[test]
    fn sup6_task163_3_missing_config_is_not_found_without_path() {
        let dir = bundle_dir("missing");
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "exec stage Landlock: failed to read config.json"
        );
    }

    /// SUP-6・TASK-163.3: 不正な JSON の `config.json` は `InvalidArgument`。
    #[test]
    fn sup6_task163_3_invalid_config_is_invalid_argument() {
        let dir = bundle_dir("invalid");
        std::fs::write(dir.join("config.json"), b"{not json").unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().starts_with("exec stage Landlock: "),
            "{}",
            err.message()
        );
    }

    /// SUP-6・SEC-1・TASK-163.3: 正しい `config.json` と rootfs ディレクトリがあれば、設定を読み rootfs を
    /// 固定できる。固定した fd は bundle 配下の `rootfs` ディレクトリそのもの（`st_dev`・`st_ino` が一致）。
    #[test]
    fn sup6_task163_3_loads_config_and_pins_bundle_rootfs() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = bundle_dir("ok");
        std::fs::write(dir.join("config.json"), MINIMAL_CONFIG).unwrap();
        std::fs::create_dir(dir.join("rootfs")).unwrap();
        let want = std::fs::metadata(dir.join("rootfs")).unwrap();
        let (config, rootfs) = load_exec_bundle(&dir).unwrap();
        let pinned = std::fs::File::from(rootfs.as_fd().try_clone_to_owned().unwrap())
            .metadata()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(config.root().path(), std::path::Path::new("rootfs"));
        assert_eq!((pinned.dev(), pinned.ino()), (want.dev(), want.ino()));
    }

    /// SUP-6・SEC-1・TASK-163.3: rootfs を固定できない bundle（不在・symlink・bundle の外を指す `root.path`）は
    /// 拒否する（照合の基準を作れないまま再適用へ進まない。fail-closed）。メッセージにパスを出さない。
    #[test]
    fn sup6_task163_3_unpinnable_rootfs_is_rejected() {
        let dir = bundle_dir("norootfs");
        std::fs::write(dir.join("config.json"), MINIMAL_CONFIG).unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs directory not found"
        );

        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("rootfs")).unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs must not contain a symlink"
        );

        std::fs::write(
            dir.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"/"}}"#,
        )
        .unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs must not be the filesystem root"
        );
    }
}
