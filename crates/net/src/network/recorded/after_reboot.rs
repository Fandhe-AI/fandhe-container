//! ホストの再起動（boot ID の違い）をまたぐ、記録だけからの detach の本体（NET-1・NET-3・SEC-1・REPAIR-4・#3412）。
//!
//! 役割: 通常の `detach_member_recorded_with` は、記録の世代（boot ID と network namespace）が現在と違うと断る
//! （nft のルールハンドルが別の boot のテーブルで再利用されうるため）。再起動後に残るメンバー記録・アドレス・
//! ポート予約（Active・解除中・墓標のすべて）は、その入口では抜けられない。本入口は **boot ID が違うときだけ**
//! それらを回収する。前の boot の bridge・veth・nsfs のマウント・nft テーブルはカーネルから消えているので、
//! 請求書にルールを載せず（`rules = None`。DELRULE を送らない）、カーネルに同名の資源が無いことの確認と、残った
//! 空の pin ファイルの除去だけを `run` に任せる（Linux 実装は `delete::member_after_reboot`）。
//! 呼び出し元の想定は supervisor（#3074）と plugin-cri（#3075）の再起動後の経路。
//!
//! # 関門（カーネル操作の前に、何も変えずに断る。fail-closed）
//! 通常の入口と同じものを引き継ぐ。
//! - 排他ロックのガード・`realized` があり未完了の操作（`realized.intent`）が無い
//! - メンバー記録があり、所有トークンがこのネットワークのもの（`DataLoss`）
//! - 同じ endpoint の回収待ちの請求書（`pending-reclaim/attach`）が無い（`reclaim_failed_attach` が世代を照合せず、
//!   作り直されたテーブルに対してルールハンドルを比べうるため。先に回収する）
//! - `netns_dir`（呼び出し側の固定設定）が記録の置き場とバイト単位で一致する
//!
//! 通常の入口と違う点は 2 つ。
//! - **boot ID が同じなら断る**。netns も同じなら通常の入口を使うよう伝え、netns だけ違う場合は資源が別の
//!   namespace で生きている可能性があるので手動回収に回す
//! - **解除の印（`unpublishing`）では断らない**。前の boot のルールは残っておらず、`unpublish_port_recorded` は
//!   世代の照合で必ず断るため、断ると抜けられなくなる
//!
//! `realized` には触れない。全メンバーを片付けた後は `delete_network_recorded` が `realized` を消す。

use std::path::Path;

use super::{
    FailedAttachClaim, HostGeneration, MemberId, NetError, NetErrorCode, NetOpKind, NetnsDirRecord,
    NetworkDeleteReport, NetworkLockGuard, PortRegistry, RecordedError, check_member_owned,
    precondition, record_net_op, require_exclusive_guard, settled_realized,
};

/// 記録だけからメンバー 1 件を、再起動をまたいで切り離す本体（OS 非依存。カーネルの照会・pin の除去は `run`）。
///
/// 手順は、関門 → 請求書の合成（veth・netns のみ。ルール無し・quarantine 無し）→ `run` →
/// メンバー記録の削除 → ポート予約の解放 → 意図記録の削除（記録の削除が失敗したら予約は解放しない）。`run` が失敗したら記録と予約を残して [`RecordedError::Op`]。
/// 成功したのに予約の解放・記録の削除に失敗したときは [`RecordedError::Uncommitted`]（再実行で収束する）。
/// 1 件の操作として結果と所要時間を記録する（REPAIR-4）。
// 実機の呼び出し（公開ラッパー）は Linux 限定。他 OS では試験だけが使う。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn detach_member_after_reboot_with<E, F>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    netns_dir: &Path,
    ports: &mut PortRegistry,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&FailedAttachClaim, &NetnsDirRecord) -> Result<NetworkDeleteReport, E>,
{
    record_net_op(
        guard.net_op_recorder(),
        NetOpKind::MemberDetachAfterReboot,
        || detach_after_reboot_inner(host, guard, member_id, netns_dir, ports, run),
    )
}

#[cfg(any(target_os = "linux", test))]
fn detach_after_reboot_inner<E, F>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    netns_dir: &Path,
    ports: &mut PortRegistry,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&FailedAttachClaim, &NetnsDirRecord) -> Result<NetworkDeleteReport, E>,
{
    require_exclusive_guard(guard)?;
    let realized = settled_realized(guard).map_err(RecordedError::Store)?;
    // boot ID が違うときだけ受ける。同じ boot の記録は、資源が生きているかもしれない。
    if realized.generation().boot_id() == host.boot_id() {
        return Err(RecordedError::Store(precondition(
            if realized.generation() == host {
                "member belongs to the current boot; use detach_member_recorded"
            } else {
                "record is from another network namespace of the same boot"
            },
        )));
    }
    let members = guard.members().map_err(RecordedError::Store)?;
    let Some(rec) = members.iter().find(|m| m.id() == member_id) else {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::NotFound,
            "member not found",
        )));
    };
    check_member_owned(&realized, rec).map_err(RecordedError::Store)?;
    let reclaim = guard.reclaim_records().map_err(RecordedError::Store)?;
    if reclaim
        .attach
        .iter()
        .any(|c| c.endpoint() == rec.endpoint())
    {
        return Err(RecordedError::Store(precondition(
            "endpoint has a pending reclaim record",
        )));
    }
    let dir = rec.netns_dir_record();
    if dir.path() != netns_dir {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns directory does not match the member record",
        )));
    }
    // ルールは載せない（別の boot のテーブルで同じハンドルが再利用されうる）。quarantine も立てない
    // （カーネルに何も無いと確かめたうえで、アドレスと予約は記録の削除で解放する）。
    let claim = FailedAttachClaim::from_detach(
        realized.name(),
        realized.token(),
        rec.endpoint(),
        rec.token(),
        rec.pin(),
        true,
        true,
        false,
        None,
    )
    .ok_or_else(|| {
        RecordedError::Store(NetError::new(
            NetErrorCode::Internal,
            "cannot build a reclaim claim from the member record",
        ))
    })?;
    let report = run(&claim, &dir).map_err(RecordedError::Op)?;
    let endpoint = rec.endpoint().clone();
    // 先にメンバー記録を消し、成功してから予約を解放する（NET-3「記録に受け口の行がある間は予約を保つ」）。
    // 記録の削除が失敗したら予約を解放せずに返す（fail-closed。再実行は同じ手順で収束する）。逆順だと、
    // 解放済みの予約と publish 行を持つ記録が食い違い、別メンバーの予約で次回の再構築が衝突になる。
    // 記録の削除後に共有ファイルの予約の解放だけが失敗した場合、記録は既に無いので再実行では NotFound になるが、
    // 予約表は `rebuild_port_registry_recorded` が記録から組み直すため、取り残した予約は次の再構築で消える。
    // メモリ上の予約表の `release` は失敗しない。
    let finished = guard
        .remove_member(member_id)
        .and_then(|_| ports.release(realized.name(), &endpoint).map(|_| ()))
        .and_then(|()| guard.remove_member_intent(member_id).map(|_| ()));
    match finished {
        Ok(()) => Ok(report),
        Err(error) => Err(RecordedError::Uncommitted {
            error,
            value: Box::new(report),
        }),
    }
}
