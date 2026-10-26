//! OCI Runtime の `delete`（停止済みコンテナの基本リソース解放。TASK-30.2・CORE-2・OCI-6）。
//!
//! # 役割と呼び出し元
//!
//! 停止済み（または未起動）のコンテナの cgroup（CORE-3）と状態記録を削除する（TASK-30.2・TASK-30.3）。
//! 状態記録の削除は `StateStore`（ファイルベース実装では `<id>/state.json` と空の `<id>/`。OCI-5）が担い、
//! cgroup の削除は依存注入された [`ContainerCgroupRemover`] が担う。将来の plugin 側
//! `ContainerRuntime::delete` 実装・CLI が呼び出し元になる。`ContainerRuntime` の実装は plugin 側に置く
//! （PLUG-1）ため、create / kill と同じく `StateStore`・`OpRecorder`・cgroup 削除を依存注入で受ける自由関数とした。
//! cgroup 削除の本番実装は Linux 限定の `cgroups::DelegatedCgroup`（`ContainerCgroupRemover` を実装）で、
//! 本モジュールは Linux 固有の型に依存しない（3 OS でビルドする。CLI-1）。
//!
//! # 処理順（ERR-2・REPAIR-4）
//!
//! 1. 操作名 `delete` で `OpRecorder` に記録する（全終了経路）
//! 2. `StateStore::get`。未 create または削除済みの ID は `NotFound`（二重 delete の 2 回目も同じ）
//! 3. 状態の確認（下表）。生きている可能性がある状態は fail-closed で拒否する（拒否した状態では cgroup に触れない）
//! 4. cgroup の削除（TASK-30.3・OCI-6）。レコードに cgroup の配置（[`StateRecord::cgroup`]）が
//!    記録されていなければ cgroup を作っていないので触れずに手順 5 へ進む。記録されていれば、
//!    `ContainerCgroupRemover::scope`（検出の失敗はそのエラーを返し、cgroup にもレコードにも触れない）を得て、
//!    revision を再確認してから、記録のスコープと一致すれば記録された instance で
//!    `ContainerCgroupRemover::remove_with_recorder` を、一致しなければ記録された配置で
//!    `ContainerCgroupRemover::remove_recorded` を呼ぶ（#2060 案 B。下の「委譲スコープの照合」）。
//!    `Removed` / `NotPresent` は成功として次へ進み、エラーはそのまま返してレコードを削除しない
//!    （実装は削除の直前に、直下に残った exec 用の子 cgroup を上限つきの待機で掃除してよい。#1596）
//! 5. `StateStore::delete` を get で得た revision つきで呼ぶ（楽観的排他）。revision 不一致
//!    （`FailedPrecondition`）なら get を 1 回だけやり直し、`NotFound` なら並行する delete が先に削除
//!    したとみなして `NotFound`、レコードが残っていれば再試行を促す `FailedPrecondition` を返す。
//!    成功した後、レコードに core が作った rootfs の記録（[`StateRecord::image_rootfs`]）があれば
//!    その rootfs も消す（下の「core が作った rootfs の削除」）
//!
//! 6. [`delete_releasing_image_ref`] だけが、手順 5 が成功した後にイメージ参照（OCI-7）を外す（下の
//!    「イメージ参照の解除」）
//!
//! | state | pid | force=false | force=true |
//! | ----- | --- | ----------- | ---------- |
//! | `Stopped` | - | 削除 | 削除 |
//! | `Created` | なし | 削除 | 削除 |
//! | `Created` | あり | `FailedPrecondition` | `Unimplemented` |
//! | `Running` | あり | `FailedPrecondition` | `Unimplemented` |
//! | `Running` | なし（中断された start の予約） | `FailedPrecondition` | 同左 |
//! | `Creating` | - | `FailedPrecondition` | 同左 |
//!
//! # イメージ参照の解除（OCI-7・TASK-183.8.1）
//!
//! [`delete_releasing_image_ref`] は、[`delete`] が `Ok` を返した後にだけ、
//! [`ContainerImageRefs::registration`] で確定済みの登録世代を読み、状態が無いことを確かめてから
//! [`ContainerImageRefs::release_if`] でその世代の参照を外す。`StateStore` の状態が残っている
//! （または削除を確かめられない）失敗では呼ばない。
//!
//! ID だけで外す `release` を使わないのは、状態削除から解除までの間に同じ ID の `create_with_image` が
//! 参照登録と状態作成を終えうるためである。世代つきなら、別の世代の参照は外れない。
//!
//! 削除前に世代を読んで持ち越す方式は採らない。別の delete が先にそのコンテナを消して同じ ID が再作成
//! されると、持ち越した世代が今回削除したコンテナのものではなくなり、解除が空振りして参照が残るため
//! （同 ID の再 create が `AlreadyExists`、イメージも使用中のまま残る）。状態の削除後に読む。
//! 確定済みの登録は外されるまで同じ ID の他の create が登録できないので、「世代を読む → 状態が無いことを
//! 確かめる」の順なら、読んだ世代のコンテナの状態は既に無い。読んだ後に状態があれば、並行する create が
//! 作り直した新しいコンテナなので外さない。
//!
//! 参照は create が状態作成の成功直後に [`ContainerImageRefs::bind`] で確定する。照合に状態の revision は
//! 使わない（start 等の更新で変わり、create 直後の値と一致しなくなって参照が解除されないため。#2265 の指摘）。
//! 確定していない参照（登録後〜状態作成前に止まった create のもの）は `registration` が返さないので、
//! その create の参照を外さない。状態作成後〜確定前に delete が状態を消した場合は、create が確定後に
//! 状態の不在を検知して自分で外す。
//!
//! 登録世代の読み取りや解除の失敗は delete の成否を変えず（状態は消えており、エラーで返すと再実行が
//! `NotFound` になるため）、結果は [`DeleteResponse::image_ref`] で呼び出し元へ返し、操作名
//! `image_ref_release` でも `recorder` に記録する。読み取りに失敗したときは
//! 解除しない。残った参照はデータを余分に持つ安全側で、起動時の照合（#854）が回収する。
//! 参照を登録しない [`delete`] でイメージつきのコンテナを消すと参照が残る（同じく安全側）。
//!
//! # core が作った rootfs の削除（OCI-7・OCI-5・OCI-6・#2378）
//!
//! 展開器つきの `create_with_image` が core 自身で作って公開した rootfs は、状態レコードの
//! [`StateRecord::image_rootfs`]（bundle 相対の経路と作成時の (dev, ino)）で所有を記録する。利用者が用意した
//! rootfs（通常の `create`・展開器なしの `create_with_image`）は記録が無く、delete は触れない。
//!
//! - **状態削除の成功後に消す**: start は `BundleLock` と revision の予約より前に rootfs の fd を固定するため、
//!   「状態削除の前に消す」順では、固定済みの start が使用中の rootfs を消された上で予約に進む窓が残る。
//!   状態を消した後なら、そのコンテナへの start・restart・update は revision 照合で `NotFound` になる
//! - **fail-closed**: 記録した bundle から経路を fd 相対・リンク非追従で辿り、末尾の (dev, ino) が記録と
//!   一致するときだけ消す。symlink・ディレクトリでないもの・差し替えは `FailedPrecondition` で何も消さない。
//!   既に無ければ成功扱い
//! - **失敗は delete を `Err` にしない**: 状態は既に消えており、エラーを返すと再実行が `NotFound` になる
//!   （`image_ref_release` と同じ）。結果は [`DeleteResponse::image_rootfs`]（`Kept { code }` 等。#2633）に載せ、
//!   操作名 `image_rootfs_remove` で `recorder` にも記録し、木は残す。残った木が
//!   あると同じ bundle の次の `create_with_image` は `AlreadyExists` になるため、手動で消す。孤児の自動回収は
//!   本件の対象外。設計と制約は `docs/design/image-rootfs-lifetime.md`
//! - **bundle の所有ロックを保持して消す**: 状態削除の前から rootfs の後始末の完了まで `BundleLock` を保持し、
//!   create・start と排他する（ロックは bundle が指す実体に取り、symlink 経由の表記でも同じ実体なら排他する）。
//!   他の保持者がいれば何も変えず `FailedPrecondition`。それでもロックを取れない理由（Linux 以外等）では、
//!   状態は消すが rootfs は消さず、失敗として記録する
//!
//! # cgroup を先に消す理由（OCI-6・CORE-3）
//!
//! cgroup を先に消すので、削除に失敗したとき（孤児プロセスが残って空でない場合は `FailedPrecondition`）も
//! レコードが残り、再実行できる（fail-closed）。逆順にすると、cgroup の削除に失敗した時点で再試行の
//! 手掛かりが消え、cgroup がリークする。cgroup を消した後で手順 5 が revision 不一致になっても、再実行時の
//! remover は `NotPresent` を返すため冪等である。
//!
//! # 委譲スコープの照合（OCI-6・CORE-3）
//!
//! remover は自分の委譲スコープの下でコンテナ用 cgroup を探すため、create と別の委譲スコープから呼ばれると
//! 実在する cgroup を見つけられず `NotPresent` を返す。照合なしにそれを成功扱いにすると、cgroup を
//! 残したまま再試行の手掛かりである状態記録だけを消してしまう。そこでスコープを状態に記録し
//! （本番の経路では start で supervisor が `UpdateStateRequest::with_cgroup_scope` により追記する。#1314・
//! TASK-32 追補。create 時の `CreateStateRequest::with_cgroup_scope` も有効）、削除側のスコープが一致したときだけ
//! `remove_with_recorder` の `NotPresent` を「cgroup 無し」の確認として扱う。
//!
//! 一致しないとき（別の端末・別のスコープからの delete、systemd がスコープを回収した後の delete）は、
//! #1314 の決定（3-ii）では `FailedPrecondition` で拒否していたが、#2060 のオーナー決定（2026-10-16・案 B）で
//! 変更した。`ContainerCgroupRemover::remove_recorded` に記録された配置（スコープ・instance）を渡し、
//! 実装が記録のスコープを fd 起点で検証つきに直接開いてコンテナ cgroup を消す（Linux の実装は
//! `cgroups::RecordedCgroupScope`）。検証に失敗すれば何も消さずエラーを返し、状態記録は残す（fail-closed）。
//! 既定実装は従来どおり `FailedPrecondition` を返す。スコープの検出自体が失敗した場合は記録の経路へ
//! 回さず、そのエラーを返す（壊れた環境で記録の経路を使わない安全側の判断。#2133 で再検討し維持した。
//! 理由と回避策は CLI の `stop_delete` の module doc）。
//!
//! # 削除・再作成との競合（OCI-6・CORE-2）
//!
//! cgroup の削除は名前指定（`unlinkat`）で、`StateStore` の楽観的排他とは原子的に組み合わせられない。
//! そこでコンテナ用 cgroup の名前に、レコードの create で割り当てた revision（instance。[`StateRecord::cgroup`]）
//! を含める（`fc-<id>@<instance>`）。revision はストア全体で再利用されないため、同じ ID が削除・再作成されると
//! 新しいコンテナの cgroup は別の名前になる。古いレコードを読んだ delete が消せるのは、そのレコードの
//! instance の名前（既に消えていれば `NotPresent`）だけで、再作成後のコンテナの cgroup には届かない。
//! 手順 4 の revision 再確認は無駄な cgroup 操作を省く早期終了で、この安全性の根拠ではない。
//!
//! # 安全性（SEC-1・CORE-1）
//!
//! - start との競合: 削除できる状態は `Stopped` と pid のない `Created` だけである。並行する start が予約した
//!   あとで子 cgroup にプロセスが参加済みなら cgroup は空でないため削除できず（`FailedPrecondition`）、
//!   空の段階で消された場合は子の参加（fd 経由の `cgroup.procs` 書き込み）が失敗して start は fail-closed で
//!   終わる。生きているプロセスの cgroup を消す経路は無い
//! - 記録された pid の生存確認（`kill(pid, 0)`・`/proc`）はしない。PID 再利用の恐れがあるため、判定の
//!   正は `StateStore` の状態とする。kill は状態を更新しないので、kill 直後は supervisor（TASK-157）が
//!   Stopped へ遷移させるまで Running のままで、その間の delete は `FailedPrecondition` になる（意図した挙動）
//! - start との排他は revision 照合だけで足りる。start は launch の前に Created → Running へ予約更新するため、
//!   競合する delete は revision 不一致で失敗する
//! - start の所有ロック（`BundleLock`）は取らない。launch の進行中・上限超過（`Timeout`）・後始末で回収を
//!   確認できずハンドルを未回収レジストリ（`take_unreaped_processes`）へ残した経路では、start は予約
//!   （Running・pid なし）を Created へ戻さないため、delete は上表どおり拒否し、生きている可能性のある
//!   プロセスの記録を消さない。予約を Created へ戻すのは、launch がプロセスを返さなかった場合・起動済み
//!   プロセスの回収を確認できた場合・`recover_interrupted_start` が生存プロセス無しを確かめた場合だけで
//!   ある（CORE-2・SEC-1）
//!
//! # 到達範囲（REPAIR-3）
//!
//! - 本関数が解放するのは cgroup（[`ContainerCgroupRemover`]）と `StateStore` のレコード（ファイルベース実装では
//!   状態ファイル）、および core が作った rootfs（記録がある場合だけ。#2378）である。bundle 自体と利用者が用意した
//!   rootfs は消さない。OCI-7 の参照解除は [`delete_releasing_image_ref`] が担う（TASK-183.8.1）。
//!   本番のアダプタと CLI / plugin からの配線は未実装
//! - 本番の呼び出し元（CLI / plugin / supervisor）が `DelegatedCgroup::detect` で得たスコープを渡す結線と、
//!   本番の create がスコープを記録する結線（`oci_runtime::create` は記録しない）は未実装（create / start が
//!   本番ではまだ cgroup を作らないため。TASK-29 / TASK-157 系）
//! - `force`（停止してから削除。`ContainerRuntime::delete` の契約）は stop が未実装のため、生きている
//!   可能性のある状態では `Unimplemented` で拒否する
//!
//! エラーメッセージは固定文言のみで、pid・パス・errno を含めない。

use super::error::{LifecycleOp, OciRuntimeError};
use super::image_refs::{ContainerImageRefs, ImageRefRelease};
use super::image_rootfs::{
    ImageRootfsPrivilege, RecordedRootfsRemoval, remove_recorded_rootfs_with,
};
use super::launch::BundleLock;
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    CgroupPlacement, CgroupScope, CleanupOutcome, ContainerId, ContainerState, DeleteRequest,
    DeleteResponse, DeleteStateRequest, ErrorCode, GetStateRequest, StateRecord, StateRevision,
    StateStore, TraitError,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const DELETE_OP_NAME: &str = "delete";

/// core が作った rootfs の削除の操作名（REPAIR-4。OCI-7・#2378）。
const IMAGE_ROOTFS_REMOVE_OP_NAME: &str = "image_rootfs_remove";

/// 参照解除の操作名（REPAIR-4）。
const IMAGE_REF_RELEASE_OP_NAME: &str = "image_ref_release";
/// 参照の登録世代の読み取りの操作名（REPAIR-4）。
const IMAGE_REF_LOOKUP_OP_NAME: &str = "image_ref_lookup";

/// [`ContainerCgroupRemover::remove`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupRemoval {
    /// 対応する cgroup を削除した。
    Removed,
    /// 対応する cgroup が存在しなかった（削除済み・未作成。成功扱い）。
    NotPresent,
}

/// コンテナ用 cgroup の削除（CORE-3・OCI-6・TASK-30.3）。[`delete`] が状態記録の削除の前に呼ぶ。
///
/// 本番実装は Linux 限定の `cgroups::DelegatedCgroup`。呼び出し元（CLI / plugin / supervisor）が検出した
/// 委譲スコープを渡す。契約:
///
/// - 対象は `id` と instance（状態記録の create で割り当てた revision）に対応する、このランタイムが CORE-3 で
///   作ったコンテナ用子 cgroup（Linux では `fc-<id>@<instance>`）だけである。同じ ID でも instance が違う
///   cgroup（削除・再作成後のコンテナ）には触れない
/// - [`Self::scope`] は `remove` が探索する委譲スコープを、[`CgroupScope`] の正規形で返す。[`delete`] は
///   これを状態に記録されたスコープと照合し、一致したときだけ `remove` を呼ぶ
/// - 存在しなければ [`CgroupRemoval::NotPresent`] を返す（成功扱い。再実行の冪等性のため）。`NotPresent` は
///   [`Self::scope`] の配下に無いことだけを意味する
/// - プロセスが残っていて空でない場合は [`ErrorCode::FailedPrecondition`] を返す
/// - 直下に残った exec 用の子 cgroup（`exec-*`）は、実装が上限つきの待機（`cgroup.kill` の後に空になるまで。
///   全体で 5 秒）で止めて消してから、コンテナ cgroup を削除してよい（#1596・SUP-6）。待機の超過は
///   [`ErrorCode::Timeout`]、掃除が完了しなければ `remove` はエラーを返し、コンテナ cgroup には触れない
/// - **`remove` は停止済み（[`delete`] の状態判定で `Stopped` か pid なしの `Created`）のコンテナに対してだけ
///   呼ぶ**。実装は呼び出し側の判定に頼らず、`exec-*` を止める前にコンテナ cgroup 自身にプロセスが居ないことを
///   確かめ、居れば何も止めずに [`ErrorCode::FailedPrecondition`] を返す（稼働中の exec コマンドを止めない。
///   OCI-6・CORE-2・SUP-6）
/// - エラーのメッセージにパス・errno を含めない（`code` だけを機械可読な判定に使う）
pub trait ContainerCgroupRemover: Send + Sync {
    /// `remove` が対象とする委譲スコープ（コンテナ用子 cgroup の親）を返す。
    ///
    /// 正規形にできない場合はエラーを返す（[`delete`] は照合できないため状態記録を削除しない）。
    fn scope(&self) -> Result<CgroupScope, TraitError>;

    /// `id` と `instance`（[`crate::traits::CgroupPlacement::instance`]）に対応する cgroup を削除する。
    fn remove(
        &self,
        id: &ContainerId,
        instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError>;

    /// [`Self::remove`] と同じ削除を、[`delete`] に注入された `recorder` へ観測値を記録しながら行う
    /// （REPAIR-4・#1596。[`delete`] はこちらを呼ぶ）。
    ///
    /// 既定実装は `recorder` を使わず [`Self::remove`] へ委ねる。削除の途中に記録すべき観測値を持つ実装
    /// （Linux の `cgroups::DelegatedCgroup` は残留 `exec-*` の掃除の成否・件数）だけが上書きする。
    fn remove_with_recorder(
        &self,
        id: &ContainerId,
        instance: StateRevision,
        recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        let _ = recorder;
        self.remove(id, instance)
    }

    /// 記録された配置のスコープが [`Self::scope`] と食い違うときに [`delete`] が呼ぶ（#2060 案 B・OCI-6・CORE-3）。
    ///
    /// 実装は `placement` のスコープを検証つきで直接開き（所有者・種別・名前を確かめ、ID だけからパスを
    /// 組み立てない）、`placement.instance()` のコンテナ cgroup だけを、空であることを確かめてから消す。
    /// 検証に 1 つでも失敗したら何も kill・削除せずエラーを返す。スコープ自体が無ければ
    /// [`CgroupRemoval::NotPresent`]。エラーのメッセージにパス・errno を含めない。
    ///
    /// 既定実装は何もせず、従来の挙動（`FailedPrecondition`）を返す。
    fn remove_recorded(
        &self,
        id: &ContainerId,
        placement: &CgroupPlacement,
        recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        let _ = (id, placement, recorder);
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "delegated cgroup scope does not match the recorded scope",
        ))
    }
}

/// [`delete_with_options`] の設定（将来の拡張に備え非網羅。#2540）。
///
/// 既定は従来の挙動（core が作った rootfs の木をホストの実効 ID で消す）。
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DeleteOptions {
    rootfs_privilege: ImageRootfsPrivilege,
}

impl DeleteOptions {
    /// 既定の設定。
    pub fn new() -> Self {
        Self::default()
    }

    /// core が作った rootfs の木を消す権限を指定する（SEC-5・#2540）。
    ///
    /// 状態レコードの `imageRootfs.ownership` が `subordinate`（rootless の userns 展開で subuid 所有の
    /// inode を含む）のコンテナは、`SubordinateIds` でないと消せない。権限が無いとき、delete は状態を消した
    /// うえで木を残し、`image_rootfs_remove` の失敗として記録する。
    pub fn with_rootfs_privilege(mut self, privilege: ImageRootfsPrivilege) -> Self {
        self.rootfs_privilege = privilege;
        self
    }
}

/// 停止済みまたは未起動のコンテナの cgroup と状態記録を削除する。
///
/// 状態の確認後、`cgroups` で cgroup を削除してから状態記録を削除する（順序の根拠はモジュール doc）。
/// cgroup の削除に失敗した場合はそのエラーを返し、状態記録は残す。レコードに cgroup スコープが
/// 記録されていなければ cgroup には触れず、記録されたスコープと `cgroups.scope()` が一致しなければ
/// [`ContainerCgroupRemover::remove_recorded`] で記録のスコープを検証つきで直接開いて消す（#2060 案 B。
/// 既定実装は [`ErrorCode::FailedPrecondition`] で、cgroup にも状態記録にも触れない）。
///
/// 未 create・削除済みの ID は [`ErrorCode::NotFound`]（二重 delete は 2 回目が `NotFound`）、
/// 生きている可能性のある状態は [`ErrorCode::FailedPrecondition`]、`force` で生きているコンテナを
/// 削除する要求は [`ErrorCode::Unimplemented`]。成功・失敗の件数と所要時間は `recorder` へ操作名
/// `delete` で記録する（全終了経路。REPAIR-4）。同じ `recorder` を
/// [`ContainerCgroupRemover::remove_with_recorder`] にも渡し、cgroup 削除中の観測値（残留 `exec-*` の掃除の
/// 件数等）を同じ記録器へ集める。
///
/// 失敗は [`OciRuntimeError`]（op = delete・内部エラーと同一の code・非ゼロの `exit_code`）で返す。標準エラーへの
/// 書き出しとプロセス終了は呼び出し元（CLI・plugin）の責務（ERR-2・TASK-96.3）。
pub fn delete(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
) -> Result<DeleteResponse, OciRuntimeError> {
    delete_with_options(store, recorder, cgroups, req, &DeleteOptions::default())
}

/// [`delete`] に、core が作った rootfs の削除の権限（[`DeleteOptions`]）を指定したもの（#2540・SEC-5）。
pub fn delete_with_options(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
    options: &DeleteOptions,
) -> Result<DeleteResponse, OciRuntimeError> {
    // 変換は最上位 1 か所のみ。内部関数は `TraitError` のまま（波及最小）。
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Delete, e);
    let name = OpName::new(DELETE_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || {
        delete_inner(store, recorder, cgroups, req, options).map_err(to_err)
    })
}

/// [`delete`] に、OCI-7 のイメージ参照の解除を後置したもの（TASK-183.8.1）。
///
/// [`delete`] が `Ok` を返した後にだけ `refs.release` を呼ぶ（根拠はモジュール doc「イメージ参照の解除」）。
/// 解除の結果は [`DeleteResponse::image_ref`] へ載せ（失敗は `Kept { code }`。delete の成否は変えない）、
/// 操作名 `image_ref_release` でも `recorder` に記録する（REPAIR-4）。
pub fn delete_releasing_image_ref(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    refs: &dyn ContainerImageRefs,
    req: &DeleteRequest,
) -> Result<DeleteResponse, OciRuntimeError> {
    delete_releasing_image_ref_with_options(
        store,
        recorder,
        cgroups,
        refs,
        req,
        &DeleteOptions::default(),
    )
}

/// [`delete_releasing_image_ref`] に、[`DeleteOptions`] を指定したもの（#2540・SEC-5）。
pub fn delete_releasing_image_ref_with_options(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    refs: &dyn ContainerImageRefs,
    req: &DeleteRequest,
    options: &DeleteOptions,
) -> Result<DeleteResponse, OciRuntimeError> {
    let response = delete_with_options(store, recorder, cgroups, req, options)?;
    Ok(response.with_image_ref(release_image_ref(store, recorder, refs, req)))
}

/// 状態削除後のイメージ参照の解除（結果は [`DeleteResponse::image_ref`] へ写す。REPAIR-4）。
///
/// 先に登録世代を読み、そのあとで状態が無いことを確かめる（この順序が要点）。
/// 確定済みの登録は、外されるまで同じ ID の他の create が登録できないので、状態が無い時点で読んだ
/// 確定済みの世代は、削除したコンテナ（または既に消えた別のコンテナ）のものである。読んだ後に状態が
/// 存在するなら、それは並行する create が作り直した新しいコンテナで、外さない（OCI-7）。
fn release_image_ref(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    refs: &dyn ContainerImageRefs,
    req: &DeleteRequest,
) -> CleanupOutcome {
    let Ok(lookup_name) = OpName::new(IMAGE_REF_LOOKUP_OP_NAME) else {
        return CleanupOutcome::Kept {
            code: ErrorCode::Internal,
        };
    };
    let generation = match recorder.record_op(&lookup_name, || refs.registration(req.id())) {
        Err(e) => return CleanupOutcome::Kept { code: e.code() },
        Ok(None) => return CleanupOutcome::AlreadyAbsent,
        Ok(Some(generation)) => generation,
    };
    match store.get(&GetStateRequest::new(req.id().clone())) {
        Err(e) if e.code() == ErrorCode::NotFound => {}
        // 並行する create が作り直したコンテナの参照なので外さない（自分の後始末の対象ではない）。
        Ok(_) => return CleanupOutcome::NotApplicable,
        Err(e) => return CleanupOutcome::Kept { code: e.code() },
    }
    let Ok(release_name) = OpName::new(IMAGE_REF_RELEASE_OP_NAME) else {
        return CleanupOutcome::Kept {
            code: ErrorCode::Internal,
        };
    };
    match recorder.record_op(&release_name, || refs.release_if(req.id(), generation)) {
        Ok(ImageRefRelease::Released) => CleanupOutcome::Removed,
        Ok(ImageRefRelease::NotRegistered) => CleanupOutcome::AlreadyAbsent,
        Err(e) => CleanupOutcome::Kept { code: e.code() },
    }
}

fn delete_inner(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
    options: &DeleteOptions,
) -> Result<DeleteResponse, TraitError> {
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    check_deletable(&record, req.force())?;
    // core が作った rootfs を持つコンテナは、状態削除から rootfs の後始末の完了まで bundle の所有ロックを保持する。
    // 状態削除でストアのロックが外れた後に、同じ bundle を採用する create・start が成功して、旧 delete が
    // 新しいコンテナの rootfs を消すのを防ぐ（create・start も同じロックを取る。OCI-7・#2378）。
    // ロックは bundle が指す実体に取る（祖先が symlink でも、実体の絶対パスで同じ bundle を指す create と排他する）。
    // 他の delete・start が保持中なら何も変えずに `FailedPrecondition` で再試行を促す。それでもロックを取れない
    // 他の理由（Linux 以外等）では、状態は消すが rootfs は消さずに残す（排他なしで消すと、状態削除の後に
    // 同じ実体を採用した create の rootfs を消しうるため。fail-closed）。
    let rootfs_lock = if record.image_rootfs().is_some() {
        match BundleLock::acquire_resolved(record.bundle()) {
            Err(e) if e.code() == ErrorCode::FailedPrecondition => return Err(e),
            other => Some(other),
        }
    } else {
        None
    };
    // 配置の記録が無いレコードは cgroup を作っていない（`StateRecord::cgroup`）ので触れない。
    if let Some(placement) = record.cgroup() {
        // 検出の失敗は記録の経路へ回さず fail-closed で返す（モジュール doc「委譲スコープの照合」）。
        let scope_matches = cgroups.scope()? == *placement.scope();
        // revision が変わっていれば cgroup に触れず再試行を促す早期終了。再作成後のコンテナの cgroup を
        // 消さないことは、instance を含む名前の一意性で保証する（モジュール doc「削除・再作成との競合」）。
        let current = store.get(&GetStateRequest::new(req.id().clone()))?;
        if current.revision() != record.revision() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container state changed during delete; retry",
            ));
        }
        // 別の委譲スコープでの `NotPresent` は「cgroup 無し」の確認にならないので、不一致のときは
        // 記録のスコープを検証つきで直接開く経路へ渡す（#2060 案 B）。Removed / NotPresent はどちらも
        // 記録されたスコープ・instance で「cgroup が無い」状態に到達したので次へ進む。失敗はレコードを残して返す。
        let removal = if scope_matches {
            cgroups.remove_with_recorder(req.id(), placement.instance(), recorder)?
        } else {
            cgroups.remove_recorded(req.id(), placement, recorder)?
        };
        match removal {
            CgroupRemoval::Removed | CgroupRemoval::NotPresent => {}
        }
    }
    let delete_req = DeleteStateRequest::new(req.id().clone(), record.revision());
    match store.delete(&delete_req) {
        Ok(_) => {
            // 状態を消した実際の revision のレコード（関数の先頭で読んだもの）に付いた記録だけを使う。
            let outcome = remove_core_created_rootfs(
                recorder,
                &record,
                rootfs_lock.as_ref(),
                &options.rootfs_privilege,
            );
            Ok(DeleteResponse::new().with_image_rootfs(outcome))
        }
        Err(e) if e.code() == ErrorCode::FailedPrecondition => {
            // get の後に状態が進んだか、並行する delete が先に削除した。1 回だけ確認する。
            match store.get(&GetStateRequest::new(req.id().clone())) {
                Err(g) => Err(g),
                Ok(_) => Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container state changed during delete; retry",
                )),
            }
        }
        Err(e) => Err(e),
    }
}

/// 状態削除の成功後に、core が `create_with_image` で作った rootfs を消す（OCI-7・OCI-5・#2378）。
///
/// 記録（[`StateRecord::image_rootfs`]）が無いレコード（利用者が用意した rootfs）では何もせず
/// [`CleanupOutcome::NotApplicable`] を返す。失敗は delete を `Err` にせず（状態は既に消えており、エラーを返すと再実行が `NotFound` になる。`image_ref_release`
/// と同じ考え方）、操作名 `image_rootfs_remove` で `recorder` に記録して木を残す。残った木は手動で消す
/// （`docs/design/image-rootfs-lifetime.md`）。
///
/// `lock` は [`delete_inner`] が状態削除の前に取った bundle の所有ロックの結果。ロックを保持しているときだけ
/// 消す。取れなかった場合（Linux 以外・bundle を開けない等）は消さずに木を残し、同じ操作名で失敗として
/// 記録する。排他なしで消すと、状態削除の後に同じ ID・同じ実体の rootfs を採用した create のコンテナの
/// rootfs を消しうるため（OCI-7 の使用中 rootfs の保持。fail-closed）。bundle 自体が無い（`NotFound`）なら
/// 消す物も無いので `NotPresent` として記録する。
///
/// 戻り値は [`DeleteResponse::image_rootfs`] へ載せる結果（`Removed`・`AlreadyAbsent`・`Kept { code }`。
/// 呼び出し側の CLI・plugin が利用者へ伝える。#2633・REPAIR-4）。
fn remove_core_created_rootfs(
    recorder: &OpRecorder,
    record: &StateRecord,
    lock: Option<&Result<BundleLock, TraitError>>,
    privilege: &ImageRootfsPrivilege,
) -> CleanupOutcome {
    let Some(rec) = record.image_rootfs() else {
        return CleanupOutcome::NotApplicable;
    };
    let Ok(name) = OpName::new(IMAGE_ROOTFS_REMOVE_OP_NAME) else {
        // 操作名を作れない（定数のため通常起きない）場合は、消さずに残したことを分類つきで返す。
        return CleanupOutcome::Kept {
            code: ErrorCode::Internal,
        };
    };
    let result = recorder.record_op(&name, || match lock {
        Some(Ok(_held)) => remove_recorded_rootfs_with(record.bundle(), rec, privilege),
        Some(Err(e)) if e.code() == ErrorCode::NotFound => Ok(RecordedRootfsRemoval::NotPresent),
        Some(Err(e)) => Err(TraitError::new(
            e.code(),
            "bundle lock is unavailable; image rootfs was kept",
        )),
        None => Err(TraitError::new(
            ErrorCode::Internal,
            "bundle lock was not taken; image rootfs was kept",
        )),
    });
    match result {
        Ok(RecordedRootfsRemoval::Removed) => CleanupOutcome::Removed,
        Ok(RecordedRootfsRemoval::NotPresent) => CleanupOutcome::AlreadyAbsent,
        Err(e) => CleanupOutcome::Kept { code: e.code() },
    }
}

/// 状態の判定表（モジュール doc）。`ContainerState` の追加をコンパイルエラーで検出するため網羅で書く。
fn check_deletable(record: &StateRecord, force: bool) -> Result<(), TraitError> {
    let status = record.status();
    match (status.state(), status.pid()) {
        (ContainerState::Stopped, _) | (ContainerState::Created, None) => Ok(()),
        (ContainerState::Created | ContainerState::Running, Some(_)) => {
            if force {
                Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "force delete of a live container is not implemented",
                ))
            } else {
                Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is still running",
                ))
            }
        }
        (ContainerState::Running, None) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container start was interrupted; recover the start reservation",
        )),
        (ContainerState::Creating, _) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container creation is in progress",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::{ImageRefGeneration, ImageRefRelease};
    use crate::traits::{
        CgroupPlacement, ContainerId, ContainerStatus, CreateStateRequest, DeleteStateResponse,
        ListStateRequest, StateList, StateRevision, UpdateStateRequest,
    };
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::Mutex;

    /// テスト専用のインメモリ `StateStore`（delete は revision 照合つき）。
    ///
    /// revision は `StateStore::create` の再利用禁止契約どおりストア全体で 1 から単調に採番し、同じ ID の
    /// 削除・再作成でも過去の値を再発行しない（`next_revision` は最後に払い出した値）。
    #[derive(Default)]
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        next_revision: Mutex<u64>,
        /// Some なら最初の delete の照合前に、同じ ID を別クライアントが削除してこの状態で再作成した
        /// ことを再現する（get と delete の間の削除・再作成の競合）。
        recreate_before_delete: Mutex<Option<ContainerStatus>>,
        /// Some なら 2 回目の get の前に、同じ ID を別クライアントが削除してこの状態で再作成した
        /// ことを再現する（最初の get と cgroup 削除前の revision 再確認の間の削除・再作成の競合）。
        recreate_before_second_get: Mutex<Option<ContainerStatus>>,
        /// get の呼び出し回数。
        gets: Mutex<u32>,
        /// true なら delete で常に revision 不一致を返す。
        stale_delete: bool,
        /// stale_delete 時に delete の中でレコードを消す（並行する delete の再現）。
        remove_on_stale: bool,
    }

    impl MemStateStore {
        fn with(status: ContainerStatus) -> Self {
            let s = Self::default();
            s.create(
                &CreateStateRequest::new(status, std::env::temp_dir().join("b")).expect("req"),
            )
            .expect("create");
            s
        }
        /// cgroup スコープ `scope` を記録したレコードを 1 件持つストア（TASK-30.3）。
        fn with_scope(status: ContainerStatus, scope: &str) -> Self {
            let s = Self::default();
            s.create(
                &CreateStateRequest::new(status, std::env::temp_dir().join("b"))
                    .expect("req")
                    .with_cgroup_scope(CgroupScope::new(scope).expect("scope")),
            )
            .expect("create");
            s
        }
        /// ストア全体で一意な revision を 1 つ払い出す。
        fn allocate_revision(&self) -> StateRevision {
            let mut last = self.next_revision.lock().unwrap_or_else(|e| e.into_inner());
            *last = last.checked_add(1).expect("revision overflow");
            StateRevision::from_raw(*last)
        }
        fn has(&self, id: &str) -> bool {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&cid(id))
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let revision = self.allocate_revision();
            let mut record =
                StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
            // `StateStore` の契約 8: instance はこの create で割り当てた revision。
            if let Some(scope) = req.cgroup_scope() {
                record = record.with_cgroup(CgroupPlacement::new(scope.clone(), revision));
            }
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }
        fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let nth = {
                let mut gets = self.gets.lock().unwrap_or_else(|e| e.into_inner());
                *gets += 1;
                *gets
            };
            if nth == 2 {
                let recreate = self
                    .recreate_before_second_get
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(status) = recreate {
                    self.records
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(req.id());
                    self.create(
                        &CreateStateRequest::new(status, std::env::temp_dir().join("b2"))
                            .expect("req")
                            .with_cgroup_scope(CgroupScope::new(SCOPE).expect("scope")),
                    )?;
                }
            }
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }
        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            let recreate = self
                .recreate_before_delete
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(status) = recreate {
                self.records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(req.id());
                self.create(
                    &CreateStateRequest::new(status, std::env::temp_dir().join("b2")).expect("req"),
                )?;
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if self.stale_delete {
                if self.remove_on_stale {
                    records.remove(req.id());
                }
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            let cur = records
                .get(req.id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            records.remove(req.id());
            Ok(DeleteStateResponse::new())
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn pid(n: u32) -> Option<NonZeroU32> {
        Some(NonZeroU32::new(n).expect("pid"))
    }

    /// テストで記録する委譲スコープ（`RecordingRemover` の既定スコープと同じ）。
    const SCOPE: &str = "/user.slice/user-1000.slice/a.scope";

    /// テスト専用の記録用 `ContainerCgroupRemover`。`remove` に渡された ID・instance と `scope` の呼び出し回数を
    /// 記録し、決まった結果を返す。
    struct RecordingRemover {
        calls: Mutex<Vec<ContainerId>>,
        instances: Mutex<Vec<StateRevision>>,
        scope_calls: Mutex<u32>,
        scope: Result<CgroupScope, TraitError>,
        result: Mutex<Result<CgroupRemoval, TraitError>>,
        /// `remove_recorded` の呼び出し（ID と配置）。
        recorded_calls: Mutex<Vec<(ContainerId, CgroupPlacement)>>,
        /// Some なら `remove_recorded` を上書きしてこの結果を返す。None は trait の既定実装（fail-closed）。
        recorded_result: Option<Result<CgroupRemoval, TraitError>>,
    }

    impl RecordingRemover {
        fn returning(result: Result<CgroupRemoval, TraitError>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                instances: Mutex::new(Vec::new()),
                scope_calls: Mutex::new(0),
                scope: CgroupScope::new(SCOPE),
                result: Mutex::new(result),
                recorded_calls: Mutex::new(Vec::new()),
                recorded_result: None,
            }
        }
        /// `remove_recorded` を上書きして `result` を返す（#2096）。
        fn with_recorded(mut self, result: Result<CgroupRemoval, TraitError>) -> Self {
            self.recorded_result = Some(result);
            self
        }
        fn recorded_calls(&self) -> Vec<(ContainerId, CgroupPlacement)> {
            self.recorded_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
        /// 委譲スコープを差し替える（`Err` は `scope` の失敗を再現する）。
        fn in_scope(mut self, scope: Result<CgroupScope, TraitError>) -> Self {
            self.scope = scope;
            self
        }
        fn scope_calls(&self) -> u32 {
            *self.scope_calls.lock().unwrap_or_else(|e| e.into_inner())
        }
        fn removed() -> Self {
            Self::returning(Ok(CgroupRemoval::Removed))
        }
        fn calls(&self) -> Vec<ContainerId> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
        fn instances(&self) -> Vec<StateRevision> {
            self.instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ContainerCgroupRemover for RecordingRemover {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            *self.scope_calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            self.scope.clone()
        }
        fn remove(
            &self,
            id: &ContainerId,
            instance: StateRevision,
        ) -> Result<CgroupRemoval, TraitError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(id.clone());
            self.instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(instance);
            self.result
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
        fn remove_recorded(
            &self,
            id: &ContainerId,
            placement: &CgroupPlacement,
            recorder: &OpRecorder,
        ) -> Result<CgroupRemoval, TraitError> {
            let Some(result) = &self.recorded_result else {
                let _ = recorder;
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "delegated cgroup scope does not match the recorded scope",
                ));
            };
            self.recorded_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((id.clone(), placement.clone()));
            result.clone()
        }
    }

    fn run_with(
        store: &MemStateStore,
        remover: &RecordingRemover,
        id: &str,
        force: bool,
    ) -> Result<DeleteResponse, OciRuntimeError> {
        delete(
            store,
            &OpRecorder::new(),
            remover,
            &DeleteRequest::new(cid(id)).with_force(force),
        )
    }

    fn run(
        store: &MemStateStore,
        id: &str,
        force: bool,
    ) -> Result<DeleteResponse, OciRuntimeError> {
        run_with(
            store,
            &RecordingRemover::returning(Ok(CgroupRemoval::NotPresent)),
            id,
            force,
        )
    }

    /// OCI-6: Stopped は削除され、以後の get は `NotFound`。
    #[test]
    fn oci6_delete_stopped_removes_record() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        assert_eq!(
            run(&store, "c1", false).expect("delete"),
            DeleteResponse::new()
        );
        let err = store
            .get(&GetStateRequest::new(cid("c1")))
            .expect_err("gone");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// OCI-6: pid のない Created（未起動）は削除される。
    #[test]
    fn oci6_delete_created_without_pid_removes_record() {
        let store = MemStateStore::with(ContainerStatus::created(cid("c1"), None));
        run(&store, "c1", false).expect("delete");
        assert!(!store.has("c1"));
    }

    /// CORE-2（受入基準 1）: Running・pid ありは拒否され、状態と revision は変わらない。
    #[test]
    fn core2_delete_rejects_running_with_pid() {
        let status = ContainerStatus::running(cid("c1"), pid(4242));
        let store = MemStateStore::with(status.clone());
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &status);
        assert_eq!(rec.revision(), StateRevision::from_raw(1));
    }

    /// CORE-2: pid のある Created（init 生存）も同じ文言で拒否される。
    #[test]
    fn core2_delete_rejects_created_with_pid() {
        let store = MemStateStore::with(ContainerStatus::created(cid("c1"), pid(11)));
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        assert!(store.has("c1"));
    }

    /// CORE-2: 中断された start の予約は force でも回復が先。
    #[test]
    fn core2_delete_rejects_interrupted_start() {
        for force in [false, true] {
            let store = MemStateStore::with(ContainerStatus::running(cid("c1"), None));
            let err = run(&store, "c1", force).expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "container start was interrupted; recover the start reservation"
            );
            assert!(store.has("c1"));
        }
    }

    /// CORE-2: Creating は拒否される。
    #[test]
    fn core2_delete_rejects_creating() {
        let store = MemStateStore::with(ContainerStatus::creating(cid("c1")));
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container creation is in progress");
        assert!(store.has("c1"));
    }

    /// CORE-2・REPAIR-3: 生きているコンテナへの force は stop 未実装のため `Unimplemented`。
    #[test]
    fn core2_delete_force_on_live_is_unimplemented() {
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), pid(4242)));
        let err = run(&store, "c1", true).expect_err("unimplemented");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "force delete of a live container is not implemented"
        );
        assert!(store.has("c1"));
    }

    /// CORE-2: Stopped への force は通常どおり削除される。
    #[test]
    fn core2_delete_force_on_stopped_deletes() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), None));
        run(&store, "c1", true).expect("delete");
        assert!(!store.has("c1"));
    }

    /// OCI-6（受入基準 2）: 二重 delete は 1 回目 Ok・2 回目 `NotFound`。
    #[test]
    fn oci6_delete_twice_returns_not_found() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        run(&store, "c1", false).expect("first");
        let err = run(&store, "c1", false).expect_err("second");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// ERR-2・TASK-96.3: delete の失敗は op = delete・終了コード・stderr 向け 1 行 JSON を備え、失敗が計数される。
    #[test]
    fn err2_delete_failure_is_structured() {
        let store = MemStateStore::default();
        let rec = OpRecorder::new();
        let remover = RecordingRemover::returning(Ok(CgroupRemoval::NotPresent));
        let err = delete(&store, &rec, &remover, &DeleteRequest::new(cid("missing")))
            .expect_err("not found");
        assert_eq!(err.op(), LifecycleOp::Delete);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.exit_code().get(), 3);
        let mut out = Vec::new();
        err.write_json_line(&mut out).expect("write");
        let line = String::from_utf8(out).expect("utf8");
        assert!(line.starts_with("{\"op\":\"delete\",\"code\":\"NOT_FOUND\",\"message\":"));
        assert!(line.ends_with("}\n"));
        let stats = rec
            .snapshot_op(&OpName::new(DELETE_OP_NAME).expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (0, 1));
    }

    /// ERR-2・TASK-96.3: 実行中の delete は終了コード 5、生存中の force は終了コード 8。
    #[test]
    fn err2_delete_live_exit_codes() {
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), pid(4242)));
        let err = run(&store, "c1", false).expect_err("precondition");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.exit_code().get(), 5);
        let err = run(&store, "c1", true).expect_err("unimplemented");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(err.exit_code().get(), 8);
        assert!(store.has("c1"));
    }

    /// OCI-6: 未 create の ID は `NotFound`。
    #[test]
    fn oci6_delete_unknown_id_returns_not_found() {
        let store = MemStateStore::default();
        let err = run(&store, "missing", false).expect_err("not found");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// CORE-2: 並行する delete に負けた側（削除中にレコードが消えた）は `NotFound`。
    #[test]
    fn core2_delete_concurrent_loser_returns_not_found() {
        let mut store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        store.stale_delete = true;
        store.remove_on_stale = true;
        let err = run(&store, "c1", false).expect_err("loser");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// CORE-2: revision が変わってレコードが残る場合は再試行を促す `FailedPrecondition`。
    #[test]
    fn core2_delete_revision_changed_returns_retry_error() {
        let mut store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        store.stale_delete = true;
        let err = run(&store, "c1", false).expect_err("retry");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        assert!(store.has("c1"));
    }

    /// CORE-2・OCI-5: get の後に同じ ID が削除・再作成されても、新しいレコードは消さない。再作成された
    /// レコードの revision はストア全体の単調採番で旧 revision と異なるため、delete は revision 不一致になり、
    /// レコードが残っていることを確かめて再試行を促す `FailedPrecondition` を返す。
    #[test]
    fn core2_delete_does_not_remove_recreated_record() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let recreated = ContainerStatus::created(cid("c1"), None);
        *store
            .recreate_before_delete
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(recreated.clone());
        let err = run(&store, "c1", false).expect_err("stale");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &recreated);
        assert_eq!(rec.revision(), StateRevision::from_raw(2));
    }

    /// OCI-6・CORE-3（AC2）: Stopped は cgroup 削除がちょうど 1 回、正しい ID で呼ばれ、レコードも消える。
    #[test]
    fn oci6_delete_stopped_removes_cgroup_then_record() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let remover = RecordingRemover::removed();
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), vec![cid("c1")]);
        // instance はレコードの create で割り当てた revision（`fc-c1@1` を対象にする）。
        assert_eq!(remover.instances(), vec![StateRevision::from_raw(1)]);
        assert!(!store.has("c1"));
    }

    /// OCI-6: pid のない Created でも呼ばれ、記録と同じスコープでの `NotPresent` なら成功する。
    #[test]
    fn oci6_delete_created_without_pid_calls_remover() {
        let store = MemStateStore::with_scope(ContainerStatus::created(cid("c1"), None), SCOPE);
        let remover = RecordingRemover::returning(Ok(CgroupRemoval::NotPresent));
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), vec![cid("c1")]);
        assert!(!store.has("c1"));
    }

    /// CORE-2: 拒否される状態では cgroup に触れない。
    #[test]
    fn core2_delete_rejected_states_do_not_touch_cgroup() {
        let cases = [
            (ContainerStatus::running(cid("c1"), pid(4242)), false),
            (ContainerStatus::running(cid("c1"), None), false),
            (ContainerStatus::created(cid("c1"), pid(11)), false),
            (ContainerStatus::creating(cid("c1")), false),
            (ContainerStatus::running(cid("c1"), pid(4242)), true),
        ];
        for (status, force) in cases {
            let store = MemStateStore::with_scope(status, SCOPE);
            let remover = RecordingRemover::removed();
            run_with(&store, &remover, "c1", force).expect_err("rejected");
            assert_eq!(remover.calls(), Vec::<ContainerId>::new());
            assert_eq!(remover.scope_calls(), 0);
            assert!(store.has("c1"));
        }
    }

    /// OCI-6: 未 create の ID は `NotFound` で、cgroup には触れない。
    #[test]
    fn oci6_delete_not_found_does_not_call_remover() {
        let store = MemStateStore::default();
        let remover = RecordingRemover::removed();
        let err = run_with(&store, &remover, "missing", false).expect_err("not found");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(remover.calls(), Vec::<ContainerId>::new());
    }

    /// CORE-2・OCI-6: cgroup の削除に失敗したら code をそのまま返し、レコードと revision は変わらない。
    #[test]
    fn core2_delete_cgroup_failure_keeps_record() {
        let status = ContainerStatus::stopped(cid("c1"), Some(0));
        let store = MemStateStore::with_scope(status.clone(), SCOPE);
        let remover = RecordingRemover::returning(Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container cgroup is not empty or changed; retry",
        )));
        let recorder = OpRecorder::new();
        let err = delete(&store, &recorder, &remover, &DeleteRequest::new(cid("c1")))
            .expect_err("cgroup busy");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container cgroup is not empty or changed; retry"
        );
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &status);
        assert_eq!(rec.revision(), StateRevision::from_raw(1));
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (0, 1));
    }

    /// CORE-2・OCI-6: revision 不一致で失敗した後の再実行は、remover が `NotPresent` を返すので冪等に成功する。
    #[test]
    fn core2_delete_retry_after_record_race_is_idempotent() {
        let mut store =
            MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        store.stale_delete = true;
        let remover = RecordingRemover::returning(Ok(CgroupRemoval::Removed));
        run_with(&store, &remover, "c1", false).expect_err("stale");
        store.stale_delete = false;
        *remover.result.lock().unwrap_or_else(|e| e.into_inner()) = Ok(CgroupRemoval::NotPresent);
        run_with(&store, &remover, "c1", false).expect("retry");
        assert_eq!(remover.calls(), vec![cid("c1"), cid("c1")]);
        assert_eq!(
            remover.instances(),
            vec![StateRevision::from_raw(1), StateRevision::from_raw(1)]
        );
        assert!(!store.has("c1"));
    }

    /// REPAIR-4: 成功と失敗が 1 件ずつ操作名 `delete` で記録される。
    #[test]
    fn repair4_delete_records_success_and_failure() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let recorder = OpRecorder::new();
        let req = DeleteRequest::new(cid("c1"));
        let remover = RecordingRemover::removed();
        delete(&store, &recorder, &remover, &req).expect("ok");
        delete(&store, &recorder, &remover, &req).expect_err("ng");
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
    }

    /// REPAIR-4・#1596: delete は注入された記録器を `remove_with_recorder` へ渡し、cgroup 削除中の観測値
    /// （ここでは試験用の操作名 `cgroup_sweep_probe`）が操作名 `delete` と同じ記録器に載る。
    #[test]
    fn repair4_delete_passes_its_recorder_to_cgroup_removal() {
        struct ProbeRemover;
        impl ContainerCgroupRemover for ProbeRemover {
            fn scope(&self) -> Result<CgroupScope, TraitError> {
                CgroupScope::new(SCOPE)
            }
            fn remove(
                &self,
                _id: &ContainerId,
                _instance: StateRevision,
            ) -> Result<CgroupRemoval, TraitError> {
                Err(TraitError::new(
                    ErrorCode::Internal,
                    "delete must call remove_with_recorder",
                ))
            }
            fn remove_with_recorder(
                &self,
                _id: &ContainerId,
                _instance: StateRevision,
                recorder: &OpRecorder,
            ) -> Result<CgroupRemoval, TraitError> {
                let name = OpName::new("cgroup_sweep_probe")?;
                recorder.record(
                    &name,
                    crate::observability::OpOutcome::Success,
                    std::time::Duration::from_millis(1),
                )?;
                Ok(CgroupRemoval::Removed)
            }
        }
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let recorder = OpRecorder::new();
        delete(
            &store,
            &recorder,
            &ProbeRemover,
            &DeleteRequest::new(cid("c1")),
        )
        .expect("ok");
        let count = |n: &str| {
            let s = recorder
                .snapshot_op(&OpName::new(n).expect("name"))
                .expect("recorded");
            (s.success(), s.failure())
        };
        assert_eq!(count("cgroup_sweep_probe"), (1, 0));
        assert_eq!(count("delete"), (1, 0));
        assert!(!store.has("c1"));
    }

    /// OCI-6・CORE-3（TASK-30.3）: 記録と異なる委譲スコープからの delete は、`remove_recorded` を上書きしない
    /// remover（既定実装。#2096 以前と同じ挙動）では `FailedPrecondition` で、cgroup の削除を呼ばず、レコードと revision を残す（別スコープでの `NotPresent` を「cgroup 無し」と
    /// 誤認して状態記録だけを消さない）。正しいスコープでの再実行は成功する。
    #[test]
    fn oci6_task30_3_delete_rejects_mismatched_scope_and_keeps_record() {
        let status = ContainerStatus::stopped(cid("c1"), Some(0));
        let store = MemStateStore::with_scope(status.clone(), SCOPE);
        let other = RecordingRemover::returning(Ok(CgroupRemoval::NotPresent))
            .in_scope(CgroupScope::new("/user.slice/user-1000.slice/b.scope"));
        let err = run_with(&store, &other, "c1", false).expect_err("scope mismatch");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "delegated cgroup scope does not match the recorded scope"
        );
        assert_eq!(other.calls(), Vec::<ContainerId>::new());
        assert_eq!(other.scope_calls(), 1);
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &status);
        assert_eq!(rec.revision(), StateRevision::from_raw(1));
        assert_eq!(
            rec.cgroup().map(|c| (c.scope().as_str(), c.instance())),
            Some((SCOPE, StateRevision::from_raw(1)))
        );

        let right = RecordingRemover::removed();
        run_with(&store, &right, "c1", false).expect("delete in the recorded scope");
        assert_eq!(right.calls(), vec![cid("c1")]);
        assert!(!store.has("c1"));
    }

    /// OCI-6・CORE-3（#2096・#2060 案 B）: スコープが一致すれば従来の `remove_with_recorder` だけが呼ばれ、
    /// `remove_recorded` は呼ばれない。
    #[test]
    fn oci6_delete_matching_scope_does_not_use_recorded_path() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let remover = RecordingRemover::removed().with_recorded(Ok(CgroupRemoval::Removed));
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), vec![cid("c1")]);
        assert_eq!(remover.recorded_calls(), Vec::new());
        assert!(!store.has("c1"));
    }

    /// OCI-6・CORE-3（#2096）: スコープが食い違い、`remove_recorded` が `Removed` / `NotPresent` を返すと、
    /// 記録の配置（スコープ・instance）で 1 回だけ呼ばれ、状態記録が消える。`remove` は呼ばれない。
    #[test]
    fn oci6_delete_mismatched_scope_removes_via_recorded_path() {
        for result in [CgroupRemoval::Removed, CgroupRemoval::NotPresent] {
            let store =
                MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
            let remover = RecordingRemover::removed()
                .in_scope(CgroupScope::new("/user.slice/user-1000.slice/b.scope"))
                .with_recorded(Ok(result));
            run_with(&store, &remover, "c1", false).expect("delete");
            assert_eq!(remover.calls(), Vec::<ContainerId>::new());
            assert_eq!(
                remover.recorded_calls(),
                vec![(
                    cid("c1"),
                    CgroupPlacement::new(
                        CgroupScope::new(SCOPE).expect("scope"),
                        StateRevision::from_raw(1)
                    )
                )]
            );
            assert!(!store.has("c1"), "{result:?}");
        }
    }

    /// OCI-6・SEC-1（#2096）: `remove_recorded` が失敗したらその code を返し、状態記録を残す。
    #[test]
    fn sec1_delete_recorded_path_error_keeps_record() {
        for code in [ErrorCode::FailedPrecondition, ErrorCode::PermissionDenied] {
            let store =
                MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
            let remover = RecordingRemover::removed()
                .in_scope(CgroupScope::new("/other.slice/b.scope"))
                .with_recorded(Err(TraitError::new(
                    code,
                    "failed to remove container cgroup",
                )));
            let err = run_with(&store, &remover, "c1", false).expect_err("recorded error");
            assert_eq!(err.code(), code);
            assert_eq!(remover.recorded_calls().len(), 1);
            assert!(store.has("c1"));
        }
    }

    /// OCI-6（#2096）: 記録の経路でも revision の再確認が効く。再作成されていれば cgroup に触れない。
    #[test]
    fn oci6_delete_recorded_path_rechecks_revision() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        *store
            .recreate_before_second_get
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(ContainerStatus::stopped(cid("c1"), None));
        let remover = RecordingRemover::removed()
            .in_scope(CgroupScope::new("/other.slice/b.scope"))
            .with_recorded(Ok(CgroupRemoval::Removed));
        let err = run_with(&store, &remover, "c1", false).expect_err("changed");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(remover.recorded_calls(), Vec::new());
        assert!(store.has("c1"));
    }

    /// OCI-6（TASK-30.3）: ルート `/` と非ルートのスコープも文字列の完全一致で照合する（接頭辞一致を
    /// 一致とみなさない）。
    #[test]
    fn oci6_task30_3_scope_match_is_exact() {
        for (recorded, actual) in [
            ("/", SCOPE),
            (SCOPE, "/"),
            ("/user.slice/user-1000.slice", SCOPE),
            (SCOPE, "/user.slice/user-1000.slice/a.scope/sub"),
        ] {
            let store =
                MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), None), recorded);
            let remover = RecordingRemover::removed().in_scope(CgroupScope::new(actual));
            let err = run_with(&store, &remover, "c1", false).expect_err("mismatch");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(remover.calls(), Vec::<ContainerId>::new());
            assert!(store.has("c1"));
        }
    }

    /// OCI-6（TASK-30.3）: remover が自分のスコープを返せない場合は照合できないため、そのエラーを返して
    /// cgroup にもレコードにも触れない（fail-closed）。
    #[test]
    fn oci6_task30_3_scope_error_keeps_record() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let remover = RecordingRemover::removed().in_scope(Err(TraitError::new(
            ErrorCode::Internal,
            "failed to determine the delegated cgroup scope",
        )));
        let err = run_with(&store, &remover, "c1", false).expect_err("scope error");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "failed to determine the delegated cgroup scope"
        );
        assert_eq!(remover.calls(), Vec::<ContainerId>::new());
        assert!(store.has("c1"));
    }

    /// OCI-6（TASK-30.3）: cgroup スコープの記録が無いレコード（cgroup を作っていない。導入前の
    /// 状態ファイルも同じ）は、remover の `scope` / `remove` をどちらも呼ばずに状態記録だけを消す。
    /// remover のスコープが取れない環境でも削除できる。
    #[test]
    fn oci6_task30_3_record_without_scope_does_not_touch_cgroup() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let remover = RecordingRemover::removed()
            .in_scope(Err(TraitError::new(ErrorCode::Internal, "unused")));
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), Vec::<ContainerId>::new());
        assert_eq!(remover.scope_calls(), 0);
        assert!(!store.has("c1"));
    }

    /// CORE-2・OCI-6: 最初の get の後に同じ ID が削除・再作成された場合、cgroup 削除の直前の revision
    /// 再確認で検出し、新しいコンテナの cgroup に触れずに再試行を促す `FailedPrecondition` を返す。
    #[test]
    fn core2_delete_revision_recheck_protects_recreated_cgroup() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let recreated = ContainerStatus::created(cid("c1"), None);
        *store
            .recreate_before_second_get
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(recreated.clone());
        let remover = RecordingRemover::removed();
        let err = run_with(&store, &remover, "c1", false).expect_err("recreated");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        assert_eq!(remover.calls(), Vec::<ContainerId>::new());
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &recreated);
        assert_eq!(rec.revision(), StateRevision::from_raw(2));
    }

    /// OCI-6・CORE-2（TASK-30.3）: revision 再確認の後・cgroup 削除の最中に同じ ID が削除・再作成されても、
    /// remove が対象にするのは読んだレコードの instance（1）で、再作成後のレコードの instance（2）とは
    /// 異なる。実 remover の対象名は `fc-c1@1` で、再作成後の `fc-c1@2` には届かない。状態記録の削除は
    /// revision 不一致で失敗し、再作成後のレコードは残る。
    #[test]
    fn oci6_task30_3_stale_delete_targets_only_its_own_instance() {
        /// `remove` の中で同じ ID のレコードを削除・再作成する（他クライアントの delete と create の再現）。
        struct RecreatingRemover<'a> {
            store: &'a MemStateStore,
            instances: Mutex<Vec<StateRevision>>,
        }
        impl ContainerCgroupRemover for RecreatingRemover<'_> {
            fn scope(&self) -> Result<CgroupScope, TraitError> {
                CgroupScope::new(SCOPE)
            }
            fn remove(
                &self,
                id: &ContainerId,
                instance: StateRevision,
            ) -> Result<CgroupRemoval, TraitError> {
                self.instances
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(instance);
                self.store
                    .records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
                self.store.create(
                    &CreateStateRequest::new(
                        ContainerStatus::created(id.clone(), None),
                        std::env::temp_dir().join("b2"),
                    )?
                    .with_cgroup_scope(CgroupScope::new(SCOPE)?),
                )?;
                Ok(CgroupRemoval::Removed)
            }
        }

        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let remover = RecreatingRemover {
            store: &store,
            instances: Mutex::new(Vec::new()),
        };
        let err = delete(
            &store,
            &OpRecorder::new(),
            &remover,
            &DeleteRequest::new(cid("c1")),
        )
        .expect_err("record replaced");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        assert_eq!(
            *remover.instances.lock().unwrap_or_else(|e| e.into_inner()),
            vec![StateRevision::from_raw(1)]
        );
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(
            rec.cgroup().map(|c| c.instance()),
            Some(StateRevision::from_raw(2))
        );
    }

    // ---- OCI-7 イメージ参照の解除（TASK-183.8.1）----

    /// `release` 時点で状態が既に消えているかを記録するテスト用 `ContainerImageRefs`。
    struct ProbeRefs<'a> {
        store: &'a MemStateStore,
        calls: Mutex<Vec<(ContainerId, bool)>>,
        result: Result<ImageRefRelease, TraitError>,
        /// `registration` が返す世代（既定は `Some(1)`）。
        generation: Option<ImageRefGeneration>,
        /// true なら `registration` の中で同じ ID を作り直す（並行する create の完了を模す）。
        recreate_on_lookup: bool,
        /// `Some` なら `registration` がこの失敗を返す。
        lookup_error: Option<TraitError>,
    }

    impl<'a> ProbeRefs<'a> {
        fn new(store: &'a MemStateStore, result: Result<ImageRefRelease, TraitError>) -> Self {
            Self {
                store,
                calls: Mutex::new(Vec::new()),
                result,
                generation: Some(ImageRefGeneration::from_raw(1)),
                recreate_on_lookup: false,
                lookup_error: None,
            }
        }
        fn with_lookup_error(mut self, e: TraitError) -> Self {
            self.lookup_error = Some(e);
            self
        }
        fn with_recreate_on_lookup(mut self) -> Self {
            self.recreate_on_lookup = true;
            self
        }
        fn with_generation(mut self, generation: Option<ImageRefGeneration>) -> Self {
            self.generation = generation;
            self
        }
        fn calls(&self) -> Vec<(ContainerId, bool)> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl ContainerImageRefs for ProbeRefs<'_> {
        fn register(
            &self,
            _id: &ContainerId,
            _manifest: &crate::oci_runtime::ImageManifestDigest,
        ) -> Result<crate::oci_runtime::ImageRefRegistration, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn bind(&self, _id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn registration(
            &self,
            _id: &ContainerId,
        ) -> Result<Option<ImageRefGeneration>, TraitError> {
            if let Some(e) = &self.lookup_error {
                return Err(e.clone());
            }
            if self.recreate_on_lookup {
                self.store
                    .create(
                        &CreateStateRequest::new(
                            ContainerStatus::stopped(cid("c1"), Some(0)),
                            std::env::temp_dir().join("b"),
                        )
                        .expect("req"),
                    )
                    .expect("recreate");
            }
            Ok(self.generation)
        }
        fn release(&self, _id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
            Err(TraitError::new(
                ErrorCode::Internal,
                "release(id) must not be used by delete",
            ))
        }
        fn release_if(
            &self,
            id: &ContainerId,
            expected: ImageRefGeneration,
        ) -> Result<ImageRefRelease, TraitError> {
            assert_eq!(Some(expected), self.generation);
            let state_gone = !self.store.has(id.as_str());
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((id.clone(), state_gone));
            self.result.clone()
        }
    }

    fn run_releasing(
        store: &MemStateStore,
        refs: &ProbeRefs<'_>,
        rec: &OpRecorder,
        id: &str,
    ) -> Result<DeleteResponse, OciRuntimeError> {
        delete_releasing_image_ref(
            store,
            rec,
            &RecordingRemover::returning(Ok(CgroupRemoval::NotPresent)),
            refs,
            &DeleteRequest::new(cid(id)),
        )
    }

    /// OCI-7: 状態削除の後に参照を外す（release 時点で状態は既に無い）。
    #[test]
    fn oci7_delete_releases_after_state_delete() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released));
        let resp = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(refs.calls(), vec![(cid("c1"), true)]);
        assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
    }

    /// OCI-7: 状態削除が失敗したら参照は外さない（FailedPrecondition・NotFound）。
    #[test]
    fn oci7_delete_does_not_release_when_state_delete_fails() {
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), pid(4242)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released));
        let err = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect_err("busy");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        let err = run_releasing(&store, &refs, &OpRecorder::new(), "missing").expect_err("missing");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(refs.calls(), vec![]);
    }

    /// OCI-7: 登録の無いコンテナ（bundle 直指定）は NotRegistered でも成功。
    #[test]
    fn oci7_delete_not_registered_is_success() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::NotRegistered));
        assert_eq!(
            run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete"),
            DeleteResponse::new().with_image_ref(CleanupOutcome::AlreadyAbsent)
        );
    }

    /// OCI-7・REPAIR-4: 解除の失敗は delete の結果を変えず、`image_ref_release` の失敗として記録される。
    #[test]
    fn oci7_delete_release_failure_is_recorded_not_returned() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Err(TraitError::new(ErrorCode::Timeout, "lock")));
        let rec = OpRecorder::new();
        let resp = run_releasing(&store, &refs, &rec, "c1").expect("delete still succeeds");
        assert_eq!(
            resp.image_ref(),
            CleanupOutcome::Kept {
                code: ErrorCode::Timeout
            }
        );
        let stats = rec
            .snapshot_op(&OpName::new("image_ref_release").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (0, 1));
    }

    /// OCI-7: 登録の無いコンテナ（bundle 直指定。`registration` が None）では解除を呼ばない。
    /// 状態削除の後に同じ ID の再作成が参照を登録しても、ID での解除で巻き込まない。
    #[test]
    fn oci7_delete_without_registration_never_releases() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released)).with_generation(None);
        let resp = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(refs.calls(), vec![]);
        assert_eq!(resp.image_ref(), CleanupOutcome::AlreadyAbsent);
    }

    /// OCI-7・REPAIR-4: 世代の読み取りの失敗は `Kept` で返り、解除は呼ばれない。
    #[test]
    fn oci7_delete_lookup_failure_is_reported_as_kept() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released))
            .with_lookup_error(TraitError::new(ErrorCode::Unavailable, "lookup"));
        let resp = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(
            resp.image_ref(),
            CleanupOutcome::Kept {
                code: ErrorCode::Unavailable
            }
        );
        assert_eq!(refs.calls(), vec![]);
    }

    /// OCI-7・REPAIR-4: `release_if` の内部エラーは `Kept { Internal }`。
    #[test]
    fn oci7_delete_release_internal_error_is_reported_as_kept() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Err(TraitError::new(ErrorCode::Internal, "x")));
        let resp = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(
            resp.image_ref(),
            CleanupOutcome::Kept {
                code: ErrorCode::Internal
            }
        );
    }

    /// OCI-7: 解除は状態削除後に読んだ世代で行う（`release_if` の `expected` 照合は ProbeRefs が assert）。
    #[test]
    fn oci7_delete_releases_with_generation_read_after_delete() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released))
            .with_generation(Some(ImageRefGeneration::from_raw(7)));
        run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(refs.calls(), vec![(cid("c1"), true)]);
    }

    /// OCI-7: 世代を読んだ後に状態が作り直されていれば（並行する create の完了）、新しいコンテナの参照を外さない。
    #[test]
    fn oci7_delete_does_not_release_when_state_recreated_after_lookup() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let refs = ProbeRefs::new(&store, Ok(ImageRefRelease::Released)).with_recreate_on_lookup();
        let resp = run_releasing(&store, &refs, &OpRecorder::new(), "c1").expect("delete");
        assert_eq!(refs.calls(), vec![]);
        assert_eq!(resp.image_ref(), CleanupOutcome::NotApplicable);
        assert!(store.has("c1"));
    }
}
