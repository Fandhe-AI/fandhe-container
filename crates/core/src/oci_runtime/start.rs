//! OCI Runtime の `start`（`process.args` の起動と Running への遷移。TASK-29.3・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! create（`create.rs`）が作った「Created・pid なし」の状態を入力に、bundle の `config.json` を
//! 再検証して [`LaunchSpec`] を組み立て、[`ProcessLauncher`] に起動を委ね、[`StateStore`] を
//! Running（pid 付き）へ更新する。将来の plugin 側 `ContainerRuntime::start` 実装・CLI が呼び出し元。
//! `ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、`StateStore` と launcher は依存注入する。
//!
//! # 処理順（固定）
//!
//! 1. 状態取得（不在は `NotFound`。launcher は呼ばない）
//! 2. `Created` 以外は `FailedPrecondition`（`ContainerRuntime::start` の契約）
//! 3. `config.json` を**一度だけ**読み込んで検証する（create 後の書き換え = TOCTOU 対策。ダイジェスト保持は
//!    `StateRecord` の拡張〔TASK-31・TASK-157.2 の領域〕を要するため採らない）。以後の検査と
//!    [`LaunchSpec`] はすべてこの 1 回の読み込み結果から作り、`config.json` を読み直さない（読み直すと
//!    検査した内容と起動する内容が食い違い得る）
//! 4. 適用できない指定の fail-closed 拒否・args / env の上限検証・rootfs の fd 固定（下記）
//! 5. 起動権の所有ロック（bundle ディレクトリの `flock`。`BundleLock`）を取得する。別プロセスの start の
//!    launch が進行中なら `FailedPrecondition`。ロックは launch が終わるまで保持し、プロセスが終了すれば
//!    カーネルが解放する（中断回復が所有プロセスの終了を確かめる手段。CORE-2）。続けて起動権の予約:
//!    `StateStore::update` を revision 照合つきで呼び、Created を Running（pid なし）へ
//!    原子的に遷移させる。別プロセスの同時 start はここで revision 不一致（`FailedPrecondition`）に
//!    なり launch へ進めない（CORE-2）
//! 6. launcher 起動（上限 [`StartTimeouts::launch`]）。失敗時は予約を Created へ戻す（戻せない場合は
//!    `Internal` で伝える）。上限を超えたら待つのをやめて `Timeout` を返し、予約は残す（launch がまだ
//!    進行中で、プロセスが後から現れ得るため Created へ戻さない）。後から返ってきた起動済みプロセスは
//!    後始末スレッドが [`LaunchedProcess::terminate`]（上限 [`StartTimeouts::terminate`] を強制）で
//!    kill・回収する。launch と後始末が終わるまでプロセス内の予約（`StartReservation`）も保持し、
//!    同一プロセス内の start・回復を拒否する（進行中の launch との二重起動防止。CORE-2）
//! 7. Running（pid 付き）へ状態更新。成功したら状態と起動済みプロセスのハンドル（[`StartedContainer`]）を
//!    返し、監視・回収の責務を呼び出し元へ引き渡す（CORE-1）。更新に失敗した場合は起動済みプロセスを上限
//!    [`StartTimeouts::terminate`] つきで終了し、予約を Created へ戻してから、元のエラーを返す。
//!    終了にも失敗した・上限を超えた場合は、未記録プロセスが残り得ることを示す `Internal` を返し、
//!    元のエラーで隠さない（予約は残す。REPAIR-5）
//!
//! # 時間上限の強制（REPAIR-5）
//!
//! launcher・起動済みプロセスへの呼び出し（launch・terminate・confirm_no_process）は、上限を引数で
//! 実装へ渡したうえで、`call_bounded` が別スレッドで呼び、上限（＋実装自身の `Timeout` 応答を受け取る
//! 猶予 [`LAUNCHER_REPLY_GRACE`]）を過ぎたら待つのをやめる。実装が上限を守らず戻らなくても start は
//! 有限時間で戻る。上限超過後に戻った結果は後始末スレッドが処理する（起動済みプロセスなら terminate）。
//!
//! start のプロセスが手順 5〜7 の間に異常終了すると Running・pid なしの予約だけが残る。この状態は
//! `FailedPrecondition`（`start was interrupted` を含むメッセージ）で識別でき、
//! [`recover_interrupted_start`] で Created へ戻せる（CORE-2）。回復は、手順 5 の所有ロックを取れる
//! （＝所有プロセスが終了済みか launch が完了済み）ことと、launch 後・pid 記録前の中断では生きた
//! プロセスが残り得るため launcher が生存プロセス無しを確認できたことの両方を条件とする（SEC-1）。
//!
//! 手順 1〜7 は同一 ID につきプロセス内でも排他する（並行 start の早期拒否。CORE-2）。プロセス間では、
//! 手順 5 の所有ロック（launch の進行中を他プロセスから観測できる）と revision 照合（`StateStore` 実装が
//! 更新を原子的に照合する契約）で排他する。
//!
//! # fail-closed の拒否（SEC-1・SEC-5・CORE-5・REPAIR-3）
//!
//! config パーサが解釈済みとする指定のうち、start 経路が現時点で適用できないものは黙って無視せず
//! `Unimplemented` で拒否する（指定より強い権限・弱い分離での起動を防ぐ）。後続タスクが適用を
//! 実装した時点で該当検査を外す。
//!
//! - `process.cwd` が `/` 以外（exec フローが cwd 未対応）
//! - `process.user` が uid 0・gid 0・追加 gid なし以外（ユーザー切替は未実装）
//! - `process.terminal` が true（端末受け渡し未実装）
//! - `mounts` が非空（mount 適用未実装）
//! - `linux.namespaces[].path` の指定（既存 namespace への join 未実装）
//! - `network`・`cgroup`・`time` namespace（exec の対応は PID/Mount/UTS/IPC/User のみ）
//! - `linux.namespaces` に user namespace が無い（`process.user` は root 必須のため、ホスト root での
//!   起動になる。`PermissionDenied`。SEC-5）
//! - `linux.namespaces` に IPC namespace が無い（ホストの IPC を共有する起動を防ぐ。共有の明示許可は
//!   未実装のため必須。`InvalidArgument`。SEC-1）
//! - `linux.namespaces` に PID・mount・UTS namespace が無い（CORE-1 の最小分離〔PID/mount/UTS/IPC〕を
//!   欠く起動を防ぐ。UTS は hostname 指定の有無にかかわらず必須で、無いとホストの hostname を共有・
//!   変更し得る。`InvalidArgument`。SEC-1）
//!
//! 必須とする namespace は CORE-1 の最小分離（PID・mount・UTS・IPC）と user（SEC-5）。network は
//! 指定が無ければホストの network namespace を共有する NET-6 の host モードに当たり（ネットワーク分離は
//! `NetworkPlugin`〔NET 系〕の担当）、指定があれば作成が未実装のため上記のとおり `Unimplemented`。
//! cgroup・time も作成が未実装で、指定が無ければ OCI の規定どおりランタイムの namespace を引き継ぐ
//! （cgroup の分離・制限は TASK-32・CORE-3 の範囲。REPAIR-3: 未実装であることを明示する）。
//! - `linux.uidMappings` / `gidMappings` が非空（config 指定の写像は subuid 範囲写像とともに
//!   TASK-40・CORE-6 で対応する。SEC-5 の「コンテナ内 root をホストの非特権 UID へ写す」写像は
//!   launcher の契約で、`exec::isolate` が呼び出しプロセスの euid / egid へ写す。`ProcessLauncher` 参照）
//! - `root.readonly` が true（読み取り専用 rootfs 未実装）
//!
//! `process.args` / `process.env` は `exec::Entrypoint::new` と同じ上限（件数 4096・1 要素 131072 バイト・
//! 合計 1 MiB。NUL 禁止・env は `KEY=VALUE`）を `LaunchSpec` 構築前に検証し、違反は `InvalidArgument`。
//! `exec` は Linux 限定のため、値は本ファイルに複製し Linux では一致をテストで固定する。
//!
//! rootfs は検査後、`/` から bundle を経て rootfs までの全要素（祖先を含む）を直前の fd を起点に
//! symlink 非追従（`O_PATH|O_DIRECTORY|O_NOFOLLOW`）で 1 要素ずつ開いて fd で固定し、その fd を
//! `LaunchSpec` に載せる（`exec::mount_proc` と同じ `exec::open_dir_beneath` を再利用。検査から使用まで・
//! 祖先の差し替え = TOCTOU を閉じる。SEC-1。`RootfsDir` 参照）。固定に失敗したら `PermissionDenied`
//! （bundle 配下の差し替え）または `InvalidArgument`（bundle 自体や祖先に symlink がある。本番 launcher の
//! `exec::prepare_rootfs` も `/` から同条件で辿るため先に拒否する。create は受理するため「create 成功・
//! start 拒否」になる）。fd 相対の open は Linux にしか無いため、Linux 以外では固定段（予約の前）で
//! `Unimplemented` を返し起動しない（fail-closed。本番 launcher も Linux のみ。CLI-1）。
//!
//! `process.args[0]` がコンテナ内の絶対パス（先頭 `/`）でない場合は `InvalidArgument`（PATH 探索は未実装）。
//! コンテナパスはホスト OS 非依存に文字列で判定する（Windows でも `/bin/echo` を受理する。3 OS 一級対応）。
//!
//! # 到達範囲（REPAIR-3）
//!
//! 本 crate に本番 [`ProcessLauncher`] は無く、exec の制限ステージ（TASK-37〜39）も未実装のため
//! 実プロセスの起動は行われない。`process.args` 等がそのまま launcher へ渡り、launcher の返した
//! pid で Running へ遷移するところまでが本関数の責務である。
//!
//! エラーメッセージは固定文言と静的なフィールドパスのみで、config の値や OS 依存の I/O エラー
//! 文字列を含めない。

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use super::config::{NamespaceKind, OciConfig};
use super::create::validate_bundle;
use super::launch::{
    BundleLock, LaunchSpec, LaunchedProcess, ProcessLauncher, RootfsDir, StartTimeouts,
};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, GetStateRequest, StartRequest,
    StateRecord, StateStore, TraitError, UpdateStateRequest,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const START_OP_NAME: &str = "start";

/// 上限を過ぎてから実装自身の `Timeout` 応答（後始末済み）を受け取るまで待つ猶予（REPAIR-5）。
///
/// launcher は同じ上限を引数で受け取るため、上限ちょうどで打ち切ると協調的な実装の `Timeout` 応答
/// （子を kill・回収済み）と境界の打ち切りが競合する。猶予内に応答があればそれを使い、予約を正しく戻す。
pub const LAUNCHER_REPLY_GRACE: Duration = Duration::from_secs(1);

/// start の成功結果（更新後の状態と、起動済みプロセスのハンドル）。
///
/// ハンドルは呼び出し元へ引き渡され、呼び出し元（supervisor〔TASK-157・SUP 系〕等）が監視・回収の
/// 所有者になる。`ContainerChildProcess` 等のハンドルは `Drop` で回収しないため、所有者は
/// [`LaunchedProcess::wait`] で終了を待って回収する（捨てるとゾンビが残り得る。CORE-1）。
#[must_use = "the launched process must be monitored and reaped by its owner"]
pub struct StartedContainer {
    record: StateRecord,
    process: Box<dyn LaunchedProcess>,
}

impl StartedContainer {
    /// 更新後（Running・pid 付き）の状態。
    pub fn record(&self) -> &StateRecord {
        &self.record
    }

    /// 起動済みプロセスのハンドル。
    pub fn process(&self) -> &dyn LaunchedProcess {
        self.process.as_ref()
    }

    /// 状態とハンドルに分解する（ハンドルの所有権を監視側へ移す）。
    pub fn into_parts(self) -> (StateRecord, Box<dyn LaunchedProcess>) {
        (self.record, self.process)
    }
}

impl std::fmt::Debug for StartedContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedContainer")
            .field("record", &self.record)
            .field("pid", &self.process.pid())
            .finish()
    }
}

/// Created 状態のコンテナのプロセスを起動し、Running（pid 付き）へ遷移させる。
///
/// 戻り値は更新後の [`StateRecord`] と起動済みプロセスのハンドル（[`StartedContainer`]。監視・回収は
/// 呼び出し元の責務）。未 create の ID は [`ErrorCode::NotFound`]、Created 以外は
/// [`ErrorCode::FailedPrecondition`]、launcher の応答が上限（`timeouts`）を超えたら
/// [`ErrorCode::Timeout`]（予約は残り [`recover_interrupted_start`] で回復する）。launcher は上限超過後も
/// 後始末スレッドから使うため `Arc` で受ける。成功・失敗の件数と所要時間は `recorder` へ操作名 `start` で
/// 記録する（全終了経路。REPAIR-4）。
pub fn start(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    launcher: &Arc<dyn ProcessLauncher>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
) -> Result<StartedContainer, TraitError> {
    let name = OpName::new(START_OP_NAME)?;
    recorder.record_op(&name, || start_inner(store, launcher, req, timeouts))
}

/// [`call_bounded`] の結果を保持する枠（呼び出し側と実行スレッドの受け渡し）。
enum Slot<T> {
    /// 実行中。
    Pending,
    /// 上限内に戻った結果（呼び出し側が取り出す）。
    Done(T),
    /// 呼び出し側が上限超過で待つのをやめた。以後の結果は実行スレッドが後始末する。
    Abandoned,
}

/// [`call_bounded`] が結果を得られなかった理由。
enum Unbounded {
    /// 上限（＋猶予）を過ぎた、または実行スレッドが結果を返さずに終わった（panic 等）。
    TimedOut,
    /// 実行スレッドを作れなかった（`call` は実行されていない）。
    SpawnFailed,
}

/// `call` を別スレッドで実行し、`limit` ＋ [`LAUNCHER_REPLY_GRACE`] までに戻った結果だけを返す（REPAIR-5）。
///
/// launcher・起動済みプロセスへの呼び出し境界で上限を強制する。上限を過ぎたら `Unbounded::TimedOut` を
/// 返して待つのをやめ、後から戻った結果は実行スレッド上で `on_late` に渡す（起動済みプロセスの
/// terminate 等）。結果の受け渡しと「待つのをやめた」印は同じ `Mutex` の下で行うため、戻った結果が
/// 誰にも処理されずに捨てられることはない。実行スレッドが `call` の途中で panic した場合は結果が
/// 無いまま上限を迎え `TimedOut` になる（結果が不明なので予約は残す側に倒す）。実装が永久に戻らない
/// 場合、実行スレッドはプロセス終了まで残る（Rust にスレッドの強制停止は無い）が、呼び出し側は上限で戻る。
fn call_bounded<T, F, L>(limit: Duration, call: F, on_late: L) -> Result<T, Unbounded>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    L: FnOnce(T) + Send + 'static,
{
    let shared = Arc::new((Mutex::new(Slot::<T>::Pending), Condvar::new()));
    let worker = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("fandhe-start-call".to_owned())
        .spawn(move || {
            let value = call();
            let (lock, cvar) = &*worker;
            let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*slot, Slot::Abandoned) {
                drop(slot);
                on_late(value);
                return;
            }
            // 結果を渡す前に後始末用の捕捉（予約の複製等）を解放する。呼び出し側が結果を受け取って
            // 戻った時点で、実行スレッド側の複製が残っていないことを保証する（直後の同一 ID の操作が
            // 予約の残りに阻まれないようにする）。
            drop(on_late);
            *slot = Slot::Done(value);
            cvar.notify_all();
        })
        .map_err(|_| Unbounded::SpawnFailed)?;
    // `limit` は `StartTimeouts` が上限つきで検証済みのため加算は溢れないが、念のため checked で扱う。
    let wait = limit.saturating_add(LAUNCHER_REPLY_GRACE);
    let deadline = Instant::now().checked_add(wait);
    let (lock, cvar) = &*shared;
    let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        // 結果があれば取り出す（取り出した後は Abandoned にして二重に取り出さない）。
        match std::mem::replace(&mut *slot, Slot::Abandoned) {
            Slot::Done(value) => return Ok(value),
            other => *slot = other,
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) if d > now => d - now,
            _ => {
                *slot = Slot::Abandoned;
                return Err(Unbounded::TimedOut);
            }
        };
        slot = cvar
            .wait_timeout(slot, remaining)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// プロセス内で start 実行中の ID 集合（同一 ID の並行 start による二重 launch を防ぐ予約表）。
fn in_flight() -> &'static Mutex<HashSet<ContainerId>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<ContainerId>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// ID の予約。Drop で解放する（全終了経路・panic でも残さない）。
///
/// start は `Arc` で包み、上限を超えた launch の実行スレッドにも複製を持たせる。予約は最後の複製が
/// 落ちるまで（＝start が戻り、かつ進行中の launch と遅れて返ったプロセスの後始末が終わるまで）解放
/// されないため、その間の同一プロセス内の start・[`recover_interrupted_start`] は `FailedPrecondition`
/// で拒否される（進行中の launch が後からプロセスを作る二重起動を防ぐ。CORE-2・SEC-1）。
/// [`recover_interrupted_start`] の生存確認（ID 単位で終了・回収し得る）も、上限超過後に確認が終わるまで
/// 複製を保持する。一方、上限を超えた `terminate` は特定のプロセスのハンドルに対する操作で、同じ ID の
/// 後続のプロセスには作用しないため、上限で予約を手放す（戻らない実装で予約が永久に残るのを避ける）。
///
/// プロセス間の排他は、予約に載せる起動権の所有ロック（`BundleLock`。bundle ディレクトリの `flock`）が
/// 担う。所有ロックも予約と同じ寿命（最後の複製が落ちるまで）で保持される。
struct StartReservation {
    id: ContainerId,
    /// 起動権の所有ロック（取得後に載せる。予約の解放と同時に閉じてロックを解放する）。
    owner: OnceLock<BundleLock>,
}

impl StartReservation {
    fn acquire(id: &ContainerId) -> Result<Self, TraitError> {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(id.clone()) {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container start is already in progress",
            ));
        }
        Ok(Self {
            id: id.clone(),
            owner: OnceLock::new(),
        })
    }

    /// `bundle` の起動権の所有ロックを取得して予約に載せる（プロセス間の排他。CORE-2）。
    fn lock_owner(&self, bundle: &Path) -> Result<(), TraitError> {
        let lock = BundleLock::acquire(bundle)?;
        // 1 つの予約で所有ロックを取るのは 1 回だけ（start・recover とも 1 回呼ぶ）。
        let _ = self.owner.set(lock);
        Ok(())
    }
}

impl Drop for StartReservation {
    fn drop(&mut self) {
        // 所有ロックを先に解放してからプロセス内の予約を外す（プロセス内で予約が外れたのを見た回復が、
        // まだ残る自分の所有ロックに阻まれないようにする）。
        let _ = self.owner.take();
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&self.id);
    }
}

/// 中断された start の起動権予約（Running・pid なし）を Created へ戻す（CORE-2）。
///
/// start は launch 前に状態を Running・pid なしへ更新して起動権を予約する。プロセスが launch 中に
/// 異常終了すると予約だけが残り、次の start は `FailedPrecondition` で拒否される。本関数はその状態を
/// revision 照合つきで Created へ戻す。Running・pid なし以外の状態は `FailedPrecondition`、不在は
/// `NotFound`。
///
/// 同一プロセス内の start とは排他する。launch が上限を超えて start が `Timeout` で戻った後も、その
/// launch が終わり遅れて返ったプロセスの後始末が済むまでは予約が解放されず、本関数は
/// `FailedPrecondition`（`container start is already in progress`）で拒否する（CORE-2）。
///
/// 別プロセスの start とは、起動権の所有ロック（bundle ディレクトリの `flock`。`BundleLock`）で排他する。
/// start は予約の前にこのロックを取り、launch（上限超過後に続く分を含む）が終わるまで保持する。
/// ロックはそのプロセスが終了するとカーネルが解放するため、本関数は呼び出し元の事前確認に依存せず、
/// ロックを取れた場合（＝所有プロセスが終了済みか launch が完了済み）に限って回復へ進む。取れなければ
/// `FailedPrecondition`（`container start is in progress in another process`）。Linux 以外はロックを
/// 取れないため `Unimplemented`（fail-closed）。
///
/// launch 後・pid 記録前の中断では生きたプロセスが残り得るため、Created へ戻す前に
/// [`ProcessLauncher::confirm_no_process`] で生存プロセスが無いことを確認する。確認できない場合
/// （既定実装を含む）はそのエラーを返して予約を残す（二重起動の防止。SEC-1・CORE-2）。
///
/// 確認の待ちは `timeouts.confirm()` まで（REPAIR-5。呼び出し境界で強制する）。超過したら `Timeout` を
/// 返して予約を残す。上限超過後も確認が終わるまではプロセス内の予約を保持し、同一プロセス内の回復・
/// start を `FailedPrecondition` で拒否する（遅れた確認が後続のプロセスを終了させないため。CORE-2）。
pub fn recover_interrupted_start(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
) -> Result<StateRecord, TraitError> {
    let reservation = Arc::new(StartReservation::acquire(id)?);
    let record = store.get(&GetStateRequest::new(id.clone()))?;
    if record.status().state() != ContainerState::Running || record.status().pid().is_some() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "no interrupted start reservation to recover",
        ));
    }
    // 別プロセスの launch が進行中でないこと（所有プロセスの終了または launch の完了）を所有ロックで
    // 確かめてから、生存プロセスの確認へ進む（CORE-2）。
    reservation.lock_owner(record.bundle())?;
    let confirm = timeouts.confirm();
    let l = Arc::clone(launcher);
    let target = id.clone();
    // confirm_no_process は ID 単位で「残っていれば終了・回収」し得るため、上限超過で本関数が戻った後も
    // 確認が終わるまでプロセス内の予約を保持する（回復の再試行・新しい start が先に進み、その後に
    // 遅れた確認が新しいプロセスを終了させることを防ぐ。CORE-2）。
    let hold = Arc::clone(&reservation);
    match call_bounded(
        confirm,
        move || {
            let result = l.confirm_no_process(&target, confirm);
            drop(hold);
            result
        },
        drop,
    ) {
        Ok(result) => result?,
        Err(Unbounded::TimedOut) => {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the launcher did not confirm within the timeout; the start reservation remains",
            ));
        }
        Err(Unbounded::SpawnFailed) => {
            return Err(TraitError::new(
                ErrorCode::Internal,
                "failed to run the launcher confirmation",
            ));
        }
    }
    store.update(&UpdateStateRequest::new(
        ContainerStatus::created(id.clone(), None),
        record.revision(),
    ))
}

fn start_inner(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
) -> Result<StartedContainer, TraitError> {
    let reservation = Arc::new(StartReservation::acquire(req.id())?);
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    if record.status().state() != ContainerState::Created {
        // Running・pid なしは start の起動権予約が残った状態（中断・クラッシュ後）。識別できる
        // メッセージで返し、`recover_interrupted_start` での回復を促す（CORE-2）。
        let interrupted =
            record.status().state() == ContainerState::Running && record.status().pid().is_none();
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            if interrupted {
                "container start was interrupted; recover the start reservation"
            } else {
                "container is not in created state"
            },
        ));
    }

    let spec = build_spec(record.bundle())?;

    // 起動権の所有ロック（プロセス間の排他）を予約の前に取り、launch が終わるまで保持する。所有ロックを
    // 持つプロセスが終了すればカーネルが解放するため、回復はその終了を条件にできる（CORE-2）。
    reservation.lock_owner(record.bundle())?;

    // 起動権の予約。revision 照合つき更新は別プロセスの同時 start と排他になる（CORE-2）。
    let claimed = store.update(&UpdateStateRequest::new(
        ContainerStatus::running(req.id().clone(), None),
        record.revision(),
    ))?;

    let launch_timeout = timeouts.launch();
    let terminate_timeout = timeouts.terminate();
    let l = Arc::clone(launcher);
    // 実行スレッドが launch を終えて後始末を済ませるまで、プロセス内の予約を保持する（CORE-2）。
    let hold = Arc::clone(&reservation);
    let launched = call_bounded(
        launch_timeout,
        move || l.launch(&spec, launch_timeout),
        move |late: Result<Box<dyn LaunchedProcess>, TraitError>| {
            late_launch_cleanup(late, terminate_timeout);
            drop(hold);
        },
    );
    let process = match launched {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => return Err(release_claim(store, req.id(), &claimed, err)),
        // launch は呼ばれていないため予約を戻してよい。
        Err(Unbounded::SpawnFailed) => {
            let err = TraitError::new(ErrorCode::Internal, "failed to run the process launcher");
            return Err(release_claim(store, req.id(), &claimed, err));
        }
        // launch がまだ進行中でプロセスが後から現れ得るため、予約は Created へ戻さない（CORE-2）。
        Err(Unbounded::TimedOut) => {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the process launch did not complete within the timeout; \
                 the start reservation remains until recovered",
            ));
        }
    };

    let running = ContainerStatus::running(req.id().clone(), Some(process.pid()));
    match store.update(&UpdateStateRequest::new(running, claimed.revision())) {
        // ハンドルは呼び出し元（監視・回収の所有者）へ引き渡す（捨てると回収できない。CORE-1）。
        Ok(record) => Ok(StartedContainer { record, process }),
        Err(err) => {
            // 状態を記録できないまま生きたプロセスを残さない。終了できなかった・上限を超えた場合は
            // 未記録プロセスが残り得ることを呼び出し元へ伝える（元のエラーで隠さない。予約は残す）。
            let terminated = call_bounded(
                terminate_timeout,
                move || process.terminate(terminate_timeout),
                drop,
            );
            match terminated {
                Ok(Ok(())) => Err(release_claim(store, req.id(), &claimed, err)),
                _ => Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to record running state and failed to terminate the launched process",
                )),
            }
        }
    }
}

/// 上限超過後に返ってきた launch の結果を後始末する（`call_bounded` の実行スレッド上で呼ばれる）。
///
/// 起動済みプロセスは状態に記録されていないため kill・回収する。この terminate にも上限
/// `terminate_timeout` を呼び出し境界で強制し、戻らない実装でも有限時間で予約（プロセス内）を手放す。
/// 終了を確認できなかった場合も、状態には start が残した起動権の予約（Running・pid なし）が残るため、
/// 回復は [`recover_interrupted_start`]（`confirm_no_process` による生存確認つき）に限られる
/// （回復可能な失敗状態として保持する。REPAIR-5・CORE-2）。
fn late_launch_cleanup(
    late: Result<Box<dyn LaunchedProcess>, TraitError>,
    terminate_timeout: Duration,
) {
    if let Ok(process) = late {
        let _ = call_bounded(
            terminate_timeout,
            move || process.terminate(terminate_timeout),
            drop,
        );
    }
}

/// 予約（Running・pid なし）を Created へ戻す。戻せない場合は状態が残り得ることを `Internal` で伝える。
fn release_claim(
    store: &dyn StateStore,
    id: &ContainerId,
    claimed: &StateRecord,
    original: TraitError,
) -> TraitError {
    let created = ContainerStatus::created(id.clone(), None);
    match store.update(&UpdateStateRequest::new(created, claimed.revision())) {
        Ok(_) => original,
        Err(_) => TraitError::new(
            ErrorCode::Internal,
            "start failed and the start reservation could not be released",
        ),
    }
}

/// bundle の `config.json` を一度だけ読んで検証し、start が適用できない指定を拒否したうえで、rootfs を
/// fd で固定して [`LaunchSpec`] を組み立てる（`config.json` は読み直さない）。
fn build_spec(bundle: &Path) -> Result<LaunchSpec, TraitError> {
    let (config, rootfs) = validate_bundle(bundle)?;
    let process = config.process().ok_or_else(|| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "config.json: process is required",
        )
    })?;

    let first_is_absolute = process.args().first().is_some_and(|a| a.starts_with('/'));
    if !first_is_absolute {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "process.args[0] must be an absolute path",
        ));
    }
    validate_entrypoint_limits(process.args(), process.env())?;
    let user = process.user();
    if process.cwd() != Path::new("/") {
        return Err(unsupported("process.cwd other than /"));
    }
    if user.uid() != 0 || user.gid() != 0 || !user.additional_gids().is_empty() {
        return Err(unsupported("process.user other than root"));
    }
    if process.terminal() {
        return Err(unsupported("process.terminal"));
    }
    reject_unsupported_linux(&config)?;
    // process.user は root 必須のため、user namespace が無いとホスト root で起動してしまう（SEC-5）。
    if !config
        .namespaces()
        .iter()
        .any(|n| n.kind() == NamespaceKind::User)
    {
        return Err(TraitError::new(
            ErrorCode::PermissionDenied,
            "a user namespace is required to run as root",
        ));
    }

    let namespaces: Vec<NamespaceKind> = config.namespaces().iter().map(|n| n.kind()).collect();
    // CORE-1 の最小分離（PID・mount・UTS・IPC）を必須とする（exec::plan の組合せ検証より強い）。
    let has = |k: NamespaceKind| namespaces.contains(&k);
    if !has(NamespaceKind::Pid) || !has(NamespaceKind::Mount) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the PID and mount namespaces are required",
        ));
    }
    // IPC namespace が無いとホストの IPC（SysV IPC・POSIX メッセージキュー）を共有する。共有を明示許可する
    // 仕組みが無いため fail-closed で必須とする（SEC-1）。
    if !has(NamespaceKind::Ipc) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the IPC namespace is required",
        ));
    }
    // UTS namespace が無いとホストの hostname・domainname を共有し、コンテナ内から変更し得る。hostname
    // 指定の有無にかかわらず fail-closed で必須とする（SEC-1・CORE-1）。
    if !has(NamespaceKind::Uts) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the UTS namespace is required",
        ));
    }
    // 検査済みの rootfs を、`/` から祖先を含む全要素を symlink 非追従で辿って fd で固定する（SEC-1）。
    // 以後の使用はこの fd に限るため、検査後に祖先や rootfs を差し替えても固定した実体は変わらない。
    let rootfs_dir = RootfsDir::pin(bundle, &rootfs)?;
    Ok(LaunchSpec::new(
        rootfs,
        rootfs_dir,
        process.args().to_vec(),
        process.env().to_vec(),
        config.hostname().map(str::to_owned),
        namespaces,
    ))
}

fn reject_unsupported_linux(config: &OciConfig) -> Result<(), TraitError> {
    if config.root().readonly() {
        return Err(unsupported("root.readonly"));
    }
    if !config.mounts().is_empty() {
        return Err(unsupported("mounts"));
    }
    if !config.uid_mappings().is_empty() || !config.gid_mappings().is_empty() {
        return Err(unsupported("linux.uidMappings / linux.gidMappings"));
    }
    for ns in config.namespaces() {
        if ns.path().is_some() {
            return Err(unsupported("linux.namespaces[].path"));
        }
        if matches!(
            ns.kind(),
            NamespaceKind::Network | NamespaceKind::Cgroup | NamespaceKind::Time
        ) {
            return Err(unsupported("network / cgroup / time namespace"));
        }
    }
    Ok(())
}

/// `exec::ENTRYPOINT_MAX_ARGS`（`exec` は Linux 限定のため複製。Linux ではテストで一致を確認する）。
const ARGS_MAX: usize = 4096;
/// `exec::ENTRYPOINT_MAX_ENV`。
const ENV_MAX: usize = 4096;
/// `exec::ENTRYPOINT_MAX_STRING_BYTES`（NUL を含む 1 要素の上限）。
const STRING_MAX_BYTES: usize = 131_072;
/// `exec::ENTRYPOINT_MAX_TOTAL_BYTES`（path・argv・env の NUL 込み合計。path は `args[0]`）。
const TOTAL_MAX_BYTES: usize = 1 << 20;

/// `exec::Entrypoint::new` 相当の上限・形式検証を `LaunchSpec` 構築前に行う（DoS 防止・REPAIR-2）。
///
/// 上限の検証は要素を走査する前の件数で先に行い、以後は加算のみで確保しない。
fn validate_entrypoint_limits(args: &[String], env: &[String]) -> Result<(), TraitError> {
    let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
    if args.is_empty() || args.len() > ARGS_MAX || env.len() > ENV_MAX {
        return Err(invalid(
            "process.args / process.env exceed the count limits",
        ));
    }
    // path（args[0]）は argv とは別に数えられるため、合計に 2 回加算される。
    let mut total = args.first().map_or(0, |a| a.len().saturating_add(1));
    for item in args.iter().chain(env.iter()) {
        let size = item.len().saturating_add(1);
        if size > STRING_MAX_BYTES {
            return Err(invalid("a process.args / process.env element is too large"));
        }
        if item.contains('\0') {
            return Err(invalid("process.args / process.env must not contain NUL"));
        }
        total = total.saturating_add(size);
        if total > TOTAL_MAX_BYTES {
            return Err(invalid(
                "process.args / process.env exceed the total size limit",
            ));
        }
    }
    for entry in env {
        if !matches!(entry.find('='), Some(i) if i > 0) {
            return Err(invalid("each process.env element must be KEY=VALUE"));
        }
    }
    Ok(())
}

/// 静的なフィールド名だけを含む `Unimplemented` を作る（config の値は含めない）。
fn unsupported(field: &'static str) -> TraitError {
    TraitError::new(
        ErrorCode::Unimplemented,
        format!("start does not support yet: {field}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::{LaunchedProcess, ProcessExit, create};
    use crate::traits::{
        ContainerId, CreateRequest, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        ListStateRequest, StateList, StateRevision,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// テスト専用のインメモリ `StateStore`。`update` は revision を照合し、失敗注入もできる。
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        /// `update` の n 回目（0 始まり）の呼び出しだけ失敗させる。
        fail_update_at: Option<usize>,
        update_calls: AtomicUsize,
    }

    impl MemStateStore {
        fn new(fail_update_at: Option<usize>) -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                fail_update_at,
                update_calls: AtomicUsize::new(0),
            }
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let n = self.update_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_update_at == Some(n) {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "conflict"));
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let cur = records
                .get(req.status().id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                cur.revision().next()?,
            )?;
            records.insert(req.status().id().clone(), next.clone());
            Ok(next)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }

        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// 開くまで呼び出しを塞ぐ門（上限を守らず戻らない実装の模擬）。
    struct Gate {
        open: Mutex<bool>,
        cvar: std::sync::Condvar,
    }

    impl Gate {
        fn new(open: bool) -> Arc<Self> {
            Arc::new(Self {
                open: Mutex::new(open),
                cvar: std::sync::Condvar::new(),
            })
        }

        #[cfg(target_os = "linux")]
        fn set_open(&self, open: bool) {
            *self.open.lock().unwrap_or_else(|e| e.into_inner()) = open;
            self.cvar.notify_all();
        }

        /// 門が開くまで待つ（テストが固まらないよう最大 30 秒で諦める）。
        fn pass(&self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            while !*open {
                let now = Instant::now();
                if now >= deadline {
                    return;
                }
                open = self
                    .cvar
                    .wait_timeout(open, deadline - now)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
    }

    /// 受け取った `LaunchSpec`・上限を記録し、固定 pid を返す launcher。
    ///
    /// `gate` が閉じている間は launch・confirm_no_process が、`term_gate` が閉じている間は起動した
    /// プロセスの terminate が戻らない。
    struct RecordingLauncher {
        specs: Mutex<Vec<LaunchSpec>>,
        /// launch・confirm_no_process に渡された上限（呼び出し順）。
        timeouts: Mutex<Vec<Duration>>,
        terminated: Arc<AtomicUsize>,
        fail: bool,
        fail_terminate: AtomicBool,
        /// `confirm_no_process` が生存プロセス無しを確認できるか。
        confirms_no_process: AtomicBool,
        gate: Arc<Gate>,
        term_gate: Arc<Gate>,
    }

    impl RecordingLauncher {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                specs: Mutex::new(Vec::new()),
                timeouts: Mutex::new(Vec::new()),
                terminated: Arc::new(AtomicUsize::new(0)),
                fail,
                fail_terminate: AtomicBool::new(false),
                confirms_no_process: AtomicBool::new(false),
                gate: Gate::new(true),
                term_gate: Gate::new(true),
            })
        }

        #[cfg(target_os = "linux")]
        fn received_timeouts(&self) -> Vec<Duration> {
            self.timeouts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn calls(&self) -> usize {
            self.specs.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        fn terminations(&self) -> usize {
            self.terminated.load(Ordering::SeqCst)
        }
    }

    /// 起動済みプロセスの模擬（terminate の回数を数え、`gate` が開くまで terminate が戻らない）。
    struct FakeProcess(Arc<AtomicUsize>, bool, Arc<Gate>);

    impl LaunchedProcess for FakeProcess {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(4242).expect("nonzero")
        }

        /// 模擬プロセスは terminate されるまで終了しない（terminate 後は SIGKILL 相当で終了済み）。
        fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            if self.0.load(Ordering::SeqCst) > 0 {
                Ok(Some(ProcessExit::Signaled(9)))
            } else {
                Ok(None)
            }
        }

        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.2.pass();
            self.0.fetch_add(1, Ordering::SeqCst);
            if self.1 {
                return Err(TraitError::new(ErrorCode::Timeout, "terminate timed out"));
            }
            Ok(())
        }
    }

    impl ProcessLauncher for RecordingLauncher {
        fn confirm_no_process(
            &self,
            _id: &ContainerId,
            timeout: Duration,
        ) -> Result<(), TraitError> {
            self.timeouts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(timeout);
            self.gate.pass();
            if self.confirms_no_process.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(TraitError::new(ErrorCode::Unimplemented, "cannot confirm"))
            }
        }

        fn launch(
            &self,
            spec: &LaunchSpec,
            timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.specs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(spec.clone());
            self.timeouts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(timeout);
            self.gate.pass();
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "launch failed"));
            }
            Ok(Box::new(FakeProcess(
                self.terminated.clone(),
                self.fail_terminate.load(Ordering::SeqCst),
                self.term_gate.clone(),
            )))
        }
    }

    /// `Arc<RecordingLauncher>` を start が受ける `Arc<dyn ProcessLauncher>` にする。
    fn dynl(l: &Arc<RecordingLauncher>) -> Arc<dyn ProcessLauncher> {
        l.clone()
    }

    /// 既定の上限で start し、更新後の状態を返す（模擬プロセスのハンドルは回収不要のため捨てる）。
    fn run(
        store: &MemStateStore,
        launcher: &Arc<RecordingLauncher>,
        id: &str,
    ) -> Result<StateRecord, TraitError> {
        start(
            store,
            &OpRecorder::new(),
            &dynl(launcher),
            &sid(id),
            &StartTimeouts::default(),
        )
        .map(|started| started.into_parts().0)
    }

    /// 既定の上限で中断回復する。
    fn recover(
        store: &MemStateStore,
        launcher: &Arc<RecordingLauncher>,
        id: &ContainerId,
    ) -> Result<StateRecord, TraitError> {
        recover_interrupted_start(store, &dynl(launcher), id, &StartTimeouts::default())
    }

    /// `cond` が真になるまで最大 `limit` ポーリングする（固定 sleep に頼らない）。
    #[cfg(target_os = "linux")]
    fn eventually(limit: Duration, cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 起動待ち 200ms・終了待ち 1s・確認待ち 200ms の短い上限（REPAIR-5 のテスト用）。
    #[cfg(target_os = "linux")]
    fn short_timeouts() -> StartTimeouts {
        StartTimeouts::new(
            Duration::from_millis(200),
            Duration::from_secs(1),
            Duration::from_millis(200),
        )
        .expect("timeouts")
    }

    /// テストごとに一意な bundle ディレクトリ（終了時に削除）。
    struct Bundle {
        dir: PathBuf,
    }

    impl Bundle {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-oci-start-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create bundle dir");
            Self { dir }
        }

        fn write_config(&self, v: &Value) {
            std::fs::write(
                self.dir.join("config.json"),
                serde_json::to_vec(v).expect("serialize"),
            )
            .expect("write config");
        }

        fn create_req(&self, id: &str) -> CreateRequest {
            CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
                .expect("absolute bundle")
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn valid_config() -> Value {
        json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "hostname": "box",
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/echo", "hello"],
                "env": ["PATH=/bin", "K=V"],
                "cwd": "/"
            },
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"},
                {"type": "ipc"}
            ]}
        })
    }

    /// 拒否ケース名と config 変更関数の組。
    type Case = (&'static str, Box<dyn Fn(&mut Value)>);

    fn sid(id: &str) -> StartRequest {
        StartRequest::new(ContainerId::new(id).expect("id"))
    }

    /// create 済みの bundle・ストアを用意する。
    fn created(name: &str) -> (Bundle, MemStateStore) {
        let b = Bundle::new(name);
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req(name)).expect("create");
        (b, store)
    }

    /// create 後に config を差し替えて start し、エラーを返す（状態は Created のまま・launcher 0 回を確認）。
    fn start_rejected_after_rewrite(name: &str, cfg: &Value) -> TraitError {
        let (b, store) = created(name);
        b.write_config(cfg);
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, name).expect_err("must fail");
        assert_eq!(launcher.calls(), 0);
        let got = store
            .get(&GetStateRequest::new(ContainerId::new(name).expect("id")))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        err
    }

    /// OCI-4・CORE-1: start で `process.args` 等がそのまま launcher に渡り、Running・pid 付きへ遷移する。
    /// 起動済みプロセスのハンドルは終了させずに呼び出し元へ引き渡される（監視・回収の所有者）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci4_start_launches_process_args_and_transitions_to_running() {
        let (b, store) = created("ok");
        let before = store
            .get(&GetStateRequest::new(ContainerId::new("ok").expect("id")))
            .expect("get");
        let launcher = RecordingLauncher::new(false);
        let started = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &sid("ok"),
            &StartTimeouts::default(),
        )
        .expect("start");
        assert_eq!(started.process().pid(), NonZeroU32::new(4242).expect("pid"));
        assert_eq!(started.process().wait(Duration::ZERO).expect("wait"), None);
        assert_eq!(launcher.terminations(), 0);
        let (record, process) = started.into_parts();
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.status().pid(), NonZeroU32::new(4242));
        assert!(record.revision() > before.revision());
        assert_eq!(launcher.calls(), 1);
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        assert_eq!(spec.args(), ["/bin/echo", "hello"]);
        assert_eq!(spec.env(), ["PATH=/bin", "K=V"]);
        assert_eq!(spec.hostname(), Some("box"));
        assert_eq!(spec.rootfs(), b.dir.join("rootfs"));
        // REPAIR-5: 呼び出し側の上限（既定 10 秒）がそのまま launcher へ渡る。
        assert_eq!(launcher.received_timeouts(), [Duration::from_secs(10)]);
        assert_eq!(
            spec.namespaces(),
            [
                NamespaceKind::Pid,
                NamespaceKind::Mount,
                NamespaceKind::User,
                NamespaceKind::Uts,
                NamespaceKind::Ipc
            ]
        );
        // 引き渡されたハンドルで所有者が終了・回収できる。
        process
            .terminate(Duration::from_secs(5))
            .expect("terminate");
        assert_eq!(
            process.wait(Duration::ZERO).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
        assert_eq!(launcher.terminations(), 1);
    }

    /// CORE-2: create されていない ID の start は NotFound で、launcher は呼ばれない。
    #[test]
    fn core2_start_unknown_id_returns_not_found() {
        let store = MemStateStore::new(None);
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "nope").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(launcher.calls(), 0);
    }

    /// CORE-2: Running への再 start は FailedPrecondition で、launcher は 1 回のまま。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_start_twice_returns_failed_precondition() {
        let (_b, store) = created("twice");
        let launcher = RecordingLauncher::new(false);
        run(&store, &launcher, "twice").expect("first");
        let err = run(&store, &launcher, "twice").expect_err("second");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
    }

    /// SEC-1: create 後に壊れた JSON へ書き換えられた config は start で拒否される（TOCTOU）。
    #[test]
    fn sec1_start_revalidates_malformed_config_after_create() {
        let (b, store) = created("rewrite-bad");
        std::fs::write(b.dir.join("config.json"), b"{ not json").expect("write");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "rewrite-bad").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: create 後に seccomp 等の未解釈フィールドが加わった config は Unimplemented。
    #[test]
    fn sec1_start_rejects_unapplied_field_added_after_create() {
        let mut cfg = valid_config();
        cfg["linux"]["seccomp"] = json!({"defaultAction": "SCMP_ACT_ALLOW"});
        let err = start_rejected_after_rewrite("rewrite-seccomp", &cfg);
        assert_eq!(err.code(), ErrorCode::Unimplemented);
    }

    /// SEC-1: create 後に rootfs が symlink へ差し替えられたら拒否する。
    #[cfg(unix)]
    #[test]
    fn sec1_start_rejects_symlinked_rootfs_after_create() {
        let (b, store) = created("swap-rootfs");
        std::fs::remove_dir(b.dir.join("rootfs")).expect("rm");
        std::fs::create_dir(b.dir.join("real")).expect("real");
        std::os::unix::fs::symlink(b.dir.join("real"), b.dir.join("rootfs")).expect("symlink");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "swap-rootfs").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: args[0] が相対パス（PATH 探索は未実装）なら InvalidArgument。
    #[test]
    fn sec1_start_rejects_relative_entrypoint() {
        let mut cfg = valid_config();
        cfg["process"]["args"] = json!(["echo", "hi"]);
        let err = start_rejected_after_rewrite("relarg", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "process.args[0] must be an absolute path");
    }

    /// SEC-1・SEC-5・CORE-5: start が適用できない指定は黙って無視せず Unimplemented で拒否する。
    #[test]
    fn sec1_start_rejects_unsupported_fields() {
        let cases: Vec<Case> = vec![
            ("cwd", Box::new(|c| c["process"]["cwd"] = json!("/work"))),
            (
                "uid",
                Box::new(|c| c["process"]["user"]["uid"] = json!(1000)),
            ),
            (
                "gid",
                Box::new(|c| c["process"]["user"]["gid"] = json!(1000)),
            ),
            (
                "addgid",
                Box::new(|c| c["process"]["user"]["additionalGids"] = json!([5])),
            ),
            ("tty", Box::new(|c| c["process"]["terminal"] = json!(true))),
            (
                "mounts",
                Box::new(|c| {
                    c["mounts"] =
                        json!([{"destination": "/proc", "type": "proc", "source": "proc"}])
                }),
            ),
            (
                "nspath",
                Box::new(|c| {
                    c["linux"]["namespaces"] = json!([{"type": "pid", "path": "/proc/1/ns/pid"}])
                }),
            ),
            (
                "netns",
                Box::new(|c| c["linux"]["namespaces"] = json!([{"type": "network"}])),
            ),
            (
                "uidmap",
                Box::new(|c| {
                    c["linux"]["uidMappings"] =
                        json!([{"containerID": 0, "hostID": 1000, "size": 1}])
                }),
            ),
            ("ro", Box::new(|c| c["root"]["readonly"] = json!(true))),
        ];
        for (name, mutate) in cases {
            let mut cfg = valid_config();
            mutate(&mut cfg);
            let err = start_rejected_after_rewrite(&format!("rej-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::Unimplemented, "case {name}");
            assert!(
                err.message().starts_with("start does not support yet: "),
                "case {name}: {}",
                err.message()
            );
        }
    }

    /// REPAIR-5: 状態更新に失敗したら起動済みプロセスをちょうど 1 回 terminate し、元のエラーを返す。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_start_terminates_process_when_state_update_fails() {
        let b = Bundle::new("upd-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("upd-fail")).expect("create");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "upd-fail").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
        assert_eq!(launcher.terminations(), 1);
    }

    /// SEC-5: user namespace が無い config（ホスト root での起動になる）は PermissionDenied で拒否する。
    #[test]
    fn sec5_start_rejects_missing_user_namespace() {
        let mut cfg = valid_config();
        cfg["linux"]["namespaces"] = json!([{"type": "pid"}, {"type": "mount"}]);
        let err = start_rejected_after_rewrite("no-userns", &cfg);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "a user namespace is required to run as root");
    }

    /// CORE-2: 同一 ID の start が進行中なら二重に launch せず FailedPrecondition を返す。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_start_rejects_concurrent_start_of_same_id() {
        let (_b, store) = created("concurrent");
        let launcher = RecordingLauncher::new(false);
        let id = ContainerId::new("concurrent").expect("id");
        let guard = StartReservation::acquire(&id).expect("reserve");
        let err = run(&store, &launcher, "concurrent").expect_err("busy");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 0);
        drop(guard);
        run(&store, &launcher, "concurrent").expect("after release");
        assert_eq!(launcher.calls(), 1);
    }

    /// REPAIR-5: 状態更新と terminate の両方に失敗したら、終了失敗を Internal で伝える。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_start_reports_terminate_failure() {
        let b = Bundle::new("term-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("term-fail")).expect("create");
        let launcher = RecordingLauncher::new(false);
        launcher.fail_terminate.store(true, Ordering::SeqCst);
        let err = run(&store, &launcher, "term-fail").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(launcher.terminations(), 1);
    }

    /// OCI-4: launcher 失敗はそのまま返り、状態は Created のまま。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci4_start_propagates_launcher_error_without_state_change() {
        let (_b, store) = created("launch-fail");
        let launcher = RecordingLauncher::new(true);
        let err = run(&store, &launcher, "launch-fail").expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        let got = store
            .get(&GetStateRequest::new(
                ContainerId::new("launch-fail").expect("id"),
            ))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(launcher.terminations(), 0);
    }

    /// REPAIR-4: 成功・失敗が `start` 操作名で 1 件ずつ記録される。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair4_start_records_success_and_failure() {
        let (_b, store) = created("rec");
        let launcher = RecordingLauncher::new(false);
        let rec = OpRecorder::new();
        let started = start(
            &store,
            &rec,
            &dynl(&launcher),
            &sid("rec"),
            &StartTimeouts::default(),
        )
        .expect("first");
        assert_eq!(started.record().status().state(), ContainerState::Running);
        start(
            &store,
            &rec,
            &dynl(&launcher),
            &sid("rec"),
            &StartTimeouts::default(),
        )
        .expect_err("second");
        let stats = rec
            .snapshot_op(&OpName::new("start").expect("name"))
            .expect("recorded");
        assert_eq!(stats.success(), 1);
        assert_eq!(stats.failure(), 1);
        assert!(stats.latency().is_some());
    }

    /// SEC-1・CORE-1: PID・mount・UTS・IPC namespace のいずれかが欠けた config は拒否する（UTS は
    /// hostname 指定が無くても必須）。
    #[test]
    fn sec1_start_rejects_incomplete_namespace_sets() {
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "userns-only",
                json!([{"type": "user"}, {"type": "uts"}, {"type": "ipc"}]),
                "the PID and mount namespaces are required",
            ),
            (
                "no-mount",
                json!([{"type": "pid"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}]),
                "the PID and mount namespaces are required",
            ),
            (
                "no-uts",
                json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "ipc"}]),
                "the UTS namespace is required",
            ),
            (
                "no-ipc",
                json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}]),
                "the IPC namespace is required",
            ),
        ];
        for (name, namespaces, message) in cases {
            let mut cfg = valid_config();
            cfg["linux"]["namespaces"] = namespaces;
            let err = start_rejected_after_rewrite(&format!("ns-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
        // hostname 指定が無くても UTS namespace の欠落は拒否する。
        let mut cfg = valid_config();
        cfg.as_object_mut().expect("object").remove("hostname");
        cfg["linux"]["namespaces"] =
            json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "ipc"}]);
        let err = start_rejected_after_rewrite("ns-no-uts-no-hostname", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "the UTS namespace is required");
    }

    /// CORE-2: 中断された予約（Running・pid なし）は識別でき、回復後に start できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_interrupted_reservation_is_recoverable() {
        let (b, store) = created("recover");
        let id = ContainerId::new("recover").expect("id");
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                rec.revision(),
            ))
            .expect("claim");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "recover").expect_err("stuck");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container start was interrupted; recover the start reservation"
        );
        // 生存プロセス無しを確認できない launcher では予約を残す（二重起動防止。SEC-1）。
        let err = recover(&store, &launcher, &id).expect_err("unconfirmed");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(rec.status().state(), ContainerState::Running);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let got = recover(&store, &launcher, &id).expect("recover");
        assert_eq!(got.status().state(), ContainerState::Created);
        let err = recover(&store, &launcher, &id).expect_err("not stuck");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        run(&store, &launcher, "recover").expect("start");
        drop(b);
    }

    /// 中断された予約（Running・pid なし）を手で作る。
    fn claim_interrupted(store: &MemStateStore, id: &ContainerId) {
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                rec.revision(),
            ))
            .expect("claim");
    }

    /// 別プロセスの所有者を模して bundle ディレクトリへ別の記述子で `flock` をかける（flock は同一
    /// プロセス内でも別に開いた記述子同士で競合する）。
    #[cfg(target_os = "linux")]
    fn lock_bundle_as_other_owner(b: &Bundle) -> std::fs::File {
        let file = std::fs::File::open(&b.dir).expect("open bundle");
        file.try_lock().expect("lock bundle");
        file
    }

    /// CORE-2・SEC-1: 別プロセスが起動権の所有ロックを持つ間は、生存確認が Ok を返す launcher でも回復を
    /// 拒否し（確認も呼ばない）、所有者が終了してロックが外れれば回復できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_recover_requires_owner_lock_across_processes() {
        let (b, store) = created("owner-recover");
        let id = ContainerId::new("owner-recover").expect("id");
        claim_interrupted(&store, &id);
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let other = lock_bundle_as_other_owner(&b);
        let err = recover(&store, &launcher, &id).expect_err("owner alive");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container start is in progress in another process"
        );
        assert_eq!(launcher.received_timeouts(), [] as [Duration; 0]);
        let got = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(got.status().state(), ContainerState::Running);
        drop(other);
        let got = recover(&store, &launcher, &id).expect("owner gone");
        assert_eq!(got.status().state(), ContainerState::Created);
    }

    /// CORE-2: 別プロセスが所有ロックを持つ間の start は、予約・launch をせず FailedPrecondition。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_start_requires_owner_lock_across_processes() {
        let (b, store) = created("owner-start");
        let launcher = RecordingLauncher::new(false);
        let other = lock_bundle_as_other_owner(&b);
        let err = run(&store, &launcher, "owner-start").expect_err("locked");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container start is in progress in another process"
        );
        assert_eq!(launcher.calls(), 0);
        let id = ContainerId::new("owner-start").expect("id");
        let got = store.get(&GetStateRequest::new(id)).expect("get");
        assert_eq!(got.status().state(), ContainerState::Created);
        drop(other);
        run(&store, &launcher, "owner-start").expect("start after unlock");
        assert_eq!(launcher.calls(), 1);
    }

    /// SEC-1・CLI-1: Linux 以外は起動権の所有ロックを取れないため、回復は Unimplemented で予約を残す。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn core2_recover_fails_closed_without_owner_lock() {
        let (_b, store) = created("recover-nolinux");
        let id = ContainerId::new("recover-nolinux").expect("id");
        claim_interrupted(&store, &id);
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let err = recover(&store, &launcher, &id).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "start requires Linux to lock the bundle directory"
        );
        let got = store.get(&GetStateRequest::new(id)).expect("get");
        assert_eq!(got.status().state(), ContainerState::Running);
    }

    /// SEC-1: 絶対指定の `root.path` でホストの `/` を rootfs にする起動は拒否する。
    #[test]
    fn sec1_start_rejects_host_root_as_rootfs() {
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("/");
        let err = start_rejected_after_rewrite("hostroot", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "rootfs must not be the filesystem root");
    }

    /// REPAIR-2: args / env の件数・サイズ・形式の違反は launcher に渡る前に InvalidArgument で拒否する。
    #[test]
    fn repair2_start_rejects_oversized_or_malformed_entrypoint() {
        let big = "a".repeat(STRING_MAX_BYTES);
        let many: Vec<String> = (0..=ARGS_MAX).map(|i| format!("/x{i}")).collect();
        let cases: Vec<(&str, Value, Value)> = vec![
            ("bigarg", json!(["/bin/echo", big]), json!(["K=V"])),
            ("manyargs", json!(many), json!(["K=V"])),
            (
                "total",
                json!(["/bin/echo", "a".repeat(100_000), "a".repeat(100_000)]),
                Value::Array(
                    (0..10)
                        .map(|i| json!(format!("K{i}={}", "v".repeat(100_000))))
                        .collect(),
                ),
            ),
            ("badenv", json!(["/bin/echo"]), json!(["NOEQUALS"])),
            ("emptykey", json!(["/bin/echo"]), json!(["=V"])),
        ];
        for (name, args, env) in cases {
            let mut cfg = valid_config();
            cfg["process"]["args"] = args;
            cfg["process"]["env"] = env;
            let err = start_rejected_after_rewrite(&format!("lim-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
        }
    }

    /// REPAIR-2: 複製した上限値が `exec::Entrypoint` の定数と一致する（Linux）。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair2_entrypoint_limits_match_exec() {
        use crate::exec;
        assert_eq!(ARGS_MAX, exec::ENTRYPOINT_MAX_ARGS);
        assert_eq!(ENV_MAX, exec::ENTRYPOINT_MAX_ENV);
        assert_eq!(STRING_MAX_BYTES, exec::ENTRYPOINT_MAX_STRING_BYTES);
        assert_eq!(TOTAL_MAX_BYTES, exec::ENTRYPOINT_MAX_TOTAL_BYTES);
    }

    /// CORE-2: 起動権の予約（Created から Running への revision 照合つき更新）に負けたら launch しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_start_does_not_launch_when_claim_is_lost() {
        let b = Bundle::new("claim-lost");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(0));
        create(&store, &OpRecorder::new(), &b.create_req("claim-lost")).expect("create");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "claim-lost").expect_err("lost");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: 成功時の LaunchSpec は検査済み rootfs を固定した fd を持つ（Linux）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_launch_spec_carries_rootfs_handle() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let (b, store) = created("handle");
        let launcher = RecordingLauncher::new(false);
        run(&store, &launcher, "handle").expect("start");
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        let fd = spec.rootfs_dir().as_fd().as_raw_fd();
        let held = std::fs::metadata(format!("/proc/thread-self/fd/{fd}")).expect("meta");
        let named = std::fs::metadata(b.dir.join("rootfs")).expect("meta");
        assert_eq!((held.dev(), held.ino()), (named.dev(), named.ino()));
    }

    /// SEC-1: bundle の祖先が symlink なら（create は受理しても）start は起動前に拒否し、予約もしない。
    /// 本番 launcher の `exec::prepare_rootfs` も `/` から symlink 非追従で辿るため、先に拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_start_rejects_bundle_under_symlinked_ancestor() {
        let base =
            std::env::temp_dir().join(format!("fandhe-oci-start-anc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        std::fs::create_dir_all(real.join("bundle").join("rootfs")).expect("mkdir");
        std::fs::write(
            real.join("bundle").join("config.json"),
            serde_json::to_vec(&valid_config()).expect("serialize"),
        )
        .expect("write");
        std::os::unix::fs::symlink(&real, base.join("link")).expect("symlink");
        let bundle = base.join("link").join("bundle");
        let store = MemStateStore::new(None);
        let id = ContainerId::new("anc").expect("id");
        create(
            &store,
            &OpRecorder::new(),
            &CreateRequest::new(id.clone(), bundle).expect("absolute"),
        )
        .expect("create accepts the bundle");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "anc").expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "bundle path must be a directory reachable without symlinks"
        );
        assert_eq!(launcher.calls(), 0);
        let got = store.get(&GetStateRequest::new(id)).expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// SEC-1・CLI-1: Linux 以外は rootfs を fd で固定できないため、予約・launch の前に Unimplemented で拒否する。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_start_fails_closed_without_rootfs_pinning() {
        let (_b, store) = created("nolinux");
        let launcher = RecordingLauncher::new(false);
        let err = run(&store, &launcher, "nolinux").expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "start requires Linux to pin the rootfs directory"
        );
        assert_eq!((launcher.calls(), launcher.terminations()), (0, 0));
        let got = store
            .get(&GetStateRequest::new(
                ContainerId::new("nolinux").expect("id"),
            ))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
    }

    /// REPAIR-5・CORE-2: launch が上限内に戻らなければ start は上限＋猶予で Timeout を返し、予約は残す。
    /// launch が進行中の間はプロセス内の予約も保持され、同一 ID の start・回復は拒否される（二重起動防止）。
    /// 後から返った起動済みプロセスは 1 回だけ terminate され、その後は回復できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_start_times_out_when_launcher_does_not_return() {
        let (b, store) = created("launch-hang");
        let launcher = RecordingLauncher::new(false);
        launcher.gate.set_open(false);
        let begin = Instant::now();
        let err = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &sid("launch-hang"),
            &short_timeouts(),
        )
        .expect_err("must time out");
        let elapsed = begin.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "the process launch did not complete within the timeout; \
             the start reservation remains until recovered"
        );
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert_eq!(launcher.received_timeouts(), [Duration::from_millis(200)]);
        let id = ContainerId::new("launch-hang").expect("id");
        let got = store.get(&GetStateRequest::new(id)).expect("stored");
        assert_eq!(got.status().state(), ContainerState::Running);
        assert_eq!(got.status().pid(), None);
        assert_eq!(launcher.terminations(), 0);
        // launch が進行中の間は、生存確認が「プロセスなし」を返す launcher でも回復・再 start を拒否する。
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        let id = ContainerId::new("launch-hang").expect("id");
        let err = recover(&store, &launcher, &id).expect_err("launch in flight");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container start is already in progress");
        let err = run(&store, &launcher, "launch-hang").expect_err("launch in flight");
        assert_eq!(err.message(), "container start is already in progress");
        assert_eq!(launcher.received_timeouts(), [Duration::from_millis(200)]);
        // 別プロセスからも、launch の進行中は所有ロック（bundle の flock）が取れないことで観測できる。
        let probe = std::fs::File::open(&b.dir).expect("open bundle");
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        launcher.gate.set_open(true);
        assert!(eventually(Duration::from_secs(10), || launcher
            .terminations()
            == 1));
        assert!(eventually(Duration::from_secs(10), || {
            run(&store, &launcher, "launch-hang").is_err_and(|e| {
                e.message() == "container start was interrupted; recover the start reservation"
            })
        }));
        assert!(eventually(Duration::from_secs(10), || probe
            .try_lock()
            .is_ok()));
        drop(probe);
        let got = recover(&store, &launcher, &id).expect("recover after the launch ended");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(launcher.calls(), 1);
    }

    /// REPAIR-5・CORE-2: 上限超過後に返った起動済みプロセスの terminate も上限で打ち切り、プロセス内の
    /// 予約を有限時間で手放す。終了を確認できないため状態の予約（Running・pid なし）は残す。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_late_terminate_is_bounded_and_keeps_reservation() {
        let (_b, store) = created("late-term-hang");
        let launcher = RecordingLauncher::new(false);
        launcher.gate.set_open(false);
        launcher.term_gate.set_open(false);
        let err = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &sid("late-term-hang"),
            &short_timeouts(),
        )
        .expect_err("must time out");
        assert_eq!(err.code(), ErrorCode::Timeout);
        launcher.gate.set_open(true);
        let begin = Instant::now();
        // 遅れて返ったプロセスの terminate が戻らなくても、上限 1 秒＋猶予 1 秒でプロセス内の予約が外れる。
        assert!(eventually(Duration::from_secs(10), || {
            run(&store, &launcher, "late-term-hang").is_err_and(|e| {
                e.message() == "container start was interrupted; recover the start reservation"
            })
        }));
        assert!(
            begin.elapsed() >= Duration::from_secs(1),
            "{:?}",
            begin.elapsed()
        );
        assert_eq!(launcher.terminations(), 0);
        let id = ContainerId::new("late-term-hang").expect("id");
        let got = store.get(&GetStateRequest::new(id)).expect("stored");
        assert_eq!(got.status().state(), ContainerState::Running);
        assert_eq!(got.status().pid(), None);
        launcher.term_gate.set_open(true);
        assert!(eventually(Duration::from_secs(10), || launcher
            .terminations()
            == 1));
    }

    /// REPAIR-5: 状態記録の失敗後に terminate が上限内に戻らなければ、Internal で未記録プロセスの
    /// 残存を伝え、予約は残す。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_start_bounds_terminate_after_record_failure() {
        let b = Bundle::new("term-hang");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("term-hang")).expect("create");
        let launcher = RecordingLauncher::new(false);
        launcher.term_gate.set_open(false);
        let begin = Instant::now();
        let err = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &sid("term-hang"),
            &short_timeouts(),
        )
        .expect_err("must fail");
        let elapsed = begin.elapsed();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "failed to record running state and failed to terminate the launched process"
        );
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        let id = ContainerId::new("term-hang").expect("id");
        let got = store.get(&GetStateRequest::new(id)).expect("stored");
        assert_eq!(got.status().state(), ContainerState::Running);
        assert_eq!(got.status().pid(), None);
        launcher.term_gate.set_open(true);
        assert!(eventually(Duration::from_secs(10), || launcher
            .terminations()
            == 1));
    }

    /// REPAIR-5・CORE-2: 生存確認が上限内に戻らなければ回復は Timeout を返して予約を残す。確認が終わる
    /// までは同一 ID の回復・start を拒否し、確認が戻った後に回復できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_recover_times_out_when_confirmation_does_not_return() {
        let (_b, store) = created("confirm-hang");
        let id = ContainerId::new("confirm-hang").expect("id");
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                rec.revision(),
            ))
            .expect("claim");
        let launcher = RecordingLauncher::new(false);
        launcher.confirms_no_process.store(true, Ordering::SeqCst);
        launcher.gate.set_open(false);
        let begin = Instant::now();
        let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
            .expect_err("must time out");
        let elapsed = begin.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "the launcher did not confirm within the timeout; the start reservation remains"
        );
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert_eq!(launcher.received_timeouts(), [Duration::from_millis(200)]);
        let got = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(got.status().state(), ContainerState::Running);
        // 確認が終わるまでは、プロセス内の回復の再試行・start を拒否する（遅れた確認との競合防止）。
        let err = recover(&store, &launcher, &id).expect_err("confirmation in flight");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container start is already in progress");
        let err = run(&store, &launcher, "confirm-hang").expect_err("confirmation in flight");
        assert_eq!(err.message(), "container start is already in progress");
        assert_eq!(launcher.received_timeouts(), [Duration::from_millis(200)]);
        launcher.gate.set_open(true);
        assert!(eventually(Duration::from_secs(10), || recover(
            &store, &launcher, &id
        )
        .is_ok()));
        let got = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(
            launcher.received_timeouts(),
            [Duration::from_millis(200), Duration::from_secs(10)]
        );
    }
}
